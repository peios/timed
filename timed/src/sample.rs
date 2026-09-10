//! One measurement, from the four timestamps of an exchange.
//!
//! ```text
//!        T1                                  T4
//!  client ---------------------------------> |
//!          \                                /
//!           \                              /
//!            v                            /
//!  server    T2 -----------------------> T3
//! ```
//!
//! Everything a time client believes is built out of three numbers derived
//! from those four, and the derivation is short enough to state in full:
//!
//! - **offset** θ = ((T2 − T1) + (T3 − T4)) / 2 — how far the local clock is
//!   from the server's, *assuming the path is symmetric*.
//! - **delay** δ = (T4 − T1) − (T3 − T2) — the round trip minus the time the
//!   server spent thinking, so: how long the packets were in flight.
//! - **dispersion** ε — the accumulated reading error, which grows with time
//!   because the local clock drifts between measurements.
//!
//! That symmetry assumption is the one real weakness of NTP and no
//! implementation can remove it: an attacker who can delay traffic in one
//! direction only can move a client's clock by half the added delay, with
//! every packet authentic and every check passing. NTS does not help, and
//! knows it. What limits the damage is that the error is bounded by δ/2, so
//! a client that refuses large-delay samples and reports its root distance
//! honestly is telling the truth about how wrong it might be.

use ntp::NtpTimestamp;

/// The assumed worst-case drift rate of an undisciplined clock, RFC 5905's
/// φ: 15 parts per million. Dispersion grows at this rate between updates,
/// which is what makes an old measurement worth less than a fresh one
/// without anybody having to decide when it "expires".
pub const PHI: f64 = 15e-6;

/// The smallest delay or dispersion worth distinguishing, RFC 5905's
/// MINDISP: one millisecond. Below this the numbers are noise, and treating
/// them as meaningful makes the selection algorithm prefer whichever server
/// happens to be closest rather than whichever is most likely right.
pub const MIN_DISPERSION: f64 = 1e-3;

/// One completed exchange, reduced.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Sample {
    /// How far the local clock is behind the server's, in seconds. Positive
    /// means the local clock is slow.
    pub offset: f64,
    /// Round-trip time with the server's processing removed, in seconds.
    pub delay: f64,
    /// Reading error at the moment of measurement, in seconds.
    pub dispersion: f64,
    /// The local time this was measured, as a Unix timestamp in seconds.
    /// Used only for ageing, so its own accuracy does not matter.
    pub at: f64,
}

/// The four timestamps, as they come off the wire and the socket.
#[derive(Debug, Clone, Copy)]
pub struct Exchange {
    /// T1: our transmit, read from our clock.
    pub origin: NtpTimestamp,
    /// T2: the server's receive.
    pub receive: NtpTimestamp,
    /// T3: the server's transmit.
    pub transmit: NtpTimestamp,
    /// T4: our receive, read from our clock — ideally a kernel timestamp
    /// taken when the packet arrived rather than when we got round to it.
    pub destination: NtpTimestamp,
}

/// Why a structurally valid exchange still cannot be turned into a sample.
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum SampleError {
    /// T4 is before T1: our own clock moved backwards during the exchange,
    /// which happens when something else stepped it. The measurement spans
    /// a discontinuity and means nothing.
    LocalWentBackwards,
    /// T3 is before T2: the server's clock moved backwards while it held
    /// our request, or it is lying.
    ServerWentBackwards,
    /// The delay is past what we are willing to believe. Because the
    /// symmetry error is bounded by half the delay, a large delay is not
    /// merely imprecise — it is an opportunity, and refusing it is the
    /// cheapest defence there is.
    TooFar { delay: f64 },
}

impl Exchange {
    /// Reduce to a sample.
    ///
    /// `local_precision` and `server_precision` are log2 seconds, as NTP
    /// reports them; both contribute to the dispersion because both clocks
    /// were read to produce these numbers.
    pub fn reduce(
        &self,
        local_precision: i8,
        server_precision: i8,
        max_delay: f64,
        at: f64,
    ) -> Result<Sample, SampleError> {
        let round_trip = self.destination.wrapping_sub(self.origin);
        if round_trip.is_negative() {
            return Err(SampleError::LocalWentBackwards);
        }
        let server_held = self.transmit.wrapping_sub(self.receive);
        if server_held.is_negative() {
            return Err(SampleError::ServerWentBackwards);
        }

        // δ = (T4 − T1) − (T3 − T2). Both terms are non-negative by the
        // checks above, so the subtraction cannot produce a large positive
        // number by wrapping — but a server whose processing time exceeds
        // our round trip (impossible physically, trivial to claim) would
        // make it negative, which the floor below absorbs.
        let delay = (round_trip - server_held)
            .as_seconds_f64()
            .max(MIN_DISPERSION);
        if delay > max_delay {
            return Err(SampleError::TooFar { delay });
        }

        // θ = ((T2 − T1) + (T3 − T4)) / 2, computed as a sum of two signed
        // differences so that each is era-correct on its own.
        let forward = self.receive.wrapping_sub(self.origin);
        let backward = self.transmit.wrapping_sub(self.destination);
        let offset = (forward + backward).as_seconds_f64() / 2.0;

        // The reading error: one tick of each clock, plus what the local
        // clock could have drifted during the exchange.
        let dispersion = log2_seconds(local_precision)
            + log2_seconds(server_precision)
            + PHI * round_trip.as_seconds_f64();

        Ok(Sample {
            offset,
            delay,
            dispersion,
            at,
        })
    }
}

/// NTP's precision field is log2 seconds in a signed byte. Clamped, because
/// a server claiming 2^127 seconds of precision would otherwise produce an
/// infinity that poisons every average it enters.
pub fn log2_seconds(exponent: i8) -> f64 {
    (2.0f64).powi(exponent.clamp(-32, 8) as i32)
}

impl Sample {
    /// This sample's dispersion now, having aged since it was taken.
    pub fn aged_dispersion(&self, now: f64) -> f64 {
        self.dispersion + PHI * (now - self.at).max(0.0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build an exchange from four Unix-second offsets relative to a base.
    fn exchange(t1: f64, t2: f64, t3: f64, t4: f64) -> Exchange {
        let ts = |s: f64| {
            NtpTimestamp::from_unix(
                1_700_000_000 + s.trunc() as i64,
                (s.fract().abs() * 1e9) as u32,
            )
        };
        Exchange {
            origin: ts(t1),
            receive: ts(t2),
            transmit: ts(t3),
            destination: ts(t4),
        }
    }

    #[test]
    fn a_symmetric_exchange_with_no_error_has_no_offset() {
        // Out at 0, arrives at 0.05, replied at 0.05, back at 0.1.
        let s = exchange(0.0, 0.05, 0.05, 0.1)
            .reduce(-20, -20, 1.0, 0.0)
            .unwrap();
        assert!(s.offset.abs() < 1e-6, "offset {}", s.offset);
        assert!((s.delay - 0.1).abs() < 1e-6, "delay {}", s.delay);
    }

    #[test]
    fn a_slow_local_clock_shows_a_positive_offset() {
        // The server is one second ahead of us: its timestamps are +1.
        let s = exchange(0.0, 1.05, 1.05, 0.1)
            .reduce(-20, -20, 1.0, 0.0)
            .unwrap();
        assert!((s.offset - 1.0).abs() < 1e-6, "offset {}", s.offset);
        assert!((s.delay - 0.1).abs() < 1e-6, "delay {}", s.delay);
    }

    #[test]
    fn the_server_thinking_for_a_while_does_not_count_as_delay() {
        // Round trip a second, but the server held the request for 0.9 of it.
        let s = exchange(0.0, 0.05, 0.95, 1.0)
            .reduce(-20, -20, 1.0, 0.0)
            .unwrap();
        assert!((s.delay - 0.1).abs() < 1e-6, "delay {}", s.delay);
    }

    #[test]
    fn an_asymmetric_path_moves_the_offset_by_half_the_asymmetry() {
        // The property that bounds how much damage a path attacker can do,
        // stated as a test so that it cannot quietly stop being true.
        // Outbound 0.1s, inbound 0.5s: total delay 0.6, asymmetry 0.4.
        let s = exchange(0.0, 0.1, 0.1, 0.6)
            .reduce(-20, -20, 2.0, 0.0)
            .unwrap();
        assert!((s.offset - (-0.2)).abs() < 1e-6, "offset {}", s.offset);
        assert!((s.offset.abs() - s.delay / 2.0 + 0.1).abs() < 1e-6);
    }

    #[test]
    fn a_local_clock_that_jumped_backwards_invalidates_the_measurement() {
        let e = exchange(1.0, 0.5, 0.5, 0.0);
        assert_eq!(
            e.reduce(-20, -20, 1.0, 0.0),
            Err(SampleError::LocalWentBackwards)
        );
    }

    #[test]
    fn a_server_that_replied_before_it_asked_is_refused() {
        let e = exchange(0.0, 0.5, 0.1, 1.0);
        assert_eq!(
            e.reduce(-20, -20, 1.0, 0.0),
            Err(SampleError::ServerWentBackwards)
        );
    }

    #[test]
    fn a_delay_past_the_limit_is_refused_rather_than_weighted_down() {
        let e = exchange(0.0, 0.5, 0.5, 1.0);
        assert!(matches!(
            e.reduce(-20, -20, 0.5, 0.0),
            Err(SampleError::TooFar { .. })
        ));
    }

    #[test]
    fn an_absurd_precision_claim_cannot_produce_an_infinity() {
        let s = exchange(0.0, 0.05, 0.05, 0.1)
            .reduce(127, 127, 1.0, 0.0)
            .unwrap();
        assert!(s.dispersion.is_finite(), "{}", s.dispersion);
    }

    #[test]
    fn dispersion_grows_with_age_at_phi() {
        let s = Sample {
            offset: 0.0,
            delay: 0.01,
            dispersion: 0.001,
            at: 100.0,
        };
        assert!((s.aged_dispersion(1100.0) - (0.001 + PHI * 1000.0)).abs() < 1e-12);
        // Never shrinks, even if asked about a time before it was taken.
        assert_eq!(s.aged_dispersion(0.0), 0.001);
    }
}
