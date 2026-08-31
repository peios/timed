//! One source: what we asked, what came back, and whether to believe it.
//!
//! A source is a server we poll. It owns a clock filter, a poll interval it
//! adapts, a reachability register, and — when NTS is in use — a set of
//! cookies and a pair of AEAD keys.
//!
//! The security of the whole client is concentrated in [`Source::accept`],
//! so it is worth saying plainly what stops an attacker moving this
//! machine's clock.
//!
//! **With NTS**, the reply carries an AEAD tag over every byte of the
//! packet, computed with a key established over an authenticated TLS
//! session. Forging one requires the key. There is nothing further to
//! discuss.
//!
//! **Without NTS**, the only defence is that the server must echo, in the
//! origin timestamp, the exact 64 bits we put in our transmit timestamp —
//! and we put a random number there rather than the actual time. An
//! attacker who cannot see our request cannot guess it, so an off-path
//! attacker cannot forge a reply. An attacker who *can* see our request can
//! forge freely, which is precisely why `AllowUnauthenticated` defaults to
//! off and why an unauthenticated source is labelled as such in every
//! listing.
//!
//! Neither defends against an attacker who can delay traffic in one
//! direction. Nothing can; see [`crate::sample`].

use std::net::SocketAddr;

use ntp::nts::{self, Keys, COOKIE_TARGET, MAX_COOKIE};
use ntp::{
    ExtensionField, LeapIndicator, Mode, NtpTimestamp, Packet, ReferenceId, NTS_AUTHENTICATOR,
    NTS_COOKIE, NTS_COOKIE_PLACEHOLDER, NTS_UNIQUE_IDENTIFIER,
};

use crate::clock::Leap;
use crate::filter::{ClockFilter, Filtered};
use crate::random;
use crate::sample::{Exchange, Sample, SampleError};

/// The unique identifier's length. RFC 8915 §5.3 requires at least 32 bytes
/// and that it be "generated using a cryptographically secure random number
/// generator", which is the whole of its job.
pub const UNIQUE_ID_LEN: usize = 32;

/// Default poll bounds, as log2 seconds: 64 seconds to about 17 minutes.
///
/// The lower bound is a courtesy to the operators of the public servers we
/// are pointed at by default; the upper bound is where a crystal's drift
/// starts to exceed what the frequency estimate can hold between polls.
pub const DEFAULT_MIN_POLL: i8 = 6;
pub const DEFAULT_MAX_POLL: i8 = 10;
/// Never poll faster than this, whatever the registry says. Sixteen seconds
/// is already brisk for a public server, and a configuration error should
/// not be able to turn this machine into a nuisance.
pub const POLL_FLOOR: i8 = 4;
pub const POLL_CEILING: i8 = 17;

/// The largest round trip we will take a measurement from. Beyond this the
/// symmetry error a path attacker could hide in is larger than any accuracy
/// worth having.
pub const MAX_DELAY: f64 = 1.0;

/// Requests sent in the initial burst. RFC 5905's BCOUNT is 8; four is
/// enough to fill the filter's most useful slots and is half the load on a
/// public server at the moment every client on a network boots at once.
pub const BURST: u32 = 4;

/// How long to wait for a reply before counting the poll lost.
pub const REPLY_TIMEOUT: f64 = 5.0;

/// What we sent and are waiting to have echoed back.
#[derive(Debug, Clone)]
pub struct Pending {
    /// The transmit timestamp we put in the packet. For a plain source this
    /// is a random number rather than the time, because it is the only
    /// unguessable thing in the exchange.
    pub transmit: NtpTimestamp,
    /// What our clock actually read when we sent, which is the T1 the
    /// measurement needs.
    pub origin: NtpTimestamp,
    /// The NTS unique identifier, when NTS is in use.
    pub unique_id: Option<Vec<u8>>,
    /// The key the reply will be authenticated with.
    pub s2c: Option<[u8; nts::KEY_LEN]>,
    /// Monotonic time of the send, for the timeout.
    pub sent_at: f64,
}

/// Why a reply was not turned into a measurement.
#[derive(Debug, Clone, PartialEq)]
pub enum Rejected {
    /// Not a well-formed NTP packet.
    Malformed(String),
    /// Not a server-mode NTPv4 reply.
    NotAReply,
    /// The origin timestamp does not echo what we sent. Either a reply to
    /// a request we have forgotten, or a forgery. Counted, never acted on.
    WrongOrigin,
    /// The NTS unique identifier does not match ours.
    WrongIdentifier,
    /// The authenticator did not verify, or the reply carried none where
    /// one was required.
    NotAuthentic,
    /// The server says it is not synchronised, or is at stratum 16.
    Unsynchronised,
    /// A kiss of death: the server is telling us something rather than the
    /// time.
    Kiss(ReferenceId),
    /// The measurement itself was unusable.
    Unusable(SampleError),
}

impl std::fmt::Display for Rejected {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Rejected::Malformed(why) => write!(f, "malformed: {why}"),
            Rejected::NotAReply => write!(f, "not a server-mode NTPv4 reply"),
            Rejected::WrongOrigin => write!(f, "origin timestamp does not echo our request"),
            Rejected::WrongIdentifier => write!(f, "NTS unique identifier does not match"),
            Rejected::NotAuthentic => write!(f, "not authentic"),
            Rejected::Unsynchronised => write!(f, "the server is not synchronised"),
            Rejected::Kiss(code) => write!(f, "kiss of death: {code}"),
            Rejected::Unusable(e) => write!(f, "unusable measurement: {e:?}"),
        }
    }
}

/// How a source authenticates.
#[derive(Debug, Default)]
pub enum Security {
    /// NTS, with keys and cookies from a completed NTS-KE handshake.
    Nts { keys: Keys, cookies: Vec<Vec<u8>> },
    /// NTS, but the handshake has not happened or the cookies ran out.
    /// Polling is suspended until it does — an NTS source never silently
    /// falls back to plain NTP, because that is exactly the downgrade the
    /// protocol exists to prevent.
    #[default]
    NtsPending,
    /// Plain NTP, only ever when `AllowUnauthenticated` says so.
    Unauthenticated,
}

impl Security {
    pub fn is_nts(&self) -> bool {
        matches!(self, Security::Nts { .. } | Security::NtsPending)
    }

    pub fn cookies(&self) -> usize {
        match self {
            Security::Nts { cookies, .. } => cookies.len(),
            _ => 0,
        }
    }
}

/// One polled server.
#[derive(Debug)]
pub struct Source {
    /// The configured name — what the operator recognises and what an NTS
    /// certificate is validated against.
    pub name: String,
    /// The address currently in use.
    pub address: SocketAddr,
    pub security: Security,
    pub filter: ClockFilter,
    /// Last eight polls, newest in the low bit. `0o377` is eight for eight.
    pub reach: u8,
    /// Current poll interval, log2 seconds.
    pub poll: i8,
    pub min_poll: i8,
    pub max_poll: i8,
    /// Monotonic time of the next poll.
    pub next_poll: f64,
    /// Outstanding request, if any.
    pub pending: Option<Pending>,
    /// Bursts left in the initial run.
    pub burst: u32,
    /// What the server last told us about itself.
    pub stratum: u8,
    pub leap: LeapIndicator,
    pub reference_id: ReferenceId,
    pub root_delay: f64,
    pub root_dispersion: f64,
    pub precision: i8,
    /// Monotonic time of the last accepted reply.
    pub last_reply: Option<f64>,
    /// Why this source is currently not contributing, for the listing.
    pub note: Option<String>,
    /// Set when the server sent a RATE kiss. Polling backs off and does not
    /// come back down until the source has been quiet and well-behaved for
    /// a while — being told to slow down is not something to argue with.
    pub rate_limited: bool,
}

impl Source {
    pub fn new(name: String, address: SocketAddr, security: Security, min: i8, max: i8) -> Source {
        let min_poll = min.clamp(POLL_FLOOR, POLL_CEILING);
        let max_poll = max.clamp(min_poll, POLL_CEILING);
        Source {
            name,
            address,
            security,
            filter: ClockFilter::new(),
            reach: 0,
            poll: min_poll,
            min_poll,
            max_poll,
            next_poll: 0.0,
            pending: None,
            burst: BURST,
            stratum: 16,
            leap: LeapIndicator::Unsynchronised,
            reference_id: ReferenceId::default(),
            root_delay: 0.0,
            root_dispersion: 0.0,
            precision: -20,
            last_reply: None,
            note: None,
            rate_limited: false,
        }
    }

    pub fn is_reachable(&self) -> bool {
        self.reach != 0
    }

    /// Is this source in a state where polling it makes sense?
    ///
    /// An NTS source with no cookies is not: sending a plain request would
    /// be a silent downgrade, and sending an NTS request without a cookie
    /// is not a thing the protocol has.
    pub fn can_poll(&self) -> bool {
        !matches!(self.security, Security::NtsPending)
            && !matches!(&self.security, Security::Nts { cookies, .. } if cookies.is_empty())
    }

    pub fn filtered(&self, now: f64) -> Option<Filtered> {
        self.filter.peek(now)
    }

    /// Build a request.
    ///
    /// Consumes one cookie when NTS is in use, and asks for enough
    /// replacements to get back to a full set — the placeholders are what
    /// make the request as large as the reply, so that NTS cannot be used
    /// to amplify traffic at somebody else.
    pub fn prepare(&mut self, wall: NtpTimestamp, monotonic: f64) -> std::io::Result<Vec<u8>> {
        let mut packet = Packet {
            mode: Mode::Client,
            version: ntp::VERSION,
            poll: self.poll,
            ..Packet::default()
        };

        // The transmit timestamp is a nonce, not a time. Nothing in the
        // protocol needs the server to see our clock — it echoes this field
        // and we compare it, which is all it is for — and putting the real
        // time there both leaks the clock and makes the echo guessable.
        let transmit = NtpTimestamp(random::u64_value()?);
        packet.transmit_timestamp = transmit;

        let mut pending = Pending {
            transmit,
            origin: wall,
            unique_id: None,
            s2c: None,
            sent_at: monotonic,
        };

        let bytes = match &mut self.security {
            Security::Nts { keys, cookies } => {
                let cookie = cookies.pop().expect("can_poll checked there is one");
                let unique_id = random::array::<UNIQUE_ID_LEN>()?.to_vec();

                packet.extensions.push(ExtensionField::new(
                    NTS_UNIQUE_IDENTIFIER,
                    unique_id.clone(),
                ));
                packet.extensions.push(ExtensionField::new(NTS_COOKIE, cookie.clone()));
                // One placeholder per cookie we want back. Each is the size
                // of a cookie, which is what keeps request and reply the
                // same size.
                let wanted = COOKIE_TARGET.saturating_sub(cookies.len() + 1);
                for _ in 0..wanted {
                    packet.extensions.push(ExtensionField::new(
                        NTS_COOKIE_PLACEHOLDER,
                        vec![0u8; cookie.len()],
                    ));
                }

                // The authenticator covers everything before it, so the
                // packet is encoded first and the field appended to those
                // exact bytes.
                let prefix = packet.encode();
                let nonce = random::array::<{ nts::NONCE_LEN }>()?;
                let authenticator = nts::seal_authenticator(&keys.c2s, &nonce, &prefix, &[])
                    .map_err(|e| std::io::Error::other(format!("sealing failed: {e}")))?;
                let mut bytes = prefix;
                authenticator.encode_into(&mut bytes);

                pending.unique_id = Some(unique_id);
                pending.s2c = Some(keys.s2c);
                bytes
            }
            Security::Unauthenticated => packet.encode(),
            Security::NtsPending => {
                return Err(std::io::Error::other("no cookies; NTS-KE has not completed"));
            }
        };

        self.pending = Some(pending);
        Ok(bytes)
    }

    /// Take a reply.
    ///
    /// The caller must already have confirmed the datagram came from
    /// [`Self::address`]; that is a property of the socket, not of the
    /// bytes, and doing it here would mean parsing before checking.
    pub fn accept(
        &mut self,
        bytes: &[u8],
        destination: NtpTimestamp,
        monotonic: f64,
    ) -> Result<Sample, Rejected> {
        let Some(pending) = self.pending.clone() else {
            return Err(Rejected::WrongOrigin);
        };

        let packet = Packet::decode(bytes).map_err(|e| Rejected::Malformed(e.to_string()))?;
        if packet.mode != Mode::Server || packet.version != ntp::VERSION {
            return Err(Rejected::NotAReply);
        }

        // The echo check, before anything in the packet is believed. For a
        // plain source this is the entire off-path defence, and it is an
        // exact 64-bit comparison against a value we chose at random.
        if packet.origin_timestamp != pending.transmit {
            return Err(Rejected::WrongOrigin);
        }

        // NTS, in the order that matters: identifier first (cheap, and
        // stops an attacker making us do AEAD work), then the tag.
        if let Some(expected) = &pending.unique_id {
            let field = packet
                .extension(NTS_UNIQUE_IDENTIFIER)
                .ok_or(Rejected::WrongIdentifier)?;
            if !constant_time_eq(&field.value, expected) {
                return Err(Rejected::WrongIdentifier);
            }
            let key = pending.s2c.ok_or(Rejected::NotAuthentic)?;
            let cookies = self.verify(&packet, bytes, &key)?;
            if let Security::Nts { cookies: held, .. } = &mut self.security {
                for cookie in cookies {
                    if held.len() < COOKIE_TARGET {
                        held.push(cookie);
                    }
                }
            }
        }

        // Authenticated, and therefore worth reading. A kiss of death is
        // checked here rather than earlier because acting on an
        // unauthenticated one would let anybody on the path shut this
        // source down by sending a DENY.
        if packet.is_kiss_of_death() {
            self.pending = None;
            return Err(Rejected::Kiss(packet.reference_id));
        }
        if packet.leap == LeapIndicator::Unsynchronised || packet.stratum >= 16 {
            self.pending = None;
            self.record_reply(monotonic);
            self.stratum = packet.stratum;
            self.leap = packet.leap;
            return Err(Rejected::Unsynchronised);
        }

        let exchange = Exchange {
            origin: pending.origin,
            receive: packet.receive_timestamp,
            transmit: packet.transmit_timestamp,
            destination,
        };
        let wall = destination_to_seconds(destination, pending.origin);
        let sample = exchange
            .reduce(self.precision, packet.precision, MAX_DELAY, wall)
            .map_err(Rejected::Unusable)?;

        self.pending = None;
        self.record_reply(monotonic);
        self.stratum = packet.stratum;
        self.leap = packet.leap;
        self.reference_id = packet.reference_id;
        self.root_delay = packet.root_delay.as_seconds_f64();
        self.root_dispersion = packet.root_dispersion.as_seconds_f64();
        self.note = None;
        Ok(sample)
    }

    /// Open the authenticator and return whatever cookies it carried.
    fn verify(
        &self,
        packet: &Packet,
        bytes: &[u8],
        key: &[u8; nts::KEY_LEN],
    ) -> Result<Vec<Vec<u8>>, Rejected> {
        let field = packet.extension(NTS_AUTHENTICATOR).ok_or(Rejected::NotAuthentic)?;
        // Where the authenticator begins in the datagram we received, which
        // is what its tag covers. Computed by walking the fields that
        // precede it rather than by re-encoding the parsed packet: the tag
        // is over the bytes the server sent, and a re-encoding proves only
        // that we can reproduce them.
        let mut at = ntp::HEADER_LEN;
        for f in &packet.extensions {
            if f.field_type == NTS_AUTHENTICATOR {
                break;
            }
            at += f.encoded_len();
        }
        let plaintext = nts::open_authenticator(key, bytes, at, &field.value)
            .map_err(|_| Rejected::NotAuthentic)?;

        // The encrypted part carries the replacement cookies.
        let mut cookies = Vec::new();
        for field in ExtensionField::decode_all(&plaintext).unwrap_or_default() {
            if field.field_type == NTS_COOKIE
                && !field.value.is_empty()
                && field.value.len() <= MAX_COOKIE
            {
                cookies.push(field.value);
            }
        }
        Ok(cookies)
    }

    fn record_reply(&mut self, monotonic: f64) {
        self.reach = (self.reach << 1) | 1;
        self.last_reply = Some(monotonic);
    }

    /// A poll went unanswered.
    pub fn record_loss(&mut self, monotonic: f64) {
        self.reach <<= 1;
        self.pending = None;
        if self.reach == 0 {
            // Nothing for eight polls. Everything the filter holds was
            // measured a long time ago against a clock that has drifted
            // since; keeping it would let a source that vanished go on
            // voting with stale numbers.
            self.filter.reset();
            self.note = Some("no reply for eight polls".into());
        }
        self.schedule(monotonic);
    }

    /// Set the next poll time, with the interval jittered.
    ///
    /// The jitter is not cosmetic. Every machine on a network boots at
    /// roughly the same time and would otherwise poll in lockstep forever,
    /// which is how a well-meaning fleet turns into a synchronised flood at
    /// somebody else's server. Spreading the interval by up to a quarter
    /// breaks the convoy on the first poll and keeps it broken.
    pub fn schedule(&mut self, monotonic: f64) {
        let interval = (2.0f64).powi(self.poll as i32);
        let spread = random::u64_value().unwrap_or(0) as f64 / u64::MAX as f64;
        self.next_poll = monotonic + interval * (1.0 + spread * 0.25);
    }

    /// Schedule the next poll of a burst: soon, but not immediately.
    pub fn schedule_burst(&mut self, monotonic: f64) {
        self.burst = self.burst.saturating_sub(1);
        if self.burst == 0 {
            self.schedule(monotonic);
        } else {
            // Two seconds apart, RFC 5905's BTIME. Fast enough to fill the
            // filter before anybody notices, slow enough not to look like
            // an attack to a rate limiter.
            self.next_poll = monotonic + 2.0;
        }
    }

    /// Adapt the poll interval to how well the clock is being held.
    ///
    /// Longer when things are calm — which is both kinder to the servers
    /// and more accurate, because a long interval measures frequency
    /// better than a short one measures phase. Shorter when the offset is
    /// moving faster than the source's own noise can explain, because
    /// something has changed and the loop needs data.
    pub fn adapt_poll(&mut self, system_offset: f64, system_jitter: f64) {
        if self.rate_limited {
            return;
        }
        let noisy = system_offset.abs() > 4.0 * system_jitter.max(1e-9);
        if noisy {
            self.poll = (self.poll - 1).max(self.min_poll);
        } else {
            self.poll = (self.poll + 1).min(self.max_poll);
        }
    }

    /// Obey a RATE kiss: back off to the maximum interval and stay there.
    ///
    /// Not negotiable and not clever. A server that says "slow down" is
    /// entitled to be obeyed, and a client that treats the request as
    /// advisory is the reason public NTP operators have to run rate
    /// limiters in the first place.
    pub fn back_off(&mut self, monotonic: f64) {
        self.rate_limited = true;
        self.poll = self.max_poll;
        self.note = Some("rate-limited by the server (KoD RATE)".into());
        self.schedule(monotonic);
    }

    /// The leap second this source is announcing, if any.
    pub fn announced_leap(&self) -> Leap {
        match self.leap {
            LeapIndicator::Insert => Leap::Insert,
            LeapIndicator::Delete => Leap::Delete,
            _ => Leap::None,
        }
    }

    /// Has the outstanding request timed out?
    pub fn timed_out(&self, monotonic: f64) -> bool {
        self.pending.as_ref().is_some_and(|p| monotonic - p.sent_at > REPLY_TIMEOUT)
    }
}

/// The wall-clock seconds a sample was taken, for ageing.
///
/// Derived from the origin timestamp plus the measured round trip rather
/// than read from the clock again, so that a sample's `at` is on the same
/// timeline as the timestamps it was computed from.
fn destination_to_seconds(destination: NtpTimestamp, origin: NtpTimestamp) -> f64 {
    let elapsed = destination.wrapping_sub(origin).as_seconds_f64();
    let (secs, nanos) = origin.to_unix_near(0);
    secs as f64 + nanos as f64 / 1e9 + elapsed
}

/// Compare without leaking where the difference is, through timing.
///
/// The unique identifier is not a secret — it travels in the clear in our
/// own request — so this is belt and braces rather than a load-bearing
/// defence. It costs one line and removes a question nobody should have to
/// think about again.
fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut difference = 0u8;
    for (x, y) in a.iter().zip(b) {
        difference |= x ^ y;
    }
    difference == 0
}

#[cfg(test)]
mod tests {
    use super::*;
    use ntp::NtpShort;

    fn address() -> SocketAddr {
        "192.0.2.1:123".parse().unwrap()
    }

    fn plain_source() -> Source {
        Source::new(
            "test".into(),
            address(),
            Security::Unauthenticated,
            DEFAULT_MIN_POLL,
            DEFAULT_MAX_POLL,
        )
    }

    fn nts_source(cookies: usize) -> Source {
        Source::new(
            "test".into(),
            address(),
            Security::Nts {
                keys: Keys { c2s: [1; nts::KEY_LEN], s2c: [2; nts::KEY_LEN] },
                cookies: (0..cookies).map(|i| vec![i as u8; 100]).collect(),
            },
            DEFAULT_MIN_POLL,
            DEFAULT_MAX_POLL,
        )
    }

    /// A cooperative server: echo the origin, add plausible timestamps.
    fn reply_to(request: &[u8], offset_seconds: i64) -> Packet {
        let asked = Packet::decode(request).unwrap();
        let base = NtpTimestamp::from_unix(1_756_000_000 + offset_seconds, 0);
        Packet {
            mode: Mode::Server,
            version: 4,
            stratum: 2,
            precision: -24,
            root_delay: NtpShort::from_seconds_f64(0.01),
            root_dispersion: NtpShort::from_seconds_f64(0.001),
            reference_id: ReferenceId([192, 0, 2, 9]),
            reference_timestamp: base,
            origin_timestamp: asked.transmit_timestamp,
            receive_timestamp: base,
            transmit_timestamp: base,
            ..Packet::default()
        }
    }

    #[test]
    fn a_plain_request_carries_a_random_nonce_not_the_time() {
        // If the transmit timestamp were the clock, an off-path attacker
        // who knows roughly what time it is could guess it. Two requests a
        // moment apart must be unrelated numbers, not adjacent ones.
        let mut source = plain_source();
        let wall = NtpTimestamp::from_unix(1_756_000_000, 0);
        let a = Packet::decode(&source.prepare(wall, 0.0).unwrap()).unwrap();
        let b = Packet::decode(&source.prepare(wall, 0.0).unwrap()).unwrap();
        assert_ne!(a.transmit_timestamp, b.transmit_timestamp);
        assert_ne!(a.transmit_timestamp, wall);
        let gap = a.transmit_timestamp.0.abs_diff(b.transmit_timestamp.0);
        assert!(gap > 1 << 40, "the two nonces are suspiciously close");
    }

    #[test]
    fn a_reply_that_does_not_echo_our_nonce_is_refused() {
        let mut source = plain_source();
        let wall = NtpTimestamp::from_unix(1_756_000_000, 0);
        let request = source.prepare(wall, 0.0).unwrap();

        let mut forged = reply_to(&request, 0);
        forged.origin_timestamp = NtpTimestamp(0xDEAD_BEEF_DEAD_BEEF);
        let destination = NtpTimestamp::from_unix(1_756_000_000, 50_000_000);
        assert_eq!(
            source.accept(&forged.encode(), destination, 1.0),
            Err(Rejected::WrongOrigin)
        );
        // And the source is not marked reachable by a forgery.
        assert!(!source.is_reachable());
    }

    #[test]
    fn a_well_formed_reply_becomes_a_measurement() {
        let mut source = plain_source();
        let wall = NtpTimestamp::from_unix(1_756_000_000, 0);
        let request = source.prepare(wall, 0.0).unwrap();
        let reply = reply_to(&request, 0).encode();
        let destination = NtpTimestamp::from_unix(1_756_000_000, 50_000_000);
        let sample = source.accept(&reply, destination, 1.0).unwrap();
        assert!(sample.delay > 0.0);
        assert!(source.is_reachable());
        assert_eq!(source.stratum, 2);
        assert!(source.pending.is_none(), "the request must be consumed");
    }

    #[test]
    fn a_reply_from_a_mode_or_version_we_did_not_ask_for_is_refused() {
        let mut source = plain_source();
        let wall = NtpTimestamp::from_unix(1_756_000_000, 0);
        let request = source.prepare(wall, 0.0).unwrap();
        let destination = NtpTimestamp::from_unix(1_756_000_000, 50_000_000);

        let mut broadcast = reply_to(&request, 0);
        broadcast.mode = Mode::Broadcast;
        assert_eq!(source.accept(&broadcast.encode(), destination, 1.0), Err(Rejected::NotAReply));

        let mut old = reply_to(&request, 0);
        old.version = 3;
        assert_eq!(source.accept(&old.encode(), destination, 1.0), Err(Rejected::NotAReply));
    }

    #[test]
    fn an_unsynchronised_server_is_recorded_as_reachable_but_unusable() {
        let mut source = plain_source();
        let wall = NtpTimestamp::from_unix(1_756_000_000, 0);
        let request = source.prepare(wall, 0.0).unwrap();
        let mut reply = reply_to(&request, 0);
        reply.leap = LeapIndicator::Unsynchronised;
        let destination = NtpTimestamp::from_unix(1_756_000_000, 50_000_000);
        assert_eq!(
            source.accept(&reply.encode(), destination, 1.0),
            Err(Rejected::Unsynchronised)
        );
        // It answered, so it is reachable — the distinction matters to an
        // operator trying to work out whether the network or the server is
        // the problem.
        assert!(source.is_reachable());
    }

    #[test]
    fn an_nts_request_spends_a_cookie_and_asks_for_replacements() {
        let mut source = nts_source(3);
        let wall = NtpTimestamp::from_unix(1_756_000_000, 0);
        let bytes = source.prepare(wall, 0.0).unwrap();
        let packet = Packet::decode(&bytes).unwrap();

        assert_eq!(source.security.cookies(), 2, "one cookie was spent");
        assert!(packet.extension(NTS_UNIQUE_IDENTIFIER).is_some());
        assert!(packet.extension(NTS_COOKIE).is_some());
        assert!(packet.extension(NTS_AUTHENTICATOR).is_some());

        // Enough placeholders to get back to a full set: we hold 2 and are
        // spending 1, so 8 − 3 = 5 more are wanted.
        let placeholders =
            packet.extensions.iter().filter(|f| f.field_type == NTS_COOKIE_PLACEHOLDER).count();
        assert_eq!(placeholders, COOKIE_TARGET - 3);
    }

    #[test]
    fn a_placeholder_makes_the_request_at_least_as_large_as_the_reply() {
        // The anti-amplification property. Without placeholders a small
        // request draws a reply carrying eight fresh cookies, which is
        // exactly the shape of a reflection attack.
        let mut source = nts_source(1);
        let wall = NtpTimestamp::from_unix(1_756_000_000, 0);
        let request = source.prepare(wall, 0.0).unwrap();
        // A reply carrying a full set of cookies of the same size.
        let cookie_bytes = COOKIE_TARGET * (100 + 4);
        assert!(
            request.len() >= cookie_bytes,
            "request {} is smaller than a full cookie reply {}",
            request.len(),
            cookie_bytes
        );
    }

    #[test]
    fn an_nts_reply_must_authenticate() {
        let mut source = nts_source(4);
        let wall = NtpTimestamp::from_unix(1_756_000_000, 0);
        let request = source.prepare(wall, 0.0).unwrap();
        let asked = Packet::decode(&request).unwrap();
        let destination = NtpTimestamp::from_unix(1_756_000_000, 50_000_000);

        // Echoing the nonce and the identifier is not enough without the
        // tag: this is the packet an attacker who watched the request could
        // build.
        let mut reply = reply_to(&request, 0);
        reply.extensions.push(asked.extension(NTS_UNIQUE_IDENTIFIER).unwrap().clone());
        assert_eq!(
            source.accept(&reply.encode(), destination, 1.0),
            Err(Rejected::NotAuthentic)
        );
    }

    #[test]
    fn an_authentic_nts_reply_is_accepted_and_its_cookies_kept() {
        let s2c = [2u8; nts::KEY_LEN];
        let mut source = nts_source(2);
        let wall = NtpTimestamp::from_unix(1_756_000_000, 0);
        let request = source.prepare(wall, 0.0).unwrap();
        let asked = Packet::decode(&request).unwrap();

        // Build the reply as a real server would: header and identifier,
        // then an authenticator whose ciphertext holds fresh cookies.
        let mut reply = reply_to(&request, 0);
        reply.extensions.push(asked.extension(NTS_UNIQUE_IDENTIFIER).unwrap().clone());
        let prefix = reply.encode();
        let mut plaintext = Vec::new();
        for i in 0..3u8 {
            ExtensionField::new(NTS_COOKIE, vec![0xC0 | i; 100]).encode_into(&mut plaintext);
        }
        let authenticator =
            nts::seal_authenticator(&s2c, &[7u8; nts::NONCE_LEN], &prefix, &plaintext).unwrap();
        let mut bytes = prefix;
        authenticator.encode_into(&mut bytes);

        let destination = NtpTimestamp::from_unix(1_756_000_000, 50_000_000);
        source.accept(&bytes, destination, 1.0).expect("an authentic reply is accepted");
        // One spent, three returned.
        assert_eq!(source.security.cookies(), 4);
    }

    #[test]
    fn a_tampered_nts_reply_is_refused() {
        let s2c = [2u8; nts::KEY_LEN];
        let mut source = nts_source(2);
        let wall = NtpTimestamp::from_unix(1_756_000_000, 0);
        let request = source.prepare(wall, 0.0).unwrap();
        let asked = Packet::decode(&request).unwrap();

        let mut reply = reply_to(&request, 0);
        reply.extensions.push(asked.extension(NTS_UNIQUE_IDENTIFIER).unwrap().clone());
        let prefix = reply.encode();
        let authenticator =
            nts::seal_authenticator(&s2c, &[7u8; nts::NONCE_LEN], &prefix, &[]).unwrap();
        let mut bytes = prefix;
        authenticator.encode_into(&mut bytes);

        // Move the server's transmit timestamp by an hour — the whole point
        // of the attack — leaving the tag as it was.
        bytes[40] = bytes[40].wrapping_add(1);
        let destination = NtpTimestamp::from_unix(1_756_000_000, 50_000_000);
        assert_eq!(source.accept(&bytes, destination, 1.0), Err(Rejected::NotAuthentic));
    }

    #[test]
    fn an_nts_source_without_cookies_is_not_polled() {
        let source = nts_source(0);
        assert!(!source.can_poll(), "polling without a cookie would be a silent downgrade");
        let pending = Source::new(
            "test".into(),
            address(),
            Security::NtsPending,
            DEFAULT_MIN_POLL,
            DEFAULT_MAX_POLL,
        );
        assert!(!pending.can_poll());
        assert!(plain_source().can_poll());
    }

    #[test]
    fn eight_lost_polls_clear_the_filter() {
        let mut source = plain_source();
        let wall = NtpTimestamp::from_unix(1_756_000_000, 0);
        let request = source.prepare(wall, 0.0).unwrap();
        let destination = NtpTimestamp::from_unix(1_756_000_000, 50_000_000);
        let sample = source.accept(&reply_to(&request, 0).encode(), destination, 1.0).unwrap();
        source.filter.insert(sample, 1.0);
        assert!(!source.filter.is_empty());

        for i in 0..8 {
            source.record_loss(i as f64);
        }
        assert_eq!(source.reach, 0);
        assert!(source.filter.is_empty(), "a vanished source must stop voting");
        assert!(source.note.is_some());
    }

    #[test]
    fn the_reach_register_shifts_the_way_the_classic_display_reads() {
        let mut source = plain_source();
        source.record_reply(0.0);
        assert_eq!(source.reach, 0b1);
        source.record_reply(0.0);
        assert_eq!(source.reach, 0b11);
        source.record_loss(0.0);
        assert_eq!(source.reach, 0b110);
        // The lost poll stays visible in the register for eight more
        // polls, which is the point of it: `377` means the last eight all
        // answered, and anything else says how recently one did not.
        for _ in 0..7 {
            source.record_reply(0.0);
        }
        assert_eq!(source.reach, 0b0111_1111, "the lost poll is the high zero");
        source.record_reply(0.0);
        assert_eq!(source.reach, 0o377, "eight for eight");
    }

    #[test]
    fn the_poll_interval_stays_inside_its_bounds() {
        let mut source = plain_source();
        for _ in 0..50 {
            source.adapt_poll(0.0, 1.0);
        }
        assert_eq!(source.poll, DEFAULT_MAX_POLL);
        for _ in 0..50 {
            source.adapt_poll(1.0, 1e-9);
        }
        assert_eq!(source.poll, DEFAULT_MIN_POLL);
    }

    #[test]
    fn a_rate_kiss_pins_the_poll_at_the_maximum() {
        let mut source = plain_source();
        source.back_off(0.0);
        assert_eq!(source.poll, DEFAULT_MAX_POLL);
        // And a calm clock must not talk it back down.
        source.adapt_poll(1.0, 1e-9);
        assert_eq!(source.poll, DEFAULT_MAX_POLL);
    }

    #[test]
    fn poll_scheduling_is_spread_so_a_fleet_does_not_march_in_step() {
        let mut source = plain_source();
        let mut times = Vec::new();
        for _ in 0..20 {
            source.schedule(0.0);
            times.push(source.next_poll);
        }
        let base = (2.0f64).powi(DEFAULT_MIN_POLL as i32);
        assert!(times.iter().all(|&t| t >= base && t <= base * 1.25));
        let distinct: std::collections::BTreeSet<u64> =
            times.iter().map(|t| t.to_bits()).collect();
        assert!(distinct.len() > 15, "the interval is barely being spread");
    }

    #[test]
    fn a_configuration_error_cannot_make_us_a_nuisance() {
        let source = Source::new("test".into(), address(), Security::Unauthenticated, -100, 100);
        assert_eq!(source.min_poll, POLL_FLOOR);
        assert!(source.max_poll <= POLL_CEILING);
        // And an inverted pair does not produce a range with no values.
        let inverted = Source::new("t".into(), address(), Security::Unauthenticated, 12, 5);
        assert!(inverted.max_poll >= inverted.min_poll);
    }
}
