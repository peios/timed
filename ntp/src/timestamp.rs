//! NTP's two time formats, and the era problem.
//!
//! An NTP timestamp is 64 bits: 32 bits of seconds since 1900-01-01 UTC and
//! 32 bits of binary fraction, giving a resolution of about 233 picoseconds
//! and a range of 136 years. The range is the interesting part, because it
//! ran out once already (1968) and runs out again on **2036-02-07**, and a
//! client written as though it will not is a client with a deadline.
//!
//! The fix is to never interpret a timestamp on its own. Every quantity NTP
//! actually computes — the offset, the round-trip delay, the dispersion — is
//! a *difference* between two timestamps taken within seconds of each other,
//! and a difference is era-independent: subtract the raw 64-bit values with
//! wrapping arithmetic, read the result as signed, and it is correct across
//! the 2036 boundary for any interval shorter than 68 years. So differences
//! are the primitive here ([`NtpDuration`]), and converting a bare timestamp
//! to a wall-clock date — the one operation that genuinely needs to know the
//! era — is done only against a reference time we already hold.

use core::fmt;

/// Seconds between 1900-01-01 and 1970-01-01, the offset between NTP era 0
/// and the Unix epoch. Includes the leap day of 1900, which was not one:
/// 1900 is divisible by 100 and not by 400, so it was a common year.
pub const UNIX_TO_NTP_ERA0: u64 = 2_208_988_800;

/// A 64-bit NTP timestamp: 32.32 fixed point, unsigned, era-relative.
///
/// Stored raw and compared raw. Ordering is *not* implemented on purpose:
/// two timestamps in different eras compare the wrong way round, and the
/// question a caller means to ask ("is this later?") is answered correctly
/// only by subtracting and looking at the sign.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Hash)]
pub struct NtpTimestamp(pub u64);

/// A signed interval in the same 32.32 fixed point.
///
/// This is what everything downstream actually works in. `i64` holds ±68
/// years of it, which is longer than any interval a time client has an
/// opinion about.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Default)]
pub struct NtpDuration(pub i64);

/// One second, as the fixed-point unit.
const ONE_SECOND: i64 = 1 << 32;

impl NtpTimestamp {
    /// The all-zero timestamp, which NTP gives the specific meaning
    /// "unknown" rather than "1900-01-01". A server that has never
    /// synchronised sends it as its reference timestamp.
    pub const UNKNOWN: NtpTimestamp = NtpTimestamp(0);

    /// From a Unix time. `nanos` is truncated toward zero, which loses at
    /// most one 233-picosecond tick and cannot produce a value in the
    /// future.
    pub fn from_unix(seconds: i64, nanos: u32) -> NtpTimestamp {
        // Wrapping is correct and intended: a Unix time past 2036 lands in
        // era 1, which is exactly where it belongs.
        let secs = (seconds as u64).wrapping_add(UNIX_TO_NTP_ERA0) as u32;
        let frac = ((nanos.min(999_999_999) as u64) << 32) / 1_000_000_000;
        NtpTimestamp(((secs as u64) << 32) | frac)
    }

    /// The Unix time this timestamp denotes, choosing the era that puts it
    /// nearest `near`.
    ///
    /// The era is not in the message, so it has to come from somewhere, and
    /// the only honest source is a time we already believe. Every caller of
    /// this has one: the local clock at the moment the packet arrived.
    /// Ambiguity is resolved to within ±68 years, which is not a limitation
    /// anybody will meet.
    pub fn to_unix_near(self, near_unix_seconds: i64) -> (i64, u32) {
        let near = NtpTimestamp::from_unix(near_unix_seconds, 0);
        // The difference carries the era correction; adding it back to a
        // time we know gives a time in the right era by construction.
        let delta = self.wrapping_sub(near);
        let seconds = near_unix_seconds + delta.whole_seconds();
        (seconds, delta.subsec_nanos())
    }

    /// The interval from `earlier` to `self`, correct across an era change.
    pub fn wrapping_sub(self, earlier: NtpTimestamp) -> NtpDuration {
        NtpDuration(self.0.wrapping_sub(earlier.0) as i64)
    }

    /// Advance by an interval.
    pub fn wrapping_add(self, by: NtpDuration) -> NtpTimestamp {
        NtpTimestamp(self.0.wrapping_add(by.0 as u64))
    }

    /// The whole seconds field, for the reference-timestamp comparisons that
    /// genuinely want it and nothing else.
    pub fn seconds(self) -> u32 {
        (self.0 >> 32) as u32
    }

    /// True when the server said "I have never been synchronised".
    pub fn is_unknown(self) -> bool {
        self.0 == 0
    }
}

impl NtpDuration {
    pub const ZERO: NtpDuration = NtpDuration(0);

    /// From seconds as a float. Saturates rather than wrapping: a
    /// discipline computation that produced an absurd number should clamp
    /// to an absurd-but-representable one and be rejected by policy above,
    /// not silently become a small number of the opposite sign.
    pub fn from_seconds_f64(seconds: f64) -> NtpDuration {
        if seconds.is_nan() {
            return NtpDuration::ZERO;
        }
        let scaled = seconds * ONE_SECOND as f64;
        if scaled >= i64::MAX as f64 {
            NtpDuration(i64::MAX)
        } else if scaled <= i64::MIN as f64 {
            NtpDuration(i64::MIN)
        } else {
            NtpDuration(scaled as i64)
        }
    }

    pub fn as_seconds_f64(self) -> f64 {
        self.0 as f64 / ONE_SECOND as f64
    }

    /// Whole seconds, truncated toward negative infinity so that the
    /// seconds/nanoseconds pair it forms with [`Self::subsec_nanos`] is
    /// always a sum rather than a sum-or-difference.
    pub fn whole_seconds(self) -> i64 {
        self.0.div_euclid(ONE_SECOND)
    }

    /// The remaining fraction, in nanoseconds, always non-negative.
    pub fn subsec_nanos(self) -> u32 {
        let frac = self.0.rem_euclid(ONE_SECOND) as u64;
        ((frac * 1_000_000_000) >> 32) as u32
    }

    pub fn abs(self) -> NtpDuration {
        NtpDuration(self.0.saturating_abs())
    }

    pub fn is_negative(self) -> bool {
        self.0 < 0
    }
}

impl core::ops::Add for NtpDuration {
    type Output = NtpDuration;
    fn add(self, rhs: NtpDuration) -> NtpDuration {
        NtpDuration(self.0.saturating_add(rhs.0))
    }
}

impl core::ops::Sub for NtpDuration {
    type Output = NtpDuration;
    fn sub(self, rhs: NtpDuration) -> NtpDuration {
        NtpDuration(self.0.saturating_sub(rhs.0))
    }
}

impl core::ops::Div<i64> for NtpDuration {
    type Output = NtpDuration;
    fn div(self, rhs: i64) -> NtpDuration {
        if rhs == 0 { NtpDuration::ZERO } else { NtpDuration(self.0 / rhs) }
    }
}

impl fmt::Display for NtpDuration {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:+.9}s", self.as_seconds_f64())
    }
}

/// NTP's 32-bit "short" format: 16.16 fixed point, unsigned. Root delay and
/// root dispersion travel in it, which is why both saturate at about 18
/// hours — a bound worth knowing when a server reports an implausible one.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Default)]
pub struct NtpShort(pub u32);

impl NtpShort {
    pub fn from_seconds_f64(seconds: f64) -> NtpShort {
        if seconds.is_nan() || seconds <= 0.0 {
            return NtpShort(0);
        }
        let scaled = seconds * 65536.0;
        NtpShort(if scaled >= u32::MAX as f64 { u32::MAX } else { scaled as u32 })
    }

    pub fn as_seconds_f64(self) -> f64 {
        self.0 as f64 / 65536.0
    }

    pub fn as_duration(self) -> NtpDuration {
        NtpDuration((self.0 as i64) << 16)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_unix_epoch_is_where_rfc_5905_says() {
        // 1970-01-01 is 2 208 988 800 seconds into era 0.
        assert_eq!(NtpTimestamp::from_unix(0, 0).seconds(), UNIX_TO_NTP_ERA0 as u32);
    }

    #[test]
    fn a_difference_survives_the_2036_rollover() {
        // Two timestamps a second apart, straddling the end of era 0:
        // 2036-02-07T06:28:15Z and :16Z. Naive subtraction of the seconds
        // fields would give -4 294 967 295 rather than 1.
        let last = NtpTimestamp(0xFFFF_FFFF_0000_0000);
        let first = NtpTimestamp(0x0000_0000_0000_0000);
        assert_eq!(first.wrapping_sub(last), NtpDuration(ONE_SECOND));
        assert_eq!(last.wrapping_sub(first), NtpDuration(-ONE_SECOND));
    }

    #[test]
    fn round_trip_through_unix_keeps_the_era() {
        // A time well into era 1: 2040-01-01, ~2 208 988 800 + 2 208 988 800.
        let unix = 2_208_988_800i64;
        let ts = NtpTimestamp::from_unix(unix, 500_000_000);
        let (secs, nanos) = ts.to_unix_near(unix);
        assert_eq!(secs, unix);
        // The fixed point cannot hold exactly half a second's worth of
        // nanoseconds; one tick of slack is the format, not a bug.
        assert!(nanos.abs_diff(500_000_000) <= 1, "{nanos}");
    }

    #[test]
    fn negative_durations_split_into_a_sum_not_a_difference() {
        let d = NtpDuration::from_seconds_f64(-1.25);
        assert_eq!(d.whole_seconds(), -2);
        assert!(d.subsec_nanos().abs_diff(750_000_000) <= 1);
        assert_eq!(d.whole_seconds() as f64 + d.subsec_nanos() as f64 / 1e9, -1.25);
    }

    #[test]
    fn absurd_floats_saturate_rather_than_wrap() {
        assert_eq!(NtpDuration::from_seconds_f64(f64::INFINITY), NtpDuration(i64::MAX));
        assert_eq!(NtpDuration::from_seconds_f64(f64::NEG_INFINITY), NtpDuration(i64::MIN));
        assert_eq!(NtpDuration::from_seconds_f64(f64::NAN), NtpDuration::ZERO);
        assert_eq!(NtpShort::from_seconds_f64(1e30), NtpShort(u32::MAX));
    }
}
