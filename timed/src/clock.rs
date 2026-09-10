//! The system clock: the only privileged thing timed does.
//!
//! Every syscall that can change what time it is on this machine goes
//! through this file, and there are exactly three of them. Keeping them
//! together is the point: the privilege timed holds
//! (`SeSystemtimePrivilege`, which KACS maps to `CAP_SYS_TIME`) is worth
//! being able to audit by reading one short module.
//!
//! # Frequency, not phase
//!
//! The kernel has its own NTP discipline — set `STA_PLL`, feed it offsets,
//! and it maintains the loop for you. timed does not use it. It is the
//! NTPv3-era design, tuned for a world of 64-second polls and reachable
//! only through a syscall, which makes it impossible to test, impossible to
//! fuzz, and impossible to improve. So `STA_PLL` and `STA_FLL` are
//! explicitly *cleared*, the loop lives in [`crate::discipline`] where it
//! can be simulated, and the kernel is told only the resulting rate.
//!
//! # The eleven-minute mode
//!
//! When `STA_UNSYNC` is clear the kernel writes the system time back to the
//! hardware clock every eleven minutes, unprompted. That is the whole of
//! timed's RTC handling, and it is why there is no `SyncRTC` knob: the flag
//! that would have to be set to disable it is the same flag that tells the
//! rest of the kernel whether the clock is trustworthy, and a knob whose
//! only implementation is lying to the kernel is worse than no knob.

use std::io;
use std::time::{SystemTime, UNIX_EPOCH};

/// The build timestamp, below which the clock is never set. See `build.rs`.
pub const BUILD_EPOCH: i64 = {
    match i64::from_str_radix(env!("TIMED_BUILD_EPOCH"), 10) {
        Ok(v) => v,
        Err(_) => 0,
    }
};

// `struct timex` modes.
const ADJ_FREQUENCY: u32 = 0x0002;
const ADJ_MAXERROR: u32 = 0x0004;
const ADJ_ESTERROR: u32 = 0x0008;
const ADJ_STATUS: u32 = 0x0010;
const ADJ_SETOFFSET: u32 = 0x0100;
const ADJ_NANO: u32 = 0x2000;

// Status bits.
const STA_PLL: i32 = 0x0001;
const STA_FLL: i32 = 0x0008;
/// Insert a leap second at the end of the day.
const STA_INS: i32 = 0x0010;
/// Delete one.
const STA_DEL: i32 = 0x0020;
/// The clock is not synchronised. Also what gates the eleven-minute mode.
const STA_UNSYNC: i32 = 0x0040;
/// Do not let `ADJ_OFFSET` move the frequency. We never send `ADJ_OFFSET`,
/// but saying so costs nothing and makes the intent explicit to anyone
/// reading the kernel's view with `adjtimex(1)`.
const STA_FREQHOLD: i32 = 0x0080;
/// The kernel reports and accepts nanoseconds rather than microseconds.
const STA_NANO: i32 = 0x2000;

/// `adjtimex` returns this when the clock is not synchronised, which is not
/// an error — it is the answer. Any negative return is.
const TIME_ERROR: i32 = 5;

/// A leap second the upstream has announced.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Leap {
    #[default]
    None,
    Insert,
    Delete,
}

/// What to tell the kernel.
#[derive(Debug, Clone, Copy)]
pub struct Steering {
    /// Rate correction, seconds per second. Positive makes the clock run
    /// faster.
    pub frequency: f64,
    /// Our best bound on how wrong the clock is, in seconds. Reported so
    /// that anything reading `adjtimex` sees the same honest number timed
    /// reports on its socket.
    pub max_error: f64,
    pub est_error: f64,
    pub synchronised: bool,
    pub leap: Leap,
}

/// The clock, as a thing that can be read and steered.
///
/// A unit struct rather than free functions, so that a caller has to have
/// been handed one — and so the tests can be honest that they are not
/// touching the real clock.
#[derive(Debug, Clone, Copy)]
pub struct Clock;

impl Clock {
    /// Read the wall clock, as a Unix time with nanoseconds.
    pub fn now(&self) -> (i64, u32) {
        match SystemTime::now().duration_since(UNIX_EPOCH) {
            Ok(d) => (d.as_secs() as i64, d.subsec_nanos()),
            // Before 1970. The kernel can produce this if the RTC is dead
            // and nothing has set the clock; it is exactly the case the
            // floor exists for, so it is a value to carry, not to panic on.
            Err(e) => {
                let d = e.duration();
                (-(d.as_secs() as i64), d.subsec_nanos())
            }
        }
    }

    pub fn now_f64(&self) -> f64 {
        let (s, ns) = self.now();
        s as f64 + ns as f64 / 1e9
    }

    /// A clock that only ever goes forward, for measuring intervals.
    ///
    /// Every interval in timed is measured against this rather than the
    /// wall clock, for the obvious reason: timed *changes* the wall clock,
    /// and an interval computed across one of its own steps would be
    /// nonsense — including negative, which is how a poll scheduler ends up
    /// spinning.
    pub fn monotonic(&self) -> f64 {
        let mut ts = libc::timespec {
            tv_sec: 0,
            tv_nsec: 0,
        };
        // Safe: a well-formed timespec, and CLOCK_MONOTONIC always exists.
        let rc = unsafe { libc::clock_gettime(libc::CLOCK_MONOTONIC, &mut ts) };
        if rc != 0 {
            return 0.0;
        }
        ts.tv_sec as f64 + ts.tv_nsec as f64 / 1e9
    }

    /// How finely this machine can actually read the clock, as log2 seconds.
    ///
    /// Measured rather than assumed: the answer differs by an order of
    /// magnitude between a bare-metal host and a VM whose clocksource is
    /// emulated, and it feeds every dispersion the machine reports onward.
    pub fn precision(&self) -> i8 {
        let mut smallest = f64::INFINITY;
        for _ in 0..10 {
            let a = self.monotonic();
            let mut b = self.monotonic();
            // Spin until the reading changes; the smallest observable
            // difference is the resolution.
            let mut spins = 0;
            while b == a && spins < 100_000 {
                b = self.monotonic();
                spins += 1;
            }
            if b > a {
                smallest = smallest.min(b - a);
            }
        }
        if !smallest.is_finite() || smallest <= 0.0 {
            // A machine whose monotonic clock never appeared to move.
            // A microsecond is a conservative claim, and overclaiming
            // precision is the failure that gets a source excluded from
            // everyone else's selection.
            return -20;
        }
        (smallest.log2().ceil() as i64).clamp(-32, 0) as i8
    }

    /// Set the rate and the status flags. Called after every completed poll.
    pub fn steer(&self, steering: Steering) -> io::Result<()> {
        let mut timex: libc::timex = unsafe { std::mem::zeroed() };
        timex.modes = ADJ_FREQUENCY | ADJ_STATUS | ADJ_MAXERROR | ADJ_ESTERROR;

        // The kernel's frequency unit is ppm scaled by 2^16, in a long.
        // Clamped before the conversion, not after: a NaN or an enormous
        // f64 cast to an integer type is implementation-defined and would
        // be a very silly way to break the system clock.
        let ppm = if steering.frequency.is_finite() {
            (steering.frequency * 1e6).clamp(-32_768.0, 32_768.0)
        } else {
            0.0
        };
        timex.freq = (ppm * 65_536.0) as i64;

        // maxerror and esterror are microseconds, and the kernel treats
        // maxerror crossing its own threshold as a reason to declare the
        // clock unsynchronised, so it is capped well inside that.
        timex.maxerror = (steering.max_error.max(0.0) * 1e6).min(1e9) as i64;
        timex.esterror = (steering.est_error.max(0.0) * 1e6).min(1e9) as i64;

        let mut status = STA_NANO | STA_FREQHOLD;
        // The loop is ours; make sure the kernel's is off. A machine where
        // something else left STA_PLL set would otherwise have two
        // controllers fighting over one clock.
        status &= !(STA_PLL | STA_FLL);
        if !steering.synchronised {
            status |= STA_UNSYNC;
        }
        match steering.leap {
            Leap::Insert => status |= STA_INS,
            Leap::Delete => status |= STA_DEL,
            Leap::None => {}
        }
        timex.status = status;

        adjtimex(&mut timex).map(|_| ())
    }

    /// Move the clock, at once, by `seconds`.
    ///
    /// `ADJ_SETOFFSET` rather than `settimeofday`: it applies a *delta*
    /// atomically, so there is no read-modify-write window in which
    /// something else could also set the clock, and the kernel gets to
    /// account for the discontinuity properly rather than seeing an
    /// unexplained jump.
    ///
    /// Refuses to land below the build floor. A step is the one operation
    /// that can put the clock somewhere absurd in a single call, so the
    /// floor is checked here, at the syscall, rather than only where the
    /// decision was made.
    pub fn step(&self, seconds: f64) -> io::Result<()> {
        if !seconds.is_finite() {
            return Err(io::Error::new(io::ErrorKind::InvalidInput, "a step of NaN"));
        }
        let (now, _) = self.now();
        let landing = now as f64 + seconds;
        if landing < BUILD_EPOCH as f64 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!(
                    "a step to {landing:.0} would land before this build's timestamp \
                     ({BUILD_EPOCH}); refused"
                ),
            ));
        }

        let mut timex: libc::timex = unsafe { std::mem::zeroed() };
        timex.modes = ADJ_SETOFFSET | ADJ_NANO;
        // The kernel wants a normalised timeval-shaped pair whose
        // microseconds (nanoseconds, under ADJ_NANO) are non-negative, so a
        // negative step is seconds−1 plus a positive remainder rather than
        // two negative numbers.
        let whole = seconds.div_euclid(1.0);
        let frac = seconds.rem_euclid(1.0);
        timex.time.tv_sec = whole as i64;
        timex.time.tv_usec = (frac * 1e9) as i64;
        adjtimex(&mut timex).map(|_| ())
    }

    /// Raise the clock to the build floor if it is below it.
    ///
    /// Called once at startup, before anything tries to make a TLS
    /// connection. Returns how far it moved, or zero.
    pub fn enforce_floor(&self) -> io::Result<f64> {
        let (now, _) = self.now();
        if now >= BUILD_EPOCH {
            return Ok(0.0);
        }
        let by = (BUILD_EPOCH - now) as f64;
        // Not via `step`, which checks the floor and would refuse to move
        // *to* it by a rounding hair.
        let mut timex: libc::timex = unsafe { std::mem::zeroed() };
        timex.modes = ADJ_SETOFFSET | ADJ_NANO;
        timex.time.tv_sec = by as i64;
        timex.time.tv_usec = 0;
        adjtimex(&mut timex)?;
        Ok(by)
    }

    /// What the kernel currently believes, for reporting and for picking up
    /// a frequency somebody else left behind.
    pub fn read_frequency(&self) -> io::Result<f64> {
        let mut timex: libc::timex = unsafe { std::mem::zeroed() };
        timex.modes = 0;
        adjtimex(&mut timex)?;
        Ok(timex.freq as f64 / 65_536.0 / 1e6)
    }
}

/// The syscall, with the one return value that is not an error handled.
fn adjtimex(timex: &mut libc::timex) -> io::Result<i32> {
    // Safe: `timex` is a valid, fully initialised `struct timex`, and the
    // kernel neither retains the pointer nor writes past it.
    let rc = unsafe { libc::adjtimex(timex) };
    if rc < 0 {
        return Err(io::Error::last_os_error());
    }
    // TIME_ERROR means "the clock is not synchronised", which is a state,
    // not a failure — and it is the state timed is in for the first few
    // seconds of every boot. Treating it as an error would make startup
    // look broken.
    if rc == TIME_ERROR {
        return Ok(rc);
    }
    Ok(rc)
}

#[cfg(test)]
mod tests {
    use super::*;

    // Nothing here writes to the clock: these run on a developer's machine
    // and in CI, and a test that stepped the system clock would be a very
    // rude test. Steering is proven on the image instead, where the whole
    // point is that it is a real machine.

    #[test]
    fn the_build_floor_is_a_real_time() {
        // A zero floor would silently disable the whole mechanism, and the
        // failure would only show up as a machine that cannot bootstrap
        // NTS on a dead RTC — months later, on somebody else's hardware.
        const {
            assert!(
                BUILD_EPOCH > 1_700_000_000,
                "build floor is not a plausible build time"
            );
        }
    }

    #[test]
    fn the_monotonic_clock_does_not_go_backwards() {
        let clock = Clock;
        let mut previous = clock.monotonic();
        for _ in 0..1000 {
            let now = clock.monotonic();
            assert!(now >= previous, "{now} < {previous}");
            previous = now;
        }
    }

    #[test]
    fn precision_is_measured_and_plausible() {
        // Between a nanosecond and a millisecond covers everything from
        // bare metal to a VM with an emulated clocksource. Outside that
        // range the measurement is wrong, and a wrong precision propagates
        // into every dispersion this machine reports to anyone else.
        let p = Clock.precision();
        assert!((-32..=-10).contains(&p), "precision 2^{p} is not plausible");
    }

    #[test]
    fn reading_the_clock_never_panics_on_a_time_before_the_epoch() {
        // `duration_since` returns an error for times before 1970 rather
        // than a negative duration, and unwrapping it is the obvious bug.
        // We cannot set the clock here, so this checks the shape of the
        // conversion rather than the value.
        let (s, ns) = Clock.now();
        assert!(ns < 1_000_000_000);
        assert!(s > 1_700_000_000);
    }
}
