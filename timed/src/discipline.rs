//! The clock discipline: turning a sequence of offsets into a corrected
//! clock.
//!
//! The machine's clock is a crystal that runs at the wrong rate. It is not
//! wrong randomly — it is wrong *consistently*, by some tens of parts per
//! million that vary slowly with temperature — and that is the whole
//! opportunity. A client that only ever corrected the phase would have to
//! keep correcting it forever; a client that learns the **frequency** error
//! can hold the clock right between measurements, and can hold it right for
//! hours when the network goes away.
//!
//! So the discipline maintains two numbers:
//!
//! - `frequency`, the intrinsic rate error, learned slowly and written to
//!   the drift file so the next boot starts from it rather than from zero.
//! - a `slew`, an extra rate applied over the coming interval to burn off
//!   whatever phase offset remains.
//!
//! The kernel is told their sum and nothing else. Steps are separate and
//! rare, and every one of them is an event worth logging.
//!
//! # The control law
//!
//! Derived rather than transcribed, because a servo whose constants nobody
//! can account for is a servo nobody can debug.
//!
//! Model the clock as `dθ/dt = e − u`, where θ is the offset we measure, e
//! is the crystal's rate error and u is the rate correction we apply. Use a
//! proportional-integral controller, `u = Kp·θ + ∫Ki·θ dt`. The closed loop
//! is then `θ'' + Kp·θ' + Ki·θ = 0`, a damped harmonic oscillator, which is
//! critically damped — the fastest approach with no overshoot — when
//! `Kp² = 4·Ki`.
//!
//! Pick a settling time `T` and that fixes both: `Kp = 2/T`, `Ki = 1/T²`.
//! Discretising over a measurement interval `mu`:
//!
//! ```text
//! slew       =  2·θ / T          applied for the coming interval
//! frequency += θ·mu / T²         the integral term
//! ```
//!
//! `T` is held at [`TIME_CONSTANT`] times the poll interval. That ratio is
//! what keeps the loop stable as the poll interval adapts: `mu/T` stays
//! constant, so the fraction of the offset removed per measurement does
//! too, and the loop cannot be destabilised by the poll interval changing
//! underneath it.

use std::fmt;

/// Offsets larger than this are corrected by stepping the clock rather than
/// slewing it. RFC 5905's STEPT: 128 milliseconds. Below it, slewing is
/// always preferable — a monotonically increasing clock is something a
/// great deal of software quietly assumes.
pub const STEP_THRESHOLD: f64 = 0.128;

/// An offset larger than this is refused outright rather than applied.
/// RFC 5905's PANICT: 1000 seconds. At startup it is allowed (the RTC may
/// be dead and the answer genuinely is "you are years out"); afterwards it
/// means something has gone badly wrong and quietly obeying would be worse
/// than stopping.
pub const PANIC_THRESHOLD: f64 = 1000.0;

/// How long a large offset must persist before it is believed to be a step
/// rather than a spike. RFC 5905's STEPOUT: 900 seconds.
///
/// This is the single most important number in the file. A spike — a
/// congested path, a server having a moment — looks exactly like a genuine
/// step until time passes, and stepping the clock on a spike is far worse
/// than being slow to correct a real one. Fifteen minutes of a consistent
/// large offset is something no transient produces.
pub const STEPOUT: f64 = 900.0;

/// The largest rate correction the discipline will ask for, in seconds per
/// second. 500 ppm is both RFC 5905's tolerance and what a crystal that bad
/// would have to be to reach; a computed frequency past it is a symptom,
/// not a measurement.
pub const MAX_FREQUENCY: f64 = 500e-6;

/// Settling time as a multiple of the poll interval. Four gives `mu/T` of
/// one quarter, so a measurement removes about half the offset it sees —
/// brisk enough to converge in a handful of polls, damped enough that a
/// single bad measurement does not swing the clock.
pub const TIME_CONSTANT: f64 = 4.0;

/// Above this interval, the frequency can be measured directly from how far
/// the offset moved, which is more accurate than integrating it. Roughly
/// the Allan intercept of a typical crystal: below it phase noise dominates
/// and the measurement would be of the network, not the clock.
pub const FLL_INTERVAL: f64 = 2048.0;

/// Where the discipline is in its life.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum State {
    /// Nothing believed yet. The next good offset is applied as a step,
    /// however large — this is the only moment at which that is safe, and
    /// it is what lets a machine with a dead RTC start correctly.
    Startup,
    /// A frequency is known but is still being refined; offsets are being
    /// applied.
    Settling,
    /// Normal operation.
    Synchronised,
    /// A large offset has appeared and is being timed. The clock is left
    /// alone meanwhile: if this is a spike it will pass, and if it is real
    /// the stepout timer will say so.
    Spike,
}

impl State {
    pub fn as_str(self) -> &'static str {
        match self {
            State::Startup => "startup",
            State::Settling => "settling",
            State::Synchronised => "synchronised",
            State::Spike => "spike",
        }
    }
}

/// What the discipline wants done to the clock.
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum Adjustment {
    /// Set the clock's rate to this, in seconds per second. The sum of the
    /// learned frequency and the current slew.
    Rate(f64),
    /// Move the clock by this many seconds, at once, and then hold this
    /// rate. Every step invalidates every measurement taken before it.
    Step { seconds: f64, rate: f64 },
    /// Do nothing. Either there is nothing to act on, or a large offset is
    /// being timed and acting would be premature.
    Hold,
    /// The offset is past [`PANIC_THRESHOLD`] and we are not in a position
    /// where a step that size is legitimate. The caller should log loudly
    /// and stop disciplining; a machine whose clock is a thousand seconds
    /// out after having been synchronised has a problem that a time client
    /// should not paper over.
    Panic { seconds: f64 },
}

/// The servo.
#[derive(Debug, Clone)]
pub struct Discipline {
    state: State,
    /// Learned rate error, seconds per second.
    frequency: f64,
    /// Rate currently being applied on top of `frequency` to burn off phase.
    slew: f64,
    /// Local time of the last update, seconds.
    last_update: Option<f64>,
    /// The offset at the last update, for the FLL term.
    last_offset: f64,
    /// When the current run of large offsets began.
    spike_since: Option<f64>,
    /// RMS of recent offset changes: how noisy the clock's own control
    /// loop is, as distinct from any one source's jitter.
    jitter: f64,
    /// How many updates have been applied, for reporting.
    updates: u64,
    /// Total seconds stepped since start, so an operator can see whether
    /// the machine has been jumping around.
    stepped: f64,
}

impl Default for Discipline {
    fn default() -> Discipline {
        Discipline::new(0.0)
    }
}

impl Discipline {
    /// Start, optionally from a frequency read out of the drift file.
    ///
    /// Starting from a known frequency is worth a great deal: a machine
    /// that remembers its crystal was 12 ppm fast yesterday is within a few
    /// milliseconds an hour after boot, instead of tens of seconds.
    pub fn new(initial_frequency: f64) -> Discipline {
        Discipline {
            state: State::Startup,
            frequency: sane_frequency(initial_frequency),
            slew: 0.0,
            last_update: None,
            last_offset: 0.0,
            spike_since: None,
            jitter: 0.0,
            updates: 0,
            stepped: 0.0,
        }
    }

    pub fn state(&self) -> State {
        self.state
    }

    /// The learned frequency error in seconds per second. This is what goes
    /// in the drift file.
    pub fn frequency(&self) -> f64 {
        self.frequency
    }

    /// The same, in the parts per million an operator reads.
    pub fn frequency_ppm(&self) -> f64 {
        self.frequency * 1e6
    }

    pub fn jitter(&self) -> f64 {
        self.jitter
    }

    pub fn updates(&self) -> u64 {
        self.updates
    }

    pub fn stepped(&self) -> f64 {
        self.stepped
    }

    /// True once the clock is being actively held, which is what
    /// "synchronised" means to everything outside this file.
    pub fn is_synchronised(&self) -> bool {
        matches!(self.state, State::Synchronised | State::Settling | State::Spike)
    }

    /// Everything measured before now was measured against a different
    /// clock: we stepped, or the machine resumed from suspend.
    ///
    /// The frequency survives deliberately. A suspend does not change the
    /// crystal, and throwing away a good frequency estimate because the
    /// laptop lid was shut would make every resume a fresh convergence.
    pub fn reset_phase(&mut self) {
        self.slew = 0.0;
        self.last_update = None;
        self.last_offset = 0.0;
        self.spike_since = None;
        if self.state != State::Startup {
            self.state = State::Settling;
        }
    }

    /// Feed in a combined offset from selection.
    ///
    /// `now` is the local clock in seconds; it is used only for intervals,
    /// so its absolute value does not matter.
    pub fn update(&mut self, offset: f64, now: f64) -> Adjustment {
        if !offset.is_finite() {
            return Adjustment::Hold;
        }

        // Startup: one step, of any size, before anything is believed.
        if self.state == State::Startup {
            self.last_update = Some(now);
            self.last_offset = offset;
            self.state = State::Settling;
            self.updates += 1;
            if offset.abs() > STEP_THRESHOLD {
                self.stepped += offset.abs();
                return Adjustment::Step { seconds: offset, rate: self.frequency };
            }
            return Adjustment::Rate(self.apply_slew(offset));
        }

        if offset.abs() > PANIC_THRESHOLD {
            return Adjustment::Panic { seconds: offset };
        }

        if offset.abs() > STEP_THRESHOLD {
            // A large offset. Time it rather than act on it.
            let since = *self.spike_since.get_or_insert(now);
            self.state = State::Spike;
            if now - since < STEPOUT {
                return Adjustment::Hold;
            }
            // It has persisted. This is a real step.
            self.spike_since = None;
            self.state = State::Settling;
            self.last_update = Some(now);
            self.last_offset = 0.0;
            self.slew = 0.0;
            self.updates += 1;
            self.stepped += offset.abs();
            return Adjustment::Step { seconds: offset, rate: self.frequency };
        }

        // A normal offset ends any spike in progress: the large readings
        // were transient after all.
        self.spike_since = None;
        if self.state == State::Spike {
            self.state = State::Settling;
        }

        let mu = match self.last_update {
            // No interval to integrate over yet; take the phase correction
            // and wait for a second measurement before touching frequency.
            None => {
                self.last_update = Some(now);
                self.last_offset = offset;
                self.updates += 1;
                return Adjustment::Rate(self.apply_slew(offset));
            }
            Some(last) => (now - last).max(1e-3),
        };

        // Loop jitter: the RMS of how much the offset moves between
        // updates. Distinct from a source's jitter — this is how well the
        // clock is actually being held, which is the number to report.
        let change = (offset - self.last_offset).abs();
        self.jitter = (self.jitter.powi(2) + (change.powi(2) - self.jitter.powi(2)) / 8.0)
            .max(0.0)
            .sqrt();

        // Settling time, tied to the measurement interval so the loop's
        // dynamics do not change when the poll interval does.
        let t = (TIME_CONSTANT * mu).max(1.0);

        // Integral term.
        let mut frequency = self.frequency + offset * mu / (t * t);

        // Frequency-locked term. Over a long interval the offset's *change*
        // is a direct measurement of the rate error, and a direct
        // measurement beats an integral. Below the Allan intercept it would
        // be measuring network noise instead, so it is off.
        if mu >= FLL_INTERVAL {
            let measured = (offset - self.last_offset) / mu;
            // Blended rather than taken whole: one long interval is still
            // one measurement, and the integral holds the history.
            frequency += measured / 4.0;
        }

        self.frequency = sane_frequency(frequency);
        self.last_update = Some(now);
        self.last_offset = offset;
        self.updates += 1;
        if self.updates > 4 {
            self.state = State::Synchronised;
        }

        Adjustment::Rate(self.apply_slew_with(offset, t))
    }

    fn apply_slew(&mut self, offset: f64) -> f64 {
        self.apply_slew_with(offset, TIME_CONSTANT * 64.0)
    }

    /// The proportional term: burn off the phase offset over the settling
    /// time. Clamped with the frequency so the pair can never ask the
    /// kernel for a rate it should refuse.
    fn apply_slew_with(&mut self, offset: f64, t: f64) -> f64 {
        self.slew = 2.0 * offset / t;
        let total = self.frequency + self.slew;
        total.clamp(-MAX_FREQUENCY, MAX_FREQUENCY)
    }
}

/// Keep the frequency inside the tolerance, and never let a NaN in.
///
/// A NaN frequency would be written to the drift file and read back at the
/// next boot, so one bad measurement would become permanent. Clamping here
/// is what makes the drift file safe to trust.
fn sane_frequency(frequency: f64) -> f64 {
    if frequency.is_finite() {
        frequency.clamp(-MAX_FREQUENCY, MAX_FREQUENCY)
    } else {
        0.0
    }
}

impl fmt::Display for Adjustment {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Adjustment::Rate(r) => write!(f, "rate {:+.3} ppm", r * 1e6),
            Adjustment::Step { seconds, rate } => {
                write!(f, "step {seconds:+.6}s then rate {:+.3} ppm", rate * 1e6)
            }
            Adjustment::Hold => write!(f, "hold"),
            Adjustment::Panic { seconds } => write!(f, "panic at {seconds:+.3}s"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A simulated clock, with the kernel's sign conventions.
    ///
    /// Those conventions are the thing most easily got backwards, so they
    /// are written out: a positive `ADJ_FREQUENCY` makes the clock run
    /// *faster*, so it **adds** to the crystal's error rather than
    /// subtracting from it — correcting a fast clock takes a negative
    /// frequency. And a measured NTP offset is `true − local`, so a clock
    /// that has run ahead produces a negative offset, and stepping by that
    /// offset brings the clock back.
    struct SimClock {
        /// The crystal's true rate error; positive means it gains.
        error: f64,
        /// The rate correction currently applied, as the kernel takes it.
        correction: f64,
        /// How far the clock reads ahead of true time.
        offset: f64,
    }

    impl SimClock {
        fn new(error_ppm: f64) -> SimClock {
            SimClock { error: error_ppm * 1e-6, correction: 0.0, offset: 0.0 }
        }

        fn advance(&mut self, seconds: f64) {
            self.offset += (self.error + self.correction) * seconds;
        }

        /// What a measurement would report: the offset needed to correct
        /// the clock, which is the negative of how far it has run ahead.
        fn measured_offset(&self) -> f64 {
            -self.offset
        }

        fn apply(&mut self, adjustment: Adjustment) {
            match adjustment {
                Adjustment::Rate(r) => self.correction = r,
                Adjustment::Step { seconds, rate } => {
                    self.offset += seconds;
                    self.correction = rate;
                }
                Adjustment::Hold | Adjustment::Panic { .. } => {}
            }
        }
    }

    /// Run the loop for `polls` intervals and report the final offset and
    /// the frequency it learned.
    fn converge(error_ppm: f64, poll: f64, polls: usize, noise: f64) -> (f64, f64, Discipline) {
        let mut clock = SimClock::new(error_ppm);
        let mut d = Discipline::new(0.0);
        let mut now = 0.0;
        // A crude but deterministic pseudo-noise, so the test is
        // reproducible and still not a perfectly clean signal.
        let mut seed = 12345u64;
        for _ in 0..polls {
            clock.advance(poll);
            now += poll;
            seed = seed.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
            let jitter = ((seed >> 33) as f64 / (1u64 << 31) as f64 - 0.5) * noise;
            let adjustment = d.update(clock.measured_offset() + jitter, now);
            clock.apply(adjustment);
        }
        (clock.offset, d.frequency_ppm(), d)
    }

    #[test]
    fn the_loop_converges_on_a_typical_crystal() {
        // 20 ppm fast is an ordinary desktop. After an hour of 64-second
        // polls the clock should be within a millisecond and the learned
        // frequency should be close to the truth.
        let (offset, ppm, d) = converge(20.0, 64.0, 60, 0.0);
        assert!(offset.abs() < 1e-3, "offset {offset}");
        assert!((ppm + 20.0).abs() < 5.0, "learned {ppm} ppm");
        assert_eq!(d.state(), State::Synchronised);
    }

    #[test]
    fn the_loop_converges_on_a_bad_crystal() {
        // 200 ppm is a cheap oscillator having a hard day, and still well
        // inside the 500 ppm tolerance.
        let (offset, ppm, _) = converge(200.0, 64.0, 120, 0.0);
        assert!(offset.abs() < 1e-3, "offset {offset}");
        assert!((ppm + 200.0).abs() < 20.0, "learned {ppm} ppm");
    }

    #[test]
    fn the_loop_does_not_overshoot() {
        // Critical damping is the point of the derivation. Track the sign
        // of the offset: a critically damped loop approaches zero from one
        // side and does not ring.
        let mut clock = SimClock::new(50.0);
        let mut d = Discipline::new(0.0);
        let mut now = 0.0;
        let mut crossings = 0;
        let mut previous = 0.0f64;
        for i in 0..80 {
            clock.advance(64.0);
            now += 64.0;
            let adjustment = d.update(clock.measured_offset(), now);
            clock.apply(adjustment);
            if i > 4 && clock.offset != 0.0 && previous != 0.0 {
                if clock.offset.signum() != previous.signum() {
                    crossings += 1;
                }
            }
            previous = clock.offset;
        }
        assert!(crossings <= 2, "the loop rang {crossings} times");
    }

    #[test]
    fn measurement_noise_does_not_destabilise_the_loop() {
        // Ten milliseconds of peak-to-peak jitter, which is a bad path.
        let (offset, ppm, _) = converge(30.0, 64.0, 200, 0.010);
        assert!(offset.abs() < 0.010, "offset {offset}");
        assert!((ppm + 30.0).abs() < 15.0, "learned {ppm} ppm");
    }

    #[test]
    fn a_remembered_frequency_converges_far_faster() {
        let poll = 64.0;
        let fresh = {
            let mut clock = SimClock::new(20.0);
            let mut d = Discipline::new(0.0);
            let mut now = 0.0;
            for _ in 0..5 {
                clock.advance(poll);
                now += poll;
                let a = d.update(clock.measured_offset(), now);
                clock.apply(a);
            }
            clock.offset.abs()
        };
        let remembered = {
            let mut clock = SimClock::new(20.0);
            let mut d = Discipline::new(-20e-6);
            let mut now = 0.0;
            for _ in 0..5 {
                clock.advance(poll);
                now += poll;
                let a = d.update(clock.measured_offset(), now);
                clock.apply(a);
            }
            clock.offset.abs()
        };
        assert!(
            remembered < fresh / 4.0,
            "remembered {remembered} was not much better than fresh {fresh}"
        );
    }

    #[test]
    fn the_first_offset_is_stepped_however_large() {
        // A machine with a dead RTC. This is the one moment a step of any
        // size is right, and getting it wrong means a machine that can
        // never bootstrap.
        let mut d = Discipline::new(0.0);
        let a = d.update(86_400.0 * 365.0, 0.0);
        assert!(matches!(a, Adjustment::Step { seconds, .. } if seconds > 3e7));
    }

    #[test]
    fn a_small_first_offset_is_slewed_not_stepped() {
        let mut d = Discipline::new(0.0);
        assert!(matches!(d.update(0.001, 0.0), Adjustment::Rate(_)));
    }

    #[test]
    fn a_spike_is_waited_out_and_never_acted_on() {
        let mut d = Discipline::new(0.0);
        d.update(0.0, 0.0);
        d.update(0.0, 64.0);
        // One wild reading, then normality returns.
        assert_eq!(d.update(30.0, 128.0), Adjustment::Hold);
        assert_eq!(d.state(), State::Spike);
        assert!(matches!(d.update(0.001, 192.0), Adjustment::Rate(_)));
        assert_ne!(d.state(), State::Spike);
        assert_eq!(d.stepped(), 0.0, "a spike must never move the clock");
    }

    #[test]
    fn a_sustained_step_is_taken_after_the_stepout() {
        let mut d = Discipline::new(0.0);
        d.update(0.0, 0.0);
        d.update(0.0, 64.0);
        let mut now = 128.0;
        // Fifteen minutes of consistent disagreement.
        while now < 128.0 + STEPOUT {
            assert_eq!(d.update(30.0, now), Adjustment::Hold, "at {now}");
            now += 64.0;
        }
        assert!(matches!(d.update(30.0, now), Adjustment::Step { seconds, .. } if seconds == 30.0));
    }

    #[test]
    fn an_absurd_offset_after_synchronisation_panics_rather_than_obeying() {
        let mut d = Discipline::new(0.0);
        d.update(0.0, 0.0);
        assert!(matches!(d.update(5000.0, 64.0), Adjustment::Panic { .. }));
    }

    #[test]
    fn the_frequency_is_clamped_and_never_becomes_a_nan() {
        // A drift file that has been corrupted, or a pathological run of
        // measurements. Neither may produce a frequency that poisons every
        // future boot.
        assert_eq!(Discipline::new(f64::NAN).frequency(), 0.0);
        assert_eq!(Discipline::new(1.0).frequency(), MAX_FREQUENCY);
        assert_eq!(Discipline::new(-1.0).frequency(), -MAX_FREQUENCY);

        let mut d = Discipline::new(0.0);
        d.update(0.0, 0.0);
        assert_eq!(d.update(f64::NAN, 64.0), Adjustment::Hold);
        assert!(d.frequency().is_finite());

        // Drive it hard in one direction for a long time; it must saturate
        // at the tolerance rather than run away.
        let mut now = 64.0;
        for _ in 0..500 {
            now += 64.0;
            d.update(0.1, now);
        }
        assert!(d.frequency().abs() <= MAX_FREQUENCY);
    }

    #[test]
    fn a_phase_reset_keeps_the_frequency() {
        // Resuming from suspend does not change the crystal.
        let (_, _, mut d) = converge(20.0, 64.0, 60, 0.0);
        let learned = d.frequency();
        d.reset_phase();
        assert_eq!(d.frequency(), learned);
        assert_eq!(d.state(), State::Settling);
    }

    #[test]
    fn the_rate_asked_for_never_exceeds_the_tolerance() {
        let mut d = Discipline::new(MAX_FREQUENCY);
        d.update(0.0, 0.0);
        // A large-ish offset on top of an already saturated frequency.
        for i in 1..50 {
            if let Adjustment::Rate(r) = d.update(0.12, i as f64 * 64.0) {
                assert!(r.abs() <= MAX_FREQUENCY + 1e-15, "asked for {} ppm", r * 1e6);
            }
        }
    }
}
