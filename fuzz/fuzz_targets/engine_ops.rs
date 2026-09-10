//! The decision core as a state machine.
//!
//! Structure-aware rather than byte-oriented: the interesting failures in
//! selection and discipline are not malformed input, they are *sequences*
//! — a source that answers, vanishes, returns with a wild offset, is
//! outvoted, comes back. Those cost nothing to reach from a derived
//! `Arbitrary` and are nearly unreachable from random bytes.
//!
//! The invariants asserted are the ones that would be silent failures:
//! nothing produces a NaN, and the discipline never asks the kernel for a
//! rate outside the tolerance. A NaN frequency reaches the drift file and
//! survives every future boot.
#![no_main]
use arbitrary::Arbitrary;
use libfuzzer_sys::fuzz_target;
use timed::discipline::{Adjustment, Discipline, MAX_FREQUENCY};
use timed::filter::{ClockFilter, Filtered};
use timed::sample::Sample;
use timed::select::{self, Candidate};

#[derive(Arbitrary, Debug)]
enum Op {
    /// A measurement arrives for one source.
    Sample {
        source: u8,
        offset: f32,
        delay: f32,
        dispersion: f32,
        at: u16,
    },
    /// A source goes quiet.
    Reset { source: u8 },
    /// Run selection over whatever the filters hold.
    Select { at: u16 },
    /// Feed an offset to the discipline.
    Discipline { offset: f32, at: u16 },
    /// The clock was stepped by something else.
    ResetPhase,
}

const SOURCES: usize = 6;

fuzz_target!(|ops: Vec<Op>| {
    let mut filters: Vec<ClockFilter> = (0..SOURCES).map(|_| ClockFilter::new()).collect();
    let mut discipline = Discipline::new(0.0);

    for op in ops.iter().take(512) {
        match op {
            Op::Sample {
                source,
                offset,
                delay,
                dispersion,
                at,
            } => {
                let sample = Sample {
                    offset: *offset as f64,
                    delay: (*delay as f64).abs(),
                    dispersion: (*dispersion as f64).abs(),
                    at: *at as f64,
                };
                if !sample.offset.is_finite()
                    || !sample.delay.is_finite()
                    || !sample.dispersion.is_finite()
                {
                    continue;
                }
                let f = &mut filters[*source as usize % SOURCES];
                f.insert(sample, *at as f64);
            }
            Op::Reset { source } => filters[*source as usize % SOURCES].reset(),
            Op::Select { at } => {
                let now = *at as f64;
                let candidates: Vec<Candidate> = filters
                    .iter()
                    .enumerate()
                    .filter_map(|(id, f)| {
                        let filtered: Filtered = f.peek(now)?;
                        Some(Candidate {
                            id,
                            filtered,
                            stratum: 2,
                            root_delay: 0.01,
                            root_dispersion: 0.001,
                            usable: true,
                            prefer: id == 0,
                        })
                    })
                    .collect();
                if let Ok(selection) = select::select(&candidates, now) {
                    assert!(
                        selection.offset.is_finite(),
                        "selection produced {}",
                        selection.offset
                    );
                    assert!(selection.jitter.is_finite(), "jitter {}", selection.jitter);
                    assert!(selection.jitter >= 0.0);
                    // A survivor cannot also be a falseticker; the two
                    // sets partition the fit candidates.
                    for id in &selection.survivors {
                        assert!(!selection.falsetickers.contains(id));
                    }
                    assert!(selection.survivors.contains(&selection.system_peer));
                }
            }
            Op::Discipline { offset, at } => {
                let offset = *offset as f64;
                if !offset.is_finite() {
                    continue;
                }
                match discipline.update(offset, *at as f64) {
                    Adjustment::Rate(rate) => {
                        assert!(rate.is_finite(), "rate {rate}");
                        assert!(
                            rate.abs() <= MAX_FREQUENCY + 1e-12,
                            "asked the kernel for {} ppm",
                            rate * 1e6
                        );
                    }
                    Adjustment::Step { seconds, rate } => {
                        assert!(seconds.is_finite() && rate.is_finite());
                        assert!(rate.abs() <= MAX_FREQUENCY + 1e-12);
                    }
                    Adjustment::Hold | Adjustment::Panic { .. } => {}
                }
                // The number that ends up in the drift file and is read
                // back at every future boot.
                assert!(discipline.frequency().is_finite());
                assert!(discipline.frequency().abs() <= MAX_FREQUENCY);
                assert!(discipline.jitter().is_finite());
            }
            Op::ResetPhase => discipline.reset_phase(),
        }
    }
});
