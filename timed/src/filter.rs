//! The clock filter, RFC 5905 §10.
//!
//! Eight samples per source in a shift register, and the one with the
//! **lowest delay** wins. That is the whole idea, and it is worth
//! understanding why it beats averaging: on a packet-switched network the
//! error in a measurement is dominated by queueing, queueing only ever adds
//! delay, and it adds it asymmetrically. So the least-delayed sample of a
//! recent batch is the one that spent least time in queues and is therefore
//! the least wrong — while an average is dragged around by exactly the
//! samples you would most like to discard.
//!
//! The filter also produces the two numbers the selection algorithm needs
//! to weigh this source against others:
//!
//! - **jitter**, the spread of the recent samples about the chosen one,
//!   which is a measure of how noisy the path is.
//! - **dispersion**, a weighted sum of the samples' own dispersions that
//!   decays geometrically with delay rank, so a filter holding one good
//!   sample and seven stale ones reports honestly that it is mostly stale.

use crate::sample::{Sample, MIN_DISPERSION, PHI};

/// Samples kept per source. Eight is RFC 5905's NSTAGE, and the geometric
/// weighting below is written for it.
pub const NSTAGE: usize = 8;

/// The dispersion of a slot that has never held a sample, RFC 5905's
/// MAXDISPERSE: sixteen seconds. Large enough that an unfilled filter is
/// never selected over a filled one, without being infinite — an infinity
/// here would propagate into the root dispersion a server reports onward.
pub const MAX_DISPERSION: f64 = 16.0;

/// What the filter currently believes about one source.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Filtered {
    /// The offset of the least-delayed recent sample.
    pub offset: f64,
    /// Its delay.
    pub delay: f64,
    /// The weighted dispersion across the register.
    pub dispersion: f64,
    /// RMS spread of the register about `offset`.
    pub jitter: f64,
    /// When the chosen sample was taken.
    pub at: f64,
}

/// One source's shift register.
#[derive(Debug, Clone, Default)]
pub struct ClockFilter {
    /// Newest first. `None` is a slot that has never been filled.
    stages: [Option<Sample>; NSTAGE],
    /// The `at` of the last sample this filter reported as output, so that
    /// the same sample is never used twice.
    last_reported: Option<f64>,
}

/// Why a sample did not produce a new filter output.
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum FilterOutcome {
    /// A fresh, usable estimate.
    Update(Filtered),
    /// The register's best sample is one we have already acted on. This is
    /// normal after a poll whose reply was worse than one already held, and
    /// it matters: acting on it again would feed the same measurement into
    /// the discipline twice and make the loop believe it has more
    /// information than it does.
    Stale,
}

// Note on what is deliberately *not* here: a popcorn spike suppressor.
//
// RFC 5905 puts one in the filter, gating a sample that differs from the
// last by more than three times the jitter. Two problems. The jitter is
// computed about the new sample, so a spike inflates its own threshold and
// walks straight through the gate — which is a bug you only find by writing
// the test. And the discipline has to handle a large offset anyway, because
// a genuine step (a corrected RTC, a resume from suspend) looks exactly
// like a spike until it persists. Deciding the same question in two places
// means one of them is eventually wrong; the decision lives in
// `discipline`, where the stepout timer can tell them apart.

impl ClockFilter {
    pub fn new() -> ClockFilter {
        ClockFilter::default()
    }

    /// Everything the register holds is now suspect: the local clock was
    /// stepped, or the machine resumed from suspend, and every stored offset
    /// was measured against a clock that no longer exists.
    pub fn reset(&mut self) {
        self.stages = Default::default();
        self.last_reported = None;
    }

    pub fn is_empty(&self) -> bool {
        self.stages[0].is_none()
    }

    /// Shift a sample in and recompute.
    pub fn insert(&mut self, sample: Sample, now: f64) -> FilterOutcome {
        self.stages.rotate_right(1);
        self.stages[0] = Some(sample);

        // Sort a *copy* by delay. The register itself stays in time order,
        // because ageing and the shift both depend on it.
        let mut ranked: Vec<Sample> = self.stages.iter().flatten().copied().collect();
        ranked.sort_by(|a, b| a.delay.total_cmp(&b.delay));

        let best = ranked[0];

        // Dispersion: each sample's own, aged to now, weighted by 1/2^(i+1)
        // in delay order. The unfilled slots contribute MAX_DISPERSION at
        // their weight, which is what makes a half-full filter report a
        // large dispersion rather than a confident wrong answer.
        let mut dispersion = 0.0;
        for i in 0..NSTAGE {
            let each = ranked.get(i).map_or(MAX_DISPERSION, |s| s.aged_dispersion(now));
            dispersion += each / (2.0f64).powi(i as i32 + 1);
        }

        // Jitter: RMS of the ranked samples about the best one. With a
        // single sample there is no spread to measure and the precision
        // floor is the honest answer.
        let jitter = if ranked.len() > 1 {
            let sum: f64 = ranked[1..].iter().map(|s| (s.offset - best.offset).powi(2)).sum();
            (sum / (ranked.len() - 1) as f64).sqrt().max(MIN_DISPERSION)
        } else {
            MIN_DISPERSION
        };

        // Freshness. The best sample may be one we already used, which
        // happens whenever a poll returns something worse than what the
        // register already held.
        if self.last_reported.is_some_and(|last| best.at <= last) {
            return FilterOutcome::Stale;
        }

        self.last_reported = Some(best.at);
        FilterOutcome::Update(Filtered {
            offset: best.offset,
            delay: best.delay,
            dispersion,
            jitter,
            at: best.at,
        })
    }

    /// The current estimate without inserting anything, aged to `now`.
    ///
    /// Selection needs this every round, not only on the polls that
    /// happened to complete — a source that has not answered for ten
    /// minutes must get steadily less believable rather than staying
    /// frozen at its last good value.
    pub fn peek(&self, now: f64) -> Option<Filtered> {
        let mut ranked: Vec<Sample> = self.stages.iter().flatten().copied().collect();
        if ranked.is_empty() {
            return None;
        }
        ranked.sort_by(|a, b| a.delay.total_cmp(&b.delay));
        let best = ranked[0];
        let mut dispersion = 0.0;
        for i in 0..NSTAGE {
            let each = ranked.get(i).map_or(MAX_DISPERSION, |s| s.aged_dispersion(now));
            dispersion += each / (2.0f64).powi(i as i32 + 1);
        }
        let jitter = if ranked.len() > 1 {
            let sum: f64 = ranked[1..].iter().map(|s| (s.offset - best.offset).powi(2)).sum();
            (sum / (ranked.len() - 1) as f64).sqrt().max(MIN_DISPERSION)
        } else {
            MIN_DISPERSION
        };
        Some(Filtered { offset: best.offset, delay: best.delay, dispersion, jitter, at: best.at })
    }
}

/// How far this source might be wrong, RFC 5905's root distance Λ.
///
/// This is the number selection ranks by and the number the machine reports
/// as its own accuracy, so it has to be an honest upper bound rather than a
/// best guess. It adds up every way the answer could be off:
///
/// - half the total path delay, ours plus the server's to its own source,
///   because that is the bound on the asymmetry error;
/// - every dispersion between here and the root, including the drift since
///   the last measurement;
/// - the jitter, because a noisy path is a less certain one.
pub fn root_distance(
    filtered: &Filtered,
    server_root_delay: f64,
    server_root_dispersion: f64,
    now: f64,
) -> f64 {
    (server_root_delay + filtered.delay).max(MIN_DISPERSION) / 2.0
        + server_root_dispersion
        + filtered.dispersion
        + PHI * (now - filtered.at).max(0.0)
        + filtered.jitter
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample(offset: f64, delay: f64, at: f64) -> Sample {
        Sample { offset, delay, dispersion: MIN_DISPERSION, at }
    }

    fn update(outcome: FilterOutcome) -> Filtered {
        match outcome {
            FilterOutcome::Update(f) => f,
            other => panic!("expected an update, got {other:?}"),
        }
    }

    #[test]
    fn the_least_delayed_sample_wins_not_the_newest() {
        let mut filter = ClockFilter::new();
        update(filter.insert(sample(0.001, 0.010, 1.0), 1.0));
        // A much later, much worse sample must not displace the good one.
        let out = filter.insert(sample(0.050, 0.200, 2.0), 2.0);
        assert_eq!(out, FilterOutcome::Stale, "the good sample is still the best");
        assert!((filter.peek(2.0).unwrap().offset - 0.001).abs() < 1e-9);
    }

    #[test]
    fn a_better_sample_displaces_the_estimate() {
        let mut filter = ClockFilter::new();
        update(filter.insert(sample(0.050, 0.200, 1.0), 1.0));
        let out = update(filter.insert(sample(0.001, 0.010, 2.0), 2.0));
        assert!((out.offset - 0.001).abs() < 1e-9);
        assert!((out.delay - 0.010).abs() < 1e-9);
    }

    #[test]
    fn an_empty_filter_reports_a_large_dispersion_not_a_confident_answer() {
        let mut filter = ClockFilter::new();
        let out = update(filter.insert(sample(0.0, 0.001, 1.0), 1.0));
        // Seven unfilled slots at MAX_DISPERSION, weights 1/4 .. 1/256.
        assert!(out.dispersion > 7.0, "dispersion {}", out.dispersion);

        // And once it fills with good samples it collapses.
        for i in 2..=NSTAGE {
            filter.insert(sample(0.0, 0.001 + i as f64 * 1e-6, i as f64), i as f64);
        }
        assert!(filter.peek(10.0).unwrap().dispersion < 0.01);
    }

    #[test]
    fn a_stale_best_sample_is_not_acted_on_twice() {
        let mut filter = ClockFilter::new();
        update(filter.insert(sample(0.001, 0.010, 1.0), 1.0));
        for t in 2..6 {
            assert_eq!(
                filter.insert(sample(0.002, 0.500, t as f64), t as f64),
                FilterOutcome::Stale,
                "at {t}"
            );
        }
    }

    #[test]
    fn a_wild_sample_is_reported_rather_than_swallowed() {
        // The filter does not judge. A low-delay outlier is the best
        // measurement it has by its own rule, so it reports it — and
        // reports the jitter that says how far out of family it is, which
        // is what the discipline decides on.
        let mut filter = ClockFilter::new();
        for t in 1..=4 {
            filter.insert(sample(0.001, 0.010 + t as f64 * 1e-9, t as f64), t as f64);
        }
        let out = update(filter.insert(sample(5.0, 0.001, 5.0), 5.0));
        assert!((out.offset - 5.0).abs() < 1e-9);
        assert!(out.jitter > 1.0, "jitter {} should show it is out of family", out.jitter);
    }

    #[test]
    fn a_reset_forgets_everything_measured_against_the_old_clock() {
        let mut filter = ClockFilter::new();
        update(filter.insert(sample(0.001, 0.010, 1.0), 1.0));
        filter.reset();
        assert!(filter.is_empty());
        assert!(filter.peek(2.0).is_none());
        // And a sample at a time already used is accepted again, because
        // the record of what was used went with it.
        assert!(matches!(filter.insert(sample(9.0, 0.010, 1.0), 1.0), FilterOutcome::Update(_)));
    }

    #[test]
    fn a_source_becomes_selectable_only_as_its_filter_fills() {
        // The property whose absence cost a whole image test. One sample
        // leaves seven empty slots contributing MAX_DISPERSION, so the
        // root distance is far past MAX_DISTANCE and the source is not fit
        // — correctly, since one measurement says very little. It becomes
        // fit as the register fills.
        //
        // What made that a bug was elsewhere: selection ran only when the
        // filter produced a *new best* sample, so a source whose first
        // measurement had the lowest delay never had selection re-run, and
        // stayed unfit for ever while its dispersion quietly fell.
        let mut filter = ClockFilter::new();
        filter.insert(sample(0.001, 0.010, 1.0), 1.0);
        let one = root_distance(&filter.peek(1.0).unwrap(), 0.02, 0.001, 1.0);
        assert!(one > 1.5, "one sample should be too uncertain, got {one}");

        // Fill it with samples that are all *worse* than the first, which
        // is the case that produced the bug: none of them displaces the
        // best, so none reported an update.
        for t in 2..=8 {
            filter.insert(sample(0.001, 0.010 + t as f64 * 1e-3, t as f64), t as f64);
        }
        let full = root_distance(&filter.peek(8.0).unwrap(), 0.02, 0.001, 8.0);
        assert!(full < 1.5, "a full filter should be usable, got {full}");
    }

    #[test]
    fn root_distance_grows_while_a_source_is_silent() {
        let f = Filtered {
            offset: 0.0,
            delay: 0.01,
            dispersion: 0.001,
            jitter: 0.0001,
            at: 100.0,
        };
        let near = root_distance(&f, 0.02, 0.001, 100.0);
        let far = root_distance(&f, 0.02, 0.001, 100.0 + 3600.0);
        assert!(far > near);
        assert!((far - near - PHI * 3600.0).abs() < 1e-12);
    }

    #[test]
    fn root_distance_includes_half_the_whole_path() {
        let f = Filtered { offset: 0.0, delay: 0.1, dispersion: 0.0, jitter: 0.0, at: 0.0 };
        // Our 0.1 plus the server's 0.2 is 0.3 of path; half of it is the
        // asymmetry bound.
        assert!((root_distance(&f, 0.2, 0.0, 0.0) - 0.15).abs() < 1e-12);
    }
}
