//! Choosing what to believe, RFC 5905 §11.2.
//!
//! This is the part of NTP that is not about clocks at all. Given several
//! servers, some of which may be wrong — broken, misconfigured, or lying —
//! decide which subset is telling the truth. It is a Byzantine agreement
//! problem, and NTP's answer is an idea worth stating plainly:
//!
//! > A server does not report a time. It reports an **interval** it
//! > promises the true time lies within. Intervals that all overlap can all
//! > be right; an interval that misses the overlap cannot be.
//!
//! The interval is `offset ± root_distance`, and `root_distance` is the
//! honest accumulation of every uncertainty between here and the reference
//! clock (see [`crate::filter::root_distance`]). A server that claims great
//! accuracy and is wrong therefore excludes *itself*: its interval is
//! narrow, so it misses the overlap, so it is discarded. Claiming to be
//! better than you are is the one lie the algorithm punishes automatically.
//!
//! Three stages:
//!
//! 1. **Intersection** finds the largest set of overlapping intervals,
//!    tolerating as many falsetickers as it can while keeping a majority.
//! 2. **Clustering** trims the survivors down to the ones that agree
//!    closely, discarding the noisiest until trimming would cost more than
//!    it gains.
//! 3. **Combining** takes a weighted average, so the final answer leans on
//!    the sources that claim least uncertainty.
//!
//! With three independent sources this survives one liar. That is why the
//! shipped fallback set has three operators in three jurisdictions rather
//! than one well-known name.

use crate::filter::{root_distance, Filtered};

/// The stratum at which a server is, by definition, unsynchronised.
pub const MAX_STRATUM: u8 = 16;

/// The largest root distance a source may have and still be considered,
/// RFC 5905's MAXDIST: 1.5 seconds. A source less certain than this
/// contributes nothing but noise to the intersection.
pub const MAX_DISTANCE: f64 = 1.5;

/// Below this many survivors, clustering stops trimming. RFC 5905's NMIN.
/// Trimming to fewer than three would throw away the redundancy that made
/// the intersection meaningful in the first place.
pub const MIN_SURVIVORS: usize = 3;

/// One source, as selection sees it.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Candidate {
    /// Stable identity, so the caller can map a survivor back to a source.
    pub id: usize,
    pub filtered: Filtered,
    pub stratum: u8,
    /// The server's own distance from its reference clock.
    pub root_delay: f64,
    pub root_dispersion: f64,
    /// Cleared when the server says it is not synchronised, when it has not
    /// answered recently enough to be reachable, or when it turns out to be
    /// synchronised to us.
    pub usable: bool,
    /// The operator said to prefer this one. Breaks ties and nothing more:
    /// a preferred source that is a falseticker is still discarded, because
    /// an operator preference is a statement about which server to lean on,
    /// not a licence to be wrong.
    pub prefer: bool,
}

impl Candidate {
    /// Is this source worth putting into the intersection at all?
    ///
    /// RFC 5905's `fit()`. Note what is *not* checked: whether the offset
    /// is plausible. A source claiming the time is a year out is a
    /// perfectly fit candidate, and it is the intersection's job to
    /// outvote it — not a threshold's. A threshold here would be a way for
    /// a majority of liars to be rejected in favour of one, which is
    /// exactly backwards.
    pub fn is_fit(&self, now: f64) -> bool {
        self.usable
            && self.stratum < MAX_STRATUM
            && self.root_distance(now) < MAX_DISTANCE
    }

    pub fn root_distance(&self, now: f64) -> f64 {
        root_distance(&self.filtered, self.root_delay, self.root_dispersion, now)
    }

    /// The clustering metric: stratum first, then distance. A stratum-1
    /// server that is slightly noisier is still preferable to a stratum-4
    /// one that is quiet, because the noise is measured and the extra
    /// layers of indirection are not.
    fn metric(&self, now: f64) -> f64 {
        MAX_DISTANCE * self.stratum as f64 + self.root_distance(now)
    }
}

/// What selection concluded.
#[derive(Debug, Clone, PartialEq)]
pub struct Selection {
    /// The combined offset to hand to the discipline.
    pub offset: f64,
    /// Spread among the survivors: how much they disagree. This becomes the
    /// system jitter and feeds the machine's reported accuracy.
    pub jitter: f64,
    /// The survivor the system takes its stratum, leap and root numbers
    /// from — the one with the best metric, not the combined average, which
    /// has no stratum of its own.
    pub system_peer: usize,
    /// Survivors, best first.
    pub survivors: Vec<usize>,
    /// Fit candidates that failed the intersection: the falsetickers. Worth
    /// naming, because "this server disagrees with the others" is the
    /// single most useful thing a time client can tell an operator.
    pub falsetickers: Vec<usize>,
}

/// Why no selection could be made.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NoSelection {
    /// Nothing was fit: no source has answered, or every one of them is
    /// unsynchronised or too uncertain to be worth considering.
    NoCandidates,
    /// Candidates exist but no majority agrees on anything. The honest
    /// state, and the one worth alarming on: it means the sources are
    /// telling different stories and there is no way to know which is
    /// right. Better to be unsynchronised than to pick one at random.
    NoMajority,
}

#[derive(Clone, Copy)]
struct Endpoint {
    edge: f64,
    /// −1 lower, 0 midpoint, +1 upper.
    kind: i32,
}

/// Run the whole selection.
pub fn select(candidates: &[Candidate], now: f64) -> Result<Selection, NoSelection> {
    let fit: Vec<&Candidate> = candidates.iter().filter(|c| c.is_fit(now)).collect();
    if fit.is_empty() {
        return Err(NoSelection::NoCandidates);
    }

    let (low, high) = intersection(&fit, now).ok_or(NoSelection::NoMajority)?;

    // A candidate survives when its *midpoint* — its actual offset — lies
    // in the agreed interval. Note it is the midpoint and not the interval
    // that has to be inside: a source with a very wide interval that
    // happens to span the agreement is not thereby a truechimer, it is
    // just vague.
    let mut survivors: Vec<&Candidate> = Vec::new();
    let mut falsetickers: Vec<usize> = Vec::new();
    for c in &fit {
        if c.filtered.offset >= low && c.filtered.offset <= high {
            survivors.push(c);
        } else {
            falsetickers.push(c.id);
        }
    }
    if survivors.is_empty() {
        return Err(NoSelection::NoMajority);
    }

    cluster(&mut survivors, now);

    // Best first, so the head is the system peer. `prefer` breaks ties and
    // is checked before the metric so that it actually does something.
    survivors.sort_by(|a, b| {
        b.prefer
            .cmp(&a.prefer)
            .then_with(|| a.metric(now).total_cmp(&b.metric(now)))
    });

    let (offset, jitter) = combine(&survivors, now);
    Ok(Selection {
        offset,
        jitter,
        system_peer: survivors[0].id,
        survivors: survivors.iter().map(|c| c.id).collect(),
        falsetickers,
    })
}

/// The largest interval a majority of candidates agree on.
///
/// Marzullo's algorithm as RFC 5905 modifies it. Each candidate contributes
/// three points to a sorted list — its lower edge, its midpoint, its upper
/// edge — and a sweep counts how many intervals are open at each point.
/// Where the count reaches `m − allow`, a majority overlaps.
///
/// `allow` starts at zero and rises: first ask whether *all* candidates
/// agree, then whether all but one do, and so on, stopping before allowing
/// so many falsetickers that the remainder is not a majority. The extra
/// condition — that the number of midpoints found outside the interval must
/// not exceed `allow` — is what stops the algorithm from declaring an
/// intersection that no candidate actually sits in.
fn intersection(fit: &[&Candidate], now: f64) -> Option<(f64, f64)> {
    let m = fit.len();
    let mut points: Vec<Endpoint> = Vec::with_capacity(m * 3);
    for c in fit {
        let distance = c.root_distance(now);
        points.push(Endpoint { edge: c.filtered.offset - distance, kind: -1 });
        points.push(Endpoint { edge: c.filtered.offset, kind: 0 });
        points.push(Endpoint { edge: c.filtered.offset + distance, kind: 1 });
    }
    // Sort by edge, and at equal edges put lower endpoints first so an
    // interval that merely touches another is counted as overlapping it.
    points.sort_by(|a, b| a.edge.total_cmp(&b.edge).then(a.kind.cmp(&b.kind)));

    let n = points.len();
    let mut allow = 0usize;
    while 2 * allow < m {
        let mut found = 0usize;
        let mut chime = 0i32;
        let mut low = None;
        for p in points.iter() {
            chime -= p.kind;
            if chime >= (m - allow) as i32 {
                low = Some(p.edge);
                break;
            }
            if p.kind == 0 {
                found += 1;
            }
        }

        let mut chime = 0i32;
        let mut high = None;
        for p in points[..n].iter().rev() {
            chime += p.kind;
            if chime >= (m - allow) as i32 {
                high = Some(p.edge);
                break;
            }
            if p.kind == 0 {
                found += 1;
            }
        }

        match (low, high) {
            // More midpoints fell outside than we are allowing falsetickers
            // for, so this interval excludes a candidate we have not yet
            // agreed to discard. Allow one more and try again.
            _ if found > allow => {}
            (Some(low), Some(high)) if high > low => return Some((low, high)),
            _ => {}
        }
        allow += 1;
    }
    None
}

/// Trim the survivors down to those that agree closely.
///
/// Repeatedly discard the survivor whose offset is furthest from the rest
/// — measured as *selection jitter*, the RMS distance from every other
/// survivor — but stop as soon as the worst selection jitter is smaller
/// than the best source's own measurement noise. Past that point the
/// disagreement between sources is smaller than the uncertainty within one
/// of them, so discarding is no longer removing an outlier, it is
/// discarding information.
fn cluster(survivors: &mut Vec<&Candidate>, now: f64) {
    while survivors.len() > MIN_SURVIVORS {
        let n = survivors.len();
        let mut worst = 0usize;
        let mut worst_weighted = f64::NEG_INFINITY;
        let mut worst_jitter = 0.0;
        let mut min_peer_jitter = f64::INFINITY;

        for (i, c) in survivors.iter().enumerate() {
            let sum: f64 = survivors
                .iter()
                .map(|o| (c.filtered.offset - o.filtered.offset).powi(2))
                .sum();
            let selection_jitter = (sum / (n - 1) as f64).sqrt();
            let weighted = selection_jitter * c.metric(now);
            if weighted > worst_weighted {
                worst_weighted = weighted;
                worst = i;
                worst_jitter = selection_jitter;
            }
            min_peer_jitter = min_peer_jitter.min(c.filtered.jitter);
        }

        if worst_jitter < min_peer_jitter {
            break;
        }
        // Never discard a preferred source for being an outlier. If it is
        // an outlier badly enough to matter it is a falseticker, and the
        // intersection has already had that conversation.
        if survivors[worst].prefer {
            break;
        }
        survivors.remove(worst);
    }
}

/// Weighted average of the survivors, RFC 5905 §11.2.3.
///
/// The weight is `1 / root_distance`, so a source that claims to be ten
/// times more certain counts ten times as much — which is the correct
/// incentive, given that overclaiming certainty is what gets a source
/// excluded by the intersection in the first place.
fn combine(survivors: &[&Candidate], now: f64) -> (f64, f64) {
    let mut weight_sum = 0.0;
    let mut offset_sum = 0.0;
    for c in survivors {
        // Floored, because a root distance of zero is not achievable and a
        // near-zero one would give a single source infinite weight.
        let distance = c.root_distance(now).max(1e-9);
        weight_sum += 1.0 / distance;
        offset_sum += c.filtered.offset / distance;
    }
    let offset = if weight_sum > 0.0 { offset_sum / weight_sum } else { 0.0 };

    // System jitter: how far the survivors sit from the one we chose, plus
    // that one's own noise. Both matter — a set of sources that agree
    // perfectly but are individually noisy is not a precise answer.
    let head = survivors[0].filtered.offset;
    let spread: f64 = survivors.iter().map(|c| (c.filtered.offset - head).powi(2)).sum();
    let n = survivors.len();
    let selection_jitter = if n > 1 { (spread / (n - 1) as f64).sqrt() } else { 0.0 };
    let jitter = (selection_jitter.powi(2) + survivors[0].filtered.jitter.powi(2)).sqrt();
    (offset, jitter)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn candidate(id: usize, offset: f64, uncertainty: f64) -> Candidate {
        Candidate {
            id,
            filtered: Filtered {
                offset,
                delay: 0.001,
                // Root distance is dominated by dispersion here, which
                // makes the interval width easy to reason about in tests.
                dispersion: uncertainty,
                jitter: 1e-6,
                at: 0.0,
            },
            stratum: 2,
            root_delay: 0.0,
            root_dispersion: 0.0,
            usable: true,
            prefer: false,
        }
    }

    #[test]
    fn three_sources_that_agree_all_survive() {
        let c = [
            candidate(0, 0.000, 0.01),
            candidate(1, 0.002, 0.01),
            candidate(2, 0.001, 0.01),
        ];
        let s = select(&c, 0.0).unwrap();
        assert_eq!(s.survivors.len(), 3);
        assert!(s.falsetickers.is_empty());
        assert!(s.offset > 0.0 && s.offset < 0.002, "offset {}", s.offset);
    }

    #[test]
    fn one_liar_among_three_is_outvoted() {
        // The whole reason three independent operators are the shipped
        // default rather than one.
        let c = [
            candidate(0, 0.000, 0.01),
            candidate(1, 0.002, 0.01),
            candidate(2, 5.000, 0.01),
        ];
        let s = select(&c, 0.0).unwrap();
        assert_eq!(s.falsetickers, vec![2]);
        assert_eq!(s.survivors.len(), 2);
        assert!(s.offset.abs() < 0.01, "offset {}", s.offset);
    }

    #[test]
    fn a_confident_liar_excludes_itself_and_a_vague_one_does_not_win() {
        // The property that makes the whole scheme work: claiming to be
        // more accurate than you are is self-punishing, because a narrow
        // interval in the wrong place cannot reach the agreement.
        let c = [
            candidate(0, 0.000, 0.01),
            candidate(1, 0.001, 0.01),
            // Wrong by a second and claiming microsecond certainty.
            candidate(2, 1.000, 0.000001),
        ];
        let s = select(&c, 0.0).unwrap();
        assert_eq!(s.falsetickers, vec![2]);
    }

    #[test]
    fn two_sources_that_disagree_produce_no_majority() {
        // With two sources and no agreement there is no way to tell which
        // is right, and saying so is better than guessing.
        let c = [candidate(0, 0.0, 0.001), candidate(1, 10.0, 0.001)];
        assert_eq!(select(&c, 0.0), Err(NoSelection::NoMajority));
    }

    #[test]
    fn a_single_source_is_believed_because_there_is_nothing_to_check_it_against() {
        let c = [candidate(0, 0.5, 0.01)];
        let s = select(&c, 0.0).unwrap();
        assert_eq!(s.survivors, vec![0]);
        assert!((s.offset - 0.5).abs() < 1e-9);
    }

    #[test]
    fn an_unsynchronised_or_distant_source_is_not_a_candidate() {
        let mut unsync = candidate(0, 0.0, 0.01);
        unsync.stratum = MAX_STRATUM;
        let mut unreachable = candidate(1, 0.0, 0.01);
        unreachable.usable = false;
        let mut vague = candidate(2, 0.0, 0.01);
        vague.root_dispersion = 10.0;
        assert_eq!(
            select(&[unsync, unreachable, vague], 0.0),
            Err(NoSelection::NoCandidates)
        );
    }

    #[test]
    fn the_combined_offset_leans_on_the_more_certain_source() {
        let c = [
            candidate(0, 0.000, 0.001),
            candidate(1, 0.100, 0.100),
            candidate(2, 0.001, 0.001),
        ];
        let s = select(&c, 0.0).unwrap();
        // All three agree (the vague one's interval is wide), but the
        // average must sit near the two confident ones.
        assert!(s.offset < 0.01, "offset {} leaned the wrong way", s.offset);
    }

    #[test]
    fn a_preferred_source_leads_but_does_not_get_to_be_wrong() {
        let mut preferred = candidate(2, 0.001, 0.01);
        preferred.prefer = true;
        let c = [candidate(0, 0.000, 0.01), candidate(1, 0.002, 0.01), preferred];
        assert_eq!(select(&c, 0.0).unwrap().system_peer, 2);

        // Now make it a falseticker. Preference must not save it.
        let mut liar = candidate(2, 9.0, 0.01);
        liar.prefer = true;
        let c = [candidate(0, 0.0, 0.01), candidate(1, 0.002, 0.01), liar];
        assert_eq!(select(&c, 0.0).unwrap().falsetickers, vec![2]);
    }

    #[test]
    fn an_even_split_has_no_majority_and_says_so() {
        // Two liars that agree with each other are indistinguishable from
        // two truthful sources. With four sources split two and two there
        // is no majority, and no amount of cleverness can manufacture one
        // — so the answer is "I do not know", not a coin toss. This is the
        // failure mode an operator most needs told about, and the reason
        // the shipped default is an odd number of independent operators.
        let c = [
            candidate(0, 0.000, 0.01),
            candidate(1, 0.001, 0.01),
            candidate(2, 5.000, 0.01),
            candidate(3, 5.001, 0.01),
        ];
        assert_eq!(select(&c, 0.0), Err(NoSelection::NoMajority));
    }

    #[test]
    fn two_liars_among_five_are_outvoted() {
        // The same situation with the majority restored: three agreeing
        // sources carry it, and both liars are named.
        let c = [
            candidate(0, 0.000, 0.01),
            candidate(1, 0.001, 0.01),
            candidate(2, 0.002, 0.01),
            candidate(3, 5.000, 0.01),
            candidate(4, 5.001, 0.01),
        ];
        let s = select(&c, 0.0).unwrap();
        assert_eq!(s.falsetickers, vec![3, 4]);
        assert!(s.offset.abs() < 0.01, "offset {}", s.offset);
    }

    #[test]
    fn clustering_trims_a_noisy_outlier_from_a_larger_set() {
        let mut c: Vec<Candidate> = (0..6).map(|i| candidate(i, 0.001, 0.001)).collect();
        // One survivor inside the agreement but visibly further out, and
        // the others quiet enough that its selection jitter dominates.
        c[5].filtered.offset = 0.004;
        for x in c.iter_mut() {
            x.filtered.jitter = 1e-9;
        }
        let s = select(&c, 0.0).unwrap();
        assert!(s.survivors.len() >= MIN_SURVIVORS);
        assert!(!s.survivors.contains(&5), "the outlier should be clustered out");
    }

    #[test]
    fn clustering_never_trims_below_three() {
        let c: Vec<Candidate> = (0..3)
            .map(|i| {
                let mut x = candidate(i, i as f64 * 0.001, 0.01);
                x.filtered.jitter = 1e-12;
                x
            })
            .collect();
        assert_eq!(select(&c, 0.0).unwrap().survivors.len(), 3);
    }

    #[test]
    fn nothing_here_divides_by_zero_or_returns_a_nan() {
        // Degenerate shapes that a real network will eventually produce.
        let shapes: Vec<Vec<Candidate>> = vec![
            vec![],
            vec![candidate(0, 0.0, 0.0)],
            vec![candidate(0, 0.0, 0.0), candidate(1, 0.0, 0.0)],
            (0..8).map(|i| candidate(i, 0.0, 0.0)).collect(),
            (0..8).map(|i| candidate(i, i as f64, 0.0)).collect(),
        ];
        for shape in shapes {
            if let Ok(s) = select(&shape, 0.0) {
                assert!(s.offset.is_finite(), "offset {}", s.offset);
                assert!(s.jitter.is_finite(), "jitter {}", s.jitter);
            }
        }
    }
}
