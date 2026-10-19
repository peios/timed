//! The rule atom and the forest it forms.

use crate::pnp_core::action::{Action, Verdict};
use crate::pnp_core::condition::{Condition, CounterView};
use crate::pnp_core::pkm_alloc::{AllocError, String as PkmString, TryClone, Vec as PkmVec};
use crate::pnp_core::snapshot::Snapshot;

/// Which rules layer a forest belongs to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Layer {
    /// The packet layer proper: judged at each traversal's richest seat.
    Packet,
    /// The wire-proximate escape hatch: judged at the device seats.
    RawPacket,
    /// The flow layer (rung 2): judged once per local endpoint of a flow
    /// at the IP seats, its verdict cached on the flow as a sentence.
    Flow,
    /// The interface layer: judged per interface by a userspace executor
    /// (netd) whenever an interface appears or changes or a generation
    /// lands. The kernel never reads it. Its verdicts are `JOIN(profile)`,
    /// `IGNORE` and `DOWN`; its facts are the `Interface.*` and
    /// `Network.*` families.
    Interface,
}

impl Layer {
    /// Registry key name under `Machine\System\Network\Rules\`.
    pub fn as_str(self) -> &'static str {
        match self {
            Layer::Packet => "Packet",
            Layer::RawPacket => "RawPacket",
            Layer::Flow => "Flow",
            Layer::Interface => "Interface",
        }
    }

    /// Whether this is the interface layer (an interface, not a packet, is
    /// the subject; a userspace executor, not the kernel, judges it).
    pub fn is_interface(self) -> bool {
        matches!(self, Layer::Interface)
    }

    /// The compiled-in backstop: what answers when nothing yielded. `DROP`
    /// for the packet layers; `IGNORE` for the interface layer, so an
    /// interface no rule speaks for is left as the kernel left it.
    pub fn backstop(self) -> Verdict {
        match self {
            Layer::Interface => Verdict::Ignore,
            _ => Verdict::Drop,
        }
    }

    /// Height in the tag-visibility order (tags flow strictly upward: a
    /// layer reads only tags written at or below its own height).
    pub fn height(self) -> u8 {
        match self {
            Layer::RawPacket => 0,
            Layer::Packet => 1,
            Layer::Flow => 2,
            // No tags exist at the interface layer (ingestion refuses the
            // reads and writes); the height only keeps the order total.
            Layer::Interface => 3,
        }
    }
}

/// What one match consulted that could change its answer later: the
/// earliest moment a consulted live-time condition would next flip. A
/// flow's sentence expires then (Flow layer); other layers ignore it.
#[derive(Debug, Default, Clone, Copy)]
pub struct MatchTrace {
    /// Epoch seconds of the earliest consulted flip; `None` = never.
    pub expires_at: Option<i64>,
}

impl MatchTrace {
    /// Records a flip moment, keeping the earliest.
    pub fn note(&mut self, at: i64) {
        self.expires_at = Some(match self.expires_at {
            Some(cur) if cur <= at => cur,
            _ => at,
        });
    }
}

/// One rule: a named registry key, its match, its standing, its actions,
/// and its exceptions (children, subset-scoped).
#[derive(Debug)]
pub struct Rule {
    /// The registry key name — the attribution handle.
    pub name: PkmString,
    /// Conjunction of match conditions (empty = matches everything).
    pub conditions: PkmVec<Condition>,
    /// Effective priority (inheritance already resolved at ingestion).
    pub priority: i64,
    /// Disabled rules do not match, and their subtree is unreachable.
    pub enabled: bool,
    /// The rule's actions.
    pub actions: PkmVec<Action>,
    /// Exceptions: children carve regions out of this rule's scope.
    pub children: PkmVec<Rule>,
}

impl Rule {
    /// Whether the rule matches a snapshot (disabled rules never match).
    pub fn matches(&self, snap: &Snapshot<'_>) -> bool {
        let mut trace = MatchTrace::default();
        self.matches_traced(snap, &mut trace)
    }

    /// `matches`, recording into `trace` every live-time condition it
    /// actually consulted — true or false, since a false one can flip to
    /// true later. Conditions are ordered at ingestion so time comes last:
    /// a rule whose other conditions fail never consults its clock, and
    /// contributes no expiry.
    pub fn matches_traced(&self, snap: &Snapshot<'_>, trace: &mut MatchTrace) -> bool {
        if !self.enabled {
            return false;
        }
        for c in self.conditions.iter() {
            if let Some(at) = c.next_flip(snap) {
                trace.note(at);
            }
            if !c.matches(snap) {
                return false;
            }
        }
        true
    }

    /// Whether the action list contains a direct verdict (PASS/DROP/REJECT
    /// at the top level — verdicts inside PROMPT fallbacks do not count).
    /// This is what makes a rule eligible to speak for an abstaining
    /// descendant in the parentage walk.
    pub fn has_direct_verdict(&self) -> bool {
        self.actions.iter().any(|a| matches!(a, Action::Verdict(_)))
    }

    /// The strictest direct verdict, if any.
    pub fn direct_verdict(&self) -> Option<Verdict> {
        let mut out: Option<Verdict> = None;
        for action in self.actions.iter() {
            if let Action::Verdict(v) = action {
                out = Some(match out {
                    Some(cur) => cur.strictest(*v),
                    None => *v,
                });
            }
        }
        out
    }
}

/// A name the forest mentions, with its store hash.
#[derive(Debug)]
pub struct NamedHash {
    /// The name as written.
    pub name: PkmString,
    /// `name_hash(name)`.
    pub hash: u64,
}

impl TryClone for NamedHash {
    fn try_clone(&self) -> Result<Self, AllocError> {
        Ok(NamedHash {
            name: self.name.try_clone()?,
            hash: self.hash,
        })
    }
}

/// A forest of rule trees for one layer. Tree order carries no meaning.
///
/// Alongside the trees, the forest carries what its machinery references —
/// the complete name sets, known at build time because rules are the only
/// source of them: the tags it reads or writes, the counter streams it
/// writes, and the counter views it reads (deduplicated; conditions refer
/// to them by index).
#[derive(Debug)]
pub struct Forest {
    /// The layer this forest governs.
    pub layer: Layer,
    /// The tree roots (each policy source ships complete trees).
    pub roots: PkmVec<Rule>,
    /// Every tag name mentioned (TAG actions and Tag.<n> conditions).
    pub tag_names: PkmVec<NamedHash>,
    /// The tag names this forest writes (TAG actions, fallbacks included).
    pub tag_writes: PkmVec<NamedHash>,
    /// First (rule path, tag name) reading each tag (`Tag.<n>` conditions)
    /// — attribution for the downward-read refusal.
    pub tag_read_sites: PkmVec<(PkmString, PkmString)>,
    /// Every counter stream written (COUNT actions).
    pub streams: PkmVec<NamedHash>,
    /// Every counter view read (Counter.<n>(...) conditions).
    pub views: PkmVec<CounterView>,
    /// First (rule path, value key) mentioning each view, parallel to
    /// `views` — attribution for the dead-read refusal.
    pub view_sites: PkmVec<(PkmString, PkmString)>,
    /// Profile paths named by `JOIN(...)` actions, in first-mention order;
    /// a `Verdict::Join(i)` indexes here. Interface layer only (empty
    /// elsewhere). Paths are as written, with `\` folded to `/`.
    pub profiles: PkmVec<PkmString>,
}
