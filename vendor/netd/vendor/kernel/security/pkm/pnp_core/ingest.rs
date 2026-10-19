//! Ingestion: registry-shaped rule input -> validated `Forest`.
//!
//! The glue lowers each rule key under
//! `Machine\System\Network\Rules\<Layer>\...` into a [`RuleInput`] tree and
//! hands it here. Ingestion parses, validates, resolves priority
//! inheritance, lints for layer-impossible facts, and collects the
//! machinery name sets (tags, counter streams, counter views) — rules are
//! the only source of those names, so the whole set is known here and can
//! be checked. A forest that builds is semantically total; a forest that
//! doesn't is rejected whole (atomic generations: the old policy stays
//! until a new one builds).
//!
//! Two checks span the name sets:
//! - hash collisions among distinct tag (or stream) names are refused, so
//!   the store hash is a deterministic identity within a running policy;
//! - a counter view over a stream no rule writes is statically dead (it
//!   can only ever read absent) and is refused. Streams are machine-scoped,
//!   so the writer may live in another layer's forest: [`check_forests`]
//!   runs that check across every forest being published together.

use crate::pnp_core::action::{parse_action, Action, ParseFailure, Verdict};
use crate::pnp_core::condition::{
    AddrPattern, CondKey, CondOp, Condition, CounterView, FactFamily, FactId, IntPattern,
};
use crate::pnp_core::error::{BuildError, LintKind, LintWarning};
use crate::pnp_core::hash::name_hash;
use crate::pnp_core::pkm_alloc::{String as PkmString, TryClone, Vec as PkmVec};
use crate::pnp_core::rule::{Forest, Layer, NamedHash, Rule};
use crate::pnp_core::sid::Sid;
use crate::pnp_core::snapshot::tcp_flags;
use crate::pnp_core::strutil::{join_path, str_to_pkm};
use crate::pnp_core::value::RegValue;

/// One rule key as read from the registry: its name, its values, and its
/// subkeys (exceptions).
#[derive(Debug, Default)]
pub struct RuleInput {
    /// The key name.
    pub name: PkmString,
    /// The key's values: (value name, value).
    pub values: PkmVec<(PkmString, RegValue)>,
    /// The key's subkeys.
    pub children: PkmVec<RuleInput>,
}

/// A built forest plus its lint findings.
#[derive(Debug)]
pub struct BuildOutput {
    /// The validated forest.
    pub forest: Forest,
    /// Non-fatal findings for the authoring surface to shout about.
    pub lints: PkmVec<LintWarning>,
}

/// What the walk collects across the whole forest.
struct Collector {
    tag_names: PkmVec<NamedHash>,
    tag_writes: PkmVec<NamedHash>,
    /// First (rule path, tag name) reading each tag.
    tag_read_sites: PkmVec<(PkmString, PkmString)>,
    streams: PkmVec<NamedHash>,
    views: PkmVec<CounterView>,
    /// First (rule path, value key) mentioning each view, parallel to
    /// `views` — attribution for the dead-read refusal.
    view_sites: PkmVec<(PkmString, PkmString)>,
    /// Profile paths named by `JOIN`, first-mention order.
    profiles: PkmVec<PkmString>,
}

impl Collector {
    /// Interns a profile path using the executor's ASCII-insensitive lookup,
    /// retaining the first spelling, and returns its index.
    fn note_profile(&mut self, path: &str) -> Result<u32, BuildError> {
        if let Some(i) = self
            .profiles
            .iter()
            .position(|p| p.as_str().eq_ignore_ascii_case(path))
        {
            return Ok(i as u32);
        }
        self.profiles.push(str_to_pkm(path)?)?;
        Ok((self.profiles.len() - 1) as u32)
    }

    fn note_name(list: &mut PkmVec<NamedHash>, name: &str) -> Result<(), BuildError> {
        if list.iter().any(|n| n.name.as_str() == name) {
            return Ok(());
        }
        list.push(NamedHash {
            name: str_to_pkm(name)?,
            hash: name_hash(name),
        })?;
        Ok(())
    }

    fn note_tag(&mut self, name: &str) -> Result<(), BuildError> {
        Self::note_name(&mut self.tag_names, name)
    }

    fn note_tag_write(&mut self, name: &str) -> Result<(), BuildError> {
        Self::note_name(&mut self.tag_writes, name)
    }

    fn note_tag_read(&mut self, name: &str, rule: &PkmString) -> Result<(), BuildError> {
        if self.tag_read_sites.iter().any(|(_, n)| n.as_str() == name) {
            return Ok(());
        }
        self.tag_read_sites
            .push((rule.try_clone_err()?, str_to_pkm(name)?))?;
        Ok(())
    }

    fn note_stream(&mut self, name: &str) -> Result<(), BuildError> {
        Self::note_name(&mut self.streams, name)
    }

    fn note_view(
        &mut self,
        view: CounterView,
        rule: &PkmString,
        key: &str,
    ) -> Result<u32, BuildError> {
        if let Some(i) = self.views.iter().position(|v| *v == view) {
            return Ok(i as u32);
        }
        self.views.push(view)?;
        self.view_sites
            .push((rule.try_clone_err()?, str_to_pkm(key)?))?;
        Ok((self.views.len() - 1) as u32)
    }

    /// Records the names an action list mentions (PROMPT fallbacks
    /// included: a fallback TAG is still a TAG).
    fn note_actions(&mut self, actions: &[Action]) -> Result<(), BuildError> {
        for action in actions {
            match action {
                Action::Tag { name, .. } => {
                    self.note_tag(name.as_str())?;
                    self.note_tag_write(name.as_str())?;
                }
                Action::Count { name, .. } => self.note_stream(name.as_str())?,
                Action::Prompt { fallback, .. } => {
                    if let Some(inner) = fallback.action() {
                        self.note_actions(core::slice::from_ref(inner))?;
                    }
                }
                _ => {}
            }
        }
        Ok(())
    }
}

/// Builds a layer's forest from registry-shaped input.
pub fn build_forest(layer: Layer, roots: &[RuleInput]) -> Result<BuildOutput, BuildError> {
    let mut out_roots = PkmVec::new();
    let mut lints = PkmVec::new();
    let mut collector = Collector {
        tag_names: PkmVec::new(),
        tag_writes: PkmVec::new(),
        tag_read_sites: PkmVec::new(),
        streams: PkmVec::new(),
        views: PkmVec::new(),
        view_sites: PkmVec::new(),
        profiles: PkmVec::new(),
    };
    // The tree is walked with an explicit stack, not recursion: this runs
    // on a kernel stack, and a rule's parse is too large a frame to repeat
    // once per level of nesting (PEI-1299). Depth costs heap here.
    let mut stack: PkmVec<BuildFrame<'_>> = PkmVec::new();
    for input in roots {
        let rule = build_node(layer, input, "", 0, &mut lints, &mut collector)?;
        stack.push(BuildFrame {
            input,
            rule,
            path: join_path("", input.name.as_str())?,
            next: 0,
        })?;
        while let Some(top) = stack.last_mut() {
            let input: &RuleInput = top.input;
            if let Some(child) = input.children.get(top.next) {
                top.next += 1;
                let rule = build_node(
                    layer,
                    child,
                    top.path.as_str(),
                    top.rule.priority,
                    &mut lints,
                    &mut collector,
                )?;
                let path = join_path(top.path.as_str(), child.name.as_str())?;
                stack.push(BuildFrame {
                    input: child,
                    rule,
                    path,
                    next: 0,
                })?;
                continue;
            }
            let Some(done) = stack.pop() else { break };
            match stack.last_mut() {
                Some(parent) => parent.rule.children.push(done.rule)?,
                None => out_roots.push(done.rule)?,
            }
        }
    }
    check_collisions(&collector.tag_names, true)?;
    check_collisions(&collector.streams, false)?;
    Ok(BuildOutput {
        forest: Forest {
            layer,
            roots: out_roots,
            tag_names: collector.tag_names,
            tag_writes: collector.tag_writes,
            tag_read_sites: collector.tag_read_sites,
            streams: collector.streams,
            views: collector.views,
            view_sites: collector.view_sites,
            profiles: collector.profiles,
        },
        lints,
    })
}

/// Cross-forest checks for a set of forests published together: tag and
/// stream hashes must be distinct across all of them (the stores are
/// machine-wide), every counter view must have a writer somewhere, and no
/// forest reads a tag a higher layer writes (tags flow strictly upward —
/// the visibility law, enforced statically because rules are the only
/// source of tag names).
pub fn check_forests(forests: &[&Forest]) -> Result<(), BuildError> {
    for reader in forests {
        for (rule, name) in reader.tag_read_sites.iter() {
            for writer in forests {
                if writer.layer.height() <= reader.layer.height() {
                    continue;
                }
                if writer
                    .tag_writes
                    .iter()
                    .any(|w| w.name.as_str() == name.as_str())
                {
                    return Err(BuildError::TagDownwardRead {
                        rule: rule.try_clone_err()?,
                        name: name.try_clone_err()?,
                    });
                }
            }
        }
    }
    let mut all_tags: PkmVec<NamedHash> = PkmVec::new();
    let mut all_streams: PkmVec<NamedHash> = PkmVec::new();
    for forest in forests {
        for t in forest.tag_names.iter() {
            if !all_tags.iter().any(|n| n.name.as_str() == t.name.as_str()) {
                all_tags.push(t.try_clone()?)?;
            }
        }
        for s in forest.streams.iter() {
            if !all_streams
                .iter()
                .any(|n| n.name.as_str() == s.name.as_str())
            {
                all_streams.push(s.try_clone()?)?;
            }
        }
    }
    check_collisions(&all_tags, true)?;
    check_collisions(&all_streams, false)?;
    for forest in forests {
        for (i, view) in forest.views.iter().enumerate() {
            if !all_streams.iter().any(|s| s.hash == view.hash) {
                let (rule, key) = &forest.view_sites[i];
                return Err(BuildError::CounterNeverWritten {
                    rule: rule.try_clone_err()?,
                    key: key.try_clone_err()?,
                });
            }
        }
    }
    Ok(())
}

fn check_collisions(names: &[NamedHash], tags: bool) -> Result<(), BuildError> {
    for (i, a) in names.iter().enumerate() {
        for b in names[i + 1..].iter() {
            if a.hash == b.hash && a.name.as_str() != b.name.as_str() {
                let a = a.name.try_clone_err()?;
                let b = b.name.try_clone_err()?;
                return Err(if tags {
                    BuildError::TagHashCollision { a, b }
                } else {
                    BuildError::StreamHashCollision { a, b }
                });
            }
        }
    }
    Ok(())
}

/// One open rule on the build stack: its input, the rule built from its
/// own values, its path, and the next child to build.
struct BuildFrame<'i> {
    input: &'i RuleInput,
    rule: Rule,
    path: PkmString,
    next: usize,
}

/// Builds one rule from its own values, without its exceptions (the
/// caller attaches those). Never inlined: its frame must appear on the
/// stack once, whatever the depth of the tree.
#[inline(never)]
fn build_node(
    layer: Layer,
    input: &RuleInput,
    parent_path: &str,
    parent_priority: i64,
    lints: &mut PkmVec<LintWarning>,
    collector: &mut Collector,
) -> Result<Rule, BuildError> {
    let name = input.name.as_str();
    if name.is_empty() || name.contains('/') || name.contains('\\') {
        return Err(BuildError::BadRuleName {
            rule: join_path(parent_path, name)?,
        });
    }
    let path = join_path(parent_path, name)?;

    let mut conditions = PkmVec::new();
    // Live-time conditions are evaluated last (see Rule::matches_traced):
    // collected separately here and appended after the rest.
    let mut time_conditions = PkmVec::new();
    let mut priority = parent_priority;
    let mut enabled = true;
    let mut actions = PkmVec::new();

    for (key, value) in input.values.iter() {
        match key.as_str() {
            "Priority" => {
                priority = value.as_int().ok_or(BuildError::BadPriority {
                    rule: path.try_clone_err()?,
                })?;
            }
            "Enabled" => match value.as_int() {
                Some(0) => enabled = false,
                Some(1) => enabled = true,
                _ => {
                    return Err(BuildError::BadEnabled {
                        rule: path.try_clone_err()?,
                    })
                }
            },
            "Actions" => {
                let list = match value {
                    RegValue::List(items) => items,
                    _ => {
                        return Err(BuildError::BadActionsValue {
                            rule: path.try_clone_err()?,
                        })
                    }
                };
                for item in list.iter() {
                    let expr = item.as_str().ok_or(BuildError::BadActionsValue {
                        rule: path.try_clone_err()?,
                    })?;
                    let action = parse_action_for_rule(expr, &path)?;
                    let action = place_action(layer, action, &path, collector)?;
                    actions.push(action)?;
                }
            }
            _ => {
                let mut condition = parse_condition(key.as_str(), value, &path, collector)?;
                condition.never = lint_condition(layer, &condition, &path, key.as_str(), lints)?;
                if condition.is_live_time() {
                    time_conditions.push(condition)?;
                } else {
                    conditions.push(condition)?;
                }
            }
        }
    }
    for condition in time_conditions.into_iter() {
        conditions.push(condition)?;
    }
    collector.note_actions(actions.as_slice())?;

    // A rule key with no Actions value is legal and means NULL (abstain):
    // authors nest pure-grouping rules. An empty Actions list means the same.

    Ok(Rule {
        name: str_to_pkm(name)?,
        conditions,
        priority,
        enabled,
        actions,
        children: PkmVec::new(),
    })
}

/// Checks an action against the rule's layer and lowers it to its
/// evaluation form. The interface layer speaks `JOIN`, `IGNORE`, `DOWN`,
/// `NULL` and `REPORT` and nothing else; the packet layers speak
/// everything but the interface verdicts. A `JOIN` is interned: the
/// profile path goes into the forest's table and the action becomes a
/// `Verdict::Join(index)`.
fn place_action(
    layer: Layer,
    action: Action,
    path: &PkmString,
    collector: &mut Collector,
) -> Result<Action, BuildError> {
    let refuse = || BuildError::ActionNotAtLayer {
        rule: path.try_clone_err().unwrap_or_default(),
    };
    if layer.is_interface() {
        match action {
            Action::Null | Action::Report { .. } => Ok(action),
            Action::Verdict(v) if v.is_interface() => Ok(action),
            Action::Join { profile } => Ok(Action::Verdict(Verdict::Join(
                collector.note_profile(profile.as_str())?,
            ))),
            _ => Err(refuse()),
        }
    } else {
        match &action {
            Action::Join { .. } => Err(refuse()),
            Action::Verdict(v) if v.is_interface() => Err(refuse()),
            Action::Prompt { fallback, .. } => {
                let bad = match fallback.action() {
                    Some(Action::Join { .. }) => true,
                    Some(Action::Verdict(v)) => v.is_interface(),
                    _ => false,
                };
                if bad {
                    Err(refuse())
                } else {
                    Ok(action)
                }
            }
            _ => Ok(action),
        }
    }
}

fn parse_action_for_rule(expr: &str, path: &PkmString) -> Result<Action, BuildError> {
    match parse_action(expr) {
        Ok(action) => Ok(action),
        Err(ParseFailure::Alloc) => Err(BuildError::Alloc),
        Err(ParseFailure::Parse(detail)) => Err(BuildError::BadAction {
            rule: path.try_clone_err()?,
            detail,
        }),
    }
}

fn parse_condition(
    key: &str,
    value: &RegValue,
    path: &PkmString,
    collector: &mut Collector,
) -> Result<Condition, BuildError> {
    let (prefix, op_name) = match key.rfind('.') {
        Some(i) => (&key[..i], &key[i + 1..]),
        None => {
            return Err(BuildError::UnknownFact {
                rule: path.try_clone_err()?,
                key: str_to_pkm(key)?,
            })
        }
    };

    let cond_key = if let Some(tag) = prefix.strip_prefix("Tag.") {
        if tag.is_empty() {
            return Err(BuildError::UnknownFact {
                rule: path.try_clone_err()?,
                key: str_to_pkm(key)?,
            });
        }
        collector.note_tag(tag)?;
        collector.note_tag_read(tag, path)?;
        CondKey::Tag {
            name: str_to_pkm(tag)?,
            hash: name_hash(tag),
        }
    } else if let Some(spec) = prefix.strip_prefix("Counter.") {
        let view = CounterView::parse(spec).map_err(|_| BuildError::BadCounterView {
            rule: path.try_clone_err().unwrap_or_default(),
            key: str_to_pkm(key).unwrap_or_default(),
        })?;
        CondKey::Counter(collector.note_view(view, path, key)?)
    } else {
        match FactId::from_key(prefix) {
            Some(fact) => CondKey::Fact(fact),
            None => {
                return Err(BuildError::UnknownFact {
                    rule: path.try_clone_err()?,
                    key: str_to_pkm(key)?,
                })
            }
        }
    };

    let family = match &cond_key {
        CondKey::Fact(fact) => fact.family(),
        CondKey::Tag { .. } | CondKey::Counter(_) => FactFamily::Int,
    };
    let fact_for_names = match &cond_key {
        CondKey::Fact(fact) => Some(*fact),
        _ => None,
    };

    let bad_op = || mk_error(path, key, false);
    let bad_pattern = || mk_error(path, key, true);

    let op = match (op_name, family) {
        // Present applies to every key: a fact, a tag, a counter view.
        ("Present", _) => CondOp::Present(match scalar_int(value) {
            Some(0) => false,
            Some(1) => true,
            _ => return Err(bad_pattern()),
        }),
        ("Equal", FactFamily::Int) => {
            let mut patterns = PkmVec::new();
            for_each_element(value, &mut |el| {
                let p = int_pattern(el, fact_for_names).ok_or(())?;
                patterns.push(p).map_err(|_| ())
            })
            .map_err(|()| bad_pattern())?;
            CondOp::EqualInt(patterns)
        }
        ("Equal", FactFamily::Str) => {
            // Process GUIDs compare as lowercase unbraced PCDS text: the
            // glue emits that, so patterns are folded once here, and the
            // braced canonical form PCDS parsers accept is unbraced.
            let fold = matches!(
                fact_for_names,
                Some(FactId::LocalProcess) | Some(FactId::RemoteProcess)
            );
            let mut patterns = PkmVec::new();
            for_each_element(value, &mut |el| {
                let mut s = el.as_str().ok_or(())?;
                if fold {
                    if let Some(inner) = s.strip_prefix('{').and_then(|t| t.strip_suffix('}')) {
                        s = inner;
                    }
                }
                let mut out = PkmString::new();
                for c in s.chars() {
                    out.push(if fold { c.to_ascii_lowercase() } else { c })
                        .map_err(|_| ())?;
                }
                patterns.push(out).map_err(|_| ())
            })
            .map_err(|()| bad_pattern())?;
            CondOp::EqualStr(patterns)
        }
        ("Equal", FactFamily::Sid) => {
            let mut patterns = PkmVec::new();
            for_each_element(value, &mut |el| {
                let s = el.as_str().ok_or(())?;
                let sid = sid_pattern(s, fact_for_names).ok_or(())?;
                patterns.push(sid).map_err(|_| ())
            })
            .map_err(|()| bad_pattern())?;
            CondOp::EqualSid(patterns)
        }
        ("Equal", FactFamily::Addr) => {
            let mut patterns = PkmVec::new();
            for_each_element(value, &mut |el| {
                let s = el.as_str().ok_or(())?;
                let p = addr_pattern(s).ok_or(())?;
                patterns.push(p).map_err(|_| ())
            })
            .map_err(|()| bad_pattern())?;
            CondOp::EqualAddr(patterns)
        }
        ("Equal", FactFamily::Mac) => {
            let mut patterns = PkmVec::new();
            for_each_element(value, &mut |el| {
                let s = el.as_str().ok_or(())?;
                let mac = parse_mac(s).ok_or(())?;
                patterns.push(mac).map_err(|_| ())
            })
            .map_err(|()| bad_pattern())?;
            CondOp::EqualMac(patterns)
        }
        ("GreaterThan", FactFamily::Int) => {
            CondOp::Gt(scalar_int_named(value, fact_for_names).ok_or_else(bad_pattern)?)
        }
        ("LessThan", FactFamily::Int) => {
            CondOp::Lt(scalar_int_named(value, fact_for_names).ok_or_else(bad_pattern)?)
        }
        ("Has", FactFamily::Flags) => CondOp::Has(flag_mask(value).ok_or_else(bad_pattern)?),
        ("Hasnt", FactFamily::Flags) => CondOp::Hasnt(flag_mask(value).ok_or_else(bad_pattern)?),
        _ => return Err(bad_op()),
    };

    Ok(Condition {
        key: cond_key,
        op,
        never: false,
    })
}

/// Builds a `BadPattern`/`BadOperator` error; if allocating the message
/// context itself fails, degrades to `Alloc`.
fn mk_error(path: &PkmString, key: &str, pattern: bool) -> BuildError {
    match (
        crate::pnp_core::pkm_alloc::TryClone::try_clone(path),
        str_to_pkm(key),
    ) {
        (Ok(rule), Ok(key)) => {
            if pattern {
                BuildError::BadPattern { rule, key }
            } else {
                BuildError::BadOperator { rule, key }
            }
        }
        _ => BuildError::Alloc,
    }
}

fn for_each_element(
    value: &RegValue,
    f: &mut dyn FnMut(&RegValue) -> Result<(), ()>,
) -> Result<(), ()> {
    match value {
        RegValue::List(items) => {
            if items.is_empty() {
                return Err(());
            }
            for item in items.iter() {
                match item {
                    RegValue::List(_) => return Err(()),
                    other => f(other)?,
                }
            }
            Ok(())
        }
        other => f(other),
    }
}

fn scalar_int(value: &RegValue) -> Option<i64> {
    match value {
        RegValue::Int(v) => Some(*v),
        RegValue::Str(s) => s.as_str().parse().ok(),
        RegValue::List(_) => None,
    }
}

/// `scalar_int`, also accepting the fact's named values (`medium` for an
/// integrity level), so a threshold reads as naturally as an equality.
fn scalar_int_named(value: &RegValue, fact: Option<FactId>) -> Option<i64> {
    match value {
        RegValue::Str(s) if s.as_str().parse::<i64>().is_err() => named_int(s.as_str(), fact?),
        other => scalar_int(other),
    }
}

fn int_pattern(el: &RegValue, fact: Option<FactId>) -> Option<IntPattern> {
    match el {
        RegValue::Int(v) => Some(IntPattern::Exact(*v)),
        RegValue::Str(s) => {
            let s = s.as_str();
            if let Ok(v) = s.parse::<i64>() {
                return Some(IntPattern::Exact(v));
            }
            if let Some((a, b)) = s.split_once('-') {
                if let (Ok(a), Ok(b)) = (a.parse::<i64>(), b.parse::<i64>()) {
                    if a <= b {
                        return Some(IntPattern::Range(a, b));
                    }
                }
                return None;
            }
            named_int(s, fact?).map(IntPattern::Exact)
        }
        RegValue::List(_) => None,
    }
}

/// Authoring-friendly names for two facts whose numeric values nobody
/// remembers. Case-insensitive.
fn named_int(name: &str, fact: FactId) -> Option<i64> {
    let eq = |s: &str| -> bool {
        name.len() == s.len()
            && name
                .bytes()
                .zip(s.bytes())
                .all(|(a, b)| a.to_ascii_lowercase() == b)
    };
    match fact {
        FactId::EtherType => {
            if eq("ipv4") {
                Some(0x0800)
            } else if eq("ipv6") {
                Some(0x86DD)
            } else if eq("arp") {
                Some(0x0806)
            } else {
                None
            }
        }
        FactId::Protocol => {
            if eq("tcp") {
                Some(6)
            } else if eq("udp") {
                Some(17)
            } else if eq("icmp") {
                Some(1)
            } else if eq("icmpv6") {
                Some(58)
            } else if eq("sctp") {
                Some(132)
            } else {
                None
            }
        }
        // The five standard integrity levels; any other level is written
        // as its number.
        FactId::LocalIntegrity | FactId::RemoteIntegrity => {
            if eq("untrusted") {
                Some(0)
            } else if eq("low") {
                Some(4096)
            } else if eq("medium") {
                Some(8192)
            } else if eq("high") {
                Some(12288)
            } else if eq("system") {
                Some(16384)
            } else {
                None
            }
        }
        _ => None,
    }
}

/// A SID pattern: the textual SID, or a name. Service facts take a
/// service name (derived exactly as the token's service SID was); every
/// other SID fact takes a well-known principal name. A name that is
/// neither is refused rather than guessed at — a typo in a group name must
/// not quietly become a service SID that matches nothing.
fn sid_pattern(s: &str, fact: Option<FactId>) -> Option<Sid> {
    let s = s.trim();
    if s.len() >= 2 && (s.starts_with("S-") || s.starts_with("s-")) {
        return Sid::parse_str(s);
    }
    if s.is_empty() {
        return None;
    }
    match fact? {
        FactId::LocalService | FactId::RemoteService => Some(Sid::service(s)),
        _ => Sid::well_known(s),
    }
}

fn addr_pattern(s: &str) -> Option<AddrPattern> {
    use core::net::IpAddr;
    if let Some((addr, prefix)) = s.split_once('/') {
        let addr: IpAddr = addr.parse().ok()?;
        let prefix: u8 = prefix.parse().ok()?;
        let width = if addr.is_ipv4() { 32 } else { 128 };
        if prefix > width {
            return None;
        }
        return Some(AddrPattern::Cidr { addr, prefix });
    }
    if let Ok(addr) = s.parse::<IpAddr>() {
        return Some(AddrPattern::Exact(addr));
    }
    // Ranges only make sense for v4 here ('-' never appears in a v6
    // address, and v6 ranges are better written as prefixes anyway).
    if let Some((a, b)) = s.split_once('-') {
        let a: IpAddr = a.parse().ok()?;
        let b: IpAddr = b.parse().ok()?;
        if a.is_ipv4() == b.is_ipv4() {
            return Some(AddrPattern::Range(a, b));
        }
    }
    None
}

fn parse_mac(s: &str) -> Option<[u8; 6]> {
    let mut out = [0u8; 6];
    let mut parts = s.split(':');
    for slot in out.iter_mut() {
        let part = parts.next()?;
        if part.len() != 2 {
            return None;
        }
        *slot = u8::from_str_radix(part, 16).ok()?;
    }
    if parts.next().is_some() {
        return None;
    }
    Some(out)
}

fn flag_mask(value: &RegValue) -> Option<u8> {
    let mut mask = 0u8;
    let mut ok = true;
    let result = for_each_element(
        value,
        &mut |el| match el.as_str().and_then(tcp_flags::from_name) {
            Some(bit) => {
                mask |= bit;
                Ok(())
            }
            None => {
                ok = false;
                Err(())
            }
        },
    );
    if result.is_err() || !ok || mask == 0 {
        return None;
    }
    Some(mask)
}

/// Facts that never exist at a layer: conditions over them are legal but
/// can never hold (absent-fact law), so the authoring surface should shout.
/// One exception is not legal: `Present`, which looks through the law,
/// would turn such a fact into an always-true or always-false condition
/// with a meaningful-looking name, so it refuses the generation. Returns
/// whether the key never exists at the layer, so the condition can be
/// built never to hold.
fn lint_condition(
    layer: Layer,
    condition: &Condition,
    path: &PkmString,
    key: &str,
    lints: &mut PkmVec<LintWarning>,
) -> Result<bool, BuildError> {
    let never = match layer {
        // The interface layer has no stores: a tag or counter read there
        // is not dead, it is meaningless, so it refuses outright. Its
        // facts are the `Interface.*` / `Network.*` families plus the
        // interface name; a packet fact never exists on an interface.
        Layer::Interface => match condition.key {
            CondKey::Tag { .. } | CondKey::Counter(_) => {
                return Err(BuildError::KeyNotAtLayer {
                    rule: path.try_clone_err()?,
                    key: str_to_pkm(key)?,
                })
            }
            CondKey::Fact(f) => !f.is_at_interface_layer(),
        },
        // Flow-only facts (Related, Start.*) exist on no packet; the
        // interface layer's own facts exist on no packet either. The
        // network context (`Network.Id`, `Network.Name`, `Network.Trust`)
        // does: the kernel reads it per interface from netd's inventory.
        Layer::Packet => {
            matches!(condition.key, CondKey::Fact(f) if f.is_flow_only() || f.is_interface_only())
        }
        // The RawPacket seat stands before conntrack (inbound) and reads no
        // other layer's state in either direction (ratified visibility law).
        Layer::RawPacket => {
            matches!(
                condition.key,
                CondKey::Fact(FactId::FlowState) | CondKey::Tag { .. }
            ) || matches!(condition.key, CondKey::Fact(f) if f.is_flow_only() || f.is_interface_only())
        }
        // A Flow fact is one identical for every packet of the flow; the
        // per-packet facts are never given to a Flow snapshot.
        Layer::Flow => matches!(
            condition.key,
            CondKey::Fact(f) if !f.is_flow_invariant() || f.is_interface_only()
        ),
    };
    if never {
        if matches!(condition.op, CondOp::Present(_)) {
            return Err(BuildError::PresentNeverAtLayer {
                rule: path.try_clone_err()?,
                key: str_to_pkm(key)?,
            });
        }
        lints.push(LintWarning {
            rule: path.try_clone_err()?,
            key: str_to_pkm(key)?,
            kind: LintKind::FactNeverPresentAtLayer,
        })?;
    }
    Ok(never)
}

/// Small extension: fallible clone that maps into `BuildError`.
trait TryCloneErr: Sized {
    fn try_clone_err(&self) -> Result<Self, BuildError>;
}

impl TryCloneErr for PkmString {
    fn try_clone_err(&self) -> Result<Self, BuildError> {
        crate::pnp_core::pkm_alloc::TryClone::try_clone(self).map_err(|_| BuildError::Alloc)
    }
}
