//! The interface layer, as netd executes it.
//!
//! `Machine\System\Network\Rules\Interface` is a PNP rules forest whose
//! subject is an interface: conditions over the `Interface.*` and
//! `Network.*` facts, verdicts `JOIN(profile)`, `IGNORE` and `DOWN`. The
//! kernel never reads it; netd builds it with `pnp-core` — the same
//! ingestion, collation and refusal the kernel uses for the packet layers,
//! so the two cannot disagree about what a rule means — and judges every
//! interface against it whenever the interface changes or a generation
//! lands.
//!
//! A generation is refused as a whole, and the last good one kept, when a
//! rule is malformed, a `JOIN` names no profile, or a profile is
//! malformed. A `JOIN` that names a *disabled* profile is not a fault: the
//! rule abstains, exactly as if its action were `NULL`, and the forest
//! answers without it (its parent, another tree, or the backstop).
//!
//! Pure: input is the neutral `RawKey` trees netd lowers from the
//! registry. Here rather than in netd so that a program checking a change
//! to the interface layer before making it applies netd's own laws to it.

use std::collections::BTreeMap;

use pnp_core::{
    BuildError, EvalContext, Forest, Layer, RegValue, RuleInput, Snapshot, Verdict, build_forest,
    evaluate,
};

use crate::profile::{self, Profile};
use crate::raw::{RawKey, RawValue};

/// A built generation: the forest and the profiles it may name.
#[derive(Debug, Default)]
pub struct Policy {
    /// `None` when `Rules\Interface` is absent: the backstop answers for
    /// every interface.
    pub forest: Option<Forest>,
    /// Resolved profiles by lower-cased path.
    pub profiles: BTreeMap<String, Profile>,
    /// Non-fatal findings (a condition that can never hold at this layer).
    pub lints: Vec<String>,
}

/// What the layer said about one interface.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Outcome {
    /// Stand in this profile.
    Join(Profile),
    /// Never touch the interface.
    Ignore,
    /// Keep it administratively down.
    Down,
}

impl Outcome {
    pub fn as_str(&self) -> &'static str {
        match self {
            Outcome::Join(_) => "JOIN",
            Outcome::Ignore => "IGNORE",
            Outcome::Down => "DOWN",
        }
    }

    pub fn profile(&self) -> Option<&Profile> {
        match self {
            Outcome::Join(p) => Some(p),
            _ => None,
        }
    }
}

/// One judgment, with its attribution.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Judgment {
    pub outcome: Outcome,
    /// The rule path that spoke, or `backstop`.
    pub rule: String,
    pub backstop: bool,
    /// Two rules tied on priority named different profiles. The outcome
    /// is `Ignore` — no answer is the honest answer — and `rule` names
    /// the two, for `net status`.
    pub conflict: bool,
}

impl Default for Judgment {
    fn default() -> Self {
        Judgment {
            outcome: Outcome::Ignore,
            rule: "backstop".into(),
            backstop: true,
            conflict: false,
        }
    }
}

/// If `expr` is a `JOIN(...)`, its target path: whitespace stripped,
/// `\` folded to `/`, lower-cased for lookup.
fn join_target(expr: &str) -> Option<String> {
    let compact: String = expr.chars().filter(|c| !c.is_ascii_whitespace()).collect();
    if compact.len() < 6
        || !compact.as_bytes()[..5].eq_ignore_ascii_case(b"join(")
        || !compact.ends_with(')')
    {
        return None;
    }
    Some(
        compact[5..compact.len() - 1]
            .replace('\\', "/")
            .to_ascii_lowercase(),
    )
}

fn lower(
    key: &RawKey,
    path: &str,
    profiles: &BTreeMap<String, Profile>,
) -> Result<RuleInput, String> {
    let here = if path.is_empty() {
        key.name.clone()
    } else {
        format!("{path}/{}", key.name)
    };
    let mut input = RuleInput {
        name: key.name.as_str().into(),
        values: Vec::new().into(),
        children: Vec::new().into(),
    };
    for (name, value) in &key.values {
        let value = match value {
            RawValue::Int(i) => RegValue::Int(*i),
            RawValue::Str(s) => RegValue::Str(s.as_str().into()),
            RawValue::List(items) => {
                let is_actions = name.eq_ignore_ascii_case("Actions");
                let mut out: Vec<RegValue> = Vec::new();
                for item in items {
                    // A JOIN of a disabled profile abstains: the executor's
                    // half of the `Enabled` law, applied before the build so
                    // the forest's own parentage walk does the rest.
                    let text = match join_target(item) {
                        Some(target) if is_actions => match profiles.get(&target) {
                            Some(p) if !p.enabled => "NULL",
                            _ => item.as_str(),
                        },
                        _ => item.as_str(),
                    };
                    out.push(RegValue::Str(text.into()));
                }
                RegValue::List(out.into())
            }
            RawValue::Other => {
                return Err(format!("rule {here}: value {name} has an unsupported type"));
            }
        };
        input
            .values
            .push((name.as_str().into(), value))
            .map_err(|_| "out of memory".to_owned())?;
    }
    for child in &key.children {
        input
            .children
            .push(lower(child, &here, profiles)?)
            .map_err(|_| "out of memory".to_owned())?;
    }
    Ok(input)
}

fn describe(e: &BuildError) -> String {
    match e {
        BuildError::Alloc => "out of memory".into(),
        BuildError::UnknownFact { rule, key } => format!("rule {rule}: unknown fact {key}"),
        BuildError::BadOperator { rule, key } => format!("rule {rule}: bad operator in {key}"),
        BuildError::BadPattern { rule, key } => format!("rule {rule}: bad pattern in {key}"),
        BuildError::BadCounterView { rule, key } => format!("rule {rule}: bad counter view {key}"),
        BuildError::BadActionsValue { rule } => format!("rule {rule}: Actions is not a list"),
        BuildError::BadAction { rule, detail } => format!("rule {rule}: bad action ({detail:?})"),
        BuildError::PromptChainTooDeep { rule } => format!("rule {rule}: PROMPT chain too deep"),
        BuildError::BadPriority { rule } => format!("rule {rule}: Priority is not an integer"),
        BuildError::BadEnabled { rule } => format!("rule {rule}: Enabled is not 0 or 1"),
        BuildError::BadRuleName { rule } => format!("rule {rule}: bad name"),
        BuildError::TagHashCollision { a, b } | BuildError::StreamHashCollision { a, b } => {
            format!("names {a} and {b} collide")
        }
        BuildError::CounterNeverWritten { rule, key } => {
            format!("rule {rule}: {key} reads a stream nobody writes")
        }
        BuildError::TagDownwardRead { rule, name } => {
            format!("rule {rule}: downward read of {name}")
        }
        BuildError::PresentNeverAtLayer { rule, key } => {
            format!("rule {rule}: {key} on a fact that never exists at this layer")
        }
        BuildError::KeyNotAtLayer { rule, key } => {
            format!("rule {rule}: {key} does not exist at the interface layer")
        }
        BuildError::ActionNotAtLayer { rule } => {
            format!("rule {rule}: an action the interface layer does not speak")
        }
    }
}

/// Builds a generation. `rules` is the `Rules\Interface` key (its subkeys
/// are the root rules); `profiles` is the `Profiles` key.
pub fn build(rules: Option<&RawKey>, profiles: Option<&RawKey>) -> Result<Policy, String> {
    let profiles = match profiles {
        Some(root) => profile::resolve(root)?,
        None => BTreeMap::new(),
    };
    let Some(rules) = rules else {
        return Ok(Policy {
            forest: None,
            profiles,
            lints: Vec::new(),
        });
    };
    let mut inputs = Vec::new();
    for child in &rules.children {
        inputs.push(lower(child, "", &profiles)?);
    }
    let out = build_forest(Layer::Interface, &inputs).map_err(|e| describe(&e))?;
    for path in out.forest.profiles.iter() {
        if !profiles.contains_key(&path.as_str().to_ascii_lowercase()) {
            return Err(format!("JOIN({}) names no profile", path.as_str()));
        }
    }
    let lints = out
        .lints
        .iter()
        .map(|l| {
            format!(
                "rule {}: {} can never hold at the interface layer",
                l.rule.as_str(),
                l.key.as_str()
            )
        })
        .collect();
    Ok(Policy {
        forest: Some(out.forest),
        profiles,
        lints,
    })
}

impl Policy {
    /// Judges one interface.
    pub fn judge(&self, snap: &Snapshot<'_>) -> Judgment {
        let Some(forest) = &self.forest else {
            return Judgment::default();
        };
        let Ok(e) = evaluate(forest, snap, &EvalContext::default()) else {
            return Judgment::default();
        };
        if e.conflict {
            let mut names: Vec<&str> = e
                .candidates
                .iter()
                .filter(|c| {
                    c.priority == e.candidates.iter().map(|c| c.priority).max().unwrap_or(0)
                })
                .map(|c| c.rule.as_str())
                .collect();
            names.sort_unstable();
            names.dedup();
            return Judgment {
                outcome: Outcome::Ignore,
                rule: names.join(" vs "),
                backstop: false,
                conflict: true,
            };
        }
        let outcome = match e.verdict {
            Verdict::Join(i) => {
                let path = forest.profiles[i as usize].as_str().to_ascii_lowercase();
                match self.profiles.get(&path) {
                    Some(p) => Outcome::Join(p.clone()),
                    // Validated at build; unreachable, but never a panic
                    // in the daemon.
                    None => Outcome::Ignore,
                }
            }
            Verdict::Down => Outcome::Down,
            _ => Outcome::Ignore,
        };
        Judgment {
            outcome,
            rule: e.attributed_to.as_str().to_owned(),
            backstop: e.backstop,
            conflict: false,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key(name: &str, values: &[(&str, RawValue)], children: Vec<RawKey>) -> RawKey {
        RawKey {
            name: name.into(),
            values: values
                .iter()
                .map(|(n, v)| ((*n).to_owned(), v.clone()))
                .collect(),
            children,
        }
    }

    fn s(v: &str) -> RawValue {
        RawValue::Str(v.into())
    }

    fn actions(items: &[&str]) -> RawValue {
        RawValue::List(items.iter().map(|s| (*s).to_owned()).collect())
    }

    fn profiles() -> RawKey {
        key(
            "Profiles",
            &[],
            vec![
                key(
                    "default",
                    &[("Address.Offered", RawValue::Int(1))],
                    vec![key("dark", &[("Enabled", RawValue::Int(0))], vec![])],
                ),
                key("office", &[("Address.Static", s("10.0.0.5/24"))], vec![]),
            ],
        )
    }

    fn wired() -> Snapshot<'static> {
        Snapshot {
            interface: Some("enp0s3".into()),
            interface_kind: Some("wired".into()),
            interface_id: Some("id-1".into()),
            interface_path: Some("pci-0000:00:03.0".into()),
            ..Snapshot::default()
        }
    }

    #[test]
    fn the_shipped_baseline_joins_wired_interfaces_in_default() {
        let rules = key(
            "Interface",
            &[],
            vec![key(
                "wired",
                &[
                    ("Interface.Kind.Equal", s("wired")),
                    ("Priority", RawValue::Int(10)),
                    ("Actions", actions(&["JOIN(default)"])),
                ],
                vec![],
            )],
        );
        let policy = build(Some(&rules), Some(&profiles())).unwrap();
        let j = policy.judge(&wired());
        assert_eq!(j.rule, "wired");
        let p = j.outcome.profile().expect("joined");
        assert_eq!(p.path, "default");
        assert!(p.address.dhcp4());
    }

    #[test]
    fn no_rules_means_the_backstop_ignores_everything() {
        let policy = build(None, Some(&profiles())).unwrap();
        let j = policy.judge(&wired());
        assert_eq!(j.outcome, Outcome::Ignore);
        assert!(j.backstop);
        assert_eq!(policy.profiles.len(), 3);
    }

    #[test]
    fn a_join_of_a_disabled_profile_abstains_and_the_parent_speaks() {
        let rules = key(
            "Interface",
            &[],
            vec![key(
                "wired",
                &[
                    ("Interface.Kind.Equal", s("wired")),
                    ("Actions", actions(&["JOIN(default)"])),
                ],
                vec![key(
                    "slot3",
                    &[
                        ("Interface.Path.Equal", s("pci-0000:00:03.0")),
                        ("Actions", actions(&["JOIN(default\\dark)"])),
                    ],
                    vec![],
                )],
            )],
        );
        let policy = build(Some(&rules), Some(&profiles())).unwrap();
        let j = policy.judge(&wired());
        assert_eq!(j.rule, "wired");
        assert_eq!(j.outcome.profile().unwrap().path, "default");
    }

    #[test]
    fn a_join_of_no_profile_refuses_the_generation() {
        let rules = key(
            "Interface",
            &[],
            vec![key("r", &[("Actions", actions(&["JOIN(nope)"]))], vec![])],
        );
        let err = build(Some(&rules), Some(&profiles())).unwrap_err();
        assert!(err.contains("names no profile"), "{err}");
    }

    #[test]
    fn a_malformed_rule_or_profile_refuses_the_generation() {
        let rules = key(
            "Interface",
            &[],
            vec![key("r", &[("Actions", actions(&["PASS"]))], vec![])],
        );
        let err = build(Some(&rules), Some(&profiles())).unwrap_err();
        assert!(err.contains("does not speak"), "{err}");
        let bad = key(
            "Profiles",
            &[],
            vec![key("x", &[("Nope", RawValue::Int(1))], vec![])],
        );
        let err = build(None, Some(&bad)).unwrap_err();
        assert!(err.contains("unknown value"), "{err}");
    }

    #[test]
    fn a_tie_between_two_joins_is_reported_as_a_conflict() {
        let rules = key(
            "Interface",
            &[],
            vec![
                key("a", &[("Actions", actions(&["JOIN(default)"]))], vec![]),
                key("b", &[("Actions", actions(&["JOIN(office)"]))], vec![]),
            ],
        );
        let policy = build(Some(&rules), Some(&profiles())).unwrap();
        let j = policy.judge(&wired());
        assert!(j.conflict);
        assert_eq!(j.outcome, Outcome::Ignore);
        assert_eq!(j.rule, "a vs b");
    }

    #[test]
    fn down_and_ignore_carry_no_profile() {
        let rules = key(
            "Interface",
            &[],
            vec![
                key("all", &[("Actions", actions(&["JOIN(office)"]))], vec![]),
                key(
                    "this",
                    &[
                        ("Interface.Id.Equal", s("id-1")),
                        ("Priority", RawValue::Int(100)),
                        ("Actions", actions(&["DOWN"])),
                    ],
                    vec![],
                ),
            ],
        );
        let policy = build(Some(&rules), Some(&profiles())).unwrap();
        let j = policy.judge(&wired());
        assert_eq!(j.outcome, Outcome::Down);
        assert_eq!(j.rule, "this");
    }

    #[test]
    fn join_targets_are_recognised_loosely() {
        assert_eq!(
            join_target(" join ( Office\\London ) "),
            Some("office/london".into())
        );
        assert_eq!(join_target("JOIN(x)"), Some("x".into()));
        assert_eq!(join_target("IGNORE"), None);
        assert_eq!(join_target("JOIN("), None);
    }
}
