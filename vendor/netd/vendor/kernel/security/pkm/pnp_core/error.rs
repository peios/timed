//! Shared error types for the PNP semantic core.

pub use crate::pnp_core::pkm_alloc::AllocError;
use crate::pnp_core::pkm_alloc::String as PkmString;

/// Why a rule forest was rejected at ingestion.
///
/// Every variant that concerns a specific rule carries the rule's registry
/// path so the authoring surface can point at the offending key.
#[derive(Debug)]
pub enum BuildError {
    /// Allocation failed while building the forest.
    Alloc,
    /// A rule value key names a fact the vocabulary does not contain.
    UnknownFact { rule: PkmString, key: PkmString },
    /// A rule value key uses an operator the fact does not support
    /// (e.g. `GreaterThan` on an address, `Has` on anything but `TcpFlags`).
    BadOperator { rule: PkmString, key: PkmString },
    /// A match value could not be parsed for its fact's type.
    BadPattern { rule: PkmString, key: PkmString },
    /// A `Counter.<n>(...)` key does not parse as a view (bad duration,
    /// unknown key fact, duplicate arguments, window over the horizon).
    BadCounterView { rule: PkmString, key: PkmString },
    /// The `Actions` value is missing, not a list, or contains a non-string.
    BadActionsValue { rule: PkmString },
    /// One action expression could not be parsed.
    BadAction {
        rule: PkmString,
        detail: ActionParseError,
    },
    /// PROMPT fallbacks nest deeper than the compiled-in chain cap.
    PromptChainTooDeep { rule: PkmString },
    /// `Priority` is present but not an integer.
    BadPriority { rule: PkmString },
    /// `Enabled` is present but not 0 or 1.
    BadEnabled { rule: PkmString },
    /// A rule name is empty or contains a path separator.
    BadRuleName { rule: PkmString },
    /// Two distinct tag names hash to the same store identity. Names are
    /// the author's; refusing the generation keeps the hash a deterministic
    /// identity within a running policy.
    TagHashCollision { a: PkmString, b: PkmString },
    /// Two distinct counter stream names hash alike (same reasoning).
    StreamHashCollision { a: PkmString, b: PkmString },
    /// A `Counter.<n>` condition views a stream no rule anywhere writes:
    /// statically dead (it can only ever read absent), refused loudly.
    CounterNeverWritten { rule: PkmString, key: PkmString },
    /// A rule reads a tag that a higher layer writes: a downward read,
    /// forbidden by the visibility law (tags flow strictly upward).
    TagDownwardRead { rule: PkmString, name: PkmString },
    /// A `Present` condition on a fact that never exists at the rule's
    /// layer. Every other operator over such a fact is merely dead (the
    /// absent-fact law makes it false, and the lint says so); `Present`
    /// looks through that law, so `X.Present = 0` on a fact absent by law
    /// would be an always-true condition wearing a meaningful name. Refused.
    PresentNeverAtLayer { rule: PkmString, key: PkmString },
    /// A condition key that cannot exist at the rule's layer at all: a
    /// `Tag.*` or `Counter.*` read in the interface layer, where no store
    /// stands behind it.
    KeyNotAtLayer { rule: PkmString, key: PkmString },
    /// An action the rule's layer does not speak: `JOIN`, `IGNORE` or
    /// `DOWN` outside the interface layer, or anything but those, `NULL`
    /// and `REPORT` inside it.
    ActionNotAtLayer { rule: PkmString },
}

impl From<AllocError> for BuildError {
    fn from(_: AllocError) -> Self {
        BuildError::Alloc
    }
}

impl BuildError {
    /// Every reason [`BuildError::reason`] can answer, in variant order.
    /// These are values of `outcome.reason` on the kernel's
    /// `ntfe.policy.rejected` event (pkm `evman/ntfe.evman`), so a name
    /// here is an ABI: add one, never rename one.
    pub const REASONS: [&'static str; 18] = [
        "out-of-memory",
        "unknown-fact",
        "bad-operator",
        "bad-pattern",
        "bad-counter-view",
        "bad-actions-value",
        "bad-action",
        "prompt-chain-too-deep",
        "bad-priority",
        "bad-enabled",
        "bad-rule-name",
        "tag-hash-collision",
        "stream-hash-collision",
        "counter-never-written",
        "tag-downward-read",
        "present-never-at-layer",
        "key-not-at-layer",
        "action-not-at-layer",
    ];

    /// Why the forest was refused, as a stable kebab-case name: the
    /// variant's own name. Pure; allocates nothing.
    pub fn reason(&self) -> &'static str {
        let i = match self {
            BuildError::Alloc => 0,
            BuildError::UnknownFact { .. } => 1,
            BuildError::BadOperator { .. } => 2,
            BuildError::BadPattern { .. } => 3,
            BuildError::BadCounterView { .. } => 4,
            BuildError::BadActionsValue { .. } => 5,
            BuildError::BadAction { .. } => 6,
            BuildError::PromptChainTooDeep { .. } => 7,
            BuildError::BadPriority { .. } => 8,
            BuildError::BadEnabled { .. } => 9,
            BuildError::BadRuleName { .. } => 10,
            BuildError::TagHashCollision { .. } => 11,
            BuildError::StreamHashCollision { .. } => 12,
            BuildError::CounterNeverWritten { .. } => 13,
            BuildError::TagDownwardRead { .. } => 14,
            BuildError::PresentNeverAtLayer { .. } => 15,
            BuildError::KeyNotAtLayer { .. } => 16,
            BuildError::ActionNotAtLayer { .. } => 17,
        };
        Self::REASONS[i]
    }

    /// The registry path of the rule the refusal names, relative to its
    /// layer key; `None` for allocation failure and the two hash
    /// collisions, which are between names, not rules.
    pub fn rule(&self) -> Option<&str> {
        match self {
            BuildError::Alloc
            | BuildError::TagHashCollision { .. }
            | BuildError::StreamHashCollision { .. } => None,
            BuildError::UnknownFact { rule, .. }
            | BuildError::BadOperator { rule, .. }
            | BuildError::BadPattern { rule, .. }
            | BuildError::BadCounterView { rule, .. }
            | BuildError::BadActionsValue { rule }
            | BuildError::BadAction { rule, .. }
            | BuildError::PromptChainTooDeep { rule }
            | BuildError::BadPriority { rule }
            | BuildError::BadEnabled { rule }
            | BuildError::BadRuleName { rule }
            | BuildError::CounterNeverWritten { rule, .. }
            | BuildError::TagDownwardRead { rule, .. }
            | BuildError::PresentNeverAtLayer { rule, .. }
            | BuildError::KeyNotAtLayer { rule, .. }
            | BuildError::ActionNotAtLayer { rule } => Some(rule.as_str()),
        }
    }

    /// Why the action expression failed to parse, for [`BuildError::BadAction`]
    /// alone.
    pub fn action_error(&self) -> Option<ActionParseError> {
        match self {
            BuildError::BadAction { detail, .. } => Some(*detail),
            _ => None,
        }
    }
}

impl ActionParseError {
    /// The stable kebab-case name: a value of the catalogue's
    /// `rule.action-error` field (pkm `evman/ntfe.evman`).
    pub fn name(self) -> &'static str {
        match self {
            ActionParseError::UnknownAction => "unknown-action",
            ActionParseError::BadArity => "bad-arity",
            ActionParseError::BadArgument => "bad-argument",
            ActionParseError::UnknownRejectKind => "unknown-reject-kind",
            ActionParseError::Malformed => "malformed",
        }
    }
}

/// Why a single action expression failed to parse.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ActionParseError {
    /// The action name is not in the language.
    UnknownAction,
    /// Wrong number of arguments for the action.
    BadArity,
    /// An argument has the wrong shape (e.g. non-integer REPORT level).
    BadArgument,
    /// `REJECT(Kind)` names a kind that is not minted.
    UnknownRejectKind,
    /// Unbalanced parentheses or trailing garbage.
    Malformed,
}

/// A non-fatal ingestion finding: the rule is legal but almost certainly
/// wrong, e.g. a condition on a fact that never exists at the rule's layer
/// (the absent-fact law makes it silently never match). Surfaced loudly by
/// authoring surfaces; never blocks ingestion.
#[derive(Debug)]
pub struct LintWarning {
    /// Registry path of the rule.
    pub rule: PkmString,
    /// The value key that triggered the warning.
    pub key: PkmString,
    /// What is wrong with it.
    pub kind: LintKind,
}

/// The kinds of lint findings.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LintKind {
    /// The fact never exists at this layer, so the condition can never hold.
    FactNeverPresentAtLayer,
}
