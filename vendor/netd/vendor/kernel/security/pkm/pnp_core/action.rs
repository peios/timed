//! The PNP action language: parsing and representation.
//!
//! Six actions, three species (ratified design, PEI-598):
//! - verdicts (PASS / DROP / REJECT[(Kind)]) — dispositions, at most one
//!   yielded per rule after resolution;
//! - facts & noise (TAG / COUNT / REPORT) — side effects, never terminal;
//! - deferral (PROMPT) plus NULL, the explicit abstention.
//!
//! Grammar per action expression: `NAME` or `NAME(arg, arg, ...)`, ASCII
//! whitespace ignored everywhere, action names case-insensitive. A PROMPT
//! fallback is itself an action expression (nesting capped).

use crate::pnp_core::error::ActionParseError;
use crate::pnp_core::pkm_alloc::{AllocError, String as PkmString};
use crate::pnp_core::strutil::str_to_pkm;

/// How deep PROMPT fallbacks may nest, e.g. `PROMPT(a, PROMPT(b, DROP))`
/// has depth 2. Compiled-in chain cap from the ratified design.
pub const MAX_PROMPT_CHAIN: usize = 4;

/// The story a REJECT tells the sender (machinery slice, ratified). Kinds
/// are semantic: the kernel owns the kind × (family, protocol) → wire
/// mapping. Routing-failure lies are deliberately unminted — DROP is the
/// silence option, and when PNP speaks it does not speak falsely.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RejectKind {
    /// "Nothing is listening": TCP RST, else ICMP port-unreachable. The
    /// default; bare `REJECT` means this.
    Refused,
    /// "Policy refused you": ICMP admin-prohibited for every protocol.
    Prohibited,
}

impl RejectKind {
    /// Parses a kind name (case-insensitive ASCII).
    pub fn from_name(name: &str) -> Option<RejectKind> {
        if upper_eq(name, "REFUSED") {
            Some(RejectKind::Refused)
        } else if upper_eq(name, "PROHIBITED") {
            Some(RejectKind::Prohibited)
        } else {
            None
        }
    }

    /// Canonical action-language name.
    pub fn as_str(self) -> &'static str {
        match self {
            RejectKind::Refused => "Refused",
            RejectKind::Prohibited => "Prohibited",
        }
    }
}

/// A disposition. Strictness order: DROP > REJECT > PASS.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Verdict {
    /// This layer approves; higher layers still judge.
    Pass,
    /// Refuse, and tell the sender the given story.
    Reject(RejectKind),
    /// Refuse silently.
    Drop,
    /// Interface layer: join the network found on the interface, standing
    /// in the profile at this index of the forest's `profiles` table.
    Join(u32),
    /// Interface layer: never touch the interface (something else owns it).
    Ignore,
    /// Interface layer: keep the interface administratively down.
    Down,
}

impl Verdict {
    /// Strictness rank; higher wins a tie at equal priority. Between two
    /// REJECTs the quieter story (`Refused`, which reveals no policy)
    /// wins — a deterministic tie-break, since tree order carries no
    /// meaning.
    ///
    /// The interface layer has its own scale (DOWN > IGNORE > JOIN); a
    /// forest holds one layer's verdicts only, so the two scales never
    /// meet.
    pub fn strictness(self) -> u8 {
        match self {
            Verdict::Pass => 0,
            Verdict::Reject(RejectKind::Prohibited) => 1,
            Verdict::Reject(RejectKind::Refused) => 2,
            Verdict::Drop => 3,
            Verdict::Join(_) => 0,
            Verdict::Ignore => 1,
            Verdict::Down => 2,
        }
    }

    /// Whether this verdict belongs to the interface layer.
    pub fn is_interface(self) -> bool {
        matches!(self, Verdict::Join(_) | Verdict::Ignore | Verdict::Down)
    }

    /// Canonical action-language name (kind elided).
    pub fn as_str(self) -> &'static str {
        match self {
            Verdict::Pass => "PASS",
            Verdict::Reject(_) => "REJECT",
            Verdict::Drop => "DROP",
            Verdict::Join(_) => "JOIN",
            Verdict::Ignore => "IGNORE",
            Verdict::Down => "DOWN",
        }
    }

    /// Whether this is a REJECT of any kind.
    pub fn is_reject(self) -> bool {
        matches!(self, Verdict::Reject(_))
    }

    /// The stricter of two verdicts.
    pub fn strictest(self, other: Verdict) -> Verdict {
        if other.strictness() > self.strictness() {
            other
        } else {
            self
        }
    }
}

/// A TAG operation on flow-scoped state (ratified ops: Set / Clear / Add).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TagOp {
    /// Set the tag to a value (default 1).
    Set(u64),
    /// Remove the tag: it reads as absent afterwards.
    Clear,
    /// Add to the tag (default 1); an absent tag counts as 0 first.
    Add(u64),
}

impl TagOp {
    /// Wire code for the kernel store: 0 = Set, 1 = Clear, 2 = Add.
    pub fn code(self) -> u8 {
        match self {
            TagOp::Set(_) => 0,
            TagOp::Clear => 1,
            TagOp::Add(_) => 2,
        }
    }

    /// The operand (0 for Clear).
    pub fn operand(self) -> u64 {
        match self {
            TagOp::Set(v) | TagOp::Add(v) => v,
            TagOp::Clear => 0,
        }
    }
}

/// What a COUNT contributes: a literal, or the packet's `Length` in bytes
/// (the one blessed fact — the bandwidth primitive).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CountAmount {
    /// A fixed amount (default 1).
    Literal(u64),
    /// The packet length at the seat.
    Length,
}

/// One parsed action.
#[derive(Debug)]
pub enum Action {
    /// Do nothing; defer to parentage.
    Null,
    /// Yield a verdict.
    Verdict(Verdict),
    /// `JOIN(profile)` as parsed: the profile path by name. Ingestion
    /// interns the path in the forest's profile table and rewrites this to
    /// `Verdict(Verdict::Join(index))`; evaluation never sees it.
    Join {
        /// The profile path, `\` folded to `/`.
        profile: PkmString,
    },
    /// Defer to a userspace handler; on no answer, the fallback applies.
    Prompt {
        /// Handler name.
        handler: PkmString,
        /// Applied when the handler returns NULL or never answers.
        fallback: Fallback,
    },
    /// Write flow-scoped state (no-op on untracked packets).
    Tag {
        /// Tag name.
        name: PkmString,
        /// Operation to apply.
        op: TagOp,
    },
    /// Emit into a named counter stream.
    Count {
        /// Stream name.
        name: PkmString,
        /// What to contribute.
        amount: CountAmount,
    },
    /// Emit an event (fires when level >= CurrentReportingLevel; at most one
    /// emission per rule per evaluation).
    Report {
        /// Severity, 1..=5; higher is more important.
        level: u8,
    },
}

/// A PROMPT fallback: a boxed action, allocated fallibly.
#[derive(Debug)]
pub struct Fallback(pub crate::pnp_core::pkm_alloc::Vec<Action>);

impl Fallback {
    /// The fallback action, or `None` for an implicit/explicit NULL.
    pub fn action(&self) -> Option<&Action> {
        self.0.iter().next()
    }
}

/// Parses one action expression. Whitespace is ignored; names are
/// case-insensitive.
pub fn parse_action(expr: &str) -> Result<Action, ParseFailure> {
    let mut compact = PkmString::new();
    for c in expr.chars() {
        if !c.is_ascii_whitespace() {
            compact.push(c).map_err(|_| ParseFailure::Alloc)?;
        }
    }
    let (action, rest) = parse_one(compact.as_str(), 0)?;
    if !rest.is_empty() {
        return Err(ParseFailure::Parse(ActionParseError::Malformed));
    }
    Ok(action)
}

/// Parse failure: either the expression is bad, or allocation failed.
#[derive(Debug)]
pub enum ParseFailure {
    /// The expression is malformed; see the inner error.
    Parse(ActionParseError),
    /// Allocation failed.
    Alloc,
}

impl From<AllocError> for ParseFailure {
    fn from(_: AllocError) -> Self {
        ParseFailure::Alloc
    }
}

fn parse_one(input: &str, prompt_depth: usize) -> Result<(Action, &str), ParseFailure> {
    let name_end = input.find(['(', ',', ')']).unwrap_or(input.len());
    let name = &input[..name_end];
    let rest = &input[name_end..];

    let mut upper = [0u8; 8];
    if name.is_empty() || name.len() > upper.len() {
        return Err(ParseFailure::Parse(ActionParseError::UnknownAction));
    }
    for (i, b) in name.bytes().enumerate() {
        upper[i] = b.to_ascii_uppercase();
    }
    let name = core::str::from_utf8(&upper[..name.len()])
        .map_err(|_| ParseFailure::Parse(ActionParseError::UnknownAction))?;

    let (args, rest) = split_args(rest)?;
    let action = match name {
        "NULL" => {
            expect_arity(&args, 0)?;
            Action::Null
        }
        "PASS" => {
            expect_arity(&args, 0)?;
            Action::Verdict(Verdict::Pass)
        }
        "DROP" => {
            expect_arity(&args, 0)?;
            Action::Verdict(Verdict::Drop)
        }
        "IGNORE" => {
            expect_arity(&args, 0)?;
            Action::Verdict(Verdict::Ignore)
        }
        "DOWN" => {
            expect_arity(&args, 0)?;
            Action::Verdict(Verdict::Down)
        }
        "JOIN" => {
            expect_arity(&args, 1)?;
            let mut profile = PkmString::new();
            for c in args[0].chars() {
                profile.push(if c == '\\' { '/' } else { c })?;
            }
            if profile.is_empty()
                || profile.starts_with('/')
                || profile.ends_with('/')
                || profile.as_str().contains("//")
            {
                return Err(ParseFailure::Parse(ActionParseError::BadArgument));
            }
            Action::Join { profile }
        }
        "REJECT" => {
            if args.len() > 1 {
                return Err(ParseFailure::Parse(ActionParseError::BadArity));
            }
            let kind = match args.first() {
                None => RejectKind::Refused,
                Some(k) => RejectKind::from_name(k)
                    .ok_or(ParseFailure::Parse(ActionParseError::UnknownRejectKind))?,
            };
            Action::Verdict(Verdict::Reject(kind))
        }
        "PROMPT" => {
            if prompt_depth >= MAX_PROMPT_CHAIN {
                return Err(ParseFailure::Parse(ActionParseError::Malformed));
            }
            if args.is_empty() || args.len() > 2 {
                return Err(ParseFailure::Parse(ActionParseError::BadArity));
            }
            let handler = str_to_pkm(args[0])?;
            if handler.is_empty() {
                return Err(ParseFailure::Parse(ActionParseError::BadArgument));
            }
            let mut fallback = crate::pnp_core::pkm_alloc::Vec::new();
            if let Some(text) = args.get(1) {
                let (inner, left) = parse_one(text, prompt_depth + 1)?;
                if !left.is_empty() {
                    return Err(ParseFailure::Parse(ActionParseError::Malformed));
                }
                match inner {
                    Action::Null => {}
                    other => fallback.push(other)?,
                }
            }
            Action::Prompt {
                handler,
                fallback: Fallback(fallback),
            }
        }
        "TAG" => {
            if args.len() < 2 || args.len() > 3 {
                return Err(ParseFailure::Parse(ActionParseError::BadArity));
            }
            let tag_name = str_to_pkm(args[0])?;
            if tag_name.is_empty() {
                return Err(ParseFailure::Parse(ActionParseError::BadArgument));
            }
            let op_name = args[1];
            let operand = match args.get(2) {
                Some(a) => {
                    Some(parse_uint(a).ok_or(ParseFailure::Parse(ActionParseError::BadArgument))?)
                }
                None => None,
            };
            let op = if upper_eq(op_name, "SET") {
                TagOp::Set(operand.unwrap_or(1))
            } else if upper_eq(op_name, "CLEAR") {
                if operand.is_some() {
                    return Err(ParseFailure::Parse(ActionParseError::BadArity));
                }
                TagOp::Clear
            } else if upper_eq(op_name, "ADD") {
                TagOp::Add(operand.unwrap_or(1))
            } else {
                return Err(ParseFailure::Parse(ActionParseError::BadArgument));
            };
            Action::Tag { name: tag_name, op }
        }
        "COUNT" => {
            if args.is_empty() || args.len() > 2 {
                return Err(ParseFailure::Parse(ActionParseError::BadArity));
            }
            let counter = str_to_pkm(args[0])?;
            if counter.is_empty() {
                return Err(ParseFailure::Parse(ActionParseError::BadArgument));
            }
            let amount = match args.get(1) {
                Some(a) if upper_eq(a, "LENGTH") => CountAmount::Length,
                Some(a) => CountAmount::Literal(
                    parse_uint(a).ok_or(ParseFailure::Parse(ActionParseError::BadArgument))?,
                ),
                None => CountAmount::Literal(1),
            };
            Action::Count {
                name: counter,
                amount,
            }
        }
        "REPORT" => {
            expect_arity(&args, 1)?;
            let level =
                parse_int(args[0]).ok_or(ParseFailure::Parse(ActionParseError::BadArgument))?;
            if !(1..=5).contains(&level) {
                return Err(ParseFailure::Parse(ActionParseError::BadArgument));
            }
            Action::Report { level: level as u8 }
        }
        _ => return Err(ParseFailure::Parse(ActionParseError::UnknownAction)),
    };
    Ok((action, rest))
}

/// Splits a leading `(...)` argument list off `input`. Returns the argument
/// substrings (split on top-level commas only) and the remainder after the
/// closing parenthesis. No leading `(` means an empty argument list.
type Args<'a> = crate::pnp_core::pkm_alloc::Vec<&'a str>;

fn split_args(input: &str) -> Result<(Args<'_>, &str), ParseFailure> {
    let mut args = Args::new();
    if !input.starts_with('(') {
        return Ok((args, input));
    }
    let bytes = input.as_bytes();
    let mut depth = 0usize;
    let mut start = 1usize;
    for (i, &b) in bytes.iter().enumerate() {
        match b {
            b'(' => depth += 1,
            b')' => {
                depth -= 1;
                if depth == 0 {
                    if i > start {
                        args.push(&input[start..i])?;
                    } else if !args.is_empty() {
                        // Trailing comma: `TAG(x,)`.
                        return Err(ParseFailure::Parse(ActionParseError::Malformed));
                    }
                    return Ok((args, &input[i + 1..]));
                }
            }
            b',' if depth == 1 => {
                if i == start {
                    return Err(ParseFailure::Parse(ActionParseError::Malformed));
                }
                args.push(&input[start..i])?;
                start = i + 1;
            }
            _ => {}
        }
    }
    Err(ParseFailure::Parse(ActionParseError::Malformed))
}

fn expect_arity(args: &Args<'_>, want: usize) -> Result<(), ParseFailure> {
    if args.len() != want {
        return Err(ParseFailure::Parse(ActionParseError::BadArity));
    }
    Ok(())
}

fn parse_int(s: &str) -> Option<i64> {
    s.parse::<i64>().ok()
}

fn parse_uint(s: &str) -> Option<u64> {
    s.parse::<u64>().ok()
}

pub(crate) fn upper_eq(s: &str, upper: &str) -> bool {
    s.len() == upper.len()
        && s.bytes()
            .zip(upper.bytes())
            .all(|(a, b)| a.to_ascii_uppercase() == b)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_bare_verdicts_case_insensitively() {
        assert!(matches!(
            parse_action("pass").unwrap(),
            Action::Verdict(Verdict::Pass)
        ));
        assert!(matches!(
            parse_action(" DROP ").unwrap(),
            Action::Verdict(Verdict::Drop)
        ));
        assert!(matches!(
            parse_action("Reject").unwrap(),
            Action::Verdict(Verdict::Reject(RejectKind::Refused))
        ));
        assert!(matches!(parse_action("NULL").unwrap(), Action::Null));
    }

    #[test]
    fn reject_kinds_are_the_two_minted_stories() {
        assert!(matches!(
            parse_action("REJECT(Refused)").unwrap(),
            Action::Verdict(Verdict::Reject(RejectKind::Refused))
        ));
        assert!(matches!(
            parse_action("reject( prohibited )").unwrap(),
            Action::Verdict(Verdict::Reject(RejectKind::Prohibited))
        ));
        assert!(matches!(
            parse_action("REJECT(host-unreachable)"),
            Err(ParseFailure::Parse(ActionParseError::UnknownRejectKind))
        ));
        assert!(parse_action("REJECT(Refused, Prohibited)").is_err());
    }

    #[test]
    fn parses_nested_prompt_with_spaces() {
        let a = parse_action("PROMPT( user , PROMPT(dpi, DROP) )").unwrap();
        match a {
            Action::Prompt { handler, fallback } => {
                assert_eq!(handler.as_str(), "user");
                match fallback.action().unwrap() {
                    Action::Prompt { handler, fallback } => {
                        assert_eq!(handler.as_str(), "dpi");
                        assert!(matches!(
                            fallback.action().unwrap(),
                            Action::Verdict(Verdict::Drop)
                        ));
                    }
                    other => panic!("unexpected {other:?}"),
                }
            }
            other => panic!("unexpected {other:?}"),
        }
    }

    #[test]
    fn prompt_chain_cap_is_enforced() {
        let deep = "PROMPT(a,PROMPT(b,PROMPT(c,PROMPT(d,PROMPT(e,DROP)))))";
        assert!(matches!(
            parse_action(deep),
            Err(ParseFailure::Parse(ActionParseError::Malformed))
        ));
    }

    #[test]
    fn parses_tag_count_report() {
        match parse_action("TAG(seen, Add)").unwrap() {
            Action::Tag { name, op } => {
                assert_eq!(name.as_str(), "seen");
                assert_eq!(op, TagOp::Add(1));
            }
            other => panic!("unexpected {other:?}"),
        }
        match parse_action("TAG(mark, SET, 7)").unwrap() {
            Action::Tag { op, .. } => assert_eq!(op, TagOp::Set(7)),
            other => panic!("unexpected {other:?}"),
        }
        match parse_action("TAG(mark, set)").unwrap() {
            Action::Tag { op, .. } => assert_eq!(op, TagOp::Set(1)),
            other => panic!("unexpected {other:?}"),
        }
        match parse_action("TAG(mark, Clear)").unwrap() {
            Action::Tag { op, .. } => assert_eq!(op, TagOp::Clear),
            other => panic!("unexpected {other:?}"),
        }
        match parse_action("COUNT(synburst)").unwrap() {
            Action::Count { name, amount } => {
                assert_eq!(name.as_str(), "synburst");
                assert_eq!(amount, CountAmount::Literal(1));
            }
            other => panic!("unexpected {other:?}"),
        }
        match parse_action("COUNT(bytes, Length)").unwrap() {
            Action::Count { amount, .. } => assert_eq!(amount, CountAmount::Length),
            other => panic!("unexpected {other:?}"),
        }
        match parse_action("COUNT(x, 40)").unwrap() {
            Action::Count { amount, .. } => assert_eq!(amount, CountAmount::Literal(40)),
            other => panic!("unexpected {other:?}"),
        }
        match parse_action("REPORT(3)").unwrap() {
            Action::Report { level } => assert_eq!(level, 3),
            other => panic!("unexpected {other:?}"),
        }
    }

    #[test]
    fn rejects_bad_expressions() {
        assert!(parse_action("").is_err());
        assert!(parse_action("ALLOW").is_err());
        assert!(parse_action("PASS(1)").is_err());
        assert!(parse_action("TAG(x, Clear, 1)").is_err()); // Clear takes no operand
        assert!(parse_action("TAG(x, Set, -1)").is_err()); // unsigned
        assert!(parse_action("TAG(x, Increment)").is_err()); // unminted op
        assert!(parse_action("REPORT(0)").is_err());
        assert!(parse_action("REPORT(6)").is_err());
        assert!(parse_action("COUNT(x, -1)").is_err());
        assert!(parse_action("COUNT(x, Ttl)").is_err()); // only Length is blessed
        assert!(parse_action("PROMPT()").is_err());
        assert!(parse_action("DROP)").is_err());
        assert!(parse_action("TAG(x,").is_err());
        assert!(parse_action("DROP PASS").is_err());
    }

    #[test]
    fn verdict_strictness_order_is_drop_reject_pass() {
        let refused = Verdict::Reject(RejectKind::Refused);
        let prohibited = Verdict::Reject(RejectKind::Prohibited);
        assert_eq!(Verdict::Pass.strictest(refused), refused);
        assert_eq!(refused.strictest(Verdict::Drop), Verdict::Drop);
        assert_eq!(Verdict::Drop.strictest(Verdict::Pass), Verdict::Drop);
        // The quieter story wins a REJECT-vs-REJECT tie, deterministically.
        assert_eq!(prohibited.strictest(refused), refused);
        assert_eq!(refused.strictest(prohibited), refused);
    }
}
