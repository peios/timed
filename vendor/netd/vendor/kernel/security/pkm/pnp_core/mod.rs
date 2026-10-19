//! PNP packet-layer semantic core.
//!
//! The pure rules engine of Peios Network Policy: fact snapshot in, verdict
//! and side effects out. No kernel dependencies, no I/O — the same code
//! compiles into the kernel (`feature = "kernel"`) and through its Cargo entry point under
//! `peios/rust/pnp-core`, where the test suite
//! encodes every ratified law of the design (PEI-598, "PNP Rules — Packet
//! Layer Design" and the machinery slice).

/// The action language: parsing and representation.
pub mod action;
/// Match conditions: facts, operators, evaluation.
pub mod condition;
/// Shared error types.
pub mod error;
/// The evaluation algorithm.
pub mod eval;
/// Name hashing for the machinery stores.
pub mod hash;
/// Registry-shaped input -> validated forest.
pub mod ingest;
/// PKM-owned fallible allocation wrappers.
pub mod pkm_alloc;
/// The rule atom and forest.
pub mod rule;
/// SHA-1, for service-SID derivation only.
pub mod sha1;
/// Security identifiers as identity facts.
pub mod sid;
/// The immutable fact snapshot.
pub mod snapshot;
/// Small string helpers over the fallible string type.
pub mod strutil;
/// Neutral registry value representation.
pub mod value;

/// Returns a stable value from the staged crate so kernel bring-up can prove
/// the real `pnp-core` module graph compiled and linked.
pub fn kernel_compile_probe() -> usize {
    action::MAX_PROMPT_CHAIN
}

pub use action::{
    parse_action, Action, CountAmount, Fallback, RejectKind, TagOp, Verdict, MAX_PROMPT_CHAIN,
};
pub use condition::{
    keyspec, AddrPattern, BadView, CondKey, CondOp, Condition, CounterView, FactFamily, FactId,
    IntPattern, MAX_WINDOW_SECS,
};
pub use error::{ActionParseError, AllocError, BuildError, LintKind, LintWarning};
pub use eval::{evaluate, Effect, EvalContext, Evaluation, VerdictCandidate};
pub use hash::name_hash;
pub use ingest::{build_forest, check_forests, BuildOutput, RuleInput};
pub use rule::{Forest, Layer, MatchTrace, NamedHash, Rule};
pub use sid::Sid;
pub use snapshot::{
    tcp_flags, Direction, Endpoint, EndpointKind, FlowState, OwnedPrincipal, Principal, Snapshot,
    TimeFacts,
};
pub use value::RegValue;
