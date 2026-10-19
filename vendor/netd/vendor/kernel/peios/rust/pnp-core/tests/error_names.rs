//! The names a refusal is known by outside the crate: `BuildError::reason`
//! and `ActionParseError::name` become `outcome.reason` and
//! `rule.action-error` on the kernel's `ntfe.policy.rejected` event, so
//! they are held here to their catalogue spelling.

mod common;

use common::*;
use pnp_core::{build_forest, ActionParseError, BuildError, Layer};

fn build_err(rule: Rb) -> BuildError {
    build_forest(Layer::Packet, &[rule.0]).expect_err("build should fail")
}

fn kebab(s: &str) -> bool {
    !s.is_empty()
        && !s.starts_with('-')
        && !s.ends_with('-')
        && !s.contains("--")
        && s.bytes().all(|b| b.is_ascii_lowercase() || b == b'-')
}

#[test]
fn every_reason_is_distinct_kebab_case() {
    for (i, r) in BuildError::REASONS.iter().enumerate() {
        assert!(kebab(r), "{r:?} is not kebab-case");
        assert!(
            !BuildError::REASONS[..i].contains(r),
            "{r:?} is listed twice"
        );
    }
}

#[test]
fn action_errors_are_the_catalogue_values() {
    let all = [
        (ActionParseError::UnknownAction, "unknown-action"),
        (ActionParseError::BadArity, "bad-arity"),
        (ActionParseError::BadArgument, "bad-argument"),
        (ActionParseError::UnknownRejectKind, "unknown-reject-kind"),
        (ActionParseError::Malformed, "malformed"),
    ];
    for (e, want) in all {
        assert_eq!(e.name(), want);
    }
}

#[test]
fn a_refusal_names_its_reason_and_the_rule_by_path() {
    let e = build_err(rb("guard").child(rb("ssh").int("Dport.Equal", 22).actions(&["PASS"])));
    assert_eq!(e.reason(), "unknown-fact");
    assert_eq!(e.rule(), Some("guard/ssh"));
    assert_eq!(e.action_error(), None);

    let e = build_err(rb("r").s("Priority", "high").actions(&["PASS"]));
    assert_eq!(e.reason(), "bad-priority");
    assert_eq!(e.rule(), Some("r"));

    let e = build_err(rb("r").int("Enabled", 2).actions(&["PASS"]));
    assert_eq!(e.reason(), "bad-enabled");

    let e = build_err(rb("r").s("Actions", "PASS"));
    assert_eq!(e.reason(), "bad-actions-value");
    assert_eq!(e.action_error(), None);
}

#[test]
fn a_bad_action_carries_why_it_did_not_parse() {
    let e = build_err(rb("r").actions(&["ALLOW"]));
    assert_eq!(e.reason(), "bad-action");
    assert_eq!(e.rule(), Some("r"));
    assert_eq!(
        e.action_error().map(ActionParseError::name),
        Some("unknown-action")
    );

    let e = build_err(rb("r").actions(&["REPORT(9)"]));
    assert_eq!(e.reason(), "bad-action");
    assert_eq!(
        e.action_error().map(ActionParseError::name),
        Some("bad-argument")
    );

    let e = build_err(rb("r").actions(&["REJECT(Sideways)"]));
    assert_eq!(
        e.action_error().map(ActionParseError::name),
        Some("unknown-reject-kind")
    );
}

#[test]
fn reason_covers_every_variant_without_allocating() {
    // The two collisions and allocation failure name no rule.
    let empty = || pnp_core::pkm_alloc::String::default();
    let cases = [
        (BuildError::Alloc, "out-of-memory", false),
        (
            BuildError::TagHashCollision {
                a: empty(),
                b: empty(),
            },
            "tag-hash-collision",
            false,
        ),
        (
            BuildError::StreamHashCollision {
                a: empty(),
                b: empty(),
            },
            "stream-hash-collision",
            false,
        ),
        (
            BuildError::ActionNotAtLayer { rule: empty() },
            "action-not-at-layer",
            true,
        ),
        (
            BuildError::TagDownwardRead {
                rule: empty(),
                name: empty(),
            },
            "tag-downward-read",
            true,
        ),
    ];
    for (e, reason, has_rule) in cases {
        assert_eq!(e.reason(), reason);
        assert_eq!(e.rule().is_some(), has_rule, "{reason}");
        assert!(BuildError::REASONS.contains(&e.reason()));
    }
}
