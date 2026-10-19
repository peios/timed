//! Side effects: union across triggered rules, never suppressed by
//! priority, report dedup and threshold, and PROMPT's unanswered path.

mod common;

use common::*;
use pnp_core::{evaluate, EvalContext, Layer, RejectKind, Verdict};

#[test]
fn side_effects_union_across_overlapping_rules() {
    let ev = judge(
        vec![
            rb("tagger")
                .int("DstPort.Equal", 22)
                .actions(&["TAG(ssh, SET, 1)", "PASS"]),
            rb("counter")
                .s("Direction.Equal", "in")
                .actions(&["COUNT(inbound)", "DROP"]),
        ],
        &tcp_in("10.0.0.7", 5555, "10.0.0.5", 22),
    );
    // Strictest verdict wins; every triggered rule's side effects ran.
    assert_eq!(ev.verdict, Verdict::Drop);
    assert_eq!(tags(&ev), vec!["ssh".to_string()]);
    assert_eq!(counts(&ev), vec!["inbound".to_string()]);
}

#[test]
fn priority_never_suppresses_side_effects() {
    // An outprioritized rule's REPORT and COUNT still run: observations are
    // not authority.
    let ev = judge(
        vec![
            rb("org-pass").int("Priority", 1000).actions(&["PASS"]),
            rb("local-monitor").int("DstPort.Equal", 22).actions(&[
                "REPORT(3)",
                "COUNT(ssh-attempts)",
                "DROP",
            ]),
        ],
        &tcp_in("10.0.0.7", 5555, "10.0.0.5", 22),
    );
    assert_eq!(ev.verdict, Verdict::Pass, "priority 1000 wins the verdict");
    assert_eq!(ev.attributed_to.as_str(), "org-pass");
    assert_eq!(reports(&ev), vec![("local-monitor".to_string(), 3)]);
    assert_eq!(counts(&ev), vec!["ssh-attempts".to_string()]);
}

#[test]
fn report_emits_once_per_rule_at_the_highest_listed_level() {
    let ev = judge(
        vec![rb("noisy").actions(&["REPORT(2)", "REPORT(4)", "REPORT(1)", "DROP"])],
        &tcp_in("10.0.0.7", 5555, "10.0.0.5", 22),
    );
    assert_eq!(reports(&ev), vec![("noisy".to_string(), 4)]);
}

#[test]
fn reporting_level_threshold_gates_emission() {
    let (forest, _) = build(
        Layer::Packet,
        vec![
            rb("low").actions(&["REPORT(2)", "PASS"]),
            rb("high").actions(&["REPORT(5)", "PASS"]),
        ],
    );
    let snap = tcp_in("10.0.0.7", 5555, "10.0.0.5", 22);

    let ev = evaluate(&forest, &snap, &EvalContext { reporting_level: 4 }).unwrap();
    assert_eq!(reports(&ev), vec![("high".to_string(), 5)]);

    let ev = evaluate(&forest, &snap, &EvalContext { reporting_level: 0 }).unwrap();
    assert_eq!(reports(&ev).len(), 2);
}

#[test]
fn prompt_unanswered_takes_the_fallback_and_is_visible() {
    let ev = judge(
        vec![rb("ask-first")
            .int("DstPort.Equal", 22)
            .actions(&["PROMPT(user, DROP)"])],
        &tcp_in("10.0.0.7", 5555, "10.0.0.5", 22),
    );
    assert_eq!(ev.verdict, Verdict::Drop);
    assert_eq!(ev.attributed_to.as_str(), "ask-first");
    assert_eq!(
        prompts(&ev),
        vec![("ask-first".to_string(), "user".to_string())]
    );
}

#[test]
fn prompt_with_null_fallback_abstains_into_the_parentage_walk() {
    let ev = judge(
        vec![rb("no-inbound")
            .s("Direction.Equal", "in")
            .actions(&["DROP"])
            .child(
                rb("ask")
                    .int("DstPort.Equal", 22)
                    .actions(&["PROMPT(user)"]),
            )],
        &tcp_in("10.0.0.7", 5555, "10.0.0.5", 22),
    );
    // Unanswered, fallback NULL: the parent speaks.
    assert_eq!(ev.verdict, Verdict::Drop);
    assert_eq!(ev.attributed_to.as_str(), "no-inbound");
    assert_eq!(prompts(&ev).len(), 1);
}

#[test]
fn nested_prompt_fallbacks_resolve_through_the_chain() {
    let ev = judge(
        vec![rb("escalate").actions(&["PROMPT(user, PROMPT(dpi, REJECT))"])],
        &tcp_in("10.0.0.7", 5555, "10.0.0.5", 22),
    );
    // Both prompts issued (observability), final fallback verdict applies.
    assert_eq!(ev.verdict, Verdict::Reject(RejectKind::Refused));
    assert_eq!(prompts(&ev).len(), 2);
}
