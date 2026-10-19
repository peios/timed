//! Totality, verdict dominance, and priority collation
//! (laws from "PNP Rules — Packet Layer Design" rev 1).

mod common;

use common::*;
use pnp_core::{RejectKind, Verdict};

#[test]
fn empty_forest_fails_closed_to_the_backstop() {
    let ev = judge(vec![], &tcp_in("192.0.2.9", 4444, "10.0.0.5", 80));
    assert_eq!(ev.verdict, Verdict::Drop);
    assert!(ev.backstop);
    assert_eq!(ev.attributed_to.as_str(), "backstop");
    assert!(ev.candidates.is_empty());
}

#[test]
fn strictest_wins_at_equal_priority() {
    // Two overlapping match-all trees: DROP > REJECT > PASS.
    let snap = tcp_in("192.0.2.9", 4444, "10.0.0.5", 80);

    let ev = judge(
        vec![rb("a").actions(&["PASS"]), rb("b").actions(&["REJECT"])],
        &snap,
    );
    assert_eq!(ev.verdict, Verdict::Reject(RejectKind::Refused));
    assert_eq!(ev.attributed_to.as_str(), "b");

    let ev = judge(
        vec![rb("a").actions(&["REJECT"]), rb("b").actions(&["DROP"])],
        &snap,
    );
    assert_eq!(ev.verdict, Verdict::Drop);

    let ev = judge(
        vec![rb("a").actions(&["DROP"]), rb("b").actions(&["PASS"])],
        &snap,
    );
    assert_eq!(ev.verdict, Verdict::Drop);
    assert_eq!(ev.attributed_to.as_str(), "a");
}

#[test]
fn higher_priority_beats_stricter_verdict() {
    // Priority is the cross-tree arbitration; the lattice only breaks ties.
    let snap = tcp_in("10.0.0.7", 5555, "10.0.0.5", 22);
    let ev = judge(
        vec![
            rb("blast-through")
                .s("SrcAddr.Equal", "10.0.0.7")
                .int("Priority", 100)
                .actions(&["PASS"]),
            rb("no-ssh").int("DstPort.Equal", 22).actions(&["DROP"]),
        ],
        &snap,
    );
    assert_eq!(ev.verdict, Verdict::Pass);
    assert_eq!(ev.attributed_to.as_str(), "blast-through");
    // Both candidates are visible for observability.
    assert_eq!(ev.candidates.len(), 2);
}

#[test]
fn multiple_verdicts_in_one_rule_reduce_to_the_strictest() {
    let ev = judge(
        vec![rb("confused").actions(&["PASS", "DROP", "REJECT"])],
        &tcp_in("192.0.2.9", 4444, "10.0.0.5", 80),
    );
    assert_eq!(ev.verdict, Verdict::Drop);
    assert_eq!(ev.candidates.len(), 1);
}

#[test]
fn shipped_policy_shape_outbound_pass_over_backstop() {
    // The ratified shipped-policy shape: permissiveness is a visible rule,
    // the backstop stays DROP.
    let roots = || {
        vec![rb("outbound-ok")
            .s("Direction.Equal", "out")
            .actions(&["PASS"])]
    };

    let out = judge(roots(), &tcp_out("93.184.216.34", 443));
    assert_eq!(out.verdict, Verdict::Pass);
    assert_eq!(out.attributed_to.as_str(), "outbound-ok");
    assert!(!out.backstop);

    let inbound = judge(roots(), &tcp_in("93.184.216.34", 443, "10.0.0.5", 8080));
    assert_eq!(inbound.verdict, Verdict::Drop);
    assert!(inbound.backstop);
}
