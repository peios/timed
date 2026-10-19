//! Tree structure: shadowing, the abstention walk, lineage locality,
//! priority inheritance, and Enabled.

mod common;

use common::*;
use pnp_core::{build_forest, BuildError, Layer, RejectKind, RuleInput, Verdict};

fn inbound_drop_with_ssh_exception() -> Vec<Rb> {
    vec![rb("no-inbound")
        .s("Direction.Equal", "in")
        .actions(&["DROP"])
        .child(
            rb("ssh-from-lan")
                .int("DstPort.Equal", 22)
                .s("SrcAddr.Equal", "10.0.0.0/24")
                .actions(&["PASS"]),
        )]
}

#[test]
fn exception_shadows_its_parent() {
    let ssh = tcp_in("10.0.0.7", 5555, "10.0.0.5", 22);
    let ev = judge(inbound_drop_with_ssh_exception(), &ssh);
    assert_eq!(ev.verdict, Verdict::Pass);
    assert_eq!(ev.attributed_to.as_str(), "no-inbound/ssh-from-lan");

    let telnet = tcp_in("10.0.0.7", 5555, "10.0.0.5", 23);
    let ev = judge(inbound_drop_with_ssh_exception(), &telnet);
    assert_eq!(ev.verdict, Verdict::Drop);
    assert_eq!(ev.attributed_to.as_str(), "no-inbound");
}

#[test]
fn deepest_matching_node_speaks_for_the_region() {
    // "Drop everything inbound — except SSH from the LAN — except not from
    // the guest segment." The sentence from the design session, verbatim.
    let roots = || {
        vec![rb("no-inbound")
            .s("Direction.Equal", "in")
            .actions(&["DROP"])
            .child(
                rb("ssh-from-lan")
                    .int("DstPort.Equal", 22)
                    .s("SrcAddr.Equal", "10.0.0.0/16")
                    .actions(&["PASS"])
                    .child(
                        rb("not-the-guest-segment")
                            .s("SrcAddr.Equal", "10.0.99.0/24")
                            .actions(&["DROP"]),
                    ),
            )]
    };

    let lan_ssh = tcp_in("10.0.1.9", 5555, "10.0.0.5", 22);
    let ev = judge(roots(), &lan_ssh);
    assert_eq!(ev.verdict, Verdict::Pass);
    assert_eq!(ev.attributed_to.as_str(), "no-inbound/ssh-from-lan");

    let guest_ssh = tcp_in("10.0.99.9", 5555, "10.0.0.5", 22);
    let ev = judge(roots(), &guest_ssh);
    assert_eq!(ev.verdict, Verdict::Drop);
    assert_eq!(
        ev.attributed_to.as_str(),
        "no-inbound/ssh-from-lan/not-the-guest-segment"
    );
}

#[test]
fn shadowing_exists_only_within_a_lineage() {
    // Tree A's exception shadows tree A's root — but tree B still triggers
    // on the same packet, regardless of anyone's depth.
    let ssh = tcp_in("10.0.0.7", 5555, "10.0.0.5", 22);
    let mut roots = inbound_drop_with_ssh_exception();
    roots.push(
        rb("watcher")
            .int("DstPort.Equal", 22)
            .actions(&["REPORT(3)", "PASS"]),
    );

    let ev = judge(roots, &ssh);
    // Both branches yielded PASS; the watcher's report fired.
    assert_eq!(ev.verdict, Verdict::Pass);
    assert_eq!(reports(&ev), vec![("watcher".to_string(), 3)]);
    assert_eq!(ev.candidates.len(), 2);
}

#[test]
fn abstention_walks_up_to_the_nearest_verdict_bearing_ancestor() {
    // Child matches and abstains (NULL); the parent speaks for the region.
    let roots = vec![rb("no-inbound")
        .s("Direction.Equal", "in")
        .actions(&["DROP", "REPORT(2)"])
        .child(
            rb("interesting")
                .int("DstPort.Equal", 22)
                .actions(&["NULL", "COUNT(ssh-seen)"]),
        )];

    let ev = judge(roots, &tcp_in("10.0.0.7", 5555, "10.0.0.5", 22));
    assert_eq!(ev.verdict, Verdict::Drop);
    // The verdict is attributed to the speaking ancestor, not the abstainer.
    assert_eq!(ev.attributed_to.as_str(), "no-inbound");
    // The abstaining (triggered) child's side effects still ran…
    assert_eq!(counts(&ev), vec!["ssh-seen".to_string()]);
    // …and the speaker executed its full action list, report included.
    assert_eq!(reports(&ev), vec![("no-inbound".to_string(), 2)]);
}

#[test]
fn intermediate_abstaining_ancestors_execute_nothing() {
    let roots = vec![rb("outer")
        .s("Direction.Equal", "in")
        .actions(&["DROP", "TAG(outer-spoke, SET, 1)"])
        .child(
            rb("mid")
                .int("DstPort.Equal", 22)
                .actions(&["TAG(mid-spoke, SET, 1)"]) // no verdict: not a speaker
                .child(rb("leaf").s("SrcAddr.Equal", "10.0.0.7").actions(&["NULL"])),
        )];

    let ev = judge(roots, &tcp_in("10.0.0.7", 5555, "10.0.0.5", 22));
    assert_eq!(ev.verdict, Verdict::Drop);
    assert_eq!(ev.attributed_to.as_str(), "outer");
    // mid was neither triggered (leaf shadows it) nor a speaker: silent.
    assert_eq!(tags(&ev), vec!["outer-spoke".to_string()]);
}

#[test]
fn a_speaker_executes_once_for_multiple_abstaining_descendants() {
    let roots = vec![rb("parent")
        .s("Direction.Equal", "in")
        .actions(&["DROP", "REPORT(4)"])
        .child(rb("a").int("DstPort.Equal", 22).actions(&["NULL"]))
        .child(rb("b").s("SrcAddr.Equal", "10.0.0.7").actions(&["NULL"]))];

    // Packet matches both overlapping abstaining siblings.
    let ev = judge(roots, &tcp_in("10.0.0.7", 5555, "10.0.0.5", 22));
    assert_eq!(ev.verdict, Verdict::Drop);
    assert_eq!(
        reports(&ev).len(),
        1,
        "speaker spoke once, not per-abstainer"
    );
    assert_eq!(ev.candidates.len(), 1);
}

#[test]
fn no_speaker_in_parentage_falls_through_to_other_trees_or_backstop() {
    // A whole tree of abstainers contributes nothing dispositive.
    let roots = vec![rb("observers")
        .s("Direction.Equal", "in")
        .actions(&["COUNT(inbound)"]) // side effects only, no verdict
        .child(rb("ssh").int("DstPort.Equal", 22).actions(&["COUNT(ssh)"]))];
    let ev = judge(roots, &tcp_in("10.0.0.7", 5555, "10.0.0.5", 22));
    assert_eq!(ev.verdict, Verdict::Drop);
    assert!(ev.backstop);
    // The deepest observer still counted (triggered side effects run).
    assert_eq!(counts(&ev), vec!["ssh".to_string()]);
}

#[test]
fn priority_inherits_down_the_tree() {
    let roots = vec![
        rb("org")
            .int("Priority", 100)
            .s("Direction.Equal", "in")
            .actions(&["DROP"])
            .child(
                // No Priority of its own: inherits 100 and outranks the
                // priority-0 pass below.
                rb("ssh").int("DstPort.Equal", 22).actions(&["REJECT"]),
            ),
        rb("local-pass").actions(&["PASS"]),
    ];
    let ev = judge(roots, &tcp_in("10.0.0.7", 5555, "10.0.0.5", 22));
    assert_eq!(ev.verdict, Verdict::Reject(RejectKind::Refused));
    assert_eq!(ev.attributed_to.as_str(), "org/ssh");
}

#[test]
fn disabled_rules_do_not_match_and_take_their_subtree_with_them() {
    let roots = vec![rb("gone")
        .int("Enabled", 0)
        .s("Direction.Equal", "in")
        .actions(&["DROP"])
        .child(rb("child-too").actions(&["PASS", "REPORT(5)"]))];
    let ev = judge(roots, &tcp_in("10.0.0.7", 5555, "10.0.0.5", 22));
    assert!(ev.backstop);
    assert!(reports(&ev).is_empty());
}

#[test]
fn rule_names_with_path_separators_are_rejected() {
    let bad = RuleInput {
        name: "a/b".into(),
        values: Vec::new().into(),
        children: Vec::new().into(),
    };
    assert!(matches!(
        build_forest(Layer::Packet, &[bad]),
        Err(BuildError::BadRuleName { .. })
    ));
}
