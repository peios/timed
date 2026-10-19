//! The absent-fact law and the layer lint: a condition over a fact the
//! packet does not have is false — never an error, never a match.

mod common;

use common::*;
use pnp_core::{FlowState, Layer, LintKind, Snapshot, Verdict};

#[test]
fn port_conditions_never_match_portless_packets() {
    let roots = || {
        vec![
            rb("web-ok").int("DstPort.Equal", 80).actions(&["PASS"]),
            rb("ping-ok").s("Protocol.Equal", "icmp").actions(&["PASS"]),
        ]
    };
    // ICMP has no ports: only the protocol rule can admit it.
    let ev = judge(roots(), &icmp_in("10.0.0.9"));
    assert_eq!(ev.verdict, Verdict::Pass);
    assert_eq!(ev.attributed_to.as_str(), "ping-ok");
}

#[test]
fn arp_frames_match_only_facts_they_have() {
    let roots = || {
        vec![
            rb("flow-pass")
                .s("FlowState.Equal", "established")
                .actions(&["PASS"]),
            rb("arp-ok").s("EtherType.Equal", "arp").actions(&["PASS"]),
        ]
    };
    let ev = judge(roots(), &arp_in());
    assert_eq!(ev.verdict, Verdict::Pass);
    assert_eq!(ev.attributed_to.as_str(), "arp-ok");

    // With neither matching (no arp rule), the backstop answers: absent
    // facts silently fail conditions rather than erroring.
    let ev = judge(
        vec![rb("flow-pass")
            .s("FlowState.Equal", "established")
            .actions(&["PASS"])],
        &arp_in(),
    );
    assert!(ev.backstop);
}

#[test]
fn established_pass_is_the_cornerstone_rule() {
    let roots = || {
        vec![rb("established")
            .s("FlowState.Equal", "established")
            .actions(&["PASS"])]
    };
    let mut snap = tcp_in("93.184.216.34", 443, "10.0.0.5", 40000);
    snap.flow_state = Some(FlowState::Established);
    let ev = judge(roots(), &snap);
    assert_eq!(ev.verdict, Verdict::Pass);

    let fresh = tcp_in("93.184.216.34", 443, "10.0.0.5", 40000); // NEW
    let ev = judge(roots(), &fresh);
    assert!(ev.backstop);
}

#[test]
fn tag_and_counter_conditions_read_the_snapshot() {
    let roots = || {
        vec![
            rb("trusted")
                .int("Tag.lan-trusted.Equal", 1)
                .actions(&["PASS"]),
            rb("flooded")
                .int("Counter.synburst.GreaterThan", 100)
                .actions(&["DROP"]),
        ]
    };

    let mut snap = tcp_in("10.0.0.7", 5555, "10.0.0.5", 22);
    snap.set_tag("lan-trusted", 1).unwrap();
    let ev = judge(roots(), &snap);
    assert_eq!(ev.verdict, Verdict::Pass);
    assert_eq!(ev.attributed_to.as_str(), "trusted");

    // The only view in the forest is index 0; the glue resolves it.
    let mut snap = tcp_in("192.0.2.1", 5555, "10.0.0.5", 22);
    snap.counter_views.push((0, 250)).unwrap();
    let ev = judge(roots(), &snap);
    assert_eq!(ev.verdict, Verdict::Drop);
    assert_eq!(ev.attributed_to.as_str(), "flooded");

    // Neither tag nor counter present: absent facts, backstop.
    let ev = judge(roots(), &tcp_in("192.0.2.1", 5555, "10.0.0.5", 22));
    assert!(ev.backstop);
}

#[test]
fn rawpacket_lints_flow_state_and_tags_loudly() {
    let (_, lints) = common::build(
        Layer::RawPacket,
        vec![rb("wrong-layer")
            .s("FlowState.Equal", "established")
            .int("Tag.x.Equal", 1)
            .int("DstPort.Equal", 22)
            .actions(&["PASS"])],
    );
    assert_eq!(lints.len(), 2);
    assert!(lints
        .iter()
        .all(|l| l.kind == LintKind::FactNeverPresentAtLayer));

    // The same rule at the Packet layer is clean.
    let (_, lints) = common::build(
        Layer::Packet,
        vec![rb("right-layer")
            .s("FlowState.Equal", "established")
            .int("Tag.x.Equal", 1)
            .actions(&["PASS"])],
    );
    assert!(lints.is_empty());
}

/// What the lint says is what evaluation does: a fact the layer never has
/// is false there even when the snapshot handed in carries it (the kernel
/// builds one snapshot per seat and judges every layer from it, PEI-1302).
#[test]
fn facts_never_at_a_layer_never_match_there() {
    let mut snap = tcp_in("10.0.0.7", 5555, "10.0.0.5", 22);
    snap.ttl = Some(64);
    snap.length = Some(60);
    snap.tcp_flags = Some(0x02);
    snap.flow_state = Some(FlowState::New);
    for rule in [
        rb("ttl").int("Ttl.Equal", 64),
        rb("length").int("Length.Equal", 60),
        rb("flags").list("TcpFlags.Has", &["syn"]),
    ] {
        let ev = judge_in(Layer::Flow, vec![rule.actions(&["PASS"])], &snap);
        assert!(ev.backstop, "{} matched at Flow", ev.attributed_to.as_str());
    }
    for layer in [Layer::Flow, Layer::RawPacket] {
        let ev = judge_in(
            layer,
            vec![rb("r").s("FlowState.Equal", "new").actions(&["PASS"])],
            &snap,
        );
        assert!(ev.backstop, "FlowState matched at {layer:?}");
    }
    // At the Packet layer the same facts are the packet's, and match.
    let ev = judge_in(
        Layer::Packet,
        vec![rb("r").int("Ttl.Equal", 64).actions(&["PASS"])],
        &snap,
    );
    assert_eq!(ev.verdict, Verdict::Pass);
}

#[test]
fn time_facts_compare_as_integers() {
    let roots = || {
        vec![rb("after-hours")
            .int("Time.Hour.GreaterThan", 21)
            .int("DstPort.Equal", 25565)
            .actions(&["DROP"])]
    };
    let mut late = tcp_out("203.0.113.5", 25565);
    late.time = Some(pnp_core::TimeFacts {
        year: 2026,
        month: 9,
        day_of_month: 1,
        day_of_week: 2,
        hour: 22,
        minute: 30,
        second: 0,
    });
    let ev = judge(roots(), &late);
    assert_eq!(ev.verdict, Verdict::Drop);

    let mut early = tcp_out("203.0.113.5", 25565);
    early.time = Some(pnp_core::TimeFacts {
        hour: 14,
        ..late.time.unwrap()
    });
    let ev = judge(roots(), &early);
    assert!(ev.backstop);

    // No clock machinery, no time facts: the condition is false.
    let ev = judge(roots(), &tcp_out("203.0.113.5", 25565));
    assert!(ev.backstop);
}

/// Snapshot with nothing at all set still evaluates (to the backstop).
#[test]
fn the_empty_snapshot_is_judged_not_crashed() {
    let ev = judge(
        vec![rb("anything").int("DstPort.Equal", 22).actions(&["PASS"])],
        &Snapshot::default(),
    );
    assert!(ev.backstop);
}
