//! Ingestion: the match grammar, action grammar errors, and the value
//! shapes rules are written in.

mod common;

use common::*;
use pnp_core::{build_forest, BuildError, Layer, RegValue, RejectKind, Verdict};

fn build_err(rule: Rb) -> BuildError {
    build_forest(Layer::Packet, &[rule.0]).expect_err("build should fail")
}

#[test]
fn unknown_facts_and_operators_are_rejected() {
    assert!(matches!(
        build_err(rb("r").int("Dport.Equal", 22).actions(&["PASS"])),
        BuildError::UnknownFact { .. }
    ));
    assert!(matches!(
        build_err(rb("r").int("DstPort", 22).actions(&["PASS"])),
        BuildError::UnknownFact { .. }
    ));
    assert!(matches!(
        build_err(
            rb("r")
                .s("SrcAddr.GreaterThan", "10.0.0.1")
                .actions(&["PASS"])
        ),
        BuildError::BadOperator { .. }
    ));
    assert!(matches!(
        build_err(rb("r").s("DstPort.Has", "SYN").actions(&["PASS"])),
        BuildError::BadOperator { .. }
    ));
}

#[test]
fn bad_patterns_are_rejected_with_the_offending_key() {
    match build_err(rb("r").s("DstPort.Equal", "eighty").actions(&["PASS"])) {
        BuildError::BadPattern { rule, key } => {
            assert_eq!(rule.as_str(), "r");
            assert_eq!(key.as_str(), "DstPort.Equal");
        }
        other => panic!("unexpected {other:?}"),
    }
    assert!(matches!(
        build_err(rb("r").s("SrcAddr.Equal", "10.0.0.0/40").actions(&["PASS"])),
        BuildError::BadPattern { .. }
    ));
    assert!(matches!(
        build_err(rb("r").s("SrcMac.Equal", "not-a-mac").actions(&["PASS"])),
        BuildError::BadPattern { .. }
    ));
    // Inverted range.
    assert!(matches!(
        build_err(rb("r").s("DstPort.Equal", "90-80").actions(&["PASS"])),
        BuildError::BadPattern { .. }
    ));
}

#[test]
fn reject_kinds_are_exactly_the_minted_two() {
    match build_err(rb("r").actions(&["REJECT(icmp-admin-prohibited)"])) {
        BuildError::BadAction { detail, .. } => {
            assert_eq!(detail, pnp_core::ActionParseError::UnknownRejectKind)
        }
        other => panic!("unexpected {other:?}"),
    }
    let (forest, _) = common::build(
        Layer::Packet,
        vec![
            rb("a").actions(&["REJECT"]),
            rb("b").actions(&["REJECT(Refused)"]),
            rb("c").actions(&["REJECT(Prohibited)"]),
        ],
    );
    let kinds: Vec<_> = forest
        .roots
        .iter()
        .map(|r| r.direct_verdict().unwrap())
        .collect();
    assert_eq!(
        kinds,
        vec![
            Verdict::Reject(RejectKind::Refused),
            Verdict::Reject(RejectKind::Refused),
            Verdict::Reject(RejectKind::Prohibited),
        ]
    );
}

#[test]
fn counter_view_keys_are_validated_with_the_offending_key() {
    match build_err(
        rb("r")
            .int("Counter.x(2d).GreaterThan", 1)
            .actions(&["PASS"]),
    ) {
        BuildError::BadCounterView { rule, key } => {
            assert_eq!(rule.as_str(), "r");
            assert_eq!(key.as_str(), "Counter.x(2d).GreaterThan");
        }
        other => panic!("unexpected {other:?}"),
    }
    assert!(matches!(
        build_err(rb("r").int("Counter.x(Ttl).Equal", 1).actions(&["PASS"])),
        BuildError::BadCounterView { .. }
    ));
    // Views compare as integers: address operators are refused.
    assert!(matches!(
        build_err(rb("r").s("Counter.x.Has", "SYN").actions(&["PASS"])),
        BuildError::BadOperator { .. }
    ));
}

#[test]
fn action_priority_enabled_value_shapes_are_validated() {
    assert!(matches!(
        build_err(rb("r").s("Actions", "PASS")),
        BuildError::BadActionsValue { .. }
    ));
    assert!(matches!(
        build_err(rb("r").actions(&["ALLOW"])),
        BuildError::BadAction { .. }
    ));
    assert!(matches!(
        build_err(rb("r").s("Priority", "high").actions(&["PASS"])),
        BuildError::BadPriority { .. }
    ));
    assert!(matches!(
        build_err(rb("r").int("Enabled", 2).actions(&["PASS"])),
        BuildError::BadEnabled { .. }
    ));
}

#[test]
fn port_lists_mix_scalars_and_ranges() {
    let roots = || {
        vec![rb("web")
            .list("DstPort.Equal", &["80-87", "89", "443"])
            .actions(&["PASS"])]
    };
    for (port, pass) in [
        (80, true),
        (85, true),
        (88, false),
        (89, true),
        (443, true),
        (8080, false),
    ] {
        let ev = judge(roots(), &tcp_in("10.0.0.9", 5555, "10.0.0.5", port));
        assert_eq!(ev.verdict == Verdict::Pass, pass, "port {port}");
    }
}

#[test]
fn address_patterns_cover_exact_range_and_cidr() {
    let roots = || {
        vec![rb("lan")
            .list(
                "SrcAddr.Equal",
                &["10.0.0.0/24", "192.168.1.5", "172.16.0.10-172.16.0.20"],
            )
            .actions(&["PASS"])]
    };
    for (src, pass) in [
        ("10.0.0.200", true),
        ("10.0.1.1", false),
        ("192.168.1.5", true),
        ("192.168.1.6", false),
        ("172.16.0.15", true),
        ("172.16.0.21", false),
    ] {
        let ev = judge(roots(), &tcp_in(src, 5555, "10.0.0.5", 22));
        assert_eq!(ev.verdict == Verdict::Pass, pass, "src {src}");
    }
}

#[test]
fn v6_prefixes_never_match_v4_addresses_and_vice_versa() {
    let roots = || {
        vec![
            rb("v6-lan")
                .s("SrcAddr.Equal", "fd00::/8")
                .actions(&["PASS"]),
            rb("v4-any")
                .s("SrcAddr.Equal", "0.0.0.0/0")
                .actions(&["REJECT"]),
        ]
    };
    let mut v6 = tcp_in("10.0.0.9", 5555, "10.0.0.5", 22);
    v6.src_addr = Some("fd00::1234".parse().unwrap());
    v6.dst_addr = Some("fd00::1".parse().unwrap());
    v6.ether_type = Some(0x86DD);
    let ev = judge(roots(), &v6);
    // v4-any's 0.0.0.0/0 must NOT swallow a v6 source.
    assert_eq!(ev.verdict, Verdict::Pass);
    assert_eq!(ev.attributed_to.as_str(), "v6-lan");

    let ev = judge(roots(), &tcp_in("10.0.0.9", 5555, "10.0.0.5", 22));
    assert_eq!(ev.verdict, Verdict::Reject(RejectKind::Refused));
}

#[test]
fn tcp_flag_algebra_uses_has_and_hasnt() {
    use pnp_core::tcp_flags;
    let roots = || {
        vec![rb("bare-syn")
            .list("TcpFlags.Has", &["SYN"])
            .s("TcpFlags.Hasnt", "ACK")
            .actions(&["DROP"])]
    };
    let syn = tcp_in("10.0.0.9", 5555, "10.0.0.5", 22); // SYN only
    assert_eq!(judge(roots(), &syn).verdict, Verdict::Drop);

    let mut synack = tcp_in("10.0.0.9", 5555, "10.0.0.5", 22);
    synack.tcp_flags = Some(tcp_flags::SYN | tcp_flags::ACK);
    assert!(judge(roots(), &synack).backstop);
}

#[test]
fn protocol_and_ethertype_accept_friendly_names() {
    let roots = || {
        vec![
            rb("no-udp").s("Protocol.Equal", "udp").actions(&["DROP"]),
            rb("tcp-ok").s("Protocol.Equal", "tcp").actions(&["PASS"]),
        ]
    };
    let ev = judge(roots(), &tcp_in("10.0.0.9", 5555, "10.0.0.5", 22));
    assert_eq!(ev.verdict, Verdict::Pass);

    let mut udp = tcp_in("10.0.0.9", 5555, "10.0.0.5", 53);
    udp.protocol = Some(17);
    udp.tcp_flags = None;
    let ev = judge(roots(), &udp);
    assert_eq!(ev.verdict, Verdict::Drop);
}

#[test]
fn mac_conditions_match_frames() {
    let roots = || {
        vec![rb("that-box")
            .s("SrcMac.Equal", "52:54:00:12:34:56")
            .actions(&["PASS"])]
    };
    let ev = judge(roots(), &arp_in());
    assert_eq!(ev.verdict, Verdict::Pass);
}

#[test]
fn rules_without_actions_are_null_rules() {
    // A grouping rule with no Actions value abstains; its exception decides
    // or the walk goes past it.
    let bare = rb("group").s("Direction.Equal", "in");
    let ev = judge(
        vec![bare.child(rb("ssh").int("DstPort.Equal", 22).actions(&["PASS"]))],
        &tcp_in("10.0.0.9", 5555, "10.0.0.5", 22),
    );
    assert_eq!(ev.verdict, Verdict::Pass);
    assert_eq!(ev.attributed_to.as_str(), "group/ssh");

    // Non-ssh inbound: group triggers, abstains, no speaking ancestor,
    // backstop.
    let ev = judge(
        vec![rb("group").s("Direction.Equal", "in")],
        &tcp_in("10.0.0.9", 5555, "10.0.0.5", 80),
    );
    assert!(ev.backstop);
}

#[test]
fn empty_condition_lists_are_rejected() {
    let empty: Vec<RegValue> = Vec::new();
    assert!(matches!(
        build_err(
            rb("r")
                .val("DstPort.Equal", RegValue::List(empty.into()))
                .actions(&["PASS"])
        ),
        BuildError::BadPattern { .. }
    ));
}
