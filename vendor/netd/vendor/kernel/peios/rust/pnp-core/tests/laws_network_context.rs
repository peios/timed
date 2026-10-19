//! The network context (PEI-598, rung 4): which network the interface a
//! packet crossed is standing on reaches the packet layers, so one rule
//! can mean "on an untrusted network" wherever it is written. The facts
//! are the interface layer's `Network.Id`, `Network.Name` and
//! `Network.Trust`; the rest of that layer's vocabulary stays its own.

mod common;

use common::{build, judge_in, rb, tcp_in};
use pnp_core::{build_forest, BuildError, Layer, LintKind, RuleInput, Snapshot, Verdict};

/// An inbound SSH approach on a card standing on a named, trusted network.
fn at_home() -> Snapshot<'static> {
    Snapshot {
        network_id: Some("net-1".into()),
        network_name: Some("palfrey-home".into()),
        network_trust: Some("home".into()),
        ..tcp_in("10.0.0.7", 43210, "10.0.0.5", 22)
    }
}

/// The same approach on a card with no network identified yet.
fn nowhere() -> Snapshot<'static> {
    tcp_in("10.0.0.7", 43210, "10.0.0.5", 22)
}

#[test]
fn the_network_context_is_a_fact_at_every_packet_layer() {
    for layer in [Layer::RawPacket, Layer::Packet, Layer::Flow] {
        for (key, value) in [
            ("Network.Id.Equal", "net-1"),
            ("Network.Name.Equal", "palfrey-home"),
            ("Network.Trust.Equal", "home"),
        ] {
            let e = judge_in(
                layer,
                vec![rb("r").s(key, value).actions(&["PASS"])],
                &at_home(),
            );
            assert_eq!(e.verdict, Verdict::Pass, "{key} at {layer:?}");
            assert_eq!(e.attributed_to.as_str(), "r");
        }
    }
}

#[test]
fn a_network_condition_never_lints_at_a_packet_layer() {
    for layer in [Layer::RawPacket, Layer::Packet, Layer::Flow] {
        let (_, lints) = build(
            layer,
            vec![rb("r").s("Network.Trust.Equal", "home").actions(&["PASS"])],
        );
        assert!(lints.is_empty(), "{layer:?}: {lints:?}");
    }
}

#[test]
fn no_network_means_the_condition_is_false_and_the_backstop_answers() {
    // Absent-fact law: a card no network has been identified on carries
    // no context, so "on the home network" is simply false there. The
    // shipped baseline applies unchanged; nothing opens by accident.
    let e = judge_in(
        Layer::Flow,
        vec![rb("home-ssh")
            .s("Network.Trust.Equal", "home")
            .actions(&["PASS"])],
        &nowhere(),
    );
    assert_eq!(e.verdict, Verdict::Drop);
    assert!(e.backstop);
}

#[test]
fn an_exception_can_open_a_door_on_one_network_only() {
    // The laptop rule: inbound SSH is refused everywhere, except on the
    // network the operator called home.
    let rules = || {
        vec![rb("no-ssh")
            .s("Direction.Equal", "in")
            .int("DstPort.Equal", 22)
            .actions(&["DROP"])
            .child(
                rb("home")
                    .s("Network.Trust.Equal", "home")
                    .actions(&["PASS"]),
            )]
    };
    let e = judge_in(Layer::Flow, rules(), &at_home());
    assert_eq!(e.verdict, Verdict::Pass);
    assert_eq!(e.attributed_to.as_str(), "no-ssh/home");
    let e = judge_in(Layer::Flow, rules(), &nowhere());
    assert_eq!(e.verdict, Verdict::Drop);
    assert_eq!(e.attributed_to.as_str(), "no-ssh");
    // A different word on the record is a different network to policy.
    let elsewhere = Snapshot {
        network_trust: Some("untrusted".into()),
        ..at_home()
    };
    let e = judge_in(Layer::Flow, rules(), &elsewhere);
    assert_eq!(e.verdict, Verdict::Drop);
}

#[test]
fn present_can_ask_whether_any_network_is_known() {
    // `Network.Id Present = 0` is the honest "not on any identified
    // network" — legal now that the fact exists at the packet layers.
    let rules = || {
        vec![rb("unknown-network")
            .int("Network.Id.Present", 0)
            .actions(&["DROP"])]
    };
    let e = judge_in(Layer::Packet, rules(), &nowhere());
    assert_eq!(e.verdict, Verdict::Drop);
    assert_eq!(e.attributed_to.as_str(), "unknown-network");
    let e = judge_in(Layer::Packet, rules(), &at_home());
    assert!(e.backstop);
}

#[test]
fn the_rest_of_the_interface_vocabulary_stays_off_the_packet_layers() {
    // `Interface.*` and `Network.Kind` are read from an interface record,
    // never from a packet: the lint still says so, and `Present` over
    // them still refuses the generation.
    for key in [
        "Interface.Kind.Equal",
        "Interface.Id.Equal",
        "Interface.Path.Equal",
        "Network.Kind.Equal",
    ] {
        for layer in [Layer::RawPacket, Layer::Packet, Layer::Flow] {
            let (_, lints) = build(layer, vec![rb("r").s(key, "x").actions(&["PASS"])]);
            assert!(
                lints
                    .iter()
                    .any(|l| l.kind == LintKind::FactNeverPresentAtLayer && l.key.as_str() == key),
                "{key} must lint at {layer:?}"
            );
        }
    }
    let inputs: Vec<RuleInput> = vec![
        rb("r")
            .int("Interface.Kind.Present", 1)
            .actions(&["PASS"])
            .0,
    ];
    let err = build_forest(Layer::Packet, &inputs).err().expect("refused");
    assert!(
        matches!(err, BuildError::PresentNeverAtLayer { .. }),
        "{err:?}"
    );
}

#[test]
fn the_interface_layer_still_reads_the_whole_vocabulary() {
    let snap = Snapshot {
        interface: Some("enp0s3".into()),
        interface_kind: Some("wired".into()),
        network_trust: Some("home".into()),
        network_kind: Some("wired".into()),
        ..Snapshot::default()
    };
    for (key, value) in [
        ("Interface.Kind.Equal", "wired"),
        ("Network.Trust.Equal", "home"),
        ("Network.Kind.Equal", "wired"),
    ] {
        let e = judge_in(
            Layer::Interface,
            vec![rb("r").s(key, value).actions(&["JOIN(p)"])],
            &snap,
        );
        assert_eq!(e.verdict, Verdict::Join(0), "{key}");
    }
}
