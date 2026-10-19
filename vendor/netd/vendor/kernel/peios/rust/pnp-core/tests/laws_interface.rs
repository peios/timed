//! The interface layer (PEI-598, the interface configuration surface):
//! an interface, not a packet, is the subject; a userspace executor, not
//! the kernel, judges it; its verdicts name profiles.

mod common;

use common::{build, judge_in, rb};
use pnp_core::{build_forest, BuildError, Layer, LintKind, RuleInput, Snapshot, Verdict};

/// A wired card in a PCI slot, on a network the operator has named.
fn wired() -> Snapshot<'static> {
    Snapshot {
        interface: Some("enp0s3".into()),
        interface_kind: Some("wired".into()),
        interface_id: Some("3f2a1b".into()),
        interface_mac: Some([0x52, 0x54, 0, 1, 2, 3]),
        interface_path: Some("pci-0000:00:03.0".into()),
        interface_driver: Some("virtio_net".into()),
        network_id: Some("net-1".into()),
        network_name: Some("office".into()),
        network_trust: Some("corporate".into()),
        network_kind: Some("wired".into()),
        ..Snapshot::default()
    }
}

/// A tunnel: no hardware address, bus position or driver, and no network
/// record yet.
fn tunnel() -> Snapshot<'static> {
    Snapshot {
        interface: Some("wg0".into()),
        interface_kind: Some("tunnel".into()),
        interface_id: Some("9c0d".into()),
        ..Snapshot::default()
    }
}

#[test]
fn join_names_a_profile_through_the_forest_table() {
    let (forest, _) = build(
        Layer::Interface,
        vec![rb("wired")
            .s("Interface.Kind.Equal", "wired")
            .actions(&["JOIN(office/london)"])],
    );
    assert_eq!(forest.profiles.len(), 1);
    assert_eq!(forest.profiles[0].as_str(), "office/london");
    let e = pnp_core::evaluate(&forest, &wired(), &Default::default()).unwrap();
    assert_eq!(e.verdict, Verdict::Join(0));
    assert_eq!(e.attributed_to.as_str(), "wired");
    assert!(!e.backstop);
    assert!(!e.conflict);
}

#[test]
fn a_backslash_path_is_folded_and_the_same_profile_is_interned_once() {
    let (forest, _) = build(
        Layer::Interface,
        vec![
            rb("a")
                .s("Interface.Kind.Equal", "wired")
                .actions(&["JOIN(office\\london)"]),
            rb("b")
                .s("Interface.Kind.Equal", "wireless")
                .actions(&["JOIN(office/london)"]),
            rb("c")
                .s("Interface.Kind.Equal", "tunnel")
                .actions(&["JOIN(vpn)"]),
        ],
    );
    let names: Vec<&str> = forest.profiles.iter().map(|p| p.as_str()).collect();
    assert_eq!(names, ["office/london", "vpn"]);
}

#[test]
fn profile_case_variants_share_an_index_and_keep_the_first_spelling() {
    let (forest, _) = build(
        Layer::Interface,
        vec![
            rb("a").actions(&["JOIN(Default)"]),
            rb("b").actions(&["JOIN(DEFAULT)"]),
            rb("c").actions(&["JOIN(default)"]),
            rb("d").actions(&["JOIN(other)"]),
        ],
    );
    let names: Vec<&str> = forest.profiles.iter().map(|p| p.as_str()).collect();
    assert_eq!(names, ["Default", "other"]);
    let e = pnp_core::evaluate(&forest, &wired(), &Default::default()).unwrap();
    let verdicts: Vec<Verdict> = e.candidates.iter().map(|c| c.verdict).collect();
    assert_eq!(
        verdicts,
        [
            Verdict::Join(0),
            Verdict::Join(0),
            Verdict::Join(0),
            Verdict::Join(1)
        ]
    );
    assert!(
        e.conflict,
        "the genuinely different profile still conflicts"
    );
}

#[test]
fn equal_priority_case_variant_joins_agree_in_either_input_order() {
    for actions in [
        ["JOIN(default)", "JOIN(DEFAULT)"],
        ["JOIN(DEFAULT)", "JOIN(default)"],
    ] {
        let e = judge_in(
            Layer::Interface,
            vec![
                rb("a").int("Priority", 10).actions(&[actions[0]]),
                rb("b").int("Priority", 10).actions(&[actions[1]]),
            ],
            &wired(),
        );
        assert!(!e.conflict, "{actions:?}");
        assert!(!e.backstop);
        assert_eq!(e.verdict, Verdict::Join(0));
        assert_eq!(e.candidates.len(), 2);
        assert!(e.candidates.iter().all(|c| c.verdict == Verdict::Join(0)));
    }
}

#[test]
fn nested_profile_case_and_separator_variants_agree() {
    let (forest, _) = build(
        Layer::Interface,
        vec![
            rb("a").actions(&["JOIN(Office\\London)"]),
            rb("b").child(rb("exception").actions(&["JOIN(office/LONDON)"])),
        ],
    );
    let e = pnp_core::evaluate(&forest, &wired(), &Default::default()).unwrap();
    assert!(!e.conflict);
    assert_eq!(e.candidates.len(), 2);
    assert!(e.candidates.iter().all(|c| c.verdict == Verdict::Join(0)));
    let names: Vec<&str> = forest.profiles.iter().map(|p| p.as_str()).collect();
    assert_eq!(names, ["Office/London"]);
}

#[test]
fn profile_interning_preserves_non_ascii_distinctions() {
    // Match netd's ASCII-only profile lookup, not Unicode case folding.
    let (forest, _) = build(
        Layer::Interface,
        vec![
            rb("a").actions(&["JOIN(Ärea)"]),
            rb("b").actions(&["JOIN(ärea)"]),
        ],
    );
    let names: Vec<&str> = forest.profiles.iter().map(|p| p.as_str()).collect();
    assert_eq!(names, ["Ärea", "ärea"]);
    let e = pnp_core::evaluate(&forest, &wired(), &Default::default()).unwrap();
    assert!(e.conflict);
    assert_eq!(e.candidates.len(), 2);
}

#[test]
fn the_backstop_is_ignore() {
    let e = judge_in(
        Layer::Interface,
        vec![rb("radio")
            .s("Interface.Kind.Equal", "wireless")
            .actions(&["JOIN(default)"])],
        &wired(),
    );
    assert_eq!(e.verdict, Verdict::Ignore);
    assert!(e.backstop);
    assert_eq!(e.attributed_to.as_str(), "backstop");
}

#[test]
fn every_interface_fact_matches_and_absent_facts_are_false() {
    let facts = [
        ("Interface.Equal", "enp0s3"),
        ("Interface.Kind.Equal", "wired"),
        ("Interface.Id.Equal", "3f2a1b"),
        ("Interface.Mac.Equal", "52:54:00:01:02:03"),
        ("Interface.Path.Equal", "pci-0000:00:03.0"),
        ("Interface.Driver.Equal", "virtio_net"),
        ("Network.Id.Equal", "net-1"),
        ("Network.Name.Equal", "office"),
        ("Network.Trust.Equal", "corporate"),
        ("Network.Kind.Equal", "wired"),
    ];
    for (key, value) in facts {
        let e = judge_in(
            Layer::Interface,
            vec![rb("r").s(key, value).actions(&["JOIN(p)"])],
            &wired(),
        );
        assert_eq!(e.verdict, Verdict::Join(0), "{key} should match");
    }
    // The tunnel lacks the hardware facts and the network record: a
    // condition over them is false (absent-fact law), so the rule never
    // matches and the backstop answers.
    for (key, value) in [
        ("Interface.Mac.Equal", "52:54:00:01:02:03"),
        ("Interface.Path.Equal", "pci-0000:00:03.0"),
        ("Network.Trust.Equal", "corporate"),
    ] {
        let e = judge_in(
            Layer::Interface,
            vec![rb("r").s(key, value).actions(&["JOIN(p)"])],
            &tunnel(),
        );
        assert_eq!(
            e.verdict,
            Verdict::Ignore,
            "{key} must be false on a tunnel"
        );
    }
    // Present looks through the law.
    let e = judge_in(
        Layer::Interface,
        vec![rb("r").int("Interface.Path.Present", 0).actions(&["DOWN"])],
        &tunnel(),
    );
    assert_eq!(e.verdict, Verdict::Down);
}

#[test]
fn strictness_is_down_over_ignore_over_join_and_priority_beats_it() {
    let both = |a: &str, b: &str| {
        judge_in(
            Layer::Interface,
            vec![
                rb("a").s("Interface.Kind.Equal", "wired").actions(&[a]),
                rb("b").s("Interface.Kind.Equal", "wired").actions(&[b]),
            ],
            &wired(),
        )
    };
    assert_eq!(both("JOIN(p)", "IGNORE").verdict, Verdict::Ignore);
    assert_eq!(both("IGNORE", "DOWN").verdict, Verdict::Down);
    assert_eq!(both("JOIN(p)", "DOWN").verdict, Verdict::Down);

    let e = judge_in(
        Layer::Interface,
        vec![
            rb("dark")
                .s("Interface.Kind.Equal", "wired")
                .actions(&["DOWN"]),
            rb("this-one")
                .s("Interface.Id.Equal", "3f2a1b")
                .int("Priority", 100)
                .actions(&["JOIN(office)"]),
        ],
        &wired(),
    );
    assert_eq!(e.verdict, Verdict::Join(0));
    assert_eq!(e.attributed_to.as_str(), "this-one");
}

#[test]
fn two_joins_tied_on_priority_are_a_conflict_not_a_choice() {
    let e = judge_in(
        Layer::Interface,
        vec![
            rb("a")
                .s("Interface.Kind.Equal", "wired")
                .actions(&["JOIN(x)"]),
            rb("b")
                .s("Interface.Kind.Equal", "wired")
                .actions(&["JOIN(y)"]),
        ],
        &wired(),
    );
    assert!(e.conflict);
    assert_eq!(e.candidates.len(), 2);
    // The same profile from two trees is agreement, not conflict.
    let e = judge_in(
        Layer::Interface,
        vec![
            rb("a")
                .s("Interface.Kind.Equal", "wired")
                .actions(&["JOIN(x)"]),
            rb("b")
                .s("Interface.Kind.Equal", "wired")
                .actions(&["JOIN(x)"]),
        ],
        &wired(),
    );
    assert!(!e.conflict);
    // Priority settles it.
    let e = judge_in(
        Layer::Interface,
        vec![
            rb("a")
                .s("Interface.Kind.Equal", "wired")
                .actions(&["JOIN(x)"]),
            rb("b")
                .s("Interface.Kind.Equal", "wired")
                .int("Priority", 5)
                .actions(&["JOIN(y)"]),
        ],
        &wired(),
    );
    assert!(!e.conflict);
    assert_eq!(e.attributed_to.as_str(), "b");
}

#[test]
fn an_exception_names_a_different_profile_and_the_laptop_case_reads() {
    let rules = vec![rb("radio")
        .s("Interface.Kind.Equal", "wired")
        .actions(&["JOIN(untrusted)"])
        .child(
            rb("home")
                .s("Network.Name.Equal", "palfrey-home")
                .actions(&["JOIN(home)"]),
        )
        .child(
            rb("office")
                .s("Network.Trust.Equal", "corporate")
                .actions(&["JOIN(corp)"]),
        )];
    let (forest, _) = build(Layer::Interface, rules);
    let e = pnp_core::evaluate(&forest, &wired(), &Default::default()).unwrap();
    assert_eq!(e.attributed_to.as_str(), "radio/office");
    let Verdict::Join(i) = e.verdict else {
        panic!("expected JOIN")
    };
    assert_eq!(forest.profiles[i as usize].as_str(), "corp");

    let mut cafe = wired();
    cafe.network_name = Some("cafe".into());
    cafe.network_trust = Some("public".into());
    let e = pnp_core::evaluate(&forest, &cafe, &Default::default()).unwrap();
    assert_eq!(e.attributed_to.as_str(), "radio");
    let Verdict::Join(i) = e.verdict else {
        panic!("expected JOIN")
    };
    assert_eq!(forest.profiles[i as usize].as_str(), "untrusted");
}

#[test]
fn an_abstaining_exception_lets_its_parent_speak() {
    // The executor rewrites a JOIN of a disabled profile to NULL before
    // building; here the abstention is written directly.
    let e = judge_in(
        Layer::Interface,
        vec![rb("wired")
            .s("Interface.Kind.Equal", "wired")
            .actions(&["JOIN(default)"])
            .child(
                rb("slot3")
                    .s("Interface.Path.Equal", "pci-0000:00:03.0")
                    .actions(&["NULL"]),
            )],
        &wired(),
    );
    assert_eq!(e.verdict, Verdict::Join(0));
    assert_eq!(e.attributed_to.as_str(), "wired");
}

#[test]
fn report_is_the_one_effect_the_layer_keeps() {
    let e = judge_in(
        Layer::Interface,
        vec![rb("wired")
            .s("Interface.Kind.Equal", "wired")
            .actions(&["JOIN(p)", "REPORT(3)"])],
        &wired(),
    );
    assert_eq!(e.effects.len(), 1);
}

fn refused(layer: Layer, rule: common::Rb) -> BuildError {
    let inputs: Vec<RuleInput> = vec![rule.0];
    build_forest(layer, &inputs).err().expect("must refuse")
}

#[test]
fn the_interface_layer_refuses_packet_actions_and_the_packet_layers_refuse_its_verdicts() {
    for action in [
        "PASS",
        "DROP",
        "REJECT",
        "TAG(t, Set)",
        "COUNT(c)",
        "PROMPT(h, DROP)",
    ] {
        let err = refused(Layer::Interface, rb("r").actions(&[action]));
        assert!(
            matches!(err, BuildError::ActionNotAtLayer { .. }),
            "{action}: {err:?}"
        );
    }
    for layer in [Layer::Packet, Layer::RawPacket, Layer::Flow] {
        for action in ["JOIN(p)", "IGNORE", "DOWN", "PROMPT(h, DOWN)"] {
            let err = refused(layer, rb("r").actions(&[action]));
            assert!(
                matches!(err, BuildError::ActionNotAtLayer { .. }),
                "{action}: {err:?}"
            );
        }
    }
}

#[test]
fn a_join_path_must_be_a_path() {
    for bad in ["JOIN()", "JOIN(/x)", "JOIN(x/)", "JOIN(a//b)", "JOIN(a, b)"] {
        let err = refused(Layer::Interface, rb("r").actions(&[bad]));
        assert!(
            matches!(err, BuildError::BadAction { .. }),
            "{bad}: {err:?}"
        );
    }
}

#[test]
fn tags_and_counters_do_not_exist_at_the_interface_layer() {
    let err = refused(
        Layer::Interface,
        rb("r").int("Tag.x.GreaterThan", 0).actions(&["DOWN"]),
    );
    assert!(matches!(err, BuildError::KeyNotAtLayer { .. }), "{err:?}");
    let err = refused(
        Layer::Interface,
        rb("r").int("Counter.c.GreaterThan", 0).actions(&["DOWN"]),
    );
    assert!(matches!(err, BuildError::KeyNotAtLayer { .. }), "{err:?}");
}

#[test]
fn packet_facts_are_dead_at_the_interface_layer_and_vice_versa() {
    let (_, lints) = build(
        Layer::Interface,
        vec![rb("r").int("DstPort.Equal", 22).actions(&["DOWN"])],
    );
    assert_eq!(lints.len(), 1);
    assert_eq!(lints[0].kind, LintKind::FactNeverPresentAtLayer);
    let err = refused(
        Layer::Interface,
        rb("r").int("DstPort.Present", 1).actions(&["DOWN"]),
    );
    assert!(
        matches!(err, BuildError::PresentNeverAtLayer { .. }),
        "{err:?}"
    );

    for layer in [Layer::Packet, Layer::RawPacket, Layer::Flow] {
        let (_, lints) = build(
            layer,
            vec![rb("r")
                .s("Interface.Kind.Equal", "wired")
                .actions(&["DROP"])],
        );
        assert_eq!(lints.len(), 1, "{layer:?}");
        // The network context (`Network.Id/Name/Trust`) is a packet fact
        // too (laws_network_context.rs); `Network.Kind` is not.
        let err = refused(
            layer,
            rb("r").int("Network.Kind.Present", 1).actions(&["DROP"]),
        );
        assert!(
            matches!(err, BuildError::PresentNeverAtLayer { .. }),
            "{layer:?}: {err:?}"
        );
    }
    // The interface name itself is shared with the packet layers.
    let (_, lints) = build(
        Layer::Interface,
        vec![rb("r").s("Interface.Equal", "eth0").actions(&["DOWN"])],
    );
    assert!(lints.is_empty());
}

#[test]
fn packet_layer_backstops_are_unchanged() {
    for layer in [Layer::Packet, Layer::RawPacket, Layer::Flow] {
        assert_eq!(layer.backstop(), Verdict::Drop);
    }
    assert_eq!(Layer::Interface.backstop(), Verdict::Ignore);
}
