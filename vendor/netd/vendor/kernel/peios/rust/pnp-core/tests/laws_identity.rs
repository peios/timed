//! The identity facts (PEI-598, rung 3): `Local`, `Local.*`, `Remote` on
//! loopback, the SID family, the `Present` operator and its refusal on
//! facts absent by law.

mod common;

use common::*;
use pnp_core::{
    build_forest, BuildError, Direction, Endpoint, EndpointKind, Layer, LintKind, OwnedPrincipal,
    RuleInput, Sid, Snapshot, Verdict,
};

fn sid(s: &str) -> Sid {
    Sid::parse_str(s).unwrap()
}

/// resolvd's token: LocalService with its per-service SID and the logon
/// SID among its groups, Medium integrity, unconfined.
fn resolvd() -> OwnedPrincipal {
    OwnedPrincipal {
        user: sid("S-1-5-19"),
        groups: vec![
            sid("S-1-1-0"),
            sid("S-1-5-6"),
            Sid::service("resolvd"),
            sid("S-1-5-5-0-4242"),
        ]
        .into(),
        integrity: 8192,
        confinement: None,
        capabilities: vec![].into(),
        process: "0f3a9c2e-1b4d-4e5f-8a6b-7c8d9e0f1a2b".into(),
    }
}

/// A confined browser page: a user token under a confinement SID with one
/// capability, Low integrity.
fn confined_page() -> OwnedPrincipal {
    OwnedPrincipal {
        user: sid("S-1-5-21-1-2-3-1001"),
        groups: vec![sid("S-1-1-0"), sid("S-1-5-32-545"), sid("S-1-5-5-0-7")].into(),
        integrity: 4096,
        confinement: Some(sid("S-1-15-2-1")),
        capabilities: vec![sid("S-1-15-3-1")].into(),
        process: "11111111-2222-3333-4444-555555555555".into(),
    }
}

/// An outbound flow's first packet at the Flow layer, owned by `p`.
fn flow_from<'a>(p: &'a dyn pnp_core::Principal, dst: &str, dport: u16) -> Snapshot<'a> {
    Snapshot {
        direction: Some(Direction::Out),
        interface: Some("eth0".into()),
        src_addr: Some("10.0.0.5".parse().unwrap()),
        dst_addr: Some(dst.parse().unwrap()),
        protocol: Some(17),
        src_port: Some(40000),
        dst_port: Some(dport),
        related: Some(false),
        local: Some(Endpoint {
            kind: EndpointKind::Program,
            principal: Some(p),
        }),
        ..Snapshot::default()
    }
}

fn flow_kind(kind: EndpointKind) -> Snapshot<'static> {
    Snapshot {
        direction: Some(Direction::In),
        interface: Some("eth0".into()),
        src_addr: Some("192.0.2.9".parse().unwrap()),
        dst_addr: Some("10.0.0.5".parse().unwrap()),
        protocol: Some(6),
        src_port: Some(51000),
        dst_port: Some(22),
        related: Some(false),
        local: Some(Endpoint {
            kind,
            principal: None,
        }),
        ..Snapshot::default()
    }
}

#[test]
fn a_service_is_named_by_its_name_or_its_sid() {
    let p = resolvd();
    let snap = flow_from(&p, "192.0.2.53", 53);
    // A posture with one exception: only resolvd asks the world names.
    let by_name = vec![rb("nothing-else").actions(&["DROP"]).child(
        rb("resolvd-dns")
            .s("Local.Service.Equal", "resolvd")
            .int("DstPort.Equal", 53)
            .actions(&["PASS"]),
    )];
    let ev = judge_in(Layer::Flow, by_name, &snap);
    assert_eq!(ev.verdict, Verdict::Pass);
    assert_eq!(ev.attributed_to.as_str(), "nothing-else/resolvd-dns");

    let by_sid = vec![rb("resolvd-dns")
        .s("Local.Service.Equal", &Sid::service("resolvd").to_string())
        .actions(&["PASS"])];
    assert_eq!(judge_in(Layer::Flow, by_sid, &snap).verdict, Verdict::Pass);

    // Another service's name is a different SID: no match, backstop.
    let other = vec![rb("netd")
        .s("Local.Service.Equal", "netd")
        .actions(&["PASS"])];
    assert!(judge_in(Layer::Flow, other, &snap).backstop);
}

#[test]
fn user_and_group_facts_read_the_token() {
    let p = resolvd();
    let snap = flow_from(&p, "192.0.2.53", 53);

    // Well-known names and SIDs are the same pattern.
    for pattern in ["LocalService", "localservice", "S-1-5-19"] {
        let ev = judge_in(
            Layer::Flow,
            vec![rb("svc").s("Local.User.Equal", pattern).actions(&["PASS"])],
            &snap,
        );
        assert_eq!(ev.verdict, Verdict::Pass, "pattern {pattern}");
    }
    let ev = judge_in(
        Layer::Flow,
        vec![rb("sys").s("Local.User.Equal", "SYSTEM").actions(&["PASS"])],
        &snap,
    );
    assert!(ev.backstop);

    // Group is any-of over the enabled groups; a list is a disjunction.
    let ev = judge_in(
        Layer::Flow,
        vec![rb("members")
            .list("Local.Group.Equal", &["Administrators", "Service"])
            .actions(&["PASS"])],
        &snap,
    );
    assert_eq!(ev.verdict, Verdict::Pass);
    let ev = judge_in(
        Layer::Flow,
        vec![rb("admins")
            .s("Local.Group.Equal", "Administrators")
            .actions(&["PASS"])],
        &snap,
    );
    assert!(ev.backstop);

    // The logon SID is reachable as a group; no separate fact.
    let ev = judge_in(
        Layer::Flow,
        vec![rb("session")
            .s("Local.Group.Equal", "S-1-5-5-0-4242")
            .actions(&["PASS"])],
        &snap,
    );
    assert_eq!(ev.verdict, Verdict::Pass);
}

#[test]
fn integrity_is_an_integer_with_named_levels() {
    let low = confined_page();
    let snap = flow_from(&low, "93.184.216.34", 443);
    let roots = || {
        vec![
            rb("below-medium")
                .s("Local.Integrity.LessThan", "medium")
                .actions(&["REJECT"]),
            rb("rest").actions(&["PASS"]),
        ]
    };
    assert!(matches!(
        judge_in(Layer::Flow, roots(), &snap).verdict,
        Verdict::Reject(_)
    ));

    let p = resolvd();
    let snap = flow_from(&p, "93.184.216.34", 443);
    assert_eq!(judge_in(Layer::Flow, roots(), &snap).verdict, Verdict::Pass);

    let ev = judge_in(
        Layer::Flow,
        vec![rb("exact")
            .int("Local.Integrity.Equal", 8192)
            .actions(&["PASS"])],
        &snap,
    );
    assert_eq!(ev.verdict, Verdict::Pass);
}

#[test]
fn confinement_and_capabilities_shape_the_sandbox() {
    let page = confined_page();
    let snap = flow_from(&page, "10.0.0.20", 445);
    // D4: "LAN only unless the sandbox holds the capability" — the
    // confined program lacks the local-network capability.
    let roots = || {
        vec![
            rb("confined")
                .int("Local.Confinement.Present", 1)
                .actions(&["DROP"])
                .child(
                    rb("may-reach-lan")
                        .s("Local.Capability.Equal", "S-1-15-3-2")
                        .s("DstAddr.Equal", "10.0.0.0/8")
                        .actions(&["PASS"]),
                ),
            rb("unconfined")
                .int("Local.Confinement.Present", 0)
                .actions(&["PASS"]),
        ]
    };
    let ev = judge_in(Layer::Flow, roots(), &snap);
    assert_eq!(ev.verdict, Verdict::Drop);
    assert_eq!(ev.attributed_to.as_str(), "confined");

    // With the capability it is a different program: the exception speaks.
    let mut page = confined_page();
    page.capabilities = vec![sid("S-1-15-3-2")].into();
    let snap = flow_from(&page, "10.0.0.20", 445);
    let ev = judge_in(Layer::Flow, roots(), &snap);
    assert_eq!(ev.verdict, Verdict::Pass);
    assert_eq!(ev.attributed_to.as_str(), "confined/may-reach-lan");

    // The confinement SID itself is a fact; an unconfined token has none,
    // and its capabilities read as absent too.
    let p = resolvd();
    let snap = flow_from(&p, "10.0.0.20", 445);
    let ev = judge_in(Layer::Flow, roots(), &snap);
    assert_eq!(ev.attributed_to.as_str(), "unconfined");
    let ev = judge_in(
        Layer::Flow,
        vec![rb("by-confinement")
            .s("Local.Confinement.Equal", "S-1-15-2-1")
            .actions(&["PASS"])],
        &snap,
    );
    assert!(ev.backstop);
}

#[test]
fn the_process_guid_is_a_fact_for_runtime_authors() {
    let p = resolvd();
    let snap = flow_from(&p, "192.0.2.53", 53);
    // Case-folded at ingestion; the glue emits lowercase.
    let ev = judge_in(
        Layer::Flow,
        vec![rb("this-process")
            .s(
                "Local.Process.Equal",
                "0F3A9C2E-1B4D-4E5F-8A6B-7C8D9E0F1A2B",
            )
            .actions(&["DROP"])],
        &snap,
    );
    assert_eq!(ev.verdict, Verdict::Drop);

    // PCDS's canonical form is braced; parsers accept it.
    let ev = judge_in(
        Layer::Flow,
        vec![rb("this-process")
            .s(
                "Local.Process.Equal",
                "{0f3a9c2e-1b4d-4e5f-8a6b-7c8d9e0f1a2b}",
            )
            .actions(&["DROP"])],
        &snap,
    );
    assert_eq!(ev.verdict, Verdict::Drop);
}

#[test]
fn local_is_a_tristate_plus_one_and_always_present_at_the_flow_layer() {
    let roots = || {
        vec![
            rb("unowned-inbound")
                .list("Local.Equal", &["none", "kernel"])
                .actions(&["REJECT"]),
            rb("multicast")
                .s("Local.Equal", "shared")
                .actions(&["PASS"]),
            rb("programs")
                .s("Local.Equal", "program")
                .actions(&["PASS"]),
        ]
    };
    assert!(matches!(
        judge_in(Layer::Flow, roots(), &flow_kind(EndpointKind::None)).verdict,
        Verdict::Reject(_)
    ));
    assert!(matches!(
        judge_in(Layer::Flow, roots(), &flow_kind(EndpointKind::Kernel)).verdict,
        Verdict::Reject(_)
    ));
    assert_eq!(
        judge_in(Layer::Flow, roots(), &flow_kind(EndpointKind::Shared))
            .attributed_to
            .as_str(),
        "multicast"
    );
    let p = resolvd();
    assert_eq!(
        judge_in(Layer::Flow, roots(), &flow_from(&p, "192.0.2.53", 53))
            .attributed_to
            .as_str(),
        "programs"
    );

    // No principal behind a kernel or none endpoint: every Local.* fact is
    // absent, and conditions over them are false, never errors.
    let ev = judge_in(
        Layer::Flow,
        vec![
            rb("system")
                .s("Local.User.Equal", "SYSTEM")
                .actions(&["PASS"]),
            rb("any-service")
                .int("Local.Service.Present", 1)
                .actions(&["PASS"]),
        ],
        &flow_kind(EndpointKind::Kernel),
    );
    assert!(ev.backstop);
}

#[test]
fn present_looks_through_the_absent_fact_law() {
    let p = resolvd();
    let owned = flow_from(&p, "192.0.2.53", 53);
    let kernel = flow_kind(EndpointKind::Kernel);

    // "Every outbound flow must have an owner" is statable.
    let roots = || {
        vec![
            rb("no-owner")
                .int("Local.User.Present", 0)
                .actions(&["DROP"]),
            rb("owned").int("Local.User.Present", 1).actions(&["PASS"]),
        ]
    };
    assert_eq!(
        judge_in(Layer::Flow, roots(), &owned).verdict,
        Verdict::Pass
    );
    assert_eq!(
        judge_in(Layer::Flow, roots(), &kernel).verdict,
        Verdict::Drop
    );

    // A user program is a program with no service SID.
    let mut user_program = resolvd();
    user_program.groups = vec![sid("S-1-1-0")].into();
    let snap = flow_from(&user_program, "192.0.2.53", 53);
    let ev = judge_in(
        Layer::Flow,
        vec![rb("services-only")
            .int("Local.Service.Present", 0)
            .actions(&["REJECT"])],
        &snap,
    );
    assert!(matches!(ev.verdict, Verdict::Reject(_)));

    // Present is general: any fact, a tag, a counter view.
    let ev = judge(
        vec![rb("portless").int("SrcPort.Present", 0).actions(&["DROP"])],
        &icmp_in("10.0.0.9"),
    );
    assert_eq!(ev.verdict, Verdict::Drop);
    let ev = judge(
        vec![rb("portless").int("SrcPort.Present", 0).actions(&["DROP"])],
        &tcp_in("10.0.0.9", 1234, "10.0.0.5", 22),
    );
    assert!(ev.backstop);
    let ev = judge(
        vec![rb("untagged").int("Tag.seen.Present", 0).actions(&["DROP"])],
        &tcp_in("10.0.0.9", 1234, "10.0.0.5", 22),
    );
    assert_eq!(ev.verdict, Verdict::Drop);

    // Present on a live-time fact never expires a sentence.
    let mut clocked = flow_from(&p, "192.0.2.53", 53);
    clocked.now_secs = Some(1_788_345_000);
    clocked.time = Some(pnp_core::TimeFacts {
        year: 2026,
        month: 9,
        day_of_month: 2,
        day_of_week: 3,
        hour: 10,
        minute: 30,
        second: 0,
    });
    let ev = judge_in(
        Layer::Flow,
        vec![rb("clocked").int("Time.Hour.Present", 1).actions(&["PASS"])],
        &clocked,
    );
    assert_eq!(ev.verdict, Verdict::Pass);
    assert_eq!(ev.expires_at, None);
}

#[test]
fn present_takes_only_zero_or_one() {
    for bad in [2i64, -1] {
        let input = RuleInput {
            name: "r".into(),
            values: vec![("Local.User.Present".into(), pnp_core::RegValue::Int(bad))].into(),
            children: vec![].into(),
        };
        assert!(matches!(
            build_forest(Layer::Flow, &[input]),
            Err(BuildError::BadPattern { .. })
        ));
    }
}

#[test]
fn present_on_a_fact_absent_by_law_refuses_the_generation() {
    // `Related.Present = 0` in the Packet layer would be always true.
    for (layer, key) in [
        (Layer::Packet, "Related.Present"),
        (Layer::Packet, "Local.Present"),
        (Layer::RawPacket, "FlowState.Present"),
        (Layer::RawPacket, "Tag.x.Present"),
        (Layer::Flow, "TcpFlags.Present"),
    ] {
        let input = RuleInput {
            name: "r".into(),
            values: vec![(key.into(), pnp_core::RegValue::Int(0))].into(),
            children: vec![].into(),
        };
        let err = build_forest(layer, &[input]).expect_err("refused");
        assert!(
            matches!(&err, BuildError::PresentNeverAtLayer { key: k, .. } if k.as_str() == key),
            "{layer:?} {key}: {err:?}"
        );
    }

    // Every other operator over the same facts is merely linted.
    let (_, lints) = build(
        Layer::Packet,
        vec![rb("r").s("Local.User.Equal", "SYSTEM").actions(&["PASS"])],
    );
    assert_eq!(lints.len(), 1);
    assert_eq!(lints[0].kind, LintKind::FactNeverPresentAtLayer);
}

#[test]
fn unresolvable_names_are_refused_not_guessed() {
    // A misspelt well-known name in a group fact must not silently become
    // a service SID that matches nothing.
    for (key, val) in [
        ("Local.Group.Equal", "Adminstrators"),
        ("Local.User.Equal", "root"),
        ("Local.User.Equal", "S-1-5-"),
        ("Local.Service.Equal", ""),
        ("Local.Capability.Equal", "internetClient"),
    ] {
        let input = RuleInput {
            name: "r".into(),
            values: vec![(key.into(), pnp_core::RegValue::Str(val.into()))].into(),
            children: vec![].into(),
        };
        assert!(
            matches!(
                build_forest(Layer::Flow, &[input]),
                Err(BuildError::BadPattern { .. })
            ),
            "{key} = {val:?}"
        );
    }
    // Operators the family does not have are refused as such.
    let input = RuleInput {
        name: "r".into(),
        values: vec![("Local.User.GreaterThan".into(), pnp_core::RegValue::Int(1))].into(),
        children: vec![].into(),
    };
    assert!(matches!(
        build_forest(Layer::Flow, &[input]),
        Err(BuildError::BadOperator { .. })
    ));
}

#[test]
fn remote_exists_only_on_loopback() {
    let client = resolvd();
    let server = confined_page();
    // A loopback flow: both ends local, both identities visible to each
    // slot's judgment.
    let mut snap = flow_from(&client, "127.0.0.1", 8080);
    snap.remote = Some(Endpoint {
        kind: EndpointKind::Program,
        principal: Some(&server),
    });
    let roots = || {
        vec![
            rb("only-resolvd-reaches-it")
                .s(
                    "Remote.Process.Equal",
                    "11111111-2222-3333-4444-555555555555",
                )
                .actions(&["DROP"])
                .child(
                    rb("resolvd")
                        .s("Local.Service.Equal", "resolvd")
                        .actions(&["PASS"]),
                ),
            rb("rest").actions(&["PASS"]),
        ]
    };
    let ev = judge_in(Layer::Flow, roots(), &snap);
    assert_eq!(ev.verdict, Verdict::Pass);
    assert_eq!(ev.attributed_to.as_str(), "only-resolvd-reaches-it/resolvd");

    // Off loopback nothing is provable about the other end: Remote is
    // absent, and Remote.Present = 0 says so.
    let off = flow_from(&client, "192.0.2.53", 53);
    let ev = judge_in(
        Layer::Flow,
        vec![
            rb("local-only").int("Remote.Present", 1).actions(&["PASS"]),
            rb("afar").int("Remote.Present", 0).actions(&["REJECT"]),
        ],
        &off,
    );
    assert!(matches!(ev.verdict, Verdict::Reject(_)));
    assert_eq!(ev.attributed_to.as_str(), "afar");
}
