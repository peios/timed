//! The Flow layer (PEI-598, "Flow Layer Design (rung 2)"): the flow fact
//! vocabulary, sentence expiry from consulted live-time conditions, the
//! layer lints, and the downward-tag-read refusal.

mod common;

use common::*;
use pnp_core::{
    build_forest, check_forests, BuildError, Direction, FlowState, Layer, LintKind, RuleInput,
    Snapshot, TimeFacts, Verdict,
};

/// 2026-09-02 (a Wednesday) 10:30:00 UTC, as epoch seconds and as facts.
const NOW: i64 = 1_788_345_000;
const MIDNIGHT: i64 = 1_788_307_200;

fn clock(hour: i64, minute: i64, second: i64) -> TimeFacts {
    TimeFacts {
        year: 2026,
        month: 9,
        day_of_month: 2,
        day_of_week: 3,
        hour,
        minute,
        second,
    }
}

/// An outbound TCP flow's first packet as the Flow layer sees it: flow
/// facts only, the clock, and the flow's start (= now).
fn flow_out(dst: &str, dport: u16) -> Snapshot<'static> {
    Snapshot {
        direction: Some(Direction::Out),
        interface: Some("eth0".into()),
        src_addr: Some("10.0.0.5".parse().unwrap()),
        dst_addr: Some(dst.parse().unwrap()),
        protocol: Some(6),
        src_port: Some(40000),
        dst_port: Some(dport),
        time: Some(clock(10, 30, 0)),
        now_secs: Some(NOW),
        related: Some(false),
        start: Some(clock(10, 30, 0)),
        ..Snapshot::default()
    }
}

#[test]
fn flow_layer_judges_flow_facts() {
    let snap = flow_out("192.0.2.9", 443);
    let ev = judge_in(
        Layer::Flow,
        vec![
            rb("out").s("Direction.Equal", "out").actions(&["PASS"]),
            rb("no-related").int("Related.Equal", 1).actions(&["DROP"]),
        ],
        &snap,
    );
    assert_eq!(ev.verdict, Verdict::Pass);
    assert_eq!(ev.attributed_to.as_str(), "out");
    assert_eq!(ev.expires_at, None, "no live-time condition consulted");

    let mut related = flow_out("192.0.2.9", 443);
    related.related = Some(true);
    let ev = judge_in(
        Layer::Flow,
        vec![
            rb("out").s("Direction.Equal", "out").actions(&["PASS"]),
            rb("no-related").int("Related.Equal", 1).actions(&["DROP"]),
        ],
        &related,
    );
    assert_eq!(ev.verdict, Verdict::Drop);
}

#[test]
fn a_consulted_true_time_condition_expires_at_its_next_flip() {
    // Working hours: true at 10:30, flips false at 18:00.
    let ev = judge_in(
        Layer::Flow,
        vec![rb("hours").s("Time.Hour.Equal", "9-17").actions(&["PASS"])],
        &flow_out("192.0.2.9", 443),
    );
    assert_eq!(ev.verdict, Verdict::Pass);
    assert_eq!(ev.expires_at, Some(MIDNIGHT + 18 * 3600));
}

#[test]
fn a_consulted_false_time_condition_still_expires() {
    // A higher-precedence rule that missed only on the clock may match
    // later: the sentence must be re-judged when it would.
    let ev = judge_in(
        Layer::Flow,
        vec![
            rb("curfew")
                .int("Time.Hour.Equal", 22)
                .int("Priority", 10)
                .actions(&["DROP"]),
            rb("out").s("Direction.Equal", "out").actions(&["PASS"]),
        ],
        &flow_out("192.0.2.9", 443),
    );
    assert_eq!(ev.verdict, Verdict::Pass);
    assert_eq!(ev.expires_at, Some(MIDNIGHT + 22 * 3600));
}

#[test]
fn time_conditions_are_consulted_last() {
    // The address condition fails first, so the clock is never consulted
    // and this flow's sentence never expires because of this rule.
    let ev = judge_in(
        Layer::Flow,
        vec![
            rb("curfew-for-one-host")
                .s("DstAddr.Equal", "192.0.2.99")
                .int("Time.Hour.Equal", 22)
                .actions(&["DROP"]),
            rb("out").s("Direction.Equal", "out").actions(&["PASS"]),
        ],
        &flow_out("192.0.2.9", 443),
    );
    assert_eq!(ev.verdict, Verdict::Pass);
    assert_eq!(ev.expires_at, None);

    // Value order in the registry does not matter: the clock key written
    // first is still evaluated last.
    let ev = judge_in(
        Layer::Flow,
        vec![
            rb("curfew-for-one-host")
                .int("Time.Hour.Equal", 22)
                .s("DstAddr.Equal", "192.0.2.99")
                .actions(&["DROP"]),
            rb("out").s("Direction.Equal", "out").actions(&["PASS"]),
        ],
        &flow_out("192.0.2.9", 443),
    );
    assert_eq!(ev.expires_at, None);
}

#[test]
fn start_facts_never_expire_a_sentence() {
    // "No new connections after 22:00, existing ones may finish."
    let ev = judge_in(
        Layer::Flow,
        vec![
            rb("no-new-late")
                .s("Start.Hour.Equal", "22-23")
                .int("Priority", 10)
                .actions(&["DROP"]),
            rb("out").s("Direction.Equal", "out").actions(&["PASS"]),
        ],
        &flow_out("192.0.2.9", 443),
    );
    assert_eq!(ev.verdict, Verdict::Pass);
    assert_eq!(ev.expires_at, None);

    let mut late = flow_out("192.0.2.9", 443);
    late.start = Some(clock(22, 5, 0));
    let ev = judge_in(
        Layer::Flow,
        vec![
            rb("no-new-late")
                .s("Start.Hour.Equal", "22-23")
                .int("Priority", 10)
                .actions(&["DROP"]),
            rb("out").s("Direction.Equal", "out").actions(&["PASS"]),
        ],
        &late,
    );
    assert_eq!(ev.verdict, Verdict::Drop);
    assert_eq!(ev.expires_at, None);
}

#[test]
fn flip_moments_are_exact_for_bounded_cycles_and_daily_otherwise() {
    let snap = flow_out("192.0.2.9", 443);
    let expiry = |key: &str, value: &str| {
        judge_in(
            Layer::Flow,
            vec![rb("r").s(key, value).actions(&["PASS"])],
            &snap,
        )
        .expires_at
    };
    // Minute 30 is true now; false at 10:31.
    assert_eq!(expiry("Time.Minute.Equal", "30"), Some(NOW + 60));
    // Second 0 is true now; false one second later.
    assert_eq!(expiry("Time.Second.Equal", "0"), Some(NOW + 1));
    // Weekdays, on a Wednesday: false at Saturday midnight.
    assert_eq!(
        expiry("Time.DayOfWeek.Equal", "1-5"),
        Some(MIDNIGHT + 3 * 86_400)
    );
    // Sunday only, on a Wednesday: true at Sunday midnight.
    assert_eq!(
        expiry("Time.DayOfWeek.Equal", "7"),
        Some(MIDNIGHT + 4 * 86_400)
    );
    // Calendar facts: conservatively, next midnight.
    assert_eq!(
        expiry("Time.DayOfMonth.Equal", "2"),
        Some(MIDNIGHT + 86_400)
    );
    assert_eq!(expiry("Time.Month.Equal", "9"), Some(MIDNIGHT + 86_400));
    assert_eq!(expiry("Time.Year.Equal", "2026"), Some(MIDNIGHT + 86_400));
    // Constant over its whole cycle: never flips.
    assert_eq!(expiry("Time.Hour.LessThan", "24"), None);
    assert_eq!(expiry("Time.Hour.Equal", "0-23"), None);
    // Operators other than Equal flip too.
    assert_eq!(
        expiry("Time.Hour.GreaterThan", "17"),
        Some(MIDNIGHT + 18 * 3600)
    );
    assert_eq!(
        expiry("Time.Hour.LessThan", "10"),
        Some(MIDNIGHT + 24 * 3600)
    );
}

#[test]
fn the_earliest_consulted_flip_wins() {
    let ev = judge_in(
        Layer::Flow,
        vec![
            rb("hours").s("Time.Hour.Equal", "9-17").actions(&["PASS"]),
            rb("minute").int("Time.Minute.Equal", 30).actions(&["PASS"]),
        ],
        &flow_out("192.0.2.9", 443),
    );
    assert_eq!(ev.expires_at, Some(NOW + 60));
}

#[test]
fn a_snapshot_without_a_clock_never_expires() {
    let mut snap = flow_out("192.0.2.9", 443);
    snap.time = None;
    snap.now_secs = None;
    let ev = judge_in(
        Layer::Flow,
        vec![
            rb("hours").s("Time.Hour.Equal", "9-17").actions(&["PASS"]),
            rb("out").s("Direction.Equal", "out").actions(&["PASS"]),
        ],
        &snap,
    );
    // Absent-fact law: the time condition is false; nothing to expire on.
    assert_eq!(ev.attributed_to.as_str(), "out");
    assert_eq!(ev.expires_at, None);
}

#[test]
fn per_packet_layers_do_not_expire_on_time_but_still_match_it() {
    // The trace is computed for every layer (it is cheap and harmless);
    // only the Flow seat acts on it. Packet-layer time rules still work.
    let mut snap = tcp_in("192.0.2.9", 4444, "10.0.0.5", 22);
    snap.time = Some(clock(10, 30, 0));
    snap.now_secs = Some(NOW);
    let ev = judge(
        vec![rb("hours").s("Time.Hour.Equal", "9-17").actions(&["PASS"])],
        &snap,
    );
    assert_eq!(ev.verdict, Verdict::Pass);
    assert_eq!(ev.expires_at, Some(MIDNIGHT + 18 * 3600));
}

fn lint_keys(layer: Layer, rule: Rb) -> Vec<String> {
    let (_, lints) = build(layer, vec![rule]);
    lints
        .iter()
        .map(|l| {
            assert_eq!(l.kind, LintKind::FactNeverPresentAtLayer);
            l.key.as_str().to_string()
        })
        .collect()
}

#[test]
fn flow_layer_lints_per_packet_facts() {
    let keys = lint_keys(
        Layer::Flow,
        rb("r")
            .int("Length.GreaterThan", 100)
            .list("TcpFlags.Has", &["SYN"])
            .int("Fragment.Equal", 1)
            .int("Ttl.LessThan", 5)
            .int("Dscp.Equal", 46)
            .s("EtherType.Equal", "ipv4")
            .s("FlowState.Equal", "new")
            .s("DstMac.Equal", "52:54:00:12:34:56")
            .s("SrcMac.Equal", "52:54:00:12:34:56")
            .int("Vlan.Equal", 100)
            .s("Interface.Equal", "eth0")
            .int("Related.Equal", 1)
            .int("Start.Hour.Equal", 9)
            .actions(&["PASS"]),
    );
    assert_eq!(
        keys,
        vec![
            "Length.GreaterThan",
            "TcpFlags.Has",
            "Fragment.Equal",
            "Ttl.LessThan",
            "Dscp.Equal",
            "EtherType.Equal",
            "FlowState.Equal",
            "DstMac.Equal",
        ]
    );
}

#[test]
fn per_packet_layers_lint_flow_only_facts() {
    let keys = lint_keys(
        Layer::Packet,
        rb("r")
            .int("Related.Equal", 1)
            .int("Start.Hour.Equal", 9)
            .int("Time.Hour.Equal", 9)
            .s("FlowState.Equal", "new")
            .actions(&["PASS"]),
    );
    assert_eq!(keys, vec!["Related.Equal", "Start.Hour.Equal"]);

    let keys = lint_keys(
        Layer::RawPacket,
        rb("r")
            .int("Related.Equal", 1)
            .int("Start.Minute.Equal", 9)
            .s("FlowState.Equal", "new")
            .int("Tag.x.Equal", 1)
            .actions(&["PASS"]),
    );
    assert_eq!(
        keys,
        vec![
            "Related.Equal",
            "Start.Minute.Equal",
            "FlowState.Equal",
            "Tag.x.Equal"
        ]
    );
}

fn forest(layer: Layer, roots: Vec<Rb>) -> pnp_core::Forest {
    let inputs: Vec<RuleInput> = roots.into_iter().map(|r| r.0).collect();
    build_forest(layer, &inputs).expect("forest builds").forest
}

#[test]
fn reading_a_tag_a_higher_layer_writes_is_refused() {
    // Tags flow strictly upward: Packet may not read what Flow writes.
    let packet = forest(
        Layer::Packet,
        vec![rb("r").int("Tag.admitted.Equal", 1).actions(&["PASS"])],
    );
    let flow = forest(
        Layer::Flow,
        vec![rb("w").actions(&["TAG(admitted, Set)", "PASS"])],
    );
    match check_forests(&[&packet, &flow]) {
        Err(BuildError::TagDownwardRead { rule, name }) => {
            assert_eq!(rule.as_str(), "r");
            assert_eq!(name.as_str(), "admitted");
        }
        other => panic!("expected a downward-read refusal, got {other:?}"),
    }

    // A fallback TAG is still a write.
    let flow = forest(
        Layer::Flow,
        vec![rb("w").actions(&["PROMPT(u, TAG(admitted, Set))", "PASS"])],
    );
    assert!(matches!(
        check_forests(&[&packet, &flow]),
        Err(BuildError::TagDownwardRead { .. })
    ));

    // RawPacket reading a Packet-written tag is a downward read too (and
    // was already a lint; now a refusal once the writer exists).
    let raw = forest(
        Layer::RawPacket,
        vec![rb("r").int("Tag.seen.Equal", 1).actions(&["PASS"])],
    );
    let packet_w = forest(
        Layer::Packet,
        vec![rb("w").actions(&["TAG(seen, Set)", "PASS"])],
    );
    assert!(matches!(
        check_forests(&[&packet_w, &raw]),
        Err(BuildError::TagDownwardRead { .. })
    ));
}

#[test]
fn upward_and_lateral_tag_reads_are_fine() {
    // Flow reads what Packet writes: upward.
    let packet = forest(
        Layer::Packet,
        vec![rb("w").actions(&["TAG(seen, Add)", "PASS"])],
    );
    let flow = forest(
        Layer::Flow,
        vec![rb("r").int("Tag.seen.GreaterThan", 3).actions(&["DROP"])],
    );
    assert!(check_forests(&[&packet, &flow]).is_ok());

    // Packet reads what Packet writes: lateral within one layer, the
    // temporal-feedback pattern.
    let packet = forest(
        Layer::Packet,
        vec![
            rb("w").actions(&["TAG(seen, Add)", "PASS"]),
            rb("r").int("Tag.seen.GreaterThan", 3).actions(&["DROP"]),
        ],
    );
    assert!(check_forests(&[&packet]).is_ok());

    // Three forests together: the stream/dead-read checks still span all.
    let raw = forest(
        Layer::RawPacket,
        vec![rb("c").actions(&["COUNT(frames)", "PASS"])],
    );
    let flow = forest(
        Layer::Flow,
        vec![rb("r")
            .int("Counter.frames(10s).GreaterThan", 100)
            .actions(&["DROP"])],
    );
    assert!(check_forests(&[&packet, &raw, &flow]).is_ok());
    assert!(matches!(
        check_forests(&[&packet, &flow]),
        Err(BuildError::CounterNeverWritten { .. })
    ));
}

#[test]
fn flow_layer_name_and_height() {
    assert_eq!(Layer::Flow.as_str(), "Flow");
    assert!(Layer::Flow.height() > Layer::Packet.height());
    assert!(Layer::Packet.height() > Layer::RawPacket.height());
    // FlowState is a Packet fact, not a Flow one; the sentinel value still
    // parses for Packet rules.
    let snap = tcp_in("192.0.2.9", 4444, "10.0.0.5", 22);
    assert_eq!(snap.flow_state, Some(FlowState::New));
}
