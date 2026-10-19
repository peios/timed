//! The machinery slice (PEI-598, "Machinery Slice Design"): REJECT kinds,
//! tag and stream identities, counter views as compiled slices of a
//! stream, the cross-forest checks, and the effects the glue applies.

mod common;

use common::*;
use pnp_core::{
    check_forests, evaluate, keyspec, name_hash, BuildError, Effect, EvalContext, Layer, NamedHash,
    RejectKind, Verdict,
};

#[test]
fn reject_ties_resolve_to_the_quieter_story() {
    let snap = tcp_in("192.0.2.9", 4444, "10.0.0.5", 80);
    let ev = judge(
        vec![
            rb("a").actions(&["REJECT(Prohibited)"]),
            rb("b").actions(&["REJECT(Refused)"]),
        ],
        &snap,
    );
    assert_eq!(ev.verdict, Verdict::Reject(RejectKind::Refused));
    assert_eq!(ev.attributed_to.as_str(), "b");

    // Prohibited still outranks PASS and loses to DROP.
    let ev = judge(
        vec![
            rb("a").actions(&["PASS"]),
            rb("b").actions(&["REJECT(Prohibited)"]),
        ],
        &snap,
    );
    assert_eq!(ev.verdict, Verdict::Reject(RejectKind::Prohibited));
    let ev = judge(
        vec![
            rb("a").actions(&["DROP"]),
            rb("b").actions(&["REJECT(Prohibited)"]),
        ],
        &snap,
    );
    assert_eq!(ev.verdict, Verdict::Drop);
}

#[test]
fn forest_collects_every_machinery_name_it_mentions() {
    let (forest, _) = build(
        Layer::Packet,
        vec![
            rb("w").actions(&[
                "TAG(seen, Set)",
                "COUNT(hits)",
                "PROMPT(u, TAG(asked, Add))",
                "PASS",
            ]),
            rb("r")
                .int("Tag.seen.Equal", 1)
                .int("Counter.hits(10s, SrcAddr).GreaterThan", 5)
                .int("Counter.hits(10s, SrcAddr).LessThan", 50)
                .int("Counter.hits(1h).GreaterThan", 500)
                .actions(&["DROP"]),
        ],
    );
    let names = |v: &[NamedHash]| -> Vec<String> {
        v.iter().map(|n| n.name.as_str().to_string()).collect()
    };
    // Tags from actions, fallbacks and conditions; deduplicated.
    assert_eq!(names(&forest.tag_names), vec!["seen", "asked"]);
    assert_eq!(forest.tag_names[0].hash, name_hash("seen"));
    assert_eq!(names(&forest.streams), vec!["hits"]);
    // The same (stream, window, keyspec) is one view; a different window
    // is another.
    assert_eq!(forest.views.len(), 2);
    assert_eq!(forest.views[0].window_secs, 10);
    assert_eq!(forest.views[0].keyspec, keyspec::SRC_ADDR);
    assert_eq!(forest.views[1].window_secs, 3600);
    assert_eq!(forest.views[1].keyspec, 0);
    assert_eq!(forest.views[1].hash, name_hash("hits"));
    assert_eq!(forest.view_sites[1].0.as_str(), "r");
    assert_eq!(
        forest.view_sites[1].1.as_str(),
        "Counter.hits(1h).GreaterThan"
    );
}

#[test]
fn a_view_over_a_stream_nobody_writes_is_refused_across_forests() {
    let (reader, _) = build(
        Layer::Packet,
        vec![rb("flooded")
            .int("Counter.synburst(10s, SrcAddr).GreaterThan", 100)
            .actions(&["DROP"])],
    );
    match check_forests(&[&reader]) {
        Err(BuildError::CounterNeverWritten { rule, key }) => {
            assert_eq!(rule.as_str(), "flooded");
            assert_eq!(key.as_str(), "Counter.synburst(10s, SrcAddr).GreaterThan");
        }
        other => panic!("unexpected {other:?}"),
    }
    // Streams are machine-scoped: a writer in the other layer's forest
    // satisfies the read.
    let (writer, _) = build(
        Layer::RawPacket,
        vec![rb("syn")
            .list("TcpFlags.Has", &["SYN"])
            .actions(&["COUNT(synburst)", "PASS"])],
    );
    check_forests(&[&reader, &writer]).expect("writer in another forest suffices");
    // Write-only streams are legal: audit is a consumer.
    check_forests(&[&writer]).expect("write-only stream is fine");
}

#[test]
fn hash_collisions_among_distinct_names_are_refused() {
    // A real FNV collision is not constructible by hand; the check is
    // over the collected name set, so craft one.
    let (mut forest, _) = build(
        Layer::Packet,
        vec![rb("w").actions(&["TAG(a, Set)", "COUNT(s)", "PASS"])],
    );
    forest
        .tag_names
        .push(NamedHash {
            name: "b".into(),
            hash: forest.tag_names[0].hash,
        })
        .unwrap();
    match check_forests(&[&forest]) {
        Err(BuildError::TagHashCollision { a, b }) => {
            assert_eq!((a.as_str(), b.as_str()), ("a", "b"));
        }
        other => panic!("unexpected {other:?}"),
    }
    forest.tag_names.pop();
    forest
        .streams
        .push(NamedHash {
            name: "t".into(),
            hash: forest.streams[0].hash,
        })
        .unwrap();
    assert!(matches!(
        check_forests(&[&forest]),
        Err(BuildError::StreamHashCollision { .. })
    ));
}

#[test]
fn effects_carry_store_identities_and_resolved_amounts() {
    let ev = judge(
        vec![rb("w").actions(&[
            "TAG(seen, Add, 3)",
            "COUNT(bytes, Length)",
            "COUNT(hits)",
            "PASS",
        ])],
        &tcp_in("10.0.0.7", 5555, "10.0.0.5", 22),
    );
    let mut saw_tag = false;
    let mut amounts = Vec::new();
    for e in ev.effects.iter() {
        match e {
            Effect::Tag { name, hash, op } => {
                assert_eq!(name.as_str(), "seen");
                assert_eq!(*hash, name_hash("seen"));
                assert_eq!(*op, pnp_core::TagOp::Add(3));
                saw_tag = true;
            }
            Effect::Count { name, hash, amount } => {
                assert_eq!(*hash, name_hash(name.as_str()));
                amounts.push((name.as_str().to_string(), *amount));
            }
            _ => {}
        }
    }
    assert!(saw_tag);
    // tcp_in() packets are 60 bytes; a literal stays literal.
    assert_eq!(
        amounts,
        vec![("bytes".to_string(), 60), ("hits".to_string(), 1)]
    );

    // No length fact: the Length amount resolves to 0 (glue counts the
    // no-op).
    let mut snap = tcp_in("10.0.0.7", 5555, "10.0.0.5", 22);
    snap.length = None;
    let ev = judge(
        vec![rb("w").actions(&["COUNT(bytes, Length)", "PASS"])],
        &snap,
    );
    assert!(ev
        .effects
        .iter()
        .any(|e| matches!(e, Effect::Count { amount: 0, .. })));
}

#[test]
fn this_packets_count_lands_after_its_own_reads() {
    // Temporal feedback: the read sees evaluation-start state; the COUNT
    // this evaluation emits is applied by the glue afterwards, so the
    // next packet sees it — never this one.
    let roots = || {
        vec![
            rb("count").actions(&["COUNT(x)", "PASS"]),
            rb("limit")
                .int("Counter.x.GreaterThan", 0)
                .actions(&["DROP"]),
        ]
    };
    let ev = judge(roots(), &tcp_in("10.0.0.7", 5555, "10.0.0.5", 22));
    assert_eq!(ev.verdict, Verdict::Pass);
    assert!(ev.effects.iter().any(|e| matches!(e, Effect::Count { .. })));

    let mut later = tcp_in("10.0.0.7", 5555, "10.0.0.5", 22);
    later.counter_views.push((0, 1)).unwrap();
    let ev = judge(roots(), &later);
    assert_eq!(ev.verdict, Verdict::Drop);
    assert_eq!(ev.attributed_to.as_str(), "limit");
}

#[test]
fn reporting_level_is_one_when_absent_so_everything_fires() {
    assert_eq!(EvalContext::default().reporting_level, 1);
    let (forest, _) = build(Layer::Packet, vec![rb("r").actions(&["REPORT(1)", "PASS"])]);
    let ev = evaluate(
        &forest,
        &tcp_in("10.0.0.7", 5555, "10.0.0.5", 22),
        &EvalContext::default(),
    )
    .unwrap();
    assert_eq!(reports(&ev), vec![("r".to_string(), 1)]);
}
