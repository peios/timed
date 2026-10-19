//! Shared helpers for the law suite: terse builders for registry-shaped
//! rule input and fact snapshots.
// Each test binary compiles this module separately and uses a subset.
#![allow(dead_code)]

use pnp_core::{
    build_forest, evaluate, BuildOutput, Direction, EvalContext, Evaluation, FlowState, Forest,
    Layer, LintWarning, RegValue, RuleInput, Snapshot,
};

/// Terse `RuleInput` builder.
pub struct Rb(pub RuleInput);

pub fn rb(name: &str) -> Rb {
    Rb(RuleInput {
        name: name.into(),
        values: Vec::new().into(),
        children: Vec::new().into(),
    })
}

impl Rb {
    pub fn val(mut self, key: &str, value: RegValue) -> Self {
        self.0.values.push((key.into(), value)).unwrap();
        self
    }

    pub fn int(self, key: &str, v: i64) -> Self {
        self.val(key, RegValue::Int(v))
    }

    pub fn s(self, key: &str, v: &str) -> Self {
        self.val(key, RegValue::Str(v.into()))
    }

    pub fn list(self, key: &str, items: &[&str]) -> Self {
        let vals: Vec<RegValue> = items.iter().map(|s| RegValue::Str((*s).into())).collect();
        self.val(key, RegValue::List(vals.into()))
    }

    pub fn actions(self, items: &[&str]) -> Self {
        self.list("Actions", items)
    }

    pub fn child(mut self, child: Rb) -> Self {
        self.0.children.push(child.0).unwrap();
        self
    }
}

/// Builds a forest (panicking on build errors) and returns it with lints.
pub fn build(layer: Layer, roots: Vec<Rb>) -> (Forest, Vec<LintWarning>) {
    let inputs: Vec<RuleInput> = roots.into_iter().map(|r| r.0).collect();
    let BuildOutput { forest, lints } = build_forest(layer, &inputs).expect("forest builds");
    (forest, lints.into_iter().collect())
}

/// Builds and evaluates in one step with the default context.
pub fn judge(roots: Vec<Rb>, snap: &Snapshot) -> Evaluation {
    judge_in(Layer::Packet, roots, snap)
}

/// `judge` at a chosen layer.
pub fn judge_in(layer: Layer, roots: Vec<Rb>, snap: &Snapshot) -> Evaluation {
    let (forest, _) = build(layer, roots);
    evaluate(&forest, snap, &EvalContext::default()).expect("evaluation succeeds")
}

/// An inbound TCP packet at the Packet layer's proper seat.
pub fn tcp_in(src: &str, sport: u16, dst: &str, dport: u16) -> Snapshot<'static> {
    Snapshot {
        direction: Some(Direction::In),
        interface: Some("eth0".into()),
        ether_type: Some(0x0800),
        src_addr: Some(src.parse().unwrap()),
        dst_addr: Some(dst.parse().unwrap()),
        protocol: Some(6),
        ttl: Some(64),
        src_port: Some(sport),
        dst_port: Some(dport),
        tcp_flags: Some(pnp_core::tcp_flags::SYN),
        length: Some(60),
        flow_state: Some(FlowState::New),
        ..Snapshot::default()
    }
}

/// An outbound TCP packet.
pub fn tcp_out(dst: &str, dport: u16) -> Snapshot<'static> {
    let mut s = tcp_in("10.0.0.5", 40000, dst, dport);
    s.direction = Some(Direction::Out);
    s
}

/// An inbound ARP frame: no IP facts, no flow state.
pub fn arp_in() -> Snapshot<'static> {
    Snapshot {
        direction: Some(Direction::In),
        interface: Some("eth0".into()),
        ether_type: Some(0x0806),
        src_mac: Some([0x52, 0x54, 0, 0x12, 0x34, 0x56]),
        dst_mac: Some([0xff; 6]),
        length: Some(42),
        ..Snapshot::default()
    }
}

/// An inbound ICMP echo: no ports.
pub fn icmp_in(src: &str) -> Snapshot<'static> {
    Snapshot {
        direction: Some(Direction::In),
        interface: Some("eth0".into()),
        ether_type: Some(0x0800),
        src_addr: Some(src.parse().unwrap()),
        dst_addr: Some("10.0.0.5".parse().unwrap()),
        protocol: Some(1),
        icmp_type: Some(8),
        icmp_code: Some(0),
        length: Some(84),
        flow_state: Some(FlowState::New),
        ..Snapshot::default()
    }
}

/// Names of rules that emitted a Report effect, with levels.
pub fn reports(ev: &Evaluation) -> Vec<(String, u8)> {
    ev.effects
        .iter()
        .filter_map(|e| match e {
            pnp_core::Effect::Report { rule, level } => Some((rule.as_str().to_string(), *level)),
            _ => None,
        })
        .collect()
}

/// Names of tags written.
pub fn tags(ev: &Evaluation) -> Vec<String> {
    ev.effects
        .iter()
        .filter_map(|e| match e {
            pnp_core::Effect::Tag { name, .. } => Some(name.as_str().to_string()),
            _ => None,
        })
        .collect()
}

/// Names of counters fed.
pub fn counts(ev: &Evaluation) -> Vec<String> {
    ev.effects
        .iter()
        .filter_map(|e| match e {
            pnp_core::Effect::Count { name, .. } => Some(name.as_str().to_string()),
            _ => None,
        })
        .collect()
}

/// (rule, handler) of prompts issued.
pub fn prompts(ev: &Evaluation) -> Vec<(String, String)> {
    ev.effects
        .iter()
        .filter_map(|e| match e {
            pnp_core::Effect::PromptIssued { rule, handler } => {
                Some((rule.as_str().to_string(), handler.as_str().to_string()))
            }
            _ => None,
        })
        .collect()
}
