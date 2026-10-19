//! The immutable fact snapshot one traversal is judged against.
//!
//! Ratified law: matching reads a snapshot taken before evaluation; nothing
//! written during an evaluation is visible to that same evaluation's
//! matching. A fact the packet does not have is simply `None`, and the
//! absent-fact law makes every condition over it false.
//!
//! The glue that builds a snapshot is responsible for the visibility laws:
//! a RawPacket-seat snapshot must carry no `flow_state` and no `tags` (they
//! do not exist there / would be downward reads); a Packet-seat snapshot
//! carries whatever conntrack and prior packets attached. Machinery facts
//! (flow tags, counter views) are resolved by the glue against the forest
//! being evaluated: tags by name hash, counter views by their index in the
//! forest's view table.

use core::fmt;
use core::net::IpAddr;

use crate::pnp_core::hash::name_hash;
use crate::pnp_core::pkm_alloc::{AllocError, String as PkmString, Vec as PkmVec};
use crate::pnp_core::sid::Sid;

/// Traversal direction, as attached by the standing seat.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Direction {
    /// Entering the machine.
    In,
    /// Leaving the machine.
    Out,
}

impl Direction {
    /// Canonical lowercase name, as written in rule values.
    pub fn as_str(self) -> &'static str {
        match self {
            Direction::In => "in",
            Direction::Out => "out",
        }
    }
}

/// Conntrack's flow classification, as attached by machinery below the rule.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FlowState {
    /// First packet of a flow conntrack will track.
    New,
    /// Packet of a flow with traffic in both directions.
    Established,
    /// Packet of a flow related to an established one (e.g. ICMP errors).
    Related,
    /// Packet conntrack could not associate coherently.
    Invalid,
    /// Packet conntrack does not track at all.
    Untracked,
}

impl FlowState {
    /// Canonical lowercase name, as written in rule values.
    pub fn as_str(self) -> &'static str {
        match self {
            FlowState::New => "new",
            FlowState::Established => "established",
            FlowState::Related => "related",
            FlowState::Invalid => "invalid",
            FlowState::Untracked => "untracked",
        }
    }
}

/// TCP flag bits for the `TcpFlags` fact (`Has` / `Hasnt` operators).
pub mod tcp_flags {
    /// FIN bit.
    pub const FIN: u8 = 0x01;
    /// SYN bit.
    pub const SYN: u8 = 0x02;
    /// RST bit.
    pub const RST: u8 = 0x04;
    /// PSH bit.
    pub const PSH: u8 = 0x08;
    /// ACK bit.
    pub const ACK: u8 = 0x10;
    /// URG bit.
    pub const URG: u8 = 0x20;
    /// ECE bit.
    pub const ECE: u8 = 0x40;
    /// CWR bit.
    pub const CWR: u8 = 0x80;

    /// Parses one flag name (case-insensitive ASCII).
    pub fn from_name(name: &str) -> Option<u8> {
        let mut buf = [0u8; 3];
        if name.len() != 3 {
            return None;
        }
        for (i, b) in name.bytes().enumerate() {
            buf[i] = b.to_ascii_uppercase();
        }
        match &buf {
            b"FIN" => Some(FIN),
            b"SYN" => Some(SYN),
            b"RST" => Some(RST),
            b"PSH" => Some(PSH),
            b"ACK" => Some(ACK),
            b"URG" => Some(URG),
            b"ECE" => Some(ECE),
            b"CWR" => Some(CWR),
            _ => None,
        }
    }
}

/// What stands at one local end of a flow — the `Local` fact, and on a
/// loopback flow the `Remote` fact for the other end. Classified by
/// whether anyone answers, not by whether a socket structure exists.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EndpointKind {
    /// A program's socket: the glue found a stamped socket that sends or
    /// will receive this flow. The identity facts are present.
    Program,
    /// The stack itself: kernel-originated traffic outbound (resets, ICMP
    /// errors, IGMP), and inbound protocols the stack consumes without a
    /// program (ICMP, neighbour discovery, tunnel outers).
    Kernel,
    /// Many receivers at once: inbound multicast or broadcast, delivered
    /// to every socket bound to the port. One sentence, no single owner;
    /// the per-program question is answered at the join, not here.
    Shared,
    /// Nobody: inbound to a port nothing listens on, which the stack will
    /// answer with a reset or an unreachable.
    None,
}

impl EndpointKind {
    /// Canonical lowercase name, as written in rule values.
    pub fn as_str(self) -> &'static str {
        match self {
            EndpointKind::Program => "program",
            EndpointKind::Kernel => "kernel",
            EndpointKind::Shared => "shared",
            EndpointKind::None => "none",
        }
    }
}

/// The principal behind a program endpoint, as read from the socket's
/// governing token. A trait rather than a copy: a token may carry up to
/// 1024 groups and the flow judgment runs in softirq context, so the
/// snapshot borrows a view the glue implements over the token and asks
/// membership questions of it instead of materialising the lists.
pub trait Principal {
    /// The token's user SID.
    fn user(&self) -> &Sid;
    /// Whether `sid` is an *enabled* group of the token. Deny-only groups
    /// are invisible to policy.
    fn is_member(&self, sid: &Sid) -> bool;
    /// The token's integrity level (0 Untrusted .. 16384 System).
    fn integrity(&self) -> i64;
    /// The confinement SID, when the token is confined.
    fn confinement(&self) -> Option<&Sid>;
    /// Whether `sid` is among the token's confinement capabilities.
    fn has_capability(&self, sid: &Sid) -> bool;
    /// The per-service SID (`S-1-5-80-…`) among the enabled groups, when
    /// the principal is a service.
    fn service(&self) -> Option<&Sid>;
    /// The process GUID, lowercase hyphenated text.
    fn process(&self) -> &str;
}

/// One end of a flow: what stands there and, for a program, who.
#[derive(Clone, Copy)]
pub struct Endpoint<'a> {
    /// What answers at this end.
    pub kind: EndpointKind,
    /// The principal, present iff `kind` is `Program`.
    pub principal: Option<&'a dyn Principal>,
}

impl fmt::Debug for Endpoint<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut d = f.debug_struct("Endpoint");
        d.field("kind", &self.kind);
        match self.principal {
            Some(p) => d.field("user", p.user()).field("process", &p.process()),
            None => d.field("principal", &"none"),
        };
        d.finish()
    }
}

/// A principal that owns its lists: the cargo suite's shape, and any
/// caller that already holds the identity as values.
#[derive(Debug, Default)]
pub struct OwnedPrincipal {
    /// The user SID.
    pub user: Sid,
    /// Enabled group SIDs (the service SID among them, if any).
    pub groups: PkmVec<Sid>,
    /// Integrity level.
    pub integrity: i64,
    /// Confinement SID, when confined.
    pub confinement: Option<Sid>,
    /// Confinement capabilities.
    pub capabilities: PkmVec<Sid>,
    /// Process GUID text.
    pub process: PkmString,
}

impl Principal for OwnedPrincipal {
    fn user(&self) -> &Sid {
        &self.user
    }
    fn is_member(&self, sid: &Sid) -> bool {
        self.groups.iter().any(|g| g == sid)
    }
    fn integrity(&self) -> i64 {
        self.integrity
    }
    fn confinement(&self) -> Option<&Sid> {
        self.confinement.as_ref()
    }
    fn has_capability(&self, sid: &Sid) -> bool {
        self.capabilities.iter().any(|c| c == sid)
    }
    fn service(&self) -> Option<&Sid> {
        self.groups.iter().find(|g| g.is_service())
    }
    fn process(&self) -> &str {
        self.process.as_str()
    }
}

/// Wall-clock facts, attached by clock machinery.
///
/// `day_of_week` is ISO: 1 = Monday .. 7 = Sunday. Timezone semantics are a
/// glue concern (unminted; the glue decides what clock it snapshots).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TimeFacts {
    /// Calendar year.
    pub year: i64,
    /// Month, 1..=12.
    pub month: i64,
    /// Day of month, 1..=31.
    pub day_of_month: i64,
    /// ISO day of week, 1 = Monday .. 7 = Sunday.
    pub day_of_week: i64,
    /// Hour, 0..=23.
    pub hour: i64,
    /// Minute, 0..=59.
    pub minute: i64,
    /// Second, 0..=59.
    pub second: i64,
}

/// The facts of one traversal at its standing seat. `None` = the packet does
/// not have the fact (absent-fact law: conditions over it are false).
///
/// The lifetime is the identity facts': a Flow-layer snapshot borrows the
/// principal views the glue built over the endpoints' tokens.
#[derive(Debug, Default)]
pub struct Snapshot<'a> {
    /// Traversal direction.
    pub direction: Option<Direction>,
    /// Interface name at the standing seat.
    pub interface: Option<PkmString>,
    /// Ethertype (host byte order).
    pub ether_type: Option<u16>,
    /// Source MAC, when the frame has one.
    pub src_mac: Option<[u8; 6]>,
    /// Destination MAC, when the frame has one.
    pub dst_mac: Option<[u8; 6]>,
    /// VLAN id, when tagged.
    pub vlan: Option<u16>,
    /// Source IP address.
    pub src_addr: Option<IpAddr>,
    /// Destination IP address.
    pub dst_addr: Option<IpAddr>,
    /// IP protocol number.
    pub protocol: Option<u8>,
    /// TTL (v4) / hop limit (v6).
    pub ttl: Option<u8>,
    /// DSCP field.
    pub dscp: Option<u8>,
    /// Whether this is a fragment (can only be true at seats before defrag).
    pub fragment: Option<bool>,
    /// L4 source port.
    pub src_port: Option<u16>,
    /// L4 destination port.
    pub dst_port: Option<u16>,
    /// TCP flag bits.
    pub tcp_flags: Option<u8>,
    /// ICMP type.
    pub icmp_type: Option<u8>,
    /// ICMP code.
    pub icmp_code: Option<u8>,
    /// Packet length as seen at the seat (stack view, not wire view).
    pub length: Option<u32>,
    /// Conntrack flow classification. Absent at the RawPacket seat.
    pub flow_state: Option<FlowState>,
    /// Wall-clock facts.
    pub time: Option<TimeFacts>,
    /// The wall clock as epoch seconds (UTC), alongside `time`; what
    /// live-time conditions compute their next flip from.
    pub now_secs: Option<i64>,
    /// Whether the flow was expected by another flow (conntrack's
    /// "related"). Flow-layer snapshots only.
    pub related: Option<bool>,
    /// The flow's start time. Flow-layer snapshots only; fixed for the
    /// flow's life, so conditions over it never expire a sentence.
    pub start: Option<TimeFacts>,
    /// The local end of the flow: the `Local` fact and, for a program,
    /// `Local.*`. Flow-layer snapshots only; always present there, and
    /// fixed for the flow's life.
    pub local: Option<Endpoint<'a>>,
    /// The other end, when it is local too (a loopback flow): `Remote`
    /// and `Remote.*`. Absent off loopback — nothing is provable there yet.
    pub remote: Option<Endpoint<'a>>,
    /// Flow tags visible to this evaluation as `(name hash, value)`
    /// (written by prior packets / layers below, per the visibility laws —
    /// the glue enforces those).
    pub tags: PkmVec<(u64, u64)>,
    /// Resolved counter views for this packet: `(view index, value)`. A
    /// view whose key facts the packet lacks is simply absent.
    pub counter_views: PkmVec<(u32, u64)>,
    /// Interface-layer snapshots only: `Interface.Kind`.
    pub interface_kind: Option<PkmString>,
    /// Interface-layer snapshots only: `Interface.Id`, the stable id.
    pub interface_id: Option<PkmString>,
    /// Interface-layer snapshots only: `Interface.Mac`; absent when the
    /// interface has no hardware address.
    pub interface_mac: Option<[u8; 6]>,
    /// Interface-layer snapshots only: `Interface.Path`; absent for
    /// anything that is not hardware.
    pub interface_path: Option<PkmString>,
    /// Interface-layer snapshots only: `Interface.Driver`; absent for
    /// anything that is not hardware.
    pub interface_driver: Option<PkmString>,
    /// The network context, every layer: `Network.Id`, the record of
    /// the network the interface is standing on. At the interface layer,
    /// present once the interface has link and an offer; at the packet
    /// layers, present while netd's inventory names a network for the
    /// interface the packet crossed.
    pub network_id: Option<PkmString>,
    /// The network context: `Network.Name`, the operator's label.
    pub network_name: Option<PkmString>,
    /// The network context: `Network.Trust`, the operator's word.
    pub network_trust: Option<PkmString>,
    /// Interface-layer snapshots only: `Network.Kind`.
    pub network_kind: Option<PkmString>,
}

impl<'a> Snapshot<'a> {
    /// Looks up a visible flow tag by its name hash.
    pub fn tag(&self, hash: u64) -> Option<u64> {
        self.tags.iter().find(|(h, _)| *h == hash).map(|(_, v)| *v)
    }

    /// Looks up a resolved counter view by index.
    pub fn counter_view(&self, view: u32) -> Option<u64> {
        self.counter_views
            .iter()
            .find(|(i, _)| *i == view)
            .map(|(_, v)| *v)
    }

    /// Attaches a flow tag by name (test and glue convenience).
    pub fn set_tag(&mut self, name: &str, value: u64) -> Result<(), AllocError> {
        self.tags.push((name_hash(name), value))
    }
}
