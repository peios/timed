//! Match conditions: the fact vocabulary, operators, and evaluation.
//!
//! A rule's match is a conjunction of conditions. Every condition is
//! evaluated against the immutable snapshot under the absent-fact law: a
//! condition over a fact the packet does not have is false.

use core::net::IpAddr;

use crate::pnp_core::hash::name_hash;
use crate::pnp_core::pkm_alloc::{String as PkmString, Vec as PkmVec};
use crate::pnp_core::sid::Sid;
use crate::pnp_core::snapshot::{Endpoint, Principal, Snapshot};
use crate::pnp_core::strutil::str_to_pkm;

/// The packet-layer fact vocabulary (ratified, complete).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FactId {
    /// Traversal direction (`in` / `out`).
    Direction,
    /// Interface name at the standing seat.
    Interface,
    /// Ethertype.
    EtherType,
    /// Source MAC address.
    SrcMac,
    /// Destination MAC address.
    DstMac,
    /// VLAN id.
    Vlan,
    /// Source IP address.
    SrcAddr,
    /// Destination IP address.
    DstAddr,
    /// IP protocol number.
    Protocol,
    /// TTL / hop limit.
    Ttl,
    /// DSCP field.
    Dscp,
    /// Fragment status.
    Fragment,
    /// L4 source port.
    SrcPort,
    /// L4 destination port.
    DstPort,
    /// TCP flags (`Has` / `Hasnt`).
    TcpFlags,
    /// ICMP type.
    IcmpType,
    /// ICMP code.
    IcmpCode,
    /// Packet length (stack view).
    Length,
    /// Conntrack flow classification.
    FlowState,
    /// Wall-clock year.
    TimeYear,
    /// Wall-clock month.
    TimeMonth,
    /// Wall-clock day of month.
    TimeDayOfMonth,
    /// ISO day of week (1 = Monday .. 7 = Sunday).
    TimeDayOfWeek,
    /// Wall-clock hour.
    TimeHour,
    /// Wall-clock minute.
    TimeMinute,
    /// Wall-clock second.
    TimeSecond,
    /// Whether the flow was expected by another (ICMP error, FTP data).
    /// Flow layer.
    Related,
    /// The flow's start time: year. Flow layer; never expires a sentence.
    StartYear,
    /// Start month.
    StartMonth,
    /// Start day of month.
    StartDayOfMonth,
    /// Start ISO day of week.
    StartDayOfWeek,
    /// Start hour.
    StartHour,
    /// Start minute.
    StartMinute,
    /// Start second.
    StartSecond,
    /// What stands at the local end: `program`, `kernel`, `shared`, `none`.
    /// Flow layer; always present there.
    Local,
    /// The local principal's user SID. Flow layer, program endpoints.
    LocalUser,
    /// The local principal's enabled groups (any-of). Flow layer.
    LocalGroup,
    /// The local principal's integrity level. Flow layer.
    LocalIntegrity,
    /// The local principal's confinement SID; absent when unconfined.
    LocalConfinement,
    /// The local principal's confinement capabilities (any-of).
    LocalCapability,
    /// The local principal's per-service SID; absent for a user program.
    LocalService,
    /// The local process GUID.
    LocalProcess,
    /// What stands at the other end, when it is local too (loopback).
    Remote,
    /// The remote principal's user SID (loopback).
    RemoteUser,
    /// The remote principal's enabled groups (loopback).
    RemoteGroup,
    /// The remote principal's integrity level (loopback).
    RemoteIntegrity,
    /// The remote principal's confinement SID (loopback).
    RemoteConfinement,
    /// The remote principal's confinement capabilities (loopback).
    RemoteCapability,
    /// The remote principal's per-service SID (loopback).
    RemoteService,
    /// The remote process GUID (loopback).
    RemoteProcess,
    /// Interface layer: what the interface is — `wired`, `wireless`,
    /// `loopback`, `tunnel`, `bridge`, `other`.
    InterfaceKind,
    /// Interface layer: the stable interface id (the inventory key name).
    InterfaceId,
    /// Interface layer: the hardware address; absent when it has none.
    InterfaceMac,
    /// Interface layer: the bus position; absent for anything not hardware.
    InterfacePath,
    /// Interface layer: the kernel driver; absent for anything not hardware.
    InterfaceDriver,
    /// Interface layer: the network record's key name; present once the
    /// interface has link and an offer.
    NetworkId,
    /// Interface layer: the operator's label for the network.
    NetworkName,
    /// Interface layer: the operator-assigned trust of the network.
    NetworkTrust,
    /// Interface layer: the kind of interface the network was seen on.
    NetworkKind,
}

impl FactId {
    /// Parses a fact name as written in rule value keys.
    pub fn from_key(name: &str) -> Option<FactId> {
        Some(match name {
            "Direction" => FactId::Direction,
            "Interface" => FactId::Interface,
            "EtherType" => FactId::EtherType,
            "SrcMac" => FactId::SrcMac,
            "DstMac" => FactId::DstMac,
            "Vlan" => FactId::Vlan,
            "SrcAddr" => FactId::SrcAddr,
            "DstAddr" => FactId::DstAddr,
            "Protocol" => FactId::Protocol,
            "Ttl" => FactId::Ttl,
            "Dscp" => FactId::Dscp,
            "Fragment" => FactId::Fragment,
            "SrcPort" => FactId::SrcPort,
            "DstPort" => FactId::DstPort,
            "TcpFlags" => FactId::TcpFlags,
            "IcmpType" => FactId::IcmpType,
            "IcmpCode" => FactId::IcmpCode,
            "Length" => FactId::Length,
            "FlowState" => FactId::FlowState,
            "Time.Year" => FactId::TimeYear,
            "Time.Month" => FactId::TimeMonth,
            "Time.DayOfMonth" => FactId::TimeDayOfMonth,
            "Time.DayOfWeek" => FactId::TimeDayOfWeek,
            "Time.Hour" => FactId::TimeHour,
            "Time.Minute" => FactId::TimeMinute,
            "Time.Second" => FactId::TimeSecond,
            "Related" => FactId::Related,
            "Start.Year" => FactId::StartYear,
            "Start.Month" => FactId::StartMonth,
            "Start.DayOfMonth" => FactId::StartDayOfMonth,
            "Start.DayOfWeek" => FactId::StartDayOfWeek,
            "Start.Hour" => FactId::StartHour,
            "Start.Minute" => FactId::StartMinute,
            "Start.Second" => FactId::StartSecond,
            "Local" => FactId::Local,
            "Local.User" => FactId::LocalUser,
            "Local.Group" => FactId::LocalGroup,
            "Local.Integrity" => FactId::LocalIntegrity,
            "Local.Confinement" => FactId::LocalConfinement,
            "Local.Capability" => FactId::LocalCapability,
            "Local.Service" => FactId::LocalService,
            "Local.Process" => FactId::LocalProcess,
            "Remote" => FactId::Remote,
            "Remote.User" => FactId::RemoteUser,
            "Remote.Group" => FactId::RemoteGroup,
            "Remote.Integrity" => FactId::RemoteIntegrity,
            "Remote.Confinement" => FactId::RemoteConfinement,
            "Remote.Capability" => FactId::RemoteCapability,
            "Remote.Service" => FactId::RemoteService,
            "Remote.Process" => FactId::RemoteProcess,
            "Interface.Kind" => FactId::InterfaceKind,
            "Interface.Id" => FactId::InterfaceId,
            "Interface.Mac" => FactId::InterfaceMac,
            "Interface.Path" => FactId::InterfacePath,
            "Interface.Driver" => FactId::InterfaceDriver,
            "Network.Id" => FactId::NetworkId,
            "Network.Name" => FactId::NetworkName,
            "Network.Trust" => FactId::NetworkTrust,
            "Network.Kind" => FactId::NetworkKind,
            _ => return None,
        })
    }

    /// The value family this fact compares in.
    pub fn family(self) -> FactFamily {
        match self {
            FactId::Direction
            | FactId::Interface
            | FactId::FlowState
            | FactId::Local
            | FactId::Remote
            | FactId::LocalProcess
            | FactId::RemoteProcess
            | FactId::InterfaceKind
            | FactId::InterfaceId
            | FactId::InterfacePath
            | FactId::InterfaceDriver
            | FactId::NetworkId
            | FactId::NetworkName
            | FactId::NetworkTrust
            | FactId::NetworkKind => FactFamily::Str,
            FactId::SrcAddr | FactId::DstAddr => FactFamily::Addr,
            FactId::SrcMac | FactId::DstMac | FactId::InterfaceMac => FactFamily::Mac,
            FactId::TcpFlags => FactFamily::Flags,
            FactId::LocalUser
            | FactId::LocalGroup
            | FactId::LocalConfinement
            | FactId::LocalCapability
            | FactId::LocalService
            | FactId::RemoteUser
            | FactId::RemoteGroup
            | FactId::RemoteConfinement
            | FactId::RemoteCapability
            | FactId::RemoteService => FactFamily::Sid,
            _ => FactFamily::Int,
        }
    }

    /// Whether this fact is the interface layer's alone (`Interface.*`
    /// and `Network.Kind`): read from an interface and its network record,
    /// never from a packet. `Interface` itself (the name) and the network
    /// context (`Network.Id`, `Network.Name`, `Network.Trust`) are shared
    /// with the packet layers.
    pub fn is_interface_only(self) -> bool {
        matches!(
            self,
            FactId::InterfaceKind
                | FactId::InterfaceId
                | FactId::InterfaceMac
                | FactId::InterfacePath
                | FactId::InterfaceDriver
                | FactId::NetworkKind
        )
    }

    /// Whether this fact is the network context: which network the
    /// interface a packet crossed is standing on, and the operator's
    /// word on it. Read from netd's inventory at every layer — from the
    /// interface record at the interface layer, from the kernel's
    /// per-interface context table at the packet layers — so a rule about
    /// a network means the same thing wherever it is written.
    pub fn is_network_context(self) -> bool {
        matches!(
            self,
            FactId::NetworkId | FactId::NetworkName | FactId::NetworkTrust
        )
    }

    /// Whether this fact exists at the interface layer at all.
    pub fn is_at_interface_layer(self) -> bool {
        self == FactId::Interface || self.is_interface_only() || self.is_network_context()
    }

    /// Whether this is an identity fact (`Local`, `Local.*`, `Remote`,
    /// `Remote.*`): read from an endpoint's token, Flow layer only.
    pub fn is_identity(self) -> bool {
        matches!(
            self,
            FactId::Local
                | FactId::LocalUser
                | FactId::LocalGroup
                | FactId::LocalIntegrity
                | FactId::LocalConfinement
                | FactId::LocalCapability
                | FactId::LocalService
                | FactId::LocalProcess
                | FactId::Remote
                | FactId::RemoteUser
                | FactId::RemoteGroup
                | FactId::RemoteIntegrity
                | FactId::RemoteConfinement
                | FactId::RemoteCapability
                | FactId::RemoteService
                | FactId::RemoteProcess
        )
    }

    /// Whether this fact reads the other end's identity (loopback only).
    pub fn is_remote(self) -> bool {
        matches!(
            self,
            FactId::Remote
                | FactId::RemoteUser
                | FactId::RemoteGroup
                | FactId::RemoteIntegrity
                | FactId::RemoteConfinement
                | FactId::RemoteCapability
                | FactId::RemoteService
                | FactId::RemoteProcess
        )
    }

    /// Whether this is a live-clock fact (`Time.*`): its answer changes
    /// while a flow lives, so a consulted condition over it expires the
    /// flow's sentence. `Start.*` facts are fixed for the flow's life.
    pub fn is_live_time(self) -> bool {
        matches!(
            self,
            FactId::TimeYear
                | FactId::TimeMonth
                | FactId::TimeDayOfMonth
                | FactId::TimeDayOfWeek
                | FactId::TimeHour
                | FactId::TimeMinute
                | FactId::TimeSecond
        )
    }

    /// Whether this fact is fixed for a flow's life — the Flow layer's
    /// vocabulary. Everything else is per packet.
    pub fn is_flow_invariant(self) -> bool {
        !matches!(
            self,
            FactId::EtherType
                | FactId::DstMac
                | FactId::Ttl
                | FactId::Dscp
                | FactId::Fragment
                | FactId::TcpFlags
                | FactId::Length
                | FactId::FlowState
        )
    }

    /// Whether this fact exists only on a flow (the Flow layer's own).
    pub fn is_flow_only(self) -> bool {
        self.is_identity()
            || matches!(
                self,
                FactId::Related
                    | FactId::StartYear
                    | FactId::StartMonth
                    | FactId::StartDayOfMonth
                    | FactId::StartDayOfWeek
                    | FactId::StartHour
                    | FactId::StartMinute
                    | FactId::StartSecond
            )
    }
}

/// Value families: which operators and pattern shapes a fact supports.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FactFamily {
    /// Integer-valued: `Equal` (scalars/ranges), `GreaterThan`, `LessThan`.
    Int,
    /// String-valued: `Equal` only.
    Str,
    /// IP addresses: `Equal` with exacts, ranges, and CIDR prefixes.
    Addr,
    /// MAC addresses: `Equal` with exacts.
    Mac,
    /// Flag sets: `Has` / `Hasnt`.
    Flags,
    /// Security identifiers: `Equal` with exact SIDs (any-of), written as
    /// `S-1-…`, a well-known name, or — for the service facts — a service
    /// name. A set-valued fact (groups, capabilities) matches when any
    /// listed SID is in the set.
    Sid,
}

/// Counter key-spec bits: which facts partition a counter view. A packet
/// lacking any keyed fact has no cell (absent-fact law, both sides).
pub mod keyspec {
    /// Keyed by source address.
    pub const SRC_ADDR: u8 = 1 << 0;
    /// Keyed by destination address.
    pub const DST_ADDR: u8 = 1 << 1;
    /// Keyed by interface.
    pub const INTERFACE: u8 = 1 << 2;

    /// Parses one key-spec fact name.
    pub fn from_name(name: &str) -> Option<u8> {
        match name {
            "SrcAddr" => Some(SRC_ADDR),
            "DstAddr" => Some(DST_ADDR),
            "Interface" => Some(INTERFACE),
            _ => None,
        }
    }
}

/// Longest window a view may ask for (one day): per-key memory scales with
/// the number of windows a stream is viewed through, so the horizon is
/// bounded.
pub const MAX_WINDOW_SECS: u32 = 86_400;

/// A `Counter.<n>(...)` spec that does not parse as a view.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BadView;

/// A compiled counter view: one way of slicing a stream. Every view the
/// forest mentions is materialized by the store at publication — windows
/// and key-specs are compile-time constants, so the hot path never sees
/// an arbitrary query.
#[derive(Debug, PartialEq, Eq)]
pub struct CounterView {
    /// Stream name.
    pub name: PkmString,
    /// `name_hash(name)`: the store's identity for the stream.
    pub hash: u64,
    /// Sliding window in seconds; 0 = the cumulative total.
    pub window_secs: u32,
    /// `keyspec::*` bits; 0 = one global cell.
    pub keyspec: u8,
}

impl CounterView {
    /// Parses the text after `Counter.`: `Name`, `Name(args)` where args
    /// are at most one duration (`10s`/`5m`/`2h`/`1d`) and at most one
    /// key-spec (`SrcAddr`, `DstAddr`, `Interface`, `+`-compounded), in
    /// any order. `Err(BadView)` for anything else (including a window over
    /// the horizon).
    pub fn parse(spec: &str) -> Result<CounterView, BadView> {
        let (name, args) = match spec.find('(') {
            Some(i) => {
                let rest = &spec[i + 1..];
                let close = rest.rfind(')').ok_or(BadView)?;
                if !rest[close + 1..].is_empty() {
                    return Err(BadView);
                }
                (&spec[..i], Some(&rest[..close]))
            }
            None => (spec, None),
        };
        let name = name.trim();
        if name.is_empty() || name.contains([')', ',', '.']) {
            return Err(BadView);
        }
        let mut window: Option<u32> = None;
        let mut keyspec: Option<u8> = None;
        if let Some(args) = args {
            for arg in args.split(',') {
                let arg = arg.trim();
                if arg.is_empty() {
                    return Err(BadView);
                }
                if let Some(secs) = parse_duration(arg) {
                    if window.replace(secs).is_some() {
                        return Err(BadView);
                    }
                    continue;
                }
                let mut bits = 0u8;
                for part in arg.split('+') {
                    let bit = keyspec::from_name(part.trim()).ok_or(BadView)?;
                    if bits & bit != 0 {
                        return Err(BadView);
                    }
                    bits |= bit;
                }
                if keyspec.replace(bits).is_some() {
                    return Err(BadView);
                }
            }
        }
        Ok(CounterView {
            name: str_to_pkm(name).map_err(|_| BadView)?,
            hash: name_hash(name),
            window_secs: window.unwrap_or(0),
            keyspec: keyspec.unwrap_or(0),
        })
    }
}

/// `<digits><unit>` with unit s/m/h/d; must be > 0 and <= MAX_WINDOW_SECS.
fn parse_duration(s: &str) -> Option<u32> {
    let (num, unit) = s.split_at(s.len().checked_sub(1)?);
    if num.is_empty() || !num.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    let n: u64 = num.parse().ok()?;
    let mult: u64 = match unit {
        "s" => 1,
        "m" => 60,
        "h" => 3600,
        "d" => 86_400,
        _ => return None,
    };
    let secs = n.checked_mul(mult)?;
    if secs == 0 || secs > u64::from(MAX_WINDOW_SECS) {
        return None;
    }
    Some(secs as u32)
}

/// What a condition is keyed on.
#[derive(Debug)]
pub enum CondKey {
    /// A vocabulary fact.
    Fact(FactId),
    /// A flow tag, by name and its store hash.
    Tag {
        /// Tag name (attribution / diagnostics).
        name: PkmString,
        /// `name_hash(name)`.
        hash: u64,
    },
    /// A counter view, by index into the forest's view table.
    Counter(u32),
}

/// One element of an integer `Equal` list.
#[derive(Debug, Clone, Copy)]
pub enum IntPattern {
    /// Exactly this value.
    Exact(i64),
    /// Inclusive range `a-b`.
    Range(i64, i64),
}

impl IntPattern {
    fn matches(self, v: i64) -> bool {
        match self {
            IntPattern::Exact(x) => v == x,
            IntPattern::Range(a, b) => v >= a && v <= b,
        }
    }
}

/// One element of an address `Equal` list.
#[derive(Debug, Clone, Copy)]
pub enum AddrPattern {
    /// Exactly this address.
    Exact(IpAddr),
    /// Inclusive range `a-b` (same family).
    Range(IpAddr, IpAddr),
    /// CIDR prefix.
    Cidr {
        /// Network address.
        addr: IpAddr,
        /// Prefix length in bits.
        prefix: u8,
    },
}

impl AddrPattern {
    fn matches(&self, v: IpAddr) -> bool {
        match *self {
            AddrPattern::Exact(a) => a == v,
            AddrPattern::Range(a, b) => match (addr_bits(a), addr_bits(b), addr_bits(v)) {
                (Some((fa, a)), Some((fb, b)), Some((fv, v))) => {
                    fa == fb && fb == fv && v >= a && v <= b
                }
                _ => false,
            },
            AddrPattern::Cidr { addr, prefix } => match (addr_bits(addr), addr_bits(v)) {
                (Some((fa, a)), Some((fv, v))) if fa == fv => {
                    let width: u32 = if fa == 4 { 32 } else { 128 };
                    if prefix == 0 {
                        return true;
                    }
                    if u32::from(prefix) > width {
                        return false;
                    }
                    let shift = width - u32::from(prefix);
                    (a >> shift) == (v >> shift)
                }
                _ => false,
            },
        }
    }
}

/// Address as (family, 128-bit value) for uniform comparison. v4 stays in
/// its own family: a v4 range never matches a v6 address and vice versa.
fn addr_bits(a: IpAddr) -> Option<(u8, u128)> {
    match a {
        IpAddr::V4(v4) => Some((4, u128::from(u32::from(v4)))),
        IpAddr::V6(v6) => Some((6, u128::from(v6))),
    }
}

/// The operator half of a condition.
#[derive(Debug)]
pub enum CondOp {
    /// Integer membership (scalars and ranges; list = OR within the field).
    EqualInt(PkmVec<IntPattern>),
    /// String membership.
    EqualStr(PkmVec<PkmString>),
    /// Address membership (exacts, ranges, CIDRs).
    EqualAddr(PkmVec<AddrPattern>),
    /// MAC membership.
    EqualMac(PkmVec<[u8; 6]>),
    /// Strictly greater than.
    Gt(i64),
    /// Strictly less than.
    Lt(i64),
    /// All listed flag bits set.
    Has(u8),
    /// All listed flag bits clear.
    Hasnt(u8),
    /// SID membership (any-of).
    EqualSid(PkmVec<Sid>),
    /// Whether the fact exists at all: `Present = 1` holds when it does,
    /// `Present = 0` when it does not. The one operator that looks through
    /// the absent-fact law — which is why ingestion refuses it on a fact
    /// absent by law at the rule's layer.
    Present(bool),
}

/// One condition: key + operator. A rule matches iff all its conditions do.
#[derive(Debug)]
pub struct Condition {
    /// What the condition looks at.
    pub key: CondKey,
    /// How it compares.
    pub op: CondOp,
    /// The key never exists at the forest's layer (ingestion's
    /// `FactNeverPresentAtLayer` lint): the condition is false by the
    /// absent-fact law whatever the snapshot carries. Snapshots are built
    /// per seat, not per layer, so the law is kept here rather than
    /// trusted to every snapshot's builder (PEI-1302).
    pub never: bool,
}

impl Condition {
    /// Whether this condition reads a live-clock fact.
    pub fn is_live_time(&self) -> bool {
        matches!(self.key, CondKey::Fact(f) if f.is_live_time())
    }

    /// The next moment (epoch seconds, UTC) at which this condition's
    /// answer would change, given the snapshot's clock — `None` when it
    /// never would, or when it reads no live-clock fact, or when the
    /// snapshot has no clock. A condition whose answer is constant over its
    /// fact's whole cycle (`Time.Hour.LessThan 24`) never flips.
    ///
    /// Hour, minute, second and day-of-week are exact (the value sequence
    /// is scanned one cycle ahead with the condition's own operator).
    /// Day-of-month, month and year answer "next midnight": exact flips
    /// need calendar arithmetic nobody has asked for, and a daily re-judge
    /// is cheap.
    pub fn next_flip(&self, snap: &Snapshot<'_>) -> Option<i64> {
        let fact = match self.key {
            CondKey::Fact(f) if f.is_live_time() => f,
            _ => return None,
        };
        // Whether the clock is present never changes while a flow lives.
        if matches!(self.op, CondOp::Present(_)) {
            return None;
        }
        let now = snap.now_secs?;
        let time = snap.time?;
        let (current, modulus, step, base): (i64, i64, i64, i64) = match fact {
            FactId::TimeSecond => (time.second, 60, 1, now),
            FactId::TimeMinute => (time.minute, 60, 60, now - now.rem_euclid(60)),
            FactId::TimeHour => (time.hour, 24, 3600, now - now.rem_euclid(3600)),
            FactId::TimeDayOfWeek => (
                time.day_of_week - 1,
                7,
                86_400,
                now - now.rem_euclid(86_400),
            ),
            _ => return Some(now - now.rem_euclid(86_400) + 86_400),
        };
        let offset = if fact == FactId::TimeDayOfWeek { 1 } else { 0 };
        let truth = int_op_matches(&self.op, current + offset);
        for k in 1..=modulus {
            let value = (current + k).rem_euclid(modulus) + offset;
            if int_op_matches(&self.op, value) != truth {
                return Some(base + k * step);
            }
        }
        None
    }

    /// Whether the condition's key exists in the snapshot — what `Present`
    /// answers.
    pub fn present(&self, snap: &Snapshot<'_>) -> bool {
        match &self.key {
            CondKey::Tag { hash, .. } => snap.tag(*hash).is_some(),
            CondKey::Counter(view) => snap.counter_view(*view).is_some(),
            CondKey::Fact(fact) => match fact.family() {
                FactFamily::Int => int_fact(*fact, snap).is_some(),
                FactFamily::Str => str_fact(*fact, snap).is_some(),
                FactFamily::Addr => match fact {
                    FactId::SrcAddr => snap.src_addr.is_some(),
                    FactId::DstAddr => snap.dst_addr.is_some(),
                    _ => false,
                },
                FactFamily::Mac => match fact {
                    FactId::SrcMac => snap.src_mac.is_some(),
                    FactId::DstMac => snap.dst_mac.is_some(),
                    FactId::InterfaceMac => snap.interface_mac.is_some(),
                    _ => false,
                },
                FactFamily::Flags => snap.tcp_flags.is_some(),
                FactFamily::Sid => sid_fact_present(*fact, snap),
            },
        }
    }

    /// Evaluates the condition against a snapshot (absent-fact law: an
    /// unresolvable key is false).
    pub fn matches(&self, snap: &Snapshot<'_>) -> bool {
        if self.never {
            return false;
        }
        if let CondOp::Present(want) = self.op {
            return self.present(snap) == want;
        }
        match &self.key {
            CondKey::Tag { hash, .. } => match snap.tag(*hash) {
                Some(v) => int_op_matches(&self.op, clamp_u64(v)),
                None => false,
            },
            CondKey::Counter(view) => match snap.counter_view(*view) {
                Some(v) => int_op_matches(&self.op, clamp_u64(v)),
                None => false,
            },
            CondKey::Fact(fact) => match fact.family() {
                FactFamily::Int => match int_fact(*fact, snap) {
                    Some(v) => int_op_matches(&self.op, v),
                    None => false,
                },
                FactFamily::Str => match str_fact(*fact, snap) {
                    Some(v) => match &self.op {
                        CondOp::EqualStr(list) => list.iter().any(|p| p.as_str() == v),
                        _ => false,
                    },
                    None => false,
                },
                FactFamily::Addr => {
                    let v = match fact {
                        FactId::SrcAddr => snap.src_addr,
                        FactId::DstAddr => snap.dst_addr,
                        _ => None,
                    };
                    match v {
                        Some(v) => match &self.op {
                            CondOp::EqualAddr(list) => list.iter().any(|p| p.matches(v)),
                            _ => false,
                        },
                        None => false,
                    }
                }
                FactFamily::Mac => {
                    let v = match fact {
                        FactId::SrcMac => snap.src_mac,
                        FactId::DstMac => snap.dst_mac,
                        FactId::InterfaceMac => snap.interface_mac,
                        _ => None,
                    };
                    match v {
                        Some(v) => match &self.op {
                            CondOp::EqualMac(list) => list.iter().any(|p| *p == v),
                            _ => false,
                        },
                        None => false,
                    }
                }
                FactFamily::Flags => match snap.tcp_flags {
                    Some(v) => match &self.op {
                        CondOp::Has(mask) => v & mask == *mask,
                        CondOp::Hasnt(mask) => v & mask == 0,
                        _ => false,
                    },
                    None => false,
                },
                FactFamily::Sid => match &self.op {
                    CondOp::EqualSid(list) => sid_fact_matches(*fact, snap, list),
                    _ => false,
                },
            },
        }
    }
}

/// The endpoint an identity fact reads.
fn endpoint<'s, 'a>(fact: FactId, snap: &'s Snapshot<'a>) -> Option<&'s Endpoint<'a>> {
    if fact.is_remote() {
        snap.remote.as_ref()
    } else {
        snap.local.as_ref()
    }
}

/// The principal an identity fact reads: present iff the endpoint is a
/// program.
fn principal<'a>(fact: FactId, snap: &Snapshot<'a>) -> Option<&'a dyn Principal> {
    endpoint(fact, snap).and_then(|e| e.principal)
}

fn sid_fact_present(fact: FactId, snap: &Snapshot<'_>) -> bool {
    let Some(p) = principal(fact, snap) else {
        return false;
    };
    match fact {
        FactId::LocalUser | FactId::RemoteUser => true,
        FactId::LocalGroup | FactId::RemoteGroup => true,
        // Confinement and its capabilities exist together: an unconfined
        // token has neither.
        FactId::LocalConfinement
        | FactId::RemoteConfinement
        | FactId::LocalCapability
        | FactId::RemoteCapability => p.confinement().is_some(),
        FactId::LocalService | FactId::RemoteService => p.service().is_some(),
        _ => false,
    }
}

fn sid_fact_matches(fact: FactId, snap: &Snapshot<'_>, list: &[Sid]) -> bool {
    let Some(p) = principal(fact, snap) else {
        return false;
    };
    match fact {
        FactId::LocalUser | FactId::RemoteUser => list.iter().any(|s| s == p.user()),
        FactId::LocalGroup | FactId::RemoteGroup => list.iter().any(|s| p.is_member(s)),
        FactId::LocalConfinement | FactId::RemoteConfinement => match p.confinement() {
            Some(c) => list.iter().any(|s| s == c),
            None => false,
        },
        FactId::LocalCapability | FactId::RemoteCapability => {
            p.confinement().is_some() && list.iter().any(|s| p.has_capability(s))
        }
        FactId::LocalService | FactId::RemoteService => match p.service() {
            Some(svc) => list.iter().any(|s| s == svc),
            None => false,
        },
        _ => false,
    }
}

fn int_op_matches(op: &CondOp, v: i64) -> bool {
    match op {
        CondOp::EqualInt(list) => list.iter().any(|p| p.matches(v)),
        CondOp::Gt(x) => v > *x,
        CondOp::Lt(x) => v < *x,
        _ => false,
    }
}

fn clamp_u64(v: u64) -> i64 {
    if v > i64::MAX as u64 {
        i64::MAX
    } else {
        v as i64
    }
}

fn int_fact(fact: FactId, snap: &Snapshot<'_>) -> Option<i64> {
    Some(match fact {
        FactId::EtherType => i64::from(snap.ether_type?),
        FactId::Vlan => i64::from(snap.vlan?),
        FactId::Protocol => i64::from(snap.protocol?),
        FactId::Ttl => i64::from(snap.ttl?),
        FactId::Dscp => i64::from(snap.dscp?),
        FactId::Fragment => i64::from(snap.fragment? as u8),
        FactId::SrcPort => i64::from(snap.src_port?),
        FactId::DstPort => i64::from(snap.dst_port?),
        FactId::IcmpType => i64::from(snap.icmp_type?),
        FactId::IcmpCode => i64::from(snap.icmp_code?),
        FactId::Length => i64::from(snap.length?),
        FactId::TimeYear => snap.time?.year,
        FactId::TimeMonth => snap.time?.month,
        FactId::TimeDayOfMonth => snap.time?.day_of_month,
        FactId::TimeDayOfWeek => snap.time?.day_of_week,
        FactId::TimeHour => snap.time?.hour,
        FactId::TimeMinute => snap.time?.minute,
        FactId::TimeSecond => snap.time?.second,
        FactId::Related => i64::from(snap.related? as u8),
        FactId::StartYear => snap.start?.year,
        FactId::StartMonth => snap.start?.month,
        FactId::StartDayOfMonth => snap.start?.day_of_month,
        FactId::StartDayOfWeek => snap.start?.day_of_week,
        FactId::StartHour => snap.start?.hour,
        FactId::StartMinute => snap.start?.minute,
        FactId::StartSecond => snap.start?.second,
        FactId::LocalIntegrity | FactId::RemoteIntegrity => principal(fact, snap)?.integrity(),
        _ => return None,
    })
}

fn str_fact<'s>(fact: FactId, snap: &'s Snapshot<'_>) -> Option<&'s str> {
    match fact {
        FactId::Direction => snap.direction.map(|d| d.as_str()),
        FactId::FlowState => snap.flow_state.map(|s| s.as_str()),
        FactId::Interface => snap.interface.as_ref().map(|s| s.as_str()),
        FactId::Local | FactId::Remote => endpoint(fact, snap).map(|e| e.kind.as_str()),
        FactId::LocalProcess | FactId::RemoteProcess => principal(fact, snap).map(|p| p.process()),
        FactId::InterfaceKind => snap.interface_kind.as_ref().map(|s| s.as_str()),
        FactId::InterfaceId => snap.interface_id.as_ref().map(|s| s.as_str()),
        FactId::InterfacePath => snap.interface_path.as_ref().map(|s| s.as_str()),
        FactId::InterfaceDriver => snap.interface_driver.as_ref().map(|s| s.as_str()),
        FactId::NetworkId => snap.network_id.as_ref().map(|s| s.as_str()),
        FactId::NetworkName => snap.network_name.as_ref().map(|s| s.as_str()),
        FactId::NetworkTrust => snap.network_trust.as_ref().map(|s| s.as_str()),
        FactId::NetworkKind => snap.network_kind.as_ref().map(|s| s.as_str()),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn counter_view_grammar_is_typed_and_order_free() {
        let v = CounterView::parse("SynFlood").unwrap();
        assert_eq!((v.window_secs, v.keyspec), (0, 0));
        assert_eq!(v.hash, name_hash("SynFlood"));

        let v = CounterView::parse("SynFlood(100s, SrcAddr+DstAddr)").unwrap();
        assert_eq!(v.window_secs, 100);
        assert_eq!(v.keyspec, keyspec::SRC_ADDR | keyspec::DST_ADDR);

        let v = CounterView::parse("x( Interface , 5m )").unwrap();
        assert_eq!(v.window_secs, 300);
        assert_eq!(v.keyspec, keyspec::INTERFACE);

        assert_eq!(CounterView::parse("x(2h)").unwrap().window_secs, 7200);
        assert_eq!(CounterView::parse("x(1d)").unwrap().window_secs, 86_400);
        assert_eq!(CounterView::parse("x(SrcAddr)").unwrap().window_secs, 0);
    }

    #[test]
    fn counter_view_grammar_refuses_nonsense() {
        assert!(CounterView::parse("").is_err());
        assert!(CounterView::parse("x(").is_err());
        assert!(CounterView::parse("x()").is_err());
        assert!(CounterView::parse("x(10s, 20s)").is_err()); // two windows
        assert!(CounterView::parse("x(SrcAddr, DstAddr)").is_err()); // two keyspecs
        assert!(CounterView::parse("x(SrcAddr+SrcAddr)").is_err()); // duplicate key
        assert!(CounterView::parse("x(2d)").is_err()); // over the horizon
        assert!(CounterView::parse("x(0s)").is_err());
        assert!(CounterView::parse("x(10)").is_err()); // unitless
        assert!(CounterView::parse("x(Ttl)").is_err()); // not a key fact
        assert!(CounterView::parse("x(10s)y").is_err());
    }
}
