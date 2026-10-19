//! netd's control wire.
//!
//! netd's control socket is a PSPU observability *query* channel: a
//! `SOCK_STREAM` socket at a configured path carrying length-prefixed
//! MessagePack maps, one request and one reply per connection. It is not a
//! second framing of our own; the observability book fixes the shape so a
//! collector-side tool that can read one daemon's query channel can read them
//! all.
//!
//! ```text
//! +---------------------+------------------------+
//! | length u32 LE       | payload (MessagePack)  |
//! +---------------------+------------------------+
//! ```
//!
//! A request is a map with a required `query` string; unknown keys are
//! ignored, duplicates rejected. A reply is a map with `ok` (bool) and either
//! the result fields or `error` (string).
//!
//! This crate is deliberately inert: types and a codec, nothing that can act.
//! It also holds the laws a program writing netd's registry configuration
//! needs to check its change by before making it: the machine's name, in
//! [`hostname`]; a profile's vocabulary and inheritance, in [`profile`];
//! and, with the `policy` feature, the interface layer as netd builds and
//! judges it, in `policy`. They are netd's own, not copies, so the check
//! and the daemon cannot disagree.

pub mod hostname;
#[cfg(feature = "policy")]
pub mod policy;
pub mod profile;
pub mod raw;

use std::io::{self, Read, Write};
use std::os::unix::net::UnixStream;

use peios::msgpack::{Reader, Type, Writer};

/// netd's runtime directory. peinit creates it (`RuntimeDirectories`) and netd
/// stamps its own descriptor on it, as lpsd does.
pub const NETD_RUN_DIR: &str = "/run/netd";
/// The control socket.
pub const CONTROL_SOCKET_PATH: &str = "/run/netd/control.sock";
/// Durable state: leases and the DUID. `/var/state/<daemon>` is the Peios
/// convention (lpsd uses `/var/state/lpsd`).
pub const NETD_STATE_DIR: &str = "/var/state/netd";

/// The registry root netd reads its configuration from.
pub const NETWORK_KEY: &str = "Machine\\System\\Network";

/// Rights on the netd control object.
///
/// Checked against `Machine\System\Network\ControlSecurity` when it exists,
/// else the compiled default: Everyone may query, SYSTEM and Administrators may
/// control.
pub const NETWORK_QUERY: u32 = 0x0000_0001;
pub const NETWORK_CONTROL: u32 = 0x0000_0002;
pub const NETWORK_ALL_ACCESS: u32 = NETWORK_QUERY | NETWORK_CONTROL | 0x000F_0000;

/// Ceiling on one control message, payload only. The observability book's
/// mainline query ceiling.
pub const MAX_MESSAGE_BYTES: usize = 65_536;

/// How far along an interface is towards being usable.
///
/// "Online" is not a boolean on Peios: a service says which level it needs.
/// Ordered, so `max()` over interfaces is the machine's level.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
pub enum Level {
    /// Not configured, or no profile matched it.
    #[default]
    Absent,
    /// Administratively up with carrier.
    Link,
    /// Has at least one usable unicast address.
    Addressed,
    /// Has a default route.
    Routed,
}

impl Level {
    pub fn as_str(self) -> &'static str {
        match self {
            Level::Absent => "absent",
            Level::Link => "link",
            Level::Addressed => "addressed",
            Level::Routed => "routed",
        }
    }

    pub fn parse(s: &str) -> Option<Level> {
        Some(match s {
            "absent" => Level::Absent,
            "link" => Level::Link,
            "addressed" => Level::Addressed,
            "routed" => Level::Routed,
            _ => return None,
        })
    }
}

/// A request to netd.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Request {
    /// The whole picture: hostname, machine level, every interface.
    Status,
    /// Release and re-acquire the DHCP lease on one interface.
    Renew { interface: String },
    /// Re-run the reconciler now.
    Reconcile,
    /// Stream DNS facts: a `snapshot` reply now, and another every time
    /// they change, on the same connection, until the peer closes it. The
    /// one request that holds a connection open. resolvd is the consumer.
    Subscribe,
}

impl Request {
    pub fn encode(&self) -> Vec<u8> {
        let mut w = Writer::new();
        match self {
            Request::Status => {
                w.write_map(1).write_str("query").write_str("status");
            }
            Request::Renew { interface } => {
                w.write_map(2)
                    .write_str("query")
                    .write_str("renew")
                    .write_str("interface")
                    .write_str(interface);
            }
            Request::Reconcile => {
                w.write_map(1).write_str("query").write_str("reconcile");
            }
            Request::Subscribe => {
                w.write_map(1).write_str("query").write_str("subscribe");
            }
        }
        w.to_bytes().expect("a request encodes")
    }

    pub fn decode(bytes: &[u8]) -> Result<Request, WireError> {
        let mut r = Reader::new(bytes);
        let mut query = None;
        let mut interface = None;
        let mut seen = Vec::new();
        for_each_field(&mut r, &mut seen, |key, r| {
            match key {
                "query" => query = Some(r.read_str()?.to_owned()),
                "interface" => interface = Some(r.read_str()?.to_owned()),
                _ => r.skip()?,
            }
            Ok(())
        })?;
        match query.as_deref() {
            Some("status") => Ok(Request::Status),
            Some("reconcile") => Ok(Request::Reconcile),
            Some("subscribe") => Ok(Request::Subscribe),
            Some("renew") => Ok(Request::Renew {
                interface: interface.ok_or(WireError::Missing("interface"))?,
            }),
            Some(other) => Err(WireError::UnknownQuery(other.to_owned())),
            None => Err(WireError::Missing("query")),
        }
    }

    /// The right this request needs on the control object.
    pub fn required_right(&self) -> u32 {
        match self {
            Request::Status | Request::Subscribe => NETWORK_QUERY,
            Request::Renew { .. } | Request::Reconcile => NETWORK_CONTROL,
        }
    }
}

/// A DHCP lease as reported.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct LeaseStatus {
    pub server: String,
    pub expires_in: u64,
    pub state: String,
    /// The lease's whole length, in seconds; 0 from a netd that does not
    /// say. `duration - expires_in` is how long ago it was bound.
    pub duration: u64,
    /// When the client starts renewing with its server (T1), and when it
    /// asks any server (T2), in seconds after the lease was bound.
    pub renew_at: u64,
    pub rebind_at: u64,
}

/// One interface as reported.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct InterfaceStatus {
    pub ifid: String,
    pub name: String,
    pub index: u32,
    pub mac: String,
    pub path: String,
    pub driver: String,
    /// `JOIN`, `IGNORE` or `DOWN`; `None` when no rule spoke (the backstop
    /// ignored it) or rules tied.
    pub verdict: Option<String>,
    /// The rule path that spoke, `backstop`, or the tied rules.
    pub rule: Option<String>,
    /// The profile path, `JOIN` only.
    pub profile: Option<String>,
    /// The network record identified on the other side, and what the
    /// operator wrote on it.
    pub network: Option<String>,
    pub network_name: Option<String>,
    pub network_trust: Option<String>,
    /// Something the operator should see: discovery unanswered, a tie.
    pub warning: Option<String>,
    pub up: bool,
    pub carrier: bool,
    pub level: Level,
    pub addresses: Vec<String>,
    pub gateway: Option<String>,
    /// The IPv6 default router — a link-local address, meaningful only on
    /// this interface.
    pub gateway6: Option<String>,
    pub dns: Vec<String>,
    pub search: Vec<String>,
    pub lease: Option<LeaseStatus>,
}

/// The `status` reply body.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Status {
    pub hostname: String,
    pub level: Level,
    /// Why the newest generation of the interface layer was refused, while
    /// the last good one stands.
    pub refusal: Option<String>,
    pub interfaces: Vec<InterfaceStatus>,
}

/// What one interface contributes to name resolution. The unit of the
/// netd -> resolvd channel; everything resolvd needs to route a query is
/// here so it never reads `Profiles\`.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct DnsScope {
    pub ifid: String,
    pub name: String,
    /// Servers in the order to try them: the profile's statics, then the
    /// lease's when `UseFromDHCP`.
    pub servers: Vec<String>,
    /// Search domains, likewise: the profile's, then the lease's domain
    /// search list or domain name.
    pub domains: Vec<String>,
    /// Time servers this interface's lease offered (DHCP option 42).
    ///
    /// Reported unconditionally, because a snapshot describes what the
    /// network *said*. Whether to believe it is timed's decision, gated on
    /// `Machine\System\Time UseFromDHCP`, which is off by default — on a
    /// network you do not control, the DHCP server's idea of the time is
    /// the attacker's idea of the time.
    pub ntp: Vec<String>,
    /// Every unicast address on the interface, CIDR form.
    pub addresses: Vec<String>,
    /// This interface's servers take names no domain matches. True when the
    /// profile says `DNSDefaultRoute`, else when the interface carries a
    /// default route.
    pub default_route: bool,
    /// While this interface is up, no other interface's servers are used
    /// for anything (`DNSExclusive`; a VPN's "ultimate protection").
    pub exclusive: bool,
    pub metric: u32,
    pub level: Level,
}

/// The `subscribe` reply body: the whole DNS picture. Sent whole every time
/// rather than as deltas — it is a few hundred bytes, and a whole picture
/// cannot be misapplied out of order.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Snapshot {
    pub hostname: String,
    /// Managed interfaces at `Link` or better, in metric order.
    pub scopes: Vec<DnsScope>,
}

/// A reply from netd.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Reply {
    Ok,
    Status(Status),
    Snapshot(Snapshot),
    Error(String),
}

impl Reply {
    pub fn encode(&self) -> Vec<u8> {
        let mut w = Writer::new();
        match self {
            Reply::Ok => {
                w.write_map(1).write_str("ok").write_bool(true);
            }
            Reply::Error(message) => {
                w.write_map(2)
                    .write_str("ok")
                    .write_bool(false)
                    .write_str("error")
                    .write_str(message);
            }
            Reply::Snapshot(snapshot) => {
                w.write_map(4).write_str("ok").write_bool(true);
                w.write_str("kind").write_str("snapshot");
                w.write_str("hostname").write_str(&snapshot.hostname);
                w.write_str("scopes")
                    .write_array(snapshot.scopes.len() as u32);
                for s in &snapshot.scopes {
                    w.write_map(10);
                    w.write_str("ifid").write_str(&s.ifid);
                    w.write_str("name").write_str(&s.name);
                    write_str_list(&mut w, "servers", &s.servers);
                    write_str_list(&mut w, "domains", &s.domains);
                    write_str_list(&mut w, "ntp", &s.ntp);
                    write_str_list(&mut w, "addresses", &s.addresses);
                    w.write_str("default_route").write_bool(s.default_route);
                    w.write_str("exclusive").write_bool(s.exclusive);
                    w.write_str("metric").write_uint(u64::from(s.metric));
                    w.write_str("level").write_str(s.level.as_str());
                }
            }
            Reply::Status(status) => {
                w.write_map(5).write_str("ok").write_bool(true);
                w.write_str("hostname").write_str(&status.hostname);
                w.write_str("level").write_str(status.level.as_str());
                write_opt_str(&mut w, "refusal", &status.refusal);
                w.write_str("interfaces")
                    .write_array(status.interfaces.len() as u32);
                for i in &status.interfaces {
                    encode_interface(&mut w, i);
                }
            }
        }
        w.to_bytes().expect("a reply encodes")
    }

    pub fn decode(bytes: &[u8]) -> Result<Reply, WireError> {
        let mut r = Reader::new(bytes);
        let mut ok = None;
        let mut error = None;
        let mut status = Status::default();
        let mut has_status = false;
        let mut snapshot = Snapshot::default();
        let mut kind = None;
        let mut seen = Vec::new();
        for_each_field(&mut r, &mut seen, |key, r| {
            match key {
                "ok" => ok = Some(r.read_bool()?),
                "error" => error = Some(r.read_str()?.to_owned()),
                "kind" => kind = Some(r.read_str()?.to_owned()),
                "scopes" => {
                    let n = r.read_array()?;
                    for _ in 0..n {
                        snapshot.scopes.push(decode_scope(r)?);
                    }
                }
                "hostname" => {
                    status.hostname = r.read_str()?.to_owned();
                    snapshot.hostname = status.hostname.clone();
                    has_status = true;
                }
                "level" => {
                    status.level = Level::parse(r.read_str()?).unwrap_or(Level::Absent);
                    has_status = true;
                }
                "refusal" => {
                    status.refusal = read_opt_str(r)?;
                    has_status = true;
                }
                "interfaces" => {
                    let n = r.read_array()?;
                    for _ in 0..n {
                        status.interfaces.push(decode_interface(r)?);
                    }
                    has_status = true;
                }
                _ => r.skip()?,
            }
            Ok(())
        })?;
        match ok {
            Some(true) if kind.as_deref() == Some("snapshot") => Ok(Reply::Snapshot(snapshot)),
            Some(true) if has_status => Ok(Reply::Status(status)),
            Some(true) => Ok(Reply::Ok),
            Some(false) => Ok(Reply::Error(
                error.unwrap_or_else(|| "unspecified error".to_owned()),
            )),
            None => Err(WireError::Missing("ok")),
        }
    }
}

fn write_str_list(w: &mut Writer, key: &str, items: &[String]) {
    w.write_str(key).write_array(items.len() as u32);
    for s in items {
        w.write_str(s);
    }
}

fn write_opt_str(w: &mut Writer, key: &str, v: &Option<String>) {
    w.write_str(key);
    match v {
        Some(s) => {
            w.write_str(s);
        }
        None => {
            w.write_nil();
        }
    }
}

fn encode_interface(w: &mut Writer, i: &InterfaceStatus) {
    w.write_map(22);
    w.write_str("ifid").write_str(&i.ifid);
    w.write_str("name").write_str(&i.name);
    w.write_str("index").write_uint(u64::from(i.index));
    w.write_str("mac").write_str(&i.mac);
    w.write_str("path").write_str(&i.path);
    w.write_str("driver").write_str(&i.driver);
    write_opt_str(w, "verdict", &i.verdict);
    write_opt_str(w, "rule", &i.rule);
    write_opt_str(w, "profile", &i.profile);
    write_opt_str(w, "network", &i.network);
    write_opt_str(w, "network_name", &i.network_name);
    write_opt_str(w, "network_trust", &i.network_trust);
    write_opt_str(w, "warning", &i.warning);
    w.write_str("up").write_bool(i.up);
    w.write_str("carrier").write_bool(i.carrier);
    w.write_str("level").write_str(i.level.as_str());
    write_str_list(w, "addresses", &i.addresses);
    write_opt_str(w, "gateway", &i.gateway);
    write_opt_str(w, "gateway6", &i.gateway6);
    write_str_list(w, "dns", &i.dns);
    write_str_list(w, "search", &i.search);
    w.write_str("lease");
    match &i.lease {
        None => {
            w.write_nil();
        }
        Some(l) => {
            w.write_map(6);
            w.write_str("server").write_str(&l.server);
            w.write_str("expires_in").write_uint(l.expires_in);
            w.write_str("state").write_str(&l.state);
            w.write_str("duration").write_uint(l.duration);
            w.write_str("renew_at").write_uint(l.renew_at);
            w.write_str("rebind_at").write_uint(l.rebind_at);
        }
    }
}

fn decode_scope(r: &mut Reader<'_>) -> Result<DnsScope, WireError> {
    let mut s = DnsScope::default();
    let mut seen = Vec::new();
    for_each_field(r, &mut seen, |key, r| {
        match key {
            "ifid" => s.ifid = r.read_str()?.to_owned(),
            "name" => s.name = r.read_str()?.to_owned(),
            "servers" => s.servers = read_str_list(r)?,
            "domains" => s.domains = read_str_list(r)?,
            "ntp" => s.ntp = read_str_list(r)?,
            "addresses" => s.addresses = read_str_list(r)?,
            "default_route" => s.default_route = r.read_bool()?,
            "exclusive" => s.exclusive = r.read_bool()?,
            "metric" => s.metric = r.read_uint()? as u32,
            "level" => s.level = Level::parse(r.read_str()?).unwrap_or(Level::Absent),
            _ => r.skip()?,
        }
        Ok(())
    })?;
    Ok(s)
}

fn read_str_list(r: &mut Reader<'_>) -> Result<Vec<String>, WireError> {
    let n = r.read_array()?;
    // Never allocate on a count the peer chose. An array header can claim
    // four billion elements in five bytes, and reserving for that is a
    // remote out-of-memory kill from a message smaller than this comment.
    // A real element costs at least one byte, so a count past what is left
    // in the message is a lie.
    if n > r.remaining() {
        return Err(WireError::TooLarge(n));
    }
    let mut out = Vec::new();
    for _ in 0..n {
        out.push(r.read_str()?.to_owned());
    }
    Ok(out)
}

fn read_opt_str(r: &mut Reader<'_>) -> Result<Option<String>, WireError> {
    if r.peek() == Some(Type::Nil) {
        r.read_nil()?;
        Ok(None)
    } else {
        Ok(Some(r.read_str()?.to_owned()))
    }
}

fn decode_interface(r: &mut Reader<'_>) -> Result<InterfaceStatus, WireError> {
    let mut i = InterfaceStatus::default();
    let mut seen = Vec::new();
    for_each_field(r, &mut seen, |key, r| {
        match key {
            "ifid" => i.ifid = r.read_str()?.to_owned(),
            "name" => i.name = r.read_str()?.to_owned(),
            "index" => i.index = r.read_uint()? as u32,
            "mac" => i.mac = r.read_str()?.to_owned(),
            "path" => i.path = r.read_str()?.to_owned(),
            "driver" => i.driver = r.read_str()?.to_owned(),
            "verdict" => i.verdict = read_opt_str(r)?,
            "rule" => i.rule = read_opt_str(r)?,
            "profile" => i.profile = read_opt_str(r)?,
            "network" => i.network = read_opt_str(r)?,
            "network_name" => i.network_name = read_opt_str(r)?,
            "network_trust" => i.network_trust = read_opt_str(r)?,
            "warning" => i.warning = read_opt_str(r)?,
            "up" => i.up = r.read_bool()?,
            "carrier" => i.carrier = r.read_bool()?,
            "level" => i.level = Level::parse(r.read_str()?).unwrap_or(Level::Absent),
            "addresses" => i.addresses = read_str_list(r)?,
            "gateway" => i.gateway = read_opt_str(r)?,
            "gateway6" => i.gateway6 = read_opt_str(r)?,
            "dns" => i.dns = read_str_list(r)?,
            "search" => i.search = read_str_list(r)?,
            "lease" => {
                if r.peek() == Some(Type::Nil) {
                    r.read_nil()?;
                } else {
                    let mut l = LeaseStatus::default();
                    let mut seen = Vec::new();
                    for_each_field(r, &mut seen, |key, r| {
                        match key {
                            "server" => l.server = r.read_str()?.to_owned(),
                            "expires_in" => l.expires_in = r.read_uint()?,
                            "state" => l.state = r.read_str()?.to_owned(),
                            "duration" => l.duration = r.read_uint()?,
                            "renew_at" => l.renew_at = r.read_uint()?,
                            "rebind_at" => l.rebind_at = r.read_uint()?,
                            _ => r.skip()?,
                        }
                        Ok(())
                    })?;
                    i.lease = Some(l);
                }
            }
            _ => r.skip()?,
        }
        Ok(())
    })?;
    Ok(i)
}

/// Walk a map's fields. Duplicate keys are a protocol error, unknown keys are
/// the caller's to skip.
fn for_each_field<'a>(
    r: &mut Reader<'a>,
    seen: &mut Vec<String>,
    mut f: impl FnMut(&str, &mut Reader<'a>) -> Result<(), WireError>,
) -> Result<(), WireError> {
    let n = r.read_map()?;
    for _ in 0..n {
        let key = r.read_str()?;
        if seen.iter().any(|s| s == key) {
            return Err(WireError::Duplicate(key.to_owned()));
        }
        seen.push(key.to_owned());
        f(key, r)?;
    }
    Ok(())
}

#[derive(Debug)]
pub enum WireError {
    Encoding(peios::Error),
    Missing(&'static str),
    Duplicate(String),
    UnknownQuery(String),
    TooLarge(usize),
    Io(io::Error),
}

impl std::fmt::Display for WireError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            WireError::Encoding(e) => write!(f, "malformed message: {e}"),
            WireError::Missing(k) => write!(f, "missing field {k}"),
            WireError::Duplicate(k) => write!(f, "duplicate field {k}"),
            WireError::UnknownQuery(q) => write!(f, "unknown query {q:?}"),
            WireError::TooLarge(n) => write!(f, "message of {n} bytes exceeds the ceiling"),
            WireError::Io(e) => write!(f, "{e}"),
        }
    }
}

impl std::error::Error for WireError {}

impl From<peios::Error> for WireError {
    fn from(e: peios::Error) -> Self {
        WireError::Encoding(e)
    }
}

impl From<io::Error> for WireError {
    fn from(e: io::Error) -> Self {
        WireError::Io(e)
    }
}

/// Write one length-prefixed message.
pub fn send(stream: &mut UnixStream, payload: &[u8]) -> Result<(), WireError> {
    if payload.len() > MAX_MESSAGE_BYTES {
        return Err(WireError::TooLarge(payload.len()));
    }
    let len = (payload.len() as u32).to_le_bytes();
    stream.write_all(&len)?;
    stream.write_all(payload)?;
    stream.flush()?;
    Ok(())
}

/// Read one length-prefixed message. An oversized length is refused before
/// its payload is read, as the observability book requires.
pub fn recv(stream: &mut UnixStream) -> Result<Vec<u8>, WireError> {
    let mut len = [0u8; 4];
    stream.read_exact(&mut len)?;
    let len = u32::from_le_bytes(len) as usize;
    if len > MAX_MESSAGE_BYTES {
        return Err(WireError::TooLarge(len));
    }
    let mut payload = vec![0u8; len];
    stream.read_exact(&mut payload)?;
    Ok(payload)
}

/// Send a request and read the reply.
pub fn call(stream: &mut UnixStream, request: &Request) -> Result<Reply, WireError> {
    send(stream, &request.encode())?;
    let bytes = recv(stream)?;
    Reply::decode(&bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn requests_round_trip() {
        for req in [
            Request::Status,
            Request::Reconcile,
            Request::Renew {
                interface: "eth0".into(),
            },
            Request::Subscribe,
        ] {
            assert_eq!(Request::decode(&req.encode()).unwrap(), req);
        }
    }

    #[test]
    fn a_status_round_trips_with_every_field() {
        let status = Status {
            hostname: "box".into(),
            level: Level::Routed,
            refusal: Some("rules a vs b tie on interface eth1".into()),
            interfaces: vec![InterfaceStatus {
                ifid: "id".into(),
                name: "eth0".into(),
                index: 2,
                mac: "52:54:00:12:34:56".into(),
                path: "pci-0000:00:03.0".into(),
                driver: "virtio_net".into(),
                profile: Some("lan".into()),
                verdict: Some("JOIN".into()),
                rule: Some("wired".into()),
                network: Some("net-1".into()),
                network_name: Some("office".into()),
                network_trust: Some("corporate".into()),
                warning: Some("asked for an address; nobody answered".into()),
                up: true,
                carrier: true,
                level: Level::Routed,
                addresses: vec!["10.0.2.15/24".into(), "fd00::1234/64".into()],
                gateway: Some("10.0.2.2".into()),
                gateway6: Some("fe80::2".into()),
                dns: vec!["10.0.2.3".into(), "fd00::3".into()],
                search: vec![],
                lease: Some(LeaseStatus {
                    server: "10.0.2.2".into(),
                    expires_in: 86000,
                    state: "bound".into(),
                    duration: 86400,
                    renew_at: 43200,
                    rebind_at: 75600,
                }),
            }],
        };
        let reply = Reply::Status(status);
        assert_eq!(Reply::decode(&reply.encode()).unwrap(), reply);
        assert_eq!(Reply::decode(&Reply::Ok.encode()).unwrap(), Reply::Ok);
        let e = Reply::Error("no".into());
        assert_eq!(Reply::decode(&e.encode()).unwrap(), e);
    }

    #[test]
    fn a_duplicate_key_is_refused_and_an_unknown_one_ignored() {
        let mut w = Writer::new();
        w.write_map(2)
            .write_str("query")
            .write_str("status")
            .write_str("query")
            .write_str("status");
        assert!(matches!(
            Request::decode(&w.to_bytes().unwrap()),
            Err(WireError::Duplicate(_))
        ));
        let mut w = Writer::new();
        w.write_map(2)
            .write_str("extra")
            .write_uint(3)
            .write_str("query")
            .write_str("status");
        assert_eq!(
            Request::decode(&w.to_bytes().unwrap()).unwrap(),
            Request::Status
        );
    }

    #[test]
    fn a_snapshot_round_trips() {
        let reply = Reply::Snapshot(Snapshot {
            hostname: "box".into(),
            scopes: vec![DnsScope {
                ifid: "id".into(),
                name: "eth0".into(),
                servers: vec!["10.0.2.3".into()],
                domains: vec!["lan".into()],
                ntp: vec!["10.0.2.4".into()],
                addresses: vec!["10.0.2.15/24".into()],
                default_route: true,
                exclusive: false,
                metric: 100,
                level: Level::Routed,
            }],
        });
        assert_eq!(Reply::decode(&reply.encode()).unwrap(), reply);
        let empty = Reply::Snapshot(Snapshot::default());
        assert_eq!(Reply::decode(&empty.encode()).unwrap(), empty);
    }

    #[test]
    fn an_array_count_the_message_cannot_hold_is_refused() {
        // Built by hand, because the writer will not emit a message whose
        // declared count does not match what follows — which is exactly the
        // message an attacker sends. A snapshot holding one scope whose
        // server list declares four billion entries in five bytes.
        // Reserving for that is a remote out-of-memory kill on a socket
        // every program on the machine may connect to.
        let mut bytes = vec![0x82];
        bytes.push(0xa0 | 4);
        bytes.extend_from_slice(b"kind");
        bytes.push(0xa0 | 8);
        bytes.extend_from_slice(b"snapshot");
        bytes.push(0xa0 | 6);
        bytes.extend_from_slice(b"scopes");
        bytes.push(0x91); // one scope
        bytes.push(0x81); // a map of one
        bytes.push(0xa0 | 7);
        bytes.extend_from_slice(b"servers");
        bytes.extend_from_slice(&[0xdd, 0xff, 0xff, 0xff, 0xff]);
        assert!(
            matches!(Reply::decode(&bytes), Err(WireError::TooLarge(_))),
            "{:?}",
            Reply::decode(&bytes)
        );
    }

    #[test]
    fn levels_are_ordered() {
        assert!(Level::Absent < Level::Link);
        assert!(Level::Link < Level::Addressed);
        assert!(Level::Addressed < Level::Routed);
        assert_eq!(Level::parse("routed"), Some(Level::Routed));
    }
}

#[cfg(test)]
mod fuzz_tests {
    //! Noise and mutations through the control-socket decoders. Everyone
    //! may connect to the socket, so the decoder sees untrusted bytes.
    use super::*;

    #[test]
    fn fuzz_decoders_never_panic() {
        let iters: usize = std::env::var("NETD_FUZZ_ITERS")
            .ok()
            .and_then(|s| s.parse().ok())
            .unwrap_or(20_000);
        let mut x: u64 = 0x1234_5678_9abc_def1;
        let mut next = move || {
            x ^= x >> 12;
            x ^= x << 25;
            x ^= x >> 27;
            x.wrapping_mul(0x2545_F491_4F6C_DD1D)
        };
        let seeds = [
            Request::Renew {
                interface: "eth0".into(),
            }
            .encode(),
            Request::Subscribe.encode(),
            Reply::Snapshot(Snapshot {
                hostname: "h".into(),
                scopes: vec![DnsScope::default()],
            })
            .encode(),
            Reply::Status(Status {
                interfaces: vec![InterfaceStatus::default()],
                ..Default::default()
            })
            .encode(),
        ];
        for _ in 0..iters {
            let mut bytes = if next() % 4 == 0 {
                (0..(next() % 200) as usize)
                    .map(|_| next() as u8)
                    .collect::<Vec<u8>>()
            } else {
                seeds[(next() % 4) as usize].clone()
            };
            for _ in 0..1 + next() % 5 {
                if bytes.is_empty() {
                    break;
                }
                let at = (next() % bytes.len() as u64) as usize;
                match next() % 3 {
                    0 => bytes[at] = next() as u8,
                    1 => bytes.truncate(at),
                    _ => bytes.insert(at, next() as u8),
                }
            }
            if let Ok(r) = Request::decode(&bytes) {
                assert_eq!(Request::decode(&r.encode()).unwrap(), r);
            }
            if let Ok(r) = Reply::decode(&bytes) {
                let _ = Reply::decode(&r.encode()).unwrap();
            }
        }
    }
}
