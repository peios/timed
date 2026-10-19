//! resolvd's native wire: `/run/resolvd/resolv.sock`.
//!
//! A PSPU query channel in the observability book's framing — a `SOCK_STREAM`
//! socket carrying length-prefixed MessagePack maps, one request and one reply
//! per connection:
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
//! The protocol is **RR-level**: a lookup names a question (name, type) and
//! the answer is records with TTLs, where they came from, and a validation
//! state — never an `addrinfo`. The one convenience is `lookup`, which asks
//! for the addresses of a name in both families at once, because that is the
//! question every `getaddrinfo` asks and two round trips for it would be
//! two chances to disagree.
//!
//! This crate is inert: types and a codec, no policy, and no dependency on
//! libpeios — it is linked into the NSS shim that every process loads.

#![forbid(unsafe_code)]

pub mod msgpack;

use std::io::{self, Read, Write};
use std::net::IpAddr;
use std::os::unix::net::UnixStream;

use msgpack::{Reader, Type, Writer};

/// resolvd's runtime directory, created by peinit (`RuntimeDirectories`).
pub const RESOLVD_RUN_DIR: &str = "/run/resolvd";
/// The native socket. Inside the runtime directory rather than at
/// `/run/resolv.sock` because resolvd is not SYSTEM and `/run` itself is.
pub const SOCKET_PATH: &str = "/run/resolvd/resolv.sock";
/// The stub listener: DNS over UDP and TCP, loopback only.
pub const STUB_ADDRESS: &str = "127.0.0.53";
pub const STUB_PORT: u16 = 53;

/// The registry key resolvd reads.
pub const RESOLVER_KEY: &str = "Machine\\System\\Network\\Dns";

/// Rights on the resolvd control object.
///
/// Checked against `Machine\System\Network\Dns ControlSecurity` when it
/// exists, else the compiled default: Everyone may query, SYSTEM and
/// Administrators may control.
pub const RESOLVER_QUERY: u32 = 0x0000_0001;
pub const RESOLVER_CONTROL: u32 = 0x0000_0002;
pub const RESOLVER_ALL_ACCESS: u32 = RESOLVER_QUERY | RESOLVER_CONTROL | 0x000F_0000;

/// Ceiling on one message, payload only.
pub const MAX_MESSAGE_BYTES: usize = 65_536;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Family {
    Any,
    V4,
    V6,
}

impl Family {
    pub fn as_str(self) -> &'static str {
        match self {
            Family::Any => "any",
            Family::V4 => "inet",
            Family::V6 => "inet6",
        }
    }

    fn parse(s: &str) -> Option<Family> {
        Some(match s {
            "any" => Family::Any,
            "inet" => Family::V4,
            "inet6" => Family::V6,
            _ => return None,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Request {
    /// One question: records of `rtype` at `name`.
    Resolve {
        name: String,
        rtype: u16,
        no_cache: bool,
    },
    /// The addresses of a name — A and/or AAAA, search expansion applied,
    /// canonical name chased. What `getaddrinfo` asks.
    Lookup { name: String, family: Family },
    /// The names of an address.
    Reverse { address: IpAddr },
    /// Scopes, counters, cache size.
    Status,
    /// Drop every cached answer.
    Flush,
}

impl Request {
    pub fn encode(&self) -> Vec<u8> {
        let mut w = Writer::new();
        match self {
            Request::Resolve {
                name,
                rtype,
                no_cache,
            } => {
                w.write_map(4)
                    .write_str("query")
                    .write_str("resolve")
                    .write_str("name")
                    .write_str(name)
                    .write_str("type")
                    .write_uint(u64::from(*rtype))
                    .write_str("no_cache")
                    .write_bool(*no_cache);
            }
            Request::Lookup { name, family } => {
                w.write_map(3)
                    .write_str("query")
                    .write_str("lookup")
                    .write_str("name")
                    .write_str(name)
                    .write_str("family")
                    .write_str(family.as_str());
            }
            Request::Reverse { address } => {
                w.write_map(2)
                    .write_str("query")
                    .write_str("reverse")
                    .write_str("address")
                    .write_str(&address.to_string());
            }
            Request::Status => {
                w.write_map(1).write_str("query").write_str("status");
            }
            Request::Flush => {
                w.write_map(1).write_str("query").write_str("flush");
            }
        }
        w.into_bytes()
    }

    pub fn decode(bytes: &[u8]) -> Result<Request, WireError> {
        let mut r = Reader::new(bytes);
        let mut query = None;
        let mut name = None;
        let mut rtype = None;
        let mut no_cache = false;
        let mut family = None;
        let mut address = None;
        let mut seen = Vec::new();
        for_each_field(&mut r, &mut seen, |key, r| {
            match key {
                "query" => query = Some(r.read_str()?.to_owned()),
                "name" => name = Some(r.read_str()?.to_owned()),
                "type" => {
                    rtype = Some(
                        u16::try_from(r.read_uint()?).map_err(|_| WireError::Missing("type"))?,
                    )
                }
                "no_cache" => no_cache = r.read_bool()?,
                "family" => family = Family::parse(r.read_str()?),
                "address" => address = Some(r.read_str()?.to_owned()),
                _ => r.skip()?,
            }
            Ok(())
        })?;
        match query.as_deref() {
            Some("resolve") => Ok(Request::Resolve {
                name: name.ok_or(WireError::Missing("name"))?,
                rtype: rtype.ok_or(WireError::Missing("type"))?,
                no_cache,
            }),
            Some("lookup") => Ok(Request::Lookup {
                name: name.ok_or(WireError::Missing("name"))?,
                family: family.unwrap_or(Family::Any),
            }),
            Some("reverse") => {
                let a = address.ok_or(WireError::Missing("address"))?;
                Ok(Request::Reverse {
                    address: a.parse().map_err(|_| WireError::Missing("address"))?,
                })
            }
            Some("status") => Ok(Request::Status),
            Some("flush") => Ok(Request::Flush),
            Some(other) => Err(WireError::UnknownQuery(other.to_owned())),
            None => Err(WireError::Missing("query")),
        }
    }

    pub fn required_right(&self) -> u32 {
        match self {
            Request::Flush => RESOLVER_CONTROL,
            _ => RESOLVER_QUERY,
        }
    }
}

/// How a question ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Outcome {
    /// Records follow. (A name that exists with no records of the type is
    /// `Found` with none — NODATA — which is not `NotFound`.)
    Found,
    /// The name does not exist, authoritatively. Cacheable.
    NotFound,
    /// Nothing that could answer did. Never cached, never an absence.
    #[default]
    Unavailable,
}

impl Outcome {
    pub fn as_str(self) -> &'static str {
        match self {
            Outcome::Found => "found",
            Outcome::NotFound => "notfound",
            Outcome::Unavailable => "unavailable",
        }
    }

    fn parse(s: &str) -> Option<Outcome> {
        Some(match s {
            "found" => Outcome::Found,
            "notfound" => Outcome::NotFound,
            "unavailable" => Outcome::Unavailable,
            _ => return None,
        })
    }
}

/// DNSSEC state of an answer. v1 never validates, so every answer from the
/// network is `Unvalidated`; the field exists so callers are written against
/// it from the start.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Validation {
    #[default]
    Unvalidated,
    Secure,
    Insecure,
    Bogus,
}

impl Validation {
    pub fn as_str(self) -> &'static str {
        match self {
            Validation::Unvalidated => "unvalidated",
            Validation::Secure => "secure",
            Validation::Insecure => "insecure",
            Validation::Bogus => "bogus",
        }
    }

    fn parse(s: &str) -> Option<Validation> {
        Some(match s {
            "unvalidated" => Validation::Unvalidated,
            "secure" => Validation::Secure,
            "insecure" => Validation::Insecure,
            "bogus" => Validation::Bogus,
            _ => return None,
        })
    }
}

/// One resource record as reported.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct RecordOut {
    pub name: String,
    pub rtype: u16,
    pub ttl: u32,
    /// The rdata in wire form, uncompressed.
    pub data: Vec<u8>,
    /// The rdata in presentation form.
    pub text: String,
}

/// The reply to `resolve` and `reverse`.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Answer {
    pub outcome: Outcome,
    pub records: Vec<RecordOut>,
    /// `synthetic`, `hosts`, `cache`, `dns`.
    pub source: String,
    /// The upstream that answered, for `dns`.
    pub server: Option<String>,
    /// The interface whose scope answered.
    pub interface: Option<String>,
    pub validation: Validation,
    /// The DNS response code, for `dns`.
    pub rcode: u16,
}

/// One address from `lookup`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AddressOut {
    pub address: IpAddr,
    pub ttl: u32,
}

/// The reply to `lookup`.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Addresses {
    pub outcome: Outcome,
    /// The name the addresses belong to after CNAME chasing and search
    /// expansion; the name asked for when neither applied.
    pub canonical: String,
    pub addresses: Vec<AddressOut>,
    pub source: String,
    pub validation: Validation,
}

/// One scope in `status`: an interface's contribution.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ScopeStatus {
    pub interface: String,
    pub servers: Vec<String>,
    pub domains: Vec<String>,
    pub default_route: bool,
    pub exclusive: bool,
    pub metric: u32,
    pub subnets: Vec<String>,
    /// Servers currently demoted after failures.
    pub demoted: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Counters {
    pub queries: u64,
    pub synthetic: u64,
    pub cache_hits: u64,
    pub upstream_sent: u64,
    pub upstream_answered: u64,
    pub upstream_failed: u64,
    pub refused: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct StatusReport {
    pub hostname: String,
    /// Whether the netd channel is up.
    pub netd: bool,
    pub scopes: Vec<ScopeStatus>,
    pub fallback_servers: Vec<String>,
    pub cache_entries: u64,
    pub counters: Counters,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Reply {
    Ok,
    Error(String),
    Answer(Answer),
    Addresses(Addresses),
    Status(StatusReport),
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
        Some(s) => w.write_str(s),
        None => w.write_nil(),
    };
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
            Reply::Answer(a) => {
                w.write_map(9).write_str("ok").write_bool(true);
                w.write_str("kind").write_str("answer");
                w.write_str("outcome").write_str(a.outcome.as_str());
                w.write_str("records").write_array(a.records.len() as u32);
                for r in &a.records {
                    w.write_map(5);
                    w.write_str("name").write_str(&r.name);
                    w.write_str("type").write_uint(u64::from(r.rtype));
                    w.write_str("ttl").write_uint(u64::from(r.ttl));
                    w.write_str("data").write_bin(&r.data);
                    w.write_str("text").write_str(&r.text);
                }
                w.write_str("source").write_str(&a.source);
                write_opt_str(&mut w, "server", &a.server);
                write_opt_str(&mut w, "interface", &a.interface);
                w.write_str("validation").write_str(a.validation.as_str());
                w.write_str("rcode").write_uint(u64::from(a.rcode));
            }
            Reply::Addresses(a) => {
                w.write_map(7).write_str("ok").write_bool(true);
                w.write_str("kind").write_str("addresses");
                w.write_str("outcome").write_str(a.outcome.as_str());
                w.write_str("canonical").write_str(&a.canonical);
                w.write_str("addresses")
                    .write_array(a.addresses.len() as u32);
                for x in &a.addresses {
                    w.write_map(2);
                    w.write_str("address").write_str(&x.address.to_string());
                    w.write_str("ttl").write_uint(u64::from(x.ttl));
                }
                w.write_str("source").write_str(&a.source);
                w.write_str("validation").write_str(a.validation.as_str());
            }
            Reply::Status(s) => {
                w.write_map(8).write_str("ok").write_bool(true);
                w.write_str("kind").write_str("status");
                w.write_str("hostname").write_str(&s.hostname);
                w.write_str("netd").write_bool(s.netd);
                w.write_str("scopes").write_array(s.scopes.len() as u32);
                for sc in &s.scopes {
                    w.write_map(8);
                    w.write_str("interface").write_str(&sc.interface);
                    write_str_list(&mut w, "servers", &sc.servers);
                    write_str_list(&mut w, "domains", &sc.domains);
                    w.write_str("default_route").write_bool(sc.default_route);
                    w.write_str("exclusive").write_bool(sc.exclusive);
                    w.write_str("metric").write_uint(u64::from(sc.metric));
                    write_str_list(&mut w, "subnets", &sc.subnets);
                    write_str_list(&mut w, "demoted", &sc.demoted);
                }
                write_str_list(&mut w, "fallback_servers", &s.fallback_servers);
                w.write_str("cache_entries").write_uint(s.cache_entries);
                let c = &s.counters;
                w.write_str("counters").write_map(7);
                for (k, v) in [
                    ("queries", c.queries),
                    ("synthetic", c.synthetic),
                    ("cache_hits", c.cache_hits),
                    ("upstream_sent", c.upstream_sent),
                    ("upstream_answered", c.upstream_answered),
                    ("upstream_failed", c.upstream_failed),
                    ("refused", c.refused),
                ] {
                    w.write_str(k).write_uint(v);
                }
            }
        }
        w.into_bytes()
    }

    pub fn decode(bytes: &[u8]) -> Result<Reply, WireError> {
        let mut r = Reader::new(bytes);
        let mut ok = None;
        let mut error = None;
        let mut kind = None;
        let mut answer = Answer::default();
        let mut addresses = Addresses::default();
        let mut status = StatusReport::default();
        let mut seen = Vec::new();
        for_each_field(&mut r, &mut seen, |key, r| {
            match key {
                "ok" => ok = Some(r.read_bool()?),
                "error" => error = Some(r.read_str()?.to_owned()),
                "kind" => kind = Some(r.read_str()?.to_owned()),
                "outcome" => {
                    let o = Outcome::parse(r.read_str()?).unwrap_or_default();
                    answer.outcome = o;
                    addresses.outcome = o;
                }
                "validation" => {
                    let v = Validation::parse(r.read_str()?).unwrap_or_default();
                    answer.validation = v;
                    addresses.validation = v;
                }
                "source" => {
                    let s = r.read_str()?.to_owned();
                    answer.source = s.clone();
                    addresses.source = s;
                }
                "server" => answer.server = read_opt_str(r)?,
                "interface" => answer.interface = read_opt_str(r)?,
                "rcode" => answer.rcode = r.read_uint()? as u16,
                "records" => {
                    let n = r.read_array()?;
                    for _ in 0..n {
                        let mut rec = RecordOut::default();
                        let mut seen = Vec::new();
                        for_each_field(r, &mut seen, |key, r| {
                            match key {
                                "name" => rec.name = r.read_str()?.to_owned(),
                                "type" => rec.rtype = r.read_uint()? as u16,
                                "ttl" => rec.ttl = r.read_uint()? as u32,
                                "data" => rec.data = r.read_bin()?.to_vec(),
                                "text" => rec.text = r.read_str()?.to_owned(),
                                _ => r.skip()?,
                            }
                            Ok(())
                        })?;
                        answer.records.push(rec);
                    }
                }
                "canonical" => addresses.canonical = r.read_str()?.to_owned(),
                "addresses" => {
                    let n = r.read_array()?;
                    for _ in 0..n {
                        let mut address = None;
                        let mut ttl = 0;
                        let mut seen = Vec::new();
                        for_each_field(r, &mut seen, |key, r| {
                            match key {
                                "address" => address = r.read_str()?.parse::<IpAddr>().ok(),
                                "ttl" => ttl = r.read_uint()? as u32,
                                _ => r.skip()?,
                            }
                            Ok(())
                        })?;
                        if let Some(address) = address {
                            addresses.addresses.push(AddressOut { address, ttl });
                        }
                    }
                }
                "hostname" => status.hostname = r.read_str()?.to_owned(),
                "netd" => status.netd = r.read_bool()?,
                "fallback_servers" => status.fallback_servers = read_str_list(r)?,
                "cache_entries" => status.cache_entries = r.read_uint()?,
                "scopes" => {
                    let n = r.read_array()?;
                    for _ in 0..n {
                        let mut sc = ScopeStatus::default();
                        let mut seen = Vec::new();
                        for_each_field(r, &mut seen, |key, r| {
                            match key {
                                "interface" => sc.interface = r.read_str()?.to_owned(),
                                "servers" => sc.servers = read_str_list(r)?,
                                "domains" => sc.domains = read_str_list(r)?,
                                "default_route" => sc.default_route = r.read_bool()?,
                                "exclusive" => sc.exclusive = r.read_bool()?,
                                "metric" => sc.metric = r.read_uint()? as u32,
                                "subnets" => sc.subnets = read_str_list(r)?,
                                "demoted" => sc.demoted = read_str_list(r)?,
                                _ => r.skip()?,
                            }
                            Ok(())
                        })?;
                        status.scopes.push(sc);
                    }
                }
                "counters" => {
                    let c = &mut status.counters;
                    let mut seen = Vec::new();
                    for_each_field(r, &mut seen, |key, r| {
                        match key {
                            "queries" => c.queries = r.read_uint()?,
                            "synthetic" => c.synthetic = r.read_uint()?,
                            "cache_hits" => c.cache_hits = r.read_uint()?,
                            "upstream_sent" => c.upstream_sent = r.read_uint()?,
                            "upstream_answered" => c.upstream_answered = r.read_uint()?,
                            "upstream_failed" => c.upstream_failed = r.read_uint()?,
                            "refused" => c.refused = r.read_uint()?,
                            _ => r.skip()?,
                        }
                        Ok(())
                    })?;
                }
                _ => r.skip()?,
            }
            Ok(())
        })?;
        match (ok, kind.as_deref()) {
            (Some(false), _) => Ok(Reply::Error(
                error.unwrap_or_else(|| "unspecified error".to_owned()),
            )),
            (Some(true), Some("answer")) => Ok(Reply::Answer(answer)),
            (Some(true), Some("addresses")) => Ok(Reply::Addresses(addresses)),
            (Some(true), Some("status")) => Ok(Reply::Status(status)),
            (Some(true), _) => Ok(Reply::Ok),
            (None, _) => Err(WireError::Missing("ok")),
        }
    }
}

fn read_str_list(r: &mut Reader<'_>) -> Result<Vec<String>, WireError> {
    let n = r.read_array()?;
    let mut out = Vec::with_capacity(n);
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

/// Walk a map's fields. Duplicate keys are a protocol error, unknown keys
/// are the caller's to skip.
pub fn for_each_field<'a>(
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
    Encoding(msgpack::Error),
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
            WireError::Missing(k) => write!(f, "missing or malformed field {k}"),
            WireError::Duplicate(k) => write!(f, "duplicate field {k}"),
            WireError::UnknownQuery(q) => write!(f, "unknown query {q:?}"),
            WireError::TooLarge(n) => write!(f, "message of {n} bytes exceeds the ceiling"),
            WireError::Io(e) => write!(f, "{e}"),
        }
    }
}

impl std::error::Error for WireError {}

impl From<msgpack::Error> for WireError {
    fn from(e: msgpack::Error) -> Self {
        WireError::Encoding(e)
    }
}

impl From<io::Error> for WireError {
    fn from(e: io::Error) -> Self {
        WireError::Io(e)
    }
}

/// Write one length-prefixed message.
pub fn send(stream: &mut impl Write, payload: &[u8]) -> Result<(), WireError> {
    if payload.len() > MAX_MESSAGE_BYTES {
        return Err(WireError::TooLarge(payload.len()));
    }
    let mut frame = Vec::with_capacity(4 + payload.len());
    frame.extend_from_slice(&(payload.len() as u32).to_le_bytes());
    frame.extend_from_slice(payload);
    stream.write_all(&frame)?;
    stream.flush()?;
    Ok(())
}

/// Read one length-prefixed message. An oversized length is refused before
/// its payload is read.
pub fn recv(stream: &mut impl Read) -> Result<Vec<u8>, WireError> {
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

/// Send a request and read the reply on an open connection.
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
            Request::Resolve {
                name: "example.com".into(),
                rtype: 1,
                no_cache: true,
            },
            Request::Lookup {
                name: "host".into(),
                family: Family::V6,
            },
            Request::Reverse {
                address: "10.0.2.15".parse().unwrap(),
            },
            Request::Status,
            Request::Flush,
        ] {
            assert_eq!(Request::decode(&req.encode()).unwrap(), req);
        }
        assert_eq!(Request::Flush.required_right(), RESOLVER_CONTROL);
        assert_eq!(Request::Status.required_right(), RESOLVER_QUERY);
    }

    #[test]
    fn replies_round_trip() {
        let answer = Reply::Answer(Answer {
            outcome: Outcome::Found,
            records: vec![RecordOut {
                name: "example.com".into(),
                rtype: 1,
                ttl: 30,
                data: vec![1, 2, 3, 4],
                text: "1.2.3.4".into(),
            }],
            source: "dns".into(),
            server: Some("10.0.2.3".into()),
            interface: Some("eth0".into()),
            validation: Validation::Unvalidated,
            rcode: 0,
        });
        assert_eq!(Reply::decode(&answer.encode()).unwrap(), answer);
        let addresses = Reply::Addresses(Addresses {
            outcome: Outcome::Found,
            canonical: "example.com".into(),
            addresses: vec![AddressOut {
                address: "1.2.3.4".parse().unwrap(),
                ttl: 30,
            }],
            source: "cache".into(),
            validation: Validation::Unvalidated,
        });
        assert_eq!(Reply::decode(&addresses.encode()).unwrap(), addresses);
        let status = Reply::Status(StatusReport {
            hostname: "box".into(),
            netd: true,
            scopes: vec![ScopeStatus {
                interface: "eth0".into(),
                servers: vec!["10.0.2.3".into()],
                domains: vec!["lan".into()],
                default_route: true,
                exclusive: false,
                metric: 100,
                subnets: vec!["10.0.2.0/24".into()],
                demoted: vec![],
            }],
            fallback_servers: vec![],
            cache_entries: 3,
            counters: Counters {
                queries: 9,
                cache_hits: 2,
                ..Default::default()
            },
        });
        assert_eq!(Reply::decode(&status.encode()).unwrap(), status);
        assert_eq!(Reply::decode(&Reply::Ok.encode()).unwrap(), Reply::Ok);
        let e = Reply::Error("no".into());
        assert_eq!(Reply::decode(&e.encode()).unwrap(), e);
    }

    #[test]
    fn framing_round_trips_and_refuses_oversize() {
        let mut buf = Vec::new();
        send(&mut buf, b"abc").unwrap();
        assert_eq!(buf, [3, 0, 0, 0, b'a', b'b', b'c']);
        assert_eq!(recv(&mut &buf[..]).unwrap(), b"abc");
        let big = [0xffu8, 0xff, 0xff, 0x00];
        assert!(matches!(recv(&mut &big[..]), Err(WireError::TooLarge(_))));
    }
}

#[cfg(test)]
mod fuzz_tests {
    //! Noise and mutations through every decoder; nothing may panic and
    //! whatever decodes must round-trip. `RESOLV_FUZZ_ITERS` raises the
    //! count; the cargo-fuzz target in `fuzz/` is the real campaign.
    use super::*;

    struct Rng(u64);
    impl Rng {
        fn next(&mut self) -> u64 {
            let mut x = self.0;
            x ^= x >> 12;
            x ^= x << 25;
            x ^= x >> 27;
            self.0 = x;
            x.wrapping_mul(0x2545_F491_4F6C_DD1D)
        }
        fn below(&mut self, n: usize) -> usize {
            (self.next() % n.max(1) as u64) as usize
        }
    }

    #[test]
    fn fuzz_decoders_never_panic() {
        let iters: usize = std::env::var("RESOLV_FUZZ_ITERS")
            .ok()
            .and_then(|s| s.parse().ok())
            .unwrap_or(20_000);
        let mut rng = Rng(0xc0de);
        let seeds: Vec<Vec<u8>> = vec![
            Request::Resolve {
                name: "a.example".into(),
                rtype: 1,
                no_cache: true,
            }
            .encode(),
            Request::Lookup {
                name: "x".into(),
                family: Family::V6,
            }
            .encode(),
            Request::Reverse {
                address: "10.0.0.1".parse().unwrap(),
            }
            .encode(),
            Reply::Answer(Answer {
                records: vec![RecordOut {
                    name: "a".into(),
                    rtype: 1,
                    ttl: 1,
                    data: vec![1],
                    text: "t".into(),
                }],
                ..Default::default()
            })
            .encode(),
            Reply::Status(StatusReport {
                scopes: vec![ScopeStatus::default()],
                ..Default::default()
            })
            .encode(),
            Reply::Addresses(Addresses {
                addresses: vec![AddressOut {
                    address: "::1".parse().unwrap(),
                    ttl: 2,
                }],
                ..Default::default()
            })
            .encode(),
        ];
        for _ in 0..iters {
            let mut bytes = if rng.below(4) == 0 {
                (0..rng.below(200)).map(|_| rng.next() as u8).collect()
            } else {
                seeds[rng.below(seeds.len())].clone()
            };
            for _ in 0..1 + rng.below(5) {
                if bytes.is_empty() {
                    break;
                }
                let at = rng.below(bytes.len());
                match rng.below(3) {
                    0 => bytes[at] = rng.next() as u8,
                    1 => bytes.truncate(at),
                    _ => bytes.insert(at, rng.next() as u8),
                }
            }
            if let Ok(r) = Request::decode(&bytes) {
                assert_eq!(Request::decode(&r.encode()).unwrap(), r);
            }
            if let Ok(r) = Reply::decode(&bytes) {
                let _ = Reply::decode(&r.encode()).unwrap();
            }
            let _ = msgpack::Reader::new(&bytes).skip();
            let _ = recv(&mut &bytes[..]);
        }
    }
}
