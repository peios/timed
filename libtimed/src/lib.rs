//! timed's control wire.
//!
//! A PSPU observability *query* channel (§3.15): a `SOCK_STREAM` socket
//! carrying length-prefixed MessagePack maps, one request and one reply per
//! connection — with `subscribe` as the exception that keeps the connection
//! open, as on netd's and trustd's channels.
//!
//! ```text
//! +---------------------+------------------------+
//! | length u32 LE       | payload (MessagePack)  |
//! +---------------------+------------------------+
//! ```
//!
//! # Who reads this
//!
//! Two consumers, wanting different things.
//!
//! `clock`, the operator command, asks [`Request::Status`] and
//! [`Request::Sources`] and prints them. That is the obvious one.
//!
//! The other is the future NTP **server** package, which subscribes and
//! receives a [`Snapshot`] after every completed poll. That is the whole
//! reason timed and the server are separate processes: the client holds the
//! privilege to set the clock and listens on nothing, while the server is
//! exposed on UDP 123 to the entire domain and needs no privilege at all,
//! because everything it must say about the machine's time arrives here.
//! A snapshot carries exactly the fields an NTP reply needs and no more.
//!
//! This crate is inert: types and a codec, nothing that can act.

use std::io::{self, Read, Write};
use std::os::unix::net::UnixStream;

use peios::msgpack::{Reader, Type, Writer};

/// timed's runtime directory. peinit creates it (`RuntimeDirectories`).
pub const TIMED_RUN_DIR: &str = "/run/timed";
/// The control socket.
pub const SOCKET_PATH: &str = "/run/timed/time.sock";

/// Durable state: the drift file and the NTS cookie store. A pre-start hook
/// running as SYSTEM creates it with a descriptor naming timed's service
/// SID, because timed itself is not privileged enough to make a directory
/// under `/var/state`.
pub const STATE_DIR: &str = "/var/state/timed";
/// The learned frequency, one line of text. Worth a great deal: a machine
/// that remembers its crystal was 12 ppm fast is within milliseconds an
/// hour after boot rather than tens of seconds.
pub const DRIFT_FILE: &str = "/var/state/timed/drift";
/// NTS cookies, one file per source. Persisted so that a reboot does not
/// require a fresh TLS handshake with every server before the clock can be
/// set — which on a machine whose clock is wrong is precisely the handshake
/// most likely to fail.
pub const COOKIE_DIR: &str = "/var/state/timed/cookies";

/// The registry subtree timed reads.
pub const TIME_KEY: &str = "Machine\\System\\Time";
/// `Servers` REG_MULTI_SZ: explicit sources, highest precedence. Each entry
/// is a host, optionally `host:port`, optionally prefixed with a flag word
/// (see the regman documentation).
pub const SERVERS_VALUE: &str = "Servers";
/// `AllowUnauthenticated` REG_DWORD, default 0. Permits plain NTP where NTS
/// is impossible. Off by default because the honest state on a network that
/// blocks port 4460 is "unsynchronised", not "synchronised to whoever
/// answered".
pub const ALLOW_UNAUTHENTICATED_VALUE: &str = "AllowUnauthenticated";
/// `UseFromDHCP` REG_DWORD, default 0. DHCP option 42. Off by default, as
/// on Windows: on a hostile network the DHCP server's idea of the time is
/// the attacker's idea of the time.
pub const USE_FROM_DHCP_VALUE: &str = "UseFromDHCP";
/// `MinPoll` / `MaxPoll` REG_DWORD, log2 seconds.
pub const MIN_POLL_VALUE: &str = "MinPoll";
pub const MAX_POLL_VALUE: &str = "MaxPoll";
/// `SyncRTC` REG_DWORD, default 1. Write the disciplined time back to the
/// hardware clock periodically, so the next boot starts close.
pub const SYNC_RTC_VALUE: &str = "SyncRTC";
/// `ControlSecurity` REG_BINARY: the control object's descriptor.
pub const CONTROL_SECURITY_VALUE: &str = "ControlSecurity";

/// Rights on the control object.
pub const TIME_QUERY: u32 = 0x1;
pub const TIME_CONTROL: u32 = 0x2;
pub const TIME_ALL_ACCESS: u32 = TIME_QUERY | TIME_CONTROL;

/// The message ceiling, matching the other PSPU query channels.
pub const MAX_MESSAGE_BYTES: usize = 1 << 20;

/// Sources per `sources` chunk. A source record is a few hundred bytes and
/// a machine has a handful of sources, so this exists for symmetry with the
/// other channels rather than out of necessity.
pub const SOURCES_PER_CHUNK: usize = 32;

// ---------------------------------------------------------------------------
// Shapes
// ---------------------------------------------------------------------------

/// How well the clock is being held.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Sync {
    /// No source is believed. The clock is free-running on whatever the
    /// last known frequency was, and the machine should say so rather than
    /// imply an accuracy it does not have.
    #[default]
    Unsynchronised,
    /// A source is believed and the clock is being steered, but the
    /// frequency estimate is still settling.
    Settling,
    /// Normal operation.
    Synchronised,
    /// A large offset is being timed to see whether it is a spike or a real
    /// step. The clock is deliberately untouched meanwhile.
    Spike,
}

impl Sync {
    pub fn as_str(self) -> &'static str {
        match self {
            Sync::Unsynchronised => "unsynchronised",
            Sync::Settling => "settling",
            Sync::Synchronised => "synchronised",
            Sync::Spike => "spike",
        }
    }

    pub fn parse(s: &str) -> Option<Sync> {
        Some(match s {
            "unsynchronised" => Sync::Unsynchronised,
            "settling" => Sync::Settling,
            "synchronised" => Sync::Synchronised,
            "spike" => Sync::Spike,
            _ => return None,
        })
    }
}

/// How a source was authenticated.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Auth {
    /// NTS: every packet carries an AEAD tag over the whole packet, and the
    /// keys came from an authenticated TLS session.
    #[default]
    Nts,
    /// Nothing. Anyone on the path can forge the reply, and the only reason
    /// it is not trivially forgeable off-path is the random transmit
    /// timestamp the server has to echo.
    None,
}

impl Auth {
    pub fn as_str(self) -> &'static str {
        match self {
            Auth::Nts => "nts",
            Auth::None => "none",
        }
    }

    pub fn parse(s: &str) -> Option<Auth> {
        Some(match s {
            "nts" => Auth::Nts,
            "none" => Auth::None,
            _ => return None,
        })
    }
}

/// Where a source came from, which is also its precedence order.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Origin {
    /// `Machine\System\Time\Servers`.
    #[default]
    Registry,
    /// The domain said so. Reserved for v2.
    Domain,
    /// DHCP option 42, and only when `UseFromDHCP` is on.
    Dhcp,
    /// The compiled fallback set behind `time.peios.org`.
    Fallback,
}

impl Origin {
    pub fn as_str(self) -> &'static str {
        match self {
            Origin::Registry => "registry",
            Origin::Domain => "domain",
            Origin::Dhcp => "dhcp",
            Origin::Fallback => "fallback",
        }
    }

    pub fn parse(s: &str) -> Option<Origin> {
        Some(match s {
            "registry" => Origin::Registry,
            "domain" => Origin::Domain,
            "dhcp" => Origin::Dhcp,
            "fallback" => Origin::Fallback,
            _ => return None,
        })
    }
}

/// How a source is faring in selection. The vocabulary an operator reads,
/// and the reason `clock sources` is worth having: "which of my servers
/// disagrees with the others" is the single most useful question a time
/// client can answer.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum SourceState {
    /// Chosen: the system takes its stratum and root numbers from this one.
    SystemPeer,
    /// In the agreement and contributing to the combined offset.
    Candidate,
    /// In the agreement but clustered out as too noisy to help.
    Outlier,
    /// Fit, but outside the agreed interval. It disagrees with the
    /// majority, and it is the one to go and look at.
    Falseticker,
    /// Not answering.
    #[default]
    Unreachable,
    /// Answering, but saying it is not synchronised itself, or too
    /// uncertain to be worth considering.
    Unusable,
}

impl SourceState {
    pub fn as_str(self) -> &'static str {
        match self {
            SourceState::SystemPeer => "system-peer",
            SourceState::Candidate => "candidate",
            SourceState::Outlier => "outlier",
            SourceState::Falseticker => "falseticker",
            SourceState::Unreachable => "unreachable",
            SourceState::Unusable => "unusable",
        }
    }

    pub fn parse(s: &str) -> Option<SourceState> {
        Some(match s {
            "system-peer" => SourceState::SystemPeer,
            "candidate" => SourceState::Candidate,
            "outlier" => SourceState::Outlier,
            "falseticker" => SourceState::Falseticker,
            "unreachable" => SourceState::Unreachable,
            "unusable" => SourceState::Unusable,
            _ => return None,
        })
    }
}

/// One source, as an operator sees it.
#[derive(Debug, Clone, PartialEq, Default)]
pub struct SourceInfo {
    /// The name as configured, which is what the operator recognises.
    pub name: String,
    /// The address currently in use.
    pub address: String,
    pub origin: Origin,
    pub auth: Auth,
    pub state: SourceState,
    pub stratum: u32,
    /// The server's reference identifier, rendered.
    pub reference: String,
    /// Last eight polls as a bitmask, newest in the low bit. Octal in the
    /// classic NTP display, and worth showing raw: `377` is eight for eight
    /// and anything else is a story.
    pub reach: u32,
    /// log2 seconds.
    pub poll: i32,
    /// Seconds since the last reply.
    pub last: f64,
    /// The filtered estimate, in seconds.
    pub offset: f64,
    pub delay: f64,
    pub jitter: f64,
    /// How wrong this source could be, all uncertainties added up.
    pub root_distance: f64,
    /// NTS cookies in hand. Zero means the next poll needs a fresh
    /// handshake.
    pub cookies: u32,
    /// Why this source is not being used, when that needs saying.
    pub note: Option<String>,
}

/// The machine's time state.
#[derive(Debug, Clone, PartialEq, Default)]
pub struct Status {
    /// Bumped on every completed poll, so a subscriber can tell whether
    /// what it holds is current.
    pub generation: u64,
    pub sync: Sync,
    /// The name of the source the system is following, if any.
    pub system_peer: Option<String>,
    /// Distance from a reference clock: 1 is a server with its own
    /// hardware, and the machine is one more than whatever it follows.
    pub stratum: u32,
    /// Current estimate of how far the clock is out, in seconds.
    pub offset: f64,
    /// The learned frequency error, in parts per million.
    pub frequency_ppm: f64,
    /// How steadily the clock is being held.
    pub jitter: f64,
    /// The bound on how wrong the machine's time might be. The honest
    /// number, and the one a Kerberos deployment cares about.
    pub root_distance: f64,
    pub root_delay: f64,
    pub root_dispersion: f64,
    /// A leap second the upstream has warned about.
    pub leap: i32,
    /// Seconds the clock has been stepped since timed started. Non-zero
    /// after boot is normal; non-zero later is worth looking at.
    pub stepped: f64,
    /// Completed polls.
    pub updates: u64,
    /// Seconds since the last accepted measurement.
    pub last_update: f64,
    /// Sources configured, and how many are contributing.
    pub sources: u32,
    pub selected: u32,
    /// The floor below which the clock is not permitted to be set: the
    /// build timestamp. Reported because "your clock is being clamped" is
    /// otherwise invisible and looks like the network being broken.
    pub floor: i64,
}

/// What the future NTP server needs in order to answer a query, and nothing
/// else.
///
/// Pushed on every completed poll rather than polled for, so the server's
/// hot path is `clock_gettime` through the vDSO plus fields it already
/// holds. The one number that has to be recomputed per reply is the root
/// dispersion, which grows at 15 ppm since `at` — the server extrapolates
/// that locally (RFC 5905 §11.2) rather than asking.
#[derive(Debug, Clone, PartialEq, Default)]
pub struct Snapshot {
    pub generation: u64,
    /// 0 none, 1 insert, 2 delete, 3 unsynchronised. Passed through from
    /// upstream: a leap second is an announcement, not a local decision.
    pub leap: u32,
    /// What the server should report. 16 when timed is not synchronised,
    /// which is how a server refuses to serve without needing a second
    /// mechanism to refuse with.
    pub stratum: u32,
    /// The reference identifier to echo, four bytes.
    pub reference_id: Vec<u8>,
    /// When the machine's clock was last set, as a Unix time.
    pub reference_time: f64,
    pub root_delay: f64,
    pub root_dispersion: f64,
    /// log2 seconds; what the machine can actually resolve.
    pub precision: i32,
    /// The local time this snapshot was taken, for extrapolating dispersion.
    pub at: f64,
    pub synchronised: bool,
}

// ---------------------------------------------------------------------------
// Requests and replies
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Request {
    /// The machine's time state.
    Status,
    /// Every source, in configured order.
    Sources,
    /// A snapshot now, and a fresh one after every completed poll, on this
    /// connection until the peer closes it.
    Subscribe,
    /// Re-read the registry, re-resolve every source name, and poll now.
    Reload,
}

impl Request {
    pub fn encode(&self) -> Vec<u8> {
        let mut w = Writer::new();
        let query = match self {
            Request::Status => "status",
            Request::Sources => "sources",
            Request::Subscribe => "subscribe",
            Request::Reload => "reload",
        };
        w.write_map(1).write_str("query").write_str(query);
        w.to_bytes().expect("a request encodes")
    }

    pub fn decode(bytes: &[u8]) -> Result<Request, WireError> {
        let mut r = Reader::new(bytes);
        let mut query = None;
        let mut seen = Vec::new();
        for_each_field(&mut r, &mut seen, |key, r| {
            match key {
                "query" => query = Some(r.read_str()?.to_owned()),
                _ => r.skip()?,
            }
            Ok(())
        })?;
        match query.as_deref() {
            Some("status") => Ok(Request::Status),
            Some("sources") => Ok(Request::Sources),
            Some("subscribe") => Ok(Request::Subscribe),
            Some("reload") => Ok(Request::Reload),
            Some(other) => Err(WireError::UnknownQuery(other.to_owned())),
            None => Err(WireError::Missing("query")),
        }
    }

    /// The right this request needs on the control object.
    ///
    /// Reading is open: what time the machine thinks it is, and how well it
    /// knows, is not a secret — and a program that wants to know whether
    /// the clock is trustworthy before doing something with a certificate
    /// should not need a privilege to find out.
    pub fn required_right(&self) -> u32 {
        match self {
            Request::Reload => TIME_CONTROL,
            _ => TIME_QUERY,
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
pub enum Reply {
    Ok,
    Error(String),
    Status(Status),
    Sources { sources: Vec<SourceInfo>, more: bool },
    Snapshot(Snapshot),
}

impl Reply {
    pub fn encode(&self) -> Vec<u8> {
        let mut w = Writer::new();
        match self {
            Reply::Ok => {
                w.write_map(1).write_str("reply").write_str("ok");
            }
            Reply::Error(message) => {
                w.write_map(2).write_str("reply").write_str("error");
                w.write_str("message").write_str(message);
            }
            Reply::Status(s) => {
                w.write_map(18).write_str("reply").write_str("status");
                w.write_str("generation").write_uint(s.generation);
                w.write_str("sync").write_str(s.sync.as_str());
                write_opt_str(&mut w, "system_peer", &s.system_peer);
                w.write_str("stratum").write_uint(s.stratum as u64);
                w.write_str("offset").write_float(s.offset);
                w.write_str("frequency_ppm").write_float(s.frequency_ppm);
                w.write_str("jitter").write_float(s.jitter);
                w.write_str("root_distance").write_float(s.root_distance);
                w.write_str("root_delay").write_float(s.root_delay);
                w.write_str("root_dispersion").write_float(s.root_dispersion);
                w.write_str("leap").write_int(s.leap as i64);
                w.write_str("stepped").write_float(s.stepped);
                w.write_str("updates").write_uint(s.updates);
                w.write_str("last_update").write_float(s.last_update);
                w.write_str("sources").write_uint(s.sources as u64);
                w.write_str("selected").write_uint(s.selected as u64);
                w.write_str("floor").write_int(s.floor);
            }
            Reply::Sources { sources, more } => {
                w.write_map(3).write_str("reply").write_str("sources");
                w.write_str("more").write_bool(*more);
                w.write_str("sources").write_array(sources.len() as u32);
                for s in sources {
                    write_source(&mut w, s);
                }
            }
            Reply::Snapshot(s) => {
                w.write_map(11).write_str("reply").write_str("snapshot");
                w.write_str("generation").write_uint(s.generation);
                w.write_str("leap").write_uint(s.leap as u64);
                w.write_str("stratum").write_uint(s.stratum as u64);
                w.write_str("reference_id").write_bin(&s.reference_id);
                w.write_str("reference_time").write_float(s.reference_time);
                w.write_str("root_delay").write_float(s.root_delay);
                w.write_str("root_dispersion").write_float(s.root_dispersion);
                w.write_str("precision").write_int(s.precision as i64);
                w.write_str("at").write_float(s.at);
                w.write_str("synchronised").write_bool(s.synchronised);
            }
        }
        w.to_bytes().expect("a reply encodes")
    }

    pub fn decode(bytes: &[u8]) -> Result<Reply, WireError> {
        let mut r = Reader::new(bytes);
        let mut reply = None;
        let mut message = None;
        let mut status = Status::default();
        let mut snapshot = Snapshot::default();
        let mut sources = Vec::new();
        let mut more = false;
        let mut seen = Vec::new();
        for_each_field(&mut r, &mut seen, |key, r| {
            match key {
                "reply" => reply = Some(r.read_str()?.to_owned()),
                "message" => message = Some(r.read_str()?.to_owned()),
                "more" => more = r.read_bool()?,
                "sources" => {
                    // Ambiguous by name: `status` carries a count here and
                    // `sources` carries the array. Distinguished by what is
                    // actually present rather than by trusting the reply
                    // label, which may not have been read yet.
                    if r.peek() == Some(Type::Array) {
                        sources = read_sources(r)?;
                    } else {
                        status.sources = r.read_uint()? as u32;
                    }
                }
                "generation" => {
                    let v = r.read_uint()?;
                    status.generation = v;
                    snapshot.generation = v;
                }
                "sync" => {
                    status.sync = Sync::parse(r.read_str()?).ok_or(WireError::Missing("sync"))?
                }
                "system_peer" => status.system_peer = read_opt_str(r)?,
                "stratum" => {
                    let v = r.read_uint()? as u32;
                    status.stratum = v;
                    snapshot.stratum = v;
                }
                "offset" => status.offset = r.read_float()?,
                "frequency_ppm" => status.frequency_ppm = r.read_float()?,
                "jitter" => status.jitter = r.read_float()?,
                "root_distance" => status.root_distance = r.read_float()?,
                "root_delay" => {
                    let v = r.read_float()?;
                    status.root_delay = v;
                    snapshot.root_delay = v;
                }
                "root_dispersion" => {
                    let v = r.read_float()?;
                    status.root_dispersion = v;
                    snapshot.root_dispersion = v;
                }
                "leap" => {
                    let v = r.read_int()?;
                    status.leap = v as i32;
                    snapshot.leap = v.max(0) as u32;
                }
                "stepped" => status.stepped = r.read_float()?,
                "updates" => status.updates = r.read_uint()?,
                "last_update" => status.last_update = r.read_float()?,
                "selected" => status.selected = r.read_uint()? as u32,
                "floor" => status.floor = r.read_int()?,
                "reference_id" => snapshot.reference_id = r.read_bin()?.to_vec(),
                "reference_time" => snapshot.reference_time = r.read_float()?,
                "precision" => snapshot.precision = r.read_int()? as i32,
                "at" => snapshot.at = r.read_float()?,
                "synchronised" => snapshot.synchronised = r.read_bool()?,
                _ => r.skip()?,
            }
            Ok(())
        })?;
        match reply.as_deref() {
            Some("ok") => Ok(Reply::Ok),
            Some("error") => Ok(Reply::Error(message.unwrap_or_default())),
            Some("status") => Ok(Reply::Status(status)),
            Some("sources") => Ok(Reply::Sources { sources, more }),
            Some("snapshot") => Ok(Reply::Snapshot(snapshot)),
            Some(other) => Err(WireError::UnknownQuery(other.to_owned())),
            None => Err(WireError::Missing("reply")),
        }
    }
}

fn write_source(w: &mut Writer, s: &SourceInfo) {
    w.write_map(16);
    w.write_str("name").write_str(&s.name);
    w.write_str("address").write_str(&s.address);
    w.write_str("origin").write_str(s.origin.as_str());
    w.write_str("auth").write_str(s.auth.as_str());
    w.write_str("state").write_str(s.state.as_str());
    w.write_str("stratum").write_uint(s.stratum as u64);
    w.write_str("reference").write_str(&s.reference);
    w.write_str("reach").write_uint(s.reach as u64);
    w.write_str("poll").write_int(s.poll as i64);
    w.write_str("last").write_float(s.last);
    w.write_str("offset").write_float(s.offset);
    w.write_str("delay").write_float(s.delay);
    w.write_str("jitter").write_float(s.jitter);
    w.write_str("root_distance").write_float(s.root_distance);
    w.write_str("cookies").write_uint(s.cookies as u64);
    write_opt_str(w, "note", &s.note);
}

fn read_sources(r: &mut Reader<'_>) -> Result<Vec<SourceInfo>, WireError> {
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
        out.push(read_source(r)?);
    }
    Ok(out)
}

fn read_source(r: &mut Reader<'_>) -> Result<SourceInfo, WireError> {
    let mut s = SourceInfo::default();
    let mut seen = Vec::new();
    for_each_field(r, &mut seen, |key, r| {
        match key {
            "name" => s.name = r.read_str()?.to_owned(),
            "address" => s.address = r.read_str()?.to_owned(),
            "origin" => s.origin = Origin::parse(r.read_str()?).unwrap_or_default(),
            "auth" => s.auth = Auth::parse(r.read_str()?).unwrap_or_default(),
            "state" => s.state = SourceState::parse(r.read_str()?).unwrap_or_default(),
            "stratum" => s.stratum = r.read_uint()? as u32,
            "reference" => s.reference = r.read_str()?.to_owned(),
            "reach" => s.reach = r.read_uint()? as u32,
            "poll" => s.poll = r.read_int()? as i32,
            "last" => s.last = r.read_float()?,
            "offset" => s.offset = r.read_float()?,
            "delay" => s.delay = r.read_float()?,
            "jitter" => s.jitter = r.read_float()?,
            "root_distance" => s.root_distance = r.read_float()?,
            "cookies" => s.cookies = r.read_uint()? as u32,
            "note" => s.note = read_opt_str(r)?,
            _ => r.skip()?,
        }
        Ok(())
    })?;
    Ok(s)
}

/// Reassemble a chunked `sources` answer, or surface the error.
pub fn sources_of(replies: Vec<Reply>) -> Result<Vec<SourceInfo>, String> {
    let mut out = Vec::new();
    for reply in replies {
        match reply {
            Reply::Sources { sources, .. } => out.extend(sources),
            Reply::Error(message) => return Err(message),
            other => return Err(format!("unexpected reply {other:?}")),
        }
    }
    Ok(out)
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
    fn from(e: peios::Error) -> WireError {
        WireError::Encoding(e)
    }
}

impl From<io::Error> for WireError {
    fn from(e: io::Error) -> WireError {
        WireError::Io(e)
    }
}

// ---------------------------------------------------------------------------
// Framing
// ---------------------------------------------------------------------------

pub fn send(stream: &mut impl Write, payload: &[u8]) -> Result<(), WireError> {
    if payload.len() > MAX_MESSAGE_BYTES {
        return Err(WireError::TooLarge(payload.len()));
    }
    stream.write_all(&(payload.len() as u32).to_le_bytes())?;
    stream.write_all(payload)?;
    stream.flush()?;
    Ok(())
}

pub fn recv(stream: &mut impl Read) -> Result<Vec<u8>, WireError> {
    let mut header = [0u8; 4];
    stream.read_exact(&mut header)?;
    let len = u32::from_le_bytes(header) as usize;
    if len > MAX_MESSAGE_BYTES {
        return Err(WireError::TooLarge(len));
    }
    let mut payload = vec![0u8; len];
    stream.read_exact(&mut payload)?;
    Ok(payload)
}

/// One request, one reply.
pub fn call(stream: &mut UnixStream, request: &Request) -> Result<Reply, WireError> {
    send(stream, &request.encode())?;
    Reply::decode(&recv(stream)?)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn source(n: u8) -> SourceInfo {
        SourceInfo {
            name: format!("{n}.time.peios.org"),
            address: format!("192.0.2.{n}"),
            origin: Origin::Fallback,
            auth: Auth::Nts,
            state: SourceState::Candidate,
            stratum: 2,
            reference: "GPS".into(),
            reach: 0o377,
            poll: 6,
            last: 12.5,
            offset: -0.000_123,
            delay: 0.014,
            jitter: 0.000_2,
            root_distance: 0.021,
            cookies: 8,
            note: None,
        }
    }

    #[test]
    fn requests_round_trip_and_carry_the_right_they_need() {
        for req in [Request::Status, Request::Sources, Request::Subscribe, Request::Reload] {
            assert_eq!(Request::decode(&req.encode()).unwrap(), req);
        }
        assert_eq!(Request::Reload.required_right(), TIME_CONTROL);
        assert_eq!(Request::Status.required_right(), TIME_QUERY);
        assert_eq!(Request::Subscribe.required_right(), TIME_QUERY);
    }

    #[test]
    fn a_status_round_trips() {
        let reply = Reply::Status(Status {
            generation: 42,
            sync: Sync::Synchronised,
            system_peer: Some("1.time.peios.org".into()),
            stratum: 3,
            offset: -0.000_412,
            frequency_ppm: -12.75,
            jitter: 0.000_18,
            root_distance: 0.031,
            root_delay: 0.028,
            root_dispersion: 0.004,
            leap: 0,
            stepped: 31_536_000.0,
            updates: 118,
            last_update: 22.5,
            sources: 4,
            selected: 3,
            floor: 1_756_000_000,
        });
        assert_eq!(Reply::decode(&reply.encode()).unwrap(), reply);

        // And with nothing selected, which is the interesting case.
        let empty = Reply::Status(Status { sync: Sync::Unsynchronised, ..Status::default() });
        assert_eq!(Reply::decode(&empty.encode()).unwrap(), empty);
    }

    #[test]
    fn sources_round_trip_and_reassemble() {
        let reply = Reply::Sources { sources: (0..3).map(source).collect(), more: true };
        assert_eq!(Reply::decode(&reply.encode()).unwrap(), reply);

        let all = sources_of(vec![
            Reply::Sources { sources: vec![source(0), source(1)], more: true },
            Reply::Sources { sources: vec![source(2)], more: false },
        ])
        .unwrap();
        assert_eq!(all.len(), 3);
        assert_eq!(sources_of(vec![Reply::Error("denied".into())]), Err("denied".into()));
    }

    #[test]
    fn a_snapshot_round_trips() {
        let reply = Reply::Snapshot(Snapshot {
            generation: 9,
            leap: 0,
            stratum: 3,
            reference_id: vec![192, 0, 2, 1],
            reference_time: 1_756_000_123.5,
            root_delay: 0.028,
            root_dispersion: 0.004,
            precision: -24,
            at: 1_756_000_130.25,
            synchronised: true,
        });
        assert_eq!(Reply::decode(&reply.encode()).unwrap(), reply);

        // The refusing form: stratum 16, not synchronised. This is how the
        // future server declines to serve without a second mechanism.
        let refusing = Reply::Snapshot(Snapshot {
            stratum: 16,
            synchronised: false,
            reference_id: b"INIT".to_vec(),
            ..Snapshot::default()
        });
        assert_eq!(Reply::decode(&refusing.encode()).unwrap(), refusing);
    }

    #[test]
    fn ok_and_error_round_trip() {
        assert_eq!(Reply::decode(&Reply::Ok.encode()).unwrap(), Reply::Ok);
        let e = Reply::Error("not permitted".into());
        assert_eq!(Reply::decode(&e.encode()).unwrap(), e);
    }

    #[test]
    fn a_full_chunk_fits_the_ceiling() {
        let big: Vec<SourceInfo> = (0..SOURCES_PER_CHUNK as u8)
            .map(|n| SourceInfo { name: "x".repeat(253), ..source(n) })
            .collect();
        let bytes = Reply::Sources { sources: big, more: true }.encode();
        assert!(bytes.len() <= MAX_MESSAGE_BYTES, "{} bytes", bytes.len());
        let mut buf = Vec::new();
        send(&mut buf, &bytes).unwrap();
        assert_eq!(recv(&mut &buf[..]).unwrap(), bytes);
    }

    #[test]
    fn a_duplicate_key_is_refused_and_an_unknown_one_ignored() {
        let mut w = Writer::new();
        w.write_map(2).write_str("query").write_str("status").write_str("query").write_str("status");
        assert!(matches!(Request::decode(&w.to_bytes().unwrap()), Err(WireError::Duplicate(_))));

        let mut w = Writer::new();
        w.write_map(2).write_str("extra").write_uint(3).write_str("query").write_str("status");
        assert_eq!(Request::decode(&w.to_bytes().unwrap()).unwrap(), Request::Status);
    }

    #[test]
    fn an_array_count_the_message_cannot_hold_is_refused() {
        // Built by hand, because the writer will not emit a message whose
        // declared count does not match what follows — which is exactly the
        // message an attacker sends. A fixmap of one, the key, then an
        // array32 header claiming four billion elements in five bytes.
        // Reserving for that is a remote out-of-memory kill from a
        // fourteen-byte message, on a socket every program may connect to.
        let mut bytes = vec![0x81];
        bytes.push(0xa0 | 7);
        bytes.extend_from_slice(b"sources");
        bytes.extend_from_slice(&[0xdd, 0xff, 0xff, 0xff, 0xff]);
        assert!(matches!(Reply::decode(&bytes), Err(WireError::TooLarge(_))));
    }

    #[test]
    fn framing_refuses_oversize_in_both_directions() {
        let big = [0xffu8, 0xff, 0xff, 0x00];
        assert!(matches!(recv(&mut &big[..]), Err(WireError::TooLarge(_))));
        assert!(matches!(
            send(&mut Vec::new(), &vec![0u8; MAX_MESSAGE_BYTES + 1]),
            Err(WireError::TooLarge(_))
        ));
    }
}
