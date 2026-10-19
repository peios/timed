//! trustd's control wire.
//!
//! trustd's socket is a PSPU observability *query* channel (§3.15): a
//! `SOCK_STREAM` socket carrying length-prefixed MessagePack maps.
//!
//! ```text
//! +---------------------+------------------------+
//! | length u32 LE       | payload (MessagePack)  |
//! +---------------------+------------------------+
//! ```
//!
//! Two things distinguish it from netd's and resolvd's channels, both of
//! them shapes the observability book already has:
//!
//! - **Replies chunk.** The effective root set is ~150 certificates and a
//!   few hundred kilobytes, well past the message ceiling, so a `roots`
//!   reply is a sequence of messages each carrying a batch and a `more`
//!   flag (§3.16). A single root is never split across messages.
//! - **`subscribe` streams.** As on netd's channel, the connection stays
//!   open and a fresh chunked sequence follows every change, so a consumer
//!   that has loaded the roots into its TLS library learns when to reload
//!   them. That is the property the compat files cannot offer.
//!
//! The socket is the trust store; the rendered files are a compatibility
//! artifact of it (`GenerateLinuxTrustFiles`).
//!
//! This crate is inert: types, a codec and the control object's default
//! descriptor, nothing that can act. What changes the trust store — the
//! registry writes `trust` and Security Policy make — is the `trust`
//! crate's library.

pub mod cert;
pub mod store;

use std::io::{self, Read, Write};
use std::os::unix::net::UnixStream;

use peios::msgpack::{Reader, Type, Writer};
use peios::security::{
    AccessMask, AceFlags, AclBuilder, GenericMapping, SdBuilder, SecurityDescriptor, Sid, WellKnown,
};

/// trustd's runtime directory. peinit creates it (`RuntimeDirectories`) and
/// trustd stamps its own descriptor on it.
pub const TRUSTD_RUN_DIR: &str = "/run/trustd";
/// The control socket.
pub const SOCKET_PATH: &str = "/run/trustd/trust.sock";

/// The registry subtree trustd reads. `Certificates\Add\<name>` holds
/// additions, `Certificates\Distrust\<fingerprint>` holds removals.
pub const TRUST_KEY: &str = "Machine\\System\\Trust";
pub const CERTIFICATES_KEY: &str = "Machine\\System\\Trust\\Certificates";

/// Names under `Certificates\`. The daemon reads these and `trust` writes
/// them; sharing the constants is what keeps the two halves in step.
pub const ADD_KEY: &str = "Add";
pub const DISTRUST_KEY: &str = "Distrust";
/// The certificate itself, DER. Written *last* when an entry is created, so
/// a key observed mid-write is never mistaken for a valid entry.
pub const CERTIFICATE_VALUE: &str = "Certificate";
pub const PURPOSES_VALUE: &str = "Purposes";
pub const COMPAT_VALUE: &str = "GenerateLinuxTrustFiles";
pub const CONTROL_SECURITY_VALUE: &str = "ControlSecurity";

/// The shipped Mozilla bundle, package *data* rather than configuration:
/// `ca-certificates` owns it, upgrades replace it, and removals upstream
/// propagate by package rather than by anything trustd does.
pub const SHARE_BUNDLE: &str = "/usr/share/ca-certificates/mozilla.crt";

/// Where the compat rendering lands: the registry-derived layer of the
/// `/etc` merge, so the files appear at `/etc/ssl/...` with no package
/// owning them.
pub const STORE_DIR: &str = "/system/retc/ssl";
/// The conventional bundle path — what Go probes first and what most
/// software is configured with.
pub const BUNDLE_PATH: &str = "/system/retc/ssl/certs/ca-certificates.crt";
/// OpenSSL's default `CAfile` for this build (`--openssldir=/etc/ssl`).
pub const OPENSSL_CERT_PEM: &str = "/system/retc/ssl/cert.pem";
/// OpenSSL's default `CApath`: the hashed directory.
pub const CERTS_DIR: &str = "/system/retc/ssl/certs";

/// Rights on the trustd control object.
///
/// Checked against `Machine\System\Trust ControlSecurity` when it exists,
/// else the compiled default: Everyone may query — the root set is public
/// and world-readable as a file — and SYSTEM and Administrators may
/// control.
///
/// Note what `TRUST_CONTROL` does *not* gate: adding or distrusting a
/// certificate. Those are registry writes, governed by the key's own
/// descriptor, so the CLI and `reg` take the same path and there is no
/// second permission model to keep in step.
pub const TRUST_QUERY: u32 = 0x0000_0001;
pub const TRUST_CONTROL: u32 = 0x0000_0002;
pub const TRUST_ALL_ACCESS: u32 = TRUST_QUERY | TRUST_CONTROL | 0x000F_0000;

/// The control object's descriptor when `ControlSecurity` is absent: SYSTEM
/// and Administrators have every right, Everyone may query. trustd checks
/// against it, and a window asks it whether to offer `reload` at all, so
/// both read it from here.
pub fn default_control_security() -> SecurityDescriptor {
    let system = Sid::well_known(WellKnown::System);
    let administrators = Sid::well_known(WellKnown::Administrators);
    let everyone = Sid::well_known(WellKnown::Everyone);
    AclBuilder::new()
        .allow(system.as_ref(), TRUST_ALL_ACCESS, AceFlags::empty())
        .allow(administrators.as_ref(), TRUST_ALL_ACCESS, AceFlags::empty())
        .allow(
            everyone.as_ref(),
            TRUST_QUERY | AccessMask::READ_CONTROL.bits(),
            AceFlags::empty(),
        )
        .build()
        .and_then(|dacl| {
            SdBuilder::new()
                .owner(system.as_ref())
                .group(system.as_ref())
                .dacl(&dacl)
                .build()
        })
        .expect("the compiled default descriptor builds")
}

/// What the generic rights mean on the control object.
pub fn control_mapping() -> GenericMapping {
    let rc = AccessMask::READ_CONTROL.bits();
    GenericMapping::new(
        TRUST_QUERY | rc,
        TRUST_CONTROL | rc,
        TRUST_QUERY,
        TRUST_ALL_ACCESS,
    )
}

/// Ceiling on one control message, payload only.
pub const MAX_MESSAGE_BYTES: usize = 65_536;

/// Roots per reply message. A root is a certificate — a kilobyte or two —
/// so this keeps a chunk comfortably inside the ceiling with room for the
/// subject strings.
pub const ROOTS_PER_CHUNK: usize = 24;

/// Where a root came from.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Source {
    /// The shipped bundle.
    #[default]
    Shipped,
    /// `Certificates\Add\<name>` in the registry.
    Added,
}

impl Source {
    pub fn as_str(self) -> &'static str {
        match self {
            Source::Shipped => "shipped",
            Source::Added => "added",
        }
    }

    pub fn parse(s: &str) -> Option<Source> {
        Some(match s {
            "shipped" => Source::Shipped,
            "added" => Source::Added,
            _ => return None,
        })
    }
}

/// One root in the effective set.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Root {
    /// Lowercase hex SHA-256 of the DER — the identity a `Distrust` names.
    pub fingerprint: String,
    /// The subject, in a form fit for a person to read.
    pub subject: String,
    /// What the root is trusted for. `ServerAuth` unless stated otherwise.
    pub purposes: Vec<String>,
    pub source: Source,
    /// For an added root, the registry value name it came from.
    pub name: Option<String>,
    /// RFC 5280 notAfter, seconds since the epoch.
    pub not_after: i64,
    /// The certificate itself. Empty when the caller asked without it.
    pub der: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Request {
    /// The effective root set. `with_der` false is the listing form — a
    /// person wants subjects, a TLS library wants certificates.
    Roots {
        with_der: bool,
        purpose: Option<String>,
    },
    /// The set now, and a fresh one after every change, on this connection
    /// until the peer closes it.
    Subscribe { with_der: bool },
    /// Counts, generation, render state, compat mode.
    Status,
    /// Recompose and re-render now.
    Reload,
}

impl Request {
    pub fn encode(&self) -> Vec<u8> {
        let mut w = Writer::new();
        match self {
            Request::Roots { with_der, purpose } => {
                w.write_map(3).write_str("query").write_str("roots");
                w.write_str("with_der").write_bool(*with_der);
                write_opt_str(&mut w, "purpose", purpose);
            }
            Request::Subscribe { with_der } => {
                w.write_map(2).write_str("query").write_str("subscribe");
                w.write_str("with_der").write_bool(*with_der);
            }
            Request::Status => {
                w.write_map(1).write_str("query").write_str("status");
            }
            Request::Reload => {
                w.write_map(1).write_str("query").write_str("reload");
            }
        }
        w.to_bytes().expect("a request encodes")
    }

    pub fn decode(bytes: &[u8]) -> Result<Request, WireError> {
        let mut r = Reader::new(bytes);
        let mut query = None;
        let mut with_der = false;
        let mut purpose = None;
        let mut seen = Vec::new();
        for_each_field(&mut r, &mut seen, |key, r| {
            match key {
                "query" => query = Some(r.read_str()?.to_owned()),
                "with_der" => with_der = r.read_bool()?,
                "purpose" => purpose = read_opt_str(r)?,
                _ => r.skip()?,
            }
            Ok(())
        })?;
        match query.as_deref() {
            Some("roots") => Ok(Request::Roots { with_der, purpose }),
            Some("subscribe") => Ok(Request::Subscribe { with_der }),
            Some("status") => Ok(Request::Status),
            Some("reload") => Ok(Request::Reload),
            Some(other) => Err(WireError::UnknownQuery(other.to_owned())),
            None => Err(WireError::Missing("query")),
        }
    }

    /// The right this request needs on the control object.
    pub fn required_right(&self) -> u32 {
        match self {
            Request::Reload => TRUST_CONTROL,
            _ => TRUST_QUERY,
        }
    }
}

/// How the store is faring. `Degraded` is the state that matters: the
/// composition failed and what is rendered is whatever was rendered last,
/// which may be stale but is never partial.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Health {
    #[default]
    Ok,
    Degraded,
}

impl Health {
    pub fn as_str(self) -> &'static str {
        match self {
            Health::Ok => "ok",
            Health::Degraded => "degraded",
        }
    }

    pub fn parse(s: &str) -> Option<Health> {
        Some(match s {
            "ok" => Health::Ok,
            "degraded" => Health::Degraded,
            _ => return None,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Status {
    /// Bumped on every successful composition; a consumer holding roots can
    /// compare it without fetching them.
    pub generation: u64,
    pub health: Health,
    /// Why, when degraded.
    pub message: Option<String>,
    /// Roots in the shipped bundle.
    pub shipped: u64,
    /// Roots added from the registry.
    pub added: u64,
    /// Distrust entries in the registry.
    pub distrusted: u64,
    /// Entries skipped as unusable (unparseable, not a CA, expired).
    pub skipped: u64,
    /// Roots in the effective set.
    pub effective: u64,
    /// `GenerateLinuxTrustFiles`: 0 none, 1 rendered, 2 reserved.
    pub compat_mode: u32,
    /// The files last written, empty in mode 0.
    pub rendered: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Reply {
    Ok,
    Error(String),
    /// One chunk of the root set. `more` is true when another follows.
    Roots {
        generation: u64,
        roots: Vec<Root>,
        more: bool,
    },
    Status(Status),
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
            Reply::Roots {
                generation,
                roots,
                more,
            } => {
                w.write_map(5).write_str("ok").write_bool(true);
                w.write_str("kind").write_str("roots");
                w.write_str("generation").write_uint(*generation);
                w.write_str("more").write_bool(*more);
                w.write_str("roots").write_array(roots.len() as u32);
                for root in roots {
                    w.write_map(7);
                    w.write_str("fingerprint").write_str(&root.fingerprint);
                    w.write_str("subject").write_str(&root.subject);
                    write_str_list(&mut w, "purposes", &root.purposes);
                    w.write_str("source").write_str(root.source.as_str());
                    write_opt_str(&mut w, "name", &root.name);
                    w.write_str("not_after").write_int(root.not_after);
                    w.write_str("der").write_bin(&root.der);
                }
            }
            Reply::Status(s) => {
                w.write_map(12).write_str("ok").write_bool(true);
                w.write_str("kind").write_str("status");
                w.write_str("generation").write_uint(s.generation);
                w.write_str("health").write_str(s.health.as_str());
                write_opt_str(&mut w, "message", &s.message);
                w.write_str("shipped").write_uint(s.shipped);
                w.write_str("added").write_uint(s.added);
                w.write_str("distrusted").write_uint(s.distrusted);
                w.write_str("skipped").write_uint(s.skipped);
                w.write_str("effective").write_uint(s.effective);
                w.write_str("compat_mode")
                    .write_uint(u64::from(s.compat_mode));
                write_str_list(&mut w, "rendered", &s.rendered);
            }
        }
        w.to_bytes().expect("a reply encodes")
    }

    pub fn decode(bytes: &[u8]) -> Result<Reply, WireError> {
        let mut r = Reader::new(bytes);
        let mut ok = None;
        let mut error = None;
        let mut kind = None;
        let mut generation = 0u64;
        let mut more = false;
        let mut roots = Vec::new();
        let mut status = Status::default();
        let mut seen = Vec::new();
        for_each_field(&mut r, &mut seen, |key, r| {
            match key {
                "ok" => ok = Some(r.read_bool()?),
                "error" => error = Some(r.read_str()?.to_owned()),
                "kind" => kind = Some(r.read_str()?.to_owned()),
                "generation" => {
                    generation = r.read_uint()?;
                    status.generation = generation;
                }
                "more" => more = r.read_bool()?,
                "roots" => {
                    let n = r.read_array()?;
                    for _ in 0..n {
                        roots.push(decode_root(r)?);
                    }
                }
                "health" => status.health = Health::parse(r.read_str()?).unwrap_or_default(),
                "message" => status.message = read_opt_str(r)?,
                "shipped" => status.shipped = r.read_uint()?,
                "added" => status.added = r.read_uint()?,
                "distrusted" => status.distrusted = r.read_uint()?,
                "skipped" => status.skipped = r.read_uint()?,
                "effective" => status.effective = r.read_uint()?,
                "compat_mode" => status.compat_mode = r.read_uint()? as u32,
                "rendered" => status.rendered = read_str_list(r)?,
                _ => r.skip()?,
            }
            Ok(())
        })?;
        match (ok, kind.as_deref()) {
            (Some(false), _) => Ok(Reply::Error(
                error.unwrap_or_else(|| "unspecified error".to_owned()),
            )),
            (Some(true), Some("roots")) => Ok(Reply::Roots {
                generation,
                roots,
                more,
            }),
            (Some(true), Some("status")) => Ok(Reply::Status(status)),
            (Some(true), _) => Ok(Reply::Ok),
            (None, _) => Err(WireError::Missing("ok")),
        }
    }
}

fn decode_root(r: &mut Reader<'_>) -> Result<Root, WireError> {
    let mut root = Root::default();
    let mut seen = Vec::new();
    for_each_field(r, &mut seen, |key, r| {
        match key {
            "fingerprint" => root.fingerprint = r.read_str()?.to_owned(),
            "subject" => root.subject = r.read_str()?.to_owned(),
            "purposes" => root.purposes = read_str_list(r)?,
            "source" => root.source = Source::parse(r.read_str()?).unwrap_or_default(),
            "name" => root.name = read_opt_str(r)?,
            "not_after" => root.not_after = r.read_int()?,
            "der" => root.der = r.read_bin()?.to_vec(),
            _ => r.skip()?,
        }
        Ok(())
    })?;
    Ok(root)
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

/// Send a request and collect a chunked reply: every message until one
/// arrives without `more`.
pub fn call(stream: &mut UnixStream, request: &Request) -> Result<Vec<Reply>, WireError> {
    send(stream, &request.encode())?;
    let mut out = Vec::new();
    loop {
        let reply = Reply::decode(&recv(stream)?)?;
        let more = matches!(reply, Reply::Roots { more: true, .. });
        out.push(reply);
        if !more {
            return Ok(out);
        }
    }
}

/// The roots from a completed `call`, or the error the daemon gave.
pub fn roots_of(replies: Vec<Reply>) -> Result<(u64, Vec<Root>), String> {
    let mut generation = None;
    let mut roots = Vec::new();
    let mut complete = false;
    for reply in replies {
        if complete {
            return Err("reply after completed root snapshot".into());
        }
        match reply {
            Reply::Roots {
                generation: current,
                roots: mut batch,
                more,
            } => {
                if generation.is_some_and(|expected| expected != current) {
                    return Err("root snapshot changed generation".into());
                }
                generation = Some(current);
                roots.append(&mut batch);
                complete = !more;
            }
            Reply::Error(error) => return Err(error),
            _ => return Err("unexpected reply".into()),
        }
    }
    if !complete {
        return Err("incomplete root snapshot".into());
    }
    Ok((
        generation.expect("a completed snapshot has a generation"),
        roots,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn root_snapshots_must_be_complete_and_consistent() {
        let chunk = |generation, more| Reply::Roots {
            generation,
            roots: vec![],
            more,
        };
        assert!(roots_of(vec![]).is_err());
        assert!(roots_of(vec![chunk(1, true)]).is_err());
        assert!(roots_of(vec![chunk(1, true), chunk(2, false)]).is_err());
        assert!(roots_of(vec![chunk(1, false), chunk(1, false)]).is_err());
        assert_eq!(
            roots_of(vec![chunk(1, true), chunk(1, false)]).unwrap(),
            (1, vec![])
        );
    }

    fn root(n: u8) -> Root {
        Root {
            fingerprint: format!("{n:064x}"),
            subject: format!("CN=Test Root {n}, O=Peios"),
            purposes: vec!["ServerAuth".into()],
            source: if n.is_multiple_of(2) {
                Source::Shipped
            } else {
                Source::Added
            },
            name: (n % 2 == 1).then(|| format!("root-{n}")),
            not_after: 1_900_000_000,
            der: vec![0x30, 0x82, n, 0x00],
        }
    }

    #[test]
    fn requests_round_trip() {
        for req in [
            Request::Roots {
                with_der: true,
                purpose: None,
            },
            Request::Roots {
                with_der: false,
                purpose: Some("ServerAuth".into()),
            },
            Request::Subscribe { with_der: true },
            Request::Status,
            Request::Reload,
        ] {
            assert_eq!(Request::decode(&req.encode()).unwrap(), req);
        }
        assert_eq!(Request::Reload.required_right(), TRUST_CONTROL);
        assert_eq!(Request::Status.required_right(), TRUST_QUERY);
    }

    #[test]
    fn a_roots_chunk_round_trips() {
        let reply = Reply::Roots {
            generation: 7,
            roots: (0..3).map(root).collect(),
            more: true,
        };
        assert_eq!(Reply::decode(&reply.encode()).unwrap(), reply);
        let empty = Reply::Roots {
            generation: 0,
            roots: vec![],
            more: false,
        };
        assert_eq!(Reply::decode(&empty.encode()).unwrap(), empty);
    }

    #[test]
    fn a_status_round_trips() {
        let reply = Reply::Status(Status {
            generation: 3,
            health: Health::Degraded,
            message: Some("the shipped bundle is unreadable".into()),
            shipped: 150,
            added: 2,
            distrusted: 1,
            skipped: 1,
            effective: 151,
            compat_mode: 1,
            rendered: vec![BUNDLE_PATH.into(), OPENSSL_CERT_PEM.into()],
        });
        assert_eq!(Reply::decode(&reply.encode()).unwrap(), reply);
        assert_eq!(Reply::decode(&Reply::Ok.encode()).unwrap(), Reply::Ok);
        let e = Reply::Error("no".into());
        assert_eq!(Reply::decode(&e.encode()).unwrap(), e);
    }

    #[test]
    fn a_chunk_of_the_agreed_size_fits_the_ceiling() {
        // A real root is one to two kilobytes; make them larger than that
        // and confirm a full chunk still frames.
        let big: Vec<Root> = (0..ROOTS_PER_CHUNK as u8)
            .map(|n| Root {
                der: vec![0x41; 2048],
                ..root(n)
            })
            .collect();
        let bytes = Reply::Roots {
            generation: 1,
            roots: big,
            more: true,
        }
        .encode();
        assert!(bytes.len() <= MAX_MESSAGE_BYTES, "{} bytes", bytes.len());
        let mut buf = Vec::new();
        send(&mut buf, &bytes).unwrap();
        assert_eq!(recv(&mut &buf[..]).unwrap(), bytes);
    }

    #[test]
    fn chunks_reassemble_and_an_error_surfaces() {
        let replies = vec![
            Reply::Roots {
                generation: 9,
                roots: vec![root(1), root(2)],
                more: true,
            },
            Reply::Roots {
                generation: 9,
                roots: vec![root(3)],
                more: false,
            },
        ];
        let (generation, roots) = roots_of(replies).unwrap();
        assert_eq!(generation, 9);
        assert_eq!(roots.len(), 3);
        assert_eq!(
            roots_of(vec![Reply::Error("denied".into())]),
            Err("denied".into())
        );
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
    fn an_array_count_the_message_cannot_hold_is_refused() {
        // Built by hand, because the writer will not emit a message whose
        // declared count does not match what follows — which is exactly the
        // message an attacker sends. A fixmap of one, the key, then an
        // array32 header claiming four billion elements in five bytes.
        // Reserving for that is a remote out-of-memory kill.
        let mut bytes = vec![0x81];
        bytes.push(0xa0 | 8);
        bytes.extend_from_slice(b"rendered");
        bytes.extend_from_slice(&[0xdd, 0xff, 0xff, 0xff, 0xff]);
        assert!(matches!(Reply::decode(&bytes), Err(WireError::TooLarge(_))));
    }

    #[test]
    fn framing_refuses_oversize() {
        let big = [0xffu8, 0xff, 0xff, 0x00];
        assert!(matches!(recv(&mut &big[..]), Err(WireError::TooLarge(_))));
        assert!(matches!(
            send(&mut Vec::new(), &vec![0u8; MAX_MESSAGE_BYTES + 1]),
            Err(WireError::TooLarge(_))
        ));
    }
}
