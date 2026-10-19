//! Changing what this machine trusts, for every front end: the `trust`
//! command and Security Policy's Certificates take the same steps through
//! here, so there is one way to add, remove, distrust and restore.
//!
//! It reads over trustd's socket and writes to the registry, and the split
//! is deliberate. Only trustd knows the *effective* set — the shipped roots
//! are package data, not registry entries, so a listing read from the
//! registry would show the handful of local decisions and none of the
//! hundred and fifty roots actually in force. Writes go the other way: to
//! the registry, exactly as `reg` would write them, so the key's own
//! descriptor is the only thing that decides who may change what this
//! machine trusts. There is no second permission model here to drift out of
//! step with that one.
//!
//! Nothing here prints. Each step says what came of it, and the front end
//! says that in its own words.

use std::io::ErrorKind;
mod channel;

use peios::access::AccessCheck;
use peios::registry::{CreateFlags, Key, KeyAccess, OpenFlags, ValueType};
use peios::security::{AccessMask, SecurityDescriptor};
pub use trust_core::cert::{self, Details, Parsed};
pub use trust_core::store::normalise_fingerprint;
use trust_core::{
    ADD_KEY, CERTIFICATE_VALUE, CERTIFICATES_KEY, COMPAT_VALUE, CONTROL_SECURITY_VALUE,
    DISTRUST_KEY, PURPOSES_VALUE, Reply, Request, Root, SOCKET_PATH, Status, TRUST_CONTROL,
    TRUST_KEY,
};

const ACCESS: KeyAccess = KeyAccess::QUERY_VALUE
    .union(KeyAccess::SET_VALUE)
    .union(KeyAccess::CREATE_SUB_KEY)
    .union(KeyAccess::ENUMERATE_SUB_KEYS);

/// Why a step was not taken.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Error {
    /// The person may not make this change: the key's descriptor said no.
    /// The text names what was refused.
    Denied(String),
    /// What was asked about isn't there: no such root, addition or distrust.
    NotFound(String),
    /// Anything else: trustd unreachable, a file that isn't a certificate,
    /// an ambiguous fingerprint.
    Failed(String),
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Error::Denied(what) => write!(
                f,
                "not permitted to change {what} — changing what this machine trusts is governed by that key's descriptor"
            ),
            Error::NotFound(why) | Error::Failed(why) => f.write_str(why),
        }
    }
}

impl std::error::Error for Error {}

/// A denied registry write is the expected failure for a person who may not
/// change the machine's trust, so it says so rather than giving a number.
fn registry_error(path: &str, error: peios::Error) -> Error {
    if error.kind() == ErrorKind::PermissionDenied {
        Error::Denied(path.to_owned())
    } else {
        Error::Failed(format!("{path}: {error}"))
    }
}

// ------------------------------------------------------------- the socket ---

/// One request to trustd, and every reply it sends to it.
pub fn call(request: &Request) -> Result<Vec<Reply>, Error> {
    bounded_call(request).map_err(|error| Error::Failed(error.to_string()))
}

fn bounded_call(request: &Request) -> std::io::Result<Vec<Reply>> {
    let end = channel::deadline(10_000)?;
    let mut channel = channel::Channel::connect(SOCKET_PATH.as_bytes(), end)?;
    channel.send(request, end)?;
    let mut replies = Vec::new();
    let mut bytes = 0usize;
    loop {
        let reply = channel.receive(end)?;
        bytes = bytes
            .checked_add(reply.encode().len())
            .filter(|bytes| *bytes <= 16 * 1024 * 1024)
            .ok_or_else(|| channel::invalid("trust snapshot exceeds 16 MiB"))?;
        let more = matches!(reply, Reply::Roots { more: true, .. });
        replies.push(reply);
        if !more {
            return Ok(replies);
        }
    }
}

/// Every root in force, with each certificate when `with_der`.
pub fn roots(with_der: bool, purpose: Option<String>) -> Result<Vec<Root>, Error> {
    trust_core::roots_of(call(&Request::Roots { with_der, purpose })?)
        .map(|(_, roots)| roots)
        .map_err(Error::Failed)
}

/// How the store is faring.
pub fn status() -> Result<Status, Error> {
    match call(&Request::Status)?.into_iter().next() {
        Some(Reply::Status(status)) => Ok(status),
        Some(Reply::Error(e)) => Err(Error::Failed(e)),
        _ => Err(Error::Failed("trustd sent an unexpected reply".into())),
    }
}

/// Asks trustd to compose the store again now.
pub fn reload() -> Result<(), Error> {
    match call(&Request::Reload)?.into_iter().next() {
        Some(Reply::Ok) => Ok(()),
        Some(Reply::Error(e)) => Err(Error::Failed(e)),
        _ => Err(Error::Failed("trustd sent an unexpected reply".into())),
    }
}

/// Whether trustd would let this program reload it: the same check it
/// makes, against `ControlSecurity` or its compiled default, asked before
/// rather than learned from a refusal.
pub fn may_reload() -> bool {
    let configured = Key::open(None, TRUST_KEY, KeyAccess::QUERY_VALUE, OpenFlags::empty())
        .ok()
        .and_then(|key| {
            key.query_value(CONTROL_SECURITY_VALUE.as_bytes(), None)
                .ok()
        })
        .and_then(|value| SecurityDescriptor::from_validated_bytes(value.data).ok());
    let sd = configured.unwrap_or_else(trust_core::default_control_security);
    AccessCheck::new(
        &sd,
        AccessMask::from_bits_retain(TRUST_CONTROL),
        trust_core::control_mapping(),
    )
    .check()
    .map(|decision| decision.allowed)
    .unwrap_or(false)
}

// ------------------------------------------------------------ the registry ---

fn open_or_create(parent: Option<&Key>, path: &str, shown: &str) -> Result<Key, Error> {
    Key::create(parent, path, ACCESS, CreateFlags::empty(), None, None)
        .map(|(key, _)| key)
        .map_err(|e| registry_error(shown, e))
}

/// `Machine\System\Trust\Certificates\<Add|Distrust>`, created if absent.
fn certificates(which: &str) -> Result<Key, Error> {
    let certificates = open_or_create(None, CERTIFICATES_KEY, CERTIFICATES_KEY)?;
    open_or_create(
        Some(&certificates),
        which,
        &format!("{CERTIFICATES_KEY}\\{which}"),
    )
}

/// Whether this person may change what the machine trusts: asked by opening
/// the certificates key for what a change takes, or, where it isn't there
/// yet, the trust key to make it in. Never worked out from who they are.
pub fn may_change() -> Result<(), Error> {
    let wanted = KeyAccess::SET_VALUE.union(KeyAccess::CREATE_SUB_KEY);
    match Key::open(None, CERTIFICATES_KEY, wanted, OpenFlags::empty()) {
        Ok(_) => Ok(()),
        Err(e) if e.kind() == ErrorKind::NotFound => Key::open(
            None,
            TRUST_KEY,
            KeyAccess::CREATE_SUB_KEY,
            OpenFlags::empty(),
        )
        .map(|_| ())
        .map_err(|e| registry_error(TRUST_KEY, e)),
        Err(e) => Err(registry_error(CERTIFICATES_KEY, e)),
    }
}

/// Whether this person may change whether the files under `/etc/ssl` are
/// written.
pub fn may_set_compat() -> Result<(), Error> {
    Key::open(None, TRUST_KEY, KeyAccess::SET_VALUE, OpenFlags::empty())
        .map(|_| ())
        .map_err(|e| registry_error(TRUST_KEY, e))
}

/// Sets `GenerateLinuxTrustFiles`: 1 to write the files, 0 to remove them.
pub fn set_compat(mode: u32) -> Result<(), Error> {
    let key = Key::open(None, TRUST_KEY, KeyAccess::SET_VALUE, OpenFlags::empty())
        .map_err(|e| registry_error(TRUST_KEY, e))?;
    key.set_value(
        COMPAT_VALUE.as_bytes(),
        ValueType::DWORD,
        &mode.to_le_bytes(),
    )
    .call()
    .map_err(|e| registry_error(TRUST_KEY, e))
}

// ------------------------------------------------------------- additions ---

/// The one certificate in `bytes`: PEM if it looks like it, DER otherwise.
/// A file of several is refused, because a bundle added under one name
/// would be one decision covering several authorities. `what` names the
/// file for the reason.
pub fn certificate(bytes: &[u8], what: &str) -> Result<Vec<u8>, Error> {
    if let Ok(text) = std::str::from_utf8(bytes) {
        let certificates = cert::from_pem(text);
        if certificates.len() > 1 {
            return Err(Error::Failed(format!(
                "{what} holds {} certificates; add them one at a time",
                certificates.len()
            )));
        }
        if let Some(der) = certificates.into_iter().next() {
            return Ok(der);
        }
    }
    Ok(bytes.to_vec())
}

fn now() -> Option<i64> {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .ok()
}

/// Whether `name` may name an addition: a registry key's name, so neither
/// empty nor holding a separator.
pub fn usable_name(name: &str) -> bool {
    !name.trim().is_empty() && !name.contains('\\') && !name.contains('/')
}

/// What `der` would be trusted as, or why it would not be: it must parse,
/// be a CA and not have expired. trustd checks again when it reads it — it
/// never trusts the writer — but checking here makes a mistake a message
/// rather than a line in a log.
pub fn vet(der: &[u8]) -> Result<Parsed, cert::Error> {
    cert::parse(der, now())
}

/// Trusts `der` under `name`, for `purposes` (ServerAuth when empty).
pub fn add(name: &str, der: &[u8], purposes: &[String]) -> Result<Parsed, Error> {
    if !usable_name(name) {
        return Err(Error::Failed(format!("{name:?} is not a usable name")));
    }
    let parsed = vet(der).map_err(|e| Error::Failed(format!("the certificate is {e}")))?;
    let shown = format!("{CERTIFICATES_KEY}\\{ADD_KEY}\\{name}");
    let add = certificates(ADD_KEY)?;
    let entry = open_or_create(Some(&add), name, &shown)?;
    if !purposes.is_empty() {
        let mut data = Vec::new();
        for purpose in purposes {
            data.extend_from_slice(purpose.as_bytes());
            data.push(0);
        }
        data.push(0);
        entry
            .set_value(PURPOSES_VALUE.as_bytes(), ValueType::MULTI_SZ, &data)
            .call()
            .map_err(|e| registry_error(&shown, e))?;
    }
    // The certificate goes last: until it exists the entry is incomplete,
    // and trustd skips incomplete entries rather than acting on half of one.
    entry
        .set_value(CERTIFICATE_VALUE.as_bytes(), ValueType::BINARY, der)
        .call()
        .map_err(|e| registry_error(&shown, e))?;
    Ok(parsed)
}

/// Takes back the addition `name`.
pub fn remove(name: &str) -> Result<(), Error> {
    let shown = format!("{CERTIFICATES_KEY}\\{ADD_KEY}\\{name}");
    let add = Key::open(
        None,
        &format!("{CERTIFICATES_KEY}\\{ADD_KEY}"),
        KeyAccess::ENUMERATE_SUB_KEYS,
        OpenFlags::empty(),
    )
    .map_err(|_| Error::NotFound(format!("no addition named {name}")))?;
    let entry = match Key::open(Some(&add), name, KeyAccess::DELETE, OpenFlags::empty()) {
        Ok(key) => key,
        Err(e) if e.kind() == ErrorKind::NotFound => {
            return Err(Error::NotFound(format!("no addition named {name}")));
        }
        Err(e) => return Err(registry_error(&shown, e)),
    };
    entry
        .delete_key(None, None)
        .map_err(|e| registry_error(&shown, e))
}

// ------------------------------------------------------------- distrusts ---

/// One certificate this machine refuses, and why, as whoever refused it
/// wrote.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Distrusted {
    pub fingerprint: String,
    pub reason: String,
}

/// Every distrust, by fingerprint.
///
/// Read from the registry rather than the socket: a distrusted certificate
/// is by definition not in the store, so the daemon cannot answer for it.
/// Only reads, so anyone may look; none at all is an empty list.
pub fn distrusted() -> Result<Vec<Distrusted>, Error> {
    let path = format!("{CERTIFICATES_KEY}\\{DISTRUST_KEY}");
    let key = match Key::open(None, &path, KeyAccess::QUERY_VALUE, OpenFlags::empty()) {
        Ok(key) => key,
        Err(e) if e.kind() == ErrorKind::NotFound => return Ok(Vec::new()),
        Err(e) => return Err(Error::Failed(format!("{path}: {e}"))),
    };
    let mut out = Vec::new();
    for value in key.values(None) {
        let Ok(value) = value else { continue };
        let Ok(name) = String::from_utf8(value.name.clone()) else {
            continue;
        };
        let end = value
            .data
            .iter()
            .position(|&b| b == 0)
            .unwrap_or(value.data.len());
        out.push(Distrusted {
            fingerprint: normalise_fingerprint(&name),
            reason: String::from_utf8_lossy(&value.data[..end]).into_owned(),
        });
    }
    out.sort_by(|a, b| a.fingerprint.cmp(&b.fingerprint));
    Ok(out)
}

/// Whether `text` is hex, as a fingerprint or a prefix of one is.
fn hex(text: &str) -> bool {
    !text.is_empty() && text.bytes().all(|b| b.is_ascii_hexdigit())
}

/// The whole fingerprint `text` stands for: a whole fingerprint in any of
/// the ways tools print them, or a prefix of at least eight digits of one
/// in `roots`.
///
/// An ambiguous prefix is refused rather than guessed at: distrusting the
/// wrong certificate is not a mistake worth being convenient about.
pub fn fingerprint_in(text: &str, roots: &[Root]) -> Result<String, Error> {
    let normalised = normalise_fingerprint(text);
    if !hex(&normalised) || normalised.len() > 64 {
        return Err(Error::Failed(format!(
            "{text} is not a SHA-256 fingerprint"
        )));
    }
    if normalised.len() == 64 {
        return Ok(normalised);
    }
    if normalised.len() < 8 {
        return Err(Error::Failed(format!(
            "{normalised} is too short; give at least eight digits"
        )));
    }
    let matches: Vec<&Root> = roots
        .iter()
        .filter(|r| r.fingerprint.starts_with(&normalised))
        .collect();
    match matches.as_slice() {
        [root] => Ok(root.fingerprint.clone()),
        [] => Err(Error::NotFound(format!(
            "no certificate in the store starts with {normalised} — give the whole fingerprint if you mean one the store does not have"
        ))),
        many => Err(Error::Failed(format!(
            "{normalised} matches {} certificates; be more specific",
            many.len()
        ))),
    }
}

/// The fingerprint to act on, from a whole fingerprint, a prefix of one as
/// `trust list` prints it (resolved against the store), or a certificate
/// file.
pub fn resolve(argument: &str) -> Result<String, Error> {
    let normalised = normalise_fingerprint(argument);
    if hex(&normalised) && normalised.len() == 64 {
        return Ok(normalised);
    }
    if hex(&normalised) && normalised.len() >= 8 {
        return fingerprint_in(argument, &roots(false, None)?);
    }
    let bytes = std::fs::read(argument).map_err(|e| Error::Failed(format!("{argument}: {e}")))?;
    let der = certificate(&bytes, argument)?;
    let parsed = cert::parse(&der, None).map_err(|e| {
        Error::Failed(format!(
            "{argument} is neither a SHA-256 fingerprint nor a certificate ({e})"
        ))
    })?;
    Ok(parsed.fingerprint)
}

/// Stops trusting the certificate `fingerprint`, wherever it came from,
/// noting `reason`. Says what it was, when the store had it: distrusting a
/// certificate the machine does not have is legitimate — the entry waits in
/// case one arrives — and looks identical otherwise.
pub fn distrust(fingerprint: &str, reason: &str) -> Result<Option<String>, Error> {
    let fingerprint = normalise_fingerprint(fingerprint);
    if !hex(&fingerprint) || fingerprint.len() != 64 {
        return Err(Error::Failed(format!(
            "{fingerprint} is not a whole SHA-256 fingerprint"
        )));
    }
    let key = certificates(DISTRUST_KEY)?;
    // Look before writing: afterwards trustd has already dropped the
    // certificate, so asking then would always answer "no match" and say
    // the opposite of the truth.
    let was = roots(false, None).ok().and_then(|list| {
        list.into_iter()
            .find(|r| r.fingerprint == fingerprint)
            .map(|r| r.subject)
    });
    let mut data = reason.as_bytes().to_vec();
    data.push(0);
    key.set_value(fingerprint.as_bytes(), ValueType::SZ, &data)
        .call()
        .map_err(|e| registry_error(&format!("{CERTIFICATES_KEY}\\{DISTRUST_KEY}"), e))?;
    Ok(was)
}

/// Trusts the distrusted certificate `argument` names again: a whole
/// fingerprint, or a prefix of one that is distrusted. Says which.
pub fn restore(argument: &str) -> Result<String, Error> {
    let normalised = normalise_fingerprint(argument);
    let fingerprint = if normalised.len() == 64 {
        normalised
    } else {
        // Resolve against what is distrusted, not against the store.
        let entries = distrusted()?;
        let matches: Vec<&Distrusted> = entries
            .iter()
            .filter(|d| d.fingerprint.starts_with(&normalised))
            .collect();
        match matches.as_slice() {
            [d] => d.fingerprint.clone(),
            [] => {
                return Err(Error::NotFound(format!(
                    "nothing distrusted starts with {normalised}"
                )));
            }
            many => {
                return Err(Error::Failed(format!(
                    "{normalised} matches {} distrust entries; be more specific",
                    many.len()
                )));
            }
        }
    };
    let path = format!("{CERTIFICATES_KEY}\\{DISTRUST_KEY}");
    let key = Key::open(None, &path, KeyAccess::SET_VALUE, OpenFlags::empty()).map_err(|e| {
        if e.kind() == ErrorKind::NotFound {
            Error::NotFound(format!("{fingerprint} is not distrusted"))
        } else {
            registry_error(&path, e)
        }
    })?;
    match key.delete_value(fingerprint.as_bytes(), None, None) {
        Ok(()) => Ok(fingerprint),
        Err(e) if e.kind() == ErrorKind::NotFound => {
            Err(Error::NotFound(format!("{fingerprint} is not distrusted")))
        }
        Err(e) => Err(registry_error(&path, e)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn root(fingerprint: &str) -> Root {
        Root {
            fingerprint: fingerprint.into(),
            ..Root::default()
        }
    }

    #[test]
    fn a_prefix_names_the_one_root_it_starts() {
        let a = format!("{}{}", "018e13f0", "0".repeat(56));
        let b = format!("{}{}", "018e13f1", "1".repeat(56));
        let roots = [root(&a), root(&b)];
        assert_eq!(fingerprint_in("018E13F0", &roots), Ok(a.clone()));
        assert_eq!(fingerprint_in("01:8e:13:f0", &roots), Ok(a.clone()));
        assert!(matches!(
            fingerprint_in("018e13f", &roots),
            Err(Error::Failed(_))
        ));
        assert!(matches!(
            fingerprint_in("018e13", &roots),
            Err(Error::Failed(_))
        ));
        assert!(matches!(
            fingerprint_in("deadbeef", &roots),
            Err(Error::NotFound(_))
        ));
        // A whole one stands for itself, in the store or not.
        let absent = "ab".repeat(32);
        assert_eq!(fingerprint_in(&absent, &roots), Ok(absent.clone()));
        assert!(matches!(
            fingerprint_in("not hex at all", &roots),
            Err(Error::Failed(_))
        ));
    }

    #[test]
    fn a_name_is_a_key_name() {
        assert!(usable_name("corp-ca"));
        assert!(!usable_name(""));
        assert!(!usable_name("  "));
        assert!(!usable_name("a\\b"));
        assert!(!usable_name("a/b"));
    }

    #[test]
    fn a_file_of_several_certificates_is_refused() {
        let one = "-----BEGIN CERTIFICATE-----\nMAA=\n-----END CERTIFICATE-----\n";
        assert_eq!(certificate(one.as_bytes(), "x").unwrap(), vec![0x30, 0x00]);
        let two = format!("{one}{one}");
        assert!(matches!(
            certificate(two.as_bytes(), "x"),
            Err(Error::Failed(_))
        ));
        // Not PEM: taken as DER.
        assert_eq!(
            certificate(&[0x30, 0x01, 0x00], "x").unwrap(),
            vec![0x30, 0x01, 0x00]
        );
    }
}
