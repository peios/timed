//! Network Time Security, RFC 8915.
//!
//! NTS is two protocols. **NTS-KE** runs once over TLS on port 4460 and
//! hands back a set of cookies and a pair of AEAD keys extracted from the
//! TLS session; **NTS for NTPv4** then authenticates ordinary NTP packets on
//! port 123 using those keys, with no further TLS and no per-client state on
//! the server — the cookie carries it.
//!
//! This module holds the record format for the first and the authenticator
//! for the second. What it does not hold is TLS: the KE handshake belongs to
//! the daemon, which owns the rustls configuration and the root store. That
//! keeps this crate free of I/O and of any opinion about who to trust.
//!
//! # Why the cookies are the interesting part
//!
//! A cookie is opaque to us and is spent when used: the client sends one and
//! the server returns a fresh one in the encrypted part of its reply. Run
//! out and the whole KE handshake has to be redone, which is why a client
//! keeps a small store of them and asks for replacements with placeholders.
//! An observer must not be able to link two requests from the same client,
//! which is the reason cookies are not reused and the reason replacements
//! arrive encrypted rather than in the clear.

use aes_siv::aead::{Aead, KeyInit, Payload};
use aes_siv::{Aes128SivAead, Nonce};

use crate::extension::{ExtensionField, NTS_AUTHENTICATOR};
use crate::WireError;

/// The protocol id NTS-KE negotiates for us: NTPv4. RFC 8915 §7.2.
pub const NEXT_PROTO_NTPV4: u16 = 0;

/// `AEAD_AES_SIV_CMAC_256`, IANA id 15. The one algorithm RFC 8915 §5.1
/// requires every implementation to support, and the only one this client
/// offers — a second algorithm would be a negotiation surface bought for no
/// benefit, since the mandatory one is not in question.
pub const AEAD_AES_SIV_CMAC_256: u16 = 15;

/// Bytes of key material each direction takes, for the AEAD above.
pub const KEY_LEN: usize = 32;

/// The nonce length this client uses. RFC 8915 leaves it open; 16 bytes is
/// what the AEAD's synthetic IV is sized for and what every deployed server
/// expects.
pub const NONCE_LEN: usize = 16;

/// RFC 8915 §4.3: the TLS exporter label, spelled exactly.
pub const EXPORTER_LABEL: &[u8] = b"EXPORTER-network-time-security";

/// The ALPN protocol name the KE connection must negotiate. A server that
/// does not select it is not an NTS-KE server, whatever else it may be.
pub const ALPN: &[u8] = b"ntske/1";

/// The KE port, RFC 8915 §4.1.9.
pub const DEFAULT_KE_PORT: u16 = 4460;
/// The NTP port a negotiated server is reached on unless it says otherwise.
pub const DEFAULT_NTP_PORT: u16 = 123;

/// The exporter context for one direction's key.
///
/// Five bytes: the next-protocol id, the AEAD id, and a byte saying which
/// direction. Getting the direction byte backwards yields two keys that are
/// each individually valid and mutually useless, which fails in a way that
/// looks like a server bug — so it is written once, here.
pub fn exporter_context(client_to_server: bool) -> [u8; 5] {
    let mut context = [0u8; 5];
    context[0..2].copy_from_slice(&NEXT_PROTO_NTPV4.to_be_bytes());
    context[2..4].copy_from_slice(&AEAD_AES_SIV_CMAC_256.to_be_bytes());
    context[4] = u8::from(!client_to_server);
    context
}

/// The two directional keys from one KE session.
///
/// Not `Debug`: these are secrets, and the single most likely way for a
/// secret to reach a log is a struct that derives `Debug` and gets
/// interpolated into a diagnostic years later.
#[derive(Clone)]
pub struct Keys {
    pub c2s: [u8; KEY_LEN],
    pub s2c: [u8; KEY_LEN],
}

impl core::fmt::Debug for Keys {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("Keys(<redacted>)")
    }
}

impl Drop for Keys {
    fn drop(&mut self) {
        // Best effort. Rust will not promise this is not optimised away, and
        // a determined attacker with our address space has already won — but
        // it costs nothing and shortens the window in which a core dump or a
        // reused allocation holds usable key material.
        self.c2s.fill(0);
        self.s2c.fill(0);
    }
}

// ---------------------------------------------------------------------------
// NTS-KE records
// ---------------------------------------------------------------------------

/// Record types, RFC 8915 §4.1.
pub mod record_type {
    pub const END_OF_MESSAGE: u16 = 0;
    pub const NEXT_PROTOCOL: u16 = 1;
    pub const ERROR: u16 = 2;
    pub const WARNING: u16 = 3;
    pub const AEAD_ALGORITHM: u16 = 4;
    pub const NEW_COOKIE: u16 = 5;
    pub const SERVER: u16 = 6;
    pub const PORT: u16 = 7;
}

/// One NTS-KE record.
///
/// ```text
/// +-+-----------------------------+-------------------------------+
/// |C|        Record Type          |          Body Length          |
/// +-+-----------------------------+-------------------------------+
/// |                          Record Body                          |
/// ```
///
/// The critical bit is the top bit of the type word, and its meaning is the
/// point of the whole encoding: a record we do not recognise is skipped if
/// it is clear and is a fatal error if it is set. That is what lets the
/// protocol grow without a version number.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Record {
    pub critical: bool,
    pub record_type: u16,
    pub body: Vec<u8>,
}

/// The largest KE message this client will assemble before giving up.
///
/// The KE stream arrives over TLS from a server we have authenticated, so
/// this is not a defence against a stranger — it is a defence against a
/// server that is broken or hostile *after* authentication, which is a
/// server we have every reason to keep at arm's length anyway. Eight
/// cookies of a few hundred bytes is the honest size; 64 KiB is room to
/// spare.
pub const MAX_KE_MESSAGE: usize = 65536;

impl Record {
    pub fn new(critical: bool, record_type: u16, body: impl Into<Vec<u8>>) -> Record {
        Record { critical, record_type, body: body.into() }
    }

    pub fn encode_into(&self, out: &mut Vec<u8>) {
        let mut head = self.record_type & 0x7FFF;
        if self.critical {
            head |= 0x8000;
        }
        out.extend_from_slice(&head.to_be_bytes());
        out.extend_from_slice(&(self.body.len() as u16).to_be_bytes());
        out.extend_from_slice(&self.body);
    }

    /// Read a whole KE message: records up to and including end-of-message.
    ///
    /// Returns `Ok(None)` when the buffer holds a valid prefix but not yet a
    /// complete message, which is how the caller knows to read more from the
    /// TLS stream rather than to give up. Any other shortfall is an error.
    pub fn decode_message(bytes: &[u8]) -> Result<Option<Vec<Record>>, WireError> {
        if bytes.len() > MAX_KE_MESSAGE {
            return Err(WireError::BadLength(bytes.len() as u32));
        }
        let mut records = Vec::new();
        let mut rest = bytes;
        loop {
            if rest.len() < 4 {
                return Ok(None);
            }
            let head = u16::from_be_bytes([rest[0], rest[1]]);
            let body_len = u16::from_be_bytes([rest[2], rest[3]]) as usize;
            if rest.len() < 4 + body_len {
                return Ok(None);
            }
            let record = Record {
                critical: head & 0x8000 != 0,
                record_type: head & 0x7FFF,
                body: rest[4..4 + body_len].to_vec(),
            };
            let end = record.record_type == record_type::END_OF_MESSAGE;
            records.push(record);
            rest = &rest[4 + body_len..];
            if end {
                return Ok(Some(records));
            }
            if records.len() > 1024 {
                // A server that sends a thousand records without ending the
                // message is not going to end it.
                return Err(WireError::BadLength(records.len() as u32));
            }
        }
    }

    /// The body read as a sequence of 16-bit values, which is the shape of
    /// the next-protocol and AEAD-algorithm records.
    pub fn body_as_u16s(&self) -> Result<Vec<u16>, WireError> {
        if self.body.len() % 2 != 0 {
            return Err(WireError::BadLength(self.body.len() as u32));
        }
        Ok(self.body.chunks_exact(2).map(|c| u16::from_be_bytes([c[0], c[1]])).collect())
    }

    /// The body read as a single 16-bit value: the port and error records.
    pub fn body_as_u16(&self) -> Result<u16, WireError> {
        if self.body.len() != 2 {
            return Err(WireError::BadLength(self.body.len() as u32));
        }
        Ok(u16::from_be_bytes([self.body[0], self.body[1]]))
    }
}

/// The request this client sends: what we speak, what we can decrypt, done.
///
/// Deliberately minimal. Every optional record is a thing the server can
/// disagree with, and a client that asks for nothing it does not need has
/// nothing to be told "no" about.
pub fn client_request() -> Vec<u8> {
    let mut out = Vec::new();
    Record::new(true, record_type::NEXT_PROTOCOL, NEXT_PROTO_NTPV4.to_be_bytes().to_vec())
        .encode_into(&mut out);
    Record::new(true, record_type::AEAD_ALGORITHM, AEAD_AES_SIV_CMAC_256.to_be_bytes().to_vec())
        .encode_into(&mut out);
    Record::new(true, record_type::END_OF_MESSAGE, Vec::new()).encode_into(&mut out);
    out
}

/// What a successful KE exchange yields.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Negotiated {
    /// Cookies, in the order the server sent them. Spent oldest first.
    pub cookies: Vec<Vec<u8>>,
    /// The NTP server to actually talk to, when the KE server names a
    /// different one. `None` means "the host we just spoke to".
    pub server: Option<String>,
    pub port: u16,
}

/// Errors a KE server can report, RFC 8915 §4.1.3, plus what we make of a
/// reply that is well-formed but unusable.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum KeError {
    /// The server rejected us, with its code.
    Server(u16),
    /// A critical record we do not understand. Per §4.1, this is fatal by
    /// construction — the sender marked it as something we must not ignore.
    UnknownCritical(u16),
    /// The server did not agree to NTPv4, or picked an AEAD we did not
    /// offer. Either way there is nothing to do with the session.
    NoAgreement(&'static str),
    /// No cookies, so nothing to authenticate a single NTP packet with.
    NoCookies,
    Wire(WireError),
}

impl core::fmt::Display for KeError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            KeError::Server(code) => {
                let meaning = match code {
                    0 => " (unrecognised critical record)",
                    1 => " (bad request)",
                    2 => " (internal server error)",
                    _ => "",
                };
                write!(f, "NTS-KE server error {code}{meaning}")
            }
            KeError::UnknownCritical(t) => write!(f, "unknown critical record type {t}"),
            KeError::NoAgreement(what) => write!(f, "no agreement on {what}"),
            KeError::NoCookies => write!(f, "server sent no cookies"),
            KeError::Wire(e) => write!(f, "{e}"),
        }
    }
}

impl std::error::Error for KeError {}

impl From<WireError> for KeError {
    fn from(e: WireError) -> KeError {
        KeError::Wire(e)
    }
}

/// The largest cookie worth keeping.
///
/// Cookies are opaque, so there is no structural check to make — only a
/// size one. Servers in the wild issue cookies of about 100 to 200 bytes;
/// a kilobyte is far past any of them and stops a server from making its
/// clients hold megabytes of state on its say-so.
pub const MAX_COOKIE: usize = 1024;
/// How many cookies to keep. RFC 8915 §5.7 suggests eight, which is what
/// servers issue, and is enough to survive a run of lost packets without a
/// fresh handshake.
pub const COOKIE_TARGET: usize = 8;

/// Interpret a complete KE response.
pub fn interpret(records: &[Record]) -> Result<Negotiated, KeError> {
    let mut out = Negotiated { port: DEFAULT_NTP_PORT, ..Negotiated::default() };
    let mut agreed_protocol = false;
    let mut agreed_aead = false;

    for record in records {
        match record.record_type {
            record_type::ERROR => return Err(KeError::Server(record.body_as_u16()?)),
            // A warning is advisory by definition, and RFC 8915 defines no
            // warning codes. Recording it and carrying on is the whole of
            // the correct behaviour.
            record_type::WARNING => {}
            record_type::NEXT_PROTOCOL => {
                agreed_protocol = record.body_as_u16s()?.contains(&NEXT_PROTO_NTPV4);
            }
            record_type::AEAD_ALGORITHM => {
                agreed_aead = record.body_as_u16s()?.contains(&AEAD_AES_SIV_CMAC_256);
            }
            record_type::NEW_COOKIE => {
                if record.body.is_empty() || record.body.len() > MAX_COOKIE {
                    return Err(KeError::Wire(WireError::BadLength(record.body.len() as u32)));
                }
                if out.cookies.len() < COOKIE_TARGET {
                    out.cookies.push(record.body.clone());
                }
            }
            record_type::SERVER => {
                // A hostname, and one we are about to resolve and then
                // validate a certificate against, so it gets checked for
                // being a hostname before it goes anywhere near either.
                let name = core::str::from_utf8(&record.body)
                    .map_err(|_| KeError::NoAgreement("server name is not text"))?;
                if !is_plausible_host(name) {
                    return Err(KeError::NoAgreement("server name is not a host"));
                }
                out.server = Some(name.to_string());
            }
            record_type::PORT => out.port = record.body_as_u16()?,
            record_type::END_OF_MESSAGE => {}
            other => {
                if record.critical {
                    return Err(KeError::UnknownCritical(other));
                }
            }
        }
    }

    if !agreed_protocol {
        return Err(KeError::NoAgreement("next protocol"));
    }
    if !agreed_aead {
        return Err(KeError::NoAgreement("AEAD algorithm"));
    }
    if out.cookies.is_empty() {
        return Err(KeError::NoCookies);
    }
    Ok(out)
}

/// Is this text something we are willing to resolve and validate against?
///
/// Not a full hostname grammar — a deliberately narrow filter over what a
/// server may redirect us to. The KE server has been authenticated by this
/// point, so this is not the primary defence; it is the check that stops a
/// compromised or careless one from steering us at something that is not a
/// host at all.
fn is_plausible_host(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 253
        && name.split('.').all(|label| {
            !label.is_empty()
                && label.len() <= 63
                && label.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
        })
}

// ---------------------------------------------------------------------------
// The authenticator extension field
// ---------------------------------------------------------------------------

/// Build the authenticator for a packet under construction.
///
/// `prefix` is every byte of the packet so far — the fixed header and all
/// extension fields that precede this one — and becomes the AEAD's
/// associated data. That is the whole security property: the tag covers the
/// packet as it will be sent, so an attacker cannot alter a timestamp, a
/// stratum or a cookie without invalidating it.
///
/// `plaintext` is the extension fields that travel encrypted, empty for a
/// plain client request.
pub fn seal_authenticator(
    key: &[u8; KEY_LEN],
    nonce: &[u8; NONCE_LEN],
    prefix: &[u8],
    plaintext: &[u8],
) -> Result<ExtensionField, WireError> {
    let cipher = Aes128SivAead::new(key.into());
    let ciphertext = cipher
        .encrypt(&Nonce::from(*nonce), Payload { msg: plaintext, aad: prefix })
        .map_err(|_| WireError::NotAuthentic)?;

    let mut value = Vec::with_capacity(4 + NONCE_LEN + ciphertext.len() + 8);
    value.extend_from_slice(&(NONCE_LEN as u16).to_be_bytes());
    value.extend_from_slice(&(ciphertext.len() as u16).to_be_bytes());
    value.extend_from_slice(nonce);
    pad_to_four(&mut value, NONCE_LEN);
    value.extend_from_slice(&ciphertext);
    pad_to_four(&mut value, ciphertext.len());
    Ok(ExtensionField::new(NTS_AUTHENTICATOR, value))
}

fn pad_to_four(out: &mut Vec<u8>, written: usize) {
    let slack = (4 - (written % 4)) % 4;
    out.resize(out.len() + slack, 0);
}

/// Verify a received packet's authenticator and return what it encrypted.
///
/// `whole` is the entire datagram as it arrived and `authenticator_at` is
/// the byte offset of the authenticator field within it. The associated
/// data is `whole[..authenticator_at]` — the bytes, exactly as received,
/// never a re-encoding of the parsed form. Re-encoding would verify that we
/// can reproduce the packet rather than that the server sent it, and the
/// two differ precisely when it matters.
pub fn open_authenticator(
    key: &[u8; KEY_LEN],
    whole: &[u8],
    authenticator_at: usize,
    field_value: &[u8],
) -> Result<Vec<u8>, WireError> {
    if authenticator_at > whole.len() {
        return Err(WireError::BadLength(authenticator_at as u32));
    }
    if field_value.len() < 4 {
        return Err(WireError::Truncated { need: 4, have: field_value.len() });
    }
    let nonce_len = u16::from_be_bytes([field_value[0], field_value[1]]) as usize;
    let ct_len = u16::from_be_bytes([field_value[2], field_value[3]]) as usize;

    // Both run to a four-byte boundary, and both are lengths a stranger
    // chose. Compute where each ends and check the total against what is
    // actually here before slicing anything.
    let nonce_end = 4 + nonce_len.next_multiple_of(4);
    let ct_end = nonce_end + ct_len.next_multiple_of(4);
    if nonce_len != NONCE_LEN || ct_end > field_value.len() {
        return Err(WireError::BadLength(ct_len as u32));
    }

    let nonce = &field_value[4..4 + nonce_len];
    let ciphertext = &field_value[nonce_end..nonce_end + ct_len];

    let cipher = Aes128SivAead::new(key.into());
    cipher
        .decrypt(
            &Nonce::try_from(nonce).map_err(|_| WireError::BadLength(nonce_len as u32))?,
            Payload { msg: ciphertext, aad: &whole[..authenticator_at] },
        )
        .map_err(|_| WireError::NotAuthentic)
}

#[cfg(test)]
mod tests {
    use super::*;

    const KEY: [u8; KEY_LEN] = [0x42; KEY_LEN];
    const NONCE: [u8; NONCE_LEN] = [0x17; NONCE_LEN];

    #[test]
    fn the_exporter_context_is_five_bytes_and_direction_aware() {
        assert_eq!(exporter_context(true), [0, 0, 0, 15, 0]);
        assert_eq!(exporter_context(false), [0, 0, 0, 15, 1]);
    }

    #[test]
    fn a_ke_message_round_trips() {
        let bytes = client_request();
        let records = Record::decode_message(&bytes).unwrap().expect("complete");
        assert_eq!(records.len(), 3);
        assert!(records.iter().all(|r| r.critical));
        assert_eq!(records[0].body_as_u16().unwrap(), NEXT_PROTO_NTPV4);
        assert_eq!(records[1].body_as_u16().unwrap(), AEAD_AES_SIV_CMAC_256);
    }

    #[test]
    fn an_incomplete_message_asks_for_more_rather_than_failing() {
        let bytes = client_request();
        for cut in 0..bytes.len() - 1 {
            assert_eq!(Record::decode_message(&bytes[..cut]), Ok(None), "at {cut}");
        }
    }

    #[test]
    fn a_server_error_record_is_reported_as_one() {
        let records = vec![
            Record::new(true, record_type::ERROR, 1u16.to_be_bytes().to_vec()),
            Record::new(true, record_type::END_OF_MESSAGE, vec![]),
        ];
        assert_eq!(interpret(&records), Err(KeError::Server(1)));
    }

    #[test]
    fn an_unknown_critical_record_is_fatal_and_a_known_one_is_not() {
        let mut records = vec![
            Record::new(true, record_type::NEXT_PROTOCOL, 0u16.to_be_bytes().to_vec()),
            Record::new(true, record_type::AEAD_ALGORITHM, 15u16.to_be_bytes().to_vec()),
            Record::new(false, record_type::NEW_COOKIE, vec![9; 100]),
            Record::new(false, 0x4242, vec![1, 2, 3]),
            Record::new(true, record_type::END_OF_MESSAGE, vec![]),
        ];
        assert!(interpret(&records).is_ok(), "a non-critical unknown is skipped");

        records[3].critical = true;
        assert_eq!(interpret(&records), Err(KeError::UnknownCritical(0x4242)));
    }

    #[test]
    fn agreement_on_both_is_required() {
        let cookie = Record::new(false, record_type::NEW_COOKIE, vec![9; 100]);
        let end = Record::new(true, record_type::END_OF_MESSAGE, vec![]);

        let no_aead = vec![
            Record::new(true, record_type::NEXT_PROTOCOL, 0u16.to_be_bytes().to_vec()),
            cookie.clone(),
            end.clone(),
        ];
        assert_eq!(interpret(&no_aead), Err(KeError::NoAgreement("AEAD algorithm")));

        // A server that agrees to an AEAD we did not offer is refused, not
        // silently taken as agreement.
        let wrong_aead = vec![
            Record::new(true, record_type::NEXT_PROTOCOL, 0u16.to_be_bytes().to_vec()),
            Record::new(true, record_type::AEAD_ALGORITHM, 17u16.to_be_bytes().to_vec()),
            cookie,
            end,
        ];
        assert_eq!(interpret(&wrong_aead), Err(KeError::NoAgreement("AEAD algorithm")));
    }

    #[test]
    fn cookies_are_bounded_in_size_and_number() {
        let mut records = vec![
            Record::new(true, record_type::NEXT_PROTOCOL, 0u16.to_be_bytes().to_vec()),
            Record::new(true, record_type::AEAD_ALGORITHM, 15u16.to_be_bytes().to_vec()),
        ];
        for _ in 0..50 {
            records.push(Record::new(false, record_type::NEW_COOKIE, vec![1; 100]));
        }
        records.push(Record::new(true, record_type::END_OF_MESSAGE, vec![]));
        assert_eq!(interpret(&records).unwrap().cookies.len(), COOKIE_TARGET);

        records[2] = Record::new(false, record_type::NEW_COOKIE, vec![1; MAX_COOKIE + 1]);
        assert!(matches!(interpret(&records), Err(KeError::Wire(WireError::BadLength(_)))));
    }

    #[test]
    fn a_redirect_to_something_that_is_not_a_host_is_refused() {
        let ok = |body: &[u8]| {
            let records = vec![
                Record::new(true, record_type::NEXT_PROTOCOL, 0u16.to_be_bytes().to_vec()),
                Record::new(true, record_type::AEAD_ALGORITHM, 15u16.to_be_bytes().to_vec()),
                Record::new(false, record_type::NEW_COOKIE, vec![9; 100]),
                Record::new(false, record_type::SERVER, body.to_vec()),
                Record::new(true, record_type::END_OF_MESSAGE, vec![]),
            ];
            interpret(&records).is_ok()
        };
        assert!(ok(b"ntp.example.org"));
        assert!(!ok(b""));
        assert!(!ok(b"a..b"));
        assert!(!ok(b"has space"));
        assert!(!ok(b"\xff\xfe"));
        assert!(!ok(&vec![b'a'; 300]));
    }

    #[test]
    fn the_authenticator_round_trips_and_covers_the_prefix() {
        let prefix = b"a forty-eight byte header and some fields".to_vec();
        let plaintext = b"an encrypted extension field".to_vec();
        let field = seal_authenticator(&KEY, &NONCE, &prefix, &plaintext).unwrap();

        let mut whole = prefix.clone();
        let at = whole.len();
        field.encode_into(&mut whole);

        let opened = open_authenticator(&KEY, &whole, at, &field.value).unwrap();
        assert_eq!(opened, plaintext);

        // Change one byte of the covered prefix and it must stop verifying.
        let mut tampered = whole.clone();
        tampered[3] ^= 1;
        assert_eq!(
            open_authenticator(&KEY, &tampered, at, &field.value),
            Err(WireError::NotAuthentic)
        );
    }

    #[test]
    fn a_lying_length_in_the_authenticator_does_not_slice_out_of_bounds() {
        // Nonce and ciphertext lengths are attacker-chosen; the field is
        // short. Every combination must be refused rather than panicking.
        for nonce_len in [0u16, 1, 16, 4096, u16::MAX] {
            for ct_len in [0u16, 1, 32, 4096, u16::MAX] {
                let mut value = Vec::new();
                value.extend_from_slice(&nonce_len.to_be_bytes());
                value.extend_from_slice(&ct_len.to_be_bytes());
                value.extend_from_slice(&[0u8; 24]);
                let whole = vec![0u8; 48];
                let _ = open_authenticator(&KEY, &whole, 48, &value);
            }
        }
    }

    #[test]
    fn keys_do_not_print_themselves() {
        let keys = Keys { c2s: [1; KEY_LEN], s2c: [2; KEY_LEN] };
        assert_eq!(format!("{keys:?}"), "Keys(<redacted>)");
    }
}
