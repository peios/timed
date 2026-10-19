//! Certificates: parsing, identity, and the two encodings the store needs.
//!
//! Everything here is pure. It reads DER that came from the shipped bundle
//! or from the registry — administrator-supplied rather than network-supplied,
//! but never assumed well-formed — and answers four questions: is this a
//! certificate, is it a CA, when does it expire, and what is it called.
//!
//! Two names matter and they are not the same thing:
//!
//! - the **fingerprint**, lowercase hex SHA-256 of the DER, which is how a
//!   `Distrust` entry names a certificate and how the store deduplicates;
//! - the **subject hash**, OpenSSL's `X509_NAME_hash`, which is the filename
//!   in a hashed certificate directory. That one is not ours to choose: it is
//!   whatever OpenSSL computes, or its `CApath` lookups silently find nothing.

use std::fmt::Write as _;

use der::{Decode, Encode};
use sha1::Sha1;
use sha2::{Digest, Sha256};
use x509_cert::Certificate;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Error {
    /// The bytes are not a certificate.
    Malformed(String),
    /// A certificate, but not a CA: no `basicConstraints` with `cA` true.
    NotACa,
    /// Past its `notAfter`.
    Expired,
    /// PEM that does not contain a certificate.
    NoCertificate,
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Error::Malformed(why) => write!(f, "not a certificate: {why}"),
            Error::NotACa => f.write_str("not a CA certificate (no basicConstraints cA)"),
            Error::Expired => f.write_str("expired"),
            Error::NoCertificate => f.write_str("no CERTIFICATE block"),
        }
    }
}

impl std::error::Error for Error {}

/// A certificate the store is willing to hold.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Parsed {
    pub der: Vec<u8>,
    /// Lowercase hex SHA-256 of `der`.
    pub fingerprint: String,
    /// RFC 4514-ish, for a person to read.
    pub subject: String,
    /// Seconds since the epoch.
    pub not_after: i64,
    /// OpenSSL's `X509_NAME_hash` of the subject, as it appears in a hashed
    /// directory (`<hash>.0`).
    pub subject_hash: String,
}

/// Parse and vet one certificate.
///
/// `now` is seconds since the epoch; pass `None` to skip the expiry check
/// (the shipped bundle is vetted at build time and an expired root there is
/// a packaging problem, not a reason to refuse the whole store).
pub fn parse(der: &[u8], now: Option<i64>) -> Result<Parsed, Error> {
    let certificate = Certificate::from_der(der).map_err(|e| Error::Malformed(e.to_string()))?;
    if !is_ca(&certificate) {
        return Err(Error::NotACa);
    }
    let not_after = certificate
        .tbs_certificate
        .validity
        .not_after
        .to_unix_duration()
        .as_secs() as i64;
    if let Some(now) = now
        && not_after <= now
    {
        return Err(Error::Expired);
    }
    let subject = certificate.tbs_certificate.subject.to_string();
    let subject_der = certificate
        .tbs_certificate
        .subject
        .to_der()
        .map_err(|e| Error::Malformed(e.to_string()))?;
    Ok(Parsed {
        der: der.to_vec(),
        fingerprint: fingerprint(der),
        subject,
        not_after,
        subject_hash: subject_hash(&subject_der).map_err(|e| Error::Malformed(e.to_string()))?,
    })
}

/// Lowercase hex SHA-256 of the DER.
pub fn fingerprint(der: &[u8]) -> String {
    let digest = Sha256::digest(der);
    let mut out = String::with_capacity(64);
    for byte in digest {
        let _ = write!(out, "{byte:02x}");
    }
    out
}

/// `basicConstraints` with `cA` true. A root without it is not one; we do
/// not fall back to "self-signed implies CA", because that is how a leaf
/// certificate becomes a trust anchor.
fn is_ca(certificate: &Certificate) -> bool {
    const BASIC_CONSTRAINTS: &str = "2.5.29.19";
    let Some(extensions) = certificate.tbs_certificate.extensions.as_ref() else {
        return false;
    };
    for extension in extensions {
        if extension.extn_id.to_string() != BASIC_CONSTRAINTS {
            continue;
        }
        // BasicConstraints ::= SEQUENCE { cA BOOLEAN DEFAULT FALSE, ... }
        let bytes = extension.extn_value.as_bytes();
        return match x509_cert::ext::pkix::BasicConstraints::from_der(bytes) {
            Ok(constraints) => constraints.ca,
            Err(_) => false,
        };
    }
    false
}

// --------------------------------------------------------------- details ---

/// What a person looking at a certificate wants to know about it. Unlike
/// [`parse`] this vets nothing: it describes whatever certificate it is
/// given, so a window can say what a file is before saying why it can't be
/// trusted.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Details {
    /// The subject's common name, organisation, unit and country, where it
    /// has them.
    pub common_name: Option<String>,
    pub organisation: Option<String>,
    pub unit: Option<String>,
    pub country: Option<String>,
    /// The whole subject and issuer, RFC 4514-ish.
    pub subject: String,
    pub issuer: String,
    /// Upper-case hex, colon-separated, as other tools print it.
    pub serial: String,
    /// Seconds since the epoch.
    pub not_before: i64,
    pub not_after: i64,
    /// The public key in words: "RSA 4096-bit", "ECDSA P-384".
    pub key: String,
    /// Whether `basicConstraints` says it is a CA.
    pub ca: bool,
}

impl Details {
    /// What to call it in a list: its common name, else its organisation,
    /// else its unit, else the whole subject.
    pub fn name(&self) -> &str {
        self.common_name
            .as_deref()
            .or(self.organisation.as_deref())
            .or(self.unit.as_deref())
            .unwrap_or(&self.subject)
    }
}

/// Describe one certificate.
pub fn describe(der: &[u8]) -> Result<Details, Error> {
    let certificate = Certificate::from_der(der).map_err(|e| Error::Malformed(e.to_string()))?;
    let tbs = &certificate.tbs_certificate;
    let mut details = Details {
        subject: tbs.subject.to_string(),
        issuer: tbs.issuer.to_string(),
        serial: {
            let bytes = tbs.serial_number.as_bytes();
            match bytes {
                [0, rest @ ..] if !rest.is_empty() => rest,
                _ => bytes,
            }
        }
        .iter()
        .map(|b| format!("{b:02X}"))
        .collect::<Vec<_>>()
        .join(":"),
        not_before: tbs.validity.not_before.to_unix_duration().as_secs() as i64,
        not_after: tbs.validity.not_after.to_unix_duration().as_secs() as i64,
        key: key_words(&tbs.subject_public_key_info),
        ca: is_ca(&certificate),
        ..Details::default()
    };
    for rdn in tbs.subject.0.iter() {
        for atv in rdn.0.iter() {
            let slot = match atv.oid.to_string().as_str() {
                "2.5.4.3" => &mut details.common_name,
                "2.5.4.10" => &mut details.organisation,
                "2.5.4.11" => &mut details.unit,
                "2.5.4.6" => &mut details.country,
                _ => continue,
            };
            if slot.is_none() {
                *slot = attribute_text(&atv.value);
            }
        }
    }
    Ok(details)
}

/// An attribute's value as text, whichever string type it was written in.
fn attribute_text(value: &der::Any) -> Option<String> {
    use der::asn1::{Ia5StringRef, PrintableStringRef, TeletexStringRef, Utf8StringRef};
    use der::{Tag, Tagged};
    let text = match value.tag() {
        Tag::Utf8String => value
            .decode_as::<Utf8StringRef<'_>>()
            .ok()?
            .as_str()
            .to_owned(),
        Tag::PrintableString => value
            .decode_as::<PrintableStringRef<'_>>()
            .ok()?
            .as_str()
            .to_owned(),
        Tag::Ia5String => value
            .decode_as::<Ia5StringRef<'_>>()
            .ok()?
            .as_str()
            .to_owned(),
        Tag::TeletexString => value
            .decode_as::<TeletexStringRef<'_>>()
            .ok()?
            .as_str()
            .to_owned(),
        Tag::BmpString => {
            // UCS-2, big-endian.
            let units: Vec<u16> = value
                .value()
                .as_chunks::<2>()
                .0
                .iter()
                .map(|pair| u16::from_be_bytes(*pair))
                .collect();
            String::from_utf16(&units).ok()?
        }
        _ => return None,
    };
    let text = text.trim();
    (!text.is_empty()).then(|| text.to_owned())
}

/// The public key's algorithm and size, in words.
fn key_words(info: &x509_cert::spki::SubjectPublicKeyInfoOwned) -> String {
    const RSA: &str = "1.2.840.113549.1.1.1";
    const EC: &str = "1.2.840.10045.2.1";
    const ED25519: &str = "1.3.101.112";
    const ED448: &str = "1.3.101.113";
    match info.algorithm.oid.to_string().as_str() {
        RSA => match info.subject_public_key.as_bytes().and_then(rsa_bits) {
            Some(bits) => format!("RSA {bits}-bit"),
            None => "RSA".into(),
        },
        EC => {
            let curve = info
                .algorithm
                .parameters
                .as_ref()
                .and_then(|p| p.decode_as::<der::asn1::ObjectIdentifier>().ok())
                .map(|oid| oid.to_string());
            match curve.as_deref() {
                Some("1.2.840.10045.3.1.7") => "ECDSA P-256".into(),
                Some("1.3.132.0.34") => "ECDSA P-384".into(),
                Some("1.3.132.0.35") => "ECDSA P-521".into(),
                _ => "ECDSA".into(),
            }
        }
        ED25519 => "Ed25519".into(),
        ED448 => "Ed448".into(),
        other => other.to_owned(),
    }
}

/// The size of an RSA key's modulus, from its `RSAPublicKey` encoding.
fn rsa_bits(key: &[u8]) -> Option<usize> {
    use der::Reader as _;
    let mut reader = der::SliceReader::new(key).ok()?;
    let modulus = reader
        .sequence(|r| {
            let modulus: der::asn1::UintRef<'_> = r.decode()?;
            let _exponent: der::asn1::UintRef<'_> = r.decode()?;
            Ok(modulus.as_bytes().to_vec())
        })
        .ok()?;
    let first = *modulus.first()?;
    Some(modulus.len() * 8 - first.leading_zeros() as usize)
}

// ------------------------------------------------------------------- PEM ---

const PEM_BEGIN: &str = "-----BEGIN CERTIFICATE-----";
const PEM_END: &str = "-----END CERTIFICATE-----";

/// Every certificate in a PEM document, in order. Anything that is not a
/// `CERTIFICATE` block — comments, other block types — is ignored, which is
/// what lets the shipped bundle carry its provenance header.
pub fn from_pem(text: &str) -> Vec<Vec<u8>> {
    let mut out = Vec::new();
    let mut body: Option<String> = None;
    for line in text.lines() {
        let line = line.trim();
        if line == PEM_BEGIN {
            body = Some(String::new());
        } else if line == PEM_END {
            if let Some(b) = body.take()
                && let Some(der) = base64_decode(&b)
            {
                out.push(der);
            }
        } else if let Some(b) = body.as_mut() {
            b.push_str(line);
        }
    }
    out
}

/// One certificate as a PEM block, 64 columns, trailing newline.
pub fn to_pem(der: &[u8]) -> String {
    let encoded = base64_encode(der);
    let mut out = String::with_capacity(encoded.len() + encoded.len() / 64 + 64);
    out.push_str(PEM_BEGIN);
    out.push('\n');
    for chunk in encoded.as_bytes().chunks(64) {
        out.push_str(std::str::from_utf8(chunk).expect("base64 is ASCII"));
        out.push('\n');
    }
    out.push_str(PEM_END);
    out.push('\n');
    out
}

const B64: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

fn base64_encode(data: &[u8]) -> String {
    let mut out = String::with_capacity(data.len().div_ceil(3) * 4);
    for chunk in data.chunks(3) {
        let b = [
            chunk[0],
            *chunk.get(1).unwrap_or(&0),
            *chunk.get(2).unwrap_or(&0),
        ];
        let n = (u32::from(b[0]) << 16) | (u32::from(b[1]) << 8) | u32::from(b[2]);
        out.push(B64[(n >> 18) as usize & 63] as char);
        out.push(B64[(n >> 12) as usize & 63] as char);
        out.push(if chunk.len() > 1 {
            B64[(n >> 6) as usize & 63] as char
        } else {
            '='
        });
        out.push(if chunk.len() > 2 {
            B64[n as usize & 63] as char
        } else {
            '='
        });
    }
    out
}

fn base64_decode(text: &str) -> Option<Vec<u8>> {
    let mut acc = 0u32;
    let mut bits = 0u32;
    let mut out = Vec::with_capacity(text.len() / 4 * 3);
    for byte in text.bytes() {
        let value = match byte {
            b'A'..=b'Z' => byte - b'A',
            b'a'..=b'z' => byte - b'a' + 26,
            b'0'..=b'9' => byte - b'0' + 52,
            b'+' => 62,
            b'/' => 63,
            b'=' => break,
            b' ' | b'\t' | b'\r' | b'\n' => continue,
            _ => return None,
        };
        acc = (acc << 6) | u32::from(value);
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push((acc >> bits) as u8);
        }
    }
    Some(out)
}

// --------------------------------------------------------- subject hash ---

/// OpenSSL's `X509_NAME_hash`: SHA-1 over the *canonical* encoding of the
/// name, first four bytes read little-endian, printed as eight hex digits.
///
/// The canonical form is OpenSSL's own (`x509_name_canon` in `x_name.c`) and
/// this must match it byte for byte or a `CApath` lookup finds nothing and
/// says nothing. Each attribute value of a string type is re-tagged
/// `UTF8String` and its bytes are folded — leading and trailing spaces
/// dropped, internal runs of spaces collapsed to one, ASCII letters
/// lowercased, non-ASCII bytes passed through untouched. Values of any other
/// type are copied verbatim. Each RDN is re-encoded as a DER `SET OF`, whose
/// members sort by their encodings.
pub fn subject_hash(name_der: &[u8]) -> Result<String, der::Error> {
    let canonical = canonical_name(name_der)?;
    let digest = Sha1::digest(&canonical);
    let value = u32::from_le_bytes([digest[0], digest[1], digest[2], digest[3]]);
    Ok(format!("{value:08x}"))
}

/// The tags OpenSSL folds (`ASN1_MASK_CANON`).
fn is_canon_string(tag: u8) -> bool {
    matches!(
        tag,
        0x0C  // UTF8String
        | 0x13 // PrintableString
        | 0x14 // T61String
        | 0x16 // IA5String
        | 0x1A // VisibleString
        | 0x1C // UniversalString
        | 0x1E // BMPString
    )
}

fn canonical_name(name_der: &[u8]) -> Result<Vec<u8>, der::Error> {
    let rdns = der_contents(name_der, 0x31)?; // SEQUENCE, tagged 0x30
    let mut sets = Vec::new();
    for rdn in rdns {
        let avas = der_elements(rdn)?;
        let mut encoded: Vec<Vec<u8>> = Vec::with_capacity(avas.len());
        for ava in avas {
            encoded.push(canonical_ava(ava)?);
        }
        // DER SET OF: members sorted by their encodings.
        encoded.sort();
        let mut body = Vec::new();
        for e in encoded {
            body.extend_from_slice(&e);
        }
        sets.push(tlv(0x31, &body));
    }
    // The canonical encoding is the concatenation of the RDN SETs and
    // nothing else: OpenSSL's i2d_name_canon appends each SET OF in turn
    // and never wraps them in the outer SEQUENCE a Name would normally
    // carry. Wrapping it produces a plausible, stable, wrong hash.
    let mut out = Vec::new();
    for set in sets {
        out.extend_from_slice(&set);
    }
    Ok(out)
}

/// One `AttributeTypeAndValue`, folded.
fn canonical_ava(ava: &[u8]) -> Result<Vec<u8>, der::Error> {
    let (tag, content, rest) = read_tlv(ava)?;
    if tag != 0x30 || !rest.is_empty() {
        return Err(der::Tag::Sequence.value_error());
    }
    let (oid_tag, oid, after_oid) = read_tlv(content)?;
    if oid_tag != 0x06 {
        return Err(der::Tag::Sequence.value_error());
    }
    let (value_tag, value, _) = read_tlv(after_oid)?;
    let mut body = tlv(0x06, oid);
    if is_canon_string(value_tag) {
        body.extend_from_slice(&tlv(0x0C, &fold(value)));
    } else {
        body.extend_from_slice(&tlv(value_tag, value));
    }
    Ok(tlv(0x30, &body))
}

/// OpenSSL's `asn1_string_canon` byte folding.
fn fold(value: &[u8]) -> Vec<u8> {
    let start = value.iter().position(|b| *b != b' ').unwrap_or(value.len());
    let end = value
        .iter()
        .rposition(|b| *b != b' ')
        .map_or(start, |i| i + 1);
    let trimmed = &value[start..end];
    let mut out = Vec::with_capacity(trimmed.len());
    let mut in_space = false;
    for &byte in trimmed {
        if byte == b' ' {
            if !in_space {
                out.push(b' ');
                in_space = true;
            }
            continue;
        }
        in_space = false;
        // Only ASCII is case-folded; anything else is opaque bytes, exactly
        // as OpenSSL treats it.
        out.push(if byte.is_ascii() {
            byte.to_ascii_lowercase()
        } else {
            byte
        });
    }
    out
}

// A minimal DER reader and writer: enough to walk a Name and rebuild it.

fn tlv(tag: u8, content: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(content.len() + 6);
    out.push(tag);
    let len = content.len();
    if len < 0x80 {
        out.push(len as u8);
    } else {
        let bytes = len.to_be_bytes();
        let first = bytes
            .iter()
            .position(|b| *b != 0)
            .unwrap_or(bytes.len() - 1);
        out.push(0x80 | (bytes.len() - first) as u8);
        out.extend_from_slice(&bytes[first..]);
    }
    out.extend_from_slice(content);
    out
}

/// Split one TLV off the front: its tag, its content, and what follows.
fn read_tlv(input: &[u8]) -> Result<(u8, &[u8], &[u8]), der::Error> {
    let bad = || der::Error::from(der::ErrorKind::Failed);
    let tag = *input.first().ok_or_else(bad)?;
    let first_len = *input.get(1).ok_or_else(bad)? as usize;
    let (len, header) = if first_len < 0x80 {
        (first_len, 2)
    } else {
        let count = first_len & 0x7F;
        if count == 0 || count > 4 {
            return Err(bad());
        }
        let bytes = input.get(2..2 + count).ok_or_else(bad)?;
        (
            bytes
                .iter()
                .fold(0usize, |acc, b| (acc << 8) | usize::from(*b)),
            2 + count,
        )
    };
    let content = input.get(header..header + len).ok_or_else(bad)?;
    Ok((tag, content, &input[header + len..]))
}

/// The elements of a constructed value, given the tag it must carry.
fn der_contents(input: &[u8], element_tag: u8) -> Result<Vec<&[u8]>, der::Error> {
    let (tag, content, rest) = read_tlv(input)?;
    if tag != 0x30 || !rest.is_empty() {
        return Err(der::Error::from(der::ErrorKind::Failed));
    }
    let mut out = Vec::new();
    let mut remaining = content;
    while !remaining.is_empty() {
        let (t, _, next) = read_tlv(remaining)?;
        if t != element_tag {
            return Err(der::Error::from(der::ErrorKind::Failed));
        }
        let consumed = remaining.len() - next.len();
        out.push(&remaining[..consumed]);
        remaining = next;
    }
    Ok(out)
}

/// The elements inside one constructed value.
fn der_elements(input: &[u8]) -> Result<Vec<&[u8]>, der::Error> {
    let (_, content, _) = read_tlv(input)?;
    let mut out = Vec::new();
    let mut remaining = content;
    while !remaining.is_empty() {
        let (_, _, next) = read_tlv(remaining)?;
        let consumed = remaining.len() - next.len();
        out.push(&remaining[..consumed]);
        remaining = next;
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Three real roots from Mozilla's set, with the subject hash `openssl
    /// x509 -noout -hash` prints for each. The second and third carry
    /// non-ASCII subjects, which is where a canonicalisation that transcodes
    /// (rather than passing bytes through) diverges from OpenSSL.
    const FIXTURES: &[(&str, &str)] = &[
        (include_str!("../tests/fixtures/comodo-ecc.pem"), "eed8c118"),
        (
            include_str!("../tests/fixtures/netlock-arany.pem"),
            "988a38cb",
        ),
        (
            include_str!("../tests/fixtures/microsec-2009.pem"),
            "8160b96c",
        ),
    ];

    #[test]
    fn subject_hashes_match_openssl() {
        for (pem, expected) in FIXTURES {
            let der = from_pem(pem);
            assert_eq!(der.len(), 1, "fixture holds one certificate");
            let parsed = parse(&der[0], None).expect("a real root parses");
            assert_eq!(&parsed.subject_hash, expected, "subject {}", parsed.subject);
        }
    }

    #[test]
    fn real_roots_parse_as_cas_with_sane_fields() {
        for (pem, _) in FIXTURES {
            let parsed = parse(&from_pem(pem)[0], None).unwrap();
            assert_eq!(parsed.fingerprint.len(), 64);
            assert!(
                parsed
                    .fingerprint
                    .bytes()
                    .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
            );
            assert!(parsed.not_after > 1_600_000_000, "{}", parsed.not_after);
            assert!(!parsed.subject.is_empty());
        }
    }

    #[test]
    fn pem_round_trips_and_a_bundle_yields_every_certificate() {
        let der = from_pem(FIXTURES[0].0);
        let pem = to_pem(&der[0]);
        assert_eq!(from_pem(&pem), der);
        // A concatenation with commentary between the blocks, as the shipped
        // bundle has.
        let bundle = format!(
            "# a header\n{}\n# and a note\n{}\n",
            to_pem(&der[0]),
            to_pem(&from_pem(FIXTURES[1].0)[0])
        );
        assert_eq!(from_pem(&bundle).len(), 2);
        assert!(from_pem("no certificates here").is_empty());
    }

    #[test]
    fn rubbish_is_refused_rather_than_believed() {
        assert!(matches!(parse(b"", None), Err(Error::Malformed(_))));
        assert!(matches!(
            parse(&[0x30, 0x82, 0xff, 0xff], None),
            Err(Error::Malformed(_))
        ));
        let real = from_pem(FIXTURES[0].0).remove(0);
        // Truncation.
        for cut in [1, 10, real.len() / 2, real.len() - 1] {
            assert!(parse(&real[..cut], None).is_err(), "truncated to {cut}");
        }
        // A single flipped byte must never panic.
        for i in (0..real.len()).step_by(7) {
            let mut mutated = real.clone();
            mutated[i] ^= 0x80;
            let _ = parse(&mutated, None);
        }
    }

    #[test]
    fn an_expired_certificate_is_refused_when_a_clock_is_given() {
        let der = from_pem(FIXTURES[0].0).remove(0);
        let parsed = parse(&der, None).unwrap();
        assert!(parse(&der, Some(parsed.not_after - 1)).is_ok());
        assert_eq!(parse(&der, Some(parsed.not_after + 1)), Err(Error::Expired));
    }

    #[test]
    fn real_roots_are_described_as_openssl_describes_them() {
        let comodo = describe(&from_pem(FIXTURES[0].0)[0]).unwrap();
        assert_eq!(comodo.name(), "COMODO ECC Certification Authority");
        assert_eq!(comodo.organisation.as_deref(), Some("COMODO CA Limited"));
        assert_eq!(comodo.country.as_deref(), Some("GB"));
        assert_eq!(
            comodo.serial,
            "1F:47:AF:AA:62:00:70:50:54:4C:01:9E:9B:63:99:2A"
        );
        assert_eq!(comodo.not_before, 1_204_761_600);
        assert_eq!(comodo.key, "ECDSA P-384");
        assert_eq!(comodo.subject, comodo.issuer);
        assert!(comodo.ca);

        // A UTF8String subject with non-ASCII letters, and an RSA key.
        let netlock = describe(&from_pem(FIXTURES[1].0)[0]).unwrap();
        assert_eq!(netlock.name(), "NetLock Arany (Class Gold) Főtanúsítvány");
        assert_eq!(
            netlock.unit.as_deref(),
            Some("Tanúsítványkiadók (Certification Services)")
        );
        assert_eq!(netlock.key, "RSA 2048-bit");

        let microsec = describe(&from_pem(FIXTURES[2].0)[0]).unwrap();
        assert_eq!(microsec.key, "RSA 2048-bit");
        // DER pads a serial whose top bit is set with a zero byte; nobody
        // prints it.
        assert_eq!(microsec.serial, "C2:7E:43:04:4E:47:3F:19");
    }

    #[test]
    fn describing_rubbish_is_an_error_not_a_panic() {
        assert!(describe(b"").is_err());
        let real = from_pem(FIXTURES[0].0).remove(0);
        for i in (0..real.len()).step_by(5) {
            let mut mutated = real.clone();
            mutated[i] ^= 0x80;
            let _ = describe(&mutated);
        }
    }

    #[test]
    fn folding_follows_openssls_rules() {
        assert_eq!(fold(b"  Peios   Root  CA "), b"peios root ca".to_vec());
        assert_eq!(fold(b"   "), b"".to_vec());
        assert_eq!(fold(b""), b"".to_vec());
        // Non-ASCII bytes pass through untouched, case and all.
        assert_eq!(
            fold(&[0xC3, 0x9A, b' ', b' ', b'X']),
            vec![0xC3, 0x9A, b' ', b'x']
        );
    }
}
