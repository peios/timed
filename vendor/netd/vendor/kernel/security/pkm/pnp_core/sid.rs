//! Security identifiers as identity facts.
//!
//! A SID (security identifier) is KACS's name for a principal: a user, a
//! group, a service, a confinement, a capability. PNP compares them only
//! — it never resolves, evaluates or trusts them — so the type here is an
//! owned, fixed-size byte value with a parser for the textual form rules
//! are written in (`S-1-5-18`), the two derivations authors rely on (a
//! well-known name, a service name), and equality. The binary layout is
//! PCDS's: revision, sub-authority count, a 48-bit big-endian identifier
//! authority, then little-endian 32-bit sub-authorities.

use core::fmt;

use crate::pnp_core::sha1::sha1;

/// Most sub-authorities a SID may carry (PCDS).
pub const MAX_SUB_AUTHORITIES: usize = crate::peios_uapi::KACS_SID_MAX_SUB_AUTHORITIES as usize;
/// Largest SID in bytes: header plus every sub-authority.
pub const MAX_SID_BYTES: usize = 8 + 4 * MAX_SUB_AUTHORITIES;

/// An owned SID. Equality is byte equality of the used prefix.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct Sid {
    len: u8,
    bytes: [u8; MAX_SID_BYTES],
}

#[cfg(feature = "kernel")]
impl crate::pnp_core::pkm_alloc::TryClone for Sid {
    fn try_clone(&self) -> Result<Self, crate::pnp_core::pkm_alloc::AllocError> {
        Ok(*self)
    }
}

impl Sid {
    /// Builds a SID from its parts. `None` if there are too many
    /// sub-authorities or the authority does not fit 48 bits.
    pub fn new(authority: u64, subs: &[u32]) -> Option<Sid> {
        if subs.len() > MAX_SUB_AUTHORITIES || authority >= 1 << 48 {
            return None;
        }
        Some(Sid::build(authority, subs))
    }

    /// `new` after its checks: callers guarantee the bounds.
    fn build(authority: u64, subs: &[u32]) -> Sid {
        let mut bytes = [0u8; MAX_SID_BYTES];
        bytes[0] = 1;
        bytes[1] = subs.len() as u8;
        bytes[2..8].copy_from_slice(&authority.to_be_bytes()[2..]);
        for (i, sub) in subs.iter().enumerate() {
            bytes[8 + i * 4..12 + i * 4].copy_from_slice(&sub.to_le_bytes());
        }
        Sid {
            len: (8 + subs.len() * 4) as u8,
            bytes,
        }
    }

    /// Reads a SID from its binary form, which must be exactly the SID.
    pub fn from_bytes(raw: &[u8]) -> Option<Sid> {
        if raw.len() < 8 || raw[0] != 1 {
            return None;
        }
        let count = usize::from(raw[1]);
        if count > MAX_SUB_AUTHORITIES || raw.len() != 8 + count * 4 {
            return None;
        }
        let mut bytes = [0u8; MAX_SID_BYTES];
        bytes[..raw.len()].copy_from_slice(raw);
        Some(Sid {
            len: raw.len() as u8,
            bytes,
        })
    }

    /// Parses the textual form: `S-1-<authority>-<sub>[-<sub>…]`. The
    /// leading `S` is case-insensitive; numbers are decimal.
    pub fn parse_str(s: &str) -> Option<Sid> {
        let mut parts = s.split('-');
        let tag = parts.next()?;
        if !(tag == "S" || tag == "s") {
            return None;
        }
        if parts.next()?.parse::<u8>().ok()? != 1 {
            return None;
        }
        let authority: u64 = parts.next()?.parse().ok()?;
        let mut subs = [0u32; MAX_SUB_AUTHORITIES];
        let mut n = 0usize;
        for part in parts {
            if n == MAX_SUB_AUTHORITIES || part.is_empty() {
                return None;
            }
            subs[n] = part.parse().ok()?;
            n += 1;
        }
        Sid::new(authority, &subs[..n])
    }

    /// The binary form.
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes[..usize::from(self.len)]
    }

    /// The 48-bit identifier authority.
    pub fn authority(&self) -> u64 {
        let mut buf = [0u8; 8];
        buf[2..].copy_from_slice(&self.bytes[2..8]);
        u64::from_be_bytes(buf)
    }

    /// Number of sub-authorities.
    pub fn sub_authority_count(&self) -> usize {
        usize::from(self.bytes[1])
    }

    /// One sub-authority by index.
    pub fn sub_authority(&self, i: usize) -> Option<u32> {
        if i >= self.sub_authority_count() {
            return None;
        }
        let at = 8 + i * 4;
        Some(u32::from_le_bytes([
            self.bytes[at],
            self.bytes[at + 1],
            self.bytes[at + 2],
            self.bytes[at + 3],
        ]))
    }

    /// Whether this is a per-service SID (`S-1-5-80-…`).
    pub fn is_service(&self) -> bool {
        self.authority() == 5 && self.sub_authority(0) == Some(80)
    }

    /// Derives a service's SID from its name, exactly as peinit and authd
    /// do when they mint the service's token: the SHA-1 of the uppercased
    /// name encoded as UTF-16LE, split into five little-endian 32-bit
    /// sub-authorities under `S-1-5-80`.
    pub fn service(name: &str) -> Sid {
        // Uppercase, then UTF-16LE, hashed incrementally: no allocation.
        // The digest is over the concatenation, so feeding the block
        // function piecewise would change nothing; buffering the whole
        // encoded name is simplest and bounded by MAX_SERVICE_NAME.
        let mut buf = [0u8; MAX_SERVICE_NAME * 4];
        let mut n = 0usize;
        for c in name.chars() {
            for up in c.to_uppercase() {
                let mut units = [0u16; 2];
                for unit in up.encode_utf16(&mut units) {
                    if n + 2 > buf.len() {
                        // Longer than any service name peinit accepts;
                        // hash what fits rather than fail — the result
                        // matches nothing, which is the honest outcome.
                        break;
                    }
                    buf[n..n + 2].copy_from_slice(&unit.to_le_bytes());
                    n += 2;
                }
            }
        }
        let digest = sha1(&buf[..n]);
        let mut subs = [80u32; 6];
        for (i, chunk) in digest.chunks_exact(4).enumerate() {
            subs[i + 1] = u32::from_le_bytes([chunk[0], chunk[1], chunk[2], chunk[3]]);
        }
        Sid::build(5, &subs)
    }

    /// Resolves a well-known principal name (case-insensitive) to its SID.
    /// The names an author is likely to write in a rule; the full catalogue
    /// lives in the reference docs, and anything else is written as a SID.
    pub fn well_known(name: &str) -> Option<Sid> {
        let eq = |s: &str| -> bool { name.eq_ignore_ascii_case(s) };
        let (authority, subs): (u64, &[u32]) = if eq("Everyone") {
            (1, &[0])
        } else if eq("CreatorOwner") {
            (3, &[0])
        } else if eq("Network") {
            (5, &[2])
        } else if eq("Interactive") {
            (5, &[4])
        } else if eq("Service") {
            (5, &[6])
        } else if eq("Anonymous") {
            (5, &[7])
        } else if eq("AuthenticatedUsers") {
            (5, &[11])
        } else if eq("SYSTEM") {
            (5, &[18])
        } else if eq("LocalService") {
            (5, &[19])
        } else if eq("NetworkService") {
            (5, &[20])
        } else if eq("Administrators") {
            (5, &[32, 544])
        } else if eq("Users") {
            (5, &[32, 545])
        } else if eq("Guests") {
            (5, &[32, 546])
        } else {
            return None;
        };
        Sid::new(authority, subs)
    }
}

/// Longest service name the derivation buffers (characters, before
/// uppercasing); peinit's own limit is far lower.
pub const MAX_SERVICE_NAME: usize = 256;

/// The null SID, `S-1-0-0`: what a principal with no identity reads as.
impl Default for Sid {
    fn default() -> Self {
        Sid::build(0, &[0])
    }
}

impl fmt::Display for Sid {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "S-1-{}", self.authority())?;
        for i in 0..self.sub_authority_count() {
            write!(f, "-{}", self.sub_authority(i).unwrap_or(0))?;
        }
        Ok(())
    }
}

impl fmt::Debug for Sid {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(self, f)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn text_and_binary_forms_round_trip() {
        let s = Sid::parse_str("S-1-5-21-1-2-3-1001").unwrap();
        assert_eq!(s.to_string(), "S-1-5-21-1-2-3-1001");
        assert_eq!(s.authority(), 5);
        assert_eq!(s.sub_authority_count(), 5);
        assert_eq!(s.sub_authority(4), Some(1001));
        assert_eq!(Sid::from_bytes(s.as_bytes()), Some(s));
        assert_eq!(s.as_bytes().len(), 8 + 5 * 4);
        // The binary layout is PCDS's: revision, count, big-endian
        // authority, little-endian sub-authorities.
        assert_eq!(&s.as_bytes()[..8], &[1, 5, 0, 0, 0, 0, 0, 5]);
        assert_eq!(&s.as_bytes()[8..12], &[21, 0, 0, 0]);
    }

    #[test]
    fn parser_refuses_malformed_text() {
        assert!(Sid::parse_str("").is_none());
        assert!(Sid::parse_str("S-2-5-18").is_none());
        assert!(Sid::parse_str("X-1-5-18").is_none());
        assert!(Sid::parse_str("S-1-5-").is_none());
        assert!(Sid::parse_str("S-1-5-18-x").is_none());
        assert!(Sid::parse_str("S-1").is_none());
        assert!(Sid::parse_str("S-1-281474976710656").is_none()); // 2^48
        let sixteen = "S-1-5-1-2-3-4-5-6-7-8-9-10-11-12-13-14-15-16";
        assert!(Sid::parse_str(sixteen).is_none());
        assert!(Sid::parse_str("s-1-5-18").is_some());
    }

    #[test]
    fn binary_reader_checks_the_frame() {
        assert!(Sid::from_bytes(&[1, 1, 0, 0, 0, 0, 0, 5]).is_none()); // short
        assert!(Sid::from_bytes(&[2, 0, 0, 0, 0, 0, 0, 5]).is_none()); // revision
        assert!(Sid::from_bytes(&[1, 0, 0, 0, 0, 0, 0, 5, 0]).is_none()); // long
        assert_eq!(
            Sid::from_bytes(&[1, 0, 0, 0, 0, 0, 0, 5])
                .unwrap()
                .to_string(),
            "S-1-5"
        );
    }

    #[test]
    fn service_sids_match_peinits_derivation() {
        assert_eq!(
            Sid::service("app").to_string(),
            "S-1-5-80-2426739453-2501902915-3009591593-922485235-2122754908"
        );
        assert_eq!(Sid::service("app"), Sid::service("APP"));
        assert!(Sid::service("resolvd").is_service());
        assert!(!Sid::well_known("SYSTEM").unwrap().is_service());
    }

    #[test]
    fn well_known_names_resolve_case_insensitively() {
        assert_eq!(Sid::well_known("system").unwrap().to_string(), "S-1-5-18");
        assert_eq!(
            Sid::well_known("localservice").unwrap().to_string(),
            "S-1-5-19"
        );
        assert_eq!(
            Sid::well_known("Administrators").unwrap().to_string(),
            "S-1-5-32-544"
        );
        assert_eq!(Sid::well_known("Everyone").unwrap().to_string(), "S-1-1-0");
        assert!(Sid::well_known("Adminstrators").is_none());
    }
}
