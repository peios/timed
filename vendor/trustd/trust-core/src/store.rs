//! Composing the effective root set.
//!
//! Three inputs: the bundle the `ca-certificates` package ships, the
//! additions an administrator (or the domain) wrote to
//! `Trust\Certificates\Add\`, and the distrusts under `Distrust\`. One
//! output: the set of roots this machine trusts, in a deterministic order.
//!
//! Two rules carry the weight:
//!
//! - **Distrust is absolute and applies last.** It removes a root whether it
//!   came from the shipped bundle or from an addition. The shipped bundle
//!   cannot be edited on a running machine — it is package payload — so this
//!   is the only mechanism that can retract trust in seconds, and it must
//!   never be conditional on anything else succeeding.
//! - **Composition is all or nothing.** A missing or unreadable bundle, or
//!   one that yields implausibly few roots, fails the whole composition; the
//!   caller then keeps whatever was rendered last. A partial store is worse
//!   than a stale one: a silently-empty set breaks every TLS client on the
//!   machine, and a silently-truncated one might drop the distrust that was
//!   the entire point of the last change.
//!
//! Individual bad *entries* are different: an addition that is not a
//! certificate, not a CA, or expired is skipped with a warning, because one
//! administrator's typo should not take the machine's trust store down.

use crate::Source;

use crate::cert::{self, Parsed};

/// The floor below which a bundle is presumed broken rather than small.
/// Mozilla's set has been well over a hundred roots for a decade; a parser
/// regression or a truncated download lands far below this.
pub const MINIMUM_SHIPPED: usize = 50;

/// One `Trust\Certificates\Add\<name>` entry, as read from the registry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Addition {
    pub name: String,
    pub der: Vec<u8>,
    pub purposes: Vec<String>,
}

/// A root in the effective set.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Entry {
    pub parsed: Parsed,
    pub source: Source,
    /// The registry value name, for an addition.
    pub name: Option<String>,
    pub purposes: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Composed {
    /// Sorted by fingerprint, so the rendering is byte-stable across runs
    /// and an unchanged store never rewrites a file.
    pub roots: Vec<Entry>,
    pub shipped: u64,
    pub added: u64,
    pub distrusted: u64,
    pub skipped: u64,
    /// One line per skipped or ignored entry, for the log.
    pub warnings: Vec<String>,
}

/// The default purpose. v1 renders these and nothing else; the field exists
/// so that a name-constrained or code-signing root is a value change rather
/// than a schema change.
pub const SERVER_AUTH: &str = "ServerAuth";

/// Compose the store. `now` is seconds since the epoch, or `None` to skip
/// expiry checks.
pub fn compose(
    shipped_pem: &str,
    additions: &[Addition],
    distrust: &[String],
    now: Option<i64>,
) -> Result<Composed, String> {
    let mut out = Composed::default();
    let shipped = cert::from_pem(shipped_pem);
    if shipped.len() < MINIMUM_SHIPPED {
        return Err(format!(
            "the shipped bundle holds {} certificate(s), below the floor of {MINIMUM_SHIPPED} — treating it as broken rather than as a very small trust store",
            shipped.len()
        ));
    }

    // Distrust is matched on the fingerprint, case-insensitively, with any
    // colons or spaces a person may have pasted removed.
    let distrust: Vec<String> = distrust.iter().map(|f| normalise_fingerprint(f)).collect();

    let mut seen: Vec<String> = Vec::new();
    for der in &shipped {
        // The shipped bundle is vetted at build time; an expired root in it
        // is a packaging problem, and dropping it here silently would hide
        // that. It is kept and reported.
        match cert::parse(der, None) {
            Ok(parsed) => {
                out.shipped += 1;
                push(
                    &mut out,
                    &mut seen,
                    &distrust,
                    Entry {
                        parsed,
                        source: Source::Shipped,
                        name: None,
                        purposes: vec![SERVER_AUTH.to_owned()],
                    },
                );
            }
            Err(e) => {
                out.skipped += 1;
                out.warnings
                    .push(format!("the shipped bundle holds an entry that is {e}"));
            }
        }
    }

    for addition in additions {
        match cert::parse(&addition.der, now) {
            Ok(parsed) => {
                out.added += 1;
                let purposes = if addition.purposes.is_empty() {
                    vec![SERVER_AUTH.to_owned()]
                } else {
                    addition.purposes.clone()
                };
                push(
                    &mut out,
                    &mut seen,
                    &distrust,
                    Entry {
                        parsed,
                        source: Source::Added,
                        name: Some(addition.name.clone()),
                        purposes,
                    },
                );
            }
            Err(e) => {
                out.skipped += 1;
                out.warnings
                    .push(format!("Add\\{} is {e}; ignored", addition.name));
            }
        }
    }

    out.distrusted = distrust.len() as u64;
    for fingerprint in &distrust {
        if !seen.iter().any(|f| f == fingerprint) {
            out.warnings.push(format!(
                "Distrust\\{fingerprint} matches no certificate in the store; it stays in force in case one arrives"
            ));
        }
    }

    out.roots
        .sort_by(|a, b| a.parsed.fingerprint.cmp(&b.parsed.fingerprint));
    if out.roots.is_empty() {
        return Err(
            "every root was distrusted or unusable; refusing to render an empty store".to_owned(),
        );
    }
    Ok(out)
}

/// Add a root unless it is distrusted or already present.
fn push(out: &mut Composed, seen: &mut Vec<String>, distrust: &[String], entry: Entry) {
    let fingerprint = entry.parsed.fingerprint.clone();
    seen.push(fingerprint.clone());
    if distrust.contains(&fingerprint) {
        out.warnings.push(format!(
            "{} is distrusted ({fingerprint})",
            entry.parsed.subject
        ));
        return;
    }
    if out
        .roots
        .iter()
        .any(|r| r.parsed.fingerprint == fingerprint)
    {
        if entry.source == Source::Added {
            out.warnings.push(format!(
                "Add\\{} duplicates a certificate already in the store; the store holds one copy",
                entry.name.unwrap_or_default()
            ));
        }
        return;
    }
    out.roots.push(entry);
}

/// Fingerprints are compared as lowercase hex with separators removed, so a
/// value pasted from any tool matches.
pub fn normalise_fingerprint(text: &str) -> String {
    text.chars()
        .filter(|c| c.is_ascii_alphanumeric())
        .flat_map(|c| c.to_lowercase())
        .collect()
}

/// The roots that carry a purpose. v1 renders `ServerAuth`.
pub fn for_purpose<'a>(roots: &'a [Entry], purpose: &str) -> Vec<&'a Entry> {
    roots
        .iter()
        .filter(|r| r.purposes.iter().any(|p| p.eq_ignore_ascii_case(purpose)))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    const COMODO: &str = include_str!("../tests/fixtures/comodo-ecc.pem");
    const NETLOCK: &str = include_str!("../tests/fixtures/netlock-arany.pem");
    const MICROSEC: &str = include_str!("../tests/fixtures/microsec-2009.pem");

    /// A bundle above the floor: the fixtures, then filler copies so the
    /// count is plausible. Composition dedupes, so the filler is the same
    /// three certificates repeated — enough to clear `MINIMUM_SHIPPED`
    /// without inventing certificates.
    fn bundle(parts: &[&str]) -> String {
        let mut text = String::from("# a shipped bundle\n");
        for _ in 0..MINIMUM_SHIPPED {
            for part in parts {
                text.push_str(part);
            }
        }
        text
    }

    fn der_of(pem: &str) -> Vec<u8> {
        cert::from_pem(pem).remove(0)
    }

    fn fingerprint_of(pem: &str) -> String {
        cert::fingerprint(&der_of(pem))
    }

    #[test]
    fn the_shipped_bundle_becomes_the_store() {
        let composed = compose(&bundle(&[COMODO, NETLOCK, MICROSEC]), &[], &[], None).unwrap();
        assert_eq!(composed.roots.len(), 3, "duplicates collapse");
        assert!(composed.roots.iter().all(|r| r.source == Source::Shipped));
        assert!(
            composed
                .roots
                .iter()
                .all(|r| r.purposes == vec![SERVER_AUTH])
        );
        // Deterministic order, so an unchanged store renders identical bytes.
        let again = compose(&bundle(&[MICROSEC, COMODO, NETLOCK]), &[], &[], None).unwrap();
        assert_eq!(
            composed
                .roots
                .iter()
                .map(|r| &r.parsed.fingerprint)
                .collect::<Vec<_>>(),
            again
                .roots
                .iter()
                .map(|r| &r.parsed.fingerprint)
                .collect::<Vec<_>>()
        );
    }

    #[test]
    fn an_addition_joins_the_store_and_keeps_its_purposes() {
        let shipped = bundle(&[COMODO, NETLOCK]);
        let addition = Addition {
            name: "corp-ca".into(),
            der: der_of(MICROSEC),
            purposes: vec!["ServerAuth".into(), "CodeSigning".into()],
        };
        let composed = compose(&shipped, &[addition], &[], None).unwrap();
        assert_eq!(composed.roots.len(), 3);
        assert_eq!(composed.added, 1);
        let added = composed
            .roots
            .iter()
            .find(|r| r.source == Source::Added)
            .unwrap();
        assert_eq!(added.name.as_deref(), Some("corp-ca"));
        assert_eq!(added.purposes.len(), 2);
        assert_eq!(for_purpose(&composed.roots, "codesigning").len(), 1);
        assert_eq!(for_purpose(&composed.roots, "ServerAuth").len(), 3);
    }

    #[test]
    fn distrust_removes_a_shipped_root_and_an_added_one_alike() {
        let shipped = bundle(&[COMODO, NETLOCK, MICROSEC]);
        // A shipped root, named in any of the formats a person might paste.
        for form in [
            fingerprint_of(NETLOCK),
            fingerprint_of(NETLOCK).to_uppercase(),
            fingerprint_of(NETLOCK)
                .as_bytes()
                .chunks(2)
                .map(|c| std::str::from_utf8(c).unwrap())
                .collect::<Vec<_>>()
                .join(":"),
        ] {
            let composed = compose(&shipped, &[], std::slice::from_ref(&form), None).unwrap();
            assert_eq!(composed.roots.len(), 2, "form {form}");
            assert!(
                !composed
                    .roots
                    .iter()
                    .any(|r| r.parsed.fingerprint == fingerprint_of(NETLOCK))
            );
            assert_eq!(composed.distrusted, 1);
        }
        // An addition can be distrusted too — the mechanism does not care
        // where a certificate came from.
        let addition = Addition {
            name: "corp-ca".into(),
            der: der_of(MICROSEC),
            purposes: vec![],
        };
        let composed = compose(
            &bundle(&[COMODO, NETLOCK]),
            &[addition],
            &[fingerprint_of(MICROSEC)],
            None,
        )
        .unwrap();
        assert_eq!(composed.roots.len(), 2);
    }

    #[test]
    fn a_bad_addition_is_skipped_and_the_store_survives() {
        let shipped = bundle(&[COMODO, NETLOCK, MICROSEC]);
        let additions = vec![
            Addition {
                name: "rubbish".into(),
                der: vec![1, 2, 3],
                purposes: vec![],
            },
            Addition {
                name: "empty".into(),
                der: vec![],
                purposes: vec![],
            },
        ];
        let composed = compose(&shipped, &additions, &[], None).unwrap();
        assert_eq!(composed.roots.len(), 3, "the good roots are unaffected");
        assert_eq!(composed.skipped, 2);
        assert_eq!(composed.warnings.len(), 2);
        assert!(composed.warnings.iter().all(|w| w.contains("ignored")));
    }

    #[test]
    fn an_expired_addition_is_refused_but_an_expired_shipped_root_is_reported() {
        let parsed = cert::parse(&der_of(COMODO), None).unwrap();
        let after = parsed.not_after + 1;
        let addition = Addition {
            name: "old".into(),
            der: der_of(COMODO),
            purposes: vec![],
        };
        let composed =
            compose(&bundle(&[NETLOCK, MICROSEC]), &[addition], &[], Some(after)).unwrap();
        assert_eq!(composed.skipped, 1);
        assert!(composed.warnings[0].contains("expired"));
        // The shipped bundle is not expiry-checked here: that is the
        // package's problem to surface, not a reason to shrink the store.
        let composed =
            compose(&bundle(&[COMODO, NETLOCK, MICROSEC]), &[], &[], Some(after)).unwrap();
        assert_eq!(composed.roots.len(), 3);
    }

    #[test]
    fn composition_fails_rather_than_render_something_wrong() {
        // Below the floor: a truncated download or a parser regression.
        let err = compose("# nothing here\n", &[], &[], None).unwrap_err();
        assert!(err.contains("below the floor"), "{err}");
        let err = compose(&format!("{COMODO}{NETLOCK}"), &[], &[], None).unwrap_err();
        assert!(err.contains("below the floor"), "{err}");
        // Everything distrusted: refuse rather than empty the machine's trust.
        let all: Vec<String> = [COMODO, NETLOCK, MICROSEC]
            .iter()
            .map(|p| fingerprint_of(p))
            .collect();
        let err = compose(&bundle(&[COMODO, NETLOCK, MICROSEC]), &[], &all, None).unwrap_err();
        assert!(err.contains("empty store"), "{err}");
    }

    #[test]
    fn a_distrust_for_an_absent_certificate_stays_in_force() {
        let composed = compose(&bundle(&[COMODO]), &[], &[format!("{:064x}", 1)], None).unwrap();
        assert_eq!(composed.distrusted, 1);
        assert!(
            composed
                .warnings
                .iter()
                .any(|w| w.contains("matches no certificate"))
        );
        assert_eq!(composed.roots.len(), 1);
    }
}
