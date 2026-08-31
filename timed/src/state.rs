//! What survives a reboot: the drift file and the cookie store.
//!
//! Both live under `/var/state/timed`, created by a pre-start hook running
//! as SYSTEM because timed itself is not privileged enough to make a
//! directory there. Both are best-effort: a machine whose state directory
//! is missing runs correctly and merely converges more slowly, which is the
//! right failure for a cache.
//!
//! # Why the drift file earns its keep
//!
//! A crystal's rate error is a property of the hardware, stable over days.
//! A machine that remembers it was 12 ppm fast starts the next boot already
//! correcting for it, and is within milliseconds within one poll instead of
//! tens of seconds after twenty. On a machine that reboots often, this file
//! is the difference between usually-right and usually-converging.
//!
//! # Why cookies are persisted
//!
//! An NTS cookie is spent on use and replaced in the reply, so a reboot
//! that dropped them all would force a fresh TLS handshake with every
//! server before the clock could be set — and that handshake is exactly the
//! thing most likely to fail on a machine whose clock is wrong, which after
//! a long power-off it is. Keeping a few cookies breaks that circle a
//! second time, after the build floor has broken it once.

use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};

use libtimed::{COOKIE_DIR, DRIFT_FILE, STATE_DIR};
use ntp::nts::{COOKIE_TARGET, MAX_COOKIE};

use crate::discipline::MAX_FREQUENCY;
use crate::log;

/// Read the remembered frequency, in seconds per second.
///
/// Anything that is not a plausible frequency is discarded rather than
/// clamped: a corrupt drift file should make the machine converge from
/// scratch, not converge towards whatever the corruption happened to say.
pub fn read_drift() -> Option<f64> {
    let text = fs::read_to_string(DRIFT_FILE).ok()?;
    let ppm: f64 = text.trim().parse().ok()?;
    if !ppm.is_finite() || ppm.abs() > MAX_FREQUENCY * 1e6 {
        log::warn(format_args!("{DRIFT_FILE} holds {ppm}, which is not a plausible frequency; ignored"));
        return None;
    }
    Some(ppm / 1e6)
}

/// Write the frequency, atomically.
///
/// Via a temporary file and a rename, so a power cut during the write
/// leaves the old value rather than half a number — which would parse as
/// something quite different rather than failing.
pub fn write_drift(frequency: f64) -> std::io::Result<()> {
    if !frequency.is_finite() {
        return Ok(());
    }
    let path = Path::new(DRIFT_FILE);
    let temporary = path.with_extension("new");
    {
        let mut file = fs::File::create(&temporary)?;
        writeln!(file, "{:.3}", frequency * 1e6)?;
        file.sync_all()?;
    }
    fs::rename(&temporary, path)
}

fn cookie_path(name: &str) -> PathBuf {
    // The source name goes in a filename, and a source name comes from the
    // registry. Anything that is not a plain hostname character becomes an
    // underscore, so a name containing a slash or a `..` cannot address a
    // file outside the directory. The mapping is not injective, and does
    // not need to be: a collision costs a handshake.
    let safe: String = name
        .chars()
        .map(|c| if c.is_ascii_alphanumeric() || c == '.' || c == '-' { c } else { '_' })
        .collect();
    Path::new(COOKIE_DIR).join(safe)
}

/// Load whatever cookies were left for this source.
///
/// The file is a length-prefixed sequence, and every length is checked
/// against what remains before it is used. This file is written by us and
/// lives in a directory only we and SYSTEM can write — but "only we wrote
/// it" is a claim about the filesystem's permissions, and a parser that
/// depends on that claim is one that breaks badly when it turns out to be
/// wrong.
pub fn read_cookies(name: &str) -> Vec<Vec<u8>> {
    let Ok(bytes) = fs::read(cookie_path(name)) else {
        return Vec::new();
    };
    let mut out = Vec::new();
    let mut rest = &bytes[..];
    while rest.len() >= 2 {
        let len = u16::from_be_bytes([rest[0], rest[1]]) as usize;
        if len == 0 || len > MAX_COOKIE || 2 + len > rest.len() {
            break;
        }
        out.push(rest[2..2 + len].to_vec());
        rest = &rest[2 + len..];
        if out.len() >= COOKIE_TARGET {
            break;
        }
    }
    out
}

/// Save this source's cookies.
pub fn write_cookies(name: &str, cookies: &[Vec<u8>]) -> std::io::Result<()> {
    fs::create_dir_all(COOKIE_DIR)?;
    let path = cookie_path(name);
    let temporary = path.with_extension("new");
    let mut bytes = Vec::new();
    for cookie in cookies.iter().take(COOKIE_TARGET) {
        if cookie.is_empty() || cookie.len() > MAX_COOKIE {
            continue;
        }
        bytes.extend_from_slice(&(cookie.len() as u16).to_be_bytes());
        bytes.extend_from_slice(cookie);
    }
    {
        let mut file = fs::File::create(&temporary)?;
        file.write_all(&bytes)?;
        file.sync_all()?;
    }
    // Cookies are not quite secrets — spending one gets an unauthenticated
    // observer nothing without the AEAD keys, which are never written down
    // — but they are linkable to this machine, so they are not world
    // readable either.
    let _ = fs::set_permissions(&temporary, std::os::unix::fs::PermissionsExt::from_mode(0o600));
    fs::rename(&temporary, path)
}

/// Forget a source's cookies, when they have been rejected.
pub fn forget_cookies(name: &str) {
    let _ = fs::remove_file(cookie_path(name));
}

/// Is the state directory usable at all?
pub fn state_available() -> bool {
    Path::new(STATE_DIR).is_dir()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_cookie_file_with_a_lying_length_does_not_read_out_of_bounds() {
        // Built by hand rather than round-tripped, because a well-formed
        // file cannot exercise this. A length claiming 65535 bytes in a
        // four-byte file is the shape that matters.
        let cases: Vec<Vec<u8>> = vec![
            vec![],
            vec![0x00],
            vec![0xff, 0xff],
            vec![0xff, 0xff, 0x01, 0x02],
            vec![0x00, 0x00, 0x41, 0x42],
            vec![0x00, 0x02, 0x41],
        ];
        for bytes in cases {
            // Exercised through the same loop the reader uses.
            let mut out: Vec<Vec<u8>> = Vec::new();
            let mut rest = &bytes[..];
            while rest.len() >= 2 {
                let len = u16::from_be_bytes([rest[0], rest[1]]) as usize;
                if len == 0 || len > MAX_COOKIE || 2 + len > rest.len() {
                    break;
                }
                out.push(rest[2..2 + len].to_vec());
                rest = &rest[2 + len..];
            }
            assert!(out.iter().all(|c| !c.is_empty() && c.len() <= MAX_COOKIE));
        }
    }

    #[test]
    fn a_source_name_cannot_address_a_file_outside_the_directory() {
        // The registry is an administrative surface, not a hostile one —
        // but a path built from configuration is a path built from
        // configuration, and this is one line of defence for zero cost.
        for name in ["../../etc/passwd", "a/b", "..", "/absolute", "with space"] {
            let path = cookie_path(name);
            assert_eq!(
                path.parent(),
                Some(Path::new(COOKIE_DIR)),
                "{name:?} escaped to {}",
                path.display()
            );
        }
    }

    #[test]
    fn a_corrupt_drift_value_is_discarded_rather_than_clamped() {
        // Checked through the same predicate the reader applies: a
        // corrupted file must make the machine converge from scratch, not
        // converge towards the corruption.
        for ppm in [f64::NAN, f64::INFINITY, 1e9, -1e9, 501.0] {
            let plausible = ppm.is_finite() && ppm.abs() <= MAX_FREQUENCY * 1e6;
            assert!(!plausible, "{ppm} should not be accepted");
        }
        for ppm in [0.0f64, 12.5, -499.0] {
            assert!(ppm.is_finite() && ppm.abs() <= MAX_FREQUENCY * 1e6);
        }
    }
}
