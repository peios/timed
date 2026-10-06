//! `/etc/localtime`: the machine's time zone, from `TimeZone`.
//!
//! `/etc` is a merged view whose top layer, `/system/retc`, holds what is
//! rendered from the registry, and `/system/retc` is SYSTEM's. So timed's
//! pre-start hook, which runs as SYSTEM, makes [`LOCALTIME`] and lets timed
//! write it, and timed copies the chosen zone's file into it.
//!
//! A copy rather than a link to the zone's file: making a link needs
//! `SeCreateSymbolicLinkPrivilege`, which nothing should be given for this.
//! A copy does not follow tzdata when tzdata is upgraded, so it is made
//! again every time timed starts, which is every boot.
//!
//! No zone chosen is UTC. A name tzdata does not have is refused, and the
//! machine stays on the zone it was on, rather than on something nobody
//! chose. A refused name is tried again whenever the registry changes and
//! every [`RETRY`] seconds, so a zone that tzdata gains later is taken up.
//!
//! The copy carries no name, so timed keeps the name beside its other
//! state, in [`ZONE_FILE`], and at start believes it only if the copy is
//! still byte for byte that zone's file: [`in_force`].

use std::fs;
use std::io::Write;
use std::path::Path;

use libtimed::{LOCALTIME, ZONE_FILE, ZONEINFO_DIR, zone};

use crate::log;

/// What to name when nothing is chosen.
pub const DEFAULT: &str = "UTC";

/// Seconds before a refused name is tried again, when no registry change
/// prompts it sooner. A try is one small read, and tzdata is not upgraded
/// often; this only bounds how long a newly installed zone waits.
pub const RETRY: f64 = 600.0;

/// Put `wanted`, or UTC, in [`LOCALTIME`]. Returns the zone now in force,
/// `None` meaning UTC.
pub fn render(wanted: Option<&str>) -> Result<Option<String>, String> {
    let name = wanted.unwrap_or(DEFAULT);
    zone::installed(name)?;
    let bytes = fs::read(zone::path(name))
        .map_err(|e| format!("cannot read the time zone {name:?}: {e}"))?;
    install(&bytes, Path::new(LOCALTIME))?;
    // After the copy, so the name is never one the copy has not reached;
    // and on every success, so a missing or stale name is put right.
    if let Err(e) = remember(wanted, Path::new(ZONE_FILE)) {
        log::warn(format_args!(
            "could not write {ZONE_FILE}: {e}; after a restart, status may not name the zone"
        ));
    }
    Ok(wanted.map(str::to_string))
}

/// Make `localtime` hold `bytes`, unless it already does.
fn install(bytes: &[u8], localtime: &Path) -> Result<(), String> {
    if fs::read(localtime).is_ok_and(|current| current == bytes) {
        return Ok(());
    }
    // Opened without O_CREAT: the hook makes the file, and timed may not
    // add one to /system/retc. One write after the truncate, so a program
    // reading at the same moment finds the old zone, an empty file (which
    // it takes as UTC), or the new zone, and never half of one.
    fs::OpenOptions::new()
        .write(true)
        .truncate(true)
        .open(localtime)
        .and_then(|mut file| file.write_all(bytes))
        .map_err(|e| {
            format!(
                "cannot write {}: {e} (timed's pre-start hook makes it)",
                localtime.display()
            )
        })
}

/// Write the name of the zone in force to `record`, empty for none chosen.
/// Via a temporary file and a rename, as the drift file is.
fn remember(wanted: Option<&str>, record: &Path) -> std::io::Result<()> {
    let text = wanted.unwrap_or("");
    if fs::read_to_string(record).is_ok_and(|current| current == text) {
        return Ok(());
    }
    let temporary = record.with_extension("new");
    {
        let mut file = fs::File::create(&temporary)?;
        file.write_all(text.as_bytes())?;
        file.sync_all()?;
    }
    fs::rename(&temporary, record)
}

/// The zone [`LOCALTIME`] holds now, `None` meaning UTC or not known.
pub fn in_force() -> Option<String> {
    identify(
        Path::new(LOCALTIME),
        Path::new(ZONE_FILE),
        Path::new(ZONEINFO_DIR),
    )
}

/// The name in `record`, if `localtime` is still a copy of that zone's file
/// under `zoneinfo`.
///
/// Neither is enough alone. Many zones' files are byte for byte the same,
/// so the copy cannot name itself; and the name can be wrong — timed
/// stopped between the copy and the name, the hook made the file afresh
/// (empty, which is UTC), or someone else wrote it. Anything that does not
/// agree is not known, and not known is shown as UTC.
fn identify(localtime: &Path, record: &Path, zoneinfo: &Path) -> Option<String> {
    let name = fs::read_to_string(record).ok()?;
    // Only timed writes the record, but it is still a path's worth of text,
    // and nothing outside the database is read on its say-so.
    zone::check_name(&name).ok()?;
    let held = fs::read(localtime).ok()?;
    let file = fs::read(zoneinfo.join(&name)).ok()?;
    (!held.is_empty() && held == file).then_some(name)
}

/// What came of [`Keeper::apply`], for the log.
#[derive(Debug, PartialEq, Eq)]
pub enum Outcome {
    /// Nothing to do: the value was put in place last time.
    Unchanged,
    /// The zone is in place.
    Applied,
    /// Refused, for a reason not logged before.
    Refused(String),
    /// Refused again, as last time; already logged.
    RefusedAgain,
}

/// The zone in force, and a value that could not be put in place.
pub struct Keeper {
    /// The zone [`LOCALTIME`] holds. `None` is UTC, or not known.
    pub in_force: Option<String>,
    /// The `TimeZone` value last put in place, so a registry write that
    /// changed something else does not copy the zone again. `None` after a
    /// refusal, so whatever is asked next is tried.
    applied: Option<Option<String>>,
    /// The value last refused and why, so each refusal is logged once.
    refused: Option<(Option<String>, String)>,
    /// When a refused value is next tried, on timed's monotonic clock.
    retry_at: f64,
}

impl Keeper {
    pub fn new(in_force: Option<String>) -> Keeper {
        Keeper {
            in_force,
            applied: None,
            refused: None,
            retry_at: 0.0,
        }
    }

    /// Is a refused value due to be tried again?
    pub fn due(&self, now: f64) -> bool {
        self.refused.is_some() && now >= self.retry_at
    }

    /// Put `wanted` in place with `render`, unless it already is.
    pub fn apply(
        &mut self,
        wanted: &Option<String>,
        now: f64,
        render: impl FnOnce(Option<&str>) -> Result<Option<String>, String>,
    ) -> Outcome {
        if self.applied.as_ref() == Some(wanted) {
            return Outcome::Unchanged;
        }
        match render(wanted.as_deref()) {
            Ok(zone) => {
                self.in_force = zone;
                self.applied = Some(wanted.clone());
                self.refused = None;
                Outcome::Applied
            }
            Err(why) => {
                self.applied = None;
                self.retry_at = now + RETRY;
                let refusal = (wanted.clone(), why);
                if self.refused.as_ref() == Some(&refusal) {
                    return Outcome::RefusedAgain;
                }
                let why = refusal.1.clone();
                self.refused = Some(refusal);
                Outcome::Refused(why)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use super::*;

    #[test]
    fn a_name_that_would_leave_the_database_is_refused_before_anything_is_read() {
        // render() must refuse on the name alone: only a file
        // `zone::installed` has looked at is ever copied.
        assert!(render(Some("../../etc/shadow")).is_err());
        assert!(render(Some("/etc/shadow")).is_err());
    }

    /// A fresh directory with a little tz database in it: two zones whose
    /// files are the same, as `Europe/London` and `GB` are, and one that
    /// differs.
    fn scratch(test: &str) -> PathBuf {
        let dir =
            std::env::temp_dir().join(format!("timed-localtime-{}-{test}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(dir.join("zoneinfo/Europe")).unwrap();
        fs::write(dir.join("zoneinfo/Europe/London"), b"TZif london").unwrap();
        fs::write(dir.join("zoneinfo/GB"), b"TZif london").unwrap();
        fs::write(dir.join("zoneinfo/UTC"), b"TZif utc").unwrap();
        fs::write(dir.join("localtime"), b"").unwrap();
        dir
    }

    fn known(dir: &Path) -> Option<String> {
        identify(
            &dir.join("localtime"),
            &dir.join("zone"),
            &dir.join("zoneinfo"),
        )
    }

    #[test]
    fn the_zone_in_force_is_known_again_after_a_restart() {
        let dir = scratch("restart");
        install(b"TZif london", &dir.join("localtime")).unwrap();
        remember(Some("Europe/London"), &dir.join("zone")).unwrap();
        assert_eq!(known(&dir).as_deref(), Some("Europe/London"));

        // GB is the same file; the record is what tells them apart.
        remember(Some("GB"), &dir.join("zone")).unwrap();
        assert_eq!(known(&dir).as_deref(), Some("GB"));

        // None chosen is recorded as such.
        install(b"TZif utc", &dir.join("localtime")).unwrap();
        remember(None, &dir.join("zone")).unwrap();
        assert_eq!(known(&dir), None);
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_name_the_copy_does_not_match_is_not_believed() {
        let dir = scratch("mismatch");
        // No record: what timed before this one left.
        install(b"TZif london", &dir.join("localtime")).unwrap();
        assert_eq!(known(&dir), None);

        // A record naming a zone the copy is not.
        remember(Some("UTC"), &dir.join("zone")).unwrap();
        assert_eq!(known(&dir), None);

        // The hook made the file afresh: empty, which is UTC.
        remember(Some("Europe/London"), &dir.join("zone")).unwrap();
        fs::write(dir.join("localtime"), b"").unwrap();
        assert_eq!(known(&dir), None);

        // A record that would leave the database is not followed.
        fs::write(dir.join("localtime"), b"TZif london").unwrap();
        fs::write(dir.join("zone"), "../localtime").unwrap();
        assert_eq!(known(&dir), None);
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn the_copy_is_written_into_the_file_the_hook_made_and_not_made() {
        let dir = scratch("install");
        install(b"TZif london", &dir.join("localtime")).unwrap();
        assert_eq!(fs::read(dir.join("localtime")).unwrap(), b"TZif london");
        install(b"TZif utc", &dir.join("localtime")).unwrap();
        assert_eq!(fs::read(dir.join("localtime")).unwrap(), b"TZif utc");
        assert!(install(b"TZif utc", &dir.join("absent")).is_err());
        assert!(!dir.join("absent").exists());
        let _ = fs::remove_dir_all(&dir);
    }

    fn name(s: &str) -> Option<String> {
        Some(s.to_string())
    }

    #[test]
    fn a_refused_name_is_tried_again_and_logged_once() {
        let mut keeper = Keeper::new(name("Europe/London"));
        let missing = |_: Option<&str>| Err::<Option<String>, _>("no Asia/Atlantis".to_string());

        assert_eq!(
            keeper.apply(&name("Asia/Atlantis"), 0.0, missing),
            Outcome::Refused("no Asia/Atlantis".into())
        );
        assert_eq!(keeper.in_force.as_deref(), Some("Europe/London"));
        // Not before it is due, then once it is.
        assert!(!keeper.due(RETRY - 1.0));
        assert!(keeper.due(RETRY));
        // The same value asked again (a registry change) is tried again,
        // but not logged again.
        assert_eq!(
            keeper.apply(&name("Asia/Atlantis"), RETRY, missing),
            Outcome::RefusedAgain
        );
        assert!(!keeper.due(RETRY + 1.0));

        // tzdata gains it.
        let found = |w: Option<&str>| Ok(w.map(str::to_string));
        assert_eq!(
            keeper.apply(&name("Asia/Atlantis"), 2.0 * RETRY, found),
            Outcome::Applied
        );
        assert_eq!(keeper.in_force.as_deref(), Some("Asia/Atlantis"));
        assert!(!keeper.due(f64::MAX));
        // In place now, so it is not copied again.
        let never = |_: Option<&str>| -> Result<Option<String>, String> { panic!("copied again") };
        assert_eq!(
            keeper.apply(&name("Asia/Atlantis"), 3.0 * RETRY, never),
            Outcome::Unchanged
        );
    }

    #[test]
    fn a_different_refusal_is_logged() {
        let mut keeper = Keeper::new(None);
        let refuse =
            |why: &'static str| move |_: Option<&str>| Err::<Option<String>, _>(why.to_string());
        assert_eq!(
            keeper.apply(&name("A/B"), 0.0, refuse("no A/B")),
            Outcome::Refused("no A/B".into())
        );
        assert_eq!(
            keeper.apply(&name("A/B"), 1.0, refuse("A/B is not a time zone")),
            Outcome::Refused("A/B is not a time zone".into())
        );
        assert_eq!(
            keeper.apply(&name("C/D"), 2.0, refuse("A/B is not a time zone")),
            Outcome::Refused("A/B is not a time zone".into())
        );
    }

    #[test]
    fn going_back_to_the_zone_in_force_after_a_refusal_puts_it_in_place() {
        let mut keeper = Keeper::new(None);
        let ok = |w: Option<&str>| Ok(w.map(str::to_string));
        assert_eq!(
            keeper.apply(&name("Europe/London"), 0.0, ok),
            Outcome::Applied
        );
        let refused = keeper.apply(&name("Asia/Atlantis"), 1.0, |_| Err("no".to_string()));
        assert_eq!(refused, Outcome::Refused("no".into()));
        // Copied again, which costs nothing when it is already there, and
        // the refusal is over: nothing is retried.
        assert_eq!(
            keeper.apply(&name("Europe/London"), 2.0, ok),
            Outcome::Applied
        );
        assert!(!keeper.due(f64::MAX));
        // A refusal logged before is logged again once something else has
        // been put in place in between.
        assert_eq!(
            keeper.apply(&name("Asia/Atlantis"), 3.0, |_| Err("no".to_string())),
            Outcome::Refused("no".into())
        );
    }
}
