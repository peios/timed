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
//! No zone chosen is UTC, and so is a zone that cannot be honoured: a name
//! tzdata does not have leaves the machine on the zone it was on before,
//! and says so, rather than on something nobody chose.

use std::io::Write;

use libtimed::{LOCALTIME, zone};

/// What to name when nothing is chosen.
pub const DEFAULT: &str = "UTC";

/// Put `wanted`, or UTC, in [`LOCALTIME`]. Returns the zone now in force,
/// `None` meaning UTC.
pub fn render(wanted: Option<&str>) -> Result<Option<String>, String> {
    let name = wanted.unwrap_or(DEFAULT);
    zone::installed(name)?;
    let bytes = std::fs::read(zone::path(name))
        .map_err(|e| format!("cannot read the time zone {name:?}: {e}"))?;
    if std::fs::read(LOCALTIME).is_ok_and(|current| current == bytes) {
        return Ok(wanted.map(str::to_string));
    }
    // Opened without O_CREAT: the hook makes the file, and timed may not
    // add one to /system/retc. One write after the truncate, so a program
    // reading at the same moment finds the old zone, an empty file (which
    // it takes as UTC), or the new zone, and never half of one.
    std::fs::OpenOptions::new()
        .write(true)
        .truncate(true)
        .open(LOCALTIME)
        .and_then(|mut file| file.write_all(&bytes))
        .map_err(|e| format!("cannot write {LOCALTIME}: {e} (timed's pre-start hook makes it)"))?;
    Ok(wanted.map(str::to_string))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_name_that_would_leave_the_database_is_refused_before_anything_is_read() {
        // render() must refuse on the name alone: only a file
        // `zone::installed` has looked at is ever copied.
        assert!(render(Some("../../etc/shadow")).is_err());
        assert!(render(Some("/etc/shadow")).is_err());
    }
}
