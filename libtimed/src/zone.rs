//! Time zone names: which ones timed will put in `/etc/localtime`.
//!
//! A name is a path under [`ZONEINFO_DIR`], so the check that matters is
//! that it cannot leave it — `../../etc/shadow` is a fine-looking value to
//! anyone who can write the registry and nothing else. Beyond that, the
//! file has to be a TZif file: the database also holds `zone.tab` and
//! friends, and a link to one of those would leave every program on the
//! machine silently on UTC.

use std::io::Read;
use std::path::PathBuf;

use crate::ZONEINFO_DIR;

/// The longest name in the database is 32 bytes
/// (`America/Argentina/ComodRivadavia`); this leaves room without inviting
/// anything that is plainly not a zone.
pub const MAX_NAME: usize = 64;

/// Is `name` shaped like a zone name? Letters, digits and `_ + -` in
/// components separated by `/`, none of them empty, `.` or `..`, and no
/// leading `/`.
pub fn check_name(name: &str) -> Result<(), String> {
    if name.is_empty() {
        return Err("no time zone named".into());
    }
    if name.len() > MAX_NAME {
        return Err(format!("{name:?} is longer than any time zone"));
    }
    for part in name.split('/') {
        if part.is_empty() || part == "." || part == ".." {
            return Err(format!("{name:?} is not a time zone name"));
        }
        if !part
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '+' | '-'))
        {
            return Err(format!("{name:?} is not a time zone name"));
        }
    }
    Ok(())
}

/// The file `name` names.
pub fn path(name: &str) -> PathBuf {
    PathBuf::from(ZONEINFO_DIR).join(name)
}

/// Is `name` a zone this machine has? A well-formed name whose file begins
/// with the TZif magic.
pub fn installed(name: &str) -> Result<(), String> {
    check_name(name)?;
    let mut magic = [0u8; 4];
    std::fs::File::open(path(name))
        .and_then(|mut f| f.read_exact(&mut magic))
        .map_err(|_| format!("there is no time zone {name:?} on this machine"))?;
    if &magic != b"TZif" {
        return Err(format!("{name:?} is not a time zone"));
    }
    Ok(())
}

/// One zone from `zone1970.tab`, the list the database keeps of the zones
/// worth choosing between: one per region whose clocks have agreed since
/// 1970, which is what a picker wants. (`zone.tab` has more, kept for
/// old names; every name in it still works as a value.)
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Listed {
    pub name: String,
    /// ISO 3166 country codes, comma-separated in the file.
    pub countries: Vec<String>,
    /// What tells this zone from others in the same country, when the file
    /// says (`"Mountain (most areas)"`).
    pub comment: Option<String>,
}

/// Read the list, sorted by name. Empty when tzdata is not installed.
pub fn list() -> Vec<Listed> {
    let text = std::fs::read_to_string(PathBuf::from(ZONEINFO_DIR).join("zone1970.tab"))
        .unwrap_or_default();
    let mut zones = parse_tab(&text);
    zones.sort_by(|a, b| a.name.cmp(&b.name));
    zones
}

/// Country names by ISO code, from `iso3166.tab`.
pub fn countries() -> Vec<(String, String)> {
    let text = std::fs::read_to_string(PathBuf::from(ZONEINFO_DIR).join("iso3166.tab"))
        .unwrap_or_default();
    text.lines()
        .filter(|l| !l.starts_with('#'))
        .filter_map(|l| {
            let (code, name) = l.split_once('\t')?;
            Some((code.to_string(), name.trim().to_string()))
        })
        .collect()
}

fn parse_tab(text: &str) -> Vec<Listed> {
    text.lines()
        .filter(|l| !l.starts_with('#') && !l.trim().is_empty())
        .filter_map(|l| {
            let mut fields = l.split('\t');
            let countries = fields.next()?;
            let _coordinates = fields.next()?;
            let name = fields.next()?;
            let comment = fields.next().map(str::trim).filter(|c| !c.is_empty());
            Some(Listed {
                name: name.to_string(),
                countries: countries.split(',').map(str::to_string).collect(),
                comment: comment.map(str::to_string),
            })
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn real_names_are_names() {
        for name in [
            "UTC",
            "Europe/London",
            "America/Argentina/ComodRivadavia",
            "Etc/GMT+5",
            "America/Port-au-Prince",
        ] {
            assert_eq!(check_name(name), Ok(()), "{name}");
        }
    }

    #[test]
    fn nothing_leaves_the_database() {
        for name in [
            "",
            "/etc/shadow",
            "../etc/shadow",
            "Europe/../../../etc/shadow",
            "Europe//London",
            "Europe/London/",
            "./UTC",
            "Europe/Lon don",
            "Europe\\London",
        ] {
            assert!(check_name(name).is_err(), "{name:?} was accepted");
        }
        assert!(check_name(&"A".repeat(MAX_NAME + 1)).is_err());
    }

    #[test]
    fn the_tab_file_is_read() {
        let text = "# tzdb timezone descriptions\n\
                    #codes\tcoordinates\tTZ\tcomments\n\
                    GB,GG,IM,JE\t+513030-0000731\tEurope/London\n\
                    US\t+394421-1045903\tAmerica/Denver\tMountain (most areas)\n";
        let zones = parse_tab(text);
        assert_eq!(zones.len(), 2);
        assert_eq!(zones[0].name, "Europe/London");
        assert_eq!(zones[0].countries, ["GB", "GG", "IM", "JE"]);
        assert_eq!(zones[0].comment, None);
        assert_eq!(zones[1].comment.as_deref(), Some("Mountain (most areas)"));
    }
}
