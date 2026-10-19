//! The machine's name: `Machine\System\Network Hostname`.
//!
//! netd validates the selected registry or DHCP name before `sethostname`,
//! and validates the registry name before announcing it in DHCP option 12.
//! Programs writing the value use the same rule: a single DNS label
//! (RFC 1123), letters, digits and hyphens, at most 63 of them, not
//! beginning or ending with a hyphen. All digits is a name too.
//!
//! The reasons are in words, for a person typing the name.

/// The value under [`crate::NETWORK_KEY`] that names the machine.
pub const HOSTNAME_VALUE: &str = "Hostname";

/// The longest a label can be.
pub const MAX: usize = 63;

/// The same rule as [`check`], as an anchored pattern a surface can test
/// what is typed against as it is typed.
pub const PATTERN: &str = "[A-Za-z0-9]([A-Za-z0-9-]*[A-Za-z0-9])?";

/// The machine's name, trimmed, if it is one a network will carry; otherwise
/// what is wrong with it.
pub fn check(answered: &str) -> Result<String, String> {
    let name = answered.trim();
    if name.is_empty() {
        return Err("Give the machine a name.".into());
    }
    if let Some(c) = name
        .chars()
        .find(|c| !c.is_ascii_alphanumeric() && *c != '-')
    {
        return Err(if c == ' ' {
            "A machine's name has no spaces; a hyphen can stand in for one.".into()
        } else if c == '.' {
            "One name, without dots: the network the machine is on gives the rest.".into()
        } else {
            format!("A machine's name is letters, digits and hyphens; “{c}” is not one of them.")
        });
    }
    if name.len() > MAX {
        return Err(format!("A machine's name is at most {MAX} characters."));
    }
    if name.starts_with('-') || name.ends_with('-') {
        return Err("A machine's name cannot begin or end with a hyphen.".into());
    }
    // Every machine is localhost to itself: named so, it is no other.
    if name.eq_ignore_ascii_case("localhost") {
        return Err("Every machine calls itself localhost. Choose a name of its own.".into());
    }
    Ok(name.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_name_a_network_will_carry_is_taken_trimmed() {
        for name in [
            "workshop",
            "peios-3f2a",
            "WS-01",
            "12345",
            "a",
            &"a".repeat(63),
        ] {
            assert_eq!(check(name).as_deref(), Ok(name), "{name:?}");
        }
        assert_eq!(check("  workshop ").as_deref(), Ok("workshop"));
    }

    #[test]
    fn anything_else_is_refused_and_says_why() {
        for name in [
            "",
            "  ",
            "my machine",
            "host.example.com",
            "café",
            "a_b",
            "-front",
            "back-",
            "LocalHost",
            &"a".repeat(64),
        ] {
            assert!(check(name).is_err(), "{name:?}");
        }
        assert!(check("my machine").unwrap_err().contains("hyphen"));
        assert!(check("host.example.com").unwrap_err().contains("dots"));
    }
}
