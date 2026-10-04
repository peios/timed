//! The grammar of a `Servers` entry.
//!
//! Here rather than in the daemon so that a program writing
//! `Machine\System\Time Servers` can refuse what timed would refuse, at the
//! moment it is typed, instead of the entry being dropped later with only a
//! log line to say so.

/// One configured source, before it has been resolved.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServerSpec {
    pub host: String,
    /// The NTP port, or the NTS-KE port when NTS is in use. `None` means
    /// the default for whichever applies.
    pub port: Option<u16>,
    /// The operator asked for this one to lead. Breaks ties in selection
    /// and nothing more — a preferred falseticker is still discarded.
    pub prefer: bool,
    /// This particular source speaks plain NTP. Only honoured when
    /// `AllowUnauthenticated` is on; otherwise the source is refused, so
    /// that turning the machine-wide switch off actually turns everything
    /// off rather than leaving per-source exceptions behind.
    pub unauthenticated: bool,
}

impl ServerSpec {
    pub fn new(host: impl Into<String>) -> ServerSpec {
        ServerSpec {
            host: host.into(),
            port: None,
            prefer: false,
            unauthenticated: false,
        }
    }
}

/// Parse one `Servers` entry.
///
/// `host`, `host:port`, or either followed by option words. Unknown words
/// are refused rather than ignored: a typo in `prefer` that silently did
/// nothing would be a configuration that looks right and is not.
pub fn parse_server(entry: &str) -> Result<ServerSpec, String> {
    let mut words = entry.split_whitespace();
    let Some(target) = words.next() else {
        return Err("empty entry".into());
    };

    let (host, port) = split_host_port(target)?;
    if host.is_empty() || host.len() > 253 {
        return Err(format!("{target:?} is not a host"));
    }

    let mut spec = ServerSpec {
        host,
        port,
        prefer: false,
        unauthenticated: false,
    };
    for word in words {
        match word {
            "prefer" => spec.prefer = true,
            "unauthenticated" | "noauth" => spec.unauthenticated = true,
            other => return Err(format!("unknown option {other:?}")),
        }
    }
    Ok(spec)
}

/// Split `host:port`, leaving a bare IPv6 address alone.
///
/// An IPv6 literal is full of colons, so the port form for one is
/// `[::1]:123` and a bare `::1` is a host. Getting this wrong turns
/// `2001:db8::1` into the host `2001:db8:` on port... nothing, and the
/// failure is a name that never resolves rather than an error.
fn split_host_port(target: &str) -> Result<(String, Option<u16>), String> {
    if let Some(rest) = target.strip_prefix('[') {
        let (host, after) = rest
            .split_once(']')
            .ok_or_else(|| format!("{target:?} opens a bracket it does not close"))?;
        let port = match after.strip_prefix(':') {
            Some(p) => Some(p.parse().map_err(|_| format!("{p:?} is not a port"))?),
            None if after.is_empty() => None,
            None => return Err(format!("{target:?} has trailing text after the address")),
        };
        return Ok((host.to_string(), port));
    }
    match target.rsplit_once(':') {
        // More than one colon and no brackets: a bare IPv6 address.
        Some(_) if target.matches(':').count() > 1 => Ok((target.to_string(), None)),
        Some((host, port)) => Ok((
            host.to_string(),
            Some(
                port.parse()
                    .map_err(|_| format!("{port:?} is not a port"))?,
            ),
        )),
        None => Ok((target.to_string(), None)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_bare_host_parses() {
        assert_eq!(
            parse_server("time.example.org").unwrap(),
            ServerSpec::new("time.example.org")
        );
    }

    #[test]
    fn a_port_parses() {
        let s = parse_server("time.example.org:4461").unwrap();
        assert_eq!(s.host, "time.example.org");
        assert_eq!(s.port, Some(4461));
    }

    #[test]
    fn options_parse_and_a_typo_is_an_error_not_a_shrug() {
        let s = parse_server("time.example.org prefer").unwrap();
        assert!(s.prefer);
        let s = parse_server("time.example.org unauthenticated prefer").unwrap();
        assert!(s.prefer && s.unauthenticated);
        // The failure that matters: a misspelled option that silently did
        // nothing would be a configuration that reads correctly and is not.
        assert!(parse_server("time.example.org prefered").is_err());
    }

    #[test]
    fn an_ipv6_literal_is_not_mistaken_for_a_host_and_port() {
        let s = parse_server("2001:db8::1").unwrap();
        assert_eq!(s.host, "2001:db8::1");
        assert_eq!(s.port, None);

        let s = parse_server("[2001:db8::1]:123").unwrap();
        assert_eq!(s.host, "2001:db8::1");
        assert_eq!(s.port, Some(123));

        let s = parse_server("[::1]").unwrap();
        assert_eq!(s.host, "::1");

        assert!(parse_server("[2001:db8::1").is_err());
        assert!(parse_server("[::1]junk").is_err());
    }

    #[test]
    fn nonsense_is_refused() {
        assert!(parse_server("").is_err());
        assert!(parse_server("host:notaport").is_err());
        assert!(parse_server(&format!("{}:123", "a".repeat(300))).is_err());
    }
}
