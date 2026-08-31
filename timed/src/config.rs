//! `Machine\System\Time`: where the machine's clock policy lives.
//!
//! ```text
//! Machine\System\Time
//!   Servers              REG_MULTI_SZ  explicit sources, highest precedence
//!   AllowUnauthenticated REG_DWORD     0 (default) NTS only, 1 permit plain
//!   UseFromDHCP          REG_DWORD     0 (default) ignore DHCP option 42
//!   MinPoll / MaxPoll    REG_DWORD     log2 seconds, 6 and 10 by default
//!   ControlSecurity      REG_BINARY    the control object's descriptor
//! ```
//!
//! # Precedence
//!
//! `Servers` → the domain (v2) → DHCP, if enabled → the compiled fallback
//! set. The first of those that yields anything wins outright rather than
//! being merged, because merging would mean a machine that has been told
//! exactly which servers to use silently also talking to somebody else's.
//!
//! # Two defaults worth defending
//!
//! **NTS is required.** A network that blocks port 4460 gets a machine that
//! reports itself unsynchronised, which is honest, rather than one
//! synchronised to whoever answered on port 123, which is not. The build
//! floor keeps TLS working meanwhile, so the machine is not bricked by it.
//!
//! **DHCP time servers are off**, as on Windows. On a network you do not
//! control, the DHCP server's idea of the time is the attacker's idea of
//! the time — and time is what certificate expiry, Kerberos tickets and log
//! ordering all rest on.

use libtimed::{
    ALLOW_UNAUTHENTICATED_VALUE, CONTROL_SECURITY_VALUE, MAX_POLL_VALUE, MIN_POLL_VALUE,
    SERVERS_VALUE, TIME_KEY, USE_FROM_DHCP_VALUE,
};
use peios::registry::{Key, KeyAccess, OpenFlags, RegValue, ValueType};

use crate::log;
use crate::source::{DEFAULT_MAX_POLL, DEFAULT_MIN_POLL, POLL_CEILING, POLL_FLOOR};

/// The compiled fallback, used when nothing else names a source.
///
/// Four names under our own zone, CNAMEd to three independent operators in
/// three jurisdictions: Cloudflare, Netnod (twice) and PTB. Three is the
/// minimum at which one liar can be outvoted — see [`crate::select`] — and
/// independence is what makes the votes worth counting: three servers run
/// by one operator would agree with each other about anything.
///
/// The indirection through `time.peios.org` is deliberate. An operator that
/// withdraws its service, or that we stop wanting to depend on, is a DNS
/// change rather than an image rebuild.
pub const FALLBACK_SERVERS: &[&str] = &[
    "0.time.peios.org",
    "1.time.peios.org",
    "2.time.peios.org",
    "3.time.peios.org",
];

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
        ServerSpec { host: host.into(), port: None, prefer: false, unauthenticated: false }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Config {
    pub servers: Vec<ServerSpec>,
    pub allow_unauthenticated: bool,
    pub use_from_dhcp: bool,
    pub min_poll: i8,
    pub max_poll: i8,
    pub control_security: Option<Vec<u8>>,
}

impl Default for Config {
    fn default() -> Config {
        Config {
            servers: Vec::new(),
            allow_unauthenticated: false,
            use_from_dhcp: false,
            min_poll: DEFAULT_MIN_POLL,
            max_poll: DEFAULT_MAX_POLL,
            control_security: None,
        }
    }
}

impl Config {
    /// Did the registry name any sources? If not, the fallback applies.
    pub fn has_explicit_servers(&self) -> bool {
        !self.servers.is_empty()
    }

    pub fn fallback() -> Vec<ServerSpec> {
        FALLBACK_SERVERS.iter().map(|h| ServerSpec::new(*h)).collect()
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

    let mut spec = ServerSpec { host, port, prefer: false, unauthenticated: false };
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
        Some((host, port)) => {
            Ok((host.to_string(), Some(port.parse().map_err(|_| format!("{port:?} is not a port"))?)))
        }
        None => Ok((target.to_string(), None)),
    }
}

fn dword(v: &RegValue) -> Option<u32> {
    (v.ty == ValueType::DWORD && v.data.len() == 4)
        .then(|| u32::from_le_bytes([v.data[0], v.data[1], v.data[2], v.data[3]]))
}

fn multi(v: &RegValue) -> Option<Vec<String>> {
    match v.ty {
        ValueType::MULTI_SZ => Some(
            v.data
                .split(|&b| b == 0)
                .filter(|s| !s.is_empty())
                .filter_map(|s| String::from_utf8(s.to_vec()).ok())
                .collect(),
        ),
        ValueType::SZ | ValueType::EXPAND_SZ => {
            let end = v.data.iter().position(|&b| b == 0).unwrap_or(v.data.len());
            String::from_utf8(v.data[..end].to_vec()).ok().map(|s| vec![s])
        }
        _ => None,
    }
}

fn read(key: &Key, name: &str) -> Option<RegValue> {
    key.query_value(name.as_bytes(), None).ok()
}

pub fn load() -> Config {
    let mut config = Config::default();
    let Ok(root) = Key::open(
        None,
        TIME_KEY,
        KeyAccess::QUERY_VALUE | KeyAccess::ENUMERATE_SUB_KEYS,
        OpenFlags::empty(),
    ) else {
        // Before the seed applies there is no key, and the defaults are the
        // right answer: the fallback set, NTS required, DHCP ignored.
        return config;
    };

    if let Some(entries) = read(&root, SERVERS_VALUE).and_then(|v| multi(&v)) {
        for entry in entries {
            match parse_server(&entry) {
                Ok(spec) => config.servers.push(spec),
                Err(why) => log::warn(format_args!("{SERVERS_VALUE}: {entry:?}: {why}; ignored")),
            }
        }
    }

    if let Some(v) = read(&root, ALLOW_UNAUTHENTICATED_VALUE).and_then(|v| dword(&v)) {
        config.allow_unauthenticated = v != 0;
    }
    if let Some(v) = read(&root, USE_FROM_DHCP_VALUE).and_then(|v| dword(&v)) {
        config.use_from_dhcp = v != 0;
    }
    if let Some(v) = read(&root, MIN_POLL_VALUE).and_then(|v| dword(&v)) {
        config.min_poll = (v as i64).clamp(POLL_FLOOR as i64, POLL_CEILING as i64) as i8;
    }
    if let Some(v) = read(&root, MAX_POLL_VALUE).and_then(|v| dword(&v)) {
        config.max_poll = (v as i64).clamp(POLL_FLOOR as i64, POLL_CEILING as i64) as i8;
    }
    if config.max_poll < config.min_poll {
        log::warn(format_args!(
            "{MAX_POLL_VALUE} ({}) is below {MIN_POLL_VALUE} ({}); using {MIN_POLL_VALUE} for both",
            config.max_poll, config.min_poll
        ));
        config.max_poll = config.min_poll;
    }

    config.control_security = read(&root, CONTROL_SECURITY_VALUE)
        .filter(|v| v.ty == ValueType::BINARY && !v.data.is_empty())
        .map(|v| v.data);

    config
}

/// Arm a subtree watch on `Machine\System\Time`.
pub fn watch() -> peios::Result<Key> {
    use peios::registry::NotifyFilter;
    let key = Key::open(None, TIME_KEY, KeyAccess::NOTIFY, OpenFlags::empty())?;
    key.notify(NotifyFilter::ALL, true)?;
    key.set_nonblocking(true)?;
    Ok(key)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_bare_host_parses() {
        assert_eq!(parse_server("time.example.org").unwrap(), ServerSpec::new("time.example.org"));
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

    #[test]
    fn the_fallback_is_four_names_under_our_own_zone() {
        let fallback = Config::fallback();
        assert_eq!(fallback.len(), 4);
        assert!(fallback.iter().all(|s| s.host.ends_with(".time.peios.org")));
        assert!(fallback.iter().all(|s| !s.unauthenticated), "the fallback is NTS");
        // Three independent operators is the point; four names is what
        // gives the third a second site.
        assert!(fallback.len() >= 3);
    }

    #[test]
    fn the_defaults_are_the_safe_ones() {
        let c = Config::default();
        assert!(!c.allow_unauthenticated, "NTS is required by default");
        assert!(!c.use_from_dhcp, "DHCP time servers are the attacker's on a hostile LAN");
        assert!(!c.has_explicit_servers());
    }
}
