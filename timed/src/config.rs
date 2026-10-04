//! `Machine\System\Time`: where the machine's clock policy lives.
//!
//! ```text
//! Machine\System\Time
//!   Servers              REG_MULTI_SZ  explicit sources, highest precedence
//!   AllowUnauthenticated REG_DWORD     0 (default) NTS only, 1 permit plain
//!   UseFromDHCP          REG_DWORD     0 (default) ignore DHCP option 42
//!   MinPoll / MaxPoll    REG_DWORD     log2 seconds, 6 and 10 by default
//!   ControlSecurity      REG_BINARY    the control object's descriptor
//!   Automatic            REG_DWORD     1 (default) keep the clock from the
//!                                      sources; 0 set it by hand
//!   TimeZone             REG_SZ        an IANA zone name; absent is UTC
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
    ALLOW_UNAUTHENTICATED_VALUE, AUTOMATIC_VALUE, CONTROL_SECURITY_VALUE, MAX_POLL_VALUE,
    MIN_POLL_VALUE, SERVERS_VALUE, TIME_KEY, TIME_ZONE_VALUE, USE_FROM_DHCP_VALUE,
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

pub use libtimed::servers::{ServerSpec, parse_server};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Config {
    pub servers: Vec<ServerSpec>,
    pub allow_unauthenticated: bool,
    pub use_from_dhcp: bool,
    pub min_poll: i8,
    pub max_poll: i8,
    pub control_security: Option<Vec<u8>>,
    /// `Automatic`: keep the clock from the sources. Off, the clock is set
    /// by hand and nothing is polled.
    pub automatic: bool,
    /// `TimeZone`, as written. Checked when it is put in place, not here,
    /// because whether it is good depends on what tzdata holds.
    pub time_zone: Option<String>,
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
            automatic: true,
            time_zone: None,
        }
    }
}

impl Config {
    /// Did the registry name any sources? If not, the fallback applies.
    pub fn has_explicit_servers(&self) -> bool {
        !self.servers.is_empty()
    }

    pub fn fallback() -> Vec<ServerSpec> {
        FALLBACK_SERVERS
            .iter()
            .map(|h| ServerSpec::new(*h))
            .collect()
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
            String::from_utf8(v.data[..end].to_vec())
                .ok()
                .map(|s| vec![s])
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

    if let Some(v) = read(&root, AUTOMATIC_VALUE).and_then(|v| dword(&v)) {
        config.automatic = v != 0;
    }
    config.time_zone = read(&root, TIME_ZONE_VALUE)
        .and_then(|v| multi(&v))
        .and_then(|v| v.into_iter().next())
        .map(|z| z.trim().to_string())
        .filter(|z| !z.is_empty());

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
    fn the_fallback_is_four_names_under_our_own_zone() {
        let fallback = Config::fallback();
        assert_eq!(fallback.len(), 4);
        assert!(fallback.iter().all(|s| s.host.ends_with(".time.peios.org")));
        assert!(
            fallback.iter().all(|s| !s.unauthenticated),
            "the fallback is NTS"
        );
        // Three independent operators is the point; four names is what
        // gives the third a second site.
        assert!(fallback.len() >= 3);
    }

    #[test]
    fn the_defaults_are_the_safe_ones() {
        let c = Config::default();
        assert!(!c.allow_unauthenticated, "NTS is required by default");
        assert!(
            !c.use_from_dhcp,
            "DHCP time servers are the attacker's on a hostile LAN"
        );
        assert!(!c.has_explicit_servers());
        assert!(c.automatic, "the clock is kept from its sources");
        assert_eq!(c.time_zone, None, "UTC until somebody chooses");
    }
}
