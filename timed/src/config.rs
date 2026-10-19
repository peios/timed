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

use std::io;
use peios::registry::{Key, KeyAccess, OpenFlags, RegValue, ValueType};
#[path = "registry_reader.rs"]
mod reader;
use reader::{Reader, open, strings};
use timed_core::{
    ALLOW_UNAUTHENTICATED_VALUE, AUTOMATIC_VALUE, CONTROL_SECURITY_VALUE, MAX_POLL_VALUE,
    MIN_POLL_VALUE, SERVERS_VALUE, TIME_KEY, TIME_ZONE_VALUE, USE_FROM_DHCP_VALUE,
};

use crate::log;
use crate::source::{DEFAULT_MAX_POLL, DEFAULT_MIN_POLL, POLL_CEILING, POLL_FLOOR};

/// The compiled fallback, used when nothing else names a source.
///
/// Explicit NTS identities from three independent operators. DNS resolution
/// supplies addresses only; changing an operator requires a policy or software
/// update. See docs/development.md for the published endpoint references.
pub const FALLBACK_SERVERS: &[&str] = &["time.cloudflare.com", "nts.netnod.se", "ptbtime1.ptb.de"];

pub use timed_core::servers::{ServerSpec, parse_server};

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

pub fn load() -> io::Result<Config> {
    let root = open(None, TIME_KEY)?;
    load_from(root.as_ref())
}

fn load_from(root: Option<&impl Reader>) -> io::Result<Config> {
    let mut config = Config::default();
    let Some(root) = root else {
        return Ok(config);
    };

    if let Some(entries) = strings(root, SERVERS_VALUE)? {
        for entry in entries {
            match parse_server(&entry) {
                Ok(spec) => config.servers.push(spec),
                Err(why) => log::warn(format_args!("{SERVERS_VALUE}: {entry:?}: {why}; ignored")),
            }
        }
    }

    if let Some(v) = root
        .value(ALLOW_UNAUTHENTICATED_VALUE)?
        .and_then(|v| dword(&v))
    {
        config.allow_unauthenticated = v != 0;
    }
    if let Some(v) = root.value(USE_FROM_DHCP_VALUE)?.and_then(|v| dword(&v)) {
        config.use_from_dhcp = v != 0;
    }
    if let Some(v) = root.value(MIN_POLL_VALUE)?.and_then(|v| dword(&v)) {
        config.min_poll = (v as i64).clamp(POLL_FLOOR as i64, POLL_CEILING as i64) as i8;
    }
    if let Some(v) = root.value(MAX_POLL_VALUE)?.and_then(|v| dword(&v)) {
        config.max_poll = (v as i64).clamp(POLL_FLOOR as i64, POLL_CEILING as i64) as i8;
    }
    if config.max_poll < config.min_poll {
        log::warn(format_args!(
            "{MAX_POLL_VALUE} ({}) is below {MIN_POLL_VALUE} ({}); using {MIN_POLL_VALUE} for both",
            config.max_poll, config.min_poll
        ));
        config.max_poll = config.min_poll;
    }

    config.control_security = root
        .value(CONTROL_SECURITY_VALUE)?
        .filter(|v| v.ty == ValueType::BINARY && !v.data.is_empty())
        .map(|v| v.data);

    if let Some(v) = root.value(AUTOMATIC_VALUE)?.and_then(|v| dword(&v)) {
        config.automatic = v != 0;
    }
    config.time_zone = strings(root, TIME_ZONE_VALUE)?
        .and_then(|v| v.into_iter().next())
        .map(|z| z.trim().to_string())
        .filter(|z| !z.is_empty());

    Ok(config)
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
    fn fallbacks_use_explicit_operator_identities() {
        let fallback = Config::fallback();
        assert_eq!(
            fallback
                .iter()
                .map(|source| source.host.as_str())
                .collect::<Vec<_>>(),
            FALLBACK_SERVERS
        );
        assert!(
            fallback.iter().all(|s| !s.unauthenticated),
            "the fallback is NTS"
        );
        // Keep independent operators without letting DNS choose TLS identities.
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

#[cfg(test)]
mod read_tests {
    use super::*;
    struct Fixture {
        fault: &'static str,
    }
    impl Reader for Fixture {
        fn value(&self, name: &str) -> io::Result<Option<peios::registry::RegValue>> {
            if self.fault == "value" && name == "ControlSecurity" {
                return Err(io::Error::from_raw_os_error(libc::EIO));
            }
            Ok(None)
        }
    }

    #[test]
    fn missing_configuration_keeps_documented_defaults() {
        assert_eq!(load_from(None::<&Fixture>).unwrap(), Config::default());
        assert_eq!(
            load_from(Some(&Fixture { fault: "" })).unwrap(),
            Config::default()
        );
    }
    #[test]
    fn failed_value_reads_do_not_produce_a_partial_configuration() {
        let error = load_from(Some(&Fixture { fault: "value" })).unwrap_err();
        assert_eq!(error.raw_os_error(), Some(libc::EIO));
    }
    #[test]
    fn malformed_text_cannot_silently_remove_one_list_entry() {
        let value = peios::registry::RegValue {
            sequence: 0,
            ty: ValueType::MULTI_SZ,
            data: b"valid\0\xff\0\0".to_vec(),
            layer: vec![],
        };
        assert_eq!(
            reader::multi(&value).unwrap_err().kind(),
            io::ErrorKind::InvalidData
        );
    }
}
