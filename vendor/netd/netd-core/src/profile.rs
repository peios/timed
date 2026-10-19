//! Profiles: how an interface stands on a network.
//!
//! `Machine\System\Network\Profiles\<path>` is PNP's profile tree (the
//! specification is on PEI-598; the reference page in the networking topic
//! lists every value). A profile is a key with flat dotted values —
//! `Address.Offered`, `Dns.Servers`, `Route.Metric` — and no match block:
//! which interfaces stand in it is the interface layer's decision
//! ([`crate::policy`]), by a `JOIN(path)` verdict.
//!
//! Subkeys inherit: `office\london` carries every value of `office` and
//! overrides those it names, per value name and wholesale (a list replaces
//! a list). A present-but-empty value means *none*; an absent value means
//! *inherit*. `Enabled = 0` makes a key and its subtree invisible.
//!
//! Every compiled default is "believe nothing, do nothing": a bare profile
//! brings the link up and nothing else. The shipped `default` profile is
//! where the friendly behaviour lives, visibly and deletably.
//!
//! This module is pure: it reads the neutral `RawKey` tree netd lowers from
//! the registry, so the vocabulary is tested without one, and a program
//! checking a profile before writing it applies netd's own laws.

use std::collections::BTreeMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use crate::raw::{RawKey, RawValue};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OnExpiry {
    Drop,
    Keep,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StaticAddress {
    pub address: IpAddr,
    pub prefix: u8,
}

/// The `Address`, `Route`, `Hostname` and `Mtu` bundles: how the
/// interface gets addressed, finds its way out, and what it tells the
/// network about itself.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AddressConfig {
    /// `Address.Offered`: take the address the network offers (DHCPv4,
    /// IPv6 autoconfiguration).
    pub offered: bool,
    /// `Address.Families`: whether the bundle deals in IPv4 at all.
    pub ipv4: bool,
    /// `Address.Families`: whether the bundle deals in IPv6 at all.
    pub ipv6: bool,
    /// `Address.Static`.
    pub statics: Vec<StaticAddress>,
    /// `Address.LinkLocal`: self-assign 169.254/16 while nobody answers.
    pub link_local: bool,
    /// `Address.Temporary`: RFC 8981 temporary addresses beside the stable.
    pub temporary: bool,
    /// `Address.OnExpiry`.
    pub on_expiry: OnExpiry,
    /// `Route.Offered`: take the way out, and extra routes, the network
    /// offers (the lease's gateway and classless routes; the routers'
    /// advertised default).
    pub route_offered: bool,
    /// `Route.Gateway`, IPv4 entry.
    pub gateway: Option<Ipv4Addr>,
    /// `Route.Gateway`, IPv6 entry.
    pub gateway6: Option<Ipv6Addr>,
    /// `Route.Metric`.
    pub route_metric: Option<u32>,
    /// `Mtu.Offered`: take the packet size limit the network offers.
    pub mtu_offered: bool,
    /// `Mtu.Value`.
    pub mtu: Option<u32>,
    /// `Hostname.Announce`: tell the network our name (DHCP option 12).
    pub announce_hostname: bool,
    /// `Hostname.Offered`: adopt the network's name for us if we have none.
    pub accept_hostname: bool,
}

impl Default for AddressConfig {
    fn default() -> Self {
        AddressConfig {
            offered: false,
            ipv4: true,
            ipv6: true,
            statics: Vec::new(),
            link_local: false,
            temporary: false,
            on_expiry: OnExpiry::Drop,
            route_offered: false,
            gateway: None,
            gateway6: None,
            route_metric: None,
            mtu_offered: false,
            mtu: None,
            announce_hostname: false,
            accept_hostname: false,
        }
    }
}

impl AddressConfig {
    /// Run a DHCPv4 client: the address is offered and IPv4 is in play.
    pub fn dhcp4(&self) -> bool {
        self.offered && self.ipv4
    }

    /// Solicit routers and autoconfigure: the address is offered and IPv6
    /// is in play.
    pub fn autoconf6(&self) -> bool {
        self.offered && self.ipv6
    }
}

/// The `Dns` bundle: what the interface contributes to name resolution.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct DnsConfig {
    /// `Dns.Servers`: our own, in order, before any offered.
    pub servers: Vec<IpAddr>,
    /// `Dns.Domains`: domains these servers answer for.
    pub domains: Vec<String>,
    /// `Dns.Offered`: also take what the network said — the lease's
    /// servers and search list, the routers' RDNSS and DNSSL, a stateless
    /// DHCPv6 answer — after our own.
    pub offered: bool,
    /// `Dns.Default`: take names no domain claims. Absent follows the
    /// default route.
    pub default_route: Option<bool>,
    /// `Dns.Exclusive`: while up, nobody else's servers are consulted.
    pub exclusive: bool,
}

/// A resolved profile: inheritance applied, vocabulary parsed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Profile {
    /// The path under `Profiles\`, `/`-separated, as written.
    pub path: String,
    /// Whether this key and every ancestor are enabled. A disabled
    /// profile is invisible: a rule that names it abstains.
    pub enabled: bool,
    pub address: AddressConfig,
    pub dns: DnsConfig,
}

/// The vocabulary, lower-cased. Anything else refuses the generation, as
/// an unknown condition name does in a rule.
const VOCABULARY: &[&str] = &[
    "address.offered",
    "address.families",
    "address.static",
    "address.linklocal",
    "address.temporary",
    "address.onexpiry",
    "route.offered",
    "route.gateway",
    "route.metric",
    "dns.offered",
    "dns.servers",
    "dns.domains",
    "dns.default",
    "dns.exclusive",
    "hostname.offered",
    "hostname.announce",
    "mtu.offered",
    "mtu.value",
];

/// Resolves every profile under the `Profiles` key, keyed by lower-cased
/// path (registry key names are case-insensitive). `root` is the
/// `Profiles` key itself; its own values are ignored.
pub fn resolve(root: &RawKey) -> Result<BTreeMap<String, Profile>, String> {
    let mut out = BTreeMap::new();
    for child in &root.children {
        walk(child, "", &BTreeMap::new(), true, &mut out)?;
    }
    Ok(out)
}

fn walk(
    key: &RawKey,
    parent_path: &str,
    inherited: &BTreeMap<String, RawValue>,
    parent_enabled: bool,
    out: &mut BTreeMap<String, Profile>,
) -> Result<(), String> {
    if key.name.is_empty() || key.name.contains('/') || key.name.contains('\\') {
        return Err(format!(
            "profile {parent_path}: bad key name {:?}",
            key.name
        ));
    }
    let path = if parent_path.is_empty() {
        key.name.clone()
    } else {
        format!("{parent_path}/{}", key.name)
    };
    let mut effective = inherited.clone();
    let mut enabled = parent_enabled;
    for (name, value) in &key.values {
        let lower = name.to_ascii_lowercase();
        if lower == "enabled" {
            match as_bool(value) {
                Some(b) => enabled &= b,
                None => return Err(format!("profile {path}: Enabled is not 0 or 1")),
            }
            continue;
        }
        if !VOCABULARY.contains(&lower.as_str()) {
            return Err(format!("profile {path}: unknown value {name}"));
        }
        effective.insert(lower, value.clone());
    }
    let (address, dns) = parse(&path, &effective)?;
    out.insert(
        path.to_ascii_lowercase(),
        Profile {
            path: path.clone(),
            enabled,
            address,
            dns,
        },
    );
    for child in &key.children {
        walk(child, &path, &effective, enabled, out)?;
    }
    Ok(())
}

fn as_bool(v: &RawValue) -> Option<bool> {
    match v {
        RawValue::Int(i) => Some(*i != 0),
        RawValue::Str(s) => match s.to_ascii_lowercase().as_str() {
            "on" | "yes" | "true" | "1" => Some(true),
            "off" | "no" | "false" | "0" => Some(false),
            _ => None,
        },
        _ => None,
    }
}

fn as_u32(v: &RawValue) -> Option<u32> {
    match v {
        RawValue::Int(i) => u32::try_from(*i).ok(),
        RawValue::Str(s) => s.trim().parse().ok(),
        _ => None,
    }
}

/// A list value; a single string is a one-item list, and an empty value
/// is the empty list (the "none" override).
fn as_list(v: &RawValue) -> Option<Vec<String>> {
    match v {
        RawValue::List(items) => Some(items.iter().filter(|s| !s.is_empty()).cloned().collect()),
        RawValue::Str(s) if s.is_empty() => Some(Vec::new()),
        RawValue::Str(s) => Some(vec![s.clone()]),
        _ => None,
    }
}

fn as_str(v: &RawValue) -> Option<String> {
    match v {
        RawValue::Str(s) => Some(s.clone()),
        RawValue::Int(i) => Some(i.to_string()),
        _ => None,
    }
}

pub fn parse_cidr(s: &str) -> Option<StaticAddress> {
    let (a, p) = s.split_once('/')?;
    let address: IpAddr = a.trim().parse().ok()?;
    let bits = if address.is_ipv4() { 32 } else { 128 };
    Some(StaticAddress {
        address,
        prefix: p.trim().parse().ok().filter(|p| *p <= bits)?,
    })
}

fn parse(
    path: &str,
    values: &BTreeMap<String, RawValue>,
) -> Result<(AddressConfig, DnsConfig), String> {
    let mut a = AddressConfig::default();
    let mut d = DnsConfig::default();
    let bad = |name: &str| format!("profile {path}: {name} has the wrong shape");
    for (name, value) in values {
        match name.as_str() {
            "address.offered" => a.offered = as_bool(value).ok_or_else(|| bad(name))?,
            "address.families" => {
                let list = as_list(value).ok_or_else(|| bad(name))?;
                a.ipv4 = false;
                a.ipv6 = false;
                for f in list {
                    match f.to_ascii_lowercase().as_str() {
                        "ipv4" => a.ipv4 = true,
                        "ipv6" => a.ipv6 = true,
                        _ => return Err(format!("profile {path}: Address.Families: {f:?}")),
                    }
                }
            }
            "address.static" => {
                a.statics = as_list(value)
                    .ok_or_else(|| bad(name))?
                    .iter()
                    .map(|s| {
                        parse_cidr(s)
                            .ok_or_else(|| format!("profile {path}: Address.Static: {s:?}"))
                    })
                    .collect::<Result<_, _>>()?;
            }
            "address.linklocal" => a.link_local = as_bool(value).ok_or_else(|| bad(name))?,
            "address.temporary" => a.temporary = as_bool(value).ok_or_else(|| bad(name))?,
            "address.onexpiry" => {
                a.on_expiry = match as_str(value)
                    .ok_or_else(|| bad(name))?
                    .to_ascii_lowercase()
                    .as_str()
                {
                    "drop" => OnExpiry::Drop,
                    "keep" => OnExpiry::Keep,
                    other => return Err(format!("profile {path}: Address.OnExpiry: {other:?}")),
                }
            }
            "route.offered" => a.route_offered = as_bool(value).ok_or_else(|| bad(name))?,
            "route.gateway" => {
                a.gateway = None;
                a.gateway6 = None;
                for g in as_list(value).ok_or_else(|| bad(name))? {
                    match g.trim().parse::<IpAddr>() {
                        Ok(IpAddr::V4(v4)) => a.gateway = Some(v4),
                        Ok(IpAddr::V6(v6)) => a.gateway6 = Some(v6),
                        Err(_) => return Err(format!("profile {path}: Route.Gateway: {g:?}")),
                    }
                }
            }
            "route.metric" => a.route_metric = Some(as_u32(value).ok_or_else(|| bad(name))?),
            "mtu.offered" => a.mtu_offered = as_bool(value).ok_or_else(|| bad(name))?,
            "mtu.value" => {
                let v = as_u32(value).ok_or_else(|| bad(name))?;
                if v < 68 {
                    return Err(format!("profile {path}: Mtu.Value {v} is below 68"));
                }
                a.mtu = Some(v);
            }
            "hostname.announce" => a.announce_hostname = as_bool(value).ok_or_else(|| bad(name))?,
            "hostname.offered" => a.accept_hostname = as_bool(value).ok_or_else(|| bad(name))?,
            "dns.offered" => d.offered = as_bool(value).ok_or_else(|| bad(name))?,
            "dns.servers" => {
                d.servers = as_list(value)
                    .ok_or_else(|| bad(name))?
                    .iter()
                    .map(|s| {
                        s.trim()
                            .parse()
                            .map_err(|_| format!("profile {path}: Dns.Servers: {s:?}"))
                    })
                    .collect::<Result<_, _>>()?;
            }
            "dns.domains" => d.domains = as_list(value).ok_or_else(|| bad(name))?,
            "dns.default" => d.default_route = Some(as_bool(value).ok_or_else(|| bad(name))?),
            "dns.exclusive" => d.exclusive = as_bool(value).ok_or_else(|| bad(name))?,
            _ => return Err(format!("profile {path}: unknown value {name}")),
        }
    }
    // Statics outside the bundle's families are not an error the operator
    // should have to see twice: the family switch simply wins.
    a.statics.retain(|s| match s.address {
        IpAddr::V4(_) => a.ipv4,
        IpAddr::V6(_) => a.ipv6,
    });
    Ok((a, d))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key(name: &str, values: &[(&str, RawValue)], children: Vec<RawKey>) -> RawKey {
        RawKey {
            name: name.into(),
            values: values
                .iter()
                .map(|(n, v)| ((*n).to_owned(), v.clone()))
                .collect(),
            children,
        }
    }

    fn s(v: &str) -> RawValue {
        RawValue::Str(v.into())
    }

    fn list(v: &[&str]) -> RawValue {
        RawValue::List(v.iter().map(|s| (*s).to_owned()).collect())
    }

    #[test]
    fn a_bare_profile_believes_nothing_and_does_nothing() {
        let root = key("Profiles", &[], vec![key("bare", &[], vec![])]);
        let p = &resolve(&root).unwrap()["bare"];
        assert!(p.enabled);
        assert!(!p.address.dhcp4());
        assert!(!p.address.autoconf6());
        assert!(!p.address.route_offered);
        assert!(!p.dns.offered);
        assert!(!p.address.link_local);
        assert!(!p.address.announce_hostname);
    }

    #[test]
    fn subkeys_inherit_and_override_per_name_wholesale() {
        let root = key(
            "Profiles",
            &[],
            vec![key(
                "office",
                &[
                    ("Address.Offered", RawValue::Int(1)),
                    ("Route.Offered", RawValue::Int(1)),
                    ("Dns.Servers", list(&["10.0.0.1", "10.0.0.2"])),
                    ("Dns.Domains", list(&["corp.example"])),
                ],
                vec![key(
                    "london",
                    &[("Dns.Servers", list(&["10.1.0.1"]))],
                    vec![key(
                        "db1",
                        &[
                            ("Address.Offered", RawValue::Int(0)),
                            ("Address.Static", s("10.1.0.50/24")),
                            ("Route.Offered", RawValue::Int(0)),
                            ("Route.Gateway", s("10.1.0.1")),
                            ("Dns.Servers", s("")),
                        ],
                        vec![],
                    )],
                )],
            )],
        );
        let all = resolve(&root).unwrap();
        let london = &all["office/london"];
        assert!(london.address.dhcp4());
        assert_eq!(london.dns.servers.len(), 1, "list replaced, not appended");
        assert_eq!(
            london.dns.domains,
            vec!["corp.example".to_owned()],
            "inherited"
        );
        let db1 = &all["office/london/db1"];
        assert!(!db1.address.dhcp4());
        assert_eq!(db1.address.statics.len(), 1);
        assert_eq!(db1.address.gateway, Some(Ipv4Addr::new(10, 1, 0, 1)));
        assert!(db1.dns.servers.is_empty(), "present-but-empty means none");
        assert_eq!(
            db1.dns.domains,
            vec!["corp.example".to_owned()],
            "still inherited"
        );
        assert_eq!(db1.path, "office/london/db1");
    }

    #[test]
    fn disabled_is_invisible_down_the_subtree_and_is_not_inherited_as_a_value() {
        let root = key(
            "Profiles",
            &[],
            vec![key(
                "office",
                &[("Enabled", RawValue::Int(0))],
                vec![key("london", &[("Enabled", RawValue::Int(1))], vec![])],
            )],
        );
        let all = resolve(&root).unwrap();
        assert!(!all["office"].enabled);
        assert!(
            !all["office/london"].enabled,
            "a child cannot re-enable itself"
        );
    }

    #[test]
    fn families_gate_the_whole_bundle() {
        let root = key(
            "Profiles",
            &[],
            vec![key(
                "v4",
                &[
                    ("Address.Offered", RawValue::Int(1)),
                    ("Address.Families", s("ipv4")),
                    ("Address.Static", list(&["fd00::5/64", "10.0.0.5/24"])),
                ],
                vec![],
            )],
        );
        let p = &resolve(&root).unwrap()["v4"];
        assert!(p.address.dhcp4());
        assert!(!p.address.autoconf6());
        assert_eq!(p.address.statics.len(), 1);
        assert!(p.address.statics[0].address.is_ipv4());
    }

    #[test]
    fn unknown_names_and_bad_shapes_refuse() {
        let root = key(
            "Profiles",
            &[],
            vec![key("x", &[("Address.Dhcp4", RawValue::Int(1))], vec![])],
        );
        assert!(resolve(&root).unwrap_err().contains("unknown value"));
        let root = key(
            "Profiles",
            &[],
            vec![key("x", &[("Mtu.Value", s("12"))], vec![])],
        );
        assert!(resolve(&root).unwrap_err().contains("below 68"));
        let root = key(
            "Profiles",
            &[],
            vec![key("x", &[("Address.OnExpiry", s("hold"))], vec![])],
        );
        assert!(resolve(&root).unwrap_err().contains("OnExpiry"));
        let root = key(
            "Profiles",
            &[],
            vec![key("x", &[("Route.Gateway", s("gateway"))], vec![])],
        );
        assert!(resolve(&root).unwrap_err().contains("Route.Gateway"));
    }

    #[test]
    fn names_are_case_insensitive_and_paths_are_looked_up_lower_cased() {
        let root = key(
            "Profiles",
            &[],
            vec![key("Office", &[("address.OFFERED", s("yes"))], vec![])],
        );
        let all = resolve(&root).unwrap();
        assert!(all["office"].address.offered);
        assert_eq!(all["office"].path, "Office");
    }
}
