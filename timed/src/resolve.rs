//! Names, from resolvd.
//!
//! DNS supplies addresses and a diagnostic canonical name. It never selects
//! the reference identity used to authenticate an NTS-KE certificate: the
//! configured source name remains the identity throughout the connection.
//!
//! Resolution goes through resolvd rather than a resolver of our own, so a
//! source configured by a name only the local DNS knows works, and so that
//! split-horizon scoping applies here as everywhere else.

use std::net::{IpAddr, SocketAddr};
use std::time::Duration;

use resolvd_client::{Client, Family, Outcome};

/// What a name resolved to.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Resolved {
    /// The name after CNAME chasing, for diagnostics only.
    pub canonical: String,
    pub addresses: Vec<IpAddr>,
}

pub fn lookup(name: &str) -> Result<Resolved, String> {
    let client = Client::system(Duration::from_secs(10)).map_err(|error| error.to_string())?;
    let a = client
        .lookup(name, Family::Any)
        .map_err(|error| format!("{name}: {error}"))?;
    if a.outcome != Outcome::Found || a.addresses.is_empty() {
        return Err(format!("{name}: {}", a.outcome.as_str()));
    }
    Ok(Resolved {
        canonical: if a.canonical.is_empty() {
            name.to_string()
        } else {
            a.canonical.trim_end_matches('.').to_string()
        },
        addresses: a.addresses.into_iter().map(|a| a.address).collect(),
    })
}

/// Pair a resolved name with a port.
pub fn socket_addrs(resolved: &Resolved, port: u16) -> Vec<SocketAddr> {
    resolved
        .addresses
        .iter()
        .map(|&a| SocketAddr::new(a, port))
        .collect()
}
