//! Names, from resolvd.
//!
//! Every source is configured by name, and the name matters twice: once to
//! find an address, and once as the identity an NTS-KE certificate is
//! validated against. Those two must agree, which is why the *canonical*
//! name is what gets used — `1.time.peios.org` is a CNAME to
//! `nts.netnod.se`, and it is Netnod's certificate that will be presented.
//!
//! Resolution goes through resolvd rather than a resolver of our own, so a
//! source configured by a name only the local DNS knows works, and so that
//! split-horizon scoping applies here as everywhere else.

use std::net::{IpAddr, SocketAddr};
use std::os::unix::net::UnixStream;

use libresolv::{Family, Outcome, Reply, Request, SOCKET_PATH};

/// What a name resolved to.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Resolved {
    /// The name after CNAME chasing — what a certificate must match.
    pub canonical: String,
    pub addresses: Vec<IpAddr>,
}

pub fn lookup(name: &str) -> Result<Resolved, String> {
    let mut stream = UnixStream::connect(SOCKET_PATH)
        .map_err(|e| format!("cannot reach the resolver at {SOCKET_PATH}: {e}"))?;
    stream
        .set_read_timeout(Some(std::time::Duration::from_secs(10)))
        .map_err(|e| e.to_string())?;

    let request = Request::Lookup { name: name.to_string(), family: Family::Any };
    match libresolv::call(&mut stream, &request).map_err(|e| e.to_string())? {
        Reply::Addresses(a) => {
            if a.outcome != Outcome::Found || a.addresses.is_empty() {
                return Err(format!("{name}: {}", a.outcome.as_str()));
            }
            Ok(Resolved {
                // resolvd answers with the name asked for when no CNAME
                // applied, so this is never empty in practice — but a
                // wrong certificate identity is not a thing to leave to
                // "in practice".
                canonical: if a.canonical.is_empty() {
                    name.to_string()
                } else {
                    a.canonical.trim_end_matches('.').to_string()
                },
                addresses: a.addresses.into_iter().map(|a| a.address).collect(),
            })
        }
        Reply::Error(message) => Err(format!("{name}: {message}")),
        other => Err(format!("{name}: unexpected reply {other:?}")),
    }
}

/// Pair a resolved name with a port.
pub fn socket_addrs(resolved: &Resolved, port: u16) -> Vec<SocketAddr> {
    resolved.addresses.iter().map(|&a| SocketAddr::new(a, port)).collect()
}
