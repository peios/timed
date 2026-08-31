//! The NTS key establishment handshake, RFC 8915 §4.
//!
//! Once per source per few days: a TLS 1.3 connection to port 4460, a short
//! exchange of records, and out comes a set of cookies and two keys
//! *exported from the TLS session itself* rather than sent over it. Nothing
//! secret crosses the wire, which is why a recorded handshake cannot be
//! replayed later even if the server's key is eventually compromised.
//!
//! Everything after this runs on plain UDP 123 with no TLS at all — the
//! cookies carry the server's side of the state, so it keeps none per
//! client, which is what lets NTS scale to a public service.
//!
//! # What is checked
//!
//! - **TLS 1.3 only.** RFC 8915 §3 requires it, and the exporter this
//!   depends on behaves differently in 1.2.
//! - **The ALPN must be `ntske/1`.** A server that does not select it is
//!   not an NTS-KE server, whatever else it may be, and continuing would
//!   mean interpreting some other protocol's bytes as records.
//! - **The certificate, against the machine's trust store**, for the
//!   *canonical* name. `1.time.peios.org` is a CNAME to `nts.netnod.se`
//!   and it is Netnod's certificate that arrives, so validating against the
//!   configured name would fail every time.

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::sync::Arc;
use std::time::Duration;

use ntp::nts::{self, KeError, Keys, Negotiated, Record, ALPN, MAX_KE_MESSAGE};
use rustls::{ClientConfig, ClientConnection, RootCertStore};
use rustls_pki_types::ServerName;

/// How long the whole handshake may take. Generous — a TLS handshake to a
/// server on another continent over a congested link is a slow thing — but
/// bounded, because a source that cannot complete one should be reported as
/// unusable rather than blocking the daemon.
pub const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(20);

#[derive(Debug)]
pub enum KeFailure {
    Connect(String),
    Tls(String),
    Protocol(KeError),
}

impl std::fmt::Display for KeFailure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            KeFailure::Connect(e) => write!(f, "{e}"),
            KeFailure::Tls(e) => write!(f, "TLS: {e}"),
            KeFailure::Protocol(e) => write!(f, "{e}"),
        }
    }
}

/// Build the TLS configuration once and share it across sources.
///
/// TLS 1.3 alone, the ring provider, the machine's roots, and the ALPN.
/// Client certificates are not offered: NTS authenticates the *server* to
/// us, and a public time server has no interest in who we are.
pub fn tls_config(roots: Arc<RootCertStore>) -> Result<Arc<ClientConfig>, String> {
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let mut config = ClientConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&rustls::version::TLS13])
        .map_err(|e| format!("TLS 1.3 is not available: {e}"))?
        .with_root_certificates(roots)
        .with_no_client_auth();
    config.alpn_protocols = vec![ALPN.to_vec()];
    Ok(Arc::new(config))
}

/// What a completed handshake yields.
#[derive(Debug)]
pub struct Established {
    pub keys: Keys,
    pub negotiated: Negotiated,
}

/// Run the handshake against one address.
///
/// `name` is what the certificate is validated against and must be the
/// canonical name; `address` is where to connect, which may be any of the
/// addresses that name resolved to.
pub fn handshake(
    config: &Arc<ClientConfig>,
    name: &str,
    address: SocketAddr,
) -> Result<Established, KeFailure> {
    let server_name = ServerName::try_from(name.to_string())
        .map_err(|e| KeFailure::Tls(format!("{name} is not a valid server name: {e}")))?;

    let mut socket = TcpStream::connect_timeout(&address, HANDSHAKE_TIMEOUT)
        .map_err(|e| KeFailure::Connect(format!("connecting to {address}: {e}")))?;
    socket.set_read_timeout(Some(HANDSHAKE_TIMEOUT)).map_err(|e| KeFailure::Connect(e.to_string()))?;
    socket
        .set_write_timeout(Some(HANDSHAKE_TIMEOUT))
        .map_err(|e| KeFailure::Connect(e.to_string()))?;
    socket.set_nodelay(true).ok();

    let mut connection = ClientConnection::new(config.clone(), server_name)
        .map_err(|e| KeFailure::Tls(e.to_string()))?;

    {
        let mut tls = rustls::Stream::new(&mut connection, &mut socket);
        tls.write_all(&nts::client_request()).map_err(|e| KeFailure::Tls(e.to_string()))?;
        tls.flush().map_err(|e| KeFailure::Tls(e.to_string()))?;
    }

    // The ALPN is only known once the handshake has completed, which the
    // write above forces. Checked before a single record is read, so that
    // no bytes from a server speaking something else are ever parsed as
    // NTS-KE.
    match connection.alpn_protocol() {
        Some(p) if p == ALPN => {}
        Some(other) => {
            return Err(KeFailure::Tls(format!(
                "the server selected ALPN {:?}, not ntske/1",
                String::from_utf8_lossy(other)
            )));
        }
        None => {
            return Err(KeFailure::Tls("the server selected no ALPN; not an NTS-KE server".into()));
        }
    }

    let records = read_message(&mut connection, &mut socket)?;
    let negotiated = nts::interpret(&records).map_err(KeFailure::Protocol)?;

    // The keys, exported from the session rather than transmitted in it.
    let mut c2s = [0u8; nts::KEY_LEN];
    let mut s2c = [0u8; nts::KEY_LEN];
    connection
        .export_keying_material(&mut c2s, nts::EXPORTER_LABEL, Some(&nts::exporter_context(true)))
        .map_err(|e| KeFailure::Tls(format!("exporting the c2s key: {e}")))?;
    connection
        .export_keying_material(&mut s2c, nts::EXPORTER_LABEL, Some(&nts::exporter_context(false)))
        .map_err(|e| KeFailure::Tls(format!("exporting the s2c key: {e}")))?;

    Ok(Established { keys: Keys { c2s, s2c }, negotiated })
}

/// Read records until the message is complete.
fn read_message(
    connection: &mut ClientConnection,
    socket: &mut TcpStream,
) -> Result<Vec<Record>, KeFailure> {
    let mut buffer = Vec::new();
    let mut chunk = [0u8; 4096];
    loop {
        // Bounded, and the bound is checked before the read rather than
        // after: a server that streams records forever must cost us a
        // fixed amount of memory, not an unbounded one. This is a server
        // we have authenticated, so it is a defence against one that is
        // broken or has turned hostile rather than against a stranger —
        // which is a category worth defending against anyway.
        if buffer.len() > MAX_KE_MESSAGE {
            return Err(KeFailure::Protocol(KeError::Wire(ntp::WireError::BadLength(
                buffer.len() as u32,
            ))));
        }
        match nts::Record::decode_message(&buffer) {
            Ok(Some(records)) => return Ok(records),
            Ok(None) => {}
            Err(e) => return Err(KeFailure::Protocol(KeError::Wire(e))),
        }

        let mut tls = rustls::Stream::new(connection, socket);
        let n = tls.read(&mut chunk).map_err(|e| KeFailure::Tls(e.to_string()))?;
        if n == 0 {
            return Err(KeFailure::Tls("the server closed before ending its message".into()));
        }
        buffer.extend_from_slice(&chunk[..n]);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_config_can_be_built_with_tls13_and_the_alpn() {
        // A store with no roots is still a valid configuration — it will
        // refuse every certificate, which is the correct behaviour for a
        // machine whose trust store is empty, and is exactly what the
        // trustd probe demonstrated.
        let config = tls_config(Arc::new(RootCertStore::empty())).unwrap();
        assert_eq!(config.alpn_protocols, vec![ALPN.to_vec()]);
    }

    #[test]
    fn a_name_that_is_not_a_name_is_refused_before_any_connection() {
        let config = tls_config(Arc::new(RootCertStore::empty())).unwrap();
        let address: SocketAddr = "127.0.0.1:1".parse().unwrap();
        let error = handshake(&config, "not a hostname", address).unwrap_err();
        assert!(matches!(error, KeFailure::Tls(_)), "{error}");
    }
}
