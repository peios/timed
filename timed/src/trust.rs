//! The root store, from trustd.
//!
//! NTS-KE is a TLS connection, so it needs to know which certificate
//! authorities to believe — and the answer has to come from the machine's
//! trust store rather than from a bundle timed reads itself, or distrusting
//! a CA would not take effect here until something restarted timed.
//!
//! So the roots come over trustd's socket. Two consequences worth stating:
//!
//! - If trustd is not up, timed has no roots and cannot do NTS. That is the
//!   correct failure: an NTS handshake against an empty root store would
//!   fail anyway, and one against a *guessed* root store would be worse.
//! - The roots are fetched once at startup and refreshed when the
//!   handshake fails, rather than subscribed to. A time client makes a
//!   handful of TLS connections a day; holding a subscription open for that
//!   would be a lot of machinery for very little.

use std::sync::Arc;
use std::time::Duration;

use rustls::RootCertStore;
use rustls_pki_types::CertificateDer;
use trust_client::Client;

use crate::log;

/// Fetch the effective root set and build a rustls store from it.
pub fn roots() -> Result<Arc<RootCertStore>, String> {
    let client = Client::system(Duration::from_secs(10)).map_err(|error| error.to_string())?;
    roots_from(&client)
}

fn roots_from(client: &Client) -> Result<Arc<RootCertStore>, String> {
    let roots = client
        .roots(true, Some("ServerAuth"))
        .map_err(|error| format!("reading TLS roots: {error}"))?;
    let mut store = RootCertStore::empty();
    let mut refused = 0usize;
    for root in &roots {
        // A root trustd vetted can still be one webpki declines to use —
        // the two have different views of what a usable CA certificate is.
        // Counting them is worth doing; failing on one is not, because a
        // single unusable root should not cost the machine every other one.
        match store.add(CertificateDer::from(root.der.clone())) {
            Ok(()) => {}
            Err(_) => refused += 1,
        }
    }
    if refused > 0 {
        log::warn(format_args!(
            "{refused} of {} roots from the trust store were not usable for TLS",
            roots.len()
        ));
    }
    if store.is_empty() {
        return Err("the trust store yielded no usable roots".into());
    }
    Ok(Arc::new(store))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::net::UnixListener;
    use std::sync::atomic::{AtomicU64, Ordering};
    use trust_core::{Reply, Request};

    #[test]
    fn tls_roots_request_server_authentication_purpose() {
        static NEXT: AtomicU64 = AtomicU64::new(0);
        let directory = std::env::temp_dir().join(format!(
            "timed-roots-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir(&directory).unwrap();
        let path = directory.join("socket");
        let listener = UnixListener::bind(&path).unwrap();
        let peer = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            stream
                .set_read_timeout(Some(Duration::from_secs(2)))
                .unwrap();
            stream
                .set_write_timeout(Some(Duration::from_secs(2)))
                .unwrap();
            let request = Request::decode(&trust_core::recv(&mut stream).unwrap()).unwrap();
            assert_eq!(
                request,
                Request::Roots {
                    with_der: true,
                    purpose: Some("ServerAuth".into())
                }
            );
            trust_core::send(
                &mut stream,
                &Reply::Roots {
                    generation: 1,
                    roots: vec![],
                    more: false,
                }
                .encode(),
            )
            .unwrap();
        });
        let client = Client::new(&path, Duration::from_secs(2)).unwrap();
        assert!(roots_from(&client).unwrap_err().contains("no usable roots"));
        peer.join().unwrap();
        std::fs::remove_dir_all(directory).unwrap();
    }
}
