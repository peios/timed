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

use std::os::unix::net::UnixStream;
use std::sync::Arc;

use libtrust::{Reply, Request, SOCKET_PATH};
use rustls::RootCertStore;
use rustls_pki_types::CertificateDer;

use crate::log;

/// Fetch the effective root set and build a rustls store from it.
pub fn roots() -> Result<Arc<RootCertStore>, String> {
    let mut stream = UnixStream::connect(SOCKET_PATH)
        .map_err(|e| format!("cannot reach the trust store at {SOCKET_PATH}: {e}"))?;
    stream
        .set_read_timeout(Some(std::time::Duration::from_secs(10)))
        .map_err(|e| e.to_string())?;

    libtrust::send(&mut stream, &Request::Roots { with_der: true, purpose: None }.encode())
        .map_err(|e| format!("asking for roots: {e}"))?;

    // The answer chunks; read until a reply says it is the last.
    let mut replies = Vec::new();
    loop {
        let bytes = libtrust::recv(&mut stream).map_err(|e| format!("reading roots: {e}"))?;
        let reply = Reply::decode(&bytes).map_err(|e| format!("malformed roots reply: {e}"))?;
        let done = !matches!(&reply, Reply::Roots { more: true, .. });
        replies.push(reply);
        if done {
            break;
        }
    }

    let (_, roots) = libtrust::roots_of(replies)?;
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
