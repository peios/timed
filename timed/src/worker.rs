//! The blocking work, off the loop.
//!
//! Three things timed does are network round trips to somebody else's
//! machine, and all three can take tens of seconds: resolving a name
//! through resolvd, fetching the root store from trustd, and the NTS-KE
//! handshake — which alone allows twenty seconds per address, times
//! however many addresses a name resolves to, times four sources.
//!
//! Doing those on the poll loop, as the first version did, means the
//! daemon that owns the system clock stops answering its own socket for
//! the duration. Measured on the image: `clock status` normally returns in
//! under a millisecond, and while a handshake was in flight one call took
//! **six seconds**. Nothing about that is acceptable in a process whose
//! whole job is to be the authority other things ask.
//!
//! So the blocking work moves to one worker thread and the loop keeps
//! turning. The loop dispatches a job, carries on polling and serving,
//! and picks the answer up whenever it arrives. Exactly one job is in
//! flight per source, which bounds the work without needing a pool.

use std::net::SocketAddr;
use std::sync::mpsc::{Receiver, Sender, TryRecvError};
use std::sync::{mpsc, Arc};

use rustls::ClientConfig;

use crate::nts_ke::{self, Established};
use crate::resolve::{self, Resolved};
use crate::{log, trust};

/// Something slow to go and do.
pub enum Job {
    /// Resolve a source's name to addresses.
    Resolve { index: usize, host: String, port: u16 },
    /// Run NTS-KE, and resolve the NTP server the KE server names if it
    /// names a different one. Both halves happen here because the second
    /// is only known once the first has finished, and splitting them
    /// would mean a round trip through the loop to learn nothing.
    Handshake {
        index: usize,
        host: String,
        canonical: String,
        ke_addresses: Vec<SocketAddr>,
        tls: Arc<ClientConfig>,
    },
    /// Fetch the machine's root store from trustd.
    Roots,
}

/// What came back.
pub enum Done {
    Resolved { index: usize, result: Result<Resolved, String> },
    Handshook {
        index: usize,
        /// The session, and the addresses to actually send NTP to.
        result: Result<(Box<Established>, Vec<SocketAddr>), String>,
    },
    Roots(Result<Arc<ClientConfig>, String>),
}

/// The loop's handle on the worker.
pub struct Worker {
    jobs: Sender<Job>,
    done: Receiver<Done>,
    /// How many jobs are out. Used only to decide how long to sleep: while
    /// anything is in flight the loop waits in short hops so an answer is
    /// acted on promptly rather than up to a minute later.
    outstanding: usize,
}

impl Worker {
    pub fn spawn() -> Worker {
        let (job_tx, job_rx) = mpsc::channel::<Job>();
        let (done_tx, done_rx) = mpsc::channel::<Done>();
        std::thread::Builder::new()
            .name("timed-net".into())
            .spawn(move || run(job_rx, done_tx))
            .expect("the worker thread starts");
        Worker { jobs: job_tx, done: done_rx, outstanding: 0 }
    }

    pub fn submit(&mut self, job: Job) {
        if self.jobs.send(job).is_ok() {
            self.outstanding += 1;
        }
    }

    pub fn busy(&self) -> bool {
        self.outstanding > 0
    }

    /// Everything that has finished since last time. Never blocks.
    pub fn collect(&mut self) -> Vec<Done> {
        let mut out = Vec::new();
        loop {
            match self.done.try_recv() {
                Ok(done) => {
                    self.outstanding = self.outstanding.saturating_sub(1);
                    out.push(done);
                }
                Err(TryRecvError::Empty) => return out,
                // The worker died. Nothing to be done about it here; the
                // loop keeps the clock steered on the sources it already
                // has, and says so.
                Err(TryRecvError::Disconnected) => {
                    if self.outstanding > 0 {
                        log::error(format_args!(
                            "the network worker stopped; no new sources will be established"
                        ));
                        self.outstanding = 0;
                    }
                    return out;
                }
            }
        }
    }
}

fn run(jobs: Receiver<Job>, done: Sender<Done>) {
    while let Ok(job) = jobs.recv() {
        let result = match job {
            Job::Resolve { index, host, port } => {
                let result = resolve::lookup(&host)
                    .map(|mut r| {
                        r.addresses.truncate(8);
                        let _ = port;
                        r
                    })
                    .map_err(|e| e.to_string());
                Done::Resolved { index, result }
            }
            Job::Handshake { index, host, canonical, ke_addresses, tls } => {
                Done::Handshook { index, result: handshake(&host, &canonical, &ke_addresses, &tls) }
            }
            Job::Roots => Done::Roots(trust::roots().and_then(nts_ke::tls_config)),
        };
        if done.send(result).is_err() {
            return;
        }
    }
}

/// Try each address in turn, then resolve whatever the server redirected to.
fn handshake(
    host: &str,
    canonical: &str,
    ke_addresses: &[SocketAddr],
    tls: &Arc<ClientConfig>,
) -> Result<(Box<Established>, Vec<SocketAddr>), String> {
    let mut last = None;
    for address in ke_addresses {
        let established = match nts_ke::handshake(tls, canonical, *address) {
            Ok(e) => e,
            Err(e) => {
                last = Some(e.to_string());
                continue;
            }
        };

        // RFC 8915 §4.1.7: the KE server may name a different NTP server,
        // and §4.1.8 a different port.
        let addresses = match &established.negotiated.server {
            // Netnod's KE server answers with a bare IP address rather than
            // a name, which RFC 8915 §4.1.7 permits ("an IPv4 address, an
            // IPv6 address, or a fully qualified domain name"). Sending
            // that to the resolver asks it to look up a name that is not
            // one; it answers "found" with no addresses, and the source is
            // lost for no reason. Parse it first.
            Some(named) => match named.parse::<std::net::IpAddr>() {
                Ok(ip) => vec![SocketAddr::new(ip, established.negotiated.port)],
                Err(_) => match resolve::lookup(named) {
                    Ok(r) => resolve::socket_addrs(&r, established.negotiated.port),
                    Err(e) => {
                        last =
                            Some(format!("the KE server named {named}, which does not resolve ({e})"));
                        continue;
                    }
                },
            },
            None => ke_addresses
                .iter()
                .map(|a| SocketAddr::new(a.ip(), established.negotiated.port))
                .collect(),
        };
        if addresses.is_empty() {
            last = Some("no usable NTP address".into());
            continue;
        }
        let _ = host;
        return Ok((Box::new(established), addresses));
    }
    Err(last.unwrap_or_else(|| "no address to try".into()))
}
