//! timed: the machine's clock authority.
//!
//! One process, one poll loop, one privilege. It polls a handful of time
//! servers, decides which of them are telling the truth, and steers the
//! system clock — and it does nothing else, listens on no network port, and
//! initiates every conversation it takes part in.
//!
//! # Order of operations at startup
//!
//! The order matters more here than in most daemons, because of a circle:
//! NTS needs TLS, TLS needs a plausible clock, and the clock is what we are
//! trying to establish.
//!
//! 1. **Raise the clock to the build floor.** Every certificate in the
//!    shipped trust store was valid at that moment, so TLS can work from
//!    here even on a machine whose RTC is dead and reading 1970.
//! 2. **Fetch the roots from trustd**, so a distrusted CA is distrusted
//!    here too, without timed needing to be restarted.
//! 3. **Resolve the sources through resolvd**, keeping the canonical name —
//!    `1.time.peios.org` is a CNAME to `nts.netnod.se`, and it is Netnod's
//!    certificate that will arrive.
//! 4. **NTS-KE**, once per source, yielding cookies and keys.
//! 5. **Poll**, and only now is there anything to set the clock from.
//!
//! Steps 2 to 4 are retried rather than fatal. A machine that starts before
//! trustd or the network converges correctly a few seconds later; one that
//! gave up would need a restart nobody would think to perform.

use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr, UdpSocket};
use std::os::fd::{AsRawFd, RawFd};
use std::os::unix::net::{UnixDatagram, UnixListener, UnixStream};
use std::sync::Arc;
use std::time::{Duration, Instant};

use libtimed::{Auth, Origin, Reply, Request, SourceInfo, SourceState, Sync};
use ntp::{NtpTimestamp, ReferenceId, MAX_PACKET};
use rustls::ClientConfig;

use timed::clock::{Clock, Leap, Steering};
use timed::config::{self, Config, ServerSpec};
use timed::control::{self, ControlObject};
use timed::discipline::{Adjustment, Discipline, State};
use timed::filter::FilterOutcome;
use timed::netd_link::NetdLink;
use timed::select::{self, Candidate, NoSelection};
use timed::source::{Rejected, Security, Source, BURST};
use timed::state;
use timed::worker::{Done, Job, Worker};
use timed::{log, resolve};

/// How often the learned frequency is written back, in seconds. Often
/// enough that an unclean shutdown loses little, rarely enough that the
/// file is not a source of wear.
const DRIFT_INTERVAL: f64 = 3600.0;

/// How long to wait before retrying a failed startup step.
const RETRY_INTERVAL: f64 = 15.0;

/// How long a set of cookies is used before a fresh handshake is made
/// anyway. Cookies do not expire on a schedule the client can see, so this
/// is a "do not let the keys get arbitrarily old" bound rather than a
/// protocol requirement.
const REKEY_INTERVAL: f64 = 24.0 * 3600.0;

fn main() {
    // A daemon that dies on SIGPIPE because a subscriber closed a socket is
    // a daemon that stops keeping the clock for everyone else.
    unsafe { libc::signal(libc::SIGPIPE, libc::SIG_IGN) };

    let clock = Clock;
    match clock.enforce_floor() {
        Ok(0.0) => {}
        Ok(by) => log::warn(format_args!(
            "the clock read before this build's timestamp; raised it by {by:.0}s so that TLS \
             can work — the real time is not known yet"
        )),
        Err(e) => log::error(format_args!("could not raise the clock to the build floor: {e}")),
    }

    let listener = match control::listen() {
        Ok(l) => l,
        Err(e) => {
            log::error(format_args!("cannot listen on the control socket: {e}"));
            std::process::exit(1);
        }
    };

    let mut timed = Timed::new(clock, listener);
    timed.run();
}

/// One polled server, plus everything timed knows about it beyond the
/// protocol state that [`Source`] holds.
struct Entry {
    source: Source,
    spec: ServerSpec,
    origin: Origin,
    /// Addresses the name resolved to, tried in turn.
    addresses: Vec<SocketAddr>,
    /// The canonical name, for the certificate.
    canonical: String,
    /// Monotonic time after which the source needs a fresh handshake.
    rekey_after: f64,
    /// Monotonic time of the next attempt at whatever it needs next.
    retry_after: f64,
    /// A job is with the worker for this source. Exactly one at a time:
    /// that bounds the work without needing a pool, and means a slow
    /// server delays only its own source.
    in_flight: bool,
    /// Where it stood in the last selection.
    state: SourceState,
    /// This source produced a measurement the discipline has not seen.
    /// Distinct from "we heard from it": a reply that did not beat what
    /// the filter already held refreshes the dispersion but must not be
    /// fed to the loop a second time.
    fresh: bool,
}

struct Timed {
    clock: Clock,
    config: Config,
    control: ControlObject,
    discipline: Discipline,
    entries: Vec<Entry>,
    v4: Option<UdpSocket>,
    v6: Option<UdpSocket>,
    tls: Option<Arc<ClientConfig>>,
    listener: UnixListener,
    subscribers: Vec<UnixStream>,
    netd: NetdLink,
    worker: Worker,
    registry_watch: Option<peios::registry::Key>,
    /// Set by `wait` when the watch descriptor became readable.
    registry_readable: bool,
    /// Time servers the current leases offered.
    dhcp_servers: Vec<String>,
    /// Address families this machine has a usable address in, from netd.
    /// `None` until netd has been heard from, meaning "try anything".
    families: Option<Families>,
    generation: u64,
    precision: i8,
    /// What the machine currently reports about itself.
    stratum: u8,
    reference_id: ReferenceId,
    reference_time: f64,
    root_delay: f64,
    root_dispersion: f64,
    leap: Leap,
    system_peer: Option<usize>,
    offset: f64,
    jitter: f64,
    updates: u64,
    last_update: Option<f64>,
    last_drift_write: f64,
    /// Monotonic time to next attempt the roots.
    roots_after: f64,
    started: Instant,
}

impl Timed {
    fn new(clock: Clock, listener: UnixListener) -> Timed {
        let config = config::load();
        let precision = clock.precision();
        let drift = state::read_drift();
        if let Some(f) = drift {
            log::info(format_args!(
                "starting from a remembered frequency of {:+.3} ppm",
                f * 1e6
            ));
        }
        if !state::state_available() {
            log::warn(format_args!(
                "{} is missing; the frequency and NTS cookies will not survive a reboot",
                libtimed::STATE_DIR
            ));
        }

        let now = Instant::now();
        Timed {
            clock,
            control: ControlObject::new(config.control_security.as_deref()),
            discipline: Discipline::new(drift.unwrap_or(0.0)),
            entries: Vec::new(),
            v4: bind("0.0.0.0:0"),
            v6: bind("[::]:0"),
            tls: None,
            listener,
            subscribers: Vec::new(),
            netd: NetdLink::new(now),
            worker: Worker::spawn(),
            registry_watch: config::watch().ok(),
            registry_readable: false,
            dhcp_servers: Vec::new(),
            families: None,
            generation: 0,
            precision,
            stratum: 16,
            reference_id: ReferenceId(*b"INIT"),
            reference_time: 0.0,
            root_delay: 0.0,
            root_dispersion: 0.0,
            leap: Leap::None,
            system_peer: None,
            offset: 0.0,
            jitter: 0.0,
            updates: 0,
            last_update: None,
            last_drift_write: 0.0,
            roots_after: 0.0,
            config,
            started: now,
        }
    }

    fn monotonic(&self) -> f64 {
        self.clock.monotonic()
    }

    fn run(&mut self) {
        log::info(format_args!(
            "timed starting; clock precision 2^{}, floor {}",
            self.precision,
            timed::clock::BUILD_EPOCH
        ));
        self.rebuild_sources();

        // Ready means "the socket is listening", not "the clock is right".
        //
        // Those are different events and only the first is a startup
        // condition. Waiting for the second would hold the boot for the
        // length of an NTS handshake and a poll on every start — and would
        // never complete at all on a machine with no network, which is
        // precisely a machine that still needs to finish booting. Whether
        // the clock is trustworthy is a question for `clock status`, and
        // will be a readiness level of its own when PEI-500 lands.
        notify_ready();

        loop {
            let now = self.monotonic();
            self.netd.maintain(Instant::now());
            self.absorb_netd();
            self.check_registry();
            self.collect_work();
            self.ensure_roots(now);
            self.maintain_sources(now);
            self.poll_due(now);
            self.expire_pending(now);
            self.persist(now);

            let timeout = self.next_deadline(now);
            self.wait(timeout);
            self.service_sockets();
            self.service_control();
        }
    }

    // -----------------------------------------------------------------
    // Configuration and sources
    // -----------------------------------------------------------------

    /// Work out the source list from the precedence order and build it.
    fn rebuild_sources(&mut self) {
        let specs = self.chosen_specs();
        let origin = self.chosen_origin();

        // Keep whatever is still configured, so a reload does not throw
        // away a working NTS session and a filled filter for a source that
        // has not changed. Restarting every source on every registry write
        // would make a `reg set` cost the machine several minutes of
        // accuracy.
        let mut kept: HashMap<String, Entry> = HashMap::new();
        for entry in self.entries.drain(..) {
            kept.insert(entry.spec.host.clone(), entry);
        }

        for spec in specs {
            if spec.unauthenticated && !self.config.allow_unauthenticated {
                log::warn(format_args!(
                    "{}: marked unauthenticated but AllowUnauthenticated is 0; not used",
                    spec.host
                ));
                continue;
            }
            if let Some(mut entry) = kept.remove(&spec.host) {
                entry.spec = spec;
                entry.origin = origin;
                self.entries.push(entry);
                continue;
            }
            let security =
                if spec.unauthenticated { Security::Unauthenticated } else { Security::NtsPending };
            let source = Source::new(
                spec.host.clone(),
                // A placeholder until the name resolves; nothing is sent
                // to it, because `addresses` being empty is what gates
                // polling.
                SocketAddr::from(([0, 0, 0, 0], 123)),
                security,
                self.config.min_poll,
                self.config.max_poll,
            );
            self.entries.push(Entry {
                canonical: spec.host.clone(),
                source,
                spec,
                origin,
                addresses: Vec::new(),
                rekey_after: 0.0,
                retry_after: 0.0,
                in_flight: false,
                state: SourceState::Unreachable,
                fresh: false,
            });
        }

        for (host, _) in kept {
            log::info(format_args!("{host}: no longer configured"));
        }
        log::info(format_args!(
            "{} source(s) from {}",
            self.entries.len(),
            origin.as_str()
        ));
    }

    /// The precedence order, resolved to one list.
    ///
    /// First match wins outright rather than merging: a machine told
    /// exactly which servers to use must not also be quietly talking to
    /// somebody else's.
    fn chosen_specs(&self) -> Vec<ServerSpec> {
        if self.config.has_explicit_servers() {
            return self.config.servers.clone();
        }
        if self.config.use_from_dhcp && !self.dhcp_servers.is_empty() {
            return self
                .dhcp_servers
                .iter()
                .map(|host| ServerSpec {
                    host: host.clone(),
                    port: None,
                    prefer: false,
                    // A DHCP server is not going to be running NTS-KE, and
                    // if the operator has turned this on they have said
                    // they trust this network.
                    unauthenticated: true,
                })
                .collect();
        }
        Config::fallback()
    }

    fn chosen_origin(&self) -> Origin {
        if self.config.has_explicit_servers() {
            Origin::Registry
        } else if self.config.use_from_dhcp && !self.dhcp_servers.is_empty() {
            Origin::Dhcp
        } else {
            Origin::Fallback
        }
    }

    /// Read the registry watch, but only when `wait` saw it become
    /// readable — the descriptor is non-blocking and reading it
    /// speculatively every turn would be a syscall per loop for nothing.
    fn check_registry(&mut self) {
        if !std::mem::take(&mut self.registry_readable) {
            return;
        }
        let Some(watch) = &self.registry_watch else { return };
        let mut buffer = vec![0u8; 16384];
        // The watch reports *which* values changed; timed does not care,
        // because reading the whole subtree again is cheap and reasoning
        // about partial reloads is not.
        match watch.read_watch_events(&mut buffer) {
            Ok(events) if events.is_empty() => return,
            Ok(_) => {}
            Err(e) => {
                log::warn(format_args!("registry watch: {e}; re-arming"));
                self.registry_watch = config::watch().ok();
                return;
            }
        }
        log::info(format_args!("the registry changed; re-reading configuration"));
        self.reload();
    }

    fn reload(&mut self) {
        self.config = config::load();
        self.control = ControlObject::new(self.config.control_security.as_deref());
        self.registry_watch = config::watch().ok();
        self.rebuild_sources();
    }

    fn absorb_netd(&mut self) {
        let snapshots = self.netd.service(Instant::now());
        let Some(latest) = snapshots.into_iter().next_back() else { return };

        // Which families this machine can actually reach. A name commonly
        // resolves to both an A and an AAAA, and connecting to the AAAA on
        // a network with no IPv6 fails — quickly, but four sources times
        // several addresses times a handshake each is minutes of a boot
        // spent on connections that were never going to work. netd already
        // tells us what addresses the interfaces carry, so use it.
        let mut families = Families { v4: false, v6: false };
        for scope in &latest.scopes {
            for address in &scope.addresses {
                let text = address.split('/').next().unwrap_or(address);
                match text.parse::<IpAddr>() {
                    Ok(IpAddr::V4(a)) if !a.is_loopback() && !a.is_link_local() => {
                        families.v4 = true
                    }
                    // A link-local IPv6 address is not connectivity: every
                    // interface has one whether or not anything is
                    // reachable through it.
                    Ok(IpAddr::V6(a)) if !a.is_loopback() && !is_link_local_v6(a) => {
                        families.v6 = true
                    }
                    _ => {}
                }
            }
        }
        let changed = self.families != Some(families);
        self.families = Some(families);
        if changed {
            log::info(format_args!(
                "usable address families: {}{}{}",
                if families.v4 { "IPv4 " } else { "" },
                if families.v6 { "IPv6" } else { "" },
                if !families.v4 && !families.v6 { "none yet" } else { "" }
            ));
            // Addresses already chosen may be in a family that just went
            // away, or a family that just arrived may be better.
            let now = self.monotonic();
            for entry in self.entries.iter_mut() {
                entry.addresses.clear();
                entry.retry_after = now;
            }
        }

        let mut servers: Vec<String> = Vec::new();
        for scope in &latest.scopes {
            for s in &scope.ntp {
                if !servers.contains(s) {
                    servers.push(s.clone());
                }
            }
        }
        if servers == self.dhcp_servers {
            return;
        }
        self.dhcp_servers = servers;
        if self.config.use_from_dhcp && !self.config.has_explicit_servers() {
            self.rebuild_sources();
        }
    }

    // -----------------------------------------------------------------
    // Getting a source ready to poll
    // -----------------------------------------------------------------

    fn ensure_roots(&mut self, now: f64) {
        if self.tls.is_some() || now < self.roots_after {
            return;
        }
        // Only needed if some source actually wants NTS.
        if self.entries.iter().all(|e| !e.source.security.is_nts()) {
            return;
        }
        self.roots_after = now + RETRY_INTERVAL;
        self.worker.submit(Job::Roots);
    }

    /// Resolve names and run handshakes for anything that needs one.
    fn maintain_sources(&mut self, now: f64) {
        for index in 0..self.entries.len() {
            if self.entries[index].in_flight || now < self.entries[index].retry_after {
                continue;
            }
            if self.entries[index].addresses.is_empty() {
                let entry = &mut self.entries[index];
                entry.in_flight = true;
                let job = Job::Resolve {
                    index,
                    host: entry.spec.host.clone(),
                    port: entry.spec.port.unwrap_or(ntp::nts::DEFAULT_NTP_PORT),
                };
                self.worker.submit(job);
                continue;
            }
            let needs_keys = matches!(self.entries[index].source.security, Security::NtsPending)
                || (self.entries[index].source.security.is_nts()
                    && now > self.entries[index].rekey_after);
            if !needs_keys {
                continue;
            }
            let Some(tls) = self.tls.clone() else {
                self.entries[index].retry_after = now + RETRY_INTERVAL;
                continue;
            };
            let entry = &mut self.entries[index];
            // The KE port is not the NTP port the addresses carry.
            let ke_port = entry.spec.port.unwrap_or(ntp::nts::DEFAULT_KE_PORT);
            let job = Job::Handshake {
                index,
                host: entry.spec.host.clone(),
                canonical: entry.canonical.clone(),
                ke_addresses: entry
                    .addresses
                    .iter()
                    .map(|a| SocketAddr::new(a.ip(), ke_port))
                    .collect(),
                tls,
            };
            entry.in_flight = true;
            self.worker.submit(job);
        }
    }

    /// Take whatever the worker finished, without ever waiting for it.
    fn collect_work(&mut self) {
        let now = self.monotonic();
        for done in self.worker.collect() {
            match done {
                Done::Roots(Ok(config)) => {
                    log::info(format_args!("loaded the machine's root store for NTS-KE"));
                    self.tls = Some(config);
                }
                Done::Roots(Err(e)) => {
                    log::warn(format_args!("no root store yet ({e}); retrying"))
                }
                Done::Resolved { index, result } => {
                    if index >= self.entries.len() {
                        continue;
                    }
                    self.entries[index].in_flight = false;
                    match result {
                        Ok(resolved) => {
                            let port =
                                self.entries[index].spec.port.unwrap_or(ntp::nts::DEFAULT_NTP_PORT);
                            let addresses =
                                self.reachable(resolve::socket_addrs(&resolved, port));
                            if addresses.is_empty() {
                                self.entries[index].source.note = Some(
                                    "no address in a family this machine can reach".into(),
                                );
                                self.entries[index].retry_after = now + RETRY_INTERVAL;
                                continue;
                            }
                            log::info(format_args!(
                                "{} is {} at {}",
                                self.entries[index].spec.host,
                                resolved.canonical,
                                addresses[0].ip()
                            ));
                            let entry = &mut self.entries[index];
                            entry.source.address = addresses[0];
                            entry.addresses = addresses;
                            entry.canonical = resolved.canonical;
                            entry.retry_after = 0.0;
                        }
                        Err(e) => {
                            self.entries[index].source.note = Some(format!("cannot resolve: {e}"));
                            self.entries[index].retry_after = now + RETRY_INTERVAL;
                        }
                    }
                }
                Done::Handshook { index, result } => {
                    if index >= self.entries.len() {
                        continue;
                    }
                    self.entries[index].in_flight = false;
                    match result {
                        Ok((established, addresses)) => {
                            let addresses = self.reachable(addresses);
                            if addresses.is_empty() {
                                self.entries[index].retry_after = now + RETRY_INTERVAL;
                                continue;
                            }
                            let cookies = established.negotiated.cookies.clone();
                            log::info(format_args!(
                                "{}: NTS-KE with {} succeeded; {} cookie(s), NTP at {}",
                                self.entries[index].spec.host,
                                self.entries[index].canonical,
                                cookies.len(),
                                addresses[0]
                            ));
                            let _ = state::write_cookies(&self.entries[index].spec.host, &cookies);
                            let entry = &mut self.entries[index];
                            entry.source.security =
                                Security::Nts { keys: established.keys.clone(), cookies };
                            entry.source.address = addresses[0];
                            entry.addresses = addresses;
                            entry.rekey_after = now + REKEY_INTERVAL;
                            entry.retry_after = 0.0;
                            entry.source.note = None;
                            entry.source.next_poll = now;
                        }
                        Err(why) => {
                            // A source that already has keys and merely
                            // failed to renew keeps working on the cookies
                            // it holds: a rekey is housekeeping, and
                            // failing it should not cost a source.
                            if matches!(
                                self.entries[index].source.security,
                                Security::NtsPending
                            ) {
                                log::warn(format_args!(
                                    "{}: NTS-KE failed ({why})",
                                    self.entries[index].spec.host
                                ));
                                self.entries[index].source.note =
                                    Some(format!("NTS-KE failed: {why}"));
                            }
                            self.entries[index].retry_after = now + RETRY_INTERVAL;
                            self.entries[index].rekey_after = now + RETRY_INTERVAL;
                        }
                    }
                }
            }
        }
    }

    // -----------------------------------------------------------------
    // Polling
    // -----------------------------------------------------------------

    fn poll_due(&mut self, now: f64) {
        for index in 0..self.entries.len() {
            let entry = &self.entries[index];
            if entry.addresses.is_empty()
                || !entry.source.can_poll()
                || entry.source.pending.is_some()
                || now < entry.source.next_poll
            {
                continue;
            }
            self.send_poll(index, now);
        }
    }

    fn send_poll(&mut self, index: usize, now: f64) {
        let (seconds, nanos) = self.clock.now();
        let wall = NtpTimestamp::from_unix(seconds, nanos);
        let address = self.entries[index].source.address;
        let bytes = match self.entries[index].source.prepare(wall, now) {
            Ok(b) => b,
            Err(e) => {
                log::warn(format_args!("{}: cannot build a request: {e}", self.entries[index].spec.host));
                self.entries[index].source.schedule(now);
                return;
            }
        };
        let socket = match address.ip() {
            IpAddr::V4(_) => self.v4.as_ref(),
            IpAddr::V6(_) => self.v6.as_ref(),
        };
        let Some(socket) = socket else {
            self.entries[index].source.note = Some("no socket for that address family".into());
            self.entries[index].source.schedule(now);
            return;
        };
        if let Err(e) = socket.send_to(&bytes, address) {
            self.entries[index].source.note = Some(format!("cannot send: {e}"));
            self.entries[index].source.pending = None;
            self.rotate_address(index);
            self.entries[index].source.schedule(now);
        }
    }

    /// Move to the next address this name resolved to.
    ///
    /// A name usually resolves to several, and the first one is not
    /// necessarily reachable — a host may be behind a route that is down,
    /// or in an address family that stopped working since it was chosen.
    /// Without this a source picks one address at startup and is pinned to
    /// it for the life of the process.
    fn rotate_address(&mut self, index: usize) {
        let entry = &mut self.entries[index];
        if entry.addresses.len() < 2 {
            return;
        }
        let current = entry.source.address;
        let position = entry.addresses.iter().position(|a| *a == current).unwrap_or(0);
        let next = entry.addresses[(position + 1) % entry.addresses.len()];
        entry.source.address = next;
        log::info(format_args!("{}: trying {next} instead", entry.spec.host));
    }

    /// Keep only the addresses this machine has any prospect of reaching.
    ///
    /// Before netd has been heard from, everything is kept: a wrong guess
    /// costs one failed connection, and refusing to try anything until the
    /// network has been described would be worse.
    fn reachable(&self, addresses: Vec<SocketAddr>) -> Vec<SocketAddr> {
        let Some(families) = self.families else { return addresses };
        if !families.v4 && !families.v6 {
            return addresses;
        }
        addresses
            .into_iter()
            .filter(|a| match a.ip() {
                IpAddr::V4(_) => families.v4,
                IpAddr::V6(_) => families.v6,
            })
            .collect()
    }

    fn expire_pending(&mut self, now: f64) {
        for index in 0..self.entries.len() {
            if !self.entries[index].source.timed_out(now) {
                continue;
            }
            let host = self.entries[index].spec.host.clone();
            self.entries[index].source.record_loss(now);
            if self.entries[index].source.reach == 0 {
                log::warn(format_args!("{host}: no reply for eight polls"));
                // A source that has gone entirely silent may have moved,
                // or the address chosen for it may be the unreachable one
                // of several the name resolves to.
                self.rotate_address(index);
                self.entries[index].addresses.clear();
                self.entries[index].retry_after = now;
            }
        }
    }

    fn service_sockets(&mut self) {
        let now = self.monotonic();
        let (seconds, nanos) = self.clock.now();
        let destination = NtpTimestamp::from_unix(seconds, nanos);
        let mut updated = false;
        // Both families, drained fully: a burst of replies must not leave
        // one waiting until the next poll(2) wakes us.
        for family in 0..2 {
            loop {
                let socket = if family == 0 { self.v4.as_ref() } else { self.v6.as_ref() };
                let Some(socket) = socket else { break };
                let mut buffer = [0u8; MAX_PACKET];
                let (n, from) = match socket.recv_from(&mut buffer) {
                    Ok(v) => v,
                    Err(_) => break,
                };
                if self.take_reply(&buffer[..n], from, destination, now) {
                    updated = true;
                }
            }
        }
        if updated {
            self.decide(now);
        }
    }

    /// Match a datagram to a source and take it, returning whether the
    /// filter produced anything new.
    fn take_reply(
        &mut self,
        bytes: &[u8],
        from: SocketAddr,
        destination: NtpTimestamp,
        now: f64,
    ) -> bool {
        // The address check comes first and is a property of the socket
        // rather than of the bytes — matching on anything inside the packet
        // would mean parsing a stranger's datagram before deciding it was
        // ours to parse.
        let Some(index) = self.entries.iter().position(|e| e.source.address == from) else {
            return false;
        };
        let host = self.entries[index].spec.host.clone();
        let wall = self.clock.now_f64();

        match self.entries[index].source.accept(bytes, destination, now) {
            Ok(sample) => {
                let outcome = self.entries[index].source.filter.insert(sample, wall);
                self.entries[index].source.schedule_burst(now);
                if self.entries[index].source.burst == 0 {
                    self.entries[index].source.schedule(now);
                }
                // Any accepted reply is worth re-running selection on, even
                // when the filter's best sample did not change. A source's
                // *dispersion* falls as the register fills, and a source
                // becomes fit by that alone — so gating selection on a
                // fresh best sample left the first measurement's enormous
                // dispersion in place for ever and the source permanently
                // unusable. Whether the discipline is fed is the separate
                // question `Update` answers.
                self.entries[index].fresh = matches!(outcome, FilterOutcome::Update(_));
                true
            }
            Err(Rejected::Kiss(code)) if code == ReferenceId::RATE => {
                log::warn(format_args!("{host}: asked us to slow down; backing off"));
                self.entries[index].source.back_off(now);
                false
            }
            Err(Rejected::Kiss(code)) if code == ReferenceId::NTSN => {
                // Our cookie was refused: the server has rotated its keys,
                // or restarted. A fresh handshake is the documented cure.
                log::warn(format_args!("{host}: rejected our NTS cookie; re-keying"));
                state::forget_cookies(&host);
                self.entries[index].source.security = Security::NtsPending;
                self.entries[index].rekey_after = 0.0;
                self.entries[index].retry_after = 0.0;
                false
            }
            Err(Rejected::Kiss(code)) => {
                log::warn(format_args!("{host}: {code}; not polling it again"));
                self.entries[index].source.note = Some(format!("refused by the server ({code})"));
                self.entries[index].source.poll = self.entries[index].source.max_poll;
                self.entries[index].source.schedule(now);
                false
            }
            Err(reason) => {
                // Every rejection is counted and none is acted on. A forged
                // reply must cost an attacker a log line and nothing else —
                // in particular it must not mark the source unreachable,
                // which would be a way to silence a good server.
                if !matches!(reason, Rejected::WrongOrigin) {
                    log::warn(format_args!("{host}: {reason}"));
                    self.entries[index].source.note = Some(reason.to_string());
                }
                false
            }
        }
    }

    // -----------------------------------------------------------------
    // Deciding and steering
    // -----------------------------------------------------------------

    fn decide(&mut self, now: f64) {
        let wall = self.clock.now_f64();
        let candidates: Vec<Candidate> = self
            .entries
            .iter()
            .enumerate()
            .filter_map(|(id, e)| {
                let filtered = e.source.filtered(wall)?;
                Some(Candidate {
                    id,
                    filtered,
                    stratum: e.source.stratum,
                    root_delay: e.source.root_delay,
                    root_dispersion: e.source.root_dispersion,
                    usable: e.source.is_reachable() && e.source.stratum < 16,
                    prefer: e.spec.prefer,
                })
            })
            .collect();

        for entry in self.entries.iter_mut() {
            entry.state = if !entry.source.is_reachable() {
                SourceState::Unreachable
            } else {
                SourceState::Unusable
            };
        }

        let selection = match select::select(&candidates, wall) {
            Ok(s) => s,
            Err(NoSelection::NoCandidates) => return,
            Err(NoSelection::NoMajority) => {
                // The state worth alarming on: sources are answering and
                // telling different stories. Better unsynchronised than
                // synchronised to whichever one we picked.
                log::warn(format_args!(
                    "no majority among {} source(s); the clock is not being steered",
                    candidates.len()
                ));
                for entry in self.entries.iter_mut() {
                    if entry.source.is_reachable() {
                        entry.state = SourceState::Falseticker;
                    }
                }
                self.publish();
                return;
            }
        };

        for &id in &selection.falsetickers {
            self.entries[id].state = SourceState::Falseticker;
            log::warn(format_args!(
                "{}: disagrees with the majority; not used",
                self.entries[id].spec.host
            ));
        }
        for &id in &selection.survivors {
            self.entries[id].state = SourceState::Candidate;
        }
        // A fit candidate that survived the intersection but was clustered
        // out is an outlier, which is a different thing from a falseticker
        // and worth saying so.
        for c in &candidates {
            if !selection.survivors.contains(&c.id) && !selection.falsetickers.contains(&c.id) {
                self.entries[c.id].state = SourceState::Outlier;
            }
        }
        self.entries[selection.system_peer].state = SourceState::SystemPeer;

        let peer = &self.entries[selection.system_peer];
        self.stratum = peer.source.stratum.saturating_add(1);
        self.reference_id = peer.source.reference_id;
        self.leap = peer.source.announced_leap();
        let peer_filtered = peer.source.filtered(wall);
        self.root_delay = peer.source.root_delay + peer_filtered.map_or(0.0, |f| f.delay);
        self.root_dispersion = peer.source.root_dispersion
            + peer_filtered.map_or(0.0, |f| f.dispersion)
            + selection.jitter;
        self.system_peer = Some(selection.system_peer);
        self.offset = selection.offset;
        self.jitter = selection.jitter;

        // Only steer on a measurement the loop has not already seen.
        // Selection itself runs on every reply, because fitness changes as
        // dispersion falls; feeding the same offset in twice would make
        // the loop believe it has more information than it does.
        let fresh = self.entries.iter().any(|e| e.fresh);
        for entry in self.entries.iter_mut() {
            entry.fresh = false;
        }
        if fresh {
            self.apply(selection.offset, now, wall);
        }

        for entry in self.entries.iter_mut() {
            entry.source.adapt_poll(selection.offset, selection.jitter.max(1e-9));
        }

        if fresh {
            self.updates += 1;
            self.last_update = Some(now);
        }
        self.generation += 1;
        self.publish();
    }

    fn apply(&mut self, offset: f64, now: f64, wall: f64) {
        match self.discipline.update(offset, now) {
            Adjustment::Rate(rate) => {
                self.reference_time = wall;
                self.steer(rate);
            }
            Adjustment::Step { seconds, rate } => {
                match self.clock.step(seconds) {
                    Ok(()) => {
                        log::info(format_args!("stepped the clock by {seconds:+.6}s"));
                        // Every measurement in every filter was taken
                        // against a clock that no longer exists.
                        for entry in self.entries.iter_mut() {
                            entry.source.filter.reset();
                        }
                        self.discipline.reset_phase();
                    }
                    Err(e) => log::error(format_args!("could not step the clock: {e}")),
                }
                self.reference_time = self.clock.now_f64();
                self.steer(rate);
            }
            Adjustment::Hold => {}
            Adjustment::Panic { seconds } => {
                log::error(format_args!(
                    "the sources say the clock is {seconds:+.0}s out, which is past the panic \
                     threshold. Not obeying: a machine this far off after having been \
                     synchronised has a problem that a time client must not paper over. \
                     Restart timed to accept it as a startup step."
                ));
            }
        }
    }

    fn steer(&mut self, rate: f64) {
        let steering = Steering {
            frequency: rate,
            max_error: self.root_distance(),
            est_error: self.jitter,
            synchronised: self.discipline.is_synchronised(),
            leap: self.leap,
        };
        if let Err(e) = self.clock.steer(steering) {
            log::error(format_args!("could not steer the clock: {e}"));
        }
    }

    fn root_distance(&self) -> f64 {
        self.root_delay / 2.0 + self.root_dispersion
    }

    fn persist(&mut self, now: f64) {
        if now - self.last_drift_write < DRIFT_INTERVAL || self.discipline.updates() < 4 {
            return;
        }
        self.last_drift_write = now;
        if let Err(e) = state::write_drift(self.discipline.frequency()) {
            log::warn(format_args!("could not write the drift file: {e}"));
        }
        for entry in &self.entries {
            if let Security::Nts { cookies, .. } = &entry.source.security {
                let _ = state::write_cookies(&entry.spec.host, cookies);
            }
        }
    }

    // -----------------------------------------------------------------
    // The socket
    // -----------------------------------------------------------------

    fn sync_state(&self) -> Sync {
        match self.discipline.state() {
            _ if self.system_peer.is_none() => Sync::Unsynchronised,
            State::Startup => Sync::Unsynchronised,
            State::Settling => Sync::Settling,
            State::Synchronised => Sync::Synchronised,
            State::Spike => Sync::Spike,
        }
    }

    fn status(&self) -> libtimed::Status {
        let now = self.monotonic();
        libtimed::Status {
            generation: self.generation,
            sync: self.sync_state(),
            system_peer: self.system_peer.map(|i| self.entries[i].spec.host.clone()),
            stratum: if self.system_peer.is_some() { self.stratum as u32 } else { 16 },
            offset: self.offset,
            frequency_ppm: self.discipline.frequency_ppm(),
            jitter: self.jitter,
            root_distance: self.root_distance(),
            root_delay: self.root_delay,
            root_dispersion: self.root_dispersion,
            leap: match self.leap {
                Leap::None => 0,
                Leap::Insert => 1,
                Leap::Delete => -1,
            },
            stepped: self.discipline.stepped(),
            updates: self.updates,
            last_update: self.last_update.map_or(-1.0, |t| now - t),
            sources: self.entries.len() as u32,
            selected: self
                .entries
                .iter()
                .filter(|e| {
                    matches!(e.state, SourceState::Candidate | SourceState::SystemPeer)
                })
                .count() as u32,
            floor: timed::clock::BUILD_EPOCH,
        }
    }

    fn sources(&self) -> Vec<SourceInfo> {
        let now = self.monotonic();
        let wall = self.clock.now_f64();
        self.entries
            .iter()
            .map(|e| {
                let filtered = e.source.filtered(wall);
                SourceInfo {
                    name: e.spec.host.clone(),
                    address: if e.addresses.is_empty() {
                        String::new()
                    } else {
                        e.source.address.to_string()
                    },
                    origin: e.origin,
                    auth: if e.source.security.is_nts() { Auth::Nts } else { Auth::None },
                    state: e.state,
                    stratum: e.source.stratum as u32,
                    reference: e.source.reference_id.to_string(),
                    reach: e.source.reach as u32,
                    poll: e.source.poll as i32,
                    last: e.source.last_reply.map_or(-1.0, |t| now - t),
                    offset: filtered.map_or(0.0, |f| f.offset),
                    delay: filtered.map_or(0.0, |f| f.delay),
                    jitter: filtered.map_or(0.0, |f| f.jitter),
                    root_distance: filtered.map_or(0.0, |f| {
                        timed::filter::root_distance(
                            &f,
                            e.source.root_delay,
                            e.source.root_dispersion,
                            wall,
                        )
                    }),
                    cookies: e.source.security.cookies() as u32,
                    note: e.source.note.clone(),
                }
            })
            .collect()
    }

    fn snapshot(&self) -> libtimed::Snapshot {
        let synchronised = self.discipline.is_synchronised() && self.system_peer.is_some();
        libtimed::Snapshot {
            generation: self.generation,
            leap: match self.leap {
                Leap::None => 0,
                Leap::Insert => 1,
                Leap::Delete => 2,
            },
            // Sixteen when not synchronised, which is how the future server
            // refuses to serve without needing a second mechanism.
            stratum: if synchronised { self.stratum as u32 } else { 16 },
            reference_id: self.reference_id.0.to_vec(),
            reference_time: self.reference_time,
            root_delay: self.root_delay,
            root_dispersion: self.root_dispersion,
            precision: self.precision as i32,
            at: self.clock.now_f64(),
            synchronised,
        }
    }

    fn publish(&mut self) {
        if self.subscribers.is_empty() {
            return;
        }
        let bytes = Reply::Snapshot(self.snapshot()).encode();
        self.subscribers.retain_mut(|s| control::send_nonblocking(s, &bytes));
    }

    fn service_control(&mut self) {
        loop {
            let Ok((mut stream, _)) = self.listener.accept() else { break };
            if self.subscribers.len() >= control::MAX_CLIENTS {
                let _ = control::write_reply(&mut stream, &Reply::Error("too many clients".into()));
                continue;
            }
            let request = match control::read_request(&mut stream) {
                Ok(r) => r,
                Err(e) => {
                    let _ = control::write_reply(&mut stream, &Reply::Error(e));
                    continue;
                }
            };
            if !self.control.permits(&stream, request.required_right()) {
                let _ = control::write_reply(&mut stream, &Reply::Error("not permitted".into()));
                continue;
            }
            match request {
                Request::Status => {
                    let _ = control::write_reply(&mut stream, &Reply::Status(self.status()));
                }
                Request::Sources => {
                    let all = self.sources();
                    let chunks: Vec<&[SourceInfo]> =
                        all.chunks(libtimed::SOURCES_PER_CHUNK).collect();
                    if chunks.is_empty() {
                        let _ = control::write_reply(
                            &mut stream,
                            &Reply::Sources { sources: Vec::new(), more: false },
                        );
                    }
                    for (i, chunk) in chunks.iter().enumerate() {
                        let reply = Reply::Sources {
                            sources: chunk.to_vec(),
                            more: i + 1 < chunks.len(),
                        };
                        if control::write_reply(&mut stream, &reply).is_err() {
                            break;
                        }
                    }
                }
                Request::Subscribe => {
                    let bytes = Reply::Snapshot(self.snapshot()).encode();
                    if control::send_nonblocking(&mut stream, &bytes) {
                        self.subscribers.push(stream);
                    }
                }
                Request::Reload => {
                    let _ = control::write_reply(&mut stream, &Reply::Ok);
                    self.reload();
                    let now = self.monotonic();
                    for entry in self.entries.iter_mut() {
                        entry.addresses.clear();
                        entry.retry_after = 0.0;
                        entry.source.burst = BURST;
                        entry.source.next_poll = now;
                    }
                }
            }
        }
    }

    // -----------------------------------------------------------------
    // Waiting
    // -----------------------------------------------------------------

    fn next_deadline(&self, now: f64) -> Duration {
        let mut soonest = now + 60.0;
        for entry in &self.entries {
            if entry.addresses.is_empty() || !entry.source.can_poll() {
                soonest = soonest.min(entry.retry_after.max(now));
            } else if entry.source.pending.is_none() {
                soonest = soonest.min(entry.source.next_poll);
            }
        }
        if self.tls.is_none() {
            soonest = soonest.min(self.roots_after.max(now));
        }
        // A floor, so a source whose deadline has passed cannot spin the
        // loop; and a ceiling, so the drift file is still written on a
        // machine with no sources at all.
        //
        // While the worker has a job out there is no descriptor to poll on
        // — a channel is not pollable — so the loop wakes in short hops
        // instead. A handshake takes seconds, so a quarter of a second
        // costs nothing and means the answer is acted on when it arrives
        // rather than up to a minute later.
        let ceiling = if self.worker.busy() { 0.25 } else { 60.0 };
        Duration::from_secs_f64((soonest - now).clamp(0.05, ceiling))
    }

    fn wait(&mut self, timeout: Duration) {
        let mut raw: Vec<RawFd> = Vec::new();
        if let Some(s) = &self.v4 {
            raw.push(s.as_raw_fd());
        }
        if let Some(s) = &self.v6 {
            raw.push(s.as_raw_fd());
        }
        raw.push(self.listener.as_raw_fd());
        if let Some(fd) = self.netd.fd() {
            raw.push(fd);
        }
        let watch_slot = self.registry_watch.as_ref().map(|w| {
            raw.push(w.as_raw_fd());
            raw.len() - 1
        });
        let mut fds: Vec<libc::pollfd> = raw
            .into_iter()
            .map(|fd| libc::pollfd { fd, events: libc::POLLIN, revents: 0 })
            .collect();
        let millis = (timeout.as_millis() as i32).max(1);
        // Safe: a slice we own, with a length that fits, and poll(2) writes
        // only into `revents`.
        unsafe {
            libc::poll(fds.as_mut_ptr(), fds.len() as libc::nfds_t, millis);
        }
        if let Some(slot) = watch_slot {
            self.registry_readable = fds[slot].revents != 0;
        }
        let _ = self.started;
    }
}

/// Which address families the machine has a usable address in.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Families {
    v4: bool,
    v6: bool,
}

/// `fe80::/10`. Not in stable std as a method on `Ipv6Addr`, and worth
/// getting right: every interface has a link-local address whether or not
/// anything at all is reachable over IPv6, so counting one as connectivity
/// would defeat the whole check.
fn is_link_local_v6(a: std::net::Ipv6Addr) -> bool {
    (a.segments()[0] & 0xffc0) == 0xfe80
}

/// Tell peinit the service has started.
///
/// The service definition declares `Readiness = Notify`, so peinit holds
/// the job in `starting` until this arrives and eventually times the start
/// out. Forgetting it produces a daemon that works perfectly and is
/// reported as hung, then killed and restarted for ever.
fn notify_ready() {
    let Ok(path) = std::env::var("NOTIFY_SOCKET") else { return };
    match UnixDatagram::unbound() {
        Ok(s) => {
            if let Err(e) = s.send_to(b"READY=1", &path) {
                log::warn(format_args!("readiness notify: {e}"));
            }
        }
        Err(e) => log::warn(format_args!("readiness notify: {e}")),
    }
}

fn bind(address: &str) -> Option<UdpSocket> {
    let socket = UdpSocket::bind(address).ok()?;
    socket.set_nonblocking(true).ok()?;
    Some(socket)
}
