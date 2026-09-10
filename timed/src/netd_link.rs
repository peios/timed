//! The channel from netd: a `subscribe` on its control socket.
//!
//! timed wants one thing from it — the time servers a DHCP lease offered,
//! option 42 — and one thing implicitly: knowing when the network changed,
//! which is when a source's address may have moved and a poll is worth
//! retrying rather than waiting out.
//!
//! Whether those DHCP servers are *used* is a separate question, decided by
//! `Machine\System\Time UseFromDHCP`, which is off by default. netd
//! reports what the network said; timed decides what to believe.
//!
//! The same client resolvd uses, because it is the same channel and the
//! reconnection behaviour is the part worth having identical: connect,
//! back off when netd is not there, hand snapshots up, never write anything
//! but the one request.

use std::io::{self, Read};
use std::os::fd::{AsRawFd, RawFd};
use std::os::unix::net::UnixStream;
use std::time::{Duration, Instant};

use libnetd::{CONTROL_SOCKET_PATH, MAX_MESSAGE_BYTES, Reply, Request, Snapshot};

use crate::log;

const MIN_BACKOFF: Duration = Duration::from_millis(500);
const MAX_BACKOFF: Duration = Duration::from_secs(10);

pub struct NetdLink {
    stream: Option<UnixStream>,
    buf: Vec<u8>,
    next_try: Instant,
    backoff: Duration,
    /// Whether the loss of the connection has been logged (once).
    warned: bool,
}

impl NetdLink {
    pub fn new(now: Instant) -> NetdLink {
        NetdLink {
            stream: None,
            buf: Vec::new(),
            next_try: now,
            backoff: MIN_BACKOFF,
            warned: false,
        }
    }

    pub fn connected(&self) -> bool {
        self.stream.is_some()
    }

    pub fn fd(&self) -> Option<RawFd> {
        self.stream.as_ref().map(|s| s.as_raw_fd())
    }

    pub fn next_deadline(&self) -> Option<Instant> {
        if self.stream.is_none() {
            Some(self.next_try)
        } else {
            None
        }
    }

    /// Connect if it is time to.
    pub fn maintain(&mut self, now: Instant) {
        if self.stream.is_some() || now < self.next_try {
            return;
        }
        match self.connect() {
            Ok(stream) => {
                log::info(format_args!("subscribed to netd"));
                self.stream = Some(stream);
                self.buf.clear();
                self.backoff = MIN_BACKOFF;
                self.warned = false;
            }
            Err(e) => {
                if !self.warned {
                    log::warn(format_args!("netd not reachable ({e}); retrying"));
                    self.warned = true;
                }
                self.next_try = now + self.backoff;
                self.backoff = (self.backoff * 2).min(MAX_BACKOFF);
            }
        }
    }

    fn connect(&self) -> io::Result<UnixStream> {
        let mut stream = UnixStream::connect(CONTROL_SOCKET_PATH)?;
        stream.set_write_timeout(Some(Duration::from_secs(2)))?;
        libnetd::send(&mut stream, &Request::Subscribe.encode())
            .map_err(|e| io::Error::other(e.to_string()))?;
        stream.set_nonblocking(true)?;
        Ok(stream)
    }

    /// Read what netd sent. Returns every complete snapshot; on EOF or
    /// error the connection is dropped and a reconnect scheduled.
    pub fn service(&mut self, now: Instant) -> Vec<Snapshot> {
        let Some(stream) = self.stream.as_mut() else {
            return Vec::new();
        };
        let mut chunk = [0u8; 8192];
        let mut lost = false;
        loop {
            match stream.read(&mut chunk) {
                Ok(0) => {
                    lost = true;
                    break;
                }
                Ok(n) => self.buf.extend_from_slice(&chunk[..n]),
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => break,
                Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
                Err(_) => {
                    lost = true;
                    break;
                }
            }
        }
        let mut out = Vec::new();
        loop {
            if self.buf.len() < 4 {
                break;
            }
            let len =
                u32::from_le_bytes([self.buf[0], self.buf[1], self.buf[2], self.buf[3]]) as usize;
            if len > MAX_MESSAGE_BYTES {
                lost = true;
                break;
            }
            if self.buf.len() < 4 + len {
                break;
            }
            let payload: Vec<u8> = self.buf.drain(..4 + len).skip(4).collect();
            match Reply::decode(&payload) {
                Ok(Reply::Snapshot(s)) => out.push(s),
                Ok(Reply::Error(e)) => {
                    log::warn(format_args!("netd refused the subscription: {e}"));
                    lost = true;
                }
                Ok(_) => {}
                Err(e) => {
                    log::warn(format_args!("netd sent something unreadable: {e}"));
                    lost = true;
                }
            }
        }
        if lost {
            log::warn(format_args!("lost the netd channel; reconnecting"));
            self.stream = None;
            self.buf.clear();
            self.next_try = now + MIN_BACKOFF;
            self.backoff = MIN_BACKOFF;
            self.warned = true;
        }
        out
    }
}
