//! Subscribe to netd snapshots for DHCP time sources and network changes.
//! Configuration decides whether DHCP sources are eligible.

use std::io::{self, Read};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::net::UnixStream;
use std::path::Path;
use std::time::{Duration, Instant};

use netd_core::{CONTROL_SOCKET_PATH, MAX_MESSAGE_BYTES, Reply, Request, Snapshot};

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
        let mut stream = connect_socket(Path::new(CONTROL_SOCKET_PATH))?;
        stream.set_write_timeout(Some(Duration::from_secs(2)))?;
        netd_core::send(&mut stream, &Request::Subscribe.encode())
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
        while self.buf.len() < MAX_MESSAGE_BYTES + 4 {
            let available = chunk.len().min(MAX_MESSAGE_BYTES + 4 - self.buf.len());
            match stream.read(&mut chunk[..available]) {
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
                Ok(Reply::Snapshot(s)) => {
                    // Connecting is not enough: netd may reject the request
                    // or close before delivering any usable state.
                    self.backoff = MIN_BACKOFF;
                    out.push(s);
                }
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
            self.next_try = now + self.backoff;
            self.backoff = (self.backoff * 2).min(MAX_BACKOFF);
            self.warned = true;
        }
        out
    }
}

/// Never wait for space in a listener's queue on the service's event loop.
fn connect_socket(path: &Path) -> io::Result<UnixStream> {
    let bytes = path.as_os_str().as_bytes();
    // SAFETY: sockaddr_un is plain C storage; all fields are initialized below.
    let mut address: libc::sockaddr_un = unsafe { std::mem::zeroed() };
    if bytes.is_empty() || bytes.len() >= address.sun_path.len() || bytes.contains(&0) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "invalid netd socket path",
        ));
    }
    address.sun_family = libc::AF_UNIX as libc::sa_family_t;
    for (target, source) in address.sun_path.iter_mut().zip(bytes) {
        *target = *source as libc::c_char;
    }
    // SAFETY: constants request a new nonblocking, close-on-exec Unix stream.
    let fd = unsafe {
        libc::socket(
            libc::AF_UNIX,
            libc::SOCK_STREAM | libc::SOCK_NONBLOCK | libc::SOCK_CLOEXEC,
            0,
        )
    };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: fd is newly allocated and uniquely owned here.
    let socket = unsafe { OwnedFd::from_raw_fd(fd) };
    let length = std::mem::offset_of!(libc::sockaddr_un, sun_path) + bytes.len() + 1;
    // SAFETY: the initialized address covers length bytes and socket remains owned.
    if unsafe {
        libc::connect(
            socket.as_raw_fd(),
            (&raw const address).cast(),
            length as libc::socklen_t,
        )
    } < 0
    {
        return Err(io::Error::last_os_error());
    }
    Ok(UnixStream::from(socket))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    #[test]
    fn a_full_listener_queue_returns_without_blocking() {
        let directory = std::env::temp_dir().join(format!("netd-queue-{}", std::process::id()));
        std::fs::create_dir(&directory).unwrap();
        let path = directory.join("socket");
        let listener = std::os::unix::net::UnixListener::bind(&path).unwrap();
        // SAFETY: the live listener is a stream socket; backlog zero keeps this test small.
        assert_eq!(unsafe { libc::listen(listener.as_raw_fd(), 0) }, 0);
        let first = connect_socket(&path).unwrap();
        let (done, wait) = std::sync::mpsc::channel();
        let worker = std::thread::spawn(move || {
            done.send(connect_socket(&path)).unwrap();
        });
        let error = wait
            .recv_timeout(Duration::from_secs(2))
            .unwrap()
            .unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::WouldBlock);
        worker.join().unwrap();
        drop((first, listener));
        std::fs::remove_dir_all(directory).unwrap();
    }

    fn attach(link: &mut NetdLink) -> UnixStream {
        let (stream, peer) = UnixStream::pair().unwrap();
        stream.set_nonblocking(true).unwrap();
        link.stream = Some(stream);
        peer
    }

    #[test]
    fn refusal_malformed_frame_and_eof_share_a_capped_retry_sequence() {
        let mut now = Instant::now();
        let mut link = NetdLink::new(now);
        for (i, millis) in [500, 1000, 2000, 4000, 8000, 10000, 10000]
            .into_iter()
            .enumerate()
        {
            let mut peer = attach(&mut link);
            match i % 3 {
                0 => netd_core::send(&mut peer, &Reply::Error("denied".into()).encode()).unwrap(),
                1 => netd_core::send(&mut peer, &[0xc1]).unwrap(),
                _ => {}
            }
            drop(peer);
            assert!(link.service(now).is_empty());
            assert!(!link.connected());
            let delay = Duration::from_millis(millis);
            assert_eq!(link.next_deadline(), Some(now + delay));
            now += delay;
        }
    }

    #[test]
    fn only_a_complete_snapshot_resets_the_backoff() {
        let now = Instant::now();
        let mut link = NetdLink::new(now);
        link.backoff = MAX_BACKOFF;
        let mut peer = attach(&mut link);
        netd_core::send(&mut peer, &Reply::Ok.encode()).unwrap();
        assert!(link.service(now).is_empty());
        assert_eq!(link.backoff, MAX_BACKOFF);
        let snapshot = Snapshot {
            hostname: "test-host".into(),
            scopes: vec![],
        };
        let bytes = Reply::Snapshot(snapshot.clone()).encode();
        peer.write_all(&(bytes.len() as u32).to_le_bytes()[..2])
            .unwrap();
        assert!(link.service(now).is_empty());
        assert_eq!(link.backoff, MAX_BACKOFF);
        let mut rest = (bytes.len() as u32).to_le_bytes()[2..].to_vec();
        rest.extend(bytes);
        peer.write_all(&rest).unwrap();
        assert_eq!(link.service(now), vec![snapshot]);
        assert_eq!(link.backoff, MIN_BACKOFF);
        assert!(link.connected());
        drop(peer);
        assert!(link.service(now).is_empty());
        assert_eq!(link.next_deadline(), Some(now + MIN_BACKOFF));
        assert_eq!(link.backoff, MIN_BACKOFF * 2);
    }
}
