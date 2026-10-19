//! Bounded control exchanges. A deadline covers the whole operation, including
//! partial reads; subscription timeouts retain their partially received frame.

use std::io::{self, Read, Write};
use std::mem::{offset_of, zeroed};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::os::unix::net::UnixStream;
use std::time::{Duration, Instant};

use resolvd_core::{MAX_MESSAGE_BYTES, Reply, Request};

pub(crate) struct Channel {
    stream: UnixStream,
    incoming: Vec<u8>,
}

pub(crate) fn invalid(message: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, message.into())
}

pub(crate) fn deadline(timeout_ms: u64) -> io::Result<Instant> {
    if timeout_ms == 0 {
        return Err(invalid("timeout_ms must be positive"));
    }
    Instant::now()
        .checked_add(Duration::from_millis(timeout_ms))
        .ok_or_else(|| invalid("timeout is too large"))
}

fn remaining(end: Instant) -> io::Result<Duration> {
    end.checked_duration_since(Instant::now())
        .ok_or_else(|| io::Error::new(io::ErrorKind::TimedOut, "resolvd operation timed out"))
}

fn wait(fd: i32, events: i16, end: Instant) -> io::Result<()> {
    loop {
        let duration = remaining(end)?;
        let timeout_ms = duration.as_millis().saturating_add(1).min(i32::MAX as u128) as i32;
        let mut descriptor = libc::pollfd {
            fd,
            events,
            revents: 0,
        };
        // SAFETY: descriptor is initialized and writable for one pollfd; fd is
        // borrowed from a live socket owned by the caller for this entire call.
        let result = unsafe { libc::poll(&mut descriptor, 1, timeout_ms) };
        if result > 0 {
            if descriptor.revents & libc::POLLNVAL != 0 {
                return Err(io::Error::from_raw_os_error(libc::EBADF));
            }
            return Ok(());
        }
        if result < 0 {
            let error = io::Error::last_os_error();
            if error.kind() != io::ErrorKind::Interrupted {
                return Err(error);
            }
        }
    }
}

impl Channel {
    pub(crate) fn connect(path: &[u8], end: Instant) -> io::Result<Self> {
        // SAFETY: all-zero sockaddr_un is valid storage, initialized below.
        let mut address: libc::sockaddr_un = unsafe { zeroed() };
        if path.is_empty() || path.contains(&0) || path.len() >= address.sun_path.len() {
            return Err(invalid(
                "expected a nonempty filesystem socket path shorter than 108 bytes",
            ));
        }
        address.sun_family = libc::AF_UNIX as libc::sa_family_t;
        for (target, byte) in address.sun_path.iter_mut().zip(path) {
            *target = *byte as libc::c_char;
        }
        // SAFETY: socket has no pointer arguments. Check the returned descriptor
        // before transferring its unique ownership to OwnedFd.
        let raw = unsafe {
            libc::socket(
                libc::AF_UNIX,
                libc::SOCK_STREAM | libc::SOCK_NONBLOCK | libc::SOCK_CLOEXEC,
                0,
            )
        };
        if raw < 0 {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: raw is a newly created descriptor owned only by this function.
        let socket = unsafe { OwnedFd::from_raw_fd(raw) };
        let length = offset_of!(libc::sockaddr_un, sun_path) + path.len() + 1;
        // SAFETY: initialized address contains length bytes, and socket is live.
        let result = unsafe {
            libc::connect(
                socket.as_raw_fd(),
                (&raw const address).cast(),
                length as libc::socklen_t,
            )
        };
        if result < 0 {
            let error = io::Error::last_os_error();
            // AF_UNIX EAGAIN means no connection was started (full listen queue).
            // Return it rather than mistaking writable readiness for a connection.
            if error.raw_os_error() != Some(libc::EINPROGRESS) {
                return Err(error);
            }
            wait(socket.as_raw_fd(), libc::POLLOUT, end)?;
        }
        let stream = UnixStream::from(socket);
        if let Some(error) = stream.take_error()? {
            return Err(error);
        }
        remaining(end)?;
        Ok(Self {
            stream,
            incoming: Vec::new(),
        })
    }

    pub(crate) fn send(&mut self, request: &Request, end: Instant) -> io::Result<()> {
        let payload = request.encode();
        if payload.len() > MAX_MESSAGE_BYTES {
            return Err(invalid("request exceeds the protocol message limit"));
        }
        let mut frame = Vec::with_capacity(4 + payload.len());
        frame.extend_from_slice(&(payload.len() as u32).to_le_bytes());
        frame.extend_from_slice(&payload);
        let mut pending = frame.as_slice();
        while !pending.is_empty() {
            remaining(end)?;
            match self.stream.write(pending) {
                Ok(0) => {
                    return Err(io::Error::new(
                        io::ErrorKind::WriteZero,
                        "resolvd closed while writing",
                    ));
                }
                Ok(count) => pending = &pending[count..],
                Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                    wait(self.stream.as_raw_fd(), libc::POLLOUT, end)?;
                }
                Err(error) => return Err(error),
            }
        }
        Ok(())
    }

    pub(crate) fn receive(&mut self, end: Instant) -> io::Result<Reply> {
        loop {
            remaining(end)?;
            let needed = if self.incoming.len() < 4 {
                4
            } else {
                let length = u32::from_le_bytes(self.incoming[..4].try_into().unwrap()) as usize;
                if length > MAX_MESSAGE_BYTES {
                    return Err(invalid("reply exceeds the protocol message limit"));
                }
                let frame_bytes = 4 + length;
                if self.incoming.len() == frame_bytes {
                    let reply = Reply::decode(&self.incoming[4..]).map_err(|error| {
                        io::Error::new(io::ErrorKind::InvalidData, error.to_string())
                    });
                    self.incoming.clear();
                    return reply;
                }
                frame_bytes
            };
            let mut bytes = [0u8; 4096];
            let capacity = bytes.len().min(needed - self.incoming.len());
            match self.stream.read(&mut bytes[..capacity]) {
                Ok(0) => {
                    return Err(io::Error::new(
                        io::ErrorKind::UnexpectedEof,
                        "resolvd closed mid-reply",
                    ));
                }
                Ok(count) => self.incoming.extend_from_slice(&bytes[..count]),
                Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                    wait(self.stream.as_raw_fd(), libc::POLLIN, end)?;
                }
                Err(error) => return Err(error),
            }
        }
    }
}
