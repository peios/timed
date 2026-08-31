//! The socket: `/run/timed/time.sock`.
//!
//! Everyone may connect and everyone may ask. What time the machine thinks
//! it is, and how well it knows, is not a secret — and a program deciding
//! whether the clock is trustworthy enough to validate a certificate
//! against should not need a privilege to find out. What the control object
//! gates is `reload`.
//!
//! `subscribe` holds the connection open and receives a snapshot after
//! every completed poll. That is the channel the future NTP server package
//! consumes, and the reason it can be an unprivileged process: everything
//! it must say about this machine's time arrives here.

use std::io::{self, Write};
use std::os::fd::AsFd;
use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::Path;
use std::time::Duration;

use libtimed::{
    Reply, Request, SOCKET_PATH, TIMED_RUN_DIR, TIME_ALL_ACCESS, TIME_CONTROL, TIME_QUERY,
};
use peios::access::AccessCheck;
use peios::security::{
    AccessMask, AceFlags, AclBuilder, GenericMapping, SdBuilder, SecurityDescriptor, Sid, WellKnown,
};
use peios::token::Token;

use crate::log;

const DIRECTORY_MODE: u32 = 0o755;
const SOCKET_MODE: u32 = 0o666;
/// How long a client has to deliver its request.
pub const CLIENT_TIMEOUT: Duration = Duration::from_secs(5);
/// How long a peer has to drain a reply before it is presumed gone.
pub const WRITE_TIMEOUT: Duration = Duration::from_secs(5);
/// Connections held at once, so a local flood exhausts a counter rather
/// than the descriptor table.
pub const MAX_CLIENTS: usize = 128;

pub fn listen() -> io::Result<UnixListener> {
    let directory = Path::new(TIMED_RUN_DIR);
    std::fs::create_dir_all(directory)?;
    std::fs::set_permissions(directory, std::fs::Permissions::from_mode(DIRECTORY_MODE))?;
    protect(directory);
    let path = Path::new(SOCKET_PATH);
    match std::fs::remove_file(path) {
        Ok(()) => log::warn(format_args!("removed a stale {SOCKET_PATH}")),
        Err(e) if e.kind() == io::ErrorKind::NotFound => {}
        Err(e) => return Err(e),
    }
    let listener = UnixListener::bind(path)?;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(SOCKET_MODE))?;
    protect(path);
    listener.set_nonblocking(true)?;
    Ok(listener)
}

/// Let everyone reach the socket; the object check decides what they may do.
///
/// **The DACL only.** An earlier version also set the owner to SYSTEM, and
/// that is the one thing a LocalService process cannot do — making somebody
/// else the owner of an object needs a privilege timed does not have and
/// should not have. `set_sd` is all-or-nothing, so asking for the owner
/// failed the whole call with `EPERM` and the DACL was never written
/// either. The directory then kept peinit's descriptor, which admits
/// SYSTEM, Administrators and this service and *nobody else*, so an
/// ordinary program could not traverse it to reach the socket at all —
/// while the code and the documentation both said reading was open to
/// everyone.
///
/// It failed silently for a long time because the error only ever went to
/// the log, and a LocalService daemon's log lines do not reach the console
/// (see PEI-581); `evctl 'LOGS FROM timed'` had them all along.
///
/// The owner is left as whoever created the object, which is timed — the
/// correct answer, and what it already was.
pub fn protect(path: &Path) {
    use peios::file::SecInfo;
    let system = Sid::well_known(WellKnown::System);
    let everyone = Sid::well_known(WellKnown::Everyone);
    let descriptor = AclBuilder::new()
        .allow(system.as_ref(), AccessMask::GENERIC_ALL.bits(), AceFlags::empty())
        .allow(
            everyone.as_ref(),
            AccessMask::GENERIC_READ.bits()
                | AccessMask::GENERIC_WRITE.bits()
                | AccessMask::GENERIC_EXECUTE.bits(),
            AceFlags::empty(),
        )
        .build()
        .and_then(|dacl| SdBuilder::new().dacl(&dacl).build());
    match descriptor {
        Ok(sd) => {
            if let Err(e) = peios::file::set_sd(None, path, SecInfo::DACL, &sd, 0) {
                log::error(format_args!(
                    "could not set a descriptor on {} ({e}); programs other than SYSTEM and \
                     administrators will not be able to reach the socket",
                    path.display()
                ));
            }
        }
        Err(e) => log::warn(format_args!("could not build a descriptor: {e}")),
    }
}

pub struct ControlObject {
    sd: SecurityDescriptor,
}

impl ControlObject {
    pub fn new(configured: Option<&[u8]>) -> ControlObject {
        if let Some(bytes) = configured {
            match SecurityDescriptor::from_validated_bytes(bytes.to_vec()) {
                Ok(sd) => return ControlObject { sd },
                Err(e) => log::warn(format_args!(
                    "ControlSecurity is not a valid descriptor ({e}); using the default"
                )),
            }
        }
        ControlObject { sd: Self::default_sd() }
    }

    fn default_sd() -> SecurityDescriptor {
        let system = Sid::well_known(WellKnown::System);
        let administrators = Sid::well_known(WellKnown::Administrators);
        let everyone = Sid::well_known(WellKnown::Everyone);
        AclBuilder::new()
            .allow(system.as_ref(), TIME_ALL_ACCESS, AceFlags::empty())
            .allow(administrators.as_ref(), TIME_ALL_ACCESS, AceFlags::empty())
            .allow(everyone.as_ref(), TIME_QUERY | AccessMask::READ_CONTROL.bits(), AceFlags::empty())
            .build()
            .and_then(|dacl| {
                SdBuilder::new().owner(system.as_ref()).group(system.as_ref()).dacl(&dacl).build()
            })
            .expect("the compiled default descriptor builds")
    }

    fn mapping() -> GenericMapping {
        let rc = AccessMask::READ_CONTROL.bits();
        GenericMapping::new(TIME_QUERY | rc, TIME_CONTROL | rc, TIME_QUERY, TIME_ALL_ACCESS)
    }

    pub fn permits(&self, stream: &UnixStream, right: u32) -> bool {
        let token = match Token::open_peer(stream.as_fd()) {
            Ok(t) => t,
            Err(e) => {
                log::warn(format_args!("could not read a peer's token ({e}); refusing"));
                return false;
            }
        };
        AccessCheck::new(&self.sd, AccessMask::from_bits_retain(right), Self::mapping())
            .token(token.as_fd())
            .check()
            .map(|d| d.allowed)
            .unwrap_or(false)
    }
}

/// Read one request from a connected peer.
pub fn read_request(stream: &mut UnixStream) -> Result<Request, String> {
    stream.set_read_timeout(Some(CLIENT_TIMEOUT)).map_err(|e| e.to_string())?;
    stream.set_write_timeout(Some(WRITE_TIMEOUT)).map_err(|e| e.to_string())?;
    let bytes = libtimed::recv(stream).map_err(|e| e.to_string())?;
    Request::decode(&bytes).map_err(|e| e.to_string())
}

pub fn write_reply(stream: &mut UnixStream, reply: &Reply) -> Result<(), String> {
    libtimed::send(stream, &reply.encode()).map_err(|e| e.to_string())
}

/// Push to a subscriber without blocking on one that has stopped reading.
///
/// A subscriber that cannot take a snapshot is dropped rather than waited
/// for. The alternative — blocking the daemon that owns the system clock on
/// a peer that has wandered off — is not a trade worth making, and a
/// dropped subscriber reconnects and gets a fresh snapshot immediately.
pub fn send_nonblocking(stream: &mut UnixStream, bytes: &[u8]) -> bool {
    if stream.set_nonblocking(true).is_err() {
        return false;
    }
    let header = (bytes.len() as u32).to_le_bytes();
    let ok = stream.write_all(&header).is_ok() && stream.write_all(bytes).is_ok();
    let _ = stream.set_nonblocking(false);
    ok
}
