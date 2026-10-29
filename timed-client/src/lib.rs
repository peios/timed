//! Safe Rust access to libtimed.so. Owned return values outlive the C result;
//! policy and subscription handles release themselves on drop.

use std::ffi::c_void;
use std::fmt;
use std::os::unix::ffi::OsStrExt;
use std::path::{Path, PathBuf};
use std::ptr::{self, NonNull};
use std::time::Duration;

use timed_abi as abi;

pub use timed_core::{
    ALLOW_UNAUTHENTICATED_VALUE, AUTOMATIC_VALUE, Auth, MAX_POLL_VALUE, MIN_POLL_VALUE, Origin,
    SERVERS_VALUE, SOCKET_PATH, Snapshot, SourceInfo, SourceState, Status, Sync, TIME_ALL_ACCESS,
    TIME_CONTROL, TIME_KEY, TIME_QUERY, TIME_ZONE_VALUE, USE_FROM_DHCP_VALUE,
};

mod decode;
mod ffi;

/// A POSIX error code and diagnostic returned by libtimed. Diagnostics are for
/// people; their wording is not a stable interface.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Error {
    pub code: i32,
    pub message: String,
}

impl fmt::Display for Error {
    fn fmt(&self, out: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.message.fmt(out)
    }
}
impl std::error::Error for Error {}

pub(crate) fn invalid(message: &str) -> Error {
    Error {
        code: libc::EINVAL,
        message: message.into(),
    }
}

pub(crate) fn span(value: &[u8]) -> abi::Bytes {
    abi::Bytes {
        data: value.as_ptr(),
        len: value.len(),
    }
}

fn timeout_ms(timeout: Duration) -> Result<u64, Error> {
    if timeout.is_zero() {
        return Err(invalid("timeout must be positive"));
    }
    let milliseconds = timeout.as_nanos().div_ceil(1_000_000);
    u64::try_from(milliseconds).map_err(|_| invalid("timeout is too large"))
}

pub(crate) struct OwnedResult(NonNull<c_void>);

impl OwnedResult {
    /// Caller must transfer a result pointer returned by this loaded libtimed.
    unsafe fn take(pointer: *mut c_void) -> Result<Self, Error> {
        let result = Self(NonNull::new(pointer).ok_or_else(|| invalid("libtimed returned null"))?);
        // SAFETY: result uniquely owns a live library allocation for these calls.
        let code = unsafe { ffi::peios_timed_result_error(result.0.as_ptr()) };
        if code != 0 {
            // SAFETY: the diagnostic remains borrowed from result until copied.
            let message =
                unsafe { decode::text(ffi::peios_timed_result_message(result.0.as_ptr())) };
            return Err(Error {
                code,
                message: message?,
            });
        }
        Ok(result)
    }
}

impl Drop for OwnedResult {
    fn drop(&mut self) {
        // SAFETY: this owner releases its live result exactly once after all
        // wrapper borrows finish; returned public values contain owned copies.
        unsafe { ffi::peios_timed_result_free(self.0.as_ptr()) };
    }
}

/// Per-operation socket settings. Constructing a client has no side effects.
#[derive(Clone, Debug)]
pub struct Client {
    path: PathBuf,
    timeout_ms: u64,
}
impl Client {
    pub fn new(path: impl AsRef<Path>, timeout: Duration) -> Result<Self, Error> {
        let path = path.as_ref();
        let bytes = path.as_os_str().as_bytes();
        if bytes.is_empty() || bytes.len() >= 108 || bytes.contains(&0) {
            return Err(invalid("invalid Unix socket path"));
        }
        Ok(Self {
            path: path.into(),
            timeout_ms: timeout_ms(timeout)?,
        })
    }
    pub fn system(timeout: Duration) -> Result<Self, Error> {
        Self::new(SOCKET_PATH, timeout)
    }
    fn path(&self) -> abi::Bytes {
        span(self.path.as_os_str().as_bytes())
    }
}

impl Client {
    /// Read the daemon status.
    pub fn status(&self) -> Result<timed_core::Status, Error> {
        // SAFETY: input storage lives through the call; result owns all decoded views.
        unsafe {
            let result =
                OwnedResult::take(ffi::peios_timed_get_status(self.path(), self.timeout_ms))?;
            let view = ffi::peios_timed_result_status(result.0.as_ptr())
                .as_ref()
                .ok_or_else(|| invalid("missing library result"))?;
            decode::status(view)
        }
    }
}
impl Client {
    /// Read the complete source list.
    pub fn sources(&self) -> Result<Vec<timed_core::SourceInfo>, Error> {
        // SAFETY: input storage lives through the call; result owns all decoded views.
        unsafe {
            let result = OwnedResult::take(ffi::peios_timed_sources(self.path(), self.timeout_ms))?;
            let view = ffi::peios_timed_result_source_info_list(result.0.as_ptr())
                .as_ref()
                .ok_or_else(|| invalid("missing library result"))?;
            decode::source_info_list(*view)
        }
    }
}
impl Client {
    /// Reload time policy using the caller's existing rights.
    pub fn reload(&self) -> Result<(), Error> {
        // SAFETY: input storage lives through the call; result owns all decoded views.
        unsafe {
            let _result = OwnedResult::take(ffi::peios_timed_reload(self.path(), self.timeout_ms))?;
            Ok(())
        }
    }
}
impl Client {
    /// Set manual time; the daemon enforces authorization and mode.
    pub fn set(&self, seconds: i64, nanos: u32) -> Result<(), Error> {
        // SAFETY: input storage lives through the call; result owns all decoded views.
        unsafe {
            let _result = OwnedResult::take(ffi::peios_timed_set(
                self.path(),
                self.timeout_ms,
                seconds,
                nanos,
            ))?;
            Ok(())
        }
    }
}
/// Parse a server configuration entry.
pub fn parse_server(entry: &str) -> Result<timed_core::servers::ServerSpec, Error> {
    // SAFETY: input storage lives through the call; result owns all decoded views.
    unsafe {
        let result = OwnedResult::take(ffi::peios_timed_parse_server(span(entry.as_bytes())))?;
        let view = ffi::peios_timed_result_server_spec(result.0.as_ptr())
            .as_ref()
            .ok_or_else(|| invalid("missing library result"))?;
        decode::server_spec(view)
    }
}
/// Check the syntax of a time-zone name.
pub fn check_zone(name: &str) -> Result<(), Error> {
    // SAFETY: input storage lives through the call; result owns all decoded views.
    unsafe {
        let _result = OwnedResult::take(ffi::peios_timed_check_zone(span(name.as_bytes())))?;
        Ok(())
    }
}
/// Check that a named time zone is installed.
pub fn installed_zone(name: &str) -> Result<(), Error> {
    // SAFETY: input storage lives through the call; result owns all decoded views.
    unsafe {
        let _result = OwnedResult::take(ffi::peios_timed_installed_zone(span(name.as_bytes())))?;
        Ok(())
    }
}
/// List installed time-zone metadata.
pub fn zones() -> Result<Vec<timed_core::zone::Listed>, Error> {
    // SAFETY: input storage lives through the call; result owns all decoded views.
    unsafe {
        let result = OwnedResult::take(ffi::peios_timed_zones())?;
        let view = ffi::peios_timed_result_listed_list(result.0.as_ptr())
            .as_ref()
            .ok_or_else(|| invalid("missing library result"))?;
        decode::listed_list(*view)
    }
}

/// A subscription owns its stream and cannot be copied. Next requires exclusive access.
pub struct Subscription(NonNull<c_void>);
impl Drop for Subscription {
    fn drop(&mut self) {
        // SAFETY: this owner releases its handle exactly once.
        unsafe {
            ffi::peios_timed_subscription_free(self.0.as_ptr());
        }
    }
}
impl Client {
    /// Start a subscription; next reads the initial snapshot or access refusal.
    pub fn subscribe(&self) -> Result<Subscription, Error> {
        let mut out = ptr::null_mut();
        // SAFETY: inputs remain live and out is a writable exclusive slot.
        unsafe {
            OwnedResult::take(ffi::peios_timed_subscribe(
                self.path(),
                self.timeout_ms,
                &mut out,
            ))?;
        }
        NonNull::new(out)
            .map(Subscription)
            .ok_or_else(|| invalid("missing subscription"))
    }
}
impl Subscription {
    /// Read a complete update. Timeout preserves partial input without replay.
    pub fn next(&mut self, timeout: Duration) -> Result<Snapshot, Error> {
        // SAFETY: this handle is exclusively borrowed, and result owns the views.
        unsafe {
            let result = OwnedResult::take(ffi::peios_timed_subscription_next(
                self.0.as_ptr(),
                timeout_ms(timeout)?,
            ))?;
            let view = ffi::peios_timed_result_snapshot(result.0.as_ptr())
                .as_ref()
                .ok_or_else(|| invalid("missing snapshot"))?;
            decode::snapshot(view)
        }
    }
}

/// List country names from the installed database. Empty if tzdata is absent.
pub fn countries() -> Result<Vec<timed_core::zone::Country>, Error> {
    // SAFETY: the result keeps the complete country list alive until copied.
    unsafe {
        let result = OwnedResult::take(ffi::peios_timed_countries())?;
        let list = ffi::peios_timed_result_country_list(result.0.as_ptr())
            .as_ref()
            .ok_or_else(|| invalid("missing country list"))?;
        decode::country_list(*list)
    }
}
/// Return the database path for a valid zone name without checking its existence.
pub fn zone_path(name: &str) -> Result<PathBuf, Error> {
    // SAFETY: the input lives through the call; the result lives through the copy.
    unsafe {
        let result = OwnedResult::take(ffi::peios_timed_zone_path(span(name.as_bytes())))?;
        Ok(PathBuf::from(decode::text(ffi::peios_timed_result_bytes(
            result.0.as_ptr(),
        ))?))
    }
}

pub use timed_core::servers::ServerSpec;
pub use timed_core::zone::{Country, Listed};
