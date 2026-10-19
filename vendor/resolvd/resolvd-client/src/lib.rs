//! Safe Rust access to libresolvd.so. Owned return values outlive the C result;
//! policy and subscription handles release themselves on drop.

use std::ffi::c_void;
use std::fmt;
use std::os::unix::ffi::OsStrExt;
use std::path::{Path, PathBuf};
use std::ptr::NonNull;
use std::time::Duration;

use resolvd_abi as abi;

pub use resolvd_core::{
    AddressOut, Addresses, Answer, Counters, Family, Outcome, RESOLVER_ALL_ACCESS,
    RESOLVER_CONTROL, RESOLVER_KEY, RESOLVER_QUERY, RecordOut, SOCKET_PATH, ScopeStatus,
    StatusReport, Validation,
};

mod decode;
mod ffi;

/// A POSIX error code and diagnostic returned by libresolvd. Diagnostics are for
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
    /// Caller must transfer a result pointer returned by this loaded libresolvd.
    unsafe fn take(pointer: *mut c_void) -> Result<Self, Error> {
        let result =
            Self(NonNull::new(pointer).ok_or_else(|| invalid("libresolvd returned null"))?);
        // SAFETY: result uniquely owns a live library allocation for these calls.
        let code = unsafe { ffi::peios_resolvd_result_error(result.0.as_ptr()) };
        if code != 0 {
            // SAFETY: the diagnostic remains borrowed from result until copied.
            let message =
                unsafe { decode::text(ffi::peios_resolvd_result_message(result.0.as_ptr())) };
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
        unsafe { ffi::peios_resolvd_result_free(self.0.as_ptr()) };
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
    pub fn status(&self) -> Result<resolvd_core::StatusReport, Error> {
        // SAFETY: input storage lives through the call; result owns all decoded views.
        unsafe {
            let result =
                OwnedResult::take(ffi::peios_resolvd_get_status(self.path(), self.timeout_ms))?;
            let view = ffi::peios_resolvd_result_status_report(result.0.as_ptr())
                .as_ref()
                .ok_or_else(|| invalid("missing library result"))?;
            decode::status_report(view)
        }
    }
}
impl Client {
    /// Look up addresses and their provenance.
    pub fn lookup(&self, name: &str, family: Family) -> Result<resolvd_core::Addresses, Error> {
        // SAFETY: input storage lives through the call; result owns all decoded views.
        unsafe {
            let result = OwnedResult::take(ffi::peios_resolvd_lookup(
                self.path(),
                self.timeout_ms,
                span(name.as_bytes()),
                match family {
                    Family::Any => 0,
                    Family::V4 => 1,
                    Family::V6 => 2,
                },
            ))?;
            let view = ffi::peios_resolvd_result_addresses(result.0.as_ptr())
                .as_ref()
                .ok_or_else(|| invalid("missing library result"))?;
            decode::addresses(view)
        }
    }
}
impl Client {
    /// Resolve a DNS record type.
    pub fn resolve(
        &self,
        name: &str,
        record_type: u16,
        no_cache: bool,
    ) -> Result<resolvd_core::Answer, Error> {
        // SAFETY: input storage lives through the call; result owns all decoded views.
        unsafe {
            let result = OwnedResult::take(ffi::peios_resolvd_resolve(
                self.path(),
                self.timeout_ms,
                span(name.as_bytes()),
                record_type,
                u32::from(no_cache),
            ))?;
            let view = ffi::peios_resolvd_result_answer(result.0.as_ptr())
                .as_ref()
                .ok_or_else(|| invalid("missing library result"))?;
            decode::answer(view)
        }
    }
}
impl Client {
    /// Look up the names of an IP address.
    pub fn reverse(&self, address: &str) -> Result<resolvd_core::Answer, Error> {
        // SAFETY: input storage lives through the call; result owns all decoded views.
        unsafe {
            let result = OwnedResult::take(ffi::peios_resolvd_reverse(
                self.path(),
                self.timeout_ms,
                span(address.as_bytes()),
            ))?;
            let view = ffi::peios_resolvd_result_answer(result.0.as_ptr())
                .as_ref()
                .ok_or_else(|| invalid("missing library result"))?;
            decode::answer(view)
        }
    }
}
impl Client {
    /// Flush the cache using the caller's existing control rights.
    pub fn flush(&self) -> Result<(), Error> {
        // SAFETY: input storage lives through the call; result owns all decoded views.
        unsafe {
            let _result =
                OwnedResult::take(ffi::peios_resolvd_flush(self.path(), self.timeout_ms))?;
            Ok(())
        }
    }
}
