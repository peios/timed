//! Safe Rust access to libtrust.so. Owned return values outlive the C result;
//! policy and subscription handles release themselves on drop.

use std::ffi::c_void;
use std::fmt;
use std::os::unix::ffi::OsStrExt;
use std::path::{Path, PathBuf};
use std::ptr::{self, NonNull};
use std::time::Duration;

use trust_abi as abi;

pub use trust_core::{
    CERTIFICATES_KEY, Health, Root, SOCKET_PATH, Source, Status, TRUST_ALL_ACCESS, TRUST_CONTROL,
    TRUST_KEY, TRUST_QUERY,
};

mod decode;
mod ffi;

/// A POSIX error code and diagnostic returned by libtrust. Diagnostics are for
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
    /// Caller must transfer a result pointer returned by this loaded libtrust.
    unsafe fn take(pointer: *mut c_void) -> Result<Self, Error> {
        let result = Self(NonNull::new(pointer).ok_or_else(|| invalid("libtrust returned null"))?);
        // SAFETY: result uniquely owns a live library allocation for these calls.
        let code = unsafe { ffi::peios_trust_result_error(result.0.as_ptr()) };
        if code != 0 {
            // SAFETY: the diagnostic remains borrowed from result until copied.
            let message =
                unsafe { decode::text(ffi::peios_trust_result_message(result.0.as_ptr())) };
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
        unsafe { ffi::peios_trust_result_free(self.0.as_ptr()) };
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
fn maybe_span(value: Option<&str>) -> abi::Bytes {
    value.map_or(
        abi::Bytes {
            data: ptr::null(),
            len: 0,
        },
        |value| span(value.as_bytes()),
    )
}
/// A durable distrust entry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Distrusted {
    pub fingerprint: String,
    pub reason: String,
}
impl Client {
    /// Read the daemon status.
    pub fn status(&self) -> Result<trust_core::Status, Error> {
        // SAFETY: input storage lives through the call; result owns all decoded views.
        unsafe {
            let result =
                OwnedResult::take(ffi::peios_trust_get_status(self.path(), self.timeout_ms))?;
            let view = ffi::peios_trust_result_status(result.0.as_ptr())
                .as_ref()
                .ok_or_else(|| invalid("missing library result"))?;
            decode::status(view)
        }
    }
}
impl Client {
    /// Read a complete, generation-consistent trust snapshot.
    pub fn roots(
        &self,
        with_der: bool,
        purpose: Option<&str>,
    ) -> Result<Vec<trust_core::Root>, Error> {
        // SAFETY: input storage lives through the call; result owns all decoded views.
        unsafe {
            let result = OwnedResult::take(ffi::peios_trust_roots(
                self.path(),
                self.timeout_ms,
                u32::from(with_der),
                maybe_span(purpose),
            ))?;
            let view = ffi::peios_trust_result_root_list(result.0.as_ptr())
                .as_ref()
                .ok_or_else(|| invalid("missing library result"))?;
            decode::root_list(*view)
        }
    }
}
impl Client {
    /// Request trust-store recomposition using the caller's rights.
    pub fn reload(&self) -> Result<(), Error> {
        // SAFETY: input storage lives through the call; result owns all decoded views.
        unsafe {
            let _result = OwnedResult::take(ffi::peios_trust_reload(self.path(), self.timeout_ms))?;
            Ok(())
        }
    }
}
/// Decode exactly one PEM or DER certificate.
pub fn certificate(bytes: &[u8], description: &str) -> Result<Vec<u8>, Error> {
    // SAFETY: input storage lives through the call; result owns all decoded views.
    unsafe {
        let result = OwnedResult::take(ffi::peios_trust_certificate(
            span(bytes),
            span(description.as_bytes()),
        ))?;
        let view = ffi::peios_trust_result_bytes(result.0.as_ptr())
            .as_ref()
            .ok_or_else(|| invalid("missing library result"))?;
        Ok(decode::bytes(*view))
    }
}
/// Inspect certificate fields without trusting the certificate.
pub fn inspect(der: &[u8]) -> Result<trust_core::cert::Details, Error> {
    // SAFETY: input storage lives through the call; result owns all decoded views.
    unsafe {
        let result = OwnedResult::take(ffi::peios_trust_inspect(span(der)))?;
        let view = ffi::peios_trust_result_details(result.0.as_ptr())
            .as_ref()
            .ok_or_else(|| invalid("missing library result"))?;
        decode::details(view)
    }
}
/// Validate a candidate root using the existing certificate policy.
pub fn vet(der: &[u8]) -> Result<trust_core::cert::Parsed, Error> {
    // SAFETY: input storage lives through the call; result owns all decoded views.
    unsafe {
        let result = OwnedResult::take(ffi::peios_trust_vet(span(der)))?;
        let view = ffi::peios_trust_result_parsed(result.0.as_ptr())
            .as_ref()
            .ok_or_else(|| invalid("missing library result"))?;
        decode::parsed(view)
    }
}
/// Check whether a certificate-store name is usable.
pub fn usable_name(name: &str) -> Result<bool, Error> {
    // SAFETY: input storage lives through the call; result owns all decoded views.
    unsafe {
        let result = OwnedResult::take(ffi::peios_trust_usable_name(span(name.as_bytes())))?;
        let view = ffi::peios_trust_result_boolean(result.0.as_ptr())
            .as_ref()
            .ok_or_else(|| invalid("missing library result"))?;
        Ok(*view != 0)
    }
}
/// Check the caller's reload access.
pub fn may_reload() -> Result<bool, Error> {
    // SAFETY: input storage lives through the call; result owns all decoded views.
    unsafe {
        let result = OwnedResult::take(ffi::peios_trust_may_reload())?;
        let view = ffi::peios_trust_result_boolean(result.0.as_ptr())
            .as_ref()
            .ok_or_else(|| invalid("missing library result"))?;
        Ok(*view != 0)
    }
}
/// Check the caller's registry write access.
pub fn may_change() -> Result<(), Error> {
    // SAFETY: input storage lives through the call; result owns all decoded views.
    unsafe {
        let _result = OwnedResult::take(ffi::peios_trust_may_change())?;
        Ok(())
    }
}
/// Check compatibility-output configuration access.
pub fn may_set_compat() -> Result<(), Error> {
    // SAFETY: input storage lives through the call; result owns all decoded views.
    unsafe {
        let _result = OwnedResult::take(ffi::peios_trust_may_set_compat())?;
        Ok(())
    }
}
/// Set compatibility output mode as the caller.
pub fn set_compat(mode: u32) -> Result<(), Error> {
    // SAFETY: input storage lives through the call; result owns all decoded views.
    unsafe {
        let _result = OwnedResult::take(ffi::peios_trust_set_compat(mode))?;
        Ok(())
    }
}
/// Add a certificate under the caller's registry permissions.
pub fn add(name: &str, der: &[u8], purposes: &[String]) -> Result<trust_core::cert::Parsed, Error> {
    let purposes_views: Vec<_> = purposes
        .iter()
        .map(|value| span(value.as_bytes()))
        .collect();
    // SAFETY: input storage lives through the call; result owns all decoded views.
    unsafe {
        let result = OwnedResult::take(ffi::peios_trust_add(
            span(name.as_bytes()),
            span(der),
            abi::Strings {
                data: purposes_views.as_ptr(),
                len: purposes_views.len(),
            },
        ))?;
        let view = ffi::peios_trust_result_parsed(result.0.as_ptr())
            .as_ref()
            .ok_or_else(|| invalid("missing library result"))?;
        decode::parsed(view)
    }
}
/// Remove an added certificate as the caller.
pub fn remove(name: &str) -> Result<(), Error> {
    // SAFETY: input storage lives through the call; result owns all decoded views.
    unsafe {
        let _result = OwnedResult::take(ffi::peios_trust_remove(span(name.as_bytes())))?;
        Ok(())
    }
}
/// Read durable distrust entries.
pub fn distrusted() -> Result<Vec<crate::Distrusted>, Error> {
    // SAFETY: input storage lives through the call; result owns all decoded views.
    unsafe {
        let result = OwnedResult::take(ffi::peios_trust_get_distrusted())?;
        let view = ffi::peios_trust_result_distrusted_list(result.0.as_ptr())
            .as_ref()
            .ok_or_else(|| invalid("missing library result"))?;
        decode::distrusted_list(*view)
    }
}
/// Distrust a fingerprint as the caller; return the subject of a matching effective certificate.
pub fn distrust(fingerprint: &str, reason: &str) -> Result<Option<String>, Error> {
    // SAFETY: input storage lives through the call; result owns all decoded views.
    unsafe {
        let result = OwnedResult::take(ffi::peios_trust_distrust(
            span(fingerprint.as_bytes()),
            span(reason.as_bytes()),
        ))?;
        let view = ffi::peios_trust_result_text(result.0.as_ptr())
            .as_ref()
            .ok_or_else(|| invalid("missing library result"))?;
        decode::maybe_text(*view)
    }
}
/// Remove a distrust entry as the caller.
pub fn restore(fingerprint: &str) -> Result<String, Error> {
    // SAFETY: input storage lives through the call; result owns all decoded views.
    unsafe {
        let result = OwnedResult::take(ffi::peios_trust_restore(span(fingerprint.as_bytes())))?;
        let view = ffi::peios_trust_result_text(result.0.as_ptr())
            .as_ref()
            .ok_or_else(|| invalid("missing library result"))?;
        decode::text(*view)
    }
}

/// A subscription owns its stream and cannot be copied. Next requires exclusive access.
pub struct Subscription(NonNull<c_void>);
impl Drop for Subscription {
    fn drop(&mut self) {
        // SAFETY: this owner releases its handle exactly once.
        unsafe {
            ffi::peios_trust_subscription_free(self.0.as_ptr());
        }
    }
}
impl Client {
    /// Start a subscription; next reads the initial snapshot or access refusal.
    pub fn subscribe(&self, with_der: bool) -> Result<Subscription, Error> {
        let mut out = ptr::null_mut();
        // SAFETY: inputs remain live and out is a writable exclusive slot.
        unsafe {
            OwnedResult::take(ffi::peios_trust_subscribe(
                self.path(),
                self.timeout_ms,
                u32::from(with_der),
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
    pub fn next(&mut self, timeout: Duration) -> Result<RootSnapshot, Error> {
        // SAFETY: this handle is exclusively borrowed, and result owns the views.
        unsafe {
            let result = OwnedResult::take(ffi::peios_trust_subscription_next(
                self.0.as_ptr(),
                timeout_ms(timeout)?,
            ))?;
            root_snapshot(&result)
        }
    }
}
/// One complete trust snapshot and the generation shared by all its roots.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RootSnapshot {
    pub generation: u64,
    pub roots: Vec<Root>,
}
unsafe fn root_snapshot(result: &OwnedResult) -> Result<RootSnapshot, Error> {
    // SAFETY: result remains alive through all accessor and copy operations.
    unsafe {
        let view = ffi::peios_trust_result_root_list(result.0.as_ptr())
            .as_ref()
            .ok_or_else(|| invalid("missing roots"))?;
        Ok(RootSnapshot {
            generation: ffi::peios_trust_result_generation(result.0.as_ptr()),
            roots: decode::root_list(*view)?,
        })
    }
}

/// Resolve a whole fingerprint or an unambiguous prefix using existing permissions.
pub fn resolve(argument: &str) -> Result<String, Error> {
    // SAFETY: argument is live during the call, and result owns the returned text.
    unsafe {
        let result = OwnedResult::take(ffi::peios_trust_resolve(span(argument.as_bytes())))?;
        let text = ffi::peios_trust_result_text(result.0.as_ptr())
            .as_ref()
            .ok_or_else(|| invalid("missing fingerprint"))?;
        decode::text(*text)
    }
}
