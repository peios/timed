//! Shared service API. See the installed header for the ownership contract.
//!
//! # Safety
//! Non-null input pointers must be aligned, initialized and readable for their
//! stated lengths. Inputs are borrowed for the call only. Result views remain
//! borrowed until their owning result is freed. Handles must originate from
//! this library. Mutation and destruction require exclusive access.
use resolvd_abi as abi;
use resolvd_core::{Reply, Request};
use std::io;
use std::ptr;
mod channel;
mod inputs;
mod views;
use channel::{Channel, deadline, invalid};
use views::Arena;

enum Payload {
    Empty,
    Answer(abi::Answer),
    Addresses(abi::Addresses),
    StatusReport(abi::StatusReport),
}
/// Immutable result and storage for every view returned from it.
pub struct ResultHandle {
    error: i32,
    message: abi::Bytes,
    arena: Arena,
    payload: Payload,
}
impl Default for ResultHandle {
    fn default() -> Self {
        Self {
            error: 0,
            message: views::absent(),
            arena: Arena::default(),
            payload: Payload::Empty,
        }
    }
}
impl ResultHandle {
    fn error(error: io::Error) -> Self {
        let mut result = Self::default();
        result.error = error.raw_os_error().unwrap_or(match error.kind() {
            io::ErrorKind::InvalidInput | io::ErrorKind::InvalidData => libc::EINVAL,
            io::ErrorKind::TimedOut => libc::ETIMEDOUT,
            io::ErrorKind::PermissionDenied => libc::EACCES,
            io::ErrorKind::NotConnected => libc::ENOTCONN,
            _ => libc::EIO,
        });
        result.message = result.arena.text(&error.to_string());
        result
    }
}
fn finish(result: io::Result<ResultHandle>) -> *mut ResultHandle {
    Box::into_raw(Box::new(result.unwrap_or_else(ResultHandle::error)))
}
/// Return the independently versioned resolvd_abi major.
#[unsafe(no_mangle)]
pub extern "C" fn peios_resolvd_abi_version() -> u32 {
    1
}
/// Release a result and every borrowed view. Null is accepted.
/// # Safety
/// A non-null result must be uniquely owned and come from this library.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn peios_resolvd_result_free(result: *mut ResultHandle) {
    if !result.is_null() {
        // SAFETY: the caller returns unique ownership of this library allocation.
        drop(unsafe { Box::from_raw(result) });
    }
}
/// Return zero on success, otherwise a POSIX error number. Null is EINVAL.
/// # Safety
/// A non-null result must remain alive and readable for this call.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn peios_resolvd_result_error(result: *const ResultHandle) -> i32 {
    // SAFETY: caller supplies a live borrowed result or null.
    unsafe { result.as_ref() }.map_or(libc::EINVAL, |result| result.error)
}
/// Return a diagnostic borrowed from result; null produces an absent span.
/// # Safety
/// A non-null result must remain alive and readable for this call.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn peios_resolvd_result_message(result: *const ResultHandle) -> abi::Bytes {
    // SAFETY: caller supplies a live borrowed result or null.
    unsafe { result.as_ref() }.map_or_else(views::absent, |result| result.message)
}
/// Return a borrowed Answer view, or null for a different payload.
/// # Safety
/// A non-null result must remain alive for this call and use of its view.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn peios_resolvd_result_answer(
    result: *const ResultHandle,
) -> *const abi::Answer {
    // SAFETY: the caller borrows a live result or supplies null.
    match unsafe { result.as_ref() }.map(|result| &result.payload) {
        Some(Payload::Answer(view)) => view,
        _ => ptr::null(),
    }
}
/// Return a borrowed Addresses view, or null for a different payload.
/// # Safety
/// A non-null result must remain alive for this call and use of its view.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn peios_resolvd_result_addresses(
    result: *const ResultHandle,
) -> *const abi::Addresses {
    // SAFETY: the caller borrows a live result or supplies null.
    match unsafe { result.as_ref() }.map(|result| &result.payload) {
        Some(Payload::Addresses(view)) => view,
        _ => ptr::null(),
    }
}
/// Return a borrowed StatusReport view, or null for a different payload.
/// # Safety
/// A non-null result must remain alive for this call and use of its view.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn peios_resolvd_result_status_report(
    result: *const ResultHandle,
) -> *const abi::StatusReport {
    // SAFETY: the caller borrows a live result or supplies null.
    match unsafe { result.as_ref() }.map(|result| &result.payload) {
        Some(Payload::StatusReport(view)) => view,
        _ => ptr::null(),
    }
}
fn reply_result(reply: Reply) -> io::Result<ResultHandle> {
    let mut result = ResultHandle::default();
    result.payload = match reply {
        Reply::Ok => Payload::Empty,
        Reply::Error(message) => return Err(io::Error::other(message)),
        Reply::Answer(value) => Payload::Answer(result.arena.answer(&value)),
        Reply::Addresses(value) => Payload::Addresses(result.arena.addresses(&value)),
        Reply::Status(value) => Payload::StatusReport(result.arena.status_report(&value)),
    };
    Ok(result)
}
fn expected(request: &Request, reply: &Reply) -> bool {
    matches!(
        (request, reply),
        (_, Reply::Error(_))
            | (Request::Status, Reply::Status(_))
            | (Request::Flush, Reply::Ok)
            | (Request::Lookup { .. }, Reply::Addresses(_))
            | (
                Request::Resolve { .. } | Request::Reverse { .. },
                Reply::Answer(_)
            )
    )
}
fn exchange(path: &[u8], timeout_ms: u64, request: Request) -> io::Result<ResultHandle> {
    let end = deadline(timeout_ms)?;
    let mut channel = Channel::connect(path, end)?;
    channel.send(&request, end)?;
    let reply = receive_complete(&mut channel, &request, &mut Vec::new(), end)?;
    reply_result(reply)
}
fn receive_complete(
    channel: &mut Channel,
    request: &Request,
    _pending: &mut Vec<Reply>,
    end: std::time::Instant,
) -> io::Result<Reply> {
    let reply = channel.receive(end)?;
    if !expected(request, &reply) {
        return Err(invalid("unexpected reply type"));
    }
    Ok(reply)
}
/// Read the daemon status.
/// # Safety
/// All spans and handles must obey the module's borrowed input contract.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn peios_resolvd_get_status(
    path: abi::Bytes,
    timeout_ms: u64,
) -> *mut ResultHandle {
    finish((|| {
        // SAFETY: the caller guarantees every input span is live for this call.
        unsafe { exchange(inputs::bytes(path)?, timeout_ms, Request::Status) }
    })())
}
/// Look up addresses and their provenance.
/// # Safety
/// All spans and handles must obey the module's borrowed input contract.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn peios_resolvd_lookup(
    path: abi::Bytes,
    timeout_ms: u64,
    name: abi::Bytes,
    family: u32,
) -> *mut ResultHandle {
    finish((|| {
        // SAFETY: the caller guarantees every input span is live for this call.
        unsafe {
            exchange(
                inputs::bytes(path)?,
                timeout_ms,
                Request::Lookup {
                    name: inputs::text(name)?.into(),
                    family: match family {
                        0 => resolvd_core::Family::Any,
                        1 => resolvd_core::Family::V4,
                        2 => resolvd_core::Family::V6,
                        _ => return Err(invalid("invalid address family")),
                    },
                },
            )
        }
    })())
}
/// Resolve a DNS record type.
/// # Safety
/// All spans and handles must obey the module's borrowed input contract.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn peios_resolvd_resolve(
    path: abi::Bytes,
    timeout_ms: u64,
    name: abi::Bytes,
    record_type: u16,
    no_cache: u32,
) -> *mut ResultHandle {
    finish((|| {
        // SAFETY: the caller guarantees every input span is live for this call.
        unsafe {
            exchange(
                inputs::bytes(path)?,
                timeout_ms,
                Request::Resolve {
                    name: inputs::text(name)?.into(),
                    rtype: record_type,
                    no_cache: inputs::boolean(no_cache)?,
                },
            )
        }
    })())
}
/// Look up the names of an IP address.
/// # Safety
/// All spans and handles must obey the module's borrowed input contract.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn peios_resolvd_reverse(
    path: abi::Bytes,
    timeout_ms: u64,
    address: abi::Bytes,
) -> *mut ResultHandle {
    finish((|| {
        // SAFETY: the caller guarantees every input span is live for this call.
        unsafe {
            exchange(
                inputs::bytes(path)?,
                timeout_ms,
                Request::Reverse {
                    address: inputs::text(address)?
                        .parse()
                        .map_err(|_| invalid("invalid IP address"))?,
                },
            )
        }
    })())
}
/// Flush the cache using the caller's existing control rights.
/// # Safety
/// All spans and handles must obey the module's borrowed input contract.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn peios_resolvd_flush(
    path: abi::Bytes,
    timeout_ms: u64,
) -> *mut ResultHandle {
    finish((|| {
        // SAFETY: the caller guarantees every input span is live for this call.
        unsafe { exchange(inputs::bytes(path)?, timeout_ms, Request::Flush) }
    })())
}
