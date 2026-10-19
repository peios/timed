//! Shared service API. See the installed header for the ownership contract.
//!
//! # Safety
//! Non-null input pointers must be aligned, initialized and readable for their
//! stated lengths. Inputs are borrowed for the call only. Result views remain
//! borrowed until their owning result is freed. Handles must originate from
//! this library. Mutation and destruction require exclusive access.
use std::io;
use std::ptr;
use timed_abi as abi;
use timed_core::{Reply, Request};
mod channel;
mod inputs;
mod views;
use channel::{Channel, deadline, invalid};
use views::Arena;

enum Payload {
    Empty,
    Bytes(abi::Bytes),
    CountryList(abi::CountryList),
    Status(abi::Status),
    SourceInfoList(abi::SourceInfoList),
    Snapshot(abi::Snapshot),
    ServerSpec(abi::ServerSpec),
    ListedList(abi::ListedList),
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
/// Return the independently versioned timed_abi major.
#[unsafe(no_mangle)]
pub extern "C" fn peios_timed_abi_version() -> u32 {
    1
}
/// Release a result and every borrowed view. Null is accepted.
/// # Safety
/// A non-null result must be uniquely owned and come from this library.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn peios_timed_result_free(result: *mut ResultHandle) {
    if !result.is_null() {
        // SAFETY: the caller returns unique ownership of this library allocation.
        drop(unsafe { Box::from_raw(result) });
    }
}
/// Return zero on success, otherwise a POSIX error number. Null is EINVAL.
/// # Safety
/// A non-null result must remain alive and readable for this call.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn peios_timed_result_error(result: *const ResultHandle) -> i32 {
    // SAFETY: caller supplies a live borrowed result or null.
    unsafe { result.as_ref() }.map_or(libc::EINVAL, |result| result.error)
}
/// Return a diagnostic borrowed from result; null produces an absent span.
/// # Safety
/// A non-null result must remain alive and readable for this call.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn peios_timed_result_message(result: *const ResultHandle) -> abi::Bytes {
    // SAFETY: caller supplies a live borrowed result or null.
    unsafe { result.as_ref() }.map_or_else(views::absent, |result| result.message)
}
/// Return a borrowed Status view, or null for a different payload.
/// # Safety
/// A non-null result must remain alive for this call and use of its view.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn peios_timed_result_status(
    result: *const ResultHandle,
) -> *const abi::Status {
    // SAFETY: the caller borrows a live result or supplies null.
    match unsafe { result.as_ref() }.map(|result| &result.payload) {
        Some(Payload::Status(view)) => view,
        _ => ptr::null(),
    }
}
/// Return a borrowed Snapshot view, or null for a different payload.
/// # Safety
/// A non-null result must remain alive for this call and use of its view.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn peios_timed_result_snapshot(
    result: *const ResultHandle,
) -> *const abi::Snapshot {
    // SAFETY: the caller borrows a live result or supplies null.
    match unsafe { result.as_ref() }.map(|result| &result.payload) {
        Some(Payload::Snapshot(view)) => view,
        _ => ptr::null(),
    }
}
/// Return a borrowed ServerSpec view, or null for a different payload.
/// # Safety
/// A non-null result must remain alive for this call and use of its view.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn peios_timed_result_server_spec(
    result: *const ResultHandle,
) -> *const abi::ServerSpec {
    // SAFETY: the caller borrows a live result or supplies null.
    match unsafe { result.as_ref() }.map(|result| &result.payload) {
        Some(Payload::ServerSpec(view)) => view,
        _ => ptr::null(),
    }
}
/// Return a borrowed SourceInfoList view, or null for a different payload.
/// # Safety
/// A non-null result must remain alive for this call and use of its view.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn peios_timed_result_source_info_list(
    result: *const ResultHandle,
) -> *const abi::SourceInfoList {
    // SAFETY: the caller borrows a live result or supplies null.
    match unsafe { result.as_ref() }.map(|result| &result.payload) {
        Some(Payload::SourceInfoList(view)) => view,
        _ => ptr::null(),
    }
}
/// Return a borrowed ListedList view, or null for a different payload.
/// # Safety
/// A non-null result must remain alive for this call and use of its view.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn peios_timed_result_listed_list(
    result: *const ResultHandle,
) -> *const abi::ListedList {
    // SAFETY: the caller borrows a live result or supplies null.
    match unsafe { result.as_ref() }.map(|result| &result.payload) {
        Some(Payload::ListedList(view)) => view,
        _ => ptr::null(),
    }
}
fn reply_result(reply: Reply) -> io::Result<ResultHandle> {
    let mut result = ResultHandle::default();
    result.payload = match reply {
        Reply::Ok => Payload::Empty,
        Reply::Error(message) => return Err(io::Error::other(message)),
        Reply::Status(value) => Payload::Status(result.arena.status(&value)),
        Reply::Snapshot(value) => Payload::Snapshot(result.arena.snapshot(&value)),
        Reply::Sources { sources, .. } => {
            Payload::SourceInfoList(result.arena.source_info_list(&sources))
        }
    };
    Ok(result)
}
fn expected(request: &Request, reply: &Reply) -> bool {
    matches!(
        (request, reply),
        (_, Reply::Error(_))
            | (Request::Status, Reply::Status(_))
            | (Request::Reload | Request::Set { .. }, Reply::Ok)
            | (Request::Sources, Reply::Sources { .. })
            | (Request::Subscribe, Reply::Snapshot(_))
    )
}
fn exchange(path: &[u8], timeout_ms: u64, request: Request) -> io::Result<ResultHandle> {
    let end = deadline(timeout_ms)?;
    let mut channel = Channel::connect(path, end)?;
    channel.send(&request, end)?;
    let reply = receive_complete(&mut channel, &request, &mut Vec::new(), end)?;
    reply_result(reply)
}
// Bound a complete snapshot as well as each individual protocol frame.
const MAX_SNAPSHOT_BYTES: usize = 16 * 1024 * 1024;
fn receive_complete(
    channel: &mut Channel,
    request: &Request,
    pending: &mut Vec<Reply>,
    end: std::time::Instant,
) -> io::Result<Reply> {
    let mut size: usize = pending.iter().map(|reply| reply.encode().len()).sum();
    loop {
        let reply = channel.receive(end)?;
        if !expected(request, &reply) {
            return Err(invalid("unexpected reply type"));
        }
        if !matches!(reply, Reply::Sources { .. }) {
            pending.clear();
            return Ok(reply);
        }
        size = size
            .checked_add(reply.encode().len())
            .filter(|size| *size <= MAX_SNAPSHOT_BYTES)
            .ok_or_else(|| invalid("snapshot exceeds 16 MiB"))?;
        let more = matches!(&reply, Reply::Sources { more: true, .. });
        pending.push(reply);
        if !more {
            break;
        }
    }
    let mut sources = Vec::new();
    for reply in pending.drain(..) {
        if let Reply::Sources { sources: batch, .. } = reply {
            sources.extend(batch);
        }
    }
    Ok(Reply::Sources {
        sources,
        more: false,
    })
}
/// Read the daemon status.
/// # Safety
/// All spans and handles must obey the module's borrowed input contract.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn peios_timed_get_status(
    path: abi::Bytes,
    timeout_ms: u64,
) -> *mut ResultHandle {
    finish((|| {
        // SAFETY: the caller guarantees every input span is live for this call.
        unsafe { exchange(inputs::bytes(path)?, timeout_ms, Request::Status) }
    })())
}
/// Read the complete source list.
/// # Safety
/// All spans and handles must obey the module's borrowed input contract.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn peios_timed_sources(
    path: abi::Bytes,
    timeout_ms: u64,
) -> *mut ResultHandle {
    finish((|| {
        // SAFETY: the caller guarantees every input span is live for this call.
        unsafe { exchange(inputs::bytes(path)?, timeout_ms, Request::Sources) }
    })())
}
/// Reload time policy using the caller's existing rights.
/// # Safety
/// All spans and handles must obey the module's borrowed input contract.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn peios_timed_reload(
    path: abi::Bytes,
    timeout_ms: u64,
) -> *mut ResultHandle {
    finish((|| {
        // SAFETY: the caller guarantees every input span is live for this call.
        unsafe { exchange(inputs::bytes(path)?, timeout_ms, Request::Reload) }
    })())
}
/// Set manual time; the daemon enforces authorization and mode.
/// # Safety
/// All spans and handles must obey the module's borrowed input contract.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn peios_timed_set(
    path: abi::Bytes,
    timeout_ms: u64,
    seconds: i64,
    nanos: u32,
) -> *mut ResultHandle {
    finish((|| {
        // SAFETY: the caller guarantees every input span is live for this call.
        unsafe {
            exchange(inputs::bytes(path)?, timeout_ms, {
                if nanos >= 1_000_000_000 {
                    return Err(invalid("nanoseconds out of range"));
                }
                Request::Set { seconds, nanos }
            })
        }
    })())
}
/// Parse a server configuration entry.
/// # Safety
/// All spans and handles must obey the module's borrowed input contract.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn peios_timed_parse_server(entry: abi::Bytes) -> *mut ResultHandle {
    finish((|| {
        // SAFETY: the caller guarantees every input span is live for this call.
        unsafe {
            let value = timed_core::servers::parse_server(inputs::text(entry)?).map_err(invalid)?;
            let mut result = ResultHandle::default();
            result.payload = Payload::ServerSpec(result.arena.server_spec(&value));
            Ok(result)
        }
    })())
}
/// Check the syntax of a time-zone name.
/// # Safety
/// All spans and handles must obey the module's borrowed input contract.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn peios_timed_check_zone(name: abi::Bytes) -> *mut ResultHandle {
    finish((|| {
        // SAFETY: the caller guarantees every input span is live for this call.
        unsafe {
            timed_core::zone::check_name(inputs::text(name)?).map_err(invalid)?;
            Ok(ResultHandle::default())
        }
    })())
}
/// Check that a named time zone is installed.
/// # Safety
/// All spans and handles must obey the module's borrowed input contract.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn peios_timed_installed_zone(name: abi::Bytes) -> *mut ResultHandle {
    finish((|| {
        // SAFETY: the caller guarantees every input span is live for this call.
        unsafe {
            timed_core::zone::installed(inputs::text(name)?).map_err(invalid)?;
            Ok(ResultHandle::default())
        }
    })())
}
/// List installed time-zone metadata.
#[unsafe(no_mangle)]
pub extern "C" fn peios_timed_zones() -> *mut ResultHandle {
    let value = timed_core::zone::list();
    let mut result = ResultHandle::default();
    result.payload = Payload::ListedList(result.arena.listed_list(&value));
    finish(Ok(result))
}

/// An exclusively owned stream with partial-frame and partial-snapshot state.
pub struct Subscription {
    channel: Option<Channel>,
    request: Request,
    pending: Vec<Reply>,
}
/// Start a subscription. The first next call reads the initial update or refusal.
/// # Safety
/// Inputs obey the module contract. out must be an exclusive writable slot.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn peios_timed_subscribe(
    path: abi::Bytes,
    timeout_ms: u64,
    out: *mut *mut Subscription,
) -> *mut ResultHandle {
    finish((|| {
        // SAFETY: caller lends an exclusive slot or supplies null.
        let out = unsafe { out.as_mut() }.ok_or_else(|| invalid("null subscription output"))?;
        *out = ptr::null_mut();
        // SAFETY: all input spans are readable for this call.
        let request = Request::Subscribe;
        let end = deadline(timeout_ms)?;
        // SAFETY: path is a live borrowed span.
        let mut channel = Channel::connect(unsafe { inputs::bytes(path)? }, end)?;
        channel.send(&request, end)?;
        *out = Box::into_raw(Box::new(Subscription {
            channel: Some(channel),
            request,
            pending: Vec::new(),
        }));
        Ok(ResultHandle::default())
    })())
}
/// Read one complete update. Timeouts preserve partial input for the next call.
/// Other transport/protocol failures close the stream; callers may resubscribe.
/// # Safety
/// subscription must be null or a live, exclusively borrowed handle.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn peios_timed_subscription_next(
    subscription: *mut Subscription,
    timeout_ms: u64,
) -> *mut ResultHandle {
    finish((|| {
        // SAFETY: caller lends its live handle exclusively or supplies null.
        let subscription =
            unsafe { subscription.as_mut() }.ok_or_else(|| invalid("null subscription"))?;
        let end = deadline(timeout_ms)?;
        let channel = subscription
            .channel
            .as_mut()
            .ok_or_else(|| io::Error::new(io::ErrorKind::NotConnected, "subscription is closed"))?;
        let outcome = receive_complete(
            channel,
            &subscription.request,
            &mut subscription.pending,
            end,
        )
        .and_then(reply_result);
        if outcome
            .as_ref()
            .is_err_and(|error| error.kind() != io::ErrorKind::TimedOut)
        {
            subscription.channel = None;
            subscription.pending.clear();
        }
        outcome
    })())
}
/// Close and free a subscription. Null is accepted.
/// # Safety
/// A non-null handle must be uniquely owned and originate from this library.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn peios_timed_subscription_free(subscription: *mut Subscription) {
    if !subscription.is_null() {
        // SAFETY: the caller returns unique ownership of this allocation.
        drop(unsafe { Box::from_raw(subscription) });
    }
}

/// Return a borrowed country list, or null for a different result.
/// # Safety
/// The result must remain alive for this call and every use of its view.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn peios_timed_result_country_list(
    result: *const ResultHandle,
) -> *const abi::CountryList {
    // SAFETY: caller borrows a live result or supplies null.
    match unsafe { result.as_ref() }.map(|result| &result.payload) {
        Some(Payload::CountryList(view)) => view,
        _ => ptr::null(),
    }
}
/// Return bytes borrowed from a result, or an absent span for a different result.
/// # Safety
/// The result must remain alive for this call and every use of its view.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn peios_timed_result_bytes(result: *const ResultHandle) -> abi::Bytes {
    // SAFETY: caller borrows a live result or supplies null.
    match unsafe { result.as_ref() }.map(|result| &result.payload) {
        Some(Payload::Bytes(view)) => *view,
        _ => views::absent(),
    }
}
/// List country names from the installed time-zone database.
#[unsafe(no_mangle)]
pub extern "C" fn peios_timed_countries() -> *mut ResultHandle {
    let countries = timed_core::zone::countries()
        .into_iter()
        .map(|(code, name)| timed_core::zone::Country { code, name })
        .collect::<Vec<_>>();
    let mut result = ResultHandle::default();
    result.payload = Payload::CountryList(result.arena.country_list(&countries));
    finish(Ok(result))
}
/// Get the database path of a syntactically valid zone name; does not check existence.
/// # Safety
/// The input span must satisfy the module's borrowed input contract.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn peios_timed_zone_path(name: abi::Bytes) -> *mut ResultHandle {
    finish((|| {
        // SAFETY: caller provides a live borrowed UTF-8 input span.
        let name = unsafe { inputs::text(name) }?;
        timed_core::zone::check_name(name).map_err(invalid)?;
        let path = timed_core::zone::path(name);
        let mut result = ResultHandle::default();
        result.payload = Payload::Bytes(
            result
                .arena
                .text(path.to_str().expect("zone paths are ASCII")),
        );
        Ok(result)
    })())
}
