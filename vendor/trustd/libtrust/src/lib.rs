//! Shared service API. See the installed header for the ownership contract.
//!
//! # Safety
//! Non-null input pointers must be aligned, initialized and readable for their
//! stated lengths. Inputs are borrowed for the call only. Result views remain
//! borrowed until their owning result is freed. Handles must originate from
//! this library. Mutation and destruction require exclusive access.
use std::io;
use std::ptr;
use trust_abi as abi;
use trust_core::{Reply, Request};
mod channel;
mod inputs;
mod views;
use channel::{Channel, deadline, invalid};
use views::Arena;

enum Payload {
    Empty,
    Text(abi::Bytes),
    Bytes(abi::Bytes),
    Boolean(u32),
    RootList(abi::RootList),
    Status(abi::Status),
    Parsed(abi::Parsed),
    Details(abi::Details),
    DistrustedList(abi::DistrustedList),
}
/// Immutable result and storage for every view returned from it.
pub struct ResultHandle {
    generation: u64,
    error: i32,
    message: abi::Bytes,
    arena: Arena,
    payload: Payload,
}
impl Default for ResultHandle {
    fn default() -> Self {
        Self {
            generation: 0,
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
            io::ErrorKind::NotFound => libc::ENOENT,
            _ => libc::EIO,
        });
        result.message = result.arena.text(&error.to_string());
        result
    }
}
fn finish(result: io::Result<ResultHandle>) -> *mut ResultHandle {
    Box::into_raw(Box::new(result.unwrap_or_else(ResultHandle::error)))
}
/// Return the independently versioned trust_abi major.
#[unsafe(no_mangle)]
pub extern "C" fn peios_trust_abi_version() -> u32 {
    1
}
/// Release a result and every borrowed view. Null is accepted.
/// # Safety
/// A non-null result must be uniquely owned and come from this library.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn peios_trust_result_free(result: *mut ResultHandle) {
    if !result.is_null() {
        // SAFETY: the caller returns unique ownership of this library allocation.
        drop(unsafe { Box::from_raw(result) });
    }
}
/// Return zero on success, otherwise a POSIX error number. Null is EINVAL.
/// # Safety
/// A non-null result must remain alive and readable for this call.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn peios_trust_result_error(result: *const ResultHandle) -> i32 {
    // SAFETY: caller supplies a live borrowed result or null.
    unsafe { result.as_ref() }.map_or(libc::EINVAL, |result| result.error)
}
/// Return a diagnostic borrowed from result; null produces an absent span.
/// # Safety
/// A non-null result must remain alive and readable for this call.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn peios_trust_result_message(result: *const ResultHandle) -> abi::Bytes {
    // SAFETY: caller supplies a live borrowed result or null.
    unsafe { result.as_ref() }.map_or_else(views::absent, |result| result.message)
}
/// Return a borrowed Text view, or null for a different payload.
/// # Safety
/// A non-null result must remain alive for this call and use of its view.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn peios_trust_result_text(result: *const ResultHandle) -> *const abi::Bytes {
    // SAFETY: the caller borrows a live result or supplies null.
    match unsafe { result.as_ref() }.map(|result| &result.payload) {
        Some(Payload::Text(view)) => view,
        _ => ptr::null(),
    }
}
/// Return a borrowed Bytes view, or null for a different payload.
/// # Safety
/// A non-null result must remain alive for this call and use of its view.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn peios_trust_result_bytes(
    result: *const ResultHandle,
) -> *const abi::Bytes {
    // SAFETY: the caller borrows a live result or supplies null.
    match unsafe { result.as_ref() }.map(|result| &result.payload) {
        Some(Payload::Bytes(view)) => view,
        _ => ptr::null(),
    }
}
/// Return a borrowed Boolean view, or null for a different payload.
/// # Safety
/// A non-null result must remain alive for this call and use of its view.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn peios_trust_result_boolean(result: *const ResultHandle) -> *const u32 {
    // SAFETY: the caller borrows a live result or supplies null.
    match unsafe { result.as_ref() }.map(|result| &result.payload) {
        Some(Payload::Boolean(view)) => view,
        _ => ptr::null(),
    }
}
/// Return a borrowed Status view, or null for a different payload.
/// # Safety
/// A non-null result must remain alive for this call and use of its view.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn peios_trust_result_status(
    result: *const ResultHandle,
) -> *const abi::Status {
    // SAFETY: the caller borrows a live result or supplies null.
    match unsafe { result.as_ref() }.map(|result| &result.payload) {
        Some(Payload::Status(view)) => view,
        _ => ptr::null(),
    }
}
/// Return a borrowed Parsed view, or null for a different payload.
/// # Safety
/// A non-null result must remain alive for this call and use of its view.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn peios_trust_result_parsed(
    result: *const ResultHandle,
) -> *const abi::Parsed {
    // SAFETY: the caller borrows a live result or supplies null.
    match unsafe { result.as_ref() }.map(|result| &result.payload) {
        Some(Payload::Parsed(view)) => view,
        _ => ptr::null(),
    }
}
/// Return a borrowed Details view, or null for a different payload.
/// # Safety
/// A non-null result must remain alive for this call and use of its view.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn peios_trust_result_details(
    result: *const ResultHandle,
) -> *const abi::Details {
    // SAFETY: the caller borrows a live result or supplies null.
    match unsafe { result.as_ref() }.map(|result| &result.payload) {
        Some(Payload::Details(view)) => view,
        _ => ptr::null(),
    }
}
/// Return a borrowed RootList view, or null for a different payload.
/// # Safety
/// A non-null result must remain alive for this call and use of its view.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn peios_trust_result_root_list(
    result: *const ResultHandle,
) -> *const abi::RootList {
    // SAFETY: the caller borrows a live result or supplies null.
    match unsafe { result.as_ref() }.map(|result| &result.payload) {
        Some(Payload::RootList(view)) => view,
        _ => ptr::null(),
    }
}
/// Return a borrowed DistrustedList view, or null for a different payload.
/// # Safety
/// A non-null result must remain alive for this call and use of its view.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn peios_trust_result_distrusted_list(
    result: *const ResultHandle,
) -> *const abi::DistrustedList {
    // SAFETY: the caller borrows a live result or supplies null.
    match unsafe { result.as_ref() }.map(|result| &result.payload) {
        Some(Payload::DistrustedList(view)) => view,
        _ => ptr::null(),
    }
}
fn reply_result(reply: Reply) -> io::Result<ResultHandle> {
    let mut result = ResultHandle::default();
    result.payload = match reply {
        Reply::Ok => Payload::Empty,
        Reply::Error(message) => return Err(io::Error::other(message)),
        Reply::Status(value) => Payload::Status(result.arena.status(&value)),
        Reply::Roots {
            generation, roots, ..
        } => {
            result.generation = generation;
            Payload::RootList(result.arena.root_list(&roots))
        }
    };
    Ok(result)
}
fn expected(request: &Request, reply: &Reply) -> bool {
    matches!(
        (request, reply),
        (_, Reply::Error(_))
            | (Request::Status, Reply::Status(_))
            | (Request::Reload, Reply::Ok)
            | (
                Request::Roots { .. } | Request::Subscribe { .. },
                Reply::Roots { .. }
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
        if !matches!(reply, Reply::Roots { .. }) {
            pending.clear();
            return Ok(reply);
        }
        size = size
            .checked_add(reply.encode().len())
            .filter(|size| *size <= MAX_SNAPSHOT_BYTES)
            .ok_or_else(|| invalid("snapshot exceeds 16 MiB"))?;
        let more = matches!(&reply, Reply::Roots { more: true, .. });
        pending.push(reply);
        if !more {
            break;
        }
    }
    let mut roots = Vec::new();
    let mut generation = None;
    for reply in pending.drain(..) {
        if let Reply::Roots {
            generation: current,
            roots: batch,
            ..
        } = reply
        {
            if generation.is_some_and(|previous| previous != current) {
                return Err(invalid("root generation changed between chunks"));
            }
            generation = Some(current);
            roots.extend(batch);
        }
    }
    Ok(Reply::Roots {
        generation: generation.unwrap_or(0),
        roots,
        more: false,
    })
}
/// Read the daemon status.
/// # Safety
/// All spans and handles must obey the module's borrowed input contract.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn peios_trust_get_status(
    path: abi::Bytes,
    timeout_ms: u64,
) -> *mut ResultHandle {
    finish((|| {
        // SAFETY: the caller guarantees every input span is live for this call.
        unsafe { exchange(inputs::bytes(path)?, timeout_ms, Request::Status) }
    })())
}
/// Read a complete, generation-consistent trust snapshot.
/// # Safety
/// All spans and handles must obey the module's borrowed input contract.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn peios_trust_roots(
    path: abi::Bytes,
    timeout_ms: u64,
    with_der: u32,
    purpose: abi::Bytes,
) -> *mut ResultHandle {
    finish((|| {
        // SAFETY: the caller guarantees every input span is live for this call.
        unsafe {
            exchange(
                inputs::bytes(path)?,
                timeout_ms,
                Request::Roots {
                    with_der: inputs::boolean(with_der)?,
                    purpose: inputs::maybe_text(purpose)?.map(str::to_owned),
                },
            )
        }
    })())
}
/// Request trust-store recomposition using the caller's rights.
/// # Safety
/// All spans and handles must obey the module's borrowed input contract.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn peios_trust_reload(
    path: abi::Bytes,
    timeout_ms: u64,
) -> *mut ResultHandle {
    finish((|| {
        // SAFETY: the caller guarantees every input span is live for this call.
        unsafe { exchange(inputs::bytes(path)?, timeout_ms, Request::Reload) }
    })())
}
fn management_error(error: trust_client_core::Error) -> io::Error {
    let kind = match &error {
        trust_client_core::Error::Denied(_) => io::ErrorKind::PermissionDenied,
        trust_client_core::Error::NotFound(_) => io::ErrorKind::NotFound,
        _ => io::ErrorKind::Other,
    };
    io::Error::new(kind, error)
}
/// Decode exactly one PEM or DER certificate.
/// # Safety
/// All spans and handles must obey the module's borrowed input contract.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn peios_trust_certificate(
    bytes: abi::Bytes,
    description: abi::Bytes,
) -> *mut ResultHandle {
    finish((|| {
        // SAFETY: the caller guarantees every input span is live for this call.
        unsafe {
            let value =
                trust_client_core::certificate(inputs::bytes(bytes)?, inputs::text(description)?)
                    .map_err(management_error)?;
            let mut result = ResultHandle::default();
            result.payload = Payload::Bytes(result.arena.bytes(&value));
            Ok(result)
        }
    })())
}
/// Inspect certificate fields without trusting the certificate.
/// # Safety
/// All spans and handles must obey the module's borrowed input contract.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn peios_trust_inspect(der: abi::Bytes) -> *mut ResultHandle {
    finish((|| {
        // SAFETY: the caller guarantees every input span is live for this call.
        unsafe {
            let value = trust_core::cert::describe(inputs::bytes(der)?)
                .map_err(|error| invalid(error.to_string()))?;
            let mut result = ResultHandle::default();
            result.payload = Payload::Details(result.arena.details(&value));
            Ok(result)
        }
    })())
}
/// Validate a candidate root using the existing certificate policy.
/// # Safety
/// All spans and handles must obey the module's borrowed input contract.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn peios_trust_vet(der: abi::Bytes) -> *mut ResultHandle {
    finish((|| {
        // SAFETY: the caller guarantees every input span is live for this call.
        unsafe {
            let value = trust_client_core::vet(inputs::bytes(der)?)
                .map_err(|error| invalid(error.to_string()))?;
            let mut result = ResultHandle::default();
            result.payload = Payload::Parsed(result.arena.parsed(&value));
            Ok(result)
        }
    })())
}
/// Check whether a certificate-store name is usable.
/// # Safety
/// All spans and handles must obey the module's borrowed input contract.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn peios_trust_usable_name(name: abi::Bytes) -> *mut ResultHandle {
    finish((|| {
        // SAFETY: the caller guarantees every input span is live for this call.
        unsafe {
            let value = trust_client_core::usable_name(inputs::text(name)?);
            Ok(ResultHandle {
                payload: Payload::Boolean(u32::from(value)),
                ..ResultHandle::default()
            })
        }
    })())
}
/// Check the caller's reload access.
#[unsafe(no_mangle)]
pub extern "C" fn peios_trust_may_reload() -> *mut ResultHandle {
    finish(Ok(ResultHandle {
        payload: Payload::Boolean(u32::from(trust_client_core::may_reload())),
        ..ResultHandle::default()
    }))
}
/// Check the caller's registry write access.
#[unsafe(no_mangle)]
pub extern "C" fn peios_trust_may_change() -> *mut ResultHandle {
    finish(
        trust_client_core::may_change()
            .map_err(management_error)
            .map(|()| ResultHandle::default()),
    )
}
/// Check compatibility-output configuration access.
#[unsafe(no_mangle)]
pub extern "C" fn peios_trust_may_set_compat() -> *mut ResultHandle {
    finish(
        trust_client_core::may_set_compat()
            .map_err(management_error)
            .map(|()| ResultHandle::default()),
    )
}
/// Set compatibility output mode as the caller.
#[unsafe(no_mangle)]
pub extern "C" fn peios_trust_set_compat(mode: u32) -> *mut ResultHandle {
    finish(
        trust_client_core::set_compat(mode)
            .map_err(management_error)
            .map(|()| ResultHandle::default()),
    )
}
/// Add a certificate under the caller's registry permissions.
/// # Safety
/// All spans and handles must obey the module's borrowed input contract.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn peios_trust_add(
    name: abi::Bytes,
    der: abi::Bytes,
    purposes: abi::Strings,
) -> *mut ResultHandle {
    finish((|| {
        // SAFETY: the caller guarantees every input span is live for this call.
        unsafe {
            let value = trust_client_core::add(
                inputs::text(name)?,
                inputs::bytes(der)?,
                &inputs::strings(purposes)?,
            )
            .map_err(management_error)?;
            let mut result = ResultHandle::default();
            result.payload = Payload::Parsed(result.arena.parsed(&value));
            Ok(result)
        }
    })())
}
/// Remove an added certificate as the caller.
/// # Safety
/// All spans and handles must obey the module's borrowed input contract.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn peios_trust_remove(name: abi::Bytes) -> *mut ResultHandle {
    finish((|| {
        // SAFETY: the caller guarantees every input span is live for this call.
        unsafe {
            trust_client_core::remove(inputs::text(name)?).map_err(management_error)?;
            Ok(ResultHandle::default())
        }
    })())
}
/// Read durable distrust entries.
#[unsafe(no_mangle)]
pub extern "C" fn peios_trust_get_distrusted() -> *mut ResultHandle {
    finish(
        trust_client_core::distrusted()
            .map_err(management_error)
            .map(|value| {
                let mut result = ResultHandle::default();
                result.payload = Payload::DistrustedList(result.arena.distrusted_list(&value));
                result
            }),
    )
}
/// Distrust a fingerprint as the caller; return the matching root subject.
/// # Safety
/// All spans and handles must obey the module's borrowed input contract.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn peios_trust_distrust(
    fingerprint: abi::Bytes,
    reason: abi::Bytes,
) -> *mut ResultHandle {
    finish((|| {
        // SAFETY: the caller guarantees every input span is live for this call.
        unsafe {
            let value =
                trust_client_core::distrust(inputs::text(fingerprint)?, inputs::text(reason)?)
                    .map_err(management_error)?;
            let mut result = ResultHandle::default();
            result.payload = Payload::Text(result.arena.maybe_text(value.as_deref()));
            Ok(result)
        }
    })())
}
/// Remove a distrust entry as the caller.
/// # Safety
/// All spans and handles must obey the module's borrowed input contract.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn peios_trust_restore(fingerprint: abi::Bytes) -> *mut ResultHandle {
    finish((|| {
        // SAFETY: the caller guarantees every input span is live for this call.
        unsafe {
            let value =
                trust_client_core::restore(inputs::text(fingerprint)?).map_err(management_error)?;
            let mut result = ResultHandle::default();
            result.payload = Payload::Text(result.arena.text(&value));
            Ok(result)
        }
    })())
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
pub unsafe extern "C" fn peios_trust_subscribe(
    path: abi::Bytes,
    timeout_ms: u64,
    with_der: u32,
    out: *mut *mut Subscription,
) -> *mut ResultHandle {
    finish((|| {
        // SAFETY: caller lends an exclusive slot or supplies null.
        let out = unsafe { out.as_mut() }.ok_or_else(|| invalid("null subscription output"))?;
        *out = ptr::null_mut();
        let request = Request::Subscribe {
            with_der: inputs::boolean(with_der)?,
        };
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
pub unsafe extern "C" fn peios_trust_subscription_next(
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
pub unsafe extern "C" fn peios_trust_subscription_free(subscription: *mut Subscription) {
    if !subscription.is_null() {
        // SAFETY: the caller returns unique ownership of this allocation.
        drop(unsafe { Box::from_raw(subscription) });
    }
}
/// Return the generation of a roots result; zero for other payloads or null.
/// # Safety
/// A non-null result must be borrowed from this library and remain alive.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn peios_trust_result_generation(result: *const ResultHandle) -> u64 {
    // SAFETY: caller supplies a live borrowed result or null.
    unsafe { result.as_ref() }.map_or(0, |result| result.generation)
}

/// Resolve an unambiguous certificate fingerprint prefix using the caller's access.
/// # Safety
/// The argument must be a readable borrowed UTF-8 span for this call.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn peios_trust_resolve(argument: abi::Bytes) -> *mut ResultHandle {
    finish((|| {
        // SAFETY: caller lends the argument span for this call.
        let value = trust_client_core::resolve(unsafe { inputs::text(argument)? })
            .map_err(management_error)?;
        let mut result = ResultHandle::default();
        result.payload = Payload::Text(result.arena.text(&value));
        Ok(result)
    })())
}
