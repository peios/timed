//! Validate C representations before handing owned data to the semantic core.

use std::io;
use std::mem::size_of;
use std::slice;
use std::str;

use trust_abi as abi;

use crate::channel::invalid;

const MAX_TEXT_BYTES: usize = 4 * 1024 * 1024;

pub(crate) unsafe fn array<'a, T>(pointer: *const T, count: usize) -> io::Result<&'a [T]> {
    if count == 0 {
        return Ok(&[]);
    }
    if pointer.is_null() || count > isize::MAX as usize / size_of::<T>().max(1) {
        return Err(invalid("invalid array span"));
    }
    // SAFETY: caller guarantees count initialized, aligned elements in a live
    // allocation, borrowed for 'a. The checks satisfy Rust's null/size bounds.
    Ok(unsafe { slice::from_raw_parts(pointer, count) })
}

pub(crate) unsafe fn bytes<'a>(value: abi::Bytes) -> io::Result<&'a [u8]> {
    if value.len > MAX_TEXT_BYTES {
        return Err(invalid("input span exceeds 4 MiB"));
    }
    // SAFETY: forwarded from the caller's span lifetime and validity contract.
    unsafe { array(value.data, value.len) }
}

pub(crate) unsafe fn text<'a>(value: abi::Bytes) -> io::Result<&'a str> {
    // SAFETY: caller supplies a live borrowed byte span; UTF-8 is checked here.
    str::from_utf8(unsafe { bytes(value)? }).map_err(|_| invalid("text is not UTF-8"))
}

pub(crate) fn boolean(value: u32) -> io::Result<bool> {
    match value {
        0 => Ok(false),
        1 => Ok(true),
        _ => Err(invalid("boolean must be 0 or 1")),
    }
}
pub(crate) unsafe fn maybe_text<'a>(value: abi::Bytes) -> io::Result<Option<&'a str>> {
    if value.data.is_null() {
        if value.len != 0 {
            return Err(invalid("absent text has nonzero length"));
        }
        return Ok(None);
    }
    // SAFETY: the caller supplies a readable span for the requested lifetime.
    unsafe { text(value) }.map(Some)
}
pub(crate) unsafe fn strings(value: abi::Strings) -> io::Result<Vec<String>> {
    if value.len > 65536 {
        return Err(invalid("too many strings"));
    }
    // SAFETY: caller supplies the array and its nested borrowed spans.
    let values = unsafe { array(value.data, value.len)? };
    let mut total = 0usize;
    values
        .iter()
        .map(|value| {
            total = total
                .checked_add(value.len)
                .filter(|total| *total <= MAX_TEXT_BYTES)
                .ok_or_else(|| invalid("string list exceeds 4 MiB"))?;
            // SAFETY: each span belongs to the caller's borrowed array.
            unsafe { text(*value) }.map(str::to_owned)
        })
        .collect()
}
