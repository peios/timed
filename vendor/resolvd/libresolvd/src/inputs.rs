//! Validate C representations before handing owned data to the semantic core.

use std::io;
use std::mem::size_of;
use std::slice;
use std::str;

use resolvd_abi as abi;

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
