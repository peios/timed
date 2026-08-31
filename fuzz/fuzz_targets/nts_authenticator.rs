//! The authenticator extension field, opened with the wrong key.
//!
//! Two attacker-chosen 16-bit lengths that index into a buffer, which is
//! the shape that produces out-of-bounds reads. Opening always fails here
//! — the key is fixed and the data is random — so what this proves is that
//! *failing* is what happens, rather than a panic or a read past the end.
#![no_main]
use libfuzzer_sys::fuzz_target;
use ntp::nts;

const KEY: [u8; nts::KEY_LEN] = [0x5A; nts::KEY_LEN];

fuzz_target!(|data: &[u8]| {
    if data.len() < 2 {
        return;
    }
    // Split the input into "the datagram" and "the field value", so the
    // offset is also fuzzed rather than fixed — an offset past the end of
    // the buffer is exactly the case that must be refused before slicing.
    let split = data[0] as usize % data.len();
    let (whole, value) = data.split_at(split);
    for at in [0usize, whole.len(), whole.len().saturating_add(1), usize::MAX] {
        let _ = nts::open_authenticator(&KEY, whole, at, value);
    }
});
