//! Random bytes, from the kernel.
//!
//! Two things need them and both are security-critical. The NTS unique
//! identifier is what makes a reply impossible to forge without seeing the
//! request; the transmit timestamp of a plain NTP request is the *only*
//! thing that plays that role when NTS is not in use. Both must come from a
//! source an attacker cannot predict, which means the kernel's and not a
//! seeded generator of our own.

use std::io;

/// Fill a buffer with random bytes.
///
/// `getrandom(2)` without `GRND_NONBLOCK`, so early in boot it blocks until
/// the pool is initialised rather than returning predictable bytes. That
/// wait is the right trade: a time client that started a few hundred
/// milliseconds sooner with forgeable requests would be worse than one that
/// waited.
pub fn fill(buffer: &mut [u8]) -> io::Result<()> {
    let mut filled = 0;
    while filled < buffer.len() {
        // Safe: writing into a buffer we own, for a length within it.
        let n = unsafe {
            libc::getrandom(
                buffer[filled..].as_mut_ptr() as *mut libc::c_void,
                buffer.len() - filled,
                0,
            )
        };
        if n < 0 {
            let error = io::Error::last_os_error();
            // A signal during the initial block is not a failure.
            if error.kind() == io::ErrorKind::Interrupted {
                continue;
            }
            return Err(error);
        }
        if n == 0 {
            return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "getrandom returned nothing"));
        }
        filled += n as usize;
    }
    Ok(())
}

pub fn array<const N: usize>() -> io::Result<[u8; N]> {
    let mut out = [0u8; N];
    fill(&mut out)?;
    Ok(out)
}

pub fn u64_value() -> io::Result<u64> {
    Ok(u64::from_ne_bytes(array::<8>()?))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn it_returns_different_bytes_each_time() {
        // Not a test of randomness — a test that we are actually calling
        // the kernel and not returning a zeroed buffer, which is the way
        // this fails silently.
        let a = array::<32>().unwrap();
        let b = array::<32>().unwrap();
        assert_ne!(a, b);
        assert_ne!(a, [0u8; 32]);
    }

    #[test]
    fn a_large_request_is_filled_completely() {
        let mut buffer = vec![0u8; 4096];
        fill(&mut buffer).unwrap();
        assert!(buffer.iter().any(|&b| b != 0));
        // The tail is the part a partial read would leave zeroed.
        assert!(buffer[4000..].iter().any(|&b| b != 0));
    }
}
