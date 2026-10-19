//! Name hashing for the machinery stores.
//!
//! Tag names and counter stream names cross into the kernel stores as
//! 64-bit hashes (the flow tag table is `(hash, value)` pairs, the counter
//! tables are keyed by stream hash). Every name in existence comes from the
//! forest, so ingestion checks the whole name set for collisions and
//! refuses the generation on one — within a running policy the hash is a
//! deterministic identity, not a probabilistic one.

/// FNV-1a, 64-bit. Stable across builds and generations by construction:
/// a flow tagged under one generation reads back under the next.
pub fn name_hash(name: &str) -> u64 {
    const OFFSET: u64 = 0xcbf2_9ce4_8422_2325;
    const PRIME: u64 = 0x0000_0100_0000_01b3;
    let mut h = OFFSET;
    for b in name.bytes() {
        h ^= u64::from(b);
        h = h.wrapping_mul(PRIME);
    }
    h
}

#[cfg(test)]
mod tests {
    use super::name_hash;

    #[test]
    fn hash_is_stable_and_distinguishes_names() {
        assert_eq!(name_hash("ssh"), name_hash("ssh"));
        assert_ne!(name_hash("ssh"), name_hash("SSH"));
        assert_ne!(name_hash("a"), name_hash("b"));
        // The FNV-1a test vector for the empty string.
        assert_eq!(name_hash(""), 0xcbf2_9ce4_8422_2325);
    }
}
