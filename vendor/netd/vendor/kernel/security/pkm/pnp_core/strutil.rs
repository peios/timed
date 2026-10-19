//! Small helpers over the fallible string type, shared by both compile
//! targets (the kernel-mode `String` has no `From<&str>`).

use crate::pnp_core::pkm_alloc::{AllocError, String as PkmString};

/// Fallibly copies a `&str` into a PKM string.
pub fn str_to_pkm(s: &str) -> Result<PkmString, AllocError> {
    let mut out = PkmString::new();
    for c in s.chars() {
        out.push(c)?;
    }
    Ok(out)
}

/// Joins a parent attribution path and a rule name with `/`. An empty
/// parent yields just the name (tree roots).
pub fn join_path(parent: &str, name: &str) -> Result<PkmString, AllocError> {
    let mut out = PkmString::new();
    if !parent.is_empty() {
        for c in parent.chars() {
            out.push(c)?;
        }
        out.push('/')?;
    }
    for c in name.chars() {
        out.push(c)?;
    }
    Ok(out)
}
