//! Neutral representation of registry values handed to ingestion.
//!
//! The kernel glue (or a test) reads `Machine\System\Network\Rules\...` and
//! lowers each rule key's values into this shape; the core never sees the
//! registry itself.

use crate::pnp_core::pkm_alloc::{String as PkmString, Vec as PkmVec};

/// One registry value, as ingestion receives it.
#[derive(Debug)]
pub enum RegValue {
    /// An integer value.
    Int(i64),
    /// A string value.
    Str(PkmString),
    /// A list value (flat; elements are ints or strings in practice).
    List(PkmVec<RegValue>),
}

impl RegValue {
    /// Returns the integer if this value is an `Int`.
    pub fn as_int(&self) -> Option<i64> {
        match self {
            RegValue::Int(v) => Some(*v),
            _ => None,
        }
    }

    /// Returns the string if this value is a `Str`.
    pub fn as_str(&self) -> Option<&str> {
        match self {
            RegValue::Str(s) => Some(s.as_str()),
            _ => None,
        }
    }
}
