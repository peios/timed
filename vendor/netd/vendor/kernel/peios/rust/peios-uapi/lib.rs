//! Raw Rust ABI bindings generated from include/uapi/pkm.
//! Constants are shared with Kbuild; regenerate using gen.sh.

#![no_std]
#![allow(non_camel_case_types)]

#[path = "../../../security/pkm/kacs/peios_uapi.rs"]
mod zconst;
mod ztypes;

pub use zconst::*;
pub use ztypes::*;
