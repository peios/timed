//! Cargo entry point for the same semantic source compiled by Kbuild.

#![cfg_attr(not(test), no_std)]

extern crate alloc;

use peios_uapi;

#[path = "../../../security/pkm/pnp_core/mod.rs"]
mod pnp_core;

pub use pnp_core::*;
