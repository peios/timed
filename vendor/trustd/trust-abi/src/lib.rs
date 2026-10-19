//! Generated C layouts. See the installed header for ownership contracts.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct Bytes {
    pub data: *const u8,
    pub len: usize,
}
#[repr(C)]
#[derive(Clone, Copy)]
pub struct Strings {
    pub data: *const Bytes,
    pub len: usize,
}
#[repr(C)]
#[derive(Clone, Copy)]
pub struct OptionalU16 {
    pub present: u32,
    pub value: u16,
}
#[repr(C)]
#[derive(Clone, Copy)]
pub struct Root {
    pub fingerprint: Bytes,
    pub subject: Bytes,
    pub purposes: Strings,
    pub source: u32,
    pub name: Bytes,
    pub not_after: i64,
    pub der: Bytes,
}
#[repr(C)]
#[derive(Clone, Copy)]
pub struct RootList {
    pub data: *const Root,
    pub len: usize,
}
#[repr(C)]
#[derive(Clone, Copy)]
pub struct Status {
    pub generation: u64,
    pub health: u32,
    pub message: Bytes,
    pub shipped: u64,
    pub added: u64,
    pub distrusted: u64,
    pub skipped: u64,
    pub effective: u64,
    pub compat_mode: u32,
    pub rendered: Strings,
}
#[repr(C)]
#[derive(Clone, Copy)]
pub struct StatusList {
    pub data: *const Status,
    pub len: usize,
}
#[repr(C)]
#[derive(Clone, Copy)]
pub struct Parsed {
    pub der: Bytes,
    pub fingerprint: Bytes,
    pub subject: Bytes,
    pub not_after: i64,
    pub subject_hash: Bytes,
}
#[repr(C)]
#[derive(Clone, Copy)]
pub struct ParsedList {
    pub data: *const Parsed,
    pub len: usize,
}
#[repr(C)]
#[derive(Clone, Copy)]
pub struct Details {
    pub common_name: Bytes,
    pub organisation: Bytes,
    pub unit: Bytes,
    pub country: Bytes,
    pub subject: Bytes,
    pub issuer: Bytes,
    pub serial: Bytes,
    pub not_before: i64,
    pub not_after: i64,
    pub key: Bytes,
    pub ca: u32,
}
#[repr(C)]
#[derive(Clone, Copy)]
pub struct DetailsList {
    pub data: *const Details,
    pub len: usize,
}
#[repr(C)]
#[derive(Clone, Copy)]
pub struct Distrusted {
    pub fingerprint: Bytes,
    pub reason: Bytes,
}
#[repr(C)]
#[derive(Clone, Copy)]
pub struct DistrustedList {
    pub data: *const Distrusted,
    pub len: usize,
}
