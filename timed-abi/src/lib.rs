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
pub struct SourceInfo {
    pub name: Bytes,
    pub address: Bytes,
    pub origin: u32,
    pub auth: u32,
    pub state: u32,
    pub stratum: u32,
    pub reference: Bytes,
    pub reach: u32,
    pub poll: i32,
    pub last: f64,
    pub offset: f64,
    pub delay: f64,
    pub jitter: f64,
    pub root_distance: f64,
    pub cookies: u32,
    pub note: Bytes,
}
#[repr(C)]
#[derive(Clone, Copy)]
pub struct SourceInfoList {
    pub data: *const SourceInfo,
    pub len: usize,
}
#[repr(C)]
#[derive(Clone, Copy)]
pub struct Status {
    pub generation: u64,
    pub sync: u32,
    pub system_peer: Bytes,
    pub stratum: u32,
    pub offset: f64,
    pub frequency_ppm: f64,
    pub jitter: f64,
    pub root_distance: f64,
    pub root_delay: f64,
    pub root_dispersion: f64,
    pub leap: i32,
    pub stepped: f64,
    pub updates: u64,
    pub last_update: f64,
    pub sources: u32,
    pub selected: u32,
    pub floor: i64,
    pub manual: u32,
    pub zone: Bytes,
}
#[repr(C)]
#[derive(Clone, Copy)]
pub struct StatusList {
    pub data: *const Status,
    pub len: usize,
}
#[repr(C)]
#[derive(Clone, Copy)]
pub struct Snapshot {
    pub generation: u64,
    pub leap: u32,
    pub stratum: u32,
    pub reference_id: Bytes,
    pub reference_time: f64,
    pub root_delay: f64,
    pub root_dispersion: f64,
    pub precision: i32,
    pub at: f64,
    pub synchronised: u32,
}
#[repr(C)]
#[derive(Clone, Copy)]
pub struct SnapshotList {
    pub data: *const Snapshot,
    pub len: usize,
}
#[repr(C)]
#[derive(Clone, Copy)]
pub struct ServerSpec {
    pub host: Bytes,
    pub port: OptionalU16,
    pub prefer: u32,
    pub unauthenticated: u32,
}
#[repr(C)]
#[derive(Clone, Copy)]
pub struct ServerSpecList {
    pub data: *const ServerSpec,
    pub len: usize,
}
#[repr(C)]
#[derive(Clone, Copy)]
pub struct Listed {
    pub name: Bytes,
    pub countries: Strings,
    pub comment: Bytes,
}
#[repr(C)]
#[derive(Clone, Copy)]
pub struct ListedList {
    pub data: *const Listed,
    pub len: usize,
}
#[repr(C)]
#[derive(Clone, Copy)]
pub struct Country {
    pub code: Bytes,
    pub name: Bytes,
}
#[repr(C)]
#[derive(Clone, Copy)]
pub struct CountryList {
    pub data: *const Country,
    pub len: usize,
}
