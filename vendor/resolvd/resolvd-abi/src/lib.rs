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
pub struct RecordOut {
    pub name: Bytes,
    pub rtype: u16,
    pub ttl: u32,
    pub data: Bytes,
    pub text: Bytes,
}
#[repr(C)]
#[derive(Clone, Copy)]
pub struct RecordOutList {
    pub data: *const RecordOut,
    pub len: usize,
}
#[repr(C)]
#[derive(Clone, Copy)]
pub struct Answer {
    pub outcome: u32,
    pub records: RecordOutList,
    pub source: Bytes,
    pub server: Bytes,
    pub interface: Bytes,
    pub validation: u32,
    pub rcode: u16,
}
#[repr(C)]
#[derive(Clone, Copy)]
pub struct AnswerList {
    pub data: *const Answer,
    pub len: usize,
}
#[repr(C)]
#[derive(Clone, Copy)]
pub struct AddressOut {
    pub address: Bytes,
    pub ttl: u32,
}
#[repr(C)]
#[derive(Clone, Copy)]
pub struct AddressOutList {
    pub data: *const AddressOut,
    pub len: usize,
}
#[repr(C)]
#[derive(Clone, Copy)]
pub struct Addresses {
    pub outcome: u32,
    pub canonical: Bytes,
    pub addresses: AddressOutList,
    pub source: Bytes,
    pub validation: u32,
}
#[repr(C)]
#[derive(Clone, Copy)]
pub struct AddressesList {
    pub data: *const Addresses,
    pub len: usize,
}
#[repr(C)]
#[derive(Clone, Copy)]
pub struct Counters {
    pub queries: u64,
    pub synthetic: u64,
    pub cache_hits: u64,
    pub upstream_sent: u64,
    pub upstream_answered: u64,
    pub upstream_failed: u64,
    pub refused: u64,
}
#[repr(C)]
#[derive(Clone, Copy)]
pub struct CountersList {
    pub data: *const Counters,
    pub len: usize,
}
#[repr(C)]
#[derive(Clone, Copy)]
pub struct ScopeStatus {
    pub interface: Bytes,
    pub servers: Strings,
    pub domains: Strings,
    pub default_route: u32,
    pub exclusive: u32,
    pub metric: u32,
    pub subnets: Strings,
    pub demoted: Strings,
}
#[repr(C)]
#[derive(Clone, Copy)]
pub struct ScopeStatusList {
    pub data: *const ScopeStatus,
    pub len: usize,
}
#[repr(C)]
#[derive(Clone, Copy)]
pub struct StatusReport {
    pub hostname: Bytes,
    pub netd: u32,
    pub scopes: ScopeStatusList,
    pub fallback_servers: Strings,
    pub cache_entries: u64,
    pub counters: Counters,
}
#[repr(C)]
#[derive(Clone, Copy)]
pub struct StatusReportList {
    pub data: *const StatusReport,
    pub len: usize,
}
