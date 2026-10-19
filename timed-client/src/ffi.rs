//! Private declarations for libtimed.
use std::ffi::c_void;
use timed_abi as abi;
#[link(name = "timed")]
unsafe extern "C" {
    pub fn peios_timed_result_free(result: *mut c_void);
    pub fn peios_timed_result_error(result: *const c_void) -> i32;
    pub fn peios_timed_result_message(result: *const c_void) -> abi::Bytes;
    pub fn peios_timed_result_status(result: *const c_void) -> *const abi::Status;
    pub fn peios_timed_result_snapshot(result: *const c_void) -> *const abi::Snapshot;
    pub fn peios_timed_result_server_spec(result: *const c_void) -> *const abi::ServerSpec;
    pub fn peios_timed_result_source_info_list(result: *const c_void)
    -> *const abi::SourceInfoList;
    pub fn peios_timed_result_listed_list(result: *const c_void) -> *const abi::ListedList;
    pub fn peios_timed_get_status(path: abi::Bytes, timeout_ms: u64) -> *mut c_void;
    pub fn peios_timed_sources(path: abi::Bytes, timeout_ms: u64) -> *mut c_void;
    pub fn peios_timed_reload(path: abi::Bytes, timeout_ms: u64) -> *mut c_void;
    pub fn peios_timed_set(
        path: abi::Bytes,
        timeout_ms: u64,
        seconds: i64,
        nanos: u32,
    ) -> *mut c_void;
    pub fn peios_timed_parse_server(entry: abi::Bytes) -> *mut c_void;
    pub fn peios_timed_check_zone(name: abi::Bytes) -> *mut c_void;
    pub fn peios_timed_installed_zone(name: abi::Bytes) -> *mut c_void;
    pub fn peios_timed_zones() -> *mut c_void;
    pub fn peios_timed_subscribe(
        path: abi::Bytes,
        timeout_ms: u64,
        out: *mut *mut c_void,
    ) -> *mut c_void;
    pub fn peios_timed_subscription_next(subscription: *mut c_void, timeout_ms: u64)
    -> *mut c_void;
    pub fn peios_timed_subscription_free(subscription: *mut c_void);
    pub fn peios_timed_result_country_list(result: *const c_void) -> *const abi::CountryList;
    pub fn peios_timed_result_bytes(result: *const c_void) -> abi::Bytes;
    pub fn peios_timed_countries() -> *mut c_void;
    pub fn peios_timed_zone_path(name: abi::Bytes) -> *mut c_void;
}
