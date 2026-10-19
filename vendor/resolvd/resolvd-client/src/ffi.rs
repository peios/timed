//! Private declarations for libresolvd.
use resolvd_abi as abi;
use std::ffi::c_void;
#[link(name = "resolvd")]
unsafe extern "C" {
    pub fn peios_resolvd_result_free(result: *mut c_void);
    pub fn peios_resolvd_result_error(result: *const c_void) -> i32;
    pub fn peios_resolvd_result_message(result: *const c_void) -> abi::Bytes;
    pub fn peios_resolvd_result_answer(result: *const c_void) -> *const abi::Answer;
    pub fn peios_resolvd_result_addresses(result: *const c_void) -> *const abi::Addresses;
    pub fn peios_resolvd_result_status_report(result: *const c_void) -> *const abi::StatusReport;
    pub fn peios_resolvd_get_status(path: abi::Bytes, timeout_ms: u64) -> *mut c_void;
    pub fn peios_resolvd_lookup(
        path: abi::Bytes,
        timeout_ms: u64,
        name: abi::Bytes,
        family: u32,
    ) -> *mut c_void;
    pub fn peios_resolvd_resolve(
        path: abi::Bytes,
        timeout_ms: u64,
        name: abi::Bytes,
        record_type: u16,
        no_cache: u32,
    ) -> *mut c_void;
    pub fn peios_resolvd_reverse(
        path: abi::Bytes,
        timeout_ms: u64,
        address: abi::Bytes,
    ) -> *mut c_void;
    pub fn peios_resolvd_flush(path: abi::Bytes, timeout_ms: u64) -> *mut c_void;
}
