//! Private declarations for libtrust.
use std::ffi::c_void;
use trust_abi as abi;
#[link(name = "trust")]
unsafe extern "C" {
    pub fn peios_trust_result_free(result: *mut c_void);
    pub fn peios_trust_result_error(result: *const c_void) -> i32;
    pub fn peios_trust_result_message(result: *const c_void) -> abi::Bytes;
    pub fn peios_trust_result_text(result: *const c_void) -> *const abi::Bytes;
    pub fn peios_trust_result_bytes(result: *const c_void) -> *const abi::Bytes;
    pub fn peios_trust_result_boolean(result: *const c_void) -> *const u32;
    pub fn peios_trust_result_status(result: *const c_void) -> *const abi::Status;
    pub fn peios_trust_result_parsed(result: *const c_void) -> *const abi::Parsed;
    pub fn peios_trust_result_details(result: *const c_void) -> *const abi::Details;
    pub fn peios_trust_result_root_list(result: *const c_void) -> *const abi::RootList;
    pub fn peios_trust_result_distrusted_list(result: *const c_void) -> *const abi::DistrustedList;
    pub fn peios_trust_get_status(path: abi::Bytes, timeout_ms: u64) -> *mut c_void;
    pub fn peios_trust_roots(
        path: abi::Bytes,
        timeout_ms: u64,
        with_der: u32,
        purpose: abi::Bytes,
    ) -> *mut c_void;
    pub fn peios_trust_reload(path: abi::Bytes, timeout_ms: u64) -> *mut c_void;
    pub fn peios_trust_certificate(bytes: abi::Bytes, description: abi::Bytes) -> *mut c_void;
    pub fn peios_trust_inspect(der: abi::Bytes) -> *mut c_void;
    pub fn peios_trust_vet(der: abi::Bytes) -> *mut c_void;
    pub fn peios_trust_usable_name(name: abi::Bytes) -> *mut c_void;
    pub fn peios_trust_may_reload() -> *mut c_void;
    pub fn peios_trust_may_change() -> *mut c_void;
    pub fn peios_trust_may_set_compat() -> *mut c_void;
    pub fn peios_trust_set_compat(mode: u32) -> *mut c_void;
    pub fn peios_trust_add(
        name: abi::Bytes,
        der: abi::Bytes,
        purposes: abi::Strings,
    ) -> *mut c_void;
    pub fn peios_trust_remove(name: abi::Bytes) -> *mut c_void;
    pub fn peios_trust_get_distrusted() -> *mut c_void;
    pub fn peios_trust_distrust(fingerprint: abi::Bytes, reason: abi::Bytes) -> *mut c_void;
    pub fn peios_trust_restore(fingerprint: abi::Bytes) -> *mut c_void;
    pub fn peios_trust_subscribe(
        path: abi::Bytes,
        timeout_ms: u64,
        with_der: u32,
        out: *mut *mut c_void,
    ) -> *mut c_void;
    pub fn peios_trust_subscription_next(subscription: *mut c_void, timeout_ms: u64)
    -> *mut c_void;
    pub fn peios_trust_subscription_free(subscription: *mut c_void);
    pub fn peios_trust_result_generation(result: *const c_void) -> u64;
    pub fn peios_trust_resolve(argument: abi::Bytes) -> *mut c_void;
}
