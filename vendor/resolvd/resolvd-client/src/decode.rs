//! Generated owned copies of views borrowed from a live library result.
use resolvd_abi as abi;
use crate::{Error, invalid};
pub(crate) unsafe fn array<'a, T>(data: *const T, len: usize) -> &'a [T] {
    if len == 0 {
        return &[];
    }
    // SAFETY: caller borrows a validated array from a live ABI result for this lifetime.
    unsafe { std::slice::from_raw_parts(data, len) }
}
pub(crate) unsafe fn bytes(value: abi::Bytes) -> Vec<u8> {
    // SAFETY: the span is borrowed from a live result for this copy.
    unsafe { array(value.data, value.len) }.to_vec()
}
pub(crate) unsafe fn text(value: abi::Bytes) -> Result<String, Error> {
    // SAFETY: the caller keeps the owning result alive.
    String::from_utf8(unsafe { bytes(value) }).map_err(|_| invalid("invalid library UTF-8"))
}
pub(crate) unsafe fn maybe_text(value: abi::Bytes) -> Result<Option<String>, Error> {
    if value.data.is_null() {
        return Ok(None);
    }
    // SAFETY: the caller keeps the owning result alive.
    unsafe { text(value) }.map(Some)
}
pub(crate) unsafe fn strings(value: abi::Strings) -> Result<Vec<String>, Error> {
    // SAFETY: all nested spans are owned by the same live result.
    unsafe { array(value.data, value.len) }
        .iter()
        .map(|value| unsafe { text(*value) })
        .collect()
}
pub(crate) unsafe fn record_out(value: &abi::RecordOut) -> Result<resolvd_core::RecordOut, Error> {
    // SAFETY: the caller keeps the result and every nested allocation alive.
    #[allow(unused_unsafe)]
    unsafe {
        Ok(resolvd_core::RecordOut {
            name: text(value.name)?,
            rtype: value.rtype,
            ttl: value.ttl,
            data: bytes(value.data),
            text: text(value.text)?,
        })
    }
}
pub(crate) unsafe fn record_out_list(
    value: abi::RecordOutList,
) -> Result<Vec<resolvd_core::RecordOut>, Error> {
    // SAFETY: all elements and nested spans belong to the live result.
    unsafe {
        array(value.data, value.len)
            .iter()
            .map(|value| record_out(value))
            .collect()
    }
}
pub(crate) unsafe fn answer(value: &abi::Answer) -> Result<resolvd_core::Answer, Error> {
    // SAFETY: the caller keeps the result and every nested allocation alive.
    #[allow(unused_unsafe)]
    unsafe {
        Ok(resolvd_core::Answer {
            outcome: match value.outcome {
                0 => resolvd_core::Outcome::Found,
                1 => resolvd_core::Outcome::NotFound,
                2 => resolvd_core::Outcome::Unavailable,
                _ => return Err(invalid("unknown library enum")),
            },
            records: record_out_list(value.records)?,
            source: text(value.source)?,
            server: maybe_text(value.server)?,
            interface: maybe_text(value.interface)?,
            validation: match value.validation {
                0 => resolvd_core::Validation::Unvalidated,
                1 => resolvd_core::Validation::Secure,
                2 => resolvd_core::Validation::Insecure,
                3 => resolvd_core::Validation::Bogus,
                _ => return Err(invalid("unknown library enum")),
            },
            rcode: value.rcode,
        })
    }
}

pub(crate) unsafe fn address_out(
    value: &abi::AddressOut,
) -> Result<resolvd_core::AddressOut, Error> {
    // SAFETY: the caller keeps the result and every nested allocation alive.
    #[allow(unused_unsafe)]
    unsafe {
        Ok(resolvd_core::AddressOut {
            address: text(value.address)?
                .parse()
                .map_err(|_| invalid("invalid library IP address"))?,
            ttl: value.ttl,
        })
    }
}
pub(crate) unsafe fn address_out_list(
    value: abi::AddressOutList,
) -> Result<Vec<resolvd_core::AddressOut>, Error> {
    // SAFETY: all elements and nested spans belong to the live result.
    unsafe {
        array(value.data, value.len)
            .iter()
            .map(|value| address_out(value))
            .collect()
    }
}
pub(crate) unsafe fn addresses(value: &abi::Addresses) -> Result<resolvd_core::Addresses, Error> {
    // SAFETY: the caller keeps the result and every nested allocation alive.
    #[allow(unused_unsafe)]
    unsafe {
        Ok(resolvd_core::Addresses {
            outcome: match value.outcome {
                0 => resolvd_core::Outcome::Found,
                1 => resolvd_core::Outcome::NotFound,
                2 => resolvd_core::Outcome::Unavailable,
                _ => return Err(invalid("unknown library enum")),
            },
            canonical: text(value.canonical)?,
            addresses: address_out_list(value.addresses)?,
            source: text(value.source)?,
            validation: match value.validation {
                0 => resolvd_core::Validation::Unvalidated,
                1 => resolvd_core::Validation::Secure,
                2 => resolvd_core::Validation::Insecure,
                3 => resolvd_core::Validation::Bogus,
                _ => return Err(invalid("unknown library enum")),
            },
        })
    }
}

pub(crate) unsafe fn counters(value: &abi::Counters) -> Result<resolvd_core::Counters, Error> {
    // SAFETY: the caller keeps the result and every nested allocation alive.
    #[allow(unused_unsafe)]
    unsafe {
        Ok(resolvd_core::Counters {
            queries: value.queries,
            synthetic: value.synthetic,
            cache_hits: value.cache_hits,
            upstream_sent: value.upstream_sent,
            upstream_answered: value.upstream_answered,
            upstream_failed: value.upstream_failed,
            refused: value.refused,
        })
    }
}

pub(crate) unsafe fn scope_status(
    value: &abi::ScopeStatus,
) -> Result<resolvd_core::ScopeStatus, Error> {
    // SAFETY: the caller keeps the result and every nested allocation alive.
    #[allow(unused_unsafe)]
    unsafe {
        Ok(resolvd_core::ScopeStatus {
            interface: text(value.interface)?,
            servers: strings(value.servers)?,
            domains: strings(value.domains)?,
            default_route: value.default_route != 0,
            exclusive: value.exclusive != 0,
            metric: value.metric,
            subnets: strings(value.subnets)?,
            demoted: strings(value.demoted)?,
        })
    }
}
pub(crate) unsafe fn scope_status_list(
    value: abi::ScopeStatusList,
) -> Result<Vec<resolvd_core::ScopeStatus>, Error> {
    // SAFETY: all elements and nested spans belong to the live result.
    unsafe {
        array(value.data, value.len)
            .iter()
            .map(|value| scope_status(value))
            .collect()
    }
}
pub(crate) unsafe fn status_report(
    value: &abi::StatusReport,
) -> Result<resolvd_core::StatusReport, Error> {
    // SAFETY: the caller keeps the result and every nested allocation alive.
    #[allow(unused_unsafe)]
    unsafe {
        Ok(resolvd_core::StatusReport {
            hostname: text(value.hostname)?,
            netd: value.netd != 0,
            scopes: scope_status_list(value.scopes)?,
            fallback_servers: strings(value.fallback_servers)?,
            cache_entries: value.cache_entries,
            counters: counters(&value.counters)?,
        })
    }
}
