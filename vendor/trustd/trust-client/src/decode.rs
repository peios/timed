//! Generated owned copies of views borrowed from a live library result.
use trust_abi as abi;
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
pub(crate) unsafe fn root(value: &abi::Root) -> Result<trust_core::Root, Error> {
    // SAFETY: the caller keeps the result and every nested allocation alive.
    #[allow(unused_unsafe)]
    unsafe {
        Ok(trust_core::Root {
            fingerprint: text(value.fingerprint)?,
            subject: text(value.subject)?,
            purposes: strings(value.purposes)?,
            source: match value.source {
                0 => trust_core::Source::Shipped,
                1 => trust_core::Source::Added,
                _ => return Err(invalid("unknown library enum")),
            },
            name: maybe_text(value.name)?,
            not_after: value.not_after,
            der: bytes(value.der),
        })
    }
}
pub(crate) unsafe fn root_list(value: abi::RootList) -> Result<Vec<trust_core::Root>, Error> {
    // SAFETY: all elements and nested spans belong to the live result.
    unsafe {
        array(value.data, value.len)
            .iter()
            .map(|value| root(value))
            .collect()
    }
}
pub(crate) unsafe fn status(value: &abi::Status) -> Result<trust_core::Status, Error> {
    // SAFETY: the caller keeps the result and every nested allocation alive.
    #[allow(unused_unsafe)]
    unsafe {
        Ok(trust_core::Status {
            generation: value.generation,
            health: match value.health {
                0 => trust_core::Health::Ok,
                1 => trust_core::Health::Degraded,
                _ => return Err(invalid("unknown library enum")),
            },
            message: maybe_text(value.message)?,
            shipped: value.shipped,
            added: value.added,
            distrusted: value.distrusted,
            skipped: value.skipped,
            effective: value.effective,
            compat_mode: value.compat_mode,
            rendered: strings(value.rendered)?,
        })
    }
}

pub(crate) unsafe fn parsed(value: &abi::Parsed) -> Result<trust_core::cert::Parsed, Error> {
    // SAFETY: the caller keeps the result and every nested allocation alive.
    #[allow(unused_unsafe)]
    unsafe {
        Ok(trust_core::cert::Parsed {
            der: bytes(value.der),
            fingerprint: text(value.fingerprint)?,
            subject: text(value.subject)?,
            not_after: value.not_after,
            subject_hash: text(value.subject_hash)?,
        })
    }
}

pub(crate) unsafe fn details(value: &abi::Details) -> Result<trust_core::cert::Details, Error> {
    // SAFETY: the caller keeps the result and every nested allocation alive.
    #[allow(unused_unsafe)]
    unsafe {
        Ok(trust_core::cert::Details {
            common_name: maybe_text(value.common_name)?,
            organisation: maybe_text(value.organisation)?,
            unit: maybe_text(value.unit)?,
            country: maybe_text(value.country)?,
            subject: text(value.subject)?,
            issuer: text(value.issuer)?,
            serial: text(value.serial)?,
            not_before: value.not_before,
            not_after: value.not_after,
            key: text(value.key)?,
            ca: value.ca != 0,
        })
    }
}

pub(crate) unsafe fn distrusted(value: &abi::Distrusted) -> Result<crate::Distrusted, Error> {
    // SAFETY: the caller keeps the result and every nested allocation alive.
    #[allow(unused_unsafe)]
    unsafe {
        Ok(crate::Distrusted {
            fingerprint: text(value.fingerprint)?,
            reason: text(value.reason)?,
        })
    }
}
pub(crate) unsafe fn distrusted_list(
    value: abi::DistrustedList,
) -> Result<Vec<crate::Distrusted>, Error> {
    // SAFETY: all elements and nested spans belong to the live result.
    unsafe {
        array(value.data, value.len)
            .iter()
            .map(|value| distrusted(value))
            .collect()
    }
}
