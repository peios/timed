//! Generated owned copies of views borrowed from a live library result.
use timed_abi as abi;
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
pub(crate) unsafe fn source_info(value: &abi::SourceInfo) -> Result<timed_core::SourceInfo, Error> {
    // SAFETY: the caller keeps the result and every nested allocation alive.
    #[allow(unused_unsafe)]
    unsafe {
        Ok(timed_core::SourceInfo {
            name: text(value.name)?,
            address: text(value.address)?,
            origin: match value.origin {
                0 => timed_core::Origin::Registry,
                1 => timed_core::Origin::Domain,
                2 => timed_core::Origin::Dhcp,
                3 => timed_core::Origin::Fallback,
                _ => return Err(invalid("unknown library enum")),
            },
            auth: match value.auth {
                0 => timed_core::Auth::Nts,
                1 => timed_core::Auth::None,
                _ => return Err(invalid("unknown library enum")),
            },
            state: match value.state {
                0 => timed_core::SourceState::SystemPeer,
                1 => timed_core::SourceState::Candidate,
                2 => timed_core::SourceState::Outlier,
                3 => timed_core::SourceState::Falseticker,
                4 => timed_core::SourceState::Unreachable,
                5 => timed_core::SourceState::Unusable,
                _ => return Err(invalid("unknown library enum")),
            },
            stratum: value.stratum,
            reference: text(value.reference)?,
            reach: value.reach,
            poll: value.poll,
            last: value.last,
            offset: value.offset,
            delay: value.delay,
            jitter: value.jitter,
            root_distance: value.root_distance,
            cookies: value.cookies,
            note: maybe_text(value.note)?,
        })
    }
}
pub(crate) unsafe fn source_info_list(
    value: abi::SourceInfoList,
) -> Result<Vec<timed_core::SourceInfo>, Error> {
    // SAFETY: all elements and nested spans belong to the live result.
    unsafe {
        array(value.data, value.len)
            .iter()
            .map(|value| source_info(value))
            .collect()
    }
}
pub(crate) unsafe fn status(value: &abi::Status) -> Result<timed_core::Status, Error> {
    // SAFETY: the caller keeps the result and every nested allocation alive.
    #[allow(unused_unsafe)]
    unsafe {
        Ok(timed_core::Status {
            generation: value.generation,
            sync: match value.sync {
                0 => timed_core::Sync::Unsynchronised,
                1 => timed_core::Sync::Settling,
                2 => timed_core::Sync::Synchronised,
                3 => timed_core::Sync::Spike,
                _ => return Err(invalid("unknown library enum")),
            },
            system_peer: maybe_text(value.system_peer)?,
            stratum: value.stratum,
            offset: value.offset,
            frequency_ppm: value.frequency_ppm,
            jitter: value.jitter,
            root_distance: value.root_distance,
            root_delay: value.root_delay,
            root_dispersion: value.root_dispersion,
            leap: value.leap,
            stepped: value.stepped,
            updates: value.updates,
            last_update: value.last_update,
            sources: value.sources,
            selected: value.selected,
            floor: value.floor,
            manual: value.manual != 0,
            zone: maybe_text(value.zone)?,
        })
    }
}

pub(crate) unsafe fn snapshot(value: &abi::Snapshot) -> Result<timed_core::Snapshot, Error> {
    // SAFETY: the caller keeps the result and every nested allocation alive.
    #[allow(unused_unsafe)]
    unsafe {
        Ok(timed_core::Snapshot {
            generation: value.generation,
            leap: value.leap,
            stratum: value.stratum,
            reference_id: bytes(value.reference_id),
            reference_time: value.reference_time,
            root_delay: value.root_delay,
            root_dispersion: value.root_dispersion,
            precision: value.precision,
            at: value.at,
            synchronised: value.synchronised != 0,
        })
    }
}

pub(crate) unsafe fn server_spec(
    value: &abi::ServerSpec,
) -> Result<timed_core::servers::ServerSpec, Error> {
    // SAFETY: the caller keeps the result and every nested allocation alive.
    #[allow(unused_unsafe)]
    unsafe {
        Ok(timed_core::servers::ServerSpec {
            host: text(value.host)?,
            port: (value.port.present != 0).then_some(value.port.value),
            prefer: value.prefer != 0,
            unauthenticated: value.unauthenticated != 0,
        })
    }
}

pub(crate) unsafe fn listed(value: &abi::Listed) -> Result<timed_core::zone::Listed, Error> {
    // SAFETY: the caller keeps the result and every nested allocation alive.
    #[allow(unused_unsafe)]
    unsafe {
        Ok(timed_core::zone::Listed {
            name: text(value.name)?,
            countries: strings(value.countries)?,
            comment: maybe_text(value.comment)?,
        })
    }
}
pub(crate) unsafe fn listed_list(
    value: abi::ListedList,
) -> Result<Vec<timed_core::zone::Listed>, Error> {
    // SAFETY: all elements and nested spans belong to the live result.
    unsafe {
        array(value.data, value.len)
            .iter()
            .map(|value| listed(value))
            .collect()
    }
}
pub(crate) unsafe fn country(value: &abi::Country) -> Result<timed_core::zone::Country, Error> {
    // SAFETY: the caller keeps the result and every nested allocation alive.
    #[allow(unused_unsafe)]
    unsafe {
        Ok(timed_core::zone::Country {
            code: text(value.code)?,
            name: text(value.name)?,
        })
    }
}
pub(crate) unsafe fn country_list(
    value: abi::CountryList,
) -> Result<Vec<timed_core::zone::Country>, Error> {
    // SAFETY: all elements and nested spans belong to the live result.
    unsafe {
        array(value.data, value.len)
            .iter()
            .map(|value| country(value))
            .collect()
    }
}
