//! Generated stable storage and C views.
use std::any::Any;
use timed_abi as abi;
#[derive(Default)]
pub(crate) struct Arena {
    allocations: Vec<Box<dyn Any>>,
}
pub(crate) fn absent() -> abi::Bytes {
    abi::Bytes {
        data: std::ptr::null(),
        len: 0,
    }
}
impl Arena {
    pub(crate) fn bytes(&mut self, value: &[u8]) -> abi::Bytes {
        let owned = value.to_vec().into_boxed_slice();
        let result = abi::Bytes {
            data: owned.as_ptr(),
            len: owned.len(),
        };
        self.allocations.push(Box::new(owned));
        result
    }
    pub(crate) fn text(&mut self, value: &str) -> abi::Bytes {
        self.bytes(value.as_bytes())
    }
    pub(crate) fn maybe_text(&mut self, value: Option<&str>) -> abi::Bytes {
        value.map_or_else(absent, |value| self.text(value))
    }
    pub(crate) fn strings(&mut self, values: &[String]) -> abi::Strings {
        let owned: Box<[_]> = values.iter().map(|value| self.text(value)).collect();
        let result = abi::Strings {
            data: owned.as_ptr(),
            len: owned.len(),
        };
        self.allocations.push(Box::new(owned));
        result
    }
    pub(crate) fn source_info(&mut self, value: &timed_core::SourceInfo) -> abi::SourceInfo {
        abi::SourceInfo {
            name: self.text(&value.name),
            address: self.text(&value.address),
            origin: match value.origin {
                timed_core::Origin::Registry => 0,
                timed_core::Origin::Domain => 1,
                timed_core::Origin::Dhcp => 2,
                timed_core::Origin::Fallback => 3,
            },
            auth: match value.auth {
                timed_core::Auth::Nts => 0,
                timed_core::Auth::None => 1,
            },
            state: match value.state {
                timed_core::SourceState::SystemPeer => 0,
                timed_core::SourceState::Candidate => 1,
                timed_core::SourceState::Outlier => 2,
                timed_core::SourceState::Falseticker => 3,
                timed_core::SourceState::Unreachable => 4,
                timed_core::SourceState::Unusable => 5,
            },
            stratum: value.stratum,
            reference: self.text(&value.reference),
            reach: value.reach,
            poll: value.poll,
            last: value.last,
            offset: value.offset,
            delay: value.delay,
            jitter: value.jitter,
            root_distance: value.root_distance,
            cookies: value.cookies,
            note: self.maybe_text(value.note.as_deref()),
        }
    }
    pub(crate) fn source_info_list(
        &mut self,
        values: &[timed_core::SourceInfo],
    ) -> abi::SourceInfoList {
        let owned: Box<[_]> = values.iter().map(|value| self.source_info(value)).collect();
        let result = abi::SourceInfoList {
            data: owned.as_ptr(),
            len: owned.len(),
        };
        self.allocations.push(Box::new(owned));
        result
    }
    pub(crate) fn status(&mut self, value: &timed_core::Status) -> abi::Status {
        abi::Status {
            generation: value.generation,
            sync: match value.sync {
                timed_core::Sync::Unsynchronised => 0,
                timed_core::Sync::Settling => 1,
                timed_core::Sync::Synchronised => 2,
                timed_core::Sync::Spike => 3,
            },
            system_peer: self.maybe_text(value.system_peer.as_deref()),
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
            manual: u32::from(value.manual),
            zone: self.maybe_text(value.zone.as_deref()),
        }
    }

    pub(crate) fn snapshot(&mut self, value: &timed_core::Snapshot) -> abi::Snapshot {
        abi::Snapshot {
            generation: value.generation,
            leap: value.leap,
            stratum: value.stratum,
            reference_id: self.bytes(&value.reference_id),
            reference_time: value.reference_time,
            root_delay: value.root_delay,
            root_dispersion: value.root_dispersion,
            precision: value.precision,
            at: value.at,
            synchronised: u32::from(value.synchronised),
        }
    }

    pub(crate) fn server_spec(
        &mut self,
        value: &timed_core::servers::ServerSpec,
    ) -> abi::ServerSpec {
        abi::ServerSpec {
            host: self.text(&value.host),
            port: abi::OptionalU16 {
                present: u32::from(value.port.is_some()),
                value: value.port.unwrap_or(0),
            },
            prefer: u32::from(value.prefer),
            unauthenticated: u32::from(value.unauthenticated),
        }
    }

    pub(crate) fn listed(&mut self, value: &timed_core::zone::Listed) -> abi::Listed {
        abi::Listed {
            name: self.text(&value.name),
            countries: self.strings(&value.countries),
            comment: self.maybe_text(value.comment.as_deref()),
        }
    }
    pub(crate) fn listed_list(&mut self, values: &[timed_core::zone::Listed]) -> abi::ListedList {
        let owned: Box<[_]> = values.iter().map(|value| self.listed(value)).collect();
        let result = abi::ListedList {
            data: owned.as_ptr(),
            len: owned.len(),
        };
        self.allocations.push(Box::new(owned));
        result
    }
    pub(crate) fn country(&mut self, value: &timed_core::zone::Country) -> abi::Country {
        abi::Country {
            code: self.text(&value.code),
            name: self.text(&value.name),
        }
    }
    pub(crate) fn country_list(
        &mut self,
        values: &[timed_core::zone::Country],
    ) -> abi::CountryList {
        let owned: Box<[_]> = values.iter().map(|value| self.country(value)).collect();
        let result = abi::CountryList {
            data: owned.as_ptr(),
            len: owned.len(),
        };
        self.allocations.push(Box::new(owned));
        result
    }
}
