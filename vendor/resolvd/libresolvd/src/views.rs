//! Generated stable storage and C views.
use std::any::Any;
use resolvd_abi as abi;
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
    pub(crate) fn record_out(&mut self, value: &resolvd_core::RecordOut) -> abi::RecordOut {
        abi::RecordOut {
            name: self.text(&value.name),
            rtype: value.rtype,
            ttl: value.ttl,
            data: self.bytes(&value.data),
            text: self.text(&value.text),
        }
    }
    pub(crate) fn record_out_list(
        &mut self,
        values: &[resolvd_core::RecordOut],
    ) -> abi::RecordOutList {
        let owned: Box<[_]> = values.iter().map(|value| self.record_out(value)).collect();
        let result = abi::RecordOutList {
            data: owned.as_ptr(),
            len: owned.len(),
        };
        self.allocations.push(Box::new(owned));
        result
    }
    pub(crate) fn answer(&mut self, value: &resolvd_core::Answer) -> abi::Answer {
        abi::Answer {
            outcome: match value.outcome {
                resolvd_core::Outcome::Found => 0,
                resolvd_core::Outcome::NotFound => 1,
                resolvd_core::Outcome::Unavailable => 2,
            },
            records: self.record_out_list(&value.records),
            source: self.text(&value.source),
            server: self.maybe_text(value.server.as_deref()),
            interface: self.maybe_text(value.interface.as_deref()),
            validation: match value.validation {
                resolvd_core::Validation::Unvalidated => 0,
                resolvd_core::Validation::Secure => 1,
                resolvd_core::Validation::Insecure => 2,
                resolvd_core::Validation::Bogus => 3,
            },
            rcode: value.rcode,
        }
    }

    pub(crate) fn address_out(&mut self, value: &resolvd_core::AddressOut) -> abi::AddressOut {
        abi::AddressOut {
            address: self.text(&value.address.to_string()),
            ttl: value.ttl,
        }
    }
    pub(crate) fn address_out_list(
        &mut self,
        values: &[resolvd_core::AddressOut],
    ) -> abi::AddressOutList {
        let owned: Box<[_]> = values.iter().map(|value| self.address_out(value)).collect();
        let result = abi::AddressOutList {
            data: owned.as_ptr(),
            len: owned.len(),
        };
        self.allocations.push(Box::new(owned));
        result
    }
    pub(crate) fn addresses(&mut self, value: &resolvd_core::Addresses) -> abi::Addresses {
        abi::Addresses {
            outcome: match value.outcome {
                resolvd_core::Outcome::Found => 0,
                resolvd_core::Outcome::NotFound => 1,
                resolvd_core::Outcome::Unavailable => 2,
            },
            canonical: self.text(&value.canonical),
            addresses: self.address_out_list(&value.addresses),
            source: self.text(&value.source),
            validation: match value.validation {
                resolvd_core::Validation::Unvalidated => 0,
                resolvd_core::Validation::Secure => 1,
                resolvd_core::Validation::Insecure => 2,
                resolvd_core::Validation::Bogus => 3,
            },
        }
    }

    pub(crate) fn counters(&mut self, value: &resolvd_core::Counters) -> abi::Counters {
        abi::Counters {
            queries: value.queries,
            synthetic: value.synthetic,
            cache_hits: value.cache_hits,
            upstream_sent: value.upstream_sent,
            upstream_answered: value.upstream_answered,
            upstream_failed: value.upstream_failed,
            refused: value.refused,
        }
    }

    pub(crate) fn scope_status(&mut self, value: &resolvd_core::ScopeStatus) -> abi::ScopeStatus {
        abi::ScopeStatus {
            interface: self.text(&value.interface),
            servers: self.strings(&value.servers),
            domains: self.strings(&value.domains),
            default_route: u32::from(value.default_route),
            exclusive: u32::from(value.exclusive),
            metric: value.metric,
            subnets: self.strings(&value.subnets),
            demoted: self.strings(&value.demoted),
        }
    }
    pub(crate) fn scope_status_list(
        &mut self,
        values: &[resolvd_core::ScopeStatus],
    ) -> abi::ScopeStatusList {
        let owned: Box<[_]> = values
            .iter()
            .map(|value| self.scope_status(value))
            .collect();
        let result = abi::ScopeStatusList {
            data: owned.as_ptr(),
            len: owned.len(),
        };
        self.allocations.push(Box::new(owned));
        result
    }
    pub(crate) fn status_report(
        &mut self,
        value: &resolvd_core::StatusReport,
    ) -> abi::StatusReport {
        abi::StatusReport {
            hostname: self.text(&value.hostname),
            netd: u32::from(value.netd),
            scopes: self.scope_status_list(&value.scopes),
            fallback_servers: self.strings(&value.fallback_servers),
            cache_entries: value.cache_entries,
            counters: self.counters(&value.counters),
        }
    }
}
