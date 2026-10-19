//! Generated stable storage and C views.
use std::any::Any;
use trust_abi as abi;
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
    pub(crate) fn root(&mut self, value: &trust_core::Root) -> abi::Root {
        abi::Root {
            fingerprint: self.text(&value.fingerprint),
            subject: self.text(&value.subject),
            purposes: self.strings(&value.purposes),
            source: match value.source {
                trust_core::Source::Shipped => 0,
                trust_core::Source::Added => 1,
            },
            name: self.maybe_text(value.name.as_deref()),
            not_after: value.not_after,
            der: self.bytes(&value.der),
        }
    }
    pub(crate) fn root_list(&mut self, values: &[trust_core::Root]) -> abi::RootList {
        let owned: Box<[_]> = values.iter().map(|value| self.root(value)).collect();
        let result = abi::RootList {
            data: owned.as_ptr(),
            len: owned.len(),
        };
        self.allocations.push(Box::new(owned));
        result
    }
    pub(crate) fn status(&mut self, value: &trust_core::Status) -> abi::Status {
        abi::Status {
            generation: value.generation,
            health: match value.health {
                trust_core::Health::Ok => 0,
                trust_core::Health::Degraded => 1,
            },
            message: self.maybe_text(value.message.as_deref()),
            shipped: value.shipped,
            added: value.added,
            distrusted: value.distrusted,
            skipped: value.skipped,
            effective: value.effective,
            compat_mode: value.compat_mode,
            rendered: self.strings(&value.rendered),
        }
    }

    pub(crate) fn parsed(&mut self, value: &trust_core::cert::Parsed) -> abi::Parsed {
        abi::Parsed {
            der: self.bytes(&value.der),
            fingerprint: self.text(&value.fingerprint),
            subject: self.text(&value.subject),
            not_after: value.not_after,
            subject_hash: self.text(&value.subject_hash),
        }
    }

    pub(crate) fn details(&mut self, value: &trust_core::cert::Details) -> abi::Details {
        abi::Details {
            common_name: self.maybe_text(value.common_name.as_deref()),
            organisation: self.maybe_text(value.organisation.as_deref()),
            unit: self.maybe_text(value.unit.as_deref()),
            country: self.maybe_text(value.country.as_deref()),
            subject: self.text(&value.subject),
            issuer: self.text(&value.issuer),
            serial: self.text(&value.serial),
            not_before: value.not_before,
            not_after: value.not_after,
            key: self.text(&value.key),
            ca: u32::from(value.ca),
        }
    }

    pub(crate) fn distrusted(&mut self, value: &trust_client_core::Distrusted) -> abi::Distrusted {
        abi::Distrusted {
            fingerprint: self.text(&value.fingerprint),
            reason: self.text(&value.reason),
        }
    }
    pub(crate) fn distrusted_list(
        &mut self,
        values: &[trust_client_core::Distrusted],
    ) -> abi::DistrustedList {
        let owned: Box<[_]> = values.iter().map(|value| self.distrusted(value)).collect();
        let result = abi::DistrustedList {
            data: owned.as_ptr(),
            len: owned.len(),
        };
        self.allocations.push(Box::new(owned));
        result
    }
}
