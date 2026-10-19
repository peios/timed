//! Registry reads distinguish absent policy from failed reads.
use std::io;
use peios::registry::{Key, KeyAccess, OpenFlags, RegValue, ValueType};

pub(super) trait Reader: Sized {
    fn value(&self, name: &str) -> io::Result<Option<RegValue>>;
}
fn optional<T>(value: peios::Result<T>) -> io::Result<Option<T>> {
    match value {
        Ok(value) => Ok(Some(value)),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(error.into()),
    }
}
pub(super) fn open(parent: Option<&Key>, path: &str) -> io::Result<Option<Key>> {
    optional(Key::open(
        parent,
        path,
        KeyAccess::QUERY_VALUE | KeyAccess::ENUMERATE_SUB_KEYS,
        OpenFlags::empty(),
    ))
}
impl Reader for Key {
    fn value(&self, name: &str) -> io::Result<Option<RegValue>> {
        optional(self.query_value(name.as_bytes(), None))
    }
}
pub(super) fn invalid(message: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}
pub(super) fn text(bytes: &[u8]) -> io::Result<String> {
    String::from_utf8(bytes.to_vec()).map_err(|_| invalid("registry text is not UTF-8"))
}
pub(super) fn multi(value: &RegValue) -> io::Result<Option<Vec<String>>> {
    match value.ty {
        ValueType::MULTI_SZ => value
            .data
            .split(|&byte| byte == 0)
            .filter(|part| !part.is_empty())
            .map(text)
            .collect::<io::Result<Vec<_>>>()
            .map(Some),
        ValueType::SZ | ValueType::EXPAND_SZ => {
            let end = value
                .data
                .iter()
                .position(|&byte| byte == 0)
                .unwrap_or(value.data.len());
            Ok(Some(vec![text(&value.data[..end])?]))
        }
        _ => Ok(None),
    }
}
pub(super) fn strings(reader: &impl Reader, name: &str) -> io::Result<Option<Vec<String>>> {
    reader
        .value(name)?
        .as_ref()
        .map(multi)
        .transpose()
        .map(Option::flatten)
}
