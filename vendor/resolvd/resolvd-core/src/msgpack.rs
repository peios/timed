//! A MessagePack codec: the subset PSPU messages use — nil, bool, integers,
//! strings, binary, arrays, maps. Unknown values may also contain floats
//! and extensions, which can be skipped without interpreting them.
//!
//! resolvd_core is linked into `libnss_peios_net.so.2`, which is loaded into
//! every process on the system, so it takes no dependency on libpeios (whose
//! `peios::msgpack` this mirrors in API) — the same choice `libauthd` made for
//! the identity shim. Total: every input decodes or returns an error.

use std::fmt;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Error {
    Truncated,
    /// The next value is not of the type asked for.
    Type,
    /// A reserved MessagePack marker.
    Unsupported,
    Utf8,
    /// A container nested deeper than a message may.
    Depth,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Error::Truncated => "truncated message",
            Error::Type => "unexpected value type",
            Error::Unsupported => "unsupported value type",
            Error::Utf8 => "string is not UTF-8",
            Error::Depth => "nested too deeply",
        })
    }
}

impl std::error::Error for Error {}

pub type Result<T> = std::result::Result<T, Error>;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Type {
    Nil,
    Bool,
    Int,
    Str,
    Bin,
    Array,
    Map,
    Other,
}

#[derive(Default)]
pub struct Writer {
    buf: Vec<u8>,
}

impl Writer {
    pub fn new() -> Writer {
        Writer {
            buf: Vec::with_capacity(256),
        }
    }

    pub fn write_nil(&mut self) -> &mut Self {
        self.buf.push(0xc0);
        self
    }

    pub fn write_bool(&mut self, v: bool) -> &mut Self {
        self.buf.push(if v { 0xc3 } else { 0xc2 });
        self
    }

    pub fn write_uint(&mut self, v: u64) -> &mut Self {
        if v < 0x80 {
            self.buf.push(v as u8);
        } else if v <= 0xff {
            self.buf.extend_from_slice(&[0xcc, v as u8]);
        } else if v <= 0xffff {
            self.buf.push(0xcd);
            self.buf.extend_from_slice(&(v as u16).to_be_bytes());
        } else if v <= 0xffff_ffff {
            self.buf.push(0xce);
            self.buf.extend_from_slice(&(v as u32).to_be_bytes());
        } else {
            self.buf.push(0xcf);
            self.buf.extend_from_slice(&v.to_be_bytes());
        }
        self
    }

    pub fn write_int(&mut self, v: i64) -> &mut Self {
        if v >= 0 {
            return self.write_uint(v as u64);
        }
        if v >= -32 {
            self.buf.push(v as i8 as u8);
        } else if v >= i8::MIN as i64 {
            self.buf.extend_from_slice(&[0xd0, v as i8 as u8]);
        } else if v >= i16::MIN as i64 {
            self.buf.push(0xd1);
            self.buf.extend_from_slice(&(v as i16).to_be_bytes());
        } else if v >= i32::MIN as i64 {
            self.buf.push(0xd2);
            self.buf.extend_from_slice(&(v as i32).to_be_bytes());
        } else {
            self.buf.push(0xd3);
            self.buf.extend_from_slice(&v.to_be_bytes());
        }
        self
    }

    pub fn write_str(&mut self, s: &str) -> &mut Self {
        let n = s.len();
        if n < 32 {
            self.buf.push(0xa0 | n as u8);
        } else if n <= 0xff {
            self.buf.extend_from_slice(&[0xd9, n as u8]);
        } else if n <= 0xffff {
            self.buf.push(0xda);
            self.buf.extend_from_slice(&(n as u16).to_be_bytes());
        } else {
            self.buf.push(0xdb);
            self.buf.extend_from_slice(&(n as u32).to_be_bytes());
        }
        self.buf.extend_from_slice(s.as_bytes());
        self
    }

    pub fn write_bin(&mut self, b: &[u8]) -> &mut Self {
        let n = b.len();
        if n <= 0xff {
            self.buf.extend_from_slice(&[0xc4, n as u8]);
        } else if n <= 0xffff {
            self.buf.push(0xc5);
            self.buf.extend_from_slice(&(n as u16).to_be_bytes());
        } else {
            self.buf.push(0xc6);
            self.buf.extend_from_slice(&(n as u32).to_be_bytes());
        }
        self.buf.extend_from_slice(b);
        self
    }

    pub fn write_array(&mut self, count: u32) -> &mut Self {
        if count < 16 {
            self.buf.push(0x90 | count as u8);
        } else if count <= 0xffff {
            self.buf.push(0xdc);
            self.buf.extend_from_slice(&(count as u16).to_be_bytes());
        } else {
            self.buf.push(0xdd);
            self.buf.extend_from_slice(&count.to_be_bytes());
        }
        self
    }

    pub fn write_map(&mut self, count: u32) -> &mut Self {
        if count < 16 {
            self.buf.push(0x80 | count as u8);
        } else if count <= 0xffff {
            self.buf.push(0xde);
            self.buf.extend_from_slice(&(count as u16).to_be_bytes());
        } else {
            self.buf.push(0xdf);
            self.buf.extend_from_slice(&count.to_be_bytes());
        }
        self
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        self.buf.clone()
    }

    pub fn into_bytes(self) -> Vec<u8> {
        self.buf
    }
}

pub struct Reader<'a> {
    buf: &'a [u8],
    pos: usize,
    depth: u32,
}

const MAX_DEPTH: u32 = 32;

impl<'a> Reader<'a> {
    pub fn new(buf: &'a [u8]) -> Reader<'a> {
        Reader {
            buf,
            pos: 0,
            depth: 0,
        }
    }

    pub fn remaining(&self) -> usize {
        self.buf.len() - self.pos
    }

    fn byte(&mut self) -> Result<u8> {
        let b = *self.buf.get(self.pos).ok_or(Error::Truncated)?;
        self.pos += 1;
        Ok(b)
    }

    fn take(&mut self, n: usize) -> Result<&'a [u8]> {
        let s = self
            .buf
            .get(self.pos..self.pos + n)
            .ok_or(Error::Truncated)?;
        self.pos += n;
        Ok(s)
    }

    fn be_u(&mut self, n: usize) -> Result<u64> {
        let s = self.take(n)?;
        Ok(s.iter().fold(0u64, |acc, &b| (acc << 8) | u64::from(b)))
    }

    pub fn peek(&self) -> Option<Type> {
        let b = *self.buf.get(self.pos)?;
        Some(match b {
            0xc0 => Type::Nil,
            0xc2 | 0xc3 => Type::Bool,
            0x00..=0x7f | 0xe0..=0xff | 0xcc..=0xd3 => Type::Int,
            0xa0..=0xbf | 0xd9..=0xdb => Type::Str,
            0xc4..=0xc6 => Type::Bin,
            0x90..=0x9f | 0xdc | 0xdd => Type::Array,
            0x80..=0x8f | 0xde | 0xdf => Type::Map,
            _ => Type::Other,
        })
    }

    pub fn read_nil(&mut self) -> Result<()> {
        match self.byte()? {
            0xc0 => Ok(()),
            _ => Err(Error::Type),
        }
    }

    pub fn read_bool(&mut self) -> Result<bool> {
        match self.byte()? {
            0xc2 => Ok(false),
            0xc3 => Ok(true),
            _ => Err(Error::Type),
        }
    }

    pub fn read_int(&mut self) -> Result<i64> {
        let b = self.byte()?;
        Ok(match b {
            0x00..=0x7f => i64::from(b),
            0xe0..=0xff => i64::from(b as i8),
            0xcc => self.be_u(1)? as i64,
            0xcd => self.be_u(2)? as i64,
            0xce => self.be_u(4)? as i64,
            0xcf => {
                let v = self.be_u(8)?;
                i64::try_from(v).map_err(|_| Error::Type)?
            }
            0xd0 => self.be_u(1)? as u8 as i8 as i64,
            0xd1 => self.be_u(2)? as u16 as i16 as i64,
            0xd2 => self.be_u(4)? as u32 as i32 as i64,
            0xd3 => self.be_u(8)? as i64,
            _ => return Err(Error::Type),
        })
    }

    pub fn read_uint(&mut self) -> Result<u64> {
        let v = self.read_int()?;
        u64::try_from(v).map_err(|_| Error::Type)
    }

    pub fn read_str(&mut self) -> Result<&'a str> {
        let b = self.byte()?;
        let n = match b {
            0xa0..=0xbf => (b & 0x1f) as usize,
            0xd9 => self.be_u(1)? as usize,
            0xda => self.be_u(2)? as usize,
            0xdb => self.be_u(4)? as usize,
            _ => return Err(Error::Type),
        };
        std::str::from_utf8(self.take(n)?).map_err(|_| Error::Utf8)
    }

    pub fn read_bin(&mut self) -> Result<&'a [u8]> {
        let b = self.byte()?;
        let n = match b {
            0xc4 => self.be_u(1)? as usize,
            0xc5 => self.be_u(2)? as usize,
            0xc6 => self.be_u(4)? as usize,
            _ => return Err(Error::Type),
        };
        self.take(n)
    }

    pub fn read_array(&mut self) -> Result<usize> {
        let b = self.byte()?;
        let n = match b {
            0x90..=0x9f => (b & 0x0f) as usize,
            0xdc => self.be_u(2)? as usize,
            0xdd => self.be_u(4)? as usize,
            _ => return Err(Error::Type),
        };
        // A count larger than the bytes left cannot be honest.
        if n > self.remaining() {
            return Err(Error::Truncated);
        }
        Ok(n)
    }

    pub fn read_map(&mut self) -> Result<usize> {
        let b = self.byte()?;
        let n = match b {
            0x80..=0x8f => (b & 0x0f) as usize,
            0xde => self.be_u(2)? as usize,
            0xdf => self.be_u(4)? as usize,
            _ => return Err(Error::Type),
        };
        if n * 2 > self.remaining() {
            return Err(Error::Truncated);
        }
        Ok(n)
    }

    /// Skip one MessagePack value, retaining string and nesting validation.
    pub fn skip(&mut self) -> Result<()> {
        match *self.buf.get(self.pos).ok_or(Error::Truncated)? {
            0x00..=0x7f | 0xe0..=0xff | 0xc0 | 0xc2 | 0xc3 => self.byte().map(drop),
            0xca..=0xd8 => {
                let n = match self.byte()? {
                    0xcc | 0xd0 => 1,
                    0xcd | 0xd1 | 0xd4 => 2,
                    0xd5 => 3,
                    0xca | 0xce | 0xd2 => 4,
                    0xd6 => 5,
                    0xcb | 0xcf | 0xd3 => 8,
                    0xd7 => 9,
                    0xd8 => 17,
                    _ => unreachable!(),
                };
                // Integers need no range conversion; fixed extensions include
                // their type byte as well as their opaque data.
                self.take(n).map(drop)
            }
            0xc7..=0xc9 => {
                let width = match self.byte()? {
                    0xc7 => 1,
                    0xc8 => 2,
                    _ => 4,
                };
                let n = self.be_u(width)? as usize;
                self.byte()?; // Extension type, even when the data is empty.
                self.take(n).map(drop)
            }
            0xa0..=0xbf | 0xd9..=0xdb => self.read_str().map(drop),
            0xc4..=0xc6 => self.read_bin().map(drop),
            0x90..=0x9f | 0xdc | 0xdd => {
                let n = self.read_array()?;
                self.nested(|r| (0..n).try_for_each(|_| r.skip()))
            }
            0x80..=0x8f | 0xde | 0xdf => {
                let n = self.read_map()?;
                self.nested(|r| (0..n).try_for_each(|_| r.skip().and_then(|_| r.skip())))
            }
            _ => Err(Error::Unsupported),
        }
    }

    fn nested<T>(&mut self, f: impl FnOnce(&mut Self) -> Result<T>) -> Result<T> {
        self.depth += 1;
        if self.depth > MAX_DEPTH {
            return Err(Error::Depth);
        }
        let r = f(self);
        self.depth -= 1;
        r
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn scalars_round_trip() {
        let mut w = Writer::new();
        w.write_array(9)
            .write_nil()
            .write_bool(true)
            .write_uint(5)
            .write_uint(300)
            .write_uint(70000)
            .write_uint(1 << 40)
            .write_int(-5)
            .write_int(-300)
            .write_str("hello");
        let bytes = w.into_bytes();
        let mut r = Reader::new(&bytes);
        assert_eq!(r.read_array().unwrap(), 9);
        r.read_nil().unwrap();
        assert!(r.read_bool().unwrap());
        assert_eq!(r.read_uint().unwrap(), 5);
        assert_eq!(r.read_uint().unwrap(), 300);
        assert_eq!(r.read_uint().unwrap(), 70000);
        assert_eq!(r.read_uint().unwrap(), 1 << 40);
        assert_eq!(r.read_int().unwrap(), -5);
        assert_eq!(r.read_int().unwrap(), -300);
        assert_eq!(r.read_str().unwrap(), "hello");
        assert_eq!(r.remaining(), 0);
    }

    #[test]
    fn long_strings_bins_and_containers() {
        let long = "x".repeat(300);
        let bin = vec![7u8; 70000];
        let mut w = Writer::new();
        w.write_map(2)
            .write_str("s")
            .write_str(&long)
            .write_str("b")
            .write_bin(&bin);
        let bytes = w.into_bytes();
        let mut r = Reader::new(&bytes);
        assert_eq!(r.read_map().unwrap(), 2);
        assert_eq!(r.read_str().unwrap(), "s");
        assert_eq!(r.read_str().unwrap(), long);
        assert_eq!(r.read_str().unwrap(), "b");
        assert_eq!(r.read_bin().unwrap(), &bin[..]);
    }

    #[test]
    fn skip_walks_nested_values_and_refuses_lies() {
        let mut w = Writer::new();
        w.write_array(2)
            .write_map(1)
            .write_str("k")
            .write_array(1)
            .write_uint(1)
            .write_str("after");
        let bytes = w.into_bytes();
        let mut r = Reader::new(&bytes);
        assert_eq!(r.read_array().unwrap(), 2);
        r.skip().unwrap();
        assert_eq!(r.read_str().unwrap(), "after");
        // An array claiming a billion elements in three bytes.
        let lie = [0xdd, 0x3b, 0x9a, 0xca, 0x00];
        assert_eq!(Reader::new(&lie).read_array(), Err(Error::Truncated));
        let mut deep = vec![0x91u8; 40];
        deep.push(0xc0);
        assert_eq!(Reader::new(&deep).skip(), Err(Error::Depth));
        assert_eq!(Reader::new(&[0xc1]).skip(), Err(Error::Unsupported));
    }

    // Raw wire values exercise forms the protocol's Writer does not emit.
    fn skippable_scalars() -> Vec<Vec<u8>> {
        let mut values = vec![
            vec![0],
            vec![0x7f],
            vec![0xe0],
            vec![0xff],
            vec![0xc0],
            vec![0xc2],
            vec![0xc3],
        ];
        for (tag, len) in [
            (0xcc, 1),
            (0xcd, 2),
            (0xce, 4),
            (0xcf, 8),
            (0xd0, 1),
            (0xd1, 2),
            (0xd2, 4),
            (0xd3, 8),
            (0xca, 4),
            (0xcb, 8),
            (0xd4, 2),
            (0xd5, 3),
            (0xd6, 5),
            (0xd7, 9),
            (0xd8, 17),
        ] {
            let mut value = vec![tag];
            // Includes uint64::MAX, arbitrary float bits and a signed ext type.
            value.extend(vec![0xff; len]);
            values.push(value);
        }
        for (tag, width) in [(0xc7, 1), (0xc8, 2), (0xc9, 4)] {
            for len in [0u32, 3] {
                let mut value = vec![tag];
                value.extend_from_slice(&len.to_be_bytes()[4 - width..]);
                value.push(0xff); // Type byte exists even for empty ext data.
                value.extend(vec![0xc1; len as usize]); // Opaque, not nested values.
                values.push(value);
            }
        }
        values
    }

    #[test]
    fn skip_scalars_and_extensions_preserves_the_next_value() {
        for value in skippable_scalars() {
            let mut bytes = value.clone();
            bytes.push(42);
            let mut r = Reader::new(&bytes);
            assert_eq!(r.skip(), Ok(()), "wire value {value:x?}");
            assert_eq!(r.read_uint(), Ok(42), "wire value {value:x?}");
            assert_eq!(r.remaining(), 0);
            // Every incomplete prefix, including missing ext type/data, fails.
            for end in 0..value.len() {
                assert_eq!(
                    Reader::new(&value[..end]).skip(),
                    Err(Error::Truncated),
                    "wire value {value:x?}, prefix {end}"
                );
            }
        }
    }

    #[test]
    fn skip_float_values() {
        // Independent of the uint64 regression on the old implementation.
        for value in skippable_scalars()
            .into_iter()
            .filter(|v| matches!(v[0], 0xca | 0xcb))
        {
            assert_eq!(Reader::new(&value).skip(), Ok(()), "wire value {value:x?}");
        }
    }

    #[test]
    fn skip_extension_values() {
        // Independent of the float regression on the old implementation.
        for value in skippable_scalars()
            .into_iter()
            .filter(|v| matches!(v[0], 0xc7..=0xc9 | 0xd4..=0xd8))
        {
            assert_eq!(Reader::new(&value).skip(), Ok(()), "wire value {value:x?}");
        }
    }

    #[test]
    fn skip_extended_values_in_nested_map_keys_and_values() {
        for value in skippable_scalars() {
            let mut bytes = vec![0x91, 0x81]; // array containing a map
            bytes.extend_from_slice(&value); // unknown map key
            bytes.push(0x91);
            bytes.extend_from_slice(&value); // array-valued map entry
            bytes.push(42);
            let mut r = Reader::new(&bytes);
            assert_eq!(r.skip(), Ok(()), "wire value {value:x?}");
            assert_eq!(r.read_uint(), Ok(42));
            assert_eq!(r.remaining(), 0);
        }
    }

    #[test]
    fn skip_keeps_depth_utf8_and_reserved_marker_checks() {
        let mut bytes = vec![0x91; MAX_DEPTH as usize];
        bytes.extend_from_slice(&[0xca, 0, 0, 0, 0]);
        assert_eq!(Reader::new(&bytes).skip(), Ok(()));
        bytes.insert(0, 0x91);
        assert_eq!(Reader::new(&bytes).skip(), Err(Error::Depth));
        assert_eq!(Reader::new(&[0xa1, 0xff]).skip(), Err(Error::Utf8));
        assert_eq!(Reader::new(&[0x91, 0xc1]).skip(), Err(Error::Unsupported));
    }

    #[test]
    fn requests_and_replies_ignore_extended_unknown_fields() {
        use crate::{Family, Reply, Request};
        for value in skippable_scalars() {
            let mut w = Writer::new();
            w.write_map(3).write_str("future");
            let mut request = w.into_bytes();
            request.extend_from_slice(&value);
            let mut w = Writer::new();
            w.write_str("query")
                .write_str("lookup")
                .write_str("name")
                .write_str("x");
            request.extend_from_slice(&w.into_bytes());
            assert_eq!(
                Request::decode(&request).unwrap(),
                Request::Lookup {
                    name: "x".into(),
                    family: Family::Any,
                }
            );

            let mut w = Writer::new();
            w.write_map(2).write_str("future").write_array(1);
            let mut reply = w.into_bytes();
            reply.extend_from_slice(&value);
            let mut w = Writer::new();
            w.write_str("ok").write_bool(true);
            reply.extend_from_slice(&w.into_bytes());
            assert_eq!(Reply::decode(&reply).unwrap(), Reply::Ok);
        }
    }

    #[test]
    fn replies_ignore_unknown_counter_values_but_validate_known_counters() {
        use crate::{Reply, StatusReport, WireError};
        for value in skippable_scalars() {
            let mut w = Writer::new();
            w.write_map(3)
                .write_str("ok")
                .write_bool(true)
                .write_str("kind")
                .write_str("status")
                .write_str("counters")
                .write_map(2)
                .write_str("future");
            let mut bytes = w.into_bytes();
            bytes.extend_from_slice(&value);
            let mut w = Writer::new();
            w.write_str("queries").write_uint(42);
            bytes.extend_from_slice(&w.into_bytes());
            let mut status = StatusReport::default();
            status.counters.queries = 42;
            assert_eq!(Reply::decode(&bytes).unwrap(), Reply::Status(status));
        }
        for invalid in [
            vec![0xca, 0, 0, 0, 0],
            vec![0xd4, 0, 0],
            vec![0xff],
            vec![0xcf, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff],
        ] {
            let mut w = Writer::new();
            w.write_map(2)
                .write_str("ok")
                .write_bool(true)
                .write_str("counters")
                .write_map(1)
                .write_str("queries");
            let mut bytes = w.into_bytes();
            bytes.extend_from_slice(&invalid);
            assert!(matches!(
                Reply::decode(&bytes),
                Err(WireError::Encoding(Error::Type))
            ));
            let mut w = Writer::new();
            w.write_map(2)
                .write_str("query")
                .write_str("status")
                .write_str("type");
            let mut bytes = w.into_bytes();
            bytes.extend_from_slice(&invalid);
            assert!(matches!(
                crate::Request::decode(&bytes),
                Err(WireError::Encoding(Error::Type))
            ));
        }
    }
}
