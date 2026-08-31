//! The NTPv4 message, RFC 5905 §7.3.
//!
//! Forty-eight fixed bytes, optionally followed by extension fields. The
//! fixed part has no length field anywhere in it, which makes it pleasant to
//! parse and means the only bound that matters is the buffer's own.

use crate::extension::ExtensionField;
use crate::timestamp::{NtpShort, NtpTimestamp};
use crate::WireError;

/// The NTP version this client speaks and the only one it accepts back.
pub const VERSION: u8 = 4;

/// The fixed header, before any extension field.
pub const HEADER_LEN: usize = 48;

/// A datagram larger than this is not something we asked for. The ceiling is
/// generous — a server's reply carries at most a handful of extension fields
/// and eight fresh cookies — and exists so that a peer cannot make us hold
/// an arbitrary amount of memory by sending a very large UDP packet, which
/// on a socket anyone on the path can write to is a cheap thing to try.
pub const MAX_PACKET: usize = 9000;

/// The leap indicator: what the server says is about to happen to UTC.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LeapIndicator {
    NoWarning,
    /// The last minute of the day has 61 seconds.
    Insert,
    /// The last minute of the day has 59 seconds.
    Delete,
    /// The server is not synchronised. Note that this is the *same* two-bit
    /// value as "alarm condition" in older text; either way the answer is
    /// unusable, which is the only thing a client needs to conclude.
    Unsynchronised,
}

impl LeapIndicator {
    fn from_bits(bits: u8) -> LeapIndicator {
        match bits & 0b11 {
            0 => LeapIndicator::NoWarning,
            1 => LeapIndicator::Insert,
            2 => LeapIndicator::Delete,
            _ => LeapIndicator::Unsynchronised,
        }
    }

    fn to_bits(self) -> u8 {
        match self {
            LeapIndicator::NoWarning => 0,
            LeapIndicator::Insert => 1,
            LeapIndicator::Delete => 2,
            LeapIndicator::Unsynchronised => 3,
        }
    }
}

/// The association mode. A client only ever sends [`Mode::Client`] and only
/// ever accepts [`Mode::Server`]; the rest are here to be recognised and
/// refused, because a symmetric or broadcast packet arriving at a client is
/// either a misconfiguration or somebody trying something.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mode {
    Reserved,
    SymmetricActive,
    SymmetricPassive,
    Client,
    Server,
    Broadcast,
    Control,
    Private,
}

impl Mode {
    fn from_bits(bits: u8) -> Mode {
        match bits & 0b111 {
            0 => Mode::Reserved,
            1 => Mode::SymmetricActive,
            2 => Mode::SymmetricPassive,
            3 => Mode::Client,
            4 => Mode::Server,
            5 => Mode::Broadcast,
            6 => Mode::Control,
            _ => Mode::Private,
        }
    }

    fn to_bits(self) -> u8 {
        match self {
            Mode::Reserved => 0,
            Mode::SymmetricActive => 1,
            Mode::SymmetricPassive => 2,
            Mode::Client => 3,
            Mode::Server => 4,
            Mode::Broadcast => 5,
            Mode::Control => 6,
            Mode::Private => 7,
        }
    }
}

/// The four-byte reference identifier, whose meaning depends on the stratum.
///
/// At stratum 0 it is a "kiss code": four ASCII characters saying why there
/// is no time in this packet. At stratum 1 it names the reference clock. At
/// stratum 2 and above it identifies the upstream server, which is how a
/// client detects a synchronisation loop — and, incidentally, the only field
/// in NTP that leaks a server's own upstream.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct ReferenceId(pub [u8; 4]);

impl ReferenceId {
    /// The kiss code, if this is a stratum-0 packet and the bytes are
    /// printable ASCII. Returned as a fixed array rather than a `&str` so
    /// that reading it cannot fail and cannot allocate.
    pub fn kiss_code(self) -> Option<[u8; 4]> {
        self.0.iter().all(|b| b.is_ascii_uppercase()).then_some(self.0)
    }

    /// "Slow down": the server is rate-limiting us and we must back off.
    /// The one kiss code a well-behaved client is obliged to obey.
    pub const RATE: ReferenceId = ReferenceId(*b"RATE");
    /// "Go away, permanently."
    pub const DENY: ReferenceId = ReferenceId(*b"DENY");
    /// "Go away, you are not permitted here."
    pub const RSTR: ReferenceId = ReferenceId(*b"RSTR");
    /// RFC 8915 §5.7: NTS negative-acknowledgement. Our cookie was not
    /// accepted, so the key establishment has to be redone.
    pub const NTSN: ReferenceId = ReferenceId(*b"NTSN");
}

impl core::fmt::Display for ReferenceId {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self.kiss_code() {
            Some(code) => write!(f, "{}", String::from_utf8_lossy(&code)),
            None => write!(f, "{}.{}.{}.{}", self.0[0], self.0[1], self.0[2], self.0[3]),
        }
    }
}

/// A parsed NTP message.
///
/// The extension fields are kept in wire order and unmodified, because NTS
/// authentication covers the bytes rather than the meaning: re-encoding and
/// re-authenticating is not the same operation as verifying what arrived.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Packet {
    pub leap: LeapIndicator,
    pub version: u8,
    pub mode: Mode,
    pub stratum: u8,
    /// log2 of the server's preferred poll interval, in seconds.
    pub poll: i8,
    /// log2 of the server's clock precision, in seconds. Always negative in
    /// practice; a modern server reports around -24 (about 60 ns).
    pub precision: i8,
    pub root_delay: NtpShort,
    pub root_dispersion: NtpShort,
    pub reference_id: ReferenceId,
    pub reference_timestamp: NtpTimestamp,
    /// T1 as the server echoes it: what we put in `transmit` when we asked.
    /// This is the client's whole defence against an off-path attacker, so
    /// it must be checked against a value the attacker could not guess.
    pub origin_timestamp: NtpTimestamp,
    /// T2: when the server received our request.
    pub receive_timestamp: NtpTimestamp,
    /// T3: when the server sent this reply.
    pub transmit_timestamp: NtpTimestamp,
    pub extensions: Vec<ExtensionField>,
}

impl Default for Packet {
    fn default() -> Packet {
        Packet {
            leap: LeapIndicator::NoWarning,
            version: VERSION,
            mode: Mode::Client,
            stratum: 0,
            poll: 6,
            precision: 0,
            root_delay: NtpShort(0),
            root_dispersion: NtpShort(0),
            reference_id: ReferenceId::default(),
            reference_timestamp: NtpTimestamp::UNKNOWN,
            origin_timestamp: NtpTimestamp::UNKNOWN,
            receive_timestamp: NtpTimestamp::UNKNOWN,
            transmit_timestamp: NtpTimestamp::UNKNOWN,
            extensions: Vec::new(),
        }
    }
}

fn u32_at(bytes: &[u8], at: usize) -> u32 {
    u32::from_be_bytes([bytes[at], bytes[at + 1], bytes[at + 2], bytes[at + 3]])
}

fn u64_at(bytes: &[u8], at: usize) -> u64 {
    let mut buf = [0u8; 8];
    buf.copy_from_slice(&bytes[at..at + 8]);
    u64::from_be_bytes(buf)
}

impl Packet {
    /// Read a datagram.
    ///
    /// Everything past the fixed header is parsed as extension fields, and a
    /// trailing run that is not a well-formed extension field makes the
    /// whole packet malformed rather than being ignored. That is stricter
    /// than RFC 7822 requires of a server, and deliberately so: for a
    /// *client*, bytes it cannot account for at the end of a packet it is
    /// about to set the system clock from are not something to shrug at.
    ///
    /// The one exception is a legacy MAC — 20 or 24 trailing bytes that are
    /// a key identifier and a digest rather than an extension field. RFC
    /// 7822 §7.5 makes it unambiguous by length, and a symmetric-key client
    /// (v2 work) will want it, so it is recognised and carried rather than
    /// rejected.
    pub fn decode(bytes: &[u8]) -> Result<Packet, WireError> {
        if bytes.len() < HEADER_LEN {
            return Err(WireError::Truncated { need: HEADER_LEN, have: bytes.len() });
        }
        if bytes.len() > MAX_PACKET {
            return Err(WireError::BadLength(bytes.len() as u32));
        }

        let flags = bytes[0];
        let packet = Packet {
            leap: LeapIndicator::from_bits(flags >> 6),
            version: (flags >> 3) & 0b111,
            mode: Mode::from_bits(flags),
            stratum: bytes[1],
            poll: bytes[2] as i8,
            precision: bytes[3] as i8,
            root_delay: NtpShort(u32_at(bytes, 4)),
            root_dispersion: NtpShort(u32_at(bytes, 8)),
            reference_id: ReferenceId([bytes[12], bytes[13], bytes[14], bytes[15]]),
            reference_timestamp: NtpTimestamp(u64_at(bytes, 16)),
            origin_timestamp: NtpTimestamp(u64_at(bytes, 24)),
            receive_timestamp: NtpTimestamp(u64_at(bytes, 32)),
            transmit_timestamp: NtpTimestamp(u64_at(bytes, 40)),
            extensions: ExtensionField::decode_all(&bytes[HEADER_LEN..])?,
        };
        Ok(packet)
    }

    /// Write the packet, header then extension fields in the order held.
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(HEADER_LEN + 64);
        out.push((self.leap.to_bits() << 6) | ((self.version & 0b111) << 3) | self.mode.to_bits());
        out.push(self.stratum);
        out.push(self.poll as u8);
        out.push(self.precision as u8);
        out.extend_from_slice(&self.root_delay.0.to_be_bytes());
        out.extend_from_slice(&self.root_dispersion.0.to_be_bytes());
        out.extend_from_slice(&self.reference_id.0);
        out.extend_from_slice(&self.reference_timestamp.0.to_be_bytes());
        out.extend_from_slice(&self.origin_timestamp.0.to_be_bytes());
        out.extend_from_slice(&self.receive_timestamp.0.to_be_bytes());
        out.extend_from_slice(&self.transmit_timestamp.0.to_be_bytes());
        for field in &self.extensions {
            field.encode_into(&mut out);
        }
        out
    }

    /// The first extension field of this type, if there is one.
    pub fn extension(&self, field_type: u16) -> Option<&ExtensionField> {
        self.extensions.iter().find(|f| f.field_type == field_type)
    }

    /// True when this reply carries no time and is only telling us
    /// something — stratum 0 with a kiss code in the reference id.
    pub fn is_kiss_of_death(&self) -> bool {
        self.stratum == 0 && self.reference_id.kiss_code().is_some()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn client_request() -> Packet {
        Packet {
            mode: Mode::Client,
            version: 4,
            poll: 6,
            transmit_timestamp: NtpTimestamp(0x1234_5678_9ABC_DEF0),
            ..Packet::default()
        }
    }

    #[test]
    fn a_request_round_trips() {
        let packet = client_request();
        let bytes = packet.encode();
        assert_eq!(bytes.len(), HEADER_LEN);
        assert_eq!(Packet::decode(&bytes).unwrap(), packet);
    }

    #[test]
    fn the_first_byte_packs_the_way_rfc_5905_draws_it() {
        // LI = 0, VN = 4, Mode = 3 (client) is 0b00_100_011 = 0x23, which is
        // the byte every packet capture of an NTP request starts with.
        assert_eq!(client_request().encode()[0], 0x23);
    }

    #[test]
    fn a_short_datagram_is_truncated_not_padded() {
        let bytes = [0u8; HEADER_LEN - 1];
        assert!(matches!(Packet::decode(&bytes), Err(WireError::Truncated { .. })));
    }

    #[test]
    fn an_enormous_datagram_is_refused_before_it_is_walked() {
        let bytes = vec![0u8; MAX_PACKET + 1];
        assert!(matches!(Packet::decode(&bytes), Err(WireError::BadLength(_))));
    }

    #[test]
    fn a_kiss_of_death_is_recognised_and_carries_no_time() {
        let mut packet = Packet::default();
        packet.stratum = 0;
        packet.reference_id = ReferenceId::RATE;
        assert!(packet.is_kiss_of_death());
        assert_eq!(packet.reference_id.to_string(), "RATE");

        // A stratum-2 server whose upstream happens to be 82.65.84.69 must
        // not be read as a kiss: the stratum is what distinguishes them.
        let mut server = Packet::default();
        server.stratum = 2;
        server.reference_id = ReferenceId::RATE;
        assert!(!server.is_kiss_of_death());
    }

    #[test]
    fn every_byte_of_the_header_survives_a_round_trip() {
        // Distinct values in every field, so a copy-paste error reading one
        // field into another's offset cannot pass.
        let packet = Packet {
            leap: LeapIndicator::Delete,
            version: 4,
            mode: Mode::Server,
            stratum: 2,
            poll: -3,
            precision: -24,
            root_delay: NtpShort(0x0001_0002),
            root_dispersion: NtpShort(0x0003_0004),
            reference_id: ReferenceId([5, 6, 7, 8]),
            reference_timestamp: NtpTimestamp(0x0102_0304_0506_0708),
            origin_timestamp: NtpTimestamp(0x1112_1314_1516_1718),
            receive_timestamp: NtpTimestamp(0x2122_2324_2526_2728),
            transmit_timestamp: NtpTimestamp(0x3132_3334_3536_3738),
            extensions: Vec::new(),
        };
        assert_eq!(Packet::decode(&packet.encode()).unwrap(), packet);
    }
}
