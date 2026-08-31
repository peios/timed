//! Extension fields, RFC 7822, and the four NTS fields built on them.
//!
//! ```text
//! +---------------+---------------+
//! | Field Type u16| Field Len u16 |
//! +---------------+---------------+
//! | Value ...                     |
//! | Padding to a multiple of four |
//! +-------------------------------+
//! ```
//!
//! The field length covers the four-byte header and the padding, so it is
//! the whole field. That makes the parse loop a simple walk — and makes a
//! declared length of zero an infinite loop in any implementation that does
//! not check for it, which is why the legal minimum is enforced here rather
//! than left to the caller.

use crate::WireError;

/// RFC 8915 §5.3. A random value the client chooses and the server echoes,
/// unpredictable to anyone off the path. This is what makes an NTS reply
/// impossible to forge blind, and it is checked before anything else in the
/// packet is believed.
pub const NTS_UNIQUE_IDENTIFIER: u16 = 0x0104;
/// RFC 8915 §5.4. An opaque blob from the server that lets it recover our
/// keys without keeping per-client state. Used once and replaced.
pub const NTS_COOKIE: u16 = 0x0204;
/// RFC 8915 §5.5. Zeroes the size of a cookie, sent to make the request as
/// large as the reply so that NTS cannot be used as a traffic amplifier.
pub const NTS_COOKIE_PLACEHOLDER: u16 = 0x0304;
/// RFC 8915 §5.6. The AEAD tag over everything before it, plus a ciphertext
/// holding the extension fields that travel encrypted.
pub const NTS_AUTHENTICATOR: u16 = 0x0404;

/// The smallest legal extension field, RFC 7822 §7.5: four bytes of header
/// and twelve of value. Anything shorter is ambiguous against a legacy MAC.
pub const MIN_FIELD: usize = 16;

/// One extension field, value unpadded.
///
/// The padding is not kept because it is not information — but note that it
/// *is* covered by the NTS authenticator, so anything that re-encodes a
/// field and expects the bytes to match must pad it identically. That is
/// why [`Self::encode_into`] is the only way to write one.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExtensionField {
    pub field_type: u16,
    pub value: Vec<u8>,
}

/// A trailing legacy MAC, kept rather than discarded so that symmetric-key
/// authentication (RFC 8573, v2 work) has somewhere to land.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LegacyMac {
    pub key_id: u32,
    pub digest: Vec<u8>,
}

fn padded_len(value_len: usize) -> usize {
    let total = 4 + value_len;
    // Round up to a multiple of four, then up to the legal minimum.
    total.div_ceil(4) * 4
}

impl ExtensionField {
    pub fn new(field_type: u16, value: impl Into<Vec<u8>>) -> ExtensionField {
        ExtensionField { field_type, value: value.into() }
    }

    /// Append this field, padded, to a buffer.
    pub fn encode_into(&self, out: &mut Vec<u8>) {
        let len = padded_len(self.value.len()).max(MIN_FIELD);
        out.extend_from_slice(&self.field_type.to_be_bytes());
        out.extend_from_slice(&(len as u16).to_be_bytes());
        out.extend_from_slice(&self.value);
        out.resize(out.len() + (len - 4 - self.value.len()), 0);
    }

    /// How many bytes this field occupies on the wire.
    pub fn encoded_len(&self) -> usize {
        padded_len(self.value.len()).max(MIN_FIELD)
    }

    /// Walk everything after the fixed header.
    ///
    /// Returns fields in wire order. A legacy MAC at the end is consumed and
    /// dropped here; [`decode_all_with_mac`] keeps it.
    pub fn decode_all(bytes: &[u8]) -> Result<Vec<ExtensionField>, WireError> {
        decode_all_with_mac(bytes).map(|(fields, _)| fields)
    }
}

/// Walk the extension-field area, returning the fields and any trailing MAC.
///
/// The ambiguity RFC 7822 §7.5 exists to resolve is that a 20- or 24-byte
/// tail could be either a final extension field or a legacy MAC. It is
/// resolved in favour of the MAC, as the RFC directs — which is safe for
/// this client because no NTS field is ever that size: the unique identifier
/// is 36 bytes, and the authenticator is far larger.
pub fn decode_all_with_mac(
    bytes: &[u8],
) -> Result<(Vec<ExtensionField>, Option<LegacyMac>), WireError> {
    let mut fields = Vec::new();
    let mut rest = bytes;

    loop {
        match rest.len() {
            0 => return Ok((fields, None)),
            // A crypto-NAK: a key identifier and no digest, meaning "I know
            // that key and your MAC was wrong".
            4 => {
                let key_id = u32::from_be_bytes([rest[0], rest[1], rest[2], rest[3]]);
                return Ok((fields, Some(LegacyMac { key_id, digest: Vec::new() })));
            }
            // Key identifier plus a 128- or 160-bit digest.
            20 | 24 => {
                let key_id = u32::from_be_bytes([rest[0], rest[1], rest[2], rest[3]]);
                return Ok((fields, Some(LegacyMac { key_id, digest: rest[4..].to_vec() })));
            }
            len if len < MIN_FIELD => return Err(WireError::BadLength(len as u32)),
            _ => {}
        }

        let field_type = u16::from_be_bytes([rest[0], rest[1]]);
        let field_len = u16::from_be_bytes([rest[2], rest[3]]) as usize;

        // Three ways a length can be a lie, and all of them end the parse.
        // The first is the one that matters most: a length below the header
        // size would advance the cursor by zero or backwards, and an
        // implementation that trusts it loops forever on a four-byte
        // datagram anyone can send.
        if field_len < MIN_FIELD || field_len % 4 != 0 || field_len > rest.len() {
            return Err(WireError::BadLength(field_len as u32));
        }

        fields.push(ExtensionField {
            field_type,
            value: rest[4..field_len].to_vec(),
        });
        rest = &rest[field_len..];
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_field_pads_to_four_and_to_the_minimum() {
        let mut out = Vec::new();
        ExtensionField::new(0x0104, vec![0xAA; 3]).encode_into(&mut out);
        // Three bytes of value would be a 7-byte field; the minimum is 16.
        assert_eq!(out.len(), 16);
        assert_eq!(&out[0..2], &[0x01, 0x04]);
        assert_eq!(&out[2..4], &[0x00, 0x10]);
        assert_eq!(&out[4..7], &[0xAA; 3]);
        assert_eq!(&out[7..], &[0u8; 9]);
    }

    #[test]
    fn fields_round_trip_in_order() {
        let fields = vec![
            ExtensionField::new(NTS_UNIQUE_IDENTIFIER, vec![1u8; 32]),
            ExtensionField::new(NTS_COOKIE, vec![2u8; 100]),
        ];
        let mut out = Vec::new();
        for f in &fields {
            f.encode_into(&mut out);
        }
        let (back, mac) = decode_all_with_mac(&out).unwrap();
        assert_eq!(back, fields);
        assert!(mac.is_none());
    }

    #[test]
    fn a_zero_length_field_does_not_loop_forever() {
        // The whole reason the minimum is enforced in the parser. Before
        // the check, this input advances the cursor by zero and spins.
        let bytes = [0x01, 0x04, 0x00, 0x00, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
        assert!(matches!(decode_all_with_mac(&bytes), Err(WireError::BadLength(0))));
    }

    #[test]
    fn a_length_past_the_buffer_is_refused() {
        let mut bytes = vec![0u8; 20];
        bytes[0..2].copy_from_slice(&0x0104u16.to_be_bytes());
        bytes[2..4].copy_from_slice(&64u16.to_be_bytes());
        // 20 bytes would read as a MAC; make it 28 so it reaches the length
        // check with a declared 64.
        bytes.resize(28, 0);
        bytes[2..4].copy_from_slice(&64u16.to_be_bytes());
        assert!(matches!(decode_all_with_mac(&bytes), Err(WireError::BadLength(64))));
    }

    #[test]
    fn a_length_that_is_not_a_multiple_of_four_is_refused() {
        let mut bytes = vec![0u8; 32];
        bytes[0..2].copy_from_slice(&0x0104u16.to_be_bytes());
        bytes[2..4].copy_from_slice(&18u16.to_be_bytes());
        assert!(matches!(decode_all_with_mac(&bytes), Err(WireError::BadLength(18))));
    }

    #[test]
    fn a_trailing_mac_is_taken_as_a_mac_not_a_field() {
        let mut bytes = Vec::new();
        ExtensionField::new(NTS_UNIQUE_IDENTIFIER, vec![7u8; 32]).encode_into(&mut bytes);
        bytes.extend_from_slice(&0xDEAD_BEEFu32.to_be_bytes());
        bytes.extend_from_slice(&[9u8; 16]);
        let (fields, mac) = decode_all_with_mac(&bytes).unwrap();
        assert_eq!(fields.len(), 1);
        let mac = mac.expect("20 trailing bytes are a MAC");
        assert_eq!(mac.key_id, 0xDEAD_BEEF);
        assert_eq!(mac.digest, vec![9u8; 16]);
    }

    #[test]
    fn a_short_unaccountable_tail_is_malformed() {
        // Eight bytes is neither a legal field nor any legal MAC length.
        assert!(matches!(decode_all_with_mac(&[0u8; 8]), Err(WireError::BadLength(8))));
    }
}
