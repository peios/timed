//! Anything can arrive on a UDP socket.
//!
//! The one target that matters most: this is the exact byte string a
//! stranger on the path can put in front of the parser, with no
//! authentication in the way, because authentication happens after
//! parsing and cannot happen before it.
#![no_main]
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let Ok(packet) = ntp::Packet::decode(data) else { return };

    // A packet that decoded must re-encode without panicking, and every
    // accessor over it must be total. Round-tripping is deliberately not
    // asserted to be byte-identical: extension-field padding is not kept,
    // so a field with a longer declared length than its value re-encodes
    // shorter. That is why the authenticator verifies against the received
    // bytes rather than a re-encoding, and this target is where that would
    // be caught if it ever stopped being true.
    let bytes = packet.encode();
    assert!(bytes.len() >= ntp::HEADER_LEN);

    let _ = packet.is_kiss_of_death();
    let _ = packet.reference_id.to_string();
    let _ = packet.extension(ntp::NTS_UNIQUE_IDENTIFIER);
    let _ = packet.extension(ntp::NTS_AUTHENTICATOR);
    for field in &packet.extensions {
        // The offset walk `Source::verify` performs, which must never
        // exceed the datagram it is walking.
        assert!(field.encoded_len() >= 16);
        assert!(field.encoded_len() % 4 == 0);
    }
    let total: usize = packet.extensions.iter().map(|f| f.encoded_len()).sum();
    assert!(ntp::HEADER_LEN + total <= data.len() + 16);
});
