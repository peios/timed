//! The NTS-KE record stream.
//!
//! Arrives over TLS from a server whose certificate we validated, so this
//! is a defence against a server that is broken or has turned hostile
//! rather than against a stranger — a category worth defending against,
//! since the whole point of NTS is that a time server is not trusted with
//! very much.
#![no_main]
use libfuzzer_sys::fuzz_target;
use ntp::nts;

fuzz_target!(|data: &[u8]| {
    match nts::Record::decode_message(data) {
        Ok(Some(records)) => {
            // A complete message is interpreted, which is where the
            // per-record length and content checks live.
            let _ = nts::interpret(&records);
            for record in &records {
                let _ = record.body_as_u16();
                let _ = record.body_as_u16s();
                let mut out = Vec::new();
                record.encode_into(&mut out);
            }
        }
        // An incomplete prefix must never be reported as complete, and a
        // complete message must never be reported as needing more: the
        // first would parse half a message, the second would hang the
        // handshake waiting for bytes that will not come.
        Ok(None) => {}
        Err(_) => {}
    }
});
