//! timed's control wire.
//!
//! The socket is connectable by everyone, and timed restarts on failure,
//! so a message that crashes it is a local denial of service that repeats
//! for as long as the attacker keeps sending it. This is the target that
//! would have caught the array-count allocation bug in libtrust and
//! libnetd, which is why it exists in the same shape here.
#![no_main]
use libfuzzer_sys::fuzz_target;
use libtimed::{Reply, Request};

fuzz_target!(|data: &[u8]| {
    if let Ok(request) = Request::decode(data) {
        let _ = request.required_right();
        // Anything that decodes must re-encode and decode back to itself.
        assert_eq!(Request::decode(&request.encode()).unwrap(), request);
    }
    if let Ok(reply) = Reply::decode(data) {
        let bytes = reply.encode();
        assert!(bytes.len() <= libtimed::MAX_MESSAGE_BYTES);
        let _ = Reply::decode(&bytes);
    }
    // The framing layer separately: a length prefix is the other place a
    // peer-chosen number reaches an allocation.
    let _ = libtimed::recv(&mut &data[..]);
});
