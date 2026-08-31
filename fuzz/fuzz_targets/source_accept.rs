//! A whole reply, against a source that is expecting one.
//!
//! Broader than `ntp_packet`: it drives the validation path — the origin
//! echo, the NTS identifier comparison, the authenticator, the kiss
//! handling, the sample reduction — with a real `Source` in a real state,
//! which is where the interactions between those checks live.
//!
//! The invariant asserted is the one that matters: **a source must never
//! be marked reachable, and never produce a sample, from a datagram that
//! did not echo the nonce it was sent.** If that ever stops holding, an
//! off-path attacker can move this machine's clock.
#![no_main]
use libfuzzer_sys::fuzz_target;
use ntp::NtpTimestamp;
use timed::source::{Security, Source, DEFAULT_MAX_POLL, DEFAULT_MIN_POLL};

fuzz_target!(|data: &[u8]| {
    let address = "192.0.2.1:123".parse().unwrap();
    let mut source = Source::new(
        "fuzz".into(),
        address,
        Security::Unauthenticated,
        DEFAULT_MIN_POLL,
        DEFAULT_MAX_POLL,
    );
    let wall = NtpTimestamp::from_unix(1_756_000_000, 0);
    let Ok(request) = source.prepare(wall, 0.0) else { return };
    let sent = ntp::Packet::decode(&request).unwrap().transmit_timestamp;

    let destination = NtpTimestamp::from_unix(1_756_000_000, 50_000_000);
    let result = source.accept(data, destination, 1.0);

    // Did this input actually echo the nonce? Only then may anything have
    // been believed. A 64-bit value the fuzzer would have to guess, so in
    // practice this is always false — which is the point.
    let echoed = ntp::Packet::decode(data).is_ok_and(|p| p.origin_timestamp == sent);
    if !echoed {
        assert!(result.is_err(), "a reply that did not echo our nonce was accepted");
        assert_eq!(source.reach, 0, "a forged reply marked the source reachable");
        assert!(source.filter.is_empty(), "a forged reply reached the filter");
    }
});
