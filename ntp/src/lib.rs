//! NTPv4 and NTS on the wire.
//!
//! This crate reads and writes bytes and does nothing else: no sockets, no
//! clock, no policy, no decision about whether a server is worth believing.
//! That separation is deliberate. Every hostile byte a time client will ever
//! see arrives through this crate, from a UDP port that anyone on the path
//! can write to, so it is the part that has to be provably careful — and the
//! part that is worth fuzzing, which requires that it be reachable without a
//! network.
//!
//! Three formats live here:
//!
//! - [`Packet`], the NTPv4 message of RFC 5905 §7.3.
//! - [`ExtensionField`], the extension-field encoding of RFC 7822, and the
//!   four NTS fields of RFC 8915 §5 built on it.
//! - [`nts::Record`], the NTS-KE record format of RFC 8915 §4, which is
//!   carried over TLS rather than UDP.
//!
//! # On trusting lengths
//!
//! Both formats are length-prefixed by a peer we have no reason to believe,
//! and both are read from a buffer we already hold in full — a datagram, or
//! a TLS record stream. So the rule throughout is that a declared length is
//! checked against what is actually present *before* it is used for
//! anything, and never used to size an allocation. There is no case in
//! either format where the honest thing to do with a length past the end of
//! the buffer is anything other than reject the whole message.

#![forbid(unsafe_code)]

pub mod nts;

mod extension;
mod packet;
mod timestamp;

pub use extension::{ExtensionField, NTS_AUTHENTICATOR, NTS_COOKIE, NTS_COOKIE_PLACEHOLDER, NTS_UNIQUE_IDENTIFIER};
pub use packet::{LeapIndicator, Mode, Packet, ReferenceId};
pub use timestamp::{NtpTimestamp, UNIX_TO_NTP_ERA0};

/// What went wrong reading something off the wire.
///
/// Deliberately coarse. A time client does not act differently on a packet
/// that was truncated than on one whose extension fields did not add up —
/// both are "this is not an answer", both are counted, and neither should
/// ever be reported to the sender. The variants exist so a log line and a
/// fuzz-target failure can say which shape of wrong it was.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WireError {
    /// Fewer bytes than the format's fixed part requires.
    Truncated { need: usize, have: usize },
    /// A declared length runs past the end of what we hold, or is not a
    /// legal length for its field.
    BadLength(u32),
    /// A field whose value is not one this version understands, where the
    /// format does not permit skipping it.
    Unsupported(&'static str),
    /// Structurally sound and cryptographically wrong: the authenticator
    /// did not open, or did not cover what it should have.
    NotAuthentic,
    /// The message says it is not NTPv4, or not the mode we asked for.
    NotOurs(&'static str),
}

impl core::fmt::Display for WireError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            WireError::Truncated { need, have } => {
                write!(f, "truncated: needs {need} bytes, has {have}")
            }
            WireError::BadLength(n) => write!(f, "illegal length {n}"),
            WireError::Unsupported(what) => write!(f, "unsupported {what}"),
            WireError::NotAuthentic => write!(f, "authenticator did not verify"),
            WireError::NotOurs(what) => write!(f, "not ours: {what}"),
        }
    }
}

impl std::error::Error for WireError {}
