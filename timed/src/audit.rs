//! The record timed writes: `timed.clock.stepped` (`timed.evman`).
//!
//! A step is the one thing timed does that changes every timestamp written
//! after it, including the times on every other record in the event store,
//! so it is `essential` (PGSS §6.8): written unconditionally, without asking
//! the emission policy. The steady rate corrections timed makes after every
//! poll are not steps and are not recorded; they never move the clock by
//! more than the discipline allows.
//!
//! Writing needs `SeAuditPrivilege`, which `timed-policy.reg` grants to
//! timed's service SID and `timed-service.reg` keeps in `RequiredPrivileges`.
//! A record that cannot be written is a warning in the log, never a reason
//! to leave the clock alone.

use peios::msgpack::Writer;

use crate::log;

/// The event type.
pub const CLOCK_STEPPED: &str = "timed.clock.stepped";

/// What moved the clock: the record's `operation.name`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Step {
    /// The discipline decided the offset was too large to slew.
    Automatic,
    /// Somebody asked timed to set it (`clock set`).
    Manual,
    /// It read before the build's timestamp at startup and was raised.
    BootFloor,
}

impl Step {
    pub fn name(self) -> &'static str {
        match self {
            Step::Automatic => "automatic",
            Step::Manual => "manual",
            Step::BootFloor => "boot-floor",
        }
    }
}

/// A Unix time as `uint.time`: nanoseconds since the epoch. `None` before
/// the epoch, which an unsigned count cannot carry; a clock with a dead RTC
/// can read that, and the boot floor exists for it.
pub fn unix_nanos(seconds: i64, nanos: u32) -> Option<u64> {
    let seconds = u64::try_from(seconds).ok()?;
    seconds
        .checked_mul(1_000_000_000)?
        .checked_add(u64::from(nanos))
}

/// The payload of a `timed.clock.stepped` record.
///
/// `previous` and `now` are the wall clock read just before and just after
/// the step, as `uint.time`; either is left out when it has no value.
/// `subject` is the binary SID of the caller who asked for a manual set;
/// an automatic step and the boot floor are timed's own decisions and carry
/// none.
pub fn clock_stepped_payload(
    step: Step,
    previous: Option<u64>,
    now: Option<u64>,
    subject: Option<&[u8]>,
) -> peios::Result<Vec<u8>> {
    let clock_fields = u32::from(previous.is_some()) + u32::from(now.is_some());
    let top = 1 + u32::from(clock_fields > 0) + u32::from(subject.is_some());
    let mut w = Writer::new();
    w.write_map(top);
    w.write_str("operation")
        .write_map(1)
        .write_str("name")
        .write_str(step.name());
    if clock_fields > 0 {
        w.write_str("clock").write_map(clock_fields);
        if let Some(now) = now {
            w.write_str("time").write_uint(now);
        }
        if let Some(previous) = previous {
            w.write_str("time-previous").write_uint(previous);
        }
    }
    if let Some(sid) = subject {
        w.write_str("subject")
            .write_map(1)
            .write_str("token")
            .write_map(1)
            .write_str("sid")
            .write_bin(sid);
    }
    w.to_bytes()
}

/// Write a `timed.clock.stepped` record. Failure is logged, not returned:
/// the clock has already moved, and nothing the caller could do differs.
pub fn clock_stepped(step: Step, previous: Option<u64>, now: Option<u64>, subject: Option<&[u8]>) {
    let result = clock_stepped_payload(step, previous, now, subject)
        .and_then(|payload| peios::event::emit(CLOCK_STEPPED, &payload));
    if let Err(e) = result {
        log::warn(format_args!(
            "could not record the {} step as {CLOCK_STEPPED}: {e}",
            step.name()
        ));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use peios::msgpack::{Reader, Type};
    use std::collections::BTreeMap;

    /// A decoded payload value, enough to check what a record carries.
    #[derive(Debug, PartialEq)]
    enum V {
        Map(BTreeMap<String, V>),
        Str(String),
        Uint(u64),
        Bin(Vec<u8>),
    }

    fn decode(r: &mut Reader<'_>) -> V {
        match r.peek().expect("a value") {
            Type::Map => {
                let n = r.read_map().unwrap();
                let mut m = BTreeMap::new();
                for _ in 0..n {
                    let k = r.read_str().unwrap().to_owned();
                    let v = decode(r);
                    assert!(m.insert(k, v).is_none(), "a key is written once");
                }
                V::Map(m)
            }
            Type::Str => V::Str(r.read_str().unwrap().to_owned()),
            Type::Int => V::Uint(r.read_uint().unwrap()),
            Type::Bin => V::Bin(r.read_bin().unwrap().to_vec()),
            other => panic!("unexpected {other:?}"),
        }
    }

    fn parse(bytes: &[u8]) -> V {
        let mut r = Reader::new(bytes);
        let v = decode(&mut r);
        assert_eq!(r.remaining(), 0, "one value, nothing after it");
        v
    }

    fn at<'a>(v: &'a V, path: &str) -> Option<&'a V> {
        path.split('.').try_fold(v, |v, key| match v {
            V::Map(m) => m.get(key),
            _ => None,
        })
    }

    #[test]
    fn an_automatic_step_carries_both_times_and_no_subject() {
        let bytes =
            clock_stepped_payload(Step::Automatic, Some(1_000), Some(5_000_000_000), None).unwrap();
        let v = parse(&bytes);
        assert_eq!(at(&v, "operation.name"), Some(&V::Str("automatic".into())));
        assert_eq!(at(&v, "clock.time"), Some(&V::Uint(5_000_000_000)));
        assert_eq!(at(&v, "clock.time-previous"), Some(&V::Uint(1_000)));
        assert_eq!(at(&v, "subject"), None);
    }

    #[test]
    fn a_manual_set_carries_the_callers_sid_as_binary() {
        let sid = [1u8, 1, 0, 0, 0, 0, 0, 5, 18, 0, 0, 0];
        let bytes = clock_stepped_payload(Step::Manual, Some(1), Some(2), Some(&sid)).unwrap();
        let v = parse(&bytes);
        assert_eq!(at(&v, "operation.name"), Some(&V::Str("manual".into())));
        assert_eq!(at(&v, "subject.token.sid"), Some(&V::Bin(sid.to_vec())));
    }

    #[test]
    fn a_time_before_the_epoch_is_left_out_rather_than_written_as_zero() {
        assert_eq!(unix_nanos(-1, 0), None);
        assert_eq!(unix_nanos(0, 5), Some(5));
        assert_eq!(unix_nanos(2, 3), Some(2_000_000_003));
        let bytes = clock_stepped_payload(Step::BootFloor, None, Some(9), None).unwrap();
        let v = parse(&bytes);
        assert_eq!(at(&v, "operation.name"), Some(&V::Str("boot-floor".into())));
        assert_eq!(at(&v, "clock.time"), Some(&V::Uint(9)));
        assert_eq!(at(&v, "clock.time-previous"), None);
        // With neither time there is no empty `clock` map either.
        let bytes = clock_stepped_payload(Step::BootFloor, None, None, None).unwrap();
        assert_eq!(at(&parse(&bytes), "clock"), None);
    }
}
