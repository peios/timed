//! `clock` — the time client's operator command.
//!
//! Reads over timed's socket and prints. It writes no policy: the machine's
//! time policy lives in `Machine\System\Time`, and `reg` is how a registry
//! value is set, so a second way of writing the same values would be a
//! second permission model to keep in step with the first. The two verbs
//! that act are `reload`, which asks timed to re-read what `reg` wrote, and
//! `set`, which asks timed to set the clock while `Automatic` is 0.
//!
//! It is called `clock` rather than `time` because `time` is a shell
//! keyword: `time status` would run `status` and report how long it took.

use std::os::unix::net::UnixStream;
use std::process::ExitCode;

use libtimed::{Reply, Request, SOCKET_PATH, SourceState, Sync};

/// Done.
const OK: u8 = 0;
/// It went wrong: the daemon is unreachable, or refused.
const FAILED: u8 = 1;
/// Asked about something that is not there.
const ABSENT: u8 = 2;
/// The command line was not understood.
const USAGE: u8 = 64;

const HELP: &str = "\
usage: clock <command>

  status              how well the clock is being kept
  sources             every configured source and how it is faring
  reload              re-read Machine\\System\\Time and poll now
  set TIME            set the clock, while Automatic is 0
                      TIME is local: 2026-10-04 14:05 or 2026-10-04 14:05:30,
                      or @SECONDS since 1970 (UTC)

Time policy is registry configuration; set it with reg, then `clock reload`.
";

fn main() -> ExitCode {
    // Restored because Rust ignores SIGPIPE at startup, which turns
    // `clock sources | head` into an error rather than a clean stop.
    unsafe { libc::signal(libc::SIGPIPE, libc::SIG_DFL) };

    let arguments: Vec<String> = std::env::args().skip(1).collect();
    let command = arguments.first().map(String::as_str).unwrap_or("status");

    let code = match command {
        "-h" | "--help" | "help" => {
            print!("{HELP}");
            OK
        }
        "status" => status(),
        "sources" => sources(),
        "reload" => reload(),
        "set" => match arguments[1..].join(" ").as_str() {
            "" => {
                eprintln!("clock: set needs a time");
                eprint!("{HELP}");
                USAGE
            }
            time => set(time),
        },
        other => {
            eprintln!("clock: unknown command {other:?}");
            eprint!("{HELP}");
            USAGE
        }
    };
    ExitCode::from(code)
}

fn connect() -> Result<UnixStream, String> {
    UnixStream::connect(SOCKET_PATH)
        .map_err(|e| format!("cannot reach timed at {SOCKET_PATH}: {e}"))
}

fn ask(request: Request) -> Result<Reply, String> {
    let mut stream = connect()?;
    stream
        .set_read_timeout(Some(std::time::Duration::from_secs(10)))
        .map_err(|e| e.to_string())?;
    libtimed::call(&mut stream, &request).map_err(|e| e.to_string())
}

fn fail(message: String) -> u8 {
    eprintln!("clock: {message}");
    FAILED
}

/// Seconds, in whatever unit reads clearly at that magnitude.
///
/// A time client's numbers span eleven orders of magnitude — a microsecond
/// of jitter and a year of correction can appear in the same listing — and
/// printing all of them in seconds makes both unreadable.
fn duration(seconds: f64) -> String {
    let magnitude = seconds.abs();
    if magnitude < 1e-6 {
        format!("{:+.0}ns", seconds * 1e9)
    } else if magnitude < 1e-3 {
        format!("{:+.1}us", seconds * 1e6)
    } else if magnitude < 1.0 {
        format!("{:+.3}ms", seconds * 1e3)
    } else if magnitude < 300.0 {
        format!("{seconds:+.3}s")
    } else if magnitude < 86_400.0 {
        format!("{:+.1}h", seconds / 3600.0)
    } else {
        format!("{:+.1}d", seconds / 86_400.0)
    }
}

/// The same, for a positive age where a sign would be noise.
fn age(seconds: f64) -> String {
    if seconds < 0.0 {
        return "-".into();
    }
    if seconds < 60.0 {
        format!("{seconds:.0}s")
    } else if seconds < 3600.0 {
        format!("{:.0}m", seconds / 60.0)
    } else if seconds < 86_400.0 {
        format!("{:.1}h", seconds / 3600.0)
    } else {
        format!("{:.1}d", seconds / 86_400.0)
    }
}

fn status() -> u8 {
    let reply = match ask(Request::Status) {
        Ok(r) => r,
        Err(e) => return fail(e),
    };
    let s = match reply {
        Reply::Status(s) => s,
        Reply::Error(e) => return fail(e),
        other => return fail(format!("unexpected reply {other:?}")),
    };

    println!("generation   {}", s.generation);
    println!(
        "time zone    {}",
        s.zone.as_deref().unwrap_or("UTC (none chosen)")
    );
    print!("state        {}", s.sync.as_str());
    match s.sync {
        _ if s.manual => println!(" — Automatic is 0: the clock is set by hand"),
        Sync::Unsynchronised => println!(" — the clock is not being steered"),
        Sync::Spike => println!(" — a large offset is being timed; the clock is untouched"),
        _ => println!(),
    }
    match &s.system_peer {
        Some(peer) => println!("following    {peer} (stratum {})", s.stratum),
        None => println!("following    nothing"),
    }
    println!("offset       {}", duration(s.offset));
    println!("frequency    {:+.3} ppm", s.frequency_ppm);
    println!("jitter       {}", duration(s.jitter));
    // The honest bound: how wrong this machine's time might be. The number
    // a Kerberos deployment actually cares about.
    println!(
        "accuracy     within {}",
        duration(s.root_distance).trim_start_matches('+')
    );
    println!(
        "  root delay      {}",
        duration(s.root_delay).trim_start_matches('+')
    );
    println!(
        "  root dispersion {}",
        duration(s.root_dispersion).trim_start_matches('+')
    );
    if s.leap != 0 {
        println!(
            "leap         a second will be {} at the end of the day",
            if s.leap > 0 { "inserted" } else { "deleted" }
        );
    }
    println!(
        "sources      {} configured, {} contributing",
        s.sources, s.selected
    );
    println!(
        "updates      {} (last {} ago)",
        s.updates,
        age(s.last_update)
    );
    if s.stepped != 0.0 {
        println!("stepped      {} in total since start", duration(s.stepped));
    }
    println!(
        "floor        {} (the build timestamp; the clock is never set below it)",
        s.floor
    );
    OK
}

fn sources() -> u8 {
    let mut stream = match connect() {
        Ok(s) => s,
        Err(e) => return fail(e),
    };
    if let Err(e) = libtimed::send(&mut stream, &Request::Sources.encode()) {
        return fail(e.to_string());
    }
    let mut replies = Vec::new();
    loop {
        let bytes = match libtimed::recv(&mut stream) {
            Ok(b) => b,
            Err(e) => return fail(e.to_string()),
        };
        let reply = match Reply::decode(&bytes) {
            Ok(r) => r,
            Err(e) => return fail(e.to_string()),
        };
        let done = !matches!(&reply, Reply::Sources { more: true, .. });
        replies.push(reply);
        if done {
            break;
        }
    }
    let sources = match libtimed::sources_of(replies) {
        Ok(s) => s,
        Err(e) => return fail(e),
    };
    if sources.is_empty() {
        println!("no sources configured");
        return ABSENT;
    }

    // The leading character is the classic NTP display's, because an
    // operator who has used any other time client already knows it.
    println!(
        "{:<1} {:<24} {:<10} {:<5} {:>4} {:>5} {:>10} {:>9} {:>9} {:>7}",
        "", "source", "state", "auth", "str", "reach", "offset", "delay", "distance", "last"
    );
    for s in &sources {
        let mark = match s.state {
            SourceState::SystemPeer => '*',
            SourceState::Candidate => '+',
            SourceState::Outlier => '-',
            SourceState::Falseticker => 'x',
            SourceState::Unreachable => ' ',
            SourceState::Unusable => '?',
        };
        println!(
            "{mark} {:<24} {:<10} {:<5} {:>4} {:>5o} {:>10} {:>9} {:>9} {:>7}",
            truncate(&s.name, 24),
            s.state.as_str(),
            s.auth.as_str(),
            s.stratum,
            s.reach,
            duration(s.offset),
            duration(s.delay).trim_start_matches('+'),
            // How wrong this source could be, everything added up. The
            // number selection actually ranks by — and the one that
            // answers "why is this source unusable?", which is otherwise
            // invisible and was worth an hour of guessing.
            duration(s.root_distance).trim_start_matches('+'),
            age(s.last),
        );
        if let Some(note) = &s.note {
            println!("    {note}");
        }
    }
    println!();
    println!("* system peer  + candidate  - outlier  x falseticker  ? unusable");
    OK
}

fn truncate(s: &str, width: usize) -> String {
    if s.chars().count() <= width {
        return s.to_string();
    }
    // The tail is the distinguishing part of a hostname far more often
    // than the head, so an elision keeps it.
    let tail: String = s.chars().skip(s.chars().count() - (width - 1)).collect();
    format!("…{tail}")
}

fn set(time: &str) -> u8 {
    let (seconds, nanos) = match parse_time(time) {
        Ok(t) => t,
        Err(e) => {
            eprintln!("clock: {e}");
            return USAGE;
        }
    };
    match ask(Request::Set { seconds, nanos }) {
        Ok(Reply::Ok) => {
            println!("the clock is set");
            OK
        }
        Ok(Reply::Error(e)) => fail(e),
        Ok(other) => fail(format!("unexpected reply {other:?}")),
        Err(e) => fail(e),
    }
}

/// `@SECONDS`, or a local `YYYY-MM-DD HH:MM[:SS]` (a `T` may stand for the
/// space). Local means the machine's time zone, which `mktime` reads from
/// `/etc/localtime` — the zone timed itself keeps there.
fn parse_time(text: &str) -> Result<(i64, u32), String> {
    if let Some(seconds) = text.strip_prefix('@') {
        return seconds
            .parse()
            .map(|s| (s, 0))
            .map_err(|_| format!("{text:?} is not a number of seconds"));
    }
    let bad = || format!("{text:?} is not a time like 2026-10-04 14:05");
    let (date, clock) = text.split_once([' ', 'T']).ok_or_else(bad)?;
    let date: Vec<&str> = date.split('-').collect();
    let clock: Vec<&str> = clock.trim().split(':').collect();
    if date.len() != 3 || !(2..=3).contains(&clock.len()) {
        return Err(bad());
    }
    let number = |s: &str| s.parse::<i32>().map_err(|_| bad());
    let (year, month, day) = (number(date[0])?, number(date[1])?, number(date[2])?);
    let (hour, minute) = (number(clock[0])?, number(clock[1])?);
    let second = clock.get(2).map_or(Ok(0), |s| number(s))?;
    if !(1..=12).contains(&month)
        || !(1..=31).contains(&day)
        || !(0..=23).contains(&hour)
        || !(0..=59).contains(&minute)
        || !(0..=60).contains(&second)
    {
        return Err(bad());
    }
    let mut tm: libc::tm = unsafe { std::mem::zeroed() };
    tm.tm_year = year - 1900;
    tm.tm_mon = month - 1;
    tm.tm_mday = day;
    tm.tm_hour = hour;
    tm.tm_min = minute;
    tm.tm_sec = second;
    // Let the zone say whether summer time applies on that date.
    tm.tm_isdst = -1;
    // Safe: a fully initialised tm, which mktime normalises in place.
    let seconds = unsafe { libc::mktime(&mut tm) };
    // mktime normalises 31 February into March rather than refusing it.
    if seconds == -1 || tm.tm_mday != day || tm.tm_mon != month - 1 {
        return Err(bad());
    }
    Ok((seconds, 0))
}

fn reload() -> u8 {
    match ask(Request::Reload) {
        Ok(Reply::Ok) => {
            println!("timed is re-reading its configuration");
            OK
        }
        Ok(Reply::Error(e)) => fail(e),
        Ok(other) => fail(format!("unexpected reply {other:?}")),
        Err(e) => fail(e),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn seconds_since_1970_are_taken_as_they_are() {
        assert_eq!(parse_time("@1790000000"), Ok((1_790_000_000, 0)));
        assert!(parse_time("@soon").is_err());
    }

    #[test]
    fn a_local_time_is_read_and_one_that_does_not_exist_refused() {
        // The zone is whatever the machine running the test is in, so only
        // the shape is checked: a minute later is sixty seconds later.
        let (a, _) = parse_time("2026-10-04 14:05").unwrap();
        let (b, _) = parse_time("2026-10-04T14:06:00").unwrap();
        assert_eq!(b - a, 60);
        for nonsense in [
            "2026-02-31 12:00",
            "2026-13-01 12:00",
            "2026-10-04 25:00",
            "2026-10-04",
            "tomorrow",
            "2026-10-04 14",
        ] {
            assert!(parse_time(nonsense).is_err(), "{nonsense:?}");
        }
    }
}
