//! `clock` — the time client's operator command.
//!
//! Reads over timed's socket and prints. It writes nothing: the machine's
//! time policy lives in `Machine\System\Time`, and `reg` is how a registry
//! value is set, so a second way of writing the same values would be a
//! second permission model to keep in step with the first. The one verb
//! that acts is `reload`, which asks timed to re-read what `reg` wrote.
//!
//! It is called `clock` rather than `time` because `time` is a shell
//! keyword: `time status` would run `status` and report how long it took.

use std::os::unix::net::UnixStream;
use std::process::ExitCode;

use libtimed::{Reply, Request, SourceState, Sync, SOCKET_PATH};

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
    print!("state        {}", s.sync.as_str());
    match s.sync {
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
    println!("accuracy     within {}", duration(s.root_distance).trim_start_matches('+'));
    println!("  root delay      {}", duration(s.root_delay).trim_start_matches('+'));
    println!("  root dispersion {}", duration(s.root_dispersion).trim_start_matches('+'));
    if s.leap != 0 {
        println!(
            "leap         a second will be {} at the end of the day",
            if s.leap > 0 { "inserted" } else { "deleted" }
        );
    }
    println!("sources      {} configured, {} contributing", s.sources, s.selected);
    println!("updates      {} (last {} ago)", s.updates, age(s.last_update));
    if s.stepped != 0.0 {
        println!("stepped      {} in total since start", duration(s.stepped));
    }
    println!("floor        {} (the build timestamp; the clock is never set below it)", s.floor);
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
        "{:<1} {:<24} {:<10} {:<5} {:>4} {:>5} {:>10} {:>9} {:>8}",
        "", "source", "state", "auth", "str", "reach", "offset", "delay", "last"
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
            "{mark} {:<24} {:<10} {:<5} {:>4} {:>5o} {:>10} {:>9} {:>8}",
            truncate(&s.name, 24),
            s.state.as_str(),
            s.auth.as_str(),
            s.stratum,
            s.reach,
            duration(s.offset),
            duration(s.delay).trim_start_matches('+'),
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
