//! Lines on stderr, mirrored to the kernel log.
//!
//! peinit captures stderr and forwards it to the log collector; on an image
//! without one those lines vanish. "Why is the clock not synchronised" is
//! exactly the kind of thing an operator needs from a serial console, so
//! every line also goes to `/dev/kmsg`, where `dmesg` and the console find
//! it. Best-effort: a machine where kmsg cannot be opened still runs.

use std::fmt::Arguments;
use std::io::Write;
use std::sync::OnceLock;

fn kmsg() -> Option<&'static std::fs::File> {
    static KMSG: OnceLock<Option<std::fs::File>> = OnceLock::new();
    KMSG.get_or_init(|| std::fs::OpenOptions::new().write(true).open("/dev/kmsg").ok()).as_ref()
}

fn emit(level: &str, args: Arguments<'_>) {
    let line = format!("timed: {level}: {args}\n");
    let _ = std::io::stderr().write_all(line.as_bytes());
    if let Some(mut k) = kmsg() {
        // One write per record: kmsg turns every write(2) into a line, so the
        // text is assembled first rather than streamed piecewise.
        // <6> is KERN_INFO; warnings and errors use <4> and <3>.
        let priority = match level {
            "error" => 3,
            "warn" => 4,
            _ => 6,
        };
        let _ = k.write_all(format!("<{priority}>{line}").as_bytes());
    }
}

pub fn info(args: Arguments<'_>) {
    emit("info", args);
}

pub fn warn(args: Arguments<'_>) {
    emit("warn", args);
}

pub fn error(args: Arguments<'_>) {
    emit("error", args);
}
