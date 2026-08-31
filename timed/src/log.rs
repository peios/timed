//! Lines on stderr, mirrored to the kernel log.
//!
//! peinit captures stderr and forwards it to eventd, which is where these
//! lines actually end up and how to read them:
//!
//! ```sh
//! evctl 'LOGS FROM timed SINCE 1h ago TAKE 40'
//! ```
//!
//! Every line is *also* written to `/dev/kmsg`, so that on an image with no
//! collector it still reaches `dmesg` and the serial console. That mirror
//! is best-effort and, for timed, always fails: `/dev/kmsg` is writable by
//! SYSTEM and timed is LocalService (PEI-581). So do not go looking for
//! these on the console — ask eventd.

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
