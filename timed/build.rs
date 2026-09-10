//! Stamp the build time into the binary.
//!
//! timed refuses to set the clock below this, which is what makes a machine
//! with a dead or absent RTC able to bootstrap at all: TLS certificates are
//! not valid before they were issued, so a clock reading 1970 cannot
//! complete the NTS-KE handshake that would tell it the real time. A floor
//! at the build date breaks that circle — every certificate in the shipped
//! trust store was valid then, by construction.
//!
//! It is timed's build date rather than the image's, because there is no
//! compose-time stamp a package can read: `peios-experimental` deliberately
//! omits `BUILD_ID` on exactly those grounds. That makes the floor
//! conservative — older than the image — which is the safe direction to be
//! wrong in. `SOURCE_DATE_EPOCH` is honoured so a reproducible build stays
//! reproducible.

use std::time::{SystemTime, UNIX_EPOCH};

fn main() {
    println!("cargo:rerun-if-env-changed=SOURCE_DATE_EPOCH");
    let epoch = std::env::var("SOURCE_DATE_EPOCH")
        .ok()
        .and_then(|s| s.trim().parse::<i64>().ok())
        .unwrap_or_else(|| {
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map(|d| d.as_secs() as i64)
                .unwrap_or(0)
        });
    println!("cargo:rustc-env=TIMED_BUILD_EPOCH={epoch}");
}
