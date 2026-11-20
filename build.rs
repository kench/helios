//! Embeds the build time as `HELIOS_BUILD_TIMESTAMP` (seconds since the Unix epoch).
//!
//! The identity manager treats a system clock earlier than this as not yet set, and then
//! only warns about certificate dates (LLD 1, section 4.6). `SOURCE_DATE_EPOCH` overrides
//! the current time, for reproducible builds.

use std::time::{SystemTime, UNIX_EPOCH};

fn main() {
    println!("cargo::rerun-if-changed=build.rs");
    println!("cargo::rerun-if-env-changed=SOURCE_DATE_EPOCH");
    let seconds = match std::env::var("SOURCE_DATE_EPOCH") {
        Ok(value) => value
            .trim()
            .parse::<u64>()
            .expect("SOURCE_DATE_EPOCH must be whole seconds since the Unix epoch"),
        Err(_) => SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("the build machine's clock is before 1970")
            .as_secs(),
    };
    println!("cargo::rustc-env=HELIOS_BUILD_TIMESTAMP={seconds}");
}
