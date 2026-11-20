//! Helios on-device agent.
//!
//! Connects to AWS IoT Core over MQTT with a key held in a PKCS#11 token, reports
//! state through Device Shadow and runs the device modules. See the Helios
//! High-Level Design for the overall design.

use std::process::ExitCode;

fn main() -> ExitCode {
    let mut terminal = helios::cli::Terminal::default();
    ExitCode::from(helios::cli::run(std::env::args_os(), &mut terminal))
}
