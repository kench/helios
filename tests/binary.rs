//! Runs the built `helios` binary end to end.
//!
//! `cargo llvm-cov` also measures coverage of binaries run from integration
//! tests, so this covers `main.rs`.

use std::process::Command;

#[test]
fn binary_runs_and_exits_successfully() {
    let output = Command::new(env!("CARGO_BIN_EXE_helios"))
        .output()
        .expect("failed to run the helios binary");

    assert!(
        output.status.success(),
        "helios exited with {}",
        output.status
    );
}
