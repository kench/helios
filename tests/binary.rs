//! Runs the built `helios` binary end to end.
//!
//! `cargo llvm-cov` also measures coverage of binaries run from integration
//! tests, so this covers `main.rs` and the service's `main`.

use std::io::{BufRead, BufReader};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::mpsc;
use std::time::Duration;

/// The SoftHSM2 module, as in `tests/softhsm.rs`.
const SOFTHSM2_MODULE: &str = "/usr/lib/softhsm/libsofthsm2.so";

#[test]
fn binary_prints_its_version() {
    let output = Command::new(env!("CARGO_BIN_EXE_helios"))
        .arg("--version")
        .output()
        .expect("failed to run the helios binary");

    assert!(
        output.status.success(),
        "helios exited with {}",
        output.status
    );
    assert!(String::from_utf8_lossy(&output.stdout).starts_with("helios "));
}

#[test]
fn service_exits_78_without_a_config() {
    let output = Command::new(env!("CARGO_BIN_EXE_helios"))
        .args(["--config", "/nonexistent/helios.toml"])
        .env_remove("HELIOS_LOG")
        .output()
        .expect("failed to run the helios binary");

    assert_eq!(
        output.status.code(),
        Some(78),
        "helios exited with {}",
        output.status
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("configuration error"), "stderr: {stderr}");
    assert!(
        stderr.contains("/nonexistent/helios.toml"),
        "stderr: {stderr}"
    );
}

/// A directory with a CA bundle, a PIN file and a local-PIN `helios.toml` for `module`.
fn service_files(module: &Path) -> (tempfile::TempDir, PathBuf) {
    use std::os::unix::fs::PermissionsExt;

    let dir = tempfile::tempdir().expect("failed to create a temporary directory");
    let key = rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).unwrap();
    let mut params = rcgen::CertificateParams::default();
    params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
    let roots = dir.path().join("roots.pem");
    std::fs::write(&roots, params.self_signed(&key).unwrap().pem()).unwrap();
    let pin = dir.path().join("pin");
    std::fs::write(&pin, "1234\n").unwrap();
    std::fs::set_permissions(&pin, std::fs::Permissions::from_mode(0o600)).unwrap();
    let config = dir.path().join("helios.toml");
    std::fs::write(
        &config,
        format!(
            r#"
[device]
thing_name = "t-01JD5VY2K7M9Q4R6T8V0X2Z4B6"

[identity]
pkcs11_module = "{module}"
token_label   = "helios"
key_label     = "device-key"
pin           = "file:{pin}"

[aws]
region               = "us-west-2"
iot_endpoint         = "example-ats.iot.us-west-2.amazonaws.com"
credentials_endpoint = "example.credentials.iot.us-west-2.amazonaws.com"
role_alias           = "helios-device-role-alias"
root_ca              = "{roots}"
"#,
            module = module.display(),
            pin = pin.display(),
            roots = roots.display(),
        ),
    )
    .unwrap();
    (dir, config)
}

#[test]
fn service_exits_78_when_the_module_cannot_load() {
    let module_dir = tempfile::tempdir().unwrap();
    let module = module_dir.path().join("libbroken-pkcs11.so");
    std::fs::write(&module, "not a shared library").unwrap();
    let (_dir, config) = service_files(&module);

    let output = Command::new(env!("CARGO_BIN_EXE_helios"))
        .arg("--config")
        .arg(&config)
        .env_remove("HELIOS_LOG")
        .output()
        .expect("failed to run the helios binary");

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert_eq!(output.status.code(), Some(78), "stderr: {stderr}");
    assert!(
        stderr.contains("starting the identity manager"),
        "stderr: {stderr}"
    );
    assert!(
        stderr.contains("PKCS#11 module could not be loaded"),
        "stderr: {stderr}"
    );
}

/// With SoftHSM2 but no token, the identity stays unavailable and retries; SIGTERM stops it
/// with exit 0.
#[test]
fn service_stops_cleanly_on_sigterm() {
    let module = Path::new(SOFTHSM2_MODULE);
    if !module.exists() {
        assert!(
            std::env::var_os("HELIOS_REQUIRE_SOFTHSM2").is_none(),
            "SoftHSM2 module not found at {SOFTHSM2_MODULE} but HELIOS_REQUIRE_SOFTHSM2 is set"
        );
        eprintln!("skipping: no SoftHSM2 module at {SOFTHSM2_MODULE}");
        return;
    }
    let (dir, config) = service_files(module);
    let tokens = dir.path().join("tokens");
    std::fs::create_dir(&tokens).unwrap();
    let softhsm_conf = dir.path().join("softhsm2.conf");
    std::fs::write(
        &softhsm_conf,
        format!(
            "directories.tokendir = {}\nobjectstore.backend = file\nlog.level = ERROR\n",
            tokens.display()
        ),
    )
    .unwrap();

    let mut child = Command::new(env!("CARGO_BIN_EXE_helios"))
        .arg("--config")
        .arg(&config)
        .env("SOFTHSM2_CONF", &softhsm_conf)
        .env_remove("HELIOS_LOG")
        .stderr(Stdio::piped())
        .spawn()
        .expect("failed to run the helios binary");
    let stderr = child.stderr.take().unwrap();
    let (lines_tx, lines) = mpsc::channel();
    let reader = std::thread::spawn(move || {
        for line in BufReader::new(stderr).lines() {
            let Ok(line) = line else { break };
            let _ = lines_tx.send(line);
        }
    });
    let mut seen = Vec::new();
    while !seen
        .iter()
        .any(|line: &String| line.contains("identity unavailable"))
    {
        match lines.recv_timeout(Duration::from_secs(10)) {
            Ok(line) => seen.push(line),
            Err(_) => {
                let _ = child.kill();
                panic!("no \"identity unavailable\" within 10 s: {seen:#?}");
            }
        }
    }

    rustix::process::kill_process(
        rustix::process::Pid::from_child(&child),
        rustix::process::Signal::TERM,
    )
    .unwrap();
    let status = child.wait().unwrap();
    reader.join().unwrap();
    seen.extend(lines.try_iter());

    assert_eq!(status.code(), Some(0), "stderr: {seen:#?}");
    assert!(
        seen.iter().any(|line| line.contains("stopped")),
        "stderr: {seen:#?}"
    );
}
