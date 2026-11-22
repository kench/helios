//! `helios token prepare` against real SoftHSM2 tokens (LLD 1, section 4.12): a good master is
//! copied, and a master whose `token.object` is torn is caught by the login-free check and
//! restored from `tokens.old`.
//!
//! Needs Debian's `softhsm2` (the module and `softhsm2-util`); skipped without it, unless
//! `HELIOS_REQUIRE_SOFTHSM2` is set, as in CI.

use std::path::{Path, PathBuf};
use std::process::Command;

const MODULE: &str = "/usr/lib/softhsm/libsofthsm2.so";

fn softhsm_available() -> bool {
    let present = Path::new(MODULE).exists()
        && Command::new("softhsm2-util")
            .arg("--version")
            .output()
            .is_ok_and(|output| output.status.success());
    assert!(
        present || std::env::var_os("HELIOS_REQUIRE_SOFTHSM2").is_none(),
        "SoftHSM2 isn't installed but HELIOS_REQUIRE_SOFTHSM2 is set"
    );
    present
}

struct Board {
    dir: tempfile::TempDir,
    master: PathBuf,
    source: PathBuf,
    config: PathBuf,
    runtime: PathBuf,
}

/// A board with `token_copy = "tmpfs"` and a real token labelled `helios` in the master.
fn board() -> Board {
    let dir = tempfile::tempdir().unwrap();
    let master = dir.path().join("lib/softhsm/tokens");
    std::fs::create_dir_all(&master).unwrap();
    let source = dir.path().join("softhsm2.conf");
    std::fs::write(
        &source,
        format!(
            "directories.tokendir = {}\nobjectstore.backend = file\nlog.level = ERROR\n",
            master.display()
        ),
    )
    .unwrap();
    let init = Command::new("softhsm2-util")
        .args(["--init-token", "--free", "--label", "helios"])
        .args(["--pin", "123456", "--so-pin", "12345678"])
        .env("SOFTHSM2_CONF", &source)
        .output()
        .unwrap();
    assert!(
        init.status.success(),
        "{}",
        String::from_utf8_lossy(&init.stderr)
    );
    let config = dir.path().join("helios.toml");
    std::fs::write(
        &config,
        format!("[identity]\npkcs11_module = \"{MODULE}\"\ntoken_copy = \"tmpfs\"\npin = \"bootstrap\"\n"),
    )
    .unwrap();
    Board {
        runtime: dir.path().join("run/token"),
        master,
        source,
        config,
        dir,
    }
}

fn prepare(board: &Board) -> (bool, String) {
    let output = Command::new(env!("CARGO_BIN_EXE_helios"))
        .arg("--config")
        .arg(&board.config)
        .args(["token", "prepare", "--source"])
        .arg(&board.source)
        .arg("--runtime")
        .arg(&board.runtime)
        .output()
        .unwrap();
    (
        output.status.success(),
        format!(
            "{}{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        ),
    )
}

fn state(board: &Board) -> serde_json::Value {
    serde_json::from_str(&std::fs::read_to_string(board.runtime.join("state.json")).unwrap())
        .unwrap()
}

/// The `token.object` of the one token in `dir`.
fn token_object(dir: &Path) -> PathBuf {
    let token = std::fs::read_dir(dir)
        .unwrap()
        .next()
        .unwrap()
        .unwrap()
        .path();
    token.join("token.object")
}

fn copy_tree(from: &Path, to: &Path) {
    std::fs::create_dir_all(to).unwrap();
    for entry in std::fs::read_dir(from).unwrap() {
        let entry = entry.unwrap();
        let target = to.join(entry.file_name());
        if entry.file_type().unwrap().is_dir() {
            copy_tree(&entry.path(), &target);
        } else {
            std::fs::copy(entry.path(), target).unwrap();
        }
    }
}

#[test]
fn a_good_master_runs_from_a_tmpfs_copy() {
    if !softhsm_available() {
        return;
    }
    let board = board();
    let (ok, output) = prepare(&board);
    assert!(ok, "{output}");
    assert!(output.contains("working copy"), "{output}");
    let state = state(&board);
    assert_eq!(state["copy"], "tmpfs");
    assert!(state.get("restored_from").is_none(), "{state}");
    let conf = std::fs::read_to_string(board.runtime.join("softhsm2.conf")).unwrap();
    assert!(
        conf.contains(&board.runtime.join("tokens").display().to_string()),
        "{conf}"
    );
    assert!(!board.master.with_file_name("tokens.old").exists());
}

#[test]
fn a_torn_master_is_restored_from_old() {
    if !softhsm_available() {
        return;
    }
    let board = board();
    // A good previous copy, then a master torn as a power cut during a login leaves it.
    copy_tree(&board.master, &board.master.with_file_name("tokens.old"));
    let object = token_object(&board.master);
    let bytes = std::fs::read(&object).unwrap();
    std::fs::write(&object, &bytes[..bytes.len() / 2]).unwrap();

    let (ok, output) = prepare(&board);
    assert!(ok, "{output}");
    assert!(output.contains("restored from tokens.old"), "{output}");
    assert_eq!(state(&board)["restored_from"], "tokens.old");
    assert_eq!(
        std::fs::read(token_object(&board.master)).unwrap(),
        bytes,
        "the master is repaired"
    );

    // Without a good copy anywhere, Helios still starts, and the copies are left alone.
    let torn = &bytes[..bytes.len() / 2];
    std::fs::write(token_object(&board.master), torn).unwrap();
    std::fs::write(
        token_object(&board.master.with_file_name("tokens.old")),
        torn,
    )
    .unwrap();
    let (ok, output) = prepare(&board);
    assert!(ok, "{output}");
    assert!(output.contains("no copy passes"), "{output}");
    assert_eq!(state(&board)["lost"], true);
    drop(board.dir);
}
