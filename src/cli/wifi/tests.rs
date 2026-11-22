use std::os::unix::fs::PermissionsExt;

use serde_json::{Value, json};

use super::*;
use crate::cli::ScriptedConsole;

struct Fixture {
    dir: tempfile::TempDir,
    store: Store,
    status: PathBuf,
}

impl Fixture {
    fn new() -> Self {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::new(dir.path().join("wifi/networks.json"));
        let status = dir.path().join("status.json");
        Self { dir, store, status }
    }

    fn run(&self, command: Command, secrets: &[&str]) -> (Result<(), Failure>, String) {
        let mut console = ScriptedConsole {
            secrets: secrets.iter().map(|s| (*s).to_owned()).collect(),
            ..ScriptedConsole::default()
        };
        let result = run_on(command, &self.store, &self.status, &mut console);
        (result, String::from_utf8(console.stdout).unwrap())
    }

    fn list(&self) -> Value {
        let (result, out) = self.run(Command::List, &[]);
        result.unwrap();
        serde_json::from_str(&out).unwrap()
    }
}

fn add(ssid: &str) -> Command {
    Command::Add {
        ssid: ssid.into(),
        open: false,
        passphrase_file: None,
        hidden: false,
    }
}

#[test]
fn adds_a_network_asking_for_its_passphrase() {
    let fixture = Fixture::new();
    let (result, out) = fixture.run(add("Home"), &["correct horse battery"]);
    result.unwrap();
    assert_eq!(out, "Saved Home.\n");
    assert_eq!(
        fixture.list(),
        json!({
            "networks": [{"ssid": "Home", "security": "personal", "hidden": false}],
            "applied": null,
        })
    );
    assert!(!fixture.list().to_string().contains("horse"));
}

#[test]
fn adds_open_and_file_passphrase_networks() {
    let fixture = Fixture::new();
    let (result, _) = fixture.run(
        Command::Add {
            ssid: "Cafe".into(),
            open: true,
            passphrase_file: None,
            hidden: true,
        },
        &[],
    );
    result.unwrap();
    let file = fixture.dir.path().join("passphrase");
    std::fs::write(&file, "from a file\nignored\n").unwrap();
    let (result, _) = fixture.run(
        Command::Add {
            ssid: "Office".into(),
            open: false,
            passphrase_file: Some(file),
            hidden: false,
        },
        &[],
    );
    result.unwrap();
    let networks = fixture.store.load().unwrap();
    assert_eq!(networks[0].passphrase, None);
    assert!(networks[0].hidden);
    assert_eq!(
        networks[1].passphrase.as_ref().map(Passphrase::expose),
        Some("from a file")
    );
}

#[test]
fn refuses_bad_input() {
    let fixture = Fixture::new();
    let (result, _) = fixture.run(add("Home"), &["short"]);
    assert!(result.unwrap_err().message.contains("passphrase must be"));
    let (result, _) = fixture.run(add(&"x".repeat(33)), &[]);
    assert!(result.unwrap_err().message.contains("SSID must be"));
    let empty = fixture.dir.path().join("empty");
    std::fs::write(&empty, "").unwrap();
    let (result, _) = fixture.run(
        Command::Add {
            ssid: "Home".into(),
            open: false,
            passphrase_file: Some(empty),
            hidden: false,
        },
        &[],
    );
    assert!(result.unwrap_err().message.contains("passphrase must be"));
    let (result, _) = fixture.run(
        Command::Add {
            ssid: "Home".into(),
            open: false,
            passphrase_file: Some(fixture.dir.path().join("missing")),
            hidden: false,
        },
        &[],
    );
    assert!(result.unwrap_err().message.contains("missing"));
    // No terminal to ask on.
    let (result, _) = fixture.run(add("Home"), &[]);
    assert!(result.is_err());
    for n in 0..16 {
        fixture
            .run(
                Command::Add {
                    ssid: format!("n{n}"),
                    open: true,
                    passphrase_file: None,
                    hidden: false,
                },
                &[],
            )
            .0
            .unwrap();
    }
    let (result, _) = fixture.run(add("one more"), &["correct horse battery"]);
    assert!(result.unwrap_err().message.contains("at most 16"));
}

#[test]
fn removes_networks() {
    let fixture = Fixture::new();
    fixture
        .run(add("Home"), &["correct horse battery"])
        .0
        .unwrap();
    let (result, out) = fixture.run(
        Command::Remove {
            ssid: "Home".into(),
        },
        &[],
    );
    result.unwrap();
    assert_eq!(out, "Removed Home.\n");
    let (result, out) = fixture.run(
        Command::Remove {
            ssid: "Home".into(),
        },
        &[],
    );
    result.unwrap();
    assert_eq!(out, "There was no network Home.\n");
}

#[test]
fn a_store_it_may_not_write_says_who_may() {
    if rustix::process::geteuid().is_root() {
        return; // root may write anyway
    }
    let fixture = Fixture::new();
    fixture
        .run(add("Home"), &["correct horse battery"])
        .0
        .unwrap();
    let dir = fixture.store.path().parent().unwrap();
    std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o500)).unwrap();
    let (result, _) = fixture.run(
        Command::Remove {
            ssid: "Home".into(),
        },
        &[],
    );
    std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700)).unwrap();
    assert!(
        result
            .unwrap_err()
            .message
            .contains("run as root or as the helios user")
    );
    std::fs::write(fixture.store.path(), "{").unwrap();
    let (result, _) = fixture.run(add("Cafe"), &["correct horse battery"]);
    assert!(!result.unwrap_err().message.contains("run as root"));
}

#[test]
fn apply_reports_what_it_did() {
    let fixture = Fixture::new();
    std::fs::create_dir_all(fixture.dir.path().join("etc/netplan")).unwrap();
    fixture
        .run(add("Home"), &["correct horse battery"])
        .0
        .unwrap();
    let mut ran = Vec::new();
    let mut output = Vec::new();
    apply_on(
        &fixture.store,
        fixture.dir.path(),
        &fixture.status,
        &mut |program: &str, _: &[&str]| {
            ran.push(program.to_owned());
            Ok(())
        },
        &mut output,
    )
    .unwrap();
    assert_eq!(ran, ["/usr/sbin/netplan"]);
    assert_eq!(
        String::from_utf8(output).unwrap(),
        "Applied 1 Wi-Fi network(s) with netplan.\n"
    );
    assert_eq!(fixture.list()["applied"]["backend"], "netplan");

    let failure = apply_on(
        &fixture.store,
        fixture.dir.path(),
        &fixture.status,
        &mut |_: &str, _: &[&str]| Err(io::Error::other("no networkd")),
        &mut Vec::new(),
    )
    .unwrap_err();
    assert!(failure.message.contains("no networkd"));
}
