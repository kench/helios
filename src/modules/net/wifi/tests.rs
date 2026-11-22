use std::cell::RefCell;
use std::os::unix::fs::PermissionsExt;

use super::*;

const SECRET: &str = "correct horse battery";

fn personal(ssid: &str) -> Network {
    Network {
        ssid: ssid.into(),
        passphrase: Some(Passphrase::new(SECRET.into()).unwrap()),
        hidden: false,
    }
}

fn open_network(ssid: &str) -> Network {
    Network {
        ssid: ssid.into(),
        passphrase: None,
        hidden: true,
    }
}

fn mode(path: &Path) -> u32 {
    std::fs::metadata(path).unwrap().permissions().mode() & 0o777
}

#[test]
fn checks_passphrases() {
    for good in [
        "12345678",
        &"x".repeat(63),
        &"aB3".repeat(21).chars().take(63).collect::<String>(),
        &"0f".repeat(32),
        " spaces and ~ symbols ",
    ] {
        assert!(Passphrase::new(good.into()).is_ok(), "{good:?}");
    }
    for bad in [
        "1234567",
        &"x".repeat(64),
        &"g".repeat(64),
        "caf\u{e9} au lait",
        "tab\there!",
        "",
    ] {
        assert_eq!(
            Passphrase::new(bad.into()).unwrap_err(),
            Refused::InvalidPassphrase,
            "{bad:?}"
        );
    }
    let passphrase = Passphrase::new(SECRET.into()).unwrap();
    assert_eq!(format!("{passphrase:?}"), "Passphrase(..)");
    assert_eq!(passphrase.expose(), SECRET);
    assert!(!format!("{:?}", personal("Home")).contains("horse"));
}

#[test]
fn checks_ssids() {
    assert!(check_ssid("Home").is_ok());
    assert!(check_ssid("Venue / Media").is_ok());
    assert!(check_ssid(&"\u{e9}".repeat(16)).is_ok(), "32 bytes");
    for bad in [
        String::new(),
        "x".repeat(33),
        "\u{e9}".repeat(17),
        "line\nbreak".into(),
        "nul\0".into(),
    ] {
        assert_eq!(check_ssid(&bad), Err(Refused::InvalidSsid), "{bad:?}");
    }
    let codes: Vec<&str> = [
        Refused::InvalidSsid,
        Refused::InvalidPassphrase,
        Refused::TooMany,
        Refused::NoAdapter,
    ]
    .iter()
    .map(Refused::code)
    .collect();
    assert_eq!(
        codes,
        [
            "INVALID_SSID",
            "INVALID_PASSPHRASE",
            "TOO_MANY",
            "NO_ADAPTER"
        ]
    );
}

#[test]
fn summaries_never_hold_the_passphrase() {
    assert_eq!(
        personal("Home").summary(),
        json!({"ssid": "Home", "security": "personal", "hidden": false})
    );
    assert_eq!(
        open_network("Cafe").summary(),
        json!({"ssid": "Cafe", "security": "open", "hidden": true})
    );
}

#[test]
fn the_store_adds_replaces_and_removes() {
    let dir = tempfile::tempdir().unwrap();
    let store = Store::new(dir.path().join("wifi/networks.json"));
    assert!(store.load().unwrap().is_empty(), "no store yet");
    assert!(!store.remove("Home").unwrap());

    store.set(personal("Home")).unwrap();
    store.set(open_network("Cafe")).unwrap();
    assert_eq!(mode(store.path()), 0o600);
    assert_eq!(mode(store.path().parent().unwrap()), 0o700);
    let mut replaced = open_network("Home");
    replaced.hidden = false;
    store.set(replaced.clone()).unwrap();
    assert_eq!(store.load().unwrap(), [replaced, open_network("Cafe")]);

    assert!(store.remove("Home").unwrap());
    assert_eq!(store.load().unwrap(), [open_network("Cafe")]);
    let text = std::fs::read_to_string(store.path()).unwrap();
    assert!(text.contains("\"version\": 1"), "{text}");
}

#[test]
fn the_store_holds_at_most_sixteen() {
    let dir = tempfile::tempdir().unwrap();
    let store = Store::new(dir.path().join("networks.json"));
    for n in 0..MAX_NETWORKS {
        store.set(open_network(&format!("net{n}"))).unwrap();
    }
    assert!(matches!(
        store.set(open_network("one more")),
        Err(StoreError::Refused(Refused::TooMany))
    ));
    // Replacing one is still fine.
    store.set(personal("net3")).unwrap();
    assert!(matches!(
        store.set(Network {
            ssid: String::new(),
            passphrase: None,
            hidden: false
        }),
        Err(StoreError::Refused(Refused::InvalidSsid))
    ));
}

#[test]
fn a_broken_store_is_an_error_that_quotes_nothing() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("networks.json");
    let store = Store::new(&path);
    std::fs::write(
        &path,
        r#"{"version": 1, "networks": [{"ssid": "Home", "passphrase": 12345678901}]}"#,
    )
    .unwrap();
    let error = store.load().unwrap_err().to_string();
    assert!(error.contains("doesn't parse at line 1"), "{error}");
    assert!(!error.contains("12345678901"), "{error}");

    std::fs::write(
        &path,
        r#"{"version": 1, "networks": [{"ssid": "Home", "passphrase": "short"}]}"#,
    )
    .unwrap();
    let error = store.load().unwrap_err().to_string();
    assert!(error.contains("passphrase must be"), "{error}");
    assert!(!error.contains("short\""), "{error}");

    let many: Vec<Value> = (0..17).map(|n| json!({"ssid": format!("n{n}")})).collect();
    std::fs::write(&path, json!({"version": 1, "networks": many}).to_string()).unwrap();
    assert!(store.load().unwrap_err().to_string().contains("at most 16"));

    // Unreadable as a file at all (a directory in its place).
    let store = Store::new(dir.path());
    assert!(store.load().is_err());
    assert!(
        Store::new("/").set(open_network("x")).is_err(),
        "no directory"
    );
}

#[test]
fn renders_netplan() {
    let wlan = ["wlP2p33s0".to_owned()];
    assert_eq!(netplan(&[], &wlan), None);
    let mut quoted = personal("Venue \"Main\" \\ Hall");
    quoted.hidden = true;
    let yaml = netplan(&[quoted, open_network("Cafe")], &wlan).unwrap();
    let expected = "# Written by helios wifi-apply from Helios's Wi-Fi networks (LLD 3, section 10).\n\
         # Change them with `helios wifi` or the Control API, not here.\n\
         network:\n  version: 2\n  renderer: networkd\n  wifis:\n    \"wlP2p33s0\":\n      \
         optional: true\n      dhcp4: true\n      dhcp6: true\n      ipv6-privacy: true\n      access-points:\n        \
         \"Venue \\\"Main\\\" \\\\ Hall\":\n          password: \"correct horse battery\"\n          \
         hidden: true\n        \"Cafe\":\n          auth:\n            key-management: none\n          \
         hidden: true\n";
    assert_eq!(yaml, expected);
    let two = netplan(&[open_network("Cafe")], &["wlan0".into(), "wlan1".into()]).unwrap();
    assert_eq!(
        two.matches("\"Cafe\":").count(),
        2,
        "every network on every adapter"
    );
}

#[test]
fn finds_wifi_interfaces_in_sysfs() {
    let root = tempfile::tempdir().unwrap();
    assert!(wifi_interfaces(root.path()).is_empty());
    for (name, marker) in [
        ("wlP2p33s0", Some("wireless")),
        ("wlan1", Some("phy80211")),
        ("eth0", None),
        ("bad name", Some("wireless")),
    ] {
        let dir = root.path().join("sys/class/net").join(name);
        std::fs::create_dir_all(&dir).unwrap();
        if let Some(marker) = marker {
            std::fs::create_dir_all(dir.join(marker)).unwrap();
        }
    }
    assert_eq!(wifi_interfaces(root.path()), ["wlP2p33s0", "wlan1"]);
}

#[test]
fn renders_networkmanager_keyfiles() {
    let mut tricky = personal("AB");
    tricky.passphrase = Some(Passphrase::new(" back\\slash pass".into()).unwrap());
    let files = keyfiles(&[tricky, open_network("C")]);
    assert_eq!(files.len(), 2);
    assert_eq!(files[0].0, "helios-wifi-01.nmconnection");
    assert!(files[0].1.contains("ssid=65;66;\n"), "{}", files[0].1);
    assert!(
        files[0].1.contains("psk=\\sback\\\\slash pass\n"),
        "{}",
        files[0].1
    );
    assert!(files[0].1.contains("hidden=false\n"));
    assert_eq!(files[1].0, "helios-wifi-02.nmconnection");
    assert!(files[1].1.contains("ssid=67;\nhidden=true\n"));
    assert!(
        !files[1].1.contains("[wifi-security]"),
        "open: no security section"
    );
    assert!(files[1].1.ends_with("[ipv6]\nmethod=auto\nip6-privacy=2\n"));
}

#[test]
fn detects_the_backend() {
    let root = tempfile::tempdir().unwrap();
    assert_eq!(Backend::detect(root.path()), None);
    std::fs::create_dir_all(root.path().join("etc/netplan")).unwrap();
    assert_eq!(Backend::detect(root.path()), Some(Backend::Netplan));
    std::fs::create_dir_all(root.path().join("run/NetworkManager")).unwrap();
    assert_eq!(Backend::detect(root.path()), Some(Backend::NetworkManager));
}

/// A board root, a store with one network, and a recorder for the commands run.
struct Board {
    root: tempfile::TempDir,
    store: Store,
    status: PathBuf,
    ran: RefCell<Vec<String>>,
}

impl Board {
    fn new(backend: &str) -> Self {
        let root = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(root.path().join(backend)).unwrap();
        std::fs::create_dir_all(root.path().join("sys/class/net/wlan0/wireless")).unwrap();
        let store = Store::new(root.path().join("var/lib/helios/wifi/networks.json"));
        store.set(personal("Home")).unwrap();
        let status = root.path().join("var/lib/helios-wifi/status.json");
        Self {
            root,
            store,
            status,
            ran: RefCell::new(Vec::new()),
        }
    }

    fn apply(&self, fail: bool) -> Status {
        let mut run = |program: &str, args: &[&str]| {
            self.ran
                .borrow_mut()
                .push(format!("{program} {}", args.join(" ")));
            if fail {
                Err(io::Error::other("netplan: boom"))
            } else {
                Ok(())
            }
        };
        apply(&self.store, self.root.path(), &self.status, &mut run).unwrap()
    }
}

#[test]
fn applies_with_netplan() {
    let board = Board::new("etc/netplan");
    let status = board.apply(false);
    assert_eq!(status.backend.as_deref(), Some("netplan"));
    assert_eq!(status.networks, 1);
    assert_eq!(status.error, None);
    let file = board.root.path().join(NETPLAN_FILE);
    assert_eq!(mode(&file), 0o600);
    assert!(
        std::fs::read_to_string(&file)
            .unwrap()
            .contains("\"Home\":")
    );
    assert_eq!(*board.ran.borrow(), ["/usr/sbin/netplan apply"]);
    let saved: Status = serde_json::from_slice(&std::fs::read(&board.status).unwrap()).unwrap();
    assert_eq!(saved, status);

    // Without networks the file goes, and netplan applies that.
    board.store.remove("Home").unwrap();
    let status = board.apply(false);
    assert_eq!(status.networks, 0);
    assert!(!file.exists());
    board.apply(false);

    // A failure is in the status, not lost.
    board.store.set(personal("Home")).unwrap();
    let status = board.apply(true);
    assert_eq!(status.backend, None);
    assert_eq!(status.error.as_deref(), Some("netplan: boom"));
}

#[test]
fn applies_with_networkmanager() {
    let board = Board::new("run/NetworkManager");
    let connections = board.root.path().join(NM_CONNECTIONS);
    std::fs::create_dir_all(&connections).unwrap();
    std::fs::write(connections.join("helios-wifi-07.nmconnection"), "stale").unwrap();
    std::fs::write(
        connections.join("Wired connection 1.nmconnection"),
        "theirs",
    )
    .unwrap();
    let status = board.apply(false);
    assert_eq!(status.backend.as_deref(), Some("networkmanager"));
    let mut names: Vec<String> = std::fs::read_dir(&connections)
        .unwrap()
        .map(|entry| entry.unwrap().file_name().into_string().unwrap())
        .collect();
    names.sort();
    assert_eq!(
        names,
        [
            "Wired connection 1.nmconnection",
            "helios-wifi-01.nmconnection"
        ]
    );
    assert_eq!(
        mode(&connections.join("helios-wifi-01.nmconnection")),
        0o600
    );
    assert_eq!(*board.ran.borrow(), ["/usr/bin/nmcli connection reload"]);
}

#[test]
fn a_netplan_board_without_wifi_is_reported() {
    let board = Board::new("etc/netplan");
    std::fs::remove_dir_all(board.root.path().join("sys")).unwrap();
    let status = board.apply(false);
    assert_eq!(
        status.error.as_deref(),
        Some("the board has no Wi-Fi interface")
    );
    assert!(board.ran.borrow().is_empty());
}

#[test]
fn a_board_without_a_backend_or_store_is_reported() {
    let board = Board::new("nothing");
    let status = board.apply(false);
    assert!(
        status
            .error
            .unwrap()
            .contains("neither NetworkManager nor netplan")
    );
    assert!(board.ran.borrow().is_empty());

    let board = Board::new("etc/netplan");
    std::fs::write(board.store.path(), "not json").unwrap();
    let status = board.apply(false);
    assert!(status.error.unwrap().contains("doesn't parse"));
}

#[test]
fn reports_networks_and_the_last_apply() {
    let board = Board::new("etc/netplan");
    assert_eq!(
        report(&board.store, &board.status),
        json!({
            "networks": [{"ssid": "Home", "security": "personal", "hidden": false}],
            "applied": null,
        })
    );
    board.apply(false);
    let reported = report(&board.store, &board.status);
    assert_eq!(reported["applied"]["backend"], "netplan");
    assert_eq!(reported["applied"]["networks"], 1);
    std::fs::write(board.store.path(), "{").unwrap();
    let reported = report(&board.store, &board.status);
    assert!(
        reported["networks"]["error"]
            .as_str()
            .unwrap()
            .contains("doesn't parse")
    );
}

#[test]
fn runs_commands_and_reports_failures() {
    run_command("true", &[]).unwrap();
    let error = run_command("sh", &["-c", "echo nope >&2; exit 3"]).unwrap_err();
    assert!(error.to_string().contains("nope"), "{error}");
    assert!(run_command("/nonexistent/program", &[]).is_err());
}
