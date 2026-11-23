//! `helios net list` against a real kernel: interfaces, addresses and default routes set up in
//! a new user and network namespace (`unshare -rn`), so the test needs no privileges. Skipped
//! where unprivileged user namespaces aren't allowed.
#![cfg(feature = "module-net")]

use std::process::Command;

use serde_json::{Value, json};

/// Sets up the namespace, then runs `helios net list` in it.
const SETUP: &str = r#"
set -e
ip link add d0 type dummy
ip link set d0 address 02:00:00:00:00:01
ip link set d0 up
ip addr add 192.0.2.2/24 dev d0
ip -6 addr add 2001:db8::2/64 dev d0 nodad
ip route add default via 192.0.2.1 dev d0 metric 50
ip -6 nexthop add id 7 via 2001:db8::1 dev d0
ip -6 route add default nhid 7 metric 60
ip link add veth0 type veth peer name veth1
exec "$0" net list
"#;

fn namespaces_allowed() -> bool {
    Command::new("unshare")
        .args(["-rn", "true"])
        .status()
        .is_ok_and(|status| status.success())
        && Command::new("ip").arg("-V").output().is_ok()
}

#[test]
fn lists_interfaces_addresses_and_routes_in_a_network_namespace() {
    if !namespaces_allowed() {
        eprintln!("skipped: unprivileged user namespaces (unshare -rn) or ip aren't available");
        return;
    }
    let output = Command::new("unshare")
        .args(["-rn", "sh", "-c", SETUP, env!("CARGO_BIN_EXE_helios")])
        .output()
        .expect("unshare runs");
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let document: Value = serde_json::from_slice(&output.stdout).expect("JSON");
    let interfaces = document["interfaces"].as_object().expect("interfaces");
    // A new namespace may also hold the kernel's fallback tunnels (gre0 and so on).
    for left_out in ["lo", "veth0", "veth1"] {
        assert!(!interfaces.contains_key(left_out), "{left_out} is left out");
    }
    let d0 = &interfaces["d0"];
    assert_eq!(d0["kind"], "virtual");
    assert_eq!(d0["mac"], "02:00:00:00:00:01");
    assert_eq!(d0["admin_up"], true);
    assert_eq!(d0["ipv4"], json!(["192.0.2.2/24"]));
    let ipv6 = d0["ipv6"].as_array().expect("ipv6");
    assert_eq!(ipv6[0]["address"], "2001:db8::2");
    assert_eq!(ipv6[0]["scope"], "global");
    assert_eq!(ipv6[0]["tentative"], false);
    assert_eq!(
        d0["default_routes"],
        json!([
            {"family": "ipv4", "gateway": "192.0.2.1", "metric": 50},
            {"family": "ipv6", "gateway": "2001:db8::1", "metric": 60},
        ])
    );
    assert_eq!(document["truncated"], false);
}

/// Two uplinks like the Orange Pi's (2026-11-22): the first with the lower metric. Before
/// `helios net routes`, traffic from the second's address leaves through the first; after, through
/// its own; stopping removes everything. Also the rp_filter check (LLD 3, section 5.7): with the
/// rules, a reply arriving on the second uplink passes even in strict mode.
const ROUTES: &str = r#"
set -e
for i in 0 1; do ip link add d$i type dummy; ip link set d$i up; mkdir -p "$1/class/net/d$i/device"; done
ip addr add 192.0.2.2/24 dev d0; ip addr add 198.51.100.2/24 dev d1
ip route add default via 192.0.2.1 dev d0 metric 100
ip route add default via 198.51.100.1 dev d1 metric 600
for k in all d0 d1; do echo 1 > /proc/sys/net/ipv4/conf/$k/rp_filter; done
out() { ip route get 203.0.113.9 from 198.51.100.2 | grep -o "dev d[01]"; }
reply() { ip route get 198.51.100.2 from 203.0.113.9 iif d1 >/dev/null 2>&1 && echo pass || echo drop; }
echo "before: $(out) $(reply)"
"$0" --config "$2" net routes --once --sysfs "$1"
echo "after: $(out) $(reply)"
echo "rules: $(ip rule | grep -cE 'lookup 10[0-9]{3}')"
"$0" --config "$2" net routes --once --sysfs "$1"
"$0" --config "$2" net routes --remove
echo "removed: $(ip rule | grep -cE 'lookup 10[0-9]{3}') $(ip route show table all proto 222 | grep -c .)"
"#;

#[test]
fn source_routes_each_uplink_in_a_network_namespace() {
    if !namespaces_allowed() {
        eprintln!("skipped: unprivileged user namespaces (unshare -rn) or ip aren't available");
        return;
    }
    let dir = tempfile::tempdir().unwrap();
    let config = dir.path().join("helios.toml");
    std::fs::write(&config, "[modules.net]\nexclude = []\n").unwrap();
    let sysfs = dir.path().join("sys");
    let output = Command::new("unshare")
        .args(["-rn", "sh", "-c", ROUTES, env!("CARGO_BIN_EXE_helios")])
        .arg(&sysfs)
        .arg(&config)
        .output()
        .unwrap();
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        output.status.success(),
        "{stdout}\n{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let lines: Vec<&str> = stdout.lines().collect();
    assert!(
        lines.contains(&"before: dev d0 drop"),
        "the problem: {stdout}"
    );
    // Tables are 10000 + the interface's index, which depends on the namespace.
    for name in ["d0", "d1"] {
        let table = lines
            .iter()
            .find_map(|line| line.strip_prefix(&format!("{name} table ")));
        assert!(
            table.is_some_and(|table| table
                .parse::<u32>()
                .is_ok_and(|t| (10_000..11_000).contains(&t))),
            "{name}: {stdout}"
        );
    }
    assert!(lines.contains(&"6 changes"), "{stdout}");
    assert!(lines.contains(&"after: dev d1 pass"), "fixed: {stdout}");
    assert!(lines.contains(&"rules: 2"), "{stdout}");
    assert!(
        lines.contains(&"0 changes"),
        "the second run changes nothing: {stdout}"
    );
    assert!(lines.contains(&"removed 6 rules and routes"), "{stdout}");
    assert!(lines.contains(&"removed: 0 0"), "{stdout}");
}

/// The service: it routes the uplinks at start, follows a new address within its quiet period,
/// and removes everything when stopped with SIGTERM.
const ROUTES_DAEMON: &str = r#"
set -e
for i in 0 1; do ip link add d$i type dummy; ip link set d$i up; mkdir -p "$1/class/net/d$i/device"; done
ip addr add 192.0.2.2/24 dev d0; ip addr add 198.51.100.2/24 dev d1
ip route add default via 192.0.2.1 dev d0 metric 100
ip route add default via 198.51.100.1 dev d1 metric 600
rules() { ip rule | grep -cE 'lookup 10[0-9]{3}' || true; }
"$0" --config "$2" net routes --sysfs "$1" &
pid=$!
for i in $(seq 50); do [ "$(rules)" = 2 ] && break; sleep 0.1; done
echo "running: $(rules) $(ip route get 203.0.113.9 from 198.51.100.2 | grep -o 'dev d[01]')"
ip addr add 198.51.100.7/24 dev d1
for i in $(seq 80); do ip rule | grep -q 'from 198.51.100.7' && break; sleep 0.1; done
echo "followed: $(rules) $(ip route get 203.0.113.9 from 198.51.100.7 | grep -o 'dev d[01]')"
kill -TERM $pid
wait $pid
echo "stopped: $(rules) $(ip route show table all proto 222 | grep -c . || true)"
"#;

#[test]
fn the_routes_service_follows_changes_and_cleans_up() {
    if !namespaces_allowed() {
        eprintln!("skipped: unprivileged user namespaces (unshare -rn) or ip aren't available");
        return;
    }
    let dir = tempfile::tempdir().unwrap();
    let config = dir.path().join("helios.toml");
    std::fs::write(&config, "[modules.net]\nexclude = []\n").unwrap();
    let output = Command::new("unshare")
        .args([
            "-rn",
            "sh",
            "-c",
            ROUTES_DAEMON,
            env!("CARGO_BIN_EXE_helios"),
        ])
        .arg(dir.path().join("sys"))
        .arg(&config)
        .output()
        .unwrap();
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        output.status.success(),
        "{stdout}\n{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let lines: Vec<&str> = stdout.lines().collect();
    assert!(lines.contains(&"running: 2 dev d1"), "{stdout}");
    assert!(
        lines.contains(&"followed: 3 dev d1"),
        "the new address got its rule: {stdout}"
    );
    assert!(
        lines.contains(&"stopped: 0 0"),
        "removed at SIGTERM: {stdout}"
    );
}
