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
