use std::net::IpAddr;
use std::sync::Mutex;

use super::super::netlink::build::{address, default_route, done, link};
use super::super::netlink::{Dump, IFF_UP, Watch};
use super::plan::{Route, Rule, State};
use super::*;

/// The Orange Pi's network (2026-11-22): Ethernet 3 and Wi-Fi 4 on one router.
struct Network;

impl Kernel for Network {
    fn dump(&self, dump: Dump) -> io::Result<Vec<Vec<u8>>> {
        let ip = |text: &str| text.parse::<IpAddr>().unwrap();
        let reply = match dump {
            Dump::Links => [
                link(3, "enP4p65s0", IFF_UP, None, 6, true),
                link(4, "wlP2p33s0", IFF_UP, None, 6, true),
                done(),
            ]
            .concat(),
            Dump::Addresses => [
                address(3, ip("192.168.5.31"), 24, 0),
                address(4, ip("192.168.5.12"), 24, 0),
                done(),
            ]
            .concat(),
            Dump::Routes => [
                default_route(false, Some(3), Some(ip("192.168.5.1")), 100, None),
                default_route(false, Some(4), Some(ip("192.168.5.1")), 600, None),
                done(),
            ]
            .concat(),
            Dump::Nexthops | Dump::Rules => done(),
        };
        Ok(vec![reply])
    }

    fn watch(&self) -> io::Result<Box<dyn Watch>> {
        Err(io::Error::other("not in tests"))
    }
}

/// Holds Helios's rules and routes like the kernel would, and can refuse one change.
#[derive(Default)]
struct Routes {
    state: Mutex<State>,
    refuse: Option<Change>,
}

impl RouteKernel for Routes {
    fn current(&self) -> io::Result<State> {
        Ok(self.state.lock().unwrap().clone())
    }

    fn apply(&self, change: &Change) -> io::Result<()> {
        if self.refuse == Some(*change) {
            return Err(io::Error::from_raw_os_error(1));
        }
        let mut state = self.state.lock().unwrap();
        match *change {
            Change::AddRoute(route) => {
                state
                    .routes
                    .retain(|r| !(r.table == route.table && r.destination == route.destination));
                state.routes.push(route);
            }
            Change::DeleteRoute(route) => state.routes.retain(|r| *r != route),
            Change::AddRule(rule) => state.rules.push(rule),
            Change::DeleteRule(rule) => state.rules.retain(|r| *r != rule),
        }
        state.routes.sort();
        state.rules.sort();
        Ok(())
    }
}

#[test]
fn reconciles_to_a_table_and_rule_per_uplink_then_settles() {
    let routes = Routes::default();
    let first = reconcile(&Network, &routes, &|_| false).unwrap();
    assert_eq!(first.uplinks.len(), 2);
    assert_eq!(
        first.applied.len(),
        6,
        "2 default + 2 subnet routes, 2 rules"
    );
    assert!(first.failed.is_empty());
    let state = routes.current().unwrap();
    assert!(state.rules.contains(&Rule {
        source: "192.168.5.12".parse().unwrap(),
        priority: 10_004,
        table: 10_004,
    }));
    let again = reconcile(&Network, &routes, &|_| false).unwrap();
    assert!(again.applied.is_empty(), "nothing changes the second time");

    // Excluding the Wi-Fi removes its rule and routes.
    let excluded = reconcile(&Network, &routes, &|name| name.starts_with("wl")).unwrap();
    assert_eq!(excluded.applied.len(), 3);
    assert!(
        routes
            .current()
            .unwrap()
            .routes
            .iter()
            .all(|r| r.table == 10_003)
    );

    let removed = remove(&routes).unwrap();
    assert_eq!(removed.applied.len(), 3);
    assert_eq!(routes.current().unwrap(), State::default());
}

#[test]
fn a_refused_change_is_reported_and_the_rest_applied() {
    let refused = Change::AddRule(Rule {
        source: "192.168.5.31".parse().unwrap(),
        priority: 10_003,
        table: 10_003,
    });
    let routes = Routes {
        refuse: Some(refused),
        ..Routes::default()
    };
    let outcome = reconcile(&Network, &routes, &|_| false).unwrap();
    assert_eq!(outcome.failed.len(), 1);
    assert_eq!(outcome.failed[0].0, refused);
    assert_eq!(outcome.applied.len(), 5);
    log(&outcome);
    log_rp_filter(&outcome.uplinks);
}

#[test]
fn skips_excluded_and_virtual_interfaces() {
    let sysfs = tempfile::tempdir().unwrap();
    std::fs::create_dir_all(sysfs.path().join("class/net/enP4p65s0/device")).unwrap();
    std::fs::create_dir_all(sysfs.path().join("class/net/veth0/device")).unwrap();
    std::fs::create_dir_all(sysfs.path().join("class/net/wg0")).unwrap();
    let settings = NetSettings::default();
    let skip = skipper(&settings, sysfs.path());
    assert!(!skip("enP4p65s0"));
    assert!(skip("veth0"), "excluded by default (veth*)");
    assert!(skip("wg0"), "virtual: no device");
    assert!(skip("missing"));
}

#[test]
fn reads_the_net_settings_from_the_config() {
    let dir = tempfile::tempdir().unwrap();
    let config = dir.path().join("helios.toml");
    std::fs::write(
        &config,
        "[modules.net]\nexclude = [\"wlP*\"]\n[identity]\npin = 3\n",
    )
    .unwrap();
    let settings = settings(&config).unwrap();
    assert!(settings.excludes("wlP2p33s0"));
    assert!(!settings.excludes("veth0"), "the list replaces the default");
    std::fs::write(&config, "[device]\n").unwrap();
    assert!(
        super::settings(&config).unwrap().excludes("veth0"),
        "defaults"
    );
    std::fs::write(&config, "[modules.net]\nexclude = 3\n").unwrap();
    assert!(
        super::settings(&config)
            .unwrap_err()
            .contains("[modules.net]")
    );
    assert!(super::settings(&dir.path().join("none.toml")).is_err());
    let _ = Route {
        table: 0,
        destination: (std::net::Ipv4Addr::UNSPECIFIED, 0),
        gateway: None,
        interface: 0,
        source: std::net::Ipv4Addr::UNSPECIFIED,
    };
}
