//! What source routing should be (LLD 3, section 5.2): for each uplink, a table with its default
//! and subnet routes and a rule sending traffic from its address there; and the changes that get
//! the kernel from what it has to that. Pure: the tables come in, the changes go out.

use std::collections::BTreeMap;
use std::net::{IpAddr, Ipv4Addr};

use super::super::netlink::{IFF_UP, Tables};

/// The first table, and rule priority, Helios uses: `BASE + ifindex`.
pub(crate) const BASE: u32 = 10_000;
/// One past the last: Helios owns `BASE..LIMIT` for tables and rule priorities.
pub(crate) const LIMIT: u32 = 11_000;
/// The route protocol Helios marks its routes with (`/etc/iproute2/rt_protos.d/helios.conf`).
pub(crate) const PROTO_HELIOS: u8 = 222;

/// An interface that gets source routing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Uplink {
    pub(crate) index: u32,
    pub(crate) name: String,
    /// Its IPv4 addresses with their prefix lengths, the first one the preferred source.
    pub(crate) addresses: Vec<(Ipv4Addr, u8)>,
    /// The main table's default gateway through it; `None` for a point-to-point link.
    pub(crate) gateway: Option<Ipv4Addr>,
}

impl Uplink {
    /// Its table, which is also its rules' priority.
    #[must_use]
    pub(crate) fn table(&self) -> u32 {
        BASE + self.index
    }
}

/// A rule: `from <source>/32 lookup <table>` at `priority`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) struct Rule {
    pub(crate) source: Ipv4Addr,
    pub(crate) priority: u32,
    pub(crate) table: u32,
}

/// A route in one of Helios's tables.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) struct Route {
    pub(crate) table: u32,
    /// The destination and its prefix length; `0.0.0.0/0` for the default route.
    pub(crate) destination: (Ipv4Addr, u8),
    pub(crate) gateway: Option<Ipv4Addr>,
    pub(crate) interface: u32,
    pub(crate) source: Ipv4Addr,
}

/// What the kernel should have, or has, in Helios's range.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct State {
    pub(crate) rules: Vec<Rule>,
    pub(crate) routes: Vec<Route>,
}

/// One change to the kernel.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Change {
    AddRoute(Route),
    AddRule(Rule),
    DeleteRule(Rule),
    DeleteRoute(Route),
}

/// The uplinks in `tables`: every interface that's up and has an IPv4 address and an IPv4
/// default route in the main table, except those `skip` names (excluded or virtual) and those
/// whose index doesn't fit Helios's range.
pub(crate) fn uplinks(tables: &Tables, skip: &dyn Fn(&str) -> bool) -> Vec<Uplink> {
    // The lowest-metric IPv4 default route's gateway through each interface.
    let mut gateways: BTreeMap<u32, (u32, Option<Ipv4Addr>)> = BTreeMap::new();
    for route in tables.routes.iter().filter(|route| !route.ipv6) {
        for hop in tables.hops(route) {
            let gateway = match hop.gateway {
                Some(IpAddr::V4(gateway)) => Some(gateway),
                Some(IpAddr::V6(_)) => continue,
                None => None,
            };
            let entry = gateways.entry(hop.index).or_insert((route.metric, gateway));
            if route.metric < entry.0 {
                *entry = (route.metric, gateway);
            }
        }
    }
    let mut uplinks = Vec::new();
    for (index, (_, gateway)) in gateways {
        let Some(link) = tables.links.iter().find(|link| link.index == index) else {
            continue;
        };
        if link.flags & IFF_UP == 0 || skip(&link.name) || BASE + index >= LIMIT {
            continue;
        }
        let addresses: Vec<(Ipv4Addr, u8)> = tables
            .addresses
            .iter()
            .filter(|address| address.index == index)
            .filter_map(|address| match address.address {
                IpAddr::V4(ip) if !ip.is_loopback() => Some((ip, address.prefix)),
                _ => None,
            })
            .collect();
        if addresses.is_empty() {
            continue;
        }
        uplinks.push(Uplink {
            index,
            name: link.name.clone(),
            addresses,
            gateway,
        });
    }
    uplinks
}

/// The rules and routes `uplinks` need.
#[must_use]
pub(crate) fn wanted(uplinks: &[Uplink]) -> State {
    let mut state = State::default();
    for uplink in uplinks {
        let table = uplink.table();
        let preferred = uplink.addresses[0].0;
        state.routes.push(Route {
            table,
            destination: (Ipv4Addr::UNSPECIFIED, 0),
            gateway: uplink.gateway,
            interface: uplink.index,
            source: preferred,
        });
        for &(address, prefix) in &uplink.addresses {
            state.routes.push(Route {
                table,
                destination: (network(address, prefix), prefix),
                gateway: None,
                interface: uplink.index,
                source: address,
            });
            state.rules.push(Rule {
                source: address,
                priority: table,
                table,
            });
        }
    }
    state.rules.sort();
    state.rules.dedup();
    state.routes.sort();
    state
        .routes
        .dedup_by(|a, b| a.table == b.table && a.destination == b.destination);
    state
}

/// The changes from `current` to `wanted`: routes first, then rules, then deletions, so a table
/// is filled before a rule points at it and emptied only after its rules are gone.
#[must_use]
pub(crate) fn changes(current: &State, wanted: &State) -> Vec<Change> {
    let mut out = Vec::new();
    for route in &wanted.routes {
        if !current.routes.contains(route) {
            out.push(Change::AddRoute(*route));
        }
    }
    for rule in &wanted.rules {
        if !current.rules.contains(rule) {
            out.push(Change::AddRule(*rule));
        }
    }
    for rule in &current.rules {
        if !wanted.rules.contains(rule) {
            out.push(Change::DeleteRule(*rule));
        }
    }
    for route in &current.routes {
        // A route replaced in place (same table and destination) isn't deleted.
        let replaced = wanted
            .routes
            .iter()
            .any(|w| w.table == route.table && w.destination == route.destination);
        if !replaced {
            out.push(Change::DeleteRoute(*route));
        }
    }
    out
}

/// The network `address/prefix` is in.
#[must_use]
pub(crate) fn network(address: Ipv4Addr, prefix: u8) -> Ipv4Addr {
    let mask = if prefix == 0 {
        0
    } else {
        u32::MAX << (32 - u32::from(prefix.min(32)))
    };
    Ipv4Addr::from(u32::from(address) & mask)
}

#[cfg(test)]
mod tests {
    use super::super::super::netlink::{Address, Hop, Link, Route as KernelRoute, Tables, Via};
    use super::*;

    fn link(index: u32, name: &str, up: bool) -> Link {
        Link {
            index,
            name: name.into(),
            flags: if up { IFF_UP } else { 0 },
            mac: None,
            permanent_mac: None,
            mtu: None,
            oper_state: 6,
            carrier: Some(true),
        }
    }

    fn address(index: u32, ip: &str, prefix: u8) -> Address {
        Address {
            index,
            address: ip.parse().unwrap(),
            prefix,
            flags: 0,
        }
    }

    fn default(index: u32, gateway: Option<&str>, metric: u32) -> KernelRoute {
        KernelRoute {
            ipv6: false,
            metric,
            via: Via::Hops(vec![Hop {
                index,
                gateway: gateway.map(|g| g.parse().unwrap()),
            }]),
        }
    }

    /// The Orange Pi on 2026-11-22: Ethernet (3) and Wi-Fi (4) on the same router, the other
    /// Ethernet port down, plus a WireGuard tunnel with a default route and an excluded veth.
    fn board() -> Tables {
        Tables {
            links: vec![
                link(2, "enP3p49s0", true),
                link(3, "enP4p65s0", true),
                link(4, "wlP2p33s0", true),
                link(5, "wg0", true),
                link(6, "veth1", true),
                link(7, "wwan0", false),
            ],
            addresses: vec![
                address(3, "192.168.5.31", 24),
                address(4, "192.168.5.12", 24),
                address(4, "2001:db8:5:1::2", 64),
                address(5, "10.9.0.2", 32),
                address(6, "172.17.0.2", 16),
                address(7, "100.64.0.5", 30),
            ],
            routes: vec![
                default(3, Some("192.168.5.1"), 100),
                default(4, Some("192.168.5.1"), 600),
                default(5, None, 900),
                default(6, Some("172.17.0.1"), 50),
                default(7, None, 10),
                KernelRoute {
                    ipv6: true,
                    metric: 100,
                    via: Via::Hops(vec![Hop {
                        index: 2,
                        gateway: Some("fe80::1".parse().unwrap()),
                    }]),
                },
            ],
            nexthops: vec![],
            source: State::default(),
        }
    }

    fn skip(name: &str) -> bool {
        name == "wg0" || name.starts_with("veth")
    }

    #[test]
    fn finds_the_uplinks() {
        let uplinks = uplinks(&board(), &skip);
        let names: Vec<&str> = uplinks.iter().map(|u| u.name.as_str()).collect();
        // Not enP3p49s0 (no IPv4 default), wg0 and veth1 (skipped), wwan0 (down).
        assert_eq!(names, ["enP4p65s0", "wlP2p33s0"]);
        assert_eq!(
            uplinks[1].addresses,
            [("192.168.5.12".parse().unwrap(), 24)]
        );
        assert_eq!(uplinks[1].gateway, Some("192.168.5.1".parse().unwrap()));
        assert_eq!(uplinks[1].table(), 10_004);
    }

    #[test]
    fn a_point_to_point_modem_has_no_gateway_and_the_lowest_metric_wins() {
        let mut tables = board();
        tables.links[5].flags = IFF_UP;
        tables.routes.push(default(4, Some("192.168.5.254"), 50));
        let uplinks = uplinks(&tables, &skip);
        let modem = uplinks.iter().find(|u| u.name == "wwan0").unwrap();
        assert_eq!(modem.gateway, None);
        let wifi = uplinks.iter().find(|u| u.name == "wlP2p33s0").unwrap();
        assert_eq!(wifi.gateway, Some("192.168.5.254".parse().unwrap()));
    }

    #[test]
    fn wants_a_table_and_a_rule_per_uplink() {
        let state = wanted(&uplinks(&board(), &skip));
        let wifi: Ipv4Addr = "192.168.5.12".parse().unwrap();
        assert!(state.rules.contains(&Rule {
            source: wifi,
            priority: 10_004,
            table: 10_004
        }));
        assert!(state.routes.contains(&Route {
            table: 10_004,
            destination: (Ipv4Addr::UNSPECIFIED, 0),
            gateway: Some("192.168.5.1".parse().unwrap()),
            interface: 4,
            source: wifi,
        }));
        assert!(state.routes.contains(&Route {
            table: 10_004,
            destination: ("192.168.5.0".parse().unwrap(), 24),
            gateway: None,
            interface: 4,
            source: wifi,
        }));
        assert_eq!((state.rules.len(), state.routes.len()), (2, 4));
    }

    #[test]
    fn changes_add_first_and_delete_last_and_leave_the_rest() {
        let wanted = wanted(&uplinks(&board(), &skip));
        let all = changes(&State::default(), &wanted);
        assert!(matches!(all[0], Change::AddRoute(_)));
        assert!(matches!(all.last(), Some(Change::AddRule(_))));
        assert!(changes(&wanted, &wanted).is_empty(), "nothing to do");

        // The Wi-Fi got a new address: its rule moves, its subnet route is replaced in place.
        let mut tables = board();
        tables.addresses[1] = address(4, "192.168.5.77", 24);
        let next = super::wanted(&uplinks(&tables, &skip));
        let moved = changes(&wanted, &next);
        let old: Ipv4Addr = "192.168.5.12".parse().unwrap();
        assert!(
            moved
                .iter()
                .any(|c| matches!(c, Change::AddRule(r) if r.source.octets()[3] == 77))
        );
        assert!(
            moved
                .iter()
                .any(|c| matches!(c, Change::DeleteRule(r) if r.source == old))
        );
        assert!(
            !moved.iter().any(|c| matches!(c, Change::DeleteRoute(_))),
            "routes are replaced, not deleted"
        );
        let deletes_last = moved
            .iter()
            .position(|c| matches!(c, Change::DeleteRule(_)))
            .unwrap();
        assert!(
            moved[..deletes_last]
                .iter()
                .all(|c| !matches!(c, Change::DeleteRule(_)))
        );

        // Everything gone: only deletions.
        let gone = changes(&wanted, &State::default());
        assert!(
            gone.iter()
                .all(|c| matches!(c, Change::DeleteRule(_) | Change::DeleteRoute(_)))
        );
        assert_eq!(gone.len(), 6);
    }

    #[test]
    fn computes_networks() {
        let ip: Ipv4Addr = "192.168.5.31".parse().unwrap();
        assert_eq!(network(ip, 24), "192.168.5.0".parse::<Ipv4Addr>().unwrap());
        assert_eq!(network(ip, 32), ip);
        assert_eq!(network(ip, 0), Ipv4Addr::UNSPECIFIED);
        assert_eq!(
            network("100.64.0.5".parse().unwrap(), 30),
            "100.64.0.4".parse::<Ipv4Addr>().unwrap()
        );
    }

    #[test]
    fn an_index_past_the_range_is_left_out() {
        let mut tables = board();
        tables.links.push(link(1_000, "usb9", true));
        tables.addresses.push(address(1_000, "10.0.0.2", 24));
        tables.routes.push(default(1_000, Some("10.0.0.1"), 700));
        assert!(!uplinks(&tables, &skip).iter().any(|u| u.name == "usb9"));
    }
}
