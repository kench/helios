//! Standby for uplinks that share a public address (LLD 3, section 3.5.1). Two uplinks with the
//! same public IPv4 go out through the same connection (Ethernet and Wi-Fi on one router), so
//! bonding both adds no redundancy, and the weaker one drags the bond. The srtla list keeps one
//! per public address and holds the rest in standby: Ethernet first, then cellular, Wi-Fi
//! last; then the lower main-table metric; then the name. An uplink whose public address isn't
//! known counts as unique, so nothing is dropped on a guess.
//!
//! The view comes from Helios's net module over the control socket (`uplinks`); the daemon's
//! own address dump still decides which uplinks exist, so an uplink that loses its address is
//! gone at the next reconcile, and its standby takes its place.

use std::collections::BTreeMap;
use std::net::{IpAddr, Ipv4Addr};

use serde_json::{Value, json};

/// What the net module knows about one interface.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Uplink {
    /// `ethernet`, `cellular`, `wifi`, `virtual` or `other`.
    pub(crate) kind: String,
    /// Its lowest IPv4 default-route metric in the main table.
    pub(crate) metric: Option<u32>,
    /// Its public IPv4 address, when the latest check found one.
    pub(crate) public: Option<IpAddr>,
}

/// The net module's view, by interface name.
pub(crate) type View = BTreeMap<String, Uplink>;

/// Reads the `uplinks` request's `interfaces` (`{name: {kind, metric, public_ipv4}}`), skipping
/// anything malformed.
pub(crate) fn parse(params: &Value) -> View {
    params["interfaces"]
        .as_object()
        .into_iter()
        .flatten()
        .map(|(name, interface)| {
            let uplink = Uplink {
                kind: interface["kind"].as_str().unwrap_or("other").to_owned(),
                metric: interface["metric"]
                    .as_u64()
                    .and_then(|m| u32::try_from(m).ok()),
                public: interface["public_ipv4"]
                    .as_str()
                    .and_then(|text| text.parse().ok()),
            };
            (name.clone(), uplink)
        })
        .collect()
}

/// An uplink left out of the bond.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Standby {
    pub(crate) interface: String,
    pub(crate) address: Ipv4Addr,
    /// The bonded uplink it shares a public address with.
    pub(crate) shares_with: String,
}

impl Standby {
    pub(crate) fn json(&self) -> Value {
        json!({
            "interface": self.interface,
            "address": self.address.to_string(),
            "shares_public_address_with": self.shares_with,
        })
    }
}

/// How strongly an uplink of `kind` is preferred: lower bonds first.
fn rank(kind: &str) -> u8 {
    match kind {
        "ethernet" => 0,
        "cellular" => 1,
        "wifi" => 3,
        _ => 2,
    }
}

/// Splits `candidates` (interface and the address srtla would bind) into the addresses to bond,
/// sorted, and the uplinks in standby.
pub(crate) fn choose(
    candidates: &[(String, Ipv4Addr)],
    view: &View,
) -> (Vec<Ipv4Addr>, Vec<Standby>) {
    // Each public address's preferred uplink.
    let mut best: BTreeMap<IpAddr, (u8, u32, &str)> = BTreeMap::new();
    for (interface, _) in candidates {
        let Some(uplink) = view.get(interface) else {
            continue;
        };
        let Some(public) = uplink.public else {
            continue;
        };
        let key = (
            rank(&uplink.kind),
            uplink.metric.unwrap_or(u32::MAX),
            interface.as_str(),
        );
        best.entry(public)
            .and_modify(|current| {
                if key < *current {
                    *current = key;
                }
            })
            .or_insert(key);
    }
    let mut bond = Vec::new();
    let mut standby = Vec::new();
    for (interface, address) in candidates {
        let winner = view
            .get(interface)
            .and_then(|uplink| uplink.public)
            .and_then(|public| best.get(&public))
            .map(|(_, _, name)| *name);
        match winner {
            Some(name) if name != interface => standby.push(Standby {
                interface: interface.clone(),
                address: *address,
                shares_with: name.to_owned(),
            }),
            _ => bond.push(*address),
        }
    }
    bond.sort();
    bond.dedup();
    standby.sort_by(|a, b| a.interface.cmp(&b.interface));
    (bond, standby)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn uplink(kind: &str, metric: Option<u32>, public: Option<&str>) -> Uplink {
        Uplink {
            kind: kind.into(),
            metric,
            public: public.map(|text| text.parse().unwrap()),
        }
    }

    fn ip(text: &str) -> Ipv4Addr {
        text.parse().unwrap()
    }

    #[test]
    fn keeps_one_uplink_per_public_address_with_wifi_last() {
        let view: View = [
            (
                "enP4p65s0".to_owned(),
                uplink("ethernet", Some(100), Some("203.0.113.7")),
            ),
            (
                "wlP2p33s0".to_owned(),
                uplink("wifi", Some(600), Some("203.0.113.7")),
            ),
            (
                "wwan0".to_owned(),
                uplink("cellular", Some(700), Some("198.51.100.9")),
            ),
        ]
        .into();
        let candidates = vec![
            ("enP4p65s0".to_owned(), ip("192.168.5.31")),
            ("wlP2p33s0".to_owned(), ip("192.168.5.12")),
            ("wwan0".to_owned(), ip("10.64.12.9")),
        ];
        let (bond, standby) = choose(&candidates, &view);
        assert_eq!(bond, vec![ip("10.64.12.9"), ip("192.168.5.31")]);
        assert_eq!(
            standby,
            vec![Standby {
                interface: "wlP2p33s0".into(),
                address: ip("192.168.5.12"),
                shares_with: "enP4p65s0".into(),
            }]
        );
        assert_eq!(
            standby[0].json(),
            json!({"interface": "wlP2p33s0", "address": "192.168.5.12",
                   "shares_public_address_with": "enP4p65s0"})
        );
    }

    #[test]
    fn prefers_by_kind_then_metric_then_name() {
        let same = Some("203.0.113.7");
        let view: View = [
            ("wlan0".to_owned(), uplink("wifi", Some(10), same)),
            ("wwan0".to_owned(), uplink("cellular", Some(900), same)),
            ("usb1".to_owned(), uplink("ethernet", Some(200), same)),
            ("eth0".to_owned(), uplink("ethernet", Some(100), same)),
            ("eth1".to_owned(), uplink("ethernet", Some(100), same)),
        ]
        .into();
        let candidates: Vec<(String, Ipv4Addr)> = view
            .keys()
            .enumerate()
            .map(|(i, name)| {
                (
                    name.clone(),
                    Ipv4Addr::new(10, 0, 0, u8::try_from(i + 1).unwrap()),
                )
            })
            .collect();
        let (bond, standby) = choose(&candidates, &view);
        let eth0 = candidates
            .iter()
            .find(|(name, _)| name == "eth0")
            .unwrap()
            .1;
        assert_eq!(bond, vec![eth0], "ethernet, metric 100, then the name");
        assert_eq!(standby.len(), 4);
        assert!(standby.iter().all(|s| s.shares_with == "eth0"));
        // Without the ethernets, cellular beats Wi-Fi despite its metric.
        let rest: Vec<(String, Ipv4Addr)> = candidates
            .iter()
            .filter(|(name, _)| name.starts_with('w'))
            .cloned()
            .collect();
        let (bond, _) = choose(&rest, &view);
        let wwan0 = rest.iter().find(|(name, _)| name == "wwan0").unwrap().1;
        assert_eq!(bond, vec![wwan0]);
    }

    #[test]
    fn unknown_public_addresses_count_as_unique() {
        let view: View = [
            (
                "eth0".to_owned(),
                uplink("ethernet", Some(100), Some("203.0.113.7")),
            ),
            ("wlan0".to_owned(), uplink("wifi", Some(600), None)),
        ]
        .into();
        let candidates = vec![
            ("eth0".to_owned(), ip("192.168.5.31")),
            ("wlan0".to_owned(), ip("192.168.5.12")),
            ("usb0".to_owned(), ip("172.20.10.2")),
        ];
        let (bond, standby) = choose(&candidates, &view);
        assert_eq!(bond.len(), 3, "not checked, not in the view: all bond");
        assert!(standby.is_empty());
        let (bond, standby) = choose(&candidates, &View::new());
        assert_eq!(
            (bond.len(), standby.len()),
            (3, 0),
            "no view at all: as before"
        );
    }

    #[test]
    fn the_standby_takes_over_when_the_bonded_uplink_goes() {
        let view: View = [
            (
                "eth0".to_owned(),
                uplink("ethernet", Some(100), Some("203.0.113.7")),
            ),
            (
                "wlan0".to_owned(),
                uplink("wifi", Some(600), Some("203.0.113.7")),
            ),
        ]
        .into();
        // Ethernet lost its address, so it's no longer a candidate.
        let (bond, standby) = choose(&[("wlan0".to_owned(), ip("192.168.5.12"))], &view);
        assert_eq!(bond, vec![ip("192.168.5.12")]);
        assert!(standby.is_empty());
    }

    #[test]
    fn parses_the_request_and_skips_malformed_entries() {
        let view = parse(&json!({"interfaces": {
            "eth0": {"kind": "ethernet", "metric": 100, "public_ipv4": "203.0.113.7"},
            "wlan0": {"kind": "wifi", "metric": "high", "public_ipv4": "nowhere"},
            "odd": {},
        }}));
        assert_eq!(
            view["eth0"],
            uplink("ethernet", Some(100), Some("203.0.113.7"))
        );
        assert_eq!(view["wlan0"], uplink("wifi", None, None));
        assert_eq!(view["odd"], uplink("other", None, None));
        assert!(parse(&json!(null)).is_empty());
    }
}
