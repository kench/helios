//! The `net` shadow's interfaces (LLD 3, sections 2.2, 2.3 and 7.1): netlink's tables, with
//! what sysfs adds (the kind, driver, USB port and link speed).

use std::cmp::Reverse;
use std::collections::BTreeMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::path::Path;

use serde_json::{Map, Value, json};

use super::NetSettings;
use super::netlink::{
    IFA_F_DADFAILED, IFA_F_DEPRECATED, IFA_F_TEMPORARY, IFA_F_TENTATIVE, IFF_LOOPBACK, IFF_UP,
    Link, Tables,
};
#[cfg(test)]
use super::nl80211::NoWireless;
use super::nl80211::Wireless;
use super::routes::plan::BASE;
use crate::sysfs::read_attr;

/// At most this many interfaces are reported.
pub(crate) const MAX_INTERFACES: usize = 16;
/// At most this many addresses of each family per interface.
pub(crate) const MAX_ADDRESSES: usize = 8;

/// `ARPHRD_ETHER`.
const ARPHRD_ETHER: &str = "1";

/// The interfaces to report, by name, and whether any were left out to fit.
pub(crate) struct Snapshot {
    pub(crate) interfaces: Map<String, Value>,
    pub(crate) truncated: bool,
}

/// Builds the snapshot from `tables`, reading `sysfs` (normally `/sys`) for each interface.
#[cfg(test)]
pub(crate) fn build(tables: &Tables, sysfs: &Path, settings: &NetSettings) -> Snapshot {
    build_with(tables, sysfs, settings, &NoWireless)
}

/// [`build`], asking `wireless` what each Wi-Fi interface is joined to (`wifi`: SSID, the access
/// point's MAC, frequency and signal, or `null` when it isn't joined).
pub(crate) fn build_with(
    tables: &Tables,
    sysfs: &Path,
    settings: &NetSettings,
    wireless: &dyn Wireless,
) -> Snapshot {
    let mut truncated = false;
    let mut links: Vec<(&Link, Device)> = tables
        .links
        .iter()
        .filter(|link| link.flags & IFF_LOOPBACK == 0 && !settings.excludes(&link.name))
        .map(|link| (link, Device::read(sysfs, &link.name)))
        .collect();
    // Real adapters first, so the limit drops virtual ones.
    links.sort_by(|(a, a_device), (b, b_device)| {
        (a_device.kind == "virtual", &a.name).cmp(&(b_device.kind == "virtual", &b.name))
    });
    if links.len() > MAX_INTERFACES {
        links.truncate(MAX_INTERFACES);
        truncated = true;
    }
    let mut routes: BTreeMap<u32, Vec<Value>> = BTreeMap::new();
    for route in &tables.routes {
        for hop in tables.hops(route) {
            let mut entry = json!({
                "family": if route.ipv6 { "ipv6" } else { "ipv4" },
                "metric": route.metric,
            });
            if let Some(gateway) = hop.gateway {
                entry["gateway"] = json!(gateway.to_string());
            }
            routes.entry(hop.index).or_default().push(entry);
        }
    }
    let mut interfaces = Map::new();
    for (link, device) in links {
        let (ipv4, ipv6, cut) = addresses(tables, link.index);
        truncated |= cut;
        let mut default_routes = routes.remove(&link.index).unwrap_or_default();
        default_routes.sort_by_key(|route| {
            (
                route["family"].as_str().map(str::to_owned),
                route["metric"].as_u64(),
                route["gateway"].as_str().map(str::to_owned),
            )
        });
        default_routes.dedup();
        let mut interface = json!({
            "kind": device.kind,
            "driver": device.driver,
            "usb_port": device.usb_port,
            "oper_state": oper_state(link.oper_state),
            "carrier": link.carrier,
            "admin_up": link.flags & IFF_UP != 0,
            "mtu": link.mtu,
            "speed_mbps": device.speed_mbps,
            "ipv4": ipv4,
            "ipv6": ipv6,
            "default_routes": default_routes,
            "source_route": source_route(tables, link.index),
        });
        if let Some(mac) = &link.mac {
            interface["mac"] = json!(hex(mac));
        }
        if let Some(permanent) = link
            .permanent_mac
            .as_ref()
            .filter(|p| Some(*p) != link.mac.as_ref())
        {
            interface["permanent_mac"] = json!(hex(permanent));
        }
        if device.kind == "wifi" {
            interface["wifi"] = match wireless.link(link.index) {
                Ok(Some(joined)) => json!({
                    "ssid": joined.ssid,
                    "bssid": joined.bssid.map(|bssid| hex(&bssid)),
                    "frequency_mhz": joined.frequency_mhz,
                    "signal_dbm": joined.signal_dbm,
                }),
                Ok(None) => Value::Null,
                Err(error) => {
                    tracing::debug!(%error, interface = %link.name, "nl80211 not read");
                    Value::Null
                }
            };
        }
        interfaces.insert(link.name.clone(), interface);
    }
    Snapshot {
        interfaces,
        truncated,
    }
}

/// Whether `helios routes` steers traffic from the interface's addresses through it (LLD 3,
/// section 5.4): `{"table", "rule"}` when its table holds a default route out of it, with `rule`
/// true when every IPv4 address it has also has its `from <address>` rule, and `null` when there's
/// no such route (the service isn't running, or the interface isn't an uplink).
fn source_route(tables: &Tables, index: u32) -> Value {
    let table = BASE + index;
    let routed = tables.source.routes.iter().any(|route| {
        route.table == table
            && route.interface == index
            && route.destination == (Ipv4Addr::UNSPECIFIED, 0)
    });
    if !routed {
        return Value::Null;
    }
    let mut ipv4 = tables
        .addresses
        .iter()
        .filter(|a| a.index == index)
        .filter_map(|a| match a.address {
            IpAddr::V4(v4) => Some(v4),
            IpAddr::V6(_) => None,
        })
        .peekable();
    let rule = ipv4.peek().is_some()
        && ipv4.all(|address| {
            tables
                .source
                .rules
                .iter()
                .any(|rule| rule.source == address && rule.table == table)
        });
    json!({"table": table, "rule": rule})
}

/// An interface's IPv4 addresses (`a.b.c.d/n`) and IPv6 addresses (objects), each list at most
/// [`MAX_ADDRESSES`] long, and whether any were left out.
fn addresses(tables: &Tables, index: u32) -> (Vec<String>, Vec<Value>, bool) {
    let mut ipv4: Vec<_> = Vec::new();
    let mut ipv6: Vec<_> = Vec::new();
    for address in tables.addresses.iter().filter(|a| a.index == index) {
        match address.address {
            IpAddr::V4(v4) => ipv4.push((v4, address.prefix)),
            IpAddr::V6(v6) if !v6.is_loopback() => ipv6.push((v6, address.prefix, address.flags)),
            IpAddr::V6(_) => {}
        }
    }
    ipv4.sort();
    ipv4.dedup();
    ipv6.sort_by_key(|(address, _, flags)| (rank(*address, *flags), *address));
    ipv6.dedup_by_key(|(address, _, _)| *address);
    let cut = ipv4.len() > MAX_ADDRESSES || ipv6.len() > MAX_ADDRESSES;
    ipv4.truncate(MAX_ADDRESSES);
    ipv6.truncate(MAX_ADDRESSES);
    let ipv4 = ipv4
        .into_iter()
        .map(|(address, prefix)| format!("{address}/{prefix}"))
        .collect();
    let ipv6 = ipv6
        .into_iter()
        .map(|(address, prefix, flags)| {
            json!({
                "address": address.to_string(),
                "prefix": prefix,
                "scope": scope(address),
                "temporary": flags & IFA_F_TEMPORARY != 0,
                "deprecated": flags & IFA_F_DEPRECATED != 0,
                "tentative": flags & IFA_F_TENTATIVE != 0,
                "dad_failed": flags & IFA_F_DADFAILED != 0,
            })
        })
        .collect();
    (ipv4, ipv6, cut)
}

/// Which IPv6 addresses are kept first: stable global, temporary global, unique-local,
/// link-local.
fn rank(address: Ipv6Addr, flags: u32) -> (u8, Reverse<bool>) {
    let order = match scope(address) {
        "global" if flags & IFA_F_TEMPORARY == 0 => 0,
        "global" => 1,
        "unique_local" => 2,
        _ => 3,
    };
    (order, Reverse(flags & IFA_F_DEPRECATED == 0))
}

/// `global`, `unique_local` (`fc00::/7`) or `link` (`fe80::/10`).
pub(crate) fn scope(address: Ipv6Addr) -> &'static str {
    let first = address.segments()[0];
    if first & 0xffc0 == 0xfe80 {
        "link"
    } else if first & 0xfe00 == 0xfc00 {
        "unique_local"
    } else {
        "global"
    }
}

/// `IF_OPER_*` by RFC 2863's names.
fn oper_state(state: u8) -> &'static str {
    match state {
        1 => "not_present",
        2 => "down",
        3 => "lower_layer_down",
        4 => "testing",
        5 => "dormant",
        6 => "up",
        _ => "unknown",
    }
}

/// `c0:74:2b:f2:75:13`.
fn hex(bytes: &[u8]) -> String {
    bytes
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<Vec<_>>()
        .join(":")
}

/// What sysfs says about an interface's hardware.
struct Device {
    kind: &'static str,
    driver: Option<String>,
    usb_port: Option<String>,
    speed_mbps: Option<u64>,
}

impl Device {
    fn read(sysfs: &Path, name: &str) -> Self {
        let dir = sysfs.join("class/net").join(name);
        let device = dir.join("device");
        let real = std::fs::canonicalize(&device).ok();
        let driver = std::fs::read_link(device.join("driver"))
            .ok()
            .and_then(|link| link.file_name()?.to_str().map(str::to_owned));
        let wwan = read_attr(&dir.join("uevent"))
            .is_some_and(|uevent| uevent.lines().any(|line| line == "DEVTYPE=wwan"))
            || matches!(driver.as_deref(), Some("qmi_wwan" | "cdc_mbim"));
        let kind = if dir.join("wireless").exists() || dir.join("phy80211").exists() {
            "wifi"
        } else if wwan {
            "cellular"
        } else if real.is_none() {
            "virtual"
        } else if read_attr(&dir.join("type")).as_deref() == Some(ARPHRD_ETHER) {
            "ethernet"
        } else {
            "other"
        };
        let usb_port = real
            .as_deref()
            .filter(|path| crate::sysfs::on_usb(path))
            .and_then(crate::sysfs::usb_port);
        let speed_mbps = (kind == "ethernet")
            .then(|| read_attr(&dir.join("speed")))
            .flatten()
            .and_then(|speed| speed.parse::<u64>().ok())
            .filter(|&speed| speed > 0);
        Self {
            kind,
            driver,
            usb_port,
            speed_mbps,
        }
    }
}
