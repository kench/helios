use std::fs;
use std::io;
use std::net::IpAddr;
use std::os::unix::fs::symlink;
use std::path::Path;
use std::sync::{Arc, Mutex, mpsc as std_mpsc};
use std::time::{Duration, SystemTime};

use serde_json::{Value, json};
use tokio::sync::mpsc;

use super::netlink::build::{address, default_route, done, error, link, nexthop};
use super::netlink::{
    Dump, IFA_F_DEPRECATED, IFA_F_TEMPORARY, IFF_LOOPBACK, IFF_UP, Kernel, Watch,
};
use super::snapshot::{MAX_ADDRESSES, MAX_INTERFACES, build, scope};
use super::{ModuleContext, NetModule, NetSettings, Reporter, changes};
use crate::modules::Module;
use crate::mqtt::manager::{MqttHandle, Request as MqttRequest};
use crate::mqtt::shadow::ShadowHandle;

const MAC: [u8; 6] = [0xc0, 0x74, 0x2b, 0x00, 0x00, 0x01];

fn ip(text: &str) -> IpAddr {
    text.parse().unwrap()
}

/// A sysfs tree in a temporary directory.
struct Sysfs(tempfile::TempDir);

impl Sysfs {
    fn new() -> Self {
        Self(tempfile::tempdir().unwrap())
    }

    fn path(&self) -> &Path {
        self.0.path()
    }

    fn write(&self, path: &str, text: &str) {
        let path = self.0.path().join(path);
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(path, text).unwrap();
    }

    fn dir(&self, path: &str) {
        fs::create_dir_all(self.0.path().join(path)).unwrap();
    }

    /// An interface with a device at `device` (under `devices/`) bound to `driver`.
    fn adapter(&self, name: &str, device: &str, driver: Option<&str>, kind: &str) {
        let device_dir = self.0.path().join("devices").join(device);
        fs::create_dir_all(&device_dir).unwrap();
        if let Some(driver) = driver {
            let driver_dir = self.0.path().join("bus/drivers").join(driver);
            fs::create_dir_all(&driver_dir).unwrap();
            symlink(&driver_dir, device_dir.join("driver")).unwrap();
        }
        let net = self.0.path().join("class/net").join(name);
        fs::create_dir_all(&net).unwrap();
        symlink(&device_dir, net.join("device")).unwrap();
        self.write(&format!("class/net/{name}/type"), kind);
    }
}

/// The tables of the Orange Pi as it was on 2026-11-22, plus a few more kinds of interface.
fn board_tables() -> Vec<(Dump, Vec<u8>)> {
    let router6 = ip("fe80::1");
    vec![
        (
            Dump::Links,
            [
                link(1, "lo", IFF_UP | IFF_LOOPBACK, None, 0, true),
                link(
                    2,
                    "enP3p49s0",
                    IFF_UP,
                    Some([0xc0, 0x74, 0x2b, 0x00, 0x00, 0x02]),
                    2,
                    false,
                ),
                link(3, "enP4p65s0", IFF_UP, Some(MAC), 6, true),
                link(
                    4,
                    "wlP2p33s0",
                    0,
                    Some([0xcc, 0x21, 0x9d, 0xb0, 0x5b, 0x16]),
                    2,
                    false,
                ),
                link(5, "veth1a2b", IFF_UP, Some([2, 0, 0, 0, 0, 1]), 6, true),
                link(6, "wg0", IFF_UP, None, 0, true),
                link(7, "wwan0", IFF_UP, None, 6, true),
                done(),
            ]
            .concat(),
        ),
        (
            Dump::Addresses,
            [
                address(1, ip("127.0.0.1"), 8, 0),
                address(3, ip("192.168.5.31"), 24, 0),
                address(3, ip("192.168.5.31"), 24, 0),
                address(3, ip("fe80::c274:2bff:fe00:1"), 64, 0),
                address(
                    3,
                    ip("2001:db8:5:1::1"),
                    64,
                    IFA_F_TEMPORARY,
                ),
                address(3, ip("2001:db8:5:1:c274:2bff:fe00:1"), 64, 0),
                address(3, ip("::1"), 128, 0),
                address(7, ip("10.64.12.9"), 30, 0),
                address(7, ip("2001:db8:7::5"), 64, 0),
                done(),
            ]
            .concat(),
        ),
        (
            Dump::Routes,
            [
                default_route(false, Some(3), Some(ip("192.168.5.1")), 100, None),
                default_route(false, Some(3), Some(ip("192.168.5.1")), 100, None),
                default_route(true, None, None, 100, Some(1_241_586_351)),
                default_route(true, Some(7), None, 1024, None),
                // helios routes: Ethernet's table, and the modem's (whose rule is missing below).
                helios_route(10_003, Some("192.168.5.1"), 3, "192.168.5.31"),
                helios_route(10_007, None, 7, "10.64.12.9"),
                done(),
            ]
            .concat(),
        ),
        (
            Dump::Nexthops,
            [nexthop(1_241_586_351, 3, router6), done()].concat(),
        ),
        (
            Dump::Rules,
            [helios_rule("192.168.5.31", 10_003), done()].concat(),
        ),
    ]
}

/// A default route in one of `helios routes`'s tables, as the kernel dumps it.
fn helios_route(table: u32, gateway: Option<&str>, interface: u32, source: &str) -> Vec<u8> {
    let route = super::routes::plan::Route {
        table,
        destination: (std::net::Ipv4Addr::UNSPECIFIED, 0),
        gateway: gateway.map(|gateway| gateway.parse().unwrap()),
        interface,
        source: source.parse().unwrap(),
    };
    super::routes::kernel::message(24, 0, &super::routes::kernel::route_body(&route))
}

/// A `from <source> lookup <table>` rule of `helios routes`'s, as the kernel dumps it.
fn helios_rule(source: &str, table: u32) -> Vec<u8> {
    let rule = super::routes::plan::Rule {
        source: source.parse().unwrap(),
        priority: table,
        table,
    };
    super::routes::kernel::message(32, 0, &super::routes::kernel::rule_body(&rule))
}

fn board_sysfs() -> Sysfs {
    let sysfs = Sysfs::new();
    sysfs.adapter(
        "enP3p49s0",
        "platform/pcie3/0003:31:00.0",
        Some("r8169"),
        "1",
    );
    sysfs.write("class/net/enP3p49s0/speed", "-1");
    sysfs.adapter(
        "enP4p65s0",
        "platform/pcie4/0004:41:00.0",
        Some("r8169"),
        "1",
    );
    sysfs.write("class/net/enP4p65s0/speed", "1000");
    sysfs.adapter(
        "wlP2p33s0",
        "platform/pcie2/0002:21:00.0",
        Some("rtw89_8852be"),
        "1",
    );
    sysfs.dir("class/net/wlP2p33s0/wireless");
    sysfs.adapter(
        "wwan0",
        "platform/xhci/usb1/1-1/1-1.2/1-1.2:1.4",
        Some("qmi_wwan"),
        "65534",
    );
    sysfs.dir("class/net/veth1a2b");
    sysfs.dir("class/net/wg0");
    sysfs
}

/// A kernel whose tables a test sets, and whose change socket a test drives.
struct FakeKernel {
    replies: Mutex<Vec<(Dump, Vec<u8>)>>,
    fail_dumps: Mutex<bool>,
    watch: Mutex<Option<std_mpsc::Receiver<io::Result<()>>>>,
}

impl FakeKernel {
    fn new(replies: Vec<(Dump, Vec<u8>)>) -> (Arc<Self>, std_mpsc::Sender<io::Result<()>>) {
        let (tx, rx) = std_mpsc::channel();
        let kernel = Arc::new(Self {
            replies: Mutex::new(replies),
            fail_dumps: Mutex::new(false),
            watch: Mutex::new(Some(rx)),
        });
        (kernel, tx)
    }

    fn set(&self, dump: Dump, reply: Vec<u8>) {
        let mut replies = self.replies.lock().unwrap();
        for entry in replies.iter_mut() {
            if entry.0 == dump {
                entry.1 = reply.clone();
            }
        }
    }
}

impl Kernel for FakeKernel {
    fn dump(&self, dump: Dump) -> io::Result<Vec<Vec<u8>>> {
        if *self.fail_dumps.lock().unwrap() {
            return Err(io::Error::other("no tables"));
        }
        let replies = self.replies.lock().unwrap();
        let mut found: Vec<Vec<u8>> = replies
            .iter()
            .filter(|(kind, _)| *kind == dump)
            .map(|(_, reply)| reply.clone())
            .collect();
        // Most tests have no source routing: an empty rules dump.
        if found.is_empty() && dump == Dump::Rules {
            found.push(done());
        }
        Ok(found)
    }

    fn watch(&self) -> io::Result<Box<dyn Watch>> {
        let receiver = self
            .watch
            .lock()
            .unwrap()
            .take()
            .ok_or_else(|| io::Error::other("only one watch"))?;
        Ok(Box::new(FakeWatch(receiver)))
    }
}

struct FakeWatch(std_mpsc::Receiver<io::Result<()>>);

impl Watch for FakeWatch {
    fn wait(&mut self) -> io::Result<bool> {
        match self.0.recv_timeout(Duration::from_millis(50)) {
            Ok(Ok(())) => Ok(true),
            Ok(Err(error)) => Err(error),
            Err(std_mpsc::RecvTimeoutError::Timeout) => Ok(false),
            Err(std_mpsc::RecvTimeoutError::Disconnected) => {
                std::thread::sleep(Duration::from_millis(50));
                Ok(false)
            }
        }
    }
}

fn read_board() -> (Value, bool) {
    let (kernel, _changes) = FakeKernel::new(board_tables());
    let sysfs = board_sysfs();
    let snapshot = super::current(
        kernel.as_ref(),
        &super::nl80211::NoWireless,
        sysfs.path(),
        &NetSettings::default(),
    )
    .unwrap();
    (Value::Object(snapshot.interfaces), snapshot.truncated)
}

#[test]
fn reports_the_boards_interfaces() {
    let (interfaces, truncated) = read_board();
    assert!(!truncated);
    let names: Vec<&String> = interfaces.as_object().unwrap().keys().collect();
    assert_eq!(
        names,
        ["enP3p49s0", "enP4p65s0", "wg0", "wlP2p33s0", "wwan0"]
    );
    assert_eq!(
        interfaces["enP4p65s0"],
        json!({
            "kind": "ethernet",
            "mac": "c0:74:2b:00:00:01",
            "driver": "r8169",
            "usb_port": null,
            "oper_state": "up",
            "carrier": true,
            "admin_up": true,
            "mtu": 1500,
            "speed_mbps": 1000,
            "ipv4": ["192.168.5.31/24"],
            "ipv6": [
                {"address": "2001:db8:5:1:c274:2bff:fe00:1", "prefix": 64,
                 "scope": "global", "temporary": false, "deprecated": false,
                 "tentative": false, "dad_failed": false},
                {"address": "2001:db8:5:1::1", "prefix": 64,
                 "scope": "global", "temporary": true, "deprecated": false,
                 "tentative": false, "dad_failed": false},
                {"address": "fe80::c274:2bff:fe00:1", "prefix": 64, "scope": "link",
                 "temporary": false, "deprecated": false, "tentative": false,
                 "dad_failed": false},
            ],
            "default_routes": [
                {"family": "ipv4", "gateway": "192.168.5.1", "metric": 100},
                {"family": "ipv6", "gateway": "fe80::1", "metric": 100},
            ],
            "source_route": {"table": 10_003, "rule": true},
        })
    );
    assert_eq!(
        interfaces["wwan0"]["source_route"],
        json!({"table": 10_007, "rule": false}),
        "a table without its rule doesn't steer anything"
    );
    let down = &interfaces["enP3p49s0"];
    assert_eq!(down["source_route"], Value::Null);
    assert_eq!(down["oper_state"], "down");
    assert_eq!(down["speed_mbps"], Value::Null, "speed -1 is unknown");
    assert_eq!(down["default_routes"], json!([]));
    let wifi = &interfaces["wlP2p33s0"];
    assert_eq!(wifi["kind"], "wifi");
    assert_eq!(wifi["admin_up"], false);
    assert_eq!(wifi["driver"], "rtw89_8852be");
    let modem = &interfaces["wwan0"];
    assert_eq!(modem["kind"], "cellular");
    assert_eq!(modem["usb_port"], "1-1.2");
    assert!(modem.get("mac").is_none(), "a raw-IP modem has no MAC");
    assert_eq!(modem["ipv4"], json!(["10.64.12.9/30"]));
    assert_eq!(
        modem["default_routes"],
        json!([{"family": "ipv6", "metric": 1024}]),
        "a point-to-point route has no gateway"
    );
    assert_eq!(interfaces["wg0"]["kind"], "virtual");
    assert_eq!(interfaces["wg0"]["driver"], Value::Null);
}

#[test]
fn classifies_other_kinds_from_sysfs() {
    let sysfs = Sysfs::new();
    sysfs.adapter("usb0", "platform/usb2/2-1/2-1:1.0", Some("cdc_ether"), "1");
    sysfs.adapter("mbim0", "platform/pcie/0001:01:00.0", None, "1");
    sysfs.write("class/net/mbim0/uevent", "INTERFACE=mbim0\nDEVTYPE=wwan\n");
    sysfs.adapter("can0", "platform/can", Some("rcar_can"), "280");
    let tables = super::netlink::Tables {
        links: ["usb0", "mbim0", "can0"]
            .iter()
            .enumerate()
            .map(|(n, name)| super::netlink::Link {
                index: u32::try_from(n).unwrap() + 10,
                name: (*name).into(),
                flags: IFF_UP,
                mac: None,
                permanent_mac: None,
                mtu: None,
                oper_state: 9,
                carrier: None,
            })
            .collect(),
        ..Default::default()
    };
    let snapshot = build(&tables, sysfs.path(), &NetSettings::default());
    let interfaces = &snapshot.interfaces;
    assert_eq!(interfaces["usb0"]["kind"], "ethernet");
    assert_eq!(interfaces["usb0"]["usb_port"], "2-1");
    assert_eq!(
        interfaces["usb0"]["speed_mbps"],
        Value::Null,
        "no speed file"
    );
    assert_eq!(interfaces["mbim0"]["kind"], "cellular");
    assert_eq!(interfaces["can0"]["kind"], "other");
    assert_eq!(interfaces["can0"]["oper_state"], "unknown");
}

#[test]
fn reports_a_permanent_mac_only_when_it_differs() {
    let mut tables = super::netlink::Tables::default();
    for (index, name, permanent) in [
        (1, "wlan0", Some(vec![0xcc, 0x21, 0x9d, 0xb0, 0x5b, 0x16])),
        (2, "eth0", Some(MAC.to_vec())),
    ] {
        tables.links.push(super::netlink::Link {
            index,
            name: name.into(),
            flags: 0,
            mac: Some(MAC.to_vec()),
            permanent_mac: permanent,
            mtu: Some(1500),
            oper_state: 2,
            carrier: Some(false),
        });
    }
    let snapshot = build(&tables, Path::new("/nonexistent"), &NetSettings::default());
    assert_eq!(
        snapshot.interfaces["wlan0"]["permanent_mac"],
        "cc:21:9d:b0:5b:16"
    );
    assert!(snapshot.interfaces["eth0"].get("permanent_mac").is_none());
}

#[test]
fn keeps_the_shadow_small() {
    let mut tables = super::netlink::Tables::default();
    for index in 0..20u32 {
        tables.links.push(super::netlink::Link {
            index,
            name: format!("tun{index:02}"),
            flags: IFF_UP,
            mac: None,
            permanent_mac: None,
            mtu: None,
            oper_state: 6,
            carrier: Some(true),
        });
    }
    let sysfs = Sysfs::new();
    sysfs.adapter("tun19", "platform/real", Some("r8169"), "1");
    for n in 0..10u16 {
        tables.addresses.push(super::netlink::Address {
            index: 19,
            address: IpAddr::V6(std::net::Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, n)),
            prefix: 64,
            flags: if n % 2 == 0 { IFA_F_DEPRECATED } else { 0 },
        });
        tables.addresses.push(super::netlink::Address {
            index: 19,
            address: IpAddr::V4(std::net::Ipv4Addr::new(10, 0, 0, u8::try_from(n).unwrap())),
            prefix: 24,
            flags: 0,
        });
    }
    let snapshot = build(&tables, sysfs.path(), &NetSettings::default());
    assert!(snapshot.truncated);
    assert_eq!(snapshot.interfaces.len(), MAX_INTERFACES);
    assert!(
        snapshot.interfaces.contains_key("tun19"),
        "the real adapter is kept over virtual ones"
    );
    let kept = &snapshot.interfaces["tun19"];
    assert_eq!(kept["ipv4"].as_array().unwrap().len(), MAX_ADDRESSES);
    let ipv6 = kept["ipv6"].as_array().unwrap();
    assert_eq!(ipv6.len(), MAX_ADDRESSES);
    assert_eq!(ipv6[0]["deprecated"], false, "preferred addresses first");
}

#[test]
fn names_ipv6_scopes() {
    assert_eq!(scope("fe80::1".parse().unwrap()), "link");
    assert_eq!(scope("febf::1".parse().unwrap()), "link");
    assert_eq!(scope("fd00::1".parse().unwrap()), "unique_local");
    assert_eq!(scope("fc12::1".parse().unwrap()), "unique_local");
    assert_eq!(scope("2001:db8::1".parse().unwrap()), "global");
    assert_eq!(scope("fec0::1".parse().unwrap()), "global");
}

#[test]
fn settings_check_patterns() {
    assert_eq!(
        NetSettings::default().check().unwrap(),
        Some(NetSettings::default())
    );
    let disabled: NetSettings = toml::from_str("enabled = false").unwrap();
    assert_eq!(disabled.check().unwrap(), None);
    let custom: NetSettings = toml::from_str(r#"exclude = ["docker*", "wg0"]"#).unwrap();
    let custom = custom.check().unwrap().unwrap();
    assert!(custom.excludes("docker0"));
    assert!(custom.excludes("wg0"));
    assert!(!custom.excludes("wg01"));
    assert!(!custom.excludes("veth0"), "the default list is replaced");
    for bad in ["", "*", "a*b", "a b", "eth/0", "much-too-long-name"] {
        let settings = NetSettings {
            enabled: true,
            exclude: vec![bad.into()],
            public_address_check: true,
        };
        assert!(settings.check().is_err(), "{bad:?}");
    }
    assert!(toml::from_str::<NetSettings>("interfaces = []").is_err());
}

fn snapshot(interfaces: Value, truncated: bool) -> super::snapshot::Snapshot {
    super::snapshot::Snapshot {
        interfaces: interfaces.as_object().unwrap().clone(),
        truncated,
    }
}

#[test]
fn since_moves_only_with_the_operating_state() {
    let mut reporter = Reporter::default();
    let start = SystemTime::UNIX_EPOCH + Duration::from_secs(1_795_000_000);
    let later = start + Duration::from_secs(60);
    let up = json!({"eth0": {"oper_state": "up", "mtu": 1500}});
    let (first, event) = reporter
        .update(snapshot(up.clone(), false), json!({}), start)
        .unwrap();
    assert!(event.is_none(), "no event for the first report");
    let since = first["interfaces"]["eth0"]["since"].clone();
    assert!(since.as_str().unwrap().starts_with("2026-11-18T"));
    assert!(
        reporter
            .update(snapshot(up, false), json!({}), later)
            .is_none(),
        "nothing changed"
    );
    let bigger = json!({"eth0": {"oper_state": "up", "mtu": 9000}});
    let (second, event) = reporter
        .update(snapshot(bigger, false), json!({}), later)
        .unwrap();
    assert_eq!(second["interfaces"]["eth0"]["since"], since);
    assert_eq!(
        event,
        Some(json!({"added": [], "removed": [], "changed": {"eth0": ["mtu"]}}))
    );
    let down = json!({"eth0": {"oper_state": "down", "mtu": 9000}});
    let (third, _) = reporter
        .update(snapshot(down, true), json!({}), later)
        .unwrap();
    assert_ne!(third["interfaces"]["eth0"]["since"], since);
    assert_eq!(third["truncated"], true);
}

#[test]
fn events_name_what_changed() {
    let report = |interfaces: Value| {
        let mut report = serde_json::Map::new();
        report.insert("interfaces".into(), interfaces);
        report
    };
    let before = report(json!({
        "eth0": {"oper_state": "up", "mac": "02:00:00:00:00:01", "since": "a"},
        "usb0": {"oper_state": "up"},
    }));
    let after = report(json!({
        "eth0": {"oper_state": "down", "since": "b"},
        "wwan0": {"oper_state": "up"},
    }));
    assert_eq!(
        changes(&before, &after),
        Some(json!({
            "added": ["wwan0"],
            "removed": ["usb0"],
            "changed": {"eth0": ["mac", "oper_state"]},
        }))
    );
    assert_eq!(changes(&before, &before), None);
    assert_eq!(
        changes(&serde_json::Map::new(), &serde_json::Map::new()),
        None
    );
}

fn context(
    sysfs: &Path,
) -> (
    ModuleContext,
    crate::mqtt::shadow::TestReports,
    mpsc::UnboundedReceiver<MqttRequest>,
) {
    let (mqtt, requests, _status) = MqttHandle::for_test();
    let (shadows, reports, _desired) = ShadowHandle::for_test();
    let ctx = ModuleContext {
        commands: mpsc::channel(1).1,
        desired: mpsc::unbounded_channel().1,
        shadows,
        mqtt,
        sysfs: sysfs.to_owned(),
        cancel: Default::default(),
    };
    (ctx, reports, requests)
}

async fn next_report(reports: &mut crate::mqtt::shadow::TestReports) -> Value {
    let (shadow, reported) = tokio::time::timeout(Duration::from_secs(10), reports.recv())
        .await
        .expect("a report")
        .expect("reports open");
    assert_eq!(shadow, "net");
    Value::Object(reported)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn reports_each_routed_uplinks_public_address() {
    let sysfs = board_sysfs();
    let (kernel, _changes) = FakeKernel::new(board_tables());
    let probe = Arc::new(super::egress::tests::FakeProbe {
        answer: Ok("203.0.113.7".parse().unwrap()),
        asked: std::sync::Mutex::new(Vec::new()),
    });
    let module = Arc::new(
        NetModule::with_kernel(
            NetSettings::default(),
            Arc::clone(&kernel) as Arc<dyn Kernel>,
            sysfs.path(),
        )
        .with_probe(Arc::clone(&probe) as Arc<dyn super::egress::Probe>),
    );
    let (ctx, mut reports, _requests) = context(sysfs.path());
    let cancel = ctx.cancel.clone();
    let running = tokio::spawn({
        let module = Arc::clone(&module);
        async move { module.run(ctx).await }
    });
    let first = next_report(&mut reports).await;
    assert_eq!(
        first["interfaces"]["enP4p65s0"]["public_ipv4"],
        Value::Null,
        "not yet checked"
    );
    let second = next_report(&mut reports).await;
    assert_eq!(
        second["interfaces"]["enP4p65s0"]["public_ipv4"]["address"],
        "203.0.113.7"
    );
    assert_eq!(
        second["interfaces"]["wwan0"]["public_ipv4"],
        Value::Null,
        "its table has no rule, so it isn't checked"
    );
    assert_eq!(
        *probe.asked.lock().unwrap(),
        vec![std::net::Ipv4Addr::new(192, 168, 5, 31)],
        "asked once, from Ethernet's address"
    );
    cancel.cancel();
    running.await.unwrap().unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn reports_at_start_and_after_a_change() {
    let sysfs = board_sysfs();
    let (kernel, changes) = FakeKernel::new(board_tables());
    let module = Arc::new(NetModule::with_kernel(
        NetSettings::default(),
        Arc::clone(&kernel) as Arc<dyn Kernel>,
        sysfs.path(),
    ));
    let (ctx, mut reports, mut requests) = context(sysfs.path());
    let cancel = ctx.cancel.clone();
    let running = tokio::spawn({
        let module = Arc::clone(&module);
        async move { module.run(ctx).await }
    });
    assert_eq!(module.name(), "net");

    let first = next_report(&mut reports).await;
    assert_eq!(
        first["interfaces"]["enP4p65s0"]["ipv4"],
        json!(["192.168.5.31/24"])
    );
    assert_eq!(first["truncated"], false);

    // The Wi-Fi joins a network: it comes up with an address.
    kernel.set(
        Dump::Links,
        [
            link(3, "enP4p65s0", IFF_UP, Some(MAC), 6, true),
            link(
                4,
                "wlP2p33s0",
                IFF_UP,
                Some([0xcc, 0x21, 0x9d, 0xb0, 0x5b, 0x16]),
                6,
                true,
            ),
            done(),
        ]
        .concat(),
    );
    kernel.set(
        Dump::Addresses,
        [address(4, ip("192.168.8.20"), 24, 0), done()].concat(),
    );
    changes.send(Ok(())).unwrap();
    changes.send(Ok(())).unwrap();
    let second = next_report(&mut reports).await;
    let wifi = &second["interfaces"]["wlP2p33s0"];
    assert_eq!(wifi["oper_state"], "up");
    assert_eq!(wifi["ipv4"], json!(["192.168.8.20/24"]));
    assert!(second["interfaces"].get("wwan0").is_none());
    let event = loop {
        match requests.recv().await.expect("an event") {
            MqttRequest::Event(event) => break event,
            MqttRequest::Now { .. } => {}
        }
    };
    assert_eq!(event.kind(), "net.changed");
    assert_eq!(
        event.payload()["removed"],
        json!(["enP3p49s0", "wg0", "wwan0"])
    );
    assert!(
        event.payload()["changed"]["wlP2p33s0"]
            .as_array()
            .unwrap()
            .contains(&json!("ipv4"))
    );

    cancel.cancel();
    assert_eq!(running.await.unwrap(), Ok(()));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn fails_when_the_kernel_does() {
    let sysfs = Sysfs::new();
    // The change socket can't be opened.
    let (kernel, _changes) = FakeKernel::new(board_tables());
    kernel.watch.lock().unwrap().take();
    let (ctx, _reports, _requests) = context(sysfs.path());
    let error = NetModule::with_kernel(NetSettings::default(), kernel, sysfs.path())
        .run(ctx)
        .await
        .unwrap_err();
    assert!(error.0.contains("can't listen"), "{error}");

    // The tables can't be read.
    let (kernel, _changes) = FakeKernel::new(board_tables());
    *kernel.fail_dumps.lock().unwrap() = true;
    let (ctx, _reports, _requests) = context(sysfs.path());
    let error = NetModule::with_kernel(NetSettings::default(), kernel, sysfs.path())
        .run(ctx)
        .await
        .unwrap_err();
    assert!(error.0.contains("reading the network tables"), "{error}");

    // The change socket fails later: the listener stops, and so does the run.
    let (kernel, changes) = FakeKernel::new(board_tables());
    let (ctx, mut reports, _requests) = context(sysfs.path());
    let wifi_dir = sysfs.path().to_owned();
    let running = tokio::spawn(async move {
        NetModule::with_kernel(NetSettings::default(), kernel, &wifi_dir)
            .run(ctx)
            .await
    });
    next_report(&mut reports).await;
    changes.send(Err(io::Error::other("socket gone"))).unwrap();
    let error = tokio::time::timeout(Duration::from_secs(10), running)
        .await
        .unwrap()
        .unwrap()
        .unwrap_err();
    assert!(error.0.contains("listener stopped"), "{error}");
}

#[test]
fn a_missing_nexthop_dump_is_fine_but_other_errors_are_not() {
    let mut replies = board_tables();
    replies.retain(|(dump, _)| *dump != Dump::Nexthops);
    replies.push((Dump::Nexthops, error(libc::EINVAL)));
    let (kernel, _changes) = FakeKernel::new(replies);
    let snapshot = super::current(
        kernel.as_ref(),
        &super::nl80211::NoWireless,
        Path::new("/nonexistent"),
        &NetSettings::default(),
    )
    .unwrap();
    // The IPv6 route through the unknown nexthop names no interface.
    assert_eq!(
        snapshot.interfaces["enP4p65s0"]["default_routes"],
        json!([{"family": "ipv4", "gateway": "192.168.5.1", "metric": 100}])
    );
}

async fn ask(
    commands: &mpsc::Sender<crate::router::PendingCommand>,
    name: &str,
    args: Value,
) -> crate::router::Outcome {
    let (pending, answer) = crate::router::PendingCommand::for_test("net", name, args);
    commands.send(pending).await.unwrap();
    tokio::time::timeout(Duration::from_secs(10), answer)
        .await
        .expect("an answer")
        .expect("answered")
}

fn error_code(outcome: &crate::router::Outcome) -> &str {
    match outcome {
        crate::router::Outcome::Err { code, .. } => code,
        crate::router::Outcome::Ok(value) => panic!("expected an error, got {value}"),
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn sets_removes_and_lists_wifi_networks() {
    let sysfs = board_sysfs();
    let wifi_dir = tempfile::tempdir().unwrap();
    let (kernel, _changes) = FakeKernel::new(board_tables());
    let (mut ctx, mut reports, _requests) = context(sysfs.path());
    let (commands, receiver) = mpsc::channel(4);
    ctx.commands = receiver;
    let cancel = ctx.cancel.clone();
    let module = NetModule::with_kernel(NetSettings::default(), kernel, wifi_dir.path());
    let running = tokio::spawn(async move { module.run(ctx).await });
    let first = next_report(&mut reports).await;
    assert_eq!(first["wifi"], json!({"networks": [], "applied": null}));

    let saved = ask(
        &commands,
        "wifi.set",
        json!({"ssid": "Venue / Media", "passphrase": "correct horse battery", "hidden": true}),
    )
    .await;
    assert_eq!(
        saved,
        crate::router::Outcome::Ok(json!({"network": {
            "ssid": "Venue / Media", "security": "personal", "hidden": true,
        }}))
    );
    let report = next_report(&mut reports).await;
    assert_eq!(
        report["wifi"]["networks"],
        json!([{"ssid": "Venue / Media", "security": "personal", "hidden": true}])
    );
    assert!(
        !report.to_string().contains("horse"),
        "no passphrase in the shadow"
    );
    let stored = std::fs::read_to_string(wifi_dir.path().join("networks.json")).unwrap();
    assert!(stored.contains("correct horse battery"));

    let open = ask(&commands, "wifi.set", json!({"ssid": "Cafe"})).await;
    assert!(matches!(open, crate::router::Outcome::Ok(_)));
    next_report(&mut reports).await;
    let listed = ask(&commands, "wifi.list", json!(null)).await;
    assert_eq!(
        listed,
        crate::router::Outcome::Ok(json!({"networks": [
            {"ssid": "Venue / Media", "security": "personal", "hidden": true},
            {"ssid": "Cafe", "security": "open", "hidden": false},
        ]}))
    );

    for (args, code) in [
        (
            json!({"ssid": "Home", "passphrase": "short"}),
            "INVALID_PASSPHRASE",
        ),
        (
            json!({"ssid": "Home", "passphrase": 12_345_678}),
            "INVALID_PASSPHRASE",
        ),
        (
            json!({"passphrase": "correct horse battery"}),
            "INVALID_SSID",
        ),
        (json!({"ssid": ""}), "INVALID_SSID"),
        (
            json!({"ssid": "Home", "hidden": "yes"}),
            "INVALID_ARGUMENTS",
        ),
        (json!(["Home"]), "INVALID_ARGUMENTS"),
    ] {
        let outcome = ask(&commands, "wifi.set", args.clone()).await;
        assert_eq!(error_code(&outcome), code, "{args}");
    }
    let outcome = ask(&commands, "wifi.remove", json!({})).await;
    assert_eq!(error_code(&outcome), "INVALID_SSID");
    let outcome = ask(&commands, "wifi.scan", json!({})).await;
    assert_eq!(error_code(&outcome), "UNKNOWN_COMMAND");

    let removed = ask(&commands, "wifi.remove", json!({"ssid": "Cafe"})).await;
    assert_eq!(
        removed,
        crate::router::Outcome::Ok(json!({"removed": true}))
    );
    let report = next_report(&mut reports).await;
    assert_eq!(report["wifi"]["networks"].as_array().unwrap().len(), 1);
    let again = ask(&commands, "wifi.remove", json!({"ssid": "Cafe"})).await;
    assert_eq!(again, crate::router::Outcome::Ok(json!({"removed": false})));

    // A store Helios can't read is an internal error, and so reported.
    std::fs::write(wifi_dir.path().join("networks.json"), "{").unwrap();
    for (name, args) in [
        ("wifi.list", json!(null)),
        ("wifi.remove", json!({"ssid": "Cafe"})),
        ("wifi.set", json!({"ssid": "Cafe"})),
    ] {
        let outcome = ask(&commands, name, args).await;
        assert_eq!(error_code(&outcome), "INTERNAL", "{name}");
    }

    drop(commands);
    cancel.cancel();
    assert_eq!(running.await.unwrap(), Ok(()));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn refuses_wifi_without_an_adapter() {
    let sysfs = Sysfs::new();
    let wifi_dir = tempfile::tempdir().unwrap();
    let (kernel, _changes) = FakeKernel::new(board_tables());
    let (mut ctx, mut reports, _requests) = context(sysfs.path());
    let (commands, receiver) = mpsc::channel(1);
    ctx.commands = receiver;
    let cancel = ctx.cancel.clone();
    let module = NetModule::with_kernel(NetSettings::default(), kernel, wifi_dir.path());
    let running = tokio::spawn(async move { module.run(ctx).await });
    next_report(&mut reports).await;
    let outcome = ask(&commands, "wifi.set", json!({"ssid": "Cafe"})).await;
    assert_eq!(error_code(&outcome), "NO_ADAPTER");
    // The module keeps going once nothing can send it commands.
    drop(commands);
    tokio::time::sleep(Duration::from_millis(50)).await;
    cancel.cancel();
    assert_eq!(running.await.unwrap(), Ok(()));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn opens_a_passphrase_sealed_to_the_device() {
    use base64::Engine;
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;

    use crate::identity::secrets::{self, POINT_LEN};
    use crate::identity::testing::{THING_NAME, ca, ready_identity};

    let device_ca = ca("net-test");
    let (identity, _token, identity_cancel) =
        ready_identity(&device_ca, rustls::RootCertStore::empty()).await;
    let public: [u8; POINT_LEN] = match &*identity.watch().borrow() {
        crate::identity::manager::IdentityState::Ready(ready) => URL_SAFE_NO_PAD
            .decode(ready.secrets.as_ref().unwrap().public_base64())
            .unwrap()
            .try_into()
            .unwrap(),
        other => panic!("not ready: {other:?}"),
    };
    let seal = |ssid: &str, passphrase: &str| {
        let ephemeral = p256::SecretKey::from_slice(&[0x33; 32]).unwrap();
        let (enc, ct) = secrets::seal(
            &public,
            &ephemeral,
            &secrets::info(THING_NAME),
            format!("wifi.passphrase {ssid}").as_bytes(),
            passphrase.as_bytes(),
        );
        json!({"sealed": {"enc": URL_SAFE_NO_PAD.encode(enc), "ct": URL_SAFE_NO_PAD.encode(ct)}})
    };

    let sysfs = board_sysfs();
    let wifi_dir = tempfile::tempdir().unwrap();
    let (kernel, _changes) = FakeKernel::new(board_tables());
    let (mut ctx, mut reports, _requests) = context(sysfs.path());
    let (commands, receiver) = mpsc::channel(4);
    ctx.commands = receiver;
    let cancel = ctx.cancel.clone();
    let module = NetModule::with_kernel(NetSettings::default(), kernel, wifi_dir.path())
        .with_identity(identity.watch());
    let running = tokio::spawn(async move { module.run(ctx).await });
    next_report(&mut reports).await;

    let saved = ask(
        &commands,
        "wifi.set",
        json!({"ssid": "Home", "passphrase": seal("Home", "correct horse battery")}),
    )
    .await;
    assert!(matches!(saved, crate::router::Outcome::Ok(_)), "{saved:?}");
    let stored = std::fs::read_to_string(wifi_dir.path().join("networks.json")).unwrap();
    assert!(stored.contains("correct horse battery"), "opened and saved");

    for (passphrase, code) in [
        (seal("Cafe", "correct horse battery"), "SECRET_UNREADABLE"),
        (
            json!({"sealed": {"enc": "AAAA", "ct": "AAAA"}}),
            "SECRET_UNREADABLE",
        ),
        (json!({"sealed": {"enc": "AAAA"}}), "SECRET_UNREADABLE"),
        (json!({"sealed": "AAAA"}), "INVALID_PASSPHRASE"),
        (json!({"other": {}}), "INVALID_PASSPHRASE"),
        (seal("Home", "short"), "INVALID_PASSPHRASE"),
    ] {
        let outcome = ask(
            &commands,
            "wifi.set",
            json!({"ssid": "Home", "passphrase": passphrase}),
        )
        .await;
        assert_eq!(error_code(&outcome), code, "{passphrase}");
    }

    drop(commands);
    cancel.cancel();
    identity_cancel.cancel();
    assert_eq!(running.await.unwrap(), Ok(()));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_sealed_passphrase_needs_a_ready_identity() {
    let sysfs = board_sysfs();
    let wifi_dir = tempfile::tempdir().unwrap();
    let (kernel, _changes) = FakeKernel::new(board_tables());
    let (mut ctx, mut reports, _requests) = context(sysfs.path());
    let (commands, receiver) = mpsc::channel(1);
    ctx.commands = receiver;
    let cancel = ctx.cancel.clone();
    let (_state, watch) =
        tokio::sync::watch::channel(crate::identity::manager::IdentityState::Starting);
    let module = NetModule::with_kernel(NetSettings::default(), kernel, wifi_dir.path())
        .with_identity(watch);
    let running = tokio::spawn(async move { module.run(ctx).await });
    next_report(&mut reports).await;
    let outcome = ask(
        &commands,
        "wifi.set",
        json!({"ssid": "Home", "passphrase": {"sealed": {"enc": "AAAA", "ct": "AAAA"}}}),
    )
    .await;
    assert_eq!(error_code(&outcome), "SECRET_UNREADABLE");
    drop(commands);
    cancel.cancel();
    assert_eq!(running.await.unwrap(), Ok(()));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn answers_commands_as_the_custom_topics_decode_them() {
    use crate::router::CommandTransport;
    use crate::router::topics::TopicsTransport;

    let sysfs = board_sysfs();
    let wifi_dir = tempfile::tempdir().unwrap();
    let (kernel, _changes) = FakeKernel::new(board_tables());
    let (mut ctx, mut reports, _requests) = context(sysfs.path());
    let (commands, receiver) = mpsc::channel(4);
    ctx.commands = receiver;
    let cancel = ctx.cancel.clone();
    let module = NetModule::with_kernel(NetSettings::default(), kernel, wifi_dir.path());
    let running = tokio::spawn(async move { module.run(ctx).await });
    next_report(&mut reports).await;

    let envelope = json!({
        "v": 1, "id": "c1", "correlation_id": null, "ts": "2026-11-22T20:00:00.000Z",
        "thing": "t-1", "module": "net", "type": "net.wifi.set",
        "payload": {"ssid": "Cafe"},
    });
    let command = TopicsTransport
        .decode("t-1", "helios/t-1/cmd/net", envelope.to_string().as_bytes())
        .unwrap()
        .unwrap();
    assert_eq!(
        (command.module.as_str(), command.name.as_str()),
        ("net", "wifi.set")
    );
    let outcome = ask(&commands, &command.name, command.args).await;
    assert!(
        matches!(outcome, crate::router::Outcome::Ok(_)),
        "{outcome:?}"
    );

    drop(commands);
    cancel.cancel();
    assert_eq!(running.await.unwrap(), Ok(()));
}

/// Wi-Fi state a test sets.
struct FakeWireless(Mutex<Option<io::Result<Option<super::nl80211::WifiLink>>>>);

impl super::nl80211::Wireless for FakeWireless {
    fn link(&self, index: u32) -> io::Result<Option<super::nl80211::WifiLink>> {
        assert_eq!(index, 4, "only the Wi-Fi interface is asked");
        match self.0.lock().unwrap().take() {
            Some(answer) => answer,
            None => Ok(None),
        }
    }
}

fn joined(signal: i32) -> super::nl80211::WifiLink {
    super::nl80211::WifiLink {
        ssid: "Home".into(),
        bssid: Some([0x8a, 0x78, 0x48, 0xfe, 0x86, 0x5a]),
        frequency_mhz: Some(5240),
        signal_dbm: Some(signal),
    }
}

#[test]
fn reports_what_the_wifi_interface_is_joined_to() {
    let sysfs = board_sysfs();
    let (kernel, _changes) = FakeKernel::new(board_tables());
    let tables = super::netlink::read(kernel.as_ref()).unwrap();
    let wireless = FakeWireless(Mutex::new(Some(Ok(Some(joined(-47))))));
    let snapshot =
        super::snapshot::build_with(&tables, sysfs.path(), &NetSettings::default(), &wireless);
    assert_eq!(
        snapshot.interfaces["wlP2p33s0"]["wifi"],
        json!({"ssid": "Home", "bssid": "8a:78:48:fe:86:5a", "frequency_mhz": 5240, "signal_dbm": -47})
    );
    assert!(
        snapshot.interfaces["enP4p65s0"].get("wifi").is_none(),
        "only Wi-Fi interfaces"
    );
    // Not joined, or nl80211 failing: null.
    for answer in [Ok(None), Err(io::Error::other("no nl80211"))] {
        let wireless = FakeWireless(Mutex::new(Some(answer)));
        let snapshot =
            super::snapshot::build_with(&tables, sysfs.path(), &NetSettings::default(), &wireless);
        assert_eq!(snapshot.interfaces["wlP2p33s0"]["wifi"], Value::Null);
    }
}

#[test]
fn the_signal_moves_in_steps() {
    let mut reporter = Reporter::default();
    let now = SystemTime::now();
    let report = |reporter: &mut Reporter, signal: i64, bssid: &str| {
        let interfaces = json!({"wlan0": {"oper_state": "up", "wifi": {
            "ssid": "Home", "bssid": bssid, "signal_dbm": signal,
        }}});
        reporter
            .update(snapshot(interfaces, false), json!({}), now)
            .map(|(reported, _)| reported["interfaces"]["wlan0"]["wifi"]["signal_dbm"].clone())
    };
    let ap = "8a:78:48:fe:86:5a";
    assert_eq!(
        report(&mut reporter, -47, ap),
        Some(json!(-45)),
        "nearest step"
    );
    for jitter in [-44, -46, -49, -41] {
        assert_eq!(
            report(&mut reporter, jitter, ap),
            None,
            "{jitter} isn't a step away"
        );
    }
    assert_eq!(
        report(&mut reporter, -50, ap),
        Some(json!(-50)),
        "a whole step"
    );
    assert_eq!(report(&mut reporter, -48, ap), None);
    assert_eq!(report(&mut reporter, -63, ap), Some(json!(-65)));
    // Another access point starts afresh.
    assert_eq!(
        report(&mut reporter, -62, "02:00:00:00:00:01"),
        Some(json!(-60))
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_module_reports_the_joined_network() {
    let sysfs = board_sysfs();
    let wifi_dir = tempfile::tempdir().unwrap();
    let (kernel, _changes) = FakeKernel::new(board_tables());
    let (ctx, mut reports, _requests) = context(sysfs.path());
    let cancel = ctx.cancel.clone();
    let module = NetModule::with_kernel(NetSettings::default(), kernel, wifi_dir.path())
        .with_wireless(Arc::new(FakeWireless(Mutex::new(Some(Ok(Some(joined(
            -71,
        ))))))));
    let running = tokio::spawn(async move { module.run(ctx).await });
    let first = next_report(&mut reports).await;
    assert_eq!(first["interfaces"]["wlP2p33s0"]["wifi"]["signal_dbm"], -70);
    assert_eq!(first["interfaces"]["wlP2p33s0"]["wifi"]["ssid"], "Home");
    cancel.cancel();
    assert_eq!(running.await.unwrap(), Ok(()));
}
