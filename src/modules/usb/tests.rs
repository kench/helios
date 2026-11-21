use std::fs;
use std::io;
use std::os::unix::fs::symlink;
use std::path::Path;
use std::sync::Arc;
use std::time::{Duration, SystemTime};

use serde_json::json;
use tokio::sync::mpsc;
use tokio::time::Instant;

use super::mounts;
use super::uevent::{self, Datagram, UeventSource};
use super::{
    Inventory, ModuleContext, State, UsbDevice, UsbEvent, UsbHandle, UsbModule, UsbSettings,
};
use crate::mqtt::{manager::MqttHandle, shadow::ShadowHandle};

fn message(action: &str, path: &str, subsystem: &str, ty: &str) -> Vec<u8> {
    format!("{action}@{path}\0ACTION={action}\0DEVPATH={path}\0SUBSYSTEM={subsystem}\0DEVTYPE={ty}\0SEQNUM=42\0").into_bytes()
}

const ROOT: &str = "/devices/platform/usb1/1-2";

#[test]
fn parses_kernel_actions_and_rejects_bad_packets() {
    for action in ["add", "remove", "change", "move", "bind", "unbind"] {
        let mut input = message(action, ROOT, "usb", "usb_device");
        input.extend_from_slice(b"DEVPATH_OLD=/devices/old\0DEVNAME=bus/usb/001/002\0");
        let event = uevent::parse(&input, 0).expect("kernel event");
        assert_eq!(event.action, action);
        assert_eq!(event.old_path.as_deref(), Some("/devices/old"));
        assert_eq!(event.sequence, Some(42));
        assert!(uevent::parse(&input, 17).is_none());
    }
    for input in [
        &b"broken"[..],
        &b"add@/devices/x\0ACTION=remove\0DEVPATH=/devices/x\0"[..],
        &b"add@/devices/x\0ACTION=add\0DEVPATH=/devices/x\0SEQNUM=oops"[..],
        &b"add@/devices/x\0DEVPATH=/devices/x\0"[..],
        &[0xff],
        &[0; 2049],
    ] {
        assert!(uevent::parse(input, 0).is_none());
    }
}

#[test]
fn mountinfo_decodes_and_keeps_all_mounts_for_a_device() {
    let mounts = mounts::parse(
        "11 10 8:1 / /one\\040two rw - vfat /dev/sda1 rw\n\
        12 10 8:1 /nested /bind\\011\\012\\134 rw - vfat /dev/sda1 rw\n\
        13 10 8:1 / /one\\040two rw - vfat /dev/sda1 rw\ninvalid\n\
        14 10 8:2 / /unknown\\042 rw - vfat /dev/sda2 rw\n",
    );
    assert_eq!(mounts["8:1"], ["/bind\t\n\\", "/one two"]);
    assert_eq!(mounts["8:2"], ["/unknown\\042"]);
}

struct Fixture {
    root: tempfile::TempDir,
}

impl Fixture {
    fn new() -> Self {
        Self {
            root: tempfile::tempdir().expect("fixture directory"),
        }
    }

    fn write(&self, path: &str, text: &str) {
        let path = self.root.path().join(path.trim_start_matches('/'));
        fs::create_dir_all(path.parent().expect("parent")).expect("fixture parent");
        fs::write(path, text).expect("attribute");
    }

    fn link(&self, target: &Path, path: &str) {
        let path = self.root.path().join(path.trim_start_matches('/'));
        fs::create_dir_all(path.parent().expect("parent")).expect("fixture parent");
        symlink(target, path).expect("fixture link");
    }

    fn device(&self, location: &str, class: &str, id: (&str, &str)) {
        self.write(&format!("{location}/idVendor"), id.0);
        self.write(&format!("{location}/idProduct"), id.1);
        self.write(&format!("{location}/bDeviceClass"), class);
        let port = location.rsplit('/').next().expect("port");
        self.link(
            &self.root.path().join(&location[1..]),
            &format!("bus/usb/devices/{port}"),
        );
    }

    fn interface(&self, location: &str, number: &str, class: &str, driver: &str) -> String {
        let port = location.rsplit('/').next().expect("port");
        let name = format!("{port}:1.{number}");
        let path = format!("{location}/{name}");
        self.write(&format!("{path}/bInterfaceClass"), class);
        self.write(&format!("{path}/bInterfaceNumber"), number);
        self.link(
            Path::new(&format!("/drivers/{driver}")),
            &format!("{path}/driver"),
        );
        self.link(
            &self.root.path().join(&path[1..]),
            &format!("bus/usb/devices/{name}"),
        );
        path
    }

    fn node(&self, parent: &str, class: &str, name: &str) -> String {
        let path = format!("{parent}/{class}/{name}");
        self.write(&format!("{path}/uevent"), "");
        self.link(
            &self.root.path().join(&parent[1..]),
            &format!("{path}/device"),
        );
        self.link(
            &self.root.path().join(&path[1..]),
            &format!("class/{class}/{name}"),
        );
        path
    }

    fn scan(&self) -> Vec<UsbDevice> {
        let labels = self.root.path().join("labels");
        let mountinfo = self.root.path().join("mountinfo");
        Inventory {
            sysfs: self.root.path(),
            labels: &labels,
            mountinfo: &mountinfo,
            mp_sd: Path::new("/init/efad/mp_sd"),
        }
        .scan()
    }
}

#[test]
fn classifies_composite_devices_and_keeps_hub_children_separate() {
    let fixture = Fixture::new();
    fixture.device(ROOT, "09", ("1234", "0001"));
    let child = format!("{ROOT}/1-2.1");
    fixture.device(&child, "00", ("1234", "0002"));
    fixture.write(&format!("{child}/serial"), " AB123 \n");
    fixture.write(&format!("{child}/speed"), "480");
    let interface = fixture.interface(&child, "0", "0e", "uvcvideo");
    for (name, index) in [("video4", "0"), ("video5", "1")] {
        let node = fixture.node(&interface, "video4linux", name);
        fixture.write(&format!("{node}/index"), index);
    }
    let interface = fixture.interface(&child, "1", "01", "snd-usb-audio");
    let card = fixture.node(&interface, "sound", "card7");
    fixture.write(&format!("{card}/id"), "Camera");
    fixture.node(&card, "sound", "pcmC7D0c");
    fixture.node(&card, "sound", "pcmC7D0p");
    let devices = fixture.scan();
    assert_eq!(devices.len(), 2);
    assert!(devices[0].hub);
    assert_eq!(devices[0].payload["categories"], json!(["other"]));
    let camera = &devices[1].payload;
    assert_eq!(camera["key"], "1234:0002:AB123");
    assert_eq!(camera["speed_mbps"], 480.0);
    assert_eq!(camera["categories"], json!(["audio", "video"]));
    assert_eq!(camera["nodes"]["video"][1]["index"], 1);
    assert_eq!(
        camera["nodes"]["alsa"][0],
        json!({"card": 7, "id": "Camera", "capture": true, "playback": true})
    );
}

#[test]
fn classifies_network_serial_smartcard_and_storage_devices() {
    let fixture = Fixture::new();
    for (index, class, driver, category) in [
        (0, "ff", "r8152", "ethernet"),
        (1, "ff", "wlan", "wifi"),
        (2, "ff", "qmi_wwan", "cellular"),
        (3, "ff", "garmin_gps", "serial"),
        (4, "02", "cdc_acm", "serial"),
        (5, "ff", "pl2303", "serial"),
        (6, "0b", "ccid", "smartcard"),
        (7, "08", "usb-storage", "storage"),
        (8, "ff", "ftdi_sio", "serial"),
    ] {
        let path = format!("/devices/platform/usb1/1-{index}");
        fixture.device(&path, "00", ("0403", "6015"));
        let interface = fixture.interface(&path, "0", class, driver);
        match category {
            "ethernet" | "wifi" | "cellular" => {
                let net = fixture.node(&interface, "net", &format!("eth{index}"));
                fixture.write(&format!("{net}/type"), "1");
                if category == "wifi" {
                    fixture.link(Path::new("/unused"), &format!("{net}/phy80211"));
                }
                if category == "cellular" {
                    fixture.write(&format!("{net}/uevent"), "DEVTYPE=wwan");
                }
            }
            "serial" => {
                let prefix = if driver == "cdc_acm" {
                    "ttyACM"
                } else {
                    "ttyUSB"
                };
                fixture.node(&interface, "tty", &format!("{prefix}{index}"));
            }
            "storage" => {
                let disk = fixture.node(&interface, "block", "sda");
                let partition = fixture.node(&disk, "block", "sda1");
                fixture.write(&format!("{partition}/dev"), "8:1");
                fixture.write(&format!("{partition}/size"), "100");
                fixture.write(
                    "mountinfo",
                    "2 1 8:1 / /init/efad/mp_sd rw - vfat /dev/sda1 rw",
                );
                fixture.link(Path::new("../../sda1"), "labels/MP_SD");
            }
            _ => {}
        }
        let devices = fixture.scan();
        let device = devices.last().expect("device");
        assert_eq!(device.payload["categories"], json!([category]));
        if category == "serial" {
            assert_eq!(device.payload["nodes"]["tty"][0]["driver"], driver);
        } else if category == "storage" {
            assert_eq!(device.payload["role"], "mp_sd");
            assert_eq!(
                device.payload["nodes"]["block"][1],
                json!({"name": "sda1", "size": 51200, "label": "MP_SD", "mounts": ["/init/efad/mp_sd"]})
            );
            fs::remove_file(fixture.root.path().join("labels/MP_SD")).expect("remove label");
            assert_eq!(
                fixture.scan().last().expect("drive").payload["role"],
                "mp_sd"
            );
        }
    }
}

fn context() -> ModuleContext {
    let (mqtt, _, _) = MqttHandle::for_test();
    let (shadows, _, _) = ShadowHandle::for_test();
    ModuleContext {
        commands: mpsc::channel(1).1,
        desired: mpsc::unbounded_channel().1,
        shadows,
        mqtt,
        sysfs: "/sys".into(),
        cancel: Default::default(),
    }
}

fn device(product: &str) -> UsbDevice {
    UsbDevice {
        port: "1-2".into(),
        devpath: ROOT.into(),
        vid: 1,
        pid: 2,
        hub: false,
        payload: serde_json::from_value(
            json!({"product": product, "categories": ["other"], "nodes": {"video": []}}),
        )
        .expect("record"),
        attached_at: SystemTime::now(),
    }
}

struct FakeSource(mpsc::UnboundedReceiver<io::Result<Datagram>>);

impl UeventSource for FakeSource {
    async fn receive(&mut self) -> io::Result<Datagram> {
        self.0.recv().await.expect("scripted datagram")
    }
}

#[tokio::test(start_paused = true)]
async fn settles_changes_and_keeps_subscribers_through_restart() {
    let handle = UsbHandle::default();
    let mut stream = handle.subscribe();
    let snapshot = handle.snapshot();
    let module = UsbModule::new(
        UsbSettings {
            max_settle_ms: 1000,
            ..UsbSettings::default()
        },
        handle,
    );
    let ctx = context();
    let mut state = State::new(&module);
    let (send, rx) = mpsc::unbounded_channel();
    let mut source = FakeSource(rx);
    state.reconcile(vec![device("original")], false, |_| true, &ctx);
    assert!(stream.try_recv().is_err());
    assert_eq!(snapshot.borrow().len(), 1);
    let start = Instant::now();
    for delay in [0, 400, 400] {
        tokio::time::advance(Duration::from_millis(delay)).await;
        send.send(Ok(Datagram {
            bytes: message("move", &format!("{ROOT}/1-2:1.0/net/eth0"), "net", ""),
            sender: 0,
        }))
        .expect("send");
        let next = super::receive(Some(&mut source)).await.expect("receive");
        state.event(
            uevent::parse(&next.bytes, next.sender).expect("event"),
            &ctx,
        );
    }
    assert_eq!(
        state.settling["1-2"].deadline,
        start + Duration::from_secs(1)
    );
    state.settle(vec![device("changed")], &ctx);
    assert!(stream.try_recv().is_err());
    tokio::time::advance(Duration::from_millis(200)).await;
    state.settle(vec![device("changed")], &ctx);
    assert!(matches!(stream.try_recv(), Ok(UsbEvent::Changed(_))));
    let attached_at = snapshot.borrow()["1-2"].attached_at;
    let mut state = State::new(&module);
    state.resync(vec![device("changed")], &ctx);
    assert!(stream.try_recv().is_err());
    assert_eq!(snapshot.borrow()["1-2"].attached_at, attached_at);
    state.event(
        uevent::parse(&message("remove", ROOT, "usb", "usb_device"), 0).expect("remove"),
        &ctx,
    );
    assert!(matches!(stream.try_recv(), Ok(UsbEvent::Detached(_))));
    assert!(snapshot.borrow().is_empty());
}

#[tokio::test(start_paused = true)]
async fn short_lived_and_flapping_devices_are_suppressed() {
    let handle = UsbHandle::default();
    let mut stream = handle.subscribe();
    let module = UsbModule::new(
        UsbSettings {
            max_events_per_port: 1,
            ..UsbSettings::default()
        },
        handle,
    );
    let ctx = context();
    let mut state = State::new(&module);
    let event =
        |action| uevent::parse(&message(action, ROOT, "usb", "usb_device"), 0).expect("event");
    state.event(event("add"), &ctx);
    state.event(event("remove"), &ctx);
    assert!(state.settling.is_empty());
    assert!(stream.try_recv().is_err());
    state.resync(vec![device("first")], &ctx);
    assert!(matches!(stream.try_recv(), Ok(UsbEvent::Attached(_))));
    state.resync(Vec::new(), &ctx);
    assert!(matches!(stream.try_recv(), Ok(UsbEvent::Detached(_))));
    state.resync(vec![device("second")], &ctx);
    assert!(stream.try_recv().is_err());
    assert_eq!(state.shadow(Some("denied"))["flapping"], json!(["1-2"]));
    assert_eq!(
        state.shadow(Some("denied"))["error"]["code"],
        "MONITOR_FAILED"
    );
    assert_eq!(state.shadow(None)["counts"]["other"], 1);
    assert_eq!(state.shadow(None)["devices"][0]["nodes"], json!({}));
    assert!(matches!(
        state.command("status"),
        crate::router::Outcome::Ok(_)
    ));
    assert!(!matches!(
        state.command("bad"),
        crate::router::Outcome::Ok(_)
    ));
    assert!(Arc::strong_count(&state.devices["1-2"]) >= 2);
}

#[test]
fn validates_configuration_and_filters_devices() {
    for config in [
        "settle_ms = 49",
        "max_settle_ms = 499",
        "max_events_per_port = 0",
    ] {
        assert!(
            toml::from_str::<UsbSettings>(config)
                .expect("config")
                .check()
                .is_err()
        );
    }
    assert!(
        toml::from_str::<UsbSettings>("enabled = false")
            .expect("config")
            .check()
            .expect("valid")
            .is_none()
    );
    let mut record = device("hub");
    record.hub = true;
    let settings = UsbSettings::default();
    assert!(!settings.reports(&record));
    let settings = UsbSettings {
        hubs: true,
        ignore: vec!["0001:0002".into()],
        ..settings
    };
    assert!(!settings.reports(&record));
}

#[tokio::test]
async fn module_reports_initial_inventory_and_stops_on_cancellation() {
    use crate::modules::Module;
    let fixture = Fixture::new();
    fixture.device(ROOT, "00", ("0403", "6015"));
    let handle = UsbHandle::default();
    let mut snapshot = handle.snapshot();
    let mut stream = handle.subscribe();
    let module = UsbModule::new(UsbSettings::default(), handle);
    let mut ctx = context();
    ctx.sysfs = fixture.root.path().to_owned();
    let cancel = ctx.cancel.clone();
    let run = tokio::spawn(async move { module.run(ctx).await });
    tokio::time::timeout(Duration::from_secs(2), snapshot.changed())
        .await
        .expect("initial scan completed")
        .expect("snapshot");
    assert_eq!(snapshot.borrow()["1-2"].vid, 0x0403);
    assert!(stream.try_recv().is_err());
    cancel.cancel();
    run.await.expect("task").expect("cancelled cleanly");
}

/// The whole run loop, with a scripted event source, real command and shadow channels and
/// Tokio's paused clock.
struct Running {
    fixture: Fixture,
    datagrams: mpsc::UnboundedSender<io::Result<Datagram>>,
    commands: mpsc::Sender<crate::router::PendingCommand>,
    published: mpsc::UnboundedReceiver<crate::mqtt::manager::Request>,
    reports: crate::mqtt::shadow::TestReports,
    stream: tokio::sync::broadcast::Receiver<UsbEvent>,
    cancel: tokio_util::sync::CancellationToken,
    task: tokio::task::JoinHandle<Result<(), crate::modules::ModuleError>>,
}

const WAIT: Duration = Duration::from_secs(120);

/// Starts the module on `fixture`. Each open of the uevent source takes the next result from
/// `opens`: `true` for a working source, `false` for an error.
fn running(fixture: Fixture, opens: &[bool]) -> Running {
    let (datagrams, received) = mpsc::unbounded_channel();
    let mut received = Some(received);
    let mut scripted = std::collections::VecDeque::new();
    for &works in opens {
        scripted.push_back(if works {
            Ok(FakeSource(received.take().expect("one working source")))
        } else {
            Err(io::Error::from_raw_os_error(libc::EACCES))
        });
    }
    let scripted = std::sync::Mutex::new(scripted);
    let open = move || {
        scripted
            .lock()
            .expect("script")
            .pop_front()
            .unwrap_or_else(|| Err(io::Error::from_raw_os_error(libc::EACCES)))
    };
    let (mqtt, published, _status) = MqttHandle::for_test();
    let (shadows, reports, _desired) = ShadowHandle::for_test();
    let (commands, commands_rx) = mpsc::channel(4);
    let cancel = tokio_util::sync::CancellationToken::new();
    let ctx = ModuleContext {
        commands: commands_rx,
        desired: mpsc::unbounded_channel().1,
        shadows,
        mqtt,
        sysfs: fixture.root.path().to_owned(),
        cancel: cancel.clone(),
    };
    let handle = UsbHandle::default();
    let stream = handle.subscribe();
    let module = UsbModule::new(UsbSettings::default(), handle);
    let labels = fixture.root.path().join("labels");
    let mountinfo = fixture.root.path().join("mountinfo");
    let task = tokio::spawn(async move { module.monitor(ctx, open, &labels, &mountinfo).await });
    Running {
        fixture,
        datagrams,
        commands,
        published,
        reports,
        stream,
        cancel,
        task,
    }
}

impl Running {
    fn send(&self, action: &str, path: &str, sequence: u64) {
        let bytes = format!(
            "{action}@{path}\0ACTION={action}\0DEVPATH={path}\0SUBSYSTEM=usb\0DEVTYPE=usb_device\0SEQNUM={sequence}\0"
        )
        .into_bytes();
        self.datagrams
            .send(Ok(Datagram { bytes, sender: 0 }))
            .expect("module running");
    }

    /// The next event for `port` from the internal channel, skipping others.
    async fn next_for(&mut self, port: &str) -> UsbEvent {
        loop {
            let event = tokio::time::timeout(WAIT, self.stream.recv())
                .await
                .expect("an event in time")
                .expect("the channel open");
            let device = match &event {
                UsbEvent::Attached(device)
                | UsbEvent::Changed(device)
                | UsbEvent::Detached(device) => device,
            };
            if device.port == port {
                return event;
            }
        }
    }

    /// The next `usb` shadow report satisfying `check`.
    async fn report_where(
        &mut self,
        check: impl Fn(&serde_json::Map<String, serde_json::Value>) -> bool,
    ) {
        loop {
            let (shadow, reported) = tokio::time::timeout(WAIT, self.reports.recv())
                .await
                .expect("a report in time")
                .expect("the channel open");
            if shadow == "usb" && check(&reported) {
                return;
            }
        }
    }

    async fn command(&self, name: &str) -> crate::router::Outcome {
        let (pending, answer) = crate::router::PendingCommand::for_test("usb", name, json!({}));
        self.commands.send(pending).await.expect("module running");
        tokio::time::timeout(WAIT, answer)
            .await
            .expect("an answer in time")
            .expect("answered")
    }

    async fn stop(self) {
        self.cancel.cancel();
        tokio::time::timeout(WAIT, self.task)
            .await
            .expect("stopped in time")
            .expect("task")
            .expect("stopped cleanly");
    }
}

const SECOND: &str = "/devices/platform/usb1/1-3";

#[tokio::test(start_paused = true)]
async fn announces_a_new_device_once_it_settles_and_publishes_the_event() {
    let fixture = Fixture::new();
    fixture.device(ROOT, "00", ("0403", "6015"));
    let mut running = running(fixture, &[true]);
    running
        .report_where(|reported| reported["devices"].as_array().is_some_and(|d| d.len() == 1))
        .await;

    running.fixture.device(SECOND, "00", ("0bda", "8153"));
    running.send("add", SECOND, 1);
    assert!(matches!(
        running.next_for("1-3").await,
        UsbEvent::Attached(_)
    ));

    let mut published = Vec::new();
    while let Ok(request) = running.published.try_recv() {
        published.push(format!("{request:?}"));
    }
    assert!(
        published
            .iter()
            .any(|request| request.contains("usb.attached") && request.contains("8153")),
        "{published:?}"
    );
    running.stop().await;
}

#[tokio::test(start_paused = true)]
async fn answers_status_and_refuses_unknown_commands() {
    let fixture = Fixture::new();
    fixture.device(ROOT, "00", ("0403", "6015"));
    let running = running(fixture, &[true]);

    match running.command("status").await {
        crate::router::Outcome::Ok(result) => {
            assert_eq!(result["devices"][0]["port"], "1-2");
            assert_eq!(result["devices"][0]["vid"], "0403");
        }
        other => panic!("{other:?}"),
    }
    assert!(!matches!(
        running.command("reboot").await,
        crate::router::Outcome::Ok(_)
    ));
    running.stop().await;
}

#[tokio::test(start_paused = true)]
async fn a_sequence_gap_rescans_and_reports_what_changed() {
    let fixture = Fixture::new();
    fixture.device(ROOT, "00", ("0403", "6015"));
    let mut running = running(fixture, &[true]);
    running.send("change", ROOT, 10);
    running
        .report_where(|reported| reported["devices"].as_array().is_some_and(|d| d.len() == 1))
        .await;

    // The device's remove event is lost: the next event's number shows the gap.
    fs::remove_file(running.fixture.root.path().join("bus/usb/devices/1-2")).expect("unplug");
    running.send("change", SECOND, 12);

    assert!(matches!(
        running.next_for("1-2").await,
        UsbEvent::Detached(_)
    ));
    running.stop().await;
}

#[tokio::test(start_paused = true)]
async fn a_receive_overflow_rescans() {
    let fixture = Fixture::new();
    fixture.device(ROOT, "00", ("0403", "6015"));
    let mut running = running(fixture, &[true]);
    running
        .report_where(|reported| reported["devices"].as_array().is_some_and(|d| d.len() == 1))
        .await;

    running.fixture.device(SECOND, "00", ("0bda", "8153"));
    running
        .datagrams
        .send(Err(io::Error::from_raw_os_error(libc::ENOBUFS)))
        .expect("module running");

    assert!(matches!(
        running.next_for("1-3").await,
        UsbEvent::Attached(_)
    ));
    running.stop().await;
}

#[tokio::test(start_paused = true)]
async fn reports_a_monitor_failure_and_recovers_when_the_socket_opens() {
    let fixture = Fixture::new();
    fixture.device(ROOT, "00", ("0403", "6015"));
    // The first open fails; the retry a second later works.
    let mut running = running(fixture, &[false, true]);

    running
        .report_where(|reported| reported["error"]["code"] == "MONITOR_FAILED")
        .await;
    // While failing, the 30 s rescan still finds new devices.
    running.fixture.device(SECOND, "00", ("0bda", "8153"));
    running
        .report_where(|reported| reported["error"].is_null())
        .await;
    assert!(matches!(
        running.next_for("1-3").await,
        UsbEvent::Attached(_)
    ));
    running.stop().await;
}

#[tokio::test(start_paused = true)]
async fn a_receive_error_closes_the_socket_and_retries() {
    let fixture = Fixture::new();
    fixture.device(ROOT, "00", ("0403", "6015"));
    let mut running = running(fixture, &[true]);
    running
        .report_where(|reported| reported["devices"].as_array().is_some_and(|d| d.len() == 1))
        .await;

    running
        .datagrams
        .send(Err(io::Error::from_raw_os_error(libc::EIO)))
        .expect("module running");

    running
        .report_where(|reported| reported["error"]["code"] == "MONITOR_FAILED")
        .await;
    running.stop().await;
}

#[tokio::test]
async fn opens_the_kernel_uevent_socket_and_the_mount_watcher() {
    // Unprivileged on Linux; a sandbox without netlink is the only reason this can fail.
    match uevent::Socket::open() {
        Ok(_) => {}
        Err(error)
            if matches!(
                error.raw_os_error(),
                Some(libc::EPERM | libc::EACCES | libc::EPROTONOSUPPORT)
            ) =>
        {
            eprintln!("no uevent netlink here: {error}");
        }
        Err(error) => panic!("{error}"),
    }
    mounts::Watcher::open(Path::new("/proc/self/mountinfo")).expect("mountinfo watcher");
}
