//! USB device inventory, kernel event monitoring and reporting.

mod classify;
mod handle;
mod mounts;
pub(crate) mod sysfs;
pub(crate) mod uevent;

use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::future::pending;
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::Ordering;
use std::time::{Duration, SystemTime};

use serde::Deserialize;
use serde_json::{Map, Value, json};
use tokio::time::Instant;

use crate::router::{Outcome, codes};

use super::{Module, ModuleContext, ModuleFuture};
pub use handle::{UsbEvent, UsbHandle, UsbSnapshot};
use sysfs::Inventory;
use uevent::{Socket, Uevent, UeventSource};

const MODULE: &str = "usb";
const MOUNTINFO: &str = "/proc/self/mountinfo";
/// udev's filesystem label links, where udevd runs.
const LABELS: &str = "/dev/disk/by-label";

/// One USB device as reported by Helios.
#[derive(Debug)]
pub struct UsbDevice {
    /// Physical port identifier.
    pub port: String,
    /// Kernel device path.
    pub devpath: String,
    /// USB vendor identifier.
    pub vid: u16,
    /// USB product identifier.
    pub pid: u16,
    /// Whether this device is a hub.
    pub hub: bool,
    /// Full device record shared by the command and events.
    pub payload: Map<String, Value>,
    /// When this attachment was first observed.
    pub attached_at: SystemTime,
}

/// Settings for the USB monitor.
#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub struct UsbSettings {
    pub(crate) enabled: bool,
    settle_ms: u64,
    max_settle_ms: u64,
    pub(crate) hubs: bool,
    ignore: Vec<String>,
    max_events_per_port: usize,
    mp_sd_mount: PathBuf,
}

impl Default for UsbSettings {
    fn default() -> Self {
        Self {
            enabled: true,
            settle_ms: 500,
            max_settle_ms: 10_000,
            hubs: false,
            ignore: Vec::new(),
            max_events_per_port: 20,
            mp_sd_mount: "/init/efad/mp_sd".into(),
        }
    }
}

impl UsbSettings {
    pub(crate) fn check(self) -> Result<Option<Self>, String> {
        if !(50..=5000).contains(&self.settle_ms) {
            return Err("modules.usb.settle_ms must be 50 to 5000".into());
        }
        if !(self.settle_ms..=60_000).contains(&self.max_settle_ms) {
            return Err("modules.usb.max_settle_ms must be settle_ms to 60000".into());
        }
        if self.max_events_per_port == 0 {
            return Err("modules.usb.max_events_per_port must be positive".into());
        }
        Ok(self.enabled.then_some(self))
    }

    fn reports(&self, device: &UsbDevice) -> bool {
        (self.hubs || !device.hub)
            && !self.ignore.iter().any(|entry| {
                entry == &device.port
                    || entry.eq_ignore_ascii_case(&format!("{:04x}:{:04x}", device.vid, device.pid))
            })
    }
}

pub(crate) fn is_port(port: &str) -> bool {
    let digits = |segment: &str| !segment.is_empty() && segment.bytes().all(|b| b.is_ascii_digit());
    port.split_once('-')
        .is_some_and(|(bus, chain)| digits(bus) && chain.split('.').all(digits))
}

fn port_for_path(path: &str) -> Option<&str> {
    path.rsplit('/').find(|segment| is_port(segment))
}

/// Supervised USB monitoring.
pub struct UsbModule {
    settings: UsbSettings,
    handle: UsbHandle,
}

impl UsbModule {
    /// Build the monitor with a service-owned handle.
    pub fn new(settings: UsbSettings, handle: UsbHandle) -> Self {
        Self { settings, handle }
    }
}

impl Module for UsbModule {
    fn name(&self) -> &'static str {
        MODULE
    }

    fn run(&self, ctx: ModuleContext) -> ModuleFuture<'_> {
        Box::pin(self.monitor(
            ctx,
            Socket::open,
            std::path::Path::new(LABELS),
            std::path::Path::new(MOUNTINFO),
        ))
    }
}

impl UsbModule {
    /// The module's run, with the uevent source and the label and mount paths given, so tests
    /// can drive it.
    async fn monitor<S, F>(
        &self,
        mut ctx: ModuleContext,
        open: F,
        labels: &std::path::Path,
        mountinfo: &std::path::Path,
    ) -> Result<(), super::ModuleError>
    where
        S: UeventSource + Send,
        F: Fn() -> std::io::Result<S> + Send,
    {
        let sysfs = ctx.sysfs.clone();
        let inventory = Inventory {
            sysfs: &sysfs,
            labels,
            mountinfo,
            mp_sd: &self.settings.mp_sd_mount,
        };
        let mut socket = open();
        let mount_watcher = mounts::Watcher::open(inventory.mountinfo).ok();
        let mut state = State::new(self);
        let emit = self.handle.initialized.swap(true, Ordering::Relaxed);
        let mut error = socket.as_ref().err().map(ToString::to_string);
        let mut reporter = Reporter::default();
        state.reconcile(inventory.scan(), emit, |_| true, &ctx);
        reporter.report(&state, error.as_deref(), &ctx);
        let mut sequence = None;
        let mut retry_delay = Duration::from_secs(1);
        let mut retry_at = Instant::now() + retry_delay;
        let mut rescan_at = Instant::now() + Duration::from_secs(30);
        let mut commands_open = true;
        let mut mount_watcher = mount_watcher;
        loop {
            let settle_at = state.settling.values().map(|settle| settle.deadline).min();
            let quiet_at = state.flapping.values().copied().min();
            tokio::select! {
                () = ctx.cancel.cancelled() => break,
                command = ctx.commands.recv(), if commands_open => match command {
                    Some(command) => {
                        let outcome = state.command(&command.command.name);
                        command.respond(outcome);
                    }
                    None => commands_open = false,
                },
                result = receive(socket.as_mut().ok()) => {
                    match result {
                        Ok(message) => if let Some(event) = uevent::parse(&message.bytes, message.sender) {
                            let gap = sequence.zip(event.sequence).is_some_and(|(previous, current): (u64, u64)| previous.checked_add(1) != Some(current));
                            sequence = event.sequence.or(sequence);
                            if gap {
                                tracing::warn!("USB uevent sequence gap");
                                state.resync(inventory.scan(), &ctx);
                            } else {
                                state.event(event, &ctx);
                            }
                        } else {
                            tracing::debug!("discarded malformed or non-kernel USB uevent");
                        },
                        Err(e) if e.raw_os_error() == Some(libc::ENOBUFS) => {
                            tracing::warn!("USB uevent receive buffer overflowed");
                            state.resync(inventory.scan(), &ctx);
                            sequence = None;
                        }
                        Err(e) => {
                            error = Some(e.to_string());
                            socket = Err(e);
                            sequence = None;
                            retry_at = Instant::now() + retry_delay;
                        }
                    }
                }
                result = mount_changed(mount_watcher.as_ref()) => {
                    if result.is_ok() {
                        let ports: BTreeSet<_> = state.devices.keys()
                            .filter(|port| !state.settling.contains_key(*port))
                            .cloned().collect();
                        let records = inventory.scan();
                        // Mount changes do not announce or remove USB devices.
                        let present: BTreeSet<_> =
                            records.iter().map(|device| device.port.clone()).collect();
                        state.reconcile(records, true, |port| {
                            present.contains(port) && ports.contains(port)
                        }, &ctx);
                    } else {
                        mount_watcher = None;
                    }
                }
                () = sleep_until(settle_at) => {
                    state.settle(inventory.scan(), &ctx);
                }
                () = sleep_until(quiet_at) => {
                    state.flapping.retain(|_, until| *until > Instant::now());
                }
                () = tokio::time::sleep_until(retry_at), if socket.is_err() => {
                    socket = open();
                    error = socket.as_ref().err().map(ToString::to_string);
                    if socket.is_ok() {
                        retry_delay = Duration::from_secs(1);
                        state.resync(inventory.scan(), &ctx);
                    } else {
                        retry_delay = (retry_delay * 2).min(Duration::from_secs(300));
                        retry_at = Instant::now() + retry_delay;
                    }
                }
                () = tokio::time::sleep_until(rescan_at), if socket.is_err() => {
                    state.resync(inventory.scan(), &ctx);
                    rescan_at = Instant::now() + Duration::from_secs(30);
                }
            }
            reporter.report(&state, error.as_deref(), &ctx);
        }
        Ok(())
    }
}

async fn receive(source: Option<&mut impl UeventSource>) -> std::io::Result<uevent::Datagram> {
    match source {
        Some(source) => source.receive().await,
        None => pending().await,
    }
}

async fn mount_changed(watcher: Option<&mounts::Watcher>) -> std::io::Result<()> {
    match watcher {
        Some(watcher) => watcher.changed().await,
        None => pending().await,
    }
}

async fn sleep_until(at: Option<Instant>) {
    match at {
        Some(at) => tokio::time::sleep_until(at).await,
        None => pending().await,
    }
}

struct Settle {
    started: Instant,
    deadline: Instant,
}

struct State<'a> {
    module: &'a UsbModule,
    devices: UsbSnapshot,
    settling: BTreeMap<String, Settle>,
    attachments: BTreeMap<String, VecDeque<Instant>>,
    flapping: BTreeMap<String, Instant>,
}

impl<'a> State<'a> {
    fn new(module: &'a UsbModule) -> Self {
        let devices = module.handle.devices.borrow().as_ref().clone();
        Self {
            module,
            devices,
            settling: BTreeMap::new(),
            attachments: BTreeMap::new(),
            flapping: BTreeMap::new(),
        }
    }

    fn event(&mut self, event: Uevent, ctx: &ModuleContext) {
        if !matches!(
            event.action.as_str(),
            "add" | "remove" | "change" | "move" | "bind" | "unbind"
        ) || !matches!(
            event.subsystem.as_str(),
            "usb" | "net" | "video4linux" | "sound" | "tty" | "block"
        ) {
            return;
        }
        let root_remove = event.subsystem == "usb"
            && event.device_type == "usb_device"
            && event.action == "remove";
        if root_remove && let Some(port) = port_for_path(&event.path) {
            let settling = self.settling.remove(port);
            if let Some(device) = self.devices.remove(port) {
                self.snapshot();
                self.emit(UsbEvent::Detached(device), ctx);
            } else if settling.is_some() {
                tracing::debug!(port, "short-lived USB device");
            }
            return;
        }
        for path in std::iter::once(event.path.as_str()).chain(event.old_path.as_deref()) {
            if let Some(port) = port_for_path(path) {
                let now = Instant::now();
                let settle = self.settling.entry(port.into()).or_insert(Settle {
                    started: now,
                    deadline: now,
                });
                settle.deadline = (now + Duration::from_millis(self.module.settings.settle_ms))
                    .min(
                        settle.started + Duration::from_millis(self.module.settings.max_settle_ms),
                    );
            }
        }
    }

    fn settle(&mut self, inventory: Vec<UsbDevice>, ctx: &ModuleContext) {
        let now = Instant::now();
        let due: BTreeSet<_> = self
            .settling
            .iter()
            .filter(|(_, settle)| settle.deadline <= now)
            .map(|(port, _)| port.clone())
            .collect();
        self.settling.retain(|port, _| !due.contains(port));
        self.reconcile(inventory, true, |port| due.contains(port), ctx);
    }

    fn resync(&mut self, inventory: Vec<UsbDevice>, ctx: &ModuleContext) {
        self.settling.clear();
        self.reconcile(inventory, true, |_| true, ctx);
    }

    fn reconcile(
        &mut self,
        inventory: Vec<UsbDevice>,
        emit: bool,
        refresh: impl Fn(&str) -> bool,
        ctx: &ModuleContext,
    ) {
        let mut previous = std::mem::take(&mut self.devices);
        let mut events = Vec::new();
        for mut device in inventory
            .into_iter()
            .filter(|device| self.module.settings.reports(device))
        {
            let port = device.port.clone();
            if !refresh(&port) {
                continue;
            }
            let old = previous.remove(&port);
            if let Some(old) = &old {
                device.attached_at = old.attached_at;
            }
            let device = Arc::new(device);
            match old {
                None => events.push(UsbEvent::Attached(device.clone())),
                Some(old) if old.payload != device.payload => {
                    events.push(UsbEvent::Changed(device.clone()))
                }
                _ => {}
            }
            self.devices.insert(port, device);
        }
        for (port, device) in previous {
            if !refresh(&port) {
                self.devices.insert(port, device);
            } else {
                events.push(UsbEvent::Detached(device));
            }
        }
        if !events.is_empty() || !emit {
            self.snapshot();
        }
        if emit {
            for event in events {
                self.emit(event, ctx);
            }
        }
    }

    fn snapshot(&self) {
        self.module
            .handle
            .devices
            .send_replace(Arc::new(self.devices.clone()));
    }

    fn emit(&mut self, event: UsbEvent, ctx: &ModuleContext) {
        let (device, kind) = match &event {
            UsbEvent::Attached(device) => (device, "usb.attached"),
            UsbEvent::Changed(device) => (device, "usb.changed"),
            UsbEvent::Detached(device) => (device, "usb.detached"),
        };
        let now = Instant::now();
        let minute = Duration::from_secs(60);
        self.attachments.retain(|_, times| {
            times.retain(|at| now.duration_since(*at) < minute);
            !times.is_empty()
        });
        let mut suppressed = self.flapping.contains_key(&device.port);
        if matches!(&event, UsbEvent::Attached(_)) && !suppressed {
            let times = self.attachments.entry(device.port.clone()).or_default();
            times.push_back(now);
            suppressed = times.len() > self.module.settings.max_events_per_port;
        }
        if suppressed {
            self.flapping.insert(device.port.clone(), now + minute);
            return;
        }
        let mut payload = device.payload.clone();
        if kind == "usb.detached" {
            payload.insert(
                "attached_s".into(),
                json!(device.attached_at.elapsed().unwrap_or_default().as_secs()),
            );
        }
        ctx.mqtt.publish_event(MODULE, kind, Value::Object(payload));
        let _ = self.module.handle.events.send(event);
    }

    fn command(&self, name: &str) -> Outcome {
        if name == "status" {
            Outcome::Ok(
                json!({"devices": self.devices.values().map(|device| &device.payload).collect::<Vec<_>>()}),
            )
        } else {
            Outcome::error(
                codes::UNKNOWN_COMMAND,
                format!("unknown USB command {name}"),
            )
        }
    }

    fn shadow(&self, error: Option<&str>) -> Map<String, Value> {
        let mut counts = BTreeMap::from([
            ("ethernet", 0),
            ("wifi", 0),
            ("cellular", 0),
            ("video", 0),
            ("audio", 0),
            ("serial", 0),
            ("storage", 0),
            ("smartcard", 0),
            ("other", 0),
        ]);
        let devices: Vec<_> = self
            .devices
            .values()
            .map(|device| {
                let mut short = device.payload.clone();
                short.retain(|key, _| {
                    matches!(
                        key.as_str(),
                        "port"
                            | "vid"
                            | "pid"
                            | "product"
                            | "serial"
                            | "categories"
                            | "nodes"
                            | "role"
                    )
                });
                if let Some(Value::Object(nodes)) = short.get_mut("nodes") {
                    nodes
                        .retain(|_, items| items.as_array().is_some_and(|items| !items.is_empty()));
                }
                if let Some(Value::Array(categories)) = short.get("categories") {
                    for category in categories.iter().filter_map(Value::as_str) {
                        if let Some(count) = counts.get_mut(category) {
                            *count += 1;
                        }
                    }
                }
                short
            })
            .collect();
        Map::from_iter([
            ("devices".into(), json!(devices)),
            ("counts".into(), json!(counts)),
            (
                "flapping".into(),
                json!(self.flapping.keys().collect::<Vec<_>>()),
            ),
            (
                "error".into(),
                json!(error.map(|message| json!({"code": "MONITOR_FAILED", "message": message}))),
            ),
        ])
    }
}

#[derive(Default)]
struct Reporter(Option<Map<String, Value>>);

impl Reporter {
    fn report(&mut self, state: &State<'_>, error: Option<&str>, ctx: &ModuleContext) {
        let reported = state.shadow(error);
        if self.0.as_ref() != Some(&reported) {
            ctx.shadows.report(MODULE, reported.clone());
            self.0 = Some(reported);
        }
    }
}

#[cfg(test)]
mod tests;
