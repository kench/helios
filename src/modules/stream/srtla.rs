//! `srtla-sender` (LLD 4, section 5): one `srtla_send` per `srtla` output, run while a stream
//! needs it (and `sender_idle_s` after), with its uplink IP file, reloads when uplinks change, and
//! its per-second statistics from the control socket.

use std::collections::{BTreeMap, VecDeque};
use std::io;
use std::net::Ipv4Addr;
use std::os::unix::fs::DirBuilderExt as _;
use std::path::{Path, PathBuf};
use std::time::Duration;

use serde_json::{Value, json};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::sync::mpsc;
use tokio::task::JoinHandle;
use tokio::time::Instant;

use super::addrs::{Address, Onboard};
use super::process::{Job, JobEvent, JobSpec, Spawner, Tagged};
use super::settings::{Output, StreamSettings};
use super::standby::{self, Standby, View};
use crate::backoff::Backoff;
use crate::modules::usb::UsbSnapshot;

/// How long `srtla_send` gets to stop after SIGTERM.
const STOP_GRACE: Duration = Duration::from_secs(5);
/// No active link for this long, after having had one, makes an output `down`.
const DOWN_AFTER: Duration = Duration::from_secs(10);
/// Log lines kept per sender.
const LOG_LINES: usize = 20;

/// An output's state, as streams and the shadow see it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum OutputState {
    /// No sender running (nothing needs it).
    Stopped,
    /// The sender is running but hasn't reported a link yet.
    Starting,
    /// Every uplink has an active link.
    Up,
    /// Some uplinks have active links.
    Degraded,
    /// None of the configured uplinks has an IPv4 address.
    NoUplinks,
    /// No active link for a while, or the sender is restarting.
    Down,
}

impl OutputState {
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Self::Stopped => "stopped",
            Self::Starting => "starting",
            Self::Up => "up",
            Self::Degraded => "degraded",
            Self::NoUplinks => "no_uplinks",
            Self::Down => "down",
        }
    }

    /// Whether a stream's ffmpeg can send through it.
    pub(crate) fn carries(self) -> bool {
        matches!(self, Self::Up | Self::Degraded)
    }
}

struct Sender {
    output: Output,
    port: u16,
    ips: Vec<Ipv4Addr>,
    /// Uplinks left out because a preferred one shares their public address (LLD 3, 3.5.1).
    standby: Vec<Standby>,
    /// Working links kept in the bond until one of the uplinks replacing them registers.
    held: Vec<Ipv4Addr>,
    job: Option<(u64, Box<dyn Job>)>,
    monitor: Option<JoinHandle<()>>,
    idle_since: Option<Instant>,
    restart_at: Option<Instant>,
    backoff: Backoff,
    stats: Option<Value>,
    /// When a snapshot last showed an active link.
    active_at: Option<Instant>,
    last_error: Option<String>,
    lines: VecDeque<String>,
}

/// What starting a process needs: the spawner, where its events go, and the module's job
/// counter (job numbers are shared with ffmpeg jobs).
pub(crate) struct Spawning<'a> {
    pub spawner: &'a dyn Spawner,
    pub events: &'a mpsc::UnboundedSender<Tagged>,
    pub next_job: &'a mut u64,
}

/// Every `srtla` output's sender.
pub(crate) struct Senders {
    senders: BTreeMap<String, Sender>,
    dir: PathBuf,
    program: PathBuf,
    idle: Duration,
    /// `modules.stream.srtla_standby`.
    standby: bool,
    stats_tx: mpsc::UnboundedSender<(u64, Value)>,
}

impl Senders {
    pub(crate) fn new(
        settings: &StreamSettings,
        stats_tx: mpsc::UnboundedSender<(u64, Value)>,
    ) -> Self {
        let senders = settings
            .outputs
            .iter()
            .filter(|(_, output)| output.mode == "srtla")
            .filter_map(|(name, output)| {
                Some((
                    name.clone(),
                    Sender::new(output.clone(), settings.sender_port(name)?),
                ))
            })
            .collect();
        Self {
            senders,
            dir: settings.runtime_dir.join("srtla"),
            program: settings.srtla_send.clone(),
            idle: settings.sender_idle(),
            standby: settings.srtla_standby,
            stats_tx,
        }
    }

    /// Sets, changes or removes the sender for a stream's SRTLA destination (`name` is its
    /// output's, `stream:<id>`): a changed output stops the running sender, and the next
    /// reconcile starts it again with the new one.
    pub(crate) fn set_dynamic(&mut self, name: &str, sender: Option<(Output, u16)>) {
        match sender {
            None => {
                if let Some(mut old) = self.senders.remove(name) {
                    old.stop();
                    let _ = std::fs::remove_file(self.dir.join(format!("{name}.ips")));
                }
            }
            Some((output, port)) => {
                if self
                    .senders
                    .get(name)
                    .is_some_and(|old| old.output == output && old.port == port)
                {
                    return;
                }
                if let Some(mut old) = self.senders.remove(name) {
                    old.stop();
                }
                self.senders
                    .insert(name.to_owned(), Sender::new(output, port));
            }
        }
    }

    /// The local port ffmpeg sends to for `output`, if it's an `srtla` output.
    pub(crate) fn port(&self, output: &str) -> Option<u16> {
        self.senders.get(output).map(|sender| sender.port)
    }

    pub(crate) fn state(&self, output: &str, now: Instant) -> OutputState {
        self.senders
            .get(output)
            .map_or(OutputState::Stopped, |sender| sender.state(now))
    }

    pub(crate) fn active_links(&self, output: &str) -> Option<u64> {
        self.senders
            .get(output)?
            .stats
            .as_ref()?
            .get("active_links")?
            .as_u64()
    }

    /// Starts, keeps or stops each sender: `wanted` are the outputs a live stream needs now.
    pub(crate) fn reconcile(
        &mut self,
        wanted: &[&str],
        usb: &UsbSnapshot,
        addresses: &[Address],
        view: &View,
        now: Instant,
        spawning: Spawning<'_>,
    ) {
        let names: Vec<String> = self.senders.keys().cloned().collect();
        for name in names {
            let candidates =
                resolve_uplink_interfaces(&self.senders[&name].output.uplinks, usb, addresses);
            let (mut ips, mut standby) = if self.standby {
                standby::choose(&candidates, view)
            } else {
                (candidates.iter().map(|(_, ip)| *ip).collect(), Vec::new())
            };
            // Make before break: while none of the uplinks to bond has a link yet, a working one
            // that's still up stays in, so srtla_send never drops to no links.
            let held = self.senders[&name].held_links(&ips, &candidates);
            if !held.is_empty() {
                standby.retain(|uplink| !held.contains(&uplink.address));
                if held != self.senders[&name].held {
                    tracing::info!(
                        output = %name,
                        ?held,
                        "keeping working links until a new link registers"
                    );
                }
                ips.extend(held.iter().copied());
            }
            self.senders.get_mut(&name).expect("listed").held = held;
            if standby != self.senders[&name].standby {
                for uplink in &standby {
                    tracing::info!(
                        output = %name,
                        interface = %uplink.interface,
                        shares_with = %uplink.shares_with,
                        "uplink in standby: it shares a public address with a preferred one"
                    );
                }
            }
            self.senders.get_mut(&name).expect("listed").standby = standby;
            let needed = wanted.contains(&name.as_str());
            let idle = self.idle;
            let sender = self.senders.get_mut(&name).expect("listed");
            if needed {
                sender.idle_since = None;
            } else if sender.job.is_some() {
                let since = *sender.idle_since.get_or_insert(now);
                if now.duration_since(since) >= idle {
                    tracing::info!(output = %name, "srtla_send idle; stopping it");
                    sender.stop();
                    sender.restart_at = None;
                }
                continue;
            } else {
                sender.restart_at = None;
                continue;
            }
            if sender.job.is_some() {
                if ips != sender.ips {
                    tracing::info!(output = %name, ?ips, "uplinks changed; reloading srtla_send");
                    sender.ips = ips;
                    match write_ips(&self.dir, &name, &sender.ips) {
                        Ok(()) => {
                            if let Some((_, job)) = &sender.job {
                                job.reload();
                            }
                        }
                        Err(error) => {
                            sender.last_error = Some(format!("can't write the IP file: {error}"))
                        }
                    }
                }
                continue;
            }
            if sender.restart_at.is_some_and(|at| at > now) {
                continue;
            }
            sender.ips = ips;
            if let Err(error) = std::fs::DirBuilder::new()
                .recursive(true)
                .mode(0o700)
                .create(&self.dir)
                .and_then(|()| write_ips(&self.dir, &name, &sender.ips))
            {
                sender.fail(format!("can't write the IP file: {error}"), now);
                continue;
            }
            let socket = self.dir.join(format!("{name}.sock"));
            let _ = std::fs::remove_file(&socket);
            let conn_timeout = (u64::from(sender.output.latency_ms) * 2).clamp(5000, 60_000);
            let spec = JobSpec {
                name: format!("srtla:{name}"),
                program: self.program.clone(),
                args: vec![
                    "--control-socket".into(),
                    socket.display().to_string(),
                    "--conn-timeout-ms".into(),
                    conn_timeout.to_string(),
                    sender.port.to_string(),
                    sender.output.host.clone(),
                    sender.output.port.to_string(),
                    self.dir.join(format!("{name}.ips")).display().to_string(),
                ],
                env: Vec::new(),
            };
            *spawning.next_job += 1;
            let id = *spawning.next_job;
            match spawning.spawner.spawn(&spec, id, spawning.events.clone()) {
                Ok(job) => {
                    tracing::info!(output = %name, port = sender.port, "srtla_send started");
                    sender.job = Some((id, job));
                    sender.stats = None;
                    sender.active_at = None;
                    sender.monitor = Some(tokio::spawn(monitor(socket, id, self.stats_tx.clone())));
                }
                Err(error) => {
                    let message = format!("can't start {}: {error}", self.program.display());
                    sender.fail(message, now);
                }
            }
        }
    }

    /// Handles an event from a sender's process; `false` if `tagged` isn't from a sender.
    pub(crate) fn job_event(&mut self, tagged: &Tagged, now: Instant) -> bool {
        let Some((name, sender)) = self
            .senders
            .iter_mut()
            .find(|(_, sender)| sender.job.as_ref().is_some_and(|(id, _)| *id == tagged.job))
        else {
            return false;
        };
        match &tagged.event {
            JobEvent::Stdout(line) | JobEvent::Stderr(line) => {
                tracing::debug!(output = %name, "srtla_send: {line}");
                if sender.lines.len() == LOG_LINES {
                    sender.lines.pop_front();
                }
                sender.lines.push_back(line.clone());
            }
            JobEvent::Exited(code) => {
                sender.job = None;
                if let Some(monitor) = sender.monitor.take() {
                    monitor.abort();
                }
                let last = sender.lines.back().cloned().unwrap_or_default();
                let reason = format!(
                    "srtla_send exited ({}): {last}",
                    code.map_or_else(|| "killed by a signal".into(), |c| format!("code {c}"))
                );
                tracing::warn!(output = %name, %reason, "srtla_send exited");
                sender.fail(reason, now);
            }
        }
        true
    }

    /// A statistics snapshot from a sender's control socket.
    pub(crate) fn stats(&mut self, job: u64, snapshot: Value, now: Instant) {
        if let Some(sender) = self
            .senders
            .values_mut()
            .find(|sender| sender.job.as_ref().is_some_and(|(id, _)| *id == job))
        {
            if snapshot
                .get("active_links")
                .and_then(Value::as_u64)
                .unwrap_or(0)
                > 0
            {
                sender.active_at = Some(now);
                sender.backoff.reset();
                sender.last_error = None;
            }
            sender.stats = Some(snapshot);
        }
    }

    /// The next time a sender needs looking at.
    pub(crate) fn next_wake(&self) -> Option<Instant> {
        self.senders
            .values()
            .flat_map(|sender| {
                [
                    sender.restart_at,
                    sender.idle_since.map(|since| since + self.idle),
                    sender.active_at.map(|at| at + DOWN_AFTER),
                ]
            })
            .flatten()
            .min()
    }

    /// Each output's state for the shadow; `significant` leaves out per-link figures.
    pub(crate) fn report(&self, now: Instant, significant: bool) -> Value {
        Value::Object(
            self.senders
                .iter()
                .map(|(name, sender)| (name.clone(), sender.report(now, significant)))
                .collect(),
        )
    }

    /// Stops every sender, for shutdown.
    pub(crate) async fn shutdown(&mut self) {
        for sender in self.senders.values_mut() {
            if let Some(monitor) = sender.monitor.take() {
                monitor.abort();
            }
            if let Some((_, mut job)) = sender.job.take() {
                job.stop(STOP_GRACE).await;
            }
        }
    }
}

impl Sender {
    fn new(output: Output, port: u16) -> Self {
        Self {
            output,
            port,
            ips: Vec::new(),
            standby: Vec::new(),
            held: Vec::new(),
            job: None,
            monitor: None,
            idle_since: None,
            restart_at: None,
            backoff: Backoff::new(Duration::from_secs(1), Duration::from_secs(60)),
            stats: None,
            active_at: None,
            last_error: None,
            lines: VecDeque::new(),
        }
    }

    /// The working links to keep while none of `bond` has a link yet: those srtla_send reports
    /// connected and not timed out, whose uplink still has its address (`present`). Without this,
    /// a switch that replaces every link (Wi-Fi back to standby as Ethernet returns) leaves
    /// srtla_send with no registered link, and its fresh handshake outlasts SRT's 5-second peer
    /// timeout, so the stream drops.
    fn held_links(&self, bond: &[Ipv4Addr], present: &[(String, Ipv4Addr)]) -> Vec<Ipv4Addr> {
        if self.job.is_none() {
            return Vec::new();
        }
        let live: Vec<Ipv4Addr> = self
            .stats
            .as_ref()
            .and_then(|stats| stats.get("links"))
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
            .filter(|link| {
                link["connected"].as_bool() == Some(true)
                    && link["timed_out"].as_bool() != Some(true)
            })
            .filter_map(|link| link["ip"].as_str()?.parse().ok())
            .collect();
        if live.iter().any(|ip| bond.contains(ip)) {
            return Vec::new();
        }
        let mut held: Vec<Ipv4Addr> = live
            .into_iter()
            .filter(|ip| present.iter().any(|(_, address)| address == ip))
            .collect();
        held.sort_unstable();
        held.dedup();
        held
    }

    fn state(&self, now: Instant) -> OutputState {
        if self.job.is_none() {
            return if self.restart_at.is_some() {
                OutputState::Down
            } else {
                OutputState::Stopped
            };
        }
        if self.ips.is_empty() {
            return OutputState::NoUplinks;
        }
        let active = self
            .stats
            .as_ref()
            .and_then(|stats| stats.get("active_links")?.as_u64())
            .unwrap_or(0);
        match (active, self.active_at) {
            (0, None) => OutputState::Starting,
            (0, Some(at)) if now.duration_since(at) < DOWN_AFTER => OutputState::Starting,
            (0, Some(_)) => OutputState::Down,
            (active, _) if usize::try_from(active).unwrap_or(0) < self.ips.len() => {
                OutputState::Degraded
            }
            _ => OutputState::Up,
        }
    }

    fn stop(&mut self) {
        if let Some(monitor) = self.monitor.take() {
            monitor.abort();
        }
        if let Some((_, mut job)) = self.job.take() {
            tokio::spawn(async move { job.stop(STOP_GRACE).await });
        }
        self.stats = None;
        self.active_at = None;
        self.idle_since = None;
    }

    fn fail(&mut self, reason: String, now: Instant) {
        self.last_error = Some(reason);
        self.stats = None;
        self.active_at = None;
        self.restart_at = Some(now + self.backoff.next_delay());
    }

    fn report(&self, now: Instant, significant: bool) -> Value {
        let stats = self.stats.as_ref();
        let figure = |key: &str| {
            stats
                .and_then(|s| s.get(key))
                .cloned()
                .unwrap_or(Value::Null)
        };
        let mut report = json!({
            "state": self.state(now).as_str(),
            "local_port": self.port,
            "uplinks": self.ips.iter().map(ToString::to_string).collect::<Vec<_>>(),
            "standby": self.standby.iter().map(Standby::json).collect::<Vec<_>>(),
            "active_links": figure("active_links"),
            "total_links": figure("total_links"),
            "last_error": self.last_error,
        });
        if !significant {
            let links: Vec<Value> = stats
                .and_then(|s| s.get("links"))
                .and_then(Value::as_array)
                .into_iter()
                .flatten()
                .map(|link| {
                    let keys = [
                        "ip",
                        "connected",
                        "timed_out",
                        "rtt_ms",
                        "nak_count",
                        "window",
                        "in_flight",
                        "bitrate_bytes_per_sec",
                        "cc_loss_permille",
                        "weak",
                    ];
                    Value::Object(
                        keys.iter()
                            .filter_map(|key| Some(((*key).to_owned(), link.get(*key)?.clone())))
                            .collect(),
                    )
                })
                .collect();
            report["links"] = json!(links);
            report["negotiated_latency_ms"] = figure("negotiated_latency_ms");
        }
        report
    }
}

/// The IPv4 addresses of the configured uplinks: `net:ethernet` and `net:wifi` (the board's own
/// ports of that kind), `usb:<category>` (the usb module's network devices in that category) or
/// interface names.
#[cfg(test)]
pub(crate) fn resolve_uplinks(
    uplinks: &[String],
    usb: &UsbSnapshot,
    addresses: &[Address],
) -> Vec<Ipv4Addr> {
    let mut ips: Vec<Ipv4Addr> = resolve_uplink_interfaces(uplinks, usb, addresses)
        .into_iter()
        .map(|(_, ip)| ip)
        .collect();
    ips.sort();
    ips.dedup();
    ips
}

/// [`resolve_uplinks`], with the interface each address is on.
pub(crate) fn resolve_uplink_interfaces(
    uplinks: &[String],
    usb: &UsbSnapshot,
    addresses: &[Address],
) -> Vec<(String, Ipv4Addr)> {
    let mut interfaces: Vec<String> = Vec::new();
    for uplink in uplinks {
        let onboard = match uplink.as_str() {
            "net:ethernet" => Some(Onboard::Ethernet),
            "net:wifi" => Some(Onboard::Wifi),
            _ => None,
        };
        if let Some(kind) = onboard {
            interfaces.extend(
                addresses
                    .iter()
                    .filter(|address| address.onboard == Some(kind))
                    .map(|address| address.interface.clone()),
            );
            continue;
        }
        match uplink.strip_prefix("usb:") {
            Some(category) => {
                for device in usb.values() {
                    let in_category = device.payload["categories"]
                        .as_array()
                        .is_some_and(|categories| categories.iter().any(|c| c == category));
                    if in_category {
                        interfaces.extend(
                            device.payload["nodes"]["net"]
                                .as_array()
                                .into_iter()
                                .flatten()
                                .filter_map(|name| name.as_str().map(str::to_owned)),
                        );
                    }
                }
            }
            None => interfaces.push(uplink.clone()),
        }
    }
    let mut found: Vec<(String, Ipv4Addr)> = addresses
        .iter()
        .filter_map(|address| {
            // An alias (eth0:1) belongs to its interface.
            let interface = interfaces.iter().find(|name| {
                address.interface == **name
                    || address
                        .interface
                        .strip_prefix(name.as_str())
                        .is_some_and(|alias| alias.starts_with(':'))
            })?;
            Some((interface.clone(), address.address))
        })
        .filter(|(_, ip)| !ip.is_loopback() && !ip.is_link_local() && !ip.is_unspecified())
        .collect();
    found.sort_by_key(|(_, ip)| *ip);
    found.dedup_by(|a, b| a.1 == b.1);
    found
}

/// Writes `<dir>/<name>.ips` (one IP per line) through a temporary file and a rename, so
/// `srtla_send` never reads half a file.
fn write_ips(dir: &Path, name: &str, ips: &[Ipv4Addr]) -> io::Result<()> {
    let text: String = ips.iter().map(|ip| format!("{ip}\n")).collect();
    let temporary = dir.join(format!(".{name}.ips.new"));
    std::fs::write(&temporary, text)?;
    std::fs::rename(&temporary, dir.join(format!("{name}.ips")))
}

/// Follows a sender's control socket: subscribes to `stats` and forwards each snapshot, tagged
/// with the sender's job. Reconnects while the sender runs (it creates the socket at start).
async fn monitor(socket: PathBuf, job: u64, stats: mpsc::UnboundedSender<(u64, Value)>) {
    loop {
        if let Ok(stream) = tokio::net::UnixStream::connect(&socket).await {
            let (reader, mut writer) = stream.into_split();
            let subscribe = "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"subscribe\",\"params\":{\"topic\":\"stats\"}}\n";
            if writer.write_all(subscribe.as_bytes()).await.is_ok() {
                let mut lines = BufReader::new(reader).lines();
                while let Ok(Some(line)) = lines.next_line().await {
                    if let Some(snapshot) = stats_update(&line)
                        && stats.send((job, snapshot)).is_err()
                    {
                        return;
                    }
                }
            }
        }
        tokio::time::sleep(Duration::from_millis(500)).await;
    }
}

/// The snapshot in a `stats.update` notification line.
pub(crate) fn stats_update(line: &str) -> Option<Value> {
    let message: Value = serde_json::from_str(line).ok()?;
    (message.get("method")?.as_str()? == "stats.update")
        .then(|| message.get("params")?.get("data").cloned())
        .flatten()
}
