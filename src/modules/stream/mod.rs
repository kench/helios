//! The `stream` module (LLD 4): video streams to SRT listeners, run by ffmpeg.
//!
//! This version runs USB-camera streams (cameras from the usb module, LLD 5) to `direct` SRT
//! outputs. Each configured stream is `live` (run whenever its camera is attached) or `stopped`,
//! from config, the `stream` shadow's desired state, or `stream.start` / `stream.stop`. The
//! module starts ffmpeg when a live stream's camera is there, reads its `-progress` output,
//! restarts it with backoff when it exits or stalls, and stops it when the camera goes or the
//! stream is stopped. `rtmp-ingest` and `srtla-sender` (LLD 4, sections 4 and 5) come later.
//!
//! Events on `helios/<thing>/evt/stream`: `stream.connected` (the source became ready),
//! `stream.live`, `stream.disconnected` (with a reason) and, while live, `stream.stats`.
//! Commands: `stream.start`, `stream.stop`, `stream.status`.

mod addrs;
#[cfg(test)]
mod e2e;
mod ffmpeg;
mod process;
pub(crate) mod settings;
mod srtla;

use std::collections::{BTreeSet, VecDeque};
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, SystemTime};

use serde_json::{Map, Value, json};
use tokio::sync::mpsc;
use tokio::time::Instant;

use crate::backoff::Backoff;
use crate::modules::usb::{UsbHandle, UsbSnapshot};
use crate::mqtt::envelope::timestamp;
use crate::router::{Outcome, codes};

use super::{Module, ModuleContext, ModuleError, ModuleFuture};
use addrs::Address;
use ffmpeg::{CameraNodes, Progress, ProgressParser};
use process::{Job, JobEvent, JobSpec, Spawner, Tagged};
pub use settings::StreamSettings;
use settings::{Source, Stream};
use srtla::Senders;

/// The module name: commands, events, shadow and config section.
pub const MODULE: &str = "stream";

/// How long ffmpeg gets to stop after SIGTERM.
const STOP_GRACE: Duration = Duration::from_secs(2);
/// No output progress for this long means a stalled job.
const STALL: Duration = Duration::from_secs(10);
/// How long a new job may take to show progress.
const FIRST_PROGRESS: Duration = Duration::from_secs(20);
/// This many failures within [`FAILURE_WINDOW`] make a stream `failed`.
const FAILURE_LIMIT: usize = 5;
const FAILURE_WINDOW: Duration = Duration::from_secs(600);
/// A job that ran this long resets the restart backoff.
const STABLE_RUN: Duration = Duration::from_secs(300);
/// Log lines kept per stream for `stream.status`.
const LOG_LINES: usize = 20;
/// At most this many `stream.connected` events per stream a minute (a flapping source).
const FLAP_LIMIT: usize = 20;
/// Encoder figures go to the shadow at most this often.
const ENCODER_REPORT: Duration = Duration::from_secs(60);

/// Where a stream is in its life (LLD 4, section 6.4).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum State {
    Stopped,
    WaitingForInput,
    Starting,
    Live,
    Reconnecting,
    Failed,
}

impl State {
    fn as_str(self) -> &'static str {
        match self {
            Self::Stopped => "stopped",
            Self::WaitingForInput => "waiting_for_input",
            Self::Starting => "starting",
            Self::Live => "live",
            Self::Reconnecting => "reconnecting",
            Self::Failed => "failed",
        }
    }
}

/// The stream module, for the supervisor.
pub struct StreamModule {
    settings: StreamSettings,
    usb: UsbHandle,
    spawner: Arc<dyn Spawner>,
    addresses: Arc<Addresses>,
}

/// Where uplink addresses come from: rtnetlink, or a fake in tests.
type Addresses = dyn Fn() -> std::io::Result<Vec<Address>> + Send + Sync;

/// How often uplink addresses are read again.
const ADDRESS_REFRESH: Duration = Duration::from_secs(5);

impl StreamModule {
    /// The module, following cameras through the usb module's `handle`.
    #[must_use]
    pub fn new(settings: StreamSettings, usb: UsbHandle) -> Self {
        Self {
            settings,
            usb,
            spawner: Arc::new(process::System),
            addresses: Arc::new(addrs::ipv4_addresses),
        }
    }

    #[cfg(test)]
    fn with_fakes(
        settings: StreamSettings,
        usb: UsbHandle,
        spawner: Arc<dyn Spawner>,
        addresses: Arc<Addresses>,
    ) -> Self {
        Self {
            settings,
            usb,
            spawner,
            addresses,
        }
    }
}

impl Module for StreamModule {
    fn name(&self) -> &'static str {
        MODULE
    }

    fn run(&self, ctx: ModuleContext) -> ModuleFuture<'_> {
        Box::pin(Streams::new(self).run(ctx))
    }
}

/// A job that's running.
struct Running {
    id: u64,
    job: Box<dyn Job>,
    started: Instant,
    /// When ffmpeg's output time last moved forward.
    advanced: Option<Instant>,
    out_time_us: Option<i64>,
    parser: ProgressParser,
}

/// One stream's state.
struct Entry {
    id: String,
    config: Stream,
    desired_live: bool,
    bitrate_kbps: u32,
    state: State,
    since: SystemTime,
    nodes: Option<CameraNodes>,
    /// The camera, for events and the shadow.
    camera: Value,
    connected: bool,
    connected_at: SystemTime,
    /// Whether this connection's events are suppressed (a flapping source).
    quiet: bool,
    connections: VecDeque<Instant>,
    job: Option<Running>,
    failures: VecDeque<Instant>,
    backoff: Backoff,
    restart_at: Option<Instant>,
    last_error: Option<String>,
    /// Why the stream can't run at all (a missing encoder).
    unusable: Option<String>,
    lines: VecDeque<String>,
    progress: Option<Progress>,
}

impl Entry {
    fn set_state(&mut self, state: State) {
        if self.state != state {
            self.state = state;
            self.since = SystemTime::now();
        }
    }

    fn encoder(&self) -> Value {
        self.progress.as_ref().map_or(Value::Null, |p| {
            json!({
                "fps": p.fps, "bitrate_kbps": p.bitrate_kbps, "drop_frames": p.drop_frames,
                "dup_frames": p.dup_frames, "speed": p.speed,
            })
        })
    }

    fn status(&self, with_log: bool) -> Value {
        let mut source = match &self.config.source {
            Source::Camera { video, audio } => {
                json!({"type": "camera", "video": video, "audio": audio})
            }
            Source::Rtmp { camera } => json!({"type": "rtmp", "camera": camera}),
            Source::Test { size, fps } => json!({"type": "test", "size": size, "fps": fps}),
        };
        if let (Some(source), Value::Object(camera)) = (source.as_object_mut(), &self.camera) {
            source.extend(camera.clone());
        }
        let mut status = json!({
            "state": self.state.as_str(),
            "since": timestamp(self.since),
            "desired": if self.desired_live { "live" } else { "stopped" },
            "source": source,
            "profile": self.config.profile,
            "bitrate_kbps": self.bitrate_kbps,
            "encoder": self.encoder(),
            "output": self.config.output,
            "last_error": self.last_error.as_ref().or(self.unusable.as_ref()),
        });
        if with_log {
            status["log"] = json!(self.lines);
        }
        status
    }
}

/// The module's run: every stream, and what they share.
struct Streams<'a> {
    module: &'a StreamModule,
    entries: Vec<Entry>,
    next_job: u64,
    events_tx: mpsc::UnboundedSender<Tagged>,
    events: mpsc::UnboundedReceiver<Tagged>,
    /// Jobs being stopped, awaited at shutdown.
    stopping: Vec<tokio::task::JoinHandle<()>>,
    reported: Option<(Value, Value, Instant)>,
    senders: Senders,
    sender_stats: mpsc::UnboundedReceiver<(u64, Value)>,
    addresses: Vec<Address>,
    addresses_at: Option<Instant>,
}

impl<'a> Streams<'a> {
    fn new(module: &'a StreamModule) -> Self {
        let (events_tx, events) = mpsc::unbounded_channel();
        let entries = module
            .settings
            .streams
            .iter()
            .map(|(id, config)| Entry {
                id: id.clone(),
                desired_live: config.desired == "live",
                bitrate_kbps: module
                    .settings
                    .profiles
                    .get(&config.profile)
                    .map_or(0, |profile| profile.bitrate_kbps),
                config: config.clone(),
                state: State::Stopped,
                since: SystemTime::now(),
                nodes: None,
                camera: Value::Null,
                connected: false,
                connected_at: SystemTime::now(),
                quiet: false,
                connections: VecDeque::new(),
                job: None,
                failures: VecDeque::new(),
                backoff: Backoff::new(Duration::from_secs(1), Duration::from_secs(60)),
                restart_at: None,
                last_error: None,
                unusable: None,
                lines: VecDeque::new(),
                progress: None,
            })
            .collect();
        let (stats_tx, sender_stats) = mpsc::unbounded_channel();
        Self {
            module,
            entries,
            next_job: 0,
            events_tx,
            events,
            stopping: Vec::new(),
            reported: None,
            senders: Senders::new(&module.settings, stats_tx),
            sender_stats,
            addresses: Vec::new(),
            addresses_at: None,
        }
    }

    async fn run(mut self, mut ctx: ModuleContext) -> Result<(), ModuleError> {
        let module = self.module;
        let settings = &module.settings;
        if let Some(encoders) = module.spawner.encoders(&settings.ffmpeg).await {
            for entry in &mut self.entries {
                entry.unusable = missing_encoders(settings, &entry.config, &encoders);
            }
        }
        let mut snapshot = module.usb.snapshot();
        let mut stats = tokio::time::interval(settings.stats_interval());
        stats.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        let mut commands_open = true;
        let mut desired_open = true;
        loop {
            let devices = snapshot.borrow_and_update().clone();
            let now = Instant::now();
            self.reconcile_senders(&devices, now);
            for index in 0..self.entries.len() {
                self.reconcile(index, &devices, now, &ctx);
            }
            self.report(&ctx);
            let wake = self.next_wake(now);
            tokio::select! {
                biased;
                () = ctx.cancel.cancelled() => break,
                command = ctx.commands.recv(), if commands_open => match command {
                    Some(pending) => {
                        let outcome = self.command(&pending.command.name, &pending.command.args);
                        pending.respond(outcome);
                    }
                    None => commands_open = false,
                },
                desired = ctx.desired.recv(), if desired_open => match desired {
                    Some(state) => self.desired(&state),
                    None => desired_open = false,
                },
                changed = snapshot.changed() => {
                    if changed.is_err() {
                        return Err(ModuleError("the usb module's snapshot closed".into()));
                    }
                    // A USB network device came or went: read uplink addresses again now.
                    self.addresses_at = None;
                }
                Some(tagged) = self.events.recv() => self.job_event(tagged, &ctx),
                Some((job, snapshot)) = self.sender_stats.recv() => {
                    self.senders.stats(job, snapshot, Instant::now());
                }
                _ = stats.tick() => self.stats(&ctx),
                () = tokio::time::sleep_until(wake) => {}
            }
        }
        self.shutdown(&ctx).await;
        Ok(())
    }

    /// Brings one stream in line with its desired state, its camera and its job.
    fn reconcile(
        &mut self,
        index: usize,
        devices: &UsbSnapshot,
        now: Instant,
        ctx: &ModuleContext,
    ) {
        let entry = &mut self.entries[index];
        let (nodes, camera) = resolve(&entry.config.source, devices);
        entry.nodes = nodes;
        if camera != Value::Null {
            entry.camera = camera;
        }
        if !entry.desired_live {
            self.stop_job(index);
            self.disconnect(index, "stopped", ctx);
            self.entries[index].set_state(State::Stopped);
            return;
        }
        if let Some(reason) = self.entries[index].unusable.clone() {
            self.entries[index].last_error = Some(reason);
            self.entries[index].set_state(State::Failed);
            return;
        }
        if self.entries[index].state == State::Failed {
            return;
        }
        let ready = matches!(self.entries[index].config.source, Source::Test { .. })
            || self.entries[index].nodes.is_some();
        if !ready {
            self.stop_job(index);
            self.disconnect(index, "camera_removed", ctx);
            let entry = &mut self.entries[index];
            entry.restart_at = None;
            entry.set_state(State::WaitingForInput);
            return;
        }
        self.connect(index, ctx);
        let stalled = self.entries[index].job.as_ref().map(|running| {
            let quiet_since = running.advanced.unwrap_or(running.started);
            let limit = if running.advanced.is_some() {
                STALL
            } else {
                FIRST_PROGRESS
            };
            now.duration_since(quiet_since) >= limit
        });
        match stalled {
            Some(true) => {
                tracing::warn!(stream = %self.entries[index].id, "ffmpeg stalled; restarting it");
                self.stop_job(index);
                self.failed_run(index, "ffmpeg stopped making progress".into(), now, ctx);
                return;
            }
            Some(false) => return,
            None => {}
        }
        let entry = &mut self.entries[index];
        if entry.restart_at.is_some_and(|at| at > now) {
            entry.set_state(State::Reconnecting);
            return;
        }
        // An srtla output must carry traffic before ffmpeg can connect through it.
        let output = &entry.config.output;
        if self.senders.port(output).is_some() && !self.senders.state(output, now).carries() {
            let waiting = format!(
                "waiting for output {output}: {}",
                self.senders.state(output, now).as_str()
            );
            let entry = &mut self.entries[index];
            if entry.state != State::Reconnecting {
                entry.set_state(State::Starting);
            }
            entry.last_error.get_or_insert(waiting);
            return;
        }
        self.start_job(index, ctx);
    }

    /// The outputs live streams need now, and the senders for them; reads uplink addresses
    /// again every few seconds while any sender is wanted.
    fn reconcile_senders(&mut self, devices: &UsbSnapshot, now: Instant) {
        let wanted: Vec<&str> = self
            .entries
            .iter()
            .filter(|entry| {
                entry.desired_live
                    && entry.unusable.is_none()
                    && entry.state != State::Failed
                    && (matches!(entry.config.source, Source::Test { .. }) || entry.nodes.is_some())
            })
            .map(|entry| entry.config.output.as_str())
            .filter(|output| self.senders.port(output).is_some())
            .collect();
        if !wanted.is_empty()
            && self
                .addresses_at
                .is_none_or(|at| now.duration_since(at) >= ADDRESS_REFRESH)
        {
            match (self.module.addresses)() {
                Ok(addresses) => self.addresses = addresses,
                Err(error) => tracing::warn!(%error, "can't read interface addresses"),
            }
            self.addresses_at = Some(now);
        }
        let wanted: Vec<String> = wanted.into_iter().map(str::to_owned).collect();
        let wanted: Vec<&str> = wanted.iter().map(String::as_str).collect();
        self.senders.reconcile(
            &wanted,
            devices,
            &self.addresses,
            now,
            srtla::Spawning {
                spawner: self.module.spawner.as_ref(),
                events: &self.events_tx,
                next_job: &mut self.next_job,
            },
        );
    }

    fn start_job(&mut self, index: usize, ctx: &ModuleContext) {
        let module = self.module;
        let settings = &module.settings;
        let entry = &mut self.entries[index];
        let (Some(profile), Some(output)) = (
            settings.profiles.get(&entry.config.profile),
            settings.outputs.get(&entry.config.output),
        ) else {
            return;
        };
        let target = ffmpeg::Target {
            output,
            streamid: &entry.config.streamid,
            sender_port: self.senders.port(&entry.config.output),
        };
        let args = match (&entry.config.source, entry.nodes.as_ref()) {
            (Source::Test { size, fps }, _) => {
                ffmpeg::test_args(profile, target, size, *fps, entry.bitrate_kbps)
            }
            (Source::Camera { .. }, Some(nodes)) => {
                ffmpeg::camera_args(profile, target, nodes, entry.bitrate_kbps)
            }
            _ => return,
        };
        let spec = JobSpec {
            name: entry.id.clone(),
            program: settings.ffmpeg.clone(),
            args,
        };
        self.next_job += 1;
        let id = self.next_job;
        let entry = &mut self.entries[index];
        entry.restart_at = None;
        match module.spawner.spawn(&spec, id, self.events_tx.clone()) {
            Ok(job) => {
                tracing::info!(stream = %entry.id, "ffmpeg started");
                entry.job = Some(Running {
                    id,
                    job,
                    started: Instant::now(),
                    advanced: None,
                    out_time_us: None,
                    parser: ProgressParser::default(),
                });
                entry.progress = None;
                if entry.state != State::Reconnecting {
                    entry.set_state(State::Starting);
                }
            }
            Err(error) => {
                let message = format!("can't start {}: {error}", settings.ffmpeg.display());
                self.failed_run(index, message, Instant::now(), ctx);
            }
        }
    }

    /// Stops the stream's job, if it has one, without waiting for it.
    fn stop_job(&mut self, index: usize) {
        if let Some(mut running) = self.entries[index].job.take() {
            self.stopping.push(tokio::spawn(
                async move { running.job.stop(STOP_GRACE).await },
            ));
            self.stopping.retain(|task| !task.is_finished());
        }
    }

    /// A run ended badly: back off, or give up after too many failures.
    fn failed_run(&mut self, index: usize, reason: String, now: Instant, ctx: &ModuleContext) {
        let entry = &mut self.entries[index];
        entry.last_error = Some(reason);
        entry.progress = None;
        entry.failures.push_back(now);
        entry
            .failures
            .retain(|at| now.duration_since(*at) < FAILURE_WINDOW);
        if entry.failures.len() >= FAILURE_LIMIT {
            tracing::warn!(stream = %entry.id, "too many failures; stream failed");
            entry.restart_at = None;
            entry.set_state(State::Failed);
            self.disconnect(index, "failed", ctx);
            return;
        }
        let delay = entry.backoff.next_delay();
        entry.restart_at = Some(now + delay);
        entry.set_state(State::Reconnecting);
    }

    fn connect(&mut self, index: usize, ctx: &ModuleContext) {
        let entry = &mut self.entries[index];
        if entry.connected {
            return;
        }
        let now = Instant::now();
        entry.connected = true;
        entry.connected_at = SystemTime::now();
        entry.connections.push_back(now);
        entry
            .connections
            .retain(|at| now.duration_since(*at) < Duration::from_secs(60));
        entry.quiet = entry.connections.len() > FLAP_LIMIT;
        if !entry.quiet {
            let payload = json!({"stream_id": entry.id, "source": entry.status(false)["source"]});
            ctx.mqtt.publish_event(MODULE, "stream.connected", payload);
        }
    }

    fn disconnect(&mut self, index: usize, reason: &str, ctx: &ModuleContext) {
        let entry = &mut self.entries[index];
        if !entry.connected {
            return;
        }
        entry.connected = false;
        if !entry.quiet {
            let ran = entry.connected_at.elapsed().unwrap_or_default().as_secs();
            let payload = json!({"stream_id": entry.id, "reason": reason, "connected_s": ran});
            ctx.mqtt
                .publish_event(MODULE, "stream.disconnected", payload);
        }
    }

    fn job_event(&mut self, tagged: Tagged, ctx: &ModuleContext) {
        if self.senders.job_event(&tagged, Instant::now()) {
            return;
        }
        let Some(index) = self
            .entries
            .iter()
            .position(|entry| entry.job.as_ref().is_some_and(|job| job.id == tagged.job))
        else {
            return; // a job already replaced or stopped
        };
        let now = Instant::now();
        match tagged.event {
            JobEvent::Stdout(line) => {
                let entry = &mut self.entries[index];
                let Some(running) = entry.job.as_mut() else {
                    return;
                };
                let Some(progress) = running.parser.line(&line) else {
                    return;
                };
                if progress
                    .out_time_us
                    .is_some_and(|t| Some(t) > running.out_time_us)
                {
                    running.out_time_us = progress.out_time_us;
                    running.advanced = Some(now);
                    if entry.state != State::Live {
                        entry.set_state(State::Live);
                        entry.last_error = None;
                        if !entry.quiet {
                            let payload = json!({
                                "stream_id": entry.id, "profile": entry.config.profile,
                                "bitrate_kbps": entry.bitrate_kbps, "output": entry.config.output,
                                "active_links": self.senders.active_links(&entry.config.output),
                            });
                            ctx.mqtt.publish_event(MODULE, "stream.live", payload);
                        }
                    }
                }
                entry.progress = Some(progress);
            }
            JobEvent::Stderr(line) => {
                let entry = &mut self.entries[index];
                tracing::debug!(stream = %entry.id, "ffmpeg: {line}");
                if entry.lines.len() == LOG_LINES {
                    entry.lines.pop_front();
                }
                entry.lines.push_back(line);
            }
            JobEvent::Exited(code) => {
                let entry = &mut self.entries[index];
                let Some(running) = entry.job.take() else {
                    return;
                };
                if now.duration_since(running.started) >= STABLE_RUN {
                    entry.backoff.reset();
                }
                let last = entry.lines.back().cloned();
                let reason = match (code, last) {
                    (_, Some(line)) => format!("ffmpeg exited ({}): {line}", exit_text(code)),
                    (code, None) => format!("ffmpeg exited ({})", exit_text(code)),
                };
                tracing::warn!(stream = %entry.id, %reason, "ffmpeg exited");
                self.failed_run(index, reason, now, ctx);
            }
        }
    }

    fn command(&mut self, name: &str, args: &Value) -> Outcome {
        let id = args.get("stream_id").and_then(Value::as_str);
        if name == "status" {
            return match id {
                None => Outcome::Ok(self.statuses(true)),
                Some(id) => match self.entries.iter().find(|entry| entry.id == id) {
                    Some(entry) => Outcome::Ok(entry.status(true)),
                    None => Outcome::error(codes::INVALID_MESSAGE, format!("no stream {id:?}")),
                },
            };
        }
        if !matches!(name, "start" | "stop") {
            return Outcome::error(
                codes::UNKNOWN_COMMAND,
                format!("unknown stream command {name}"),
            );
        }
        let Some(id) = id else {
            return Outcome::error(codes::INVALID_MESSAGE, "stream_id is required");
        };
        let Some(index) = self.entries.iter().position(|entry| entry.id == id) else {
            return Outcome::error(codes::INVALID_MESSAGE, format!("no stream {id:?}"));
        };
        let bitrate = match args.get("bitrate_kbps") {
            None | Some(Value::Null) => None,
            Some(value) => match value.as_u64().and_then(|v| u32::try_from(v).ok()) {
                Some(bitrate) if self.bitrate_allowed(index, bitrate) => Some(bitrate),
                _ => {
                    return Outcome::error(
                        codes::INVALID_MESSAGE,
                        "bitrate_kbps is outside the profile's limits",
                    );
                }
            },
        };
        if name == "start" {
            self.set_live(index, true, bitrate);
        } else {
            self.set_live(index, false, None);
        }
        Outcome::Ok(self.entries[index].status(false))
    }

    fn bitrate_allowed(&self, index: usize, bitrate: u32) -> bool {
        self.module
            .settings
            .profiles
            .get(&self.entries[index].config.profile)
            .is_some_and(|profile| {
                profile.video != "copy"
                    && (profile.min_bitrate_kbps..=profile.max_bitrate_kbps).contains(&bitrate)
            })
    }

    /// The desired state from a command or the shadow. Starting a failed stream gives it a new
    /// chance; a new bitrate restarts a running job.
    fn set_live(&mut self, index: usize, live: bool, bitrate: Option<u32>) {
        let entry = &mut self.entries[index];
        entry.desired_live = live;
        if live && entry.state == State::Failed && entry.unusable.is_none() {
            entry.failures.clear();
            entry.restart_at = None;
            entry.backoff.reset();
            entry.set_state(State::Stopped);
        }
        if let Some(bitrate) = bitrate
            && bitrate != entry.bitrate_kbps
        {
            entry.bitrate_kbps = bitrate;
            self.stop_job(index);
        }
    }

    /// The `stream` shadow's desired state: `{"streams": {"<id>": {"state", "bitrate_kbps"}}}`.
    fn desired(&mut self, state: &Value) {
        let Some(streams) = state.get("streams").and_then(Value::as_object) else {
            return;
        };
        for (id, desired) in streams {
            let Some(index) = self.entries.iter().position(|entry| entry.id == *id) else {
                tracing::warn!(stream = %id, "desired state for an unknown stream");
                continue;
            };
            let bitrate = desired
                .get("bitrate_kbps")
                .and_then(Value::as_u64)
                .and_then(|v| u32::try_from(v).ok())
                .filter(|bitrate| self.bitrate_allowed(index, *bitrate));
            match desired.get("state").and_then(Value::as_str) {
                Some("live") => self.set_live(index, true, bitrate),
                Some("stopped") => self.set_live(index, false, None),
                _ if bitrate.is_some() => {
                    let live = self.entries[index].desired_live;
                    self.set_live(index, live, bitrate);
                }
                _ => tracing::warn!(stream = %id, "desired state needs live or stopped"),
            }
        }
    }

    fn stats(&self, ctx: &ModuleContext) {
        for entry in self
            .entries
            .iter()
            .filter(|e| e.state == State::Live && !e.quiet)
        {
            let outputs = self.senders.report(Instant::now(), false);
            let payload = json!({
                "stream_id": entry.id, "encoder": entry.encoder(),
                "bitrate_kbps": entry.bitrate_kbps, "output": entry.config.output,
                "link_stats": outputs.get(&entry.config.output),
            });
            ctx.mqtt.publish_event(MODULE, "stream.stats", payload);
        }
    }

    fn statuses(&self, with_log: bool) -> Value {
        Value::Object(
            self.entries
                .iter()
                .map(|entry| (entry.id.clone(), entry.status(with_log)))
                .collect(),
        )
    }

    /// Reports the shadow: state changes at once, encoder figures at most once a minute.
    fn report(&mut self, ctx: &ModuleContext) {
        let now = Instant::now();
        let streams = self.statuses(false);
        let mut quiet_streams = streams.clone();
        if let Some(streams) = quiet_streams.as_object_mut() {
            for status in streams.values_mut() {
                if let Some(status) = status.as_object_mut() {
                    status.remove("encoder");
                }
            }
        }
        // Encoder and per-link figures change all the time: they wait for the interval.
        let full = json!({"streams": streams, "outputs": self.senders.report(now, false)});
        let significant =
            json!({"streams": quiet_streams, "outputs": self.senders.report(now, true)});
        let due = match &self.reported {
            None => true,
            Some((last_significant, last_full, at)) => {
                *last_significant != significant
                    || (*last_full != full && at.elapsed() >= ENCODER_REPORT)
            }
        };
        if due {
            let reported: Map<String, Value> = full.as_object().cloned().unwrap_or_default();
            ctx.shadows.report(MODULE, reported);
            self.reported = Some((significant, full, Instant::now()));
        }
    }

    /// The next time something needs looking at: a restart, a stall check, or a pending
    /// encoder report.
    fn next_wake(&self, now: Instant) -> Instant {
        let mut wake = now + Duration::from_secs(3600);
        for entry in &self.entries {
            if let Some(at) = entry.restart_at {
                wake = wake.min(at);
            }
            if let Some(running) = &entry.job {
                wake = wake.min(match running.advanced {
                    Some(at) => at + STALL,
                    None => running.started + FIRST_PROGRESS,
                });
            }
        }
        if let Some((_, _, at)) = &self.reported {
            wake = wake.min((*at + ENCODER_REPORT).max(now + Duration::from_secs(1)));
        }
        if let Some(at) = self.senders.next_wake() {
            wake = wake.min(at.max(now + Duration::from_millis(100)));
        }
        if let Some(at) = self.addresses_at {
            wake = wake.min(at + ADDRESS_REFRESH);
        }
        wake
    }

    async fn shutdown(&mut self, ctx: &ModuleContext) {
        for index in 0..self.entries.len() {
            self.stop_job(index);
            self.disconnect(index, "stopped", ctx);
            self.entries[index].set_state(State::Stopped);
        }
        for task in self.stopping.drain(..) {
            let _ = task.await;
        }
        self.senders.shutdown().await;
        self.report(ctx);
    }
}

fn exit_text(code: Option<i32>) -> String {
    code.map_or_else(
        || "killed by a signal".into(),
        |code| format!("code {code}"),
    )
}

/// The encoders a stream needs that `encoders` doesn't have, as an error message.
fn missing_encoders(
    settings: &StreamSettings,
    stream: &Stream,
    encoders: &BTreeSet<String>,
) -> Option<String> {
    let profile = settings.profiles.get(&stream.profile)?;
    let mut needed = Vec::new();
    if profile.video != "copy" {
        needed.push(profile.video.as_str());
    }
    if profile.audio == "aac" {
        needed.push("aac");
    }
    let missing: Vec<_> = needed
        .into_iter()
        .filter(|name| !encoders.contains(*name))
        .collect();
    (!missing.is_empty()).then(|| {
        format!(
            "{} has no {} encoder",
            settings.ffmpeg.display(),
            missing.join(" or ")
        )
    })
}

/// Finds a USB device by `usb:<port>` or `<vid>:<pid>:<serial>`.
fn find<'a>(
    devices: &'a UsbSnapshot,
    selector: &str,
) -> Option<&'a crate::modules::usb::UsbDevice> {
    if let Some(port) = selector.strip_prefix("usb:") {
        return devices.get(port).map(AsRef::as_ref);
    }
    devices
        .values()
        .find(|device| device.payload.get("key").and_then(Value::as_str) == Some(selector))
        .map(AsRef::as_ref)
}

/// A camera source's nodes, if its devices are attached with what it needs, and what to report
/// about the camera.
fn resolve(source: &Source, devices: &UsbSnapshot) -> (Option<CameraNodes>, Value) {
    let Source::Camera { video, audio } = source else {
        return (None, Value::Null);
    };
    let Some(camera) = find(devices, video) else {
        return (None, Value::Null);
    };
    let report = json!({"port": camera.port, "product": camera.payload.get("product")});
    // The capture node: a UVC camera makes two, and index 0 is the one that captures.
    let node = camera.payload["nodes"]["video"]
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(|node| {
            Some((
                node["index"].as_u64().unwrap_or(u64::MAX),
                node["name"].as_str()?,
            ))
        })
        .min();
    let Some((_, name)) = node else {
        return (None, report);
    };
    let audio = match audio {
        None => None,
        Some(selector) => {
            let card = find(devices, selector).and_then(|device| {
                device.payload["nodes"]["alsa"]
                    .as_array()?
                    .iter()
                    .find(|card| card["capture"] == true)?["card"]
                    .as_u64()
            });
            match card {
                Some(card) => Some(format!("hw:{card},0")),
                None => return (None, report),
            }
        }
    };
    let nodes = CameraNodes {
        video: PathBuf::from("/dev").join(name),
        audio,
    };
    (Some(nodes), report)
}

#[cfg(test)]
mod tests;
