//! The `stream` module (LLD 4): video streams to SRT listeners, run by ffmpeg.
//!
//! Streams read USB cameras (from the usb module, LLD 5), RTMP publishers (`rtmp-ingest`, LLD 4
//! section 4: nginx under systemd, with its publish hook and statistics page in [`rtmp`]) or a
//! test pattern, and go to `direct` SRT outputs or `srtla` ones through `srtla_send` (section 5).
//! Each configured stream is `live` (run whenever its input is there) or `stopped`, from config,
//! the `stream` shadow's desired state, or `stream.start` / `stream.stop`. The desired state can
//! also change a stream's source, profile, destination and ceiling percentage (HLD section
//! 7.3.7), checked as `helios.toml` is; what it refuses is reported in the stream's `rejected`. The module starts
//! ffmpeg when a live stream's input is there, reads its `-progress` output, restarts it with
//! backoff when it exits or stalls, and stops it when the input goes or the stream is stopped.
//!
//! Events on `helios/<thing>/evt/stream`: `stream.connected` (the source became ready),
//! `stream.live`, `stream.disconnected` (with a reason) and, while live, `stream.stats`.
//! Commands: `stream.start`, `stream.stop`, `stream.status`.

mod addrs;
mod client;
mod control;
pub mod daemon;
mod destination;
#[cfg(test)]
mod e2e;
mod encoder;
mod ffmpeg;
mod inputs;
mod process;
mod rtmp;
pub(crate) mod settings;
mod srtla;
mod v4l2;

use std::collections::{BTreeMap, BTreeSet, VecDeque};
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
pub use client::StreamClient;
use destination::Destination;
use encoder::{Backend, Signal, Watch};
use ffmpeg::{CameraNodes, Progress};
use process::{Job, JobEvent, JobSpec, Spawner, Tagged};
use rtmp::IngestEvent;
pub use settings::StreamSettings;
use settings::{Output, Profile, Source, Stream};
use srtla::Senders;

/// The module name: commands, events, shadow and config section.
pub const MODULE: &str = "stream";

/// How long ffmpeg gets to stop after SIGTERM.
const STOP_GRACE: Duration = Duration::from_secs(2);
/// No output progress for this long means a stalled job.
const STALL: Duration = Duration::from_secs(10);
/// How long a new job may take to show progress.
const FIRST_PROGRESS: Duration = Duration::from_secs(20);
/// How long a GStreamer encoder may take to connect over SRT (it retries by itself).
const FIRST_CONNECT: Duration = Duration::from_secs(60);
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
/// A publish the hook accepted this recently stays even if the statistics page doesn't show it
/// yet (nginx asks before it lists the publisher).
const PUBLISH_GRACE: Duration = Duration::from_secs(if cfg!(test) { 2 } else { 10 });

/// What a command or the desired state does to a stream's bitrate.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum BitrateChange {
    Keep,
    /// Back to the profile's bitrate.
    Profile,
    Override(u32),
}

/// A camera publishing to `rtmp-ingest`.
#[derive(Debug, Clone)]
struct Publisher {
    address: String,
    /// Its video bitrate from the statistics page, smoothed (half the last reading, half the
    /// new one); `None` until nginx has measured one.
    video_kbps: Option<f64>,
    /// When the hook accepted it; `None` if it was found on the statistics page.
    accepted: Option<Instant>,
    /// When it started publishing, for the shadow.
    since: SystemTime,
    /// From the statistics page's metadata, once nginx has it.
    video_codec: Option<String>,
    width: Option<u32>,
    height: Option<u32>,
}

impl Publisher {
    /// Takes the statistics page's description of the stream, keeping what it doesn't give.
    fn describe(&mut self, seen: &rtmp::Seen) {
        if seen.video_codec.is_some() {
            self.video_codec.clone_from(&seen.video_codec);
        }
        self.width = seen.width.or(self.width);
        self.height = seen.height.or(self.height);
    }
}

/// `rtmp-ingest` as the daemon sees it, for the shadow.
#[derive(Debug, Default)]
struct Ingest {
    publishers: BTreeMap<String, Publisher>,
    /// Why the hook or the statistics page last failed; cleared when the page reads again.
    last_error: Option<String>,
}

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
    formats: Arc<FormatReader>,
}

/// Where uplink addresses come from: rtnetlink, or a fake in tests.
type Addresses = dyn Fn() -> std::io::Result<Vec<Address>> + Send + Sync;

/// Where a camera's formats come from: V4L2, or a fake in tests.
type FormatReader = dyn Fn(&std::path::Path) -> std::io::Result<Vec<v4l2::Format>> + Send + Sync;

/// The most a report may take of the shadow's 8 KB before the cameras' formats are left out.
const REPORT_BUDGET: usize = 7 * 1024;

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
            formats: Arc::new(v4l2::formats),
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
            formats: Arc::new(|_| Ok(Vec::new())),
        }
    }

    #[cfg(test)]
    fn with_formats(mut self, formats: Arc<FormatReader>) -> Self {
        self.formats = formats;
        self
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
    /// When ffmpeg's output time last moved forward, or a GStreamer encoder connected.
    advanced: Option<Instant>,
    out_time_us: Option<i64>,
    backend: Backend,
    watch: Watch,
}

impl Running {
    /// Whether it's stalled: no progress for too long (ffmpeg), or no SRT connection in time (a
    /// GStreamer encoder, which catches its own stalls once connected).
    fn stalled(&self, now: Instant) -> bool {
        self.deadline().is_some_and(|at| now >= at)
    }

    fn deadline(&self) -> Option<Instant> {
        match (self.backend.reports_progress(), self.advanced) {
            (true, Some(at)) => Some(at + STALL),
            (true, None) => Some(self.started + FIRST_PROGRESS),
            (false, None) => Some(self.started + FIRST_CONNECT),
            (false, Some(_)) => None,
        }
    }
}

/// A desired value the stream refused, for the shadow's `rejected`.
#[derive(Debug, Clone)]
struct Rejected {
    /// What was asked, so the same value sent again keeps its first time.
    value: Value,
    reason: String,
    at: SystemTime,
}

/// One stream's state.
struct Entry {
    id: String,
    /// The stream as `helios.toml` defines it.
    configured: Stream,
    /// The stream as it runs: `configured` with the desired state's source, profile and
    /// destination (`output` is then `stream:<id>`, and `streamid` the destination's).
    config: Stream,
    /// A destination set through the shadow, and the output it makes.
    destination: Option<(Destination, Output)>,
    /// A `source_ceiling_percent` set through the shadow.
    ceiling_override: Option<u32>,
    /// Desired values refused, by setting: `source`, `profile`, `destination`,
    /// `source_ceiling_percent`, `bitrate` or `state`.
    rejected: BTreeMap<&'static str, Rejected>,
    desired_live: bool,
    /// The bitrate in use: the override if there is one, else the profile's.
    bitrate_kbps: u32,
    /// A bitrate set by `stream.start` or the desired state, which outlasts restarts; `None`
    /// follows the profile, so a changed `bitrate_kbps` in the config applies.
    bitrate_override: Option<u32>,
    /// An adaptive RTMP stream's ceiling from its camera's bitrate, once known.
    source_ceiling: Option<u32>,
    /// The camera's video bitrate (smoothed), for the shadow.
    source_kbps: Option<u32>,
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

    /// The output it sends to: its destination's, or the configured one.
    fn output<'s>(&'s self, settings: &'s StreamSettings) -> Option<&'s Output> {
        match &self.destination {
            Some((_, output)) => Some(output),
            None => settings.outputs.get(&self.config.output),
        }
    }

    /// Its profile, with the ceiling percentage set through the shadow.
    fn profile(&self, settings: &StreamSettings) -> Option<Profile> {
        let mut profile = settings.profiles.get(&self.config.profile)?.clone();
        if let Some(percent) = self.ceiling_override {
            profile.source_ceiling_percent = percent;
        }
        Some(profile)
    }

    /// The destination URL in use, in the Control API's normal form.
    fn destination_url(&self, settings: &StreamSettings) -> Value {
        match &self.destination {
            Some((destination, _)) => json!(destination.url()),
            None => settings
                .outputs
                .get(&self.config.output)
                .map_or(Value::Null, |output| {
                    json!(Destination::of_output(output, &self.config.streamid).url())
                }),
        }
    }

    fn status(&self, settings: &StreamSettings, with_log: bool) -> Value {
        let mut source = source_value(&self.config.source);
        if let (Some(source), Value::Object(camera)) = (source.as_object_mut(), &self.camera) {
            source.extend(camera.clone());
        }
        let rejected: Vec<Value> = self
            .rejected
            .iter()
            .map(|(setting, rejected)| {
                json!({"setting": setting, "reason": rejected.reason, "at": timestamp(rejected.at)})
            })
            .collect();
        // Every key, null when not overridden: the shadow only removes a key set to null.
        let overrides = json!({
            "source": (self.config.source != self.configured.source)
                .then(|| source_value(&self.config.source)),
            "profile": (self.config.profile != self.configured.profile)
                .then_some(&self.config.profile),
            "destination": self.destination.as_ref().map(|(destination, _)| destination.url()),
            "source_ceiling_percent": self.ceiling_override,
        });
        let mut status = json!({
            "state": self.state.as_str(),
            "since": timestamp(self.since),
            "desired": if self.desired_live { "live" } else { "stopped" },
            "source": source,
            "profile": self.config.profile,
            "bitrate_kbps": self.bitrate_kbps,
            "bitrate_override_kbps": self.bitrate_override,
            "source_kbps": self.source_kbps,
            "bitrate_ceiling_kbps": self.source_ceiling,
            "encoder": self.encoder(),
            "output": self.config.output,
            "destination": self.destination_url(settings),
            "source_ceiling_percent": self.profile(settings).map(|p| p.source_ceiling_percent),
            "last_error": self.last_error.as_ref().or(self.unusable.as_ref()),
            "rejected": rejected,
            "overrides": overrides,
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
    ingest: Ingest,
    /// ffmpeg's encoders, once listed: a profile set through the shadow must find its own.
    encoders: Option<BTreeSet<String>>,
    /// The usb module's latest snapshot, for `inputs`.
    devices: Arc<UsbSnapshot>,
    /// Attached cameras' formats, and the cameras being read.
    formats: inputs::Formats,
    formats_reading: BTreeSet<String>,
    formats_tx: mpsc::UnboundedSender<(String, std::io::Result<Vec<v4l2::Format>>)>,
    formats_rx: mpsc::UnboundedReceiver<(String, std::io::Result<Vec<v4l2::Format>>)>,
    /// Whether the last report left the formats out (logged once, when that starts).
    formats_left_out: bool,
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
                configured: config.clone(),
                destination: None,
                ceiling_override: None,
                rejected: BTreeMap::new(),
                desired_live: config.desired == "live",
                bitrate_kbps: module
                    .settings
                    .profiles
                    .get(&config.profile)
                    .map_or(0, |profile| profile.bitrate_kbps),
                bitrate_override: None,
                source_ceiling: None,
                source_kbps: None,
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
        let (formats_tx, formats_rx) = mpsc::unbounded_channel();
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
            ingest: Ingest::default(),
            encoders: None,
            devices: Arc::default(),
            formats: inputs::Formats::new(),
            formats_reading: BTreeSet::new(),
            formats_tx,
            formats_rx,
            formats_left_out: false,
        }
    }

    /// Reads the formats of each newly attached camera (off the async threads: opening a UVC
    /// device can wake it), and forgets those of cameras gone.
    fn read_formats(&mut self) {
        let mut attached = BTreeSet::new();
        for device in self.devices.values() {
            let Some(node) = inputs::capture_node(device) else {
                continue;
            };
            let key = inputs::format_key(device, node);
            attached.insert(key.clone());
            if self.formats.contains_key(&key) || self.formats_reading.contains(&key) {
                continue;
            }
            self.formats_reading.insert(key.clone());
            let read = Arc::clone(&self.module.formats);
            let path = PathBuf::from("/dev").join(node);
            let results = self.formats_tx.clone();
            tokio::task::spawn_blocking(move || {
                let _ = results.send((key, read(&path)));
            });
        }
        self.formats.retain(|key, _| attached.contains(key));
    }

    fn formats_read(&mut self, key: String, result: std::io::Result<Vec<v4l2::Format>>) {
        self.formats_reading.remove(&key);
        let attached = self.devices.values().any(|device| {
            inputs::capture_node(device).is_some_and(|node| inputs::format_key(device, node) == key)
        });
        if !attached {
            return;
        }
        let formats = match result {
            Ok(formats) => Some(formats),
            Err(error) => {
                tracing::warn!(camera = %key, %error, "couldn't read the camera's formats");
                None
            }
        };
        self.formats.insert(key, formats);
    }

    /// The RTMP keys for `inputs`: `ingest`, every key a stream's configured or current source
    /// takes, and every key publishing.
    fn rtmp_keys(&self) -> BTreeSet<String> {
        let mut keys = BTreeSet::from(["ingest".to_owned()]);
        for entry in &self.entries {
            keys.extend(entry.configured.source.rtmp_key());
            keys.extend(entry.config.source.rtmp_key());
        }
        keys.extend(self.ingest.publishers.keys().cloned());
        keys
    }

    /// Whether a stream's input is there: its camera attached, or its RTMP key publishing.
    fn input_ready(&self, entry: &Entry) -> bool {
        match &entry.config.source {
            Source::Test { .. } => true,
            Source::Camera { .. } => entry.nodes.is_some(),
            Source::Rtmp { .. } => entry
                .config
                .source
                .rtmp_key()
                .is_some_and(|key| self.ingest.publishers.contains_key(&key)),
        }
    }

    /// Something from the publish hook or the statistics page.
    fn ingest_event(&mut self, event: IngestEvent) {
        let now = Instant::now();
        match event {
            IngestEvent::Publish {
                key,
                address,
                accept,
            } => {
                let stream = self
                    .entries
                    .iter()
                    .find(|entry| entry.config.source.rtmp_key().as_deref() == Some(key.as_str()));
                let verdict = match stream {
                    None => Err("no stream takes this key"),
                    Some(entry) if entry.unusable.is_some() => Err("its stream can't run"),
                    Some(_) if self.ingest.publishers.contains_key(&key) => {
                        Err("the key is already publishing")
                    }
                    Some(_) => Ok(()),
                };
                match verdict {
                    Ok(()) => {
                        tracing::info!(%key, %address, "RTMP publish accepted");
                        self.ingest.publishers.insert(
                            key,
                            Publisher {
                                address,
                                video_kbps: None,
                                accepted: Some(now),
                                since: SystemTime::now(),
                                video_codec: None,
                                width: None,
                                height: None,
                            },
                        );
                    }
                    Err(why) => tracing::warn!(%key, %address, why, "RTMP publish refused"),
                }
                let _ = accept.send(verdict.is_ok());
            }
            IngestEvent::PublishDone { key } => {
                if self.ingest.publishers.remove(&key).is_some() {
                    tracing::info!(%key, "RTMP publisher stopped");
                }
            }
            IngestEvent::Publishers(Ok(found)) => {
                if self.ingest.last_error.take().is_some() {
                    tracing::info!("rtmp-ingest: nginx's statistics page reads again");
                }
                let recent = |publisher: &Publisher| {
                    publisher
                        .accepted
                        .is_some_and(|at| now.duration_since(at) < PUBLISH_GRACE)
                };
                self.ingest.publishers.retain(|key, publisher| {
                    let keep = found.contains_key(key) || recent(publisher);
                    if !keep {
                        tracing::info!(%key, "RTMP publisher gone (statistics page)");
                    }
                    keep
                });
                for (key, seen) in found {
                    let sample = seen.video_kbps.map(f64::from);
                    if let Some(publisher) = self.ingest.publishers.get_mut(&key) {
                        publisher.describe(&seen);
                        if let Some(sample) = sample {
                            publisher.video_kbps = Some(
                                publisher
                                    .video_kbps
                                    .map_or(sample, |smoothed| (smoothed + sample) / 2.0),
                            );
                        }
                        continue;
                    }
                    let known = self.entries.iter().any(|entry| {
                        entry.config.source.rtmp_key().as_deref() == Some(key.as_str())
                    });
                    if known {
                        tracing::info!(
                            %key, address = %seen.address, "RTMP publisher found (statistics page)"
                        );
                        let connected = Duration::from_millis(seen.connected_ms.unwrap_or(0));
                        let mut publisher = Publisher {
                            address: seen.address.clone(),
                            video_kbps: sample,
                            accepted: None,
                            since: SystemTime::now()
                                .checked_sub(connected)
                                .unwrap_or_else(SystemTime::now),
                            video_codec: None,
                            width: None,
                            height: None,
                        };
                        publisher.describe(&seen);
                        self.ingest.publishers.insert(key, publisher);
                    }
                }
                self.follow_sources();
            }
            IngestEvent::Publishers(Err(error)) | IngestEvent::HookFailed(error) => {
                if self.ingest.last_error.as_ref() != Some(&error) {
                    tracing::warn!(%error, "rtmp-ingest");
                }
                self.ingest.last_error = Some(error);
            }
        }
    }

    /// Adaptive RTMP streams' ceilings, from their cameras' bitrates: a change of more than 10%
    /// reaches a running encoder as a new range (SIGHUP), so the ceiling doesn't chase noise.
    fn follow_sources(&mut self) {
        for index in 0..self.entries.len() {
            let entry = &self.entries[index];
            let Some(profile) = entry.profile(&self.module.settings) else {
                continue;
            };
            let source = entry
                .config
                .source
                .rtmp_key()
                .and_then(|key| self.ingest.publishers.get(&key))
                .and_then(|publisher| publisher.video_kbps);
            let Some(source_kbps) = source else {
                continue;
            };
            let target = encoder::source_ceiling(&profile, entry.bitrate_kbps, source_kbps);
            let entry = &mut self.entries[index];
            // Rounded to whole kbps, for the shadow.
            #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
            let reported = source_kbps.round().clamp(0.0, f64::from(u32::MAX)) as u32;
            entry.source_kbps = Some(reported);
            let Some(target) = target else {
                continue;
            };
            let moved = entry.source_ceiling.is_none_or(|current| {
                u64::from(target.abs_diff(current)) * 10 > u64::from(current)
            });
            if !moved {
                continue;
            }
            tracing::info!(
                stream = %entry.id, source_kbps = reported, ceiling_kbps = target,
                "bitrate ceiling follows the camera"
            );
            entry.source_ceiling = Some(target);
            if entry.job.is_some() {
                self.reload_bitrate(index);
            }
        }
    }

    /// `rtmp_ingest` in the shadow, when it's enabled.
    fn ingest_report(&self) -> Value {
        if !self.module.settings.rtmp_ingest.enabled {
            return Value::Null;
        }
        let publishers: Map<String, Value> = self
            .ingest
            .publishers
            .iter()
            .map(|(key, publisher)| {
                // Rounded to whole kbps, for the shadow.
                #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
                let kbps = publisher
                    .video_kbps
                    .map(|kbps| kbps.round().clamp(0.0, f64::from(u32::MAX)) as u32);
                (
                    key.clone(),
                    json!({
                        "address": publisher.address,
                        "since": timestamp(publisher.since),
                        "video_codec": publisher.video_codec,
                        "width": publisher.width,
                        "height": publisher.height,
                        "video_kbps": kbps,
                    }),
                )
            })
            .collect();
        json!({
            "state": if self.ingest.last_error.is_some() { "degraded" } else { "ok" },
            "publishers": publishers,
            "last_error": self.ingest.last_error,
        })
    }

    async fn run(mut self, mut ctx: ModuleContext) -> Result<(), ModuleError> {
        let module = self.module;
        let settings = &module.settings;
        if let Some(encoders) = module.spawner.encoders(&settings.ffmpeg).await {
            for entry in &mut self.entries {
                entry.unusable = missing_encoders(settings, &entry.config, &encoders);
            }
            self.encoders = Some(encoders);
        }
        let mut snapshot = module.usb.snapshot();
        let mut stats = tokio::time::interval(settings.stats_interval());
        stats.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        let mut commands_open = true;
        let mut desired_open = true;
        let (ingest_tx, mut ingest_rx) = mpsc::unbounded_channel();
        let ingest_cancel = ctx.cancel.child_token();
        let ingest_task = settings.rtmp_ingest.enabled.then(|| {
            let ingest = &settings.rtmp_ingest;
            tokio::spawn(rtmp::run(
                ingest.hook_port,
                ingest.stat_url.clone(),
                ingest_tx,
                ingest_cancel.clone(),
            ))
        });
        // Desired state queued before the start (the daemon's saved state) applies before the
        // first pass, so a stream saved as stopped doesn't start for a moment.
        while let Ok(state) = ctx.desired.try_recv() {
            self.desired(&state, &ctx);
        }
        loop {
            let devices = snapshot.borrow_and_update().clone();
            self.devices = Arc::clone(&devices);
            self.read_formats();
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
                    Some(state) => self.desired(&state, &ctx),
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
                Some(event) = ingest_rx.recv() => self.ingest_event(event),
                Some((key, result)) = self.formats_rx.recv() => self.formats_read(key, result),
                Some((job, snapshot)) = self.sender_stats.recv() => {
                    self.senders.stats(job, snapshot, Instant::now());
                }
                _ = stats.tick() => self.stats(&ctx),
                () = tokio::time::sleep_until(wake) => {}
            }
        }
        ingest_cancel.cancel();
        if let Some(task) = ingest_task {
            let _ = task.await;
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
        let rtmp_key = self.entries[index].config.source.rtmp_key();
        if let Some(publisher) = rtmp_key
            .as_ref()
            .and_then(|key| self.ingest.publishers.get(key))
        {
            self.entries[index].camera = json!({"key": rtmp_key, "publisher": publisher.address});
        }
        if !self.input_ready(&self.entries[index]) {
            self.stop_job(index);
            let reason = if rtmp_key.is_some() {
                "publish_done"
            } else {
                "camera_removed"
            };
            self.disconnect(index, reason, ctx);
            let entry = &mut self.entries[index];
            entry.restart_at = None;
            // The next camera starts from the stream's own ceiling until it's measured.
            entry.source_ceiling = None;
            entry.source_kbps = None;
            entry.set_state(State::WaitingForInput);
            return;
        }
        self.connect(index, ctx);
        let stalled = self.entries[index].job.as_ref().map(|running| {
            (
                running.stalled(now),
                running.backend,
                running.advanced.is_some(),
            )
        });
        match stalled {
            Some((true, backend, advanced)) => {
                let name = backend.name();
                tracing::warn!(stream = %self.entries[index].id, "{name} stalled; restarting it");
                self.stop_job(index);
                let reason = if backend.reports_progress() || advanced {
                    format!("{name} stopped making progress")
                } else {
                    format!("{name} didn't connect over SRT in time")
                };
                self.failed_run(index, reason, now, ctx);
                return;
            }
            Some((false, ..)) => return,
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
                    && self.input_ready(entry)
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
        let entry = &self.entries[index];
        let (Some(profile), Some(output)) = (entry.profile(settings), entry.output(settings))
        else {
            return;
        };
        let target = ffmpeg::Target {
            output,
            streamid: &entry.config.streamid,
            sender_port: self.senders.port(&entry.config.output),
        };
        let url = entry.config.source.rtmp_key().map(|key| {
            format!(
                "rtmp://127.0.0.1:{}/{}/{key}",
                settings.rtmp_ingest.port,
                rtmp::APP
            )
        });
        let input = match (&entry.config.source, entry.nodes.as_ref(), url.as_deref()) {
            (Source::Test { size, fps }, _, _) => encoder::Input::Test { size, fps: *fps },
            (Source::Camera { .. }, Some(nodes), _) => encoder::Input::Camera(nodes),
            (Source::Rtmp { .. }, _, Some(url)) => encoder::Input::Rtmp(url),
            _ => return,
        };
        let range = encoder::Range::new(&profile, entry.bitrate_kbps, entry.source_ceiling);
        let plan = encoder::plan(settings, &entry.id, &profile, target, input, range);
        let backend = profile.encoder;
        if let Err(error) = write_files(&plan.files) {
            let message = format!("can't write {}'s files: {error}", backend.name());
            self.failed_run(index, message, Instant::now(), ctx);
            return;
        }
        let spec = JobSpec {
            name: entry.id.clone(),
            program: plan.program,
            args: plan.args,
            env: plan.env,
        };
        self.next_job += 1;
        let id = self.next_job;
        let entry = &mut self.entries[index];
        entry.restart_at = None;
        match module.spawner.spawn(&spec, id, self.events_tx.clone()) {
            Ok(job) => {
                tracing::info!(stream = %entry.id, encoder = backend.name(), "encoder started");
                entry.job = Some(Running {
                    id,
                    job,
                    started: Instant::now(),
                    advanced: None,
                    out_time_us: None,
                    backend,
                    watch: Watch::new(backend),
                });
                entry.progress = None;
                if entry.state != State::Reconnecting {
                    entry.set_state(State::Starting);
                }
            }
            Err(error) => {
                let message = format!("can't start {}: {error}", spec.program.display());
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
            let payload = json!({
                "stream_id": entry.id,
                "source": entry.status(&self.module.settings, false)["source"],
            });
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
            JobEvent::Stdout(line) => self.job_line(index, &line, true, now, ctx),
            JobEvent::Stderr(line) => self.job_line(index, &line, false, now, ctx),
            JobEvent::Exited(code) => {
                let entry = &mut self.entries[index];
                let Some(running) = entry.job.take() else {
                    return;
                };
                if now.duration_since(running.started) >= STABLE_RUN {
                    entry.backoff.reset();
                }
                let last = entry.lines.back().cloned();
                let name = running.backend.name();
                let reason = match (code, last) {
                    (_, Some(line)) => format!("{name} exited ({}): {line}", exit_text(code)),
                    (code, None) => format!("{name} exited ({})", exit_text(code)),
                };
                tracing::warn!(stream = %entry.id, %reason, "encoder exited");
                self.failed_run(index, reason, now, ctx);
            }
        }
    }

    /// A line of a stream job's output: ffmpeg's progress (stdout), or log lines, which for a
    /// GStreamer encoder include its SRT connection.
    fn job_line(
        &mut self,
        index: usize,
        line: &str,
        stdout: bool,
        now: Instant,
        ctx: &ModuleContext,
    ) {
        let entry = &mut self.entries[index];
        let Some(running) = entry.job.as_mut() else {
            return;
        };
        let signal = if stdout {
            running.watch.stdout(line)
        } else {
            running.watch.stderr(line)
        };
        let backend = running.backend;
        let advanced = match signal {
            Some(Signal::Progress(progress)) => {
                let moved = progress
                    .out_time_us
                    .is_some_and(|t| Some(t) > running.out_time_us);
                if moved {
                    running.out_time_us = progress.out_time_us;
                    running.advanced = Some(now);
                }
                entry.progress = Some(progress);
                moved
            }
            Some(Signal::Connected) => {
                running.advanced = Some(now);
                true
            }
            None => false,
        };
        // ffmpeg's stdout is its progress; everything else is kept for stream.status.
        if !(stdout && backend.reports_progress()) {
            tracing::debug!(stream = %entry.id, "{}: {line}", backend.name());
            if entry.lines.len() == LOG_LINES {
                entry.lines.pop_front();
            }
            entry.lines.push_back(line.to_owned());
        }
        if advanced && entry.state != State::Live {
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

    fn command(&mut self, name: &str, args: &Value) -> Outcome {
        let id = args.get("stream_id").and_then(Value::as_str);
        if name == "status" {
            return match id {
                None => Outcome::Ok(self.statuses(true)),
                Some(id) => match self.entries.iter().find(|entry| entry.id == id) {
                    Some(entry) => Outcome::Ok(entry.status(&self.module.settings, true)),
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
        let Ok(bitrate) = self.bitrate_change(index, args.get("bitrate_kbps")) else {
            return Outcome::error(
                codes::INVALID_MESSAGE,
                "bitrate_kbps is outside the profile's limits",
            );
        };
        if name == "start" {
            self.set_live(index, true, bitrate);
        } else {
            self.set_live(index, false, BitrateChange::Keep);
        }
        Outcome::Ok(self.entries[index].status(&self.module.settings, false))
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

    /// What a `bitrate_kbps` value asks for: absent, no change; `null` or the profile's own
    /// bitrate, back to the profile; another value within the profile's limits, an override.
    fn bitrate_change(&self, index: usize, value: Option<&Value>) -> Result<BitrateChange, ()> {
        let profile = self
            .module
            .settings
            .profiles
            .get(&self.entries[index].config.profile);
        match value {
            None => Ok(BitrateChange::Keep),
            Some(Value::Null) => Ok(BitrateChange::Profile),
            Some(value) => {
                let bitrate = value
                    .as_u64()
                    .and_then(|v| u32::try_from(v).ok())
                    .ok_or(())?;
                if profile.is_some_and(|profile| profile.bitrate_kbps == bitrate) {
                    Ok(BitrateChange::Profile)
                } else if self.bitrate_allowed(index, bitrate) {
                    Ok(BitrateChange::Override(bitrate))
                } else {
                    Err(())
                }
            }
        }
    }

    /// The desired state from a command or the shadow. Starting a failed stream gives it a new
    /// chance; a new bitrate restarts a running job.
    fn set_live(&mut self, index: usize, live: bool, bitrate: BitrateChange) {
        let entry = &mut self.entries[index];
        entry.desired_live = live;
        if live && entry.state == State::Failed && entry.unusable.is_none() {
            entry.failures.clear();
            entry.restart_at = None;
            entry.backoff.reset();
            entry.set_state(State::Stopped);
        }
        let profile_kbps = self
            .module
            .settings
            .profiles
            .get(&entry.config.profile)
            .map_or(entry.bitrate_kbps, |profile| profile.bitrate_kbps);
        entry.bitrate_override = match bitrate {
            BitrateChange::Keep => return,
            BitrateChange::Profile => None,
            BitrateChange::Override(bitrate) => Some(bitrate),
        };
        let bitrate = entry.bitrate_override.unwrap_or(profile_kbps);
        if bitrate != entry.bitrate_kbps {
            entry.bitrate_kbps = bitrate;
            if !self.reload_bitrate(index) {
                self.stop_job(index);
            }
        }
    }

    /// Gives a running GStreamer encoder the stream's new bitrate range (rewritten file, then
    /// SIGHUP); `false` if the job must restart instead (ffmpeg, or no job).
    fn reload_bitrate(&mut self, index: usize) -> bool {
        let settings = &self.module.settings;
        let entry = &self.entries[index];
        let (Some(running), Some(profile), Some(output)) = (
            entry.job.as_ref(),
            entry.profile(settings),
            entry.output(settings),
        ) else {
            return false;
        };
        if !running.backend.reloads() {
            return false;
        }
        let range = encoder::Range::new(&profile, entry.bitrate_kbps, entry.source_ceiling);
        let file = encoder::range_file(
            settings,
            running.backend,
            &entry.id,
            range,
            output.latency_ms,
        );
        match write_files(std::slice::from_ref(&file)) {
            Ok(()) => {
                tracing::info!(
                    stream = %entry.id, min_kbps = range.min_kbps, max_kbps = range.max_kbps,
                    "new bitrate range for {}", running.backend.name()
                );
                running.job.reload();
                true
            }
            Err(error) => {
                tracing::warn!(stream = %entry.id, %error, "can't write the bitrate range; restarting");
                false
            }
        }
    }

    /// The `stream` shadow's desired state (HLD section 7.3.7): `{"streams": {"<id>": {...}}}`
    /// with `state`, `bitrate_kbps` (an override, `null` for the profile's), and `source`,
    /// `profile`, `destination` and `source_ceiling_percent` (`null` for `helios.toml`'s). Each
    /// member present is applied in that order (settings first, so a bitrate is checked against
    /// the new profile) or refused, and a refusal is reported in the stream's `rejected` until a
    /// value for that setting is accepted.
    fn desired(&mut self, state: &Value, ctx: &ModuleContext) {
        let Some(streams) = state.get("streams").and_then(Value::as_object) else {
            return;
        };
        for (id, desired) in streams {
            let Some(index) = self.entries.iter().position(|entry| entry.id == *id) else {
                tracing::warn!(stream = %id, "desired state for an unknown stream");
                continue;
            };
            self.desired_settings(index, desired, ctx);
            let value = desired.get("bitrate_kbps");
            let bitrate = match self.bitrate_change(index, value) {
                Ok(change) => {
                    if value.is_some() {
                        self.accept(index, "bitrate");
                    }
                    change
                }
                Err(()) => {
                    let value = value.cloned().unwrap_or_default();
                    let reason = "bitrate_kbps is outside the profile's limits".to_owned();
                    self.reject(index, "bitrate", &value, reason);
                    BitrateChange::Keep
                }
            };
            match desired.get("state") {
                Some(value) if value == "live" || value == "stopped" => {
                    self.accept(index, "state");
                    self.set_live(index, value == "live", bitrate);
                }
                Some(value) => {
                    let reason = "state must be live or stopped".to_owned();
                    self.reject(index, "state", value, reason);
                }
                None if bitrate != BitrateChange::Keep => {
                    let live = self.entries[index].desired_live;
                    self.set_live(index, live, bitrate);
                }
                None => {}
            }
        }
    }

    /// The desired `profile`, `source`, `destination` and `source_ceiling_percent`. A changed
    /// source, profile or destination stops the job; the next pass starts it again with them.
    fn desired_settings(&mut self, index: usize, desired: &Value, ctx: &ModuleContext) {
        let settings = &self.module.settings;
        let mut reconfigured = false;
        if let Some(value) = desired.get("profile") {
            let entry = &self.entries[index];
            let wanted = match value {
                Value::Null => Ok(entry.configured.profile.clone()),
                Value::String(name) => Ok(name.clone()),
                _ => Err("profile must be a profile name".to_owned()),
            };
            let checked = wanted.and_then(|name| {
                let mut candidate = entry.config.clone();
                candidate.profile = name;
                self.check(index, &candidate).map(|()| candidate)
            });
            match checked {
                Ok(candidate) => {
                    self.accept(index, "profile");
                    if candidate.profile != self.entries[index].config.profile {
                        self.entries[index].config.profile = candidate.profile;
                        reconfigured = true;
                    }
                }
                Err(reason) => self.reject(index, "profile", value, reason),
            }
        }
        if let Some(value) = desired.get("source") {
            let entry = &self.entries[index];
            let wanted = match value {
                Value::Null => Ok(entry.configured.source.clone()),
                value => serde_json::from_value::<Source>(value.clone())
                    .map_err(|error| format!("source: {error}")),
            };
            let checked = wanted.and_then(|source| {
                let mut candidate = entry.config.clone();
                candidate.source = source;
                self.check(index, &candidate).map(|()| candidate)
            });
            match checked {
                Ok(candidate) => {
                    self.accept(index, "source");
                    if candidate.source != self.entries[index].config.source {
                        self.entries[index].config.source = candidate.source;
                        reconfigured = true;
                    }
                }
                Err(reason) => self.reject(index, "source", value, reason),
            }
        }
        if let Some(value) = desired.get("destination") {
            match self.destination_for(index, value) {
                Ok(destination) => {
                    self.accept(index, "destination");
                    let url = |d: &Option<(Destination, Output)>| d.as_ref().map(|(d, _)| d.url());
                    if url(&destination) != url(&self.entries[index].destination) {
                        self.set_destination(index, destination);
                        reconfigured = true;
                    }
                }
                Err(reason) => self.reject(index, "destination", value, reason),
            }
        }
        if let Some(value) = desired.get("source_ceiling_percent") {
            let wanted = match value {
                Value::Null => Ok(None),
                value => value
                    .as_u64()
                    .and_then(|percent| u32::try_from(percent).ok())
                    .filter(|percent| *percent <= 400)
                    .map(Some)
                    .ok_or_else(|| "source_ceiling_percent must be 0 to 400".to_owned()),
            };
            match wanted {
                Ok(percent) => {
                    self.accept(index, "source_ceiling_percent");
                    if percent != self.entries[index].ceiling_override {
                        self.set_ceiling(index, percent);
                    }
                }
                Err(reason) => self.reject(index, "source_ceiling_percent", value, reason),
            }
        }
        if reconfigured {
            tracing::info!(
                stream = %self.entries[index].id, profile = %self.entries[index].config.profile,
                output = %self.entries[index].config.output, "new settings from the desired state"
            );
            self.stop_job(index);
            self.disconnect(index, "reconfigured", ctx);
            let encoders = self.encoders.as_ref();
            let entry = &mut self.entries[index];
            entry.nodes = None;
            entry.camera = Value::Null;
            entry.source_ceiling = None;
            entry.source_kbps = None;
            entry.progress = None;
            entry.last_error = None;
            entry.restart_at = None;
            entry.failures.clear();
            entry.backoff.reset();
            entry.unusable =
                encoders.and_then(|encoders| missing_encoders(settings, &entry.config, encoders));
            if entry.state == State::Failed {
                entry.set_state(State::Stopped);
            }
            // The bitrate follows the new profile; an override outside its limits goes.
            if let Some(profile) = settings.profiles.get(&entry.config.profile) {
                let limits = profile.min_bitrate_kbps..=profile.max_bitrate_kbps;
                if entry
                    .bitrate_override
                    .is_some_and(|kbps| profile.video == "copy" || !limits.contains(&kbps))
                {
                    entry.bitrate_override = None;
                }
                entry.bitrate_kbps = entry.bitrate_override.unwrap_or(profile.bitrate_kbps);
            }
        }
    }

    /// Checks a stream's new source or profile as `helios.toml`'s are checked, and that ffmpeg
    /// has the profile's encoders and no other stream takes the RTMP key.
    fn check(&self, index: usize, candidate: &Stream) -> Result<(), String> {
        let settings = &self.module.settings;
        let entry = &self.entries[index];
        settings.check_stream(&entry.id, candidate)?;
        if let Some(key) = candidate.source.rtmp_key()
            && let Some(other) = self.entries.iter().find(|other| {
                other.id != entry.id && other.config.source.rtmp_key().as_ref() == Some(&key)
            })
        {
            return Err(format!(
                "{}: stream {} already takes RTMP key {key:?}",
                entry.id, other.id
            ));
        }
        if let Some(missing) = self
            .encoders
            .as_ref()
            .and_then(|encoders| missing_encoders(settings, candidate, encoders))
        {
            return Err(missing);
        }
        Ok(())
    }

    /// The destination a desired `destination` asks for: `None` for the configured one (`null`,
    /// or a URL equal to it).
    fn destination_for(
        &self,
        index: usize,
        value: &Value,
    ) -> Result<Option<(Destination, Output)>, String> {
        let settings = &self.module.settings;
        let entry = &self.entries[index];
        let url = match value {
            Value::Null => return Ok(None),
            Value::String(url) => url,
            _ => return Err("destination must be an srt:// or srtla:// URL".into()),
        };
        let destination = Destination::parse(url)?;
        let Some(base) = settings.outputs.get(&entry.configured.output) else {
            return Err(format!("no output {:?}", entry.configured.output));
        };
        if destination.url() == Destination::of_output(base, &entry.configured.streamid).url() {
            return Ok(None);
        }
        let output = destination.output(base, &settings.srtla_uplinks);
        if output.mode == "srtla" && output.uplinks.is_empty() {
            return Err(
                "an srtla:// destination needs uplinks: modules.stream.srtla_uplinks is empty"
                    .into(),
            );
        }
        Ok(Some((destination, output)))
    }

    /// Points the stream at `destination` (`None`: the configured output), with its own sender
    /// if it's SRTLA.
    fn set_destination(&mut self, index: usize, destination: Option<(Destination, Output)>) {
        let settings = &self.module.settings;
        let entry = &mut self.entries[index];
        let name = format!("stream:{}", entry.id);
        let sender = destination
            .as_ref()
            .filter(|(_, output)| output.mode == "srtla")
            .and_then(|(_, output)| {
                Some((output.clone(), settings.stream_sender_port(&entry.id)?))
            });
        match &destination {
            Some((url, _)) => {
                entry.config.output.clone_from(&name);
                entry.config.streamid = url
                    .streamid
                    .clone()
                    .unwrap_or_else(|| entry.configured.streamid.clone());
            }
            None => {
                entry.config.output.clone_from(&entry.configured.output);
                entry.config.streamid.clone_from(&entry.configured.streamid);
            }
        }
        entry.destination = destination;
        self.senders.set_dynamic(&name, sender);
    }

    /// A new ceiling percentage: the ceiling is worked out again from the camera's bitrate, and
    /// a running GStreamer encoder takes it without a restart.
    fn set_ceiling(&mut self, index: usize, percent: Option<u32>) {
        let entry = &mut self.entries[index];
        entry.ceiling_override = percent;
        entry.source_ceiling = None;
        self.follow_sources();
        let entry = &self.entries[index];
        if entry.source_ceiling.is_none() && entry.job.is_some() && !self.reload_bitrate(index) {
            self.stop_job(index);
        }
    }

    /// Records a refused desired value; the same value again keeps its first time.
    fn reject(&mut self, index: usize, setting: &'static str, value: &Value, reason: String) {
        let entry = &mut self.entries[index];
        if entry
            .rejected
            .get(setting)
            .is_some_and(|rejected| rejected.value == *value)
        {
            return;
        }
        tracing::warn!(stream = %entry.id, setting, %reason, "desired setting refused");
        entry.rejected.insert(
            setting,
            Rejected {
                value: value.clone(),
                reason,
                at: SystemTime::now(),
            },
        );
    }

    fn accept(&mut self, index: usize, setting: &str) {
        self.entries[index].rejected.remove(setting);
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
                .map(|entry| {
                    (
                        entry.id.clone(),
                        entry.status(&self.module.settings, with_log),
                    )
                })
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
        let ingest = self.ingest_report();
        let profiles = inputs::profiles(&self.module.settings);
        let keys = self.rtmp_keys();
        let settings = &self.module.settings;
        let mut inputs = inputs::inputs(settings, &self.devices, &self.formats, &keys, true);
        let mut full = json!({
            "streams": streams, "outputs": self.outputs_report(now, false), "rtmp_ingest": ingest,
            "profiles": profiles, "inputs": inputs,
        });
        let too_big = full.to_string().len() > REPORT_BUDGET;
        if too_big {
            inputs = inputs::inputs(settings, &self.devices, &self.formats, &keys, false);
            full["inputs"] = inputs.clone();
        }
        if too_big != self.formats_left_out {
            if too_big {
                tracing::warn!(
                    "the stream shadow is near AWS IoT's 8 KB: cameras' formats left out"
                );
            }
            self.formats_left_out = too_big;
        }
        let significant = json!({
            "streams": quiet_streams, "outputs": self.outputs_report(now, true),
            "rtmp_ingest": ingest, "profiles": profiles, "inputs": inputs,
        });
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

    /// The senders' report, with `null` for each stream's destination sender that isn't there:
    /// the shadow keeps a nested key until it's set to `null`.
    fn outputs_report(&self, now: Instant, significant: bool) -> Value {
        let mut outputs = self.senders.report(now, significant);
        if let Some(outputs) = outputs.as_object_mut() {
            for entry in &self.entries {
                outputs
                    .entry(format!("stream:{}", entry.id))
                    .or_insert(Value::Null);
            }
        }
        outputs
    }

    /// The next time something needs looking at: a restart, a stall check, or a pending
    /// encoder report.
    fn next_wake(&self, now: Instant) -> Instant {
        let mut wake = now + Duration::from_secs(3600);
        for entry in &self.entries {
            if let Some(at) = entry.restart_at {
                wake = wake.min(at);
            }
            if let Some(at) = entry.job.as_ref().and_then(Running::deadline) {
                wake = wake.min(at);
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

/// Writes a job's files (a GStreamer encoder's pipeline and bitrate range), each replaced in
/// one step so a SIGHUP never reads half a file.
fn write_files(files: &[(PathBuf, String)]) -> std::io::Result<()> {
    for (path, contents) in files {
        if let Some(dir) = path.parent() {
            std::fs::create_dir_all(dir)?;
        }
        let partial = path.with_extension("partial");
        std::fs::write(&partial, contents)?;
        std::fs::rename(&partial, path)?;
    }
    Ok(())
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
    if profile.encoder != Backend::Ffmpeg {
        return None; // GStreamer elements; a missing one fails the job with its message
    }
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

/// A source as the shadow shows it (and as `helios.toml` writes it).
fn source_value(source: &Source) -> Value {
    match source {
        Source::Camera { video, audio } => {
            json!({"type": "camera", "video": video, "audio": audio})
        }
        Source::Rtmp { camera } => json!({"type": "rtmp", "camera": camera}),
        Source::Test { size, fps } => json!({"type": "test", "size": size, "fps": fps}),
    }
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
    let Some(name) = inputs::capture_node(camera) else {
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
