//! `[modules.stream]` (LLD 4, section 6.2): outputs, profiles and streams, checked at start-up.
//!
//! This version runs USB-camera and test-pattern streams to `direct` or `srtla` SRT outputs. RTMP
//! sources (`rtmp-ingest`) come in a later version; a config that uses them is refused with a
//! message saying so, rather than ignored. SRT URLs, passphrases included, aren't secrets (owner,
//! 2026-11-21), so the passphrase is set here.

use std::collections::BTreeMap;
use std::path::PathBuf;
use std::time::Duration;

use serde::Deserialize;

/// The stream module's settings.
#[derive(Debug, Clone, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct StreamSettings {
    pub(crate) enabled: bool,
    /// The ffmpeg to run.
    pub(crate) ffmpeg: PathBuf,
    /// The `srtla_send` to run for `srtla` outputs.
    pub(crate) srtla_send: PathBuf,
    /// The stream daemon's control socket (LLD 4, section 15), which Helios connects to.
    pub(crate) control_socket: PathBuf,
    /// Where the daemon keeps the desired state across its restarts.
    pub(crate) state_dir: PathBuf,
    /// The user whose processes may use the control socket (besides root and the daemon's
    /// own user): Helios's.
    pub(crate) client_user: String,
    /// Where senders' IP files and control sockets go (`<runtime_dir>/srtla/`): the daemon's
    /// `RuntimeDirectory`, and where the upgrade's `restart-pending` file appears.
    pub(crate) runtime_dir: PathBuf,
    /// The first local UDP port for senders: outputs get consecutive ports in name order.
    pub(crate) srtla_port_base: u16,
    /// How long a sender stays up after its last stream stops, so a source that comes back
    /// keeps a warm bond.
    sender_idle_s: u64,
    /// How often `stream.stats` goes out while a stream is live.
    stats_interval_s: u64,
    pub(crate) outputs: BTreeMap<String, Output>,
    pub(crate) profiles: BTreeMap<String, Profile>,
    pub(crate) streams: BTreeMap<String, Stream>,
}

impl Default for StreamSettings {
    fn default() -> Self {
        Self {
            enabled: true,
            ffmpeg: "/usr/lib/helios-ffmpeg/bin/ffmpeg".into(),
            srtla_send: "/usr/bin/srtla_send".into(),
            control_socket: "/run/helios-stream/control.sock".into(),
            state_dir: "/var/lib/helios-stream".into(),
            client_user: "helios".into(),
            runtime_dir: "/run/helios-stream".into(),
            srtla_port_base: 6000,
            sender_idle_s: 60,
            stats_interval_s: 30,
            outputs: BTreeMap::new(),
            profiles: BTreeMap::new(),
            streams: BTreeMap::new(),
        }
    }
}

/// Where a stream goes.
#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Output {
    /// `direct`: ffmpeg calls the SRT listener. (`srtla` comes with `srtla-sender`.)
    pub(crate) mode: String,
    pub(crate) host: String,
    pub(crate) port: u16,
    #[serde(default = "default_latency_ms")]
    pub(crate) latency_ms: u32,
    /// Which uplinks to bond (srtla only).
    #[serde(default)]
    pub(crate) uplinks: Vec<String>,
    /// The SRT passphrase (10 to 79 characters), or none for an unencrypted stream. Not a
    /// secret.
    #[serde(default)]
    pub(crate) passphrase: Option<String>,
}

fn default_latency_ms() -> u32 {
    2000
}

/// How a stream is encoded.
#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Profile {
    /// `copy`, `libx264`, `libx265` (software; the harness's HEVC), `h264_rkmpp`, `hevc_rkmpp` or
    /// `h264_v4l2m2m`.
    pub(crate) video: String,
    #[serde(default = "default_bitrate")]
    pub(crate) bitrate_kbps: u32,
    #[serde(default = "default_min_bitrate")]
    pub(crate) min_bitrate_kbps: u32,
    #[serde(default = "default_max_bitrate")]
    pub(crate) max_bitrate_kbps: u32,
    /// Keyframe interval in seconds, whatever the frame rate.
    #[serde(default = "default_gop_s")]
    pub(crate) gop_s: u32,
    /// `WIDTHxHEIGHT`, or empty for the input's size.
    #[serde(default)]
    pub(crate) scale: String,
    /// `aac` or `none` for cameras (ALSA audio is raw PCM, so it can't be copied into
    /// MPEG-TS); `copy` for RTMP sources.
    #[serde(default = "default_audio")]
    pub(crate) audio: String,
    /// For cameras: what to ask the camera for.
    #[serde(default)]
    pub(crate) input: CameraInput,
}

fn default_bitrate() -> u32 {
    6000
}
fn default_min_bitrate() -> u32 {
    500
}
fn default_max_bitrate() -> u32 {
    20_000
}
fn default_gop_s() -> u32 {
    2
}
fn default_audio() -> String {
    "aac".into()
}

/// What a profile asks a V4L2 camera for; empty fields leave it to the camera.
#[derive(Debug, Clone, Default, Deserialize, PartialEq, Eq)]
#[serde(default, deny_unknown_fields)]
pub struct CameraInput {
    /// `mjpeg`, `h264`, `yuyv422`, `nv12`, …
    pub(crate) format: String,
    /// `WIDTHxHEIGHT`.
    pub(crate) size: String,
    pub(crate) fps: u32,
}

/// What a stream reads.
#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
#[serde(tag = "type", rename_all = "lowercase", deny_unknown_fields)]
pub enum Source {
    /// A USB camera, by stable port (`usb:1-1.3`) or key (`0bda:8153:SERIAL`), with optional
    /// audio from a USB device chosen the same way.
    Camera {
        video: String,
        #[serde(default)]
        audio: Option<String>,
    },
    /// RTMP from `rtmp-ingest`: key `ingest`, or `ingest-<camera>`. Not supported yet.
    Rtmp {
        #[serde(default)]
        camera: Option<u32>,
    },
    /// A generated test pattern with a tone: checks the whole chain without a camera.
    Test {
        #[serde(default = "default_test_size")]
        size: String,
        #[serde(default = "default_test_fps")]
        fps: u32,
    },
}

fn default_test_size() -> String {
    "1280x720".into()
}
fn default_test_fps() -> u32 {
    30
}

/// One configured stream.
#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Stream {
    pub(crate) source: Source,
    pub(crate) profile: String,
    pub(crate) output: String,
    /// The SRT stream ID, for example `publish/live/backpack-01`.
    pub(crate) streamid: String,
    /// `live` (run whenever the source is ready) or `stopped`.
    #[serde(default = "default_desired")]
    pub(crate) desired: String,
}

fn default_desired() -> String {
    "live".into()
}

/// Encoders profiles may name.
pub(crate) const ENCODERS: [&str; 6] = [
    "copy",
    "libx264",
    "libx265",
    "h264_rkmpp",
    "hevc_rkmpp",
    "h264_v4l2m2m",
];

impl StreamSettings {
    /// Checks the settings; `None` when the module is disabled.
    ///
    /// # Errors
    ///
    /// A message naming the setting that's wrong.
    pub(crate) fn check(self) -> Result<Option<Self>, String> {
        if !(5..=3600).contains(&self.stats_interval_s) {
            return Err("modules.stream.stats_interval_s must be 5 to 3600".into());
        }
        if !(1..=3600).contains(&self.sender_idle_s) {
            return Err("modules.stream.sender_idle_s must be 1 to 3600".into());
        }
        let last_port = usize::from(self.srtla_port_base) + self.outputs.len();
        if self.srtla_port_base < 1024 || last_port > 65535 {
            return Err(
                "modules.stream.srtla_port_base must leave a port per output in 1024 to 65535"
                    .into(),
            );
        }
        for (name, output) in &self.outputs {
            let at = format!("modules.stream.outputs.{name}");
            check_name(name, &at)?;
            match output.mode.as_str() {
                "direct" => {
                    if !output.uplinks.is_empty() {
                        return Err(format!("{at}.uplinks is only for srtla outputs"));
                    }
                }
                "srtla" => {
                    if output.uplinks.is_empty() {
                        return Err(format!("{at}.uplinks must name at least one uplink"));
                    }
                    for uplink in &output.uplinks {
                        if !valid_uplink(uplink) {
                            return Err(format!(
                                "{at}.uplinks: {uplink:?} must be usb:ethernet, usb:cellular, \
                                 usb:wifi or an interface name"
                            ));
                        }
                    }
                }
                other => return Err(format!("{at}.mode must be direct or srtla, not {other:?}")),
            }
            if output.host.is_empty()
                || !output
                    .host
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b"-._:".contains(&b))
            {
                return Err(format!("{at}.host must be a host name or IP address"));
            }
            if output.port == 0 {
                return Err(format!("{at}.port must be 1 to 65535"));
            }
            if !(20..=30_000).contains(&output.latency_ms) {
                return Err(format!("{at}.latency_ms must be 20 to 30000"));
            }
            if let Some(passphrase) = &output.passphrase
                && (!(10..=79).contains(&passphrase.len())
                    || !passphrase
                        .bytes()
                        .all(|b| b.is_ascii_alphanumeric() || b"-._~!$'()*+,;:@".contains(&b)))
            {
                return Err(format!(
                    "{at}.passphrase must be 10 to 79 letters, digits or - . _ ~ ! $ ' ( ) * +                      , ; : @"
                ));
            }
        }
        for (name, profile) in &self.profiles {
            let at = format!("modules.stream.profiles.{name}");
            check_name(name, &at)?;
            if !ENCODERS.contains(&profile.video.as_str()) {
                return Err(format!("{at}.video must be one of {}", ENCODERS.join(", ")));
            }
            if !["aac", "none", "copy"].contains(&profile.audio.as_str()) {
                return Err(format!("{at}.audio must be aac, none or copy"));
            }
            if profile.min_bitrate_kbps < 100
                || profile.max_bitrate_kbps > 100_000
                || !(profile.min_bitrate_kbps..=profile.max_bitrate_kbps)
                    .contains(&profile.bitrate_kbps)
            {
                return Err(format!(
                    "{at}: bitrate_kbps must be within min_bitrate_kbps to max_bitrate_kbps, \
                     inside 100 to 100000"
                ));
            }
            if !(1..=10).contains(&profile.gop_s) {
                return Err(format!("{at}.gop_s must be 1 to 10"));
            }
            for (field, value) in [
                ("scale", &profile.scale),
                ("input.size", &profile.input.size),
            ] {
                if !value.is_empty() && parse_size(value).is_none() {
                    return Err(format!("{at}.{field} must be WIDTHxHEIGHT"));
                }
            }
            if !profile.input.format.is_empty()
                && !profile
                    .input
                    .format
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'_')
            {
                return Err(format!("{at}.input.format must be a pixel or codec name"));
            }
            if profile.input.fps > 240 {
                return Err(format!("{at}.input.fps must be 0 to 240"));
            }
            if profile.video == "copy" && !profile.scale.is_empty() {
                return Err(format!("{at}: scale needs an encoder, not copy"));
            }
        }
        for (name, stream) in &self.streams {
            let at = format!("modules.stream.streams.{name}");
            check_name(name, &at)?;
            let Some(profile) = self.profiles.get(&stream.profile) else {
                return Err(format!("{at}.profile: no profile {:?}", stream.profile));
            };
            if !self.outputs.contains_key(&stream.output) {
                return Err(format!("{at}.output: no output {:?}", stream.output));
            }
            match &stream.source {
                Source::Rtmp { .. } => {
                    return Err(format!("{at}: RTMP sources aren't supported yet"));
                }
                Source::Test { size, fps } => {
                    if parse_size(size).is_none() || !(1..=120).contains(fps) {
                        return Err(format!(
                            "{at}.source: a test pattern needs size WIDTHxHEIGHT and fps 1 to 120"
                        ));
                    }
                    if profile.video == "copy" || profile.audio == "copy" {
                        return Err(format!(
                            "{at}: a test pattern is generated, so its profile needs encoders, \
                             not copy"
                        ));
                    }
                }
                Source::Camera { video, audio } => {
                    for selector in std::iter::once(video).chain(audio) {
                        if !valid_selector(selector) {
                            return Err(format!(
                                "{at}.source: {selector:?} must be usb:<port> or \
                                 <vid>:<pid>:<serial>"
                            ));
                        }
                    }
                    if audio.is_some() && profile.audio == "copy" {
                        return Err(format!(
                            "{at}: camera audio is raw PCM, so its profile needs audio = \
                             \"aac\" or \"none\""
                        ));
                    }
                }
            }
            if stream.streamid.is_empty()
                || stream.streamid.len() > 512
                || !stream
                    .streamid
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b"/_.-:=,".contains(&b))
            {
                return Err(format!(
                    "{at}.streamid must be letters, digits and / _ . - : = ,"
                ));
            }
            if !["live", "stopped"].contains(&stream.desired.as_str()) {
                return Err(format!("{at}.desired must be live or stopped"));
            }
        }
        Ok(self.enabled.then_some(self))
    }

    pub(crate) fn sender_idle(&self) -> Duration {
        Duration::from_secs(self.sender_idle_s)
    }

    /// Each `srtla` output's local port: consecutive from `srtla_port_base`, in name order.
    pub(crate) fn sender_port(&self, output: &str) -> Option<u16> {
        let index = self.outputs.keys().position(|name| name == output)?;
        self.srtla_port_base.checked_add(u16::try_from(index).ok()?)
    }

    pub(crate) fn stats_interval(&self) -> Duration {
        Duration::from_secs(self.stats_interval_s)
    }
}

fn check_name(name: &str, at: &str) -> Result<(), String> {
    if name.is_empty()
        || name.len() > 64
        || !name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
    {
        return Err(format!("{at}: names are letters, digits, - and _"));
    }
    Ok(())
}

/// `usb:<port>` or `<vid>:<pid>:<serial>`.
fn valid_selector(selector: &str) -> bool {
    if let Some(port) = selector.strip_prefix("usb:") {
        return crate::modules::usb::is_port(port);
    }
    let mut parts = selector.splitn(3, ':');
    let hex4 = |part: Option<&str>| {
        part.is_some_and(|p| p.len() == 4 && p.bytes().all(|b| b.is_ascii_hexdigit()))
    };
    hex4(parts.next()) && hex4(parts.next()) && parts.next().is_some_and(|s| !s.is_empty())
}

/// `usb:ethernet`, `usb:cellular`, `usb:wifi`, or an interface name.
fn valid_uplink(uplink: &str) -> bool {
    matches!(uplink, "usb:ethernet" | "usb:cellular" | "usb:wifi")
        || (!uplink.is_empty()
            && uplink.len() <= 15
            && uplink
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"-_.".contains(&b)))
}

/// `WIDTHxHEIGHT`, each 16 to 8192.
pub(crate) fn parse_size(size: &str) -> Option<(u32, u32)> {
    let (width, height) = size.split_once('x')?;
    let width: u32 = width.parse().ok()?;
    let height: u32 = height.parse().ok()?;
    ((16..=8192).contains(&width) && (16..=8192).contains(&height)).then_some((width, height))
}
