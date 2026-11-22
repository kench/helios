//! Encoder backends: what encodes a stream and sends it over SRT (LLD 4, adaptive bitrate).
//!
//! - `ffmpeg` (the default): a fixed bitrate; a new bitrate restarts it. Its `-progress` output
//!   shows it's live and lets a stall be caught.
//! - `belacoder` (BELABOX) and `ceracoder` (its CERALIVE fork): a GStreamer pipeline from a file,
//!   sent over SRT by the encoder itself, which adapts the video bitrate within a range to what
//!   the link carries (`bitrate_mode = "adaptive"`), or holds it (`"fixed"`). The range is in a
//!   file they reread on SIGHUP, so a new bitrate needs no restart. They print no running
//!   statistics: a stream is live once they log `SRT connected`, and they exit by themselves when
//!   the pipeline stalls or SRT fails.
//!
//! belacoder sets the encoder's `bitrate` property (BELABOX's Rockchip plugin and `x264enc`
//! have one); ceracoder sets `bps`, which `x264enc` doesn't have, so settings refuse that pair.
//! Upstream, neither sets an SRT passphrase: helios-packages' builds add `-p <passphrase>`
//! (`SRTO_PASSPHRASE`), which outputs with a passphrase use. SRT passphrases aren't secrets
//! (owner, 2026-11-21), so it's an argument, as it's in ffmpeg's SRT URL.

use std::path::{Path, PathBuf};

use serde::Deserialize;

use super::ffmpeg::{self, CameraNodes, Progress, ProgressParser, Target};
use super::settings::{Profile, StreamSettings, parse_size};

/// What encodes a stream (a profile's `encoder`).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Backend {
    #[default]
    Ffmpeg,
    Belacoder,
    Ceracoder,
}

impl Backend {
    pub(crate) fn name(self) -> &'static str {
        match self {
            Self::Ffmpeg => "ffmpeg",
            Self::Belacoder => "belacoder",
            Self::Ceracoder => "ceracoder",
        }
    }

    /// Whether it takes a new bitrate range on SIGHUP (otherwise a new bitrate restarts it).
    pub(crate) fn reloads(self) -> bool {
        self != Self::Ffmpeg
    }

    /// Whether it reports progress, so a stall can be caught from here.
    pub(crate) fn reports_progress(self) -> bool {
        self == Self::Ffmpeg
    }

    /// The video encoders it can drive.
    pub(crate) fn video_encoders(self) -> &'static [&'static str] {
        match self {
            Self::Ffmpeg => &[],
            Self::Belacoder => &["hevc_rkmpp", "h264_rkmpp", "libx264"],
            Self::Ceracoder => &["hevc_rkmpp", "h264_rkmpp"],
        }
    }
}

/// A profile's `bitrate_mode`.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum BitrateMode {
    /// The stream's bitrate, held.
    #[default]
    Fixed,
    /// Between the profile's `min_bitrate_kbps` and the stream's bitrate (its ceiling), as the
    /// link allows.
    Adaptive,
}

/// The video bitrate range an encoder works in; both ends equal for a fixed bitrate.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Range {
    pub min_kbps: u32,
    pub max_kbps: u32,
}

impl Range {
    /// The range for `profile` with the stream's bitrate `kbps` (an override or the profile's),
    /// and for an adaptive stream the ceiling its source sets, if any (never above `kbps`).
    pub(crate) fn new(profile: &Profile, kbps: u32, source_ceiling: Option<u32>) -> Self {
        match profile.bitrate_mode {
            BitrateMode::Fixed => Self {
                min_kbps: kbps,
                max_kbps: kbps,
            },
            BitrateMode::Adaptive => {
                let max_kbps = source_ceiling.map_or(kbps, |ceiling| ceiling.min(kbps));
                Self {
                    min_kbps: profile.min_bitrate_kbps.min(max_kbps),
                    max_kbps,
                }
            }
        }
    }
}

/// The ceiling an adaptive stream's source sets: its video bitrate times `percent`, within the
/// profile's minimum and the stream's bitrate `kbps`. `None` when it doesn't follow its source.
pub(crate) fn source_ceiling(profile: &Profile, kbps: u32, source_kbps: f64) -> Option<u32> {
    if profile.bitrate_mode != BitrateMode::Adaptive || profile.source_ceiling_percent == 0 {
        return None;
    }
    let target = source_kbps * f64::from(profile.source_ceiling_percent) / 100.0;
    let floor = f64::from(profile.min_bitrate_kbps.min(kbps));
    // In range of u32 after the clamp.
    #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
    let ceiling = target.clamp(floor, f64::from(kbps)).round() as u32;
    Some(ceiling)
}

/// Where a stream's video comes from, as the encoder reads it.
#[derive(Debug, Clone, Copy)]
pub(crate) enum Input<'a> {
    Test {
        size: &'a str,
        fps: u32,
    },
    Camera(&'a CameraNodes),
    /// The RTMP URL to read back from nginx.
    Rtmp(&'a str),
}

/// What to run, and the files to write before it starts.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Plan {
    pub program: PathBuf,
    pub args: Vec<String>,
    pub env: Vec<(String, String)>,
    pub files: Vec<(PathBuf, String)>,
}

/// The job for one stream.
pub(crate) fn plan(
    settings: &StreamSettings,
    stream_id: &str,
    profile: &Profile,
    target: Target<'_>,
    input: Input<'_>,
    range: Range,
) -> Plan {
    let backend = profile.encoder;
    if backend == Backend::Ffmpeg {
        let kbps = range.max_kbps;
        let args = match input {
            Input::Test { size, fps } => ffmpeg::test_args(profile, target, size, fps, kbps),
            Input::Camera(nodes) => ffmpeg::camera_args(profile, target, nodes, kbps),
            Input::Rtmp(url) => ffmpeg::rtmp_args(profile, target, url, kbps),
        };
        return Plan {
            program: settings.ffmpeg.clone(),
            args,
            env: Vec::new(),
            files: Vec::new(),
        };
    }
    let pipeline_file = file(settings, stream_id, "pipeline");
    let mut args = vec![
        "-s".to_owned(),
        target.streamid.to_owned(),
        "-l".to_owned(),
        target.output.latency_ms.to_string(),
    ];
    if let Some(passphrase) = &target.output.passphrase {
        args.extend(["-p".to_owned(), passphrase.clone()]);
    }
    let mut files = vec![(pipeline_file.clone(), pipeline(profile, input))];
    let range_file = range_file(
        settings,
        backend,
        stream_id,
        range,
        target.output.latency_ms,
    );
    args.push(
        if backend == Backend::Ceracoder {
            "-c"
        } else {
            "-b"
        }
        .to_owned(),
    );
    args.push(range_file.0.display().to_string());
    files.push(range_file);
    let (host, port) = match target.sender_port {
        Some(port) => ("127.0.0.1".to_owned(), port),
        None => (target.output.host.clone(), target.output.port),
    };
    args.extend([pipeline_file.display().to_string(), host, port.to_string()]);
    let program = match backend {
        Backend::Ceracoder => settings.ceracoder.clone(),
        _ => settings.belacoder.clone(),
    };
    let path = &settings.gst_plugin_path;
    let env = if path.as_os_str().is_empty() {
        Vec::new()
    } else {
        vec![("GST_PLUGIN_PATH".to_owned(), path.display().to_string())]
    };
    Plan {
        program,
        args,
        env,
        files,
    }
}

/// The bitrate range file for a GStreamer encoder: belacoder's two lines in bps, or ceracoder's
/// INI in kbps. Rewritten, then SIGHUP, for a new bitrate.
pub(crate) fn range_file(
    settings: &StreamSettings,
    backend: Backend,
    stream_id: &str,
    range: Range,
    latency_ms: u32,
) -> (PathBuf, String) {
    match backend {
        Backend::Ceracoder => {
            let balancer = if range.min_kbps == range.max_kbps {
                "fixed"
            } else {
                "adaptive"
            };
            (
                file(settings, stream_id, "conf"),
                format!(
                    "# Written by the Helios stream daemon.\n[general]\nmin_bitrate = {}\n\
                     max_bitrate = {}\nbalancer = {balancer}\n\n[srt]\nlatency = {latency_ms}\n",
                    range.min_kbps, range.max_kbps
                ),
            )
        }
        _ => (
            file(settings, stream_id, "bitrate"),
            format!(
                "{}\n{}\n",
                u64::from(range.min_kbps) * 1000,
                u64::from(range.max_kbps) * 1000
            ),
        ),
    }
}

/// `<runtime_dir>/encoders/<stream>.<extension>`.
fn file(settings: &StreamSettings, stream_id: &str, extension: &str) -> PathBuf {
    encoders_dir(&settings.runtime_dir).join(format!("{stream_id}.{extension}"))
}

/// Where the GStreamer encoders' files go.
pub(crate) fn encoders_dir(runtime_dir: &Path) -> PathBuf {
    runtime_dir.join("encoders")
}

/// The GStreamer pipeline: video and audio into MPEG-TS, to `appsink name=appsink` (which the
/// encoder sends over SRT). The video encoder is `venc_bps` (Rockchip, bits per second) or
/// `venc_kbps` (`x264enc`), whose bitrate the encoder sets and adapts.
pub(crate) fn pipeline(profile: &Profile, input: Input<'_>) -> String {
    let hardware = profile.video.ends_with("_rkmpp");
    let scale = parse_size(&profile.scale);
    let fps = match input {
        Input::Test { fps, .. } => fps,
        _ if profile.input.fps > 0 => profile.input.fps,
        _ => 30,
    };
    let gop = profile.gop_s * fps;
    let mut lines: Vec<String> = Vec::new();

    // Video, decoded.
    match input {
        Input::Test { size, fps } => {
            let (width, height) = parse_size(size).unwrap_or((1280, 720));
            lines.push(format!(
                "videotestsrc is-live=true pattern=smpte ! \
                 video/x-raw,width={width},height={height},framerate={fps}/1 ! videoconvert !"
            ));
        }
        Input::Camera(nodes) => {
            let mut caps = Vec::new();
            if let Some((width, height)) = parse_size(&profile.input.size) {
                caps.push(format!("width={width},height={height}"));
            }
            if profile.input.fps > 0 {
                caps.push(format!("framerate={}/1", profile.input.fps));
            }
            let caps = caps.iter().map(|c| format!(",{c}")).collect::<String>();
            let device = nodes.video.display();
            if profile.input.format == "mjpeg" {
                let decoder = if hardware { "mppjpegdec" } else { "jpegdec" };
                lines.push(format!(
                    "v4l2src device={device} ! image/jpeg{caps} ! queue ! {decoder} !"
                ));
            } else {
                lines.push(format!(
                    "v4l2src device={device} ! video/x-raw,format=YUY2{caps} ! videoconvert !"
                ));
            }
        }
        Input::Rtmp(url) => {
            let decoder = if hardware {
                "mppvideodec"
            } else {
                "avdec_h264"
            };
            lines.push(format!("rtmpsrc location={url} ! flvdemux name=demux"));
            lines.push(String::new());
            lines.push(format!(
                "demux.video ! queue max-size-time=10000000000 max-size-buffers=1000 \
                 max-size-bytes=41943040 ! h264parse ! {decoder} !"
            ));
            if profile.input.fps > 0 {
                lines.push(format!(
                    "videorate ! video/x-raw,framerate={}/1 !",
                    profile.input.fps
                ));
            }
        }
    }

    // Scaled, and encoded.
    if hardware {
        let element = if profile.video == "hevc_rkmpp" {
            "mpph265enc"
        } else {
            "mpph264enc"
        };
        let size = scale.map_or_else(String::new, |(w, h)| format!(" width={w} height={h}"));
        let parser = if profile.video == "hevc_rkmpp" {
            "h265parse"
        } else {
            "h264parse"
        };
        lines.push(format!(
            "queue ! {element} name=venc_bps zero-copy-pkt=0 qp-max=51 gop={gop}{size} ! \
             {parser} config-interval=-1 ! queue ! mux."
        ));
    } else {
        if let Some((width, height)) = scale {
            lines.push(format!(
                "videoconvert ! videoscale ! video/x-raw,width={width},height={height} !"
            ));
        }
        lines.push(format!(
            "queue ! x264enc name=venc_kbps speed-preset=veryfast tune=zerolatency \
             key-int-max={gop} ! h264parse config-interval=-1 ! queue ! mux."
        ));
    }

    // Audio.
    let aac = "audioconvert ! audioresample ! voaacenc bitrate=128000 ! aacparse ! queue ! mux.";
    if profile.audio != "none" {
        lines.push(String::new());
        match input {
            Input::Test { .. } => lines.push(format!(
                "audiotestsrc is-live=true wave=sine freq=1000 ! audio/x-raw,rate=48000 ! {aac}"
            )),
            Input::Camera(nodes) => {
                if let Some(device) = &nodes.audio {
                    lines.push(format!("alsasrc device={device} ! {aac}"));
                }
            }
            Input::Rtmp(_) if profile.audio == "copy" => {
                lines.push("demux.audio ! queue ! aacparse ! queue ! mux.".to_owned());
            }
            Input::Rtmp(_) => lines.push(format!(
                "demux.audio ! queue ! aacparse ! avdec_aac ! {aac}"
            )),
        }
    }

    lines.push(String::new());
    lines.push("mpegtsmux name=mux ! appsink name=appsink".to_owned());
    let mut text = lines.join("\n");
    text.push('\n');
    text
}

/// What a job's output says.
#[derive(Debug, Clone, PartialEq)]
pub(crate) enum Signal {
    /// ffmpeg's progress.
    Progress(Progress),
    /// A GStreamer encoder connected (or reconnected) to its SRT listener.
    Connected,
}

/// Reads a job's output for its backend.
#[derive(Debug)]
pub(crate) enum Watch {
    Progress(ProgressParser),
    Connection,
}

impl Watch {
    pub(crate) fn new(backend: Backend) -> Self {
        if backend.reports_progress() {
            Self::Progress(ProgressParser::default())
        } else {
            Self::Connection
        }
    }

    /// A line from the job's stdout.
    pub(crate) fn stdout(&mut self, line: &str) -> Option<Signal> {
        match self {
            Self::Progress(parser) => parser.line(line).map(Signal::Progress),
            Self::Connection => connected(line),
        }
    }

    /// A line from the job's stderr.
    pub(crate) fn stderr(&mut self, line: &str) -> Option<Signal> {
        match self {
            Self::Progress(_) => None,
            Self::Connection => connected(line),
        }
    }
}

/// belacoder's and ceracoder's lines for an SRT connection made.
fn connected(line: &str) -> Option<Signal> {
    (line.starts_with("SRT connected to") || line.starts_with("SRT reconnected"))
        .then_some(Signal::Connected)
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::modules::stream::tests::settings;

    pub(crate) const GST: &str = r#"
ffmpeg = "/opt/ffmpeg"
belacoder = "/opt/belacoder"
ceracoder = "/opt/ceracoder"
gst_plugin_path = "/opt/helios-gst"
runtime_dir = "/run/test"

[outputs.main]
mode = "direct"
host = "ingest.example.com"
port = 4001
latency_ms = 1500
passphrase = "not-a-secret-123"

[outputs.open]
mode = "direct"
host = "ingest.example.com"
port = 4001

[profiles.ada]
video = "hevc_rkmpp"
encoder = "belacoder"
bitrate_mode = "adaptive"
bitrate_kbps = 4000
min_bitrate_kbps = 1000
max_bitrate_kbps = 8000
gop_s = 2
audio = "aac"

[profiles.cera]
video = "h264_rkmpp"
encoder = "ceracoder"
bitrate_kbps = 3000
scale = "1280x720"
audio = "copy"
input = { fps = 30 }

[profiles.soft]
video = "libx264"
encoder = "belacoder"
bitrate_kbps = 2000
scale = "640x360"
audio = "none"
input = { format = "mjpeg", size = "1920x1080", fps = 25 }

[streams.pattern]
source = { type = "test", size = "1280x720", fps = 30 }
profile = "ada"
output = "main"
streamid = "publish/live/pattern"
"#;

    fn target<'a>(output: &'a super::super::settings::Output, port: Option<u16>) -> Target<'a> {
        Target {
            output,
            streamid: "publish/live/s",
            sender_port: port,
        }
    }

    #[test]
    fn ranges_follow_the_mode() {
        let settings = settings(GST);
        let adaptive = Range::new(&settings.profiles["ada"], 4000, None);
        assert_eq!((adaptive.min_kbps, adaptive.max_kbps), (1000, 4000));
        // An override below the floor narrows the range rather than inverting it.
        let low = Range::new(&settings.profiles["ada"], 600, None);
        assert_eq!((low.min_kbps, low.max_kbps), (600, 600));
        let fixed = Range::new(&settings.profiles["cera"], 3000, Some(2000));
        assert_eq!((fixed.min_kbps, fixed.max_kbps), (3000, 3000));
        // A source's ceiling lowers an adaptive stream's top, never past its bitrate.
        let followed = Range::new(&settings.profiles["ada"], 4000, Some(2500));
        assert_eq!((followed.min_kbps, followed.max_kbps), (1000, 2500));
        let capped = Range::new(&settings.profiles["ada"], 4000, Some(9000));
        assert_eq!(capped.max_kbps, 4000);
        let below_floor = Range::new(&settings.profiles["ada"], 4000, Some(600));
        assert_eq!((below_floor.min_kbps, below_floor.max_kbps), (600, 600));
    }

    #[test]
    fn the_ceiling_follows_the_source_within_the_profile() {
        let settings = settings(GST);
        let mut profile = settings.profiles["ada"].clone();
        assert_eq!(source_ceiling(&profile, 4000, 3812.4), Some(3812));
        assert_eq!(
            source_ceiling(&profile, 4000, 9000.0),
            Some(4000),
            "capped at the bitrate"
        );
        assert_eq!(
            source_ceiling(&profile, 4000, 300.0),
            Some(1000),
            "kept at the minimum"
        );
        profile.source_ceiling_percent = 70;
        assert_eq!(source_ceiling(&profile, 4000, 3000.0), Some(2100));
        profile.source_ceiling_percent = 0;
        assert_eq!(source_ceiling(&profile, 4000, 3000.0), None, "off");
        assert_eq!(
            source_ceiling(&settings.profiles["cera"], 3000, 1000.0),
            None,
            "fixed"
        );
    }

    #[test]
    fn plans_belacoder_with_its_files_passphrase_and_plugin_path() {
        let settings = settings(GST);
        let profile = &settings.profiles["ada"];
        let input = Input::Test {
            size: "1280x720",
            fps: 30,
        };
        let range = Range::new(profile, 4000, None);
        let plan = plan(
            &settings,
            "pattern",
            profile,
            target(&settings.outputs["main"], None),
            input,
            range,
        );
        assert_eq!(plan.program, PathBuf::from("/opt/belacoder"));
        assert_eq!(
            plan.args.join(" "),
            "-s publish/live/s -l 1500 -p not-a-secret-123 -b /run/test/encoders/pattern.bitrate \
             /run/test/encoders/pattern.pipeline ingest.example.com 4001"
        );
        assert_eq!(
            plan.env,
            [("GST_PLUGIN_PATH".to_owned(), "/opt/helios-gst".to_owned())]
        );
        // By default, helios-packages' plugin directory; empty, none.
        let mut defaults = settings.clone();
        defaults.gst_plugin_path = StreamSettings::default().gst_plugin_path;
        let output = target(&settings.outputs["main"], None);
        let env = super::plan(&defaults, "pattern", profile, output, input, range).env;
        assert_eq!(
            env,
            [(
                "GST_PLUGIN_PATH".to_owned(),
                "/usr/lib/helios-gst/gstreamer-1.0".to_owned()
            )]
        );
        defaults.gst_plugin_path = PathBuf::new();
        assert!(
            super::plan(&defaults, "pattern", profile, output, input, range)
                .env
                .is_empty()
        );
        let files: Vec<_> = plan
            .files
            .iter()
            .map(|(path, _)| path.display().to_string())
            .collect();
        assert_eq!(
            files,
            [
                "/run/test/encoders/pattern.pipeline",
                "/run/test/encoders/pattern.bitrate"
            ]
        );
        assert_eq!(plan.files[1].1, "1000000\n4000000\n");
        let pipeline = &plan.files[0].1;
        assert!(pipeline.starts_with("videotestsrc is-live=true pattern=smpte ! video/x-raw,width=1280,height=720,framerate=30/1"), "{pipeline}");
        assert!(pipeline.contains("mpph265enc name=venc_bps zero-copy-pkt=0 qp-max=51 gop=60 ! h265parse config-interval=-1 ! queue ! mux."), "{pipeline}");
        assert!(
            pipeline.contains("audiotestsrc is-live=true wave=sine freq=1000"),
            "{pipeline}"
        );
        assert!(
            pipeline.ends_with("mpegtsmux name=mux ! appsink name=appsink\n"),
            "{pipeline}"
        );
    }

    #[test]
    fn plans_ceracoder_for_rtmp_through_a_local_sender() {
        let settings = settings(GST);
        let profile = &settings.profiles["cera"];
        let url = "rtmp://127.0.0.1:1935/live/ingest";
        let plan = plan(
            &settings,
            "pocket",
            profile,
            target(&settings.outputs["open"], Some(6000)),
            Input::Rtmp(url),
            Range::new(profile, 3000, None),
        );
        assert_eq!(plan.program, PathBuf::from("/opt/ceracoder"));
        assert_eq!(
            plan.args.join(" "),
            "-s publish/live/s -l 2000 -c /run/test/encoders/pocket.conf \
             /run/test/encoders/pocket.pipeline 127.0.0.1 6000"
        );
        let conf = &plan.files[1].1;
        assert!(
            conf.contains("min_bitrate = 3000\nmax_bitrate = 3000\nbalancer = fixed\n"),
            "{conf}"
        );
        assert!(conf.contains("[srt]\nlatency = 2000\n"), "{conf}");
        let pipeline = &plan.files[0].1;
        assert!(
            pipeline.starts_with(
                "rtmpsrc location=rtmp://127.0.0.1:1935/live/ingest ! flvdemux name=demux\n"
            ),
            "{pipeline}"
        );
        assert!(
            pipeline
                .contains("h264parse ! mppvideodec !\nvideorate ! video/x-raw,framerate=30/1 !"),
            "{pipeline}"
        );
        assert!(pipeline.contains("mpph264enc name=venc_bps zero-copy-pkt=0 qp-max=51 gop=60 width=1280 height=720 ! h264parse"), "{pipeline}");
        assert!(
            pipeline.contains("demux.audio ! queue ! aacparse ! queue ! mux."),
            "{pipeline}"
        );
    }

    #[test]
    fn builds_software_camera_pipelines() {
        let settings = settings(GST);
        let profile = &settings.profiles["soft"];
        let nodes = CameraNodes {
            video: "/dev/video2".into(),
            audio: Some("hw:1,0".into()),
        };
        let pipeline = pipeline(profile, Input::Camera(&nodes));
        assert!(pipeline.starts_with("v4l2src device=/dev/video2 ! image/jpeg,width=1920,height=1080,framerate=25/1 ! queue ! jpegdec !"), "{pipeline}");
        assert!(
            pipeline.contains("videoscale ! video/x-raw,width=640,height=360 !"),
            "{pipeline}"
        );
        assert!(
            pipeline.contains(
                "x264enc name=venc_kbps speed-preset=veryfast tune=zerolatency key-int-max=50"
            ),
            "{pipeline}"
        );
        assert!(!pipeline.contains("alsasrc"), "audio = none: {pipeline}");
        let mut with_audio = profile.clone();
        with_audio.audio = "aac".into();
        with_audio.input.format = "yuyv422".into();
        let pipeline = super::pipeline(&with_audio, Input::Camera(&nodes));
        assert!(
            pipeline.contains("video/x-raw,format=YUY2,width=1920"),
            "{pipeline}"
        );
        assert!(
            pipeline.contains("alsasrc device=hw:1,0 ! audioconvert ! audioresample ! voaacenc"),
            "{pipeline}"
        );
    }

    #[test]
    fn watches_each_backends_output() {
        let mut ffmpeg = Watch::new(Backend::Ffmpeg);
        assert_eq!(
            ffmpeg.stderr("SRT connected to x:1. Negotiated latency: 2000 ms"),
            None
        );
        assert_eq!(ffmpeg.stdout("frame=1"), None);
        let mut gst = Watch::new(Backend::Belacoder);
        assert_eq!(gst.stderr("Gstreamer pipeline: ..."), None);
        assert_eq!(
            gst.stderr("SRT connected to 127.0.0.1:6000. Negotiated latency: 2000 ms"),
            Some(Signal::Connected)
        );
        assert_eq!(
            gst.stderr("SRT reconnected on attempt 2 (total reconnects this run: 1)"),
            Some(Signal::Connected)
        );
        assert_eq!(gst.stdout("progress=continue"), None);
        assert!(Backend::Ceracoder.reloads() && !Backend::Ffmpeg.reloads());
    }
}
