//! ffmpeg's arguments for a stream, built only from local settings (LLD 4, sections 4.4 and 6.2),
//! and its `-progress` output (section 6.5). The cloud never supplies arguments.

use std::path::PathBuf;

use super::settings::{Output, Profile, parse_size};

/// A USB camera's nodes, as the usb module found them.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct CameraNodes {
    /// The capture node, for example `/dev/video0`.
    pub video: PathBuf,
    /// The ALSA capture device, for example `hw:2,0`.
    pub audio: Option<String>,
}

/// The arguments (after the program) for a camera stream to an SRT output.
/// Where ffmpeg sends: the output's SRT listener (`direct`), or its local `srtla_send`'s port
/// on loopback (`srtla`).
#[derive(Debug, Clone, Copy)]
pub(crate) struct Target<'a> {
    pub output: &'a Output,
    pub streamid: &'a str,
    /// The local sender's port, for `srtla` outputs.
    pub sender_port: Option<u16>,
}

const COMMON: [&str; 8] = [
    "-hide_banner",
    "-nostdin",
    "-loglevel",
    "warning",
    "-progress",
    "pipe:1",
    "-stats_period",
    "2",
];

/// The arguments for a generated test pattern with a 1 kHz tone, at real-time speed.
pub(crate) fn test_args(
    profile: &Profile,
    target: Target<'_>,
    size: &str,
    fps: u32,
    bitrate_kbps: u32,
) -> Vec<String> {
    let mut args: Vec<String> = COMMON.map(String::from).into();
    args.extend(
        [
            "-re".into(),
            "-f".into(),
            "lavfi".into(),
            "-i".into(),
            format!("testsrc2=size={size}:rate={fps}"),
        ]
        .into_iter()
        .chain(
            (profile.audio != "none")
                .then(|| {
                    [
                        "-re",
                        "-f",
                        "lavfi",
                        "-i",
                        "sine=frequency=1000:sample_rate=48000",
                    ]
                    .map(String::from)
                })
                .into_iter()
                .flatten(),
        ),
    );
    args.extend(["-map".into(), "0:v:0".into()]);
    if profile.audio != "none" {
        args.extend(["-map".into(), "1:a:0".into()]);
    }
    args.extend(video_args(profile, bitrate_kbps, false));
    if profile.audio == "none" {
        args.push("-an".into());
    } else {
        args.extend(audio_args(&profile.audio));
    }
    args.extend(output_args(target));
    args
}

/// The arguments for an RTMP stream read back from nginx on loopback (`rtmp-ingest`). With a
/// Rockchip encoder the input is decoded by MPP and scaled by RGA, so frames stay in DMA buffers
/// (tested on the Orange Pi 5 Plus: 1080p60 to HEVC at 7.5x real time). Audio is optional: a
/// camera that sends none still streams.
pub(crate) fn rtmp_args(
    profile: &Profile,
    target: Target<'_>,
    url: &str,
    bitrate_kbps: u32,
) -> Vec<String> {
    let mut args: Vec<String> = COMMON.map(String::from).into();
    let hardware = profile.video.ends_with("_rkmpp");
    if hardware {
        args.extend(["-hwaccel", "rkmpp", "-hwaccel_output_format", "drm_prime"].map(String::from));
    }
    // A publisher that stops sending ends the read after 10 s (in microseconds).
    args.extend([
        "-rw_timeout".into(),
        "10000000".into(),
        "-i".into(),
        url.to_owned(),
    ]);
    args.extend(["-map".into(), "0:v:0".into()]);
    if profile.audio != "none" {
        args.extend(["-map".into(), "0:a:0?".into()]);
    }
    args.extend(video_args(profile, bitrate_kbps, hardware));
    if profile.audio == "none" {
        args.push("-an".into());
    } else {
        args.extend(audio_args(&profile.audio));
    }
    args.extend(output_args(target));
    args
}

/// The arguments for a camera stream.
pub(crate) fn camera_args(
    profile: &Profile,
    target: Target<'_>,
    nodes: &CameraNodes,
    bitrate_kbps: u32,
) -> Vec<String> {
    let mut args: Vec<String> = COMMON.map(String::from).into();
    args.extend(["-f", "v4l2", "-thread_queue_size", "512"].map(String::from));
    let input = &profile.input;
    if !input.format.is_empty() {
        args.extend(["-input_format".into(), input.format.clone()]);
    }
    if !input.size.is_empty() {
        args.extend(["-video_size".into(), input.size.clone()]);
    }
    if input.fps > 0 {
        args.extend(["-framerate".into(), input.fps.to_string()]);
    }
    args.extend(["-i".into(), nodes.video.display().to_string()]);
    let audio = nodes.audio.as_ref().filter(|_| profile.audio != "none");
    if let Some(device) = audio {
        args.extend(["-f", "alsa", "-thread_queue_size", "512", "-i", device].map(String::from));
    }
    args.extend(["-map".into(), "0:v:0".into()]);
    if audio.is_some() {
        args.extend(["-map".into(), "1:a:0".into()]);
    }
    args.extend(video_args(profile, bitrate_kbps, false));
    if audio.is_some() {
        args.extend(audio_args(&profile.audio));
    } else {
        args.push("-an".into());
    }
    args.extend(output_args(target));
    args
}

/// `hardware`: the frames are MPP-decoded DRM PRIME buffers, so scaling is RGA's.
fn video_args(profile: &Profile, bitrate_kbps: u32, hardware: bool) -> Vec<String> {
    let bitrate = format!("{bitrate_kbps}k");
    let mut args = vec!["-c:v".to_owned(), profile.video.clone()];
    match profile.video.as_str() {
        "copy" => return args,
        "libx264" => args.extend(
            [
                "-preset",
                "veryfast",
                "-tune",
                "zerolatency",
                "-pix_fmt",
                "yuv420p",
                "-maxrate",
                &bitrate,
                "-bufsize",
                &format!("{}k", u64::from(bitrate_kbps) * 2),
            ]
            .map(String::from),
        ),
        "h264_rkmpp" | "hevc_rkmpp" => args.extend(["-rc_mode".into(), "CBR".into()]),
        "libx265" => args.extend(
            [
                "-preset",
                "ultrafast",
                "-tune",
                "zerolatency",
                "-x265-params",
                "log-level=error",
            ]
            .map(String::from),
        ),
        _ => {}
    }
    args.extend(["-b:v".into(), bitrate]);
    // Keyframes by time, whatever frame rate the camera picked.
    args.extend([
        "-force_key_frames".into(),
        format!("expr:gte(t,n_forced*{})", profile.gop_s),
    ]);
    if let Some((width, height)) = parse_size(&profile.scale) {
        let filter = if hardware {
            format!("scale_rkrga=w={width}:h={height}")
        } else {
            format!("scale={width}:{height}")
        };
        args.extend(["-vf".into(), filter]);
    }
    args
}

fn audio_args(audio: &str) -> Vec<String> {
    match audio {
        "copy" => vec!["-c:a".into(), "copy".into()],
        _ => ["-c:a", "aac", "-b:a", "128k"].map(String::from).into(),
    }
}

/// MPEG-TS (irl-srt-server accepts only that) to an SRT listener in caller mode. ffmpeg's SRT
/// `latency` is in microseconds.
fn output_args(target: Target<'_>) -> Vec<String> {
    vec![
        "-f".into(),
        "mpegts".into(),
        "-mpegts_flags".into(),
        "+resend_headers".into(),
        srt_url(target),
    ]
}

pub(crate) fn srt_url(target: Target<'_>) -> String {
    let output = target.output;
    let (host, port) = match target.sender_port {
        Some(port) => ("127.0.0.1".to_owned(), port),
        None if output.host.contains(':') => (format!("[{}]", output.host), output.port),
        None => (output.host.clone(), output.port),
    };
    let mut url = format!(
        "srt://{host}:{port}?mode=caller&latency={}&streamid={}",
        u64::from(output.latency_ms) * 1000,
        target.streamid
    );
    if let Some(passphrase) = &output.passphrase {
        url.push_str("&passphrase=");
        url.push_str(passphrase);
    }
    url
}

/// One `-progress` block: ffmpeg writes `key=value` lines and ends each block with
/// `progress=continue` (or `end`).
#[derive(Debug, Clone, Default, PartialEq)]
pub(crate) struct Progress {
    pub frame: Option<u64>,
    pub fps: Option<f64>,
    pub bitrate_kbps: Option<f64>,
    pub total_size: Option<u64>,
    pub out_time_us: Option<i64>,
    pub drop_frames: Option<u64>,
    pub dup_frames: Option<u64>,
    pub speed: Option<f64>,
    /// `progress=end`: ffmpeg is finishing.
    pub end: bool,
}

/// Collects `-progress` lines into blocks.
#[derive(Debug, Default)]
pub(crate) struct ProgressParser {
    current: Progress,
}

impl ProgressParser {
    /// Feeds one line; returns the block it completes, if any. Unknown keys and values ffmpeg
    /// reports as `N/A` are ignored.
    pub(crate) fn line(&mut self, line: &str) -> Option<Progress> {
        let (key, value) = line.trim().split_once('=')?;
        let value = value.trim();
        let current = &mut self.current;
        match key {
            "frame" => current.frame = value.parse().ok(),
            "fps" => current.fps = value.parse().ok(),
            "bitrate" => {
                current.bitrate_kbps = value
                    .strip_suffix("kbits/s")
                    .and_then(|v| v.trim().parse().ok());
            }
            "total_size" => current.total_size = value.parse().ok(),
            "out_time_us" | "out_time_ms" => current.out_time_us = value.parse().ok(),
            "drop_frames" => current.drop_frames = value.parse().ok(),
            "dup_frames" => current.dup_frames = value.parse().ok(),
            "speed" => current.speed = value.strip_suffix('x').and_then(|v| v.trim().parse().ok()),
            "progress" => {
                let mut done = std::mem::take(&mut self.current);
                done.end = value == "end";
                return Some(done);
            }
            _ => {}
        }
        None
    }
}
