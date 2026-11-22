//! Stream module tests: the settings, ffmpeg's arguments and progress, and the module with a
//! fake spawner, fake cameras and Tokio's paused clock.

use std::collections::BTreeSet;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, SystemTime};

use serde_json::{Value, json};
use tokio::sync::mpsc;

use super::ffmpeg::{self, CameraNodes, ProgressParser};
use super::process::{self, BoxFuture, Job, JobEvent, JobSpec, Spawner, Tagged};
use super::settings::StreamSettings;
use super::{ModuleContext, StreamModule};
use crate::modules::Module;
use crate::modules::usb::{UsbDevice, UsbHandle, UsbSnapshot};
use crate::mqtt::manager::{MqttHandle, Request as MqttRequest};
use crate::mqtt::shadow::{ShadowHandle, TestReports};
use crate::router::{Outcome, PendingCommand};

const WAIT: Duration = Duration::from_secs(600);

const CONFIG: &str = r#"
ffmpeg = "/opt/ffmpeg"
stats_interval_s = 30

[outputs.main]
mode = "direct"
host = "ingest.example.com"
port = 4001
latency_ms = 1500
passphrase = "not-a-secret-123"

[profiles.cam]
video = "libx264"
bitrate_kbps = 4000
min_bitrate_kbps = 1000
max_bitrate_kbps = 8000
gop_s = 2
scale = "1280x720"
audio = "aac"
input = { format = "mjpeg", size = "1920x1080", fps = 30 }

[streams.camera]
source = { type = "camera", video = "usb:1-1.3", audio = "usb:1-1.3" }
profile = "cam"
output = "main"
streamid = "publish/live/backpack"
"#;

pub(super) fn settings(text: &str) -> StreamSettings {
    toml::from_str::<StreamSettings>(text)
        .expect("settings")
        .check()
        .expect("valid")
        .expect("enabled")
}

fn refused(text: &str) -> String {
    toml::from_str::<StreamSettings>(text)
        .expect("parses")
        .check()
        .expect_err("refused")
}

#[test]
fn accepts_a_camera_stream_to_a_direct_output() {
    let settings = settings(CONFIG);
    assert_eq!(settings.streams["camera"].output, "main");
    assert_eq!(settings.stats_interval(), Duration::from_secs(30));
    assert!(
        toml::from_str::<StreamSettings>("enabled = false")
            .expect("parses")
            .check()
            .expect("valid")
            .is_none()
    );
}

#[test]
fn refuses_what_this_version_cannot_run_and_bad_values() {
    for (from, to, message) in [
        (
            "mode = \"direct\"",
            "mode = \"srtla\"",
            "uplinks must name at least one uplink",
        ),
        (
            "mode = \"direct\"",
            "mode = \"udp\"",
            "mode must be direct or srtla",
        ),
        (
            "type = \"camera\", video = \"usb:1-1.3\", audio = \"usb:1-1.3\"",
            "type = \"rtmp\"",
            "RTMP sources need [modules.stream.rtmp_ingest] enabled",
        ),
        ("not-a-secret-123", "short", "passphrase must be 10 to 79"),
        ("not-a-secret-123", "has space in it", "passphrase must be"),
        (
            "bitrate_kbps = 4000",
            "bitrate_kbps = 9000",
            "bitrate_kbps must be within",
        ),
        (
            "video = \"libx264\"",
            "video = \"vp9\"",
            "video must be one of",
        ),
        ("audio = \"aac\"", "audio = \"copy\"", "raw PCM"),
        ("gop_s = 2", "gop_s = 0", "gop_s must be 1 to 10"),
        (
            "scale = \"1280x720\"",
            "scale = \"big\"",
            "scale must be WIDTHxHEIGHT",
        ),
        ("format = \"mjpeg\"", "format = \"mj peg\"", "input.format"),
        ("fps = 30", "fps = 999", "input.fps"),
        (
            "streamid = \"publish/live/backpack\"",
            "streamid = \"a&b\"",
            "streamid must be",
        ),
        ("profile = \"cam\"", "profile = \"other\"", "no profile"),
        ("output = \"main\"", "output = \"other\"", "no output"),
        (
            "video = \"usb:1-1.3\", audio",
            "video = \"/dev/video0\", audio",
            "must be usb:<port>",
        ),
        (
            "latency_ms = 1500",
            "latency_ms = 5",
            "latency_ms must be 20 to 30000",
        ),
        (
            "host = \"ingest.example.com\"",
            "host = \"a b\"",
            "host must be",
        ),
        (
            "stats_interval_s = 30",
            "stats_interval_s = 1",
            "stats_interval_s",
        ),
        ("[streams.camera]", "[streams.\"bad name\"]", "names are"),
    ] {
        let text = CONFIG.replacen(from, to, 1);
        let error = refused(&text);
        assert!(error.contains(message), "{to}: {error}");
    }
    let copy_with_scale = CONFIG.replacen("video = \"libx264\"", "video = \"copy\"", 1);
    assert!(refused(&copy_with_scale).contains("scale needs an encoder"));
    let keyed = CONFIG.replacen("usb:1-1.3\", audio", "0bda:5830:CAM1\", audio", 1);
    settings(&keyed);
}

fn target<'a>(output: &'a super::settings::Output, streamid: &'a str) -> ffmpeg::Target<'a> {
    ffmpeg::Target {
        output,
        streamid,
        sender_port: None,
    }
}

fn nodes(audio: bool) -> CameraNodes {
    CameraNodes {
        video: "/dev/video2".into(),
        audio: audio.then(|| "hw:1,0".to_owned()),
    }
}

#[test]
fn builds_camera_arguments_from_the_profile() {
    let settings = settings(CONFIG);
    let args = ffmpeg::camera_args(
        &settings.profiles["cam"],
        target(&settings.outputs["main"], "publish/live/backpack"),
        &nodes(true),
        5000,
    )
    .join(" ");
    for part in [
        "-progress pipe:1",
        "-f v4l2 -thread_queue_size 512 -input_format mjpeg -video_size 1920x1080 -framerate 30 -i /dev/video2",
        "-f alsa -thread_queue_size 512 -i hw:1,0",
        "-map 0:v:0 -map 1:a:0",
        "-c:v libx264 -preset veryfast -tune zerolatency -pix_fmt yuv420p -maxrate 5000k -bufsize 10000k -b:v 5000k",
        "-force_key_frames expr:gte(t,n_forced*2) -vf scale=1280:720",
        "-c:a aac -b:a 128k",
        "-f mpegts -mpegts_flags +resend_headers srt://ingest.example.com:4001?mode=caller&latency=1500000&streamid=publish/live/backpack&passphrase=not-a-secret-123",
    ] {
        assert!(args.contains(part), "missing {part:?} in {args}");
    }
}

#[test]
fn copies_or_uses_hardware_encoders_and_brackets_ipv6() {
    let mut settings = settings(CONFIG);
    let output = settings.outputs.get_mut("main").expect("output");
    output.host = "2001:db8::1".into();
    output.passphrase = None;
    let output = output.clone();
    let profile = settings.profiles.get_mut("cam").expect("profile");
    profile.video = "copy".into();
    profile.scale = String::new();
    profile.input = Default::default();
    let args = ffmpeg::camera_args(profile, target(&output, "s"), &nodes(false), 1).join(" ");
    assert!(
        args.contains("-i /dev/video2 -map 0:v:0 -c:v copy -an"),
        "{args}"
    );
    assert!(
        args.ends_with("srt://[2001:db8::1]:4001?mode=caller&latency=1500000&streamid=s"),
        "{args}"
    );
    profile.video = "hevc_rkmpp".into();
    let args = ffmpeg::camera_args(profile, target(&output, "s"), &nodes(false), 6000).join(" ");
    assert!(
        args.contains("-c:v hevc_rkmpp -rc_mode CBR -b:v 6000k"),
        "{args}"
    );
    profile.audio = "copy".into();
    let args = ffmpeg::camera_args(profile, target(&output, "s"), &nodes(true), 6000).join(" ");
    assert!(args.contains("-c:a copy"), "{args}");
}

#[test]
fn parses_progress_blocks() {
    let mut parser = ProgressParser::default();
    let mut blocks = Vec::new();
    for line in "frame=120\nfps=29.97\nbitrate=4012.3kbits/s\ntotal_size=N/A\nout_time_us=4000000\n\
                 drop_frames=1\ndup_frames=0\nspeed=1.01x\nbogus line\nunknown=1\nprogress=continue\n\
                 out_time_us=4100000\nprogress=end\n"
        .lines()
    {
        blocks.extend(parser.line(line));
    }
    assert_eq!(blocks.len(), 2);
    assert_eq!(blocks[0].frame, Some(120));
    assert_eq!(blocks[0].fps, Some(29.97));
    assert_eq!(blocks[0].bitrate_kbps, Some(4012.3));
    assert_eq!(blocks[0].total_size, None);
    assert_eq!(blocks[0].out_time_us, Some(4_000_000));
    assert_eq!(blocks[0].drop_frames, Some(1));
    assert_eq!(blocks[0].speed, Some(1.01));
    assert!(!blocks[0].end);
    assert!(blocks[1].end);
    assert_eq!(blocks[1].frame, None);
}

#[test]
fn reads_encoder_names_from_the_listing() {
    let listing = "Encoders:\n V..... = Video\n ------\n V....D libx264              H.264\n A....D aac                  AAC\n";
    let encoders = process::parse_encoders(listing);
    assert_eq!(
        encoders,
        BTreeSet::from(["libx264".to_owned(), "aac".to_owned()])
    );
}

#[tokio::test]
async fn the_system_spawner_runs_and_stops_a_process_group() {
    let (events, mut received) = mpsc::unbounded_channel();
    let spec = JobSpec {
        name: "test".into(),
        program: "/bin/sh".into(),
        args: vec!["-c".into(), "echo out; echo err >&2; exec sleep 30".into()],
        env: vec![("HELIOS_TEST".into(), "1".into())],
    };
    let mut job = process::System.spawn(&spec, 7, events).expect("spawned");
    let mut seen = Vec::new();
    while seen.len() < 2 {
        let tagged = tokio::time::timeout(Duration::from_secs(5), received.recv())
            .await
            .expect("output in time")
            .expect("events");
        assert_eq!(tagged.job, 7);
        seen.push(tagged.event);
    }
    assert!(seen.contains(&JobEvent::Stdout("out".into())));
    assert!(seen.contains(&JobEvent::Stderr("err".into())));
    tokio::time::timeout(Duration::from_secs(10), job.stop(Duration::from_secs(2)))
        .await
        .expect("stopped in time");
    let exited = tokio::time::timeout(Duration::from_secs(5), received.recv())
        .await
        .expect("exit in time")
        .expect("events");
    assert_eq!(exited.event, JobEvent::Exited(None));
    assert!(
        process::System
            .spawn(
                &JobSpec {
                    program: "/nonexistent/ffmpeg".into(),
                    ..spec
                },
                8,
                mpsc::unbounded_channel().0,
            )
            .is_err()
    );
    let encoders = process::System
        .encoders("/nonexistent/ffmpeg".as_ref())
        .await;
    assert!(encoders.is_none());
}

/// A job started by the fake spawner.
pub(super) struct Started {
    pub(super) spec: JobSpec,
    job: u64,
    events: mpsc::UnboundedSender<Tagged>,
    pub(super) stopped: Arc<AtomicBool>,
    reloads: Arc<std::sync::atomic::AtomicUsize>,
}

impl Started {
    pub(super) fn send(&self, event: JobEvent) {
        let _ = self.events.send(Tagged {
            job: self.job,
            event,
        });
    }

    pub(super) fn progress(&self, out_time_us: i64) {
        for line in [
            format!("fps=30\nout_time_us={out_time_us}"),
            "progress=continue".into(),
        ] {
            for line in line.lines() {
                self.send(JobEvent::Stdout(line.into()));
            }
        }
    }
}

struct FakeJob {
    stopped: Arc<AtomicBool>,
    reloads: Arc<std::sync::atomic::AtomicUsize>,
    job: u64,
    events: mpsc::UnboundedSender<Tagged>,
}

impl Job for FakeJob {
    fn reload(&self) {
        self.reloads.fetch_add(1, Ordering::SeqCst);
    }

    fn stop(&mut self, _grace: Duration) -> BoxFuture<'_, ()> {
        self.stopped.store(true, Ordering::SeqCst);
        let _ = self.events.send(Tagged {
            job: self.job,
            event: JobEvent::Exited(None),
        });
        Box::pin(async {})
    }
}

pub(super) struct FakeSpawner {
    pub(super) started: mpsc::UnboundedSender<Started>,
    pub(super) encoders: Option<BTreeSet<String>>,
    pub(super) refuse: AtomicBool,
}

impl Spawner for FakeSpawner {
    fn spawn(
        &self,
        spec: &JobSpec,
        job: u64,
        events: mpsc::UnboundedSender<Tagged>,
    ) -> std::io::Result<Box<dyn Job>> {
        if self.refuse.load(Ordering::SeqCst) {
            return Err(std::io::Error::from(std::io::ErrorKind::NotFound));
        }
        let stopped = Arc::new(AtomicBool::new(false));
        let reloads = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let _ = self.started.send(Started {
            spec: spec.clone(),
            job,
            events: events.clone(),
            stopped: stopped.clone(),
            reloads: reloads.clone(),
        });
        Ok(Box::new(FakeJob {
            stopped,
            reloads,
            job,
            events,
        }))
    }

    fn encoders<'a>(
        &'a self,
        _ffmpeg: &'a std::path::Path,
    ) -> BoxFuture<'a, Option<BTreeSet<String>>> {
        let encoders = self.encoders.clone();
        Box::pin(async move { encoders })
    }
}

fn camera(port: &str, with_audio: bool) -> (String, Arc<UsbDevice>) {
    let mut payload = json!({
        "port": port, "key": "0bda:5830:CAM1", "product": "Webcam",
        "nodes": {
            "video": [{"name": "video3", "index": 1}, {"name": "video2", "index": 0}],
            "alsa": if with_audio { json!([{"card": 1, "id": "Webcam", "capture": true, "playback": false}]) } else { json!([]) },
        },
    });
    let payload = payload.as_object_mut().expect("object").clone();
    (
        port.to_owned(),
        Arc::new(UsbDevice {
            port: port.to_owned(),
            devpath: format!("/devices/usb1/{port}"),
            vid: 0x0bda,
            pid: 0x5830,
            hub: false,
            payload,
            attached_at: SystemTime::now(),
        }),
    )
}

struct Harness {
    usb: UsbHandle,
    started: mpsc::UnboundedReceiver<Started>,
    published: mpsc::UnboundedReceiver<MqttRequest>,
    reports: TestReports,
    commands: mpsc::Sender<PendingCommand>,
    desired: mpsc::UnboundedSender<Value>,
    cancel: tokio_util::sync::CancellationToken,
    task: tokio::task::JoinHandle<Result<(), crate::modules::ModuleError>>,
}

fn harness(config: &str, encoders: Option<&[&str]>, refuse: bool) -> Harness {
    harness_with(config, encoders, refuse, Arc::new(|| Ok(Vec::new())))
}

fn harness_with(
    config: &str,
    encoders: Option<&[&str]>,
    refuse: bool,
    addresses: Arc<super::Addresses>,
) -> Harness {
    let usb = UsbHandle::default();
    let (started_tx, started) = mpsc::unbounded_channel();
    let spawner = FakeSpawner {
        started: started_tx,
        encoders: encoders.map(|names| names.iter().map(|name| (*name).to_owned()).collect()),
        refuse: AtomicBool::new(refuse),
    };
    let module =
        StreamModule::with_fakes(settings(config), usb.clone(), Arc::new(spawner), addresses);
    let (mqtt, published, _status) = MqttHandle::for_test();
    let (shadows, reports, _desired) = ShadowHandle::for_test();
    let (commands, commands_rx) = mpsc::channel(4);
    let (desired, desired_rx) = mpsc::unbounded_channel();
    let cancel = tokio_util::sync::CancellationToken::new();
    let ctx = ModuleContext {
        commands: commands_rx,
        desired: desired_rx,
        shadows,
        mqtt,
        sysfs: "/sys".into(),
        cancel: cancel.clone(),
    };
    let task = tokio::spawn(async move { module.run(ctx).await });
    Harness {
        usb,
        started,
        published,
        reports,
        commands,
        desired,
        cancel,
        task,
    }
}

impl Harness {
    fn plug(&self, with_audio: bool) {
        self.usb
            .set_for_test(UsbSnapshot::from([camera("1-1.3", with_audio)]));
    }

    fn unplug(&self) {
        self.usb.set_for_test(UsbSnapshot::new());
    }

    async fn next_start(&mut self) -> Started {
        tokio::time::timeout(WAIT, self.started.recv())
            .await
            .expect("a job in time")
            .expect("spawner")
    }

    /// The next published event of `kind`, skipping others.
    async fn event(&mut self, kind: &str) -> String {
        loop {
            let request = tokio::time::timeout(WAIT, self.published.recv())
                .await
                .expect("an event in time")
                .expect("mqtt");
            let text = format!("{request:?}");
            if text.contains(&format!("kind: \"{kind}\"")) {
                return text;
            }
        }
    }

    /// Waits for the shadow to show the camera stream in `state`.
    async fn state(&mut self, state: &str) -> Value {
        self.state_of("camera", state).await
    }

    /// Waits for the shadow to show stream `id` in `state`.
    async fn state_of(&mut self, id: &str, state: &str) -> Value {
        loop {
            let (shadow, reported) = tokio::time::timeout(WAIT, self.reports.recv())
                .await
                .expect("a report in time")
                .expect("shadow");
            if shadow == "stream" && reported["streams"][id]["state"] == state {
                return reported["streams"][id].clone();
            }
        }
    }

    async fn command(&self, name: &str, args: Value) -> Outcome {
        let (pending, answer) = PendingCommand::for_test("stream", name, args);
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

#[tokio::test(start_paused = true)]
async fn runs_a_camera_stream_from_attach_to_live_to_removal() {
    let mut harness = harness(CONFIG, None, false);
    harness.state("waiting_for_input").await;

    harness.plug(true);
    let job = harness.next_start().await;
    assert_eq!(job.spec.program, std::path::PathBuf::from("/opt/ffmpeg"));
    let args = job.spec.args.join(" ");
    assert!(args.contains("-i /dev/video2"), "{args}");
    assert!(args.contains("-i hw:1,0"), "{args}");
    let connected = harness.event("stream.connected").await;
    assert!(connected.contains("Webcam"), "{connected}");
    harness.state("starting").await;

    job.progress(1_000_000);
    job.progress(3_000_000);
    harness.event("stream.live").await;
    let live = harness.state("live").await;
    assert_eq!(live["source"]["port"], "1-1.3");

    // Stats go out while live.
    tokio::time::advance(Duration::from_secs(31)).await;
    harness.event("stream.stats").await;

    harness.unplug();
    let disconnected = harness.event("stream.disconnected").await;
    assert!(disconnected.contains("camera_removed"), "{disconnected}");
    harness.state("waiting_for_input").await;
    assert!(job.stopped.load(Ordering::SeqCst));
    harness.stop().await;
}

#[tokio::test(start_paused = true)]
async fn waits_for_the_audio_device_too() {
    let mut harness = harness(CONFIG, None, false);
    harness.plug(false);
    harness.state("waiting_for_input").await;
    harness.plug(true);
    harness.next_start().await;
    harness.stop().await;
}

#[tokio::test(start_paused = true)]
async fn restarts_ffmpeg_with_backoff_then_gives_up() {
    let mut harness = harness(CONFIG, None, false);
    harness.plug(true);
    for attempt in 0..5 {
        let job = harness.next_start().await;
        job.send(JobEvent::Stderr(format!("Connection refused {attempt}")));
        job.send(JobEvent::Exited(Some(1)));
        if attempt < 4 {
            let reconnecting = harness.state("reconnecting").await;
            assert!(
                reconnecting["last_error"]
                    .as_str()
                    .is_some_and(|e| e.contains("code 1") && e.contains("Connection refused")),
                "{reconnecting}"
            );
        }
    }
    let failed = harness.state("failed").await;
    assert!(
        failed["last_error"]
            .as_str()
            .is_some_and(|e| e.contains("Connection refused 4"))
    );
    let disconnected = harness.event("stream.disconnected").await;
    assert!(disconnected.contains("\"failed\""), "{disconnected}");

    // A start command gives it another chance.
    let Outcome::Ok(_) = harness
        .command("start", json!({"stream_id": "camera"}))
        .await
    else {
        panic!("start refused");
    };
    harness.next_start().await;
    harness.stop().await;
}

#[tokio::test(start_paused = true)]
async fn restarts_a_stalled_ffmpeg() {
    let mut harness = harness(CONFIG, None, false);
    harness.plug(true);
    let job = harness.next_start().await;
    job.progress(1_000_000);
    job.progress(2_000_000);
    harness.state("live").await;
    // No more progress: stalled after 10 s.
    let reconnecting = harness.state("reconnecting").await;
    assert!(
        reconnecting["last_error"]
            .as_str()
            .is_some_and(|e| e.contains("progress"))
    );
    assert!(job.stopped.load(Ordering::SeqCst));
    harness.next_start().await;
    harness.stop().await;
}

#[tokio::test(start_paused = true)]
async fn commands_stop_start_and_change_the_bitrate() {
    let mut harness = harness(CONFIG, None, false);
    harness.plug(true);
    let job = harness.next_start().await;

    let Outcome::Ok(stopped) = harness
        .command("stop", json!({"stream_id": "camera"}))
        .await
    else {
        panic!("stop refused");
    };
    assert_eq!(stopped["desired"], "stopped");
    harness.state("stopped").await;
    assert!(job.stopped.load(Ordering::SeqCst));
    let disconnected = harness.event("stream.disconnected").await;
    assert!(disconnected.contains("\"stopped\""), "{disconnected}");

    let Outcome::Ok(_) = harness
        .command(
            "start",
            json!({"stream_id": "camera", "bitrate_kbps": 2500}),
        )
        .await
    else {
        panic!("start refused");
    };
    let job = harness.next_start().await;
    assert!(job.spec.args.join(" ").contains("-b:v 2500k"));

    // A new bitrate restarts the running job.
    let Outcome::Ok(_) = harness
        .command(
            "start",
            json!({"stream_id": "camera", "bitrate_kbps": 3000}),
        )
        .await
    else {
        panic!("start refused");
    };
    assert!(
        harness
            .next_start()
            .await
            .spec
            .args
            .join(" ")
            .contains("-b:v 3000k")
    );
    assert!(job.stopped.load(Ordering::SeqCst));

    for (name, args, code) in [
        (
            "start",
            json!({"stream_id": "camera", "bitrate_kbps": 99_999}),
            "INVALID_MESSAGE",
        ),
        ("start", json!({"stream_id": "nope"}), "INVALID_MESSAGE"),
        ("start", json!({}), "INVALID_MESSAGE"),
        ("status", json!({"stream_id": "nope"}), "INVALID_MESSAGE"),
        ("reboot", json!({}), "UNKNOWN_COMMAND"),
    ] {
        match harness.command(name, args).await {
            Outcome::Err { code: got, .. } => assert_eq!(got, code, "{name}"),
            Outcome::Ok(value) => panic!("{name} accepted: {value}"),
        }
    }
    let Outcome::Ok(all) = harness.command("status", json!({})).await else {
        panic!("status refused");
    };
    assert!(all["camera"]["log"].is_array());
    let Outcome::Ok(one) = harness
        .command("status", json!({"stream_id": "camera"}))
        .await
    else {
        panic!("status refused");
    };
    assert_eq!(one["bitrate_kbps"], 3000);
    harness.stop().await;
}

#[tokio::test(start_paused = true)]
async fn a_bitrate_override_is_kept_apart_from_the_profiles() {
    let mut harness = harness(CONFIG, None, false);
    harness.plug(true);
    assert!(
        harness
            .next_start()
            .await
            .spec
            .args
            .join(" ")
            .contains("-b:v 4000k")
    );
    let live = harness.state("starting").await;
    assert_eq!(live["bitrate_kbps"], 4000);
    assert_eq!(live["bitrate_override_kbps"], Value::Null);

    // The profile's own bitrate (as an old saved state held it) is no override: nothing restarts.
    harness
        .desired
        .send(json!({"streams": {"camera": {"state": "live", "bitrate_kbps": 4000}}}))
        .expect("module running");
    // An override restarts the job with it, and is reported as one.
    harness
        .desired
        .send(json!({"streams": {"camera": {"state": "live", "bitrate_kbps": 2500}}}))
        .expect("module running");
    assert!(
        harness
            .next_start()
            .await
            .spec
            .args
            .join(" ")
            .contains("-b:v 2500k")
    );
    let overridden = loop {
        let status = harness.state("starting").await;
        if status["bitrate_override_kbps"] == 2500 {
            break status;
        }
    };
    assert_eq!(overridden["bitrate_kbps"], 2500);

    // null goes back to the profile's.
    let outcome = harness
        .command(
            "start",
            json!({"stream_id": "camera", "bitrate_kbps": null}),
        )
        .await;
    let Outcome::Ok(status) = outcome else {
        panic!("{outcome:?}");
    };
    assert_eq!(status["bitrate_kbps"], 4000);
    assert_eq!(status["bitrate_override_kbps"], Value::Null);
    assert!(
        harness
            .next_start()
            .await
            .spec
            .args
            .join(" ")
            .contains("-b:v 4000k")
    );
    // A value outside the profile's limits is ignored, not applied.
    harness
        .desired
        .send(json!({"streams": {"camera": {"bitrate_kbps": 99_999}}}))
        .expect("module running");
    let Outcome::Ok(status) = harness
        .command("status", json!({"stream_id": "camera"}))
        .await
    else {
        panic!("status");
    };
    assert_eq!(status["bitrate_kbps"], 4000);
    assert_eq!(status["bitrate_override_kbps"], Value::Null);
    harness.stop().await;
}

#[tokio::test(start_paused = true)]
async fn follows_the_shadows_desired_state() {
    let mut harness = harness(CONFIG, None, false);
    harness.plug(true);
    harness.next_start().await;

    harness
        .desired
        .send(json!({"streams": {"camera": {"state": "stopped"}, "unknown": {"state": "live"}}}))
        .expect("module running");
    harness.state("stopped").await;
    harness
        .desired
        .send(json!({"streams": {"camera": {"bitrate_kbps": 2000}}}))
        .expect("module running");
    harness
        .desired
        .send(json!({"streams": {"camera": {"state": "live", "bitrate_kbps": 2000}}}))
        .expect("module running");
    assert!(
        harness
            .next_start()
            .await
            .spec
            .args
            .join(" ")
            .contains("-b:v 2000k")
    );
    harness
        .desired
        .send(json!({"streams": {"camera": {}}}))
        .expect("module running");
    harness
        .desired
        .send(json!({"other": 1}))
        .expect("module running");
    harness.stop().await;
}

#[tokio::test(start_paused = true)]
async fn a_missing_encoder_fails_the_stream_without_running_ffmpeg() {
    let mut harness = harness(CONFIG, Some(&["aac", "h264_rkmpp"]), false);
    harness.plug(true);
    let failed = harness.state("failed").await;
    assert!(
        failed["last_error"]
            .as_str()
            .is_some_and(|e| e.contains("no libx264 encoder")),
        "{failed}"
    );
    assert!(harness.started.try_recv().is_err());
    harness.stop().await;
}

#[tokio::test(start_paused = true)]
async fn a_program_that_cannot_start_counts_as_a_failure() {
    let mut harness = harness(CONFIG, Some(&["aac", "libx264"]), true);
    harness.plug(true);
    let reconnecting = harness.state("reconnecting").await;
    assert!(
        reconnecting["last_error"]
            .as_str()
            .is_some_and(|e| e.contains("can't start /opt/ffmpeg"))
    );
    harness.stop().await;
}

#[tokio::test(start_paused = true)]
async fn shutdown_stops_running_jobs() {
    let mut harness = harness(CONFIG, None, false);
    harness.plug(true);
    let job = harness.next_start().await;
    harness.stop().await;
    assert!(job.stopped.load(Ordering::SeqCst));
}

#[tokio::test(start_paused = true)]
async fn a_flapping_camera_stops_sending_events() {
    let mut harness = harness(CONFIG, None, false);
    for _ in 0..(super::FLAP_LIMIT + 2) {
        harness.plug(true);
        harness.next_start().await;
        harness.unplug();
        harness.state("waiting_for_input").await;
    }
    let mut connected = 0;
    while let Ok(request) = harness.published.try_recv() {
        if format!("{request:?}").contains("stream.connected") {
            connected += 1;
        }
    }
    assert_eq!(connected, super::FLAP_LIMIT);
    harness.stop().await;
}

// --- srtla outputs, test-pattern sources, uplinks, addresses -------------------------------------

use super::addrs::{self, Address};
use super::srtla;

const SRTLA: &str = r#"
ffmpeg = "/opt/ffmpeg"
srtla_send = "/opt/srtla_send"
runtime_dir = "RUNTIME"
sender_idle_s = 1

[outputs.bond]
mode = "srtla"
host = "rec.example.com"
port = 5000
latency_ms = 2000
uplinks = ["usb:ethernet", "wlan0"]

[profiles.test]
video = "libx264"
audio = "aac"

[streams.pattern]
source = { type = "test", size = "640x360", fps = 25 }
profile = "test"
output = "bond"
streamid = "publish/live/pattern"
"#;

#[test]
fn checks_srtla_outputs_test_sources_and_sender_settings() {
    let config = SRTLA.replace("RUNTIME", "/run/helios");
    let settings = settings(&config);
    assert_eq!(settings.sender_port("bond"), Some(6000));
    assert_eq!(settings.sender_port("nope"), None);
    for (from, to, message) in [
        (
            "uplinks = [\"usb:ethernet\", \"wlan0\"]",
            "uplinks = []",
            "at least one uplink",
        ),
        ("\"wlan0\"", "\"usb:modem\"", "must be usb:ethernet"),
        (
            "\"wlan0\"",
            "\"this-name-is-far-too-long\"",
            "must be usb:ethernet",
        ),
        (
            "video = \"libx264\"",
            "video = \"copy\"",
            "needs encoders, not copy",
        ),
        (
            "size = \"640x360\"",
            "size = \"tiny\"",
            "test pattern needs size",
        ),
        ("fps = 25", "fps = 0", "test pattern needs size"),
        ("sender_idle_s = 1", "sender_idle_s = 0", "sender_idle_s"),
        (
            "sender_idle_s = 1",
            "srtla_port_base = 80",
            "srtla_port_base",
        ),
    ] {
        let error = refused(&config.replacen(from, to, 1));
        assert!(error.contains(message), "{to}: {error}");
    }
    let direct = CONFIG.replacen(
        "latency_ms = 1500",
        "latency_ms = 1500\nuplinks = [\"eth1\"]",
        1,
    );
    assert!(refused(&direct).contains("only for srtla outputs"));
}

#[test]
fn builds_test_pattern_arguments_and_srtla_urls() {
    let config = SRTLA.replace("RUNTIME", "/run/helios");
    let settings = settings(&config);
    let target = ffmpeg::Target {
        output: &settings.outputs["bond"],
        streamid: "publish/live/pattern",
        sender_port: Some(6000),
    };
    let args = ffmpeg::test_args(&settings.profiles["test"], target, "640x360", 25, 3000).join(" ");
    for part in [
        "-re -f lavfi -i testsrc2=size=640x360:rate=25",
        "-re -f lavfi -i sine=frequency=1000:sample_rate=48000",
        "-map 0:v:0 -map 1:a:0 -c:v libx264",
        "-c:a aac",
        "srt://127.0.0.1:6000?mode=caller&latency=2000000&streamid=publish/live/pattern",
    ] {
        assert!(args.contains(part), "missing {part:?} in {args}");
    }
    let mut silent = settings.profiles["test"].clone();
    silent.audio = "none".into();
    let args = ffmpeg::test_args(&silent, target, "640x360", 25, 3000).join(" ");
    assert!(!args.contains("sine") && args.contains("-an"), "{args}");
}

/// An `RTM_NEWADDR` message as the kernel sends it.
fn newaddr(interface: &str, address: [u8; 4]) -> Vec<u8> {
    let mut attributes = Vec::new();
    for (kind, value) in [
        (2u16, address.to_vec()),
        (3u16, [interface.as_bytes(), &[0]].concat()),
    ] {
        let len = 4 + value.len();
        attributes.extend_from_slice(&u16::try_from(len).expect("short").to_ne_bytes());
        attributes.extend_from_slice(&kind.to_ne_bytes());
        attributes.extend_from_slice(&value);
        attributes.resize(attributes.len().div_ceil(4) * 4, 0);
    }
    let total = 16 + 8 + attributes.len();
    let mut message = Vec::new();
    message.extend_from_slice(&u32::try_from(total).expect("short").to_ne_bytes());
    message.extend_from_slice(&20u16.to_ne_bytes());
    message.extend_from_slice(&[0; 10]);
    message.extend_from_slice(&[2, 24, 0, 0, 1, 0, 0, 0]);
    message.extend_from_slice(&attributes);
    message
}

fn done() -> Vec<u8> {
    let mut message = 16u32.to_ne_bytes().to_vec();
    message.extend_from_slice(&3u16.to_ne_bytes());
    message.extend_from_slice(&[0; 10]);
    message
}

#[test]
fn parses_the_kernels_address_dump() {
    let mut addresses = Vec::new();
    let first = [
        newaddr("eth1", [10, 0, 1, 2]),
        newaddr("wlan0", [10, 0, 2, 2]),
    ]
    .concat();
    assert!(!addrs::parse_dump(&first, &mut addresses).expect("parsed"));
    assert!(addrs::parse_dump(&done(), &mut addresses).expect("parsed"));
    assert_eq!(
        addresses,
        [
            Address {
                interface: "eth1".into(),
                address: [10, 0, 1, 2].into()
            },
            Address {
                interface: "wlan0".into(),
                address: [10, 0, 2, 2].into()
            },
        ]
    );
    let mut error = 36u32.to_ne_bytes().to_vec();
    error.extend_from_slice(&2u16.to_ne_bytes());
    error.extend_from_slice(&[0; 10]);
    error.extend_from_slice(&(-1i32).to_ne_bytes());
    error.resize(36, 0);
    assert!(addrs::parse_dump(&error, &mut addresses).is_err());
    assert!(
        addrs::parse_dump(
            &[255, 255, 0, 0, 20, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
            &mut addresses
        )
        .is_err()
    );
    // The real kernel: loopback at least.
    let real = addrs::ipv4_addresses().expect("rtnetlink");
    assert!(real.iter().any(|a| a.address.is_loopback()), "{real:?}");
}

fn ethernet_adapter() -> (String, Arc<UsbDevice>) {
    let payload = json!({"port": "1-2", "categories": ["ethernet"], "nodes": {"net": ["eth1"]}});
    (
        "1-2".into(),
        Arc::new(UsbDevice {
            port: "1-2".into(),
            devpath: "/devices/usb1/1-2".into(),
            vid: 0x0bda,
            pid: 0x8153,
            hub: false,
            payload: payload.as_object().expect("object").clone(),
            attached_at: SystemTime::now(),
        }),
    )
}

fn address(interface: &str, ip: [u8; 4]) -> Address {
    Address {
        interface: interface.into(),
        address: ip.into(),
    }
}

#[test]
fn resolves_uplinks_from_usb_categories_and_interface_names() {
    let usb = UsbSnapshot::from([ethernet_adapter()]);
    let addresses = [
        address("eth1", [10, 0, 1, 2]),
        address("wlan0", [10, 0, 2, 2]),
        address("wlan0:1", [10, 0, 2, 3]),
        address("wlan0", [169, 254, 1, 1]),
        address("lo", [127, 0, 0, 1]),
        address("eth0", [192, 168, 1, 5]),
    ];
    let uplinks = [
        "usb:ethernet".to_owned(),
        "wlan0".to_owned(),
        "lo".to_owned(),
    ];
    let ips = srtla::resolve_uplinks(&uplinks, &usb, &addresses);
    assert_eq!(
        ips,
        [[10, 0, 1, 2], [10, 0, 2, 2], [10, 0, 2, 3]].map(std::net::Ipv4Addr::from)
    );
    assert!(srtla::resolve_uplinks(&["usb:cellular".into()], &usb, &addresses).is_empty());
}

#[test]
fn reads_stats_update_notifications_only() {
    let update = r#"{"jsonrpc":"2.0","method":"stats.update","params":{"subscription_id":"sub-0","data":{"active_links":2}}}"#;
    assert_eq!(
        srtla::stats_update(update),
        Some(json!({"active_links": 2}))
    );
    assert_eq!(
        srtla::stats_update(r#"{"jsonrpc":"2.0","result":{"subscription_id":"sub-0"},"id":1}"#),
        None
    );
    assert_eq!(srtla::stats_update("not json"), None);
}

/// A fake `srtla_send` control socket: accepts one client, checks it subscribes, and sends it
/// the given snapshots.
async fn control_socket(path: std::path::PathBuf) -> mpsc::UnboundedSender<Value> {
    let (snapshots, mut receive) = mpsc::unbounded_channel::<Value>();
    let listener = tokio::net::UnixListener::bind(&path).expect("socket");
    tokio::spawn(async move {
        use tokio::io::{AsyncBufReadExt, AsyncWriteExt};
        let (stream, _) = listener.accept().await.expect("client");
        let (reader, mut writer) = stream.into_split();
        let mut lines = tokio::io::BufReader::new(reader).lines();
        let subscribe = lines.next_line().await.expect("read").expect("a line");
        assert!(
            subscribe.contains("\"subscribe\"") && subscribe.contains("\"stats\""),
            "{subscribe}"
        );
        while let Some(data) = receive.recv().await {
            let line = json!({"jsonrpc": "2.0", "method": "stats.update", "params": {"subscription_id": "sub-0", "data": data}});
            writer
                .write_all(format!("{line}\n").as_bytes())
                .await
                .expect("write");
        }
    });
    snapshots
}

fn snapshot(active: u64) -> Value {
    json!({
        "active_links": active, "total_links": 2, "total_window": 4000, "total_in_flight": 0,
        "negotiated_latency_ms": 2000,
        "links": [
            {"ip": "10.0.1.2", "connected": true, "timed_out": false, "rtt_ms": 30, "nak_count": 0, "weak": false, "label": "x"},
            {"ip": "10.0.2.2", "connected": active > 1, "timed_out": false, "rtt_ms": 60, "nak_count": 3, "weak": false},
        ],
    })
}

impl Harness {
    /// Waits for the shadow's `outputs.<name>.state` to be `state`.
    async fn output_state(&mut self, name: &str, state: &str) -> Value {
        loop {
            let (shadow, reported) =
                tokio::time::timeout(Duration::from_secs(20), self.reports.recv())
                    .await
                    .expect("a report in time")
                    .expect("shadow");
            if shadow == "stream" && reported["outputs"][name]["state"] == state {
                return reported["outputs"][name].clone();
            }
        }
    }
}

#[tokio::test]
async fn an_srtla_output_runs_its_sender_first_and_follows_its_uplinks() {
    let runtime = tempfile::tempdir().expect("runtime directory");
    let config = SRTLA.replace("RUNTIME", &runtime.path().display().to_string());
    let addresses = Arc::new(std::sync::Mutex::new(vec![
        address("eth1", [10, 0, 1, 2]),
        address("wlan0", [10, 0, 2, 2]),
    ]));
    let source = addresses.clone();
    let mut harness = harness_with(
        &config,
        None,
        false,
        Arc::new(move || Ok(source.lock().expect("addresses").clone())),
    );
    harness
        .usb
        .set_for_test(UsbSnapshot::from([ethernet_adapter()]));

    // The sender starts first, with the uplinks' addresses in its IP file.
    let sender = harness.next_start().await;
    assert_eq!(
        sender.spec.program,
        std::path::PathBuf::from("/opt/srtla_send")
    );
    let dir = runtime.path().join("srtla");
    let socket = dir.join("bond.sock");
    let ips = dir.join("bond.ips");
    assert_eq!(
        sender.spec.args,
        [
            "--control-socket".to_owned(),
            socket.display().to_string(),
            "--conn-timeout-ms".into(),
            "5000".into(),
            "6000".into(),
            "rec.example.com".into(),
            "5000".into(),
            ips.display().to_string(),
        ]
    );
    assert_eq!(
        std::fs::read_to_string(&ips).expect("ips"),
        "10.0.1.2\n10.0.2.2\n"
    );
    let starting = harness.state_of("pattern", "starting").await;
    assert!(
        starting["last_error"]
            .as_str()
            .is_some_and(|e| e.contains("waiting for output bond")),
        "{starting}"
    );

    // ffmpeg waits until the bond has an active link.
    let stats = control_socket(socket).await;
    stats.send(snapshot(2)).expect("socket");
    let job = harness.next_start().await;
    let args = job.spec.args.join(" ");
    assert!(
        args.contains(
            "srt://127.0.0.1:6000?mode=caller&latency=2000000&streamid=publish/live/pattern"
        ),
        "{args}"
    );
    assert!(args.contains("testsrc2=size=640x360:rate=25"), "{args}");
    job.progress(1_000_000);
    job.progress(2_000_000);
    let live = harness.event("stream.live").await;
    assert!(live.contains("active_links\": Number(2)"), "{live}");
    let up = harness.output_state("bond", "up").await;
    assert_eq!(up["uplinks"], json!(["10.0.1.2", "10.0.2.2"]));

    // An uplink loses its address: the IP file is rewritten and the sender reloaded.
    addresses
        .lock()
        .expect("addresses")
        .retain(|a| a.interface != "wlan0");
    harness
        .usb
        .set_for_test(UsbSnapshot::from([ethernet_adapter()]));
    tokio::time::timeout(Duration::from_secs(10), async {
        while sender.reloads.load(Ordering::SeqCst) == 0 {
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .expect("reloaded");
    assert_eq!(std::fs::read_to_string(&ips).expect("ips"), "10.0.1.2\n");
    stats.send(snapshot(1)).expect("socket");
    // One uplink now, and one active link: still up.
    while harness.output_state("bond", "up").await["active_links"] != 1 {}

    // Stopped: ffmpeg goes at once, the sender after its idle time.
    let Outcome::Ok(_) = harness
        .command("stop", json!({"stream_id": "pattern"}))
        .await
    else {
        panic!("stop refused");
    };
    harness.output_state("bond", "stopped").await;
    assert!(job.stopped.load(Ordering::SeqCst));
    assert!(sender.stopped.load(Ordering::SeqCst));
    harness.stop().await;
}

#[tokio::test]
async fn a_sender_that_exits_is_restarted() {
    let runtime = tempfile::tempdir().expect("runtime directory");
    let config = SRTLA.replace("RUNTIME", &runtime.path().display().to_string());
    let mut harness = harness_with(
        &config,
        None,
        false,
        Arc::new(|| Ok(vec![address("wlan0", [10, 0, 2, 2])])),
    );
    let sender = harness.next_start().await;
    sender.send(JobEvent::Stderr("can't resolve rec.example.com".into()));
    sender.send(JobEvent::Exited(Some(1)));
    let down = harness.output_state("bond", "down").await;
    assert!(
        down["last_error"]
            .as_str()
            .is_some_and(|e| e.contains("can't resolve")),
        "{down}"
    );
    let again = harness.next_start().await;
    assert_eq!(
        again.spec.program,
        std::path::PathBuf::from("/opt/srtla_send")
    );
    harness.stop().await;
}

#[tokio::test]
async fn no_uplink_addresses_leave_the_output_waiting() {
    let runtime = tempfile::tempdir().expect("runtime directory");
    let config = SRTLA.replace("RUNTIME", &runtime.path().display().to_string());
    let mut harness = harness_with(
        &config,
        None,
        false,
        Arc::new(|| Err(std::io::Error::other("no netlink"))),
    );
    harness.next_start().await;
    harness.output_state("bond", "no_uplinks").await;
    harness.stop().await;
}

const RTMP: &str = r#"
ffmpeg = "/opt/ffmpeg"

[rtmp_ingest]
enabled = true
hook_port = HOOK
stat_url = "http://127.0.0.1:STAT/stat"

[outputs.main]
mode = "direct"
host = "ingest.example.com"
port = 4001

[profiles.pocket]
video = "hevc_rkmpp"
bitrate_kbps = 6000
audio = "copy"

[streams.pocket]
source = { type = "rtmp" }
profile = "pocket"
output = "main"
streamid = "publish/live/pocket"

[streams.second]
source = { type = "rtmp", camera = 1 }
profile = "pocket"
output = "main"
streamid = "publish/live/second"
"#;

#[test]
fn checks_rtmp_sources_and_their_keys() {
    let config = RTMP.replace("HOOK", "1936").replace("STAT", "1937");
    let parsed = settings(&config);
    let keys: Vec<_> = parsed
        .streams
        .values()
        .map(|stream| stream.source.rtmp_key())
        .collect();
    assert_eq!(
        keys,
        [Some("ingest".to_owned()), Some("ingest-1".to_owned())]
    );
    for (from, to, message) in [
        ("camera = 1", "camera = 0", "counts from 1"),
        (
            "{ type = \"rtmp\", camera = 1 }",
            "{ type = \"rtmp\" }",
            "already takes RTMP key \"ingest\"",
        ),
        ("hook_port = 1936", "hook_port = 1935", "must be distinct"),
        (
            "http://127.0.0.1:1937/stat",
            "http://10.0.0.1:1937/stat",
            "http://127.0.0.1",
        ),
        (
            "enabled = true",
            "enabled = false",
            "need [modules.stream.rtmp_ingest] enabled",
        ),
    ] {
        let error = refused(&config.replacen(from, to, 1));
        assert!(error.contains(message), "{to}: {error}");
    }
}

#[test]
fn builds_rtmp_arguments_with_hardware_decoding_for_rockchip() {
    let config = RTMP.replace("HOOK", "1936").replace("STAT", "1937");
    let settings = settings(&config);
    let output = &settings.outputs["main"];
    let url = "rtmp://127.0.0.1:1935/live/ingest";
    let mut profile = settings.profiles["pocket"].clone();
    profile.scale = "1280x720".into();
    let args = ffmpeg::rtmp_args(&profile, target(output, "s"), url, 6000).join(" ");
    assert!(
        args.contains("-hwaccel rkmpp -hwaccel_output_format drm_prime -rw_timeout 10000000 -i rtmp://127.0.0.1:1935/live/ingest"),
        "{args}"
    );
    assert!(
        args.contains("-map 0:v:0 -map 0:a:0? -c:v hevc_rkmpp -rc_mode CBR -b:v 6000k"),
        "{args}"
    );
    assert!(
        args.contains("-vf scale_rkrga=w=1280:h=720 -c:a copy"),
        "{args}"
    );
    // H.264 passed through (the relay): no decoding, no encoder options.
    profile.video = "copy".into();
    profile.scale = String::new();
    let args = ffmpeg::rtmp_args(&profile, target(output, "s"), url, 6000).join(" ");
    assert!(!args.contains("hwaccel"), "{args}");
    assert!(args.contains("-c:v copy -c:a copy -f mpegts"), "{args}");
    assert!(!args.contains("-b:v"), "{args}");
}

/// A free loopback port (nothing listens on it once this returns).
fn free_port() -> u16 {
    std::net::TcpListener::bind("127.0.0.1:0")
        .expect("bind")
        .local_addr()
        .expect("address")
        .port()
}

/// nginx's statistics page, serving whatever `page` holds.
async fn stat_server(page: Arc<std::sync::Mutex<String>>) -> u16 {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind");
    let port = listener.local_addr().expect("address").port();
    tokio::spawn(async move {
        use tokio::io::AsyncWriteExt;
        while let Ok((mut stream, _)) = listener.accept().await {
            let body = page.lock().expect("page").clone();
            let response = format!("HTTP/1.1 200 OK\r\nContent-Type: text/xml\r\n\r\n{body}");
            let _ = stream.write_all(response.as_bytes()).await;
        }
    });
    port
}

fn stat_page(publishing: &[(&str, &str)]) -> String {
    let streams: String = publishing
        .iter()
        .map(|(key, address)| {
            format!("<stream><name>{key}</name><client><address>{address}</address><publishing/></client></stream>")
        })
        .collect();
    format!(
        "<rtmp><server><application><name>live</name><live>{streams}</live></application></server></rtmp>"
    )
}

/// nginx's `on_publish` / `on_publish_done`; the hook's status code.
async fn hook(port: u16, call: &str, key: &str, address: &str) -> u16 {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let body = format!("call={call}&app=live&name={key}&addr={address}&clientid=1");
    for _ in 0..100 {
        if let Ok(mut stream) = tokio::net::TcpStream::connect(("127.0.0.1", port)).await {
            let request = format!(
                "POST /rtmp/{call} HTTP/1.0\r\nContent-Length: {}\r\n\r\n{body}",
                body.len()
            );
            stream.write_all(request.as_bytes()).await.expect("send");
            let mut reply = String::new();
            stream.read_to_string(&mut reply).await.expect("reply");
            return reply[9..12].parse().expect("status");
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    panic!("the hook never listened");
}

#[tokio::test]
async fn rtmp_streams_follow_the_hook_and_the_statistics_page() {
    let page = Arc::new(std::sync::Mutex::new(stat_page(&[(
        "ingest",
        "192.168.8.20",
    )])));
    let stat = stat_server(page.clone()).await;
    let hook_port = free_port();
    let config = RTMP
        .replace("HOOK", &hook_port.to_string())
        .replace("STAT", &stat.to_string());
    let mut harness = harness(&config, None, false);

    // Already publishing when the daemon starts: found on the statistics page.
    let job = harness.next_start().await;
    let args = job.spec.args.join(" ");
    assert!(
        args.contains("-i rtmp://127.0.0.1:1935/live/ingest"),
        "{args}"
    );
    let connected = harness.event("stream.connected").await;
    assert!(connected.contains("192.168.8.20"), "{connected}");
    harness.state_of("second", "waiting_for_input").await;

    // Gone from the page (a publish_done the daemon missed): the stream waits again.
    *page.lock().expect("page") = stat_page(&[]);
    let disconnected = harness.event("stream.disconnected").await;
    assert!(disconnected.contains("publish_done"), "{disconnected}");
    harness.state_of("pocket", "waiting_for_input").await;
    assert!(job.stopped.load(Ordering::SeqCst));

    // A camera publishes through the hook; nginx lists it a moment later.
    assert_eq!(
        hook(hook_port, "publish", "ingest-1", "192.168.8.21").await,
        200
    );
    let job = harness.next_start().await;
    assert!(job.spec.args.join(" ").contains("/live/ingest-1"));
    *page.lock().expect("page") = stat_page(&[("ingest-1", "192.168.8.21")]);
    // A second publisher on the same key, and a key no stream takes, are refused.
    assert_eq!(
        hook(hook_port, "publish", "ingest-1", "192.168.8.22").await,
        403
    );
    assert_eq!(
        hook(hook_port, "publish", "ingest-7", "192.168.8.22").await,
        403
    );
    // Past the grace period, the page keeps it.
    tokio::time::sleep(Duration::from_secs(3)).await;
    assert!(!job.stopped.load(Ordering::SeqCst));
    let reported = loop {
        let (shadow, reported) = tokio::time::timeout(WAIT, harness.reports.recv())
            .await
            .expect("a report")
            .expect("shadow");
        if shadow == "stream" && reported["rtmp_ingest"]["publishers"]["ingest-1"].is_object() {
            break reported;
        }
    };
    assert_eq!(reported["rtmp_ingest"]["state"], "ok");
    assert_eq!(
        reported["rtmp_ingest"]["publishers"]["ingest-1"]["address"],
        "192.168.8.21"
    );
    assert_eq!(
        reported["streams"]["second"]["source"]["publisher"],
        "192.168.8.21"
    );

    // The camera stops.
    assert_eq!(
        hook(hook_port, "publish_done", "ingest-1", "192.168.8.21").await,
        200
    );
    *page.lock().expect("page") = stat_page(&[]);
    harness.state_of("second", "waiting_for_input").await;
    assert!(job.stopped.load(Ordering::SeqCst));
    harness.stop().await;
}

#[test]
fn checks_encoder_backends_and_bitrate_modes() {
    let gst = super::encoder::tests::GST;
    settings(gst);
    for (from, to, message) in [
        (
            "encoder = \"belacoder\"\nbitrate_mode",
            "bitrate_mode",
            "needs encoder = \"belacoder\"",
        ),
        (
            "video = \"h264_rkmpp\"\nencoder = \"ceracoder\"",
            "video = \"libx264\"\nencoder = \"ceracoder\"",
            "takes video hevc_rkmpp, h264_rkmpp",
        ),
        (
            "video = \"hevc_rkmpp\"\nencoder = \"belacoder\"",
            "video = \"libx265\"\nencoder = \"belacoder\"",
            "takes video",
        ),
        (
            "format = \"mjpeg\"",
            "format = \"h264\"",
            "mjpeg or yuyv422",
        ),
        (
            "encoder = \"belacoder\"\nbitrate_mode",
            "encoder = \"gstreamer\"\nbitrate_mode",
            "encoder",
        ),
        (
            "bitrate_mode = \"adaptive\"",
            "bitrate_mode = \"adaptive\"\nsource_ceiling_percent = 500",
            "source_ceiling_percent must be 0 to 400",
        ),
    ] {
        assert!(gst.contains(from), "{from}");
        let text = gst.replacen(from, to, 1);
        let error = toml::from_str::<StreamSettings>(&text)
            .map_err(|e| e.to_string())
            .and_then(|s| s.check().map(|_| ()))
            .expect_err("refused");
        assert!(error.contains(message), "{to}: {error}");
    }
}

const BELACODER: &str = r#"
belacoder = "/opt/belacoder"
runtime_dir = "RUNTIME"

[outputs.main]
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
audio = "aac"

[streams.pattern]
source = { type = "test", size = "1280x720", fps = 30 }
profile = "ada"
output = "main"
streamid = "publish/live/pattern"
"#;

#[tokio::test(start_paused = true)]
async fn a_gstreamer_encoder_goes_live_on_connect_and_reloads_new_bitrates() {
    let runtime = tempfile::tempdir().expect("runtime directory");
    let config = BELACODER.replace("RUNTIME", &runtime.path().display().to_string());
    let mut harness = harness(&config, None, false);
    let bitrate_file = runtime.path().join("encoders/pattern.bitrate");

    // It starts with its pipeline and range written, and goes live on its SRT connection.
    let job = harness.next_start().await;
    assert_eq!(job.spec.program, std::path::PathBuf::from("/opt/belacoder"));
    assert!(runtime.path().join("encoders/pattern.pipeline").exists());
    assert_eq!(
        std::fs::read_to_string(&bitrate_file).expect("range"),
        "1000000\n4000000\n"
    );
    harness.state_of("pattern", "starting").await;
    job.send(JobEvent::Stderr(
        "Gstreamer pipeline: videotestsrc ...".into(),
    ));
    job.send(JobEvent::Stderr(
        "SRT connected to ingest.example.com:4001. Negotiated latency: 2000 ms".into(),
    ));
    harness.event("stream.live").await;
    harness.state_of("pattern", "live").await;

    // No progress output, and no stall: it watches its own pipeline.
    tokio::time::advance(Duration::from_secs(120)).await;
    let Outcome::Ok(status) = harness
        .command("status", json!({"stream_id": "pattern"}))
        .await
    else {
        panic!("status");
    };
    assert_eq!(status["state"], "live");
    assert!(
        status["log"].to_string().contains("SRT connected"),
        "{status}"
    );
    assert!(!job.stopped.load(Ordering::SeqCst));

    // A new ceiling is a rewritten range and a SIGHUP, not a restart.
    let outcome = harness
        .command(
            "start",
            json!({"stream_id": "pattern", "bitrate_kbps": 6000}),
        )
        .await;
    assert!(matches!(outcome, Outcome::Ok(_)), "{outcome:?}");
    assert_eq!(
        std::fs::read_to_string(&bitrate_file).expect("range"),
        "1000000\n6000000\n"
    );
    assert_eq!(job.reloads.load(Ordering::SeqCst), 1);
    assert!(!job.stopped.load(Ordering::SeqCst));

    // When it exits, the reason names it, with its last line.
    job.send(JobEvent::Stderr(
        "Pipeline stall detected. Will exit now".into(),
    ));
    job.send(JobEvent::Exited(Some(1)));
    let status = harness.state_of("pattern", "reconnecting").await;
    let error = status["last_error"].as_str().expect("error").to_owned();
    assert!(
        error.starts_with("belacoder exited (code 1): Pipeline stall"),
        "{error}"
    );
    harness.stop().await;
}

#[tokio::test(start_paused = true)]
async fn a_gstreamer_encoder_that_never_connects_is_restarted() {
    let runtime = tempfile::tempdir().expect("runtime directory");
    let config = BELACODER.replace("RUNTIME", &runtime.path().display().to_string());
    let mut harness = harness(&config, None, false);
    let job = harness.next_start().await;
    tokio::time::advance(Duration::from_secs(61)).await;
    let status = harness.state_of("pattern", "reconnecting").await;
    assert!(job.stopped.load(Ordering::SeqCst));
    let error = status["last_error"].as_str().expect("error").to_owned();
    assert!(error.contains("didn't connect over SRT in time"), "{error}");
    harness.stop().await;
}

const RTMP_ADAPTIVE: &str = r#"
belacoder = "/opt/belacoder"
runtime_dir = "RUNTIME"

[rtmp_ingest]
enabled = true
hook_port = HOOK
stat_url = "http://127.0.0.1:STAT/stat"

[outputs.main]
mode = "direct"
host = "ingest.example.com"
port = 4001

[profiles.pocket]
video = "hevc_rkmpp"
encoder = "belacoder"
bitrate_mode = "adaptive"
bitrate_kbps = 6000
min_bitrate_kbps = 1000
max_bitrate_kbps = 8000
audio = "copy"

[streams.pocket]
source = { type = "rtmp" }
profile = "pocket"
output = "main"
streamid = "publish/live/pocket"
"#;

fn measured_page(video_bps: u64) -> String {
    format!(
        "<rtmp><server><application><name>live</name><live><stream><name>ingest</name>\
         <bw_video>{video_bps}</bw_video><client><address>192.168.8.20</address><publishing/>\
         </client></stream></live></application></server></rtmp>"
    )
}

/// Waits until `file` holds `contents`.
async fn file_becomes(file: &std::path::Path, contents: &str) {
    let found = tokio::time::timeout(Duration::from_secs(20), async {
        while std::fs::read_to_string(file).ok().as_deref() != Some(contents) {
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    })
    .await;
    assert!(
        found.is_ok(),
        "{} never held {contents:?}: {:?}",
        file.display(),
        std::fs::read_to_string(file)
    );
}

#[tokio::test]
async fn an_adaptive_rtmp_streams_ceiling_follows_the_camera() {
    let runtime = tempfile::tempdir().expect("runtime directory");
    let page = Arc::new(std::sync::Mutex::new(measured_page(3_000_000)));
    let stat = stat_server(page.clone()).await;
    let config = RTMP_ADAPTIVE
        .replace("RUNTIME", &runtime.path().display().to_string())
        .replace("HOOK", &free_port().to_string())
        .replace("STAT", &stat.to_string());
    let mut harness = harness(&config, None, false);
    let range = runtime.path().join("encoders/pocket.bitrate");

    // The camera sends 3 Mbps: the encoder starts with that as its ceiling, not 6.
    let job = harness.next_start().await;
    assert_eq!(
        std::fs::read_to_string(&range).expect("range"),
        "1000000\n3000000\n"
    );
    job.send(JobEvent::Stderr(
        "SRT connected to ingest.example.com:4001. Negotiated latency: 2000 ms".into(),
    ));
    harness.state_of("pocket", "live").await;

    // A small change (smoothed 3.1 Mbps, 3%) leaves it alone.
    *page.lock().expect("page") = measured_page(3_200_000);
    tokio::time::sleep(Duration::from_secs(3)).await;
    assert_eq!(job.reloads.load(Ordering::SeqCst), 0);
    assert_eq!(
        std::fs::read_to_string(&range).expect("range"),
        "1000000\n3000000\n"
    );

    // A big one moves it, by SIGHUP; never past the stream's 6 Mbps.
    *page.lock().expect("page") = measured_page(9_000_000);
    file_becomes(&range, "1000000\n6000000\n").await;
    assert!(job.reloads.load(Ordering::SeqCst) >= 1);
    assert!(!job.stopped.load(Ordering::SeqCst), "no restart");
    let Outcome::Ok(status) = harness
        .command("status", json!({"stream_id": "pocket"}))
        .await
    else {
        panic!("status");
    };
    assert_eq!(status["bitrate_ceiling_kbps"], 6000);
    assert!(
        status["source_kbps"]
            .as_u64()
            .is_some_and(|kbps| kbps > 6000),
        "{status}"
    );

    // The camera goes: the ceiling is forgotten, for the next one to set.
    *page.lock().expect("page") = stat_page(&[]);
    let waiting = harness.state_of("pocket", "waiting_for_input").await;
    assert_eq!(waiting["bitrate_ceiling_kbps"], Value::Null);
    assert_eq!(waiting["source_kbps"], Value::Null);
    harness.stop().await;
}

// --- Settings from the desired state (HLD section 7.3.7) ---------------------------------------

const REMOTE: &str = r#"
ffmpeg = "/opt/ffmpeg"
srtla_send = "/opt/srtla_send"
runtime_dir = "RUNTIME"
srtla_uplinks = ["wlan0"]

[outputs.main]
mode = "direct"
host = "ingest.example.com"
port = 4001
latency_ms = 1500
passphrase = "not-a-secret-123"

[profiles.big]
video = "libx264"
bitrate_kbps = 4000
min_bitrate_kbps = 1000
max_bitrate_kbps = 8000

[profiles.small]
video = "libx264"
bitrate_kbps = 2000
min_bitrate_kbps = 500
max_bitrate_kbps = 3000

[profiles.hevc]
video = "libx265"

[profiles.passthrough]
video = "copy"
audio = "copy"

[streams.pattern]
source = { type = "test", size = "1280x720", fps = 30 }
profile = "big"
output = "main"
streamid = "publish/live/pattern"
"#;

const CONFIGURED: &str = "srt://ingest.example.com:4001?streamid=publish/live/pattern&latency=1500&passphrase=not-a-secret-123";

impl Harness {
    /// The next `stream` report that `matches`.
    async fn report_where(&mut self, matches: impl Fn(&Value) -> bool) -> Value {
        loop {
            let (shadow, reported) = tokio::time::timeout(WAIT, self.reports.recv())
                .await
                .expect("a report in time")
                .expect("shadow");
            let reported = Value::Object(reported);
            if shadow == "stream" && matches(&reported) {
                return reported;
            }
        }
    }

    async fn status_of(&self, id: &str) -> Value {
        match self.command("status", json!({"stream_id": id})).await {
            Outcome::Ok(status) => status,
            other => panic!("{other:?}"),
        }
    }

    fn desire(&self, desired: Value) {
        self.desired
            .send(json!({"streams": {"pattern": desired}}))
            .expect("module running");
    }
}

fn settings_of(rejected: &Value) -> Vec<&str> {
    rejected
        .as_array()
        .expect("rejected")
        .iter()
        .map(|r| r["setting"].as_str().expect("setting"))
        .collect()
}

#[test]
fn checks_srtla_uplinks_and_leaves_a_sender_port_per_stream() {
    let config = REMOTE.replace("RUNTIME", "/run/helios");
    let parsed = settings(&config);
    assert_eq!(parsed.stream_sender_port("pattern"), Some(6001));
    assert_eq!(parsed.stream_sender_port("nope"), None);
    assert_eq!(
        settings(&config.replace("srtla_uplinks = [\"wlan0\"]\n", "")).srtla_uplinks,
        ["usb:ethernet", "usb:cellular", "usb:wifi"]
    );
    assert!(
        refused(&config.replace("[\"wlan0\"]", "[\"usb:modem\"]"))
            .contains("srtla_uplinks: \"usb:modem\" must be")
    );
    // The last port must leave one for the stream too.
    let full = format!("srtla_port_base = 65534\n{config}");
    assert!(refused(&full).contains("a port per output and per stream"));
    settings(&full.replace("65534", "65533"));
}

#[tokio::test(start_paused = true)]
async fn the_desired_state_sets_a_streams_profile_source_and_destination() {
    let runtime = tempfile::tempdir().expect("runtime directory");
    let config = REMOTE.replace("RUNTIME", &runtime.path().display().to_string());
    let mut harness = harness(&config, Some(&["libx264", "aac"]), false);
    let first = harness.next_start().await;
    let args = first.spec.args.join(" ");
    assert!(args.contains("-b:v 4000k"), "{args}");
    assert!(args.contains("srt://ingest.example.com:4001?"), "{args}");
    let status = harness.state_of("pattern", "starting").await;
    assert_eq!(status["destination"], CONFIGURED);
    assert_eq!(status["source_ceiling_percent"], 100);
    assert_eq!(status["rejected"], json!([]));
    assert_eq!(
        status["overrides"],
        json!({"source": null, "profile": null, "destination": null, "source_ceiling_percent": null})
    );

    // A new profile and destination together: one restart with both.
    harness.desire(json!({
        "profile": "small", "destination": "srt://other.example.com:4000?streamid=x/y",
    }));
    let second = harness.next_start().await;
    assert!(first.stopped.load(Ordering::SeqCst));
    let args = second.spec.args.join(" ");
    assert!(args.contains("-b:v 2000k"), "{args}");
    assert!(
        args.contains("srt://other.example.com:4000?mode=caller&latency=1500000&streamid=x/y"),
        "the configured latency, the URL's stream ID: {args}"
    );
    assert!(
        !args.contains("passphrase"),
        "the passphrase is the server's: {args}"
    );
    let reported = harness
        .report_where(|r| r["streams"]["pattern"]["profile"] == "small")
        .await;
    let status = &reported["streams"]["pattern"];
    assert_eq!(
        status["destination"],
        "srt://other.example.com:4000?streamid=x/y"
    );
    assert_eq!(status["output"], "stream:pattern");
    assert_eq!(status["bitrate_kbps"], 2000);
    assert_eq!(status["overrides"]["profile"], "small");
    assert_eq!(status["overrides"]["destination"], status["destination"]);
    assert_eq!(
        reported["outputs"]["stream:pattern"],
        Value::Null,
        "direct: no sender"
    );

    // Refusals change nothing, and each says why.
    let refused = json!({
        "profile": "hevc", "destination": "srt://h:1?mode=listener",
        "source": {"type": "test", "size": "big"}, "source_ceiling_percent": 500,
        "bitrate_kbps": 99_999, "state": "paused",
    });
    // (Commands go before desired state, so the report shows when it's applied.)
    harness.desire(refused.clone());
    let reported = harness
        .report_where(|r| {
            r["streams"]["pattern"]["rejected"]
                .as_array()
                .is_some_and(|rejected| rejected.len() == 6)
        })
        .await;
    let status = reported["streams"]["pattern"].clone();
    assert_eq!(status["profile"], "small");
    assert_eq!(
        status["destination"],
        "srt://other.example.com:4000?streamid=x/y"
    );
    assert_eq!(
        settings_of(&status["rejected"]),
        [
            "bitrate",
            "destination",
            "profile",
            "source",
            "source_ceiling_percent",
            "state"
        ]
    );
    let reasons: Vec<&str> = status["rejected"]
        .as_array()
        .expect("rejected")
        .iter()
        .map(|r| r["reason"].as_str().expect("reason"))
        .collect();
    for (reason, expected) in reasons.iter().zip([
        "outside the profile's limits",
        "mode: only streamid, latency and passphrase",
        "has no libx265 encoder",
        "a test pattern needs size WIDTHxHEIGHT",
        "0 to 400",
        "live or stopped",
    ]) {
        assert!(
            reason.contains(expected),
            "{reason:?} should say {expected:?}"
        );
    }
    // The same values again keep their first time; a new value gets its own.
    harness.desire(refused);
    harness.desire(json!({"profile": "passthrough"}));
    let reported = harness
        .report_where(|r| {
            r["streams"]["pattern"]["rejected"][2]["reason"]
                .as_str()
                .is_some_and(|r| r.contains("pattern: a test pattern is generated"))
        })
        .await;
    let rejected = &reported["streams"]["pattern"]["rejected"];
    for index in [0, 1, 3, 4, 5] {
        assert_eq!(rejected[index], status["rejected"][index]);
    }
    assert!(
        harness.started.try_recv().is_err(),
        "nothing restarted for refused values"
    );

    // null goes back to helios.toml's; a new source restarts too.
    harness.desire(json!({
        "profile": null, "destination": null, "source": {"type": "test", "size": "640x360", "fps": 25},
    }));
    let third = harness.next_start().await;
    assert!(second.stopped.load(Ordering::SeqCst));
    let args = third.spec.args.join(" ");
    assert!(args.contains("-b:v 4000k"), "{args}");
    assert!(args.contains("testsrc2=size=640x360:rate=25"), "{args}");
    assert!(args.contains("srt://ingest.example.com:4001?"), "{args}");
    let status = harness.status_of("pattern").await;
    assert_eq!(status["destination"], CONFIGURED);
    assert_eq!(status["output"], "main");
    assert_eq!(
        status["overrides"],
        json!({
            "source": {"type": "test", "size": "640x360", "fps": 25}, "profile": null,
            "destination": null, "source_ceiling_percent": null,
        })
    );
    assert_eq!(
        settings_of(&status["rejected"]),
        ["bitrate", "source_ceiling_percent", "state"],
        "accepted settings clear their refusals"
    );
    harness.stop().await;
}

#[tokio::test(start_paused = true)]
async fn an_srtla_destination_runs_its_own_sender() {
    let runtime = tempfile::tempdir().expect("runtime directory");
    let config = REMOTE.replace("RUNTIME", &runtime.path().display().to_string());
    let mut harness = harness_with(
        &config,
        None,
        false,
        Arc::new(|| {
            Ok(vec![
                address("eth0", [10, 0, 1, 2]),
                address("wlan0", [10, 0, 2, 2]),
            ])
        }),
    );
    let first = harness.next_start().await;

    harness.desire(json!({"destination": "srtla://rec.example.com:5000?latency=800"}));
    let sender = harness.next_start().await;
    assert!(first.stopped.load(Ordering::SeqCst));
    let dir = runtime.path().join("srtla");
    assert_eq!(sender.spec.name, "srtla:stream:pattern");
    assert_eq!(
        sender.spec.args,
        [
            "--control-socket".to_owned(),
            dir.join("stream:pattern.sock").display().to_string(),
            "--conn-timeout-ms".into(),
            "5000".into(),
            "6001".into(),
            "rec.example.com".into(),
            "5000".into(),
            dir.join("stream:pattern.ips").display().to_string(),
        ],
        "the port after the outputs'"
    );
    assert_eq!(
        std::fs::read_to_string(dir.join("stream:pattern.ips")).expect("ips"),
        "10.0.2.2\n",
        "a direct output's stream bonds srtla_uplinks"
    );
    let reported = harness
        .report_where(|r| r["outputs"]["stream:pattern"].is_object())
        .await;
    let status = &reported["streams"]["pattern"];
    assert_eq!(status["output"], "stream:pattern");
    assert_eq!(
        status["destination"],
        "srtla://rec.example.com:5000?latency=800"
    );
    assert!(
        status["last_error"]
            .as_str()
            .is_some_and(|e| e.contains("waiting for output stream:pattern")),
        "{status}"
    );

    // The configured destination, written out in full, is no override: the sender goes.
    harness.desire(json!({"destination": CONFIGURED}));
    let job = harness.next_start().await;
    assert_eq!(job.spec.name, "pattern");
    assert!(
        job.spec
            .args
            .join(" ")
            .contains("srt://ingest.example.com:4001?")
    );
    let reported = harness
        .report_where(|r| r["outputs"]["stream:pattern"].is_null())
        .await;
    assert!(sender.stopped.load(Ordering::SeqCst));
    assert_eq!(
        reported["streams"]["pattern"]["overrides"]["destination"],
        Value::Null
    );
    assert_eq!(reported["streams"]["pattern"]["destination"], CONFIGURED);
    harness.stop().await;
}

#[tokio::test(start_paused = true)]
async fn a_saved_profile_applies_before_the_first_start() {
    let runtime = tempfile::tempdir().expect("runtime directory");
    let config = REMOTE.replace("RUNTIME", &runtime.path().display().to_string());
    let mut harness = harness(&config, None, false);
    // Queued before the module's first pass, as the daemon's saved state is.
    harness.desire(json!({"state": "live", "profile": "small", "source_ceiling_percent": 80}));
    let job = harness.next_start().await;
    assert!(job.spec.args.join(" ").contains("-b:v 2000k"));
    let status = harness.status_of("pattern").await;
    assert_eq!(status["source_ceiling_percent"], 80);
    assert_eq!(status["overrides"]["source_ceiling_percent"], 80);
    harness.stop().await;
}

#[tokio::test(start_paused = true)]
async fn refuses_a_taken_rtmp_key_an_unbondable_destination_and_wrong_types() {
    let runtime = tempfile::tempdir().expect("runtime directory");
    let config = REMOTE
        .replace("RUNTIME", &runtime.path().display().to_string())
        .replace("srtla_uplinks = [\"wlan0\"]", "srtla_uplinks = []")
        + &format!(
            r#"
[rtmp_ingest]
enabled = true
hook_port = {}
stat_url = "http://127.0.0.1:{}/stat"

[streams.pocket]
source = {{ type = "rtmp" }}
profile = "big"
output = "main"
streamid = "publish/live/pocket"
desired = "stopped"
"#,
            free_port(),
            free_port()
        );
    let mut harness = harness(&config, None, false);
    harness.next_start().await;

    // An override the new profile can't take goes back to the profile's bitrate.
    harness.desire(json!({"bitrate_kbps": 7000}));
    let job = harness.next_start().await;
    assert!(job.spec.args.join(" ").contains("-b:v 7000k"));
    harness.desire(json!({"profile": "small"}));
    let job = harness.next_start().await;
    assert!(job.spec.args.join(" ").contains("-b:v 2000k"));

    harness.desire(json!({
        "source": {"type": "rtmp"}, "destination": "srtla://rec.example.com:5000",
        "profile": 7, "source_ceiling_percent": "high",
    }));
    let reported = harness
        .report_where(|r| {
            r["streams"]["pattern"]["rejected"]
                .as_array()
                .is_some_and(|rejected| rejected.len() == 4)
        })
        .await;
    let status = &reported["streams"]["pattern"];
    assert_eq!(status["bitrate_override_kbps"], Value::Null);
    let rejected = &status["rejected"];
    for (index, expected) in [
        "srtla_uplinks is empty",
        "profile must be a profile name",
        "pattern: stream pocket already takes RTMP key \"ingest\"",
        "0 to 400",
    ]
    .into_iter()
    .enumerate()
    {
        assert!(
            rejected[index]["reason"]
                .as_str()
                .is_some_and(|r| r.contains(expected)),
            "{rejected}"
        );
    }
    harness.desire(json!({"source": {"type": "usb"}, "destination": 5}));
    let reported = harness
        .report_where(|r| {
            r["streams"]["pattern"]["rejected"][0]["reason"]
                .as_str()
                .is_some_and(|r| r.contains("must be an srt:// or srtla:// URL"))
        })
        .await;
    assert!(
        reported["streams"]["pattern"]["rejected"][2]["reason"]
            .as_str()
            .is_some_and(|r| r.starts_with("source: ")),
        "{reported}"
    );
    harness.stop().await;
}
