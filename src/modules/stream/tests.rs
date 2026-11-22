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

fn settings(text: &str) -> StreamSettings {
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
            "srtla outputs aren't supported yet",
        ),
        ("mode = \"direct\"", "mode = \"udp\"", "mode must be direct"),
        (
            "type = \"camera\", video = \"usb:1-1.3\", audio = \"usb:1-1.3\"",
            "type = \"rtmp\"",
            "RTMP sources aren't supported yet",
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
        &settings.outputs["main"],
        "publish/live/backpack",
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
    let args = ffmpeg::camera_args(profile, &output, "s", &nodes(false), 1).join(" ");
    assert!(
        args.contains("-i /dev/video2 -map 0:v:0 -c:v copy -an"),
        "{args}"
    );
    assert!(
        args.ends_with("srt://[2001:db8::1]:4001?mode=caller&latency=1500000&streamid=s"),
        "{args}"
    );
    profile.video = "hevc_rkmpp".into();
    let args = ffmpeg::camera_args(profile, &output, "s", &nodes(false), 6000).join(" ");
    assert!(
        args.contains("-c:v hevc_rkmpp -rc_mode CBR -b:v 6000k"),
        "{args}"
    );
    profile.audio = "copy".into();
    let args = ffmpeg::camera_args(profile, &output, "s", &nodes(true), 6000).join(" ");
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
struct Started {
    spec: JobSpec,
    job: u64,
    events: mpsc::UnboundedSender<Tagged>,
    stopped: Arc<AtomicBool>,
}

impl Started {
    fn send(&self, event: JobEvent) {
        let _ = self.events.send(Tagged {
            job: self.job,
            event,
        });
    }

    fn progress(&self, out_time_us: i64) {
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
    job: u64,
    events: mpsc::UnboundedSender<Tagged>,
}

impl Job for FakeJob {
    fn stop(&mut self, _grace: Duration) -> BoxFuture<'_, ()> {
        self.stopped.store(true, Ordering::SeqCst);
        let _ = self.events.send(Tagged {
            job: self.job,
            event: JobEvent::Exited(None),
        });
        Box::pin(async {})
    }
}

struct FakeSpawner {
    started: mpsc::UnboundedSender<Started>,
    encoders: Option<BTreeSet<String>>,
    refuse: AtomicBool,
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
        let _ = self.started.send(Started {
            spec: spec.clone(),
            job,
            events: events.clone(),
            stopped: stopped.clone(),
        });
        Ok(Box::new(FakeJob {
            stopped,
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
    let usb = UsbHandle::default();
    let (started_tx, started) = mpsc::unbounded_channel();
    let spawner = FakeSpawner {
        started: started_tx,
        encoders: encoders.map(|names| names.iter().map(|name| (*name).to_owned()).collect()),
        refuse: AtomicBool::new(refuse),
    };
    let module = StreamModule::with_spawner(settings(config), usb.clone(), Arc::new(spawner));
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
        loop {
            let (shadow, reported) = tokio::time::timeout(WAIT, self.reports.recv())
                .await
                .expect("a report in time")
                .expect("shadow");
            if shadow == "stream" && reported["streams"]["camera"]["state"] == state {
                return reported["streams"]["camera"].clone();
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
