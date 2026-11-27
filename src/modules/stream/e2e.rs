//! The stream daemon end to end (LLD 4, sections 12 and 15): `helios stream-daemon` as its own
//! process, with the real ffmpeg, `srtla_send`, `srtla_rec` and irl-srt-server, and this test as
//! Helios (the daemon's client). Run only by `tests/stream-e2e/helios.sh`, inside the network
//! namespace it sets up (uplinks `up0` 10.10.1.2 and `up1` 10.10.2.2, the receiving side on
//! 10.10.0.1, nginx from `dist/rtmp/nginx.conf`); skipped otherwise.

use std::process::{Child, Command};
use std::time::Duration;

use serde_json::{Value, json};
use tokio::sync::mpsc;

use super::StreamClient;
use crate::modules::{Module, ModuleContext};
use crate::mqtt::manager::{MqttHandle, Request as MqttRequest};
use crate::mqtt::shadow::{ShadowHandle, TestReports};
use crate::router::{Outcome, PendingCommand};

const WAIT: Duration = Duration::from_secs(60);

fn say(message: &str) {
    println!("HELIOS  {message}");
}

/// Plays `play/live/e2e` from irl-srt-server for a few seconds; the codecs it got.
fn played_codecs(run: &str, name: &str) -> String {
    played(run, name, "e2e")
}

/// Plays `play/live/<stream>` from irl-srt-server for a few seconds; the codecs it got.
fn played(run: &str, name: &str, stream: &str) -> String {
    let file = format!("{run}/{name}.ts");
    let _ = Command::new("timeout")
        .args(["20", "ffmpeg", "-hide_banner", "-loglevel", "error", "-i"])
        .arg(format!(
            "srt://10.10.0.1:4000?mode=caller&streamid=play/live/{stream}&latency=200000"
        ))
        .args(["-t", "4", "-c", "copy", "-f", "mpegts", &file])
        .status();
    let output = Command::new("ffprobe")
        .args([
            "-v",
            "error",
            "-show_entries",
            "stream=codec_name",
            "-of",
            "csv=p=0",
            &file,
        ])
        .output()
        .map(|output| String::from_utf8_lossy(&output.stdout).into_owned())
        .unwrap_or_default();
    let mut codecs: Vec<&str> = output.lines().filter(|line| !line.is_empty()).collect();
    codecs.sort_unstable();
    codecs.dedup();
    codecs.join(",")
}

fn ip(args: &str) {
    let status = Command::new("ip")
        .args(args.split(' '))
        .status()
        .expect("ip");
    assert!(status.success(), "ip {args}");
}

/// The PIDs of processes named `name`.
fn pids(name: &str) -> String {
    let output = Command::new("pgrep")
        .args(["-x", name])
        .output()
        .expect("pgrep");
    String::from_utf8_lossy(&output.stdout)
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(",")
}

/// Helios's side of the test: the stream module as the daemon's client.
struct Helios {
    published: mpsc::UnboundedReceiver<MqttRequest>,
    reports: TestReports,
    commands: mpsc::Sender<PendingCommand>,
    cancel: tokio_util::sync::CancellationToken,
    task: tokio::task::JoinHandle<Result<(), crate::modules::ModuleError>>,
}

impl Helios {
    fn start(socket: &str) -> Self {
        let (mqtt, published, _status) = MqttHandle::for_test();
        let (shadows, reports) = ShadowHandle::for_test();
        let (commands, commands_rx) = mpsc::channel(4);
        let cancel = tokio_util::sync::CancellationToken::new();
        let ctx = ModuleContext {
            commands: commands_rx,
            shadows,
            mqtt,
            sysfs: "/sys".into(),
            cancel: cancel.clone(),
        };
        let client = StreamClient::new(socket.into());
        let task = tokio::spawn(async move { client.run(ctx).await });
        Self {
            published,
            reports,
            commands,
            cancel,
            task,
        }
    }

    async fn event(&mut self, kind: &str) -> String {
        loop {
            let request = tokio::time::timeout(WAIT, self.published.recv())
                .await
                .unwrap_or_else(|_| panic!("no {kind} in time"))
                .expect("mqtt");
            let text = format!("{request:?}");
            if text.contains(&format!("kind: \"{kind}\"")) {
                return text;
            }
        }
    }

    async fn shadow(&mut self, what: &str, check: impl Fn(&Value) -> bool) -> Value {
        let reported = tokio::time::timeout(WAIT, async {
            loop {
                let (shadow, reported) = self.reports.recv().await.expect("shadow");
                let reported = Value::Object(reported);
                if shadow == "stream" && check(&reported) {
                    return reported;
                }
            }
        })
        .await
        .unwrap_or_else(|_| panic!("the shadow never showed {what}"));
        say(&format!("shadow: {what}"));
        reported
    }

    async fn command(&self, name: &str, args: Value) -> Outcome {
        let (pending, answer) = PendingCommand::for_test("stream", name, args);
        self.commands.send(pending).await.expect("client running");
        tokio::time::timeout(WAIT, answer)
            .await
            .expect("an answer")
            .expect("answered")
    }

    /// Stops this Helios, as a restart or a crash would.
    async fn stop(self) {
        self.cancel.cancel();
        let _ = tokio::time::timeout(WAIT, self.task).await;
    }
}

struct Daemon(Child);

impl Drop for Daemon {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

impl Daemon {
    /// `helios stream-daemon` with `streams` (TOML under `[modules.stream]`) as its config.
    fn start(bin: &str, run: &str, log: &str, settings: &str) -> Self {
        // The daemon loads the whole helios.toml, which checks the CA bundle holds certificates.
        for file in ["libsofthsm2.so", "pin"] {
            std::fs::write(format!("{run}/{file}"), "").expect("placeholder");
        }
        let config = format!(
            r#"
[device]
thing_name = "t-01J0000000000000000000E2E0"

[identity]
pkcs11_module = "{run}/libsofthsm2.so"
token_label = "helios"
key_label = "device-key"
pin = "file:{run}/pin"

[aws]
region = "us-west-2"
iot_endpoint = "example-ats.iot.us-west-2.amazonaws.com"
credentials_endpoint = "example.credentials.iot.us-west-2.amazonaws.com"
role_alias = "helios-device-role-alias"
root_ca = "/etc/ssl/certs/ca-certificates.crt"

[modules.usb]
enabled = false

{settings}
"#
        );
        let path = format!("{run}/helios.toml");
        std::fs::write(&path, config).expect("config");
        let log = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(format!("{run}/{log}"))
            .expect("log");
        Self(
            Command::new(bin)
                .args(["--config", &path, "stream-daemon"])
                .stdout(log.try_clone().expect("log"))
                .stderr(log)
                .spawn()
                .expect("helios stream-daemon"),
        )
    }

    /// SIGTERM, and a clean exit.
    fn terminate(mut self) {
        let pid =
            rustix::process::Pid::from_raw(i32::try_from(self.0.id()).expect("pid")).expect("pid");
        rustix::process::kill_process(pid, rustix::process::Signal::TERM).expect("signal");
        let status = self.0.wait().expect("exit");
        assert!(status.success(), "{status}");
    }
}

/// A camera publishing RTMP to nginx: H.264 and AAC, as the Osmo Pocket 3 sends.
struct Camera(Child);

impl Camera {
    fn publish(run: &str, key: &str) -> Self {
        let log = std::fs::File::create(format!("{run}/camera-{key}.log")).expect("log");
        Self(
            Command::new("ffmpeg")
                .args(["-hide_banner", "-nostdin", "-loglevel", "warning", "-re"])
                .args(["-f", "lavfi", "-i", "testsrc2=size=1280x720:rate=30"])
                .args([
                    "-re",
                    "-f",
                    "lavfi",
                    "-i",
                    "sine=frequency=440:sample_rate=48000",
                ])
                .args([
                    "-c:v",
                    "libx264",
                    "-preset",
                    "ultrafast",
                    "-tune",
                    "zerolatency",
                ])
                .args([
                    "-g", "60", "-b:v", "3M", "-c:a", "aac", "-b:a", "128k", "-f", "flv",
                ])
                .arg(format!("rtmp://127.0.0.1:1935/live/{key}"))
                .stdout(std::process::Stdio::null())
                .stderr(log)
                .spawn()
                .expect("ffmpeg"),
        )
    }

    /// Whether nginx dropped it within `limit` (a refused publish).
    fn refused_within(&mut self, limit: Duration) -> bool {
        let deadline = std::time::Instant::now() + limit;
        while std::time::Instant::now() < deadline {
            if self.0.try_wait().expect("wait").is_some() {
                return true;
            }
            std::thread::sleep(Duration::from_millis(200));
        }
        false
    }
}

impl Drop for Camera {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "run by tests/stream-e2e/helios.sh"]
async fn streams_survive_helios_and_follow_the_bond() {
    let (Ok(e2e), Ok(run), Ok(bin)) = (
        std::env::var("HELIOS_E2E_DIR"),
        std::env::var("HELIOS_E2E_RUN"),
        std::env::var("HELIOS_E2E_BIN"),
    ) else {
        eprintln!("skipping: run through tests/stream-e2e/helios.sh");
        return;
    };
    // The daemon loads the whole helios.toml, which checks the CA bundle holds certificates.
    for file in ["libsofthsm2.so", "pin"] {
        std::fs::write(format!("{run}/{file}"), "").expect("placeholder");
    }
    let socket = format!("{run}/control.sock");
    let config = format!(
        r#"
[device]
thing_name = "t-01J0000000000000000000E2E0"

[identity]
pkcs11_module = "{run}/libsofthsm2.so"
token_label = "helios"
key_label = "device-key"
pin = "file:{run}/pin"

[aws]
region = "us-west-2"
iot_endpoint = "example-ats.iot.us-west-2.amazonaws.com"
credentials_endpoint = "example.credentials.iot.us-west-2.amazonaws.com"
role_alias = "helios-device-role-alias"
root_ca = "/etc/ssl/certs/ca-certificates.crt"

[modules.usb]
enabled = false

[modules.stream]
ffmpeg = "/usr/bin/ffmpeg"
srtla_send = "{e2e}/bin/srtla_send"
control_socket = "{socket}"
state_dir = "{run}/state"
runtime_dir = "{run}/runtime"
sender_idle_s = 2

[modules.stream.outputs.bond]
mode = "srtla"
host = "10.10.0.1"
port = 5000
latency_ms = 2000
uplinks = ["up0", "up1"]

[modules.stream.profiles.hevc]
video = "libx265"
bitrate_kbps = 3000
audio = "aac"

[modules.stream.streams.e2e]
source = {{ type = "test", size = "1280x720", fps = 30 }}
profile = "hevc"
output = "bond"
streamid = "publish/live/e2e"
"#
    );
    let config_path = format!("{run}/helios.toml");
    std::fs::write(&config_path, config).expect("config");
    let log = std::fs::File::create(format!("{run}/daemon.log")).expect("log");
    let mut daemon = Daemon(
        Command::new(&bin)
            .args(["--config", &config_path, "stream-daemon"])
            .stdout(log.try_clone().expect("log"))
            .stderr(log)
            .spawn()
            .expect("helios stream-daemon"),
    );
    say("started helios stream-daemon as its own process");

    // Helios connects; the daemon brings the bond up and the stream live.
    let mut helios = Helios::start(&socket);
    helios
        .shadow("connected to the daemon", |r| {
            r["daemon"]["state"] == "connected"
        })
        .await;
    helios
        .shadow("output bond up with 2 active links", |r| {
            r["outputs"]["bond"]["state"] == "up" && r["outputs"]["bond"]["active_links"] == 2
        })
        .await;
    helios.event("stream.live").await;
    say("event: stream.live");
    let codecs = played_codecs(&run, "first");
    say(&format!("player on irl-srt-server :4000 got {codecs}"));
    assert_eq!(codecs, "aac,hevc");

    // Helios goes away mid-stream; the stream doesn't.
    let before = (pids("ffmpeg"), pids("srtla_send"));
    helios.stop().await;
    say("Helios stopped mid-stream");
    tokio::time::sleep(Duration::from_secs(3)).await;
    let codecs = played_codecs(&run, "without-helios");
    say(&format!("with Helios gone, the player got {codecs}"));
    assert_eq!(codecs, "aac,hevc");
    let after = (pids("ffmpeg"), pids("srtla_send"));
    assert!(!before.0.is_empty() && !before.1.is_empty(), "{before:?}");
    assert_eq!(before, after, "ffmpeg or srtla_send restarted");
    say(&format!(
        "same ffmpeg ({}) and srtla_send ({}) throughout",
        after.0, after.1
    ));

    // Helios is back: the stream is still live.
    let mut helios = Helios::start(&socket);
    helios
        .shadow("reconnected, stream still live", |r| {
            r["daemon"]["state"] == "connected" && r["streams"]["e2e"]["state"] == "live"
        })
        .await;

    // An uplink loses its address: the daemon rewrites the IP file and reloads srtla_send.
    ip("addr del 10.10.2.2/24 dev up1");
    let one = helios
        .shadow("uplinks down to 10.10.1.2", |r| {
            r["outputs"]["bond"]["uplinks"] == json!(["10.10.1.2"])
        })
        .await;
    assert_eq!(one["streams"]["e2e"]["state"], "live");
    helios
        .shadow("1 active link after the reload", |r| {
            r["outputs"]["bond"]["active_links"] == 1
        })
        .await;
    let codecs = played_codecs(&run, "one-link");
    say(&format!("on one uplink, the player got {codecs}"));
    assert_eq!(codecs, "aac,hevc");
    ip("addr add 10.10.2.2/24 dev up1");
    helios
        .shadow("both uplinks active again", |r| {
            r["outputs"]["bond"]["uplinks"] == json!(["10.10.1.2", "10.10.2.2"])
                && r["outputs"]["bond"]["active_links"] == 2
        })
        .await;

    // Stopped: ffmpeg at once, srtla_send after its idle time.
    assert!(matches!(
        helios.command("stop", json!({"stream_id": "e2e"})).await,
        Outcome::Ok(_)
    ));
    let disconnected = helios.event("stream.disconnected").await;
    say("event: stream.disconnected");
    assert!(disconnected.contains("\"stopped\""), "{disconnected}");
    helios
        .shadow("output bond stopped", |r| {
            r["outputs"]["bond"]["state"] == "stopped"
        })
        .await;
    tokio::time::sleep(Duration::from_secs(1)).await;
    assert!(pids("srtla_send").is_empty(), "srtla_send still running");
    say("srtla_send stopped after its idle time");
    helios.stop().await;

    // SIGTERM stops the daemon cleanly.
    let pid =
        rustix::process::Pid::from_raw(i32::try_from(daemon.0.id()).expect("pid")).expect("pid");
    rustix::process::kill_process(pid, rustix::process::Signal::TERM).expect("signal");
    let status = daemon.0.wait().expect("exit");
    assert!(status.success(), "{status}");
    say("the daemon stopped on SIGTERM");
}

const RTMP_SETTINGS: &str = r#"
[modules.stream]
ffmpeg = "/usr/bin/ffmpeg"
srtla_send = "E2E/bin/srtla_send"
control_socket = "RUN/control.sock"
state_dir = "RUN/rtmp-state"
runtime_dir = "RUN/runtime"
sender_idle_s = 2

[modules.stream.rtmp_ingest]
enabled = true

[modules.stream.outputs.bond]
mode = "srtla"
host = "10.10.0.1"
port = 5000
latency_ms = 2000
uplinks = ["up0", "up1"]

[modules.stream.profiles.hevc]
video = "libx265"
bitrate_kbps = 3000
audio = "copy"

[modules.stream.profiles.passthrough]
video = "copy"
audio = "copy"

[modules.stream.streams.pocket]
source = { type = "rtmp" }
profile = "hevc"
output = "bond"
streamid = "publish/live/pocket"

[modules.stream.streams.relay]
source = { type = "rtmp", camera = 1 }
profile = "passthrough"
output = "bond"
streamid = "publish/live/relay"
"#;

#[tokio::test(flavor = "multi_thread")]
#[ignore = "run by tests/stream-e2e/helios.sh"]
async fn rtmp_cameras_go_through_nginx_and_the_daemon() {
    let (Ok(e2e), Ok(run), Ok(bin)) = (
        std::env::var("HELIOS_E2E_DIR"),
        std::env::var("HELIOS_E2E_RUN"),
        std::env::var("HELIOS_E2E_BIN"),
    ) else {
        eprintln!("skipping: run through tests/stream-e2e/helios.sh");
        return;
    };
    let settings = RTMP_SETTINGS.replace("E2E", &e2e).replace("RUN", &run);
    let socket = format!("{run}/control.sock");
    let daemon = Daemon::start(&bin, &run, "rtmp-daemon.log", &settings);
    say("started the daemon with rtmp_ingest on");

    let mut helios = Helios::start(&socket);
    helios
        .shadow("rtmp_ingest ok, pocket waiting for its camera", |r| {
            r["rtmp_ingest"]["state"] == "ok"
                && r["streams"]["pocket"]["state"] == "waiting_for_input"
        })
        .await;

    // The Osmo Pocket publishes `ingest`: nginx asks the daemon, which starts the HEVC job.
    let pocket = Camera::publish(&run, "ingest");
    say("camera publishing rtmp://127.0.0.1:1935/live/ingest");
    helios.event("stream.connected").await;
    helios.event("stream.live").await;
    say("event: stream.live");
    helios
        .shadow("ingest's publisher in the shadow", |r| {
            r["rtmp_ingest"]["publishers"]["ingest"]["address"] == "127.0.0.1"
        })
        .await;
    // nginx's statistics page describes it (read every 10 s), and its key is an input.
    let described = helios
        .shadow("ingest's publisher described", |r| {
            r["rtmp_ingest"]["publishers"]["ingest"]["video_codec"].is_string()
        })
        .await;
    let publisher = &described["rtmp_ingest"]["publishers"]["ingest"];
    say(&format!("publisher: {publisher}"));
    assert_eq!(publisher["video_codec"], "H264", "{publisher}");
    assert_eq!(publisher["width"], 1280, "{publisher}");
    assert_eq!(publisher["height"], 720, "{publisher}");
    assert!(publisher["since"].is_string(), "{publisher}");
    assert!(
        described["inputs"]
            .as_array()
            .is_some_and(|inputs| inputs.contains(&json!({"type": "rtmp", "key": "ingest"}))),
        "{}",
        described["inputs"]
    );
    let codecs = played(&run, "pocket", "pocket");
    say(&format!("player on play/live/pocket got {codecs}"));
    assert_eq!(codecs, "aac,hevc");

    // A key no stream takes: the daemon refuses it and nginx drops the camera.
    let mut stranger = Camera::publish(&run, "ingest-9");
    assert!(
        stranger.refused_within(Duration::from_secs(15)),
        "ingest-9 was accepted"
    );
    say("ingest-9 refused: nginx dropped the camera");

    // A second camera on `ingest-1`, H.264 passed through.
    let second = Camera::publish(&run, "ingest-1");
    helios
        .shadow("relay live", |r| r["streams"]["relay"]["state"] == "live")
        .await;
    let codecs = played(&run, "relay", "relay");
    say(&format!(
        "player on play/live/relay got {codecs} (passed through)"
    ));
    assert_eq!(codecs, "aac,h264");

    // The daemon restarts while both cameras publish: no new on_publish comes, so it finds them
    // on nginx's statistics page.
    helios.stop().await;
    daemon.terminate();
    say("daemon stopped; cameras still publishing to nginx");
    let daemon = Daemon::start(&bin, &run, "rtmp-daemon.log", &settings);
    let mut helios = Helios::start(&socket);
    helios
        .shadow("both streams live again from the statistics page", |r| {
            r["streams"]["pocket"]["state"] == "live" && r["streams"]["relay"]["state"] == "live"
        })
        .await;
    let codecs = played(&run, "pocket-after-restart", "pocket");
    say(&format!("after the restart, play/live/pocket got {codecs}"));
    assert_eq!(codecs, "aac,hevc");

    // The Pocket stops: on_publish_done, and the stream waits for it again.
    drop(pocket);
    let disconnected = helios.event("stream.disconnected").await;
    assert!(disconnected.contains("publish_done"), "{disconnected}");
    say("event: stream.disconnected (publish_done)");
    helios
        .shadow("pocket waiting, relay still live", |r| {
            r["streams"]["pocket"]["state"] == "waiting_for_input"
                && r["streams"]["relay"]["state"] == "live"
        })
        .await;
    drop(second);
    helios
        .shadow("relay waiting", |r| {
            r["streams"]["relay"]["state"] == "waiting_for_input"
        })
        .await;
    helios.stop().await;
    daemon.terminate();
    say("the daemon stopped on SIGTERM");
}
