//! Stream daemon tests: the protocol, and the daemon with Helios's client over a real socket,
//! with the fake spawner standing in for ffmpeg.

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use serde_json::{Map, Value, json};
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;

use super::super::control::{self, Message};
use super::super::tests::{FakeSpawner, Started, address, settings};
use super::super::{StreamClient, StreamModule};
use super::{Daemon, busy, load_overrides, overrides, uid_of};
use crate::modules::usb::UsbSettings;
use crate::modules::{Module, ModuleContext};
use crate::mqtt::manager::{MqttHandle, Request as MqttRequest};
use crate::mqtt::shadow::{ShadowHandle, TestReports};
use crate::router::{Outcome, PendingCommand, codes};

const WAIT: Duration = Duration::from_secs(20);

#[test]
fn frames_requests_responses_and_notifications() {
    let request = control::request(7, "command", json!({"name": "status"}));
    assert!(request.ends_with('\n'));
    assert_eq!(
        control::parse(&request),
        Some(Message::Request {
            id: json!(7),
            method: "command".into(),
            params: json!({"name": "status"})
        })
    );
    assert_eq!(
        control::parse(&control::notification(
            "event",
            json!({"kind": "stream.live"})
        )),
        Some(Message::Notification {
            method: "event".into(),
            params: json!({"kind": "stream.live"})
        })
    );
    assert_eq!(
        control::parse(&control::response(&json!(7), Outcome::Ok(json!({"a": 1})))),
        Some(Message::Response {
            id: 7,
            outcome: Outcome::Ok(json!({"a": 1}))
        })
    );
    assert_eq!(
        control::parse(&control::response(
            &json!(8),
            Outcome::error(codes::INVALID_MESSAGE, "no stream")
        )),
        Some(Message::Response {
            id: 8,
            outcome: Outcome::error(codes::INVALID_MESSAGE, "no stream")
        })
    );
    for bad in [
        "",
        "not json",
        r#"{"id": 1, "result": 1}"#,
        r#"{"jsonrpc": "2.0"}"#,
        r#"{"jsonrpc": "2.0", "id": "x", "result": 1}"#,
        r#"{"jsonrpc": "2.0", "id": 1}"#,
    ] {
        assert_eq!(control::parse(bad), None, "{bad}");
    }
    let unknown = control::parse(r#"{"jsonrpc": "2.0", "id": 3, "error": {"message": "boom"}}"#);
    assert_eq!(
        unknown,
        Some(Message::Response {
            id: 3,
            outcome: Outcome::error(codes::INTERNAL, "boom")
        })
    );
}

#[test]
fn reads_users_overrides_and_activity() {
    let passwd =
        "root:x:0:0:root:/root:/bin/sh\nhelios:x:998:998::/nonexistent:/usr/sbin/nologin\nbad\n";
    assert_eq!(uid_of("helios", passwd), Some(998));
    assert_eq!(uid_of("root", passwd), Some(0));
    assert_eq!(uid_of("nobody", passwd), None);
    let shadow: Map<String, Value> = json!({"streams": {
        "a": {"state": "live", "desired": "live", "bitrate_kbps": 3000, "bitrate_override_kbps": 3000},
        "b": {"state": "stopped", "desired": "stopped", "bitrate_kbps": 2000, "bitrate_override_kbps": null},
    }})
    .as_object()
    .cloned()
    .expect("object");
    assert_eq!(
        overrides(&shadow),
        // Only an override is saved: b follows its profile, even if the profile changes.
        json!({"streams": {
            "a": {"desired": "live", "bitrate_override_kbps": 3000, "overrides": null},
            "b": {"desired": "stopped", "bitrate_override_kbps": null, "overrides": null},
        }})
    );
    // Settings set by stream.update are saved too: null ones follow helios.toml.
    let overridden: Map<String, Value> = json!({"streams": {"a": {
        "desired": "live", "bitrate_override_kbps": null,
        "overrides": {
            "source": {"type": "rtmp", "camera": 2}, "profile": null,
            "destination": "srt://h.example:1", "source_ceiling_percent": 80,
        },
    }}})
    .as_object()
    .cloned()
    .expect("object");
    assert_eq!(
        overrides(&overridden),
        json!({"streams": {"a": {
            "desired": "live", "bitrate_override_kbps": null, "overrides": {
                "source": {"type": "rtmp", "camera": 2}, "profile": null,
                "destination": "srt://h.example:1", "source_ceiling_percent": 80,
            },
        }}})
    );
    assert!(busy(&shadow));
    assert!(!busy(&Map::new()));
    assert_eq!(overrides(&Map::new()), Value::Null);
}

const CONFIG: &str = r#"
ffmpeg = "/opt/ffmpeg"
control_socket = "DIR/control.sock"
state_dir = "DIR/state"
runtime_dir = "DIR/run"
stats_interval_s = 5

[outputs.main]
mode = "direct"
host = "ingest.example.com"
port = 4001

[profiles.test]
video = "libx264"
audio = "aac"

[streams.pattern]
source = { type = "test" }
profile = "test"
output = "main"
streamid = "publish/live/pattern"
"#;

struct Agent {
    published: mpsc::UnboundedReceiver<MqttRequest>,
    reports: TestReports,
    commands: mpsc::Sender<PendingCommand>,
    cancel: CancellationToken,
    task: tokio::task::JoinHandle<Result<(), crate::modules::ModuleError>>,
}

/// Helios's side: the stream module as a client of the daemon at `socket`.
fn agent(socket: std::path::PathBuf) -> Agent {
    agent_with(socket, None)
}

/// Helios's client, passing on `uplinks` (the net module's view) when given.
fn agent_with(
    socket: std::path::PathBuf,
    uplinks: Option<tokio::sync::watch::Receiver<Value>>,
) -> Agent {
    let (mqtt, published, _status) = MqttHandle::for_test();
    let (shadows, reports, _desired) = ShadowHandle::for_test();
    let (commands, commands_rx) = mpsc::channel(4);
    let cancel = CancellationToken::new();
    let ctx = ModuleContext {
        commands: commands_rx,
        desired: mpsc::unbounded_channel().1,
        shadows,
        mqtt,
        sysfs: "/sys".into(),
        cancel: cancel.clone(),
    };
    let client = match uplinks {
        Some(view) => StreamClient::new(socket).with_uplink_view(view),
        None => StreamClient::new(socket),
    };
    let task = tokio::spawn(async move { client.run(ctx).await });
    Agent {
        published,
        reports,
        commands,
        cancel,
        task,
    }
}

impl Agent {
    async fn shadow_where(&mut self, what: &str, check: impl Fn(&Value) -> bool) -> Value {
        tokio::time::timeout(WAIT, async {
            loop {
                let (shadow, reported) = self.reports.recv().await.expect("shadow");
                let reported = Value::Object(reported);
                if shadow == "stream" && check(&reported) {
                    return reported;
                }
            }
        })
        .await
        .unwrap_or_else(|_| panic!("the shadow never showed {what}"))
    }

    /// The next `clear_desired` path for the stream shadow, skipping reports.
    async fn cleared(&mut self) -> Value {
        tokio::time::timeout(WAIT, async {
            loop {
                let (shadow, value) = self.reports.recv().await.expect("shadow");
                if shadow == "stream#desired" {
                    return value["clear"].clone();
                }
            }
        })
        .await
        .unwrap_or_else(|_| panic!("nothing was cleared from the desired state"))
    }

    async fn event(&mut self, kind: &str) -> String {
        tokio::time::timeout(WAIT, async {
            loop {
                let text = format!("{:?}", self.published.recv().await.expect("mqtt"));
                if text.contains(&format!("kind: \"{kind}\"")) {
                    return text;
                }
            }
        })
        .await
        .unwrap_or_else(|_| panic!("no {kind}"))
    }

    async fn command(&self, name: &str, args: Value) -> Outcome {
        let (pending, answer) = PendingCommand::for_test("stream", name, args);
        self.commands.send(pending).await.expect("client running");
        tokio::time::timeout(WAIT, answer)
            .await
            .expect("an answer")
            .expect("answered")
    }

    async fn stop(self) {
        self.cancel.cancel();
        tokio::time::timeout(WAIT, self.task)
            .await
            .expect("stopped")
            .expect("task")
            .expect("ok");
    }
}

struct Running {
    started: mpsc::UnboundedReceiver<Started>,
    cancel: CancellationToken,
    task: tokio::task::JoinHandle<Result<(), String>>,
}

fn daemon(config: &str) -> Running {
    daemon_with(config, Arc::new(|| Ok(Vec::new())))
}

/// The daemon, with interface addresses from `addresses`.
fn daemon_with(config: &str, addresses: Arc<super::super::Addresses>) -> Running {
    let (started_tx, started) = mpsc::unbounded_channel();
    let spawner = Arc::new(FakeSpawner {
        started: started_tx,
        encoders: None,
        refuse: AtomicBool::new(false),
    });
    let daemon = Daemon {
        settings: settings(config),
        usb: UsbSettings::default(),
        sysfs: "/nonexistent/sys".into(),
        engine: Box::new(move |settings, usb| {
            StreamModule::with_fakes(settings, usb, spawner, addresses)
        }),
    };
    let cancel = CancellationToken::new();
    let task = tokio::spawn(daemon.run(cancel.clone()));
    Running {
        started,
        cancel,
        task,
    }
}

async fn next_start(started: &mut mpsc::UnboundedReceiver<Started>) -> Started {
    tokio::time::timeout(WAIT, started.recv())
        .await
        .expect("a job")
        .expect("spawner")
}

#[tokio::test]
async fn streams_keep_running_while_helios_is_away() {
    let dir = tempfile::tempdir().expect("directory");
    let config = CONFIG.replace("DIR", &dir.path().display().to_string());
    let socket = dir.path().join("control.sock");
    let mut running = daemon(&config);
    let job = next_start(&mut running.started).await;

    // Helios connects, sees the stream go live, and can command it.
    let mut first = agent(socket.clone());
    first
        .shadow_where("daemon connected", |r| r["daemon"]["state"] == "connected")
        .await;
    job.progress(1_000_000);
    job.progress(2_000_000);
    first.event("stream.live").await;
    first
        .shadow_where("the stream live", |r| {
            r["streams"]["pattern"]["state"] == "live"
        })
        .await;
    let Outcome::Ok(status) = first
        .command("status", json!({"stream_id": "pattern"}))
        .await
    else {
        panic!("status refused");
    };
    assert_eq!(status["state"], "live");
    let Outcome::Err { code, .. } = first.command("status", json!({"stream_id": "nope"})).await
    else {
        panic!("an unknown stream accepted");
    };
    assert_eq!(code, codes::INVALID_MESSAGE);

    // Helios goes away: the job keeps running, and events wait for it.
    first.stop().await;
    tokio::time::sleep(Duration::from_secs(6)).await; // a stream.stats while nobody listens
    assert!(
        !job.stopped.load(Ordering::SeqCst),
        "the job stopped with Helios"
    );

    // Helios is back: the snapshot says live, and the waiting events arrive.
    let mut second = agent(socket.clone());
    second
        .shadow_where("still live after reconnecting", |r| {
            r["daemon"]["state"] == "connected" && r["streams"]["pattern"]["state"] == "live"
        })
        .await;
    second.event("stream.stats").await;

    // An upgrade waits while the stream is live, then goes once it's stopped.
    std::fs::create_dir_all(dir.path().join("run")).expect("run directory");
    std::fs::write(dir.path().join("run/restart-pending"), "").expect("flag");
    tokio::time::sleep(Duration::from_secs(6)).await;
    assert!(!running.task.is_finished(), "restarted while live");
    let Outcome::Ok(_) = second
        .command("stop", json!({"stream_id": "pattern"}))
        .await
    else {
        panic!("stop refused");
    };
    tokio::time::timeout(WAIT, &mut running.task)
        .await
        .expect("restarted once idle")
        .expect("task")
        .expect("ok");
    assert!(job.stopped.load(Ordering::SeqCst));
    let saved: Value = serde_json::from_str(
        &std::fs::read_to_string(dir.path().join("state/overrides.json")).expect("saved"),
    )
    .expect("json");
    assert_eq!(saved["streams"]["pattern"]["desired"], "stopped");

    // The next daemon resumes the saved overrides: stopped, so nothing starts.
    second
        .shadow_where("daemon unreachable", |r| {
            r["daemon"]["state"] == "unreachable"
        })
        .await;
    let mut again = daemon(&config);
    second
        .shadow_where("connected to the new daemon, stream stopped", |r| {
            r["daemon"]["state"] == "connected" && r["streams"]["pattern"]["state"] == "stopped"
        })
        .await;
    assert!(
        again.started.try_recv().is_err(),
        "a stopped stream started"
    );
    second.stop().await;
    again.cancel.cancel();
    tokio::time::timeout(WAIT, again.task)
        .await
        .expect("stopped")
        .expect("task")
        .expect("ok");
    running.cancel.cancel();
}

#[tokio::test]
async fn without_the_daemon_commands_fail_and_the_shadow_says_why() {
    let dir = tempfile::tempdir().expect("directory");
    let mut agent = agent(dir.path().join("missing.sock"));
    let shadow = agent
        .shadow_where("daemon unreachable", |r| {
            r["daemon"]["state"] == "unreachable"
        })
        .await;
    assert!(
        shadow["daemon"]["error"]
            .as_str()
            .is_some_and(|e| e.contains("missing.sock"))
    );
    let Outcome::Err { code, .. } = agent.command("status", json!({})).await else {
        panic!("answered without a daemon");
    };
    assert_eq!(code, codes::MODULE_UNAVAILABLE);
    agent.stop().await;
}

#[tokio::test]
async fn a_bad_socket_path_is_an_error() {
    let config = CONFIG.replace("DIR", "/nonexistent/helios-stream");
    let running = daemon(&config);
    let result = tokio::time::timeout(WAIT, running.task)
        .await
        .expect("ended")
        .expect("task");
    assert!(result.is_err_and(|e| e.contains("/nonexistent")));
}

const BONDED: &str = r#"
ffmpeg = "/opt/ffmpeg"
srtla_send = "/opt/srtla_send"
control_socket = "DIR/control.sock"
state_dir = "DIR/state"
runtime_dir = "DIR/run"

[outputs.bond]
mode = "srtla"
host = "rec.example.com"
port = 5000
latency_ms = 2000
uplinks = ["eth1", "wlan0"]

[profiles.test]
video = "libx264"
audio = "aac"

[streams.pattern]
source = { type = "test" }
profile = "test"
output = "bond"
streamid = "publish/live/pattern"
"#;

fn view(wifi_public: &str) -> Value {
    json!({"interfaces": {
        "eth1": {"kind": "ethernet", "metric": 100, "public_ipv4": "203.0.113.7"},
        "wlan0": {"kind": "wifi", "metric": 600, "public_ipv4": wifi_public},
    }})
}

async fn ips_become(path: &std::path::Path, want: &str) {
    tokio::time::timeout(WAIT, async {
        loop {
            if std::fs::read_to_string(path).is_ok_and(|text| text == want) {
                return;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    })
    .await
    .unwrap_or_else(|_| panic!("{} never became {want:?}", path.display()));
}

#[tokio::test]
async fn helios_uplink_view_puts_a_shared_uplink_in_standby() {
    let dir = tempfile::tempdir().expect("directory");
    let config = BONDED
        .replace("DIR", &dir.path().display().to_string())
        .replace(
            "ffmpeg = \"/opt/ffmpeg\"\n",
            "ffmpeg = \"/opt/ffmpeg\"\nsrtla_standby = true\n",
        );
    let socket = dir.path().join("control.sock");
    let ips = dir.path().join("run/srtla/bond.ips");
    let mut running = daemon_with(
        &config,
        Arc::new(|| {
            Ok(vec![
                address("eth1", [10, 0, 1, 2]),
                address("wlan0", [10, 0, 2, 2]),
            ])
        }),
    );
    // Ethernet and Wi-Fi share a public address: Wi-Fi waits.
    let (uplinks, uplinks_view) = tokio::sync::watch::channel(view("203.0.113.7"));
    let mut helios = agent_with(socket, Some(uplinks_view));
    let sender = next_start(&mut running.started).await;
    assert_eq!(
        sender.spec.program,
        std::path::PathBuf::from("/opt/srtla_send")
    );
    let shadow = helios
        .shadow_where("Wi-Fi in standby", |r| {
            r["outputs"]["bond"]["standby"][0]["interface"] == "wlan0"
        })
        .await;
    assert_eq!(
        shadow["outputs"]["bond"]["standby"],
        json!([{"interface": "wlan0", "address": "10.0.2.2",
                "shares_public_address_with": "eth1"}])
    );
    ips_become(&ips, "10.0.1.2\n").await;

    // Wi-Fi turns out to have its own public address: both bond.
    uplinks.send_replace(view("198.51.100.9"));
    helios
        .shadow_where("no standby", |r| {
            r["outputs"]["bond"]["standby"] == json!([])
        })
        .await;
    ips_become(&ips, "10.0.1.2\n10.0.2.2\n").await;
    helios.stop().await;
    running.cancel.cancel();
}

#[tokio::test]
async fn the_client_removes_desired_state_from_the_stream_shadow() {
    let dir = tempfile::tempdir().expect("directory");
    let socket = dir.path().join("control.sock");
    // Reported-only: whatever desired state is left (from before 0.17.0) goes, daemon or not.
    let mut helios = agent(socket);
    assert_eq!(helios.cleared().await, json!(["streams"]));
    helios.stop().await;
}

#[tokio::test]
async fn a_new_daemon_resumes_the_overrides_saved_before_0_17() {
    let dir = tempfile::tempdir().expect("directory");
    let config = CONFIG.replace("DIR", &dir.path().display().to_string());
    let state = dir.path().join("state");
    std::fs::create_dir_all(&state).expect("state directory");
    // 0.16.0's desired.json: the pattern stopped.
    std::fs::write(
        state.join("desired.json"),
        r#"{"streams": {"pattern": {"state": "stopped", "bitrate_kbps": null}}}"#,
    )
    .expect("old file");
    let mut running = daemon(&config);
    let mut helios = agent(dir.path().join("control.sock"));
    helios
        .shadow_where("connected, the stream stopped", |r| {
            r["daemon"]["state"] == "connected" && r["streams"]["pattern"]["desired"] == "stopped"
        })
        .await;
    assert!(
        running.started.try_recv().is_err(),
        "a stopped stream started"
    );
    // Saved under the new name, and the old file is gone.
    let saved = tokio::time::timeout(WAIT, async {
        loop {
            if let Ok(text) = std::fs::read_to_string(state.join("overrides.json")) {
                break text;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    })
    .await
    .expect("saved");
    let saved: Value = serde_json::from_str(&saved).expect("json");
    assert_eq!(saved["streams"]["pattern"]["desired"], "stopped");
    assert!(!state.join("desired.json").exists(), "the old file stayed");
    helios.stop().await;
    running.cancel.cancel();
    let _ = running.task.await;
}

#[test]
fn reads_overrides_from_the_old_desired_state() {
    let dir = tempfile::tempdir().expect("directory");
    let (file, old) = (
        dir.path().join("overrides.json"),
        dir.path().join("desired.json"),
    );
    assert_eq!(load_overrides(&file, &old), None);
    std::fs::write(
        &old,
        r#"{"streams": {"a": {"state": "live", "bitrate_kbps": 3000, "profile": "hd"}}}"#,
    )
    .expect("old file");
    assert_eq!(
        load_overrides(&file, &old),
        Some(json!({"streams": {"a": {
            "desired": "live", "bitrate_override_kbps": 3000, "overrides": {"profile": "hd"},
        }}}))
    );
    // The new file wins once it's there.
    std::fs::write(&file, r#"{"streams": {}}"#).expect("new file");
    assert_eq!(load_overrides(&file, &old), Some(json!({"streams": {}})));
}
