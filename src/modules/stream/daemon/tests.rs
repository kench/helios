//! Stream daemon tests: the protocol, and the daemon with Helios's client over a real socket,
//! with the fake spawner standing in for ffmpeg.

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use serde_json::{Map, Value, json};
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;

use super::super::control::{self, Message};
use super::super::tests::{FakeSpawner, Started, settings};
use super::super::{StreamClient, StreamModule};
use super::{Daemon, busy, desired_state, uid_of};
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
fn reads_users_desired_state_and_activity() {
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
        desired_state(&shadow),
        // Only an override is saved: b follows its profile, even if the profile changes.
        json!({"streams": {"a": {"state": "live", "bitrate_kbps": 3000}, "b": {"state": "stopped", "bitrate_kbps": null}}})
    );
    assert!(busy(&shadow));
    assert!(!busy(&Map::new()));
    assert_eq!(desired_state(&Map::new()), Value::Null);
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
    let client = StreamClient::new(socket);
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
            StreamModule::with_fakes(settings, usb, spawner, Arc::new(|| Ok(Vec::new())))
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
        &std::fs::read_to_string(dir.path().join("state/desired.json")).expect("saved"),
    )
    .expect("json");
    assert_eq!(saved["streams"]["pattern"]["state"], "stopped");

    // The next daemon resumes the saved desired state: stopped, so nothing starts.
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
