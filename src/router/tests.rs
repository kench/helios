//! Router tests with the custom-topics transport and a test MQTT handle.

use serde_json::json;
use tokio::sync::watch;

use crate::mqtt::envelope::{Envelope, Status};
use crate::mqtt::manager::{MqttStatus, Request as MqttRequest};
use crate::router::topics::TopicsTransport;

use super::*;

const THING: &str = "t-1";
const WAIT: Duration = Duration::from_secs(5);

struct Setup {
    router: RouterHandle,
    incoming: mpsc::Sender<Incoming>,
    published: mpsc::UnboundedReceiver<MqttRequest>,
    status: watch::Sender<MqttStatus>,
    cancel: CancellationToken,
}

impl Drop for Setup {
    fn drop(&mut self) {
        self.cancel.cancel();
    }
}

fn setup(timing: Timing) -> Setup {
    let (mqtt, published, status) = MqttHandle::for_test();
    status.send_modify(|s| {
        s.connected = true;
        s.session = 1;
        s.thing = Some(THING.to_owned());
    });
    let (incoming, incoming_rx) = mpsc::channel(32);
    let cancel = CancellationToken::new();
    let (router, _task) = Router::start(
        mqtt,
        Arc::new(TopicsTransport),
        incoming_rx,
        timing,
        cancel.clone(),
    );
    Setup {
        router,
        incoming,
        published,
        status,
        cancel,
    }
}

fn command(id: &str, module: &str, name: &str, payload: Value) -> Incoming {
    Incoming {
        topic: format!("helios/{THING}/cmd/{module}"),
        payload: json!({
            "v": 1, "id": id, "correlation_id": null, "ts": "2026-11-21T05:00:00.000Z",
            "thing": THING, "module": module, "type": format!("{module}.{name}"),
            "payload": payload
        })
        .to_string()
        .into_bytes(),
    }
}

/// The next response: its topic and envelope.
async fn response(setup: &mut Setup) -> (String, Envelope) {
    let request = tokio::time::timeout(WAIT, setup.published.recv())
        .await
        .expect("a response")
        .unwrap();
    match request {
        MqttRequest::Now { topic, payload } => (topic, serde_json::from_slice(&payload).unwrap()),
        MqttRequest::Event(event) => panic!("unexpected event {event:?}"),
    }
}

async fn assert_no_response(setup: &mut Setup) {
    if let Ok(Some(request)) =
        tokio::time::timeout(Duration::from_millis(100), setup.published.recv()).await
    {
        panic!("unexpected publish {request:?}");
    }
}

/// Waits until the router has handled earlier registrations, by round-tripping a command.
async fn registered(setup: &mut Setup) {
    setup
        .incoming
        .send(command("sync", "nobody", "x", json!({})))
        .await
        .unwrap();
    let (_, sync) = response(setup).await;
    assert_eq!(sync.correlation_id.as_deref(), Some("sync"));
}

#[tokio::test]
async fn passes_commands_to_their_module_and_publishes_the_answer() {
    let mut setup = setup(Timing::default());
    let mut video = setup.router.register("video");
    registered(&mut setup).await;

    setup
        .incoming
        .send(command(
            "c1",
            "video",
            "stream.start",
            json!({"stream": "main"}),
        ))
        .await
        .unwrap();
    let pending = tokio::time::timeout(WAIT, video.recv())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(pending.command.name, "stream.start");
    assert_eq!(pending.command.args["stream"], "main");
    pending.respond(Outcome::Ok(json!({"state": "live"})));
    let (topic, envelope) = response(&mut setup).await;

    assert_eq!(topic, format!("helios/{THING}/rsp/video"));
    assert_eq!(envelope.correlation_id.as_deref(), Some("c1"));
    assert_eq!(envelope.status, Some(Status::Ok));
    assert_eq!(envelope.payload["state"], "live");
}

#[tokio::test]
async fn answers_for_unknown_modules() {
    let mut setup = setup(Timing::default());

    setup
        .incoming
        .send(command("c1", "usb", "list", json!({})))
        .await
        .unwrap();
    let (topic, envelope) = response(&mut setup).await;

    assert_eq!(topic, format!("helios/{THING}/rsp/usb"));
    assert_eq!(envelope.error.unwrap().code, codes::UNKNOWN_COMMAND);
}

#[tokio::test]
async fn answers_invalid_commands_that_have_an_id() {
    let mut setup = setup(Timing::default());
    let mut bad = command("c1", "video", "stream.start", json!({}));
    bad.payload = String::from_utf8(bad.payload)
        .unwrap()
        .replace("\"v\":1", "\"v\":9")
        .into_bytes();

    setup.incoming.send(bad).await.unwrap();
    let (_, envelope) = response(&mut setup).await;
    setup
        .incoming
        .send(Incoming {
            topic: format!("helios/{THING}/cmd/video"),
            payload: b"not json".to_vec(),
        })
        .await
        .unwrap();

    assert_eq!(envelope.error.unwrap().code, codes::INVALID_MESSAGE);
    assert_no_response(&mut setup).await;
}

#[tokio::test]
async fn drops_repeated_commands() {
    let mut setup = setup(Timing::default());
    let mut video = setup.router.register("video");
    registered(&mut setup).await;

    for _ in 0..2 {
        setup
            .incoming
            .send(command("c1", "video", "stream.stop", json!({})))
            .await
            .unwrap();
    }
    let pending = tokio::time::timeout(WAIT, video.recv())
        .await
        .unwrap()
        .unwrap();
    pending.respond(Outcome::Ok(json!({})));
    response(&mut setup).await;

    assert_no_response(&mut setup).await;
    assert!(video.try_recv().is_err());
}

#[tokio::test]
async fn forgets_old_ids_after_the_window() {
    let mut setup = setup(Timing {
        dedupe_window: Duration::from_millis(20),
        ..Timing::default()
    });

    setup
        .incoming
        .send(command("c1", "usb", "list", json!({})))
        .await
        .unwrap();
    response(&mut setup).await;
    tokio::time::sleep(Duration::from_millis(40)).await;
    setup
        .incoming
        .send(command("c1", "usb", "list", json!({})))
        .await
        .unwrap();

    response(&mut setup).await;
}

#[tokio::test]
async fn times_out_slow_commands() {
    let mut setup = setup(Timing {
        default_timeout: Duration::from_millis(50),
        ..Timing::default()
    });
    let mut video = setup.router.register("video");
    registered(&mut setup).await;

    setup
        .incoming
        .send(command("c1", "video", "stream.start", json!({})))
        .await
        .unwrap();
    let pending = tokio::time::timeout(WAIT, video.recv())
        .await
        .unwrap()
        .unwrap();
    let (_, envelope) = response(&mut setup).await;
    // A late answer goes nowhere.
    pending.respond(Outcome::Ok(json!({})));

    assert_eq!(envelope.status, Some(Status::Timeout));
    assert_eq!(envelope.error.unwrap().code, codes::TIMEOUT);
    assert_no_response(&mut setup).await;
}

#[tokio::test]
async fn a_past_deadline_times_out_at_once() {
    let mut setup = setup(Timing::default());
    let _video = setup.router.register("video");
    registered(&mut setup).await;

    setup
        .incoming
        .send(command(
            "c1",
            "video",
            "stream.start",
            json!({"deadline": "2020-01-01T00:00:00Z"}),
        ))
        .await
        .unwrap();
    let (_, envelope) = response(&mut setup).await;

    assert_eq!(envelope.status, Some(Status::Timeout));
}

#[tokio::test]
async fn a_busy_module_is_unavailable() {
    let mut setup = setup(Timing::default());
    // Registered, but never reads.
    let _video = setup.router.register("video");
    registered(&mut setup).await;

    for n in 0..=MODULE_QUEUE {
        setup
            .incoming
            .send(command(
                &format!("c{n}"),
                "video",
                "stream.status",
                json!({}),
            ))
            .await
            .unwrap();
    }
    let (_, envelope) = response(&mut setup).await;

    assert_eq!(envelope.correlation_id.as_deref(), Some("c16"));
    assert_eq!(envelope.error.unwrap().code, codes::MODULE_UNAVAILABLE);
}

#[tokio::test]
async fn a_dropped_command_is_an_internal_error() {
    let mut setup = setup(Timing::default());
    let mut video = setup.router.register("video");
    registered(&mut setup).await;

    setup
        .incoming
        .send(command("c1", "video", "stream.start", json!({})))
        .await
        .unwrap();
    drop(
        tokio::time::timeout(WAIT, video.recv())
            .await
            .unwrap()
            .unwrap(),
    );
    let (_, envelope) = response(&mut setup).await;

    assert_eq!(envelope.error.unwrap().code, codes::INTERNAL);
}

#[tokio::test]
async fn ignores_other_topics_and_waits_for_a_session() {
    let mut setup = setup(Timing::default());

    setup
        .incoming
        .send(Incoming {
            topic: format!("helios/{THING}/evt/usb"),
            payload: b"{}".to_vec(),
        })
        .await
        .unwrap();
    assert_no_response(&mut setup).await;
    setup.status.send_modify(|s| s.thing = None);
    setup
        .incoming
        .send(command("c1", "usb", "list", json!({})))
        .await
        .unwrap();

    assert_no_response(&mut setup).await;
}

#[tokio::test]
async fn the_helios_module_answers_ping() {
    let mut setup = setup(Timing::default());
    let (status_tx, status) = watch::channel(MqttStatus {
        session: 3,
        ..MqttStatus::default()
    });
    let _helios = helios::start(
        setup.router.register(helios::MODULE),
        status,
        Instant::now(),
    );
    registered(&mut setup).await;

    setup
        .incoming
        .send(command("p1", "helios", "ping", json!({})))
        .await
        .unwrap();
    let (topic, ping) = response(&mut setup).await;
    setup
        .incoming
        .send(command("p2", "helios", "reboot", json!({})))
        .await
        .unwrap();
    let (_, unknown) = response(&mut setup).await;

    assert_eq!(topic, format!("helios/{THING}/rsp/helios"));
    assert_eq!(ping.status, Some(Status::Ok));
    assert_eq!(ping.payload["version"], env!("CARGO_PKG_VERSION"));
    assert_eq!(ping.payload["session"], 3);
    assert!(ping.payload["uptime_s"].is_u64());
    assert_eq!(unknown.error.unwrap().code, codes::UNKNOWN_COMMAND);
    drop(status_tx);
}

#[test]
fn outcome_error_builds_a_failure() {
    assert_eq!(
        Outcome::error(codes::TIMEOUT, "late"),
        Outcome::Err {
            code: "TIMEOUT".into(),
            message: "late".into()
        }
    );
}
