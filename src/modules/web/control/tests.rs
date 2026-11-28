//! The local Control API against a real router, with a fake stream and net module behind it,
//! and the reports in a detached shadow handle.

use std::time::Duration;

use serde_json::{Map, Value, json};
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;

use super::{Device, handle, update_args};
use crate::mqtt::manager::MqttHandle;
use crate::mqtt::shadow::ShadowHandle;
use crate::router::{Outcome, PendingCommand, Router, Timing};

const THING: &str = "t-01M80KAX049HNYQ4K9NYP8SNFH";
const WAIT: Duration = Duration::from_secs(5);

struct Setup {
    device: Device,
    stream: mpsc::Receiver<PendingCommand>,
    net: mpsc::Receiver<PendingCommand>,
    cancel: CancellationToken,
}

impl Drop for Setup {
    fn drop(&mut self) {
        self.cancel.cancel();
    }
}

fn map(value: Value) -> Map<String, Value> {
    value.as_object().unwrap().clone()
}

async fn setup() -> Setup {
    let (mqtt, _published, _status) = MqttHandle::for_test();
    let cancel = CancellationToken::new();
    let (_incoming, incoming) = mpsc::channel(4);
    let (router, _task) = Router::start(
        mqtt.clone(),
        Vec::new(),
        incoming,
        Timing {
            default_timeout: Duration::from_millis(300),
            ..Timing::default()
        },
        cancel.clone(),
    );
    let stream = router.register("stream");
    let net = router.register("net");
    let (shadows, _reports) = ShadowHandle::detached();
    shadows.report(
        "stream",
        map(json!({"streams": {"pocket": {
            "desired": "stopped", "state": "stopped", "since": "2026-11-27T07:12:17.002Z",
            "source": {"type": "test", "size": "848x480"}, "profile": "hevc-720p",
            "destination": "srt://ingest.example.com:4001?streamid=publish/live/pocket",
            "bitrate_kbps": 1500
        }}, "profiles": {}, "inputs": [{"type": "test"}]})),
    );
    shadows.report(
        "net",
        map(json!({"interfaces": {}, "wifi": {"networks": [{"ssid": "Home", "security": "personal"}]}})),
    );
    shadows.report(
        "helios",
        map(json!({"modules": {"stream": {"state": "running"}, "net": {"state": "running"}}})),
    );
    // Let the router take the registrations.
    tokio::time::sleep(Duration::from_millis(20)).await;
    Setup {
        device: Device {
            shadows,
            router,
            mqtt,
            identity: None,
            thing_name: Some(THING.into()),
            role: "transcoder".into(),
        },
        stream,
        net,
        cancel,
    }
}

async fn call(setup: &Setup, method: &str, path: &str, body: Value) -> super::Answer {
    let (path, query) = path.split_once('?').unwrap_or((path, ""));
    let query: Vec<(String, String)> = query
        .split('&')
        .filter(|p| !p.is_empty())
        .map(|p| {
            let (k, v) = p.split_once('=').unwrap();
            (k.to_owned(), v.to_owned())
        })
        .collect();
    handle(&setup.device, method, path, &query, &body).await
}

/// Answers the next command the fake `module` gets with `outcome`, and returns the command.
async fn answer(
    module: &mut mpsc::Receiver<PendingCommand>,
    outcome: Outcome,
) -> crate::router::Command {
    let pending = tokio::time::timeout(WAIT, module.recv())
        .await
        .unwrap()
        .unwrap();
    let command = pending.command.clone();
    pending.respond(outcome);
    command
}

#[tokio::test]
async fn lists_this_device_alone_and_reads_its_reports() {
    let setup = setup().await;
    let devices = call(&setup, "GET", "/v1/control/devices", Value::Null).await;
    assert_eq!(devices.status, 200);
    let summary = &devices.body["devices"][0];
    assert_eq!(
        summary["deviceId"], THING,
        "no bootstrap yet: the thing name"
    );
    assert_eq!(summary["thingName"], THING);
    assert_eq!(summary["role"], "transcoder");
    assert_eq!(summary["heliosVersion"], env!("CARGO_PKG_VERSION"));
    assert_eq!(devices.body["devices"].as_array().unwrap().len(), 1);

    let base = format!("/v1/control/devices/{THING}");
    let device = call(&setup, "GET", &base, Value::Null).await;
    assert_eq!(
        device.body["modules"],
        json!({"net": "running", "stream": "running"})
    );
    let streams = call(&setup, "GET", &format!("{base}/streams"), Value::Null).await;
    assert_eq!(streams.status, 200);
    assert_eq!(streams.body["streams"][0]["streamId"], "pocket");
    assert_eq!(streams.body["streams"][0]["reported"]["state"], "stopped");
    let wifi = call(&setup, "GET", &format!("{base}/wifi/networks"), Value::Null).await;
    assert_eq!(wifi.body["networks"][0]["ssid"], "Home");
    let gps = call(&setup, "GET", &format!("{base}/location"), Value::Null).await;
    assert_eq!(
        (gps.status, gps.error),
        (409, Some("DeviceStateUnavailable"))
    );

    let other = call(
        &setup,
        "GET",
        "/v1/control/devices/d-OTHER/streams",
        Value::Null,
    )
    .await;
    assert_eq!((other.status, other.error), (404, Some("DeviceNotFound")));
    let nothing = call(&setup, "GET", &format!("{base}/nope"), Value::Null).await;
    assert_eq!(
        (nothing.status, nothing.error),
        (404, Some("UnknownOperationException"))
    );
}

#[tokio::test]
async fn starts_a_stream_with_a_local_command_and_shows_it_after() {
    let mut setup = setup().await;
    let path = format!("/v1/control/devices/{THING}/streams/pocket/start");
    let device = setup.device.clone();
    let call =
        tokio::spawn(async move { super::handle(&device, "POST", &path, &[], &json!({})).await });
    let command = answer(
        &mut setup.stream,
        Outcome::Ok(json!({"status": {
            "desired": "live", "state": "starting", "since": "2026-11-27T07:20:00.000Z",
            "source": {"type": "test", "size": "848x480"}, "profile": "hevc-720p",
            "destination": "srt://ingest.example.com:4001?streamid=publish/live/pocket",
            "bitrate_kbps": 1500
        }})),
    )
    .await;
    assert_eq!(
        (command.module.as_str(), command.name.as_str()),
        ("stream", "start")
    );
    assert_eq!(command.args, json!({"stream_id": "pocket"}));
    assert!(command.local);
    let answered = call.await.unwrap();
    assert_eq!(answered.status, 202);
    assert_eq!(answered.body["stream"]["desired"]["state"], "live");
    assert_eq!(answered.body["stream"]["reported"]["state"], "starting");
    assert_eq!(
        answered.body["stream"]["reported"]["since"],
        "2026-11-27T07:20:00Z"
    );
}

#[tokio::test]
async fn sends_updates_and_destinations_as_stream_update() {
    let mut setup = setup().await;
    let base = format!("/v1/control/devices/{THING}/streams/pocket");
    for (method, path, body, args) in [
        (
            "PATCH",
            base.clone(),
            json!({"profile": "hevc-720p", "bitrate": {"overrideKbps": 2500}, "record": true,
                   "sourceCeilingPercent": 80, "source": {"camera": {"video": "usb:3-1"}},
                   "clientToken": "t1"}),
            json!({"stream_id": "pocket", "profile": {"set": "hevc-720p"}, "bitrate": {"set": 2500},
                   "record": {"set": true}, "source_ceiling_percent": {"set": 80},
                   "source": {"set": {"camera": {"video": "usb:3-1"}}}}),
        ),
        (
            "PATCH",
            base.clone(),
            json!({"bitrate": {"profileDefault": {}}}),
            json!({"stream_id": "pocket", "bitrate": {"configured": {}}}),
        ),
        (
            "PUT",
            format!("{base}/destination"),
            json!({"url": "srt://ingest.example.com:4001?streamid=a&passphrase=not-a-secret-1"}),
            json!({"stream_id": "pocket", "destination": {"set": {"url":
                "srt://ingest.example.com:4001?streamid=a&passphrase=not-a-secret-1"}}}),
        ),
    ] {
        let device = setup.device.clone();
        let call = tokio::spawn(async move { handle(&device, method, &path, &[], &body).await });
        let command = answer(
            &mut setup.stream,
            Outcome::Ok(json!({"status": {"desired": "stopped"}})),
        )
        .await;
        assert_eq!(command.name, "update");
        assert_eq!(command.args, args);
        assert_eq!(call.await.unwrap().status, 202);
    }
}

#[tokio::test]
async fn names_a_refusal_and_the_device_errors_as_the_cloud_does() {
    let mut setup = setup().await;
    let path = format!("/v1/control/devices/{THING}/streams/pocket");
    for (outcome, status, error) in [
        (
            Outcome::Ok(json!({"status": {}, "refused": [
                {"setting": "profile", "reason": "no profile \"x\""},
                {"setting": "source_ceiling_percent", "reason": "too high"}]})),
            409,
            "StreamChangeRefused",
        ),
        (
            Outcome::error("INVALID_MESSAGE", "no stream nope"),
            404,
            "StreamNotFound",
        ),
        (
            Outcome::error("INVALID_MESSAGE", "bitrate must be a number"),
            400,
            "ValidationException",
        ),
        (
            Outcome::error("MODULE_UNAVAILABLE", "the stream daemon went away"),
            409,
            "DeviceStateUnavailable",
        ),
        (Outcome::error("INTERNAL", "boom"), 500, "InternalError"),
    ] {
        let device = setup.device.clone();
        let path = path.clone();
        let call = tokio::spawn(async move {
            handle(&device, "PATCH", &path, &[], &json!({"profile": "x"})).await
        });
        answer(&mut setup.stream, outcome).await;
        let answered = call.await.unwrap();
        assert_eq!(
            (answered.status, answered.error),
            (status, Some(error)),
            "{}",
            answered.body
        );
        if status == 409 && error == "StreamChangeRefused" {
            assert_eq!(
                answered.body["refused"][1]["setting"],
                "sourceCeilingPercent"
            );
        }
    }
    // The module doesn't answer in time (the router's timeout).
    let device = setup.device.clone();
    let late = tokio::spawn(async move {
        handle(&device, "PATCH", &path, &[], &json!({"record": false})).await
    });
    let _held = tokio::time::timeout(WAIT, setup.stream.recv())
        .await
        .unwrap()
        .unwrap();
    let answered = late.await.unwrap();
    assert_eq!(
        (answered.status, answered.error),
        (504, Some("DeviceUnreachable"))
    );
}

#[test]
fn refuses_update_bodies_outside_the_model() {
    for (body, problem) in [
        (json!([]), "JSON object"),
        (json!({"profile": 3}), "profile"),
        (
            json!({"bitrate": {"overrideKbps": 1, "profileDefault": {}}}),
            "bitrate",
        ),
        (json!({"bitrate": {"overrideKbps": "fast"}}), "overrideKbps"),
        (
            json!({"source": {"camera": {"video": "usb:1-1"}, "test": {}}}),
            "source",
        ),
        (json!({"source": {"floppy": {}}}), "unknown source"),
        (
            json!({"source": {"test": {"fps": 30, "color": "red"}}}),
            "source.test.color",
        ),
        (json!({"name": "x"}), "unknown member name"),
    ] {
        let error = update_args(&body).unwrap_err();
        assert!(error.contains(problem), "{body}: {error}");
    }
}

#[tokio::test]
async fn sets_and_removes_wifi_networks_with_plain_passphrases() {
    let mut setup = setup().await;
    let path = format!("/v1/control/devices/{THING}/wifi/networks");
    let device = setup.device.clone();
    let set_path = path.clone();
    let call = tokio::spawn(async move {
        handle(
            &device,
            "PUT",
            &set_path,
            &[],
            &json!({"ssid": "Cafe", "passphrase": "not-a-secret-2"}),
        )
        .await
    });
    let command = answer(
        &mut setup.net,
        Outcome::Ok(json!({"network": {"ssid": "Cafe", "security": "personal", "hidden": false}})),
    )
    .await;
    assert_eq!(command.name, "wifi.set");
    assert_eq!(
        command.args,
        json!({"ssid": "Cafe", "hidden": false, "passphrase": "not-a-secret-2"})
    );
    let answered = call.await.unwrap();
    assert_eq!(answered.status, 200);
    assert_eq!(
        answered.body,
        json!({"network": {"ssid": "Cafe", "security": "personal", "hidden": false}})
    );
    assert!(!answered.body.to_string().contains("not-a-secret-2"));

    // A refusal's code becomes its reason, as in the cloud.
    let device = setup.device.clone();
    let refused_path = path.clone();
    let call = tokio::spawn(async move {
        handle(&device, "PUT", &refused_path, &[], &json!({"ssid": "More"})).await
    });
    answer(
        &mut setup.net,
        Outcome::error("TOO_MANY", "16 networks already"),
    )
    .await;
    let refused = call.await.unwrap();
    assert_eq!(
        (refused.status, refused.error),
        (409, Some("WifiNetworkRefused"))
    );
    assert_eq!(refused.body["reason"], "too_many");

    let device = setup.device.clone();
    let call = tokio::spawn(async move {
        handle(
            &device,
            "DELETE",
            &path,
            &[("ssid".into(), "Cafe".into())],
            &Value::Null,
        )
        .await
    });
    let command = answer(&mut setup.net, Outcome::Ok(json!({"removed": true}))).await;
    assert_eq!(
        (command.name.as_str(), &command.args),
        ("wifi.remove", &json!({"ssid": "Cafe"}))
    );
    assert_eq!(call.await.unwrap().body, json!({"removed": true}));
}
