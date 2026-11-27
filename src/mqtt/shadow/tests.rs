//! Shadow manager tests, with a test MQTT handle that records publishes and fakes sessions.

use crate::mqtt::manager::Request as MqttRequest;

use super::*;

const THING: &str = "t-1";
const WAIT: Duration = Duration::from_secs(5);

struct Setup {
    shadows: ShadowHandle,
    published: mpsc::UnboundedReceiver<MqttRequest>,
    status: watch::Sender<MqttStatus>,
    incoming: mpsc::Sender<Incoming>,
    cancel: CancellationToken,
}

impl Drop for Setup {
    fn drop(&mut self) {
        self.cancel.cancel();
    }
}

fn timing() -> Timing {
    Timing {
        min_interval: Duration::from_millis(50),
        reply_timeout: Duration::from_millis(300),
        tick: Duration::from_millis(5),
    }
}

fn setup() -> Setup {
    let (mqtt, published, status) = MqttHandle::for_test();
    let (incoming, incoming_rx) = mpsc::channel(16);
    let cancel = CancellationToken::new();
    let (shadows, _task) = ShadowManager::start(
        mqtt,
        incoming_rx,
        timing(),
        crate::clock::ClockSamples::discard(),
        cancel.clone(),
    );
    Setup {
        shadows,
        published,
        status,
        incoming,
        cancel,
    }
}

fn connect(setup: &Setup, session: u64) {
    setup.status.send_modify(|status| {
        status.connected = true;
        status.session = session;
        status.thing = Some(THING.to_owned());
    });
}

fn disconnect(setup: &Setup) {
    setup.status.send_modify(|status| status.connected = false);
}

fn map(value: Value) -> Map<String, Value> {
    value.as_object().unwrap().clone()
}

/// The next publish: its topic and JSON payload.
async fn next(setup: &mut Setup) -> (String, Value) {
    let request = tokio::time::timeout(WAIT, setup.published.recv())
        .await
        .expect("a publish")
        .unwrap();
    match request {
        MqttRequest::Now { topic, payload } => (topic, serde_json::from_slice(&payload).unwrap()),
        MqttRequest::Event(event) => panic!("unexpected event {event:?}"),
    }
}

/// The next publish to `…/update`, skipping gets.
async fn next_update(setup: &mut Setup) -> Value {
    loop {
        let (topic, document) = next(setup).await;
        if topic.ends_with("/update") {
            assert_eq!(
                topic,
                format!("$aws/things/{THING}/shadow/name/helios/update")
            );
            return document;
        }
    }
}

async fn assert_quiet(setup: &mut Setup, for_how_long: Duration) {
    if let Ok(Some(request)) = tokio::time::timeout(for_how_long, setup.published.recv()).await {
        panic!("unexpected publish {request:?}");
    }
}

async fn reply(setup: &Setup, suffix: &str, document: Value) {
    setup
        .incoming
        .send(Incoming {
            topic: format!("$aws/things/{THING}/shadow/name/helios/{suffix}"),
            payload: document.to_string().into_bytes(),
        })
        .await
        .unwrap();
}

#[tokio::test]
async fn reads_the_shadow_and_sends_the_snapshot_after_connecting() {
    let mut setup = setup();
    setup
        .shadows
        .report("helios", map(json!({"version": "0.1.0"})));
    connect(&setup, 1);

    let (topic, get) = next(&mut setup).await;
    assert_eq!(topic, format!("$aws/things/{THING}/shadow/name/helios/get"));
    assert_eq!(get, json!({}));
    let update = next_update(&mut setup).await;

    assert_eq!(update["state"]["reported"], json!({"version": "0.1.0"}));
    assert_eq!(update["clientToken"].as_str().unwrap().len(), 26);
}

#[tokio::test]
async fn sends_nothing_while_disconnected() {
    let mut setup = setup();

    setup.shadows.report("helios", map(json!({"a": 1})));

    assert_quiet(&mut setup, Duration::from_millis(100)).await;
}

#[tokio::test]
async fn sends_one_update_at_a_time_and_coalesces_changes() {
    let mut setup = setup();
    connect(&setup, 1);
    setup.shadows.report("helios", map(json!({"n": 1})));
    let first = next_update(&mut setup).await;

    setup.shadows.report("helios", map(json!({"n": 2})));
    setup.shadows.report("helios", map(json!({"n": 3})));
    // Nothing until the first is accepted.
    assert_quiet(&mut setup, Duration::from_millis(100)).await;
    reply(
        &setup,
        "update/accepted",
        json!({"clientToken": first["clientToken"]}),
    )
    .await;
    let second = next_update(&mut setup).await;

    assert_eq!(second["state"]["reported"]["n"], 3);
}

#[tokio::test]
async fn ignores_replies_to_other_updates() {
    let mut setup = setup();
    connect(&setup, 1);
    setup.shadows.report("helios", map(json!({"n": 1})));
    next_update(&mut setup).await;
    setup.shadows.report("helios", map(json!({"n": 2})));

    reply(
        &setup,
        "update/accepted",
        json!({"clientToken": "someone-else"}),
    )
    .await;

    assert_quiet(&mut setup, Duration::from_millis(100)).await;
}

#[tokio::test]
async fn removes_fields_that_are_no_longer_reported() {
    let mut setup = setup();
    connect(&setup, 1);
    setup.shadows.report("helios", map(json!({"a": 1, "b": 2})));
    let first = next_update(&mut setup).await;
    reply(
        &setup,
        "update/accepted",
        json!({"clientToken": first["clientToken"]}),
    )
    .await;

    setup.shadows.report("helios", map(json!({"a": 1})));
    let second = next_update(&mut setup).await;

    assert_eq!(second["state"]["reported"], json!({"a": 1, "b": null}));
    reply(
        &setup,
        "update/accepted",
        json!({"clientToken": second["clientToken"]}),
    )
    .await;
    setup.shadows.report("helios", map(json!({"a": 2})));
    let third = next_update(&mut setup).await;
    assert_eq!(third["state"]["reported"], json!({"a": 2}));
}

#[tokio::test]
async fn keeps_removals_made_while_an_update_is_in_flight() {
    let mut setup = setup();
    connect(&setup, 1);
    setup.shadows.report("helios", map(json!({"a": 1, "b": 2})));
    let first = next_update(&mut setup).await;

    // b goes before the first update is accepted.
    setup.shadows.report("helios", map(json!({"a": 1})));
    tokio::time::sleep(Duration::from_millis(20)).await;
    reply(
        &setup,
        "update/accepted",
        json!({"clientToken": first["clientToken"]}),
    )
    .await;
    let second = next_update(&mut setup).await;

    assert_eq!(second["state"]["reported"], json!({"a": 1, "b": null}));
}

#[tokio::test]
async fn removes_fields_an_earlier_run_left() {
    let mut setup = setup();
    connect(&setup, 1);
    setup.shadows.report("helios", map(json!({"a": 1})));
    let first = next_update(&mut setup).await;
    reply(
        &setup,
        "update/accepted",
        json!({"clientToken": first["clientToken"]}),
    )
    .await;

    reply(
        &setup,
        "get/accepted",
        json!({"state": {"reported": {"a": 0, "old": true}}}),
    )
    .await;
    let second = next_update(&mut setup).await;

    assert_eq!(second["state"]["reported"], json!({"a": 1, "old": null}));
}

#[tokio::test]
async fn removes_nested_fields_that_are_no_longer_reported() {
    let mut setup = setup();
    connect(&setup, 1);
    let both = json!({"ingest": {"publishers": {"a": {"address": "x"}, "b": {"address": "y"}}}});
    setup.shadows.report("helios", map(both));
    let first = next_update(&mut setup).await;
    reply(
        &setup,
        "update/accepted",
        json!({"clientToken": first["clientToken"]}),
    )
    .await;

    setup.shadows.report(
        "helios",
        map(json!({"ingest": {"publishers": {"a": {"address": "x"}}}})),
    );
    let second = next_update(&mut setup).await;

    assert_eq!(
        second["state"]["reported"],
        json!({"ingest": {"publishers": {"a": {"address": "x"}, "b": null}}})
    );
    reply(
        &setup,
        "update/accepted",
        json!({"clientToken": second["clientToken"]}),
    )
    .await;
    // b came back: no null for it any more; and a's whole object going takes one null.
    setup.shadows.report(
        "helios",
        map(json!({"ingest": {"publishers": {"b": {"address": "z"}}}})),
    );
    let third = next_update(&mut setup).await;
    assert_eq!(
        third["state"]["reported"],
        json!({"ingest": {"publishers": {"a": null, "b": {"address": "z"}}}})
    );
}

#[tokio::test]
async fn a_nested_null_gives_way_to_a_new_value_of_another_kind() {
    let mut setup = setup();
    connect(&setup, 1);
    setup
        .shadows
        .report("helios", map(json!({"ingest": {"publishers": {"a": 1}}})));
    let first = next_update(&mut setup).await;
    reply(
        &setup,
        "update/accepted",
        json!({"clientToken": first["clientToken"]}),
    )
    .await;

    // The parent stops being an object: its own value replaces everything under it.
    setup.shadows.report("helios", map(json!({"ingest": null})));
    let second = next_update(&mut setup).await;

    assert_eq!(second["state"]["reported"], json!({"ingest": null}));
}

#[tokio::test]
async fn removes_nested_fields_an_earlier_run_left() {
    let mut setup = setup();
    connect(&setup, 1);
    setup.shadows.report(
        "helios",
        map(json!({"streams": {"now": {"state": "live"}}})),
    );
    let first = next_update(&mut setup).await;
    reply(
        &setup,
        "update/accepted",
        json!({"clientToken": first["clientToken"]}),
    )
    .await;

    reply(
        &setup,
        "get/accepted",
        json!({"state": {"reported": {"streams": {
            "now": {"state": "stopped", "old_field": 1}, "old": {"state": "live"}
        }}}}),
    )
    .await;
    let second = next_update(&mut setup).await;

    assert_eq!(
        second["state"]["reported"],
        json!({"streams": {"now": {"state": "live", "old_field": null}, "old": null}})
    );
}

#[tokio::test]
async fn a_rejected_update_waits_for_the_next_change() {
    let mut setup = setup();
    connect(&setup, 1);
    setup.shadows.report("helios", map(json!({"n": 1})));
    let first = next_update(&mut setup).await;

    reply(
        &setup,
        "update/rejected",
        json!({"clientToken": first["clientToken"], "code": 400, "message": "bad"}),
    )
    .await;
    assert_quiet(&mut setup, Duration::from_millis(100)).await;
    setup.shadows.report("helios", map(json!({"n": 2})));

    assert_eq!(next_update(&mut setup).await["state"]["reported"]["n"], 2);
}

#[tokio::test]
async fn sends_again_without_a_reply() {
    let mut setup = setup();
    connect(&setup, 1);
    setup.shadows.report("helios", map(json!({"n": 1})));
    let first = next_update(&mut setup).await;

    let again = next_update(&mut setup).await;

    assert_eq!(again["state"]["reported"]["n"], 1);
    assert_ne!(again["clientToken"], first["clientToken"]);
}

#[tokio::test]
async fn sends_every_snapshot_again_after_reconnecting() {
    let mut setup = setup();
    connect(&setup, 1);
    setup.shadows.report("helios", map(json!({"n": 1})));
    let first = next_update(&mut setup).await;
    reply(
        &setup,
        "update/accepted",
        json!({"clientToken": first["clientToken"]}),
    )
    .await;
    disconnect(&setup);

    connect(&setup, 2);

    assert_eq!(next_update(&mut setup).await["state"]["reported"]["n"], 1);
}

#[tokio::test]
async fn skips_documents_too_large_for_aws_iot() {
    let mut setup = setup();
    connect(&setup, 1);

    setup.shadows.report(
        "helios",
        map(json!({"big": "x".repeat(MAX_DOCUMENT_BYTES)})),
    );

    // Only the get, never the update.
    let (topic, _) = next(&mut setup).await;
    assert!(topic.ends_with("/get"), "{topic}");
    assert_quiet(&mut setup, Duration::from_millis(100)).await;
}

#[tokio::test]
async fn ignores_unrelated_and_malformed_replies() {
    let mut setup = setup();
    connect(&setup, 1);
    setup.shadows.report("helios", map(json!({"n": 1})));
    next_update(&mut setup).await;

    for topic in [
        "helios/t-1/cmd/video".to_owned(),
        format!("$aws/things/{THING}/shadow/name/unknown/update/accepted"),
        format!("$aws/things/{THING}/shadow/name/helios/get/rejected"),
    ] {
        setup
            .incoming
            .send(Incoming {
                topic,
                payload: b"not json".to_vec(),
            })
            .await
            .unwrap();
    }
    reply(
        &setup,
        "get/rejected",
        json!({"code": 404, "message": "No shadow exists"}),
    )
    .await;

    assert_quiet(&mut setup, Duration::from_millis(100)).await;
}

#[test]
fn parses_shadow_topics() {
    assert_eq!(
        parse_topic(THING, "$aws/things/t-1/shadow/name/usb/update/delta"),
        Some(ShadowTopic {
            name: "usb",
            operation: "update",
            result: "delta"
        })
    );
    assert_eq!(
        parse_topic(THING, "$aws/things/t-2/shadow/name/usb/update/delta"),
        None
    );
    assert_eq!(
        parse_topic(THING, "$aws/things/t-1/shadow/name//get/accepted"),
        None
    );
    assert_eq!(
        parse_topic(THING, "$aws/things/t-1/shadow/name/usb/update/documents/x"),
        None
    );
    assert_eq!(parse_topic(THING, "helios/t-1/cmd/usb"), None);
}

#[tokio::test]
async fn offers_accepted_timestamps_to_the_clock_checks() {
    let (mqtt, mut published, status) = MqttHandle::for_test();
    let (incoming, incoming_rx) = mpsc::channel(16);
    let cancel = CancellationToken::new();
    let (clock, mut samples) = crate::clock::ClockSamples::for_test();
    let (shadows, _task) = ShadowManager::start(mqtt, incoming_rx, timing(), clock, cancel.clone());
    let mut setup = Setup {
        shadows,
        published: {
            let (_, empty) = mpsc::unbounded_channel();
            std::mem::replace(&mut published, empty)
        },
        status,
        incoming,
        cancel,
    };
    connect(&setup, 1);
    setup.shadows.report("helios", map(json!({"n": 1})));
    let update = next_update(&mut setup).await;

    // Another update's reply, then ours without and with a timestamp.
    reply(
        &setup,
        "update/accepted",
        json!({"clientToken": "other", "timestamp": 1}),
    )
    .await;
    reply(
        &setup,
        "update/accepted",
        json!({"clientToken": update["clientToken"], "timestamp": 1_795_240_800}),
    )
    .await;
    let sample = tokio::time::timeout(WAIT, samples.recv())
        .await
        .unwrap()
        .unwrap();

    assert_eq!(sample.source, crate::clock::offset::Source::Shadow);
    assert_eq!(
        sample.server,
        UNIX_EPOCH + Duration::from_secs(1_795_240_800)
    );
    assert!(sample.received >= sample.sent);
    assert!(samples.try_recv().is_err());
}

#[tokio::test]
async fn clears_desired_state_until_an_update_carrying_it_is_accepted() {
    let mut setup = setup();
    connect(&setup, 1);
    setup.shadows.report("helios", map(json!({"a": 1})));
    let first = next_update(&mut setup).await;
    assert!(
        first["state"].get("desired").is_none(),
        "nothing to clear yet"
    );
    reply(
        &setup,
        "update/accepted",
        json!({"clientToken": first["clientToken"]}),
    )
    .await;

    setup.shadows.clear_desired("helios", &["streams", "gone"]);
    setup.shadows.clear_desired("helios", &["streams", "gone"]);
    setup.shadows.clear_desired("helios", &["streams", "old"]);
    let second = next_update(&mut setup).await;
    assert_eq!(
        second["state"]["desired"],
        json!({"streams": {"gone": null, "old": null}}),
        "each path once, under its parents"
    );
    assert_eq!(second["state"]["reported"], json!({"a": 1}));

    // Rejected: sent again with the next update.
    reply(
        &setup,
        "update/rejected",
        json!({"clientToken": second["clientToken"], "code": 500, "message": "busy"}),
    )
    .await;
    setup.shadows.report("helios", map(json!({"a": 2})));
    let third = next_update(&mut setup).await;
    assert_eq!(
        third["state"]["desired"],
        json!({"streams": {"gone": null, "old": null}})
    );
    reply(
        &setup,
        "update/accepted",
        json!({"clientToken": third["clientToken"]}),
    )
    .await;

    setup.shadows.report("helios", map(json!({"a": 3})));
    let fourth = next_update(&mut setup).await;
    assert!(
        fourth["state"].get("desired").is_none(),
        "accepted: cleared for good"
    );
}

#[test]
fn null_at_adds_the_objects_above_a_key() {
    let mut object = map(json!({"streams": {"keep": {"state": "live"}}, "other": 1}));
    null_at(&mut object, &["streams".into(), "gone".into()]);
    null_at(&mut object, &["other".into(), "deep".into()]);
    null_at(&mut object, &[]);
    assert_eq!(
        Value::Object(object),
        json!({"streams": {"keep": {"state": "live"}, "gone": null}, "other": {"deep": null}})
    );
}
