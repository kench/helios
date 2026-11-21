//! `helios` shadow reporter tests, with watch channels standing in for the real components.

use crate::mqtt::manager::{MqttHandle, Request as MqttRequest};
use crate::mqtt::shadow::{ShadowManager, Timing};

use super::*;

const WAIT: Duration = Duration::from_secs(5);

struct Setup {
    identity: watch::Sender<IdentityState>,
    credentials: watch::Sender<CredentialsStatus>,
    mqtt: watch::Sender<MqttStatus>,
    clock: watch::Sender<ClockStatus>,
    published: tokio::sync::mpsc::UnboundedReceiver<MqttRequest>,
    replies: tokio::sync::mpsc::Sender<crate::mqtt::manager::Incoming>,
    cancel: CancellationToken,
}

impl Drop for Setup {
    fn drop(&mut self) {
        self.cancel.cancel();
    }
}

fn setup(interval: Duration) -> Setup {
    let (handle, published, mqtt) = MqttHandle::for_test();
    let (replies, incoming) = tokio::sync::mpsc::channel(4);
    let cancel = CancellationToken::new();
    let timing = Timing {
        min_interval: Duration::ZERO,
        reply_timeout: Duration::from_secs(10),
        tick: Duration::from_millis(5),
    };
    let (shadows, _task) = ShadowManager::start(
        handle,
        incoming,
        timing,
        crate::clock::ClockSamples::discard(),
        cancel.clone(),
    );
    let (identity, identity_rx) = watch::channel(IdentityState::Starting);
    let (credentials, credentials_rx) = watch::channel(CredentialsStatus::default());
    let (clock, clock_rx) = watch::channel(ClockStatus::default());
    let _reporter = start(
        Sources {
            identity: identity_rx,
            credentials: credentials_rx,
            mqtt: mqtt.subscribe(),
            clock: clock_rx,
            boot_id: Some("boot-1".into()),
            started_at: SystemTime::UNIX_EPOCH,
        },
        shadows,
        interval,
        cancel.clone(),
    );
    mqtt.send_modify(|status| {
        status.connected = true;
        status.session = 1;
        status.thing = Some("t-1".into());
    });
    Setup {
        identity,
        credentials,
        mqtt,
        clock,
        published,
        replies,
        cancel,
    }
}

/// The next `helios` shadow update's reported state, acknowledged as AWS IoT would.
async fn next_report(setup: &mut Setup) -> Value {
    loop {
        let request = tokio::time::timeout(WAIT, setup.published.recv())
            .await
            .expect("a shadow update")
            .unwrap();
        if let MqttRequest::Now { topic, payload } = request
            && topic == "$aws/things/t-1/shadow/name/helios/update"
        {
            let document: Value = serde_json::from_slice(&payload).unwrap();
            setup
                .replies
                .send(crate::mqtt::manager::Incoming {
                    topic: format!("{topic}/accepted"),
                    payload: json!({"clientToken": document["clientToken"]})
                        .to_string()
                        .into_bytes(),
                })
                .await
                .unwrap();
            return document["state"]["reported"].clone();
        }
    }
}

#[tokio::test]
async fn reports_the_agent_state() {
    let mut setup = setup(COUNTER_INTERVAL);

    let reported = next_report(&mut setup).await;

    assert_eq!(reported["version"], env!("CARGO_PKG_VERSION"));
    assert_eq!(reported["boot_id"], "boot-1");
    assert_eq!(reported["started_at"], "1970-01-01T00:00:00.000Z");
    assert_eq!(reported["identity"]["state"], "starting");
    assert_eq!(reported["mqtt"]["session"], 1);
    assert_eq!(reported["credentials"]["last_error"], Value::Null);
}

#[tokio::test]
async fn reports_significant_changes_at_once() {
    let mut setup = setup(COUNTER_INTERVAL);
    next_report(&mut setup).await;

    setup.identity.send_replace(IdentityState::Unavailable {
        reason: "token lost".into(),
        since: Instant::now(),
    });
    let reported = next_report(&mut setup).await;

    assert_eq!(reported["identity"]["state"], "unavailable");
    assert_eq!(reported["identity"]["reason"], "token lost");
    setup
        .credentials
        .send_modify(|c| c.last_error = Some("403 Forbidden".into()));
    assert_eq!(
        next_report(&mut setup).await["credentials"]["last_error"],
        "403 Forbidden"
    );
}

#[tokio::test]
async fn reports_counter_changes_at_most_once_an_interval() {
    let mut setup = setup(Duration::from_millis(300));
    next_report(&mut setup).await;
    let start = Instant::now();

    setup.mqtt.send_modify(|status| status.dropped_events = 5);
    let reported = next_report(&mut setup).await;

    assert_eq!(reported["mqtt"]["dropped_events"], 5);
    assert!(
        start.elapsed() >= Duration::from_millis(250),
        "{:?}",
        start.elapsed()
    );
}

#[tokio::test]
async fn reports_bootstrap_and_fatal_reasons() {
    let mut setup = setup(COUNTER_INTERVAL);
    next_report(&mut setup).await;

    setup.identity.send_replace(IdentityState::Bootstrapping {
        attempts: 2,
        last_error: Some("404 UnknownDevice".into()),
    });
    assert_eq!(
        next_report(&mut setup).await["identity"]["reason"],
        "404 UnknownDevice"
    );
    setup.identity.send_replace(IdentityState::Fatal {
        reason: crate::identity::manager::FatalReason::PinLocked,
    });
    let reported = next_report(&mut setup).await;
    assert_eq!(reported["identity"]["state"], "fatal");
    assert_eq!(reported["identity"]["reason"], "token PIN is locked");
}

#[tokio::test]
async fn reports_the_clock_checks_at_once() {
    let mut setup = setup(COUNTER_INTERVAL);
    let first = next_report(&mut setup).await;
    assert_eq!(first["clock"]["synced"], Value::Null);
    assert_eq!(first["clock"]["offset_ms"], Value::Null);

    setup.clock.send_replace(ClockStatus {
        synced: Some(true),
        max_error_ms: Some(16_500),
        drift_ppm: Some(-12.345_678),
        offset: Some(crate::clock::offset::Offset {
            offset_ms: 21_292_000,
            uncertainty: Duration::from_millis(540),
            source: crate::clock::offset::Source::Credentials,
            at: SystemTime::UNIX_EPOCH,
        }),
        boot_offset_s: Some(21_292),
    });
    let clock = next_report(&mut setup).await["clock"].clone();

    assert_eq!(
        clock,
        json!({
            "synced": true,
            "max_error_ms": 16_500,
            "drift_ppm": -12.35,
            "offset_ms": 21_292_000,
            "offset_uncertainty_ms": 540,
            "offset_source": "credentials",
            "offset_at": "1970-01-01T00:00:00.000Z",
            "boot_offset_s": 21_292,
        })
    );
}
