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
    modules: watch::Sender<crate::modules::ModuleStates>,
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
    setup_with(interval, Value::Null)
}

fn setup_with(interval: Duration, token: Value) -> Setup {
    setup_report(interval, token, ClockReport::Full)
}

fn setup_report(interval: Duration, token: Value, clock_report: ClockReport) -> Setup {
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
    let (modules, modules_rx) = watch::channel(crate::modules::ModuleStates::new());
    let _reporter = start(
        Sources {
            identity: identity_rx,
            credentials: credentials_rx,
            mqtt: mqtt.subscribe(),
            clock: clock_rx,
            clock_report,
            modules: modules_rx,
            boot_id: Some("boot-1".into()),
            started_at: SystemTime::UNIX_EPOCH,
            token,
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
        modules,
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
    let mut setup = setup(DEFAULT_INTERVAL);

    let reported = next_report(&mut setup).await;

    assert_eq!(reported["version"], env!("CARGO_PKG_VERSION"));
    assert_eq!(reported["boot_id"], "boot-1");
    assert_eq!(reported["started_at"], "1970-01-01T00:00:00.000Z");
    assert_eq!(reported["identity"]["state"], "starting");
    assert_eq!(reported["mqtt"]["session"], 1);
    assert_eq!(reported["credentials"]["last_error"], Value::Null);
}

#[tokio::test]
async fn reports_the_token_copy_only_when_there_is_one() {
    let mut direct = setup(DEFAULT_INTERVAL);
    assert!(next_report(&mut direct).await.get("token").is_none());

    let token = json!({"copy": "tmpfs", "restored_from": "tokens.old",
                       "restored_at": "2026-11-22T22:30:00.000Z", "lost": false});
    let mut tmpfs = setup_with(DEFAULT_INTERVAL, token.clone());
    assert_eq!(next_report(&mut tmpfs).await["token"], token);
}

#[tokio::test]
async fn reports_significant_changes_at_once() {
    let mut setup = setup(DEFAULT_INTERVAL);
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
    let mut setup = setup(DEFAULT_INTERVAL);
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
async fn synced_mode_reports_only_whether_the_clock_is_synced() {
    let mut setup = setup_report(DEFAULT_INTERVAL, Value::Null, ClockReport::Synced);
    let first = next_report(&mut setup).await;
    assert_eq!(first["clock"], json!({"synced": null}));

    setup.clock.send_replace(ClockStatus {
        synced: Some(true),
        max_error_ms: Some(16_500),
        drift_ppm: Some(-12.3),
        offset: Some(crate::clock::offset::Offset {
            offset_ms: 2_096_114,
            uncertainty: Duration::from_millis(1801),
            source: crate::clock::offset::Source::Bootstrap,
            at: SystemTime::UNIX_EPOCH,
        }),
        boot_offset_s: Some(2_096),
    });
    assert_eq!(
        next_report(&mut setup).await["clock"],
        json!({"synced": true})
    );

    // Drift and error bounds move every minute; they don't make a report in this mode.
    setup
        .clock
        .send_modify(|clock| clock.drift_ppm = Some(-12.9));
    let quiet = tokio::time::timeout(Duration::from_millis(300), async {
        loop {
            if let Some(MqttRequest::Now { topic, .. }) = setup.published.recv().await
                && topic.ends_with("/shadow/name/helios/update")
            {
                return;
            }
        }
    })
    .await;
    assert!(quiet.is_err(), "nothing to report");
}

#[tokio::test]
async fn reports_the_clock_checks_at_once() {
    let mut setup = setup(DEFAULT_INTERVAL);
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

#[tokio::test]
async fn waits_for_the_interval_for_clock_details() {
    let mut setup = setup(Duration::from_millis(300));
    let offset = crate::clock::offset::Offset {
        offset_ms: 0,
        uncertainty: Duration::from_millis(540),
        source: crate::clock::offset::Source::Credentials,
        at: SystemTime::UNIX_EPOCH,
    };
    setup.clock.send_replace(ClockStatus {
        synced: Some(true),
        drift_ppm: Some(19.0),
        offset: Some(offset),
        ..ClockStatus::default()
    });
    let first = next_report(&mut setup).await;
    // The first report may predate the clock status; wait for the one that has it.
    if first["clock"]["synced"] != json!(true) {
        next_report(&mut setup).await;
    }
    let start = Instant::now();

    // NTP moves the frequency correction, and a new sample comes from another source.
    setup.clock.send_modify(|clock| {
        clock.drift_ppm = Some(24.2);
        clock.offset = Some(crate::clock::offset::Offset {
            source: crate::clock::offset::Source::Shadow,
            ..offset
        });
    });
    let reported = next_report(&mut setup).await;

    assert_eq!(reported["clock"]["drift_ppm"], 24.2);
    assert_eq!(reported["clock"]["offset_source"], "shadow");
    assert!(
        start.elapsed() >= Duration::from_millis(250),
        "{:?}",
        start.elapsed()
    );
}

#[tokio::test]
async fn sends_a_waiting_change_as_soon_as_the_interval_has_passed() {
    let mut setup = setup(Duration::from_millis(400));
    next_report(&mut setup).await;

    // An urgent report halfway through the interval, then a change that isn't urgent.
    tokio::time::sleep(Duration::from_millis(200)).await;
    setup.identity.send_replace(IdentityState::Bootstrapping {
        attempts: 1,
        last_error: None,
    });
    next_report(&mut setup).await;
    let urgent = Instant::now();
    setup.mqtt.send_modify(|status| status.dropped_events = 1);
    let reported = next_report(&mut setup).await;

    // About one interval after the urgent report; a fixed 400 ms timer would wait until 800 ms.
    let waited = urgent.elapsed();
    assert_eq!(reported["mqtt"]["dropped_events"], 1);
    assert!(waited >= Duration::from_millis(350), "{waited:?}");
    assert!(waited < Duration::from_millis(550), "{waited:?}");
}

#[tokio::test]
async fn reports_module_states_at_once_but_not_their_timestamps() {
    use crate::modules::{ModuleStatus, RunState};
    let mut setup = setup(Duration::from_secs(3600));
    assert_eq!(next_report(&mut setup).await["modules"], json!({}));

    setup.modules.send_modify(|modules| {
        modules.insert(
            "display",
            ModuleStatus {
                state: RunState::Restarting,
                restarts: 0,
                last_error: Some("framebuffer gone".into()),
                since: SystemTime::UNIX_EPOCH,
            },
        );
    });
    let reported = next_report(&mut setup).await;

    assert_eq!(
        reported["modules"]["display"],
        json!({
            "state": "restarting",
            "restarts": 0,
            "last_error": "framebuffer gone",
            "since": "1970-01-01T00:00:00.000Z",
        })
    );
    // Only the time changes: not urgent, so nothing goes out before the hour's interval.
    setup.modules.send_modify(|modules| {
        if let Some(display) = modules.get_mut("display") {
            display.since = SystemTime::UNIX_EPOCH + Duration::from_secs(1);
        }
    });
    let quiet = tokio::time::timeout(Duration::from_millis(300), next_report(&mut setup)).await;
    assert!(
        quiet.is_err(),
        "a timestamp alone shouldn't be reported at once"
    );
}
