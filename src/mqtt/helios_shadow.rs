//! The `helios` shadow (LLD 2, section 5): the agent's own reported state, from the identity,
//! the credentials and the MQTT connection. Reported only; it accepts no desired state.
//!
//! Urgent changes are reported at once: the identity state, the MQTT session or disconnect
//! reason, a credentials error, and the clock's synced flag, offset or boot offset. Other changes
//! (timestamps, counters, the clock's drift and error bounds) are reported at most once per
//! `mqtt.helios_shadow_interval_s`, 60 s by default. Each module's state (`modules`) is urgent
//! too, except when it last changed.

use std::time::{Duration, Instant, SystemTime};

use serde_json::{Map, Value, json};
use tokio::sync::watch;
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;

use crate::clock::ClockStatus;
use crate::credentials::provider::CredentialsStatus;
use crate::identity::manager::IdentityState;
use crate::modules::ModuleStates;
use crate::mqtt::envelope::timestamp;
use crate::mqtt::manager::MqttStatus;
use crate::mqtt::shadow::ShadowHandle;

/// The shadow's name.
pub const SHADOW: &str = "helios";

/// The default `mqtt.helios_shadow_interval_s`: how often changes that aren't urgent are
/// reported.
pub const DEFAULT_INTERVAL: Duration = Duration::from_secs(60);

/// The shortest `mqtt.helios_shadow_interval_s`.
pub const MIN_INTERVAL: Duration = Duration::from_secs(10);

/// The longest `mqtt.helios_shadow_interval_s`: a day.
pub const MAX_INTERVAL: Duration = Duration::from_secs(86_400);

/// What the reporter watches.
pub struct Sources {
    /// The identity manager's state.
    pub identity: watch::Receiver<IdentityState>,
    /// The credentials refresher's status.
    pub credentials: watch::Receiver<CredentialsStatus>,
    /// The MQTT connection's status.
    pub mqtt: watch::Receiver<MqttStatus>,
    /// The clock checks' results (LLD 1, section 4.11).
    pub clock: watch::Receiver<ClockStatus>,
    /// Each device module's state, from the supervisor.
    pub modules: watch::Receiver<ModuleStates>,
    /// The kernel's boot ID.
    pub boot_id: Option<String>,
    /// When Helios started.
    pub started_at: SystemTime,
}

/// Starts the reporter, which ends when `cancel` is cancelled.
///
/// # Panics
///
/// Panics if called outside a tokio runtime.
#[must_use]
pub fn start(
    sources: Sources,
    shadows: ShadowHandle,
    interval: Duration,
    cancel: CancellationToken,
) -> JoinHandle<()> {
    tokio::spawn(run(sources, shadows, interval, cancel))
}

async fn run(
    mut sources: Sources,
    shadows: ShadowHandle,
    interval: Duration,
    cancel: CancellationToken,
) {
    // The last report: its state, its significant part, and when it was sent.
    let mut last: Option<(Map<String, Value>, Value, Instant)> = None;
    loop {
        let reported = reported(&sources);
        let key = significant(&reported);
        // When a change that isn't urgent may go: `interval` after the last report.
        let mut waiting_until = None;
        let due = match &last {
            None => true,
            Some((previous, previous_key, at)) => {
                if *previous_key != key {
                    true
                } else if *previous != reported {
                    waiting_until = Some(*at + interval);
                    at.elapsed() >= interval
                } else {
                    false
                }
            }
        };
        if due {
            shadows.report(SHADOW, reported.clone());
            last = Some((reported, key, Instant::now()));
            waiting_until = None;
        }
        let wake = async {
            match waiting_until {
                Some(at) => tokio::time::sleep_until(tokio::time::Instant::from_std(at)).await,
                None => std::future::pending().await,
            }
        };
        tokio::select! {
            () = cancel.cancelled() => return,
            changed = sources.identity.changed() => if changed.is_err() { return },
            changed = sources.credentials.changed() => if changed.is_err() { return },
            changed = sources.mqtt.changed() => if changed.is_err() { return },
            changed = sources.clock.changed() => if changed.is_err() { return },
            changed = sources.modules.changed() => if changed.is_err() { return },
            () = wake => {}
        }
    }
}

/// The parts of the state that are reported as soon as they change. The clock's drift, error
/// bounds and offset details move with every NTP adjustment and sample, so they wait for the
/// interval; its offset only changes when the clock moves by a second or more.
fn significant(reported: &Map<String, Value>) -> Value {
    json!({
        "identity": reported["identity"]["state"],
        "credentials_error": reported["credentials"]["last_error"],
        "mqtt_session": reported["mqtt"]["session"],
        "mqtt_reason": reported["mqtt"]["last_disconnect_reason"],
        "clock_synced": reported["clock"]["synced"],
        "clock_offset": reported["clock"]["offset_ms"],
        "clock_boot_offset": reported["clock"]["boot_offset_s"],
        "modules": reported["modules"]
            .as_object()
            .map(|modules| {
                modules
                    .iter()
                    .map(|(name, module)| {
                        (
                            name.clone(),
                            json!([module["state"], module["restarts"], module["last_error"]]),
                        )
                    })
                    .collect::<Map<String, Value>>()
            }),
    })
}

/// The `helios` shadow's reported state now.
fn reported(sources: &Sources) -> Map<String, Value> {
    let identity = sources.identity.borrow().clone();
    let credentials = sources.credentials.borrow().clone();
    let mqtt = sources.mqtt.borrow().clone();
    let clock = sources.clock.borrow().clone();
    let modules: Map<String, Value> = sources
        .modules
        .borrow()
        .iter()
        .map(|(name, status)| {
            (
                (*name).to_owned(),
                json!({
                    "state": status.state.as_str(),
                    "restarts": status.restarts,
                    "last_error": status.last_error,
                    "since": timestamp(status.since),
                }),
            )
        })
        .collect();
    let mut identity_json = json!({"state": identity.name()});
    match &identity {
        IdentityState::Ready(ready) => {
            identity_json["token"] = json!(ready.token.model);
            identity_json["cert_not_after"] = json!(timestamp(ready.cert.not_after));
        }
        IdentityState::Unavailable { reason, .. } => identity_json["reason"] = json!(reason),
        IdentityState::Fatal { reason } => identity_json["reason"] = json!(reason.to_string()),
        IdentityState::Bootstrapping { last_error, .. } => {
            identity_json["reason"] = json!(last_error);
        }
        IdentityState::Starting => {}
    }
    let mut reported = Map::new();
    reported.insert("version".into(), json!(env!("CARGO_PKG_VERSION")));
    reported.insert("boot_id".into(), json!(sources.boot_id));
    reported.insert("started_at".into(), json!(timestamp(sources.started_at)));
    reported.insert("identity".into(), identity_json);
    reported.insert(
        "credentials".into(),
        json!({
            "expires_at": credentials.expires_at.map(timestamp),
            "last_error": credentials.last_error,
        }),
    );
    reported.insert(
        "mqtt".into(),
        json!({
            "session": mqtt.session,
            "connected_at": mqtt.connected_at.map(timestamp),
            "last_disconnect_reason": mqtt.last_disconnect_reason,
            "dropped_events": mqtt.dropped_events,
        }),
    );
    let offset = clock.offset;
    reported.insert(
        "clock".into(),
        json!({
            "synced": clock.synced,
            "max_error_ms": clock.max_error_ms,
            // Two decimals: finer than NTP's estimate means, and stable in the shadow.
            "drift_ppm": clock.drift_ppm.map(|ppm| (ppm * 100.0).round() / 100.0),
            "offset_ms": offset.map(|o| o.offset_ms),
            "offset_uncertainty_ms": offset.map(|o| u64::try_from(o.uncertainty.as_millis()).unwrap_or(u64::MAX)),
            "offset_source": offset.map(|o| o.source.as_str()),
            "offset_at": offset.map(|o| timestamp(o.at)),
            "boot_offset_s": clock.boot_offset_s,
        }),
    );
    reported.insert("modules".into(), Value::Object(modules));
    reported
}

#[cfg(test)]
mod tests;
