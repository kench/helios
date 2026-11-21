//! The `helios` shadow (LLD 2, section 5): the agent's own reported state, from the identity,
//! the credentials and the MQTT connection. Reported only; it accepts no desired state.
//!
//! It's reported whenever something meaningful changes (the identity state, the MQTT session, a
//! credentials error, the clock checks' results). A change to counters or timestamps alone is reported at most once a
//! minute.

use std::time::{Duration, Instant, SystemTime};

use serde_json::{Map, Value, json};
use tokio::sync::watch;
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;

use crate::clock::ClockStatus;
use crate::credentials::provider::CredentialsStatus;
use crate::identity::manager::IdentityState;
use crate::mqtt::envelope::timestamp;
use crate::mqtt::manager::MqttStatus;
use crate::mqtt::shadow::ShadowHandle;

/// The shadow's name.
pub const SHADOW: &str = "helios";

/// How often a change to counters alone is reported.
pub const COUNTER_INTERVAL: Duration = Duration::from_secs(60);

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
    let mut timer = tokio::time::interval(interval);
    timer.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    loop {
        let reported = reported(&sources);
        let key = significant(&reported);
        let due = match &last {
            None => true,
            Some((previous, previous_key, at)) => {
                *previous_key != key || (*previous != reported && at.elapsed() >= interval)
            }
        };
        if due {
            shadows.report(SHADOW, reported.clone());
            last = Some((reported, key, Instant::now()));
        }
        tokio::select! {
            () = cancel.cancelled() => return,
            changed = sources.identity.changed() => if changed.is_err() { return },
            changed = sources.credentials.changed() => if changed.is_err() { return },
            changed = sources.mqtt.changed() => if changed.is_err() { return },
            changed = sources.clock.changed() => if changed.is_err() { return },
            _ = timer.tick() => {}
        }
    }
}

/// The parts of the state that are reported as soon as they change.
fn significant(reported: &Map<String, Value>) -> Value {
    json!({
        "identity": reported["identity"]["state"],
        "credentials_error": reported["credentials"]["last_error"],
        "mqtt_session": reported["mqtt"]["session"],
        "mqtt_reason": reported["mqtt"]["last_disconnect_reason"],
        // The clock checks publish only changes worth reporting.
        "clock": reported["clock"],
    })
}

/// The `helios` shadow's reported state now.
fn reported(sources: &Sources) -> Map<String, Value> {
    let identity = sources.identity.borrow().clone();
    let credentials = sources.credentials.borrow().clone();
    let mqtt = sources.mqtt.borrow().clone();
    let clock = sources.clock.borrow().clone();
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
    reported
}

#[cfg(test)]
mod tests;
