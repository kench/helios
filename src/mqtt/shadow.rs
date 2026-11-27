//! The shadow manager (LLD 2, section 5): each module's named shadow, `$aws/things/<thing>/
//! shadow/name/<module>`.
//!
//! Modules hand it their whole reported state with [`ShadowHandle::report`]. It sends that
//! snapshot after every connect and whenever it changes: at most one update per shadow a second,
//! and one at a time per shadow (until `accepted`, `rejected` or a timeout). After connecting it
//! also sends `get` for each shadow. The reply's `reported` state tells it which fields a module
//! no longer reports, and those are set to `null` in the next update, which removes them. That
//! goes for nested keys too (`streams.<id>`), since the service merges an update into what it
//! holds and keeps a nested key until it's set to `null`. The
//! Shadows are reported-only: writes to the device are commands (the page "Helios - State
//! Management: Tenets and Practices"), so no desired state reaches a module and deltas aren't
//! subscribed to. A module removes desired state left in its shadow (from before 0.17.0) with
//! [`ShadowHandle::clear_desired`]: the next update sets that key to `null` in `desired`, until
//! an update carrying it is accepted.

use std::collections::BTreeMap;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use serde_json::{Map, Value, json};
use tokio::sync::{mpsc, watch};
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;

use crate::clock::ClockSamples;
use crate::clock::offset::{Sample, Source};
use crate::mqtt::manager::{Incoming, MqttHandle, MqttStatus};

/// AWS IoT's limit on a shadow document.
pub const MAX_DOCUMENT_BYTES: usize = 8 * 1024;

/// Timing for updates. Tests shorten it.
#[derive(Debug, Clone, Copy)]
pub struct Timing {
    /// The shortest time between two updates of one shadow.
    pub min_interval: Duration,
    /// How long to wait for `accepted` or `rejected` before sending again.
    pub reply_timeout: Duration,
    /// How often to look for work.
    pub tick: Duration,
}

impl Default for Timing {
    fn default() -> Self {
        Self {
            min_interval: Duration::from_secs(1),
            reply_timeout: Duration::from_secs(10),
            tick: Duration::from_millis(100),
        }
    }
}

/// Reports shadow state. Cheap to clone.
#[derive(Debug, Clone)]
pub struct ShadowHandle {
    requests: mpsc::UnboundedSender<Request>,
}

#[derive(Debug)]
enum Request {
    Report {
        shadow: String,
        reported: Map<String, Value>,
    },
    ClearDesired {
        shadow: String,
        path: Path,
    },
}

impl ShadowHandle {
    /// Replaces `shadow`'s reported state with `reported`, a full snapshot. Fields left out are
    /// removed from the shadow.
    pub fn report(&self, shadow: &str, reported: Map<String, Value>) {
        let _ = self.requests.send(Request::Report {
            shadow: shadow.to_owned(),
            reported,
        });
    }

    /// Removes `path` (`["streams"]`) from `shadow`'s desired state: desired state left from
    /// before 0.17.0, which the service would otherwise keep sending in a delta after every
    /// report.
    pub fn clear_desired(&self, shadow: &str, path: &[&str]) {
        let _ = self.requests.send(Request::ClearDesired {
            shadow: shadow.to_owned(),
            path: path.iter().map(|&key| key.to_owned()).collect(),
        });
    }
}

/// Starts the shadow manager.
pub struct ShadowManager;

impl ShadowManager {
    /// Starts the shadow manager on `mqtt`. `incoming` carries the shadow service's replies (the
    /// `$aws/things/…/shadow/…` topics). Ends when `cancel` is cancelled.
    ///
    /// # Panics
    ///
    /// Panics if called outside a tokio runtime.
    #[must_use]
    pub fn start(
        mqtt: MqttHandle,
        incoming: mpsc::Receiver<Incoming>,
        timing: Timing,
        clock: ClockSamples,
        cancel: CancellationToken,
    ) -> (ShadowHandle, JoinHandle<()>) {
        let (requests_tx, requests) = mpsc::unbounded_channel();
        let manager = Manager {
            status: mqtt.status(),
            mqtt,
            incoming,
            requests,
            timing,
            clock,
            cancel,
            shadows: BTreeMap::new(),
        };
        (
            ShadowHandle {
                requests: requests_tx,
            },
            tokio::spawn(manager.run()),
        )
    }
}

/// The parts of a shadow topic: `$aws/things/<thing>/shadow/name/<name>/<operation>/<result>`.
#[derive(Debug, PartialEq, Eq)]
struct ShadowTopic<'a> {
    name: &'a str,
    operation: &'a str,
    result: &'a str,
}

/// Parses a named shadow's reply topic for `thing`.
fn parse_topic<'a>(thing: &str, topic: &'a str) -> Option<ShadowTopic<'a>> {
    let rest = topic
        .strip_prefix("$aws/things/")?
        .strip_prefix(thing)?
        .strip_prefix("/shadow/name/")?;
    let mut parts = rest.split('/');
    let (name, operation, result) = (parts.next()?, parts.next()?, parts.next()?);
    (parts.next().is_none() && !name.is_empty()).then_some(ShadowTopic {
        name,
        operation,
        result,
    })
}

/// An update waiting for `accepted` or `rejected`.
#[derive(Debug)]
struct InFlight {
    token: String,
    sent: Instant,
    /// When it was sent, by the device clock, for clock checks.
    sent_at: SystemTime,
    /// The stale keys it set to `null`; once accepted, they're gone from the shadow.
    nulls: Vec<Path>,
    /// The desired keys it set to `null`.
    desired_nulls: Vec<Path>,
}

#[derive(Debug, Default)]
struct Shadow {
    /// The module's latest snapshot.
    reported: Map<String, Value>,
    /// Keys the service holds that the snapshot no longer has, by path: sent as `null`.
    stale: Vec<Path>,
    /// Desired keys to remove ([`ShadowHandle::clear_desired`]), until an update is accepted.
    clear_desired: Vec<Path>,
    /// Whether the snapshot hasn't been sent since it changed (or since connecting).
    dirty: bool,
    /// The update waiting for a reply.
    in_flight: Option<InFlight>,
    last_sent: Option<Instant>,
}

struct Manager {
    mqtt: MqttHandle,
    status: watch::Receiver<MqttStatus>,
    incoming: mpsc::Receiver<Incoming>,
    requests: mpsc::UnboundedReceiver<Request>,
    timing: Timing,
    clock: ClockSamples,
    cancel: CancellationToken,
    shadows: BTreeMap<String, Shadow>,
}

impl Manager {
    async fn run(mut self) {
        let mut tick = tokio::time::interval(self.timing.tick);
        tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        let mut session = 0;
        let initial = self.status.borrow_and_update().clone();
        if initial.connected {
            session = initial.session;
            self.connected();
        }
        loop {
            tokio::select! {
                () = self.cancel.cancelled() => return,
                changed = self.status.changed() => {
                    if changed.is_err() {
                        return;
                    }
                    let status = self.status.borrow_and_update().clone();
                    if status.connected && status.session != session {
                        session = status.session;
                        self.connected();
                    }
                }
                Some(request) = self.requests.recv() => self.request(request),
                Some(message) = self.incoming.recv() => self.reply(&message),
                _ = tick.tick() => {}
            }
            self.send_due();
        }
    }

    fn thing(&self) -> Option<String> {
        let status = self.status.borrow();
        status.connected.then(|| status.thing.clone()).flatten()
    }

    /// A new session: every snapshot is sent again, and every shadow is read once.
    fn connected(&mut self) {
        let Some(thing) = self.thing() else {
            return;
        };
        for (name, shadow) in &mut self.shadows {
            shadow.dirty = true;
            shadow.in_flight = None;
            self.mqtt
                .publish_now(format!("{}/get", base(&thing, name)), b"{}".to_vec());
        }
    }

    fn request(&mut self, request: Request) {
        match request {
            Request::Report { shadow, reported } => {
                let entry = self.shadows.entry(shadow.clone()).or_default();
                let first = entry.reported.is_empty() && entry.last_sent.is_none();
                // A key reported before and gone now must be removed from the shadow.
                let mut gone = Vec::new();
                missing(&entry.reported, &reported, &mut Vec::new(), &mut gone);
                for path in gone {
                    if !entry.stale.contains(&path) {
                        entry.stale.push(path);
                    }
                }
                entry.stale.retain(|path| still_stale(&reported, path));
                if entry.reported != reported || first {
                    entry.reported = reported;
                    entry.dirty = true;
                }
                if first && let Some(thing) = self.thing() {
                    // Learn what an earlier run left in the shadow.
                    self.mqtt
                        .publish_now(format!("{}/get", base(&thing, &shadow)), b"{}".to_vec());
                }
            }
            Request::ClearDesired { shadow, path } => {
                let entry = self.shadows.entry(shadow).or_default();
                if !entry.clear_desired.contains(&path) {
                    entry.clear_desired.push(path);
                    entry.dirty = true;
                }
            }
        }
    }

    /// A reply from the shadow service.
    fn reply(&mut self, message: &Incoming) {
        let Some(thing) = self.thing() else {
            return;
        };
        let Some(topic) = parse_topic(&thing, &message.topic) else {
            return;
        };
        let Some(shadow) = self.shadows.get_mut(topic.name) else {
            return;
        };
        let document: Value = serde_json::from_slice(&message.payload).unwrap_or(Value::Null);
        let token = document["clientToken"].as_str();
        let ours = shadow
            .in_flight
            .as_ref()
            .is_some_and(|in_flight| token == Some(in_flight.token.as_str()));
        match (topic.operation, topic.result) {
            ("update", "accepted") if ours => {
                if let Some(in_flight) = shadow.in_flight.take() {
                    // Only the keys this update removed: others may have gone stale since.
                    shadow.stale.retain(|path| !in_flight.nulls.contains(path));
                    shadow
                        .clear_desired
                        .retain(|path| !in_flight.desired_nulls.contains(path));
                    if let Some(seconds) = document["timestamp"].as_u64() {
                        self.clock.offer(Sample {
                            source: Source::Shadow,
                            sent: in_flight.sent_at,
                            received: SystemTime::now(),
                            round_trip: in_flight.sent.elapsed(),
                            server: UNIX_EPOCH + Duration::from_secs(seconds),
                        });
                    }
                }
            }
            ("update", "rejected") if ours => {
                shadow.in_flight = None;
                tracing::warn!(
                    shadow = topic.name,
                    code = %document["code"],
                    message = %document["message"],
                    "shadow update rejected"
                );
            }
            ("get", "accepted") => {
                if let Some(reported) = document["state"]["reported"].as_object() {
                    let mut gone = Vec::new();
                    missing(reported, &shadow.reported, &mut Vec::new(), &mut gone);
                    for path in gone {
                        if !shadow.stale.contains(&path) {
                            shadow.stale.push(path);
                            shadow.dirty = true;
                        }
                    }
                }
            }
            // 404 just means the shadow doesn't exist yet.
            ("get", "rejected") if document["code"] != 404 => tracing::warn!(
                shadow = topic.name,
                code = %document["code"],
                message = %document["message"],
                "shadow get rejected"
            ),
            _ => {}
        }
    }

    /// Sends each changed snapshot that's allowed to go now.
    fn send_due(&mut self) {
        let Some(thing) = self.thing() else {
            return;
        };
        let now = Instant::now();
        for (name, shadow) in &mut self.shadows {
            if shadow.in_flight.as_ref().is_some_and(|in_flight| {
                now.duration_since(in_flight.sent) >= self.timing.reply_timeout
            }) {
                tracing::warn!(shadow = %name, "no reply to a shadow update; sending again");
                shadow.in_flight = None;
                shadow.dirty = true;
            }
            let too_soon = shadow
                .last_sent
                .is_some_and(|sent| now.duration_since(sent) < self.timing.min_interval);
            if !shadow.dirty || shadow.in_flight.is_some() || too_soon {
                continue;
            }
            let mut reported = shadow.reported.clone();
            for path in &shadow.stale {
                set_null(&mut reported, path);
            }
            let mut state = json!({"reported": reported});
            if !shadow.clear_desired.is_empty() {
                let mut desired = Map::new();
                for path in &shadow.clear_desired {
                    null_at(&mut desired, path);
                }
                state["desired"] = Value::Object(desired);
            }
            let sent_at = SystemTime::now();
            let token = crate::ulid::new(sent_at);
            let document = json!({"state": state, "clientToken": token});
            let bytes = document.to_string().into_bytes();
            shadow.dirty = false;
            if bytes.len() > MAX_DOCUMENT_BYTES {
                tracing::error!(
                    shadow = %name,
                    bytes = bytes.len(),
                    "shadow update too large for AWS IoT (8 KB); not sent"
                );
                continue;
            }
            tracing::debug!(shadow = %name, bytes = bytes.len(), "shadow update sent");
            tracing::trace!(shadow = %name, document = %document, "shadow update");
            self.mqtt
                .publish_now(format!("{}/update", base(&thing, name)), bytes);
            shadow.in_flight = Some(InFlight {
                token,
                sent: now,
                sent_at,
                nulls: shadow.stale.clone(),
                desired_nulls: shadow.clear_desired.clone(),
            });
            shadow.last_sent = Some(now);
        }
    }
}

/// Reports as module tests see them: (shadow, reported).
#[cfg(test)]
pub(crate) type TestReports = mpsc::UnboundedReceiver<(String, Map<String, Value>)>;

#[cfg(any(test, feature = "module-stream"))]
/// Reports from a detached handle: (shadow, reported).
pub(crate) type DetachedReports = mpsc::UnboundedReceiver<(String, Map<String, Value>)>;

impl ShadowHandle {
    #[cfg(any(test, feature = "module-stream"))]
    /// A handle that isn't connected to a shadow manager: reports arrive as (shadow, reported),
    /// and a `clear_desired(shadow, path)` as (`<shadow>#desired`, `{"clear": path}`). For
    /// components run outside the agent, such as the stream daemon's engine, and for tests.
    ///
    /// # Panics
    ///
    /// Panics if called outside a tokio runtime.
    pub(crate) fn detached() -> (Self, DetachedReports) {
        let (requests, mut incoming) = mpsc::unbounded_channel();
        let (reports_tx, reports) = mpsc::unbounded_channel();
        tokio::spawn(async move {
            while let Some(request) = incoming.recv().await {
                match request {
                    Request::Report { shadow, reported } => {
                        let _ = reports_tx.send((shadow, reported));
                    }
                    // Arrives with the reports, as `<shadow>#desired` with `{"clear": path}`.
                    Request::ClearDesired { shadow, path } => {
                        let mut cleared = Map::new();
                        cleared.insert("clear".into(), json!(path));
                        let _ = reports_tx.send((format!("{shadow}#desired"), cleared));
                    }
                }
            }
        });
        (Self { requests }, reports)
    }

    /// A handle for module tests: [`Self::detached`].
    #[cfg(test)]
    pub(crate) fn for_test() -> (Self, TestReports) {
        Self::detached()
    }
}

/// `$aws/things/<thing>/shadow/name/<name>`.
/// A key in a reported document: top-level first, then each nested object's key.
type Path = Vec<String>;

/// Collects into `gone` the paths of keys in `held` that `now` no longer has, where both hold an
/// object at the parent path. Below a key that went altogether, nothing more is collected: the
/// `null` for it removes everything under it.
fn missing(
    held: &Map<String, Value>,
    now: &Map<String, Value>,
    at: &mut Path,
    gone: &mut Vec<Path>,
) {
    for (key, value) in held {
        at.push(key.clone());
        match (value, now.get(key)) {
            (_, None) => gone.push(at.clone()),
            (Value::Object(held), Some(Value::Object(now))) => missing(held, now, at, gone),
            _ => {}
        }
        at.pop();
    }
}

/// Whether `path` still needs a `null`: its parent is still an object in `reported` (otherwise
/// the parent's own value replaces it) and that object doesn't have the key.
fn still_stale(reported: &Map<String, Value>, path: &[String]) -> bool {
    let Some((key, parents)) = path.split_last() else {
        return false;
    };
    let mut object = reported;
    for parent in parents {
        match object.get(parent) {
            Some(Value::Object(inner)) => object = inner,
            _ => return false,
        }
    }
    !object.contains_key(key)
}

/// Sets `path` to `null` in `reported`, if its parent is an object there.
fn set_null(reported: &mut Map<String, Value>, path: &[String]) {
    let Some((key, parents)) = path.split_last() else {
        return;
    };
    let mut object = reported;
    for parent in parents {
        match object.get_mut(parent) {
            Some(Value::Object(inner)) => object = inner,
            _ => return,
        }
    }
    object.entry(key.clone()).or_insert(Value::Null);
}

/// Sets `path` to `null` in `object`, adding the objects above it.
fn null_at(object: &mut Map<String, Value>, path: &[String]) {
    let Some((key, parents)) = path.split_last() else {
        return;
    };
    let mut object = object;
    for parent in parents {
        let entry = object
            .entry(parent.clone())
            .or_insert_with(|| Value::Object(Map::new()));
        if !entry.is_object() {
            *entry = Value::Object(Map::new());
        }
        let Value::Object(inner) = entry else {
            return;
        };
        object = inner;
    }
    object.insert(key.clone(), Value::Null);
}

fn base(thing: &str, name: &str) -> String {
    format!("$aws/things/{thing}/shadow/name/{name}")
}

#[cfg(test)]
mod tests;
