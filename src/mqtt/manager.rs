//! The MQTT connection manager (LLD 2, section 6): one task that owns the `rumqttc` event loop.
//!
//! It connects only while the identity is ready, with the thing name as client ID, the
//! identity's TLS config (so handshakes use the token-backed key), a clean session and a
//! `lifecycle.offline` Last Will. On each connect it subscribes, publishes `lifecycle.online`
//! and sends what waited in the offline queue. It reconnects with backoff, and on shutdown
//! publishes `lifecycle.offline` itself and disconnects, so the broker doesn't send the Will.
//!
//! Other components use an [`MqttHandle`]: events go out through it, and incoming publishes
//! arrive on the channel given to [`MqttManager::start`].

use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime};

use rumqttc::{
    AsyncClient, ConnectionError, Event, EventLoop, LastWill, MqttOptions, Outgoing, Packet, QoS,
    SubscribeFilter, SubscribeReasonCode, TlsConfiguration, Transport,
};
use serde_json::{Value, json};
use tokio::sync::{mpsc, watch};
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;

use crate::backoff::Backoff;
use crate::identity::manager::{IdentityHandle, IdentityState};
use crate::identity::tls::Alpn;
use crate::mqtt::envelope::Envelope;
use crate::mqtt::queue::OfflineQueue;
use crate::mqtt::{MqttSettings, PORT_443, topics};

/// The client's request channel; publishes beyond it wait in the offline queue.
const CLIENT_CAPACITY: usize = 64;
/// Incoming packets up to AWS IoT's 128 KB payload limit, plus the topic and headers.
const MAX_PACKET: usize = 132 * 1024;

/// Timing for reconnects and shutdown. Tests shorten it.
#[derive(Debug, Clone, Copy)]
pub struct Timing {
    /// First reconnect delay. Doubles on each failure.
    pub initial_backoff: Duration,
    /// Longest reconnect delay.
    pub max_backoff: Duration,
    /// A connection that lasted this long resets the backoff.
    pub stable_after: Duration,
    /// A connection dropped sooner than this counts towards the duplicate client ID warning.
    pub short_session: Duration,
    /// How long shutdown waits for `lifecycle.offline` to be acknowledged.
    pub shutdown_wait: Duration,
    /// Publishes allowed per second (AWS IoT allows 100 per connection, both directions).
    pub publishes_per_second: u32,
}

impl Default for Timing {
    fn default() -> Self {
        Self {
            initial_backoff: Duration::from_secs(1),
            max_backoff: Duration::from_secs(5 * 60),
            stable_after: Duration::from_secs(5 * 60),
            short_session: Duration::from_secs(10),
            shutdown_wait: Duration::from_secs(2),
            publishes_per_second: 50,
        }
    }
}

/// What the manager needs besides the identity.
#[derive(Debug, Clone)]
pub struct Options {
    /// The `[mqtt]` settings.
    pub settings: MqttSettings,
    /// `aws.iot_endpoint` from the local config, used unless the bootstrap service supplies one.
    pub local_endpoint: Option<String>,
    /// The kernel's boot ID (`/proc/sys/kernel/random/boot_id`), reported in `lifecycle.online`.
    pub boot_id: Option<String>,
    /// Reconnect and shutdown timing.
    pub timing: Timing,
}

/// A publish that arrived on a subscribed topic.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Incoming {
    /// The topic.
    pub topic: String,
    /// The payload.
    pub payload: Vec<u8>,
}

/// The connection's state, for logs and the `helios` shadow.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct MqttStatus {
    /// Whether a session is up (connected and subscribed).
    pub connected: bool,
    /// Sessions since start, including the current one.
    pub session: u64,
    /// When the current or last session started.
    pub connected_at: Option<SystemTime>,
    /// Why the last session ended or the last connect failed.
    pub last_disconnect_reason: Option<String>,
    /// Events the offline queue dropped since start.
    pub dropped_events: u64,
    /// The thing name of the current or last session.
    pub thing: Option<String>,
}

/// An event waiting to be published. The envelope is built when it's sent, once the thing name
/// is known.
#[derive(Debug, Clone)]
pub(crate) struct PendingEvent {
    module: String,
    kind: String,
    payload: Value,
    time: SystemTime,
}

/// What [`MqttHandle`] sends the manager.
#[derive(Debug)]
pub(crate) enum Request {
    /// An event, queued while offline.
    Event(PendingEvent),
    /// A publish that only matters while connected, such as a shadow update: dropped otherwise.
    Now { topic: String, payload: Vec<u8> },
}

/// Publishes through the manager. Cheap to clone.
#[derive(Debug, Clone)]
pub struct MqttHandle {
    events: mpsc::UnboundedSender<Request>,
    status: watch::Receiver<MqttStatus>,
}

impl MqttHandle {
    /// Publishes an event of `kind` (`<module>.<name>`) on `helios/<thing>/evt/<module>`, at
    /// QoS 1. While disconnected it waits in the offline queue. Does nothing once the manager has
    /// stopped.
    pub fn publish_event(&self, module: &str, kind: &str, payload: Value) {
        let _ = self.events.send(Request::Event(PendingEvent {
            module: module.to_owned(),
            kind: kind.to_owned(),
            payload,
            time: SystemTime::now(),
        }));
    }

    /// Publishes `payload` on `topic` at QoS 1 if a session is up, and drops it otherwise: for
    /// messages that are stale by the time a connection is back, such as shadow updates (which
    /// are re-sent as snapshots after connecting) and command responses (LLD 2, section 6).
    pub fn publish_now(&self, topic: String, payload: Vec<u8>) {
        let _ = self.events.send(Request::Now { topic, payload });
    }

    /// The connection's state. Await changes with `changed()`.
    #[must_use]
    pub fn status(&self) -> watch::Receiver<MqttStatus> {
        self.status.clone()
    }
}

impl MqttHandle {
    /// For tests of components built on MQTT: a handle whose requests and status the test
    /// controls.
    #[cfg(test)]
    pub(crate) fn for_test() -> (
        Self,
        mpsc::UnboundedReceiver<Request>,
        watch::Sender<MqttStatus>,
    ) {
        let (events, requests) = mpsc::unbounded_channel();
        let (status_tx, status) = watch::channel(MqttStatus::default());
        (Self { events, status }, requests, status_tx)
    }
}

/// Starts the MQTT connection manager.
pub struct MqttManager;

impl MqttManager {
    /// Starts the manager task for `identity`. Incoming publishes go to `incoming`; when it's full,
    /// they're dropped with a warning. The task ends when `cancel` is cancelled, after a clean
    /// disconnect.
    ///
    /// # Panics
    ///
    /// Panics if called outside a tokio runtime.
    #[must_use]
    pub fn start(
        identity: IdentityHandle,
        options: Options,
        incoming: mpsc::Sender<Incoming>,
        cancel: CancellationToken,
    ) -> (MqttHandle, JoinHandle<()>) {
        let (events_tx, events) = mpsc::unbounded_channel();
        let (status_tx, status) = watch::channel(MqttStatus::default());
        let backoff = Backoff::new(options.timing.initial_backoff, options.timing.max_backoff);
        let manager = Manager {
            queue: OfflineQueue::new(options.settings.queue_messages),
            options,
            identity,
            incoming,
            events,
            status: status_tx,
            cancel,
            backoff,
            short_sessions: 0,
        };
        let handle = MqttHandle {
            events: events_tx,
            status,
        };
        (handle, tokio::spawn(manager.run()))
    }
}

/// Where and as whom to connect, from a ready identity.
struct Target {
    thing: String,
    endpoint: String,
}

/// How a session ended.
enum SessionEnd {
    /// Shutdown was requested; the manager stops.
    Cancelled,
    /// The identity stopped being ready.
    IdentityLost,
    /// The connection failed or dropped.
    Failed {
        reason: String,
        connected_for: Option<Duration>,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Phase {
    Connecting,
    Subscribing,
    Ready,
}

struct Manager {
    options: Options,
    identity: IdentityHandle,
    incoming: mpsc::Sender<Incoming>,
    events: mpsc::UnboundedReceiver<Request>,
    status: watch::Sender<MqttStatus>,
    cancel: CancellationToken,
    queue: OfflineQueue<PendingEvent>,
    backoff: Backoff,
    short_sessions: u32,
}

impl Manager {
    async fn run(mut self) {
        loop {
            let Some(target) = self.wait_until_ready().await else {
                return;
            };
            match self.session(&target).await {
                SessionEnd::Cancelled => return,
                SessionEnd::IdentityLost => {
                    self.ended("the device identity isn't ready".to_owned(), None);
                }
                SessionEnd::Failed {
                    reason,
                    connected_for,
                } => {
                    tracing::warn!(%reason, "MQTT connection ended; reconnecting");
                    self.ended(reason, connected_for);
                    let delay = self.backoff.next_delay();
                    if !self.idle(delay).await {
                        return;
                    }
                }
            }
        }
    }

    /// A request while disconnected: events wait in the queue, the rest are dropped.
    fn offline_request(&mut self, request: Request) {
        match request {
            Request::Event(event) => self.queue.push(event),
            Request::Now { .. } => tracing::debug!("MQTT publish dropped: not connected"),
        }
    }

    /// Records the end of a session or a failed connect.
    fn ended(&mut self, reason: String, connected_for: Option<Duration>) {
        let timing = self.options.timing;
        if connected_for.is_some_and(|d| d >= timing.stable_after) {
            self.backoff.reset();
        }
        if connected_for.is_some_and(|d| d < timing.short_session) {
            self.short_sessions += 1;
            if self.short_sessions == 3 {
                tracing::warn!(
                    "disconnected soon after connecting three times in a row: another device may \
                     be using the same thing name, or the IoT policy may not allow this client"
                );
            }
        } else {
            self.short_sessions = 0;
        }
        let dropped = self.queue.dropped();
        self.status.send_modify(|status| {
            status.connected = false;
            status.last_disconnect_reason = Some(reason);
            status.dropped_events = dropped;
        });
    }

    /// Waits until the identity is ready and an endpoint is known, queueing events meanwhile.
    /// `None` if shutdown was requested.
    async fn wait_until_ready(&mut self) -> Option<Target> {
        let mut state = self.identity.watch();
        let mut warned = false;
        loop {
            if let IdentityState::Ready(identity) = &*state.borrow_and_update() {
                let endpoint = identity
                    .device
                    .aws
                    .as_ref()
                    .map(|aws| aws.iot_endpoint.clone())
                    .or_else(|| self.options.local_endpoint.clone());
                match endpoint {
                    Some(endpoint) => {
                        return Some(Target {
                            thing: identity.device.thing_name.clone(),
                            endpoint,
                        });
                    }
                    None if !warned => {
                        tracing::error!(
                            "no AWS IoT endpoint: set aws.iot_endpoint, or have the bootstrap \
                             service supply it"
                        );
                        warned = true;
                    }
                    None => {}
                }
            }
            tokio::select! {
                () = self.cancel.cancelled() => return None,
                changed = state.changed() => if changed.is_err() { return None },
                Some(request) = self.events.recv() => self.offline_request(request),
            }
        }
    }

    /// Waits `delay`, queueing events meanwhile. `false` if shutdown was requested.
    async fn idle(&mut self, delay: Duration) -> bool {
        let sleep = tokio::time::sleep(delay);
        tokio::pin!(sleep);
        loop {
            tokio::select! {
                () = self.cancel.cancelled() => return false,
                () = &mut sleep => return true,
                Some(request) = self.events.recv() => self.offline_request(request),
            }
        }
    }

    fn options_for(&self, target: &Target) -> Result<MqttOptions, String> {
        let settings = &self.options.settings;
        let alpn = if settings.port == PORT_443 {
            Alpn::MqttOver443
        } else {
            Alpn::None
        };
        let tls = self
            .identity
            .tls_config(alpn)
            .map_err(|error| format!("TLS config: {error}"))?;
        let mut options = MqttOptions::new(&target.thing, &target.endpoint, settings.port);
        options
            .set_keep_alive(settings.keep_alive)
            .set_clean_session(true)
            .set_max_packet_size(MAX_PACKET, MAX_PACKET)
            .set_last_will(LastWill::new(
                topics::event(&target.thing, topics::LIFECYCLE),
                self.offline(&target.thing, "connection_lost").to_bytes(),
                QoS::AtLeastOnce,
                false,
            ))
            .set_transport(Transport::tls_with_config(TlsConfiguration::Rustls(
                Arc::clone(&tls),
            )));
        Ok(options)
    }

    /// One connection, from CONNECT until it ends.
    async fn session(&mut self, target: &Target) -> SessionEnd {
        let options = match self.options_for(target) {
            Ok(options) => options,
            Err(reason) => {
                return SessionEnd::Failed {
                    reason,
                    connected_for: None,
                };
            }
        };
        let (client, mut eventloop) = AsyncClient::new(options, CLIENT_CAPACITY);
        let mut identity = self.identity.watch();
        let mut phase = Phase::Connecting;
        let mut connected: Option<Instant> = None;
        let mut rate = RateLimit::new(self.options.timing.publishes_per_second);
        let mut flush = tokio::time::interval(Duration::from_millis(100));
        flush.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        loop {
            tokio::select! {
                biased;
                () = self.cancel.cancelled() => {
                    if phase == Phase::Ready {
                        self.shut_down(target, &client, &mut eventloop).await;
                    }
                    return SessionEnd::Cancelled;
                }
                changed = identity.changed() => {
                    let ready = changed.is_ok()
                        && matches!(&*identity.borrow_and_update(), IdentityState::Ready(_));
                    if !ready {
                        let _ = client.try_disconnect();
                        return SessionEnd::IdentityLost;
                    }
                }
                Some(request) = self.events.recv() => match request {
                    Request::Event(event) => self.queue.push(event),
                    Request::Now { topic, payload } => {
                        let sent = phase == Phase::Ready
                            && rate.take()
                            && client.try_publish(topic, QoS::AtLeastOnce, false, payload).is_ok();
                        if !sent {
                            tracing::debug!("MQTT publish dropped: not connected, or too many");
                        }
                    }
                },
                polled = eventloop.poll() => match polled {
                    Ok(Event::Incoming(Packet::ConnAck(_))) => {
                        connected = Some(Instant::now());
                        phase = Phase::Subscribing;
                        let filters = topics::session_filters(&target.thing)
                            .into_iter()
                            .map(|path| SubscribeFilter::new(path, QoS::AtLeastOnce));
                        if let Err(error) = client.try_subscribe_many(filters) {
                            return failed(format!("subscribe: {error}"), connected);
                        }
                    }
                    Ok(Event::Incoming(Packet::SubAck(ack))) if phase == Phase::Subscribing => {
                        let filters = topics::session_filters(&target.thing);
                        for (filter, code) in filters.iter().zip(&ack.return_codes) {
                            if matches!(code, SubscribeReasonCode::Failure) {
                                tracing::warn!(
                                    %filter,
                                    "subscription refused: check the device IoT policy"
                                );
                            }
                        }
                        phase = Phase::Ready;
                        self.online(target, &client);
                    }
                    Ok(Event::Incoming(Packet::Publish(publish))) => {
                        let message = Incoming {
                            topic: publish.topic,
                            payload: publish.payload.to_vec(),
                        };
                        if self.incoming.try_send(message).is_err() {
                            tracing::warn!("incoming MQTT message dropped: the receiver is behind");
                        }
                    }
                    Ok(_) => {}
                    Err(error) => {
                        return failed(classify(&error, connected.map(|c| c.elapsed())), connected);
                    }
                },
                _ = flush.tick(), if phase == Phase::Ready && !self.queue.is_empty() => {}
            }
            if phase == Phase::Ready {
                self.send_queued(target, &client, &mut rate);
            }
        }
    }

    /// Starts a session: `lifecycle.online`, then the queue.
    fn online(&mut self, target: &Target, client: &AsyncClient) {
        let now = SystemTime::now();
        let previous = self.status.borrow().clone();
        let session = previous.session + 1;
        let since_last = previous
            .connected_at
            .and_then(|at| now.duration_since(at).ok())
            .map(|d| d.as_secs());
        let dropped = self.queue.dropped();
        let payload = json!({
            "helios_version": env!("CARGO_PKG_VERSION"),
            "boot_id": self.options.boot_id,
            "session": session,
            "since_last_connect_s": since_last,
            "last_disconnect_reason": previous.last_disconnect_reason,
            "dropped_events": dropped,
        });
        let envelope = Envelope::event(
            &target.thing,
            topics::LIFECYCLE,
            "lifecycle.online",
            payload,
            now,
        );
        if let Err(error) = client.try_publish(
            topics::event(&target.thing, topics::LIFECYCLE),
            QoS::AtLeastOnce,
            false,
            envelope.to_bytes(),
        ) {
            tracing::warn!(%error, "couldn't publish lifecycle.online");
        }
        tracing::info!(session, endpoint = %target.endpoint, thing = %target.thing, "MQTT connected");
        self.status.send_modify(|status| {
            status.connected = true;
            status.session = session;
            status.connected_at = Some(now);
            status.dropped_events = dropped;
            status.thing = Some(target.thing.clone());
        });
    }

    /// Sends queued events, as fast as the rate limit and the client's channel allow.
    fn send_queued(&mut self, target: &Target, client: &AsyncClient, rate: &mut RateLimit) {
        while !self.queue.is_empty() && rate.take() {
            let Some(event) = self.queue.pop() else {
                break;
            };
            let envelope = Envelope::event(
                &target.thing,
                &event.module,
                &event.kind,
                event.payload.clone(),
                event.time,
            );
            let topic = topics::event(&target.thing, &event.module);
            if client
                .try_publish(topic, QoS::AtLeastOnce, false, envelope.to_bytes())
                .is_err()
            {
                // The client's channel is full: try again on the next tick.
                self.queue.push_front(event);
                break;
            }
        }
    }

    fn offline(&self, thing: &str, reason: &str) -> Envelope {
        Envelope::event(
            thing,
            topics::LIFECYCLE,
            "lifecycle.offline",
            json!({ "reason": reason }),
            SystemTime::now(),
        )
    }

    /// Publishes `lifecycle.offline` and disconnects cleanly, so the broker doesn't send the Will.
    async fn shut_down(&self, target: &Target, client: &AsyncClient, eventloop: &mut EventLoop) {
        let wait = self.options.timing.shutdown_wait;
        let published = client.try_publish(
            topics::event(&target.thing, topics::LIFECYCLE),
            QoS::AtLeastOnce,
            false,
            self.offline(&target.thing, "shutdown").to_bytes(),
        );
        if published.is_ok() {
            let acked = tokio::time::timeout(wait, async {
                let mut ours = None;
                loop {
                    match eventloop.poll().await {
                        Ok(Event::Outgoing(Outgoing::Publish(pkid))) if ours.is_none() => {
                            ours = Some(pkid);
                        }
                        Ok(Event::Incoming(Packet::PubAck(ack))) if Some(ack.pkid) == ours => {
                            return;
                        }
                        Ok(_) => {}
                        Err(_) => return,
                    }
                }
            })
            .await;
            if acked.is_err() {
                tracing::warn!("lifecycle.offline wasn't acknowledged before shutdown");
            }
        }
        if client.try_disconnect().is_ok() {
            let _ = tokio::time::timeout(wait, async {
                loop {
                    match eventloop.poll().await {
                        Ok(Event::Outgoing(Outgoing::Disconnect)) | Err(_) => return,
                        Ok(_) => {}
                    }
                }
            })
            .await;
        }
        tracing::info!("MQTT disconnected");
    }
}

fn failed(reason: String, connected: Option<Instant>) -> SessionEnd {
    SessionEnd::Failed {
        reason,
        connected_for: connected.map(|c| c.elapsed()),
    }
}

/// A reason for the log and the `helios` shadow (LLD 2, section 6).
fn classify(error: &ConnectionError, connected_for: Option<Duration>) -> String {
    match error {
        ConnectionError::Tls(error) => {
            format!("TLS: {error} (check the certificate and the clock)")
        }
        ConnectionError::ConnectionRefused(code) => format!("connection refused: {code:?}"),
        ConnectionError::NetworkTimeout => "network timeout".to_owned(),
        _ if connected_for.is_some_and(|d| d < Duration::from_secs(5)) => format!(
            "closed right after connecting (check the device IoT policy and thing name): {error}"
        ),
        _ => format!("network: {error}"),
    }
}

/// A token bucket: `per_second` publishes a second, with bursts of up to that many.
struct RateLimit {
    tokens: f64,
    capacity: f64,
    per_second: f64,
    last: Instant,
}

impl RateLimit {
    fn new(per_second: u32) -> Self {
        let rate = f64::from(per_second.max(1));
        Self {
            tokens: rate,
            capacity: rate,
            per_second: rate,
            last: Instant::now(),
        }
    }

    /// Takes a token if one is available.
    fn take(&mut self) -> bool {
        let now = Instant::now();
        let elapsed = now.duration_since(self.last).as_secs_f64();
        self.last = now;
        self.tokens = (self.tokens + elapsed * self.per_second).min(self.capacity);
        if self.tokens >= 1.0 {
            self.tokens -= 1.0;
            true
        } else {
            false
        }
    }
}

#[cfg(test)]
mod tests;
