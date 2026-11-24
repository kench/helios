//! Connection manager tests against a fake MQTT broker over mutual TLS, which accepts only the
//! token-backed device certificate, as AWS IoT Core does (LLD 2, sections 6 and 10).

use std::sync::Mutex;

use bytes::BytesMut;
use rcgen::{CertificateParams, KeyPair};
use rumqttc::mqttbytes::v4::{ConnAck, Connect, PubAck, Publish, SubAck};
use rumqttc::{ConnectReturnCode, Packet};
use rustls::server::WebPkiClientVerifier;
use rustls::{RootCertStore, ServerConfig};
use rustls_pki_types::PrivateKeyDer;
use serde_json::Value;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio_rustls::TlsAcceptor;

use super::*;
use crate::identity::testing::{THING_NAME, ca, ready_identity};
use crate::identity::tls::{crypto_provider, root_store_from_pem};

const WAIT: Duration = Duration::from_secs(10);

/// What the broker saw, and how it should behave.
#[derive(Default)]
struct BrokerState {
    connects: Vec<Connect>,
    subscribes: Vec<Vec<String>>,
    publishes: Vec<(String, Value)>,
    disconnects: u32,
    /// Refuse every subscription (return code 0x80).
    refuse_subscriptions: bool,
    /// Close the connection after acknowledging the next `lifecycle.online`.
    drop_after_online: bool,
    /// Don't acknowledge publishes.
    no_pubacks: bool,
    /// Sends packets to the connected client.
    client: Option<mpsc::UnboundedSender<Packet>>,
}

struct Broker {
    port: u16,
    roots: RootCertStore,
    state: Arc<Mutex<BrokerState>>,
}

impl Broker {
    /// A broker on localhost that requires a client certificate from `device_ca`.
    async fn start(device_ca: &crate::identity::testing::Ca) -> Self {
        let server_ca = ca("Helios test broker CA");
        let key = KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).unwrap();
        let cert = CertificateParams::new(vec!["localhost".to_owned()])
            .unwrap()
            .signed_by(&key, &server_ca.issuer)
            .unwrap();
        let verifier = WebPkiClientVerifier::builder_with_provider(
            Arc::new(root_store_from_pem(device_ca.pem.as_bytes()).unwrap()),
            crypto_provider(),
        )
        .build()
        .unwrap();
        let config = ServerConfig::builder_with_provider(crypto_provider())
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_client_cert_verifier(verifier)
            .with_single_cert(
                vec![cert.der().clone()],
                PrivateKeyDer::try_from(key.serialize_der()).unwrap(),
            )
            .unwrap();
        let acceptor = TlsAcceptor::from(Arc::new(config));
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let state = Arc::new(Mutex::new(BrokerState::default()));
        let shared = state.clone();
        tokio::spawn(async move {
            while let Ok((tcp, _)) = listener.accept().await {
                let acceptor = acceptor.clone();
                let state = shared.clone();
                tokio::spawn(async move {
                    if let Ok(tls) = acceptor.accept(tcp).await {
                        serve(tls, state).await;
                    }
                });
            }
        });
        Self {
            port,
            roots: root_store_from_pem(server_ca.pem.as_bytes()).unwrap(),
            state,
        }
    }

    fn state(&self) -> std::sync::MutexGuard<'_, BrokerState> {
        self.state.lock().unwrap()
    }

    /// The publishes seen so far, as (topic, envelope type).
    fn published_types(&self) -> Vec<(String, String)> {
        self.state()
            .publishes
            .iter()
            .map(|(topic, json)| {
                (
                    topic.clone(),
                    json["type"].as_str().unwrap_or("").to_owned(),
                )
            })
            .collect()
    }

    /// Waits until `check` holds for the broker's state.
    async fn until(&self, what: &str, check: impl Fn(&BrokerState) -> bool) {
        let deadline = Instant::now() + WAIT;
        while !check(&self.state()) {
            if Instant::now() >= deadline {
                let state = self.state();
                panic!(
                    "timed out waiting until {what}: {} connects, subscribes {:?}, publishes {:?}",
                    state.connects.len(),
                    state.subscribes,
                    state
                        .publishes
                        .iter()
                        .map(|(t, j)| (t.clone(), j["type"].clone()))
                        .collect::<Vec<_>>()
                );
            }
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    }
}

/// One client connection: read packets, answer them, and forward packets from the test.
async fn serve(
    mut tls: tokio_rustls::server::TlsStream<tokio::net::TcpStream>,
    state: Arc<Mutex<BrokerState>>,
) {
    let (to_client, mut outgoing) = mpsc::unbounded_channel();
    state.lock().unwrap().client = Some(to_client);
    let mut buffer = BytesMut::new();
    let mut chunk = vec![0u8; 4096];
    loop {
        // Answer every complete packet in the buffer.
        loop {
            let packet = match Packet::read(&mut buffer, MAX_PACKET) {
                Ok(packet) => packet,
                Err(rumqttc::mqttbytes::Error::InsufficientBytes(_)) => break,
                Err(_) => return,
            };
            let mut replies = Vec::new();
            let mut close = false;
            {
                let mut state = state.lock().unwrap();
                match packet {
                    Packet::Connect(connect) => {
                        state.connects.push(connect);
                        replies.push(Packet::ConnAck(ConnAck::new(
                            ConnectReturnCode::Success,
                            false,
                        )));
                    }
                    Packet::Subscribe(subscribe) => {
                        let code = if state.refuse_subscriptions {
                            SubscribeReasonCode::Failure
                        } else {
                            SubscribeReasonCode::Success(QoS::AtLeastOnce)
                        };
                        state
                            .subscribes
                            .push(subscribe.filters.iter().map(|f| f.path.clone()).collect());
                        replies.push(Packet::SubAck(SubAck::new(
                            subscribe.pkid,
                            vec![code; subscribe.filters.len()],
                        )));
                    }
                    Packet::Publish(publish) => {
                        let json: Value =
                            serde_json::from_slice(&publish.payload).unwrap_or(Value::Null);
                        if json["type"] == "lifecycle.online" {
                            close = std::mem::take(&mut state.drop_after_online);
                        }
                        state.publishes.push((publish.topic.clone(), json));
                        if publish.qos == QoS::AtLeastOnce && !state.no_pubacks {
                            replies.push(Packet::PubAck(PubAck::new(publish.pkid)));
                        }
                    }
                    Packet::PingReq => replies.push(Packet::PingResp),
                    Packet::Disconnect => state.disconnects += 1,
                    _ => {}
                }
            }
            for reply in replies {
                let mut out = BytesMut::new();
                reply.write(&mut out, MAX_PACKET).unwrap();
                if tls.write_all(&out).await.is_err() {
                    return;
                }
            }
            if close {
                let _ = tls.shutdown().await;
                return;
            }
        }
        tokio::select! {
            read = tls.read(&mut chunk) => match read {
                Ok(0) | Err(_) => return,
                Ok(n) => buffer.extend_from_slice(&chunk[..n]),
            },
            Some(packet) = outgoing.recv() => {
                let mut out = BytesMut::new();
                packet.write(&mut out, MAX_PACKET).unwrap();
                if tls.write_all(&out).await.is_err() {
                    return;
                }
            }
        }
    }
}

fn timing() -> Timing {
    Timing {
        initial_backoff: Duration::from_millis(10),
        max_backoff: Duration::from_millis(50),
        shutdown_wait: Duration::from_millis(500),
        ..Timing::default()
    }
}

fn options(port: u16) -> Options {
    Options {
        settings: MqttSettings {
            port,
            ..MqttSettings::default()
        },
        local_endpoint: Some("localhost".to_owned()),
        boot_id: Some("boot-1".to_owned()),
        timing: timing(),
        commands: Arc::new(crate::router::topics::TopicsTransport),
    }
}

struct Running {
    broker: Broker,
    handle: MqttHandle,
    task: JoinHandle<()>,
    incoming: mpsc::Receiver<Incoming>,
    cancel: CancellationToken,
    identity_cancel: CancellationToken,
}

impl Drop for Running {
    fn drop(&mut self) {
        self.cancel.cancel();
        self.identity_cancel.cancel();
    }
}

/// A broker and a manager for a ready mock-token identity; `before` runs before the manager
/// starts, for queueing or broker setup.
async fn start_with(adjust: impl FnOnce(&mut Options), before: impl FnOnce(&Broker)) -> Running {
    let device_ca = ca("Helios test device CA");
    let broker = Broker::start(&device_ca).await;
    before(&broker);
    let (identity, _token, identity_cancel) =
        ready_identity(&device_ca, broker.roots.clone()).await;
    let mut options = options(broker.port);
    adjust(&mut options);
    let (incoming_tx, incoming) = mpsc::channel(8);
    let cancel = CancellationToken::new();
    let (handle, task) = MqttManager::start(identity, options, incoming_tx, cancel.clone());
    Running {
        broker,
        handle,
        task,
        incoming,
        cancel,
        identity_cancel,
    }
}

async fn start() -> Running {
    start_with(|_| {}, |_| {}).await
}

fn lifecycle_topic() -> String {
    format!("helios/{THING_NAME}/evt/lifecycle")
}

#[tokio::test]
async fn connects_as_the_thing_with_a_will_and_a_clean_session() {
    let running = start().await;
    let broker = &running.broker;

    broker
        .until("lifecycle.online", |s| !s.publishes.is_empty())
        .await;

    let state = broker.state();
    let connect = &state.connects[0];
    assert_eq!(connect.client_id, THING_NAME);
    assert!(connect.clean_session);
    assert_eq!(connect.keep_alive, 60);
    let will = connect.last_will.as_ref().unwrap();
    assert_eq!(will.topic, lifecycle_topic());
    assert_eq!(will.qos, QoS::AtLeastOnce);
    assert!(!will.retain);
    let will: Value = serde_json::from_slice(&will.message).unwrap();
    assert_eq!(will["type"], "lifecycle.offline");
    assert_eq!(will["payload"]["reason"], "connection_lost");
    let mut filters = topics::shadow_filters(THING_NAME);
    filters.push(format!("helios/{THING_NAME}/cmd/+"));
    assert_eq!(state.subscribes, vec![filters]);
    let (topic, online) = &state.publishes[0];
    assert_eq!(topic, &lifecycle_topic());
    assert_eq!(online["type"], "lifecycle.online");
    assert_eq!(online["thing"], THING_NAME);
    assert_eq!(online["payload"]["session"], 1);
    assert_eq!(online["payload"]["boot_id"], "boot-1");
    assert_eq!(online["payload"]["dropped_events"], 0);
    assert_eq!(
        online["payload"]["helios_version"],
        env!("CARGO_PKG_VERSION")
    );
}

#[tokio::test]
async fn subscribes_in_batches_of_eight_and_goes_online_after_the_last() {
    let running = start_with(
        |options| options.commands = crate::mqtt::CommandTransports::default().transport(),
        |_| {},
    )
    .await;
    let broker = &running.broker;
    broker
        .until("lifecycle.online", |s| !s.publishes.is_empty())
        .await;
    let state = broker.state();
    let mut filters = topics::shadow_filters(THING_NAME);
    filters.push(format!("helios/{THING_NAME}/cmd/+"));
    let base = format!("$aws/commands/things/{THING_NAME}/executions/+");
    filters.push(format!("{base}/request/json"));
    filters.push(format!("{base}/response/accepted/json"));
    filters.push(format!("{base}/response/rejected/json"));
    // Five shadow filters, the custom topic and three for AWS IoT commands: nine, so two.
    assert_eq!(filters.len(), 9);
    assert_eq!(
        state.subscribes,
        vec![filters[..8].to_vec(), filters[8..].to_vec()]
    );
    assert_eq!(state.publishes[0].1["type"], "lifecycle.online");
}

#[tokio::test]
async fn reports_the_connection_in_its_status() {
    let running = start().await;
    let mut status = running.handle.status();

    let status = tokio::time::timeout(WAIT, status.wait_for(|s| s.connected))
        .await
        .unwrap()
        .unwrap()
        .clone();

    assert_eq!(status.session, 1);
    assert!(status.connected_at.is_some());
    assert_eq!(status.last_disconnect_reason, None);
}

#[tokio::test]
async fn sends_events_queued_before_connecting_after_lifecycle_online() {
    let device_ca = ca("Helios test device CA");
    let broker = Broker::start(&device_ca).await;
    let (identity, _token, identity_cancel) =
        ready_identity(&device_ca, broker.roots.clone()).await;
    let (incoming_tx, _incoming) = mpsc::channel(8);
    let cancel = CancellationToken::new();
    let (handle, _task) =
        MqttManager::start(identity, options(broker.port), incoming_tx, cancel.clone());

    handle.publish_event("usb", "usb.attached", json!({"port": 1}));
    handle.publish_event("net", "net.changed", json!({}));
    broker
        .until("three publishes", |s| s.publishes.len() >= 3)
        .await;

    assert_eq!(
        broker.published_types(),
        vec![
            (lifecycle_topic(), "lifecycle.online".to_owned()),
            (
                format!("helios/{THING_NAME}/evt/usb"),
                "usb.attached".to_owned()
            ),
            (
                format!("helios/{THING_NAME}/evt/net"),
                "net.changed".to_owned()
            ),
        ]
    );
    let usb = &broker.state().publishes[1].1;
    assert_eq!(usb["payload"]["port"], 1);
    assert_eq!(usb["thing"], THING_NAME);
    assert_eq!(usb["v"], 1);
    cancel.cancel();
    identity_cancel.cancel();
}

#[tokio::test]
async fn publishes_events_while_connected() {
    let running = start().await;
    let mut status = running.handle.status();
    tokio::time::timeout(WAIT, status.wait_for(|s| s.connected))
        .await
        .unwrap()
        .unwrap();

    running
        .handle
        .publish_event("usb", "usb.detached", json!({"port": 2}));
    running
        .broker
        .until("usb.detached", |s| s.publishes.len() >= 2)
        .await;

    assert_eq!(running.broker.published_types()[1].1, "usb.detached");
}

#[tokio::test]
async fn waits_without_an_endpoint() {
    let device_ca = ca("Helios test device CA");
    let broker = Broker::start(&device_ca).await;
    let (identity, _token, identity_cancel) =
        ready_identity(&device_ca, broker.roots.clone()).await;
    let mut options = options(broker.port);
    // Neither the local config nor the bootstrap service gave an endpoint.
    options.local_endpoint = None;
    let (incoming_tx, _incoming) = mpsc::channel(8);
    let cancel = CancellationToken::new();
    let (handle, task) = MqttManager::start(identity, options, incoming_tx, cancel.clone());
    handle.publish_event("usb", "usb.attached", json!({}));
    tokio::time::sleep(Duration::from_millis(100)).await;

    // It never connects, and stops cleanly when asked.
    assert!(broker.state().connects.is_empty());
    assert!(!handle.status().borrow().connected);
    cancel.cancel();
    tokio::time::timeout(WAIT, task).await.unwrap().unwrap();
    identity_cancel.cancel();
}

#[tokio::test]
async fn reports_dropped_events_in_lifecycle_online() {
    let device_ca = ca("Helios test device CA");
    let broker = Broker::start(&device_ca).await;
    let (identity, _token, identity_cancel) =
        ready_identity(&device_ca, broker.roots.clone()).await;
    let mut options = options(broker.port);
    options.settings.queue_messages = 2;
    let (incoming_tx, _incoming) = mpsc::channel(8);
    let cancel = CancellationToken::new();
    let (handle, _task) = MqttManager::start(identity, options, incoming_tx, cancel.clone());
    // These are queued before the first connect completes; three don't fit.
    for n in 0..5 {
        handle.publish_event("usb", "usb.attached", json!({"n": n}));
    }

    broker
        .until("lifecycle.online and the two kept events", |s| {
            s.publishes.len() >= 3
        })
        .await;

    let state = broker.state();
    let online = &state.publishes[0].1;
    assert_eq!(online["type"], "lifecycle.online");
    assert_eq!(online["payload"]["dropped_events"], 3);
    // The newest two were kept.
    assert_eq!(state.publishes[1].1["payload"]["n"], 3);
    assert_eq!(state.publishes[2].1["payload"]["n"], 4);
    drop(state);
    assert_eq!(handle.status().borrow().dropped_events, 3);
    cancel.cancel();
    identity_cancel.cancel();
}

#[tokio::test]
async fn reconnects_after_the_connection_drops() {
    let running = start_with(|_| {}, |broker| broker.state().drop_after_online = true).await;

    running
        .broker
        .until("a second lifecycle.online", |s| {
            s.publishes
                .iter()
                .filter(|(_, json)| json["type"] == "lifecycle.online")
                .count()
                >= 2
        })
        .await;
    let mut status = running.handle.status();
    let status = tokio::time::timeout(WAIT, status.wait_for(|s| s.connected && s.session == 2))
        .await
        .unwrap()
        .unwrap()
        .clone();

    assert!(status.last_disconnect_reason.is_some());
    let second = running.broker.state().publishes.last().unwrap().1.clone();
    assert_eq!(second["payload"]["session"], 2);
    assert!(second["payload"]["last_disconnect_reason"].is_string());
    assert!(second["payload"]["since_last_connect_s"].is_u64());
    assert_eq!(running.broker.state().connects.len(), 2);
}

#[tokio::test]
async fn shuts_down_with_lifecycle_offline_and_a_disconnect() {
    let mut running = start().await;
    let mut status = running.handle.status();
    tokio::time::timeout(WAIT, status.wait_for(|s| s.connected))
        .await
        .unwrap()
        .unwrap();

    running.cancel.cancel();
    tokio::time::timeout(WAIT, &mut running.task)
        .await
        .unwrap()
        .unwrap();
    running
        .broker
        .until("DISCONNECT", |s| s.disconnects == 1)
        .await;

    let types = running.broker.published_types();
    let (topic, kind) = types.last().unwrap();
    assert_eq!(topic, &lifecycle_topic());
    assert_eq!(kind, "lifecycle.offline");
    let offline = running.broker.state().publishes.last().unwrap().1.clone();
    assert_eq!(offline["payload"]["reason"], "shutdown");
}

#[tokio::test]
async fn shutdown_gives_up_waiting_for_an_unacknowledged_offline() {
    let mut running = start_with(|_| {}, |broker| broker.state().no_pubacks = true).await;
    let mut status = running.handle.status();
    tokio::time::timeout(WAIT, status.wait_for(|s| s.connected))
        .await
        .unwrap()
        .unwrap();

    running.cancel.cancel();

    tokio::time::timeout(WAIT, &mut running.task)
        .await
        .unwrap()
        .unwrap();
}

#[tokio::test]
async fn passes_incoming_publishes_on() {
    let mut running = start().await;
    let mut status = running.handle.status();
    tokio::time::timeout(WAIT, status.wait_for(|s| s.connected))
        .await
        .unwrap()
        .unwrap();
    let topic = format!("helios/{THING_NAME}/cmd/video");

    let client = running.broker.state().client.clone().unwrap();
    client
        .send(Packet::Publish(Publish::new(
            &topic,
            QoS::AtMostOnce,
            b"{}".to_vec(),
        )))
        .unwrap();
    let message = tokio::time::timeout(WAIT, running.incoming.recv())
        .await
        .unwrap()
        .unwrap();

    assert_eq!(message.topic, topic);
    assert_eq!(message.payload, b"{}");
}

#[tokio::test]
async fn a_refused_subscription_still_starts_the_session() {
    let running = start_with(|_| {}, |broker| broker.state().refuse_subscriptions = true).await;

    running
        .broker
        .until("lifecycle.online", |s| !s.publishes.is_empty())
        .await;

    assert_eq!(running.broker.published_types()[0].1, "lifecycle.online");
}

#[tokio::test]
async fn an_untrusted_broker_is_a_tls_failure() {
    let device_ca = ca("Helios test device CA");
    let broker = Broker::start(&device_ca).await;
    // The identity trusts a different CA from the broker's.
    let other = root_store_from_pem(ca("Someone else").pem.as_bytes()).unwrap();
    let (identity, _token, identity_cancel) = ready_identity(&device_ca, other).await;
    let (incoming_tx, _incoming) = mpsc::channel(8);
    let cancel = CancellationToken::new();
    let (handle, _task) =
        MqttManager::start(identity, options(broker.port), incoming_tx, cancel.clone());
    let mut status = handle.status();

    let status = tokio::time::timeout(
        WAIT,
        status.wait_for(|s| s.last_disconnect_reason.is_some()),
    )
    .await
    .unwrap()
    .unwrap()
    .clone();

    let reason = status.last_disconnect_reason.unwrap();
    assert!(reason.starts_with("TLS"), "{reason}");
    assert!(broker.state().connects.is_empty());
    cancel.cancel();
    identity_cancel.cancel();
}

#[test]
fn classifies_failures() {
    let refused = ConnectionError::ConnectionRefused(ConnectReturnCode::NotAuthorized);
    assert!(classify(&refused, None).starts_with("connection refused"));
    assert_eq!(
        classify(&ConnectionError::NetworkTimeout, None),
        "network timeout"
    );
    let io = || ConnectionError::Io(std::io::Error::other("reset"));
    assert!(classify(&io(), Some(Duration::from_secs(1))).starts_with("closed right after"));
    assert!(classify(&io(), Some(Duration::from_secs(60))).starts_with("network"));
    assert!(classify(&io(), None).starts_with("network"));
}

#[test]
fn rate_limit_allows_a_burst_then_refills() {
    let mut rate = RateLimit::new(3);

    assert!((0..3).all(|_| rate.take()));
    assert!(!rate.take());
    rate.last -= Duration::from_secs(1);
    assert!(rate.take());
}

#[tokio::test]
async fn publishes_now_only_while_connected() {
    let device_ca = ca("Helios test device CA");
    let broker = Broker::start(&device_ca).await;
    let (identity, _token, identity_cancel) =
        ready_identity(&device_ca, broker.roots.clone()).await;
    let (incoming_tx, _incoming) = mpsc::channel(8);
    let cancel = CancellationToken::new();
    let (handle, _task) =
        MqttManager::start(identity, options(broker.port), incoming_tx, cancel.clone());
    // Sent before the session is up: dropped, not queued.
    handle.publish_now("early/topic".to_owned(), b"{\"type\":\"early\"}".to_vec());
    let mut status = handle.status();
    tokio::time::timeout(WAIT, status.wait_for(|s| s.connected))
        .await
        .unwrap()
        .unwrap();
    let shadow = format!("$aws/things/{THING_NAME}/shadow/name/helios/update");

    handle.publish_now(shadow.clone(), b"{\"type\":\"now\"}".to_vec());
    broker
        .until("the shadow update", |s| s.publishes.len() >= 2)
        .await;

    assert_eq!(
        broker.published_types(),
        vec![
            (lifecycle_topic(), "lifecycle.online".to_owned()),
            (shadow, "now".to_owned()),
        ]
    );
    assert_eq!(status.borrow().thing.as_deref(), Some(THING_NAME));
    cancel.cancel();
    identity_cancel.cancel();
}

/// Whether the fake local address exists, for `reconnects_when_its_local_address_goes_away`.
static LOCAL_ADDRESS_GONE: std::sync::atomic::AtomicBool =
    std::sync::atomic::AtomicBool::new(false);

#[tokio::test]
async fn reconnects_when_its_local_address_goes_away() {
    let running = start_with(
        |options| {
            options.timing.address_watch = AddressWatch {
                interval: Duration::from_millis(20),
                // The real lookup finds the test's connection to the broker on localhost.
                find: crate::mqtt::local_address::connection_local,
                exists: |_| !LOCAL_ADDRESS_GONE.load(std::sync::atomic::Ordering::SeqCst),
            };
        },
        |_| {},
    )
    .await;
    let mut status = running.handle.status();
    tokio::time::timeout(WAIT, status.wait_for(|s| s.connected && s.session == 1))
        .await
        .unwrap()
        .unwrap();
    // Let the watch find the connection first.
    tokio::time::sleep(Duration::from_millis(200)).await;

    // The uplink carrying the connection goes away (the socket itself stays up).
    LOCAL_ADDRESS_GONE.store(true, std::sync::atomic::Ordering::SeqCst);
    let ended = tokio::time::timeout(WAIT, status.wait_for(|s| !s.connected))
        .await
        .unwrap()
        .unwrap()
        .clone();
    assert_eq!(
        ended.last_disconnect_reason.as_deref(),
        Some("the connection's local address went away")
    );
    LOCAL_ADDRESS_GONE.store(false, std::sync::atomic::Ordering::SeqCst);
    tokio::time::timeout(WAIT, status.wait_for(|s| s.connected && s.session == 2))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(running.broker.state().connects.len(), 2);
}
