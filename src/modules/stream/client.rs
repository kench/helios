//! Helios's `stream` module (LLD 4, section 15): a client of the stream daemon
//! (`helios-stream.service`). It forwards commands and the shadow's desired state to the daemon
//! over its control socket, and the daemon's events and shadow to MQTT. Streams themselves run
//! in the daemon, so they keep going while Helios restarts.

use std::collections::BTreeMap;
use std::path::PathBuf;
use std::time::Duration;

use serde_json::{Map, Value, json};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::UnixStream;

use super::MODULE;
use super::control::{self, Message};
use crate::backoff::Backoff;
use crate::modules::{Module, ModuleContext, ModuleError, ModuleFuture};
use crate::router::{Outcome, PendingCommand, codes};

/// How long to wait for the daemon's answer to `hello`.
const HELLO_TIMEOUT: Duration = Duration::from_secs(10);

/// The `stream` module in Helios.
pub struct StreamClient {
    socket: PathBuf,
}

impl StreamClient {
    /// A client of the daemon listening on `socket`.
    #[must_use]
    pub fn new(socket: PathBuf) -> Self {
        Self { socket }
    }
}

impl Module for StreamClient {
    fn name(&self) -> &'static str {
        MODULE
    }

    fn run(&self, ctx: ModuleContext) -> ModuleFuture<'_> {
        Box::pin(run(self.socket.clone(), ctx))
    }
}

/// What a connection ended with.
enum Ended {
    Cancelled,
    Lost(String),
}

async fn run(socket: PathBuf, mut ctx: ModuleContext) -> Result<(), ModuleError> {
    let mut backoff = Backoff::new(Duration::from_secs(1), Duration::from_secs(30));
    // The latest desired state, sent again after each reconnect.
    let mut desired: Option<Value> = None;
    loop {
        let failure = match UnixStream::connect(&socket).await {
            Ok(stream) => match session(stream, &mut ctx, &mut desired).await {
                Ended::Cancelled => return Ok(()),
                Ended::Lost(why) => {
                    backoff.reset();
                    why
                }
            },
            Err(error) => format!("can't connect to {}: {error}", socket.display()),
        };
        tracing::warn!(error = %failure, "stream daemon unreachable");
        ctx.shadows.report(MODULE, unreachable(&failure));
        // Until the daemon is back: refuse commands, remember desired state.
        let retry = tokio::time::sleep(backoff.next_delay());
        tokio::pin!(retry);
        loop {
            tokio::select! {
                () = ctx.cancel.cancelled() => return Ok(()),
                () = &mut retry => break,
                Some(pending) = ctx.commands.recv() => pending.respond(Outcome::error(
                    codes::MODULE_UNAVAILABLE,
                    format!("the stream daemon is unreachable: {failure}"),
                )),
                Some(state) = ctx.desired.recv() => desired = Some(state),
            }
        }
    }
}

fn unreachable(error: &str) -> Map<String, Value> {
    Map::from_iter([(
        "daemon".to_owned(),
        json!({"state": "unreachable", "error": error}),
    )])
}

/// The daemon's shadow, with the connection's state added.
fn with_daemon(mut reported: Map<String, Value>, version: &Value) -> Map<String, Value> {
    reported.insert(
        "daemon".into(),
        json!({"state": "connected", "version": version, "error": null}),
    );
    reported
}

/// One connection: `hello`, then commands out, events and shadow in, until it drops.
async fn session(
    stream: UnixStream,
    ctx: &mut ModuleContext,
    desired: &mut Option<Value>,
) -> Ended {
    let (reader, mut writer) = stream.into_split();
    let mut lines = BufReader::new(reader).lines();
    let mut next_id = 1u64;
    if writer
        .write_all(control::request(next_id, "hello", json!({})).as_bytes())
        .await
        .is_err()
    {
        return Ended::Lost("the daemon closed the connection".into());
    }
    let hello = loop {
        let line = match tokio::time::timeout(HELLO_TIMEOUT, lines.next_line()).await {
            Ok(Ok(Some(line))) => line,
            Ok(Ok(None) | Err(_)) => return Ended::Lost("the daemon closed the connection".into()),
            Err(_) => return Ended::Lost("no answer to hello".into()),
        };
        if let Some(Message::Response { id: 1, outcome }) = control::parse(&line) {
            break outcome;
        }
    };
    let Outcome::Ok(hello) = hello else {
        return Ended::Lost("the daemon refused hello".into());
    };
    let version = hello["version"].clone();
    tracing::info!(version = %version, "connected to the stream daemon");
    let shadow = hello["shadow"].as_object().cloned().unwrap_or_default();
    ctx.shadows.report(MODULE, with_daemon(shadow, &version));
    if let Some(dropped) = hello["dropped_events"].as_u64().filter(|n| *n > 0) {
        tracing::warn!(
            dropped,
            "the stream daemon dropped events while Helios was away"
        );
    }
    for event in hello["events"].as_array().into_iter().flatten() {
        publish(ctx, event);
    }
    let mut waiting: BTreeMap<u64, PendingCommand> = BTreeMap::new();
    if let Some(state) = desired.take() {
        next_id += 1;
        let line = control::request(next_id, "desired", json!({"state": state}));
        if writer.write_all(line.as_bytes()).await.is_err() {
            return Ended::Lost("the daemon closed the connection".into());
        }
    }
    let ended = loop {
        tokio::select! {
            () = ctx.cancel.cancelled() => break Ended::Cancelled,
            Some(pending) = ctx.commands.recv() => {
                next_id += 1;
                let params = json!({"name": pending.command.name, "args": pending.command.args});
                if writer.write_all(control::request(next_id, "command", params).as_bytes()).await.is_err() {
                    pending.respond(Outcome::error(codes::MODULE_UNAVAILABLE, "the stream daemon went away"));
                    break Ended::Lost("the daemon closed the connection".into());
                }
                waiting.insert(next_id, pending);
            }
            Some(state) = ctx.desired.recv() => {
                next_id += 1;
                let line = control::request(next_id, "desired", json!({"state": state.clone()}));
                if writer.write_all(line.as_bytes()).await.is_err() {
                    *desired = Some(state);
                    break Ended::Lost("the daemon closed the connection".into());
                }
            }
            line = lines.next_line() => match line {
                Ok(Some(line)) => match control::parse(&line) {
                    Some(Message::Response { id, outcome }) => {
                        if let Some(pending) = waiting.remove(&id) {
                            pending.respond(outcome);
                        }
                    }
                    Some(Message::Notification { method, params }) => match method.as_str() {
                        "event" => publish(ctx, &params),
                        "shadow" => {
                            let reported = params["reported"].as_object().cloned().unwrap_or_default();
                            ctx.shadows.report(MODULE, with_daemon(reported, &version));
                        }
                        other => tracing::debug!(method = other, "ignoring a daemon notification"),
                    },
                    _ => {}
                },
                Ok(None) | Err(_) => break Ended::Lost("the daemon closed the connection".into()),
            },
        }
    };
    for (_, pending) in waiting {
        pending.respond(Outcome::error(
            codes::MODULE_UNAVAILABLE,
            "the stream daemon went away",
        ));
    }
    ended
}

fn publish(ctx: &ModuleContext, event: &Value) {
    if let Some(kind) = event["kind"].as_str() {
        ctx.mqtt.publish_event(
            MODULE,
            kind,
            event.get("payload").cloned().unwrap_or(Value::Null),
        );
    }
}
