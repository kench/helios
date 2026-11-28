//! Helios's `stream` module (LLD 4, section 15): a client of the stream daemon
//! (`helios-stream.service`). It forwards commands to the daemon over its control socket, and the
//! daemon's events and shadow to MQTT. Streams themselves run in the daemon, so they keep going
//! while Helios restarts. The `stream` shadow is reported-only: changes are commands.
//!
//! A `stream.update` with a sealed destination is opened here, where the device's secrets key
//! is (the daemon has no access to it), and passed on as `{"url": ...}`, or as
//! `{"unreadable": reason}` so the daemon refuses it with the rest of the command.

use std::collections::BTreeMap;
use std::path::PathBuf;
use std::time::Duration;

use serde_json::{Map, Value, json};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::UnixStream;

use super::MODULE;
use super::control::{self, Message};
use crate::backoff::Backoff;
use crate::identity::manager::IdentityState;
use crate::identity::secrets::{Sealed, open_sealed};
use crate::modules::{Module, ModuleContext, ModuleError, ModuleFuture};
use crate::router::{Outcome, PendingCommand, codes};

/// How long to wait for the daemon's answer to `hello`.
const HELLO_TIMEOUT: Duration = Duration::from_secs(10);

/// The `stream` module in Helios.
pub struct StreamClient {
    socket: PathBuf,
    /// The net module's uplink view, passed on to the daemon (`uplinks`) for standby.
    uplinks: Option<tokio::sync::watch::Receiver<Value>>,
    /// The identity, for opening sealed destinations.
    identity: Option<tokio::sync::watch::Receiver<IdentityState>>,
}

impl StreamClient {
    /// A client of the daemon listening on `socket`.
    #[must_use]
    pub fn new(socket: PathBuf) -> Self {
        Self {
            socket,
            uplinks: None,
            identity: None,
        }
    }

    /// Opens sealed destinations (`stream.update`) with this identity's secrets key.
    #[must_use]
    pub fn with_identity(mut self, identity: tokio::sync::watch::Receiver<IdentityState>) -> Self {
        self.identity = Some(identity);
        self
    }

    /// Passes the net module's uplink view on to the daemon, after each connect and on change.
    #[must_use]
    pub fn with_uplink_view(mut self, uplinks: tokio::sync::watch::Receiver<Value>) -> Self {
        self.uplinks = Some(uplinks);
        self
    }
}

impl Module for StreamClient {
    fn name(&self) -> &'static str {
        MODULE
    }

    fn run(&self, ctx: ModuleContext) -> ModuleFuture<'_> {
        Box::pin(run(
            self.socket.clone(),
            ctx,
            self.uplinks.clone(),
            self.identity.clone(),
        ))
    }
}

/// The uplink view's next change, or never without a view (or once its sender is gone).
async fn changed(view: Option<&mut tokio::sync::watch::Receiver<Value>>) -> Option<Value> {
    match view {
        Some(view) => match view.changed().await {
            Ok(()) => Some(view.borrow_and_update().clone()),
            Err(_) => std::future::pending().await,
        },
        None => std::future::pending().await,
    }
}

/// What a connection ended with.
enum Ended {
    Cancelled,
    Lost(String),
}

async fn run(
    socket: PathBuf,
    mut ctx: ModuleContext,
    mut uplinks: Option<tokio::sync::watch::Receiver<Value>>,
    identity: Option<tokio::sync::watch::Receiver<IdentityState>>,
) -> Result<(), ModuleError> {
    let mut backoff = Backoff::new(Duration::from_secs(1), Duration::from_secs(30));
    loop {
        let failure = match UnixStream::connect(&socket).await {
            Ok(stream) => {
                match session(stream, &mut ctx, uplinks.as_mut(), identity.as_ref()).await {
                    Ended::Cancelled => return Ok(()),
                    Ended::Lost(why) => {
                        backoff.reset();
                        why
                    }
                }
            }
            Err(error) => format!("can't connect to {}: {error}", socket.display()),
        };
        tracing::warn!(error = %failure, "stream daemon unreachable");
        ctx.shadows.report(MODULE, unreachable(&failure));
        // Until the daemon is back: refuse commands.
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
    mut uplinks: Option<&mut tokio::sync::watch::Receiver<Value>>,
    identity: Option<&tokio::sync::watch::Receiver<IdentityState>>,
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
    // The uplink view: the current one now, then each change.
    if let Some(view) = uplinks.as_deref_mut() {
        let current = view.borrow_and_update().clone();
        if !current.is_null() {
            next_id += 1;
            let line = control::request(next_id, "uplinks", current);
            if writer.write_all(line.as_bytes()).await.is_err() {
                return Ended::Lost("the daemon closed the connection".into());
            }
        }
    }
    let ended = loop {
        tokio::select! {
            () = ctx.cancel.cancelled() => break Ended::Cancelled,
            Some(view) = changed(uplinks.as_deref_mut()) => {
                next_id += 1;
                let line = control::request(next_id, "uplinks", view);
                if writer.write_all(line.as_bytes()).await.is_err() {
                    break Ended::Lost("the daemon closed the connection".into());
                }
            }
            Some(pending) = ctx.commands.recv() => {
                next_id += 1;
                let mut args = pending.command.args.clone();
                if pending.command.name == "update" {
                    args = open_destination(identity, args, pending.command.local).await;
                }
                let params = json!({"name": pending.command.name, "args": args});
                if writer.write_all(control::request(next_id, "command", params).as_bytes()).await.is_err() {
                    pending.respond(Outcome::error(codes::MODULE_UNAVAILABLE, "the stream daemon went away"));
                    break Ended::Lost("the daemon closed the connection".into());
                }
                waiting.insert(next_id, pending);
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

/// `stream.update`'s sealed destination, opened for the daemon: `{"set": {"url": ...}}`, or
/// `{"set": {"unreadable": reason}}` when it can't be (the daemon then refuses it). A plain
/// `url` is refused the same way, unless the command is `local` (Helios's own console, LLD 13:
/// nothing between it and the device keeps the URL, and offline there may be no key to seal
/// to). Arguments without a well-formed sealed destination go on as they are, for the daemon
/// to check.
async fn open_destination(
    identity: Option<&tokio::sync::watch::Receiver<IdentityState>>,
    mut args: Value,
    local: bool,
) -> Value {
    // `url` and `unreadable` are this function's own: from the cloud, a destination is sealed.
    let inner = args.pointer("/destination/set").and_then(Value::as_object);
    if local && inner.is_some_and(|inner| inner.len() == 1 && inner.contains_key("url")) {
        return args;
    }
    if inner.is_some_and(|inner| inner.contains_key("url") || inner.contains_key("unreadable")) {
        args["destination"] =
            json!({"set": {"unreadable": "a destination from the cloud must be sealed"}});
        return args;
    }
    let Some(sealed) = args
        .pointer("/destination/set/sealed")
        .and_then(|sealed| serde_json::from_value::<Sealed>(sealed.clone()).ok())
    else {
        return args;
    };
    let stream = args["stream_id"].as_str().unwrap_or_default().to_owned();
    let aad = format!("stream.destination {stream}");
    let opened = match identity {
        None => Err("the device has no key for sealed secrets".to_owned()),
        Some(identity) => open_sealed(identity, aad.as_bytes(), &sealed)
            .await
            .map_err(|error| error.to_string())
            .and_then(|plain| {
                String::from_utf8(plain.to_vec())
                    .map_err(|_| "the sealed destination isn't text".to_owned())
            }),
    };
    args["destination"] = match opened {
        Ok(url) => json!({"set": {"url": url}}),
        Err(reason) => {
            tracing::warn!(%stream, %reason, "sealed destination not opened");
            json!({"set": {"unreadable": reason}})
        }
    };
    args
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

#[cfg(test)]
mod tests;
