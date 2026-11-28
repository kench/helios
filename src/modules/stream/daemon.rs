//! `helios stream-daemon` (LLD 4, section 15): runs the stream engine in its own process,
//! `helios-stream.service`, so streams keep going while Helios restarts.
//!
//! The engine is the stream module unchanged, given detached MQTT and shadow handles: its events
//! and shadow reports come back here and go to the connected client (Helios) over the control
//! socket, or wait in a buffer while none is connected. Commands come the other way. The daemon
//! saves the streams' overrides (what commands set: live or stopped, a bitrate, settings) in
//! `<state_dir>/overrides.json` and gives them back to the engine at startup. The daemon runs its
//! own usb monitor for cameras, which reports nowhere.

use std::collections::VecDeque;
use std::path::{Path, PathBuf};
use std::time::Duration;

use serde_json::{Map, Value, json};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::{UnixListener, UnixStream};
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;

use super::control::{self, Message};
use super::{MODULE, StreamModule, StreamSettings};
use crate::modules::usb::{UsbHandle, UsbModule, UsbSettings};
use crate::modules::{Module, ModuleContext};
use crate::mqtt::manager::{MqttHandle, Request as MqttRequest};
use crate::mqtt::shadow::ShadowHandle;
use crate::router::{Outcome, PendingCommand, codes};

/// Events kept while no client is connected.
const BUFFERED_EVENTS: usize = 256;
/// How often the daemon looks for a pending upgrade restart.
const RESTART_CHECK: Duration = Duration::from_secs(5);
/// Stream states that mean something is running or about to: an upgrade restart waits.
const BUSY: [&str; 3] = ["starting", "live", "reconnecting"];

/// Builds the engine from the settings and the daemon's usb monitor: the real one, or a fake
/// in tests.
pub(crate) type MakeEngine = Box<dyn FnOnce(StreamSettings, UsbHandle) -> StreamModule + Send>;

/// What the daemon needs from outside.
pub(crate) struct Daemon {
    pub settings: StreamSettings,
    pub usb: UsbSettings,
    pub sysfs: PathBuf,
    pub engine: MakeEngine,
}

/// A line from a client connection, tagged with the connection.
struct Incoming {
    connection: u64,
    message: Message,
}

/// The connected client.
struct Client {
    connection: u64,
    lines: mpsc::UnboundedSender<String>,
}

impl Daemon {
    /// Runs until `cancel` fires, or a pending upgrade restart finds the daemon idle.
    ///
    /// # Errors
    ///
    /// If the control socket can't be created.
    pub(crate) async fn run(self, cancel: CancellationToken) -> Result<(), String> {
        let socket = self.settings.control_socket.clone();
        let listener = bind(&socket)?;
        tracing::info!(socket = %socket.display(), "stream daemon listening");
        let allowed = allowed_users(&self.settings.client_user);

        // The usb monitor, reporting nowhere.
        let usb = UsbHandle::default();
        let usb_task = {
            let module = UsbModule::new(self.usb.clone(), usb.clone());
            let ctx = detached_context(&self.sysfs, cancel.child_token()).0;
            tokio::spawn(async move { module.run(ctx).await })
        };

        // The engine, with its outputs coming back here.
        let engine_cancel = cancel.child_token();
        let (ctx, mut requests, mut reports, commands) =
            detached_context(&self.sysfs, engine_cancel.clone());
        let state_file = self.settings.state_dir.join(OVERRIDES);
        let saved = read_json(&state_file);
        if saved.is_some() {
            tracing::info!("resuming the saved overrides");
        }
        let pending_restart = self.settings.runtime_dir.join("restart-pending");
        // The uplink view Helios sends (`uplinks`), for standby (LLD 3, section 3.5.1).
        let (uplinks, uplinks_view) = tokio::sync::watch::channel(super::standby::View::new());
        let engine = (self.engine)(self.settings, usb)
            .with_uplinks(uplinks_view)
            .with_saved(saved);
        let engine_task = tokio::spawn(async move { engine.run(ctx).await });

        let (incoming_tx, mut incoming) = mpsc::unbounded_channel::<Incoming>();
        let mut client: Option<Client> = None;
        let mut next_connection = 0u64;
        let mut buffered: VecDeque<Value> = VecDeque::new();
        let mut dropped = 0u64;
        let mut shadow = Map::new();
        let mut saved = Value::Null;
        let mut restart_check = tokio::time::interval(RESTART_CHECK);
        loop {
            tokio::select! {
                () = cancel.cancelled() => break,
                accepted = listener.accept() => {
                    let Ok((stream, _)) = accepted else { continue };
                    match peer_allowed(&stream, &allowed) {
                        Ok(()) => {}
                        Err(why) => {
                            tracing::warn!(%why, "control connection refused");
                            continue;
                        }
                    }
                    next_connection += 1;
                    if client.is_some() {
                        tracing::info!("a new client replaces the connected one");
                    }
                    client = Some(serve_connection(stream, next_connection, incoming_tx.clone()));
                }
                Some(Incoming { connection, message }) = incoming.recv() => {
                    let Some(current) = client.as_ref().filter(|c| c.connection == connection) else {
                        continue;
                    };
                    if let Message::Request { id, method, params } = message {
                        let reply = match method.as_str() {
                            "hello" => {
                                let events: Vec<Value> = buffered.drain(..).collect();
                                let result = json!({
                                    "version": env!("CARGO_PKG_VERSION"),
                                    "shadow": shadow,
                                    "events": events,
                                    "dropped_events": dropped,
                                });
                                dropped = 0;
                                Some(control::response(&id, Outcome::Ok(result)))
                            }
                            "command" => {
                                let name = params["name"].as_str().unwrap_or_default();
                                let args = params.get("args").cloned().unwrap_or(json!({}));
                                let (pending, answer) =
                                    PendingCommand::local(format!("control-{id}"), MODULE, name, args);
                                if commands.send(pending).await.is_err() {
                                    Some(control::response(&id, Outcome::error(codes::MODULE_UNAVAILABLE, "the stream engine stopped")))
                                } else {
                                    let lines = current.lines.clone();
                                    tokio::spawn(async move {
                                        let outcome = answer.await.unwrap_or_else(|_| {
                                            Outcome::error(codes::INTERNAL, "no answer from the stream engine")
                                        });
                                        let _ = lines.send(control::response(&id, outcome));
                                    });
                                    None
                                }
                            }
                            "uplinks" => {
                                uplinks.send_replace(super::standby::parse(&params));
                                Some(control::response(&id, Outcome::Ok(json!({}))))
                            }
                            other => Some(control::response(
                                &id,
                                Outcome::error(codes::UNKNOWN_COMMAND, format!("unknown method {other}")),
                            )),
                        };
                        if let Some(reply) = reply {
                            let _ = current.lines.send(reply);
                        }
                    }
                }
                Some(request) = requests.recv() => {
                    if let MqttRequest::Event(event) = request {
                        let event = json!({
                            "kind": event.kind(), "payload": event.payload(),
                            "at": crate::mqtt::envelope::timestamp(event.time()),
                        });
                        let sent = client.as_ref().is_some_and(|c| {
                            c.lines.send(control::notification("event", event.clone())).is_ok()
                        });
                        if !sent {
                            if buffered.len() == BUFFERED_EVENTS {
                                buffered.pop_front();
                                dropped += 1;
                            }
                            buffered.push_back(event);
                        }
                    }
                }
                Some((name, reported)) = reports.recv() => {
                    if name != MODULE {
                        continue;
                    }
                    shadow = reported;
                    let now = overrides(&shadow);
                    if now != saved {
                        if let Err(error) = save_overrides(&state_file, &now) {
                            tracing::warn!(%error, file = %state_file.display(), "can't save the overrides");
                        }
                        saved = now;
                    }
                    if let Some(c) = &client {
                        let _ = c.lines.send(control::notification("shadow", json!({"reported": shadow})));
                    }
                }
                _ = restart_check.tick() => {
                    if pending_restart.exists() && !busy(&shadow) {
                        tracing::info!("an upgrade is waiting and no stream is running: restarting");
                        let _ = std::fs::remove_file(&pending_restart);
                        break;
                    }
                }
            }
        }
        engine_cancel.cancel();
        let _ = engine_task.await;
        usb_task.abort();
        let _ = std::fs::remove_file(&socket);
        Ok(())
    }
}

type Detached = (
    ModuleContext,
    mpsc::UnboundedReceiver<MqttRequest>,
    crate::mqtt::shadow::DetachedReports,
    mpsc::Sender<PendingCommand>,
);

/// A module context whose outputs come back to the daemon.
fn detached_context(sysfs: &Path, cancel: CancellationToken) -> Detached {
    let (mqtt, requests, _status) = MqttHandle::detached();
    let (shadows, reports) = ShadowHandle::detached();
    let (commands_tx, commands) = mpsc::channel(crate::router::MODULE_QUEUE);
    let ctx = ModuleContext {
        commands,
        shadows,
        mqtt,
        sysfs: sysfs.to_owned(),
        cancel,
    };
    (ctx, requests, reports, commands_tx)
}

/// Creates the control socket: owner and group may connect (the unit's group is `helios`).
fn bind(socket: &Path) -> Result<UnixListener, String> {
    use std::os::unix::fs::PermissionsExt as _;
    if let Some(dir) = socket.parent() {
        std::fs::create_dir_all(dir).map_err(|e| format!("can't create {}: {e}", dir.display()))?;
    }
    let _ = std::fs::remove_file(socket);
    let listener = UnixListener::bind(socket)
        .map_err(|e| format!("can't listen on {}: {e}", socket.display()))?;
    std::fs::set_permissions(socket, std::fs::Permissions::from_mode(0o660))
        .map_err(|e| format!("can't set {}'s mode: {e}", socket.display()))?;
    Ok(listener)
}

/// Reads and writes one client connection's lines.
fn serve_connection(
    stream: UnixStream,
    connection: u64,
    incoming: mpsc::UnboundedSender<Incoming>,
) -> Client {
    let (reader, mut writer) = stream.into_split();
    let (lines, mut outgoing) = mpsc::unbounded_channel::<String>();
    tokio::spawn(async move {
        while let Some(line) = outgoing.recv().await {
            if writer.write_all(line.as_bytes()).await.is_err() {
                return;
            }
        }
    });
    tokio::spawn(async move {
        let mut reader = BufReader::new(reader).lines();
        while let Ok(Some(line)) = reader.next_line().await {
            match control::parse(&line) {
                Some(message) => {
                    if incoming
                        .send(Incoming {
                            connection,
                            message,
                        })
                        .is_err()
                    {
                        return;
                    }
                }
                None => tracing::debug!("ignoring a malformed control line"),
            }
        }
    });
    Client { connection, lines }
}

/// The user IDs that may connect: root, the daemon's own user, and `client_user`.
fn allowed_users(client_user: &str) -> Vec<u32> {
    let mut allowed = vec![0, rustix::process::getuid().as_raw()];
    match uid_of(
        client_user,
        &std::fs::read_to_string("/etc/passwd").unwrap_or_default(),
    ) {
        Some(uid) => allowed.push(uid),
        None => tracing::warn!(user = client_user, "no such user; only root may connect"),
    }
    allowed
}

/// `user`'s UID in a passwd file's text.
pub(crate) fn uid_of(user: &str, passwd: &str) -> Option<u32> {
    passwd.lines().find_map(|line| {
        let mut fields = line.split(':');
        (fields.next()? == user).then(|| fields.nth(1)?.parse().ok())?
    })
}

fn peer_allowed(stream: &UnixStream, allowed: &[u32]) -> Result<(), String> {
    let uid = stream
        .peer_cred()
        .map_err(|e| format!("can't read the peer's credentials: {e}"))?
        .uid();
    if allowed.contains(&uid) {
        Ok(())
    } else {
        Err(format!("UID {uid} isn't allowed"))
    }
}

/// The overrides store, in `state_dir`.
const OVERRIDES: &str = "overrides.json";

/// The overrides in a `stream` shadow report (operator intent, never effective values): each
/// stream's `desired` (live or stopped), `bitrate_override_kbps` (`null`: the profile's, so a
/// config change to the profile applies after a restart) and `overrides` (`null` members follow
/// `helios.toml`).
pub(crate) fn overrides(shadow: &Map<String, Value>) -> Value {
    let streams: Map<String, Value> = shadow
        .get("streams")
        .and_then(Value::as_object)
        .into_iter()
        .flatten()
        .map(|(id, status)| {
            let saved = json!({
                "desired": status["desired"],
                "bitrate_override_kbps": status["bitrate_override_kbps"],
                "overrides": status["overrides"],
            });
            (id.clone(), saved)
        })
        .collect();
    if streams.is_empty() {
        Value::Null
    } else {
        json!({ "streams": streams })
    }
}

/// Whether any stream is running or about to.
pub(crate) fn busy(shadow: &Map<String, Value>) -> bool {
    shadow
        .get("streams")
        .and_then(Value::as_object)
        .is_some_and(|streams| {
            streams
                .values()
                .any(|status| status["state"].as_str().is_some_and(|s| BUSY.contains(&s)))
        })
}

/// The saved overrides in `file`, if it's there and valid.
fn read_json(file: &Path) -> Option<Value> {
    let text = std::fs::read_to_string(file).ok()?;
    serde_json::from_str(&text)
        .map_err(
            |error| tracing::warn!(%error, file = %file.display(), "ignoring the saved overrides"),
        )
        .ok()
}

/// Writes the overrides through a temporary file and a rename.
fn save_overrides(file: &Path, overrides: &Value) -> std::io::Result<()> {
    if overrides.is_null() {
        return Ok(());
    }
    if let Some(dir) = file.parent() {
        std::fs::create_dir_all(dir)?;
    }
    let temporary = file.with_extension("json.new");
    std::fs::write(&temporary, format!("{overrides:#}\n"))?;
    std::fs::rename(&temporary, file)
}

/// `helios stream-daemon`: loads `config_path`'s `[modules.stream]` (and `[modules.usb]`) and runs
/// until SIGTERM or SIGINT. The exit code follows `helios.service`'s: 0, 78 for a configuration
/// problem, 1 otherwise.
pub fn main(config_path: &Path) -> u8 {
    crate::logging::init();
    tracing::info!(version = env!("CARGO_PKG_VERSION"), config = %config_path.display(), "stream daemon starting");
    // The identity's environment checks are the agent's, not the daemon's.
    let config = match crate::config::Config::load(config_path, |_| true) {
        Ok(config) => config,
        Err(error) => {
            tracing::error!(%error, "configuration error");
            return 78;
        }
    };
    let Some(settings) = config.stream else {
        tracing::error!(
            "[modules.stream] isn't enabled in {}",
            config_path.display()
        );
        return 78;
    };
    let runtime = match tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
    {
        Ok(runtime) => runtime,
        Err(error) => {
            tracing::error!(%error, "can't start the async runtime");
            return 1;
        }
    };
    runtime.block_on(async {
        let shutdown = match crate::service::shutdown_signal() {
            Ok(shutdown) => shutdown,
            Err(error) => {
                tracing::error!(%error, "can't install signal handlers");
                return 1;
            }
        };
        let cancel = CancellationToken::new();
        let daemon = Daemon {
            settings,
            usb: config.usb.unwrap_or_default(),
            sysfs: "/sys".into(),
            engine: Box::new(StreamModule::new),
        };
        let run = tokio::spawn(daemon.run(cancel.clone()));
        tokio::pin!(run);
        let result = tokio::select! {
            () = shutdown => {
                tracing::info!("stopping");
                cancel.cancel();
                (&mut run).await
            }
            result = &mut run => result,
        };
        match result {
            Ok(Ok(())) => {
                tracing::info!("stopped");
                0
            }
            Ok(Err(error)) => {
                tracing::error!(%error, "can't run");
                1
            }
            Err(error) => {
                tracing::error!(%error, "the daemon panicked");
                1
            }
        }
    })
}

#[cfg(test)]
mod tests;
