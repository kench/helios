//! The command router (LLD 2, section 7): commands from the cloud to modules, and their responses.
//!
//! Commands arrive through a [`CommandTransport`], so the wire format can change (custom topics
//! now, AWS IoT commands later) without modules noticing: modules only see a [`Command`] and
//! answer with an [`Outcome`]. A module registers with [`RouterHandle::register`] and receives
//! [`PendingCommand`]s. The router drops QoS 1 repeats, answers for modules that don't exist or
//! are too busy, and times commands out.

use std::collections::HashMap;
use std::fmt;
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime};

use serde_json::Value;
use tokio::sync::{mpsc, oneshot};
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;

use crate::mqtt::manager::{Incoming, MqttHandle};

pub mod helios;
pub mod topics;

/// Shared error codes (LLD 2, section 3).
pub mod codes {
    /// The message isn't a valid command.
    pub const INVALID_MESSAGE: &str = "INVALID_MESSAGE";
    /// No module or command by that name.
    pub const UNKNOWN_COMMAND: &str = "UNKNOWN_COMMAND";
    /// The module can't take the command now.
    pub const MODULE_UNAVAILABLE: &str = "MODULE_UNAVAILABLE";
    /// The command didn't finish in time.
    pub const TIMEOUT: &str = "TIMEOUT";
    /// Something went wrong in Helios.
    pub const INTERNAL: &str = "INTERNAL";
}

/// A command as modules see it, whichever transport carried it.
#[derive(Debug, Clone, PartialEq)]
pub struct Command {
    /// The envelope `id`, or the AWS IoT execution ID.
    pub id: String,
    /// The module, such as `video`.
    pub module: String,
    /// The command within the module, such as `stream.start`.
    pub name: String,
    /// The command's arguments.
    pub args: Value,
    /// When the sender stops waiting, if it said.
    pub deadline: Option<SystemTime>,
}

/// How a command ended.
#[derive(Debug, Clone, PartialEq)]
pub enum Outcome {
    /// It succeeded, with this result.
    Ok(Value),
    /// It failed.
    Err {
        /// Upper snake case: a shared code from [`codes`], or the module's own.
        code: String,
        /// For people.
        message: String,
    },
}

impl Outcome {
    /// A failure with `code` and `message`.
    #[must_use]
    pub fn error(code: &str, message: impl Into<String>) -> Self {
        Self::Err {
            code: code.to_owned(),
            message: message.into(),
        }
    }
}

/// An incoming message on a command topic that isn't a valid command.
#[derive(Debug, Clone, PartialEq)]
pub struct InvalidCommand {
    /// Why.
    pub reason: String,
    /// As much of the command as could be read, to answer it: present when it had an `id`.
    pub partial: Option<Box<Command>>,
}

/// A publish to send.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Publish {
    /// The topic.
    pub topic: String,
    /// The payload.
    pub payload: Vec<u8>,
}

/// How commands travel over MQTT (LLD 2, section 7.1).
pub trait CommandTransport: Send + Sync + fmt::Debug {
    /// Topic filters to subscribe to for `thing`.
    fn subscriptions(&self, thing: &str) -> Vec<String>;
    /// An incoming publish as a command; `None` if this transport doesn't own the topic.
    fn decode(
        &self,
        thing: &str,
        topic: &str,
        payload: &[u8],
    ) -> Option<Result<Command, InvalidCommand>>;
    /// The response publish for `command`.
    fn encode(&self, thing: &str, command: &Command, outcome: &Outcome) -> Publish;
}

/// Router timing. Tests shorten it.
#[derive(Debug, Clone, Copy)]
pub struct Timing {
    /// How long a command may take when it has no deadline.
    pub default_timeout: Duration,
    /// How long command IDs are remembered, to drop QoS 1 repeats.
    pub dedupe_window: Duration,
}

impl Default for Timing {
    fn default() -> Self {
        Self {
            default_timeout: Duration::from_secs(30),
            dedupe_window: Duration::from_secs(10 * 60),
        }
    }
}

/// How many commands may wait for one module.
pub const MODULE_QUEUE: usize = 16;

/// A command waiting for its module's answer.
#[derive(Debug)]
pub struct PendingCommand {
    /// The command.
    pub command: Command,
    reply: oneshot::Sender<Outcome>,
}

impl PendingCommand {
    /// Answers the command. An answer after its deadline is dropped.
    pub fn respond(self, outcome: Outcome) {
        let _ = self.reply.send(outcome);
    }
}

/// Registers modules with the router. Cheap to clone.
#[derive(Debug, Clone)]
pub struct RouterHandle {
    registrations: mpsc::UnboundedSender<(String, mpsc::Sender<PendingCommand>)>,
}

impl RouterHandle {
    /// Registers `module`: its commands arrive on the returned channel.
    #[must_use]
    pub fn register(&self, module: &str) -> mpsc::Receiver<PendingCommand> {
        let (sender, receiver) = mpsc::channel(MODULE_QUEUE);
        let _ = self.registrations.send((module.to_owned(), sender));
        receiver
    }
}

/// Starts the router.
pub struct Router;

impl Router {
    /// Starts the router: commands arrive on `incoming` (non-shadow MQTT messages), are decoded
    /// with `transport`, and responses go out through `mqtt`. Ends when `cancel` is cancelled.
    ///
    /// # Panics
    ///
    /// Panics if called outside a tokio runtime.
    #[must_use]
    pub fn start(
        mqtt: MqttHandle,
        transport: Arc<dyn CommandTransport>,
        incoming: mpsc::Receiver<Incoming>,
        timing: Timing,
        cancel: CancellationToken,
    ) -> (RouterHandle, JoinHandle<()>) {
        let (registrations_tx, registrations) = mpsc::unbounded_channel();
        let router = Running {
            mqtt,
            transport,
            incoming,
            registrations,
            timing,
            cancel,
            modules: HashMap::new(),
            seen: HashMap::new(),
        };
        (
            RouterHandle {
                registrations: registrations_tx,
            },
            tokio::spawn(router.run()),
        )
    }
}

struct Running {
    mqtt: MqttHandle,
    transport: Arc<dyn CommandTransport>,
    incoming: mpsc::Receiver<Incoming>,
    registrations: mpsc::UnboundedReceiver<(String, mpsc::Sender<PendingCommand>)>,
    timing: Timing,
    cancel: CancellationToken,
    modules: HashMap<String, mpsc::Sender<PendingCommand>>,
    /// Command IDs seen recently, and when.
    seen: HashMap<String, Instant>,
}

impl Running {
    async fn run(mut self) {
        loop {
            tokio::select! {
                () = self.cancel.cancelled() => return,
                Some((module, sender)) = self.registrations.recv() => {
                    self.modules.insert(module, sender);
                }
                Some(message) = self.incoming.recv() => self.received(&message),
                else => return,
            }
        }
    }

    fn received(&mut self, message: &Incoming) {
        let Some(thing) = self.mqtt.status().borrow().thing.clone() else {
            return;
        };
        let Some(decoded) = self
            .transport
            .decode(&thing, &message.topic, &message.payload)
        else {
            tracing::debug!(topic = %message.topic, "MQTT message on no command topic");
            return;
        };
        let command = match decoded {
            Ok(command) => command,
            Err(invalid) => {
                tracing::warn!(topic = %message.topic, reason = %invalid.reason, "invalid command");
                if let Some(partial) = invalid.partial {
                    self.respond(
                        &thing,
                        &partial,
                        &Outcome::error(codes::INVALID_MESSAGE, invalid.reason),
                    );
                }
                return;
            }
        };
        if !self.first_time(&command.id) {
            tracing::debug!(id = %command.id, "repeated command dropped");
            return;
        }
        let Some(module) = self.modules.get(&command.module) else {
            let message = format!("no module {:?}", command.module);
            self.respond(
                &thing,
                &command,
                &Outcome::error(codes::UNKNOWN_COMMAND, message),
            );
            return;
        };
        let (reply, answer) = oneshot::channel();
        let pending = PendingCommand {
            command: command.clone(),
            reply,
        };
        if module.try_send(pending).is_err() {
            let message = format!("module {:?} is busy or stopped", command.module);
            self.respond(
                &thing,
                &command,
                &Outcome::error(codes::MODULE_UNAVAILABLE, message),
            );
            return;
        }
        tracing::info!(id = %command.id, module = %command.module, name = %command.name, "command");
        // A deadline already past times out at once.
        let timeout = command
            .deadline
            .map_or(self.timing.default_timeout, |deadline| {
                deadline
                    .duration_since(SystemTime::now())
                    .unwrap_or(Duration::ZERO)
            });
        let mqtt = self.mqtt.clone();
        let transport = Arc::clone(&self.transport);
        tokio::spawn(async move {
            let outcome = match tokio::time::timeout(timeout, answer).await {
                Ok(Ok(outcome)) => outcome,
                Ok(Err(_)) => Outcome::error(codes::INTERNAL, "the module dropped the command"),
                Err(_) => Outcome::error(codes::TIMEOUT, "the command didn't finish in time"),
            };
            let publish = transport.encode(&thing, &command, &outcome);
            mqtt.publish_now(publish.topic, publish.payload);
        });
    }

    /// Whether `id` is new; remembers it for the dedupe window.
    fn first_time(&mut self, id: &str) -> bool {
        let now = Instant::now();
        let window = self.timing.dedupe_window;
        self.seen.retain(|_, at| now.duration_since(*at) < window);
        self.seen.insert(id.to_owned(), now).is_none()
    }

    fn respond(&self, thing: &str, command: &Command, outcome: &Outcome) {
        let publish = self.transport.encode(thing, command, outcome);
        self.mqtt.publish_now(publish.topic, publish.payload);
    }
}

#[cfg(test)]
mod tests;
