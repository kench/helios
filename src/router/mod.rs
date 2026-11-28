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

pub mod aws_commands;
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

/// A command as modules see it, whichever transport carried it. Its `Debug` leaves out the
/// arguments, which can hold secrets (a Wi-Fi passphrase).
#[derive(Clone, PartialEq)]
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
    /// Sent by Helios itself (`RouterHandle::dispatch`: the web module's local console, LLD 13),
    /// not over MQTT. Only such a command may carry a destination in plain text.
    pub local: bool,
}

impl fmt::Debug for Command {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Command")
            .field("id", &self.id)
            .field("module", &self.module)
            .field("name", &self.name)
            .field("args", &format_args!(".."))
            .field("deadline", &self.deadline)
            .finish()
    }
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

    /// A command that didn't come through the router, such as one the stream daemon received
    /// over its control socket, with the channel its answer arrives on.
    #[cfg(feature = "module-stream")]
    pub(crate) fn local(
        id: String,
        module: &str,
        name: &str,
        args: Value,
    ) -> (Self, oneshot::Receiver<Outcome>) {
        let (reply, answer) = oneshot::channel();
        let command = Command {
            id,
            module: module.to_owned(),
            name: name.to_owned(),
            args,
            deadline: None,
            local: false,
        };
        (Self { command, reply }, answer)
    }

    /// A command for module tests, with the channel its answer arrives on.
    #[cfg(all(
        test,
        any(
            feature = "module-display",
            feature = "module-usb",
            feature = "module-net"
        )
    ))]
    pub(crate) fn for_test(
        module: &str,
        name: &str,
        args: Value,
    ) -> (Self, oneshot::Receiver<Outcome>) {
        let (reply, answer) = oneshot::channel();
        let command = Command {
            id: format!("test-{name}"),
            module: module.to_owned(),
            name: name.to_owned(),
            args,
            deadline: None,
            local: false,
        };
        (Self { command, reply }, answer)
    }
}

/// Registers modules with the router. Cheap to clone.
#[derive(Debug, Clone)]
pub struct RouterHandle {
    registrations: mpsc::UnboundedSender<(String, mpsc::Sender<PendingCommand>)>,
    /// Commands from inside Helios (the web module's local console), answered to the caller.
    local: mpsc::UnboundedSender<(Command, oneshot::Sender<Outcome>)>,
}

impl RouterHandle {
    /// For tests: each registration arrives on the returned channel as (module, queue).
    #[cfg(test)]
    pub(crate) fn for_test() -> (
        Self,
        mpsc::UnboundedReceiver<(String, mpsc::Sender<PendingCommand>)>,
    ) {
        let (registrations, received) = mpsc::unbounded_channel();
        // No router behind it: a dispatch answers that the router has stopped.
        let (local, _) = mpsc::unbounded_channel();
        (
            Self {
                registrations,
                local,
            },
            received,
        )
    }

    /// Registers `module`: its commands arrive on the returned channel.
    #[must_use]
    pub fn register(&self, module: &str) -> mpsc::Receiver<PendingCommand> {
        let (sender, receiver) = mpsc::channel(MODULE_QUEUE);
        let _ = self.registrations.send((module.to_owned(), sender));
        receiver
    }

    /// Runs `command` as if it had come over MQTT (the same deadline, module and timeout
    /// checks), and returns its outcome instead of publishing it. For the web module's local
    /// console (LLD 13), whose writes are the same commands the cloud sends.
    pub async fn dispatch(&self, mut command: Command) -> Outcome {
        command.local = true;
        let (reply, answer) = oneshot::channel();
        if self.local.send((command, reply)).is_err() {
            return Outcome::error(codes::INTERNAL, "the router has stopped");
        }
        answer
            .await
            .unwrap_or_else(|_| Outcome::error(codes::INTERNAL, "the router dropped the command"))
    }
}

/// Where a command's outcome goes.
enum Reply {
    /// Published on the transport that decoded it.
    Mqtt {
        transport: Arc<dyn CommandTransport>,
        thing: String,
    },
    /// Back to whoever dispatched it.
    Local(oneshot::Sender<Outcome>),
}

impl Reply {
    fn send(self, mqtt: &MqttHandle, command: &Command, outcome: Outcome) {
        match self {
            Self::Mqtt { transport, thing } => {
                let publish = transport.encode(&thing, command, &outcome);
                mqtt.publish_now(publish.topic, publish.payload);
            }
            Self::Local(reply) => {
                let _ = reply.send(outcome);
            }
        }
    }
}

/// Starts the router.
pub struct Router;

impl Router {
    /// Starts the router: commands arrive on `incoming` (non-shadow MQTT messages), are decoded
    /// by the first of `transports` that owns the topic, and each answer goes out through `mqtt`
    /// on that same transport. Ends when `cancel` is cancelled.
    ///
    /// # Panics
    ///
    /// Panics if called outside a tokio runtime.
    #[must_use]
    pub fn start(
        mqtt: MqttHandle,
        transports: Vec<Arc<dyn CommandTransport>>,
        incoming: mpsc::Receiver<Incoming>,
        timing: Timing,
        cancel: CancellationToken,
    ) -> (RouterHandle, JoinHandle<()>) {
        let (registrations_tx, registrations) = mpsc::unbounded_channel();
        let (local_tx, local) = mpsc::unbounded_channel();
        let router = Running {
            local,
            mqtt,
            transports,
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
                local: local_tx,
            },
            tokio::spawn(router.run()),
        )
    }
}

struct Running {
    mqtt: MqttHandle,
    transports: Vec<Arc<dyn CommandTransport>>,
    incoming: mpsc::Receiver<Incoming>,
    registrations: mpsc::UnboundedReceiver<(String, mpsc::Sender<PendingCommand>)>,
    local: mpsc::UnboundedReceiver<(Command, oneshot::Sender<Outcome>)>,
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
                Some((command, reply)) = self.local.recv() => {
                    self.run_command(command, Reply::Local(reply));
                }
                else => return,
            }
        }
    }

    fn received(&mut self, message: &Incoming) {
        let Some(thing) = self.mqtt.status().borrow().thing.clone() else {
            return;
        };
        let Some((transport, decoded)) = self.transports.iter().find_map(|transport| {
            let decoded = transport.decode(&thing, &message.topic, &message.payload)?;
            Some((Arc::clone(transport), decoded))
        }) else {
            tracing::debug!(topic = %message.topic, "MQTT message on no command topic");
            return;
        };
        let command = match decoded {
            Ok(command) => command,
            Err(invalid) => {
                tracing::warn!(topic = %message.topic, reason = %invalid.reason, "invalid command");
                if let Some(partial) = invalid.partial {
                    self.respond(
                        &*transport,
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
        self.run_command(command, Reply::Mqtt { transport, thing });
    }

    /// Hands `command` to its module and sends its outcome to `reply`: at once if it can't run,
    /// else when the module answers or the time runs out.
    fn run_command(&mut self, command: Command, reply: Reply) {
        // A command that arrives after its deadline isn't run: its sender has stopped waiting
        // and reported a failure, so running it now (a Wi-Fi network saved, a stream started)
        // would contradict that.
        if command
            .deadline
            .is_some_and(|deadline| deadline <= SystemTime::now())
        {
            tracing::warn!(id = %command.id, module = %command.module, name = %command.name, "command arrived after its deadline");
            reply.send(
                &self.mqtt,
                &command,
                Outcome::error(codes::TIMEOUT, "the command arrived after its deadline"),
            );
            return;
        }
        let Some(module) = self.modules.get(&command.module) else {
            let message = format!("no module {:?}", command.module);
            reply.send(
                &self.mqtt,
                &command,
                Outcome::error(codes::UNKNOWN_COMMAND, message),
            );
            return;
        };
        let (module_reply, answer) = oneshot::channel();
        let pending = PendingCommand {
            command: command.clone(),
            reply: module_reply,
        };
        if module.try_send(pending).is_err() {
            let message = format!("module {:?} is busy or stopped", command.module);
            reply.send(
                &self.mqtt,
                &command,
                Outcome::error(codes::MODULE_UNAVAILABLE, message),
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
        tokio::spawn(async move {
            let outcome = match tokio::time::timeout(timeout, answer).await {
                Ok(Ok(outcome)) => outcome,
                Ok(Err(_)) => Outcome::error(codes::INTERNAL, "the module dropped the command"),
                Err(_) => Outcome::error(codes::TIMEOUT, "the command didn't finish in time"),
            };
            reply.send(&mqtt, &command, outcome);
        });
    }

    /// Whether `id` is new; remembers it for the dedupe window.
    fn first_time(&mut self, id: &str) -> bool {
        let now = Instant::now();
        let window = self.timing.dedupe_window;
        self.seen.retain(|_, at| now.duration_since(*at) < window);
        self.seen.insert(id.to_owned(), now).is_none()
    }

    /// Answers `command` through `transport`, the one that decoded it.
    fn respond(
        &self,
        transport: &dyn CommandTransport,
        thing: &str,
        command: &Command,
        outcome: &Outcome,
    ) {
        let publish = transport.encode(thing, command, outcome);
        self.mqtt.publish_now(publish.topic, publish.payload);
    }
}

#[cfg(test)]
mod tests;
