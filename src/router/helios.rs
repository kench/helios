//! The `helios` module's commands: the agent's own, for checking the command path end to end.
//!
//! - `helios.ping`: answers with the Helios version, the uptime and the MQTT session number.

use std::time::Instant;

use serde_json::json;
use tokio::sync::{mpsc, watch};
use tokio::task::JoinHandle;

use crate::mqtt::manager::MqttStatus;
use crate::router::{Outcome, PendingCommand, codes};

/// The module name.
pub const MODULE: &str = "helios";

/// Answers `helios` commands from `commands` until the router goes away.
///
/// # Panics
///
/// Panics if called outside a tokio runtime.
#[must_use]
pub fn start(
    mut commands: mpsc::Receiver<PendingCommand>,
    mqtt: watch::Receiver<MqttStatus>,
    started: Instant,
) -> JoinHandle<()> {
    tokio::spawn(async move {
        while let Some(pending) = commands.recv().await {
            let outcome = match pending.command.name.as_str() {
                "ping" => Outcome::Ok(json!({
                    "version": env!("CARGO_PKG_VERSION"),
                    "uptime_s": started.elapsed().as_secs(),
                    "session": mqtt.borrow().session,
                })),
                other => {
                    Outcome::error(codes::UNKNOWN_COMMAND, format!("no command helios.{other}"))
                }
            };
            pending.respond(outcome);
        }
    })
}
