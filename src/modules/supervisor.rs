//! Runs the device modules (LLD 5, section 14): each in its own task, restarted with backoff
//! when a run fails, panics or ends without being cancelled.
//!
//! Every run gets a new [`ModuleContext`]: the module registers with the router again (the
//! router replaces the old queue) and asks for its shadow's desired state again (the shadow
//! manager reads the shadow once more, so the run gets the full desired state). A run that
//! lasted [`STABLE_RUN`] resets the backoff, so a module that fails once a day restarts after a
//! second, not after the maximum delay.

use std::any::Any;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, SystemTime};

use tokio::sync::watch;
use tokio::task::{JoinError, JoinHandle};
use tokio::time::Instant;
use tokio_util::sync::CancellationToken;

use super::{Module, ModuleContext, ModuleStates, ModuleStatus, RunState};
use crate::backoff::Backoff;
use crate::mqtt::manager::MqttHandle;
use crate::mqtt::shadow::ShadowHandle;
use crate::router::RouterHandle;

/// The first delay before a restart.
pub const INITIAL_DELAY: Duration = Duration::from_secs(1);

/// The longest delay before a restart.
pub const MAX_DELAY: Duration = Duration::from_secs(300);

/// A run at least this long resets the backoff.
pub const STABLE_RUN: Duration = Duration::from_secs(300);

/// What the supervisor gives modules.
#[derive(Debug, Clone)]
pub struct Deps {
    /// Command registration.
    pub router: RouterHandle,
    /// Reported and desired state.
    pub shadows: ShadowHandle,
    /// Events and the connection's status.
    pub mqtt: MqttHandle,
    /// Normally `/sys`.
    pub sysfs: PathBuf,
}

/// Restart timing; [`Timing::default`] outside tests.
#[derive(Debug, Clone, Copy)]
pub struct Timing {
    /// The first delay before a restart.
    pub initial_delay: Duration,
    /// The longest delay.
    pub max_delay: Duration,
    /// A run at least this long resets the backoff.
    pub stable_run: Duration,
}

impl Default for Timing {
    fn default() -> Self {
        Self {
            initial_delay: INITIAL_DELAY,
            max_delay: MAX_DELAY,
            stable_run: STABLE_RUN,
        }
    }
}

/// Starts every module. The tasks end once `cancel` fires and each module's run has returned,
/// so await them before exiting. The receiver has each module's state, for the `helios`
/// shadow.
///
/// # Panics
///
/// Panics if called outside a tokio runtime.
pub fn start(
    modules: Vec<Arc<dyn Module>>,
    deps: &Deps,
    timing: Timing,
    cancel: &CancellationToken,
) -> (watch::Receiver<ModuleStates>, Vec<JoinHandle<()>>) {
    let now = SystemTime::now();
    let initial = modules
        .iter()
        .map(|module| {
            (
                module.name(),
                ModuleStatus {
                    state: RunState::Running,
                    restarts: 0,
                    last_error: None,
                    since: now,
                },
            )
        })
        .collect();
    let (states, states_rx) = watch::channel(initial);
    let tasks = modules
        .into_iter()
        .map(|module| {
            tokio::spawn(supervise(
                module,
                deps.clone(),
                timing,
                states.clone(),
                cancel.clone(),
            ))
        })
        .collect();
    (states_rx, tasks)
}

async fn supervise(
    module: Arc<dyn Module>,
    deps: Deps,
    timing: Timing,
    states: watch::Sender<ModuleStates>,
    cancel: CancellationToken,
) {
    let name = module.name();
    let mut backoff = Backoff::new(timing.initial_delay, timing.max_delay);
    loop {
        let ctx = ModuleContext {
            commands: deps.router.register(name),
            desired: deps.shadows.desired(name),
            shadows: deps.shadows.clone(),
            mqtt: deps.mqtt.clone(),
            sysfs: deps.sysfs.clone(),
            cancel: cancel.clone(),
        };
        let started = Instant::now();
        let run = Arc::clone(&module);
        // Its own task, so a panic ends only this run.
        let result = tokio::spawn(async move { run.run(ctx).await }).await;
        if cancel.is_cancelled() {
            if let Some(error) = failure(result) {
                tracing::warn!(module = name, %error, "module failed while stopping");
            }
            set(&states, name, RunState::Stopped, None);
            return;
        }
        let error =
            failure(result).unwrap_or_else(|| "returned without being asked to stop".to_owned());
        if started.elapsed() >= timing.stable_run {
            backoff.reset();
        }
        let delay = backoff.next_delay();
        tracing::warn!(module = name, %error, ?delay, "module failed; restarting");
        set(&states, name, RunState::Restarting, Some(error));
        tokio::select! {
            () = cancel.cancelled() => {
                set(&states, name, RunState::Stopped, None);
                return;
            }
            () = tokio::time::sleep(delay) => {}
        }
        set(&states, name, RunState::Running, None);
    }
}

/// Why a run ended, if it failed: an error or a panic. `None` for `Ok(())`.
fn failure(result: Result<Result<(), super::ModuleError>, JoinError>) -> Option<String> {
    match result {
        Ok(Ok(())) => None,
        Ok(Err(error)) => Some(error.to_string()),
        Err(error) if error.is_panic() => Some(format!(
            "panicked: {}",
            panic_message(error.into_panic().as_ref())
        )),
        Err(_) => Some("its task was cancelled".to_owned()),
    }
}

fn panic_message(payload: &(dyn Any + Send)) -> &str {
    payload
        .downcast_ref::<&str>()
        .copied()
        .or_else(|| payload.downcast_ref::<String>().map(String::as_str))
        .unwrap_or("(no message)")
}

/// Records `name`'s new state. A restart counts when it goes back to running; the last error
/// stays until then, so the shadow shows why it's restarting.
fn set(
    states: &watch::Sender<ModuleStates>,
    name: &'static str,
    state: RunState,
    error: Option<String>,
) {
    states.send_modify(|states| {
        let Some(status) = states.get_mut(name) else {
            return;
        };
        if state == RunState::Running && status.state == RunState::Restarting {
            status.restarts = status.restarts.saturating_add(1);
        }
        if error.is_some() {
            status.last_error = error;
        }
        status.state = state;
        status.since = SystemTime::now();
    });
}

#[cfg(test)]
mod tests;
