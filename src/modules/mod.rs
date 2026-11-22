//! Device modules (HLD section 6), each turned on by its `[modules.<name>]` config section, and
//! the framework that runs them (LLD 5, section 14; LLD 8, section 3).
//!
//! - `display`: screens on the scanner's framebuffer (LLD 9).
//! - `usb`: USB devices arriving and leaving, from kernel uevents and sysfs (LLD 5).
//! - `stream`: video streams to SRT listeners through ffmpeg (LLD 4).
//! - `net`: network interfaces, their link state, addresses and default routes (LLD 3).
//!
//! Each module is behind a Cargo feature (`module-display`, `module-usb`, `module-stream`,
//! `module-net`), off by default, so a device's build
//! carries only the modules it uses. In a build without it, the module's config section is
//! reported as unused, like any other unknown section.
//!
//! A module implements [`Module`]. The [`supervisor`] runs each enabled module as its own task,
//! gives every run a fresh [`ModuleContext`], and restarts a module whose run fails, panics or
//! ends without being cancelled, with backoff. Each module's state goes in the `helios` shadow.

use std::collections::BTreeMap;
use std::future::Future;
use std::path::PathBuf;
use std::pin::Pin;
use std::time::SystemTime;

use serde_json::Value;
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;

use crate::mqtt::manager::MqttHandle;
use crate::mqtt::shadow::ShadowHandle;
use crate::router::PendingCommand;

#[cfg(feature = "module-display")]
pub mod display;
#[cfg(feature = "module-net")]
pub mod net;
#[cfg(feature = "module-stream")]
pub mod stream;
pub mod supervisor;
#[cfg(feature = "module-usb")]
pub mod usb;

/// What a module's run returns.
pub type ModuleFuture<'a> = Pin<Box<dyn Future<Output = Result<(), ModuleError>> + Send + 'a>>;

/// A device module. Futures are boxed so modules can live in a `Vec<Arc<dyn Module>>` without
/// the `async-trait` crate.
pub trait Module: Send + Sync + 'static {
    /// The stable name: the command topic, the shadow's name and the config section.
    fn name(&self) -> &'static str;

    /// Runs until `ctx.cancel` fires, then returns `Ok(())`. Returning an error, panicking or
    /// returning while not cancelled makes the supervisor restart the module with a new context.
    fn run(&self, ctx: ModuleContext) -> ModuleFuture<'_>;
}

/// Why a module's run failed.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("{0}")]
pub struct ModuleError(pub String);

/// What one run of a module gets. Every run gets new command and desired-state channels, so a
/// restarted module starts from a clean queue.
#[derive(Debug)]
pub struct ModuleContext {
    /// Commands on `helios/<thing>/cmd/<name>` (`RouterHandle::register`).
    pub commands: mpsc::Receiver<PendingCommand>,
    /// The `<name>` shadow's desired state (`ShadowHandle::desired`).
    pub desired: mpsc::UnboundedReceiver<Value>,
    /// For the module's reported state.
    pub shadows: ShadowHandle,
    /// For events (`publish_event`) and the connection's status.
    pub mqtt: MqttHandle,
    /// Normally `/sys`.
    pub sysfs: PathBuf,
    /// Shutdown.
    pub cancel: CancellationToken,
}

/// Where a module is in its life, as the `helios` shadow reports it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RunState {
    /// Running.
    Running,
    /// Waiting to start again after a failure.
    Restarting,
    /// Stopped at shutdown.
    Stopped,
}

impl RunState {
    /// The name in the shadow.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Running => "running",
            Self::Restarting => "restarting",
            Self::Stopped => "stopped",
        }
    }
}

/// One module's state.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ModuleStatus {
    /// Running, restarting or stopped.
    pub state: RunState,
    /// How many times it has been restarted since Helios started.
    pub restarts: u32,
    /// Why the last run failed.
    pub last_error: Option<String>,
    /// When the state last changed.
    pub since: SystemTime,
}

/// Every supervised module's state, by name.
pub type ModuleStates = BTreeMap<&'static str, ModuleStatus>;
