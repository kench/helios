//! The Helios service: `helios` with no subcommand, as run by `helios.service` (LLD 1,
//! section 6).
//!
//! It loads `helios.toml`, starts the identity manager (with the bootstrap service or a local
//! PIN), the credentials refresher and the MQTT connection manager (LLD 2, section 6), and runs
//! until SIGTERM or SIGINT, or until the identity fails. On shutdown, MQTT stops first, so
//! `lifecycle.offline` goes out before the token is closed. It also runs the shadow manager,
//! reports the `helios` shadow (LLD 2, section 5), and routes commands (section 7), answering the
//! built-in `helios` module's. The other modules come later.
//!
//! Exit codes, as `helios.service` expects them:
//!
//! - 0 after SIGTERM or SIGINT.
//! - 78 (`EX_CONFIG`) for a config error or a fatal identity problem, such as a wrong or
//!   locked PIN. The unit's `RestartPreventExitStatus=78` stops systemd spending another PIN
//!   try on a restart.
//! - 1 for anything else, such as the signer thread stopping, so systemd restarts Helios.

use std::future::Future;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use tokio::sync::mpsc;
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;

use crate::cli::{EXIT_CONFIG, EXIT_ERROR, EXIT_OK};
use crate::clock::{ClockMonitor, Probes};
use crate::config::Config;
use crate::credentials::provider::{HeliosCredentialsProvider, LocalSettings};
use crate::identity::bootstrap::adapters::{PermanentAddresses, Rtnetlink};
use crate::identity::bootstrap::client::BootstrapClient;
use crate::identity::bootstrap::{DEVICE_TREE_MODEL, hardware_model};
use crate::identity::cryptoki::CryptokiToken;
use crate::identity::manager::{
    BootstrapSetup, BootstrapTiming, IdentityHandle, IdentityManager, ManagerConfig, ManagerExit,
    PinSetting, StartError,
};
use crate::identity::pin::credentials_directory_from_env;
use crate::identity::token::TokenBackend;
#[cfg(feature = "module-display")]
use crate::modules::display;
use crate::modules::{Module, supervisor};
use crate::mqtt::helios_shadow::{self, Sources};
use crate::mqtt::manager::{Incoming, MqttHandle, MqttManager, Options as MqttOptions};
use crate::mqtt::shadow::{ShadowHandle, ShadowManager};
use crate::provision::DEFAULT_TOKEN_LABEL;
use crate::router::{CommandTransport, Router, RouterHandle};
use crate::{hardening, logging};

/// Where the service finds things on the device. Tests point these at fakes.
pub struct Platform {
    /// Normally `/sys`, for finding the built-in network adapters.
    pub sysfs: PathBuf,
    /// Where permanent MAC addresses come from: normally [`Rtnetlink`].
    pub permanent_addresses: Arc<dyn PermanentAddresses>,
    /// Normally `/proc/device-tree/model`.
    pub device_tree_model: PathBuf,
    /// `$CREDENTIALS_DIRECTORY`, for `identity.pin = "credential:<name>"`.
    pub credentials_directory: Option<PathBuf>,
    /// The kernel's boot ID, reported in `lifecycle.online`.
    pub boot_id: Option<String>,
}

/// Where the kernel's boot ID is.
pub const BOOT_ID: &str = "/proc/sys/kernel/random/boot_id";

/// Retry timing for the service's parts. Tests shorten it.
#[derive(Debug, Clone, Copy, Default)]
pub struct Timing {
    /// The credentials refresher's.
    pub credentials: crate::credentials::provider::Timing,
    /// The MQTT connection manager's.
    pub mqtt: crate::mqtt::manager::Timing,
    /// The shadow manager's.
    pub shadows: crate::mqtt::shadow::Timing,
    /// The router's.
    pub router: crate::router::Timing,
    /// The clock checks'.
    pub clock: crate::clock::Timing,
    /// The module supervisor's restarts.
    pub modules: crate::modules::supervisor::Timing,
}

/// Incoming MQTT messages wait here until the router and shadow manager read them.
const INCOMING_CAPACITY: usize = 64;

/// How long modules get to finish after shutdown starts.
const MODULE_STOP_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(5);

impl Platform {
    /// The real device.
    #[must_use]
    pub fn system() -> Self {
        Self {
            sysfs: PathBuf::from("/sys"),
            permanent_addresses: Arc::new(Rtnetlink),
            device_tree_model: PathBuf::from(DEVICE_TREE_MODEL),
            credentials_directory: credentials_directory_from_env(),
            boot_id: std::fs::read_to_string(BOOT_ID)
                .ok()
                .map(|id| id.trim().to_owned()),
        }
    }
}

/// The service couldn't start.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("{message}")]
pub struct StartFailure {
    /// What went wrong.
    pub message: String,
    /// Whether it's a configuration problem (exit 78) rather than a runtime one (exit 1).
    pub config: bool,
}

impl StartFailure {
    fn config(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
            config: true,
        }
    }

    /// The exit code for this failure.
    #[must_use]
    pub fn exit_code(&self) -> u8 {
        if self.config { EXIT_CONFIG } else { EXIT_ERROR }
    }
}

impl From<StartError> for StartFailure {
    fn from(error: StartError) -> Self {
        Self {
            config: matches!(error, StartError::Missing(_)),
            message: error.to_string(),
        }
    }
}

/// The running service.
pub struct Service {
    #[cfg(feature = "module-usb")]
    usb: Option<crate::modules::usb::UsbHandle>,
    identity: IdentityHandle,
    credentials: HeliosCredentialsProvider,
    mqtt: MqttHandle,
    shadows: ShadowHandle,
    router: RouterHandle,
    identity_task: JoinHandle<ManagerExit>,
    credentials_task: JoinHandle<()>,
    mqtt_task: JoinHandle<()>,
    /// Routes incoming MQTT messages, runs the shadow manager and reports the `helios` shadow.
    helpers: Vec<JoinHandle<()>>,
    /// The device modules, which get time to finish after `cancel` (the display shows that
    /// Helios stopped).
    modules: Vec<JoinHandle<()>>,
    cancel: CancellationToken,
    /// Stops MQTT before everything else.
    mqtt_cancel: CancellationToken,
}

impl Service {
    /// Starts the identity manager with `backend`, the credentials refresher and the MQTT
    /// connection manager.
    ///
    /// # Errors
    ///
    /// [`StartFailure`] if the PIN source or bootstrap client can't be set up, or the identity
    /// manager can't start.
    ///
    /// # Panics
    ///
    /// Panics if called outside a tokio runtime.
    pub fn start(
        config: Config,
        backend: Box<dyn TokenBackend>,
        platform: &Platform,
        timing: Timing,
    ) -> Result<Self, StartFailure> {
        for section in &config.ignored_sections {
            tracing::info!(section = %section, "config section not used by this version");
        }
        tracing::info!(
            pin = %config.pin,
            thing_name = config.thing_name.as_deref().unwrap_or("(from the bootstrap service)"),
            "starting the identity manager"
        );
        let mut manager = ManagerConfig::for_bootstrap();
        manager.thing_name.clone_from(&config.thing_name);
        manager.key_label.clone_from(&config.key_label);
        manager.token_label.clone_from(&config.token_label);
        manager.certificate = config.certificate.clone();
        manager.allow_final_pin_try = config.allow_final_pin_try;
        manager.sign_timeout = config.sign_timeout;

        let cancel = CancellationToken::new();
        let (clock_samples, clock_status, clock_task) = ClockMonitor::start(
            config.clock.clone(),
            timing.clock,
            Probes::default(),
            cancel.clone(),
        );
        let pin = match config.bootstrap {
            Some(bootstrap) => {
                let client =
                    BootstrapClient::new(&bootstrap.url, bootstrap.roots, bootstrap.timeout)
                        .map_err(|error| StartFailure::config(error.to_string()))?
                        .with_clock(clock_samples.clone());
                PinSetting::Bootstrap(Box::new(BootstrapSetup {
                    client,
                    interfaces: bootstrap.interfaces,
                    sysfs: platform.sysfs.clone(),
                    permanent_addresses: platform.permanent_addresses.clone(),
                    hardware_model: hardware_model(&platform.device_tree_model),
                    challenge_key_label: bootstrap.challenge_key_label,
                    aws: config.aws.clone(),
                    timing: BootstrapTiming::default(),
                }))
            }
            None => {
                let source = config
                    .pin
                    .local_source(platform.credentials_directory.as_deref())
                    .map_err(|error| StartFailure::config(error.to_string()))?
                    .ok_or_else(|| StartFailure::config("identity.pin has no local source"))?;
                PinSetting::Local(source)
            }
        };

        let (identity, identity_task) =
            IdentityManager::start(manager, backend, pin, config.roots, cancel.clone())?;
        let local_endpoint = config.aws.as_ref().map(|aws| aws.iot_endpoint.clone());
        let helios_shadow_interval = config.mqtt.helios_shadow_interval;
        let local = config.aws.map(|aws| LocalSettings {
            credentials_endpoint: aws.credentials_endpoint,
            role_alias: aws.role_alias,
        });
        let (credentials, credentials_task) = HeliosCredentialsProvider::start(
            identity.clone(),
            local,
            timing.credentials,
            clock_samples.clone(),
            cancel.clone(),
        );
        // Custom topics and AWS IoT commands, as mqtt.commands chooses (LLD 2, section 7.3).
        let transport: Arc<dyn CommandTransport> = config.mqtt.commands.transport();
        let started = std::time::Instant::now();
        let mqtt_cancel = CancellationToken::new();
        let (incoming_tx, incoming) = mpsc::channel(INCOMING_CAPACITY);
        let (mqtt, mqtt_task) = MqttManager::start(
            identity.clone(),
            MqttOptions {
                settings: config.mqtt,
                local_endpoint,
                boot_id: platform.boot_id.clone(),
                timing: timing.mqtt,
                commands: Arc::clone(&transport),
            },
            incoming_tx,
            mqtt_cancel.clone(),
        );
        let (shadow_tx, shadow_rx) = mpsc::channel(INCOMING_CAPACITY);
        let (shadows, shadow_task) = ShadowManager::start(
            mqtt.clone(),
            shadow_rx,
            timing.shadows,
            clock_samples,
            cancel.clone(),
        );
        let started_at = std::time::SystemTime::now();
        let (commands_tx, commands_rx) = mpsc::channel(INCOMING_CAPACITY);
        let (router, router_task) = Router::start(
            mqtt.clone(),
            transport,
            commands_rx,
            timing.router,
            cancel.clone(),
        );
        let helios_commands = crate::router::helios::start(
            router.register(crate::router::helios::MODULE),
            mqtt.status(),
            started,
        );
        #[allow(
            unused_mut,
            reason = "which modules there are depends on Cargo features"
        )]
        let mut enabled: Vec<Arc<dyn Module>> = Vec::new();
        #[cfg(feature = "module-display")]
        if let Some(settings) = config.display {
            let module = display::DisplayModule::new(settings).map_err(|message| StartFailure {
                message,
                config: false,
            })?;
            enabled.push(Arc::new(module));
        }
        #[cfg(feature = "module-usb")]
        let usb = config.usb.map(|settings| {
            let handle = crate::modules::usb::UsbHandle::default();
            enabled.push(Arc::new(crate::modules::usb::UsbModule::new(
                settings,
                handle.clone(),
            )));
            handle
        });
        #[cfg(feature = "module-net")]
        if let Some(settings) = config.net {
            enabled.push(Arc::new(crate::modules::net::NetModule::new(
                settings,
                identity.watch(),
            )));
        }
        // Streams run in the stream daemon (helios-stream.service); here the module is its
        // client, so streams outlive Helios's restarts (LLD 4, section 15).
        #[cfg(feature = "module-stream")]
        if let Some(settings) = config.stream {
            enabled.push(Arc::new(crate::modules::stream::StreamClient::new(
                settings.control_socket.clone(),
            )));
        }
        let (module_states, modules) = supervisor::start(
            enabled,
            &supervisor::Deps {
                router: router.clone(),
                shadows: shadows.clone(),
                mqtt: mqtt.clone(),
                sysfs: platform.sysfs.clone(),
            },
            timing.modules,
            &cancel,
        );
        let reporter = helios_shadow::start(
            Sources {
                identity: identity.watch(),
                credentials: credentials.status(),
                mqtt: mqtt.status(),
                clock: clock_status,
                modules: module_states,
                boot_id: platform.boot_id.clone(),
                started_at,
            },
            shadows.clone(),
            helios_shadow_interval,
            cancel.clone(),
        );
        let routing = tokio::spawn(route(incoming, shadow_tx, commands_tx));
        Ok(Self {
            #[cfg(feature = "module-usb")]
            usb,
            identity,
            credentials,
            mqtt,
            shadows,
            router,
            identity_task,
            credentials_task,
            mqtt_task,
            helpers: vec![
                routing,
                shadow_task,
                reporter,
                router_task,
                helios_commands,
                clock_task,
            ],
            modules,
            cancel,
            mqtt_cancel,
        })
    }

    /// The USB monitor's handle when enabled.
    #[cfg(feature = "module-usb")]
    #[must_use]
    pub fn usb(&self) -> Option<&crate::modules::usb::UsbHandle> {
        self.usb.as_ref()
    }

    /// The device identity.
    #[must_use]
    pub fn identity(&self) -> &IdentityHandle {
        &self.identity
    }

    /// The AWS credentials provider, for the AWS SDK.
    #[must_use]
    pub fn credentials(&self) -> &HeliosCredentialsProvider {
        &self.credentials
    }

    /// The MQTT connection.
    #[must_use]
    pub fn mqtt(&self) -> &MqttHandle {
        &self.mqtt
    }

    /// The shadow manager, for modules' reported and desired state.
    #[must_use]
    pub fn shadows(&self) -> &ShadowHandle {
        &self.shadows
    }

    /// The command router, for modules to register with.
    #[must_use]
    pub fn router(&self) -> &RouterHandle {
        &self.router
    }

    /// Runs until `shutdown` completes or the identity manager stops, then stops everything
    /// and returns the exit code.
    pub async fn run_until(self, shutdown: impl Future<Output = ()>) -> u8 {
        let Self {
            identity_task,
            credentials_task,
            mqtt_task,
            helpers,
            modules,
            cancel,
            mqtt_cancel,
            ..
        } = self;
        let mut identity_task = identity_task;
        let finished = tokio::select! {
            () = shutdown => {
                tracing::info!("stopping");
                // MQTT first: lifecycle.offline needs the connection, which needs the identity.
                mqtt_cancel.cancel();
                let _ = mqtt_task.await;
                cancel.cancel();
                (&mut identity_task).await
            }
            finished = &mut identity_task => {
                mqtt_cancel.cancel();
                let _ = mqtt_task.await;
                finished
            }
        };
        cancel.cancel();
        let _ = credentials_task.await;
        for module in modules {
            if tokio::time::timeout(MODULE_STOP_TIMEOUT, module)
                .await
                .is_err()
            {
                tracing::warn!("a module didn't stop in time");
            }
        }
        for helper in helpers {
            helper.abort();
        }
        match finished {
            Ok(ManagerExit::Cancelled) => {
                tracing::info!("stopped");
                EXIT_OK
            }
            // The manager has logged why.
            Ok(ManagerExit::Fatal(_)) => EXIT_CONFIG,
            Ok(ManagerExit::SignerStopped) => EXIT_ERROR,
            Err(error) => {
                tracing::error!(%error, "the identity manager failed");
                EXIT_ERROR
            }
        }
    }
}

/// Sends incoming MQTT messages where they belong: shadow replies to the shadow manager, and
/// everything else to the router, which knows the command transport's topics.
async fn route(
    mut incoming: mpsc::Receiver<Incoming>,
    shadows: mpsc::Sender<Incoming>,
    commands: mpsc::Sender<Incoming>,
) {
    while let Some(message) = incoming.recv().await {
        let (target, name) = if message.topic.starts_with("$aws/things/") {
            (&shadows, "shadow manager")
        } else {
            (&commands, "router")
        };
        if target.try_send(message).is_err() {
            tracing::warn!("MQTT message dropped: the {name} is behind");
        }
    }
}

/// Completes on SIGTERM or SIGINT.
///
/// # Errors
///
/// Fails if the signal handlers can't be installed.
///
/// # Panics
///
/// Panics if called outside a tokio runtime.
pub fn shutdown_signal() -> std::io::Result<impl Future<Output = ()>> {
    use tokio::signal::unix::{SignalKind, signal};

    let mut terminate = signal(SignalKind::terminate())?;
    let mut interrupt = signal(SignalKind::interrupt())?;
    Ok(async move {
        tokio::select! {
            _ = terminate.recv() => {}
            _ = interrupt.recv() => {}
        }
    })
}

/// Runs the service with the config at `config_path` and returns the exit code.
#[must_use]
pub fn main(config_path: &Path) -> u8 {
    logging::init();
    tracing::info!(
        version = env!("CARGO_PKG_VERSION"),
        config = %config_path.display(),
        "helios starting"
    );
    if let Err(error) = hardening::disable_core_dumps() {
        tracing::error!(%error, "can't disable core dumps");
        return EXIT_ERROR;
    }
    let config = match Config::load(config_path, |name| std::env::var_os(name).is_some()) {
        Ok(config) => config,
        Err(error) => {
            tracing::error!(%error, "configuration error");
            return EXIT_CONFIG;
        }
    };
    let runtime = match tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
    {
        Ok(runtime) => runtime,
        Err(error) => {
            tracing::error!(%error, "can't start the async runtime");
            return EXIT_ERROR;
        }
    };
    runtime.block_on(async {
        let shutdown = match shutdown_signal() {
            Ok(shutdown) => shutdown,
            Err(error) => {
                tracing::error!(%error, "can't install signal handlers");
                return EXIT_ERROR;
            }
        };
        let backend = Box::new(CryptokiToken::new(
            &config.pkcs11_module,
            config.token_label.as_deref().unwrap_or(DEFAULT_TOKEN_LABEL),
        ));
        match Service::start(config, backend, &Platform::system(), Timing::default()) {
            Ok(service) => service.run_until(shutdown).await,
            Err(failure) => {
                tracing::error!(error = %failure, "can't start");
                failure.exit_code()
            }
        }
    })
}

#[cfg(test)]
mod tests;
