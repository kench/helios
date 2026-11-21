//! The Helios service: `helios` with no subcommand, as run by `helios.service` (LLD 1,
//! section 6).
//!
//! It loads `helios.toml`, starts the identity manager (with the bootstrap service or a local
//! PIN) and the credentials refresher, and runs until SIGTERM or SIGINT, or until the identity
//! fails. MQTT and the modules come later (LLD 2).
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

use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;

use crate::cli::{EXIT_CONFIG, EXIT_ERROR, EXIT_OK};
use crate::config::Config;
use crate::credentials::provider::{HeliosCredentialsProvider, LocalSettings, Timing};
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
use crate::provision::DEFAULT_TOKEN_LABEL;
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
}

impl Platform {
    /// The real device.
    #[must_use]
    pub fn system() -> Self {
        Self {
            sysfs: PathBuf::from("/sys"),
            permanent_addresses: Arc::new(Rtnetlink),
            device_tree_model: PathBuf::from(DEVICE_TREE_MODEL),
            credentials_directory: credentials_directory_from_env(),
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
    identity: IdentityHandle,
    credentials: HeliosCredentialsProvider,
    identity_task: JoinHandle<ManagerExit>,
    credentials_task: JoinHandle<()>,
    cancel: CancellationToken,
}

impl Service {
    /// Starts the identity manager with `backend` and the credentials refresher.
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

        let pin = match config.bootstrap {
            Some(bootstrap) => {
                let client =
                    BootstrapClient::new(&bootstrap.url, bootstrap.roots, bootstrap.timeout)
                        .map_err(|error| StartFailure::config(error.to_string()))?;
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

        let cancel = CancellationToken::new();
        let (identity, identity_task) =
            IdentityManager::start(manager, backend, pin, config.roots, cancel.clone())?;
        let local = config.aws.map(|aws| LocalSettings {
            credentials_endpoint: aws.credentials_endpoint,
            role_alias: aws.role_alias,
        });
        let (credentials, credentials_task) =
            HeliosCredentialsProvider::start(identity.clone(), local, timing, cancel.clone());
        Ok(Self {
            identity,
            credentials,
            identity_task,
            credentials_task,
            cancel,
        })
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

    /// Runs until `shutdown` completes or the identity manager stops, then stops everything
    /// and returns the exit code.
    pub async fn run_until(self, shutdown: impl Future<Output = ()>) -> u8 {
        let Self {
            identity_task,
            credentials_task,
            cancel,
            ..
        } = self;
        let mut identity_task = identity_task;
        let finished = tokio::select! {
            () = shutdown => {
                tracing::info!("stopping");
                cancel.cancel();
                (&mut identity_task).await
            }
            finished = &mut identity_task => finished,
        };
        cancel.cancel();
        let _ = credentials_task.await;
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
