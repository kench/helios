//! The `web` module (LLD 13): the Helios console served by the board itself, for phones and
//! laptops on the same network, with no internet. It serves the console's files and a local
//! version of the Control API: the same paths and JSON as the cloud's, for this one device.
//!
//! [`reports`] reads the modules' reports into the Control API's responses exactly as the cloud
//! does (helios-contract's report vectors check both), and [`auth`] signs people in with the
//! device password.

use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use serde::Deserialize;
use serde_json::json;
use tokio::sync::watch;

use super::{Module, ModuleContext, ModuleError, ModuleFuture};
use crate::identity::manager::IdentityState;
use crate::router::RouterHandle;

pub(crate) mod auth;
pub(crate) mod control;
pub(crate) mod http;
pub(crate) mod reports;
pub(crate) mod server;

/// Where the console listens by default: every interface, port 8080 (Helios's firewall lets
/// only private and link-local addresses reach it, LLD 13 section 5).
pub const DEFAULT_LISTEN: &str = "0.0.0.0:8080";
/// Where the `helios-console` package puts the console's build.
pub const DEFAULT_CONSOLE_DIR: &str = "/usr/share/helios-console";

/// `[modules.web]`.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct WebSettings {
    pub(crate) enabled: bool,
    /// The board's short name: published as `helios-<name>.local` (LLD 13, section 7).
    pub(crate) name: String,
    /// The address and port to listen on.
    pub(crate) listen: String,
    /// The device password's Argon2id hash (`helios web hash-password`).
    pub(crate) password_hash: Option<String>,
    /// The console's files.
    pub(crate) console_dir: PathBuf,
    /// This device's role, as ListDevices shows it (the cloud's registry knows it, the board
    /// doesn't): `transcoder` or `relay`.
    pub(crate) role: String,
}

impl Default for WebSettings {
    fn default() -> Self {
        Self {
            enabled: true,
            name: String::new(),
            listen: DEFAULT_LISTEN.into(),
            password_hash: None,
            console_dir: DEFAULT_CONSOLE_DIR.into(),
            role: "transcoder".into(),
        }
    }
}

impl WebSettings {
    /// The settings if the module is enabled, checked.
    ///
    /// # Errors
    ///
    /// A message naming the setting that's wrong.
    pub(crate) fn check(self) -> Result<Option<Self>, String> {
        if !self.enabled {
            return Ok(None);
        }
        let name_ok = !self.name.is_empty()
            && self.name.len() <= 56
            && self
                .name
                .bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
            && !self.name.starts_with('-')
            && !self.name.ends_with('-');
        if !name_ok {
            return Err(format!(
                "modules.web.name: {:?} must be 1 to 56 lower-case letters, digits and -, such as \
                 pocket (the board is helios-<name>.local)",
                self.name
            ));
        }
        self.listen.parse::<SocketAddr>().map_err(|_| {
            format!(
                "modules.web.listen: {:?} isn't an IP address and port, such as {DEFAULT_LISTEN}",
                self.listen
            )
        })?;
        match &self.password_hash {
            Some(hash) if auth::is_argon2id(hash) => {}
            Some(_) => {
                return Err(
                    "modules.web.password_hash isn't an Argon2id hash ($argon2id$v=19$...): make \
                     one with helios web hash-password"
                        .into(),
                );
            }
            None => {
                return Err(
                    "modules.web.password_hash is required: the console never runs without a \
                     password (helios web hash-password makes the hash)"
                        .into(),
                );
            }
        }
        if !self.console_dir.is_absolute() {
            return Err("modules.web.console_dir must be an absolute path".into());
        }
        if !matches!(self.role.as_str(), "transcoder" | "relay") {
            return Err(format!(
                "modules.web.role: {:?} must be transcoder or relay",
                self.role
            ));
        }
        Ok(Some(self))
    }

    /// The address to listen on (checked).
    #[must_use]
    pub fn listen(&self) -> SocketAddr {
        self.listen
            .parse()
            .unwrap_or_else(|_| SocketAddr::from(([0, 0, 0, 0], 8080)))
    }
}

/// The module's name: its config section and its shadow.
pub const MODULE: &str = "web";

/// The web module: serves the console and the local Control API.
#[derive(Debug)]
pub struct WebModule {
    settings: WebSettings,
    router: Option<RouterHandle>,
    identity: Option<watch::Receiver<IdentityState>>,
    thing_name: Option<String>,
}

impl WebModule {
    /// A module serving `settings`.
    #[must_use]
    pub fn new(settings: WebSettings) -> Self {
        Self {
            settings,
            router: None,
            identity: None,
            thing_name: None,
        }
    }

    /// The router the local console's changes go through, as commands.
    #[must_use]
    pub fn with_router(mut self, router: RouterHandle) -> Self {
        self.router = Some(router);
        self
    }

    /// The identity, for the device's ID once it has bootstrapped.
    #[must_use]
    pub fn with_identity(mut self, identity: watch::Receiver<IdentityState>) -> Self {
        self.identity = Some(identity);
        self
    }

    /// The thing name from `helios.toml`: the device's ID until it has bootstrapped.
    #[must_use]
    pub fn with_thing_name(mut self, thing_name: Option<String>) -> Self {
        self.thing_name = thing_name;
        self
    }
}

impl Module for WebModule {
    fn name(&self) -> &'static str {
        MODULE
    }

    fn run(&self, ctx: ModuleContext) -> ModuleFuture<'_> {
        Box::pin(async move {
            let router = self
                .router
                .clone()
                .ok_or_else(|| ModuleError("the web module has no router".into()))?;
            let address = self.settings.listen();
            let listener = tokio::net::TcpListener::bind(address)
                .await
                .map_err(|error| ModuleError(format!("can't listen on {address}: {error}")))?;
            let installed = self.settings.console_dir.join("index.html").is_file();
            tracing::info!(%address, name = %self.settings.name, installed, "web console listening");
            let mut reported = serde_json::Map::new();
            reported.insert("name".into(), json!(self.settings.name));
            reported.insert("listen".into(), json!(address.to_string()));
            reported.insert("console_installed".into(), json!(installed));
            ctx.shadows.report(MODULE, reported);
            let web = Arc::new(http::Web {
                device: control::Device {
                    shadows: ctx.shadows.clone(),
                    router,
                    mqtt: ctx.mqtt.clone(),
                    identity: self.identity.clone(),
                    thing_name: self.thing_name.clone(),
                    role: self.settings.role.clone(),
                },
                name: self.settings.name.clone(),
                password_hash: self.settings.password_hash.clone().unwrap_or_default(),
                console_dir: self.settings.console_dir.clone(),
                sessions: Mutex::new(auth::Sessions::default()),
                throttle: Mutex::new(auth::Throttle::default()),
            });
            server::run(listener, web, ctx.cancel.clone()).await;
            Ok(())
        })
    }
}

#[cfg(test)]
mod tests;
