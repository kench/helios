//! `helios.toml`: parsing and the startup checks (LLD 1, section 3).
//!
//! [`Config::load`] reads the file, checks it and returns the settings ready to use. Any
//! problem is a [`ConfigError`], and Helios exits with code 78 (`EX_CONFIG`) so systemd
//! doesn't restart it until someone fixes the file. The PIN itself isn't read here; that
//! happens at login (LLD 1, section 4.5).
//!
//! Sections this version doesn't use (for example `[modules.usb]`, HLD section 8) are
//! reported by [`Config::ignored_sections`] rather than rejected, so one file can serve
//! several versions. Unknown keys inside a known section are errors, since they are most
//! likely typos.

use std::fmt;
use std::path::{Path, PathBuf};
use std::str::FromStr;
use std::time::Duration;

use rustls::RootCertStore;
use rustls_pki_types::CertificateDer;
use rustls_pki_types::pem::PemObject;
use serde::Deserialize;

use crate::clock::{ClockSettings, ERROR_OFFSET};
use crate::identity::bootstrap::adapters::Interfaces;
use crate::identity::bootstrap::api::AwsSettings;
use crate::identity::manager::CertificateSource;
use crate::identity::pin::PinSpec;
use crate::identity::signer::DEFAULT_SIGN_TIMEOUT;
use crate::identity::tls;
use crate::modules::display::DisplaySettings;
use crate::modules::display::templates::Screen;
use crate::mqtt::helios_shadow;
use crate::mqtt::{MAX_KEEP_ALIVE, MIN_KEEP_ALIVE, MqttSettings, PORT_443, PORT_8883};
use crate::provision::DEFAULT_MODULE;

/// Where the service reads its config from unless `--config` says otherwise.
pub const DEFAULT_PATH: &str = "/etc/helios/helios.toml";
/// PKCS#11 labels are at most 32 bytes (`CK_TOKEN_INFO.label`).
pub const MAX_LABEL_LEN: usize = 32;
/// AWS IoT thing names are 1 to 128 characters from `[a-zA-Z0-9:_-]`.
pub const MAX_THING_NAME_LEN: usize = 128;
/// The environment variable the SoftHSM2 module needs.
pub const SOFTHSM2_CONF: &str = "SOFTHSM2_CONF";

/// The bootstrap service's request timeout when `bootstrap.timeout_ms` isn't set.
const DEFAULT_BOOTSTRAP_TIMEOUT_MS: u64 = 10_000;

/// The display module's framebuffer when `modules.display.framebuffer` isn't set.
const DEFAULT_FRAMEBUFFER: &str = "/dev/fb0";
/// How often the display redraws while the kernel's console is attached (LLD 9, section 3).
const DEFAULT_REDRAW_INTERVAL_S: u64 = 10;
const MAX_REDRAW_INTERVAL_S: u64 = 3600;

/// The config can't be used. The message names the file and the setting.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("{path}: {message}")]
pub struct ConfigError {
    /// The config file.
    pub path: PathBuf,
    /// What's wrong.
    pub message: String,
}

/// The checked settings.
#[derive(Debug, Clone)]
pub struct Config {
    /// Where the PIN comes from (`identity.pin`).
    pub pin: PinSpec,
    /// The PKCS#11 module (`identity.pkcs11_module`).
    pub pkcs11_module: PathBuf,
    /// The token label (`identity.token_label`). Required with a local PIN.
    pub token_label: Option<String>,
    /// The device key label (`identity.key_label`). Required with a local PIN.
    pub key_label: Option<String>,
    /// The thing name (`device.thing_name`). Required with a local PIN.
    pub thing_name: Option<String>,
    /// Where the certificate comes from (`identity.certificate`).
    pub certificate: CertificateSource,
    /// `identity.allow_final_pin_try`.
    pub allow_final_pin_try: bool,
    /// `identity.sign_timeout_ms`.
    pub sign_timeout: Duration,
    /// The root CAs for AWS IoT Core and the credentials provider (`aws.root_ca`).
    pub roots: RootCertStore,
    /// The local AWS settings, when all four are set. Required with a local PIN; with
    /// bootstrap, the service's must match them.
    pub aws: Option<AwsSettings>,
    /// The `[bootstrap]` settings, when the PIN comes from the bootstrap service.
    pub bootstrap: Option<BootstrapConfig>,
    /// The `[mqtt]` settings (LLD 2, section 6).
    pub mqtt: MqttSettings,
    /// The `[clock]` settings (LLD 1, section 4.11).
    pub clock: ClockSettings,
    /// The `[modules.display]` settings, when it's enabled (LLD 9).
    pub display: Option<DisplaySettings>,
    /// Sections this version doesn't use: modules as `modules.<name>`, then top-level sections.
    pub ignored_sections: Vec<String>,
}

/// The checked `[bootstrap]` settings.
#[derive(Debug, Clone)]
pub struct BootstrapConfig {
    /// `bootstrap.url`, always `https://`.
    pub url: String,
    /// The root CAs for the service's certificate (`bootstrap.ca`).
    pub roots: RootCertStore,
    /// `bootstrap.interfaces`.
    pub interfaces: Interfaces,
    /// `bootstrap.timeout_ms`.
    pub timeout: Duration,
    /// `bootstrap.challenge_key_label`.
    pub challenge_key_label: Option<String>,
}

/// The file as written, before the checks.
#[derive(Debug, Deserialize)]
struct File {
    bootstrap: Option<BootstrapSection>,
    #[serde(default)]
    device: DeviceSection,
    identity: IdentitySection,
    aws: AwsSection,
    #[serde(default)]
    mqtt: MqttSection,
    #[serde(default)]
    clock: ClockSection,
    #[serde(default)]
    modules: ModulesSection,
    /// Everything else: sections for other versions.
    #[serde(flatten)]
    other: toml::Table,
}

/// `[modules.*]`: the ones this version has, and the rest, which are ignored.
#[derive(Debug, Default, Deserialize)]
struct ModulesSection {
    display: Option<DisplaySection>,
    #[serde(flatten)]
    other: toml::Table,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct DisplaySection {
    #[serde(default)]
    enabled: bool,
    framebuffer: Option<PathBuf>,
    idle_template: Option<String>,
    time_zone: Option<String>,
    redraw_interval_s: Option<u64>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct BootstrapSection {
    url: String,
    ca: PathBuf,
    #[serde(default)]
    interfaces: Option<InterfacesSetting>,
    timeout_ms: Option<u64>,
    challenge_key_label: Option<String>,
}

/// `"auto"` or a list of interface names.
#[derive(Debug, Deserialize)]
#[serde(untagged)]
enum InterfacesSetting {
    Word(String),
    List(Vec<String>),
}

#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct DeviceSection {
    thing_name: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct IdentitySection {
    pkcs11_module: Option<PathBuf>,
    token_label: Option<String>,
    key_label: Option<String>,
    certificate: Option<String>,
    pin: String,
    #[serde(default)]
    allow_final_pin_try: bool,
    sign_timeout_ms: Option<u64>,
}

#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct MqttSection {
    port: Option<u16>,
    keep_alive_s: Option<u64>,
    queue_messages: Option<usize>,
    commands: Option<String>,
    helios_shadow_interval_s: Option<u64>,
}

#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct ClockSection {
    warn_offset_s: Option<u64>,
    state_file: Option<PathBuf>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct AwsSection {
    region: Option<String>,
    iot_endpoint: Option<String>,
    credentials_endpoint: Option<String>,
    role_alias: Option<String>,
    root_ca: PathBuf,
}

impl Config {
    /// Reads and checks the config at `path`. `env_is_set` says whether an environment
    /// variable is set; normally `|name| std::env::var_os(name).is_some()`.
    ///
    /// # Errors
    ///
    /// [`ConfigError`] if the file can't be read or parsed, or a startup check fails.
    pub fn load(path: &Path, env_is_set: impl Fn(&str) -> bool) -> Result<Self, ConfigError> {
        let error = |message: String| ConfigError {
            path: path.to_owned(),
            message,
        };
        let text = std::fs::read_to_string(path).map_err(|e| error(e.to_string()))?;
        let file: File = toml::from_str(&text).map_err(|e| error(e.to_string()))?;
        file.check(env_is_set).map_err(error)
    }
}

impl File {
    fn check(self, env_is_set: impl Fn(&str) -> bool) -> Result<Config, String> {
        let pin = PinSpec::from_str(&self.identity.pin).map_err(|e| e.to_string())?;
        let token_label = optional_label("identity.token_label", self.identity.token_label)?;
        let key_label = optional_label("identity.key_label", self.identity.key_label)?;
        let thing_name = self.device.thing_name.map(thing_name).transpose()?;
        let aws = aws_settings(&self.aws)?;

        let bootstrap = match (&pin, self.bootstrap) {
            (PinSpec::Bootstrap, Some(section)) => Some(section.check()?),
            (PinSpec::Bootstrap, None) => {
                return Err(
                    "identity.pin = \"bootstrap\" needs a [bootstrap] section with url and ca"
                        .to_owned(),
                );
            }
            // A [bootstrap] section is allowed but unused with a local PIN, so switching
            // between the two is a one-line change.
            (_, _) => None,
        };
        if bootstrap.is_none() {
            for (value, name) in [
                (thing_name.is_some(), "device.thing_name"),
                (token_label.is_some(), "identity.token_label"),
                (key_label.is_some(), "identity.key_label"),
                (
                    aws.is_some(),
                    "aws.region, aws.iot_endpoint, aws.credentials_endpoint and aws.role_alias",
                ),
            ] {
                if !value {
                    return Err(format!(
                        "{name} must be set when the PIN is not from the bootstrap service"
                    ));
                }
            }
        }

        let pkcs11_module = self
            .identity
            .pkcs11_module
            .unwrap_or_else(|| PathBuf::from(DEFAULT_MODULE));
        readable("identity.pkcs11_module", &pkcs11_module)?;
        let module_name = pkcs11_module.file_name().unwrap_or_default();
        if module_name.to_string_lossy().contains("softhsm") && !env_is_set(SOFTHSM2_CONF) {
            return Err(format!(
                "{SOFTHSM2_CONF} must be set for the SoftHSM2 module {}; set it in the systemd \
                 unit",
                pkcs11_module.display()
            ));
        }

        Ok(Config {
            pin,
            pkcs11_module,
            token_label,
            key_label,
            thing_name,
            certificate: certificate(self.identity.certificate.as_deref())?,
            allow_final_pin_try: self.identity.allow_final_pin_try,
            sign_timeout: self
                .identity
                .sign_timeout_ms
                .map_or(DEFAULT_SIGN_TIMEOUT, Duration::from_millis),
            roots: roots("aws.root_ca", &self.aws.root_ca)?,
            aws,
            bootstrap,
            mqtt: self.mqtt.check()?,
            clock: self.clock.check()?,
            display: self
                .modules
                .display
                .map(DisplaySection::check)
                .transpose()?
                .flatten(),
            ignored_sections: self
                .modules
                .other
                .keys()
                .map(|name| format!("modules.{name}"))
                .chain(self.other.keys().cloned())
                .collect(),
        })
    }
}

impl DisplaySection {
    /// The settings, or `None` when the module isn't enabled.
    fn check(self) -> Result<Option<DisplaySettings>, String> {
        if !self.enabled {
            return Ok(None);
        }
        let idle_template = self.idle_template.unwrap_or_else(|| "status".to_owned());
        let idle = Screen::parse(&idle_template, &serde_json::Value::Null).map_err(|error| {
            format!(
                "modules.display.idle_template: {error} (status, blank or test; other templates \
                 need fields, which only the shadow's desired state can set)"
            )
        })?;
        let time_zone_name = self.time_zone.unwrap_or_else(|| "UTC".to_owned());
        let time_zone = if time_zone_name == "UTC" {
            jiff::tz::TimeZone::UTC
        } else {
            jiff::tz::db().get(&time_zone_name).map_err(|error| {
                format!(
                    "modules.display.time_zone {time_zone_name:?} isn't a known time zone \
                     (an IANA name such as \"America/Los_Angeles\"): {error}"
                )
            })?
        };
        let redraw = self.redraw_interval_s.unwrap_or(DEFAULT_REDRAW_INTERVAL_S);
        if redraw > MAX_REDRAW_INTERVAL_S {
            return Err(format!(
                "modules.display.redraw_interval_s must be 0 to {MAX_REDRAW_INTERVAL_S}, not \
                 {redraw}"
            ));
        }
        Ok(Some(DisplaySettings {
            framebuffer: self
                .framebuffer
                .unwrap_or_else(|| PathBuf::from(DEFAULT_FRAMEBUFFER)),
            idle,
            time_zone_name,
            time_zone,
            redraw_interval: Duration::from_secs(redraw),
        }))
    }
}

impl ClockSection {
    fn check(self) -> Result<ClockSettings, String> {
        let defaults = ClockSettings::default();
        let warn_offset = self
            .warn_offset_s
            .map_or(defaults.warn_offset, Duration::from_secs);
        if warn_offset.is_zero() || warn_offset >= ERROR_OFFSET {
            return Err(format!(
                "clock.warn_offset_s must be from 1 to {}, below the error level, not {}",
                ERROR_OFFSET.as_secs() - 1,
                warn_offset.as_secs()
            ));
        }
        if self.state_file.is_some() {
            return Err(
                "clock.state_file isn't supported yet (LLD 1, section 4.11); leave it unset"
                    .to_owned(),
            );
        }
        Ok(ClockSettings {
            warn_offset,
            ..defaults
        })
    }
}

impl MqttSection {
    fn check(self) -> Result<MqttSettings, String> {
        let defaults = MqttSettings::default();
        let port = self.port.unwrap_or(defaults.port);
        if port != PORT_8883 && port != PORT_443 {
            return Err(format!(
                "mqtt.port must be {PORT_8883} or {PORT_443} (AWS IoT's MQTT ports), not {port}"
            ));
        }
        let keep_alive = self
            .keep_alive_s
            .map_or(defaults.keep_alive, Duration::from_secs);
        if !(MIN_KEEP_ALIVE..=MAX_KEEP_ALIVE).contains(&keep_alive) {
            return Err(format!(
                "mqtt.keep_alive_s must be {} to {} (AWS IoT's range), not {}",
                MIN_KEEP_ALIVE.as_secs(),
                MAX_KEEP_ALIVE.as_secs(),
                keep_alive.as_secs()
            ));
        }
        let queue_messages = self.queue_messages.unwrap_or(defaults.queue_messages);
        if queue_messages == 0 {
            return Err("mqtt.queue_messages must be at least 1".to_owned());
        }
        match self.commands.as_deref() {
            None | Some("topics") => {}
            Some("aws-iot-commands") => {
                return Err(
                    "mqtt.commands = \"aws-iot-commands\" isn't supported yet (LLD 2, section 7.3); \
                     use \"topics\""
                        .to_owned(),
                );
            }
            Some(other) => {
                return Err(format!(
                    "mqtt.commands must be \"topics\" or \"aws-iot-commands\", not {other:?}"
                ));
            }
        }
        let helios_shadow_interval = self
            .helios_shadow_interval_s
            .map_or(defaults.helios_shadow_interval, Duration::from_secs);
        if !(helios_shadow::MIN_INTERVAL..=helios_shadow::MAX_INTERVAL)
            .contains(&helios_shadow_interval)
        {
            return Err(format!(
                "mqtt.helios_shadow_interval_s must be {} to {}, not {}",
                helios_shadow::MIN_INTERVAL.as_secs(),
                helios_shadow::MAX_INTERVAL.as_secs(),
                helios_shadow_interval.as_secs()
            ));
        }
        Ok(MqttSettings {
            port,
            keep_alive,
            queue_messages,
            helios_shadow_interval,
        })
    }
}

impl BootstrapSection {
    fn check(self) -> Result<BootstrapConfig, String> {
        if !self.url.starts_with("https://") {
            return Err(format!(
                "bootstrap.url must start with https://, not {:?}",
                self.url
            ));
        }
        let interfaces = match self.interfaces {
            None => Interfaces::Auto,
            Some(InterfacesSetting::Word(word)) if word == "auto" => Interfaces::Auto,
            Some(InterfacesSetting::Word(word)) => {
                return Err(format!(
                    "bootstrap.interfaces must be \"auto\" or a list of names, not {word:?}"
                ));
            }
            Some(InterfacesSetting::List(names)) if names.is_empty() => {
                return Err("bootstrap.interfaces must not be an empty list".to_owned());
            }
            Some(InterfacesSetting::List(names)) => Interfaces::Named(names),
        };
        Ok(BootstrapConfig {
            roots: roots("bootstrap.ca", &self.ca)?,
            url: self.url,
            interfaces,
            timeout: Duration::from_millis(self.timeout_ms.unwrap_or(DEFAULT_BOOTSTRAP_TIMEOUT_MS)),
            challenge_key_label: optional_label(
                "bootstrap.challenge_key_label",
                self.challenge_key_label,
            )?,
        })
    }
}

fn optional_label(name: &str, label: Option<String>) -> Result<Option<String>, String> {
    match label {
        Some(label) if label.is_empty() || label.len() > MAX_LABEL_LEN => Err(format!(
            "{name} must be 1 to {MAX_LABEL_LEN} bytes, not {} bytes",
            label.len()
        )),
        label => Ok(label),
    }
}

fn thing_name(name: String) -> Result<String, String> {
    let valid = (1..=MAX_THING_NAME_LEN).contains(&name.len())
        && name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b':' | b'_' | b'-'));
    if valid {
        Ok(name)
    } else {
        Err(format!(
            "device.thing_name {name:?} is not a valid AWS IoT thing name (1 to \
             {MAX_THING_NAME_LEN} of a-z, A-Z, 0-9, ':', '_' and '-')"
        ))
    }
}

/// All four `[aws]` endpoint settings, or none.
fn aws_settings(section: &AwsSection) -> Result<Option<AwsSettings>, String> {
    match (
        &section.region,
        &section.iot_endpoint,
        &section.credentials_endpoint,
        &section.role_alias,
    ) {
        (Some(region), Some(iot), Some(credentials), Some(alias)) => Ok(Some(AwsSettings {
            region: region.clone(),
            iot_endpoint: iot.clone(),
            credentials_endpoint: credentials.clone(),
            role_alias: alias.clone(),
        })),
        (None, None, None, None) => Ok(None),
        _ => Err(
            "aws.region, aws.iot_endpoint, aws.credentials_endpoint and aws.role_alias must be \
             set together, or all left out"
                .to_owned(),
        ),
    }
}

fn readable(name: &str, path: &Path) -> Result<(), String> {
    std::fs::File::open(path)
        .map(drop)
        .map_err(|e| format!("{name} {}: {e}", path.display()))
}

fn roots(name: &str, path: &Path) -> Result<RootCertStore, String> {
    let pem = std::fs::read(path).map_err(|e| format!("{name} {}: {e}", path.display()))?;
    tls::root_store_from_pem(&pem).map_err(|e| format!("{name} {}: {e}", path.display()))
}

fn certificate(value: Option<&str>) -> Result<CertificateSource, String> {
    let path = match value {
        None | Some("token") => return Ok(CertificateSource::Token),
        Some(path) => Path::new(path),
    };
    let error = |message: &dyn fmt::Display| {
        format!(
            "identity.certificate must be \"token\" or a PEM file: {}: {message}",
            path.display()
        )
    };
    let chain = CertificateDer::pem_file_iter(path)
        .map_err(|e| error(&e))?
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| error(&e))?;
    if chain.is_empty() {
        return Err(error(&"no certificates in the file"));
    }
    Ok(CertificateSource::Chain(chain))
}

#[cfg(test)]
mod tests;
