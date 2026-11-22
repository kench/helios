//! Wi-Fi networks for the WLAN adapter to join (LLD 3, section 10; net module part 2).
//!
//! Helios runs unprivileged, so it only keeps the wanted networks in its own store,
//! `/var/lib/helios/wifi/networks.json` (0600). Writing the store starts `helios-wifi.service`
//! (through `helios-wifi.path`), a root oneshot that runs `helios wifi-apply`: it checks the
//! store again, renders it for the board's network configuration and applies it:
//!
//! - netplan (Armbian): its own `/etc/netplan/60-helios-wifi.yaml`, then `netplan apply`;
//! - NetworkManager (Raspberry Pi OS): one `helios-wifi-NN.nmconnection` keyfile per network in
//!   `/etc/NetworkManager/system-connections`, then `nmcli connection reload`.
//!
//! It never touches the board's other configuration, and removing its files reverts it. It
//! records what it did in `/var/lib/helios-wifi/status.json`, which the net module reports.
//!
//! Passphrases are secrets: they're never logged, put in a shadow, an event or an argument list,
//! and the files that hold them are readable only by their owner. Personal (WPA-PSK) and open
//! networks; 802.1X is out of scope (owner, 2026-11-22). netplan has no priority for access
//! points, so there's none here yet.

use std::fmt;
use std::io::{self, Write};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::time::SystemTime;

use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

use crate::mqtt::envelope::timestamp;

/// The store Helios writes.
pub(crate) const STORE: &str = "/var/lib/helios/wifi/networks.json";
/// Where `helios wifi-apply` records what it did.
pub(crate) const STATUS: &str = "/var/lib/helios-wifi/status.json";
/// At most this many networks.
pub(crate) const MAX_NETWORKS: usize = 16;
/// The netplan file `helios wifi-apply` owns, under the root.
const NETPLAN_FILE: &str = "etc/netplan/60-helios-wifi.yaml";
/// Where NetworkManager keeps connections, under the root.
const NM_CONNECTIONS: &str = "etc/NetworkManager/system-connections";
/// The prefix of the keyfiles `helios wifi-apply` owns.
const NM_PREFIX: &str = "helios-wifi-";

/// Why a network can't be saved. The codes are the commands' error codes; the Control API
/// passes them on as `WifiNetworkRefused.reason`, lower-cased.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub(crate) enum Refused {
    #[error("the SSID must be 1 to 32 bytes of UTF-8 without control characters")]
    InvalidSsid,
    #[error("the passphrase must be 8 to 63 printable ASCII characters, or 64 hexadecimal digits")]
    InvalidPassphrase,
    #[error("the device keeps at most {MAX_NETWORKS} Wi-Fi networks")]
    TooMany,
    #[error("the device has no Wi-Fi adapter")]
    NoAdapter,
}

impl Refused {
    pub(crate) fn code(&self) -> &'static str {
        match self {
            Self::InvalidSsid => "INVALID_SSID",
            Self::InvalidPassphrase => "INVALID_PASSPHRASE",
            Self::TooMany => "TOO_MANY",
            Self::NoAdapter => "NO_ADAPTER",
        }
    }
}

/// A passphrase: never shown by `Debug`, wiped from memory when dropped.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(transparent)]
pub(crate) struct Passphrase(String);

impl Passphrase {
    /// `text`, if it's a valid WPA passphrase or hex PSK.
    pub(crate) fn new(text: String) -> Result<Self, Refused> {
        let passphrase = Self(text);
        passphrase.check()?;
        Ok(passphrase)
    }

    fn check(&self) -> Result<(), Refused> {
        let text = &self.0;
        let printable =
            (8..=63).contains(&text.len()) && text.bytes().all(|b| (0x20..=0x7e).contains(&b));
        let hex = text.len() == 64 && text.bytes().all(|b| b.is_ascii_hexdigit());
        if printable || hex {
            Ok(())
        } else {
            Err(Refused::InvalidPassphrase)
        }
    }

    pub(crate) fn expose(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for Passphrase {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Passphrase(..)")
    }
}

impl Drop for Passphrase {
    fn drop(&mut self) {
        secrecy::zeroize::Zeroize::zeroize(&mut self.0);
    }
}

/// One network.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Network {
    pub(crate) ssid: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) passphrase: Option<Passphrase>,
    #[serde(default)]
    pub(crate) hidden: bool,
}

impl Network {
    /// Checks every field.
    pub(crate) fn check(&self) -> Result<(), Refused> {
        check_ssid(&self.ssid)?;
        self.passphrase.as_ref().map_or(Ok(()), Passphrase::check)
    }

    /// What may be shown: everything but the passphrase.
    pub(crate) fn summary(&self) -> Value {
        json!({
            "ssid": self.ssid,
            "security": if self.passphrase.is_some() { "personal" } else { "open" },
            "hidden": self.hidden,
        })
    }
}

/// An SSID Helios accepts: 1 to 32 bytes of UTF-8, no control characters (so it can't break the
/// files it's written into).
pub(crate) fn check_ssid(ssid: &str) -> Result<(), Refused> {
    if (1..=32).contains(&ssid.len()) && !ssid.chars().any(char::is_control) {
        Ok(())
    } else {
        Err(Refused::InvalidSsid)
    }
}

/// The store's file.
#[derive(Debug, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct StoreFile {
    version: u32,
    networks: Vec<Network>,
}

/// The networks Helios wants, in its store.
#[derive(Debug, Clone)]
pub(crate) struct Store {
    path: PathBuf,
}

impl Store {
    pub(crate) fn new(path: impl Into<PathBuf>) -> Self {
        Self { path: path.into() }
    }

    pub(crate) fn path(&self) -> &Path {
        &self.path
    }

    /// The saved networks; none if there's no store yet.
    ///
    /// # Errors
    ///
    /// The store can't be read or doesn't parse, or holds an invalid network.
    pub(crate) fn load(&self) -> io::Result<Vec<Network>> {
        let bytes = match std::fs::read(&self.path) {
            Ok(bytes) => bytes,
            Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(Vec::new()),
            Err(error) => return Err(error),
        };
        // serde's message can quote a value, which could be a passphrase: say only where.
        let file: StoreFile = serde_json::from_slice(&bytes).map_err(|error| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!(
                    "{}: doesn't parse at line {}, column {}",
                    self.path.display(),
                    error.line(),
                    error.column()
                ),
            )
        })?;
        if file.networks.len() > MAX_NETWORKS {
            return Err(invalid_store(&self.path, &Refused::TooMany));
        }
        for network in &file.networks {
            network
                .check()
                .map_err(|refused| invalid_store(&self.path, &refused))?;
        }
        Ok(file.networks)
    }

    /// Adds `network`, or replaces the one with its SSID.
    ///
    /// # Errors
    ///
    /// [`StoreError::Refused`] for an invalid network or one too many; [`StoreError::Io`] if the
    /// store can't be read or written.
    pub(crate) fn set(&self, network: Network) -> Result<(), StoreError> {
        network.check()?;
        let mut networks = self.load()?;
        if let Some(existing) = networks.iter_mut().find(|n| n.ssid == network.ssid) {
            *existing = network;
        } else if networks.len() >= MAX_NETWORKS {
            return Err(Refused::TooMany.into());
        } else {
            networks.push(network);
        }
        self.save(networks)?;
        Ok(())
    }

    /// Removes the network with `ssid`; whether there was one.
    ///
    /// # Errors
    ///
    /// The store can't be read or written.
    pub(crate) fn remove(&self, ssid: &str) -> io::Result<bool> {
        let mut networks = self.load()?;
        let before = networks.len();
        networks.retain(|network| network.ssid != ssid);
        if networks.len() == before {
            return Ok(false);
        }
        self.save(networks)?;
        Ok(true)
    }

    /// Writes the store atomically, 0600, owned by whoever owns its directory (so a store
    /// written by root through `helios wifi` stays Helios's).
    fn save(&self, networks: Vec<Network>) -> io::Result<()> {
        let dir = self
            .path
            .parent()
            .ok_or_else(|| io::Error::other("the store has no directory"))?;
        if !dir.exists() {
            std::fs::create_dir_all(dir)?;
            std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700))?;
            if let Some(owner) = dir
                .parent()
                .and_then(|parent| std::fs::metadata(parent).ok())
            {
                own(dir, &owner);
            }
        }
        let file = StoreFile {
            version: 1,
            networks,
        };
        let mut bytes = serde_json::to_vec_pretty(&file).map_err(io::Error::from)?;
        bytes.push(b'\n');
        let result = write_private(&self.path, &bytes);
        secrecy::zeroize::Zeroize::zeroize(&mut bytes);
        result?;
        if let Ok(owner) = std::fs::metadata(dir) {
            own(&self.path, &owner);
        }
        Ok(())
    }
}

/// Gives `path` the owner of `like`, when running as root; otherwise it's already ours.
fn own(path: &Path, like: &std::fs::Metadata) {
    let _ = std::os::unix::fs::chown(path, Some(like.uid()), Some(like.gid()));
}

fn invalid_store(path: &Path, refused: &Refused) -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidData,
        format!("{}: {refused}", path.display()),
    )
}

/// Why [`Store::set`] failed.
#[derive(Debug, thiserror::Error)]
pub(crate) enum StoreError {
    #[error(transparent)]
    Refused(#[from] Refused),
    #[error(transparent)]
    Io(#[from] io::Error),
}

/// Writes `bytes` to a temporary file next to `path`, mode 0600, then renames it over `path`.
fn write_private(path: &Path, bytes: &[u8]) -> io::Result<()> {
    let name = path
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or_else(|| io::Error::other("no file name"))?;
    let temporary = path.with_file_name(format!(".{name}.tmp"));
    let _ = std::fs::remove_file(&temporary);
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&temporary)?;
    file.write_all(bytes)?;
    file.sync_all()?;
    drop(file);
    std::fs::rename(&temporary, path)
}

// --- Applying (as root) --------------------------------------------------------------------

/// The network configuration the board uses.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Backend {
    Netplan,
    NetworkManager,
}

impl Backend {
    /// NetworkManager if it's running (`/run/NetworkManager`), else netplan if it's installed
    /// (`/etc/netplan`), under `root`.
    pub(crate) fn detect(root: &Path) -> Option<Self> {
        if root.join("run/NetworkManager").is_dir() {
            Some(Self::NetworkManager)
        } else if root.join("etc/netplan").is_dir() {
            Some(Self::Netplan)
        } else {
            None
        }
    }

    fn name(self) -> &'static str {
        match self {
            Self::Netplan => "netplan",
            Self::NetworkManager => "networkmanager",
        }
    }
}

/// netplan's YAML for `networks`, or `None` if there are none (then the file is removed). One
/// `wifis` entry matches every WLAN interface (`wl*`) with DHCP for IPv4 and IPv6, as Armbian's
/// own file does for Ethernet. Strings are written as JSON strings, which YAML reads the same.
pub(crate) fn netplan(networks: &[Network]) -> Option<String> {
    if networks.is_empty() {
        return None;
    }
    let quote = |text: &str| serde_json::to_string(text).unwrap_or_default();
    let mut yaml = String::from(
        "# Written by helios wifi-apply from Helios's Wi-Fi networks (LLD 3, section 10).\n\
         # Change them with `helios wifi` or the Control API, not here.\n\
         network:\n  version: 2\n  renderer: networkd\n  wifis:\n    helios-wifi:\n      \
         match:\n        name: \"wl*\"\n      dhcp4: true\n      dhcp6: true\n      \
         ipv6-privacy: true\n      access-points:\n",
    );
    for network in networks {
        yaml.push_str(&format!("        {}:\n", quote(&network.ssid)));
        match &network.passphrase {
            Some(passphrase) => {
                yaml.push_str(&format!(
                    "          password: {}\n",
                    quote(passphrase.expose())
                ));
            }
            None => yaml.push_str("          auth:\n            key-management: none\n"),
        }
        if network.hidden {
            yaml.push_str("          hidden: true\n");
        }
    }
    Some(yaml)
}

/// NetworkManager keyfiles for `networks`: (file name, contents). The SSID is written as its
/// bytes, so any character works.
pub(crate) fn keyfiles(networks: &[Network]) -> Vec<(String, String)> {
    networks
        .iter()
        .enumerate()
        .map(|(n, network)| {
            let id = format!("{NM_PREFIX}{:02}", n + 1);
            let ssid: Vec<String> = network.ssid.bytes().map(|b| b.to_string()).collect();
            let mut text = format!(
                "# Written by helios wifi-apply from Helios's Wi-Fi networks (LLD 3, section 10).\n\
                 [connection]\nid={id}\ntype=wifi\nautoconnect=true\n\n\
                 [wifi]\nmode=infrastructure\nssid={};\nhidden={}\n\n",
                ssid.join(";"),
                network.hidden,
            );
            if let Some(passphrase) = &network.passphrase {
                text.push_str(&format!(
                    "[wifi-security]\nkey-mgmt=wpa-psk\npsk={}\n\n",
                    keyfile_escape(passphrase.expose())
                ));
            }
            text.push_str("[ipv4]\nmethod=auto\n\n[ipv6]\nmethod=auto\nip6-privacy=2\n");
            (format!("{id}.nmconnection"), text)
        })
        .collect()
}

/// GLib key file escaping for a value: backslashes, and a leading space.
fn keyfile_escape(text: &str) -> String {
    let escaped = text.replace('\\', "\\\\");
    match escaped.strip_prefix(' ') {
        Some(rest) => format!("\\s{rest}"),
        None => escaped,
    }
}

/// What `helios wifi-apply` did, as `status.json` and the net shadow's `wifi.applied` have it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct Status {
    pub(crate) at: String,
    pub(crate) backend: Option<String>,
    pub(crate) networks: usize,
    pub(crate) error: Option<String>,
}

/// Runs a fixed command (never with a secret in it).
pub(crate) type Run<'a> = &'a mut dyn FnMut(&str, &[&str]) -> io::Result<()>;

/// Renders `store` for the board under `root` (normally `/`), applies it with `run`, and records
/// the result in `status`. Returns the status written.
///
/// # Errors
///
/// The status couldn't be written. A failure to apply is in the status, not an error.
pub(crate) fn apply(store: &Store, root: &Path, status: &Path, run: Run<'_>) -> io::Result<Status> {
    let result = Backend::detect(root)
        .ok_or_else(|| io::Error::other("neither NetworkManager nor netplan is on this board"))
        .and_then(|backend| {
            let networks = store.load()?;
            match backend {
                Backend::Netplan => apply_netplan(&networks, root, run)?,
                Backend::NetworkManager => apply_networkmanager(&networks, root, run)?,
            }
            Ok((backend, networks.len()))
        });
    let written = Status {
        at: timestamp(SystemTime::now()),
        backend: result
            .as_ref()
            .ok()
            .map(|(backend, _)| backend.name().to_owned()),
        networks: result.as_ref().map_or(0, |(_, networks)| *networks),
        error: result.as_ref().err().map(ToString::to_string),
    };
    if let Some(dir) = status.parent() {
        std::fs::create_dir_all(dir)?;
    }
    let mut bytes = serde_json::to_vec_pretty(&written).map_err(io::Error::from)?;
    bytes.push(b'\n');
    std::fs::write(status, bytes)?;
    Ok(written)
}

fn apply_netplan(networks: &[Network], root: &Path, run: Run<'_>) -> io::Result<()> {
    let path = root.join(NETPLAN_FILE);
    match netplan(networks) {
        Some(yaml) => {
            let mut bytes = yaml.into_bytes();
            let result = write_private(&path, &bytes);
            secrecy::zeroize::Zeroize::zeroize(&mut bytes);
            result?;
        }
        None => match std::fs::remove_file(&path) {
            Err(error) if error.kind() != io::ErrorKind::NotFound => return Err(error),
            _ => {}
        },
    }
    run("/usr/sbin/netplan", &["apply"])
}

fn apply_networkmanager(networks: &[Network], root: &Path, run: Run<'_>) -> io::Result<()> {
    let dir = root.join(NM_CONNECTIONS);
    std::fs::create_dir_all(&dir)?;
    for entry in std::fs::read_dir(&dir)? {
        let path = entry?.path();
        let ours = path
            .file_name()
            .and_then(|name| name.to_str())
            .is_some_and(|name| name.starts_with(NM_PREFIX) && name.ends_with(".nmconnection"));
        if ours {
            std::fs::remove_file(&path)?;
        }
    }
    for (name, text) in keyfiles(networks) {
        let mut bytes = text.into_bytes();
        let result = write_private(&dir.join(name), &bytes);
        secrecy::zeroize::Zeroize::zeroize(&mut bytes);
        result?;
    }
    run("/usr/bin/nmcli", &["connection", "reload"])
}

/// Runs `program` with `args`, failing if it exits unsuccessfully.
///
/// # Errors
///
/// It can't be started or fails.
pub(crate) fn run_command(program: &str, args: &[&str]) -> io::Result<()> {
    let output = std::process::Command::new(program)
        .args(args)
        .stdin(std::process::Stdio::null())
        .output()?;
    if output.status.success() {
        return Ok(());
    }
    let stderr = String::from_utf8_lossy(&output.stderr);
    Err(io::Error::other(format!(
        "{program} {} failed ({}): {}",
        args.join(" "),
        output.status,
        stderr.trim()
    )))
}

/// The `wifi` part of the net shadow: the configured networks (never passphrases) and what
/// `helios wifi-apply` last did. An unreadable store is reported as its error.
pub(crate) fn report(store: &Store, status: &Path) -> Value {
    let networks = match store.load() {
        Ok(networks) => json!(networks.iter().map(Network::summary).collect::<Vec<_>>()),
        Err(error) => json!({"error": error.to_string()}),
    };
    let applied = std::fs::read(status)
        .ok()
        .and_then(|bytes| serde_json::from_slice::<Status>(&bytes).ok());
    json!({"networks": networks, "applied": applied})
}

#[cfg(test)]
mod tests;
