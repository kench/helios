//! `helios wifi`: the Wi-Fi networks the WLAN adapter joins (LLD 3, section 10), set on the
//! device, and `helios wifi-apply`, which `helios-wifi.service` runs as root to apply them.
//!
//! A passphrase is read from the terminal without echo, or from a file (`--passphrase-file`),
//! never from the command line, where other users could see it.

use std::io::{self, Write};
use std::path::{Path, PathBuf};

use secrecy::ExposeSecret;

use super::{Console, Failure};
use crate::modules::net::wifi::{
    self, Network, Passphrase, Refused, STATUS, STORE, Store, StoreError,
};

#[derive(Debug, clap::Subcommand)]
pub(super) enum Command {
    /// Add a network, or replace the one with the same SSID. Asks for the passphrase unless
    /// --open or --passphrase-file.
    Add {
        /// The network's name.
        ssid: String,
        /// An open network: no passphrase.
        #[arg(long, conflicts_with = "passphrase_file")]
        open: bool,
        /// Read the passphrase from this file's first line instead of asking.
        #[arg(long)]
        passphrase_file: Option<PathBuf>,
        /// The network doesn't broadcast its SSID.
        #[arg(long)]
        hidden: bool,
    },
    /// Remove a network.
    Remove {
        /// The network's name.
        ssid: String,
    },
    /// List the networks (never their passphrases) and what was last applied, as JSON.
    List,
}

/// `helios wifi …`, on the real store.
pub(super) fn run(command: Command, console: &mut dyn Console) -> Result<(), Failure> {
    run_on(command, &Store::new(STORE), Path::new(STATUS), console)
}

fn run_on(
    command: Command,
    store: &Store,
    status: &Path,
    console: &mut dyn Console,
) -> Result<(), Failure> {
    match command {
        Command::Add {
            ssid,
            open,
            passphrase_file,
            hidden,
        } => {
            wifi::check_ssid(&ssid).map_err(|refused| Failure::error(refused.to_string()))?;
            let passphrase = if open {
                None
            } else {
                let text = match passphrase_file {
                    Some(path) => first_line(&path)?,
                    None => console
                        .read_secret(&format!("Passphrase for {ssid}: "))?
                        .expose_secret()
                        .clone(),
                };
                Some(Passphrase::new(text).map_err(|refused| Failure::error(refused.to_string()))?)
            };
            store
                .set(Network {
                    ssid: ssid.clone(),
                    passphrase,
                    hidden,
                })
                .map_err(|error| match error {
                    StoreError::Refused(refused) => Failure::error(refused.to_string()),
                    StoreError::Io(error) => store_error(store, &error),
                })?;
            writeln!(console.out(), "Saved {ssid}.")?;
            Ok(())
        }
        Command::Remove { ssid } => {
            let removed = store
                .remove(&ssid)
                .map_err(|error| store_error(store, &error))?;
            if removed {
                writeln!(console.out(), "Removed {ssid}.")?;
            } else {
                writeln!(console.out(), "There was no network {ssid}.")?;
            }
            Ok(())
        }
        Command::List => {
            let report = wifi::report(store, status);
            serde_json::to_writer_pretty(console.out(), &report).map_err(io::Error::from)?;
            writeln!(console.out())?;
            Ok(())
        }
    }
}

fn first_line(path: &Path) -> Result<String, Failure> {
    let mut text = std::fs::read_to_string(path)
        .map_err(|error| Failure::error(format!("{}: {error}", path.display())))?;
    let line = text.lines().next().unwrap_or_default().to_owned();
    secrecy::zeroize::Zeroize::zeroize(&mut text);
    if line.is_empty() {
        return Err(Failure::error(Refused::InvalidPassphrase.to_string()));
    }
    Ok(line)
}

fn store_error(store: &Store, error: &io::Error) -> Failure {
    let hint = if error.kind() == io::ErrorKind::PermissionDenied {
        " (run as root or as the helios user)"
    } else {
        ""
    };
    Failure::error(format!("{}: {error}{hint}", store.path().display()))
}

/// `helios wifi-apply`: renders the store for the board and applies it (as root, from
/// `helios-wifi.service`). Fails if it couldn't, with the reason also in the status file.
pub(super) fn apply(output: &mut dyn Write) -> Result<(), Failure> {
    apply_on(
        &Store::new(STORE),
        Path::new("/"),
        Path::new(STATUS),
        &mut wifi::run_command,
        output,
    )
}

fn apply_on(
    store: &Store,
    root: &Path,
    status: &Path,
    run: wifi::Run<'_>,
    output: &mut dyn Write,
) -> Result<(), Failure> {
    let applied = wifi::apply(store, root, status, run)?;
    match applied.error {
        Some(error) => Err(Failure::error(error)),
        None => {
            writeln!(
                output,
                "Applied {} Wi-Fi network(s) with {}.",
                applied.networks,
                applied.backend.as_deref().unwrap_or("?")
            )?;
            Ok(())
        }
    }
}

#[cfg(test)]
mod tests;
