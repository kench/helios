//! `helios token`: the token's working copy (LLD 1, section 4.12).
//!
//! `prepare` is `helios.service`'s `ExecStartPre`, run as `helios` before Helios loads the
//! PKCS#11 module. It reads only `[identity]` from the config, so a mistake elsewhere in the
//! config doesn't stop the token being prepared (Helios reports that one itself). `check` is
//! what `prepare` runs, once per copy, in a child process: SoftHSM reads `SOFTHSM2_CONF` once per
//! process, and Helios doesn't change its own environment.

use std::path::{Path, PathBuf};
use std::process::{Command as Process, Stdio};
use std::time::SystemTime;

use clap::Subcommand;

use super::{Console, Failure};
use crate::identity::token_copy::{self, CONF_FILE, TokenCopy};
use crate::provision::{DEFAULT_MODULE, DEFAULT_TOKEN_LABEL};

/// `helios token`.
#[derive(Debug, Subcommand)]
pub(super) enum Command {
    /// Prepare the token before Helios starts: helios.service runs this (ExecStartPre). With
    /// identity.token_copy = "tmpfs", copy the master token into tmpfs, check it, fall back to
    /// tokens.new or tokens.old if it's damaged, and write the SoftHSM config Helios runs with.
    Prepare {
        /// The SoftHSM config that names the master token directory.
        #[arg(long, default_value = "/etc/helios/softhsm2.conf")]
        source: PathBuf,
        /// Where the working copy and the SoftHSM config Helios runs with go.
        #[arg(long, default_value = token_copy::RUNTIME_DIR)]
        runtime: PathBuf,
    },
    /// Exit 0 if a token with this label is present and initialized, without logging in (used
    /// by prepare, with SOFTHSM2_CONF set for the copy being checked).
    #[command(hide = true)]
    Check {
        /// The PKCS#11 module.
        #[arg(long)]
        module: PathBuf,
        /// The token label.
        #[arg(long)]
        label: String,
    },
}

/// The settings `prepare` needs from `[identity]`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct Identity {
    copy: TokenCopy,
    module: PathBuf,
    label: String,
}

pub(super) fn run(
    command: Command,
    config: &Path,
    console: &mut dyn Console,
) -> Result<(), Failure> {
    match command {
        Command::Prepare { source, runtime } => {
            let identity = identity(config)?;
            let exe = std::env::current_exe().map_err(|error| {
                Failure::error(format!("can't find the helios binary: {error}"))
            })?;
            let conf = runtime.join(CONF_FILE);
            let mut check = || check_copy(&exe, &conf, &identity.module, &identity.label);
            let now = crate::mqtt::envelope::timestamp(SystemTime::now());
            let state = token_copy::prepare(&source, &runtime, identity.copy, &mut check, &now)
                .map_err(|error| Failure::error(error.to_string()))?;
            let summary = match (&state.restored_from, state.lost, state.copy) {
                (_, _, TokenCopy::Direct) => format!("token: direct, {}", state.master.display()),
                (Some(from), _, _) => format!(
                    "token: restored from {from}; working copy {}",
                    state.working.display()
                ),
                (None, true, _) => format!(
                    "token: no copy passes its check; running on the master as it is ({})",
                    state.master.display()
                ),
                (None, false, _) => format!("token: working copy {}", state.working.display()),
            };
            let _ = writeln!(console.out(), "{summary}");
            Ok(())
        }
        Command::Check { module, label } => {
            match crate::identity::cryptoki::token_present(&module, &label) {
                Ok(true) => Ok(()),
                Ok(false) => Err(Failure::error(format!(
                    "no initialized token labelled {label}"
                ))),
                Err(error) => Err(Failure::config(error.to_string())),
            }
        }
    }
}

/// Runs `helios token check` on the copy `conf` describes: exit 0 is a good copy, 1 a bad one,
/// anything else (the module didn't load) an error.
fn check_copy(exe: &Path, conf: &Path, module: &Path, label: &str) -> Result<bool, String> {
    let status = Process::new(exe)
        .args(["token", "check", "--module"])
        .arg(module)
        .args(["--label", label])
        .env("SOFTHSM2_CONF", conf)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .map_err(|error| format!("can't run {}: {error}", exe.display()))?;
    match status.code() {
        Some(0) => Ok(true),
        Some(1) => Ok(false),
        other => Err(format!("helios token check exited with {other:?}")),
    }
}

/// `[identity]`'s token_copy, pkcs11_module and token_label, with the service's defaults.
pub(super) fn identity(config: &Path) -> Result<Identity, Failure> {
    let text = std::fs::read_to_string(config)
        .map_err(|error| Failure::config(format!("{}: {error}", config.display())))?;
    let table: toml::Table = toml::from_str(&text)
        .map_err(|error| Failure::config(format!("{}: {error}", config.display())))?;
    let identity = table.get("identity").and_then(toml::Value::as_table);
    let string = |key: &str| {
        identity
            .and_then(|t| t.get(key))
            .and_then(toml::Value::as_str)
    };
    let copy = match string("token_copy") {
        None | Some("direct") => TokenCopy::Direct,
        Some("tmpfs") => TokenCopy::Tmpfs,
        Some(other) => {
            return Err(Failure::config(format!(
                "{}: identity.token_copy must be \"direct\" or \"tmpfs\", not {other:?}",
                config.display()
            )));
        }
    };
    Ok(Identity {
        copy,
        module: string("pkcs11_module").map_or_else(|| DEFAULT_MODULE.into(), PathBuf::from),
        label: string("token_label")
            .unwrap_or(DEFAULT_TOKEN_LABEL)
            .to_owned(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reads_the_identity_settings_with_defaults() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("helios.toml");
        std::fs::write(
            &path,
            "[identity]\npin = \"bootstrap\"\ntoken_copy = \"tmpfs\"\ntoken_label = \"t\"\n\
             [bootstrap]\nurl = 3\n",
        )
        .unwrap();
        assert_eq!(
            identity(&path).unwrap(),
            Identity {
                copy: TokenCopy::Tmpfs,
                module: DEFAULT_MODULE.into(),
                label: "t".into(),
            },
            "the rest of the file isn't checked"
        );
        std::fs::write(&path, "[device]\n").unwrap();
        let defaults = identity(&path).unwrap();
        assert_eq!(defaults.copy, TokenCopy::Direct);
        assert_eq!(defaults.label, DEFAULT_TOKEN_LABEL);
        std::fs::write(&path, "[identity]\ntoken_copy = \"ram\"\n").unwrap();
        assert!(
            identity(&path)
                .unwrap_err()
                .message
                .contains("\"direct\" or \"tmpfs\"")
        );
        std::fs::write(&path, "not toml [").unwrap();
        assert!(identity(&path).unwrap_err().config);
        assert!(identity(&dir.path().join("missing.toml")).is_err());
    }

    #[test]
    fn a_check_that_cannot_run_is_an_error() {
        let result = check_copy(
            Path::new("/nonexistent/helios"),
            Path::new("/c"),
            Path::new("/m"),
            "helios",
        );
        assert!(result.unwrap_err().contains("can't run"));
        // `false` exits 1: a bad copy; `true` exits 0 (both ignore the arguments).
        assert_eq!(
            check_copy(
                Path::new("/bin/false"),
                Path::new("/c"),
                Path::new("/m"),
                "x"
            ),
            Ok(false)
        );
        assert_eq!(
            check_copy(
                Path::new("/bin/true"),
                Path::new("/c"),
                Path::new("/m"),
                "x"
            ),
            Ok(true)
        );
    }
}
