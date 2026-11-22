//! Token safety on the boards (LLD 1, section 4.12): SoftHSM works on a copy of the token in
//! tmpfs, and the master copy on disk is written only for a deliberate change.
//!
//! SoftHSM 2.6 rewrites the token's `token.object` in place at every login, and `generation` at
//! every `C_Initialize`. A power cut during one of those writes can tear `token.object`, which
//! holds the key every other object is encrypted with, and the whole token is lost (the Orange
//! Pi, 2026-11-22). With `identity.token_copy = "tmpfs"`:
//!
//! - `helios token prepare` (the unit's `ExecStartPre`, as `helios`) copies the master into
//!   [`RUNTIME_DIR`], checks it without logging in, falls back to `tokens.new` then `tokens.old`,
//!   repairs the master from a fallback, and writes the SoftHSM config Helios runs with;
//! - Helios saves the working copy back with [`save`] after it changes the token (creating
//!   `helios-secrets`): `tokens.new`, synced and compared, then renamed into place with the
//!   previous master kept as `tokens.old`, so a power cut at any step leaves a good copy.
//!
//! With `"direct"` (the default), `prepare` only copies the SoftHSM config, and SoftHSM uses the
//! master as before.

use std::fs;
use std::io;
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

/// Where the working copy, the SoftHSM config Helios runs with, and [`State`] live. systemd
/// creates it (`RuntimeDirectory=helios/token`) and removes it when Helios stops.
pub const RUNTIME_DIR: &str = "/run/helios/token";
/// The SoftHSM config in [`RUNTIME_DIR`]: the unit's `SOFTHSM2_CONF`.
pub const CONF_FILE: &str = "softhsm2.conf";
/// [`State`] in [`RUNTIME_DIR`], for the main process.
pub const STATE_FILE: &str = "state.json";
/// The working copy's directory in [`RUNTIME_DIR`].
pub const WORKING_DIR: &str = "tokens";

/// The fallbacks, in the order they're tried after the master: an interrupted save leaves a
/// complete `.new` before it renames anything, and `.old` is the master before the last save.
const FALLBACKS: [&str; 2] = [".new", ".old"];

/// `identity.token_copy`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum TokenCopy {
    /// SoftHSM uses the master directly (today's behaviour).
    #[default]
    Direct,
    /// SoftHSM uses a copy in tmpfs; the master is written only by [`save`].
    Tmpfs,
}

/// What `prepare` did, for the main process and the `helios` shadow.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct State {
    /// The mode.
    pub copy: TokenCopy,
    /// The master token directory (the source config's `directories.tokendir`).
    pub master: PathBuf,
    /// The working copy SoftHSM uses (the master itself with `direct`).
    pub working: PathBuf,
    /// The fallback the working copy came from (`tokens.old`), when the master failed its check.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub restored_from: Option<String>,
    /// When it was restored (RFC 3339).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub restored_at: Option<String>,
    /// Copies existed, but none passed the check: the token is lost.
    #[serde(default)]
    pub lost: bool,
}

/// Why `prepare` or [`save`] failed.
#[derive(Debug, thiserror::Error)]
pub enum CopyError {
    /// The source SoftHSM config can't be read, or has no `directories.tokendir`.
    #[error("{path}: {message}")]
    Config {
        /// The config.
        path: PathBuf,
        /// What's wrong.
        message: String,
    },
    /// A file operation failed.
    #[error("{action} {path}: {source}")]
    Io {
        /// What was being done.
        action: &'static str,
        /// On what.
        path: PathBuf,
        /// The error.
        source: io::Error,
    },
    /// A copy didn't match what it was copied from.
    #[error("the copy in {0} differs from the working copy")]
    Mismatch(PathBuf),
}

fn io_error<'a>(action: &'static str, path: &'a Path) -> impl FnOnce(io::Error) -> CopyError + 'a {
    move |source| CopyError::Io {
        action,
        path: path.to_owned(),
        source,
    }
}

/// `directories.tokendir` in a SoftHSM config.
#[must_use]
pub fn tokendir(conf: &str) -> Option<PathBuf> {
    conf.lines().find_map(|line| {
        let (key, value) = line.split_once('=')?;
        (key.trim() == "directories.tokendir" && !line.trim_start().starts_with('#'))
            .then(|| PathBuf::from(value.trim()))
            .filter(|dir| !dir.as_os_str().is_empty())
    })
}

/// `conf` with `directories.tokendir` set to `dir`, every other line as it was.
#[must_use]
pub fn with_tokendir(conf: &str, dir: &Path) -> String {
    let mut out = String::new();
    let mut replaced = false;
    for line in conf.lines() {
        let is_tokendir = !line.trim_start().starts_with('#')
            && line
                .split_once('=')
                .is_some_and(|(key, _)| key.trim() == "directories.tokendir");
        if is_tokendir && !replaced {
            out.push_str(&format!("directories.tokendir = {}\n", dir.display()));
            replaced = true;
        } else if !is_tokendir {
            out.push_str(line);
            out.push('\n');
        }
    }
    if !replaced {
        out.push_str(&format!("directories.tokendir = {}\n", dir.display()));
    }
    out
}

/// `master` with `suffix` added to its last component: `tokens` → `tokens.old`.
#[must_use]
pub fn sibling(master: &Path, suffix: &str) -> PathBuf {
    let mut name = master.file_name().unwrap_or_default().to_os_string();
    name.push(suffix);
    master.with_file_name(name)
}

/// Prepares the token for Helios: see the module docs. `check` says whether the working copy,
/// as the config in `runtime` describes it, holds the token (an `Err` counts as no). `now` is
/// the restore time to record.
///
/// # Errors
///
/// [`CopyError`] if the source config is unusable or a file operation fails.
pub fn prepare(
    source_conf: &Path,
    runtime: &Path,
    copy: TokenCopy,
    check: &mut dyn FnMut() -> Result<bool, String>,
    now: &str,
) -> Result<State, CopyError> {
    let conf = fs::read_to_string(source_conf).map_err(io_error("read", source_conf))?;
    let master = tokendir(&conf).ok_or_else(|| CopyError::Config {
        path: source_conf.to_owned(),
        message: "no directories.tokendir".into(),
    })?;
    create_private_dir(runtime)?;
    let conf_path = runtime.join(CONF_FILE);
    let mut state = State {
        copy,
        master: master.clone(),
        working: master.clone(),
        restored_from: None,
        restored_at: None,
        lost: false,
    };
    if copy == TokenCopy::Direct {
        write_private(&conf_path, conf.as_bytes())?;
        write_state(runtime, &state)?;
        return Ok(state);
    }

    let working = runtime.join(WORKING_DIR);
    state.working.clone_from(&working);
    write_private(&conf_path, with_tokendir(&conf, &working).as_bytes())?;
    let candidates: Vec<(String, PathBuf)> = std::iter::once("")
        .chain(FALLBACKS)
        .map(|suffix| (suffix.to_owned(), sibling(&master, suffix)))
        .filter(|(_, path)| path.is_dir())
        .collect();
    let mut chosen = None;
    for (suffix, candidate) in &candidates {
        replace_with_copy(candidate, &working)?;
        match check() {
            Ok(true) => {
                chosen = Some(suffix.clone());
                break;
            }
            Ok(false) => {
                tracing::warn!(copy = %candidate.display(), "the token copy fails its check");
            }
            Err(error) => {
                tracing::warn!(copy = %candidate.display(), %error, "can't check the token copy");
            }
        }
    }
    match chosen {
        Some(suffix) if suffix.is_empty() => {}
        Some(suffix) => {
            let from = sibling(&master, &suffix);
            let name = from
                .file_name()
                .unwrap_or_default()
                .to_string_lossy()
                .into_owned();
            tracing::warn!(
                from = %from.display(),
                "the master token failed its check; restored it from a previous copy"
            );
            save(&working, &master)?;
            state.restored_from = Some(name);
            state.restored_at = Some(now.to_owned());
        }
        None => {
            // Nothing passed: run on the master as it is, so Helios reports the same
            // "no token" it would without the copy, and leave every copy for a person.
            if master.is_dir() {
                replace_with_copy(&master, &working)?;
            } else {
                replace_with_copy_of_nothing(&working)?;
            }
            state.lost = !candidates.is_empty();
            if state.lost {
                tracing::error!(master = %master.display(), "no copy of the token passes its check");
            }
        }
    }
    write_state(runtime, &state)?;
    Ok(state)
}

/// Saves the working copy as the master: `tokens.new`, synced and compared, then the master
/// renamed to `tokens.old` and `tokens.new` to the master.
///
/// # Errors
///
/// [`CopyError`] if a file operation fails or the copy differs; the master is then unchanged.
pub fn save(working: &Path, master: &Path) -> Result<(), CopyError> {
    let new = sibling(master, ".new");
    let old = sibling(master, ".old");
    if new.exists() {
        fs::remove_dir_all(&new).map_err(io_error("remove", &new))?;
    }
    copy_dir(working, &new)?;
    if !same_tree(working, &new)? {
        return Err(CopyError::Mismatch(new));
    }
    let parent = master.parent().unwrap_or_else(|| Path::new("/"));
    if master.exists() {
        if old.exists() {
            fs::remove_dir_all(&old).map_err(io_error("remove", &old))?;
        }
        fs::rename(master, &old).map_err(io_error("rename", master))?;
        sync_dir(parent)?;
    }
    fs::rename(&new, master).map_err(io_error("rename", &new))?;
    sync_dir(parent)?;
    Ok(())
}

/// Reads the [`State`] `prepare` left in `runtime`, if any.
#[must_use]
pub fn read_state(runtime: &Path) -> Option<State> {
    let text = fs::read_to_string(runtime.join(STATE_FILE)).ok()?;
    serde_json::from_str(&text).ok()
}

fn write_state(runtime: &Path, state: &State) -> Result<(), CopyError> {
    let path = runtime.join(STATE_FILE);
    let json = serde_json::to_vec_pretty(state).map_err(|error| CopyError::Io {
        action: "encode",
        path: path.clone(),
        source: io::Error::other(error),
    })?;
    write_private(&path, &json)
}

fn create_private_dir(dir: &Path) -> Result<(), CopyError> {
    fs::DirBuilder::new()
        .recursive(true)
        .mode(0o700)
        .create(dir)
        .map_err(io_error("create", dir))
}

/// Writes `bytes` to `path` (0600), synced.
fn write_private(path: &Path, bytes: &[u8]) -> Result<(), CopyError> {
    use std::io::Write;
    let mut file = fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .open(path)
        .map_err(io_error("write", path))?;
    file.write_all(bytes).map_err(io_error("write", path))?;
    file.sync_all().map_err(io_error("sync", path))
}

fn replace_with_copy(from: &Path, to: &Path) -> Result<(), CopyError> {
    replace_with_copy_of_nothing(to)?;
    fs::remove_dir(to).map_err(io_error("remove", to))?;
    copy_dir(from, to)
}

fn replace_with_copy_of_nothing(dir: &Path) -> Result<(), CopyError> {
    if dir.exists() {
        fs::remove_dir_all(dir).map_err(io_error("remove", dir))?;
    }
    create_private_dir(dir)
}

/// Copies the tree at `from` to `to` (which must not exist): directories 0700, files 0600,
/// each synced.
fn copy_dir(from: &Path, to: &Path) -> Result<(), CopyError> {
    fs::DirBuilder::new()
        .mode(0o700)
        .create(to)
        .map_err(io_error("create", to))?;
    for entry in fs::read_dir(from).map_err(io_error("read", from))? {
        let entry = entry.map_err(io_error("read", from))?;
        let source = entry.path();
        let target = to.join(entry.file_name());
        let kind = entry.file_type().map_err(io_error("read", &source))?;
        if kind.is_dir() {
            copy_dir(&source, &target)?;
        } else if kind.is_file() {
            let bytes = fs::read(&source).map_err(io_error("read", &source))?;
            write_private(&target, &bytes)?;
        }
        // Anything else (a symlink) isn't part of a SoftHSM token: left out.
    }
    fs::set_permissions(to, fs::Permissions::from_mode(0o700)).map_err(io_error("chmod", to))?;
    sync_dir(to)
}

fn sync_dir(dir: &Path) -> Result<(), CopyError> {
    fs::File::open(dir)
        .and_then(|file| file.sync_all())
        .map_err(io_error("sync", dir))
}

/// Whether two trees hold the same regular files with the same bytes.
fn same_tree(a: &Path, b: &Path) -> Result<bool, CopyError> {
    let list = |dir: &Path| -> Result<Vec<(PathBuf, Vec<u8>)>, CopyError> {
        let mut files = Vec::new();
        let mut stack = vec![dir.to_owned()];
        while let Some(current) = stack.pop() {
            for entry in fs::read_dir(&current).map_err(io_error("read", &current))? {
                let entry = entry.map_err(io_error("read", &current))?;
                let path = entry.path();
                let kind = entry.file_type().map_err(io_error("read", &path))?;
                if kind.is_dir() {
                    stack.push(path);
                } else if kind.is_file() {
                    let bytes = fs::read(&path).map_err(io_error("read", &path))?;
                    let relative = path.strip_prefix(dir).unwrap_or(&path).to_owned();
                    files.push((relative, bytes));
                }
            }
        }
        files.sort();
        Ok(files)
    };
    Ok(list(a)? == list(b)?)
}

#[cfg(test)]
mod tests;
