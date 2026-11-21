use std::collections::BTreeMap;
use std::fs::File;
use std::io;
use std::path::Path;

use tokio::io::{Interest, unix::AsyncFd};

pub(crate) type Mounts = BTreeMap<String, Vec<String>>;

fn unescape(field: &str) -> String {
    let mut decoded = String::new();
    let mut rest = field;
    while let Some((prefix, suffix)) = rest.split_once('\\') {
        decoded.push_str(prefix);
        let escape = suffix.get(..3);
        let replacement = match escape {
            Some("040") => ' ',
            Some("011") => '\t',
            Some("012") => '\n',
            Some("134") => '\\',
            _ => {
                decoded.push('\\');
                rest = suffix;
                continue;
            }
        };
        decoded.push(replacement);
        rest = &suffix[3..];
    }
    decoded.push_str(rest);
    decoded
}

pub(crate) fn parse(input: &str) -> Mounts {
    let mut mounts = Mounts::new();
    for line in input.lines() {
        let Some((fields, _)) = line.split_once(" - ") else {
            continue;
        };
        let mut fields = fields.split_ascii_whitespace().skip(2);
        if let (Some(device), Some(mount)) = (fields.next(), fields.nth(1)) {
            mounts
                .entry(device.into())
                .or_default()
                .push(unescape(mount));
        }
    }
    for paths in mounts.values_mut() {
        paths.sort();
        paths.dedup();
    }
    mounts
}

/// Waits for changes to the mount table.
pub(crate) struct Watcher(AsyncFd<File>);

/// Registers `file` with tokio's reactor for priority readiness. One of Helios's two approved
/// `unsafe` sites (with `uevent::register`, owner's OK on 2026-11-21): tokio 1.54 deprecated the
/// safe-looking `AsyncFd::with_interest` as unsound and made the replacement an `unsafe fn`.
#[allow(unsafe_code)]
fn register(file: File) -> io::Result<AsyncFd<File>> {
    // SAFETY: the `AsyncFd` takes ownership of `file`, so its descriptor stays open and refers to
    // the same open file until the `AsyncFd` is dropped, and `as_raw_fd` always returns that same
    // descriptor. Nothing else can close it, as nothing else owns it.
    unsafe { AsyncFd::register_with_interest(file, Interest::PRIORITY) }.map_err(io::Error::from)
}

impl Watcher {
    /// Opens `path` (normally `/proc/self/mountinfo`), which the kernel marks with priority
    /// readiness (`POLLPRI`) whenever the mount table changes.
    pub(crate) fn open(path: &Path) -> io::Result<Self> {
        Ok(Self(register(File::open(path)?)?))
    }

    pub(crate) async fn changed(&self) -> io::Result<()> {
        let mut ready = self.0.ready(Interest::PRIORITY).await?;
        // Seeking and reading this same descriptor acknowledges the mount notification.
        use std::io::{Read, Seek, SeekFrom};
        let mut file = self.0.get_ref();
        file.seek(SeekFrom::Start(0))?;
        io::copy(&mut file.by_ref(), &mut io::sink())?;
        ready.clear_ready();
        Ok(())
    }
}
