//! Child processes for the stream module (LLD 4, section 3): ffmpeg now, and nginx and
//! `srtla_send` later. Behind [`Spawner`], so tests use fake processes.
//!
//! Each child runs in its own process group with stdin closed; its stdout and stderr lines and
//! its exit arrive as [`Tagged`] events. Stopping sends SIGTERM to the group, then SIGKILL after
//! a grace period. If Helios itself dies, systemd's `KillMode=control-group` stops the children:
//! `PR_SET_PDEATHSIG` would need an `unsafe` `pre_exec` hook.

use std::collections::BTreeSet;
use std::future::Future;
use std::io;
use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::process::Stdio;
use std::time::Duration;

use rustix::process::{Pid, Signal, kill_process, kill_process_group};
use tokio::io::{AsyncBufReadExt, AsyncRead, BufReader};
use tokio::sync::{mpsc, watch};

/// What to run.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct JobSpec {
    /// For logs: the stream's ID.
    pub name: String,
    pub program: PathBuf,
    pub args: Vec<String>,
}

/// Something a child did.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum JobEvent {
    Stdout(String),
    Stderr(String),
    /// It exited, with its exit code if it had one (none when killed by a signal).
    Exited(Option<i32>),
}

/// A [`JobEvent`] with the number of the job it came from, so events from a job that has
/// been replaced can be ignored.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Tagged {
    pub job: u64,
    pub event: JobEvent,
}

/// A boxed future, for the object-safe traits below.
pub(crate) type BoxFuture<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

/// A running child.
pub(crate) trait Job: Send {
    /// Stops it: SIGTERM, then SIGKILL after `grace`. Returns once it has exited.
    fn stop(&mut self, grace: Duration) -> BoxFuture<'_, ()>;

    /// Asks it to reload (SIGHUP to the child itself): `srtla_send` rereads its IP file.
    fn reload(&self);
}

/// Starts children.
pub(crate) trait Spawner: Send + Sync + 'static {
    /// Starts `spec`; its events go to `events`, tagged with `job`.
    ///
    /// # Errors
    ///
    /// If the program can't be started.
    fn spawn(
        &self,
        spec: &JobSpec,
        job: u64,
        events: mpsc::UnboundedSender<Tagged>,
    ) -> io::Result<Box<dyn Job>>;

    /// The encoders `ffmpeg -encoders` lists, or `None` if it can't be asked.
    fn encoders<'a>(&'a self, ffmpeg: &'a Path) -> BoxFuture<'a, Option<BTreeSet<String>>>;
}

/// The real spawner.
#[derive(Debug, Default)]
pub(crate) struct System;

impl Spawner for System {
    fn spawn(
        &self,
        spec: &JobSpec,
        job: u64,
        events: mpsc::UnboundedSender<Tagged>,
    ) -> io::Result<Box<dyn Job>> {
        let mut child = tokio::process::Command::new(&spec.program)
            .args(&spec.args)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .process_group(0)
            .kill_on_drop(true)
            .spawn()?;
        let group = child
            .id()
            .and_then(|id| i32::try_from(id).ok())
            .and_then(Pid::from_raw);
        if let Some(stdout) = child.stdout.take() {
            tokio::spawn(forward(stdout, job, events.clone(), JobEvent::Stdout));
        }
        if let Some(stderr) = child.stderr.take() {
            tokio::spawn(forward(stderr, job, events.clone(), JobEvent::Stderr));
        }
        let (done_tx, done) = watch::channel(false);
        tokio::spawn(async move {
            let code = child.wait().await.ok().and_then(|status| status.code());
            let _ = done_tx.send(true);
            let _ = events.send(Tagged {
                job,
                event: JobEvent::Exited(code),
            });
        });
        Ok(Box::new(SystemJob { group, done }))
    }

    fn encoders<'a>(&'a self, ffmpeg: &'a Path) -> BoxFuture<'a, Option<BTreeSet<String>>> {
        Box::pin(async move {
            let output = tokio::time::timeout(
                Duration::from_secs(10),
                tokio::process::Command::new(ffmpeg)
                    .args(["-hide_banner", "-encoders"])
                    .stdin(Stdio::null())
                    .kill_on_drop(true)
                    .output(),
            )
            .await
            .ok()?
            .ok()?;
            output
                .status
                .success()
                .then(|| parse_encoders(&String::from_utf8_lossy(&output.stdout)))
        })
    }
}

/// The names in `ffmpeg -encoders` output: lines like ` V....D libx264  libx264 H.264 …`,
/// after the `------` separator.
pub(crate) fn parse_encoders(listing: &str) -> BTreeSet<String> {
    listing
        .lines()
        .skip_while(|line| !line.trim_start().starts_with("---"))
        .skip(1)
        .filter_map(|line| line.split_whitespace().nth(1).map(str::to_owned))
        .collect()
}

async fn forward(
    reader: impl AsyncRead + Unpin,
    job: u64,
    events: mpsc::UnboundedSender<Tagged>,
    kind: fn(String) -> JobEvent,
) {
    let mut lines = BufReader::new(reader).lines();
    while let Ok(Some(line)) = lines.next_line().await {
        if events
            .send(Tagged {
                job,
                event: kind(line),
            })
            .is_err()
        {
            return;
        }
    }
}

struct SystemJob {
    group: Option<Pid>,
    done: watch::Receiver<bool>,
}

impl SystemJob {
    fn signal(&self, signal: Signal) {
        if let Some(group) = self.group
            && !*self.done.borrow()
        {
            let _ = kill_process_group(group, signal);
        }
    }
}

impl Job for SystemJob {
    fn reload(&self) {
        // The child leads its own process group, so the group's ID is its PID.
        if let Some(pid) = self.group
            && !*self.done.borrow()
        {
            let _ = kill_process(pid, Signal::HUP);
        }
    }

    fn stop(&mut self, grace: Duration) -> BoxFuture<'_, ()> {
        Box::pin(async move {
            self.signal(Signal::TERM);
            if tokio::time::timeout(grace, self.done.wait_for(|done| *done))
                .await
                .is_err()
            {
                self.signal(Signal::KILL);
                let _ =
                    tokio::time::timeout(Duration::from_secs(5), self.done.wait_for(|d| *d)).await;
            }
        })
    }
}

impl Drop for SystemJob {
    fn drop(&mut self) {
        // The group's other processes too, not only the child kill_on_drop covers.
        self.signal(Signal::KILL);
    }
}
