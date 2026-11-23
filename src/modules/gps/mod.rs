//! The device's position, from gpsd, in the `gps` shadow (LLD 10).
//!
//! The module is a gpsd client: it connects to gpsd's TCP port, asks for JSON reports
//! ([`gpsd::WATCH`]) and folds the receivers, fixes and satellites gpsd sends into a [`State`],
//! which it reports on the schedule in [`report`]: at once when gpsd, a receiver or the fix mode
//! changes, every 25 m (at most every 10 s) while moving, and once an hour while still. A fix
//! gained or lost raises a `gps.fix` event. The full fix is reported, unrounded (owner,
//! 2026-11-22); when it's lost, `last_fix` keeps the last one.
//!
//! When gpsd isn't there (not installed, stopped, restarting), the shadow says
//! `"gpsd": "unavailable"` and the module tries again with backoff, 1 s doubling to 60 s.

pub(crate) mod gpsd;
pub(crate) mod report;

use std::net::SocketAddr;
use std::path::Path;
use std::time::{Duration, SystemTime};

use serde::Deserialize;
use serde_json::json;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::TcpStream;
use tokio::time::Instant;

use super::{Module, ModuleContext, ModuleError, ModuleFuture};
use crate::backoff::Backoff;
use report::{Mode, Schedule, State};

const MODULE: &str = "gps";
/// gpsd's default address (Debian's `gpsd.socket` listens on it).
const DEFAULT_GPSD: &str = "127.0.0.1:2947";
/// The longest line read from gpsd; a longer one ends the connection.
const MAX_LINE: usize = 64 * 1024;

/// `[modules.gps]`.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct GpsSettings {
    pub(crate) enabled: bool,
    /// gpsd's address, `host:port`.
    gpsd: String,
}

impl Default for GpsSettings {
    fn default() -> Self {
        Self {
            enabled: true,
            gpsd: DEFAULT_GPSD.into(),
        }
    }
}

impl GpsSettings {
    pub(crate) fn check(self) -> Result<Option<Self>, String> {
        self.gpsd.parse::<SocketAddr>().map_err(|_| {
            format!(
                "modules.gps.gpsd: {:?} isn't an IP address and port, such as {DEFAULT_GPSD}",
                self.gpsd
            )
        })?;
        Ok(self.enabled.then_some(self))
    }

    fn address(&self) -> SocketAddr {
        self.gpsd
            .parse()
            .unwrap_or_else(|_| SocketAddr::from(([127, 0, 0, 1], 2947)))
    }
}

/// The supervised gps module.
pub struct GpsModule {
    address: SocketAddr,
    backoff: (Duration, Duration),
}

impl GpsModule {
    /// The module, for checked settings.
    #[must_use]
    pub fn new(settings: &GpsSettings) -> Self {
        Self {
            address: settings.address(),
            backoff: (Duration::from_secs(1), Duration::from_secs(60)),
        }
    }
}

impl Module for GpsModule {
    fn name(&self) -> &'static str {
        MODULE
    }

    fn run(&self, ctx: ModuleContext) -> ModuleFuture<'_> {
        Box::pin(self.watch(ctx))
    }
}

/// What the module has reported and knows, across connections.
struct Reporter {
    state: State,
    schedule: Schedule,
    mode: Mode,
}

impl Reporter {
    /// Reports if it's due, and raises `gps.fix` when the mode changed.
    fn publish(&mut self, ctx: &ModuleContext) {
        let mode = self.state.mode();
        if mode != self.mode {
            ctx.mqtt.publish_event(
                MODULE,
                "gps.fix",
                json!({"mode": mode.as_str(), "previous": self.mode.as_str()}),
            );
            self.mode = mode;
        }
        let now = Instant::now();
        if self.schedule.due(&self.state, now) {
            ctx.shadows.report(MODULE, self.state.reported());
            self.schedule.sent(&self.state, now);
        }
    }
}

impl GpsModule {
    async fn watch(&self, ctx: ModuleContext) -> Result<(), ModuleError> {
        let mut reporter = Reporter {
            state: State::new(SystemTime::now()),
            schedule: Schedule::default(),
            mode: Mode::None,
        };
        let mut backoff = Backoff::new(self.backoff.0, self.backoff.1);
        let mut warned = false;
        loop {
            let connected = tokio::select! {
                () = ctx.cancel.cancelled() => return Ok(()),
                connected = TcpStream::connect(self.address) => connected,
            };
            match connected {
                Ok(stream) => {
                    backoff.reset();
                    warned = false;
                    tracing::info!(gpsd = %self.address, "connected to gpsd");
                    if session(&ctx, stream, &mut reporter).await {
                        return Ok(());
                    }
                    tracing::warn!(gpsd = %self.address, "gpsd closed the connection");
                }
                Err(error) => {
                    if !warned {
                        tracing::warn!(gpsd = %self.address, %error, "can't reach gpsd; retrying");
                        warned = true;
                    }
                }
            }
            reporter.state.set_connected(false, SystemTime::now());
            reporter.publish(&ctx);
            let retry = Instant::now() + backoff.next_delay();
            loop {
                tokio::select! {
                    () = ctx.cancel.cancelled() => return Ok(()),
                    () = tokio::time::sleep_until(retry) => break,
                    () = sleep_until(reporter.schedule.next()) => reporter.publish(&ctx),
                }
            }
        }
    }
}

/// One connection to gpsd. Returns whether it ended because the module was cancelled.
async fn session(ctx: &ModuleContext, stream: TcpStream, reporter: &mut Reporter) -> bool {
    let (read, mut write) = stream.into_split();
    if write.write_all(gpsd::WATCH.as_bytes()).await.is_err() {
        return false;
    }
    reporter.state.set_connected(true, SystemTime::now());
    reporter.publish(ctx);
    let sysfs = ctx.sysfs.clone();
    let usb_port = move |path: &str| receiver_usb_port(&sysfs, Path::new(path));
    let mut lines = BufReader::new(read);
    let mut line = String::new();
    loop {
        line.clear();
        tokio::select! {
            () = ctx.cancel.cancelled() => return true,
            read = read_line(&mut lines, &mut line) => {
                if !read {
                    return false;
                }
                reporter.state.apply(gpsd::parse(&line), SystemTime::now(), &usb_port);
                reporter.publish(ctx);
            }
            () = sleep_until(reporter.schedule.next()) => reporter.publish(ctx),
        }
    }
}

/// Reads one line into `line`; false at the end of the stream, on an error, or past
/// [`MAX_LINE`].
async fn read_line<R: tokio::io::AsyncBufRead + Unpin>(reader: &mut R, line: &mut String) -> bool {
    use tokio::io::AsyncReadExt;
    let mut limited = reader.take(MAX_LINE as u64);
    match limited.read_line(line).await {
        Ok(0) | Err(_) => false,
        Ok(_) => line.ends_with('\n'),
    }
}

async fn sleep_until(deadline: Option<Instant>) {
    match deadline {
        Some(deadline) => tokio::time::sleep_until(deadline).await,
        None => std::future::pending().await,
    }
}

/// The USB port a receiver's device is on: its path (often a `/dev/serial/by-id` link) to the
/// tty, then the tty's sysfs device.
fn receiver_usb_port(sysfs: &Path, path: &Path) -> Option<String> {
    let tty = std::fs::canonicalize(path).ok()?;
    let name = tty.file_name()?;
    let device = std::fs::canonicalize(sysfs.join("class/tty").join(name).join("device")).ok()?;
    crate::sysfs::usb_port(&device)
}

#[cfg(test)]
mod tests;
