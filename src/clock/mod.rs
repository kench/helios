//! Clock checks (LLD 1, section 4.11). The validity check, TLS and signed AWS requests all
//! depend on the device clock, so Helios checks it and reports what it finds. It never sets the
//! clock: that's the platform's NTP client's job.
//!
//! - The kernel's NTP state, every 60 s ([`kernel`]).
//! - The offset from server time, from replies Helios gets anyway ([`offset`]): the most certain
//!   sample of the last 10 minutes.
//! - The offset at power-on, from the platform's boot mark ([`boot`]), once per boot, as soon as
//!   a sample shows the clock is right.
//!
//! The results go to the `helios` shadow through [`ClockStatus`], which changes only when a
//! value moves by at least a second (or a ppm), the synced flag flips, or the source changes.
//! Offsets over `clock.warn_offset_s` are logged as warnings, over 240 s as errors, once per
//! change of level.

use std::io;
use std::path::PathBuf;
use std::time::{Duration, Instant, SystemTime};

use tokio::sync::{mpsc, watch};
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;

use crate::https::Response;

pub mod boot;
pub mod kernel;
pub mod offset;

use kernel::KernelClock;
use offset::{Offset, Sample, Source, Window};

/// Offsets over this are errors: close to the 5 minutes of clock skew AWS allows for signed
/// requests.
pub const ERROR_OFFSET: Duration = Duration::from_secs(240);

/// The default `clock.warn_offset_s`.
pub const DEFAULT_WARN_OFFSET: Duration = Duration::from_secs(60);

/// A level is left only once the offset is below this share of its threshold, so an offset near
/// a threshold isn't logged on every sample.
const HYSTERESIS: f64 = 0.9;

/// What the clock checks found.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct ClockStatus {
    /// Whether the kernel says NTP has synchronized the clock; `None` before the first read.
    pub synced: Option<bool>,
    /// The kernel's maximum error, in ms.
    pub max_error_ms: Option<u64>,
    /// The oscillator's drift, from the NTP client's frequency correction, in ppm.
    pub drift_ppm: Option<f64>,
    /// The most certain recent offset from server time.
    pub offset: Option<Offset>,
    /// How far off the clock was at power-on, in seconds (positive: behind).
    pub boot_offset_s: Option<i64>,
}

/// Takes server-time samples to the clock checks. Cheap to clone.
#[derive(Debug, Clone)]
pub struct ClockSamples {
    sender: Option<mpsc::UnboundedSender<Sample>>,
}

impl ClockSamples {
    /// Samples that go nowhere, for callers without clock checks (the CLI, tests).
    #[must_use]
    pub fn discard() -> Self {
        Self { sender: None }
    }

    /// Offers a sample.
    pub fn offer(&self, sample: Sample) {
        if let Some(sender) = &self.sender {
            let _ = sender.send(sample);
        }
    }

    /// Offers the server time in an HTTPS response's `Date` header, if it has one.
    pub fn offer_http(&self, source: Source, response: &Response) {
        let server = response
            .headers
            .get(hyper::header::DATE)
            .and_then(|date| date.to_str().ok())
            .and_then(|date| httpdate::parse_http_date(date).ok());
        if let Some(server) = server {
            self.offer(Sample {
                source,
                sent: response.exchange.sent,
                received: response.exchange.received,
                round_trip: response.exchange.round_trip,
                server,
            });
        }
    }

    /// Samples that arrive on the returned receiver, for tests.
    #[cfg(test)]
    pub(crate) fn for_test() -> (Self, mpsc::UnboundedReceiver<Sample>) {
        let (sender, receiver) = mpsc::unbounded_channel();
        (
            Self {
                sender: Some(sender),
            },
            receiver,
        )
    }
}

/// The `[clock]` settings.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClockSettings {
    /// `clock.warn_offset_s`.
    pub warn_offset: Duration,
    /// Where to read the boot mark; `None` for no boot offset.
    pub boot_mark: Option<PathBuf>,
}

impl Default for ClockSettings {
    fn default() -> Self {
        Self {
            warn_offset: DEFAULT_WARN_OFFSET,
            boot_mark: Some(PathBuf::from(boot::BOOT_MARK)),
        }
    }
}

/// Check timing. Tests shorten it.
#[derive(Debug, Clone, Copy)]
pub struct Timing {
    /// How often the kernel is read.
    pub kernel_interval: Duration,
    /// How long the clock may stay unsynchronized after startup before a warning.
    pub unsynced_grace: Duration,
    /// How long samples count.
    pub window: Duration,
}

impl Default for Timing {
    fn default() -> Self {
        Self {
            kernel_interval: Duration::from_secs(60),
            unsynced_grace: Duration::from_secs(10 * 60),
            window: Duration::from_secs(10 * 60),
        }
    }
}

/// Reads the kernel clock state.
pub type KernelProbe = Box<dyn FnMut() -> io::Result<KernelClock> + Send>;

/// Reads `CLOCK_BOOTTIME`.
pub type BoottimeProbe = Box<dyn Fn() -> Duration + Send>;

/// Where the checks read the clock. Tests use fakes.
pub struct Probes {
    /// The kernel's NTP state.
    pub kernel: KernelProbe,
    /// `CLOCK_BOOTTIME`.
    pub boottime: BoottimeProbe,
}

impl Default for Probes {
    fn default() -> Self {
        Self {
            kernel: Box::new(kernel::read),
            boottime: Box::new(|| {
                let now = rustix::time::clock_gettime(rustix::time::ClockId::Boottime);
                Duration::new(
                    u64::try_from(now.tv_sec).unwrap_or(0),
                    u32::try_from(now.tv_nsec).unwrap_or(0),
                )
            }),
        }
    }
}

/// Starts the clock checks.
pub struct ClockMonitor;

impl ClockMonitor {
    /// Starts the checks. Samples go in through the returned [`ClockSamples`]; results come out
    /// on the returned watch. Ends when `cancel` is cancelled.
    ///
    /// # Panics
    ///
    /// Panics if called outside a tokio runtime.
    #[must_use]
    pub fn start(
        settings: ClockSettings,
        timing: Timing,
        probes: Probes,
        cancel: CancellationToken,
    ) -> (ClockSamples, watch::Receiver<ClockStatus>, JoinHandle<()>) {
        let (sender, samples) = mpsc::unbounded_channel();
        let (status, status_rx) = watch::channel(ClockStatus::default());
        let boot_mark = settings.boot_mark.as_deref().and_then(boot::read);
        let monitor = Monitor {
            settings,
            timing,
            probes,
            samples,
            status,
            window: Window::new(timing.window),
            current: ClockStatus::default(),
            boot_mark,
            level: Level::Ok,
            started: Instant::now(),
            unsynced_warned: false,
            kernel_failed: false,
        };
        (
            ClockSamples {
                sender: Some(sender),
            },
            status_rx,
            tokio::spawn(monitor.run(cancel)),
        )
    }
}

/// How far off the clock is, for logging.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum Level {
    Ok,
    Warn,
    Error,
}

struct Monitor {
    settings: ClockSettings,
    timing: Timing,
    probes: Probes,
    samples: mpsc::UnboundedReceiver<Sample>,
    status: watch::Sender<ClockStatus>,
    window: Window,
    /// The latest values, published only when they change enough.
    current: ClockStatus,
    boot_mark: Option<boot::BootMark>,
    level: Level,
    started: Instant,
    unsynced_warned: bool,
    kernel_failed: bool,
}

impl Monitor {
    async fn run(mut self, cancel: CancellationToken) {
        let mut tick = tokio::time::interval(self.timing.kernel_interval);
        tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        loop {
            tokio::select! {
                () = cancel.cancelled() => return,
                _ = tick.tick() => self.read_kernel(),
                Some(sample) = self.samples.recv() => {
                    self.window.add(Instant::now(), sample.offset());
                }
            }
            self.evaluate();
        }
    }

    fn read_kernel(&mut self) {
        match (self.probes.kernel)() {
            Ok(clock) => {
                self.kernel_failed = false;
                self.current.synced = Some(clock.synced);
                self.current.max_error_ms =
                    Some(u64::try_from(clock.max_error.as_millis()).unwrap_or(u64::MAX));
                self.current.drift_ppm = Some(clock.drift_ppm);
            }
            Err(error) => {
                if !self.kernel_failed {
                    tracing::warn!(%error, "can't read the kernel clock state");
                }
                self.kernel_failed = true;
                self.current.synced = None;
                self.current.max_error_ms = None;
                self.current.drift_ppm = None;
            }
        }
    }

    fn evaluate(&mut self) {
        self.current.offset = self.window.best(Instant::now());
        self.check_level();
        self.check_synced();
        self.check_boot_offset();
        let current = self.current.clone();
        self.status.send_if_modified(|published| {
            let changed = differs(published, &current);
            if changed {
                tracing::debug!(status = ?current, "clock status");
                *published = current;
            }
            changed
        });
    }

    fn check_level(&mut self) {
        let Some(offset) = self.current.offset else {
            return;
        };
        let level = level(
            offset.offset_ms.unsigned_abs(),
            self.settings.warn_offset,
            self.level,
        );
        if level == self.level {
            return;
        }
        self.level = level;
        let (offset_ms, source) = (offset.offset_ms, offset.source.as_str());
        let uncertainty_ms = offset.uncertainty.as_millis();
        match level {
            Level::Error => tracing::error!(
                offset_ms,
                uncertainty_ms,
                source,
                "device clock is off from server time by more than 240 s; signed AWS requests \
                 may fail"
            ),
            Level::Warn => tracing::warn!(
                offset_ms,
                uncertainty_ms,
                source,
                "device clock is off from server time"
            ),
            Level::Ok => tracing::info!(
                offset_ms,
                source,
                "device clock is close to server time again"
            ),
        }
    }

    fn check_synced(&mut self) {
        match self.current.synced {
            Some(false)
                if !self.unsynced_warned
                    && self.started.elapsed() >= self.timing.unsynced_grace =>
            {
                self.unsynced_warned = true;
                tracing::warn!(
                    minutes = self.timing.unsynced_grace.as_secs() / 60,
                    "the kernel says the clock isn't synchronized by NTP"
                );
            }
            Some(true) if self.unsynced_warned => {
                self.unsynced_warned = false;
                tracing::info!("the clock is synchronized by NTP now");
            }
            _ => {}
        }
    }

    /// Once the clock is right, how far off it was at boot. "Right" means no measurable offset
    /// from server time: within about half a second. The kernel's synced flag isn't needed, and
    /// some NTP clients (the scanner's BusyBox ntpd) never set it.
    fn check_boot_offset(&mut self) {
        let right = self
            .current
            .offset
            .is_some_and(|offset| offset.offset_ms == 0);
        if !right || self.current.boot_offset_s.is_some() {
            return;
        }
        let Some(mark) = self.boot_mark.take() else {
            return;
        };
        let offset = boot::boot_offset(mark, SystemTime::now(), (self.probes.boottime)());
        if let Some(seconds) = offset {
            tracing::info!(
                boot_offset_s = seconds,
                "the clock at power-on, before NTP fixed it"
            );
        }
        self.current.boot_offset_s = offset;
    }
}

/// The level for an offset of `offset_ms`, given the current level.
fn level(offset_ms: u64, warn_offset: Duration, current: Level) -> Level {
    #[expect(clippy::cast_precision_loss, reason = "offsets are far below 2^52 ms")]
    let offset = offset_ms as f64;
    let threshold = |level: Level| match level {
        Level::Ok => 0.0,
        Level::Warn => warn_offset.as_secs_f64() * 1000.0,
        Level::Error => ERROR_OFFSET.as_secs_f64() * 1000.0,
    };
    let reached = |level: Level| {
        // Staying at a level is easier than reaching it.
        let factor = if level <= current { HYSTERESIS } else { 1.0 };
        offset > threshold(level) * factor
    };
    [Level::Error, Level::Warn]
        .into_iter()
        .find(|&level| reached(level))
        .unwrap_or(Level::Ok)
}

/// Whether `new` differs from `old` enough to report.
fn differs(old: &ClockStatus, new: &ClockStatus) -> bool {
    let by_a_second = |a: Option<u64>, b: Option<u64>| match (a, b) {
        (Some(a), Some(b)) => a.abs_diff(b) >= 1000,
        (a, b) => a.is_some() != b.is_some(),
    };
    let offset_changed = match (old.offset, new.offset) {
        (Some(a), Some(b)) => {
            a.offset_ms.abs_diff(b.offset_ms) >= 1000
                || by_a_second(
                    Some(u64::try_from(a.uncertainty.as_millis()).unwrap_or(u64::MAX)),
                    Some(u64::try_from(b.uncertainty.as_millis()).unwrap_or(u64::MAX)),
                )
                || a.source != b.source
        }
        (a, b) => a.is_some() != b.is_some(),
    };
    let drift_changed = match (old.drift_ppm, new.drift_ppm) {
        (Some(a), Some(b)) => (a - b).abs() >= 1.0,
        (a, b) => a.is_some() != b.is_some(),
    };
    old.synced != new.synced
        || by_a_second(old.max_error_ms, new.max_error_ms)
        || drift_changed
        || offset_changed
        || old.boot_offset_s != new.boot_offset_s
}

#[cfg(test)]
mod tests;
