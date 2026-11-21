//! The device clock's offset from server time (LLD 1, section 4.11), from replies Helios gets
//! anyway: HTTP `Date` headers and shadow reply timestamps, both in whole seconds.

use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

/// Where a server-time sample came from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Source {
    /// The bootstrap service.
    Bootstrap,
    /// The AWS IoT credentials provider.
    Credentials,
    /// An AWS IoT shadow reply.
    Shadow,
}

impl Source {
    /// The name in the `helios` shadow.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Bootstrap => "bootstrap",
            Self::Credentials => "credentials",
            Self::Shadow => "shadow",
        }
    }
}

/// One request and its reply's server time.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Sample {
    /// Where it came from.
    pub source: Source,
    /// The device time when the request went out (t₁).
    pub sent: SystemTime,
    /// The device time when the reply arrived (t₂).
    pub received: SystemTime,
    /// The round trip, by a monotonic clock.
    pub round_trip: Duration,
    /// The server's time, truncated to whole seconds.
    pub server: SystemTime,
}

/// The device clock's offset from server time, from one sample.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Offset {
    /// Server time minus device time, in ms: positive when the device clock is behind. Zero when
    /// it's smaller than the uncertainty.
    pub offset_ms: i64,
    /// How far the true offset may be from `offset_ms`.
    pub uncertainty: Duration,
    /// Where it came from.
    pub source: Source,
    /// When the sample was taken, by the device clock.
    pub at: SystemTime,
}

impl Sample {
    /// The offset this sample shows:
    ///
    /// - offset = (server time + 0.5 s) − (t₁ + t₂) / 2
    /// - uncertainty = round trip / 2 + 0.5 s
    #[must_use]
    pub fn offset(&self) -> Offset {
        let half_second = 500_000_000_i128;
        let midpoint = i128::midpoint(nanos(self.sent), nanos(self.received));
        let offset = nanos(self.server) + half_second - midpoint;
        let uncertainty = self.round_trip / 2 + Duration::from_millis(500);
        let offset_ms = if offset.unsigned_abs() < uncertainty.as_nanos() {
            0
        } else {
            i64::try_from(offset / 1_000_000).unwrap_or(i64::MAX)
        };
        Offset {
            offset_ms,
            uncertainty,
            source: self.source,
            at: self.received,
        }
    }
}

/// Nanoseconds since the epoch, negative before it.
fn nanos(time: SystemTime) -> i128 {
    match time.duration_since(UNIX_EPOCH) {
        Ok(after) => i128::try_from(after.as_nanos()).unwrap_or(i128::MAX),
        Err(before) => -i128::try_from(before.duration().as_nanos()).unwrap_or(i128::MAX),
    }
}

/// Recent offsets, to pick the most certain one.
#[derive(Debug)]
pub struct Window {
    span: Duration,
    offsets: Vec<(Instant, Offset)>,
}

impl Window {
    /// A window that keeps offsets for `span`.
    #[must_use]
    pub fn new(span: Duration) -> Self {
        Self {
            span,
            offsets: Vec::new(),
        }
    }

    /// Adds an offset taken at `now`.
    pub fn add(&mut self, now: Instant, offset: Offset) {
        self.forget(now);
        self.offsets.push((now, offset));
    }

    /// The offset with the smallest uncertainty in the window at `now`; the latest of equals.
    pub fn best(&mut self, now: Instant) -> Option<Offset> {
        self.forget(now);
        self.offsets
            .iter()
            .rev()
            .min_by_key(|(_, offset)| offset.uncertainty)
            .map(|(_, offset)| *offset)
    }

    fn forget(&mut self, now: Instant) {
        let span = self.span;
        self.offsets
            .retain(|(at, _)| now.saturating_duration_since(*at) < span);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const SERVER: u64 = 1_795_240_000;

    /// A sample whose request went out `sent_ms` after the server's second began, by the device
    /// clock, and took `round_trip_ms`.
    fn sample(device_offset_ms: i64, round_trip_ms: u64) -> Sample {
        // The server's clock reads SERVER + 0.4 s at the midpoint: truncated to SERVER.
        let true_midpoint = UNIX_EPOCH + Duration::from_millis(SERVER * 1000 + 400);
        let device_midpoint = if device_offset_ms >= 0 {
            true_midpoint - Duration::from_millis(device_offset_ms.unsigned_abs())
        } else {
            true_midpoint + Duration::from_millis(device_offset_ms.unsigned_abs())
        };
        let half = Duration::from_millis(round_trip_ms / 2);
        Sample {
            source: Source::Credentials,
            sent: device_midpoint - half,
            received: device_midpoint + half,
            round_trip: Duration::from_millis(round_trip_ms),
            server: UNIX_EPOCH + Duration::from_secs(SERVER),
        }
    }

    #[test]
    fn a_correct_clock_shows_no_offset() {
        let offset = sample(0, 80).offset();

        assert_eq!(offset.offset_ms, 0);
        assert_eq!(offset.uncertainty, Duration::from_millis(540));
    }

    #[test]
    fn measures_a_slow_or_fast_clock() {
        // Within the 0.5 s truncation error of the true offset.
        let behind = sample(21_292_000, 80).offset();
        let ahead = sample(-120_000, 80).offset();

        assert!((behind.offset_ms - 21_292_000).abs() <= 500, "{behind:?}");
        assert!((ahead.offset_ms + 120_000).abs() <= 500, "{ahead:?}");
    }

    #[test]
    fn slow_round_trips_are_less_certain() {
        let slow = sample(2000, 3000).offset();

        assert_eq!(slow.uncertainty, Duration::from_millis(2000));
        // 2 s off, but within 2 s of uncertainty: shown as about 2 s, not zero.
        assert!(slow.offset_ms >= 1500, "{slow:?}");
        assert_eq!(sample(1000, 3000).offset().offset_ms, 0);
    }

    #[test]
    fn handles_times_before_the_epoch() {
        let mut early = sample(0, 0);
        early.sent = UNIX_EPOCH - Duration::from_secs(10);
        early.received = UNIX_EPOCH - Duration::from_secs(10);

        assert!(early.offset().offset_ms > 0);
    }

    #[test]
    fn keeps_the_most_certain_recent_offset() {
        let mut window = Window::new(Duration::from_secs(600));
        let start = Instant::now();
        let precise = sample(5000, 40).offset();
        let rough = sample(5000, 900).offset();

        window.add(start, rough);
        window.add(start + Duration::from_secs(1), precise);
        window.add(start + Duration::from_secs(2), rough);

        assert_eq!(window.best(start + Duration::from_secs(3)), Some(precise));
        assert_eq!(window.best(start + Duration::from_secs(601)), Some(rough));
        assert_eq!(window.best(start + Duration::from_secs(700)), None);
    }

    #[test]
    fn names_its_sources() {
        assert_eq!(Source::Bootstrap.as_str(), "bootstrap");
        assert_eq!(Source::Credentials.as_str(), "credentials");
        assert_eq!(Source::Shadow.as_str(), "shadow");
    }
}
