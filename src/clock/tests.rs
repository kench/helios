//! Clock monitor tests, with fake kernel and boot-time probes.

use std::sync::{Arc, Mutex};
use std::time::UNIX_EPOCH;

use hyper::StatusCode;
use hyper::body::Bytes;
use hyper::header::{DATE, HeaderMap, HeaderValue};

use super::*;
use crate::https::Exchange;

const WAIT: Duration = Duration::from_secs(5);

type Kernel = Arc<Mutex<io::Result<KernelClock>>>;

fn synced(synced: bool) -> io::Result<KernelClock> {
    Ok(KernelClock {
        synced,
        max_error: Duration::from_millis(16_500),
        est_error: Duration::from_millis(2),
        drift_ppm: -12.5,
    })
}

struct Setup {
    samples: ClockSamples,
    status: watch::Receiver<ClockStatus>,
    kernel: Kernel,
    cancel: CancellationToken,
}

impl Drop for Setup {
    fn drop(&mut self) {
        self.cancel.cancel();
    }
}

fn timing() -> Timing {
    Timing {
        kernel_interval: Duration::from_millis(20),
        unsynced_grace: Duration::ZERO,
        window: Duration::from_secs(600),
    }
}

fn setup(settings: ClockSettings, kernel: io::Result<KernelClock>, boottime: Duration) -> Setup {
    let kernel: Kernel = Arc::new(Mutex::new(kernel));
    let probe = Arc::clone(&kernel);
    let probes = Probes {
        kernel: Box::new(move || match &*probe.lock().unwrap() {
            Ok(clock) => Ok(*clock),
            Err(error) => Err(io::Error::new(error.kind(), error.to_string())),
        }),
        boottime: Box::new(move || boottime),
    };
    let cancel = CancellationToken::new();
    let (samples, status, _task) = ClockMonitor::start(settings, timing(), probes, cancel.clone());
    Setup {
        samples,
        status,
        kernel,
        cancel,
    }
}

fn no_mark() -> ClockSettings {
    ClockSettings {
        boot_mark: None,
        ..ClockSettings::default()
    }
}

/// A sample taken now, from a server `offset_ms` ahead of the device clock.
fn sample_now(offset_ms: i64) -> Sample {
    let now = SystemTime::now();
    let server = if offset_ms >= 0 {
        now + Duration::from_millis(offset_ms.unsigned_abs())
    } else {
        now - Duration::from_millis(offset_ms.unsigned_abs())
    };
    let whole =
        UNIX_EPOCH + Duration::from_secs(server.duration_since(UNIX_EPOCH).unwrap().as_secs());
    Sample {
        source: Source::Credentials,
        sent: now - Duration::from_millis(20),
        received: now,
        round_trip: Duration::from_millis(20),
        server: whole,
    }
}

async fn wait_for(
    setup: &mut Setup,
    what: &str,
    condition: impl Fn(&ClockStatus) -> bool,
) -> ClockStatus {
    let result = tokio::time::timeout(WAIT, setup.status.wait_for(|status| condition(status)))
        .await
        .map(|status| status.unwrap().clone());
    result.unwrap_or_else(|_| panic!("timed out waiting for {what}: {:?}", *setup.status.borrow()))
}

#[tokio::test]
async fn reports_the_kernel_state() {
    let mut setup = setup(no_mark(), synced(true), Duration::ZERO);

    let status = wait_for(&mut setup, "the kernel state", |s| s.synced.is_some()).await;

    assert_eq!(status.synced, Some(true));
    assert_eq!(status.max_error_ms, Some(16_500));
    assert_eq!(status.drift_ppm, Some(-12.5));
    assert_eq!(status.offset, None);
    assert_eq!(status.boot_offset_s, None);
}

#[tokio::test]
async fn reports_the_offset_from_samples() {
    let mut setup = setup(no_mark(), synced(false), Duration::ZERO);

    setup.samples.offer(sample_now(90_000));
    let status = wait_for(&mut setup, "an offset", |s| s.offset.is_some()).await;

    let offset = status.offset.unwrap();
    assert!((offset.offset_ms - 90_000).abs() <= 1000, "{offset:?}");
    assert_eq!(offset.source, Source::Credentials);
    assert_eq!(offset.uncertainty, Duration::from_millis(510));
}

#[tokio::test]
async fn publishes_only_changes_of_a_second_or_more() {
    let mut setup = setup(no_mark(), synced(true), Duration::ZERO);
    setup.samples.offer(sample_now(10_000));
    wait_for(&mut setup, "an offset and the kernel state", |s| {
        s.offset.is_some() && s.synced.is_some()
    })
    .await;
    setup.status.mark_unchanged();

    // The same offset again, and kernel reads that don't change.
    setup.samples.offer(sample_now(10_000));
    tokio::time::sleep(Duration::from_millis(100)).await;
    assert!(!setup.status.has_changed().unwrap());

    *setup.kernel.lock().unwrap() = synced(false);
    let status = wait_for(&mut setup, "unsynced", |s| s.synced == Some(false)).await;
    assert_eq!(status.synced, Some(false));
}

#[tokio::test]
async fn measures_the_boot_offset_once_the_clock_is_right() {
    let dir = std::env::temp_dir().join(format!("helios-clock-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let mark = dir.join("boot-clock");
    // 100 s of boot time ago, the clock said 21,292 s less than it should have.
    let true_then = SystemTime::now() - Duration::from_secs(100);
    let then = true_then.duration_since(UNIX_EPOCH).unwrap().as_secs() - 21_292;
    std::fs::write(&mark, format!("{then} 5.0\n")).unwrap();
    let settings = ClockSettings {
        boot_mark: Some(mark),
        ..ClockSettings::default()
    };
    // The kernel's synced flag doesn't matter: the server says when the clock is right.
    let mut setup = setup(settings, synced(false), Duration::from_secs(105));

    // Not while the server says the clock is off.
    setup.samples.offer(sample_now(5000));
    wait_for(&mut setup, "an offset", |s| s.offset.is_some()).await;
    assert_eq!(setup.status.borrow().boot_offset_s, None);
    setup.samples.offer(sample_now(0));
    let status = wait_for(&mut setup, "the boot offset", |s| s.boot_offset_s.is_some()).await;

    let seconds = status.boot_offset_s.unwrap();
    assert!((seconds - 21_292).abs() <= 1, "{seconds}");
    std::fs::remove_dir_all(&dir).unwrap();
}

#[tokio::test]
async fn copes_with_a_kernel_read_failure() {
    let mut setup = setup(
        no_mark(),
        Err(io::Error::from(io::ErrorKind::PermissionDenied)),
        Duration::ZERO,
    );
    setup.samples.offer(sample_now(0));
    wait_for(&mut setup, "an offset", |s| s.offset.is_some()).await;
    assert_eq!(setup.status.borrow().synced, None);

    *setup.kernel.lock().unwrap() = synced(true);
    wait_for(&mut setup, "synced", |s| s.synced == Some(true)).await;
    *setup.kernel.lock().unwrap() = Err(io::Error::from(io::ErrorKind::PermissionDenied));
    wait_for(&mut setup, "the failure", |s| s.synced.is_none()).await;
}

#[tokio::test]
async fn logs_levels_as_the_offset_changes() {
    // Through every level and back, for the log lines (checked by eye with --nocapture).
    let mut setup = setup(no_mark(), synced(false), Duration::ZERO);
    for offset_ms in [300_000, 120_000, 0] {
        setup.samples.offer(sample_now(offset_ms));
        tokio::time::sleep(Duration::from_millis(30)).await;
    }
    *setup.kernel.lock().unwrap() = synced(true);

    wait_for(&mut setup, "synced", |s| s.synced == Some(true)).await;
}

#[test]
fn levels_have_hysteresis() {
    let warn = Duration::from_secs(60);

    assert_eq!(level(59_000, warn, Level::Ok), Level::Ok);
    assert_eq!(level(61_000, warn, Level::Ok), Level::Warn);
    assert_eq!(level(241_000, warn, Level::Ok), Level::Error);
    // Leaving a level takes dropping below 90% of its threshold.
    assert_eq!(level(55_000, warn, Level::Warn), Level::Warn);
    assert_eq!(level(53_000, warn, Level::Warn), Level::Ok);
    assert_eq!(level(220_000, warn, Level::Error), Level::Error);
    assert_eq!(level(210_000, warn, Level::Error), Level::Warn);
    assert_eq!(level(0, warn, Level::Error), Level::Ok);
}

#[test]
fn small_changes_are_not_reported() {
    let offset = |offset_ms, uncertainty_ms, source| Offset {
        offset_ms,
        uncertainty: Duration::from_millis(uncertainty_ms),
        source,
        at: SystemTime::now(),
    };
    let base = ClockStatus {
        synced: Some(true),
        max_error_ms: Some(1000),
        drift_ppm: Some(3.0),
        offset: Some(offset(0, 600, Source::Shadow)),
        boot_offset_s: None,
    };
    let with = |change: fn(&mut ClockStatus)| {
        let mut status = base.clone();
        change(&mut status);
        differs(&base, &status)
    };

    assert!(!with(|s| s.offset.as_mut().unwrap().at = UNIX_EPOCH));
    assert!(!with(|s| s.offset.as_mut().unwrap().offset_ms = 999));
    assert!(!with(|s| s.max_error_ms = Some(1999)));
    assert!(!with(|s| s.drift_ppm = Some(3.9)));
    assert!(with(|s| s.offset.as_mut().unwrap().offset_ms = 1000));
    assert!(with(
        |s| s.offset.as_mut().unwrap().uncertainty = Duration::from_millis(1600)
    ));
    assert!(with(
        |s| s.offset.as_mut().unwrap().source = Source::Bootstrap
    ));
    assert!(with(|s| s.offset = None));
    assert!(with(|s| s.max_error_ms = Some(2000)));
    assert!(with(|s| s.max_error_ms = None));
    assert!(with(|s| s.drift_ppm = Some(4.0)));
    assert!(with(|s| s.drift_ppm = None));
    assert!(with(|s| s.synced = Some(false)));
    assert!(with(|s| s.boot_offset_s = Some(5)));
}

#[test]
fn samples_http_date_headers() {
    let (samples, mut received) = ClockSamples::for_test();
    let exchange = Exchange {
        sent: UNIX_EPOCH + Duration::from_secs(100),
        received: UNIX_EPOCH + Duration::from_secs(101),
        round_trip: Duration::from_secs(1),
    };
    let response = |date: Option<&'static str>| {
        let mut headers = HeaderMap::new();
        if let Some(date) = date {
            headers.insert(DATE, HeaderValue::from_static(date));
        }
        Response {
            status: StatusCode::OK,
            headers,
            body: Bytes::new(),
            exchange,
        }
    };

    samples.offer_http(
        Source::Bootstrap,
        &response(Some("Sat, 21 Nov 2026 06:00:00 GMT")),
    );
    samples.offer_http(Source::Bootstrap, &response(Some("not a date")));
    samples.offer_http(Source::Bootstrap, &response(None));
    ClockSamples::discard().offer_http(
        Source::Bootstrap,
        &response(Some("Sat, 21 Nov 2026 06:00:00 GMT")),
    );

    let sample = received.try_recv().unwrap();
    assert_eq!(sample.source, Source::Bootstrap);
    assert_eq!(
        sample.server,
        UNIX_EPOCH + Duration::from_secs(1_795_240_800)
    );
    assert_eq!(sample.round_trip, Duration::from_secs(1));
    assert!(received.try_recv().is_err());
}

#[test]
fn the_real_boottime_probe_advances() {
    let probes = Probes::default();
    let first = (probes.boottime)();
    std::thread::sleep(Duration::from_millis(5));
    assert!((probes.boottime)() > first);
}
