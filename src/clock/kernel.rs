//! The kernel's NTP state from `adjtimex(2)` (LLD 1, section 4.11), read without changing
//! anything.

use std::io;
use std::time::Duration;

/// What the kernel knows about the clock's synchronization.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct KernelClock {
    /// Whether an NTP client has synchronized the clock.
    pub synced: bool,
    /// The maximum error, as estimated by the NTP client.
    pub max_error: Duration,
    /// The estimated error.
    pub est_error: Duration,
    /// The frequency correction the NTP client applies: the oscillator's drift, in ppm.
    pub drift_ppm: f64,
}

/// `adjtimex` returns this when the clock isn't synchronized.
const TIME_ERROR: i32 = 5;
/// The `status` bit for an unsynchronized clock.
const STA_UNSYNC: i64 = 0x0040;

/// Reads the kernel's NTP state.
///
/// # Errors
///
/// The `adjtimex` error, which shouldn't happen for a read.
#[allow(
    clippy::useless_conversion,
    reason = "c_long is i64 here but i32 on the 32-bit scanner"
)]
pub fn read() -> io::Result<KernelClock> {
    let (state, timex) = adjtimex()?;
    Ok(from_timex(
        state,
        i64::from(timex.status),
        i64::from(timex.maxerror),
        i64::from(timex.esterror),
        i64::from(timex.freq),
    ))
}

/// The one `unsafe` call in Helios: a read-only `adjtimex(2)`.
#[allow(unsafe_code)]
fn adjtimex() -> io::Result<(i32, libc::timex)> {
    // SAFETY: `timex` is a plain C struct of integers, so all zeros is a valid value, and
    // `modes = 0` (from the zeroing) makes the call read-only.
    let mut timex: libc::timex = unsafe { std::mem::zeroed() };
    // SAFETY: `timex` is a valid, writable `struct timex` for the duration of the call, and the
    // kernel doesn't keep the pointer.
    let state = unsafe { libc::adjtimex(&raw mut timex) };
    if state == -1 {
        return Err(io::Error::last_os_error());
    }
    Ok((state, timex))
}

/// Interprets `adjtimex`'s result: `maxerror` and `esterror` are in µs, and `freq` is in ppm
/// with a 16-bit fraction.
fn from_timex(state: i32, status: i64, maxerror: i64, esterror: i64, freq: i64) -> KernelClock {
    let micros = |value: i64| Duration::from_micros(u64::try_from(value).unwrap_or(0));
    #[expect(clippy::cast_precision_loss, reason = "freq is at most ±32,768,000")]
    let drift_ppm = freq as f64 / 65_536.0;
    KernelClock {
        synced: state != TIME_ERROR && status & STA_UNSYNC == 0,
        max_error: micros(maxerror),
        est_error: micros(esterror),
        drift_ppm,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reads_this_machine() {
        let clock = read().unwrap();

        assert!(clock.drift_ppm.abs() <= 500.0, "{clock:?}");
    }

    #[test]
    fn synced_needs_both_the_state_and_the_status_bit() {
        assert!(from_timex(0, 0, 0, 0, 0).synced);
        assert!(!from_timex(TIME_ERROR, 0, 0, 0, 0).synced);
        assert!(!from_timex(0, STA_UNSYNC | 1, 0, 0, 0).synced);
    }

    #[test]
    fn converts_units() {
        let clock = from_timex(0, 0, 16_000_000, 1500, -65_536 * 12 - 32_768);

        assert_eq!(clock.max_error, Duration::from_secs(16));
        assert_eq!(clock.est_error, Duration::from_micros(1500));
        assert!((clock.drift_ppm + 12.5).abs() < 1e-9, "{}", clock.drift_ppm);
        assert_eq!(from_timex(0, 0, -1, -1, 0).max_error, Duration::ZERO);
    }
}
