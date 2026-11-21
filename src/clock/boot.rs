//! The boot mark (LLD 1, section 4.11): the system time and `CLOCK_BOOTTIME` recorded by the
//! platform's setup before NTP steps the clock, to tell how far off the clock was at power-on.
//!
//! The file holds two decimal numbers in seconds, separated by white space: the system time
//! (seconds since the epoch) and the boot time (`/proc/uptime`'s first field, which counts
//! `CLOCK_BOOTTIME`). For example, written by a shell script:
//!
//! ```sh
//! echo "$(date +%s) $(cut -d' ' -f1 /proc/uptime)" > /run/helios/boot-clock
//! ```

use std::path::Path;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

/// Where the platform writes the boot mark.
pub const BOOT_MARK: &str = "/run/helios/boot-clock";

/// The clock before NTP stepped it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BootMark {
    /// The system time (R₀).
    pub system: SystemTime,
    /// `CLOCK_BOOTTIME` at the same moment (B₀).
    pub boottime: Duration,
}

/// Reads the boot mark at `path`: `None` if there's none, or it can't be read.
#[must_use]
pub fn read(path: &Path) -> Option<BootMark> {
    match std::fs::read_to_string(path) {
        Ok(text) => {
            let mark = parse(&text);
            if mark.is_none() {
                tracing::warn!(path = %path.display(), "boot clock mark isn't two numbers; ignored");
            }
            mark
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => None,
        Err(error) => {
            tracing::warn!(path = %path.display(), %error, "can't read the boot clock mark");
            None
        }
    }
}

/// Parses `"<system seconds> <boot seconds>"`.
fn parse(text: &str) -> Option<BootMark> {
    let mut fields = text.split_whitespace();
    let system = seconds(fields.next()?)?;
    let boottime = seconds(fields.next()?)?;
    fields.next().is_none().then_some(BootMark {
        system: UNIX_EPOCH + system,
        boottime,
    })
}

fn seconds(text: &str) -> Option<Duration> {
    let value: f64 = text.parse().ok()?;
    Duration::try_from_secs_f64(value).ok()
}

/// How far off the clock was at the mark, in whole seconds: true time minus the clock then,
/// positive when the clock was behind. `now` and `boottime_now` are read together, after the
/// clock is right.
#[must_use]
pub fn boot_offset(mark: BootMark, now: SystemTime, boottime_now: Duration) -> Option<i64> {
    let since_mark = boottime_now.checked_sub(mark.boottime)?;
    let true_then = now.checked_sub(since_mark)?;
    let seconds = match true_then.duration_since(mark.system) {
        Ok(behind) => i64::try_from(behind.as_secs_f64().round() as u64).ok()?,
        Err(ahead) => -i64::try_from(ahead.duration().as_secs_f64().round() as u64).ok()?,
    };
    Some(seconds)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_the_mark() {
        assert_eq!(
            parse("1795218700 3.27\n"),
            Some(BootMark {
                system: UNIX_EPOCH + Duration::from_secs(1_795_218_700),
                boottime: Duration::from_millis(3270),
            })
        );
        for bad in ["", "1795218700", "a 1", "1 2 3", "-1 2"] {
            assert_eq!(parse(bad), None, "{bad:?}");
        }
    }

    #[test]
    fn measures_a_clock_that_was_behind_at_boot() {
        // At boot (3.27 s) the clock said R₀; NTP then stepped it 21,292 s forward.
        let mark = BootMark {
            system: UNIX_EPOCH + Duration::from_secs(1_795_218_700),
            boottime: Duration::from_millis(3270),
        };
        let boottime_now = Duration::from_millis(603_270);
        let now = UNIX_EPOCH + Duration::from_secs(1_795_218_700 + 21_292 + 600);

        assert_eq!(boot_offset(mark, now, boottime_now), Some(21_292));
    }

    #[test]
    fn measures_a_clock_that_was_ahead() {
        let mark = BootMark {
            system: UNIX_EPOCH + Duration::from_secs(1000),
            boottime: Duration::from_secs(5),
        };

        assert_eq!(
            boot_offset(
                mark,
                UNIX_EPOCH + Duration::from_secs(1000 + 10 - 90),
                Duration::from_secs(15)
            ),
            Some(-90)
        );
        // A mark from the future of this boot is ignored.
        assert_eq!(
            boot_offset(mark, SystemTime::now(), Duration::from_secs(1)),
            None
        );
    }

    #[test]
    fn reads_files() {
        let dir = std::env::temp_dir().join(format!("helios-boot-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("boot-clock");
        std::fs::write(&path, "1795218700 3.27").unwrap();
        let garbled = dir.join("garbled");
        std::fs::write(&garbled, "yesterday").unwrap();

        assert!(read(&path).is_some());
        assert!(read(&garbled).is_none());
        assert!(read(&dir.join("missing")).is_none());
        assert!(read(&dir).is_none());
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
