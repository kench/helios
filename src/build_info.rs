//! Facts about the build, embedded by `build.rs`.

use std::time::{Duration, SystemTime, UNIX_EPOCH};

/// When this binary was built, in seconds since the Unix epoch (or `SOURCE_DATE_EPOCH`).
pub const BUILD_TIMESTAMP: u64 = parse_seconds(env!("HELIOS_BUILD_TIMESTAMP"));

/// When this binary was built. A system clock earlier than this hasn't been set yet.
#[must_use]
pub fn build_time() -> SystemTime {
    UNIX_EPOCH + Duration::from_secs(BUILD_TIMESTAMP)
}

/// Parses decimal seconds at compile time.
const fn parse_seconds(value: &str) -> u64 {
    let digits = value.as_bytes();
    assert!(!digits.is_empty(), "HELIOS_BUILD_TIMESTAMP is empty");
    let mut seconds: u64 = 0;
    let mut i = 0;
    while i < digits.len() {
        let digit = digits[i];
        assert!(
            digit.is_ascii_digit(),
            "HELIOS_BUILD_TIMESTAMP must be decimal seconds"
        );
        seconds = seconds * 10 + (digit - b'0') as u64;
        i += 1;
    }
    seconds
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_build_time_is_recent_and_not_in_the_future() {
        // 2026-01-01T00:00:00Z: earlier than any build of this crate.
        let earliest = UNIX_EPOCH + Duration::from_secs(1_767_225_600);

        assert!(build_time() > earliest);
        assert!(build_time() <= SystemTime::now());
    }

    #[test]
    fn parses_decimal_seconds() {
        assert_eq!(parse_seconds("0"), 0);
        assert_eq!(parse_seconds("1767225600"), 1_767_225_600);
    }

    #[test]
    #[should_panic(expected = "must be decimal seconds")]
    fn rejects_other_characters() {
        parse_seconds("17672x");
    }

    #[test]
    #[should_panic(expected = "is empty")]
    fn rejects_an_empty_value() {
        parse_seconds("");
    }
}
