//! When to refresh the credentials (LLD 1, section 5.3).

use std::time::Duration;

/// Refresh at this fraction of the lifetime...
pub const REFRESH_FRACTION: f64 = 0.8;
/// ...minus up to this much random jitter, so devices don't refresh in step...
pub const MAX_JITTER: Duration = Duration::from_secs(60);
/// ...and no later than this long before expiry.
pub const MIN_MARGIN: Duration = Duration::from_secs(5 * 60);
/// First retry delay after a network, TLS or 5xx error. Doubles on each failure.
pub const INITIAL_BACKOFF: Duration = Duration::from_secs(5);
/// Longest retry delay after a network, TLS or 5xx error.
pub const MAX_BACKOFF: Duration = Duration::from_secs(5 * 60);
/// Retry delay after the provider rejected the request (configuration or policy error).
pub const REJECTED_RETRY: Duration = Duration::from_secs(5 * 60);

/// How long after a fetch to refresh credentials that live for `lifetime`, with `jitter`
/// between 0 and 1. With the default 1-hour lifetime that is about 48 minutes.
#[must_use]
pub fn refresh_after(lifetime: Duration, jitter: f64) -> Duration {
    let target = lifetime
        .mul_f64(REFRESH_FRACTION)
        .saturating_sub(MAX_JITTER.mul_f64(jitter.clamp(0.0, 1.0)));
    target.min(lifetime.saturating_sub(MIN_MARGIN))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn refreshes_at_eighty_percent_minus_jitter() {
        let hour = Duration::from_secs(3600);

        assert_eq!(refresh_after(hour, 0.0), Duration::from_secs(2880));
        assert_eq!(refresh_after(hour, 1.0), Duration::from_secs(2820));
        assert_eq!(refresh_after(hour, 0.5), Duration::from_secs(2850));
        assert_eq!(refresh_after(hour, 9.0), Duration::from_secs(2820));
    }

    #[test]
    fn refreshes_at_least_five_minutes_before_expiry() {
        // 80% of 15 minutes is 12, but that's only 3 minutes before expiry.
        assert_eq!(
            refresh_after(Duration::from_secs(900), 0.0),
            Duration::from_secs(600)
        );
        // Shorter than the margin: refresh straight away.
        assert_eq!(refresh_after(Duration::from_secs(60), 0.0), Duration::ZERO);
    }
}
