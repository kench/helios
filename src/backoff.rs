//! Exponential backoff with jitter, for retries (LLD 1, sections 4.7, 4.8 and 5.3).

use std::time::Duration;

/// Exponential backoff with jitter: each delay is between half and all of the current step,
/// and the step doubles up to the maximum.
#[derive(Debug)]
pub(crate) struct Backoff {
    initial: Duration,
    max: Duration,
    step: Duration,
}

impl Backoff {
    pub(crate) fn new(initial: Duration, max: Duration) -> Self {
        Self {
            initial,
            max,
            step: initial,
        }
    }

    pub(crate) fn next_delay(&mut self) -> Duration {
        let step = self.step;
        self.step = (self.step * 2).min(self.max);
        jitter(step, random_fraction())
    }

    pub(crate) fn reset(&mut self) {
        self.step = self.initial;
    }
}

/// Between half and all of `step`, by `fraction` (0 to 1).
pub(crate) fn jitter(step: Duration, fraction: f64) -> Duration {
    step.mul_f64(0.5 + 0.5 * fraction.clamp(0.0, 1.0))
}

pub(crate) fn random_fraction() -> f64 {
    let mut bytes = [0u8; 4];
    // Without randomness the delay is just the full step.
    match getrandom::fill(&mut bytes) {
        Ok(()) => f64::from(u32::from_le_bytes(bytes)) / f64::from(u32::MAX),
        Err(_) => 1.0,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn backoff_doubles_with_jitter_up_to_the_maximum() {
        let mut backoff = Backoff::new(Duration::from_secs(1), Duration::from_secs(30));
        for step in [1, 2, 4, 8, 16, 30, 30] {
            let step = Duration::from_secs(step);
            let delay = backoff.next_delay();
            assert!(delay >= step / 2 && delay <= step, "{delay:?} for {step:?}");
        }
        backoff.reset();
        assert!(backoff.next_delay() <= Duration::from_secs(1));

        assert_eq!(jitter(Duration::from_secs(10), 0.0), Duration::from_secs(5));
        assert_eq!(
            jitter(Duration::from_secs(10), 1.0),
            Duration::from_secs(10)
        );
        assert_eq!(
            jitter(Duration::from_secs(10), 7.0),
            Duration::from_secs(10)
        );
        assert!((0.0..=1.0).contains(&random_fraction()));
    }
}
