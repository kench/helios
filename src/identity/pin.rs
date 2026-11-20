//! Where the token PIN comes from (LLD 1, section 4.5).
//!
//! The identity manager reads the PIN from a [`PinSource`] on the signer thread, just before
//! each login, and drops it straight after. The `credential:` and `file:` sources (task 5) read
//! it again each time. The bootstrap source fetches it once per process start and keeps it in
//! a [`FixedPin`].

use secrecy::{ExposeSecret, SecretString};

/// The PIN couldn't be read. This is a configuration problem, so it is fatal.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("token PIN could not be read: {reason}")]
pub struct PinError {
    reason: String,
}

impl PinError {
    /// An error with `reason`, which must not contain the PIN.
    #[must_use]
    pub fn new(reason: impl Into<String>) -> Self {
        Self {
            reason: reason.into(),
        }
    }
}

/// Supplies the token PIN for each login.
pub trait PinSource: Send + Sync + 'static {
    /// Reads the PIN.
    ///
    /// # Errors
    ///
    /// [`PinError`] if the PIN isn't available.
    fn read(&self) -> Result<SecretString, PinError>;
}

/// A PIN held in memory, such as the one the bootstrap service returns. Zeroized when dropped.
#[derive(Debug)]
pub struct FixedPin(SecretString);

impl FixedPin {
    /// Holds `pin`.
    #[must_use]
    pub fn new(pin: SecretString) -> Self {
        Self(pin)
    }
}

impl PinSource for FixedPin {
    fn read(&self) -> Result<SecretString, PinError> {
        Ok(SecretString::new(self.0.expose_secret().clone()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_fixed_pin_is_read_every_time() {
        let pin = FixedPin::new(SecretString::new("123456".into()));

        assert_eq!(pin.read().unwrap().expose_secret(), "123456");
        assert_eq!(pin.read().unwrap().expose_secret(), "123456");
        assert!(!format!("{pin:?}").contains("123456"));
    }

    #[test]
    fn errors_describe_the_reason() {
        assert_eq!(
            PinError::new("credential helios-pin is missing").to_string(),
            "token PIN could not be read: credential helios-pin is missing"
        );
    }
}
