//! PKCS#11 token access behind a trait, so tests can use a mock token (LLD 1, section 4.2).
//!
//! The identity manager and the signer thread only use [`TokenBackend`]. The production
//! implementation is [`CryptokiToken`](crate::identity::cryptoki::CryptokiToken).

use std::path::PathBuf;

use secrecy::SecretString;

/// Length of a raw P-256 ECDSA signature (`r || s`), as returned by `CKM_ECDSA`.
pub use crate::identity::der::RAW_SIGNATURE_LEN;

/// A raw `r || s` P-256 signature.
pub type RawSignature = [u8; RAW_SIGNATURE_LEN];

/// A SHA-256 digest to sign.
pub type Digest = [u8; 32];

/// Access to one PKCS#11 token.
///
/// The methods follow the open sequence in LLD 1, section 4.2: [`open`](Self::open), check
/// [`pin_status`](Self::pin_status), [`login`](Self::login), [`find_key`](Self::find_key),
/// [`read_certificate`](Self::read_certificate), then [`sign_digest`](Self::sign_digest) for
/// each TLS handshake. [`close`](Self::close) releases everything so the next `open` starts
/// from scratch, which is the most reliable way to see a re-inserted token.
///
/// Implementations are used from one thread at a time (the signer thread), so they only need
/// to be [`Send`].
pub trait TokenBackend: Send + 'static {
    /// Loads the module, finds the token by label and opens a session.
    ///
    /// # Errors
    ///
    /// [`TokenError::NotPresent`] if no token has the label, [`TokenError::AmbiguousToken`] if
    /// more than one does, and [`TokenError::ModuleLoad`] if the module can't be loaded.
    fn open(&mut self) -> Result<TokenSummary, TokenError>;

    /// The token's PIN flags, read before logging in (LLD 1, section 4.5).
    ///
    /// # Errors
    ///
    /// Any [`TokenError`] from reading the token information.
    fn pin_status(&mut self) -> Result<PinStatus, TokenError>;

    /// Signs with a key that needs no login: a SoftHSM2 key with `CKA_PRIVATE = false`, or
    /// YubiKey slot 9e. Used for the optional bootstrap challenge.
    ///
    /// # Errors
    ///
    /// [`TokenError::KeyNotFound`] if no such key is visible without logging in, or any
    /// error from signing.
    fn sign_without_login(
        &mut self,
        label: &str,
        digest: &Digest,
    ) -> Result<RawSignature, TokenError>;

    /// Logs in as the normal user. Being logged in already counts as success.
    ///
    /// # Errors
    ///
    /// [`TokenError::PinIncorrect`], [`TokenError::PinLocked`] or [`TokenError::PinInvalid`]
    /// for PIN problems. These are fatal: retrying could lock the token.
    fn login(&mut self, pin: &SecretString) -> Result<(), TokenError>;

    /// Finds the EC private key with this label. Exactly one must exist.
    ///
    /// # Errors
    ///
    /// [`TokenError::KeyNotFound`] or [`TokenError::Ambiguous`].
    fn find_key(&mut self, label: &str) -> Result<KeyRef, TokenError>;

    /// Reads the certificate stored next to `key` (same `CKA_ID`), if there is one.
    ///
    /// # Errors
    ///
    /// [`TokenError::Ambiguous`] if more than one certificate has the key's ID.
    fn read_certificate(&mut self, key: &KeyRef) -> Result<Option<Vec<u8>>, TokenError>;

    /// Signs a SHA-256 digest with `CKM_ECDSA`.
    ///
    /// # Errors
    ///
    /// [`TokenError::TokenLost`] if the token or session went away, or another
    /// [`TokenError`].
    fn sign_digest(&mut self, key: &KeyRef, digest: &Digest) -> Result<RawSignature, TokenError>;

    /// Closes all sessions and unloads the module. Key references from before are invalid
    /// afterwards.
    fn close(&mut self);
}

/// What was opened, for logs and the `helios` shadow. Holds no secrets.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TokenSummary {
    /// Path of the PKCS#11 module.
    pub module: PathBuf,
    /// Token label, without PKCS#11 padding.
    pub label: String,
    /// Token manufacturer.
    pub manufacturer: String,
    /// Token model.
    pub model: String,
    /// Token serial number.
    pub serial: String,
}

/// PIN flags from the token information, if the module reports them.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct PinStatus {
    /// The user PIN is locked. Logging in must not be tried.
    pub locked: bool,
    /// The next wrong PIN locks the token.
    pub final_try: bool,
    /// At least one wrong PIN has been entered since the last successful login.
    pub count_low: bool,
}

/// A private key found on the token. Valid until the backend is closed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KeyRef {
    /// The key's `CKA_LABEL`.
    pub label: String,
    /// The key's `CKA_ID`. The certificate is found by this ID.
    pub id: Vec<u8>,
    pub(crate) handle: KeyHandle,
}

/// Backend-specific reference to a key, tied to one open session.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct KeyHandle {
    /// Incremented on every open, so references from an earlier session are rejected.
    pub(crate) generation: u64,
    pub(crate) index: usize,
}

/// Errors from a [`TokenBackend`], grouped as in the LLD 1 table (section 4.2).
///
/// [`is_fatal`](Self::is_fatal) tells the identity manager whether to recover or stop with
/// exit code 78.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum TokenError {
    /// The PKCS#11 module couldn't be loaded or initialized.
    #[error("PKCS#11 module could not be loaded: {0}")]
    ModuleLoad(String),
    /// No token has the configured label (yet).
    #[error("no token with label {label:?}")]
    NotPresent {
        /// The configured token label.
        label: String,
    },
    /// More than one token has the configured label.
    #[error("{count} tokens have label {label:?}")]
    AmbiguousToken {
        /// The configured token label.
        label: String,
        /// How many tokens have it.
        count: usize,
    },
    /// The backend isn't open, or a key reference is from an earlier session.
    #[error("token is not open")]
    NotOpen,
    /// The token or session went away (unplugged, pcscd restarted, session closed).
    #[error("token lost: {0}")]
    TokenLost(String),
    /// Wrong user PIN. One try was used.
    #[error("token PIN is incorrect")]
    PinIncorrect,
    /// The user PIN is locked.
    #[error("token PIN is locked")]
    PinLocked,
    /// The PIN has an invalid length. No try was used.
    #[error("token PIN has an invalid length")]
    PinInvalid,
    /// The token doesn't support the key type or mechanism.
    #[error("token does not support the operation: {0}")]
    Unsupported(String),
    /// No key with this label.
    #[error("no private EC key with label {label:?}")]
    KeyNotFound {
        /// The key label looked for.
        label: String,
    },
    /// More than one object matched where one was required.
    #[error("{count} objects match {what}")]
    Ambiguous {
        /// What was looked for.
        what: String,
        /// How many matched.
        count: usize,
    },
    /// Any other PKCS#11 error. Retried with backoff.
    #[error("PKCS#11 error: {0}")]
    Other(String),
}

impl TokenError {
    /// Whether the error is fatal: a configuration, PIN or key problem that retrying can't
    /// fix. The others are recovered from by reopening the token (LLD 1, section 4.7).
    #[must_use]
    pub fn is_fatal(&self) -> bool {
        match self {
            Self::ModuleLoad(_)
            | Self::AmbiguousToken { .. }
            | Self::PinIncorrect
            | Self::PinLocked
            | Self::PinInvalid
            | Self::Unsupported(_)
            | Self::KeyNotFound { .. }
            | Self::Ambiguous { .. } => true,
            Self::NotPresent { .. } | Self::NotOpen | Self::TokenLost(_) | Self::Other(_) => false,
        }
    }
}

/// Converts a raw signature returned by a module into a fixed-size array.
pub(crate) fn raw_signature(bytes: &[u8]) -> Result<RawSignature, TokenError> {
    bytes.try_into().map_err(|_| {
        TokenError::Unsupported(format!(
            "signature is {} bytes, expected {RAW_SIGNATURE_LEN}",
            bytes.len()
        ))
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn classifies_errors_as_in_the_lld_table() {
        let fatal = [
            TokenError::ModuleLoad("x".into()),
            TokenError::AmbiguousToken {
                label: "helios".into(),
                count: 2,
            },
            TokenError::PinIncorrect,
            TokenError::PinLocked,
            TokenError::PinInvalid,
            TokenError::Unsupported("x".into()),
            TokenError::KeyNotFound {
                label: "device-key".into(),
            },
            TokenError::Ambiguous {
                what: "x".into(),
                count: 2,
            },
        ];
        let recoverable = [
            TokenError::NotPresent {
                label: "helios".into(),
            },
            TokenError::NotOpen,
            TokenError::TokenLost("x".into()),
            TokenError::Other("x".into()),
        ];

        for error in fatal {
            assert!(error.is_fatal(), "{error:?} should be fatal");
        }
        for error in recoverable {
            assert!(!error.is_fatal(), "{error:?} should be recoverable");
        }
    }

    #[test]
    fn error_messages_name_the_problem() {
        assert_eq!(
            TokenError::NotPresent {
                label: "helios".into()
            }
            .to_string(),
            "no token with label \"helios\""
        );
        assert_eq!(
            TokenError::AmbiguousToken {
                label: "helios".into(),
                count: 2
            }
            .to_string(),
            "2 tokens have label \"helios\""
        );
        assert_eq!(
            TokenError::KeyNotFound {
                label: "device-key".into()
            }
            .to_string(),
            "no private EC key with label \"device-key\""
        );
        assert_eq!(
            TokenError::Ambiguous {
                what: "certificates with CKA_ID 01".into(),
                count: 3
            }
            .to_string(),
            "3 objects match certificates with CKA_ID 01"
        );
        assert_eq!(
            TokenError::PinIncorrect.to_string(),
            "token PIN is incorrect"
        );
        assert_eq!(TokenError::NotOpen.to_string(), "token is not open");
    }

    #[test]
    fn raw_signatures_must_be_64_bytes() {
        assert_eq!(raw_signature(&[7; 64]), Ok([7; 64]));
        assert_eq!(
            raw_signature(&[7; 70]),
            Err(TokenError::Unsupported(
                "signature is 70 bytes, expected 64".into()
            ))
        );
    }
}
