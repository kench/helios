//! A [`TokenBackend`] for tests that behaves like a small PKCS#11 token and can inject
//! failures (LLD 1, section 9: tests with a mock token).
//!
//! The state is shared through an `Arc`, so a test can keep a [`MockToken`] handle to inspect
//! calls and inject errors after the backend has moved to another thread.

use std::collections::{HashMap, VecDeque};
use std::path::PathBuf;
use std::sync::{Arc, Mutex, MutexGuard};

use p256::ecdsa::signature::hazmat::PrehashSigner;
use p256::ecdsa::{Signature, SigningKey};
use secrecy::{ExposeSecret, SecretString};

use crate::identity::token::{
    Digest, KeyHandle, KeyRef, PinStatus, RawSignature, TokenBackend, TokenError, TokenSummary,
};

/// The operations a test can inject a failure into.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(crate) enum Op {
    Open,
    PinStatus,
    SignWithoutLogin,
    Login,
    FindKey,
    ReadCertificate,
    SignDigest,
}

/// A key on the mock token.
#[derive(Debug, Clone)]
pub(crate) struct MockKey {
    pub(crate) label: String,
    pub(crate) id: Vec<u8>,
    pub(crate) signing_key: SigningKey,
    /// `CKA_PRIVATE`: if true, the key is only visible after login.
    pub(crate) private: bool,
    /// DER certificate stored with the same `CKA_ID`.
    pub(crate) certificate: Option<Vec<u8>>,
}

#[derive(Debug)]
struct State {
    summary: TokenSummary,
    pin: String,
    pin_status: PinStatus,
    keys: Vec<MockKey>,
    open: bool,
    logged_in: bool,
    generation: u64,
    calls: Vec<Op>,
    failures: HashMap<Op, VecDeque<TokenError>>,
}

/// A mock token. Clones share the same state.
#[derive(Debug, Clone)]
pub(crate) struct MockToken {
    state: Arc<Mutex<State>>,
}

impl MockToken {
    /// A token with label `helios`, user PIN `pin` and no keys.
    pub(crate) fn new(pin: &str) -> Self {
        let summary = TokenSummary {
            module: PathBuf::from("/mock/libmock-pkcs11.so"),
            label: "helios".to_owned(),
            manufacturer: "Helios tests".to_owned(),
            model: "MockToken".to_owned(),
            serial: "0001".to_owned(),
        };
        let state = State {
            summary,
            pin: pin.to_owned(),
            pin_status: PinStatus::default(),
            keys: Vec::new(),
            open: false,
            logged_in: false,
            generation: 0,
            calls: Vec::new(),
            failures: HashMap::new(),
        };
        Self {
            state: Arc::new(Mutex::new(state)),
        }
    }

    fn state(&self) -> MutexGuard<'_, State> {
        self.state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    /// Adds a key.
    pub(crate) fn add_key(&self, key: MockKey) {
        self.state().keys.push(key);
    }

    /// Sets the PIN flags that [`TokenBackend::pin_status`] reports.
    pub(crate) fn set_pin_status(&self, status: PinStatus) {
        self.state().pin_status = status;
    }

    /// Makes the next call of `op` fail with `error`. Several failures queue up in order.
    pub(crate) fn fail_next(&self, op: Op, error: TokenError) {
        self.state()
            .failures
            .entry(op)
            .or_default()
            .push_back(error);
    }

    /// The operations called so far, in order. `close` isn't recorded.
    pub(crate) fn calls(&self) -> Vec<Op> {
        self.state().calls.clone()
    }

    /// Whether the token is open.
    pub(crate) fn is_open(&self) -> bool {
        self.state().open
    }

    /// Whether the user is logged in.
    pub(crate) fn is_logged_in(&self) -> bool {
        self.state().logged_in
    }
}

impl State {
    /// Records the call and returns an injected failure, if one is queued.
    fn enter(&mut self, op: Op) -> Result<(), TokenError> {
        self.calls.push(op);
        if let Some(error) = self.failures.get_mut(&op).and_then(VecDeque::pop_front) {
            return Err(error);
        }
        if op != Op::Open && !self.open {
            return Err(TokenError::NotOpen);
        }
        Ok(())
    }

    fn visible_key(&self, label: &str) -> Result<usize, TokenError> {
        let matches: Vec<usize> = self
            .keys
            .iter()
            .enumerate()
            .filter(|(_, key)| key.label == label && (self.logged_in || !key.private))
            .map(|(index, _)| index)
            .collect();
        match matches.as_slice() {
            [] => Err(TokenError::KeyNotFound {
                label: label.to_owned(),
            }),
            [index] => Ok(*index),
            more => Err(TokenError::Ambiguous {
                what: format!("private EC keys with label {label:?}"),
                count: more.len(),
            }),
        }
    }

    fn key(&self, key: &KeyRef) -> Result<&MockKey, TokenError> {
        if key.handle.generation != self.generation {
            return Err(TokenError::NotOpen);
        }
        self.keys.get(key.handle.index).ok_or(TokenError::NotOpen)
    }
}

fn sign(key: &MockKey, digest: &Digest) -> Result<RawSignature, TokenError> {
    let signature: Signature = key
        .signing_key
        .sign_prehash(digest)
        .map_err(|e| TokenError::Other(e.to_string()))?;
    Ok(signature.to_bytes().into())
}

impl TokenBackend for MockToken {
    fn open(&mut self) -> Result<TokenSummary, TokenError> {
        let mut state = self.state();
        state.enter(Op::Open)?;
        state.open = true;
        state.logged_in = false;
        state.generation += 1;
        Ok(state.summary.clone())
    }

    fn pin_status(&mut self) -> Result<PinStatus, TokenError> {
        let mut state = self.state();
        state.enter(Op::PinStatus)?;
        Ok(state.pin_status)
    }

    fn sign_without_login(
        &mut self,
        label: &str,
        digest: &Digest,
    ) -> Result<RawSignature, TokenError> {
        let mut state = self.state();
        state.enter(Op::SignWithoutLogin)?;
        let index = state.visible_key(label)?;
        let key = &state.keys[index];
        if key.private {
            return Err(TokenError::KeyNotFound {
                label: label.to_owned(),
            });
        }
        sign(key, digest)
    }

    fn login(&mut self, pin: &SecretString) -> Result<(), TokenError> {
        let mut state = self.state();
        state.enter(Op::Login)?;
        if state.pin_status.locked {
            return Err(TokenError::PinLocked);
        }
        if pin.expose_secret() != &state.pin {
            return Err(TokenError::PinIncorrect);
        }
        state.logged_in = true;
        Ok(())
    }

    fn find_key(&mut self, label: &str) -> Result<KeyRef, TokenError> {
        let mut state = self.state();
        state.enter(Op::FindKey)?;
        let index = state.visible_key(label)?;
        let key = &state.keys[index];
        Ok(KeyRef {
            label: key.label.clone(),
            id: key.id.clone(),
            handle: KeyHandle {
                generation: state.generation,
                index,
            },
        })
    }

    fn read_certificate(&mut self, key: &KeyRef) -> Result<Option<Vec<u8>>, TokenError> {
        let mut state = self.state();
        state.enter(Op::ReadCertificate)?;
        Ok(state.key(key)?.certificate.clone())
    }

    fn sign_digest(&mut self, key: &KeyRef, digest: &Digest) -> Result<RawSignature, TokenError> {
        let mut state = self.state();
        state.enter(Op::SignDigest)?;
        let key = state.key(key)?;
        if key.private && !state.logged_in {
            return Err(TokenError::Other("CKR_USER_NOT_LOGGED_IN".to_owned()));
        }
        sign(key, digest)
    }

    fn close(&mut self) {
        let mut state = self.state();
        state.open = false;
        state.logged_in = false;
    }
}

#[cfg(test)]
mod tests {
    use p256::ecdsa::VerifyingKey;
    use p256::ecdsa::signature::hazmat::PrehashVerifier;

    use super::*;

    fn key(label: &str, id: u8, private: bool) -> MockKey {
        MockKey {
            label: label.to_owned(),
            id: vec![id],
            signing_key: SigningKey::from_slice(&[id.max(1); 32]).unwrap(),
            private,
            certificate: Some(vec![0x30, id]),
        }
    }

    fn pin(value: &str) -> SecretString {
        SecretString::new(value.to_owned())
    }

    fn verifies(key: &MockKey, digest: &Digest, raw: &RawSignature) -> bool {
        let signature = Signature::from_slice(raw).unwrap();
        VerifyingKey::from(&key.signing_key)
            .verify_prehash(digest, &signature)
            .is_ok()
    }

    #[test]
    fn follows_the_open_login_sign_sequence() {
        let token = MockToken::new("1234");
        let device_key = key("device-key", 1, true);
        token.add_key(device_key.clone());
        let mut backend = token.clone();

        let summary = backend.open().unwrap();
        assert_eq!(summary.label, "helios");
        assert!(token.is_open());
        assert_eq!(backend.pin_status(), Ok(PinStatus::default()));
        backend.login(&pin("1234")).unwrap();
        assert!(token.is_logged_in());
        let key_ref = backend.find_key("device-key").unwrap();
        assert_eq!(key_ref.id, vec![1]);
        assert_eq!(backend.read_certificate(&key_ref), Ok(Some(vec![0x30, 1])));
        let raw = backend.sign_digest(&key_ref, &[9; 32]).unwrap();
        assert!(verifies(&device_key, &[9; 32], &raw));

        backend.close();
        assert!(!token.is_open());
        assert!(!token.is_logged_in());
        assert_eq!(
            token.calls(),
            [
                Op::Open,
                Op::PinStatus,
                Op::Login,
                Op::FindKey,
                Op::ReadCertificate,
                Op::SignDigest
            ]
        );
    }

    #[test]
    fn private_keys_are_hidden_until_login() {
        let token = MockToken::new("1234");
        token.add_key(key("device-key", 1, true));
        let mut backend = token.clone();
        backend.open().unwrap();

        assert_eq!(
            backend.find_key("device-key"),
            Err(TokenError::KeyNotFound {
                label: "device-key".into()
            })
        );
        assert_eq!(
            backend.sign_without_login("device-key", &[1; 32]),
            Err(TokenError::KeyNotFound {
                label: "device-key".into()
            })
        );
    }

    #[test]
    fn public_keys_sign_without_login() {
        let token = MockToken::new("1234");
        let challenge_key = key("challenge-key", 2, false);
        token.add_key(challenge_key.clone());
        let mut backend = token.clone();
        backend.open().unwrap();

        let raw = backend
            .sign_without_login("challenge-key", &[3; 32])
            .unwrap();

        assert!(verifies(&challenge_key, &[3; 32], &raw));
        assert!(!token.is_logged_in());
    }

    #[test]
    fn a_visible_private_key_still_cannot_sign_without_login() {
        let token = MockToken::new("1234");
        token.add_key(key("device-key", 1, true));
        let mut backend = token.clone();
        backend.open().unwrap();
        backend.login(&pin("1234")).unwrap();

        // Logged in, the key is visible, but sign_without_login only allows public keys.
        assert_eq!(
            backend.sign_without_login("device-key", &[1; 32]),
            Err(TokenError::KeyNotFound {
                label: "device-key".into()
            })
        );
    }

    #[test]
    fn signing_with_a_private_key_needs_login() {
        let token = MockToken::new("1234");
        token.add_key(key("device-key", 1, true));
        let mut backend = token.clone();
        backend.open().unwrap();
        backend.login(&pin("1234")).unwrap();
        let key_ref = backend.find_key("device-key").unwrap();
        // Reopening logs out but keeps the handle's generation stale.
        backend.close();
        backend.open().unwrap();

        assert_eq!(
            backend.sign_digest(&key_ref, &[1; 32]),
            Err(TokenError::NotOpen)
        );
        let fresh = KeyRef {
            handle: KeyHandle {
                generation: 2,
                index: 0,
            },
            ..key_ref
        };
        assert_eq!(
            backend.sign_digest(&fresh, &[1; 32]),
            Err(TokenError::Other("CKR_USER_NOT_LOGGED_IN".into()))
        );
    }

    #[test]
    fn rejects_wrong_and_locked_pins() {
        let token = MockToken::new("1234");
        let mut backend = token.clone();
        backend.open().unwrap();

        assert_eq!(backend.login(&pin("0000")), Err(TokenError::PinIncorrect));
        token.set_pin_status(PinStatus {
            locked: true,
            final_try: false,
            count_low: true,
        });
        assert_eq!(
            backend.pin_status(),
            Ok(PinStatus {
                locked: true,
                final_try: false,
                count_low: true
            })
        );
        assert_eq!(backend.login(&pin("1234")), Err(TokenError::PinLocked));
        assert!(!token.is_logged_in());
    }

    #[test]
    fn reports_ambiguous_keys() {
        let token = MockToken::new("1234");
        token.add_key(key("device-key", 1, false));
        token.add_key(key("device-key", 2, false));
        let mut backend = token.clone();
        backend.open().unwrap();

        assert_eq!(
            backend.find_key("device-key"),
            Err(TokenError::Ambiguous {
                what: "private EC keys with label \"device-key\"".into(),
                count: 2
            })
        );
    }

    #[test]
    fn injected_failures_are_returned_in_order_once() {
        let token = MockToken::new("1234");
        token.fail_next(
            Op::Open,
            TokenError::NotPresent {
                label: "helios".into(),
            },
        );
        token.fail_next(Op::Open, TokenError::TokenLost("unplugged".into()));
        let mut backend = token.clone();

        assert_eq!(
            backend.open(),
            Err(TokenError::NotPresent {
                label: "helios".into()
            })
        );
        assert_eq!(
            backend.open(),
            Err(TokenError::TokenLost("unplugged".into()))
        );
        assert!(backend.open().is_ok());
        assert_eq!(token.calls(), [Op::Open, Op::Open, Op::Open]);
    }

    #[test]
    fn calls_before_open_fail() {
        let token = MockToken::new("1234");
        let mut backend = token.clone();
        let key_ref = KeyRef {
            label: "device-key".into(),
            id: vec![1],
            handle: KeyHandle {
                generation: 0,
                index: 0,
            },
        };

        assert_eq!(backend.pin_status(), Err(TokenError::NotOpen));
        assert_eq!(backend.login(&pin("1234")), Err(TokenError::NotOpen));
        assert_eq!(backend.find_key("device-key"), Err(TokenError::NotOpen));
        assert_eq!(backend.read_certificate(&key_ref), Err(TokenError::NotOpen));
        assert_eq!(
            backend.sign_digest(&key_ref, &[0; 32]),
            Err(TokenError::NotOpen)
        );
        assert_eq!(
            backend.sign_without_login("x", &[0; 32]),
            Err(TokenError::NotOpen)
        );
    }

    #[test]
    fn stale_or_unknown_key_references_are_rejected() {
        let token = MockToken::new("1234");
        let mut backend = token.clone();
        backend.open().unwrap();
        let unknown = KeyRef {
            label: "device-key".into(),
            id: vec![1],
            handle: KeyHandle {
                generation: 1,
                index: 5,
            },
        };

        assert_eq!(backend.read_certificate(&unknown), Err(TokenError::NotOpen));
    }
}
