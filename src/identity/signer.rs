//! The dedicated signer thread that owns the token (LLD 1, section 4.3).
//!
//! A PKCS#11 session can't be used from several threads at once, so one OS thread owns the
//! [`TokenBackend`]. The TLS signer sends [`SignerClient::sign`] requests and waits with a
//! timeout. The identity manager runs the open sequence on the same thread with
//! [`SignerHandle::run`].

use std::sync::mpsc;
use std::thread::JoinHandle;
use std::time::Duration;

use tokio::sync::{mpsc as tokio_mpsc, oneshot};

use crate::identity::token::{Digest, KeyRef, RawSignature, TokenBackend, TokenError};

/// Default time to wait for a signature. A hung pcscd or YubiKey looks like a removed token,
/// so a timeout counts as [`TokenError::TokenLost`].
pub const DEFAULT_SIGN_TIMEOUT: Duration = Duration::from_secs(5);

type Job = Box<dyn FnOnce(&mut dyn TokenBackend) + Send>;

enum Request {
    Sign {
        key: KeyRef,
        digest: Digest,
        reply: mpsc::SyncSender<Result<RawSignature, TokenError>>,
    },
    Run(Job),
    Shutdown,
}

/// The signer thread has stopped, so the request couldn't be run.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("the signer thread has stopped")]
pub struct SignerStopped;

/// Owns the signer thread. Dropping it asks the thread to close the token and stop.
#[derive(Debug)]
pub struct SignerHandle {
    client: SignerClient,
    thread: Option<JoinHandle<()>>,
}

/// Sends signing requests to the signer thread. Cheap to clone, and usable from any thread.
#[derive(Debug, Clone)]
pub struct SignerClient {
    requests: mpsc::Sender<Request>,
    lost: Option<tokio_mpsc::UnboundedSender<TokenError>>,
    timeout: Duration,
}

impl SignerHandle {
    /// Starts the signer thread with `backend`.
    ///
    /// Signing errors that mean the token is gone ([`TokenError::TokenLost`], including
    /// timeouts) are also sent to `lost`, so the identity manager can start recovery.
    ///
    /// # Errors
    ///
    /// Fails if the operating system can't start a thread.
    pub fn spawn(
        backend: Box<dyn TokenBackend>,
        lost: Option<tokio_mpsc::UnboundedSender<TokenError>>,
        timeout: Duration,
    ) -> std::io::Result<Self> {
        let (requests, receiver) = mpsc::channel();
        let thread = std::thread::Builder::new()
            .name("helios-signer".to_owned())
            .spawn(move || serve(backend, &receiver))?;
        Ok(Self {
            client: SignerClient {
                requests,
                lost,
                timeout,
            },
            thread: Some(thread),
        })
    }

    /// A client for signing requests.
    #[must_use]
    pub fn client(&self) -> SignerClient {
        self.client.clone()
    }

    /// Runs `job` on the signer thread with the backend and returns its result. Used by the
    /// identity manager for open, login, key lookup and close.
    ///
    /// # Errors
    ///
    /// [`SignerStopped`] if the thread has stopped.
    pub async fn run<R, F>(&self, job: F) -> Result<R, SignerStopped>
    where
        R: Send + 'static,
        F: FnOnce(&mut dyn TokenBackend) -> R + Send + 'static,
    {
        let (reply, result) = oneshot::channel();
        let job: Job = Box::new(move |backend| {
            // The caller may have stopped waiting. There is nothing to do then.
            let _ = reply.send(job(backend));
        });
        self.client
            .requests
            .send(Request::Run(job))
            .map_err(|_| SignerStopped)?;
        result.await.map_err(|_| SignerStopped)
    }

    /// Closes the token and waits for the thread to stop.
    pub fn shutdown(mut self) {
        self.stop(true);
    }

    fn stop(&mut self, wait: bool) {
        let _ = self.client.requests.send(Request::Shutdown);
        if let Some(thread) = self.thread.take()
            && wait
        {
            // A panic on the signer thread was already reported by the panic hook.
            let _ = thread.join();
        }
    }
}

impl Drop for SignerHandle {
    fn drop(&mut self) {
        self.stop(false);
    }
}

impl SignerClient {
    /// Signs `digest` with `key` and waits up to the configured timeout. Blocks the calling
    /// thread, because rustls calls signers synchronously.
    ///
    /// # Errors
    ///
    /// The backend's error, [`TokenError::TokenLost`] on a timeout, or
    /// [`TokenError::TokenLost`] if the signer thread has stopped.
    pub fn sign(&self, key: &KeyRef, digest: &Digest) -> Result<RawSignature, TokenError> {
        let (reply, result) = mpsc::sync_channel(1);
        let request = Request::Sign {
            key: key.clone(),
            digest: *digest,
            reply,
        };
        let outcome = if self.requests.send(request).is_err() {
            Err(TokenError::TokenLost(
                "the signer thread has stopped".to_owned(),
            ))
        } else {
            match result.recv_timeout(self.timeout) {
                Ok(outcome) => outcome,
                Err(mpsc::RecvTimeoutError::Timeout) => Err(TokenError::TokenLost(format!(
                    "signing timed out after {} ms",
                    self.timeout.as_millis()
                ))),
                Err(mpsc::RecvTimeoutError::Disconnected) => Err(TokenError::TokenLost(
                    "the signer thread has stopped".to_owned(),
                )),
            }
        };
        if let Err(error @ TokenError::TokenLost(_)) = &outcome
            && let Some(lost) = &self.lost
        {
            // The manager may have shut down. There is nobody left to tell then.
            let _ = lost.send(error.clone());
        }
        outcome
    }
}

fn serve(mut backend: Box<dyn TokenBackend>, requests: &mpsc::Receiver<Request>) {
    for request in requests {
        match request {
            Request::Sign { key, digest, reply } => {
                // The caller may have timed out and stopped waiting.
                let _ = reply.send(backend.sign_digest(&key, &digest));
            }
            Request::Run(job) => job(backend.as_mut()),
            Request::Shutdown => break,
        }
    }
    backend.close();
}

#[cfg(test)]
mod tests {
    use p256::ecdsa::signature::hazmat::PrehashVerifier;
    use p256::ecdsa::{Signature, SigningKey, VerifyingKey};
    use secrecy::SecretString;

    use super::*;
    use crate::identity::mock::{MockKey, MockToken, Op};

    fn token_with_key() -> (MockToken, SigningKey) {
        let token = MockToken::new("1234");
        let signing_key = SigningKey::from_slice(&[5; 32]).unwrap();
        token.add_key(MockKey {
            label: "device-key".into(),
            id: vec![1],
            signing_key: signing_key.clone(),
            private: true,
            certificate: None,
        });
        (token, signing_key)
    }

    async fn open(handle: &SignerHandle) -> KeyRef {
        handle
            .run(|backend| {
                backend.open()?;
                backend.login(&SecretString::new("1234".into()))?;
                backend.find_key("device-key")
            })
            .await
            .unwrap()
            .unwrap()
    }

    #[tokio::test]
    async fn signs_on_the_signer_thread() {
        let (token, signing_key) = token_with_key();
        let handle =
            SignerHandle::spawn(Box::new(token.clone()), None, DEFAULT_SIGN_TIMEOUT).unwrap();
        let key = open(&handle).await;
        let client = handle.client();

        let raw = tokio::task::spawn_blocking(move || client.sign(&key, &[4; 32]))
            .await
            .unwrap()
            .unwrap();

        let signature = Signature::from_slice(&raw).unwrap();
        assert!(
            VerifyingKey::from(&signing_key)
                .verify_prehash(&[4; 32], &signature)
                .is_ok()
        );
        handle.shutdown();
        assert!(!token.is_open(), "shutdown should close the token");
    }

    #[tokio::test]
    async fn reports_lost_tokens_to_the_manager() {
        let (token, _) = token_with_key();
        let (lost_tx, mut lost_rx) = tokio_mpsc::unbounded_channel();
        let handle =
            SignerHandle::spawn(Box::new(token.clone()), Some(lost_tx), DEFAULT_SIGN_TIMEOUT)
                .unwrap();
        let key = open(&handle).await;
        token.fail_next(Op::SignDigest, TokenError::TokenLost("unplugged".into()));
        token.fail_next(Op::SignDigest, TokenError::PinIncorrect);
        let client = handle.client();

        let (first, second) = tokio::task::spawn_blocking(move || {
            (client.sign(&key, &[1; 32]), client.sign(&key, &[1; 32]))
        })
        .await
        .unwrap();

        assert_eq!(first, Err(TokenError::TokenLost("unplugged".into())));
        assert_eq!(second, Err(TokenError::PinIncorrect));
        assert_eq!(
            lost_rx.recv().await,
            Some(TokenError::TokenLost("unplugged".into()))
        );
        // Only TokenLost is reported, not other errors.
        assert!(lost_rx.try_recv().is_err());
    }

    #[tokio::test]
    async fn a_slow_token_times_out_as_lost() {
        let (token, _) = token_with_key();
        let (lost_tx, mut lost_rx) = tokio_mpsc::unbounded_channel();
        let handle = SignerHandle::spawn(
            Box::new(token.clone()),
            Some(lost_tx),
            Duration::from_millis(50),
        )
        .unwrap();
        let key = open(&handle).await;
        token.set_sign_delay(Duration::from_millis(500));
        let client = handle.client();

        let outcome = tokio::task::spawn_blocking(move || client.sign(&key, &[1; 32]))
            .await
            .unwrap();

        let expected = TokenError::TokenLost("signing timed out after 50 ms".into());
        assert_eq!(outcome, Err(expected.clone()));
        assert_eq!(lost_rx.recv().await, Some(expected));
        // The late reply is dropped without panicking the signer thread.
        token.set_sign_delay(Duration::ZERO);
        handle.shutdown();
    }

    #[tokio::test]
    async fn requests_fail_once_the_thread_has_stopped() {
        let (token, _) = token_with_key();
        let (lost_tx, mut lost_rx) = tokio_mpsc::unbounded_channel();
        let handle =
            SignerHandle::spawn(Box::new(token), Some(lost_tx), DEFAULT_SIGN_TIMEOUT).unwrap();
        let key = open(&handle).await;
        let client = handle.client();
        handle.shutdown();

        let stopped = TokenError::TokenLost("the signer thread has stopped".into());
        assert_eq!(client.sign(&key, &[1; 32]), Err(stopped.clone()));
        assert_eq!(lost_rx.recv().await, Some(stopped));
    }

    #[tokio::test]
    async fn run_fails_once_the_thread_has_stopped() {
        let (token, _) = token_with_key();
        let mut handle = SignerHandle::spawn(Box::new(token), None, DEFAULT_SIGN_TIMEOUT).unwrap();
        handle.stop(true);

        assert_eq!(handle.run(|_| ()).await, Err(SignerStopped));
        assert_eq!(SignerStopped.to_string(), "the signer thread has stopped");
    }

    #[tokio::test]
    async fn a_reply_lost_in_flight_is_reported_as_stopped() {
        let (token, _) = token_with_key();
        let handle = SignerHandle::spawn(Box::new(token), None, DEFAULT_SIGN_TIMEOUT).unwrap();

        // The job panics before replying, so the reply sender is dropped unanswered and the
        // signer thread stops.
        let outcome = handle
            .run::<(), _>(|_| panic!("job failed on purpose"))
            .await;

        assert_eq!(outcome, Err(SignerStopped));
    }

    /// A backend whose signing panics, like a crashing PKCS#11 module.
    struct CrashingToken;

    impl TokenBackend for CrashingToken {
        fn open(&mut self) -> Result<crate::identity::token::TokenSummary, TokenError> {
            Err(TokenError::NotOpen)
        }
        fn pin_status(&mut self) -> Result<crate::identity::token::PinStatus, TokenError> {
            Err(TokenError::NotOpen)
        }
        fn sign_without_login(&mut self, _: &str, _: &Digest) -> Result<RawSignature, TokenError> {
            Err(TokenError::NotOpen)
        }
        fn login(&mut self, _: &SecretString) -> Result<(), TokenError> {
            Err(TokenError::NotOpen)
        }
        fn find_key(&mut self, _: &str) -> Result<KeyRef, TokenError> {
            Err(TokenError::NotOpen)
        }
        fn read_certificate(&mut self, _: &KeyRef) -> Result<Option<Vec<u8>>, TokenError> {
            Err(TokenError::NotOpen)
        }
        fn sign_digest(&mut self, _: &KeyRef, _: &Digest) -> Result<RawSignature, TokenError> {
            panic!("the PKCS#11 module crashed on purpose")
        }
        fn close(&mut self) {}
    }

    #[test]
    fn a_signer_thread_that_dies_mid_request_reports_the_token_lost() {
        let handle =
            SignerHandle::spawn(Box::new(CrashingToken), None, DEFAULT_SIGN_TIMEOUT).unwrap();
        let key = KeyRef {
            label: "device-key".into(),
            id: vec![1],
            handle: crate::identity::token::KeyHandle {
                generation: 0,
                index: 0,
            },
        };

        let outcome = handle.client().sign(&key, &[1; 32]);

        assert_eq!(
            outcome,
            Err(TokenError::TokenLost(
                "the signer thread has stopped".into()
            ))
        );
        // Fails the same way for every open/close/stop call on the crashing backend.
        let mut crashing = CrashingToken;
        assert_eq!(crashing.open(), Err(TokenError::NotOpen));
        assert_eq!(crashing.pin_status(), Err(TokenError::NotOpen));
        assert_eq!(
            crashing.sign_without_login("x", &[0; 32]),
            Err(TokenError::NotOpen)
        );
        assert_eq!(
            crashing.login(&SecretString::new("1".into())),
            Err(TokenError::NotOpen)
        );
        assert_eq!(crashing.find_key("x"), Err(TokenError::NotOpen));
        assert_eq!(crashing.read_certificate(&key), Err(TokenError::NotOpen));
        crashing.close();
    }

    #[tokio::test]
    async fn dropping_the_handle_stops_the_thread() {
        let (token, _) = token_with_key();
        let handle =
            SignerHandle::spawn(Box::new(token.clone()), None, DEFAULT_SIGN_TIMEOUT).unwrap();
        open(&handle).await;
        let client = handle.client();

        drop(handle);

        // The thread closes the token when it sees the shutdown request.
        for _ in 0..100 {
            if !token.is_open() {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        assert!(!token.is_open());
        drop(client);
    }
}
