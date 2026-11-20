//! The identity manager: opens the token, checks the certificate, publishes the identity and
//! recovers when the token is lost (LLD 1, sections 4.1, 4.6 and 4.7).
//!
//! The manager runs as a tokio task. It runs the open sequence on the signer thread, checks
//! the result, swaps the certified key into the shared [`Resolver`] and publishes an
//! [`IdentityState`] on a watch channel. The MQTT and credential managers connect only while
//! the state is [`IdentityState::Ready`].
//!
//! A lost token (a signature that fails or times out) clears the resolver, closes the token
//! and retries with backoff until the token is back. PIN, key and certificate problems that
//! retrying can't fix end the manager with [`ManagerExit::Fatal`], and Helios exits with
//! code 78 so systemd doesn't restart it and spend another PIN try.

use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime};

use rustls::sign::CertifiedKey;
use rustls::{ClientConfig, RootCertStore};
use rustls_pki_types::CertificateDer;
use tokio::sync::{Notify, mpsc, oneshot, watch};
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;

use crate::build_info;
use crate::identity::cert::{self, CertError, DeviceCertificate, Validity};
use crate::identity::pin::{PinError, PinSource};
use crate::identity::signer::{DEFAULT_SIGN_TIMEOUT, SignerHandle};
use crate::identity::tls::{self, Alpn, Resolver, TlsError};
use crate::identity::token::{
    Digest, KeyRef, RawSignature, TokenBackend, TokenError, TokenSummary,
};

/// Where the device certificate comes from (`identity.certificate`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CertificateSource {
    /// Read from the token: the certificate object with the key's `CKA_ID`.
    Token,
    /// Supplied by the caller, such as a PEM file: the device certificate first, then any
    /// intermediates.
    Chain(Vec<CertificateDer<'static>>),
}

/// Retry timing (LLD 1, section 4.7).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Recovery {
    /// First retry delay after the token is lost or missing. Doubles on each failure.
    pub initial_backoff: Duration,
    /// Longest retry delay.
    pub max_backoff: Duration,
    /// Retry delay while the certificate has expired. AWS IoT would reject it anyway.
    pub expired_retry: Duration,
    /// How long to wait for the open sequence before treating the token as unavailable. The
    /// next attempt keeps waiting for the same open rather than queueing another.
    pub open_timeout: Duration,
}

impl Default for Recovery {
    fn default() -> Self {
        Self {
            initial_backoff: Duration::from_secs(1),
            max_backoff: Duration::from_secs(30),
            expired_retry: Duration::from_secs(60 * 60),
            open_timeout: Duration::from_secs(30),
        }
    }
}

/// Identity manager settings, from the `[identity]` and `[device]` config (or the bootstrap
/// response).
#[derive(Debug, Clone)]
pub struct ManagerConfig {
    /// The AWS IoT thing name. The certificate's subject CN should match it.
    pub thing_name: String,
    /// `CKA_LABEL` of the device key.
    pub key_label: String,
    /// Where the certificate comes from.
    pub certificate: CertificateSource,
    /// Log in even when the token says the next wrong PIN locks it.
    pub allow_final_pin_try: bool,
    /// How long a TLS signature may take before the token counts as lost.
    pub sign_timeout: Duration,
    /// The earliest time the clock can plausibly show. Earlier than this, certificate dates
    /// are only warned about. Defaults to the build time.
    pub earliest_trusted: SystemTime,
    /// Retry timing.
    pub recovery: Recovery,
}

impl ManagerConfig {
    /// Settings for `thing_name` with the key labelled `key_label`, and defaults for the rest:
    /// the certificate from the token, no final PIN try, a 5 s sign timeout and the build time
    /// as the earliest trusted time.
    #[must_use]
    pub fn new(thing_name: impl Into<String>, key_label: impl Into<String>) -> Self {
        Self {
            thing_name: thing_name.into(),
            key_label: key_label.into(),
            certificate: CertificateSource::Token,
            allow_final_pin_try: false,
            sign_timeout: DEFAULT_SIGN_TIMEOUT,
            earliest_trusted: build_info::build_time(),
            recovery: Recovery::default(),
        }
    }
}

/// The identity's state, published on a watch channel.
#[derive(Debug, Clone)]
pub enum IdentityState {
    /// Opening the token for the first time.
    Starting,
    /// The token is open and the certificate checked. TLS connections can be made.
    Ready(Arc<Identity>),
    /// The token is missing or lost, or the certificate isn't valid yet or has expired.
    /// Retrying.
    Unavailable {
        /// Why, for logs and the `helios` shadow.
        reason: String,
        /// When the identity became unavailable.
        since: Instant,
    },
    /// A problem retrying can't fix. Helios exits with code 78.
    Fatal {
        /// Why.
        reason: FatalReason,
    },
}

impl IdentityState {
    /// The identity, if the state is [`Ready`](Self::Ready).
    #[must_use]
    pub fn identity(&self) -> Option<&Arc<Identity>> {
        match self {
            Self::Ready(identity) => Some(identity),
            _ => None,
        }
    }

    /// The state's name as reported in the `helios` shadow (`identity.state`).
    #[must_use]
    pub fn name(&self) -> &'static str {
        match self {
            Self::Starting => "starting",
            Self::Ready(_) => "ready",
            Self::Unavailable { .. } => "unavailable",
            Self::Fatal { .. } => "fatal",
        }
    }
}

/// The device identity while the token is ready.
#[derive(Debug)]
pub struct Identity {
    /// The certificate chain and token-backed key presented in TLS handshakes.
    pub certified_key: Arc<CertifiedKey>,
    /// The device certificate.
    pub cert: CertInfo,
    /// The token it was opened from (no secrets).
    pub token: TokenSummary,
    /// Device settings.
    pub device: DeviceInfo,
    /// Problems worth reporting that don't stop the identity being used.
    pub warnings: Vec<Warning>,
}

/// Facts about the device certificate, for logs and the `helios` shadow.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CertInfo {
    /// The subject CN, if there is one.
    pub subject_cn: Option<String>,
    /// End of the validity period.
    pub not_after: SystemTime,
    /// SHA-256 fingerprint as lowercase hex.
    pub fingerprint: String,
}

/// Device settings.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeviceInfo {
    /// The AWS IoT thing name.
    pub thing_name: String,
}

/// A problem that doesn't stop the identity being used. Each one is logged as a warning.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum Warning {
    /// A wrong PIN was entered since the last successful login (`user_pin_count_low`).
    #[error("a wrong PIN was entered since the last successful login")]
    PinCountLow,
    /// The certificate expires within 30 days.
    #[error("certificate expires in {} days", remaining.as_secs() / (24 * 60 * 60))]
    ExpiresSoon {
        /// Time left.
        remaining: Duration,
    },
    /// The system clock is earlier than the build time, so the certificate dates weren't
    /// checked.
    #[error("system clock is earlier than the build time; certificate dates were not checked")]
    ClockUntrusted,
    /// The certificate's subject CN isn't the thing name. AWS IoT doesn't require it to be.
    #[error("certificate subject CN {subject_cn:?} does not match thing name {thing_name:?}")]
    SubjectMismatch {
        /// The certificate's subject CN.
        subject_cn: Option<String>,
        /// The configured thing name.
        thing_name: String,
    },
    /// The certificate changed since the last time the token was open, for example because a
    /// different YubiKey was plugged in.
    #[error("certificate changed (previous fingerprint {previous})")]
    CertificateChanged {
        /// The previous certificate's fingerprint.
        previous: String,
    },
}

/// Why the identity can't be used without someone fixing the device (LLD 1, section 8).
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum FatalReason {
    /// The user PIN is locked. Only the PUK can unlock it.
    #[error("token PIN is locked")]
    PinLocked,
    /// The next wrong PIN would lock the token, so login wasn't tried.
    #[error("token PIN has one try left; not logging in (set allow_final_pin_try to override)")]
    PinFinalTry,
    /// The PIN is wrong. One try was used.
    #[error("token PIN is incorrect")]
    PinIncorrect,
    /// The PIN has an invalid length.
    #[error("token PIN has an invalid length")]
    PinInvalid,
    /// The PIN couldn't be read.
    #[error(transparent)]
    PinSource(PinError),
    /// A token error retrying can't fix, such as a missing module or key.
    #[error(transparent)]
    Token(TokenError),
    /// No certificate was found for the key.
    #[error("no certificate on the token for key {key_label:?}")]
    CertificateMissing {
        /// The key label.
        key_label: String,
    },
    /// The certificate isn't usable: not P-256, unparseable, or not for the token's key.
    #[error(transparent)]
    Certificate(CertError),
    /// The operating system's random number generator failed.
    #[error("random number generator failed: {0}")]
    Random(String),
}

/// Why the manager stopped.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ManagerExit {
    /// A fatal problem. Exit with code 78 (`EX_CONFIG`) so systemd doesn't restart.
    Fatal(FatalReason),
    /// The signer thread stopped, for example because the PKCS#11 module crashed. Exit with
    /// an error so systemd restarts Helios.
    SignerStopped,
    /// Shutdown was requested.
    Cancelled,
}

/// Access to the identity for the MQTT and credential managers. Cheap to clone.
#[derive(Debug, Clone)]
pub struct IdentityHandle {
    state: watch::Receiver<IdentityState>,
    resolver: Arc<Resolver>,
    roots: Arc<RootCertStore>,
    poke: Arc<Notify>,
}

impl IdentityHandle {
    /// A receiver for the state. Await changes with `changed()`.
    #[must_use]
    pub fn watch(&self) -> watch::Receiver<IdentityState> {
        self.state.clone()
    }

    /// The current state.
    #[must_use]
    pub fn state(&self) -> IdentityState {
        self.state.borrow().clone()
    }

    /// A TLS client config that verifies servers against the root CAs and always presents
    /// the current identity.
    ///
    /// # Errors
    ///
    /// [`TlsError::Config`] if rustls rejects the configuration.
    pub fn tls_config(&self, alpn: Alpn) -> Result<Arc<ClientConfig>, TlsError> {
        tls::client_config((*self.roots).clone(), self.resolver.clone(), alpn)
    }

    /// Asks the manager to retry opening the token now, for example on a Yubico USB attach
    /// event. Does nothing while the identity is ready.
    pub fn poke(&self) {
        self.poke.notify_one();
    }
}

/// Starts the identity manager.
pub struct IdentityManager;

impl IdentityManager {
    /// Starts the signer thread with `backend` and the manager task, which opens the token
    /// straight away. Returns a handle and the task, which ends when the identity is fatal,
    /// the signer thread stops, or `cancel` is cancelled.
    ///
    /// # Errors
    ///
    /// Fails if the operating system can't start the signer thread.
    ///
    /// # Panics
    ///
    /// Panics if called outside a tokio runtime.
    pub fn start(
        config: ManagerConfig,
        backend: Box<dyn TokenBackend>,
        pin: Arc<dyn PinSource>,
        roots: RootCertStore,
        cancel: CancellationToken,
    ) -> std::io::Result<(IdentityHandle, JoinHandle<ManagerExit>)> {
        let (lost_tx, lost) = mpsc::unbounded_channel();
        let signer = SignerHandle::spawn(backend, Some(lost_tx), config.sign_timeout)?;
        let (state_tx, state) = watch::channel(IdentityState::Starting);
        let resolver = Arc::new(Resolver::new());
        let poke = Arc::new(Notify::new());
        let backoff = Backoff::new(config.recovery.initial_backoff, config.recovery.max_backoff);
        let manager = Manager {
            config,
            signer,
            lost,
            state: state_tx,
            resolver: resolver.clone(),
            poke: poke.clone(),
            cancel,
            pin,
            pending: None,
            last_fingerprint: None,
            backoff,
        };
        let handle = IdentityHandle {
            state,
            resolver,
            roots: Arc::new(roots),
            poke,
        };
        Ok((handle, tokio::spawn(manager.run())))
    }
}

/// When to retry after a failed open.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Retry {
    Backoff,
    Expired,
}

/// Why an open attempt didn't produce an identity.
#[derive(Debug)]
enum Failure {
    Fatal(FatalReason),
    Unavailable { reason: String, retry: Retry },
}

impl Failure {
    fn unavailable(reason: impl Into<String>) -> Self {
        Self::Unavailable {
            reason: reason.into(),
            retry: Retry::Backoff,
        }
    }
}

/// What the open sequence on the signer thread needs.
struct OpenRequest {
    key_label: String,
    certificate_from_token: bool,
    allow_final_pin_try: bool,
    pin: Arc<dyn PinSource>,
    digest: Digest,
}

/// What the open sequence found.
#[derive(Debug)]
struct Opened {
    summary: TokenSummary,
    pin_count_low: bool,
    key: KeyRef,
    token_certificate: Option<Vec<u8>>,
    digest: Digest,
    signature: RawSignature,
}

type OpenResult = Result<Opened, Failure>;

struct Manager {
    config: ManagerConfig,
    signer: SignerHandle,
    lost: mpsc::UnboundedReceiver<TokenError>,
    state: watch::Sender<IdentityState>,
    resolver: Arc<Resolver>,
    poke: Arc<Notify>,
    cancel: CancellationToken,
    pin: Arc<dyn PinSource>,
    /// An open that timed out and is still running on the signer thread.
    pending: Option<oneshot::Receiver<OpenResult>>,
    last_fingerprint: Option<[u8; 32]>,
    backoff: Backoff,
}

/// The result of one open attempt.
enum Attempt {
    Ready,
    Failed(Failure),
    Exit(ManagerExit),
}

impl Manager {
    async fn run(mut self) -> ManagerExit {
        loop {
            let delay = match self.attempt().await {
                Attempt::Exit(exit) => return self.exit(exit),
                Attempt::Failed(Failure::Fatal(reason)) => {
                    return self.exit(ManagerExit::Fatal(reason));
                }
                Attempt::Failed(Failure::Unavailable { reason, retry }) => {
                    self.set_unavailable(&reason);
                    match retry {
                        Retry::Backoff => self.backoff.next_delay(),
                        Retry::Expired => self.config.recovery.expired_retry,
                    }
                }
                Attempt::Ready => {
                    self.backoff.reset();
                    let lost = tokio::select! {
                        () = self.cancel.cancelled() => return self.exit(ManagerExit::Cancelled),
                        lost = self.lost.recv() => lost,
                    };
                    let reason = lost.map_or_else(
                        || "the signer thread has stopped".to_owned(),
                        |error| error.to_string(),
                    );
                    self.resolver.set(None);
                    self.close_token();
                    self.set_unavailable(&reason);
                    self.backoff.next_delay()
                }
            };
            tokio::select! {
                () = self.cancel.cancelled() => return self.exit(ManagerExit::Cancelled),
                () = tokio::time::sleep(delay) => {}
                () = self.poke.notified() => {}
            }
        }
    }

    /// One pass of the open sequence and the certificate checks.
    async fn attempt(&mut self) -> Attempt {
        let mut receiver = match self.pending.take() {
            Some(receiver) => receiver,
            None => match self.submit_open() {
                Ok(receiver) => receiver,
                Err(attempt) => return attempt,
            },
        };
        let result = tokio::select! {
            () = self.cancel.cancelled() => return Attempt::Exit(ManagerExit::Cancelled),
            result = &mut receiver => result,
            () = tokio::time::sleep(self.config.recovery.open_timeout) => {
                // Keep waiting for this open next time rather than queueing another behind
                // it. It isn't closed: the open may still succeed.
                self.pending = Some(receiver);
                return Attempt::Failed(Failure::unavailable(format!(
                    "opening the token timed out after {} ms",
                    self.config.recovery.open_timeout.as_millis()
                )));
            }
        };
        let opened = match result {
            Err(_) => return Attempt::Exit(ManagerExit::SignerStopped),
            Ok(Err(failure)) => return Attempt::Failed(failure),
            Ok(Ok(opened)) => opened,
        };
        match self.check(opened) {
            Ok(identity) => {
                self.publish_ready(identity);
                Attempt::Ready
            }
            Err(failure) => {
                self.close_token();
                Attempt::Failed(failure)
            }
        }
    }

    fn submit_open(&self) -> Result<oneshot::Receiver<OpenResult>, Attempt> {
        let digest = cert::random_digest().map_err(|error| {
            Attempt::Failed(Failure::Fatal(FatalReason::Random(error.to_string())))
        })?;
        let request = OpenRequest {
            key_label: self.config.key_label.clone(),
            certificate_from_token: self.config.certificate == CertificateSource::Token,
            allow_final_pin_try: self.config.allow_final_pin_try,
            pin: self.pin.clone(),
            digest,
        };
        self.signer
            .submit(move |backend| open_token(backend, &request))
            .map_err(|_| Attempt::Exit(ManagerExit::SignerStopped))
    }

    /// The certificate checks in LLD 1, section 4.6.
    fn check(&mut self, opened: Opened) -> Result<Identity, Failure> {
        let chain = match (opened.token_certificate, &self.config.certificate) {
            (Some(der), _) => vec![CertificateDer::from(der)],
            (None, CertificateSource::Chain(chain)) => chain.clone(),
            (None, CertificateSource::Token) => Vec::new(),
        };
        let Some(leaf) = chain.first() else {
            return Err(Failure::Fatal(FatalReason::CertificateMissing {
                key_label: self.config.key_label.clone(),
            }));
        };
        let certificate = DeviceCertificate::from_der(leaf)
            .map_err(|error| Failure::Fatal(FatalReason::Certificate(error)))?;
        certificate
            .verify_possession(&opened.digest, &opened.signature)
            .map_err(|error| Failure::Fatal(FatalReason::Certificate(error)))?;

        let mut warnings = Vec::new();
        if opened.pin_count_low {
            warnings.push(Warning::PinCountLow);
        }
        match certificate.check_validity(SystemTime::now(), self.config.earliest_trusted) {
            Validity::Valid => {}
            Validity::ExpiresSoon { remaining } => {
                warnings.push(Warning::ExpiresSoon { remaining });
            }
            Validity::ClockUntrusted => warnings.push(Warning::ClockUntrusted),
            Validity::NotYetValid => {
                return Err(Failure::unavailable("certificate is not valid yet"));
            }
            Validity::Expired => {
                return Err(Failure::Unavailable {
                    reason: "certificate has expired".to_owned(),
                    retry: Retry::Expired,
                });
            }
        }
        if !certificate.subject_cn_matches(&self.config.thing_name) {
            warnings.push(Warning::SubjectMismatch {
                subject_cn: certificate.subject_cn().map(str::to_owned),
                thing_name: self.config.thing_name.clone(),
            });
        }
        let fingerprint = certificate.fingerprint();
        if let Some(previous) = self.last_fingerprint
            && previous != fingerprint
        {
            warnings.push(Warning::CertificateChanged {
                previous: hex(&previous),
            });
        }
        self.last_fingerprint = Some(fingerprint);

        Ok(Identity {
            certified_key: tls::certified_key(chain, self.signer.client(), opened.key),
            cert: CertInfo {
                subject_cn: certificate.subject_cn().map(str::to_owned),
                not_after: certificate.not_after(),
                fingerprint: certificate.fingerprint_hex(),
            },
            token: opened.summary,
            device: DeviceInfo {
                thing_name: self.config.thing_name.clone(),
            },
            warnings,
        })
    }

    fn publish_ready(&mut self, identity: Identity) {
        for warning in &identity.warnings {
            tracing::warn!(%warning, "identity warning");
        }
        tracing::info!(
            token = %identity.token.label,
            serial = %identity.token.serial,
            fingerprint = %identity.cert.fingerprint,
            thing_name = %identity.device.thing_name,
            "identity ready"
        );
        // Lost-token reports from before this open are stale.
        while self.lost.try_recv().is_ok() {}
        self.resolver.set(Some(identity.certified_key.clone()));
        self.state
            .send_replace(IdentityState::Ready(Arc::new(identity)));
    }

    fn set_unavailable(&self, reason: &str) {
        tracing::warn!(reason, "identity unavailable; retrying");
        self.state.send_if_modified(|state| match state {
            IdentityState::Unavailable {
                reason: current, ..
            } if current == reason => false,
            IdentityState::Unavailable {
                reason: current, ..
            } => {
                reason.clone_into(current);
                true
            }
            _ => {
                *state = IdentityState::Unavailable {
                    reason: reason.to_owned(),
                    since: Instant::now(),
                };
                true
            }
        });
    }

    /// Closes the token so the next open starts from scratch. Doesn't wait: the signer thread
    /// may be stuck on a hung token, and the close runs once it's free.
    fn close_token(&self) {
        let _ = self.signer.submit(|backend| backend.close());
    }

    fn exit(self, exit: ManagerExit) -> ManagerExit {
        self.resolver.set(None);
        match &exit {
            ManagerExit::Fatal(reason) => {
                tracing::error!(%reason, "identity failed; stopping");
                self.state.send_replace(IdentityState::Fatal {
                    reason: reason.clone(),
                });
            }
            ManagerExit::SignerStopped => {
                tracing::error!("the signer thread has stopped");
                self.set_unavailable("the signer thread has stopped");
            }
            ManagerExit::Cancelled => {}
        }
        // Dropping the signer handle closes the token and stops the thread.
        exit
    }
}

/// The open sequence (LLD 1, section 4.2), run on the signer thread. Closes the token again
/// if any step fails.
fn open_token(backend: &mut dyn TokenBackend, request: &OpenRequest) -> OpenResult {
    let result = open_steps(backend, request);
    if result.is_err() {
        backend.close();
    }
    result
}

fn open_steps(backend: &mut dyn TokenBackend, request: &OpenRequest) -> OpenResult {
    let summary = backend.open().map_err(token_failure)?;
    let status = backend.pin_status().map_err(token_failure)?;
    if status.locked {
        return Err(Failure::Fatal(FatalReason::PinLocked));
    }
    if status.final_try && !request.allow_final_pin_try {
        return Err(Failure::Fatal(FatalReason::PinFinalTry));
    }
    let pin = request
        .pin
        .read()
        .map_err(|error| Failure::Fatal(FatalReason::PinSource(error)))?;
    backend.login(&pin).map_err(token_failure)?;
    drop(pin);
    let key = backend
        .find_key(&request.key_label)
        .map_err(token_failure)?;
    let token_certificate = if request.certificate_from_token {
        let certificate = backend.read_certificate(&key).map_err(token_failure)?;
        Some(certificate.ok_or_else(|| {
            Failure::Fatal(FatalReason::CertificateMissing {
                key_label: request.key_label.clone(),
            })
        })?)
    } else {
        None
    };
    let signature = backend
        .sign_digest(&key, &request.digest)
        .map_err(token_failure)?;
    Ok(Opened {
        summary,
        pin_count_low: status.count_low,
        key,
        token_certificate,
        digest: request.digest,
        signature,
    })
}

/// Fatal or retried, following LLD 1, section 4.7.
fn token_failure(error: TokenError) -> Failure {
    match error {
        TokenError::PinIncorrect => Failure::Fatal(FatalReason::PinIncorrect),
        TokenError::PinLocked => Failure::Fatal(FatalReason::PinLocked),
        TokenError::PinInvalid => Failure::Fatal(FatalReason::PinInvalid),
        error if error.is_fatal() => Failure::Fatal(FatalReason::Token(error)),
        error => Failure::unavailable(error.to_string()),
    }
}

/// Exponential backoff with jitter: each delay is between half and all of the current step,
/// and the step doubles up to the maximum.
#[derive(Debug)]
struct Backoff {
    initial: Duration,
    max: Duration,
    step: Duration,
}

impl Backoff {
    fn new(initial: Duration, max: Duration) -> Self {
        Self {
            initial,
            max,
            step: initial,
        }
    }

    fn next_delay(&mut self) -> Duration {
        let step = self.step;
        self.step = (self.step * 2).min(self.max);
        jitter(step, random_fraction())
    }

    fn reset(&mut self) {
        self.step = self.initial;
    }
}

/// Between half and all of `step`, by `fraction` (0 to 1).
fn jitter(step: Duration, fraction: f64) -> Duration {
    step.mul_f64(0.5 + 0.5 * fraction.clamp(0.0, 1.0))
}

fn random_fraction() -> f64 {
    let mut bytes = [0u8; 4];
    // Without randomness the delay is just the full step.
    match getrandom::fill(&mut bytes) {
        Ok(()) => f64::from(u32::from_le_bytes(bytes)) / f64::from(u32::MAX),
        Err(_) => 1.0,
    }
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

#[cfg(test)]
mod tests;
