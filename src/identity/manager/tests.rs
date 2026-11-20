//! Identity manager tests with the mock token (LLD 1, section 9).

use std::time::{Duration, SystemTime};

use p256::ecdsa::SigningKey;
use rustls::SignatureScheme;
use secrecy::SecretString;

use super::*;
use crate::identity::mock::{MockKey, MockToken, Op};
use crate::identity::pin::FixedPin;
use crate::identity::testing::{self, Ca, THING_NAME, ca, days, server};
use crate::identity::tls::root_store_from_pem;
use crate::identity::token::PinStatus;

pub(super) const PIN: &str = "1234";
const WAIT: Duration = Duration::from_secs(10);

/// Retries quickly, so tests don't wait.
pub(super) fn fast() -> Recovery {
    Recovery {
        initial_backoff: Duration::from_millis(10),
        max_backoff: Duration::from_millis(50),
        expired_retry: Duration::from_millis(50),
        open_timeout: Duration::from_secs(5),
    }
}

/// Never retries on its own, so only `poke()` triggers a retry.
pub(super) fn poke_only() -> Recovery {
    Recovery {
        initial_backoff: Duration::from_secs(3600),
        max_backoff: Duration::from_secs(3600),
        ..fast()
    }
}

pub(super) fn config(recovery: Recovery) -> ManagerConfig {
    let mut config = ManagerConfig::new(THING_NAME, "device-key");
    config.recovery = recovery;
    config
}

pub(super) fn signing_key(seed: u8) -> SigningKey {
    SigningKey::from_slice(&[seed; 32]).unwrap()
}

pub(super) fn device_key(key: &SigningKey, certificate: Option<CertificateDer<'_>>) -> MockKey {
    MockKey {
        label: "device-key".into(),
        id: vec![1],
        signing_key: key.clone(),
        private: true,
        certificate: certificate.map(|der| der.to_vec()),
    }
}

/// A mock token with a device key and a certificate for it from a test CA.
pub(super) struct Device {
    pub(super) ca: Ca,
    pub(super) token: MockToken,
    pub(super) key: SigningKey,
}

pub(super) fn device() -> Device {
    let ca = ca("Helios test device CA");
    let key = signing_key(7);
    let token = MockToken::new(PIN);
    token.add_key(device_key(
        &key,
        Some(testing::device_certificate(&ca, &key, THING_NAME)),
    ));
    Device { ca, token, key }
}

pub(super) struct Running {
    pub(super) handle: IdentityHandle,
    pub(super) task: JoinHandle<ManagerExit>,
    pub(super) cancel: CancellationToken,
}

fn start(token: &MockToken, config: ManagerConfig) -> Running {
    start_with(token, config, pin(PIN), any_roots())
}

pub(super) fn start_with(
    token: &MockToken,
    config: ManagerConfig,
    pin: Arc<dyn PinSource>,
    roots: RootCertStore,
) -> Running {
    let cancel = CancellationToken::new();
    let (handle, task) = IdentityManager::start(
        config,
        Box::new(token.clone()),
        PinSetting::Local(pin),
        roots,
        cancel.clone(),
    )
    .unwrap();
    Running {
        handle,
        task,
        cancel,
    }
}

pub(super) fn pin(value: &str) -> Arc<dyn PinSource> {
    Arc::new(FixedPin::new(SecretString::new(value.into())))
}

pub(super) fn any_roots() -> RootCertStore {
    root_store_from_pem(ca("Helios test roots").pem.as_bytes()).unwrap()
}

pub(super) async fn wait_for(
    handle: &IdentityHandle,
    what: impl Fn(&IdentityState) -> bool,
) -> IdentityState {
    let mut state = handle.watch();
    let result = tokio::time::timeout(WAIT, state.wait_for(|current| what(current))).await;
    match result {
        Ok(Ok(state)) => state.clone(),
        _ => panic!("state never matched; last state: {:?}", handle.state()),
    }
}

pub(super) async fn ready(handle: &IdentityHandle) -> Arc<Identity> {
    let state = wait_for(handle, |state| {
        matches!(state, IdentityState::Ready(_) | IdentityState::Fatal { .. })
    })
    .await;
    match state {
        IdentityState::Ready(identity) => identity,
        other => panic!("expected ready, got {other:?}"),
    }
}

pub(super) async fn unavailable(handle: &IdentityHandle) -> (String, Instant) {
    match wait_for(handle, |state| {
        matches!(state, IdentityState::Unavailable { .. })
    })
    .await
    {
        IdentityState::Unavailable { reason, since } => (reason, since),
        _ => unreachable!(),
    }
}

pub(super) async fn fatal(running: Running) -> FatalReason {
    let exit = tokio::time::timeout(WAIT, running.task)
        .await
        .expect("the manager should stop")
        .unwrap();
    let ManagerExit::Fatal(reason) = exit else {
        panic!("expected a fatal exit, got {exit:?}");
    };
    match running.handle.state() {
        IdentityState::Fatal { reason: published } => assert_eq!(published, reason),
        other => panic!("expected the fatal state to be published, got {other:?}"),
    }
    assert!(running.handle.resolver.current().is_none());
    reason
}

/// Waits until `check` holds, polling.
pub(super) async fn eventually(what: &str, check: impl Fn() -> bool) {
    let deadline = Instant::now() + WAIT;
    while !check() {
        assert!(Instant::now() < deadline, "timed out waiting until {what}");
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
}

pub(super) fn count(token: &MockToken, op: Op) -> usize {
    token.calls().iter().filter(|call| **call == op).count()
}

/// Signs through the identity's key the way rustls does, on a blocking thread.
pub(super) async fn sign_with(identity: &Identity) -> Result<Vec<u8>, rustls::Error> {
    let signer = identity
        .certified_key
        .key
        .choose_scheme(&[SignatureScheme::ECDSA_NISTP256_SHA256])
        .unwrap();
    tokio::task::spawn_blocking(move || signer.sign(b"handshake transcript"))
        .await
        .unwrap()
}

#[tokio::test]
async fn opens_the_token_and_publishes_the_identity() {
    let device = device();
    let running = start(&device.token, config(fast()));

    let identity = ready(&running.handle).await;

    assert_eq!(identity.cert.subject_cn.as_deref(), Some(THING_NAME));
    assert_eq!(identity.cert.fingerprint.len(), 64);
    assert_eq!(identity.token.label, "helios");
    assert_eq!(identity.device.thing_name, THING_NAME);
    assert!(identity.warnings.is_empty(), "{:?}", identity.warnings);
    assert_eq!(
        device.token.calls(),
        [
            Op::Open,
            Op::PinStatus,
            Op::Login,
            Op::FindKey,
            Op::ReadCertificate,
            // Proof of possession.
            Op::SignDigest,
        ]
    );
    assert!(Arc::ptr_eq(
        &running.handle.resolver.current().unwrap(),
        &identity.certified_key
    ));
    assert_eq!(running.handle.state().name(), "ready");
    assert!(running.handle.state().identity().is_some());
    assert!(sign_with(&identity).await.is_ok());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn recovers_after_the_token_is_lost_during_a_handshake() {
    let device = device();
    let (port, server_ca) = server(&device.ca).await;
    let roots = root_store_from_pem(server_ca.pem.as_bytes()).unwrap();
    let running = start_with(&device.token, config(poke_only()), pin(PIN), roots);
    ready(&running.handle).await;
    let tls = running.handle.tls_config(Alpn::None).unwrap();
    assert_eq!(
        testing::connect(port, tls.clone()).await.unwrap(),
        format!("hello {THING_NAME}")
    );

    device
        .token
        .fail_next(Op::SignDigest, TokenError::TokenLost("unplugged".into()));
    assert!(testing::connect(port, tls.clone()).await.is_err());

    let (reason, _) = unavailable(&running.handle).await;
    assert_eq!(reason, "token lost: unplugged");
    assert_eq!(running.handle.state().name(), "unavailable");
    assert!(running.handle.state().identity().is_none());
    assert!(running.handle.resolver.current().is_none());
    eventually("the token is closed", || !device.token.is_open()).await;

    running.handle.poke();
    ready(&running.handle).await;
    assert_eq!(
        testing::connect(port, tls.clone()).await.unwrap(),
        format!("hello {THING_NAME}")
    );
    assert_eq!(count(&device.token, Op::Open), 2);
}

#[tokio::test]
async fn recovers_after_a_hung_token_times_out() {
    let device = device();
    let mut config = config(poke_only());
    config.sign_timeout = Duration::from_millis(100);
    let running = start(&device.token, config);
    let identity = ready(&running.handle).await;

    device.token.set_sign_delay(Duration::from_millis(500));
    assert!(sign_with(&identity).await.is_err());

    let (reason, _) = unavailable(&running.handle).await;
    assert_eq!(reason, "token lost: signing timed out after 100 ms");
    device.token.set_sign_delay(Duration::ZERO);
    running.handle.poke();
    let identity = ready(&running.handle).await;
    assert!(sign_with(&identity).await.is_ok());
}

#[tokio::test]
async fn keeps_retrying_while_the_token_is_missing() {
    let device = device();
    for _ in 0..3 {
        device.token.fail_next(
            Op::Open,
            TokenError::NotPresent {
                label: "helios".into(),
            },
        );
    }

    let running = start(&device.token, config(fast()));

    ready(&running.handle).await;
    assert_eq!(count(&device.token, Op::Open), 4);
    // Failed opens never got as far as logging in.
    assert_eq!(count(&device.token, Op::Login), 1);
}

#[tokio::test]
async fn updates_the_reason_but_keeps_the_time_while_unavailable() {
    let device = device();
    let missing = TokenError::NotPresent {
        label: "helios".into(),
    };
    device.token.fail_next(Op::Open, missing.clone());
    device.token.fail_next(Op::Open, missing.clone());
    device
        .token
        .fail_next(Op::Open, TokenError::Other("CKR_FUNCTION_FAILED".into()));
    let running = start(&device.token, config(poke_only()));

    let (reason, since) = unavailable(&running.handle).await;
    assert_eq!(reason, missing.to_string());

    running.handle.poke();
    eventually("the token is opened again", || {
        count(&device.token, Op::Open) == 2
    })
    .await;
    running.handle.poke();
    let (reason, same_since) = wait_for(&running.handle, |state| {
        matches!(state, IdentityState::Unavailable { reason, .. } if reason.contains("FUNCTION"))
    })
    .await
    .unavailable_parts();
    assert_eq!(reason, "PKCS#11 error: CKR_FUNCTION_FAILED");
    assert_eq!(same_since, since);

    running.handle.poke();
    ready(&running.handle).await;
}

impl IdentityState {
    fn unavailable_parts(self) -> (String, Instant) {
        match self {
            Self::Unavailable { reason, since } => (reason, since),
            other => panic!("expected unavailable, got {other:?}"),
        }
    }
}

#[tokio::test]
async fn keeps_waiting_for_a_slow_open_instead_of_queueing_another() {
    let device = device();
    // The proof-of-possession signature during the open is slow.
    device.token.set_sign_delay(Duration::from_millis(400));
    let mut config = config(fast());
    config.recovery.open_timeout = Duration::from_millis(100);
    let running = start(&device.token, config);

    let (reason, _) = unavailable(&running.handle).await;
    assert_eq!(reason, "opening the token timed out after 100 ms");

    ready(&running.handle).await;
    assert_eq!(count(&device.token, Op::Open), 1);
}

#[tokio::test]
async fn publishes_a_different_certificate_after_recovery() {
    let device = device();
    let running = start(&device.token, config(poke_only()));
    let first = ready(&running.handle).await;

    // A different token is plugged in.
    let other_key = signing_key(8);
    device.token.replace_keys(vec![device_key(
        &other_key,
        Some(testing::device_certificate(
            &device.ca, &other_key, THING_NAME,
        )),
    )]);
    device
        .token
        .fail_next(Op::SignDigest, TokenError::TokenLost("unplugged".into()));
    assert!(sign_with(&first).await.is_err());
    unavailable(&running.handle).await;
    running.handle.poke();

    let second = ready(&running.handle).await;
    assert_ne!(second.cert.fingerprint, first.cert.fingerprint);
    assert_eq!(
        second.warnings,
        [Warning::CertificateChanged {
            previous: first.cert.fingerprint.clone()
        }]
    );
    assert!(sign_with(&second).await.is_ok());
}

#[tokio::test]
async fn an_expired_certificate_is_retried_until_it_is_replaced() {
    let device = device();
    let now = SystemTime::now();
    let expired = testing::device_certificate_valid(
        &device.ca,
        &device.key,
        THING_NAME,
        now - days(10),
        now - days(1),
    );
    device
        .token
        .replace_keys(vec![device_key(&device.key, Some(expired))]);
    let running = start(&device.token, config(fast()));

    let (reason, _) = unavailable(&running.handle).await;
    assert_eq!(reason, "certificate has expired");
    eventually("the token is closed", || !device.token.is_open()).await;

    device.token.replace_keys(vec![device_key(
        &device.key,
        Some(testing::device_certificate(
            &device.ca,
            &device.key,
            THING_NAME,
        )),
    )]);
    ready(&running.handle).await;
}

#[tokio::test]
async fn a_certificate_that_is_not_valid_yet_is_unavailable() {
    let device = device();
    let now = SystemTime::now();
    let future = testing::device_certificate_valid(
        &device.ca,
        &device.key,
        THING_NAME,
        now + days(1),
        now + days(10),
    );
    device
        .token
        .replace_keys(vec![device_key(&device.key, Some(future))]);
    let running = start(&device.token, config(poke_only()));

    let (reason, _) = unavailable(&running.handle).await;

    assert_eq!(reason, "certificate is not valid yet");
}

#[tokio::test]
async fn warns_about_certificates_that_expire_soon_or_name_another_thing() {
    let device = device();
    let now = SystemTime::now();
    let soon = testing::device_certificate_valid(
        &device.ca,
        &device.key,
        "t-SOMETHINGELSE",
        now - days(1),
        now + days(10),
    );
    device
        .token
        .replace_keys(vec![device_key(&device.key, Some(soon))]);
    device.token.set_pin_status(PinStatus {
        count_low: true,
        ..PinStatus::default()
    });
    let running = start(&device.token, config(fast()));

    let identity = ready(&running.handle).await;

    let [
        Warning::PinCountLow,
        Warning::ExpiresSoon { remaining },
        Warning::SubjectMismatch { .. },
    ] = identity.warnings.as_slice()
    else {
        panic!("unexpected warnings: {:?}", identity.warnings);
    };
    assert!(*remaining > days(9) && *remaining <= days(10));
    assert_eq!(
        identity.warnings[1].to_string(),
        "certificate expires in 9 days"
    );
    assert_eq!(
        identity.warnings[2],
        Warning::SubjectMismatch {
            subject_cn: Some("t-SOMETHINGELSE".into()),
            thing_name: THING_NAME.into(),
        }
    );
    assert_eq!(
        identity.warnings[0].to_string(),
        "a wrong PIN was entered since the last successful login"
    );
}

#[tokio::test]
async fn only_warns_about_dates_while_the_clock_is_unset() {
    let device = device();
    let now = SystemTime::now();
    let expired = testing::device_certificate_valid(
        &device.ca,
        &device.key,
        THING_NAME,
        now - days(10),
        now - days(1),
    );
    device
        .token
        .replace_keys(vec![device_key(&device.key, Some(expired))]);
    let mut config = config(fast());
    // The clock reads earlier than the build, so it hasn't been set yet.
    config.earliest_trusted = now + days(1);
    let running = start(&device.token, config);

    let identity = ready(&running.handle).await;

    assert_eq!(identity.warnings, [Warning::ClockUntrusted]);
    assert!(
        Warning::ClockUntrusted
            .to_string()
            .contains("certificate dates were not checked")
    );
}

#[tokio::test]
async fn a_locked_pin_stops_without_logging_in() {
    let device = device();
    device.token.set_pin_status(PinStatus {
        locked: true,
        ..PinStatus::default()
    });
    let running = start(&device.token, config(fast()));

    assert_eq!(fatal(running).await, FatalReason::PinLocked);
    assert_eq!(count(&device.token, Op::Login), 0);
    assert!(!device.token.is_open());
}

#[tokio::test]
async fn the_final_pin_try_is_not_used_unless_allowed() {
    let device = device();
    let final_try = PinStatus {
        final_try: true,
        ..PinStatus::default()
    };
    device.token.set_pin_status(final_try);

    let running = start(&device.token, config(fast()));
    let reason = fatal(running).await;
    assert_eq!(reason, FatalReason::PinFinalTry);
    assert!(reason.to_string().contains("allow_final_pin_try"));
    assert_eq!(count(&device.token, Op::Login), 0);

    let mut allowed = config(fast());
    allowed.allow_final_pin_try = true;
    let running = start(&device.token, allowed);
    ready(&running.handle).await;
    assert_eq!(count(&device.token, Op::Login), 1);
}

#[tokio::test]
async fn a_wrong_pin_is_tried_once() {
    let device = device();
    let running = start_with(&device.token, config(fast()), pin("0000"), any_roots());

    assert_eq!(fatal(running).await, FatalReason::PinIncorrect);
    assert_eq!(count(&device.token, Op::Login), 1);
}

#[tokio::test]
async fn pin_errors_from_the_token_are_fatal() {
    for (error, expected) in [
        (TokenError::PinInvalid, FatalReason::PinInvalid),
        (TokenError::PinLocked, FatalReason::PinLocked),
    ] {
        let device = device();
        device.token.fail_next(Op::Login, error);
        let running = start(&device.token, config(fast()));

        assert_eq!(fatal(running).await, expected);
    }
}

struct MissingPin;

impl PinSource for MissingPin {
    fn read(&self) -> Result<SecretString, PinError> {
        Err(PinError::new("credential helios-pin is missing"))
    }
}

#[tokio::test]
async fn an_unreadable_pin_is_fatal() {
    let device = device();
    let running = start_with(
        &device.token,
        config(fast()),
        Arc::new(MissingPin),
        any_roots(),
    );

    let reason = fatal(running).await;

    assert_eq!(
        reason,
        FatalReason::PinSource(PinError::new("credential helios-pin is missing"))
    );
    assert_eq!(count(&device.token, Op::Login), 0);
}

#[tokio::test]
async fn token_errors_retrying_cannot_fix_are_fatal() {
    let device = device();
    device
        .token
        .fail_next(Op::Open, TokenError::ModuleLoad("no such file".into()));
    let running = start(&device.token, config(fast()));
    assert_eq!(
        fatal(running).await,
        FatalReason::Token(TokenError::ModuleLoad("no such file".into()))
    );

    let mut other_key = config(fast());
    other_key.key_label = Some("missing-key".into());
    let running = start(&device.token, other_key);
    let reason = fatal(running).await;
    assert_eq!(
        reason,
        FatalReason::Token(TokenError::KeyNotFound {
            label: "missing-key".into()
        })
    );
    assert_eq!(
        reason.to_string(),
        "no private EC key with label \"missing-key\""
    );
}

#[tokio::test]
async fn a_key_without_a_certificate_is_fatal() {
    let device = device();
    device
        .token
        .replace_keys(vec![device_key(&device.key, None)]);
    let running = start(&device.token, config(fast()));

    let reason = fatal(running).await;

    assert_eq!(
        reason,
        FatalReason::CertificateMissing {
            key_label: "device-key".into()
        }
    );
    assert_eq!(
        reason.to_string(),
        "no certificate on the token for key \"device-key\""
    );
}

#[tokio::test]
async fn a_certificate_for_another_key_is_fatal() {
    let device = device();
    let wrong = testing::device_certificate(&device.ca, &signing_key(9), THING_NAME);
    device
        .token
        .replace_keys(vec![device_key(&device.key, Some(wrong))]);
    let running = start(&device.token, config(fast()));

    assert_eq!(
        fatal(running).await,
        FatalReason::Certificate(CertError::KeyMismatch)
    );
}

#[tokio::test]
async fn a_certificate_that_does_not_parse_is_fatal() {
    let device = device();
    let mut token_key = device_key(&device.key, None);
    token_key.certificate = Some(vec![0x30, 0x03, 0x02, 0x01, 0x01]);
    device.token.replace_keys(vec![token_key]);
    let running = start(&device.token, config(fast()));

    let reason = fatal(running).await;

    assert!(
        matches!(reason, FatalReason::Certificate(CertError::Parse(_))),
        "{reason:?}"
    );
}

#[tokio::test]
async fn uses_a_certificate_chain_from_the_config() {
    let device = device();
    let certificate = testing::device_certificate(&device.ca, &device.key, THING_NAME);
    device
        .token
        .replace_keys(vec![device_key(&device.key, None)]);
    let mut chain = config(fast());
    chain.certificate = CertificateSource::Chain(vec![certificate.clone()]);
    let running = start(&device.token, chain);

    let identity = ready(&running.handle).await;

    assert_eq!(identity.certified_key.cert, [certificate]);
    assert_eq!(count(&device.token, Op::ReadCertificate), 0);

    let mut empty = config(fast());
    empty.certificate = CertificateSource::Chain(Vec::new());
    let running = start(&device.token, empty);
    assert!(matches!(
        fatal(running).await,
        FatalReason::CertificateMissing { .. }
    ));
}

#[tokio::test]
async fn stops_and_closes_the_token_when_cancelled() {
    let device = device();
    let running = start(&device.token, config(fast()));
    ready(&running.handle).await;

    running.cancel.cancel();

    assert_eq!(running.task.await.unwrap(), ManagerExit::Cancelled);
    assert!(running.handle.resolver.current().is_none());
    eventually("the token is closed", || !device.token.is_open()).await;
}

#[tokio::test]
async fn can_be_cancelled_while_waiting_to_retry_or_opening() {
    let device = device();
    device.token.fail_next(
        Op::Open,
        TokenError::NotPresent {
            label: "helios".into(),
        },
    );
    let running = start(&device.token, config(poke_only()));
    unavailable(&running.handle).await;
    running.cancel.cancel();
    assert_eq!(running.task.await.unwrap(), ManagerExit::Cancelled);

    let device = self::device();
    device.token.set_sign_delay(Duration::from_millis(500));
    let running = start(&device.token, config(fast()));
    eventually("the open has started", || {
        count(&device.token, Op::Open) == 1
    })
    .await;
    running.cancel.cancel();
    assert_eq!(running.task.await.unwrap(), ManagerExit::Cancelled);
}

#[tokio::test]
async fn a_crashed_signer_thread_ends_the_manager() {
    let device = device();
    device.token.panic_next(Op::Open);
    let running = start(&device.token, config(fast()));

    let exit = tokio::time::timeout(WAIT, running.task)
        .await
        .unwrap()
        .unwrap();

    assert_eq!(exit, ManagerExit::SignerStopped);
    let (reason, _) = unavailable(&running.handle).await;
    assert_eq!(reason, "the signer thread has stopped");
}

#[test]
fn defaults_follow_the_lld() {
    let config = ManagerConfig::new(THING_NAME, "device-key");

    assert_eq!(config.certificate, CertificateSource::Token);
    assert!(!config.allow_final_pin_try);
    assert_eq!(config.sign_timeout, Duration::from_secs(5));
    assert_eq!(config.earliest_trusted, build_info::build_time());
    assert_eq!(config.recovery.initial_backoff, Duration::from_secs(1));
    assert_eq!(config.recovery.max_backoff, Duration::from_secs(30));
    assert_eq!(config.recovery.expired_retry, Duration::from_secs(3600));
    assert_eq!(IdentityState::Starting.name(), "starting");
    assert_eq!(
        IdentityState::Fatal {
            reason: FatalReason::PinLocked
        }
        .name(),
        "fatal"
    );
    assert_eq!(
        FatalReason::Random("no entropy".into()).to_string(),
        "random number generator failed: no entropy"
    );
    assert_eq!(hex(&[0x00, 0xff]), "00ff");
}
