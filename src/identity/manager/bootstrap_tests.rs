//! Identity manager tests with bootstrap: the mock token and the local HTTPS mock of the
//! bootstrap service (LLD 1, section 9).

use std::time::Duration;

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as BASE64;
use p256::ecdsa::signature::hazmat::PrehashVerifier;
use p256::ecdsa::{Signature, VerifyingKey};

use super::tests::{
    Device, Running, any_roots, count, device_key, eventually, fatal, ready, signing_key,
    unavailable, wait_for,
};
use super::*;
use crate::identity::bootstrap::adapters::{Adapter, AdapterKind};
use crate::identity::bootstrap::api::tests::{json, protocol_test_body};
use crate::identity::bootstrap::challenge;
use crate::identity::mock::{MockKey, MockToken, Op};
use crate::identity::testing::{
    self, MockResponse, MockService, NoPermanentAddresses, THING_NAME, ca, fake_sysfs,
};

/// The PIN in the contract's identity response.
const SERVICE_PIN: &str = "123456";

/// A token whose PIN is the one the service returns, with a certificate for the thing.
fn device() -> Device {
    let ca = ca("Helios test device CA");
    let key = signing_key(7);
    let token = MockToken::new(SERVICE_PIN);
    token.add_key(device_key(
        &key,
        Some(testing::device_certificate(&ca, &key, THING_NAME)),
    ));
    Device { ca, token, key }
}

fn add_challenge_key(token: &MockToken) -> VerifyingKey {
    let key = signing_key(11);
    token.add_key(MockKey {
        label: "challenge-key".into(),
        id: vec![2],
        signing_key: key.clone(),
        private: false,
        certificate: None,
    });
    *key.verifying_key()
}

fn timing() -> BootstrapTiming {
    BootstrapTiming {
        initial_backoff: Duration::from_millis(10),
        max_backoff: Duration::from_millis(50),
        slow_retry: Duration::from_millis(50),
        rejections_before_slow: 2,
    }
}

struct Bootstrapped {
    running: Running,
    service: MockService,
    _sysfs: tempfile::TempDir,
}

fn identity_response() -> MockResponse {
    MockResponse::json(200, &protocol_test_body("BootstrapReturnsIdentity"))
}

fn bare_identity_response() -> MockResponse {
    let body = json(&protocol_test_body("BootstrapReturnsIdentity"))["identity"].to_string();
    MockResponse::json(200, &body)
}

fn challenge_response() -> MockResponse {
    MockResponse::json(200, &protocol_test_body("BootstrapReturnsChallenge"))
}

/// Starts the manager with bootstrap against a fresh mock service. `customize` adjusts the
/// config and setup; `respond` queues the service's answers before the manager starts.
async fn start(
    token: &MockToken,
    customize: impl FnOnce(&mut ManagerConfig, &mut BootstrapSetup),
    respond: impl FnOnce(&MockService),
) -> Bootstrapped {
    let service = MockService::start().await;
    respond(&service);
    let sysfs = fake_sysfs(&[
        ("wlan0", "2c:cf:67:00:00:02"),
        ("eth0", "2c:cf:67:00:00:01"),
    ]);
    let mut config = ManagerConfig::for_bootstrap();
    config.recovery = super::tests::fast();
    let mut setup = BootstrapSetup {
        client: BootstrapClient::new(&service.url(), service.roots(), Duration::from_secs(5))
            .unwrap(),
        interfaces: Interfaces::Auto,
        sysfs: sysfs.path().to_owned(),
        permanent_addresses: Arc::new(NoPermanentAddresses),
        hardware_model: Some("Raspberry Pi 5 Model B Rev 1.0".into()),
        challenge_key_label: None,
        aws: None,
        timing: timing(),
    };
    customize(&mut config, &mut setup);
    let cancel = CancellationToken::new();
    let (handle, task) = IdentityManager::start(
        config,
        Box::new(token.clone()),
        PinSetting::Bootstrap(Box::new(setup)),
        any_roots(),
        cancel.clone(),
    )
    .unwrap();
    Bootstrapped {
        running: Running {
            handle,
            task,
            cancel,
        },
        service,
        _sysfs: sysfs,
    }
}

fn paths(service: &MockService) -> Vec<String> {
    service.requests().into_iter().map(|r| r.path).collect()
}

async fn bootstrapping_error(handle: &IdentityHandle, containing: &str) -> u32 {
    let state = wait_for(handle, |state| {
        matches!(state, IdentityState::Bootstrapping { last_error: Some(error), .. } if error.contains(containing))
    })
    .await;
    match state {
        IdentityState::Bootstrapping { attempts, .. } => attempts,
        _ => unreachable!(),
    }
}

#[tokio::test]
async fn bootstraps_then_logs_in_with_the_service_pin() {
    let device = device();
    let b = start(&device.token, |_, _| {}, |s| s.respond(identity_response())).await;

    let identity = ready(&b.running.handle).await;

    assert_eq!(identity.device.thing_name, THING_NAME);
    assert_eq!(
        identity.device.device_id.as_deref(),
        Some("d-01JD5VZ6R1H8P3S0W2Y4A6C8E0")
    );
    assert_eq!(identity.device.aws.as_ref().unwrap().region, "us-west-2");
    assert_eq!(count(&device.token, Op::Login), 1);
    let [request] = b.service.requests().try_into().unwrap();
    assert_eq!(
        request.json(),
        serde_json::json!({
            "adapters": [
                {"interfaceName": "eth0", "kind": "ethernet", "mac": "2c:cf:67:00:00:01"},
                {"interfaceName": "wlan0", "kind": "ethernet", "mac": "2c:cf:67:00:00:02"}
            ],
            "heliosVersion": env!("CARGO_PKG_VERSION"),
            "hardwareModel": "Raspberry Pi 5 Model B Rev 1.0"
        })
    );
}

#[tokio::test]
async fn keeps_the_pin_for_recovery_without_asking_again() {
    let device = device();
    let b = start(&device.token, |_, _| {}, |s| s.respond(identity_response())).await;
    let identity = ready(&b.running.handle).await;

    device
        .token
        .fail_next(Op::SignDigest, TokenError::TokenLost("unplugged".into()));
    assert!(super::tests::sign_with(&identity).await.is_err());
    unavailable(&b.running.handle).await;
    ready(&b.running.handle).await;

    assert_eq!(count(&device.token, Op::Login), 2);
    assert_eq!(b.service.requests().len(), 1, "bootstrap isn't repeated");
}

#[tokio::test]
async fn retries_until_the_device_is_registered() {
    let device = device();
    let b = start(
        &device.token,
        |_, setup| setup.timing.slow_retry = Duration::from_secs(3600),
        |s| {
            s.respond(MockResponse::error(404, "UnknownDevice"));
            s.respond(MockResponse::error(429, "RateLimited").header("retry-after", "0"));
            s.respond(MockResponse::error(500, "InternalError"));
            s.respond(identity_response());
        },
    )
    .await;

    // An unknown device retries every 5 minutes (here: an hour), or when poked.
    let attempts = bootstrapping_error(&b.running.handle, "UnknownDevice").await;
    assert_eq!(attempts, 1);
    assert_eq!(b.running.handle.state().name(), "bootstrapping");
    b.running.handle.poke();

    ready(&b.running.handle).await;
    assert_eq!(b.service.requests().len(), 4);
}

#[tokio::test]
async fn answers_a_challenge_with_the_challenge_key() {
    let device = device();
    let challenge_key = add_challenge_key(&device.token);
    let b = start(
        &device.token,
        |config, setup| {
            config.token_label = Some("helios".into());
            setup.challenge_key_label = Some("challenge-key".into());
        },
        |s| {
            s.respond(challenge_response());
            s.respond(bare_identity_response());
        },
    )
    .await;

    ready(&b.running.handle).await;

    let requests = b.service.requests();
    assert_eq!(
        paths(&b.service),
        ["/v1/device/bootstrap", "/v1/device/bootstrap/challenge"]
    );
    assert_eq!(
        requests[0].json()["capabilities"],
        serde_json::json!(["token-challenge"])
    );
    let answer = requests[1].json();
    let challenge = json(&protocol_test_body("BootstrapReturnsChallenge"))["challenge"].clone();
    assert_eq!(answer["challengeId"], challenge["challengeId"]);
    assert_eq!(answer["adapters"], requests[0].json()["adapters"]);
    let adapters = [
        ("eth0", "2c:cf:67:00:00:01"),
        ("wlan0", "2c:cf:67:00:00:02"),
    ]
    .map(|(name, mac)| Adapter {
        interface_name: name.into(),
        kind: AdapterKind::Ethernet,
        mac: mac.parse().unwrap(),
    });
    let digest = challenge::digest(&challenge::message(
        challenge["challengeId"].as_str().unwrap(),
        challenge["nonce"].as_str().unwrap(),
        &adapters,
    ));
    let signature = BASE64
        .decode(answer["signature"].as_str().unwrap())
        .unwrap();
    let signature = Signature::from_der(&signature).unwrap();
    assert!(challenge_key.verify_prehash(&digest, &signature).is_ok());
    // One login, for the real open: the challenge was signed without one.
    assert_eq!(count(&device.token, Op::Login), 1);
}

#[tokio::test]
async fn does_not_offer_challenges_without_the_challenge_key() {
    let device = device();
    let b = start(
        &device.token,
        |config, setup| {
            config.token_label = Some("helios".into());
            setup.challenge_key_label = Some("challenge-key".into());
        },
        |s| {
            s.respond(MockResponse::error(403, "ChallengeUnsupported"));
            // The service sends a challenge anyway.
            s.respond(challenge_response());
            s.respond(identity_response());
        },
    )
    .await;

    ready(&b.running.handle).await;

    for request in b.service.requests() {
        assert_eq!(request.json().get("capabilities"), None);
    }
    assert_eq!(b.service.requests().len(), 3);
}

#[tokio::test]
async fn starts_again_at_once_when_the_challenge_expired() {
    let device = device();
    add_challenge_key(&device.token);
    let b = start(
        &device.token,
        |config, setup| {
            config.token_label = Some("helios".into());
            setup.challenge_key_label = Some("challenge-key".into());
            setup.timing.initial_backoff = Duration::from_secs(3600);
            setup.timing.max_backoff = Duration::from_secs(3600);
        },
        |s| {
            s.respond(challenge_response());
            s.respond(MockResponse::error(403, "ChallengeExpired"));
            s.respond(challenge_response());
            s.respond(bare_identity_response());
        },
    )
    .await;

    // Backoff is an hour, so only an immediate retry can get there.
    ready(&b.running.handle).await;
    assert_eq!(b.service.requests().len(), 4);
}

#[tokio::test]
async fn slows_down_after_repeated_challenge_rejections() {
    let device = device();
    add_challenge_key(&device.token);
    let b = start(
        &device.token,
        |config, setup| {
            config.token_label = Some("helios".into());
            setup.challenge_key_label = Some("challenge-key".into());
            setup.timing.slow_retry = Duration::from_secs(3600);
        },
        |s| {
            for _ in 0..2 {
                s.respond(challenge_response());
                s.respond(MockResponse::error(403, "ChallengeFailed"));
            }
            s.respond(identity_response());
        },
    )
    .await;

    // The second rejection in a row waits for the slow retry.
    let attempts = bootstrapping_error(&b.running.handle, "ChallengeFailed").await;
    eventually("two rejections", || b.service.requests().len() == 4).await;
    tokio::time::sleep(Duration::from_millis(200)).await;
    assert_eq!(b.service.requests().len(), 4, "waiting for the slow retry");
    assert!(attempts >= 1);

    b.running.handle.poke();
    ready(&b.running.handle).await;
}

#[tokio::test]
async fn waits_for_the_token_when_the_challenge_cannot_be_signed() {
    let device = device();
    add_challenge_key(&device.token);
    device.token.fail_next(
        Op::SignWithoutLogin,
        TokenError::TokenLost("unplugged".into()),
    );
    let b = start(
        &device.token,
        |config, setup| {
            config.token_label = Some("helios".into());
            setup.challenge_key_label = Some("challenge-key".into());
        },
        |s| {
            s.respond(challenge_response());
            s.respond(challenge_response());
            s.respond(bare_identity_response());
        },
    )
    .await;

    ready(&b.running.handle).await;

    assert_eq!(
        paths(&b.service),
        [
            "/v1/device/bootstrap",
            "/v1/device/bootstrap",
            "/v1/device/bootstrap/challenge"
        ]
    );
}

#[tokio::test]
async fn a_mismatch_with_local_config_is_fatal() {
    let device = device();
    let b = start(
        &device.token,
        |config, _| config.thing_name = Some("t-SOMEOTHERTHING".into()),
        |s| s.respond(identity_response()),
    )
    .await;

    let reason = fatal(b.running).await;

    assert_eq!(
        reason,
        FatalReason::IdentityMismatch {
            field: "thing_name",
            local: "t-SOMEOTHERTHING".into(),
            service: THING_NAME.into(),
        }
    );
    assert_eq!(count(&device.token, Op::Login), 0);
}

#[tokio::test]
async fn matching_local_values_are_fine() {
    let device = device();
    add_challenge_key(&device.token);
    let b = start(
        &device.token,
        |config, setup| {
            config.thing_name = Some(THING_NAME.into());
            config.token_label = Some("helios".into());
            config.key_label = Some("device-key".into());
            setup.challenge_key_label = Some("challenge-key".into());
        },
        |s| s.respond(identity_response()),
    )
    .await;

    ready(&b.running.handle).await;
}

#[tokio::test]
async fn a_wrong_pin_from_the_service_is_fatal_after_one_try() {
    let device = device();
    let b = start(
        &device.token,
        |_, _| {},
        |s| {
            s.respond(MockResponse::json(
                200,
                &protocol_test_body("BootstrapReturnsIdentity").replace(SERVICE_PIN, "000000"),
            ))
        },
    )
    .await;

    assert_eq!(fatal(b.running).await, FatalReason::PinIncorrect);
    assert_eq!(count(&device.token, Op::Login), 1);
}

#[tokio::test]
async fn opens_the_token_the_service_names() {
    let device = device();
    let body = protocol_test_body("BootstrapReturnsIdentity")
        .replace("\"tokenLabel\": \"helios\"", "\"tokenLabel\": \"other\"");
    let b = start(
        &device.token,
        |_, _| {},
        |s| s.respond(MockResponse::json(200, &body)),
    )
    .await;

    let (reason, _) = unavailable(&b.running.handle).await;

    assert_eq!(reason, "no token with label \"other\"");
}

#[tokio::test]
async fn needs_a_built_in_adapter() {
    let device = device();
    let b = start(
        &device.token,
        |_, setup| setup.interfaces = Interfaces::Named(vec!["eth9".into()]),
        |_| {},
    )
    .await;

    let reason = fatal(b.running).await;

    assert!(matches!(reason, FatalReason::Adapters(_)), "{reason:?}");
    assert_eq!(
        reason.to_string(),
        "bootstrap: network interface \"eth9\" does not exist"
    );
    assert!(b.service.requests().is_empty());
}

#[tokio::test]
async fn can_be_cancelled_while_bootstrapping() {
    let device = device();
    // No queued responses: the service keeps answering 500.
    let b = start(&device.token, |_, _| {}, |_| {}).await;
    bootstrapping_error(&b.running.handle, "InternalError").await;

    b.running.cancel.cancel();

    assert_eq!(b.running.task.await.unwrap(), ManagerExit::Cancelled);
}

#[test]
fn a_local_pin_needs_local_names() {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    let _guard = runtime.enter();
    let pin = super::tests::pin("1234");
    let token = MockToken::new("1234");

    for (config, missing) in [
        (ManagerConfig::for_bootstrap(), "device.thing_name"),
        (
            ManagerConfig {
                thing_name: Some(THING_NAME.into()),
                ..ManagerConfig::for_bootstrap()
            },
            "identity.key_label",
        ),
    ] {
        let error = IdentityManager::start(
            config,
            Box::new(token.clone()),
            PinSetting::Local(pin.clone()),
            any_roots(),
            CancellationToken::new(),
        )
        .err()
        .unwrap();
        assert!(matches!(error, StartError::Missing(name) if name == missing));
        assert!(error.to_string().starts_with(missing));
    }
    assert_eq!(
        NotYetFetched.read().unwrap_err(),
        PinError::new("the bootstrap service has not supplied the PIN yet")
    );
    let timing = BootstrapTiming::default();
    assert_eq!(timing.initial_backoff, Duration::from_secs(2));
    assert_eq!(timing.max_backoff, Duration::from_secs(60));
    assert_eq!(timing.slow_retry, Duration::from_secs(300));
}
