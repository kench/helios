//! `verify` tests with the mock token and the mock bootstrap service.

use secrecy::SecretString;

use super::*;
use crate::identity::bootstrap::adapters::Interfaces;
use crate::identity::bootstrap::api::tests::protocol_test_body;
use crate::identity::bootstrap::client::BootstrapClient;
use crate::identity::manager::{BootstrapSetup, BootstrapTiming};
use crate::identity::mock::{MockKey, MockToken, Op};
use crate::identity::pin::FixedPin;
use crate::identity::testing::{
    self, MockResponse, MockService, NoPermanentAddresses, THING_NAME, ca, fake_sysfs,
};

fn token(pin: &str) -> MockToken {
    let ca = ca("Helios test device CA");
    let key = p256::ecdsa::SigningKey::from_slice(&[7; 32]).unwrap();
    let token = MockToken::new(pin);
    token.add_key(MockKey {
        label: "device-key".into(),
        id: vec![1],
        signing_key: key.clone(),
        private: true,
        certificate: Some(testing::device_certificate(&ca, &key, THING_NAME).to_vec()),
    });
    token
}

fn local(pin: &str) -> PinSetting {
    PinSetting::Local(Arc::new(FixedPin::new(SecretString::new(pin.into()))))
}

const TIMEOUT: Duration = Duration::from_secs(10);

#[tokio::test]
async fn reports_a_ready_identity() {
    let token = token("1234");

    let verified = verify_identity(
        ManagerConfig::new(THING_NAME, "device-key"),
        Box::new(token.clone()),
        local("1234"),
        TIMEOUT,
    )
    .await
    .unwrap();

    let Verified::Ready(identity) = verified else {
        panic!("expected ready, got {verified:?}");
    };
    let lines = describe(&identity);
    assert_eq!(lines[1], format!("thing name: {THING_NAME}"));
    assert!(
        lines
            .iter()
            .any(|l| l.starts_with("certificate: subject CN t-01JD5VY2K7M9Q4R6T8V0X2Z4B6"))
    );
    assert!(lines.iter().any(|l| l.starts_with("proof of possession")));
    assert!(!lines.iter().any(|l| l.contains("1234")));
    // The manager closed the token when it stopped.
    for _ in 0..100 {
        if !token.is_open() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    assert!(!token.is_open());
}

#[tokio::test]
async fn reports_fatal_problems() {
    let verified = verify_identity(
        ManagerConfig::new(THING_NAME, "device-key"),
        Box::new(token("1234")),
        local("0000"),
        TIMEOUT,
    )
    .await
    .unwrap();

    assert!(
        matches!(verified, Verified::Fatal(FatalReason::PinIncorrect)),
        "{verified:?}"
    );
}

#[tokio::test]
async fn reports_where_it_got_to_when_time_runs_out() {
    let token = token("1234");
    for _ in 0..100 {
        token.fail_next(
            Op::Open,
            TokenError::NotPresent {
                label: "helios".into(),
            },
        );
    }

    let verified = verify_identity(
        ManagerConfig::new(THING_NAME, "device-key"),
        Box::new(token),
        local("1234"),
        Duration::from_millis(300),
    )
    .await
    .unwrap();

    let Verified::TimedOut(IdentityState::Unavailable { reason, .. }) = verified else {
        panic!("expected unavailable, got {verified:?}");
    };
    assert_eq!(reason, "no token with label \"helios\"");
}

#[tokio::test]
async fn verifies_bootstrap_too() {
    let service = MockService::start().await;
    service.respond(MockResponse::json(
        200,
        &protocol_test_body("BootstrapReturnsIdentity"),
    ));
    let sysfs = fake_sysfs(&[("eth0", "2c:cf:67:00:00:01")]);
    let setup = BootstrapSetup {
        client: BootstrapClient::new(&service.url(), service.roots(), Duration::from_secs(5))
            .unwrap(),
        interfaces: Interfaces::Auto,
        sysfs: sysfs.path().to_owned(),
        permanent_addresses: Arc::new(NoPermanentAddresses),
        hardware_model: None,
        challenge_key_label: None,
        aws: None,
        timing: BootstrapTiming::default(),
    };

    // The service's PIN is the contract example's.
    let verified = verify_identity(
        ManagerConfig::for_bootstrap(),
        Box::new(token("123456")),
        PinSetting::Bootstrap(Box::new(setup)),
        TIMEOUT,
    )
    .await
    .unwrap();

    let Verified::Ready(identity) = verified else {
        panic!("expected ready, got {verified:?}");
    };
    let lines = describe(&identity);
    assert!(
        lines.contains(&"device ID (bootstrap service): d-01JD5VZ6R1H8P3S0W2Y4A6C8E0".to_owned())
    );
    assert!(
        lines
            .iter()
            .any(|l| l.starts_with("AWS (bootstrap service): region us-west-2"))
    );
    assert!(!lines.iter().any(|l| l.contains("123456")), "{lines:?}");
}

#[tokio::test]
async fn reports_bootstrap_problems_when_time_runs_out() {
    let service = MockService::start().await;
    service.respond(MockResponse::error(404, "UnknownDevice"));
    let sysfs = fake_sysfs(&[("eth0", "2c:cf:67:00:00:01")]);
    let setup = BootstrapSetup {
        client: BootstrapClient::new(&service.url(), service.roots(), Duration::from_secs(5))
            .unwrap(),
        interfaces: Interfaces::Auto,
        sysfs: sysfs.path().to_owned(),
        permanent_addresses: Arc::new(NoPermanentAddresses),
        hardware_model: None,
        challenge_key_label: None,
        aws: None,
        timing: BootstrapTiming::default(),
    };

    let verified = verify_identity(
        ManagerConfig::for_bootstrap(),
        Box::new(token("123456")),
        PinSetting::Bootstrap(Box::new(setup)),
        Duration::from_millis(500),
    )
    .await
    .unwrap();

    let Verified::TimedOut(IdentityState::Bootstrapping { last_error, .. }) = verified else {
        panic!("expected bootstrapping, got {verified:?}");
    };
    assert!(last_error.unwrap().contains("UnknownDevice"));
}

#[test]
fn a_missing_module_fails_the_challenge_check() {
    let error = check_challenge_key(
        Path::new("/nonexistent/libpkcs11.so"),
        "helios",
        "challenge-key",
    )
    .unwrap_err();

    assert!(error.is_config(), "{error:?}");
}
