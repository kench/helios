//! Service tests: the real identity manager and credentials refresher with a mock token, a
//! PIN file and a local mutual-TLS mock of the credentials provider (LLD 1, section 9).

use std::os::unix::fs::PermissionsExt;
use std::time::Duration;

use p256::ecdsa::SigningKey;
use tokio::sync::oneshot;

use super::*;
use crate::config::BootstrapConfig;
use crate::identity::bootstrap::adapters::Interfaces;
use crate::identity::bootstrap::api::AwsSettings;
use crate::identity::manager::{CertificateSource, IdentityState};
use crate::identity::mock::{MockKey, MockToken};
use crate::identity::pin::PinSpec;
use crate::identity::signer::DEFAULT_SIGN_TIMEOUT;
use crate::identity::testing::{
    Ca, MockResponse, MockService, NoPermanentAddresses, THING_NAME, ca, device_certificate,
    fake_sysfs,
};

const WAIT: Duration = Duration::from_secs(10);

/// A token with PIN 1234 and a device key whose certificate comes from `device_ca`.
fn token(device_ca: &Ca) -> MockToken {
    let key = SigningKey::from_slice(&[7; 32]).unwrap();
    let token = MockToken::new("1234");
    token.add_key(MockKey {
        label: "device-key".into(),
        id: vec![1],
        signing_key: key.clone(),
        private: true,
        certificate: Some(device_certificate(device_ca, &key, THING_NAME).to_vec()),
    });
    token
}

/// A PIN file holding `pin`, mode 0600.
fn pin_file(pin: &str) -> tempfile::TempDir {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("pin");
    std::fs::write(&path, format!("{pin}\n")).unwrap();
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
    dir
}

/// A local-PIN config for the credentials provider mock `service`.
fn local_config(service: &MockService, pin_dir: &Path) -> Config {
    Config {
        pin: PinSpec::File(pin_dir.join("pin")),
        pkcs11_module: PathBuf::from("/mock/libmock-pkcs11.so"),
        token_label: Some("helios".into()),
        key_label: Some("device-key".into()),
        thing_name: Some(THING_NAME.into()),
        certificate: CertificateSource::Token,
        allow_final_pin_try: false,
        sign_timeout: DEFAULT_SIGN_TIMEOUT,
        roots: service.roots(),
        aws: Some(AwsSettings {
            region: "us-west-2".into(),
            // MQTT tries this and gets refused straight away (see `mqtt` below).
            iot_endpoint: "localhost".into(),
            credentials_endpoint: format!("localhost:{}", service.port),
            role_alias: "helios-device-role-alias".into(),
        }),
        bootstrap: None,
        // A closed port: MQTT has its own tests (mqtt/manager/tests.rs).
        mqtt: crate::mqtt::MqttSettings {
            port: 9,
            ..crate::mqtt::MqttSettings::default()
        },
        clock: crate::clock::ClockSettings {
            boot_mark: None,
            ..crate::clock::ClockSettings::default()
        },
        ignored_sections: vec!["modules".into()],
    }
}

fn platform() -> Platform {
    Platform {
        sysfs: PathBuf::from("/nonexistent"),
        permanent_addresses: Arc::new(NoPermanentAddresses),
        device_tree_model: PathBuf::from("/nonexistent/model"),
        credentials_directory: None,
        boot_id: None,
    }
}

fn timing() -> Timing {
    Timing {
        credentials: crate::credentials::provider::Timing {
            initial_backoff: Duration::from_millis(10),
            max_backoff: Duration::from_millis(50),
            rejected_retry: Duration::from_millis(50),
            ..crate::credentials::provider::Timing::default()
        },
        mqtt: crate::mqtt::manager::Timing {
            initial_backoff: Duration::from_millis(10),
            max_backoff: Duration::from_millis(50),
            shutdown_wait: Duration::from_millis(200),
            ..crate::mqtt::manager::Timing::default()
        },
        shadows: crate::mqtt::shadow::Timing::default(),
        router: crate::router::Timing::default(),
        clock: crate::clock::Timing::default(),
    }
}

fn credentials_response() -> MockResponse {
    MockResponse::json(
        200,
        r#"{"credentials":{"accessKeyId":"ASIAEXAMPLE","secretAccessKey":"secret-key-value","sessionToken":"session-token-value","expiration":"2033-11-06T09:49:37Z"}}"#,
    )
    .header("date", "Sun, 06 Nov 2033 08:49:37 GMT")
}

/// Runs `service` until the returned sender fires, on its own task.
fn run(service: Service) -> (oneshot::Sender<()>, JoinHandle<u8>) {
    let (stop, stopped) = oneshot::channel();
    let task = tokio::spawn(service.run_until(async {
        let _ = stopped.await;
    }));
    (stop, task)
}

#[tokio::test]
async fn gets_credentials_with_a_local_pin_and_stops_on_shutdown() {
    let device_ca = ca("Helios test device CA");
    let service = MockService::start_mtls(&device_ca).await;
    service.respond(credentials_response());
    let token = token(&device_ca);
    let pin = pin_file("1234");

    let helios = Service::start(
        local_config(&service, pin.path()),
        Box::new(token.clone()),
        &platform(),
        timing(),
    )
    .unwrap();
    let mut identity = helios.identity().watch();
    let mut credentials = helios.credentials().status();
    tokio::time::timeout(
        WAIT,
        identity.wait_for(|state| matches!(state, IdentityState::Ready(_))),
    )
    .await
    .unwrap()
    .unwrap();
    tokio::time::timeout(
        WAIT,
        credentials.wait_for(|status| status.expires_at.is_some()),
    )
    .await
    .unwrap()
    .unwrap();
    let (stop, task) = run(helios);
    stop.send(()).unwrap();
    let code = tokio::time::timeout(WAIT, task).await.unwrap().unwrap();

    assert_eq!(code, EXIT_OK);
    let requests = service.requests();
    assert_eq!(requests.len(), 1);
    assert_eq!(
        requests[0].path,
        "/role-aliases/helios-device-role-alias/credentials"
    );
    // The signer thread closes the token after the manager stops, without the manager
    // waiting for it (a hung token mustn't block shutdown).
    tokio::time::timeout(WAIT, async {
        while token.is_open() {
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    })
    .await
    .expect("the token is closed on shutdown");
}

#[tokio::test]
async fn exits_78_for_a_wrong_pin() {
    let device_ca = ca("Helios test device CA");
    let service = MockService::start_mtls(&device_ca).await;
    let pin = pin_file("0000");

    let helios = Service::start(
        local_config(&service, pin.path()),
        Box::new(token(&device_ca)),
        &platform(),
        timing(),
    )
    .unwrap();
    let (_stop, task) = run(helios);
    let code = tokio::time::timeout(WAIT, task).await.unwrap().unwrap();

    assert_eq!(code, EXIT_CONFIG);
    assert!(
        service.requests().is_empty(),
        "no credentials without an identity"
    );
}

#[tokio::test]
async fn a_systemd_credential_needs_the_credentials_directory() {
    let device_ca = ca("Helios test device CA");
    let service = MockService::start_mtls(&device_ca).await;
    let pin = pin_file("1234");
    let mut config = local_config(&service, pin.path());
    config.pin = PinSpec::Credential("helios-pin".into());

    let Err(failure) = Service::start(config, Box::new(token(&device_ca)), &platform(), timing())
    else {
        panic!("started without CREDENTIALS_DIRECTORY");
    };

    assert!(failure.config);
    assert_eq!(failure.exit_code(), EXIT_CONFIG);
    assert!(
        failure.message.contains("CREDENTIALS_DIRECTORY"),
        "{failure}"
    );
}

#[tokio::test]
async fn reads_a_systemd_credential() {
    let device_ca = ca("Helios test device CA");
    let service = MockService::start_mtls(&device_ca).await;
    service.respond(credentials_response());
    let credentials = tempfile::tempdir().unwrap();
    std::fs::write(credentials.path().join("helios-pin"), "1234\n").unwrap();
    let pin = pin_file("unused");
    let mut config = local_config(&service, pin.path());
    config.pin = PinSpec::Credential("helios-pin".into());
    let mut platform = platform();
    platform.credentials_directory = Some(credentials.path().to_owned());

    let helios = Service::start(config, Box::new(token(&device_ca)), &platform, timing()).unwrap();
    let mut identity = helios.identity().watch();
    tokio::time::timeout(
        WAIT,
        identity.wait_for(|state| matches!(state, IdentityState::Ready(_))),
    )
    .await
    .unwrap()
    .unwrap();
    let (stop, task) = run(helios);
    stop.send(()).unwrap();

    assert_eq!(
        tokio::time::timeout(WAIT, task).await.unwrap().unwrap(),
        EXIT_OK
    );
}

#[tokio::test]
async fn bootstraps_until_shutdown() {
    let device_ca = ca("Helios test device CA");
    let bootstrap = MockService::start().await;
    for _ in 0..20 {
        bootstrap.respond(MockResponse::error(404, "UnknownDevice"));
    }
    let sysfs = fake_sysfs(&[("eth0", "2c:cf:67:00:00:01")]);
    let mut config = local_config(&bootstrap, Path::new("/unused"));
    config.pin = PinSpec::Bootstrap;
    config.thing_name = None;
    config.key_label = None;
    config.aws = None;
    config.bootstrap = Some(BootstrapConfig {
        url: bootstrap.url(),
        roots: bootstrap.roots(),
        interfaces: Interfaces::Auto,
        timeout: Duration::from_secs(5),
        challenge_key_label: None,
    });
    let mut platform = platform();
    platform.sysfs = sysfs.path().to_owned();

    let helios = Service::start(config, Box::new(token(&device_ca)), &platform, timing()).unwrap();
    let mut identity = helios.identity().watch();
    tokio::time::timeout(
        WAIT,
        identity.wait_for(|state| matches!(state, IdentityState::Bootstrapping { .. })),
    )
    .await
    .unwrap()
    .unwrap();
    tokio::time::timeout(WAIT, async {
        while bootstrap.requests().is_empty() {
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    })
    .await
    .unwrap();
    let (stop, task) = run(helios);
    stop.send(()).unwrap();

    assert_eq!(
        tokio::time::timeout(WAIT, task).await.unwrap().unwrap(),
        EXIT_OK
    );
    let request = bootstrap.requests()[0].json();
    assert_eq!(request["adapters"][0]["mac"], "2c:cf:67:00:00:01");
}

#[tokio::test]
async fn rejects_a_bootstrap_url_the_client_cannot_use() {
    let device_ca = ca("Helios test device CA");
    let service = MockService::start().await;
    let mut config = local_config(&service, Path::new("/unused"));
    config.pin = PinSpec::Bootstrap;
    config.bootstrap = Some(BootstrapConfig {
        url: "https://".into(),
        roots: service.roots(),
        interfaces: Interfaces::Auto,
        timeout: Duration::from_secs(5),
        challenge_key_label: None,
    });

    let Err(failure) = Service::start(config, Box::new(token(&device_ca)), &platform(), timing())
    else {
        panic!("started with an unusable URL");
    };

    assert!(failure.config, "{failure}");
}

#[tokio::test]
async fn a_missing_local_setting_is_a_config_error() {
    let device_ca = ca("Helios test device CA");
    let service = MockService::start_mtls(&device_ca).await;
    let pin = pin_file("1234");
    let mut config = local_config(&service, pin.path());
    config.thing_name = None;

    let Err(failure) = Service::start(config, Box::new(token(&device_ca)), &platform(), timing())
    else {
        panic!("started without a thing name");
    };

    assert_eq!(failure.exit_code(), EXIT_CONFIG);
    assert!(failure.message.contains("device.thing_name"), "{failure}");
}

#[test]
fn start_errors_map_to_exit_codes() {
    let missing = StartFailure::from(StartError::Missing("identity.key_label"));
    assert_eq!(missing.exit_code(), EXIT_CONFIG);

    let spawn = StartFailure::from(StartError::Spawn(std::io::Error::other("no threads")));
    assert!(!spawn.config);
    assert_eq!(spawn.exit_code(), EXIT_ERROR);
}

#[test]
fn the_system_platform_uses_the_real_paths() {
    let platform = Platform::system();

    assert_eq!(platform.sysfs, Path::new("/sys"));
    assert_eq!(platform.device_tree_model, Path::new(DEVICE_TREE_MODEL));
}

#[test]
fn main_exits_78_for_a_missing_config() {
    assert_eq!(main(Path::new("/nonexistent/helios.toml")), EXIT_CONFIG);
}

#[tokio::test]
async fn shutdown_signal_installs() {
    let signal = shutdown_signal().unwrap();

    // Not raised, so it doesn't complete.
    assert!(
        tokio::time::timeout(Duration::from_millis(20), signal)
            .await
            .is_err()
    );
}

#[tokio::test]
async fn routes_shadow_replies_and_commands() {
    let (incoming_tx, incoming) = mpsc::channel(4);
    let (shadows_tx, mut shadows) = mpsc::channel(1);
    let (commands_tx, mut commands) = mpsc::channel(4);
    let router = tokio::spawn(route(incoming, shadows_tx, commands_tx));
    let message = |topic: &str| Incoming {
        topic: topic.to_owned(),
        payload: b"{}".to_vec(),
    };

    incoming_tx
        .send(message("helios/t-1/cmd/video"))
        .await
        .unwrap();
    incoming_tx
        .send(message(
            "$aws/things/t-1/shadow/name/helios/update/accepted",
        ))
        .await
        .unwrap();
    // The shadow channel holds one; this one is dropped with a warning.
    incoming_tx
        .send(message("$aws/things/t-1/shadow/name/helios/update/delta"))
        .await
        .unwrap();
    drop(incoming_tx);
    router.await.unwrap();

    let routed = shadows.recv().await.unwrap();
    assert_eq!(
        routed.topic,
        "$aws/things/t-1/shadow/name/helios/update/accepted"
    );
    assert!(shadows.recv().await.is_none());
    assert_eq!(commands.recv().await.unwrap().topic, "helios/t-1/cmd/video");
    assert!(commands.recv().await.is_none());
}
