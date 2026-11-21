//! Credentials provider and refresher tests, against a local mutual-TLS mock of the
//! credentials provider and a running identity manager (LLD 1, section 9).

use aws_credential_types::provider::error::CredentialsError as SdkError;

use super::*;
use crate::identity::bootstrap::api::AwsSettings;
use crate::identity::mock::{MockToken, Op};
use crate::identity::testing::{MockResponse, MockService, THING_NAME, ca, ready_identity};
use crate::identity::token::TokenError;

const WAIT: Duration = Duration::from_secs(10);

/// One hour of credentials, by the server's clock.
fn credentials_response() -> MockResponse {
    MockResponse::json(
        200,
        r#"{"credentials":{"accessKeyId":"ASIAEXAMPLE","secretAccessKey":"secret-key-value","sessionToken":"session-token-value","expiration":"2033-11-06T09:49:37Z"}}"#,
    )
    .header("date", "Sun, 06 Nov 2033 08:49:37 GMT")
}

fn timing(refresh_after: fn(Duration, f64) -> Duration) -> Timing {
    Timing {
        refresh_after,
        initial_backoff: Duration::from_millis(10),
        max_backoff: Duration::from_millis(50),
        rejected_retry: Duration::from_millis(50),
    }
}

fn hourly(_: Duration, _: f64) -> Duration {
    Duration::from_secs(3600)
}

struct Setup {
    service: MockService,
    provider: HeliosCredentialsProvider,
    task: Option<JoinHandle<()>>,
    token: MockToken,
    cancel: CancellationToken,
    identity: CancellationToken,
}

impl Drop for Setup {
    fn drop(&mut self) {
        self.cancel.cancel();
        self.identity.cancel();
    }
}

async fn setup(timing: Timing, respond: impl FnOnce(&MockService)) -> Setup {
    let device_ca = ca("Helios test device CA");
    let service = MockService::start_mtls(&device_ca).await;
    respond(&service);
    let (identity_handle, token, identity) = ready_identity(&device_ca, service.roots()).await;
    let local = LocalSettings {
        credentials_endpoint: format!("localhost:{}", service.port),
        role_alias: "helios-device-role-alias".into(),
    };
    let cancel = CancellationToken::new();
    let (provider, task) = HeliosCredentialsProvider::start(
        identity_handle,
        Some(local),
        timing,
        crate::clock::ClockSamples::discard(),
        cancel.clone(),
    );
    Setup {
        service,
        provider,
        task: Some(task),
        token,
        cancel,
        identity,
    }
}

async fn eventually(what: &str, check: impl Fn() -> bool) {
    let deadline = Instant::now() + WAIT;
    while !check() {
        assert!(Instant::now() < deadline, "timed out waiting until {what}");
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
}

async fn status_where(
    setup: &Setup,
    what: impl Fn(&CredentialsStatus) -> bool,
) -> CredentialsStatus {
    let mut status = setup.provider.status();
    tokio::time::timeout(WAIT, status.wait_for(|status| what(status)))
        .await
        .expect("status never matched")
        .unwrap()
        .clone()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn fetches_when_ready_and_serves_the_sdk_from_the_cache() {
    let setup = setup(timing(hourly), |s| s.respond(credentials_response())).await;

    let status = status_where(&setup, |s| s.last_refresh.is_some()).await;

    let credentials = setup.provider.provide_credentials().await.unwrap();
    assert_eq!(credentials.access_key_id(), "ASIAEXAMPLE");
    assert_eq!(credentials.secret_access_key(), "secret-key-value");
    assert_eq!(credentials.session_token(), Some("session-token-value"));
    // The expiry is by the device clock: about an hour from now, not 2033.
    let remaining = credentials
        .expiry()
        .unwrap()
        .duration_since(SystemTime::now())
        .unwrap();
    assert!(remaining > Duration::from_secs(3590), "{remaining:?}");
    assert_eq!(status.expires_at, credentials.expiry());
    assert_eq!(status.last_error, None);
    setup.provider.provide_credentials().await.unwrap();
    assert_eq!(setup.service.requests().len(), 1);
    let debug = format!("{:?}", setup.provider);
    assert!(!debug.contains("secret-key-value"), "{debug}");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn refreshes_on_schedule() {
    let setup = setup(timing(|_, _| Duration::from_millis(100)), |s| {
        for _ in 0..3 {
            s.respond(credentials_response());
        }
    })
    .await;

    eventually("three refreshes", || setup.service.requests().len() >= 3).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn callers_share_one_refresh() {
    let setup = setup(timing(hourly), |s| {
        s.respond(credentials_response().delay(Duration::from_millis(300)));
    })
    .await;

    let calls: Vec<_> = (0..5)
        .map(|_| {
            let provider = setup.provider.clone();
            tokio::spawn(async move { provider.provide_credentials().await })
        })
        .collect();
    for call in calls {
        assert_eq!(call.await.unwrap().unwrap().access_key_id(), "ASIAEXAMPLE");
    }

    assert_eq!(setup.service.requests().len(), 1);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn retries_rejections_and_server_errors() {
    let setup = setup(timing(hourly), |s| {
        s.respond(MockResponse::json(403, r#"{"message":"Access Denied"}"#));
        s.respond(MockResponse::json(500, ""));
        s.respond(credentials_response());
    })
    .await;

    let status = status_where(&setup, |s| s.last_error.is_some()).await;
    assert_eq!(
        status.last_error.as_deref(),
        Some("credentials provider rejected the request (403 Forbidden): Access Denied")
    );

    let status = status_where(&setup, |s| s.last_refresh.is_some()).await;
    assert_eq!(status.last_error, None);
    assert_eq!(setup.service.requests().len(), 3);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn keeps_cached_credentials_while_the_identity_recovers() {
    let setup = setup(timing(|_, _| Duration::from_millis(100)), |s| {
        s.respond(credentials_response());
        s.respond(credentials_response());
    })
    .await;
    status_where(&setup, |s| s.last_refresh.is_some()).await;

    // The next refresh's handshake finds the token gone.
    setup
        .token
        .fail_next(Op::SignDigest, TokenError::TokenLost("unplugged".into()));
    let status = status_where(&setup, |s| s.last_error.is_some()).await;
    assert!(
        status.last_error.unwrap().contains("TLS"),
        "{:?}",
        setup.provider
    );

    // The cached credentials still work.
    let credentials = setup.provider.provide_credentials().await.unwrap();
    assert_eq!(credentials.access_key_id(), "ASIAEXAMPLE");

    // Once the identity recovers, the refresh that was due happens.
    eventually("a refresh after recovery", || {
        setup.service.requests().len() == 2
    })
    .await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn without_credentials_the_sdk_gets_the_reason() {
    let setup = setup(timing(hourly), |s| {
        s.respond(MockResponse::json(403, r#"{"message":"Access Denied"}"#));
        s.respond(MockResponse::json(403, r#"{"message":"Access Denied"}"#));
    })
    .await;

    let error = setup.provider.provide_credentials().await.unwrap_err();

    assert!(
        matches!(error, SdkError::CredentialsNotLoaded(_)),
        "{error:?}"
    );
    let source = std::error::Error::source(&error).unwrap().to_string();
    assert_eq!(
        source,
        "no AWS credentials yet: credentials provider rejected the request (403 Forbidden): \
         Access Denied"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn needs_an_endpoint_and_role_alias() {
    let device_ca = ca("Helios test device CA");
    let service = MockService::start_mtls(&device_ca).await;
    let (identity, _token, identity_cancel) = ready_identity(&device_ca, service.roots()).await;
    let cancel = CancellationToken::new();
    let (provider, task) = HeliosCredentialsProvider::start(
        identity,
        None,
        timing(hourly),
        crate::clock::ClockSamples::discard(),
        cancel.clone(),
    );

    let error = provider.provide_credentials().await.unwrap_err();

    let source = std::error::Error::source(&error).unwrap().to_string();
    assert!(
        source.contains("no credentials endpoint and role alias"),
        "{source}"
    );
    cancel.cancel();
    task.await.unwrap();
    identity_cancel.cancel();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn stops_when_cancelled_or_when_the_identity_stops() {
    let mut setup = setup(timing(hourly), |s| s.respond(credentials_response())).await;
    status_where(&setup, |s| s.last_refresh.is_some()).await;
    setup.identity.cancel();
    let task = setup.task.take().unwrap();
    tokio::time::timeout(WAIT, task).await.unwrap().unwrap();

    let mut setup = self::setup(timing(hourly), |s| s.respond(credentials_response())).await;
    setup.cancel.cancel();
    let task = setup.task.take().unwrap();
    tokio::time::timeout(WAIT, task).await.unwrap().unwrap();
}

#[test]
fn prefers_the_bootstrap_services_aws_settings() {
    let service = AwsSettings {
        region: "us-west-2".into(),
        iot_endpoint: "a-ats.iot.us-west-2.amazonaws.com".into(),
        credentials_endpoint: "a.credentials.iot.us-west-2.amazonaws.com".into(),
        role_alias: "service-alias".into(),
    };
    let local = LocalSettings {
        credentials_endpoint: "b.credentials.iot.us-west-2.amazonaws.com".into(),
        role_alias: "local-alias".into(),
    };

    assert_eq!(
        endpoints(Some(&service), Some(&local)),
        Some(("a.credentials.iot.us-west-2.amazonaws.com", "service-alias"))
    );
    assert_eq!(
        endpoints(None, Some(&local)),
        Some(("b.credentials.iot.us-west-2.amazonaws.com", "local-alias"))
    );
    assert_eq!(endpoints(None, None), None);
    let defaults = Timing::default();
    assert_eq!(defaults.initial_backoff, Duration::from_secs(5));
    assert_eq!(defaults.max_backoff, Duration::from_secs(300));
    assert_eq!(defaults.rejected_retry, Duration::from_secs(300));
    assert_eq!(
        (defaults.refresh_after)(Duration::from_secs(3600), 0.0),
        Duration::from_secs(2880)
    );
    let _ = THING_NAME;
}
