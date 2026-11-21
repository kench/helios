//! Credentials client tests against a local mutual-TLS mock of the credentials provider
//! (LLD 1, section 9).

use secrecy::ExposeSecret;

use super::*;
use crate::clock::ClockSamples;
use crate::clock::offset::Source;
use crate::identity::manager::IdentityHandle;
use crate::identity::testing::{MockResponse, MockService, THING_NAME, ca, ready_identity};
use crate::identity::tls::Alpn;

const ROLE_ALIAS: &str = "helios-device-role-alias";

fn body(expiration: &str) -> String {
    format!(
        r#"{{"credentials":{{"accessKeyId":"ASIAEXAMPLE","secretAccessKey":"secret-key-value","sessionToken":"session-token-value","expiration":"{expiration}"}}}}"#
    )
}

/// The credentials provider and an identity it trusts.
struct Setup {
    service: MockService,
    identity: IdentityHandle,
    client: CredentialsClient,
    _cancel: tokio_util::sync::DropGuard,
}

async fn setup() -> Setup {
    let device_ca = ca("Helios test device CA");
    let service = MockService::start_mtls(&device_ca).await;
    let (identity, _token, cancel) = ready_identity(&device_ca, service.roots()).await;
    let client = CredentialsClient::new(
        &format!("localhost:{}", service.port),
        ROLE_ALIAS,
        THING_NAME,
    )
    .unwrap();
    Setup {
        service,
        identity,
        client,
        _cancel: cancel.drop_guard(),
    }
}

impl Setup {
    async fn fetch(&self) -> Result<FetchedCredentials, CredentialsError> {
        self.client
            .fetch(self.identity.tls_config(Alpn::Http1).unwrap())
            .await
    }
}

#[tokio::test]
async fn fetches_credentials_with_the_device_certificate() {
    let setup = setup().await;
    setup.service.respond(
        MockResponse::json(200, &body("2033-11-06T09:49:37Z"))
            .header("date", "Sun, 06 Nov 2033 08:49:37 GMT"),
    );

    let credentials = setup.fetch().await.unwrap();

    assert_eq!(credentials.access_key_id, "ASIAEXAMPLE");
    assert_eq!(
        credentials.secret_access_key.expose_secret(),
        "secret-key-value"
    );
    assert_eq!(
        credentials.session_token.expose_secret(),
        "session-token-value"
    );
    let debug = format!("{credentials:?}");
    assert!(!debug.contains("secret-key-value") && !debug.contains("session-token-value"));
    let [request] = setup.service.requests().try_into().unwrap();
    assert_eq!(request.method, "GET");
    assert_eq!(
        request.path,
        format!("/role-aliases/{ROLE_ALIAS}/credentials")
    );
    assert_eq!(request.headers["x-amzn-iot-thingname"], THING_NAME);
    assert_eq!(request.client_cn.as_deref(), Some(THING_NAME));
}

#[tokio::test]
async fn measures_the_lifetime_by_the_server_clock() {
    // The server's clock reads 2033, whatever the device clock says.
    let setup = setup().await;
    setup.service.respond(
        MockResponse::json(200, &body("2033-11-06T09:49:37.500Z"))
            .header("date", "Sun, 06 Nov 2033 08:49:37 GMT"),
    );

    let credentials = setup.fetch().await.unwrap();

    assert_eq!(credentials.lifetime, Duration::from_millis(3_600_500));
}

#[tokio::test]
async fn falls_back_to_the_device_clock_without_a_date() {
    let setup = setup().await;
    let expiration = SystemTime::now() + Duration::from_secs(3600);
    let expiration = httpdate_to_rfc3339(expiration);
    setup
        .service
        .respond(MockResponse::json(200, &body(&expiration)));

    let credentials = setup.fetch().await.unwrap();

    let lifetime = credentials.lifetime.as_secs();
    assert!((3590..=3600).contains(&lifetime), "{lifetime}");
}

/// Formats a time as RFC 3339 by way of the HTTP date (seconds precision).
fn httpdate_to_rfc3339(time: SystemTime) -> String {
    let seconds = time.duration_since(UNIX_EPOCH).unwrap().as_secs();
    let days = seconds / 86_400;
    let (h, m, s) = (seconds / 3600 % 24, seconds / 60 % 60, seconds % 60);
    // Invert days_from_civil by search: fine for a test.
    let mut year = 1970;
    while days_from_civil(year + 1, 1, 1) <= i64::try_from(days).unwrap() {
        year += 1;
    }
    let mut month = 1;
    while month < 12 && days_from_civil(year, month + 1, 1) <= i64::try_from(days).unwrap() {
        month += 1;
    }
    let day = i64::try_from(days).unwrap() - days_from_civil(year, month, 1) + 1;
    format!("{year:04}-{month:02}-{day:02}T{h:02}:{m:02}:{s:02}Z")
}

#[tokio::test]
async fn rejects_credentials_that_expired_already() {
    let setup = setup().await;
    setup.service.respond(
        MockResponse::json(200, &body("2033-11-06T08:49:37Z"))
            .header("date", "Sun, 06 Nov 2033 08:49:37 GMT"),
    );
    setup
        .service
        .respond(MockResponse::json(200, &body("2033-13-06T08:49:37Z")));

    let error = setup.fetch().await.unwrap_err();
    assert_eq!(
        error.to_string(),
        "credentials provider response is malformed: credentials expired before they arrived"
    );
    let error = setup.fetch().await.unwrap_err();
    assert!(error.to_string().contains("RFC 3339"), "{error}");
    assert_eq!(error.retry(), Retry::Backoff);
}

#[tokio::test]
async fn configuration_errors_retry_slowly() {
    let setup = setup().await;
    setup
        .service
        .respond(MockResponse::json(403, r#"{"message":"Access Denied"}"#));
    setup.service.respond(MockResponse::json(404, "not json"));
    setup.service.respond(MockResponse::json(
        400,
        &format!(r#"{{"message":"{}"}}"#, "x".repeat(500)),
    ));

    let error = setup.fetch().await.unwrap_err();
    assert_eq!(error.retry(), Retry::Slowly);
    assert_eq!(
        error.to_string(),
        "credentials provider rejected the request (403 Forbidden): Access Denied"
    );
    let error = setup.fetch().await.unwrap_err();
    assert!(error.to_string().ends_with("(no message)"), "{error}");
    let CredentialsError::Rejected { message, .. } = setup.fetch().await.unwrap_err() else {
        panic!("expected a rejection");
    };
    assert_eq!(message.len(), 200);
}

#[tokio::test]
async fn other_errors_back_off() {
    let setup = setup().await;
    setup
        .service
        .respond(MockResponse::json(429, r#"{"message":"Rate exceeded"}"#));
    setup.service.respond(MockResponse::json(503, ""));
    setup
        .service
        .respond(MockResponse::json(302, "").header("location", "https://elsewhere.example/"));

    for status in [429, 503, 302] {
        let error = setup.fetch().await.unwrap_err();
        assert!(
            matches!(&error, CredentialsError::Status(s) if s.as_u16() == status),
            "{error:?}"
        );
        assert_eq!(error.retry(), Retry::Backoff);
    }
    assert_eq!(setup.service.requests().len(), 3);
}

#[tokio::test]
async fn malformed_bodies_never_show_their_contents() {
    let setup = setup().await;
    setup.service.respond(MockResponse::json(
        200,
        r#"{"credentials":{"accessKeyId":"ASIAEXAMPLE","secretAccessKey":123456789,"sessionToken":"t","expiration":"2033-11-06T09:49:37Z"}}"#,
    ));

    let error = setup.fetch().await.unwrap_err();

    assert!(matches!(error, CredentialsError::Malformed(_)), "{error:?}");
    assert!(!error.to_string().contains("123456789"), "{error}");
}

#[tokio::test]
async fn fails_without_a_client_certificate() {
    let setup = setup().await;
    let no_identity =
        crate::identity::tls::server_auth_config(setup.service.roots(), Alpn::Http1).unwrap();

    let error = setup.client.fetch(no_identity).await.unwrap_err();

    assert!(matches!(error, CredentialsError::Transport(_)), "{error:?}");
    assert_eq!(error.retry(), Retry::Backoff);
    assert!(
        error.to_string().starts_with("credentials provider: "),
        "{error}"
    );
}

#[test]
fn validates_the_settings() {
    assert!(
        CredentialsClient::new(
            "example.credentials.iot.us-west-2.amazonaws.com",
            ROLE_ALIAS,
            THING_NAME
        )
        .is_ok()
    );
    for alias in ["", "a/b", "role alias", &"r".repeat(129)] {
        assert_eq!(
            CredentialsClient::new("example.com", alias, THING_NAME).unwrap_err(),
            ConfigError::RoleAlias(alias.to_owned())
        );
    }
    let error = CredentialsClient::new("https://example.com", ROLE_ALIAS, THING_NAME).unwrap_err();
    assert!(matches!(error, ConfigError::Endpoint(_)));
    assert!(error.to_string().starts_with("aws.credentials_endpoint: "));
}

#[test]
fn parses_rfc3339_utc_times() {
    let at = |seconds: u64, nanos: u32| Some(UNIX_EPOCH + Duration::new(seconds, nanos));

    assert_eq!(parse_rfc3339("1970-01-01T00:00:00Z"), at(0, 0));
    assert_eq!(parse_rfc3339("2026-11-19T05:41:00Z"), at(1_795_066_860, 0));
    assert_eq!(
        parse_rfc3339("2026-11-19T05:41:00+00:00"),
        at(1_795_066_860, 0)
    );
    assert_eq!(
        parse_rfc3339("2026-11-19T05:41:00.25Z"),
        at(1_795_066_860, 250_000_000)
    );
    // Precision beyond nanoseconds is truncated.
    assert_eq!(
        parse_rfc3339("2026-11-19T05:41:00.1234567891Z"),
        at(1_795_066_860, 123_456_789)
    );
    assert_eq!(parse_rfc3339("2024-02-29T00:00:00Z"), at(1_709_164_800, 0));
    assert_eq!(parse_rfc3339("2000-03-01T00:00:00Z"), at(951_868_800, 0));
    for bad in [
        "",
        "2026-11-19T05:41:00",
        "2026-11-19T05:41:00-08:00",
        "2026-11-19 05:41:00Z",
        "2026-11-19T05:41Z",
        "2026-11-19T05:41:00:00Z",
        "2026-11-19-01T05:41:00Z",
        "26-11-19T05:41:00Z",
        "2026-13-19T05:41:00Z",
        "2026-02-30T05:41:00Z",
        "2023-02-29T05:41:00Z",
        "2100-02-29T05:41:00Z",
        "2026-04-31T05:41:00Z",
        "2026-11-19T24:00:00Z",
        "2026-11-19T05:60:00Z",
        "2026-11-19T05:41:61Z",
        "2026-11-19T05:41:00.Z1",
        "1969-12-31T23:59:59Z",
        "+026-11-19T05:41:00Z",
    ] {
        assert_eq!(parse_rfc3339(bad), None, "{bad}");
    }
}

#[tokio::test]
async fn offers_the_server_time_to_the_clock_checks() {
    let mut setup = setup().await;
    let (clock, mut samples) = ClockSamples::for_test();
    setup.client = setup.client.with_clock(clock);
    setup.service.respond(
        MockResponse::json(200, &body("2033-11-06T09:49:37Z"))
            .header("date", "Sun, 06 Nov 2033 08:49:37 GMT"),
    );

    setup.fetch().await.unwrap();

    let sample = samples.try_recv().unwrap();
    assert_eq!(sample.source, Source::Credentials);
    assert_eq!(
        sample.server,
        std::time::UNIX_EPOCH + std::time::Duration::from_secs(2_014_879_777)
    );
}
