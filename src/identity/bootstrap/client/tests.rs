//! Bootstrap client tests against the local HTTPS mock (LLD 1, section 9).

use secrecy::ExposeSecret;

use super::*;
use crate::clock::ClockSamples;
use crate::clock::offset::Source;
use crate::identity::bootstrap::api::tests::{json, protocol_test_body, relay_adapters};
use crate::identity::bootstrap::api::{Capability, Challenge};
use crate::identity::testing::{MockResponse, MockService, ca};
use crate::identity::tls::root_store_from_pem;

fn client(service: &MockService) -> BootstrapClient {
    BootstrapClient::new(&service.url(), service.roots(), Duration::from_secs(5)).unwrap()
}

fn request() -> BootstrapRequest {
    BootstrapRequest::new(relay_adapters(), None, vec![Capability::TokenChallenge])
}

fn identity_body() -> String {
    protocol_test_body("BootstrapReturnsIdentity")
}

/// The identity object without the `identity` wrapper, as `AnswerChallenge` returns it.
fn bare_identity_body() -> String {
    json(&identity_body())["identity"].to_string()
}

#[tokio::test]
async fn posts_the_request_and_returns_the_identity() {
    let service = MockService::start().await;
    service.respond(MockResponse::json(200, &identity_body()));

    let result = client(&service).bootstrap(&request()).await.unwrap();

    let BootstrapResult::Identity(identity) = result else {
        panic!("expected an identity");
    };
    assert_eq!(identity.pin.expose_secret(), "123456");
    let [recorded] = service.requests().try_into().unwrap();
    assert_eq!(recorded.method, "POST");
    assert_eq!(recorded.path, "/v1/device/bootstrap");
    assert_eq!(recorded.headers["content-type"], "application/json");
    assert_eq!(recorded.headers["accept"], "application/json");
    assert_eq!(
        recorded.headers["host"],
        format!("localhost:{}", service.port).as_str()
    );
    assert_eq!(
        recorded.headers["user-agent"],
        concat!("helios/", env!("CARGO_PKG_VERSION"))
    );
    assert_eq!(recorded.json(), serde_json::to_value(request()).unwrap());
}

#[tokio::test]
async fn returns_a_challenge_and_takes_the_answer() {
    let service = MockService::start().await;
    service.respond(MockResponse::json(
        200,
        &protocol_test_body("BootstrapReturnsChallenge"),
    ));
    service.respond(MockResponse::json(200, &bare_identity_body()));
    let client = client(&service);

    let result = client.bootstrap(&request()).await.unwrap();
    let BootstrapResult::Challenge(Challenge { challenge_id, .. }) = result else {
        panic!("expected a challenge");
    };
    let answer = AnswerChallengeRequest {
        challenge_id,
        signature: "MEQCIB2k".into(),
        adapters: relay_adapters(),
    };
    let identity = client.answer_challenge(&answer).await.unwrap();

    assert_eq!(identity.thing_name, "t-01JD5VY2K7M9Q4R6T8V0X2Z4B6");
    let requests = service.requests();
    assert_eq!(requests[1].path, "/v1/device/bootstrap/challenge");
    assert_eq!(requests[1].json(), serde_json::to_value(&answer).unwrap());
}

#[tokio::test]
async fn names_service_errors_and_says_when_to_retry() {
    let cases = [
        (403, "DeviceDisabled", Retry::Slowly),
        (
            403,
            "tv.kenley.helios.contract#DeviceDisabled",
            Retry::Slowly,
        ),
        (
            404,
            "UnknownDevice:http://internal.amazon.com/coral/",
            Retry::Slowly,
        ),
        (409, "AmbiguousDevice", Retry::Slowly),
        (403, "ChallengeUnsupported", Retry::Slowly),
        (403, "ChallengeExpired", Retry::Now),
        (403, "ChallengeFailed", Retry::ChallengeRejected),
        (400, "ValidationException", Retry::Backoff),
        (500, "InternalError", Retry::Backoff),
        (429, "RateLimited", Retry::Backoff),
    ];
    let service = MockService::start().await;
    for (status, error_type, _) in cases {
        service.respond(MockResponse::error(status, error_type));
    }
    let client = client(&service);

    for (status, error_type, retry) in cases {
        let error = client.bootstrap(&request()).await.unwrap_err();
        assert_eq!(error.retry(), retry, "{error_type}");
        let BootstrapError::Service { status: got, .. } = &error else {
            panic!("expected a service error, got {error:?}");
        };
        assert_eq!(got.as_u16(), status);
        let name = error.error_type().unwrap();
        assert!(
            error_type.contains(name) && !name.contains([':', '#']),
            "{name}"
        );
    }
}

#[tokio::test]
async fn waits_as_long_as_retry_after_says() {
    let service = MockService::start().await;
    service.respond(MockResponse::error(429, "RateLimited").header("retry-after", "7"));
    service.respond(MockResponse::json(502, "").header("retry-after", "soon"));

    let client = client(&service);
    let error = client.bootstrap(&request()).await.unwrap_err();
    assert_eq!(error.retry(), Retry::After(Duration::from_secs(7)));
    let error = client.bootstrap(&request()).await.unwrap_err();
    assert_eq!(error.retry(), Retry::Backoff);
    assert_eq!(error.error_type(), None);
    assert_eq!(
        error.to_string(),
        "the bootstrap service returned 502 Bad Gateway (no error type)"
    );
}

#[tokio::test]
async fn does_not_follow_redirects() {
    let service = MockService::start().await;
    service.respond(MockResponse::json(302, "").header("location", "https://elsewhere.example/v1"));

    let error = client(&service).bootstrap(&request()).await.unwrap_err();

    assert!(
        matches!(error, BootstrapError::Redirect(StatusCode::FOUND)),
        "{error:?}"
    );
    assert_eq!(error.retry(), Retry::Backoff);
    assert_eq!(service.requests().len(), 1);
}

#[tokio::test]
async fn malformed_bodies_never_show_their_contents() {
    let service = MockService::start().await;
    // The PIN has the wrong type: serde's own message would quote it.
    let wrong_type = identity_body().replace("\"123456\"", "987654");
    service.respond(MockResponse::json(200, &wrong_type));
    service.respond(MockResponse::json(200, "not json at all"));
    let client = client(&service);

    for _ in 0..2 {
        let error = client.bootstrap(&request()).await.unwrap_err();
        assert!(matches!(error, BootstrapError::Malformed(_)), "{error:?}");
        assert!(!error.to_string().contains("987654"), "{error}");
        assert!(!format!("{error:?}").contains("987654"), "{error:?}");
        assert!(error.to_string().contains(" at line "), "{error}");
        assert_eq!(error.retry(), Retry::Backoff);
    }
}

#[tokio::test]
async fn rejects_responses_that_break_the_model() {
    let service = MockService::start().await;
    service.respond(MockResponse::json(
        200,
        &identity_body().replace("device-key", "a-label-that-is-longer-than-32-bytes"),
    ));
    service.respond(MockResponse::json(
        200,
        &protocol_test_body("BootstrapReturnsChallenge").replace("ecdsa-p256-sha256", "rsa"),
    ));
    service.respond(MockResponse::json(
        200,
        &bare_identity_body().replace("\"123456\"", "\"12\""),
    ));
    let client = client(&service);

    let error = client.bootstrap(&request()).await.unwrap_err();
    assert_eq!(
        error.to_string(),
        "the bootstrap service response is malformed: response member token.keyLabel is not valid"
    );
    let error = client.bootstrap(&request()).await.unwrap_err();
    assert!(error.to_string().contains("challenge.alg"), "{error}");
    let answer = AnswerChallengeRequest {
        challenge_id: "c-01JD5W3Q8T6M2K4X9B0N7C1D2E".into(),
        signature: "MEQCIB2k".into(),
        adapters: relay_adapters(),
    };
    let error = client.answer_challenge(&answer).await.unwrap_err();
    assert!(matches!(error, BootstrapError::Invalid(_)), "{error:?}");
}

#[tokio::test]
async fn refuses_oversized_bodies() {
    let service = MockService::start().await;
    let huge = format!("{{\"padding\":\"{}\"}}", "x".repeat(MAX_RESPONSE_LEN));
    service.respond(MockResponse::json(200, &huge));

    let error = client(&service).bootstrap(&request()).await.unwrap_err();

    assert!(matches!(error, BootstrapError::TooLarge), "{error:?}");
}

#[tokio::test]
async fn checks_the_service_certificate_and_host_name() {
    let service = MockService::start().await;
    let other_roots = root_store_from_pem(ca("Someone else").pem.as_bytes()).unwrap();
    let untrusting =
        BootstrapClient::new(&service.url(), other_roots, Duration::from_secs(5)).unwrap();

    let error = untrusting.bootstrap(&request()).await.unwrap_err();
    assert!(matches!(error, BootstrapError::Tls(_)), "{error:?}");
    assert!(error.to_string().starts_with("TLS handshake"), "{error}");
    assert_eq!(error.retry(), Retry::Backoff);

    let misnamed = MockService::start_as("device-management.services.kenley.tv").await;
    let error = client(&misnamed).bootstrap(&request()).await.unwrap_err();
    assert!(matches!(error, BootstrapError::Tls(_)), "{error:?}");
    assert!(service.requests().is_empty() && misnamed.requests().is_empty());
}

#[tokio::test]
async fn times_out_slow_responses() {
    let service = MockService::start().await;
    service.respond(MockResponse::json(200, &identity_body()).delay(Duration::from_secs(2)));
    let client =
        BootstrapClient::new(&service.url(), service.roots(), Duration::from_millis(200)).unwrap();

    let error = client.bootstrap(&request()).await.unwrap_err();

    assert!(matches!(error, BootstrapError::Timeout(_)), "{error:?}");
    assert_eq!(
        error.to_string(),
        "the bootstrap service did not respond within 200 ms"
    );
}

#[tokio::test]
async fn reports_connection_failures() {
    // Bind and drop a listener to get a port nothing listens on.
    let port = std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port();
    let roots = root_store_from_pem(ca("roots").pem.as_bytes()).unwrap();
    let client = BootstrapClient::new(
        &format!("https://localhost:{port}/v1"),
        roots,
        Duration::from_secs(5),
    )
    .unwrap();

    let error = client.bootstrap(&request()).await.unwrap_err();

    assert!(matches!(error, BootstrapError::Connect(_)), "{error:?}");
    assert_eq!(error.retry(), Retry::Backoff);
}

#[tokio::test]
async fn reports_http_errors() {
    // A server that accepts TLS and then closes without answering.
    let service = MockService::start().await;
    service.respond(MockResponse::json(200, "{}").delay(Duration::from_secs(30)));
    let client =
        BootstrapClient::new(&service.url(), service.roots(), Duration::from_secs(5)).unwrap();
    let raw = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = raw.local_addr().unwrap().port();
    tokio::spawn(async move {
        while let Ok((tcp, _)) = raw.accept().await {
            drop(tcp);
        }
    });
    let closing = BootstrapClient {
        endpoint: Endpoint::new("localhost", port).unwrap(),
        ..client.clone()
    };

    let error = closing.bootstrap(&request()).await.unwrap_err();

    // The connection closes during the TLS handshake.
    assert!(
        matches!(error, BootstrapError::Tls(_) | BootstrapError::Http(_)),
        "{error:?}"
    );
}

fn roots() -> RootCertStore {
    root_store_from_pem(ca("roots").pem.as_bytes()).unwrap()
}

#[test]
fn accepts_only_https_urls_without_queries() {
    let client = BootstrapClient::new(
        "https://device-management.services.kenley.tv/v1/",
        roots(),
        DEFAULT_TIMEOUT,
    )
    .unwrap();
    assert_eq!(
        client.endpoint.host(),
        "device-management.services.kenley.tv"
    );
    assert_eq!(client.endpoint.port(), 443);
    assert_eq!(client.base_path, "/v1");
    assert_eq!(client.timeout, Duration::from_secs(10));

    type Expected = fn(&UrlError) -> bool;
    let cases: [(&str, Expected); 5] = [
        ("http://device-management.services.kenley.tv/v1", |e| {
            matches!(e, UrlError::NotHttps(_))
        }),
        (
            "https://device-management.services.kenley.tv/v1?debug=1",
            |e| matches!(e, UrlError::Query(_)),
        ),
        ("https://device-management.services.kenley.tv/v1#x", |e| {
            matches!(e, UrlError::Query(_) | UrlError::Invalid(_))
        }),
        ("not a url", |e| matches!(e, UrlError::Invalid(_))),
        ("https:///v1", |e| matches!(e, UrlError::Invalid(_))),
    ];
    for (url, expected) in cases {
        let error = BootstrapClient::new(url, roots(), DEFAULT_TIMEOUT).unwrap_err();
        assert!(expected(&error), "{url}: {error:?}");
        assert!(error.to_string().contains("bootstrap.url"), "{error}");
    }
    let error =
        BootstrapClient::new("https://exa mple.com/v1", roots(), DEFAULT_TIMEOUT).unwrap_err();
    assert!(
        matches!(error, UrlError::Invalid(_) | UrlError::Host(_)),
        "{error:?}"
    );
}

#[test]
fn parses_error_type_headers() {
    fn header(value: &str) -> HeaderMap {
        let mut headers = HeaderMap::new();
        headers.insert(ERROR_TYPE, value.parse().unwrap());
        headers
    }
    assert_eq!(
        error_type(&header("DeviceDisabled")).as_deref(),
        Some("DeviceDisabled")
    );
    assert_eq!(
        error_type(&header("ns#DeviceDisabled:extra")).as_deref(),
        Some("DeviceDisabled")
    );
    assert_eq!(error_type(&header("")), None);
    assert_eq!(error_type(&HeaderMap::new()), None);
    assert_eq!(retry_after(&HeaderMap::new()), None);
}

#[tokio::test]
async fn offers_the_server_time_to_the_clock_checks() {
    let service = MockService::start().await;
    service.respond(
        MockResponse::error(404, "UnknownDevice").header("date", "Sat, 21 Nov 2026 06:00:00 GMT"),
    );
    let (clock, mut samples) = ClockSamples::for_test();

    let result = client(&service)
        .with_clock(clock)
        .bootstrap(&request())
        .await;

    assert!(result.is_err());
    // Error responses carry the server's time too.
    let sample = samples.try_recv().unwrap();
    assert_eq!(sample.source, Source::Bootstrap);
    assert_eq!(
        sample.server,
        std::time::UNIX_EPOCH + Duration::from_secs(1_795_240_800)
    );
    assert!(sample.received >= sample.sent);
}
