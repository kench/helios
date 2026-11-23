use std::sync::Mutex;

use super::*;

fn client(url: &str) -> Result<EgressClient, String> {
    let credentials: Arc<dyn ProvideCredentials> = Arc::new(
        aws_credential_types::Credentials::new("AKIDEXAMPLE", "secret", None, None, "test"),
    );
    EgressClient::new(url, RootCertStore::empty(), credentials)
}

#[test]
fn reads_the_echo_location_from_the_bootstrap_url() {
    let echo = client("https://p3u8fqa24c.execute-api.us-west-2.amazonaws.com/dev/v1").unwrap();
    assert_eq!(echo.path, "/dev/v1/device/egress");
    assert_eq!(echo.region, "us-west-2");
    assert_eq!(echo.host, "p3u8fqa24c.execute-api.us-west-2.amazonaws.com");
    let trailing = client("https://a.execute-api.eu-west-1.amazonaws.com/dev/v1/").unwrap();
    assert_eq!(trailing.path, "/dev/v1/device/egress");
    let local = client("https://a.execute-api.local:8443/v1").unwrap();
    assert_eq!(
        (local.region.as_str(), local.host.as_str()),
        ("local", "a.execute-api.local:8443")
    );
    for bad in [
        "http://a.execute-api.us-west-2.amazonaws.com/dev/v1",
        "https://bootstrap.example.com/v1",
        "https://a.execute-api./v1",
    ] {
        assert!(client(bad).is_err(), "{bad}");
    }
    assert!(format!("{echo:?}").contains("us-west-2"));
}

#[test]
fn parses_the_echo_answer() {
    assert_eq!(
        parse(br#"{"address": "203.0.113.7", "atMs": 1795378530000}"#),
        Ok("203.0.113.7".parse().unwrap())
    );
    assert_eq!(
        parse(br#"{"address": "2001:db8::7", "atMs": 1}"#),
        Ok("2001:db8::7".parse().unwrap())
    );
    for bad in [&b"{}"[..], b"not json", br#"{"address": "nowhere"}"#] {
        assert_eq!(parse(bad), Err("bad response".into()));
    }
}

fn ip(text: &str) -> IpAddr {
    text.parse().unwrap()
}

const ETH: Ipv4Addr = Ipv4Addr::new(192, 168, 5, 31);

#[tokio::test(start_paused = true)]
async fn schedules_checks_and_reports_what_they_found() {
    let mut checks = Checks::default();
    let start = Instant::now();
    let wall = SystemTime::UNIX_EPOCH + Duration::from_secs(1_795_378_530);
    checks.sync(&[("eth0".into(), ETH)], start);
    assert_eq!(
        checks.next(),
        Some(("eth0".into(), ETH, start)),
        "new: at once"
    );
    assert_eq!(checks.report("eth0"), Value::Null, "not checked yet");
    assert_eq!(checks.report("wlan0"), Value::Null, "not an uplink");

    checks.record("eth0", ETH, Ok(ip("203.0.113.7")), start, wall);
    let (_, _, due) = checks.next().unwrap();
    let wait = due - start;
    assert!(
        wait >= INTERVAL - INTERVAL_JITTER && wait <= INTERVAL + INTERVAL_JITTER,
        "{wait:?}"
    );
    let first = checks.report("eth0");
    assert_eq!(
        first,
        json!({"address": "203.0.113.7", "checked_at": timestamp(wall)})
    );

    // The same address 15 minutes later: checked_at stays, so the shadow doesn't change.
    let later = wall + Duration::from_secs(15 * 60);
    checks.record("eth0", ETH, Ok(ip("203.0.113.7")), start, later);
    assert_eq!(checks.report("eth0"), first);
    // An hour after the last one shown, it moves.
    let hour = wall + RENEWAL_REPORT;
    checks.record("eth0", ETH, Ok(ip("203.0.113.7")), start, hour);
    assert_eq!(checks.report("eth0")["checked_at"], json!(timestamp(hour)));
    // A new address shows at once.
    let moved = hour + Duration::from_secs(60);
    checks.record("eth0", ETH, Ok(ip("198.51.100.9")), start, moved);
    assert_eq!(
        checks.report("eth0"),
        json!({"address": "198.51.100.9", "checked_at": timestamp(moved)})
    );

    // A failure keeps the last answer, says so, and retries within the first backoff step.
    let failed = moved + Duration::from_secs(900);
    checks.record("eth0", ETH, Err("timeout".into()), start, failed);
    let report = checks.report("eth0");
    assert_eq!(report["address"], "198.51.100.9");
    assert_eq!(report["error"], "timeout");
    assert_eq!(report["failed_at"], json!(timestamp(failed)));
    let (_, _, retry) = checks.next().unwrap();
    assert!(retry - start <= RETRY_FIRST, "{:?}", retry - start);
    // A success clears the error.
    checks.record("eth0", ETH, Ok(ip("198.51.100.9")), start, failed);
    assert!(checks.report("eth0").get("error").is_none());
}

#[tokio::test(start_paused = true)]
async fn follows_uplinks_coming_changing_and_going() {
    let mut checks = Checks::default();
    let now = Instant::now();
    let wall = SystemTime::UNIX_EPOCH;
    checks.sync(&[("eth0".into(), ETH)], now);
    checks.record("eth0", ETH, Err("connect".into()), now, wall);
    assert_eq!(
        checks.report("eth0"),
        json!({"address": null, "error": "connect", "failed_at": timestamp(wall)}),
        "never answered"
    );
    checks.record("eth0", ETH, Ok(ip("203.0.113.7")), now, wall);
    // Its address changes: a fresh uplink, checked at once, nothing known.
    let other = Ipv4Addr::new(192, 168, 5, 40);
    let later = now + Duration::from_secs(5);
    checks.sync(&[("eth0".into(), other)], later);
    assert_eq!(checks.next(), Some(("eth0".into(), other, later)));
    assert_eq!(checks.report("eth0"), Value::Null);
    // A late answer for the old address is ignored.
    checks.record("eth0", ETH, Ok(ip("203.0.113.7")), later, wall);
    assert_eq!(checks.report("eth0"), Value::Null);
    // Gone: forgotten.
    checks.sync(&[], later);
    assert_eq!(checks.next(), None);
    assert_eq!(checks.report("eth0"), Value::Null);
}

#[test]
fn checks_only_uplinks_with_a_source_route() {
    let interfaces = json!({
        "eth0": {"ipv4": ["192.168.5.31/24", "10.0.0.2/8"],
                 "source_route": {"table": 10003, "rule": true}},
        "wwan0": {"ipv4": ["10.64.12.9/30"], "source_route": {"table": 10007, "rule": false}},
        "wlan0": {"ipv4": ["192.168.5.12/24"], "source_route": null},
        "usb0": {"ipv4": [], "source_route": {"table": 10009, "rule": true}},
    });
    assert_eq!(
        uplinks(interfaces.as_object().unwrap()),
        vec![("eth0".into(), ETH)],
        "the first address of a routed uplink only"
    );
}

/// A probe that answers with a fixed address and records each source it was asked from.
pub(crate) struct FakeProbe {
    pub(crate) answer: Result<IpAddr, String>,
    pub(crate) asked: Mutex<Vec<Ipv4Addr>>,
}

impl Probe for FakeProbe {
    fn check(
        &self,
        source: Ipv4Addr,
    ) -> Pin<Box<dyn Future<Output = Result<IpAddr, String>> + Send + '_>> {
        self.asked.lock().unwrap().push(source);
        let answer = self.answer.clone();
        Box::pin(async move { answer })
    }
}

#[tokio::test]
async fn the_client_reports_a_connection_failure() {
    // Nothing listens on 127.0.0.1:9, so the check fails, as a short reason.
    let echo = client("https://127.0.0.1.execute-api.local:9/v1");
    assert!(echo.is_ok());
    let echo = EgressClient {
        endpoint: Endpoint::new("127.0.0.1", 9).unwrap(),
        ..echo.unwrap()
    };
    let error = echo.check(Ipv4Addr::LOCALHOST).await.unwrap_err();
    assert!(["connect", "timeout"].contains(&error.as_str()), "{error}");
}
