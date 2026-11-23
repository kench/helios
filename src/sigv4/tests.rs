use std::path::{Path, PathBuf};
use std::time::Duration;

use super::*;

/// One case of AWS's SigV4 test suite (`tests/data/sigv4`, from awslabs/aws-c-auth).
struct Case {
    name: String,
    method: String,
    path: String,
    query: Vec<(String, String)>,
    host: String,
    headers: Vec<(String, String)>,
    body: Vec<u8>,
    credentials: Credentials,
    scope: (String, String, bool),
    now: SystemTime,
    canonical_request: String,
    string_to_sign: String,
    authorization: String,
}

fn cases_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/data/sigv4")
}

fn read(dir: &Path, file: &str) -> String {
    std::fs::read_to_string(dir.join(file)).unwrap_or_else(|e| panic!("{dir:?}/{file}: {e}"))
}

fn load(dir: &Path) -> Case {
    let context: serde_json::Value = serde_json::from_str(&read(dir, "context.json")).unwrap();
    let request = read(dir, "request.txt");
    let (head, body) = request.split_once("\n\n").unwrap_or((request.as_str(), ""));
    let mut lines = head.lines();
    let first: Vec<&str> = lines.next().unwrap().split(' ').collect();
    let (path, query) = first[1].split_once('?').unwrap_or((first[1], ""));
    let query = query
        .split('&')
        .filter(|pair| !pair.is_empty())
        .map(|pair| {
            let (key, value) = pair.split_once('=').unwrap_or((pair, ""));
            (key.to_owned(), value.to_owned())
        })
        .collect();
    let mut host = String::new();
    let mut headers = Vec::new();
    for line in lines {
        let (name, value) = line.split_once(':').unwrap();
        if name.eq_ignore_ascii_case("host") {
            host = value.to_owned();
        } else {
            headers.push((name.to_owned(), value.to_owned()));
        }
    }
    let credentials = &context["credentials"];
    let timestamp = context["timestamp"].as_str().unwrap();
    assert_eq!(
        timestamp, "2015-08-30T12:36:00Z",
        "the suite's one timestamp"
    );
    let authorization = read(dir, "header-signed-request.txt")
        .lines()
        .find_map(|line| line.strip_prefix("Authorization:").map(str::to_owned))
        .unwrap();
    Case {
        name: dir.file_name().unwrap().to_string_lossy().into_owned(),
        method: first[0].to_owned(),
        path: path.to_owned(),
        query,
        host,
        headers,
        body: body.as_bytes().to_vec(),
        credentials: Credentials::new(
            credentials["access_key_id"].as_str().unwrap(),
            credentials["secret_access_key"].as_str().unwrap(),
            credentials["token"].as_str().map(str::to_owned),
            None,
            "test",
        ),
        scope: (
            context["region"].as_str().unwrap().to_owned(),
            context["service"].as_str().unwrap().to_owned(),
            context["sign_body"].as_bool().unwrap_or(false),
        ),
        now: UNIX_EPOCH + Duration::from_secs(1_440_938_160),
        canonical_request: read(dir, "header-canonical-request.txt"),
        string_to_sign: read(dir, "header-string-to-sign.txt"),
        authorization,
    }
}

#[test]
fn matches_the_aws_sigv4_test_suite() {
    let mut names: Vec<PathBuf> = std::fs::read_dir(cases_dir())
        .unwrap()
        .map(|entry| entry.unwrap().path())
        .filter(|path| path.is_dir())
        .collect();
    names.sort();
    assert_eq!(names.len(), 16, "the cases in tests/data/sigv4");
    for dir in names {
        let case = load(&dir);
        let query: Vec<(&str, &str)> = case
            .query
            .iter()
            .map(|(k, v)| (k.as_str(), v.as_str()))
            .collect();
        let headers: Vec<(&str, &str)> = case
            .headers
            .iter()
            .map(|(k, v)| (k.as_str(), v.as_str()))
            .collect();
        let request = Request {
            method: &case.method,
            host: &case.host,
            path: &case.path,
            query: &query,
            headers: &headers,
            body: &case.body,
        };
        let scope = Scope {
            region: &case.scope.0,
            service: &case.scope.1,
            sign_body: case.scope.2,
        };
        let signing = signing(&request, &case.credentials, scope, case.now)
            .unwrap_or_else(|e| panic!("{}: {e}", case.name));
        assert_eq!(
            signing.canonical_request, case.canonical_request,
            "{}",
            case.name
        );
        assert_eq!(signing.string_to_sign, case.string_to_sign, "{}", case.name);
        let authorization = signing
            .headers
            .iter()
            .find(|(name, _)| *name == "Authorization")
            .map(|(_, value)| value.clone());
        assert_eq!(
            authorization,
            Some(case.authorization.clone()),
            "{}",
            case.name
        );
        let signed = sign(&request, &case.credentials, scope, case.now).unwrap();
        assert_eq!(signed, signing.headers, "{}", case.name);
        assert_eq!(
            signed
                .iter()
                .any(|(name, _)| *name == "X-Amz-Security-Token"),
            case.credentials.session_token().is_some(),
            "{}",
            case.name
        );
    }
}

fn plain() -> (Credentials, Scope<'static>) {
    (
        Credentials::new("AKIDEXAMPLE", "secret", None, None, "test"),
        Scope {
            region: "us-west-2",
            service: "execute-api",
            sign_body: false,
        },
    )
}

fn get<'a>(path: &'a str, headers: &'a [(&'a str, &'a str)]) -> Request<'a> {
    Request {
        method: "GET",
        host: "example.execute-api.us-west-2.amazonaws.com",
        path,
        query: &[],
        headers,
        body: b"",
    }
}

#[test]
fn signs_the_egress_echo_request() {
    let (credentials, scope) = plain();
    let headers = sign(
        &get("/dev/v1/device/egress", &[]),
        &credentials,
        scope,
        UNIX_EPOCH + Duration::from_secs(1_795_378_530),
    )
    .unwrap();
    assert_eq!(headers[0], ("X-Amz-Date", "20261122T201530Z".to_owned()));
    assert!(
        headers[1].1.starts_with(
            "AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE/20261122/us-west-2/execute-api/aws4_request, \
             SignedHeaders=host;x-amz-date, Signature="
        ),
        "{headers:?}"
    );
    assert_eq!(headers.len(), 2, "no token, no body hash");
}

#[test]
fn refuses_what_it_can_not_sign_exactly() {
    let (credentials, scope) = plain();
    for path in [
        "",
        "relative",
        "/a//b",
        "/a/./b",
        "/a/../b",
        "/a b",
        "/caf\u{e9}",
        "/%41",
    ] {
        assert_eq!(
            sign(&get(path, &[]), &credentials, scope, SystemTime::now()),
            Err(SignError::Path(path.to_owned())),
            "{path:?}"
        );
    }
    for (name, value) in [
        ("", "x"),
        ("a:b", "x"),
        ("a b", "x"),
        ("X-Ok", "line\r\nbreak"),
    ] {
        assert_eq!(
            sign(
                &get("/", &[(name, value)]),
                &credentials,
                scope,
                SystemTime::now()
            ),
            Err(SignError::Header(name.to_owned())),
            "{name:?}"
        );
    }
    assert_eq!(
        sign(
            &get("/", &[]),
            &credentials,
            scope,
            UNIX_EPOCH - Duration::from_secs(1)
        ),
        Err(SignError::Clock)
    );
    assert_eq!(SignError::Clock.to_string(), "the clock is before 1970");
}

#[test]
fn formats_dates_in_utc() {
    let at = |seconds: u64| amz_date(UNIX_EPOCH + Duration::from_secs(seconds)).unwrap();
    assert_eq!(at(0), ("19700101".into(), "19700101T000000Z".into()));
    assert_eq!(
        at(951_782_400),
        ("20000229".into(), "20000229T000000Z".into()),
        "leap day"
    );
    assert_eq!(
        at(4_102_444_799),
        ("20991231".into(), "20991231T235959Z".into())
    );
    assert_eq!(civil(-1), (1969, 12, 31));
}

#[test]
fn encodes_all_but_unreserved_characters() {
    assert_eq!(encode("AZaz09-_.~"), "AZaz09-_.~");
    assert_eq!(encode("a b/c=d&é"), "a%20b%2Fc%3Dd%26%C3%A9");
}
