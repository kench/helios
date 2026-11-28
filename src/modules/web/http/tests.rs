use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Mutex;

use serde_json::{Value, json};

use super::{Request, Response, Web, content_security_policy, inline_script_hashes, serve};
use crate::modules::web::auth::{self, Sessions, Throttle};
use crate::modules::web::control::Device;
use crate::mqtt::manager::MqttHandle;
use crate::mqtt::shadow::ShadowHandle;
use crate::router::RouterHandle;

const PASSWORD: &str = "a long console password";
const INDEX: &str = "<!DOCTYPE html><html><head><script type=\"module\" src=\"/assets/app.js\"></script></head><body><script>window.ready = true;</script></body></html>";

struct Site {
    web: Web,
    _dir: tempfile::TempDir,
}

fn site(with_console: bool) -> Site {
    // The console's folder, with a file beside it that must never be served.
    let root = tempfile::tempdir().unwrap();
    let console = root.path().join("console");
    std::fs::create_dir(&console).unwrap();
    std::fs::write(root.path().join("outside.txt"), "not for the web").unwrap();
    let dir = &console;
    if with_console {
        std::fs::write(dir.join("index.html"), INDEX).unwrap();
        std::fs::create_dir(dir.join("assets")).unwrap();
        std::fs::write(dir.join("assets/app.js"), "export const a = 1;").unwrap();
    }
    let (mqtt, _published, _status) = MqttHandle::for_test();
    let (shadows, _reports) = ShadowHandle::detached();
    let (router, _registrations) = RouterHandle::for_test();
    let web = Web {
        device: Device {
            shadows,
            router,
            mqtt,
            identity: None,
            thing_name: Some("t-1".into()),
            role: "transcoder".into(),
        },
        name: "pocket".into(),
        password_hash: auth::hash_password(PASSWORD.as_bytes()).unwrap(),
        console_dir: dir.clone(),
        sessions: Mutex::new(Sessions::default()),
        throttle: Mutex::new(Throttle::default()),
    };
    Site { web, _dir: root }
}

fn request(method: &str, path: &str) -> Request {
    let mut headers = HashMap::new();
    headers.insert("host".into(), "helios-pocket.local:8080".into());
    Request {
        method: method.into(),
        path: path.into(),
        query: Vec::new(),
        headers,
        body: Vec::new(),
        peer: Some(IpAddr::from([192, 168, 5, 50])),
    }
}

fn write(method: &str, path: &str, body: &Value) -> Request {
    let mut request = request(method, path);
    request
        .headers
        .insert("x-helios-request".into(), "1".into());
    request
        .headers
        .insert("origin".into(), "http://helios-pocket.local:8080".into());
    request.body = body.to_string().into_bytes();
    request
}

fn body(response: &Response) -> Value {
    serde_json::from_slice(&response.body).unwrap_or(Value::Null)
}

/// Signs in and returns the session cookie (`helios-session=<id>`).
async fn sign_in(site: &Site) -> String {
    let response = serve(
        &site.web,
        &write("POST", "/v1/local/session", &json!({"password": PASSWORD})),
    )
    .await;
    assert_eq!(response.status, 204);
    let cookie = response.header_value("set-cookie").unwrap();
    assert!(
        cookie.contains("HttpOnly") && cookie.contains("SameSite=Strict"),
        "{cookie}"
    );
    assert!(!cookie.contains("Secure"), "plain HTTP: no Secure");
    cookie.split(';').next().unwrap().to_owned()
}

#[tokio::test]
async fn serves_the_console_and_its_routes_with_its_headers() {
    let site = site(true);
    let index = serve(&site.web, &request("GET", "/")).await;
    assert_eq!(index.status, 200);
    assert_eq!(index.body, INDEX.as_bytes());
    assert_eq!(
        index.header_value("content-type"),
        Some("text/html; charset=utf-8")
    );
    assert_eq!(index.header_value("cache-control"), Some("no-cache"));
    let csp = index.header_value("content-security-policy").unwrap();
    assert_eq!(csp, content_security_policy(&inline_script_hashes(INDEX)));
    assert!(csp.contains("'sha256-"), "{csp}");
    assert_eq!(index.header_value("x-frame-options"), Some("DENY"));
    assert_eq!(index.header_value("referrer-policy"), Some("no-referrer"));
    assert_eq!(index.header_value("strict-transport-security"), None);

    let asset = serve(&site.web, &request("GET", "/assets/app.js")).await;
    assert_eq!(asset.body, b"export const a = 1;");
    assert_eq!(
        asset.header_value("cache-control"),
        Some("public, max-age=31536000, immutable")
    );
    assert_eq!(
        asset.header_value("content-type"),
        Some("text/javascript; charset=utf-8")
    );

    // The app's own routes, and anything not a file, get index.html; nothing outside the folder.
    for path in [
        "/devices/t-1",
        "/assets/missing.js",
        "/../outside.txt",
        "/assets/../../outside.txt",
    ] {
        let response = serve(&site.web, &request("GET", path)).await;
        assert_eq!(
            (response.status, response.body.as_slice()),
            (200, INDEX.as_bytes()),
            "{path}"
        );
    }

    let config = serve(&site.web, &request("GET", "/config.json")).await;
    assert_eq!(
        body(&config),
        json!({"apiUrl": "", "auth": {"kind": "device"}, "name": "pocket"})
    );

    let missing = site_without_console().await;
    assert_eq!(missing.status, 503);
}

async fn site_without_console() -> Response {
    let site = site(false);
    serve(&site.web, &request("GET", "/")).await
}

#[test]
fn hashes_only_inline_scripts() {
    let html = "<script src=\"/a.js\"></script><SCRIPT>one()</SCRIPT><script type=\"module\">two()</script><script>one()</script><script></script>";
    let hashes = inline_script_hashes(html);
    assert_eq!(hashes.len(), 2, "{hashes:?}");
    assert!(
        hashes
            .iter()
            .all(|h| h.starts_with("'sha256-") && h.ends_with('\''))
    );
}

#[tokio::test]
async fn signs_in_with_the_device_password_and_slows_wrong_guesses() {
    let site = site(true);
    let wrong = serve(
        &site.web,
        &write("POST", "/v1/local/session", &json!({"password": "nope"})),
    )
    .await;
    assert_eq!(wrong.status, 401);
    assert_eq!(wrong.header_value("set-cookie"), None);
    // Straight after a wrong one, even the right password waits.
    let waiting = serve(
        &site.web,
        &write("POST", "/v1/local/session", &json!({"password": PASSWORD})),
    )
    .await;
    assert_eq!(waiting.status, 429);
    assert_eq!(waiting.header_value("retry-after"), Some("1"));
    tokio::time::sleep(std::time::Duration::from_millis(1100)).await;
    let cookie = sign_in(&site).await;

    let mut check = request("GET", "/v1/local/session");
    check
        .headers
        .insert("cookie".into(), format!("theme=dark; {cookie}"));
    let checked = serve(&site.web, &check).await;
    assert_eq!(body(&checked), json!({"signedIn": true, "name": "pocket"}));

    let bad = serve(
        &site.web,
        &write("POST", "/v1/local/session", &json!({"pw": 1})),
    )
    .await;
    assert_eq!(bad.status, 400);
}

#[tokio::test]
async fn keeps_the_api_behind_a_session_and_writes_behind_the_consoles_header() {
    let site = site(true);
    let api = serve(&site.web, &request("GET", "/v1/control/devices")).await;
    assert_eq!(
        (api.status, api.header_value("x-amzn-errortype")),
        (401, Some("Unauthorized"))
    );

    let cookie = sign_in(&site).await;
    let mut list = request("GET", "/v1/control/devices");
    list.headers.insert("cookie".into(), cookie.clone());
    let listed = serve(&site.web, &list).await;
    assert_eq!(listed.status, 200);
    assert_eq!(body(&listed)["devices"][0]["deviceId"], "t-1");

    // A write without the console's header, or from another page, is refused before anything.
    let mut bare = request("POST", "/v1/control/devices/t-1/streams/pocket/start");
    bare.headers.insert("cookie".into(), cookie.clone());
    assert_eq!(serve(&site.web, &bare).await.status, 403);
    let mut foreign = write(
        "POST",
        "/v1/control/devices/t-1/streams/pocket/start",
        &json!({}),
    );
    foreign.headers.insert("cookie".into(), cookie.clone());
    foreign
        .headers
        .insert("origin".into(), "http://evil.example".into());
    assert_eq!(serve(&site.web, &foreign).await.status, 403);
    let mut garbled = write(
        "PATCH",
        "/v1/control/devices/t-1/streams/pocket",
        &json!({}),
    );
    garbled.headers.insert("cookie".into(), cookie.clone());
    garbled.body = b"{not json".to_vec();
    assert_eq!(serve(&site.web, &garbled).await.status, 400);
    // Signing in itself needs the header too.
    let mut cross = request("POST", "/v1/local/session");
    cross.body = json!({"password": PASSWORD}).to_string().into_bytes();
    assert_eq!(serve(&site.web, &cross).await.status, 403);

    // Signing out ends the session.
    let mut out = request("DELETE", "/v1/local/session");
    out.headers.insert("cookie".into(), cookie.clone());
    let signed_out = serve(&site.web, &out).await;
    assert_eq!(signed_out.status, 204);
    assert!(
        signed_out
            .header_value("set-cookie")
            .unwrap()
            .contains("Max-Age=0")
    );
    assert_eq!(serve(&site.web, &list).await.status, 401);
}
