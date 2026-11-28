use super::*;

const THING: &str = "t-1";
const REQUEST: &str = "$aws/commands/things/t-1/executions/exec-1/request/json";

fn request(args: &Value) -> Vec<u8> {
    json!({
        "module": "net",
        "name": "wifi.set",
        "timeout_s": 10,
        "args": STANDARD.encode(args.to_string()),
    })
    .to_string()
    .into_bytes()
}

#[test]
fn subscribes_to_requests_and_aws_replies() {
    assert_eq!(
        AwsCommandsTransport.subscriptions(THING),
        [
            "$aws/commands/things/t-1/executions/+/request/json",
            "$aws/commands/things/t-1/executions/+/response/accepted/json",
            "$aws/commands/things/t-1/executions/+/response/rejected/json",
        ]
    );
}

#[test]
fn decodes_a_request() {
    let args = json!({"ssid": "Venue / Media \"Main\"", "hidden": true});
    let before = SystemTime::now();
    let command = AwsCommandsTransport
        .decode(THING, REQUEST, &request(&args))
        .unwrap()
        .unwrap();
    assert_eq!(command.id, "exec-1");
    assert_eq!(command.module, "net");
    assert_eq!(command.name, "wifi.set");
    assert_eq!(command.args, args);
    let window = command.deadline.unwrap().duration_since(before).unwrap();
    assert!(
        window > Duration::from_secs(7) && window <= Duration::from_secs(9),
        "{window:?}"
    );

    // No timeout: no deadline. Short ones still get a second. No args: empty.
    let bare = br#"{"module": "net", "name": "wifi.list"}"#;
    let command = AwsCommandsTransport
        .decode(THING, REQUEST, bare)
        .unwrap()
        .unwrap();
    assert_eq!(command.deadline, None);
    assert_eq!(command.args, json!({}));
    let short = br#"{"module": "net", "name": "wifi.list", "timeout_s": 1, "args": ""}"#;
    let command = AwsCommandsTransport
        .decode(THING, REQUEST, short)
        .unwrap()
        .unwrap();
    assert!(command.deadline.unwrap() > SystemTime::now());
    // AWS's template gives the timeout as a string.
    let quoted = br#"{"module": "net", "name": "wifi.list", "timeout_s": "10"}"#;
    let command = AwsCommandsTransport
        .decode(THING, REQUEST, quoted)
        .unwrap()
        .unwrap();
    assert!(command.deadline.unwrap() > SystemTime::now() + Duration::from_secs(7));
    // Unpadded base64url works too.
    let url = json!({"module": "net", "name": "wifi.set", "args": URL_SAFE_NO_PAD.encode(b"{\"ssid\":\"~?~\"}")});
    let command = AwsCommandsTransport
        .decode(THING, REQUEST, url.to_string().as_bytes())
        .unwrap()
        .unwrap();
    assert_eq!(command.args, json!({"ssid": "~?~"}));
}

#[test]
fn a_bad_request_is_answered_by_its_execution() {
    for (payload, reason) in [
        (b"not json".to_vec(), "not a Helios command request"),
        (
            br#"{"module": "", "name": "x"}"#.to_vec(),
            "must not be empty",
        ),
        (
            br#"{"module": "net", "name": "x", "timeout_s": "soon"}"#.to_vec(),
            "isn't a number of seconds",
        ),
        (
            br#"{"module": "net", "name": "x", "timeout_s": -1}"#.to_vec(),
            "isn't a number of seconds",
        ),
        (
            br#"{"module": "net", "name": "x", "timeout_s": []}"#.to_vec(),
            "isn't a number of seconds",
        ),
        (
            br#"{"module": "net", "name": "x", "args": "***"}"#.to_vec(),
            "isn't base64",
        ),
        (
            json!({"module": "net", "name": "x", "args": STANDARD.encode("nope")})
                .to_string()
                .into_bytes(),
            "isn't base64 of JSON",
        ),
        (
            json!({"module": "net", "name": "x", "args": STANDARD.encode("[1]")})
                .to_string()
                .into_bytes(),
            "must be a JSON object",
        ),
    ] {
        let invalid = AwsCommandsTransport
            .decode(THING, REQUEST, &payload)
            .unwrap()
            .unwrap_err();
        assert!(invalid.reason.contains(reason), "{}", invalid.reason);
        assert_eq!(invalid.partial.unwrap().id, "exec-1");
    }
}

#[test]
fn ignores_topics_it_doesnt_own() {
    for topic in [
        "helios/t-1/cmd/net",
        "$aws/commands/things/t-2/executions/exec-1/request/json",
        "$aws/commands/things/t-1/executions//request/json",
        "$aws/commands/things/t-1/executions/exec-1",
        "$aws/commands/things/t-1/executions/exec-1/request/cbor",
        "$aws/commands/things/t-1/executions/exec-1/response/accepted/json",
        "$aws/commands/things/t-1/executions/exec-1/response/rejected/json",
    ] {
        assert!(
            AwsCommandsTransport.decode(THING, topic, b"{}").is_none(),
            "{topic}"
        );
    }
}

fn command() -> Command {
    Command {
        id: "exec-1".into(),
        module: "net".into(),
        name: "wifi.set".into(),
        args: json!({}),
        deadline: None,
    }
}

fn body(publish: &Publish) -> Value {
    serde_json::from_slice(&publish.payload).unwrap()
}

#[test]
fn encodes_answers_as_aws_expects() {
    let ok = AwsCommandsTransport.encode(
        THING,
        &command(),
        &Outcome::Ok(json!({"network": {"ssid": "Home"}})),
    );
    assert_eq!(
        ok.topic,
        "$aws/commands/things/t-1/executions/exec-1/response/json"
    );
    assert_eq!(
        body(&ok),
        json!({"status": "SUCCEEDED", "result": {"json": {"s": "{\"network\":{\"ssid\":\"Home\"}}"}}})
    );
    for (code, status) in [
        ("UNKNOWN_COMMAND", "REJECTED"),
        ("INVALID_MESSAGE", "REJECTED"),
        ("TIMEOUT", "TIMED_OUT"),
        ("TOO_MANY", "FAILED"),
    ] {
        let failed = AwsCommandsTransport.encode(
            THING,
            &command(),
            &Outcome::error(code, "line one\nline two"),
        );
        let body = body(&failed);
        assert_eq!(body["status"], status);
        assert_eq!(body["statusReason"]["reasonCode"], code);
        assert_eq!(
            body["statusReason"]["reasonDescription"],
            "line one line two"
        );
    }
    assert_eq!(reason_code("bad code!"), "BADCODE");
    assert_eq!(reason_code("!!!"), "INTERNAL");
    assert_eq!(reason_code(&"A".repeat(100)).len(), 64);
    assert_eq!(description(&"x".repeat(2000)).len(), 1024);
}
