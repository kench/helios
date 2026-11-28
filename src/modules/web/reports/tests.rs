//! The contract's report vectors (helios-contract `test-vectors/control-reports-v1.json`): the
//! cloud answers them from the shadows (helios-cloud's `ReportVectorsTest`), and Helios must
//! answer them the same way from the modules' reports.

use serde_json::{Value, json};

use super::{Read, Reports, answer, instant};

fn vectors() -> Vec<Value> {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("contract/test-vectors/control-reports-v1.json");
    let text = std::fs::read_to_string(&path).unwrap_or_else(|e| {
        panic!(
            "{}: {e} (is the contract submodule checked out?)",
            path.display()
        )
    });
    let file: Value = serde_json::from_str(&text).unwrap();
    file["cases"].as_array().unwrap().clone()
}

/// The read a vector's request is.
fn read_of(request: &Value) -> Read {
    let path = request["path"].as_str().unwrap();
    let suffix = path.strip_prefix("/v1/control/devices/{deviceId}").unwrap();
    match suffix {
        "/streams" => Read::ListStreams,
        "/streams/{streamId}" => {
            Read::GetStream(request["params"]["streamId"].as_str().unwrap().to_owned())
        }
        "/inputs" => Read::ListInputs,
        "/profiles" => Read::ListProfiles,
        "/uplinks" => Read::GetUplinks {
            public_addresses: false,
        },
        "/location" => Read::GetLocation,
        "/wifi/networks" => Read::ListWifi,
        other => panic!("no read for {other}"),
    }
}

/// JSON equality with numbers compared by value: Java writes a float 30 as `30.0`, Rust as `30`.
fn same(a: &Value, b: &Value) -> bool {
    match (a, b) {
        (Value::Number(x), Value::Number(y)) => x.as_f64() == y.as_f64(),
        (Value::Array(x), Value::Array(y)) => {
            x.len() == y.len() && x.iter().zip(y).all(|(p, q)| same(p, q))
        }
        (Value::Object(x), Value::Object(y)) => {
            x.len() == y.len() && x.iter().all(|(k, v)| y.get(k).is_some_and(|w| same(v, w)))
        }
        _ => a == b,
    }
}

#[test]
fn answers_every_report_vector_as_the_cloud_does() {
    let cases = vectors();
    assert!(!cases.is_empty(), "no report vectors");
    let mut failures = Vec::new();
    for case in &cases {
        let name = case["name"].as_str().unwrap();
        let reported = &case["reported"];
        let reports = Reports {
            stream: reported.get("stream"),
            net: reported.get("net"),
            gps: reported.get("gps"),
        };
        let expected = &case["response"];
        let status = expected["status"].as_u64().unwrap();
        match answer(reports, &read_of(&case["request"])) {
            Ok(body) => {
                if status != 200 {
                    failures.push(format!("{name}: answered 200, the vector says {status}"));
                } else if !same(&body, &expected["body"]) {
                    failures.push(format!(
                        "{name}: body differs\n  expected {}\n  answered {body}",
                        expected["body"]
                    ));
                }
            }
            Err(refusal) => {
                if u64::from(refusal.status) != status
                    || Some(refusal.error) != expected["errorType"].as_str()
                {
                    failures.push(format!(
                        "{name}: answered {} {}, the vector says {status} {}",
                        refusal.status, refusal.error, expected["errorType"]
                    ));
                }
                assert!(!refusal.message.is_empty(), "{name}: no message");
            }
        }
    }
    assert!(failures.is_empty(), "{}", failures.join("\n"));
}

#[test]
fn writes_instants_as_the_api_does() {
    for (input, written) in [
        ("2026-11-22T20:15:30.000Z", Some("2026-11-22T20:15:30Z")),
        ("2026-11-22T20:15:30Z", Some("2026-11-22T20:15:30Z")),
        ("2026-11-22T20:15:30.5Z", Some("2026-11-22T20:15:30.500Z")),
        (
            "2026-11-22T20:15:30.123456Z",
            Some("2026-11-22T20:15:30.123456Z"),
        ),
        (
            "2026-11-22T20:15:30.1234567Z",
            Some("2026-11-22T20:15:30.123456700Z"),
        ),
        ("2028-02-29T00:00:00Z", Some("2028-02-29T00:00:00Z")),
        ("2026-02-29T00:00:00Z", None),
        ("2026-11-22T24:00:00Z", None),
        ("2026-11-22T20:15:30+01:00", None),
        ("2026-11-22 20:15:30Z", None),
        ("2026-11-22T20:15:30.Z", None),
        ("yesterday", None),
    ] {
        assert_eq!(instant(input).as_deref(), written, "{input}");
    }
}

#[test]
fn shows_public_addresses_only_when_asked() {
    let net = json!({"interfaces": {
        "wwan0": {"kind": "cellular", "ipv4": ["10.64.12.9/30"],
                  "public_ipv4": {"address": "198.51.100.9", "checked_at": "2026-11-23T16:12:00Z"}},
        "wlan0": {"kind": "wifi", "ipv4": ["192.168.5.12/24"],
                  "public_ipv4": {"address": "198.51.100.9", "checked_at": "2026-11-23T16:12:00Z"}}
    }});
    let reports = Reports {
        net: Some(&net),
        ..Reports::default()
    };
    let hidden = answer(
        reports,
        &Read::GetUplinks {
            public_addresses: false,
        },
    )
    .unwrap();
    assert!(!hidden.to_string().contains("198.51.100.9"), "{hidden}");
    assert_eq!(
        hidden["uplinks"][0]["publicIpv4"]["sharesPublicAddressWith"],
        json!(["wwan0"])
    );
    let shown = answer(
        reports,
        &Read::GetUplinks {
            public_addresses: true,
        },
    )
    .unwrap();
    assert_eq!(shown["uplinks"][1]["publicIpv4"]["address"], "198.51.100.9");
}

#[test]
fn leaves_out_what_a_report_gets_wrong() {
    let stream = json!({"streams": {
        "a": {"desired": "live", "state": "flying", "since": "2026-11-22T20:15:30Z",
              "source": {"type": "test"}, "profile": "p", "destination": "srt://h:1",
              "bitrate_kbps": 1000},
        "b": {"desired": 7}
    }, "profiles": {"x": {"video": "libx264"}}, "inputs": [{"type": "camera"}, {"type": "test"}, null]});
    let reports = Reports {
        stream: Some(&stream),
        ..Reports::default()
    };
    let streams = answer(reports, &Read::ListStreams).unwrap();
    assert_eq!(
        streams,
        json!({"streams": [
            {"streamId": "a", "desired": {"state": "live"}, "pending": false},
            {"streamId": "b", "desired": {"state": "stopped"}, "pending": false}
        ]})
    );
    assert_eq!(
        answer(reports, &Read::ListProfiles).unwrap(),
        json!({"profiles": []})
    );
    assert_eq!(
        answer(reports, &Read::ListInputs).unwrap(),
        json!({"inputs": [{"test": {}}]})
    );
}
