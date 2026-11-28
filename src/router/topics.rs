//! The custom-topics command transport (LLD 2, section 7.2): commands on
//! `helios/<thing>/cmd/<module>` and responses on `helios/<thing>/rsp/<module>`, both in the
//! message envelope (section 3).

use std::time::SystemTime;

use serde_json::{Value, json};

use crate::mqtt::envelope::{self, Envelope, ErrorBody, Status, VERSION};
use crate::router::{Command, CommandTransport, InvalidCommand, Outcome, Publish, codes};

/// Commands and responses on Helios's own topics, in the envelope.
#[derive(Debug, Default, Clone, Copy)]
pub struct TopicsTransport;

impl CommandTransport for TopicsTransport {
    fn subscriptions(&self, thing: &str) -> Vec<String> {
        vec![format!("helios/{thing}/cmd/+")]
    }

    fn decode(
        &self,
        thing: &str,
        topic: &str,
        payload: &[u8],
    ) -> Option<Result<Command, InvalidCommand>> {
        let module = topic
            .strip_prefix("helios/")?
            .strip_prefix(thing)?
            .strip_prefix("/cmd/")?;
        if module.is_empty() || module.contains('/') {
            return None;
        }
        Some(decode(thing, module, payload))
    }

    fn encode(&self, thing: &str, command: &Command, outcome: &Outcome) -> Publish {
        let now = SystemTime::now();
        let (status, payload, error) = match outcome {
            Outcome::Ok(result) => (Status::Ok, result.clone(), None),
            Outcome::Err { code, message } => (
                if code == codes::TIMEOUT {
                    Status::Timeout
                } else {
                    Status::Error
                },
                json!({}),
                Some(ErrorBody {
                    code: code.clone(),
                    message: message.clone(),
                }),
            ),
        };
        let response = Envelope {
            v: VERSION,
            id: crate::ulid::new(now),
            correlation_id: Some(command.id.clone()),
            ts: envelope::timestamp(now),
            thing: thing.to_owned(),
            module: command.module.clone(),
            kind: format!("{}.{}", command.module, command.name),
            payload,
            status: Some(status),
            error,
        };
        Publish {
            topic: format!("helios/{thing}/rsp/{}", command.module),
            payload: response.to_bytes(),
        }
    }
}

/// Decodes a command for `module`, checking the envelope (LLD 2, sections 3 and 7.2).
fn decode(thing: &str, module: &str, payload: &[u8]) -> Result<Command, InvalidCommand> {
    let json: Value = serde_json::from_slice(payload).map_err(|e| InvalidCommand {
        reason: format!("not JSON: {e}"),
        partial: None,
    })?;
    // Answerable once there's an id; the name may be a placeholder until the type is checked.
    let id = json["id"]
        .as_str()
        .filter(|id| !id.is_empty())
        .map(str::to_owned);
    let invalid = |reason: String, name: &str| InvalidCommand {
        reason,
        partial: id.clone().map(|id| {
            Box::new(Command {
                id,
                module: module.to_owned(),
                name: name.to_owned(),
                args: Value::Null,
                deadline: None,
                local: false,
            })
        }),
    };
    let envelope: Envelope = serde_json::from_value(json.clone())
        .map_err(|e| invalid(format!("not an envelope: {e}"), "invalid"))?;
    let name = envelope
        .kind
        .strip_prefix(module)
        .and_then(|rest| rest.strip_prefix('.'))
        .filter(|name| !name.is_empty())
        .map(str::to_owned);
    let Some(name) = name else {
        return Err(invalid(
            format!(
                "type {:?} isn't <module>.<name> for module {module:?}",
                envelope.kind
            ),
            "invalid",
        ));
    };
    if envelope.v != VERSION {
        return Err(invalid(
            format!("envelope version {} isn't {VERSION}", envelope.v),
            &name,
        ));
    }
    if envelope.id.is_empty() {
        return Err(invalid("id is empty".to_owned(), &name));
    }
    if envelope.thing != thing {
        return Err(invalid(
            format!("thing {:?} isn't {thing:?}", envelope.thing),
            &name,
        ));
    }
    if envelope.module != module {
        return Err(invalid(
            format!("module {:?} doesn't match the topic", envelope.module),
            &name,
        ));
    }
    let deadline = match envelope.payload.get("deadline") {
        None | Some(Value::Null) => None,
        Some(Value::String(text)) => Some(
            envelope::parse_timestamp(text)
                .ok_or_else(|| invalid(format!("deadline {text:?} isn't RFC 3339 UTC"), &name))?,
        ),
        Some(other) => return Err(invalid(format!("deadline {other} isn't a string"), &name)),
    };
    Ok(Command {
        id: envelope.id,
        module: module.to_owned(),
        name,
        args: envelope.payload,
        deadline,
        local: false,
    })
}

#[cfg(test)]
mod tests {
    use std::time::{Duration, UNIX_EPOCH};

    use super::*;

    const THING: &str = "t-1";
    const TOPIC: &str = "helios/t-1/cmd/video";

    fn command(overrides: Value) -> Vec<u8> {
        let mut json = json!({
            "v": 1, "id": "01CMD", "correlation_id": null, "ts": "2026-11-21T05:00:00.000Z",
            "thing": THING, "module": "video", "type": "video.stream.start",
            "payload": {"stream": "main"}
        });
        for (key, value) in overrides.as_object().unwrap() {
            json[key] = value.clone();
        }
        json.to_string().into_bytes()
    }

    #[test]
    fn subscribes_to_its_command_topics() {
        assert_eq!(TopicsTransport.subscriptions(THING), ["helios/t-1/cmd/+"]);
    }

    #[test]
    fn decodes_a_command() {
        let command = TopicsTransport
            .decode(THING, TOPIC, &command(json!({})))
            .unwrap()
            .unwrap();

        assert_eq!(command.id, "01CMD");
        assert_eq!(command.module, "video");
        assert_eq!(command.name, "stream.start");
        assert_eq!(command.args["stream"], "main");
        assert_eq!(command.deadline, None);
    }

    #[test]
    fn reads_a_deadline() {
        let payload = command(json!({"payload": {"deadline": "2026-11-21T05:00:30.000Z"}}));

        let command = TopicsTransport
            .decode(THING, TOPIC, &payload)
            .unwrap()
            .unwrap();

        assert_eq!(
            command.deadline,
            Some(UNIX_EPOCH + Duration::from_secs(1_795_237_230))
        );
    }

    #[test]
    fn ignores_topics_it_doesnt_own() {
        for topic in [
            "helios/t-2/cmd/video",
            "helios/t-1/evt/video",
            "helios/t-1/cmd/",
            "helios/t-1/cmd/video/extra",
            "$aws/things/t-1/shadow/name/video/update/delta",
        ] {
            assert!(
                TopicsTransport.decode(THING, topic, b"{}").is_none(),
                "{topic}"
            );
        }
    }

    #[test]
    fn rejects_invalid_commands_and_answers_those_with_an_id() {
        for (overrides, reason) in [
            (json!({"v": 2}), "version"),
            (json!({"thing": "t-2"}), "thing"),
            (json!({"module": "usb"}), "module"),
            (json!({"type": "usb.attach"}), "type"),
            (json!({"type": "video."}), "type"),
            (json!({"payload": {"deadline": "soon"}}), "deadline"),
            (json!({"payload": {"deadline": 5}}), "deadline"),
            (json!({"ts": 5}), "envelope"),
        ] {
            let invalid = TopicsTransport
                .decode(THING, TOPIC, &command(overrides.clone()))
                .unwrap()
                .unwrap_err();

            assert!(
                invalid.reason.contains(reason),
                "{overrides}: {}",
                invalid.reason
            );
            assert_eq!(invalid.partial.unwrap().id, "01CMD", "{overrides}");
        }
    }

    #[test]
    fn cant_answer_commands_without_an_id() {
        let not_json = TopicsTransport
            .decode(THING, TOPIC, b"nope")
            .unwrap()
            .unwrap_err();
        let no_id = TopicsTransport
            .decode(THING, TOPIC, &command(json!({"id": ""})))
            .unwrap()
            .unwrap_err();

        assert!(not_json.partial.is_none());
        assert!(no_id.partial.is_none());
    }

    fn decoded() -> Command {
        TopicsTransport
            .decode(THING, TOPIC, &command(json!({})))
            .unwrap()
            .unwrap()
    }

    #[test]
    fn encodes_a_success() {
        let publish = TopicsTransport.encode(THING, &decoded(), &Outcome::Ok(json!({"ok": 1})));

        assert_eq!(publish.topic, "helios/t-1/rsp/video");
        let response: Envelope = serde_json::from_slice(&publish.payload).unwrap();
        assert_eq!(response.correlation_id.as_deref(), Some("01CMD"));
        assert_eq!(response.kind, "video.stream.start");
        assert_eq!(response.status, Some(Status::Ok));
        assert_eq!(response.payload, json!({"ok": 1}));
        assert_eq!(response.error, None);
        assert_ne!(response.id, "01CMD");
    }

    #[test]
    fn encodes_errors_and_timeouts() {
        let error = TopicsTransport.encode(
            THING,
            &decoded(),
            &Outcome::error(codes::UNKNOWN_COMMAND, "no such command"),
        );
        let timeout =
            TopicsTransport.encode(THING, &decoded(), &Outcome::error(codes::TIMEOUT, "late"));

        let error: Envelope = serde_json::from_slice(&error.payload).unwrap();
        assert_eq!(error.status, Some(Status::Error));
        assert_eq!(error.error.unwrap().code, "UNKNOWN_COMMAND");
        let timeout: Envelope = serde_json::from_slice(&timeout.payload).unwrap();
        assert_eq!(timeout.status, Some(Status::Timeout));
    }
}
