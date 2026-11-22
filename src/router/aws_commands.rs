//! The AWS IoT commands transport (LLD 2, section 7.3): commands as AWS IoT Device Management
//! command executions, on `$aws/commands/things/<thing>/executions/<id>/request/json`, answered
//! on `…/executions/<id>/response/json`.
//!
//! Every Helios command resource in AWS has the same payload template, so the request is
//! `{"module": "net", "name": "wifi.set", "timeout_s": 10, "args": "<base64 of the arguments'
//! JSON>"}`: the module and name are fixed per resource, `timeout_s` is the execution's timeout,
//! and the arguments are base64 so no string in them needs escaping in AWS's template. The
//! command's id is the execution id, and its deadline is the timeout, counted from receipt,
//! less a margin: AWS doesn't queue commands for a clean session, so receipt is within moments
//! of the start.

use std::time::{Duration, SystemTime};

use base64::Engine;
use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use serde::Deserialize;
use serde_json::{Value, json};

use crate::router::{Command, CommandTransport, InvalidCommand, Outcome, Publish, codes};

/// How much of the execution's timeout is left for the answer to reach AWS.
const MARGIN: Duration = Duration::from_secs(2);
/// The shortest deadline a command gets, whatever its timeout.
const MIN_DEADLINE: Duration = Duration::from_secs(1);
/// AWS's limit on `statusReason.reasonDescription`.
const MAX_DESCRIPTION: usize = 1024;
/// AWS's limit on `statusReason.reasonCode`.
const MAX_CODE: usize = 64;

/// Commands as AWS IoT command executions.
#[derive(Debug, Default, Clone, Copy)]
pub struct AwsCommandsTransport;

fn executions(thing: &str) -> String {
    format!("$aws/commands/things/{thing}/executions/")
}

/// The request payload the command resources' template makes.
#[derive(Debug, Deserialize)]
struct Request {
    module: String,
    name: String,
    timeout_s: Option<u64>,
    args: Option<String>,
}

impl CommandTransport for AwsCommandsTransport {
    fn subscriptions(&self, thing: &str) -> Vec<String> {
        let base = executions(thing);
        vec![
            format!("{base}+/request/json"),
            format!("{base}+/response/accepted/json"),
            format!("{base}+/response/rejected/json"),
        ]
    }

    fn decode(
        &self,
        thing: &str,
        topic: &str,
        payload: &[u8],
    ) -> Option<Result<Command, InvalidCommand>> {
        let rest = topic.strip_prefix(&executions(thing))?;
        let (id, kind) = rest.split_once('/')?;
        if id.is_empty() {
            return None;
        }
        match kind {
            "request/json" => Some(decode(id, payload)),
            "response/accepted/json" => {
                tracing::debug!(execution = %id, "AWS IoT accepted the command response");
                None
            }
            "response/rejected/json" => {
                tracing::warn!(
                    execution = %id,
                    reply = %String::from_utf8_lossy(payload),
                    "AWS IoT rejected the command response"
                );
                None
            }
            _ => None,
        }
    }

    fn encode(&self, thing: &str, command: &Command, outcome: &Outcome) -> Publish {
        let body = match outcome {
            Outcome::Ok(result) => json!({
                "status": "SUCCEEDED",
                "result": {"json": {"s": result.to_string()}},
            }),
            Outcome::Err { code, message } => json!({
                "status": status_for(code),
                "statusReason": {
                    "reasonCode": reason_code(code),
                    "reasonDescription": description(message),
                },
            }),
        };
        Publish {
            topic: format!("{}{}/response/json", executions(thing), command.id),
            payload: body.to_string().into_bytes(),
        }
    }
}

fn decode(id: &str, payload: &[u8]) -> Result<Command, InvalidCommand> {
    // Answerable with the execution id even when the payload is wrong.
    let invalid = |reason: String| InvalidCommand {
        reason,
        partial: Some(Box::new(Command {
            id: id.to_owned(),
            module: String::new(),
            name: "invalid".to_owned(),
            args: Value::Null,
            deadline: None,
        })),
    };
    let request: Request = serde_json::from_slice(payload).map_err(|error| {
        invalid(format!(
            "not a Helios command request: line {}, column {}",
            error.line(),
            error.column()
        ))
    })?;
    if request.module.is_empty() || request.name.is_empty() {
        return Err(invalid("module and name must not be empty".into()));
    }
    let args = match request.args.as_deref() {
        None | Some("") => Value::Object(serde_json::Map::new()),
        Some(encoded) => {
            let bytes = STANDARD
                .decode(encoded)
                .or_else(|_| URL_SAFE_NO_PAD.decode(encoded))
                .map_err(|_| invalid("args isn't base64".into()))?;
            let args: Value = serde_json::from_slice(&bytes)
                .map_err(|_| invalid("args isn't base64 of JSON".into()))?;
            if !args.is_object() {
                return Err(invalid("args must be a JSON object".into()));
            }
            args
        }
    };
    let deadline = request.timeout_s.map(|seconds| {
        let window = Duration::from_secs(seconds)
            .saturating_sub(MARGIN)
            .max(MIN_DEADLINE);
        SystemTime::now() + window
    });
    Ok(Command {
        id: id.to_owned(),
        module: request.module,
        name: request.name,
        args,
        deadline,
    })
}

/// `REJECTED` for a command Helios can't take at all, `TIMED_OUT` for one past its deadline,
/// `FAILED` otherwise.
fn status_for(code: &str) -> &'static str {
    match code {
        codes::UNKNOWN_COMMAND | codes::INVALID_MESSAGE => "REJECTED",
        codes::TIMEOUT => "TIMED_OUT",
        _ => "FAILED",
    }
}

/// AWS allows `[A-Z0-9_-]{1,64}`; Helios's codes already are, but make sure.
fn reason_code(code: &str) -> String {
    let code: String = code
        .chars()
        .map(|c| c.to_ascii_uppercase())
        .filter(|c| c.is_ascii_uppercase() || c.is_ascii_digit() || *c == '_' || *c == '-')
        .take(MAX_CODE)
        .collect();
    if code.is_empty() {
        codes::INTERNAL.to_owned()
    } else {
        code
    }
}

/// At most 1,024 characters, without control characters.
fn description(message: &str) -> String {
    message
        .chars()
        .map(|c| if c.is_control() { ' ' } else { c })
        .take(MAX_DESCRIPTION)
        .collect()
}

/// Several transports at once (LLD 2, section 7.3): each publish goes to the first that owns its
/// topic, and a command's answer goes back through the transport that decoded it.
#[derive(Debug)]
pub struct Transports {
    transports: Vec<std::sync::Arc<dyn CommandTransport>>,
    /// Which transport decoded each command still unanswered, by id.
    origins: std::sync::Mutex<std::collections::HashMap<String, usize>>,
}

/// More unanswered commands than this means something leaked; the oldest are forgotten.
const MAX_ORIGINS: usize = 1024;

impl Transports {
    /// The transports, tried in order. At least one.
    #[must_use]
    pub fn new(transports: Vec<std::sync::Arc<dyn CommandTransport>>) -> Self {
        Self {
            transports,
            origins: std::sync::Mutex::default(),
        }
    }

    fn origins(&self) -> std::sync::MutexGuard<'_, std::collections::HashMap<String, usize>> {
        self.origins
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }
}

impl CommandTransport for Transports {
    fn subscriptions(&self, thing: &str) -> Vec<String> {
        self.transports
            .iter()
            .flat_map(|transport| transport.subscriptions(thing))
            .collect()
    }

    fn decode(
        &self,
        thing: &str,
        topic: &str,
        payload: &[u8],
    ) -> Option<Result<Command, InvalidCommand>> {
        self.transports
            .iter()
            .enumerate()
            .find_map(|(index, transport)| {
                let decoded = transport.decode(thing, topic, payload)?;
                let id = match &decoded {
                    Ok(command) => Some(command.id.clone()),
                    Err(invalid) => invalid.partial.as_ref().map(|command| command.id.clone()),
                };
                if let Some(id) = id {
                    let mut origins = self.origins();
                    if origins.len() >= MAX_ORIGINS {
                        origins.clear();
                    }
                    origins.insert(id, index);
                }
                Some(decoded)
            })
    }

    fn encode(&self, thing: &str, command: &Command, outcome: &Outcome) -> Publish {
        let index = self.origins().remove(&command.id).unwrap_or(0);
        let transport = self
            .transports
            .get(index)
            .or_else(|| self.transports.first())
            .map(std::sync::Arc::clone);
        match transport {
            Some(transport) => transport.encode(thing, command, outcome),
            None => Publish {
                topic: String::new(),
                payload: Vec::new(),
            },
        }
    }
}

#[cfg(test)]
mod tests;
