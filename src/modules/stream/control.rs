//! The stream daemon's control protocol (LLD 4, section 15): newline-delimited JSON-RPC 2.0 over
//! a Unix socket, between Helios (the client) and `helios stream-daemon`.
//!
//! Helios → daemon requests: `hello`, `command` (`{name, args}`), `desired` (`{state}`),
//! `uplinks` (`{interfaces: {name: {kind, metric, public_ipv4}}}`, the net module's view for
//! standby, LLD 3 section 3.5.1).
//! Daemon → Helios notifications: `event` (`{kind, payload, at}`) and `shadow` (`{reported}`).

use serde_json::{Value, json};

use crate::router::{Outcome, codes};

/// JSON-RPC's code for an application error; the command's own code is in `data.code`.
const APPLICATION_ERROR: i64 = -32000;

/// A request line.
pub(crate) fn request(id: u64, method: &str, params: Value) -> String {
    format!(
        "{}\n",
        json!({"jsonrpc": "2.0", "id": id, "method": method, "params": params})
    )
}

/// A notification line (no reply expected).
pub(crate) fn notification(method: &str, params: Value) -> String {
    format!(
        "{}\n",
        json!({"jsonrpc": "2.0", "method": method, "params": params})
    )
}

/// A response line for `outcome`.
pub(crate) fn response(id: &Value, outcome: Outcome) -> String {
    let message = match outcome {
        Outcome::Ok(result) => json!({"jsonrpc": "2.0", "id": id, "result": result}),
        Outcome::Err { code, message } => json!({
            "jsonrpc": "2.0", "id": id,
            "error": {"code": APPLICATION_ERROR, "message": message, "data": {"code": code}},
        }),
    };
    format!("{message}\n")
}

/// A parsed line.
#[derive(Debug, Clone, PartialEq)]
pub(crate) enum Message {
    Request {
        id: Value,
        method: String,
        params: Value,
    },
    Notification {
        method: String,
        params: Value,
    },
    Response {
        id: u64,
        outcome: Outcome,
    },
}

/// Parses one line; `None` for anything that isn't JSON-RPC 2.0.
pub(crate) fn parse(line: &str) -> Option<Message> {
    let message: Value = serde_json::from_str(line).ok()?;
    if message.get("jsonrpc")? != "2.0" {
        return None;
    }
    let params = message.get("params").cloned().unwrap_or(Value::Null);
    match (
        message.get("method").and_then(Value::as_str),
        message.get("id"),
    ) {
        (Some(method), Some(id)) => Some(Message::Request {
            id: id.clone(),
            method: method.to_owned(),
            params,
        }),
        (Some(method), None) => Some(Message::Notification {
            method: method.to_owned(),
            params,
        }),
        (None, Some(id)) => {
            let id = id.as_u64()?;
            let outcome = match (message.get("result"), message.get("error")) {
                (Some(result), _) => Outcome::Ok(result.clone()),
                (None, Some(error)) => Outcome::error(
                    error["data"]["code"].as_str().unwrap_or(codes::INTERNAL),
                    error["message"].as_str().unwrap_or("stream daemon error"),
                ),
                (None, None) => return None,
            };
            Some(Message::Response { id, outcome })
        }
        (None, None) => None,
    }
}
