//! The local Control API (LLD 13, section 3): the cloud's `/v1/control/...` paths and JSON, for
//! this one device. Reads come from the modules' latest reports ([`super::reports`]); writes
//! are the same commands the cloud sends, through the router ([`RouterHandle::dispatch`]), so
//! the modules check and apply them the same way. Errors are named as the cloud names them.
//!
//! Differences from the cloud, because nothing sits between this API and the device: a
//! destination and a Wi-Fi passphrase go to the device in the request's own words (the cloud
//! seals them), and nothing is kept beside the device, so a stream's `desired` is what the
//! device reports wanting.

use serde_json::{Map, Value, json};
use tokio::sync::watch;

use super::reports::{self, Read, Reports};
use crate::identity::manager::IdentityState;
use crate::mqtt::manager::MqttHandle;
use crate::mqtt::shadow::ShadowHandle;
use crate::router::{Command, Outcome, RouterHandle, codes};

/// A response: the HTTP status, the modeled error's name (`X-Amzn-Errortype`), and the body.
#[derive(Debug, Clone, PartialEq)]
pub(crate) struct Answer {
    pub status: u16,
    pub error: Option<&'static str>,
    pub body: Value,
}

impl Answer {
    fn ok(status: u16, body: Value) -> Self {
        Self {
            status,
            error: None,
            body,
        }
    }

    fn error(status: u16, error: &'static str, message: impl Into<String>) -> Self {
        Self {
            status,
            error: Some(error),
            body: json!({ "message": message.into() }),
        }
    }
}

/// What the local API reads from and writes to.
#[derive(Debug, Clone)]
pub(crate) struct Device {
    pub shadows: ShadowHandle,
    pub router: RouterHandle,
    pub mqtt: MqttHandle,
    pub identity: Option<watch::Receiver<IdentityState>>,
    /// The thing name from `helios.toml`, the device's ID when it hasn't bootstrapped.
    pub thing_name: Option<String>,
    /// `[modules.web] role`.
    pub role: String,
}

impl Device {
    /// The device's ID (from the bootstrap service) and thing name, as far as it knows them.
    fn ids(&self) -> (String, String) {
        let identity = self
            .identity
            .as_ref()
            .and_then(|watch| match &*watch.borrow() {
                IdentityState::Ready(identity) => Some(identity.device.clone()),
                _ => None,
            });
        let thing = identity
            .as_ref()
            .map(|device| device.thing_name.clone())
            .or_else(|| self.thing_name.clone())
            .unwrap_or_else(|| "helios".to_owned());
        let id = identity
            .and_then(|device| device.device_id)
            .unwrap_or_else(|| thing.clone());
        (id, thing)
    }

    fn summary(&self) -> Value {
        let (id, thing) = self.ids();
        json!({
            "deviceId": id,
            "thingName": thing,
            "role": self.role,
            "status": "active",
            "connected": self.mqtt.status().borrow().connected,
            "heliosVersion": env!("CARGO_PKG_VERSION"),
        })
    }

    async fn report(&self, shadow: &str) -> Option<Value> {
        self.shadows.latest(shadow).await.map(Value::Object)
    }
}

/// Answers one request on `/v1/control/...`. `body` is the request's JSON (`Null` if none).
pub(crate) async fn handle(
    device: &Device,
    method: &str,
    path: &str,
    query: &[(String, String)],
    body: &Value,
) -> Answer {
    let Some(rest) = path.strip_prefix("/v1/control/devices") else {
        return unknown();
    };
    if rest.is_empty() || rest == "/" {
        return match method {
            "GET" => Answer::ok(200, json!({ "devices": [device.summary()] })),
            _ => unknown(),
        };
    }
    let parts: Vec<&str> = rest.trim_start_matches('/').split('/').collect();
    let (id, thing) = device.ids();
    if parts[0] != id && parts[0] != thing {
        return Answer::error(404, "DeviceNotFound", format!("No device {}.", parts[0]));
    }
    match (method, &parts[1..]) {
        ("GET", []) => {
            let mut out = Map::new();
            out.insert("device".into(), device.summary());
            if let Some(helios) = device.report("helios").await {
                let modules: Map<String, Value> = helios
                    .get("modules")
                    .and_then(Value::as_object)
                    .into_iter()
                    .flatten()
                    .filter_map(|(name, status)| {
                        status
                            .get("state")
                            .and_then(Value::as_str)
                            .map(|state| (name.clone(), json!(state)))
                    })
                    .collect();
                out.insert("modules".into(), Value::Object(modules));
            }
            Answer::ok(200, Value::Object(out))
        }
        ("GET", ["streams"]) => read(device, Read::ListStreams).await,
        ("GET", ["streams", stream]) => read(device, Read::GetStream((*stream).to_owned())).await,
        ("GET", ["inputs"]) => read(device, Read::ListInputs).await,
        ("GET", ["profiles"]) => read(device, Read::ListProfiles).await,
        ("GET", ["location"]) => read(device, Read::GetLocation).await,
        ("GET", ["uplinks"]) => {
            let public_addresses = query
                .iter()
                .any(|(k, v)| k == "includePublicAddresses" && v == "true");
            read(device, Read::GetUplinks { public_addresses }).await
        }
        ("GET", ["wifi", "networks"]) => read(device, Read::ListWifi).await,
        ("POST", ["streams", stream, "start"]) => {
            stream_change(device, stream, "start", Map::new()).await
        }
        ("POST", ["streams", stream, "stop"]) => {
            stream_change(device, stream, "stop", Map::new()).await
        }
        ("PATCH", ["streams", stream]) => match update_args(body) {
            Ok(args) => stream_change(device, stream, "update", args).await,
            Err(message) => Answer::error(400, "ValidationException", message),
        },
        ("PUT", ["streams", stream, "destination"]) => {
            match body.get("url").and_then(Value::as_str) {
                Some(url) => {
                    let mut args = Map::new();
                    args.insert("destination".into(), json!({ "set": { "url": url } }));
                    stream_change(device, stream, "update", args).await
                }
                None => Answer::error(400, "ValidationException", "url is required"),
            }
        }
        ("PUT", ["wifi", "networks"]) => wifi_set(device, body).await,
        ("DELETE", ["wifi", "networks"]) => {
            match query.iter().find(|(k, _)| k == "ssid").map(|(_, v)| v) {
                Some(ssid) => wifi_remove(device, ssid).await,
                None => Answer::error(400, "ValidationException", "ssid is required"),
            }
        }
        _ => unknown(),
    }
}

fn unknown() -> Answer {
    Answer::error(404, "UnknownOperationException", "No such operation.")
}

async fn read(device: &Device, read: Read) -> Answer {
    let (stream, net, gps) = (
        device.report("stream").await,
        device.report("net").await,
        device.report("gps").await,
    );
    let reports = Reports {
        stream: stream.as_ref(),
        net: net.as_ref(),
        gps: gps.as_ref(),
    };
    match reports::answer(reports, &read) {
        Ok(body) => Answer::ok(200, body),
        Err(refusal) => Answer::error(refusal.status, refusal.error, refusal.message),
    }
}

/// UpdateStream's body as `stream.update` takes it: each setting `{"set": v}`, or the bitrate
/// `{"configured": {}}` for the profile's own. The device checks the values.
pub(crate) fn update_args(body: &Value) -> Result<Map<String, Value>, String> {
    let Some(body) = body.as_object() else {
        return Err("the body must be a JSON object".into());
    };
    let mut args = Map::new();
    for (name, value) in body {
        match name.as_str() {
            "source" => {
                let source = source_arg(value)?;
                args.insert("source".into(), json!({ "set": source }));
            }
            "profile" => {
                let profile = value.as_str().ok_or("profile must be a string")?;
                args.insert("profile".into(), json!({ "set": profile }));
            }
            "bitrate" => {
                let bitrate = match (value.get("overrideKbps"), value.get("profileDefault")) {
                    (Some(kbps), None) => json!({ "set": whole(kbps, "bitrate.overrideKbps")? }),
                    (None, Some(_)) => json!({ "configured": {} }),
                    _ => return Err("bitrate is {overrideKbps} or {profileDefault}".into()),
                };
                args.insert("bitrate".into(), bitrate);
            }
            "sourceCeilingPercent" => {
                let percent = whole(value, "sourceCeilingPercent")?;
                args.insert("source_ceiling_percent".into(), json!({ "set": percent }));
            }
            "record" => {
                let record = value.as_bool().ok_or("record must be true or false")?;
                args.insert("record".into(), json!({ "set": record }));
            }
            // Makes a change safe to retry in the cloud; a device answers at once, so it's
            // taken and not needed.
            "clientToken" => {}
            other => return Err(format!("unknown member {other}")),
        }
    }
    Ok(args)
}

fn whole(value: &Value, name: &str) -> Result<i64, String> {
    value
        .as_i64()
        .ok_or_else(|| format!("{name} must be a whole number"))
}

/// The API's source union, as the stream command takes it (the same members).
fn source_arg(value: &Value) -> Result<Value, String> {
    let object = value
        .as_object()
        .filter(|o| o.len() == 1)
        .ok_or("source is one of {camera}, {rtmp} or {test}")?;
    let (kind, inner) = object.iter().next().ok_or("source is empty")?;
    let inner = inner
        .as_object()
        .ok_or("a source's settings are an object")?;
    let allowed: &[&str] = match kind.as_str() {
        "camera" => &["video", "audio"],
        "rtmp" => &["key"],
        "test" => &["size", "fps"],
        other => return Err(format!("unknown source {other}")),
    };
    if let Some(extra) = inner.keys().find(|k| !allowed.contains(&k.as_str())) {
        return Err(format!("unknown member source.{kind}.{extra}"));
    }
    Ok(json!({ kind: inner }))
}

/// Runs a stream command and answers as the cloud does: the stream after the change, or every
/// refusal.
async fn stream_change(
    device: &Device,
    stream: &str,
    name: &str,
    mut args: Map<String, Value>,
) -> Answer {
    args.insert("stream_id".into(), json!(stream));
    let outcome = device
        .router
        .dispatch(Command {
            id: new_id(),
            module: "stream".into(),
            name: name.into(),
            args: Value::Object(args),
            deadline: None,
            local: true,
        })
        .await;
    match outcome {
        Outcome::Ok(result) => {
            let refused: Vec<Value> = result
                .get("refused")
                .and_then(Value::as_array)
                .into_iter()
                .flatten()
                .filter_map(refusal)
                .collect();
            if !refused.is_empty() {
                return Answer {
                    status: 409,
                    error: Some("StreamChangeRefused"),
                    body: json!({
                        "message": "The device refused the change and changed nothing.",
                        "refused": refused,
                    }),
                };
            }
            let status = result.get("status").unwrap_or(&result);
            let report = device.report("stream").await;
            Answer::ok(
                202,
                json!({ "stream": reports::stream_after(report.as_ref(), stream, status) }),
            )
        }
        Outcome::Err { code, message } => match code.as_str() {
            codes::INVALID_MESSAGE if message.starts_with("no stream") => Answer::error(
                404,
                "StreamNotFound",
                format!("The device has no stream {stream}."),
            ),
            codes::INVALID_MESSAGE => Answer::error(400, "ValidationException", message),
            codes::UNKNOWN_COMMAND | codes::MODULE_UNAVAILABLE => Answer::error(
                409,
                "DeviceStateUnavailable",
                format!("The device couldn't take the change ({code}): {message}"),
            ),
            codes::TIMEOUT => Answer::error(
                504,
                "DeviceUnreachable",
                "The stream module didn't answer in time.",
            ),
            _ => Answer::error(500, "InternalError", "The change failed on the device."),
        },
    }
}

/// A refusal, with the setting named as the API names it.
fn refusal(refused: &Value) -> Option<Value> {
    let setting = refused.get("setting")?.as_str()?;
    let reason = refused.get("reason")?.as_str()?;
    let setting = match setting {
        "source_ceiling_percent" => "sourceCeilingPercent",
        other => other,
    };
    Some(json!({ "setting": setting, "reason": reason }))
}

async fn wifi_set(device: &Device, body: &Value) -> Answer {
    let Some(ssid) = body.get("ssid").and_then(Value::as_str) else {
        return Answer::error(400, "ValidationException", "ssid is required");
    };
    let mut args = Map::new();
    args.insert("ssid".into(), json!(ssid));
    args.insert(
        "hidden".into(),
        json!(body.get("hidden").and_then(Value::as_bool).unwrap_or(false)),
    );
    match body.get("passphrase") {
        None | Some(Value::Null) => {}
        Some(Value::String(passphrase)) => {
            args.insert("passphrase".into(), json!(passphrase));
        }
        Some(_) => return Answer::error(400, "ValidationException", "passphrase must be a string"),
    }
    match wifi_command(device, "wifi.set", args).await {
        Ok(result) => match result.get("network").and_then(reports::wifi_network) {
            Some(network) => Answer::ok(200, json!({ "network": network })),
            None => Answer::error(500, "InternalError", "The device's answer has no network."),
        },
        Err(answer) => answer,
    }
}

async fn wifi_remove(device: &Device, ssid: &str) -> Answer {
    let mut args = Map::new();
    args.insert("ssid".into(), json!(ssid));
    match wifi_command(device, "wifi.remove", args).await {
        Ok(result) => Answer::ok(
            200,
            json!({ "removed": result.get("removed").and_then(Value::as_bool).unwrap_or(false) }),
        ),
        Err(answer) => answer,
    }
}

/// Runs a net command; a failure is a WifiNetworkRefused, its code lower-cased as the reason,
/// as the cloud answers it.
async fn wifi_command(
    device: &Device,
    name: &str,
    args: Map<String, Value>,
) -> Result<Value, Answer> {
    let outcome = device
        .router
        .dispatch(Command {
            id: new_id(),
            module: "net".into(),
            name: name.into(),
            args: Value::Object(args),
            deadline: None,
            local: true,
        })
        .await;
    match outcome {
        Outcome::Ok(result) => Ok(result),
        Outcome::Err { code, .. } if code == codes::TIMEOUT => Err(Answer::error(
            504,
            "DeviceUnreachable",
            "The net module didn't answer in time.",
        )),
        Outcome::Err { code, message } => {
            let reason = match code.as_str() {
                codes::UNKNOWN_COMMAND => "unsupported".to_owned(),
                codes::INTERNAL | codes::MODULE_UNAVAILABLE => "apply_failed".to_owned(),
                other => other.to_ascii_lowercase(),
            };
            Err(Answer {
                status: 409,
                error: Some("WifiNetworkRefused"),
                body: json!({ "reason": reason, "message": message }),
            })
        }
    }
}

/// A command ID for a local change: `local-` and a ULID.
fn new_id() -> String {
    format!("local-{}", crate::ulid::new(std::time::SystemTime::now()))
}

#[cfg(test)]
mod tests;
