//! The modules' reports, read into the Control API's read responses (helios-contract's
//! `HeliosControl` model), as the cloud reads them from the shadows (helios-cloud's
//! `StreamShadow`, `UplinksShadow`, `GpsShadow` and `WifiControl`). The contract's report
//! vectors (`test-vectors/control-reports-v1.json`) pin both to the same answers.
//!
//! The input is what each module reports: the `reported` section of its named shadow. Anything
//! missing or of the wrong type is left out rather than failing the read, so a report from an
//! older Helios still works for the rest. Nothing here has secrets: reports never carry
//! passphrases. The answers have no `reportedAt`, which the cloud takes from the shadow's
//! metadata.

use std::collections::{BTreeMap, HashMap};

use serde_json::{Map, Value, json};

/// The reports a read can use: each module's latest `reported` state, if it has reported.
#[derive(Debug, Default, Clone, Copy)]
pub(crate) struct Reports<'a> {
    /// The stream module's report (`stream` shadow).
    pub stream: Option<&'a Value>,
    /// The net module's report (`net` shadow).
    pub net: Option<&'a Value>,
    /// The gps module's report (`gps` shadow).
    pub gps: Option<&'a Value>,
}

/// A read the reports answer, by its Control API operation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Read {
    /// `GET /v1/control/devices/{id}/streams`
    ListStreams,
    /// `GET /v1/control/devices/{id}/streams/{streamId}`
    GetStream(String),
    /// `GET /v1/control/devices/{id}/inputs`
    ListInputs,
    /// `GET /v1/control/devices/{id}/profiles`
    ListProfiles,
    /// `GET /v1/control/devices/{id}/uplinks`, with public addresses only if asked for.
    GetUplinks {
        /// `includePublicAddresses`.
        public_addresses: bool,
    },
    /// `GET /v1/control/devices/{id}/location`
    GetLocation,
    /// `GET /v1/control/devices/{id}/wifi/networks`
    ListWifi,
}

/// A read that can't be answered: the HTTP status and the modeled error's name.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Refusal {
    /// 404 or 409.
    pub status: u16,
    /// The error's name, as `X-Amzn-Errortype` carries it.
    pub error: &'static str,
    /// For people.
    pub message: String,
}

/// The response body for `read`, or why it can't be answered.
///
/// # Errors
///
/// [`Refusal`] when the module the read needs hasn't reported (409 `DeviceStateUnavailable`)
/// or there's no such stream (404 `StreamNotFound`).
pub(crate) fn answer(reports: Reports<'_>, read: &Read) -> Result<Value, Refusal> {
    match read {
        Read::ListStreams => list_streams(streams_reported(reports.stream)?),
        Read::GetStream(id) => get_stream(streams_reported(reports.stream)?, id),
        Read::ListInputs => list_inputs(reports.stream),
        Read::ListProfiles => list_profiles(reports.stream),
        Read::GetUplinks { public_addresses } => {
            uplinks(reports.net, reports.stream, *public_addresses)
        }
        Read::GetLocation => location(reports.gps),
        Read::ListWifi => wifi(reports.net),
    }
}

fn unavailable(message: &str) -> Refusal {
    Refusal {
        status: 409,
        error: "DeviceStateUnavailable",
        message: message.to_owned(),
    }
}

// --- Streams ---------------------------------------------------------------------------------

const STREAM_STATES: &[&str] = &[
    "stopped",
    "waiting_for_input",
    "starting",
    "live",
    "reconnecting",
    "failed",
];
const RECORDING_STATES: &[&str] = &[
    "off",
    "idle",
    "recording",
    "unavailable",
    "disk_full",
    "error",
];
const BITRATE_MODES: &[&str] = &["fixed", "adaptive"];

/// The stream report, if it reports its streams at all.
fn streams_reported(stream: Option<&Value>) -> Result<&Value, Refusal> {
    match stream {
        Some(report) if at(report, &["streams"]).is_some() => Ok(report),
        _ => Err(unavailable(
            "The device hasn't reported its streams (it may never have connected).",
        )),
    }
}

fn list_streams(report: &Value) -> Result<Value, Refusal> {
    let ids: BTreeMap<&String, ()> = map(report, &["streams"]).keys().map(|k| (k, ())).collect();
    let streams: Vec<Value> = ids.keys().map(|id| describe(report, id)).collect();
    let mut body = Map::new();
    body.insert("streams".into(), Value::Array(streams));
    if let Some(storage) = recording_storage(report) {
        body.insert("recording".into(), storage);
    }
    Ok(Value::Object(body))
}

fn get_stream(report: &Value, id: &str) -> Result<Value, Refusal> {
    if at(report, &["streams", id]).is_none() {
        return Err(Refusal {
            status: 404,
            error: "StreamNotFound",
            message: format!("The device reports no stream {id}."),
        });
    }
    Ok(json!({ "stream": describe(report, id) }))
}

/// A stream: `desired` is what the device reports wanting (nothing is kept beside it on the
/// device), `reported` its state if it reports everything that needs.
fn describe(report: &Value, id: &str) -> Value {
    let stream = at(report, &["streams", id]);
    let state = stream
        .and_then(|s| string(s, &["desired"]))
        .filter(|s| *s == "live")
        .map_or("stopped", |_| "live");
    let mut body = Map::new();
    body.insert("streamId".into(), json!(id));
    body.insert("desired".into(), json!({ "state": state }));
    // Deprecated in the contract, but still required: always false with commands.
    body.insert("pending".into(), json!(false));
    if let Some(reported) = stream.and_then(|s| stream_reported(report, s)) {
        body.insert("reported".into(), reported);
    }
    Value::Object(body)
}

fn stream_reported(report: &Value, r: &Value) -> Option<Value> {
    let state = string(r, &["state"]).filter(|s| STREAM_STATES.contains(s))?;
    let since = string(r, &["since"]).and_then(instant)?;
    let source = at(r, &["source"]).and_then(source_of)?;
    let profile = string(r, &["profile"])?;
    let destination = string(r, &["destination"])?;
    let bitrate = integer(r, &["bitrate_kbps"])?;
    let mut out = Map::new();
    out.insert("state".into(), json!(state));
    out.insert("since".into(), json!(since));
    out.insert("source".into(), source);
    out.insert("profile".into(), json!(profile));
    out.insert("destination".into(), json!(destination));
    out.insert("bitrateKbps".into(), json!(bitrate));
    put_int(
        &mut out,
        "bitrateOverrideKbps",
        integer(r, &["bitrate_override_kbps"]),
    );
    put_int(
        &mut out,
        "bitrateCeilingKbps",
        integer(r, &["bitrate_ceiling_kbps"]),
    );
    put_int(&mut out, "sourceKbps", integer(r, &["source_kbps"]));
    put_str(&mut out, "lastError", string(r, &["last_error"]));
    if let Some(encoder) = at(r, &["encoder"]).filter(|e| e.is_object()) {
        out.insert("encoder".into(), encoder_of(encoder));
    }
    let links = string(r, &["output"])
        .and_then(|output| integer(report, &["outputs", output, "active_links"]));
    put_int(&mut out, "activeLinks", links);
    if let Some(recording) = at(r, &["recording"])
        .filter(|d| d.is_object())
        .and_then(recording_of)
    {
        out.insert("recording".into(), recording);
    }
    Some(Value::Object(out))
}

fn recording_of(d: &Value) -> Option<Value> {
    let state = string(d, &["state"]).filter(|s| RECORDING_STATES.contains(s))?;
    let mut out = Map::new();
    out.insert("state".into(), json!(state));
    put_str(&mut out, "files", string(d, &["files"]));
    put_str(&mut out, "segment", string(d, &["segment"]));
    put_string(&mut out, "since", string(d, &["since"]).and_then(instant));
    put_str(&mut out, "lastError", string(d, &["last_error"]));
    Some(Value::Object(out))
}

/// The recordings storage, if the device reports one whole (Helios 0.15.0 and later).
fn recording_storage(report: &Value) -> Option<Value> {
    let d = at(report, &["recording"]).filter(|d| d.is_object())?;
    let dir = string(d, &["dir"])?;
    let mounted = boolean(d, &["mounted"])?;
    let full = boolean(d, &["full"])?;
    let mut out = Map::new();
    out.insert("dir".into(), json!(dir));
    out.insert("mounted".into(), json!(mounted));
    out.insert("full".into(), json!(full));
    put_long(&mut out, "totalBytes", whole(d, &["total_bytes"]));
    put_long(&mut out, "freeBytes", whole(d, &["free_bytes"]));
    put_int(&mut out, "segments", integer(d, &["segments"]));
    put_string(&mut out, "oldest", string(d, &["oldest"]).and_then(instant));
    put_str(&mut out, "lastError", string(d, &["last_error"]));
    Some(Value::Object(out))
}

fn encoder_of(e: &Value) -> Value {
    let mut out = Map::new();
    put_value(&mut out, "fps", number(e, &["fps"]).and_then(float32));
    put_value(
        &mut out,
        "bitrateKbps",
        number(e, &["bitrate_kbps"]).and_then(float32),
    );
    put_long(&mut out, "dropFrames", whole(e, &["drop_frames"]));
    put_long(&mut out, "dupFrames", whole(e, &["dup_frames"]));
    put_value(&mut out, "speed", number(e, &["speed"]).and_then(float32));
    Value::Object(out)
}

/// A reported source (`{"type": ...}`, with the device's details) as the API's union, if it's
/// one the API knows.
fn source_of(source: &Value) -> Option<Value> {
    match string(source, &["type"]).unwrap_or("") {
        "camera" => {
            let video = string(source, &["video"])?;
            let mut camera = Map::new();
            camera.insert("video".into(), json!(video));
            put_str(&mut camera, "audio", string(source, &["audio"]));
            Some(json!({ "camera": camera }))
        }
        "rtmp" => {
            let key = integer(source, &["camera"])
                .map_or_else(|| "ingest".to_owned(), |n| format!("ingest-{n}"));
            Some(json!({ "rtmp": { "key": key } }))
        }
        "test" => {
            let mut test = Map::new();
            put_str(&mut test, "size", string(source, &["size"]));
            put_int(&mut test, "fps", integer(source, &["fps"]));
            Some(json!({ "test": test }))
        }
        _ => None,
    }
}

// --- Inputs and profiles ---------------------------------------------------------------------

fn list_inputs(stream: Option<&Value>) -> Result<Value, Refusal> {
    let Some(report) = stream.filter(|r| at(r, &["inputs"]).is_some()) else {
        return Err(unavailable(
            "The device doesn't report its inputs (its Helios predates the Control API).",
        ));
    };
    let mut inputs = Vec::new();
    for input in list(report, &["inputs"]) {
        let entry = match string(input, &["type"]).unwrap_or("") {
            "camera" => camera_of(input).map(|c| json!({ "camera": c })),
            "audio" => audio_of(input).map(|a| json!({ "audio": a })),
            "rtmp" => rtmp_of(report, input).map(|r| json!({ "rtmp": r })),
            "test" => Some(json!({ "test": {} })),
            _ => None,
        };
        inputs.extend(entry);
    }
    Ok(json!({ "inputs": inputs }))
}

fn camera_of(input: &Value) -> Option<Value> {
    let selector = string(input, &["selector"])?;
    let port = string(input, &["port"])?;
    let mut out = Map::new();
    out.insert("selector".into(), json!(selector));
    out.insert("port".into(), json!(port));
    out.insert(
        "hasAudio".into(),
        json!(boolean(input, &["has_audio"]).unwrap_or(false)),
    );
    put_str(&mut out, "product", string(input, &["product"]));
    put_str(&mut out, "manufacturer", string(input, &["manufacturer"]));
    if at(input, &["formats"]).is_some() {
        let formats: Vec<Value> = list(input, &["formats"])
            .into_iter()
            .filter_map(format_of)
            .collect();
        out.insert("formats".into(), Value::Array(formats));
    }
    Some(Value::Object(out))
}

fn format_of(format: &Value) -> Option<Value> {
    let pixel = string(format, &["pixel_format"])?;
    let width = integer(format, &["width"])?;
    let height = integer(format, &["height"])?;
    let fps: Vec<Value> = list(format, &["fps"])
        .into_iter()
        .filter_map(|f| f.as_f64().and_then(float32))
        .collect();
    Some(json!({ "pixelFormat": pixel, "width": width, "height": height, "fps": fps }))
}

fn audio_of(input: &Value) -> Option<Value> {
    let selector = string(input, &["selector"])?;
    let port = string(input, &["port"])?;
    let mut out = Map::new();
    out.insert("selector".into(), json!(selector));
    out.insert("port".into(), json!(port));
    put_str(&mut out, "product", string(input, &["product"]));
    put_str(&mut out, "manufacturer", string(input, &["manufacturer"]));
    Some(Value::Object(out))
}

/// An RTMP key, with the camera publishing to it now, if any.
fn rtmp_of(report: &Value, input: &Value) -> Option<Value> {
    let key = string(input, &["key"])?;
    let mut out = Map::new();
    out.insert("key".into(), json!(key));
    put_str(&mut out, "publishUrl", string(input, &["publish_url"]));
    if let Some(publisher) = at(report, &["rtmp_ingest", "publishers", key]).and_then(publisher_of)
    {
        out.insert("publisher".into(), publisher);
    }
    Some(Value::Object(out))
}

fn publisher_of(p: &Value) -> Option<Value> {
    let address = string(p, &["address"])?;
    let since = string(p, &["since"]).and_then(instant)?;
    let mut out = Map::new();
    out.insert("address".into(), json!(address));
    out.insert("since".into(), json!(since));
    put_str(&mut out, "videoCodec", string(p, &["video_codec"]));
    put_int(&mut out, "width", integer(p, &["width"]));
    put_int(&mut out, "height", integer(p, &["height"]));
    put_int(&mut out, "videoKbps", integer(p, &["video_kbps"]));
    Some(Value::Object(out))
}

fn list_profiles(stream: Option<&Value>) -> Result<Value, Refusal> {
    let Some(report) = stream.filter(|r| at(r, &["profiles"]).is_some()) else {
        return Err(unavailable(
            "The device doesn't report its profiles (its Helios predates the Control API).",
        ));
    };
    let by_name: BTreeMap<&String, &Value> = map(report, &["profiles"]).iter().collect();
    let profiles: Vec<Value> = by_name
        .into_iter()
        .filter_map(|(name, p)| profile_of(name, p))
        .collect();
    Ok(json!({ "profiles": profiles }))
}

fn profile_of(name: &str, p: &Value) -> Option<Value> {
    let video = string(p, &["video"])?;
    let encoder = string(p, &["encoder"])?;
    let mode = string(p, &["bitrate_mode"]).filter(|m| BITRATE_MODES.contains(m))?;
    let bitrate = integer(p, &["bitrate_kbps"])?;
    let min = integer(p, &["min_bitrate_kbps"])?;
    let max = integer(p, &["max_bitrate_kbps"])?;
    let audio = string(p, &["audio"])?;
    let mut out = Map::new();
    out.insert("name".into(), json!(name));
    out.insert("video".into(), json!(video));
    out.insert("encoder".into(), json!(encoder));
    out.insert("bitrateMode".into(), json!(mode));
    out.insert("bitrateKbps".into(), json!(bitrate));
    out.insert("minBitrateKbps".into(), json!(min));
    out.insert("maxBitrateKbps".into(), json!(max));
    out.insert("audio".into(), json!(audio));
    put_str(
        &mut out,
        "scale",
        string(p, &["scale"]).filter(|s| !s.is_empty()),
    );
    Some(Value::Object(out))
}

// --- Uplinks ---------------------------------------------------------------------------------

/// The device's interfaces and what its SRTLA bonds do with them (LLD 3). Public addresses
/// only when asked for.
fn uplinks(
    net: Option<&Value>,
    stream: Option<&Value>,
    public_addresses: bool,
) -> Result<Value, Refusal> {
    let Some(net) = net.filter(|n| at(n, &["interfaces"]).is_some_and(Value::is_object)) else {
        return Err(unavailable(
            "The device hasn't reported its interfaces (no net module, or a Helios before 0.5.0).",
        ));
    };
    let interfaces: BTreeMap<&String, &Value> = map(net, &["interfaces"])
        .iter()
        .filter(|(_, i)| i.is_object())
        .collect();
    let addresses = public_ipv4s(&interfaces);
    let mut bonding = bonding(&interfaces, stream);
    let uplinks: Vec<Value> = interfaces
        .iter()
        .map(|(name, i)| {
            uplink(
                name,
                i,
                &addresses,
                bonding.remove(name.as_str()).unwrap_or_default(),
                public_addresses,
            )
        })
        .collect();
    Ok(json!({ "uplinks": uplinks }))
}

fn uplink(
    name: &str,
    i: &Value,
    addresses: &HashMap<&str, &str>,
    bonding: Vec<Value>,
    public_addresses: bool,
) -> Value {
    let mut out = Map::new();
    out.insert("interface".into(), json!(name));
    out.insert(
        "kind".into(),
        json!(string(i, &["kind"]).unwrap_or("other")),
    );
    out.insert(
        "operState".into(),
        json!(string(i, &["oper_state"]).unwrap_or("unknown")),
    );
    out.insert("ipv4".into(), json!(strings(i, &["ipv4"])));
    out.insert(
        "sourceRouted".into(),
        json!(boolean(i, &["source_route", "rule"]).unwrap_or(false)),
    );
    out.insert("bonding".into(), Value::Array(bonding));
    put_value(
        &mut out,
        "carrier",
        boolean(i, &["carrier"]).map(Value::Bool),
    );
    let metric = list(i, &["default_routes"])
        .into_iter()
        .filter(|r| string(r, &["family"]) == Some("ipv4"))
        .filter_map(|r| integer(r, &["metric"]))
        .min();
    put_int(&mut out, "defaultRouteMetric", metric);
    if let Some(w) = at(i, &["wifi"]).filter(|w| w.is_object()) {
        let mut wifi = Map::new();
        put_str(&mut wifi, "ssid", string(w, &["ssid"]));
        put_int(&mut wifi, "signalDbm", integer(w, &["signal_dbm"]));
        put_int(&mut wifi, "frequencyMhz", integer(w, &["frequency_mhz"]));
        out.insert("wifi".into(), Value::Object(wifi));
    }
    if let Some(p) = at(i, &["public_ipv4"]).filter(|p| p.is_object()) {
        out.insert(
            "publicIpv4".into(),
            public_check(name, p, addresses, public_addresses),
        );
    }
    Value::Object(out)
}

fn public_check(
    name: &str,
    p: &Value,
    addresses: &HashMap<&str, &str>,
    public_addresses: bool,
) -> Value {
    let mut shares: Vec<&str> = match addresses.get(name) {
        Some(mine) => addresses
            .iter()
            .filter(|(other, address)| **other != name && *address == mine)
            .map(|(other, _)| *other)
            .collect(),
        None => Vec::new(),
    };
    shares.sort_unstable();
    let mut out = Map::new();
    out.insert("sharesPublicAddressWith".into(), json!(shares));
    if public_addresses {
        put_str(&mut out, "address", string(p, &["address"]));
    }
    put_string(
        &mut out,
        "checkedAt",
        string(p, &["checked_at"]).and_then(instant),
    );
    put_str(&mut out, "error", string(p, &["error"]));
    put_string(
        &mut out,
        "failedAt",
        string(p, &["failed_at"]).and_then(instant),
    );
    Value::Object(out)
}

/// Each interface's public address from its latest check, when that check succeeded: a failed
/// check's kept address doesn't count as shared (LLD 3, section 3.5.1).
fn public_ipv4s<'a>(interfaces: &BTreeMap<&'a String, &'a Value>) -> HashMap<&'a str, &'a str> {
    interfaces
        .iter()
        .filter(|(_, i)| string(i, &["public_ipv4", "error"]).is_none())
        .filter_map(|(name, i)| {
            string(i, &["public_ipv4", "address"]).map(|address| (name.as_str(), address))
        })
        .collect()
}

/// What each running SRTLA output does with each interface: `uplinks` are the local addresses
/// it bonds (matched to interfaces by their IPv4 addresses), `standby` names interfaces left
/// out.
fn bonding(
    interfaces: &BTreeMap<&String, &Value>,
    stream: Option<&Value>,
) -> HashMap<String, Vec<Value>> {
    let mut by_address: HashMap<&str, &str> = HashMap::new();
    for (name, i) in interfaces {
        for address in strings(i, &["ipv4"]) {
            let address = address.split('/').next().unwrap_or(address);
            by_address.entry(address).or_insert(name.as_str());
        }
    }
    let mut bonding: HashMap<String, Vec<Value>> = HashMap::new();
    let Some(stream) = stream else {
        return bonding;
    };
    let outputs: BTreeMap<&String, &Value> = map(stream, &["outputs"]).iter().collect();
    for (output, o) in outputs {
        if !o.is_object() || !has(o, "uplinks") || string(o, &["state"]) == Some("stopped") {
            continue;
        }
        let mut seen = Vec::new();
        for name in strings(o, &["uplinks"])
            .into_iter()
            .filter_map(|address| by_address.get(address).copied())
        {
            if !seen.contains(&name) {
                seen.push(name);
                bonding
                    .entry(name.to_owned())
                    .or_default()
                    .push(json!({ "output": output, "state": "bonded" }));
            }
        }
        for s in list(o, &["standby"]) {
            if let Some(name) = string(s, &["interface"]) {
                let mut standby = Map::new();
                standby.insert("output".into(), json!(output));
                standby.insert("state".into(), json!("standby"));
                put_str(
                    &mut standby,
                    "sharesPublicAddressWith",
                    string(s, &["shares_public_address_with"]),
                );
                bonding
                    .entry(name.to_owned())
                    .or_default()
                    .push(Value::Object(standby));
            }
        }
    }
    bonding
}

// --- Location --------------------------------------------------------------------------------

const FIX_MODES: &[&str] = &["none", "2d", "3d"];

/// The device's gps state and fix (LLD 10). Its exact position: never logged.
fn location(gps: Option<&Value>) -> Result<Value, Refusal> {
    let Some(report) = gps.filter(|g| string(g, &["gpsd"]).is_some()) else {
        return Err(unavailable(
            "The device hasn't reported a gps state (no gps module, or a Helios before 0.8.0).",
        ));
    };
    let gpsd = match string(report, &["gpsd"]) {
        Some("connected") => "connected",
        _ => "unavailable",
    };
    let receivers: Vec<Value> = list(report, &["receivers"])
        .into_iter()
        .filter_map(|r| {
            let path = string(r, &["path"])?;
            let mut out = Map::new();
            out.insert("path".into(), json!(path));
            put_str(&mut out, "driver", string(r, &["driver"]));
            put_int(&mut out, "bps", integer(r, &["bps"]));
            put_str(&mut out, "usbPort", string(r, &["usb_port"]));
            Some(Value::Object(out))
        })
        .collect();
    let mut out = Map::new();
    out.insert("gpsd".into(), json!(gpsd));
    out.insert("receivers".into(), Value::Array(receivers));
    out.insert(
        "fix".into(),
        at(report, &["fix"]).map_or_else(|| json!({ "mode": "none" }), fix_of),
    );
    // The module always reports since; without it, the epoch (the cloud falls back to the
    // report's time, which a report alone doesn't carry).
    out.insert(
        "since".into(),
        json!(
            string(report, &["since"])
                .and_then(instant)
                .unwrap_or_else(|| "1970-01-01T00:00:00Z".to_owned())
        ),
    );
    if let Some(last) = at(report, &["last_fix"]).filter(|f| f.is_object()) {
        out.insert("lastFix".into(), fix_of(last));
    }
    if let Some(s) = at(report, &["satellites"])
        .and_then(Value::as_object)
        .filter(|s| !s.is_empty())
    {
        let s = Value::Object(s.clone());
        let mut satellites = Map::new();
        put_int(&mut satellites, "used", integer(&s, &["used"]));
        put_int(&mut satellites, "visible", integer(&s, &["visible"]));
        put_value(
            &mut satellites,
            "hdop",
            number(&s, &["hdop"]).and_then(float64),
        );
        put_value(
            &mut satellites,
            "pdop",
            number(&s, &["pdop"]).and_then(float64),
        );
        out.insert("satellites".into(), Value::Object(satellites));
    }
    if let Some((d, path)) =
        at(report, &["device"]).and_then(|d| string(d, &["path"]).map(|path| (d, path)))
    {
        let mut configured = Map::new();
        configured.insert("path".into(), json!(path));
        configured.insert(
            "added".into(),
            json!(boolean(d, &["added"]).unwrap_or(false)),
        );
        put_str(&mut configured, "error", string(d, &["error"]));
        out.insert("configuredReceiver".into(), Value::Object(configured));
    }
    Ok(Value::Object(out))
}

/// A fix; a mode of none carries no position, whatever else the report holds. The module sends
/// only none, 2d and 3d, so any other mode counts as none.
fn fix_of(f: &Value) -> Value {
    let mode = string(f, &["mode"])
        .filter(|m| FIX_MODES.contains(m))
        .unwrap_or("none");
    let mut out = Map::new();
    out.insert("mode".into(), json!(mode));
    if mode == "none" {
        return Value::Object(out);
    }
    put_string(&mut out, "time", string(f, &["time"]).and_then(instant));
    for (from, to) in [
        ("lat", "latitude"),
        ("lon", "longitude"),
        ("alt_msl_m", "altitudeM"),
        ("speed_mps", "speedMps"),
        ("track_deg", "trackDeg"),
        ("climb_mps", "climbMps"),
        ("eph_m", "horizontalErrorM"),
        ("epv_m", "verticalErrorM"),
    ] {
        put_value(&mut out, to, number(f, &[from]).and_then(float64));
    }
    Value::Object(out)
}

// --- Wi-Fi -----------------------------------------------------------------------------------

/// The Wi-Fi networks the device is set to join, as it reports them (never a passphrase: the
/// cloud keeps those, and the device doesn't report them).
fn wifi(net: Option<&Value>) -> Result<Value, Refusal> {
    let Some(wifi) = net.and_then(|n| at(n, &["wifi"])) else {
        return Err(unavailable(
            "The device doesn't report Wi-Fi networks (no net module, or its Helios predates Wi-Fi).",
        ));
    };
    let networks: Vec<Value> = list(wifi, &["networks"])
        .into_iter()
        .filter_map(|network| {
            let ssid = string(network, &["ssid"])?;
            let security =
                string(network, &["security"]).filter(|s| matches!(*s, "open" | "personal"))?;
            Some(json!({
                "ssid": ssid,
                "security": security,
                "hidden": boolean(network, &["hidden"]).unwrap_or(false),
            }))
        })
        .collect();
    Ok(json!({ "networks": networks }))
}

// --- Reading reports, as helios-cloud's ShadowJson does --------------------------------------

/// The member at `path`, if every step is an object that has it and it isn't null.
fn at<'a>(value: &'a Value, path: &[&str]) -> Option<&'a Value> {
    let mut current = value;
    for key in path {
        current = current.as_object()?.get(*key)?;
    }
    (!current.is_null()).then_some(current)
}

/// Whether object `value` has `key`, even with a null value.
fn has(value: &Value, key: &str) -> bool {
    value.as_object().is_some_and(|o| o.contains_key(key))
}

fn string<'a>(value: &'a Value, path: &[&str]) -> Option<&'a str> {
    at(value, path)?.as_str()
}

fn number(value: &Value, path: &[&str]) -> Option<f64> {
    at(value, path)?.as_f64()
}

/// A whole number that fits in an `i32`, as the Control API's integers are.
fn integer(value: &Value, path: &[&str]) -> Option<i64> {
    let n = number(value, path)?;
    (n.fract() == 0.0 && n >= f64::from(i32::MIN) && n <= f64::from(i32::MAX))
        .then(|| at(value, path).and_then(Value::as_i64).unwrap_or(n as i64))
}

/// A whole number (the API's longs).
fn whole(value: &Value, path: &[&str]) -> Option<i64> {
    let found = at(value, path)?;
    if let Some(n) = found.as_i64() {
        return Some(n);
    }
    let n = found.as_f64()?;
    (n.fract() == 0.0 && n.is_finite() && n.abs() < 9.0e18).then_some(n as i64)
}

fn boolean(value: &Value, path: &[&str]) -> Option<bool> {
    at(value, path)?.as_bool()
}

/// The object at `path`, empty if there's none.
fn map<'a>(value: &'a Value, path: &[&str]) -> &'a Map<String, Value> {
    static EMPTY: std::sync::OnceLock<Map<String, Value>> = std::sync::OnceLock::new();
    at(value, path)
        .and_then(Value::as_object)
        .unwrap_or_else(|| EMPTY.get_or_init(Map::new))
}

/// The list at `path`, empty if there's none; nulls dropped.
fn list<'a>(value: &'a Value, path: &[&str]) -> Vec<&'a Value> {
    at(value, path)
        .and_then(Value::as_array)
        .map(|items| items.iter().filter(|v| !v.is_null()).collect())
        .unwrap_or_default()
}

/// The strings in the list at `path`, in order; anything else in it skipped.
fn strings<'a>(value: &'a Value, path: &[&str]) -> Vec<&'a str> {
    list(value, path)
        .into_iter()
        .filter_map(Value::as_str)
        .collect()
}

/// An ISO 8601 instant in UTC (`2026-11-22T20:15:30.000Z`), written as the API writes
/// timestamps: no fraction when it's zero, else 3, 6 or 9 digits (Java's `Instant.toString`).
/// Anything else (another offset, an invalid date) is no instant.
pub(crate) fn instant(text: &str) -> Option<String> {
    let bytes = text.as_bytes();
    let digits = |range: std::ops::Range<usize>| -> Option<u32> {
        let part = text.get(range)?;
        part.bytes()
            .all(|b| b.is_ascii_digit())
            .then(|| part.parse().ok())?
    };
    if bytes.len() < 20
        || bytes[4] != b'-'
        || bytes[7] != b'-'
        || !matches!(bytes[10], b'T' | b't')
        || bytes[13] != b':'
        || bytes[16] != b':'
    {
        return None;
    }
    let (year, month, day) = (digits(0..4)?, digits(5..7)?, digits(8..10)?);
    let (hour, minute, second) = (digits(11..13)?, digits(14..16)?, digits(17..19)?);
    let leap = (year % 4 == 0 && year % 100 != 0) || year % 400 == 0;
    let days = match month {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        2 if leap => 29,
        2 => 28,
        _ => return None,
    };
    if day == 0 || day > days || hour > 23 || minute > 59 || second > 59 {
        return None;
    }
    let rest = &text[19..];
    let (fraction, zone) = match rest.strip_prefix('.') {
        Some(after) => {
            let end = after
                .find(|c: char| !c.is_ascii_digit())
                .unwrap_or(after.len());
            if end == 0 || end > 9 {
                return None;
            }
            (&after[..end], &after[end..])
        }
        None => ("", rest),
    };
    if !matches!(zone, "Z" | "z") {
        return None;
    }
    let mut nanos = format!("{fraction:0<9}");
    let digits_kept = if nanos == "000000000" {
        0
    } else if nanos.ends_with("000000") {
        3
    } else if nanos.ends_with("000") {
        6
    } else {
        9
    };
    nanos.truncate(digits_kept);
    let fraction = if nanos.is_empty() {
        String::new()
    } else {
        format!(".{nanos}")
    };
    Some(format!(
        "{year:04}-{month:02}-{day:02}T{hour:02}:{minute:02}:{second:02}{fraction}Z"
    ))
}

/// `n` as the API's `float` (32 bits), written as its shortest form.
fn float32(n: f64) -> Option<Value> {
    #[allow(
        clippy::cast_possible_truncation,
        reason = "the API's floats are 32-bit"
    )]
    let f = n as f32;
    if !f.is_finite() {
        return None;
    }
    serde_json::from_str(&f.to_string()).ok()
}

/// `n` as the API's `double`.
fn float64(n: f64) -> Option<Value> {
    serde_json::Number::from_f64(n).map(Value::Number)
}

fn put_str(out: &mut Map<String, Value>, key: &str, value: Option<&str>) {
    if let Some(value) = value {
        out.insert(key.into(), json!(value));
    }
}

fn put_string(out: &mut Map<String, Value>, key: &str, value: Option<String>) {
    if let Some(value) = value {
        out.insert(key.into(), json!(value));
    }
}

fn put_int(out: &mut Map<String, Value>, key: &str, value: Option<i64>) {
    if let Some(value) = value {
        out.insert(key.into(), json!(value));
    }
}

fn put_long(out: &mut Map<String, Value>, key: &str, value: Option<i64>) {
    put_int(out, key, value);
}

fn put_value(out: &mut Map<String, Value>, key: &str, value: Option<Value>) {
    if let Some(value) = value {
        out.insert(key.into(), value);
    }
}

#[cfg(test)]
mod tests;
