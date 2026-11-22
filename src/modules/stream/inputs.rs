//! What a stream can read and how it can encode, for the `stream` shadow (HLD 7.3.7): `inputs`
//! (USB cameras with their formats, USB audio devices, RTMP keys, the test pattern) and
//! `profiles`. The Control API checks a source or profile set from the cloud against these.

use std::collections::{BTreeMap, BTreeSet};

use serde_json::{Map, Value, json};

use crate::modules::usb::{UsbDevice, UsbSnapshot};

use super::rtmp;
use super::settings::StreamSettings;
use super::v4l2::Format;

/// A camera's capture formats, by [`format_key`]: `None` when they couldn't be read.
pub(crate) type Formats = BTreeMap<String, Option<Vec<Format>>>;

/// A USB device's capture node (`video0`): a UVC camera makes two, and the lowest index is the
/// one that captures.
pub(crate) fn capture_node(device: &UsbDevice) -> Option<&str> {
    device
        .payload
        .get("nodes")
        .and_then(|nodes| nodes.get("video"))
        .and_then(Value::as_array)?
        .iter()
        .filter_map(|node| {
            Some((
                node["index"].as_u64().unwrap_or(u64::MAX),
                node["name"].as_str()?,
            ))
        })
        .min()
        .map(|(_, name)| name)
}

/// Where a camera's formats are kept: its port and node, so a different camera on the same
/// node is read again.
pub(crate) fn format_key(device: &UsbDevice, node: &str) -> String {
    format!("{}/{node}", device.port)
}

/// Whether a USB device records sound (an ALSA capture card).
fn records_audio(device: &UsbDevice) -> bool {
    device
        .payload
        .get("nodes")
        .and_then(|nodes| nodes.get("alsa"))
        .and_then(Value::as_array)
        .is_some_and(|cards| cards.iter().any(|card| card["capture"] == true))
}

/// `profiles`: each profile's encoding, by name.
pub(crate) fn profiles(settings: &StreamSettings) -> Value {
    let profiles: Map<String, Value> = settings
        .profiles
        .iter()
        .map(|(name, profile)| {
            (
                name.clone(),
                json!({
                    "video": profile.video,
                    "encoder": profile.encoder.name(),
                    "bitrate_mode": profile.bitrate_mode.name(),
                    "bitrate_kbps": profile.bitrate_kbps,
                    "min_bitrate_kbps": profile.min_bitrate_kbps,
                    "max_bitrate_kbps": profile.max_bitrate_kbps,
                    "scale": profile.scale,
                    "audio": profile.audio,
                }),
            )
        })
        .collect();
    Value::Object(profiles)
}

/// `inputs`: the attached cameras and audio devices, the RTMP keys (`keys`, when
/// `rtmp_ingest` is enabled) and the test pattern. `with_formats` false leaves out the
/// cameras' formats, to fit the shadow's size limit.
pub(crate) fn inputs(
    settings: &StreamSettings,
    devices: &UsbSnapshot,
    formats: &Formats,
    keys: &BTreeSet<String>,
    with_formats: bool,
) -> Value {
    let mut inputs = Vec::new();
    // A key (`<vid>:<pid>:<serial>`) follows a device from port to port, so it's the
    // selector, unless two attached devices share it.
    let mut keys_seen: BTreeMap<&str, usize> = BTreeMap::new();
    for device in devices.values() {
        if let Some(key) = device.payload.get("key").and_then(Value::as_str) {
            *keys_seen.entry(key).or_default() += 1;
        }
    }
    for device in devices.values() {
        let selector = match device.payload.get("key").and_then(Value::as_str) {
            Some(key) if keys_seen.get(key) == Some(&1) => key.to_owned(),
            _ => format!("usb:{}", device.port),
        };
        let described = |kind: &str| {
            json!({
                "type": kind,
                "selector": selector,
                "port": device.port,
                "product": device.payload.get("product"),
                "manufacturer": device.payload.get("manufacturer"),
            })
        };
        if let Some(node) = capture_node(device) {
            let mut camera = described("camera");
            camera["has_audio"] = json!(records_audio(device));
            if with_formats && let Some(Some(formats)) = formats.get(&format_key(device, node)) {
                camera["formats"] = formats
                    .iter()
                    .map(|format| {
                        json!({
                            "pixel_format": format.pixel_format,
                            "width": format.width,
                            "height": format.height,
                            "fps": format.fps,
                        })
                    })
                    .collect();
            }
            inputs.push(camera);
        } else if records_audio(device) {
            inputs.push(described("audio"));
        }
    }
    let ingest = &settings.rtmp_ingest;
    if ingest.enabled {
        for key in keys {
            let mut input = json!({"type": "rtmp", "key": key});
            if !ingest.publish_host.is_empty() {
                input["publish_url"] = json!(format!(
                    "rtmp://{}:{}/{}/{key}",
                    ingest.publish_host,
                    ingest.port,
                    rtmp::APP
                ));
            }
            inputs.push(input);
        }
    }
    inputs.push(json!({"type": "test"}));
    Value::Array(inputs)
}
