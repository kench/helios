//! gpsd's JSON protocol, the parts the gps module reads (LLD 10, section 4): one object per
//! line, told apart by `class`. `DEVICES` and `DEVICE` say which receivers gpsd has, `TPV` is a
//! receiver's time, position and velocity, `SKY` its satellites. Everything else is ignored.

use serde::Deserialize;

/// What the module asks for after connecting: JSON reports from every receiver.
pub(crate) const WATCH: &str = "?WATCH={\"enable\":true,\"json\":true}\n";
/// Asks gpsd for every receiver it has; it answers with a `DEVICES` line.
pub(crate) const DEVICES: &str = "?DEVICES;\n";

/// A receiver gpsd has open.
#[derive(Debug, Clone, PartialEq, Deserialize)]
pub(crate) struct Receiver {
    /// Its device path, as gpsd opened it.
    pub(crate) path: String,
    /// gpsd's driver for it (`NMEA0183`, `u-blox`, `Garmin USB binary`).
    #[serde(default)]
    pub(crate) driver: Option<String>,
    /// The serial speed, when it's a serial device.
    #[serde(default)]
    pub(crate) bps: Option<u32>,
    /// When gpsd opened it (RFC 3339), or the number 0 when it has closed it.
    #[serde(default)]
    activated: Option<serde_json::Value>,
}

impl Receiver {
    /// Whether this report says gpsd closed the device (`"activated": 0`).
    pub(crate) fn closed(&self) -> bool {
        self.activated.as_ref().is_some_and(|value| value == 0)
    }
}

/// A `TPV` report. Fields gpsd leaves out are `None`.
#[derive(Debug, Clone, PartialEq, Default, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct Tpv {
    /// The receiver.
    #[serde(default)]
    pub(crate) device: Option<String>,
    /// 0 unknown, 1 no fix, 2 2D, 3 3D.
    #[serde(default)]
    pub(crate) mode: u8,
    /// The fix's time (RFC 3339, UTC).
    #[serde(default)]
    pub(crate) time: Option<String>,
    /// Degrees, WGS 84.
    #[serde(default)]
    pub(crate) lat: Option<f64>,
    /// Degrees, WGS 84.
    #[serde(default)]
    pub(crate) lon: Option<f64>,
    /// Metres above mean sea level (gpsd's `altMSL`, which camelCase would spell `altMsl`).
    #[serde(default, rename = "altMSL")]
    pub(crate) alt_msl: Option<f64>,
    /// Metres above mean sea level: older gpsd's name for `altMSL`.
    #[serde(default)]
    pub(crate) alt: Option<f64>,
    /// Metres a second over the ground.
    #[serde(default)]
    pub(crate) speed: Option<f64>,
    /// Degrees from true north.
    #[serde(default)]
    pub(crate) track: Option<f64>,
    /// Metres a second, up.
    #[serde(default)]
    pub(crate) climb: Option<f64>,
    /// Estimated horizontal error, metres.
    #[serde(default)]
    pub(crate) eph: Option<f64>,
    /// Estimated vertical error, metres.
    #[serde(default)]
    pub(crate) epv: Option<f64>,
}

/// A `SKY` report. gpsd sends some with only a few fields; the module keeps the last value of
/// each.
#[derive(Debug, Clone, PartialEq, Default, Deserialize)]
pub(crate) struct Sky {
    /// The receiver.
    #[serde(default)]
    pub(crate) device: Option<String>,
    /// Satellites in the fix.
    #[serde(default, rename = "uSat")]
    pub(crate) used: Option<u32>,
    /// Satellites seen.
    #[serde(default, rename = "nSat")]
    pub(crate) visible: Option<u32>,
    /// Horizontal dilution of precision.
    #[serde(default)]
    pub(crate) hdop: Option<f64>,
    /// Position dilution of precision.
    #[serde(default)]
    pub(crate) pdop: Option<f64>,
}

/// One line from gpsd.
#[derive(Debug, Clone, PartialEq)]
pub(crate) enum Message {
    /// Every receiver gpsd has.
    Devices(Vec<Receiver>),
    /// One receiver opened, changed or closed.
    Device(Receiver),
    /// A fix.
    Tpv(Tpv),
    /// Satellites.
    Sky(Sky),
    /// Another class, or a line that isn't one of these.
    Other,
}

#[derive(Deserialize)]
struct Devices {
    #[serde(default)]
    devices: Vec<Receiver>,
}

/// Parses one line. A line that isn't JSON, or a known class that doesn't parse, is
/// [`Message::Other`]: gpsd's protocol grows, and one odd line mustn't end the connection.
#[must_use]
pub(crate) fn parse(line: &str) -> Message {
    let Ok(value) = serde_json::from_str::<serde_json::Value>(line) else {
        return Message::Other;
    };
    let class = value["class"].as_str().unwrap_or_default().to_owned();
    let parsed = match class.as_str() {
        "DEVICES" => serde_json::from_value::<Devices>(value).map(|d| Message::Devices(d.devices)),
        "DEVICE" => serde_json::from_value(value).map(Message::Device),
        "TPV" => serde_json::from_value(value).map(Message::Tpv),
        "SKY" => serde_json::from_value(value).map(Message::Sky),
        _ => return Message::Other,
    };
    parsed.unwrap_or(Message::Other)
}
