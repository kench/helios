//! What the gps module knows, and when it reports it (LLD 10, sections 5 and 6).
//!
//! [`State`] folds gpsd's messages into the latest fix, receivers and satellites. [`Schedule`]
//! decides when that's worth a shadow update: at once when gpsd comes or goes, a receiver comes
//! or goes, or the fix mode changes; while moving, every [`MOVE_DISTANCE_M`] but at most every
//! [`MOVE_INTERVAL`]; while still, every [`STILL_INTERVAL`].

use std::collections::BTreeMap;
use std::time::{Duration, SystemTime};

use serde_json::{Map, Value, json};
use tokio::time::Instant;

use super::gpsd::{Message, Receiver, Sky, Tpv};
use crate::mqtt::envelope::timestamp;

/// How far a moving device goes between reports.
pub(crate) const MOVE_DISTANCE_M: f64 = 25.0;
/// The shortest time between reports while moving.
pub(crate) const MOVE_INTERVAL: Duration = Duration::from_secs(10);
/// How often a device that isn't moving reports (owner, 2026-11-22: once an hour).
pub(crate) const STILL_INTERVAL: Duration = Duration::from_secs(60 * 60);

/// A fix's mode, as reported.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Mode {
    /// No fix, or gpsd doesn't know.
    None,
    /// Latitude and longitude.
    TwoD,
    /// With altitude.
    ThreeD,
}

impl Mode {
    fn from_gpsd(mode: u8) -> Self {
        match mode {
            2 => Self::TwoD,
            3 => Self::ThreeD,
            _ => Self::None,
        }
    }

    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Self::None => "none",
            Self::TwoD => "2d",
            Self::ThreeD => "3d",
        }
    }
}

/// A position fix, as the shadow reports it.
#[derive(Debug, Clone, PartialEq)]
pub(crate) struct Fix {
    pub(crate) mode: Mode,
    time: Option<String>,
    lat: f64,
    lon: f64,
    alt_msl_m: Option<f64>,
    speed_mps: Option<f64>,
    track_deg: Option<f64>,
    climb_mps: Option<f64>,
    eph_m: Option<f64>,
    epv_m: Option<f64>,
}

impl Fix {
    /// A fix from a TPV report, if it has one (a 2D or 3D mode and a position).
    fn from_tpv(tpv: &Tpv) -> Option<Self> {
        let mode = Mode::from_gpsd(tpv.mode);
        if mode == Mode::None {
            return None;
        }
        Some(Self {
            mode,
            time: tpv.time.clone(),
            lat: tpv.lat?,
            lon: tpv.lon?,
            alt_msl_m: if mode == Mode::ThreeD {
                tpv.alt_msl.or(tpv.alt)
            } else {
                None
            },
            speed_mps: tpv.speed,
            track_deg: tpv.track,
            climb_mps: tpv.climb,
            eph_m: tpv.eph,
            epv_m: tpv.epv,
        })
    }

    fn json(&self) -> Value {
        let mut out = Map::new();
        out.insert("mode".into(), json!(self.mode.as_str()));
        if let Some(time) = &self.time {
            out.insert("time".into(), json!(time));
        }
        out.insert("lat".into(), json!(self.lat));
        out.insert("lon".into(), json!(self.lon));
        for (key, value) in [
            ("alt_msl_m", self.alt_msl_m),
            ("speed_mps", self.speed_mps),
            ("track_deg", self.track_deg),
            ("climb_mps", self.climb_mps),
            ("eph_m", self.eph_m),
            ("epv_m", self.epv_m),
        ] {
            if let Some(value) = value {
                out.insert(key.into(), json!(value));
            }
        }
        Value::Object(out)
    }
}

/// Satellites, with each field's last reported value.
#[derive(Debug, Clone, Default, PartialEq)]
struct Satellites {
    used: Option<u32>,
    visible: Option<u32>,
    hdop: Option<f64>,
    pdop: Option<f64>,
}

impl Satellites {
    fn merge(&mut self, sky: &Sky) {
        self.used = sky.used.or(self.used);
        self.visible = sky.visible.or(self.visible);
        self.hdop = sky.hdop.or(self.hdop);
        self.pdop = sky.pdop.or(self.pdop);
    }

    fn json(&self) -> Option<Value> {
        let mut out = Map::new();
        if let Some(used) = self.used {
            out.insert("used".into(), json!(used));
        }
        if let Some(visible) = self.visible {
            out.insert("visible".into(), json!(visible));
        }
        if let Some(hdop) = self.hdop {
            out.insert("hdop".into(), json!(hdop));
        }
        if let Some(pdop) = self.pdop {
            out.insert("pdop".into(), json!(pdop));
        }
        (!out.is_empty()).then_some(Value::Object(out))
    }
}

/// One receiver, with what the module knows of it.
#[derive(Debug, Clone, PartialEq)]
struct Known {
    receiver: Receiver,
    usb_port: Option<String>,
    /// Its latest fix, if its latest TPV had one.
    fix: Option<Fix>,
    satellites: Satellites,
}

/// What the module knows now.
#[derive(Debug, Clone, PartialEq)]
pub(crate) struct State {
    connected: bool,
    receivers: BTreeMap<String, Known>,
    /// The last fix any receiver had, kept when the fix is lost (owner, 2026-11-22).
    last_fix: Option<Fix>,
    mode: Mode,
    since: SystemTime,
    /// `[modules.gps] device`, and whether gpsd opened it when last asked.
    device: Option<(String, Result<(), String>)>,
}

impl State {
    pub(crate) fn new(now: SystemTime) -> Self {
        Self {
            connected: false,
            receivers: BTreeMap::new(),
            last_fix: None,
            mode: Mode::None,
            since: now,
            device: None,
        }
    }

    /// Records whether gpsd opened the configured receiver.
    pub(crate) fn set_device(&mut self, path: &str, added: Result<(), String>) {
        self.device = Some((path.to_owned(), added));
    }

    /// Whether gpsd has the receiver at `path`.
    pub(crate) fn has_receiver(&self, path: &str) -> bool {
        self.receivers.contains_key(path)
    }

    /// The fix the shadow reports: the first receiver (by path) that has one.
    fn fix(&self) -> Option<(&String, &Known, &Fix)> {
        self.receivers
            .iter()
            .find_map(|(path, known)| known.fix.as_ref().map(|fix| (path, known, fix)))
    }

    /// Records the connection to gpsd. Losing it loses the fix (the last one is kept).
    pub(crate) fn set_connected(&mut self, connected: bool, now: SystemTime) {
        self.connected = connected;
        if !connected {
            self.receivers.clear();
        }
        self.update_mode(now);
    }

    /// Applies one message. `usb_port` finds a receiver's USB port from its path.
    pub(crate) fn apply(
        &mut self,
        message: Message,
        now: SystemTime,
        usb_port: &dyn Fn(&str) -> Option<String>,
    ) {
        let add = |receivers: &mut BTreeMap<String, Known>, receiver: Receiver| {
            let port = usb_port(&receiver.path);
            receivers
                .entry(receiver.path.clone())
                .and_modify(|known| {
                    known.receiver = receiver.clone();
                    known.usb_port.clone_from(&port);
                })
                .or_insert(Known {
                    receiver,
                    usb_port: port,
                    fix: None,
                    satellites: Satellites::default(),
                });
        };
        match message {
            Message::Devices(receivers) => {
                self.receivers
                    .retain(|path, _| receivers.iter().any(|r| &r.path == path && !r.closed()));
                for receiver in receivers.into_iter().filter(|r| !r.closed()) {
                    add(&mut self.receivers, receiver);
                }
            }
            Message::Device(receiver) if receiver.closed() => {
                self.receivers.remove(&receiver.path);
            }
            Message::Device(receiver) => add(&mut self.receivers, receiver),
            Message::Tpv(tpv) => {
                if let Some(known) = tpv.device.as_ref().and_then(|d| self.receivers.get_mut(d)) {
                    known.fix = Fix::from_tpv(&tpv);
                }
            }
            Message::Sky(sky) => {
                if let Some(known) = sky.device.as_ref().and_then(|d| self.receivers.get_mut(d)) {
                    known.satellites.merge(&sky);
                }
            }
            Message::Other => {}
        }
        self.update_mode(now);
    }

    fn update_mode(&mut self, now: SystemTime) {
        let fix = self.fix().map(|(_, _, fix)| fix.clone());
        let mode = fix.as_ref().map_or(Mode::None, |fix| fix.mode);
        if let Some(fix) = fix {
            self.last_fix = Some(fix);
        }
        if mode != self.mode {
            self.mode = mode;
            self.since = now;
        }
    }

    pub(crate) fn mode(&self) -> Mode {
        self.mode
    }

    /// The position of the current fix.
    fn position(&self) -> Option<(f64, f64)> {
        self.fix().map(|(_, _, fix)| (fix.lat, fix.lon))
    }

    /// What decides an immediate report: gpsd, the receivers, the mode, and whether satellites
    /// are known (gpsd sends the first SKY just after the first TPV; without this, a still device
    /// would report its satellites only an hour later).
    fn key(&self) -> Key {
        let satellites = match self.fix() {
            Some((_, known, _)) => known.satellites.json().is_some(),
            None => self
                .receivers
                .values()
                .any(|known| known.satellites.json().is_some()),
        };
        (
            self.connected,
            self.receivers.keys().cloned().collect(),
            self.mode,
            satellites,
            self.device.as_ref().is_some_and(|(_, added)| added.is_ok()),
        )
    }

    /// The `gps` shadow's reported state.
    pub(crate) fn reported(&self) -> Map<String, Value> {
        let mut out = Map::new();
        out.insert(
            "gpsd".into(),
            json!(if self.connected {
                "connected"
            } else {
                "unavailable"
            }),
        );
        let receivers: Vec<Value> = self
            .receivers
            .values()
            .map(|known| {
                let mut receiver = Map::new();
                receiver.insert("path".into(), json!(known.receiver.path));
                if let Some(driver) = &known.receiver.driver {
                    receiver.insert("driver".into(), json!(driver));
                }
                if let Some(bps) = known.receiver.bps {
                    receiver.insert("bps".into(), json!(bps));
                }
                receiver.insert("usb_port".into(), json!(known.usb_port));
                Value::Object(receiver)
            })
            .collect();
        out.insert("receivers".into(), Value::Array(receivers));
        match self.fix() {
            Some((_, known, fix)) => {
                out.insert("fix".into(), fix.json());
                if let Some(satellites) = known.satellites.json() {
                    out.insert("satellites".into(), satellites);
                }
            }
            None => {
                out.insert("fix".into(), json!({"mode": "none"}));
                if let Some(last) = &self.last_fix {
                    out.insert("last_fix".into(), last.json());
                }
                if let Some(satellites) = self
                    .receivers
                    .values()
                    .find_map(|known| known.satellites.json())
                {
                    out.insert("satellites".into(), satellites);
                }
            }
        }
        out.insert("since".into(), json!(timestamp(self.since)));
        if let Some((path, added)) = &self.device {
            let mut device = Map::new();
            device.insert("path".into(), json!(path));
            device.insert("added".into(), json!(added.is_ok()));
            if let Err(error) = added {
                device.insert("error".into(), json!(error));
            }
            out.insert("device".into(), Value::Object(device));
        }
        out
    }
}

/// The great-circle distance between two positions, metres (haversine, mean Earth radius).
#[must_use]
pub(crate) fn distance_m((lat1, lon1): (f64, f64), (lat2, lon2): (f64, f64)) -> f64 {
    const EARTH_RADIUS_M: f64 = 6_371_008.8;
    let (phi1, phi2) = (lat1.to_radians(), lat2.to_radians());
    let dphi = (lat2 - lat1).to_radians();
    let dlambda = (lon2 - lon1).to_radians();
    let a = (dphi / 2.0).sin().powi(2) + phi1.cos() * phi2.cos() * (dlambda / 2.0).sin().powi(2);
    2.0 * EARTH_RADIUS_M * a.sqrt().asin()
}

/// When the last report went out, and what it said.
#[derive(Debug, Default)]
pub(crate) struct Schedule {
    last: Option<Sent>,
}

/// gpsd connected, the receivers, the mode, satellites known, the configured receiver added.
type Key = (bool, Vec<String>, Mode, bool, bool);

#[derive(Debug)]
struct Sent {
    at: Instant,
    key: Key,
    position: Option<(f64, f64)>,
}

impl Schedule {
    /// Whether `state` should be reported now.
    #[must_use]
    pub(crate) fn due(&self, state: &State, now: Instant) -> bool {
        let Some(last) = &self.last else {
            return true;
        };
        if last.key != state.key() {
            return true;
        }
        let elapsed = now.saturating_duration_since(last.at);
        if elapsed >= STILL_INTERVAL {
            return true;
        }
        match (last.position, state.position()) {
            (Some(then), Some(position)) => {
                elapsed >= MOVE_INTERVAL && distance_m(then, position) >= MOVE_DISTANCE_M
            }
            _ => false,
        }
    }

    /// When a report is next due with no new message: the still interval.
    #[must_use]
    pub(crate) fn next(&self) -> Option<Instant> {
        self.last.as_ref().map(|last| last.at + STILL_INTERVAL)
    }

    /// Records that `state` was reported at `now`.
    pub(crate) fn sent(&mut self, state: &State, now: Instant) {
        self.last = Some(Sent {
            at: now,
            key: state.key(),
            position: state.position(),
        });
    }
}
