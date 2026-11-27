//! `stream.update` (helios-contract `device.smithy`, `StreamUpdate`; AWS IoT command
//! `helios-stream-update-v1`): changes any of a stream's settings at once, whole or not at all
//! (the page "Helios - State Management: Tenets and Practices").
//!
//! Each setting is `{"set": value}` or `{"configured": {}}` (back to `helios.toml`'s); one left
//! out is unchanged, and a `null` is never a setting. Arguments that don't match the model are
//! `INVALID_MESSAGE`. Everything else is checked against the device (the profile exists and
//! suits the source, a bitrate within the new profile's limits, a destination it can use)
//! before anything changes; if any setting is refused, nothing changes and every refusal is in
//! the result beside the stream's status.
//!
//! The stream client in Helios opens a sealed destination before the command reaches the
//! daemon, and passes it on as `{"url": ...}`, or `{"unreadable": reason}` when it can't.

use serde::Deserialize;
use serde::de::Deserializer;
use serde_json::{Value, json};

use super::settings::Source;
use super::{BitrateChange, Streams};
use crate::modules::ModuleContext;
use crate::router::{Outcome, codes};

/// The arguments, as the model has them.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct UpdateArgs {
    pub(crate) stream_id: String,
    #[serde(default, deserialize_with = "present")]
    source: Option<Setting<SourceArg>>,
    #[serde(default, deserialize_with = "present")]
    profile: Option<Setting<String>>,
    #[serde(default, deserialize_with = "present")]
    pub(crate) destination: Option<Setting<DestinationArg>>,
    #[serde(default, deserialize_with = "present")]
    bitrate: Option<Setting<u32>>,
    #[serde(default, deserialize_with = "present")]
    source_ceiling_percent: Option<Setting<u32>>,
    #[serde(default, deserialize_with = "present")]
    record: Option<Setting<bool>>,
}

/// A member that's there must be a value: `null` doesn't mean "left out".
fn present<'de, D: Deserializer<'de>, T: Deserialize<'de>>(d: D) -> Result<Option<T>, D::Error> {
    T::deserialize(d).map(Some)
}

/// A setting: a value, or back to `helios.toml`'s.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum Setting<T> {
    Set(T),
    Configured(Empty),
}

/// `{}`, and nothing else.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Empty {}

/// The Control API's `Source` union.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "snake_case")]
enum SourceArg {
    Camera(CameraArg),
    Rtmp(RtmpArg),
    Test(TestArg),
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct CameraArg {
    video: String,
    #[serde(default, deserialize_with = "present")]
    audio: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RtmpArg {
    key: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct TestArg {
    #[serde(default, deserialize_with = "present")]
    size: Option<String>,
    #[serde(default, deserialize_with = "present")]
    fps: Option<u32>,
}

/// A destination: sealed as the cloud sends it, or as the stream client passes it on.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub(crate) enum DestinationArg {
    /// As the cloud sends it; the daemon can't open it (only Helios holds the key).
    Sealed(Value),
    /// Opened by the stream client, or given on the local control socket.
    Url(String),
    /// The stream client couldn't open it.
    Unreadable(String),
}

// The model's patterns and ranges (`control.smithy`).
fn plain(value: &str, extra: &[u8], max: usize) -> bool {
    !value.is_empty()
        && value.len() <= max
        && value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || extra.contains(&b))
}

/// `DeviceSelector`: `usb:<bus>-<port>[.<port>...]`, or `<vid>:<pid>:<serial>`.
fn selector_ok(value: &str) -> bool {
    if !(5..=200).contains(&value.len()) {
        return false;
    }
    if let Some(port) = value.strip_prefix("usb:") {
        let mut parts = port.splitn(2, '-');
        let bus = parts.next().unwrap_or_default();
        let rest = parts.next().unwrap_or_default();
        let digits = |s: &str| !s.is_empty() && s.bytes().all(|b| b.is_ascii_digit());
        return digits(bus) && rest.split('.').all(digits);
    }
    let mut parts = value.splitn(3, ':');
    let hex4 = |s: Option<&str>| {
        s.is_some_and(|s| s.len() == 4 && s.bytes().all(|b| b.is_ascii_hexdigit()))
    };
    hex4(parts.next())
        && hex4(parts.next())
        && parts.next().is_some_and(|serial| {
            !serial.is_empty() && !serial.bytes().any(|b| b.is_ascii_whitespace())
        })
}

/// `RtmpKey`: `ingest`, or `ingest-<n>` for n 1 to 999. The camera number, if any.
fn rtmp_camera(key: &str) -> Result<Option<u32>, ()> {
    match key.strip_prefix("ingest") {
        Some("") => Ok(None),
        Some(rest) => rest
            .strip_prefix('-')
            .filter(|n| (1..=3).contains(&n.len()) && !n.starts_with('0'))
            .and_then(|n| n.parse().ok())
            .map(Some)
            .ok_or(()),
        None => Err(()),
    }
}

/// `WIDTHxHEIGHT` with 2 to 4 digits each.
fn size_ok(size: &str) -> bool {
    let digits = |s: &str| (2..=4).contains(&s.len()) && s.bytes().all(|b| b.is_ascii_digit());
    size.split_once('x')
        .is_some_and(|(w, h)| digits(w) && digits(h))
}

impl UpdateArgs {
    /// Parses and checks `args` against the model: anything else is `INVALID_MESSAGE`.
    pub(crate) fn parse(args: &Value) -> Result<Self, String> {
        let parsed: Self = serde_json::from_value(args.clone())
            .map_err(|error| format!("stream.update: {error}"))?;
        parsed
            .check()
            .map_err(|why| format!("stream.update: {why}"))?;
        Ok(parsed)
    }

    fn check(&self) -> Result<(), &'static str> {
        if !plain(&self.stream_id, b"_-", 64) {
            return Err("stream_id must be 1 to 64 letters, digits, _ or -");
        }
        if let Some(Setting::Set(source)) = &self.source {
            match source {
                SourceArg::Camera(camera) => {
                    if !selector_ok(&camera.video)
                        || camera.audio.as_deref().is_some_and(|a| !selector_ok(a))
                    {
                        return Err(
                            "a camera's video and audio are usb:<port> or <vid>:<pid>:<serial>",
                        );
                    }
                }
                SourceArg::Rtmp(rtmp) => {
                    if rtmp_camera(&rtmp.key).is_err() {
                        return Err("an RTMP key is ingest or ingest-<1-999>");
                    }
                }
                SourceArg::Test(test) => {
                    if test.size.as_deref().is_some_and(|s| !size_ok(s)) {
                        return Err("a test pattern's size is WIDTHxHEIGHT");
                    }
                    if test.fps.is_some_and(|fps| !(1..=120).contains(&fps)) {
                        return Err("a test pattern's fps is 1 to 120");
                    }
                }
            }
        }
        if let Some(Setting::Set(profile)) = &self.profile
            && !plain(profile, b"_-", 64)
        {
            return Err("a profile is 1 to 64 letters, digits, _ or -");
        }
        if let Some(Setting::Set(DestinationArg::Sealed(sealed))) = &self.destination {
            let part = |name: &str| {
                sealed
                    .get(name)
                    .and_then(Value::as_str)
                    .is_some_and(|s| !s.is_empty())
            };
            if !sealed.is_object()
                || sealed.as_object().is_some_and(|o| o.len() != 2)
                || !part("enc")
                || !part("ct")
            {
                return Err("a sealed destination is {\"sealed\": {\"enc\", \"ct\"}}");
            }
        }
        if let Some(Setting::Set(kbps)) = self.bitrate
            && !(100..=100_000).contains(&kbps)
        {
            return Err("a bitrate is 100 to 100000 kbps");
        }
        if let Some(Setting::Set(percent)) = self.source_ceiling_percent
            && percent > 400
        {
            return Err("source_ceiling_percent is 0 to 400");
        }
        Ok(())
    }
}

impl SourceArg {
    fn into_source(self) -> Source {
        match self {
            Self::Camera(CameraArg { video, audio }) => Source::Camera { video, audio },
            Self::Rtmp(RtmpArg { key }) => Source::Rtmp {
                camera: rtmp_camera(&key).unwrap_or(None),
            },
            Self::Test(TestArg { size, fps }) => Source::Test {
                size: size.unwrap_or_else(super::settings::default_test_size),
                fps: fps.unwrap_or_else(super::settings::default_test_fps),
            },
        }
    }
}

impl Streams<'_> {
    /// `stream.update`.
    pub(crate) fn update(&mut self, args: &Value, ctx: &ModuleContext) -> Outcome {
        let args = match UpdateArgs::parse(args) {
            Ok(args) => args,
            Err(why) => return Outcome::error(codes::INVALID_MESSAGE, why),
        };
        let Some(index) = self
            .entries
            .iter()
            .position(|entry| entry.id == args.stream_id)
        else {
            return Outcome::error(
                codes::INVALID_MESSAGE,
                format!("no stream {:?}", args.stream_id),
            );
        };
        let given = [
            ("source", args.source.is_some()),
            ("profile", args.profile.is_some()),
            ("destination", args.destination.is_some()),
            ("bitrate", args.bitrate.is_some()),
            (
                "source_ceiling_percent",
                args.source_ceiling_percent.is_some(),
            ),
            ("record", args.record.is_some()),
        ];
        let settings = &self.module.settings;
        let entry = &self.entries[index];
        let mut refused: Vec<(&'static str, String)> = Vec::new();

        // Source and profile together: the profile is checked against the new source.
        let mut candidate = entry.config.clone();
        match args.source {
            Some(Setting::Set(source)) => candidate.source = source.into_source(),
            Some(Setting::Configured(_)) => candidate.source = entry.configured.source.clone(),
            None => {}
        }
        match args.profile {
            Some(Setting::Set(ref profile)) => candidate.profile = profile.clone(),
            Some(Setting::Configured(_)) => candidate.profile = entry.configured.profile.clone(),
            None => {}
        }
        let new_settings =
            candidate.source != entry.config.source || candidate.profile != entry.config.profile;
        if new_settings && let Err(reason) = self.check(index, &candidate) {
            let profile_changed = candidate.profile != entry.config.profile;
            let setting = if args.profile.is_some() && profile_changed {
                "profile"
            } else {
                "source"
            };
            refused.push((setting, reason));
        }

        let destination = match args.destination {
            None => None,
            Some(Setting::Configured(_)) => Some(None),
            Some(Setting::Set(DestinationArg::Url(url))) => {
                match self.destination_for(index, &Value::String(url)) {
                    Ok(destination) => Some(destination),
                    Err(reason) => {
                        refused.push(("destination", reason));
                        None
                    }
                }
            }
            Some(Setting::Set(DestinationArg::Unreadable(reason))) => {
                refused.push(("destination", reason));
                None
            }
            Some(Setting::Set(DestinationArg::Sealed(_))) => {
                refused.push((
                    "destination",
                    "the sealed destination wasn't opened (only Helios can open it)".into(),
                ));
                None
            }
        };

        let profile = settings.profiles.get(&candidate.profile);
        let bitrate = match args.bitrate {
            None => BitrateChange::Keep,
            Some(Setting::Configured(_)) => BitrateChange::Profile,
            Some(Setting::Set(kbps)) => match profile {
                Some(profile) if profile.video == "copy" => {
                    refused.push((
                        "bitrate",
                        format!(
                            "profile {:?} copies the video: no bitrate to set",
                            candidate.profile
                        ),
                    ));
                    BitrateChange::Keep
                }
                Some(profile) if profile.bitrate_kbps == kbps => BitrateChange::Profile,
                Some(profile)
                    if (profile.min_bitrate_kbps..=profile.max_bitrate_kbps).contains(&kbps) =>
                {
                    BitrateChange::Override(kbps)
                }
                Some(profile) => {
                    refused.push((
                        "bitrate",
                        format!(
                            "{kbps} kbps is outside the profile's limits ({}-{})",
                            profile.min_bitrate_kbps, profile.max_bitrate_kbps
                        ),
                    ));
                    BitrateChange::Keep
                }
                // The profile itself is refused above.
                None => BitrateChange::Keep,
            },
        };

        if !refused.is_empty() {
            let refused: Vec<Value> = refused
                .into_iter()
                .map(|(setting, reason)| json!({"setting": setting, "reason": reason}))
                .collect();
            tracing::info!(stream = %args.stream_id, ?refused, "stream.update refused");
            return Outcome::Ok(json!({
                "status": self.entries[index].status(settings, false),
                "refused": refused,
            }));
        }

        // Everything checks: apply it all.
        let mut reconfigured = new_settings;
        if new_settings {
            let entry = &mut self.entries[index];
            entry.config.source = candidate.source;
            entry.config.profile = candidate.profile;
        }
        if let Some(destination) = destination {
            let new = destination.as_ref().map(|(d, _)| d.url());
            if new
                != self.entries[index]
                    .destination
                    .as_ref()
                    .map(|(d, _)| d.url())
            {
                self.set_destination(index, destination);
                reconfigured = true;
            }
        }
        if let Some(ceiling) = args.source_ceiling_percent {
            let percent = match ceiling {
                Setting::Set(percent) => Some(percent),
                Setting::Configured(_) => None,
            };
            if percent != self.entries[index].ceiling_override {
                self.set_ceiling(index, percent);
            }
        }
        if let Some(record) = args.record {
            let entry = &mut self.entries[index];
            let before = entry.record();
            entry.record_override = match record {
                Setting::Set(on) => Some(on),
                Setting::Configured(_) => None,
            };
            if entry.record() != before {
                tracing::info!(stream = %entry.id, record = entry.record(), "recording switched by stream.update");
                entry.record_error = None;
                // The encoder starts again with or without its recording branch.
                if !reconfigured && entry.job.is_some() {
                    self.stop_job(index);
                }
            }
        }
        for (setting, given) in given {
            if given {
                self.accept(index, setting);
            }
        }
        if reconfigured {
            tracing::info!(stream = %args.stream_id, "new settings from stream.update");
            self.reconfigure(index, ctx);
        }
        if bitrate != BitrateChange::Keep {
            let live = self.entries[index].desired_live;
            self.set_live(index, live, bitrate);
        }
        Outcome::Ok(json!({"status": self.entries[index].status(&self.module.settings, false)}))
    }
}
