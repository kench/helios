//! The `display` module (LLD 9): screens on the scanner's framebuffer.
//!
//! It shows one screen at a time: the most recent `display.show` until it expires or is cleared,
//! otherwise the idle screen, which `display.idle` can change until Helios restarts. The idle
//! `status` screen follows the MQTT connection and shows the clock in the configured time zone.
//! Writes go only to the rows that changed. On shutdown it shows "Helios stopped", so the screen
//! never shows stale information.
//!
//! Commands (`helios/<thing>/cmd/display`): `show` (`template`, `fields`, `duration_s`), `clear`,
//! `idle` and `status`. `idle` (AWS IoT command `helios-display-idle-v1`, helios-contract
//! `model/device.smithy`) takes `{"idle": {"set": {"<template>": {fields}}}}` or
//! `{"idle": {"configured": {}}}` and answers `{"status": ...}`; arguments outside the model are
//! `INVALID_MESSAGE` and change nothing. The `display` shadow is reported-only (the page "Helios -
//! State Management: Tenets and Practices").

pub mod canvas;
pub mod fb;
pub mod templates;
pub mod text;

use std::net::{IpAddr, UdpSocket};
use std::path::PathBuf;
use std::time::{Duration, SystemTime};

use jiff::Timestamp;
use jiff::tz::TimeZone;
use serde_json::{Map, Value, json};
use tokio::sync::{mpsc, watch};
use tokio::task::JoinHandle;
use tokio::time::Instant;
use tokio_util::sync::CancellationToken;

use crate::backoff::Backoff;
use crate::modules::{Module, ModuleContext, ModuleFuture};
use crate::mqtt::manager::MqttStatus;
use crate::mqtt::shadow::ShadowHandle;
use crate::router::{Outcome, PendingCommand, codes};

use canvas::{Canvas, Color};
use fb::{Framebuffer, Geometry};
use templates::{Screen, StatusInfo};
use text::{Align, Fonts, Style, TextBox, Weight};

/// The module name: commands, shadow and config section.
pub const MODULE: &str = "display";

/// The longest `display.show` duration: a day.
const MAX_DURATION_S: u64 = 86_400;

/// The checked `[modules.display]` settings.
#[derive(Debug, Clone)]
pub struct DisplaySettings {
    /// The framebuffer device.
    pub framebuffer: PathBuf,
    /// The idle screen until `display.idle` sets one.
    pub idle: Screen,
    /// The clock's time zone, by name.
    pub time_zone_name: String,
    /// The clock's time zone.
    pub time_zone: TimeZone,
    /// How often to redraw while the kernel's console is still attached; zero for never.
    pub redraw_interval: Duration,
    /// A font file for bold text in place of the built-in Noto Sans Bold, read at start. For
    /// licensed fonts kept on the device rather than compiled in.
    pub bold_font: Option<PathBuf>,
}

/// Where the module gets and sends things.
#[derive(Debug)]
pub struct Inputs {
    /// Commands from the router (`RouterHandle::register("display")`).
    pub commands: mpsc::Receiver<PendingCommand>,
    /// For the `display` shadow's reported state.
    pub shadows: ShadowHandle,
    /// The MQTT connection, for the idle screen.
    pub mqtt: watch::Receiver<MqttStatus>,
    /// Normally `/sys`.
    pub sysfs: PathBuf,
}

/// The display module, for the supervisor. The fonts are loaded once, when it's created; each
/// run starts from them with a fresh screen state.
pub struct DisplayModule {
    settings: DisplaySettings,
    fonts: Fonts,
    /// The configured bold font and whether it loaded; null for the built-in one.
    bold_font: Value,
}

impl DisplayModule {
    /// Loads the fonts, and the configured bold font if there is one. A bold font that can't be
    /// read or parsed is reported in the shadow, and the built-in one is used.
    ///
    /// # Errors
    ///
    /// If the compiled-in fonts can't be loaded.
    pub fn new(settings: DisplaySettings) -> Result<Self, String> {
        let mut fonts = Fonts::load()?;
        let bold_font = settings.bold_font.as_ref().map_or(Value::Null, |path| {
            let loaded = std::fs::read(path)
                .map_err(|error| format!("can't read it: {error}"))
                .and_then(|bytes| fonts.replace_bold(bytes));
            match loaded {
                Ok(()) => {
                    tracing::info!(path = %path.display(), "bold font loaded");
                    json!({"path": path, "error": null})
                }
                Err(error) => {
                    tracing::warn!(
                        path = %path.display(),
                        %error,
                        "bold font not loaded; using the built-in Noto Sans Bold"
                    );
                    json!({"path": path, "error": error})
                }
            }
        });
        Ok(Self {
            settings,
            fonts,
            bold_font,
        })
    }

    fn display(&self, inputs: Inputs) -> Display {
        let mut display = Display::new(self.settings.clone(), inputs, self.fonts.clone());
        display.bold_font = self.bold_font.clone();
        display
    }
}

impl Module for DisplayModule {
    fn name(&self) -> &'static str {
        MODULE
    }

    fn run(&self, ctx: ModuleContext) -> ModuleFuture<'_> {
        Box::pin(async move {
            let inputs = Inputs {
                commands: ctx.commands,
                shadows: ctx.shadows,
                mqtt: ctx.mqtt.status(),
                sysfs: ctx.sysfs,
            };
            self.display(inputs).run(ctx.cancel).await;
            Ok(())
        })
    }
}

/// Starts the display module outside the supervisor. It runs until `cancel` is cancelled, then
/// shows "Helios stopped" and ends, so await the handle before exiting.
///
/// # Errors
///
/// If the compiled-in fonts can't be loaded.
///
/// # Panics
///
/// Panics if called outside a tokio runtime.
pub fn start(
    settings: DisplaySettings,
    inputs: Inputs,
    cancel: CancellationToken,
) -> Result<JoinHandle<()>, String> {
    let module = DisplayModule::new(settings)?;
    Ok(tokio::spawn(module.display(inputs).run(cancel)))
}

/// What's on screen, or should be.
#[derive(Debug, Clone)]
struct Shown {
    screen: Screen,
    at: SystemTime,
    /// When it goes back to the idle screen: by the monotonic clock, and as a time to report.
    until: Option<(Instant, SystemTime)>,
}

struct Display {
    settings: DisplaySettings,
    inputs: Inputs,
    fonts: Fonts,
    framebuffer: Option<Framebuffer>,
    /// When to try opening the framebuffer again.
    retry_at: Instant,
    backoff: Backoff,
    console_bound: bool,
    /// The idle screen, from config or `display.idle`.
    idle: Screen,
    /// The last `display.show`, while it lasts.
    shown: Option<Shown>,
    /// When the idle screen started showing.
    idle_since: SystemTime,
    /// Why the screen can't be used.
    error: Option<String>,
    /// The last state reported, to report only changes.
    reported: Option<Map<String, Value>>,
    /// The configured bold font and whether it loaded; null for the built-in one.
    bold_font: Value,
}

impl Display {
    fn new(settings: DisplaySettings, inputs: Inputs, fonts: Fonts) -> Self {
        Self {
            idle: settings.idle.clone(),
            settings,
            inputs,
            fonts,
            framebuffer: None,
            retry_at: Instant::now(),
            backoff: Backoff::new(Duration::from_secs(1), Duration::from_secs(60)),
            console_bound: false,
            shown: None,
            idle_since: SystemTime::now(),
            error: None,
            reported: None,
            bold_font: Value::Null,
        }
    }

    async fn run(mut self, cancel: CancellationToken) {
        let mut commands_open = true;
        let mut mqtt_open = true;
        loop {
            self.expire(Instant::now());
            if self.framebuffer.is_none() && Instant::now() >= self.retry_at {
                self.open();
            }
            self.report();
            let wake = self.next_wake(Instant::now(), SystemTime::now());
            tokio::select! {
                biased;
                () = cancel.cancelled() => {
                    self.draw_stopped();
                    return;
                }
                command = self.inputs.commands.recv(), if commands_open => match command {
                    Some(pending) => {
                        let outcome = self.command(&pending.command.name, &pending.command.args);
                        pending.respond(outcome);
                    }
                    None => commands_open = false,
                },
                changed = self.inputs.mqtt.changed(), if mqtt_open => {
                    if changed.is_err() {
                        mqtt_open = false;
                    } else if self.current().has_clock() {
                        self.draw(false);
                    }
                }
                () = tokio::time::sleep_until(wake) => {
                    if self.current().has_clock() || self.console_bound {
                        self.draw(self.console_bound);
                    }
                }
            }
        }
    }

    /// The screen that should be showing.
    fn current(&self) -> &Screen {
        self.shown
            .as_ref()
            .map_or(&self.idle, |shown| &shown.screen)
    }

    /// Goes back to the idle screen once a timed screen has run out.
    fn expire(&mut self, now: Instant) {
        if let Some(Shown {
            until: Some((until, _)),
            ..
        }) = self.shown
            && now >= until
        {
            tracing::debug!("timed screen expired; back to the idle screen");
            self.shown = None;
            self.idle_since = SystemTime::now();
            self.draw(false);
        }
    }

    /// The next time something needs doing: a timed screen running out, the clock's next
    /// minute, a redraw while the console is attached, or another try at the framebuffer.
    fn next_wake(&self, now: Instant, wall: SystemTime) -> Instant {
        let mut wake = now + Duration::from_secs(3600);
        if let Some(Shown {
            until: Some((until, _)),
            ..
        }) = self.shown
        {
            wake = wake.min(until);
        }
        if self.current().has_clock() {
            let into_minute =
                wall.duration_since(SystemTime::UNIX_EPOCH)
                    .map_or(Duration::ZERO, |since| {
                        Duration::from_millis(u64::from(
                            u32::try_from(since.as_millis() % 60_000).unwrap_or(0),
                        ))
                    });
            wake = wake.min(now + (Duration::from_secs(60) - into_minute));
        }
        if self.console_bound && !self.settings.redraw_interval.is_zero() {
            wake = wake.min(now + self.settings.redraw_interval);
        }
        if self.framebuffer.is_none() {
            wake = wake.min(self.retry_at);
        }
        wake
    }

    /// Opens the framebuffer and draws the current screen; on failure, reports why and tries
    /// again later.
    fn open(&mut self) {
        let path = self.settings.framebuffer.clone();
        let opened = Geometry::read(&self.inputs.sysfs, &path).and_then(|geometry| {
            Framebuffer::open(&path, geometry)
                .map_err(|error| format!("can't open {}: {error}", path.display()))
        });
        match opened {
            Ok(framebuffer) => {
                let g = framebuffer.geometry();
                tracing::info!(
                    framebuffer = %path.display(),
                    width = g.width,
                    height = g.height,
                    stride = g.stride,
                    "display ready"
                );
                self.framebuffer = Some(framebuffer);
                self.backoff.reset();
                self.error = None;
                self.console_bound = fb::console_bound(&self.inputs.sysfs);
                if self.console_bound {
                    tracing::warn!(
                        "the kernel's console is attached to the framebuffer and may draw over \
                         the screen; redrawing every {:?}",
                        self.settings.redraw_interval
                    );
                }
                self.draw(true);
            }
            Err(error) => {
                let delay = self.backoff.next_delay();
                tracing::warn!(%error, retry_in = ?delay, "display not available");
                self.error = Some(error);
                self.retry_at = Instant::now() + delay;
            }
        }
    }

    /// Draws the current screen.
    fn draw(&mut self, force: bool) {
        let screen = self.current().clone();
        self.draw_screen(&screen, force);
    }

    fn draw_screen(&mut self, screen: &Screen, force: bool) {
        let Some(framebuffer) = self.framebuffer.as_mut() else {
            return;
        };
        let geometry = framebuffer.geometry();
        let mut canvas = Canvas::new(geometry.width, geometry.height);
        let status = status_info(
            &self.inputs.mqtt.borrow(),
            &self.settings.time_zone,
            SystemTime::now(),
            default_route_address(),
        );
        templates::render(screen, &status, &mut canvas, &mut self.fonts);
        if let Err(error) = framebuffer.write(&canvas, force) {
            tracing::warn!(%error, "can't write to the display");
            self.error = Some(format!("can't write to the display: {error}"));
            self.framebuffer = None;
            self.retry_at = Instant::now() + self.backoff.next_delay();
        }
    }

    /// The screen shown when Helios stops.
    fn draw_stopped(&mut self) {
        let Some(framebuffer) = self.framebuffer.as_mut() else {
            return;
        };
        let geometry = framebuffer.geometry();
        let mut canvas = Canvas::new(geometry.width, geometry.height);
        canvas.clear(Color::rgb(18, 22, 30));
        let scale = geometry.height as f32 / 480.0;
        let style = Style {
            size: 40.0 * scale,
            weight: Weight::Bold,
            color: Color::rgb(150, 160, 175),
            align: Align::Center,
            max_lines: 1,
        };
        let area = TextBox {
            x: 0,
            y: (210.0 * scale) as i64,
            width: geometry.width as f32,
        };
        self.fonts.draw(&mut canvas, "Helios stopped", area, &style);
        match framebuffer.write(&canvas, false) {
            Ok(_) => tracing::info!("display shows that Helios stopped"),
            Err(error) => tracing::warn!(%error, "can't write to the display"),
        }
    }

    fn command(&mut self, name: &str, args: &Value) -> Outcome {
        match name {
            "show" => match show_request(args) {
                Ok((screen, duration)) => {
                    let now = SystemTime::now();
                    let until = duration.map(|d| (Instant::now() + d, now + d));
                    tracing::info!(template = screen.template(), ?duration, "showing a screen");
                    self.shown = Some(Shown {
                        screen,
                        at: now,
                        until,
                    });
                    self.draw(false);
                    self.report();
                    Outcome::Ok(self.state())
                }
                Err(message) => Outcome::error(codes::INVALID_MESSAGE, message),
            },
            "clear" => {
                if self.shown.take().is_some() {
                    self.idle_since = SystemTime::now();
                    self.draw(false);
                    self.report();
                }
                Outcome::Ok(self.state())
            }
            "idle" => match idle_request(args, &self.settings.idle) {
                Ok(screen) => {
                    tracing::info!(template = screen.template(), "idle screen set");
                    if screen != self.idle {
                        self.idle = screen;
                        self.idle_since = SystemTime::now();
                        if self.shown.is_none() {
                            self.draw(false);
                        }
                    }
                    self.report();
                    Outcome::Ok(json!({"status": self.state()}))
                }
                Err(message) => Outcome::error(codes::INVALID_MESSAGE, message),
            },
            "status" => Outcome::Ok(self.state()),
            other => Outcome::error(
                codes::UNKNOWN_COMMAND,
                format!("no command display.{other}"),
            ),
        }
    }

    /// The `display` shadow's reported state, also the commands' result.
    fn state(&self) -> Value {
        let (template, at, until) = match &self.shown {
            Some(shown) => (
                shown.screen.template(),
                shown.at,
                shown.until.map(|(_, until)| until),
            ),
            None => (self.idle.template(), self.idle_since, None),
        };
        let geometry = self.framebuffer.as_ref().map(|framebuffer| {
            let g = framebuffer.geometry();
            json!({
                "width": g.width,
                "height": g.height,
                "bits_per_pixel": g.bits_per_pixel,
                "stride": g.stride,
            })
        });
        json!({
            "template": template,
            "shown_at": time(at),
            "until": until.map(time),
            "idle": self.idle.template(),
            "available": self.framebuffer.is_some(),
            "geometry": geometry,
            "console_bound": self.console_bound,
            "time_zone": self.settings.time_zone_name,
            "bold_font": self.bold_font,
            "error": self.error,
        })
    }

    /// Reports the state to the `display` shadow when it changed.
    fn report(&mut self) {
        let Value::Object(state) = self.state() else {
            return;
        };
        if self.reported.as_ref() != Some(&state) {
            self.inputs.shadows.report(MODULE, state.clone());
            self.reported = Some(state);
        }
    }
}

/// The idle screen a `display.idle` command's arguments ask for (helios-contract `DisplayIdle`):
/// `{"idle": {"set": {"<template>": {fields}}}}`, or `{"idle": {"configured": {}}}` for
/// `configured`, `helios.toml`'s.
fn idle_request(args: &Value, configured: &Screen) -> Result<Screen, String> {
    /// The one member of `value`, an object that must have exactly one.
    fn only<'a>(value: &'a Value, what: &str) -> Result<(&'a str, &'a Value), String> {
        match value.as_object() {
            Some(object) if object.len() == 1 => object
                .iter()
                .next()
                .map(|(key, value)| (key.as_str(), value))
                .ok_or_else(|| format!("{what} needs exactly one member")),
            _ => Err(format!("{what} needs exactly one member")),
        }
    }
    let Value::Object(members) = args else {
        return Err("display.idle needs an object with idle".to_owned());
    };
    if let Some(unknown) = members.keys().find(|key| key.as_str() != "idle") {
        return Err(format!("display.idle has no argument {unknown:?}"));
    }
    let idle = members
        .get("idle")
        .ok_or("display.idle needs idle: {\"set\": screen} or {\"configured\": {}}")?;
    match only(idle, "idle")? {
        ("configured", Value::Object(empty)) if empty.is_empty() => Ok(configured.clone()),
        ("set", screen) => {
            let (template, fields) = only(screen, "a screen")?;
            if !fields.is_object() {
                return Err(format!("the {template} screen's fields must be an object"));
            }
            Screen::parse(template, fields)
        }
        _ => Err("idle is {\"set\": screen} or {\"configured\": {}}".to_owned()),
    }
}

/// The screen and duration from a `display.show` command's arguments.
fn show_request(args: &Value) -> Result<(Screen, Option<Duration>), String> {
    let Value::Object(args) = args else {
        return Err("display.show needs an object with template".to_owned());
    };
    if let Some(unknown) = args
        .keys()
        .find(|key| !["template", "fields", "duration_s"].contains(&key.as_str()))
    {
        return Err(format!("display.show has no argument {unknown:?}"));
    }
    let template = args
        .get("template")
        .and_then(Value::as_str)
        .ok_or("display.show needs template, a string")?;
    let screen = Screen::parse(template, args.get("fields").unwrap_or(&Value::Null))?;
    let duration = match args.get("duration_s") {
        None | Some(Value::Null) => None,
        Some(value) => match value.as_u64() {
            Some(seconds @ 1..=MAX_DURATION_S) => Some(Duration::from_secs(seconds)),
            _ => {
                return Err(format!(
                    "duration_s must be a whole number from 1 to {MAX_DURATION_S}"
                ));
            }
        },
    };
    Ok((screen, duration))
}

/// What the idle screen shows at `now`.
fn status_info(
    mqtt: &MqttStatus,
    time_zone: &TimeZone,
    now: SystemTime,
    address: Option<IpAddr>,
) -> StatusInfo {
    let local = |at: SystemTime, format: &str| {
        Timestamp::try_from(at).map_or_else(
            |_| String::new(),
            |at| {
                at.to_zoned_datetime(time_zone.clone())
                    .strftime(format)
                    .to_string()
            },
        )
    };
    StatusInfo {
        thing: mqtt.thing.clone(),
        connected: mqtt.connected,
        connected_since: mqtt
            .connected_at
            .filter(|_| mqtt.connected)
            .map(|at| local(at, "%H:%M")),
        address,
        time: local(now, "%H:%M"),
        date: local(now, "%a %-d %b %Y"),
        zone: local(now, "%Z"),
        version: env!("CARGO_PKG_VERSION").to_owned(),
    }
}

/// The address the device would use to reach the internet: the source address of a UDP socket
/// connected to a documentation address. No packet is sent.
fn default_route_address() -> Option<IpAddr> {
    let socket = UdpSocket::bind("0.0.0.0:0").ok()?;
    socket.connect("192.0.2.1:9").ok()?;
    let address = socket.local_addr().ok()?.ip();
    (!address.is_unspecified()).then_some(address)
}

fn time(at: SystemTime) -> Value {
    Timestamp::try_from(at).map_or(Value::Null, |at| Value::String(at.to_string()))
}

#[cfg(test)]
mod tests;
