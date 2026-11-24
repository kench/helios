//! The screens (LLD 9, section 6): templates compiled into Helios. The cloud picks one and fills
//! in its fields, which are checked here; it never sends layouts or images.
//!
//! Layouts are designed for the scanner's 800×480 screen and scale with its height.

use std::net::IpAddr;

use serde_json::{Map, Value};

use super::canvas::{Canvas, Color};
use super::text::{Align, Fonts, Style, TextBox, Weight};

/// Maximum lengths, in characters.
const TITLE_MAX: usize = 40;
const MESSAGE_BODY_MAX: usize = 300;
const RESULT_BODY_MAX: usize = 160;

const BACKGROUND: Color = Color::rgb(18, 22, 30);
const MUTED: Color = Color::rgb(150, 160, 175);
const GREEN: Color = Color::rgb(30, 160, 80);
const RED: Color = Color::rgb(200, 45, 45);
const AMBER: Color = Color::rgb(230, 160, 20);
const BLUE: Color = Color::rgb(40, 120, 210);

/// A message's severity, which sets its colour and icon.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Severity {
    /// Information (blue).
    Info,
    /// Something worked (green).
    Success,
    /// A warning (amber).
    Warning,
    /// An error (red).
    Error,
}

/// A screen to show, with its checked fields.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Screen {
    /// The idle screen: device name, connection, address, clock and version.
    Status,
    /// A message from the cloud.
    Message {
        /// The title.
        title: String,
        /// The body, possibly empty.
        body: String,
        /// The severity.
        severity: Severity,
    },
    /// An accepted or rejected result, such as a scan.
    Result {
        /// Whether it was accepted.
        accepted: bool,
        /// The title, possibly empty.
        title: String,
        /// The body, possibly empty.
        body: String,
    },
    /// A black screen.
    Blank,
    /// Colour bars, a grid and the geometry, for checking colours and alignment.
    Test,
}

impl Screen {
    /// The template's name.
    #[must_use]
    pub fn template(&self) -> &'static str {
        match self {
            Self::Status => "status",
            Self::Message { .. } => "message",
            Self::Result { .. } => "result",
            Self::Blank => "blank",
            Self::Test => "test",
        }
    }

    /// Whether the screen shows the clock, so it needs redrawing every minute.
    #[must_use]
    pub fn has_clock(&self) -> bool {
        matches!(self, Self::Status)
    }

    /// The screen `template` with `fields` (a JSON object, or null for none).
    ///
    /// # Errors
    ///
    /// A message naming the template or field: unknown templates, unknown, missing or
    /// over-long fields, and values of the wrong type.
    pub fn parse(template: &str, fields: &Value) -> Result<Self, String> {
        let empty = Map::new();
        let fields = match fields {
            Value::Null => &empty,
            Value::Object(fields) => fields,
            _ => return Err("fields must be an object".to_owned()),
        };
        let allowed: &[&str] = match template {
            "status" | "blank" | "test" => &[],
            "message" => &["title", "body", "severity"],
            "result" => &["outcome", "title", "body"],
            other => return Err(format!("no template {other:?}")),
        };
        if let Some(unknown) = fields.keys().find(|key| !allowed.contains(&key.as_str())) {
            return Err(format!("template {template} has no field {unknown:?}"));
        }
        Ok(match template {
            "status" => Self::Status,
            "blank" => Self::Blank,
            "test" => Self::Test,
            "message" => Self::Message {
                title: text(fields, "title", TITLE_MAX, true)?,
                body: text(fields, "body", MESSAGE_BODY_MAX, false)?,
                severity: match optional_str(fields, "severity")?.unwrap_or("info") {
                    "info" => Severity::Info,
                    "success" => Severity::Success,
                    "warning" => Severity::Warning,
                    "error" => Severity::Error,
                    other => {
                        return Err(format!(
                            "severity must be info, success, warning or error, not {other:?}"
                        ));
                    }
                },
            },
            _ => Self::Result {
                accepted: match optional_str(fields, "outcome")? {
                    Some("accepted") => true,
                    Some("rejected") => false,
                    Some(other) => {
                        return Err(format!(
                            "outcome must be accepted or rejected, not {other:?}"
                        ));
                    }
                    None => return Err("template result needs the field outcome".to_owned()),
                },
                title: text(fields, "title", TITLE_MAX, false)?,
                body: text(fields, "body", RESULT_BODY_MAX, false)?,
            },
        })
    }
}

fn optional_str<'a>(fields: &'a Map<String, Value>, name: &str) -> Result<Option<&'a str>, String> {
    match fields.get(name) {
        None | Some(Value::Null) => Ok(None),
        Some(Value::String(value)) => Ok(Some(value)),
        Some(_) => Err(format!("field {name} must be a string")),
    }
}

/// A text field: control characters removed (line breaks kept), at most `max` characters.
fn text(
    fields: &Map<String, Value>,
    name: &str,
    max: usize,
    required: bool,
) -> Result<String, String> {
    let value = optional_str(fields, name)?.unwrap_or_default();
    let cleaned: String = value
        .chars()
        .filter(|c| *c == '\n' || !c.is_control())
        .collect();
    let cleaned = cleaned.trim().to_owned();
    if required && cleaned.is_empty() {
        return Err(format!("field {name} is required"));
    }
    let length = cleaned.chars().count();
    if length > max {
        return Err(format!(
            "field {name} is {length} characters; the limit is {max}"
        ));
    }
    Ok(cleaned)
}

/// What the idle screen shows, gathered by the module.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StatusInfo {
    /// The thing name, once known.
    pub thing: Option<String>,
    /// Whether MQTT is connected.
    pub connected: bool,
    /// When the connection came up, as local time ("14:02").
    pub connected_since: Option<String>,
    /// The device's address on its default route.
    pub address: Option<IpAddr>,
    /// The time ("14:05").
    pub time: String,
    /// The date ("Sat 21 Nov 2026").
    pub date: String,
    /// The time zone's abbreviation ("PST").
    pub zone: String,
    /// The Helios version.
    pub version: String,
}

/// Draws `screen` on `canvas`.
pub fn render(screen: &Screen, status: &StatusInfo, canvas: &mut Canvas, fonts: &mut Fonts) {
    let layout = Layout::new(canvas);
    match screen {
        Screen::Status => draw_status(status, canvas, fonts, &layout),
        Screen::Message {
            title,
            body,
            severity,
        } => draw_message(title, body, *severity, canvas, fonts, &layout),
        Screen::Result {
            accepted,
            title,
            body,
        } => draw_result(*accepted, title, body, canvas, fonts, &layout),
        Screen::Blank => canvas.clear(Color::BLACK),
        Screen::Test => draw_test(canvas, fonts, &layout),
    }
}

/// Positions scaled to the screen: designed for 800×480.
struct Layout {
    width: f32,
    height: f32,
    scale: f32,
}

impl Layout {
    fn new(canvas: &Canvas) -> Self {
        let width = canvas.width() as f32;
        let height = canvas.height() as f32;
        Self {
            width,
            height,
            scale: (height / 480.0).min(width / 800.0),
        }
    }

    /// `value` design pixels in screen pixels.
    fn px(&self, value: f32) -> f32 {
        value * self.scale
    }

    fn margin(&self) -> f32 {
        self.px(32.0)
    }

    /// A full-width text box at `y` design pixels, inside the margins.
    fn row(&self, y: f32) -> TextBox {
        TextBox {
            x: self.margin() as i64,
            y: self.px(y) as i64,
            width: self.width - 2.0 * self.margin(),
        }
    }

    fn style(&self, size: f32, weight: Weight, color: Color, align: Align, lines: usize) -> Style {
        Style {
            size: self.px(size),
            weight,
            color,
            align,
            max_lines: lines,
        }
    }
}

fn draw_status(status: &StatusInfo, canvas: &mut Canvas, fonts: &mut Fonts, layout: &Layout) {
    canvas.clear(BACKGROUND);
    let center = |size, weight, color| layout.style(size, weight, color, Align::Center, 1);

    fonts.draw(
        canvas,
        &status.time,
        layout.row(48.0),
        &center(96.0, Weight::Bold, Color::WHITE),
    );
    let date = format!("{}  {}", status.date, status.zone);
    fonts.draw(
        canvas,
        &date,
        layout.row(176.0),
        &center(28.0, Weight::Regular, MUTED),
    );

    let thing = status.thing.as_deref().unwrap_or("Not registered yet");
    fonts.draw(
        canvas,
        thing,
        layout.row(250.0),
        &center(32.0, Weight::Bold, Color::WHITE),
    );

    let (color, connection) = if status.connected {
        let since = status
            .connected_since
            .as_deref()
            .map_or(String::new(), |time| format!(" since {time}"));
        (GREEN, format!("Connected{since}"))
    } else {
        (RED, "Offline".to_owned())
    };
    let size = layout.px(28.0);
    let text_width = fonts.width(&connection, size, Weight::Regular);
    let dot = layout.px(10.0);
    let gap = layout.px(14.0);
    let total = 2.0 * dot + gap + text_width;
    let left = (layout.width - total) / 2.0;
    let y = layout.px(312.0);
    let line_height = fonts.line_height(size, Weight::Regular);
    canvas.fill_circle(
        f64::from(left + dot),
        f64::from(y + line_height / 2.0),
        f64::from(dot),
        color,
    );
    fonts.draw(
        canvas,
        &connection,
        TextBox {
            x: (left + 2.0 * dot + gap) as i64,
            y: y as i64,
            width: text_width + 2.0,
        },
        &layout.style(28.0, Weight::Regular, Color::WHITE, Align::Left, 1),
    );

    let address = status.address.map_or_else(
        || "No network address".to_owned(),
        |address| address.to_string(),
    );
    fonts.draw(
        canvas,
        &address,
        layout.row(360.0),
        &center(24.0, Weight::Regular, MUTED),
    );
    let footer = format!("Helios {}", status.version);
    fonts.draw(
        canvas,
        &footer,
        layout.row(432.0),
        &center(18.0, Weight::Regular, MUTED),
    );
}

fn draw_message(
    title: &str,
    body: &str,
    severity: Severity,
    canvas: &mut Canvas,
    fonts: &mut Fonts,
    layout: &Layout,
) {
    canvas.clear(BACKGROUND);
    let color = match severity {
        Severity::Info => BLUE,
        Severity::Success => GREEN,
        Severity::Warning => AMBER,
        Severity::Error => RED,
    };
    canvas.fill_rect(0, 0, layout.width as i64, layout.px(16.0) as i64, color);

    let radius = layout.px(36.0);
    let (cx, cy) = (layout.margin() + radius, layout.px(56.0) + radius);
    draw_icon(
        canvas,
        severity,
        f64::from(cx),
        f64::from(cy),
        f64::from(radius),
        color,
    );

    let left = cx + radius + layout.px(24.0);
    let title_box = TextBox {
        x: left as i64,
        y: (cy - layout.px(30.0)) as i64,
        width: layout.width - left - layout.margin(),
    };
    fonts.draw(
        canvas,
        title,
        title_box,
        &layout.style(44.0, Weight::Bold, Color::WHITE, Align::Left, 1),
    );
    fonts.draw(
        canvas,
        body,
        layout.row(172.0),
        &layout.style(30.0, Weight::Regular, Color::WHITE, Align::Left, 6),
    );
}

/// A severity icon: a disc in `color` with a symbol in the background colour.
fn draw_icon(canvas: &mut Canvas, severity: Severity, cx: f64, cy: f64, r: f64, color: Color) {
    let stroke = r * 0.2;
    match severity {
        Severity::Warning => {
            canvas.fill_triangle(
                (cx, cy - r),
                (cx + r * 1.1, cy + r * 0.85),
                (cx - r * 1.1, cy + r * 0.85),
                color,
            );
            canvas.line((cx, cy - r * 0.35), (cx, cy + r * 0.3), stroke, BACKGROUND);
            canvas.fill_circle(cx, cy + r * 0.6, stroke * 0.6, BACKGROUND);
        }
        Severity::Info => {
            canvas.fill_circle(cx, cy, r, color);
            canvas.fill_circle(cx, cy - r * 0.45, stroke * 0.6, BACKGROUND);
            canvas.line((cx, cy - r * 0.1), (cx, cy + r * 0.5), stroke, BACKGROUND);
        }
        Severity::Success => {
            canvas.fill_circle(cx, cy, r, color);
            draw_tick(canvas, cx, cy, r * 0.55, stroke, BACKGROUND);
        }
        Severity::Error => {
            canvas.fill_circle(cx, cy, r, color);
            draw_cross(canvas, cx, cy, r * 0.4, stroke, BACKGROUND);
        }
    }
}

fn draw_tick(canvas: &mut Canvas, cx: f64, cy: f64, size: f64, stroke: f64, color: Color) {
    let a = (cx - size * 0.8, cy + size * 0.05);
    let b = (cx - size * 0.2, cy + size * 0.6);
    let c = (cx + size * 0.85, cy - size * 0.55);
    canvas.line(a, b, stroke, color);
    canvas.line(b, c, stroke, color);
}

fn draw_cross(canvas: &mut Canvas, cx: f64, cy: f64, size: f64, stroke: f64, color: Color) {
    canvas.line(
        (cx - size, cy - size),
        (cx + size, cy + size),
        stroke,
        color,
    );
    canvas.line(
        (cx - size, cy + size),
        (cx + size, cy - size),
        stroke,
        color,
    );
}

fn draw_result(
    accepted: bool,
    title: &str,
    body: &str,
    canvas: &mut Canvas,
    fonts: &mut Fonts,
    layout: &Layout,
) {
    let color = if accepted { GREEN } else { RED };
    canvas.clear(color);
    let (cx, cy) = (f64::from(layout.width / 2.0), f64::from(layout.px(130.0)));
    let radius = f64::from(layout.px(90.0));
    canvas.fill_circle(cx, cy, radius, Color::WHITE);
    let stroke = radius * 0.18;
    if accepted {
        draw_tick(canvas, cx, cy, radius * 0.6, stroke, color);
    } else {
        draw_cross(canvas, cx, cy, radius * 0.42, stroke, color);
    }
    let default_title = if accepted { "Accepted" } else { "Rejected" };
    let title = if title.is_empty() {
        default_title
    } else {
        title
    };
    let center =
        |size, weight, lines| layout.style(size, weight, Color::WHITE, Align::Center, lines);
    fonts.draw(
        canvas,
        title,
        layout.row(244.0),
        &center(52.0, Weight::Bold, 1),
    );
    fonts.draw(
        canvas,
        body,
        layout.row(330.0),
        &center(30.0, Weight::Regular, 3),
    );
}

fn draw_test(canvas: &mut Canvas, fonts: &mut Fonts, layout: &Layout) {
    canvas.clear(Color::BLACK);
    let bars = [
        Color::WHITE,
        Color::rgb(255, 255, 0),
        Color::rgb(0, 255, 255),
        Color::rgb(0, 255, 0),
        Color::rgb(255, 0, 255),
        Color::rgb(255, 0, 0),
        Color::rgb(0, 0, 255),
        Color::BLACK,
    ];
    let bar_height = (layout.height / 2.0) as i64;
    let count = i64::try_from(bars.len()).unwrap_or(8);
    let width = layout.width as i64;
    for (i, color) in (0..).zip(bars) {
        let x0 = width * i / count;
        let x1 = width * (i + 1) / count;
        canvas.fill_rect(x0, 0, x1 - x0, bar_height, color);
    }
    let grid = Color::rgb(70, 70, 70);
    let step = layout.px(40.0).max(1.0) as usize;
    let height = layout.height as i64;
    for x in (0..layout.width as usize).step_by(step) {
        canvas.fill_rect(
            i64::try_from(x).unwrap_or(0),
            bar_height,
            1,
            height - bar_height,
            grid,
        );
    }
    for y in (bar_height as usize..layout.height as usize).step_by(step) {
        canvas.fill_rect(0, i64::try_from(y).unwrap_or(0), width, 1, grid);
    }
    let mark = layout.px(24.0) as i64;
    for (x, y) in [
        (0, 0),
        (width - mark, 0),
        (0, height - mark),
        (width - mark, height - mark),
    ] {
        canvas.fill_rect(x, y, mark, mark, RED);
    }
    let label = format!("{}×{}  32 bpp  B8G8R8A8", canvas.width(), canvas.height());
    fonts.draw(
        canvas,
        &label,
        layout.row(330.0),
        &layout.style(36.0, Weight::Bold, Color::WHITE, Align::Center, 1),
    );
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    #[test]
    fn parses_templates_and_their_fields() {
        assert_eq!(Screen::parse("status", &Value::Null), Ok(Screen::Status));
        assert_eq!(Screen::parse("blank", &json!({})), Ok(Screen::Blank));
        assert_eq!(
            Screen::parse("test", &Value::Null).map(|s| s.template()),
            Ok("test")
        );
        assert_eq!(
            Screen::parse("message", &json!({"title": " Hi\u{7} ", "body": "a\nb"})),
            Ok(Screen::Message {
                title: "Hi".to_owned(),
                body: "a\nb".to_owned(),
                severity: Severity::Info
            })
        );
        for (severity, expected) in [
            ("success", Severity::Success),
            ("warning", Severity::Warning),
            ("error", Severity::Error),
        ] {
            let screen = Screen::parse("message", &json!({"title": "x", "severity": severity}));
            assert!(matches!(screen, Ok(Screen::Message { severity, .. }) if severity == expected));
        }
        assert_eq!(
            Screen::parse("result", &json!({"outcome": "rejected"})),
            Ok(Screen::Result {
                accepted: false,
                title: String::new(),
                body: String::new()
            })
        );
        assert!(Screen::Status.has_clock());
        assert!(!Screen::Blank.has_clock());
    }

    #[test]
    fn refuses_bad_fields() {
        let long = "x".repeat(41);
        for (template, fields, expected) in [
            ("nope", json!({}), "no template"),
            ("status", json!({"title": "x"}), "has no field"),
            ("message", json!([]), "must be an object"),
            ("message", json!({}), "title is required"),
            ("message", json!({"title": 5}), "must be a string"),
            ("message", json!({"title": long}), "the limit is 40"),
            (
                "message",
                json!({"title": "x", "severity": "loud"}),
                "severity must be",
            ),
            ("result", json!({}), "needs the field outcome"),
            ("result", json!({"outcome": "maybe"}), "outcome must be"),
        ] {
            let error = Screen::parse(template, &fields).unwrap_err();
            assert!(error.contains(expected), "{template} {fields}: {error}");
        }
    }

    fn status() -> StatusInfo {
        StatusInfo {
            thing: Some("t-01M0000000000000000000TEST".to_owned()),
            connected: true,
            connected_since: Some("13:58".to_owned()),
            address: Some("192.168.5.61".parse().unwrap()),
            time: "14:05".to_owned(),
            date: "Sat 21 Nov 2026".to_owned(),
            zone: "PST".to_owned(),
            version: "0.1.0".to_owned(),
        }
    }

    /// Renders `screen` at 800×480, and saves it as a PPM image in `$HELIOS_SCREENS` if set,
    /// for looking at the layouts.
    fn rendered(name: &str, screen: &Screen, status: &StatusInfo) -> Canvas {
        let mut fonts = Fonts::load().unwrap();
        let mut canvas = Canvas::new(800, 480);
        render(screen, status, &mut canvas, &mut fonts);
        if let Some(dir) = std::env::var_os("HELIOS_SCREENS") {
            let mut ppm = format!("P6\n{} {}\n255\n", canvas.width(), canvas.height()).into_bytes();
            for pixel in canvas.bytes().as_chunks::<4>().0 {
                ppm.extend_from_slice(&[pixel[2], pixel[1], pixel[0]]);
            }
            std::fs::write(std::path::Path::new(&dir).join(format!("{name}.ppm")), ppm).unwrap();
        }
        canvas
    }

    /// Whether any pixel in the rows `y0..y1` differs from `background`.
    fn has_content(canvas: &Canvas, y0: usize, y1: usize, background: Color) -> bool {
        (y0..y1).any(|y| (0..canvas.width()).any(|x| canvas.pixel(x, y) != background))
    }

    #[test]
    fn draws_the_status_screen() {
        let canvas = rendered("status", &Screen::Status, &status());
        assert_eq!(canvas.pixel(0, 0), BACKGROUND);
        assert!(has_content(&canvas, 48, 170, BACKGROUND), "time");
        assert!(has_content(&canvas, 250, 300, BACKGROUND), "thing");
        assert!(has_content(&canvas, 312, 350, BACKGROUND), "connection");
        // The connection dot is green.
        assert!((0..800).any(|x| (312..350).any(|y| canvas.pixel(x, y) == GREEN)));

        let mut offline = status();
        offline.connected = false;
        offline.thing = None;
        offline.address = None;
        let canvas = rendered("status-offline", &Screen::Status, &offline);
        assert!((0..800).any(|x| (312..350).any(|y| canvas.pixel(x, y) == RED)));
    }

    #[test]
    fn draws_messages_in_their_colours() {
        for (severity, color) in [
            (Severity::Info, BLUE),
            (Severity::Success, GREEN),
            (Severity::Warning, AMBER),
            (Severity::Error, RED),
        ] {
            let screen = Screen::Message {
                title: "Service notice".to_owned(),
                body: "This validator will restart at 02:00 for maintenance. ".repeat(4),
                severity,
            };
            let canvas = rendered(&format!("message-{severity:?}"), &screen, &status());
            assert_eq!(canvas.pixel(400, 4), color);
            assert!(has_content(&canvas, 172, 470, BACKGROUND), "body");
        }
    }

    #[test]
    fn draws_results() {
        let accepted = Screen::Result {
            accepted: true,
            title: String::new(),
            body: "Day pass, valid until 23:59".to_owned(),
        };
        let canvas = rendered("result-accepted", &accepted, &status());
        assert_eq!(canvas.pixel(5, 470), GREEN);
        assert_eq!(canvas.pixel(400, 70), Color::WHITE);

        let rejected = Screen::Result {
            accepted: false,
            title: "Expired".to_owned(),
            body: String::new(),
        };
        let canvas = rendered("result-rejected", &rejected, &status());
        assert_eq!(canvas.pixel(5, 470), RED);
        assert!(has_content(&canvas, 244, 320, RED), "title");
    }

    #[test]
    fn draws_blank_and_test_screens() {
        let canvas = rendered("blank", &Screen::Blank, &status());
        assert!(!has_content(&canvas, 0, 480, Color::BLACK));

        let canvas = rendered("test", &Screen::Test, &status());
        assert_eq!(canvas.pixel(50, 100), Color::WHITE);
        assert_eq!(canvas.pixel(750, 100), Color::BLACK);
        assert_eq!(canvas.pixel(650, 100), Color::rgb(0, 0, 255));
        assert_eq!(canvas.pixel(2, 478), RED);
    }
}
