//! Display module tests: the module against a regular file standing in for the framebuffer and a
//! fake sysfs, driven through its real channels.

use std::path::PathBuf;
use std::time::{Duration, SystemTime};

use serde_json::{Map, Value, json};
use tokio::sync::{mpsc, oneshot, watch};
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;

use super::canvas::Color;
use super::templates::Screen;
use super::*;
use crate::router::Outcome;

const BACKGROUND: Color = Color::rgb(18, 22, 30);
const BLUE: Color = Color::rgb(40, 120, 210);
const GREEN: Color = Color::rgb(30, 160, 80);
const RED: Color = Color::rgb(200, 45, 45);
const STOPPED_TEXT: Color = Color::rgb(150, 160, 175);

struct Harness {
    dir: PathBuf,
    commands: mpsc::Sender<PendingCommand>,
    desired: mpsc::UnboundedSender<Value>,
    mqtt: watch::Sender<MqttStatus>,
    reports: mpsc::UnboundedReceiver<(String, Map<String, Value>)>,
    cancel: CancellationToken,
    task: Option<JoinHandle<()>>,
}

fn temp_dir(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("helios-display-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(dir.join("sys/class/graphics/fb0")).unwrap();
    std::fs::create_dir_all(dir.join("dev")).unwrap();
    let fb = dir.join("sys/class/graphics/fb0");
    std::fs::write(fb.join("virtual_size"), "800,480\n").unwrap();
    std::fs::write(fb.join("bits_per_pixel"), "32\n").unwrap();
    std::fs::write(fb.join("stride"), "3200\n").unwrap();
    dir
}

fn create_framebuffer(dir: &std::path::Path) {
    std::fs::write(dir.join("dev/fb0"), vec![0u8; 800 * 480 * 4]).unwrap();
}

fn settings(dir: &std::path::Path) -> DisplaySettings {
    DisplaySettings {
        framebuffer: dir.join("dev/fb0"),
        idle: Screen::Status,
        time_zone_name: "UTC".to_owned(),
        time_zone: TimeZone::UTC,
        redraw_interval: Duration::from_secs(10),
        bold_font: None,
    }
}

impl Harness {
    fn start(name: &str, with_framebuffer: bool) -> Self {
        let dir = temp_dir(name);
        if with_framebuffer {
            create_framebuffer(&dir);
        }
        Self::start_in(dir, |settings| settings)
    }

    fn start_in(dir: PathBuf, adjust: impl FnOnce(DisplaySettings) -> DisplaySettings) -> Self {
        let (commands, commands_rx) = mpsc::channel(16);
        let (desired, desired_rx) = mpsc::unbounded_channel();
        let (mqtt, mqtt_rx) = watch::channel(MqttStatus::default());
        let (shadows, reports, _desired_requests) = ShadowHandle::for_test();
        let cancel = CancellationToken::new();
        let inputs = Inputs {
            commands: commands_rx,
            desired: desired_rx,
            shadows,
            mqtt: mqtt_rx,
            sysfs: dir.join("sys"),
        };
        let task = start(adjust(settings(&dir)), inputs, cancel.clone()).unwrap();
        Self {
            dir,
            commands,
            desired,
            mqtt,
            reports,
            cancel,
            task: Some(task),
        }
    }

    /// The colour at (`x`, `y`) in the framebuffer file.
    fn pixel(&self, x: usize, y: usize) -> Color {
        let bytes = std::fs::read(self.dir.join("dev/fb0")).unwrap();
        let i = (y * 800 + x) * 4;
        Color::rgb(bytes[i + 2], bytes[i + 1], bytes[i])
    }

    fn band_has(&self, y0: usize, y1: usize, color: Color) -> bool {
        let bytes = std::fs::read(self.dir.join("dev/fb0")).unwrap();
        (y0..y1).any(|y| {
            (0..800).any(|x| {
                let i = (y * 800 + x) * 4;
                Color::rgb(bytes[i + 2], bytes[i + 1], bytes[i]) == color
            })
        })
    }

    async fn command(&self, name: &str, args: Value) -> Outcome {
        let (pending, answer): (PendingCommand, oneshot::Receiver<Outcome>) =
            PendingCommand::for_test(MODULE, name, args);
        self.commands.send(pending).await.unwrap();
        answer.await.unwrap()
    }

    /// Waits for a report matching `check`, and returns it.
    async fn report(&mut self, check: impl Fn(&Map<String, Value>) -> bool) -> Map<String, Value> {
        loop {
            let (shadow, reported) =
                tokio::time::timeout(Duration::from_secs(5), self.reports.recv())
                    .await
                    .expect("a report")
                    .expect("reports open");
            assert_eq!(shadow, MODULE);
            if check(&reported) {
                return reported;
            }
        }
    }

    /// Lets the module run until it's idle.
    async fn settle() {
        for _ in 0..20 {
            tokio::task::yield_now().await;
        }
    }

    async fn stop(&mut self) {
        self.cancel.cancel();
        if let Some(task) = self.task.take() {
            task.await.unwrap();
        }
    }
}

impl Drop for Harness {
    fn drop(&mut self) {
        self.cancel.cancel();
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

fn ok(outcome: Outcome) -> Value {
    match outcome {
        Outcome::Ok(value) => value,
        Outcome::Err { code, message } => panic!("{code}: {message}"),
    }
}

fn error_code(outcome: Outcome) -> String {
    match outcome {
        Outcome::Err { code, .. } => code,
        Outcome::Ok(value) => panic!("expected an error, got {value}"),
    }
}

#[tokio::test]
async fn shows_the_idle_screen_and_reports_it() {
    let mut harness = Harness::start("idle", true);

    let report = harness.report(|r| r["available"] == true).await;
    assert_eq!(report["template"], "status");
    assert_eq!(report["idle"], "status");
    assert_eq!(report["time_zone"], "UTC");
    assert_eq!(report["console_bound"], false);
    assert_eq!(
        report["geometry"],
        json!({"width": 800, "height": 480, "bits_per_pixel": 32, "stride": 3200})
    );
    assert_eq!(report["error"], Value::Null);
    assert_eq!(harness.pixel(0, 0), BACKGROUND);
    assert!(harness.band_has(312, 350, RED), "offline dot");

    harness.mqtt.send_modify(|status| {
        status.connected = true;
        status.connected_at = Some(SystemTime::now());
        status.thing = Some("t-1".to_owned());
    });
    Harness::settle().await;
    tokio::time::sleep(Duration::from_millis(50)).await;
    assert!(harness.band_has(312, 350, GREEN), "connected dot");

    let status = ok(harness.command("status", Value::Null).await);
    assert_eq!(status["template"], "status");
    harness.stop().await;
}

#[tokio::test]
async fn shows_a_screen_for_a_while_then_goes_back() {
    let mut harness = Harness::start("show", true);
    harness.report(|r| r["available"] == true).await;

    let shown = ok(harness
        .command(
            "show",
            json!({"template": "message", "fields": {"title": "Hello"}, "duration_s": 1}),
        )
        .await);
    assert_eq!(shown["template"], "message");
    assert!(shown["until"].is_string());
    assert_eq!(harness.pixel(400, 4), BLUE);

    harness.report(|r| r["template"] == "status").await;
    assert_eq!(harness.pixel(400, 4), BACKGROUND);
    harness.stop().await;
}

#[tokio::test]
async fn clears_a_screen_shown_without_a_duration() {
    let mut harness = Harness::start("clear", true);
    harness.report(|r| r["available"] == true).await;

    let shown = ok(harness
        .command(
            "show",
            json!({"template": "result", "fields": {"outcome": "accepted"}}),
        )
        .await);
    assert_eq!(shown["until"], Value::Null);
    assert_eq!(harness.pixel(5, 470), GREEN);

    let cleared = ok(harness.command("clear", Value::Null).await);
    assert_eq!(cleared["template"], "status");
    assert_eq!(harness.pixel(5, 470), BACKGROUND);
    // Clearing the idle screen is fine too.
    assert_eq!(
        ok(harness.command("clear", Value::Null).await)["template"],
        "status"
    );
    harness.stop().await;
}

#[tokio::test]
async fn refuses_bad_commands() {
    let mut harness = Harness::start("bad", true);
    harness.report(|r| r["available"] == true).await;

    for (name, args, expected) in [
        ("show", json!({"template": "nope"}), "INVALID_MESSAGE"),
        ("show", json!("message"), "INVALID_MESSAGE"),
        ("show", json!({}), "INVALID_MESSAGE"),
        (
            "show",
            json!({"template": "blank", "colour": "red"}),
            "INVALID_MESSAGE",
        ),
        (
            "show",
            json!({"template": "blank", "duration_s": 0}),
            "INVALID_MESSAGE",
        ),
        (
            "show",
            json!({"template": "blank", "duration_s": 86_401}),
            "INVALID_MESSAGE",
        ),
        (
            "show",
            json!({"template": "blank", "duration_s": "5"}),
            "INVALID_MESSAGE",
        ),
        ("dance", Value::Null, "UNKNOWN_COMMAND"),
    ] {
        assert_eq!(
            error_code(harness.command(name, args.clone()).await),
            expected,
            "{name} {args}"
        );
    }
    // A duration of null is no duration.
    let shown = ok(harness
        .command("show", json!({"template": "blank", "duration_s": null}))
        .await);
    assert_eq!(shown["template"], "blank");
    harness.stop().await;
}

#[tokio::test]
async fn follows_the_desired_idle_screen() {
    let mut harness = Harness::start("desired", true);
    harness.report(|r| r["available"] == true).await;

    harness
        .desired
        .send(json!({"idle": {"template": "blank"}}))
        .unwrap();
    harness.report(|r| r["idle"] == "blank").await;
    assert_eq!(harness.pixel(0, 0), Color::BLACK);

    harness
        .desired
        .send(json!({"idle": {"template": "message"}}))
        .unwrap();
    let refused = harness.report(|r| !r["error"].is_null()).await;
    assert!(
        refused["error"]
            .as_str()
            .unwrap()
            .contains("title is required")
    );
    assert_eq!(refused["idle"], "blank");

    // Other desired fields are ignored; null goes back to the configured idle screen.
    harness.desired.send(json!({"something": 1})).unwrap();
    harness.desired.send(json!({"idle": null})).unwrap();
    let back = harness.report(|r| r["idle"] == "status").await;
    assert_eq!(back["error"], Value::Null);
    assert_eq!(harness.pixel(0, 0), BACKGROUND);

    // While a screen is shown, a new idle screen waits for it to end.
    ok(harness.command("show", json!({"template": "test"})).await);
    harness
        .desired
        .send(json!({"idle": {"template": "blank"}}))
        .unwrap();
    harness.report(|r| r["idle"] == "blank").await;
    assert_eq!(harness.pixel(50, 100), Color::WHITE);
    harness.stop().await;
}

#[tokio::test]
async fn shows_that_helios_stopped() {
    let mut harness = Harness::start("stop", true);
    harness.report(|r| r["available"] == true).await;

    harness.stop().await;
    assert!(harness.band_has(200, 280, STOPPED_TEXT));
    assert_eq!(harness.pixel(0, 0), BACKGROUND);
}

#[tokio::test]
async fn waits_for_the_framebuffer() {
    let dir = temp_dir("wait");
    let mut harness = Harness::start_in(dir.clone(), |settings| settings);

    let missing = harness.report(|r| !r["error"].is_null()).await;
    assert_eq!(missing["available"], false);
    assert!(missing["error"].as_str().unwrap().contains("can't open"));
    // The first retry comes within a second.
    create_framebuffer(&dir);
    let ready = harness.report(|r| r["available"] == true).await;
    assert_eq!(ready["error"], Value::Null);
    harness.stop().await;
}

#[tokio::test]
async fn redraws_while_the_console_is_attached() {
    let dir = temp_dir("console");
    create_framebuffer(&dir);
    let vt = dir.join("sys/class/vtconsole/vtcon1");
    std::fs::create_dir_all(&vt).unwrap();
    std::fs::write(vt.join("name"), "(M) frame buffer device\n").unwrap();
    std::fs::write(vt.join("bind"), "1\n").unwrap();
    let mut harness = Harness::start_in(dir, |mut settings| {
        settings.idle = Screen::Blank;
        settings.redraw_interval = Duration::from_secs(1);
        settings
    });

    let report = harness.report(|r| r["available"] == true).await;
    assert_eq!(report["console_bound"], true);
    // Console output drawn over the screen goes away at the next redraw.
    let mut bytes = std::fs::read(harness.dir.join("dev/fb0")).unwrap();
    bytes[..4].copy_from_slice(&[255, 255, 255, 255]);
    std::fs::write(harness.dir.join("dev/fb0"), &bytes).unwrap();
    tokio::time::sleep(Duration::from_millis(1500)).await;
    assert_eq!(harness.pixel(0, 0), Color::BLACK);
    harness.stop().await;
}

#[tokio::test]
async fn keeps_running_when_its_inputs_close() {
    let mut harness = Harness::start("closed", true);
    harness.report(|r| r["available"] == true).await;
    let (closed_commands, _) = mpsc::channel(1);
    let (closed_desired, _) = mpsc::unbounded_channel();
    let (closed_mqtt, _) = watch::channel(MqttStatus::default());
    drop(std::mem::replace(&mut harness.commands, closed_commands));
    drop(std::mem::replace(&mut harness.desired, closed_desired));
    drop(std::mem::replace(&mut harness.mqtt, closed_mqtt));
    Harness::settle().await;

    harness.stop().await;
    assert!(harness.band_has(200, 280, STOPPED_TEXT));
}

#[test]
fn formats_the_status_in_the_time_zone() {
    let la = jiff::tz::db().get("America/Los_Angeles").unwrap();
    // 2026-11-21 15:04:00 UTC is 07:04 PST.
    let now = SystemTime::UNIX_EPOCH + Duration::from_secs(1_795_273_440);
    let mqtt = MqttStatus {
        connected: true,
        connected_at: Some(now - Duration::from_secs(600)),
        thing: Some("t-1".to_owned()),
        ..MqttStatus::default()
    };

    let info = status_info(&mqtt, &la, now, None);
    assert_eq!(info.time, "07:04");
    assert_eq!(info.date, "Sat 21 Nov 2026");
    assert_eq!(info.zone, "PST");
    assert_eq!(info.connected_since.as_deref(), Some("06:54"));
    assert_eq!(info.thing.as_deref(), Some("t-1"));

    let offline = MqttStatus {
        connected: false,
        ..mqtt
    };
    assert_eq!(status_info(&offline, &la, now, None).connected_since, None);
    let _ = default_route_address();
    assert!(time(now).as_str().unwrap().starts_with("2026-11-21T15:04"));
}

#[tokio::test]
async fn loads_a_bold_font_from_a_file() {
    let dir = temp_dir("bold");
    create_framebuffer(&dir);
    let font =
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("assets/fonts/NotoSans-Regular-subset.ttf");
    let mut harness = Harness::start_in(dir, |mut settings| {
        settings.bold_font = Some(font.clone());
        settings
    });

    let report = harness.report(|r| r["available"] == true).await;
    assert_eq!(report["bold_font"]["path"], font.to_str().unwrap());
    assert_eq!(report["bold_font"]["error"], Value::Null);
    harness.stop().await;
}

#[tokio::test]
async fn falls_back_to_the_built_in_bold_font() {
    for (name, contents) in [
        ("bold-missing", None),
        ("bold-broken", Some(b"not a font".as_slice())),
    ] {
        let dir = temp_dir(name);
        create_framebuffer(&dir);
        let font = dir.join("Missing-Bold.otf");
        if let Some(contents) = contents {
            std::fs::write(&font, contents).unwrap();
        }
        let mut harness = Harness::start_in(dir, |mut settings| {
            settings.bold_font = Some(font.clone());
            settings
        });

        let report = harness.report(|r| r["available"] == true).await;
        let error = report["bold_font"]["error"].as_str().unwrap();
        assert!(
            error.contains("can't read it") || error.contains("not a usable font"),
            "{error}"
        );
        // The screen is still drawn, with the built-in font.
        assert_eq!(harness.pixel(0, 0), BACKGROUND);
        assert_eq!(report["error"], Value::Null);
        harness.stop().await;
    }
}
