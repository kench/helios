//! The stream module end to end, with the real ffmpeg, `srtla_send`, `srtla_rec` and
//! irl-srt-server (LLD 4, section 12). Run only by `tests/stream-e2e/helios.sh`, inside the
//! network namespace it sets up (uplinks `up0` 10.10.1.2 and `up1` 10.10.2.2, the receiving
//! side on 10.10.0.1); skipped otherwise.

use std::process::Command;
use std::time::Duration;

use serde_json::{Value, json};
use tokio::sync::mpsc;

use super::{StreamModule, StreamSettings};
use crate::modules::usb::UsbHandle;
use crate::modules::{Module, ModuleContext};
use crate::mqtt::manager::{MqttHandle, Request as MqttRequest};
use crate::mqtt::shadow::{ShadowHandle, TestReports};
use crate::router::{Outcome, PendingCommand};

const WAIT: Duration = Duration::from_secs(60);

fn say(message: &str) {
    println!("HELIOS  {message}");
}

/// Plays `play/live/e2e` from irl-srt-server for a few seconds; the codecs it got.
fn played_codecs(run: &str, name: &str) -> String {
    let file = format!("{run}/{name}.ts");
    let _ = Command::new("timeout")
        .args(["20", "ffmpeg", "-hide_banner", "-loglevel", "error", "-i"])
        .arg("srt://10.10.0.1:4000?mode=caller&streamid=play/live/e2e&latency=200000")
        .args(["-t", "4", "-c", "copy", "-f", "mpegts", &file])
        .status();
    let output = Command::new("ffprobe")
        .args([
            "-v",
            "error",
            "-show_entries",
            "stream=codec_name",
            "-of",
            "csv=p=0",
            &file,
        ])
        .output()
        .map(|output| String::from_utf8_lossy(&output.stdout).into_owned())
        .unwrap_or_default();
    let mut codecs: Vec<&str> = output.lines().filter(|line| !line.is_empty()).collect();
    codecs.sort_unstable();
    codecs.dedup();
    codecs.join(",")
}

fn ip(args: &str) {
    let status = Command::new("ip")
        .args(args.split(' '))
        .status()
        .expect("ip");
    assert!(status.success(), "ip {args}");
}

async fn next_event(published: &mut mpsc::UnboundedReceiver<MqttRequest>, kind: &str) -> String {
    loop {
        let request = tokio::time::timeout(WAIT, published.recv())
            .await
            .unwrap_or_else(|_| panic!("no {kind} in time"))
            .expect("mqtt");
        let text = format!("{request:?}");
        if text.contains(&format!("kind: \"{kind}\"")) {
            return text;
        }
    }
}

async fn report_where(
    reports: &mut TestReports,
    what: &str,
    check: impl Fn(&Value) -> bool,
) -> Value {
    let reported = tokio::time::timeout(WAIT, async {
        loop {
            let (shadow, reported) = reports.recv().await.expect("shadow");
            let reported = Value::Object(reported);
            if shadow == "stream" && check(&reported) {
                return reported;
            }
        }
    })
    .await
    .unwrap_or_else(|_| panic!("the shadow never showed {what}"));
    say(&format!("shadow: {what}"));
    reported
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "run by tests/stream-e2e/helios.sh"]
async fn streams_a_test_pattern_through_the_bond() {
    let (Ok(e2e), Ok(run)) = (
        std::env::var("HELIOS_E2E_DIR"),
        std::env::var("HELIOS_E2E_RUN"),
    ) else {
        eprintln!("skipping: run through tests/stream-e2e/helios.sh");
        return;
    };
    let config = format!(
        r#"
ffmpeg = "/usr/bin/ffmpeg"
srtla_send = "{e2e}/bin/srtla_send"
runtime_dir = "{run}/runtime"
sender_idle_s = 2

[outputs.bond]
mode = "srtla"
host = "10.10.0.1"
port = 5000
latency_ms = 2000
uplinks = ["up0", "up1"]

[profiles.hevc]
video = "libx265"
bitrate_kbps = 3000
audio = "aac"

[streams.e2e]
source = {{ type = "test", size = "1280x720", fps = 30 }}
profile = "hevc"
output = "bond"
streamid = "publish/live/e2e"
"#
    );
    let settings = toml::from_str::<StreamSettings>(&config)
        .expect("settings")
        .check()
        .expect("valid")
        .expect("enabled");
    let module = StreamModule::new(settings, UsbHandle::default());
    let (mqtt, mut published, _status) = MqttHandle::for_test();
    let (shadows, mut reports, _desired) = ShadowHandle::for_test();
    let (commands, commands_rx) = mpsc::channel(4);
    let cancel = tokio_util::sync::CancellationToken::new();
    let ctx = ModuleContext {
        commands: commands_rx,
        desired: mpsc::unbounded_channel().1,
        shadows,
        mqtt,
        sysfs: "/sys".into(),
        cancel: cancel.clone(),
    };
    let task = tokio::spawn(async move { module.run(ctx).await });

    // Helios starts srtla_send on both uplinks, then ffmpeg once the bond is up.
    report_where(&mut reports, "output bond up with 2 active links", |r| {
        r["outputs"]["bond"]["state"] == "up" && r["outputs"]["bond"]["active_links"] == 2
    })
    .await;
    let live = next_event(&mut published, "stream.live").await;
    say("event: stream.live");
    assert!(live.contains("Number(2)"), "{live}");
    let codecs = played_codecs(&run, "first");
    say(&format!("player on irl-srt-server :4000 got {codecs}"));
    assert_eq!(codecs, "aac,hevc");

    // An uplink loses its address: Helios rewrites the IP file and reloads srtla_send.
    ip("addr del 10.10.2.2/24 dev up1");
    let one = report_where(&mut reports, "uplinks down to 10.10.1.2", |r| {
        r["outputs"]["bond"]["uplinks"] == json!(["10.10.1.2"])
    })
    .await;
    assert_eq!(one["streams"]["e2e"]["state"], "live");
    let ips = std::fs::read_to_string(format!("{run}/runtime/srtla/bond.ips")).expect("ips");
    assert_eq!(ips, "10.10.1.2\n");
    report_where(&mut reports, "1 active link after the reload", |r| {
        r["outputs"]["bond"]["active_links"] == 1
    })
    .await;
    let codecs = played_codecs(&run, "one-link");
    say(&format!("on one uplink, the player got {codecs}"));
    assert_eq!(codecs, "aac,hevc");

    // It comes back.
    ip("addr add 10.10.2.2/24 dev up1");
    report_where(&mut reports, "both uplinks active again", |r| {
        r["outputs"]["bond"]["uplinks"] == json!(["10.10.1.2", "10.10.2.2"])
            && r["outputs"]["bond"]["active_links"] == 2
    })
    .await;

    // Stopped: ffmpeg at once, srtla_send after its idle time.
    let (pending, answer) = PendingCommand::for_test("stream", "stop", json!({"stream_id": "e2e"}));
    commands.send(pending).await.expect("module running");
    assert!(matches!(answer.await, Ok(Outcome::Ok(_))));
    let disconnected = next_event(&mut published, "stream.disconnected").await;
    say("event: stream.disconnected");
    assert!(disconnected.contains("\"stopped\""), "{disconnected}");
    report_where(&mut reports, "output bond stopped", |r| {
        r["outputs"]["bond"]["state"] == "stopped"
    })
    .await;
    tokio::time::sleep(Duration::from_secs(1)).await;
    let senders = Command::new("pgrep")
        .args(["-x", "srtla_send"])
        .output()
        .expect("pgrep");
    assert!(senders.stdout.is_empty(), "srtla_send still running");
    say("srtla_send stopped after its idle time");

    cancel.cancel();
    tokio::time::timeout(WAIT, task)
        .await
        .expect("stopped in time")
        .expect("task")
        .expect("stopped cleanly");
}
