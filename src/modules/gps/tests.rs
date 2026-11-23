use std::path::PathBuf;
use std::sync::Arc;

use serde_json::Value;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::TcpListener;
use tokio::sync::mpsc;

use super::gpsd::{Message, parse};
use super::report::{MOVE_INTERVAL, STILL_INTERVAL, distance_m};
use super::*;
use crate::mqtt::manager::{MqttHandle, Request as MqttRequest};
use crate::mqtt::shadow::{ShadowHandle, TestReports};

const PATH: &str =
    "/dev/serial/by-id/usb-Microchip_Technology_Inc._MCP2221_USB-I2C_UART_Combo-if00";

// gpsd 3.25's output on the Orange Pi (2026-11-22), with a made-up position.
const VERSION: &str =
    r#"{"class":"VERSION","release":"3.25","rev":"3.25","proto_major":3,"proto_minor":15}"#;
const DEVICES: &str = r#"{"class":"DEVICES","devices":[{"class":"DEVICE","path":"/dev/serial/by-id/usb-Microchip_Technology_Inc._MCP2221_USB-I2C_UART_Combo-if00","driver":"NMEA0183","activated":"2026-11-22T22:41:20.000Z","native":0,"bps":4800,"parity":"N","stopbits":1,"cycle":1.00}]}"#;
const TPV_2D: &str = r#"{"class":"TPV","device":"/dev/serial/by-id/usb-Microchip_Technology_Inc._MCP2221_USB-I2C_UART_Combo-if00","mode":2,"time":"2026-11-22T22:39:42.000Z","ept":0.005,"lat":37.4219983,"lon":-122.0840000,"track":84.6000,"magtrack":100.8000,"magvar":16.2,"speed":0.000}"#;
const TPV_3D: &str = r#"{"class":"TPV","device":"/dev/serial/by-id/usb-Microchip_Technology_Inc._MCP2221_USB-I2C_UART_Combo-if00","mode":3,"time":"2026-11-22T22:39:43.000Z","ept":0.005,"lat":37.4219983,"lon":-122.0840000,"altHAE":11.8,"altMSL":30.2,"alt":30.2,"epv":18.400,"track":84.6000,"speed":0.000,"climb":0.000,"geoidSep":-18.400,"eph":17.100}"#;
const SKY_SHORT: &str = r#"{"class":"SKY","device":"/dev/serial/by-id/usb-Microchip_Technology_Inc._MCP2221_USB-I2C_UART_Combo-if00","hdop":0.90,"uSat":9}"#;
const SKY_FULL: &str = r#"{"class":"SKY","device":"/dev/serial/by-id/usb-Microchip_Technology_Inc._MCP2221_USB-I2C_UART_Combo-if00","gdop":1.74,"hdop":0.90,"pdop":1.20,"vdop":0.80,"nSat":12,"uSat":9,"satellites":[{"PRN":1,"used":true}]}"#;
const TPV_NONE: &str = r#"{"class":"TPV","device":"/dev/serial/by-id/usb-Microchip_Technology_Inc._MCP2221_USB-I2C_UART_Combo-if00","mode":1}"#;

fn no_usb(_: &str) -> Option<String> {
    None
}

fn state_after(lines: &[&str]) -> State {
    let mut state = State::new(SystemTime::UNIX_EPOCH);
    state.set_connected(true, SystemTime::UNIX_EPOCH);
    for line in lines {
        state.apply(parse(line), SystemTime::UNIX_EPOCH, &no_usb);
    }
    state
}

#[test]
fn parses_the_classes_it_reads_and_ignores_the_rest() {
    assert_eq!(parse(VERSION), Message::Other);
    assert_eq!(parse("not json"), Message::Other);
    assert_eq!(parse(r#"{"class":"TPV","mode":"three"}"#), Message::Other);
    let Message::Devices(devices) = parse(DEVICES) else {
        panic!("DEVICES");
    };
    assert_eq!(devices[0].path, PATH);
    assert_eq!(devices[0].driver.as_deref(), Some("NMEA0183"));
    assert_eq!(devices[0].bps, Some(4800));
    assert!(!devices[0].closed());
    let Message::Device(closed) = parse(r#"{"class":"DEVICE","path":"/dev/x","activated":0}"#)
    else {
        panic!("DEVICE");
    };
    assert!(closed.closed());
    let Message::Tpv(tpv) = parse(TPV_3D) else {
        panic!("TPV");
    };
    assert_eq!(
        (tpv.mode, tpv.alt_msl, tpv.eph),
        (3, Some(30.2), Some(17.1))
    );
    let Message::Sky(sky) = parse(SKY_FULL) else {
        panic!("SKY");
    };
    assert_eq!(
        (sky.used, sky.visible, sky.pdop),
        (Some(9), Some(12), Some(1.2))
    );
    assert!(gpsd::WATCH.ends_with('\n'));
}

#[test]
fn reports_the_full_fix_and_its_satellites() {
    let state = state_after(&[VERSION, DEVICES, TPV_3D, SKY_SHORT, SKY_FULL]);
    let reported = Value::Object(state.reported());
    assert_eq!(reported["gpsd"], "connected");
    assert_eq!(
        reported["receivers"],
        json!([{"path": PATH, "driver": "NMEA0183", "bps": 4800, "usb_port": null}])
    );
    assert_eq!(
        reported["fix"],
        json!({"mode": "3d", "time": "2026-11-22T22:39:43.000Z", "lat": 37.4219983,
               "lon": -122.084, "alt_msl_m": 30.2, "speed_mps": 0.0, "track_deg": 84.6,
               "climb_mps": 0.0, "eph_m": 17.1, "epv_m": 18.4})
    );
    assert_eq!(
        reported["satellites"],
        json!({"used": 9, "visible": 12, "hdop": 0.9, "pdop": 1.2})
    );
    assert!(
        reported.get("last_fix").is_none(),
        "only when the fix is lost"
    );
    assert_eq!(state.mode(), Mode::ThreeD);

    // A 2D fix has no altitude even if gpsd sends one.
    let two_d = Value::Object(state_after(&[DEVICES, TPV_2D]).reported());
    assert_eq!(two_d["fix"]["mode"], "2d");
    assert!(two_d["fix"].get("alt_msl_m").is_none());
}

#[test]
fn keeps_the_last_fix_when_it_is_lost() {
    let mut state = state_after(&[DEVICES, TPV_3D, SKY_FULL]);
    let later = SystemTime::UNIX_EPOCH + Duration::from_secs(60);
    state.apply(parse(TPV_NONE), later, &no_usb);
    let reported = Value::Object(state.reported());
    assert_eq!(reported["fix"], json!({"mode": "none"}));
    assert_eq!(reported["last_fix"]["lat"], 37.4219983);
    assert_eq!(reported["last_fix"]["time"], "2026-11-22T22:39:43.000Z");
    assert_eq!(
        reported["satellites"]["visible"], 12,
        "satellites still reported"
    );
    assert_eq!(
        reported["since"], "1970-01-01T00:01:00.000Z",
        "when the mode changed"
    );

    // gpsd going away loses the receivers too, but not the last fix.
    state.set_connected(false, later);
    let reported = Value::Object(state.reported());
    assert_eq!(reported["gpsd"], "unavailable");
    assert_eq!(reported["receivers"], json!([]));
    assert_eq!(reported["last_fix"]["lon"], -122.084);
    assert!(reported.get("satellites").is_none());

    // Before any fix there's no last_fix.
    let fresh = Value::Object(state_after(&[DEVICES, TPV_NONE]).reported());
    assert!(fresh.get("last_fix").is_none());
}

#[test]
fn follows_receivers_coming_and_going() {
    let other = r#"{"class":"DEVICE","path":"/dev/ttyACM1","driver":"u-blox","activated":"x"}"#;
    let other_fix = r#"{"class":"TPV","device":"/dev/ttyACM1","mode":3,"lat":1.0,"lon":2.0}"#;
    let mut state = state_after(&[DEVICES, other, other_fix, TPV_NONE]);
    let reported = Value::Object(state.reported());
    assert_eq!(reported["receivers"].as_array().unwrap().len(), 2);
    assert_eq!(reported["fix"]["lat"], 1.0, "the receiver that has a fix");

    // A TPV for a receiver gpsd never announced is ignored.
    state.apply(
        parse(r#"{"class":"TPV","device":"/dev/unknown","mode":3,"lat":9.0,"lon":9.0}"#),
        SystemTime::UNIX_EPOCH,
        &no_usb,
    );
    assert_eq!(Value::Object(state.reported())["fix"]["lat"], 1.0);

    state.apply(
        parse(r#"{"class":"DEVICE","path":"/dev/ttyACM1","activated":0}"#),
        SystemTime::UNIX_EPOCH,
        &no_usb,
    );
    let reported = Value::Object(state.reported());
    assert_eq!(reported["receivers"].as_array().unwrap().len(), 1);
    assert_eq!(reported["fix"]["mode"], "none");
    assert_eq!(reported["last_fix"]["lat"], 1.0);

    // DEVICES is the whole list: a receiver not in it is gone.
    state.apply(
        parse(r#"{"class":"DEVICES","devices":[]}"#),
        SystemTime::UNIX_EPOCH,
        &|_| Some("6-1".into()),
    );
    assert_eq!(Value::Object(state.reported())["receivers"], json!([]));
    state.apply(parse(DEVICES), SystemTime::UNIX_EPOCH, &|_| {
        Some("6-1".into())
    });
    assert_eq!(
        Value::Object(state.reported())["receivers"][0]["usb_port"],
        "6-1"
    );
}

#[test]
fn measures_distances() {
    let one_degree = distance_m((0.0, 0.0), (1.0, 0.0));
    assert!((one_degree - 111_195.0).abs() < 10.0, "{one_degree}");
    assert!(distance_m((37.0, -122.0), (37.0, -122.0)) < 1e-6);
    let small = distance_m((37.4219983, -122.084), (37.4222, -122.084));
    assert!((small - 22.4).abs() < 0.5, "{small}");
}

fn moved(lat: f64) -> String {
    TPV_3D.replace("37.4219983", &lat.to_string())
}

#[tokio::test(start_paused = true)]
async fn reports_on_its_schedule() {
    let mut state = state_after(&[DEVICES, TPV_3D]);
    let mut schedule = Schedule::default();
    let start = Instant::now();
    assert!(schedule.due(&state, start), "the first report");
    assert_eq!(schedule.next(), None);
    schedule.sent(&state, start);
    assert_eq!(schedule.next(), Some(start + STILL_INTERVAL));
    assert!(!schedule.due(&state, start + Duration::from_secs(1)));

    // Moving 30 m: not before 10 s have passed, then at once.
    state.apply(parse(&moved(37.4222683)), SystemTime::UNIX_EPOCH, &no_usb);
    assert!(!schedule.due(&state, start + Duration::from_secs(5)));
    assert!(schedule.due(&state, start + MOVE_INTERVAL));
    schedule.sent(&state, start + MOVE_INTERVAL);

    // 20 m more isn't enough; staying put reports after an hour.
    state.apply(parse(&moved(37.4224483)), SystemTime::UNIX_EPOCH, &no_usb);
    let later = start + MOVE_INTERVAL;
    assert!(!schedule.due(&state, later + Duration::from_secs(600)));
    assert!(schedule.due(&state, later + STILL_INTERVAL));

    // Satellites arriving after the fix report at once (gpsd sends SKY just after TPV).
    state.apply(parse(SKY_SHORT), SystemTime::UNIX_EPOCH, &no_usb);
    assert!(schedule.due(&state, later + Duration::from_secs(1)));
    schedule.sent(&state, later + Duration::from_secs(1));
    state.apply(parse(SKY_FULL), SystemTime::UNIX_EPOCH, &no_usb);
    assert!(
        !schedule.due(&state, later + Duration::from_secs(2)),
        "new counts wait for the schedule"
    );

    // Losing the fix reports at once.
    state.apply(parse(TPV_NONE), SystemTime::UNIX_EPOCH, &no_usb);
    assert!(schedule.due(&state, later + Duration::from_secs(1)));
}

#[test]
fn checks_its_settings() {
    let defaults = GpsSettings::default().check().unwrap().unwrap();
    assert_eq!(
        GpsModule::new(&defaults).address,
        "127.0.0.1:2947".parse().unwrap()
    );
    let disabled = GpsSettings {
        enabled: false,
        ..GpsSettings::default()
    };
    assert_eq!(disabled.check().unwrap(), None);
    let bad = GpsSettings {
        gpsd: "localhost".into(),
        ..GpsSettings::default()
    };
    assert!(bad.check().unwrap_err().contains("modules.gps.gpsd"));
    let ipv6: GpsSettings = toml::from_str("gpsd = \"[::1]:2947\"").unwrap();
    assert!(ipv6.check().unwrap().is_some());
    let device: GpsSettings = toml::from_str(&format!("device = \"{PATH}\"")).unwrap();
    let module = GpsModule::new(&device.check().unwrap().unwrap());
    assert_eq!(
        module.device,
        Some((PATH.to_owned(), PathBuf::from("/run/gpsd.sock")))
    );
    for bad in [
        "device = \"ttyACM0\"",
        "device = \"/dev/a b\"",
        "control_socket = \"gpsd.sock\"",
    ] {
        assert!(
            toml::from_str::<GpsSettings>(bad).unwrap().check().is_err(),
            "{bad}"
        );
    }
}

#[test]
fn finds_a_receivers_usb_port() {
    let dir = tempfile::tempdir().unwrap();
    let dev = dir.path().join("dev");
    std::fs::create_dir_all(dev.join("serial/by-id")).unwrap();
    std::fs::write(dev.join("ttyACM0"), "").unwrap();
    std::os::unix::fs::symlink("../../ttyACM0", dev.join("serial/by-id/usb-x")).unwrap();
    let sysfs = dir.path().join("sys");
    let interface = sysfs.join("devices/platform/fc880000.usb/usb6/6-1/6-1:1.0");
    std::fs::create_dir_all(&interface).unwrap();
    std::fs::create_dir_all(sysfs.join("class/tty/ttyACM0")).unwrap();
    std::os::unix::fs::symlink(&interface, sysfs.join("class/tty/ttyACM0/device")).unwrap();
    assert_eq!(
        receiver_usb_port(&sysfs, &dev.join("serial/by-id/usb-x")).as_deref(),
        Some("6-1")
    );
    assert_eq!(receiver_usb_port(&sysfs, &dev.join("nothing")), None);
}

fn context() -> (
    ModuleContext,
    TestReports,
    mpsc::UnboundedReceiver<MqttRequest>,
) {
    let (mqtt, requests, _status) = MqttHandle::for_test();
    let (shadows, reports, _desired) = ShadowHandle::for_test();
    let ctx = ModuleContext {
        commands: mpsc::channel(1).1,
        desired: mpsc::unbounded_channel().1,
        shadows,
        mqtt,
        sysfs: "/nonexistent".into(),
        cancel: Default::default(),
    };
    (ctx, reports, requests)
}

async fn next_report(reports: &mut TestReports) -> Value {
    let (shadow, reported) = tokio::time::timeout(Duration::from_secs(10), reports.recv())
        .await
        .expect("a report")
        .expect("reports open");
    assert_eq!(shadow, "gps");
    Value::Object(reported)
}

async fn next_event(requests: &mut mpsc::UnboundedReceiver<MqttRequest>) -> (String, Value) {
    loop {
        match tokio::time::timeout(Duration::from_secs(10), requests.recv())
            .await
            .expect("an event")
            .expect("requests open")
        {
            MqttRequest::Event(event) => return (event.kind().to_owned(), event.payload().clone()),
            MqttRequest::Now { .. } => {}
        }
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn reads_gpsd_and_reconnects() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let module = Arc::new(GpsModule {
        address,
        backoff: (Duration::from_millis(10), Duration::from_millis(20)),
        device: None,
        readd: READD,
    });
    assert_eq!(module.name(), "gps");
    let (ctx, mut reports, mut requests) = context();
    let cancel = ctx.cancel.clone();
    let running = tokio::spawn({
        let module = Arc::clone(&module);
        async move { module.run(ctx).await }
    });

    // gpsd answers the WATCH with its version and devices, then a fix.
    let (stream, _) = listener.accept().await.unwrap();
    let (read, mut write) = stream.into_split();
    let mut watch = String::new();
    BufReader::new(read).read_line(&mut watch).await.unwrap();
    assert_eq!(watch, gpsd::WATCH);
    assert_eq!(next_report(&mut reports).await["gpsd"], "connected");
    for line in [VERSION, DEVICES, "garbage", TPV_3D, SKY_FULL] {
        write
            .write_all(format!("{line}\n").as_bytes())
            .await
            .unwrap();
    }
    // The fix reports at once, then again when its satellites arrive.
    let mut reported = next_report(&mut reports).await;
    while reported["fix"]["mode"] != "3d" || reported.get("satellites").is_none() {
        reported = next_report(&mut reports).await;
    }
    assert_eq!(reported["fix"]["lat"], 37.4219983);
    assert_eq!(reported["satellites"]["used"], 9);
    assert_eq!(
        next_event(&mut requests).await,
        (
            "gps.fix".to_owned(),
            json!({"mode": "3d", "previous": "none"})
        )
    );

    // gpsd stops: unavailable at once, the last fix kept, and a fix-lost event.
    drop(write);
    let reported = next_report(&mut reports).await;
    assert_eq!(reported["gpsd"], "unavailable");
    assert_eq!(reported["last_fix"]["lat"], 37.4219983);
    assert_eq!(
        next_event(&mut requests).await,
        (
            "gps.fix".to_owned(),
            json!({"mode": "none", "previous": "3d"})
        )
    );

    // It comes back: the module reconnects.
    let (_again, _) = tokio::time::timeout(Duration::from_secs(10), listener.accept())
        .await
        .expect("a reconnect")
        .unwrap();
    assert_eq!(next_report(&mut reports).await["gpsd"], "connected");
    cancel.cancel();
    assert_eq!(running.await.unwrap(), Ok(()));
}

#[tokio::test]
async fn reports_unavailable_without_gpsd() {
    // Nothing listens on this port of the local machine.
    let module = GpsModule {
        address: "127.0.0.1:9".parse().unwrap(),
        backoff: (Duration::from_millis(10), Duration::from_millis(20)),
        device: None,
        readd: READD,
    };
    let (ctx, mut reports, _requests) = context();
    let cancel = ctx.cancel.clone();
    let running = tokio::spawn(async move { module.run(ctx).await });
    let reported = next_report(&mut reports).await;
    assert_eq!(reported["gpsd"], "unavailable");
    assert_eq!(reported["fix"], json!({"mode": "none"}));
    cancel.cancel();
    assert_eq!(running.await.unwrap(), Ok(()));
}

#[tokio::test]
async fn a_line_too_long_ends_the_connection() {
    let long = "x".repeat(MAX_LINE + 10);
    let mut reader = BufReader::new(long.as_bytes());
    let mut line = String::new();
    assert!(!read_line(&mut reader, &mut line).await);
    let mut reader = BufReader::new("ok\n".as_bytes());
    let mut line = String::new();
    assert!(read_line(&mut reader, &mut line).await);
    assert_eq!(line, "ok\n");
}

/// Against a real gpsd: `HELIOS_GPSD_TEST_ADDR=127.0.0.1:2947 cargo test --features module-gps
/// live_gpsd -- --ignored`. Waits for a fix and checks its shape; prints no position.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "needs a running gpsd with a receiver"]
async fn live_gpsd() {
    let address = std::env::var("HELIOS_GPSD_TEST_ADDR").expect("HELIOS_GPSD_TEST_ADDR");
    let module = GpsModule {
        address: address.parse().expect("an IP address and port"),
        backoff: (Duration::from_secs(1), Duration::from_secs(2)),
        device: None,
        readd: READD,
    };
    let (ctx, mut reports, _requests) = context();
    let cancel = ctx.cancel.clone();
    let running = tokio::spawn(async move { module.run(ctx).await });
    let mut reported = next_report(&mut reports).await;
    while reported["fix"]["mode"] == "none" || reported.get("satellites").is_none() {
        reported = next_report(&mut reports).await;
    }
    let fix = &reported["fix"];
    assert!(fix["lat"].is_f64() && fix["lon"].is_f64(), "a position");
    println!(
        "gpsd {}, receivers {}, fix {}, satellites {}",
        reported["gpsd"],
        reported["receivers"].as_array().map_or(0, Vec::len),
        fix["mode"],
        reported["satellites"]
    );
    cancel.cancel();
    assert_eq!(running.await.unwrap(), Ok(()));
}

/// A fake gpsd control socket: answers each request with `answer`, and records it.
async fn control_socket(
    dir: &Path,
    answer: &'static str,
) -> (PathBuf, mpsc::UnboundedReceiver<String>) {
    let path = dir.join("gpsd.sock");
    let listener = tokio::net::UnixListener::bind(&path).unwrap();
    let (tx, rx) = mpsc::unbounded_channel();
    tokio::spawn(async move {
        while let Ok((stream, _)) = listener.accept().await {
            let (read, mut write) = stream.into_split();
            let mut line = String::new();
            BufReader::new(read).read_line(&mut line).await.unwrap();
            let _ = tx.send(line);
            if !answer.is_empty() {
                write.write_all(answer.as_bytes()).await.unwrap();
            }
            // Keep the connection open until the client hangs up.
            let _ = write.shutdown().await;
        }
    });
    (path, rx)
}

#[tokio::test]
async fn adds_the_receiver_through_the_control_socket() {
    let dir = tempfile::tempdir().unwrap();
    let (ok, mut requests) = control_socket(dir.path(), "OK\n").await;
    assert_eq!(add_device(&ok, PATH).await, Ok(()));
    assert_eq!(requests.recv().await.unwrap(), format!("+{PATH}\n"));

    let json = tempfile::tempdir().unwrap();
    let (ok_json, _) = control_socket(json.path(), "{\"class\":\"OK\"}\r\n").await;
    assert_eq!(
        add_device(&ok_json, PATH).await,
        Ok(()),
        "gpsd 3.25's answer"
    );

    let refusing = tempfile::tempdir().unwrap();
    let (error, _) = control_socket(refusing.path(), "{\"class\":\"ERROR\"}\r\n").await;
    assert!(
        add_device(&error, PATH)
            .await
            .unwrap_err()
            .contains("ERROR")
    );
    let missing = add_device(&dir.path().join("none.sock"), PATH)
        .await
        .unwrap_err();
    assert!(
        missing.contains("can't reach gpsd's control socket"),
        "{missing}"
    );
}

#[tokio::test(start_paused = true)]
async fn a_silent_control_socket_times_out() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("gpsd.sock");
    let listener = tokio::net::UnixListener::bind(&path).unwrap();
    let _hold = tokio::spawn(async move {
        let (stream, _) = listener.accept().await.unwrap();
        std::future::pending::<()>().await;
        drop(stream);
    });
    assert!(
        add_device(&path, PATH)
            .await
            .unwrap_err()
            .contains("didn't answer")
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn adds_its_receiver_on_connect_and_again_when_gpsd_loses_it() {
    let dir = tempfile::tempdir().unwrap();
    let (socket, mut added) = control_socket(dir.path(), "OK\n").await;
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let module = Arc::new(GpsModule {
        address: listener.local_addr().unwrap(),
        backoff: (Duration::from_millis(10), Duration::from_millis(20)),
        device: Some((PATH.to_owned(), socket)),
        readd: Duration::from_millis(200),
    });
    let (ctx, mut reports, _requests) = context();
    let cancel = ctx.cancel.clone();
    let running = tokio::spawn({
        let module = Arc::clone(&module);
        async move { module.run(ctx).await }
    });
    // gpsd lists no receivers: the module adds it.
    let (stream, _) = listener.accept().await.unwrap();
    let (_read, mut write) = stream.into_split();
    write
        .write_all(b"{\"class\":\"DEVICES\",\"devices\":[]}\n")
        .await
        .unwrap();
    assert_eq!(added.recv().await.unwrap(), format!("+{PATH}\n"));
    let mut reported = next_report(&mut reports).await;
    while reported.get("device").is_none() {
        reported = next_report(&mut reports).await;
    }
    assert_eq!(reported["device"], json!({"path": PATH, "added": true}));

    // gpsd opens it and lists it: no more requests. Then it's gone (unplugged): added again.
    write
        .write_all(format!("{DEVICES}\n").as_bytes())
        .await
        .unwrap();
    tokio::time::sleep(Duration::from_millis(500)).await;
    assert!(added.try_recv().is_err(), "gpsd has it");
    let closed = format!("{{\"class\":\"DEVICE\",\"path\":\"{PATH}\",\"activated\":0}}\n");
    write.write_all(closed.as_bytes()).await.unwrap();
    let again = tokio::time::timeout(Duration::from_secs(5), added.recv()).await;
    assert_eq!(again.unwrap().unwrap(), format!("+{PATH}\n"));
    cancel.cancel();
    assert_eq!(running.await.unwrap(), Ok(()));
}

#[test]
fn reports_a_receiver_gpsd_refused() {
    let mut state = state_after(&[DEVICES]);
    state.set_device(PATH, Err("gpsd couldn't open it".into()));
    let reported = Value::Object(state.reported());
    assert_eq!(
        reported["device"],
        json!({"path": PATH, "added": false, "error": "gpsd couldn't open it"})
    );
    assert!(state.has_receiver(PATH));
    assert!(!state.has_receiver("/dev/other"));
    assert!(
        Value::Object(state_after(&[]).reported())
            .get("device")
            .is_none()
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_receiver_gpsd_already_has_is_not_added_again() {
    let dir = tempfile::tempdir().unwrap();
    let (socket, mut added) = control_socket(dir.path(), "{\"class\":\"ERROR\"}\r\n").await;
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let module = GpsModule {
        address: listener.local_addr().unwrap(),
        backoff: (Duration::from_millis(10), Duration::from_millis(20)),
        device: Some((PATH.to_owned(), socket)),
        readd: Duration::from_millis(100),
    };
    let (ctx, mut reports, _requests) = context();
    let cancel = ctx.cancel.clone();
    let running = tokio::spawn(async move { module.run(ctx).await });
    let (stream, _) = listener.accept().await.unwrap();
    let (_read, mut write) = stream.into_split();
    write
        .write_all(format!("{DEVICES}\n").as_bytes())
        .await
        .unwrap();
    let mut reported = next_report(&mut reports).await;
    while reported.get("device").is_none() {
        reported = next_report(&mut reports).await;
    }
    assert_eq!(reported["device"], json!({"path": PATH, "added": true}));
    assert!(added.try_recv().is_err(), "never asked: gpsd had it");
    cancel.cancel();
    assert_eq!(running.await.unwrap(), Ok(()));
}
