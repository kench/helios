//! `helios.toml` parsing and startup-check tests (LLD 1, sections 3 and 9).

use std::path::Path;

use super::*;
use crate::identity::testing::{THING_NAME, ca, device_certificate};

/// A directory with a fake PKCS#11 module and CA bundle, for configs to point at.
struct Files {
    dir: tempfile::TempDir,
}

impl Files {
    fn new() -> Self {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("libsofthsm2.so"), b"not really a module").unwrap();
        std::fs::write(dir.path().join("libmock.so"), b"not really a module").unwrap();
        std::fs::write(dir.path().join("roots.pem"), ca("Helios test root").pem).unwrap();
        Self { dir }
    }

    fn path(&self, name: &str) -> String {
        self.dir.path().join(name).display().to_string()
    }

    /// A config with a local PIN file and every setting it needs, plus `extra`.
    fn local(&self, extra: &str) -> String {
        format!(
            r#"
[device]
thing_name = "{THING_NAME}"

[identity]
pkcs11_module = "{module}"
token_label   = "helios"
key_label     = "device-key"
pin           = "file:/etc/helios/pin"

[aws]
region               = "us-west-2"
iot_endpoint         = "example-ats.iot.us-west-2.amazonaws.com"
credentials_endpoint = "example.credentials.iot.us-west-2.amazonaws.com"
role_alias           = "helios-device-role-alias"
root_ca              = "{roots}"
{extra}"#,
            module = self.path("libsofthsm2.so"),
            roots = self.path("roots.pem"),
        )
    }

    /// A bootstrap config with nothing else set locally, plus `extra` in `[bootstrap]`.
    fn bootstrap(&self, extra: &str) -> String {
        format!(
            r#"
[bootstrap]
url = "https://device-management.services.kenley.tv/v1"
ca  = "{roots}"
{extra}

[identity]
pkcs11_module = "{module}"
pin           = "bootstrap"

[aws]
root_ca = "{roots}"
"#,
            module = self.path("libsofthsm2.so"),
            roots = self.path("roots.pem"),
        )
    }

    fn load(&self, text: &str) -> Result<Config, ConfigError> {
        let path = self.dir.path().join("helios.toml");
        std::fs::write(&path, text).unwrap();
        Config::load(&path, |name| name == SOFTHSM2_CONF)
    }

    fn error(&self, text: &str) -> String {
        self.load(text).unwrap_err().message
    }
}

#[test]
fn loads_a_local_pin_config() {
    let files = Files::new();

    let config = files.load(&files.local("")).unwrap();

    assert_eq!(config.pin, PinSpec::File("/etc/helios/pin".into()));
    assert_eq!(
        config.pkcs11_module,
        Path::new(&files.path("libsofthsm2.so"))
    );
    assert_eq!(config.thing_name.as_deref(), Some(THING_NAME));
    assert_eq!(config.token_label.as_deref(), Some("helios"));
    assert_eq!(config.key_label.as_deref(), Some("device-key"));
    assert_eq!(config.certificate, CertificateSource::Token);
    assert!(!config.allow_final_pin_try);
    assert_eq!(config.sign_timeout, DEFAULT_SIGN_TIMEOUT);
    assert_eq!(config.roots.len(), 1);
    let aws = config.aws.unwrap();
    assert_eq!(aws.role_alias, "helios-device-role-alias");
    assert_eq!(
        aws.credentials_endpoint,
        "example.credentials.iot.us-west-2.amazonaws.com"
    );
    assert!(config.bootstrap.is_none());
    assert!(config.ignored_sections.is_empty());
}

#[test]
fn loads_a_bootstrap_config() {
    let files = Files::new();

    let config = files.load(&files.bootstrap("")).unwrap();

    assert_eq!(config.pin, PinSpec::Bootstrap);
    assert!(config.thing_name.is_none());
    assert!(config.token_label.is_none());
    assert!(config.aws.is_none());
    let bootstrap = config.bootstrap.unwrap();
    assert_eq!(
        bootstrap.url,
        "https://device-management.services.kenley.tv/v1"
    );
    assert_eq!(bootstrap.interfaces, Interfaces::Auto);
    assert_eq!(bootstrap.timeout, Duration::from_secs(10));
    assert!(bootstrap.challenge_key_label.is_none());
}

#[test]
fn reads_the_optional_bootstrap_settings() {
    let files = Files::new();

    let config = files
        .load(&files.bootstrap(
            "interfaces = [\"eth0\", \"wlan0\"]\ntimeout_ms = 2500\nchallenge_key_label = \
             \"challenge-key\"",
        ))
        .unwrap();

    let bootstrap = config.bootstrap.unwrap();
    assert_eq!(
        bootstrap.interfaces,
        Interfaces::Named(vec!["eth0".into(), "wlan0".into()])
    );
    assert_eq!(bootstrap.timeout, Duration::from_millis(2500));
    assert_eq!(
        bootstrap.challenge_key_label.as_deref(),
        Some("challenge-key")
    );

    let auto = files
        .load(&files.bootstrap("interfaces = \"auto\""))
        .unwrap();
    assert_eq!(auto.bootstrap.unwrap().interfaces, Interfaces::Auto);
}

#[test]
fn reads_the_optional_identity_settings() {
    let files = Files::new();
    let text = files.local("").replace(
        "pin           = \"file:/etc/helios/pin\"",
        "pin = \"credential:helios-pin\"\nallow_final_pin_try = true\nsign_timeout_ms = 1500",
    );

    let config = files.load(&text).unwrap();

    assert_eq!(config.pin, PinSpec::Credential("helios-pin".into()));
    assert!(config.allow_final_pin_try);
    assert_eq!(config.sign_timeout, Duration::from_millis(1500));
}

#[test]
fn reads_the_clock_report_setting() {
    use crate::clock::ClockReport;
    let files = Files::new();
    let with = |section: &str| format!("{}\n[clock]\n{section}\n", files.local(""));
    assert_eq!(
        files.load(&files.local("")).unwrap().clock.report,
        ClockReport::Synced
    );
    assert_eq!(
        files.load(&with("report = \"full\"")).unwrap().clock.report,
        ClockReport::Full
    );
    assert_eq!(
        files
            .load(&with("report = \"synced\""))
            .unwrap()
            .clock
            .report,
        ClockReport::Synced
    );
    let error = files.load(&with("report = \"all\"")).unwrap_err();
    assert!(error.message.contains("clock.report"), "{error}");
}

#[test]
fn reads_the_token_copy_mode() {
    use crate::identity::token_copy::TokenCopy;
    let files = Files::new();
    let with = |line: &str| {
        files.local("").replace(
            "pin           = \"file:/etc/helios/pin\"",
            &format!("pin           = \"file:/etc/helios/pin\"\n{line}"),
        )
    };
    assert_eq!(files.load(&with("")).unwrap().token_copy, TokenCopy::Direct);
    assert_eq!(
        files
            .load(&with("token_copy = \"tmpfs\""))
            .unwrap()
            .token_copy,
        TokenCopy::Tmpfs
    );
    assert_eq!(
        files
            .load(&with("token_copy = \"direct\""))
            .unwrap()
            .token_copy,
        TokenCopy::Direct
    );
    let error = files.load(&with("token_copy = \"ram\"")).unwrap_err();
    assert!(error.message.contains("token_copy"), "{error}");
}

#[test]
fn defaults_to_the_softhsm2_module() {
    let files = Files::new();
    let text = files.local("").replace(
        &format!("pkcs11_module = \"{}\"\n", files.path("libsofthsm2.so")),
        "",
    );

    // Whether or not SoftHSM2 is installed where the test runs, the default is the one used.
    match files.load(&text) {
        Ok(config) => assert_eq!(config.pkcs11_module, Path::new(DEFAULT_MODULE)),
        Err(error) => assert!(error.message.contains(DEFAULT_MODULE), "{error}"),
    }
}

#[test]
fn reads_a_certificate_chain_from_a_pem_file() {
    let files = Files::new();
    let device_ca = ca("Helios test device CA");
    let key = p256::ecdsa::SigningKey::from_slice(&[7; 32]).unwrap();
    let cert = device_certificate(&device_ca, &key, THING_NAME);
    let pem = format!(
        "-----BEGIN CERTIFICATE-----\n{}\n-----END CERTIFICATE-----\n",
        base64::Engine::encode(&base64::engine::general_purpose::STANDARD, cert.as_ref())
    );
    std::fs::write(files.dir.path().join("cert.pem"), pem).unwrap();
    let text = files.local("").replace(
        "pin           =",
        &format!("certificate = \"{}\"\npin =", files.path("cert.pem")),
    );

    let config = files.load(&text).unwrap();

    assert_eq!(config.certificate, CertificateSource::Chain(vec![cert]));
}

#[test]
fn rejects_a_certificate_file_without_certificates() {
    let files = Files::new();
    std::fs::write(files.dir.path().join("empty.pem"), "nothing here\n").unwrap();
    for (value, expected) in [
        (files.path("empty.pem"), "no certificates"),
        (files.path("missing.pem"), "missing.pem"),
    ] {
        let text = files.local("").replace(
            "pin           =",
            &format!("certificate = \"{value}\"\npin ="),
        );

        let error = files.error(&text);

        assert!(error.contains("identity.certificate"), "{error}");
        assert!(error.contains(expected), "{error}");
    }
}

#[test]
fn reports_sections_it_does_not_use() {
    let files = Files::new();

    let config = files
        .load(&files.local("\n[modules.usb]\nenabled = true\n\n[telemetry]\ninterval_s = 30\n"))
        .unwrap();

    #[cfg(feature = "module-usb")]
    {
        assert!(config.usb.is_some());
        assert_eq!(config.ignored_sections, ["telemetry"]);
    }
    #[cfg(not(feature = "module-usb"))]
    assert_eq!(config.ignored_sections, ["modules.usb", "telemetry"]);
}

#[test]
fn allows_an_unused_bootstrap_section_with_a_local_pin() {
    let files = Files::new();
    let text = format!(
        "{}\n[bootstrap]\nurl = \"https://example.com/v1\"\nca = \"{}\"\n",
        files.local(""),
        files.path("roots.pem")
    );

    let config = files.load(&text).unwrap();

    assert!(config.bootstrap.is_none());
}

#[test]
fn rejects_unknown_keys_in_known_sections() {
    let files = Files::new();
    let text = files
        .local("")
        .replace("key_label     =", "key_lable = \"x\"\nkey_label =");

    let error = files.error(&text);

    assert!(error.contains("key_lable"), "{error}");
}

#[test]
fn reports_unreadable_and_unparseable_files() {
    let files = Files::new();
    let missing = files.dir.path().join("nope.toml");
    let error = Config::load(&missing, |_| true).unwrap_err();
    assert_eq!(error.path, missing);

    let error = files.error("[identity\npin = ");
    assert!(
        error.contains("TOML") || error.contains("expected"),
        "{error}"
    );

    // The error names the file.
    let error = files.load("[identity]\n").unwrap_err();
    assert!(error.to_string().starts_with(&files.path("helios.toml")));
}

#[test]
fn needs_identity_and_aws_sections_and_a_pin() {
    let files = Files::new();

    assert!(
        files
            .error("[aws]\nroot_ca = \"/x\"\n")
            .contains("identity")
    );
    assert!(
        files
            .error("[identity]\npin = \"bootstrap\"\n")
            .contains("aws")
    );
    assert!(
        files
            .error(
                &files
                    .local("")
                    .replace("pin           = \"file:/etc/helios/pin\"\n", "")
            )
            .contains("pin")
    );
}

#[test]
fn rejects_an_invalid_pin_setting() {
    let files = Files::new();
    for (pin, expected) in [
        ("1234", "identity.pin must be"),
        ("file:relative/pin", "must be absolute"),
        ("credential:", "credential name"),
    ] {
        let text = files.local("").replace("file:/etc/helios/pin", pin);

        let error = files.error(&text);

        assert!(error.contains(expected), "{pin}: {error}");
    }
}

#[test]
fn local_pin_needs_the_device_settings() {
    let files = Files::new();
    for (line, setting) in [
        (
            format!("thing_name = \"{THING_NAME}\""),
            "device.thing_name",
        ),
        (
            "token_label   = \"helios\"".to_owned(),
            "identity.token_label",
        ),
        (
            "key_label     = \"device-key\"".to_owned(),
            "identity.key_label",
        ),
    ] {
        let text = files.local("").replace(&line, "");

        let error = files.error(&text);

        assert!(error.contains(setting), "{setting}: {error}");
        assert!(error.contains("not from the bootstrap service"), "{error}");
    }
}

#[test]
fn local_pin_needs_the_aws_endpoints() {
    let files = Files::new();
    let text = files
        .local("")
        .lines()
        .filter(|line| {
            ![
                "region",
                "iot_endpoint",
                "credentials_endpoint",
                "role_alias",
            ]
            .iter()
            .any(|key| line.starts_with(key))
        })
        .collect::<Vec<_>>()
        .join("\n");

    let error = files.error(&text);

    assert!(error.contains("aws.role_alias must be set"), "{error}");
}

#[test]
fn aws_endpoints_are_all_or_nothing() {
    let files = Files::new();
    let text = files
        .local("")
        .replace("role_alias           = \"helios-device-role-alias\"\n", "");

    let error = files.error(&text);

    assert!(error.contains("set together"), "{error}");
}

#[test]
fn bootstrap_pin_needs_a_bootstrap_section() {
    let files = Files::new();
    let text = files.bootstrap("");
    let text = &text[text.find("[identity]").unwrap()..];

    let error = files.error(text);

    assert!(error.contains("[bootstrap] section"), "{error}");
}

#[test]
fn bootstrap_url_must_be_https() {
    let files = Files::new();
    let text = files.bootstrap("").replace("https://", "http://");

    let error = files.error(&text);

    assert!(error.contains("must start with https://"), "{error}");
}

#[test]
fn rejects_bad_bootstrap_interfaces() {
    let files = Files::new();

    assert!(
        files
            .error(&files.bootstrap("interfaces = \"eth0\""))
            .contains("\"auto\" or a list")
    );
    assert!(
        files
            .error(&files.bootstrap("interfaces = []"))
            .contains("empty list")
    );
}

#[test]
fn rejects_long_and_empty_labels() {
    let files = Files::new();
    let long = "x".repeat(MAX_LABEL_LEN + 1);
    for (from, to, setting) in [
        (
            "token_label   = \"helios\"",
            format!("token_label = \"{long}\""),
            "identity.token_label",
        ),
        (
            "key_label     = \"device-key\"",
            "key_label = \"\"".to_owned(),
            "identity.key_label",
        ),
    ] {
        let text = files.local("").replace(from, &to);

        let error = files.error(&text);

        assert!(error.contains(setting), "{error}");
        assert!(error.contains("1 to 32 bytes"), "{error}");
    }
    let error = files.error(&files.bootstrap(&format!("challenge_key_label = \"{long}\"")));
    assert!(error.contains("bootstrap.challenge_key_label"), "{error}");
}

#[test]
fn accepts_a_label_of_exactly_32_bytes() {
    let files = Files::new();
    let label = "x".repeat(MAX_LABEL_LEN);
    let text = files
        .local("")
        .replace("\"device-key\"", &format!("\"{label}\""));

    assert_eq!(files.load(&text).unwrap().key_label, Some(label));
}

#[test]
fn rejects_invalid_thing_names() {
    let files = Files::new();
    for name in [
        "",
        "has space",
        "slash/name",
        &"x".repeat(MAX_THING_NAME_LEN + 1),
    ] {
        let text = files.local("").replace(THING_NAME, name);

        let error = files.error(&text);

        assert!(
            error.contains("not a valid AWS IoT thing name"),
            "{name:?}: {error}"
        );
    }
}

#[test]
fn checks_that_the_files_are_there() {
    let files = Files::new();
    let module = files.local("").replace("libsofthsm2.so", "missing.so");
    assert!(files.error(&module).contains("identity.pkcs11_module"));

    let roots = files.local("").replace("roots.pem", "missing.pem");
    assert!(files.error(&roots).contains("aws.root_ca"));

    std::fs::write(files.dir.path().join("junk.pem"), "junk").unwrap();
    let junk = files.local("").replace("roots.pem", "junk.pem");
    assert!(files.error(&junk).contains("aws.root_ca"));

    let bootstrap_ca =
        files
            .bootstrap("")
            .replacen(&files.path("roots.pem"), &files.path("missing.pem"), 1);
    assert!(files.error(&bootstrap_ca).contains("bootstrap.ca"));
}

#[test]
fn softhsm2_needs_its_config_variable() {
    let files = Files::new();
    let path = files.dir.path().join("helios.toml");
    std::fs::write(&path, files.local("")).unwrap();

    let error = Config::load(&path, |_| false).unwrap_err();

    assert!(error.message.contains(SOFTHSM2_CONF), "{error}");

    // Other modules don't need it.
    let other = files.local("").replace("libsofthsm2.so", "libmock.so");
    std::fs::write(&path, other).unwrap();
    assert!(Config::load(&path, |_| false).is_ok());
}

#[test]
fn the_shipped_example_parses() {
    let text =
        std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/dist/helios.toml")).unwrap();

    let file: File = toml::from_str(&text).unwrap();

    assert_eq!(file.identity.pin, "bootstrap");
    assert!(file.bootstrap.is_some());
    assert!(file.other.is_empty());
    #[cfg(feature = "module-usb")]
    assert!(
        file.modules
            .usb
            .expect("the usb section")
            .check()
            .expect("valid usb settings")
            .is_some()
    );
    #[cfg(feature = "module-net")]
    assert_eq!(
        file.modules
            .net
            .expect("the net section")
            .check()
            .expect("valid net settings"),
        Some(crate::modules::net::NetSettings::default())
    );
}

#[cfg(feature = "module-net")]
#[test]
fn reads_and_checks_the_net_settings() {
    let files = Files::new();
    let config = files
        .load(&files.local("\n[modules.net]\nexclude = [\"docker*\"]\n"))
        .unwrap();
    assert!(config.net.expect("enabled").excludes("docker0"));
    let config = files
        .load(&files.local("\n[modules.net]\nenabled = false\n"))
        .unwrap();
    assert_eq!(config.net, None);
    let error = files
        .load(&files.local("\n[modules.net]\nexclude = [\"a b\"]\n"))
        .unwrap_err();
    assert!(error.to_string().contains("modules.net.exclude"), "{error}");
}

#[test]
fn reads_the_mqtt_settings() {
    let files = Files::new();
    let text = files.local(
        "\n[mqtt]\nport = 443\nkeep_alive_s = 300\nqueue_messages = 50\ncommands = \"topics\"\nhelios_shadow_interval_s = 900\n",
    );

    let config = files.load(&text).unwrap();

    assert_eq!(config.mqtt.port, 443);
    assert_eq!(config.mqtt.keep_alive, Duration::from_secs(300));
    assert_eq!(config.mqtt.queue_messages, 50);
    assert_eq!(config.mqtt.helios_shadow_interval, Duration::from_secs(900));
    assert!(config.ignored_sections.is_empty());
}

#[test]
fn mqtt_defaults_without_a_section() {
    let files = Files::new();

    assert_eq!(
        files.load(&files.local("")).unwrap().mqtt,
        crate::mqtt::MqttSettings::default()
    );
}

#[test]
fn reads_the_command_transports() {
    let files = Files::new();
    let config = files.load(&files.local("")).unwrap();
    assert_eq!(
        config.mqtt.commands,
        crate::mqtt::CommandTransports::default()
    );
    assert!(config.mqtt.commands.topics && config.mqtt.commands.aws_iot_commands);
    for (setting, topics, aws) in [
        ("\"topics\"", true, false),
        ("\"aws-iot-commands\"", false, true),
        ("[\"aws-iot-commands\", \"topics\"]", true, true),
    ] {
        let config = files
            .load(&files.local(&format!("\n[mqtt]\ncommands = {setting}\n")))
            .unwrap();
        assert_eq!(
            (
                config.mqtt.commands.topics,
                config.mqtt.commands.aws_iot_commands
            ),
            (topics, aws),
            "{setting}"
        );
        let subscriptions = config
            .mqtt
            .commands
            .transports()
            .iter()
            .flat_map(|transport| transport.subscriptions("t-1"))
            .count();
        assert_eq!(subscriptions, usize::from(topics) + 3 * usize::from(aws));
    }
}

#[test]
fn rejects_bad_mqtt_settings() {
    let files = Files::new();
    for (section, expected) in [
        ("port = 1883", "mqtt.port must be 8883 or 443"),
        ("keep_alive_s = 10", "mqtt.keep_alive_s must be 30 to 1200"),
        (
            "keep_alive_s = 1201",
            "mqtt.keep_alive_s must be 30 to 1200",
        ),
        (
            "queue_messages = 0",
            "mqtt.queue_messages must be at least 1",
        ),
        ("commands = \"jobs\"", "mqtt.commands must be"),
        ("commands = [\"topics\", \"jobs\"]", "mqtt.commands must be"),
        ("commands = []", "at least one transport"),
        ("commands = 1", "TOML parse error"),
        (
            "helios_shadow_interval_s = 9",
            "mqtt.helios_shadow_interval_s must be 10 to 86400",
        ),
        (
            "helios_shadow_interval_s = 86401",
            "mqtt.helios_shadow_interval_s must be 10 to 86400",
        ),
        ("unknown = 1", "unknown"),
    ] {
        let error = files.error(&files.local(&format!("\n[mqtt]\n{section}\n")));

        assert!(error.contains(expected), "{section}: {error}");
    }
}

#[test]
fn reads_the_clock_settings() {
    let files = Files::new();

    let config = files
        .load(&files.local("\n[clock]\nwarn_offset_s = 30\n"))
        .unwrap();
    let defaults = files.load(&files.local("")).unwrap();

    assert_eq!(config.clock.warn_offset, Duration::from_secs(30));
    assert_eq!(defaults.clock, crate::clock::ClockSettings::default());
    assert_eq!(
        defaults.clock.boot_mark.as_deref(),
        Some(std::path::Path::new("/run/helios/boot-clock"))
    );
}

#[test]
fn rejects_bad_clock_settings() {
    let files = Files::new();
    for (section, expected) in [
        (
            "warn_offset_s = 0",
            "clock.warn_offset_s must be from 1 to 239",
        ),
        (
            "warn_offset_s = 240",
            "clock.warn_offset_s must be from 1 to 239",
        ),
        (
            "state_file = \"/var/lib/helios/clock\"",
            "isn't supported yet",
        ),
        ("unknown = 1", "unknown"),
    ] {
        let error = files.error(&files.local(&format!("\n[clock]\n{section}\n")));

        assert!(error.contains(expected), "{section}: {error}");
    }
}

#[cfg(feature = "module-display")]
#[test]
fn display_module_is_off_unless_enabled() {
    let files = Files::new();

    assert!(files.load(&files.local("")).unwrap().display.is_none());
    let disabled = files
        .load(&files.local("\n[modules.display]\nenabled = false\ntime_zone = \"Nowhere/Else\"\n"))
        .unwrap();
    assert!(disabled.display.is_none());
}

#[cfg(feature = "module-display")]
#[test]
fn display_module_defaults() {
    let files = Files::new();

    let config = files
        .load(&files.local("\n[modules.display]\nenabled = true\n"))
        .unwrap();
    let display = config.display.unwrap();
    assert_eq!(display.framebuffer, PathBuf::from("/dev/fb0"));
    assert_eq!(display.idle, Screen::Status);
    assert_eq!(display.time_zone_name, "UTC");
    assert_eq!(display.redraw_interval, Duration::from_secs(10));
    assert_eq!(display.bold_font, None);
    assert!(config.ignored_sections.is_empty());
}

#[cfg(feature = "module-display")]
#[test]
fn display_module_settings() {
    let files = Files::new();

    let config = files
        .load(&files.local(
            "\n[modules.display]\nenabled = true\nframebuffer = \"/dev/fb1\"\n\
             idle_template = \"blank\"\ntime_zone = \"America/Los_Angeles\"\n\
             redraw_interval_s = 0\nbold_font = \"/run/helios/fonts/Bold.otf\"\n\n\
             [modules.barcode]\nenabled = true\n",
        ))
        .unwrap();
    let display = config.display.unwrap();
    assert_eq!(display.framebuffer, PathBuf::from("/dev/fb1"));
    assert_eq!(display.idle, Screen::Blank);
    assert_eq!(display.time_zone_name, "America/Los_Angeles");
    assert!(display.redraw_interval.is_zero());
    assert_eq!(
        display.bold_font,
        Some(PathBuf::from("/run/helios/fonts/Bold.otf"))
    );
    assert_eq!(config.ignored_sections, ["modules.barcode"]);
}

#[cfg(feature = "module-display")]
#[test]
fn display_module_refuses_bad_settings() {
    let files = Files::new();

    for (section, expected) in [
        ("time_zone = \"Nowhere/Else\"", "isn't a known time zone"),
        ("idle_template = \"message\"", "only display.idle can set"),
        ("idle_template = \"fancy\"", "no template"),
        (
            "redraw_interval_s = 3601",
            "redraw_interval_s must be 0 to 3600",
        ),
        ("brightness = 5", "unknown field"),
    ] {
        let error =
            files.error(&files.local(&format!("\n[modules.display]\nenabled = true\n{section}\n")));
        assert!(error.contains(expected), "{section}: {error}");
    }
}

#[cfg(not(feature = "module-display"))]
#[test]
fn a_build_without_the_display_module_ignores_its_section() {
    let files = Files::new();

    let config = files
        .load(&files.local("\n[modules.display]\nenabled = true\nbold_font = 5\n"))
        .unwrap();
    assert_eq!(config.ignored_sections, ["modules.display"]);
}
