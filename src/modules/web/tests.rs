use super::{DEFAULT_CONSOLE_DIR, WebSettings, auth};

fn settings(toml: &str) -> Result<Option<WebSettings>, String> {
    let parsed: WebSettings = toml::from_str(toml).map_err(|e| e.to_string())?;
    parsed.check()
}

#[test]
fn checks_its_settings() {
    let hash = auth::hash_password(b"password-1").unwrap();
    let ok = settings(&format!("name = \"pocket\"\npassword_hash = \"{hash}\""))
        .unwrap()
        .unwrap();
    assert_eq!(ok.name, "pocket");
    assert_eq!(ok.listen().to_string(), "0.0.0.0:8080");
    assert_eq!(ok.console_dir.to_str(), Some(DEFAULT_CONSOLE_DIR));
    assert_eq!(ok.role, "transcoder");
    assert_eq!(
        settings("enabled = false").unwrap(),
        None,
        "off: nothing checked"
    );

    for (toml, problem) in [
        (format!("password_hash = \"{hash}\""), "modules.web.name"),
        (
            format!("name = \"Pocket\"\npassword_hash = \"{hash}\""),
            "modules.web.name",
        ),
        (
            format!("name = \"-a\"\npassword_hash = \"{hash}\""),
            "modules.web.name",
        ),
        ("name = \"pocket\"".to_owned(), "password_hash is required"),
        (
            "name = \"pocket\"\npassword_hash = \"hunter2\"".to_owned(),
            "isn't an Argon2id hash",
        ),
        (
            format!("name = \"pocket\"\npassword_hash = \"{hash}\"\nlisten = \"8080\""),
            "modules.web.listen",
        ),
        (
            format!("name = \"pocket\"\npassword_hash = \"{hash}\"\nconsole_dir = \"site\""),
            "console_dir",
        ),
        (
            format!("name = \"pocket\"\npassword_hash = \"{hash}\"\nrole = \"scanner\""),
            "modules.web.role",
        ),
    ] {
        let error = settings(&toml).unwrap_err();
        assert!(error.contains(problem), "{toml}: {error}");
        assert!(!error.contains("password-1"), "never the password");
    }
    assert!(
        settings("name = \"pocket\"\nport = 1")
            .unwrap_err()
            .contains("unknown field")
    );
}
