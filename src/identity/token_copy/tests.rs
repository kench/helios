use std::cell::RefCell;

use super::*;

/// A token directory with one token, as SoftHSM lays it out: `<uuid>/token.object` and more.
fn token(dir: &Path, marker: &str) {
    let token = dir.join("ba45177d-51c9-714b-48fc-c248b15742ce");
    fs::create_dir_all(&token).unwrap();
    fs::write(token.join("token.object"), format!("token {marker}")).unwrap();
    fs::write(token.join("generation"), "1").unwrap();
    fs::write(token.join("token.lock"), "").unwrap();
    fs::write(token.join("key.object"), format!("key {marker}")).unwrap();
}

fn marker(dir: &Path) -> String {
    fs::read_to_string(dir.join("ba45177d-51c9-714b-48fc-c248b15742ce/token.object")).unwrap()
}

struct Setup {
    _dir: tempfile::TempDir,
    master: PathBuf,
    runtime: PathBuf,
    conf: PathBuf,
}

fn setup() -> Setup {
    let dir = tempfile::tempdir().unwrap();
    let master = dir.path().join("lib/softhsm/tokens");
    fs::create_dir_all(master.parent().unwrap()).unwrap();
    let conf = dir.path().join("softhsm2.conf");
    fs::write(
        &conf,
        format!(
            "# Written by helios-firstboot.\ndirectories.tokendir = {}\nobjectstore.backend = \
             file\nlog.level = INFO\n",
            master.display()
        ),
    )
    .unwrap();
    Setup {
        runtime: dir.path().join("run/token"),
        master,
        conf,
        _dir: dir,
    }
}

/// A check that passes for copies whose token.object holds one of `good`, recording the
/// markers it saw.
fn checker<'a>(
    working: &'a Path,
    good: &'a [&'a str],
    seen: &'a RefCell<Vec<String>>,
) -> impl FnMut() -> Result<bool, String> + 'a {
    move || {
        let found =
            fs::read_to_string(working.join("ba45177d-51c9-714b-48fc-c248b15742ce/token.object"))
                .unwrap_or_default();
        seen.borrow_mut().push(found.clone());
        Ok(good.iter().any(|marker| found == format!("token {marker}")))
    }
}

#[test]
fn reads_and_rewrites_the_tokendir() {
    let conf = "# directories.tokendir = /old\ndirectories.tokendir = /var/lib/x \nlog.level = \
                INFO\n";
    assert_eq!(tokendir(conf), Some(PathBuf::from("/var/lib/x")));
    assert_eq!(tokendir("log.level = INFO\n"), None);
    assert_eq!(tokendir("directories.tokendir =\n"), None);
    assert_eq!(
        with_tokendir(conf, Path::new("/run/t")),
        "# directories.tokendir = /old\ndirectories.tokendir = /run/t\nlog.level = INFO\n"
    );
    assert_eq!(
        with_tokendir("log.level = INFO", Path::new("/run/t")),
        "log.level = INFO\ndirectories.tokendir = /run/t\n"
    );
    assert_eq!(
        sibling(Path::new("/var/lib/tokens"), ".old"),
        PathBuf::from("/var/lib/tokens.old")
    );
}

#[test]
fn direct_copies_the_config_and_touches_no_token() {
    let s = setup();
    token(&s.master, "a");
    let state = prepare(
        &s.conf,
        &s.runtime,
        TokenCopy::Direct,
        &mut || panic!("no check in direct mode"),
        "now",
    )
    .unwrap();
    assert_eq!(state.working, s.master);
    assert_eq!(
        fs::read_to_string(s.runtime.join(CONF_FILE)).unwrap(),
        fs::read_to_string(&s.conf).unwrap()
    );
    assert!(!s.runtime.join(WORKING_DIR).exists());
    assert_eq!(read_state(&s.runtime), Some(state));
}

#[test]
fn tmpfs_runs_on_a_copy_of_a_good_master() {
    let s = setup();
    token(&s.master, "a");
    let working = s.runtime.join(WORKING_DIR);
    let seen = RefCell::new(Vec::new());
    let state = prepare(
        &s.conf,
        &s.runtime,
        TokenCopy::Tmpfs,
        &mut checker(&working, &["a"], &seen),
        "now",
    )
    .unwrap();
    assert_eq!(state.working, working);
    assert_eq!(state.restored_from, None);
    assert!(!state.lost);
    assert_eq!(marker(&working), "token a");
    let conf = fs::read_to_string(s.runtime.join(CONF_FILE)).unwrap();
    assert_eq!(tokendir(&conf), Some(working.clone()));
    assert!(
        conf.contains("log.level = INFO"),
        "the rest is kept: {conf}"
    );
    let mode = |path: &Path| fs::metadata(path).unwrap().permissions().mode() & 0o777;
    assert_eq!(mode(&working), 0o700);
    assert_eq!(
        mode(&working.join("ba45177d-51c9-714b-48fc-c248b15742ce/token.object")),
        0o600
    );
    assert_eq!(mode(&s.runtime.join(CONF_FILE)), 0o600);
    assert!(
        !sibling(&s.master, ".old").exists(),
        "the master isn't rewritten"
    );
}

#[test]
fn a_broken_master_is_restored_from_old_and_repaired() {
    let s = setup();
    token(&s.master, "torn");
    token(&sibling(&s.master, ".old"), "good");
    let working = s.runtime.join(WORKING_DIR);
    let seen = RefCell::new(Vec::new());
    let state = prepare(
        &s.conf,
        &s.runtime,
        TokenCopy::Tmpfs,
        &mut checker(&working, &["good"], &seen),
        "2026-11-22T22:30:00Z",
    )
    .unwrap();
    assert_eq!(state.restored_from.as_deref(), Some("tokens.old"));
    assert_eq!(state.restored_at.as_deref(), Some("2026-11-22T22:30:00Z"));
    assert_eq!(marker(&working), "token good");
    assert_eq!(marker(&s.master), "token good", "the master is repaired");
    assert_eq!(
        marker(&sibling(&s.master, ".old")),
        "token torn",
        "the torn master is kept as .old for a person to look at"
    );
    assert_eq!(*seen.borrow(), ["token torn", "token good"]);
    assert_eq!(read_state(&s.runtime), Some(state));
}

#[test]
fn an_interrupted_save_is_finished_from_new() {
    // A save that stopped after renaming the master to .old: the complete .new is newest.
    let s = setup();
    token(&sibling(&s.master, ".new"), "newest");
    token(&sibling(&s.master, ".old"), "older");
    let working = s.runtime.join(WORKING_DIR);
    let seen = RefCell::new(Vec::new());
    let state = prepare(
        &s.conf,
        &s.runtime,
        TokenCopy::Tmpfs,
        &mut checker(&working, &["newest", "older"], &seen),
        "now",
    )
    .unwrap();
    assert_eq!(state.restored_from.as_deref(), Some("tokens.new"));
    assert_eq!(marker(&s.master), "token newest");
    assert!(!sibling(&s.master, ".new").exists());
}

#[test]
fn when_nothing_passes_it_runs_on_the_master_and_says_lost() {
    let s = setup();
    token(&s.master, "torn");
    token(&sibling(&s.master, ".old"), "torn too");
    let working = s.runtime.join(WORKING_DIR);
    let mut failing = || Err::<bool, String>("can't run the check".into());
    let state = prepare(&s.conf, &s.runtime, TokenCopy::Tmpfs, &mut failing, "now").unwrap();
    assert!(state.lost);
    assert_eq!(state.restored_from, None);
    assert_eq!(marker(&working), "token torn");
    assert_eq!(
        marker(&sibling(&s.master, ".old")),
        "token torn too",
        "nothing is overwritten"
    );
}

#[test]
fn an_unprovisioned_board_gets_an_empty_working_copy() {
    let s = setup();
    let working = s.runtime.join(WORKING_DIR);
    let state = prepare(
        &s.conf,
        &s.runtime,
        TokenCopy::Tmpfs,
        &mut || panic!("nothing to check"),
        "now",
    )
    .unwrap();
    assert!(!state.lost);
    assert!(working.is_dir());
    assert_eq!(fs::read_dir(&working).unwrap().count(), 0);
}

#[test]
fn saves_through_new_and_keeps_the_previous_master() {
    let s = setup();
    token(&s.master, "v1");
    let working = s.runtime.join(WORKING_DIR);
    token(&working, "v2");
    save(&working, &s.master).unwrap();
    assert_eq!(marker(&s.master), "token v2");
    assert_eq!(marker(&sibling(&s.master, ".old")), "token v1");
    assert!(!sibling(&s.master, ".new").exists());

    // A stale .new from an earlier interrupted save is replaced, not trusted.
    token(&sibling(&s.master, ".new"), "stale");
    token(&working, "v3");
    save(&working, &s.master).unwrap();
    assert_eq!(marker(&s.master), "token v3");
    assert_eq!(marker(&sibling(&s.master, ".old")), "token v2");

    // The first save of a board that has no master yet.
    let fresh = s.runtime.join("fresh/tokens");
    fs::create_dir_all(fresh.parent().unwrap()).unwrap();
    save(&working, &fresh).unwrap();
    assert_eq!(marker(&fresh), "token v3");
    assert!(!sibling(&fresh, ".old").exists());
}

#[test]
fn reports_unusable_configs_and_files() {
    let s = setup();
    fs::write(&s.conf, "log.level = INFO\n").unwrap();
    let error = prepare(
        &s.conf,
        &s.runtime,
        TokenCopy::Direct,
        &mut || Ok(true),
        "now",
    )
    .unwrap_err();
    assert!(matches!(error, CopyError::Config { .. }), "{error}");
    assert!(error.to_string().contains("directories.tokendir"));
    let missing = s.runtime.join("missing.conf");
    let error = prepare(
        &missing,
        &s.runtime,
        TokenCopy::Direct,
        &mut || Ok(true),
        "now",
    )
    .unwrap_err();
    assert!(error.to_string().starts_with("read "), "{error}");
    assert!(save(&s.runtime.join("nothing"), &s.master).is_err());
    assert_eq!(read_state(&s.runtime.join("nowhere")), None);
}
