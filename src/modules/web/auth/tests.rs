use std::net::{IpAddr, Ipv4Addr};
use std::time::{Duration, Instant};

use super::{
    IDLE, LIFETIME, Sessions, Throttle, hash_password, is_argon2id, new_session_id,
    password_matches,
};

#[test]
fn hashes_and_checks_passwords() {
    let hash = hash_password(b"correct horse").unwrap();
    assert!(hash.starts_with("$argon2id$v=19$"), "{hash}");
    assert!(is_argon2id(&hash));
    assert!(password_matches(&hash, b"correct horse"));
    assert!(!password_matches(&hash, b"correct horse "));
    assert_ne!(
        hash,
        hash_password(b"correct horse").unwrap(),
        "a new salt each time"
    );
    for bad in ["", "plain", "$argon2i$v=19$m=16,t=2,p=1$c2FsdHNhbHQ$aGFzaA"] {
        assert!(!is_argon2id(bad), "{bad}");
        assert!(!password_matches(bad, b"x"), "{bad}");
    }
}

#[test]
fn session_ids_are_random_256_bit_hex() {
    let a = new_session_id().unwrap();
    assert_eq!(a.len(), 64);
    assert!(a.bytes().all(|b| b.is_ascii_hexdigit()));
    assert_ne!(a, new_session_id().unwrap());
}

#[test]
fn sessions_end_when_idle_too_long_or_too_old() {
    let start = Instant::now();
    let mut sessions = Sessions::default();
    sessions.start("a".into(), start);
    assert!(sessions.check("a", start + Duration::from_secs(60)));
    assert!(!sessions.check("b", start));

    // Used every 11 hours: never idle 12, but gone after 7 days.
    let mut now = start;
    while now.duration_since(start) + Duration::from_secs(11 * 3600) < LIFETIME {
        now += Duration::from_secs(11 * 3600);
        assert!(sessions.check("a", now));
    }
    assert!(!sessions.check("a", start + LIFETIME));

    sessions.start("c".into(), start);
    assert!(!sessions.check("c", start + IDLE), "idle 12 hours");
    sessions.start("d".into(), start);
    sessions.end("d");
    assert!(!sessions.check("d", start));
}

#[test]
fn keeps_at_most_64_sessions_dropping_the_oldest() {
    let start = Instant::now();
    let mut sessions = Sessions::default();
    for n in 0..70_u64 {
        sessions.start(format!("s{n}"), start + Duration::from_millis(n));
    }
    assert_eq!(sessions.len(), 64);
    let later = start + Duration::from_secs(1);
    assert!(!sessions.check("s0", later));
    assert!(sessions.check("s69", later));
}

#[test]
fn slows_each_address_down_after_wrong_passwords() {
    let now = Instant::now();
    let phone: IpAddr = Ipv4Addr::new(192, 168, 5, 50).into();
    let other: IpAddr = Ipv4Addr::new(192, 168, 5, 51).into();
    let mut throttle = Throttle::default();
    assert_eq!(throttle.wait(phone, now), None);
    for expected in [1, 2, 4, 8, 16, 32, 60, 60] {
        throttle.failed(phone, now);
        assert_eq!(
            throttle.wait(phone, now),
            Some(Duration::from_secs(expected))
        );
    }
    assert_eq!(throttle.wait(other, now), None, "per address");
    assert_eq!(throttle.wait(phone, now + Duration::from_secs(61)), None);
    throttle.succeeded(phone);
    throttle.failed(phone, now);
    assert_eq!(
        throttle.wait(phone, now),
        Some(Duration::from_secs(1)),
        "a right password starts it again"
    );
}
