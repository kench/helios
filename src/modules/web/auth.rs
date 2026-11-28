//! Signing in to the local console (LLD 13, section 4): the device password, checked against
//! the Argon2id hash in `[modules.web] password_hash`; sessions held in memory; and a slowdown
//! for each source address that keeps getting the password wrong.

use std::collections::HashMap;
use std::net::IpAddr;
use std::time::{Duration, Instant};

use argon2::Argon2;
use argon2::password_hash::phc::PasswordHash;
use argon2::password_hash::{PasswordHasher, PasswordVerifier};

/// A session ends after this long without a request.
pub(crate) const IDLE: Duration = Duration::from_secs(12 * 60 * 60);
/// And after this long whatever happens.
pub(crate) const LIFETIME: Duration = Duration::from_secs(7 * 24 * 60 * 60);
/// At most this many sessions at once; the oldest go first.
const MAX_SESSIONS: usize = 64;
/// The longest a source address waits after wrong passwords.
const MAX_WAIT: Duration = Duration::from_secs(60);
/// At most this many addresses are remembered; the oldest go first.
const MAX_ADDRESSES: usize = 1024;

/// `password`'s Argon2id hash with a random salt, as a PHC string (`$argon2id$v=19$...`).
///
/// # Errors
///
/// If the system has no randomness for the salt.
pub(crate) fn hash_password(password: &[u8]) -> Result<String, String> {
    let mut salt = [0_u8; 16];
    getrandom::fill(&mut salt).map_err(|error| format!("no random salt: {error}"))?;
    Argon2::default()
        .hash_password_with_salt(password, &salt)
        .map(|hash| hash.to_string())
        .map_err(|error| format!("can't hash the password: {error}"))
}

/// Whether `hash` is an Argon2id PHC string this module can check passwords against.
pub(crate) fn is_argon2id(hash: &str) -> bool {
    PasswordHash::new(hash).is_ok_and(|parsed| parsed.algorithm.as_str() == "argon2id")
}

/// Whether `password` is the one `hash` was made from.
pub(crate) fn password_matches(hash: &str, password: &[u8]) -> bool {
    PasswordHash::new(hash)
        .is_ok_and(|parsed| Argon2::default().verify_password(password, &parsed).is_ok())
}

/// A random session ID: 256 bits, as hex.
///
/// # Errors
///
/// If the system has no randomness.
pub(crate) fn new_session_id() -> Result<String, String> {
    let mut bytes = [0_u8; 32];
    getrandom::fill(&mut bytes).map_err(|error| format!("no random session ID: {error}"))?;
    Ok(bytes.iter().map(|b| format!("{b:02x}")).collect())
}

#[derive(Debug, Clone, Copy)]
struct Session {
    created: Instant,
    used: Instant,
}

/// The signed-in sessions, in memory: a restart signs everyone out.
#[derive(Debug, Default)]
pub(crate) struct Sessions {
    by_id: HashMap<String, Session>,
}

impl Sessions {
    /// Starts a session `id` at `now`.
    pub(crate) fn start(&mut self, id: String, now: Instant) {
        self.expire(now);
        if self.by_id.len() >= MAX_SESSIONS
            && let Some(oldest) = self
                .by_id
                .iter()
                .min_by_key(|(_, s)| s.created)
                .map(|(id, _)| id.clone())
        {
            self.by_id.remove(&oldest);
        }
        self.by_id.insert(
            id,
            Session {
                created: now,
                used: now,
            },
        );
    }

    /// Whether `id` is a live session; a hit counts as use.
    pub(crate) fn check(&mut self, id: &str, now: Instant) -> bool {
        self.expire(now);
        match self.by_id.get_mut(id) {
            Some(session) => {
                session.used = now;
                true
            }
            None => false,
        }
    }

    /// Ends session `id`.
    pub(crate) fn end(&mut self, id: &str) {
        self.by_id.remove(id);
    }

    fn expire(&mut self, now: Instant) {
        self.by_id.retain(|_, s| {
            now.duration_since(s.used) < IDLE && now.duration_since(s.created) < LIFETIME
        });
    }

    #[cfg(test)]
    pub(crate) fn len(&self) -> usize {
        self.by_id.len()
    }
}

/// Wrong passwords, by source address: after each one, that address waits twice as long (1 s,
/// 2 s, 4 s, up to a minute) before it may try again.
#[derive(Debug, Default)]
pub(crate) struct Throttle {
    by_address: HashMap<IpAddr, (u32, Instant)>,
}

impl Throttle {
    /// How long `address` must still wait before trying again, if at all.
    pub(crate) fn wait(&self, address: IpAddr, now: Instant) -> Option<Duration> {
        let (_, until) = self.by_address.get(&address)?;
        until.checked_duration_since(now).filter(|d| !d.is_zero())
    }

    /// A wrong password from `address`.
    pub(crate) fn failed(&mut self, address: IpAddr, now: Instant) {
        if self.by_address.len() >= MAX_ADDRESSES
            && !self.by_address.contains_key(&address)
            && let Some(oldest) = self
                .by_address
                .iter()
                .min_by_key(|(_, (_, until))| *until)
                .map(|(a, _)| *a)
        {
            self.by_address.remove(&oldest);
        }
        let failures = self.by_address.get(&address).map_or(0, |(n, _)| *n) + 1;
        let wait = Duration::from_secs(1_u64 << (failures - 1).min(6)).min(MAX_WAIT);
        self.by_address.insert(address, (failures, now + wait));
    }

    /// The right password from `address`: it starts again from nothing.
    pub(crate) fn succeeded(&mut self, address: IpAddr) {
        self.by_address.remove(&address);
    }
}

#[cfg(test)]
mod tests;
