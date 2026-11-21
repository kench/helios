//! The request to the AWS IoT credentials provider (LLD 1, sections 5.1 and 5.2).
//!
//! `GET /role-aliases/{role_alias}/credentials` with the thing name in
//! `x-amzn-iot-thingname`, over mutual TLS with the device certificate. The response's
//! secrets go straight into `SecretString`s and the body is never logged.
//!
//! The device clock may be wrong, so the credentials' lifetime is `expiration` minus the
//! response's `Date` header, both server time.

use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use hyper::body::Bytes;
use hyper::header::{ACCEPT, DATE};
use hyper::{Request, StatusCode};
use rustls::ClientConfig;
use secrecy::SecretString;
use serde::Deserialize;

use crate::clock::ClockSamples;
use crate::clock::offset::Source;
use crate::https::{self, Endpoint, HttpsError, InvalidHost, Limits};

/// Time allowed to connect.
pub const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
/// Time allowed for the whole request.
pub const TOTAL_TIMEOUT: Duration = Duration::from_secs(20);
/// The largest response body accepted.
pub const MAX_RESPONSE_LEN: usize = 16 * 1024;
/// The header that names the thing.
const THING_NAME_HEADER: &str = "x-amzn-iot-thingname";
/// How much of an error message to keep for logs and the `helios` shadow.
const MAX_MESSAGE_LEN: usize = 200;

/// Temporary AWS credentials.
#[derive(Debug)]
pub struct FetchedCredentials {
    /// The access key ID (not secret).
    pub access_key_id: String,
    /// The secret access key.
    pub secret_access_key: SecretString,
    /// The session token.
    pub session_token: SecretString,
    /// How long they are valid from when the response was sent, by the server's clock.
    pub lifetime: Duration,
}

/// A setting for the client isn't valid.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ConfigError {
    /// The credentials endpoint isn't a host name.
    #[error("aws.credentials_endpoint: {0}")]
    Endpoint(#[from] InvalidHost),
    /// The role alias has characters AWS doesn't allow.
    #[error("aws.role_alias {0:?} is not a valid role alias")]
    RoleAlias(String),
}

/// A credentials request failed.
#[derive(Debug, thiserror::Error)]
pub enum CredentialsError {
    /// No complete response.
    #[error("credentials provider: {0}")]
    Transport(#[from] HttpsError),
    /// 400, 403 or 404: a wrong role alias, IoT policy or thing name.
    #[error("credentials provider rejected the request ({status}): {message}")]
    Rejected {
        /// The status.
        status: StatusCode,
        /// The error message from the body, shortened.
        message: String,
    },
    /// Any other unsuccessful status, such as 429 or 5xx.
    #[error("credentials provider returned {0}")]
    Status(StatusCode),
    /// The body isn't the expected JSON. The body isn't included.
    #[error("credentials provider response is malformed: {0}")]
    Malformed(String),
}

/// When to try again after a [`CredentialsError`] (LLD 1, section 5.3).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Retry {
    /// Exponential backoff (5 s doubling to 5 min) until the cached credentials expire.
    Backoff,
    /// Every 5 minutes: the configuration or policy needs fixing.
    Slowly,
}

impl CredentialsError {
    /// When to retry.
    #[must_use]
    pub fn retry(&self) -> Retry {
        match self {
            Self::Rejected { .. } => Retry::Slowly,
            _ => Retry::Backoff,
        }
    }
}

/// A client for one role alias on one credentials endpoint.
#[derive(Debug, Clone)]
pub struct CredentialsClient {
    endpoint: Endpoint,
    path: String,
    thing_name: String,
    clock: ClockSamples,
}

impl CredentialsClient {
    /// A client for `role_alias` at `endpoint` (`host` or `host:port`), asking as
    /// `thing_name`.
    ///
    /// # Errors
    ///
    /// [`ConfigError`] if the endpoint or role alias isn't valid.
    pub fn new(endpoint: &str, role_alias: &str, thing_name: &str) -> Result<Self, ConfigError> {
        let valid_alias = (1..=128).contains(&role_alias.len())
            && role_alias.bytes().all(|b| {
                b.is_ascii_alphanumeric() || matches!(b, b'_' | b'=' | b',' | b'@' | b'-')
            });
        if !valid_alias {
            return Err(ConfigError::RoleAlias(role_alias.to_owned()));
        }
        Ok(Self {
            endpoint: Endpoint::parse(endpoint)?,
            path: format!("/role-aliases/{role_alias}/credentials"),
            thing_name: thing_name.to_owned(),
            clock: ClockSamples::discard(),
        })
    }

    /// Offers each response's server time to the clock checks.
    #[must_use]
    pub fn with_clock(mut self, clock: ClockSamples) -> Self {
        self.clock = clock;
        self
    }

    /// Fetches credentials over mutual TLS with `tls`, normally
    /// `identity.tls_config(Alpn::Http1)`.
    ///
    /// # Errors
    ///
    /// [`CredentialsError`]; [`CredentialsError::retry`] says when to try again.
    pub async fn fetch(
        &self,
        tls: Arc<ClientConfig>,
    ) -> Result<FetchedCredentials, CredentialsError> {
        let request = Request::get(&self.path)
            .header(THING_NAME_HEADER, &self.thing_name)
            .header(ACCEPT, "application/json");
        let limits = Limits {
            connect_timeout: CONNECT_TIMEOUT,
            total_timeout: TOTAL_TIMEOUT,
            max_body: MAX_RESPONSE_LEN,
        };
        let response = https::send(&self.endpoint, tls, request, Bytes::new(), limits).await?;
        self.clock.offer_http(Source::Credentials, &response);
        match response.status {
            StatusCode::OK => {}
            StatusCode::BAD_REQUEST | StatusCode::FORBIDDEN | StatusCode::NOT_FOUND => {
                return Err(CredentialsError::Rejected {
                    status: response.status,
                    message: error_message(&response.body),
                });
            }
            status => return Err(CredentialsError::Status(status)),
        }
        let envelope: Envelope = serde_json::from_slice(&response.body).map_err(|error| {
            // serde_json's message can quote the offending value, which might be a secret.
            CredentialsError::Malformed(format!(
                "{:?} error at line {} column {}",
                error.classify(),
                error.line(),
                error.column()
            ))
        })?;
        let credentials = envelope.credentials;
        let expiration = parse_rfc3339(&credentials.expiration).ok_or_else(|| {
            CredentialsError::Malformed("expiration is not an RFC 3339 UTC time".to_owned())
        })?;
        let server_time = response
            .headers
            .get(DATE)
            .and_then(|date| date.to_str().ok())
            .and_then(|date| httpdate::parse_http_date(date).ok());
        let now = server_time.unwrap_or_else(|| {
            tracing::warn!("credentials response has no Date header; using the device clock");
            SystemTime::now()
        });
        let lifetime = expiration
            .duration_since(now)
            .ok()
            .filter(|lifetime| !lifetime.is_zero())
            .ok_or_else(|| {
                CredentialsError::Malformed("credentials expired before they arrived".to_owned())
            })?;
        Ok(FetchedCredentials {
            access_key_id: credentials.access_key_id,
            secret_access_key: credentials.secret_access_key,
            session_token: credentials.session_token,
            lifetime,
        })
    }
}

#[derive(Deserialize)]
struct Envelope {
    credentials: RawCredentials,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct RawCredentials {
    access_key_id: String,
    secret_access_key: SecretString,
    session_token: SecretString,
    expiration: String,
}

/// The `message` from an AWS error body, shortened, or a note that there wasn't one.
fn error_message(body: &[u8]) -> String {
    #[derive(Deserialize)]
    struct ErrorBody {
        message: String,
    }
    serde_json::from_slice::<ErrorBody>(body).map_or_else(
        |_| "(no message)".to_owned(),
        |error| error.message.chars().take(MAX_MESSAGE_LEN).collect(),
    )
}

/// Parses an RFC 3339 time in UTC, such as `2026-11-19T05:41:00Z`, with optional fractional
/// seconds and `Z` or `+00:00`.
fn parse_rfc3339(text: &str) -> Option<SystemTime> {
    let text = text
        .strip_suffix('Z')
        .or_else(|| text.strip_suffix("+00:00"))?;
    let (date, time) = text.split_once('T')?;
    let mut date_parts = date.split('-');
    let year: i64 = number(date_parts.next()?, 4)?;
    let month: u32 = number(date_parts.next()?, 2)?;
    let day: u32 = number(date_parts.next()?, 2)?;
    if date_parts.next().is_some() {
        return None;
    }
    let (time, fraction) = time.split_once('.').unwrap_or((time, ""));
    if !fraction.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    let mut time_parts = time.split(':');
    let hour: u64 = number(time_parts.next()?, 2)?;
    let minute: u64 = number(time_parts.next()?, 2)?;
    let second: u64 = number(time_parts.next()?, 2)?;
    if time_parts.next().is_some()
        || !(1..=12).contains(&month)
        || !(1..=days_in_month(year, month)).contains(&day)
        || hour > 23
        || minute > 59
        || second > 60
    {
        return None;
    }
    let days = u64::try_from(days_from_civil(year, month, day)).ok()?;
    let seconds = days * 86_400 + hour * 3600 + minute * 60 + second;
    let nanos: u32 = if fraction.is_empty() {
        0
    } else {
        format!("{fraction:0<9}").get(..9)?.parse().ok()?
    };
    Some(UNIX_EPOCH + Duration::new(seconds, nanos))
}

fn number<T: std::str::FromStr>(text: &str, digits: usize) -> Option<T> {
    (text.len() == digits && text.bytes().all(|b| b.is_ascii_digit()))
        .then(|| text.parse().ok())
        .flatten()
}

fn days_in_month(year: i64, month: u32) -> u32 {
    match month {
        2 if (year % 4 == 0 && year % 100 != 0) || year % 400 == 0 => 29,
        2 => 28,
        4 | 6 | 9 | 11 => 30,
        _ => 31,
    }
}

/// Days since 1970-01-01 (Howard Hinnant's `days_from_civil`).
fn days_from_civil(year: i64, month: u32, day: u32) -> i64 {
    let year = if month <= 2 { year - 1 } else { year };
    let era = year.div_euclid(400);
    let year_of_era = year - era * 400;
    let month = i64::from(month);
    let day_of_year =
        (153 * (if month > 2 { month - 3 } else { month + 9 }) + 2) / 5 + i64::from(day) - 1;
    let day_of_era = year_of_era * 365 + year_of_era / 4 - year_of_era / 100 + day_of_year;
    era * 146_097 + day_of_era - 719_468
}

#[cfg(test)]
mod tests;
