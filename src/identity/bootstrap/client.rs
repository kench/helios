//! HTTPS client for the bootstrap service's device API (LLD 1, section 4.8).
//!
//! Each call is one HTTP/1.1 request on a new TLS connection, made with `hyper` over
//! `tokio-rustls`. The service's certificate is checked against the configured roots (the
//! Amazon root CAs) and its hostname. Redirects are never followed. The whole call, including
//! connecting, has one timeout.
//!
//! Response bodies are parsed straight into types that keep the PIN in a `SecretString`, and
//! are never logged. Parse errors only say where the problem is, not what the value was.

use std::sync::Arc;
use std::time::Duration;

use hyper::body::Bytes;
use hyper::header::{ACCEPT, CONTENT_TYPE, HeaderMap, RETRY_AFTER};
use hyper::{Method, Request, StatusCode, Uri};
use rustls::{ClientConfig, RootCertStore};
use serde::Serialize;
use serde::de::DeserializeOwned;

use crate::https::{self, Endpoint, HttpsError, Limits};

use crate::identity::bootstrap::api::{
    AnswerChallengeRequest, BootstrapRequest, BootstrapResult, DeviceIdentity, InvalidMember,
};
use crate::identity::tls::{self, Alpn, TlsError};

/// Default timeout for one call (`bootstrap.timeout_ms`).
pub const DEFAULT_TIMEOUT: Duration = Duration::from_secs(10);
/// Largest response body accepted.
pub const MAX_RESPONSE_LEN: usize = 64 * 1024;
/// The header that names a `restJson1` error.
const ERROR_TYPE: &str = "x-amzn-errortype";

/// `bootstrap.url` isn't usable.
#[derive(Debug, thiserror::Error)]
pub enum UrlError {
    /// Not a URL.
    #[error("bootstrap.url {0:?} is not a valid URL")]
    Invalid(String),
    /// Not `https://`.
    #[error("bootstrap.url {0:?} must use https")]
    NotHttps(String),
    /// Has a query or fragment.
    #[error("bootstrap.url {0:?} must not have a query")]
    Query(String),
    /// The host isn't a valid TLS server name.
    #[error("bootstrap.url {0:?} has no valid host name")]
    Host(String),
    /// The TLS config couldn't be built.
    #[error(transparent)]
    Tls(#[from] TlsError),
}

/// A bootstrap call failed.
#[derive(Debug, thiserror::Error)]
pub enum BootstrapError {
    /// Couldn't connect.
    #[error("could not connect to the bootstrap service: {0}")]
    Connect(std::io::Error),
    /// The TLS handshake failed: a wrong CA, interception, or a clock that is still wrong.
    #[error("TLS handshake with the bootstrap service failed: {0}")]
    Tls(std::io::Error),
    /// The HTTP exchange failed.
    #[error("HTTP error talking to the bootstrap service: {0}")]
    Http(#[from] hyper::Error),
    /// No complete response within the timeout.
    #[error("the bootstrap service did not respond within {} ms", .0.as_millis())]
    Timeout(Duration),
    /// The service redirected. Redirects aren't followed.
    #[error("the bootstrap service redirected ({0}); redirects are not followed")]
    Redirect(StatusCode),
    /// The service returned an error.
    #[error(
        "the bootstrap service returned {status} {}",
        error_type.as_deref().unwrap_or("(no error type)")
    )]
    Service {
        /// The HTTP status.
        status: StatusCode,
        /// The `restJson1` error name, such as `DeviceDisabled`.
        error_type: Option<String>,
        /// The `Retry-After` header, for `RateLimited`.
        retry_after: Option<Duration>,
    },
    /// The response body is too large.
    #[error("the bootstrap service response is larger than {MAX_RESPONSE_LEN} bytes")]
    TooLarge,
    /// The response body isn't the expected JSON. The body isn't included.
    #[error("the bootstrap service response is malformed: {0}")]
    Malformed(String),
    /// The response breaks the model's constraints.
    #[error("the bootstrap service response is malformed: {0}")]
    Invalid(#[from] InvalidMember),
}

/// When to try again after a [`BootstrapError`] (LLD 1, section 4.8).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Retry {
    /// Exponential backoff (2 s doubling to 60 s).
    Backoff,
    /// Every 5 minutes: the device record needs fixing in the service.
    Slowly,
    /// Start a new lookup straight away (the challenge expired).
    Now,
    /// Wait at least this long (`Retry-After`), then back off.
    After(Duration),
    /// The challenge signature was rejected: back off, slowing to every 5 minutes.
    ChallengeRejected,
}

impl From<HttpsError> for BootstrapError {
    fn from(error: HttpsError) -> Self {
        match error {
            HttpsError::Connect(error) => Self::Connect(error),
            HttpsError::Tls(error) => Self::Tls(error),
            HttpsError::Http(error) => Self::Http(error),
            HttpsError::Timeout(timeout) => Self::Timeout(timeout),
            HttpsError::TooLarge(_) => Self::TooLarge,
            HttpsError::Request(error) => Self::Malformed(format!("request: {error}")),
        }
    }
}

impl BootstrapError {
    /// The `restJson1` error name, if the service returned one.
    #[must_use]
    pub fn error_type(&self) -> Option<&str> {
        match self {
            Self::Service { error_type, .. } => error_type.as_deref(),
            _ => None,
        }
    }

    /// When to retry, from the table in LLD 1, section 4.8. Errors are told apart by name,
    /// because several share a status code.
    #[must_use]
    pub fn retry(&self) -> Retry {
        let Self::Service {
            status,
            error_type,
            retry_after,
        } = self
        else {
            return Retry::Backoff;
        };
        match error_type.as_deref() {
            Some(
                "UnknownDevice" | "AmbiguousDevice" | "DeviceDisabled" | "ChallengeUnsupported",
            ) => Retry::Slowly,
            Some("ChallengeExpired") => Retry::Now,
            Some("ChallengeFailed") => Retry::ChallengeRejected,
            _ if *status == StatusCode::TOO_MANY_REQUESTS => {
                retry_after.map_or(Retry::Backoff, Retry::After)
            }
            _ => Retry::Backoff,
        }
    }
}

/// A client for one bootstrap service.
#[derive(Debug, Clone)]
pub struct BootstrapClient {
    endpoint: Endpoint,
    base_path: String,
    tls: Arc<ClientConfig>,
    timeout: Duration,
}

impl BootstrapClient {
    /// A client for the service at `url` (such as
    /// `https://device-management.services.kenley.tv/v1`), trusting `roots`.
    ///
    /// # Errors
    ///
    /// [`UrlError`] if `url` isn't an `https://` URL without a query.
    pub fn new(url: &str, roots: RootCertStore, timeout: Duration) -> Result<Self, UrlError> {
        let uri: Uri = url.parse().map_err(|_| UrlError::Invalid(url.to_owned()))?;
        if uri.scheme_str() != Some("https") {
            return Err(UrlError::NotHttps(url.to_owned()));
        }
        if uri.query().is_some() || url.contains('#') {
            return Err(UrlError::Query(url.to_owned()));
        }
        let authority = uri
            .authority()
            .ok_or_else(|| UrlError::Invalid(url.to_owned()))?;
        let endpoint = Endpoint::new(authority.host(), authority.port_u16().unwrap_or(443))
            .map_err(|_| UrlError::Host(url.to_owned()))?;
        Ok(Self {
            endpoint,
            base_path: uri.path().trim_end_matches('/').to_owned(),
            tls: tls::server_auth_config(roots, Alpn::Http1)?,
            timeout,
        })
    }

    /// `Bootstrap`: looks the device up by its adapters.
    ///
    /// # Errors
    ///
    /// [`BootstrapError`]; [`BootstrapError::retry`] says when to try again.
    pub async fn bootstrap(
        &self,
        request: &BootstrapRequest,
    ) -> Result<BootstrapResult, BootstrapError> {
        let result: BootstrapResult = self.post("/device/bootstrap", request).await?;
        match &result {
            BootstrapResult::Identity(identity) => identity.validate()?,
            BootstrapResult::Challenge(challenge) => challenge.validate()?,
        }
        Ok(result)
    }

    /// `AnswerChallenge`: sends the signed challenge and gets the identity.
    ///
    /// # Errors
    ///
    /// [`BootstrapError`]; [`BootstrapError::retry`] says when to try again.
    pub async fn answer_challenge(
        &self,
        request: &AnswerChallengeRequest,
    ) -> Result<DeviceIdentity, BootstrapError> {
        let identity: DeviceIdentity = self.post("/device/bootstrap/challenge", request).await?;
        identity.validate()?;
        Ok(identity)
    }

    async fn post<T: DeserializeOwned>(
        &self,
        path: &str,
        body: &impl Serialize,
    ) -> Result<T, BootstrapError> {
        let body = serde_json::to_vec(body)
            .map_err(|error| BootstrapError::Malformed(format!("request: {error}")))?;
        let request = Request::builder()
            .method(Method::POST)
            .uri(format!("{}{path}", self.base_path))
            .header(CONTENT_TYPE, "application/json")
            .header(ACCEPT, "application/json");
        let limits = Limits {
            connect_timeout: self.timeout,
            total_timeout: self.timeout,
            max_body: MAX_RESPONSE_LEN,
        };
        let response = https::send(
            &self.endpoint,
            self.tls.clone(),
            request,
            Bytes::from(body),
            limits,
        )
        .await?;
        if response.status.is_redirection() {
            return Err(BootstrapError::Redirect(response.status));
        }
        if !response.status.is_success() {
            return Err(BootstrapError::Service {
                status: response.status,
                error_type: error_type(&response.headers),
                retry_after: retry_after(&response.headers),
            });
        }
        serde_json::from_slice(&response.body).map_err(|error| {
            // serde_json's message can quote the offending value, which might be the PIN.
            BootstrapError::Malformed(format!(
                "{:?} error at line {} column {}",
                error.classify(),
                error.line(),
                error.column()
            ))
        })
    }
}

/// The error name from `X-Amzn-Errortype`. `restJson1` allows a namespace before `#` and extra
/// data after `:`, as in `tv.kenley.helios.contract#DeviceDisabled:http://...`.
fn error_type(headers: &HeaderMap) -> Option<String> {
    let value = headers.get(ERROR_TYPE)?.to_str().ok()?;
    let name = value.split(':').next().unwrap_or(value);
    let name = name.rsplit('#').next().unwrap_or(name).trim();
    (!name.is_empty()).then(|| name.to_owned())
}

/// `Retry-After` in seconds. The HTTP-date form isn't used by the service.
fn retry_after(headers: &HeaderMap) -> Option<Duration> {
    let seconds = headers
        .get(RETRY_AFTER)?
        .to_str()
        .ok()?
        .trim()
        .parse()
        .ok()?;
    Some(Duration::from_secs(seconds))
}

#[cfg(test)]
mod tests;
