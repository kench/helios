//! One HTTPS request per connection, with `hyper` over `tokio-rustls` (LLD 1, section 10:
//! the HTTP client decision).
//!
//! Used for the bootstrap service and the AWS IoT credentials provider. The caller supplies the
//! rustls `ClientConfig`, so it decides the roots and whether a client certificate is
//! presented. Redirects are never followed: a 3xx comes back as a response like any other.

use std::sync::Arc;
use std::time::Duration;

use http_body_util::{BodyExt, Full, Limited};
use hyper::body::Bytes;
use hyper::header::{HOST, HeaderMap, USER_AGENT};
use hyper::http::request::Builder;
use hyper::{Request, StatusCode};
use hyper_util::rt::TokioIo;
use rustls::ClientConfig;
use rustls_pki_types::ServerName;
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;

/// The `User-Agent` sent with every request.
pub const USER_AGENT_VALUE: &str = concat!("helios/", env!("CARGO_PKG_VERSION"));

/// A host and port to connect to.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Endpoint {
    host: String,
    port: u16,
    authority: String,
    server_name: ServerName<'static>,
}

/// The host isn't a valid DNS name or IP address.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("{0:?} is not a valid host name")]
pub struct InvalidHost(pub String);

impl Endpoint {
    /// `host` on `port`. The TLS server name is checked against `host`.
    ///
    /// # Errors
    ///
    /// [`InvalidHost`] if `host` isn't a valid DNS name or IP address.
    pub fn new(host: &str, port: u16) -> Result<Self, InvalidHost> {
        let server_name =
            ServerName::try_from(host.to_owned()).map_err(|_| InvalidHost(host.to_owned()))?;
        let authority = if port == 443 {
            host.to_owned()
        } else {
            format!("{host}:{port}")
        };
        Ok(Self {
            host: host.to_owned(),
            port,
            authority,
            server_name,
        })
    }

    /// Parses `host` or `host:port` (port 443 if left out).
    ///
    /// # Errors
    ///
    /// [`InvalidHost`] if the host or port isn't valid.
    pub fn parse(value: &str) -> Result<Self, InvalidHost> {
        let (host, port) = match value.rsplit_once(':') {
            Some((host, port)) => (
                host,
                port.parse().map_err(|_| InvalidHost(value.to_owned()))?,
            ),
            None => (value, 443),
        };
        if host.is_empty() || host.contains(['/', ' ']) {
            return Err(InvalidHost(value.to_owned()));
        }
        Self::new(host, port)
    }

    /// The host name.
    #[must_use]
    pub fn host(&self) -> &str {
        &self.host
    }

    /// The port.
    #[must_use]
    pub fn port(&self) -> u16 {
        self.port
    }
}

/// Time and size limits for one request.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Limits {
    /// For the TCP connection.
    pub connect_timeout: Duration,
    /// For the whole request, including connecting and reading the body.
    pub total_timeout: Duration,
    /// The largest response body accepted.
    pub max_body: usize,
}

/// A complete response.
#[derive(Debug)]
pub struct Response {
    /// The status.
    pub status: StatusCode,
    /// The headers.
    pub headers: HeaderMap,
    /// The whole body.
    pub body: Bytes,
}

/// The request failed before a complete response arrived.
#[derive(Debug, thiserror::Error)]
pub enum HttpsError {
    /// Couldn't connect.
    #[error("could not connect: {0}")]
    Connect(std::io::Error),
    /// The TLS handshake failed.
    #[error("TLS handshake failed: {0}")]
    Tls(std::io::Error),
    /// The HTTP exchange failed.
    #[error("HTTP error: {0}")]
    Http(#[from] hyper::Error),
    /// A timeout passed.
    #[error("no response within {} ms", .0.as_millis())]
    Timeout(Duration),
    /// The body is larger than allowed.
    #[error("response body is larger than {0} bytes")]
    TooLarge(usize),
    /// The request couldn't be built.
    #[error("invalid request: {0}")]
    Request(#[from] hyper::http::Error),
}

/// Sends `request` with `body` to `endpoint` over TLS with `tls`, adding the `Host` and
/// `User-Agent` headers, and reads the whole response.
///
/// # Errors
///
/// [`HttpsError`] if there is no complete response within the limits.
pub async fn send(
    endpoint: &Endpoint,
    tls: Arc<ClientConfig>,
    request: Builder,
    body: Bytes,
    limits: Limits,
) -> Result<Response, HttpsError> {
    let request = request
        .header(HOST, &endpoint.authority)
        .header(USER_AGENT, USER_AGENT_VALUE)
        .body(Full::new(body))?;
    tokio::time::timeout(
        limits.total_timeout,
        exchange(endpoint, tls, request, limits),
    )
    .await
    .map_err(|_| HttpsError::Timeout(limits.total_timeout))?
}

async fn exchange(
    endpoint: &Endpoint,
    tls: Arc<ClientConfig>,
    request: Request<Full<Bytes>>,
    limits: Limits,
) -> Result<Response, HttpsError> {
    let tcp = tokio::time::timeout(
        limits.connect_timeout,
        TcpStream::connect((endpoint.host.as_str(), endpoint.port)),
    )
    .await
    .map_err(|_| HttpsError::Timeout(limits.connect_timeout))?
    .map_err(HttpsError::Connect)?;
    let stream = TlsConnector::from(tls)
        .connect(endpoint.server_name.clone(), tcp)
        .await
        .map_err(HttpsError::Tls)?;
    let (mut sender, connection) =
        hyper::client::conn::http1::handshake(TokioIo::new(stream)).await?;
    let connection = tokio::spawn(connection);
    let response = sender.send_request(request).await?;
    let (parts, body) = response.into_parts();
    let body = Limited::new(body, limits.max_body)
        .collect()
        .await
        .map_err(|error| match error.downcast::<hyper::Error>() {
            Ok(error) => HttpsError::Http(*error),
            Err(_) => HttpsError::TooLarge(limits.max_body),
        })?
        .to_bytes();
    connection.abort();
    Ok(Response {
        status: parts.status,
        headers: parts.headers,
        body,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_endpoints() {
        let endpoint = Endpoint::parse("example.credentials.iot.us-west-2.amazonaws.com").unwrap();
        assert_eq!(
            endpoint.host(),
            "example.credentials.iot.us-west-2.amazonaws.com"
        );
        assert_eq!(endpoint.port(), 443);
        assert_eq!(
            endpoint.authority,
            "example.credentials.iot.us-west-2.amazonaws.com"
        );

        let local = Endpoint::parse("localhost:8443").unwrap();
        assert_eq!((local.host(), local.port()), ("localhost", 8443));
        assert_eq!(local.authority, "localhost:8443");

        for bad in [
            "",
            ":443",
            "host:port",
            "host:99999",
            "a b",
            "https://host",
            "host/path",
        ] {
            assert_eq!(
                Endpoint::parse(bad),
                Err(InvalidHost(bad.to_owned())),
                "{bad}"
            );
        }
        assert_eq!(
            InvalidHost("a b".into()).to_string(),
            "\"a b\" is not a valid host name"
        );
    }

    #[tokio::test]
    async fn times_out_connecting() {
        // 192.0.2.0/24 is reserved for documentation, so nothing answers there.
        let endpoint = Endpoint::new("192.0.2.1", 443).unwrap();
        let tls = crate::identity::tls::server_auth_config(
            rustls::RootCertStore::empty(),
            crate::identity::tls::Alpn::Http1,
        )
        .unwrap();
        let limits = Limits {
            connect_timeout: Duration::from_millis(50),
            total_timeout: Duration::from_secs(5),
            max_body: 1024,
        };

        let error = send(&endpoint, tls, Request::get("/"), Bytes::new(), limits)
            .await
            .unwrap_err();

        assert!(
            matches!(error, HttpsError::Timeout(t) if t == Duration::from_millis(50))
                || matches!(error, HttpsError::Connect(_)),
            "{error:?}"
        );
    }
}
