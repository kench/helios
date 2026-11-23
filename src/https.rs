//! One HTTPS request per connection, with `hyper` over `tokio-rustls` (LLD 1, section 10:
//! the HTTP client decision).
//!
//! Used for the bootstrap service and the AWS IoT credentials provider. The caller supplies the
//! rustls `ClientConfig`, so it decides the roots and whether a client certificate is
//! presented. Redirects are never followed: a 3xx comes back as a response like any other.

use std::collections::VecDeque;
use std::future::Future;
use std::io;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime};

use http_body_util::{BodyExt, Full, Limited};
use hyper::body::Bytes;
use hyper::header::{HOST, HeaderMap, USER_AGENT};
use hyper::http::request::Builder;
use hyper::{Request, StatusCode};
use hyper_util::rt::TokioIo;
use rustls::ClientConfig;
use rustls_pki_types::ServerName;
use tokio::net::TcpStream;
use tokio::task::JoinSet;
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
    /// When the request went out and the response came back, for clock checks.
    pub exchange: Exchange,
}

/// The timing of one HTTP exchange: from sending the request to receiving the response's
/// headers, after the connection and TLS handshake.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Exchange {
    /// The device time when the request was sent.
    pub sent: SystemTime,
    /// The device time when the response's headers arrived.
    pub received: SystemTime,
    /// The time between them, by a monotonic clock.
    pub round_trip: Duration,
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
        connect(endpoint.host.as_str(), endpoint.port),
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
    let (sent, started) = (SystemTime::now(), Instant::now());
    let response = sender.send_request(request).await?;
    let exchange = Exchange {
        sent,
        received: SystemTime::now(),
        round_trip: started.elapsed(),
    };
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
        exchange,
    })
}

/// RFC 8305's Connection Attempt Delay: how long an attempt gets before the next address is
/// tried alongside it.
const ATTEMPT_DELAY: Duration = Duration::from_millis(250);

/// Connects to `host` with Happy Eyeballs (RFC 8305): its addresses alternate between IPv6 and
/// IPv4, starting with the resolver's first choice, and each next one is tried
/// [`ATTEMPT_DELAY`] after the previous (or as soon as it fails). The first to connect wins. So
/// an endpoint with IPv6 addresses still connects promptly where IPv6 is advertised but broken.
async fn connect(host: &str, port: u16) -> io::Result<TcpStream> {
    let addresses: Vec<SocketAddr> = tokio::net::lookup_host((host, port)).await?.collect();
    race(interleave(addresses), ATTEMPT_DELAY, TcpStream::connect).await
}

/// `addresses` reordered to alternate between the address families, starting with the first
/// address's family, each family keeping the resolver's order (RFC 8305, section 4).
fn interleave(addresses: Vec<SocketAddr>) -> Vec<SocketAddr> {
    let Some(first) = addresses.first() else {
        return addresses;
    };
    let first_v6 = first.is_ipv6();
    let (mut preferred, mut other): (VecDeque<SocketAddr>, VecDeque<SocketAddr>) = addresses
        .into_iter()
        .partition(|address| address.is_ipv6() == first_v6);
    let mut ordered = Vec::with_capacity(preferred.len() + other.len());
    while !preferred.is_empty() || !other.is_empty() {
        ordered.extend(preferred.pop_front());
        ordered.extend(other.pop_front());
    }
    ordered
}

/// Starts an attempt on each address in turn, the next one `delay` after the previous or as
/// soon as one fails, and returns the first that succeeds. The attempts still running are
/// cancelled. When all fail, the last failure is returned.
async fn race<C, F, T>(addresses: Vec<SocketAddr>, delay: Duration, connect: C) -> io::Result<T>
where
    C: Fn(SocketAddr) -> F,
    F: Future<Output = io::Result<T>> + Send + 'static,
    T: Send + 'static,
{
    let mut queue = addresses.into_iter().peekable();
    let mut attempts = JoinSet::new();
    let mut last_error = None;
    let mut next = queue.next();
    loop {
        if let Some(address) = next.take() {
            attempts.spawn(connect(address));
        }
        let more = queue.peek().is_some();
        if attempts.is_empty() {
            return Err(last_error.unwrap_or_else(|| {
                io::Error::new(io::ErrorKind::NotFound, "the host has no addresses")
            }));
        }
        tokio::select! {
            Some(done) = attempts.join_next() => {
                match done {
                    Ok(Ok(stream)) => return Ok(stream),
                    Ok(Err(error)) => last_error = Some(error),
                    Err(error) => last_error = Some(io::Error::other(error)),
                }
                if more {
                    next = queue.next();
                }
            }
            () = tokio::time::sleep(delay), if more => next = queue.next(),
        }
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Mutex;

    use super::*;

    fn addr(text: &str) -> SocketAddr {
        text.parse().unwrap()
    }

    #[test]
    fn interleaves_the_families_starting_with_the_first() {
        let v6 = [
            "[2001:db8::1]:443",
            "[2001:db8::2]:443",
            "[2001:db8::3]:443",
        ]
        .map(addr);
        let v4 = ["192.0.2.1:443", "192.0.2.2:443"].map(addr);
        assert_eq!(
            interleave(vec![v6[0], v6[1], v6[2], v4[0], v4[1]]),
            vec![v6[0], v4[0], v6[1], v4[1], v6[2]]
        );
        assert_eq!(
            interleave(vec![v4[0], v6[0], v6[1], v4[1]]),
            vec![v4[0], v6[0], v4[1], v6[1]]
        );
        assert_eq!(interleave(vec![v4[1], v4[0]]), vec![v4[1], v4[0]]);
        assert!(interleave(vec![]).is_empty());
    }

    /// A fake connector: addresses ending in .1 (or ::1) never answer, .2 fail at once, and the
    /// rest connect, returning their address; it records when each attempt starts.
    fn fake(
        started: Arc<Mutex<Vec<(SocketAddr, tokio::time::Instant)>>>,
    ) -> impl Fn(SocketAddr) -> std::pin::Pin<Box<dyn Future<Output = io::Result<SocketAddr>> + Send>>
    {
        move |address| {
            started
                .lock()
                .unwrap()
                .push((address, tokio::time::Instant::now()));
            Box::pin(async move {
                let last = match address.ip() {
                    std::net::IpAddr::V4(ip) => u16::from(ip.octets()[3]),
                    std::net::IpAddr::V6(ip) => ip.segments()[7],
                };
                match last {
                    1 => std::future::pending().await,
                    2 => Err(io::Error::from(io::ErrorKind::ConnectionRefused)),
                    _ => Ok(address),
                }
            })
        }
    }

    #[tokio::test(start_paused = true)]
    async fn a_silent_address_gets_the_attempt_delay_then_the_next_one_wins() {
        let started = Arc::new(Mutex::new(Vec::new()));
        let begin = tokio::time::Instant::now();
        let winner = race(
            vec![addr("[2001:db8::1]:443"), addr("192.0.2.9:443")],
            ATTEMPT_DELAY,
            fake(Arc::clone(&started)),
        )
        .await
        .unwrap();
        assert_eq!(winner, addr("192.0.2.9:443"));
        let started = started.lock().unwrap();
        assert_eq!(started[1].1 - begin, ATTEMPT_DELAY, "IPv4 after the delay");
    }

    #[tokio::test(start_paused = true)]
    async fn a_failure_starts_the_next_attempt_at_once() {
        let started = Arc::new(Mutex::new(Vec::new()));
        let begin = tokio::time::Instant::now();
        let winner = race(
            vec![addr("[2001:db8::2]:443"), addr("192.0.2.9:443")],
            ATTEMPT_DELAY,
            fake(Arc::clone(&started)),
        )
        .await
        .unwrap();
        assert_eq!(winner, addr("192.0.2.9:443"));
        assert_eq!(started.lock().unwrap()[1].1 - begin, Duration::ZERO);
    }

    #[tokio::test(start_paused = true)]
    async fn returns_the_last_failure_when_every_attempt_fails() {
        let started = Arc::new(Mutex::new(Vec::new()));
        let error = race(
            vec![addr("[2001:db8::2]:443"), addr("192.0.2.2:443")],
            ATTEMPT_DELAY,
            fake(Arc::clone(&started)),
        )
        .await
        .unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::ConnectionRefused);
        assert_eq!(started.lock().unwrap().len(), 2);
        let error = race(vec![], ATTEMPT_DELAY, fake(started))
            .await
            .unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::NotFound);
    }

    #[tokio::test(start_paused = true)]
    async fn the_first_success_wins_even_if_an_earlier_attempt_is_still_running() {
        // The first never answers, the second fails, the third connects.
        let started = Arc::new(Mutex::new(Vec::new()));
        let winner = race(
            vec![
                addr("192.0.2.1:443"),
                addr("[2001:db8::2]:443"),
                addr("192.0.2.3:443"),
            ],
            ATTEMPT_DELAY,
            fake(Arc::clone(&started)),
        )
        .await
        .unwrap();
        assert_eq!(winner, addr("192.0.2.3:443"));
        assert_eq!(started.lock().unwrap().len(), 3);
    }

    #[tokio::test]
    async fn connects_to_a_real_listener_past_an_address_that_never_answers() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        // 192.0.2.0/24 is reserved for documentation: nothing answers (or it's unreachable).
        let stream = race(
            vec![
                SocketAddr::from(([192, 0, 2, 1], port)),
                SocketAddr::from(([127, 0, 0, 1], port)),
            ],
            ATTEMPT_DELAY,
            TcpStream::connect,
        )
        .await
        .unwrap();
        assert_eq!(stream.peer_addr().unwrap().port(), port);
        let stream = connect("localhost", port).await.unwrap();
        assert_eq!(stream.peer_addr().unwrap().port(), port);
    }

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
