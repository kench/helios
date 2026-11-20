//! Test helpers shared by the identity tests: test CAs, device certificates and a local
//! mutual-TLS server.

use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use p256::ecdsa::SigningKey;
use p256::pkcs8::EncodePublicKey;
use rcgen::{CertificateParams, DnType, Issuer, KeyPair, SubjectPublicKeyInfo};
use rustls::server::WebPkiClientVerifier;
use rustls::{ClientConfig, ServerConfig};
use rustls_pki_types::{CertificateDer, PrivateKeyDer, ServerName};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio_rustls::{TlsAcceptor, TlsConnector};
use x509_parser::time::ASN1Time;

use crate::identity::tls::{crypto_provider, root_store_from_pem};

/// The thing name the test certificates are issued for.
pub(crate) const THING_NAME: &str = "t-01JD5VY2K7M9Q4R6T8V0X2Z4B6";

/// A test CA.
pub(crate) struct Ca {
    pub(crate) issuer: Issuer<'static, KeyPair>,
    pub(crate) pem: String,
}

/// A new self-signed P-256 CA.
pub(crate) fn ca(name: &str) -> Ca {
    let key = KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).unwrap();
    let mut params = CertificateParams::default();
    params.distinguished_name.push(DnType::CommonName, name);
    params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
    let pem = params.self_signed(&key).unwrap().pem();
    Ca {
        issuer: Issuer::new(params, key),
        pem,
    }
}

/// A certificate for `key` from `ca`, with subject CN `cn`, valid from `not_before` until
/// `not_after`.
pub(crate) fn device_certificate_valid(
    ca: &Ca,
    key: &SigningKey,
    cn: &str,
    not_before: SystemTime,
    not_after: SystemTime,
) -> CertificateDer<'static> {
    let spki = key.verifying_key().to_public_key_der().unwrap();
    let mut params = CertificateParams::default();
    params.distinguished_name.push(DnType::CommonName, cn);
    params.not_before = asn1_time(not_before).to_datetime();
    params.not_after = asn1_time(not_after).to_datetime();
    params
        .signed_by(
            &SubjectPublicKeyInfo::from_der(spki.as_bytes()).unwrap(),
            &ca.issuer,
        )
        .unwrap()
        .der()
        .clone()
}

/// A certificate for `key` from `ca` with subject CN `cn`, valid from a day ago for a year.
pub(crate) fn device_certificate(ca: &Ca, key: &SigningKey, cn: &str) -> CertificateDer<'static> {
    let now = SystemTime::now();
    device_certificate_valid(ca, key, cn, now - days(1), now + days(365))
}

/// `count` days.
pub(crate) fn days(count: u64) -> Duration {
    Duration::from_secs(count * 24 * 60 * 60)
}

fn asn1_time(time: SystemTime) -> ASN1Time {
    let seconds = time.duration_since(UNIX_EPOCH).unwrap().as_secs();
    ASN1Time::from_timestamp(i64::try_from(seconds).unwrap()).unwrap()
}

/// A TLS server that requires a client certificate from `client_ca` and replies with the
/// subject CN it saw. Returns its port and the CA that issued its own certificate.
pub(crate) async fn server(client_ca: &Ca) -> (u16, Ca) {
    let server_ca = ca("Helios test server CA");
    let server_key = KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).unwrap();
    let server_cert = CertificateParams::new(vec!["localhost".to_owned()])
        .unwrap()
        .signed_by(&server_key, &server_ca.issuer)
        .unwrap();
    let verifier = WebPkiClientVerifier::builder_with_provider(
        Arc::new(root_store_from_pem(client_ca.pem.as_bytes()).unwrap()),
        crypto_provider(),
    )
    .build()
    .unwrap();
    let config = ServerConfig::builder_with_provider(crypto_provider())
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_client_cert_verifier(verifier)
        .with_single_cert(
            vec![server_cert.der().clone()],
            PrivateKeyDer::try_from(server_key.serialize_der()).unwrap(),
        )
        .unwrap();
    let acceptor = TlsAcceptor::from(Arc::new(config));
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    tokio::spawn(async move {
        while let Ok((tcp, _)) = listener.accept().await {
            let acceptor = acceptor.clone();
            tokio::spawn(async move {
                let Ok(mut tls) = acceptor.accept(tcp).await else {
                    return;
                };
                let peer = tls.get_ref().1.peer_certificates().unwrap()[0].clone();
                let (_, cert) = x509_parser::parse_x509_certificate(&peer).unwrap();
                let cn = cert.subject().iter_common_name().next().unwrap();
                let reply = format!("hello {}", cn.as_str().unwrap());
                let _ = tls.write_all(reply.as_bytes()).await;
                let _ = tls.shutdown().await;
            });
        }
    });
    (port, server_ca)
}

/// Connects to the [`server`] on `port` with `config` and returns its reply.
pub(crate) async fn connect(port: u16, config: Arc<ClientConfig>) -> std::io::Result<String> {
    let tcp = TcpStream::connect(("127.0.0.1", port)).await?;
    let name = ServerName::try_from("localhost").unwrap();
    let mut tls = TlsConnector::from(config).connect(name, tcp).await?;
    let mut reply = String::new();
    tls.read_to_string(&mut reply).await?;
    Ok(reply)
}

/// A canned response from the [`MockService`].
#[derive(Debug, Clone)]
pub(crate) struct MockResponse {
    pub(crate) status: u16,
    pub(crate) headers: Vec<(String, String)>,
    pub(crate) body: Vec<u8>,
    pub(crate) delay: Duration,
}

impl MockResponse {
    /// A JSON response.
    pub(crate) fn json(status: u16, body: &str) -> Self {
        Self {
            status,
            headers: vec![("content-type".into(), "application/json".into())],
            body: body.as_bytes().to_vec(),
            delay: Duration::ZERO,
        }
    }

    /// A `restJson1` error named `error_type`.
    pub(crate) fn error(status: u16, error_type: &str) -> Self {
        Self::json(status, r#"{"message":"mock error"}"#).header("x-amzn-errortype", error_type)
    }

    pub(crate) fn header(mut self, name: &str, value: &str) -> Self {
        self.headers.push((name.into(), value.into()));
        self
    }

    pub(crate) fn delay(mut self, delay: Duration) -> Self {
        self.delay = delay;
        self
    }
}

/// A request the [`MockService`] received.
#[derive(Debug, Clone)]
pub(crate) struct Recorded {
    pub(crate) method: String,
    pub(crate) path: String,
    pub(crate) headers: hyper::HeaderMap,
    pub(crate) body: Vec<u8>,
    /// The subject CN of the client certificate, if the service required one.
    pub(crate) client_cn: Option<String>,
}

impl Recorded {
    pub(crate) fn json(&self) -> serde_json::Value {
        serde_json::from_slice(&self.body).unwrap()
    }
}

#[derive(Default)]
struct MockState {
    responses: std::collections::VecDeque<MockResponse>,
    requests: Vec<Recorded>,
}

/// A local HTTPS mock of the bootstrap service. Responds with queued [`MockResponse`]s in
/// order, then `500 InternalError`, and records every request.
pub(crate) struct MockService {
    pub(crate) port: u16,
    pub(crate) ca: Ca,
    state: Arc<std::sync::Mutex<MockState>>,
}

impl MockService {
    /// A service with a certificate for `localhost`.
    pub(crate) async fn start() -> Self {
        Self::start_as("localhost").await
    }

    /// A service whose certificate names `host`.
    pub(crate) async fn start_as(host: &str) -> Self {
        Self::start_with(host, None).await
    }

    /// A service for `localhost` that requires a client certificate from `client_ca`, like the
    /// AWS IoT credentials provider.
    pub(crate) async fn start_mtls(client_ca: &Ca) -> Self {
        Self::start_with("localhost", Some(client_ca)).await
    }

    async fn start_with(host: &str, client_ca: Option<&Ca>) -> Self {
        use http_body_util::{BodyExt, Full};
        use hyper::body::Bytes;

        let ca = ca("Helios test bootstrap CA");
        let key = KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).unwrap();
        let cert = CertificateParams::new(vec![host.to_owned()])
            .unwrap()
            .signed_by(&key, &ca.issuer)
            .unwrap();
        let builder = ServerConfig::builder_with_provider(crypto_provider())
            .with_safe_default_protocol_versions()
            .unwrap();
        let builder = match client_ca {
            Some(client_ca) => builder.with_client_cert_verifier(
                WebPkiClientVerifier::builder_with_provider(
                    Arc::new(root_store_from_pem(client_ca.pem.as_bytes()).unwrap()),
                    crypto_provider(),
                )
                .build()
                .unwrap(),
            ),
            None => builder.with_no_client_auth(),
        };
        let config = builder
            .with_single_cert(
                vec![cert.der().clone()],
                PrivateKeyDer::try_from(key.serialize_der()).unwrap(),
            )
            .unwrap();
        let acceptor = TlsAcceptor::from(Arc::new(config));
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let state = Arc::new(std::sync::Mutex::new(MockState::default()));
        let shared = state.clone();
        tokio::spawn(async move {
            while let Ok((tcp, _)) = listener.accept().await {
                let acceptor = acceptor.clone();
                let state = shared.clone();
                tokio::spawn(async move {
                    let Ok(tls) = acceptor.accept(tcp).await else {
                        return;
                    };
                    let client_cn = tls.get_ref().1.peer_certificates().map(|chain| {
                        let (_, cert) = x509_parser::parse_x509_certificate(&chain[0]).unwrap();
                        let cn = cert.subject().iter_common_name().next().unwrap();
                        cn.as_str().unwrap().to_owned()
                    });
                    let service = hyper::service::service_fn(
                        move |request: hyper::Request<hyper::body::Incoming>| {
                            let state = state.clone();
                            let client_cn = client_cn.clone();
                            async move {
                                let (parts, body) = request.into_parts();
                                let body = body
                                    .collect()
                                    .await
                                    .map(|b| b.to_bytes().to_vec())
                                    .unwrap_or_default();
                                let response = {
                                    let mut state = state.lock().unwrap();
                                    state.requests.push(Recorded {
                                        method: parts.method.to_string(),
                                        path: parts.uri.to_string(),
                                        headers: parts.headers,
                                        body,
                                        client_cn,
                                    });
                                    state.responses.pop_front()
                                }
                                .unwrap_or_else(|| MockResponse::error(500, "InternalError"));
                                tokio::time::sleep(response.delay).await;
                                let mut builder =
                                    hyper::Response::builder().status(response.status);
                                for (name, value) in &response.headers {
                                    builder = builder.header(name, value);
                                }
                                Ok::<_, std::convert::Infallible>(
                                    builder.body(Full::new(Bytes::from(response.body))).unwrap(),
                                )
                            }
                        },
                    );
                    let _ = hyper::server::conn::http1::Builder::new()
                        .serve_connection(hyper_util::rt::TokioIo::new(tls), service)
                        .await;
                });
            }
        });
        Self { port, ca, state }
    }

    /// Queues a response.
    pub(crate) fn respond(&self, response: MockResponse) {
        self.state.lock().unwrap().responses.push_back(response);
    }

    /// The requests received so far.
    pub(crate) fn requests(&self) -> Vec<Recorded> {
        self.state.lock().unwrap().requests.clone()
    }

    /// The service's base URL.
    pub(crate) fn url(&self) -> String {
        format!("https://localhost:{}/v1", self.port)
    }

    /// Roots that trust the service's certificate.
    pub(crate) fn roots(&self) -> rustls::RootCertStore {
        root_store_from_pem(self.ca.pem.as_bytes()).unwrap()
    }
}

/// A fake `/sys` with built-in Ethernet adapters named `name` with permanent MAC `mac`.
pub(crate) fn fake_sysfs(adapters: &[(&str, &str)]) -> tempfile::TempDir {
    let root = tempfile::tempdir().unwrap();
    let net = root.path().join("class/net");
    std::fs::create_dir_all(&net).unwrap();
    for (name, mac) in adapters {
        let device = root.path().join("devices/platform").join(name);
        let interface = device.join("net").join(name);
        std::fs::create_dir_all(&interface).unwrap();
        std::os::unix::fs::symlink(&device, interface.join("device")).unwrap();
        std::fs::write(interface.join("type"), "1\n").unwrap();
        std::fs::write(interface.join("addr_assign_type"), "0\n").unwrap();
        std::fs::write(interface.join("address"), format!("{mac}\n")).unwrap();
        std::os::unix::fs::symlink(&interface, net.join(name)).unwrap();
    }
    root
}

/// A kernel that reports no permanent addresses, so the sysfs fallback is used.
pub(crate) struct NoPermanentAddresses;

impl crate::identity::bootstrap::adapters::PermanentAddresses for NoPermanentAddresses {
    fn permanent_address(
        &self,
        _: &str,
    ) -> std::io::Result<Option<crate::identity::bootstrap::adapters::MacAddress>> {
        Ok(None)
    }
}

/// A running identity manager with a mock token whose certificate comes from `ca`, trusting
/// servers under `roots`, waited on until it is ready. Cancel the token to stop it.
pub(crate) async fn ready_identity(
    ca: &Ca,
    roots: rustls::RootCertStore,
) -> (
    crate::identity::manager::IdentityHandle,
    crate::identity::mock::MockToken,
    tokio_util::sync::CancellationToken,
) {
    use crate::identity::manager::{IdentityManager, IdentityState, ManagerConfig, PinSetting};
    use crate::identity::mock::{MockKey, MockToken};
    use crate::identity::pin::FixedPin;

    let key = SigningKey::from_slice(&[7; 32]).unwrap();
    let token = MockToken::new("1234");
    token.add_key(MockKey {
        label: "device-key".into(),
        id: vec![1],
        signing_key: key.clone(),
        private: true,
        certificate: Some(device_certificate(ca, &key, THING_NAME).to_vec()),
    });
    let cancel = tokio_util::sync::CancellationToken::new();
    let (handle, _task) = IdentityManager::start(
        ManagerConfig::new(THING_NAME, "device-key"),
        Box::new(token.clone()),
        PinSetting::Local(Arc::new(FixedPin::new(secrecy::SecretString::new(
            "1234".into(),
        )))),
        roots,
        cancel.clone(),
    )
    .unwrap();
    let mut state = handle.watch();
    tokio::time::timeout(
        Duration::from_secs(10),
        state.wait_for(|state| matches!(state, IdentityState::Ready(_))),
    )
    .await
    .unwrap()
    .unwrap();
    (handle, token, cancel)
}
