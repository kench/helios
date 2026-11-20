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
