//! rustls integration: a signing key backed by the token, the client certificate resolver,
//! and the TLS client configs for MQTT and HTTPS (LLD 1, section 4.4).

use std::sync::{Arc, PoisonError, RwLock};

use rustls::client::ResolvesClientCert;
use rustls::crypto::CryptoProvider;
use rustls::sign::{CertifiedKey, Signer, SigningKey};
use rustls::{ClientConfig, RootCertStore, SignatureAlgorithm, SignatureScheme};
use rustls_pki_types::CertificateDer;
use rustls_pki_types::pem::PemObject;
use sha2::{Digest as _, Sha256};

use crate::identity::der;
use crate::identity::signer::SignerClient;
use crate::identity::token::KeyRef;

/// The only scheme a P-256 key can sign with in TLS 1.3, and the one AWS IoT uses.
const SCHEME: SignatureScheme = SignatureScheme::ECDSA_NISTP256_SHA256;

/// ALPN for each use of the TLS config (LLD 1, section 4.4).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Alpn {
    /// MQTT on port 8883: no ALPN.
    None,
    /// MQTT on port 443: `x-amzn-mqtt-ca`.
    MqttOver443,
    /// The credentials provider over HTTPS: `http/1.1`.
    Http1,
}

impl Alpn {
    /// The protocol names to offer.
    #[must_use]
    pub fn protocols(self) -> Vec<Vec<u8>> {
        match self {
            Self::None => Vec::new(),
            Self::MqttOver443 => vec![b"x-amzn-mqtt-ca".to_vec()],
            Self::Http1 => vec![b"http/1.1".to_vec()],
        }
    }
}

/// Errors from building TLS configs.
#[derive(Debug, thiserror::Error)]
pub enum TlsError {
    /// The root CA file isn't valid PEM.
    #[error("root CA bundle is not valid PEM: {0}")]
    Pem(String),
    /// The root CA bundle has no certificates.
    #[error("root CA bundle contains no certificates")]
    NoRoots,
    /// A root certificate was rejected.
    #[error("root CA certificate rejected: {0}")]
    BadRoot(rustls::Error),
    /// rustls rejected the configuration.
    #[error("TLS configuration error: {0}")]
    Config(rustls::Error),
}

/// A P-256 key held in the token. Signing goes through the signer thread.
#[derive(Debug)]
pub struct TokenSigningKey {
    signer: SignerClient,
    key: KeyRef,
}

impl TokenSigningKey {
    /// A signing key for `key`, signing through `signer`.
    #[must_use]
    pub fn new(signer: SignerClient, key: KeyRef) -> Self {
        Self { signer, key }
    }
}

impl SigningKey for TokenSigningKey {
    fn choose_scheme(&self, offered: &[SignatureScheme]) -> Option<Box<dyn Signer>> {
        offered.contains(&SCHEME).then(|| {
            Box::new(TokenSigner {
                signer: self.signer.clone(),
                key: self.key.clone(),
            }) as Box<dyn Signer>
        })
    }

    fn algorithm(&self) -> SignatureAlgorithm {
        SignatureAlgorithm::ECDSA
    }
}

#[derive(Debug)]
struct TokenSigner {
    signer: SignerClient,
    key: KeyRef,
}

impl Signer for TokenSigner {
    fn sign(&self, message: &[u8]) -> Result<Vec<u8>, rustls::Error> {
        let digest: [u8; 32] = Sha256::digest(message).into();
        // Details are reported through the signer's lost-token channel and the manager's
        // logs. rustls only needs to know that the handshake can't continue.
        let raw = self
            .signer
            .sign(&self.key, &digest)
            .map_err(|_| rustls::Error::General("token signing failed".to_owned()))?;
        der::raw_to_der(&raw).map_err(|_| rustls::Error::General("token signing failed".to_owned()))
    }

    fn scheme(&self) -> SignatureScheme {
        SCHEME
    }
}

/// Presents the current device certificate and key, or nothing while the identity isn't
/// ready. The identity manager swaps in a new value after each successful open, so every
/// connection uses the current certificate.
#[derive(Debug, Default)]
pub struct Resolver {
    current: RwLock<Option<Arc<CertifiedKey>>>,
}

impl Resolver {
    /// A resolver with no identity yet.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Replaces the identity, or clears it with `None`.
    pub fn set(&self, certified_key: Option<Arc<CertifiedKey>>) {
        *self.current.write().unwrap_or_else(PoisonError::into_inner) = certified_key;
    }

    /// The current identity, if there is one.
    #[must_use]
    pub fn current(&self) -> Option<Arc<CertifiedKey>> {
        self.current
            .read()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
    }
}

impl ResolvesClientCert for Resolver {
    fn resolve(
        &self,
        _root_hint_subjects: &[&[u8]],
        sigschemes: &[SignatureScheme],
    ) -> Option<Arc<CertifiedKey>> {
        // Without a usable scheme the server would reject our signature anyway.
        if sigschemes.contains(&SCHEME) {
            self.current()
        } else {
            None
        }
    }

    fn has_certs(&self) -> bool {
        self.current().is_some()
    }
}

/// A certified key for the token key, with the device certificate (and any intermediates).
#[must_use]
pub fn certified_key(
    chain: Vec<CertificateDer<'static>>,
    signer: SignerClient,
    key: KeyRef,
) -> Arc<CertifiedKey> {
    Arc::new(CertifiedKey::new(
        chain,
        Arc::new(TokenSigningKey::new(signer, key)),
    ))
}

/// Parses a PEM bundle of root CAs, such as `AmazonRootCA1.pem`.
///
/// # Errors
///
/// [`TlsError::Pem`] for invalid PEM, [`TlsError::NoRoots`] if it has no certificates, and
/// [`TlsError::BadRoot`] if a certificate can't be used as a root.
pub fn root_store_from_pem(pem: &[u8]) -> Result<RootCertStore, TlsError> {
    let mut roots = RootCertStore::empty();
    for cert in CertificateDer::pem_slice_iter(pem) {
        let cert = cert.map_err(|e| TlsError::Pem(e.to_string()))?;
        roots.add(cert).map_err(TlsError::BadRoot)?;
    }
    if roots.is_empty() {
        return Err(TlsError::NoRoots);
    }
    Ok(roots)
}

/// The crypto provider: `ring`, which cross-compiles without CMake (LLD 1, section 4.4).
#[must_use]
pub fn crypto_provider() -> Arc<CryptoProvider> {
    Arc::new(rustls::crypto::ring::default_provider())
}

/// A client config that verifies servers against `roots` and presents whatever identity
/// `resolver` currently holds.
///
/// Session resumption is turned off. A resumed TLS 1.3 session skips the client signature,
/// so a lost or replaced token would go unnoticed and the device could keep reconnecting
/// without the key. One signature per connection costs little.
///
/// # Errors
///
/// [`TlsError::Config`] if rustls rejects the protocol versions for the provider.
pub fn client_config(
    roots: RootCertStore,
    resolver: Arc<Resolver>,
    alpn: Alpn,
) -> Result<Arc<ClientConfig>, TlsError> {
    let mut config = ClientConfig::builder_with_provider(crypto_provider())
        .with_safe_default_protocol_versions()
        .map_err(TlsError::Config)?
        .with_root_certificates(roots)
        .with_client_cert_resolver(resolver);
    config.alpn_protocols = alpn.protocols();
    config.resumption = rustls::client::Resumption::disabled();
    Ok(Arc::new(config))
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use p256::ecdsa::SigningKey as P256SigningKey;
    use secrecy::SecretString;

    use super::*;
    use crate::identity::mock::{MockKey, MockToken, Op};
    use crate::identity::signer::{DEFAULT_SIGN_TIMEOUT, SignerHandle};
    use crate::identity::testing::{self, Ca, THING_NAME, ca, server};
    use crate::identity::token::TokenError;

    struct Device {
        token: MockToken,
        signer: SignerHandle,
        resolver: Arc<Resolver>,
        lost: tokio::sync::mpsc::UnboundedReceiver<TokenError>,
    }

    /// A mock token whose key has a certificate from `client_ca`, opened on a signer thread,
    /// with the resolver holding the certified key.
    async fn device(client_ca: &Ca, timeout: Duration) -> Device {
        let signing_key = P256SigningKey::from_slice(&[9; 32]).unwrap();
        let cert = testing::device_certificate(client_ca, &signing_key, THING_NAME);
        let token = MockToken::new("1234");
        token.add_key(MockKey {
            label: "device-key".into(),
            id: vec![1],
            signing_key,
            private: true,
            certificate: Some(cert.to_vec()),
        });
        let (lost_tx, lost) = tokio::sync::mpsc::unbounded_channel();
        let signer = SignerHandle::spawn(Box::new(token.clone()), Some(lost_tx), timeout).unwrap();
        let key = signer
            .run(|backend| {
                backend.open()?;
                backend.login(&SecretString::new("1234".into()))?;
                backend.find_key("device-key")
            })
            .await
            .unwrap()
            .unwrap();
        let resolver = Arc::new(Resolver::new());
        resolver.set(Some(certified_key(vec![cert], signer.client(), key)));
        Device {
            token,
            signer,
            resolver,
            lost,
        }
    }

    async fn connect(
        port: u16,
        server_ca: &Ca,
        resolver: Arc<Resolver>,
    ) -> std::io::Result<String> {
        let roots = root_store_from_pem(server_ca.pem.as_bytes()).unwrap();
        let config = client_config(roots, resolver, Alpn::None).unwrap();
        testing::connect(port, config).await
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn mutual_tls_handshake_signs_with_the_token() {
        let client_ca = ca("Helios test device CA");
        let (port, server_ca) = server(&client_ca).await;
        let device = device(&client_ca, DEFAULT_SIGN_TIMEOUT).await;

        let reply = connect(port, &server_ca, device.resolver.clone())
            .await
            .unwrap();

        assert_eq!(reply, format!("hello {THING_NAME}"));
        assert!(device.token.calls().contains(&Op::SignDigest));
        device.signer.shutdown();
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn every_connection_signs_with_the_token() {
        let client_ca = ca("Helios test device CA");
        let (port, server_ca) = server(&client_ca).await;
        let device = device(&client_ca, DEFAULT_SIGN_TIMEOUT).await;
        let roots = root_store_from_pem(server_ca.pem.as_bytes()).unwrap();
        let config = client_config(roots, device.resolver.clone(), Alpn::None).unwrap();

        for _ in 0..2 {
            let reply = testing::connect(port, config.clone()).await.unwrap();
            assert_eq!(reply, format!("hello {THING_NAME}"));
        }

        // No session resumption: the second connection proves possession of the key again.
        let signatures = device
            .token
            .calls()
            .into_iter()
            .filter(|op| *op == Op::SignDigest);
        assert_eq!(signatures.count(), 2);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn the_handshake_fails_without_an_identity() {
        let client_ca = ca("Helios test device CA");
        let (port, server_ca) = server(&client_ca).await;
        let device = device(&client_ca, DEFAULT_SIGN_TIMEOUT).await;
        device.resolver.set(None);

        let reply = connect(port, &server_ca, device.resolver.clone()).await;

        // The server requires a client certificate, so it ends the connection without a reply.
        assert!(
            reply.as_ref().map_or(true, String::is_empty),
            "unexpected reply: {reply:?}"
        );
        assert!(!device.token.calls().contains(&Op::SignDigest));
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_lost_token_fails_the_handshake_and_is_reported() {
        let client_ca = ca("Helios test device CA");
        let (port, server_ca) = server(&client_ca).await;
        let mut device = device(&client_ca, DEFAULT_SIGN_TIMEOUT).await;
        device
            .token
            .fail_next(Op::SignDigest, TokenError::TokenLost("unplugged".into()));

        let error = connect(port, &server_ca, device.resolver.clone())
            .await
            .unwrap_err();

        assert!(
            error.to_string().contains("token signing failed"),
            "{error}"
        );
        assert_eq!(
            device.lost.recv().await,
            Some(TokenError::TokenLost("unplugged".into()))
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_hung_token_times_out_the_handshake() {
        let client_ca = ca("Helios test device CA");
        let (port, server_ca) = server(&client_ca).await;
        let mut device = device(&client_ca, Duration::from_millis(100)).await;
        device.token.set_sign_delay(Duration::from_secs(1));

        let error = connect(port, &server_ca, device.resolver.clone())
            .await
            .unwrap_err();

        assert!(
            error.to_string().contains("token signing failed"),
            "{error}"
        );
        assert_eq!(
            device.lost.recv().await,
            Some(TokenError::TokenLost(
                "signing timed out after 100 ms".into()
            ))
        );
        device.token.set_sign_delay(Duration::ZERO);
    }

    #[test]
    fn only_offers_a_signer_for_p256_sha256() {
        let token = MockToken::new("1234");
        let signer = SignerHandle::spawn(Box::new(token), None, DEFAULT_SIGN_TIMEOUT).unwrap();
        let key = KeyRef {
            label: "device-key".into(),
            id: vec![1],
            handle: crate::identity::token::KeyHandle {
                generation: 0,
                index: 0,
            },
        };
        let signing_key = TokenSigningKey::new(signer.client(), key);

        assert_eq!(signing_key.algorithm(), SignatureAlgorithm::ECDSA);
        let chosen = signing_key
            .choose_scheme(&[SignatureScheme::RSA_PSS_SHA256, SCHEME])
            .expect("P-256 SHA-256 was offered");
        assert_eq!(chosen.scheme(), SCHEME);
        assert!(
            signing_key
                .choose_scheme(&[
                    SignatureScheme::ECDSA_NISTP384_SHA384,
                    SignatureScheme::ED25519,
                    SignatureScheme::RSA_PSS_SHA256,
                ])
                .is_none()
        );
        assert!(signing_key.choose_scheme(&[]).is_none());
    }

    #[test]
    fn a_signature_that_is_not_valid_fails_the_handshake() {
        let token = MockToken::new("1234");
        let signer = SignerHandle::spawn(Box::new(token), None, DEFAULT_SIGN_TIMEOUT).unwrap();
        let key = KeyRef {
            label: "device-key".into(),
            id: vec![1],
            handle: crate::identity::token::KeyHandle {
                generation: 0,
                index: 0,
            },
        };
        let tls_signer = TokenSigner {
            signer: signer.client(),
            key,
        };

        // The mock isn't open, so signing fails.
        let error = tls_signer.sign(b"handshake transcript").unwrap_err();

        assert_eq!(error, rustls::Error::General("token signing failed".into()));
    }

    #[test]
    fn the_resolver_needs_an_identity_and_the_p256_scheme() {
        let resolver = Resolver::new();
        assert!(!resolver.has_certs());
        assert!(resolver.resolve(&[], &[SCHEME]).is_none());

        let token = MockToken::new("1234");
        let signer = SignerHandle::spawn(Box::new(token), None, DEFAULT_SIGN_TIMEOUT).unwrap();
        let key = KeyRef {
            label: "device-key".into(),
            id: vec![1],
            handle: crate::identity::token::KeyHandle {
                generation: 0,
                index: 0,
            },
        };
        let certified = certified_key(vec![CertificateDer::from(vec![0x30])], signer.client(), key);
        resolver.set(Some(certified.clone()));

        assert!(resolver.has_certs());
        assert!(Arc::ptr_eq(
            &resolver.resolve(&[], &[SCHEME]).unwrap(),
            &certified
        ));
        assert!(resolver.resolve(&[], &[SignatureScheme::ED25519]).is_none());
        resolver.set(None);
        assert!(resolver.current().is_none());
    }

    #[test]
    fn alpn_matches_the_lld_table() {
        assert!(Alpn::None.protocols().is_empty());
        assert_eq!(
            Alpn::MqttOver443.protocols(),
            vec![b"x-amzn-mqtt-ca".to_vec()]
        );
        assert_eq!(Alpn::Http1.protocols(), vec![b"http/1.1".to_vec()]);

        let roots = root_store_from_pem(ca("root").pem.as_bytes()).unwrap();
        let config = client_config(roots, Arc::new(Resolver::new()), Alpn::Http1).unwrap();
        assert_eq!(config.alpn_protocols, vec![b"http/1.1".to_vec()]);
    }

    #[test]
    fn root_bundles_must_hold_valid_certificates() {
        let two = format!("{}{}", ca("a").pem, ca("b").pem);
        assert_eq!(root_store_from_pem(two.as_bytes()).unwrap().len(), 2);

        assert!(matches!(root_store_from_pem(b""), Err(TlsError::NoRoots)));
        assert!(matches!(
            root_store_from_pem(b"not pem at all"),
            Err(TlsError::NoRoots)
        ));
        let broken = "-----BEGIN CERTIFICATE-----\n!!!!\n-----END CERTIFICATE-----\n";
        assert!(matches!(
            root_store_from_pem(broken.as_bytes()),
            Err(TlsError::Pem(_))
        ));
        let junk = "-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----\n";
        let error = root_store_from_pem(junk.as_bytes()).unwrap_err();
        assert!(matches!(error, TlsError::BadRoot(_)), "{error:?}");
        assert!(
            error
                .to_string()
                .starts_with("root CA certificate rejected")
        );
        assert_eq!(
            TlsError::NoRoots.to_string(),
            "root CA bundle contains no certificates"
        );
    }
}
