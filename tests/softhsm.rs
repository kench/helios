//! Integration tests for `CryptokiToken` against a real SoftHSM2 token (LLD 1, section 9).
//!
//! SoftHSM2 reads its config from `SOFTHSM2_CONF` when the module is initialized, and a
//! PKCS#11 module can only be initialized once per process at a time. So `softhsm_suite`
//! runs the tests in `suite` in a child process, one at a time, with `SOFTHSM2_CONF` pointing
//! at a fresh token directory. The `suite` tests are `#[ignore]`d so they only run there.
//!
//! The module is `$HELIOS_SOFTHSM2_MODULE`, or `/usr/lib/softhsm/libsofthsm2.so` (Debian's
//! `softhsm2` package). Without it the suite is skipped, unless `HELIOS_REQUIRE_SOFTHSM2` is
//! set, as in CI.

use std::path::PathBuf;
use std::process::Command;

const DEFAULT_MODULE: &str = "/usr/lib/softhsm/libsofthsm2.so";
const SUITE_MARKER: &str = "HELIOS_SOFTHSM2_SUITE";

fn module_path() -> PathBuf {
    std::env::var_os("HELIOS_SOFTHSM2_MODULE").map_or_else(|| DEFAULT_MODULE.into(), PathBuf::from)
}

#[test]
fn softhsm_suite() {
    let module = module_path();
    if !module.exists() {
        assert!(
            std::env::var_os("HELIOS_REQUIRE_SOFTHSM2").is_none(),
            "SoftHSM2 module not found at {} but HELIOS_REQUIRE_SOFTHSM2 is set",
            module.display()
        );
        eprintln!("skipping SoftHSM2 tests: no module at {}", module.display());
        return;
    }

    let dir = tempfile::tempdir().expect("failed to create a temporary directory");
    let tokens = dir.path().join("tokens");
    std::fs::create_dir(&tokens).expect("failed to create the token directory");
    let conf = dir.path().join("softhsm2.conf");
    std::fs::write(
        &conf,
        format!(
            "directories.tokendir = {}\nobjectstore.backend = file\nlog.level = ERROR\n",
            tokens.display()
        ),
    )
    .expect("failed to write softhsm2.conf");

    let output = Command::new(std::env::current_exe().expect("no current executable"))
        .args(["--ignored", "--test-threads=1", "--color=never", "suite::"])
        .env("SOFTHSM2_CONF", &conf)
        .env("HELIOS_SOFTHSM2_MODULE", &module)
        .env(SUITE_MARKER, "1")
        .output()
        .expect("failed to run the SoftHSM2 suite");

    let stdout = String::from_utf8_lossy(&output.stdout);
    println!("{stdout}");
    eprintln!("{}", String::from_utf8_lossy(&output.stderr));
    assert!(
        output.status.success(),
        "SoftHSM2 suite failed: {}",
        output.status
    );
    assert!(
        !stdout.contains("running 0 tests"),
        "the SoftHSM2 suite ran no tests"
    );
}

mod suite {
    use ::cryptoki::context::{CInitializeArgs, Pkcs11};
    use ::cryptoki::mechanism::Mechanism;
    use ::cryptoki::object::{
        Attribute, AttributeType, CertificateType, ObjectClass, ObjectHandle,
    };
    use ::cryptoki::session::{Session, UserType};
    use ::cryptoki::slot::Slot;
    use helios::identity::cert::DeviceCertificate;
    use helios::identity::cryptoki::CryptokiToken;
    use helios::identity::token::{PinStatus, TokenBackend, TokenError};
    use p256::ecdsa::signature::hazmat::PrehashVerifier;
    use p256::ecdsa::{Signature, VerifyingKey};
    use p256::pkcs8::{DecodePublicKey, EncodePublicKey};
    use rcgen::{CertificateParams, DnType, Issuer, KeyPair, SubjectPublicKeyInfo};
    use rustls_pki_types::pem::PemObject;
    use secrecy::SecretString;

    use super::{SUITE_MARKER, module_path};

    const SO_PIN: &str = "12345678";
    const USER_PIN: &str = "123456";
    /// DER OID for prime256v1 (P-256), the CKA_EC_PARAMS value.
    const P256_PARAMS: [u8; 10] = [0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07];

    fn in_suite() -> bool {
        let inside = std::env::var_os(SUITE_MARKER).is_some();
        if !inside {
            eprintln!("skipping: run through softhsm_suite");
        }
        inside
    }

    fn pin(value: &str) -> SecretString {
        SecretString::new(value.to_owned())
    }

    fn pkcs11() -> Pkcs11 {
        let pkcs11 = Pkcs11::new(module_path()).expect("failed to load SoftHSM2");
        pkcs11
            .initialize(CInitializeArgs::OsThreads)
            .expect("failed to initialize SoftHSM2");
        pkcs11
    }

    fn slot_with_label(pkcs11: &Pkcs11, label: &str) -> Slot {
        pkcs11
            .get_slots_with_token()
            .unwrap()
            .into_iter()
            .find(|slot| pkcs11.get_token_info(*slot).unwrap().label().trim_end() == label)
            .unwrap_or_else(|| panic!("no token {label:?}"))
    }

    /// Initializes a new SoftHSM2 token with the user PIN set.
    fn create_token(label: &str) {
        let pkcs11 = pkcs11();
        let free = pkcs11
            .get_slots_with_token()
            .unwrap()
            .into_iter()
            .find(|slot| !pkcs11.get_token_info(*slot).unwrap().token_initialized())
            .expect("SoftHSM2 has no free slot");
        pkcs11.init_token(free, &pin(SO_PIN), label).unwrap();
        // SoftHSM2 moves an initialized token to a new slot, so look it up again.
        let session = pkcs11
            .open_rw_session(slot_with_label(&pkcs11, label))
            .unwrap();
        session.login(UserType::So, Some(&pin(SO_PIN))).unwrap();
        session.init_pin(&pin(USER_PIN)).unwrap();
    }

    fn user_session(pkcs11: &Pkcs11, token: &str) -> Session {
        let session = pkcs11
            .open_rw_session(slot_with_label(pkcs11, token))
            .unwrap();
        session.login(UserType::User, Some(&pin(USER_PIN))).unwrap();
        session
    }

    fn public_key_der(session: &Session, public: ObjectHandle) -> Vec<u8> {
        let point = session
            .get_attributes(public, &[AttributeType::EcPoint])
            .unwrap()
            .into_iter()
            .find_map(|attribute| match attribute {
                Attribute::EcPoint(point) => Some(point),
                _ => None,
            })
            .expect("no CKA_EC_POINT");
        // CKA_EC_POINT is a DER OCTET STRING around the 65-byte uncompressed point.
        assert_eq!(
            &point[..2],
            &[0x04, 0x41],
            "unexpected CKA_EC_POINT encoding"
        );
        let key = p256::PublicKey::from_sec1_bytes(&point[2..]).unwrap();
        key.to_public_key_der().unwrap().as_bytes().to_vec()
    }

    /// Generates a P-256 key pair in the token and returns the public key as SPKI DER.
    fn generate_key(token: &str, label: &str, id: u8, private: bool) -> Vec<u8> {
        let pkcs11 = pkcs11();
        let session = user_session(&pkcs11, token);
        let public_template = [
            Attribute::Token(true),
            Attribute::EcParams(P256_PARAMS.to_vec()),
            Attribute::Verify(true),
            Attribute::Label(label.as_bytes().to_vec()),
            Attribute::Id(vec![id]),
        ];
        let private_template = [
            Attribute::Token(true),
            Attribute::Private(private),
            Attribute::Sensitive(true),
            Attribute::Sign(true),
            Attribute::Label(label.as_bytes().to_vec()),
            Attribute::Id(vec![id]),
        ];
        let (public, _) = session
            .generate_key_pair(
                &Mechanism::EccKeyPairGen,
                &public_template,
                &private_template,
            )
            .unwrap();
        public_key_der(&session, public)
    }

    /// Issues a certificate for `spki_der` from a throwaway test CA.
    fn issue_certificate(spki_der: &[u8], cn: &str) -> Vec<u8> {
        let ca_key = KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).unwrap();
        let mut ca_params = CertificateParams::default();
        ca_params
            .distinguished_name
            .push(DnType::CommonName, "Helios test CA");
        let issuer = Issuer::new(ca_params, ca_key);
        let mut params = CertificateParams::default();
        params.distinguished_name.push(DnType::CommonName, cn);
        let public_key = SubjectPublicKeyInfo::from_der(spki_der).unwrap();
        params
            .signed_by(&public_key, &issuer)
            .unwrap()
            .der()
            .to_vec()
    }

    fn store_certificate(token: &str, id: u8, der: &[u8]) {
        let (_, cert) = x509_parser::parse_x509_certificate(der).unwrap();
        let pkcs11 = pkcs11();
        let session = user_session(&pkcs11, token);
        session
            .create_object(&[
                Attribute::Class(ObjectClass::CERTIFICATE),
                Attribute::CertificateType(CertificateType::X_509),
                Attribute::Token(true),
                Attribute::Id(vec![id]),
                Attribute::Label(b"device-key".to_vec()),
                Attribute::Subject(cert.subject().as_raw().to_vec()),
                Attribute::Value(der.to_vec()),
            ])
            .unwrap();
    }

    /// A token with a private device key (CKA_ID 01) and its certificate.
    fn provisioned_token(token: &str) -> Vec<u8> {
        create_token(token);
        let spki = generate_key(token, "device-key", 1, true);
        let cert = issue_certificate(&spki, "t-01JD5VY2K7M9Q4R6T8V0X2Z4B6");
        store_certificate(token, 1, &cert);
        cert
    }

    fn backend(token: &str) -> CryptokiToken {
        CryptokiToken::new(module_path(), token)
    }

    #[test]
    #[ignore = "run by softhsm_suite"]
    fn opens_logs_in_reads_the_certificate_and_signs() {
        if !in_suite() {
            return;
        }
        let cert_der = provisioned_token("open-sequence");
        let mut token = backend("open-sequence");

        let summary = token.open().unwrap();
        assert_eq!(summary.label, "open-sequence");
        assert_eq!(summary.module, module_path());
        assert!(summary.manufacturer.contains("SoftHSM"), "{summary:?}");
        assert!(!summary.serial.is_empty());
        assert_eq!(token.pin_status(), Ok(PinStatus::default()));
        token.login(&pin(USER_PIN)).unwrap();
        let key = token.find_key("device-key").unwrap();
        assert_eq!(key.id, vec![1]);
        assert_eq!(
            token.read_certificate(&key).unwrap(),
            Some(cert_der.clone())
        );

        // Proof of possession with the certificate from the token (LLD 1, section 4.6).
        let digest = helios::identity::cert::random_digest().unwrap();
        let raw = token.sign_digest(&key, &digest).unwrap();
        let cert = DeviceCertificate::from_der(&cert_der).unwrap();
        assert_eq!(cert.verify_possession(&digest, &raw), Ok(()));
        assert_eq!(cert.subject_cn(), Some("t-01JD5VY2K7M9Q4R6T8V0X2Z4B6"));

        token.close();
        assert_eq!(token.sign_digest(&key, &digest), Err(TokenError::NotOpen));
    }

    #[test]
    #[ignore = "run by softhsm_suite"]
    fn makes_the_secrets_key_once_and_derives_with_it() {
        use p256::elliptic_curve::sec1::ToSec1Point;

        if !in_suite() {
            return;
        }
        provisioned_token("secrets");
        let mut token = backend("secrets");
        token.open().unwrap();
        token.login(&pin(USER_PIN)).unwrap();
        let public = token.secrets_key("helios-secrets").unwrap();
        assert_eq!(public.len(), 65);
        assert_eq!(public[0], 0x04);
        // Found, not made again, now and after reopening.
        assert_eq!(token.secrets_key("helios-secrets").unwrap(), public);
        token.open().unwrap();
        token.login(&pin(USER_PIN)).unwrap();
        assert_eq!(token.secrets_key("helios-secrets").unwrap(), public);

        // ECDH agrees with the peer's side.
        let peer = p256::SecretKey::from_slice(&[0x42; 32]).unwrap();
        let peer_point = peer.public_key().to_sec1_point(false);
        let derived = token.ecdh("helios-secrets", peer_point.as_bytes()).unwrap();
        let ours = p256::PublicKey::from_sec1_bytes(&public).unwrap();
        let expected = p256::ecdh::diffie_hellman(peer.to_nonzero_scalar(), ours.as_affine());
        assert_eq!(derived.as_slice(), expected.raw_secret_bytes().as_slice());
        assert!(
            token.ecdh("helios-secrets", &[4; 65]).is_err(),
            "not a point"
        );
        assert!(matches!(
            token.ecdh("no-such-key", peer_point.as_bytes()),
            Err(TokenError::KeyNotFound { .. })
        ));

        // The private half can only derive, and never leaves the token.
        token.close();
        let pkcs11 = pkcs11();
        let session = pkcs11
            .open_ro_session(slot_with_label(&pkcs11, "secrets"))
            .unwrap();
        session.login(UserType::User, Some(&pin(USER_PIN))).unwrap();
        let private = session
            .find_objects(&[
                Attribute::Class(ObjectClass::PRIVATE_KEY),
                Attribute::Label(b"helios-secrets".to_vec()),
            ])
            .unwrap();
        assert_eq!(private.len(), 1);
        let attributes = session
            .get_attributes(
                private[0],
                &[
                    AttributeType::Sign,
                    AttributeType::Derive,
                    AttributeType::Extractable,
                    AttributeType::Sensitive,
                    AttributeType::Token,
                ],
            )
            .unwrap();
        assert!(
            attributes.contains(&Attribute::Sign(false)),
            "{attributes:?}"
        );
        assert!(attributes.contains(&Attribute::Derive(true)));
        assert!(attributes.contains(&Attribute::Extractable(false)));
        assert!(attributes.contains(&Attribute::Sensitive(true)));
        assert!(attributes.contains(&Attribute::Token(true)));
        // No derived secret is left behind as a session object.
        let secrets = session
            .find_objects(&[Attribute::Class(ObjectClass::SECRET_KEY)])
            .unwrap();
        assert!(secrets.is_empty());
    }

    #[test]
    #[ignore = "run by softhsm_suite"]
    fn key_references_do_not_survive_a_reopen() {
        if !in_suite() {
            return;
        }
        provisioned_token("reopen");
        let mut token = backend("reopen");
        token.open().unwrap();
        token.login(&pin(USER_PIN)).unwrap();
        let old = token.find_key("device-key").unwrap();

        token.open().unwrap();
        token.login(&pin(USER_PIN)).unwrap();

        assert_eq!(token.sign_digest(&old, &[1; 32]), Err(TokenError::NotOpen));
        assert_eq!(token.read_certificate(&old), Err(TokenError::NotOpen));
        let fresh = token.find_key("device-key").unwrap();
        assert!(token.sign_digest(&fresh, &[1; 32]).is_ok());
    }

    #[test]
    #[ignore = "run by softhsm_suite"]
    fn logging_in_twice_is_fine() {
        if !in_suite() {
            return;
        }
        create_token("login-twice");
        let mut token = backend("login-twice");
        token.open().unwrap();

        assert_eq!(token.login(&pin(USER_PIN)), Ok(()));
        assert_eq!(token.login(&pin(USER_PIN)), Ok(()));
    }

    #[test]
    #[ignore = "run by softhsm_suite"]
    fn a_wrong_pin_is_reported_as_incorrect() {
        if !in_suite() {
            return;
        }
        create_token("wrong-pin");
        let mut token = backend("wrong-pin");
        token.open().unwrap();

        let error = token.login(&pin("000000")).unwrap_err();

        assert_eq!(error, TokenError::PinIncorrect);
        assert!(error.is_fatal());
        assert_eq!(token.login(&pin(USER_PIN)), Ok(()));
    }

    #[test]
    #[ignore = "run by softhsm_suite"]
    fn a_missing_token_is_not_present() {
        if !in_suite() {
            return;
        }
        create_token("present");
        let mut token = backend("absent");

        let error = token.open().unwrap_err();

        assert_eq!(
            error,
            TokenError::NotPresent {
                label: "absent".into()
            }
        );
        assert!(!error.is_fatal());
    }

    #[test]
    #[ignore = "run by softhsm_suite"]
    fn duplicate_token_labels_are_ambiguous() {
        if !in_suite() {
            return;
        }
        create_token("twin");
        create_token("twin");
        let mut token = backend("twin");

        assert_eq!(
            token.open(),
            Err(TokenError::AmbiguousToken {
                label: "twin".into(),
                count: 2
            })
        );
    }

    #[test]
    #[ignore = "run by softhsm_suite"]
    fn keys_must_exist_exactly_once() {
        if !in_suite() {
            return;
        }
        create_token("keys");
        generate_key("keys", "twice", 1, true);
        generate_key("keys", "twice", 2, true);
        let mut token = backend("keys");
        token.open().unwrap();
        token.login(&pin(USER_PIN)).unwrap();

        assert_eq!(
            token.find_key("missing"),
            Err(TokenError::KeyNotFound {
                label: "missing".into()
            })
        );
        assert_eq!(
            token.find_key("twice"),
            Err(TokenError::Ambiguous {
                what: "private EC keys with label \"twice\"".into(),
                count: 2
            })
        );
    }

    #[test]
    #[ignore = "run by softhsm_suite"]
    fn certificates_are_optional_but_unique() {
        if !in_suite() {
            return;
        }
        create_token("certs");
        generate_key("certs", "no-cert", 1, true);
        let spki = generate_key("certs", "two-certs", 2, true);
        store_certificate("certs", 2, &issue_certificate(&spki, "a"));
        store_certificate("certs", 2, &issue_certificate(&spki, "b"));
        let mut token = backend("certs");
        token.open().unwrap();
        token.login(&pin(USER_PIN)).unwrap();

        let no_cert = token.find_key("no-cert").unwrap();
        assert_eq!(token.read_certificate(&no_cert), Ok(None));
        let two_certs = token.find_key("two-certs").unwrap();
        assert_eq!(
            token.read_certificate(&two_certs),
            Err(TokenError::Ambiguous {
                what: "certificates with CKA_ID 02".into(),
                count: 2
            })
        );
    }

    #[test]
    #[ignore = "run by softhsm_suite"]
    fn a_public_challenge_key_signs_without_login() {
        if !in_suite() {
            return;
        }
        create_token("challenge");
        generate_key("challenge", "device-key", 1, true);
        let spki = generate_key("challenge", "challenge-key", 2, false);
        let mut token = backend("challenge");
        token.open().unwrap();

        let raw = token.sign_without_login("challenge-key", &[7; 32]).unwrap();

        let verifying_key = VerifyingKey::from_public_key_der(&spki).unwrap();
        let signature = Signature::from_slice(&raw).unwrap();
        assert!(verifying_key.verify_prehash(&[7; 32], &signature).is_ok());
        // The device key is CKA_PRIVATE, so it can't be found without logging in.
        assert_eq!(
            token.sign_without_login("device-key", &[7; 32]),
            Err(TokenError::KeyNotFound {
                label: "device-key".into()
            })
        );
    }

    #[test]
    #[ignore = "run by softhsm_suite"]
    fn answers_a_bootstrap_challenge_with_the_softhsm_challenge_key() {
        use base64::Engine as _;
        use base64::engine::general_purpose::STANDARD as BASE64;
        use helios::identity::bootstrap::adapters::{Adapter, AdapterKind};
        use helios::identity::bootstrap::challenge;

        if !in_suite() {
            return;
        }
        create_token("answer");
        generate_key("answer", "device-key", 1, true);
        let spki = generate_key("answer", "challenge-key", 2, false);
        let adapters = [Adapter {
            interface_name: "eth0".into(),
            kind: AdapterKind::Ethernet,
            mac: "2c:cf:67:00:00:01".parse().unwrap(),
        }];
        let message = challenge::message(
            "c-01JD5W3Q8T6M2K4X9B0N7C1D2E",
            "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8=",
            &adapters,
        );
        let digest = challenge::digest(&message);

        let signature = challenge::sign(&mut backend("answer"), "challenge-key", &digest).unwrap();

        // What the service does: verify the DER signature with the registered public key.
        let der = BASE64.decode(signature).unwrap();
        let signature = Signature::from_der(&der).unwrap();
        let verifying_key = VerifyingKey::from_public_key_der(&spki).unwrap();
        assert!(verifying_key.verify_prehash(&digest, &signature).is_ok());
    }

    /// A TLS server on localhost that requires a client certificate from `client_ca_pem` and
    /// replies with the subject CN it saw. Returns its port and its own CA certificate.
    async fn mtls_server(client_ca_pem: &str) -> (u16, String) {
        use std::sync::Arc;

        use helios::identity::tls::{crypto_provider, root_store_from_pem};
        use rustls::ServerConfig;
        use rustls::server::WebPkiClientVerifier;
        use rustls_pki_types::PrivateKeyDer;
        use tokio::io::AsyncWriteExt;

        let ca_key = KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).unwrap();
        let mut ca_params = CertificateParams::default();
        ca_params
            .distinguished_name
            .push(DnType::CommonName, "Helios test server CA");
        ca_params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        let ca_pem = ca_params.self_signed(&ca_key).unwrap().pem();
        let issuer = Issuer::new(ca_params, ca_key);
        let server_key = KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).unwrap();
        let server_cert = CertificateParams::new(vec!["localhost".to_owned()])
            .unwrap()
            .signed_by(&server_key, &issuer)
            .unwrap();
        let verifier = WebPkiClientVerifier::builder_with_provider(
            Arc::new(root_store_from_pem(client_ca_pem.as_bytes()).unwrap()),
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
        let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(config));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        tokio::spawn(async move {
            let (tcp, _) = listener.accept().await.unwrap();
            let mut tls = acceptor.accept(tcp).await.unwrap();
            let peer = tls.get_ref().1.peer_certificates().unwrap()[0].clone();
            let (_, cert) = x509_parser::parse_x509_certificate(&peer).unwrap();
            let cn = cert
                .subject()
                .iter_common_name()
                .next()
                .unwrap()
                .as_str()
                .unwrap();
            tls.write_all(format!("hello {cn}").as_bytes())
                .await
                .unwrap();
            tls.shutdown().await.unwrap();
        });
        (port, ca_pem)
    }

    #[test]
    #[ignore = "run by softhsm_suite"]
    fn mutual_tls_handshake_with_the_softhsm_key() {
        use std::sync::Arc;

        use helios::identity::signer::{DEFAULT_SIGN_TIMEOUT, SignerHandle};
        use helios::identity::tls::root_store_from_pem;
        use helios::identity::tls::{Alpn, Resolver, certified_key, client_config};
        use rustls_pki_types::{CertificateDer, ServerName};
        use tokio::io::AsyncReadExt;

        if !in_suite() {
            return;
        }
        // A device CA that issues the client certificate for the key in the token.
        let ca_key = KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).unwrap();
        let mut ca_params = CertificateParams::default();
        ca_params
            .distinguished_name
            .push(DnType::CommonName, "Helios test device CA");
        ca_params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        let device_ca_pem = ca_params.self_signed(&ca_key).unwrap().pem();
        let device_ca = Issuer::new(ca_params, ca_key);
        create_token("mtls");
        let spki = generate_key("mtls", "device-key", 1, true);
        let mut params = CertificateParams::default();
        params
            .distinguished_name
            .push(DnType::CommonName, "t-01JD5VY2K7M9Q4R6T8V0X2Z4B6");
        let public_key = SubjectPublicKeyInfo::from_der(&spki).unwrap();
        let cert_der = params
            .signed_by(&public_key, &device_ca)
            .unwrap()
            .der()
            .to_vec();
        store_certificate("mtls", 1, &cert_der);

        let runtime = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .enable_all()
            .build()
            .unwrap();
        let reply = runtime.block_on(async {
            let (port, server_ca_pem) = mtls_server(&device_ca_pem).await;
            let signer =
                SignerHandle::spawn(Box::new(backend("mtls")), None, DEFAULT_SIGN_TIMEOUT).unwrap();
            let (key, chain) = signer
                .run(|token| {
                    token.open()?;
                    token.login(&pin(USER_PIN))?;
                    let key = token.find_key("device-key")?;
                    let cert = token.read_certificate(&key)?;
                    Ok::<_, TokenError>((key, cert))
                })
                .await
                .unwrap()
                .unwrap();
            let chain = vec![CertificateDer::from(
                chain.expect("certificate on the token"),
            )];
            let resolver = Arc::new(Resolver::new());
            resolver.set(Some(certified_key(chain, signer.client(), key)));
            let roots = root_store_from_pem(server_ca_pem.as_bytes()).unwrap();
            let config = client_config(roots, resolver, Alpn::None).unwrap();

            let tcp = tokio::net::TcpStream::connect(("127.0.0.1", port))
                .await
                .unwrap();
            let name = ServerName::try_from("localhost").unwrap();
            let mut tls = tokio_rustls::TlsConnector::from(config)
                .connect(name, tcp)
                .await
                .unwrap();
            let mut reply = String::new();
            tls.read_to_string(&mut reply).await.unwrap();
            signer.shutdown();
            reply
        });

        assert_eq!(reply, "hello t-01JD5VY2K7M9Q4R6T8V0X2Z4B6");
    }
    #[test]
    #[ignore = "run by softhsm_suite"]
    fn the_identity_manager_opens_the_softhsm_token() {
        use helios::identity::manager::{
            IdentityManager, IdentityState, ManagerConfig, ManagerExit, PinSetting,
        };
        use std::os::unix::fs::PermissionsExt;

        use helios::identity::pin::PinSpec;
        use rustls::RootCertStore;
        use tokio_util::sync::CancellationToken;

        if !in_suite() {
            return;
        }
        let cert = provisioned_token("managed");
        // The PIN comes from a private file, as with identity.pin = "file:<path>".
        let pin_dir = tempfile::tempdir().unwrap();
        let pin_path = pin_dir.path().join("pin");
        std::fs::write(&pin_path, format!("{USER_PIN}\n")).unwrap();
        std::fs::set_permissions(&pin_path, std::fs::Permissions::from_mode(0o600)).unwrap();
        let pin_source = format!("file:{}", pin_path.display())
            .parse::<PinSpec>()
            .unwrap()
            .local_source(None)
            .unwrap()
            .unwrap();
        let fingerprint = DeviceCertificate::from_der(&cert)
            .unwrap()
            .fingerprint_hex();

        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        runtime.block_on(async {
            let cancel = CancellationToken::new();
            let (handle, task) = IdentityManager::start(
                ManagerConfig::new("t-01JD5VY2K7M9Q4R6T8V0X2Z4B6", "device-key"),
                Box::new(backend("managed")),
                PinSetting::Local(pin_source),
                RootCertStore::empty(),
                cancel.clone(),
            )
            .unwrap();

            let mut state = handle.watch();
            let state = state
                .wait_for(|state| !matches!(state, IdentityState::Starting))
                .await
                .unwrap()
                .clone();
            let IdentityState::Ready(identity) = state else {
                panic!("expected ready, got {state:?}");
            };
            // Proof of possession passed with a signature from SoftHSM2.
            assert_eq!(identity.cert.fingerprint, fingerprint);
            assert_eq!(identity.token.label, "managed");
            assert!(identity.warnings.is_empty(), "{:?}", identity.warnings);

            cancel.cancel();
            assert_eq!(task.await.unwrap(), ManagerExit::Cancelled);
        });
    }
    /// A console that answers yes/no questions from a list and captures output.
    #[derive(Default)]
    struct TestConsole {
        answers: Vec<bool>,
        stdout: Vec<u8>,
        stderr: Vec<u8>,
    }

    impl helios::cli::Console for TestConsole {
        fn read_secret(&mut self, _: &str) -> std::io::Result<SecretString> {
            Err(std::io::Error::other("tests use --pin-file"))
        }
        fn confirm(&mut self, _: &str) -> std::io::Result<bool> {
            Ok(self.answers.pop().unwrap_or(false))
        }
        fn out(&mut self) -> &mut dyn std::io::Write {
            &mut self.stdout
        }
        fn err(&mut self) -> &mut dyn std::io::Write {
            &mut self.stderr
        }
    }

    impl TestConsole {
        fn stdout(&self) -> String {
            String::from_utf8_lossy(&self.stdout).into_owned()
        }
        fn stderr(&self) -> String {
            String::from_utf8_lossy(&self.stderr).into_owned()
        }
    }

    /// A private PIN file in `directory`.
    fn pin_file(directory: &std::path::Path) -> std::path::PathBuf {
        use std::os::unix::fs::PermissionsExt;
        let path = directory.join("pin");
        std::fs::write(&path, format!("{USER_PIN}\n")).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
        path
    }

    /// Runs `helios provision --token-label <token> --pin-file <pin> <args>`.
    fn provision(
        token: &str,
        pin: &std::path::Path,
        args: &[&str],
        console: &mut TestConsole,
    ) -> u8 {
        let module = module_path();
        let mut all = vec![
            "helios".to_owned(),
            "provision".to_owned(),
            "--module".to_owned(),
            module.display().to_string(),
            "--token-label".to_owned(),
            token.to_owned(),
            "--pin-file".to_owned(),
            pin.display().to_string(),
        ];
        all.extend(args.iter().map(|arg| (*arg).to_owned()));
        helios::cli::run(all.into_iter().map(std::ffi::OsString::from), console)
    }

    fn attribute_flags(session: &Session, handle: ObjectHandle) -> Vec<Attribute> {
        session
            .get_attributes(
                handle,
                &[
                    AttributeType::Token,
                    AttributeType::Private,
                    AttributeType::Sensitive,
                    AttributeType::Extractable,
                    AttributeType::Sign,
                    AttributeType::Verify,
                    AttributeType::Decrypt,
                    AttributeType::Derive,
                    AttributeType::Unwrap,
                    AttributeType::Encrypt,
                    AttributeType::Wrap,
                ],
            )
            .unwrap()
    }

    #[test]
    #[ignore = "run by softhsm_suite"]
    fn provisions_a_challenge_key_from_the_template() {
        use ::cryptoki::object::ObjectClass;

        if !in_suite() {
            return;
        }
        provisioned_token("provision");
        let directory = tempfile::tempdir().unwrap();
        let pin = pin_file(directory.path());
        let out = directory.path().join("challenge-key.pub.pem");
        let mut console = TestConsole::default();

        let code = provision(
            "provision",
            &pin,
            &["challenge-key", "--out", out.to_str().unwrap()],
            &mut console,
        );

        assert_eq!(code, 0, "{}", console.stderr());
        let pem = std::fs::read_to_string(&out).unwrap();
        let spki = VerifyingKey::from_public_key_der(
            &rustls_pki_types::SubjectPublicKeyInfoDer::from_pem_slice(pem.as_bytes()).unwrap(),
        )
        .unwrap();
        let fingerprint = helios::provision::hex(&<sha2::Sha256 as sha2::Digest>::digest(
            spki.to_public_key_der().unwrap().as_bytes(),
        ));
        assert!(
            console.stdout().contains(&fingerprint),
            "{}",
            console.stdout()
        );

        // The template from LLD 1, section 4.10.
        let pkcs11 = pkcs11();
        let session = user_session(&pkcs11, "provision");
        let find = |class| {
            let handles = session
                .find_objects(&[
                    Attribute::Class(class),
                    Attribute::Label(b"challenge-key".to_vec()),
                    Attribute::Id(vec![2]),
                ])
                .unwrap();
            assert_eq!(handles.len(), 1);
            handles[0]
        };
        let private = attribute_flags(&session, find(ObjectClass::PRIVATE_KEY));
        for expected in [
            Attribute::Token(true),
            Attribute::Private(false),
            Attribute::Sensitive(true),
            Attribute::Extractable(false),
            Attribute::Sign(true),
            Attribute::Decrypt(false),
            Attribute::Derive(false),
            Attribute::Unwrap(false),
        ] {
            assert!(
                private.contains(&expected),
                "private key: {expected:?} in {private:?}"
            );
        }
        let public = attribute_flags(&session, find(ObjectClass::PUBLIC_KEY));
        for expected in [
            Attribute::Token(true),
            Attribute::Private(false),
            Attribute::Verify(true),
            Attribute::Encrypt(false),
            Attribute::Wrap(false),
        ] {
            assert!(
                public.contains(&expected),
                "public key: {expected:?} in {public:?}"
            );
        }
        // Close this session and the module before the backend loads it again.
        drop(session);
        drop(pkcs11);

        // It signs without logging in, and the exported key verifies the signature.
        let mut token = backend("provision");
        token.open().unwrap();
        let raw = token.sign_without_login("challenge-key", &[9; 32]).unwrap();
        let signature = Signature::from_slice(&raw).unwrap();
        assert!(spki.verify_prehash(&[9; 32], &signature).is_ok());
    }

    #[test]
    #[ignore = "run by softhsm_suite"]
    fn refuses_labels_and_ids_in_use_and_replaces_on_request() {
        if !in_suite() {
            return;
        }
        provisioned_token("replace");
        let directory = tempfile::tempdir().unwrap();
        let pin = pin_file(directory.path());
        let out = directory.path().join("key.pem");
        let out = out.to_str().unwrap();

        // CKA_ID 01 is the device key's.
        let mut console = TestConsole::default();
        assert_eq!(
            provision(
                "replace",
                &pin,
                &["challenge-key", "--id", "01", "--out", out],
                &mut console
            ),
            1
        );
        assert!(
            console
                .stderr()
                .contains("private key \"device-key\" (CKA_ID 01, private)"),
            "{}",
            console.stderr()
        );

        let mut console = TestConsole::default();
        assert_eq!(
            provision(
                "replace",
                &pin,
                &["challenge-key", "--out", out],
                &mut console
            ),
            0
        );
        let first = std::fs::read_to_string(out).unwrap();

        // Again: the label is taken, and so is the output file.
        let mut console = TestConsole::default();
        assert_eq!(
            provision(
                "replace",
                &pin,
                &["challenge-key", "--out", out],
                &mut console
            ),
            1
        );
        assert!(
            console.stderr().contains("use --replace"),
            "{}",
            console.stderr()
        );
        let other = directory.path().join("other.pem");
        let mut console = TestConsole::default();
        assert_eq!(
            provision(
                "replace",
                &pin,
                &["challenge-key", "--out", other.to_str().unwrap()],
                &mut console
            ),
            1
        );
        assert!(
            console.stderr().contains("already has"),
            "{}",
            console.stderr()
        );

        // --replace asks first. "No" leaves it alone.
        let mut console = TestConsole::default();
        assert_eq!(
            provision(
                "replace",
                &pin,
                &["challenge-key", "--replace", "--out", out],
                &mut console
            ),
            1
        );
        assert!(console.stderr().contains("not replaced"));
        assert_eq!(std::fs::read_to_string(out).unwrap(), first);

        let mut console = TestConsole {
            answers: vec![true],
            ..TestConsole::default()
        };
        assert_eq!(
            provision(
                "replace",
                &pin,
                &["challenge-key", "--replace", "--out", out],
                &mut console
            ),
            0,
            "{}",
            console.stderr()
        );
        assert!(
            console.stdout().contains("deleted 2 objects"),
            "{}",
            console.stdout()
        );
        let second = std::fs::read_to_string(out).unwrap();
        assert_ne!(second, first);

        let mut console = TestConsole::default();
        assert_eq!(
            provision(
                "replace",
                &pin,
                &["challenge-key", "--replace", "--yes", "--out", out],
                &mut console
            ),
            0
        );
        assert_ne!(std::fs::read_to_string(out).unwrap(), second);
    }

    #[test]
    #[ignore = "run by softhsm_suite"]
    fn shows_the_token_without_secrets() {
        if !in_suite() {
            return;
        }
        let cert = provisioned_token("show");
        generate_key("show", "challenge-key", 2, false);
        let directory = tempfile::tempdir().unwrap();
        let pin = pin_file(directory.path());
        let mut console = TestConsole::default();

        assert_eq!(
            provision("show", &pin, &["show"], &mut console),
            0,
            "{}",
            console.stderr()
        );

        let output = console.stdout();
        let fingerprint = DeviceCertificate::from_der(&cert)
            .unwrap()
            .fingerprint_hex();
        for expected in [
            "token \"show\"",
            "private key \"device-key\" (CKA_ID 01, private)",
            "private key \"challenge-key\" (CKA_ID 02, public)",
            "certificate \"device-key\" (CKA_ID 01): subject CN t-01JD5VY2K7M9Q4R6T8V0X2Z4B6",
            fingerprint.as_str(),
        ] {
            assert!(
                output.contains(expected),
                "{expected:?} missing from:\n{output}"
            );
        }
        assert!(!output.contains(USER_PIN));
    }

    #[test]
    #[ignore = "run by softhsm_suite"]
    fn a_wrong_pin_or_missing_token_is_a_configuration_error() {
        use std::os::unix::fs::PermissionsExt;

        if !in_suite() {
            return;
        }
        provisioned_token("bad-pin");
        let directory = tempfile::tempdir().unwrap();
        let wrong = directory.path().join("wrong");
        std::fs::write(&wrong, "000000").unwrap();
        std::fs::set_permissions(&wrong, std::fs::Permissions::from_mode(0o600)).unwrap();

        let mut console = TestConsole::default();
        assert_eq!(provision("bad-pin", &wrong, &["show"], &mut console), 78);
        assert!(
            console.stderr().contains("PIN is incorrect"),
            "{}",
            console.stderr()
        );
        let mut console = TestConsole::default();
        assert_eq!(
            provision("no-such-token", &wrong, &["show"], &mut console),
            78
        );
    }

    #[test]
    #[ignore = "run by softhsm_suite"]
    fn the_binary_runs_provision_commands() {
        if !in_suite() {
            return;
        }
        provisioned_token("binary");
        let directory = tempfile::tempdir().unwrap();
        let pin = pin_file(directory.path());

        let output = std::process::Command::new(env!("CARGO_BIN_EXE_helios"))
            .args(["provision", "--module"])
            .arg(module_path())
            .args(["--token-label", "binary", "--pin-file"])
            .arg(&pin)
            .arg("show")
            .output()
            .unwrap();

        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(String::from_utf8_lossy(&output.stdout).contains("device-key"));
        // Without --pin-file and without a terminal, it can't ask for the PIN.
        let output = std::process::Command::new(env!("CARGO_BIN_EXE_helios"))
            .args(["provision", "--module"])
            .arg(module_path())
            .args(["--token-label", "binary", "show"])
            .stdin(std::process::Stdio::null())
            .output()
            .unwrap();
        assert_eq!(output.status.code(), Some(78));
        assert!(String::from_utf8_lossy(&output.stderr).contains("--pin-file"));
    }
    #[test]
    #[ignore = "run by softhsm_suite"]
    fn verify_reports_the_identity_and_the_challenge_key() {
        if !in_suite() {
            return;
        }
        let cert = provisioned_token("verify");
        let challenge = generate_key("verify", "challenge-key", 2, false);
        let directory = tempfile::tempdir().unwrap();
        let pin = pin_file(directory.path());
        let mut console = TestConsole::default();

        let code = provision(
            "verify",
            &pin,
            &[
                "verify",
                "--thing-name",
                "t-01JD5VY2K7M9Q4R6T8V0X2Z4B6",
                "--timeout",
                "10",
            ],
            &mut console,
        );

        assert_eq!(code, 0, "{}", console.stderr());
        let output = console.stdout();
        let challenge_fingerprint =
            helios::provision::hex(&<sha2::Sha256 as sha2::Digest>::digest(&challenge));
        let cert_fingerprint = DeviceCertificate::from_der(&cert)
            .unwrap()
            .fingerprint_hex();
        for expected in [
            format!(
                "challenge key \"challenge-key\": signs without login (public key SHA-256 {challenge_fingerprint})"
            ),
            "identity: ready".to_owned(),
            "thing name: t-01JD5VY2K7M9Q4R6T8V0X2Z4B6".to_owned(),
            cert_fingerprint,
            "proof of possession".to_owned(),
        ] {
            assert!(
                output.contains(&expected),
                "{expected:?} missing from:\n{output}"
            );
        }
        assert!(!output.contains(USER_PIN));
    }

    #[test]
    #[ignore = "run by softhsm_suite"]
    fn verify_reports_problems() {
        use std::os::unix::fs::PermissionsExt;

        if !in_suite() {
            return;
        }
        provisioned_token("verify-bad");
        let directory = tempfile::tempdir().unwrap();
        let pin = pin_file(directory.path());

        // No challenge key: reported, but not an error.
        let mut console = TestConsole::default();
        let args = ["verify", "--thing-name", "t-01JD5VY2K7M9Q4R6T8V0X2Z4B6"];
        assert_eq!(
            provision("verify-bad", &pin, &args, &mut console),
            0,
            "{}",
            console.stderr()
        );
        assert!(
            console.stdout().contains("not on the token (optional"),
            "{}",
            console.stdout()
        );

        // A wrong PIN is fatal, as at startup.
        let wrong = directory.path().join("wrong");
        std::fs::write(&wrong, "000000").unwrap();
        std::fs::set_permissions(&wrong, std::fs::Permissions::from_mode(0o600)).unwrap();
        let mut console = TestConsole::default();
        assert_eq!(provision("verify-bad", &wrong, &args, &mut console), 78);
        assert!(
            console
                .stderr()
                .contains("identity: token PIN is incorrect"),
            "{}",
            console.stderr()
        );

        // With bootstrap, a configured interface that doesn't exist is fatal before any lookup.
        let ca = directory.path().join("ca.pem");
        let ca_key = KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).unwrap();
        let mut ca_params = CertificateParams::default();
        ca_params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        std::fs::write(&ca, ca_params.self_signed(&ca_key).unwrap().pem()).unwrap();
        let mut console = TestConsole::default();
        let bootstrap = [
            "verify",
            "--bootstrap",
            "--bootstrap-url",
            "https://localhost:1/v1",
            "--bootstrap-ca",
            ca.to_str().unwrap(),
            "--interfaces",
            "helios-none0",
            "--timeout",
            "5",
        ];
        assert_eq!(provision("verify-bad", &pin, &bootstrap, &mut console), 78);
        assert!(
            console
                .stderr()
                .contains("network interface \"helios-none0\" does not exist"),
            "{}",
            console.stderr()
        );

        // Without bootstrap, the thing name has to be given.
        let mut console = TestConsole::default();
        assert_eq!(provision("verify-bad", &pin, &["verify"], &mut console), 78);
        assert!(
            console.stderr().contains("--thing-name is required"),
            "{}",
            console.stderr()
        );
    }
}
