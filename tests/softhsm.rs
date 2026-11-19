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
}
