//! Answering a bootstrap challenge with the PIN-less challenge key (LLD 1, section 4.8;
//! Bootstrap API, section 3.2).
//!
//! The signed message is the UTF-8 bytes of `"helios-bootstrap-v1\n" + challengeId + "\n" +
//! nonce (base64, exactly as received) + "\n" + the request's MACs sorted ascending and joined
//! with ","`, hashed with SHA-256 and signed with ECDSA P-256. The signature is sent as base64
//! DER.

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as BASE64;
use sha2::{Digest as _, Sha256};

use crate::identity::bootstrap::adapters::Adapter;
use crate::identity::der;
use crate::identity::token::{Digest, TokenBackend, TokenError};

/// The prefix that keeps a challenge signature from being reused for anything else.
pub const MESSAGE_PREFIX: &str = "helios-bootstrap-v1";

/// The message to sign for `challenge_id` and `nonce`, with the MACs of `adapters`.
#[must_use]
pub fn message(challenge_id: &str, nonce: &str, adapters: &[Adapter]) -> String {
    let mut macs: Vec<String> = adapters.iter().map(|a| a.mac.to_string()).collect();
    macs.sort();
    format!(
        "{MESSAGE_PREFIX}\n{challenge_id}\n{nonce}\n{}",
        macs.join(",")
    )
}

/// SHA-256 of the message.
#[must_use]
pub fn digest(message: &str) -> Digest {
    Sha256::digest(message.as_bytes()).into()
}

/// Signs `digest` with the challenge key labelled `key_label`, without logging in, and
/// returns the base64 DER signature. Opens the token first and closes it afterwards, so the
/// normal open with login starts from scratch. Runs on the signer thread.
///
/// # Errors
///
/// The token's error, such as [`TokenError::KeyNotFound`] if there is no PIN-less key with
/// that label, or [`TokenError::Unsupported`] if the signature isn't a valid P-256 signature.
pub fn sign(
    backend: &mut dyn TokenBackend,
    key_label: &str,
    digest: &Digest,
) -> Result<String, TokenError> {
    let result = backend
        .open()
        .and_then(|_| backend.sign_without_login(key_label, digest));
    backend.close();
    let der = der::raw_to_der(&result?)
        .map_err(|error| TokenError::Unsupported(format!("challenge signature: {error}")))?;
    Ok(BASE64.encode(der))
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use p256::ecdsa::signature::hazmat::PrehashVerifier;
    use p256::ecdsa::{Signature, SigningKey, VerifyingKey};
    use p256::pkcs8::{DecodePrivateKey, DecodePublicKey};
    use rustls_pki_types::pem::PemObject;
    use rustls_pki_types::{PrivatePkcs8KeyDer, SubjectPublicKeyInfoDer};
    use serde_json::Value;

    use super::*;
    use crate::identity::bootstrap::adapters::{AdapterKind, MacAddress};
    use crate::identity::mock::{MockKey, MockToken, Op};

    fn vectors() -> Value {
        let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("contract/test-vectors/challenge-v1.json");
        let text = std::fs::read_to_string(&path).unwrap_or_else(|e| {
            panic!(
                "{}: {e} (run `git submodule update --init`)",
                path.display()
            )
        });
        serde_json::from_str(&text).unwrap()
    }

    fn adapters(macs: &[Value]) -> Vec<Adapter> {
        macs.iter()
            .enumerate()
            .map(|(i, mac)| Adapter {
                interface_name: format!("eth{i}"),
                kind: AdapterKind::Ethernet,
                mac: mac.as_str().unwrap().parse::<MacAddress>().unwrap(),
            })
            .collect()
    }

    fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{b:02x}")).collect()
    }

    #[test]
    fn builds_the_messages_in_the_test_vectors() {
        let vectors = vectors();
        let challenge_id = vectors["challenge"]["challengeId"].as_str().unwrap();
        let public_key = VerifyingKey::from_public_key_der(
            &SubjectPublicKeyInfoDer::from_pem_slice(
                vectors["testKey"]["publicKeySpkiPem"]
                    .as_str()
                    .unwrap()
                    .as_bytes(),
            )
            .unwrap(),
        )
        .unwrap();
        let signature = Signature::from_der(
            &BASE64
                .decode(vectors["signature"]["derBase64"].as_str().unwrap())
                .unwrap(),
        )
        .unwrap();

        let cases = vectors["cases"].as_array().unwrap();
        assert_eq!(cases.len(), 3);
        for case in cases {
            let id = case["id"].as_str().unwrap();
            let message = message(
                challenge_id,
                case["nonce"].as_str().unwrap(),
                &adapters(case["macs"].as_array().unwrap()),
            );
            assert_eq!(message, case["message"].as_str().unwrap(), "{id}");
            let digest = digest(&message);
            assert_eq!(
                hex(&digest),
                case["messageSha256Hex"].as_str().unwrap(),
                "{id}"
            );
            assert_eq!(
                public_key.verify_prehash(&digest, &signature).is_ok(),
                case["signatureVerifies"].as_bool().unwrap(),
                "{id}"
            );
        }
    }

    #[test]
    fn signs_with_the_challenge_key_without_logging_in() {
        let vectors = vectors();
        let signing_key = SigningKey::from_pkcs8_der(
            PrivatePkcs8KeyDer::from_pem_slice(
                vectors["testKey"]["privateKeyPkcs8Pem"]
                    .as_str()
                    .unwrap()
                    .as_bytes(),
            )
            .unwrap()
            .secret_pkcs8_der(),
        )
        .unwrap();
        let token = MockToken::new("1234");
        token.add_key(MockKey {
            label: "challenge-key".into(),
            id: vec![2],
            signing_key: signing_key.clone(),
            private: false,
            certificate: None,
        });
        let valid = &vectors["cases"][0];
        let message = message(
            vectors["challenge"]["challengeId"].as_str().unwrap(),
            valid["nonce"].as_str().unwrap(),
            &adapters(valid["macs"].as_array().unwrap()),
        );
        let digest = digest(&message);

        let signature = sign(&mut token.clone(), "challenge-key", &digest).unwrap();

        let signature = Signature::from_der(&BASE64.decode(signature).unwrap()).unwrap();
        assert!(
            VerifyingKey::from(&signing_key)
                .verify_prehash(&digest, &signature)
                .is_ok()
        );
        assert_eq!(token.calls(), [Op::Open, Op::SignWithoutLogin]);
        assert!(!token.is_logged_in());
        assert!(!token.is_open(), "the token is closed again");
    }

    #[test]
    fn a_missing_key_or_token_fails_and_closes() {
        let token = MockToken::new("1234");
        token.add_key(MockKey {
            label: "device-key".into(),
            id: vec![1],
            signing_key: SigningKey::from_slice(&[3; 32]).unwrap(),
            private: true,
            certificate: None,
        });

        // Only private keys: the device key needs a login, so it isn't found.
        assert_eq!(
            sign(&mut token.clone(), "device-key", &[0; 32]),
            Err(TokenError::KeyNotFound {
                label: "device-key".into()
            })
        );
        assert!(!token.is_open());

        token.fail_next(
            Op::Open,
            TokenError::NotPresent {
                label: "helios".into(),
            },
        );
        assert_eq!(
            sign(&mut token.clone(), "challenge-key", &[0; 32]),
            Err(TokenError::NotPresent {
                label: "helios".into()
            })
        );
    }

    #[test]
    fn a_malformed_signature_is_unsupported() {
        let token = MockToken::new("1234");
        token.add_key(MockKey {
            label: "challenge-key".into(),
            id: vec![2],
            signing_key: SigningKey::from_slice(&[3; 32]).unwrap(),
            private: false,
            certificate: None,
        });
        // A zero r is not a valid signature, so it can't be DER-encoded.
        token.set_raw_signature_override(Some([0; 64]));

        let error = sign(&mut token.clone(), "challenge-key", &[0; 32]).unwrap_err();

        assert!(matches!(error, TokenError::Unsupported(_)), "{error:?}");
    }
}
