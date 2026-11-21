//! Token provisioning for `helios provision` (LLD 1, section 4.10).
//!
//! Opens a read-write session on the token and works on its objects directly through
//! `cryptoki`: listing them, creating the PIN-less challenge key from the LLD's template, and
//! exporting its public key for registering with the bootstrap service.

pub mod verify;

use std::fmt;
use std::path::Path;

use ::cryptoki::context::{CInitializeArgs, Pkcs11};
use ::cryptoki::mechanism::Mechanism;
use ::cryptoki::object::{Attribute, AttributeType, ObjectClass, ObjectHandle};
use ::cryptoki::session::{Session, UserType};
use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as BASE64;
use p256::pkcs8::EncodePublicKey;
use secrecy::SecretString;
use sha2::{Digest as _, Sha256};

use crate::identity::cert::DeviceCertificate;
use crate::identity::cryptoki::map_error;
use crate::identity::token::{TokenError, TokenSummary};

/// The default PKCS#11 module, from Debian's `softhsm2` package.
pub const DEFAULT_MODULE: &str = "/usr/lib/softhsm/libsofthsm2.so";
/// The default token label (LLD 1, section 4.9).
pub const DEFAULT_TOKEN_LABEL: &str = "helios";
/// The default challenge key label.
pub const DEFAULT_CHALLENGE_LABEL: &str = "challenge-key";
/// The default challenge key `CKA_ID`.
pub const DEFAULT_CHALLENGE_ID: u8 = 0x02;

/// DER OID for prime256v1 (P-256), the `CKA_EC_PARAMS` value.
const P256_PARAMS: [u8; 10] = [0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07];

/// A provisioning step failed.
#[derive(Debug, thiserror::Error)]
pub enum ProvisionError {
    /// A token error, such as a wrong PIN or a missing token.
    #[error(transparent)]
    Token(#[from] TokenError),
    /// Objects already use the label or ID.
    #[error("the token already has {}: {}", if .0.len() == 1 { "an object with that label or ID" } else { "objects with that label or ID" }, list(.0))]
    Conflict(Vec<ObjectInfo>),
    /// The module returned something unexpected.
    #[error("unexpected token response: {0}")]
    Unexpected(String),
}

impl ProvisionError {
    /// Whether the error is a configuration problem (exit code 78): a missing module or token,
    /// or a PIN that can't be used.
    #[must_use]
    pub fn is_config(&self) -> bool {
        matches!(
            self,
            Self::Token(
                TokenError::ModuleLoad(_)
                    | TokenError::NotPresent { .. }
                    | TokenError::AmbiguousToken { .. }
                    | TokenError::PinIncorrect
                    | TokenError::PinLocked
                    | TokenError::PinInvalid
            )
        )
    }
}

fn list(objects: &[ObjectInfo]) -> String {
    objects
        .iter()
        .map(ToString::to_string)
        .collect::<Vec<_>>()
        .join("; ")
}

/// What kind of object it is.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ObjectKind {
    /// `CKO_PRIVATE_KEY`.
    PrivateKey,
    /// `CKO_PUBLIC_KEY`.
    PublicKey,
    /// `CKO_CERTIFICATE`.
    Certificate,
    /// Anything else.
    Other,
}

impl fmt::Display for ObjectKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::PrivateKey => "private key",
            Self::PublicKey => "public key",
            Self::Certificate => "certificate",
            Self::Other => "other object",
        })
    }
}

/// An object on the token. Holds no secrets.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ObjectInfo {
    /// The object's class.
    pub kind: ObjectKind,
    /// `CKA_LABEL`.
    pub label: String,
    /// `CKA_ID`.
    pub id: Vec<u8>,
    /// `CKA_PRIVATE`: whether it is only visible after login.
    pub private: bool,
}

impl fmt::Display for ObjectInfo {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{} {:?} (CKA_ID {}, {})",
            self.kind,
            self.label,
            hex(&self.id),
            if self.private { "private" } else { "public" }
        )
    }
}

/// A certificate on the token.
#[derive(Debug, Clone)]
pub struct CertificateInfo {
    /// The certificate object.
    pub object: ObjectInfo,
    /// The parsed certificate, or why it couldn't be parsed as a P-256 device certificate.
    pub certificate: Result<DeviceCertificate, String>,
}

/// A new challenge key's public half.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChallengePublicKey {
    /// The SubjectPublicKeyInfo, DER.
    pub spki_der: Vec<u8>,
}

impl ChallengePublicKey {
    /// The public key as a PEM `PUBLIC KEY` file, for the bootstrap service's
    /// `PutChallengeKey`.
    #[must_use]
    pub fn pem(&self) -> String {
        let encoded = BASE64.encode(&self.spki_der);
        let mut pem = String::from("-----BEGIN PUBLIC KEY-----\n");
        for line in encoded.as_bytes().chunks(64) {
            pem.push_str(&String::from_utf8_lossy(line));
            pem.push('\n');
        }
        pem.push_str("-----END PUBLIC KEY-----\n");
        pem
    }

    /// SHA-256 of the DER SubjectPublicKeyInfo, lowercase hex: the bootstrap service's
    /// `keyFingerprint`.
    #[must_use]
    pub fn fingerprint(&self) -> String {
        hex(&Sha256::digest(&self.spki_der))
    }
}

/// A read-write session on the token. The session is dropped before the module.
pub struct ProvisionToken {
    session: Session,
    summary: TokenSummary,
    _pkcs11: Pkcs11,
}

impl fmt::Debug for ProvisionToken {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ProvisionToken")
            .field("summary", &self.summary)
            .finish_non_exhaustive()
    }
}

impl ProvisionToken {
    /// Loads `module` and opens a read-write session on the token labelled `label`.
    ///
    /// # Errors
    ///
    /// [`ProvisionError::Token`] if the module can't be loaded, or no single token has the
    /// label.
    pub fn open(module: &Path, label: &str) -> Result<Self, ProvisionError> {
        let pkcs11 = Pkcs11::new(module).map_err(map_error)?;
        pkcs11
            .initialize(CInitializeArgs::OsThreads)
            .map_err(map_error)?;
        let mut matches = Vec::new();
        for slot in pkcs11.get_slots_with_token().map_err(map_error)? {
            let info = pkcs11.get_token_info(slot).map_err(map_error)?;
            if info.label().trim_end() == label {
                matches.push((slot, info));
            }
        }
        let (slot, info) = match matches.len() {
            0 => {
                return Err(TokenError::NotPresent {
                    label: label.to_owned(),
                }
                .into());
            }
            1 => matches.remove(0),
            count => {
                return Err(TokenError::AmbiguousToken {
                    label: label.to_owned(),
                    count,
                }
                .into());
            }
        };
        let session = pkcs11.open_rw_session(slot).map_err(map_error)?;
        Ok(Self {
            session,
            summary: TokenSummary {
                module: module.to_owned(),
                label: info.label().trim_end().to_owned(),
                manufacturer: info.manufacturer_id().trim_end().to_owned(),
                model: info.model().trim_end().to_owned(),
                serial: info.serial_number().trim_end().to_owned(),
            },
            _pkcs11: pkcs11,
        })
    }

    /// What was opened.
    #[must_use]
    pub fn summary(&self) -> &TokenSummary {
        &self.summary
    }

    /// Logs in as the user.
    ///
    /// # Errors
    ///
    /// [`TokenError::PinIncorrect`] and the other PIN errors.
    pub fn login(&self, pin: &SecretString) -> Result<(), ProvisionError> {
        self.session
            .login(UserType::User, Some(pin))
            .map_err(|error| map_error(error).into())
    }

    /// Every object visible in the session, sorted by ID, class and label.
    ///
    /// # Errors
    ///
    /// Token errors.
    pub fn objects(&self) -> Result<Vec<ObjectInfo>, ProvisionError> {
        let mut objects = self
            .handles(&[])?
            .into_iter()
            .map(|handle| self.describe(handle))
            .collect::<Result<Vec<_>, _>>()?;
        objects
            .sort_by(|a, b| (&a.id, a.kind as u8, &a.label).cmp(&(&b.id, b.kind as u8, &b.label)));
        Ok(objects)
    }

    /// The certificates on the token, parsed.
    ///
    /// # Errors
    ///
    /// Token errors.
    pub fn certificates(&self) -> Result<Vec<CertificateInfo>, ProvisionError> {
        let mut certificates = Vec::new();
        for handle in self.handles(&[Attribute::Class(ObjectClass::CERTIFICATE)])? {
            let object = self.describe(handle)?;
            let value = self
                .session
                .get_attributes(handle, &[AttributeType::Value])
                .map_err(map_error)?
                .into_iter()
                .find_map(|attribute| match attribute {
                    Attribute::Value(value) => Some(value),
                    _ => None,
                })
                .unwrap_or_default();
            certificates.push(CertificateInfo {
                object,
                certificate: DeviceCertificate::from_der(&value).map_err(|e| e.to_string()),
            });
        }
        certificates.sort_by(|a, b| a.object.id.cmp(&b.object.id));
        Ok(certificates)
    }

    /// Objects that use `label` or `id`.
    ///
    /// # Errors
    ///
    /// Token errors.
    pub fn conflicts(&self, label: &str, id: &[u8]) -> Result<Vec<ObjectInfo>, ProvisionError> {
        Ok(self
            .objects()?
            .into_iter()
            .filter(|object| object.label == label || object.id == id)
            .collect())
    }

    /// Deletes the challenge key pair: the private and public keys with both `label` and
    /// `id`. Returns how many objects were deleted.
    ///
    /// # Errors
    ///
    /// Token errors.
    pub fn delete_key_pair(&self, label: &str, id: &[u8]) -> Result<usize, ProvisionError> {
        let mut deleted = 0;
        for class in [ObjectClass::PRIVATE_KEY, ObjectClass::PUBLIC_KEY] {
            let template = [
                Attribute::Class(class),
                Attribute::Label(label.as_bytes().to_vec()),
                Attribute::Id(id.to_vec()),
            ];
            for handle in self.handles(&template)? {
                self.session.destroy_object(handle).map_err(map_error)?;
                deleted += 1;
            }
        }
        Ok(deleted)
    }

    /// Generates the challenge key pair from the template in LLD 1, section 4.10: a P-256 key
    /// on the token whose private half is `CKA_PRIVATE = false` (usable without login),
    /// sensitive, not extractable, and only for signing. Refuses if any object already uses
    /// `label` or `id`.
    ///
    /// # Errors
    ///
    /// [`ProvisionError::Conflict`] if the label or ID is taken, and token errors.
    pub fn generate_challenge_key(
        &self,
        label: &str,
        id: &[u8],
    ) -> Result<ChallengePublicKey, ProvisionError> {
        let conflicts = self.conflicts(label, id)?;
        if !conflicts.is_empty() {
            return Err(ProvisionError::Conflict(conflicts));
        }
        let label = Attribute::Label(label.as_bytes().to_vec());
        let id = Attribute::Id(id.to_vec());
        let public_template = [
            Attribute::Token(true),
            Attribute::Private(false),
            Attribute::EcParams(P256_PARAMS.to_vec()),
            Attribute::Verify(true),
            Attribute::Encrypt(false),
            Attribute::Wrap(false),
            Attribute::Derive(false),
            label.clone(),
            id.clone(),
        ];
        let private_template = [
            Attribute::Token(true),
            Attribute::Private(false),
            Attribute::Sensitive(true),
            Attribute::Extractable(false),
            Attribute::Sign(true),
            Attribute::Decrypt(false),
            Attribute::Derive(false),
            Attribute::Unwrap(false),
            label,
            id,
        ];
        let (public, _) = self
            .session
            .generate_key_pair(
                &Mechanism::EccKeyPairGen,
                &public_template,
                &private_template,
            )
            .map_err(map_error)?;
        self.public_key(public)
    }

    /// The public key labelled `label`, if there is exactly one. Public keys are visible
    /// without login.
    ///
    /// # Errors
    ///
    /// [`TokenError::Ambiguous`] if several public keys have the label, and token errors.
    pub fn public_key_by_label(
        &self,
        label: &str,
    ) -> Result<Option<ChallengePublicKey>, ProvisionError> {
        let handles = self.handles(&[
            Attribute::Class(ObjectClass::PUBLIC_KEY),
            Attribute::Label(label.as_bytes().to_vec()),
        ])?;
        match handles.as_slice() {
            [] => Ok(None),
            [handle] => self.public_key(*handle).map(Some),
            more => Err(TokenError::Ambiguous {
                what: format!("public keys with label {label:?}"),
                count: more.len(),
            }
            .into()),
        }
    }

    /// The SubjectPublicKeyInfo of an EC public key object, from `CKA_EC_POINT`.
    fn public_key(&self, handle: ObjectHandle) -> Result<ChallengePublicKey, ProvisionError> {
        let point = self
            .session
            .get_attributes(handle, &[AttributeType::EcPoint])
            .map_err(map_error)?
            .into_iter()
            .find_map(|attribute| match attribute {
                Attribute::EcPoint(point) => Some(point),
                _ => None,
            })
            .ok_or_else(|| ProvisionError::Unexpected("no CKA_EC_POINT".to_owned()))?;
        Ok(ChallengePublicKey {
            spki_der: spki_from_ec_point(&point)?,
        })
    }

    fn handles(&self, template: &[Attribute]) -> Result<Vec<ObjectHandle>, ProvisionError> {
        self.session
            .find_objects(template)
            .map_err(|error| map_error(error).into())
    }

    fn describe(&self, handle: ObjectHandle) -> Result<ObjectInfo, ProvisionError> {
        let attributes = self
            .session
            .get_attributes(
                handle,
                &[
                    AttributeType::Class,
                    AttributeType::Label,
                    AttributeType::Id,
                    AttributeType::Private,
                ],
            )
            .map_err(map_error)?;
        let mut info = ObjectInfo {
            kind: ObjectKind::Other,
            label: String::new(),
            id: Vec::new(),
            private: false,
        };
        for attribute in attributes {
            match attribute {
                Attribute::Class(class) => {
                    info.kind = match class {
                        ObjectClass::PRIVATE_KEY => ObjectKind::PrivateKey,
                        ObjectClass::PUBLIC_KEY => ObjectKind::PublicKey,
                        ObjectClass::CERTIFICATE => ObjectKind::Certificate,
                        _ => ObjectKind::Other,
                    }
                }
                Attribute::Label(label) => info.label = String::from_utf8_lossy(&label).into(),
                Attribute::Id(id) => info.id = id,
                Attribute::Private(private) => info.private = private,
                _ => {}
            }
        }
        Ok(info)
    }
}

/// `CKA_EC_POINT` is a DER OCTET STRING around the uncompressed point (`04 41 04 ...`). Some
/// modules return the bare point, which is accepted too.
fn spki_from_ec_point(point: &[u8]) -> Result<Vec<u8>, ProvisionError> {
    let sec1 = match point {
        [0x04, 0x41, rest @ ..] if rest.len() == 65 => rest,
        bare => bare,
    };
    let key = p256::PublicKey::from_sec1_bytes(sec1)
        .map_err(|_| ProvisionError::Unexpected("CKA_EC_POINT is not a P-256 point".to_owned()))?;
    let der = key
        .to_public_key_der()
        .map_err(|error| ProvisionError::Unexpected(error.to_string()))?;
    Ok(der.as_bytes().to_vec())
}

/// Lowercase hex.
#[must_use]
pub fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

#[cfg(test)]
mod tests {
    use p256::ecdsa::SigningKey;

    use super::*;

    fn point() -> Vec<u8> {
        let key = SigningKey::from_slice(&[5; 32]).unwrap();
        // Uncompressed: the public key's SEC1 bytes are 0x04 followed by x and y.
        let public = p256::PublicKey::from(key.verifying_key());
        let bytes = public.to_sec1_bytes().to_vec();
        assert_eq!((bytes.len(), bytes[0]), (65, 0x04));
        bytes
    }

    #[test]
    fn exports_the_public_key_from_cka_ec_point() {
        let bare = point();
        let mut wrapped = vec![0x04, 0x41];
        wrapped.extend_from_slice(&bare);

        let spki = spki_from_ec_point(&wrapped).unwrap();

        assert_eq!(spki, spki_from_ec_point(&bare).unwrap());
        let key = ChallengePublicKey { spki_der: spki };
        let pem = key.pem();
        assert!(pem.starts_with("-----BEGIN PUBLIC KEY-----\n"), "{pem}");
        assert!(pem.ends_with("\n-----END PUBLIC KEY-----\n"), "{pem}");
        assert!(pem.lines().all(|line| line.len() <= 64));
        assert_eq!(key.fingerprint().len(), 64);
        assert!(matches!(
            spki_from_ec_point(&[0x04, 0x01, 0x02]),
            Err(ProvisionError::Unexpected(_))
        ));
    }

    #[test]
    fn describes_objects_without_secrets() {
        let object = ObjectInfo {
            kind: ObjectKind::PrivateKey,
            label: "challenge-key".into(),
            id: vec![2],
            private: false,
        };
        assert_eq!(
            object.to_string(),
            "private key \"challenge-key\" (CKA_ID 02, public)"
        );
        let two = vec![
            object.clone(),
            ObjectInfo {
                kind: ObjectKind::Certificate,
                private: true,
                ..object.clone()
            },
        ];
        assert_eq!(
            ProvisionError::Conflict(vec![object]).to_string(),
            "the token already has an object with that label or ID: private key \
             \"challenge-key\" (CKA_ID 02, public)"
        );
        assert!(
            ProvisionError::Conflict(two)
                .to_string()
                .contains("objects with that label or ID: private key")
        );
        assert_eq!(ObjectKind::PublicKey.to_string(), "public key");
        assert_eq!(ObjectKind::Other.to_string(), "other object");
    }

    #[test]
    fn sorts_out_configuration_errors() {
        assert!(ProvisionError::from(TokenError::PinIncorrect).is_config());
        assert!(
            ProvisionError::from(TokenError::NotPresent {
                label: "helios".into()
            })
            .is_config()
        );
        assert!(!ProvisionError::Conflict(Vec::new()).is_config());
        assert!(!ProvisionError::from(TokenError::Other("x".into())).is_config());
    }

    #[test]
    fn a_missing_module_fails_to_open() {
        let error =
            ProvisionToken::open(Path::new("/nonexistent/libpkcs11.so"), "helios").unwrap_err();

        assert!(error.is_config(), "{error:?}");
    }
}
