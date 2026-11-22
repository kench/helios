//! [`TokenBackend`] over the `cryptoki` crate (LLD 1, section 4.2).
//!
//! Works with any PKCS#11 module: SoftHSM2 (P1) and `libykcs11` for the YubiKey (P2).

use std::path::{Path, PathBuf};

use ::cryptoki::context::{CInitializeArgs, Pkcs11};
use ::cryptoki::error::{Error as CryptokiError, RvError};
use ::cryptoki::mechanism::Mechanism;
use ::cryptoki::mechanism::elliptic_curve::{EcKdf, Ecdh1DeriveParams};
use ::cryptoki::object::{Attribute, AttributeType, KeyType, ObjectClass, ObjectHandle};
use ::cryptoki::session::{Session, UserType};
use ::cryptoki::slot::Slot;
use secrecy::SecretString;
use secrecy::zeroize::Zeroizing;

use crate::identity::token::{
    Digest, KeyHandle, KeyRef, PinStatus, RawSignature, TokenBackend, TokenError, TokenSummary,
    raw_signature,
};

/// Whether `module` has an initialized token labelled `label`, without opening a session or
/// logging in: what `helios token check` asks of a copy (LLD 1, section 4.12). SoftHSM shows a
/// token that fails its integrity check as an empty, uninitialized slot.
///
/// # Errors
///
/// [`TokenError`] if the module can't be loaded or initialized.
pub fn token_present(module: &Path, label: &str) -> Result<bool, TokenError> {
    let pkcs11 = Pkcs11::new(module).map_err(map_error)?;
    pkcs11
        .initialize(CInitializeArgs::OsThreads)
        .map_err(map_error)?;
    for slot in pkcs11.get_slots_with_token().map_err(map_error)? {
        let info = pkcs11.get_token_info(slot).map_err(map_error)?;
        if info.label().trim_end() == label && info.token_initialized() {
            return Ok(true);
        }
    }
    Ok(false)
}

/// A PKCS#11 token reached through a module such as `libsofthsm2.so`.
#[derive(Debug)]
pub struct CryptokiToken {
    module: PathBuf,
    token_label: String,
    generation: u64,
    open: Option<OpenToken>,
    /// With `identity.token_copy = "tmpfs"`: the working copy and the master to save it to after
    /// a deliberate change (LLD 1, section 4.12).
    persist: Option<(PathBuf, PathBuf)>,
}

/// State that exists only while the token is open. The session is dropped before the
/// context, so `C_CloseSession` runs before `C_Finalize`.
#[derive(Debug)]
struct OpenToken {
    session: Session,
    slot: Slot,
    keys: Vec<ObjectHandle>,
    pkcs11: Pkcs11,
}

impl CryptokiToken {
    /// A backend for the token with `token_label` in the module at `module`. Nothing is
    /// loaded until [`TokenBackend::open`].
    #[must_use]
    pub fn new(module: impl Into<PathBuf>, token_label: impl Into<String>) -> Self {
        Self {
            module: module.into(),
            token_label: token_label.into(),
            generation: 0,
            open: None,
            persist: None,
        }
    }

    /// Saves the working copy `working` to `master` after each deliberate change to the token
    /// (creating `helios-secrets`), as `identity.token_copy = "tmpfs"` needs.
    #[must_use]
    pub fn persist_to(mut self, working: PathBuf, master: PathBuf) -> Self {
        self.persist = Some((working, master));
        self
    }

    /// Saves the working copy, if this token is a tmpfs copy. A failure is logged: the change
    /// is in effect until Helios restarts, then lost (and made again).
    fn persist(&self) {
        let Some((working, master)) = &self.persist else {
            return;
        };
        match crate::identity::token_copy::save(working, master) {
            Ok(()) => tracing::info!(master = %master.display(), "token saved"),
            Err(error) => {
                tracing::warn!(%error, "can't save the token; the change is lost when Helios restarts");
            }
        }
    }

    /// The configured module path.
    #[must_use]
    pub fn module(&self) -> &Path {
        &self.module
    }

    fn token(&mut self) -> Result<&mut OpenToken, TokenError> {
        self.open.as_mut().ok_or(TokenError::NotOpen)
    }

    fn key_handle(&self, key: &KeyRef) -> Result<ObjectHandle, TokenError> {
        let open = self.open.as_ref().ok_or(TokenError::NotOpen)?;
        if key.handle.generation != self.generation {
            return Err(TokenError::NotOpen);
        }
        open.keys
            .get(key.handle.index)
            .copied()
            .ok_or(TokenError::NotOpen)
    }

    fn find_private_key(&mut self, label: &str) -> Result<KeyRef, TokenError> {
        let generation = self.generation;
        let token = self.token()?;
        let template = [
            Attribute::Class(ObjectClass::PRIVATE_KEY),
            Attribute::KeyType(KeyType::EC),
            Attribute::Label(label.as_bytes().to_vec()),
        ];
        let handles = token.session.find_objects(&template).map_err(map_error)?;
        let handle = match handles.as_slice() {
            [] => {
                return Err(TokenError::KeyNotFound {
                    label: label.to_owned(),
                });
            }
            [handle] => *handle,
            more => {
                return Err(TokenError::Ambiguous {
                    what: format!("private EC keys with label {label:?}"),
                    count: more.len(),
                });
            }
        };
        let id = token
            .session
            .get_attributes(handle, &[AttributeType::Id])
            .map_err(map_error)?
            .into_iter()
            .find_map(|attribute| match attribute {
                Attribute::Id(id) => Some(id),
                _ => None,
            })
            .unwrap_or_default();
        token.keys.push(handle);
        let index = token.keys.len() - 1;
        Ok(KeyRef {
            label: label.to_owned(),
            id,
            handle: KeyHandle { generation, index },
        })
    }

    /// The one object of `class` labelled `label`, if any.
    fn find_one(
        &mut self,
        class: ObjectClass,
        label: &str,
    ) -> Result<Option<ObjectHandle>, TokenError> {
        let template = [
            Attribute::Class(class),
            Attribute::KeyType(KeyType::EC),
            Attribute::Label(label.as_bytes().to_vec()),
        ];
        let handles = self
            .token()?
            .session
            .find_objects(&template)
            .map_err(map_error)?;
        match handles.as_slice() {
            [] => Ok(None),
            [handle] => Ok(Some(*handle)),
            more => Err(TokenError::Ambiguous {
                what: format!("EC keys of one class with label {label:?}"),
                count: more.len(),
            }),
        }
    }

    /// The public key's point, unwrapped from `CKA_EC_POINT`'s DER OCTET STRING.
    fn public_point(&mut self, handle: ObjectHandle) -> Result<Vec<u8>, TokenError> {
        let attributes = self
            .token()?
            .session
            .get_attributes(handle, &[AttributeType::EcPoint])
            .map_err(map_error)?;
        let der = attributes
            .into_iter()
            .find_map(|attribute| match attribute {
                Attribute::EcPoint(point) => Some(point),
                _ => None,
            })
            .ok_or_else(|| TokenError::Other("the secrets key has no CKA_EC_POINT".into()))?;
        ec_point(&der)
    }

    /// Generates the secrets key pair in a short read-write session (the identity session is
    /// read-only); the login carries over to it.
    fn generate_secrets_key(&mut self, label: &str) -> Result<(), TokenError> {
        let token = self.token()?;
        let session = token
            .pkcs11
            .open_rw_session(token.slot)
            .map_err(map_error)?;
        let label = label.as_bytes().to_vec();
        let id = b"helios-secrets".to_vec();
        let public = [
            Attribute::Token(true),
            Attribute::Label(label.clone()),
            Attribute::Id(id.clone()),
            Attribute::EcParams(P256_OID.to_vec()),
            Attribute::Derive(true),
            Attribute::Verify(false),
        ];
        let private = [
            Attribute::Token(true),
            Attribute::Label(label),
            Attribute::Id(id),
            Attribute::Private(true),
            Attribute::Sensitive(true),
            Attribute::Extractable(false),
            Attribute::Derive(true),
            Attribute::Sign(false),
            Attribute::Decrypt(false),
            Attribute::Unwrap(false),
        ];
        session
            .generate_key_pair(&Mechanism::EccKeyPairGen, &public, &private)
            .map_err(map_error)?;
        Ok(())
    }

    fn sign_with(&mut self, key: &KeyRef, digest: &Digest) -> Result<RawSignature, TokenError> {
        let handle = self.key_handle(key)?;
        let signature = self
            .token()?
            .session
            .sign(&Mechanism::Ecdsa, handle, digest)
            .map_err(map_error)?;
        raw_signature(&signature)
    }
}

impl TokenBackend for CryptokiToken {
    fn open(&mut self) -> Result<TokenSummary, TokenError> {
        self.close();
        let pkcs11 = Pkcs11::new(&self.module).map_err(map_error)?;
        pkcs11
            .initialize(CInitializeArgs::OsThreads)
            .map_err(map_error)?;

        let mut matches = Vec::new();
        for slot in pkcs11.get_slots_with_token().map_err(map_error)? {
            let info = pkcs11.get_token_info(slot).map_err(map_error)?;
            if info.label().trim_end() == self.token_label {
                matches.push((slot, info));
            }
        }
        let (slot, info) = match matches.len() {
            0 => {
                return Err(TokenError::NotPresent {
                    label: self.token_label.clone(),
                });
            }
            1 => matches.remove(0),
            count => {
                return Err(TokenError::AmbiguousToken {
                    label: self.token_label.clone(),
                    count,
                });
            }
        };

        let session = pkcs11.open_ro_session(slot).map_err(map_error)?;
        self.generation += 1;
        self.open = Some(OpenToken {
            session,
            slot,
            keys: Vec::new(),
            pkcs11,
        });
        Ok(TokenSummary {
            module: self.module.clone(),
            label: info.label().trim_end().to_owned(),
            manufacturer: info.manufacturer_id().trim_end().to_owned(),
            model: info.model().trim_end().to_owned(),
            serial: info.serial_number().trim_end().to_owned(),
        })
    }

    fn pin_status(&mut self) -> Result<PinStatus, TokenError> {
        let open = self.token()?;
        let token = open.pkcs11.get_token_info(open.slot).map_err(map_error)?;
        Ok(PinStatus {
            locked: token.user_pin_locked(),
            final_try: token.user_pin_final_try(),
            count_low: token.user_pin_count_low(),
        })
    }

    fn sign_without_login(
        &mut self,
        label: &str,
        digest: &Digest,
    ) -> Result<RawSignature, TokenError> {
        let key = self.find_private_key(label)?;
        self.sign_with(&key, digest)
    }

    fn login(&mut self, pin: &SecretString) -> Result<(), TokenError> {
        match self.token()?.session.login(UserType::User, Some(pin)) {
            Ok(()) | Err(CryptokiError::Pkcs11(RvError::UserAlreadyLoggedIn, _)) => Ok(()),
            Err(error) => Err(map_error(error)),
        }
    }

    fn find_key(&mut self, label: &str) -> Result<KeyRef, TokenError> {
        self.find_private_key(label)
    }

    fn read_certificate(&mut self, key: &KeyRef) -> Result<Option<Vec<u8>>, TokenError> {
        self.key_handle(key)?;
        let token = self.token()?;
        let template = [
            Attribute::Class(ObjectClass::CERTIFICATE),
            Attribute::Id(key.id.clone()),
        ];
        let handles = token.session.find_objects(&template).map_err(map_error)?;
        let handle = match handles.as_slice() {
            [] => return Ok(None),
            [handle] => *handle,
            more => {
                return Err(TokenError::Ambiguous {
                    what: format!("certificates with CKA_ID {}", hex(&key.id)),
                    count: more.len(),
                });
            }
        };
        let value = token
            .session
            .get_attributes(handle, &[AttributeType::Value])
            .map_err(map_error)?
            .into_iter()
            .find_map(|attribute| match attribute {
                Attribute::Value(value) => Some(value),
                _ => None,
            });
        Ok(value)
    }

    fn sign_digest(&mut self, key: &KeyRef, digest: &Digest) -> Result<RawSignature, TokenError> {
        self.sign_with(key, digest)
    }

    fn close(&mut self) {
        self.open = None;
    }

    fn set_token_label(&mut self, label: &str) {
        if self.token_label != label {
            self.close();
            label.clone_into(&mut self.token_label);
        }
    }

    fn secrets_key(&mut self, label: &str) -> Result<Vec<u8>, TokenError> {
        if self.find_one(ObjectClass::PRIVATE_KEY, label)?.is_none() {
            self.generate_secrets_key(label)?;
            self.persist();
        }
        let public = self
            .find_one(ObjectClass::PUBLIC_KEY, label)?
            .ok_or_else(|| TokenError::KeyNotFound {
                label: format!("{label} (public)"),
            })?;
        self.public_point(public)
    }

    fn ecdh(&mut self, label: &str, peer: &[u8]) -> Result<Zeroizing<Vec<u8>>, TokenError> {
        let private = self
            .find_one(ObjectClass::PRIVATE_KEY, label)?
            .ok_or_else(|| TokenError::KeyNotFound {
                label: label.to_owned(),
            })?;
        // The agreed x-coordinate as a session object Helios may read, then destroyed.
        let template = [
            Attribute::Class(ObjectClass::SECRET_KEY),
            Attribute::KeyType(KeyType::GENERIC_SECRET),
            Attribute::ValueLen(32.into()),
            Attribute::Token(false),
            Attribute::Sensitive(false),
            Attribute::Extractable(true),
        ];
        let session = &self.token()?.session;
        let mechanism = Mechanism::Ecdh1Derive(Ecdh1DeriveParams::new(EcKdf::null(), peer));
        let secret = session
            .derive_key(&mechanism, private, &template)
            .map_err(map_error)?;
        let value = session.get_attributes(secret, &[AttributeType::Value]);
        let _ = session.destroy_object(secret);
        value
            .map_err(map_error)?
            .into_iter()
            .find_map(|attribute| match attribute {
                Attribute::Value(value) => Some(Zeroizing::new(value)),
                _ => None,
            })
            .ok_or_else(|| TokenError::Other("the derived secret has no value".into()))
    }
}

/// DER of the prime256v1 (P-256) OID, for `CKA_EC_PARAMS`.
const P256_OID: [u8; 10] = [0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07];

/// The point inside `CKA_EC_POINT`: a DER OCTET STRING (`04 41 04 …` for P-256), or, from
/// some modules, the raw point.
fn ec_point(der: &[u8]) -> Result<Vec<u8>, TokenError> {
    let point = match der {
        [0x04, 0x41, rest @ ..] if rest.len() == 65 => rest,
        raw if raw.len() == 65 && raw[0] == 0x04 => raw,
        _ => {
            return Err(TokenError::Other(
                "the secrets key isn't an uncompressed P-256 point".into(),
            ));
        }
    };
    Ok(point.to_vec())
}

/// Maps a `cryptoki` error to a [`TokenError`], following the table in LLD 1, section 4.2.
pub(crate) fn map_error(error: CryptokiError) -> TokenError {
    match error {
        CryptokiError::Pkcs11(rv, function) => map_rv(rv, &format!("{function}: {rv}")),
        CryptokiError::LibraryLoading(error) => TokenError::ModuleLoad(error.to_string()),
        other => TokenError::Other(other.to_string()),
    }
}

fn map_rv(rv: RvError, detail: &str) -> TokenError {
    match rv {
        RvError::TokenNotPresent
        | RvError::DeviceRemoved
        | RvError::SessionHandleInvalid
        | RvError::SessionClosed
        | RvError::DeviceError
        | RvError::GeneralError => TokenError::TokenLost(detail.to_owned()),
        RvError::PinIncorrect => TokenError::PinIncorrect,
        RvError::PinLocked => TokenError::PinLocked,
        RvError::PinLenRange => TokenError::PinInvalid,
        RvError::MechanismInvalid | RvError::KeyTypeInconsistent => {
            TokenError::Unsupported(detail.to_owned())
        }
        _ => TokenError::Other(detail.to_owned()),
    }
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn maps_return_values_as_in_the_lld_table() {
        let lost = [
            RvError::TokenNotPresent,
            RvError::DeviceRemoved,
            RvError::SessionHandleInvalid,
            RvError::SessionClosed,
            RvError::DeviceError,
            RvError::GeneralError,
        ];
        for rv in lost {
            assert_eq!(
                map_rv(rv, "detail"),
                TokenError::TokenLost("detail".into()),
                "{rv:?}"
            );
        }
        assert_eq!(map_rv(RvError::PinIncorrect, "d"), TokenError::PinIncorrect);
        assert_eq!(map_rv(RvError::PinLocked, "d"), TokenError::PinLocked);
        assert_eq!(map_rv(RvError::PinLenRange, "d"), TokenError::PinInvalid);
        assert_eq!(
            map_rv(RvError::MechanismInvalid, "d"),
            TokenError::Unsupported("d".into())
        );
        assert_eq!(
            map_rv(RvError::KeyTypeInconsistent, "d"),
            TokenError::Unsupported("d".into())
        );
        assert_eq!(
            map_rv(RvError::FunctionFailed, "d"),
            TokenError::Other("d".into())
        );
    }

    #[test]
    fn maps_non_pkcs11_errors() {
        let message = CryptokiError::PinNotSet.to_string();

        assert_eq!(
            map_error(CryptokiError::PinNotSet),
            TokenError::Other(message)
        );
    }

    #[test]
    fn a_missing_module_fails_to_load() {
        let mut token = CryptokiToken::new("/nonexistent/libpkcs11-missing.so", "helios");

        let error = token.open().unwrap_err();

        assert!(
            matches!(error, TokenError::ModuleLoad(_)),
            "unexpected error: {error:?}"
        );
        assert!(error.is_fatal());
        assert_eq!(
            token.module(),
            Path::new("/nonexistent/libpkcs11-missing.so")
        );
    }

    #[test]
    fn methods_need_an_open_token() {
        let mut token = CryptokiToken::new("/nonexistent/libpkcs11-missing.so", "helios");
        let key = KeyRef {
            label: "device-key".into(),
            id: vec![1],
            handle: KeyHandle {
                generation: 0,
                index: 0,
            },
        };

        assert_eq!(token.pin_status(), Err(TokenError::NotOpen));
        assert_eq!(
            token.login(&SecretString::new("1234".into())),
            Err(TokenError::NotOpen)
        );
        assert_eq!(token.find_key("device-key"), Err(TokenError::NotOpen));
        assert_eq!(token.read_certificate(&key), Err(TokenError::NotOpen));
        assert_eq!(token.sign_digest(&key, &[0; 32]), Err(TokenError::NotOpen));
        assert_eq!(
            token.sign_without_login("challenge-key", &[0; 32]),
            Err(TokenError::NotOpen)
        );
        token.close();
    }

    #[test]
    fn changing_the_token_label_takes_effect_on_the_next_open() {
        let mut token = CryptokiToken::new("/nonexistent/libpkcs11-missing.so", "helios");

        token.set_token_label("helios");
        assert_eq!(token.token_label, "helios");
        token.set_token_label("other");
        assert_eq!(token.token_label, "other");
    }

    #[test]
    fn formats_ids_as_hex() {
        assert_eq!(hex(&[0x01, 0xab, 0x00]), "01ab00");
        assert_eq!(hex(&[]), "");
    }
}
