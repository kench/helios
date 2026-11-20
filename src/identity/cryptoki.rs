//! [`TokenBackend`] over the `cryptoki` crate (LLD 1, section 4.2).
//!
//! Works with any PKCS#11 module: SoftHSM2 (P1) and `libykcs11` for the YubiKey (P2).

use std::path::{Path, PathBuf};

use ::cryptoki::context::{CInitializeArgs, Pkcs11};
use ::cryptoki::error::{Error as CryptokiError, RvError};
use ::cryptoki::mechanism::Mechanism;
use ::cryptoki::object::{Attribute, AttributeType, KeyType, ObjectClass, ObjectHandle};
use ::cryptoki::session::{Session, UserType};
use ::cryptoki::slot::Slot;
use secrecy::SecretString;

use crate::identity::token::{
    Digest, KeyHandle, KeyRef, PinStatus, RawSignature, TokenBackend, TokenError, TokenSummary,
    raw_signature,
};

/// A PKCS#11 token reached through a module such as `libsofthsm2.so`.
#[derive(Debug)]
pub struct CryptokiToken {
    module: PathBuf,
    token_label: String,
    generation: u64,
    open: Option<OpenToken>,
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
}

/// Maps a `cryptoki` error to a [`TokenError`], following the table in LLD 1, section 4.2.
fn map_error(error: CryptokiError) -> TokenError {
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
