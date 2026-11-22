//! Secrets sealed to the device (LLD 3, section 10.7): a value the cloud encrypts to the
//! device's `helios-secrets` key, so only this device can read it, and services in between
//! (AWS IoT Commands keeps a command's parameters) only ever hold ciphertext.
//!
//! The scheme is HPKE (RFC 9180) in base mode with DHKEM(P-256, HKDF-SHA256), HKDF-SHA256 and
//! AES-128-GCM. The key's private half stays in the PKCS#11 token: the token does the ECDH
//! (`CKM_ECDH1_DERIVE`), and this module does the rest of the KEM, the key schedule and the
//! AEAD in software. `info` binds a sealed value to the device (`helios secret v1 <thing>`), and
//! the AAD binds it to its purpose (for a Wi-Fi passphrase, `wifi.passphrase <ssid>`).

use std::fmt;

use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::{Aes128Gcm, Nonce};
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use hkdf::Hkdf;
use secrecy::zeroize::Zeroizing;
use serde::Deserialize;
use sha2::Sha256;

use crate::identity::signer::SignerClient;
use crate::identity::token::TokenError;

/// The token label of the key pair secrets are sealed to.
pub const SECRETS_KEY_LABEL: &str = "helios-secrets";
/// The suite's name in the `helios` shadow's `secrets_key`.
pub const SUITE: &str = "hpke-p256-sha256-aes128gcm";

/// DHKEM(P-256, HKDF-SHA256).
const KEM_ID: u16 = 0x0010;
/// HKDF-SHA256.
const KDF_ID: u16 = 0x0001;
/// AES-128-GCM.
const AEAD_ID: u16 = 0x0001;
/// An uncompressed P-256 point: `04 || x || y`.
pub const POINT_LEN: usize = 65;
const SECRET_LEN: usize = 32;
const KEY_LEN: usize = 16;
const NONCE_LEN: usize = 12;
/// Sealed values are small (a passphrase is at most 64 bytes).
const MAX_CIPHERTEXT: usize = 4096;

/// A value sealed to the device: the sender's encapsulated key and the ciphertext, both
/// base64url without padding, as they appear in a command's arguments.
#[derive(Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Sealed {
    /// The sender's ephemeral public key (`enc`), an uncompressed P-256 point.
    pub enc: String,
    /// AES-128-GCM ciphertext with its tag.
    pub ct: String,
}

impl fmt::Debug for Sealed {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Sealed(..)")
    }
}

/// Why a sealed value couldn't be opened. The message never includes the value.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum SecretError {
    /// The device has no secrets key (the token couldn't make one).
    #[error("the device has no key for sealed secrets")]
    NoKey,
    /// `enc` or `ct` isn't base64url, or `enc` isn't a P-256 point.
    #[error("the sealed value is malformed: {0}")]
    Malformed(&'static str),
    /// The ciphertext didn't authenticate: sealed for another key, device, purpose, or altered.
    #[error("the sealed value can't be opened with this device's key")]
    Unreadable,
    /// The token failed.
    #[error("the token couldn't open the sealed value: {0}")]
    Token(String),
}

impl SecretError {
    /// The command error code for it.
    #[must_use]
    pub fn code(&self) -> &'static str {
        "SECRET_UNREADABLE"
    }
}

impl From<TokenError> for SecretError {
    fn from(error: TokenError) -> Self {
        Self::Token(error.to_string())
    }
}

/// The device's secrets key: its public half, and the token that holds the private half.
#[derive(Clone)]
pub struct SecretsKey {
    public: [u8; POINT_LEN],
    signer: SignerClient,
}

impl fmt::Debug for SecretsKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SecretsKey")
            .field("public", &self.public_base64())
            .finish_non_exhaustive()
    }
}

impl SecretsKey {
    /// The key with public point `public`, held by `signer`'s token.
    #[must_use]
    pub fn new(public: [u8; POINT_LEN], signer: SignerClient) -> Self {
        Self { public, signer }
    }

    /// The public key as the shadow reports it: base64url of the uncompressed point.
    #[must_use]
    pub fn public_base64(&self) -> String {
        URL_SAFE_NO_PAD.encode(self.public)
    }

    /// Opens `sealed` for this device (`thing`) and purpose (`aad`).
    ///
    /// # Errors
    ///
    /// [`SecretError`] if it's malformed, doesn't open, or the token fails.
    pub async fn open(
        &self,
        thing: &str,
        aad: &[u8],
        sealed: &Sealed,
    ) -> Result<Zeroizing<Vec<u8>>, SecretError> {
        let (enc, ct) = decode(sealed)?;
        let peer = enc;
        let dh = self
            .signer
            .run(move |backend| backend.ecdh(SECRETS_KEY_LABEL, &peer))
            .await
            .map_err(|_| SecretError::Token("the token thread stopped".into()))??;
        open_with(&dh, &self.public, &enc, &info(thing), aad, &ct)
    }
}

/// `info` for a device: `helios secret v1 <thing>`.
#[must_use]
pub fn info(thing: &str) -> Vec<u8> {
    format!("helios secret v1 {thing}").into_bytes()
}

fn decode(sealed: &Sealed) -> Result<([u8; POINT_LEN], Vec<u8>), SecretError> {
    let enc = URL_SAFE_NO_PAD
        .decode(&sealed.enc)
        .map_err(|_| SecretError::Malformed("enc isn't base64url"))?;
    let enc: [u8; POINT_LEN] = enc
        .try_into()
        .map_err(|_| SecretError::Malformed("enc isn't an uncompressed P-256 point"))?;
    if enc[0] != 0x04 {
        return Err(SecretError::Malformed(
            "enc isn't an uncompressed P-256 point",
        ));
    }
    if sealed.ct.len() > MAX_CIPHERTEXT * 4 / 3 + 4 {
        return Err(SecretError::Malformed("ct is too long"));
    }
    let ct = URL_SAFE_NO_PAD
        .decode(&sealed.ct)
        .map_err(|_| SecretError::Malformed("ct isn't base64url"))?;
    Ok((enc, ct))
}

/// HPKE base-mode open, given the DH secret (the x-coordinate of `skR * enc`), the recipient's
/// public point, `enc`, `info`, the AAD and the ciphertext. Single-shot: sequence number 0.
pub(crate) fn open_with(
    dh: &[u8],
    public: &[u8; POINT_LEN],
    enc: &[u8; POINT_LEN],
    info: &[u8],
    aad: &[u8],
    ct: &[u8],
) -> Result<Zeroizing<Vec<u8>>, SecretError> {
    let (key, nonce) = key_schedule(dh, public, enc, info);
    let cipher = Aes128Gcm::new_from_slice(key.as_slice()).map_err(|_| SecretError::Unreadable)?;
    cipher
        .decrypt(&nonce_of(&nonce)?, Payload { msg: ct, aad })
        .map(Zeroizing::new)
        .map_err(|_| SecretError::Unreadable)
}

fn nonce_of(bytes: &[u8]) -> Result<Nonce<aes_gcm::aead::consts::U12>, SecretError> {
    Nonce::try_from(bytes).map_err(|_| SecretError::Unreadable)
}

/// The KEM's ExtractAndExpand, then the base-mode key schedule: the AEAD key and base nonce.
fn key_schedule(
    dh: &[u8],
    public: &[u8; POINT_LEN],
    enc: &[u8; POINT_LEN],
    info: &[u8],
) -> (Zeroizing<Vec<u8>>, Zeroizing<Vec<u8>>) {
    let kem_suite = [b"KEM".as_slice(), &KEM_ID.to_be_bytes()].concat();
    let mut kem_context = Vec::with_capacity(2 * POINT_LEN);
    kem_context.extend_from_slice(enc);
    kem_context.extend_from_slice(public);
    let eae_prk = labeled_extract(&kem_suite, b"", b"eae_prk", dh);
    let shared_secret = labeled_expand(
        &kem_suite,
        &eae_prk,
        b"shared_secret",
        &kem_context,
        SECRET_LEN,
    );

    let suite = [
        b"HPKE".as_slice(),
        &KEM_ID.to_be_bytes(),
        &KDF_ID.to_be_bytes(),
        &AEAD_ID.to_be_bytes(),
    ]
    .concat();
    let psk_id_hash = labeled_extract(&suite, b"", b"psk_id_hash", b"");
    let info_hash = labeled_extract(&suite, b"", b"info_hash", info);
    let mut context = vec![0u8]; // mode_base
    context.extend_from_slice(&psk_id_hash);
    context.extend_from_slice(&info_hash);
    let secret = labeled_extract(&suite, &shared_secret, b"secret", b"");
    let key = labeled_expand(&suite, &secret, b"key", &context, KEY_LEN);
    let nonce = labeled_expand(&suite, &secret, b"base_nonce", &context, NONCE_LEN);
    (key, nonce)
}

/// `LabeledExtract(salt, label, ikm)`: HKDF-Extract over `"HPKE-v1" || suite || label || ikm`.
fn labeled_extract(suite: &[u8], salt: &[u8], label: &[u8], ikm: &[u8]) -> Zeroizing<Vec<u8>> {
    let labeled = Zeroizing::new([b"HPKE-v1".as_slice(), suite, label, ikm].concat());
    let (prk, _) = Hkdf::<Sha256>::extract(Some(salt), &labeled);
    Zeroizing::new(prk.to_vec())
}

/// `LabeledExpand(prk, label, info, len)`.
fn labeled_expand(
    suite: &[u8],
    prk: &[u8],
    label: &[u8],
    info: &[u8],
    len: usize,
) -> Zeroizing<Vec<u8>> {
    let length = u16::try_from(len).unwrap_or(u16::MAX).to_be_bytes();
    let labeled = [length.as_slice(), b"HPKE-v1", suite, label, info].concat();
    let mut out = Zeroizing::new(vec![0u8; len]);
    // A PRK from extract is always long enough, and `len` is at most 32.
    if let Ok(hkdf) = Hkdf::<Sha256>::from_prk(prk) {
        let _ = hkdf.expand(&labeled, &mut out);
    }
    out
}

/// Seals `plaintext` to `public`, as the cloud does: for tests, and as the reference for
/// helios-cloud's implementation.
#[cfg(test)]
pub(crate) fn seal(
    public: &[u8; POINT_LEN],
    ephemeral: &p256::SecretKey,
    info: &[u8],
    aad: &[u8],
    plaintext: &[u8],
) -> ([u8; POINT_LEN], Vec<u8>) {
    use p256::elliptic_curve::sec1::ToSec1Point;
    let recipient = p256::PublicKey::from_sec1_bytes(public).unwrap();
    let enc: [u8; POINT_LEN] = ephemeral
        .public_key()
        .to_sec1_point(false)
        .as_bytes()
        .try_into()
        .unwrap();
    let dh = p256::ecdh::diffie_hellman(ephemeral.to_nonzero_scalar(), recipient.as_affine());
    let (key, nonce) = key_schedule(dh.raw_secret_bytes().as_slice(), public, &enc, info);
    let ct = Aes128Gcm::new_from_slice(&key)
        .unwrap()
        .encrypt(
            &nonce_of(&nonce).unwrap(),
            Payload {
                msg: plaintext,
                aad,
            },
        )
        .unwrap();
    (enc, ct)
}

#[cfg(test)]
mod tests;
