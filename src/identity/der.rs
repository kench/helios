//! Conversion of raw PKCS#11 ECDSA signatures to the DER form TLS needs (LLD 1, section 4.4).
//!
//! `CKM_ECDSA` returns a P-256 signature as raw `r || s`, 32 bytes each. TLS and X.509 carry
//! ECDSA signatures as a DER `SEQUENCE { r INTEGER, s INTEGER }`.

use p256::ecdsa::Signature;

/// Length of a raw P-256 ECDSA signature (`r || s`), as returned by `CKM_ECDSA`.
pub const RAW_SIGNATURE_LEN: usize = 64;

/// Why a raw signature could not be converted.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum DerError {
    /// The signature isn't 64 bytes long.
    #[error("raw ECDSA signature is {0} bytes, expected {RAW_SIGNATURE_LEN}")]
    InvalidLength(usize),
    /// `r` or `s` is zero or not below the P-256 group order.
    #[error("raw ECDSA signature has r or s out of range")]
    OutOfRange,
}

/// Parses a raw `r || s` P-256 signature.
///
/// # Errors
///
/// [`DerError::InvalidLength`] if `raw` isn't 64 bytes, and [`DerError::OutOfRange`] if `r` or
/// `s` isn't a valid scalar.
pub fn parse_raw(raw: &[u8]) -> Result<Signature, DerError> {
    if raw.len() != RAW_SIGNATURE_LEN {
        return Err(DerError::InvalidLength(raw.len()));
    }
    Signature::from_slice(raw).map_err(|_| DerError::OutOfRange)
}

/// Converts a raw `r || s` P-256 signature to DER.
///
/// # Errors
///
/// The same as [`parse_raw`].
pub fn raw_to_der(raw: &[u8]) -> Result<Vec<u8>, DerError> {
    Ok(parse_raw(raw)?.to_der().as_bytes().to_vec())
}

#[cfg(test)]
mod tests {
    use p256::ecdsa::signature::Signer;
    use p256::ecdsa::signature::Verifier;
    use p256::ecdsa::{SigningKey, VerifyingKey};

    use super::*;

    /// Builds a raw signature from `r` and `s`, each given as 32 big-endian bytes.
    fn raw(r: [u8; 32], s: [u8; 32]) -> [u8; RAW_SIGNATURE_LEN] {
        let mut out = [0u8; RAW_SIGNATURE_LEN];
        out[..32].copy_from_slice(&r);
        out[32..].copy_from_slice(&s);
        out
    }

    fn scalar(first: u8, last: u8) -> [u8; 32] {
        let mut v = [0x11u8; 32];
        v[0] = first;
        v[31] = last;
        v
    }

    #[test]
    fn high_bit_gets_a_leading_zero_byte() {
        // r starts with 0x80, so its DER INTEGER needs a 0x00 prefix to stay positive.
        let der = raw_to_der(&raw(scalar(0x80, 0x01), scalar(0x01, 0x02))).unwrap();

        // SEQUENCE, length, then INTEGER r with 33 content bytes.
        assert_eq!(der[0], 0x30);
        assert_eq!(&der[2..5], &[0x02, 33, 0x00]);
        assert_eq!(der[5], 0x80);
        // INTEGER s keeps its 32 bytes: its high bit is clear.
        assert_eq!(&der[37..39], &[0x02, 32]);
        assert_eq!(der.len(), 2 + 35 + 34);
        assert_eq!(usize::from(der[1]), der.len() - 2);
    }

    #[test]
    fn leading_zero_bytes_are_dropped() {
        let mut r = [0u8; 32];
        r[2] = 0x01;
        r[31] = 0x05;
        let der = raw_to_der(&raw(r, scalar(0x7f, 0x09))).unwrap();

        // r = 0x0100..05 is 30 bytes once its two leading zero bytes are removed.
        assert_eq!(&der[2..4], &[0x02, 30]);
        assert_eq!(der[4], 0x01);
        assert_eq!(&der[34..36], &[0x02, 32]);
        assert_eq!(der.len(), 2 + 32 + 34);
    }

    #[test]
    fn round_trips_with_p256() {
        let key = SigningKey::from_slice(&[0x42; 32]).unwrap();
        let verifying_key = VerifyingKey::from(&key);
        for message in [
            &b"helios"[..],
            b"",
            b"a longer message to sign with the test key",
        ] {
            let signature: Signature = key.sign(message);
            let raw: [u8; RAW_SIGNATURE_LEN] = signature.to_bytes().into();

            let der = raw_to_der(&raw).unwrap();

            assert_eq!(der, signature.to_der().as_bytes());
            let parsed = Signature::from_der(&der).unwrap();
            assert!(verifying_key.verify(message, &parsed).is_ok());
            assert_eq!(parse_raw(&raw).unwrap(), signature);
        }
    }

    #[test]
    fn rejects_wrong_lengths() {
        assert_eq!(raw_to_der(&[]), Err(DerError::InvalidLength(0)));
        assert_eq!(raw_to_der(&[1; 63]), Err(DerError::InvalidLength(63)));
        assert_eq!(raw_to_der(&[1; 72]), Err(DerError::InvalidLength(72)));
    }

    #[test]
    fn rejects_out_of_range_scalars() {
        // Zero is never a valid r or s.
        assert_eq!(
            raw_to_der(&raw([0; 32], scalar(0x01, 0x01))),
            Err(DerError::OutOfRange)
        );
        assert_eq!(
            raw_to_der(&raw(scalar(0x01, 0x01), [0; 32])),
            Err(DerError::OutOfRange)
        );
        // 0xff..ff is above the P-256 group order.
        assert_eq!(
            raw_to_der(&raw([0xff; 32], scalar(0x01, 0x01))),
            Err(DerError::OutOfRange)
        );
    }

    #[test]
    fn error_messages_name_the_problem() {
        assert_eq!(
            DerError::InvalidLength(10).to_string(),
            "raw ECDSA signature is 10 bytes, expected 64"
        );
        assert_eq!(
            DerError::OutOfRange.to_string(),
            "raw ECDSA signature has r or s out of range"
        );
    }
}
