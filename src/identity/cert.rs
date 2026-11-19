//! Device certificate checks, run on every successful token open (LLD 1, section 4.6).
//!
//! The certificate must hold an EC P-256 key, and the token must prove it holds the matching
//! private key. Its validity dates and subject CN are checked too. The SHA-256 fingerprint
//! identifies the certificate in logs and in the `helios` shadow.

use std::time::{Duration, SystemTime};

use p256::ecdsa::VerifyingKey;
use p256::ecdsa::signature::hazmat::PrehashVerifier;
use p256::pkcs8::DecodePublicKey;
use sha2::{Digest, Sha256};
use x509_parser::certificate::X509Certificate;
use x509_parser::time::ASN1Time;

use crate::identity::der;

/// How long before `not_after` a certificate counts as expiring soon.
pub const EXPIRY_WARNING: Duration = Duration::from_secs(30 * 24 * 60 * 60);

/// Why a certificate was rejected.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum CertError {
    /// The bytes aren't a DER-encoded X.509 certificate.
    #[error("certificate is not a valid DER X.509 certificate: {0}")]
    Parse(String),
    /// The certificate is followed by extra bytes.
    #[error("certificate is followed by {0} bytes of trailing data")]
    TrailingData(usize),
    /// The certificate's key isn't an EC P-256 key.
    #[error("certificate key is not an EC P-256 key")]
    UnsupportedKey,
    /// The token's signature doesn't verify with the certificate's key.
    #[error("the token key does not match the certificate")]
    KeyMismatch,
    /// The token returned a signature that isn't a valid raw P-256 signature.
    #[error("the token returned a malformed signature: {0}")]
    MalformedSignature(#[from] der::DerError),
}

/// Result of checking a certificate's validity dates against the system clock.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Validity {
    /// Within its validity period, with more than [`EXPIRY_WARNING`] left.
    Valid,
    /// Valid, but expires within [`EXPIRY_WARNING`]. The caller logs a warning.
    ExpiresSoon {
        /// Time left until `not_after`.
        remaining: Duration,
    },
    /// The clock is earlier than `not_before`.
    NotYetValid,
    /// The clock is later than `not_after`.
    Expired,
    /// The clock is earlier than the earliest trusted time (the build timestamp), so it
    /// probably hasn't been set yet. The dates aren't checked, and the caller only logs a
    /// warning.
    ClockUntrusted,
}

impl Validity {
    /// Whether the certificate may be used. `ClockUntrusted` counts as usable, because a
    /// wrong clock at boot must not keep the device offline.
    #[must_use]
    pub fn is_usable(self) -> bool {
        matches!(
            self,
            Self::Valid | Self::ExpiresSoon { .. } | Self::ClockUntrusted
        )
    }
}

/// A parsed device certificate with an EC P-256 key.
#[derive(Debug, Clone)]
pub struct DeviceCertificate {
    der: Vec<u8>,
    subject_cn: Option<String>,
    not_before: SystemTime,
    not_after: SystemTime,
    fingerprint: [u8; 32],
    public_key: VerifyingKey,
}

impl DeviceCertificate {
    /// Parses a DER-encoded certificate and checks that its key is EC P-256.
    ///
    /// # Errors
    ///
    /// [`CertError::Parse`] or [`CertError::TrailingData`] if `der` isn't exactly one DER
    /// certificate, and [`CertError::UnsupportedKey`] if its key isn't EC P-256.
    pub fn from_der(der: &[u8]) -> Result<Self, CertError> {
        let (rest, cert) = x509_parser::parse_x509_certificate(der)
            .map_err(|e| CertError::Parse(e.to_string()))?;
        if !rest.is_empty() {
            return Err(CertError::TrailingData(rest.len()));
        }
        let public_key = VerifyingKey::from_public_key_der(cert.public_key().raw)
            .map_err(|_| CertError::UnsupportedKey)?;
        Ok(Self {
            der: der.to_vec(),
            subject_cn: subject_cn(&cert),
            not_before: to_system_time(cert.validity().not_before),
            not_after: to_system_time(cert.validity().not_after),
            fingerprint: Sha256::digest(der).into(),
            public_key,
        })
    }

    /// The certificate in DER form.
    #[must_use]
    pub fn der(&self) -> &[u8] {
        &self.der
    }

    /// The first common name in the subject, if there is one.
    #[must_use]
    pub fn subject_cn(&self) -> Option<&str> {
        self.subject_cn.as_deref()
    }

    /// Start of the validity period.
    #[must_use]
    pub fn not_before(&self) -> SystemTime {
        self.not_before
    }

    /// End of the validity period.
    #[must_use]
    pub fn not_after(&self) -> SystemTime {
        self.not_after
    }

    /// SHA-256 of the DER certificate.
    #[must_use]
    pub fn fingerprint(&self) -> [u8; 32] {
        self.fingerprint
    }

    /// The SHA-256 fingerprint as lowercase hex.
    #[must_use]
    pub fn fingerprint_hex(&self) -> String {
        self.fingerprint
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect()
    }

    /// Proof of possession: checks that `raw_signature`, made by the token over `digest`,
    /// verifies with the certificate's public key.
    ///
    /// Use a fresh [`random_digest`] for each check. This catches a wrong certificate file or
    /// a re-provisioned token without relying on how a token stores its public-key objects.
    ///
    /// # Errors
    ///
    /// [`CertError::MalformedSignature`] if `raw_signature` isn't a valid raw P-256
    /// signature, and [`CertError::KeyMismatch`] if it doesn't verify.
    pub fn verify_possession(
        &self,
        digest: &[u8; 32],
        raw_signature: &[u8],
    ) -> Result<(), CertError> {
        let signature = der::parse_raw(raw_signature)?;
        self.public_key
            .verify_prehash(digest, &signature)
            .map_err(|_| CertError::KeyMismatch)
    }

    /// Checks the validity dates against `now`.
    ///
    /// `earliest_trusted` is the earliest time the clock can plausibly show, normally the
    /// build timestamp. Before that the clock is assumed to be unset.
    #[must_use]
    pub fn check_validity(&self, now: SystemTime, earliest_trusted: SystemTime) -> Validity {
        if now < earliest_trusted {
            return Validity::ClockUntrusted;
        }
        if now < self.not_before {
            return Validity::NotYetValid;
        }
        match self.not_after.duration_since(now) {
            Err(_) => Validity::Expired,
            Ok(remaining) if remaining <= EXPIRY_WARNING => Validity::ExpiresSoon { remaining },
            Ok(_) => Validity::Valid,
        }
    }

    /// Whether the subject CN equals `thing_name`. Provisioning sets the CN to the thing name,
    /// but AWS IoT doesn't require it, so a mismatch is only a warning.
    #[must_use]
    pub fn subject_cn_matches(&self, thing_name: &str) -> bool {
        self.subject_cn() == Some(thing_name)
    }
}

/// A random SHA-256-sized digest for [`DeviceCertificate::verify_possession`].
///
/// # Errors
///
/// Fails if the operating system's random number generator does.
pub fn random_digest() -> Result<[u8; 32], getrandom::Error> {
    let mut digest = [0u8; 32];
    getrandom::fill(&mut digest)?;
    Ok(digest)
}

fn subject_cn(cert: &X509Certificate<'_>) -> Option<String> {
    cert.subject()
        .iter_common_name()
        .next()
        .and_then(|cn| cn.as_str().ok())
        .map(str::to_owned)
}

fn to_system_time(time: ASN1Time) -> SystemTime {
    let seconds = time.timestamp();
    let magnitude = Duration::from_secs(seconds.unsigned_abs());
    if seconds >= 0 {
        SystemTime::UNIX_EPOCH + magnitude
    } else {
        SystemTime::UNIX_EPOCH - magnitude
    }
}

#[cfg(test)]
mod tests {
    use p256::ecdsa::signature::hazmat::PrehashSigner;
    use p256::ecdsa::{Signature, SigningKey};
    use p256::pkcs8::DecodePrivateKey;
    use rcgen::{CertificateParams, DistinguishedName, DnType, KeyPair, SignatureAlgorithm};

    use super::*;

    const DAY: Duration = Duration::from_secs(24 * 60 * 60);

    struct TestCert {
        der: Vec<u8>,
        key: SigningKey,
    }

    fn issue(alg: &'static SignatureAlgorithm, cn: Option<&str>) -> (Vec<u8>, KeyPair) {
        let key_pair = KeyPair::generate_for(alg).unwrap();
        let mut params = CertificateParams::default();
        let mut name = DistinguishedName::new();
        if let Some(cn) = cn {
            name.push(DnType::CommonName, cn);
        }
        name.push(DnType::OrganizationName, "Helios test");
        params.distinguished_name = name;
        params.not_before = rcgen::date_time_ymd(2026, 1, 1);
        params.not_after = rcgen::date_time_ymd(2027, 1, 1);
        let cert = params.self_signed(&key_pair).unwrap();
        (cert.der().to_vec(), key_pair)
    }

    fn p256_cert(cn: Option<&str>) -> TestCert {
        let (der, key_pair) = issue(&rcgen::PKCS_ECDSA_P256_SHA256, cn);
        let key = SigningKey::from_pkcs8_der(&key_pair.serialize_der()).unwrap();
        TestCert { der, key }
    }

    fn sign_raw(key: &SigningKey, digest: &[u8; 32]) -> [u8; 64] {
        let signature: Signature = key.sign_prehash(digest).unwrap();
        signature.to_bytes().into()
    }

    fn at(days: u32) -> SystemTime {
        // 2026-01-01T00:00:00Z plus the given number of days.
        SystemTime::UNIX_EPOCH + Duration::from_secs(1_767_225_600) + DAY * days
    }

    #[test]
    fn parses_a_p256_certificate() {
        let test = p256_cert(Some("t-01JD5VY2K7M9Q4R6T8V0X2Z4B6"));

        let cert = DeviceCertificate::from_der(&test.der).unwrap();

        assert_eq!(cert.der(), test.der.as_slice());
        assert_eq!(cert.subject_cn(), Some("t-01JD5VY2K7M9Q4R6T8V0X2Z4B6"));
        assert_eq!(cert.not_before(), at(0));
        assert_eq!(cert.not_after(), at(365));
        let expected: [u8; 32] = Sha256::digest(&test.der).into();
        assert_eq!(cert.fingerprint(), expected);
        assert_eq!(cert.fingerprint_hex().len(), 64);
        assert!(
            cert.fingerprint_hex()
                .chars()
                .all(|c| matches!(c, '0'..='9' | 'a'..='f'))
        );
    }

    #[test]
    fn subject_cn_is_optional() {
        let cert = DeviceCertificate::from_der(&p256_cert(None).der).unwrap();

        assert_eq!(cert.subject_cn(), None);
        assert!(!cert.subject_cn_matches("t-01JD5VY2K7M9Q4R6T8V0X2Z4B6"));
    }

    #[test]
    fn compares_subject_cn_with_thing_name() {
        let cert = DeviceCertificate::from_der(&p256_cert(Some("thing-a")).der).unwrap();

        assert!(cert.subject_cn_matches("thing-a"));
        assert!(!cert.subject_cn_matches("thing-b"));
        assert!(!cert.subject_cn_matches(""));
    }

    #[test]
    fn rejects_keys_other_than_p256() {
        let (der, _) = issue(&rcgen::PKCS_ECDSA_P384_SHA384, Some("thing"));

        assert_eq!(
            DeviceCertificate::from_der(&der).unwrap_err(),
            CertError::UnsupportedKey
        );
    }

    #[test]
    fn rejects_bytes_that_are_not_a_certificate() {
        let err = DeviceCertificate::from_der(b"not a certificate").unwrap_err();

        assert!(
            matches!(err, CertError::Parse(_)),
            "unexpected error: {err:?}"
        );
        assert!(
            err.to_string()
                .starts_with("certificate is not a valid DER X.509 certificate")
        );
    }

    #[test]
    fn rejects_trailing_data() {
        let mut der = p256_cert(Some("thing")).der;
        der.extend_from_slice(&[0, 1, 2]);

        assert_eq!(
            DeviceCertificate::from_der(&der).unwrap_err(),
            CertError::TrailingData(3)
        );
    }

    #[test]
    fn possession_succeeds_with_the_matching_key() {
        let test = p256_cert(Some("thing"));
        let cert = DeviceCertificate::from_der(&test.der).unwrap();
        let digest = random_digest().unwrap();

        assert_eq!(
            cert.verify_possession(&digest, &sign_raw(&test.key, &digest)),
            Ok(())
        );
    }

    #[test]
    fn possession_fails_with_another_key() {
        let cert = DeviceCertificate::from_der(&p256_cert(Some("thing")).der).unwrap();
        let other_key = p256_cert(Some("thing")).key;
        let digest = random_digest().unwrap();

        assert_eq!(
            cert.verify_possession(&digest, &sign_raw(&other_key, &digest)),
            Err(CertError::KeyMismatch)
        );
    }

    #[test]
    fn possession_fails_for_a_different_digest() {
        let test = p256_cert(Some("thing"));
        let cert = DeviceCertificate::from_der(&test.der).unwrap();
        let signature = sign_raw(&test.key, &[1; 32]);

        assert_eq!(
            cert.verify_possession(&[2; 32], &signature),
            Err(CertError::KeyMismatch)
        );
    }

    #[test]
    fn possession_reports_malformed_signatures() {
        let cert = DeviceCertificate::from_der(&p256_cert(Some("thing")).der).unwrap();

        let err = cert.verify_possession(&[1; 32], &[0; 10]).unwrap_err();

        assert_eq!(
            err,
            CertError::MalformedSignature(der::DerError::InvalidLength(10))
        );
        assert!(
            err.to_string()
                .starts_with("the token returned a malformed signature")
        );
    }

    #[test]
    fn random_digests_differ() {
        assert_ne!(random_digest().unwrap(), random_digest().unwrap());
    }

    #[test]
    fn validity_follows_the_dates() {
        let cert = DeviceCertificate::from_der(&p256_cert(Some("thing")).der).unwrap();
        let build_time = at(0) - DAY * 30;

        assert_eq!(cert.check_validity(at(10), build_time), Validity::Valid);
        assert_eq!(cert.check_validity(at(0), build_time), Validity::Valid);
        assert_eq!(
            cert.check_validity(at(0) - DAY, build_time),
            Validity::NotYetValid
        );
        assert_eq!(
            cert.check_validity(at(365) + DAY, build_time),
            Validity::Expired
        );
        assert_eq!(
            cert.check_validity(at(365) - DAY * 10, build_time),
            Validity::ExpiresSoon {
                remaining: DAY * 10
            }
        );
        assert_eq!(
            cert.check_validity(at(365) - EXPIRY_WARNING, build_time),
            Validity::ExpiresSoon {
                remaining: EXPIRY_WARNING
            }
        );
        assert_eq!(
            cert.check_validity(at(365), build_time),
            Validity::ExpiresSoon {
                remaining: Duration::ZERO
            }
        );
        assert_eq!(
            cert.check_validity(at(365) - EXPIRY_WARNING - DAY, build_time),
            Validity::Valid
        );
    }

    #[test]
    fn an_unset_clock_is_not_trusted() {
        let cert = DeviceCertificate::from_der(&p256_cert(Some("thing")).der).unwrap();
        // A device that booted without a real-time clock often starts at the epoch.
        let unset_clock = SystemTime::UNIX_EPOCH;

        assert_eq!(
            cert.check_validity(unset_clock, at(10)),
            Validity::ClockUntrusted
        );
        // A clock past the build time but before not_before is a real problem.
        assert_eq!(
            cert.check_validity(at(0) - DAY, at(0) - DAY * 2),
            Validity::NotYetValid
        );
    }

    #[test]
    fn only_some_results_are_usable() {
        assert!(Validity::Valid.is_usable());
        assert!(Validity::ExpiresSoon { remaining: DAY }.is_usable());
        assert!(Validity::ClockUntrusted.is_usable());
        assert!(!Validity::NotYetValid.is_usable());
        assert!(!Validity::Expired.is_usable());
    }

    #[test]
    fn converts_times_before_the_epoch() {
        let before = ASN1Time::from_timestamp(-86_400).unwrap();

        assert_eq!(to_system_time(before), SystemTime::UNIX_EPOCH - DAY);
    }

    #[test]
    fn error_messages_name_the_problem() {
        assert_eq!(
            CertError::TrailingData(3).to_string(),
            "certificate is followed by 3 bytes of trailing data"
        );
        assert_eq!(
            CertError::UnsupportedKey.to_string(),
            "certificate key is not an EC P-256 key"
        );
        assert_eq!(
            CertError::KeyMismatch.to_string(),
            "the token key does not match the certificate"
        );
    }
}
