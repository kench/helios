//! `helios provision verify` (LLD 1, section 4.10): run the startup checks and report.
//!
//! The identity checks run through the real identity manager, so they are exactly what the
//! service does at startup: the bootstrap lookup if asked, then open, PIN flags, login, key and
//! certificate lookup, proof of possession and the certificate checks. The challenge key is
//! checked separately, by signing a random digest without logging in and verifying it against
//! the key's public half.

use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use p256::ecdsa::signature::hazmat::PrehashVerifier;
use p256::ecdsa::{Signature, VerifyingKey};
use p256::pkcs8::DecodePublicKey;
use rustls::RootCertStore;
use tokio_util::sync::CancellationToken;

use crate::identity::cert::random_digest;
use crate::identity::cryptoki::CryptokiToken;
use crate::identity::manager::{
    FatalReason, Identity, IdentityManager, IdentityState, ManagerConfig, PinSetting, StartError,
};
use crate::identity::token::{TokenBackend, TokenError};
use crate::provision::{ProvisionError, ProvisionToken};

/// How the identity checks ended.
#[derive(Debug)]
pub enum Verified {
    /// Every check passed.
    Ready(Arc<Identity>),
    /// A problem the service would stop for, with exit code 78.
    Fatal(FatalReason),
    /// Still not ready when the time ran out: the last state, such as bootstrapping or
    /// unavailable, with its reason.
    TimedOut(IdentityState),
}

/// Runs the identity manager's startup checks with `backend`, waiting up to `timeout`.
///
/// # Errors
///
/// [`StartError`] if the manager can't start.
pub async fn verify_identity(
    config: ManagerConfig,
    backend: Box<dyn TokenBackend>,
    pin: PinSetting,
    timeout: Duration,
) -> Result<Verified, StartError> {
    let cancel = CancellationToken::new();
    let (handle, task) =
        IdentityManager::start(config, backend, pin, RootCertStore::empty(), cancel.clone())?;
    let mut state = handle.watch();
    let finished = tokio::time::timeout(
        timeout,
        state.wait_for(|state| {
            matches!(state, IdentityState::Ready(_) | IdentityState::Fatal { .. })
        }),
    )
    .await;
    let verified = match finished {
        Ok(Ok(state)) => match &*state {
            IdentityState::Ready(identity) => Verified::Ready(identity.clone()),
            IdentityState::Fatal { reason } => Verified::Fatal(reason.clone()),
            _ => unreachable!("waited for ready or fatal"),
        },
        // The manager stopped without being ready or fatal: report where it got to.
        Ok(Err(_)) | Err(_) => Verified::TimedOut(handle.state()),
    };
    cancel.cancel();
    // The manager closes the token when it stops.
    let _ = task.await;
    Ok(verified)
}

/// A description of the identity for the report. Holds no secrets.
#[must_use]
pub fn describe(identity: &Identity) -> Vec<String> {
    let mut lines = vec![
        format!(
            "token {:?}: {} {} serial {}",
            identity.token.label,
            identity.token.manufacturer,
            identity.token.model,
            identity.token.serial
        ),
        format!("thing name: {}", identity.device.thing_name),
    ];
    if let Some(device_id) = &identity.device.device_id {
        lines.push(format!("device ID (bootstrap service): {device_id}"));
    }
    if let Some(aws) = &identity.device.aws {
        lines.push(format!(
            "AWS (bootstrap service): region {}, IoT endpoint {}, credentials endpoint {}, role \
             alias {}",
            aws.region, aws.iot_endpoint, aws.credentials_endpoint, aws.role_alias
        ));
    }
    lines.push(format!(
        "certificate: subject CN {}, not after {}, SHA-256 {}",
        identity.cert.subject_cn.as_deref().unwrap_or("(none)"),
        httpdate::fmt_http_date(identity.cert.not_after),
        identity.cert.fingerprint
    ));
    lines.push("proof of possession: the token's key matches the certificate".to_owned());
    for warning in &identity.warnings {
        lines.push(format!("warning: {warning}"));
    }
    lines
}

/// The result of checking the challenge key.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ChallengeCheck {
    /// It signed without login, and the signature verifies against its public key.
    Signed {
        /// SHA-256 of its SubjectPublicKeyInfo.
        fingerprint: String,
    },
    /// There is no public key with the label. The challenge key is optional.
    Missing,
}

/// Checks the challenge key labelled `label` on the token: signs a random digest without
/// logging in, and verifies the signature with the key's public half. Each step opens and
/// closes its own session, so nothing else may have the module open at the same time.
///
/// # Errors
///
/// [`ProvisionError`] if the token can't be used, the key can't sign without login, or the
/// signature doesn't verify.
pub fn check_challenge_key(
    module: &Path,
    token_label: &str,
    label: &str,
) -> Result<ChallengeCheck, ProvisionError> {
    let public = {
        let token = ProvisionToken::open(module, token_label)?;
        token.public_key_by_label(label)?
    };
    let Some(public) = public else {
        return Ok(ChallengeCheck::Missing);
    };
    let digest = random_digest().map_err(|error| ProvisionError::Unexpected(error.to_string()))?;
    let mut backend = CryptokiToken::new(module, token_label);
    let signed = backend
        .open()
        .and_then(|_| backend.sign_without_login(label, &digest));
    backend.close();
    let raw = signed?;
    let key = VerifyingKey::from_public_key_der(&public.spki_der)
        .map_err(|error| ProvisionError::Unexpected(error.to_string()))?;
    let signature = Signature::from_slice(&raw).map_err(|_| {
        ProvisionError::Token(TokenError::Unsupported("malformed signature".into()))
    })?;
    key.verify_prehash(&digest, &signature).map_err(|_| {
        ProvisionError::Unexpected(format!(
            "the challenge key {label:?} signed, but the signature doesn't verify with its public \
             key"
        ))
    })?;
    Ok(ChallengeCheck::Signed {
        fingerprint: public.fingerprint(),
    })
}

#[cfg(test)]
mod tests;
