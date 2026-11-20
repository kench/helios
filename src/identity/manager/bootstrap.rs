//! Bootstrap in the identity manager (LLD 1, section 4.8): find the built-in adapters, look the
//! device up, answer a challenge if asked, merge the answer with local config, and keep the PIN
//! in memory for every login until Helios restarts.
//!
//! No bootstrap failure is fatal except a missing built-in adapter or a mismatch with local
//! config. A missing or disabled record often just means the device isn't registered yet.

use std::sync::Arc;
use std::time::Duration;

use crate::identity::bootstrap::adapters::{Adapter, find_adapters};
use crate::identity::bootstrap::api::{
    AnswerChallengeRequest, AwsSettings, BootstrapRequest, BootstrapResult, Capability,
    DeviceIdentity,
};
use crate::identity::bootstrap::challenge;
use crate::identity::bootstrap::client::{BootstrapError, Retry};
use crate::identity::pin::FixedPin;

use super::{
    Backoff, BootstrapSetup, DeviceInfo, FatalReason, IdentityState, Manager, ManagerExit,
};

/// Why a lookup didn't produce an identity.
enum LookupFailure {
    /// Retry as `retry` says.
    Retry { reason: String, retry: Retry },
    /// Stop the manager.
    Exit(ManagerExit),
}

impl From<BootstrapError> for LookupFailure {
    fn from(error: BootstrapError) -> Self {
        Self::Retry {
            retry: error.retry(),
            reason: error.to_string(),
        }
    }
}

impl Manager {
    /// Bootstraps, retrying until the service answers. Returns when the PIN and identity are in
    /// place, or with the reason to stop.
    pub(super) async fn bootstrap(&mut self, setup: BootstrapSetup) -> Result<(), ManagerExit> {
        if let Some(label) = self.config.token_label.clone() {
            self.signer
                .run(move |backend| backend.set_token_label(&label))
                .await
                .map_err(|_| ManagerExit::SignerStopped)?;
        }
        let adapters = find_adapters(
            &setup.sysfs,
            &setup.interfaces,
            setup.permanent_addresses.as_ref(),
        )
        .map_err(|error| ManagerExit::Fatal(FatalReason::Adapters(error.to_string())))?;
        for adapter in &adapters {
            tracing::info!(
                interface = %adapter.interface_name,
                kind = adapter.kind.as_str(),
                mac = %adapter.mac,
                "bootstrap adapter"
            );
        }

        let timing = setup.timing;
        let mut backoff = Backoff::new(timing.initial_backoff, timing.max_backoff);
        let mut attempts = 0;
        let mut last_error = None;
        let mut rejections = 0;
        let mut retried_now = false;
        loop {
            attempts += 1;
            self.state.send_replace(IdentityState::Bootstrapping {
                attempts,
                last_error: last_error.clone(),
            });
            let outcome = tokio::select! {
                () = self.cancel.cancelled() => return Err(ManagerExit::Cancelled),
                outcome = self.lookup(&setup, &adapters) => outcome,
            };
            let (reason, retry) = match outcome {
                Ok(identity) => return self.adopt(&setup, identity).await,
                Err(LookupFailure::Exit(exit)) => return Err(exit),
                Err(LookupFailure::Retry { reason, retry }) => (reason, retry),
            };
            if reason.contains("UnknownDevice") {
                let macs: Vec<String> = adapters.iter().map(|a| a.mac.to_string()).collect();
                tracing::warn!(macs = %macs.join(","), "device not registered with the bootstrap service");
            }
            tracing::warn!(%reason, attempts, "bootstrap failed; retrying");
            let delay = match retry {
                Retry::Now if !retried_now => Duration::ZERO,
                Retry::Now | Retry::Backoff => backoff.next_delay(),
                Retry::Slowly => timing.slow_retry,
                Retry::After(wait) => wait.max(backoff.next_delay()),
                Retry::ChallengeRejected => {
                    rejections += 1;
                    if rejections >= timing.rejections_before_slow {
                        timing.slow_retry
                    } else {
                        backoff.next_delay()
                    }
                }
            };
            retried_now = retry == Retry::Now && !retried_now;
            if retry != Retry::ChallengeRejected {
                rejections = 0;
            }
            last_error = Some(reason);
            self.state.send_replace(IdentityState::Bootstrapping {
                attempts,
                last_error: last_error.clone(),
            });
            tokio::select! {
                () = self.cancel.cancelled() => return Err(ManagerExit::Cancelled),
                () = tokio::time::sleep(delay) => {}
                () = self.poke.notified() => {}
            }
        }
    }

    /// One lookup, answering a challenge if the service sends one.
    async fn lookup(
        &self,
        setup: &BootstrapSetup,
        adapters: &[Adapter],
    ) -> Result<DeviceIdentity, LookupFailure> {
        let challenge_key = match &setup.challenge_key_label {
            Some(label) if self.has_challenge_key(label).await? => Some(label.clone()),
            _ => None,
        };
        let capabilities = challenge_key
            .iter()
            .map(|_| Capability::TokenChallenge)
            .collect();
        let request = BootstrapRequest::new(
            adapters.to_vec(),
            setup.hardware_model.clone(),
            capabilities,
        );
        let challenge = match setup.client.bootstrap(&request).await? {
            BootstrapResult::Identity(identity) => return Ok(identity),
            BootstrapResult::Challenge(challenge) => challenge,
        };
        let Some(label) = challenge_key else {
            // The service shouldn't send a challenge without the capability, but it might.
            return Err(LookupFailure::Retry {
                reason: "challenge received, but no challenge key is configured or found"
                    .to_owned(),
                retry: Retry::Slowly,
            });
        };
        tracing::info!(challenge_id = %challenge.challenge_id, expires_at = %challenge.expires_at, "answering bootstrap challenge");
        let digest = challenge::digest(&challenge::message(
            &challenge.challenge_id,
            &challenge.nonce,
            adapters,
        ));
        let signature = self
            .signer
            .run(move |backend| challenge::sign(backend, &label, &digest))
            .await
            .map_err(|_| LookupFailure::Exit(ManagerExit::SignerStopped))?
            .map_err(|error| LookupFailure::Retry {
                // Token missing or lost: wait for it (backoff or a USB attach event).
                reason: format!("signing the challenge failed: {error}"),
                retry: Retry::Backoff,
            })?;
        let answer = AnswerChallengeRequest {
            challenge_id: challenge.challenge_id,
            signature,
            adapters: adapters.to_vec(),
        };
        Ok(setup.client.answer_challenge(&answer).await?)
    }

    /// Whether the PIN-less challenge key is on the token, so the request can offer to answer
    /// challenges.
    async fn has_challenge_key(&self, label: &str) -> Result<bool, LookupFailure> {
        let label = label.to_owned();
        let found = self
            .signer
            .run(move |backend| {
                let found = backend
                    .open()
                    .and_then(|_| backend.find_key(&label))
                    .is_ok();
                backend.close();
                found
            })
            .await
            .map_err(|_| LookupFailure::Exit(ManagerExit::SignerStopped))?;
        if !found {
            tracing::warn!("challenge key not found on the token; not offering token-challenge");
        }
        Ok(found)
    }

    /// Merges the service's answer with local config and keeps the PIN for logins.
    async fn adopt(
        &mut self,
        setup: &BootstrapSetup,
        identity: DeviceIdentity,
    ) -> Result<(), ManagerExit> {
        let fatal = ManagerExit::Fatal;
        let thing_name = merge(
            "thing_name",
            self.config.thing_name.as_deref(),
            &identity.thing_name,
        )
        .map_err(fatal)?;
        let token_label = merge(
            "token_label",
            self.config.token_label.as_deref(),
            &identity.token.token_label,
        )
        .map_err(fatal)?;
        let key_label = merge(
            "key_label",
            self.config.key_label.as_deref(),
            &identity.token.key_label,
        )
        .map_err(fatal)?;
        if let (Some(local), Some(service)) = (
            setup.challenge_key_label.as_deref(),
            identity.token.challenge_key_label.as_deref(),
        ) {
            merge("challenge_key_label", Some(local), service).map_err(fatal)?;
        }
        let aws = merge_aws(setup.aws.as_ref(), identity.aws.as_ref()).map_err(fatal)?;

        tracing::info!(device_id = %identity.device_id, %thing_name, "bootstrapped");
        self.device = DeviceInfo {
            thing_name,
            device_id: Some(identity.device_id),
            aws,
        };
        self.key_label = key_label;
        // Kept until Helios restarts, so recovering a token doesn't depend on the service.
        self.pin = Arc::new(FixedPin::new(identity.pin));
        self.signer
            .run(move |backend| backend.set_token_label(&token_label))
            .await
            .map_err(|_| ManagerExit::SignerStopped)?;
        self.state.send_replace(IdentityState::Starting);
        Ok(())
    }
}

/// The service's value, which must match the local one if there is one.
fn merge(field: &'static str, local: Option<&str>, service: &str) -> Result<String, FatalReason> {
    match local {
        Some(local) if local != service => Err(FatalReason::IdentityMismatch {
            field,
            local: local.to_owned(),
            service: service.to_owned(),
        }),
        _ => Ok(service.to_owned()),
    }
}

fn merge_aws(
    local: Option<&AwsSettings>,
    service: Option<&AwsSettings>,
) -> Result<Option<AwsSettings>, FatalReason> {
    let (Some(local), Some(service)) = (local, service) else {
        return Ok(service.or(local).cloned());
    };
    let fields = [
        ("aws.region", &local.region, &service.region),
        (
            "aws.iot_endpoint",
            &local.iot_endpoint,
            &service.iot_endpoint,
        ),
        (
            "aws.credentials_endpoint",
            &local.credentials_endpoint,
            &service.credentials_endpoint,
        ),
        ("aws.role_alias", &local.role_alias, &service.role_alias),
    ];
    for (field, local, service) in fields {
        merge(field, Some(local), service)?;
    }
    Ok(Some(service.clone()))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn aws(region: &str) -> AwsSettings {
        AwsSettings {
            region: region.into(),
            iot_endpoint: "example-ats.iot.us-west-2.amazonaws.com".into(),
            credentials_endpoint: "example.credentials.iot.us-west-2.amazonaws.com".into(),
            role_alias: "helios-device-role-alias".into(),
        }
    }

    #[test]
    fn local_values_must_match_the_service() {
        assert_eq!(merge("thing_name", None, "t-1"), Ok("t-1".into()));
        assert_eq!(merge("thing_name", Some("t-1"), "t-1"), Ok("t-1".into()));
        let error = merge("thing_name", Some("t-2"), "t-1").unwrap_err();
        assert_eq!(
            error.to_string(),
            "bootstrap service says thing_name is \"t-1\", but the local config has \"t-2\""
        );
    }

    #[test]
    fn merges_aws_settings() {
        let west = aws("us-west-2");
        assert_eq!(merge_aws(None, None), Ok(None));
        assert_eq!(merge_aws(Some(&west), None), Ok(Some(west.clone())));
        assert_eq!(merge_aws(None, Some(&west)), Ok(Some(west.clone())));
        assert_eq!(merge_aws(Some(&west), Some(&west)), Ok(Some(west.clone())));
        assert_eq!(
            merge_aws(Some(&aws("us-east-1")), Some(&west)),
            Err(FatalReason::IdentityMismatch {
                field: "aws.region",
                local: "us-east-1".into(),
                service: "us-west-2".into(),
            })
        );
    }
}
