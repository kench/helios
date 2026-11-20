//! Request and response types for the device API (`HeliosBootstrap` in `helios-contract`).
//!
//! Hand-written `serde` types for the two operations, checked against the model's protocol
//! tests (Bootstrap API, section 9). Members are camelCase. Unknown members are ignored, as
//! the API may add optional ones within v1. Responses are checked against the model's
//! constraints by [`DeviceIdentity::validate`] and [`Challenge::validate`].

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as BASE64;
use secrecy::{ExposeSecret, SecretString};
use serde::{Deserialize, Serialize};

use crate::identity::bootstrap::adapters::Adapter;

/// The only challenge signature algorithm in v1.
pub const ALG_ECDSA_P256_SHA256: &str = "ecdsa-p256-sha256";
/// Length of a challenge nonce, in bytes.
pub const NONCE_LEN: usize = 32;
/// Longest PKCS#11 label, in bytes.
pub const MAX_LABEL_LEN: usize = 32;

/// What Helios can do beyond a plain lookup.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub enum Capability {
    /// Helios has a challenge key and can answer challenges.
    #[serde(rename = "token-challenge")]
    TokenChallenge,
}

/// `Bootstrap` request: `POST /v1/device/bootstrap`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct BootstrapRequest {
    /// The built-in adapters, sorted by interface name.
    pub adapters: Vec<Adapter>,
    /// This Helios version.
    pub helios_version: String,
    /// From `/proc/device-tree/model`, for logs and audit.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub hardware_model: Option<String>,
    /// `token-challenge` when a challenge key is configured and found.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub capabilities: Vec<Capability>,
}

impl BootstrapRequest {
    /// A request from this Helios version.
    #[must_use]
    pub fn new(
        adapters: Vec<Adapter>,
        hardware_model: Option<String>,
        capabilities: Vec<Capability>,
    ) -> Self {
        Self {
            adapters,
            helios_version: env!("CARGO_PKG_VERSION").to_owned(),
            hardware_model,
            capabilities,
        }
    }
}

/// `AnswerChallenge` request: `POST /v1/device/bootstrap/challenge`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AnswerChallengeRequest {
    /// The challenge being answered.
    pub challenge_id: String,
    /// Base64 DER ECDSA signature over the challenge message.
    pub signature: String,
    /// The same adapters as in the `Bootstrap` request.
    pub adapters: Vec<Adapter>,
}

/// The `Bootstrap` response: a challenge to answer first, or the identity.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum BootstrapResult {
    /// Proof that the token is present is required first.
    Challenge(Challenge),
    /// The device identity and token PIN.
    Identity(DeviceIdentity),
}

/// A challenge from `Bootstrap`.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Challenge {
    /// `c-` followed by a ULID.
    pub challenge_id: String,
    /// 32 random bytes, base64. Signed exactly as received.
    pub nonce: String,
    /// The signature algorithm.
    pub alg: String,
    /// When the challenge expires (RFC 3339). Only logged: the device clock may be wrong.
    pub expires_at: String,
}

/// The device identity, from `Bootstrap` or `AnswerChallenge`.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DeviceIdentity {
    /// The service's ID for the record: `d-` followed by a ULID.
    pub device_id: String,
    /// The AWS IoT thing name.
    pub thing_name: String,
    /// The token user PIN. Never logged.
    pub pin: SecretString,
    /// Token and key labels.
    pub token: TokenLabels,
    /// AWS settings, if the service sends them.
    pub aws: Option<AwsSettings>,
}

/// Labels Helios uses to find its token and keys.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TokenLabels {
    /// The token label.
    pub token_label: String,
    /// The device key label.
    pub key_label: String,
    /// The challenge key label, if the device has one.
    pub challenge_key_label: Option<String>,
}

/// AWS settings for the device.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AwsSettings {
    /// The AWS region.
    pub region: String,
    /// The AWS IoT Core data endpoint.
    pub iot_endpoint: String,
    /// The AWS IoT credentials provider endpoint.
    pub credentials_endpoint: String,
    /// The role alias for credentials.
    pub role_alias: String,
}

/// A response member breaks the model's constraints.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("response member {member} is not valid")]
pub struct InvalidMember {
    /// The member's JSON path, such as `token.keyLabel`. Never its value.
    pub member: &'static str,
}

impl DeviceIdentity {
    /// Checks the members against the model's constraints.
    ///
    /// # Errors
    ///
    /// The first member that breaks them. The error never includes the value.
    pub fn validate(&self) -> Result<(), InvalidMember> {
        check(is_ulid_id(&self.device_id, "d-"), "deviceId")?;
        check(is_thing_name(&self.thing_name), "thingName")?;
        let pin_len = self.pin.expose_secret().chars().count();
        check((4..=255).contains(&pin_len), "pin")?;
        check(is_label(&self.token.token_label), "token.tokenLabel")?;
        check(is_label(&self.token.key_label), "token.keyLabel")?;
        if let Some(label) = &self.token.challenge_key_label {
            check(is_label(label), "token.challengeKeyLabel")?;
        }
        if let Some(aws) = &self.aws {
            check(is_region(&aws.region), "aws.region")?;
            check(is_host_name(&aws.iot_endpoint), "aws.iotEndpoint")?;
            check(
                is_host_name(&aws.credentials_endpoint),
                "aws.credentialsEndpoint",
            )?;
            check(is_role_alias(&aws.role_alias), "aws.roleAlias")?;
        }
        Ok(())
    }
}

impl Challenge {
    /// Checks the members against the model's constraints, including that the nonce decodes to
    /// 32 bytes and the algorithm is one Helios supports.
    ///
    /// # Errors
    ///
    /// The first member that breaks them.
    pub fn validate(&self) -> Result<(), InvalidMember> {
        check(
            is_ulid_id(&self.challenge_id, "c-"),
            "challenge.challengeId",
        )?;
        let nonce = BASE64.decode(&self.nonce).ok();
        check(
            nonce.is_some_and(|nonce| nonce.len() == NONCE_LEN),
            "challenge.nonce",
        )?;
        check(self.alg == ALG_ECDSA_P256_SHA256, "challenge.alg")?;
        Ok(())
    }
}

fn check(valid: bool, member: &'static str) -> Result<(), InvalidMember> {
    if valid {
        Ok(())
    } else {
        Err(InvalidMember { member })
    }
}

/// `prefix` followed by a ULID (Crockford base32, no I, L, O or U).
fn is_ulid_id(value: &str, prefix: &str) -> bool {
    value.strip_prefix(prefix).is_some_and(|ulid| {
        ulid.len() == 26
            && ulid.bytes().all(|b| {
                b.is_ascii_digit()
                    || (b.is_ascii_uppercase() && !matches!(b, b'I' | b'L' | b'O' | b'U'))
            })
    })
}

fn is_thing_name(value: &str) -> bool {
    (1..=128).contains(&value.len())
        && value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b':' | b'_' | b'-'))
}

fn is_label(value: &str) -> bool {
    (1..=MAX_LABEL_LEN).contains(&value.len())
}

/// `^[a-z]{2}(-[a-z]+)+-[0-9]+$`, such as `us-west-2`.
fn is_region(value: &str) -> bool {
    let parts: Vec<&str> = value.split('-').collect();
    let [first, middle @ .., last] = parts.as_slice() else {
        return false;
    };
    first.len() == 2
        && first.bytes().all(|b| b.is_ascii_lowercase())
        && !middle.is_empty()
        && middle
            .iter()
            .all(|part| !part.is_empty() && part.bytes().all(|b| b.is_ascii_lowercase()))
        && !last.is_empty()
        && last.bytes().all(|b| b.is_ascii_digit())
}

fn is_host_name(value: &str) -> bool {
    (1..=253).contains(&value.len())
        && value
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || matches!(b, b'.' | b'-'))
}

/// `^[\w=,@-]+$`, at most 128 characters.
fn is_role_alias(value: &str) -> bool {
    (1..=128).contains(&value.len())
        && value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'=' | b',' | b'@' | b'-'))
}

#[cfg(test)]
pub(crate) mod tests {
    use std::path::PathBuf;

    use serde_json::Value;

    use super::*;
    use crate::identity::bootstrap::adapters::{AdapterKind, MacAddress};

    /// The body of the protocol test `id` in the contract's `bootstrap.smithy`.
    pub(crate) fn protocol_test_body(id: &str) -> String {
        let model =
            PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("contract/model/bootstrap.smithy");
        let model = std::fs::read_to_string(&model).unwrap_or_else(|e| {
            panic!(
                "{}: {e} (run `git submodule update --init`)",
                model.display()
            )
        });
        let start = model
            .find(&format!("id: \"{id}\""))
            .unwrap_or_else(|| panic!("no protocol test {id}"));
        let rest = &model[start..];
        let body = &rest[rest.find("body: \"\"\"").unwrap() + "body: \"\"\"".len()..];
        body[..body.find("\"\"\"").unwrap()].to_owned()
    }

    pub(crate) fn json(text: &str) -> Value {
        serde_json::from_str(text).unwrap()
    }

    fn adapter(name: &str, kind: AdapterKind, mac: &str) -> Adapter {
        Adapter {
            interface_name: name.into(),
            kind,
            mac: mac.parse::<MacAddress>().unwrap(),
        }
    }

    pub(crate) fn relay_adapters() -> Vec<Adapter> {
        vec![
            adapter("eth0", AdapterKind::Ethernet, "2c:cf:67:00:00:01"),
            adapter("wlan0", AdapterKind::Wifi, "2c:cf:67:00:00:02"),
        ]
    }

    #[test]
    fn bootstrap_requests_match_the_protocol_tests() {
        let mut request = BootstrapRequest::new(
            relay_adapters(),
            Some("Raspberry Pi 5 Model B Rev 1.0".into()),
            vec![Capability::TokenChallenge],
        );
        request.helios_version = "0.1.0".into();
        assert_eq!(
            serde_json::to_value(&request).unwrap(),
            json(&protocol_test_body(
                "BootstrapRequestWithChallengeCapability"
            ))
        );

        let mut minimal = BootstrapRequest::new(
            vec![adapter("eth0", AdapterKind::Ethernet, "00:11:22:33:44:55")],
            None,
            Vec::new(),
        );
        minimal.helios_version = "0.1.0".into();
        assert_eq!(
            serde_json::to_value(&minimal).unwrap(),
            json(&protocol_test_body("BootstrapRequestMinimal"))
        );

        assert_eq!(
            BootstrapRequest::new(Vec::new(), None, Vec::new()).helios_version,
            env!("CARGO_PKG_VERSION")
        );
    }

    #[test]
    fn answer_challenge_requests_match_the_protocol_test() {
        let request = AnswerChallengeRequest {
            challenge_id: "c-01JD5W3Q8T6M2K4X9B0N7C1D2E".into(),
            signature: BASE64.encode("test-signature"),
            adapters: vec![adapter("eth0", AdapterKind::Ethernet, "2c:cf:67:00:00:01")],
        };

        assert_eq!(
            serde_json::to_value(&request).unwrap(),
            json(&protocol_test_body("AnswerChallengeRequest"))
        );
    }

    #[test]
    fn parses_the_identity_response() {
        let result: BootstrapResult =
            serde_json::from_str(&protocol_test_body("BootstrapReturnsIdentity")).unwrap();

        let BootstrapResult::Identity(identity) = result else {
            panic!("expected an identity");
        };
        identity.validate().unwrap();
        assert_eq!(identity.device_id, "d-01JD5VZ6R1H8P3S0W2Y4A6C8E0");
        assert_eq!(identity.thing_name, "t-01JD5VY2K7M9Q4R6T8V0X2Z4B6");
        assert_eq!(identity.pin.expose_secret(), "123456");
        assert_eq!(
            identity.token,
            TokenLabels {
                token_label: "helios".into(),
                key_label: "device-key".into(),
                challenge_key_label: Some("challenge-key".into()),
            }
        );
        assert_eq!(identity.aws.unwrap().role_alias, "helios-device-role-alias");
        // The PIN never shows up in debug output.
        let again: BootstrapResult =
            serde_json::from_str(&protocol_test_body("BootstrapReturnsIdentity")).unwrap();
        assert!(!format!("{again:?}").contains("123456"));
    }

    #[test]
    fn parses_the_challenge_response() {
        let result: BootstrapResult =
            serde_json::from_str(&protocol_test_body("BootstrapReturnsChallenge")).unwrap();

        let BootstrapResult::Challenge(challenge) = result else {
            panic!("expected a challenge");
        };
        challenge.validate().unwrap();
        assert_eq!(challenge.challenge_id, "c-01JD5W3Q8T6M2K4X9B0N7C1D2E");
        assert_eq!(challenge.alg, ALG_ECDSA_P256_SHA256);
        assert_eq!(challenge.expires_at, "2026-11-19T05:31:00Z");
    }

    #[test]
    fn ignores_unknown_members_but_not_unknown_results() {
        let identity: DeviceIdentity = serde_json::from_value(serde_json::json!({
            "deviceId": "d-01JD5VZ6R1H8P3S0W2Y4A6C8E0",
            "thingName": "relay-1",
            "pin": "1234",
            "token": {"tokenLabel": "helios", "keyLabel": "device-key", "future": 1},
            "addedLater": true
        }))
        .unwrap();
        identity.validate().unwrap();
        assert!(identity.aws.is_none());
        assert!(identity.token.challenge_key_label.is_none());

        let unknown = serde_json::from_str::<BootstrapResult>(r#"{"somethingNew": {}}"#);
        assert!(unknown.is_err());
    }

    fn identity() -> DeviceIdentity {
        serde_json::from_str::<BootstrapResult>(&protocol_test_body("BootstrapReturnsIdentity"))
            .map(|result| match result {
                BootstrapResult::Identity(identity) => identity,
                BootstrapResult::Challenge(_) => unreachable!(),
            })
            .unwrap()
    }

    #[test]
    fn rejects_identities_that_break_the_model() {
        type Breaker = fn(&mut DeviceIdentity);
        let cases: [(&str, Breaker); 12] = [
            ("deviceId", |i| {
                i.device_id = "dev_01JD5VZ6R1H8P3S0W2Y4A6C8E0".into()
            }),
            ("deviceId", |i| {
                i.device_id = "d-01JD5VZ6R1H8P3S0W2Y4A6C8EU".into()
            }),
            ("thingName", |i| i.thing_name = "thing name".into()),
            ("thingName", |i| i.thing_name = "t".repeat(129)),
            ("pin", |i| i.pin = SecretString::new("123".into())),
            ("pin", |i| i.pin = SecretString::new("1".repeat(256))),
            ("token.tokenLabel", |i| i.token.token_label = String::new()),
            ("token.keyLabel", |i| i.token.key_label = "k".repeat(33)),
            ("token.challengeKeyLabel", |i| {
                i.token.challenge_key_label = Some(String::new());
            }),
            ("aws.region", |i| {
                i.aws.as_mut().unwrap().region = "uswest2".into()
            }),
            ("aws.iotEndpoint", |i| {
                i.aws.as_mut().unwrap().iot_endpoint = "Example.com".into();
            }),
            ("aws.roleAlias", |i| {
                i.aws.as_mut().unwrap().role_alias = "a/b".into()
            }),
        ];
        for (member, breaker) in cases {
            let mut identity = identity();
            breaker(&mut identity);
            assert_eq!(
                identity.validate(),
                Err(InvalidMember { member }),
                "{member}"
            );
        }
        let mut identity = identity();
        identity.aws.as_mut().unwrap().credentials_endpoint = "a_b".into();
        assert_eq!(
            identity.validate().unwrap_err().to_string(),
            "response member aws.credentialsEndpoint is not valid"
        );
    }

    #[test]
    fn rejects_challenges_that_break_the_model() {
        let valid = Challenge {
            challenge_id: "c-01JD5W3Q8T6M2K4X9B0N7C1D2E".into(),
            nonce: BASE64.encode([7u8; 32]),
            alg: ALG_ECDSA_P256_SHA256.into(),
            expires_at: "2026-11-19T05:31:00Z".into(),
        };
        valid.validate().unwrap();
        let cases = [
            (
                "challenge.challengeId",
                Challenge {
                    challenge_id: "chl_01JD5W3Q8T6M2K4X9B0N7C1D2E".into(),
                    ..valid.clone()
                },
            ),
            (
                "challenge.nonce",
                Challenge {
                    nonce: BASE64.encode([7u8; 31]),
                    ..valid.clone()
                },
            ),
            (
                "challenge.nonce",
                Challenge {
                    nonce: "not base64!".into(),
                    ..valid.clone()
                },
            ),
            (
                "challenge.alg",
                Challenge {
                    alg: "ed25519".into(),
                    ..valid.clone()
                },
            ),
        ];
        for (member, challenge) in cases {
            assert_eq!(
                challenge.validate(),
                Err(InvalidMember { member }),
                "{member}"
            );
        }
    }

    #[test]
    fn checks_regions() {
        for region in ["us-west-2", "ap-southeast-1", "us-gov-west-1"] {
            assert!(is_region(region), "{region}");
        }
        for region in [
            "",
            "us",
            "us-2",
            "usa-west-2",
            "us-west-",
            "us--2",
            "US-west-2",
            "us-west-x",
        ] {
            assert!(!is_region(region), "{region}");
        }
    }
}
