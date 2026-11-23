//! The public address of each uplink (LLD 3, section 3): Helios asks the bootstrap API's
//! egress echo (`GET …/v1/device/egress`, IAM-signed, the device role only) what address it sees
//! a request come from, with the request bound to the uplink's IPv4 address so source routing
//! sends it out of that uplink. Only uplinks with a source route are checked: without one the
//! answer would be the main default route's.
//!
//! The public address is personal data (the owner's home connection): it goes to the `net`
//! shadow only, never to the log.

use std::collections::BTreeMap;
use std::future::Future;
use std::net::{IpAddr, Ipv4Addr};
use std::pin::Pin;
use std::sync::Arc;
use std::time::{Duration, SystemTime};

use aws_credential_types::provider::ProvideCredentials;
use hyper::Request;
use hyper::body::Bytes;
use rustls::{ClientConfig, RootCertStore};
use serde_json::{Value, json};
use tokio::time::Instant;

use crate::backoff::{Backoff, random_fraction};
use crate::https::{self, Endpoint, HttpsError, Limits};
use crate::mqtt::envelope::timestamp;
use crate::sigv4;

/// The regular interval between checks of an uplink, ± [`INTERVAL_JITTER`].
pub(crate) const INTERVAL: Duration = Duration::from_secs(15 * 60);
const INTERVAL_JITTER: Duration = Duration::from_secs(60);
/// After a failure: 1 minute, doubling to the regular interval.
const RETRY_FIRST: Duration = Duration::from_secs(60);
/// A check whose address didn't change is reported at most this often (only `checked_at`
/// would move, rewriting the shadow every 15 minutes for nothing).
pub(crate) const RENEWAL_REPORT: Duration = Duration::from_secs(60 * 60);
const LIMITS: Limits = Limits {
    connect_timeout: Duration::from_secs(5),
    total_timeout: Duration::from_secs(10),
    max_body: 4096,
};

/// Asks the echo what address a request from `source` arrives from.
pub(crate) trait Probe: Send + Sync + 'static {
    /// The public address, or a short reason for the shadow (`timeout`, `http 403`...).
    fn check(
        &self,
        source: Ipv4Addr,
    ) -> Pin<Box<dyn Future<Output = Result<IpAddr, String>> + Send + '_>>;
}

/// The real echo, on the bootstrap API.
pub struct EgressClient {
    endpoint: Endpoint,
    host: String,
    path: String,
    region: String,
    tls: Arc<ClientConfig>,
    credentials: Arc<dyn ProvideCredentials>,
}

impl std::fmt::Debug for EgressClient {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("EgressClient")
            .field("host", &self.host)
            .field("path", &self.path)
            .field("region", &self.region)
            .finish_non_exhaustive()
    }
}

impl EgressClient {
    /// The echo on the bootstrap API at `bootstrap_url` (`https://<api>.execute-api.<region>
    /// .amazonaws.com/<stage>/v1`), trusting `roots`, signing with `credentials`.
    ///
    /// # Errors
    ///
    /// A message when the URL isn't an `execute-api` URL the region can be read from, or the
    /// TLS settings can't be built.
    pub fn new(
        bootstrap_url: &str,
        roots: RootCertStore,
        credentials: Arc<dyn ProvideCredentials>,
    ) -> Result<Self, String> {
        let rest = bootstrap_url
            .strip_prefix("https://")
            .ok_or_else(|| format!("{bootstrap_url:?} isn't an https:// URL"))?;
        let (authority, base) = rest.split_once('/').unwrap_or((rest, ""));
        let host = authority.split(':').next().unwrap_or(authority);
        let region = host
            .split('.')
            .skip_while(|label| *label != "execute-api")
            .nth(1)
            .filter(|region| !region.is_empty())
            .ok_or_else(|| format!("{host:?} isn't an execute-api host with a region"))?
            .to_owned();
        let endpoint = Endpoint::parse(authority).map_err(|error| error.to_string())?;
        let tls =
            crate::identity::tls::server_auth_config(roots, crate::identity::tls::Alpn::Http1)
                .map_err(|error| error.to_string())?;
        Ok(Self {
            endpoint,
            host: authority.to_owned(),
            path: format!("/{}/device/egress", base.trim_end_matches('/')).replace("//", "/"),
            region,
            tls,
            credentials,
        })
    }

    async fn ask(&self, source: Ipv4Addr) -> Result<IpAddr, String> {
        let credentials = self
            .credentials
            .provide_credentials()
            .await
            .map_err(|_| "no credentials".to_owned())?;
        let request = sigv4::Request {
            method: "GET",
            host: &self.host,
            path: &self.path,
            query: &[],
            headers: &[],
            body: b"",
        };
        let scope = sigv4::Scope {
            region: &self.region,
            service: "execute-api",
            sign_body: false,
        };
        let signed = sigv4::sign(&request, &credentials, scope, SystemTime::now())
            .map_err(|error| error.to_string())?;
        let mut builder = Request::get(self.path.as_str());
        for (name, value) in signed {
            builder = builder.header(name, value);
        }
        let response = https::send_from(
            &self.endpoint,
            Arc::clone(&self.tls),
            builder,
            Bytes::new(),
            LIMITS,
            IpAddr::V4(source),
        )
        .await
        .map_err(|error| match error {
            HttpsError::Timeout(_) => "timeout".to_owned(),
            HttpsError::Connect(_) => "connect".to_owned(),
            HttpsError::Tls(_) => "tls".to_owned(),
            other => format!("http: {other}"),
        })?;
        if !response.status.is_success() {
            return Err(format!("http {}", response.status.as_u16()));
        }
        parse(&response.body)
    }
}

impl Probe for EgressClient {
    fn check(
        &self,
        source: Ipv4Addr,
    ) -> Pin<Box<dyn Future<Output = Result<IpAddr, String>> + Send + '_>> {
        Box::pin(self.ask(source))
    }
}

/// The echo's answer: `{"address": "<ip>", "atMs": <ms>}`.
fn parse(body: &[u8]) -> Result<IpAddr, String> {
    serde_json::from_slice::<Value>(body)
        .ok()
        .and_then(|value| value["address"].as_str().and_then(|text| text.parse().ok()))
        .ok_or_else(|| "bad response".to_owned())
}

/// What's known about one uplink's public address.
#[derive(Debug)]
struct Uplink {
    source: Ipv4Addr,
    address: Option<IpAddr>,
    checked_at: Option<SystemTime>,
    error: Option<(String, SystemTime)>,
    /// The address and check time last put in the shadow.
    reported: Option<(IpAddr, SystemTime)>,
    due: Instant,
    retry: Backoff,
}

/// The checks' schedule and results, per interface.
#[derive(Debug, Default)]
pub(crate) struct Checks {
    uplinks: BTreeMap<String, Uplink>,
}

impl Checks {
    /// Follows the current uplinks (name and the IPv4 address checks are bound to): a new one,
    /// or one whose address changed, is checked at once; a gone one is forgotten.
    pub(crate) fn sync(&mut self, uplinks: &[(String, Ipv4Addr)], now: Instant) {
        self.uplinks
            .retain(|name, _| uplinks.iter().any(|(wanted, _)| wanted == name));
        for (name, source) in uplinks {
            let fresh = self
                .uplinks
                .get(name)
                .is_none_or(|uplink| uplink.source != *source);
            if fresh {
                self.uplinks.insert(
                    name.clone(),
                    Uplink {
                        source: *source,
                        address: None,
                        checked_at: None,
                        error: None,
                        reported: None,
                        due: now,
                        retry: Backoff::new(RETRY_FIRST, INTERVAL),
                    },
                );
            }
        }
    }

    /// The uplink to check next and when.
    pub(crate) fn next(&self) -> Option<(String, Ipv4Addr, Instant)> {
        self.uplinks
            .iter()
            .min_by_key(|(_, uplink)| uplink.due)
            .map(|(name, uplink)| (name.clone(), uplink.source, uplink.due))
    }

    /// Records a check of `name` from `source` (ignored if the uplink moved on meanwhile).
    pub(crate) fn record(
        &mut self,
        name: &str,
        source: Ipv4Addr,
        result: Result<IpAddr, String>,
        now: Instant,
        wall: SystemTime,
    ) {
        let Some(uplink) = self
            .uplinks
            .get_mut(name)
            .filter(|uplink| uplink.source == source)
        else {
            return;
        };
        match result {
            Ok(address) => {
                uplink.address = Some(address);
                uplink.checked_at = Some(wall);
                uplink.error = None;
                uplink.retry.reset();
                let jitter = INTERVAL_JITTER.mul_f64(2.0 * random_fraction());
                uplink.due = now + INTERVAL - INTERVAL_JITTER + jitter;
            }
            Err(reason) => {
                uplink.error = Some((reason, wall));
                uplink.due = now + uplink.retry.next_delay();
            }
        }
    }

    /// `public_ipv4` for `name`: the address and when it was checked, with the last failure if
    /// the latest check failed; `null` when it isn't checked or never answered. A check that
    /// found the same address moves `checked_at` at most every [`RENEWAL_REPORT`].
    pub(crate) fn report(&mut self, name: &str) -> Value {
        let Some(uplink) = self.uplinks.get_mut(name) else {
            return Value::Null;
        };
        let (Some(address), Some(checked_at)) = (uplink.address, uplink.checked_at) else {
            return match &uplink.error {
                Some((reason, at)) => json!({"address": null, "error": reason,
                                             "failed_at": timestamp(*at)}),
                None => Value::Null,
            };
        };
        let shown = match uplink.reported {
            Some((reported, at))
                if reported == address
                    && checked_at
                        .duration_since(at)
                        .is_ok_and(|age| age < RENEWAL_REPORT) =>
            {
                at
            }
            _ => checked_at,
        };
        uplink.reported = Some((address, shown));
        let mut value = json!({"address": address.to_string(), "checked_at": timestamp(shown)});
        if let Some((reason, at)) = &uplink.error {
            value["error"] = json!(reason);
            value["failed_at"] = json!(timestamp(*at));
        }
        value
    }
}

/// The uplinks to check in a `net` report: interfaces whose `source_route.rule` is true, with
/// their first IPv4 address.
pub(crate) fn uplinks(interfaces: &serde_json::Map<String, Value>) -> Vec<(String, Ipv4Addr)> {
    interfaces
        .iter()
        .filter(|(_, interface)| interface["source_route"]["rule"] == true)
        .filter_map(|(name, interface)| {
            let first = interface["ipv4"].as_array()?.first()?.as_str()?;
            let address = first.split('/').next()?.parse().ok()?;
            Some((name.clone(), address))
        })
        .collect()
}

#[cfg(test)]
pub(crate) mod tests;
