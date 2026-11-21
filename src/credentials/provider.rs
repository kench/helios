//! AWS SDK integration: a cached, single-flight `ProvideCredentials` and the background task
//! that refreshes the credentials (LLD 1, sections 5.3 and 5.4).
//!
//! The refresher fetches as soon as the identity is ready, then again at about 80% of the
//! lifetime. While the identity isn't ready it pauses, and cached credentials stay usable until
//! they expire. SDK calls share the cache: they get the cached credentials while more than 60 s
//! remain, and otherwise wait for one refresh shared by every caller.

use std::fmt;
use std::sync::{Arc, PoisonError};
use std::time::{Duration, Instant, SystemTime};

use aws_credential_types::Credentials;
use aws_credential_types::provider::{
    self, ProvideCredentials, error::CredentialsError as SdkError, future,
};
use secrecy::ExposeSecret;
use tokio::sync::watch;
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;

use crate::backoff::{self, Backoff};
use crate::clock::ClockSamples;
use crate::credentials::client::{CredentialsClient, CredentialsError, Retry};
use crate::credentials::refresh;
use crate::identity::manager::{IdentityHandle, IdentityState};
use crate::identity::tls::Alpn;

/// The provider name the SDK sees.
pub const PROVIDER_NAME: &str = "helios-iot";
/// Cached credentials are handed out while at least this much of their lifetime remains.
pub const MIN_REMAINING: Duration = Duration::from_secs(60);

/// The credentials endpoint and role alias from the local `[aws]` config.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LocalSettings {
    /// `aws.credentials_endpoint`.
    pub credentials_endpoint: String,
    /// `aws.role_alias`.
    pub role_alias: String,
}

/// Refresh timing (LLD 1, section 5.3). Tests shorten it.
#[derive(Debug, Clone, Copy)]
pub struct Timing {
    /// When to refresh credentials with a given lifetime, from a jitter fraction (0 to 1).
    pub refresh_after: fn(Duration, f64) -> Duration,
    /// First retry delay after a network, TLS or 5xx error.
    pub initial_backoff: Duration,
    /// Longest retry delay after such an error.
    pub max_backoff: Duration,
    /// Retry delay after the provider rejected the request.
    pub rejected_retry: Duration,
}

impl Default for Timing {
    fn default() -> Self {
        Self {
            refresh_after: refresh::refresh_after,
            initial_backoff: refresh::INITIAL_BACKOFF,
            max_backoff: refresh::MAX_BACKOFF,
            rejected_retry: refresh::REJECTED_RETRY,
        }
    }
}

/// Credentials status for logs and the `helios` shadow (LLD 1, section 7). No secrets.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct CredentialsStatus {
    /// When the current credentials expire, by the device clock.
    pub expires_at: Option<SystemTime>,
    /// When they were last fetched, by the device clock.
    pub last_refresh: Option<SystemTime>,
    /// Why the last refresh failed, if it did.
    pub last_error: Option<String>,
}

/// Why credentials couldn't be refreshed.
#[derive(Debug, thiserror::Error)]
enum RefreshError {
    /// The identity isn't ready, so there is no client certificate.
    #[error("the device identity is not ready ({0})")]
    IdentityNotReady(&'static str),
    /// Neither the bootstrap service nor the local config gave an endpoint and role alias.
    #[error("no credentials endpoint and role alias are configured")]
    NotConfigured,
    /// The endpoint or role alias isn't valid.
    #[error(transparent)]
    Config(#[from] crate::credentials::client::ConfigError),
    /// The request failed.
    #[error(transparent)]
    Fetch(#[from] CredentialsError),
}

impl RefreshError {
    fn retry(&self) -> Retry {
        match self {
            Self::Fetch(error) => error.retry(),
            Self::IdentityNotReady(_) => Retry::Backoff,
            Self::NotConfigured | Self::Config(_) => Retry::Slowly,
        }
    }
}

/// The error the SDK gets when there are no usable credentials.
#[derive(Debug, thiserror::Error)]
#[error("no AWS credentials yet: {0}")]
struct NotLoaded(String);

struct Cached {
    credentials: Credentials,
    expires: Instant,
    refresh_at: Instant,
}

struct Inner {
    identity: IdentityHandle,
    local: Option<LocalSettings>,
    timing: Timing,
    cached: std::sync::Mutex<Option<Cached>>,
    /// Held while a refresh runs, so concurrent callers share it.
    refreshing: tokio::sync::Mutex<()>,
    status: watch::Sender<CredentialsStatus>,
    clock: ClockSamples,
}

/// The AWS SDK credentials provider. Cheap to clone.
#[derive(Clone)]
pub struct HeliosCredentialsProvider {
    inner: Arc<Inner>,
}

impl fmt::Debug for HeliosCredentialsProvider {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("HeliosCredentialsProvider")
            .field("status", &*self.inner.status.borrow())
            .finish_non_exhaustive()
    }
}

impl ProvideCredentials for HeliosCredentialsProvider {
    fn provide_credentials<'a>(&'a self) -> future::ProvideCredentials<'a>
    where
        Self: 'a,
    {
        future::ProvideCredentials::new(self.inner.clone().get())
    }
}

impl HeliosCredentialsProvider {
    /// A provider for the device with `identity`, and the background task that keeps its
    /// credentials fresh until `cancel` is cancelled. `local` is the local `[aws]` config,
    /// used unless the bootstrap service supplied AWS settings. Responses' server times go to
    /// `clock`.
    ///
    /// # Panics
    ///
    /// Panics if called outside a tokio runtime.
    #[must_use]
    pub fn start(
        identity: IdentityHandle,
        local: Option<LocalSettings>,
        timing: Timing,
        clock: ClockSamples,
        cancel: CancellationToken,
    ) -> (Self, JoinHandle<()>) {
        let provider = Self {
            inner: Arc::new(Inner {
                identity,
                local,
                timing,
                cached: std::sync::Mutex::new(None),
                refreshing: tokio::sync::Mutex::new(()),
                status: watch::channel(CredentialsStatus::default()).0,
                clock,
            }),
        };
        let task = tokio::spawn(refresher(provider.inner.clone(), cancel));
        (provider, task)
    }

    /// The credentials status. Await changes with `changed()`.
    #[must_use]
    pub fn status(&self) -> watch::Receiver<CredentialsStatus> {
        self.inner.status.subscribe()
    }
}

impl Inner {
    /// Cached credentials with at least `margin` left.
    fn cached(&self, margin: Duration) -> Option<Credentials> {
        let cached = self.cached.lock().unwrap_or_else(PoisonError::into_inner);
        cached
            .as_ref()
            .filter(|cached| cached.expires.saturating_duration_since(Instant::now()) > margin)
            .map(|cached| cached.credentials.clone())
    }

    /// For the SDK: cached credentials, or one shared refresh.
    async fn get(self: Arc<Self>) -> provider::Result {
        if let Some(credentials) = self.cached(MIN_REMAINING) {
            return Ok(credentials);
        }
        let _refreshing = self.refreshing.lock().await;
        if let Some(credentials) = self.cached(MIN_REMAINING) {
            // Another caller refreshed while this one waited.
            return Ok(credentials);
        }
        let result = self.fetch().await;
        // Fresh credentials, or ones about to expire if the refresh failed: better than none.
        if let Some(credentials) = self.cached(Duration::ZERO) {
            return Ok(credentials);
        }
        let reason = match result {
            Ok(_) => "the credentials expired as they arrived".to_owned(),
            Err(error) => error.to_string(),
        };
        tracing::warn!(%reason, "no AWS credentials for the SDK");
        Err(SdkError::not_loaded(NotLoaded(reason)))
    }

    /// Refreshes if the cached credentials are due, and returns when to refresh next.
    async fn refresh_if_due(&self) -> Result<Instant, RefreshError> {
        let _refreshing = self.refreshing.lock().await;
        let due = self
            .cached
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .as_ref()
            .map(|cached| cached.refresh_at)
            .filter(|refresh_at| *refresh_at > Instant::now());
        match due {
            Some(refresh_at) => Ok(refresh_at),
            None => self.fetch().await,
        }
    }

    /// Fetches new credentials and caches them. The caller holds `refreshing`.
    async fn fetch(&self) -> Result<Instant, RefreshError> {
        let result = self.try_fetch().await;
        // One update, so watchers never see new credentials next to an old error.
        self.status.send_modify(|status| match &result {
            Ok((_, expires_at)) => {
                status.expires_at = Some(*expires_at);
                status.last_refresh = Some(SystemTime::now());
                status.last_error = None;
            }
            Err(error) => status.last_error = Some(error.to_string()),
        });
        result.map(|(refresh_at, _)| refresh_at)
    }

    /// Fetches and caches new credentials. Returns when to refresh and when they expire.
    async fn try_fetch(&self) -> Result<(Instant, SystemTime), RefreshError> {
        let state = self.identity.state();
        let Some(identity) = state.identity() else {
            return Err(RefreshError::IdentityNotReady(state.name()));
        };
        let (endpoint, role_alias) = endpoints(identity.device.aws.as_ref(), self.local.as_ref())
            .ok_or(RefreshError::NotConfigured)?;
        let client = CredentialsClient::new(endpoint, role_alias, &identity.device.thing_name)?
            .with_clock(self.clock.clone());
        let tls = self
            .identity
            .tls_config(Alpn::Http1)
            .map_err(|error| RefreshError::Fetch(CredentialsError::Malformed(error.to_string())))?;
        let fetched = client.fetch(tls).await?;

        let now = Instant::now();
        let expires_at = SystemTime::now() + fetched.lifetime;
        let refresh_at =
            now + (self.timing.refresh_after)(fetched.lifetime, backoff::random_fraction());
        let credentials = Credentials::new(
            fetched.access_key_id,
            fetched.secret_access_key.expose_secret().clone(),
            Some(fetched.session_token.expose_secret().clone()),
            Some(expires_at),
            PROVIDER_NAME,
        );
        *self.cached.lock().unwrap_or_else(PoisonError::into_inner) = Some(Cached {
            credentials,
            expires: now + fetched.lifetime,
            refresh_at,
        });
        tracing::info!(
            lifetime_s = fetched.lifetime.as_secs(),
            "AWS credentials refreshed"
        );
        Ok((refresh_at, expires_at))
    }
}

/// The credentials endpoint and role alias: the bootstrap service's (already merged with the
/// local config), or the local config's.
fn endpoints<'a>(
    service: Option<&'a crate::identity::bootstrap::api::AwsSettings>,
    local: Option<&'a LocalSettings>,
) -> Option<(&'a str, &'a str)> {
    service
        .map(|aws| (aws.credentials_endpoint.as_str(), aws.role_alias.as_str()))
        .or_else(|| {
            local.map(|local| {
                (
                    local.credentials_endpoint.as_str(),
                    local.role_alias.as_str(),
                )
            })
        })
}

/// Keeps the credentials fresh while the identity is ready.
async fn refresher(inner: Arc<Inner>, cancel: CancellationToken) {
    let mut identity = inner.identity.watch();
    let mut backoff = Backoff::new(inner.timing.initial_backoff, inner.timing.max_backoff);
    loop {
        // Pause until the identity is ready. Cached credentials stay usable meanwhile.
        tokio::select! {
            () = cancel.cancelled() => return,
            ready = identity.wait_for(|state| matches!(state, IdentityState::Ready(_))) => {
                if ready.is_err() {
                    // The identity manager has stopped.
                    return;
                }
            }
        }
        let delay = match inner.refresh_if_due().await {
            Ok(refresh_at) => {
                backoff.reset();
                refresh_at.saturating_duration_since(Instant::now())
            }
            Err(error) => {
                tracing::warn!(%error, "refreshing AWS credentials failed");
                match error.retry() {
                    Retry::Slowly => inner.timing.rejected_retry,
                    Retry::Backoff => backoff.next_delay(),
                }
            }
        };
        tokio::select! {
            () = cancel.cancelled() => return,
            () = tokio::time::sleep(delay) => {}
            // A new identity state: pause if it isn't ready, or check what is due.
            changed = identity.changed() => {
                if changed.is_err() {
                    return;
                }
            }
        }
    }
}

#[cfg(test)]
mod tests;
