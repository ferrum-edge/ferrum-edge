//! Refreshing cache for AWS credentials that belong to the gateway process or
//! its workload identity.
//!
//! `serverless_function` (`aws_lambda`) can opt into the AWS SDK default
//! credential chain with `aws_credentials: default_chain`: environment
//! variables, shared config/credentials profile files, web identity (EKS
//! IRSA), ECS container credentials, and EC2 instance metadata (IMDSv2). Those
//! sources mint temporary credentials that expire, so a snapshot taken at
//! plugin construction would stop signing after one credential lifetime.
//!
//! [`RefreshingAwsCredentials`] keeps the current credential set in an
//! [`ArcSwapOption`] so the request path reads it without a lock, and renews it
//! before it expires:
//!
//! - **Fresh** credentials are returned directly.
//! - Credentials inside the refresh window (by default five minutes before
//!   expiry) are still returned directly, and one background refresh task is
//!   started. The request never waits for it.
//! - With **no usable** credentials (first use, or after a failed renewal let
//!   them expire) the request waits — bounded by the fetch timeout — for one
//!   shared fetch. Concurrent requests join the same fetch instead of each
//!   starting one.
//! - A failed fetch arms a short retry backoff so an unavailable provider is
//!   not re-contacted by every request, and expired credentials are never
//!   signed with: the caller fails closed.
//!
//! The provider itself is injected as an [`AwsCredentialFetcher`]. The AWS SDK
//! default chain is wired in only when the crate is built with the
//! `secrets-aws` feature ([`aws_default_chain_fetcher`]); the cache logic is
//! feature-independent so it is exercised by the default build's tests.
//!
//! Every fetch runs in its own spawned task, so a request whose bounded wait
//! elapses leaves the fetch running for a later request to use, and a task that
//! ends without an answer (runtime shutdown, or a provider panic in an
//! unwinding build) is a fixed refusal rather than a wedged refresh. Nothing
//! here outlives an in-flight fetch: there is no periodic task, so a replaced
//! plugin generation leaves no work behind.
//!
//! Endpoint scoping is NOT decided here. These credentials are ambient, and the
//! caller must apply [`super::ambient_cloud_credentials::AmbientAwsEndpointScope`]
//! exactly as it does for the `AWS_*` environment fallbacks.

use std::future::Future;
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, PoisonError};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use arc_swap::ArcSwapOption;
use futures_util::FutureExt as _;
use futures_util::future::{BoxFuture, Shared};
use http::HeaderValue;

use super::aws_sigv4::AwsSigV4Config;
use crate::plugins::utils::log_sampling::warn_sampled;

/// Default lead time before expiry at which a background refresh starts.
pub const DEFAULT_REFRESH_BEFORE_EXPIRY: Duration = Duration::from_secs(5 * 60);
/// Default margin before expiry after which a credential is no longer signed
/// with, so a request signed now still verifies when it reaches AWS.
pub const DEFAULT_EXPIRY_SKEW: Duration = Duration::from_secs(10);
/// Default upper bound on one credential fetch, and on how long a request
/// waits for one when it has no usable credential.
pub const DEFAULT_FETCH_TIMEOUT: Duration = Duration::from_secs(10);
/// Default pause after a failed fetch before another one is started.
pub const DEFAULT_RETRY_BACKOFF: Duration = Duration::from_secs(5);

/// One resolved AWS credential set.
#[derive(Clone)]
pub struct AwsCredentialSnapshot {
    access_key_id: String,
    secret_access_key: String,
    session_token: Option<String>,
    expires_at: Option<SystemTime>,
}

/// Hand-written so `{:?}` never prints the secret key or the session token.
impl std::fmt::Debug for AwsCredentialSnapshot {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("AwsCredentialSnapshot")
            .field("access_key_id", &self.access_key_id)
            .field("secret_access_key", &"[REDACTED]")
            .field(
                "session_token",
                &self.session_token.as_ref().map(|_| "[REDACTED]"),
            )
            .field("expires_at", &self.expires_at)
            .finish()
    }
}

impl AwsCredentialSnapshot {
    /// A credential set. `expires_at: None` marks a credential that does not
    /// expire (long-lived IAM user keys); it is never refreshed.
    pub fn new(
        access_key_id: impl Into<String>,
        secret_access_key: impl Into<String>,
        session_token: Option<String>,
        expires_at: Option<SystemTime>,
    ) -> Self {
        Self {
            access_key_id: access_key_id.into(),
            secret_access_key: secret_access_key.into(),
            session_token,
            expires_at,
        }
    }

    /// The access key id (an identifier, not a secret).
    pub fn access_key_id(&self) -> &str {
        &self.access_key_id
    }

    /// Whether the set carries an STS session token.
    pub fn has_session_token(&self) -> bool {
        self.session_token.is_some()
    }

    /// When the set expires, if it does.
    pub fn expires_at(&self) -> Option<SystemTime> {
        self.expires_at
    }

    /// SigV4 signing input for `region`.
    pub fn signing_config(&self, region: &str) -> AwsSigV4Config {
        AwsSigV4Config {
            region: region.to_string(),
            access_key_id: self.access_key_id.clone(),
            secret_access_key: self.secret_access_key.clone(),
            session_token: self.session_token.clone(),
        }
    }

    /// The access key id lands in `Authorization` and the session token in
    /// `x-amz-security-token`, so both must be HTTP field values; a provider
    /// answer that is not would fail every signed request. The reason names a
    /// field only, never a value.
    fn validate(&self) -> Result<(), &'static str> {
        if self.access_key_id.is_empty() || HeaderValue::from_str(&self.access_key_id).is_err() {
            return Err("the credential provider returned an unusable access key id");
        }
        if self.secret_access_key.is_empty() {
            return Err("the credential provider returned an empty secret access key");
        }
        if let Some(token) = self.session_token.as_deref()
            && (token.is_empty() || HeaderValue::from_str(token).is_err())
        {
            return Err("the credential provider returned an unusable session token");
        }
        Ok(())
    }
}

/// Future returned by an [`AwsCredentialFetcher`]. The error string is for
/// operator diagnostics only and must never contain credential material.
pub type AwsCredentialFetchFuture =
    Pin<Box<dyn Future<Output = Result<AwsCredentialSnapshot, String>> + Send>>;

/// Source of fresh credentials. Called once per refresh.
pub type AwsCredentialFetcher = Arc<dyn Fn() -> AwsCredentialFetchFuture + Send + Sync>;

/// Refresh timing. [`Default`] is the production policy; tests shrink it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AwsCredentialRefreshTiming {
    /// Start a background refresh this long before expiry.
    pub refresh_before_expiry: Duration,
    /// Stop signing with a credential this long before its expiry.
    pub expiry_skew: Duration,
    /// Bound on one fetch and on a request's wait for one.
    pub fetch_timeout: Duration,
    /// Pause after a failed fetch before another one starts.
    pub retry_backoff: Duration,
}

impl Default for AwsCredentialRefreshTiming {
    fn default() -> Self {
        Self {
            refresh_before_expiry: DEFAULT_REFRESH_BEFORE_EXPIRY,
            expiry_skew: DEFAULT_EXPIRY_SKEW,
            fetch_timeout: DEFAULT_FETCH_TIMEOUT,
            retry_backoff: DEFAULT_RETRY_BACKOFF,
        }
    }
}

/// No usable credential could be produced for this request. `reason` is a
/// fixed, credential-free class suitable for an operator log.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AwsCredentialsUnavailable {
    pub reason: &'static str,
}

impl std::fmt::Display for AwsCredentialsUnavailable {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(self.reason)
    }
}

type FetchOutcome = Result<Arc<AwsCredentialSnapshot>, &'static str>;
type SharedFetch = Shared<BoxFuture<'static, FetchOutcome>>;
type CredentialClock = Arc<dyn Fn() -> SystemTime + Send + Sync>;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Freshness {
    Fresh,
    RefreshDue,
    Expired,
}

struct Inner {
    fetcher: AwsCredentialFetcher,
    timing: AwsCredentialRefreshTiming,
    clock: CredentialClock,
    current: ArcSwapOption<AwsCredentialSnapshot>,
    /// The fetch every waiter joins. Locked only to start or join a fetch,
    /// never on the fresh-credential path, and never across an `.await`.
    in_flight: Mutex<Option<SharedFetch>>,
    /// Lock-free hint that a fetch is running, so requests inside the refresh
    /// window do not touch the mutex.
    fetch_running: AtomicBool,
    /// Unix milliseconds before which no new fetch starts after a failure.
    retry_not_before_ms: AtomicU64,
    fetch_count: AtomicU64,
}

/// Lock-free credential cache with single-flight, refresh-ahead renewal.
#[derive(Clone)]
pub struct RefreshingAwsCredentials {
    inner: Arc<Inner>,
}

impl std::fmt::Debug for RefreshingAwsCredentials {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("RefreshingAwsCredentials")
            .field("timing", &self.inner.timing)
            .finish_non_exhaustive()
    }
}

impl RefreshingAwsCredentials {
    /// Cache over `fetcher` with the production refresh policy.
    pub fn new(fetcher: AwsCredentialFetcher) -> Self {
        Self::with_timing(fetcher, AwsCredentialRefreshTiming::default())
    }

    /// Cache over `fetcher` with explicit timing.
    pub fn with_timing(fetcher: AwsCredentialFetcher, timing: AwsCredentialRefreshTiming) -> Self {
        Self::with_timing_and_clock(fetcher, timing, SystemTime::now)
    }

    /// Cache over `fetcher` with explicit timing and a clock for credential
    /// expiry and retry backoff. The clock must use the same time basis as
    /// the snapshots' expiry timestamps; fetch timeouts still use Tokio time.
    pub fn with_timing_and_clock(
        fetcher: AwsCredentialFetcher,
        timing: AwsCredentialRefreshTiming,
        clock: impl Fn() -> SystemTime + Send + Sync + 'static,
    ) -> Self {
        Self {
            inner: Arc::new(Inner {
                fetcher,
                timing,
                clock: Arc::new(clock),
                current: ArcSwapOption::empty(),
                in_flight: Mutex::new(None),
                fetch_running: AtomicBool::new(false),
                retry_not_before_ms: AtomicU64::new(0),
                fetch_count: AtomicU64::new(0),
            }),
        }
    }

    /// How many fetches have been started. Diagnostics and tests.
    pub fn fetch_count(&self) -> u64 {
        self.inner.fetch_count.load(Ordering::Acquire)
    }

    /// A credential set that is safe to sign with now.
    ///
    /// Must be called inside a tokio runtime: a refresh is a spawned task.
    pub async fn credentials(
        &self,
    ) -> Result<Arc<AwsCredentialSnapshot>, AwsCredentialsUnavailable> {
        let now = (self.inner.clock)();
        if let Some(current) = self.inner.current.load_full() {
            match self.inner.freshness(&current, now) {
                Freshness::Fresh => return Ok(current),
                Freshness::RefreshDue => {
                    if !self.inner.fetch_running.load(Ordering::Acquire) {
                        // Started in the background; this request keeps the
                        // still-valid credential and never waits.
                        drop(Inner::start_or_join_fetch(&self.inner, now));
                    }
                    return Ok(current);
                }
                Freshness::Expired => {}
            }
        }

        let Some(fetch) = Inner::start_or_join_fetch(&self.inner, now) else {
            return Err(AwsCredentialsUnavailable {
                reason: "the credential provider failed recently; retry is backing off",
            });
        };
        match tokio::time::timeout(self.inner.timing.fetch_timeout, fetch).await {
            Ok(Ok(snapshot)) => {
                if self.inner.freshness(&snapshot, (self.inner.clock)()) == Freshness::Expired {
                    Err(AwsCredentialsUnavailable {
                        reason: "the credential provider returned expired credentials",
                    })
                } else {
                    Ok(snapshot)
                }
            }
            Ok(Err(reason)) => Err(AwsCredentialsUnavailable { reason }),
            Err(_) => Err(AwsCredentialsUnavailable {
                reason: "timed out waiting for the credential provider",
            }),
        }
    }
}

impl Inner {
    fn freshness(&self, snapshot: &AwsCredentialSnapshot, now: SystemTime) -> Freshness {
        let Some(expires_at) = snapshot.expires_at else {
            return Freshness::Fresh;
        };
        let usable_until = expires_at
            .checked_sub(self.timing.expiry_skew)
            .unwrap_or(UNIX_EPOCH);
        if now >= usable_until {
            return Freshness::Expired;
        }
        let refresh_at = expires_at
            .checked_sub(self.timing.refresh_before_expiry)
            .unwrap_or(UNIX_EPOCH);
        if now >= refresh_at {
            Freshness::RefreshDue
        } else {
            Freshness::Fresh
        }
    }

    /// Join the running fetch, or start one unless a recent failure is still
    /// backing off. `None` means no fetch is available to wait for.
    fn start_or_join_fetch(inner: &Arc<Self>, now: SystemTime) -> Option<SharedFetch> {
        let mut slot = inner
            .in_flight
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        if let Some(existing) = slot.as_ref() {
            return Some(existing.clone());
        }
        // A fetch that finished between the caller's snapshot read and this
        // lock already published its result; do not start another.
        if let Some(current) = inner.current.load_full()
            && inner.freshness(&current, (inner.clock)()) == Freshness::Fresh
        {
            let ready: BoxFuture<'static, FetchOutcome> =
                futures_util::future::ready(Ok(current)).boxed();
            return Some(ready.shared());
        }
        if unix_millis(now) < inner.retry_not_before_ms.load(Ordering::Acquire) {
            return None;
        }

        inner.fetch_count.fetch_add(1, Ordering::AcqRel);
        inner.fetch_running.store(true, Ordering::Release);
        let task_inner = Arc::clone(inner);
        // The task clears `in_flight` when it ends; it needs this lock to do
        // so, which orders that clear after the store below.
        let handle = tokio::spawn(async move { task_inner.run_fetch().await });
        let fetch: BoxFuture<'static, FetchOutcome> = async move {
            handle
                .await
                .unwrap_or(Err("the credential provider task failed"))
        }
        .boxed();
        let fetch = fetch.shared();
        *slot = Some(fetch.clone());
        Some(fetch)
    }

    async fn run_fetch(self: Arc<Self>) -> FetchOutcome {
        // Dropped last: the result is published before the slot is cleared, so
        // a caller that finds no fetch running also finds the new credential.
        let _clear = ClearInFlight(Arc::clone(&self));
        let outcome = match tokio::time::timeout(self.timing.fetch_timeout, (self.fetcher)()).await
        {
            Ok(Ok(snapshot)) => snapshot.validate().map(|()| snapshot),
            Ok(Err(_)) => Err("the credential provider returned no credentials"),
            Err(_) => Err("timed out waiting for the credential provider"),
        };
        let outcome = outcome.and_then(|snapshot| {
            if self.freshness(&snapshot, (self.clock)()) == Freshness::Expired {
                Err("the credential provider returned expired credentials")
            } else {
                Ok(Arc::new(snapshot))
            }
        });
        match outcome {
            Ok(snapshot) => {
                self.current.store(Some(Arc::clone(&snapshot)));
                self.retry_not_before_ms.store(0, Ordering::Release);
                Ok(snapshot)
            }
            Err(reason) => {
                let backoff_ms =
                    u64::try_from(self.timing.retry_backoff.as_millis()).unwrap_or(u64::MAX);
                self.retry_not_before_ms.store(
                    unix_millis((self.clock)()).saturating_add(backoff_ms),
                    Ordering::Release,
                );
                warn_sampled!(
                    reason = reason,
                    "AWS default-chain credential refresh failed"
                );
                Err(reason)
            }
        }
    }
}

/// Clears the in-flight fetch slot whenever the fetch task ends — including by
/// cancellation or unwinding — so a failed provider can never wedge future
/// refreshes.
struct ClearInFlight(Arc<Inner>);

impl Drop for ClearInFlight {
    fn drop(&mut self) {
        let mut slot = self
            .0
            .in_flight
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        *slot = None;
        self.0.fetch_running.store(false, Ordering::Release);
    }
}

fn unix_millis(time: SystemTime) -> u64 {
    time.duration_since(UNIX_EPOCH)
        .map(|elapsed| u64::try_from(elapsed.as_millis()).unwrap_or(u64::MAX))
        .unwrap_or(0)
}

/// Fetcher over the AWS SDK default credential chain for `region` (the region
/// is used for STS web-identity exchanges). The chain is built lazily on the
/// first fetch and reused afterwards.
///
/// Available only when the crate is built with the `secrets-aws` feature,
/// which already carries `aws-config` for the AWS Secrets Manager backend.
#[cfg(feature = "secrets-aws")]
pub fn aws_default_chain_fetcher(region: &str) -> AwsCredentialFetcher {
    use aws_config::default_provider::credentials::DefaultCredentialsChain;
    use aws_sdk_secretsmanager::config::ProvideCredentials as _;

    let chain: Arc<tokio::sync::OnceCell<DefaultCredentialsChain>> =
        Arc::new(tokio::sync::OnceCell::new());
    let region = region.to_string();
    Arc::new(move || -> AwsCredentialFetchFuture {
        let chain = Arc::clone(&chain);
        let region = region.clone();
        Box::pin(async move {
            let provider = chain
                .get_or_init(|| async move {
                    DefaultCredentialsChain::builder()
                        .region(aws_config::Region::new(region))
                        .build()
                        .await
                })
                .await;
            // The SDK error can name profile files and endpoints; keep the
            // diagnostic fixed rather than forwarding it.
            let credentials = match provider.provide_credentials().await {
                Ok(credentials) => credentials,
                Err(_) => {
                    return Err(
                        "the AWS default credential chain returned no credentials".to_string()
                    );
                }
            };
            Ok::<AwsCredentialSnapshot, String>(AwsCredentialSnapshot::new(
                credentials.access_key_id(),
                credentials.secret_access_key(),
                credentials.session_token().map(str::to_string),
                credentials.expiry(),
            ))
        })
    })
}
