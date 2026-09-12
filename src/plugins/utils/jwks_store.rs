//! JWKS (JSON Web Key Set) key store with background refresh.
//!
//! Fetches public keys from a remote JWKS endpoint and caches them
//! for JWT validation. Supports RSA (RS256, RS384, RS512) and
//! EC (ES256, ES384) key types.

use arc_swap::ArcSwap;
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use jsonwebtoken::{Algorithm, DecodingKey};
use serde::Deserialize;
use std::collections::HashMap;
use std::sync::Arc;
use std::sync::OnceLock;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;
use tokio::sync::{Mutex, Notify};
use tokio::time::Instant;
use tracing::{debug, warn};
use url::Url;

use super::PluginHttpClient;
use super::response_body::{BoundedReadError, read_response_body_bounded};

const EMPTY_STORE_RETRY_1: Duration = Duration::from_secs(5);
const EMPTY_STORE_RETRY_2: Duration = Duration::from_secs(15);
const EMPTY_STORE_RETRY_MAX: Duration = Duration::from_secs(30);
const MAX_JWKS_RESPONSE_BYTES: usize = 1024 * 1024;
const MAX_JWKS_KEYS: usize = 256;
const MAX_JWK_ID_BYTES: usize = 1024;
const MAX_JWK_COMPONENT_BYTES: usize = 16 * 1024;

/// Default maximum age of the last validated non-empty remote JWKS.
pub const DEFAULT_JWKS_MAX_STALE_SECONDS: u64 = 3_600;
/// Default minimum spacing between on-demand JWKS refetches triggered by a
/// token naming a `kid` the trusted snapshot does not contain.
pub const DEFAULT_KID_MISS_REFRESH_COOLDOWN_SECONDS: u64 = 30;
/// Hard ceiling for the configurable on-demand refetch cooldown.
pub const MAX_KID_MISS_REFRESH_COOLDOWN_SECONDS: u64 = 3_600;

/// Sentinel meaning "no on-demand refetch has ever been triggered".
const KID_MISS_NEVER_TRIGGERED: u64 = u64::MAX;
/// Hard ceiling for remote JWKS trust after the last validated non-empty fetch.
pub const MAX_JWKS_MAX_STALE_SECONDS: u64 = 86_400;

/// Fixed-cardinality trust state for a remote JWKS store.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum JwksTrustState {
    Fresh,
    Grace,
    Expired,
}

impl JwksTrustState {
    pub const ALL: [Self; 3] = [Self::Fresh, Self::Grace, Self::Expired];

    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Fresh => "fresh",
            Self::Grace => "grace",
            Self::Expired => "expired",
        }
    }
}

/// Bounded, fixed-cardinality outcome of the latest failed refresh attempt.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum JwksFailureClass {
    Empty,
    Transport,
    HttpStatus,
    Oversized,
    Malformed,
    UnusableKeys,
}

impl JwksFailureClass {
    pub const ALL: [Self; 6] = [
        Self::Empty,
        Self::Transport,
        Self::HttpStatus,
        Self::Oversized,
        Self::Malformed,
        Self::UnusableKeys,
    ];

    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Empty => "empty",
            Self::Transport => "transport",
            Self::HttpStatus => "http_status",
            Self::Oversized => "oversized",
            Self::Malformed => "malformed",
            Self::UnusableKeys => "unusable_keys",
        }
    }

    pub(crate) const fn index(self) -> usize {
        match self {
            Self::Empty => 0,
            Self::Transport => 1,
            Self::HttpStatus => 2,
            Self::Oversized => 3,
            Self::Malformed => 4,
            Self::UnusableKeys => 5,
        }
    }
}

static REFRESH_FAILURE_COUNTS: [AtomicU64; 6] = [
    AtomicU64::new(0),
    AtomicU64::new(0),
    AtomicU64::new(0),
    AtomicU64::new(0),
    AtomicU64::new(0),
    AtomicU64::new(0),
];

/// Process-wide hook so the shared cache can republish the O(1) trust-health
/// aggregate whenever a store's snapshot or policy changes.
static TRUST_CHANGE_HOOK: OnceLock<fn()> = OnceLock::new();

/// Register the shared-cache republish callback. Idempotent: the first
/// registration wins for the process lifetime.
pub fn register_trust_change_hook(hook: fn()) {
    let _ = TRUST_CHANGE_HOOK.set(hook);
}

fn note_trust_change() {
    if let Some(hook) = TRUST_CHANGE_HOOK.get() {
        hook();
    }
}

pub fn redacted_jwks_uri(raw: &str) -> String {
    let Ok(mut url) = Url::parse(raw) else {
        return "redacted-jwks-url".to_string();
    };
    let _ = url.set_username("");
    let _ = url.set_password(None);
    url.set_query(None);
    url.set_fragment(None);
    url.set_path("/");
    url.to_string()
}

/// A cached JWKS key with its algorithm and decoding key.
#[derive(Clone)]
pub struct CachedJwk {
    pub algorithm: Algorithm,
    pub decoding_key: DecodingKey,
}

struct JwksSnapshot {
    keys: Arc<HashMap<String, CachedJwk>>,
    last_success: Option<Instant>,
    last_attempt: Option<Instant>,
    last_failure: Option<JwksFailureClass>,
    consecutive_failures: u32,
}

struct JwksTrustPolicy {
    refresh_interval: Duration,
    max_stale: Duration,
}

/// Bounded on-demand refetch trigger for an unknown JWT `kid`.
///
/// The verifier signals this from the request path when a token names a key
/// identifier the trusted snapshot does not contain — the observable shape of
/// an identity provider rotating its signing key. Signalling is synchronous,
/// non-blocking, and allocation-free; the fetch itself happens on the store's
/// background refresh task, so the triggering request still fails closed.
struct KidMissTrigger {
    /// Woken by [`JwksKeyStore::request_refresh_on_kid_miss`]; selected on by
    /// the background refresh task alongside its periodic timer.
    notify: Notify,
    /// Minimum spacing between triggers, in milliseconds. `0` disables the
    /// on-demand refetch entirely.
    cooldown_ms: AtomicU64,
    /// Monotonic tick (`crate::socket_opts::monotonic_now_ms`) of the last
    /// admitted trigger, or [`KID_MISS_NEVER_TRIGGERED`]. Deliberately not
    /// wall time: an NTP step must not be able to disable or spam the trigger.
    last_trigger_ms: AtomicU64,
    /// Triggers admitted through the cooldown. Sanitized observability for
    /// tests and diagnostics: a count, never a `kid`.
    admitted: AtomicU64,
}

impl KidMissTrigger {
    fn new(cooldown: Duration) -> Self {
        Self {
            notify: Notify::new(),
            cooldown_ms: AtomicU64::new(duration_to_millis(cooldown)),
            last_trigger_ms: AtomicU64::new(KID_MISS_NEVER_TRIGGERED),
            admitted: AtomicU64::new(0),
        }
    }
}

fn duration_to_millis(value: Duration) -> u64 {
    u64::try_from(value.as_millis()).unwrap_or(u64::MAX)
}

/// Sanitized in-process health snapshot. It intentionally contains no URI,
/// key identifier, token, claim, or key material.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct JwksHealthSnapshot {
    pub trust_state: JwksTrustState,
    pub last_success_age: Option<Duration>,
    pub last_attempt_age: Option<Duration>,
    pub last_failure: Option<JwksFailureClass>,
    pub consecutive_failures: u32,
    pub retained_key_count: usize,
}

/// Thread-safe store of JWKS keys fetched from a remote endpoint.
///
/// Keys are cached in an `ArcSwap` for lock-free reads on the hot path.
/// A background task periodically refreshes the keys.
#[derive(Clone)]
pub struct JwksKeyStore {
    snapshot: Arc<ArcSwap<JwksSnapshot>>,
    trust_policy: Arc<ArcSwap<JwksTrustPolicy>>,
    jwks_uri: String,
    http_client: PluginHttpClient,
    fetch_lock: Arc<Mutex<()>>,
    refreshable: bool,
    /// Completed remote refresh attempts (success or failure). Used by tests
    /// and operators to observe forced reconfiguration refreshes without
    /// scraping endpoint URLs.
    refresh_completions: Arc<AtomicU64>,
    refresh_notify: Arc<Notify>,
    /// Rate-limited on-demand refetch trigger for an unknown JWT `kid`.
    kid_miss: Arc<KidMissTrigger>,
}

/// Raw JWKS response from the endpoint.
#[derive(Deserialize)]
struct JwksResponse {
    keys: Vec<JwkKey>,
}

/// A single JWK (JSON Web Key) from the JWKS endpoint.
#[derive(Deserialize)]
struct JwkKey {
    /// Key ID — used to match against the `kid` in JWT headers.
    kid: Option<String>,
    /// Key type: "RSA" or "EC".
    kty: String,
    /// Algorithm hint: "RS256", "ES256", etc.
    alg: Option<String>,
    /// Key use: "sig" (signing) or "enc" (encryption).
    #[serde(rename = "use")]
    key_use: Option<String>,
    /// Operations for which the key is intended (RFC 7517 section 4.3).
    key_ops: Option<Vec<String>>,

    // RSA parameters
    /// RSA modulus (base64url-encoded).
    n: Option<String>,
    /// RSA exponent (base64url-encoded).
    e: Option<String>,

    // EC parameters
    /// EC curve name: "P-256", "P-384".
    crv: Option<String>,
    /// EC x coordinate (base64url-encoded).
    x: Option<String>,
    /// EC y coordinate (base64url-encoded).
    y: Option<String>,
}

fn validate_jwk_field_sizes(jwk: &JwkKey) -> Result<(), String> {
    if jwk
        .kid
        .as_ref()
        .is_some_and(|value| value.len() > MAX_JWK_ID_BYTES)
    {
        return Err("JWK kid exceeds the supported length".to_string());
    }
    for (name, value) in [
        ("kty", Some(jwk.kty.as_str())),
        ("alg", jwk.alg.as_deref()),
        ("use", jwk.key_use.as_deref()),
        ("n", jwk.n.as_deref()),
        ("e", jwk.e.as_deref()),
        ("crv", jwk.crv.as_deref()),
        ("x", jwk.x.as_deref()),
        ("y", jwk.y.as_deref()),
    ] {
        if value.is_some_and(|value| value.len() > MAX_JWK_COMPONENT_BYTES) {
            return Err(format!("JWK {name} exceeds the supported length"));
        }
    }
    if let Some(key_ops) = jwk.key_ops.as_ref() {
        if key_ops.len() > 16 {
            return Err("JWK key_ops contains too many operations".to_string());
        }
        if key_ops
            .iter()
            .any(|operation| operation.len() > MAX_JWK_COMPONENT_BYTES)
        {
            return Err("JWK key_ops operation exceeds the supported length".to_string());
        }
    }
    Ok(())
}

fn required_jwk_kid(jwk: &JwkKey) -> Result<&str, String> {
    match jwk.kid.as_deref() {
        Some(kid) if !kid.is_empty() => Ok(kid),
        _ => Err("JWK kid must be non-empty".to_string()),
    }
}

fn validate_jwk_verification_use(jwk: &JwkKey) -> Result<(), String> {
    if let Some(key_use) = jwk.key_use.as_deref()
        && key_use != "sig"
    {
        return Err(format!(
            "JWK use '{key_use}' does not permit signature verification"
        ));
    }
    if let Some(key_ops) = jwk.key_ops.as_ref()
        && !key_ops.iter().any(|operation| operation == "verify")
    {
        return Err("JWK key_ops does not include 'verify'".to_string());
    }
    if jwk.key_use.as_deref() == Some("sig")
        && jwk.key_ops.as_ref().is_some_and(|key_ops| {
            key_ops
                .iter()
                .any(|operation| !matches!(operation.as_str(), "sign" | "verify"))
        })
    {
        return Err("JWK use 'sig' conflicts with key_ops".to_string());
    }
    Ok(())
}

impl JwksKeyStore {
    /// Create a new key store for the given JWKS URI.
    ///
    /// Does NOT fetch keys immediately — call [`fetch_keys`] or
    /// [`start_background_refresh`] after construction.
    pub fn new(jwks_uri: String, http_client: PluginHttpClient) -> Self {
        Self {
            snapshot: Arc::new(ArcSwap::from_pointee(JwksSnapshot {
                keys: Arc::new(HashMap::new()),
                last_success: None,
                last_attempt: None,
                last_failure: None,
                consecutive_failures: 0,
            })),
            trust_policy: Arc::new(ArcSwap::from_pointee(JwksTrustPolicy {
                refresh_interval: Duration::from_secs(900),
                max_stale: Duration::from_secs(DEFAULT_JWKS_MAX_STALE_SECONDS),
            })),
            jwks_uri,
            http_client,
            fetch_lock: Arc::new(Mutex::new(())),
            refreshable: true,
            refresh_completions: Arc::new(AtomicU64::new(0)),
            refresh_notify: Arc::new(Notify::new()),
            kid_miss: Arc::new(KidMissTrigger::new(Duration::from_secs(
                DEFAULT_KID_MISS_REFRESH_COOLDOWN_SECONDS,
            ))),
        }
    }

    /// Create a non-refreshing key store from inline JWKS JSON.
    pub fn from_inline_jwks(jwks_json: &str) -> Result<Self, String> {
        let jwks: JwksResponse = serde_json::from_str(jwks_json)
            .map_err(|e| format!("inline JWKS parse failed: {}", e))?;
        let keys = Self::parse_jwks_response(&jwks)?;

        Ok(Self {
            snapshot: Arc::new(ArcSwap::from_pointee(JwksSnapshot {
                keys: Arc::new(keys),
                last_success: None,
                last_attempt: None,
                last_failure: None,
                consecutive_failures: 0,
            })),
            trust_policy: Arc::new(ArcSwap::from_pointee(JwksTrustPolicy {
                refresh_interval: Duration::MAX,
                max_stale: Duration::MAX,
            })),
            jwks_uri: "inline".to_string(),
            http_client: PluginHttpClient::default(),
            fetch_lock: Arc::new(Mutex::new(())),
            refreshable: false,
            refresh_completions: Arc::new(AtomicU64::new(0)),
            refresh_notify: Arc::new(Notify::new()),
            // Inline stores never refetch; the trigger stays inert.
            kid_miss: Arc::new(KidMissTrigger::new(Duration::ZERO)),
        })
    }

    /// Get the JWKS URI this store fetches keys from.
    pub fn jwks_uri(&self) -> &str {
        &self.jwks_uri
    }

    /// Whether this store fetches keys from an external JWKS URI.
    pub fn is_refreshable(&self) -> bool {
        self.refreshable
    }

    /// Atomically install the effective policy selected by the shared cache.
    ///
    /// Does not publish trust-health changes. Shared-cache callers often hold a
    /// `DashMap` entry/`get_mut`/`retain` guard; invoking the process-wide
    /// republish hook here would re-enter the same map and self-deadlock.
    /// Cache boundaries republish after those guards are dropped. Refresh
    /// success/failure still publishes through the store refresh-completion path.
    pub fn configure_trust_policy(&self, refresh_interval: Duration, max_stale: Duration) {
        self.trust_policy.store(Arc::new(JwksTrustPolicy {
            refresh_interval,
            max_stale,
        }));
    }

    /// Install the effective on-demand refetch cooldown for this store.
    ///
    /// `Duration::ZERO` disables the unknown-`kid` refetch. Shared stores take
    /// the most restrictive cooldown among their active consumers, so a
    /// consumer that disables the behaviour disables it for the shared store.
    pub fn configure_kid_miss_cooldown(&self, cooldown: Duration) {
        self.kid_miss
            .cooldown_ms
            .store(duration_to_millis(cooldown), Ordering::Release);
    }

    /// Currently installed on-demand refetch cooldown.
    #[allow(dead_code)] // external unit tests assert the effective policy
    pub fn kid_miss_cooldown(&self) -> Duration {
        Duration::from_millis(self.kid_miss.cooldown_ms.load(Ordering::Acquire))
    }

    /// Ask the background refresh task for one out-of-band JWKS fetch because
    /// a token named a `kid` the trusted snapshot does not contain.
    ///
    /// Called from the request path: synchronous, non-blocking, and
    /// allocation-free. At most one fetch is requested per cooldown window, so
    /// a flood of tokens carrying random identifiers cannot become a fetch
    /// storm against the identity provider. The caller does not await the
    /// fetch — the request that observed the miss still fails closed, and a
    /// later request verifies once the refreshed snapshot is published.
    ///
    /// No `kid`, token, claim, or key material is recorded or logged here.
    #[inline]
    pub fn request_refresh_on_kid_miss(&self) {
        if !self.refreshable {
            return;
        }
        let cooldown_ms = self.kid_miss.cooldown_ms.load(Ordering::Acquire);
        if cooldown_ms == 0 {
            return;
        }
        let now = crate::socket_opts::monotonic_now_ms();
        let mut observed = self.kid_miss.last_trigger_ms.load(Ordering::Acquire);
        loop {
            if observed != KID_MISS_NEVER_TRIGGERED && now.saturating_sub(observed) < cooldown_ms {
                return;
            }
            match self.kid_miss.last_trigger_ms.compare_exchange_weak(
                observed,
                now,
                Ordering::AcqRel,
                Ordering::Acquire,
            ) {
                // Exactly one concurrent caller wins the window and signals.
                Ok(_) => break,
                Err(current) => observed = current,
            }
        }
        self.kid_miss.admitted.fetch_add(1, Ordering::Relaxed);
        self.kid_miss.notify.notify_one();
    }

    /// Number of unknown-`kid` refetch triggers admitted through the cooldown.
    ///
    /// A count only — no key identifier, token, or claim is retained anywhere
    /// on this path.
    #[allow(dead_code)] // external unit tests assert the rate-limit contract
    pub fn kid_miss_refresh_requests(&self) -> u64 {
        self.kid_miss.admitted.load(Ordering::Relaxed)
    }

    /// Monotonic deadline when this remote store's retained keys become
    /// untrusted. `None` for inline stores or stores that have never succeeded.
    pub fn expiry_deadline(&self) -> Option<Instant> {
        if !self.refreshable {
            return None;
        }
        let snapshot = self.snapshot.load();
        let last_success = snapshot.last_success?;
        let max_stale = self.trust_policy.load().max_stale;
        Some(last_success + max_stale)
    }

    /// Monotonic deadline when a still-fresh remote store enters grace because
    /// its refresh interval elapsed. Stores already in grace/expired return
    /// `None`.
    pub fn grace_deadline(&self) -> Option<Instant> {
        if !self.refreshable {
            return None;
        }
        let snapshot = self.snapshot.load();
        if snapshot.last_failure.is_some() {
            return None;
        }
        let last_success = snapshot.last_success?;
        let policy = self.trust_policy.load();
        let grace_at = last_success + policy.refresh_interval;
        let expires_at = last_success + policy.max_stale;
        if grace_at >= expires_at {
            None
        } else {
            Some(grace_at)
        }
    }

    /// Number of completed remote refresh attempts (success or failure).
    #[allow(dead_code)] // external unit tests observe refresh sync; dead in the binary target
    pub fn refresh_completions(&self) -> u64 {
        self.refresh_completions.load(Ordering::Acquire)
    }

    /// Wait until a remote refresh attempt completes after `before`.
    ///
    /// Uses the store's completion notify so callers under a paused Tokio clock
    /// do not need to sleep through virtual time to observe a forced refresh.
    /// Subscribe before reading the counter so a completion that races the
    /// check cannot be lost between the load and `notified().await`.
    #[allow(dead_code)] // external unit tests observe refresh sync; dead in the binary target
    pub async fn wait_for_refresh_completion_after(&self, before: u64) {
        loop {
            let notified = self.refresh_notify.notified();
            if self.refresh_completions() > before {
                return;
            }
            notified.await;
        }
    }

    fn note_refresh_completion(&self) {
        self.refresh_completions.fetch_add(1, Ordering::AcqRel);
        self.refresh_notify.notify_waiters();
        note_trust_change();
    }

    fn trust_state_for_snapshot(&self, snapshot: &JwksSnapshot, now: Instant) -> JwksTrustState {
        if !self.refreshable {
            return if snapshot.keys.is_empty() {
                JwksTrustState::Expired
            } else {
                JwksTrustState::Fresh
            };
        }
        let Some(last_success) = snapshot.last_success else {
            return JwksTrustState::Expired;
        };
        let age = now.saturating_duration_since(last_success);
        let policy = self.trust_policy.load();
        if age >= policy.max_stale {
            JwksTrustState::Expired
        } else if snapshot.last_failure.is_some() || age >= policy.refresh_interval {
            JwksTrustState::Grace
        } else {
            JwksTrustState::Fresh
        }
    }

    /// Current sanitized health state for metrics and diagnostics.
    pub fn health_snapshot(&self) -> JwksHealthSnapshot {
        let now = Instant::now();
        let snapshot = self.snapshot.load();
        JwksHealthSnapshot {
            trust_state: self.trust_state_for_snapshot(&snapshot, now),
            last_success_age: snapshot
                .last_success
                .map(|instant| now.saturating_duration_since(instant)),
            last_attempt_age: snapshot
                .last_attempt
                .map(|instant| now.saturating_duration_since(instant)),
            last_failure: snapshot.last_failure,
            consecutive_failures: snapshot.consecutive_failures,
            retained_key_count: snapshot.keys.len(),
        }
    }

    /// Process-wide refresh-failure counters in [`JwksFailureClass::ALL`] order.
    pub fn refresh_failure_counts() -> [u64; 6] {
        std::array::from_fn(|index| REFRESH_FAILURE_COUNTS[index].load(Ordering::Relaxed))
    }

    /// Return one lock-free key snapshot only while its trust deadline holds.
    pub fn trusted_keys(&self) -> Option<Arc<HashMap<String, CachedJwk>>> {
        let snapshot = self.snapshot.load();
        (self.trust_state_for_snapshot(&snapshot, Instant::now()) != JwksTrustState::Expired)
            .then(|| Arc::clone(&snapshot.keys))
    }

    /// Returns true if diagnostic/recovery state retains any cached keys.
    pub fn has_keys(&self) -> bool {
        !self.snapshot.load().keys.is_empty()
    }

    /// Fetch keys from the JWKS endpoint and update the cache.
    pub async fn fetch_keys(&self) -> Result<usize, String> {
        let _fetch_guard = self.fetch_lock.lock().await;
        self.fetch_keys_unlocked().await
    }

    /// Fetch keys unless the store already has a fresh successful snapshot.
    ///
    /// This lets an eager warmup share the store's immediate background refresh
    /// without issuing a second successful request, while expired or failed
    /// stores still retry immediately after worker reconfiguration.
    pub async fn fetch_keys_if_empty(&self) -> Result<usize, String> {
        let _fetch_guard = self.fetch_lock.lock().await;
        let snapshot = self.snapshot.load();
        let may_skip = !snapshot.keys.is_empty()
            && snapshot.last_failure.is_none()
            && self.trust_state_for_snapshot(&snapshot, Instant::now()) == JwksTrustState::Fresh;
        if may_skip {
            return Ok(snapshot.keys.len());
        }
        drop(snapshot);
        self.fetch_keys_unlocked().await
    }

    async fn fetch_keys_unlocked(&self) -> Result<usize, String> {
        if !self.refreshable {
            return Ok(self.snapshot.load().keys.len());
        }

        let redacted_uri = redacted_jwks_uri(&self.jwks_uri);
        debug!("Fetching JWKS keys from {}", redacted_uri);

        let Some(client) = self.http_client.get().ok() else {
            return self.fail_refresh(JwksFailureClass::Transport);
        };
        let req = client.get(&self.jwks_uri);
        let response = match self
            .http_client
            .execute_redacted(req, "jwks_fetch", &redacted_uri)
            .await
        {
            Ok(response) => response,
            Err(_) => return self.fail_refresh(JwksFailureClass::Transport),
        };

        if !response.status().is_success() {
            return self.fail_refresh(JwksFailureClass::HttpStatus);
        }

        let body = match read_response_body_bounded(response, MAX_JWKS_RESPONSE_BYTES).await {
            Ok(body) => body,
            Err(BoundedReadError::LimitExceeded { .. }) => {
                return self.fail_refresh(JwksFailureClass::Oversized);
            }
            Err(BoundedReadError::Stream(_)) => {
                return self.fail_refresh(JwksFailureClass::Transport);
            }
        };
        let jwks: JwksResponse = match serde_json::from_slice(&body) {
            Ok(jwks) => jwks,
            Err(_) => return self.fail_refresh(JwksFailureClass::Malformed),
        };

        let new_keys = match Self::parse_jwks_response(&jwks) {
            Ok(keys) => keys,
            Err(_) => return self.fail_refresh(JwksFailureClass::UnusableKeys),
        };

        // An authoritative empty 200 is a failed trust refresh. Retain the
        // last-known-good map for bounded grace, diagnostics, and immediate
        // recovery, but never advance its monotonic trust deadline.
        if new_keys.is_empty() {
            warn!(
                "JWKS endpoint at {} returned 0 usable keys; retaining bounded last-known-good state",
                redacted_uri
            );
            return self.fail_refresh(JwksFailureClass::Empty);
        }

        let count = new_keys.len();
        let completed_at = Instant::now();
        self.snapshot.store(Arc::new(JwksSnapshot {
            keys: Arc::new(new_keys),
            last_success: Some(completed_at),
            last_attempt: Some(completed_at),
            last_failure: None,
            consecutive_failures: 0,
        }));
        self.note_refresh_completion();
        debug!("JWKS key store updated: {} keys cached", count);
        Ok(count)
    }

    fn fail_refresh<T>(&self, class: JwksFailureClass) -> Result<T, String> {
        REFRESH_FAILURE_COUNTS[class.index()].fetch_add(1, Ordering::Relaxed);
        let attempted_at = Instant::now();
        let current = self.snapshot.load();
        self.snapshot.store(Arc::new(JwksSnapshot {
            keys: Arc::clone(&current.keys),
            last_success: current.last_success,
            last_attempt: Some(attempted_at),
            last_failure: Some(class),
            consecutive_failures: current.consecutive_failures.saturating_add(1),
        }));
        self.note_refresh_completion();
        Err(format!("JWKS refresh failed: {}", class.as_str()))
    }

    fn parse_jwks_response(jwks: &JwksResponse) -> Result<HashMap<String, CachedJwk>, String> {
        let total_keys = jwks.keys.len();
        if total_keys > MAX_JWKS_KEYS {
            return Err(format!(
                "JWKS response contains {total_keys} keys, exceeding the limit of {MAX_JWKS_KEYS}"
            ));
        }
        let mut new_keys = HashMap::new();

        for (idx, jwk) in jwks.keys.iter().enumerate() {
            let parsed = required_jwk_kid(jwk).and_then(|kid| {
                validate_jwk_field_sizes(jwk)?;
                validate_jwk_verification_use(jwk)?;
                let cached = Self::parse_jwk(jwk)?;
                Ok((kid.to_string(), cached))
            });
            match parsed {
                Ok((kid, cached)) => {
                    if new_keys.insert(kid, cached).is_some() {
                        return Err("JWKS response contains duplicate kid".to_string());
                    }
                }
                Err(_) => {
                    warn!("Skipping invalid or unsupported JWKS key at index {}", idx);
                }
            }
        }

        let count = new_keys.len();
        if count == 0 && total_keys > 0 {
            return Err(
                "JWKS response contained keys but no usable signing keys were parsed".to_string(),
            );
        }

        Ok(new_keys)
    }

    /// Start a background task that refreshes keys periodically.
    ///
    /// The task runs until the returned [`tokio::task::JoinHandle`] is aborted
    /// or the process exits. Populated stores keep the configured refresh cadence
    /// based on fetch start time; every failed refresh (including an empty 200)
    /// retries on a short capped backoff without advancing key trust.
    pub fn start_background_refresh(&self, interval: Duration) -> tokio::task::JoinHandle<()> {
        self.start_background_refresh_task(interval, false)
    }

    /// Replace a background task after publishing a changed refresh policy.
    ///
    /// Unlike ordinary startup, the first iteration contacts the endpoint
    /// before waiting on the timer wheel. A retained snapshot may be fresh
    /// under the new policy but close enough to its stricter deadline that
    /// waiting a full interval would leave it expired before the next
    /// recovery attempt. Skipping the initial `sleep_until` is also required
    /// for correctness under a paused Tokio clock: `sleep_until(now)` is not
    /// guaranteed to fire until time advances past the deadline.
    pub(crate) fn start_background_refresh_after_policy_change(
        &self,
        interval: Duration,
    ) -> tokio::task::JoinHandle<()> {
        self.start_background_refresh_task(interval, true)
    }

    fn start_background_refresh_task(
        &self,
        interval: Duration,
        force_first_refresh: bool,
    ) -> tokio::task::JoinHandle<()> {
        let store = self.clone();
        let interval = if interval.is_zero() {
            Duration::from_secs(1)
        } else {
            interval
        };
        tokio::spawn(tokio::task::unconstrained(async move {
            let mut empty_store_retry_attempt = 0;
            let mut next_refresh_at = Instant::now();
            let mut first_refresh = true;
            loop {
                // Policy reconfiguration must hit the endpoint immediately.
                // Do not register a zero-delay timer for that first pass —
                // under a frozen/paused clock the timer may never become ready
                // until time is advanced, which would miss the stricter
                // max-stale window the reconfiguration exists to honor.
                // `unconstrained` keeps that first fetch from being fairness-
                // delayed behind unrelated tasks under the full/coverage matrix.
                //
                // Every pass AFTER the first also races the unknown-`kid`
                // trigger. The notify arm registers no timer, so the
                // paused-clock guarantee above is unchanged: a kid-miss wake is
                // driven purely by the signalling request, not by virtual time.
                // The first pass is deliberately excluded — it is already about
                // to fetch, and a trigger raised before it runs is not lost:
                // `notify_one` leaves a permit the next `notified()` consumes.
                let mut woke_on_kid_miss = false;
                if first_refresh {
                    if !force_first_refresh {
                        tokio::time::sleep_until(next_refresh_at).await;
                    }
                } else {
                    tokio::select! {
                        _ = tokio::time::sleep_until(next_refresh_at) => {}
                        _ = store.kid_miss.notify.notified() => {
                            woke_on_kid_miss = true;
                        }
                    }
                }
                let fetch_started_at = Instant::now();

                let fetch_result = if first_refresh && !force_first_refresh {
                    store.fetch_keys_if_empty().await
                } else {
                    // A kid-miss wake always contacts the endpoint: skipping a
                    // fetch because the snapshot still looks fresh is exactly
                    // the stale state the trigger exists to escape.
                    store.fetch_keys().await
                };
                first_refresh = false;

                let refresh_succeeded = fetch_result.is_ok();
                if let Err(e) = fetch_result {
                    warn!("JWKS background refresh failed: {}", e);
                }

                // An on-demand fetch is strictly out of band. It leaves the
                // periodic deadline and the empty-store retry backoff exactly
                // as the scheduled cadence left them, so request-driven
                // refetches can never tighten the configured interval.
                if !woke_on_kid_miss {
                    let fetch_completed_at = Instant::now();
                    next_refresh_at = next_refresh_deadline(
                        fetch_started_at,
                        fetch_completed_at,
                        refresh_succeeded,
                        interval,
                        empty_store_retry_attempt,
                    );

                    if refresh_succeeded {
                        empty_store_retry_attempt = 0;
                    } else {
                        empty_store_retry_attempt = empty_store_retry_attempt.saturating_add(1);
                    }
                }
            }
        }))
    }

    /// Parse a single JWK into a cached key.
    fn parse_jwk(jwk: &JwkKey) -> Result<CachedJwk, String> {
        match jwk.kty.as_str() {
            "RSA" => Self::parse_rsa_jwk(jwk),
            "EC" => Self::parse_ec_jwk(jwk),
            other => Err(format!("unsupported key type: {}", other)),
        }
    }

    /// Parse an RSA JWK.
    fn parse_rsa_jwk(jwk: &JwkKey) -> Result<CachedJwk, String> {
        let n = jwk.n.as_deref().ok_or("missing RSA modulus 'n'")?;
        let e = jwk.e.as_deref().ok_or("missing RSA exponent 'e'")?;

        let n_bytes = URL_SAFE_NO_PAD
            .decode(n)
            .map_err(|e| format!("invalid base64url in 'n': {}", e))?;
        let e_bytes = URL_SAFE_NO_PAD
            .decode(e)
            .map_err(|e| format!("invalid base64url in 'e': {}", e))?;

        // Approved RSA strength. A JWKS is fetched from an operator-configured
        // issuer, so a weak signing key admitted here would make that issuer's
        // compromise Ferrum's authentication failure. Only public components
        // are inspected, and diagnostics report strength/form without
        // reproducing key bytes.
        crate::fips::keys::check_jwk_rsa_modulus_enforced(&n_bytes)?;
        crate::fips::keys::check_jwk_rsa_public_key(&n_bytes, &e_bytes)?;

        // RFC 7517 §4.4: `alg` identifies the algorithm intended for use with
        // the key. Defaulting every unrecognized value to RS256 admitted keys
        // the issuer published for a different purpose entirely — RSA-OAEP /
        // RSA1_5 encryption keys, and PSS keys — as PKCS#1 v1.5
        // signature-verification keys, which is cross-algorithm use of the
        // issuer's key material. Only an absent `alg` falls back to RS256; any
        // present value must name a supported RSA signature algorithm, and it
        // then binds verification to exactly that algorithm because
        // `build_validation` seeds `Validation::new` from it.
        let algorithm = match jwk.alg.as_deref() {
            None | Some("RS256") => Algorithm::RS256,
            Some("RS384") => Algorithm::RS384,
            Some("RS512") => Algorithm::RS512,
            Some(other) => {
                return Err(format!(
                    "JWK alg '{other}' is not a supported RSA signature algorithm"
                ));
            }
        };

        let decoding_key = DecodingKey::from_rsa_raw_components(&n_bytes, &e_bytes);

        Ok(CachedJwk {
            algorithm,
            decoding_key,
        })
    }

    /// Parse an EC (Elliptic Curve) JWK.
    fn parse_ec_jwk(jwk: &JwkKey) -> Result<CachedJwk, String> {
        let x = jwk.x.as_deref().ok_or("missing EC coordinate 'x'")?;
        let y = jwk.y.as_deref().ok_or("missing EC coordinate 'y'")?;

        let x_bytes = URL_SAFE_NO_PAD
            .decode(x)
            .map_err(|e| format!("invalid base64url in 'x': {e}"))?;
        let y_bytes = URL_SAFE_NO_PAD
            .decode(y)
            .map_err(|e| format!("invalid base64url in 'y': {e}"))?;
        crate::fips::keys::check_jwk_ec_public_key(jwk.crv.as_deref(), &x_bytes, &y_bytes)?;

        let algorithm = match jwk.crv.as_deref() {
            Some("P-384") => Algorithm::ES384,
            Some("P-256") | None => Algorithm::ES256,
            Some(other) => return Err(format!("unsupported EC curve: {}", other)),
        };

        // RFC 7517 §4.4: a present `alg` must name a supported EC signature
        // algorithm AND agree with the curve. Previously a contradicting or
        // non-signature `alg` (`ECDH-ES`, `ES512` on a P-256 key) was silently
        // ignored in favour of the curve-derived algorithm, so a key published
        // for key agreement was admitted for signature verification.
        match jwk.alg.as_deref() {
            None => {}
            Some("ES256") if algorithm == Algorithm::ES256 => {}
            Some("ES384") if algorithm == Algorithm::ES384 => {}
            Some(other) => {
                return Err(format!(
                    "JWK alg '{other}' is not a supported EC signature algorithm for this curve"
                ));
            }
        }

        // from_ec_components takes base64url-encoded strings directly
        let decoding_key = DecodingKey::from_ec_components(x, y)
            .map_err(|e| format!("invalid EC key components: {}", e))?;

        Ok(CachedJwk {
            algorithm,
            decoding_key,
        })
    }
}

fn refresh_delay_after_attempt(
    refresh_succeeded: bool,
    interval: Duration,
    failed_refresh_attempt: u32,
) -> Duration {
    if refresh_succeeded {
        interval
    } else {
        std::cmp::min(interval, empty_store_retry_interval(failed_refresh_attempt))
    }
}

fn empty_store_retry_interval(empty_store_retry_attempt: u32) -> Duration {
    match empty_store_retry_attempt {
        0 => EMPTY_STORE_RETRY_1,
        1 => EMPTY_STORE_RETRY_2,
        _ => EMPTY_STORE_RETRY_MAX,
    }
}

fn next_refresh_deadline(
    fetch_started_at: Instant,
    fetch_completed_at: Instant,
    refresh_succeeded: bool,
    interval: Duration,
    failed_refresh_attempt: u32,
) -> Instant {
    if refresh_succeeded {
        fetch_started_at + interval
    } else {
        fetch_completed_at + refresh_delay_after_attempt(false, interval, failed_refresh_attempt)
    }
}

#[cfg(test)]
mod tests {
    use super::{
        EMPTY_STORE_RETRY_1, EMPTY_STORE_RETRY_2, EMPTY_STORE_RETRY_MAX, JwksKeyStore,
        JwksResponse, MAX_JWK_ID_BYTES, MAX_JWKS_KEYS, empty_store_retry_interval,
        next_refresh_deadline, refresh_delay_after_attempt,
    };
    use serde_json::json;
    use std::time::Duration;
    use tokio::time::Instant;

    #[test]
    fn successful_refresh_uses_configured_refresh_interval() {
        let interval = Duration::from_secs(900);
        assert_eq!(refresh_delay_after_attempt(true, interval, 2), interval);
    }

    #[test]
    fn failed_refresh_backs_off_until_capped_when_interval_is_longer() {
        assert_eq!(
            refresh_delay_after_attempt(false, Duration::from_secs(900), 0),
            EMPTY_STORE_RETRY_1
        );
        assert_eq!(
            refresh_delay_after_attempt(false, Duration::from_secs(900), 1),
            EMPTY_STORE_RETRY_2
        );
        assert_eq!(
            refresh_delay_after_attempt(false, Duration::from_secs(900), 2),
            EMPTY_STORE_RETRY_MAX
        );
        assert_eq!(
            refresh_delay_after_attempt(false, Duration::from_secs(900), 12),
            EMPTY_STORE_RETRY_MAX
        );
    }

    #[test]
    fn failed_refresh_keeps_shorter_configured_interval() {
        let interval = Duration::from_secs(2);
        assert_eq!(refresh_delay_after_attempt(false, interval, 0), interval);
        assert_eq!(refresh_delay_after_attempt(false, interval, 1), interval);
        assert_eq!(refresh_delay_after_attempt(false, interval, 2), interval);
    }

    #[test]
    fn empty_store_retry_interval_uses_five_fifteen_thirty_sequence() {
        assert_eq!(empty_store_retry_interval(0), EMPTY_STORE_RETRY_1);
        assert_eq!(empty_store_retry_interval(1), EMPTY_STORE_RETRY_2);
        assert_eq!(empty_store_retry_interval(2), EMPTY_STORE_RETRY_MAX);
        assert_eq!(empty_store_retry_interval(u32::MAX), EMPTY_STORE_RETRY_MAX);
    }

    #[test]
    fn successful_refresh_next_deadline_is_based_on_fetch_start() {
        let started = Instant::now();
        let completed = started + Duration::from_secs(10);
        let interval = Duration::from_secs(60);

        assert_eq!(
            next_refresh_deadline(started, completed, true, interval, 0),
            started + interval
        );
    }

    #[test]
    fn failed_refresh_next_retry_is_based_on_fetch_completion() {
        let started = Instant::now();
        let completed = started + Duration::from_secs(10);
        let interval = Duration::from_secs(900);

        assert_eq!(
            next_refresh_deadline(started, completed, false, interval, 1),
            completed + EMPTY_STORE_RETRY_2
        );
    }

    #[test]
    fn jwks_key_count_is_bounded() {
        let keys = (0..=MAX_JWKS_KEYS)
            .map(|idx| {
                json!({
                    "kty": "RSA",
                    "kid": format!("key-{idx}"),
                    "n": "AQAB",
                    "e": "AQAB"
                })
            })
            .collect::<Vec<_>>();
        let response: JwksResponse =
            serde_json::from_value(json!({"keys": keys})).expect("test JWKS parses");

        assert!(JwksKeyStore::parse_jwks_response(&response).is_err());
    }

    #[test]
    fn oversized_jwk_identifier_is_rejected() {
        let response: JwksResponse = serde_json::from_value(json!({"keys": [{
            "kty": "RSA",
            "kid": "x".repeat(MAX_JWK_ID_BYTES + 1),
            "n": "AQAB",
            "e": "AQAB"
        }]}))
        .expect("test JWKS parses");

        assert!(JwksKeyStore::parse_jwks_response(&response).is_err());
    }
}
