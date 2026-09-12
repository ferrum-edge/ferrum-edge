//! Shared rate-limit algorithms plus local/Redis/failover storage adapters.

use crate::plugins::utils::log_sampling::warn_sampled;

use async_trait::async_trait;
use dashmap::DashMap;
use serde_json::Value;
use std::collections::{HashMap, VecDeque};
use std::hash::Hash;
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, OnceLock, Weak};
use std::time::{Duration, Instant};
use tracing::{info, warn};

use super::http_client::PluginHttpClient;
use super::redis_rate_limiter::{RedisConfig, RedisRateLimitClient};

/// Root config keys every Redis-backed rate-limit plugin accepts.
///
/// This is [`super::redis_rate_limiter::REDIS_PLUGIN_CONFIG_KEYS`] plus
/// `redis_failure_policy`, which is meaningful only for enforcement plugins
/// (`request_deduplication` expresses the same choice as `on_redis_unavailable`,
/// and a cache has no enforcement decision to fail closed on). Plugins with a
/// closed root key set must union this — not the shared Redis list — with their
/// own policy keys, or a supplied `redis_failure_policy` would be rejected.
///
/// Parity with the shared list is asserted by
/// [`debug_assert_rate_limit_redis_keys`].
pub const RATE_LIMIT_REDIS_CONFIG_KEYS: &[&str] = &[
    "sync_mode",
    "redis_url",
    "redis_tls",
    "redis_key_prefix",
    "redis_pool_size",
    "redis_connect_timeout_seconds",
    "redis_health_check_interval_seconds",
    "redis_username",
    "redis_password",
    "redis_failure_policy",
];

/// HTTP status for a refusal caused by unavailable centralized enforcement.
///
/// Deliberately not `429`: the caller is not over its budget, the budget simply
/// cannot be evaluated. `503` also keeps rate-limit dashboards from counting an
/// infrastructure outage as client abuse.
pub const ENFORCEMENT_UNAVAILABLE_STATUS: u16 = 503;

/// Client-facing message for [`ENFORCEMENT_UNAVAILABLE_STATUS`]. Names no
/// endpoint, key, credential, or backend detail — an unauthenticated caller
/// must not learn that a Redis endpoint exists, let alone its state.
pub const ENFORCEMENT_UNAVAILABLE_MESSAGE: &str =
    "Rate limit enforcement is temporarily unavailable";

/// JSON body paired with [`ENFORCEMENT_UNAVAILABLE_STATUS`].
pub const ENFORCEMENT_UNAVAILABLE_BODY: &str =
    r#"{"error":"Rate limit enforcement is temporarily unavailable"}"#;

/// Config value of `redis_failure_policy`, i.e. what a Redis-backed rate-limit
/// policy does when the centralized store cannot be consulted — an outage, an
/// egress/DNS screen failure, or an endpoint rejected as an unsupported
/// topology (Redis Cluster).
///
/// The default is [`RedisFailurePolicy::FailClosed`]. `sync_mode: "redis"` is
/// chosen precisely because a budget must hold *across* gateway processes;
/// silently continuing on per-process counters turns one distributed budget into
/// N independent ones, so a client can multiply the configured limit by the
/// number of data planes it can reach. Preserving availability through an
/// outage remains supported, but only as an explicit operator decision.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RedisFailurePolicy {
    /// Deny while centralized enforcement is unavailable. Default.
    FailClosed,
    /// Explicitly accept per-process budgets during an outage: fall back to the
    /// in-memory limiter, which enforces the configured limit once per gateway.
    LocalFallback,
}

/// Parse `redis_failure_policy` from a plugin's root config object.
///
/// Validated even when `sync_mode` is not `"redis"` (same rationale as the
/// shared Redis field parser): toggling sync mode later must not suddenly
/// activate a value admission never checked.
pub fn parse_redis_failure_policy(config: &Value) -> Result<RedisFailurePolicy, String> {
    let Some(raw) = config.get("redis_failure_policy") else {
        return Ok(RedisFailurePolicy::FailClosed);
    };
    let Some(raw) = raw.as_str() else {
        return Err(
            "rate limiting: 'redis_failure_policy' must be a string ('fail_closed' or \
             'local_fallback')"
                .to_string(),
        );
    };
    match raw {
        "fail_closed" => Ok(RedisFailurePolicy::FailClosed),
        "local_fallback" => Ok(RedisFailurePolicy::LocalFallback),
        // Value-redacted diagnostics: the root object can carry redis_url /
        // redis_password, so name the accepted shape without echoing input.
        _ => Err(
            "rate limiting: 'redis_failure_policy' must be exactly 'fail_closed' or \
             'local_fallback'"
                .to_string(),
        ),
    }
}

/// Debug-only parity check that [`RATE_LIMIT_REDIS_CONFIG_KEYS`] is exactly the
/// shared Redis keys plus `redis_failure_policy`.
pub fn debug_assert_rate_limit_redis_keys() {
    debug_assert!(
        super::redis_rate_limiter::REDIS_PLUGIN_CONFIG_KEYS
            .iter()
            .all(|key| RATE_LIMIT_REDIS_CONFIG_KEYS.contains(key))
            && RATE_LIMIT_REDIS_CONFIG_KEYS.contains(&"redis_failure_policy")
            && RATE_LIMIT_REDIS_CONFIG_KEYS.len()
                == super::redis_rate_limiter::REDIS_PLUGIN_CONFIG_KEYS.len() + 1
    );
}

/// Placeholder plugin-config identity for constructions that have no stable
/// resource id (config validation, direct/test construction).
///
/// Production `PluginCache` always supplies the real plugin-config resource id
/// so sibling policies never share a default Redis key space.
pub const STANDALONE_RATE_LIMIT_CONFIG_ID: &str = "standalone";

/// Largest accepted rate-limit window, in seconds (31 days).
///
/// Every window is used three ways, and this bound has to be safe for all of
/// them: as a monotonic [`Duration`] subtracted from [`Instant::now`], as a
/// signed Redis `EXPIRE` TTL derived from `window * 2 + 1`, and as the
/// stale-state retention horizon. Values near `u64::MAX` previously wrapped or
/// underflowed at each of those sites, which either aborted the process or
/// wrote a zero/negative expiry that deleted the counter and removed
/// enforcement entirely.
pub const MAX_RATE_LIMIT_WINDOW_SECONDS: u64 = 31 * 24 * 60 * 60;

/// Largest accepted request cap for one rate-limit window.
///
/// Caps configured budgets at an operationally sane ceiling so Redis counter
/// math, diagnostics, and operator-facing remaining/limit headers stay within
/// predictable ranges. Local sliding-window memory is bounded independently by
/// [`SLIDING_WINDOW_BUCKET_COUNT`] aggregate buckets per key — not by retaining
/// one timestamp per admitted request.
pub const MAX_RATE_LIMIT_MAX_REQUESTS: u64 = 1_000_000;

/// Fixed number of aggregate count buckets retained by one local sliding window.
///
/// Independent of [`MAX_RATE_LIMIT_MAX_REQUESTS`]: each hot key retains at most
/// this many `u64` counters (plus a handful of scalar fields), so sustained
/// traffic under a maximally configured identity cannot grow per-key state
/// with the admission count. The ring spans the current sub-interval plus the
/// preceding 63 sub-intervals; one configured window contains 63 sub-intervals.
/// Consequently a slot is not reused until every request in it is outside the
/// exact window. The oldest retained bucket is counted in full, so over-count
/// is bounded by one sub-interval (`ceil(window / 63)`) and enforcement remains
/// fail-closed relative to an exact timestamp log.
pub const SLIDING_WINDOW_BUCKET_COUNT: usize = 64;

/// Number of sub-intervals in one configured sliding window. One additional
/// ring slot retains the oldest partially overlapping bucket.
const SLIDING_WINDOW_INTERVALS_PER_WINDOW: u128 = (SLIDING_WINDOW_BUCKET_COUNT - 1) as u128;

/// Local windows at or below this many whole seconds use a token bucket;
/// longer windows use the bounded aggregate [`SlidingWindow`].
pub const LOCAL_TOKEN_BUCKET_MAX_WINDOW_SECONDS: u64 = 5;

/// Which local algorithm a window duration selects.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LocalWindowAlgorithm {
    TokenBucket,
    SlidingAggregate,
}

/// Map a window duration onto the local algorithm used by ordinary HTTP,
/// GraphQL, and gRPC-method shared window state.
#[inline]
pub fn local_window_algorithm(duration: Duration) -> LocalWindowAlgorithm {
    if duration.as_secs() <= LOCAL_TOKEN_BUCKET_MAX_WINDOW_SECONDS {
        LocalWindowAlgorithm::TokenBucket
    } else {
        LocalWindowAlgorithm::SlidingAggregate
    }
}

/// Reject a configured window that is zero or beyond [`MAX_RATE_LIMIT_WINDOW_SECONDS`].
///
/// `label` is the caller's diagnostic prefix (for example
/// `"rate_limiting: limits[0]"`) and `field` the offending key.
pub fn validate_window_seconds(label: &str, field: &str, value: u64) -> Result<u64, String> {
    if value == 0 {
        return Err(format!("{label}: '{field}' must be greater than zero"));
    }
    if value > MAX_RATE_LIMIT_WINDOW_SECONDS {
        return Err(format!(
            "{label}: '{field}' must be <= {MAX_RATE_LIMIT_WINDOW_SECONDS} seconds, got: {value}"
        ));
    }
    Ok(value)
}

/// Reject a configured request cap that is zero or beyond
/// [`MAX_RATE_LIMIT_MAX_REQUESTS`].
pub fn validate_max_requests(label: &str, field: &str, value: u64) -> Result<u64, String> {
    if value == 0 {
        return Err(format!("{label}: '{field}' must be greater than zero"));
    }
    if value > MAX_RATE_LIMIT_MAX_REQUESTS {
        return Err(format!(
            "{label}: '{field}' must be <= {MAX_RATE_LIMIT_MAX_REQUESTS}, got: {value}"
        ));
    }
    Ok(value)
}

/// TTL for a two-window (previous + current) Redis sliding-window pair.
///
/// Saturating rather than wrapping: admission already bounds `window_seconds`,
/// but a wrapped `window * 2 + 1` produced a zero or negative `EXPIRE` that
/// deleted the counter on every increment — silently disabling enforcement.
/// The result is additionally clamped into the signed range redis-rs sends.
pub fn two_window_ttl_seconds(window_seconds: u64) -> u64 {
    window_seconds
        .saturating_mul(2)
        .saturating_add(1)
        .min(i64::MAX as u64)
}

/// TTL for a single fixed-window Redis counter (`window + 1`), saturating.
pub fn single_window_ttl_seconds(window_seconds: u64) -> u64 {
    window_seconds.saturating_add(1).min(i64::MAX as u64)
}

/// Debug-only parity check that a plugin's closed root key set is exactly the
/// union of its policy keys and the shared Redis keys.
///
/// Keeps the documented key groups, the admission allowlist, and OpenAPI from
/// drifting apart when a field is added to only one of them.
pub fn debug_assert_closed_root_keys(full: &[&str], policy: &[&str], redis: &[&str]) {
    debug_assert!(
        policy
            .iter()
            .chain(redis.iter())
            .all(|key| full.contains(key))
            && full.len() == policy.len() + redis.len()
    );
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RateLimitOutcome {
    pub allowed: bool,
    pub remaining: Option<u64>,
    pub limit: Option<u64>,
    pub window_seconds: Option<u64>,
    pub usage: Option<u64>,
    pub metric: Option<&'static str>,
    /// Identifier of the reservation created by an `AiRateLimitOp::Reserve` in
    /// the local (in-memory) `TokenUsageWindow`. The reconciliation op carries
    /// it back so a negative correction releases the *matching* reservation
    /// rather than the newest entry — see `TokenUsageWindow::adjust_usage`.
    /// `None` for every other algorithm/op and for the Redis path (whose
    /// counter is aggregate and has no per-entry identity).
    pub reservation_id: Option<u64>,
    /// Redis sliding-window index that an `AiRateLimitOp::Reserve` credited in
    /// the centralized (Redis) path. Carried back on the reconciliation op so a
    /// negative correction debits the SAME window the reservation landed in,
    /// even when the request straddles a window rollover before reconciling —
    /// see the Redis `AdjustUsage` arm. `None` for the local path (whose
    /// per-entry timestamp already pins the correction to the right window) and
    /// for every other algorithm/op.
    pub reserved_window_index: Option<u64>,
    /// The decision was a refusal because centralized enforcement could not be
    /// consulted (`redis_failure_policy: "fail_closed"`), not because the
    /// configured budget was exhausted. Consumers surface it as `503` rather
    /// than `429` — the client is not over its limit, the limit is unprovable.
    pub enforcement_unavailable: bool,
}

impl RateLimitOutcome {
    pub fn allow() -> Self {
        Self {
            allowed: true,
            ..Self::default()
        }
    }

    pub fn deny() -> Self {
        Self {
            allowed: false,
            ..Self::default()
        }
    }

    /// Refusal because the centralized store could not be consulted under a
    /// fail-closed policy. Carries no remaining/limit/usage: this gateway has no
    /// authoritative view of the budget, and reporting a locally-derived number
    /// would advertise a budget nothing is enforcing.
    pub fn deny_enforcement_unavailable() -> Self {
        Self {
            allowed: false,
            enforcement_unavailable: true,
            ..Self::default()
        }
    }

    pub fn with_remaining(mut self, remaining: u64) -> Self {
        self.remaining = Some(remaining);
        self
    }

    pub fn with_limit(mut self, limit: u64) -> Self {
        self.limit = Some(limit);
        self
    }

    pub fn with_window(mut self, window_seconds: u64) -> Self {
        self.window_seconds = Some(window_seconds);
        self
    }

    pub fn with_usage(mut self, usage: u64) -> Self {
        self.usage = Some(usage);
        self
    }

    pub fn with_metric(mut self, metric: &'static str) -> Self {
        self.metric = Some(metric);
        self
    }

    pub fn with_reservation_id(mut self, reservation_id: u64) -> Self {
        self.reservation_id = Some(reservation_id);
        self
    }

    pub fn with_reserved_window_index(mut self, reserved_window_index: u64) -> Self {
        self.reserved_window_index = Some(reserved_window_index);
        self
    }
}

#[async_trait]
pub trait RateLimitAlgorithm: Send + Sync + 'static {
    type State: Send + Sync + 'static;
    type Op: Send + Sync;

    fn new_state(&self) -> Self::State;

    fn check_local(&self, state: &mut Self::State, op: &Self::Op, now: Instant)
    -> RateLimitOutcome;

    async fn check_redis(
        &self,
        redis: &RedisRateLimitClient,
        key: &str,
        op: &Self::Op,
    ) -> Result<RateLimitOutcome, ()>;

    fn is_state_active(&self, state: &Self::State, now: Instant) -> bool;
}

pub struct LocalLimiter<K, A>
where
    K: Eq + Hash,
    A: RateLimitAlgorithm,
{
    algorithm: A,
    state: DashMap<K, A::State>,
    /// Exact resident-entry count coordinated with insert/remove. Steady-path
    /// capacity checks load this atomic instead of `DashMap::len()`, which
    /// takes a read guard on every shard.
    entry_count: AtomicUsize,
    /// Counts all-shard `DashMap::len()` observations. Production steady paths
    /// never increment this; tests assert it stays flat under admission.
    #[cfg(debug_assertions)]
    all_shard_len_calls: AtomicUsize,
    #[cfg(test)]
    shard_amount: usize,
}

impl<K, A> LocalLimiter<K, A>
where
    K: Eq + Hash + Clone,
    A: RateLimitAlgorithm,
{
    /// Build a local limiter whose hot-path state map uses `shard_amount`.
    ///
    /// Callers must pass an already-normalized effective shard count (for
    /// example [`PluginHttpClient::pool_shard_amount`]). This constructor does
    /// not re-normalize so `FERRUM_POOL_SHARD_AMOUNT` zero/explicit behavior is
    /// applied exactly once at the HTTP-client boundary.
    pub fn new(algorithm: A, shard_amount: usize) -> Self {
        Self {
            algorithm,
            state: DashMap::with_shard_amount(shard_amount),
            entry_count: AtomicUsize::new(0),
            #[cfg(debug_assertions)]
            all_shard_len_calls: AtomicUsize::new(0),
            #[cfg(test)]
            shard_amount,
        }
    }

    #[cfg(test)]
    pub fn check(&self, key: K, op: &A::Op) -> RateLimitOutcome {
        self.check_at(key, op, Instant::now())
    }

    pub fn check_at(&self, key: K, op: &A::Op, now: Instant) -> RateLimitOutcome {
        self.check_at_with_capacity(key, op, now, usize::MAX)
            .unwrap_or_else(RateLimitOutcome::deny)
    }

    /// Check one key while admitting at most max_entries distinct resident
    /// keys. Existing keys continue at capacity; a vacant key must atomically
    /// reserve a slot before its state is published.
    pub fn check_at_with_capacity(
        &self,
        key: K,
        op: &A::Op,
        now: Instant,
        max_entries: usize,
    ) -> Option<RateLimitOutcome> {
        use dashmap::mapref::entry::Entry;
        match self.state.entry(key) {
            Entry::Occupied(mut occupied) => {
                Some(self.algorithm.check_local(occupied.get_mut(), op, now))
            }
            Entry::Vacant(vacant) => {
                if !self.try_reserve_entry_slot(max_entries) {
                    return None;
                }
                let mut state = self.algorithm.new_state();
                let outcome = self.algorithm.check_local(&mut state, op, now);
                vacant.insert(state);
                Some(outcome)
            }
        }
    }

    pub fn tracked_keys_count(&self) -> usize {
        self.entry_count.load(Ordering::Acquire)
    }

    /// Drop idle entries according to the algorithm's activity predicate.
    ///
    /// This is the below-cap periodic cleanup path: it never force-evicts
    /// still-active keys and is safe to invoke on a sampled schedule even when
    /// the map sits under the hard capacity ceiling.
    pub fn prune_stale_at(&self, now: Instant) {
        self.state.retain(|_, state| {
            if self.algorithm.is_state_active(state, now) {
                true
            } else {
                self.release_entry_slot();
                false
            }
        });
    }

    /// Reclaim idle state under capacity pressure.
    ///
    /// Hard cardinality is enforced by atomic reservation on admission
    /// ([`Self::check_at_with_capacity`] /
    /// [`RateLimitBackend::check_with_redis_key_and_local_capacity`]). This
    /// helper only prunes idle entries — it never deletes still-active
    /// budgets, which would reset consumed windows and weaken enforcement
    /// (GHSA-3xxf-5m26-c8pv). `max_entries` is retained for call-site
    /// compatibility with shared cleanup wrappers; admission already refuses
    /// previously unseen local/fallback keys at the configured cap.
    pub fn enforce_capacity(&self, max_entries: usize, now: Instant) {
        let _ = max_entries;
        self.prune_stale_at(now);
    }

    pub fn contains_key(&self, key: &K) -> bool {
        self.state.contains_key(key)
    }

    fn release_entry_slot(&self) {
        let _ = self
            .entry_count
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |count| {
                count.checked_sub(1)
            });
    }

    fn try_reserve_entry_slot(&self, max_entries: usize) -> bool {
        self.entry_count
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |count| {
                (count < max_entries).then_some(count + 1)
            })
            .is_ok()
    }

    /// All-shard `DashMap::len()` for test reconciliation only. Never call from
    /// steady admission — each invocation takes every shard read lock.
    #[allow(dead_code)] // used only by external tests; dead in binary test target
    pub(crate) fn map_len_for_test(&self) -> usize {
        #[cfg(debug_assertions)]
        self.all_shard_len_calls.fetch_add(1, Ordering::Relaxed);
        self.state.len()
    }

    /// Number of all-shard length observations since construction.
    #[allow(dead_code)] // used only by external tests; dead in binary test target
    pub(crate) fn all_shard_len_calls_for_test(&self) -> usize {
        #[cfg(debug_assertions)]
        {
            self.all_shard_len_calls.load(Ordering::Relaxed)
        }
        #[cfg(not(debug_assertions))]
        {
            0
        }
    }

    /// DashMap shard count for the local token-state map. Test-only so
    /// production builds do not expose limiter debug state.
    #[cfg(test)]
    pub fn shard_amount(&self) -> usize {
        self.shard_amount
    }
}

pub struct RedisLimiter<A: RateLimitAlgorithm> {
    redis_client: Arc<RedisRateLimitClient>,
    algorithm: A,
    /// Effective Redis key prefix (explicit `redis_key_prefix`, or the
    /// policy-isolated default). Retained unconditionally so isolation between
    /// sibling policies is observable from external tests; one cold `String`
    /// per plugin instance, never touched on the hot path.
    key_prefix: String,
    health_check_interval: Duration,
}

impl<A: RateLimitAlgorithm> RedisLimiter<A> {
    #[allow(dead_code)] // direct/test construction; production factory supplies the config id
    pub fn new(
        plugin_name: &str,
        config: &Value,
        http_client: &PluginHttpClient,
        algorithm: A,
    ) -> Result<Option<Self>, String> {
        Self::new_with_config_id(
            plugin_name,
            STANDALONE_RATE_LIMIT_CONFIG_ID,
            config,
            http_client,
            algorithm,
        )
    }

    /// Build the Redis-backed limiter with a policy-isolated default key prefix.
    ///
    /// The default prefix is `{namespace}:{plugin_name}:{config_id}`. Without
    /// `config_id`, every instance of one plugin type in a namespace shared a
    /// single key space, so two independent policies (different proxies,
    /// routes, or tenants) incremented and rejected against the same counters.
    /// The plugin-config resource id is stable across reloads and identical on
    /// every data plane serving that policy, so replicas of the *same* policy
    /// still share a distributed budget while distinct policies do not.
    ///
    /// An explicit `redis_key_prefix` still wins: it is the documented
    /// opt-in for deliberately shared budgets.
    pub fn new_with_config_id(
        plugin_name: &str,
        config_id: &str,
        config: &Value,
        http_client: &PluginHttpClient,
        algorithm: A,
    ) -> Result<Option<Self>, String> {
        crate::config::types::validate_resource_id(plugin_name)
            .map_err(|error| format!("{plugin_name}: invalid canonical plugin name: {error}"))?;
        crate::config::types::validate_resource_id(config_id)
            .map_err(|error| format!("{plugin_name}: invalid plugin config id: {error}"))?;
        crate::config::types::validate_namespace(http_client.namespace())
            .map_err(|error| format!("{plugin_name}: invalid Redis namespace: {error}"))?;
        let default_prefix = format!("{}:{plugin_name}:{config_id}", http_client.namespace());
        let Some(cfg) = RedisConfig::from_plugin_config(config, &default_prefix)? else {
            return Ok(None);
        };
        let health_check_interval = Duration::from_secs(cfg.health_check_interval_seconds.max(1));
        let key_prefix = cfg.key_prefix.clone();

        let redis_client = Arc::new(RedisRateLimitClient::new(
            cfg,
            http_client.dns_cache().cloned(),
            http_client.tls_no_verify(),
            http_client.tls_ca_bundle_path(),
        )?);
        Ok(Some(Self {
            redis_client,
            algorithm,
            key_prefix,
            health_check_interval,
        }))
    }

    // Redis command failures are intentionally collapsed to () at this boundary.
    #[allow(clippy::result_unit_err)]
    pub async fn check(&self, key: &str, op: &A::Op) -> Result<RateLimitOutcome, ()> {
        self.algorithm
            .check_redis(&self.redis_client, key, op)
            .await
    }

    pub fn warmup_hostname(&self) -> Option<String> {
        self.redis_client.warmup_hostname()
    }

    pub fn key_prefix(&self) -> &str {
        &self.key_prefix
    }

    fn is_available(&self) -> bool {
        self.redis_client.is_available()
    }

    /// Whether the configured endpoint was rejected as an unsupported topology
    /// (Redis Cluster). Surfaced in degradation diagnostics so an operator can
    /// tell a misconfiguration apart from an outage.
    fn is_topology_unsupported(&self) -> bool {
        self.redis_client.is_topology_unsupported()
    }

    fn health_check_interval(&self) -> Duration {
        self.health_check_interval
    }
}

pub struct FailoverLimiter<K, A>
where
    K: Eq + Hash,
    A: RateLimitAlgorithm,
{
    plugin_name: &'static str,
    primary: RedisLimiter<A>,
    /// Shared with every compatible plugin-cache generation for this policy
    /// identity, so a reload cannot hand callers a fresh local budget.
    fallback: Arc<LocalLimiter<K, A>>,
    /// What happens when the centralized store cannot be consulted. Under the
    /// default [`RedisFailurePolicy::FailClosed`] the `fallback` limiter is
    /// retained but never consulted for admission — the plugin's cleanup and
    /// capacity helpers still operate on it, and a policy change rebuilds the
    /// instance.
    failure_policy: RedisFailurePolicy,
    /// Edge-detection mirror for the observer's recovery log line **only**.
    ///
    /// Admission is gated on `RedisLimiter::is_available` — the client's own
    /// semantic signal — and never on this flag. Gating on both used to latch a
    /// second recovery delay: an ordinary command failure makes the client
    /// unavailable, the client republishes availability at most one health
    /// interval later, and this independent observer needed a further interval
    /// before it mirrored the recovery. Under the fail-closed default that
    /// turned routine socket recycling into roughly two intervals of blanket
    /// refusals. The mirror is now purely a logging latch.
    observed_available: Arc<AtomicBool>,
    fallback_warned: Arc<AtomicBool>,
    /// Abort handle for the failover health observer; aborted on Drop.
    health_observer_abort: Option<tokio::task::AbortHandle>,
}

impl<K, A> FailoverLimiter<K, A>
where
    K: Eq + Hash + Clone + Send + Sync + 'static,
    A: RateLimitAlgorithm,
{
    pub fn new(
        plugin_name: &'static str,
        primary: RedisLimiter<A>,
        fallback: Arc<LocalLimiter<K, A>>,
        failure_policy: RedisFailurePolicy,
    ) -> Self {
        let observed_available = Arc::new(AtomicBool::new(true));
        let fallback_warned = Arc::new(AtomicBool::new(false));

        let mut limiter = Self {
            plugin_name,
            primary,
            fallback,
            failure_policy,
            observed_available,
            fallback_warned,
            health_observer_abort: None,
        };
        limiter.spawn_health_observer();
        limiter
    }

    /// Log the degradation once per outage and report whether admission may
    /// continue on per-process state.
    fn degraded_allows_local(&self) -> bool {
        let first = !self.fallback_warned.swap(true, Ordering::Relaxed);
        match self.failure_policy {
            RedisFailurePolicy::FailClosed => {
                if first {
                    warn!(
                        plugin = self.plugin_name,
                        topology_unsupported = self.primary.is_topology_unsupported(),
                        "Redis rate limiting unavailable — denying under \
                         redis_failure_policy='fail_closed'"
                    );
                }
                false
            }
            RedisFailurePolicy::LocalFallback => {
                if first {
                    warn!(
                        plugin = self.plugin_name,
                        topology_unsupported = self.primary.is_topology_unsupported(),
                        "Redis rate limiting unavailable — falling back to local in-memory state \
                         under redis_failure_policy='local_fallback'; the configured budget is \
                         now enforced once per gateway process"
                    );
                }
                true
            }
        }
    }

    #[cfg(test)]
    pub async fn check(&self, local_key: K, redis_key: &str, op: &A::Op) -> RateLimitOutcome {
        // Single authoritative gate: the client's own semantic availability. It
        // reads false while the topology is terminal, so a refused endpoint can
        // never be consulted, and it reads true the moment the client itself
        // recovers — no second observer interval in front of admission.
        if self.primary.is_available() {
            match self.primary.check(redis_key, op).await {
                // Re-check the terminal flag at the success boundary: a task
                // that proved an unsupported topology while this operation was
                // in flight must not be overruled by its result.
                Ok(result) if !self.primary.is_topology_unsupported() => {
                    self.fallback_warned.store(false, Ordering::Relaxed);
                    return result;
                }
                // The client marked itself unavailable (or terminal) on this
                // failure, so the next request re-reads that signal directly.
                Ok(_) | Err(()) => {}
            }
        }

        if !self.degraded_allows_local() {
            return RateLimitOutcome::deny_enforcement_unavailable();
        }

        self.fallback.check(local_key, op)
    }

    /// Prefer Redis when healthy; otherwise atomically cap distinct local
    /// fallback keys. None means a new local key was denied at capacity.
    pub async fn check_with_local_capacity(
        &self,
        local_key: K,
        redis_key: &str,
        op: &A::Op,
        max_entries: usize,
    ) -> Option<RateLimitOutcome> {
        // See `check`: `is_available()` is the only admission gate, and a
        // concurrent topology rejection wins over an in-flight success.
        if self.primary.is_available() {
            match self.primary.check(redis_key, op).await {
                Ok(result) if !self.primary.is_topology_unsupported() => {
                    self.fallback_warned.store(false, Ordering::Relaxed);
                    return Some(result);
                }
                Ok(_) | Err(()) => {}
            }
        }

        if !self.degraded_allows_local() {
            return Some(RateLimitOutcome::deny_enforcement_unavailable());
        }

        self.fallback
            .check_at_with_capacity(local_key, op, Instant::now(), max_entries)
    }

    pub fn tracked_keys_count(&self) -> usize {
        self.fallback.tracked_keys_count()
    }

    pub fn prune_local_stale_at(&self, now: Instant) {
        self.fallback.prune_stale_at(now);
    }

    pub fn enforce_local_capacity(&self, max_entries: usize, now: Instant) {
        self.fallback.enforce_capacity(max_entries, now);
    }

    pub fn contains_local_key(&self, key: &K) -> bool {
        self.fallback.contains_key(key)
    }

    #[allow(dead_code)] // used only by external tests; dead in binary test target
    pub(crate) fn map_len_for_test(&self) -> usize {
        self.fallback.map_len_for_test()
    }

    #[allow(dead_code)] // used only by external tests; dead in binary test target
    pub(crate) fn all_shard_len_calls_for_test(&self) -> usize {
        self.fallback.all_shard_len_calls_for_test()
    }

    pub fn warmup_hostname(&self) -> Option<String> {
        self.primary.warmup_hostname()
    }

    /// Shared Redis client Arc for lifecycle tests (strong-count / Weak proofs).
    #[allow(dead_code)] // used only by external tests; dead in binary test target
    pub fn redis_client_arc_for_test(&self) -> Arc<RedisRateLimitClient> {
        Arc::clone(&self.primary.redis_client)
    }

    /// Abort handle for the failover observer, when started (tests).
    #[allow(dead_code)] // used only by external tests; dead in binary test target
    pub fn health_observer_abort_for_test(&self) -> Option<tokio::task::AbortHandle> {
        self.health_observer_abort.clone()
    }

    /// Log-only observer: reports the availability edge once per outage.
    ///
    /// It deliberately gates nothing. Admission reads
    /// `RedisLimiter::is_available` directly on every request, so a recovery
    /// this task has not observed yet is already eligible for centralized
    /// enforcement; the task exists so operators still get one "recovered" line
    /// per outage even for a policy that sees no traffic in between.
    fn spawn_health_observer(&mut self) {
        let plugin_name = self.plugin_name;
        let observed_available = Arc::clone(&self.observed_available);
        let fallback_warned = Arc::clone(&self.fallback_warned);
        // Observe availability without retaining the full Redis client (and its
        // cached connections / credentials) after this limiter is dropped. The
        // signal is semantic: it cannot read available while the endpoint's
        // topology is terminal, so this observer can never advertise a false
        // recovery for an endpoint the client refused.
        let availability = self.primary.redis_client.availability_signal();
        let interval = self.primary.health_check_interval();

        let Ok(handle) = tokio::runtime::Handle::try_current() else {
            warn!(
                plugin = plugin_name,
                "Redis rate limiting health observer not started because no Tokio runtime is active"
            );
            return;
        };

        let join = handle.spawn(async move {
            loop {
                tokio::time::sleep(interval).await;
                let is_available = availability.is_available();
                let was_healthy = observed_available.swap(is_available, Ordering::Relaxed);
                if is_available && !was_healthy {
                    fallback_warned.store(false, Ordering::Relaxed);
                    info!(plugin = plugin_name, "Redis rate limiting recovered");
                }
            }
        });
        self.health_observer_abort = Some(join.abort_handle());
    }
}

impl<K, A> Drop for FailoverLimiter<K, A>
where
    K: Eq + Hash,
    A: RateLimitAlgorithm,
{
    fn drop(&mut self) {
        if let Some(abort) = self.health_observer_abort.take() {
            abort.abort();
        }
    }
}

/// Process registry of live local rate-limit state for one `(key, algorithm)`
/// pair, keyed by stable policy identity.
///
/// Entries are `Weak`, so a limiter survives only while a plugin instance still
/// owns it. Every resolution prunes dead entries first, which bounds retention
/// to the currently configured policies plus any retired semantic generation
/// whose instance is still installed in a live plugin-cache generation. A
/// removed policy therefore becomes reclaimable as soon as its last instance is
/// dropped — nothing here keeps a strong reference.
///
/// The lock is taken at plugin construction/reload only. The request path holds
/// the resolved `Arc` and never touches this map.
///
/// Public only because [`SharedLocalLimiterState::registry`] names it; every
/// operation on it is module-private.
pub struct LocalLimiterRegistry<K, A>
where
    K: Eq + Hash,
    A: RateLimitAlgorithm,
{
    /// Policy identity -> every still-live semantic generation for it, as
    /// `(compatibility fingerprint, weak limiter)`.
    #[allow(clippy::type_complexity)]
    // the shape is the contract; naming it needs a bounded alias
    generations: OnceLock<Mutex<HashMap<String, Vec<(String, Weak<LocalLimiter<K, A>>)>>>>,
}

impl<K, A> LocalLimiterRegistry<K, A>
where
    K: Eq + Hash + Clone + Send + Sync + 'static,
    A: RateLimitAlgorithm,
{
    const fn new() -> Self {
        Self {
            generations: OnceLock::new(),
        }
    }

    #[allow(clippy::type_complexity)] // mirrors the `generations` field shape
    fn locked(
        &self,
    ) -> std::sync::MutexGuard<'_, HashMap<String, Vec<(String, Weak<LocalLimiter<K, A>>)>>> {
        self.generations
            .get_or_init(|| Mutex::new(HashMap::new()))
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    /// Resolve the limiter for one policy identity and semantic fingerprint.
    ///
    /// A compatible reload generation inherits the live limiter, so an already
    /// consumed budget keeps rejecting. A semantic change resolves onto a fresh
    /// limiter and registers a second generation for the identity, so a retired
    /// generation's still-installed instance keeps enforcing on the state it
    /// admitted against and can never corrupt the replacement policy. Every
    /// live generation is retained (not just the last), so while A and B are
    /// concurrently live another A construction recovers A's budget rather
    /// than minting a third empty domain.
    fn resolve(
        &self,
        namespace: &str,
        plugin_name: &str,
        config_id: &str,
        fingerprint: String,
        build: impl FnOnce() -> LocalLimiter<K, A>,
    ) -> Arc<LocalLimiter<K, A>> {
        let identity = local_limiter_policy_identity(namespace, plugin_name, config_id);
        let mut guard = self.locked();
        prune_dead_generations(&mut guard);
        if let Some(existing) = guard.get(&identity).and_then(|generations| {
            generations
                .iter()
                .find(|(known, _)| *known == fingerprint)
                .and_then(|(_, weak)| weak.upgrade())
        }) {
            return existing;
        }
        let resets_live_budget = guard
            .get(&identity)
            .is_some_and(|generations| !generations.is_empty());
        let limiter = Arc::new(build());
        if resets_live_budget {
            info!(
                namespace = %namespace,
                plugin = %plugin_name,
                config_id = %config_id,
                "Rate-limit policy semantics changed; starting a fresh local budget"
            );
        }
        guard
            .entry(identity)
            .or_default()
            .push((fingerprint, Arc::downgrade(&limiter)));
        limiter
    }

    /// Number of still-live semantic generations retained for `identity`.
    #[allow(dead_code)] // used only by external tests; dead in binary test target
    fn live_generations(&self, identity: &str) -> usize {
        let mut guard = self.locked();
        prune_dead_generations(&mut guard);
        guard
            .get(identity)
            .map(|generations| generations.len())
            .unwrap_or(0)
    }
}

/// Drop every generation whose limiter has no live owner, and every identity
/// left with none.
#[allow(clippy::type_complexity)] // mirrors the `LocalLimiterRegistry` field shape
fn prune_dead_generations<K, A>(
    generations: &mut HashMap<String, Vec<(String, Weak<LocalLimiter<K, A>>)>>,
) where
    K: Eq + Hash,
    A: RateLimitAlgorithm,
{
    generations.retain(|_, entries| {
        entries.retain(|(_, weak)| weak.strong_count() > 0);
        !entries.is_empty()
    });
}

/// A rate-limit algorithm whose local enforcement state can be inherited by a
/// compatible plugin-cache generation.
///
/// Each implementation owns a *distinct, statically typed* registry, so two
/// algorithms can never observe one another's state and no downcast is
/// involved. Two plugin kinds that happen to share one algorithm type (the
/// three `DynamicHttpRateLimitAlgorithm` consumers) are separated by the
/// plugin name carried in the policy identity — see
/// [`local_limiter_policy_identity`].
pub trait SharedLocalLimiterState: RateLimitAlgorithm + Clone + Sized {
    /// Local limiter key type this algorithm is enforced with.
    type Key: Eq + Hash + Clone + Send + Sync + 'static;

    /// The process registry for this exact `(Key, Self)` pair.
    fn registry() -> &'static LocalLimiterRegistry<Self::Key, Self>;
}

/// Stable policy identity for local rate-limit state.
///
/// The components are trusted configuration — namespace, plugin kind, and the
/// configured plugin-config resource id — never request-controlled data, an
/// allocation address, or construction order. NUL cannot appear in any of them,
/// so the joined form is unambiguous: two tenants that reuse a bare
/// plugin-config id stay in separate enforcement domains, and two limiter
/// plugin kinds that share one id never collide.
fn local_limiter_policy_identity(namespace: &str, plugin_name: &str, config_id: &str) -> String {
    format!("{namespace}\0{plugin_name}\0{config_id}")
}

/// Canonical description of one policy's **effective** local enforcement
/// semantics, built by the plugin after its own parsing, defaulting, and
/// normalization have already run.
///
/// Raw configuration syntax is deliberately not an input. Two configurations
/// that parse to the same enforcement — an omitted optional field and its
/// explicit effective default, a value the parser lower-cases or trims, an
/// omitted rate map and an explicit empty one — describe the same budget and
/// must keep the same counters, or config churn alone would mint a fresh
/// budget without changing what is enforced. Conversely any value the parser
/// keeps is encoded here, so a real enforcement change still isolates.
///
/// Fields are self-delimiting and sorted by label before hashing, so neither
/// the order a plugin records them in nor a hash-map iteration order can change
/// the result. Never record a credential, URL, username, password, or TLS
/// material: this value feeds [`local_limiter_fingerprint`], and the shared
/// Redis posture is added there rather than by a plugin.
#[derive(Debug, Default)]
pub struct LocalStateSemantics {
    fields: Vec<(&'static str, Vec<u8>)>,
}

impl LocalStateSemantics {
    pub fn new() -> Self {
        Self::default()
    }

    fn push(&mut self, label: &'static str, encoded: Vec<u8>) {
        debug_assert!(
            !RATE_LIMIT_REDIS_CONFIG_KEYS.contains(&label),
            "local rate-limit compatibility must not record shared Redis config fields; the \
             enforcement posture is added by local_limiter_fingerprint"
        );
        debug_assert!(
            !self.fields.iter().any(|(known, _)| *known == label),
            "duplicate local rate-limit semantic label"
        );
        self.fields.push((label, encoded));
    }

    /// Record an already-normalized effective string (a parsed enum rendered
    /// canonically, not the operator's raw spelling).
    pub fn text(&mut self, label: &'static str, value: &str) {
        self.push(label, value.as_bytes().to_vec());
    }

    /// Record an effective integer parameter (the value after defaulting).
    pub fn u64(&mut self, label: &'static str, value: u64) {
        self.push(label, value.to_le_bytes().to_vec());
    }

    /// Record an effective optional integer parameter. Unset is a distinct
    /// enforcement state from any set value (an unlimited axis is not a
    /// bounded one), so it is encoded distinctly rather than as zero.
    pub fn optional_u64(&mut self, label: &'static str, value: Option<u64>) {
        let mut encoded = Vec::with_capacity(9);
        match value {
            Some(value) => {
                encoded.push(1);
                encoded.extend_from_slice(&value.to_le_bytes());
            }
            None => encoded.push(0),
        }
        self.push(label, encoded);
    }

    /// Record one window list (limit + duration per window, in the order the
    /// limiter evaluates them).
    pub fn windows(&mut self, label: &'static str, specs: &[RateLimitWindowSpec]) {
        self.push(label, encode_window_specs(specs));
    }

    /// Record a keyed set of window lists (per consumer, per operation, per
    /// method). Entries are sorted by key, so a hash-map iteration order can
    /// never change the fingerprint, and an omitted map and an explicit empty
    /// map both encode as zero entries.
    pub fn window_map<'a, I>(&mut self, label: &'static str, entries: I)
    where
        I: IntoIterator<Item = (&'a str, &'a [RateLimitWindowSpec])>,
    {
        let mut entries: Vec<(&str, &[RateLimitWindowSpec])> = entries.into_iter().collect();
        entries.sort_by_key(|(key, _)| *key);
        let mut encoded = Vec::new();
        encoded.extend_from_slice(&(entries.len() as u64).to_le_bytes());
        for (key, specs) in entries {
            encoded.extend_from_slice(&(key.len() as u64).to_le_bytes());
            encoded.extend_from_slice(key.as_bytes());
            let specs = encode_window_specs(specs);
            encoded.extend_from_slice(&(specs.len() as u64).to_le_bytes());
            encoded.extend_from_slice(&specs);
        }
        self.push(label, encoded);
    }
}

/// Self-delimiting encoding of one window list. Durations are encoded in
/// nanoseconds so a sub-second window can never collide with a whole-second one.
fn encode_window_specs(specs: &[RateLimitWindowSpec]) -> Vec<u8> {
    let mut encoded = Vec::with_capacity(8 + specs.len() * 24);
    encoded.extend_from_slice(&(specs.len() as u64).to_le_bytes());
    for spec in specs {
        encoded.extend_from_slice(&spec.limit.to_le_bytes());
        encoded.extend_from_slice(&spec.duration.as_nanos().to_le_bytes());
    }
    encoded
}

/// Canonical, non-reversible fingerprint of everything that changes what local
/// enforcement state *means* for one policy.
///
/// Inputs are the plugin's effective enforcement semantics
/// ([`LocalStateSemantics`], built after validation) plus the shared posture
/// resolved here: whether a centralized store is authoritative, and — only when
/// it is — the outage policy that decides whether the local map is ever an
/// admission domain and any explicitly configured Redis key prefix that names
/// the counter domain. The default prefix is already determined by the stable
/// policy identity and is therefore not a separate input.
///
/// `redis_failure_policy` is deliberately *conditional*. With `sync_mode: local`
/// there is no centralized store to lose, the local map is the sole enforcement
/// domain under every posture, and the field changes nothing that is enforced —
/// so toggling it must not discard a live budget. Once Redis is enabled it
/// decides whether the local map can admit at all during an outage, which is a
/// real change in what the retained counters mean, so it isolates.
///
/// Secret-bearing configuration is never an input: `redis_url`,
/// `redis_username`, `redis_password`, and the TLS material keys are excluded
/// by construction, and [`LocalStateSemantics::push`] debug-asserts that no
/// plugin records a shared Redis config field. The output is a SHA-256 hex
/// digest: it is compared for equality only, is never logged, and carries no
/// configuration text.
fn local_limiter_fingerprint(
    plugin_name: &str,
    semantics: &LocalStateSemantics,
    redis_enabled: bool,
    failure_policy: RedisFailurePolicy,
    explicit_redis_key_prefix: Option<&str>,
) -> String {
    use crate::fips::approved::Sha256;

    let mut hasher = Sha256::new();
    // Length-prefixed framing: no component can be re-read as part of another.
    let mut absorb = |label: &str, value: &[u8]| {
        hasher.update((label.len() as u64).to_le_bytes());
        hasher.update(label.as_bytes());
        hasher.update((value.len() as u64).to_le_bytes());
        hasher.update(value);
    };
    absorb("v", b"ferrum-edge/rate-limit/local-state/v2");
    absorb("plugin", plugin_name.as_bytes());
    absorb("redis", if redis_enabled { b"1" } else { b"0" });
    if redis_enabled {
        absorb(
            "failure_policy",
            match failure_policy {
                RedisFailurePolicy::FailClosed => b"fail_closed".as_slice(),
                RedisFailurePolicy::LocalFallback => b"local_fallback".as_slice(),
            },
        );
        if let Some(redis_key_prefix) = explicit_redis_key_prefix {
            absorb("redis_key_prefix", redis_key_prefix.as_bytes());
        }
    }
    // Sorted by label so the order a plugin records its semantics in is not
    // itself a compatibility input.
    let mut fields: Vec<(&str, &[u8])> = semantics
        .fields
        .iter()
        .map(|(label, encoded)| (*label, encoded.as_slice()))
        .collect();
    fields.sort_by_key(|(label, _)| *label);
    for (label, encoded) in fields {
        absorb(label, encoded);
    }
    hex::encode(hasher.finalize())
}

/// Number of retained live generations for one policy identity. Test-only
/// lifecycle probe; production code never inspects the registry.
#[allow(dead_code)] // used only by external tests; dead in binary test target
pub(crate) fn shared_local_limiter_generations_for_test<A>(
    namespace: &str,
    plugin_name: &str,
    config_id: &str,
) -> usize
where
    A: SharedLocalLimiterState,
{
    let identity = local_limiter_policy_identity(namespace, plugin_name, config_id);
    A::registry().live_generations(&identity)
}

impl SharedLocalLimiterState for DynamicHttpRateLimitAlgorithm {
    type Key = String;

    fn registry() -> &'static LocalLimiterRegistry<String, Self> {
        static REGISTRY: LocalLimiterRegistry<String, DynamicHttpRateLimitAlgorithm> =
            LocalLimiterRegistry::new();
        &REGISTRY
    }
}

impl SharedLocalLimiterState for AiTokenRateAlgorithm {
    type Key = String;

    fn registry() -> &'static LocalLimiterRegistry<String, Self> {
        static REGISTRY: LocalLimiterRegistry<String, AiTokenRateAlgorithm> =
            LocalLimiterRegistry::new();
        &REGISTRY
    }
}

impl SharedLocalLimiterState for WsFrameRateAlgorithm {
    type Key = u64;

    fn registry() -> &'static LocalLimiterRegistry<u64, Self> {
        static REGISTRY: LocalLimiterRegistry<u64, WsFrameRateAlgorithm> =
            LocalLimiterRegistry::new();
        &REGISTRY
    }
}

impl SharedLocalLimiterState for UdpRateLimitAlgorithm {
    type Key = Arc<str>;

    fn registry() -> &'static LocalLimiterRegistry<Arc<str>, Self> {
        static REGISTRY: LocalLimiterRegistry<Arc<str>, UdpRateLimitAlgorithm> =
            LocalLimiterRegistry::new();
        &REGISTRY
    }
}

pub enum RateLimitBackend<K, A>
where
    K: Eq + Hash,
    A: RateLimitAlgorithm,
{
    Local(Arc<LocalLimiter<K, A>>),
    Failover(FailoverLimiter<K, A>),
}

impl<K, A> RateLimitBackend<K, A>
where
    K: Eq + Hash + Clone + Send + Sync + 'static,
    A: RateLimitAlgorithm + Clone,
{
    #[allow(dead_code)] // direct/test construction; production factory supplies the config id
    pub fn from_plugin_config(
        plugin_name: &'static str,
        config: &Value,
        http_client: &PluginHttpClient,
        algorithm: A,
    ) -> Result<Self, String> {
        Self::from_plugin_config_with_config_id(
            plugin_name,
            STANDALONE_RATE_LIMIT_CONFIG_ID,
            config,
            http_client,
            algorithm,
        )
    }

    /// [`Self::from_plugin_config`] with the stable plugin-config resource id
    /// that isolates this policy's default Redis key space from sibling
    /// instances of the same plugin type. See [`RedisLimiter::new_with_config_id`].
    pub fn from_plugin_config_with_config_id(
        plugin_name: &'static str,
        config_id: &str,
        config: &Value,
        http_client: &PluginHttpClient,
        algorithm: A,
    ) -> Result<Self, String> {
        // Normalize once via PluginHttpClient so local-only and Redis-fallback
        // maps share the same effective FERRUM_POOL_SHARD_AMOUNT.
        let shard_amount = http_client.pool_shard_amount();
        // Validated regardless of sync_mode so a later toggle cannot activate an
        // unchecked value.
        let failure_policy = parse_redis_failure_policy(config)?;
        let local = Arc::new(LocalLimiter::new(algorithm.clone(), shard_amount));
        match RedisLimiter::new_with_config_id(
            plugin_name,
            config_id,
            config,
            http_client,
            algorithm,
        ) {
            Ok(Some(redis)) => Ok(Self::Failover(FailoverLimiter::new(
                plugin_name,
                redis,
                local,
                failure_policy,
            ))),
            Ok(None) => Ok(Self::Local(local)),
            Err(err) => Err(err),
        }
    }

    /// [`Self::from_plugin_config_with_config_id`] that additionally inherits
    /// live *local* enforcement state from a compatible plugin-cache
    /// generation for the same stable policy identity.
    ///
    /// Every path that reconstructs a plugin instance — a full reload
    /// (file-mode `SIGHUP`, a DP full CP snapshot, a rejected-delta fallback),
    /// a global plugin-config change or deletion anywhere in the namespace, or
    /// a change to the owning proxy's associations — used to hand every caller
    /// a brand new empty budget. The configured ceiling then became effectively
    /// unbounded for anyone able to churn configuration. State is now owned by
    /// the policy, not by the instance the cache happened to construct.
    ///
    /// `namespace` is `None` only for construction entry points that have no
    /// stable policy identity, including direct/test and standalone validation
    /// helpers. Those keep private state. Security-composition candidate
    /// validation and production [`crate::plugin_cache::PluginCache`] builds
    /// supply the config's validated identity; candidates can resolve retained
    /// state but never run traffic or mutate its counters.
    ///
    /// `semantics` carries this plugin's **effective** enforcement parameters —
    /// limit dimension, windows, maximums, algorithm parameters, and any
    /// plugin-specific shaping — as they are after the plugin's own parsing,
    /// defaulting, and normalization. It is deliberately not raw config syntax:
    /// two configurations that parse to the same enforcement keep one budget,
    /// so config churn alone cannot mint a fresh one. Together with the shared
    /// posture resolved here (`sync_mode`, and when Redis is enabled the
    /// failure posture and any explicitly configured key prefix) it forms the
    /// compatibility fingerprint: a real enforcement change isolates
    /// immediately onto fresh state, while an unrelated config, ordering, or
    /// HTTP-client rebuild inherits the live budget. Never record a
    /// secret-bearing value there (see [`local_limiter_fingerprint`]).
    pub fn from_plugin_config_with_policy_identity(
        plugin_name: &'static str,
        namespace: Option<&str>,
        config_id: &str,
        config: &Value,
        http_client: &PluginHttpClient,
        algorithm: A,
        semantics: &LocalStateSemantics,
    ) -> Result<Self, String>
    where
        A: SharedLocalLimiterState<Key = K>,
    {
        let shard_amount = http_client.pool_shard_amount();
        let failure_policy = parse_redis_failure_policy(config)?;
        // Resolved before any state is registered so a rejected Redis config
        // cannot register a generation for this identity at all.
        let redis = RedisLimiter::new_with_config_id(
            plugin_name,
            config_id,
            config,
            http_client,
            algorithm.clone(),
        )?;
        let explicit_redis_key_prefix = config.get("redis_key_prefix").and_then(Value::as_str);
        let local = match namespace {
            Some(namespace) => A::registry().resolve(
                namespace,
                plugin_name,
                config_id,
                local_limiter_fingerprint(
                    plugin_name,
                    semantics,
                    redis.is_some(),
                    failure_policy,
                    explicit_redis_key_prefix,
                ),
                // Shard count is the process-wide FERRUM_POOL_SHARD_AMOUNT and
                // is therefore identical for every generation in this process;
                // it is deliberately not a compatibility input, because
                // resetting a live budget is the very failure being fixed.
                || LocalLimiter::new(algorithm.clone(), shard_amount),
            ),
            None => Arc::new(LocalLimiter::new(algorithm.clone(), shard_amount)),
        };
        match redis {
            Some(redis) => Ok(Self::Failover(FailoverLimiter::new(
                plugin_name,
                redis,
                local,
                failure_policy,
            ))),
            None => Ok(Self::Local(local)),
        }
    }

    /// Whether this backend enforces on the same local state as `other`.
    ///
    /// A compatible reload generation for one policy identity must share; an
    /// unrelated policy, tenant, plugin kind, or semantically changed policy
    /// must not. Not a production API.
    #[allow(dead_code)] // used only by external tests; dead in binary test target
    pub(crate) fn shares_local_state_with(&self, other: &Self) -> bool {
        Arc::ptr_eq(self.local_state_arc(), other.local_state_arc())
    }

    fn local_state_arc(&self) -> &Arc<LocalLimiter<K, A>> {
        match self {
            Self::Local(local) => local,
            Self::Failover(failover) => &failover.fallback,
        }
    }

    /// Effective `redis_failure_policy`, or `None` when this backend is
    /// local-only (no centralized store to lose).
    ///
    /// Exposed so external coverage can prove the default is fail-closed and
    /// that `local_fallback` is only reached by explicit configuration.
    pub fn redis_failure_policy(&self) -> Option<RedisFailurePolicy> {
        match self {
            Self::Local(_) => None,
            Self::Failover(failover) => Some(failover.failure_policy),
        }
    }

    /// Effective Redis key prefix, or `None` when this backend is local-only.
    ///
    /// Exposed so policy-isolation coverage can prove that two independent
    /// plugin configs of the same type do not share a default key space.
    pub fn redis_key_prefix(&self) -> Option<&str> {
        match self {
            Self::Local(_) => None,
            Self::Failover(failover) => Some(failover.primary.key_prefix()),
        }
    }

    /// Shard count of the local-only map or Redis-fallback map. Test-only so
    /// production builds do not expose limiter debug state.
    #[cfg(test)]
    pub fn local_map_shard_amount(&self) -> usize {
        match self {
            Self::Local(local) => local.shard_amount(),
            Self::Failover(failover) => failover.fallback.shard_amount(),
        }
    }

    /// Check through Redis when available, or reserve a bounded local/fallback
    /// entry slot atomically. None denies only a previously unseen local key.
    pub async fn check_with_redis_key_and_local_capacity<F>(
        &self,
        local_key: K,
        redis_key: F,
        op: &A::Op,
        max_entries: usize,
    ) -> Option<RateLimitOutcome>
    where
        F: FnOnce() -> String,
    {
        match self {
            Self::Local(local) => {
                local.check_at_with_capacity(local_key, op, Instant::now(), max_entries)
            }
            Self::Failover(failover) => {
                let redis_key = redis_key();
                failover
                    .check_with_local_capacity(local_key, &redis_key, op, max_entries)
                    .await
            }
        }
    }

    pub fn tracked_keys_count(&self) -> usize {
        match self {
            Self::Local(local) => local.tracked_keys_count(),
            Self::Failover(failover) => failover.tracked_keys_count(),
        }
    }

    pub fn prune_stale_at(&self, now: Instant) {
        match self {
            Self::Local(local) => local.prune_stale_at(now),
            Self::Failover(failover) => failover.prune_local_stale_at(now),
        }
    }

    pub fn enforce_capacity(&self, max_entries: usize, now: Instant) {
        match self {
            Self::Local(local) => local.enforce_capacity(max_entries, now),
            Self::Failover(failover) => failover.enforce_local_capacity(max_entries, now),
        }
    }

    /// Seed or refresh a local/fallback key at a controllable instant.
    ///
    /// Test-support only: production admission always uses wall-clock `check`.
    #[allow(dead_code)] // used only by external tests; dead in binary test target
    pub fn check_local_at(&self, key: K, op: &A::Op, now: Instant) -> RateLimitOutcome {
        match self {
            Self::Local(local) => local.check_at(key, op, now),
            Self::Failover(failover) => failover.fallback.check_at(key, op, now),
        }
    }

    /// Local operation with an explicit hard cap. Also used for terminal AI
    /// accounting when centralized enforcement is unavailable; admission still
    /// goes through the configured failover policy.
    pub fn check_local_at_with_capacity(
        &self,
        key: K,
        op: &A::Op,
        now: Instant,
        max_entries: usize,
    ) -> Option<RateLimitOutcome> {
        match self {
            Self::Local(local) => local.check_at_with_capacity(key, op, now, max_entries),
            Self::Failover(failover) => {
                failover
                    .fallback
                    .check_at_with_capacity(key, op, now, max_entries)
            }
        }
    }

    pub fn contains_local_key(&self, key: &K) -> bool {
        match self {
            Self::Local(local) => local.contains_key(key),
            Self::Failover(failover) => failover.contains_local_key(key),
        }
    }

    /// All-shard map length for test reconciliation only.
    #[allow(dead_code)] // used only by external tests; dead in binary test target
    pub(crate) fn map_len_for_test(&self) -> usize {
        match self {
            Self::Local(local) => local.map_len_for_test(),
            Self::Failover(failover) => failover.map_len_for_test(),
        }
    }

    /// All-shard `DashMap::len()` call counter for hot-path regression tests.
    #[allow(dead_code)] // used only by external tests; dead in binary test target
    pub fn all_shard_len_calls_for_test(&self) -> usize {
        match self {
            Self::Local(local) => local.all_shard_len_calls_for_test(),
            Self::Failover(failover) => failover.all_shard_len_calls_for_test(),
        }
    }

    pub fn warmup_hostname(&self) -> Option<String> {
        match self {
            Self::Local(_) => None,
            Self::Failover(failover) => failover.warmup_hostname(),
        }
    }

    /// Configured Redis multiplexed-connection pool size when this backend uses Redis.
    ///
    /// Test-support only: proves `redis_pool_size` flowed from plugin config into
    /// the shared [`RedisRateLimitClient`] (issue #2304).
    #[allow(dead_code)] // used by the external unit-test target
    pub fn redis_pool_size_for_test(&self) -> Option<usize> {
        match self {
            Self::Local(_) => None,
            Self::Failover(failover) => Some(failover.primary.redis_client.pool_size_for_test()),
        }
    }

    /// Shared Redis client Arc for lifecycle tests (issue #2305).
    #[allow(dead_code)] // used by the external unit-test target
    pub fn redis_client_arc_for_test(&self) -> Option<Arc<RedisRateLimitClient>> {
        match self {
            Self::Local(_) => None,
            Self::Failover(failover) => Some(failover.redis_client_arc_for_test()),
        }
    }

    /// Failover health-observer abort handle for lifecycle tests (issue #2305).
    #[allow(dead_code)] // used by the external unit-test target
    pub fn health_observer_abort_for_test(&self) -> Option<tokio::task::AbortHandle> {
        match self {
            Self::Local(_) => None,
            Self::Failover(failover) => failover.health_observer_abort_for_test(),
        }
    }
}

/// Shared consumer cleanup branch: below-cap prune vs over-cap stale reclaim.
///
/// Every rate-limit consumer wrapper routes through this helper so omitted or
/// reversed `prune_stale_at` / `enforce_capacity` wiring is a single shared
/// failure mode rather than six divergent copies. Both arms only drop idle
/// state — live budgets are never force-evicted. Hard cardinality is enforced
/// by atomic admission reservation, not by deleting active keys.
#[inline]
pub fn apply_rate_limit_cleanup<K, A>(
    limiter: &RateLimitBackend<K, A>,
    max_entries: usize,
    now: Instant,
    over_capacity: bool,
) where
    K: Eq + Hash + Clone + Send + Sync + 'static,
    A: RateLimitAlgorithm + Clone,
{
    if over_capacity {
        limiter.enforce_capacity(max_entries, now);
    } else {
        limiter.prune_stale_at(now);
    }
}

#[cfg_attr(not(test), allow(dead_code))]
#[derive(Debug, Clone)]
pub struct FixedWindow {
    limit: u64,
    window_seconds: u64,
}

#[cfg_attr(not(test), allow(dead_code))]
impl FixedWindow {
    pub fn new(limit: u64, window_seconds: u64) -> Self {
        Self {
            limit,
            window_seconds: window_seconds.max(1),
        }
    }

    pub fn weighted_count(&self, previous: u64, current: u64, elapsed_fraction: f64) -> f64 {
        previous as f64 * (1.0 - elapsed_fraction.clamp(0.0, 1.0)) + current as f64
    }

    pub fn outcome(&self, previous: u64, current: u64, elapsed_fraction: f64) -> RateLimitOutcome {
        let weighted = self.weighted_count(previous, current, elapsed_fraction);
        let remaining = (self.limit as f64 - weighted).max(0.0) as u64;
        let allowed = weighted <= self.limit as f64;
        if allowed {
            RateLimitOutcome::allow()
        } else {
            RateLimitOutcome::deny()
        }
        .with_limit(self.limit)
        .with_window(self.window_seconds)
        .with_remaining(remaining)
    }
}

#[derive(Debug)]
pub struct SlidingWindow {
    /// Ring of per-sub-interval request counts. Length is always
    /// [`SLIDING_WINDOW_BUCKET_COUNT`] and never grows with admissions.
    buckets: Box<[u64; SLIDING_WINDOW_BUCKET_COUNT]>,
    /// Absolute monotonic bucket index of the newest live slot.
    current_bucket: u64,
    /// Origin for bucket-index math; set on first admission.
    epoch: Option<Instant>,
    /// Cached sum of live bucket counts.
    total: u64,
    /// Most recent admission, used for idle/activity checks without scanning.
    last_activity: Option<Instant>,
    window_duration: Duration,
    limit: u64,
}

impl SlidingWindow {
    pub fn new(limit: u64, window_duration: Duration) -> Self {
        Self {
            // One allocation when a new key/window is admitted; steady
            // request checks reuse this fixed-size ring without allocation.
            buckets: Box::new([0; SLIDING_WINDOW_BUCKET_COUNT]),
            current_bucket: 0,
            epoch: None,
            total: 0,
            last_activity: None,
            window_duration,
            limit,
        }
    }

    /// Fixed upper bound on retained aggregate buckets for any key/window.
    #[inline]
    #[allow(dead_code)] // used only by external tests; dead in binary test target
    pub const fn bucket_capacity() -> usize {
        SLIDING_WINDOW_BUCKET_COUNT
    }

    /// Number of aggregate bucket slots retained (always [`bucket_capacity`]).
    #[inline]
    #[allow(dead_code)] // used only by external tests; dead in binary test target
    pub fn retained_buckets(&self) -> usize {
        self.buckets.len()
    }

    /// Admissions currently counted inside the live window.
    #[inline]
    #[allow(dead_code)] // used only by external tests; dead in binary test target
    pub fn counted_requests(&self) -> u64 {
        self.total
    }

    /// Check whether the window would allow a request without incrementing.
    /// Advances the bucket ring so the counted total reflects `now`.
    pub fn would_allow(&mut self, now: Instant) -> bool {
        self.advance(now);
        self.total < self.limit
    }

    /// Record a request in the window (caller must have checked `would_allow` first).
    pub fn increment(&mut self, now: Instant) {
        if self.epoch.is_none() {
            self.epoch = Some(now);
            self.current_bucket = 0;
        }
        self.advance(now);
        let slot = (self.current_bucket % SLIDING_WINDOW_BUCKET_COUNT as u64) as usize;
        self.buckets[slot] = self.buckets[slot].saturating_add(1);
        self.total = self.total.saturating_add(1);
        // `LocalLimiter::check` samples `Instant::now()` before the per-key
        // DashMap write guard, so concurrent admissions can arrive in reverse
        // timestamp order. Never move the cleanup watermark backwards: a delayed
        // older sample must not make still-live newer usage look idle.
        self.note_activity(now);
    }

    /// Advance the idle/activity watermark only forward.
    #[inline]
    fn note_activity(&mut self, now: Instant) {
        match self.last_activity {
            Some(last) if now < last => {}
            _ => self.last_activity = Some(now),
        }
    }

    pub fn remaining(&self) -> u64 {
        self.limit.saturating_sub(self.total)
    }

    pub fn has_recent_activity(&self, now: Instant) -> bool {
        let Some(last) = self.last_activity else {
            return false;
        };
        match now.checked_duration_since(last) {
            // The aggregate algorithm intentionally retains the oldest
            // partially overlapping bucket. Cleanup must use the same
            // conservative horizon or it could drop still-counted state and
            // under-enforce on the next request.
            Some(elapsed) => elapsed < sliding_window_retention(self.window_duration),
            // `now` before `last` should not happen on a monotonic clock; treat
            // as still active so cleanup stays fail-closed.
            None => true,
        }
    }

    fn advance(&mut self, now: Instant) {
        let Some(epoch) = self.epoch else {
            return;
        };
        // Checked: a clock that appears to move backwards relative to `epoch`
        // must not panic, and leaves the current ring untouched.
        let Some(elapsed) = now.checked_duration_since(epoch) else {
            return;
        };
        let new_bucket = absolute_sliding_bucket(elapsed, self.window_duration);
        if new_bucket <= self.current_bucket {
            return;
        }
        let steps = new_bucket.saturating_sub(self.current_bucket);
        if steps >= SLIDING_WINDOW_BUCKET_COUNT as u64 {
            self.buckets.fill(0);
            self.total = 0;
        } else {
            let mut bucket = self.current_bucket;
            for _ in 0..steps {
                bucket = bucket.saturating_add(1);
                let slot = (bucket % SLIDING_WINDOW_BUCKET_COUNT as u64) as usize;
                self.total = self.total.saturating_sub(self.buckets[slot]);
                self.buckets[slot] = 0;
            }
        }
        self.current_bucket = new_bucket;
    }
}

/// Map elapsed time onto an absolute aggregate bucket index.
///
/// A configured window spans 63 sub-intervals while the ring retains 64 slots.
/// The extra slot is essential: at the first nominal-window boundary, bucket
/// zero can still contain a request exactly on the inclusive cutoff and must
/// not be reused. It is reused only at the following bucket boundary, when the
/// entire old bucket is outside the intended window.
///
/// Uses `u128` nanosecond math so `elapsed * INTERVALS` cannot wrap before the
/// division by the (admission-bounded) window length.
fn absolute_sliding_bucket(elapsed: Duration, window: Duration) -> u64 {
    let window_nanos = window.as_nanos().max(1);
    let elapsed_nanos = elapsed.as_nanos();
    let indexed = elapsed_nanos.saturating_mul(SLIDING_WINDOW_INTERVALS_PER_WINDOW) / window_nanos;
    u64::try_from(indexed).unwrap_or(u64::MAX)
}

/// Longest time one aggregate bucket may remain counted after its last event.
///
/// This is `ceil(window * 64 / 63)`: the configured window plus at most one
/// sub-interval of deliberate fail-closed over-count. Saturation keeps cleanup
/// conservative even if this helper is called outside the admission-bounded
/// production configuration path.
fn sliding_window_retention(window: Duration) -> Duration {
    let retention_nanos = window
        .as_nanos()
        .saturating_mul(SLIDING_WINDOW_BUCKET_COUNT as u128)
        .div_ceil(SLIDING_WINDOW_INTERVALS_PER_WINDOW);
    let seconds = retention_nanos / 1_000_000_000;
    let nanos = (retention_nanos % 1_000_000_000) as u32;
    match u64::try_from(seconds) {
        Ok(seconds) => Duration::new(seconds, nanos),
        Err(_) => Duration::MAX,
    }
}

#[derive(Debug)]
pub struct TokenBucket {
    tokens: f64,
    capacity: f64,
    refill_rate: f64,
    last_refill: Instant,
}

impl TokenBucket {
    pub fn from_window(limit: u64, window: Duration) -> Self {
        let capacity = limit as f64;
        let window_secs = window.as_secs_f64().max(0.001);
        Self {
            tokens: capacity,
            capacity,
            refill_rate: capacity / window_secs,
            last_refill: Instant::now(),
        }
    }

    pub fn from_rate(capacity: f64, refill_rate: f64) -> Self {
        Self {
            tokens: capacity,
            capacity,
            refill_rate,
            last_refill: Instant::now(),
        }
    }

    pub fn check_and_consume(&mut self, now: Instant, weight: u64) -> bool {
        self.refill(now);
        let weight = weight as f64;
        if self.tokens >= weight {
            self.tokens -= weight;
            true
        } else {
            false
        }
    }

    /// Check whether the bucket would allow consuming `weight` tokens without
    /// actually consuming them. Refills first to ensure an accurate count.
    pub fn would_allow(&mut self, now: Instant, weight: u64) -> bool {
        self.refill(now);
        self.tokens >= weight as f64
    }

    /// Consume `weight` tokens (caller must have checked `would_allow` first).
    pub fn consume(&mut self, weight: u64) {
        self.tokens = (self.tokens - weight as f64).max(0.0);
    }

    pub fn remaining(&self) -> u64 {
        self.tokens.max(0.0) as u64
    }
    pub fn is_active(&self, now: Instant) -> bool {
        if self.refill_rate <= 0.0 || self.capacity <= 0.0 {
            return false;
        }
        let window_secs = self.capacity / self.refill_rate;
        now.checked_duration_since(self.last_refill)
            .is_none_or(|elapsed| elapsed.as_secs_f64() < window_secs * 2.0)
    }

    fn refill(&mut self, now: Instant) {
        // Requests capture `now` before taking the per-key DashMap write guard.
        // Concurrent requests can therefore reach this state in reverse
        // timestamp order. Moving `last_refill` backwards would count the same
        // elapsed interval twice and over-admit; leave state untouched instead.
        let Some(elapsed) = now.checked_duration_since(self.last_refill) else {
            return;
        };
        self.last_refill = now;
        self.tokens = (self.tokens + elapsed.as_secs_f64() * self.refill_rate).min(self.capacity);
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RateLimitWindowSpec {
    pub limit: u64,
    pub duration: Duration,
}

#[derive(Debug)]
pub enum HttpWindowState {
    Sliding(SlidingWindow),
    Bucket(TokenBucket),
}

impl HttpWindowState {
    fn remaining(&self) -> u64 {
        match self {
            Self::Sliding(window) => window.remaining(),
            Self::Bucket(bucket) => bucket.remaining(),
        }
    }

    fn is_active(&self, now: Instant) -> bool {
        match self {
            Self::Sliding(window) => window.has_recent_activity(now),
            Self::Bucket(bucket) => bucket.is_active(now),
        }
    }
}

fn new_http_window_states(specs: &[RateLimitWindowSpec]) -> Vec<HttpWindowState> {
    specs
        .iter()
        .map(|spec| match local_window_algorithm(spec.duration) {
            LocalWindowAlgorithm::TokenBucket => {
                HttpWindowState::Bucket(TokenBucket::from_window(spec.limit, spec.duration))
            }
            LocalWindowAlgorithm::SlidingAggregate => {
                HttpWindowState::Sliding(SlidingWindow::new(spec.limit, spec.duration))
            }
        })
        .collect()
}

fn check_http_windows(
    specs: &[RateLimitWindowSpec],
    state: &mut [HttpWindowState],
    now: Instant,
) -> RateLimitOutcome {
    // Two-pass approach to prevent phantom counter increments.
    // Without this, if window 0 allows+increments but window 1 denies,
    // window 0's counter is inflated — the request was never served but
    // the rate limit budget is consumed.

    // First pass: check all windows without modifying counters.
    for (idx, window) in state.iter_mut().enumerate() {
        let spec = &specs[idx];
        let allowed = match window {
            HttpWindowState::Sliding(sliding) => sliding.would_allow(now),
            HttpWindowState::Bucket(bucket) => bucket.would_allow(now, 1),
        };
        if !allowed {
            return RateLimitOutcome::deny()
                .with_limit(spec.limit)
                .with_window(spec.duration.as_secs());
        }
    }

    // Second pass: all windows allow — now increment all counters.
    let mut tightest: Option<(u64, u64, u64)> = None;
    for (idx, window) in state.iter_mut().enumerate() {
        let spec = &specs[idx];
        match window {
            HttpWindowState::Sliding(sliding) => sliding.increment(now),
            HttpWindowState::Bucket(bucket) => bucket.consume(1),
        }

        let remaining = window.remaining();
        match tightest {
            Some((current_remaining, _, _)) if remaining >= current_remaining => {}
            _ => {
                tightest = Some((remaining, spec.limit, spec.duration.as_secs()));
            }
        }
    }

    let mut outcome = RateLimitOutcome::allow();
    if let Some((remaining, limit, window_seconds)) = tightest {
        outcome = outcome
            .with_remaining(remaining)
            .with_limit(limit)
            .with_window(window_seconds);
    }
    outcome
}

/// Distributed (Redis-backed) multi-window admission check.
///
/// Unlike [`check_http_windows`], which does an explicit check-then-increment
/// across all windows so an earlier (looser) window's budget is never consumed
/// when a later (tighter) window denies, the Redis path **couples the increment
/// to the admission decision**: it `INCR`s each window as it iterates and
/// returns deny as soon as one window's weighted count exceeds its limit.
///
/// # Known limitation (documented phantom increment)
///
/// For a multi-window config (e.g. `100/min` + `10/sec`), a request that is
/// ultimately denied by a later window has *already* incremented every earlier
/// window's Redis counter. So under sustained load the effective limit on the
/// looser windows is slightly *tighter* than configured. This is a deliberate
/// trade-off, not a bug:
///
/// * The increment must be coupled to the decision because multiple gateway
///   instances race on the same key; a separate check-then-increment would
///   open a cross-instance over-admission window (TOCTOU) that a single
///   `INCR`-and-compare avoids without a Lua/`EVAL` script.
/// * The error direction is conservative: it over-counts looser windows and
///   can only make them stricter — it never over-admits, so there is no
///   security or limit-bypass exposure.
///
/// Exactness across multi-window Redis configs would require moving the
/// admission into a single Lua/`EVAL` script that pre-checks every window's
/// projected `(current + cost)` weighted count and only `INCR`s all windows
/// when every window admits (otherwise `INCR`s none and returns the denying
/// window). Tracked as a follow-up enhancement; the current behavior is correct
/// and safe in the conservative direction.
async fn check_http_windows_redis(
    specs: &[RateLimitWindowSpec],
    redis: &RedisRateLimitClient,
    key: &str,
) -> Result<RateLimitOutcome, ()> {
    let mut tightest: Option<(u64, u64, u64)> = None;

    // See the function doc: the increment is intentionally coupled to the
    // admission decision (INCR-then-compare per window) to prevent
    // cross-instance over-admission. For multi-window configs this can consume
    // an earlier (looser) window's budget when a later (tighter) window denies
    // — a conservative over-count, never an over-admit.
    for spec in specs {
        let window = FixedWindow::new(spec.limit, spec.duration.as_secs());
        let progress = RedisRateLimitClient::window_progress(window.window_seconds);
        let curr_idx = progress.index;
        let prev_idx = curr_idx.saturating_sub(1);
        let elapsed_fraction = progress.elapsed_fraction;
        let curr_key = redis.make_slot_key(key, &[&curr_idx.to_string()]);
        let prev_key = redis.make_slot_key(key, &[&prev_idx.to_string()]);
        let ttl = two_window_ttl_seconds(window.window_seconds);

        let (prev_count, curr_count) = redis
            .sliding_window_increment(&prev_key, &curr_key, ttl)
            .await?;
        let weighted = prev_count as f64 * (1.0 - elapsed_fraction) + curr_count as f64;
        if weighted > spec.limit as f64 {
            return Ok(RateLimitOutcome::deny()
                .with_limit(spec.limit)
                .with_window(spec.duration.as_secs()));
        }

        let remaining = (spec.limit as f64 - weighted).max(0.0) as u64;

        match tightest {
            Some((current_remaining, _, _)) if remaining >= current_remaining => {}
            _ => {
                tightest = Some((remaining, spec.limit, spec.duration.as_secs()));
            }
        }
    }

    let mut outcome = RateLimitOutcome::allow();
    if let Some((remaining, limit, window_seconds)) = tightest {
        outcome = outcome
            .with_remaining(remaining)
            .with_limit(limit)
            .with_window(window_seconds);
    }
    Ok(outcome)
}

#[cfg(test)]
#[derive(Debug, Clone, Copy)]
pub struct RequestUnit;

#[cfg(test)]
#[derive(Debug, Clone)]
pub struct HttpRateLimitAlgorithm {
    specs: Arc<[RateLimitWindowSpec]>,
}

#[cfg(test)]
impl HttpRateLimitAlgorithm {
    pub fn new(specs: Vec<RateLimitWindowSpec>) -> Self {
        Self {
            specs: specs.into(),
        }
    }
}

#[cfg(test)]
#[async_trait]
impl RateLimitAlgorithm for HttpRateLimitAlgorithm {
    type State = Vec<HttpWindowState>;
    type Op = RequestUnit;

    fn new_state(&self) -> Self::State {
        new_http_window_states(&self.specs)
    }

    fn check_local(
        &self,
        state: &mut Self::State,
        _op: &Self::Op,
        now: Instant,
    ) -> RateLimitOutcome {
        check_http_windows(&self.specs, state, now)
    }

    async fn check_redis(
        &self,
        redis: &RedisRateLimitClient,
        key: &str,
        _op: &Self::Op,
    ) -> Result<RateLimitOutcome, ()> {
        check_http_windows_redis(&self.specs, redis, key).await
    }

    fn is_state_active(&self, state: &Self::State, now: Instant) -> bool {
        state.iter().any(|window| window.is_active(now))
    }
}

#[derive(Debug, Clone)]
pub struct DynamicRateLimitOp {
    specs: Arc<[RateLimitWindowSpec]>,
}

impl DynamicRateLimitOp {
    pub fn new(specs: Vec<RateLimitWindowSpec>) -> Self {
        Self {
            specs: specs.into(),
        }
    }

    pub fn specs(&self) -> &[RateLimitWindowSpec] {
        &self.specs
    }
}

#[derive(Debug)]
pub struct DynamicHttpRateLimitState {
    specs: Arc<[RateLimitWindowSpec]>,
    windows: Vec<HttpWindowState>,
}

#[derive(Debug, Clone, Copy, Default)]
pub struct DynamicHttpRateLimitAlgorithm;

impl DynamicHttpRateLimitAlgorithm {
    pub fn new() -> Self {
        Self
    }
}

#[async_trait]
impl RateLimitAlgorithm for DynamicHttpRateLimitAlgorithm {
    type State = DynamicHttpRateLimitState;
    type Op = DynamicRateLimitOp;

    fn new_state(&self) -> Self::State {
        DynamicHttpRateLimitState {
            specs: Vec::new().into(),
            windows: Vec::new(),
        }
    }

    fn check_local(
        &self,
        state: &mut Self::State,
        op: &Self::Op,
        now: Instant,
    ) -> RateLimitOutcome {
        if !Arc::ptr_eq(&state.specs, &op.specs) {
            // Pointer inequality alone is NOT a spec change. Every compatible
            // plugin rebuild — a full reload, a global plugin-config change or
            // deletion, a proxy-association edit — constructs a fresh
            // `DynamicRateLimitOp` with the same window values, so keying the
            // reset on identity would discard the retained counters on the
            // first request through the rebuilt instance and defeat the
            // policy-owned local state entirely (issue #4268). Compare the
            // window values instead; only a genuinely different spec resets.
            let specs_changed = {
                let retained: &[RateLimitWindowSpec] = &state.specs;
                let requested: &[RateLimitWindowSpec] = &op.specs;
                retained != requested
            };
            if specs_changed {
                state.windows = new_http_window_states(op.specs());
            }
            // Retarget onto the caller's `Arc` either way, so the steady state
            // after a rebuild is a pointer comparison again and the value
            // compare is paid once per key. Two live cache generations that
            // alternate equal-spec `Arc`s on one key keep retargeting, which is
            // a short slice compare under the per-key write guard already held
            // — never a reset, so neither generation can over-admit.
            state.specs = Arc::clone(&op.specs);
        }
        check_http_windows(op.specs(), &mut state.windows, now)
    }

    async fn check_redis(
        &self,
        redis: &RedisRateLimitClient,
        key: &str,
        op: &Self::Op,
    ) -> Result<RateLimitOutcome, ()> {
        check_http_windows_redis(op.specs(), redis, key).await
    }

    fn is_state_active(&self, state: &Self::State, now: Instant) -> bool {
        state.windows.iter().any(|window| window.is_active(now))
    }
}

/// A single token reservation/charge within the sliding window. The `id`
/// uniquely identifies a `reserve()` so that a later out-of-order
/// reconciliation can release *its own* reservation instead of whichever entry
/// happens to be newest.
///
/// `id == 0` is the "no identity" sentinel: `allocate_id` never hands it out and
/// `adjust_usage` filters it out of reservation lookups.
#[derive(Debug, Clone, Copy)]
struct TokenEntry {
    at: Instant,
    id: u64,
    tokens: u64,
}

/// Hard ceiling on the number of `TokenEntry` records ONE identity's window may
/// retain (`GHSA-q2hx-w52w-c6r3`).
///
/// Before this bound the only limit on per-key history was the configured
/// `token_limit` itself — every retained record carries at least one token — so
/// an admitted budget of `u64::MAX` over a 31-day window (both accepted at
/// construction) let a single identity grow one deque without any practical
/// resource ceiling, and made the reconciliation scan linear in that history.
/// The hard cardinality cap (`MAX_STATE_ENTRIES`) bounds identities, not
/// records per identity.
///
/// 1,024 is far above any realistic in-flight concurrency for one consumer or
/// client IP, so ordinary traffic never coalesces at all, while the worst-case
/// retention per key becomes a small constant instead of a configuration
/// parameter.
const MAX_TOKEN_WINDOW_ENTRIES: usize = 1_024;

/// [`MAX_TOKEN_WINDOW_ENTRIES`] for external bounded-history tests.
#[doc(hidden)]
#[allow(dead_code)] // used only by external tests; dead in binary test target
pub const fn max_token_window_entries_for_test() -> usize {
    MAX_TOKEN_WINDOW_ENTRIES
}

#[derive(Debug)]
pub struct TokenUsageWindow {
    entries: VecDeque<TokenEntry>,
    window_duration: Duration,
    limit: u64,
    total: u64,
    /// Newest admission/reconciliation watermark for idle cleanup. Updated only
    /// forward so reverse-ordered `now` samples (captured before the per-key
    /// write guard) cannot make still-live newer usage look stale.
    last_activity: Option<Instant>,
    /// Monotonic per-window source of reservation ids. `0` is reserved as the
    /// "no reservation" sentinel, so ids handed out start at `1`.
    next_reservation_id: u64,
}

impl TokenUsageWindow {
    fn new(limit: u64, window_duration: Duration) -> Self {
        Self {
            entries: VecDeque::new(),
            window_duration,
            limit,
            total: 0,
            last_activity: None,
            next_reservation_id: 1,
        }
    }

    fn current_usage(&mut self, now: Instant) -> u64 {
        // A maximum admitted window can be longer than the monotonic clock's
        // representable history. Retain all entries when subtraction is not
        // representable so cleanup remains fail-closed instead of panicking.
        let Some(cutoff) = now.checked_sub(self.window_duration) else {
            return self.total;
        };
        while let Some(entry) = self.entries.front() {
            if entry.at < cutoff {
                let expired = entry.tokens;
                self.entries.pop_front();
                self.total = self.total.saturating_sub(expired);
            } else {
                break;
            }
        }
        self.total
    }

    /// Record a charge with no caller-tracked reservation id (positive
    /// reconciliation deltas and any anonymous usage). Returns the id assigned.
    fn record_usage(&mut self, now: Instant, tokens: u64) -> u64 {
        let id = self.allocate_id();
        // Clamp reverse-ordered samples forward so the deque stays chronological
        // for window expiry and the cleanup watermark never moves backward.
        let at = match self.last_activity {
            Some(last) if now < last => last,
            _ => now,
        };
        self.last_activity = Some(at);
        self.entries.push_back(TokenEntry { at, id, tokens });
        self.total = self.total.saturating_add(tokens);
        self.coalesce_oldest_entries();
        id
    }

    /// Keep retained history within [`MAX_TOKEN_WINDOW_ENTRIES`] by AGGREGATING
    /// the two oldest records, never by dropping usage.
    ///
    /// The merged record keeps the sum of both token counts and the NEWER of
    /// the two timestamps, so the window's running total is unchanged and the
    /// merged tokens expire no EARLIER than either constituent would have —
    /// the conservative direction, and the reason this is an accounting
    /// approximation rather than an eviction. A live budget is never reduced to
    /// meet the bound.
    ///
    /// Exactly ONE identity is lost per merge — the OLDEST record's. The
    /// surviving record keeps its own `id`, so its reconciliation still applies
    /// to it normally: a correction is bounded by what THAT reservation
    /// reserved, and the absorbed tokens simply remain as retained usage. A
    /// reconciliation that still targets the absorbed reservation finds no
    /// entry and takes the existing "reservation already gone" path — a
    /// negative correction is dropped (releasing from an unrelated entry would
    /// UNDER-count the budget), a positive one is recorded as new usage.
    ///
    /// Merging from the oldest end is what makes that loss theoretical for real
    /// traffic: in-flight reservations are the NEWEST records, so an identity
    /// would have to hold more than [`MAX_TOKEN_WINDOW_ENTRIES`] unreconciled
    /// requests at once before any of them could lose its release.
    ///
    /// Each insert adds at most one record, so at most one merge runs per
    /// insert and the loop is amortised O(1).
    fn coalesce_oldest_entries(&mut self) {
        while self.entries.len() > MAX_TOKEN_WINDOW_ENTRIES {
            let Some(oldest) = self.entries.pop_front() else {
                return;
            };
            let Some(next) = self.entries.front_mut() else {
                // Cannot happen while the length exceeds a cap of at least 1,
                // but restoring the record keeps the total honest either way.
                self.entries.push_front(oldest);
                return;
            };
            next.tokens = next.tokens.saturating_add(oldest.tokens);
        }
    }

    fn allocate_id(&mut self) -> u64 {
        let id = self.next_reservation_id;
        // Wrap past u64::MAX back to 1 (never 0, the sentinel). Collisions
        // after 2^64 reservations in a single window are not a practical
        // concern, and a stale collision only degrades to the back-pop
        // fallback, never an over-count.
        self.next_reservation_id = self.next_reservation_id.checked_add(1).unwrap_or(1);
        id
    }

    fn reserve(&mut self, now: Instant, tokens: u64) -> RateLimitOutcome {
        let usage = self.current_usage(now);
        let reserved_usage = usage.saturating_add(tokens);
        if reserved_usage > self.limit {
            return RateLimitOutcome::deny()
                .with_limit(self.limit)
                .with_window(self.window_duration.as_secs())
                .with_usage(usage)
                .with_remaining(self.limit.saturating_sub(usage));
        }

        let reservation_id = self.record_usage(now, tokens);
        RateLimitOutcome::allow()
            .with_limit(self.limit)
            .with_window(self.window_duration.as_secs())
            .with_usage(reserved_usage)
            .with_remaining(self.limit.saturating_sub(reserved_usage))
            .with_reservation_id(reservation_id)
    }

    /// Apply a reconciliation `delta` to the window.
    ///
    /// When `reservation_id` matches a live entry, the correction is applied to
    /// *that* entry (its token count becomes `tokens + delta`, floored at zero,
    /// removed when it reaches zero). This keeps accounting correct under
    /// concurrency: an older request's negative reconciliation no longer steals
    /// a newer request's reservation off the back of the queue. The entry's
    /// timestamp is preserved, so its usage still expires on the original
    /// reservation's schedule.
    ///
    /// When a non-zero `reservation_id` is supplied but no matching entry
    /// remains (the reservation already aged out of the window, or a non-2xx
    /// release already removed it and a later final-body rejection re-runs
    /// reconciliation), the outcome depends on the delta sign:
    ///
    /// - **Negative delta → no-op.** The reservation this correction targets is
    ///   already gone, so there is nothing of *this request's* to release.
    ///   Falling through to the back-of-queue release here would pop tokens from
    ///   an unrelated, still-live reservation for the same key and under-count
    ///   the budget (the bug a stale/duplicate reconciliation would otherwise
    ///   cause). The expired reservation's own usage was already dropped by the
    ///   window/TTL or the earlier release, so dropping the delta is correct.
    /// - **Positive delta → append a fresh entry.** Actual usage exceeded the
    ///   (now-expired) reservation; recording the extra consumption never
    ///   under-counts, so it is safe to add it back as new usage.
    ///
    /// When `reservation_id` is `None` (the legacy / anonymous path with no
    /// per-entry identity), positive deltas append a fresh entry and negative
    /// deltas release from the back of the queue, floored at zero.
    fn adjust_usage(&mut self, now: Instant, reservation_id: Option<u64>, delta: i64) {
        if delta == 0 {
            self.current_usage(now);
            return;
        }

        self.current_usage(now);

        if let Some(id) = reservation_id.filter(|id| *id != 0) {
            // PERF: linear scan (and the `retain` below on full release) over the
            // window's entries while the caller holds the per-key shard
            // write-lock. Bounded by MAX_TOKEN_WINDOW_ENTRIES rather than by the
            // key's history, so it no longer grows with `window_seconds × RPS`
            // (GHSA-q2hx-w52w-c6r3): a hot key's completed charges coalesce into
            // a fixed number of records instead of accumulating one per request.
            // This runs at most once per request (reconciliation is idempotent)
            // and off the request-admission hot path. Documented in
            // docs/plugins.md (Local-mode performance).
            if let Some(entry) = self.entries.iter_mut().find(|entry| entry.id == id) {
                let new_tokens = if delta >= 0 {
                    entry.tokens.saturating_add(delta as u64)
                } else {
                    entry.tokens.saturating_sub(delta.unsigned_abs())
                };
                let previous = entry.tokens;
                entry.tokens = new_tokens;
                if new_tokens >= previous {
                    self.total = self.total.saturating_add(new_tokens - previous);
                } else {
                    self.total = self.total.saturating_sub(previous - new_tokens);
                }
                if new_tokens == 0 {
                    self.entries.retain(|entry| entry.id != id);
                }
                return;
            }

            // A reservation id was supplied but the entry is gone. Do NOT fall
            // through to the anonymous back-of-queue release: that would steal a
            // different in-flight reservation's tokens. Only a positive delta
            // (extra usage above an expired reservation) is recorded; a negative
            // delta is a no-op because the reservation it targeted is already
            // released/expired.
            if delta > 0 {
                self.record_usage(now, delta as u64);
            }
            return;
        }

        if delta > 0 {
            self.record_usage(now, delta as u64);
            return;
        }

        let mut remaining_release = delta.unsigned_abs();
        while remaining_release > 0 {
            let Some(entry) = self.entries.back_mut() else {
                self.total = 0;
                break;
            };

            if entry.tokens > remaining_release {
                entry.tokens -= remaining_release;
                self.total = self.total.saturating_sub(remaining_release);
                break;
            }

            remaining_release -= entry.tokens;
            self.total = self.total.saturating_sub(entry.tokens);
            self.entries.pop_back();
        }
    }

    fn remaining(&mut self, now: Instant) -> u64 {
        self.limit.saturating_sub(self.current_usage(now))
    }

    /// Records this window currently retains, and the bytes they occupy.
    ///
    /// Test/diagnostic accessor for the bounded-history guarantee
    /// (`GHSA-q2hx-w52w-c6r3`): it is what lets a deterministic test assert that
    /// records stop growing as completed requests increase, without standing up
    /// a live workload.
    #[doc(hidden)]
    #[allow(dead_code)] // used only by external tests; dead in binary test target
    pub fn retained_records_for_test(&self) -> (usize, usize) {
        (
            self.entries.len(),
            self.entries.len() * std::mem::size_of::<TokenEntry>(),
        )
    }

    fn has_recent_activity(&self, now: Instant) -> bool {
        // Prefer the forward-only watermark over `entries.back()`: concurrent
        // reverse-timestamp admissions can leave an older sample at the back
        // even when newer usage is still live.
        let Some(last) = self.last_activity else {
            return false;
        };
        now.checked_duration_since(last)
            .is_none_or(|elapsed| elapsed < self.window_duration)
    }
}

/// Which backend the original `Reserve` for a reconciliation actually landed
/// on. Carried on `AiRateLimitOp::AdjustUsage` so the reconciliation arm that
/// ends up running (which is always the *currently* healthy backend) can detect
/// a backend switch — Redis recovering, or going down, between the reservation
/// and the reconciliation — and avoid corrupting a backend that never received
/// the reservation. See the `AdjustUsage` arms of `check_local` / `check_redis`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReservationBackend {
    /// The reservation was made in the in-memory `TokenUsageWindow` (Redis was
    /// down at reserve time, or no Redis is configured). Identified by the
    /// outcome carrying a `reservation_id` and no `reserved_window_index`.
    Local,
    /// The reservation was made on the centralized Redis counter. Identified by
    /// the outcome carrying a `reserved_window_index` and no `reservation_id`.
    Redis,
    /// The reservation backend is unknown — the caller stored no reservation
    /// markers (e.g. the estimate was 0 tokens, so nothing was charged). In this
    /// case `delta == actual_tokens` already (`reserved == 0`), so the normal
    /// path is correct and no switch handling is needed.
    Unknown,
}

#[derive(Debug, Clone, Copy)]
pub enum AiRateLimitOp {
    CheckBudget,
    Reserve {
        tokens: u64,
    },
    AdjustUsage {
        /// Id returned by the `Reserve` outcome, so the local window can release
        /// the exact reservation this reconciliation belongs to. `None` (or `0`)
        /// falls back to back-of-queue release. Ignored by the Redis path, whose
        /// counter is aggregate.
        reservation_id: Option<u64>,
        /// Redis window index the `Reserve` credited (from the outcome's
        /// `reserved_window_index`). The Redis path debits THIS window so a
        /// correction for a request that straddled a rollover lands on the
        /// window that received the reservation, not the window current at
        /// reconcile time. `None` falls back to the current window (legacy
        /// behavior). Ignored by the local path, whose per-entry timestamp
        /// already pins the window.
        reserved_window_index: Option<u64>,
        /// Backend the original reservation landed on. The reconciliation arm
        /// that runs is always the currently healthy backend; when it differs
        /// from this value the reservation lives on a *different* backend, so the
        /// stale `reserved` must NOT be subtracted here (it was never charged to
        /// this backend) and the full `actual_tokens` is charged instead. See the
        /// `AdjustUsage` arms below.
        reservation_backend: ReservationBackend,
        /// Actual tokens the request consumed (`0` for a full release, e.g. a
        /// non-2xx response or `on_unmetered_response=warn`). Used to charge the
        /// FULL usage to the now-active backend when a backend switch is detected,
        /// instead of the relative `delta` (which subtracts a `reserved` that the
        /// active backend never received).
        actual_tokens: u64,
        /// `actual_tokens - reserved_tokens`, the normal same-backend correction
        /// applied when no backend switch occurred.
        delta: i64,
    },
}

fn u64_to_i64_saturating(value: u64) -> i64 {
    i64::try_from(value).unwrap_or(i64::MAX)
}

#[derive(Debug, Clone)]
pub struct AiTokenRateAlgorithm {
    token_limit: u64,
    window_seconds: u64,
}

impl AiTokenRateAlgorithm {
    pub fn new(token_limit: u64, window_seconds: u64) -> Self {
        Self {
            token_limit,
            window_seconds: window_seconds.max(1),
        }
    }
}

#[async_trait]
impl RateLimitAlgorithm for AiTokenRateAlgorithm {
    type State = TokenUsageWindow;
    type Op = AiRateLimitOp;

    fn new_state(&self) -> Self::State {
        TokenUsageWindow::new(
            self.token_limit,
            Duration::from_secs(self.window_seconds.max(1)),
        )
    }

    fn check_local(
        &self,
        state: &mut Self::State,
        op: &Self::Op,
        now: Instant,
    ) -> RateLimitOutcome {
        match *op {
            AiRateLimitOp::CheckBudget => {
                let usage = state.current_usage(now);
                let remaining = state.remaining(now);
                let outcome = if usage >= self.token_limit {
                    RateLimitOutcome::deny()
                } else {
                    RateLimitOutcome::allow()
                };
                outcome
                    .with_limit(self.token_limit)
                    .with_window(self.window_seconds)
                    .with_usage(usage)
                    .with_remaining(remaining)
            }
            AiRateLimitOp::Reserve { tokens } => state.reserve(now, tokens),
            AiRateLimitOp::AdjustUsage {
                reservation_id,
                // The local window pins the correction to the right window via
                // the matched entry's preserved timestamp, so the Redis window
                // index is not needed here.
                reserved_window_index: _,
                reservation_backend,
                actual_tokens,
                delta,
            } => {
                if reservation_backend == ReservationBackend::Redis {
                    // Backend switch: the reservation was charged to the Redis
                    // counter, but Redis went down between reserve and reconcile
                    // so this correction is now running against the LOCAL window.
                    // The `reserved` was never charged here, so applying the
                    // relative `delta` (which subtracts that `reserved`) would
                    // pop tokens off an unrelated local reservation and
                    // under-count the budget. Charge the FULL actual usage as
                    // fresh local usage instead; the stale Redis reservation is
                    // left to expire via its window TTL. (`reservation_id` is
                    // `None` for a Redis-origin reservation anyway.)
                    if actual_tokens > 0 {
                        state.record_usage(now, actual_tokens);
                    } else {
                        // Keep the window's expiry bookkeeping current even when
                        // there is nothing to charge (full release of a remote
                        // reservation).
                        state.current_usage(now);
                    }
                } else {
                    state.adjust_usage(now, reservation_id, delta);
                }
                // Surface post-reconcile bucket state so `expose_headers` can
                // refresh `x-ai-ratelimit-usage` / `remaining` after admission.
                let usage = state.current_usage(now);
                let remaining = state.remaining(now);
                RateLimitOutcome::allow()
                    .with_limit(self.token_limit)
                    .with_window(self.window_seconds)
                    .with_usage(usage)
                    .with_remaining(remaining)
            }
        }
    }

    async fn check_redis(
        &self,
        redis: &RedisRateLimitClient,
        key: &str,
        op: &Self::Op,
    ) -> Result<RateLimitOutcome, ()> {
        match *op {
            AiRateLimitOp::CheckBudget => {
                let progress = RedisRateLimitClient::window_progress(self.window_seconds);
                let curr_idx = progress.index;
                let prev_idx = curr_idx.saturating_sub(1);
                let elapsed_fraction = progress.elapsed_fraction;
                let curr_key = redis.make_slot_key(key, &[&curr_idx.to_string()]);
                let prev_key = redis.make_slot_key(key, &[&prev_idx.to_string()]);
                let (prev_count, curr_count) = redis.get_two_counters(&prev_key, &curr_key).await?;
                let weighted = prev_count as f64 * (1.0 - elapsed_fraction) + curr_count as f64;
                let usage = weighted as u64;
                let remaining = self.token_limit.saturating_sub(usage);
                let outcome = if usage >= self.token_limit {
                    RateLimitOutcome::deny()
                } else {
                    RateLimitOutcome::allow()
                };
                Ok(outcome
                    .with_limit(self.token_limit)
                    .with_window(self.window_seconds)
                    .with_usage(usage)
                    .with_remaining(remaining))
            }
            AiRateLimitOp::Reserve { tokens } => {
                let progress = RedisRateLimitClient::window_progress(self.window_seconds);
                let curr_idx = progress.index;
                let prev_idx = curr_idx.saturating_sub(1);
                let elapsed_fraction = progress.elapsed_fraction;
                let curr_key = redis.make_slot_key(key, &[&curr_idx.to_string()]);
                let prev_key = redis.make_slot_key(key, &[&prev_idx.to_string()]);
                let ttl = two_window_ttl_seconds(self.window_seconds);
                let increment = u64_to_i64_saturating(tokens);
                let new_curr_count = redis.incrby_with_expire(&curr_key, increment, ttl).await?;
                let (prev_count, _) = redis.get_two_counters(&prev_key, &curr_key).await?;
                let weighted = prev_count as f64 * (1.0 - elapsed_fraction) + new_curr_count as f64;
                let usage = weighted.max(0.0) as u64;
                let remaining = self.token_limit.saturating_sub(usage);
                if weighted > self.token_limit as f64 {
                    // Roll back the speculative reservation we just added. Use
                    // the floor-at-zero variant (not a raw negative INCRBY): a
                    // concurrent reconciliation racing this rollback on the same
                    // window key could otherwise drive the counter negative,
                    // which later reads as zero usage and lets a consumer
                    // re-reserve the full limit — the exact bypass class the
                    // floor closes for the reconciliation path. Surface a failed
                    // rollback (Redis blip) so a leaked reservation is
                    // observable rather than silently charged until TTL.
                    if let Err(()) = redis
                        .incrby_with_expire_floor_zero(&curr_key, -increment, ttl)
                        .await
                    {
                        // `curr_key` embeds the caller-supplied identity
                        // dimension, so it is not logged.
                        warn_sampled!(
                            "ai_rate_limiter: failed to roll back denied Redis token reservation; \
                             estimate stays charged until the window TTL expires"
                        );
                    }
                    return Ok(RateLimitOutcome::deny()
                        .with_limit(self.token_limit)
                        .with_window(self.window_seconds)
                        .with_usage(usage.saturating_sub(tokens))
                        .with_remaining(
                            self.token_limit
                                .saturating_sub(usage.saturating_sub(tokens)),
                        ));
                }
                Ok(RateLimitOutcome::allow()
                    .with_limit(self.token_limit)
                    .with_window(self.window_seconds)
                    .with_usage(usage)
                    .with_remaining(remaining)
                    // Carry the window this reservation credited so the
                    // reconciliation debits the SAME window even after a
                    // rollover. See the `AdjustUsage` arm below.
                    .with_reserved_window_index(curr_idx))
            }
            AiRateLimitOp::AdjustUsage {
                reservation_id: _,
                reserved_window_index,
                reservation_backend,
                actual_tokens,
                delta,
            } => {
                // Read both live sliding-window counters before mutating either
                // one. If this read fails, failover is still safe because Redis
                // has not been changed. A post-mutation telemetry read could
                // fail after the correction landed and then replay the same
                // operation against the local fallback.
                let progress = RedisRateLimitClient::window_progress(self.window_seconds);
                let curr_idx = progress.index;
                let prev_idx = curr_idx.saturating_sub(1);
                let elapsed_fraction = progress.elapsed_fraction;
                let curr_key = redis.make_slot_key(key, &[&curr_idx.to_string()]);
                let prev_key = redis.make_slot_key(key, &[&prev_idx.to_string()]);
                let (mut prev_count, mut curr_count) =
                    redis.get_two_counters(&prev_key, &curr_key).await?;
                let ttl = two_window_ttl_seconds(self.window_seconds);

                // `reservation_id` identifies the matching entry only in the
                // local in-memory window; the Redis counter is aggregate, so it
                // is intentionally ignored here.
                if reservation_backend == ReservationBackend::Local {
                    // Backend switch: the reservation was charged to the LOCAL
                    // in-memory window (Redis was down at reserve time) but Redis
                    // recovered before this reconciliation, so we are now running
                    // against the centralized counter. The `reserved` was never
                    // credited to Redis, so applying the relative `delta` here is
                    // wrong both ways: a negative delta would subtract from an
                    // unrelated, still-live request's Redis usage (corrupting its
                    // accounting), and a positive delta would only add
                    // `actual - reserved`, under-charging the centralized budget
                    // by the un-credited `reserved`. Charge the FULL actual usage
                    // to the current window instead; the stale local reservation
                    // is left to expire from the in-memory window on its own
                    // schedule. No `reserved_window_index` exists for a
                    // local-origin reservation, so the current window is correct.
                    if actual_tokens > 0 {
                        let increment = u64_to_i64_saturating(actual_tokens);
                        curr_count = redis.incrby_with_expire(&curr_key, increment, ttl).await?;
                    }
                    // `actual_tokens == 0` (full release of a local reservation)
                    // is a no-op against Redis — there is nothing on this backend
                    // to release, and the local reservation expires on its own.
                } else if delta != 0 {
                    // Debit the window the reservation actually credited (carried
                    // back from the `Reserve` outcome) so a request that
                    // straddles a window rollover corrects the right counter. If
                    // the reserved window is unknown (e.g. an `Unknown`-origin
                    // reservation with no markers), fall back to the current
                    // window — the floor below still prevents a budget-bypass.
                    let target_idx = reserved_window_index.unwrap_or(curr_idx);
                    let redis_key = redis.make_slot_key(key, &[&target_idx.to_string()]);
                    // Floor the per-window counter at zero. Reconciliation
                    // deltas are usually negative (reserved ≫ actual; non-2xx
                    // releases the full reservation); a raw INCRBY could drive
                    // the counter negative, which later reads as zero usage and
                    // lets the consumer reserve the full limit again — defeating
                    // centralized enforcement. Matches the floor-at-zero in the
                    // local `TokenUsageWindow::adjust_usage` path.
                    let adjusted_count = redis
                        .incrby_with_expire_floor_zero(&redis_key, delta, ttl)
                        .await?;
                    if target_idx == curr_idx {
                        curr_count = adjusted_count;
                    } else if target_idx == prev_idx {
                        prev_count = adjusted_count;
                    }
                }
                // Compute post-reconcile telemetry without another fallible
                // Redis call after the mutation.
                let weighted = prev_count as f64 * (1.0 - elapsed_fraction) + curr_count as f64;
                let usage = weighted.max(0.0) as u64;
                let remaining = self.token_limit.saturating_sub(usage);
                Ok(RateLimitOutcome::allow()
                    .with_limit(self.token_limit)
                    .with_window(self.window_seconds)
                    .with_usage(usage)
                    .with_remaining(remaining))
            }
        }
    }

    fn is_state_active(&self, state: &Self::State, now: Instant) -> bool {
        state.has_recent_activity(now)
    }
}

/// One `ws_rate_limiting` admission decision covering `frames` physical
/// WebSocket frames.
///
/// A reassembled message can cost many wire frames: the shared relay charges
/// the completing message as one frame and charges the initial non-final frame
/// plus every intermediate continuation frame in a single batched op. Batching
/// keeps the Redis path at one round trip per read instead of one per fragment
/// (GHSA-qq94-2gv2-phh6).
#[derive(Debug, Clone, Copy)]
pub struct WsRateLimitOp {
    frames: u64,
}

impl WsRateLimitOp {
    /// A single-frame charge (one unfragmented message or control frame).
    pub const ONE: Self = Self { frames: 1 };

    /// A batched charge. Zero is normalized to one so an accidental empty
    /// batch can never be a free admission.
    pub fn frames(frames: u64) -> Self {
        Self {
            frames: frames.max(1),
        }
    }

    /// Frames this op charges; always at least one.
    pub fn frame_count(&self) -> u64 {
        self.frames.max(1)
    }
}

#[derive(Debug, Clone)]
pub struct WsFrameRateAlgorithm {
    frames_per_second: f64,
    burst_size: f64,
}

/// Upper bound on the Redis sliding-window length used to approximate the
/// local token bucket for `ws_rate_limiting`, in seconds.
///
/// Redis mode enforces `burst_size` admissions over a fixed window of
/// `burst_size / frames_per_second` seconds. Windows longer than this bound
/// would force multi-hour (or multi-day) per-connection key TTLs. Configs that
/// need a longer refill period are rejected at construction rather than
/// clamping the window while retaining the full burst limit — that clamp
/// previously over-admitted the configured sustained rate by orders of
/// magnitude (GHSA-cjcm-546w-696v).
pub const WS_FRAME_REDIS_MAX_WINDOW_SECONDS: u64 = 3600;

/// Validate `ws_rate_limiting` capacity/refill so local token-bucket and Redis
/// two-window enforcement share the same sustained rate and burst ceiling.
///
/// Accepted configs must:
/// - keep both values in `1..=MAX_RATE_LIMIT_MAX_REQUESTS`
/// - keep `burst_size >= frames_per_second`
/// - make `burst_size` an integer multiple of `frames_per_second` (exact
///   Redis window length; non-integral ratios under-admit on Redis)
/// - keep the derived refill window
///   (`burst_size / frames_per_second`) in `1..=WS_FRAME_REDIS_MAX_WINDOW_SECONDS`
///
/// Rejecting unrepresentable configs is fail-closed: Redis never silently
/// raises the configured frame rate, and Redis failure/recovery cannot change
/// the effective sustained-rate policy for an accepted config.
pub fn validate_ws_frame_rate_params(
    frames_per_second: u64,
    burst_size: u64,
) -> Result<(), String> {
    if frames_per_second == 0 {
        return Err("ws_rate_limiting: 'frames_per_second' must be greater than zero".to_string());
    }
    if burst_size == 0 {
        return Err("ws_rate_limiting: 'burst_size' must be greater than zero".to_string());
    }
    if frames_per_second > MAX_RATE_LIMIT_MAX_REQUESTS {
        return Err(format!(
            "ws_rate_limiting: 'frames_per_second' must be <= {MAX_RATE_LIMIT_MAX_REQUESTS}, got: {frames_per_second}"
        ));
    }
    if burst_size > MAX_RATE_LIMIT_MAX_REQUESTS {
        return Err(format!(
            "ws_rate_limiting: 'burst_size' must be <= {MAX_RATE_LIMIT_MAX_REQUESTS}, got: {burst_size}"
        ));
    }
    if burst_size < frames_per_second {
        return Err(format!(
            "ws_rate_limiting: 'burst_size' ({burst_size}) must be >= 'frames_per_second' ({frames_per_second})"
        ));
    }
    if !burst_size.is_multiple_of(frames_per_second) {
        return Err(format!(
            "ws_rate_limiting: 'burst_size' ({burst_size}) must be an integer multiple of \
             'frames_per_second' ({frames_per_second}) so Redis and local sustained rates match"
        ));
    }
    let window_seconds = burst_size / frames_per_second;
    if window_seconds > WS_FRAME_REDIS_MAX_WINDOW_SECONDS {
        return Err(format!(
            "ws_rate_limiting: 'burst_size' / 'frames_per_second' refill window \
             ({window_seconds}s) exceeds the Redis-representable maximum of \
             {WS_FRAME_REDIS_MAX_WINDOW_SECONDS} seconds"
        ));
    }
    Ok(())
}

impl WsFrameRateAlgorithm {
    pub fn new(frames_per_second: f64, burst_size: f64) -> Self {
        Self {
            frames_per_second,
            burst_size,
        }
    }

    /// Returns `(window_seconds, limit)` for the Redis sliding-window
    /// approximation of the local token bucket.
    ///
    /// For configs admitted by [`validate_ws_frame_rate_params`], the window
    /// is exactly `burst_size / frames_per_second` and the limit is
    /// `burst_size`, so the average sustained rate matches
    /// `frames_per_second`.
    ///
    /// Defense in depth for unvalidated inputs: never raise the sustained
    /// rate above `frames_per_second`. A window that would exceed
    /// [`WS_FRAME_REDIS_MAX_WINDOW_SECONDS`] is capped and the limit is scaled
    /// down with it (`fps * window`), never left at the full burst (the
    /// GHSA-cjcm-546w-696v over-admit). Non-integral ratios still ceil the
    /// window and keep `limit <= burst`, which can only under-admit.
    fn redis_window_derivation(&self) -> (u64, u64) {
        let fps = self.frames_per_second as u64;
        let burst = self.burst_size as u64;
        if fps == 0 {
            // Unreachable after plugin construction validation; deny all.
            return (1, 0);
        }
        if burst >= fps && burst.is_multiple_of(fps) {
            let window = burst / fps;
            if (1..=WS_FRAME_REDIS_MAX_WINDOW_SECONDS).contains(&window) {
                return (window, burst);
            }
        }

        let raw_window = burst.div_ceil(fps).max(1);
        let window_seconds = raw_window.min(WS_FRAME_REDIS_MAX_WINDOW_SECONDS);
        let limit = fps.saturating_mul(window_seconds).min(burst);
        (window_seconds, limit)
    }
}

#[async_trait]
impl RateLimitAlgorithm for WsFrameRateAlgorithm {
    type State = TokenBucket;
    type Op = WsRateLimitOp;

    fn new_state(&self) -> Self::State {
        TokenBucket::from_rate(self.burst_size, self.frames_per_second)
    }

    fn check_local(
        &self,
        state: &mut Self::State,
        op: &Self::Op,
        now: Instant,
    ) -> RateLimitOutcome {
        // All-or-nothing: a batch larger than the remaining budget consumes
        // nothing and is denied, which is terminal for the connection. A batch
        // larger than `burst_size` can never be admitted — that is the intended
        // fail-closed answer for a message built from more wire frames than the
        // configured burst.
        let outcome = if state.check_and_consume(now, op.frame_count()) {
            RateLimitOutcome::allow()
        } else {
            RateLimitOutcome::deny()
        };
        outcome
            .with_limit(self.burst_size as u64)
            .with_remaining(state.remaining())
    }

    async fn check_redis(
        &self,
        redis: &RedisRateLimitClient,
        key: &str,
        op: &Self::Op,
    ) -> Result<RateLimitOutcome, ()> {
        // Approximate the local TokenBucket via a sliding two-window check
        // over the bucket's full-refill period. See `redis_window_derivation`
        // for the (window_seconds, limit) contract. The previous
        // implementation hard-coded a 1-second window with `burst_size` as
        // the limit, which silently ignored `frames_per_second` and admitted
        // up to `burst_size` frames every second indefinitely — much higher
        // than the configured sustained rate.
        let (window_seconds, limit) = self.redis_window_derivation();

        let progress = RedisRateLimitClient::window_progress(window_seconds);
        let curr_idx = progress.index;
        let prev_idx = curr_idx.saturating_sub(1);
        let elapsed_fraction = progress.elapsed_fraction;
        let curr_key = redis.make_slot_key(key, &[&curr_idx.to_string()]);
        let prev_key = redis.make_slot_key(key, &[&prev_idx.to_string()]);
        let ttl = two_window_ttl_seconds(window_seconds);

        // Charge the whole batch in one round trip. `frame_count()` is bounded
        // by the relay's incomplete-message frame ceiling, so the INCRBY amount
        // cannot be driven arbitrarily high by a peer (GHSA-qq94-2gv2-phh6).
        let charge = i64::try_from(op.frame_count()).unwrap_or(i64::MAX);
        let (prev_count, curr_count) = redis
            .sliding_window_increment_by(&prev_key, &curr_key, charge, ttl)
            .await?;
        let weighted = prev_count as f64 * (1.0 - elapsed_fraction) + curr_count as f64;
        let allowed = weighted <= limit as f64;
        let remaining = ((limit as f64) - weighted).max(0.0) as u64;

        let outcome = if allowed {
            RateLimitOutcome::allow()
        } else {
            RateLimitOutcome::deny()
        };
        Ok(outcome
            .with_limit(limit)
            .with_window(window_seconds)
            .with_remaining(remaining))
    }

    fn is_state_active(&self, state: &Self::State, now: Instant) -> bool {
        state.is_active(now)
    }
}

pub struct UdpWindowState {
    count: AtomicU64,
    bytes: AtomicU64,
    window_epoch: AtomicU64,
    last_check_secs: AtomicU64,
}

impl UdpWindowState {
    fn new(epoch: u64, now_secs: u64) -> Self {
        Self {
            count: AtomicU64::new(0),
            bytes: AtomicU64::new(0),
            window_epoch: AtomicU64::new(epoch),
            last_check_secs: AtomicU64::new(now_secs),
        }
    }

    fn is_stale(&self, now_secs: u64, max_idle_secs: u64) -> bool {
        let last = self.last_check_secs.load(Ordering::Relaxed);
        now_secs.saturating_sub(last) > max_idle_secs
    }
}

#[derive(Debug, Clone, Copy)]
pub struct UdpRateLimitOp {
    pub datagram_size: u64,
}

#[derive(Debug, Clone)]
pub struct UdpRateLimitAlgorithm {
    datagrams_per_window: Option<u64>,
    bytes_per_window: Option<u64>,
    window_seconds: u64,
    epoch_base: Instant,
}

impl UdpRateLimitAlgorithm {
    pub fn new(
        datagrams_per_window: Option<u64>,
        bytes_per_window: Option<u64>,
        window_seconds: u64,
        epoch_base: Instant,
    ) -> Self {
        Self {
            datagrams_per_window,
            bytes_per_window,
            window_seconds: window_seconds.max(1),
            epoch_base,
        }
    }
}

#[async_trait]
impl RateLimitAlgorithm for UdpRateLimitAlgorithm {
    type State = UdpWindowState;
    type Op = UdpRateLimitOp;

    fn new_state(&self) -> Self::State {
        UdpWindowState::new(0, 0)
    }

    fn check_local(
        &self,
        state: &mut Self::State,
        op: &Self::Op,
        now: Instant,
    ) -> RateLimitOutcome {
        let now_secs = now.saturating_duration_since(self.epoch_base).as_secs();
        let current_epoch = now_secs / self.window_seconds;
        let stored_epoch = state.window_epoch.load(Ordering::Acquire);

        if current_epoch > stored_epoch
            && state
                .window_epoch
                .compare_exchange(
                    stored_epoch,
                    current_epoch,
                    Ordering::Release,
                    Ordering::Relaxed,
                )
                .is_ok()
        {
            state.count.store(0, Ordering::Release);
            state.bytes.store(0, Ordering::Release);
        }

        // Same reverse-arrival hazard as SlidingWindow/`TokenBucket`: `now` is
        // sampled before the per-key write guard. `fetch_max` keeps the idle
        // watermark monotonic so a delayed older datagram cannot make newer
        // live usage look stale to cleanup.
        state.last_check_secs.fetch_max(now_secs, Ordering::Relaxed);

        let new_count = saturating_atomic_add(&state.count, 1);
        let new_bytes = saturating_atomic_add(&state.bytes, op.datagram_size);

        if let Some(max_datagrams) = self.datagrams_per_window
            && new_count > max_datagrams
        {
            return RateLimitOutcome::deny()
                .with_limit(max_datagrams)
                .with_window(self.window_seconds)
                .with_usage(new_count)
                .with_metric("count");
        }

        if let Some(max_bytes) = self.bytes_per_window
            && new_bytes > max_bytes
        {
            return RateLimitOutcome::deny()
                .with_limit(max_bytes)
                .with_window(self.window_seconds)
                .with_usage(new_bytes)
                .with_metric("bytes");
        }

        RateLimitOutcome::allow()
    }

    async fn check_redis(
        &self,
        redis: &RedisRateLimitClient,
        key: &str,
        op: &Self::Op,
    ) -> Result<RateLimitOutcome, ()> {
        let window_idx = RedisRateLimitClient::window_index(self.window_seconds);
        let ttl = single_window_ttl_seconds(self.window_seconds);

        match self.datagrams_per_window {
            Some(max_datagrams) if self.bytes_per_window.is_some() => {
                let datagram_key =
                    redis.make_slot_key(key, &["datagrams", &window_idx.to_string()]);
                let bytes_key = redis.make_slot_key(key, &["bytes", &window_idx.to_string()]);
                let (count, bytes) = redis
                    .incr_and_incrby_with_expire(
                        &datagram_key,
                        &bytes_key,
                        u64_to_i64_saturating(op.datagram_size),
                        ttl,
                    )
                    .await?;
                if count as u64 > max_datagrams {
                    return Ok(RateLimitOutcome::deny()
                        .with_limit(max_datagrams)
                        .with_window(self.window_seconds)
                        .with_usage(count as u64)
                        .with_metric("count"));
                }
                if let Some(max_bytes) = self.bytes_per_window
                    && bytes as u64 > max_bytes
                {
                    return Ok(RateLimitOutcome::deny()
                        .with_limit(max_bytes)
                        .with_window(self.window_seconds)
                        .with_usage(bytes as u64)
                        .with_metric("bytes"));
                }
            }
            Some(max_datagrams) => {
                let datagram_key =
                    redis.make_slot_key(key, &["datagrams", &window_idx.to_string()]);
                let count = redis.incr_with_expire(&datagram_key, ttl).await?;
                if count as u64 > max_datagrams {
                    return Ok(RateLimitOutcome::deny()
                        .with_limit(max_datagrams)
                        .with_window(self.window_seconds)
                        .with_usage(count as u64)
                        .with_metric("count"));
                }
            }
            None => {
                if let Some(max_bytes) = self.bytes_per_window {
                    let bytes_key = redis.make_slot_key(key, &["bytes", &window_idx.to_string()]);
                    let bytes = redis
                        .incrby_with_expire(
                            &bytes_key,
                            u64_to_i64_saturating(op.datagram_size),
                            ttl,
                        )
                        .await?;
                    if bytes as u64 > max_bytes {
                        return Ok(RateLimitOutcome::deny()
                            .with_limit(max_bytes)
                            .with_window(self.window_seconds)
                            .with_usage(bytes as u64)
                            .with_metric("bytes"));
                    }
                }
            }
        }

        Ok(RateLimitOutcome::allow())
    }

    fn is_state_active(&self, state: &Self::State, now: Instant) -> bool {
        let now_secs = now.saturating_duration_since(self.epoch_base).as_secs();
        let max_idle = self.window_seconds.saturating_mul(2).max(10);
        !state.is_stale(now_secs, max_idle)
    }
}

/// Atomically add without allowing a wrapped counter to reset enforcement.
fn saturating_atomic_add(counter: &AtomicU64, value: u64) -> u64 {
    match counter.fetch_update(Ordering::AcqRel, Ordering::Acquire, |current| {
        Some(current.saturating_add(value))
    }) {
        Ok(previous) => previous.saturating_add(value),
        // The closure always returns `Some`; keep the observed value as a
        // fail-closed fallback if that invariant ever changes.
        Err(current) => current,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::PoolConfig;
    use crate::dns::{DnsCache, DnsConfig};
    use serde_json::json;

    #[derive(Clone)]
    struct TestAlgorithm {
        redis_ok: Arc<AtomicBool>,
    }

    #[derive(Default)]
    struct TestState {
        count: u64,
        last_seen: Option<Instant>,
    }

    #[derive(Clone, Copy)]
    struct TestOp;

    #[async_trait]
    impl RateLimitAlgorithm for TestAlgorithm {
        type State = TestState;
        type Op = TestOp;

        fn new_state(&self) -> Self::State {
            TestState::default()
        }

        fn check_local(
            &self,
            state: &mut Self::State,
            _op: &Self::Op,
            now: Instant,
        ) -> RateLimitOutcome {
            state.count += 1;
            state.last_seen = Some(now);
            RateLimitOutcome::allow().with_usage(state.count)
        }

        async fn check_redis(
            &self,
            _redis: &RedisRateLimitClient,
            _key: &str,
            _op: &Self::Op,
        ) -> Result<RateLimitOutcome, ()> {
            if self.redis_ok.load(Ordering::Relaxed) {
                Ok(RateLimitOutcome::allow().with_usage(99))
            } else {
                Err(())
            }
        }

        fn is_state_active(&self, state: &Self::State, now: Instant) -> bool {
            state
                .last_seen
                .is_some_and(|last_seen| now.duration_since(last_seen) < Duration::from_secs(10))
        }
    }

    fn namespaced_http_client(namespace: &str) -> PluginHttpClient {
        http_client_with_shards(namespace, 0)
    }

    fn http_client_with_shards(namespace: &str, pool_shard_amount: usize) -> PluginHttpClient {
        PluginHttpClient::new(
            &PoolConfig::default(),
            DnsCache::new(DnsConfig::default()),
            1000,
            0,
            100,
            false,
            None,
            std::sync::Arc::new(Vec::new()),
            namespace,
            crate::config::BackendEgressPolicy::unrestricted(),
            std::sync::Arc::new(Vec::new()),
            pool_shard_amount,
        )
    }

    fn test_redis_limiter(
        http_client: &PluginHttpClient,
        algorithm: TestAlgorithm,
    ) -> RedisLimiter<TestAlgorithm> {
        match RedisLimiter::new(
            "rate_limiting",
            &json!({
                "sync_mode": "redis",
                "redis_url": "redis://127.0.0.1:6379/0",
                "redis_health_check_interval_seconds": 1
            }),
            http_client,
            algorithm,
        ) {
            Ok(Some(limiter)) => limiter,
            Ok(None) => panic!("redis limiter should be enabled by sync_mode=redis"),
            Err(error) => panic!("redis limiter config should be valid: {error}"),
        }
    }

    #[test]
    fn ws_frame_rate_redis_window_derivation_normal_cases() {
        // The reviewed regression: `frames_per_second` must drive
        // `window_seconds`, not be silently dropped. Each pair is
        // `(fps, burst) -> (window_seconds, limit)`.
        //
        // burst == fps → 1-second window
        let alg = WsFrameRateAlgorithm::new(100.0, 100.0);
        assert_eq!(alg.redis_window_derivation(), (1, 100));
        // burst = 4 * fps → 4-second window
        let alg = WsFrameRateAlgorithm::new(5.0, 20.0);
        assert_eq!(alg.redis_window_derivation(), (4, 20));
        // Max representable refill window (validated at construction)
        let alg = WsFrameRateAlgorithm::new(1.0, WS_FRAME_REDIS_MAX_WINDOW_SECONDS as f64);
        assert_eq!(
            alg.redis_window_derivation(),
            (
                WS_FRAME_REDIS_MAX_WINDOW_SECONDS,
                WS_FRAME_REDIS_MAX_WINDOW_SECONDS
            )
        );
    }

    #[test]
    fn ws_frame_rate_redis_window_derivation_fail_closed_for_unvalidated_inputs() {
        // GHSA-cjcm-546w-696v: never clamp the window while retaining a limit
        // that raises the configured sustained rate. Unvalidated pathological
        // inputs scale the limit down with the capped window.
        let alg = WsFrameRateAlgorithm::new(1.0, 10_000_000.0);
        assert_eq!(
            alg.redis_window_derivation(),
            (
                WS_FRAME_REDIS_MAX_WINDOW_SECONDS,
                WS_FRAME_REDIS_MAX_WINDOW_SECONDS
            )
        );
        // Non-integral ratio: ceil window, keep limit <= burst (under-admit).
        // Construction rejects these; derivation must not over-admit if reached.
        let alg = WsFrameRateAlgorithm::new(3.0, 10.0);
        assert_eq!(alg.redis_window_derivation(), (4, 10));
    }

    #[test]
    fn validate_ws_frame_rate_params_rejects_unrepresentable_ratios() {
        assert!(validate_ws_frame_rate_params(100, 100).is_ok());
        assert!(validate_ws_frame_rate_params(50, 100).is_ok());
        assert!(validate_ws_frame_rate_params(1, WS_FRAME_REDIS_MAX_WINDOW_SECONDS).is_ok());

        let err = validate_ws_frame_rate_params(50, 75).unwrap_err();
        assert!(err.contains("integer multiple"), "{err}");

        let err =
            validate_ws_frame_rate_params(1, WS_FRAME_REDIS_MAX_WINDOW_SECONDS + 1).unwrap_err();
        assert!(err.contains("Redis-representable maximum"), "{err}");

        let err = validate_ws_frame_rate_params(1, 10_000_000).unwrap_err();
        assert!(
            err.contains("must be <=") || err.contains("Redis-representable"),
            "{err}"
        );

        let err = validate_ws_frame_rate_params(100, 50).unwrap_err();
        assert!(err.contains("must be >="), "{err}");

        let err = validate_ws_frame_rate_params(
            MAX_RATE_LIMIT_MAX_REQUESTS + 1,
            MAX_RATE_LIMIT_MAX_REQUESTS + 1,
        )
        .unwrap_err();
        assert!(err.contains("frames_per_second"), "{err}");
    }

    #[test]
    fn fixed_window_weighted_math_matches_two_window_approximation() {
        let window = FixedWindow::new(10, 60);
        let weighted = window.weighted_count(8, 4, 0.25);
        assert!((weighted - 10.0).abs() < f64::EPSILON);
        let outcome = window.outcome(8, 4, 0.25);
        assert!(outcome.allowed);
        assert_eq!(outcome.remaining, Some(0));
    }

    #[test]
    fn local_window_algorithm_threshold_matches_http_construction() {
        assert_eq!(
            local_window_algorithm(Duration::from_secs(5)),
            LocalWindowAlgorithm::TokenBucket
        );
        assert_eq!(
            local_window_algorithm(Duration::from_secs(6)),
            LocalWindowAlgorithm::SlidingAggregate
        );
    }

    #[test]
    fn sliding_window_state_stays_bucket_bounded_under_sustained_hot_key() {
        // GHSA-jjjw-rqjm-fvf3: one hot key at a high cap must not retain one
        // Instant per admission. Aggregate buckets are a fixed ring.
        let mut window = SlidingWindow::new(100_000, Duration::from_secs(60));
        let t0 = Instant::now();
        for i in 0..50_000u64 {
            assert!(window.would_allow(t0), "admission {i} must pass");
            window.increment(t0);
            assert_eq!(window.retained_buckets(), SLIDING_WINDOW_BUCKET_COUNT);
            assert_eq!(window.retained_buckets(), SlidingWindow::bucket_capacity());
        }
        assert_eq!(window.counted_requests(), 50_000);
        assert_eq!(window.remaining(), 50_000);
        // Fill to the limit and prove deny without growing state.
        while window.would_allow(t0) {
            window.increment(t0);
            assert_eq!(window.retained_buckets(), SLIDING_WINDOW_BUCKET_COUNT);
        }
        assert!(!window.would_allow(t0));
        assert_eq!(window.counted_requests(), 100_000);
        assert_eq!(window.remaining(), 0);
        assert_eq!(window.retained_buckets(), SLIDING_WINDOW_BUCKET_COUNT);
    }

    #[test]
    fn sliding_window_enforces_limit_boundary_and_ages_out() {
        let mut window = SlidingWindow::new(3, Duration::from_secs(60));
        let t0 = Instant::now();
        for _ in 0..3 {
            assert!(window.would_allow(t0));
            window.increment(t0);
        }
        assert!(!window.would_allow(t0));
        assert_eq!(window.remaining(), 0);

        let Some(later) = t0.checked_add(Duration::from_secs(61)) else {
            return;
        };
        assert!(
            window.would_allow(later),
            "full window age-out must clear the aggregate count"
        );
        assert_eq!(window.counted_requests(), 0);
        assert_eq!(window.retained_buckets(), SLIDING_WINDOW_BUCKET_COUNT);
    }

    #[test]
    fn sliding_window_advance_uses_checked_time_arithmetic() {
        // A freshly constructed window with no epoch must not panic when
        // asked about a time that cannot subtract the full window from now.
        let mut window = SlidingWindow::new(1, Duration::from_secs(MAX_RATE_LIMIT_WINDOW_SECONDS));
        let now = Instant::now();
        assert!(window.would_allow(now));
        window.increment(now);
        assert!(!window.would_allow(now));
        assert!(window.has_recent_activity(now));
        assert_eq!(window.retained_buckets(), SLIDING_WINDOW_BUCKET_COUNT);
    }

    #[test]
    fn token_bucket_consume_saturates_at_zero() {
        let mut bucket = TokenBucket::from_window(1, Duration::from_secs(1));
        bucket.consume(2);
        assert_eq!(bucket.remaining(), 0);
    }

    #[test]
    fn ai_token_window_over_release_floors_at_zero() {
        // In-memory equivalent of the Redis reconciliation bypass: a
        // reconciliation delta more negative than the outstanding usage must
        // floor the window at zero, not leave it negative. A negative counter
        // would later read as zero usage and let the consumer reserve the full
        // limit again, defeating budget enforcement. The Redis path mirrors
        // this via `RedisRateLimitClient::incrby_with_expire_floor_zero`
        // (regression for the centralized path requires a live Redis server and
        // is covered by functional/ignored tests).
        let algorithm = AiTokenRateAlgorithm::new(1000, 60);
        let mut state = algorithm.new_state();
        let now = Instant::now();

        // Reserve 100 tokens, then over-release by reconciling -500 (e.g. a
        // full reservation release stacked on a low actual count).
        let reserved =
            algorithm.check_local(&mut state, &AiRateLimitOp::Reserve { tokens: 100 }, now);
        assert!(reserved.allowed);
        algorithm.check_local(
            &mut state,
            &AiRateLimitOp::AdjustUsage {
                reservation_id: None,
                reserved_window_index: None,
                reservation_backend: ReservationBackend::Local,
                actual_tokens: 0,
                delta: -500,
            },
            now,
        );

        // Usage must be floored at zero, and the full limit must remain
        // available — never more than the limit (which a negative counter would
        // wrongly imply by reading as zero usage while extra capacity leaks).
        let budget = algorithm.check_local(&mut state, &AiRateLimitOp::CheckBudget, now);
        assert!(budget.allowed);
        assert_eq!(budget.usage, Some(0));
        assert_eq!(budget.remaining, Some(1000));

        // A fresh full-limit reservation should succeed exactly once and then
        // deny — proving the counter is at zero, not negative.
        let full = algorithm.check_local(&mut state, &AiRateLimitOp::Reserve { tokens: 1000 }, now);
        assert!(full.allowed);
        let over = algorithm.check_local(&mut state, &AiRateLimitOp::Reserve { tokens: 1 }, now);
        assert!(!over.allowed);
    }

    #[test]
    fn ai_token_window_local_reserve_has_no_redis_window_index() {
        // codex P2 (reserved-window targeting): `reserved_window_index` is a
        // Redis-only concept. The local path must leave it `None` (the in-memory
        // window pins the correction via the matched entry's timestamp), so a
        // local-mode reservation never carries a stray Redis window index into
        // reconciliation.
        let algorithm = AiTokenRateAlgorithm::new(1000, 60);
        let mut state = algorithm.new_state();
        let now = Instant::now();

        let reserved =
            algorithm.check_local(&mut state, &AiRateLimitOp::Reserve { tokens: 100 }, now);
        assert!(reserved.allowed);
        assert!(
            reserved.reserved_window_index.is_none(),
            "local-mode reserve must not carry a Redis window index"
        );
        assert!(
            reserved.reservation_id.is_some(),
            "local-mode reserve must carry a per-entry reservation id"
        );
    }

    #[test]
    fn ai_token_window_local_adjust_ignores_reserved_window_index() {
        // A `reserved_window_index` carried on the op (e.g. a request that began
        // in Redis mode then fell back to local) must be harmlessly ignored by
        // the local path — accounting stays correct and pinned by reservation id.
        let algorithm = AiTokenRateAlgorithm::new(1000, 60);
        let mut state = algorithm.new_state();
        let now = Instant::now();

        let reserved =
            algorithm.check_local(&mut state, &AiRateLimitOp::Reserve { tokens: 200 }, now);
        let id = reserved.reservation_id.expect("reserve returns an id");

        algorithm.check_local(
            &mut state,
            &AiRateLimitOp::AdjustUsage {
                reservation_id: Some(id),
                // A non-None Redis window index must not affect the local path.
                reserved_window_index: Some(123_456),
                reservation_backend: ReservationBackend::Local,
                actual_tokens: 0,
                delta: -50,
            },
            now,
        );

        let budget = algorithm.check_local(&mut state, &AiRateLimitOp::CheckBudget, now);
        assert_eq!(
            budget.usage,
            Some(150),
            "local adjust must shrink the matched reservation regardless of the Redis window index"
        );
    }

    #[test]
    fn ai_token_window_local_reconcile_of_redis_origin_reservation_charges_full_actual() {
        // codex P2 (backend switch — Redis recovery/outage between reserve and
        // reconcile): the original reservation was charged to the centralized
        // REDIS counter (`reservation_backend == Redis`), but the reconciliation
        // is now running against the LOCAL window (Redis went down before the
        // response landed). The `reserved` was never charged to this local
        // window, so the reconciliation must NOT apply the relative `delta`
        // (which subtracts that `reserved`) — that would pop tokens off an
        // unrelated, still-live local reservation and under-count the budget.
        // Instead it charges the FULL actual usage to the local window as fresh
        // usage; the stale Redis reservation is left to expire via its TTL.
        let algorithm = AiTokenRateAlgorithm::new(1000, 60);
        let mut state = algorithm.new_state();
        let now = Instant::now();

        // An unrelated, still-live LOCAL reservation for the same key. The
        // backend-switch reconciliation must leave this completely untouched.
        let live = algorithm.check_local(&mut state, &AiRateLimitOp::Reserve { tokens: 200 }, now);
        let live_id = live.reservation_id.expect("local reserve returns an id");
        assert!(live.allowed);

        // Reconcile a request that reserved 100 tokens ON REDIS and actually used
        // 40. The relative delta (40 - 100 = -60) is what the SAME-backend path
        // would apply; it must be IGNORED here. `reservation_id` is `None`
        // (Redis-origin reservations carry only a window index) and
        // `reserved_window_index` is `Some` on the wire — neither is consulted on
        // the switch path.
        algorithm.check_local(
            &mut state,
            &AiRateLimitOp::AdjustUsage {
                reservation_id: None,
                reserved_window_index: Some(7),
                reservation_backend: ReservationBackend::Redis,
                actual_tokens: 40,
                delta: -60,
            },
            now,
        );

        // Local usage must be the live 200 PLUS the full 40 actual charged for
        // the switched request — never 200 - 60 = 140 (which the corrupting
        // relative-delta path would produce by stealing from the live entry).
        let budget = algorithm.check_local(&mut state, &AiRateLimitOp::CheckBudget, now);
        assert_eq!(
            budget.usage,
            Some(240),
            "backend switch must charge the full actual (40) on top of the live 200, not subtract the stale Redis reserved"
        );

        // The live reservation is intact and still releasable by its own id.
        algorithm.check_local(
            &mut state,
            &AiRateLimitOp::AdjustUsage {
                reservation_id: Some(live_id),
                reserved_window_index: None,
                reservation_backend: ReservationBackend::Local,
                actual_tokens: 0,
                delta: -200,
            },
            now,
        );
        let budget = algorithm.check_local(&mut state, &AiRateLimitOp::CheckBudget, now);
        assert_eq!(
            budget.usage,
            Some(40),
            "releasing the untouched live reservation leaves only the switched request's 40"
        );
    }

    #[test]
    fn ai_token_window_local_reconcile_of_redis_origin_full_release_is_local_noop() {
        // The release variant of the backend switch: a Redis-origin reservation
        // (`reservation_backend == Redis`) reconciled on the LOCAL window with
        // `actual_tokens == 0` (a non-2xx response or `on_unmetered_response=warn`
        // released the full reservation). There is nothing of this request's on
        // the local window, so the reconciliation must be a no-op locally — it
        // must not subtract the stale Redis `reserved` from an unrelated live
        // local reservation.
        let algorithm = AiTokenRateAlgorithm::new(1000, 60);
        let mut state = algorithm.new_state();
        let now = Instant::now();

        let live = algorithm.check_local(&mut state, &AiRateLimitOp::Reserve { tokens: 150 }, now);
        assert!(live.allowed);

        algorithm.check_local(
            &mut state,
            &AiRateLimitOp::AdjustUsage {
                reservation_id: None,
                reserved_window_index: Some(3),
                reservation_backend: ReservationBackend::Redis,
                actual_tokens: 0,
                // Full release of a 120-token Redis reservation (0 - 120).
                delta: -120,
            },
            now,
        );

        let budget = algorithm.check_local(&mut state, &AiRateLimitOp::CheckBudget, now);
        assert_eq!(
            budget.usage,
            Some(150),
            "a full-release reconciliation for a Redis-origin reservation must not touch local usage"
        );
    }

    // The mirror direction — a LOCAL-origin reservation reconciled on the REDIS
    // counter after Redis recovered (`check_redis` AdjustUsage arm with
    // `reservation_backend == Local`) — charges the full actual to the current
    // Redis window and never subtracts the un-credited local `reserved`. It is
    // exercised against a live Redis server in the functional/ignored suite,
    // matching the existing centralized floor-at-zero coverage note above; the
    // in-memory half of the same invariant is asserted by the two tests above.

    #[test]
    fn ai_token_window_reserve_allows_then_denies_at_limit() {
        // The `Reserve` op pre-charges the estimate against the window. A
        // reservation that fits returns `allow` with the reserved usage folded
        // into `usage`/`remaining`; the next reservation that would cross the
        // limit must `deny` WITHOUT charging (usage/remaining unchanged from the
        // pre-deny state) so the window is not corrupted by rejected attempts.
        let algorithm = AiTokenRateAlgorithm::new(100, 60);
        let mut state = algorithm.new_state();
        let now = Instant::now();

        let first = algorithm.check_local(&mut state, &AiRateLimitOp::Reserve { tokens: 60 }, now);
        assert!(first.allowed);
        assert_eq!(first.limit, Some(100));
        assert_eq!(first.window_seconds, Some(60));
        assert_eq!(first.usage, Some(60));
        assert_eq!(first.remaining, Some(40));

        // 60 + 60 = 120 > 100 → deny. The deny outcome reports usage as the
        // already-committed 60 (the new reservation is rejected, not applied).
        let denied = algorithm.check_local(&mut state, &AiRateLimitOp::Reserve { tokens: 60 }, now);
        assert!(!denied.allowed);
        assert_eq!(denied.usage, Some(60));
        assert_eq!(denied.remaining, Some(40));

        // The rejected reservation must not have been charged: a follow-up
        // CheckBudget still shows only the committed 60.
        let budget = algorithm.check_local(&mut state, &AiRateLimitOp::CheckBudget, now);
        assert!(budget.allowed);
        assert_eq!(budget.usage, Some(60));
        assert_eq!(budget.remaining, Some(40));

        // A reservation that exactly fits the headroom is allowed.
        let exact = algorithm.check_local(&mut state, &AiRateLimitOp::Reserve { tokens: 40 }, now);
        assert!(exact.allowed);
        assert_eq!(exact.usage, Some(100));
        assert_eq!(exact.remaining, Some(0));
    }

    #[test]
    fn ai_token_window_adjust_usage_returns_post_reconcile_usage_remaining() {
        // #2261: AdjustUsage must surface the post-reconcile bucket so expose_headers
        // can refresh x-ai-ratelimit-usage / remaining after admission.
        let algorithm = AiTokenRateAlgorithm::new(1000, 60);
        let mut state = algorithm.new_state();
        let now = Instant::now();

        let reserved =
            algorithm.check_local(&mut state, &AiRateLimitOp::Reserve { tokens: 100 }, now);
        let id = reserved.reservation_id.expect("reserve returns an id");
        assert_eq!(reserved.usage, Some(100));
        assert_eq!(reserved.remaining, Some(900));

        let adjusted = algorithm.check_local(
            &mut state,
            &AiRateLimitOp::AdjustUsage {
                reservation_id: Some(id),
                reserved_window_index: None,
                reservation_backend: ReservationBackend::Local,
                actual_tokens: 10,
                delta: -90,
            },
            now,
        );
        assert!(adjusted.allowed);
        assert_eq!(adjusted.usage, Some(10));
        assert_eq!(adjusted.remaining, Some(990));
        assert_eq!(adjusted.limit, Some(1000));
        assert_eq!(adjusted.window_seconds, Some(60));
    }

    #[test]
    fn ai_token_window_adjust_usage_positive_delta_charges_more() {
        // Reconciliation with a positive delta (actual > reserved) must add the
        // shortfall to the window — exercising the `delta > 0` branch of
        // `adjust_usage`.
        let algorithm = AiTokenRateAlgorithm::new(1000, 60);
        let mut state = algorithm.new_state();
        let now = Instant::now();

        let reserved =
            algorithm.check_local(&mut state, &AiRateLimitOp::Reserve { tokens: 100 }, now);
        assert!(reserved.allowed);

        // Actual usage came in 50 higher than the reservation.
        algorithm.check_local(
            &mut state,
            &AiRateLimitOp::AdjustUsage {
                reservation_id: None,
                reserved_window_index: None,
                reservation_backend: ReservationBackend::Local,
                actual_tokens: 50,
                delta: 50,
            },
            now,
        );

        let budget = algorithm.check_local(&mut state, &AiRateLimitOp::CheckBudget, now);
        assert_eq!(budget.usage, Some(150));
        assert_eq!(budget.remaining, Some(850));
    }

    #[test]
    fn ai_token_window_adjust_usage_zero_delta_is_noop() {
        // A zero delta must leave the committed usage untouched (the
        // `delta == 0` early-return branch of `adjust_usage`).
        let algorithm = AiTokenRateAlgorithm::new(1000, 60);
        let mut state = algorithm.new_state();
        let now = Instant::now();

        assert!(
            algorithm
                .check_local(&mut state, &AiRateLimitOp::Reserve { tokens: 200 }, now)
                .allowed
        );
        algorithm.check_local(
            &mut state,
            &AiRateLimitOp::AdjustUsage {
                reservation_id: None,
                reserved_window_index: None,
                reservation_backend: ReservationBackend::Local,
                actual_tokens: 0,
                delta: 0,
            },
            now,
        );

        let budget = algorithm.check_local(&mut state, &AiRateLimitOp::CheckBudget, now);
        assert_eq!(budget.usage, Some(200));
        assert_eq!(budget.remaining, Some(800));
    }

    #[test]
    fn ai_token_window_adjust_usage_partial_release_trims_last_entry() {
        // A negative delta smaller than the most-recent entry must trim that
        // entry in place rather than popping it — exercising the
        // `*tokens > remaining_release` branch of `adjust_usage` (distinct from
        // the over-release floor and full-entry pop paths).
        let algorithm = AiTokenRateAlgorithm::new(1000, 60);
        let mut state = algorithm.new_state();
        let now = Instant::now();

        // Two separate reservations create two entries in the window.
        assert!(
            algorithm
                .check_local(&mut state, &AiRateLimitOp::Reserve { tokens: 70 }, now)
                .allowed
        );
        assert!(
            algorithm
                .check_local(&mut state, &AiRateLimitOp::Reserve { tokens: 80 }, now)
                .allowed
        );

        // Release 30 < 80 (the last entry): only the last entry shrinks.
        algorithm.check_local(
            &mut state,
            &AiRateLimitOp::AdjustUsage {
                reservation_id: None,
                reserved_window_index: None,
                reservation_backend: ReservationBackend::Local,
                actual_tokens: 0,
                delta: -30,
            },
            now,
        );

        let budget = algorithm.check_local(&mut state, &AiRateLimitOp::CheckBudget, now);
        assert_eq!(budget.usage, Some(120));
        assert_eq!(budget.remaining, Some(880));

        // Releasing exactly the remainder of the last entry pops it, then trims
        // into the first — drives both the pop and the trim branches in one go.
        algorithm.check_local(
            &mut state,
            &AiRateLimitOp::AdjustUsage {
                reservation_id: None,
                reserved_window_index: None,
                reservation_backend: ReservationBackend::Local,
                actual_tokens: 0,
                delta: -60,
            },
            now,
        );
        let budget = algorithm.check_local(&mut state, &AiRateLimitOp::CheckBudget, now);
        assert_eq!(budget.usage, Some(60));
        assert_eq!(budget.remaining, Some(940));
    }

    #[test]
    fn ai_token_window_adjust_usage_releases_matching_reservation() {
        // codex P2: a negative reconciliation carrying a reservation id must
        // release THAT reservation, not whichever entry is newest. Reproduce
        // out-of-order completion: reserve A (older) then B (newer), then
        // reconcile A's reservation downward; B's entry must be untouched.
        let algorithm = AiTokenRateAlgorithm::new(1000, 60);
        let mut state = algorithm.new_state();
        let now = Instant::now();

        let a = algorithm.check_local(&mut state, &AiRateLimitOp::Reserve { tokens: 100 }, now);
        let b = algorithm.check_local(&mut state, &AiRateLimitOp::Reserve { tokens: 300 }, now);
        let id_a = a.reservation_id.expect("reserve returns an id");
        let id_b = b.reservation_id.expect("reserve returns an id");
        assert_ne!(id_a, id_b, "each reservation gets a distinct id");

        // A's actual usage was 40 (delta = 40 - 100 = -60). Reconcile A.
        algorithm.check_local(
            &mut state,
            &AiRateLimitOp::AdjustUsage {
                reservation_id: Some(id_a),
                reserved_window_index: None,
                reservation_backend: ReservationBackend::Local,
                actual_tokens: 0,
                delta: -60,
            },
            now,
        );

        // Total must be A(40) + B(300) = 340 — B's reservation is intact.
        let budget = algorithm.check_local(&mut state, &AiRateLimitOp::CheckBudget, now);
        assert_eq!(
            budget.usage,
            Some(340),
            "reconciling A must shrink A to 40 and leave B's 300 untouched"
        );

        // Now fully release B by its id (delta = 0 - 300). A must remain at 40.
        algorithm.check_local(
            &mut state,
            &AiRateLimitOp::AdjustUsage {
                reservation_id: Some(id_b),
                reserved_window_index: None,
                reservation_backend: ReservationBackend::Local,
                actual_tokens: 0,
                delta: -300,
            },
            now,
        );
        let budget = algorithm.check_local(&mut state, &AiRateLimitOp::CheckBudget, now);
        assert_eq!(
            budget.usage,
            Some(40),
            "releasing B by id removes only B; A's 40 survives"
        );
    }

    #[test]
    fn ai_token_window_adjust_usage_unknown_reservation_id_negative_delta_is_noop() {
        // codex P1: a negative reconciliation whose reservation id no longer
        // matches a live entry (the reservation already aged out of the window,
        // or was already released by a non-2xx response and a later final-body
        // rejection re-runs reconciliation) must be a NO-OP. It must NOT fall
        // back to back-of-queue release, which would steal tokens from a
        // different, still-live reservation for the same key and under-count the
        // budget.
        let algorithm = AiTokenRateAlgorithm::new(1000, 60);
        let mut state = algorithm.new_state();
        let now = Instant::now();

        // A genuine, still-live reservation for the same key.
        let live = algorithm.check_local(&mut state, &AiRateLimitOp::Reserve { tokens: 200 }, now);
        let live_id = live.reservation_id.expect("reserve returns an id");
        assert!(live.allowed);

        // Id 99_999 was never handed out (or already expired). A negative delta
        // must leave the live 200 untouched.
        algorithm.check_local(
            &mut state,
            &AiRateLimitOp::AdjustUsage {
                reservation_id: Some(99_999),
                reserved_window_index: None,
                reservation_backend: ReservationBackend::Local,
                actual_tokens: 0,
                delta: -50,
            },
            now,
        );
        let budget = algorithm.check_local(&mut state, &AiRateLimitOp::CheckBudget, now);
        assert_eq!(
            budget.usage,
            Some(200),
            "an unknown reservation id with a negative delta must NOT release another reservation's usage"
        );

        // The live reservation can still be released by its own id afterwards.
        algorithm.check_local(
            &mut state,
            &AiRateLimitOp::AdjustUsage {
                reservation_id: Some(live_id),
                reserved_window_index: None,
                reservation_backend: ReservationBackend::Local,
                actual_tokens: 0,
                delta: -200,
            },
            now,
        );
        let budget = algorithm.check_local(&mut state, &AiRateLimitOp::CheckBudget, now);
        assert_eq!(
            budget.usage,
            Some(0),
            "releasing the live reservation by its own id still works"
        );
    }

    #[test]
    fn ai_token_window_adjust_usage_unknown_reservation_id_positive_delta_records_extra() {
        // A positive reconciliation whose reservation id has expired still
        // represents genuine extra usage above the (now-gone) reservation, so it
        // is recorded as fresh usage — never under-counting. This keeps the
        // budget conservative even when actual usage lands after the window
        // dropped the reservation.
        let algorithm = AiTokenRateAlgorithm::new(1000, 60);
        let mut state = algorithm.new_state();
        let now = Instant::now();

        let live = algorithm.check_local(&mut state, &AiRateLimitOp::Reserve { tokens: 100 }, now);
        assert!(live.allowed);

        algorithm.check_local(
            &mut state,
            &AiRateLimitOp::AdjustUsage {
                reservation_id: Some(99_999),
                reserved_window_index: None,
                reservation_backend: ReservationBackend::Local,
                actual_tokens: 30,
                delta: 30,
            },
            now,
        );
        let budget = algorithm.check_local(&mut state, &AiRateLimitOp::CheckBudget, now);
        assert_eq!(
            budget.usage,
            Some(130),
            "a positive delta for an expired reservation is recorded as extra usage"
        );
    }

    #[test]
    fn ai_token_window_adjust_usage_anonymous_negative_delta_releases_from_back() {
        // The anonymous path (reservation_id = None) retains the legacy
        // back-of-queue release used by callers without per-entry identity
        // (e.g. the Redis fallback or positive reconciliations with no target).
        let algorithm = AiTokenRateAlgorithm::new(1000, 60);
        let mut state = algorithm.new_state();
        let now = Instant::now();

        assert!(
            algorithm
                .check_local(&mut state, &AiRateLimitOp::Reserve { tokens: 200 }, now)
                .allowed
        );

        algorithm.check_local(
            &mut state,
            &AiRateLimitOp::AdjustUsage {
                reservation_id: None,
                reserved_window_index: None,
                reservation_backend: ReservationBackend::Local,
                actual_tokens: 0,
                delta: -50,
            },
            now,
        );
        let budget = algorithm.check_local(&mut state, &AiRateLimitOp::CheckBudget, now);
        assert_eq!(
            budget.usage,
            Some(150),
            "anonymous negative delta trims the back entry by 50"
        );
    }

    #[tokio::test]
    async fn local_http_limiter_denies_after_limit() {
        let limiter = LocalLimiter::new(
            HttpRateLimitAlgorithm::new(vec![RateLimitWindowSpec {
                limit: 2,
                duration: Duration::from_secs(60),
            }]),
            crate::util::sharding::pool_shard_amount(0),
        );
        let op = RequestUnit;

        assert!(limiter.check("ip:1".to_string(), &op).allowed);
        assert!(limiter.check("ip:1".to_string(), &op).allowed);

        let denied = limiter.check("ip:1".to_string(), &op);
        assert!(!denied.allowed);
        assert_eq!(denied.limit, Some(2));
    }

    #[test]
    fn local_limiter_enforce_capacity_preserves_active_entries() {
        let limiter = LocalLimiter::new(
            TestAlgorithm {
                redis_ok: Arc::new(AtomicBool::new(true)),
            },
            crate::util::sharding::pool_shard_amount(0),
        );
        let op = TestOp;
        let now = Instant::now();

        for idx in 0..5 {
            let key = format!("key:{idx}");
            assert!(
                limiter
                    .check_at_with_capacity(key, &op, now, 5)
                    .expect("admit within cap")
                    .allowed
            );
        }
        assert_eq!(limiter.tracked_keys_count(), 5);
        assert!(
            limiter
                .check_at_with_capacity("key:new".to_string(), &op, now, 5)
                .is_none(),
            "previously unseen keys must deny at capacity"
        );

        // Cleanup must not delete still-active budgets to make room.
        limiter.enforce_capacity(3, now);
        assert_eq!(limiter.tracked_keys_count(), 5);
        for idx in 0..5 {
            assert!(limiter.contains_key(&format!("key:{idx}")));
        }
    }

    #[test]
    fn local_limiter_prune_stale_below_cap_preserves_active_keys() {
        let limiter = LocalLimiter::new(
            TestAlgorithm {
                redis_ok: Arc::new(AtomicBool::new(true)),
            },
            crate::util::sharding::pool_shard_amount(0),
        );
        let op = TestOp;
        let t0 = Instant::now();

        assert!(limiter.check_at("stale-a".to_string(), &op, t0).allowed);
        assert!(limiter.check_at("stale-b".to_string(), &op, t0).allowed);
        let t_active = t0 + Duration::from_secs(20);
        assert!(
            limiter
                .check_at("active".to_string(), &op, t_active)
                .allowed
        );
        assert_eq!(limiter.tracked_keys_count(), 3);

        // TestAlgorithm treats entries idle for >= 10s as inactive.
        limiter.prune_stale_at(t_active);
        assert_eq!(limiter.tracked_keys_count(), 1);
        assert!(limiter.contains_key(&"active".to_string()));
        assert!(!limiter.contains_key(&"stale-a".to_string()));
        assert!(!limiter.contains_key(&"stale-b".to_string()));
    }

    #[test]
    fn local_limiter_enforce_capacity_prunes_stale_below_cap() {
        let limiter = LocalLimiter::new(
            TestAlgorithm {
                redis_ok: Arc::new(AtomicBool::new(true)),
            },
            crate::util::sharding::pool_shard_amount(0),
        );
        let op = TestOp;
        let t0 = Instant::now();

        for idx in 0..4 {
            assert!(limiter.check_at(format!("stale:{idx}"), &op, t0).allowed);
        }
        let t_active = t0 + Duration::from_secs(20);
        assert!(
            limiter
                .check_at("active".to_string(), &op, t_active)
                .allowed
        );
        assert_eq!(limiter.tracked_keys_count(), 5);

        // Cap is above current length; stale pruning must still run.
        limiter.enforce_capacity(100, t_active);
        assert_eq!(limiter.tracked_keys_count(), 1);
        assert!(limiter.contains_key(&"active".to_string()));
    }

    #[tokio::test]
    async fn failover_limiter_prunes_stale_local_fallback_below_cap() {
        let http_client = namespaced_http_client("tenant-a");
        let redis_ok = Arc::new(AtomicBool::new(false));
        let algorithm = TestAlgorithm {
            redis_ok: Arc::clone(&redis_ok),
        };
        let local = Arc::new(LocalLimiter::new(
            algorithm.clone(),
            http_client.pool_shard_amount(),
        ));
        let redis = test_redis_limiter(&http_client, algorithm);
        let limiter = FailoverLimiter::new(
            "rate_limiting",
            redis,
            local,
            RedisFailurePolicy::LocalFallback,
        );
        let op = TestOp;
        let t0 = Instant::now();

        // Redis algorithm reports unavailable, so checks land in the local
        // fallback map (the Redis-fallback consumer path).
        assert!(
            limiter
                .check("stale".to_string(), "redis:stale", &op)
                .await
                .allowed
        );
        assert!(
            limiter
                .check("active".to_string(), "redis:active", &op)
                .await
                .allowed
        );
        assert_eq!(limiter.tracked_keys_count(), 2);

        // Controllable-time refresh of only the active key, then prune past
        // TestAlgorithm's 10s idle threshold.
        let t_active = t0 + Duration::from_secs(20);
        let _ = limiter
            .fallback
            .check_at("active".to_string(), &op, t_active);
        // Ensure the stale key's last_seen is pinned at t0 even if the async
        // check path observed a slightly later Instant::now().
        let _ = limiter.fallback.check_at("stale".to_string(), &op, t0);
        limiter.prune_local_stale_at(t_active);

        assert_eq!(limiter.tracked_keys_count(), 1);
        assert!(limiter.contains_local_key(&"active".to_string()));
        assert!(!limiter.contains_local_key(&"stale".to_string()));
    }

    #[test]
    fn failover_limiter_new_without_runtime_does_not_panic() {
        let http_client = namespaced_http_client("tenant-a");
        let algorithm = TestAlgorithm {
            redis_ok: Arc::new(AtomicBool::new(true)),
        };
        let local: Arc<LocalLimiter<String, TestAlgorithm>> = Arc::new(LocalLimiter::new(
            algorithm.clone(),
            http_client.pool_shard_amount(),
        ));
        let redis = test_redis_limiter(&http_client, algorithm);

        let _limiter = FailoverLimiter::new(
            "rate_limiting",
            redis,
            local,
            RedisFailurePolicy::LocalFallback,
        );
    }

    #[tokio::test]
    async fn failover_limiter_falls_back_and_recovers() {
        let http_client = namespaced_http_client("tenant-a");
        let redis_ok = Arc::new(AtomicBool::new(true));
        let algorithm = TestAlgorithm {
            redis_ok: Arc::clone(&redis_ok),
        };
        let local = Arc::new(LocalLimiter::new(
            algorithm.clone(),
            http_client.pool_shard_amount(),
        ));
        let redis = test_redis_limiter(&http_client, algorithm);
        let limiter = FailoverLimiter::new(
            "rate_limiting",
            redis,
            local,
            RedisFailurePolicy::LocalFallback,
        );
        let op = TestOp;

        let primary = limiter.check("local".to_string(), "redis", &op).await;
        assert_eq!(primary.usage, Some(99));

        redis_ok.store(false, Ordering::Relaxed);
        let fallback = limiter.check("local".to_string(), "redis", &op).await;
        assert_eq!(fallback.usage, Some(1));

        redis_ok.store(true, Ordering::Relaxed);
        tokio::time::sleep(Duration::from_millis(1100)).await;
        let recovered = limiter.check("local".to_string(), "redis", &op).await;
        assert_eq!(recovered.usage, Some(99));
    }

    #[test]
    fn redis_limiter_centralizes_default_namespace_prefix() {
        let default_client = namespaced_http_client("ferrum");
        let default = test_redis_limiter(
            &default_client,
            TestAlgorithm {
                redis_ok: Arc::new(AtomicBool::new(true)),
            },
        );
        let tenant_client = namespaced_http_client("tenant-a");
        let tenant = test_redis_limiter(
            &tenant_client,
            TestAlgorithm {
                redis_ok: Arc::new(AtomicBool::new(true)),
            },
        );

        assert_eq!(default.key_prefix(), "ferrum:rate_limiting:standalone");
        assert_eq!(tenant.key_prefix(), "tenant-a:rate_limiting:standalone");
    }

    #[test]
    fn from_plugin_config_local_backend_honors_explicit_http_client_shard_amount() {
        let http_client = http_client_with_shards("ferrum", 256);
        let backend: RateLimitBackend<String, TestAlgorithm> =
            RateLimitBackend::from_plugin_config(
                "rate_limiting",
                &json!({"sync_mode": "local"}),
                &http_client,
                TestAlgorithm {
                    redis_ok: Arc::new(AtomicBool::new(true)),
                },
            )
            .expect("local backend constructs");

        assert!(matches!(backend, RateLimitBackend::Local(_)));
        assert_eq!(backend.local_map_shard_amount(), 256);
        assert_eq!(
            backend.local_map_shard_amount(),
            http_client.pool_shard_amount()
        );
    }

    #[test]
    fn from_plugin_config_redis_fallback_honors_explicit_http_client_shard_amount() {
        let http_client = http_client_with_shards("ferrum", 128);
        let backend: RateLimitBackend<String, TestAlgorithm> =
            RateLimitBackend::from_plugin_config(
                "rate_limiting",
                &json!({
                    "sync_mode": "redis",
                    "redis_url": "redis://127.0.0.1:6379/0",
                }),
                &http_client,
                TestAlgorithm {
                    redis_ok: Arc::new(AtomicBool::new(true)),
                },
            )
            .expect("redis failover backend constructs");

        assert!(matches!(backend, RateLimitBackend::Failover(_)));
        assert_eq!(backend.local_map_shard_amount(), 128);
        assert_eq!(
            backend.local_map_shard_amount(),
            http_client.pool_shard_amount()
        );
    }

    #[test]
    fn from_plugin_config_normalizes_non_power_of_two_shard_override_once() {
        let http_client = http_client_with_shards("ferrum", 100);
        let expected = crate::util::sharding::pool_shard_amount(100);
        assert_eq!(expected, 128);
        assert_eq!(http_client.pool_shard_amount(), expected);

        let local: RateLimitBackend<String, TestAlgorithm> = RateLimitBackend::from_plugin_config(
            "rate_limiting",
            &json!({}),
            &http_client,
            TestAlgorithm {
                redis_ok: Arc::new(AtomicBool::new(true)),
            },
        )
        .expect("local backend constructs");
        let failover: RateLimitBackend<String, TestAlgorithm> =
            RateLimitBackend::from_plugin_config(
                "rate_limiting",
                &json!({
                    "sync_mode": "redis",
                    "redis_url": "redis://127.0.0.1:6379/0",
                }),
                &http_client,
                TestAlgorithm {
                    redis_ok: Arc::new(AtomicBool::new(true)),
                },
            )
            .expect("redis failover backend constructs");

        assert_eq!(local.local_map_shard_amount(), expected);
        assert_eq!(failover.local_map_shard_amount(), expected);
    }

    #[test]
    fn from_plugin_config_zero_shard_override_keeps_auto_behavior() {
        let http_client = http_client_with_shards("ferrum", 0);
        let expected = crate::util::sharding::pool_shard_amount(0);
        assert_eq!(http_client.pool_shard_amount(), expected);

        let backend: RateLimitBackend<String, TestAlgorithm> =
            RateLimitBackend::from_plugin_config(
                "rate_limiting",
                &json!({"sync_mode": "local"}),
                &http_client,
                TestAlgorithm {
                    redis_ok: Arc::new(AtomicBool::new(true)),
                },
            )
            .expect("local backend constructs");

        assert_eq!(backend.local_map_shard_amount(), expected);
    }

    #[test]
    fn shared_limiter_consumers_honor_explicit_http_client_shard_amount() {
        let http_client = http_client_with_shards("ferrum", 256);
        let expected = http_client.pool_shard_amount();
        assert_eq!(expected, 256);

        let rate_limiting = crate::plugins::rate_limiting::RateLimiting::new(
            &json!({
                "limits": [{
                    "scope": "default",
                    "window_seconds": 60,
                    "max_requests": 10
                }]
            }),
            http_client.clone(),
        )
        .expect("rate_limiting constructs");
        assert_eq!(rate_limiting.local_map_shard_amount(), expected);

        let ai = crate::plugins::ai_rate_limiter::AiRateLimiter::new(
            &json!({"token_limit": 1000, "window_seconds": 60}),
            http_client.clone(),
        )
        .expect("ai_rate_limiter constructs");
        assert_eq!(ai.local_map_shard_amount(), expected);

        let graphql = crate::plugins::graphql::GraphqlPlugin::new(
            &json!({
                "type_rate_limits": {
                    "query": {"max_requests": 10, "window_seconds": 60}
                }
            }),
            http_client.clone(),
        )
        .expect("graphql constructs");
        assert_eq!(graphql.local_map_shard_amount(), expected);

        let grpc = crate::plugins::grpc_method_router::GrpcMethodRouter::new(
            &json!({
                "method_rate_limits": {
                    "/pkg.Svc/Method": {"max_requests": 10, "window_seconds": 60}
                }
            }),
            http_client.clone(),
        )
        .expect("grpc_method_router constructs");
        assert_eq!(grpc.local_map_shard_amount(), expected);

        let ws = crate::plugins::ws_rate_limiting::WsRateLimiting::new(
            &json!({"frames_per_second": 100}),
            http_client.clone(),
        )
        .expect("ws_rate_limiting constructs");
        assert_eq!(ws.local_map_shard_amount(), expected);

        let udp = crate::plugins::udp_rate_limiting::UdpRateLimiting::new_with_http_client(
            &json!({"datagrams_per_second": 100}),
            http_client.clone(),
        )
        .expect("udp_rate_limiting constructs");
        assert_eq!(udp.local_map_shard_amount(), expected);
    }

    #[test]
    fn shared_limiter_consumers_redis_fallback_honors_explicit_shard_amount() {
        let http_client = http_client_with_shards("ferrum", 64);
        let expected = http_client.pool_shard_amount();
        assert_eq!(expected, 64);
        let redis = json!({
            "sync_mode": "redis",
            "redis_url": "redis://127.0.0.1:6379/0",
        });

        let rate_limiting = crate::plugins::rate_limiting::RateLimiting::new(
            &json!({
                "limits": [{
                    "scope": "default",
                    "window_seconds": 60,
                    "max_requests": 10
                }],
                "sync_mode": "redis",
                "redis_url": "redis://127.0.0.1:6379/0",
            }),
            http_client.clone(),
        )
        .expect("rate_limiting redis constructs");
        assert_eq!(rate_limiting.local_map_shard_amount(), expected);

        let mut ai_config = json!({"token_limit": 1000, "window_seconds": 60});
        ai_config
            .as_object_mut()
            .expect("object")
            .extend(redis.as_object().expect("object").clone());
        let ai =
            crate::plugins::ai_rate_limiter::AiRateLimiter::new(&ai_config, http_client.clone())
                .expect("ai_rate_limiter redis constructs");
        assert_eq!(ai.local_map_shard_amount(), expected);

        let mut graphql_config = json!({
            "type_rate_limits": {
                "query": {"max_requests": 10, "window_seconds": 60}
            }
        });
        graphql_config
            .as_object_mut()
            .expect("object")
            .extend(redis.as_object().expect("object").clone());
        let graphql =
            crate::plugins::graphql::GraphqlPlugin::new(&graphql_config, http_client.clone())
                .expect("graphql redis constructs");
        assert_eq!(graphql.local_map_shard_amount(), expected);

        let mut grpc_config = json!({
            "method_rate_limits": {
                "/pkg.Svc/Method": {"max_requests": 10, "window_seconds": 60}
            }
        });
        grpc_config
            .as_object_mut()
            .expect("object")
            .extend(redis.as_object().expect("object").clone());
        let grpc = crate::plugins::grpc_method_router::GrpcMethodRouter::new(
            &grpc_config,
            http_client.clone(),
        )
        .expect("grpc_method_router redis constructs");
        assert_eq!(grpc.local_map_shard_amount(), expected);

        let mut ws_config = json!({"frames_per_second": 100});
        ws_config
            .as_object_mut()
            .expect("object")
            .extend(redis.as_object().expect("object").clone());
        let ws =
            crate::plugins::ws_rate_limiting::WsRateLimiting::new(&ws_config, http_client.clone())
                .expect("ws_rate_limiting redis constructs");
        assert_eq!(ws.local_map_shard_amount(), expected);

        let mut udp_config = json!({"datagrams_per_second": 100});
        udp_config
            .as_object_mut()
            .expect("object")
            .extend(redis.as_object().expect("object").clone());
        let udp = crate::plugins::udp_rate_limiting::UdpRateLimiting::new_with_http_client(
            &udp_config,
            http_client,
        )
        .expect("udp_rate_limiting redis constructs");
        assert_eq!(udp.local_map_shard_amount(), expected);
    }

    #[test]
    fn local_limiter_entry_count_matches_map_under_concurrent_capped_insert_prune() {
        use std::sync::Arc;
        use std::thread;

        let limiter = Arc::new(LocalLimiter::new(
            TestAlgorithm {
                redis_ok: Arc::new(AtomicBool::new(true)),
            },
            64,
        ));
        let op = TestOp;
        let max_entries = 64usize;
        let stop = Arc::new(AtomicBool::new(false));

        let mut handles = Vec::new();
        for worker in 0..8 {
            let limiter = Arc::clone(&limiter);
            let stop = Arc::clone(&stop);
            handles.push(thread::spawn(move || {
                let mut i = 0u64;
                while !stop.load(Ordering::Relaxed) {
                    let key = format!("w{worker}:{i}");
                    let _ = limiter.check_at_with_capacity(key, &op, Instant::now(), max_entries);
                    i = i.wrapping_add(1);
                    if i.is_multiple_of(17) {
                        limiter.prune_stale_at(Instant::now() + Duration::from_secs(30));
                    }
                    if i.is_multiple_of(23) {
                        // Over-cap cleanup must only prune idle state.
                        limiter.enforce_capacity(max_entries, Instant::now());
                    }
                }
            }));
        }

        thread::sleep(Duration::from_millis(150));
        stop.store(true, Ordering::Relaxed);
        for handle in handles {
            handle.join().expect("worker joins");
        }

        limiter.enforce_capacity(max_entries, Instant::now());
        let tracked = limiter.tracked_keys_count();
        let map_len = limiter.map_len_for_test();
        assert_eq!(
            tracked, map_len,
            "atomic entry count must stay exact with insert/remove coordination"
        );
        assert!(
            tracked <= max_entries,
            "hard cap must hold via atomic admission reservation (tracked={tracked})"
        );
    }

    #[test]
    fn steady_admission_tracked_keys_count_does_not_scale_with_shard_count() {
        fn steady_all_shard_calls(shard_amount: usize) -> usize {
            let limiter = LocalLimiter::new(
                TestAlgorithm {
                    redis_ok: Arc::new(AtomicBool::new(true)),
                },
                shard_amount,
            );
            let op = TestOp;
            // Warm a handful of keys so later checks are occupied-entry hits.
            for idx in 0..16 {
                assert!(limiter.check(format!("steady:{idx}"), &op).allowed);
            }
            let before = limiter.all_shard_len_calls_for_test();
            for _ in 0..2_000 {
                // Occupied-key admission + capacity observation (the UDP
                // maybe_evict pattern) must stay O(1) in shard count.
                let _ = limiter.check("steady:0".to_string(), &op);
                let _ = limiter.tracked_keys_count();
            }
            limiter.all_shard_len_calls_for_test() - before
        }

        let calls_4 = steady_all_shard_calls(4);
        let calls_256 = steady_all_shard_calls(256);
        assert_eq!(
            calls_4, 0,
            "steady admission must not call DashMap::len() (4 shards)"
        );
        assert_eq!(
            calls_256, 0,
            "steady admission must not call DashMap::len() (256 shards)"
        );
        assert_eq!(
            calls_4, calls_256,
            "steady all-shard work must not scale with DashMap shard count"
        );
    }

    #[test]
    fn redis_failover_tracked_keys_count_skips_all_shard_scans() {
        let http_client = http_client_with_shards("ferrum", 128);
        let algorithm = TestAlgorithm {
            redis_ok: Arc::new(AtomicBool::new(true)),
        };
        let backend: RateLimitBackend<String, TestAlgorithm> =
            RateLimitBackend::from_plugin_config(
                "udp_rate_limiting",
                &json!({
                    "sync_mode": "redis",
                    "redis_url": "redis://127.0.0.1:9/0",
                    "redis_health_check_interval_seconds": 1
                }),
                &http_client,
                algorithm,
            )
            .expect("failover backend");
        assert!(matches!(backend, RateLimitBackend::Failover(_)));

        // Seed local fallback state the way Redis-outage / test seeding does.
        let op = TestOp;
        for idx in 0..32 {
            let _ = backend.check_local_at(format!("ip:{idx}"), &op, Instant::now());
        }
        let before = backend.all_shard_len_calls_for_test();
        for _ in 0..5_000 {
            let _ = backend.tracked_keys_count();
        }
        assert_eq!(
            backend.all_shard_len_calls_for_test(),
            before,
            "Redis-mode local fallback capacity reads must not scan all shards"
        );
        assert_eq!(backend.tracked_keys_count(), backend.map_len_for_test());
    }
}
