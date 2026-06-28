//! Shared rate-limit algorithms plus local/Redis/failover storage adapters.

use async_trait::async_trait;
use dashmap::DashMap;
use serde_json::Value;
use std::collections::VecDeque;
use std::hash::Hash;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::{Duration, Instant};
use tracing::{info, warn};

use super::http_client::PluginHttpClient;
use super::redis_rate_limiter::{RedisConfig, RedisRateLimitClient};

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RateLimitOutcome {
    pub allowed: bool,
    pub remaining: Option<u64>,
    pub limit: Option<u64>,
    pub window_seconds: Option<u64>,
    pub usage: Option<u64>,
    pub metric: Option<&'static str>,
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
}

impl<K, A> LocalLimiter<K, A>
where
    K: Eq + Hash + Clone,
    A: RateLimitAlgorithm,
{
    pub fn new(algorithm: A) -> Self {
        Self {
            algorithm,
            state: DashMap::new(),
        }
    }

    pub fn check(&self, key: K, op: &A::Op) -> RateLimitOutcome {
        self.check_at(key, op, Instant::now())
    }

    pub fn check_at(&self, key: K, op: &A::Op, now: Instant) -> RateLimitOutcome {
        let mut entry = self
            .state
            .entry(key)
            .or_insert_with(|| self.algorithm.new_state());
        self.algorithm.check_local(entry.value_mut(), op, now)
    }

    pub fn tracked_keys_count(&self) -> usize {
        self.state.len()
    }

    pub fn retain_active_at(&self, now: Instant) {
        self.state
            .retain(|_, state| self.algorithm.is_state_active(state, now));
    }

    pub fn enforce_capacity(&self, max_entries: usize, now: Instant) {
        if self.state.len() <= max_entries {
            return;
        }

        self.retain_active_at(now);

        let len = self.state.len();
        if len <= max_entries {
            return;
        }

        let remove_count = len.saturating_sub(max_entries);
        // DashMap iteration order is intentionally arbitrary here. Rate-limit
        // state is already window-bounded, so after stale entries are retained
        // away any remaining key can be evicted to enforce the hard cap.
        let keys: Vec<K> = self
            .state
            .iter()
            .take(remove_count)
            .map(|entry| entry.key().clone())
            .collect();
        for key in keys {
            self.state.remove(&key);
        }
    }

    pub fn contains_key(&self, key: &K) -> bool {
        self.state.contains_key(key)
    }
}

pub struct RedisLimiter<A: RateLimitAlgorithm> {
    redis_client: Arc<RedisRateLimitClient>,
    algorithm: A,
    #[cfg(test)]
    key_prefix: String,
    health_check_interval: Duration,
}

impl<A: RateLimitAlgorithm> RedisLimiter<A> {
    pub fn new(
        plugin_name: &str,
        config: &Value,
        http_client: &PluginHttpClient,
        algorithm: A,
    ) -> Result<Option<Self>, String> {
        let default_prefix = format!("{}:{plugin_name}", http_client.namespace());
        let Some(cfg) = RedisConfig::from_plugin_config(config, &default_prefix)? else {
            return Ok(None);
        };
        let health_check_interval = Duration::from_secs(cfg.health_check_interval_seconds.max(1));
        #[cfg(test)]
        let key_prefix = cfg.key_prefix.clone();

        Ok(Some(Self {
            redis_client: Arc::new(RedisRateLimitClient::new(
                cfg,
                http_client.dns_cache().cloned(),
                http_client.tls_no_verify(),
                http_client.tls_ca_bundle_path(),
            )),
            algorithm,
            #[cfg(test)]
            key_prefix,
            health_check_interval,
        }))
    }

    pub async fn check(&self, key: &str, op: &A::Op) -> Result<RateLimitOutcome, ()> {
        self.algorithm
            .check_redis(&self.redis_client, key, op)
            .await
    }

    pub fn warmup_hostname(&self) -> Option<String> {
        self.redis_client.warmup_hostname()
    }

    #[cfg(test)]
    pub fn key_prefix(&self) -> &str {
        &self.key_prefix
    }

    fn is_available(&self) -> bool {
        self.redis_client.is_available()
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
    fallback: LocalLimiter<K, A>,
    redis_healthy: Arc<AtomicBool>,
    fallback_warned: Arc<AtomicBool>,
}

impl<K, A> FailoverLimiter<K, A>
where
    K: Eq + Hash + Clone + Send + Sync + 'static,
    A: RateLimitAlgorithm,
{
    pub fn new(
        plugin_name: &'static str,
        primary: RedisLimiter<A>,
        fallback: LocalLimiter<K, A>,
    ) -> Self {
        let redis_healthy = Arc::new(AtomicBool::new(true));
        let fallback_warned = Arc::new(AtomicBool::new(false));

        let limiter = Self {
            plugin_name,
            primary,
            fallback,
            redis_healthy,
            fallback_warned,
        };
        limiter.spawn_health_observer();
        limiter
    }

    pub async fn check(&self, local_key: K, redis_key: &str, op: &A::Op) -> RateLimitOutcome {
        if self.redis_healthy.load(Ordering::Relaxed) && self.primary.is_available() {
            match self.primary.check(redis_key, op).await {
                Ok(result) => {
                    self.redis_healthy.store(true, Ordering::Relaxed);
                    self.fallback_warned.store(false, Ordering::Relaxed);
                    return result;
                }
                Err(()) => {
                    self.redis_healthy.store(false, Ordering::Relaxed);
                }
            }
        }

        if !self.fallback_warned.swap(true, Ordering::Relaxed) {
            warn!(
                plugin = self.plugin_name,
                "Redis rate limiting unavailable — falling back to local in-memory state"
            );
        }

        self.fallback.check(local_key, op)
    }

    pub fn tracked_keys_count(&self) -> usize {
        self.fallback.tracked_keys_count()
    }

    pub fn enforce_local_capacity(&self, max_entries: usize, now: Instant) {
        self.fallback.enforce_capacity(max_entries, now);
    }

    pub fn contains_local_key(&self, key: &K) -> bool {
        self.fallback.contains_key(key)
    }

    pub fn warmup_hostname(&self) -> Option<String> {
        self.primary.warmup_hostname()
    }

    fn spawn_health_observer(&self) {
        let plugin_name = self.plugin_name;
        let redis_healthy = Arc::clone(&self.redis_healthy);
        let fallback_warned = Arc::clone(&self.fallback_warned);
        let redis_client = Arc::clone(&self.primary.redis_client);
        let interval = self.primary.health_check_interval();

        let Ok(handle) = tokio::runtime::Handle::try_current() else {
            warn!(
                plugin = plugin_name,
                "Redis rate limiting health observer not started because no Tokio runtime is active"
            );
            return;
        };

        handle.spawn(async move {
            loop {
                tokio::time::sleep(interval).await;
                let available = redis_client.is_available();
                let was_healthy = redis_healthy.swap(available, Ordering::Relaxed);
                if available && !was_healthy {
                    fallback_warned.store(false, Ordering::Relaxed);
                    info!(
                        plugin = plugin_name,
                        "Redis rate limiting recovered — switching back from local fallback"
                    );
                }
            }
        });
    }
}

pub enum RateLimitBackend<K, A>
where
    K: Eq + Hash,
    A: RateLimitAlgorithm,
{
    Local(LocalLimiter<K, A>),
    Failover(FailoverLimiter<K, A>),
}

impl<K, A> RateLimitBackend<K, A>
where
    K: Eq + Hash + Clone + Send + Sync + 'static,
    A: RateLimitAlgorithm + Clone,
{
    pub fn from_plugin_config(
        plugin_name: &'static str,
        config: &Value,
        http_client: &PluginHttpClient,
        algorithm: A,
    ) -> Result<Self, String> {
        let local = LocalLimiter::new(algorithm.clone());
        match RedisLimiter::new(plugin_name, config, http_client, algorithm) {
            Ok(Some(redis)) => Ok(Self::Failover(FailoverLimiter::new(
                plugin_name,
                redis,
                local,
            ))),
            Ok(None) => Ok(Self::Local(local)),
            Err(err) => Err(err),
        }
    }

    pub async fn check(&self, local_key: K, redis_key: &str, op: &A::Op) -> RateLimitOutcome {
        match self {
            Self::Local(local) => local.check(local_key, op),
            Self::Failover(failover) => failover.check(local_key, redis_key, op).await,
        }
    }

    pub async fn check_with_redis_key<F>(
        &self,
        local_key: K,
        redis_key: F,
        op: &A::Op,
    ) -> RateLimitOutcome
    where
        F: FnOnce() -> String,
    {
        match self {
            Self::Local(local) => local.check(local_key, op),
            Self::Failover(failover) => {
                let redis_key = redis_key();
                failover.check(local_key, &redis_key, op).await
            }
        }
    }

    pub fn tracked_keys_count(&self) -> usize {
        match self {
            Self::Local(local) => local.tracked_keys_count(),
            Self::Failover(failover) => failover.tracked_keys_count(),
        }
    }

    pub fn enforce_capacity(&self, max_entries: usize, now: Instant) {
        match self {
            Self::Local(local) => local.enforce_capacity(max_entries, now),
            Self::Failover(failover) => failover.enforce_local_capacity(max_entries, now),
        }
    }

    pub fn contains_local_key(&self, key: &K) -> bool {
        match self {
            Self::Local(local) => local.contains_key(key),
            Self::Failover(failover) => failover.contains_local_key(key),
        }
    }

    pub fn warmup_hostname(&self) -> Option<String> {
        match self {
            Self::Local(_) => None,
            Self::Failover(failover) => failover.warmup_hostname(),
        }
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
    timestamps: VecDeque<Instant>,
    window_duration: Duration,
    limit: u64,
}

impl SlidingWindow {
    pub fn new(limit: u64, window_duration: Duration) -> Self {
        Self {
            timestamps: VecDeque::new(),
            window_duration,
            limit,
        }
    }

    /// Check whether the window would allow a request without incrementing.
    /// Evicts stale entries to ensure an accurate count.
    pub fn would_allow(&mut self, now: Instant) -> bool {
        self.evict(now);
        (self.timestamps.len() as u64) < self.limit
    }

    /// Record a request in the window (caller must have checked `would_allow` first).
    pub fn increment(&mut self, now: Instant) {
        self.timestamps.push_back(now);
    }

    pub fn remaining(&self) -> u64 {
        self.limit.saturating_sub(self.timestamps.len() as u64)
    }

    pub fn has_recent_activity(&self, now: Instant) -> bool {
        self.timestamps
            .back()
            .is_some_and(|last| now.duration_since(*last) < self.window_duration)
    }

    fn evict(&mut self, now: Instant) {
        let cutoff = now - self.window_duration;
        while let Some(front) = self.timestamps.front() {
            if *front < cutoff {
                self.timestamps.pop_front();
            } else {
                break;
            }
        }
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
        now.duration_since(self.last_refill).as_secs_f64() < window_secs * 2.0
    }

    fn refill(&mut self, now: Instant) {
        let elapsed = now.duration_since(self.last_refill).as_secs_f64();
        self.last_refill = now;
        self.tokens = (self.tokens + elapsed * self.refill_rate).min(self.capacity);
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
        .map(|spec| {
            if spec.duration.as_secs() <= 5 {
                HttpWindowState::Bucket(TokenBucket::from_window(spec.limit, spec.duration))
            } else {
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
        let curr_idx = RedisRateLimitClient::window_index(window.window_seconds);
        let prev_idx = curr_idx.saturating_sub(1);
        let elapsed_fraction = RedisRateLimitClient::elapsed_fraction(window.window_seconds);
        let curr_key = redis.make_key(&[key, &curr_idx.to_string()]);
        let prev_key = redis.make_key(&[key, &prev_idx.to_string()]);
        let ttl = window.window_seconds * 2 + 1;

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
            if !state.windows.is_empty() {
                warn!(
                    "DynamicHttpRateLimitAlgorithm: spec change detected for in-progress key; counter state will be reset"
                );
            }
            state.specs = Arc::clone(&op.specs);
            state.windows = new_http_window_states(op.specs());
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

#[derive(Debug)]
pub struct TokenUsageWindow {
    entries: VecDeque<(Instant, u64)>,
    window_duration: Duration,
    limit: u64,
    total: u64,
}

impl TokenUsageWindow {
    fn new(limit: u64, window_duration: Duration) -> Self {
        Self {
            entries: VecDeque::new(),
            window_duration,
            limit,
            total: 0,
        }
    }

    fn current_usage(&mut self, now: Instant) -> u64 {
        let cutoff = now - self.window_duration;
        while let Some((timestamp, tokens)) = self.entries.front() {
            if *timestamp < cutoff {
                let expired = *tokens;
                self.entries.pop_front();
                self.total = self.total.saturating_sub(expired);
            } else {
                break;
            }
        }
        self.total
    }

    fn record_usage(&mut self, now: Instant, tokens: u64) {
        self.entries.push_back((now, tokens));
        self.total = self.total.saturating_add(tokens);
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

        self.record_usage(now, tokens);
        RateLimitOutcome::allow()
            .with_limit(self.limit)
            .with_window(self.window_duration.as_secs())
            .with_usage(reserved_usage)
            .with_remaining(self.limit.saturating_sub(reserved_usage))
    }

    fn adjust_usage(&mut self, now: Instant, delta: i64) {
        if delta == 0 {
            self.current_usage(now);
            return;
        }

        if delta > 0 {
            self.record_usage(now, delta as u64);
            return;
        }

        self.current_usage(now);
        let mut remaining_release = delta.unsigned_abs();
        while remaining_release > 0 {
            let Some((_, tokens)) = self.entries.back_mut() else {
                self.total = 0;
                break;
            };

            if *tokens > remaining_release {
                *tokens -= remaining_release;
                self.total = self.total.saturating_sub(remaining_release);
                break;
            }

            remaining_release -= *tokens;
            self.total = self.total.saturating_sub(*tokens);
            self.entries.pop_back();
        }
    }

    fn remaining(&mut self, now: Instant) -> u64 {
        self.limit.saturating_sub(self.current_usage(now))
    }

    fn has_recent_activity(&self, now: Instant) -> bool {
        self.entries
            .back()
            .is_some_and(|(timestamp, _)| now.duration_since(*timestamp) < self.window_duration)
    }
}

#[derive(Debug, Clone, Copy)]
pub enum AiRateLimitOp {
    CheckBudget,
    Reserve { tokens: u64 },
    AdjustUsage { delta: i64 },
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
            AiRateLimitOp::AdjustUsage { delta } => {
                state.adjust_usage(now, delta);
                RateLimitOutcome::allow()
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
                let curr_idx = RedisRateLimitClient::window_index(self.window_seconds);
                let prev_idx = curr_idx.saturating_sub(1);
                let elapsed_fraction = RedisRateLimitClient::elapsed_fraction(self.window_seconds);
                let curr_key = redis.make_key(&[key, &curr_idx.to_string()]);
                let prev_key = redis.make_key(&[key, &prev_idx.to_string()]);
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
                let curr_idx = RedisRateLimitClient::window_index(self.window_seconds);
                let prev_idx = curr_idx.saturating_sub(1);
                let elapsed_fraction = RedisRateLimitClient::elapsed_fraction(self.window_seconds);
                let curr_key = redis.make_key(&[key, &curr_idx.to_string()]);
                let prev_key = redis.make_key(&[key, &prev_idx.to_string()]);
                let ttl = self.window_seconds * 2 + 1;
                let increment = u64_to_i64_saturating(tokens);
                let new_curr_count = redis.incrby_with_expire(&curr_key, increment, ttl).await?;
                let (prev_count, _) = redis.get_two_counters(&prev_key, &curr_key).await?;
                let weighted = prev_count as f64 * (1.0 - elapsed_fraction) + new_curr_count as f64;
                let usage = weighted.max(0.0) as u64;
                let remaining = self.token_limit.saturating_sub(usage);
                if weighted > self.token_limit as f64 {
                    let _ = redis.incrby_with_expire(&curr_key, -increment, ttl).await;
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
                    .with_remaining(remaining))
            }
            AiRateLimitOp::AdjustUsage { delta } => {
                if delta != 0 {
                    let curr_idx = RedisRateLimitClient::window_index(self.window_seconds);
                    let redis_key = redis.make_key(&[key, &curr_idx.to_string()]);
                    let ttl = self.window_seconds * 2 + 1;
                    let _ = redis.incrby_with_expire(&redis_key, delta, ttl).await?;
                }
                Ok(RateLimitOutcome::allow())
            }
        }
    }

    fn is_state_active(&self, state: &Self::State, now: Instant) -> bool {
        state.has_recent_activity(now)
    }
}

#[derive(Debug, Clone, Copy)]
pub struct WsRateLimitOp;

#[derive(Debug, Clone)]
pub struct WsFrameRateAlgorithm {
    frames_per_second: f64,
    burst_size: f64,
}

/// Upper bound on the Redis sliding-window length, in seconds. With
/// pathological-but-legal configs (`burst_size=10_000_000, frames_per_second=1`)
/// the derived window would otherwise span ~115 days, leaving per-connection
/// Redis keys alive for ~230 days. Capping turns those configs into a lower-
/// resolution counter (still safe — admission stays bounded by `burst_size`)
/// instead of a multi-month TTL.
const REDIS_MAX_WINDOW_SECONDS: u64 = 3600;

impl WsFrameRateAlgorithm {
    pub fn new(frames_per_second: f64, burst_size: f64) -> Self {
        Self {
            frames_per_second,
            burst_size,
        }
    }

    /// Returns `(window_seconds, limit)` for the Redis sliding-window
    /// approximation. The window length is the bucket's full-refill period
    /// (`ceil(burst_size / frames_per_second)`); the cap at
    /// [`REDIS_MAX_WINDOW_SECONDS`] bounds Redis TTLs.
    ///
    /// `ws_rate_limiting::new` rejects `frames_per_second == 0` and
    /// `burst_size < frames_per_second` at construction, so the derived
    /// window is always at least 1 second and the average sustained rate
    /// matches `frames_per_second` for all configs that reach this code.
    fn redis_window_derivation(&self) -> (u64, u64) {
        debug_assert!(
            self.frames_per_second > 0.0,
            "WsFrameRateAlgorithm: frames_per_second must be > 0; \
             enforced by optional_positive_u64 at plugin construction"
        );
        let limit = self.burst_size as u64;
        let window_seconds = ((self.burst_size / self.frames_per_second).ceil() as u64)
            .clamp(1, REDIS_MAX_WINDOW_SECONDS);
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
        _op: &Self::Op,
        now: Instant,
    ) -> RateLimitOutcome {
        let outcome = if state.check_and_consume(now, 1) {
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
        _op: &Self::Op,
    ) -> Result<RateLimitOutcome, ()> {
        // Approximate the local TokenBucket via a sliding two-window check
        // over the bucket's full-refill period. See `redis_window_derivation`
        // for the (window_seconds, limit) contract. The previous
        // implementation hard-coded a 1-second window with `burst_size` as
        // the limit, which silently ignored `frames_per_second` and admitted
        // up to `burst_size` frames every second indefinitely — much higher
        // than the configured sustained rate.
        let (window_seconds, limit) = self.redis_window_derivation();

        let curr_idx = RedisRateLimitClient::window_index(window_seconds);
        let prev_idx = curr_idx.saturating_sub(1);
        let elapsed_fraction = RedisRateLimitClient::elapsed_fraction(window_seconds);
        let curr_key = redis.make_key(&[key, &curr_idx.to_string()]);
        let prev_key = redis.make_key(&[key, &prev_idx.to_string()]);
        let ttl = window_seconds * 2 + 1;

        let (prev_count, curr_count) = redis
            .sliding_window_increment(&prev_key, &curr_key, ttl)
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
        let now_secs = now.duration_since(self.epoch_base).as_secs();
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

        state.last_check_secs.store(now_secs, Ordering::Relaxed);

        let new_count = state.count.fetch_add(1, Ordering::AcqRel) + 1;
        let new_bytes =
            state.bytes.fetch_add(op.datagram_size, Ordering::AcqRel) + op.datagram_size;

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
        let ttl = self.window_seconds + 1;

        match self.datagrams_per_window {
            Some(max_datagrams) if self.bytes_per_window.is_some() => {
                let datagram_key = redis.make_key(&[key, "datagrams", &window_idx.to_string()]);
                let bytes_key = redis.make_key(&[key, "bytes", &window_idx.to_string()]);
                let (count, bytes) = redis
                    .incr_and_incrby_with_expire(
                        &datagram_key,
                        &bytes_key,
                        op.datagram_size as i64,
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
                let datagram_key = redis.make_key(&[key, "datagrams", &window_idx.to_string()]);
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
                    let bytes_key = redis.make_key(&[key, "bytes", &window_idx.to_string()]);
                    let bytes = redis
                        .incrby_with_expire(&bytes_key, op.datagram_size as i64, ttl)
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
        let now_secs = now.duration_since(self.epoch_base).as_secs();
        let max_idle = (self.window_seconds * 2).max(10);
        !state.is_stale(now_secs, max_idle)
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
            crate::config::BackendAllowIps::Both,
            std::sync::Arc::new(Vec::new()),
            0,
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
        // Non-integer ratio → ceil
        let alg = WsFrameRateAlgorithm::new(3.0, 10.0);
        assert_eq!(alg.redis_window_derivation(), (4, 10));
    }

    #[test]
    fn ws_frame_rate_redis_window_derivation_caps_pathological_configs() {
        // Without the cap, `burst=10_000_000, fps=1` would produce a
        // ~115-day window and ~230-day Redis TTL on per-connection keys.
        let alg = WsFrameRateAlgorithm::new(1.0, 10_000_000.0);
        assert_eq!(
            alg.redis_window_derivation(),
            (REDIS_MAX_WINDOW_SECONDS, 10_000_000)
        );
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
    fn token_bucket_consume_saturates_at_zero() {
        let mut bucket = TokenBucket::from_window(1, Duration::from_secs(1));
        bucket.consume(2);
        assert_eq!(bucket.remaining(), 0);
    }

    #[tokio::test]
    async fn local_http_limiter_denies_after_limit() {
        let limiter = LocalLimiter::new(HttpRateLimitAlgorithm::new(vec![RateLimitWindowSpec {
            limit: 2,
            duration: Duration::from_secs(60),
        }]));
        let op = RequestUnit;

        assert!(limiter.check("ip:1".to_string(), &op).allowed);
        assert!(limiter.check("ip:1".to_string(), &op).allowed);

        let denied = limiter.check("ip:1".to_string(), &op);
        assert!(!denied.allowed);
        assert_eq!(denied.limit, Some(2));
    }

    #[test]
    fn local_limiter_enforce_capacity_removes_excess_entries() {
        let limiter = LocalLimiter::new(TestAlgorithm {
            redis_ok: Arc::new(AtomicBool::new(true)),
        });
        let op = TestOp;

        for idx in 0..5 {
            let key = format!("key:{idx}");
            assert!(limiter.check(key, &op).allowed);
        }
        assert_eq!(limiter.tracked_keys_count(), 5);

        limiter.enforce_capacity(3, Instant::now());
        assert!(limiter.tracked_keys_count() <= 3);
    }

    #[test]
    fn failover_limiter_new_without_runtime_does_not_panic() {
        let http_client = namespaced_http_client("tenant-a");
        let algorithm = TestAlgorithm {
            redis_ok: Arc::new(AtomicBool::new(true)),
        };
        let local: LocalLimiter<String, TestAlgorithm> = LocalLimiter::new(algorithm.clone());
        let redis = test_redis_limiter(&http_client, algorithm);

        let _limiter = FailoverLimiter::new("rate_limiting", redis, local);
    }

    #[tokio::test]
    async fn failover_limiter_falls_back_and_recovers() {
        let http_client = namespaced_http_client("tenant-a");
        let redis_ok = Arc::new(AtomicBool::new(true));
        let algorithm = TestAlgorithm {
            redis_ok: Arc::clone(&redis_ok),
        };
        let local = LocalLimiter::new(algorithm.clone());
        let redis = test_redis_limiter(&http_client, algorithm);
        let limiter = FailoverLimiter::new("rate_limiting", redis, local);
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

        assert_eq!(default.key_prefix(), "ferrum:rate_limiting");
        assert_eq!(tenant.key_prefix(), "tenant-a:rate_limiting");
    }
}
