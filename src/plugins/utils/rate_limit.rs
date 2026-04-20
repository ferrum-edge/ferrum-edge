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
    ) -> Option<Self> {
        let default_prefix = format!("{}:{plugin_name}", http_client.namespace());
        let cfg = RedisConfig::from_plugin_config(config, &default_prefix)?;
        let health_check_interval = Duration::from_secs(cfg.health_check_interval_seconds.max(1));
        #[cfg(test)]
        let key_prefix = cfg.key_prefix.clone();

        Some(Self {
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
        })
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

    pub fn retain_local_active_at(&self, now: Instant) {
        self.fallback.retain_active_at(now);
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

        tokio::spawn(async move {
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
    ) -> Self {
        let local = LocalLimiter::new(algorithm.clone());
        match RedisLimiter::new(plugin_name, config, http_client, algorithm) {
            Some(redis) => Self::Failover(FailoverLimiter::new(plugin_name, redis, local)),
            None => Self::Local(local),
        }
    }

    pub async fn check(&self, local_key: K, redis_key: &str, op: &A::Op) -> RateLimitOutcome {
        match self {
            Self::Local(local) => local.check(local_key, op),
            Self::Failover(failover) => failover.check(local_key, redis_key, op).await,
        }
    }

    pub fn tracked_keys_count(&self) -> usize {
        match self {
            Self::Local(local) => local.tracked_keys_count(),
            Self::Failover(failover) => failover.tracked_keys_count(),
        }
    }

    pub fn retain_active_at(&self, now: Instant) {
        match self {
            Self::Local(local) => local.retain_active_at(now),
            Self::Failover(failover) => failover.retain_local_active_at(now),
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

    pub fn check_and_increment(&mut self, now: Instant) -> bool {
        self.evict(now);
        if self.timestamps.len() as u64 >= self.limit {
            return false;
        }
        self.timestamps.push_back(now);
        true
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

#[derive(Debug, Clone)]
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

#[derive(Debug, Clone, Copy)]
pub struct RequestUnit;

#[derive(Debug, Clone)]
pub struct HttpRateLimitAlgorithm {
    specs: Arc<[RateLimitWindowSpec]>,
}

impl HttpRateLimitAlgorithm {
    pub fn new(specs: Vec<RateLimitWindowSpec>) -> Self {
        Self {
            specs: specs.into(),
        }
    }
}

#[async_trait]
impl RateLimitAlgorithm for HttpRateLimitAlgorithm {
    type State = Vec<HttpWindowState>;
    type Op = RequestUnit;

    fn new_state(&self) -> Self::State {
        self.specs
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

    fn check_local(
        &self,
        state: &mut Self::State,
        _op: &Self::Op,
        now: Instant,
    ) -> RateLimitOutcome {
        let mut tightest: Option<(u64, u64, u64)> = None;

        for (idx, window) in state.iter_mut().enumerate() {
            let spec = &self.specs[idx];
            let allowed = match window {
                HttpWindowState::Sliding(sliding) => sliding.check_and_increment(now),
                HttpWindowState::Bucket(bucket) => bucket.check_and_consume(now, 1),
            };

            if !allowed {
                return RateLimitOutcome::deny()
                    .with_limit(spec.limit)
                    .with_window(spec.duration.as_secs());
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

    async fn check_redis(
        &self,
        redis: &RedisRateLimitClient,
        key: &str,
        _op: &Self::Op,
    ) -> Result<RateLimitOutcome, ()> {
        let mut tightest: Option<(u64, u64, u64)> = None;

        for spec in self.specs.iter() {
            let window = FixedWindow::new(spec.limit, spec.duration.as_secs());
            let curr_idx = RedisRateLimitClient::window_index(window.window_seconds);
            let prev_idx = curr_idx.saturating_sub(1);
            let elapsed_fraction = RedisRateLimitClient::elapsed_fraction(window.window_seconds);
            let curr_key = redis.make_key(&[key, &curr_idx.to_string()]);
            let prev_key = redis.make_key(&[key, &prev_idx.to_string()]);
            let ttl = window.window_seconds * 2 + 1;

            let result = redis
                .sliding_window_check(&prev_key, &curr_key, ttl, elapsed_fraction, spec.limit)
                .await?;

            if !result.allowed {
                return Ok(RateLimitOutcome::deny()
                    .with_limit(spec.limit)
                    .with_window(spec.duration.as_secs()));
            }

            match tightest {
                Some((current_remaining, _, _)) if result.remaining >= current_remaining => {}
                _ => {
                    tightest = Some((result.remaining, spec.limit, spec.duration.as_secs()));
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

    fn is_state_active(&self, state: &Self::State, now: Instant) -> bool {
        state.iter().any(|window| window.is_active(now))
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
    RecordUsage { tokens: u64 },
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
            AiRateLimitOp::RecordUsage { tokens } => {
                state.record_usage(now, tokens);
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
            AiRateLimitOp::RecordUsage { tokens } => {
                let curr_idx = RedisRateLimitClient::window_index(self.window_seconds);
                let redis_key = redis.make_key(&[key, &curr_idx.to_string()]);
                let ttl = self.window_seconds * 2 + 1;
                let _ = redis
                    .incrby_with_expire(&redis_key, tokens as i64, ttl)
                    .await?;
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

impl WsFrameRateAlgorithm {
    pub fn new(frames_per_second: f64, burst_size: f64) -> Self {
        Self {
            frames_per_second,
            burst_size,
        }
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
        let window_idx = RedisRateLimitClient::window_index(1);
        let redis_key = redis.make_key(&[key, &window_idx.to_string()]);
        let count = redis.incr_with_expire(&redis_key, 2).await?;
        let allowed = count <= self.burst_size as i64;
        let remaining = (self.burst_size as i64 - count).max(0) as u64;
        let outcome = if allowed {
            RateLimitOutcome::allow()
        } else {
            RateLimitOutcome::deny()
        };
        Ok(outcome
            .with_limit(self.burst_size as u64)
            .with_window(1)
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

        let count = match self.datagrams_per_window {
            Some(_) if self.bytes_per_window.is_some() => {
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
                if let Some(max_bytes) = self.bytes_per_window
                    && bytes as u64 > max_bytes
                {
                    return Ok(RateLimitOutcome::deny()
                        .with_limit(max_bytes)
                        .with_window(self.window_seconds)
                        .with_usage(bytes as u64)
                        .with_metric("bytes"));
                }
                count
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
                count
            }
            None => 0,
        };

        if self.datagrams_per_window.is_none()
            && let Some(max_bytes) = self.bytes_per_window
        {
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
        } else if let Some(max_datagrams) = self.datagrams_per_window
            && count as u64 > max_datagrams
        {
            return Ok(RateLimitOutcome::deny()
                .with_limit(max_datagrams)
                .with_window(self.window_seconds)
                .with_usage(count as u64)
                .with_metric("count"));
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
            namespace,
        )
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

    #[tokio::test]
    async fn failover_limiter_falls_back_and_recovers() {
        let http_client = namespaced_http_client("tenant-a");
        let redis_ok = Arc::new(AtomicBool::new(true));
        let algorithm = TestAlgorithm {
            redis_ok: Arc::clone(&redis_ok),
        };
        let local = LocalLimiter::new(algorithm.clone());
        let redis = RedisLimiter::new(
            "rate_limiting",
            &json!({
                "sync_mode": "redis",
                "redis_url": "redis://127.0.0.1:6379/0",
                "redis_health_check_interval_seconds": 1
            }),
            &http_client,
            algorithm,
        )
        .unwrap();
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
        let default = RedisLimiter::new(
            "rate_limiting",
            &json!({
                "sync_mode": "redis",
                "redis_url": "redis://127.0.0.1:6379/0"
            }),
            &namespaced_http_client("ferrum"),
            TestAlgorithm {
                redis_ok: Arc::new(AtomicBool::new(true)),
            },
        )
        .unwrap();
        let tenant = RedisLimiter::new(
            "rate_limiting",
            &json!({
                "sync_mode": "redis",
                "redis_url": "redis://127.0.0.1:6379/0"
            }),
            &namespaced_http_client("tenant-a"),
            TestAlgorithm {
                redis_ok: Arc::new(AtomicBool::new(true)),
            },
        )
        .unwrap();

        assert_eq!(default.key_prefix(), "ferrum:rate_limiting");
        assert_eq!(tenant.key_prefix(), "tenant-a:rate_limiting");
    }
}
