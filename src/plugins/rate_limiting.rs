//! Rate limiting plugin with dual-algorithm design and optional Redis sync.
//!
//! **Algorithm selection** (automatic based on window duration):
//! - **Token bucket** (`window_seconds <= 5`): Fixed-capacity bucket refilled at
//!   `limit / window_seconds` tokens/sec. Best for TPS limiting where sub-second
//!   burst control matters. O(1) memory per key.
//! - **Sliding window** (`window_seconds > 5`): Tracks individual request timestamps
//!   within the window for exact counting with zero boundary-burst vulnerability.
//!   Best for longer windows (minutes, hours). O(n) memory per key where n = requests
//!   in window.
//!
//! **Dual-phase execution**: Runs in both `before_proxy` (to reject over-limit
//! requests early) and `on_response_body` (to count requests that actually completed).
//!
//! **Redis sync** (`sync_mode: "redis"`): When enabled, counters are stored in Redis
//! using a two-window weighted approximation algorithm (no Lua scripts, single
//! pipelined round-trip). Falls back to local DashMap state if Redis is unavailable.

use async_trait::async_trait;
use dashmap::DashMap;
use serde_json::Value;
use std::collections::{HashMap, VecDeque};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tracing::warn;

use super::{Plugin, PluginHttpClient, PluginResult, RequestContext};

use super::utils::redis_rate_limiter::{RedisConfig, RedisRateLimitClient};

/// Sliding window rate limiter. Tracks individual request timestamps within the
/// window to provide exact counting with zero boundary-burst vulnerability.
///
/// Best for longer windows (minutes, hours) where the per-key timestamp count
/// stays bounded. For sub-second / per-second TPS limiting, use [`TokenBucket`]
/// instead to avoid O(n) memory per key.
#[derive(Debug)]
struct SlidingWindow {
    timestamps: VecDeque<Instant>,
    window_duration: Duration,
    limit: u64,
}

impl SlidingWindow {
    fn new(limit: u64, duration: Duration) -> Self {
        Self {
            timestamps: VecDeque::new(),
            window_duration: duration,
            limit,
        }
    }

    fn check_and_increment(&mut self) -> bool {
        let now = Instant::now();
        let window_start = now - self.window_duration;

        // Evict timestamps outside the sliding window
        while let Some(front) = self.timestamps.front() {
            if *front < window_start {
                self.timestamps.pop_front();
            } else {
                break;
            }
        }

        if (self.timestamps.len() as u64) < self.limit {
            self.timestamps.push_back(now);
            true
        } else {
            false
        }
    }

    fn remaining(&self) -> u64 {
        self.limit.saturating_sub(self.timestamps.len() as u64)
    }
}

/// Token bucket rate limiter. O(1) memory and O(1) per check regardless of TPS.
///
/// Tokens refill at a constant rate. Each request consumes one token.
/// When the bucket is empty, requests are rejected until tokens refill.
///
/// For a limit of N requests per T seconds:
/// - `capacity` = N (maximum burst size)
/// - `refill_rate` = N / T tokens per second
///
/// This provides smooth rate limiting suitable for high-TPS scenarios
/// (e.g., 10,000 req/s) without storing individual request timestamps.
#[derive(Debug)]
struct TokenBucket {
    /// Current available tokens (fractional for smooth refill).
    tokens: f64,
    /// Maximum tokens (= request limit).
    capacity: f64,
    /// Tokens added per second.
    refill_rate: f64,
    /// Last time tokens were refilled.
    last_refill: Instant,
}

impl TokenBucket {
    fn new(limit: u64, window: Duration) -> Self {
        let capacity = limit as f64;
        let window_secs = window.as_secs_f64().max(0.001); // avoid division by zero
        Self {
            tokens: capacity,
            capacity,
            refill_rate: capacity / window_secs,
            last_refill: Instant::now(),
        }
    }

    fn check_and_consume(&mut self) -> bool {
        let now = Instant::now();
        let elapsed = now.duration_since(self.last_refill).as_secs_f64();
        self.last_refill = now;

        // Refill tokens based on elapsed time
        self.tokens = (self.tokens + elapsed * self.refill_rate).min(self.capacity);

        if self.tokens >= 1.0 {
            self.tokens -= 1.0;
            true
        } else {
            false
        }
    }

    fn remaining(&self) -> u64 {
        self.tokens.max(0.0) as u64
    }
}

/// A rate window that automatically picks the best algorithm.
///
/// - Short windows (≤5s): token bucket — O(1) memory, ideal for TPS limiting
/// - Longer windows (>5s): sliding window — exact counting, no boundary burst
#[derive(Debug)]
enum RateWindow {
    Sliding(SlidingWindow),
    Bucket(TokenBucket),
}

impl RateWindow {
    fn new(limit: u64, duration: Duration) -> Self {
        if duration.as_secs() <= 5 {
            RateWindow::Bucket(TokenBucket::new(limit, duration))
        } else {
            RateWindow::Sliding(SlidingWindow::new(limit, duration))
        }
    }

    fn check_and_increment(&mut self) -> bool {
        match self {
            RateWindow::Sliding(sw) => sw.check_and_increment(),
            RateWindow::Bucket(tb) => tb.check_and_consume(),
        }
    }

    /// Returns the window duration (for stale entry eviction).
    fn window_duration(&self) -> Duration {
        match self {
            RateWindow::Sliding(sw) => sw.window_duration,
            RateWindow::Bucket(tb) => {
                // For staleness: if tokens are full, no recent activity
                Duration::from_secs_f64(tb.capacity / tb.refill_rate)
            }
        }
    }

    /// Returns the number of requests remaining before this window rejects.
    fn remaining(&self) -> u64 {
        match self {
            RateWindow::Sliding(sw) => sw.remaining(),
            RateWindow::Bucket(tb) => tb.remaining(),
        }
    }

    /// Returns the configured limit for this window.
    fn limit(&self) -> u64 {
        match self {
            RateWindow::Sliding(sw) => sw.limit,
            RateWindow::Bucket(tb) => tb.capacity as u64,
        }
    }

    /// Returns true if this window has had recent activity.
    fn has_recent_activity(&self, now: Instant) -> bool {
        match self {
            RateWindow::Sliding(sw) => sw
                .timestamps
                .back()
                .is_some_and(|last| now.duration_since(*last) < sw.window_duration),
            RateWindow::Bucket(tb) => now.duration_since(tb.last_refill) < self.window_duration(),
        }
    }
}

/// Maximum entries before triggering eviction of stale rate-limit state.
const MAX_STATE_ENTRIES: usize = 100_000;

/// A rate window specification: requests allowed within a duration.
#[derive(Debug, Clone)]
struct WindowSpec {
    limit: u64,
    duration: Duration,
}

pub struct RateLimiting {
    limit_by: String,
    /// When true, inject `x-ratelimit-*` headers on requests (to backend) and
    /// responses (to client) so both sides can see current rate-limit state.
    expose_headers: bool,
    /// Window specifications used to create RateWindows per key.
    window_specs: Vec<WindowSpec>,
    // key -> windows (local in-memory state)
    state: Arc<DashMap<String, Vec<RateWindow>>>,
    /// Redis-backed rate limiter for centralized mode. When set, rate limit
    /// counters are stored in Redis so multiple gateway instances share state.
    /// Falls back to local `state` DashMap when Redis is unreachable.
    redis_client: Option<Arc<RedisRateLimitClient>>,
}

impl RateLimiting {
    pub fn new(config: &Value, http_client: PluginHttpClient) -> Self {
        let limit_by = config["limit_by"].as_str().unwrap_or("ip").to_string();
        let expose_headers = config["expose_headers"].as_bool().unwrap_or(false);

        let window_specs = if let Some(window_seconds) = config["window_seconds"].as_u64() {
            let max_requests = config["max_requests"].as_u64().unwrap_or(10);
            // Use the exact window duration — no conversion or precision loss
            vec![WindowSpec {
                limit: max_requests,
                duration: Duration::from_secs(window_seconds.max(1)),
            }]
        } else {
            // Use the explicit rate limits if provided
            let mut specs = Vec::new();
            if let Some(limit) = config["requests_per_second"].as_u64() {
                specs.push(WindowSpec {
                    limit,
                    duration: Duration::from_secs(1),
                });
            }
            if let Some(limit) = config["requests_per_minute"].as_u64() {
                specs.push(WindowSpec {
                    limit,
                    duration: Duration::from_secs(60),
                });
            }
            if let Some(limit) = config["requests_per_hour"].as_u64() {
                specs.push(WindowSpec {
                    limit,
                    duration: Duration::from_secs(3600),
                });
            }
            specs
        };

        if window_specs.is_empty() {
            tracing::warn!(
                "rate_limiting: no rate limit windows configured — set 'window_seconds'+'max_requests', or 'requests_per_second'/'requests_per_minute'/'requests_per_hour'"
            );
        }

        let dns_cache = http_client.dns_cache().cloned();
        let tls_no_verify = http_client.tls_no_verify();
        let tls_ca_bundle_path = http_client.tls_ca_bundle_path().map(|s| s.to_string());
        let redis_client =
            RedisConfig::from_plugin_config(config, "ferrum:rate_limiting").map(|cfg| {
                tracing::info!(
                    redis_url = %cfg.url,
                    key_prefix = %cfg.key_prefix,
                    "rate_limiting: centralized Redis mode enabled"
                );
                Arc::new(RedisRateLimitClient::new(
                    cfg,
                    dns_cache,
                    tls_no_verify,
                    tls_ca_bundle_path.as_deref(),
                ))
            });

        Self {
            limit_by,
            expose_headers,
            window_specs,
            state: Arc::new(DashMap::new()),
            redis_client,
        }
    }

    /// Evict entries whose rate windows have had no recent activity.
    /// Called periodically to prevent unbounded memory growth.
    fn evict_stale_entries(&self) {
        if self.state.len() <= MAX_STATE_ENTRIES {
            return;
        }

        let now = Instant::now();
        self.state
            .retain(|_, windows| windows.iter().any(|w| w.has_recent_activity(now)));
    }

    /// Check rate limit using Redis (centralized mode).
    ///
    /// Uses a two-window weighted approximation for sliding window semantics:
    /// the previous window's count is weighted by `(1 - elapsed_fraction)` and
    /// added to the current window's count. This provides smooth rate limiting
    /// without boundary bursts, using only native Redis commands.
    ///
    /// Returns `None` if Redis is unavailable (caller should fall back to local).
    async fn check_rate_redis(
        &self,
        redis: &RedisRateLimitClient,
        key: &str,
        spec: &WindowSpec,
    ) -> Option<RedisCheckResult> {
        if !redis.is_available() {
            return None;
        }

        let window_secs = spec.duration.as_secs().max(1);
        let curr_idx = RedisRateLimitClient::window_index(window_secs);
        let prev_idx = curr_idx.saturating_sub(1);
        let elapsed_fraction = RedisRateLimitClient::elapsed_fraction(window_secs);

        let curr_key = redis.make_key(&[key, &curr_idx.to_string()]);
        let prev_key = redis.make_key(&[key, &prev_idx.to_string()]);

        // TTL: 2x window to keep previous window data available for the weighted calc
        let ttl = window_secs * 2 + 1;

        match redis
            .sliding_window_check(&prev_key, &curr_key, ttl, elapsed_fraction, spec.limit)
            .await
        {
            Ok(result) => Some(RedisCheckResult {
                allowed: result.allowed,
                remaining: result.remaining,
                limit: spec.limit,
            }),
            Err(()) => None, // Redis unavailable, fall back to local
        }
    }

    /// Rate check for stream connections (TCP/UDP). No metadata injection
    /// since streams don't have response headers to inject ratelimit info into.
    fn check_rate_stream_local(&self, key: &str) -> PluginResult {
        self.evict_stale_entries();

        let specs = &self.window_specs;
        let mut entry = self.state.entry(key.to_string()).or_insert_with(|| {
            specs
                .iter()
                .map(|spec| RateWindow::new(spec.limit, spec.duration))
                .collect()
        });

        for (i, window) in entry.value_mut().iter_mut().enumerate() {
            if !window.check_and_increment() {
                warn!(rate_limit_key = %key, plugin = "rate_limiting", "Rate limit exceeded (stream)");
                let mut headers = HashMap::new();
                if self.expose_headers {
                    headers.insert("x-ratelimit-limit".to_string(), specs[i].limit.to_string());
                    headers.insert("x-ratelimit-remaining".to_string(), "0".to_string());
                }
                return PluginResult::Reject {
                    status_code: 429,
                    body: r#"{"error":"Rate limit exceeded"}"#.into(),
                    headers,
                };
            }
        }

        PluginResult::Continue
    }

    /// Rate check for stream connections with Redis support.
    async fn check_rate_stream_redis(&self, key: &str) -> Option<PluginResult> {
        let redis = self.redis_client.as_ref()?;
        if !redis.is_available() {
            return None;
        }

        for spec in &self.window_specs {
            if let Some(result) = self.check_rate_redis(redis, key, spec).await {
                if !result.allowed {
                    warn!(rate_limit_key = %key, plugin = "rate_limiting", "Rate limit exceeded (stream, redis)");
                    let mut headers = HashMap::new();
                    if self.expose_headers {
                        headers.insert("x-ratelimit-limit".to_string(), result.limit.to_string());
                        headers.insert("x-ratelimit-remaining".to_string(), "0".to_string());
                    }
                    return Some(PluginResult::Reject {
                        status_code: 429,
                        body: r#"{"error":"Rate limit exceeded"}"#.into(),
                        headers,
                    });
                }
            } else {
                return None; // Redis unavailable, fall back to local
            }
        }

        Some(PluginResult::Continue)
    }

    fn check_rate_local(&self, key: &str, ctx: &mut RequestContext) -> PluginResult {
        // Periodically evict stale entries to bound memory usage
        self.evict_stale_entries();

        let specs = &self.window_specs;
        let mut entry = self.state.entry(key.to_string()).or_insert_with(|| {
            specs
                .iter()
                .map(|spec| RateWindow::new(spec.limit, spec.duration))
                .collect()
        });

        let mut rejected_spec_idx: Option<usize> = None;
        for (i, window) in entry.value_mut().iter_mut().enumerate() {
            if !window.check_and_increment() {
                rejected_spec_idx = Some(i);
                break;
            }
        }

        if let Some(idx) = rejected_spec_idx {
            warn!(rate_limit_key = %key, plugin = "rate_limiting", "Rate limit exceeded");
            let mut headers = HashMap::new();
            if self.expose_headers {
                headers.insert(
                    "x-ratelimit-limit".to_string(),
                    specs[idx].limit.to_string(),
                );
                headers.insert("x-ratelimit-remaining".to_string(), "0".to_string());
                headers.insert(
                    "x-ratelimit-window".to_string(),
                    specs[idx].duration.as_secs().to_string(),
                );
                headers.insert("x-ratelimit-identity".to_string(), key.to_string());
            }
            return PluginResult::Reject {
                status_code: 429,
                body: r#"{"error":"Rate limit exceeded"}"#.into(),
                headers,
            };
        }

        // Store rate info in metadata for header injection in before_proxy / after_proxy
        if self.expose_headers {
            // Find the tightest window (lowest remaining) for header reporting
            if let Some((i, window)) = entry
                .value()
                .iter()
                .enumerate()
                .min_by_key(|(_, w)| w.remaining())
            {
                ctx.metadata
                    .insert("ratelimit_limit".to_string(), window.limit().to_string());
                ctx.metadata.insert(
                    "ratelimit_remaining".to_string(),
                    window.remaining().to_string(),
                );
                ctx.metadata.insert(
                    "ratelimit_window".to_string(),
                    specs[i].duration.as_secs().to_string(),
                );
                ctx.metadata
                    .insert("ratelimit_identity".to_string(), key.to_string());
            }
        }

        PluginResult::Continue
    }

    /// Check rate limit with Redis fallback to local.
    async fn check_rate_redis_with_fallback(
        &self,
        key: &str,
        ctx: &mut RequestContext,
    ) -> Option<PluginResult> {
        let redis = self.redis_client.as_ref()?;
        if !redis.is_available() {
            return None;
        }

        // Check all window specs against Redis
        let mut tightest_remaining: Option<(u64, u64, u64)> = None; // (remaining, limit, window_secs)

        for spec in &self.window_specs {
            if let Some(result) = self.check_rate_redis(redis, key, spec).await {
                if !result.allowed {
                    warn!(rate_limit_key = %key, plugin = "rate_limiting", "Rate limit exceeded (redis)");
                    let mut headers = HashMap::new();
                    if self.expose_headers {
                        headers.insert("x-ratelimit-limit".to_string(), result.limit.to_string());
                        headers.insert("x-ratelimit-remaining".to_string(), "0".to_string());
                        headers.insert(
                            "x-ratelimit-window".to_string(),
                            spec.duration.as_secs().to_string(),
                        );
                        headers.insert("x-ratelimit-identity".to_string(), key.to_string());
                    }
                    return Some(PluginResult::Reject {
                        status_code: 429,
                        body: r#"{"error":"Rate limit exceeded"}"#.into(),
                        headers,
                    });
                }

                // Track tightest window for header reporting
                match &tightest_remaining {
                    Some((prev_remaining, _, _)) if result.remaining < *prev_remaining => {
                        tightest_remaining =
                            Some((result.remaining, result.limit, spec.duration.as_secs()));
                    }
                    None => {
                        tightest_remaining =
                            Some((result.remaining, result.limit, spec.duration.as_secs()));
                    }
                    _ => {}
                }
            } else {
                return None; // Redis unavailable, fall back to local
            }
        }

        // Store rate info in metadata for header injection
        if self.expose_headers
            && let Some((remaining, limit, window_secs)) = tightest_remaining
        {
            ctx.metadata
                .insert("ratelimit_limit".to_string(), limit.to_string());
            ctx.metadata
                .insert("ratelimit_remaining".to_string(), remaining.to_string());
            ctx.metadata
                .insert("ratelimit_window".to_string(), window_secs.to_string());
            ctx.metadata
                .insert("ratelimit_identity".to_string(), key.to_string());
        }

        Some(PluginResult::Continue)
    }

    /// Unified rate check: tries Redis first (if configured), falls back to local.
    async fn check_rate(&self, key: &str, ctx: &mut RequestContext) -> PluginResult {
        if self.redis_client.is_some()
            && let Some(result) = self.check_rate_redis_with_fallback(key, ctx).await
        {
            return result;
        }

        self.check_rate_local(key, ctx)
    }

    /// Unified stream rate check: tries Redis first (if configured), falls back to local.
    async fn check_rate_stream(&self, key: &str) -> PluginResult {
        if self.redis_client.is_some()
            && let Some(result) = self.check_rate_stream_redis(key).await
        {
            return result;
        }

        self.check_rate_stream_local(key)
    }
}

/// Result of a Redis rate limit check for a single window.
struct RedisCheckResult {
    allowed: bool,
    remaining: u64,
    limit: u64,
}

#[async_trait]
impl Plugin for RateLimiting {
    fn name(&self) -> &str {
        "rate_limiting"
    }

    fn priority(&self) -> u16 {
        super::priority::RATE_LIMITING
    }

    fn supported_protocols(&self) -> &'static [super::ProxyProtocol] {
        super::ALL_PROTOCOLS
    }

    fn tracked_keys_count(&self) -> Option<usize> {
        Some(self.state.len())
    }

    fn modifies_request_headers(&self) -> bool {
        self.expose_headers
    }

    fn warmup_hostnames(&self) -> Vec<String> {
        self.redis_client
            .as_ref()
            .and_then(|r| r.warmup_hostname())
            .into_iter()
            .collect()
    }

    async fn on_stream_connect(
        &self,
        ctx: &mut super::StreamConnectionContext,
    ) -> super::PluginResult {
        let ip_key = format!("ip:{}", ctx.client_ip);
        self.check_rate_stream(&ip_key).await
    }

    async fn on_request_received(&self, ctx: &mut RequestContext) -> PluginResult {
        // Phase 1: always enforce IP-based limits early (before auth).
        // This protects auth endpoints from brute-force regardless of limit_by mode.
        let ip_key = format!("ip:{}", ctx.client_ip);
        self.check_rate(&ip_key, ctx).await
    }

    async fn authorize(&self, ctx: &mut RequestContext) -> PluginResult {
        // Phase 3: enforce consumer-based limits after authentication has identified
        // the consumer. Only runs when limit_by is "consumer" and a consumer was found.
        // IP-based limiting already ran in phase 1 as a safety net.
        if self.limit_by != "consumer" {
            return PluginResult::Continue;
        }

        if let Some(consumer) = &ctx.identified_consumer {
            let key = format!("consumer:{}", consumer.username);
            self.check_rate(&key, ctx).await
        } else if let Some(ref identity) = ctx.authenticated_identity {
            // External auth (e.g. jwks_auth) identified a user without a gateway Consumer
            let key = format!("consumer:{}", identity);
            self.check_rate(&key, ctx).await
        } else {
            // No consumer identified — IP limit already applied in phase 1
            PluginResult::Continue
        }
    }

    async fn before_proxy(
        &self,
        ctx: &mut RequestContext,
        headers: &mut HashMap<String, String>,
    ) -> PluginResult {
        if !self.expose_headers {
            return PluginResult::Continue;
        }
        inject_rate_limit_headers_from_metadata(&ctx.metadata, headers);
        PluginResult::Continue
    }

    async fn after_proxy(
        &self,
        ctx: &mut RequestContext,
        _response_status: u16,
        response_headers: &mut HashMap<String, String>,
    ) -> PluginResult {
        if !self.expose_headers {
            return PluginResult::Continue;
        }
        inject_rate_limit_headers_from_metadata(&ctx.metadata, response_headers);
        PluginResult::Continue
    }
}

/// Copy rate-limit metadata into a headers map.
fn inject_rate_limit_headers_from_metadata(
    metadata: &HashMap<String, String>,
    headers: &mut HashMap<String, String>,
) {
    static KEYS: &[(&str, &str)] = &[
        ("ratelimit_limit", "x-ratelimit-limit"),
        ("ratelimit_remaining", "x-ratelimit-remaining"),
        ("ratelimit_window", "x-ratelimit-window"),
        ("ratelimit_identity", "x-ratelimit-identity"),
    ];
    for &(meta_key, header_name) in KEYS {
        if let Some(val) = metadata.get(meta_key) {
            headers.insert(header_name.to_string(), val.clone());
        }
    }
}
