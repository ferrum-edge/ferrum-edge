use async_trait::async_trait;
use dashmap::DashMap;
use serde_json::Value;
use std::collections::{HashMap, VecDeque};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tracing::warn;

use super::{Plugin, PluginResult, RequestContext};

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
    // key -> windows
    state: Arc<DashMap<String, Vec<RateWindow>>>,
}

impl RateLimiting {
    pub fn new(config: &Value) -> Self {
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

        Self {
            limit_by,
            expose_headers,
            window_specs,
            state: Arc::new(DashMap::new()),
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

    fn check_rate(&self, key: &str, ctx: &mut RequestContext) -> PluginResult {
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

    async fn on_request_received(&self, ctx: &mut RequestContext) -> PluginResult {
        // Phase 1: always enforce IP-based limits early (before auth).
        // This protects auth endpoints from brute-force regardless of limit_by mode.
        let ip_key = format!("ip:{}", ctx.client_ip);
        self.check_rate(&ip_key, ctx)
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
            self.check_rate(&key, ctx)
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
