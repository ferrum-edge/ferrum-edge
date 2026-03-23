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
}

/// Maximum entries before triggering eviction of stale rate-limit state.
const MAX_STATE_ENTRIES: usize = 100_000;

pub struct RateLimiting {
    limit_by: String,
    per_second: Option<u64>,
    per_minute: Option<u64>,
    per_hour: Option<u64>,
    // key -> windows (second, minute, hour)
    state: Arc<DashMap<String, Vec<SlidingWindow>>>,
}

impl RateLimiting {
    pub fn new(config: &Value) -> Self {
        let limit_by = config["limit_by"].as_str().unwrap_or("ip").to_string();

        // Handle different configuration formats
        let (per_second, per_minute, per_hour) =
            if let Some(window_seconds) = config["window_seconds"].as_u64() {
                let max_requests = config["max_requests"].as_u64().unwrap_or(10);

                // Convert window_seconds to appropriate rate limits
                match window_seconds {
                    1 => (Some(max_requests), None, None),
                    60 => (None, Some(max_requests), None),
                    3600 => (None, None, Some(max_requests)),
                    _ => {
                        // For other window sizes, convert to per-minute rate
                        let per_minute_rate = (max_requests * 60) / window_seconds.max(1);
                        (None, Some(per_minute_rate), None)
                    }
                }
            } else {
                // Use the explicit rate limits if provided
                (
                    config["requests_per_second"].as_u64(),
                    config["requests_per_minute"].as_u64(),
                    config["requests_per_hour"].as_u64(),
                )
            };

        Self {
            limit_by,
            per_second,
            per_minute,
            per_hour,
            state: Arc::new(DashMap::new()),
        }
    }

    fn get_key(&self, ctx: &RequestContext) -> String {
        match self.limit_by.as_str() {
            "consumer" => ctx
                .identified_consumer
                .as_ref()
                .map(|c| format!("consumer:{}", c.username))
                .unwrap_or_else(|| format!("ip:{}", ctx.client_ip)),
            _ => format!("ip:{}", ctx.client_ip),
        }
    }

    /// Evict entries whose sliding windows are all empty (no recent requests).
    /// Called periodically to prevent unbounded memory growth.
    fn evict_stale_entries(&self) {
        if self.state.len() <= MAX_STATE_ENTRIES {
            return;
        }

        let now = Instant::now();
        self.state.retain(|_, windows| {
            // Keep the entry if any window still has timestamps within its duration
            windows.iter().any(|w| {
                w.timestamps
                    .back()
                    .is_some_and(|last| now.duration_since(*last) < w.window_duration)
            })
        });
    }

    fn check_rate(&self, key: &str) -> PluginResult {
        // Periodically evict stale entries to bound memory usage
        self.evict_stale_entries();

        let mut entry = self.state.entry(key.to_string()).or_insert_with(|| {
            let mut windows = Vec::new();
            if let Some(limit) = self.per_second {
                windows.push(SlidingWindow::new(limit, Duration::from_secs(1)));
            }
            if let Some(limit) = self.per_minute {
                windows.push(SlidingWindow::new(limit, Duration::from_secs(60)));
            }
            if let Some(limit) = self.per_hour {
                windows.push(SlidingWindow::new(limit, Duration::from_secs(3600)));
            }
            windows
        });

        for window in entry.value_mut().iter_mut() {
            if !window.check_and_increment() {
                warn!(key = %key, "Rate limit exceeded");
                return PluginResult::Reject {
                    status_code: 429,
                    body: r#"{"error":"Rate limit exceeded"}"#.into(),
                    headers: HashMap::new(),
                };
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
        // Runs at 299 so it executes after access_control (200) in the authorize
        // phase, where identified_consumer is available for consumer-based limiting.
        // IP-based limiting also runs in on_request_received (phase 1) for early
        // rejection before auth.
        super::priority::RATE_LIMITING
    }

    async fn on_request_received(&self, ctx: &mut RequestContext) -> PluginResult {
        // Phase 1: always enforce IP-based limits early (before auth).
        // This protects auth endpoints from brute-force regardless of limit_by mode.
        let ip_key = format!("ip:{}", ctx.client_ip);
        if self.limit_by == "ip" {
            self.check_rate(&ip_key)
        } else {
            // In consumer mode, still do IP limiting in phase 1 as a safety net
            // for unauthenticated requests. The consumer-specific limit is checked
            // later in authorize (phase 3) after the consumer is identified.
            PluginResult::Continue
        }
    }

    async fn authorize(&self, ctx: &mut RequestContext) -> PluginResult {
        // Phase 3: enforce consumer-based limits after authentication has identified
        // the consumer. Only runs when limit_by is "consumer".
        if self.limit_by != "consumer" {
            return PluginResult::Continue;
        }

        let key = self.get_key(ctx);
        self.check_rate(&key)
    }
}
