use async_trait::async_trait;
use dashmap::DashMap;
use serde_json::Value;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tracing::debug;

use super::{Plugin, PluginResult, RequestContext};

#[derive(Debug)]
struct RateWindow {
    count: u64,
    window_start: Instant,
    window_duration: Duration,
    limit: u64,
}

impl RateWindow {
    fn new(limit: u64, duration: Duration) -> Self {
        Self {
            count: 0,
            window_start: Instant::now(),
            window_duration: duration,
            limit,
        }
    }

    fn check_and_increment(&mut self) -> bool {
        let now = Instant::now();
        if now.duration_since(self.window_start) >= self.window_duration {
            self.window_start = now;
            self.count = 1;
            true
        } else if self.count < self.limit {
            self.count += 1;
            true
        } else {
            false
        }
    }
}

pub struct RateLimiting {
    limit_by: String,
    per_second: Option<u64>,
    per_minute: Option<u64>,
    per_hour: Option<u64>,
    // key -> windows (second, minute, hour)
    state: Arc<DashMap<String, Vec<RateWindow>>>,
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
                .map(|c| c.username.clone())
                .unwrap_or_else(|| ctx.client_ip.clone()),
            _ => ctx.client_ip.clone(),
        }
    }
}

#[async_trait]
impl Plugin for RateLimiting {
    fn name(&self) -> &str {
        "rate_limiting"
    }

    async fn on_request_received(&self, ctx: &mut RequestContext) -> PluginResult {
        let key = self.get_key(ctx);

        let mut entry = self.state.entry(key.clone()).or_insert_with(|| {
            let mut windows = Vec::new();
            if let Some(limit) = self.per_second {
                windows.push(RateWindow::new(limit, Duration::from_secs(1)));
            }
            if let Some(limit) = self.per_minute {
                windows.push(RateWindow::new(limit, Duration::from_secs(60)));
            }
            if let Some(limit) = self.per_hour {
                windows.push(RateWindow::new(limit, Duration::from_secs(3600)));
            }
            windows
        });

        for window in entry.value_mut().iter_mut() {
            if !window.check_and_increment() {
                debug!("rate_limiting: limit exceeded for key '{}'", key);
                return PluginResult::Reject {
                    status_code: 429,
                    body: r#"{"error":"Rate limit exceeded"}"#.into(),
                };
            }
        }

        PluginResult::Continue
    }

    // Rate limiting is applied only in on_request_received to avoid double-counting.
    // The authorize phase is intentionally left as the default (Continue).
}
