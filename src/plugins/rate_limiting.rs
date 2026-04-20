//! General request rate limiting with optional Redis-backed failover.

use async_trait::async_trait;
use serde_json::Value;
use std::collections::HashMap;
use std::time::{Duration, Instant};
use tracing::warn;

use super::utils::rate_limit::{
    HttpRateLimitAlgorithm, RateLimitBackend, RateLimitOutcome, RateLimitWindowSpec, RequestUnit,
};
use super::{Plugin, PluginHttpClient, PluginResult, RequestContext};

const MAX_STATE_ENTRIES: usize = 100_000;

pub struct RateLimiting {
    limit_by: String,
    expose_headers: bool,
    limiter: RateLimitBackend<String, HttpRateLimitAlgorithm>,
}

impl RateLimiting {
    pub fn new(config: &Value, http_client: PluginHttpClient) -> Result<Self, String> {
        let limit_by = config["limit_by"].as_str().unwrap_or("ip").to_string();
        let expose_headers = config["expose_headers"].as_bool().unwrap_or(false);

        let window_specs = if let Some(window_seconds) = config["window_seconds"].as_u64() {
            let max_requests = config["max_requests"].as_u64().unwrap_or(10);
            if max_requests == 0 {
                return Err("rate_limiting: 'max_requests' must be greater than zero".to_string());
            }
            vec![RateLimitWindowSpec {
                limit: max_requests,
                duration: Duration::from_secs(window_seconds.max(1)),
            }]
        } else {
            let mut specs = Vec::new();

            if let Some(limit) = config["requests_per_second"].as_u64() {
                if limit == 0 {
                    return Err(
                        "rate_limiting: 'requests_per_second' must be greater than zero"
                            .to_string(),
                    );
                }
                specs.push(RateLimitWindowSpec {
                    limit,
                    duration: Duration::from_secs(1),
                });
            }

            if let Some(limit) = config["requests_per_minute"].as_u64() {
                if limit == 0 {
                    return Err(
                        "rate_limiting: 'requests_per_minute' must be greater than zero"
                            .to_string(),
                    );
                }
                specs.push(RateLimitWindowSpec {
                    limit,
                    duration: Duration::from_secs(60),
                });
            }

            if let Some(limit) = config["requests_per_hour"].as_u64() {
                if limit == 0 {
                    return Err(
                        "rate_limiting: 'requests_per_hour' must be greater than zero".to_string(),
                    );
                }
                specs.push(RateLimitWindowSpec {
                    limit,
                    duration: Duration::from_secs(3600),
                });
            }

            specs
        };

        if window_specs.is_empty() {
            return Err(
                "rate_limiting: no rate limit windows configured — set 'window_seconds'+'max_requests', or 'requests_per_second'/'requests_per_minute'/'requests_per_hour'"
                    .to_string(),
            );
        }

        let limiter = RateLimitBackend::from_plugin_config(
            "rate_limiting",
            config,
            &http_client,
            HttpRateLimitAlgorithm::new(window_specs),
        );

        Ok(Self {
            limit_by,
            expose_headers,
            limiter,
        })
    }

    fn evict_stale_entries(&self) {
        if self.limiter.tracked_keys_count() > MAX_STATE_ENTRIES {
            self.limiter.retain_active_at(Instant::now());
        }
    }

    fn reject(&self, key: &str, outcome: &RateLimitOutcome) -> PluginResult {
        let mut headers = HashMap::new();
        if self.expose_headers {
            if let Some(limit) = outcome.limit {
                headers.insert("x-ratelimit-limit".to_string(), limit.to_string());
            }
            headers.insert("x-ratelimit-remaining".to_string(), "0".to_string());
            if let Some(window) = outcome.window_seconds {
                headers.insert("x-ratelimit-window".to_string(), window.to_string());
            }
            headers.insert("x-ratelimit-identity".to_string(), key.to_string());
        }

        PluginResult::Reject {
            status_code: 429,
            body: r#"{"error":"Rate limit exceeded"}"#.into(),
            headers,
        }
    }

    fn store_metadata(&self, key: &str, outcome: &RateLimitOutcome, ctx: &mut RequestContext) {
        if !self.expose_headers {
            return;
        }

        if let Some(limit) = outcome.limit {
            ctx.metadata
                .insert("ratelimit_limit".to_string(), limit.to_string());
        }
        if let Some(remaining) = outcome.remaining {
            ctx.metadata
                .insert("ratelimit_remaining".to_string(), remaining.to_string());
        }
        if let Some(window) = outcome.window_seconds {
            ctx.metadata
                .insert("ratelimit_window".to_string(), window.to_string());
        }
        ctx.metadata
            .insert("ratelimit_identity".to_string(), key.to_string());
    }

    async fn check_rate(&self, key: String, ctx: &mut RequestContext) -> PluginResult {
        self.evict_stale_entries();
        let outcome = self.limiter.check(key.clone(), &key, &RequestUnit).await;
        if !outcome.allowed {
            warn!(rate_limit_key = %key, plugin = "rate_limiting", "Rate limit exceeded");
            return self.reject(&key, &outcome);
        }

        self.store_metadata(&key, &outcome, ctx);
        PluginResult::Continue
    }

    async fn check_rate_stream(&self, key: String) -> PluginResult {
        self.evict_stale_entries();
        let outcome = self.limiter.check(key.clone(), &key, &RequestUnit).await;
        if !outcome.allowed {
            warn!(rate_limit_key = %key, plugin = "rate_limiting", "Rate limit exceeded (stream)");
            return self.reject(&key, &outcome);
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
        Some(self.limiter.tracked_keys_count())
    }

    fn modifies_request_headers(&self) -> bool {
        self.expose_headers
    }

    fn warmup_hostnames(&self) -> Vec<String> {
        self.limiter.warmup_hostname().into_iter().collect()
    }

    async fn on_stream_connect(
        &self,
        ctx: &mut super::StreamConnectionContext,
    ) -> super::PluginResult {
        let key = if self.limit_by == "consumer" {
            ctx.effective_identity()
                .map(|identity| format!("consumer:{identity}"))
                .unwrap_or_else(|| format!("ip:{}", ctx.client_ip))
        } else {
            format!("ip:{}", ctx.client_ip)
        };
        self.check_rate_stream(key).await
    }

    async fn on_request_received(&self, ctx: &mut RequestContext) -> PluginResult {
        let ip_key = format!("ip:{}", ctx.client_ip);
        self.check_rate(ip_key, ctx).await
    }

    async fn authorize(&self, ctx: &mut RequestContext) -> PluginResult {
        if self.limit_by != "consumer" {
            return PluginResult::Continue;
        }

        if let Some(identity) = ctx.effective_identity() {
            self.check_rate(format!("consumer:{identity}"), ctx).await
        } else {
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
        if let Some(value) = metadata.get(meta_key) {
            headers.insert(header_name.to_string(), value.clone());
        }
    }
}
