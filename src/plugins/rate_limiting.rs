//! General request rate limiting with optional Redis-backed failover.

use async_trait::async_trait;
use serde_json::Value;
use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};
use tracing::warn;

use super::utils::rate_limit::{
    HttpRateLimitAlgorithm, RateLimitBackend, RateLimitOutcome, RateLimitWindowSpec, RequestUnit,
};
use super::{Plugin, PluginHttpClient, PluginResult, RequestContext};

const MAX_STATE_ENTRIES: usize = 100_000;
const EVICTION_CHECK_INTERVAL_REQUESTS: u64 = 1024;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum LimitBy {
    Ip,
    Consumer,
    SpiffeIdentity,
}

pub struct RateLimiting {
    limit_by: LimitBy,
    expose_headers: bool,
    limiter: RateLimitBackend<String, HttpRateLimitAlgorithm>,
    request_counter: AtomicU64,
}

impl RateLimiting {
    pub fn new(config: &Value, http_client: PluginHttpClient) -> Result<Self, String> {
        let object = config
            .as_object()
            .ok_or_else(|| format!("rate_limiting: config must be an object, got: {config}"))?;
        let limit_by = parse_limit_by(object)?;
        let expose_headers = parse_optional_bool(object, "expose_headers")?.unwrap_or(false);

        let window_specs = if let Some(window_seconds) =
            parse_optional_u64(object, "window_seconds")?
        {
            if window_seconds == 0 {
                return Err("rate_limiting: 'window_seconds' must be greater than zero".to_string());
            }
            let max_requests = parse_optional_u64(object, "max_requests")?.unwrap_or(10);
            if max_requests == 0 {
                return Err("rate_limiting: 'max_requests' must be greater than zero".to_string());
            }
            vec![RateLimitWindowSpec {
                limit: max_requests,
                duration: Duration::from_secs(window_seconds),
            }]
        } else {
            let mut specs = Vec::new();

            if let Some(limit) = parse_optional_u64(object, "requests_per_second")? {
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

            if let Some(limit) = parse_optional_u64(object, "requests_per_minute")? {
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

            if let Some(limit) = parse_optional_u64(object, "requests_per_hour")? {
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
        )?;

        Ok(Self {
            limit_by,
            expose_headers,
            limiter,
            request_counter: AtomicU64::new(0),
        })
    }

    fn maybe_evict_stale_entries(&self) {
        let request = self.request_counter.fetch_add(1, Ordering::Relaxed);
        if !request.is_multiple_of(EVICTION_CHECK_INTERVAL_REQUESTS) {
            return;
        }

        if self.limiter.tracked_keys_count() > MAX_STATE_ENTRIES {
            self.limiter
                .enforce_capacity(MAX_STATE_ENTRIES, Instant::now());
        }
    }

    fn request_key(&self, ctx: &RequestContext) -> String {
        match self.limit_by {
            LimitBy::Consumer => {
                if let Some(identity) = ctx.effective_identity() {
                    return prefixed_key("consumer:", identity);
                }
            }
            LimitBy::SpiffeIdentity => {
                if let Some(spiffe_id) = ctx.peer_spiffe_id.as_ref() {
                    return prefixed_key("spiffe:", spiffe_id.as_str());
                }
            }
            LimitBy::Ip => {}
        }

        ip_key(&ctx.client_ip)
    }

    fn stream_key(&self, ctx: &super::StreamConnectionContext) -> String {
        match self.limit_by {
            LimitBy::Consumer => {
                if let Some(identity) = ctx.effective_identity() {
                    return prefixed_key("consumer:", identity);
                }
            }
            LimitBy::SpiffeIdentity => {
                if let Some(spiffe_id) = ctx
                    .metadata
                    .as_ref()
                    .and_then(|metadata| metadata.get("peer_spiffe_id"))
                {
                    return prefixed_key("spiffe:", spiffe_id);
                }
            }
            LimitBy::Ip => {}
        }

        ip_key(&ctx.client_ip)
    }

    fn reject(&self, key: &str, outcome: &RateLimitOutcome) -> PluginResult {
        let mut headers = HashMap::with_capacity(4);
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
        let outcome = self.limiter.check(key.clone(), &key, &RequestUnit).await;
        self.maybe_evict_stale_entries();
        if !outcome.allowed {
            warn!(rate_limit_key = %key, plugin = "rate_limiting", "Rate limit exceeded");
            return self.reject(&key, &outcome);
        }

        self.store_metadata(&key, &outcome, ctx);
        PluginResult::Continue
    }

    async fn check_rate_stream(&self, key: String) -> PluginResult {
        let outcome = self.limiter.check(key.clone(), &key, &RequestUnit).await;
        self.maybe_evict_stale_entries();
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
        let key = self.stream_key(ctx);
        self.check_rate_stream(key).await
    }

    async fn on_request_received(&self, ctx: &mut RequestContext) -> PluginResult {
        if self.limit_by != LimitBy::Ip {
            return PluginResult::Continue;
        }

        let ip_key = self.request_key(ctx);
        self.check_rate(ip_key, ctx).await
    }

    async fn authorize(&self, ctx: &mut RequestContext) -> PluginResult {
        if !matches!(self.limit_by, LimitBy::Consumer | LimitBy::SpiffeIdentity) {
            return PluginResult::Continue;
        }

        let key = self.request_key(ctx);
        self.check_rate(key, ctx).await
    }

    fn is_authorize_plugin(&self) -> bool {
        matches!(self.limit_by, LimitBy::Consumer | LimitBy::SpiffeIdentity)
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

fn parse_limit_by(object: &serde_json::Map<String, Value>) -> Result<LimitBy, String> {
    match object.get("limit_by") {
        None | Some(Value::Null) => Ok(LimitBy::Ip),
        Some(Value::String(value)) => match value.to_ascii_lowercase().as_str() {
            "ip" => Ok(LimitBy::Ip),
            "consumer" => Ok(LimitBy::Consumer),
            "spiffe" | "spiffe_identity" => Ok(LimitBy::SpiffeIdentity),
            _ => Err(format!(
                "rate_limiting: 'limit_by' must be one of 'ip', 'consumer', or 'spiffe_identity', got: {value:?}"
            )),
        },
        Some(other) => Err(format!(
            "rate_limiting: 'limit_by' must be a string, got: {other}"
        )),
    }
}

fn parse_optional_bool(
    object: &serde_json::Map<String, Value>,
    field: &str,
) -> Result<Option<bool>, String> {
    object
        .get(field)
        .map(|value| {
            value
                .as_bool()
                .ok_or_else(|| format!("rate_limiting: '{field}' must be a boolean"))
        })
        .transpose()
}

fn parse_optional_u64(
    object: &serde_json::Map<String, Value>,
    field: &str,
) -> Result<Option<u64>, String> {
    object
        .get(field)
        .map(|value| {
            value
                .as_u64()
                .ok_or_else(|| format!("rate_limiting: '{field}' must be an integer"))
        })
        .transpose()
}

fn prefixed_key(prefix: &str, value: &str) -> String {
    let mut key = String::with_capacity(prefix.len() + value.len());
    key.push_str(prefix);
    key.push_str(value);
    key
}

fn ip_key(client_ip: &str) -> String {
    prefixed_key("ip:", client_ip)
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
