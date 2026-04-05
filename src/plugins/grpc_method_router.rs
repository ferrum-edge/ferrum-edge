//! gRPC Method Router Plugin
//!
//! Adds gRPC method-aware proxying capabilities:
//! - Parses the gRPC path (`/package.Service/Method`) to extract service and method names
//! - Per-method access control (allow/deny lists)
//! - Per-method rate limiting with token bucket algorithm
//! - Populates `grpc_service`, `grpc_method`, and `grpc_full_method` metadata
//!   for downstream plugins (logging, rate limiting, tracing)

use async_trait::async_trait;
use dashmap::DashMap;
use serde_json::Value;
use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tracing::{debug, warn};

use super::{GRPC_ONLY_PROTOCOLS, Plugin, PluginResult, ProxyProtocol, RequestContext};

/// Maximum rate-limit state entries before triggering stale eviction.
const MAX_STATE_ENTRIES: usize = 100_000;

/// A rate window spec parsed from config.
#[derive(Debug, Clone)]
struct RateSpec {
    max_requests: u64,
    window: Duration,
}

/// Token bucket for per-method rate limiting.
#[derive(Debug)]
struct TokenBucket {
    tokens: f64,
    capacity: f64,
    refill_rate: f64,
    last_refill: Instant,
}

impl TokenBucket {
    fn new(limit: u64, window: Duration) -> Self {
        let capacity = limit as f64;
        let window_secs = window.as_secs_f64().max(0.001);
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

    fn has_recent_activity(&self, now: Instant) -> bool {
        let window_secs = self.capacity / self.refill_rate;
        now.duration_since(self.last_refill).as_secs_f64() < window_secs
    }
}

pub struct GrpcMethodRouter {
    allow_methods: Option<HashSet<String>>,
    deny_methods: HashSet<String>,
    method_rate_limits: HashMap<String, RateSpec>,
    limit_by: String,
    state: Arc<DashMap<String, TokenBucket>>,
}

impl GrpcMethodRouter {
    pub fn new(config: &Value) -> Result<Self, String> {
        // Normalize method paths: strip leading '/' for consistent matching.
        // Users can configure either "/pkg.Svc/Method" or "pkg.Svc/Method".
        let allow_methods = config["allow_methods"].as_array().map(|arr| {
            arr.iter()
                .filter_map(|v| {
                    v.as_str()
                        .map(|s| s.strip_prefix('/').unwrap_or(s).to_string())
                })
                .collect::<HashSet<_>>()
        });

        let deny_methods = config["deny_methods"]
            .as_array()
            .map(|arr| {
                arr.iter()
                    .filter_map(|v| {
                        v.as_str()
                            .map(|s| s.strip_prefix('/').unwrap_or(s).to_string())
                    })
                    .collect::<HashSet<_>>()
            })
            .unwrap_or_default();

        let limit_by = config["limit_by"].as_str().unwrap_or("ip").to_string();

        let mut method_rate_limits = HashMap::new();
        if let Some(obj) = config["method_rate_limits"].as_object() {
            for (method, spec) in obj {
                if let (Some(max_requests), Some(window_seconds)) = (
                    spec["max_requests"].as_u64(),
                    spec["window_seconds"].as_u64(),
                ) {
                    let normalized = method.strip_prefix('/').unwrap_or(method).to_string();
                    method_rate_limits.insert(
                        normalized,
                        RateSpec {
                            max_requests,
                            window: Duration::from_secs(window_seconds.max(1)),
                        },
                    );
                }
            }
        }

        let has_any_config =
            allow_methods.is_some() || !deny_methods.is_empty() || !method_rate_limits.is_empty();

        if !has_any_config {
            return Err(
                "grpc_method_router: no rules configured — set 'allow_methods', 'deny_methods', \
                 or 'method_rate_limits'"
                    .to_string(),
            );
        }

        Ok(Self {
            allow_methods,
            deny_methods,
            method_rate_limits,
            limit_by,
            state: Arc::new(DashMap::new()),
        })
    }

    /// Evict entries with no recent activity to bound memory.
    fn evict_stale_entries(&self) {
        if self.state.len() <= MAX_STATE_ENTRIES {
            return;
        }
        let now = Instant::now();
        self.state
            .retain(|_, bucket| bucket.has_recent_activity(now));
    }

    /// Check a rate limit by key, creating a bucket if needed.
    fn check_rate(&self, key: &str, spec: &RateSpec) -> bool {
        self.evict_stale_entries();
        let mut entry = self
            .state
            .entry(key.to_string())
            .or_insert_with(|| TokenBucket::new(spec.max_requests, spec.window));
        entry.check_and_consume()
    }

    /// Get remaining count for a key (for metadata/headers).
    fn get_remaining(&self, key: &str) -> Option<u64> {
        self.state.get(key).map(|bucket| bucket.remaining())
    }

    /// Build the rate limit key based on `limit_by` config.
    ///
    /// When `limit_by: "consumer"`, uses the identified consumer's username,
    /// falling back to `authenticated_identity` (for external auth like JWKS
    /// where no gateway Consumer exists), then to client IP.
    fn rate_key(&self, ctx: &RequestContext, method_path: &str) -> String {
        let identity = if self.limit_by == "consumer" {
            ctx.effective_identity().unwrap_or(ctx.client_ip.as_str())
        } else {
            ctx.client_ip.as_str()
        };
        format!("grpc_method:{}:{}", identity, method_path)
    }
}

/// Parse a gRPC path into (service, method).
///
/// gRPC paths follow the format `/package.Service/Method`.
/// Returns `None` if the path doesn't match the expected format.
fn parse_grpc_path(path: &str) -> Option<(&str, &str)> {
    let path = path.strip_prefix('/')?;
    let (service, method) = path.split_once('/')?;
    if service.is_empty() || method.is_empty() {
        return None;
    }
    // Method should not contain additional slashes
    if method.contains('/') {
        return None;
    }
    Some((service, method))
}

/// Returns a header map with `content-type: application/grpc`.
fn grpc_content_type_header() -> HashMap<String, String> {
    let mut h = HashMap::new();
    h.insert("content-type".to_string(), "application/grpc".to_string());
    h
}

/// Escape special characters for safe JSON string interpolation.
fn escape_json_string(s: &str) -> String {
    s.replace('\\', "\\\\").replace('"', "\\\"")
}

#[async_trait]
impl Plugin for GrpcMethodRouter {
    fn name(&self) -> &str {
        "grpc_method_router"
    }

    fn priority(&self) -> u16 {
        super::priority::GRPC_METHOD_ROUTER
    }

    fn supported_protocols(&self) -> &'static [ProxyProtocol] {
        GRPC_ONLY_PROTOCOLS
    }

    fn tracked_keys_count(&self) -> Option<usize> {
        Some(self.state.len())
    }

    async fn on_request_received(&self, ctx: &mut RequestContext) -> PluginResult {
        // Parse the gRPC path and populate metadata
        if let Some((service, method)) = parse_grpc_path(&ctx.path) {
            let full_method = format!("{}/{}", service, method);
            ctx.metadata
                .insert("grpc_service".to_string(), service.to_string());
            ctx.metadata
                .insert("grpc_method".to_string(), method.to_string());
            ctx.metadata
                .insert("grpc_full_method".to_string(), full_method);
        } else {
            debug!(
                path = %ctx.path,
                plugin = "grpc_method_router",
                "Could not parse gRPC method path"
            );
        }
        PluginResult::Continue
    }

    async fn before_proxy(
        &self,
        ctx: &mut RequestContext,
        _headers: &mut HashMap<String, String>,
    ) -> PluginResult {
        // Borrow as &str — avoids a String clone on every gRPC request.
        // HashSet::contains and HashMap::get both accept &str via Borrow<str>.
        let full_method: &str = match ctx.metadata.get("grpc_full_method") {
            Some(m) => m.as_str(),
            None => {
                // Path wasn't parseable as gRPC — skip enforcement
                return PluginResult::Continue;
            }
        };

        // Check deny list first (deny wins over allow)
        if self.deny_methods.contains(full_method) {
            debug!(
                method = %full_method,
                plugin = "grpc_method_router",
                "gRPC method denied"
            );
            return PluginResult::Reject {
                status_code: 403,
                body: format!(
                    r#"{{"error":"gRPC method '{}' is not permitted"}}"#,
                    escape_json_string(full_method)
                ),
                headers: grpc_content_type_header(),
            };
        }

        // Check allow list (if configured, only listed methods pass)
        if let Some(ref allow_methods) = self.allow_methods
            && !allow_methods.contains(full_method)
        {
            debug!(
                method = %full_method,
                plugin = "grpc_method_router",
                "gRPC method not in allow list"
            );
            return PluginResult::Reject {
                status_code: 403,
                body: format!(
                    r#"{{"error":"gRPC method '{}' is not permitted"}}"#,
                    escape_json_string(full_method)
                ),
                headers: grpc_content_type_header(),
            };
        }

        // Check per-method rate limits
        if let Some(spec) = self.method_rate_limits.get(full_method) {
            let key = self.rate_key(ctx, full_method);
            if !self.check_rate(&key, spec) {
                warn!(
                    method = %full_method,
                    plugin = "grpc_method_router",
                    "gRPC method rate limit exceeded"
                );
                let remaining = self.get_remaining(&key).unwrap_or(0);
                let mut headers = grpc_content_type_header();
                headers.insert(
                    "x-grpc-ratelimit-limit".to_string(),
                    spec.max_requests.to_string(),
                );
                headers.insert(
                    "x-grpc-ratelimit-remaining".to_string(),
                    remaining.to_string(),
                );
                headers.insert(
                    "x-grpc-ratelimit-method".to_string(),
                    full_method.to_string(),
                );
                return PluginResult::Reject {
                    status_code: 429,
                    body: format!(
                        r#"{{"error":"Rate limit exceeded for gRPC method '{}'"}}"#,
                        escape_json_string(full_method)
                    ),
                    headers,
                };
            }
        }

        PluginResult::Continue
    }
}
