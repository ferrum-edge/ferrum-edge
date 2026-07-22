//! gRPC Method Router Plugin
//!
//! Adds gRPC method-aware proxying capabilities:
//! - Parses the gRPC path (`/package.Service/Method`) to extract service and method names
//! - Enforces access control and rate limits against the backend-effective method
//! - Populates `grpc_service`, `grpc_method`, and `grpc_full_method` metadata
//!   from that finalized method for downstream response phases

use async_trait::async_trait;
use serde_json::Value;
use std::collections::{HashMap, HashSet};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};
use tracing::{debug, warn};

use super::utils::rate_limit::{
    DynamicHttpRateLimitAlgorithm, DynamicRateLimitOp, RateLimitBackend, RateLimitOutcome,
    RateLimitWindowSpec,
};
use super::{
    GRPC_ONLY_PROTOCOLS, Plugin, PluginHttpClient, PluginResult, ProxyProtocol, RequestContext,
};

/// Maximum rate-limit state entries before triggering stale eviction.
const MAX_STATE_ENTRIES: usize = 100_000;
const EVICTION_CHECK_INTERVAL_REQUESTS: u64 = 1024;

/// A rate window spec parsed from config.
#[derive(Debug, Clone)]
struct RateSpec {
    max_requests: u64,
    op: DynamicRateLimitOp,
}

pub struct GrpcMethodRouter {
    allow_methods: Option<HashSet<String>>,
    deny_methods: HashSet<String>,
    method_rate_limits: HashMap<String, RateSpec>,
    limit_by: String,
    limiter: RateLimitBackend<String, DynamicHttpRateLimitAlgorithm>,
    request_counter: AtomicU64,
}

impl GrpcMethodRouter {
    pub fn new(config: &Value, http_client: PluginHttpClient) -> Result<Self, String> {
        let allow_methods = parse_optional_method_set(config, "allow_methods")?;
        let deny_methods = parse_optional_method_set(config, "deny_methods")?.unwrap_or_default();

        // limit_by must be a recognized policy — silently treating "user" as "ip"
        // would be a security misconfiguration footgun.
        let limit_by = match config.get("limit_by") {
            None | Some(Value::Null) => "ip".to_string(),
            Some(Value::String(s)) => {
                let lc = s.to_lowercase();
                if !matches!(lc.as_str(), "ip" | "consumer") {
                    return Err(format!(
                        "grpc_method_router: 'limit_by' must be one of 'ip' or 'consumer', got: {s:?}"
                    ));
                }
                lc
            }
            Some(other) => {
                return Err(format!(
                    "grpc_method_router: 'limit_by' must be a string, got: {other}"
                ));
            }
        };

        let mut method_rate_limits = HashMap::new();
        if let Some(value) = config.get("method_rate_limits")
            && !value.is_null()
        {
            let obj = value.as_object().ok_or_else(|| {
                format!("grpc_method_router: 'method_rate_limits' must be an object, got: {value}")
            })?;
            for (method, spec) in obj {
                let spec_obj = spec.as_object().ok_or_else(|| {
                    format!("grpc_method_router: method_rate_limits['{method}'] must be an object")
                })?;
                let max_requests = spec_obj
                    .get("max_requests")
                    .and_then(Value::as_u64)
                    .ok_or_else(|| {
                        format!(
                            "grpc_method_router: method_rate_limits['{method}']: 'max_requests' is required and must be a positive integer"
                        )
                    })?;
                let window_seconds = spec_obj
                    .get("window_seconds")
                    .and_then(Value::as_u64)
                    .ok_or_else(|| {
                        format!(
                            "grpc_method_router: method_rate_limits['{method}']: 'window_seconds' is required and must be a positive integer"
                        )
                    })?;
                if max_requests == 0 {
                    return Err(format!(
                        "grpc_method_router: method_rate_limits['{method}']: 'max_requests' must be greater than zero"
                    ));
                }
                if window_seconds == 0 {
                    return Err(format!(
                        "grpc_method_router: method_rate_limits['{method}']: 'window_seconds' must be greater than zero"
                    ));
                }
                let normalized = normalize_config_method_path(method, "method_rate_limits")?;
                let window = Duration::from_secs(window_seconds);
                if method_rate_limits
                    .insert(
                        normalized,
                        RateSpec {
                            max_requests,
                            op: DynamicRateLimitOp::new(vec![RateLimitWindowSpec {
                                limit: max_requests,
                                duration: window,
                            }]),
                        },
                    )
                    .is_some()
                {
                    return Err(format!(
                        "grpc_method_router: duplicate method_rate_limits entry after normalization: {method:?}"
                    ));
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
            limiter: RateLimitBackend::from_plugin_config(
                "grpc_method_router",
                config,
                &http_client,
                DynamicHttpRateLimitAlgorithm::new(),
            )?,
            request_counter: AtomicU64::new(0),
        })
    }

    /// Local/fallback DashMap shard count. Test-only; not a production API.
    #[cfg(test)]
    pub(crate) fn local_map_shard_amount(&self) -> usize {
        self.limiter.local_map_shard_amount()
    }

    /// Evict entries with no recent activity to bound memory.
    fn evict_stale_entries(&self) {
        let request = self.request_counter.fetch_add(1, Ordering::Relaxed);
        if !request.is_multiple_of(EVICTION_CHECK_INTERVAL_REQUESTS) {
            return;
        }
        if self.limiter.tracked_keys_count() > MAX_STATE_ENTRIES {
            self.limiter
                .enforce_capacity(MAX_STATE_ENTRIES, Instant::now());
        }
    }

    /// Check a rate limit by key, creating a bucket if needed.
    async fn check_rate(&self, key: &str, spec: &RateSpec) -> RateLimitOutcome {
        self.evict_stale_entries();
        self.limiter.check(key.to_string(), key, &spec.op).await
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
        let mut key =
            String::with_capacity("grpc_method::".len() + identity.len() + method_path.len());
        key.push_str("grpc_method:");
        key.push_str(identity);
        key.push(':');
        key.push_str(method_path);
        key
    }
}

fn parse_optional_method_set(config: &Value, key: &str) -> Result<Option<HashSet<String>>, String> {
    let Some(value) = config.get(key) else {
        return Ok(None);
    };
    if value.is_null() {
        return Ok(None);
    }

    let entries = value
        .as_array()
        .ok_or_else(|| format!("grpc_method_router: '{key}' must be an array, got: {value}"))?;
    let mut methods = HashSet::with_capacity(entries.len());
    for (idx, entry) in entries.iter().enumerate() {
        let method = entry.as_str().ok_or_else(|| {
            format!("grpc_method_router: '{key}[{idx}]' must be a string, got: {entry}")
        })?;
        let normalized = normalize_config_method_path(method, key)?;
        if !methods.insert(normalized.clone()) {
            return Err(format!(
                "grpc_method_router: duplicate method in '{key}' after normalization: {normalized:?}"
            ));
        }
    }
    Ok(Some(methods))
}

fn normalize_config_method_path(method: &str, field: &str) -> Result<String, String> {
    let trimmed = method.trim();
    if trimmed.is_empty() {
        return Err(format!(
            "grpc_method_router: '{field}' entries must not be empty"
        ));
    }
    let normalized = trimmed.strip_prefix('/').unwrap_or(trimmed);
    let Some((service, method_name)) = normalized.split_once('/') else {
        return Err(format!(
            "grpc_method_router: '{field}' entry must use 'package.Service/Method': {method:?}"
        ));
    };
    if service.is_empty() || method_name.is_empty() || method_name.contains('/') {
        return Err(format!(
            "grpc_method_router: invalid gRPC method path in '{field}': {method:?}"
        ));
    }
    if !is_valid_grpc_service(service) || !is_valid_grpc_identifier(method_name) {
        return Err(format!(
            "grpc_method_router: invalid gRPC method path in '{field}': {method:?}"
        ));
    }
    Ok(normalized.to_string())
}

fn is_valid_grpc_service(service: &str) -> bool {
    service
        .split('.')
        .all(|segment| !segment.is_empty() && is_valid_grpc_identifier(segment))
}

fn is_valid_grpc_identifier(value: &str) -> bool {
    let mut chars = value.chars();
    let Some(first) = chars.next() else {
        return false;
    };
    if !(first == '_' || first.is_ascii_alphabetic()) {
        return false;
    }
    chars.all(|ch| ch == '_' || ch.is_ascii_alphanumeric())
}

/// Parse a gRPC path into (service, method).
///
/// gRPC paths follow the format `/package.Service/Method`.
/// Returns `None` if the path doesn't match the expected format.
fn parse_grpc_path(path: &str) -> Option<(&str, &str)> {
    let path = path.strip_prefix('/')?;
    let (service, method) = path.split_once('/')?;
    if !is_valid_grpc_service(service) || !is_valid_grpc_identifier(method) {
        return None;
    }
    Some((service, method))
}

fn grpc_method_metadata(path: &str) -> Option<(String, String, String)> {
    let (service, method) = parse_grpc_path(path)?;
    let mut full_method = String::with_capacity(service.len() + 1 + method.len());
    full_method.push_str(service);
    full_method.push('/');
    full_method.push_str(method);
    Some((service.to_string(), method.to_string(), full_method))
}

/// Replace the provisional/client-path gRPC metadata as one request-local
/// operation. `RequestContext` is exclusively borrowed here, so downstream
/// phases observe either the refreshed method or no gRPC method fields when
/// the backend-effective path is invalid; stale client-path values cannot
/// survive a rewrite.
fn refresh_grpc_method_metadata(
    ctx: &mut RequestContext,
    metadata: Option<(String, String, String)>,
) {
    ctx.metadata.remove("grpc_service");
    ctx.metadata.remove("grpc_method");
    ctx.metadata.remove("grpc_full_method");

    if let Some((service, method, full_method)) = metadata {
        ctx.metadata.insert("grpc_service".to_string(), service);
        ctx.metadata.insert("grpc_method".to_string(), method);
        ctx.metadata
            .insert("grpc_full_method".to_string(), full_method);
    }
}

/// Returns a header map with `content-type: application/grpc`.
fn grpc_content_type_header() -> HashMap<String, String> {
    let mut h = HashMap::new();
    h.insert("content-type".to_string(), "application/grpc".to_string());
    h
}

fn grpc_json_error_body(message: String) -> String {
    serde_json::json!({ "error": message }).to_string()
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
        Some(self.limiter.tracked_keys_count())
    }

    fn warmup_hostnames(&self) -> Vec<String> {
        self.limiter.warmup_hostname().into_iter().collect()
    }

    async fn on_request_received(&self, ctx: &mut RequestContext) -> PluginResult {
        // Populate provisional metadata for early downstream consumers. The
        // authoritative method is refreshed and enforced only after routing,
        // rewrites, prefix stripping, and target selection are complete.
        let metadata = grpc_method_metadata(&ctx.path);
        let method_is_valid = metadata.is_some();
        refresh_grpc_method_metadata(ctx, metadata);
        if !method_is_valid {
            debug!(
                path = %ctx.path,
                plugin = "grpc_method_router",
                "Could not parse gRPC method path"
            );
        }
        PluginResult::Continue
    }

    fn requires_backend_path_resolution(&self) -> bool {
        true
    }

    async fn on_backend_path_resolved(
        &self,
        ctx: &mut RequestContext,
        backend_path: &str,
    ) -> PluginResult {
        let metadata = grpc_method_metadata(backend_path);
        refresh_grpc_method_metadata(ctx, metadata);
        let full_method = match ctx.metadata.get("grpc_full_method") {
            Some(method) => method.as_str(),
            None => {
                debug!(
                    path = %backend_path,
                    plugin = "grpc_method_router",
                    "Rejecting gRPC request with invalid backend-effective method path"
                );
                return PluginResult::Reject {
                    status_code: 403,
                    body: grpc_json_error_body(
                        "backend-effective gRPC method path could not be parsed".to_string(),
                    ),
                    headers: grpc_content_type_header(),
                };
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
                body: grpc_json_error_body(format!("gRPC method '{full_method}' is not permitted")),
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
                body: grpc_json_error_body(format!("gRPC method '{full_method}' is not permitted")),
                headers: grpc_content_type_header(),
            };
        }

        // Check per-method rate limits on the pinned selected method.
        if let Some(spec) = self.method_rate_limits.get(full_method) {
            let key = self.rate_key(ctx, full_method);
            let outcome = self.check_rate(&key, spec).await;
            if !outcome.allowed {
                warn!(
                    method = %full_method,
                    plugin = "grpc_method_router",
                    "gRPC method rate limit exceeded"
                );
                let remaining = outcome.remaining.unwrap_or(0);
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
                    body: grpc_json_error_body(format!(
                        "Rate limit exceeded for gRPC method '{full_method}'"
                    )),
                    headers,
                };
            }
        }

        PluginResult::Continue
    }
}
