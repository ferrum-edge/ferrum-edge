//! gRPC Method Router Plugin
//!
//! Adds gRPC method-aware proxying capabilities:
//! - Parses the gRPC path (`/package.Service/Method`) to extract service and method names
//! - Enforces access control and rate limits against the backend-effective method
//! - Populates `grpc_service`, `grpc_method`, and `grpc_full_method` metadata
//!   from that finalized method for downstream response phases

use crate::plugins::utils::log_sampling::warn_sampled;

use async_trait::async_trait;
use serde_json::Value;
use std::collections::{HashMap, HashSet};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};
use tracing::debug;

use super::utils::rate_limit::{
    DynamicHttpRateLimitAlgorithm, DynamicRateLimitOp, ENFORCEMENT_UNAVAILABLE_MESSAGE,
    ENFORCEMENT_UNAVAILABLE_STATUS, LocalStateSemantics, RATE_LIMIT_REDIS_CONFIG_KEYS,
    RateLimitBackend, RateLimitOutcome, RateLimitWindowSpec, STANDALONE_RATE_LIMIT_CONFIG_ID,
    apply_rate_limit_cleanup, debug_assert_closed_root_keys, debug_assert_rate_limit_redis_keys,
    validate_max_requests, validate_window_seconds,
};
use super::{
    GRPC_ONLY_PROTOCOLS, Plugin, PluginHttpClient, PluginResult, ProxyProtocol, RequestContext,
};
use crate::util::unknown_keys::reject_unknown_keys;

/// Maximum rate-limit state entries before triggering stale eviction.
const MAX_STATE_ENTRIES: usize = 100_000;
const EVICTION_CHECK_INTERVAL_REQUESTS: u64 = 1024;
/// Bounds below-cap full-map scans under high RPS. Sampled over-cap
/// reclaim skips this cooldown so a sampled observation of pressure can
/// drop idle keys without waiting for the next cool-down window. Live
/// budgets are never force-evicted.
const EVICTION_COOLDOWN_SECS: u64 = 1;
const CAPACITY_REJECT_BODY: &str = r#"{"error":"Rate limit state capacity exceeded"}"#;

/// `grpc_method_router`-specific top-level config keys (excludes Redis fields).
const GRPC_METHOD_ROUTER_POLICY_CONFIG_KEYS: &[&str] = &[
    "allow_methods",
    "deny_methods",
    "method_rate_limits",
    "limit_by",
];

/// Closed top-level key set for `grpc_method_router` plugin config.
///
/// Must stay aligned with OpenAPI `GrpcMethodRouterConfig`,
/// [`RATE_LIMIT_REDIS_CONFIG_KEYS`], and `docs/plugins.md`. Unknown root keys fail
/// closed: a valid method rule previously masked a misspelled `sync_mdoe`,
/// `limit_byy`, or `redis_key_prefx`, so the plugin loaded with local, IP-keyed,
/// or shared-prefix enforcement instead of the intended policy.
pub const GRPC_METHOD_ROUTER_CONFIG_KEYS: &[&str] = &[
    "allow_methods",
    "deny_methods",
    "method_rate_limits",
    "limit_by",
    // Shared Redis sync (see RATE_LIMIT_REDIS_CONFIG_KEYS)
    "sync_mode",
    "redis_url",
    "redis_tls",
    "redis_key_prefix",
    "redis_pool_size",
    "redis_connect_timeout_seconds",
    "redis_health_check_interval_seconds",
    "redis_username",
    "redis_password",
    "redis_failure_policy",
];

/// Closed key set for one `method_rate_limits` entry.
const RATE_SPEC_KEYS: &[&str] = &["max_requests", "window_seconds"];

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
    epoch_base: Instant,
    last_periodic_sweep_secs: AtomicU64,
}

impl GrpcMethodRouter {
    #[allow(dead_code)] // direct/test construction; production factory supplies the config id
    pub fn new(config: &Value, http_client: PluginHttpClient) -> Result<Self, String> {
        Self::new_with_config_id(config, http_client, STANDALONE_RATE_LIMIT_CONFIG_ID)
    }

    /// Construct with the stable plugin-config resource id that isolates this
    /// policy's default Redis counters from sibling `grpc_method_router`
    /// instances in the same namespace. See
    /// [`super::utils::rate_limit::RedisLimiter::new_with_config_id`].
    pub fn new_with_config_id(
        config: &Value,
        http_client: PluginHttpClient,
        config_id: &str,
    ) -> Result<Self, String> {
        Self::from_parts(config, http_client, None, config_id)
    }

    /// Construct with local enforcement state shared across compatible
    /// plugin-cache generations for the stable `(namespace, plugin kind,
    /// plugin-config id)` policy identity. See
    /// [`super::utils::rate_limit::RateLimitBackend::from_plugin_config_with_policy_identity`].
    pub fn new_with_policy_identity(
        config: &Value,
        http_client: PluginHttpClient,
        namespace: &str,
        config_id: &str,
    ) -> Result<Self, String> {
        Self::from_parts(config, http_client, Some(namespace), config_id)
    }

    fn from_parts(
        config: &Value,
        http_client: PluginHttpClient,
        namespace: Option<&str>,
        config_id: &str,
    ) -> Result<Self, String> {
        let object = config.as_object().ok_or_else(|| {
            format!("grpc_method_router: config must be an object, got: {config}")
        })?;
        // Keeps the documented key groups aligned with the closed root
        // allowlist used for admission and OpenAPI parity.
        debug_assert_rate_limit_redis_keys();
        debug_assert_closed_root_keys(
            GRPC_METHOD_ROUTER_CONFIG_KEYS,
            GRPC_METHOD_ROUTER_POLICY_CONFIG_KEYS,
            RATE_LIMIT_REDIS_CONFIG_KEYS,
        );
        reject_unknown_keys(
            object,
            "config",
            GRPC_METHOD_ROUTER_CONFIG_KEYS,
            "grpc_method_router: ",
        )?;

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
                let label = format!("grpc_method_router: method_rate_limits['{method}']");
                reject_unknown_keys(
                    spec_obj,
                    &format!("config.method_rate_limits[{method}]"),
                    RATE_SPEC_KEYS,
                    "grpc_method_router: ",
                )?;
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
                let max_requests = validate_max_requests(&label, "max_requests", max_requests)?;
                let window_seconds =
                    validate_window_seconds(&label, "window_seconds", window_seconds)?;
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

        // Effective enforcement semantics, not raw syntax: the lower-cased limit
        // dimension and the path-normalized per-method budgets, so a spelling
        // the parser normalizes keeps one budget. `allow_methods` /
        // `deny_methods` are stateless admission lists that never consult a
        // counter; the shared Redis posture is added by the backend.
        let mut semantics = LocalStateSemantics::new();
        semantics.text("limit_by", &limit_by);
        semantics.window_map(
            "method_rate_limits",
            method_rate_limits
                .iter()
                .map(|(method, spec)| (method.as_str(), spec.op.specs())),
        );

        Ok(Self {
            allow_methods,
            deny_methods,
            method_rate_limits,
            limit_by,
            limiter: RateLimitBackend::from_plugin_config_with_policy_identity(
                "grpc_method_router",
                namespace,
                config_id,
                config,
                &http_client,
                DynamicHttpRateLimitAlgorithm::new(),
                &semantics,
            )?,
            request_counter: AtomicU64::new(0),
            epoch_base: Instant::now(),
            last_periodic_sweep_secs: AtomicU64::new(0),
        })
    }

    /// Whether this instance enforces on the same live local state as `other`.
    ///
    /// A compatible reload generation for one policy identity must share; an
    /// unrelated policy, tenant, plugin kind, or semantically changed policy
    /// must not. Not a production API.
    #[allow(dead_code)] // used only by external tests; dead in binary test target
    pub(crate) fn shares_local_state_with(&self, other: &Self) -> bool {
        self.limiter.shares_local_state_with(&other.limiter)
    }

    /// Local/fallback DashMap shard count. Test-only; not a production API.
    #[cfg(test)]
    pub(crate) fn local_map_shard_amount(&self) -> usize {
        self.limiter.local_map_shard_amount()
    }

    /// Effective `redis_failure_policy` for advisory coverage: `None` for a
    /// local-only config, `FailClosed` unless the operator opted into
    /// `local_fallback`. Not a production API.
    #[allow(dead_code)] // used only by external tests; dead in binary test target
    pub(crate) fn redis_failure_policy_for_test(
        &self,
    ) -> Option<super::utils::rate_limit::RedisFailurePolicy> {
        self.limiter.redis_failure_policy()
    }

    /// Effective Redis key prefix for policy-isolation coverage. Not a
    /// production API.
    #[allow(dead_code)] // used only by external tests; dead in binary test target
    pub(crate) fn redis_key_prefix_for_test(&self) -> Option<String> {
        self.limiter.redis_key_prefix().map(str::to_string)
    }

    /// Controllable-time seed for external cleanup tests. Not a production API.
    #[allow(dead_code)] // used only by external tests; dead in binary test target
    pub(crate) fn seed_key_at_for_test(&self, key: String, now: Instant) {
        let op = DynamicRateLimitOp::new(vec![RateLimitWindowSpec {
            limit: 100,
            duration: Duration::from_secs(1),
        }]);
        let _ = self.limiter.check_local_at(key, &op, now);
    }

    /// Attempt to seed one local/fallback key through the production atomic
    /// capacity gate. Returns false only for a previously unseen key at cap.
    #[allow(dead_code)] // used only by external tests; dead in binary test target
    pub(crate) fn seed_key_at_with_cap_for_test(
        &self,
        key: String,
        now: Instant,
        max_entries: usize,
    ) -> bool {
        let op = DynamicRateLimitOp::new(vec![RateLimitWindowSpec {
            limit: 100,
            duration: Duration::from_secs(1),
        }]);
        self.limiter
            .check_local_at_with_capacity(key, &op, now, max_entries)
            .is_some()
    }

    /// Arm the sampled below-cap gate without spinning 1024 requests. Test-only.
    #[allow(dead_code)] // used only by external tests; dead in binary test target
    pub(crate) fn arm_periodic_eviction_for_test(&self) {
        self.request_counter
            .store(EVICTION_CHECK_INTERVAL_REQUESTS, Ordering::Relaxed);
        self.last_periodic_sweep_secs.store(0, Ordering::Relaxed);
    }

    /// Invoke the production cleanup wrapper at `now`. Test-only.
    #[allow(dead_code)] // used only by external tests; dead in binary test target
    pub(crate) fn evict_stale_entries_at_for_test(&self, now: Instant) {
        self.evict_stale_entries_at(now);
    }

    /// Exercise the shared prune/enforce branch with a testable cap. Test-only.
    #[allow(dead_code)] // used only by external tests; dead in binary test target
    pub(crate) fn apply_cleanup_branch_for_test(
        &self,
        now: Instant,
        over_capacity: bool,
        max_entries: usize,
    ) {
        apply_rate_limit_cleanup(&self.limiter, max_entries, now, over_capacity);
    }

    #[allow(dead_code)] // used only by external tests; dead in binary test target
    pub(crate) fn contains_key_for_test(&self, key: &str) -> bool {
        self.limiter.contains_local_key(&key.to_string())
    }

    /// Evict entries with no recent activity to bound memory.
    fn evict_stale_entries(&self) {
        self.evict_stale_entries_at(Instant::now());
    }

    fn evict_stale_entries_at(&self, now: Instant) {
        // Sample every 1024 requests before any tracked_keys_count /
        // cleanup work so the hot path avoids capacity bookkeeping on every
        // request. Entry counts are atomic (not DashMap::len()).
        let request = self.request_counter.fetch_add(1, Ordering::Relaxed);
        if !request.is_multiple_of(EVICTION_CHECK_INTERVAL_REQUESTS) {
            return;
        }

        let len = self.limiter.tracked_keys_count();
        if len == 0 {
            return;
        }
        let now_secs = now.saturating_duration_since(self.epoch_base).as_secs();

        // Sampled over-cap observation reclaims idle keys after prune. Live
        // budgets are never force-evicted; hard cardinality is enforced by
        // atomic admission reservation. The below-cap cooldown must not
        // suppress this branch once pressure is seen on a sampled pass.
        if len > MAX_STATE_ENTRIES {
            apply_rate_limit_cleanup(&self.limiter, MAX_STATE_ENTRIES, now, true);
            self.last_periodic_sweep_secs
                .store(now_secs, Ordering::Release);
            return;
        }

        // At/below the hard cap: cooldown-gate to at most one full DashMap
        // retain per second under high RPS.
        let last_sweep = self.last_periodic_sweep_secs.load(Ordering::Relaxed);
        if now_secs.saturating_sub(last_sweep) < EVICTION_COOLDOWN_SECS {
            return;
        }
        if self
            .last_periodic_sweep_secs
            .compare_exchange(last_sweep, now_secs, Ordering::AcqRel, Ordering::Relaxed)
            .is_err()
        {
            return;
        }

        apply_rate_limit_cleanup(&self.limiter, MAX_STATE_ENTRIES, now, false);
    }

    /// Check a rate limit by key, creating a bucket if needed.
    ///
    /// Returns `None` when a previously unseen local/fallback key is denied at
    /// the hard cardinality cap (Redis-healthy admission is unaffected).
    async fn check_rate(&self, key: &str, spec: &RateSpec) -> Option<RateLimitOutcome> {
        self.evict_stale_entries();
        self.limiter
            .check_with_redis_key_and_local_capacity(
                key.to_string(),
                || key.to_string(),
                &spec.op,
                MAX_STATE_ENTRIES,
            )
            .await
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
            match self.check_rate(&key, spec).await {
                None => {
                    super::prometheus_metrics::global_registry().record_rate_limit_exceeded();
                    return PluginResult::Reject {
                        status_code: 429,
                        body: CAPACITY_REJECT_BODY.to_string(),
                        headers: grpc_content_type_header(),
                    };
                }
                Some(outcome) if !outcome.allowed => {
                    // Centralized enforcement could not be consulted under
                    // `redis_failure_policy: "fail_closed"`. Refuse without
                    // advertising a budget this gateway is not enforcing; the
                    // gRPC status derives from the HTTP status, so this maps to
                    // UNAVAILABLE rather than RESOURCE_EXHAUSTED. The shared
                    // backend owns the once-per-outage warning.
                    if outcome.enforcement_unavailable {
                        return PluginResult::Reject {
                            status_code: ENFORCEMENT_UNAVAILABLE_STATUS,
                            body: grpc_json_error_body(ENFORCEMENT_UNAVAILABLE_MESSAGE.to_string()),
                            headers: grpc_content_type_header(),
                        };
                    }
                    warn_sampled!(
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
                Some(_) => {}
            }
        }

        PluginResult::Continue
    }
}
