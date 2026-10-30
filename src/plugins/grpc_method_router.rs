//! gRPC Method Router Plugin
//!
//! Adds gRPC method-aware proxying capabilities:
//! - Parses the gRPC path (`/package.Service/Method`) to extract service and method names
//! - Enforces access control and rate limits against the backend-effective method
//! - Matches exact `package.Service/Method` rules and service-level
//!   `package.Service/*` rules; rate limits fall back to an optional
//!   `default_rate_limit` (exact beats service, service beats default)
//! - Populates `grpc_service`, `grpc_method`, and `grpc_full_method` metadata
//!   from that finalized method for downstream response phases

use crate::plugins::utils::log_sampling::warn_sampled;

use async_trait::async_trait;
use serde_json::Value;
use std::borrow::Cow;
use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};
use tracing::debug;

use super::prometheus_metrics::{MetricsRegistry, global_registry};
use super::utils::rate_limit::{
    DynamicHttpRateLimitAlgorithm, DynamicRateLimitOp, ENFORCEMENT_UNAVAILABLE_MESSAGE,
    ENFORCEMENT_UNAVAILABLE_STATUS, LocalStateSemantics, RATE_LIMIT_REDIS_CONFIG_KEYS,
    RateLimitBackend, RateLimitOutcome, RateLimitWindowSpec, STANDALONE_RATE_LIMIT_CONFIG_ID,
    apply_rate_limit_cleanup, debug_assert_closed_root_keys, debug_assert_rate_limit_redis_keys,
    validate_max_requests, validate_window_seconds,
};
use super::{
    GRPC_ONLY_PROTOCOLS, MetadataMap, Plugin, PluginHttpClient, PluginResult, ProxyProtocol,
    RequestContext,
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
/// Method segment that turns a configured rule into a service-level rule.
const SERVICE_WILDCARD_METHOD: &str = "*";
/// Rate-key rule component of `default_rate_limit`. Never collides with an
/// exact (`svc/Method`) or service-level (`svc/*`) rule, which both carry `/`.
const DEFAULT_RATE_RULE: &str = "*";

/// `grpc_method_router`-specific top-level config keys (excludes Redis fields).
const GRPC_METHOD_ROUTER_POLICY_CONFIG_KEYS: &[&str] = &[
    "allow_methods",
    "deny_methods",
    "method_rate_limits",
    "default_rate_limit",
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
    "default_rate_limit",
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

/// Closed key set for one `method_rate_limits` entry and `default_rate_limit`.
const RATE_SPEC_KEYS: &[&str] = &["max_requests", "window_seconds"];

/// A rate window spec parsed from config.
#[derive(Debug, Clone)]
struct RateSpec {
    max_requests: u64,
    op: DynamicRateLimitOp,
    /// Rule component of the rate key: the exact `svc/Method` for an exact
    /// rule, `svc/*` for a service-level rule, `*` for `default_rate_limit`.
    /// Service-level and default budgets are therefore pooled per caller
    /// across every method they cover, and request-chosen method names can
    /// never mint new counter keys.
    rule: String,
}

impl RateSpec {
    fn new(max_requests: u64, window: Duration, rule: String) -> Self {
        Self {
            max_requests,
            op: DynamicRateLimitOp::new(vec![RateLimitWindowSpec {
                limit: max_requests,
                duration: window,
            }]),
            rule,
        }
    }
}

/// One configured allow or deny list: exact methods plus service-level
/// (`package.Service/*`) rules.
#[derive(Debug, Default)]
struct MethodSet {
    /// Exact `package.Service/Method` entries, without the leading slash.
    methods: HashSet<String>,
    /// Bare service names from `package.Service/*` entries.
    services: HashSet<String>,
}

impl MethodSet {
    fn is_empty(&self) -> bool {
        self.methods.is_empty() && self.services.is_empty()
    }

    fn matches(&self, full_method: &str, service: &str) -> bool {
        self.methods.contains(full_method)
            || (!self.services.is_empty() && self.services.contains(service))
    }
}

/// One normalized configured method rule.
enum MethodPattern {
    /// `package.Service/Method`, stored without the leading slash.
    Exact(String),
    /// `package.Service/*`, stored as the bare service name.
    Service(String),
}

pub struct GrpcMethodRouter {
    allow_methods: Option<MethodSet>,
    deny_methods: MethodSet,
    /// Exact-method rate rules keyed by `package.Service/Method`.
    method_rate_limits: HashMap<String, RateSpec>,
    /// Service-level rate rules keyed by bare service name.
    service_rate_limits: HashMap<String, RateSpec>,
    /// Rate rule for methods no exact or service-level rule covers.
    default_rate_limit: Option<RateSpec>,
    limit_by: String,
    limiter: RateLimitBackend<String, DynamicHttpRateLimitAlgorithm>,
    metrics: Arc<MetricsRegistry>,
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
            format!(
                "grpc_method_router: config must be an object, got: {config:?}",
                config = config.to_string()
            )
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
            "grpc_method_router: `config`: ",
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
                        "grpc_method_router: `limit_by` must be one of `ip` or `consumer`, got: {s:?}"
                    ));
                }
                lc
            }
            Some(other) => {
                return Err(format!(
                    "grpc_method_router: `limit_by` must be a string, got: {other:?}",
                    other = other.to_string()
                ));
            }
        };

        let mut method_rate_limits = HashMap::new();
        let mut service_rate_limits = HashMap::new();
        if let Some(value) = config.get("method_rate_limits")
            && !value.is_null()
        {
            let obj = value.as_object().ok_or_else(|| {
                format!(
                    "grpc_method_router: `method_rate_limits` must be an object, got: {value:?}",
                    value = value.to_string()
                )
            })?;
            for (method, spec) in obj {
                // Bounds are validated before the key is normalized, so a
                // hostile key still reaches the shared validators.
                let (max_requests, window) = parse_rate_window(
                    spec,
                    &format!("`method_rate_limits` entry {method:?}"),
                    "`method_rate_limits`",
                    &format!("config.method_rate_limits[{method}]"),
                )?;
                let duplicate = match normalize_config_method_pattern(method, "method_rate_limits")?
                {
                    MethodPattern::Exact(full_method) => {
                        let rate = RateSpec::new(max_requests, window, full_method.clone());
                        method_rate_limits.insert(full_method, rate).is_some()
                    }
                    MethodPattern::Service(service) => {
                        let rate =
                            RateSpec::new(max_requests, window, service_rule_label(&service));
                        service_rate_limits.insert(service, rate).is_some()
                    }
                };
                if duplicate {
                    return Err(format!(
                        "grpc_method_router: duplicate `method_rate_limits` entry after normalization: {method:?}"
                    ));
                }
            }
        }

        let default_rate_limit = match config.get("default_rate_limit") {
            None | Some(Value::Null) => None,
            Some(value) => {
                let (max_requests, window) = parse_rate_window(
                    value,
                    "`default_rate_limit`",
                    "`default_rate_limit`",
                    "config.default_rate_limit",
                )?;
                Some(RateSpec::new(
                    max_requests,
                    window,
                    DEFAULT_RATE_RULE.to_string(),
                ))
            }
        };

        let has_any_config = allow_methods.is_some()
            || !deny_methods.is_empty()
            || !method_rate_limits.is_empty()
            || !service_rate_limits.is_empty()
            || default_rate_limit.is_some();

        if !has_any_config {
            return Err(
                "grpc_method_router: no rules configured — set `allow_methods`, `deny_methods`, \
                 `method_rate_limits`, or `default_rate_limit`"
                    .to_string(),
            );
        }

        // Effective enforcement semantics, not raw syntax: the lower-cased limit
        // dimension and the path-normalized per-method budgets, so a spelling
        // the parser normalizes keeps one budget. Exact and service-level
        // rules share one map keyed by their rule label (`svc/Method` vs
        // `svc/*`, never equal). `default_rate_limit` is recorded only when
        // set, so omitting it (or `null`) keeps the pre-existing fingerprint.
        // `allow_methods` / `deny_methods` are stateless admission lists that
        // never consult a counter; the shared Redis posture is added by the
        // backend.
        let mut semantics = LocalStateSemantics::new();
        semantics.text("limit_by", &limit_by);
        semantics.window_map(
            "method_rate_limits",
            method_rate_limits
                .values()
                .chain(service_rate_limits.values())
                .map(|spec| (spec.rule.as_str(), spec.op.specs())),
        );
        if let Some(spec) = &default_rate_limit {
            semantics.windows("default_rate_limit", spec.op.specs());
        }

        Ok(Self {
            allow_methods,
            deny_methods,
            method_rate_limits,
            service_rate_limits,
            default_rate_limit,
            limit_by,
            limiter: RateLimitBackend::from_plugin_config_with_policy_identity(
                "grpc_method_router",
                namespace,
                config_id,
                config,
                &http_client,
                DynamicHttpRateLimitAlgorithm::new(),
                &semantics,
            )
            .map_err(|error| format!("grpc_method_router: {error}"))?,
            metrics: global_registry(),
            request_counter: AtomicU64::new(0),
            epoch_base: Instant::now(),
            last_periodic_sweep_secs: AtomicU64::new(0),
        })
    }

    /// Give external metric tests their own registry instead of racing other
    /// plugins' process-wide counter updates. Production uses the global registry.
    #[allow(dead_code)] // used only by external tests; dead in binary test target
    pub(crate) fn with_metrics_registry_for_test(mut self, registry: Arc<MetricsRegistry>) -> Self {
        self.metrics = registry;
        self
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

    /// Whether this policy's centralized client demands the Redis server clock
    /// (`TIME`). `None` for a local-only config. Not a production API.
    ///
    /// Only the request-quota ladder selects sub-buckets on the server's clock,
    /// so this is what proves which of the six Redis-backed rate-limit roots
    /// forces an operator's ACL to grant `+time`.
    #[allow(dead_code)] // used only by external tests; dead in binary test target
    pub(crate) fn redis_requires_server_clock_for_test(&self) -> Option<bool> {
        self.limiter
            .redis_client_arc_for_test()
            .map(|client| client.requires_server_clock_for_test())
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

    /// The most specific rate rule covering a method: exact, then
    /// service-level, then `default_rate_limit`. At most one rule is charged.
    fn rate_spec_for(&self, full_method: &str, service: &str) -> Option<&RateSpec> {
        if let Some(spec) = self.method_rate_limits.get(full_method) {
            return Some(spec);
        }
        if !self.service_rate_limits.is_empty()
            && let Some(spec) = self.service_rate_limits.get(service)
        {
            return Some(spec);
        }
        self.default_rate_limit.as_ref()
    }

    /// Build the rate limit key based on `limit_by` config.
    ///
    /// When `limit_by: "consumer"`, uses the identified consumer's username,
    /// falling back to `authenticated_identity` (for external auth like JWKS
    /// where no gateway Consumer exists), then to client IP.
    ///
    /// The identity is tagged `consumer:` or `ip:` (as in `rate_limiting`) so an
    /// identity string that equals an IP never shares a budget with the
    /// unauthenticated caller at that IP.
    ///
    /// `rule` is the matched rule's [`RateSpec::rule`], so an exact rule keeps
    /// its per-method key and service/default rules pool per caller.
    fn rate_key(&self, ctx: &RequestContext, rule: &str) -> String {
        let (kind, identity) = match (self.limit_by == "consumer")
            .then(|| ctx.effective_identity())
            .flatten()
        {
            Some(identity) => ("consumer:", Cow::Borrowed(identity)),
            None => (
                "ip:",
                Cow::Owned(
                    crate::util::client_identity::rate_limit_client_ip_string(&ctx.client_ip, 64)
                        .unwrap_or_else(|| ctx.client_ip.clone()),
                ),
            ),
        };
        let mut key =
            String::with_capacity("grpc_method::".len() + kind.len() + identity.len() + rule.len());
        key.push_str("grpc_method:");
        key.push_str(kind);
        key.push_str(&identity);
        key.push(':');
        key.push_str(rule);
        key
    }
}

fn parse_optional_method_set(config: &Value, key: &str) -> Result<Option<MethodSet>, String> {
    let Some(value) = config.get(key) else {
        return Ok(None);
    };
    if value.is_null() {
        return Ok(None);
    }

    let entries = value.as_array().ok_or_else(|| {
        format!(
            "grpc_method_router: `{key}` must be an array, got: {value:?}",
            value = value.to_string()
        )
    })?;
    let mut set = MethodSet::default();
    for (idx, entry) in entries.iter().enumerate() {
        let method = entry.as_str().ok_or_else(|| {
            format!(
                "grpc_method_router: `{key}[{idx}]` must be a string, got: {entry:?}",
                entry = entry.to_string()
            )
        })?;
        let duplicate = match normalize_config_method_pattern(method, key)? {
            MethodPattern::Exact(full_method) => {
                if set.methods.contains(&full_method) {
                    Some(full_method)
                } else {
                    set.methods.insert(full_method);
                    None
                }
            }
            MethodPattern::Service(service) => {
                if set.services.contains(&service) {
                    Some(service_rule_label(&service))
                } else {
                    set.services.insert(service);
                    None
                }
            }
        };
        if let Some(normalized) = duplicate {
            return Err(format!(
                "grpc_method_router: duplicate method in `{key}` after normalization: {normalized:?}"
            ));
        }
    }
    Ok(Some(set))
}

/// Parse one closed `{max_requests, window_seconds}` spec.
///
/// `subject` names the entry in diagnostics (Debug-escaped by the shared
/// validators), `field` is the schema-authored config key, and `path` is the
/// unknown-key location.
fn parse_rate_window(
    spec: &Value,
    subject: &str,
    field: &str,
    path: &str,
) -> Result<(u64, Duration), String> {
    let spec_obj = spec
        .as_object()
        .ok_or_else(|| format!("grpc_method_router: {subject} must be an object"))?;
    let label = format!("grpc_method_router: {subject}");
    reject_unknown_keys(spec_obj, path, RATE_SPEC_KEYS, "grpc_method_router: ")
        .map_err(|error| format!("{field}: {error}"))?;
    let max_requests = spec_obj
        .get("max_requests")
        .and_then(Value::as_u64)
        .ok_or_else(|| {
            format!(
                "grpc_method_router: {subject}: `max_requests` is required and must be a positive integer"
            )
        })?;
    let window_seconds = spec_obj
        .get("window_seconds")
        .and_then(Value::as_u64)
        .ok_or_else(|| {
            format!(
                "grpc_method_router: {subject}: `window_seconds` is required and must be a positive integer"
            )
        })?;
    let max_requests = validate_max_requests(&label, "max_requests", max_requests)
        .map_err(|error| format!("grpc_method_router: {field}: {error}"))?;
    let window_seconds = validate_window_seconds(&label, "window_seconds", window_seconds)
        .map_err(|error| format!("grpc_method_router: {field}: {error}"))?;
    Ok((max_requests, Duration::from_secs(window_seconds)))
}

/// `package.Service/*`, the configured spelling of a service-level rule.
fn service_rule_label(service: &str) -> String {
    let mut rule = String::with_capacity(service.len() + 1 + SERVICE_WILDCARD_METHOD.len());
    rule.push_str(service);
    rule.push('/');
    rule.push_str(SERVICE_WILDCARD_METHOD);
    rule
}

fn normalize_config_method_pattern(method: &str, field: &str) -> Result<MethodPattern, String> {
    let trimmed = method.trim();
    if trimmed.is_empty() {
        return Err(format!(
            "grpc_method_router: `{field}` entries must not be empty"
        ));
    }
    let normalized = trimmed.strip_prefix('/').unwrap_or(trimmed);
    let Some((service, method_name)) = normalized.split_once('/') else {
        return Err(format!(
            "grpc_method_router: `{field}` entry must use `package.Service/Method` or `package.Service/*`: {method:?}"
        ));
    };
    if service.is_empty() || method_name.is_empty() || method_name.contains('/') {
        return Err(format!(
            "grpc_method_router: invalid gRPC method path in `{field}`: {method:?}"
        ));
    }
    if !is_valid_grpc_service(service) {
        return Err(format!(
            "grpc_method_router: invalid gRPC method path in `{field}`: {method:?}"
        ));
    }
    // A service-level rule is exactly `*` in the method segment. The service
    // segment never takes a wildcard, and there is no pattern grammar beyond
    // this one literal form.
    if method_name == SERVICE_WILDCARD_METHOD {
        return Ok(MethodPattern::Service(service.to_string()));
    }
    if !is_valid_grpc_identifier(method_name) {
        return Err(format!(
            "grpc_method_router: invalid gRPC method path in `{field}`: {method:?}"
        ));
    }
    Ok(MethodPattern::Exact(normalized.to_string()))
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

/// Publish (or clear) the gRPC method metadata as one request-local operation.
///
/// `RequestContext` is exclusively borrowed by the caller, so downstream
/// phases observe either the method parsed here or no gRPC method fields when
/// the path is invalid; stale client-path values cannot survive a rewrite.
/// A value that already matches is left in place and a changed value reuses
/// its existing buffer, so the common no-rewrite request does not
/// re-materialize the three strings on the backend-path refresh.
fn publish_grpc_method_metadata(metadata: &mut MetadataMap, parsed: Option<(&str, &str)>) {
    let Some((service, method)) = parsed else {
        metadata.remove("grpc_service");
        metadata.remove("grpc_method");
        metadata.remove("grpc_full_method");
        return;
    };
    set_metadata_parts(metadata, "grpc_service", &[service]);
    set_metadata_parts(metadata, "grpc_method", &[method]);
    set_metadata_parts(metadata, "grpc_full_method", &[service, "/", method]);
}

/// Set `key` to the concatenation of `parts`, without allocating when the
/// published value already matches.
fn set_metadata_parts(metadata: &mut MetadataMap, key: &str, parts: &[&str]) {
    if let Some(existing) = metadata.get_mut(key) {
        if !equals_concatenation(existing, parts) {
            existing.clear();
            for part in parts {
                existing.push_str(part);
            }
        }
        return;
    }
    let mut value = String::with_capacity(parts.iter().map(|part| part.len()).sum());
    for part in parts {
        value.push_str(part);
    }
    metadata.insert(key.to_string(), value);
}

fn equals_concatenation(value: &str, parts: &[&str]) -> bool {
    let mut rest = value;
    for part in parts {
        match rest.strip_prefix(*part) {
            Some(remaining) => rest = remaining,
            None => return false,
        }
    }
    rest.is_empty()
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
    /// Starts the Redis failover health observer only once this generation is
    /// installed, so validation that builds and drops the plugin spawns
    /// nothing (issue #6616).
    fn commit_background_tasks(&self) {
        self.limiter.commit_background_tasks();
    }

    fn name(&self) -> &str {
        "grpc_method_router"
    }

    fn priority(&self) -> u16 {
        super::priority::GRPC_METHOD_ROUTER
    }

    fn lifecycle_hooks(&self) -> crate::plugins::PluginHooks {
        crate::plugins::PluginHooks::ON_REQUEST_RECEIVED
    }

    fn supported_protocols(&self) -> &'static [ProxyProtocol] {
        GRPC_ONLY_PROTOCOLS
    }

    /// Every instance enforces a method allow list, deny list, or rate limit
    /// (the constructor refuses a config with none), so a route configured
    /// with one is gRPC-intended: its plain HTTP and WebSocket views, which
    /// skip this gRPC-only plugin, are refused (issue #6110).
    fn gates_request_admission(&self) -> bool {
        true
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
        let parsed = parse_grpc_path(&ctx.path);
        let method_is_valid = parsed.is_some();
        publish_grpc_method_metadata(&mut ctx.metadata, parsed);
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
        let parsed = parse_grpc_path(backend_path);
        publish_grpc_method_metadata(&mut ctx.metadata, parsed);
        let (full_method, service) = match (ctx.metadata.get("grpc_full_method"), parsed) {
            (Some(method), Some((service, _))) => (method.as_str(), service),
            _ => {
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
        // Check deny list first (deny wins over allow, including an exact
        // allow entry under a denied service).
        if self.deny_methods.matches(full_method, service) {
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
            && !allow_methods.matches(full_method, service)
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

        // Check the most specific rate rule on the pinned selected method.
        if let Some(spec) = self.rate_spec_for(full_method, service) {
            let key = self.rate_key(ctx, &spec.rule);
            match self.check_rate(&key, spec).await {
                None => {
                    self.metrics.record_rate_limit_exceeded();
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
                    self.metrics.record_rate_limit_exceeded();
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
