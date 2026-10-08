//! GraphQL Plugin
//!
//! Adds GraphQL-aware proxying capabilities:
//! - Query parsing and operation extraction
//! - Query depth limiting (bounds selection-set nesting)
//! - Query complexity limiting (bounds approximate field count)
//! - Alias count limiting (mitigates alias-based DoS)
//! - Per-operation-type rate limiting (query vs mutation vs subscription)
//! - Per-named-operation rate limiting (e.g., "getUser" vs "createOrder")
//! - Introspection control (allow/deny __schema/__type queries)
//!
//! GraphQL requests are expected as POST with `application/json` body
//! containing `{"query": "...", "operationName": "..."}`. Other HTTP
//! representations the plugin cannot inspect (GraphQL GET,
//! `application/graphql`, JSON batch arrays, APQ hash-only envelopes,
//! multipart `operations`, missing or unparseable bodies) fail closed.
//! WebSocket GraphQL upgrades also fail closed during their HTTP handshake;
//! the plugin never admits an upgraded frame stream it cannot inspect.
//!
//! The analyzer is a lightweight, allocation-light parser rather than a full
//! GraphQL AST. It selects the operation to analyze using `operationName` (per
//! the GraphQL spec, `operationName` is required for multi-operation documents)
//! so per-type rate limits and depth/complexity caps apply to the operation the
//! backend will actually execute. Fragment spreads (`...Frag`) are expanded at
//! their use sites when computing depth/complexity — with cycle detection and a
//! byte budget so expansion cannot itself become a DoS — so those limits cannot
//! be bypassed by hiding nesting or fields behind fragments. It is still a
//! heuristic (e.g. it does not type-check or validate against a schema) and is
//! intended as an edge filter layered in front of the backend GraphQL server.

use crate::plugins::utils::log_sampling::warn_sampled;

use async_trait::async_trait;
use serde_json::Value;
use std::collections::HashMap;
use std::fmt::Write as _;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};
use tracing::debug;

use super::utils::body_transform::is_json_content_type;
use super::utils::rate_limit::{
    DynamicHttpRateLimitAlgorithm, DynamicRateLimitOp, ENFORCEMENT_UNAVAILABLE_BODY,
    ENFORCEMENT_UNAVAILABLE_STATUS, LocalStateSemantics, RATE_LIMIT_REDIS_CONFIG_KEYS,
    RateLimitBackend, RateLimitOutcome, RateLimitWindowSpec, STANDALONE_RATE_LIMIT_CONFIG_ID,
    apply_rate_limit_cleanup, debug_assert_rate_limit_redis_keys, validate_max_requests,
    validate_window_seconds,
};
use super::{Plugin, PluginHttpClient, PluginResult, RequestContext};
use crate::util::unknown_keys::reject_unknown_keys;

/// Maximum rate-limit state entries before triggering stale eviction.
const MAX_STATE_ENTRIES: usize = 100_000;
const EVICTION_CHECK_INTERVAL_REQUESTS: u64 = 1024;
/// Bounds below-cap full-map scans under high RPS. Sampled over-cap
/// reclaim skips this cooldown so a sampled observation of pressure can
/// drop idle keys without waiting for the next cool-down window. Live
/// budgets are never force-evicted.
const EVICTION_COOLDOWN_SECS: u64 = 1;
const CAPACITY_REJECT_BODY: &str =
    r#"{"errors":[{"message":"Rate limit state capacity exceeded"}]}"#;
const GRAPHQL_PROTOCOLS: &[super::ProxyProtocol] =
    &[super::ProxyProtocol::Http, super::ProxyProtocol::WebSocket];

/// GraphQL-specific top-level config keys (excludes shared Redis sync fields).
const GRAPHQL_POLICY_CONFIG_KEYS: &[&str] = &[
    "max_depth",
    "max_complexity",
    "max_aliases",
    "introspection_allowed",
    "limit_by",
    "type_rate_limits",
    "operation_rate_limits",
];

/// Closed top-level key set for `graphql` plugin config.
///
/// Must stay aligned with OpenAPI `GraphqlConfig`, `RATE_LIMIT_REDIS_CONFIG_KEYS`,
/// and `docs/plugins.md`. Unknown root keys fail closed so typos cannot silently
/// replace introspection, identity, rate-map, or Redis synchronization policy.
pub const GRAPHQL_CONFIG_KEYS: &[&str] = &[
    "max_depth",
    "max_complexity",
    "max_aliases",
    "introspection_allowed",
    "limit_by",
    "type_rate_limits",
    "operation_rate_limits",
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

const RATE_SPEC_KEYS: &[&str] = &["max_requests", "window_seconds"];

/// A rate window spec parsed from config.
#[derive(Debug, Clone)]
struct RateSpec {
    max_requests: u64,
    op: DynamicRateLimitOp,
}

/// Parsed GraphQL operation info.
#[derive(Debug, Clone)]
struct GraphqlOperation {
    /// "query", "mutation", or "subscription"
    op_type: &'static str,
    /// Named operation (from operationName field or parsed from query)
    op_name: Option<String>,
    /// Maximum nesting depth of selection sets
    depth: u32,
    /// Total field count (complexity proxy)
    complexity: u32,
    /// Number of aliases used
    alias_count: u32,
    /// Whether this is an introspection query
    is_introspection: bool,
}

pub struct GraphqlPlugin {
    max_depth: Option<u32>,
    max_complexity: Option<u32>,
    max_aliases: Option<u32>,
    introspection_allowed: bool,
    limit_by: String,
    /// Rate limits by operation type: "query", "mutation", "subscription"
    type_rate_limits: HashMap<String, RateSpec>,
    /// Rate limits by named operation
    operation_rate_limits: HashMap<String, RateSpec>,
    limiter: RateLimitBackend<String, DynamicHttpRateLimitAlgorithm>,
    request_counter: AtomicU64,
    epoch_base: Instant,
    last_periodic_sweep_secs: AtomicU64,
    has_any_config: bool,
    /// Process-unique identity for this constructed instance, used to scope the
    /// per-request "already evaluated this envelope" marker so multiple
    /// configured `graphql` instances cannot consume each other's decision.
    instance_id: u64,
}

/// Source of [`GraphqlPlugin::instance_id`]. Process-unique and never persisted;
/// it exists only to key per-request state for the lifetime of one request.
static NEXT_GRAPHQL_INSTANCE_ID: AtomicU64 = AtomicU64::new(1);

impl GraphqlPlugin {
    #[allow(dead_code)] // direct/test construction; production factory supplies the config id
    pub fn new(config: &Value, http_client: PluginHttpClient) -> Result<Self, String> {
        Self::new_with_config_id(config, http_client, STANDALONE_RATE_LIMIT_CONFIG_ID)
    }

    /// Construct with the stable plugin-config resource id that isolates this
    /// policy's default Redis counters from sibling `graphql` instances in the
    /// same namespace. See
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
        let object = config
            .as_object()
            .ok_or_else(|| "graphql: config must be an object".to_string())?;
        // Debug assertion keeps the documented key groups aligned with the
        // closed root allowlist used for admission and OpenAPI parity.
        debug_assert_rate_limit_redis_keys();
        debug_assert!(
            GRAPHQL_POLICY_CONFIG_KEYS
                .iter()
                .chain(RATE_LIMIT_REDIS_CONFIG_KEYS.iter())
                .all(|key| GRAPHQL_CONFIG_KEYS.contains(key))
                && GRAPHQL_CONFIG_KEYS.len()
                    == GRAPHQL_POLICY_CONFIG_KEYS.len() + RATE_LIMIT_REDIS_CONFIG_KEYS.len()
        );
        reject_unknown_keys(object, "config", GRAPHQL_CONFIG_KEYS, "graphql: `config`: ")?;

        match config.get("sync_mode") {
            None => {}
            Some(Value::String(sync_mode)) if matches!(sync_mode.as_str(), "local" | "redis") => {}
            Some(Value::String(sync_mode)) => {
                return Err(format!(
                    "graphql: `sync_mode` must be exactly `local` or `redis`, got: {sync_mode:?}"
                ));
            }
            Some(_) => {
                return Err("graphql: `sync_mode` must be a string".to_string());
            }
        }

        let max_depth = optional_u32(config, "max_depth")?;
        let max_complexity = optional_u32(config, "max_complexity")?;
        let max_aliases = optional_u32(config, "max_aliases")?;
        let introspection_allowed = optional_bool(config, "introspection_allowed")?.unwrap_or(true);
        // limit_by must be a recognized policy — silently treating "user" as "ip"
        // would be a security misconfiguration footgun.
        let limit_by = match config.get("limit_by") {
            None => "ip".to_string(),
            Some(Value::String(s)) => {
                if !matches!(s.as_str(), "ip" | "consumer") {
                    return Err(format!(
                        "graphql: `limit_by` must be exactly `ip` or `consumer`, got: {s:?}"
                    ));
                }
                s.clone()
            }
            Some(other) => {
                return Err(format!(
                    "graphql: `limit_by` must be a string, got: {other:?}",
                    other = other.to_string()
                ));
            }
        };

        let type_rate_limits = parse_type_rate_limits(config)?;
        let operation_rate_limits = parse_operation_rate_limits(config)?;

        let has_any_config = max_depth.is_some()
            || max_complexity.is_some()
            || max_aliases.is_some()
            || !introspection_allowed
            || !type_rate_limits.is_empty()
            || !operation_rate_limits.is_empty();

        if !has_any_config {
            return Err(
                "graphql: no protection rules configured — set `max_depth`, `max_complexity`, \
                 `max_aliases`, `introspection_allowed: false`, `type_rate_limits`, or \
                 `operation_rate_limits`"
                    .to_string(),
            );
        }

        // Effective enforcement semantics, not raw syntax: the parsed limit
        // dimension and the parsed rate maps, so an omitted map and an explicit
        // empty one describe the same budget. `max_depth` / `max_complexity` /
        // `max_aliases` / `introspection_allowed` are stateless per-document
        // checks that never consult a counter, so changing them must not reset
        // a live budget; the shared Redis posture is added by the backend.
        let mut semantics = LocalStateSemantics::new();
        semantics.text("limit_by", &limit_by);
        semantics.window_map(
            "type_rate_limits",
            type_rate_limits
                .iter()
                .map(|(op_type, spec)| (op_type.as_str(), spec.op.specs())),
        );
        semantics.window_map(
            "operation_rate_limits",
            operation_rate_limits
                .iter()
                .map(|(op_name, spec)| (op_name.as_str(), spec.op.specs())),
        );

        Ok(Self {
            max_depth,
            max_complexity,
            max_aliases,
            introspection_allowed,
            limit_by,
            type_rate_limits,
            operation_rate_limits,
            limiter: RateLimitBackend::from_plugin_config_with_policy_identity(
                "graphql",
                namespace,
                config_id,
                config,
                &http_client,
                DynamicHttpRateLimitAlgorithm::new(),
                &semantics,
            )
            .map_err(|error| format!("graphql: {error}"))?,
            request_counter: AtomicU64::new(0),
            epoch_base: Instant::now(),
            last_periodic_sweep_secs: AtomicU64::new(0),
            has_any_config,
            instance_id: NEXT_GRAPHQL_INSTANCE_ID.fetch_add(1, Ordering::Relaxed),
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
            duration: std::time::Duration::from_secs(1),
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
            duration: std::time::Duration::from_secs(1),
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

    /// Claim one rate-limit bucket for this request, returning whether this
    /// pass owes it a token.
    ///
    /// `before_proxy` and the final request-body re-check both apply the whole
    /// policy, so without this claim an ordinary `request_transformer` body rule
    /// — one that adds an `extensions` member, or merely reserializes the JSON —
    /// charged the same operation twice and refused the first request under
    /// `max_requests: 1`. Structural, alias, and introspection policy still runs
    /// on every pass over the dispatched envelope; only the accounting is
    /// once-per-bucket. A transform that selects a different operation type or
    /// name lands on a different bucket, which is still unclaimed and therefore
    /// still enforced.
    fn charge_bucket_once(&self, ctx: &mut RequestContext, key: &str) -> bool {
        ctx.plugin_state_mut()
            .graphql_charged_rate_buckets
            .insert((self.instance_id, key.to_string()))
    }

    /// Build the rate limit key based on `limit_by` config.
    ///
    /// The identity is tagged `consumer:` or `ip:` (as in `rate_limiting`) so an
    /// identity string that equals an IP never shares a budget with the
    /// unauthenticated caller at that IP.
    fn rate_key(&self, ctx: &RequestContext, kind: &str, value: &str) -> String {
        let (identity_kind, identity) = match (self.limit_by == "consumer")
            .then(|| ctx.effective_identity())
            .flatten()
        {
            Some(identity) => ("consumer:", identity.to_string()),
            None => (
                "ip:",
                crate::util::client_identity::rate_limit_client_ip_string(&ctx.client_ip, 64)
                    .unwrap_or_else(|| ctx.client_ip.to_string()),
            ),
        };
        let mut key = String::with_capacity(
            4 + identity_kind.len() + identity.len() + kind.len() + value.len() + 2,
        );
        key.push_str("gql:");
        key.push_str(identity_kind);
        key.push_str(identity);
        key.push(':');
        key.push_str(kind);
        key.push(':');
        key.push_str(value);
        key
    }
}

fn optional_u32(config: &Value, field: &'static str) -> Result<Option<u32>, String> {
    let Some(value) = config.get(field) else {
        return Ok(None);
    };
    let Some(value) = value.as_u64() else {
        return Err(format!("graphql: `{field}` must be an integer"));
    };
    u32::try_from(value)
        .map(Some)
        .map_err(|_| format!("graphql: `{field}` must fit in a 32-bit unsigned integer"))
}

fn optional_bool(config: &Value, field: &'static str) -> Result<Option<bool>, String> {
    let Some(value) = config.get(field) else {
        return Ok(None);
    };
    value
        .as_bool()
        .map(Some)
        .ok_or_else(|| format!("graphql: `{field}` must be a boolean"))
}

fn parse_type_rate_limits(config: &Value) -> Result<HashMap<String, RateSpec>, String> {
    let Some(value) = config.get("type_rate_limits") else {
        return Ok(HashMap::new());
    };
    let Some(obj) = value.as_object() else {
        return Err("graphql: `type_rate_limits` must be an object".to_string());
    };

    let mut limits = HashMap::new();
    for (op_type, spec) in obj {
        if !matches!(op_type.as_str(), "query" | "mutation" | "subscription") {
            return Err(format!(
                "graphql: `type_rate_limits` key must be exactly `query`, `mutation`, or `subscription`, got: {op_type:?}"
            ));
        }
        limits.insert(
            op_type.clone(),
            parse_rate_spec("type_rate_limits", op_type, spec)?,
        );
    }

    Ok(limits)
}

fn parse_operation_rate_limits(config: &Value) -> Result<HashMap<String, RateSpec>, String> {
    let Some(value) = config.get("operation_rate_limits") else {
        return Ok(HashMap::new());
    };
    let Some(obj) = value.as_object() else {
        return Err("graphql: `operation_rate_limits` must be an object".to_string());
    };

    let mut limits = HashMap::new();
    for (op_name, spec) in obj {
        if !is_graphql_name(op_name) {
            return Err(format!(
                "graphql: `operation_rate_limits` key must be a valid GraphQL operation name, got: {op_name:?}"
            ));
        }
        limits.insert(
            op_name.clone(),
            parse_rate_spec("operation_rate_limits", op_name, spec)?,
        );
    }

    Ok(limits)
}

fn parse_rate_spec(field: &str, key: &str, spec: &Value) -> Result<RateSpec, String> {
    let object = spec
        .as_object()
        .ok_or_else(|| format!("graphql: `{field}` entry {key:?} must be an object"))?;
    let path = format!("config.{field}[{key}]");
    reject_unknown_keys(object, &path, RATE_SPEC_KEYS, "graphql: ")
        .map_err(|error| format!("`{field}`: {error}"))?;
    let max_requests = required_positive_u64(spec, field, key, "max_requests")?;
    let window_seconds = required_positive_u64(spec, field, key, "window_seconds")?;
    // Bound both axes before they reach the shared dynamic HTTP window: an
    // extreme window underflows local `Instant` subtraction and overflows the
    // signed Redis TTL, and an extreme cap is rejected so budgets stay within
    // the shared production maxima. Local sliding-window memory itself is
    // bounded by a fixed aggregate-bucket ring, not by one timestamp per request.
    let label = format!("graphql: `{field}` entry {key:?}");
    // `field` is one of the two schema-authored caller literals. Preserve it
    // outside the opaque label, which also contains the supplied operation key.
    let max_requests = validate_max_requests(&label, "max_requests", max_requests)
        .map_err(|error| format!("graphql: `{field}`: {error}"))?;
    let window_seconds = validate_window_seconds(&label, "window_seconds", window_seconds)
        .map_err(|error| format!("graphql: `{field}`: {error}"))?;
    let window = Duration::from_secs(window_seconds);
    Ok(RateSpec {
        max_requests,
        op: DynamicRateLimitOp::new(vec![RateLimitWindowSpec {
            limit: max_requests,
            duration: window,
        }]),
    })
}

fn required_positive_u64(
    spec: &Value,
    parent: &str,
    key: &str,
    field: &str,
) -> Result<u64, String> {
    let value = spec[field].as_u64().ok_or_else(|| {
        format!("graphql: `{parent}` entry {key:?}: `{field}` is required and must be a positive integer")
    })?;
    if value == 0 {
        return Err(format!(
            "graphql: `{parent}` entry {key:?}: `{field}` must be greater than zero"
        ));
    }
    Ok(value)
}

/// Bound on the total bytes scanned while expanding fragment spreads for a
/// single request. Fragment expansion can multiply work (a wide fragment
/// spread at many sites, or chained fragments), so the resolver itself must be
/// bounded or it becomes a DoS vector. The request body is already size-limited
/// upstream (buffering + size_limiting), so this budget only ever trips for
/// pathological documents; exceeding it is treated as a depth/complexity
/// violation (400) rather than analyzed further.
const MAX_FRAGMENT_EXPANSION_BYTES: usize = 4 * 1024 * 1024;

/// Bound on the analyzer's recursion depth. Each nested selection set, fragment
/// spread, and inline fragment recurses one frame; without a cap a pathological
/// document (e.g. a long non-cyclic chain of single-spread fragments) could
/// recurse deeply enough to overflow the stack — turning the limiter into its
/// own DoS. This bound is far above any legitimate query's resolved nesting and
/// comfortably below stack-exhaustion territory on a default worker stack.
/// Exceeding it yields a 400.
const MAX_ANALYSIS_RECURSION: u32 = 512;

/// Outcome of parsing a GraphQL document into the operation to analyze.
enum ParsedQuery {
    /// The selected operation, ready for limit checks.
    Operation(GraphqlOperation),
    /// The document is invalid per the GraphQL spec or exceeds the expansion
    /// budget and must be rejected before reaching the backend.
    Reject { status_code: u16, message: String },
}

/// A top-level operation definition located in the document.
struct OperationDef<'a> {
    op_type: &'static str,
    /// Operation name as written in the document, if any.
    name: Option<&'a str>,
    /// The operation's top-level selection set body (the bytes between the
    /// outermost `{` and its matching `}`), borrowed from the document.
    selection_set: &'a str,
}

/// Parse a GraphQL query string and select the operation to analyze.
///
/// This is a lightweight parser that handles the subset of GraphQL syntax
/// needed for depth/complexity/alias analysis without a full AST. It (1) lexes
/// the whole document with the spec's token rules, (2) splits it into
/// individual operation and fragment definitions, (3) selects which operation
/// is analyzed using `operation_name` (per the GraphQL spec: `operationName` is
/// required when a document defines more than one operation), and (4) expands
/// fragment spreads (`...Frag`) at their use sites when computing
/// depth/complexity so those limits cannot be bypassed by hiding
/// nesting/fields behind fragments. Fragment expansion is cycle-safe and
/// byte-budgeted so the expansion itself cannot be turned into a DoS.
///
/// Every stage fails closed. A document that does not lex
/// ([`validate_document_tokens`]), is not a sequence of complete definitions,
/// defines no operation, or spreads a fragment it does not define is rejected
/// with a 400 rather than measured by a weaker scan, so the measured operation
/// is always the one a conforming backend would execute.
fn parse_graphql_query(query: &str, operation_name: Option<&str>) -> ParsedQuery {
    if let Err(error) = validate_document_tokens(query.as_bytes()) {
        return malformed_document(error.message());
    }
    let document = match parse_document(query) {
        Ok(document) => document,
        Err(message) => return malformed_document(message),
    };
    let operations = &document.operations;
    if operations.is_empty() {
        return malformed_document("the document defines no operation");
    }
    let operation_name = operation_name.filter(|n| !n.is_empty());

    // Select the operation to analyze.
    let selected = match operation_name {
        // Explicit operationName: it must match exactly one operation.
        Some(name) => match operations.iter().find(|op| op.name == Some(name)) {
            Some(op) => op,
            None => {
                return ParsedQuery::Reject {
                    status_code: 400,
                    message: format!("Unknown operation named \"{name}\""),
                };
            }
        },
        // No operationName: the GraphQL spec requires it for multi-operation
        // documents. Reject those rather than silently analyzing the wrong
        // operation (which would let per-type limits be bypassed).
        None => match operations.as_slice() {
            [op] => op,
            _ => {
                return ParsedQuery::Reject {
                    status_code: 400,
                    message:
                        "operationName is required when the document contains multiple operations"
                            .to_string(),
                };
            }
        },
    };

    let op_name = operation_name
        .map(String::from)
        .or_else(|| selected.name.map(String::from));

    match analyze_operation(selected.selection_set, &document.fragments) {
        Ok((depth, complexity, alias_count, is_introspection)) => {
            ParsedQuery::Operation(GraphqlOperation {
                op_type: selected.op_type,
                op_name,
                depth,
                complexity,
                alias_count,
                is_introspection,
            })
        }
        Err(error) => ParsedQuery::Reject {
            status_code: 400,
            message: error.message().to_string(),
        },
    }
}

fn malformed_document(detail: &str) -> ParsedQuery {
    ParsedQuery::Reject {
        status_code: 400,
        message: format!("Malformed GraphQL document: {detail}"),
    }
}

/// The document's operation definitions and a `name -> selection-set body`
/// map of its fragment definitions.
struct ParsedDocument<'a> {
    operations: Vec<OperationDef<'a>>,
    fragments: HashMap<&'a str, &'a str>,
}

/// Split an already-lexed GraphQL document into its top-level definitions.
///
/// String literals, block strings, comments, and argument lists are respected
/// so keywords/braces inside them are never mistaken for structure. Anything
/// that is not a complete executable definition is an error: an unbalanced or
/// unterminated definition, a document-level token other than an operation
/// keyword, `fragment`, a shorthand `{`, or a string (a description), a
/// nameless or duplicate fragment, a duplicate operation name, or an anonymous
/// operation that is not alone. A conforming server refuses every one of
/// those, so refusing them here costs no valid traffic and leaves no document
/// the gateway would measure differently from the backend.
fn parse_document(query: &str) -> Result<ParsedDocument<'_>, &'static str> {
    const INCOMPLETE_DEFINITION: &str = "unbalanced or incomplete definition";

    let bytes = query.as_bytes();
    let len = bytes.len();
    let mut operations: Vec<OperationDef<'_>> = Vec::new();
    let mut fragments: HashMap<&str, &str> = HashMap::new();
    let mut i = 0;

    loop {
        // Skip the complete `Ignored` run (BOM, whitespace, line terminators,
        // commas, comments) through the shared lexer-level scanner.
        i = skip_ignored(bytes, i);
        if i >= len {
            break;
        }
        let c = bytes[i];

        // A document-level string (a description, where a backend accepts
        // one) is a single opaque token. Scanning its contents byte by byte
        // would parse selection-looking text inside it as a definition.
        if c == b'"' {
            i = skip_string(bytes, i);
            continue;
        }

        // A bare selection set is an anonymous (shorthand) query operation.
        if c == b'{' {
            let Some(end) = find_matching_brace(bytes, i) else {
                return Err(INCOMPLETE_DEFINITION);
            };
            operations.push(OperationDef {
                op_type: "query",
                name: None,
                selection_set: &query[i + 1..end],
            });
            i = end + 1;
            continue;
        }

        if !is_graphql_name_start(c) {
            return Err("unexpected token between definitions");
        }
        let (ident, after_ident) = read_name(bytes, i);
        let op_type = match ident {
            "query" => Some("query"),
            "mutation" => Some("mutation"),
            "subscription" => Some("subscription"),
            "fragment" => None,
            _ => return Err("unexpected token between definitions"),
        };

        // Optional name, then (operations) variable definitions and
        // directives or (fragments) the `on Type` condition and directives,
        // then the selection set `{ ... }`.
        let (name, after_name) = read_optional_name(bytes, after_ident, query);
        let Some(brace) = find_next_top_level_brace(bytes, after_name) else {
            return Err(INCOMPLETE_DEFINITION);
        };
        let Some(end) = find_matching_brace(bytes, brace) else {
            return Err(INCOMPLETE_DEFINITION);
        };
        let selection_set = &query[brace + 1..end];

        match op_type {
            Some(op_type) => {
                if name.is_some() && operations.iter().any(|op| op.name == name) {
                    return Err("duplicate operation name");
                }
                operations.push(OperationDef {
                    op_type,
                    name,
                    selection_set,
                });
            }
            None => {
                // `on` is the type-condition keyword, never a fragment name.
                let Some(name) = name.filter(|name| *name != "on") else {
                    return Err("fragment definition without a name");
                };
                if fragments.insert(name, selection_set).is_some() {
                    return Err("duplicate fragment name");
                }
            }
        }
        i = end + 1;
    }

    if operations.len() > 1 && operations.iter().any(|op| op.name.is_none()) {
        return Err("an anonymous operation must be the only operation in the document");
    }
    Ok(ParsedDocument {
        operations,
        fragments,
    })
}

/// Read a GraphQL name starting at `start` (must be a name-start byte).
/// Returns the name slice and the index just past it.
fn read_name(bytes: &[u8], start: usize) -> (&str, usize) {
    let mut end = start + 1;
    while end < bytes.len() && is_graphql_name_continue(bytes[end]) {
        end += 1;
    }
    // SAFETY of from_utf8: names are ASCII (name-start/continue are ASCII), so
    // this slice is valid UTF-8; use the checked conversion regardless.
    let name = std::str::from_utf8(&bytes[start..end]).unwrap_or("");
    (name, end)
}

/// After an operation/fragment keyword, skip ignored tokens and read an
/// optional name. Returns the name (if present) and the index to continue from.
///
/// The name borrows from `query` (not the temporary `bytes` slice) so it shares
/// the document's lifetime. The first name after `query`/`mutation`/
/// `subscription` is the operation name; the first name after `fragment` is the
/// fragment name (the `on Type` condition comes after and is skipped by the
/// brace search).
fn read_optional_name<'a>(bytes: &[u8], i: usize, query: &'a str) -> (Option<&'a str>, usize) {
    let i = skip_ignored(bytes, i);
    if i < bytes.len() && is_graphql_name_start(bytes[i]) {
        let (_, after) = read_name(bytes, i);
        return (Some(&query[i..after]), after);
    }
    (None, i)
}

/// Find the next top-level `{` starting at `i`, skipping balanced parentheses
/// (variable definitions / arguments), strings, and comments. Returns `None`
/// if a `}` or end-of-input is reached first (which would be malformed).
fn find_next_top_level_brace(bytes: &[u8], mut i: usize) -> Option<usize> {
    let len = bytes.len();
    while i < len {
        let c = bytes[i];
        match c {
            b'{' => return Some(i),
            b'}' => return None,
            b'#' => i = skip_line_comment(bytes, i),
            b'"' => i = skip_string(bytes, i),
            b'(' => i = skip_parens(bytes, i),
            _ => i += 1,
        }
    }
    None
}

/// Given `bytes[open] == b'{'`, return the index of the matching `}`,
/// respecting nested braces, strings, comments, and argument parens. Returns
/// `None` if the document ends before the brace is closed.
fn find_matching_brace(bytes: &[u8], open: usize) -> Option<usize> {
    let len = bytes.len();
    let mut depth = 0u32;
    let mut i = open;
    while i < len {
        match bytes[i] {
            b'#' => {
                i = skip_line_comment(bytes, i);
                continue;
            }
            b'"' => {
                i = skip_string(bytes, i);
                continue;
            }
            b'(' => {
                i = skip_parens(bytes, i);
                continue;
            }
            b'{' => depth += 1,
            b'}' => {
                depth -= 1;
                if depth == 0 {
                    return Some(i);
                }
            }
            _ => {}
        }
        i += 1;
    }
    None
}

/// Skip a balanced parenthesized group starting at `bytes[i] == b'('`.
/// Returns the index just past the matching `)`. Respects strings and comments
/// inside the group; braces inside arguments are ignored by the caller.
fn skip_parens(bytes: &[u8], i: usize) -> usize {
    let len = bytes.len();
    let mut depth = 0u32;
    let mut j = i;
    while j < len {
        match bytes[j] {
            b'#' => {
                j = skip_line_comment(bytes, j);
                continue;
            }
            b'"' => {
                j = skip_string(bytes, j);
                continue;
            }
            b'(' => depth += 1,
            b')' => {
                depth -= 1;
                if depth == 0 {
                    return j + 1;
                }
            }
            _ => {}
        }
        j += 1;
    }
    len
}

/// GraphQL `BlockString` delimiter.
const BLOCK_STRING_DELIMITER: &[u8] = b"\"\"\"";

/// The only escape a GraphQL `BlockString` has: `\"""` is three literal
/// quotes of content, not a delimiter.
const ESCAPED_BLOCK_STRING_DELIMITER: &[u8] = b"\\\"\"\"";

/// Why a document failed to lex under the GraphQL token rules.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum TokenError {
    /// A regular string reached a line terminator or end-of-input unclosed.
    UnterminatedString,
    /// A block string reached end-of-input without its closing `"""`.
    UnterminatedBlockString,
    /// A regular string holds a `\` that starts no `EscapedCharacter` or
    /// `EscapedUnicode`.
    InvalidEscape,
    /// A byte outside strings and comments that starts no token and is not
    /// `Ignored`.
    InvalidCharacter,
    /// A malformed `IntValue` or `FloatValue`.
    InvalidNumber,
}

impl TokenError {
    fn message(self) -> &'static str {
        match self {
            Self::UnterminatedString => "unterminated string",
            Self::UnterminatedBlockString => "unterminated block string",
            Self::InvalidEscape => "invalid escape sequence in string",
            Self::InvalidCharacter => "invalid character outside a string or comment",
            Self::InvalidNumber => "invalid number",
        }
    }
}

/// Single-byte GraphQL `Punctuator`s (`...` is lexed separately).
const PUNCTUATORS: &[u8] = b"!$&():=@[]{|}";

/// Lex the whole document with the GraphQL token rules, without interpreting
/// its structure.
///
/// Outside strings and comments only the lexical grammar's tokens are
/// accepted: `Ignored` (tab, space, LF, CR, comma, the UnicodeBOM), the
/// punctuators, names (`[_A-Za-z][_0-9A-Za-z]*`), and numbers. Anything else
/// (a non-ASCII character, a form feed, a lone `.`) would be a separator to the
/// structural scanners below but a syntax error to a conforming parser, so it
/// is refused rather than allowed to split or hide a name.
///
/// The structural scanners locate strings with [`skip_string`] from many entry
/// points and on sub-slices of the document. Lexing every string up front
/// through the same [`scan_string`] means a malformed string is refused (fail
/// closed) instead of silently running to end-of-input, and every later scan
/// sees exactly the token boundaries a conforming parser draws.
fn validate_document_tokens(bytes: &[u8]) -> Result<(), TokenError> {
    let len = bytes.len();
    let mut i = 0;
    while i < len {
        let c = bytes[i];
        i = match c {
            b'\t' | b' ' | b'\n' | b'\r' | b',' => i + 1,
            b'#' => skip_line_comment(bytes, i),
            b'"' => scan_string(bytes, i)?,
            _ if PUNCTUATORS.contains(&c) => i + 1,
            b'.' if bytes[i..].starts_with(b"...") => i + 3,
            b'-' | b'0'..=b'9' => scan_number(bytes, i)?,
            _ if is_graphql_name_start(c) => read_name(bytes, i).1,
            _ if is_unicode_bom(bytes, i) => i + UNICODE_BOM.len(),
            _ => return Err(TokenError::InvalidCharacter),
        };
    }
    Ok(())
}

/// Lex an `IntValue` or `FloatValue` starting at `bytes[i]` (`-` or a digit)
/// and return the index just past it.
fn scan_number(bytes: &[u8], i: usize) -> Result<usize, TokenError> {
    let mut j = i;
    if bytes[j] == b'-' {
        j += 1;
    }
    let integer_start = j;
    j = skip_digits(bytes, j);
    let integer_digits = j - integer_start;
    // `IntegerPart` is `0` or a non-zero digit followed by digits.
    if integer_digits == 0 || (integer_digits > 1 && bytes[integer_start] == b'0') {
        return Err(TokenError::InvalidNumber);
    }
    if bytes.get(j) == Some(&b'.') {
        let fraction_start = j + 1;
        j = skip_digits(bytes, fraction_start);
        if j == fraction_start {
            return Err(TokenError::InvalidNumber);
        }
    }
    if matches!(bytes.get(j), Some(b'e' | b'E')) {
        j += 1;
        if matches!(bytes.get(j), Some(b'+' | b'-')) {
            j += 1;
        }
        let exponent_start = j;
        j = skip_digits(bytes, exponent_start);
        if j == exponent_start {
            return Err(TokenError::InvalidNumber);
        }
    }
    // Neither numeric token may be followed directly by `.` or a `NameStart`.
    if matches!(bytes.get(j), Some(&next) if next == b'.' || is_graphql_name_start(next)) {
        return Err(TokenError::InvalidNumber);
    }
    Ok(j)
}

fn skip_digits(bytes: &[u8], mut j: usize) -> usize {
    while bytes.get(j).is_some_and(u8::is_ascii_digit) {
        j += 1;
    }
    j
}

/// Skip a string literal (regular or block) starting at `bytes[i] == b'"'`.
/// Returns the index just past the closing quote(s).
///
/// [`parse_graphql_query`] refuses any document that fails
/// [`validate_document_tokens`] before a structural scan runs, so the
/// end-of-input result for a malformed string is only a scan terminator here.
fn skip_string(bytes: &[u8], i: usize) -> usize {
    scan_string(bytes, i).unwrap_or(bytes.len())
}

/// Lex one GraphQL `StringValue` starting at `bytes[i] == b'"'` and return the
/// index just past its closing quote(s).
///
/// Regular and block strings have different escape grammars and must never
/// share one: a regular string's `\` always begins a two-or-more-byte escape,
/// while inside a block string the four bytes `\"""` are the only escape and
/// every other `\` is one byte of content. Pairing backslashes inside a block
/// string ends it early at `\\"""`, where a conforming parser keeps going, and
/// the text the parser still reads as string content is then analyzed as the
/// operation's selection set.
fn scan_string(bytes: &[u8], i: usize) -> Result<usize, TokenError> {
    if bytes[i..].starts_with(BLOCK_STRING_DELIMITER) {
        return scan_block_string(bytes, i + BLOCK_STRING_DELIMITER.len());
    }
    let len = bytes.len();
    let mut j = i + 1;
    while j < len {
        match bytes[j] {
            b'"' => return Ok(j + 1),
            // `StringCharacter` excludes `LineTerminator`.
            b'\n' | b'\r' => return Err(TokenError::UnterminatedString),
            b'\\' => j = scan_string_escape(bytes, j + 1)?,
            _ => j += 1,
        }
    }
    Err(TokenError::UnterminatedString)
}

/// Lex a `BlockString` body starting just past its opening `"""`.
fn scan_block_string(bytes: &[u8], mut j: usize) -> Result<usize, TokenError> {
    let len = bytes.len();
    while j < len {
        match bytes[j] {
            b'\\' if bytes[j..].starts_with(ESCAPED_BLOCK_STRING_DELIMITER) => {
                j += ESCAPED_BLOCK_STRING_DELIMITER.len();
            }
            b'"' if bytes[j..].starts_with(BLOCK_STRING_DELIMITER) => {
                return Ok(j + BLOCK_STRING_DELIMITER.len());
            }
            // Any other byte, a lone `\` included, is one byte of content.
            _ => j += 1,
        }
    }
    Err(TokenError::UnterminatedBlockString)
}

/// Lex a regular-string escape whose `\` sits just before `bytes[j]`. Returns
/// the index just past the escape.
fn scan_string_escape(bytes: &[u8], j: usize) -> Result<usize, TokenError> {
    match bytes.get(j) {
        Some(b'"' | b'\\' | b'/' | b'b' | b'f' | b'n' | b'r' | b't') => Ok(j + 1),
        Some(b'u') => scan_unicode_escape(bytes, j + 1),
        _ => Err(TokenError::InvalidEscape),
    }
}

/// Lex the `EscapedUnicode` after `\u` starting at `bytes[j]`: either the
/// variable-width `{HexDigit+}` form or exactly four hex digits.
///
/// Only the escape's extent is checked here, because that is what decides
/// where the string ends. Code-point range and surrogate pairing are value
/// rules the backend applies to a string whose boundaries are already fixed.
fn scan_unicode_escape(bytes: &[u8], j: usize) -> Result<usize, TokenError> {
    if bytes.get(j) == Some(&b'{') {
        let digits_start = j + 1;
        let digits = bytes[digits_start..]
            .iter()
            .take_while(|b| b.is_ascii_hexdigit())
            .count();
        let close = digits_start + digits;
        if digits == 0 || bytes.get(close) != Some(&b'}') {
            return Err(TokenError::InvalidEscape);
        }
        return Ok(close + 1);
    }
    match bytes.get(j..j + 4) {
        Some(hex) if hex.iter().all(u8::is_ascii_hexdigit) => Ok(j + 4),
        _ => Err(TokenError::InvalidEscape),
    }
}

/// Skip a `#` line comment starting at `bytes[i] == b'#'`. Returns the index of
/// the line terminator (or end-of-input).
fn skip_line_comment(bytes: &[u8], i: usize) -> usize {
    let len = bytes.len();
    let mut j = i + 1;
    while j < len && bytes[j] != b'\n' && bytes[j] != b'\r' {
        j += 1;
    }
    j
}

/// UTF-8 encoding of the GraphQL `UnicodeBOM` ignored token (U+FEFF).
const UNICODE_BOM: &[u8] = "\u{feff}".as_bytes();

/// Whether `bytes[i..]` starts with the UnicodeBOM ignored token.
fn is_unicode_bom(bytes: &[u8], i: usize) -> bool {
    bytes
        .get(i..)
        .is_some_and(|rest| rest.starts_with(UNICODE_BOM))
}

/// Skip GraphQL `Ignored` tokens starting at `i`.
///
/// This is the plugin's single lexer-level `Ignored` scanner and it implements
/// exactly the complete production: `UnicodeBOM` (U+FEFF), `WhiteSpace` (tab,
/// space), `LineTerminator` (LF, CR), `Comment`, and `Comma`, and nothing
/// else. Every name scan (operation and fragment names, alias colons,
/// directive names) goes through it, so a document's parsed operation
/// identity and its structural measurements stay invariant under insertion or
/// removal of legal ignored tokens at token boundaries. Omitting a token class
/// here silently reclassifies a named operation as anonymous and bypasses the
/// named-operation budget (`GHSA-wr84-jm45-wrwp`), exactly as the omitted
/// comma/comment classes once did for alias accounting
/// (`GHSA-hpxh-qrx9-m7r5`). Characters outside the production never reach
/// here: [`validate_document_tokens`] refuses them first.
fn skip_ignored(bytes: &[u8], mut i: usize) -> usize {
    let len = bytes.len();
    while i < len {
        let c = bytes[i];
        if matches!(c, b'\t' | b' ' | b'\n' | b'\r' | b',') {
            i += 1;
        } else if c == b'#' {
            i = skip_line_comment(bytes, i);
        } else if is_unicode_bom(bytes, i) {
            i += UNICODE_BOM.len();
        } else {
            break;
        }
    }
    i
}

/// Why a selected operation could not be measured.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum AnalysisError {
    /// The fragment-expansion byte budget or the recursion bound was exceeded.
    TooLarge,
    /// A named fragment spread has no matching fragment definition.
    UnknownFragment,
    /// A selection set is structurally incomplete.
    Malformed,
}

impl AnalysisError {
    fn message(self) -> &'static str {
        match self {
            Self::TooLarge => "Query is too large to analyze (fragment expansion budget exceeded)",
            Self::UnknownFragment => "Query spreads a fragment the document does not define",
            Self::Malformed => "Malformed GraphQL document: incomplete selection set",
        }
    }
}

/// Analyze a selected operation's selection set, expanding fragment spreads.
///
/// Returns `(max_depth, complexity, alias_count, is_introspection)` measured
/// over the operation with all reachable fragments expanded in place, or an
/// error the caller turns into a 400: the byte-expansion budget was exceeded,
/// a spread names an undefined fragment (whose selections would otherwise be
/// silently left unmeasured), or a selection set is incomplete. Cyclic
/// fragment spreads are detected via a per-path visited set so the expansion
/// always terminates.
fn analyze_operation(
    selection_set: &str,
    fragments: &HashMap<&str, &str>,
) -> Result<(u32, u32, u32, bool), AnalysisError> {
    let mut acc = AnalysisAcc::default();
    let mut visited: Vec<&str> = Vec::new();
    let mut budget = MAX_FRAGMENT_EXPANSION_BYTES;
    // The operation selection set sits one level inside the operation's
    // outermost braces, so its fields are at depth 1.
    analyze_selection_set(
        selection_set,
        1,
        0,
        fragments,
        &mut visited,
        &mut acc,
        &mut budget,
    )?;
    Ok((
        acc.max_depth,
        acc.complexity,
        acc.alias_count,
        acc.is_introspection,
    ))
}

/// Mutable accumulator for an analysis pass.
#[derive(Default)]
struct AnalysisAcc {
    max_depth: u32,
    complexity: u32,
    alias_count: u32,
    is_introspection: bool,
}

/// Scan one selection-set body (the bytes between a matched `{` `}`), with the
/// enclosing brace already accounted for as `base_depth`. Fields are counted
/// into `acc.complexity`; nested selection sets recurse; `...Frag` spreads
/// expand the named fragment's selection set at the current depth (guarded
/// against cycles via `visited` and bounded by `budget`).
///
/// `call_depth` is the analyzer's recursion depth (independent of `base_depth`,
/// since fragment spreads recurse without adding GraphQL nesting); it caps stack
/// usage. Exceeding either the byte budget or the recursion bound is
/// [`AnalysisError::TooLarge`].
fn analyze_selection_set<'a>(
    body: &'a str,
    base_depth: u32,
    call_depth: u32,
    fragments: &HashMap<&'a str, &'a str>,
    visited: &mut Vec<&'a str>,
    acc: &mut AnalysisAcc,
    budget: &mut usize,
) -> Result<(), AnalysisError> {
    if call_depth >= MAX_ANALYSIS_RECURSION {
        return Err(AnalysisError::TooLarge);
    }
    let Some(remaining) = budget.checked_sub(body.len()) else {
        return Err(AnalysisError::TooLarge);
    };
    *budget = remaining;
    if base_depth > acc.max_depth {
        acc.max_depth = base_depth;
    }

    let bytes = body.as_bytes();
    let len = bytes.len();
    let mut i = 0;

    while i < len {
        let c = bytes[i];

        match c {
            b'#' => {
                i = skip_line_comment(bytes, i);
                continue;
            }
            b'"' => {
                i = skip_string(bytes, i);
                continue;
            }
            b'(' => {
                // Argument list: skip entirely (matches the original scanner,
                // which ignored everything inside arguments).
                i = skip_parens(bytes, i);
                continue;
            }
            b'{' => {
                // Nested selection set: recurse one level deeper.
                let Some(end) = find_matching_brace(bytes, i) else {
                    return Err(AnalysisError::Malformed);
                };
                analyze_selection_set(
                    &body[i + 1..end],
                    base_depth + 1,
                    call_depth + 1,
                    fragments,
                    visited,
                    acc,
                    budget,
                )?;
                i = end + 1;
                continue;
            }
            b'}' => {
                // Should not appear at this level (bodies are pre-balanced), but
                // tolerate it.
                i += 1;
                continue;
            }
            b'@' => {
                // Directive: the `@` punctuator and its name are distinct
                // lexical tokens, so legal ignored tokens may sit between them.
                // Consume the name here rather than inferring directive context
                // from the immediately preceding byte, which counted
                // `@ skip(if: false)` as a selected field (#5130). The
                // directive's arguments are skipped by the `(` arm.
                let after_at = skip_ignored(bytes, i + 1);
                if after_at < len && is_graphql_name_start(bytes[after_at]) {
                    let (_, after_name) = read_name(bytes, after_at);
                    i = after_name;
                } else {
                    i += 1;
                }
                continue;
            }
            b'.' => {
                // Fragment spread `...Name` or inline fragment
                // (`... on Type { ... }`, `... { ... }`, `... @dir { ... }`).
                if i + 2 < len && bytes[i + 1] == b'.' && bytes[i + 2] == b'.' {
                    let after_dots = skip_ignored(bytes, i + 3);
                    // A named fragment spread is `...` followed by a name that is
                    // not the `on` keyword. Anything else is an inline fragment.
                    if after_dots < len && is_graphql_name_start(bytes[after_dots]) {
                        let (name, after_name) = read_name(bytes, after_dots);
                        if name != "on" {
                            // Named fragment spread: expand the fragment body at
                            // the current depth. An undefined fragment is an
                            // error, not an empty expansion, since skipping it
                            // would leave whatever the backend resolves for it
                            // unmeasured. A spread whose name is already on the
                            // current path is a cycle (invalid GraphQL); we
                            // simply do not recurse into it, which guarantees the
                            // expansion terminates.
                            let Some(frag_body) = fragments.get(name).copied() else {
                                return Err(AnalysisError::UnknownFragment);
                            };
                            if !visited.contains(&name) {
                                visited.push(name);
                                let result = analyze_selection_set(
                                    frag_body,
                                    base_depth,
                                    call_depth + 1,
                                    fragments,
                                    visited,
                                    acc,
                                    budget,
                                );
                                visited.pop();
                                result?;
                            }
                            i = after_name;
                            continue;
                        }
                    }
                    // Inline fragment: its selection set is spliced in at the
                    // SAME depth (an inline fragment adds no nesting level). Skip
                    // any `on Type` / directives, then analyze the `{ ... }` body
                    // at the current base_depth.
                    let Some(brace) = find_next_top_level_brace(bytes, i + 3) else {
                        return Err(AnalysisError::Malformed);
                    };
                    let Some(end) = find_matching_brace(bytes, brace) else {
                        return Err(AnalysisError::Malformed);
                    };
                    analyze_selection_set(
                        &body[brace + 1..end],
                        base_depth,
                        call_depth + 1,
                        fragments,
                        visited,
                        acc,
                        budget,
                    )?;
                    i = end + 1;
                    continue;
                }
                i += 1;
                continue;
            }
            _ => {}
        }

        if is_graphql_name_start(c) {
            // Selection-set bodies only: identifiers here are field names (or
            // aliases), including names that spell document/value keywords.
            // Top-level `query`/`mutation`/`subscription`/`fragment` are
            // consumed by `parse_document`; inline-fragment `on` is consumed
            // by the `...` branch above; argument literals live inside
            // `skip_parens`.
            let (ident, after_ident) = read_name(bytes, i);

            // Look past ignored tokens for an alias `:`.
            let j = skip_ignored(bytes, after_ident);
            if j < len && bytes[j] == b':' {
                acc.alias_count += 1;
                // The aliased field name follows and is counted on a later
                // iteration.
                i = j + 1;
                continue;
            }

            // A field: directive names never reach here, the `@` arm above
            // consumes them together with their punctuator.
            if ident == "__schema" || ident == "__type" {
                acc.is_introspection = true;
            }
            acc.complexity += 1;
            i = after_ident;
            continue;
        }

        i += 1;
    }

    Ok(())
}

fn is_graphql_name(value: &str) -> bool {
    let bytes = value.as_bytes();
    bytes.first().is_some_and(|b| is_graphql_name_start(*b))
        && bytes.iter().skip(1).all(|b| is_graphql_name_continue(*b))
}

fn is_graphql_name_start(b: u8) -> bool {
    b == b'_' || b.is_ascii_alphabetic()
}

fn is_graphql_name_continue(b: u8) -> bool {
    is_graphql_name_start(b) || b.is_ascii_digit()
}

fn is_graphql_json_content_type(content_type: &str) -> bool {
    is_json_content_type(content_type) || ascii_contains_ignore_case(content_type, "json")
}

fn ascii_contains_ignore_case(haystack: &str, needle: &str) -> bool {
    let hb = haystack.as_bytes();
    let nb = needle.as_bytes();
    if nb.is_empty() {
        return true;
    }
    if nb.len() > hb.len() {
        return false;
    }

    hb.windows(nb.len()).any(|window| {
        window
            .iter()
            .zip(nb.iter())
            .all(|(a, b)| a.eq_ignore_ascii_case(b))
    })
}

#[async_trait]
impl Plugin for GraphqlPlugin {
    fn name(&self) -> &str {
        "graphql"
    }

    fn priority(&self) -> u16 {
        super::priority::GRAPHQL
    }

    fn supported_protocols(&self) -> &'static [super::ProxyProtocol] {
        GRAPHQL_PROTOCOLS
    }

    /// GraphQL policy now also decides in the final request-body phase, over the
    /// exact backend-visible envelope. Composition admission therefore refuses to
    /// pair it with a plugin that egresses the request before finalization, the
    /// same rule `waf` and `body_validator` carry (GHSA-4vr5-4wm3-x5xv).
    fn enforces_finalized_request_policy(&self) -> bool {
        self.has_any_config
    }

    fn tracked_keys_count(&self) -> Option<usize> {
        Some(self.limiter.tracked_keys_count())
    }

    fn warmup_hostnames(&self) -> Vec<String> {
        self.limiter.warmup_hostname().into_iter().collect()
    }

    fn requires_request_body_before_before_proxy(&self) -> bool {
        self.has_any_config
    }

    fn should_buffer_request_body(&self, ctx: &RequestContext) -> bool {
        self.has_any_config
            && ctx.method == "POST"
            && ctx
                .headers
                .get("content-type")
                .is_some_and(|ct| is_graphql_json_content_type(ct))
    }

    async fn before_proxy(
        &self,
        ctx: &mut RequestContext,
        headers: &mut HashMap<String, String>,
    ) -> PluginResult {
        // Only inspect POST + JSON + object with string `query`. Other HTTP
        // representations fail closed, including WebSocket GET upgrades.
        if ctx.method != "POST" {
            return reject_uninspectable_transport(
                "GraphQL request uses an unsupported HTTP method; \
                 only POST with an inspectable JSON body is accepted",
            );
        }

        if !headers
            .get("content-type")
            .is_some_and(|ct| is_graphql_json_content_type(ct))
        {
            return reject_uninspectable_transport(
                "GraphQL request uses an unsupported content type; \
                 only JSON content types are inspectable",
            );
        }

        let body = match ctx.metadata.get("request_body") {
            Some(b) if !b.is_empty() => b.as_str(),
            _ => {
                debug!("graphql: no request body available");
                return reject_uninspectable_transport(
                    "GraphQL request body is missing or empty \
                     and cannot be inspected",
                );
            }
        };

        let body = body.as_bytes().to_vec();
        ctx.plugin_state_mut()
            .graphql_request_envelope_hashes
            .insert(self.instance_id, graphql_envelope_digest(&body));
        self.enforce_graphql_envelope(ctx, &body).await
    }

    /// Re-evaluate the envelope the backend will actually receive.
    ///
    /// `before_proxy` (priority 2850) is the only pass GraphQL policy used to
    /// get, and `request_transformer` (3000) applies its `add`/`update`/
    /// `remove`/`rename` body rules afterwards. A rename of an
    /// attacker-controlled `pending_query` onto `query`, or a replacement of
    /// `operationName`, therefore produced a backend-visible operation that was
    /// never parsed for depth, complexity, aliases, or introspection, and was
    /// never charged against the configured per-type / per-operation budgets
    /// (`GHSA-3xrr-4h3f-89pc`).
    ///
    /// Work is skipped for an UNCHANGED envelope through an instance-scoped
    /// digest, so the ordinary untransformed request does not re-parse its
    /// query. A CHANGED envelope is re-parsed and re-decided in full, but rate
    /// accounting is claimed per bucket for the whole request
    /// (`charge_bucket_once`): a transform that leaves the operation type and
    /// name alone — adding an `extensions` member, reserializing the JSON —
    /// still costs exactly one token, while a transform that selects a
    /// different operation lands on a bucket this request has not claimed and
    /// is charged and enforced there.
    async fn on_final_request_body_with_context(
        &self,
        ctx: &mut RequestContext,
        headers: &HashMap<String, String>,
        body: &[u8],
    ) -> PluginResult {
        if !self.has_any_config {
            return PluginResult::Continue;
        }
        // Only a request this instance already admitted has a recorded digest.
        // Its absence means `before_proxy` never ran or already rejected, so
        // there is nothing to re-decide here.
        let Some(previous) = ctx
            .plugin_state()
            .and_then(|state| state.graphql_request_envelope_hashes.get(&self.instance_id))
            .copied()
        else {
            return PluginResult::Continue;
        };

        // Inspect the plaintext: `inspectable_final_request_body` returns `body`
        // itself unless the shared request representation gate decoded a content
        // coding, and a claimed representation it could not decode never reaches
        // this hook (`GHSA-3973-47g5-4mcx`).
        //
        // The owned handle is an `O(1)` `Bytes` clone sharing the gate's one
        // charged allocation — it exists to escape the borrow of `ctx` that
        // `enforce_graphql_envelope` needs, not to copy the document. When
        // nothing was decoded there is no handle at all and the wire slice is
        // used directly, so an ordinary identity-coded request allocates nothing
        // here.
        let decoded_view = ctx.inspectable_final_request_body_owned();
        let envelope: &[u8] = decoded_view.as_deref().unwrap_or(body);
        if graphql_envelope_digest(envelope) == previous {
            return PluginResult::Continue;
        }

        // The dispatched representation must still be an inspectable GraphQL
        // JSON envelope. A transform that turned it into something else removed
        // the gateway's ability to enforce, which is a rejection rather than a
        // pass-through.
        if !headers
            .get("content-type")
            .is_some_and(|ct| is_graphql_json_content_type(ct))
        {
            return reject_uninspectable_transport(
                "GraphQL request uses an unsupported content type; \
                 only JSON content types are inspectable",
            );
        }
        if envelope.is_empty() {
            return reject_uninspectable_transport(
                "GraphQL request body is missing or empty \
                 and cannot be inspected",
            );
        }
        ctx.plugin_state_mut()
            .graphql_request_envelope_hashes
            .insert(self.instance_id, graphql_envelope_digest(envelope));
        self.enforce_graphql_envelope(ctx, envelope).await
    }

    fn needs_final_request_body_context(&self) -> bool {
        self.has_any_config
    }

    /// Claim the finalized envelope so the shared request representation gate
    /// hands this plugin plaintext for a compressed GraphQL upload, or fails the
    /// request closed (`GHSA-3973-47g5-4mcx`).
    fn enforces_final_request_body_policy(
        &self,
        ctx: &RequestContext,
        headers: &HashMap<String, String>,
        _body: &[u8],
    ) -> bool {
        self.has_any_config
            && ctx.plugin_state().is_some_and(|state| {
                state
                    .graphql_request_envelope_hashes
                    .contains_key(&self.instance_id)
            })
            && headers
                .get("content-type")
                .is_some_and(|ct| is_graphql_json_content_type(ct))
    }
}

/// SHA-256 over one GraphQL request envelope.
///
/// Used only to answer "is the dispatched envelope the one already parsed and
/// charged?". It is never logged, exported, or compared against
/// attacker-supplied input; SHA-256 is used rather than a fast non-cryptographic
/// hash because a collision would let a transformed operation reuse the admitted
/// one's decision.
fn graphql_envelope_digest(envelope: &[u8]) -> [u8; 32] {
    crate::fips::approved::Sha256::digest(envelope)
}

/// Top-level envelope members whose value decides what the backend executes.
const GRAPHQL_ENVELOPE_MEMBERS: [&str; 4] = ["query", "operationName", "variables", "extensions"];

/// Whether the envelope's top-level JSON object names one of
/// [`GRAPHQL_ENVELOPE_MEMBERS`] more than once, compared after JSON unescaping
/// (`"qu\u0065ry"` is `query`) and ignoring ASCII case (`Query` is `query`,
/// for backends whose JSON binding ignores case). Only called on a body that
/// already parsed as a JSON object; a body the audit cannot read is treated as
/// repeating one.
fn envelope_repeats_a_graphql_member(body: &[u8]) -> bool {
    match serde_json::from_slice::<EnvelopeMemberAudit>(body) {
        Ok(audit) => audit.repeated,
        Err(_) => true,
    }
}

/// Result of one pass over an envelope's top-level member names.
struct EnvelopeMemberAudit {
    repeated: bool,
}

impl<'de> serde::Deserialize<'de> for EnvelopeMemberAudit {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        deserializer.deserialize_map(EnvelopeMemberAuditVisitor)
    }
}

struct EnvelopeMemberAuditVisitor;

impl<'de> serde::de::Visitor<'de> for EnvelopeMemberAuditVisitor {
    type Value = EnvelopeMemberAudit;

    fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("a GraphQL request envelope object")
    }

    fn visit_map<A>(self, mut map: A) -> Result<Self::Value, A::Error>
    where
        A: serde::de::MapAccess<'de>,
    {
        let mut seen = [false; GRAPHQL_ENVELOPE_MEMBERS.len()];
        let mut repeated = false;
        while let Some(key) = map.next_key::<String>()? {
            map.next_value::<serde::de::IgnoredAny>()?;
            let member = GRAPHQL_ENVELOPE_MEMBERS
                .iter()
                .position(|m| m.eq_ignore_ascii_case(&key));
            if let Some(index) = member {
                repeated |= std::mem::replace(&mut seen[index], true);
            }
        }
        Ok(EnvelopeMemberAudit { repeated })
    }
}

impl GraphqlPlugin {
    /// Parse one GraphQL envelope and apply the complete structural,
    /// introspection, alias, complexity, selection, and rate policy to the
    /// operation it selects.
    ///
    /// Shared by `before_proxy` and the final request-body re-check so the
    /// operation actually dispatched is governed by exactly the same rules as
    /// the one the client first presented.
    async fn enforce_graphql_envelope(
        &self,
        ctx: &mut RequestContext,
        body: &[u8],
    ) -> PluginResult {
        let parsed: Value = match serde_json::from_slice(body) {
            Ok(v) => v,
            Err(_) => {
                debug!("graphql: request body is not valid JSON");
                return reject_uninspectable_transport(
                    "GraphQL request body is not valid JSON \
                     and cannot be inspected",
                );
            }
        };

        let query = match parsed.get("query").and_then(|q| q.as_str()) {
            Some(q) if !q.is_empty() => q,
            _ => {
                // Batch arrays, APQ hash-only envelopes, empty/missing query.
                return reject_uninspectable_transport(
                    "GraphQL request must include an inspectable string \
                     query field; batch arrays and persisted-query \
                     envelopes without a query document are refused",
                );
            }
        };

        // `Value` keeps only the last of a repeated member, while other JSON
        // readers keep the first or refuse the body. A repeated member that
        // decides what the backend executes is therefore refused outright
        // rather than enforced over a copy the backend may not read.
        if envelope_repeats_a_graphql_member(body) {
            return reject_uninspectable_transport(
                "GraphQL request body repeats a top-level query, operationName, \
                 variables, or extensions member",
            );
        }

        let operation_name = parsed.get("operationName").and_then(|n| n.as_str());

        // Parse the GraphQL query and select the operation to analyze. The
        // parser rejects spec-invalid documents (e.g. multiple operations
        // without operationName) and over-budget fragment expansion.
        let op = match parse_graphql_query(query, operation_name) {
            ParsedQuery::Operation(op) => op,
            ParsedQuery::Reject {
                status_code,
                message,
            } => {
                debug!(status_code, %message, "graphql: query rejected during parsing");
                return PluginResult::Reject {
                    status_code,
                    body: graphql_error_body(&message),
                    headers: json_content_type_header(),
                };
            }
        };

        // Store operation info in metadata for logging/downstream plugins
        ctx.metadata
            .insert("graphql_operation_type".to_string(), op.op_type.to_string());
        if let Some(ref name) = op.op_name {
            ctx.metadata
                .insert("graphql_operation_name".to_string(), name.clone());
        }
        ctx.metadata
            .insert("graphql_depth".to_string(), op.depth.to_string());
        ctx.metadata
            .insert("graphql_complexity".to_string(), op.complexity.to_string());

        // Check introspection
        if !self.introspection_allowed && op.is_introspection {
            debug!("graphql: introspection query blocked");
            return PluginResult::Reject {
                status_code: 403,
                body: graphql_error_body("Introspection queries are not allowed"),
                headers: json_content_type_header(),
            };
        }

        // Check depth limit
        if let Some(max_depth) = self.max_depth
            && op.depth > max_depth
        {
            debug!(
                depth = op.depth,
                max_depth, "graphql: query depth exceeds limit"
            );
            return PluginResult::Reject {
                status_code: 400,
                body: depth_error_body(op.depth, max_depth),
                headers: json_content_type_header(),
            };
        }

        // Check complexity limit
        if let Some(max_complexity) = self.max_complexity
            && op.complexity > max_complexity
        {
            debug!(
                complexity = op.complexity,
                max_complexity, "graphql: query complexity exceeds limit"
            );
            return PluginResult::Reject {
                status_code: 400,
                body: complexity_error_body(op.complexity, max_complexity),
                headers: json_content_type_header(),
            };
        }

        // Check alias count limit
        if let Some(max_aliases) = self.max_aliases
            && op.alias_count > max_aliases
        {
            debug!(
                alias_count = op.alias_count,
                max_aliases, "graphql: alias count exceeds limit"
            );
            return PluginResult::Reject {
                status_code: 400,
                body: alias_error_body(op.alias_count, max_aliases),
                headers: json_content_type_header(),
            };
        }

        // Check operation type rate limit. `charge_bucket_once` keeps the
        // second (final-envelope) pass from spending another token on a budget
        // this request already paid.
        let type_bucket = self
            .type_rate_limits
            .get(op.op_type)
            .map(|spec| (self.rate_key(ctx, "type", op.op_type), spec));
        if let Some((key, spec)) = type_bucket
            && self.charge_bucket_once(ctx, &key)
        {
            match self.check_rate(&key, spec).await {
                None => {
                    super::prometheus_metrics::global_registry().record_rate_limit_exceeded();
                    return PluginResult::Reject {
                        status_code: 429,
                        body: CAPACITY_REJECT_BODY.to_string(),
                        headers: json_content_type_header(),
                    };
                }
                Some(outcome) if !outcome.allowed => {
                    // Centralized enforcement could not be consulted under
                    // `redis_failure_policy: "fail_closed"`: refuse without
                    // advertising a budget this gateway is not enforcing. The
                    // shared backend owns the once-per-outage warning.
                    if outcome.enforcement_unavailable {
                        return PluginResult::Reject {
                            status_code: ENFORCEMENT_UNAVAILABLE_STATUS,
                            body: ENFORCEMENT_UNAVAILABLE_BODY.to_string(),
                            headers: json_content_type_header(),
                        };
                    }
                    warn_sampled!(
                        op_type = %op.op_type,
                        plugin = "graphql",
                        "GraphQL operation type rate limit exceeded"
                    );
                    let remaining = outcome.remaining.unwrap_or(0);
                    let mut headers = json_content_type_header();
                    headers.insert(
                        "x-graphql-ratelimit-limit".to_string(),
                        spec.max_requests.to_string(),
                    );
                    headers.insert(
                        "x-graphql-ratelimit-remaining".to_string(),
                        remaining.to_string(),
                    );
                    return PluginResult::Reject {
                        status_code: 429,
                        body: type_rate_limit_error_body(op.op_type),
                        headers,
                    };
                }
                Some(_) => {}
            }
        }

        // Check named operation rate limit, charged at most once per request
        // like the operation-type bucket above.
        let operation_bucket = op.op_name.as_ref().and_then(|op_name| {
            self.operation_rate_limits
                .get(op_name)
                .map(|spec| (op_name, self.rate_key(ctx, "op", op_name), spec))
        });
        if let Some((op_name, key, spec)) = operation_bucket
            && self.charge_bucket_once(ctx, &key)
        {
            match self.check_rate(&key, spec).await {
                None => {
                    super::prometheus_metrics::global_registry().record_rate_limit_exceeded();
                    return PluginResult::Reject {
                        status_code: 429,
                        body: CAPACITY_REJECT_BODY.to_string(),
                        headers: json_content_type_header(),
                    };
                }
                Some(outcome) if !outcome.allowed => {
                    // See the operation-type arm above.
                    if outcome.enforcement_unavailable {
                        return PluginResult::Reject {
                            status_code: ENFORCEMENT_UNAVAILABLE_STATUS,
                            body: ENFORCEMENT_UNAVAILABLE_BODY.to_string(),
                            headers: json_content_type_header(),
                        };
                    }
                    warn_sampled!(
                        operation = %op_name,
                        plugin = "graphql",
                        "GraphQL named operation rate limit exceeded"
                    );
                    let remaining = outcome.remaining.unwrap_or(0);
                    let mut headers = json_content_type_header();
                    headers.insert(
                        "x-graphql-ratelimit-limit".to_string(),
                        spec.max_requests.to_string(),
                    );
                    headers.insert(
                        "x-graphql-ratelimit-remaining".to_string(),
                        remaining.to_string(),
                    );
                    return PluginResult::Reject {
                        status_code: 429,
                        body: operation_rate_limit_error_body(op_name),
                        headers,
                    };
                }
                Some(_) => {}
            }
        }

        PluginResult::Continue
    }
}

/// Returns a header map with `content-type: application/json`.
fn json_content_type_header() -> HashMap<String, String> {
    let mut h = HashMap::new();
    h.insert("content-type".to_string(), "application/json".to_string());
    h
}

/// Reject an HTTP GraphQL representation that cannot be inspected.
fn reject_uninspectable_transport(message: &str) -> PluginResult {
    PluginResult::Reject {
        status_code: 400,
        body: graphql_error_body(message),
        headers: json_content_type_header(),
    }
}

fn graphql_error_body(message: &str) -> String {
    serde_json::json!({ "errors": [{ "message": message }] }).to_string()
}

fn depth_error_body(depth: u32, max_depth: u32) -> String {
    let mut message = String::with_capacity(72);
    let _ = write!(
        &mut message,
        "Query depth {depth} exceeds maximum allowed depth of {max_depth}"
    );
    graphql_error_body(&message)
}

fn complexity_error_body(complexity: u32, max_complexity: u32) -> String {
    let mut message = String::with_capacity(88);
    let _ = write!(
        &mut message,
        "Query complexity {complexity} exceeds maximum allowed complexity of {max_complexity}"
    );
    graphql_error_body(&message)
}

fn alias_error_body(alias_count: u32, max_aliases: u32) -> String {
    let mut message = String::with_capacity(64);
    let _ = write!(
        &mut message,
        "Query uses {alias_count} aliases, maximum allowed is {max_aliases}"
    );
    graphql_error_body(&message)
}

fn type_rate_limit_error_body(op_type: &str) -> String {
    let mut message = String::with_capacity(45 + op_type.len());
    message.push_str("Rate limit exceeded for ");
    message.push_str(op_type);
    message.push_str(" operations");
    graphql_error_body(&message)
}

fn operation_rate_limit_error_body(op_name: &str) -> String {
    let mut message = String::with_capacity(37 + op_name.len());
    message.push_str("Rate limit exceeded for operation '");
    message.push_str(op_name);
    message.push('\'');
    graphql_error_body(&message)
}
