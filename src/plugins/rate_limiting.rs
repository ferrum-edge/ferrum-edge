//! General request rate limiting with optional Redis-backed failover.
//!
//! With `mcp_tool_calls` the same limiter counts MCP JSON-RPC `tools/call`
//! requests instead of HTTP requests (issue #5908): `initialize`,
//! `tools/list`, notifications, and every other method pass uncounted, each
//! `tools/call` member of a batch is one charge, and a refusal is a JSON-RPC
//! error an MCP client can surface.

use crate::plugins::utils::log_sampling::warn_sampled;

use async_trait::async_trait;
use serde_json::Value;
use serde_json::value::RawValue;
use std::collections::{HashMap, HashSet};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

use super::utils::mcp_jsonrpc::{self, RequestScan};
use super::utils::rate_limit::{
    DynamicHttpRateLimitAlgorithm, DynamicRateLimitOp, ENFORCEMENT_UNAVAILABLE_BODY,
    ENFORCEMENT_UNAVAILABLE_STATUS, LocalStateSemantics, RATE_LIMIT_REDIS_CONFIG_KEYS,
    RateLimitBackend, RateLimitOutcome, RateLimitWindowSpec, STANDALONE_RATE_LIMIT_CONFIG_ID,
    apply_rate_limit_cleanup, debug_assert_closed_root_keys, debug_assert_rate_limit_redis_keys,
    validate_max_requests, validate_window_seconds,
};
use super::{Plugin, PluginHttpClient, PluginResult, RequestContext};
use crate::util::unknown_keys::reject_unknown_keys;

const MAX_STATE_ENTRIES: usize = 100_000;
const EVICTION_CHECK_INTERVAL_REQUESTS: u64 = 1024;
/// Bounds below-cap full-map scans under high RPS. Sampled over-cap
/// reclaim skips this cooldown so a sampled observation of pressure can
/// drop idle keys without waiting for the next cool-down window. Live
/// budgets are never force-evicted.
const EVICTION_COOLDOWN_SECS: u64 = 1;
const RATE_LIMIT_IDENTITY_HEADER: &str = "x-ratelimit-identity";

/// Shared request-metadata key naming which composed `rate_limiting` instance
/// currently owns the single public `x-ratelimit-*` header set.
///
/// The three telemetry keys are deliberately NOT instance-scoped: their header
/// names are a fixed public contract, so exactly one instance's values may be
/// published and they must stay internally consistent. Every instance opts into
/// the shared rejection finalizer (`applies_after_proxy_on_reject`), so without
/// an explicit owner the last `after_proxy` in plugin order re-published its own
/// staged budget over the refusal — a client could receive `429` alongside
/// `x-ratelimit-remaining: 98` from a sibling that admitted the same request.
const RATE_LIMIT_AUTHORITY_KEY: &str = "ratelimit_authority";

/// Encoded [`HeaderAuthority::Refused`] verdict.
const RATE_LIMIT_AUTHORITY_REFUSED: &str = "refused";

/// Prefix of an encoded [`HeaderAuthority::Admitted`] verdict, followed by the
/// admitted budget's remaining count.
const RATE_LIMIT_AUTHORITY_ADMITTED_PREFIX: &str = "admitted:";

/// Which composed limiter's telemetry the public `x-ratelimit-*` headers carry.
///
/// Ordering is total and independent of plugin order, so two limiters on one
/// route publish the same headers however they are prioritized:
/// a refusal outranks every admitted budget (the refusing limiter is the one
/// that produced the status the client sees), and among admitted budgets the
/// tightest `remaining` wins — the same "tightest window" rule a single
/// instance already applies across its own windows.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum HeaderAuthority {
    Admitted(u64),
    Refused,
}

impl HeaderAuthority {
    fn encode(self) -> String {
        match self {
            Self::Refused => RATE_LIMIT_AUTHORITY_REFUSED.to_string(),
            Self::Admitted(remaining) => {
                format!("{RATE_LIMIT_AUTHORITY_ADMITTED_PREFIX}{remaining}")
            }
        }
    }

    /// Whether this verdict may take the public header set from `existing`.
    ///
    /// An absent or unrecognized owner yields to the candidate: staged
    /// telemetry with no recorded owner cannot be attributed, and publishing
    /// the current verdict is the fail-safe direction.
    fn outranks(self, existing: Option<&str>) -> bool {
        let Some(existing) = existing else {
            return true;
        };
        if existing == RATE_LIMIT_AUTHORITY_REFUSED {
            // One request has at most one refusal: it short-circuits the chain.
            return false;
        }
        match self {
            Self::Refused => true,
            Self::Admitted(remaining) => existing
                .strip_prefix(RATE_LIMIT_AUTHORITY_ADMITTED_PREFIX)
                .and_then(|value| value.parse::<u64>().ok())
                .is_none_or(|current| remaining < current),
        }
    }
}

/// `rate_limiting`-specific top-level config keys (excludes shared Redis fields).
const RATE_LIMITING_POLICY_CONFIG_KEYS: &[&str] = &[
    "limit_by",
    "ipv6_prefix",
    "expose_headers",
    "limits",
    "mcp_tool_calls",
];

/// Closed key set for the optional `mcp_tool_calls` object.
pub const RATE_LIMITING_MCP_TOOL_CALLS_KEYS: &[&str] = &["endpoint_path", "tools", "per_tool"];

/// Most tool names one `mcp_tool_calls.tools` list may name.
pub const MAX_MCP_TOOL_CALL_TOOLS: usize = 256;

/// Longest tool name `mcp_tool_calls.tools` accepts, in bytes.
pub const MAX_MCP_TOOL_CALL_TOOL_NAME_BYTES: usize = 255;

/// JSON-RPC error code of a `tools/call` refused by an exhausted tool-call
/// budget. In the server-defined range `mcp_gateway` uses for its own
/// gateway errors (`-32001` .. `-32014`).
pub const MCP_TOOL_CALL_RATE_LIMITED: i64 = -32015;

/// JSON-RPC error code of a `tools/call` refused because the tool-call budget
/// cannot be enforced (`redis_failure_policy: fail_closed` during an outage).
pub const MCP_TOOL_CALL_RATE_LIMIT_UNAVAILABLE: i64 = -32016;

/// JSON-RPC error code when an in-scope POST uses a non-identity content coding
/// the governance recognizer cannot inspect (`-32017`). This applies whether
/// or not the body contains `tools/call`; `endpoint_path` narrows the scope.
pub const MCP_TOOL_CALL_UNINSPECTABLE_ENCODING: i64 = -32017;

const MCP_TOOL_CALL_RATE_LIMITED_MESSAGE: &str = "MCP tool-call rate limit exceeded";
const MCP_TOOL_CALL_RATE_LIMIT_UNAVAILABLE_MESSAGE: &str = "MCP tool-call rate limit unavailable";
const MCP_TOOL_CALL_UNINSPECTABLE_ENCODING_MESSAGE: &str =
    "MCP request content encoding cannot be inspected";

/// Closed top-level key set for `rate_limiting` plugin config.
///
/// Must stay aligned with OpenAPI `RateLimitingConfig` (which already declares
/// `additionalProperties: false`), [`RATE_LIMIT_REDIS_CONFIG_KEYS`], and
/// `docs/plugins.md`. Unknown root keys fail closed: a misspelled `sync_mdoe`,
/// `limit_byy`, `redis_tls`, or `redis_key_prefix` previously passed admission
/// whenever a valid `limits` rule let construction succeed, silently replacing
/// distributed enforcement, the caller-identity boundary, Redis transport, or
/// counter isolation with defaults.
pub const RATE_LIMITING_CONFIG_KEYS: &[&str] = &[
    "limit_by",
    "ipv6_prefix",
    "expose_headers",
    "limits",
    "mcp_tool_calls",
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

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum LimitBy {
    Ip,
    Consumer,
    SpiffeIdentity,
}

impl LimitBy {
    /// Canonical rendering of the parsed dimension. `parse_limit_by` accepts
    /// mixed case and the `spiffe` / `spiffe_identity` spellings, all of which
    /// enforce identically, so the *parsed* value is what local-state
    /// compatibility is decided on.
    fn as_str(self) -> &'static str {
        match self {
            Self::Ip => "ip",
            Self::Consumer => "consumer",
            Self::SpiffeIdentity => "spiffe_identity",
        }
    }
}

/// `mcp_tool_calls`: count MCP `tools/call` requests instead of HTTP requests.
struct McpToolCallCounting {
    /// Only requests to exactly this path are inspected (and buffered).
    endpoint_path: Option<String>,
    /// Only calls naming one of these public tool names are counted.
    tools: Option<HashSet<String>>,
    /// Keep one budget per counted tool instead of one for every call.
    per_tool: bool,
}

impl McpToolCallCounting {
    /// Whether this request is in scope: an MCP JSON-RPC exchange is a `POST`.
    fn applies_to(&self, ctx: &RequestContext) -> bool {
        ctx.method.eq_ignore_ascii_case("POST")
            && self
                .endpoint_path
                .as_deref()
                .is_none_or(|path| ctx.path == path)
    }

    /// Whether a call naming `name` is counted.
    fn counts(&self, name: Option<&str>) -> bool {
        match &self.tools {
            None => true,
            Some(tools) => name.is_some_and(|name| tools.contains(name)),
        }
    }
}

/// What one request asks an `mcp_tool_calls` limiter to do. Decided from the
/// request body before any charge, so nothing borrowed from the body outlives
/// the decision.
enum McpToolCallPlan {
    /// No counted `tools/call`: the request passes uncounted.
    Skip,
    /// The body may call a tool but cannot be counted faithfully.
    Refuse,
    /// One charge per entry, in wire order. `Some(name)` charges that tool's
    /// own budget (`per_tool`).
    Charge {
        charges: Vec<Option<String>>,
        replies: McpReplyShape,
    },
}

/// How a JSON-RPC refusal answers the request: one error per request-form
/// member, correlated by the id token the client sent.
#[derive(Default)]
struct McpReplyShape {
    batch: bool,
    /// The id of each request-form member, in wire order. `None` answers
    /// `id: null` (an id past the reflected-id bound).
    ids: Vec<Option<Box<RawValue>>>,
}

/// One admission decision, before it is rendered for HTTP or JSON-RPC.
enum RateVerdict {
    Admitted,
    /// A previously unseen key refused at the state-capacity bound. Carries no
    /// budget of its own.
    Capacity,
    /// Refused by a window (or because enforcement is unavailable).
    Refused(RateLimitOutcome),
}

pub struct RateLimiting {
    limit_by: LimitBy,
    ipv6_prefix: u8,
    expose_headers: bool,
    /// `Some` when this instance counts MCP `tools/call` requests.
    mcp_tool_calls: Option<McpToolCallCounting>,
    default_limit: DynamicRateLimitOp,
    consumer_overrides: HashMap<String, DynamicRateLimitOp>,
    limiter: RateLimitBackend<String, DynamicHttpRateLimitAlgorithm>,
    request_counter: AtomicU64,
    epoch_base: Instant,
    last_periodic_sweep_secs: AtomicU64,
}

impl RateLimiting {
    #[allow(dead_code)] // direct/test construction; production factory supplies the config id
    pub fn new(config: &Value, http_client: PluginHttpClient) -> Result<Self, String> {
        Self::new_with_config_id(config, http_client, STANDALONE_RATE_LIMIT_CONFIG_ID)
    }

    /// Construct with the stable plugin-config resource id that isolates this
    /// policy's default Redis counters from sibling `rate_limiting` instances
    /// in the same namespace. See
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
    /// plugin-config id)` policy identity.
    ///
    /// A reload that does not change this policy's enforcement semantics keeps
    /// the live counters, so a co-tenant churning unrelated configuration can
    /// no longer hand every caller a fresh budget.
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
                "rate_limiting: config must be an object, got: {config:?}",
                config = config.to_string()
            )
        })?;
        // Legacy root window fields get their own actionable diagnostic before
        // the closed-key sweep would report them as merely "unknown".
        reject_legacy_window_fields(object)?;
        // Keeps the documented key groups aligned with the closed root
        // allowlist used for admission and OpenAPI parity.
        debug_assert_rate_limit_redis_keys();
        debug_assert_closed_root_keys(
            RATE_LIMITING_CONFIG_KEYS,
            RATE_LIMITING_POLICY_CONFIG_KEYS,
            RATE_LIMIT_REDIS_CONFIG_KEYS,
        );
        reject_unknown_keys(
            object,
            "config",
            RATE_LIMITING_CONFIG_KEYS,
            "rate_limiting: `config`: ",
        )?;
        let limit_by = parse_limit_by(object)?;
        let ipv6_prefix = match object.get("ipv6_prefix") {
            None => 64,
            Some(Value::Null) => {
                return Err(
                    "rate_limiting: `ipv6_prefix` must be an integer from 1 through 128"
                        .to_string(),
                );
            }
            Some(value) => {
                let prefix = value.as_u64().ok_or_else(|| {
                    "rate_limiting: `ipv6_prefix` must be an integer from 1 through 128".to_string()
                })?;
                u8::try_from(prefix)
                    .ok()
                    .filter(|prefix| (1..=128).contains(prefix))
                    .ok_or_else(|| {
                        "rate_limiting: `ipv6_prefix` must be an integer from 1 through 128"
                            .to_string()
                    })?
            }
        };
        let expose_headers = parse_optional_bool(object, "expose_headers")?.unwrap_or(false);

        let parsed_limits = parse_limits(object)?;
        let mcp_tool_calls = parse_mcp_tool_calls(object)?;
        if !parsed_limits.consumer_overrides.is_empty() && limit_by != LimitBy::Consumer {
            return Err(
                "rate_limiting: consumer-scoped limits can only be used with `limit_by=consumer`"
                    .to_string(),
            );
        }

        // Effective enforcement semantics, not raw syntax: the parsed dimension
        // and the parsed window/consumer budgets. `expose_headers` is response
        // presentation only and never resets a live budget, and the shared
        // Redis posture is added by the backend.
        let mut semantics = LocalStateSemantics::new();
        semantics.text("limit_by", limit_by.as_str());
        semantics.text("ipv6_prefix", &ipv6_prefix.to_string());
        semantics.windows("default_limit", parsed_limits.default_limit.specs());
        semantics.window_map(
            "consumer_limits",
            parsed_limits
                .consumer_overrides
                .iter()
                .map(|(consumer, limit)| (consumer.as_str(), limit.specs())),
        );
        // What is counted is enforcement semantics too: a request counter and
        // a tool-call counter must never share a live budget. Nothing is added
        // for an ordinary request limiter, so its existing budgets survive.
        if let Some(mcp) = mcp_tool_calls.as_ref() {
            semantics.text("count", "mcp_tool_calls");
            semantics.text(
                "mcp_endpoint_path",
                mcp.endpoint_path.as_deref().unwrap_or(""),
            );
            let mut tools: Vec<&str> = mcp.tools.iter().flatten().map(String::as_str).collect();
            tools.sort_unstable();
            semantics.text("mcp_tools", &tools.join("\n"));
            semantics.text("mcp_per_tool", if mcp.per_tool { "true" } else { "false" });
        }

        let limiter = RateLimitBackend::from_plugin_config_with_policy_identity(
            "rate_limiting",
            namespace,
            config_id,
            config,
            &http_client,
            DynamicHttpRateLimitAlgorithm::new(),
            &semantics,
        )
        .map_err(|error| format!("rate_limiting: {error}"))?;

        Ok(Self {
            limit_by,
            ipv6_prefix,
            expose_headers,
            mcp_tool_calls,
            default_limit: parsed_limits.default_limit,
            consumer_overrides: parsed_limits.consumer_overrides,
            limiter,
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

    /// Mark this policy's centralized store unavailable so the next enforcement
    /// decision takes the fail-closed path. `false` for a local-only policy.
    ///
    /// Lets composition tests drive a real `503` through `on_request_received`
    /// with a live `RequestContext`, instead of only through the key-level
    /// helper below. Not a production API.
    #[allow(dead_code)] // used only by external tests; dead in binary test target
    pub(crate) fn mark_redis_unavailable_for_test(&self) -> bool {
        match self.limiter.redis_client_arc_for_test() {
            Some(client) => {
                client.mark_unavailable_for_test();
                true
            }
            None => false,
        }
    }

    /// Mark the centralized store unavailable, run one admission against the
    /// default limit, and report the refusal this plugin would emit — `None`
    /// when the request was still allowed (i.e. it degraded to local state).
    ///
    /// Exercises the production [`Self::reject`] mapping so the fail-closed
    /// status/body cannot drift from the outage path. Not a production API.
    #[allow(dead_code)] // used only by external tests; dead in binary test target
    pub(crate) async fn refusal_under_redis_outage_for_test(
        &self,
        key: &str,
    ) -> Option<(u16, String)> {
        if let Some(client) = self.limiter.redis_client_arc_for_test() {
            client.mark_unavailable_for_test();
        }
        let Some(outcome) = self
            .limiter
            .check_with_redis_key_and_local_capacity(
                key.to_string(),
                || key.to_string(),
                &self.default_limit,
                MAX_STATE_ENTRIES,
            )
            .await
        else {
            return match self.reject_capacity() {
                PluginResult::Reject {
                    status_code, body, ..
                } => Some((status_code, body)),
                _ => None,
            };
        };
        if outcome.allowed {
            return None;
        }
        match self.reject(&outcome) {
            PluginResult::Reject {
                status_code, body, ..
            } => Some((status_code, body)),
            _ => None,
        }
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
        let _ = self.limiter.check_local_at(key, &self.default_limit, now);
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
        self.limiter
            .check_local_at_with_capacity(key, &self.default_limit, now, max_entries)
            .is_some()
    }

    /// Arm the sampled below-cap gate without spinning 1024 requests. Test-only.
    #[allow(dead_code)] // used only by external tests; dead in binary test target
    pub(crate) fn arm_periodic_eviction_for_test(&self) {
        self.request_counter
            .store(EVICTION_CHECK_INTERVAL_REQUESTS, Ordering::Relaxed);
        self.last_periodic_sweep_secs.store(0, Ordering::Relaxed);
    }

    /// Block the below-cap cooldown so an armed sample does not scan. Test-only.
    #[allow(dead_code)] // used only by external tests; dead in binary test target
    pub(crate) fn block_periodic_cooldown_at_for_test(&self, now: Instant) {
        let now_secs = now.saturating_duration_since(self.epoch_base).as_secs();
        self.last_periodic_sweep_secs
            .store(now_secs, Ordering::Relaxed);
    }

    /// Invoke the production cleanup wrapper at `now`. Test-only.
    #[allow(dead_code)] // used only by external tests; dead in binary test target
    pub(crate) fn maybe_evict_stale_entries_at_for_test(&self, now: Instant) {
        self.maybe_evict_stale_entries_at(now);
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

    fn maybe_evict_stale_entries(&self) {
        self.maybe_evict_stale_entries_at(Instant::now());
    }

    fn maybe_evict_stale_entries_at(&self, now: Instant) {
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
        // retain per second so high RPS cannot turn periodic reclamation into
        // an unbounded scan storm.
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

        ip_key(&ctx.client_ip, self.ipv6_prefix)
    }

    fn request_limit_op(&self, ctx: &RequestContext) -> &DynamicRateLimitOp {
        if self.limit_by == LimitBy::Consumer
            && let Some(identity) = ctx.effective_identity()
            && let Some(limit) = self.consumer_overrides.get(identity)
        {
            return limit;
        }

        &self.default_limit
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

        ip_key(&ctx.client_ip, self.ipv6_prefix)
    }

    fn stream_limit_op(&self, ctx: &super::StreamConnectionContext) -> &DynamicRateLimitOp {
        if self.limit_by == LimitBy::Consumer
            && let Some(identity) = ctx.effective_identity()
            && let Some(limit) = self.consumer_overrides.get(identity)
        {
            return limit;
        }

        &self.default_limit
    }

    fn reject(&self, outcome: &RateLimitOutcome) -> PluginResult {
        // Never reflect the rate-limit key (limiter identity) back to the
        // downstream client. For limit_by=consumer/spiffe the key embeds the
        // gateway's internal notion of the caller identity (consumer username) or
        // the peer workload SVID — information the client did not necessarily
        // supply in that form. Only the standard, non-sensitive
        // limit/remaining/window headers are exposed.
        // A fail-closed refusal is not a budget verdict: this gateway has no
        // authoritative counter to report, so no rate-limit headers are set and
        // the status distinguishes "cannot enforce" from "over limit".
        if outcome.enforcement_unavailable {
            return PluginResult::Reject {
                status_code: ENFORCEMENT_UNAVAILABLE_STATUS,
                body: ENFORCEMENT_UNAVAILABLE_BODY.into(),
                headers: HashMap::new(),
            };
        }

        PluginResult::Reject {
            status_code: 429,
            body: r#"{"error":"Rate limit exceeded"}"#.into(),
            headers: self.refusal_headers(outcome),
        }
    }

    /// The `x-ratelimit-*` headers a quota refusal carries (none unless
    /// `expose_headers`).
    fn refusal_headers(&self, outcome: &RateLimitOutcome) -> HashMap<String, String> {
        let mut headers = HashMap::with_capacity(3);
        if self.expose_headers {
            if let Some(limit) = outcome.limit {
                headers.insert("x-ratelimit-limit".to_string(), limit.to_string());
            }
            headers.insert("x-ratelimit-remaining".to_string(), "0".to_string());
            if let Some(window) = outcome.window_seconds {
                headers.insert("x-ratelimit-window".to_string(), window.to_string());
            }
        }
        headers
    }

    fn store_metadata(&self, outcome: &RateLimitOutcome, ctx: &mut RequestContext) {
        if !self.expose_headers {
            return;
        }

        // An outcome with no remaining count has nothing to publish, so it must
        // not displace what a sibling already staged. (`allow()` only omits it
        // when a policy has no windows at all, which admission rejects.)
        let Some(remaining) = outcome.remaining else {
            return;
        };

        // A composed sibling may already own the public header set. Only the
        // tightest admitted budget publishes, so the client is told to back off
        // against the limit that will actually refuse it next.
        let authority = HeaderAuthority::Admitted(remaining);
        let owner = ctx.metadata.get(RATE_LIMIT_AUTHORITY_KEY);
        if !authority.outranks(owner.map(String::as_str)) {
            return;
        }

        // Intentionally does not store the rate-limit key/identity: it would be
        // injected onto the downstream response by after_proxy and disclose the
        // gateway's internal consumer/SPIFFE identity to the client.
        self.claim_published_headers(ctx, authority);
        if let Some(limit) = outcome.limit {
            ctx.metadata
                .insert("ratelimit_limit".to_string(), limit.to_string());
        }
        ctx.metadata
            .insert("ratelimit_remaining".to_string(), remaining.to_string());
        if let Some(window) = outcome.window_seconds {
            ctx.metadata
                .insert("ratelimit_window".to_string(), window.to_string());
        }
    }

    /// Record a new owner and drop every value the previous one staged.
    ///
    /// Clearing is what makes the takeover complete: `after_proxy` publishes
    /// whichever of the three keys are present, so a partial overwrite would
    /// mix this limiter's `limit` with a sibling's `remaining`.
    fn claim_published_headers(&self, ctx: &mut RequestContext, authority: HeaderAuthority) {
        for &(meta_key, _) in EXPOSED_RATELIMIT_HEADERS {
            ctx.metadata.remove(meta_key);
        }
        ctx.metadata
            .insert(RATE_LIMIT_AUTHORITY_KEY.to_string(), authority.encode());
    }

    /// Take the public header set for a refusal produced by this limiter.
    ///
    /// The refusing limiter authored the status the client sees, so its verdict
    /// is the only telemetry that may describe the response. A sibling that
    /// admitted this request earlier is discarded, and the shared rejection
    /// finalizer then re-publishes these values from every instance identically
    /// instead of restoring the admitted budget.
    ///
    /// A fail-closed refusal publishes nothing at all: this gateway has no
    /// authoritative counter to report, which is also why `reject` sets no
    /// headers on `ENFORCEMENT_UNAVAILABLE_STATUS`. `expose_headers: false` on
    /// the refusing limiter likewise publishes nothing — that policy's verdict
    /// is that the client is told no budget.
    fn claim_refusal_headers(&self, outcome: &RateLimitOutcome, ctx: &mut RequestContext) {
        self.claim_published_headers(ctx, HeaderAuthority::Refused);
        if outcome.enforcement_unavailable || !self.expose_headers {
            return;
        }
        if let Some(limit) = outcome.limit {
            ctx.metadata
                .insert("ratelimit_limit".to_string(), limit.to_string());
        }
        ctx.metadata
            .insert("ratelimit_remaining".to_string(), "0".to_string());
        if let Some(window) = outcome.window_seconds {
            ctx.metadata
                .insert("ratelimit_window".to_string(), window.to_string());
        }
    }

    fn reject_capacity(&self) -> PluginResult {
        // Capacity denial is fail-closed for previously unseen local/fallback
        // keys. Do not reflect limiter identity back to the client or emit an
        // attacker-rate warning for every new key; the counter is the bounded
        // operational signal.
        super::prometheus_metrics::global_registry().record_rate_limit_exceeded();
        PluginResult::Reject {
            status_code: 429,
            body: r#"{"error":"Rate limit exceeded"}"#.into(),
            headers: HashMap::new(),
        }
    }

    /// Attribute one decision to the per-process fallback budget.
    ///
    /// The metadata marker is sticky across composed instances: any fallback is
    /// operationally relevant, even when another limiter owns the public
    /// headers. The counter is the alertable form of the same fact —
    /// `rate_limiting` defaults to `redis_failure_policy: local_fallback`, so
    /// degraded enforcement is the silent common case and the latched
    /// once-per-outage warning is not enough on its own.
    fn mark_local_fallback(&self, ctx: &mut RequestContext) {
        ctx.metadata
            .insert("ratelimit_local_fallback".to_string(), "true".to_string());
        super::prometheus_metrics::global_registry().record_rate_limit_local_fallback_decision();
    }

    async fn check_rate(
        &self,
        key: String,
        limit_op: &DynamicRateLimitOp,
        ctx: &mut RequestContext,
    ) -> PluginResult {
        match self.decide(key, limit_op, ctx).await {
            RateVerdict::Admitted => PluginResult::Continue,
            RateVerdict::Capacity => self.reject_capacity(),
            RateVerdict::Refused(outcome) => self.reject(&outcome),
        }
    }

    /// Charge one unit against `key` and record the decision's telemetry and
    /// metrics. Rendering the refusal is the caller's: an HTTP request limiter
    /// answers `429` / `503`, an `mcp_tool_calls` limiter a JSON-RPC error.
    async fn decide(
        &self,
        key: String,
        limit_op: &DynamicRateLimitOp,
        ctx: &mut RequestContext,
    ) -> RateVerdict {
        // Run sampled idle reclamation before admission. Capacity denial must
        // still advance the cleanup schedule; otherwise an exactly-full map of
        // expired keys could remain pinned closed when only new identities
        // arrive. Cleanup never removes live budgets.
        self.maybe_evict_stale_entries();
        let decision = self
            .limiter
            .check_with_redis_key_and_local_capacity_attributed(
                key.clone(),
                || key.clone(),
                limit_op,
                MAX_STATE_ENTRIES,
            )
            .await;
        let Some(outcome) = decision.outcome else {
            // A capacity denial carries no budget of its own, and a composed
            // sibling's admitted budget must not be published as its verdict.
            self.claim_published_headers(ctx, HeaderAuthority::Refused);
            // A capacity denial reached while THIS decision was being served on
            // the per-process fallback budget IS a fallback-caused refusal, and
            // the one an operator most needs attributed: a Redis-backed policy
            // suddenly hitting the local key cap is an outage symptom, not
            // client behaviour. The `Some(outcome)` arms below carry the marker
            // on the outcome; this arm has none, so it reads the provenance the
            // decision carried out with it. Asking the backend whether it is
            // unavailable *now* would answer a different question and lose the
            // attribution for every per-decision fallback (a staleness
            // rollover, an unpairable reply) that leaves the client healthy.
            if decision.local_fallback {
                self.mark_local_fallback(ctx);
            }
            return RateVerdict::Capacity;
        };
        if outcome.local_fallback {
            self.mark_local_fallback(ctx);
        }
        if !outcome.allowed {
            // The refusing limiter owns the client-visible telemetry from here
            // on; see `claim_refusal_headers`.
            self.claim_refusal_headers(&outcome, ctx);
            if outcome.enforcement_unavailable {
                // The shared failover backend emits one bounded operational
                // warning per outage. Avoid an attacker-rate warning for every
                // request while centralized enforcement is unavailable; the
                // bounded counter is the per-request operational signal.
                super::prometheus_metrics::global_registry()
                    .record_rate_limit_enforcement_unavailable();
                return RateVerdict::Refused(outcome);
            }
            super::prometheus_metrics::global_registry().record_rate_limit_exceeded();
            // The rate-limit key embeds the identity dimension (consumer
            // username, authenticated identity, SPIFFE ID, or client IP), so it
            // is never logged. Enforcement outcomes are attributed through the
            // transaction summary, which applies metadata redaction.
            warn_sampled!(plugin = "rate_limiting", "Rate limit exceeded");
            return RateVerdict::Refused(outcome);
        }

        self.store_metadata(&outcome, ctx);
        RateVerdict::Admitted
    }

    /// Decide what an `mcp_tool_calls` limiter charges for `body`.
    ///
    /// Only `tools/call` members are counted — `initialize`, `tools/list`,
    /// notifications, and every other method pass uncounted — and a batch is
    /// one charge per counted `tools/call` member. Recognition is shared with
    /// `mcp_gateway` and the other AI governance plugins
    /// ([`mcp_jsonrpc::scan_request_bytes`]), so escaped member names count and
    /// an ambiguous or over-bound batch is refused rather than read one way
    /// here and another way downstream.
    fn mcp_tool_call_plan(&self, mcp: &McpToolCallCounting, body: &[u8]) -> McpToolCallPlan {
        let (batch, members) = match mcp_jsonrpc::scan_request_bytes(body) {
            RequestScan::NoToolCall => return McpToolCallPlan::Skip,
            RequestScan::Uninspectable(_) => return McpToolCallPlan::Refuse,
            RequestScan::ToolCalls { batch, members } => (batch, members),
        };
        let charges: Vec<Option<String>> = members
            .iter()
            .filter_map(|member| member.tool_call.as_ref())
            .filter(|call| mcp.counts(call.name.as_deref()))
            .map(|call| call.name.clone().filter(|_| mcp.per_tool))
            .collect();
        if charges.is_empty() {
            return McpToolCallPlan::Skip;
        }
        let ids = members
            .iter()
            .filter_map(|member| member.id)
            .map(|id| {
                (id.get().len() <= mcp_jsonrpc::MAX_REFLECTED_ID_BYTES).then(|| id.to_owned())
            })
            .collect();
        McpToolCallPlan::Charge {
            charges,
            replies: McpReplyShape { batch, ids },
        }
    }

    /// Count this request's `tools/call` members against the tool-call budget.
    ///
    /// Charges are taken in wire order and the first refused charge refuses
    /// the whole request (a JSON-RPC batch is one HTTP exchange and cannot be
    /// forwarded in part). Charges admitted before that refusal stay charged:
    /// a batch that crosses the budget boundary consumes what was left of it,
    /// which is the conservative direction.
    async fn check_mcp_tool_calls(
        &self,
        mcp: &McpToolCallCounting,
        ctx: &mut RequestContext,
        headers: &HashMap<String, String>,
    ) -> PluginResult {
        // `mcp_gateway` admits JSON (`application/json`, `application/json-rpc`,
        // `+json`) and a request with no `Content-Type` at all, so the counter
        // must see exactly that set: a narrower one would let a client omit
        // the header and call tools uncounted.
        if !mcp.applies_to(ctx)
            || headers
                .get("content-type")
                .is_some_and(|value| !mcp_jsonrpc::content_type_is_json(value))
        {
            return PluginResult::Continue;
        }
        if headers.get("content-encoding").is_some_and(|value| {
            value
                .split(',')
                .map(str::trim)
                .any(|token| !token.is_empty() && !token.eq_ignore_ascii_case("identity"))
        }) {
            ctx.metadata.insert(
                "ratelimit_mcp_uninspectable".to_string(),
                "unsupported_content_encoding".to_string(),
            );
            return mcp_jsonrpc_refusal(
                &McpReplyShape::default(),
                MCP_TOOL_CALL_UNINSPECTABLE_ENCODING,
                MCP_TOOL_CALL_UNINSPECTABLE_ENCODING_MESSAGE,
                HashMap::new(),
            );
        }
        let plan = match mcp_request_body(ctx) {
            Some(body) => self.mcp_tool_call_plan(mcp, body),
            None => McpToolCallPlan::Skip,
        };
        let (charges, replies) = match plan {
            McpToolCallPlan::Skip => return PluginResult::Continue,
            McpToolCallPlan::Refuse => {
                ctx.metadata.insert(
                    "ratelimit_mcp_uninspectable".to_string(),
                    "true".to_string(),
                );
                return mcp_jsonrpc_refusal(
                    &McpReplyShape::default(),
                    -32600,
                    "Invalid MCP JSON-RPC request",
                    HashMap::new(),
                );
            }
            McpToolCallPlan::Charge { charges, replies } => (charges, replies),
        };
        ctx.metadata.insert(
            "ratelimit_mcp_tool_calls".to_string(),
            charges.len().to_string(),
        );
        let base_key = self.request_key(ctx);
        let limit_op = self.request_limit_op(ctx);
        for tool in &charges {
            let key = match tool {
                Some(name) => per_tool_key(name, &base_key),
                None => base_key.clone(),
            };
            match self.decide(key, limit_op, ctx).await {
                RateVerdict::Admitted => {}
                RateVerdict::Capacity => {
                    super::prometheus_metrics::global_registry().record_rate_limit_exceeded();
                    return mcp_jsonrpc_refusal(
                        &replies,
                        MCP_TOOL_CALL_RATE_LIMITED,
                        MCP_TOOL_CALL_RATE_LIMITED_MESSAGE,
                        HashMap::new(),
                    );
                }
                RateVerdict::Refused(outcome) if outcome.enforcement_unavailable => {
                    return mcp_jsonrpc_refusal(
                        &replies,
                        MCP_TOOL_CALL_RATE_LIMIT_UNAVAILABLE,
                        MCP_TOOL_CALL_RATE_LIMIT_UNAVAILABLE_MESSAGE,
                        HashMap::new(),
                    );
                }
                RateVerdict::Refused(outcome) => {
                    return mcp_jsonrpc_refusal(
                        &replies,
                        MCP_TOOL_CALL_RATE_LIMITED,
                        MCP_TOOL_CALL_RATE_LIMITED_MESSAGE,
                        self.refusal_headers(&outcome),
                    );
                }
            }
        }
        PluginResult::Continue
    }

    async fn check_rate_stream(
        &self,
        key: String,
        limit_op: &DynamicRateLimitOp,
        ctx: &mut super::StreamConnectionContext,
    ) -> PluginResult {
        self.maybe_evict_stale_entries();
        // Attribution travels with the decision, exactly as `check_rate` does
        // above: a capacity refusal taken on the local fallback budget is
        // marked from the decision that took it, never reconstructed from the
        // client's availability signal (a second sub-bucket rollover refuses
        // through the failure policy while that signal still reads available).
        let decision = self
            .limiter
            .check_with_redis_key_and_local_capacity_attributed(
                key.clone(),
                || key.clone(),
                limit_op,
                MAX_STATE_ENTRIES,
            )
            .await;
        let Some(outcome) = decision.outcome else {
            if decision.local_fallback {
                ctx.metadata
                    .get_or_insert_with(HashMap::new)
                    .insert("ratelimit_local_fallback".to_string(), "true".to_string());
                super::prometheus_metrics::global_registry()
                    .record_rate_limit_local_fallback_decision();
            }
            return self.reject_capacity();
        };
        if outcome.local_fallback {
            ctx.metadata
                .get_or_insert_with(HashMap::new)
                .insert("ratelimit_local_fallback".to_string(), "true".to_string());
            super::prometheus_metrics::global_registry()
                .record_rate_limit_local_fallback_decision();
        }
        if !outcome.allowed {
            if outcome.enforcement_unavailable {
                // See `check_rate`: the backend owns bounded outage
                // observability, and a 503 is not a rate-limit exceedance.
                super::prometheus_metrics::global_registry()
                    .record_rate_limit_enforcement_unavailable();
                return self.reject(&outcome);
            }
            super::prometheus_metrics::global_registry().record_rate_limit_exceeded();
            // Identity-bearing key deliberately omitted (see `check_rate`).
            warn_sampled!(plugin = "rate_limiting", "Rate limit exceeded (stream)");
            return self.reject(&outcome);
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
        // `tools/call` is an HTTP JSON-RPC exchange; a tool-call limiter has
        // nothing to count on a stream, WebSocket, or gRPC request.
        if self.mcp_tool_calls.is_some() {
            super::HTTP_ONLY_PROTOCOLS
        } else {
            super::ALL_PROTOCOLS
        }
    }

    fn tracked_keys_count(&self) -> Option<usize> {
        Some(self.limiter.tracked_keys_count())
    }

    /// A tool-call limiter reads the buffered JSON-RPC body in `before_proxy`.
    fn requires_request_body_before_before_proxy(&self) -> bool {
        self.mcp_tool_calls.is_some()
    }

    /// Only an in-scope MCP `POST` is buffered: JSON (the media types
    /// `mcp_gateway` admits) or no `Content-Type` at all, and only on
    /// `mcp_tool_calls.endpoint_path` when one is configured.
    fn should_buffer_request_body(&self, ctx: &RequestContext) -> bool {
        self.mcp_tool_calls.as_ref().is_some_and(|mcp| {
            mcp.applies_to(ctx)
                && ctx
                    .headers
                    .get("content-type")
                    .is_none_or(|value| mcp_jsonrpc::content_type_is_json(value))
        })
    }

    fn modifies_request_headers(&self) -> bool {
        true
    }

    /// The exposed `x-ratelimit-*` set and the stripped identity header.
    fn modified_request_header_names(&self) -> Option<Vec<String>> {
        let mut names = EXPOSED_RATELIMIT_POLICY_NAMES.to_vec();
        names.push(RATE_LIMIT_IDENTITY_HEADER.to_string());
        Some(names)
    }

    fn warmup_hostnames(&self) -> Vec<String> {
        self.limiter.warmup_hostname().into_iter().collect()
    }

    async fn on_stream_connect(
        &self,
        ctx: &mut super::StreamConnectionContext,
    ) -> super::PluginResult {
        if self.mcp_tool_calls.is_some() {
            return PluginResult::Continue;
        }
        let key = self.stream_key(ctx);
        let limit_op = self.stream_limit_op(ctx);
        self.check_rate_stream(key, limit_op, ctx).await
    }

    async fn on_request_received(&self, ctx: &mut RequestContext) -> PluginResult {
        // A tool-call limiter charges `tools/call` members in `before_proxy`,
        // once the JSON-RPC body is buffered, never the HTTP request itself.
        if self.mcp_tool_calls.is_some() || self.limit_by != LimitBy::Ip {
            return PluginResult::Continue;
        }

        let ip_key = self.request_key(ctx);
        let limit_op = self.request_limit_op(ctx);
        self.check_rate(ip_key, limit_op, ctx).await
    }

    async fn authorize(&self, ctx: &mut RequestContext) -> PluginResult {
        if self.mcp_tool_calls.is_some()
            || !matches!(self.limit_by, LimitBy::Consumer | LimitBy::SpiffeIdentity)
        {
            return PluginResult::Continue;
        }

        let key = self.request_key(ctx);
        let limit_op = self.request_limit_op(ctx);
        self.check_rate(key, limit_op, ctx).await
    }

    fn is_authorize_plugin(&self) -> bool {
        self.mcp_tool_calls.is_none()
            && matches!(self.limit_by, LimitBy::Consumer | LimitBy::SpiffeIdentity)
    }

    /// Never reusable, in any `limit_by` mode (issue #5583). A limit is a
    /// per-operation CHARGE: reuse would consume one token on the CONNECT and
    /// then let an unbounded number of later operations ride free, which is the
    /// budget bypass this classification exists to prevent. The trait default
    /// already refuses; this override says so in the plugin that charges,
    /// because the mode is exactly what makes the answer non-obvious — IP
    /// limiting charges in `on_request_received` rather than in the authorize
    /// phase, so no authorize-phase marker on this plugin describes it.
    fn allows_hbone_inner_reuse(&self) -> bool {
        false
    }

    /// Participate in the shared rejection/synthetic finalizer so an admitted,
    /// counted request still receives `x-ratelimit-*` decoration (and identity
    /// stripping) when a later plugin short-circuits or rejects. `after_proxy`
    /// remains a no-op for header injection when metadata is absent, so requests
    /// that never reached the rate-limit check are not given synthesized values.
    fn applies_after_proxy_on_reject(&self) -> bool {
        true
    }

    async fn before_proxy(
        &self,
        ctx: &mut RequestContext,
        headers: &mut HashMap<String, String>,
    ) -> PluginResult {
        if let Some(mcp) = self.mcp_tool_calls.as_ref() {
            let verdict = self.check_mcp_tool_calls(mcp, ctx, headers).await;
            if !matches!(verdict, PluginResult::Continue) {
                return verdict;
            }
        }
        remove_rate_limit_identity_header(headers);
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
        remove_rate_limit_identity_header(response_headers);
        if !self.expose_headers {
            return PluginResult::Continue;
        }
        inject_rate_limit_headers_from_metadata(&ctx.metadata, response_headers);
        PluginResult::Continue
    }

    /// These telemetry writes are unconditional `insert`s of a gateway-computed
    /// value, so a backend that pre-populates the identical bytes makes them
    /// invisible to net-diff mutation tracking. Without this declaration, a
    /// later body/committed hook that exhausts the gRPC deadline would rebuild
    /// the DEADLINE_EXCEEDED response with the operator's rate-limit telemetry
    /// silently dropped. Mirrors `ai_rate_limiter`: sourced from the same
    /// [`EXPOSED_RATELIMIT_HEADERS`] table `after_proxy` writes from so the two
    /// cannot drift apart, and gated on the same `expose_headers` +
    /// metadata-presence conditions so nothing is claimed that was not actually
    /// written on this request.
    fn owns_deadline_response_header(&self, ctx: &RequestContext, name: &str) -> bool {
        if !self.expose_headers {
            return false;
        }
        for &(meta_key, header_name) in EXPOSED_RATELIMIT_HEADERS {
            if name.eq_ignore_ascii_case(header_name) && ctx.metadata.contains_key(meta_key) {
                return true;
            }
        }
        false
    }

    /// Config-time form of the same ownership. The exposed rate-limit values are
    /// the gateway's own accounting; a backend trailer repeating one would hand
    /// the client a budget the gateway never computed, and a backend echoing an
    /// identical value hides the `after_proxy` write from observed-mutation
    /// reconciliation. Empty when `expose_headers` is off, so a limiter that
    /// writes no response headers governs no trailers.
    fn response_trailer_policy(&self) -> super::ResponseTrailerPolicy<'_> {
        if self.expose_headers {
            super::ResponseTrailerPolicy::Names(&EXPOSED_RATELIMIT_POLICY_NAMES)
        } else {
            super::ResponseTrailerPolicy::None
        }
    }
}

/// Parse the optional `mcp_tool_calls` object.
fn parse_mcp_tool_calls(
    object: &serde_json::Map<String, Value>,
) -> Result<Option<McpToolCallCounting>, String> {
    let config = match object.get("mcp_tool_calls") {
        None | Some(Value::Null) => return Ok(None),
        Some(Value::Object(config)) => config,
        Some(_) => return Err("rate_limiting: `mcp_tool_calls` must be an object".to_string()),
    };
    reject_unknown_keys(
        config,
        "config.mcp_tool_calls",
        RATE_LIMITING_MCP_TOOL_CALLS_KEYS,
        "rate_limiting: `mcp_tool_calls`: ",
    )?;
    let endpoint_path = match config.get("endpoint_path") {
        None | Some(Value::Null) => None,
        Some(Value::String(path)) if valid_mcp_endpoint_path(path) => Some(path.clone()),
        Some(_) => {
            return Err(
                "rate_limiting: `mcp_tool_calls.endpoint_path` must be a path starting with `/`, without a query, fragment, or control character"
                    .to_string(),
            );
        }
    };
    let tools = match config.get("tools") {
        None | Some(Value::Null) => None,
        Some(Value::Array(entries)) => {
            if entries.is_empty() || entries.len() > MAX_MCP_TOOL_CALL_TOOLS {
                return Err(format!(
                    "rate_limiting: `mcp_tool_calls.tools` must name between 1 and {MAX_MCP_TOOL_CALL_TOOLS} tools"
                ));
            }
            let mut tools = HashSet::with_capacity(entries.len());
            for (idx, entry) in entries.iter().enumerate() {
                let Some(name) = entry.as_str().filter(|name| valid_mcp_tool_name(name)) else {
                    return Err(format!(
                        "rate_limiting: `mcp_tool_calls.tools[{idx}]` must be a non-empty tool name of at most {MAX_MCP_TOOL_CALL_TOOL_NAME_BYTES} bytes without control characters"
                    ));
                };
                if !tools.insert(name.to_string()) {
                    return Err(format!(
                        "rate_limiting: `mcp_tool_calls.tools[{idx}]` duplicates an earlier entry"
                    ));
                }
            }
            Some(tools)
        }
        Some(_) => {
            return Err(
                "rate_limiting: `mcp_tool_calls.tools` must be an array of tool names".to_string(),
            );
        }
    };
    let per_tool = match config.get("per_tool") {
        None | Some(Value::Null) => false,
        Some(Value::Bool(per_tool)) => *per_tool,
        Some(_) => {
            return Err("rate_limiting: `mcp_tool_calls.per_tool` must be a boolean".to_string());
        }
    };
    if per_tool && tools.is_none() {
        return Err(
            "rate_limiting: `mcp_tool_calls.per_tool` requires `mcp_tool_calls.tools`: a per-tool budget is kept only for configured tool names, so a caller cannot mint limiter state with invented names"
                .to_string(),
        );
    }
    Ok(Some(McpToolCallCounting {
        endpoint_path,
        tools,
        per_tool,
    }))
}

/// An `mcp_tool_calls.endpoint_path` is compared with the request path, so it
/// is a path: no query, fragment, or control character.
fn valid_mcp_endpoint_path(path: &str) -> bool {
    path.starts_with('/') && !path.contains(['?', '#']) && !path.chars().any(char::is_control)
}

fn valid_mcp_tool_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= MAX_MCP_TOOL_CALL_TOOL_NAME_BYTES
        && !name.chars().any(char::is_control)
}

/// The buffered request body, read exactly as `mcp_gateway` reads it.
fn mcp_request_body(ctx: &RequestContext) -> Option<&[u8]> {
    ctx.request_body_bytes
        .as_ref()
        .map(|body| body.as_ref())
        .or_else(|| ctx.metadata.get("request_body").map(|body| body.as_bytes()))
}

/// The key of one tool's own budget for the caller keyed `base_key`.
///
/// The tool name is length-prefixed, so no identity text can make one
/// caller's per-tool key equal another caller's: every such key starts with
/// `tool:<len>:`, which no `ip:` / `consumer:` / `spiffe:` key does.
fn per_tool_key(tool: &str, base_key: &str) -> String {
    let length = tool.len().to_string();
    let mut key = String::with_capacity(7 + length.len() + tool.len() + base_key.len());
    key.push_str("tool:");
    key.push_str(&length);
    key.push(':');
    key.push_str(tool);
    key.push('|');
    key.push_str(base_key);
    key
}

/// A JSON-RPC error answering every request-form member of a refused MCP
/// request, on HTTP `200`.
///
/// HTTP `200` is deliberate and matches `mcp_gateway`, which answers every
/// JSON-RPC error on `200`: the MCP streamable HTTP clients resolve the
/// pending request from a JSON-RPC error body on a 2xx response and surface
/// its code and message, while a non-2xx POST response is raised as a
/// transport failure that loses both. The `x-ratelimit-*` headers still carry
/// the budget. A batch is answered with one error per request-form member
/// (notifications get none); a refusal with no request-form member at all is
/// one error with `id: null`, as `mcp_gateway` answers a blocked
/// notification-only batch. `message` is a compiled-in literal and every id is
/// the member's own already-parsed JSON token, so nothing is re-escaped.
fn mcp_jsonrpc_refusal(
    replies: &McpReplyShape,
    code: i64,
    message: &'static str,
    mut headers: HashMap<String, String>,
) -> PluginResult {
    headers.insert("content-type".to_string(), "application/json".to_string());
    let member = |id: Option<&RawValue>| {
        let id = id.map_or("null", RawValue::get);
        format!(r#"{{"jsonrpc":"2.0","id":{id},"error":{{"code":{code},"message":"{message}"}}}}"#)
    };
    let body = if replies.batch && !replies.ids.is_empty() {
        let members: Vec<String> = replies.ids.iter().map(|id| member(id.as_deref())).collect();
        format!("[{}]", members.join(","))
    } else {
        member(replies.ids.first().and_then(|id| id.as_deref()))
    };
    PluginResult::Reject {
        status_code: 200,
        body,
        headers,
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
                "rate_limiting: `limit_by` must be one of `ip`, `consumer`, or `spiffe_identity`, got: {value:?}"
            )),
        },
        Some(other) => Err(format!(
            "rate_limiting: `limit_by` must be a string, got: {other:?}",
            other = other.to_string()
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
                .ok_or_else(|| format!("rate_limiting: `{field}` must be a boolean"))
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
                .ok_or_else(|| format!("rate_limiting: `{field}` must be an integer"))
        })
        .transpose()
}

fn parse_window_specs(
    label: &str,
    object: &serde_json::Map<String, Value>,
) -> Result<Vec<RateLimitWindowSpec>, String> {
    let has_preset = [
        "requests_per_second",
        "requests_per_minute",
        "requests_per_hour",
    ]
    .iter()
    .any(|field| object.contains_key(*field));
    let has_custom = object.contains_key("window_seconds") || object.contains_key("max_requests");
    if has_preset && has_custom {
        return Err(format!(
            "{label}: cannot combine `window_seconds`/`max_requests` with `requests_per_second`/`requests_per_minute`/`requests_per_hour` in the same rule"
        ));
    }

    if let Some(window_seconds) = parse_optional_u64(object, "window_seconds")? {
        let window_seconds = validate_window_seconds(label, "window_seconds", window_seconds)?;
        let max_requests = parse_optional_u64(object, "max_requests")?.ok_or_else(|| {
            format!("{label}: `max_requests` is required when `window_seconds` is set")
        })?;
        let max_requests = validate_max_requests(label, "max_requests", max_requests)?;
        return Ok(vec![RateLimitWindowSpec {
            limit: max_requests,
            duration: Duration::from_secs(window_seconds),
        }]);
    }

    if object.contains_key("max_requests") {
        return Err(format!("{label}: `max_requests` requires `window_seconds`"));
    }

    let mut specs = Vec::new();

    if let Some(limit) = parse_optional_u64(object, "requests_per_second")? {
        let limit = validate_max_requests(label, "requests_per_second", limit)?;
        specs.push(RateLimitWindowSpec {
            limit,
            duration: Duration::from_secs(1),
        });
    }

    if let Some(limit) = parse_optional_u64(object, "requests_per_minute")? {
        let limit = validate_max_requests(label, "requests_per_minute", limit)?;
        specs.push(RateLimitWindowSpec {
            limit,
            duration: Duration::from_secs(60),
        });
    }

    if let Some(limit) = parse_optional_u64(object, "requests_per_hour")? {
        let limit = validate_max_requests(label, "requests_per_hour", limit)?;
        specs.push(RateLimitWindowSpec {
            limit,
            duration: Duration::from_secs(3600),
        });
    }

    Ok(specs)
}

struct ParsedLimits {
    default_limit: DynamicRateLimitOp,
    consumer_overrides: HashMap<String, DynamicRateLimitOp>,
}

fn parse_limits(object: &serde_json::Map<String, Value>) -> Result<ParsedLimits, String> {
    reject_legacy_window_fields(object)?;

    let limits = object
        .get("limits")
        .ok_or_else(|| "rate_limiting: `limits` is required".to_string())?
        .as_array()
        .ok_or_else(|| "rate_limiting: `limits` must be an array".to_string())?;
    if limits.is_empty() {
        return Err("rate_limiting: `limits` must contain at least one rule".to_string());
    }

    let mut default_limit = None;
    let mut consumer_overrides = HashMap::new();
    for (idx, raw_rule) in limits.iter().enumerate() {
        let label = format!("rate_limiting: `limits[{idx}]`");
        let rule = raw_rule
            .as_object()
            .ok_or_else(|| format!("{label} must be an object"))?;
        validate_limit_rule_fields(&label, rule)?;

        // The shared bound helpers withhold the whole label. Keep the schema
        // ordinal separately so a rendered rejection still locates this rule.
        let specs = parse_window_specs(&label, rule)
            .map_err(|error| format!("rate_limiting: `limits[{idx}]`: {error}"))?;
        if specs.is_empty() {
            return Err(format!(
                "{label}: no rate limit windows configured — set `window_seconds`+`max_requests`, or `requests_per_second`/`requests_per_minute`/`requests_per_hour`"
            ));
        }
        let limit = DynamicRateLimitOp::new(specs);

        match parse_limit_scope(&label, rule)? {
            LimitScope::Default => {
                if let Some((first_idx, _)) = default_limit.replace((idx, limit)) {
                    return Err(format!(
                        "rate_limiting: `limits[{idx}]` is a second `scope: default` rule; `limits[{first_idx}]` already defines the default rule"
                    ));
                }
            }
            LimitScope::Consumers(consumers) => {
                // Each listed consumer gets an independent counter keyed by
                // consumer:<identity>; the rule only shares the window template.
                for consumer in consumers {
                    match consumer_overrides.entry(consumer) {
                        std::collections::hash_map::Entry::Vacant(entry) => {
                            entry.insert((idx, limit.clone()));
                        }
                        std::collections::hash_map::Entry::Occupied(entry) => {
                            let first_idx = entry.get().0;
                            return Err(format!(
                                "rate_limiting: `limits[{idx}]` duplicates consumer-specific limit for {:?}; first defined in `limits[{first_idx}]`",
                                entry.key()
                            ));
                        }
                    }
                }
            }
        }
    }

    let Some((_, default_limit)) = default_limit else {
        return Err(
            "rate_limiting: `limits` must include one rule with `scope=default`".to_string(),
        );
    };

    Ok(ParsedLimits {
        default_limit,
        consumer_overrides: consumer_overrides
            .into_iter()
            .map(|(consumer, (_, limit))| (consumer, limit))
            .collect(),
    })
}

enum LimitScope {
    Default,
    Consumers(Vec<String>),
}

fn parse_limit_scope(
    label: &str,
    object: &serde_json::Map<String, Value>,
) -> Result<LimitScope, String> {
    let scope = object
        .get("scope")
        .and_then(Value::as_str)
        .ok_or_else(|| format!("{label}: `scope` is required and must be a string"))?;
    let scope = scope.to_ascii_lowercase();

    match scope.as_str() {
        "default" => {
            if object.contains_key("consumers") {
                return Err(format!(
                    "{label}: `consumers` is only valid when `scope=consumers`"
                ));
            }
            Ok(LimitScope::Default)
        }
        "consumers" => {
            let consumers = object
                .get("consumers")
                .ok_or_else(|| format!("{label}: `consumers` is required"))?
                .as_array()
                .ok_or_else(|| format!("{label}: `consumers` must be an array"))?;
            if consumers.is_empty() {
                return Err(format!(
                    "{label}: `consumers` must contain at least one identity"
                ));
            }
            let mut parsed = Vec::with_capacity(consumers.len());
            let mut seen = HashSet::with_capacity(consumers.len());
            for (idx, raw_consumer) in consumers.iter().enumerate() {
                let consumer = raw_consumer
                    .as_str()
                    .ok_or_else(|| format!("{label}: `consumers[{idx}]` must be a string"))?;
                if consumer.is_empty() {
                    return Err(format!(
                        "{label}: `consumers[{idx}]` must be a non-empty string"
                    ));
                }
                if !seen.insert(consumer) {
                    return Err(format!(
                        "{label}: `consumers[{idx}]` duplicates consumer identity {consumer:?} in the same rule"
                    ));
                }
                parsed.push(consumer.to_string());
            }
            Ok(LimitScope::Consumers(parsed))
        }
        other => Err(format!(
            "{label}: `scope` must be `default` or `consumers`, got: {other:?}"
        )),
    }
}

fn reject_legacy_window_fields(object: &serde_json::Map<String, Value>) -> Result<(), String> {
    static LEGACY_FIELDS: &[&str] = &[
        "requests_per_second",
        "requests_per_minute",
        "requests_per_hour",
        "window_seconds",
        "max_requests",
        "consumer_limits",
    ];

    for field in LEGACY_FIELDS {
        if object.contains_key(*field) {
            return Err(format!(
                "rate_limiting: `{field}` must be configured inside `limits` rules"
            ));
        }
    }

    Ok(())
}

fn validate_limit_rule_fields(
    label: &str,
    object: &serde_json::Map<String, Value>,
) -> Result<(), String> {
    static ALLOWED_FIELDS: &[&str] = &[
        "scope",
        "consumers",
        "requests_per_second",
        "requests_per_minute",
        "requests_per_hour",
        "window_seconds",
        "max_requests",
    ];

    for key in object.keys() {
        if key == "sync_mode" || key.starts_with("redis_") {
            return Err(format!(
                "{label}: {key:?} is not valid inside `limits`; configure counter storage once at the rate_limiting plugin level"
            ));
        }
        if !ALLOWED_FIELDS.contains(&key.as_str()) {
            return Err(format!(
                "{label}: {key:?} is not valid inside `limits`; allowed fields are `scope`, `consumers`, `requests_per_second`, `requests_per_minute`, `requests_per_hour`, `window_seconds`, `max_requests`"
            ));
        }
    }
    Ok(())
}

fn prefixed_key(prefix: &str, value: &str) -> String {
    let mut key = String::with_capacity(prefix.len() + value.len());
    key.push_str(prefix);
    key.push_str(value);
    key
}

fn ip_key(client_ip: &str, ipv6_prefix: u8) -> String {
    use std::fmt::Write as _;

    let mut key = String::with_capacity(3 + client_ip.len());
    key.push_str("ip:");
    if !client_ip.contains(':') {
        key.push_str(client_ip);
        return key;
    }
    let Some(ip) = crate::util::client_identity::parse_canonical_client_ip(client_ip) else {
        key.push_str(client_ip);
        return key;
    };
    match ip {
        std::net::IpAddr::V4(ipv4) => {
            let _ = write!(key, "{ipv4}");
        }
        std::net::IpAddr::V6(ipv6) => {
            let prefix = ipv6_prefix.min(128);
            let mut octets = ipv6.octets();
            let whole_bytes = usize::from(prefix / 8);
            let remaining_bits = prefix % 8;
            if remaining_bits != 0 {
                octets[whole_bytes] &= u8::MAX << (8 - remaining_bits);
            }
            let zero_from = if remaining_bits == 0 {
                whole_bytes
            } else {
                whole_bytes + 1
            };
            octets[zero_from..].fill(0);
            let _ = write!(key, "{}", std::net::Ipv6Addr::from(octets));
        }
    }
    key
}

/// Metadata key -> response header for the telemetry `expose_headers` publishes.
///
/// x-ratelimit-identity is intentionally NOT mapped: injecting the limiter key
/// here would echo the gateway's internal consumer/SPIFFE identity to the
/// downstream client (after_proxy) — an information-disclosure surface.
///
/// Shared by the injection site and `owns_deadline_response_header` so the
/// written set and the declared-owned set cannot drift apart.
static EXPOSED_RATELIMIT_HEADERS: &[(&str, &str)] = &[
    ("ratelimit_limit", "x-ratelimit-limit"),
    ("ratelimit_remaining", "x-ratelimit-remaining"),
    ("ratelimit_window", "x-ratelimit-window"),
];

/// The same table in the bounded `&[String]` form
/// `Plugin::response_trailer_policy` hands to the plugin cache. Derived from
/// [`EXPOSED_RATELIMIT_HEADERS`] so the two cannot drift, built once per
/// process, and never allocated per request.
static EXPOSED_RATELIMIT_POLICY_NAMES: std::sync::LazyLock<Vec<String>> =
    std::sync::LazyLock::new(|| {
        EXPOSED_RATELIMIT_HEADERS
            .iter()
            .map(|(_, header_name)| (*header_name).to_string())
            .collect()
    });

fn inject_rate_limit_headers_from_metadata(
    metadata: &HashMap<String, String>,
    headers: &mut HashMap<String, String>,
) {
    for &(meta_key, header_name) in EXPOSED_RATELIMIT_HEADERS {
        if let Some(value) = metadata.get(meta_key) {
            headers.insert(header_name.to_string(), value.clone());
        }
    }
}

fn remove_rate_limit_identity_header(headers: &mut HashMap<String, String>) {
    headers.retain(|name, _| !name.eq_ignore_ascii_case(RATE_LIMIT_IDENTITY_HEADER));
}
