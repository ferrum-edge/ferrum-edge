//! General request rate limiting with optional Redis-backed failover.

use async_trait::async_trait;
use serde_json::Value;
use std::collections::{HashMap, HashSet};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};
use tracing::warn;

use super::utils::rate_limit::{
    DynamicHttpRateLimitAlgorithm, DynamicRateLimitOp, ENFORCEMENT_UNAVAILABLE_BODY,
    ENFORCEMENT_UNAVAILABLE_STATUS, RATE_LIMIT_REDIS_CONFIG_KEYS, RateLimitBackend,
    RateLimitOutcome, RateLimitWindowSpec, STANDALONE_RATE_LIMIT_CONFIG_ID,
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

/// `rate_limiting`-specific top-level config keys (excludes shared Redis fields).
const RATE_LIMITING_POLICY_CONFIG_KEYS: &[&str] = &["limit_by", "expose_headers", "limits"];

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
    "expose_headers",
    "limits",
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

pub struct RateLimiting {
    limit_by: LimitBy,
    expose_headers: bool,
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
        let object = config
            .as_object()
            .ok_or_else(|| format!("rate_limiting: config must be an object, got: {config}"))?;
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
            "rate_limiting: ",
        )?;
        let limit_by = parse_limit_by(object)?;
        let expose_headers = parse_optional_bool(object, "expose_headers")?.unwrap_or(false);

        let parsed_limits = parse_limits(object)?;
        if !parsed_limits.consumer_overrides.is_empty() && limit_by != LimitBy::Consumer {
            return Err(
                "rate_limiting: consumer-scoped limits can only be used with limit_by='consumer'"
                    .to_string(),
            );
        }

        let limiter = RateLimitBackend::from_plugin_config_with_config_id(
            "rate_limiting",
            config_id,
            config,
            &http_client,
            DynamicHttpRateLimitAlgorithm::new(),
        )?;

        Ok(Self {
            limit_by,
            expose_headers,
            default_limit: parsed_limits.default_limit,
            consumer_overrides: parsed_limits.consumer_overrides,
            limiter,
            request_counter: AtomicU64::new(0),
            epoch_base: Instant::now(),
            last_periodic_sweep_secs: AtomicU64::new(0),
        })
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

        ip_key(&ctx.client_ip)
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

        ip_key(&ctx.client_ip)
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

        PluginResult::Reject {
            status_code: 429,
            body: r#"{"error":"Rate limit exceeded"}"#.into(),
            headers,
        }
    }

    fn store_metadata(&self, outcome: &RateLimitOutcome, ctx: &mut RequestContext) {
        if !self.expose_headers {
            return;
        }

        // Intentionally does not store the rate-limit key/identity: it would be
        // injected onto the downstream response by after_proxy and disclose the
        // gateway's internal consumer/SPIFFE identity to the client.
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

    async fn check_rate(
        &self,
        key: String,
        limit_op: &DynamicRateLimitOp,
        ctx: &mut RequestContext,
    ) -> PluginResult {
        // Run sampled idle reclamation before admission. Capacity denial must
        // still advance the cleanup schedule; otherwise an exactly-full map of
        // expired keys could remain pinned closed when only new identities
        // arrive. Cleanup never removes live budgets.
        self.maybe_evict_stale_entries();
        let Some(outcome) = self
            .limiter
            .check_with_redis_key_and_local_capacity(
                key.clone(),
                || key.clone(),
                limit_op,
                MAX_STATE_ENTRIES,
            )
            .await
        else {
            return self.reject_capacity();
        };
        if !outcome.allowed {
            if outcome.enforcement_unavailable {
                // The shared failover backend emits one bounded operational
                // warning per outage. Avoid an attacker-rate warning/metric for
                // every request while centralized enforcement is unavailable.
                return self.reject(&outcome);
            }
            super::prometheus_metrics::global_registry().record_rate_limit_exceeded();
            // The rate-limit key embeds the identity dimension (consumer
            // username, authenticated identity, SPIFFE ID, or client IP), so it
            // is never logged. Enforcement outcomes are attributed through the
            // transaction summary, which applies metadata redaction.
            warn!(plugin = "rate_limiting", "Rate limit exceeded");
            return self.reject(&outcome);
        }

        self.store_metadata(&outcome, ctx);
        PluginResult::Continue
    }

    async fn check_rate_stream(&self, key: String, limit_op: &DynamicRateLimitOp) -> PluginResult {
        self.maybe_evict_stale_entries();
        let Some(outcome) = self
            .limiter
            .check_with_redis_key_and_local_capacity(
                key.clone(),
                || key.clone(),
                limit_op,
                MAX_STATE_ENTRIES,
            )
            .await
        else {
            return self.reject_capacity();
        };
        if !outcome.allowed {
            if outcome.enforcement_unavailable {
                // See `check_rate`: the backend owns bounded outage
                // observability, and a 503 is not a rate-limit exceedance.
                return self.reject(&outcome);
            }
            super::prometheus_metrics::global_registry().record_rate_limit_exceeded();
            // Identity-bearing key deliberately omitted (see `check_rate`).
            warn!(plugin = "rate_limiting", "Rate limit exceeded (stream)");
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
        super::ALL_PROTOCOLS
    }

    fn tracked_keys_count(&self) -> Option<usize> {
        Some(self.limiter.tracked_keys_count())
    }

    fn modifies_request_headers(&self) -> bool {
        true
    }

    fn warmup_hostnames(&self) -> Vec<String> {
        self.limiter.warmup_hostname().into_iter().collect()
    }

    async fn on_stream_connect(
        &self,
        ctx: &mut super::StreamConnectionContext,
    ) -> super::PluginResult {
        let key = self.stream_key(ctx);
        let limit_op = self.stream_limit_op(ctx);
        self.check_rate_stream(key, limit_op).await
    }

    async fn on_request_received(&self, ctx: &mut RequestContext) -> PluginResult {
        if self.limit_by != LimitBy::Ip {
            return PluginResult::Continue;
        }

        let ip_key = self.request_key(ctx);
        let limit_op = self.request_limit_op(ctx);
        self.check_rate(ip_key, limit_op, ctx).await
    }

    async fn authorize(&self, ctx: &mut RequestContext) -> PluginResult {
        if !matches!(self.limit_by, LimitBy::Consumer | LimitBy::SpiffeIdentity) {
            return PluginResult::Continue;
        }

        let key = self.request_key(ctx);
        let limit_op = self.request_limit_op(ctx);
        self.check_rate(key, limit_op, ctx).await
    }

    fn is_authorize_plugin(&self) -> bool {
        matches!(self.limit_by, LimitBy::Consumer | LimitBy::SpiffeIdentity)
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
            "{label}: cannot combine 'window_seconds'/'max_requests' with 'requests_per_second'/'requests_per_minute'/'requests_per_hour' in the same rule"
        ));
    }

    if let Some(window_seconds) = parse_optional_u64(object, "window_seconds")? {
        let window_seconds = validate_window_seconds(label, "window_seconds", window_seconds)?;
        let max_requests = parse_optional_u64(object, "max_requests")?.ok_or_else(|| {
            format!("{label}: 'max_requests' is required when 'window_seconds' is set")
        })?;
        let max_requests = validate_max_requests(label, "max_requests", max_requests)?;
        return Ok(vec![RateLimitWindowSpec {
            limit: max_requests,
            duration: Duration::from_secs(window_seconds),
        }]);
    }

    if object.contains_key("max_requests") {
        return Err(format!("{label}: 'max_requests' requires 'window_seconds'"));
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
        .ok_or_else(|| "rate_limiting: 'limits' is required".to_string())?
        .as_array()
        .ok_or_else(|| "rate_limiting: 'limits' must be an array".to_string())?;
    if limits.is_empty() {
        return Err("rate_limiting: 'limits' must contain at least one rule".to_string());
    }

    let mut default_limit = None;
    let mut consumer_overrides = HashMap::new();
    for (idx, raw_rule) in limits.iter().enumerate() {
        let label = format!("rate_limiting: limits[{idx}]");
        let rule = raw_rule
            .as_object()
            .ok_or_else(|| format!("{label} must be an object"))?;
        validate_limit_rule_fields(&label, rule)?;

        let specs = parse_window_specs(&label, rule)?;
        if specs.is_empty() {
            return Err(format!(
                "{label}: no rate limit windows configured — set 'window_seconds'+'max_requests', or 'requests_per_second'/'requests_per_minute'/'requests_per_hour'"
            ));
        }
        let limit = DynamicRateLimitOp::new(specs);

        match parse_limit_scope(&label, rule)? {
            LimitScope::Default => {
                if let Some((first_idx, _)) = default_limit.replace((idx, limit)) {
                    return Err(format!(
                        "rate_limiting: limits[{idx}] is a second 'scope: default' rule; limits[{first_idx}] already defines the default rule"
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
                                "rate_limiting: limits[{idx}] duplicates consumer-specific limit for {:?}; first defined in limits[{first_idx}]",
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
            "rate_limiting: 'limits' must include one rule with scope='default'".to_string(),
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
        .ok_or_else(|| format!("{label}: 'scope' is required and must be a string"))?;
    let scope = scope.to_ascii_lowercase();

    match scope.as_str() {
        "default" => {
            if object.contains_key("consumers") {
                return Err(format!(
                    "{label}: 'consumers' is only valid when scope='consumers'"
                ));
            }
            Ok(LimitScope::Default)
        }
        "consumers" => {
            let consumers = object
                .get("consumers")
                .ok_or_else(|| format!("{label}: 'consumers' is required"))?
                .as_array()
                .ok_or_else(|| format!("{label}: 'consumers' must be an array"))?;
            if consumers.is_empty() {
                return Err(format!(
                    "{label}: 'consumers' must contain at least one identity"
                ));
            }
            let mut parsed = Vec::with_capacity(consumers.len());
            let mut seen = HashSet::with_capacity(consumers.len());
            for (idx, raw_consumer) in consumers.iter().enumerate() {
                let consumer = raw_consumer
                    .as_str()
                    .ok_or_else(|| format!("{label}: 'consumers[{idx}]' must be a string"))?;
                if consumer.is_empty() {
                    return Err(format!(
                        "{label}: 'consumers[{idx}]' must be a non-empty string"
                    ));
                }
                if !seen.insert(consumer) {
                    return Err(format!(
                        "{label}: 'consumers[{idx}]' duplicates consumer identity {consumer:?} in the same rule"
                    ));
                }
                parsed.push(consumer.to_string());
            }
            Ok(LimitScope::Consumers(parsed))
        }
        other => Err(format!(
            "{label}: 'scope' must be 'default' or 'consumers', got: {other:?}"
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
                "rate_limiting: '{field}' must be configured inside 'limits' rules"
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
                "{label}: '{key}' is not valid inside 'limits'; configure counter storage once at the rate_limiting plugin level"
            ));
        }
        if !ALLOWED_FIELDS.contains(&key.as_str()) {
            return Err(format!(
                "{label}: '{key}' is not valid inside 'limits'; allowed fields are scope, consumers, requests_per_second, requests_per_minute, requests_per_hour, window_seconds, max_requests"
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

fn ip_key(client_ip: &str) -> String {
    prefixed_key("ip:", client_ip)
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
