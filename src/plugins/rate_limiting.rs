//! General request rate limiting with optional Redis-backed failover.

use async_trait::async_trait;
use serde_json::Value;
use std::collections::{HashMap, HashSet};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};
use tracing::warn;

use super::utils::rate_limit::{
    DynamicHttpRateLimitAlgorithm, DynamicRateLimitOp, RateLimitBackend, RateLimitOutcome,
    RateLimitWindowSpec,
};
use super::{Plugin, PluginHttpClient, PluginResult, RequestContext};

const MAX_STATE_ENTRIES: usize = 100_000;
const EVICTION_CHECK_INTERVAL_REQUESTS: u64 = 1024;
const RATE_LIMIT_IDENTITY_HEADER: &str = "x-ratelimit-identity";

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
}

impl RateLimiting {
    pub fn new(config: &Value, http_client: PluginHttpClient) -> Result<Self, String> {
        let object = config
            .as_object()
            .ok_or_else(|| format!("rate_limiting: config must be an object, got: {config}"))?;
        let limit_by = parse_limit_by(object)?;
        let expose_headers = parse_optional_bool(object, "expose_headers")?.unwrap_or(false);

        let parsed_limits = parse_limits(object)?;
        if !parsed_limits.consumer_overrides.is_empty() && limit_by != LimitBy::Consumer {
            return Err(
                "rate_limiting: consumer-scoped limits can only be used with limit_by='consumer'"
                    .to_string(),
            );
        }

        let limiter = RateLimitBackend::from_plugin_config(
            "rate_limiting",
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
        })
    }

    /// Local/fallback DashMap shard count. Test-only; not a production API.
    #[cfg(test)]
    pub(crate) fn local_map_shard_amount(&self) -> usize {
        self.limiter.local_map_shard_amount()
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

    async fn check_rate(
        &self,
        key: String,
        limit_op: &DynamicRateLimitOp,
        ctx: &mut RequestContext,
    ) -> PluginResult {
        let outcome = self.limiter.check(key.clone(), &key, limit_op).await;
        self.maybe_evict_stale_entries();
        if !outcome.allowed {
            super::prometheus_metrics::global_registry().record_rate_limit_exceeded();
            warn!(rate_limit_key = %key, plugin = "rate_limiting", "Rate limit exceeded");
            return self.reject(&outcome);
        }

        self.store_metadata(&outcome, ctx);
        PluginResult::Continue
    }

    async fn check_rate_stream(&self, key: String, limit_op: &DynamicRateLimitOp) -> PluginResult {
        let outcome = self.limiter.check(key.clone(), &key, limit_op).await;
        self.maybe_evict_stale_entries();
        if !outcome.allowed {
            super::prometheus_metrics::global_registry().record_rate_limit_exceeded();
            warn!(rate_limit_key = %key, plugin = "rate_limiting", "Rate limit exceeded (stream)");
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

    /// An admitted request records its limit/remaining/window in request
    /// metadata before later plugins run. Gateway-generated responses that
    /// still consumed budget — cache hits, response mocks, serverless
    /// short-circuits, and rejections from plugins later in the lifecycle —
    /// finalize through the shared synthetic/rejection pipeline, which only
    /// invokes `after_proxy` for plugins that opt in here. Opt in so every
    /// counted request's client-visible response carries the configured
    /// `x-ratelimit-*` telemetry regardless of response origin. The hook
    /// remains metadata-gated: requests that never reached the rate-limit
    /// check carry no metadata and get no synthesized headers, and with
    /// `expose_headers: false` the hook only strips `x-ratelimit-identity`.
    fn applies_after_proxy_on_reject(&self) -> bool {
        true
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
        if window_seconds == 0 {
            return Err(format!(
                "{label}: 'window_seconds' must be greater than zero"
            ));
        }
        let max_requests = parse_optional_u64(object, "max_requests")?.ok_or_else(|| {
            format!("{label}: 'max_requests' is required when 'window_seconds' is set")
        })?;
        if max_requests == 0 {
            return Err(format!("{label}: 'max_requests' must be greater than zero"));
        }
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
        if limit == 0 {
            return Err(format!(
                "{label}: 'requests_per_second' must be greater than zero"
            ));
        }
        specs.push(RateLimitWindowSpec {
            limit,
            duration: Duration::from_secs(1),
        });
    }

    if let Some(limit) = parse_optional_u64(object, "requests_per_minute")? {
        if limit == 0 {
            return Err(format!(
                "{label}: 'requests_per_minute' must be greater than zero"
            ));
        }
        specs.push(RateLimitWindowSpec {
            limit,
            duration: Duration::from_secs(60),
        });
    }

    if let Some(limit) = parse_optional_u64(object, "requests_per_hour")? {
        if limit == 0 {
            return Err(format!(
                "{label}: 'requests_per_hour' must be greater than zero"
            ));
        }
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
