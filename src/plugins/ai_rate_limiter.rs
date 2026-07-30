//! AI token-budget rate limiting with shared local/Redis/failover storage.
//!
//! ## Protocol scope (HTTP only)
//!
//! This limiter is registered for `ProxyProtocol::Http` only
//! (`HTTP_ONLY_PROTOCOLS`). Its whole accounting lifecycle — prompt estimation,
//! pre-reservation, and post-response reconciliation — is defined over bare
//! JSON request bodies and JSON/SSE response bodies. Native gRPC carries
//! length-prefixed, optionally compressed protobuf frames with no
//! gateway-known usage schema, so there is no bounded, explicitly configured
//! descriptor-based extraction that could charge those calls. Advertising
//! `ProxyProtocol::Grpc` therefore meant an operator could attach an
//! enforcement plugin to native gRPC AI traffic that charged nothing at all:
//! every call re-checked an empty window and passed (GHSA-8f27-23x9-f825).
//!
//! Because native gRPC is never pinned in proxy configuration (a single
//! `http`/`https` proxy serves REST, gRPC, and WebSocket by runtime
//! content-type detection — see `BackendScheme` in `docs/routing.md`), the
//! protocol contract *is* the admission boundary: `PluginCache` builds one
//! plugin list per `ProxyProtocol` from `supported_protocols()`, so a native
//! gRPC request resolves a `ProxyProtocol::Grpc` view that this plugin is not
//! part of. Every configuration path — admin API, file mode, CP validation,
//! and DP full/incremental config application — goes through that same shared
//! cache build, so none of them can install this limiter on native gRPC.
//!
//! gRPC-Web is likewise unsupported, but it rides the HTTP (and composed H3
//! gRPC-Web) view, so this plugin can still observe it. Framed
//! `application/grpc-web*` bodies — including the `+json` variants that
//! `is_json_content_type` matches — are never buffered, never parsed as a
//! bare JSON AI request, and never treated as a JSON usage document on the
//! response side. They are classified as non-AI traffic and left untouched
//! rather than being charged zero tokens against a budget.

use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::HashMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Instant;
use tracing::{debug, warn};

use super::utils::ai_providers::{
    AiTokenUsage, detect_response_provider, extract_response_usage, parse_ai_provider,
};
use super::utils::ai_stream_usage::{StreamUsageFormat, StreamUsageScanner};
use super::utils::body_transform::is_json_content_type;
use super::utils::rate_limit::{
    AiRateLimitOp, AiTokenRateAlgorithm, ENFORCEMENT_UNAVAILABLE_BODY,
    ENFORCEMENT_UNAVAILABLE_STATUS, RATE_LIMIT_REDIS_CONFIG_KEYS, RateLimitBackend,
    RateLimitOutcome, ReservationBackend, STANDALONE_RATE_LIMIT_CONFIG_ID,
    apply_rate_limit_cleanup, debug_assert_closed_root_keys, debug_assert_rate_limit_redis_keys,
    validate_window_seconds,
};
use super::{
    Plugin, PluginHttpClient, PluginResult, RequestContext, ResponseStreamAction,
    ResponseStreamHandoff, ResponseStreamInspector, allocate_response_stream_handoff_id,
};
/// Shared key for the original (pre-rejection) backend HTTP status. Recorded by
/// the proxy's `run_after_proxy_hooks` *before* the after_proxy loop, and again
/// by this plugin's own genuine `after_proxy` pass — both write the same value.
/// Reusing the `crate::proxy` constants (instead of local copies) keeps the
/// proxy-side and plugin-side writers/readers from drifting apart. See
/// `should_release_gateway_rejection` (`BACKEND_STATUS_METADATA_KEY`) and the
/// AI-request gate on the unmetered-response policy (`AI_REQUEST_METADATA_KEY`).
use crate::proxy::{
    AI_REQUEST_METADATA_KEY, BACKEND_STATUS_METADATA_KEY, RESERVED_TOKENS_METADATA_KEY,
};
use crate::util::unknown_keys::reject_unknown_keys;

const MAX_STATE_ENTRIES: usize = 100_000;
const EVICTION_CHECK_INTERVAL_REQUESTS: u64 = 1024;
/// Bounds below-cap full-map scans under high RPS. Sampled over-cap
/// reclaim skips this cooldown so a sampled observation of pressure can
/// drop idle keys without waiting for the next cool-down window. Live
/// budgets are never force-evicted.
const EVICTION_COOLDOWN_SECS: u64 = 1;
const CAPACITY_REJECT_BODY: &str = r#"{"error":"AI token rate limit exceeded","details":"Rate-limit state capacity exceeded (max 100000 keys)"}"#;
/// Base prefix for this instance's typed reservation record (see
/// [`InstanceReservation`]). The full key appends a process-unique instance id.
const RESERVATION_RECORD_METADATA_KEY_PREFIX: &str = "ai_ratelimit_reservation";
/// Base prefix for the per-instance O(1) "this instance must meter the response
/// body" index (see [`AiRateLimiter::meter_flag_key`]).
const METER_RESPONSE_METADATA_KEY_PREFIX: &str = "ai_ratelimit_meter";
/// Client-invisible telemetry: the actual tokens the LAST reconciling instance
/// charged. Never read for an accounting decision — every decision reads the
/// per-instance [`InstanceReservation`] — so a sibling instance overwriting it
/// cannot corrupt a budget. Kept shared because it is a transaction-log field.
const ACTUAL_TOKENS_METADATA_KEY: &str = "ai_ratelimit_actual_tokens";
/// Base prefix for the per-request idempotency flag that marks a federated
/// response's tokens as already reconciled by `after_proxy` (the sole federation
/// charger — `on_response_body` always skips federation traffic). The flag guards
/// the case where `after_proxy` runs twice for one request (a synthetic 2xx
/// short-circuit followed by a response-body rejection that re-runs the reject
/// hooks). The full key is per-limiter-instance (see
/// [`AiRateLimiter::federation_flag_key`]) so that multiple `ai_rate_limiter`
/// instances on one proxy (e.g. a per-consumer and a per-IP budget) each
/// reconcile the federation tokens against their own window exactly once, instead
/// of the first instance's flag suppressing the others.
const FEDERATION_TOKENS_RECORDED_METADATA_KEY_PREFIX: &str =
    "ai_ratelimit_federation_tokens_recorded";
const REJECTION_RESPONSE_METADATA_KEY: &str = "ferrum:rejection_response";
/// Metadata key the `compression` plugin sets (see `compression.rs::before_proxy`)
/// when it decompresses a request body. It is written into `ctx.metadata`, which
/// clients cannot influence, so — unlike the `x-ferrum-original-content-encoding`
/// header, which is only sanitized when `compression` actually runs — it is a
/// trustworthy signal that the body WAS compressed and will be available
/// decompressed in `on_final_request_body`. Detecting the deferred (Case A) path
/// from a client-settable header would let a spoofed header skip pre-reservation.
const COMPRESSION_REQUEST_ENCODING_METADATA_KEY: &str = "compression:request_encoding";

/// Process-wide monotonic counter used to give every `AiRateLimiter` instance a
/// unique id. The id is folded into [`AiRateLimiter::federation_flag_key`] so the
/// per-request federation idempotency flag is scoped to ONE limiter instance,
/// never to a budget-config fingerprint that two intentionally-separate budgets
/// could share. Mirrors the `INSTANCE_ID_COUNTER` idiom in `openapi_validator`.
static INSTANCE_ID_COUNTER: AtomicU64 = AtomicU64::new(0);

/// Everything one `ai_rate_limiter` instance knows about ONE request's
/// reservation lifecycle, stored as a single instance-owned `ctx.metadata`
/// entry keyed by [`AiRateLimiter::reservation_record_key`].
///
/// Multiple `ai_rate_limiter` instances on one proxy are documented as
/// independent budgets (a per-consumer limiter plus a per-IP limiter is the
/// canonical defence-in-depth composition). Previously every instance wrote the
/// same unscoped `ctx.metadata` keys for reserved tokens, local reservation id,
/// Redis window index, inferred backend, AI classification, and release
/// idempotency, so the second instance's admission pass overwrote the first
/// instance's markers: on the response pass each instance reconciled its own
/// window using a sibling's reservation data, and the first release set a shared
/// flag that suppressed every sibling's release (GHSA-wh4p-pmxm-3784).
///
/// One typed record per instance closes that whole class: an instance can only
/// ever read back the fields it itself wrote. It is deliberately ONE record
/// rather than a family of instance-suffixed string keys — a single
/// serialize/deserialize point makes it impossible to scope four fields and
/// forget the fifth, and it keeps the per-request metadata footprint to one
/// entry per instance.
///
/// `ctx.metadata` is gateway- and plugin-owned (never client-settable), so the
/// serialized form is trusted input; an unreadable record still degrades to
/// `Default`, which reserves nothing and settles nothing.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
struct InstanceReservation {
    /// Tokens THIS instance pre-reserved in `before_proxy`.
    #[serde(default)]
    reserved_tokens: u64,
    /// Local-backend reservation id, so reconciliation releases the exact entry
    /// this instance created under concurrent out-of-order completions.
    #[serde(default)]
    reservation_id: Option<u64>,
    /// Redis sliding-window index this instance's reservation credited, so a
    /// negative correction debits the same window across a rollover. `None` in
    /// local mode, where the entry timestamp pins the correction.
    #[serde(default)]
    reserved_window_index: Option<u64>,
    /// Whether THIS instance classified the request as an AI call. Instances can
    /// legitimately disagree only through configuration, but each must gate its
    /// own `on_unmetered_response` policy on its own classification.
    #[serde(default)]
    ai_request: bool,
    /// Compressed AI candidate with no safe pre-request estimate.
    #[serde(default)]
    compressed_ai_candidate: bool,
    /// `before_proxy` could not classify a compressed body and deferred to this
    /// instance's `on_final_request_body` pass (Case A). Per instance, so
    /// co-located limiters do not race to consume one shared marker.
    #[serde(default)]
    deferred_compressed_classification: bool,
    /// Set once this instance has settled its reservation — charged actual
    /// usage OR released the estimate. Every terminal path consults it, so each
    /// instance settles exactly once no matter how many times the response
    /// phases re-run (a non-2xx release followed by a rejection re-run of
    /// `after_proxy`, a synthetic short-circuit followed by a body rejection, a
    /// streaming terminal hook racing a rejection path, …).
    ///
    /// This covers the charge path as well as the release path. The charge is
    /// authoritative and runs at most once per instance per request anyway, and
    /// gating it here is what makes "settle exactly once" a single invariant
    /// instead of two partially overlapping ones — no undercharge, no
    /// overcharge, no double release, and no stale reservation left behind.
    #[serde(default)]
    settled: bool,
    /// The `on_unmetered_response` action this instance applied, if any.
    #[serde(default)]
    unmetered_action: Option<String>,
    /// Actual tokens this instance charged, for its own telemetry.
    #[serde(default)]
    actual_tokens: Option<u64>,
    /// Last authoritative window snapshot this instance observed, used to
    /// publish ITS OWN exposed-header values rather than a sibling's.
    #[serde(default)]
    exposed_remaining: Option<u64>,
    #[serde(default)]
    exposed_usage: Option<u64>,
}

impl InstanceReservation {
    /// Which backend this instance's reservation landed on.
    ///
    /// A local reservation carries a `reservation_id`; a Redis reservation
    /// carries a `reserved_window_index`. Neither means nothing was reserved
    /// (a 0-token estimate), so the ordinary reconciliation path applies. This
    /// lets reconciliation detect a Redis outage/recovery between reserve and
    /// reconcile and avoid corrupting a backend that never held the
    /// reservation — now per instance, so a mixed local/Redis pair can no
    /// longer make a sibling apply backend-switch logic to the wrong
    /// reservation.
    fn backend(&self) -> ReservationBackend {
        if self.reserved_window_index.is_some() {
            ReservationBackend::Redis
        } else if self.reservation_id.is_some() {
            ReservationBackend::Local
        } else {
            ReservationBackend::Unknown
        }
    }

    /// Whether this record holds anything worth persisting back to metadata.
    fn is_empty(&self) -> bool {
        *self == Self::default()
    }

    /// Whether this instance still has something to meter from the response
    /// body. A request it never classified as an AI call and never reserved
    /// against has nothing to reconcile, so its response body is irrelevant.
    fn needs_response_body(&self) -> bool {
        self.ai_request
            || self.reserved_tokens > 0
            || self.compressed_ai_candidate
            || self.deferred_compressed_classification
    }
}

/// Terminal result of one streamed response's usage scan.
#[derive(Debug, Clone, Default)]
struct StreamUsageResult {
    usage: Option<AiTokenUsage>,
    malformed: bool,
}

/// Request-owned handoff cell carrying a stream scanner from the detached body
/// task to this instance's terminal hook.
///
/// The inspector runs inside the task that drives the poll-based H1/H2 channel
/// body (and inside the H3 loop), neither of which can borrow the request
/// context, so the result is published through the bounded, request-scoped
/// [`ResponseStreamHandoff`] rather than any process-global map. That keeps
/// aggregate concurrency state bounded by the in-flight requests themselves —
/// there is no gateway-wide table of live streams to grow.
#[derive(Debug)]
struct StreamUsageSlot {
    scanner: std::sync::Mutex<StreamUsageScanner>,
    result: std::sync::Mutex<StreamUsageResult>,
}

impl StreamUsageSlot {
    fn new(scanner: StreamUsageScanner) -> Self {
        Self {
            scanner: std::sync::Mutex::new(scanner),
            result: std::sync::Mutex::new(StreamUsageResult::default()),
        }
    }

    fn observe(&self, chunk: &[u8]) {
        if let Ok(mut scanner) = self.scanner.lock() {
            scanner.observe(chunk);
        }
    }

    /// Finalize the scan and latch its result.
    ///
    /// A poisoned lock is treated as a damaged scan (`malformed`), which routes
    /// the response through the fail-closed unmetered posture instead of
    /// reporting a usage-free stream.
    fn finish(&self) {
        let latched = match self.scanner.lock() {
            Ok(mut scanner) => {
                scanner.finish();
                StreamUsageResult {
                    usage: scanner.authoritative_usage().cloned(),
                    malformed: scanner.malformed(),
                }
            }
            Err(_) => StreamUsageResult {
                usage: None,
                malformed: true,
            },
        };
        if let Ok(mut result) = self.result.lock() {
            *result = latched;
        }
    }

    fn snapshot(&self) -> StreamUsageResult {
        match self.result.lock() {
            Ok(result) => result.clone(),
            Err(_) => StreamUsageResult {
                usage: None,
                malformed: true,
            },
        }
    }
}

/// Per-response streaming usage inspector for one `ai_rate_limiter` instance.
///
/// Purely observational: every chunk is forwarded downstream unchanged and the
/// bytes are not retained. Only bounded terminal metadata is extracted.
struct AiRateLimitStreamInspector {
    slot: Arc<StreamUsageSlot>,
    handoff: Option<ResponseStreamHandoff>,
    handoff_id: u64,
    published: bool,
}

impl AiRateLimitStreamInspector {
    /// Latch the scan result and hand it to the terminal hook.
    ///
    /// Called from both `on_end` (clean completion) and `Drop`/`on_before_drop`
    /// (client disconnect, deadline, cancelled task), so a stream that dies
    /// mid-flight still publishes — with whatever it managed to observe, which
    /// the terminal hook then treats as incomplete and settles fail-closed.
    fn publish(&mut self) {
        if self.published {
            return;
        }
        self.published = true;
        self.slot.finish();
        if let Some(handoff) = self.handoff.as_ref() {
            handoff.publish(self.handoff_id, Arc::clone(&self.slot));
        }
    }
}

#[async_trait]
impl ResponseStreamInspector for AiRateLimitStreamInspector {
    async fn on_chunk(&mut self, chunk: &[u8]) -> ResponseStreamAction {
        self.slot.observe(chunk);
        ResponseStreamAction::Forward(bytes::Bytes::copy_from_slice(chunk))
    }

    async fn on_end(&mut self) -> ResponseStreamAction {
        self.publish();
        ResponseStreamAction::Forward(bytes::Bytes::new())
    }

    /// A later inspector cut the stream, so the bytes this scanner saw are not
    /// the client-visible response. Latch what was observed and let the terminal
    /// hook settle it as an incomplete stream.
    fn on_downstream_terminated(&mut self) {
        self.publish();
    }

    fn on_before_drop(&mut self) {
        self.publish();
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum OnUnmeteredResponse {
    Reject,
    ChargeEstimate,
    Warn,
}

impl OnUnmeteredResponse {
    fn parse(raw: &str) -> Option<Self> {
        match raw {
            "reject" => Some(Self::Reject),
            "charge_estimate" => Some(Self::ChargeEstimate),
            "warn" => Some(Self::Warn),
            _ => None,
        }
    }

    fn as_str(self) -> &'static str {
        match self {
            Self::Reject => "reject",
            Self::ChargeEstimate => "charge_estimate",
            Self::Warn => "warn",
        }
    }
}

/// `(metadata key, response header)` pairs this plugin exposes downstream when
/// `expose_headers` is set. Single source of truth for both the `after_proxy`
/// write and the gRPC-deadline ownership declaration.
const EXPOSED_RATELIMIT_HEADERS: &[(&str, &str)] = &[
    ("ai_ratelimit_limit", "x-ai-ratelimit-limit"),
    ("ai_ratelimit_remaining", "x-ai-ratelimit-remaining"),
    ("ai_ratelimit_window", "x-ai-ratelimit-window"),
    ("ai_ratelimit_usage", "x-ai-ratelimit-usage"),
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

/// `ai_rate_limiter`-specific top-level config keys (excludes shared Redis fields).
const AI_RATE_LIMITER_POLICY_CONFIG_KEYS: &[&str] = &[
    "token_limit",
    "window_seconds",
    "count_mode",
    "limit_by",
    "expose_headers",
    "provider",
    "on_unmetered_response",
];

/// Closed top-level key set for `ai_rate_limiter` plugin config.
///
/// Must stay aligned with OpenAPI `AiRateLimiterConfig` (which must declare
/// `additionalProperties: false`), [`RATE_LIMIT_REDIS_CONFIG_KEYS`], and
/// `docs/plugins.md`. Unknown root keys fail closed: a valid `token_limit` can
/// mask a misspelled `sync_mdoe`, `on_unmetered_responce`, or `limit_byy`, so
/// construction would succeed while distributed enforcement, identity scope,
/// unmetered posture, or provider extraction silently fell back to defaults.
pub const AI_RATE_LIMITER_CONFIG_KEYS: &[&str] = &[
    "token_limit",
    "window_seconds",
    "count_mode",
    "limit_by",
    "expose_headers",
    "provider",
    "on_unmetered_response",
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

pub struct AiRateLimiter {
    token_limit: u64,
    window_seconds: u64,
    count_mode: String,
    limit_by: String,
    expose_headers: bool,
    provider: String,
    on_unmetered_response: OnUnmeteredResponse,
    /// Per-instance metadata key for the federation-tokens-recorded idempotency
    /// flag. Scoped to this limiter instance via a process-unique id so that two
    /// `ai_rate_limiter` instances — even with byte-identical budget config but
    /// intentionally separate budgets (distinct `sync_mode`/`redis_key_prefix`,
    /// or simply two local instances) — never share the flag. Each instance
    /// reconciles the federation tokens against its own window exactly once.
    federation_flag_key: String,
    /// Metadata key holding THIS instance's [`InstanceReservation`]. Scoped by
    /// the same process-unique instance id as `federation_flag_key`, so two
    /// instances with byte-identical config still own separate records.
    reservation_record_key: String,
    /// O(1) hot-path index derived from [`InstanceReservation`]: present exactly
    /// when this instance still has something to meter from the response.
    ///
    /// The response-buffering decision is consulted several times per request
    /// (stream/buffer selection, retry release, synthetic body gating), and it
    /// runs for every request on the proxy — including non-AI ones. Deserializing
    /// the record there would put a JSON parse on that path, so the boolean is
    /// precomputed whenever the record changes. It is an index over the record,
    /// never a second source of truth: nothing reads it for an accounting
    /// decision.
    meter_flag_key: String,
    /// Process-unique key for this instance's typed response-stream handoff, so
    /// a streaming response hands its own scanner result to this instance's
    /// terminal hook and never to a sibling's.
    stream_handoff_id: u64,
    limiter: RateLimitBackend<String, AiTokenRateAlgorithm>,
    request_counter: AtomicU64,
    epoch_base: Instant,
    last_periodic_sweep_secs: AtomicU64,
}

impl AiRateLimiter {
    #[allow(dead_code)] // direct/test construction; production factory supplies the config id
    pub fn new(config: &Value, http_client: PluginHttpClient) -> Result<Self, String> {
        Self::new_with_config_id(config, http_client, STANDALONE_RATE_LIMIT_CONFIG_ID)
    }

    /// Construct with the stable plugin-config resource id that isolates this
    /// policy's default Redis token counters from sibling `ai_rate_limiter`
    /// instances in the same namespace. See
    /// [`super::utils::rate_limit::RedisLimiter::new_with_config_id`].
    pub fn new_with_config_id(
        config: &Value,
        http_client: PluginHttpClient,
        config_id: &str,
    ) -> Result<Self, String> {
        let object = config
            .as_object()
            .ok_or_else(|| "ai_rate_limiter: config must be an object".to_string())?;
        // Keeps the documented key groups aligned with the closed root
        // allowlist used for admission and OpenAPI parity. The Redis group is
        // the rate-limit list (shared keys plus `redis_failure_policy`), not the
        // bare shared list: an enforcement plugin that unioned the shared list
        // would reject the advisory's fail-closed/local_fallback opt-in.
        debug_assert_rate_limit_redis_keys();
        debug_assert_closed_root_keys(
            AI_RATE_LIMITER_CONFIG_KEYS,
            AI_RATE_LIMITER_POLICY_CONFIG_KEYS,
            RATE_LIMIT_REDIS_CONFIG_KEYS,
        );
        reject_unknown_keys(
            object,
            "config",
            AI_RATE_LIMITER_CONFIG_KEYS,
            "ai_rate_limiter: ",
        )?;

        let token_limit = required_u64(config, "token_limit")?;
        if token_limit == 0 {
            return Err("ai_rate_limiter: 'token_limit' must be greater than zero".to_string());
        }

        let window_seconds = validate_window_seconds(
            "ai_rate_limiter",
            "window_seconds",
            optional_u64(config, "window_seconds")?.unwrap_or(60),
        )?;

        let count_mode = optional_string(config, "count_mode")?
            .unwrap_or("total_tokens")
            .to_string();
        if !matches!(
            count_mode.as_str(),
            "prompt_tokens" | "completion_tokens" | "total_tokens"
        ) {
            return Err(format!(
                "ai_rate_limiter: unknown 'count_mode' value '{}' (expected 'prompt_tokens', 'completion_tokens', or 'total_tokens')",
                count_mode
            ));
        }

        let limit_by = optional_string(config, "limit_by")?
            .unwrap_or("consumer")
            .to_string();
        if !matches!(limit_by.as_str(), "consumer" | "ip") {
            return Err(format!(
                "ai_rate_limiter: unknown 'limit_by' value '{}' (expected 'consumer' or 'ip')",
                limit_by
            ));
        }

        let expose_headers = optional_bool(config, "expose_headers")?.unwrap_or(false);
        let provider = match optional_string(config, "provider")? {
            Some(raw) => {
                let provider = raw.trim();
                if provider.is_empty() {
                    return Err("ai_rate_limiter: 'provider' must not be empty".to_string());
                }
                provider.to_ascii_lowercase()
            }
            None => "auto".to_string(),
        };
        if provider != "auto" && parse_ai_provider(&provider).is_none() {
            return Err(format!(
                "ai_rate_limiter: unknown 'provider' value '{}' (expected auto, openai, anthropic, google, cohere, mistral, bedrock, or tgi)",
                provider
            ));
        }

        let on_unmetered_response = match optional_string(config, "on_unmetered_response")? {
            Some(raw) => OnUnmeteredResponse::parse(raw).ok_or_else(|| {
                format!(
                    "ai_rate_limiter: unknown 'on_unmetered_response' value '{raw}' (expected 'reject', 'charge_estimate', or 'warn')"
                )
            })?,
            None => OnUnmeteredResponse::ChargeEstimate,
        };

        // Scope the per-request federation idempotency flag to THIS limiter
        // instance via a process-unique id, not to a budget-config fingerprint.
        // Each instance owns its own token window (a separate in-memory map for
        // the local backend, or a distinct `redis_key_prefix` for the centralized
        // backend), so the idempotency flag — which guards against `after_proxy`
        // running twice for ONE request — must be per instance too. A
        // config-derived key would be shared by two limiters with identical
        // budget config that are nonetheless SEPARATE budgets (e.g. different
        // `sync_mode`/`redis_key_prefix`, or just two local instances): the first
        // to run would set the flag and the second would skip its own federation
        // reconcile, under-counting its own window for `ai_federation` traffic and
        // contradicting the documented per-instance accounting contract. The id
        // keeps the within-request, within-instance dedup semantics intact while
        // never cross-suppressing a sibling instance.
        let instance_id = INSTANCE_ID_COUNTER.fetch_add(1, Ordering::Relaxed);
        let federation_flag_key =
            format!("{FEDERATION_TOKENS_RECORDED_METADATA_KEY_PREFIX}:{instance_id}");
        // The whole reservation lifecycle is scoped by the same id, for the same
        // reason: independent budgets must never read back each other's
        // reservation state (GHSA-wh4p-pmxm-3784). A process-unique counter —
        // not a config fingerprint and not a reload generation — is what keeps
        // two intentionally-separate instances distinct even when their config
        // is byte-identical, and keeps a reloaded instance from aliasing an
        // unrelated one.
        let reservation_record_key =
            format!("{RESERVATION_RECORD_METADATA_KEY_PREFIX}:{instance_id}");
        let meter_flag_key = format!("{METER_RESPONSE_METADATA_KEY_PREFIX}:{instance_id}");

        Ok(Self {
            token_limit,
            window_seconds,
            count_mode,
            limit_by,
            expose_headers,
            provider,
            on_unmetered_response,
            federation_flag_key,
            reservation_record_key,
            meter_flag_key,
            stream_handoff_id: allocate_response_stream_handoff_id(),
            limiter: RateLimitBackend::from_plugin_config_with_config_id(
                "ai_rate_limiter",
                config_id,
                config,
                &http_client,
                AiTokenRateAlgorithm::new(token_limit, window_seconds),
            )?,
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

    /// Effective `redis_failure_policy` for advisory coverage. Not a production
    /// API.
    #[allow(dead_code)] // used only by external tests; dead in binary test target
    pub(crate) fn redis_failure_policy_for_test(
        &self,
    ) -> Option<super::utils::rate_limit::RedisFailurePolicy> {
        self.limiter.redis_failure_policy()
    }

    /// Controllable-time seed for external cleanup tests. Not a production API.
    #[allow(dead_code)] // used only by external tests; dead in binary test target
    pub(crate) fn seed_key_at_for_test(&self, key: String, now: Instant) {
        let _ = self
            .limiter
            .check_local_at(key, &AiRateLimitOp::Reserve { tokens: 1 }, now);
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
            .check_local_at_with_capacity(
                key,
                &AiRateLimitOp::Reserve { tokens: 1 },
                now,
                max_entries,
            )
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

    /// Whether THIS instance has already settled its reservation for the
    /// request. The record is instance-scoped and its key is private, so
    /// external coverage of the settle-once invariant goes through here rather
    /// than guessing a metadata key. Not a production API.
    #[doc(hidden)]
    #[allow(dead_code)] // used only by external tests; dead in binary test target
    pub fn reservation_settled_for_test(&self, ctx: &RequestContext) -> bool {
        self.load_reservation(ctx).settled
    }

    /// Tokens THIS instance reserved for the request. Not a production API.
    #[doc(hidden)]
    #[allow(dead_code)] // used only by external tests; dead in binary test target
    pub fn reserved_tokens_for_test(&self, ctx: &RequestContext) -> u64 {
        self.load_reservation(ctx).reserved_tokens
    }

    /// Whether THIS instance classified the request as an AI call. Not a
    /// production API.
    #[doc(hidden)]
    #[allow(dead_code)] // used only by external tests; dead in binary test target
    pub fn ai_request_for_test(&self, ctx: &RequestContext) -> bool {
        self.load_reservation(ctx).ai_request
    }

    /// The `on_unmetered_response` action THIS instance applied, if any. Not a
    /// production API.
    #[doc(hidden)]
    #[allow(dead_code)] // used only by external tests; dead in binary test target
    pub fn unmetered_action_for_test(&self, ctx: &RequestContext) -> Option<String> {
        self.load_reservation(ctx).unmetered_action
    }

    /// Seed this instance's reservation record so a test can drive a response
    /// phase without replaying admission. Not a production API.
    #[doc(hidden)]
    #[allow(dead_code)] // used only by external tests; dead in binary test target
    pub fn seed_reservation_for_test(
        &self,
        ctx: &mut RequestContext,
        reserved_tokens: u64,
        reservation_id: Option<u64>,
        reserved_window_index: Option<u64>,
        ai_request: bool,
    ) {
        let mut record = self.load_reservation(ctx);
        record.reserved_tokens = reserved_tokens;
        record.reservation_id = reservation_id;
        record.reserved_window_index = reserved_window_index;
        record.ai_request = ai_request;
        self.store_reservation(ctx, &record);
    }

    /// Force this instance's applied unmetered action. Not a production API.
    #[doc(hidden)]
    #[allow(dead_code)] // used only by external tests; dead in binary test target
    pub fn seed_unmetered_action_for_test(&self, ctx: &mut RequestContext, action: &str) {
        let mut record = self.load_reservation(ctx);
        record.unmetered_action = Some(action.to_string());
        self.store_reservation(ctx, &record);
    }

    fn rate_key(&self, ctx: &RequestContext) -> String {
        if self.limit_by == "consumer"
            && let Some(identity) = ctx.effective_identity()
        {
            let mut key = String::with_capacity(identity.len() + 9);
            key.push_str("consumer:");
            key.push_str(identity);
            return key;
        }

        let mut key = String::with_capacity(ctx.client_ip.len() + 3);
        key.push_str("ip:");
        key.push_str(&ctx.client_ip);
        key
    }

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
        // retain per second so high RPS cannot turn periodic reclamation
        // into an unbounded scan storm.
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

    /// Record this instance's authoritative window snapshot.
    ///
    /// The values land BOTH in this instance's own record (which is what
    /// [`Self::apply_exposed_headers`] publishes, so an instance never advertises
    /// a sibling's numbers) and in the shared, log-facing `ai_ratelimit_*`
    /// metadata keys. The shared keys are presentation only and are never read
    /// back for an accounting decision.
    fn store_metadata(
        &self,
        ctx: &mut RequestContext,
        outcome: &RateLimitOutcome,
        record: &mut InstanceReservation,
    ) {
        if !self.expose_headers {
            return;
        }
        // A fail-closed reconciliation outcome carries no authoritative counter
        // (centralized enforcement could not be consulted). Publishing its empty
        // remaining/usage would advertise `0 used` for a budget this gateway
        // cannot see; leave the previously stored values in place instead.
        if outcome.enforcement_unavailable {
            return;
        }

        ctx.metadata.insert(
            "ai_ratelimit_limit".to_string(),
            self.token_limit.to_string(),
        );
        ctx.metadata.insert(
            "ai_ratelimit_window".to_string(),
            self.window_seconds.to_string(),
        );
        ctx.metadata.insert(
            "ai_ratelimit_remaining".to_string(),
            outcome.remaining.unwrap_or(0).to_string(),
        );
        ctx.metadata.insert(
            "ai_ratelimit_usage".to_string(),
            outcome.usage.unwrap_or(0).to_string(),
        );
        record.exposed_remaining = Some(outcome.remaining.unwrap_or(0));
        record.exposed_usage = Some(outcome.usage.unwrap_or(0));
    }

    /// Copy exposed rate-limit telemetry from request metadata into the
    /// client-visible response map. Used by `after_proxy` (admission and
    /// federation/gateway reconcile) and again by `on_response_body` after
    /// buffered usage reconciliation so the final headers match the bucket.
    /// Copy this instance's exposed rate-limit telemetry into the
    /// client-visible response map.
    ///
    /// Limit/window come from this instance's own configuration and
    /// remaining/usage from its own [`InstanceReservation`] snapshot, so with
    /// several exposing instances each publishes ITS OWN budget rather than
    /// reading whichever sibling wrote the shared metadata last. The header
    /// NAMES are still a single shared namespace, so when more than one
    /// instance sets `expose_headers` the last one in configured order is the
    /// one the client sees — documented in `docs/plugins.md`; expose headers on
    /// at most one instance per proxy if the values must be unambiguous.
    fn apply_exposed_headers(
        &self,
        record: &InstanceReservation,
        response_headers: &mut HashMap<String, String>,
    ) {
        if !self.expose_headers {
            return;
        }
        let Some(remaining) = record.exposed_remaining else {
            return;
        };

        response_headers.insert(
            "x-ai-ratelimit-limit".to_string(),
            self.token_limit.to_string(),
        );
        response_headers.insert(
            "x-ai-ratelimit-window".to_string(),
            self.window_seconds.to_string(),
        );
        response_headers.insert("x-ai-ratelimit-remaining".to_string(), remaining.to_string());
        response_headers.insert(
            "x-ai-ratelimit-usage".to_string(),
            record.exposed_usage.unwrap_or(0).to_string(),
        );
    }

    fn reject(&self, usage: u64) -> PluginResult {
        let mut headers = HashMap::new();
        if self.expose_headers {
            headers.insert(
                "x-ai-ratelimit-limit".to_string(),
                self.token_limit.to_string(),
            );
            headers.insert("x-ai-ratelimit-remaining".to_string(), "0".to_string());
            headers.insert(
                "x-ai-ratelimit-window".to_string(),
                self.window_seconds.to_string(),
            );
            headers.insert("x-ai-ratelimit-usage".to_string(), usage.to_string());
        }

        PluginResult::Reject {
            status_code: 429,
            body: format!(
                r#"{{"error":"AI token rate limit exceeded","details":"Token usage {} exceeds limit {} in window of {} seconds"}}"#,
                usage, self.token_limit, self.window_seconds
            ),
            headers,
        }
    }

    /// Generic refusal for "centralized enforcement could not be consulted".
    ///
    /// Shared by admission (`before_proxy`) and by authoritative post-response
    /// usage reconciliation so the two cannot drift apart. Carries **no**
    /// rate-limit headers: this gateway has no authoritative counter to report,
    /// and the body names no endpoint, key, credential, or consumer identity —
    /// a caller must not learn that a centralized store exists, let alone its
    /// state.
    fn reject_enforcement_unavailable(&self) -> PluginResult {
        PluginResult::Reject {
            status_code: ENFORCEMENT_UNAVAILABLE_STATUS,
            body: ENFORCEMENT_UNAVAILABLE_BODY.to_string(),
            headers: HashMap::new(),
        }
    }

    fn reject_unmetered(&self) -> PluginResult {
        PluginResult::Reject {
            status_code: 502,
            body: r#"{"error":"AI token usage missing","details":"Successful AI response did not include token usage metadata required by ai_rate_limiter"}"#.to_string(),
            headers: HashMap::new(),
        }
    }

    fn reject_capacity(&self) -> PluginResult {
        // The metric is deliberately the only operational signal here. A
        // warning per attacker-selected new key would turn fail-closed
        // admission into log amplification.
        super::prometheus_metrics::global_registry().record_rate_limit_exceeded();
        PluginResult::Reject {
            status_code: 429,
            body: CAPACITY_REJECT_BODY.to_string(),
            headers: HashMap::new(),
        }
    }

    async fn reserve_usage(&self, key: String, tokens: u64) -> Option<RateLimitOutcome> {
        self.limiter
            .check_with_redis_key_and_local_capacity(
                key.clone(),
                || key.clone(),
                &AiRateLimitOp::Reserve { tokens },
                MAX_STATE_ENTRIES,
            )
            .await
    }

    async fn adjust_usage(
        &self,
        key: String,
        reservation_id: Option<u64>,
        reserved_window_index: Option<u64>,
        reservation_backend: ReservationBackend,
        actual_tokens: u64,
        reserved_tokens: u64,
    ) -> Option<RateLimitOutcome> {
        let delta = Self::reservation_delta(actual_tokens, reserved_tokens);
        // Skip only when there is genuinely nothing to apply on ANY backend:
        // no actual usage to charge and no reservation to release. `delta == 0`
        // alone is NOT sufficient — when a backend switch is detected the active
        // backend charges the FULL `actual_tokens` (not the relative `delta`), so
        // a request whose `actual == reserved` (`delta == 0`) but `actual > 0`
        // must still be dispatched so the now-active backend records that usage.
        if actual_tokens == 0 && delta == 0 {
            return None;
        }
        self.limiter
            .check_with_redis_key_and_local_capacity(
                key.clone(),
                || key.clone(),
                &AiRateLimitOp::AdjustUsage {
                    reservation_id,
                    reserved_window_index,
                    reservation_backend,
                    actual_tokens,
                    delta,
                },
                MAX_STATE_ENTRIES,
            )
            .await
    }

    /// This instance's reservation record for the request, or a default (empty)
    /// record when it never reserved.
    ///
    /// An unreadable record degrades to `Default` rather than to a sibling's
    /// state: the worst case is that this instance behaves as if it reserved
    /// nothing, which never charges another budget and never releases one twice.
    fn load_reservation(&self, ctx: &RequestContext) -> InstanceReservation {
        ctx.metadata
            .get(&self.reservation_record_key)
            .and_then(|raw| serde_json::from_str::<InstanceReservation>(raw).ok())
            .unwrap_or_default()
    }

    /// Persist this instance's record and refresh its O(1) meter index.
    ///
    /// The index is recomputed here — the single write point for the record — so
    /// it cannot drift from the state it summarizes.
    fn store_reservation(&self, ctx: &mut RequestContext, record: &InstanceReservation) {
        if record.needs_response_body() {
            ctx.metadata
                .insert(self.meter_flag_key.clone(), "true".to_string());
        } else {
            ctx.metadata.remove(&self.meter_flag_key);
        }
        if record.is_empty() {
            ctx.metadata.remove(&self.reservation_record_key);
            return;
        }
        // Serialization of a fixed, small struct of integers/bools/short
        // strings cannot fail; if it somehow did, dropping the record is the
        // fail-closed outcome (this instance then behaves as if it never
        // reserved rather than inheriting stale state).
        match serde_json::to_string(record) {
            Ok(encoded) => {
                ctx.metadata
                    .insert(self.reservation_record_key.clone(), encoded);
            }
            Err(_) => {
                ctx.metadata.remove(&self.reservation_record_key);
            }
        }
    }

    /// The original backend status, if a backend response was produced. Recorded
    /// in two complementary places so it survives every after-proxy ordering:
    /// (1) this plugin's own genuine `after_proxy` pass, and (2) the proxy's
    /// `run_after_proxy_hooks`, *before* the after_proxy loop — the latter covers
    /// the case where a lower-priority after_proxy plugin (e.g.
    /// `response_size_limiting` at 3490 < this plugin's 4200) rejects a 2xx so
    /// this plugin's genuine pass never runs. Absent only when no backend
    /// response existed at all (a before-proxy gateway rejection that
    /// short-circuited dispatch, or the federation synthetic-response path, which
    /// reconciles via its own branch).
    fn backend_status(ctx: &RequestContext) -> Option<u16> {
        ctx.metadata
            .get(BACKEND_STATUS_METADATA_KEY)
            .and_then(|value| value.parse::<u16>().ok())
    }

    fn should_release_gateway_rejection(
        ctx: &RequestContext,
        record: &InstanceReservation,
    ) -> bool {
        // Only release when this is a genuine gateway rejection that never
        // produced a successful backend response. If the backend already
        // returned 2xx and a *later* plugin rejected it — either a response-body
        // plugin (e.g. ai_response_guard via on_response_body) or a
        // lower-priority after_proxy plugin (e.g. response_size_limiting at 3490,
        // which makes this plugin's genuine after_proxy pass at 4200 never run) —
        // the provider call consumed tokens, so keep the reservation charged
        // rather than making the call free. The 2xx backend status is recorded by
        // `run_after_proxy_hooks` before the after_proxy loop, so it is present
        // even when this plugin's own pass is skipped. A recorded non-2xx backend
        // status, or no recorded backend status at all (a before-proxy reject that
        // short-circuited dispatch), still releases.
        if Self::backend_status(ctx).is_some_and(|status| (200..300).contains(&status)) {
            return false;
        }

        ctx.metadata
            .get(REJECTION_RESPONSE_METADATA_KEY)
            .is_some_and(|value| value == "true")
            && record.reserved_tokens > 0
            && record.unmetered_action.as_deref() != Some(OnUnmeteredResponse::Reject.as_str())
    }

    fn reservation_delta(actual_tokens: u64, reserved_tokens: u64) -> i64 {
        let delta = i128::from(actual_tokens) - i128::from(reserved_tokens);
        delta.clamp(i128::from(i64::MIN), i128::from(i64::MAX)) as i64
    }

    /// Estimate the tokens to pre-reserve for this request and report whether it
    /// looked like an AI call at all. The returned `bool` is `true` only when the
    /// buffered `request_body` parsed as JSON **and** carries a recognized LLM
    /// request field (see [`json_looks_like_ai_request`]); a parseable but non-LLM
    /// JSON `POST` returns `false` so a shared proxy doesn't subject ordinary API
    /// traffic to the `on_unmetered_response` policy. The estimate itself may still
    /// be 0 for a genuine AI request (e.g. `completion_tokens` mode with no `max_*`
    /// cap), which is why callers must track the AI-request signal separately from
    /// `reserved_tokens > 0`. Parses the body exactly once.
    fn estimate_request_tokens(&self, ctx: &RequestContext) -> (bool, u64) {
        let Some(body) = ctx.metadata.get("request_body") else {
            return (false, 0);
        };
        let Ok(json) = serde_json::from_str::<Value>(body) else {
            return (false, 0);
        };
        // Gate the AI-request marker on LLM shape, not mere JSON parseability.
        // The classification is what decides whether this instance meters the
        // response at all, so without the gate a `reject`-mode limiter would 502
        // (and `charge_estimate` would bill) an ordinary non-LLM JSON `POST` that
        // happens to share the proxy. See `InstanceReservation::ai_request`.
        if !json_looks_like_ai_request(&json) {
            return (false, 0);
        }

        (true, self.estimate_request_tokens_from_json(&json))
    }

    fn estimate_request_tokens_from_json(&self, json: &Value) -> u64 {
        let prompt_tokens = estimate_prompt_tokens(json);
        let completion_tokens = requested_completion_tokens(json);
        match self.count_mode.as_str() {
            "prompt_tokens" => prompt_tokens,
            "completion_tokens" => completion_tokens,
            _ => prompt_tokens.saturating_add(completion_tokens),
        }
    }

    async fn reconcile_usage(
        &self,
        ctx: &mut RequestContext,
        response_status: u16,
        actual_tokens: Option<u64>,
        unmetered_detail: &str,
    ) -> PluginResult {
        let mut record = self.load_reservation(ctx);
        let result = self
            .reconcile_with_record(
                ctx,
                &mut record,
                response_status,
                actual_tokens,
                unmetered_detail,
            )
            .await;
        self.store_reservation(ctx, &record);
        result
    }

    /// The reconciliation body, operating on THIS instance's record.
    ///
    /// Settling is exactly-once per instance per request: every terminal path
    /// (authoritative charge, non-2xx release, unmetered posture, gateway
    /// rejection release, streaming termination) runs through here and is gated
    /// on `record.settled`.
    async fn reconcile_with_record(
        &self,
        ctx: &mut RequestContext,
        record: &mut InstanceReservation,
        response_status: u16,
        actual_tokens: Option<u64>,
        unmetered_detail: &str,
    ) -> PluginResult {
        let reserved_tokens = record.reserved_tokens;
        let reservation_id = record.reservation_id;
        let reserved_window_index = record.reserved_window_index;
        let reservation_backend = record.backend();

        // Exactly-once settlement for THIS instance. A request can reach a
        // terminal reconcile more than once across phases: a non-2xx release in
        // `on_response_body` followed by a gateway-rejection re-run of
        // `after_proxy` for the same non-2xx backend; a synthetic 2xx
        // short-circuit followed by a response-body rejection that re-runs the
        // reject hooks; a streaming terminal hook alongside a rejection path.
        //
        // Both the charge and the release are gated. Without the gate on the
        // release, the Redis backend — which has no per-entry reservation id and
        // simply subtracts `reserved` from the shared window — double-subtracts
        // and under-counts the consumer's own budget, permitting the
        // oversubscription this reservation model exists to close. Without the
        // gate on the charge, a re-run could charge the same provider tokens
        // twice. Previously this flag was a SHARED metadata key, so the first
        // instance to settle suppressed every sibling's settlement
        // (GHSA-wh4p-pmxm-3784); it is now part of the per-instance record.
        if record.settled {
            return PluginResult::Continue;
        }

        if let Some(actual_tokens) = actual_tokens {
            record.settled = true;
            record.actual_tokens = Some(actual_tokens);
            ctx.metadata.insert(
                ACTUAL_TOKENS_METADATA_KEY.to_string(),
                actual_tokens.to_string(),
            );
            if let Some(outcome) = self
                .adjust_usage(
                    self.rate_key(ctx),
                    reservation_id,
                    reserved_window_index,
                    reservation_backend,
                    actual_tokens,
                    reserved_tokens,
                )
                .await
            {
                // The authoritative charge could not be recorded: centralized
                // enforcement went away between admission/reservation and this
                // post-response reconcile, and `redis_failure_policy` is
                // `fail_closed`. Delivering the upstream 2xx would hand the
                // client a completion whose tokens nothing charged — the exact
                // budget bypass the fail-closed default exists to prevent — so
                // refuse with the same generic 503 admission uses.
                //
                // Only for a successful response. When the response is already
                // non-2xx the charge/release failure is a conservative
                // over-count against this consumer's own budget, and replacing
                // an error response with a different error buys nothing.
                //
                // No warning here: the failover backend already emits one
                // bounded operational warning per outage, and this path runs
                // once per request.
                if outcome.enforcement_unavailable {
                    if (200..300).contains(&response_status) {
                        return self.reject_enforcement_unavailable();
                    }
                    return PluginResult::Continue;
                }
                // Refresh expose-header metadata to the post-reconcile bucket so
                // later header copies (after_proxy federation/gateway, or
                // on_response_body on the normal path) describe actual usage —
                // not the pre-request admission estimate (#2261).
                self.store_metadata(ctx, &outcome, record);
            }
            return PluginResult::Continue;
        }

        // Mark settled before doing any window work so an unmetered `reject`
        // (which returns a 502 rather than `Continue`) is likewise settled
        // exactly once.
        record.settled = true;

        if !(200..300).contains(&response_status) {
            if let Some(outcome) = self
                .adjust_usage(
                    self.rate_key(ctx),
                    reservation_id,
                    reserved_window_index,
                    reservation_backend,
                    0,
                    reserved_tokens,
                )
                .await
            {
                self.store_metadata(ctx, &outcome, record);
            }
            return PluginResult::Continue;
        }

        // The `on_unmetered_response` policy (charge_estimate / warn / reject)
        // only applies when THIS instance identified the request as an AI call.
        // Without the gate a `reject`-mode limiter would turn a GET, a
        // 204/empty-body 200, a non-JSON 2xx, or a non-LLM JSON 2xx on the same
        // proxy into a 502 — a proxy-wide blast radius. Gate on the
        // classification, NOT `reserved_tokens > 0`: `completion_tokens` mode
        // reserves 0 for valid AI calls with no output cap, and those must still
        // be subject to the policy. A non-AI response is left untouched (no
        // reject, no charge); any reservation it somehow carries is 0, so the
        // skipped `adjust_usage` is a no-op anyway.
        if !record.ai_request {
            return PluginResult::Continue;
        }

        match self.on_unmetered_response {
            OnUnmeteredResponse::ChargeEstimate => {
                record.unmetered_action =
                    Some(OnUnmeteredResponse::ChargeEstimate.as_str().to_string());
                if reserved_tokens == 0 && record.compressed_ai_candidate {
                    warn!(
                        provider = %self.provider,
                        count_mode = %self.count_mode,
                        detail = %unmetered_detail,
                        "ai_rate_limiter: rejecting compressed AI response without token usage because no safe pre-request estimate exists"
                    );
                    return self.reject_unmetered();
                }
                warn!(
                    provider = %self.provider,
                    count_mode = %self.count_mode,
                    reserved_tokens,
                    detail = %unmetered_detail,
                    "ai_rate_limiter: successful response did not include token usage; keeping pre-request reservation"
                );
                PluginResult::Continue
            }
            OnUnmeteredResponse::Warn => {
                record.unmetered_action = Some(OnUnmeteredResponse::Warn.as_str().to_string());
                if let Some(outcome) = self
                    .adjust_usage(
                        self.rate_key(ctx),
                        reservation_id,
                        reserved_window_index,
                        reservation_backend,
                        0,
                        reserved_tokens,
                    )
                    .await
                {
                    self.store_metadata(ctx, &outcome, record);
                }
                warn!(
                    provider = %self.provider,
                    count_mode = %self.count_mode,
                    reserved_tokens,
                    detail = %unmetered_detail,
                    "ai_rate_limiter: successful response did not include token usage; releasing reservation because on_unmetered_response=warn"
                );
                PluginResult::Continue
            }
            OnUnmeteredResponse::Reject => {
                record.unmetered_action = Some(OnUnmeteredResponse::Reject.as_str().to_string());
                warn!(
                    provider = %self.provider,
                    count_mode = %self.count_mode,
                    reserved_tokens,
                    detail = %unmetered_detail,
                    "ai_rate_limiter: rejecting successful response without token usage"
                );
                self.reject_unmetered()
            }
        }
    }

    fn read_tokens_from_metadata(&self, metadata: &HashMap<String, String>) -> Option<u64> {
        let key = match self.count_mode.as_str() {
            "prompt_tokens" => "ai_prompt_tokens",
            "completion_tokens" => "ai_completion_tokens",
            _ => "ai_total_tokens",
        };
        metadata
            .get(key)
            .and_then(|value| value.parse::<u64>().ok())
    }

    fn extract_token_count(&self, body: &[u8]) -> Option<u64> {
        let json: Value = serde_json::from_slice(body).ok()?;
        let usage = if self.provider != "auto" {
            extract_response_usage(&json, parse_ai_provider(&self.provider)?)
        } else {
            extract_response_usage(&json, detect_response_provider(&json)?)
        };
        usage.total_for_mode(&self.count_mode)
    }

    /// Extract usage from a BUFFERED stream body using the same bounded,
    /// incremental scanner the streaming inspector drives.
    ///
    /// Sharing one decoder is what keeps the buffered and streamed paths from
    /// reporting different numbers for the same bytes, and it is why the
    /// buffered path also gained Gemini `usageMetadata`, AWS event-stream, and
    /// native TGI coverage. A malformed or truncated body reports no usage, so
    /// the caller applies the configured unmetered posture instead of charging
    /// a fabricated zero.
    fn extract_token_count_from_stream(
        &self,
        format: StreamUsageFormat,
        body: &[u8],
    ) -> Option<u64> {
        let fixed_provider = if self.provider == "auto" {
            None
        } else {
            parse_ai_provider(&self.provider)
        };
        let mut scanner = StreamUsageScanner::new(format, fixed_provider);
        scanner.observe(body);
        scanner.finish();
        if scanner.malformed() {
            return None;
        }
        scanner
            .authoritative_usage()
            .and_then(|usage| usage.total_for_mode(&self.count_mode))
    }
}

/// Output-token cap requested by the client, across OpenAI and provider-native
/// request shapes. Sizes the `completion_tokens` portion of the pre-dispatch
/// reservation. Returns the max across every recognized field (only one is
/// normally present, so `max` is a safe union) or 0 when none is set.
///
/// Top-level: OpenAI `max_tokens` / `max_completion_tokens`, OpenAI Responses
/// `max_output_tokens`, legacy Anthropic `max_tokens_to_sample`, TGI/HuggingFace
/// `max_new_tokens`, and the rarer top-level provider forms `maxOutputTokens` /
/// `maxTokens`. Nested provider containers: Gemini/Vertex
/// `generationConfig.maxOutputTokens`, AWS Bedrock Converse
/// `inferenceConfig.maxTokens`, Amazon Titan `textGenerationConfig.maxTokenCount`,
/// and TGI `parameters.max_new_tokens`. Without the nested forms a native Gemini,
/// Bedrock, or Titan request reserves 0 in `completion_tokens` mode, so a burst of
/// capped completions can oversubscribe the budget until post-response
/// reconciliation. Mirrors the token-field coverage in `ai_request_guard`.
fn requested_completion_tokens(json: &Value) -> u64 {
    let top_level = [
        "max_tokens",
        "max_completion_tokens",
        "max_output_tokens",
        "max_tokens_to_sample",
        "max_new_tokens",
        "maxOutputTokens",
        "maxTokens",
    ]
    .iter()
    .filter_map(|field| json.get(*field).and_then(Value::as_u64))
    .max()
    .unwrap_or(0);

    let nested = [
        ("generationConfig", "maxOutputTokens"),
        ("generation_config", "max_output_tokens"),
        ("inferenceConfig", "maxTokens"),
        ("inference_config", "max_tokens"),
        ("textGenerationConfig", "maxTokenCount"),
        ("parameters", "max_new_tokens"),
    ]
    .iter()
    .filter_map(|(container, field)| {
        json.get(*container)
            .and_then(|nested| nested.get(*field))
            .and_then(Value::as_u64)
    })
    .max()
    .unwrap_or(0);

    top_level.max(nested)
}

/// Strong, LLM-idiomatic top-level fields — each marks an AI request on its own.
/// These (chat message arrays, Gemini `contents`, Cohere `chat_history`, TGI/Titan
/// inputs, the legacy completions `prompt`) do not appear in ordinary non-LLM JSON,
/// so classifying on them does not risk a false `on_unmetered_response` rejection.
/// `system` is intentionally absent: an Anthropic body always carries `messages`,
/// so a bare top-level `system` (a common generic word) is never the sole signal.
const AI_REQUEST_STRONG_MARKERS: &[&str] = &[
    "messages",             // OpenAI / Anthropic / Mistral chat (array)
    "contents",             // Google Gemini / Vertex (array)
    "chat_history",         // Cohere history (array)
    "inputs",               // TGI / HuggingFace
    "inputText",            // Amazon Titan
    "prompt",               // legacy completions
    "input",                // OpenAI Responses / embeddings
    "previous_response_id", // OpenAI Responses continuation (no `input` needed)
];

/// Generic words that ALSO appear in ordinary non-LLM JSON (e.g. `{"message":
/// "contact me"}`, `{"instructions": "..."}`). They mark an AI request only when
/// corroborated by a top-level `model` field — which real LLM requests (Cohere v2
/// chat, OpenAI Responses) carry — so a bare `{"message": "..."}` on a shared
/// proxy is NOT classified as AI and is never turned into a false 502 under
/// `reject`. `instructions` is the OpenAI Responses system field (matching
/// `ai_request_guard::looks_like_responses`), gated on `model` for the same
/// false-positive reason. (`input` stays strong: as a top-level request field it
/// is LLM-idiomatic, and Codex flagged only the much more generic `message`.)
const AI_REQUEST_WEAK_MARKERS: &[&str] = &["message", "instructions"];

/// Whether a parsed request body looks like an LLM/AI call. A strong marker alone
/// qualifies; a generic weak marker qualifies only alongside a top-level `model`.
/// A JSON object matching neither is treated as non-AI traffic and left out of the
/// token-budget / unmetered-response path.
fn json_looks_like_ai_request(json: &Value) -> bool {
    let Some(obj) = json.as_object() else {
        return false;
    };
    if AI_REQUEST_STRONG_MARKERS
        .iter()
        .any(|field| obj.contains_key(*field))
    {
        return true;
    }
    obj.contains_key("model")
        && AI_REQUEST_WEAK_MARKERS
            .iter()
            .any(|field| obj.contains_key(*field))
}

/// True when a `content-encoding` header marks the request body as encoded with
/// anything other than `identity`.
///
/// `ai_rate_limiter` runs in `before_proxy`, but request-body decompression (the
/// `compression` plugin's `decompress_request`) only happens later in
/// `transform_request_body`. At this phase `ctx.metadata["request_body"]` still
/// holds the *compressed wire bytes*, not UTF-8 JSON — so a token estimate
/// derived from it would parse-fail (estimate 0) or, worse, undercount, letting
/// compressed AI requests dodge the estimate-based pre-reservation. When this
/// returns true the caller skips pre-reservation entirely and falls back to the
/// no-reservation `CheckBudget` path; post-response reconciliation then charges
/// the actual usage reported by the provider. Mirrors the same phase-ordering
/// handling `ai_request_guard` uses for compressed bodies (#1919).
/// Allocation-free; tolerant of comma-separated encoding lists.
fn has_non_identity_content_encoding(headers: &HashMap<String, String>) -> bool {
    headers.get("content-encoding").is_some_and(|value| {
        value
            .split(',')
            .map(|token| token.trim())
            .any(|token| !token.is_empty() && !token.eq_ignore_ascii_case("identity"))
    })
}

/// True for native gRPC (`application/grpc*`) and gRPC-Web (`application/grpc-web*`)
/// content types, including the `+json` variants. Their bodies are length-prefixed
/// wire frames, not a bare JSON document, so they must be excluded from the
/// JSON-AI candidate path even though `is_json_content_type` matches the `+json`
/// suffix — otherwise a normal HTTP-200 gRPC response without LLM usage could be
/// turned into a 502 by `on_unmetered_response`. Mirrors `ai_request_guard`.
fn is_framed_grpc_content_type(content_type: &str) -> bool {
    crate::proxy::backend_dispatch::is_native_grpc_content_type(content_type.as_bytes())
        || crate::plugins::grpc_web::is_grpc_web_content_type(content_type)
}

fn estimate_prompt_tokens(json: &Value) -> u64 {
    let chars = prompt_character_count(json);
    if chars == 0 { 0 } else { chars.div_ceil(4) }
}

fn prompt_character_count(json: &Value) -> u64 {
    let mut chars = 0_u64;

    if let Some(system) = json.get("system") {
        chars = chars.saturating_add(string_value_character_count(system));
    }
    if let Some(messages) = json.get("messages") {
        chars = chars.saturating_add(string_value_character_count(messages));
    }
    if let Some(prompt) = json.get("prompt") {
        chars = chars.saturating_add(string_value_character_count(prompt));
    }
    if let Some(input) = json.get("input") {
        chars = chars.saturating_add(string_value_character_count(input));
    }
    if let Some(contents) = json.get("contents") {
        chars = chars.saturating_add(string_value_character_count(contents));
    }
    if let Some(tools) = json.get("tools") {
        chars = chars.saturating_add(string_value_character_count(tools));
    }

    if chars == 0 {
        // No recognized prompt field carried text. Fall back to counting the whole
        // body — this is how AI markers that are NOT summed above (`inputs`,
        // `inputText`, `chat_history`, `previous_response_id`) get their prompt
        // text counted. That whole-body walk already includes any `data_sources` /
        // `dataSources` role_information, so the targeted add below is gated behind
        // this early return: counting it again would double it, and (worse) making
        // `chars` nonzero here would skip the fallback and drop the real prompt,
        // reserving only the instruction.
        return string_value_character_count(json);
    }

    // Azure OpenAI "On Your Data" carries a per-data-source system instruction in
    // `data_sources[].parameters.role_information` (current chat-completions data
    // plane) / `dataSources[].parameters.roleInformation` (the original
    // extensions-API camelCase). That text is sent to the model and billed as
    // input, but it is not part of any recognized field above. A recognized field
    // DID contribute (we are past the zero-char fallback), so add the instruction
    // text explicitly — otherwise an On Your Data request (which always carries
    // `messages`) would never count it and the reservation would under-estimate
    // the prompt the backend bills.
    chars.saturating_add(count_data_source_role_information(json))
}

/// The data-source entries of an Azure OpenAI "On Your Data" request, across both
/// the current chat-completions casing (`data_sources`) and the original
/// extensions-API camelCase (`dataSources`). Both keys are scanned and their
/// arrays concatenated rather than `or_else`-chained, so a body carrying one
/// casing — or, defensively, both — is fully enumerated. Non-array values (and
/// absent keys) yield nothing.
fn azure_data_source_items(json: &Value) -> impl Iterator<Item = &Value> {
    ["data_sources", "dataSources"]
        .into_iter()
        .filter_map(move |key| json.get(key))
        .filter_map(Value::as_array)
        .flatten()
}

/// The `role_information` instruction string(s) for one data-source entry, across
/// both the current `role_information` and the legacy `roleInformation` field
/// casings. Every present key is yielded independently — we deliberately do NOT
/// fold to the first present key with `or_else`, because `Value::as_str` on an
/// empty string returns `Some("")` (not `None`), so an `or_else` chain would stop
/// at a decoy `role_information: ""` and never see a real `roleInformation`
/// sibling. Non-string values are skipped.
fn azure_role_information_values(item: &Value) -> impl Iterator<Item = &str> {
    item.get("parameters").into_iter().flat_map(|parameters| {
        ["role_information", "roleInformation"]
            .into_iter()
            .filter_map(move |key| parameters.get(key))
            .filter_map(Value::as_str)
    })
}

/// Total characters of every Azure "On Your Data" `role_information` instruction
/// in the request. This text is sent to the model and billed as input but is not
/// part of any field `prompt_character_count` already recognizes, so it is counted
/// here. Only the instruction text is summed — the surrounding `endpoint`,
/// `index_name`, and key/secret fields under `parameters` are intentionally left
/// out (they are not prompt input, and counting them would inflate the estimate).
fn count_data_source_role_information(json: &Value) -> u64 {
    let mut chars = 0_u64;
    for item in azure_data_source_items(json) {
        for text in azure_role_information_values(item) {
            chars = chars.saturating_add(text.chars().count() as u64);
        }
    }
    chars
}

/// Object keys whose values carry binary/non-text payloads (base64 image,
/// audio, file, or document bytes) in the common multimodal request shapes.
/// Counting those bytes as prompt characters wildly inflates the estimate — a
/// 1 MB image is ~1.37 M base64 chars (~340k "tokens" at chars/4), which would
/// deny a vision request with a `429` *before* it is ever proxied, and a
/// pre-proxy reject never reconciles, so the bogus estimate is never corrected.
/// Image/audio inputs actually cost a small fixed number of tokens, not
/// `bytes/4`, so we skip these subtrees entirely and rely on the text-bearing
/// parts plus the requested output cap for the estimate.
///
/// Covered shapes:
/// - OpenAI vision part: `{"type":"image_url","image_url":{"url":"data:..."}}`
/// - OpenAI audio part: `{"type":"input_audio","input_audio":{"data":"..."}}`
/// - OpenAI file part: `{"type":"file","file":{"file_data":"..."}}`
/// - Google inline data: `{"inline_data":{"data":"..."}}` / `inlineData`
///
/// Anthropic's `source` block is handled separately (see `source_is_text_document`)
/// because it is binary for image/PDF documents but carries prose for a *text*
/// document (`source:{type:"text",media_type:"text/plain",data:"<prose>"}`); that
/// prose is real prompt input and must be counted, so `source` is not a blanket
/// skip key.
const BINARY_CONTENT_KEYS: &[&str] = &[
    "image_url",
    "input_audio",
    "inline_data",
    "inlineData",
    "file_data",
];

/// Whether an Anthropic-style `source` block carries TEXT prose to count toward
/// the estimate, rather than a binary blob to skip. Only an explicit
/// `type:"text"` source (the Anthropic text-document shape
/// `source:{type:"text",media_type:"text/plain",data:"<prose>"}`) qualifies. We
/// deliberately do NOT key off `media_type` alone: a base64 source can declare
/// `media_type:"text/plain"` (`type:"base64"`) while its `data` is encoded bytes,
/// and counting those would charge the ~33%-inflated base64 payload as prompt
/// text — the exact over-count `BINARY_CONTENT_KEYS` exists to prevent. Every
/// non-`text` shape (`base64`, `url`, `file`, …) is treated as binary and skipped.
fn source_is_text_document(value: &Value) -> bool {
    value
        .as_object()
        .and_then(|obj| obj.get("type"))
        .and_then(Value::as_str)
        == Some("text")
}

fn string_value_character_count(value: &Value) -> u64 {
    match value {
        // A data URL (`data:<mime>;base64,<payload>`) is an inline binary blob,
        // not prose — count it as zero so a base64 image embedded directly in a
        // text field (rather than under a known binary key) still can't inflate
        // the estimate.
        Value::String(value) => {
            if is_data_url(value) {
                0
            } else {
                value.chars().count() as u64
            }
        }
        Value::Array(values) => values.iter().fold(0_u64, |acc, value| {
            acc.saturating_add(string_value_character_count(value))
        }),
        Value::Object(values) => values.iter().fold(0_u64, |acc, (key, value)| {
            if matches!(
                key.as_str(),
                "max_tokens" | "max_completion_tokens" | "max_output_tokens"
            ) {
                return acc;
            }
            // `source` is binary for image/PDF documents (skip) but prose for a
            // text document (`source:{type:"text",...,data:"<prose>"}`) — that
            // prose is sent to the model and billed as input, so count it. Only a
            // genuinely binary source is skipped.
            if key == "source" {
                return if source_is_text_document(value) {
                    acc.saturating_add(string_value_character_count(value))
                } else {
                    acc
                };
            }
            if BINARY_CONTENT_KEYS.contains(&key.as_str()) {
                acc
            } else {
                acc.saturating_add(string_value_character_count(value))
            }
        }),
        _ => 0,
    }
}

/// Maximum length of the header portion (`[<mediatype>][;base64]`) of a `data:`
/// URL we will scan for the mandatory `,` separator. RFC 2397 mediatypes plus
/// parameters are short; this bounds the prose check so an arbitrarily long
/// string that merely starts with `data:` is not scanned end-to-end.
const DATA_URL_MAX_HEADER_LEN: usize = 256;

/// Whether a string is an inline `data:` URL carrying a (typically base64)
/// binary payload, per RFC 2397: `data:[<mediatype>][;base64],<payload>`.
///
/// Requiring the structural `,` separator (and rejecting whitespace/control
/// chars in the header) avoids treating ordinary prose that merely begins with
/// `data:` — e.g. `"data: my notes"` — as a 0-char binary blob. A real data URL
/// has the comma and a whitespace-free header; the prose case has neither.
/// Case-insensitive on the `data:` scheme; allocation-light (byte scan only).
fn is_data_url(value: &str) -> bool {
    let Some(rest) = value
        .get(..5)
        .filter(|prefix| prefix.eq_ignore_ascii_case("data:"))
        .and_then(|_| value.get(5..))
    else {
        return false;
    };

    // The header (between `data:` and the first `,`) is a mediatype + optional
    // parameters: ASCII tokens with no whitespace or control characters. Scan up
    // to a bounded length for the `,`; bail on the first disqualifying byte.
    for &byte in rest.as_bytes().iter().take(DATA_URL_MAX_HEADER_LEN) {
        match byte {
            b',' => return true,
            b if b.is_ascii_whitespace() || b.is_ascii_control() => return false,
            _ => {}
        }
    }
    false
}

fn optional_string<'a>(config: &'a Value, field: &'static str) -> Result<Option<&'a str>, String> {
    let Some(value) = config.get(field) else {
        return Ok(None);
    };
    value
        .as_str()
        .map(Some)
        .ok_or_else(|| format!("ai_rate_limiter: '{field}' must be a string"))
}

fn required_u64(config: &Value, field: &'static str) -> Result<u64, String> {
    let Some(value) = config.get(field) else {
        return Err(format!(
            "ai_rate_limiter: '{field}' is required (positive integer)"
        ));
    };
    value
        .as_u64()
        .ok_or_else(|| format!("ai_rate_limiter: '{field}' must be an unsigned integer"))
}

fn optional_u64(config: &Value, field: &'static str) -> Result<Option<u64>, String> {
    let Some(value) = config.get(field) else {
        return Ok(None);
    };
    value
        .as_u64()
        .map(Some)
        .ok_or_else(|| format!("ai_rate_limiter: '{field}' must be an unsigned integer"))
}

fn optional_bool(config: &Value, field: &'static str) -> Result<Option<bool>, String> {
    let Some(value) = config.get(field) else {
        return Ok(None);
    };
    value
        .as_bool()
        .map(Some)
        .ok_or_else(|| format!("ai_rate_limiter: '{field}' must be a boolean"))
}

#[async_trait]
impl Plugin for AiRateLimiter {
    fn name(&self) -> &str {
        "ai_rate_limiter"
    }

    fn priority(&self) -> u16 {
        super::priority::AI_RATE_LIMITER
    }

    fn supported_protocols(&self) -> &'static [super::ProxyProtocol] {
        // HTTP only. Native gRPC protobuf frames have no supported usage
        // schema here, so every hook of the accounting lifecycle would be
        // inert and the budget would never advance — an operator must not be
        // able to attach this as an enforcement control on native gRPC AI
        // traffic (GHSA-8f27-23x9-f825). See the module-level "Protocol scope"
        // notes: this declaration is the admission boundary, because gRPC is
        // detected per request rather than pinned in proxy config.
        super::HTTP_ONLY_PROTOCOLS
    }

    fn modifies_request_headers(&self) -> bool {
        self.expose_headers
    }

    fn requires_request_body_before_before_proxy(&self) -> bool {
        true
    }

    fn should_buffer_request_body(&self, ctx: &RequestContext) -> bool {
        // A compressed body can't be estimated at `before_proxy` (decompression
        // runs later in `transform_request_body`), so `before_proxy` forces
        // `reserved_tokens = 0` and takes the reconcile-only path for it. Buffering
        // it here would only spend memory/latency (and risk the pre-buffer size
        // cap) for a reservation this plugin will never compute. Returning `false`
        // just withdraws *this* plugin's buffering request — the handler still
        // buffers if a co-located plugin (e.g. `ai_request_guard`) needs the body.
        // See `has_non_identity_content_encoding` and `before_proxy` limitation #4.
        if has_non_identity_content_encoding(&ctx.headers) {
            return false;
        }
        // Framed gRPC-Web bodies reach the HTTP view (native gRPC does not —
        // see `supported_protocols`). Their `+json` media types match
        // `is_json_content_type` but the payload is a length-prefixed wire
        // frame, which `before_proxy` refuses to classify, so buffering one
        // would spend memory for an estimate this plugin will never compute.
        ctx.method == "POST"
            && ctx.headers.get("content-type").is_some_and(|content_type| {
                is_json_content_type(content_type) && !is_framed_grpc_content_type(content_type)
            })
    }

    fn needs_final_request_body_context(&self) -> bool {
        // A compressed POST JSON body decompressed by a co-located `compression`
        // plugin is classified in `on_final_request_body_with_context` (the
        // decompressed bytes are only available there). See `before_proxy`
        // Case A. `requires_request_body_buffering()` is already true (this
        // plugin overrides `requires_request_body_before_before_proxy`), so the
        // proxy passes the mutable context to the final-body hook.
        true
    }

    fn warmup_hostnames(&self) -> Vec<String> {
        self.limiter.warmup_hostname().into_iter().collect()
    }

    fn tracked_keys_count(&self) -> Option<usize> {
        Some(self.limiter.tracked_keys_count())
    }

    fn requires_response_body_buffering(&self) -> bool {
        // Config-time upper bound only. The per-request and per-content-type
        // refinements below are what actually decide, and they never pin a
        // streaming response.
        true
    }

    /// Buffer only a response THIS instance could still have to meter from a
    /// complete body.
    ///
    /// Previously this returned `true` unconditionally, which pinned EVERY
    /// response on the proxy — including long-lived SSE model streams — onto the
    /// buffered path. Incremental delivery was destroyed and each concurrent
    /// stream accumulated bytes up to the global response cap, so a handful of
    /// slow or never-ending streams exhausted gateway memory and task lifetime
    /// (GHSA-q2r2-6r7h-f69x). Token extraction could not even begin until the
    /// stream ended, so the fail-closed unmetered posture could not mitigate the
    /// in-progress resource use either.
    ///
    /// A request this instance never classified as an AI call and never reserved
    /// against has nothing to reconcile, so its body is irrelevant here. The
    /// deferred-compressed case is included because classification has not
    /// happened yet at this point.
    fn should_buffer_response_body(&self, ctx: &RequestContext) -> bool {
        ctx.metadata.contains_key(&self.meter_flag_key)
    }

    /// Release the response to the streaming path once the backend headers name
    /// a representation this instance either meters incrementally or cannot
    /// meter at all.
    ///
    /// This is the earliest boundary at which the response representation is
    /// known, and it is the one that ends unconditional buffering:
    ///
    /// * `text/event-stream` and `application/vnd.amazon.eventstream` are
    ///   metered incrementally by [`AiRateLimitStreamInspector`], so buffering
    ///   them buys nothing and costs everything.
    /// * A non-2xx response only ever releases the reservation, which needs no
    ///   body.
    /// * Framed gRPC-Web bodies are never a JSON usage document.
    /// * Anything else keeps the buffered JSON extraction path.
    ///
    /// Per the hook contract this only ever NARROWS
    /// [`Self::should_buffer_response_body`].
    fn should_buffer_response_body_for_content_type(
        &self,
        ctx: &RequestContext,
        content_type: Option<&str>,
        response_status: u16,
        _response_headers: &HashMap<String, String>,
    ) -> bool {
        if !self.should_buffer_response_body(ctx) {
            return false;
        }
        if !(200..300).contains(&response_status) {
            return false;
        }
        let Some(content_type) = content_type else {
            return true;
        };
        if is_framed_grpc_content_type(content_type) {
            return false;
        }
        StreamUsageFormat::for_content_type(content_type).is_none()
    }

    fn requires_response_stream_hooks(&self) -> bool {
        true
    }

    /// Attach a bounded, incremental usage scanner to a streaming response.
    ///
    /// The inspector forwards every chunk downstream byte-for-byte and retains
    /// only a fixed reassembly window plus the latest usage snapshot, so a
    /// never-ending stream costs O(1) state instead of O(bytes). Returning
    /// `None` leaves the stream completely untouched.
    fn response_stream_inspector(
        &self,
        ctx: &RequestContext,
        response_status: u16,
        content_type: Option<&str>,
    ) -> Option<Box<dyn ResponseStreamInspector>> {
        if !(200..300).contains(&response_status) {
            return None;
        }
        let record = self.load_reservation(ctx);
        if !record.ai_request && record.reserved_tokens == 0 {
            return None;
        }
        // Federation traffic is reconciled exclusively by `after_proxy`.
        if ctx.metadata.contains_key("ai_federation_provider") {
            return None;
        }
        let format = StreamUsageFormat::for_content_type(content_type?)?;
        let fixed_provider = if self.provider == "auto" {
            None
        } else {
            parse_ai_provider(&self.provider)
        };
        Some(Box::new(AiRateLimitStreamInspector {
            slot: Arc::new(StreamUsageSlot::new(StreamUsageScanner::new(
                format,
                fixed_provider,
            ))),
            handoff: ctx.response_stream_handoff(),
            handoff_id: self.stream_handoff_id,
            published: false,
        }))
    }

    /// Settle this instance's reservation for a streamed response.
    ///
    /// Reconciliation happens ONLY on an explicit authoritative usage signal
    /// from the provider. Every other terminal state — no usage event, damaged
    /// or oversized framing, a client disconnect, or a body that never completed
    /// — applies the configured unmetered posture exactly once instead.
    async fn on_response_stream_terminated(
        &self,
        ctx: &mut RequestContext,
        response_status: u16,
        outcome: &crate::proxy::deferred_log::BodyOutcome,
    ) {
        // Federation traffic is settled exclusively by `after_proxy`.
        if ctx.metadata.contains_key("ai_federation_provider") {
            return;
        }
        // Nothing this instance reserved or classified — nothing to settle. This
        // is the common case for unrelated streamed traffic on a shared proxy.
        if !self.load_reservation(ctx).needs_response_body() {
            return;
        }

        // The scan result is absent whenever no inspector was attached: a non-2xx
        // response, or a 2xx whose representation carries no usage this limiter
        // can decode. Those streams must still SETTLE — a non-2xx releases the
        // reservation and a 2xx applies the unmetered posture — otherwise
        // releasing the buffered path to streaming would silently leave every
        // such reservation charged until the window expired.
        let result = ctx
            .response_stream_handoff()
            .and_then(|handoff| handoff.take::<StreamUsageSlot>(self.stream_handoff_id))
            .map(|slot| slot.snapshot());

        // A stream that did not complete cleanly cannot present its absent usage
        // as "the provider reported nothing": the tail that would have carried
        // the terminal usage record may simply never have arrived. Treat it as
        // unmetered so the configured posture decides, rather than silently
        // charging nothing.
        let complete = outcome.body_completed && !outcome.client_disconnected;
        let (tokens, detail) = match result {
            None => (None, "stream_not_meterable"),
            Some(_) if !complete => (None, "stream_incomplete"),
            Some(result) if result.malformed => (None, "stream_malformed_frames"),
            Some(result) => match result
                .usage
                .as_ref()
                .and_then(|usage| usage.total_for_mode(&self.count_mode))
            {
                Some(tokens) => (Some(tokens), "stream_usage"),
                None => (None, "stream_without_usage"),
            },
        };

        let settlement = self
            .reconcile_usage(ctx, response_status, tokens, detail)
            .await;
        if !matches!(settlement, PluginResult::Continue) {
            // Response headers and bytes are already on the wire, so a streamed
            // response can no longer be replaced with a 502/503. The fail-closed
            // outcome for a stream is therefore to KEEP the reservation charged
            // (never to release it), which `reconcile_usage` has already done by
            // marking this instance settled without applying a release.
            warn!(
                provider = %self.provider,
                count_mode = %self.count_mode,
                detail = %detail,
                plugin = "ai_rate_limiter",
                "ai_rate_limiter: streamed response could not be settled authoritatively; keeping the reservation charged because the response is already committed"
            );
        }
    }

    fn applies_after_proxy_on_reject(&self) -> bool {
        true
    }

    async fn before_proxy(
        &self,
        ctx: &mut RequestContext,
        headers: &mut HashMap<String, String>,
    ) -> PluginResult {
        let key = self.rate_key(ctx);
        // Classify the request against the `on_unmetered_response` policy. The
        // hard input is a *compressed* body, which is not JSON-parseable here.
        // There are three cases, distinguished by how the optional co-located
        // `compression` plugin (priority 4050, runs before this plugin at 4200)
        // handled the body:
        //
        //   Case A — `compression` with `decompress_request: true` already
        //     decoded the body: it strips `content-encoding`, records the
        //     `compression:request_encoding` metadata key, and decodes the body in
        //     its later `transform_request_body`. The decoded bytes are NOT written
        //     back into `ctx.metadata["request_body"]`, so we cannot classify here
        //     — but `on_final_request_body` receives the decompressed body, so
        //     classification is DEFERRED to there. We detect this from the
        //     compression-owned METADATA key (not the `x-ferrum-original-content-`
        //     `encoding` header, which a client can forge when `compression` is
        //     absent or ordered after this plugin — that would let a forged header
        //     skip pre-reservation). Without deferral the bare `content-encoding`
        //     check below misses the request (the header is gone) and a usage-less
        //     compressed AI 2xx would bypass the policy in the common setup.
        //   Case B — the body stays compressed end to end (no co-located
        //     decompression, or an encoding `compression` does not support):
        //     `content-encoding` is still present and the body is never
        //     inspectable, so fail closed — mark a POST JSON body as an AI
        //     candidate so the unmetered policy still applies, leaving
        //     GET/empty/non-JSON traffic exempt.
        //   Case C — uncompressed: estimate normally over the buffered body.
        //
        // Read headers from the `headers` parameter, not `ctx.headers`: when no
        // plugin advertises `modifies_request_headers()` the handler `mem::take`s
        // headers out of `ctx.headers` for this phase. See limitation #4 below
        // and docs/plugins.md. Mirrors `ai_request_guard` (#1919), which defers
        // compressed-body inspection the same way. We do NOT decompress here.
        // Framed gRPC / gRPC-Web bodies carry length-prefixed wire frames, not a
        // bare JSON document, even when their media type ends in `+json`; exclude
        // them so a normal gRPC 2xx without LLM usage is never marked an AI
        // candidate and turned into a 502.
        let is_post_json = ctx.method == "POST"
            && headers.get("content-type").is_some_and(|content_type| {
                is_json_content_type(content_type) && !is_framed_grpc_content_type(content_type)
            });
        // A framed request is never an AI candidate on any branch below, even if
        // a co-located plugin left a JSON-parseable `request_body` in metadata:
        // the wire body is a length-prefixed frame sequence, so estimating over
        // it would attribute another representation's tokens to this request.
        // Native gRPC never reaches here (HTTP-only protocol view); this covers
        // gRPC-Web, which rides the HTTP view.
        let is_framed_grpc = headers
            .get("content-type")
            .is_some_and(|content_type| is_framed_grpc_content_type(content_type));
        let still_compressed = has_non_identity_content_encoding(headers);
        // Detect the decompressed-by-`compression` (Case A) path from the
        // compression-owned metadata, NOT a client-settable header. See
        // `COMPRESSION_REQUEST_ENCODING_METADATA_KEY`.
        let decompressed_by_compression = !still_compressed
            && ctx
                .metadata
                .contains_key(COMPRESSION_REQUEST_ENCODING_METADATA_KEY);
        let defer_compressed_classification = decompressed_by_compression && is_post_json;
        let (is_ai_request, reserved_tokens) = if is_framed_grpc {
            // Framed gRPC-Web: out of scope for this JSON policy entirely.
            (false, 0)
        } else if still_compressed {
            // Case B: uninspectable compressed body — fail closed for POST JSON.
            (is_post_json, 0)
        } else if defer_compressed_classification {
            // Case A: defer to `on_final_request_body` (decompressed body there).
            (false, 0)
        } else {
            // Case C: uncompressed — estimate over the buffered inbound body.
            self.estimate_request_tokens(ctx)
        };
        // Pre-reservation vs. fall-back-to-check behavior, and two
        // intentional limitations operators must understand:
        //
        // 1. Estimate of 0 => no pre-reservation. With `count_mode:
        //    "completion_tokens"` the estimate comes solely from
        //    `requested_completion_tokens` (max_tokens / max_completion_tokens
        //    / max_output_tokens). A client that omits all of those makes the
        //    estimate 0, so this falls back to the legacy `CheckBudget` path
        //    (no pre-reservation) and the request is only charged after the
        //    fact via reconciliation. A caller can therefore dodge
        //    pre-reservation in that mode by omitting the max_* fields. This is
        //    documented under `count_mode` / `on_unmetered_response` in
        //    docs/plugins.md; tightening it (a minimum-reservation floor) is a
        //    follow-up.
        //
        // 2. Reservations are self-healing only via window/TTL expiry.
        //    Reconciliation (`reconcile_usage` in `after_proxy` /
        //    `on_response_body`) is best-effort: several paths reserve here but
        //    never reconcile — fail-closed early returns (e.g. BAD_GATEWAY),
        //    client disconnect before the buffered response, or another plugin
        //    rejecting in `after_proxy` so `on_response_body` never runs. In
        //    those cases the estimate stays charged until the sliding window /
        //    Redis TTL drops it, so a burst of aborted requests can transiently
        //    over-count usage. The window/TTL is the deliberate backstop;
        //    eagerly releasing on every early-abort branch would require
        //    touching broad proxy code and is intentionally out of scope here.
        //
        // 3. The estimate reads the *pre-transform* request body
        //    (`ctx.metadata["request_body"]`, the buffered inbound body). Body
        //    rules in `request_transformer` run later in the pipeline
        //    (`transform_request_body`, at dispatch time — after this
        //    `before_proxy` phase), and the transformed body is a dispatch-local
        //    value that is never written back into `ctx.metadata`. So a proxy
        //    that adds/raises `max_tokens` or appends prompt content in a body
        //    transform reserves against the smaller inbound body; concurrent
        //    transformed requests can briefly oversubscribe the budget until
        //    post-response reconciliation charges actual usage. Reserving
        //    against the final body is not feasible here without running the
        //    transform pipeline twice; reconciliation is the corrective. This is
        //    documented under `count_mode` / `request_transformer` interaction
        //    in docs/plugins.md.
        //
        // 4. Compressed request bodies are never pre-reserved: `reserved_tokens`
        //    is forced to 0 above (an estimate over the still-compressed bytes
        //    would be wrong/tiny), so they fall through to the `CheckBudget` path
        //    (which still enforces an already-exhausted budget) and post-response
        //    reconciliation charges the actual provider-reported usage. They are
        //    NOT exempt from `on_unmetered_response`, however: a body a co-located
        //    `compression` plugin decompressed is classified in
        //    `on_final_request_body` against the decoded bytes (Case A above), and
        //    an uninspectable still-compressed POST JSON body is marked a
        //    fail-closed AI candidate (Case B), so a usage-less compressed AI 2xx
        //    cannot bypass `reject`/`charge_estimate` enforcement. This matches
        //    how `ai_request_guard` treats compressed bodies (#1919) and is
        //    documented under `count_mode` / `on_unmetered_response` in
        //    docs/plugins.md.
        // Advance sampled idle reclamation before admission so an exactly-full
        // map of expired keys cannot remain pinned closed when only new
        // identities arrive. Cleanup never removes live budgets.
        self.evict_stale_entries();
        let Some(outcome) = (if reserved_tokens > 0 {
            self.reserve_usage(key.clone(), reserved_tokens).await
        } else {
            self.limiter
                .check_with_redis_key_and_local_capacity(
                    key.clone(),
                    || key.clone(),
                    &AiRateLimitOp::CheckBudget,
                    MAX_STATE_ENTRIES,
                )
                .await
        }) else {
            return self.reject_capacity();
        };

        if !outcome.allowed {
            if outcome.enforcement_unavailable {
                // The shared failover backend emits one bounded operational
                // warning per outage. Do not turn an unavailable dependency
                // into one warning and one "exceeded" metric per request.
                return self.reject_enforcement_unavailable();
            }
            super::prometheus_metrics::global_registry().record_rate_limit_exceeded();
            let usage = outcome.usage.unwrap_or(0);
            // The rate-limit key embeds the identity dimension (consumer,
            // authenticated identity, SPIFFE ID, or client IP) and is never
            // logged; the bounded counters below stay.
            warn!(
                current_tokens = usage,
                limit = self.token_limit,
                plugin = "ai_rate_limiter",
                "AI token rate limit exceeded"
            );
            return self.reject(usage);
        }

        // Everything below lands in THIS instance's own reservation record, so a
        // sibling limiter's admission pass can never overwrite it
        // (GHSA-wh4p-pmxm-3784).
        let mut record = self.load_reservation(ctx);

        // Record this request's `on_unmetered_response` classification:
        //   - Case A (decompressed-by-compression): DEFER. This instance's
        //     `on_final_request_body` pass inspects the decompressed body and
        //     classifies there, so a non-AI JSON body is never falsely subjected
        //     to the policy. The deferral lives in this instance's record, so
        //     co-located instances each defer and classify independently rather
        //     than the first one to run consuming a shared marker for all.
        //   - Case B (uninspectable compressed POST JSON): `is_ai_request` is the
        //     fail-closed candidate; also tag it compressed so the default
        //     `charge_estimate` path rejects a usage-less 2xx (no safe estimate).
        //   - Case C / estimated AI: mark from the parsed body.
        if defer_compressed_classification {
            record.deferred_compressed_classification = true;
        } else if is_ai_request {
            record.ai_request = true;
            record.compressed_ai_candidate = still_compressed;
            // The proxy-visible marker stays shared: it is a fact about the
            // REQUEST, and `run_after_proxy_hooks` and the transaction log read
            // it as a presence flag only. No accounting decision reads it.
            ctx.metadata
                .insert(AI_REQUEST_METADATA_KEY.to_string(), "true".to_string());
        }

        if reserved_tokens > 0 {
            record.reserved_tokens = reserved_tokens;
            // Carry the local-window reservation id so reconciliation releases
            // the exact entry this request created (correct under concurrent,
            // out-of-order completions). `None` in Redis mode — harmless, the
            // Redis reconciliation path ignores it.
            record.reservation_id = outcome.reservation_id;
            // Carry the Redis window this reservation credited so reconciliation
            // debits the SAME window even across a rollover (centralized mode).
            // `None` in local mode — the in-memory window pins the correction via
            // the matched entry's timestamp instead.
            record.reserved_window_index = outcome.reserved_window_index;
            // Presence-only signal for `run_after_proxy_hooks`, which uses it to
            // decide whether recording the genuine backend status is worthwhile.
            // The VALUE is telemetry: every accounting read goes through the
            // per-instance record, so a sibling overwriting this cannot corrupt
            // a budget.
            ctx.metadata.insert(
                RESERVED_TOKENS_METADATA_KEY.to_string(),
                reserved_tokens.to_string(),
            );
        }
        self.store_metadata(ctx, &outcome, &mut record);
        self.store_reservation(ctx, &record);
        PluginResult::Continue
    }

    async fn on_final_request_body_with_context(
        &self,
        ctx: &mut RequestContext,
        headers: &HashMap<String, String>,
        body: &[u8],
    ) -> PluginResult {
        // Only act on a request THIS instance deferred in `before_proxy` (Case A:
        // a compressed POST JSON body a co-located `compression` plugin
        // decompressed). The deferral lives in this instance's own record, so
        // every co-located `ai_rate_limiter` classifies the decompressed body
        // for itself instead of the first one to run consuming a shared marker
        // on behalf of all of them. The common uncompressed path never defers,
        // so it skips this hook.
        let mut record = self.load_reservation(ctx);
        if !record.deferred_compressed_classification {
            return PluginResult::Continue;
        }
        record.deferred_compressed_classification = false;

        // Defensive re-check against the final headers: a deferred body should be
        // JSON and decompressed by now. If `content-encoding` is somehow still
        // present (no `transform_request_body` decoded it) or the content-type was
        // relabeled to non-JSON, the body cannot be inspected — fail closed so a
        // usage-less compressed AI 2xx still cannot bypass the unmetered policy.
        // A relabel to a framed gRPC / gRPC-Web media type counts as
        // uninspectable too: the `+json` suffix satisfies `is_json_content_type`
        // but the payload is a length-prefixed wire frame, so parsing it as a
        // bare JSON document would silently exempt a deferred AI candidate.
        // Genuine gRPC-Web traffic never reaches here — `before_proxy` refuses
        // to defer a framed content-type in the first place.
        let content_type = headers
            .get("content-type")
            .map(String::as_str)
            .unwrap_or("");
        if has_non_identity_content_encoding(headers)
            || !is_json_content_type(content_type)
            || is_framed_grpc_content_type(content_type)
        {
            record.ai_request = true;
            record.compressed_ai_candidate = true;
            ctx.metadata
                .insert(AI_REQUEST_METADATA_KEY.to_string(), "true".to_string());
            self.store_reservation(ctx, &record);
            return PluginResult::Continue;
        }

        // The decompressed body is available now. Mark the request as an AI call
        // ONLY when it actually parses as one, so a non-AI JSON body on a shared
        // proxy is never subjected to the `on_unmetered_response` policy (the
        // false-positive the bare `before_proxy` header check would cause). Tag it
        // compressed so the default `charge_estimate` path rejects a usage-less
        // 2xx — there is no safe pre-request estimate for a compressed body.
        if serde_json::from_slice::<Value>(body)
            .ok()
            .as_ref()
            .is_some_and(json_looks_like_ai_request)
        {
            record.ai_request = true;
            record.compressed_ai_candidate = true;
            ctx.metadata
                .insert(AI_REQUEST_METADATA_KEY.to_string(), "true".to_string());
        }

        self.store_reservation(ctx, &record);
        PluginResult::Continue
    }

    async fn after_proxy(
        &self,
        ctx: &mut RequestContext,
        response_status: u16,
        response_headers: &mut HashMap<String, String>,
    ) -> PluginResult {
        // Record the backend status on the genuine after_proxy run (not the
        // re-run inside a rejection, which carries the rejection status). This
        // lets `should_release_gateway_rejection` distinguish a 2xx backend whose
        // body a later plugin rejected (keep the reservation — tokens were
        // consumed) from a real gateway rejection (release). The federation path
        // delivers the provider response via `RejectBinary`, so its after_proxy
        // always runs in rejection context and never records here — federation
        // reconciliation is handled by the `ai_federation_provider` branch below.
        //
        // Gated on the presence of a token reservation
        // (`RESERVED_TOKENS_METADATA_KEY`), mirroring the proxy-side write in
        // `run_after_proxy_hooks`: without a reservation the keep/release decision
        // is moot (`should_release_gateway_rejection` requires `reserved > 0`), so
        // recording the status only adds dead metadata — and a transaction-log
        // field — to every request on the proxy, including non-AI ones.
        let in_rejection_context = ctx
            .metadata
            .get(REJECTION_RESPONSE_METADATA_KEY)
            .is_some_and(|value| value == "true");
        if !in_rejection_context && ctx.metadata.contains_key(RESERVED_TOKENS_METADATA_KEY) {
            ctx.metadata.insert(
                BACKEND_STATUS_METADATA_KEY.to_string(),
                response_status.to_string(),
            );
        }

        // `after_proxy` is the SOLE federation-token charger. It runs exactly once
        // per request on whichever path applies — first on the normal path, and
        // LAST on the synthetic short-circuit reject path
        // (`apply_reject_after_proxy_and_synthetic_body_hooks` runs the body hooks
        // first and this hook once afterwards). `on_response_body` deliberately
        // skips ALL federation traffic (it returns early when
        // `ai_federation_provider` is present), so there is no second federation
        // charger to coordinate with.
        //
        // The only remaining double-charge risk is `after_proxy` itself running
        // twice for ONE request (e.g. a synthetic 2xx short-circuit followed by a
        // response-body rejection that re-runs the reject hooks). The per-instance
        // `federation_flag_key` guards against that: the first run reconciles and
        // sets it, any later run skips. The flag is per limiter instance so
        // multiple `ai_rate_limiter` budgets on one proxy each reconcile their own
        // window once. The federation reconcile itself goes through
        // `reconcile_usage`, which charges the actual provider tokens (or releases
        // the reservation on a non-2xx federation response).
        if ctx.metadata.contains_key("ai_federation_provider") {
            if !ctx.metadata.contains_key(&self.federation_flag_key) {
                let actual_tokens = self.read_tokens_from_metadata(&ctx.metadata);
                // Reconcile against the federation provider's ORIGINAL synthetic
                // status, not the current after_proxy status. `ai_federation`
                // delivers its provider response as a `before_proxy` RejectBinary,
                // and on the synthetic short-circuit path a response-body guardrail
                // (`ai_response_guard` / `ai_semantic_firewall`) can replace that
                // 2xx with a 5xx before this hook runs. Reconciling a usage-less
                // response against the 5xx would take the non-2xx branch and
                // RELEASE the reservation for a provider call that already consumed
                // tokens — making a paid call free. `ai_federation` records its
                // status in `ai_federation_status`; absent it (older path / no
                // federation status), fall back to the observed `response_status`.
                // When `actual_tokens` is `Some`, reconciliation charges the actual
                // usage regardless of status, so this only changes the usage-less
                // case (routes it through `on_unmetered_response` instead).
                let federation_status = ctx
                    .metadata
                    .get("ai_federation_status")
                    .and_then(|value| value.parse::<u16>().ok())
                    .unwrap_or(response_status);
                let result = self
                    .reconcile_usage(
                        ctx,
                        federation_status,
                        actual_tokens,
                        "ai_federation_metadata",
                    )
                    .await;
                if !matches!(result, PluginResult::Continue) {
                    return result;
                }
                ctx.metadata
                    .insert(self.federation_flag_key.clone(), "true".to_string());
            }
        } else if Self::should_release_gateway_rejection(ctx, &self.load_reservation(ctx)) {
            let result = self
                .reconcile_usage(ctx, 500, None, "gateway_rejection")
                .await;
            if !matches!(result, PluginResult::Continue) {
                return result;
            }
        }

        if !self.expose_headers {
            return PluginResult::Continue;
        }

        self.apply_exposed_headers(&self.load_reservation(ctx), response_headers);

        PluginResult::Continue
    }

    /// These telemetry writes are unconditional `insert`s of a gateway-computed
    /// value, so a backend that pre-populates the identical bytes makes them
    /// invisible to net-diff mutation tracking. Without this declaration, a
    /// later body/committed hook that exhausts the gRPC deadline would rebuild
    /// the DEADLINE_EXCEEDED response with the operator's rate-limit telemetry
    /// silently dropped. Sourced from the same [`EXPOSED_RATELIMIT_HEADERS`]
    /// table `after_proxy` writes from, so the two cannot drift apart, and
    /// gated on the same `expose_headers` + metadata-presence conditions so
    /// nothing is claimed that was not actually written.
    fn owns_deadline_response_header(&self, ctx: &RequestContext, name: &str) -> bool {
        if !self.expose_headers {
            return false;
        }
        for (meta_key, header_name) in EXPOSED_RATELIMIT_HEADERS {
            if name.eq_ignore_ascii_case(header_name) && ctx.metadata.contains_key(*meta_key) {
                return true;
            }
        }
        false
    }

    /// Config-time form of the same ownership. Mirrors `rate_limiting`: the
    /// exposed token budget is gateway accounting, an identical backend echo is
    /// invisible to observed-mutation reconciliation, and `expose_headers: false`
    /// writes nothing and therefore governs no trailers.
    fn response_trailer_policy(&self) -> super::ResponseTrailerPolicy<'_> {
        if self.expose_headers {
            super::ResponseTrailerPolicy::Names(&EXPOSED_RATELIMIT_POLICY_NAMES)
        } else {
            super::ResponseTrailerPolicy::None
        }
    }

    async fn on_response_body(
        &self,
        ctx: &mut RequestContext,
        response_status: u16,
        response_headers: &mut HashMap<String, String>,
        body: &[u8],
    ) -> PluginResult {
        // Federation tokens are reconciled EXCLUSIVELY by `after_proxy`, never
        // here. `after_proxy` is the single authoritative federation charger: it
        // runs exactly once per request — first on the normal response path, and
        // LAST on the synthetic short-circuit reject path
        // (`apply_reject_after_proxy_and_synthetic_body_hooks` runs the body
        // hooks, i.e. this `on_response_body`, FIRST and the reject `after_proxy`
        // hook once afterwards). If `on_response_body` also reconciled the same
        // `ai_federation` tokens the consumer would be double-charged for one
        // synthetic response (and a *blocked* response could be pushed over the
        // limit). The federation marker is present BEFORE its `after_proxy`
        // idempotency flag is set (the flag is written after `after_proxy` runs,
        // which is after this hook on the synthetic path), so gating on the marker
        // — not the flag — is the correct, race-free guard. `after_proxy` carries
        // its own per-instance idempotency guard (`federation_flag_key`) for the
        // case where it runs twice for one request, so the only thing this hook
        // must do for federation traffic is stay out of the way (no charge AND no
        // release; the federation reconcile, including any non-2xx release, is
        // owned by `after_proxy`).
        if ctx.metadata.contains_key("ai_federation_provider") {
            return PluginResult::Continue;
        }

        // Do not reconcile (charge OR release) for ANY synthetic short-circuit
        // body. A synthetic body is a plugin-generated 2xx that never reached the
        // upstream model (cache hit, dedup replay, `response_mock`,
        // `serverless_function`, `request_termination`, federation, …). All of
        // them flow through `on_response_body` via the `RejectBinary`
        // short-circuit, and the proxy sets `ferrum:synthetic_short_circuit` in
        // `ctx.metadata` for the duration of that body-hook phase (see
        // `apply_synthetic_response_body_hooks`). Without this guard a synthetic
        // body that happens to carry an OpenAI-shaped `usage` block — e.g. a
        // `response_mock` returning a canned chat-completion — would be charged
        // against the window even though no provider tokens were consumed,
        // silently shrinking the user's budget; equally, a synthetic body must not
        // trigger a spurious reservation RELEASE here (the genuine request's
        // reservation lifecycle is owned by its own real-response reconcile /
        // `after_proxy`). The synthetic marker is the correct exemption signal
        // precisely BECAUSE it is internal and unspoofable: it is set only on the
        // synthetic path and never on a real backend response, so a backend (or a
        // `response_transformer` rewrite) emitting a `usage` block, an
        // `x-idempotent-replayed`, or any cache header on a genuine model response
        // cannot satisfy it. A FRESH backend response carries no synthetic marker
        // and is reconciled normally below.
        if ctx
            .metadata
            .contains_key(crate::proxy::SYNTHETIC_SHORT_CIRCUIT_METADATA_KEY)
        {
            debug!(
                "ai_rate_limiter: skipping synthetic short-circuit response (no model tokens consumed)"
            );
            return PluginResult::Continue;
        }

        if !(200..300).contains(&response_status) {
            debug!(
                "ai_rate_limiter: skipping non-2xx response (status {})",
                response_status
            );
            let result = self
                .reconcile_usage(ctx, response_status, None, "non_2xx_response")
                .await;
            // `after_proxy` already copied admission-time usage/remaining; refresh
            // the client-visible map now that the reservation was released.
            if matches!(result, PluginResult::Continue) {
                self.apply_exposed_headers(&self.load_reservation(ctx), response_headers);
            }
            return result;
        }

        let content_type = response_headers
            .get("content-type")
            .map(String::as_str)
            .unwrap_or("");

        let metadata_tokens = self.read_tokens_from_metadata(&ctx.metadata);
        let mut unmetered_detail = "metadata_without_usage";
        let tokens = metadata_tokens.or_else(|| {
            if body.is_empty() {
                unmetered_detail = "empty_body";
                return None;
            }

            // Framed gRPC-Web responses (`application/grpc-web*`, including the
            // `+json` variants) are length-prefixed wire frames, not a bare
            // JSON usage document. Screen them out before the JSON branch so a
            // framed body is never parsed as JSON — and, when the request was
            // an identified AI call, so the response is routed through the
            // explicit `on_unmetered_response` policy instead of silently
            // reconciling as if the provider had reported zero usage. Native
            // gRPC cannot reach this hook at all (HTTP-only protocol view).
            if is_framed_grpc_content_type(content_type) {
                unmetered_detail = "framed_grpc_content_type";
                return None;
            }

            // A buffered SSE or AWS event-stream body (a co-located plugin can
            // still pin one onto the buffered path) goes through the SAME
            // bounded scanner the streaming inspector uses, so both paths report
            // identical counts and both cover every documented provider-native
            // format — Gemini `usageMetadata`, Bedrock event-stream usage, and
            // native TGI terminal `details` included (GHSA-rxj9-f483-g53f).
            if let Some(format) = StreamUsageFormat::for_content_type(content_type) {
                unmetered_detail = if format == StreamUsageFormat::Sse {
                    "sse_without_usage"
                } else {
                    "event_stream_without_usage"
                };
                return self.extract_token_count_from_stream(format, body);
            }

            if !is_json_content_type(content_type) {
                unmetered_detail = "unsupported_content_type";
                return None;
            }

            unmetered_detail = "json_without_usage";
            self.extract_token_count(body)
        });

        let result = self
            .reconcile_usage(ctx, response_status, tokens, unmetered_detail)
            .await;
        // Production ordering is `after_proxy` (admission headers) →
        // `on_response_body` (reconcile). Re-apply so the final client-visible
        // `x-ai-ratelimit-usage` / `remaining` match the reconciled bucket, not
        // the reservation estimate. Limit/window stay coherent from metadata.
        // Reject paths rebuild the response from `PluginResult::Reject` headers
        // (e.g. unmetered `reject` → empty map), so skip the refresh there.
        if matches!(result, PluginResult::Continue) {
            self.apply_exposed_headers(&self.load_reservation(ctx), response_headers);
        }
        result
    }
}
