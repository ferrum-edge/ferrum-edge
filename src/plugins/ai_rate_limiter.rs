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

use crate::plugins::utils::log_sampling::warn_sampled;

use async_trait::async_trait;
use serde_json::Value;
use std::collections::HashMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::time::Instant;
use tracing::{debug, warn};

use super::utils::ai_providers::{
    AiProvider, detect_response_provider, extract_response_usage, parse_ai_provider,
};
use super::utils::ai_usage_stream::{
    UsageAccumulator, UsageStreamExtractor, UsageStreamFormat, is_aws_event_stream_content_type,
};
use super::utils::body_transform::{is_event_stream_content_type, is_json_content_type};
use super::utils::content_encoding::{DecodeLimits, parse_content_codings};
use super::utils::rate_limit::{
    AiRateLimitOp, AiTokenRateAlgorithm, ENFORCEMENT_UNAVAILABLE_BODY,
    ENFORCEMENT_UNAVAILABLE_STATUS, LocalStateSemantics, RATE_LIMIT_REDIS_CONFIG_KEYS,
    RateLimitBackend, RateLimitOutcome, ReservationBackend, STANDALONE_RATE_LIMIT_CONFIG_ID,
    apply_rate_limit_cleanup, debug_assert_closed_root_keys, debug_assert_rate_limit_redis_keys,
    validate_window_seconds,
};
use super::{
    Plugin, PluginHttpClient, PluginResult, RequestContext, ResponseStreamAction,
    ResponseStreamInspector, allocate_response_stream_handoff_id,
};
/// Shared key for the original (pre-rejection) backend HTTP status. Recorded by
/// the proxy's `run_after_proxy_hooks` *before* the after_proxy loop, and again
/// by this plugin's own genuine `after_proxy` pass — both write the same value.
/// Reusing the `crate::proxy` constants (instead of local copies) keeps the
/// proxy-side and plugin-side writers/readers from drifting apart. See
/// `should_release_gateway_rejection` (`BACKEND_STATUS_METADATA_KEY`) and the
/// shared presence marker `RESERVED_TOKENS_METADATA_KEY` that gates it.
use crate::proxy::{BACKEND_STATUS_METADATA_KEY, RESERVED_TOKENS_METADATA_KEY};
use crate::util::unknown_keys::reject_unknown_keys;

const MAX_STATE_ENTRIES: usize = 100_000;
const EVICTION_CHECK_INTERVAL_REQUESTS: u64 = 1024;
/// Bounds below-cap full-map scans under high RPS. Sampled over-cap
/// reclaim skips this cooldown so a sampled observation of pressure can
/// drop idle keys without waiting for the next cool-down window. Live
/// budgets are never force-evicted.
const EVICTION_COOLDOWN_SECS: u64 = 1;
const CAPACITY_REJECT_BODY: &str = r#"{"error":"AI token rate limit exceeded","details":"Rate-limit state capacity exceeded (max 100000 keys)"}"#;
const REJECTION_RESPONSE_METADATA_KEY: &str = "ferrum:rejection_response";

/// Base names of every per-request reservation-lifecycle metadata entry this
/// plugin owns. Each is turned into an INSTANCE-SCOPED `ctx.metadata` key by
/// [`InstanceKeys::new`] (`"<base>#<instance id>"`).
///
/// Scoping is load-bearing, not cosmetic (GHSA-wh4p-pmxm-3784). Multiple
/// `ai_rate_limiter` instances on one proxy are a documented, supported
/// composition — a per-consumer budget plus a per-IP budget is the canonical
/// defense-in-depth setup. Every instance runs its OWN admission pass and its
/// OWN reconciliation, with its own estimate, its own `count_mode`, its own
/// identity dimension, and possibly its own backend (one local, one Redis). If
/// those instances share unscoped metadata, the second admission overwrites the
/// first instance's reserved size, reservation id, Redis window index, and
/// inferred backend; then each response pass reconciles ITS window against the
/// LAST instance's reservation, and the first release sets a shared flag that
/// suppresses every sibling release. One configured budget is then
/// under-enforced while another is overcharged.
mod meta {
    /// Estimate this instance reserved before dispatch. Absent when the
    /// estimate was 0 (no pre-reservation was taken).
    pub const RESERVED_TOKENS: &str = "ai_ratelimit_reserved_tokens";
    /// Local-window reservation id, so reconciliation releases the exact entry
    /// this instance created under concurrent, out-of-order completions.
    pub const RESERVATION_ID: &str = "ai_ratelimit_reservation_id";
    /// Redis sliding-window index this instance's reservation credited
    /// (centralized mode only). Carried back to the reconciliation op so a
    /// negative correction debits the same window even when the request
    /// straddles a window rollover. Absent in local mode (the in-memory window
    /// pins the correction via the entry's timestamp).
    pub const RESERVED_WINDOW_INDEX: &str = "ai_ratelimit_reserved_window_index";
    /// Actual provider usage this instance charged (diagnostic).
    pub const ACTUAL_TOKENS: &str = "ai_ratelimit_actual_tokens";
    /// `on_unmetered_response` action this instance applied (diagnostic, and
    /// read back by this instance's gateway-rejection release gate).
    pub const UNMETERED_ACTION: &str = "ai_ratelimit_unmetered_action";
    /// Idempotency flag for a federated response's tokens, already reconciled
    /// by `after_proxy` (the sole federation charger — `on_response_body`
    /// always skips federation traffic). Guards the case where `after_proxy`
    /// runs twice for one request (a synthetic 2xx short-circuit followed by a
    /// response-body rejection that re-runs the reject hooks).
    pub const FEDERATION_TOKENS_RECORDED: &str = "ai_ratelimit_federation_tokens_recorded";
    /// Idempotency marker for the reservation lifecycle once this instance has
    /// finished with it. Set after an authoritative actual-token *charge*, after
    /// a reservation *release* (`reconcile_usage` with `actual_tokens == None`),
    /// and after streamed `on_unmetered_response: "reject"` keep-charged
    /// accounting (which cannot rewrite a committed stream). Checked only before
    /// a later *release* so no second release can apply. One request can reach a
    /// release more than once across phases — a non-2xx release in `after_proxy`,
    /// the streamed-response terminal hook, a buffered `on_response_body` pass,
    /// and a later gateway-rejection re-run of `after_proxy` are all reachable
    /// for the same response. In local mode the per-entry `reservation_id`
    /// already makes the second release a no-op (the entry is gone), but the
    /// Redis backend has no per-entry id — it only subtracts `reserved` from the
    /// shared window, so a double-release double-subtracts and under-counts the
    /// consumer's own window, permitting oversubscription.
    ///
    /// The authoritative actual-token *charge* path does NOT *consult* this
    /// marker before charging (that path runs at most once per request, and
    /// `adjust_usage` advances sliding-window bookkeeping, so gating it would
    /// drop a legitimate usage record). It *does* set the marker before the
    /// terminal charge so a subsequent release is a clean no-op on every exit.
    pub const RESERVATION_RELEASED: &str = "ai_ratelimit_reservation_reconciled";
    /// Actual usage was charged to the local window after centralized failure.
    pub const LOCALLY_ACCOUNTED: &str = "ai_ratelimit_locally_accounted";
    /// This instance classified the request as an AI call. Gate for the
    /// `on_unmetered_response` policy AND for response-body/stream inspection:
    /// a non-AI response is never buffered, inspected, charged, or rejected.
    pub const AI_REQUEST: &str = "ai_ratelimit_request";
    /// Marks compressed JSON requests that look like possible AI calls but
    /// could not be estimated before proxying because decompression happens
    /// later.
    pub const COMPRESSED_AI_REQUEST: &str = "ai_ratelimit_compressed_ai_request";
    /// Marks the rare fallback where a co-located `compression` plugin decoded
    /// a POST JSON body without a mutable pre-`before_proxy` buffer. The normal
    /// buffered path refreshes `ctx.metadata["request_body"]` to plaintext and
    /// is classified and pre-reserved immediately; only the fallback defers the
    /// AI-shape check to `on_final_request_body_with_context`.
    pub const DEFERRED_COMPRESSED_CLASSIFICATION: &str =
        "ai_ratelimit_deferred_compressed_classify";
    /// The response this instance is about to release to the streaming path
    /// carries a non-identity `Content-Encoding`. Written by `after_proxy`,
    /// which is the last hook that sees the response header map before the body
    /// commits; read by the stream-inspector factory, which is handed only the
    /// content TYPE. The incremental parsers decode SSE/event-stream framing,
    /// not content codings, so an encoded stream is declined outright and
    /// resolved by `on_unmetered_response` rather than being parsed as if the
    /// compressed octets were frames.
    pub const ENCODED_STREAM: &str = "ai_ratelimit_encoded_stream";
}

/// Largest encoded buffered response this limiter will decode to look for a
/// usage document, and the largest plaintext one decode may materialize.
/// Matched to the sibling `ai_token_metrics` inspection ceiling so the two
/// plugins agree about which representations are readable at all.
const MAX_USAGE_DECODE_BYTES: usize = 4 * 1024 * 1024;
/// Aggregate plaintext one stacked `Content-Encoding` chain may produce.
const MAX_USAGE_DECODE_CUMULATIVE_BYTES: usize = 8 * 1024 * 1024;
/// Largest `#content-coding` list this limiter will undo.
const MAX_USAGE_DECODE_CODINGS: usize = 4;
/// Largest decoded/encoded size ratio, per layer and end to end. A usage
/// document is small and ordinary model JSON compresses well under 20:1, so
/// this bounds the amplification a hostile upstream can buy while leaving real
/// provider responses far inside the limit.
const MAX_USAGE_DECODE_AMPLIFICATION_RATIO: u32 = 500;

/// Process-wide ceiling on concurrently inspected AI response streams.
///
/// Streaming accounting replaced unbounded full-response buffering, so the only
/// state a long-lived stream can now retain is one bounded parser carry plus a
/// four-scalar accumulator. This cap bounds the AGGREGATE of those parsers as
/// well (GHSA-q2r2-6r7h-f69x): beyond it no inspector is attached, the response
/// still streams untouched, and the request is resolved by the configured
/// `on_unmetered_response` policy — fail-closed by default, because
/// `charge_estimate` keeps the pre-request reservation charged.
const MAX_CONCURRENT_STREAM_ACCOUNTING: usize = 4_096;

/// Live [`UsageStreamInspector`] count backing [`MAX_CONCURRENT_STREAM_ACCOUNTING`].
static ACTIVE_STREAM_ACCOUNTING: AtomicUsize = AtomicUsize::new(0);
/// Cumulative refusals at that ceiling, used only to sample the operational
/// warning so saturation cannot become one log line per request.
static STREAM_ACCOUNTING_REFUSALS: AtomicU64 = AtomicU64::new(0);
const STREAM_ACCOUNTING_REFUSAL_LOG_INTERVAL: u64 = 1024;
/// Metadata key the `compression` plugin sets (see `compression.rs::before_proxy`)
/// when it decompresses a request body. It is written into `ctx.metadata`, which
/// clients cannot influence, so — unlike the `x-ferrum-original-content-encoding`
/// header, which is only sanitized when `compression` actually runs — it is a
/// trustworthy signal that the body WAS compressed. On the normal buffered
/// path the shared normalizer also refreshes `ctx.metadata["request_body"]` to
/// plaintext before this plugin runs. Only the rare fallback without that text
/// view must defer classification to the final request-body hook.
const COMPRESSION_REQUEST_ENCODING_METADATA_KEY: &str = "compression:request_encoding";

/// Process-wide monotonic counter used to give every `AiRateLimiter` instance a
/// unique id. The id is folded into every key in [`InstanceKeys`] so the whole
/// per-request reservation lifecycle is scoped to ONE limiter instance, never to
/// a budget-config fingerprint that two intentionally-separate budgets could
/// share. A process-unique counter (rather than the plugin-config id) is the
/// right discriminator precisely because two instances may carry byte-identical
/// configuration and still own separate budgets. Mirrors the
/// `INSTANCE_ID_COUNTER` idiom in `openapi_validator`.
static INSTANCE_ID_COUNTER: AtomicU64 = AtomicU64::new(0);

/// Every `ctx.metadata` key this limiter instance owns, precomputed once at
/// construction so the request hot path never formats a key.
///
/// See the [`meta`] module for what each entry carries and why the scoping is
/// load-bearing.
struct InstanceKeys {
    reserved_tokens: String,
    reservation_id: String,
    reserved_window_index: String,
    actual_tokens: String,
    unmetered_action: String,
    federation_tokens_recorded: String,
    reservation_released: String,
    locally_accounted: String,
    ai_request: String,
    compressed_ai_request: String,
    deferred_compressed_classification: String,
    encoded_stream: String,
    /// `(base name, instance-scoped metadata key, response header name)` for
    /// `expose_headers`. The header NAMES are fixed by the public contract, but
    /// the metadata each instance stages them from is instance-owned, so a
    /// two-instance proxy never publishes instance A's `limit` beside instance
    /// B's `remaining`.
    exposed_headers: Vec<(&'static str, String, &'static str)>,
}

impl InstanceKeys {
    fn new(instance_id: u64) -> Self {
        let scoped = |base: &str| format!("{base}#{instance_id}");
        Self {
            reserved_tokens: scoped(meta::RESERVED_TOKENS),
            reservation_id: scoped(meta::RESERVATION_ID),
            reserved_window_index: scoped(meta::RESERVED_WINDOW_INDEX),
            actual_tokens: scoped(meta::ACTUAL_TOKENS),
            unmetered_action: scoped(meta::UNMETERED_ACTION),
            federation_tokens_recorded: scoped(meta::FEDERATION_TOKENS_RECORDED),
            reservation_released: scoped(meta::RESERVATION_RELEASED),
            locally_accounted: scoped(meta::LOCALLY_ACCOUNTED),
            ai_request: scoped(meta::AI_REQUEST),
            compressed_ai_request: scoped(meta::COMPRESSED_AI_REQUEST),
            deferred_compressed_classification: scoped(meta::DEFERRED_COMPRESSED_CLASSIFICATION),
            encoded_stream: scoped(meta::ENCODED_STREAM),
            exposed_headers: EXPOSED_RATELIMIT_HEADERS
                .iter()
                .map(|(base, header_name)| (*base, scoped(base), *header_name))
                .collect(),
        }
    }
}

/// Terminal usage captured by one response-stream inspector, handed back to
/// [`Plugin::on_response_stream_terminated`] through the request-owned stream
/// handoff. Fixed size: three optional counters plus one flag — never response
/// bytes.
#[derive(Debug, Default)]
struct StreamUsageHandoff {
    usage: std::sync::Mutex<UsageAccumulator>,
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

/// `(metadata base name, response header)` pairs this plugin exposes downstream
/// when `expose_headers` is set. Single source of truth for the per-instance
/// metadata keys ([`InstanceKeys::exposed_headers`]), the `after_proxy` write,
/// and the gRPC-deadline ownership declaration.
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
    /// Configured provider, resolved once. `None` means `auto` (detect per
    /// response document).
    configured_provider: Option<AiProvider>,
    /// Process-unique identity for this constructed instance. Scopes every
    /// reservation-lifecycle metadata key so two `ai_rate_limiter` instances —
    /// even with byte-identical budget config but intentionally separate budgets
    /// (distinct `sync_mode`/`redis_key_prefix`, or simply two local instances)
    /// — never read, overwrite, or suppress each other's reservation state.
    instance_id: u64,
    keys: InstanceKeys,
    /// Process-unique key for this instance's per-response stream-usage handoff.
    /// Allocated once so two instances inspecting the same stream each publish
    /// and take their own terminal usage.
    stream_usage_handoff_key: u64,
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
        let configured_provider = if provider == "auto" {
            None
        } else {
            match parse_ai_provider(&provider) {
                Some(parsed) => Some(parsed),
                None => {
                    return Err(format!(
                        "ai_rate_limiter: unknown 'provider' value '{}' (expected auto, openai, anthropic, google, cohere, mistral, bedrock, or tgi)",
                        provider
                    ));
                }
            }
        };

        let on_unmetered_response = match optional_string(config, "on_unmetered_response")? {
            Some(raw) => OnUnmeteredResponse::parse(raw).ok_or_else(|| {
                format!(
                    "ai_rate_limiter: unknown 'on_unmetered_response' value '{raw}' (expected 'reject', 'charge_estimate', or 'warn')"
                )
            })?,
            None => OnUnmeteredResponse::ChargeEstimate,
        };

        // Scope the ENTIRE per-request reservation lifecycle to THIS limiter
        // instance via a process-unique id, not to a budget-config fingerprint.
        // Two instances routinely enforce on SEPARATE token windows: a different
        // plugin-config policy identity, a semantically changed generation, and an
        // identityless (config-validation / direct) construction each own their own
        // in-memory map, and a distinct `redis_key_prefix` owns its own centralized
        // window. This instance's reserved estimate, reservation id, Redis window
        // index, inferred backend, AI classification, unmetered action, release
        // idempotency, and exposed telemetry must therefore all be per instance
        // too. A config-derived key would be shared by two limiters with identical
        // budget config that are nonetheless SEPARATE budgets (e.g. different
        // `sync_mode`/`redis_key_prefix`, or two distinct plugin-config policies):
        // the first to run would overwrite the second's reservation state and its
        // release would suppress the sibling's, under-counting one window and
        // over-counting the other — contradicting the documented per-instance
        // accounting contract (GHSA-wh4p-pmxm-3784). Per-instance scoping is still
        // required where two COMPATIBLE plugin-cache generations for one policy
        // identity DO share a token window (issue #4268): reservation ids are then
        // drawn from that single shared window so they cannot collide, and a
        // retired generation must reconcile only the reservations it took.
        let instance_id = INSTANCE_ID_COUNTER.fetch_add(1, Ordering::Relaxed);

        // Effective enforcement semantics, not raw syntax: the algorithm
        // parameters after defaulting (`window_seconds` omitted is 60), the
        // parsed limit dimension and count mode, the trimmed/lower-cased
        // provider (omitted is `auto`), and the parsed unmetered-response
        // action (omitted is `charge_estimate`) — all of which decide which
        // tokens are charged. `expose_headers` is response presentation only
        // and never resets a live budget; the shared Redis posture is added by
        // the backend.
        let mut semantics = LocalStateSemantics::new();
        semantics.u64("token_limit", token_limit);
        semantics.u64("window_seconds", window_seconds);
        semantics.text("count_mode", &count_mode);
        semantics.text("limit_by", &limit_by);
        semantics.text("provider", &provider);
        semantics.text("on_unmetered_response", on_unmetered_response.as_str());

        Ok(Self {
            token_limit,
            window_seconds,
            count_mode,
            limit_by,
            expose_headers,
            provider,
            on_unmetered_response,
            configured_provider,
            instance_id,
            keys: InstanceKeys::new(instance_id),
            stream_usage_handoff_key: allocate_response_stream_handoff_id(),
            limiter: RateLimitBackend::from_plugin_config_with_policy_identity(
                "ai_rate_limiter",
                namespace,
                config_id,
                config,
                &http_client,
                AiTokenRateAlgorithm::new(token_limit, window_seconds),
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

    /// This instance's process-unique reservation-scoping id. Not a production
    /// API; external tests use it to assert that two instances never share a
    /// reservation-lifecycle metadata key.
    #[doc(hidden)]
    #[allow(dead_code)] // used only by external tests; dead in binary test target
    pub fn instance_id_for_test(&self) -> u64 {
        self.instance_id
    }

    /// The instance-scoped `ctx.metadata` key for one reservation-lifecycle
    /// base name (see the [`meta`] module). Not a production API.
    #[doc(hidden)]
    #[allow(dead_code)] // used only by external tests; dead in binary test target
    pub fn metadata_key_for_test(&self, base: &str) -> String {
        format!("{base}#{}", self.instance_id)
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

    fn store_metadata(&self, ctx: &mut RequestContext, outcome: &RateLimitOutcome) {
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

        // Instance-scoped staging keys: with two exposing instances on one
        // proxy the header NAMES still collide (they are a fixed public
        // contract, last writer in configured plugin order wins), but each
        // instance's four values stay internally consistent instead of
        // interleaving one instance's limit with another's remaining.
        for (base, meta_key, _) in &self.keys.exposed_headers {
            let value = match *base {
                "ai_ratelimit_limit" => self.token_limit.to_string(),
                "ai_ratelimit_window" => self.window_seconds.to_string(),
                "ai_ratelimit_remaining" => outcome.remaining.unwrap_or(0).to_string(),
                "ai_ratelimit_usage" => outcome.usage.unwrap_or(0).to_string(),
                // Unreachable for the compiled-in table; a new entry that
                // forgets a value here writes nothing rather than a wrong one.
                _ => continue,
            };
            ctx.metadata.insert(meta_key.clone(), value);
        }
    }

    /// Copy exposed rate-limit telemetry from THIS instance's metadata into the
    /// client-visible response map. Used by `after_proxy` (admission and
    /// federation/gateway reconcile) and again by `on_response_body` after
    /// buffered usage reconciliation so the final headers match the bucket.
    fn apply_exposed_headers(
        &self,
        ctx: &RequestContext,
        response_headers: &mut HashMap<String, String>,
    ) {
        if !self.expose_headers {
            return;
        }

        for (_, meta_key, header_name) in &self.keys.exposed_headers {
            if let Some(value) = ctx.metadata.get(meta_key) {
                response_headers.insert((*header_name).to_string(), value.clone());
            }
        }
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

    /// Which backend the original reservation for this request landed on,
    /// inferred from the markers `before_proxy` stored. A local-mode reservation
    /// carries a `reservation_id` (and no Redis window index); a Redis-mode
    /// reservation carries a `reserved_window_index` (and no reservation id).
    /// When neither marker is present the estimate was 0 tokens (nothing was
    /// reserved), so the backend is `Unknown` and the normal reconciliation path
    /// applies (`delta == actual` because `reserved == 0`). This lets the
    /// reconciliation arm detect a backend switch — Redis recovering, or going
    /// down, between reserve and reconcile — and avoid corrupting a backend that
    /// never received the reservation.
    fn reservation_backend(&self, ctx: &RequestContext) -> ReservationBackend {
        if self.reserved_window_index(ctx).is_some() {
            ReservationBackend::Redis
        } else if self.reservation_id(ctx).is_some() {
            ReservationBackend::Local
        } else {
            ReservationBackend::Unknown
        }
    }

    fn reserved_tokens(&self, ctx: &RequestContext) -> u64 {
        ctx.metadata
            .get(&self.keys.reserved_tokens)
            .and_then(|value| value.parse::<u64>().ok())
            .unwrap_or(0)
    }

    /// Whether THIS instance's `before_proxy` identified the request as an AI
    /// call (it parsed a JSON request body that carries a recognized LLM request
    /// field — see [`json_looks_like_ai_request`]). This is the gate for the
    /// `on_unmetered_response` policy and for response buffering / stream
    /// inspection: without it, that policy would apply to every 2xx on the proxy
    /// regardless of method or content type, so under `reject` a GET, a
    /// 204/empty-body 200, a non-JSON 2xx, or a non-LLM JSON 2xx on the same
    /// proxy would be turned into a 502. The marker — not `reserved_tokens > 0`
    /// — is the correct signal: `completion_tokens` mode legitimately reserves 0
    /// for valid AI requests with no output cap, so those must still be subject
    /// to the unmetered policy.
    fn request_was_ai_call(&self, ctx: &RequestContext) -> bool {
        ctx.metadata.contains_key(&self.keys.ai_request)
    }

    fn request_was_compressed_ai_candidate(&self, ctx: &RequestContext) -> bool {
        ctx.metadata.contains_key(&self.keys.compressed_ai_request)
    }

    /// Whether this instance may still need the response representation to
    /// resolve its own reservation lifecycle.
    ///
    /// This is the header-time exclusion of irrelevant traffic
    /// (GHSA-q2r2-6r7h-f69x): an ordinary non-AI request on a shared proxy is
    /// never buffered and never stream-inspected by this plugin, so it costs
    /// nothing. A deferred compressed classification counts as a candidate
    /// because `on_final_request_body_with_context` may still promote it.
    fn response_accounting_candidate(&self, ctx: &RequestContext) -> bool {
        self.request_was_ai_call(ctx)
            || ctx
                .metadata
                .contains_key(&self.keys.deferred_compressed_classification)
            || ctx.metadata.contains_key(&self.keys.reserved_tokens)
    }

    fn reservation_id(&self, ctx: &RequestContext) -> Option<u64> {
        ctx.metadata
            .get(&self.keys.reservation_id)
            .and_then(|value| value.parse::<u64>().ok())
    }

    fn reserved_window_index(&self, ctx: &RequestContext) -> Option<u64> {
        ctx.metadata
            .get(&self.keys.reserved_window_index)
            .and_then(|value| value.parse::<u64>().ok())
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

    fn should_release_gateway_rejection(&self, ctx: &RequestContext) -> bool {
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
            && self.reserved_tokens(ctx) > 0
            && ctx
                .metadata
                .get(&self.keys.unmetered_action)
                .map(String::as_str)
                != Some(OnUnmeteredResponse::Reject.as_str())
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
        self.classify_request_tokens(ctx).unwrap_or((false, 0))
    }

    /// Parse the staged request text once, distinguishing an unavailable or
    /// malformed view (`None`) from valid non-AI JSON (`Some((false, 0))`). The
    /// distinction lets pre-`before_proxy` decompression reserve immediately
    /// from refreshed plaintext while retaining the rare final-body fallback.
    fn classify_request_tokens(&self, ctx: &RequestContext) -> Option<(bool, u64)> {
        let body = ctx.metadata.get("request_body")?;
        let Ok(json) = serde_json::from_str::<Value>(body) else {
            return None;
        };
        // Gate the AI-request marker on LLM shape, not mere JSON parseability: the
        // plugin forces full response buffering, so `reconcile_usage` runs for
        // EVERY buffered 2xx. Without this gate a `reject`-mode limiter would 502
        // (and `charge_estimate` would bill) an ordinary non-LLM JSON `POST` that
        // happens to share the proxy. See `request_was_ai_call`.
        if !json_looks_like_ai_request(&json) {
            return Some((false, 0));
        }

        Some((true, self.estimate_request_tokens_from_json(&json)))
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
        let reserved_tokens = self.reserved_tokens(ctx);
        let reservation_id = self.reservation_id(ctx);
        let reserved_window_index = self.reserved_window_index(ctx);
        let reservation_backend = self.reservation_backend(ctx);

        // The actual-token charge path (`Some(actual_tokens)`) is the authoritative
        // reconcile and runs at most once per request in production — it is reached
        // from exactly one of three mutually exclusive places: `on_response_body`'s
        // 2xx branch (buffered response), `on_response_stream_terminated` (streamed
        // response), or the federation `after_proxy` branch (itself guarded by the
        // per-instance federation-recorded flag). A response is either buffered or
        // streamed, never both, and federation traffic is excluded from the other
        // two by their own guards. It must NOT *consult* the release-dedup marker
        // below before charging: `adjust_usage` advances the sliding window's
        // running-sum/eviction bookkeeping (via `current_usage`), so suppressing a
        // legitimate usage record would corrupt the window accounting. For a
        // terminal charge, though, the marker IS set so a later release path
        // (`actual_tokens == None`) cannot double-adjust the same reservation.
        if let Some(actual_tokens) = actual_tokens {
            // Terminal ownership must survive every exit, including a failed
            // centralized charge. Redis reservations then expire by their TTL;
            // a later release must not subtract them a second time.
            ctx.metadata
                .insert(self.keys.reservation_released.clone(), "true".to_string());
            ctx.metadata
                .insert(self.keys.actual_tokens.clone(), actual_tokens.to_string());
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
                if outcome.enforcement_unavailable {
                    // Usage already happened, even if committed stream headers
                    // make the refusal below ineffective. Account locally using
                    // the original reservation provenance, so a Redis estimate
                    // is never subtracted from an unrelated local reservation.
                    let local = self.limiter.check_local_at_with_capacity(
                        self.rate_key(ctx),
                        &AiRateLimitOp::AdjustUsage {
                            reservation_id,
                            reserved_window_index,
                            reservation_backend,
                            actual_tokens,
                            delta: Self::reservation_delta(actual_tokens, reserved_tokens),
                        },
                        Instant::now(),
                        MAX_STATE_ENTRIES,
                    );
                    let registry = super::prometheus_metrics::global_registry();
                    if let Some(local) = local {
                        self.store_metadata(ctx, &local);
                        ctx.metadata
                            .insert(self.keys.locally_accounted.clone(), "true".to_string());
                        registry
                            .ai_rate_limit_local_accounting_tokens
                            .fetch_add(actual_tokens, Ordering::Relaxed);
                    } else {
                        // Keep the hard identity cap even during an outage and
                        // expose any charge it prevents without identity labels.
                        registry
                            .ai_rate_limit_unaccounted_tokens
                            .fetch_add(actual_tokens, Ordering::Relaxed);
                    }
                    // Preserve the buffered/federated fail-closed response
                    // contract; streamed callers cannot replace sent headers.
                    if (200..300).contains(&response_status) {
                        return self.reject_enforcement_unavailable();
                    }
                    return PluginResult::Continue;
                }
                // Refresh expose-header metadata to the post-reconcile bucket so
                // later header copies (after_proxy federation/gateway, or
                // on_response_body on the normal path) describe actual usage —
                // not the pre-request admission estimate (#2261).
                self.store_metadata(ctx, &outcome);
            }
            return PluginResult::Continue;
        }

        // Idempotency gate for the reservation-RELEASE paths only (`actual_tokens
        // == None`): a request can reach a release more than once across phases —
        // e.g. a non-2xx release in `on_response_body` followed by a
        // gateway-rejection re-run of `after_proxy` for the same non-2xx backend,
        // or an unmetered `warn`/`reject` policy that also releases. The first
        // release owns the correction; any later one must be a clean no-op so the
        // reservation is never released twice. Without this, the Redis backend —
        // which has no per-entry reservation id and simply subtracts `reserved`
        // from the shared window — double-subtracts and under-counts the consumer's
        // own budget, allowing oversubscription. (Local mode already self-dedups
        // via `reservation_id`; this makes the guard uniform across both backends.)
        // Set the marker before doing any window work so an unmetered `reject`
        // (which returns a 502 rather than `Continue`) is likewise reconciled
        // exactly once. This deliberately does NOT gate the `Some(actual_tokens)`
        // charge path above, so independent usage records and the window-eviction
        // maintenance they drive are never suppressed.
        if ctx.metadata.contains_key(&self.keys.reservation_released) {
            return PluginResult::Continue;
        }
        ctx.metadata
            .insert(self.keys.reservation_released.clone(), "true".to_string());

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
                self.store_metadata(ctx, &outcome);
            }
            return PluginResult::Continue;
        }

        // The `on_unmetered_response` policy (charge_estimate / warn / reject)
        // only applies when `before_proxy` identified this as an AI request.
        // `on_response_body` still runs for every response this instance (or a
        // co-located plugin) pinned onto the buffered path — including non-AI
        // JSON that some other plugin buffered — so without this gate a
        // `reject`-mode limiter would turn a GET, a 204/empty-body 200, a
        // non-JSON 2xx, or a non-LLM JSON 2xx on the same proxy into a 502 — a
        // proxy-wide blast radius. Gate on the AI-request marker, NOT
        // `reserved_tokens > 0`: `completion_tokens` mode reserves 0 for valid
        // AI calls with no output cap, and those must still be subject to the
        // policy. A non-AI response is left untouched (no reject, no charge);
        // any reservation it somehow carries is 0, so the skipped
        // `adjust_usage` is a no-op anyway.
        if !self.request_was_ai_call(ctx) {
            return PluginResult::Continue;
        }

        match self.on_unmetered_response {
            OnUnmeteredResponse::ChargeEstimate => {
                ctx.metadata.insert(
                    self.keys.unmetered_action.clone(),
                    OnUnmeteredResponse::ChargeEstimate.as_str().to_string(),
                );
                if reserved_tokens == 0 && self.request_was_compressed_ai_candidate(ctx) {
                    warn_sampled!(
                        provider = %self.provider,
                        count_mode = %self.count_mode,
                        detail = %unmetered_detail,
                        "ai_rate_limiter: rejecting compressed AI response without token usage because no safe pre-request estimate exists"
                    );
                    return self.reject_unmetered();
                }
                warn_sampled!(
                    provider = %self.provider,
                    count_mode = %self.count_mode,
                    reserved_tokens,
                    detail = %unmetered_detail,
                    "ai_rate_limiter: successful response did not include token usage; keeping pre-request reservation"
                );
                PluginResult::Continue
            }
            OnUnmeteredResponse::Warn => {
                ctx.metadata.insert(
                    self.keys.unmetered_action.clone(),
                    OnUnmeteredResponse::Warn.as_str().to_string(),
                );
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
                    self.store_metadata(ctx, &outcome);
                }
                warn_sampled!(
                    provider = %self.provider,
                    count_mode = %self.count_mode,
                    reserved_tokens,
                    detail = %unmetered_detail,
                    "ai_rate_limiter: successful response did not include token usage; releasing reservation because on_unmetered_response=warn"
                );
                PluginResult::Continue
            }
            OnUnmeteredResponse::Reject => {
                ctx.metadata.insert(
                    self.keys.unmetered_action.clone(),
                    OnUnmeteredResponse::Reject.as_str().to_string(),
                );
                warn_sampled!(
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

    /// Resolve an observed provider counter for reservation reconciliation.
    ///
    /// A partial counter is authoritative as a lower bound only. In particular,
    /// TGI may report `details.generated_tokens` without `details.prefill`, and
    /// Anthropic can terminate after reporting only one component. In
    /// `total_tokens` mode those observations must never release the prompt or
    /// completion portion the provider did not report. Keep the larger of the
    /// existing reservation and the partial observation; a complete selected
    /// counter still replaces the estimate normally.
    fn reconciliation_tokens(
        &self,
        ctx: &RequestContext,
        observed_tokens: Option<u64>,
        selected_mode_complete: bool,
    ) -> Option<u64> {
        observed_tokens.map(|tokens| {
            if selected_mode_complete {
                tokens
            } else {
                tokens.max(self.reserved_tokens(ctx))
            }
        })
    }

    /// Bounded, budget-charged plaintext view of a buffered response body.
    ///
    /// Returns the body untouched when no content coding was applied, an owned
    /// plaintext buffer when one was, and a fixed unmetered reason when the
    /// representation cannot be reduced safely. A refusal never falls back to
    /// parsing the encoded bytes: the caller then applies `on_unmetered_response`,
    /// which is fail-closed by default.
    ///
    /// The decode goes through [`crate::plugins::charged_decode`], the strict,
    /// Large-Window-refusing codec pair whose decoder heap and every output
    /// growth are reserved against the shared retained-response budget BEFORE
    /// they are allocated (`GHSA-q76p-952x-7c3v`). The reservation is released
    /// when this returns, so a usage inspection cannot leave a residual charge.
    /// Only a request this instance classified as an AI call reaches here, so
    /// ordinary traffic on a shared proxy never pays for a decode.
    fn decoded_inspection_body<'a>(
        &self,
        response_headers: &HashMap<String, String>,
        body: &'a [u8],
    ) -> Result<std::borrow::Cow<'a, [u8]>, &'static str> {
        let Some(header) = response_headers.get("content-encoding") else {
            return Ok(std::borrow::Cow::Borrowed(body));
        };
        let Ok(codings) = parse_content_codings(header) else {
            return Err("undecodable_content_encoding");
        };
        if codings.iter().all(|coding| coding == "identity") {
            return Ok(std::borrow::Cow::Borrowed(body));
        }
        if codings.iter().any(|coding| coding == "identity") {
            return Err("undecodable_content_encoding");
        }
        if codings.len() > MAX_USAGE_DECODE_CODINGS || body.len() > MAX_USAGE_DECODE_BYTES {
            return Err("undecodable_content_encoding");
        }
        match super::charged_decode::decode_charged_content_coding_chain(
            &codings,
            body,
            DecodeLimits {
                max_decoded_bytes: MAX_USAGE_DECODE_BYTES,
                max_cumulative_bytes: MAX_USAGE_DECODE_CUMULATIVE_BYTES,
                max_codings: MAX_USAGE_DECODE_CODINGS,
                max_amplification_ratio: MAX_USAGE_DECODE_AMPLIFICATION_RATIO,
            },
            crate::proxy::response_buffer_budget::BudgetRef::global(),
        ) {
            Ok(plaintext) => Ok(std::borrow::Cow::Owned(plaintext)),
            Err(error) => {
                debug!(
                    limiter_instance = self.instance_id,
                    "ai_rate_limiter: response content decoding skipped: {error:?}"
                );
                Err("undecodable_content_encoding")
            }
        }
    }

    fn extract_token_count(&self, ctx: &RequestContext, body: &[u8]) -> Option<u64> {
        let json: Value = serde_json::from_slice(body).ok()?;
        let provider = match self.configured_provider {
            Some(provider) => provider,
            None => detect_response_provider(&json)?,
        };
        let usage = extract_response_usage(&json, provider);
        self.reconciliation_tokens(
            ctx,
            usage.total_for_mode(&self.count_mode),
            usage.is_complete_for_mode(&self.count_mode),
        )
    }

    /// Buffered-SSE usage extraction.
    ///
    /// Runs the SAME [`UsageStreamExtractor`] the streaming inspector uses, so
    /// a provider event is interpreted identically whether the response was
    /// streamed past the gateway or collected first. Sharing the extractor —
    /// rather than repeating a per-line loop here — is what keeps the two
    /// halves from disagreeing about event assembly: an SSE event may carry
    /// several `data:` fields whose values the standard joins with newlines
    /// before dispatch, and parsing each field on its own silently discarded a
    /// legal usage document split across two of them
    /// (`GHSA-pqjf-4jcj-34rp`). Only reachable when some other plugin pinned an
    /// event stream onto the buffered path; this limiter no longer does
    /// (GHSA-q2r2-6r7h-f69x).
    fn extract_token_count_from_sse(&self, ctx: &RequestContext, body: &[u8]) -> Option<u64> {
        let mut extractor =
            UsageStreamExtractor::new(UsageStreamFormat::Sse, self.configured_provider);
        extractor.push(body);
        extractor.finish();
        self.reconciliation_tokens(
            ctx,
            extractor.usage().total_for_mode(&self.count_mode),
            extractor.usage().is_complete_for_mode(&self.count_mode),
        )
    }

    /// Whether the buffered `on_unmetered_response` path would answer a
    /// usage-less 2xx with the 502 a committed stream can no longer deliver.
    ///
    /// `reject` always would. `charge_estimate` also does for a compressed AI
    /// candidate that never produced a safe pre-request estimate — that branch
    /// of [`Self::reconcile_usage`] returns [`Self::reject_unmetered`] too. Both
    /// therefore degrade to the same fail-closed accounting half on a stream and
    /// must say so, rather than logging a rejection that never reached the
    /// client. `warn` releases and is unaffected.
    fn unmetered_policy_would_reject(&self, ctx: &RequestContext) -> bool {
        match self.on_unmetered_response {
            OnUnmeteredResponse::Reject => true,
            OnUnmeteredResponse::ChargeEstimate => {
                self.reserved_tokens(ctx) == 0 && self.request_was_compressed_ai_candidate(ctx)
            }
            OnUnmeteredResponse::Warn => false,
        }
    }

    /// Reconcile a STREAMED response's terminal usage.
    ///
    /// Headers were committed before the first byte, so this path can neither
    /// reject nor rewrite the response. Every `on_unmetered_response` posture
    /// that would have answered with a 502 therefore degrades to its fail-closed
    /// accounting half — the pre-request reservation stays charged, exactly like
    /// `charge_estimate` — instead of substituting a status the client already
    /// cannot receive. `warn` still releases, `charge_estimate` still keeps.
    /// Release idempotency is the same per-instance marker the buffered path
    /// uses, so a stream that also ran a gateway-rejection `after_proxy` pass
    /// releases exactly once.
    async fn reconcile_streamed_usage(
        &self,
        ctx: &mut RequestContext,
        response_status: u16,
        actual_tokens: Option<u64>,
        unmetered_detail: &str,
    ) {
        if actual_tokens.is_none()
            && (200..300).contains(&response_status)
            && self.request_was_ai_call(ctx)
            && self.unmetered_policy_would_reject(ctx)
            && !ctx.metadata.contains_key(&self.keys.reservation_released)
        {
            // Record the action so a later gateway-rejection pass does not
            // release a reservation this policy deliberately keeps. Same value
            // the buffered path records for the same configured action, so the
            // two halves stay comparable in the transaction log.
            ctx.metadata.insert(
                self.keys.unmetered_action.clone(),
                self.on_unmetered_response.as_str().to_string(),
            );
            warn_sampled!(
                limiter_instance = self.instance_id,
                provider = %self.provider,
                count_mode = %self.count_mode,
                on_unmetered_response = self.on_unmetered_response.as_str(),
                detail = %unmetered_detail,
                "ai_rate_limiter: streamed successful response had no token usage; keeping the reservation charged (a committed streaming response cannot be replaced with a 502)"
            );
            // Mark the release path consumed so nothing later releases it.
            ctx.metadata
                .insert(self.keys.reservation_released.clone(), "true".to_string());
            return;
        }

        let _ = self
            .reconcile_usage(ctx, response_status, actual_tokens, unmetered_detail)
            .await;
    }
}

/// Top-level output-cap field spellings read by [`requested_completion_tokens`]
/// and excluded from the prompt walk only at the JSON root object.
const TOP_LEVEL_TOKEN_CAP_FIELDS: &[&str] = &[
    "max_tokens",
    "max_completion_tokens",
    "max_output_tokens",
    "max_tokens_to_sample",
    "max_new_tokens",
    "maxOutputTokens",
    "maxTokens",
];

/// Named provider containers whose immediate numeric child is an output cap.
/// Only the root-level `(container, field)` pairs listed here match
/// [`requested_completion_tokens`]; the same spellings deeper in tool schemas
/// or content are billed prompt material.
const NESTED_TOKEN_CAP_FIELDS: &[(&str, &str)] = &[
    ("generationConfig", "maxOutputTokens"),
    ("generation_config", "max_output_tokens"),
    ("inferenceConfig", "maxTokens"),
    ("inference_config", "max_tokens"),
    ("textGenerationConfig", "maxTokenCount"),
    ("parameters", "max_new_tokens"),
];

fn is_top_level_token_cap_field(key: &str) -> bool {
    TOP_LEVEL_TOKEN_CAP_FIELDS.contains(&key)
}

fn nested_token_cap_field_for_container(container: &str) -> Option<&'static str> {
    NESTED_TOKEN_CAP_FIELDS
        .iter()
        .find_map(|(name, field)| (*name == container).then_some(*field))
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
/// Field lists and the unsigned acceptance contract are shared with prompt-walk
/// exclusion via [`TOP_LEVEL_TOKEN_CAP_FIELDS`] / [`NESTED_TOKEN_CAP_FIELDS`] and
/// [`token_cap_u64`].
fn requested_completion_tokens(json: &Value) -> u64 {
    let top_level = TOP_LEVEL_TOKEN_CAP_FIELDS
        .iter()
        .filter_map(|field| json.get(*field).and_then(token_cap_u64))
        .max()
        .unwrap_or(0);

    let nested = NESTED_TOKEN_CAP_FIELDS
        .iter()
        .filter_map(|(container, field)| {
            json.get(*container)
                .and_then(|nested| nested.get(*field))
                .and_then(token_cap_u64)
        })
        .max()
        .unwrap_or(0);

    top_level.max(nested)
}

/// Unsigned output-cap values accepted by [`requested_completion_tokens`].
/// Negative and fractional JSON numbers are not recognized controls.
fn token_cap_u64(value: &Value) -> Option<u64> {
    value.as_u64()
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

/// Pre-dispatch prompt character estimate for token reservation.
///
/// # Estimator contract
///
/// Walks the already-parsed request JSON once via [`prompt_json_character_count`],
/// counting every billable string value, every visited object member name, and
/// JSON scalar literals (`null` / `true` / `false` / numbers) at their serialized
/// widths. Providers tokenize tool/function JSON Schema property names, nested
/// schema keys, and schema scalar keywords as prompt input, so omitting them
/// under-reserves. The single pass covers known billed shapes and unknown
/// provider-native textual siblings alike — a present recognized field never
/// suppresses an unknown sibling, and distinct alias keys over-reserve rather
/// than omit.
///
/// Exclusions are **path/context aware**, not name- or shape-only at arbitrary
/// depth:
/// - Numeric output caps are excluded only at the exact paths read by
///   [`requested_completion_tokens`] (root-level cap fields and the documented
///   named provider containers) and only when the value is an unsigned integer
///   accepted by that helper (`as_u64`). Nested schema/content numbers with the
///   same spelling, and negative/fractional numbers at cap paths, count
///   fail-closed.
/// - Multimodal binary URL/base64/file payloads are excluded only as **leaves**
///   inside a recognized provider content-part family **and** part `type` (OpenAI
///   Chat `messages` + `image_url`/`input_audio`/`file`, Responses `input` +
///   `input_image`/`input_audio`/`input_file`, Gemini `contents` parts +
///   `inline_data`/`inlineData`, Anthropic `messages` + `image`/`document`
///   `source`). Wrong-family / malformed / text parts count fail-closed. Member
///   names and every unrelated textual sibling still count. Ordinary strings —
///   including well-formed `data:` URLs in `instructions`, `input`, schemas, or
///   unknown fields — always count.
/// - Unknown, malformed, or collision-shaped objects outside those contexts
///   count fail-closed.
///
/// This is a conservative chars/4 estimate, not provider tokenizer parity.
///
/// The hot path is allocation-light: recursion carries a `Copy` context enum
/// (no per-request path vectors, maps, or locks) and follows the `Value` tree
/// the caller already parsed (bounded by the gateway's request-body limits).
/// Non-integer JSON numbers may format once via `Number::to_string` (bounded by
/// the already-parsed token).
fn prompt_character_count(json: &Value) -> u64 {
    prompt_json_character_count(json, PromptWalkCtx::root())
}

/// Compact walk context: where exclusions may apply. `Copy` and allocation-free.
#[derive(Clone, Copy)]
struct PromptWalkCtx {
    location: PromptLocation,
}

impl PromptWalkCtx {
    const fn root() -> Self {
        Self {
            location: PromptLocation::Root,
        }
    }

    const fn at(location: PromptLocation) -> Self {
        Self { location }
    }
}

/// Provider / content-container family carried through
/// ProviderMessages → MessageObject → ContentArray → ContentPart.
/// Disambiguates which reserved binary keys may exclude leaves.
#[derive(Clone, Copy, PartialEq, Eq)]
enum ContentFamily {
    /// Root `messages` — OpenAI Chat or Anthropic (part `type` selects).
    Messages,
    /// Root `input` — OpenAI Responses API.
    ResponsesInput,
    /// Root `contents` — Gemini / Vertex `parts`.
    GeminiContents,
    /// Root `chat_history` — Cohere; no multimodal leaf exclusions.
    ChatHistory,
}

/// Structural location for path-exact token-cap exclusion and multimodal
/// leaf exclusion. Never stores paths or strings.
#[derive(Clone, Copy, PartialEq, Eq)]
enum PromptLocation {
    /// The JSON root value before entering the root object.
    Root,
    /// Members of the request root object.
    RootObject,
    /// Immediate members of a root-level provider cap container
    /// (`generationConfig`, `parameters`, …). `field` is the only numeric key
    /// excluded here.
    RootCapContainer { field: &'static str },
    /// Root-level `messages` / `contents` / `input` / `chat_history` value.
    ProviderMessages { family: ContentFamily },
    /// One element of a provider messages array (a message / content object).
    MessageObject { family: ContentFamily },
    /// A `content` / `parts` array under a message object.
    ContentArray { family: ContentFamily },
    /// One multimodal/text content-part object.
    ContentPart { family: ContentFamily },
    /// Recognized binary payload object under a content part.
    BinaryObject { kind: BinaryObjectKind },
    /// Everywhere else — count fail-closed; no binary/cap exclusions.
    Nested,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum BinaryObjectKind {
    ImageUrl,
    InputAudio,
    InlineData,
    File,
    AnthropicSource,
}

/// Anthropic multimodal `source.type` values whose URL/base64/file **leaf**
/// may be excluded inside a content-block `source` object.
const BINARY_SOURCE_TYPES: &[&str] = &["base64", "url", "file"];

/// Minimum length before an alphabet-only string under a recognized binary
/// payload leaf is treated as base64. Shorter labels stay counted.
const MIN_BASE64_PAYLOAD_LEN: usize = 48;

/// Whether this object member is an output-cap control at a path also read by
/// [`requested_completion_tokens`]. Uses the same unsigned (`as_u64`) acceptance
/// contract so negative/fractional numbers count fail-closed.
fn is_excluded_token_cap_member(ctx: PromptWalkCtx, key: &str, value: &Value) -> bool {
    if token_cap_u64(value).is_none() {
        return false;
    }
    match ctx.location {
        PromptLocation::RootObject => is_top_level_token_cap_field(key),
        PromptLocation::RootCapContainer { field } => key == field,
        _ => false,
    }
}

fn is_remote_fetch_url(value: &str) -> bool {
    let bytes = value.as_bytes();
    (bytes.len() >= 8 && bytes[..7].eq_ignore_ascii_case(b"http://"))
        || (bytes.len() >= 9 && bytes[..8].eq_ignore_ascii_case(b"https://"))
}

fn is_likely_base64_payload(value: &str) -> bool {
    if value.len() < MIN_BASE64_PAYLOAD_LEN {
        return false;
    }
    value.bytes().all(|b| {
        matches!(
            b,
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'+' | b'/' | b'=' | b'-' | b'_'
        )
    })
}

/// True when `value` is a recognized multimodal URL/base64 leaf string.
fn is_binary_payload_string(value: &str) -> bool {
    is_data_url(value) || is_remote_fetch_url(value) || is_likely_base64_payload(value)
}

fn member_name_character_count(key: &str) -> u64 {
    key.chars().count() as u64
}

fn count_member_and_value(acc: u64, key: &str, value: &Value, child_ctx: PromptWalkCtx) -> u64 {
    acc.saturating_add(member_name_character_count(key))
        .saturating_add(prompt_json_character_count(value, child_ctx))
}

fn u64_decimal_character_count(mut value: u64) -> u64 {
    if value == 0 {
        return 1;
    }
    let mut len = 0_u64;
    while value > 0 {
        len = len.saturating_add(1);
        value /= 10;
    }
    len
}

/// Serialized width of a JSON number literal (digits / sign / fraction / exponent).
/// Integers use digit counting; non-integers format once (bounded by the parsed token).
fn json_number_literal_character_count(n: &serde_json::Number) -> u64 {
    if let Some(u) = n.as_u64() {
        return u64_decimal_character_count(u);
    }
    if let Some(i) = n.as_i64() {
        return if i < 0 {
            1u64.saturating_add(u64_decimal_character_count(i.unsigned_abs()))
        } else {
            u64_decimal_character_count(i as u64)
        };
    }
    n.to_string().len() as u64
}

/// Child context when entering `key`'s value from `ctx`.
fn child_context_for_member(ctx: PromptWalkCtx, key: &str) -> PromptWalkCtx {
    match ctx.location {
        PromptLocation::RootObject => {
            if let Some(field) = nested_token_cap_field_for_container(key) {
                return PromptWalkCtx::at(PromptLocation::RootCapContainer { field });
            }
            let family = match key {
                "messages" => Some(ContentFamily::Messages),
                "contents" => Some(ContentFamily::GeminiContents),
                "input" => Some(ContentFamily::ResponsesInput),
                "chat_history" => Some(ContentFamily::ChatHistory),
                _ => None,
            };
            match family {
                Some(family) => PromptWalkCtx::at(PromptLocation::ProviderMessages { family }),
                None => PromptWalkCtx::at(PromptLocation::Nested),
            }
        }
        PromptLocation::MessageObject { family } => match key {
            "content" | "parts" => PromptWalkCtx::at(PromptLocation::ContentArray { family }),
            _ => PromptWalkCtx::at(PromptLocation::Nested),
        },
        // Content-part binary children are handled by [`count_content_part_object`].
        _ => PromptWalkCtx::at(PromptLocation::Nested),
    }
}

/// Recognized binary payload object under a content part for this family+type.
/// Unknown / malformed / wrong-family parts return `None` (count fail-closed).
fn content_part_binary_kind(
    family: ContentFamily,
    part_type: Option<&str>,
    key: &str,
    value: &Value,
) -> Option<BinaryObjectKind> {
    if !value.is_object() {
        return None;
    }
    match family {
        ContentFamily::Messages => match (part_type, key) {
            (Some("image_url"), "image_url") => Some(BinaryObjectKind::ImageUrl),
            (Some("input_audio"), "input_audio") => Some(BinaryObjectKind::InputAudio),
            (Some("file"), "file") => Some(BinaryObjectKind::File),
            (Some("image") | Some("document"), "source") => Some(BinaryObjectKind::AnthropicSource),
            _ => None,
        },
        ContentFamily::ResponsesInput => match (part_type, key) {
            (Some("input_image"), "image_url") => Some(BinaryObjectKind::ImageUrl),
            (Some("input_audio"), "input_audio") => Some(BinaryObjectKind::InputAudio),
            (Some("input_file"), "file") => Some(BinaryObjectKind::File),
            _ => None,
        },
        ContentFamily::GeminiContents => match key {
            // Gemini parts omit a discriminator `type`; inline data is the
            // provider-native binary shape on `contents[].parts[]` only.
            "inline_data" | "inlineData" => Some(BinaryObjectKind::InlineData),
            _ => None,
        },
        ContentFamily::ChatHistory => None,
    }
}

/// Whether a direct string member on a content part is a recognized binary leaf.
fn content_part_string_leaf_excluded(
    family: ContentFamily,
    part_type: Option<&str>,
    key: &str,
    value: &str,
) -> bool {
    if !is_binary_payload_string(value) {
        return false;
    }
    match family {
        ContentFamily::Messages => matches!(
            (part_type, key),
            (Some("image_url"), "image_url") | (Some("file"), "file_data")
        ),
        ContentFamily::ResponsesInput => matches!(
            (part_type, key),
            (Some("input_image"), "image_url") | (Some("input_file"), "file_data")
        ),
        ContentFamily::GeminiContents | ContentFamily::ChatHistory => false,
    }
}

/// Array-element context when walking an array at `ctx`.
fn child_context_for_array_element(ctx: PromptWalkCtx) -> PromptWalkCtx {
    match ctx.location {
        PromptLocation::ProviderMessages { family } => {
            PromptWalkCtx::at(PromptLocation::MessageObject { family })
        }
        PromptLocation::ContentArray { family } => {
            PromptWalkCtx::at(PromptLocation::ContentPart { family })
        }
        _ => PromptWalkCtx::at(PromptLocation::Nested),
    }
}

/// Exclude a recognized binary leaf string inside a binary payload object.
/// Member names are counted by the caller. Content-part string leaves are
/// handled by [`count_content_part_object`].
fn should_exclude_binary_leaf(ctx: PromptWalkCtx, key: &str, value: &Value) -> bool {
    let Some(s) = value.as_str() else {
        return false;
    };

    match ctx.location {
        PromptLocation::BinaryObject { kind } => match kind {
            BinaryObjectKind::ImageUrl => {
                key == "url" && (is_data_url(s) || is_remote_fetch_url(s))
            }
            BinaryObjectKind::InputAudio | BinaryObjectKind::InlineData => {
                key == "data" && is_binary_payload_string(s)
            }
            BinaryObjectKind::File => {
                (key == "file_data" || key == "data") && is_binary_payload_string(s)
            }
            // AnthropicSource uses [`count_anthropic_source_object`] instead.
            BinaryObjectKind::AnthropicSource => false,
        },
        _ => false,
    }
}

/// Count members of an Anthropic content-block `source` object: exclude only the
/// binary payload leaf (`data` / `url` / `file_id`) when `type` is binary **and**
/// the leaf string is itself a recognized URL/base64 payload
/// ([`is_binary_payload_string`]); count the member name and every other sibling
/// fail-closed. The payload-shape gate mirrors the OpenAI / Responses / Gemini
/// leaves: a `source` that merely declares `type: "base64"` / `"url"` / `"file"`
/// while carrying prose is malformed, so a reserved spelling alone can never drop
/// unbounded billed text from the reservation.
fn count_anthropic_source_object(acc: u64, source: &serde_json::Map<String, Value>) -> u64 {
    let binary_ty = source
        .get("type")
        .and_then(Value::as_str)
        .filter(|ty| BINARY_SOURCE_TYPES.contains(ty));

    source.iter().fold(acc, |acc, (key, value)| {
        let acc = acc.saturating_add(member_name_character_count(key));
        let exclude_leaf = match (binary_ty, key.as_str(), value) {
            (Some("base64"), "data", Value::String(payload))
            | (Some("url"), "url", Value::String(payload))
            | (Some("file"), "file_id" | "data" | "url", Value::String(payload)) => {
                is_binary_payload_string(payload)
            }
            _ => false,
        };
        if exclude_leaf {
            acc
        } else {
            acc.saturating_add(prompt_json_character_count(
                value,
                PromptWalkCtx::at(PromptLocation::Nested),
            ))
        }
    })
}

/// Count members of a recognized multimodal payload object, excluding only the
/// binary URL/base64/file leaf string; names and textual siblings always count.
fn count_binary_object_members(
    acc: u64,
    kind: BinaryObjectKind,
    obj: &serde_json::Map<String, Value>,
) -> u64 {
    if kind == BinaryObjectKind::AnthropicSource {
        return count_anthropic_source_object(acc, obj);
    }

    let ctx = PromptWalkCtx::at(PromptLocation::BinaryObject { kind });
    obj.iter().fold(acc, |acc, (key, value)| {
        if should_exclude_binary_leaf(ctx, key, value) {
            return acc.saturating_add(member_name_character_count(key));
        }
        count_member_and_value(acc, key, value, PromptWalkCtx::at(PromptLocation::Nested))
    })
}

/// Count a provider content-part object: inspect part `type` (when the family
/// defines one) and exclude only matching binary leaves; wrong-family /
/// malformed reserved spellings count fail-closed.
fn count_content_part_object(family: ContentFamily, part: &serde_json::Map<String, Value>) -> u64 {
    let part_type = part.get("type").and_then(Value::as_str);

    part.iter().fold(0_u64, |acc, (key, value)| {
        if let Some(s) = value.as_str()
            && content_part_string_leaf_excluded(family, part_type, key, s)
        {
            return acc.saturating_add(member_name_character_count(key));
        }

        if let (Some(kind), Some(obj)) = (
            content_part_binary_kind(family, part_type, key, value),
            value.as_object(),
        ) {
            return count_binary_object_members(
                acc.saturating_add(member_name_character_count(key)),
                kind,
                obj,
            );
        }

        count_member_and_value(acc, key, value, PromptWalkCtx::at(PromptLocation::Nested))
    })
}

/// Fail-closed prompt character walk with path/context-aware exclusions.
fn prompt_json_character_count(value: &Value, ctx: PromptWalkCtx) -> u64 {
    match value {
        // JSON Schema and provider bodies include numeric/boolean/`null` keywords
        // that appear in the serialized prompt. Count each at its JSON literal
        // width so large schemas cannot omit scalars at scale.
        Value::Null => 4,
        Value::Bool(true) => 4,
        Value::Bool(false) => 5,
        Value::Number(n) => json_number_literal_character_count(n),
        // Ordinary strings always count — including well-formed `data:` URLs in
        // instructions, schemas, or unknown fields. Binary payload exclusion
        // happens only at recognized multimodal leaves (member handling below).
        Value::String(value) => value.chars().count() as u64,
        Value::Array(values) => {
            let elem_ctx = child_context_for_array_element(ctx);
            values.iter().fold(0_u64, |acc, value| {
                acc.saturating_add(prompt_json_character_count(value, elem_ctx))
            })
        }
        Value::Object(values) => match ctx.location {
            PromptLocation::ContentPart { family } => count_content_part_object(family, values),
            _ => {
                let member_ctx = match ctx.location {
                    PromptLocation::Root => PromptWalkCtx::at(PromptLocation::RootObject),
                    other => PromptWalkCtx::at(other),
                };
                values.iter().fold(0_u64, |acc, (key, value)| {
                    // Exact-path unsigned caps (parity with requested_completion_tokens).
                    if is_excluded_token_cap_member(member_ctx, key, value) {
                        return acc;
                    }

                    let child_ctx = child_context_for_member(member_ctx, key);
                    count_member_and_value(acc, key, value, child_ctx)
                })
            }
        },
    }
}

/// Maximum length of the header portion (`[<mediatype>][;base64]`) of a `data:`
/// URL we will scan for the mandatory `,` separator. RFC 2397 mediatypes plus
/// parameters are short; this bounds the scan so an arbitrarily long string that
/// merely starts with `data:` is not scanned end-to-end.
const DATA_URL_MAX_HEADER_LEN: usize = 256;

/// Whether a string is an inline `data:` URL per RFC 2397:
/// `data:[<mediatype>][;base64],<payload>`.
///
/// Used only to recognize multimodal binary **leaves** under content-block
/// context. Ordinary billed strings that happen to be well-formed `data:` URLs
/// (e.g. Responses `instructions`) are still counted by the walk. Requiring the
/// structural `,` separator avoids treating prose like `"data: my notes"` as a
/// binary URL when evaluating a leaf. Case-insensitive on the `data:` scheme;
/// allocation-light (byte scan only).
fn is_data_url(value: &str) -> bool {
    let Some(rest) = value
        .get(..5)
        .filter(|prefix| prefix.eq_ignore_ascii_case("data:"))
        .and_then(|_| value.get(5..))
    else {
        return false;
    };

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

    /// This limiter never mutates a backend-visible request header.
    ///
    /// `expose_headers` writes the four `x-ai-ratelimit-*` values into the
    /// RESPONSE map (see [`Self::apply_exposed_headers`]), so declaring a
    /// request-header mutation here described a capability the plugin does not
    /// have — and that declaration is load-bearing for composition admission.
    /// `PluginCache` refuses a `request_deduplication` (3010) or
    /// `response_caching` (3500) instance that would fingerprint headers before
    /// a later request-header mutator at 4200, so merely turning response
    /// telemetry on made an otherwise valid limiter-plus-cache/dedup proxy fail
    /// validation (issue #5318). `before_proxy` only READS the header map it is
    /// handed, which is exactly what the default `false` promises.
    fn modifies_request_headers(&self) -> bool {
        false
    }

    fn requires_request_body_before_before_proxy(&self) -> bool {
        true
    }

    fn should_buffer_request_body(&self, ctx: &RequestContext) -> bool {
        // This plugin cannot decode a compressed body itself. Withdraw its own
        // buffering vote: a co-located `compression` plugin that supports the
        // coding requests the pre-`before_proxy` buffer, normalizes it, and
        // refreshes the plaintext view this limiter then reserves from. Without
        // such a decoder the body stays encoded and takes the reconcile-only,
        // fail-closed candidate path. Avoid buffering bytes this plugin cannot
        // interpret merely to discover that they are encoded.
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
        // The normal pre-`before_proxy` decompression path refreshes plaintext
        // early. Retain final-body context for the rare fallback where a decoder
        // could only stage plaintext for the later transform; its instance-owned
        // deferred marker is consumed there.
        true
    }

    fn warmup_hostnames(&self) -> Vec<String> {
        self.limiter.warmup_hostname().into_iter().collect()
    }

    fn tracked_keys_count(&self) -> Option<usize> {
        Some(self.limiter.tracked_keys_count())
    }

    /// Config-time upper bound only. A metered AI response whose usage lives in
    /// a JSON document still needs the collected body; every other response is
    /// released by the per-request refinements below.
    fn requires_response_body_buffering(&self) -> bool {
        true
    }

    /// Per-request refinement: buffer nothing for a request this instance never
    /// classified as an AI call.
    ///
    /// Before GHSA-q2r2-6r7h-f69x this returned `true` unconditionally, so an
    /// active limiter pinned EVERY response on its proxy — including SSE and
    /// other long-lived model streams — onto the buffered path. Incremental
    /// delivery was destroyed and each concurrent stream retained a growing
    /// buffer, bounded only per-response by the global response limit and not at
    /// all in aggregate.
    fn should_buffer_response_body(&self, ctx: &RequestContext) -> bool {
        self.response_accounting_candidate(ctx)
    }

    /// Header-time refinement: the ONLY representation this limiter still needs
    /// collected is a JSON usage document on a successful metered response.
    ///
    /// Everything else is released to the streaming path and resolved without a
    /// buffer:
    ///   * event streams (SSE) and AWS Bedrock event-stream framing are metered
    ///     incrementally by [`Self::response_stream_inspector`];
    ///   * a non-2xx response only needs its reservation released, which is a
    ///     status-only decision `after_proxy` already made;
    ///   * framed gRPC-Web and other non-JSON media carry no usage document this
    ///     plugin can read, so collecting them buys nothing — the terminal
    ///     stream hook applies `on_unmetered_response` instead.
    ///
    /// Contract: this only ever NARROWS [`Self::should_buffer_response_body`].
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
        content_type.is_some_and(|content_type| {
            is_json_content_type(content_type) && !is_framed_grpc_content_type(content_type)
        })
    }

    /// A retry-eligible response may still be released to the streaming path.
    ///
    /// Without this the retry branch of the buffering decision keeps every
    /// response collected while retries are configured, which would reinstate
    /// exactly the unbounded SSE buffering this plugin no longer needs. The
    /// confirmation below is header-complete, so releasing here never discards a
    /// body a retry could have replayed for THIS plugin.
    fn may_release_response_body_under_retries(&self, ctx: &RequestContext) -> bool {
        self.should_buffer_response_body(ctx)
    }

    fn should_release_response_body_under_retries(
        &self,
        ctx: &RequestContext,
        response_status: u16,
        response_headers: &HashMap<String, String>,
    ) -> bool {
        let content_type = response_headers.get("content-type").map(String::as_str);
        !self.should_buffer_response_body_for_content_type(
            ctx,
            content_type,
            response_status,
            response_headers,
        )
    }

    /// An event stream can be released even though a later `after_proxy` hook
    /// may rewrite `Content-Type`.
    ///
    /// The conservative default pins a buffered response whenever any later
    /// plugin might relabel the representation. That guard exists for plugins
    /// whose body NEED depends on the label; this one's does not for a stream:
    /// relabelling an unbounded event stream does not bound it, and the usage is
    /// metered incrementally rather than from a collected body. A JSON-labelled
    /// response keeps the conservative default, so a relabel can never move a
    /// usage document off the buffered path.
    fn should_release_response_body_before_content_type_rewrite(
        &self,
        ctx: &RequestContext,
        response_status: u16,
        response_headers: &HashMap<String, String>,
    ) -> bool {
        if !self.should_buffer_response_body(ctx) {
            return true;
        }
        if !(200..300).contains(&response_status) {
            return true;
        }
        response_headers
            .get("content-type")
            .is_some_and(|content_type| {
                is_event_stream_content_type(content_type)
                    || is_aws_event_stream_content_type(content_type)
            })
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
        //     decoded the normal buffered body in the shared pre-`before_proxy`
        //     normalization phase: it strips `content-encoding`, records the
        //     `compression:request_encoding` metadata key, and refreshes
        //     `ctx.metadata["request_body"]` to the plaintext the backend will
        //     receive. Classify and pre-reserve that plaintext normally. On the
        //     rare fallback where the trusted marker exists but no parseable text
        //     view was refreshed, defer classification to `on_final_request_body`.
        //     Detect this only from compression-owned metadata, never from the
        //     client-settable `x-ferrum-original-content-encoding` header.
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
        let normalized_request_tokens = (decompressed_by_compression && is_post_json)
            .then(|| self.classify_request_tokens(ctx))
            .flatten();
        let defer_compressed_classification =
            decompressed_by_compression && is_post_json && normalized_request_tokens.is_none();
        let (is_ai_request, reserved_tokens) = if is_framed_grpc {
            // Framed gRPC-Web: out of scope for this JSON policy entirely.
            (false, 0)
        } else if still_compressed {
            // Case B: uninspectable compressed body — fail closed for POST JSON.
            (is_post_json, 0)
        } else if defer_compressed_classification {
            // Case A fallback: defer to `on_final_request_body` (plaintext there).
            (false, 0)
        } else if let Some(classification) = normalized_request_tokens {
            // Case A normal buffered decode: the shared normalizer refreshed
            // the text view, so classify and reserve from that plaintext now.
            classification
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
        // 2. Reconciliation is exact on every terminal outcome the proxy can
        //    observe; window/TTL is only a cancellation backstop.
        //    `reconcile_usage` / `reconcile_streamed_usage` run from:
        //      - buffered JSON 2xx → `on_response_body`
        //      - meterable streams → `on_response_stream_terminated` (completion,
        //        backend body error, client-disconnect Drop; inspector-cap
        //        refusal still resolves via `on_unmetered_response`)
        //      - genuine non-2xx backend → status-only `after_proxy` release
        //      - genuine pre-provider / failed-dispatch gateway rejection →
        //        reject-replay `after_proxy` via `should_release_gateway_rejection`
        //      - federation → reject-path `after_proxy` (sole federation charger)
        //    A later after_proxy / body-policy rejection of a provider-consumed
        //    2xx deliberately KEEPS the charge. Streamed `on_unmetered_response:
        //    "reject"` cannot substitute a 502 after headers are committed; it
        //    keeps the reservation charged and marks the release path consumed
        //    so reject-replay cannot free it. Window/TTL remains only for
        //    cancellation-only cases that truly cannot await reconciliation
        //    (request-task abort, deferred-logger Drop outside a Tokio runtime).
        //    Docs must not claim ordinary non-2xx / reject-replay /
        //    client-disconnect paths leak when these hooks handle them.
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
        // 4. A body normalized by a co-located `compression` plugin is classified
        //    and pre-reserved from the refreshed plaintext view (Case A). A body
        //    that stays compressed cannot be estimated safely: it falls through
        //    to `CheckBudget`, is marked as a fail-closed AI candidate for a JSON
        //    POST, and post-response reconciliation charges authoritative usage
        //    (Case B). The rare decoded fallback without a refreshed text view
        //    defers classification to `on_final_request_body`; a usage-less 2xx
        //    can therefore never turn the missing estimate into a free call.
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
            warn_sampled!(
                current_tokens = usage,
                limit = self.token_limit,
                plugin = "ai_rate_limiter",
                "AI token rate limit exceeded"
            );
            return self.reject(usage);
        }

        // Record this request's `on_unmetered_response` classification:
        //   - Case A normal buffered decode: classify and reserve from the
        //     refreshed plaintext above. Only its rare no-text-view fallback
        //     defers to `on_final_request_body`.
        //   - Case B (uninspectable compressed POST JSON): `is_ai_request` is the
        //     fail-closed candidate; also tag it compressed so the default
        //     `charge_estimate` path rejects a usage-less 2xx (no safe estimate).
        //   - Case C / estimated AI: mark from the parsed body.
        if defer_compressed_classification {
            ctx.metadata.insert(
                self.keys.deferred_compressed_classification.clone(),
                "true".to_string(),
            );
        } else if is_ai_request {
            ctx.metadata
                .insert(self.keys.ai_request.clone(), "true".to_string());
            if still_compressed {
                ctx.metadata
                    .insert(self.keys.compressed_ai_request.clone(), "true".to_string());
            }
        }

        if reserved_tokens > 0 {
            ctx.metadata.insert(
                self.keys.reserved_tokens.clone(),
                reserved_tokens.to_string(),
            );
            // Shared PRESENCE marker consumed only by the proxy's
            // `run_after_proxy_hooks` gate for recording the genuine backend
            // status. Its value is this instance's estimate but is never read
            // back for a decision — every accounting read uses the
            // instance-scoped key above (GHSA-wh4p-pmxm-3784).
            ctx.metadata.insert(
                RESERVED_TOKENS_METADATA_KEY.to_string(),
                reserved_tokens.to_string(),
            );
            // Carry the local-window reservation id so reconciliation releases
            // the exact entry this request created (correct under concurrent,
            // out-of-order completions). `None` in Redis mode — harmless, the
            // Redis reconciliation path ignores it.
            if let Some(reservation_id) = outcome.reservation_id {
                ctx.metadata
                    .insert(self.keys.reservation_id.clone(), reservation_id.to_string());
            }
            // Carry the Redis window this reservation credited so reconciliation
            // debits the SAME window even across a rollover (centralized mode).
            // `None` in local mode — the in-memory window pins the correction via
            // the matched entry's timestamp instead.
            if let Some(reserved_window_index) = outcome.reserved_window_index {
                ctx.metadata.insert(
                    self.keys.reserved_window_index.clone(),
                    reserved_window_index.to_string(),
                );
            }
        }
        self.store_metadata(ctx, &outcome);
        PluginResult::Continue
    }

    async fn on_final_request_body_with_context(
        &self,
        ctx: &mut RequestContext,
        headers: &HashMap<String, String>,
        body: &[u8],
    ) -> PluginResult {
        // Only act on the rare Case A fallback where a co-located `compression`
        // plugin decoded a POST JSON body but the pre-`before_proxy` phase had no
        // parseable text view to refresh. The normal buffered decode is already
        // classified and pre-reserved from plaintext in `before_proxy`. Keys are
        // instance-scoped, so each co-located limiter consumes only its own
        // deferred marker.
        if ctx
            .metadata
            .remove(&self.keys.deferred_compressed_classification)
            .is_none()
        {
            return PluginResult::Continue;
        }

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
            ctx.metadata
                .insert(self.keys.ai_request.clone(), "true".to_string());
            ctx.metadata
                .insert(self.keys.compressed_ai_request.clone(), "true".to_string());
            return PluginResult::Continue;
        }

        // The decompressed body is available now. Mark the request as an AI call
        // ONLY when it actually parses as one, so a non-AI JSON body on a shared
        // proxy is never subjected to the `on_unmetered_response` policy. This
        // fallback could not take a safe pre-reservation, so tag it compressed;
        // default `charge_estimate` rejects a usage-less 2xx instead of treating
        // an absent estimate as a free charge.
        if serde_json::from_slice::<Value>(body)
            .ok()
            .as_ref()
            .is_some_and(json_looks_like_ai_request)
        {
            ctx.metadata
                .insert(self.keys.ai_request.clone(), "true".to_string());
            ctx.metadata
                .insert(self.keys.compressed_ai_request.clone(), "true".to_string());
        }

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
        // Gated on this instance's reserved-tokens metadata (mirroring the
        // proxy-side presence check on `RESERVED_TOKENS_METADATA_KEY` in
        // `run_after_proxy_hooks`): without a reservation the keep/release
        // decision is moot (`should_release_gateway_rejection` requires
        // `reserved > 0`), so recording the status only adds dead metadata —
        // and a transaction-log field — to every request on the proxy,
        // including non-AI ones.
        let in_rejection_context = ctx
            .metadata
            .get(REJECTION_RESPONSE_METADATA_KEY)
            .is_some_and(|value| value == "true");
        if !in_rejection_context && ctx.metadata.contains_key(&self.keys.reserved_tokens) {
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
            if !ctx
                .metadata
                .contains_key(&self.keys.federation_tokens_recorded)
            {
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
                // A failed centralized reconcile can still charge locally.
                // Claim this usage before any return so reject-hook replay
                // cannot apply the same terminal charge a second time.
                ctx.metadata.insert(
                    self.keys.federation_tokens_recorded.clone(),
                    "true".to_string(),
                );
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
            }
        } else if self.should_release_gateway_rejection(ctx) {
            let result = self
                .reconcile_usage(ctx, 500, None, "gateway_rejection")
                .await;
            if !matches!(result, PluginResult::Continue) {
                return result;
            }
        } else if !in_rejection_context
            && !(200..300).contains(&response_status)
            && self.reserved_tokens(ctx) > 0
        {
            // Release the reservation for a genuine non-2xx backend response
            // here rather than from a body hook. The decision is status-only, so
            // it must not depend on collecting a body this plugin no longer
            // pins onto the buffered path (GHSA-q2r2-6r7h-f69x): `after_proxy`
            // runs on every H1/H2/H3, buffered and streaming, gRPC and gRPC-Web
            // response. The per-instance release marker makes the later
            // buffered `on_response_body` pass and the streamed terminal hook
            // clean no-ops.
            let result = self
                .reconcile_usage(ctx, response_status, None, "non_2xx_response")
                .await;
            if !matches!(result, PluginResult::Continue) {
                return result;
            }
        }

        // A representation released to the streaming path is committed after
        // this hook. If this request reserved nothing, terminal reconciliation
        // cannot enforce a rejection: there is no charge to keep and it is too
        // late to substitute a 502. Refuse that unsafe combination before the
        // headers are committed. Streams backed by a non-zero reservation keep
        // their incremental, bounded accounting path.
        let response_content_type = response_headers.get("content-type").map(String::as_str);
        let response_will_stream = !response_content_type.is_some_and(|content_type| {
            is_json_content_type(content_type) && !is_framed_grpc_content_type(content_type)
        });
        // Last hook that sees the response header map before a streamed body
        // commits. The stream-inspector factory is handed only the content
        // TYPE, and the incremental parsers understand SSE / AWS event-stream
        // FRAMING, not content codings — feeding them compressed octets would
        // find no usage while pretending the stream was metered. Record the
        // coding here so the factory can decline and let the terminal hook
        // apply `on_unmetered_response` (fail-closed by default) instead.
        if response_will_stream && has_non_identity_content_encoding(response_headers) {
            ctx.metadata
                .insert(self.keys.encoded_stream.clone(), "true".to_string());
        }
        if !in_rejection_context
            && (200..300).contains(&response_status)
            && response_will_stream
            && self.request_was_ai_call(ctx)
            && self.reserved_tokens(ctx) == 0
            && self.unmetered_policy_would_reject(ctx)
        {
            ctx.metadata.insert(
                self.keys.unmetered_action.clone(),
                self.on_unmetered_response.as_str().to_string(),
            );
            warn_sampled!(
                limiter_instance = self.instance_id,
                provider = %self.provider,
                count_mode = %self.count_mode,
                on_unmetered_response = self.on_unmetered_response.as_str(),
                "ai_rate_limiter: rejecting an unreserved streaming response before commit because missing usage could not be enforced later"
            );
            return self.reject_unmetered();
        }

        if !self.expose_headers {
            return PluginResult::Continue;
        }

        self.apply_exposed_headers(ctx, response_headers);

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
        for (_, meta_key, header_name) in &self.keys.exposed_headers {
            if name.eq_ignore_ascii_case(header_name) && ctx.metadata.contains_key(meta_key) {
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

    fn requires_response_stream_hooks(&self) -> bool {
        // Always: a metered AI response can stream on any of H1/H2/H3, and the
        // terminal hook is also what applies `on_unmetered_response` to a
        // streamed response that never reported usage. The per-request factory
        // below declines everything that is not a meterable AI stream, so an
        // ordinary proxy pays only the capability check.
        true
    }

    /// Attach a bounded incremental usage extractor to a meterable AI stream.
    ///
    /// Replaces full-response buffering for streamed responses
    /// (GHSA-q2r2-6r7h-f69x) and is the authoritative usage source for the
    /// provider-native streaming formats that previously had none
    /// (GHSA-rxj9-f483-g53f): Gemini SSE `usageMetadata`, AWS Bedrock
    /// `application/vnd.amazon.eventstream` framing, and TGI
    /// `details.generated_tokens`, alongside the existing OpenAI, Anthropic, and
    /// Cohere signals.
    ///
    /// Bytes are forwarded unchanged and never held, so SSE delivery latency is
    /// unaffected. Retention per stream is one bounded parser carry plus a
    /// four-scalar accumulator, and the process-wide inspector count is capped
    /// by [`MAX_CONCURRENT_STREAM_ACCOUNTING`]; over that cap no inspector is
    /// attached and the response resolves through `on_unmetered_response`,
    /// which is fail-closed by default.
    fn response_stream_inspector(
        &self,
        ctx: &RequestContext,
        response_status: u16,
        content_type: Option<&str>,
    ) -> Option<Box<dyn ResponseStreamInspector>> {
        if !(200..300).contains(&response_status) {
            return None;
        }
        // Only a request THIS instance classified as an AI call. An unrelated
        // SSE route on a shared proxy is never parsed or accounted.
        if !self.response_accounting_candidate(ctx) {
            return None;
        }
        // A content-coded stream is not a framing this parser can read; see
        // [`meta::ENCODED_STREAM`].
        if ctx.metadata.contains_key(&self.keys.encoded_stream) {
            return None;
        }
        let content_type = content_type?;
        // Framed gRPC-Web wire frames are not a usage representation and are
        // never charged (they are excluded on the request side too).
        if is_framed_grpc_content_type(content_type) {
            return None;
        }
        let format = if is_event_stream_content_type(content_type) {
            UsageStreamFormat::Sse
        } else if is_aws_event_stream_content_type(content_type) {
            UsageStreamFormat::AwsEventStream
        } else {
            return None;
        };

        let handoff = ctx.response_stream_handoff()?;
        let Some(permit) = StreamAccountingPermit::acquire() else {
            // Aggregate accounting state is saturated. Forward the stream
            // untouched; the terminal hook applies the configured unmetered
            // policy exactly once, so the budget is never silently freed.
            // Sampled so saturation cannot turn every request into a log line.
            let refused = STREAM_ACCOUNTING_REFUSALS.fetch_add(1, Ordering::Relaxed);
            if refused.is_multiple_of(STREAM_ACCOUNTING_REFUSAL_LOG_INTERVAL) {
                warn!(
                    plugin = "ai_rate_limiter",
                    limit = MAX_CONCURRENT_STREAM_ACCOUNTING,
                    refused_total = refused.saturating_add(1),
                    "streaming token accounting at capacity; responses are resolved by on_unmetered_response until it drains"
                );
            }
            return None;
        };
        let shared = Arc::new(StreamUsageHandoff::default());
        handoff.publish(self.stream_usage_handoff_key, Arc::clone(&shared));
        Some(Box::new(UsageStreamInspector {
            extractor: UsageStreamExtractor::new(format, self.configured_provider),
            shared,
            _permit: permit,
        }))
    }

    /// Reconcile a streamed response's terminal usage exactly once.
    ///
    /// Runs on every terminal outcome of a streamed body — normal completion,
    /// backend error, and the client-disconnect `Drop` safety net — so a stream
    /// abandoned mid-flight still resolves its reservation instead of leaking it
    /// to window/TTL expiry.
    async fn on_response_stream_terminated(
        &self,
        ctx: &mut RequestContext,
        response_status: u16,
        _outcome: &crate::proxy::deferred_log::BodyOutcome,
    ) {
        // Federation reconciles exclusively in `after_proxy`; synthetic
        // short-circuit bodies consumed no provider tokens. Both mirror the
        // buffered `on_response_body` guards.
        if ctx.metadata.contains_key("ai_federation_provider")
            || ctx
                .metadata
                .contains_key(crate::proxy::SYNTHETIC_SHORT_CIRCUIT_METADATA_KEY)
        {
            return;
        }
        if !self.response_accounting_candidate(ctx) {
            return;
        }

        let captured = ctx
            .response_stream_handoff()
            .and_then(|handoff| handoff.take::<StreamUsageHandoff>(self.stream_usage_handoff_key));
        let (tokens, detail) = match &captured {
            Some(shared) => {
                let usage = match shared.usage.lock() {
                    Ok(usage) => usage.clone(),
                    Err(poisoned) => poisoned.into_inner().clone(),
                };
                if usage.observed() {
                    (
                        self.reconciliation_tokens(
                            ctx,
                            usage.total_for_mode(&self.count_mode),
                            usage.is_complete_for_mode(&self.count_mode),
                        ),
                        "stream_usage",
                    )
                } else {
                    (
                        self.read_tokens_from_metadata(&ctx.metadata),
                        "stream_without_usage",
                    )
                }
            }
            // No inspector ran: a non-meterable streamed representation, or the
            // aggregate accounting cap was reached. A co-located plugin may
            // still have published authoritative usage into metadata.
            None => (
                self.read_tokens_from_metadata(&ctx.metadata),
                "stream_not_inspected",
            ),
        };

        self.reconcile_streamed_usage(ctx, response_status, tokens, detail)
            .await;
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

        // Classify the REQUEST before touching the response, exactly as the
        // streamed halves already do (`response_stream_inspector` and
        // `on_response_stream_terminated` both gate on this predicate). This
        // hook runs for every response some other plugin pinned onto the
        // buffered path, so without the gate an ordinary non-AI reply whose
        // JSON happens to carry a usage-shaped object — a stored transcript, a
        // usage-reporting endpoint, an `ai_token_metrics` metadata write for a
        // sibling route — was charged against the budget, and the same GET was
        // billed over H1/H2 while the streamed H3 path left it alone (issue
        // #5319). A non-candidate holds no reservation of this instance's, so
        // there is nothing to release either: skipping is the whole lifecycle.
        if !self.response_accounting_candidate(ctx) {
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
            // `after_proxy` already released (or will no-op on the marker) and
            // refreshed expose headers; re-apply so a body-hook-only caller still
            // sees the post-release bucket.
            if matches!(result, PluginResult::Continue) {
                self.apply_exposed_headers(ctx, response_headers);
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

            let is_sse = is_event_stream_content_type(content_type);
            // A Bedrock event stream normally reaches the incremental
            // inspector; it can still land here when an unrelated plugin pins
            // the response onto the buffered path. Decode it with the same
            // bounded framing parser so both paths charge identically.
            let is_aws_event_stream = is_aws_event_stream_content_type(content_type);
            if !is_sse && !is_aws_event_stream && !is_json_content_type(content_type) {
                unmetered_detail = "unsupported_content_type";
                return None;
            }

            // Inspect the DECODED representation. A provider (or an
            // intermediary) may ship a perfectly ordinary usage document under
            // `Content-Encoding: gzip`/`br`; parsing the wire bytes classified
            // it as unmetered, so the budget silently followed the heuristic
            // estimate and `on_unmetered_response: reject` refused a response
            // that had reported its usage. The original bytes are forwarded
            // untouched — this plaintext is a local, transient view whose whole
            // working set is reserved against the shared retained-response
            // budget BEFORE it is allocated, so the fix cannot become an
            // uncharged decompression path.
            let decoded = match self.decoded_inspection_body(response_headers, body) {
                Ok(decoded) => decoded,
                Err(detail) => {
                    unmetered_detail = detail;
                    return None;
                }
            };
            let inspected: &[u8] = &decoded;

            if is_sse {
                unmetered_detail = "sse_without_usage";
                return self.extract_token_count_from_sse(ctx, inspected);
            }

            if is_aws_event_stream {
                unmetered_detail = "event_stream_without_usage";
                let mut extractor = UsageStreamExtractor::new(
                    UsageStreamFormat::AwsEventStream,
                    self.configured_provider,
                );
                extractor.push(inspected);
                extractor.finish();
                return self.reconciliation_tokens(
                    ctx,
                    extractor.usage().total_for_mode(&self.count_mode),
                    extractor.usage().is_complete_for_mode(&self.count_mode),
                );
            }

            unmetered_detail = "json_without_usage";
            self.extract_token_count(ctx, inspected)
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
            self.apply_exposed_headers(ctx, response_headers);
        }
        result
    }
}

// ---------------------------------------------------------------------------
// Streaming response accounting
// ---------------------------------------------------------------------------

/// RAII slot in the process-wide [`MAX_CONCURRENT_STREAM_ACCOUNTING`] budget.
///
/// Acquisition is a bounded CAS loop, so a burst of concurrent streams can
/// never push the live parser count past the cap, and the slot is returned when
/// the inspector is dropped — including when the client disconnects mid-stream
/// and the stream task is torn down.
struct StreamAccountingPermit;

impl StreamAccountingPermit {
    fn acquire() -> Option<Self> {
        let mut current = ACTIVE_STREAM_ACCOUNTING.load(Ordering::Relaxed);
        loop {
            if current >= MAX_CONCURRENT_STREAM_ACCOUNTING {
                return None;
            }
            match ACTIVE_STREAM_ACCOUNTING.compare_exchange_weak(
                current,
                current + 1,
                Ordering::AcqRel,
                Ordering::Relaxed,
            ) {
                Ok(_) => return Some(Self),
                Err(observed) => current = observed,
            }
        }
    }

    /// Live inspector count. Test/diagnostic accessor.
    #[allow(dead_code)] // used only by tests/, dead code in the bin target
    fn active() -> usize {
        ACTIVE_STREAM_ACCOUNTING.load(Ordering::Relaxed)
    }
}

impl Drop for StreamAccountingPermit {
    fn drop(&mut self) {
        ACTIVE_STREAM_ACCOUNTING.fetch_sub(1, Ordering::AcqRel);
    }
}

/// Live inspector count backing the aggregate stream-accounting bound.
/// Test-only observability; not a production API.
#[doc(hidden)]
#[allow(dead_code)] // used only by tests/, dead code in the bin target
pub fn active_stream_accounting_for_test() -> usize {
    StreamAccountingPermit::active()
}

/// Process-wide ceiling on concurrent streaming token accounting. Test-only.
#[doc(hidden)]
#[allow(dead_code)] // used only by tests/, dead code in the bin target
pub fn max_concurrent_stream_accounting_for_test() -> usize {
    MAX_CONCURRENT_STREAM_ACCOUNTING
}

/// Pass-through stream inspector that extracts terminal provider usage.
///
/// Every chunk is forwarded byte-for-byte and immediately — the inspector never
/// holds a window, so SSE event latency and H1/H2/H3 backpressure are exactly
/// what they would be with no plugin attached. It also never terminates the
/// stream: response headers are already committed by the time a body flows, so
/// truncating would only corrupt a generation the client is already paying for.
struct UsageStreamInspector {
    extractor: UsageStreamExtractor,
    shared: Arc<StreamUsageHandoff>,
    _permit: StreamAccountingPermit,
}

impl UsageStreamInspector {
    fn publish(&mut self) {
        let usage = self.extractor.usage().clone();
        match self.shared.usage.lock() {
            Ok(mut slot) => *slot = usage,
            Err(poisoned) => *poisoned.into_inner() = usage,
        }
    }
}

#[async_trait]
impl ResponseStreamInspector for UsageStreamInspector {
    async fn on_chunk(&mut self, chunk: &[u8]) -> ResponseStreamAction {
        self.extractor.push(chunk);
        ResponseStreamAction::Forward(bytes::Bytes::copy_from_slice(chunk))
    }

    async fn on_end(&mut self) -> ResponseStreamAction {
        self.extractor.finish();
        self.publish();
        ResponseStreamAction::Forward(bytes::Bytes::new())
    }

    /// A later inspector cut the stream: the bytes this one already parsed are
    /// still the bytes the provider generated and billed, so the accumulated
    /// usage stays. Publish it now because `on_end` will not run. `finish`
    /// first, so a terminal usage event that arrived without its trailing blank
    /// line is still dispatched by the SSE event assembler; it is idempotent
    /// and only ever applies bytes already received.
    fn on_downstream_terminated(&mut self) {
        self.extractor.finish();
        self.publish();
    }

    /// Publish before the owning task wakes the terminal hooks, so a stream that
    /// ends by client disconnect (no `on_end`) still hands back whatever usage
    /// the provider had already reported.
    fn on_before_drop(&mut self) {
        self.extractor.finish();
        self.publish();
    }
}
