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
use super::utils::ai_stream_accounting::{StreamAccountingPermit, try_admit_stream_accounting};
use super::utils::ai_stream_usage::{
    StreamUsageFormat, StreamUsageScanner, is_aws_event_stream_content_type,
};
use super::utils::body_transform::{ascii_contains_ignore_case, is_json_content_type};
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
/// Status for a refused aggregate stream-accounting admission. `503` rather
/// than `429`: this is a gateway resource ceiling, not the caller's token
/// budget, and conflating the two would tell a client its budget was spent.
pub(crate) const STREAM_ACCOUNTING_CAPACITY_STATUS: u16 = 503;
/// Fixed refusal body for a saturated stream-accounting budget. Names no key,
/// identity, provider, backend, configured value, or response content.
pub(crate) const STREAM_ACCOUNTING_CAPACITY_BODY: &str = r#"{"error":"Service unavailable","details":"The gateway cannot admit another metered AI response stream right now"}"#;
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
///
/// Immutable once published: the inspector builds exactly one of these at
/// terminal/drop and hands it to the terminal hook through the request-scoped
/// [`ResponseStreamHandoff`]. Nothing mutable, and no scanner, crosses tasks.
#[derive(Debug, Clone, Default)]
struct StreamUsageResult {
    usage: Option<AiTokenUsage>,
    malformed: bool,
    /// The aggregate stream-accounting budget refused this stream, so no
    /// scanner was ever allocated. Distinguished from `malformed` so the
    /// settlement names a gateway capacity bound rather than provider damage.
    capacity_refused: bool,
}

/// What one `before_proxy` admission pass learned from the buffered inbound
/// request body.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
struct RequestEstimate {
    /// The body parsed as JSON and carries a recognized LLM request field.
    is_ai_request: bool,
    /// Tokens to pre-reserve. May be `0` for a genuine AI request (see the
    /// `count_mode` limitations documented in `before_proxy`).
    reserved_tokens: u64,
    /// The client asked the provider for an incrementally delivered response,
    /// so this instance expects to attach a bounded stream scanner and must
    /// reserve aggregate accounting state up front.
    declares_streaming: bool,
}

/// Whether a decoded AI request body asks the provider for a streamed response.
///
/// Every provider-native shape this limiter meters spells the request-side
/// choice the same way — a top-level boolean `stream` (OpenAI, Anthropic,
/// Mistral, Cohere, TGI, Bedrock `ConverseStream` request bodies proxied
/// verbatim). Gemini and Bedrock additionally select streaming through the URL
/// rather than the body; that is handled by
/// [`path_declares_streaming_response`].
///
/// Read as a *hint for reservation*, never as an accounting decision: a body
/// that omits it still gets a late, fail-closed admission attempt when the
/// backend turns out to stream anyway. Also read from
/// `on_final_request_body_with_context` for a body that was still compressed in
/// `before_proxy`, so the deferred path reserves before backend dispatch too.
fn json_declares_streaming_response(json: &Value) -> bool {
    json.get("stream").and_then(Value::as_bool).unwrap_or(false)
}

/// Whether the request target names a provider-native streaming operation.
///
/// Google Gemini streams through `:streamGenerateContent`; Bedrock streams
/// through `invoke-with-response-stream` and `converse-stream`. Neither carries
/// a body-level `stream` flag, so the path is the only pre-backend signal.
/// Matched case-insensitively on the canonical policy path.
///
/// This runs on the request hot path for every candidate AI request, so the
/// match is the shared allocation-free ASCII-insensitive substring scan rather
/// than a per-request lowercased copy of the path.
fn path_declares_streaming_response(path: &str) -> bool {
    const STREAMING_OPERATION_MARKERS: [&str; 3] = [
        "streamgeneratecontent",
        "invoke-with-response-stream",
        "converse-stream",
    ];
    STREAMING_OPERATION_MARKERS
        .iter()
        .any(|marker| ascii_contains_ignore_case(path, marker))
}

/// Which wire framing a request target predicts for its streamed response.
///
/// Only Bedrock's streaming operations emit `application/vnd.amazon.eventstream`
/// (the 256 KiB retention class); every other supported provider streams SSE
/// (64 KiB). Used solely to size the pre-backend reservation — the authoritative
/// format still comes from the response `Content-Type`.
///
/// Allocation-free for the same hot-path reason as
/// [`path_declares_streaming_response`].
fn predicted_stream_format(path: &str) -> StreamUsageFormat {
    const BEDROCK_STREAM_MARKERS: [&str; 2] = ["invoke-with-response-stream", "converse-stream"];
    if BEDROCK_STREAM_MARKERS
        .iter()
        .any(|marker| ascii_contains_ignore_case(path, marker))
    {
        StreamUsageFormat::AwsEventStream
    } else {
        StreamUsageFormat::Sse
    }
}

/// Which event-stream representation the client asked for in `Accept`, if any.
///
/// This is the only streaming signal available for a request body this instance
/// cannot inspect (a still-compressed body, Case B in `before_proxy`), so it is
/// checked alongside the body and path signals rather than instead of them.
///
/// Two distinct media types matter and they select **different retention
/// classes**, so the answer carries the format rather than a bare bool:
///
///  * the hyphenated `event-stream` family (`text/event-stream` and the
///    vendor-prefixed SSE types) — the 64 KiB SSE class; and
///  * the exact AWS media type `application/vnd.amazon.eventstream`, which has
///    no hyphen and therefore does not match the SSE classifier at all. Bedrock
///    clients that spell their streaming intent only in `Accept` were
///    previously invisible here, and a request that *was* detected some other
///    way would have pre-reserved the smaller SSE class.
///
/// Both are matched case-insensitively and tolerate `Accept` parameters
/// (`;q=…`), the AWS type through the shared delimiter-aware
/// [`is_aws_event_stream_content_type`] essence comparison rather than a
/// substring test.
fn accept_declares_event_stream(headers: &HashMap<String, String>) -> Option<StreamUsageFormat> {
    let accept = headers.get("accept")?;
    let mut declared = None;
    for entry in accept.split(',') {
        let entry = entry.trim();
        // The larger retention class wins outright: nothing later in the header
        // can make an AWS event-stream scanner fit in the SSE reservation.
        if is_aws_event_stream_content_type(entry) {
            return Some(StreamUsageFormat::AwsEventStream);
        }
        if super::utils::body_transform::is_event_stream_content_type(entry) {
            declared = Some(StreamUsageFormat::Sse);
        }
    }
    declared
}

/// The retention class a pre-backend admission must reserve.
///
/// The request target and `Accept` can each predict the wire framing and can
/// disagree. Reserve the larger class whenever either predicts the AWS framing:
/// under-reserving would only defer the shortfall to the late admission in
/// `response_stream_inspector`, where a refusal can no longer reject and the
/// stream degrades to the unmetered posture instead.
fn reserved_stream_format(
    path: &str,
    accept_format: Option<StreamUsageFormat>,
) -> StreamUsageFormat {
    if predicted_stream_format(path) == StreamUsageFormat::AwsEventStream
        || accept_format == Some(StreamUsageFormat::AwsEventStream)
    {
        StreamUsageFormat::AwsEventStream
    } else {
        StreamUsageFormat::Sse
    }
}

/// Per-response streaming usage inspector for one `ai_rate_limiter` instance.
///
/// Purely observational: every chunk is forwarded downstream unchanged and the
/// bytes are not retained. Only bounded terminal metadata is extracted.
///
/// ## Ownership: no lock on the chunk path
///
/// Exactly one task drives one response body — the detached H1/H2 channel-body
/// task, or the H3 send loop — and that task owns this inspector by value, so
/// the mutable scanner is owned *directly* rather than shared behind a
/// `Mutex`. A per-chunk lock acquisition on a streaming AI response is an
/// avoidable hot-path lock under the repository's hot-path invariants, and it
/// bought nothing: there was never a second observer of the scanner.
///
/// The terminal hook DOES run on another task and cannot borrow the inspector,
/// so exactly one immutable, bounded [`StreamUsageResult`] is published through
/// the request-scoped [`ResponseStreamHandoff`] at terminal/drop — before
/// `CompletionNotifyingInspector` signals completion, which is what makes the
/// publication visible to the waiter. Nothing mutable ever crosses the task
/// boundary.
struct AiRateLimitStreamInspector {
    /// Taken at terminal/drop so the reassembly window is freed as soon as the
    /// scan is final, and so a second `publish()` cannot re-scan.
    scanner: Option<StreamUsageScanner>,
    /// Aggregate accounting-state reservation covering this scanner. Held for
    /// the inspector's whole life so the budget is returned on clean EOF,
    /// streaming error, client disconnect, deadline, downstream termination,
    /// and task cancellation alike. `None` only on the refused path, where
    /// there is no scanner to cover.
    _permit: Option<Arc<StreamAccountingPermit<'static>>>,
    /// The aggregate budget refused this stream. The inspector stays attached as
    /// a pure passthrough so the terminal hook still learns why.
    capacity_refused: bool,
    handoff: Option<ResponseStreamHandoff>,
    handoff_id: u64,
    published: bool,
}

impl AiRateLimitStreamInspector {
    /// Finalize the scan and hand its immutable result to the terminal hook.
    ///
    /// Called from `on_end` (clean completion), `on_downstream_terminated` (a
    /// later inspector cut the stream), and `on_before_drop` (client
    /// disconnect, deadline, cancelled task), so a stream that dies mid-flight
    /// still publishes — with whatever it managed to observe, which the
    /// terminal hook then treats as incomplete and settles fail-closed.
    ///
    /// Idempotent. A scanner already taken by an earlier publish yields the
    /// fail-closed `malformed` result rather than a usage-free stream, so no
    /// ordering of the terminal callbacks can present an unfinished scan as a
    /// clean "the provider reported nothing".
    fn publish(&mut self) {
        if self.published {
            return;
        }
        self.published = true;
        let result = match self.scanner.take() {
            Some(mut scanner) => {
                scanner.finish();
                StreamUsageResult {
                    usage: scanner.authoritative_usage().cloned(),
                    malformed: scanner.malformed(),
                    capacity_refused: false,
                }
            }
            None => StreamUsageResult {
                usage: None,
                malformed: true,
                capacity_refused: self.capacity_refused,
            },
        };
        if let Some(handoff) = self.handoff.as_ref() {
            handoff.publish(self.handoff_id, Arc::new(result));
        }
    }
}

#[async_trait]
impl ResponseStreamInspector for AiRateLimitStreamInspector {
    async fn on_chunk(&mut self, chunk: &[u8]) -> ResponseStreamAction {
        // Directly owned `&mut` scanner: no lock, no shared cell, no contention.
        if let Some(scanner) = self.scanner.as_mut() {
            scanner.observe(chunk);
        }
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
    /// Process-unique key for this instance's request-scoped aggregate
    /// stream-accounting permit slot, so co-located limiter instances each hold
    /// (and release) their own reservation instead of aliasing one.
    stream_permit_slot_id: u64,
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
            stream_permit_slot_id: allocate_response_stream_handoff_id(),
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

    /// Request-scoped slot id this instance's aggregate stream-accounting
    /// permit is retained under.
    ///
    /// A plain accessor for an existing field, with no behavior of its own.
    /// Exposed so advisory coverage can read the permit back through
    /// [`RequestContext::plugin_request_state`] and assert *which* retention
    /// class a pre-backend admission actually reserved — the difference between
    /// the 64 KiB SSE class and the 256 KiB AWS event-stream class is not
    /// otherwise observable from outside the plugin.
    #[doc(hidden)]
    pub fn stream_permit_slot_id(&self) -> u64 {
        self.stream_permit_slot_id
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

    /// Whether THIS instance deferred classification of a compressed request
    /// body to its `on_final_request_body` pass. The deferral used to be a
    /// shared `ctx.metadata` marker; it is instance-scoped now
    /// (GHSA-wh4p-pmxm-3784), so co-located limiters each defer and classify
    /// independently. Not a production API.
    #[doc(hidden)]
    #[allow(dead_code)] // used only by external tests; dead in binary test target
    pub fn deferred_compressed_classification_for_test(&self, ctx: &RequestContext) -> bool {
        self.load_reservation(ctx).deferred_compressed_classification
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

    /// Refusal for "the process-wide incremental stream-accounting budget is
    /// fully committed".
    ///
    /// Issued from `before_proxy` only, i.e. **before the backend is dialed**.
    /// That placement is the whole point:
    ///
    /// * *Gateway-local* — no upstream was contacted, so no connection,
    ///   circuit-breaker sample, passive-health observation, or adaptive
    ///   concurrency measurement is produced for it. A saturated accounting
    ///   budget can never be mistaken for a sick backend.
    /// * *Redaction-safe* — a fixed body naming no key, identity, consumer,
    ///   provider, backend, budget value, or response byte. A caller learns only
    ///   that the gateway declined right now.
    /// * *Not retroactive* — once a stream's headers and bytes are on the wire a
    ///   rejection is impossible, which is exactly why admission cannot wait for
    ///   the response representation.
    fn reject_stream_accounting_capacity(&self) -> PluginResult {
        // Metric only, deliberately: this path is reachable by a remote client,
        // so a per-request warning would be log amplification.
        super::prometheus_metrics::global_registry().record_rate_limit_exceeded();
        PluginResult::Reject {
            status_code: STREAM_ACCOUNTING_CAPACITY_STATUS,
            body: STREAM_ACCOUNTING_CAPACITY_BODY.to_string(),
            headers: HashMap::new(),
        }
    }

    /// Reserve this request's aggregate stream-accounting state before the
    /// backend is contacted, or produce the fixed capacity rejection.
    ///
    /// Idempotent per instance: a permit this instance already retained for
    /// this request (a `before_proxy` admission that the deferred final-body
    /// pass then re-examines) is reused rather than charged twice. Reuse is
    /// keyed on `stream_permit_slot_id`, which is allocated per plugin
    /// instance, so a co-located sibling can never satisfy this instance's
    /// admission.
    ///
    /// **Both refusals fail closed.** The budget refusing is the obvious one.
    /// The typed-slot refusal matters just as much: `retain_plugin_request_state`
    /// returns `false` for a duplicate key or once the bounded 64-slot
    /// per-request ceiling is reached, and an unretained permit is released the
    /// moment this function returns. Treating that as success would let a
    /// client-declared AI stream reach the backend with no live reservation
    /// covering the scanner it is about to allocate — exactly the aggregate
    /// bound this admission exists to hold.
    fn admit_stream_accounting_state(
        &self,
        ctx: &mut RequestContext,
        format: StreamUsageFormat,
    ) -> Result<(), PluginResult> {
        if ctx
            .plugin_request_state::<StreamAccountingPermit<'static>>(self.stream_permit_slot_id)
            .is_some()
        {
            return Ok(());
        }
        let Some(permit) = try_admit_stream_accounting(format) else {
            return Err(self.reject_stream_accounting_capacity());
        };
        // Retained for the whole request, so the reservation is returned on
        // every terminal path — completion, rejection, error, disconnect, and
        // task cancellation — without any explicit release call.
        if !ctx.retain_plugin_request_state(self.stream_permit_slot_id, Arc::new(permit)) {
            // The slot refused the insertion, so the permit taken just above is
            // dropped here and its bytes are returned to the budget. The stream
            // must not proceed unadmitted.
            return Err(self.reject_stream_accounting_capacity());
        }
        Ok(())
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

    /// What one admission pass learned from the buffered inbound request body.
    ///
    /// Estimate the tokens to pre-reserve for this request and report whether it
    /// looked like an AI call at all. The returned `bool` is `true` only when the
    /// buffered `request_body` parsed as JSON **and** carries a recognized LLM
    /// request field (see [`json_looks_like_ai_request`]); a parseable but non-LLM
    /// JSON `POST` returns `false` so a shared proxy doesn't subject ordinary API
    /// traffic to the `on_unmetered_response` policy. The estimate itself may still
    /// be 0 for a genuine AI request (e.g. `completion_tokens` mode with no `max_*`
    /// cap), which is why callers must track the AI-request signal separately from
    /// `reserved_tokens > 0`. Parses the body exactly once.
    fn estimate_request_tokens(&self, ctx: &RequestContext) -> RequestEstimate {
        let Some(body) = ctx.metadata.get("request_body") else {
            return RequestEstimate::default();
        };
        let Ok(json) = serde_json::from_str::<Value>(body) else {
            return RequestEstimate::default();
        };
        // Gate the AI-request marker on LLM shape, not mere JSON parseability.
        // The classification is what decides whether this instance meters the
        // response at all, so without the gate a `reject`-mode limiter would 502
        // (and `charge_estimate` would bill) an ordinary non-LLM JSON `POST` that
        // happens to share the proxy. See `InstanceReservation::ai_request`.
        if !json_looks_like_ai_request(&json) {
            // A non-AI JSON body is out of scope entirely, including for stream
            // admission: this instance will never attach a scanner to it.
            return RequestEstimate::default();
        }

        RequestEstimate {
            is_ai_request: true,
            reserved_tokens: self.estimate_request_tokens_from_json(&json),
            declares_streaming: json_declares_streaming_response(&json),
        }
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

        // Aggregate admission, second and last chance. Preferred source is the
        // reservation `before_proxy` already took for this request; it is reused
        // as-is whenever it covers this format's retention class, so the common
        // path allocates no new budget here.
        //
        // A request that did not declare streaming (or whose body could not be
        // inspected) has no pre-admission, and a mispredicted SSE reservation
        // does not cover an AWS event-stream scanner. Both fall through to a
        // fresh admission attempt. Refusal here CANNOT reject: the response is
        // about to be written. It fails closed the only way still available —
        // no scanner is allocated, so the aggregate bound holds, and the
        // terminal hook settles the stream through the configured
        // `on_unmetered_response` posture with a `stream_accounting_capacity`
        // detail rather than charging zero.
        let held = ctx
            .plugin_request_state::<StreamAccountingPermit<'static>>(self.stream_permit_slot_id)
            .filter(|permit| permit.reserved_bytes() >= format.retained_state_bytes());
        let permit = match held {
            Some(permit) => Some(permit),
            None => try_admit_stream_accounting(format).map(Arc::new),
        };

        let fixed_provider = if self.provider == "auto" {
            None
        } else {
            parse_ai_provider(&self.provider)
        };
        // On refusal the inspector is still attached, but with no scanner and no
        // reservation: it forwards bytes untouched and exists only to publish an
        // explicit `capacity_refused` terminal result, so the settlement names
        // the real cause instead of degrading into "not meterable".
        let scanner = permit
            .is_some()
            .then(|| StreamUsageScanner::new(format, fixed_provider));
        Some(Box::new(AiRateLimitStreamInspector {
            capacity_refused: permit.is_none(),
            scanner,
            _permit: permit,
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
            .and_then(|handoff| handoff.take::<StreamUsageResult>(self.stream_handoff_id));

        // A stream that did not complete cleanly cannot present its absent usage
        // as "the provider reported nothing": the tail that would have carried
        // the terminal usage record may simply never have arrived. Treat it as
        // unmetered so the configured posture decides, rather than silently
        // charging nothing.
        let complete = outcome.body_completed && !outcome.client_disconnected;
        let (tokens, detail) = match result {
            None => (None, "stream_not_meterable"),
            // Checked before completeness: a refused aggregate admission is the
            // more specific cause, and the operator needs to see a gateway
            // capacity bound rather than an apparently damaged provider stream.
            Some(result) if result.capacity_refused => (None, "stream_accounting_capacity"),
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
        let estimate = if is_framed_grpc {
            // Framed gRPC-Web: out of scope for this JSON policy entirely.
            RequestEstimate::default()
        } else if still_compressed {
            // Case B: uninspectable compressed body — fail closed for POST JSON.
            // The body cannot be read, so streaming intent is taken from the
            // request target and `Accept` alone (see the admission block below).
            RequestEstimate {
                is_ai_request: is_post_json,
                ..RequestEstimate::default()
            }
        } else if defer_compressed_classification {
            // Case A: defer to `on_final_request_body` (decompressed body there).
            RequestEstimate::default()
        } else {
            // Case C: uncompressed — estimate over the buffered inbound body.
            self.estimate_request_tokens(ctx)
        };
        let RequestEstimate {
            is_ai_request,
            reserved_tokens,
            declares_streaming,
        } = estimate;
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
        // ── Aggregate stream-accounting admission (GHSA-q2r2-6r7h-f69x) ──
        //
        // A bounded per-stream scanner is not an aggregate bound: each live SSE
        // scanner may retain 64 KiB and each AWS event-stream scanner 256 KiB,
        // and nothing stops a client from opening many concurrent streams. The
        // process-wide byte budget in `ai_stream_accounting` is the aggregate
        // bound, and THIS is the only point in the lifecycle where exhausting it
        // can still produce a gateway-authored response: `before_proxy` runs
        // before the backend is dialed, so a refusal contacts no upstream, emits
        // no circuit-breaker/passive-health/adaptive-concurrency sample, and
        // commits no response bytes. Once the response is streaming, a rejection
        // is physically impossible — see `on_response_stream_terminated`.
        //
        // Reserved before the token reservation deliberately: a refusal here
        // must not strand a token reservation that only window/TTL expiry would
        // reclaim.
        //
        // Streaming intent is the client's own declaration, taken from whichever
        // signals are readable: the body's `stream` flag, a provider-native
        // streaming operation in the request target, and an event-stream
        // `Accept` (SSE or the AWS media type, which also selects the retention
        // class). A body this pass could not classify (Case A) is not exempt:
        // `on_final_request_body_with_context` repeats this admission over the
        // decoded body, and that hook still runs before the backend request is
        // sent. Only a request that declares nothing anywhere yet whose backend
        // streams anyway falls through to the late, fail-closed admission in
        // `response_stream_inspector`, which can only decline to meter, never
        // reject.
        let accept_format = accept_declares_event_stream(headers);
        let wants_streamed_response = is_ai_request
            && (declares_streaming
                || path_declares_streaming_response(&ctx.path)
                || accept_format.is_some());
        if wants_streamed_response && !ctx.metadata.contains_key("ai_federation_provider") {
            // The response representation is unknown here, so charge the larger
            // of the classes the request target and `Accept` predict. A
            // mispredicted (smaller) reservation is re-admitted for the real
            // format at inspector time rather than silently under-reserving.
            let predicted = reserved_stream_format(&ctx.path, accept_format);
            if let Err(rejection) = self.admit_stream_accounting_state(ctx, predicted) {
                return rejection;
            }
        }

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
        // `declares_streaming` is the decoded body's own top-level `stream`
        // flag. It is only knowable on the inspectable branch; the uninspectable
        // branch falls back to the request target and `Accept`, exactly as
        // `before_proxy` does for a still-compressed Case B body.
        let (is_ai_request, declares_streaming) = if has_non_identity_content_encoding(headers)
            || !is_json_content_type(content_type)
            || is_framed_grpc_content_type(content_type)
        {
            (true, false)
        } else {
            // The decompressed body is available now. Mark the request as an AI
            // call ONLY when it actually parses as one, so a non-AI JSON body on
            // a shared proxy is never subjected to the `on_unmetered_response`
            // policy (the false-positive the bare `before_proxy` header check
            // would cause).
            match serde_json::from_slice::<Value>(body).ok() {
                Some(json) if json_looks_like_ai_request(&json) => {
                    (true, json_declares_streaming_response(&json))
                }
                _ => (false, false),
            }
        };

        if is_ai_request {
            record.ai_request = true;
            // Tag it compressed so the default `charge_estimate` path rejects a
            // usage-less 2xx — there is no safe pre-request estimate for a
            // compressed body.
            record.compressed_ai_candidate = true;
            ctx.metadata
                .insert(AI_REQUEST_METADATA_KEY.to_string(), "true".to_string());
        }

        self.store_reservation(ctx, &record);

        // ── Deferred aggregate stream-accounting admission (GHSA-q2r2-6r7h-f69x) ──
        //
        // `before_proxy` deliberately could not classify this body, so it took
        // no reservation for it. This hook is the last point in the lifecycle
        // that still runs BEFORE the backend request is sent, so it is the last
        // point at which a saturated aggregate budget can still be answered with
        // a gateway-authored 503 instead of degrading a committed stream to the
        // unmetered posture. Without this, a client could evade the aggregate
        // bound simply by gzipping its request.
        //
        // Neutral for everything else: a body that did not parse as an AI
        // request, and an AI request that declares no streamed response, reserve
        // nothing and are returned unchanged.
        if is_ai_request && !ctx.metadata.contains_key("ai_federation_provider") {
            let accept_format = accept_declares_event_stream(headers);
            let wants_streamed_response = declares_streaming
                || path_declares_streaming_response(&ctx.path)
                || accept_format.is_some();
            if wants_streamed_response {
                let predicted = reserved_stream_format(&ctx.path, accept_format);
                // Reuses this instance's existing permit when `before_proxy`
                // already reserved one (a deferred body whose path or `Accept`
                // declared streaming up front), so the two admission points
                // never double-charge one request. RAII release is unchanged:
                // the permit lives in the request-scoped slot and is returned on
                // every terminal and cancellation path.
                if let Err(rejection) = self.admit_stream_accounting_state(ctx, predicted) {
                    return rejection;
                }
            }
        }

        PluginResult::Continue
    }

    fn enforces_finalized_request_policy(&self) -> bool {
        // The deferred stream-accounting admission above can reject the
        // backend-visible request from `on_final_request_body_with_context`, so
        // this instance is a final request-body policy plugin for the
        // early-egress composition gate: a plugin that egresses the request body
        // before finalization would make that rejection unable to retract a
        // disclosure it had already sent.
        true
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
