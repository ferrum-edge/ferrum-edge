//! AI transcript audit — controlled AI payload capture for compliance.
//!
//! Captures AI request/response payloads (after redaction), keyed HMAC-SHA256
//! body hashes, model/provider, token metadata, guardrail decisions, tool
//! names, and cache metadata, then exports them asynchronously to an HTTP
//! collector in batches
//! via the shared [`BatchingLogger`]/[`PluginHttpClient`] framework. The proxy
//! hot path only enqueues records non-blockingly; a background task drains the
//! queue. Unless the operator opts into a fail-closed policy (`on_buffer_full`
//! /`on_sink_error` = `reject`) the plugin never blocks or rejects traffic.
//!
//! Runs at priority `AI_TRANSCRIPT_AUDIT` (2740): after authentication and
//! authorization, but before `request_deduplication` (2750) and reject-capable
//! AI guardrails, so cached replays and blocked prompts can still be audited.
//! It also remains before `ai_semantic_cache` (2980) / `ai_federation` (4060).
//! The audit candidate is staged in `before_proxy` over the
//! prebuffered request body (so terminate-and-respond plugins downstream cannot
//! consume the transaction unaudited, and so the proxy's response buffering /
//! dispatch decisions can see the candidate state), then refreshed with the
//! final backend-visible body in `on_final_request_body_with_context` after
//! request redaction/transforms ran.
//!
//! This plugin is **not** a security boundary on its own — it observes and
//! redacts, it does not enforce. Pair it with `ai_prompt_shield`,
//! `ai_semantic_firewall`, `ai_response_guard`, and the tool governance in
//! `ai_semantic_firewall` for enforcement.

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::net::IpAddr;
use std::sync::Arc;
use std::sync::Mutex;
use std::sync::OnceLock;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::{Duration, Instant};

use async_trait::async_trait;
use bytes::Bytes;
use dashmap::DashMap;
use http::header::{HeaderName, HeaderValue};
use serde::Serialize;
use serde_json::Value;
use sha2::{Digest, Sha256};
use tokio::sync::{OwnedSemaphorePermit, Semaphore};
use tracing::warn;

use super::utils::ai_pii::{KeyedBodyHasher, PiiRedactor};
use super::utils::body_transform::is_json_content_type;
use super::utils::byte_budget::{
    BoundedJsonWriter, ByteBudget, ByteLease, HARD_MAX_ENTRY_BYTES, accounted_summary_bytes,
    admit_byte_limits,
};
use super::utils::metadata_redaction::{REDACTED_PLACEHOLDER, is_sensitive_metadata_key};
use super::utils::{
    BatchConfig, BatchConfigDefaults, BatchingLoggerPermit, DeferredBatchingLogger,
    HttpBatchDrainOutcome, LoggerHooks, PluginHttpClient, build_batch_config,
    drain_http_batch_response_body, parse_http_endpoint, validate_batch_config,
};
use super::{
    HTTP_ONLY_PROTOCOLS, Plugin, PluginResult, ProxyProtocol, RequestContext, ResponseStreamAction,
    ResponseStreamInspector, TransactionSummary,
};
use crate::proxy::{
    REJECTION_RESPONSE_METADATA_KEY, REPLACEABLE_REJECTION_RESPONSE_METADATA_KEY,
    SYNTHETIC_SHORT_CIRCUIT_METADATA_KEY,
};
use crate::util::unknown_keys::reject_unknown_keys;

/// Schema version stamped onto every emitted record.
const RECORD_VERSION: u32 = 1;

const ERROR_PREFIX: &str = "ai_transcript_audit: ";

/// Accepted root keys for `ai_transcript_audit` config objects.
pub const AI_TRANSCRIPT_AUDIT_CONFIG_KEYS: &[&str] = &[
    "mode",
    "allow_full_body",
    "capture",
    "sampling",
    "redaction",
    "limits",
    "privacy",
    "sink",
];

/// Accepted keys under `capture`.
pub const AI_TRANSCRIPT_AUDIT_CAPTURE_KEYS: &[&str] = &[
    "request",
    "response",
    "streaming_response",
    "headers",
    "tool_calls",
];

/// Accepted keys under `sampling`.
pub const AI_TRANSCRIPT_AUDIT_SAMPLING_KEYS: &[&str] = &[
    "rate",
    "always_capture_on_guardrail",
    "always_capture_on_error",
    "max_records_per_minute",
];

/// Accepted keys under `redaction`.
pub const AI_TRANSCRIPT_AUDIT_REDACTION_KEYS: &[&str] = &[
    "builtins",
    "custom_patterns",
    "placeholder",
    "hash_redacted_values",
    "hash_secret",
];

/// Accepted keys under each `redaction.custom_patterns[]` object.
pub const AI_TRANSCRIPT_AUDIT_CUSTOM_PATTERN_KEYS: &[&str] = &["name", "regex"];

/// Accepted keys under `limits`.
pub const AI_TRANSCRIPT_AUDIT_LIMITS_KEYS: &[&str] = &[
    "max_request_bytes",
    "max_response_bytes",
    "max_stream_capture_bytes",
    "max_model_chars",
    "max_tool_count",
    "max_tool_name_chars",
    "max_tool_names_bytes",
    "hash_full_stream",
    "max_staging_reservation_secs",
];

/// Hard maximum for each capture excerpt / stream buffer limit (1 MiB).
pub const HARD_MAX_CAPTURE_BYTES: usize = HARD_MAX_ENTRY_BYTES;
/// Hard maximum for the sum of the three capture byte limits.
pub const HARD_MAX_CAPTURE_AGGREGATE_BYTES: usize = HARD_MAX_CAPTURE_BYTES.saturating_mul(2);
/// Default / hard maximum model string length retained in staging and records.
pub const HARD_MAX_MODEL_CHARS: usize = 256;
/// Default / hard maximum number of tool names retained per record.
pub const HARD_MAX_TOOL_COUNT: usize = 128;
/// Default / hard maximum length of one tool name.
pub const HARD_MAX_TOOL_NAME_CHARS: usize = 256;
/// Default / hard maximum aggregate UTF-8 bytes across retained tool names.
pub const HARD_MAX_TOOL_NAMES_BYTES: usize = 8_192;
/// Default / hard maximum age for staging entries, including active streams with
/// reserved commit permits.
pub const HARD_MAX_STAGING_RESERVATION_SECS: u64 = 60 * 60;
/// Domain separator mixed into capped stream HMACs so partial digests cannot be
/// confused with full-stream digests.
const PARTIAL_STREAM_HASH_DOMAIN: &[u8] = b"\0ferrum.ai_transcript_audit.partial_stream_hash/v1\0";
/// Env-var prefixes permitted inside `sink.custom_headers` `${NAME}` references.
const AUDIT_SECRET_ENV_PREFIXES: &[&str] = &["AUDIT_", "FERRUM_AUDIT_"];

/// Accepted keys under `privacy`.
pub const AI_TRANSCRIPT_AUDIT_PRIVACY_KEYS: &[&str] = &[
    "include_consumer_username",
    "include_client_ip",
    "include_raw_headers",
];

/// Accepted keys under `sink`. `custom_headers` remains an intentional free-form
/// string map; every other sink property is fixed-shape.
pub const AI_TRANSCRIPT_AUDIT_SINK_KEYS: &[&str] = &[
    "type",
    "endpoint_url",
    "allow_insecure_loopback",
    "custom_headers",
    "batch_size",
    "flush_interval_ms",
    "buffer_capacity",
    "max_entry_bytes",
    "buffer_max_bytes",
    "max_retries",
    "retry_delay_ms",
    "on_buffer_full",
    "on_sink_error",
];

/// Above this many staged entries, opportunistically drop expired orphans (a
/// request that never reached the `log` hook). The common path removes staging
/// at emit/log time, so this only guards pathological cases.
const STAGING_SWEEP_THRESHOLD: usize = 512;
/// Hard bound for in-flight request excerpts and permits. At the default
/// fail-open policy, excess candidates are omitted; fail-closed policies reject
/// instead of forwarding a transaction that cannot be staged.
const MAX_STAGING_ENTRIES: usize = 4096;
/// Amortize orphan cleanup so request admission never repeats a full shared-map
/// scan for every request while the live set remains above the threshold.
const STAGING_SWEEP_INTERVAL_SECS: u64 = 60;

// Metadata keys written into `ctx.metadata` (small strings only — never bodies).
// These flow into the transaction log via the summary metadata.
const MD_RECORD_ID: &str = "ai_transcript_audit.record_id";
const MD_CANDIDATE: &str = "ai_transcript_audit.candidate";
const MD_SAMPLED: &str = "ai_transcript_audit.sampled";
const MD_SAMPLE_HIT: &str = "ai_transcript_audit.sample_hit";
const MD_REQUEST_HASH: &str = "ai_transcript_audit.request_hash";
const MD_RESPONSE_HASH: &str = "ai_transcript_audit.response_hash";
const MD_SINK_STATUS: &str = "ai_transcript_audit.sink_status";
/// Set when the request body carries `stream: true` (an SSE response is
/// expected), so the response buffer decision does not stall the stream.
const MD_STREAM_REQUEST: &str = "ai_transcript_audit.stream_request";
/// Set once the final-request-body hook captured the backend-visible request, so
/// the reject-path `after_proxy` refresh only runs for `before_proxy`
/// short-circuits (where that hook never fired).
const MD_FINAL_REQ_SEEN: &str = "ai_transcript_audit.final_req_seen";

/// What to capture and export.
#[derive(Clone, Copy, PartialEq, Eq)]
enum AuditMode {
    MetadataOnly,
    RedactedBody,
    FullBody,
    HashOnly,
}

impl AuditMode {
    fn as_str(self) -> &'static str {
        match self {
            AuditMode::MetadataOnly => "metadata_only",
            AuditMode::RedactedBody => "redacted_body",
            AuditMode::FullBody => "full_body",
            AuditMode::HashOnly => "hash_only",
        }
    }

    /// Modes that emit a (capped) body excerpt.
    fn captures_body(self) -> bool {
        matches!(self, AuditMode::RedactedBody | AuditMode::FullBody)
    }

    /// Only `redacted_body` runs the PII redactor over the captured body.
    fn redacts_body(self) -> bool {
        matches!(self, AuditMode::RedactedBody)
    }

    /// `hash_only` reduces the record to hashes + envelope: no model/provider,
    /// token, cache, guardrail, tool, or header metadata.
    fn harvests_metadata(self) -> bool {
        !matches!(self, AuditMode::HashOnly)
    }
}

/// Streaming (SSE) response capture policy.
#[derive(Clone, Copy, PartialEq, Eq)]
enum StreamingCapture {
    Off,
    On,
    Sampled,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum BufferFullPolicy {
    Drop,
    Reject,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum SinkErrorPolicy {
    Warn,
    Reject,
}

#[derive(Clone, Copy)]
struct CaptureConfig {
    request: bool,
    response: bool,
    streaming: StreamingCapture,
    headers: bool,
    tool_calls: bool,
}

#[derive(Clone, Copy)]
struct SamplingConfig {
    rate: f64,
    always_on_guardrail: bool,
    always_on_error: bool,
    max_records_per_minute: u64,
}

#[derive(Clone, Copy)]
struct LimitsConfig {
    max_request_bytes: usize,
    max_response_bytes: usize,
    max_stream_capture_bytes: usize,
    max_model_chars: usize,
    max_tool_count: usize,
    max_tool_name_chars: usize,
    max_tool_names_bytes: usize,
    hash_full_stream: bool,
    max_staging_reservation_secs: u64,
}

/// Effective capture / metadata / reservation limits after admission.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AdmittedCaptureLimits {
    pub max_request_bytes: usize,
    pub max_response_bytes: usize,
    pub max_stream_capture_bytes: usize,
    pub max_model_chars: usize,
    pub max_tool_count: usize,
    pub max_tool_name_chars: usize,
    pub max_tool_names_bytes: usize,
    pub hash_full_stream: bool,
    pub max_staging_reservation_secs: u64,
    pub max_entry_bytes: usize,
    pub buffer_max_bytes: usize,
}

#[derive(Clone, Copy)]
struct PrivacyConfig {
    include_consumer_username: bool,
    include_client_ip: bool,
    include_raw_headers: bool,
}

/// Per-request request-side capture, keyed by `record_id`. Never holds a full
/// body — only the redacted/capped excerpt (bounded by `max_request_bytes`).
struct AuditStaging {
    /// Holds one slot in the hard in-flight staging bound.
    _staging_permit: OwnedSemaphorePermit,
    captured_at: Instant,
    sample_hit: bool,
    request_excerpt: Option<String>,
    request_truncated: bool,
    request_hash: Option<String>,
    /// Unkeyed SHA-256 of the staged request bytes. Used only to detect
    /// transforms before recomputing the exported keyed HMAC; never exported.
    request_content_digest: [u8; 32],
    request_model: Option<String>,
    model_truncated: bool,
    tool_names: Vec<String>,
    tool_names_truncated: bool,
    commit_permit: Option<BatchingLoggerPermit<QueuedAuditRecord>>,
    /// True only after the response path confirms that this transaction is
    /// actively streaming. A pre-commit reservation alone is not sufficient:
    /// requests abandoned before stream selection must remain TTL-collectable.
    /// Active streams still age out at `max_staging_reservation_secs`.
    stream_active: bool,
}

/// Response bytes captured by the streaming inspector, handed to
/// `on_response_stream_terminated` for record assembly (which has `ctx` and so
/// can harvest response-side guardrail metadata).
struct StreamCaptured {
    response_excerpt: Option<String>,
    response_truncated: bool,
    response_hash: String,
    response_hash_complete: bool,
    response_hashed_bytes: u64,
}

struct StreamSlot {
    /// `Some` once the inspector's `on_end` ran (normal completion). Stays
    /// `None` on abnormal termination, which the terminated hook treats as a
    /// truncated, body-omitted capture.
    captured: Mutex<Option<StreamCaptured>>,
    /// Set when a later stream inspector *cuts* the stream (`Terminate`) after
    /// this inspector already accumulated backend bytes. A downstream cut means
    /// the client received a truncated/blocked stream, so the prefix we captured
    /// was never fully delivered — the terminated hook omits the body/hash and
    /// treats the cut as a guardrail signal. A downstream inspector that merely
    /// *reformats* chunks without cutting is deliberately NOT flagged: this
    /// plugin captures the backend/provider-emitted transcript (the ground truth
    /// of what the model returned), not a gateway's post-transform rewrite, so a
    /// complete provider stream stays a valid record even when a downstream
    /// normalizer (e.g. `ai_stream_router`) rewrites the client-visible bytes.
    downstream_terminated: AtomicBool,
}

/// A single exported audit record.
#[derive(Clone, Serialize)]
struct AuditRecord {
    version: u32,
    record_id: String,
    timestamp: String,
    namespace: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    proxy_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    proxy_name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    consumer_username: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    client_ip: Option<String>,
    method: String,
    path: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    model: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    provider: Option<String>,
    status_code: u16,
    mode: &'static str,
    sampled: bool,
    capture_reason: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    request_hash: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    response_hash: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    response_hash_complete: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    response_hashed_bytes: Option<u64>,
    request_body_truncated: bool,
    response_body_truncated: bool,
    model_truncated: bool,
    tool_names_truncated: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    request_body: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    response_body: Option<String>,
    #[serde(skip_serializing_if = "BTreeMap::is_empty")]
    tokens: BTreeMap<String, String>,
    #[serde(skip_serializing_if = "BTreeMap::is_empty")]
    cache: BTreeMap<String, String>,
    #[serde(skip_serializing_if = "BTreeMap::is_empty")]
    guardrails: BTreeMap<String, String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    tool_names: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    headers: Option<BTreeMap<String, String>>,
}

/// Pre-serialized audit record retained in the batching queue under a byte lease.
#[derive(Clone)]
struct QueuedAuditRecord {
    json: Arc<str>,
    _lease: Arc<ByteLease>,
}

/// Owned request/response envelope fields, sourced from either a live
/// `RequestContext` or a `TransactionSummary`.
struct EnvelopeOwned {
    proxy_id: Option<String>,
    proxy_name: Option<String>,
    namespace: String,
    consumer_username: Option<String>,
    client_ip: Option<String>,
    method: String,
    path: String,
    status_code: u16,
}

#[derive(Default)]
struct Harvest {
    model: Option<String>,
    provider: Option<String>,
    tokens: BTreeMap<String, String>,
    cache: BTreeMap<String, String>,
    guardrails: BTreeMap<String, String>,
}

enum SinkOutcome {
    Queued,
    Dropped,
    Rejected,
}

/// Fixed-window records-per-minute limiter. `max == 0` means unlimited.
struct RecordsPerMinute {
    max_per_minute: u64,
    window: Mutex<(Instant, u64)>,
}

impl RecordsPerMinute {
    fn new(max_per_minute: u64) -> Self {
        Self {
            max_per_minute,
            window: Mutex::new((Instant::now(), 0)),
        }
    }

    fn try_acquire(&self) -> bool {
        if self.max_per_minute == 0 {
            return true;
        }
        let mut guard = match self.window.lock() {
            Ok(guard) => guard,
            Err(poisoned) => poisoned.into_inner(),
        };
        let now = Instant::now();
        if now.duration_since(guard.0) >= Duration::from_secs(60) {
            guard.0 = now;
            guard.1 = 0;
        }
        if guard.1 >= self.max_per_minute {
            return false;
        }
        guard.1 += 1;
        true
    }
}

#[derive(Clone)]
struct HttpFlushConfig {
    endpoint_url: String,
    /// Header name + value. `${AUDIT_*}` / `${FERRUM_AUDIT_*}` references are
    /// validated (allowlisted and present) at construction; values are expanded
    /// again at send time from that same allowlist only.
    custom_headers: Vec<(HeaderName, String)>,
    http_client: PluginHttpClient,
    sink_healthy: Arc<AtomicBool>,
}

pub struct AiTranscriptAudit {
    mode: AuditMode,
    capture: CaptureConfig,
    sampling: SamplingConfig,
    limits: LimitsConfig,
    privacy: PrivacyConfig,
    on_buffer_full: BufferFullPolicy,
    on_sink_error: SinkErrorPolicy,
    redactor: Arc<PiiRedactor>,
    batch_config: BatchConfig,
    flush_config: HttpFlushConfig,
    logger: DeferredBatchingLogger<QueuedAuditRecord>,
    byte_budget: Arc<ByteBudget>,
    max_entry_bytes: usize,
    endpoint_hostname: String,
    namespace: String,
    staging: Arc<DashMap<String, AuditStaging>>,
    staging_permits: Arc<Semaphore>,
    pending_streams: Arc<DashMap<String, Arc<StreamSlot>>>,
    rate_limiter: Arc<RecordsPerMinute>,
    sink_healthy: Arc<AtomicBool>,
    /// `true` when at least one capture path is enabled (validated in `new`).
    active: bool,
    staging_ttl: Duration,
    /// Monotonic process-relative second at which another staging sweep may run.
    next_staging_sweep_at: AtomicU64,
    /// Test-only counter of keyed HMAC body hashes computed on the request path.
    keyed_request_hash_calls: AtomicU64,
}

impl AiTranscriptAudit {
    pub fn new(config: &Value, http_client: PluginHttpClient) -> Result<Self, String> {
        let Some(config_obj) = config.as_object() else {
            return Err("ai_transcript_audit: config must be an object".to_string());
        };
        reject_unknown_keys(
            config_obj,
            "config",
            AI_TRANSCRIPT_AUDIT_CONFIG_KEYS,
            ERROR_PREFIX,
        )?;
        let empty = Value::Object(serde_json::Map::new());

        // ---- mode + full-body guardrail ----
        let mode = match cfg_str(config, "mode", "config")?.unwrap_or("redacted_body") {
            "metadata_only" => AuditMode::MetadataOnly,
            "redacted_body" => AuditMode::RedactedBody,
            "full_body" => AuditMode::FullBody,
            "hash_only" => AuditMode::HashOnly,
            other => {
                return Err(format!(
                    "ai_transcript_audit: 'mode' must be one of metadata_only, redacted_body, \
                     full_body, hash_only (got {other:?})"
                ));
            }
        };
        let allow_full_body = cfg_bool(config, "allow_full_body", false, "config")?;
        if mode == AuditMode::FullBody && !allow_full_body {
            return Err(
                "ai_transcript_audit: mode 'full_body' captures unredacted payloads and \
                 requires 'allow_full_body: true' to prevent accidental rollout"
                    .to_string(),
            );
        }

        // ---- capture ----
        reject_nested_unknown_keys(
            config,
            "capture",
            "config.capture",
            AI_TRANSCRIPT_AUDIT_CAPTURE_KEYS,
        )?;
        let capture_obj = cfg_object(config, "capture", "capture")?.unwrap_or(&empty);
        let streaming = cfg_streaming(capture_obj, "streaming_response")?;
        let capture = CaptureConfig {
            request: cfg_bool(capture_obj, "request", true, "capture")?,
            response: cfg_bool(capture_obj, "response", true, "capture")?,
            streaming,
            headers: cfg_bool(capture_obj, "headers", false, "capture")?,
            tool_calls: cfg_bool(capture_obj, "tool_calls", true, "capture")?,
        };
        if !capture.request && !capture.response && streaming == StreamingCapture::Off {
            return Err(
                "ai_transcript_audit: at least one of capture.request, capture.response, \
                 or capture.streaming_response must be enabled"
                    .to_string(),
            );
        }

        // ---- sampling ----
        reject_nested_unknown_keys(
            config,
            "sampling",
            "config.sampling",
            AI_TRANSCRIPT_AUDIT_SAMPLING_KEYS,
        )?;
        let sampling_obj = cfg_object(config, "sampling", "sampling")?.unwrap_or(&empty);
        let rate = cfg_f64(sampling_obj, "rate", 1.0, "sampling")?;
        if !(0.0..=1.0).contains(&rate) {
            return Err(
                "ai_transcript_audit: 'sampling.rate' must be between 0.0 and 1.0".to_string(),
            );
        }
        let sampling = SamplingConfig {
            rate,
            always_on_guardrail: cfg_bool(
                sampling_obj,
                "always_capture_on_guardrail",
                true,
                "sampling",
            )?,
            always_on_error: cfg_bool(sampling_obj, "always_capture_on_error", true, "sampling")?,
            max_records_per_minute: cfg_u64(sampling_obj, "max_records_per_minute", 0, "sampling")?,
        };

        // ---- redaction ----
        reject_nested_unknown_keys(
            config,
            "redaction",
            "config.redaction",
            AI_TRANSCRIPT_AUDIT_REDACTION_KEYS,
        )?;
        let redaction_obj = cfg_object(config, "redaction", "redaction")?.unwrap_or(&empty);
        let builtins = cfg_string_array(redaction_obj, "builtins", "redaction")?
            .unwrap_or_else(default_builtins);
        let custom = parse_custom_patterns(redaction_obj)?;
        if matches!(mode, AuditMode::RedactedBody | AuditMode::MetadataOnly)
            && builtins.is_empty()
            && custom.is_empty()
        {
            // An explicitly emptied pattern set would make the redactor a
            // silent pass-through while the records still claim redaction —
            // unredacted capture must go through the `full_body` opt-in. This
            // covers every mode that exports request-derived strings through
            // the redactor: `redacted_body` (body excerpts + `model`/
            // `tool_names`) and `metadata_only` (`model`/`tool_names`).
            // `hash_only` exports no request-derived strings (envelope +
            // keyed hashes only), so it is exempt.
            return Err(format!(
                "ai_transcript_audit: mode '{}' with 'redaction.builtins: []' and no \
                 'redaction.custom_patterns' would export unredacted request-derived data; \
                 configure at least one pattern, or use mode 'full_body' with \
                 'allow_full_body: true' for deliberate raw capture",
                mode.as_str()
            ));
        }
        let placeholder =
            cfg_str(redaction_obj, "placeholder", "redaction")?.unwrap_or("[REDACTED:{type}]");
        let hash_redacted = cfg_bool(redaction_obj, "hash_redacted_values", true, "redaction")?;
        let hash_secret = cfg_str(redaction_obj, "hash_secret", "redaction")?;
        if let Some(secret) = hash_secret
            && secret.len() < 16
        {
            return Err(
                "ai_transcript_audit: 'redaction.hash_secret' must be at least 16 characters"
                    .to_string(),
            );
        }
        let redactor = PiiRedactor::from_config(
            &builtins,
            &custom,
            placeholder,
            hash_redacted,
            hash_secret,
            "ai_transcript_audit",
        )?;

        // ---- limits ----
        reject_nested_unknown_keys(
            config,
            "limits",
            "config.limits",
            AI_TRANSCRIPT_AUDIT_LIMITS_KEYS,
        )?;
        let limits_obj = cfg_object(config, "limits", "limits")?.unwrap_or(&empty);
        let max_request_bytes = cfg_bounded_usize(
            limits_obj,
            "max_request_bytes",
            65536,
            1,
            HARD_MAX_CAPTURE_BYTES,
            "limits",
        )?;
        let max_response_bytes = cfg_bounded_usize(
            limits_obj,
            "max_response_bytes",
            65536,
            1,
            HARD_MAX_CAPTURE_BYTES,
            "limits",
        )?;
        let max_stream_capture_bytes = cfg_bounded_usize(
            limits_obj,
            "max_stream_capture_bytes",
            65536,
            1,
            HARD_MAX_CAPTURE_BYTES,
            "limits",
        )?;
        let capture_aggregate = max_request_bytes
            .saturating_add(max_response_bytes)
            .saturating_add(max_stream_capture_bytes);
        if capture_aggregate > HARD_MAX_CAPTURE_AGGREGATE_BYTES {
            return Err(format!(
                "ai_transcript_audit: sum of limits.max_request_bytes, \
                 limits.max_response_bytes, and limits.max_stream_capture_bytes \
                 must be <= {HARD_MAX_CAPTURE_AGGREGATE_BYTES}"
            ));
        }
        let limits = LimitsConfig {
            max_request_bytes,
            max_response_bytes,
            max_stream_capture_bytes,
            max_model_chars: cfg_bounded_usize(
                limits_obj,
                "max_model_chars",
                HARD_MAX_MODEL_CHARS,
                1,
                HARD_MAX_MODEL_CHARS,
                "limits",
            )?,
            max_tool_count: cfg_bounded_usize(
                limits_obj,
                "max_tool_count",
                HARD_MAX_TOOL_COUNT,
                1,
                HARD_MAX_TOOL_COUNT,
                "limits",
            )?,
            max_tool_name_chars: cfg_bounded_usize(
                limits_obj,
                "max_tool_name_chars",
                HARD_MAX_TOOL_NAME_CHARS,
                1,
                HARD_MAX_TOOL_NAME_CHARS,
                "limits",
            )?,
            max_tool_names_bytes: cfg_bounded_usize(
                limits_obj,
                "max_tool_names_bytes",
                HARD_MAX_TOOL_NAMES_BYTES,
                1,
                HARD_MAX_TOOL_NAMES_BYTES,
                "limits",
            )?,
            hash_full_stream: cfg_bool(limits_obj, "hash_full_stream", false, "limits")?,
            max_staging_reservation_secs: cfg_bounded_u64(
                limits_obj,
                "max_staging_reservation_secs",
                HARD_MAX_STAGING_RESERVATION_SECS,
                1,
                HARD_MAX_STAGING_RESERVATION_SECS,
                "limits",
            )?,
        };

        // ---- privacy ----
        reject_nested_unknown_keys(
            config,
            "privacy",
            "config.privacy",
            AI_TRANSCRIPT_AUDIT_PRIVACY_KEYS,
        )?;
        let privacy_obj = cfg_object(config, "privacy", "privacy")?.unwrap_or(&empty);
        let privacy = PrivacyConfig {
            include_consumer_username: cfg_bool(
                privacy_obj,
                "include_consumer_username",
                true,
                "privacy",
            )?,
            include_client_ip: cfg_bool(privacy_obj, "include_client_ip", false, "privacy")?,
            include_raw_headers: cfg_bool(privacy_obj, "include_raw_headers", false, "privacy")?,
        };

        // ---- sink ----
        reject_nested_unknown_keys(config, "sink", "config.sink", AI_TRANSCRIPT_AUDIT_SINK_KEYS)?;
        let sink_obj = cfg_object(config, "sink", "sink")?
            .ok_or("ai_transcript_audit: 'sink' configuration is required")?;
        if let Some(sink_type) = cfg_str(sink_obj, "type", "sink")?
            && sink_type != "http"
        {
            return Err(format!(
                "ai_transcript_audit: only sink.type 'http' is supported in this version \
                 (got {sink_type:?})"
            ));
        }
        let (endpoint_url, endpoint_hostname) = parse_http_endpoint(
            sink_obj,
            "ai_transcript_audit",
            http_client.backend_allow_ips(),
        )?;
        let allow_insecure_loopback = cfg_bool(sink_obj, "allow_insecure_loopback", false, "sink")?;
        if endpoint_url
            .get(..7)
            .is_some_and(|prefix| prefix.eq_ignore_ascii_case("http://"))
        {
            if !allow_insecure_loopback {
                return Err("ai_transcript_audit: sink.endpoint_url must use https://; \
                     local cleartext collectors require sink.allow_insecure_loopback: true"
                    .to_string());
            }
            let loopback = endpoint_hostname.eq_ignore_ascii_case("localhost")
                || endpoint_hostname
                    .parse::<IpAddr>()
                    .is_ok_and(|address| address.is_loopback());
            if !loopback {
                return Err(
                    "ai_transcript_audit: sink.allow_insecure_loopback permits http:// only \
                     for localhost or a loopback IP address"
                        .to_string(),
                );
            }
        }
        let custom_headers = parse_sink_headers(sink_obj)?;
        let byte_limits = admit_byte_limits(sink_obj, "ai_transcript_audit")?;
        let batch_defaults = BatchConfigDefaults {
            batch_size_key: "batch_size",
            batch_size: 50,
            flush_interval_ms: 1000,
            min_flush_interval_ms: 100,
            buffer_capacity: 10000,
            max_retries: 3,
            retry_delay_ms: 1000,
            min_retry_delay_ms: 0,
        };
        validate_batch_config(sink_obj, "ai_transcript_audit", batch_defaults)?;
        let on_buffer_full = match cfg_str(sink_obj, "on_buffer_full", "sink")?.unwrap_or("drop") {
            "drop" => BufferFullPolicy::Drop,
            "reject" => BufferFullPolicy::Reject,
            other => {
                return Err(format!(
                    "ai_transcript_audit: 'sink.on_buffer_full' must be 'drop' or 'reject' \
                     (got {other:?})"
                ));
            }
        };
        let on_sink_error = match cfg_str(sink_obj, "on_sink_error", "sink")?.unwrap_or("warn") {
            "warn" => SinkErrorPolicy::Warn,
            "reject" => SinkErrorPolicy::Reject,
            other => {
                return Err(format!(
                    "ai_transcript_audit: 'sink.on_sink_error' must be 'warn' or 'reject' \
                     (got {other:?})"
                ));
            }
        };

        // ---- deferred background worker ----
        let shard_amount = http_client.pool_shard_amount();
        let sink_healthy = Arc::new(AtomicBool::new(true));
        let flush_config = HttpFlushConfig {
            endpoint_url,
            custom_headers,
            http_client,
            sink_healthy: Arc::clone(&sink_healthy),
        };
        let batch_config = build_batch_config(sink_obj, "ai_transcript_audit", batch_defaults)?;
        let byte_budget = Arc::new(ByteBudget::new(
            "ai_transcript_audit",
            byte_limits.buffer_max_bytes,
        ));

        let active = capture.request || capture.response || streaming != StreamingCapture::Off;
        let namespace = std::env::var("FERRUM_NAMESPACE")
            .ok()
            .filter(|value| !value.is_empty())
            .unwrap_or_else(|| "default".to_string());

        Ok(Self {
            mode,
            capture,
            sampling,
            limits,
            privacy,
            on_buffer_full,
            on_sink_error,
            redactor: Arc::new(redactor),
            batch_config,
            flush_config,
            logger: DeferredBatchingLogger::new(),
            byte_budget,
            max_entry_bytes: byte_limits.max_entry_bytes,
            endpoint_hostname,
            namespace,
            staging: Arc::new(DashMap::with_shard_amount(shard_amount)),
            staging_permits: Arc::new(Semaphore::new(MAX_STAGING_ENTRIES)),
            pending_streams: Arc::new(DashMap::with_shard_amount(shard_amount)),
            rate_limiter: Arc::new(RecordsPerMinute::new(sampling.max_records_per_minute)),
            sink_healthy,
            active,
            staging_ttl: Duration::from_secs(limits.max_staging_reservation_secs),
            next_staging_sweep_at: AtomicU64::new(0),
            keyed_request_hash_calls: AtomicU64::new(0),
        })
    }

    /// Effective capture, metadata, and sink byte limits after admission.
    pub fn admitted_limits(&self) -> AdmittedCaptureLimits {
        AdmittedCaptureLimits {
            max_request_bytes: self.limits.max_request_bytes,
            max_response_bytes: self.limits.max_response_bytes,
            max_stream_capture_bytes: self.limits.max_stream_capture_bytes,
            max_model_chars: self.limits.max_model_chars,
            max_tool_count: self.limits.max_tool_count,
            max_tool_name_chars: self.limits.max_tool_name_chars,
            max_tool_names_bytes: self.limits.max_tool_names_bytes,
            hash_full_stream: self.limits.hash_full_stream,
            max_staging_reservation_secs: self.limits.max_staging_reservation_secs,
            max_entry_bytes: self.max_entry_bytes,
            buffer_max_bytes: self.byte_budget.max_bytes(),
        }
    }

    pub fn byte_budget_used_for_test(&self) -> usize {
        self.byte_budget.used()
    }

    pub fn byte_budget_drops_for_test(&self) -> u64 {
        self.byte_budget.drops_total()
    }

    pub fn keyed_request_hash_calls_for_test(&self) -> u64 {
        self.keyed_request_hash_calls.load(Ordering::Relaxed)
    }

    pub fn staging_len_for_test(&self) -> usize {
        self.staging.len()
    }

    pub fn sink_healthy_for_test(&self) -> bool {
        self.sink_healthy.load(Ordering::Relaxed)
    }

    pub fn set_sink_healthy_for_test(&self, healthy: bool) {
        self.sink_healthy.store(healthy, Ordering::Relaxed);
    }

    pub fn force_sweep_staging_for_test(&self) {
        let now = Instant::now();
        let ttl = self.staging_ttl;
        let expired: Vec<String> = self
            .staging
            .iter()
            .filter_map(|entry| {
                if now.duration_since(entry.captured_at) >= ttl {
                    Some(entry.key().clone())
                } else {
                    None
                }
            })
            .collect();
        for record_id in expired {
            self.staging.remove(&record_id);
            self.pending_streams.remove(&record_id);
        }
    }

    pub fn mark_stream_active_for_test(&self, record_id: &str) {
        if let Some(mut staging) = self.staging.get_mut(record_id) {
            staging.stream_active = true;
        }
    }

    pub fn set_staging_captured_at_for_test(&self, record_id: &str, captured_at: Instant) {
        if let Some(mut staging) = self.staging.get_mut(record_id) {
            staging.captured_at = captured_at;
        }
    }

    pub fn hold_byte_budget_for_test(&self, bytes: usize) -> Option<AuditByteLeaseGuardForTest> {
        self.byte_budget
            .try_acquire(bytes)
            .map(|lease| AuditByteLeaseGuardForTest { _lease: lease })
    }

    /// (emit?, reason) — guardrail/error overrides beat the sampling roll.
    fn emit_decision(
        &self,
        sample_hit: bool,
        guardrail: bool,
        errored: bool,
    ) -> (bool, &'static str) {
        if guardrail && self.sampling.always_on_guardrail {
            (true, "guardrail")
        } else if errored && self.sampling.always_on_error {
            (true, "error")
        } else if sample_hit {
            (true, "sampled")
        } else {
            (false, "not_sampled")
        }
    }

    fn enqueue(&self, record: AuditRecord, staging: Option<&mut AuditStaging>) -> SinkOutcome {
        if !self.rate_limiter.try_acquire() {
            return SinkOutcome::Dropped;
        }
        let Some(queued) = serialize_audit_under_byte_budget(
            &self.byte_budget,
            self.max_entry_bytes,
            &record,
        ) else {
            return if self.on_buffer_full == BufferFullPolicy::Reject {
                SinkOutcome::Rejected
            } else {
                SinkOutcome::Dropped
            };
        };
        if let Some(permit) = staging.and_then(|staging| staging.commit_permit.take()) {
            permit.send(queued);
            return SinkOutcome::Queued;
        }
        if self.logger.try_send(queued) {
            SinkOutcome::Queued
        } else if self.on_buffer_full == BufferFullPolicy::Reject {
            SinkOutcome::Rejected
        } else {
            SinkOutcome::Dropped
        }
    }

    fn commit_may_emit(&self, sample_hit: bool) -> bool {
        sample_hit || self.sampling.always_on_error || self.sampling.always_on_guardrail
    }

    /// Reserve fail-closed sink capacity before the response becomes
    /// immutable. The permit is stored with the bounded request staging and is
    /// consumed only after validators determine the final status/body.
    fn ensure_commit_admission(&self, ctx: &mut RequestContext) -> PluginResult {
        let Some(record_id) = ctx.metadata.get(MD_RECORD_ID).cloned() else {
            return PluginResult::Continue;
        };
        let Some(mut staging) = self.staging.get_mut(&record_id) else {
            return PluginResult::Continue;
        };
        if !self.commit_may_emit(staging.sample_hit) {
            return PluginResult::Continue;
        }

        if self.on_buffer_full == BufferFullPolicy::Reject && staging.commit_permit.is_none() {
            let Some(permit) = self.logger.try_reserve() else {
                ctx.metadata
                    .insert(MD_SINK_STATUS.to_string(), "rejected".to_string());
                return reject_audit_unavailable();
            };
            staging.commit_permit = Some(permit);
        }
        if self.on_sink_error == SinkErrorPolicy::Reject
            && !self.sink_healthy.load(Ordering::Relaxed)
        {
            ctx.metadata
                .insert(MD_SINK_STATUS.to_string(), "rejected".to_string());
            return reject_audit_unavailable();
        }
        PluginResult::Continue
    }

    fn stream_commit_selected(
        &self,
        ctx: &RequestContext,
        _response_status: u16,
        _content_type: Option<&str>,
    ) -> bool {
        if self.capture.streaming == StreamingCapture::Off
            || !flag(&ctx.metadata, MD_CANDIDATE)
            || !self.has_staged_candidate(&ctx.metadata)
        {
            return false;
        }

        let sample_hit = self.staged_sample_hit(&ctx.metadata);
        sample_hit
            // A response-side streaming inspector can fire the guardrail only
            // after headers commit. Reserve now for that possible terminal
            // emission; the permit is released if the stream completes without
            // an emission override.
            || self.sampling.always_on_guardrail
            // A 2xx stream can still terminate with a body error after headers
            // commit. Reserve before commit whenever terminal errors override
            // sampling so that later failure records remain fail-closed.
            || self.sampling.always_on_error
    }

    fn stream_fail_closed_rejection(
        &self,
        ctx: &mut RequestContext,
        response_status: u16,
        response_headers: &HashMap<String, String>,
    ) -> PluginResult {
        let content_type = response_headers.get("content-type").map(String::as_str);
        if !self.stream_commit_selected(ctx, response_status, content_type) {
            return PluginResult::Continue;
        }

        let Some(record_id) = ctx.metadata.get(MD_RECORD_ID).cloned() else {
            return PluginResult::Continue;
        };
        let Some(mut staging) = self.staging.get_mut(&record_id) else {
            return PluginResult::Continue;
        };
        if self.on_buffer_full == BufferFullPolicy::Reject && staging.commit_permit.is_none() {
            let Some(permit) = self.logger.try_reserve() else {
                ctx.metadata
                    .insert(MD_SINK_STATUS.to_string(), "rejected".to_string());
                return reject_audit_unavailable();
            };
            staging.commit_permit = Some(permit);
        }
        if self.on_sink_error == SinkErrorPolicy::Reject
            && !self.sink_healthy.load(Ordering::Relaxed)
        {
            ctx.metadata
                .insert(MD_SINK_STATUS.to_string(), "rejected".to_string());
            return reject_audit_unavailable();
        }
        PluginResult::Continue
    }

    fn sweep_staging(&self) {
        if self.staging.len() < STAGING_SWEEP_THRESHOLD {
            return;
        }
        let now_seconds = process_monotonic_seconds();
        let next = self.next_staging_sweep_at.load(Ordering::Relaxed);
        if now_seconds < next
            || self
                .next_staging_sweep_at
                .compare_exchange(
                    next,
                    now_seconds.saturating_add(STAGING_SWEEP_INTERVAL_SECS),
                    Ordering::AcqRel,
                    Ordering::Relaxed,
                )
                .is_err()
        {
            return;
        }
        let now = Instant::now();
        let ttl = self.staging_ttl;
        let expired: Vec<String> = self
            .staging
            .iter()
            .filter_map(|entry| {
                // Active streams with reserved permits still age out: abandoned
                // or never-ending streams must not pin staging/queue capacity.
                if now.duration_since(entry.captured_at) >= ttl {
                    Some(entry.key().clone())
                } else {
                    None
                }
            })
            .collect();
        for record_id in expired {
            self.staging.remove(&record_id);
            self.pending_streams.remove(&record_id);
        }
    }

    fn discard_staged_candidate(&self, ctx: &mut RequestContext) {
        let removed_staging = ctx.metadata.get(MD_RECORD_ID).is_some_and(|record_id| {
            let removed = self.staging.remove(record_id).is_some();
            self.pending_streams.remove(record_id);
            removed
        });
        // The marker is shared by co-located instances. A saturated instance
        // that never staged this request must not erase a peer instance's live
        // candidate and cause its record id to be stripped before logging.
        if removed_staging || !flag(&ctx.metadata, MD_CANDIDATE) {
            ctx.metadata
                .insert(MD_CANDIDATE.to_string(), "false".to_string());
            ctx.metadata.remove(MD_REQUEST_HASH);
            ctx.metadata.remove(MD_STREAM_REQUEST);
        }
    }

    fn shape_body(&self, raw: &[u8], max_bytes: usize) -> (Option<String>, bool) {
        shape_bytes(self.mode, &self.redactor, raw, max_bytes)
    }

    /// Classify `body` and stage the audit candidate: writes the
    /// `ai_transcript_audit.*` request-side metadata and inserts the staging
    /// entry keyed by the new `record_id`. `body` is the request body as
    /// currently known (pre-transform in `before_proxy`, final in the
    /// final-body hook fallback); callers have already checked the JSON
    /// content-type. Body hashes are keyed (see [`PiiRedactor::keyed_hash_hex`]).
    fn stage_candidate(&self, ctx: &mut RequestContext, body: &[u8]) -> PluginResult {
        if body.is_empty() {
            self.discard_staged_candidate(ctx);
            return PluginResult::Continue;
        }
        let parsed: Option<Value> = serde_json::from_slice(body).ok();
        let is_ai = parsed.as_ref().is_some_and(json_looks_like_ai_request);
        if !is_ai {
            self.discard_staged_candidate(ctx);
            return PluginResult::Continue;
        }

        let record_id = ctx
            .metadata
            .get(MD_RECORD_ID)
            .cloned()
            .unwrap_or_else(|| uuid::Uuid::new_v4().to_string());
        self.sweep_staging();
        let staging_permit = match Arc::clone(&self.staging_permits).try_acquire_owned() {
            Ok(permit) => permit,
            Err(_) => {
                self.discard_staged_candidate(ctx);
                let fail_closed = self.on_buffer_full == BufferFullPolicy::Reject
                    || self.on_sink_error == SinkErrorPolicy::Reject;
                ctx.metadata.insert(
                    MD_SINK_STATUS.to_string(),
                    if fail_closed { "rejected" } else { "dropped" }.to_string(),
                );
                return if fail_closed {
                    reject_audit_unavailable()
                } else {
                    PluginResult::Continue
                };
            }
        };
        let sample_hit = sample_from_record_id(&record_id) < self.sampling.rate;
        // Exported body hashes are keyed HMAC-SHA256 (same key as the redaction
        // placeholders): a plain SHA-256 of a mostly-predictable body (a fixed
        // chat JSON wrapper around one secret) would be an offline brute-force
        // oracle for the secret in every mode, including hash_only.
        let request_content_digest = content_digest(body);
        let request_hash = self.keyed_request_hash(body);

        ctx.metadata
            .insert(MD_RECORD_ID.to_string(), record_id.clone());
        ctx.metadata
            .insert(MD_CANDIDATE.to_string(), "true".to_string());
        ctx.metadata
            .insert(MD_SAMPLE_HIT.to_string(), bool_str(sample_hit));
        // `sampled` carries the sampling ROLL (matching the exported record's
        // `sampled` field), which is fully known here at staging time — write
        // it now so request-only configs and streamed responses (which never
        // reach the buffered response hook) still log it. The buffered path
        // re-confirms the same value.
        ctx.metadata
            .insert(MD_SAMPLED.to_string(), bool_str(sample_hit));
        ctx.metadata
            .insert(MD_REQUEST_HASH.to_string(), request_hash.clone());
        // `stream: true` means an SSE response is expected; record it so the
        // response buffer decision streams rather than stalls (buffering a
        // stream holds it until EOF, and under retry the buffered->stream
        // content-type downgrade is disabled).
        if parsed
            .as_ref()
            .and_then(|json| json.get("stream"))
            .and_then(Value::as_bool)
            == Some(true)
        {
            ctx.metadata
                .insert(MD_STREAM_REQUEST.to_string(), "true".to_string());
        }

        // Every staged AI candidate is eligible for stream capture.
        // `forces_reqwest_dispatch` and `response_stream_inspector` apply the
        // `sampled`-mode tee gate
        // (`stream_tee_wanted`) at dispatch/response time, when the request-side
        // guardrails (2925–2978, which run after this plugin's staging at 2740)
        // have already published their metadata. Non-AI JSON POSTs are never
        // staged, so they stay on the native-H3 path.
        let (request_model, model_truncated) = parsed
            .as_ref()
            .map(|json| admit_model(json, self.limits.max_model_chars))
            .unwrap_or((None, false));
        let (tool_names, tool_names_truncated) = if self.capture.tool_calls {
            parsed
                .as_ref()
                .map(|json| {
                    admit_tool_names(
                        json,
                        self.limits.max_tool_count,
                        self.limits.max_tool_name_chars,
                        self.limits.max_tool_names_bytes,
                    )
                })
                .unwrap_or_default()
        } else {
            (Vec::new(), false)
        };
        let (request_excerpt, request_truncated) = if self.capture.request {
            self.shape_body(body, self.limits.max_request_bytes)
        } else {
            (None, false)
        };

        self.staging.insert(
            record_id,
            AuditStaging {
                _staging_permit: staging_permit,
                captured_at: Instant::now(),
                sample_hit,
                request_excerpt,
                request_truncated,
                request_hash: Some(request_hash),
                request_content_digest,
                request_model,
                model_truncated,
                tool_names,
                tool_names_truncated,
                commit_permit: None,
                stream_active: false,
            },
        );
        PluginResult::Continue
    }

    fn keyed_request_hash(&self, body: &[u8]) -> String {
        self.keyed_request_hash_calls
            .fetch_add(1, Ordering::Relaxed);
        self.redactor.keyed_hash_hex(body)
    }

    /// Refresh an already-staged candidate with the FINAL backend-visible
    /// request body (request transforms run after `before_proxy`, where the
    /// candidate was staged). No-op when the body is unchanged, so the common
    /// no-transform path costs one keyed-hash pass at staging plus a cheap
    /// content-digest compare here.
    fn refresh_staged_request(&self, ctx: &mut RequestContext, body: &[u8]) {
        let Some(record_id) = ctx.metadata.get(MD_RECORD_ID).cloned() else {
            return;
        };
        let parsed: Option<Value> = serde_json::from_slice(body).ok();
        if !parsed.as_ref().is_some_and(json_looks_like_ai_request) {
            self.discard_staged_candidate(ctx);
            return;
        }
        let digest = content_digest(body);
        if self
            .staging
            .get(&record_id)
            .is_some_and(|staging| staging.request_content_digest == digest)
        {
            // Body bytes are identical to staging; only refresh the stream
            // marker from the already-validated JSON shape when needed. The
            // stream flag cannot change without changing bytes, so leave
            // metadata as-is and skip the second keyed HMAC.
            return;
        }
        let request_hash = self.keyed_request_hash(body);
        if let Some(mut staged) = self.staging.get_mut(&record_id) {
            let (request_excerpt, request_truncated) = if self.capture.request {
                self.shape_body(body, self.limits.max_request_bytes)
            } else {
                (None, false)
            };
            staged.request_excerpt = request_excerpt;
            staged.request_truncated = request_truncated;
            staged.request_hash = Some(request_hash.clone());
            staged.request_content_digest = digest;
            let (request_model, model_truncated) = parsed
                .as_ref()
                .map(|json| admit_model(json, self.limits.max_model_chars))
                .unwrap_or((None, false));
            staged.request_model = request_model;
            staged.model_truncated = model_truncated;
            if self.capture.tool_calls {
                let (tool_names, tool_names_truncated) = parsed
                    .as_ref()
                    .map(|json| {
                        admit_tool_names(
                            json,
                            self.limits.max_tool_count,
                            self.limits.max_tool_name_chars,
                            self.limits.max_tool_names_bytes,
                        )
                    })
                    .unwrap_or_default();
                staged.tool_names = tool_names;
                staged.tool_names_truncated = tool_names_truncated;
            }
        }
        // Re-detect `stream` on the FINAL backend-visible body: a
        // `request_transformer` may have added OR removed `"stream": true`
        // after `before_proxy` staged the candidate. `MD_STREAM_REQUEST` drives
        // the later buffer-vs-stream response decision
        // (`buffered_response_capture_wanted`), so — mirroring
        // `ai_tool_governor` — the marker must track the final body in BOTH
        // directions.
        if parsed
            .as_ref()
            .and_then(|json| json.get("stream"))
            .and_then(Value::as_bool)
            == Some(true)
        {
            ctx.metadata
                .insert(MD_STREAM_REQUEST.to_string(), "true".to_string());
        } else {
            ctx.metadata.remove(MD_STREAM_REQUEST);
        }
        ctx.metadata
            .insert(MD_REQUEST_HASH.to_string(), request_hash);
    }

    fn has_staged_candidate(&self, metadata: &HashMap<String, String>) -> bool {
        metadata
            .get(MD_RECORD_ID)
            .is_some_and(|record_id| self.staging.contains_key(record_id))
    }

    /// THIS instance's staged sampling roll, not the shared
    /// `ai_transcript_audit.sample_hit` metadata key: a second instance of the
    /// plugin can overwrite that key with its own roll, and each instance keys
    /// its own `staging` map by the shared record id.
    fn staged_sample_hit(&self, metadata: &HashMap<String, String>) -> bool {
        let staged = metadata
            .get(MD_RECORD_ID)
            .and_then(|record_id| self.staging.get(record_id))
            .map(|staging| staging.sample_hit);
        staged.unwrap_or_else(|| flag(metadata, MD_SAMPLE_HIT))
    }

    /// Whether a marked AI candidate's stream should actually be teed. `On`
    /// tees every marked candidate; `Sampled` tees only sampling-roll winners
    /// plus requests a request-side guardrail flagged (evaluated here — at
    /// dispatch/response time — because the guardrail plugins at 2925–2978 run
    /// AFTER staging at 2740 but BEFORE the proxy's dispatch decision, so
    /// `always_capture_on_guardrail` can still capture response evidence on an
    /// un-sampled stream). Error statuses and response-side guardrail hits are
    /// only known later still: on un-sampled streams those overrides emit via
    /// the `log` fallback without a response body/hash (teeing every stream
    /// "just in case" would defeat sampled capture entirely).
    fn stream_tee_wanted(&self, metadata: &HashMap<String, String>) -> bool {
        match self.capture.streaming {
            StreamingCapture::Off => false,
            StreamingCapture::On => true,
            StreamingCapture::Sampled => {
                self.staged_sample_hit(metadata)
                    || (self.sampling.always_on_guardrail && guardrail_fired(metadata))
            }
        }
    }

    fn envelope_from_ctx(&self, ctx: &RequestContext, status: u16) -> EnvelopeOwned {
        let (proxy_id, proxy_name, namespace) = match ctx.matched_proxy.as_ref() {
            Some(proxy) => (
                Some(proxy.id.clone()),
                proxy.name.clone(),
                if proxy.namespace.is_empty() {
                    self.namespace.clone()
                } else {
                    proxy.namespace.clone()
                },
            ),
            None => (None, None, self.namespace.clone()),
        };
        EnvelopeOwned {
            proxy_id,
            proxy_name,
            namespace,
            consumer_username: if self.privacy.include_consumer_username {
                consumer_name(ctx)
            } else {
                None
            },
            client_ip: if self.privacy.include_client_ip {
                Some(ctx.client_ip.clone())
            } else {
                None
            },
            method: ctx.method.clone(),
            path: ctx.path.clone(),
            status_code: status,
        }
    }

    fn envelope_from_summary(&self, summary: &TransactionSummary) -> EnvelopeOwned {
        EnvelopeOwned {
            proxy_id: summary.proxy_id.clone(),
            proxy_name: summary.proxy_name.clone(),
            namespace: if summary.namespace.is_empty() {
                self.namespace.clone()
            } else {
                summary.namespace.clone()
            },
            consumer_username: if self.privacy.include_consumer_username {
                summary.consumer_username.clone()
            } else {
                None
            },
            client_ip: if self.privacy.include_client_ip {
                Some(summary.client_ip.clone())
            } else {
                None
            },
            method: summary.http_method.clone(),
            path: summary.request_path.clone(),
            status_code: summary.response_status_code,
        }
    }

    fn harvest_metadata(&self, metadata: &HashMap<String, String>) -> Harvest {
        let mut harvest = Harvest::default();
        // `ai_federation` publishes both `ai_provider` (the provider type) and
        // `ai_federation_provider` (the configured federation name). Resolve them
        // with a fixed precedence after the scan so the exported `provider` field
        // does not flip with HashMap iteration order.
        let mut federation_provider: Option<String> = None;
        for (key, value) in metadata {
            if key.starts_with("ai_transcript_audit.") {
                continue;
            }
            // Audit records bypass the transaction-log redaction layer, so apply
            // the same key predicate defensively before copying any value out.
            let safe = |raw: &String| {
                if is_sensitive_metadata_key(key) {
                    REDACTED_PLACEHOLDER.to_string()
                } else {
                    raw.clone()
                }
            };
            match key.as_str() {
                "ai_model" => harvest.model = Some(value.clone()),
                "ai_provider" => harvest.provider = Some(value.clone()),
                "ai_federation_provider" => federation_provider = Some(value.clone()),
                "ai_total_tokens"
                | "ai_prompt_tokens"
                | "ai_completion_tokens"
                | "ai_estimated_cost"
                | "ai_streaming" => {
                    harvest.tokens.insert(key.clone(), safe(value));
                }
                _ => {
                    if key.starts_with("ai_cache") || key.starts_with("request_deduplication.") {
                        harvest.cache.insert(key.clone(), safe(value));
                    } else if is_guardrail_key(key) {
                        harvest.guardrails.insert(key.clone(), safe(value));
                    }
                }
            }
        }
        // `ai_provider` wins; fall back to the federation name only when no
        // provider type was published.
        if harvest.provider.is_none() {
            harvest.provider = federation_provider;
        }
        harvest
    }

    #[allow(clippy::too_many_arguments)]
    fn build_record(
        &self,
        record_id: &str,
        envelope: EnvelopeOwned,
        metadata: &HashMap<String, String>,
        staging: Option<&AuditStaging>,
        response_excerpt: Option<String>,
        response_truncated: bool,
        response_hash: Option<String>,
        response_hash_complete: Option<bool>,
        response_hashed_bytes: Option<u64>,
        sampled: bool,
        reason: &'static str,
        response_headers: Option<&HashMap<String, String>>,
    ) -> AuditRecord {
        let harvests = self.mode.harvests_metadata();
        let harvest = if harvests {
            self.harvest_metadata(metadata)
        } else {
            Harvest::default()
        };

        let request_excerpt = staging.and_then(|s| s.request_excerpt.clone());
        let request_truncated = staging.map(|s| s.request_truncated).unwrap_or(false);
        let request_hash = staging.and_then(|s| s.request_hash.clone());
        let req_model = staging.and_then(|s| s.request_model.clone());
        let model_truncated = staging.map(|s| s.model_truncated).unwrap_or(false);
        let tool_names_truncated = staging.map(|s| s.tool_names_truncated).unwrap_or(false);
        // `model` and `tool_names` are copied straight out of the user request
        // body, so they bypass the body-excerpt redaction path. Run them through
        // the same redactor before export in every mode except the explicit
        // `full_body` raw-capture opt-in — a PII-bearing "model" string must not
        // leak through the metadata side door in redacted/metadata/hash modes.
        let redact_request_derived = self.mode != AuditMode::FullBody;
        let tool_names = if harvests {
            let tool_names = staging.map(|s| s.tool_names.clone()).unwrap_or_default();
            if redact_request_derived {
                tool_names
                    .iter()
                    .map(|name| self.redactor.redact(name))
                    .collect()
            } else {
                tool_names
            }
        } else {
            Vec::new()
        };

        let model = if harvests {
            let model = req_model.or(harvest.model);
            if redact_request_derived {
                model.map(|value| self.redactor.redact(&value))
            } else {
                model
            }
        } else {
            None
        };
        let provider = if harvests { harvest.provider } else { None };
        // Raw headers require BOTH the capture switch and the privacy opt-in
        // (defense in depth); values are still redacted by key.
        let headers = if harvests && self.capture.headers && self.privacy.include_raw_headers {
            response_headers
                .map(redact_headers)
                .filter(|map| !map.is_empty())
        } else {
            None
        };

        AuditRecord {
            version: RECORD_VERSION,
            record_id: record_id.to_string(),
            timestamp: chrono::Utc::now().to_rfc3339(),
            namespace: envelope.namespace,
            proxy_id: envelope.proxy_id,
            proxy_name: envelope.proxy_name,
            consumer_username: envelope.consumer_username,
            client_ip: envelope.client_ip,
            method: envelope.method,
            path: envelope.path,
            model,
            provider,
            status_code: envelope.status_code,
            mode: self.mode.as_str(),
            sampled,
            capture_reason: reason,
            request_hash,
            response_hash,
            response_hash_complete,
            response_hashed_bytes,
            request_body_truncated: request_truncated,
            response_body_truncated: response_truncated,
            model_truncated,
            tool_names_truncated,
            request_body: request_excerpt,
            response_body: response_excerpt,
            tokens: harvest.tokens,
            cache: harvest.cache,
            guardrails: harvest.guardrails,
            tool_names,
            headers,
        }
    }

    /// Shared per-request buffered-capture predicate used by both
    /// `should_buffer_response_body` and
    /// `should_buffer_response_body_for_content_type` so the initial
    /// buffer-vs-stream decision and the proxy's later content-type
    /// re-evaluation (`refine_stream_response_for_content_type`) can never
    /// disagree about whether this request's response is worth buffering.
    fn buffered_response_capture_wanted(&self, ctx: &RequestContext) -> bool {
        if !self.capture.response {
            return false;
        }
        // A `stream: true` request expects an SSE response; do not buffer it —
        // buffering holds the stream until EOF, and under retry the
        // buffered->stream content-type downgrade is disabled, so an oversized
        // stream would be capped at `max_response_body_size_bytes` and fail
        // rather than stream. Streaming capture still tees it via the response
        // stream inspector when enabled. Tradeoff (deliberate): a provider that
        // answers a `stream: true` request with a non-SSE JSON 4xx/5xx error is
        // then streamed too, so its body is not buffered-captured — the log
        // fallback still records the request side, status, and error reason.
        // Forcing a buffer to catch that body would risk the failure above for
        // the common SSE success case. The marker is refreshed from the final
        // backend-visible body by `on_final_request_body_with_context`
        // (via `refresh_staged_request` for an already-classified candidate, or
        // `stage_candidate` otherwise) — after transforms and before this
        // response policy is committed — in both directions, so a
        // transformer-added or -removed `stream` value is reflected here.
        if flag(&ctx.metadata, MD_STREAM_REQUEST) {
            return false;
        }
        match ctx.metadata.get(MD_CANDIDATE).map(String::as_str) {
            Some("true") => true,
            // The final transformed body was classified as non-AI. Do not
            // buffer every JSON POST response: that would over-buffer ordinary
            // non-AI traffic. The transaction is still audited request-side via
            // the `log` fallback.
            Some("false") => false,
            _ => {
                ctx.method == "POST"
                    && ctx
                        .headers
                        .get("content-type")
                        .is_some_and(|content_type| is_json_content_type(content_type))
            }
        }
    }

    fn buffered_response_capture_enabled(
        &self,
        response_headers: &HashMap<String, String>,
    ) -> bool {
        self.capture.response
            || (self.capture.streaming != StreamingCapture::Off
                && response_headers
                    .get("content-type")
                    .is_some_and(|content_type| is_event_stream(content_type)))
    }
}

#[async_trait]
impl Plugin for AiTranscriptAudit {
    fn name(&self) -> &str {
        "ai_transcript_audit"
    }

    fn priority(&self) -> u16 {
        super::priority::AI_TRANSCRIPT_AUDIT
    }

    fn supported_protocols(&self) -> &'static [ProxyProtocol] {
        HTTP_ONLY_PROTOCOLS
    }

    fn start_background_tasks(&self) -> Result<(), String> {
        let flush_config = self.flush_config.clone();
        let healthy = Arc::clone(&self.sink_healthy);
        let hooks = LoggerHooks {
            on_failed_batch: Some(Arc::new(move |_batch: Vec<QueuedAuditRecord>, _error: String| {
                healthy.store(false, Ordering::Relaxed);
            })),
            ..LoggerHooks::default()
        };
        self.logger.start_with_hooks(
            "ai_transcript_audit",
            self.batch_config,
            hooks,
            move |batch| {
                let flush_config = flush_config.clone();
                async move { send_batch(&flush_config, batch).await }
            },
        )
    }

    fn commit_background_tasks(&self) {
        self.logger.commit();
    }

    fn warmup_hostnames(&self) -> Vec<String> {
        vec![self.endpoint_hostname.clone()]
    }

    // ---- request body capture ----

    fn requires_request_body_buffering(&self) -> bool {
        self.active
    }

    /// The request body must be prebuffered before `before_proxy` so the
    /// candidate is staged **before**:
    /// - request-phase terminators (`ai_federation`, `ai_semantic_cache`
    ///   hits) consume it and short-circuit — their transactions must still
    ///   be audited via the response/log hooks;
    /// - the proxy's post-transform response stream-vs-buffer decision runs (it
    ///   reads `ai_transcript_audit.candidate` via
    ///   `should_buffer_response_body`);
    /// - the final `forces_reqwest_dispatch` preference is evaluated (it checks
    ///   this instance's bounded staging entry).
    fn requires_request_body_before_before_proxy(&self) -> bool {
        self.active
    }

    fn should_buffer_request_body(&self, ctx: &RequestContext) -> bool {
        self.active
            && ctx.method == "POST"
            && ctx
                .headers
                .get("content-type")
                .is_some_and(|content_type| is_json_content_type(content_type))
    }

    async fn before_proxy(
        &self,
        ctx: &mut RequestContext,
        headers: &mut HashMap<String, String>,
    ) -> PluginResult {
        if !self.active {
            return PluginResult::Continue;
        }
        let candidate_shape = ctx.method == "POST"
            && headers
                .get("content-type")
                .is_some_and(|content_type| is_json_content_type(content_type));
        if !candidate_shape {
            return PluginResult::Continue;
        }
        // The stream marker is set inside `stage_candidate`, only once the body
        // proved AI-shaped — marking every JSON POST here would push ordinary
        // non-AI traffic off the native-H3 path via `forces_reqwest_dispatch`.
        // The prebuffered body is stored as UTF-8 metadata; JSON is UTF-8 by
        // definition, so a missing entry means the body was not prebuffered on
        // this path (or is not valid JSON anyway) — leave classification to
        // the final-body hook fallback. `remove`/re-insert avoids cloning the
        // full body just to satisfy the borrow checker.
        let Some(body) = ctx.metadata.remove("request_body") else {
            return PluginResult::Continue;
        };
        let stage_result = self.stage_candidate(ctx, body.as_bytes());
        ctx.metadata.insert("request_body".to_string(), body);
        if !matches!(stage_result, PluginResult::Continue) {
            return stage_result;
        }
        if flag(&ctx.metadata, MD_STREAM_REQUEST) && self.requires_response_committed_hook() {
            PluginResult::Continue
        } else {
            self.ensure_commit_admission(ctx)
        }
    }

    /// The proxy only routes the context-aware final-body hook to plugins that
    /// advertise it; without this the context-free default would run instead
    /// and no metadata/staging would ever be written on the H1/H2 path.
    fn needs_final_request_body_context(&self) -> bool {
        self.active
    }

    async fn on_final_request_body_with_context(
        &self,
        ctx: &mut RequestContext,
        headers: &HashMap<String, String>,
        body: &[u8],
    ) -> PluginResult {
        if !self.active {
            return PluginResult::Continue;
        }
        // Mark that the backend-visible request was captured, so the reject-path
        // `after_proxy` refresh knows this was NOT a `before_proxy` short-circuit.
        ctx.metadata
            .insert(MD_FINAL_REQ_SEEN.to_string(), "true".to_string());
        // Staged in `before_proxy`: request transforms may have changed the
        // body since, so refresh the captured hash/excerpt with the final
        // backend-visible bytes.
        if flag(&ctx.metadata, MD_CANDIDATE) && self.has_staged_candidate(&ctx.metadata) {
            self.refresh_staged_request(ctx, body);
            return PluginResult::Continue;
        }
        // Fallback for paths where the body was not available before
        // `before_proxy` (e.g. non-UTF-8 metadata skip above).
        let is_json = headers
            .get("content-type")
            .is_some_and(|content_type| is_json_content_type(content_type));
        if !is_json {
            self.discard_staged_candidate(ctx);
            return PluginResult::Continue;
        }
        let stage_result = self.stage_candidate(ctx, body);
        if !matches!(stage_result, PluginResult::Continue) {
            return stage_result;
        }
        if flag(&ctx.metadata, MD_STREAM_REQUEST) && self.requires_response_committed_hook() {
            PluginResult::Continue
        } else {
            self.ensure_commit_admission(ctx)
        }
    }

    // ---- reject-path request refresh ----

    fn applies_after_proxy_on_reject(&self) -> bool {
        self.active
    }

    fn may_replace_rejection_response(&self) -> bool {
        self.active
    }

    /// On a `before_proxy` short-circuit (no backend dispatch, so no final
    /// request-body hook), a later terminator can rewrite `request_body` after we
    /// staged the candidate — e.g. `ai_prompt_shield` redacts, then
    /// `ai_federation` returns a non-2xx `RejectBinary` whose synthetic
    /// response-body hooks never run. Refresh the staged request from the final
    /// `request_body` so the record reflects the provider-visible (redacted)
    /// request, not the pre-redaction prompt/hash. The normal backend path
    /// already captured the backend-visible request in the final-body hook
    /// (`MD_FINAL_REQ_SEEN`), so skip there to avoid reverting it from carried
    /// pre-transform metadata.
    async fn after_proxy(
        &self,
        ctx: &mut RequestContext,
        response_status: u16,
        response_headers: &mut HashMap<String, String>,
    ) -> PluginResult {
        if !self.active || !flag(&ctx.metadata, MD_CANDIDATE) {
            return PluginResult::Continue;
        }
        if !flag(&ctx.metadata, MD_FINAL_REQ_SEEN)
            && let Some(body) = ctx.metadata.remove("request_body")
        {
            self.refresh_staged_request(ctx, body.as_bytes());
            ctx.metadata.insert("request_body".to_string(), body);
        }
        if ctx.metadata.contains_key(REJECTION_RESPONSE_METADATA_KEY)
            && !ctx
                .metadata
                .contains_key(REPLACEABLE_REJECTION_RESPONSE_METADATA_KEY)
        {
            // Proxy core cannot apply a fresh reject while replaying hooks over
            // an already-fixed response. Only the explicitly replaceable pass
            // may perform fail-closed admission here. Do not retain a
            // provisional "rejected" status from an earlier admission hook:
            // that 503 was ignored and the existing response remains selected.
            if ctx
                .metadata
                .get(MD_SINK_STATUS)
                .is_some_and(|status| status == "rejected")
            {
                ctx.metadata
                    .insert(MD_SINK_STATUS.to_string(), "deferred".to_string());
            }
            return PluginResult::Continue;
        }
        if self.capture.streaming != StreamingCapture::Off {
            let stream_admission =
                self.stream_fail_closed_rejection(ctx, response_status, response_headers);
            if !matches!(stream_admission, PluginResult::Continue) {
                return stream_admission;
            }
        }
        if flag(&ctx.metadata, MD_STREAM_REQUEST) {
            // Stream admission above is selective: unsampled successful
            // streams must not consume buffered-response capacity.
            PluginResult::Continue
        } else {
            // Streaming and buffered capture are independent policies. A
            // response that remains JSON still needs the buffered path's
            // admission even when streaming capture is also configured. Both
            // checks reuse the same per-record permit when they select the
            // same eventual audit record.
            self.ensure_commit_admission(ctx)
        }
    }

    // ---- buffered response capture ----

    fn requires_response_body_buffering(&self) -> bool {
        self.capture.response
    }

    fn should_buffer_response_body(&self, ctx: &RequestContext) -> bool {
        self.buffered_response_capture_wanted(ctx)
    }

    fn should_buffer_response_body_for_content_type(
        &self,
        ctx: &RequestContext,
        content_type: Option<&str>,
        _response_status: u16,
        _response_headers: &HashMap<String, String>,
    ) -> bool {
        // Mirror the full per-request decision `should_buffer_response_body`
        // makes (`stream: true` opt-out AND the AI-candidate tri-state). This
        // hook also runs when the proxy re-evaluates buffer-vs-stream for a
        // released response (`refine_stream_response_for_content_type`);
        // without the same gates, a co-located plugin's released non-AI (or
        // `stream: true`) JSON response would be re-pinned to the buffered
        // path even though `on_final_response_body` would ignore it —
        // needlessly buffering ordinary JSON traffic and risking the global
        // response-size-cap failure the opt-outs exist to avoid.
        if !self.buffered_response_capture_wanted(ctx) {
            return false;
        }
        // Buffer JSON AI responses here; SSE goes down the streaming inspector
        // path, and framed gRPC bodies are not JSON documents.
        content_type.is_some_and(|content_type| {
            is_json_content_type(content_type) && !is_framed_grpc(content_type)
        })
    }

    async fn on_final_response_body(
        &self,
        ctx: &mut RequestContext,
        _response_status: u16,
        response_headers: &HashMap<String, String>,
        _body: &[u8],
    ) -> PluginResult {
        // `capture.response` gates buffered *JSON* responses. A buffered SSE body
        // can still reach this hook when streaming capture is enabled but the
        // proxy (or another plugin) buffered the event stream instead of
        // streaming it — the streaming inspector never ran, so this is the only
        // path left to attach the response transcript. Honor the streaming
        // policy (`response_body_capture_allowed` already permits SSE) even when
        // buffered JSON capture is off.
        if !self.buffered_response_capture_enabled(response_headers) {
            return PluginResult::Continue;
        }
        let Some(record_id) = ctx.metadata.get(MD_RECORD_ID).cloned() else {
            return PluginResult::Continue;
        };
        if !flag(&ctx.metadata, MD_CANDIDATE) {
            self.staging.remove(&record_id);
            return PluginResult::Continue;
        }

        // On synthetic short-circuits, downstream `before_proxy` plugins may
        // have updated `ctx.metadata["request_body"]` and then returned a
        // synthetic 2xx before the final request-body hook could run. Refresh
        // from that live metadata before consuming staging. Do not do this on
        // the normal backend path: there, the final-body hook already saw the
        // backend-visible bytes and the carried `request_body` metadata may be
        // the intentionally preserved pre-transform body.
        if flag(&ctx.metadata, SYNTHETIC_SHORT_CIRCUIT_METADATA_KEY)
            && let Some(body) = ctx.metadata.remove("request_body")
        {
            self.refresh_staged_request(ctx, body.as_bytes());
            ctx.metadata.insert("request_body".to_string(), body);
        }

        // Peek (do not consume) the staging entry for the fail-closed gate. The
        // observe-only committed hook consumes it after every validator has run.
        let sample_hit = self
            .staging
            .get(&record_id)
            .map(|staging| staging.sample_hit)
            .unwrap_or_else(|| flag(&ctx.metadata, MD_SAMPLE_HIT));
        // The transaction-log `sampled` flag carries the sampling ROLL (matching
        // the exported record's `sampled` field), not the emit decision —
        // `sink_status` already conveys whether a record was emitted.
        ctx.metadata
            .insert(MD_SAMPLED.to_string(), bool_str(sample_hit));

        if self.commit_may_emit(sample_hit) {
            let admission = self.ensure_commit_admission(ctx);
            if !matches!(admission, PluginResult::Continue) {
                return admission;
            }
        }

        // Keep rejection-capable sink admission here, before the response is
        // committed. Record construction and enqueue happen later with the
        // final status/body. The committed 503 record remains a recovery probe:
        // a successful flush flips sink health back to true.
        ctx.metadata
            .insert(MD_SINK_STATUS.to_string(), "deferred".to_string());
        PluginResult::Continue
    }

    fn requires_response_committed_hook(&self) -> bool {
        self.capture.response || self.capture.streaming != StreamingCapture::Off
    }

    async fn on_response_committed(
        &self,
        ctx: &mut RequestContext,
        response_status: u16,
        response_headers: &HashMap<String, String>,
        body: &[u8],
    ) {
        if !self.buffered_response_capture_enabled(response_headers) {
            return;
        }
        let Some(record_id) = ctx.metadata.get(MD_RECORD_ID).cloned() else {
            return;
        };
        if !flag(&ctx.metadata, MD_CANDIDATE) {
            self.staging.remove(&record_id);
            return;
        }
        let request_rejected_for_sink = ctx
            .metadata
            .get(MD_SINK_STATUS)
            .is_some_and(|status| status == "rejected");

        let sample_hit = self
            .staging
            .get(&record_id)
            .map(|staging| staging.sample_hit)
            .unwrap_or_else(|| flag(&ctx.metadata, MD_SAMPLE_HIT));
        let (emit, reason) = self.emit_decision(
            sample_hit,
            guardrail_fired(&ctx.metadata),
            response_status >= 400,
        );
        ctx.metadata
            .insert(MD_SAMPLED.to_string(), bool_str(sample_hit));

        let mut staging = self.staging.remove(&record_id).map(|(_, value)| value);
        if !emit {
            // A fail-closed rejection (`on_sink_error`/`on_buffer_full: reject`)
            // stamps `MD_SINK_STATUS = "rejected"` and returns a 503 in the
            // admission phase; that verdict is terminal. A later not-emitting
            // decision must not overwrite it, or the client-visible 503 would be
            // logged as `skipped` and the fail-closed audit trail lost.
            ctx.metadata.insert(
                MD_SINK_STATUS.to_string(),
                if request_rejected_for_sink {
                    "rejected".to_string()
                } else {
                    "skipped".to_string()
                },
            );
            return;
        }

        let captures_response_body = response_body_capture_allowed(self.capture, response_headers);
        let response_hash = captures_response_body.then(|| self.redactor.keyed_hash_hex(body));
        if let Some(response_hash) = response_hash.as_ref() {
            ctx.metadata
                .insert(MD_RESPONSE_HASH.to_string(), response_hash.clone());
        }
        let (response_excerpt, response_truncated) = if captures_response_body {
            self.shape_body(body, self.limits.max_response_bytes)
        } else {
            (None, false)
        };
        let envelope = self.envelope_from_ctx(ctx, response_status);
        let record = self.build_record(
            &record_id,
            envelope,
            &ctx.metadata,
            staging.as_ref(),
            response_excerpt,
            response_truncated,
            response_hash,
            response_hash.as_ref().map(|_| true),
            response_hash
                .as_ref()
                .map(|_| body.len() as u64),
            sample_hit,
            reason,
            Some(response_headers),
        );
        let status = match self.enqueue(record, staging.as_mut()) {
            SinkOutcome::Queued => "queued",
            SinkOutcome::Dropped => "dropped",
            SinkOutcome::Rejected => "rejected",
        };
        ctx.metadata.insert(
            MD_SINK_STATUS.to_string(),
            if request_rejected_for_sink {
                "rejected".to_string()
            } else {
                status.to_string()
            },
        );
    }

    // ---- streaming (SSE) response capture ----

    fn requires_response_stream_hooks(&self) -> bool {
        self.capture.streaming != StreamingCapture::Off
            || (self.capture.response && self.on_buffer_full == BufferFullPolicy::Reject)
    }

    fn defers_response_stream_termination_until_after_peers(&self) -> bool {
        true
    }

    fn on_response_stream_selected(
        &self,
        ctx: &RequestContext,
        response_status: u16,
        content_type: Option<&str>,
    ) {
        let Some(record_id) = ctx.metadata.get(MD_RECORD_ID) else {
            return;
        };
        // Retain a slot reserved by the final pre-commit stream admission; the
        // terminal hook or log fallback consumes it after the response ends.
        // Other streams still release any conservative buffered-response slot.
        if self.stream_commit_selected(ctx, response_status, content_type) {
            if let Some(mut staging) = self.staging.get_mut(record_id) {
                staging.stream_active = true;
            }
            return;
        }
        if let Some(mut staging) = self.staging.get_mut(record_id) {
            staging.commit_permit.take();
        }
    }

    fn forces_reqwest_dispatch(&self, ctx: &RequestContext) -> bool {
        self.capture.streaming != StreamingCapture::Off
            && self.has_staged_candidate(&ctx.metadata)
            && self.stream_tee_wanted(&ctx.metadata)
    }

    fn response_stream_inspector(
        &self,
        ctx: &RequestContext,
        response_status: u16,
        content_type: Option<&str>,
    ) -> Option<Box<dyn ResponseStreamInspector>> {
        if !content_type.is_some_and(is_event_stream) {
            return None;
        }
        let record_id = ctx.metadata.get(MD_RECORD_ID)?.clone();
        if self.capture.streaming == StreamingCapture::Off
            || !self.has_staged_candidate(&ctx.metadata)
        {
            return None;
        }
        // In `sampled` mode the marker alone is not enough: only tee streams
        // that won the sampling roll or that a request-side guardrail flagged
        // (see `stream_tee_wanted`).
        if !self.stream_tee_wanted(&ctx.metadata) {
            return None;
        }
        let sample_hit = self.staged_sample_hit(&ctx.metadata);
        // 2xx SSE is the normal capture path. A non-2xx SSE is teed too when the
        // record will emit anyway — either `always_capture_on_error` is set, or
        // this request won the sampling roll (`emit_decision` emits on `sampled`
        // regardless of status). Error transactions are exactly where operators
        // asked for response evidence, and skipping the inspector for a record
        // that still emits would leave the `log` fallback with request-side data
        // only. (3xx SSE stays untouched: no error trigger, not a completion.)
        let status_eligible = (200..300).contains(&response_status)
            || (response_status >= 400 && (self.sampling.always_on_error || sample_hit));
        if !status_eligible {
            return None;
        }

        let slot = Arc::new(StreamSlot {
            captured: Mutex::new(None),
            downstream_terminated: AtomicBool::new(false),
        });
        Some(Box::new(AuditStreamInspector {
            record_id,
            slot,
            pending_streams: Arc::clone(&self.pending_streams),
            staging: Arc::clone(&self.staging),
            hasher: self.redactor.keyed_hasher(),
            redactor: Arc::clone(&self.redactor),
            mode: self.mode,
            max_bytes: self.limits.max_stream_capture_bytes,
            hash_full_stream: self.limits.hash_full_stream,
            accumulated: Vec::new(),
            hashed_bytes: 0,
            hashing: true,
            truncated: false,
            registered: false,
        }))
    }

    async fn on_response_stream_terminated(
        &self,
        ctx: &mut RequestContext,
        response_status: u16,
        outcome: &crate::proxy::deferred_log::BodyOutcome,
    ) {
        if self.capture.streaming == StreamingCapture::Off {
            return;
        }
        let Some(record_id) = ctx.metadata.get(MD_RECORD_ID).cloned() else {
            return;
        };
        let Some((_, slot)) = self.pending_streams.remove(&record_id) else {
            return; // not a stream we teed
        };
        // The response is no longer active. Normally this hook or the immediate
        // log fallback consumes staging; clearing the marker also ensures an
        // unexpectedly orphaned terminal record can be reclaimed after its TTL.
        if let Some(mut staging) = self.staging.get_mut(&record_id) {
            staging.stream_active = false;
        }
        let downstream_terminated = slot.downstream_terminated.load(Ordering::Relaxed);
        let captured = slot.captured.lock().ok().and_then(|mut guard| guard.take());
        let sample_hit = self
            .staging
            .get(&record_id)
            .map(|staging| staging.sample_hit)
            .unwrap_or_else(|| flag(&ctx.metadata, MD_SAMPLE_HIT));
        let errored = response_status >= 400 || !outcome.body_completed;
        let guardrail = guardrail_fired(&ctx.metadata) || downstream_terminated;
        let (excerpt, truncated, hash, hash_complete, hashed_bytes) = if downstream_terminated {
            (None, true, None, None, None)
        } else {
            match captured {
                Some(captured) => (
                    captured.response_excerpt,
                    captured.response_truncated,
                    Some(captured.response_hash),
                    Some(captured.response_hash_complete),
                    Some(captured.response_hashed_bytes),
                ),
                None => (None, true, None, None, None), // abnormal end: on_end never ran
            }
        };
        if let Some(response_hash) = hash.as_ref() {
            ctx.metadata
                .insert(MD_RESPONSE_HASH.to_string(), response_hash.clone());
        }
        let (emit, reason) = self.emit_decision(sample_hit, guardrail, errored);
        if !emit {
            // Match the buffered path: the response evidence is finalized, but
            // no record was emitted at this hook. Keep staging for the immediate
            // log fallback to consume and mark the sink status non-terminal.
            ctx.metadata
                .insert(MD_SINK_STATUS.to_string(), "deferred".to_string());
            return;
        }

        // A response already being streamed cannot run a new rejecting
        // admission, so stream-terminal enqueue is best-effort.
        let mut staging = self.staging.remove(&record_id).map(|(_, value)| value);
        let envelope = self.envelope_from_ctx(ctx, response_status);
        let record = self.build_record(
            &record_id,
            envelope,
            &ctx.metadata,
            staging.as_ref(),
            excerpt,
            truncated,
            hash,
            hash_complete,
            hashed_bytes,
            sample_hit,
            reason,
            None,
        );
        let status = match self.enqueue(record, staging.as_mut()) {
            SinkOutcome::Queued => "queued",
            SinkOutcome::Dropped => "dropped",
            SinkOutcome::Rejected => "rejected",
        };
        ctx.metadata
            .insert(MD_SINK_STATUS.to_string(), status.to_string());
    }

    // ---- fallback emission ----

    async fn log(&self, summary: &TransactionSummary) {
        if !self.active {
            return;
        }
        let Some(record_id) = summary.metadata.get(MD_RECORD_ID).cloned() else {
            return;
        };
        // Emit here only if no response hook already did (staging still present).
        let Some((_, mut staging)) = self.staging.remove(&record_id) else {
            return;
        };

        let sample_hit = staging.sample_hit;
        let errored = summary.response_status_code >= 400
            || (summary.response_streamed
                && (!summary.body_completed || summary.body_error_class.is_some()));
        let (emit, reason) =
            self.emit_decision(sample_hit, guardrail_fired(&summary.metadata), errored);
        if !emit {
            return;
        }
        let envelope = self.envelope_from_summary(summary);
        // Response body/hash are `None` here: `TransactionSummary` carries no
        // body, and this fallback is the only emission path for a transaction
        // whose response never reached a response-body hook — notably a
        // `before_proxy` short-circuit that returns a non-2xx `RejectBinary`
        // (e.g. `ai_federation` surfacing a provider 4xx/5xx error), since the
        // synthetic response-body hooks only run for 2xx short-circuits. The
        // record still captures the request side plus status and guardrail
        // metadata; capturing those provider error bodies too would need a
        // body-carrying reject hook in the proxy core, out of scope here.
        let record = self.build_record(
            &record_id,
            envelope,
            &summary.metadata,
            Some(&staging),
            None,
            false,
            None,
            None,
            None,
            sample_hit,
            reason,
            None,
        );
        let _ = self.enqueue(record, Some(&mut staging));
    }
}

/// Tees streaming (SSE) response bytes into a bounded accumulator while
/// forwarding every chunk unchanged. Keyed HMAC covers the full stream only
/// when `hash_full_stream` is set; otherwise hashing stops with the capture cap
/// and the digest is domain-separated as partial.
struct AuditStreamInspector {
    record_id: String,
    slot: Arc<StreamSlot>,
    pending_streams: Arc<DashMap<String, Arc<StreamSlot>>>,
    staging: Arc<DashMap<String, AuditStaging>>,
    redactor: Arc<PiiRedactor>,
    mode: AuditMode,
    max_bytes: usize,
    hash_full_stream: bool,
    accumulated: Vec<u8>,
    hasher: KeyedBodyHasher,
    hashed_bytes: u64,
    hashing: bool,
    truncated: bool,
    registered: bool,
}

impl AuditStreamInspector {
    fn ensure_registered(&mut self) {
        if !self.registered {
            self.pending_streams
                .insert(self.record_id.clone(), Arc::clone(&self.slot));
            self.registered = true;
        }
    }

    fn clear_stream_active(&self) {
        if let Some(mut staging) = self.staging.get_mut(&self.record_id) {
            staging.stream_active = false;
        }
    }
}

impl Drop for AuditStreamInspector {
    fn drop(&mut self) {
        // Cancellation / task drop must not leave stream_active pinned forever.
        // Terminal hooks also clear this; clearing twice is harmless.
        self.clear_stream_active();
    }
}

#[async_trait]
impl ResponseStreamInspector for AuditStreamInspector {
    async fn on_chunk(&mut self, chunk: &[u8]) -> ResponseStreamAction {
        self.ensure_registered();
        if self.hashing {
            if self.hash_full_stream {
                self.hasher.update(chunk);
                self.hashed_bytes = self.hashed_bytes.saturating_add(chunk.len() as u64);
            } else {
                let remaining = self
                    .max_bytes
                    .saturating_sub(self.hashed_bytes as usize);
                if remaining > 0 {
                    let take = remaining.min(chunk.len());
                    self.hasher.update(&chunk[..take]);
                    self.hashed_bytes = self.hashed_bytes.saturating_add(take as u64);
                }
                if self.hashed_bytes as usize >= self.max_bytes {
                    self.hashing = false;
                }
            }
        }
        if self.accumulated.len() < self.max_bytes {
            let remaining = self.max_bytes - self.accumulated.len();
            let take = remaining.min(chunk.len());
            self.accumulated.extend_from_slice(&chunk[..take]);
            if take < chunk.len() {
                self.truncated = true;
            }
        } else if !chunk.is_empty() {
            self.truncated = true;
        }
        // Tee: forward the bytes exactly as received, never altering the stream.
        ResponseStreamAction::Forward(Bytes::copy_from_slice(chunk))
    }

    async fn on_end(&mut self) -> ResponseStreamAction {
        self.ensure_registered();
        let hash_complete = self.hash_full_stream || !self.truncated;
        let mut hasher = std::mem::replace(&mut self.hasher, self.redactor.keyed_hasher());
        if !hash_complete {
            hasher.update(PARTIAL_STREAM_HASH_DOMAIN);
            hasher.update(&self.hashed_bytes.to_be_bytes());
        }
        let response_hash = hasher.finalize_hex();
        // A cap-truncated redacted stream can cut through an unbounded secret or
        // a custom pattern, leaving only a raw prefix that no regex can match.
        // Omit the excerpt rather than exporting a boundary fragment. Full-body
        // mode is the explicit raw-capture opt-in and still returns the cap.
        let (response_excerpt, _) = if self.truncated && self.mode.redacts_body() {
            (None, true)
        } else {
            shape_bytes(self.mode, &self.redactor, &self.accumulated, self.max_bytes)
        };
        if let Ok(mut guard) = self.slot.captured.lock() {
            *guard = Some(StreamCaptured {
                response_excerpt,
                response_truncated: self.truncated,
                response_hash,
                response_hash_complete: hash_complete,
                response_hashed_bytes: self.hashed_bytes,
            });
        }
        ResponseStreamAction::Forward(Bytes::new())
    }

    fn on_downstream_terminated(&mut self) {
        self.ensure_registered();
        self.slot
            .downstream_terminated
            .store(true, Ordering::Relaxed);
        if let Ok(mut guard) = self.slot.captured.lock() {
            *guard = None;
        }
    }
}

// ---- sink ----

async fn send_batch(cfg: &HttpFlushConfig, batch: Vec<QueuedAuditRecord>) -> Result<(), String> {
    let entry_count = batch.len();
    let body = assemble_audit_json_array(&batch);
    let mut request = cfg
        .http_client
        .get()
        .post(&cfg.endpoint_url)
        .header(http::header::CONTENT_TYPE, "application/json")
        .body(body);
    for (name, template) in &cfg.custom_headers {
        let value = expand_audit_secret_refs(template)?;
        match HeaderValue::from_str(&value) {
            Ok(header_value) => request = request.header(name.clone(), header_value),
            Err(_) => {
                // Never log the expanded value — it may contain a sink token.
                warn!(
                    header = %name,
                    "ai_transcript_audit: dropping custom header with an invalid value after secret expansion"
                );
            }
        }
    }
    let response = cfg
        .http_client
        .execute(request, "ai_transcript_audit")
        .await;
    // Health tracks the full delivery contract: HTTP status AND a successful
    // bounded acknowledgement-body drain. A 2xx whose body times out, overflows,
    // or resets is a failed batch (retried) and must not advertise a healthy
    // sink to fail-closed admission. Non-retryable 4xx also mark unhealthy so
    // silently discarded batches stop audited traffic. Recovery: the next fully
    // successful batch flips health back to true (rejected traffic still enqueues
    // recovery probes).
    match response {
        Ok(resp) => {
            let status = resp.status();
            let drain = drain_http_batch_response_body(resp).await;
            let delivered =
                status.is_success() && matches!(drain, HttpBatchDrainOutcome::Complete(_));
            cfg.sink_healthy.store(delivered, Ordering::Relaxed);
            classify_audit_batch_response(entry_count, status, drain)
        }
        Err(err) => {
            cfg.sink_healthy.store(false, Ordering::Relaxed);
            Err(format!("ai_transcript_audit batch failed: {err}"))
        }
    }
}

fn classify_audit_batch_response(
    entry_count: usize,
    status: reqwest::StatusCode,
    drain: HttpBatchDrainOutcome,
) -> Result<(), String> {
    if status.is_success() {
        return match drain {
            HttpBatchDrainOutcome::Complete(_) => Ok(()),
            other => Err(format!(
                "ai_transcript_audit batch failed: successful response acknowledgement incomplete ({})",
                other.diagnostic()
            )),
        };
    }

    if status.is_client_error()
        && status != reqwest::StatusCode::REQUEST_TIMEOUT
        && status != reqwest::StatusCode::TOO_MANY_REQUESTS
    {
        warn!(
            "ai_transcript_audit batch discarded due to {} response ({} entries lost); {}",
            status,
            entry_count,
            drain.diagnostic(),
        );
        return Ok(());
    }

    Err(format!(
        "ai_transcript_audit batch failed with status {status}; {}",
        drain.diagnostic()
    ))
}

fn assemble_audit_json_array(batch: &[QueuedAuditRecord]) -> String {
    let capacity = batch.iter().fold(2usize, |total, entry| {
        total.saturating_add(entry.json.len().saturating_add(1))
    });
    let mut body = String::with_capacity(capacity);
    body.push('[');
    for (idx, entry) in batch.iter().enumerate() {
        if idx > 0 {
            body.push(',');
        }
        body.push_str(entry.json.as_ref());
    }
    body.push(']');
    body
}

fn serialize_audit_under_byte_budget(
    budget: &ByteBudget,
    max_entry_bytes: usize,
    record: &AuditRecord,
) -> Option<QueuedAuditRecord> {
    let lease = budget.try_acquire(accounted_summary_bytes(max_entry_bytes))?;
    let mut writer = BoundedJsonWriter::new(max_entry_bytes);
    if let Err(error) = serde_json::to_writer(&mut writer, record) {
        if writer.limit_exceeded {
            budget.record_drop("serialized entry exceeded max_entry_bytes");
        } else {
            warn!("ai_transcript_audit: failed to serialize audit record: {error}");
            budget.record_drop("serialization failed");
        }
        return None;
    }
    let retained = writer.bytes.len();
    if retained > max_entry_bytes {
        budget.record_drop("serialized entry exceeded max_entry_bytes");
        return None;
    }
    lease.shrink_to(accounted_summary_bytes(retained));
    let json = match String::from_utf8(writer.bytes) {
        Ok(line) => Arc::<str>::from(line),
        Err(_) => {
            budget.record_drop("serialized entry was not UTF-8");
            return None;
        }
    };
    Some(QueuedAuditRecord {
        json,
        _lease: lease,
    })
}

/// Test-only lease handle so unit tests can saturate the retained-byte budget.
pub struct AuditByteLeaseGuardForTest {
    _lease: Arc<ByteLease>,
}

// ---- free helpers ----

pub(crate) fn redact_internal_log_metadata(metadata: &mut HashMap<String, String>) {
    let candidate = flag(metadata, MD_CANDIDATE);
    let saturation_outcome = metadata
        .get(MD_SINK_STATUS)
        .is_some_and(|status| matches!(status.as_str(), "dropped" | "rejected"));
    metadata.remove(MD_CANDIDATE);
    metadata.remove(MD_SAMPLE_HIT);
    metadata.remove(MD_STREAM_REQUEST);
    metadata.remove(MD_FINAL_REQ_SEEN);
    metadata.retain(|key, _| !key.starts_with("ai_transcript_audit.stream_marker"));
    if !candidate {
        metadata.remove(MD_RECORD_ID);
        metadata.remove(MD_SAMPLED);
        metadata.remove(MD_REQUEST_HASH);
        metadata.remove(MD_RESPONSE_HASH);
        if !saturation_outcome {
            metadata.remove(MD_SINK_STATUS);
        }
    }
}

fn process_monotonic_seconds() -> u64 {
    static START: OnceLock<Instant> = OnceLock::new();
    START.get_or_init(Instant::now).elapsed().as_secs()
}

fn reject_audit_unavailable() -> PluginResult {
    let mut headers = HashMap::new();
    headers.insert("content-type".to_string(), "application/json".to_string());
    PluginResult::Reject {
        status_code: 503,
        body: r#"{"error":"audit_unavailable","message":"request rejected by ai_transcript_audit: transcript sink unavailable"}"#
            .to_string(),
        headers,
    }
}

/// Shape a captured payload into an excerpt. Returns the shaped excerpt (or
/// `None` for non-body modes) and whether it was truncated.
///
/// For `redacted_body`, work is bounded by `max_bytes`: bodies larger than the
/// export budget omit the excerpt rather than scanning/allocating the full
/// payload (matching truncated stream semantics and avoiding boundary-fragment
/// leaks). `full_body` truncates first by design.
fn shape_bytes(
    mode: AuditMode,
    redactor: &PiiRedactor,
    raw: &[u8],
    max_bytes: usize,
) -> (Option<String>, bool) {
    if !mode.captures_body() {
        return (None, false);
    }
    let truncated = raw.len() > max_bytes;
    if mode.redacts_body() {
        if truncated {
            return (None, true);
        }
        let shaped = redact_body_decoded_json_strings(redactor, raw);
        let shaped = if shaped.len() > max_bytes {
            truncate_on_char_boundary(shaped, max_bytes)
        } else {
            shaped
        };
        return (Some(shaped), false);
    }
    let shaped = String::from_utf8_lossy(&raw[..raw.len().min(max_bytes)]).into_owned();
    (Some(shaped), truncated)
}

fn redact_body_decoded_json_strings(redactor: &PiiRedactor, raw: &[u8]) -> String {
    if let Ok(mut json) = serde_json::from_slice::<Value>(raw) {
        redact_json_value_strings(redactor, &mut json);
        serde_json::to_string(&json)
            .map(|serialized| redactor.redact(&serialized))
            .unwrap_or_else(|_| redactor.redact(&String::from_utf8_lossy(raw)))
    } else if let Some(mut reassembled) = reassemble_openai_sse_deltas(raw) {
        // OpenAI-chunk SSE capture: per-frame redaction would miss PII split
        // across `delta.content` fragments (each frame carries an unmatched
        // piece), so the exported excerpt is the redaction of the REASSEMBLED
        // per-choice completion text, not the raw frames.
        redact_json_value_strings(redactor, &mut reassembled);
        serde_json::to_string(&reassembled)
            .map(|serialized| redactor.redact(&serialized))
            .unwrap_or_else(|_| redactor.redact(&String::from_utf8_lossy(raw)))
    } else if let Some(redacted_sse) = redact_sse_json_frames(redactor, raw) {
        redacted_sse
    } else {
        redactor.redact(&String::from_utf8_lossy(raw))
    }
}

#[derive(Default)]
struct ReassembledToolCall {
    id: String,
    call_type: String,
    name: String,
    arguments: String,
}

#[derive(Default)]
struct ReassembledChoice {
    content: String,
    tool_calls: BTreeMap<u64, ReassembledToolCall>,
    finish_reason: Option<String>,
}

/// Reassemble captured OpenAI `chat.completion.chunk` SSE frames by choice.
/// Text and tool-call fragments are concatenated in frame order, including
/// fragmented arguments, before the caller applies sensitive-field and pattern
/// redaction. Uniformly parseable tool-call-only streams use this path too.
fn reassemble_openai_sse_deltas(raw: &[u8]) -> Option<Value> {
    let text = std::str::from_utf8(raw).ok()?;
    let mut per_choice: BTreeMap<u64, ReassembledChoice> = BTreeMap::new();
    let mut tool_call_choices_seen = BTreeSet::new();
    for line in text.lines() {
        let Some(rest) = line.strip_prefix("data:") else {
            continue;
        };
        let payload = rest.trim();
        if payload.is_empty() || payload == "[DONE]" {
            continue;
        }
        // Every data frame must be a parseable OpenAI chunk; anything else
        // (Anthropic events, provider-specific shapes, partial/corrupt JSON)
        // keeps the raw-frame fallback rather than exporting a lossy guess.
        let frame: Value = serde_json::from_str(payload).ok()?;
        if frame.get("object").and_then(Value::as_str) != Some("chat.completion.chunk") {
            return None;
        }
        let Some(choices) = frame.get("choices").and_then(Value::as_array) else {
            continue;
        };
        for choice in choices {
            let index = choice.get("index").and_then(Value::as_u64).unwrap_or(0);
            let accumulated = per_choice.entry(index).or_default();
            if let Some(finish_reason) = choice.get("finish_reason")
                && !finish_reason.is_null()
            {
                accumulated.finish_reason = Some(finish_reason.as_str()?.to_string());
            }
            let Some(delta) = choice.get("delta") else {
                continue;
            };
            let delta = delta.as_object()?;
            if let Some(content) = delta.get("content")
                && !content.is_null()
            {
                accumulated.content.push_str(content.as_str()?);
            }
            if let Some(tool_calls) = delta.get("tool_calls") {
                let tool_calls = tool_calls.as_array()?;
                let has_indexless_call = tool_calls
                    .iter()
                    .any(|tool_call| tool_call.get("index").is_none());
                if has_indexless_call && tool_call_choices_seen.contains(&index) {
                    // Position is only an unambiguous fallback within one
                    // frame. A later indexless frame could continue any prior
                    // call, so keep the raw-frame redaction path rather than
                    // joining potentially unrelated tool calls.
                    return None;
                }
                tool_call_choices_seen.insert(index);
                for (position, tool_call) in tool_calls.iter().enumerate() {
                    let tool_call = tool_call.as_object()?;
                    let tool_index = match tool_call.get("index") {
                        Some(index) => index.as_u64()?,
                        None => position as u64,
                    };
                    let call = accumulated.tool_calls.entry(tool_index).or_default();
                    if let Some(id) = tool_call.get("id")
                        && !id.is_null()
                    {
                        merge_sse_scalar_fragment(&mut call.id, id.as_str()?);
                    }
                    if let Some(call_type) = tool_call.get("type")
                        && !call_type.is_null()
                    {
                        merge_sse_scalar_fragment(&mut call.call_type, call_type.as_str()?);
                    }
                    if let Some(function) = tool_call.get("function")
                        && !function.is_null()
                    {
                        let function = function.as_object()?;
                        if let Some(name) = function.get("name")
                            && !name.is_null()
                        {
                            merge_sse_scalar_fragment(&mut call.name, name.as_str()?);
                        }
                        if let Some(arguments) = function.get("arguments")
                            && !arguments.is_null()
                        {
                            call.arguments.push_str(arguments.as_str()?);
                        }
                    }
                }
            }
        }
    }
    if !per_choice
        .values()
        .any(|choice| !choice.content.is_empty() || !choice.tool_calls.is_empty())
    {
        return None;
    }
    let mut completion_text = serde_json::Map::new();
    let mut response_tool_calls = serde_json::Map::new();
    let mut finish_reasons = serde_json::Map::new();
    for (choice_index, choice) in per_choice {
        let choice_key = choice_index.to_string();
        if !choice.content.is_empty() {
            completion_text.insert(choice_key.clone(), Value::String(choice.content));
        }
        if !choice.tool_calls.is_empty() {
            let mut calls = Vec::with_capacity(choice.tool_calls.len());
            for (tool_index, call) in choice.tool_calls {
                let mut call_json = serde_json::Map::new();
                call_json.insert("index".to_string(), Value::from(tool_index));
                if !call.id.is_empty() {
                    call_json.insert("id".to_string(), Value::String(call.id));
                }
                if !call.call_type.is_empty() {
                    call_json.insert("type".to_string(), Value::String(call.call_type));
                }
                if !call.name.is_empty() || !call.arguments.is_empty() {
                    let mut function = serde_json::Map::new();
                    if !call.name.is_empty() {
                        function.insert("name".to_string(), Value::String(call.name));
                    }
                    if !call.arguments.is_empty() {
                        function.insert("arguments".to_string(), Value::String(call.arguments));
                    }
                    call_json.insert("function".to_string(), Value::Object(function));
                }
                calls.push(Value::Object(call_json));
            }
            response_tool_calls.insert(choice_key.clone(), Value::Array(calls));
        }
        if let Some(finish_reason) = choice.finish_reason {
            finish_reasons.insert(choice_key, Value::String(finish_reason));
        }
    }
    let mut annotated = serde_json::Map::new();
    annotated.insert("sse_reassembled".to_string(), Value::Bool(true));
    annotated.insert(
        "object".to_string(),
        Value::String("chat.completion.chunk".to_string()),
    );
    if !completion_text.is_empty() {
        annotated.insert(
            "completion_text".to_string(),
            Value::Object(completion_text),
        );
    }
    if !response_tool_calls.is_empty() {
        annotated.insert("tool_calls".to_string(), Value::Object(response_tool_calls));
    }
    if !finish_reasons.is_empty() {
        annotated.insert("finish_reason".to_string(), Value::Object(finish_reasons));
    }
    Some(Value::Object(annotated))
}

fn merge_sse_scalar_fragment(target: &mut String, fragment: &str) {
    if fragment.is_empty() || fragment == target.as_str() || target.ends_with(fragment) {
        return;
    }
    if fragment.starts_with(target.as_str()) {
        target.clear();
        target.push_str(fragment);
    } else {
        target.push_str(fragment);
    }
}

const MAX_JSON_REDACTION_DEPTH: usize = 64;

fn redact_json_value_strings(redactor: &PiiRedactor, value: &mut Value) {
    redact_json_value_strings_at_depth(redactor, value, 0);
}

fn redact_json_value_strings_at_depth(redactor: &PiiRedactor, value: &mut Value, depth: usize) {
    if depth >= MAX_JSON_REDACTION_DEPTH {
        *value = Value::String(REDACTED_PLACEHOLDER.to_string());
        return;
    }
    match value {
        Value::String(text) => {
            // Tool arguments are commonly JSON encoded inside a string. Decode
            // object/array strings before redaction so a sensitive parent key
            // split away from its value cannot bypass the field-name policy.
            if let Ok(mut embedded) = serde_json::from_str::<Value>(text)
                && matches!(embedded, Value::Object(_) | Value::Array(_))
            {
                redact_json_value_strings_at_depth(redactor, &mut embedded, depth + 1);
                if let Ok(serialized) = serde_json::to_string(&embedded) {
                    *text = redactor.redact(&serialized);
                    return;
                }
            }
            *text = redactor.redact(text);
        }
        Value::Number(number) => {
            let raw = number.to_string();
            let redacted = redactor.redact(&raw);
            if redacted != raw {
                *value = Value::String(redacted);
            }
        }
        Value::Array(values) => {
            for value in values {
                redact_json_value_strings_at_depth(redactor, value, depth + 1);
            }
        }
        Value::Object(map) => {
            let entries = std::mem::take(map);
            for (key, mut value) in entries {
                if sensitive_json_field(&key) {
                    value = Value::String(REDACTED_PLACEHOLDER.to_string());
                } else {
                    redact_json_value_strings_at_depth(redactor, &mut value, depth + 1);
                }
                map.insert(redactor.redact(&key), value);
            }
        }
        Value::Null | Value::Bool(_) => {}
    }
}

fn sensitive_json_field(key: &str) -> bool {
    if is_sensitive_metadata_key(key) {
        return true;
    }
    // Collapse case and separators, including zero-width/non-ASCII separators,
    // so `pass_word`, `Pass-Word`, and `pass\u{200b}word` share one policy.
    let compact: String = key
        .chars()
        .filter(|ch| ch.is_ascii_alphanumeric())
        .map(|ch| ch.to_ascii_lowercase())
        .collect();
    [
        "password",
        "passwd",
        "clientsecret",
        "privatekey",
        "authorization",
        "setcookie",
        "sessionid",
        "sessionkey",
        "credential",
        "apikey",
    ]
    .iter()
    .any(|sensitive| compact.contains(sensitive))
        || matches!(
            compact.as_str(),
            "auth"
                | "authentication"
                | "cookie"
                | "session"
                | "secret"
                | "pwd"
                | "token"
                | "accesstoken"
                | "refreshtoken"
                | "authtoken"
                | "idtoken"
                | "apitoken"
                | "bearertoken"
                | "sessiontoken"
                | "csrftoken"
        )
}

fn redact_sse_json_frames(redactor: &PiiRedactor, raw: &[u8]) -> Option<String> {
    let text = std::str::from_utf8(raw).ok()?;
    if !text.lines().any(|line| line.starts_with("data:")) {
        return None;
    }
    let mut changed = false;
    let mut out = String::with_capacity(text.len());
    for line in text.split_inclusive('\n') {
        let (line_no_newline, newline) = match line.strip_suffix('\n') {
            Some(stripped) => (stripped.strip_suffix('\r').unwrap_or(stripped), "\n"),
            None => (line, ""),
        };
        if let Some(rest) = line_no_newline
            .strip_prefix("data: ")
            .or_else(|| line_no_newline.strip_prefix("data:"))
        {
            let trimmed = rest.trim();
            if !trimmed.is_empty()
                && trimmed != "[DONE]"
                && let Ok(mut json) = serde_json::from_str::<Value>(trimmed)
            {
                redact_json_value_strings(redactor, &mut json);
                if let Ok(serialized) = serde_json::to_string(&json) {
                    out.push_str("data: ");
                    out.push_str(&redactor.redact(&serialized));
                    out.push_str(newline);
                    changed = true;
                    continue;
                }
            }
        }
        out.push_str(line);
    }
    changed.then(|| redactor.redact(&out))
}

fn response_body_capture_allowed(
    capture: CaptureConfig,
    response_headers: &HashMap<String, String>,
) -> bool {
    response_headers
        .get("content-type")
        .is_some_and(|content_type| {
            !is_framed_grpc(content_type)
                && (is_json_content_type(content_type)
                    || (capture.streaming != StreamingCapture::Off
                        && is_event_stream(content_type)))
        })
}

/// Truncate `text` to at most `max_bytes` without splitting a UTF-8 code point.
fn truncate_on_char_boundary(mut text: String, max_bytes: usize) -> String {
    if text.len() <= max_bytes {
        return text;
    }
    let mut end = max_bytes;
    while end > 0 && !text.is_char_boundary(end) {
        end -= 1;
    }
    text.truncate(end);
    text
}

fn consumer_name(ctx: &RequestContext) -> Option<String> {
    ctx.identified_consumer
        .as_ref()
        .map(|consumer| consumer.username.clone())
        .or_else(|| ctx.authenticated_identity.clone())
}

fn redact_headers(headers: &HashMap<String, String>) -> BTreeMap<String, String> {
    headers
        .iter()
        .map(|(name, value)| {
            let value = if is_sensitive_metadata_key(name) {
                REDACTED_PLACEHOLDER.to_string()
            } else {
                value.clone()
            };
            (name.clone(), value)
        })
        .collect()
}

/// Whether any guard plugin fired on this transaction (drives
/// `always_capture_on_guardrail`). A curated heuristic over the metadata other
/// AI plugins publish.
fn guardrail_fired(metadata: &HashMap<String, String>) -> bool {
    const FIRED_TRUE_KEYS: &[&str] = &[
        "ai_semantic_firewall_rejected",
        "ai_semantic_firewall_response_blocked",
        "ai_semantic_firewall_streaming_rejected",
        "ai_response_guard_detected",
        "ai_response_guard_rejected",
        "ai_response_guard_redacted",
        "ai_shield_rejected",
        "ai_shield_redacted",
    ];
    if FIRED_TRUE_KEYS.iter().any(|key| {
        metadata
            .get(*key)
            .is_some_and(|value| fired_metadata_value(value))
    }) {
        return true;
    }
    for key in [
        "ai_shield_warnings",
        "ai_response_guard_warning",
        "ai_request_guard.uninspectable_body",
    ] {
        if metadata
            .get(key)
            .is_some_and(|value| fired_metadata_value(value))
        {
            return true;
        }
    }
    if let Some(decision) = metadata
        .get("ai_semantic_firewall.decision")
        .or_else(|| metadata.get("ai_semantic_firewall.action"))
        && !decision.is_empty()
        && !decision.eq_ignore_ascii_case("allow")
    {
        return true;
    }
    for key in [
        "ai_semantic_firewall.request.decision",
        "ai_semantic_firewall.request.action",
        "ai_semantic_firewall.request.would_action",
        "ai_semantic_firewall.response.decision",
        "ai_semantic_firewall.response.action",
        "ai_semantic_firewall.response.would_action",
    ] {
        if let Some(value) = metadata.get(key)
            && !value.is_empty()
            && !value.eq_ignore_ascii_case("allow")
        {
            return true;
        }
    }
    if let Some(decision) = metadata.get("ai_tool_governor.decision")
        && !decision.is_empty()
        && !decision.eq_ignore_ascii_case("allow")
    {
        return true;
    }
    false
}

fn fired_metadata_value(value: &str) -> bool {
    let value = value.trim();
    !value.is_empty() && !value.eq_ignore_ascii_case("false")
}

fn is_guardrail_key(key: &str) -> bool {
    const PREFIXES: &[&str] = &[
        "ai_semantic_firewall",
        "ai_response_guard",
        "ai_prompt_shield",
        "ai_shield",
        "ai_request_guard",
        "ai_ratelimit",
        "ai_federation",
        "ai_tool_governor",
    ];
    PREFIXES.iter().any(|prefix| key.starts_with(prefix))
}

fn extract_model(json: &Value) -> Option<String> {
    json.get("model")
        .and_then(|value| value.as_str())
        .map(str::to_string)
}

fn admit_model(json: &Value, max_chars: usize) -> (Option<String>, bool) {
    let Some(model) = extract_model(json) else {
        return (None, false);
    };
    if model.chars().count() <= max_chars {
        return (Some(model), false);
    }
    let truncated: String = model.chars().take(max_chars).collect();
    (Some(truncated), true)
}

fn extract_tool_names(json: &Value) -> Vec<String> {
    let mut names = Vec::new();
    for key in ["tools", "functions"] {
        if let Some(entries) = json.get(key).and_then(|value| value.as_array()) {
            for entry in entries {
                let name = entry
                    .get("function")
                    .and_then(|function| function.get("name"))
                    .and_then(|name| name.as_str())
                    .or_else(|| entry.get("name").and_then(|name| name.as_str()));
                if let Some(name) = name {
                    names.push(name.to_string());
                }
            }
        }
    }
    names.sort();
    names.dedup();
    names
}

fn admit_tool_names(
    json: &Value,
    max_count: usize,
    max_name_chars: usize,
    max_aggregate_bytes: usize,
) -> (Vec<String>, bool) {
    let raw = extract_tool_names(json);
    let mut out = Vec::new();
    let mut aggregate = 0usize;
    let mut truncated = false;
    for name in raw {
        if out.len() >= max_count {
            truncated = true;
            break;
        }
        let mut admitted = name;
        if admitted.chars().count() > max_name_chars {
            admitted = admitted.chars().take(max_name_chars).collect();
            truncated = true;
        }
        let next = aggregate.saturating_add(admitted.len());
        if next > max_aggregate_bytes {
            truncated = true;
            break;
        }
        aggregate = next;
        out.push(admitted);
    }
    (out, truncated)
}

fn content_digest(bytes: &[u8]) -> [u8; 32] {
    Sha256::digest(bytes).into()
}

fn is_event_stream(content_type: &str) -> bool {
    content_type
        .split(';')
        .next()
        .map(|essence| essence.trim().eq_ignore_ascii_case("text/event-stream"))
        .unwrap_or(false)
}

fn is_framed_grpc(content_type: &str) -> bool {
    crate::proxy::backend_dispatch::is_native_grpc_content_type(content_type.as_bytes())
        || super::grpc_web::is_grpc_web_content_type(content_type)
}

/// Uniform value in `[0, 1)` derived from a record id, so the same request rolls
/// identically across hooks.
fn sample_from_record_id(record_id: &str) -> f64 {
    let digest = Sha256::digest(record_id.as_bytes());
    let mut buffer = [0u8; 8];
    buffer.copy_from_slice(&digest[..8]);
    (u64::from_be_bytes(buffer) as f64) / (u64::MAX as f64 + 1.0)
}

fn flag(metadata: &HashMap<String, String>, key: &str) -> bool {
    metadata.get(key).is_some_and(|value| value == "true")
}

fn bool_str(value: bool) -> String {
    if value { "true" } else { "false" }.to_string()
}

/// Expand `${NAME}` occurrences, but only for the audit-sink secret allowlist
/// (`AUDIT_*` / `FERRUM_AUDIT_*`). Unknown names are rejected; unset allowlisted
/// names fail closed so a missing token cannot become an empty Authorization
/// header. Applied at send time so the resolved secret is never stored in
/// config files; construction already verified each reference is allowlisted
/// and present.
fn expand_audit_secret_refs(template: &str) -> Result<String, String> {
    if !template.contains("${") {
        return Ok(template.to_string());
    }
    let mut out = String::with_capacity(template.len());
    let mut rest = template;
    while let Some(start) = rest.find("${") {
        out.push_str(&rest[..start]);
        let after = &rest[start + 2..];
        if let Some(end) = after.find('}') {
            let name = &after[..end];
            if is_valid_env_name(name) {
                ensure_audit_secret_env_name(name)?;
                match std::env::var(name) {
                    Ok(value) => out.push_str(&value),
                    Err(_) => {
                        return Err(format!(
                            "ai_transcript_audit: sink.custom_headers secret reference \
                             '${{{name}}}' is unset"
                        ));
                    }
                }
                rest = &after[end + 1..];
                continue;
            }
        }
        out.push_str("${");
        rest = after;
    }
    out.push_str(rest);
    Ok(out)
}

fn ensure_audit_secret_env_name(name: &str) -> Result<(), String> {
    if AUDIT_SECRET_ENV_PREFIXES
        .iter()
        .any(|prefix| name.starts_with(prefix))
    {
        Ok(())
    } else {
        Err(format!(
            "ai_transcript_audit: sink.custom_headers may only expand \
             ${{AUDIT_*}} or ${{FERRUM_AUDIT_*}} secret references (got '${{{name}}}')"
        ))
    }
}

fn is_valid_env_name(name: &str) -> bool {
    !name.is_empty()
        && name.bytes().enumerate().all(|(index, byte)| {
            byte == b'_' || byte.is_ascii_alphabetic() || (index > 0 && byte.is_ascii_digit())
        })
}

// ---- config parsing helpers ----

fn reject_nested_unknown_keys(
    parent: &Value,
    key: &str,
    path: &str,
    allowed: &[&str],
) -> Result<(), String> {
    if let Some(Value::Object(map)) = parent.get(key) {
        reject_unknown_keys(map, path, allowed, ERROR_PREFIX)?;
    }
    Ok(())
}

fn default_builtins() -> Vec<String> {
    [
        "ssn",
        "credit_card",
        "email",
        "phone_us",
        "api_key",
        "aws_key",
        "iban",
    ]
    .iter()
    .map(|name| name.to_string())
    .collect()
}

fn parse_custom_patterns(obj: &Value) -> Result<Vec<(String, String)>, String> {
    let Some(value) = obj.get("custom_patterns") else {
        return Ok(Vec::new());
    };
    let entries = value
        .as_array()
        .ok_or("ai_transcript_audit: 'redaction.custom_patterns' must be an array")?;
    let mut out = Vec::with_capacity(entries.len());
    for (index, entry) in entries.iter().enumerate() {
        let path = format!("config.redaction.custom_patterns[{index}]");
        let map = entry
            .as_object()
            .ok_or_else(|| format!("ai_transcript_audit: '{path}' must be an object"))?;
        reject_unknown_keys(
            map,
            &path,
            AI_TRANSCRIPT_AUDIT_CUSTOM_PATTERN_KEYS,
            ERROR_PREFIX,
        )?;
        let name = entry.get("name").and_then(|value| value.as_str()).ok_or_else(|| {
            format!("ai_transcript_audit: redaction.custom_patterns[{index}] requires a string 'name'")
        })?;
        let regex = entry.get("regex").and_then(|value| value.as_str()).ok_or_else(|| {
            format!(
                "ai_transcript_audit: redaction.custom_patterns[{index}] requires a string 'regex'"
            )
        })?;
        out.push((name.to_string(), regex.to_string()));
    }
    Ok(out)
}

fn parse_sink_headers(obj: &Value) -> Result<Vec<(HeaderName, String)>, String> {
    let mut out = Vec::new();
    let Some(value) = obj.get("custom_headers") else {
        return Ok(out);
    };
    let map = value
        .as_object()
        .ok_or("ai_transcript_audit: 'sink.custom_headers' must be an object")?;
    for (key, value) in map {
        let value = value.as_str().ok_or_else(|| {
            format!("ai_transcript_audit: sink.custom_headers['{key}'] must be a string")
        })?;
        let name = HeaderName::from_bytes(key.as_bytes()).map_err(|error| {
            format!("ai_transcript_audit: invalid sink.custom_headers name '{key}': {error}")
        })?;
        validate_sink_header_secret_refs(value)?;
        out.retain(|(existing, _)| *existing != name);
        out.push((name, value.to_string()));
    }
    Ok(out)
}

fn validate_sink_header_secret_refs(template: &str) -> Result<(), String> {
    let mut rest = template;
    while let Some(start) = rest.find("${") {
        let after = &rest[start + 2..];
        let Some(end) = after.find('}') else {
            // Unterminated placeholders are left literal at expansion time.
            break;
        };
        let name = &after[..end];
        if is_valid_env_name(name) {
            ensure_audit_secret_env_name(name)?;
            if std::env::var(name).is_err() {
                return Err(format!(
                    "ai_transcript_audit: sink.custom_headers secret reference \
                     '${{{name}}}' is unset"
                ));
            }
        }
        rest = &after[end + 1..];
    }
    Ok(())
}

fn cfg_object<'a>(config: &'a Value, key: &str, ctx: &str) -> Result<Option<&'a Value>, String> {
    match config.get(key) {
        None | Some(Value::Null) => Ok(None),
        Some(value) if value.is_object() => Ok(Some(value)),
        Some(_) => Err(format!("ai_transcript_audit: '{ctx}' must be an object")),
    }
}

fn cfg_bool(obj: &Value, key: &str, default: bool, ctx: &str) -> Result<bool, String> {
    match obj.get(key) {
        None | Some(Value::Null) => Ok(default),
        Some(Value::Bool(value)) => Ok(*value),
        Some(_) => Err(format!(
            "ai_transcript_audit: '{ctx}.{key}' must be a boolean"
        )),
    }
}

fn cfg_str<'a>(obj: &'a Value, key: &str, ctx: &str) -> Result<Option<&'a str>, String> {
    match obj.get(key) {
        None | Some(Value::Null) => Ok(None),
        Some(Value::String(value)) => Ok(Some(value.as_str())),
        Some(_) => Err(format!(
            "ai_transcript_audit: '{ctx}.{key}' must be a string"
        )),
    }
}

fn cfg_u64(obj: &Value, key: &str, default: u64, ctx: &str) -> Result<u64, String> {
    match obj.get(key) {
        None | Some(Value::Null) => Ok(default),
        Some(value) => value.as_u64().ok_or_else(|| {
            format!("ai_transcript_audit: '{ctx}.{key}' must be a non-negative integer")
        }),
    }
}

fn cfg_f64(obj: &Value, key: &str, default: f64, ctx: &str) -> Result<f64, String> {
    match obj.get(key) {
        None | Some(Value::Null) => Ok(default),
        Some(value) => value
            .as_f64()
            .ok_or_else(|| format!("ai_transcript_audit: '{ctx}.{key}' must be a number")),
    }
}

fn cfg_bounded_usize(
    obj: &Value,
    key: &str,
    default: usize,
    minimum: usize,
    maximum: usize,
    ctx: &str,
) -> Result<usize, String> {
    match obj.get(key) {
        None | Some(Value::Null) => Ok(default),
        Some(value) => {
            let number = value.as_u64().ok_or_else(|| {
                format!("ai_transcript_audit: '{ctx}.{key}' must be a positive integer")
            })?;
            let parsed = usize::try_from(number).map_err(|_| {
                format!("ai_transcript_audit: '{ctx}.{key}' must be between {minimum} and {maximum}")
            })?;
            if parsed < minimum || parsed > maximum {
                return Err(format!(
                    "ai_transcript_audit: '{ctx}.{key}' must be between {minimum} and {maximum}"
                ));
            }
            Ok(parsed)
        }
    }
}

fn cfg_bounded_u64(
    obj: &Value,
    key: &str,
    default: u64,
    minimum: u64,
    maximum: u64,
    ctx: &str,
) -> Result<u64, String> {
    match obj.get(key) {
        None | Some(Value::Null) => Ok(default),
        Some(value) => {
            let number = value.as_u64().ok_or_else(|| {
                format!("ai_transcript_audit: '{ctx}.{key}' must be a positive integer")
            })?;
            if number < minimum || number > maximum {
                return Err(format!(
                    "ai_transcript_audit: '{ctx}.{key}' must be between {minimum} and {maximum}"
                ));
            }
            Ok(number)
        }
    }
}

fn cfg_string_array(obj: &Value, key: &str, ctx: &str) -> Result<Option<Vec<String>>, String> {
    match obj.get(key) {
        None | Some(Value::Null) => Ok(None),
        Some(Value::Array(items)) => {
            let mut out = Vec::with_capacity(items.len());
            for item in items {
                out.push(
                    item.as_str()
                        .ok_or_else(|| {
                            format!(
                                "ai_transcript_audit: '{ctx}.{key}' must be an array of strings"
                            )
                        })?
                        .to_string(),
                );
            }
            Ok(Some(out))
        }
        Some(_) => Err(format!(
            "ai_transcript_audit: '{ctx}.{key}' must be an array of strings"
        )),
    }
}

fn cfg_streaming(obj: &Value, key: &str) -> Result<StreamingCapture, String> {
    match obj.get(key) {
        None | Some(Value::Null) => Ok(StreamingCapture::Off),
        Some(Value::Bool(true)) => Ok(StreamingCapture::On),
        Some(Value::Bool(false)) => Ok(StreamingCapture::Off),
        Some(Value::String(value)) => match value.as_str() {
            "true" => Ok(StreamingCapture::On),
            "false" => Ok(StreamingCapture::Off),
            "sampled" => Ok(StreamingCapture::Sampled),
            other => Err(format!(
                "ai_transcript_audit: 'capture.{key}' must be false, true, or 'sampled' (got {other:?})"
            )),
        },
        Some(_) => Err(format!(
            "ai_transcript_audit: 'capture.{key}' must be a boolean or 'sampled'"
        )),
    }
}

/// Whether a parsed request body looks like an LLM/AI call. Mirrors
/// `ai_rate_limiter::json_looks_like_ai_request`: a strong marker alone
/// qualifies; a generic weak marker qualifies only alongside a top-level
/// `model` field, so ordinary JSON on a shared proxy is not misclassified.
fn json_looks_like_ai_request(json: &Value) -> bool {
    const STRONG_MARKERS: &[&str] = &[
        "messages",
        "contents",
        "chat_history",
        "inputs",
        "inputText",
        "prompt",
        "input",
        "previous_response_id",
    ];
    const WEAK_MARKERS: &[&str] = &["message", "instructions"];
    let Some(object) = json.as_object() else {
        return false;
    };
    if STRONG_MARKERS
        .iter()
        .any(|field| object.contains_key(*field))
    {
        return true;
    }
    object.contains_key("model") && WEAK_MARKERS.iter().any(|field| object.contains_key(*field))
}
