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
//! authorization, but before `request_deduplication` (3010) and reject-capable
//! AI guardrails, so cached replays and blocked prompts can still be audited.
//! It also remains before `ai_semantic_cache` (4057) / `ai_federation` (4060).
//! The audit candidate is staged in `before_proxy` over the
//! prebuffered request body (so terminate-and-respond plugins downstream cannot
//! consume the transaction unaudited, and so the proxy's response buffering /
//! dispatch decisions can see the candidate state).
//!
//! Staging is deliberately cheap: JSON classification, the sampling roll, the
//! `stream` marker, and a bounded staging slot — no hashing, redaction, excerpt
//! shaping, or model/tool extraction. All of that runs exactly once per
//! transaction, in `on_final_request_body_with_context` (or, for a
//! `before_proxy` short-circuit, the reject/synthetic response hooks) over the
//! backend-visible body, and only after cheap capture admission confirms an
//! exportable record is still possible: the sampling roll must be able to emit
//! directly, or remain eligible for an `always_capture_on_*` override. Sampling
//! hits atomically reserve finite `sampling.max_records_per_minute` budget;
//! override-only candidates acquire budget only after the response proves they
//! will emit, so a slow successful request cannot suppress a concurrent error
//! audit. A candidate that cannot be exported therefore costs a
//! classification pass and a staging slot, not a cryptographic pass plus a
//! retained excerpt. The deliberate trade-off is that a candidate whose
//! transaction ends before ANY of those hooks run (e.g. a client disconnect
//! after `before_proxy` but before dispatch) emits its `log`-fallback record
//! without a request hash/excerpt; see the documented limitation in
//! `docs/plugins.md`.
//!
//! This plugin is **not** a security boundary on its own — it observes and
//! redacts, it does not enforce. Pair it with `ai_prompt_shield`,
//! `ai_semantic_firewall`, `ai_response_guard`, and the tool governance in
//! `ai_semantic_firewall` for enforcement.

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::io::Write;
use std::net::IpAddr;
use std::sync::Mutex;
use std::sync::OnceLock;
use std::sync::atomic::{AtomicBool, AtomicU8, AtomicU64, Ordering};
use std::sync::{Arc, Weak};
use std::time::{Duration, Instant};

use async_trait::async_trait;
use bytes::Bytes;
use dashmap::DashMap;
use http::header::{CONTENT_TYPE, HeaderName, HeaderValue};
use serde::Serialize;
use serde_json::Value;
use sha2::{Digest, Sha256};
use tokio::sync::{Notify, OwnedSemaphorePermit, Semaphore};

use super::utils::ai_pii::{KeyedBodyHasher, PiiRedactor};
use super::utils::body_transform::is_json_content_type;
use super::utils::byte_budget::{ByteBudget, ByteLease};
use super::utils::metadata_redaction::{REDACTED_PLACEHOLDER, is_sensitive_metadata_key};
use super::utils::response_body::{
    BoundedReadError, measure_response_body_bounded, read_response_body_bounded,
};
use super::utils::{
    BatchConfig, BatchConfigDefaults, BatchingLoggerPermit, DeferredBatchingLogger,
    HTTP_BATCH_RESPONSE_BODY_LIMIT_BYTES, LoggerHooks, PluginHttpClient, build_batch_config,
    parse_http_endpoint, redacted_endpoint_url_str, validate_batch_config,
};
use super::{
    HTTP_ONLY_PROTOCOLS, Plugin, PluginResult, ProxyProtocol, RequestContext, ResponseStreamAction,
    ResponseStreamHandoff, ResponseStreamInspector, TransactionSummary,
    allocate_response_stream_handoff_id,
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
    "stream_hash",
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
    "max_redaction_scan_bytes",
    "max_entry_bytes",
    "buffer_max_bytes",
    "max_stream_reservation_secs",
];

/// Accepted keys under `privacy`.
pub const AI_TRANSCRIPT_AUDIT_PRIVACY_KEYS: &[&str] = &[
    "include_consumer_username",
    "include_client_ip",
    "include_raw_headers",
    "path_mode",
];

/// Accepted keys under `sink`. `custom_headers` remains an intentional free-form
/// string map (arbitrary header names -> value templates); every other sink
/// property is fixed-shape. Header value templates are literal text plus
/// `${secret:NAME}` references, which resolve only the
/// `FERRUM_TRANSCRIPT_SINK_SECRET_*` env namespace (see [`SINK_SECRET_ENV_PREFIX`]).
pub const AI_TRANSCRIPT_AUDIT_SINK_KEYS: &[&str] = &[
    "type",
    "endpoint_url",
    "allow_insecure_loopback",
    "custom_headers",
    "batch_size",
    "flush_interval_ms",
    "buffer_capacity",
    "max_retries",
    "retry_delay_ms",
    "on_buffer_full",
    "on_sink_error",
    "ack_policy",
    "ack_max_bytes",
    "ack_timeout_ms",
];

/// Env-var namespace that transcript-sink custom headers may reference. A
/// `${secret:NAME}` header-value reference resolves
/// `FERRUM_TRANSCRIPT_SINK_SECRET_<NAME>` only, so a config writer can never
/// expand unrelated Ferrum/database/cloud/system environment variables into an
/// outbound header. There is no generic `${NAME}` process-environment
/// interpolation; any other `${...}` form is rejected at config parse.
const SINK_SECRET_ENV_PREFIX: &str = "FERRUM_TRANSCRIPT_SINK_SECRET_";

/// Deployment-safe hard maximum for `limits.max_request_bytes` (1 MiB). Aligns
/// with the shared logger entry ceiling so a single excerpt cannot exceed what
/// sink byte budgets can sanely retain.
pub const HARD_MAX_REQUEST_BYTES: usize = 1_048_576;
/// Deployment-safe hard maximum for `limits.max_response_bytes` (1 MiB).
pub const HARD_MAX_RESPONSE_BYTES: usize = 1_048_576;
/// Deployment-safe hard maximum for `limits.max_stream_capture_bytes` (1 MiB).
pub const HARD_MAX_STREAM_CAPTURE_BYTES: usize = 1_048_576;
/// Cross-field aggregate hard maximum for the sum of the three capture limits
/// (2 MiB). Prevents an individually-valid triple from retaining an unsafe
/// combined body budget on one record.
pub const HARD_MAX_CAPTURE_BYTES_AGGREGATE: usize = 2_097_152;

/// Hard bound for a retained request-derived `model` string (UTF-8 bytes).
/// Independent of excerpt limits; matches ordinary provider model-id length.
pub const MAX_MODEL_BYTES: usize = 256;
/// Hard bound on how many distinct tool/function names one record retains.
pub const MAX_TOOL_NAMES: usize = 64;
/// Hard bound for each retained tool/function name (UTF-8 bytes).
pub const MAX_TOOL_NAME_BYTES: usize = 128;
/// Hard bound on the aggregate UTF-8 bytes of all retained tool/function names.
pub const MAX_TOOL_NAMES_AGGREGATE_BYTES: usize = 4_096;

/// Hard maximum for `limits.max_redaction_scan_bytes` (8 MiB). Above this a
/// single redacted capture could dominate a worker's CPU/allocation budget no
/// matter how small the exported excerpt limit is.
pub const HARD_MAX_REDACTION_SCAN_BYTES: usize = 8_388_608;
/// Minimum admitted `limits.max_redaction_scan_bytes`. Keeps the bound above
/// any realistic small AI request so an ordinary prompt is never skipped.
pub const MIN_REDACTION_SCAN_BYTES: usize = 4_096;
/// Default hard processing bound for redaction shaping (1 MiB). Bodies larger
/// than this are never parsed/scanned/copied for a redacted excerpt; the
/// excerpt fails closed (omitted with an explicit reason) instead.
pub const DEFAULT_MAX_REDACTION_SCAN_BYTES: usize = 1_048_576;

/// Fixed envelope allowance used to derive the default serialized-entry bound:
/// record id, timestamps, namespace/proxy/consumer/path strings,
/// token/cache/guardrail maps, and JSON field framing.
pub const RECORD_ENVELOPE_OVERHEAD_BYTES: usize = 8_192;
/// Fixed allowance charged for one staged candidate on top of its excerpt and
/// bounded model/tool metadata (record id, hashes, map/vec headers).
pub const STAGING_ENTRY_OVERHEAD_BYTES: usize = 1_024;
/// Attacker-shaped serialized copies charged for one admitted record: its
/// pre-serialized queue payload plus its bytes in the contiguous HTTP batch.
/// The shared logger Arc-shares the queue payload across retries; attempts run
/// sequentially.
pub const RECORD_RETAINED_COPIES: usize = 2;
/// Maximum expansion of one input byte when serde_json escapes it (`\u00XX`).
/// This is used only to derive a default/minimum serialized-entry ceiling from
/// the operator's raw capture-byte contract; actual admission is exact bounded
/// serialization.
pub const JSON_WORST_CASE_EXPANSION: usize = 6;
/// Per-record share of JSON-array framing. Across a non-empty batch, charging
/// one byte to each of two retained copies covers `[` + commas + `]`.
pub const RECORD_BATCH_FRAMING_BYTES: usize = 1;
/// Fixed delivery-state allowance for the queue item, its shared `Bytes`
/// allocation, the shared `Arc<[QueuedAuditRecord]>` batch handle, and lease
/// handles. Attacker-shaped content is charged exactly in addition to this
/// allowance.
pub const RECORD_DELIVERY_OVERHEAD_BYTES: usize = 128;
/// Default aggregate retained-byte budget for one plugin instance (128 MiB),
/// covering staged candidates, pre-commit reservations, and queued records.
///
/// This is deliberately generous relative to the per-record contract: a
/// fail-closed (`on_buffer_full: reject`) deployment reserves worst-case
/// response bytes per in-flight candidate, and the budget must admit a normal
/// concurrency level before it starts refusing. Operators who want a tighter
/// memory ceiling lower `limits.buffer_max_bytes`; those with very large
/// capture limits raise it toward [`HARD_MAX_RETAINED_BUFFER_BYTES`].
pub const DEFAULT_RETAINED_BUFFER_MAX_BYTES: usize = 134_217_728;
/// Hard maximum aggregate retained-byte budget for one plugin instance.
pub const HARD_MAX_RETAINED_BUFFER_BYTES: usize = 268_435_456;
/// Minimum admitted `limits.buffer_max_bytes`. The configured value must also
/// fit the complete retained charge for one maximal serialized record.
pub const MIN_RETAINED_BUFFER_BYTES: usize = 65_536;
/// Hard maximum for `limits.max_entry_bytes`.
pub const HARD_MAX_RECORD_ENTRY_BYTES: usize = 16_777_216;

/// Default bound on how long one active stream may hold a staging entry and its
/// reserved commit permit (15 minutes). Long-lived SSE completions finish well
/// inside this; an abandoned or never-ending stream does not hold a reservation
/// forever.
pub const DEFAULT_MAX_STREAM_RESERVATION_SECS: u64 = 900;
/// Hard maximum for `limits.max_stream_reservation_secs` (24 hours).
pub const HARD_MAX_STREAM_RESERVATION_SECS: u64 = 86_400;
/// Minimum admitted `limits.max_stream_reservation_secs`.
pub const MIN_STREAM_RESERVATION_SECS: u64 = 1;

/// Default bound on the acknowledgement body drained and validated from the
/// collector before sink health is published.
pub const DEFAULT_ACK_MAX_BYTES: usize = 65_536;
/// Hard maximum for `sink.ack_max_bytes`; shares the gateway-wide HTTP batch
/// acknowledgement ceiling so no log sink can read a larger ACK.
pub const HARD_MAX_ACK_BYTES: usize = HTTP_BATCH_RESPONSE_BODY_LIMIT_BYTES;
/// Minimum admitted `sink.ack_max_bytes`.
pub const MIN_ACK_BYTES: usize = 64;
/// Default acknowledgement drain/validate timeout in milliseconds.
pub const DEFAULT_ACK_TIMEOUT_MS: u64 = 1_000;
/// Hard maximum `sink.ack_timeout_ms`; a stalled ACK must never pin the flush
/// worker for longer than this.
pub const MAX_ACK_TIMEOUT_MS: u64 = 30_000;
/// Minimum admitted `sink.ack_timeout_ms`.
pub const MIN_ACK_TIMEOUT_MS: u64 = 1;

/// Domain-separation suffix mixed into a keyed stream digest that covered only
/// a bounded prefix of the response. A capped digest can therefore never be
/// mistaken for — or collide with — a full-stream digest of the same bytes.
const PARTIAL_STREAM_HASH_DOMAIN: &[u8] = b"\x00ferrum-transcript-partial-stream-v1:";

/// `response_hash` covers the complete observed body.
const HASH_SCOPE_FULL: &str = "full";
/// `response_hash` covers only a bounded prefix (see `response_hash_bytes`).
const HASH_SCOPE_PARTIAL: &str = "partial";

/// Body omitted because the raw payload exceeded `limits.max_redaction_scan_bytes`
/// and a safe bounded redaction of it was not possible.
const OMIT_REASON_REDACTION_SCAN_LIMIT: &str = "redaction_scan_limit";
/// Body omitted because a cap-truncated redacted stream could have cut through
/// an unmatched secret prefix.
const OMIT_REASON_STREAM_TRUNCATION: &str = "stream_truncation_boundary";
/// Body omitted because the instance's aggregate retained-byte budget could not
/// admit the refreshed excerpt.
const OMIT_REASON_RETAINED_BYTE_BUDGET: &str = "retained_byte_budget";

/// Hard bound for in-flight request excerpts and permits. At the default
/// fail-open policy, excess candidates are omitted; fail-closed policies reject
/// instead of forwarding a transaction that cannot be staged.
const MAX_STAGING_ENTRIES: usize = 4096;
/// Amortize orphan/reservation cleanup so request admission never repeats a
/// full shared-map scan for every request. Clamped down at construction when
/// `limits.max_stream_reservation_secs` is shorter than twice this interval.
const STAGING_SWEEP_INTERVAL_SECS: u64 = 60;

/// Per-record retained-memory contract (bodies + bounded request-derived
/// metadata). Envelope/tokens/guardrail maps are separately cardinality-bounded
/// by upstream publishers; this captures the operator-visible body+metadata
/// budget one queued record may retain:
/// `max_request_bytes + max(max_response_bytes, max_stream_capture_bytes)
///  + MAX_MODEL_BYTES + MAX_TOOL_NAMES_AGGREGATE_BYTES`.
pub fn max_retained_record_bytes(
    max_request_bytes: usize,
    max_response_bytes: usize,
    max_stream_capture_bytes: usize,
) -> usize {
    max_request_bytes
        .saturating_add(max_response_bytes.max(max_stream_capture_bytes))
        .saturating_add(MAX_MODEL_BYTES)
        .saturating_add(MAX_TOOL_NAMES_AGGREGATE_BYTES)
}

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

/// How much of a streamed response the keyed HMAC covers.
///
/// **Security contract.** The exported `response_hash` is a *tamper-evidence
/// and correlation* token over the transcript this plugin captured — it is not
/// a full-body integrity attestation for the client's byte stream (the plugin
/// forwards bytes it never re-derives, and abnormally terminated or downstream
/// cut streams already omit the hash entirely). `Capped` therefore stops
/// hashing at `limits.max_stream_capture_bytes`, matching the documented
/// retention bound, and marks the digest `partial` with its exact covered byte
/// count plus domain separation. Deployments that genuinely require a
/// full-stream digest (for example an external evidence chain that re-hashes
/// the provider's complete response) opt into `Full` explicitly and accept the
/// unbounded per-byte keyed-hashing cost that comes with it.
#[derive(Clone, Copy, PartialEq, Eq)]
enum StreamHashScope {
    /// Hash the first `limits.max_stream_capture_bytes` only (default).
    Capped,
    /// Hash every streamed byte, however long the stream runs.
    Full,
}

impl StreamHashScope {
    fn as_str(self) -> &'static str {
        match self {
            StreamHashScope::Capped => "capped",
            StreamHashScope::Full => "full",
        }
    }
}

/// How a collector acknowledgement is validated before sink health is published.
#[derive(Clone, Copy, PartialEq, Eq)]
enum AckPolicy {
    /// Read the acknowledgement to EOF under the configured byte bound and
    /// timeout, discarding the bytes. Content is not inspected.
    Drain,
    /// Additionally require the acknowledgement to be a JSON object that does
    /// not report per-record failures.
    Json,
}

impl AckPolicy {
    fn as_str(self) -> &'static str {
        match self {
            AckPolicy::Drain => "drain",
            AckPolicy::Json => "json",
        }
    }
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

/// How the request path is exported. Applications routinely embed emails,
/// account ids, document names, or tokens in path segments, so the literal
/// path is never exported by default in a privacy mode — the safe default is
/// the low-cardinality route identifier (`Template`) for every mode except the
/// explicit `full_body` raw-capture opt-in.
#[derive(Clone, Copy, PartialEq, Eq)]
enum PathMode {
    /// Do not export the path at all.
    Omit,
    /// Export the matched route identifier (proxy `listen_path`, else proxy
    /// name) instead of the user-controlled request path. Omitted when no
    /// route identifier is available.
    Template,
    /// Export the literal path with the configured PII redactor applied.
    Redact,
    /// Export a keyed HMAC-SHA256 hex digest of the literal path (stable
    /// correlation token, not brute-forceable offline; shares the redaction key).
    Hash,
    /// Export the literal path verbatim. Must be opted into explicitly.
    Raw,
}

/// Default path privacy for a capture mode. `full_body` is the deliberate raw
/// capture opt-in, so it defaults to the literal path; every privacy mode
/// defaults to the route identifier so a literal path is never exported by
/// accident under `metadata_only`, `redacted_body`, or `hash_only`.
fn default_path_mode(mode: AuditMode) -> PathMode {
    match mode {
        AuditMode::FullBody => PathMode::Raw,
        _ => PathMode::Template,
    }
}

#[derive(Clone, Copy)]
struct CaptureConfig {
    request: bool,
    response: bool,
    streaming: StreamingCapture,
    headers: bool,
    tool_calls: bool,
    stream_hash: StreamHashScope,
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
    /// Hard processing bound for redacted request classification/extraction and
    /// body shaping. Raw payloads above this are never parsed/scanned/copied.
    max_redaction_scan_bytes: usize,
    /// Per-record serialized JSON admission ceiling.
    max_entry_bytes: usize,
    /// Aggregate retained-byte budget across staging, reservations, and the
    /// queued records of one plugin instance.
    buffer_max_bytes: usize,
    /// Maximum lifetime of one active stream's staging entry + commit permit.
    max_stream_reservation: Duration,
}

impl LimitsConfig {
    fn max_retained_record_bytes(self) -> usize {
        max_retained_record_bytes(
            self.max_request_bytes,
            self.max_response_bytes,
            self.max_stream_capture_bytes,
        )
    }

    /// Minimum admissible serialized `max_entry_bytes`: the coherent
    /// per-record body + bounded-metadata contract plus the fixed envelope
    /// allowance, expanded for worst-case JSON escaping. Actual record
    /// admission uses exact bounded serialization and may be smaller.
    fn min_entry_bytes(self) -> usize {
        max_serialized_record_bytes(
            self.max_retained_record_bytes()
                .saturating_add(RECORD_ENVELOPE_OVERHEAD_BYTES),
        )
    }

    fn max_entry_retained_bytes(self) -> usize {
        accounted_record_bytes(self.max_entry_bytes)
    }
}

/// Conservative serialized ceiling derived from an unescaped byte contract.
pub const fn max_serialized_record_bytes(unescaped_bytes: usize) -> usize {
    unescaped_bytes.saturating_mul(JSON_WORST_CASE_EXPANSION)
}

/// Exact aggregate retained charge for one pre-serialized record while it is
/// queued or flushing. The immutable queue payload is shared by every retry
/// clone; only one exact-capacity contiguous HTTP batch exists at a time.
pub const fn accounted_record_bytes(serialized_bytes: usize) -> usize {
    serialized_bytes
        .saturating_add(RECORD_BATCH_FRAMING_BYTES)
        .saturating_mul(RECORD_RETAINED_COPIES)
        .saturating_add(RECORD_DELIVERY_OVERHEAD_BYTES)
}

/// Acknowledgement drain/validation bounds applied before sink health publishes.
#[derive(Clone, Copy)]
struct AckConfig {
    policy: AckPolicy,
    max_bytes: usize,
    timeout: Duration,
}

/// Authenticated `/health`/`/status` snapshot of admitted capture ceilings.
/// Contains only numeric limits — never request/response content.
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct AiTranscriptAuditSnapshot {
    pub instance_id: u64,
    pub max_request_bytes: u64,
    pub max_response_bytes: u64,
    pub max_stream_capture_bytes: u64,
    pub hard_max_request_bytes: u64,
    pub hard_max_response_bytes: u64,
    pub hard_max_stream_capture_bytes: u64,
    pub hard_max_capture_bytes_aggregate: u64,
    pub max_model_bytes: u64,
    pub max_tool_names: u64,
    pub max_tool_name_bytes: u64,
    pub max_tool_names_aggregate_bytes: u64,
    pub max_retained_record_bytes: u64,
    /// Hard processing bound for redacted-capture shaping.
    pub max_redaction_scan_bytes: u64,
    /// Per-record bounded serialized JSON ceiling.
    pub max_entry_bytes: u64,
    /// Maximum aggregate retained charge for one entry at `max_entry_bytes`.
    pub max_entry_retained_bytes: u64,
    /// Aggregate retained-byte budget for this instance.
    pub buffer_max_bytes: u64,
    /// Aggregate retained bytes currently charged (staging + reservations +
    /// queued records). Live gauge, never content.
    pub retained_bytes: u64,
    /// Admissions refused because the aggregate retained-byte budget was full.
    pub retained_byte_drops: u64,
    /// Maximum lifetime of one active stream's staging entry + commit permit.
    pub max_stream_reservation_secs: u64,
    /// Stream reservations reclaimed by the staging-owned deadline or repair
    /// sweep after exceeding that lifetime. A non-zero value means streams are
    /// outliving their bound.
    pub stream_reservations_expired: u64,
    /// `capped` or `full` — how much of a stream the keyed digest covers.
    pub stream_hash_scope: &'static str,
    /// `drain` or `json` — how a collector acknowledgement is validated.
    pub ack_policy: &'static str,
    pub ack_max_bytes: u64,
    pub ack_timeout_ms: u64,
    /// Whether the last completed batch delivery published a healthy sink.
    pub sink_healthy: bool,
}

#[derive(Clone, Copy)]
struct PrivacyConfig {
    include_consumer_username: bool,
    include_client_ip: bool,
    include_raw_headers: bool,
    path_mode: PathMode,
}

const STREAM_DEADLINE_ARMED: u8 = 0;
const STREAM_DEADLINE_FIRED: u8 = 1;
const STREAM_DEADLINE_CANCELLED: u8 = 2;

/// Single-fire state shared by one active staging entry and its exact deadline
/// task. The staging owner, rather than an optional inspector, defines the
/// reservation lifetime: concrete inspector decline and terminal-to-log
/// handoff paths still retain the same staging/queue/byte capability.
struct StreamReservationDeadlineControl {
    state: AtomicU8,
    cancel: Notify,
}

impl StreamReservationDeadlineControl {
    fn new() -> Self {
        Self {
            state: AtomicU8::new(STREAM_DEADLINE_ARMED),
            cancel: Notify::new(),
        }
    }

    /// Claim the expiry transaction. Exactly one deadline task, repair sweep,
    /// or inspector-side deadline check can win.
    fn try_fire(&self) -> bool {
        self.state
            .compare_exchange(
                STREAM_DEADLINE_ARMED,
                STREAM_DEADLINE_FIRED,
                Ordering::AcqRel,
                Ordering::Acquire,
            )
            .is_ok()
    }

    /// Cancel a still-armed deadline. The state transition makes cancellation
    /// race-safe even when the sleep and notification become ready together.
    fn cancel(&self) -> bool {
        let cancelled = self
            .state
            .compare_exchange(
                STREAM_DEADLINE_ARMED,
                STREAM_DEADLINE_CANCELLED,
                Ordering::AcqRel,
                Ordering::Acquire,
            )
            .is_ok();
        if cancelled {
            self.cancel.notify_one();
        }
        cancelled
    }

    fn is_armed(&self) -> bool {
        self.state.load(Ordering::Acquire) == STREAM_DEADLINE_ARMED
    }
}

/// Cancellation owner stored with [`AuditStaging`]. Removing a completed or
/// discarded staging entry wakes its task promptly instead of leaving one
/// sleeper per completed request until the full reservation age.
struct StreamReservationDeadlineOwner {
    control: Arc<StreamReservationDeadlineControl>,
}

impl Drop for StreamReservationDeadlineOwner {
    fn drop(&mut self) {
        self.control.cancel();
    }
}

/// Per-request request-side capture, keyed by `record_id`. Never holds a full
/// body — only the redacted/capped excerpt (bounded by `max_request_bytes`)
/// plus independently bounded model/tool metadata.
struct AuditStaging {
    /// Holds one slot in the hard in-flight staging bound.
    _staging_permit: OwnedSemaphorePermit,
    /// Aggregate retained-byte lease covering this staged candidate's excerpt
    /// and bounded metadata. Released on every removal path (emit, discard,
    /// TTL sweep, reservation expiry) because the lease drops with the entry.
    retained_lease: Arc<ByteLease>,
    /// Bytes currently charged by `retained_lease` (leases shrink, never grow;
    /// a larger refreshed excerpt re-acquires).
    retained_bytes: usize,
    captured_at: Instant,
    sample_hit: bool,
    request_excerpt: Option<String>,
    request_truncated: bool,
    /// Compiled-in reason the request excerpt was withheld (never a value).
    request_body_omitted_reason: Option<&'static str>,
    request_hash: Option<String>,
    request_model: Option<String>,
    request_model_truncated: bool,
    /// Keyed hash of the original model string when truncated; never raw excess.
    request_model_hash: Option<String>,
    tool_names: Vec<String>,
    tool_names_truncated: bool,
    tool_names_omitted: u32,
    /// Keyed hash over every observed tool name (including omitted) when
    /// truncation/omission occurred; never raw excess bytes.
    tool_names_hash: Option<String>,
    commit_permit: Option<BatchingLoggerPermit<QueuedAuditRecord>>,
    /// Retained-byte reservation (lease, reserved bytes) held alongside
    /// `commit_permit` so a fail-closed admission that promised queue capacity
    /// also promised the bytes that record will retain. Consumed (shrunk to the
    /// exact record size) at enqueue; released with the entry on every other
    /// path.
    commit_lease: Option<(Arc<ByteLease>, usize)>,
    /// True only after the response path confirms that this transaction is
    /// actively streaming. A pre-commit reservation alone is not sufficient:
    /// requests abandoned before stream selection must remain TTL-collectable.
    stream_active: bool,
    /// When `stream_active` was set. The sweeper bounds how long an active
    /// stream may hold this entry and its reserved permit, so a never-ending
    /// or terminal-hook-losing stream cannot pin capacity forever.
    stream_active_since: Option<Instant>,
    /// Authoritative reservation deadline owner. Armed at the first active
    /// response selection and retained until this staging entry is actually
    /// consumed, discarded, or expired — including the normal terminal
    /// non-emitting handoff to transaction logging.
    stream_deadline: Option<StreamReservationDeadlineOwner>,
    /// Set once [`AiTranscriptAudit::capture_request`] has run for this record
    /// against a backend-visible body — whether it captured or deliberately
    /// skipped. The request keyed HMAC, excerpt, and model/tool extraction are
    /// therefore performed at most once per transaction; the later refresh
    /// hooks (reject path, synthetic short-circuit) are no-ops once set instead
    /// of re-hashing the same bytes just to discover they are unchanged.
    captured: bool,
    /// Fixed-cardinality reason capture was skipped before doing any expensive
    /// work ([`CAPTURE_SKIP_NOT_SAMPLED`] / [`CAPTURE_SKIP_RATE_LIMITED`]).
    /// `Some` means this record can never be exported, so `enqueue` drops it
    /// rather than shipping a hash-less, body-less envelope.
    capture_skipped: Option<&'static str>,
    /// Finite-window limiter slot reserved at capture admission. `enqueue`
    /// commits it (so queue-full/sink drops still consume budget, matching the
    /// historical acquire-before-`try_send` order); Drop releases an
    /// uncommitted reservation when the candidate is discarded, loses staging,
    /// expires, or does not emit.
    rate_reservation: Option<RateLimitReservation>,
}

impl AuditStaging {
    /// Cancel the exact deadline before a normal consumer uses this staging
    /// capability. Returns false if expiry already claimed it, in which case
    /// the caller must drop the entry without emitting or transferring owners.
    fn cancel_stream_deadline(&mut self) -> bool {
        let Some(owner) = self.stream_deadline.take() else {
            return true;
        };
        owner.control.cancel()
    }
}

/// Response bytes captured by the streaming inspector, handed to
/// `on_response_stream_terminated` for record assembly (which has `ctx` and so
/// can harvest response-side guardrail metadata).
struct StreamCaptured {
    response_excerpt: Option<String>,
    response_truncated: bool,
    response_body_omitted_reason: Option<&'static str>,
    response_hash: String,
    /// `full` when the digest covered every streamed byte, `partial` when it
    /// stopped at the configured stream-hash bound.
    response_hash_scope: &'static str,
    /// Exact number of response bytes the digest covered.
    response_hash_bytes: u64,
}

/// Mutable audit-only work for one live response stream. It lives behind the
/// slot mutex so the reservation sweeper can synchronously take and drop both
/// the retained bytes and keyed hasher before releasing the corresponding
/// staging/queue accounting.
struct StreamCaptureWork {
    accumulated: Vec<u8>,
    hasher: KeyedBodyHasher,
    hashed_bytes: u64,
    hash_capped: bool,
    truncated: bool,
    redaction_scan_limited: bool,
}

/// Ownership state shared by the stream task, terminal hook, and sweeper.
///
/// The mutex is deliberately scoped to this one stream. It is taken once per
/// inspected chunk because prompt cross-task revocation cannot be implemented
/// while the `Vec` and HMAC stay exclusively inspector-owned; the sweeper must
/// be able to take and drop them even when no later chunk arrives. There is no
/// allocation or global lock added to the chunk path, and the only contending
/// writer is the one-shot expiry/terminal transition.
enum StreamCaptureLifecycle {
    Active(StreamCaptureWork),
    Complete(Option<StreamCaptured>),
    /// `hashed_bytes` is retained for external lifecycle probes after expiry
    /// revokes capture; production emission paths only match on the variant.
    Revoked {
        #[allow(dead_code)] // read by AuditStreamCaptureProbe in external tests
        hashed_bytes: u64,
    },
    Claimed,
}

/// Response-side capture handed to `build_record`. Bundled so every emission
/// path (buffered, stream-terminal, log fallback) carries the same evidence
/// fields and cannot drift apart.
#[derive(Default)]
struct ResponseCapture {
    excerpt: Option<String>,
    truncated: bool,
    omitted_reason: Option<&'static str>,
    hash: Option<String>,
    hash_scope: Option<&'static str>,
    hash_bytes: Option<u64>,
}

struct StreamSlot {
    capture: Mutex<StreamCaptureLifecycle>,
    /// Sampling roll copied from this instance's staging entry when the
    /// inspector is created. It becomes the body-free terminal capability only
    /// after expiry has revoked capture and released the staging owner.
    ///
    /// A shared metadata marker can never populate this field: inspector
    /// creation requires `owned_sample_hit`, and `claim_terminal` consumes the
    /// slot exactly once.
    sample_hit: bool,
    /// Worst-case retained-record lease acquired before the inspector can copy
    /// response bytes. Fail-closed streams already hold the same reservation
    /// in `AuditStaging`, so only fail-open streams need a slot-owned lease.
    ///
    /// Normal terminal enqueue transfers this lease into staging; expiry takes
    /// and drops it immediately after revocation, before the staging owner is
    /// released.
    record_lease: Mutex<Option<(Arc<ByteLease>, usize)>>,
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
    /// True after the deadline owner or repair sweep cleared all audit
    /// capture/hash work.
    revoked: AtomicBool,
    /// True only after the response inspector reaches its drop boundary.
    inspector_dropped: AtomicBool,
    /// Set after expiry removes the live slot from the global map. A revoked
    /// fallback handoff may be published only after this transition, otherwise
    /// a concurrent remove could erase the newly published marker.
    detached_after_revocation: AtomicBool,
    /// Single-fire guard for the tiny drop-time fallback handoff.
    fallback_published: AtomicBool,
    /// Production inspectors publish into request-owned completion state.
    /// `false` exists only for external tests that call the plugin factory
    /// directly without the core response-stream wrapper.
    uses_request_handoff: bool,
    /// Bounds entries while they are reachable from the process-global live
    /// map. Production expiry/terminal claim removes the entry before releasing
    /// this permit; request-owned terminal handoffs need no global capacity.
    pending_permit: Mutex<Option<OwnedSemaphorePermit>>,
}

enum ClaimedStreamCapture {
    Captured(StreamCaptured),
    Abnormal,
    Revoked,
}

impl StreamSlot {
    fn lock_capture(&self) -> std::sync::MutexGuard<'_, StreamCaptureLifecycle> {
        match self.capture.lock() {
            Ok(capture) => capture,
            Err(poisoned) => poisoned.into_inner(),
        }
    }

    /// Revoke audit work before reservation accounting is released. Returns
    /// false when the terminal hook already claimed the slot.
    fn revoke(&self) -> bool {
        let prior = {
            let mut capture = self.lock_capture();
            let hashed_bytes = match &*capture {
                StreamCaptureLifecycle::Active(work) => work.hashed_bytes,
                StreamCaptureLifecycle::Complete(Some(captured)) => captured.response_hash_bytes,
                StreamCaptureLifecycle::Complete(None) => 0,
                StreamCaptureLifecycle::Revoked { .. } | StreamCaptureLifecycle::Claimed => {
                    return false;
                }
            };
            std::mem::replace(
                &mut *capture,
                StreamCaptureLifecycle::Revoked { hashed_bytes },
            )
        };
        // Drop the Vec, completed excerpt/hash, and keyed hasher before the
        // caller removes staging and releases any byte/queue reservations.
        drop(prior);
        self.revoked.store(true, Ordering::Release);
        true
    }

    fn finish_abnormally(&self) {
        let prior = {
            let mut capture = self.lock_capture();
            if !matches!(&*capture, StreamCaptureLifecycle::Active(_)) {
                return;
            }
            std::mem::replace(&mut *capture, StreamCaptureLifecycle::Complete(None))
        };
        drop(prior);
    }

    fn claim_terminal(&self) -> Option<ClaimedStreamCapture> {
        let prior = {
            let mut capture = self.lock_capture();
            if matches!(&*capture, StreamCaptureLifecycle::Active(_))
                && !self.inspector_dropped.load(Ordering::Acquire)
            {
                // Production terminal hooks wait for inspector completion.
                // Preserve that ownership boundary for direct callers too: an
                // inspector that is still live and never saw on_end has not
                // produced a terminal result to claim.
                return None;
            }
            if matches!(&*capture, StreamCaptureLifecycle::Claimed) {
                return None;
            }
            std::mem::replace(&mut *capture, StreamCaptureLifecycle::Claimed)
        };
        Some(match prior {
            StreamCaptureLifecycle::Complete(Some(captured)) => {
                ClaimedStreamCapture::Captured(captured)
            }
            StreamCaptureLifecycle::Revoked { .. } => ClaimedStreamCapture::Revoked,
            StreamCaptureLifecycle::Active(_) | StreamCaptureLifecycle::Complete(None) => {
                ClaimedStreamCapture::Abnormal
            }
            StreamCaptureLifecycle::Claimed => return None,
        })
    }

    fn mark_downstream_terminated(&self) {
        self.downstream_terminated.store(true, Ordering::Relaxed);
        let prior = {
            let mut capture = self.lock_capture();
            if matches!(
                &*capture,
                StreamCaptureLifecycle::Revoked { .. } | StreamCaptureLifecycle::Claimed
            ) {
                return;
            }
            std::mem::replace(&mut *capture, StreamCaptureLifecycle::Complete(None))
        };
        drop(prior);
    }

    fn release_pending_permit(&self) {
        let mut permit = match self.pending_permit.lock() {
            Ok(permit) => permit,
            Err(poisoned) => poisoned.into_inner(),
        };
        permit.take();
    }

    fn take_record_lease(&self) -> Option<(Arc<ByteLease>, usize)> {
        let mut lease = match self.record_lease.lock() {
            Ok(lease) => lease,
            Err(poisoned) => poisoned.into_inner(),
        };
        lease.take()
    }

    #[allow(dead_code)] // used only by external tests; dead in binary target
    fn capture_snapshot(&self) -> AuditStreamCaptureSnapshot {
        let capture = self.lock_capture();
        match &*capture {
            StreamCaptureLifecycle::Active(work) => AuditStreamCaptureSnapshot {
                retained_capture_bytes: work.accumulated.len() as u64,
                hashed_bytes: work.hashed_bytes,
                revoked: false,
                terminal_claimed: false,
            },
            StreamCaptureLifecycle::Complete(Some(captured)) => AuditStreamCaptureSnapshot {
                retained_capture_bytes: captured.response_excerpt.as_deref().map_or(0, str::len)
                    as u64,
                hashed_bytes: captured.response_hash_bytes,
                revoked: false,
                terminal_claimed: false,
            },
            StreamCaptureLifecycle::Complete(None) => AuditStreamCaptureSnapshot {
                retained_capture_bytes: 0,
                hashed_bytes: 0,
                revoked: false,
                terminal_claimed: false,
            },
            StreamCaptureLifecycle::Revoked { hashed_bytes } => AuditStreamCaptureSnapshot {
                retained_capture_bytes: 0,
                hashed_bytes: *hashed_bytes,
                revoked: true,
                terminal_claimed: false,
            },
            StreamCaptureLifecycle::Claimed => AuditStreamCaptureSnapshot {
                retained_capture_bytes: 0,
                hashed_bytes: 0,
                revoked: self.revoked.load(Ordering::Acquire),
                terminal_claimed: true,
            },
        }
    }
}

/// Read-only test probe for one inspector-owned capture lifecycle. It holds a
/// weak reference so tests cannot extend the production state lifetime.
#[doc(hidden)]
#[allow(dead_code)] // constructed only by external tests; dead in binary target
pub struct AuditStreamCaptureProbe {
    slot: Weak<StreamSlot>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[doc(hidden)]
#[allow(dead_code)] // constructed only by external tests; dead in binary target
pub struct AuditStreamCaptureSnapshot {
    pub retained_capture_bytes: u64,
    pub hashed_bytes: u64,
    pub revoked: bool,
    pub terminal_claimed: bool,
}

impl AuditStreamCaptureProbe {
    #[doc(hidden)]
    #[allow(dead_code)] // used only by external tests; dead in binary target
    pub fn snapshot(&self) -> Option<AuditStreamCaptureSnapshot> {
        self.slot.upgrade().map(|slot| slot.capture_snapshot())
    }
}

fn publish_revoked_fallback_if_ready(
    record_id: &str,
    slot: &Arc<StreamSlot>,
    pending_streams: &DashMap<String, Arc<StreamSlot>>,
) {
    if slot.uses_request_handoff
        || !slot.revoked.load(Ordering::Acquire)
        || !slot.inspector_dropped.load(Ordering::Acquire)
        || !slot.detached_after_revocation.load(Ordering::Acquire)
        || slot
            .fallback_published
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .is_err()
    {
        return;
    }
    // Serialize publication with `claim_terminal`: without this lifecycle
    // guard, a direct-factory terminal caller could claim/remove the slot
    // between the compare-exchange above and this insert, leaving a claimed
    // tombstone in the bounded global map. Production uses request handoff,
    // but the compatibility path must retain the same single-consumer rule.
    let capture = slot.lock_capture();
    if !matches!(&*capture, StreamCaptureLifecycle::Revoked { .. }) {
        return;
    }
    // This marker owns no transcript bytes, hash state, staging lease, or
    // commit permit. It is published only at actual inspector drop and is
    // consumed immediately after the completion signal. This direct-factory
    // compatibility path retains its live-map permit until terminal claim.
    pending_streams.insert(record_id.to_string(), Arc::clone(slot));
    drop(capture);
}

fn expire_stream_reservation(
    record_id: &str,
    pending_streams: &DashMap<String, Arc<StreamSlot>>,
    staging: &DashMap<String, AuditStaging>,
    stream_reservations_expired: &AtomicU64,
    max_reservation: Duration,
) -> bool {
    // Claim the staging-owned single-fire token before touching either map.
    // Normal staging consumers race this same state to CANCELLED; whichever
    // transition wins owns the capability and the loser must not emit,
    // transfer, or resurrect it.
    let deadline = {
        let Some(entry) = staging.get(record_id) else {
            return false;
        };
        if !entry.stream_active {
            return false;
        }
        let Some(owner) = entry.stream_deadline.as_ref() else {
            return false;
        };
        Arc::clone(&owner.control)
    };
    if !deadline.try_fire() {
        return false;
    }

    // Resolve the slot only after winning expiry. Selection can be active
    // without any concrete inspector, while an inspector can also be installed
    // after selection and before this deadline fires.
    let slot = pending_streams
        .get(record_id)
        .map(|entry| Arc::clone(entry.value()));
    if let Some(slot) = slot.as_ref() {
        // Synchronously drop the live Vec, completed excerpt/hash, and HMAC
        // before releasing any staging, queue, or retained-byte owner.
        let revoked = slot.revoke() || slot.revoked.load(Ordering::Acquire);
        pending_streams.remove_if(record_id, |_, current| Arc::ptr_eq(current, slot));
        if slot.uses_request_handoff {
            slot.release_pending_permit();
        }
        // Fail-open streams own their retained-record reservation in the slot;
        // fail-closed streams release the equivalent staging-owned reservation
        // below. Both happen only after capture/HMAC revocation.
        drop(slot.take_record_lease());
        if revoked {
            slot.detached_after_revocation
                .store(true, Ordering::Release);
            publish_revoked_fallback_if_ready(record_id, slot, pending_streams);
        }
    }

    // If a normal terminal consumer removed the entry after expiry won the
    // token, its cancellation attempt observes FIRED and drops the capability
    // without emission. Either way, this expiry is counted exactly once.
    drop(staging.remove_if(record_id, |_, staging| staging.stream_active));
    let total = stream_reservations_expired
        .fetch_add(1, Ordering::Relaxed)
        .saturating_add(1);
    tracing::warn!(
        plugin = "ai_transcript_audit",
        expired = 1_u64,
        total_expired = total,
        max_reservation_secs = max_reservation.as_secs(),
        "ai_transcript_audit: reclaimed a streaming audit reservation that exceeded \
         limits.max_stream_reservation_secs"
    );
    true
}

/// A single exported audit record. It exists only during bounded record
/// assembly; queue publication converts it into [`QueuedAuditRecord`].
#[derive(Serialize)]
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
    /// Request path, transformed per `privacy.path_mode` (omitted, route
    /// identifier, redacted, keyed hash, or raw). Absent when omitted or when
    /// `template` mode has no route identifier available.
    #[serde(skip_serializing_if = "Option::is_none")]
    path: Option<String>,
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
    /// `full` or `partial` — how much of the observed response the keyed
    /// `response_hash` covers. Present whenever `response_hash` is.
    #[serde(skip_serializing_if = "Option::is_none")]
    response_hash_scope: Option<&'static str>,
    /// Exact byte count the keyed `response_hash` covers.
    #[serde(skip_serializing_if = "Option::is_none")]
    response_hash_bytes: Option<u64>,
    request_body_truncated: bool,
    response_body_truncated: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    request_body: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    response_body: Option<String>,
    /// Compiled-in reason a body excerpt was withheld (never a captured value).
    #[serde(skip_serializing_if = "Option::is_none")]
    request_body_omitted_reason: Option<&'static str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    response_body_omitted_reason: Option<&'static str>,
    #[serde(skip_serializing_if = "BTreeMap::is_empty")]
    tokens: BTreeMap<String, String>,
    #[serde(skip_serializing_if = "BTreeMap::is_empty")]
    cache: BTreeMap<String, String>,
    #[serde(skip_serializing_if = "BTreeMap::is_empty")]
    guardrails: BTreeMap<String, String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    tool_names: Vec<String>,
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    model_truncated: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    model_hash: Option<String>,
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    tool_names_truncated: bool,
    #[serde(skip_serializing_if = "is_zero_u32")]
    tool_names_omitted: u32,
    #[serde(skip_serializing_if = "Option::is_none")]
    tool_names_hash: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    headers: Option<BTreeMap<String, String>>,
}

/// One bounded, pre-serialized audit record retained by the batching queue.
///
/// `Bytes` keeps the queued payload immutable and cheap to share. The shared
/// logger hands every flush attempt and the failed-batch hook an `Arc` clone of
/// the same batch slice — never a deep clone of attacker-shaped strings/maps/
/// vectors. The lease remains live across queueing, exact-capacity batch
/// assembly, the HTTP request, retries, and the failed-batch hook.
#[derive(Clone)]
struct QueuedAuditRecord {
    json: Bytes,
    _lease: Arc<ByteLease>,
}

impl QueuedAuditRecord {
    fn as_bytes(&self) -> &[u8] {
        &self.json
    }
}

/// Allocation-free first pass for exact bounded JSON serialization.
///
/// Counting before allocation makes JSON escaping/framing part of admission,
/// and lets the second pass allocate exactly the bytes it will retain. This
/// avoids both Vec growth slack and an unbounded `serde_json::to_vec` temporary.
struct BoundedJsonCounter {
    bytes: usize,
    max_bytes: usize,
    limit_exceeded: bool,
}

impl BoundedJsonCounter {
    fn new(max_bytes: usize) -> Self {
        Self {
            bytes: 0,
            max_bytes,
            limit_exceeded: false,
        }
    }
}

impl Write for BoundedJsonCounter {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        let Some(next) = self.bytes.checked_add(buf.len()) else {
            self.limit_exceeded = true;
            return Err(std::io::Error::other(
                "serialized audit record exceeded its byte limit",
            ));
        };
        if next > self.max_bytes {
            self.limit_exceeded = true;
            return Err(std::io::Error::other(
                "serialized audit record exceeded its byte limit",
            ));
        }
        self.bytes = next;
        Ok(buf.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

fn is_zero_u32(value: &u32) -> bool {
    *value == 0
}

#[derive(Default)]
struct BoundedModel {
    value: Option<String>,
    truncated: bool,
    hash: Option<String>,
}

#[derive(Default)]
struct BoundedToolNames {
    names: Vec<String>,
    truncated: bool,
    omitted: u32,
    hash: Option<String>,
}

/// Capture was skipped because the sampling roll lost and no override
/// (`always_capture_on_guardrail` / `always_capture_on_error`) is configured,
/// so `emit_decision` can never emit for this record.
const CAPTURE_SKIP_NOT_SAMPLED: &str = "not_sampled";
/// Capture was skipped because `sampling.max_records_per_minute` had no budget
/// left in the current window when the backend-visible body became known.
const CAPTURE_SKIP_RATE_LIMITED: &str = "rate_limited";

/// Which request body a staging/capture call is looking at.
#[derive(Clone, Copy, PartialEq, Eq)]
enum BodyPhase {
    /// The pre-`before_proxy` buffered body. Request transforms have not run
    /// yet, so it is only classified (AI shape, `stream`) — never hashed,
    /// redacted, excerpted, or harvested.
    Provisional,
    /// The backend/provider-visible body. The single point where expensive
    /// capture work is worth paying for.
    Final,
}

/// Expensive request-side capture derived from the FINAL backend-visible body.
/// Built outside the staging map's shard guard so redaction/hashing never runs
/// while a `DashMap` shard lock is held.
#[derive(Default)]
struct RequestCapture {
    /// Keyed HMAC-SHA256 of the backend-visible request body. `None` only when
    /// `skipped` is set — never a stale digest from an earlier body.
    hash: Option<String>,
    excerpt: Option<String>,
    truncated: bool,
    /// Compiled-in reason the request excerpt was withheld (never a value).
    omitted_reason: Option<&'static str>,
    model: BoundedModel,
    tools: BoundedToolNames,
    skipped: Option<&'static str>,
    /// Limiter slot reserved before expensive work when admission succeeded.
    /// Moved onto [`AuditStaging`]; Drop releases it if staging never accepts it.
    rate_reservation: Option<RateLimitReservation>,
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
    /// Literal request path (never exported directly; transformed by
    /// `privacy.path_mode` in `build_record`).
    path: String,
    /// Low-cardinality route identifier for `path_mode = template`: the matched
    /// proxy `listen_path` (else proxy name). `None` when unavailable.
    route_template: Option<String>,
    status_code: u16,
}

#[derive(Default)]
struct Harvest {
    model: Option<String>,
    model_truncated: bool,
    model_hash: Option<String>,
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

/// Length of one records-per-minute window, in seconds.
const RECORDS_WINDOW_SECONDS: u64 = 60;

/// Largest admissible effective `max_records_per_minute`. The in-window count
/// lives in the low 32 bits of the packed limiter state, so the ceiling is
/// clamped below `u32::MAX` and the counter can never wrap.
const MAX_RECORDS_PER_WINDOW: u64 = (u32::MAX as u64) - 1;

/// Fixed-window records-per-minute limiter. `max == 0` means unlimited.
///
/// Lock-free by design: the window index and the in-window count are packed
/// into one `AtomicU64` (`window << 32 | count`) and advanced by CAS. Capture
/// admission **reserves** a slot on the request path — before any hashing,
/// redaction, or excerpt work — so concurrent candidates cannot all observe
/// headroom and pay capture cost beyond the configured ceiling. A mutex here
/// would add a hot-path lock. Windows are anchored to the process-monotonic
/// clock.
struct RecordsPerMinute {
    max_per_minute: u64,
    state: AtomicU64,
}

/// RAII token for one reserved records-per-minute slot.
///
/// Created by [`RecordsPerMinute::try_reserve`] before expensive capture work.
/// [`Self::commit`] consumes the slot without releasing (enqueue / sink-drop
/// path). Drop releases an uncommitted reservation, but only while the token's
/// window is still the current window — an older-window release never
/// decrements the live counter.
struct RateLimitReservation {
    slot: Option<RateLimitSlot>,
}

struct RateLimitSlot {
    limiter: Arc<RecordsPerMinute>,
    window: u64,
}

impl RateLimitReservation {
    /// Consume the reservation without returning budget. Used when an
    /// exportable record reaches enqueue (including queue-full/sink drops,
    /// which historically acquired before `try_send`).
    fn commit(mut self) {
        self.slot = None;
    }
}

impl Drop for RateLimitReservation {
    fn drop(&mut self) {
        if let Some(slot) = self.slot.take() {
            slot.limiter.release(slot.window);
        }
    }
}

impl RecordsPerMinute {
    fn new(max_per_minute: u64) -> Self {
        Self {
            max_per_minute: max_per_minute.min(MAX_RECORDS_PER_WINDOW),
            state: AtomicU64::new(0),
        }
    }

    fn current_window() -> u64 {
        process_monotonic_seconds() / RECORDS_WINDOW_SECONDS
    }

    fn unpack(state: u64) -> (u64, u64) {
        (state >> 32, state & u32::MAX as u64)
    }

    fn pack(window: u64, count: u64) -> u64 {
        (window << 32) | (count & u32::MAX as u64)
    }

    /// Atomically reserve one slot in the current window for upcoming capture
    /// work. `None` means the window is saturated. Unlimited (`max == 0`)
    /// returns an empty reservation that neither increments nor releases.
    fn try_reserve(self: &Arc<Self>) -> Option<RateLimitReservation> {
        if self.max_per_minute == 0 {
            return Some(RateLimitReservation { slot: None });
        }
        let mut observed = self.state.load(Ordering::Relaxed);
        loop {
            let now = Self::current_window();
            let (window, count) = Self::unpack(observed);
            let count = if window == now { count } else { 0 };
            if count >= self.max_per_minute {
                return None;
            }
            match self.state.compare_exchange_weak(
                observed,
                Self::pack(now, count.saturating_add(1)),
                Ordering::AcqRel,
                Ordering::Relaxed,
            ) {
                Ok(_) => {
                    return Some(RateLimitReservation {
                        slot: Some(RateLimitSlot {
                            limiter: Arc::clone(self),
                            window: now,
                        }),
                    });
                }
                Err(actual) => observed = actual,
            }
        }
    }

    /// Release an uncommitted reservation from `window`. No-op when the live
    /// window has already advanced past `window`, so stale releases cannot
    /// inflate the current window's budget.
    fn release(&self, window: u64) {
        if self.max_per_minute == 0 {
            return;
        }
        let mut observed = self.state.load(Ordering::Relaxed);
        loop {
            let now = Self::current_window();
            if window != now {
                return;
            }
            let (state_window, count) = Self::unpack(observed);
            if state_window != now || count == 0 {
                return;
            }
            match self.state.compare_exchange_weak(
                observed,
                Self::pack(now, count - 1),
                Ordering::AcqRel,
                Ordering::Relaxed,
            ) {
                Ok(_) => return,
                Err(actual) => observed = actual,
            }
        }
    }

    /// Late acquire for the rare path that reaches enqueue without a
    /// capture-time reservation (transaction ended before any request-side
    /// capture hook). Identical CAS shape to [`Self::try_reserve`].
    fn try_acquire(self: &Arc<Self>) -> bool {
        self.try_reserve()
            .map(RateLimitReservation::commit)
            .is_some()
    }
}

#[derive(Clone)]
struct HttpFlushConfig {
    /// Complete configured URL. Used **only** to build the outbound request; a
    /// collector may legitimately carry a reusable credential in its path or
    /// query.
    endpoint_url: String,
    /// Structurally redacted rendering of [`Self::endpoint_url`] for every
    /// diagnostic surface: egress denial, DNS/TLS/connect failure, retry,
    /// slow-call, and batch-failure error strings.
    endpoint_url_for_logs: String,
    /// Fully materialized outbound headers, resolved once at background-task
    /// activation from [`CustomHeaderSpec`]s (secrets marked sensitive so they
    /// are never logged). Empty until `start_background_tasks` publishes the
    /// materialized set; the hot send path never re-parses templates or reads
    /// the environment per batch, and there is no fallible per-field
    /// construction that could skip a header and send anyway.
    custom_headers: Arc<Vec<(HeaderName, HeaderValue)>>,
    http_client: PluginHttpClient,
    sink_healthy: Arc<AtomicBool>,
    /// Acknowledgement bound/timeout/validation applied before health publishes.
    ack: AckConfig,
}

/// One segment of a custom-header value template.
enum HeaderSegment {
    /// Literal text validated as header-value-safe at config parse.
    Literal(String),
    /// A `${secret:NAME}` reference; holds the fully-qualified env var name
    /// (`FERRUM_TRANSCRIPT_SINK_SECRET_<NAME>`), resolved at activation only.
    Secret(String),
}

/// A parsed, statically-validated custom outbound header. The value is a
/// template of literal and secret segments; the secret is materialized once at
/// activation (never stored resolved in config, never logged).
struct CustomHeaderSpec {
    name: HeaderName,
    /// Original header-name text for diagnostics (never the secret value).
    display_name: String,
    segments: Vec<HeaderSegment>,
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
    /// Statically-validated custom header templates. Materialized into
    /// `flush_config.custom_headers` at `start_background_tasks`, so a missing/
    /// empty/invalid secret or header value fails activation (the generation is
    /// never published) rather than being silently skipped at send time.
    custom_header_specs: Vec<CustomHeaderSpec>,
    logger: DeferredBatchingLogger<QueuedAuditRecord>,
    endpoint_hostname: String,
    namespace: String,
    staging: Arc<DashMap<String, AuditStaging>>,
    staging_permits: Arc<Semaphore>,
    /// Aggregate retained-byte budget covering staged candidates, pre-commit
    /// reservations, and queued records. Record-count capacity alone cannot
    /// bound attacker-shaped payload retention.
    retained_budget: Arc<ByteBudget>,
    /// Stream reservations reclaimed by the staging-owned deadline or repair
    /// sweep after exceeding the configured maximum reservation age.
    stream_reservations_expired: Arc<AtomicU64>,
    pending_streams: Arc<DashMap<String, Arc<StreamSlot>>>,
    /// Independent hard bound for inspector slots while they are reachable
    /// from the process-global live map. Request-owned terminal handoffs never
    /// consume this capacity.
    pending_stream_permits: Arc<Semaphore>,
    stream_handoff_id: u64,
    rate_limiter: Arc<RecordsPerMinute>,
    sink_healthy: Arc<AtomicBool>,
    /// `true` when at least one capture path is enabled (validated in `new`).
    active: bool,
    staging_ttl: Duration,
    /// Amortization interval between staging sweeps. Normally
    /// [`STAGING_SWEEP_INTERVAL_SECS`], but never longer than half the
    /// configured stream-reservation bound — a 60s sweep would make a short
    /// `limits.max_stream_reservation_secs` meaningless.
    staging_sweep_interval_secs: u64,
    /// Monotonic process-relative second at which another staging sweep may run.
    next_staging_sweep_at: AtomicU64,
    /// Number of expensive request captures performed (one keyed HMAC over the
    /// request body, plus redaction/excerpt/model/tool work, each). Kept as a
    /// plain relaxed counter — never exported to logs, records, or the status
    /// snapshot — so the "one HMAC per transaction" and
    /// "no capture work for records that cannot be emitted" invariants are
    /// externally observable instead of only reviewable.
    request_captures: AtomicU64,
    /// Number of captures skipped by early admission (see
    /// [`CAPTURE_SKIP_NOT_SAMPLED`] / [`CAPTURE_SKIP_RATE_LIMITED`]).
    request_captures_skipped: AtomicU64,
    /// Process-local id published into authenticated `/health` after commit.
    status_id: OnceLock<u64>,
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
        let stream_hash_value = cfg_str(capture_obj, "stream_hash", "capture")?.unwrap_or("capped");
        let stream_hash = match stream_hash_value {
            "capped" => StreamHashScope::Capped,
            "full" => StreamHashScope::Full,
            other => {
                return Err(format!(
                    "ai_transcript_audit: 'capture.stream_hash' must be 'capped' or 'full' \
                     (got {other:?})"
                ));
            }
        };
        let capture = CaptureConfig {
            request: cfg_bool(capture_obj, "request", true, "capture")?,
            response: cfg_bool(capture_obj, "response", true, "capture")?,
            streaming,
            headers: cfg_bool(capture_obj, "headers", false, "capture")?,
            tool_calls: cfg_bool(capture_obj, "tool_calls", true, "capture")?,
            stream_hash,
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
        let limits = admit_limits_config(limits_obj)?;

        // ---- privacy ----
        reject_nested_unknown_keys(
            config,
            "privacy",
            "config.privacy",
            AI_TRANSCRIPT_AUDIT_PRIVACY_KEYS,
        )?;
        let privacy_obj = cfg_object(config, "privacy", "privacy")?.unwrap_or(&empty);
        let path_mode = match cfg_str(privacy_obj, "path_mode", "privacy")? {
            Some("omit") => PathMode::Omit,
            Some("template") => PathMode::Template,
            Some("redact") => PathMode::Redact,
            Some("hash") => PathMode::Hash,
            Some("raw") => PathMode::Raw,
            Some(other) => {
                return Err(format!(
                    "ai_transcript_audit: 'privacy.path_mode' must be one of omit, template, \
                     redact, hash, raw (got {other:?})"
                ));
            }
            None => default_path_mode(mode),
        };
        // `redact` path mode with an empty pattern set would export the literal
        // path unchanged while claiming redaction — the same silent
        // pass-through the body-redaction guard rejects. `hash_only`/`full_body`
        // are exempt from that body guard, so re-check here for the path.
        if path_mode == PathMode::Redact && builtins.is_empty() && custom.is_empty() {
            return Err(
                "ai_transcript_audit: 'privacy.path_mode: redact' requires at least one \
                 'redaction.builtins' or 'redaction.custom_patterns' pattern; otherwise the \
                 literal path would be exported unredacted — use 'omit', 'template', or 'hash'"
                    .to_string(),
            );
        }
        let privacy = PrivacyConfig {
            include_consumer_username: cfg_bool(
                privacy_obj,
                "include_consumer_username",
                true,
                "privacy",
            )?,
            include_client_ip: cfg_bool(privacy_obj, "include_client_ip", false, "privacy")?,
            include_raw_headers: cfg_bool(privacy_obj, "include_raw_headers", false, "privacy")?,
            path_mode,
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
        let custom_header_specs = parse_sink_headers(sink_obj)?;
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

        // ---- acknowledgement contract ----
        // Sink health must never be published from response headers alone: a
        // 2xx whose acknowledgement stalls, overruns its bound, or fails
        // transport is an ambiguous delivery, and under `on_sink_error: reject`
        // fail-closed admission would otherwise keep admitting traffic against
        // a demonstrably failing collector.
        let ack_policy = match cfg_str(sink_obj, "ack_policy", "sink")?.unwrap_or("drain") {
            "drain" => AckPolicy::Drain,
            "json" => AckPolicy::Json,
            other => {
                return Err(format!(
                    "ai_transcript_audit: 'sink.ack_policy' must be 'drain' or 'json' \
                     (got {other:?})"
                ));
            }
        };
        let ack_max_bytes = cfg_positive_usize_capped(
            sink_obj,
            "ack_max_bytes",
            DEFAULT_ACK_MAX_BYTES,
            "sink",
            HARD_MAX_ACK_BYTES,
        )?;
        if ack_max_bytes < MIN_ACK_BYTES {
            return Err(format!(
                "ai_transcript_audit: 'sink.ack_max_bytes' must be >= {MIN_ACK_BYTES}"
            ));
        }
        let ack_timeout_ms = cfg_u64(sink_obj, "ack_timeout_ms", DEFAULT_ACK_TIMEOUT_MS, "sink")?;
        if !(MIN_ACK_TIMEOUT_MS..=MAX_ACK_TIMEOUT_MS).contains(&ack_timeout_ms) {
            return Err(format!(
                "ai_transcript_audit: 'sink.ack_timeout_ms' must be between \
                 {MIN_ACK_TIMEOUT_MS} and {MAX_ACK_TIMEOUT_MS}"
            ));
        }
        let ack = AckConfig {
            policy: ack_policy,
            max_bytes: ack_max_bytes,
            timeout: Duration::from_millis(ack_timeout_ms),
        };

        // ---- deferred background worker ----
        let shard_amount = http_client.pool_shard_amount();
        let sink_healthy = Arc::new(AtomicBool::new(true));
        let flush_config = HttpFlushConfig {
            endpoint_url_for_logs: redacted_endpoint_url_str(&endpoint_url),
            endpoint_url,
            // Materialized from `custom_header_specs` at `start_background_tasks`.
            custom_headers: Arc::new(Vec::new()),
            http_client,
            sink_healthy: Arc::clone(&sink_healthy),
            ack,
        };
        let batch_config = build_batch_config(sink_obj, "ai_transcript_audit", batch_defaults)?;

        let staging_sweep_interval_secs = STAGING_SWEEP_INTERVAL_SECS
            .min(limits.max_stream_reservation.as_secs() / 2)
            .max(1);
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
            custom_header_specs,
            logger: DeferredBatchingLogger::new(),
            endpoint_hostname,
            namespace,
            staging: Arc::new(DashMap::with_shard_amount(shard_amount)),
            staging_permits: Arc::new(Semaphore::new(MAX_STAGING_ENTRIES)),
            retained_budget: Arc::new(ByteBudget::new_observability(
                "ai_transcript_audit",
                limits.buffer_max_bytes,
            )),
            stream_reservations_expired: Arc::new(AtomicU64::new(0)),
            pending_streams: Arc::new(DashMap::with_shard_amount(shard_amount)),
            pending_stream_permits: Arc::new(Semaphore::new(MAX_STAGING_ENTRIES)),
            stream_handoff_id: allocate_response_stream_handoff_id(),
            rate_limiter: Arc::new(RecordsPerMinute::new(sampling.max_records_per_minute)),
            sink_healthy,
            active,
            staging_ttl: Duration::from_secs(60 * 60),
            staging_sweep_interval_secs,
            next_staging_sweep_at: AtomicU64::new(0),
            request_captures: AtomicU64::new(0),
            request_captures_skipped: AtomicU64::new(0),
            status_id: OnceLock::new(),
        })
    }

    /// `(captures_performed, captures_skipped)` — see [`Self::request_captures`].
    #[allow(dead_code)] // used only by external tests; dead in binary test target
    pub fn capture_counters(&self) -> (u64, u64) {
        (
            self.request_captures.load(Ordering::Relaxed),
            self.request_captures_skipped.load(Ordering::Relaxed),
        )
    }

    /// Effective admitted capture ceilings for authenticated status / tests.
    #[allow(dead_code)] // used only by external tests; dead in binary test target
    pub fn status_snapshot(&self) -> AiTranscriptAuditSnapshot {
        self.status_snapshot_for_id(self.status_id.get().copied().unwrap_or(0))
    }

    /// Obtain a weak, read-only probe for focused external lifecycle tests.
    /// Production code never calls this and the probe cannot retain the slot.
    #[doc(hidden)]
    #[allow(dead_code)] // used only by external tests; dead in binary target
    pub fn stream_capture_probe(&self, ctx: &RequestContext) -> Option<AuditStreamCaptureProbe> {
        let record_id = ctx.metadata.get(MD_RECORD_ID)?;
        self.pending_streams
            .get(record_id)
            .map(|slot| AuditStreamCaptureProbe {
                slot: Arc::downgrade(slot.value()),
            })
    }

    fn status_snapshot_for_id(&self, instance_id: u64) -> AiTranscriptAuditSnapshot {
        AiTranscriptAuditSnapshot {
            instance_id,
            max_request_bytes: self.limits.max_request_bytes as u64,
            max_response_bytes: self.limits.max_response_bytes as u64,
            max_stream_capture_bytes: self.limits.max_stream_capture_bytes as u64,
            hard_max_request_bytes: HARD_MAX_REQUEST_BYTES as u64,
            hard_max_response_bytes: HARD_MAX_RESPONSE_BYTES as u64,
            hard_max_stream_capture_bytes: HARD_MAX_STREAM_CAPTURE_BYTES as u64,
            hard_max_capture_bytes_aggregate: HARD_MAX_CAPTURE_BYTES_AGGREGATE as u64,
            max_model_bytes: MAX_MODEL_BYTES as u64,
            max_tool_names: MAX_TOOL_NAMES as u64,
            max_tool_name_bytes: MAX_TOOL_NAME_BYTES as u64,
            max_tool_names_aggregate_bytes: MAX_TOOL_NAMES_AGGREGATE_BYTES as u64,
            max_retained_record_bytes: self.limits.max_retained_record_bytes() as u64,
            max_redaction_scan_bytes: self.limits.max_redaction_scan_bytes as u64,
            max_entry_bytes: self.limits.max_entry_bytes as u64,
            max_entry_retained_bytes: self.limits.max_entry_retained_bytes() as u64,
            buffer_max_bytes: self.limits.buffer_max_bytes as u64,
            retained_bytes: self.retained_budget.used() as u64,
            retained_byte_drops: self.retained_budget.drops_total(),
            max_stream_reservation_secs: self.limits.max_stream_reservation.as_secs(),
            stream_reservations_expired: self.stream_reservations_expired.load(Ordering::Relaxed),
            stream_hash_scope: self.capture.stream_hash.as_str(),
            ack_policy: self.flush_config.ack.policy.as_str(),
            ack_max_bytes: self.flush_config.ack.max_bytes as u64,
            ack_timeout_ms: self.flush_config.ack.timeout.as_millis() as u64,
            sink_healthy: self.sink_healthy.load(Ordering::Relaxed),
        }
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

    fn enqueue(&self, record: AuditRecord, mut staging: Option<&mut AuditStaging>) -> SinkOutcome {
        // Capture admission already decided this record cannot be exported (the
        // limiter window was saturated when the backend-visible body became
        // known), so the request side was never hashed/excerpted. Drop it here
        // rather than shipping a body-less, hash-less envelope if the window
        // happened to roll over in the meantime, and do not consume limiter
        // budget that a fully-captured record could still use.
        let precluded = match staging.as_ref() {
            Some(staged) => staged.capture_skipped.is_some(),
            None => false,
        };
        if precluded {
            return SinkOutcome::Dropped;
        }
        // Prefer the capture-time reservation: committing it consumes the slot
        // without a second CAS. Queue-full / sink drops after this point still
        // keep the slot (historical acquire-before-`try_send` semantics). The
        // late `try_acquire` path covers transactions that reach enqueue
        // without any request-side capture hook.
        match staging
            .as_mut()
            .and_then(|staged| staged.rate_reservation.take())
        {
            Some(reservation) => reservation.commit(),
            None => {
                if !self.rate_limiter.try_acquire() {
                    return SinkOutcome::Dropped;
                }
            }
        }
        let (permit, staged_lease) = match staging {
            Some(staging) => {
                // Record fields are already copied out of staging. Release the
                // staging byte lease before taking a fail-open delivery
                // reservation so peak charge is not staging + provisional.
                if staging.commit_lease.is_none() {
                    staging.retained_lease.shrink_to(0);
                    staging.retained_bytes = 0;
                }
                (staging.commit_permit.take(), staging.commit_lease.take())
            }
            None => (None, None),
        };
        let provisional = self.limits.max_entry_retained_bytes();
        let lease = match staged_lease {
            // Fail-closed admission reserves the full serialized-entry charge,
            // so later metadata growth cannot turn an admitted response into an
            // under-accounted enqueue.
            Some((lease, reserved)) if reserved >= provisional => lease,
            Some((lease, _)) => {
                drop(lease);
                drop(permit);
                self.retained_budget
                    .record_drop("record reservation was below the serialized-entry charge");
                return self.saturated_outcome();
            }
            // Fail-open admission takes the worst-case lease before
            // serialization, then shrinks it to the exact immutable payload.
            None => match self.retained_budget.try_acquire(provisional) {
                Some(lease) => lease,
                None => {
                    drop(permit);
                    return self.saturated_outcome();
                }
            },
        };

        let mut counter = BoundedJsonCounter::new(self.limits.max_entry_bytes);
        if serde_json::to_writer(&mut counter, &record).is_err() {
            self.retained_budget.record_drop(if counter.limit_exceeded {
                "serialized record exceeded limits.max_entry_bytes"
            } else {
                "record serialization failed"
            });
            drop(permit);
            return self.saturated_outcome();
        }
        let serialized_bytes = counter.bytes;
        if serialized_bytes > self.limits.max_entry_bytes {
            self.retained_budget
                .record_drop("serialized record exceeded limits.max_entry_bytes");
            drop(permit);
            return self.saturated_outcome();
        }
        let exact_charge = accounted_record_bytes(serialized_bytes);
        if exact_charge > provisional {
            self.retained_budget
                .record_drop("serialized record exceeded its retained-byte reservation");
            drop(permit);
            return self.saturated_outcome();
        }
        lease.shrink_to(exact_charge);
        let mut json = Vec::with_capacity(serialized_bytes);
        if serde_json::to_writer(&mut json, &record).is_err() || json.len() != serialized_bytes {
            self.retained_budget
                .record_drop("record serialization changed between bounded passes");
            drop(permit);
            return self.saturated_outcome();
        }
        let queued = QueuedAuditRecord {
            json: Bytes::from(json),
            _lease: lease,
        };

        if let Some(permit) = permit {
            permit.send(queued);
            return SinkOutcome::Queued;
        }
        if self.logger.try_send(queued) {
            SinkOutcome::Queued
        } else {
            self.saturated_outcome()
        }
    }

    /// Shared saturation verdict for the queue and the retained-byte budget:
    /// fail-open configurations drop, fail-closed configurations reject.
    fn saturated_outcome(&self) -> SinkOutcome {
        if self.on_buffer_full == BufferFullPolicy::Reject {
            SinkOutcome::Rejected
        } else {
            SinkOutcome::Dropped
        }
    }

    /// Reserve the complete retained charge a record may consume at the
    /// admitted serialized-entry ceiling. Paired with the queue permit so a
    /// promise of capacity is a promise of both a slot and every attacker-shaped
    /// byte the queue, shared retry batch, and HTTP request can retain;
    /// `enqueue` shrinks it after exact bounded serialization.
    fn reserve_commit_lease(&self) -> Option<(Arc<ByteLease>, usize)> {
        let projected = self.limits.max_entry_retained_bytes();
        self.retained_budget
            .try_acquire(projected)
            .map(|lease| (lease, projected))
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
        let sample_hit = {
            let Some(mut staging) = self.staging.get_mut(&record_id) else {
                return PluginResult::Continue;
            };
            if !self.commit_may_emit(staging.sample_hit) {
                return PluginResult::Continue;
            }
            let sample_hit = staging.sample_hit;

            if self.on_buffer_full == BufferFullPolicy::Reject && staging.commit_permit.is_none() {
                let Some(permit) = self.logger.try_reserve() else {
                    ctx.metadata
                        .insert(MD_SINK_STATUS.to_string(), "rejected".to_string());
                    return reject_audit_unavailable();
                };
                // Both halves of the promise or neither: dropping `permit` here
                // returns the queue slot.
                let Some(reservation) = self.reserve_commit_lease() else {
                    ctx.metadata
                        .insert(MD_SINK_STATUS.to_string(), "rejected".to_string());
                    return reject_audit_unavailable();
                };
                staging.commit_permit = Some(permit);
                staging.commit_lease = Some(reservation);
            }
            sample_hit
        };
        self.ensure_sink_error_admission_for_sample(ctx, sample_hit)
    }

    /// Fail closed on a known-unhealthy sink without taking a full-entry
    /// reservation. Used on the request path when buffer reservation is
    /// deferred to a later response/stream gate.
    fn ensure_sink_error_admission(&self, ctx: &mut RequestContext) -> PluginResult {
        let Some(record_id) = ctx.metadata.get(MD_RECORD_ID) else {
            return PluginResult::Continue;
        };
        let Some(staging) = self.staging.get(record_id) else {
            return PluginResult::Continue;
        };
        let sample_hit = staging.sample_hit;
        drop(staging);
        self.ensure_sink_error_admission_for_sample(ctx, sample_hit)
    }

    fn ensure_sink_error_admission_for_sample(
        &self,
        ctx: &mut RequestContext,
        sample_hit: bool,
    ) -> PluginResult {
        if !self.commit_may_emit(sample_hit) {
            return PluginResult::Continue;
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

    /// Whether request-phase hooks must leave fail-closed *buffer* reservation
    /// to a later response-side gate.
    ///
    /// Ordinary buffered JSON responses reserve in `on_final_response_body`
    /// before the response becomes immutable. Active streaming capture reserves
    /// at response-header / inspector selection. Request-only configs, and
    /// conservative maybe-streaming markers when streaming capture is off, still
    /// reserve on the request path because no later buffered/stream gate will.
    /// Sink-health rejection still runs on the request path even when
    /// reservation is deferred.
    fn defer_commit_admission_to_response(&self, ctx: &RequestContext) -> bool {
        let response_side_hooks =
            self.capture.response || self.capture.streaming != StreamingCapture::Off;
        if flag(&ctx.metadata, MD_STREAM_REQUEST)
            && self.capture.streaming != StreamingCapture::Off
            && response_side_hooks
        {
            return true;
        }
        self.capture.response && !flag(&ctx.metadata, MD_STREAM_REQUEST)
    }

    /// Request-phase fail-closed gate: full reservation when no later response
    /// /stream gate will admit, otherwise sink-health rejection only.
    fn request_phase_commit_admission(&self, ctx: &mut RequestContext) -> PluginResult {
        if self.defer_commit_admission_to_response(ctx) {
            self.ensure_sink_error_admission(ctx)
        } else {
            self.ensure_commit_admission(ctx)
        }
    }

    fn stream_commit_selected(
        &self,
        ctx: &RequestContext,
        _response_status: u16,
        _content_type: Option<&str>,
    ) -> bool {
        if self.capture.streaming == StreamingCapture::Off || !flag(&ctx.metadata, MD_CANDIDATE) {
            return false;
        }
        // Ownership is proven by a local staging entry only — never by the
        // shared peer-writable `MD_SAMPLE_HIT` key (see `owned_sample_hit`).
        let Some(sample_hit) = self.owned_sample_hit(&ctx.metadata) else {
            return false;
        };
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

    fn stream_inspector_selected(
        &self,
        ctx: &RequestContext,
        response_status: u16,
        content_type: Option<&str>,
    ) -> bool {
        if !content_type.is_some_and(is_event_stream)
            || self.capture.streaming == StreamingCapture::Off
            || !self.has_staged_candidate(&ctx.metadata)
            || !self.stream_tee_wanted(&ctx.metadata)
        {
            return false;
        }
        let Some(sample_hit) = self.owned_sample_hit(&ctx.metadata) else {
            return false;
        };
        (200..300).contains(&response_status)
            || (response_status >= 400 && (self.sampling.always_on_error || sample_hit))
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
            let Some(reservation) = self.reserve_commit_lease() else {
                ctx.metadata
                    .insert(MD_SINK_STATUS.to_string(), "rejected".to_string());
                return reject_audit_unavailable();
            };
            staging.commit_permit = Some(permit);
            staging.commit_lease = Some(reservation);
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

    /// Mark the first active response selection and attach the reservation's
    /// one authoritative exact deadline to staging. This covers non-SSE
    /// responses and every concrete-inspector admission decline as well as
    /// successfully installed inspectors.
    fn arm_stream_reservation(&self, record_id: &str) {
        let started = Instant::now();
        let max_reservation = self.limits.max_stream_reservation;
        let deadline_at = started.checked_add(max_reservation).unwrap_or(started);
        let control = {
            let Some(mut staging) = self.staging.get_mut(record_id) else {
                return;
            };
            if staging.stream_active {
                return;
            }
            let control = Arc::new(StreamReservationDeadlineControl::new());
            staging.stream_active = true;
            staging.stream_active_since = Some(started);
            staging.stream_deadline = Some(StreamReservationDeadlineOwner {
                control: Arc::clone(&control),
            });
            control
        };

        // Production stream selection runs inside a Tokio runtime. If a direct
        // caller has no runtime, the same staging-owned token remains available
        // to the bounded repair sweep.
        let Ok(runtime) = tokio::runtime::Handle::try_current() else {
            return;
        };
        let deadline_record_id = record_id.to_string();
        let deadline_pending_streams = Arc::clone(&self.pending_streams);
        let deadline_staging = Arc::clone(&self.staging);
        let deadline_expired = Arc::clone(&self.stream_reservations_expired);
        let sleep_for = deadline_at.saturating_duration_since(Instant::now());
        let wait_control = Arc::clone(&control);
        let _deadline_task = runtime.spawn(async move {
            tokio::select! {
                _ = tokio::time::sleep(sleep_for) => {
                    expire_stream_reservation(
                        &deadline_record_id,
                        &deadline_pending_streams,
                        &deadline_staging,
                        &deadline_expired,
                        max_reservation,
                    );
                }
                _ = wait_control.cancel.notified() => {}
            }
        });
    }

    /// Atomically consume staging for a normal emission/fallback path and
    /// cancel its exact deadline before transferring any permit or byte lease.
    /// If expiry already won, drop the removed entry and expose no capability.
    fn take_staging_for_consumption(&self, record_id: &str) -> Option<AuditStaging> {
        let (_, mut staging) = self.staging.remove(record_id)?;
        staging.cancel_stream_deadline().then_some(staging)
    }

    /// Reclaim staging entries whose owner will never return: orphaned
    /// candidates past `staging_ttl`, and active-stream entries that have held
    /// a reserved commit permit longer than `limits.max_stream_reservation`.
    ///
    /// The sweep runs on an amortized interval (normally 60s, shortened for a
    /// smaller stream-reservation limit) but is no longer gated on a 512-entry
    /// high-water mark: a handful of never-ending streams can exhaust the
    /// reserved queue slots without ever approaching that threshold, so an
    /// entry-count gate would let the leak the bound exists to stop pass
    /// through untouched. Every scan is bounded by [`MAX_STAGING_ENTRIES`].
    fn sweep_staging(&self) {
        if self.staging.is_empty() {
            return;
        }
        let now_seconds = process_monotonic_seconds();
        let next = self.next_staging_sweep_at.load(Ordering::Relaxed);
        if now_seconds < next
            || self
                .next_staging_sweep_at
                .compare_exchange(
                    next,
                    now_seconds.saturating_add(self.staging_sweep_interval_secs),
                    Ordering::AcqRel,
                    Ordering::Relaxed,
                )
                .is_err()
        {
            return;
        }
        let now = Instant::now();
        let ttl = self.staging_ttl;
        let max_reservation = self.limits.max_stream_reservation;
        // First collect only ids while holding staging shard read guards. Slot
        // revocation and map removals happen afterward, so no cross-DashMap
        // lock order exists.
        let expired_stream_ids: Vec<String> = self
            .staging
            .iter()
            .filter(|entry| {
                let staging = entry.value();
                if !staging.stream_active {
                    return false;
                }
                let started = staging.stream_active_since.unwrap_or(staging.captured_at);
                now.duration_since(started) >= max_reservation
            })
            .map(|entry| entry.key().clone())
            .collect();
        for record_id in expired_stream_ids {
            expire_stream_reservation(
                &record_id,
                &self.pending_streams,
                &self.staging,
                &self.stream_reservations_expired,
                max_reservation,
            );
        }
        // Non-stream owners still use the ordinary orphan TTL. Active streams
        // are handled only by the ordered revoke-then-release loop above.
        self.staging.retain(|_, staging| {
            staging.stream_active || now.duration_since(staging.captured_at) < ttl
        });
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

    fn shape_body(&self, raw: &[u8], max_bytes: usize) -> ShapedBody {
        shape_bytes(
            self.mode,
            &self.redactor,
            raw,
            max_bytes,
            self.limits.max_redaction_scan_bytes,
        )
    }

    /// Cheap capture admission, evaluated once per transaction on the FIRST
    /// backend-visible body — before any hashing, redaction, excerpt shaping,
    /// or model/tool extraction.
    ///
    /// `Ok` admits full capture. Sampling hits carry a reservation from
    /// [`RecordsPerMinute::try_reserve`], while override-only candidates carry
    /// no reservation and acquire only if their final outcome emits. `Err`
    /// means no exportable record can result, so expensive work is skipped:
    /// * [`CAPTURE_SKIP_NOT_SAMPLED`] — the sampling roll lost and neither
    ///   override is configured, so [`Self::emit_decision`] can never emit.
    ///   Exact: this is the same predicate the emit decision would apply later.
    /// * [`CAPTURE_SKIP_RATE_LIMITED`] — `sampling.max_records_per_minute` had
    ///   no reservable budget for a sampling hit in the current window. The
    ///   reservation is atomic so concurrent sampled candidates cannot all pass
    ///   a non-consuming peek and amplify past the ceiling.
    fn capture_skip_reason(
        &self,
        sample_hit: bool,
    ) -> Result<Option<RateLimitReservation>, &'static str> {
        if !self.commit_may_emit(sample_hit) {
            return Err(CAPTURE_SKIP_NOT_SAMPLED);
        }
        // An override-only candidate does not yet know whether it will emit.
        // Reserving now would let a slow successful request strand the window
        // budget and permanently preclude a concurrent error/guardrail audit.
        // Capture its request evidence, then acquire at enqueue only if the
        // final response actually activates an override.
        if !sample_hit {
            return Ok(None);
        }
        self.rate_limiter
            .try_reserve()
            .map(Some)
            .ok_or(CAPTURE_SKIP_RATE_LIMITED)
    }

    /// Perform (or deliberately skip) the expensive request-side capture over a
    /// backend-visible `body`. Runs outside the staging map's shard guard.
    ///
    /// This is the ONLY place the request body is hashed, redacted, excerpted,
    /// or harvested, and each transaction reaches it at most once
    /// ([`AuditStaging::captured`]) — so the common no-transform path performs a
    /// single keyed HMAC pass instead of hashing once at staging and again to
    /// discover the final body was unchanged.
    fn capture_request(
        &self,
        parsed: Option<&Value>,
        body: &[u8],
        sample_hit: bool,
    ) -> RequestCapture {
        let reservation = match self.capture_skip_reason(sample_hit) {
            Ok(reservation) => reservation,
            Err(skipped) => {
                self.request_captures_skipped
                    .fetch_add(1, Ordering::Relaxed);
                return RequestCapture {
                    skipped: Some(skipped),
                    ..RequestCapture::default()
                };
            }
        };
        self.request_captures.fetch_add(1, Ordering::Relaxed);
        // Exported body hashes are keyed HMAC-SHA256 (same key as the redaction
        // placeholders): a plain SHA-256 of a mostly-predictable body (a fixed
        // chat JSON wrapper around one secret) would be an offline brute-force
        // oracle for the secret in every mode, including hash_only.
        let hash = self.redactor.keyed_hash_hex(body);
        let redact_before_bound = self.mode != AuditMode::FullBody;
        // `hash_only` exports no model/provider/tool metadata at all
        // (`build_record` discards it), so do not extract or redact it.
        let harvests = self.mode.harvests_metadata();
        let model = if harvests {
            parsed
                .map(|json| extract_model_bounded(json, &self.redactor, redact_before_bound))
                .unwrap_or_default()
        } else {
            BoundedModel::default()
        };
        let tools = if harvests && self.capture.tool_calls {
            parsed
                .map(|json| extract_tool_names_bounded(json, &self.redactor, redact_before_bound))
                .unwrap_or_default()
        } else {
            BoundedToolNames::default()
        };
        let shaped = if self.capture.request {
            self.shape_body(body, self.limits.max_request_bytes)
        } else {
            ShapedBody::default()
        };
        RequestCapture {
            hash: Some(hash),
            excerpt: shaped.excerpt,
            truncated: shaped.truncated,
            omitted_reason: shaped.omitted_reason,
            model,
            tools,
            skipped: None,
            rate_reservation: reservation,
        }
    }

    /// Publish a [`RequestCapture`] onto `ctx` metadata. The keyed hash is
    /// exported as a transaction-log correlation field only when capture
    /// actually ran; a skipped capture removes any stale value.
    fn publish_request_capture(&self, ctx: &mut RequestContext, capture: &RequestCapture) {
        match capture.hash.as_ref() {
            Some(hash) => {
                ctx.metadata
                    .insert(MD_REQUEST_HASH.to_string(), hash.clone());
            }
            None => {
                ctx.metadata.remove(MD_REQUEST_HASH);
            }
        }
    }

    /// Classify `body` and stage the audit candidate: writes the
    /// `ai_transcript_audit.*` request-side metadata and inserts the staging
    /// entry keyed by the new `record_id`. `body` is the request body as
    /// currently known; callers have already checked the JSON content-type.
    ///
    /// Staging itself is deliberately cheap — JSON classification plus bounded
    /// metadata. Expensive capture (keyed HMAC, redaction, excerpt, model/tool
    /// extraction) runs only for [`BodyPhase::Final`], where the bytes are the
    /// backend-visible ones and capture admission can be decided.
    ///
    /// Invariant: this instance must not publish shared candidate / sampling /
    /// stream / request-hash metadata until its retained-byte lease has been
    /// acquired and its local staging entry is installed. Publishing earlier
    /// leaves stale markers when `try_acquire` fails; `discard_staged_candidate`
    /// deliberately refuses to clear a true shared marker when this instance
    /// inserted no staging (a co-located peer may own that state), so a failed
    /// local admission would otherwise poison final-phase fallback decisions.
    /// Failure paths drop the staging permit and any rate reservation via RAII
    /// and never install a lease or staging entry.
    fn stage_candidate(
        &self,
        ctx: &mut RequestContext,
        body: &[u8],
        phase: BodyPhase,
    ) -> PluginResult {
        if body.is_empty() {
            self.discard_staged_candidate(ctx);
            return PluginResult::Continue;
        }
        // In redacted mode the scan bound is also the classification/extraction
        // bound. Check it before serde_json so an oversized body cannot force a
        // full parse/allocation and then disappear as "non-AI". Every oversized
        // JSON POST is conservatively audited as a possible AI request.
        let scan_limited =
            self.mode.redacts_body() && body.len() > self.limits.max_redaction_scan_bytes;
        let parsed: Option<Value> = if scan_limited {
            None
        } else {
            serde_json::from_slice(body).ok()
        };
        let is_ai = scan_limited || parsed.as_ref().is_some_and(json_looks_like_ai_request);
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
        // Decide the stream marker locally; publish only after local staging
        // succeeds so a refused retained-byte lease cannot leave
        // `MD_STREAM_REQUEST` without an owning staging entry.
        let stream_requested = scan_limited
            || parsed
                .as_ref()
                .and_then(|json| json.get("stream"))
                .and_then(Value::as_bool)
                == Some(true);

        // Every staged AI candidate is eligible for stream capture.
        // `forces_reqwest_dispatch` and `response_stream_inspector` apply the
        // `sampled`-mode tee gate
        // (`stream_tee_wanted`) at dispatch/response time, when the request-side
        // guardrails (2925–2978, which run after this plugin's staging
        // publication below) have already published their metadata. Non-AI JSON
        // POSTs are never staged, so they stay on the native-H3 path.
        //
        // A `Provisional` body is pre-transform: hashing/redacting/excerpting it
        // would be discarded by the final-body refresh on any mutating chain and
        // duplicated on every non-mutating one, so all of that is deferred to
        // the single `Final` capture.
        let capture = match phase {
            BodyPhase::Final => self.capture_request(parsed.as_ref(), body, sample_hit),
            BodyPhase::Provisional => RequestCapture::default(),
        };

        // Charge the aggregate retained-byte budget for this staged candidate
        // before it is published into the shared map or onto shared request
        // metadata. Provisional staging and deliberately skipped captures
        // charge zero; Final captures charge the measured excerpt + bounded
        // model/tool bytes.
        let staged_bytes = if capture.skipped.is_some() {
            0
        } else {
            staged_retained_bytes(
                capture.excerpt.as_deref().map_or(0, str::len),
                capture.model.value.as_deref().map_or(0, str::len),
                tool_names_bytes(&capture.tools.names),
            )
        };
        let Some(retained_lease) = self.retained_budget.try_acquire(staged_bytes) else {
            // No local staging entry was installed, so discard must not clear a
            // peer-owned shared marker/hash. Dropping `staging_permit` and
            // `capture` (rate reservation) releases every resource taken here.
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
        };

        // Install local staging before any shared metadata publish so a later
        // failure cannot leave candidate/hash/stream markers without an owner.
        let published_hash = capture.hash.clone();
        self.staging.insert(
            record_id.clone(),
            AuditStaging {
                _staging_permit: staging_permit,
                retained_lease,
                retained_bytes: staged_bytes,
                captured_at: Instant::now(),
                sample_hit,
                request_excerpt: capture.excerpt,
                request_truncated: capture.truncated,
                request_body_omitted_reason: capture.omitted_reason,
                request_hash: capture.hash,
                request_model: capture.model.value,
                request_model_truncated: capture.model.truncated,
                request_model_hash: capture.model.hash,
                tool_names: capture.tools.names,
                tool_names_truncated: capture.tools.truncated,
                tool_names_omitted: capture.tools.omitted,
                tool_names_hash: capture.tools.hash,
                commit_permit: None,
                commit_lease: None,
                stream_active: false,
                stream_active_since: None,
                stream_deadline: None,
                captured: phase == BodyPhase::Final,
                capture_skipped: capture.skipped,
                rate_reservation: capture.rate_reservation,
            },
        );

        // Local staging owns this candidate: only now publish shared metadata.
        ctx.metadata.insert(MD_RECORD_ID.to_string(), record_id);
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
        // `stream: true` means an SSE response is expected; record it so the
        // response buffer decision streams rather than stalls (buffering a
        // stream holds it until EOF, and under retry the buffered->stream
        // content-type downgrade is disabled).
        if stream_requested {
            ctx.metadata
                .insert(MD_STREAM_REQUEST.to_string(), "true".to_string());
        }
        self.publish_request_capture(
            ctx,
            &RequestCapture {
                hash: published_hash,
                ..RequestCapture::default()
            },
        );
        PluginResult::Continue
    }

    /// Complete an already-staged candidate from a FINAL backend-visible request
    /// body. `before_proxy` stages the candidate cheaply (classification only),
    /// so this is where the transaction's single keyed HMAC / redaction /
    /// excerpt / model+tool pass happens.
    ///
    /// Idempotent: once [`AuditStaging::captured`] is set, later refresh hooks
    /// (the reject path's `after_proxy`, a synthetic short-circuit's buffered
    /// response hook) are no-ops. That is what removes the second cryptographic
    /// pass the old "hash again, then compare" refresh needed just to learn the
    /// body had not changed — and the alternative, retaining the staged bytes to
    /// compare against, would have doubled retained request memory per
    /// in-flight candidate.
    fn capture_staged_request(&self, ctx: &mut RequestContext, body: &[u8]) {
        let Some(record_id) = ctx.metadata.get(MD_RECORD_ID).cloned() else {
            return;
        };
        // Mirror `stage_candidate`: a redacted-mode body above the scan limit
        // is never parsed for classification, model/tool extraction, or the
        // stream flag. It remains conservatively in audit scope.
        let scan_limited =
            self.mode.redacts_body() && body.len() > self.limits.max_redaction_scan_bytes;
        let parsed: Option<Value> = if scan_limited {
            None
        } else {
            serde_json::from_slice(body).ok()
        };
        if !scan_limited && !parsed.as_ref().is_some_and(json_looks_like_ai_request) {
            self.discard_staged_candidate(ctx);
            return;
        }
        // Re-detect `stream` on the FINAL backend-visible body: a
        // `request_transformer` may have added OR removed `"stream": true`
        // after `before_proxy` staged the candidate. `MD_STREAM_REQUEST` drives
        // the later buffer-vs-stream response decision
        // (`buffered_response_capture_wanted`), so — mirroring
        // `ai_tool_governor` — the marker must track the final body in BOTH
        // directions. This is cheap and runs even when capture is skipped,
        // because stream-vs-buffer correctness is not a capture concern.
        if scan_limited
            || parsed
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

        // Read the staged sampling roll and the already-captured marker under a
        // short read guard, then build the capture with no shard lock held.
        let staged_state = self
            .staging
            .get(&record_id)
            .map(|staging| (staging.sample_hit, staging.captured));
        let Some((sample_hit, already_captured)) = staged_state else {
            return;
        };
        if already_captured {
            return;
        }
        let mut capture = self.capture_request(parsed.as_ref(), body, sample_hit);
        self.publish_request_capture(ctx, &capture);
        if let Some(mut staged) = self.staging.get_mut(&record_id) {
            staged.captured = true;
            staged.capture_skipped = capture.skipped;
            // Charge / refresh the aggregate retained-byte budget for the first
            // (and only) capture of this candidate. Provisional staging charged
            // zero; a skipped capture stays at zero. Growth re-acquires; a
            // refused growth withholds the excerpt rather than retaining
            // unaccounted bytes.
            let mut apply_metadata = true;
            if capture.skipped.is_some() {
                staged.retained_lease.shrink_to(0);
                staged.retained_bytes = 0;
            } else {
                let model_bytes = capture.model.value.as_deref().map_or(0, str::len);
                let tool_bytes = tool_names_bytes(&capture.tools.names);
                let captured_bytes = staged_retained_bytes(
                    capture.excerpt.as_deref().map_or(0, str::len),
                    model_bytes,
                    tool_bytes,
                );
                if captured_bytes <= staged.retained_bytes {
                    staged.retained_lease.shrink_to(captured_bytes);
                    staged.retained_bytes = captured_bytes;
                } else if let Some(lease) = self.retained_budget.try_acquire(captured_bytes) {
                    staged.retained_lease = lease;
                    staged.retained_bytes = captured_bytes;
                } else {
                    capture.excerpt = None;
                    capture.truncated = true;
                    capture.omitted_reason = Some(OMIT_REASON_RETAINED_BYTE_BUDGET);
                    let without_excerpt = staged_retained_bytes(0, model_bytes, tool_bytes);
                    if without_excerpt <= staged.retained_bytes {
                        staged.retained_lease.shrink_to(without_excerpt);
                        staged.retained_bytes = without_excerpt;
                    } else {
                        apply_metadata = false;
                        let prior_model_bytes = staged.request_model.as_deref().map_or(0, str::len);
                        let prior_tool_bytes = tool_names_bytes(&staged.tool_names);
                        let prior_without_excerpt =
                            staged_retained_bytes(0, prior_model_bytes, prior_tool_bytes);
                        if prior_without_excerpt <= staged.retained_bytes {
                            staged.retained_lease.shrink_to(prior_without_excerpt);
                            staged.retained_bytes = prior_without_excerpt;
                        }
                    }
                }
            }
            staged.request_excerpt = capture.excerpt;
            staged.request_truncated = capture.truncated;
            staged.request_body_omitted_reason = capture.omitted_reason;
            staged.request_hash = capture.hash;
            if apply_metadata {
                staged.request_model = capture.model.value;
                staged.request_model_truncated = capture.model.truncated;
                staged.request_model_hash = capture.model.hash;
                staged.tool_names = capture.tools.names;
                staged.tool_names_truncated = capture.tools.truncated;
                staged.tool_names_omitted = capture.tools.omitted;
                staged.tool_names_hash = capture.tools.hash;
            }
            // Replace any prior reservation (there should be none on the
            // classification-only provisional staging path). If staging vanished
            // between build and publish, `capture`'s Drop releases the new slot.
            staged.rate_reservation = capture.rate_reservation;
        }
    }

    fn has_staged_candidate(&self, metadata: &HashMap<String, String>) -> bool {
        metadata
            .get(MD_RECORD_ID)
            .is_some_and(|record_id| self.staging.contains_key(record_id))
    }

    /// THIS instance's staged sampling roll, or `None` when this instance holds
    /// no staging entry for the record — i.e. the shared `MD_CANDIDATE` marker on
    /// the context belongs to a co-located peer instance. There is deliberately
    /// no `MD_SAMPLE_HIT` fallback: that key is shared and peer-writable, so
    /// falling back to it would let a peer's roll drive this instance's stream
    /// selection, commit admission, and client-visible fail-closed 503.
    fn owned_sample_hit(&self, metadata: &HashMap<String, String>) -> Option<bool> {
        metadata
            .get(MD_RECORD_ID)
            .and_then(|record_id| self.staging.get(record_id))
            .map(|staging| staging.sample_hit)
    }

    /// Whether a marked AI candidate's stream should actually be teed. `On`
    /// tees every candidate THIS instance staged; `Sampled` tees only
    /// sampling-roll winners plus requests a request-side guardrail flagged
    /// (evaluated here — at dispatch/response time — because the guardrail
    /// plugins at 2925–2978 run AFTER staging at 2740 but BEFORE the proxy's
    /// dispatch decision, so `always_capture_on_guardrail` can still capture
    /// response evidence on an un-sampled stream). A peer-only marker yields
    /// no tee. Error statuses and response-side guardrail hits are only known
    /// later still: on un-sampled streams those overrides emit via the `log`
    /// fallback without a response body/hash (teeing every stream "just in
    /// case" would defeat sampled capture entirely).
    ///
    /// Every mode — `On` included — additionally requires that an exportable
    /// record is still possible for this candidate (`commit_may_emit`) and that
    /// capture admission has not already precluded export
    /// ([`export_precluded`]). Teeing, hashing, and accumulating an SSE prefix
    /// for a sampling loser or a rate-limited candidate that no override can ever
    /// emit is pure amplification: `emit_decision` / `enqueue` would discard
    /// the result. This also keeps the mode off the reqwest-pinned dispatch
    /// path, since `forces_reqwest_dispatch` shares this predicate.
    fn stream_tee_wanted(&self, metadata: &HashMap<String, String>) -> bool {
        if self.capture.streaming == StreamingCapture::Off {
            return false;
        }
        // Ownership is proven by a local staging entry only — never by the
        // shared peer-writable `MD_SAMPLE_HIT` key (see `owned_sample_hit`).
        let Some(sample_hit) = self.owned_sample_hit(metadata) else {
            return false;
        };
        if !self.commit_may_emit(sample_hit) {
            return false;
        }
        if metadata
            .get(MD_RECORD_ID)
            .and_then(|record_id| self.staging.get(record_id))
            .is_some_and(|staged| export_precluded(Some(&staged)))
        {
            return false;
        }
        match self.capture.streaming {
            StreamingCapture::Off => false,
            StreamingCapture::On => true,
            StreamingCapture::Sampled => {
                sample_hit || (self.sampling.always_on_guardrail && guardrail_fired(metadata))
            }
        }
    }

    fn envelope_from_ctx(&self, ctx: &RequestContext, status: u16) -> EnvelopeOwned {
        let (proxy_id, proxy_name, namespace, route_template) = match ctx.matched_proxy.as_ref() {
            Some(proxy) => (
                Some(proxy.id.clone()),
                proxy.name.clone(),
                if proxy.namespace.is_empty() {
                    self.namespace.clone()
                } else {
                    proxy.namespace.clone()
                },
                // Prefer the operator-configured `listen_path` (a path-shaped,
                // low-cardinality route identifier), else the proxy name.
                proxy.listen_path.clone().or_else(|| proxy.name.clone()),
            ),
            None => (None, None, self.namespace.clone(), None),
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
            route_template,
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
            // The summary carries no `listen_path`; the proxy name is the
            // available low-cardinality route identifier on this fallback path.
            route_template: summary.proxy_name.clone(),
            status_code: summary.response_status_code,
        }
    }

    /// Apply `privacy.path_mode` to the envelope's literal path. Returns the
    /// value to export (or `None` to omit). Runs off the request hot path (only
    /// during record assembly for a captured transaction).
    fn resolve_export_path(&self, envelope: &EnvelopeOwned) -> Option<String> {
        match self.privacy.path_mode {
            PathMode::Omit => None,
            PathMode::Raw => Some(envelope.path.clone()),
            PathMode::Redact => Some(self.redactor.redact(&envelope.path)),
            PathMode::Hash => Some(self.redactor.keyed_hash_hex(envelope.path.as_bytes())),
            PathMode::Template => envelope.route_template.clone(),
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
                "ai_model" => {
                    // Bound before retaining: metadata values can be attacker-shaped.
                    // Protected modes redact the full observed string first so a
                    // PII span straddling the model ceiling cannot leak as a raw
                    // prefix; `full_body` keeps the bounded raw prefix.
                    let bounded =
                        bound_model_str(value, &self.redactor, self.mode != AuditMode::FullBody);
                    harvest.model = bounded.value;
                    harvest.model_truncated = bounded.truncated;
                    harvest.model_hash = bounded.hash;
                }
                "ai_provider" => harvest.provider = Some(bound_short_metadata(value)),
                "ai_federation_provider" => federation_provider = Some(bound_short_metadata(value)),
                "ai_total_tokens"
                | "ai_prompt_tokens"
                | "ai_completion_tokens"
                | "ai_estimated_cost"
                | "ai_streaming" => {
                    harvest.tokens.insert(key.clone(), safe(value));
                }
                _ => {
                    if let Some(suffix) = cache_telemetry_suffix(key) {
                        // Admit only the producer's own value domain. A key
                        // that matches the grammar but carries an out-of-domain
                        // value is dropped rather than exported, so the `cache`
                        // section can never widen past the fixed schema.
                        if cache_telemetry_value_admitted(suffix, value) {
                            harvest.cache.insert(key.clone(), safe(value));
                        }
                    } else if is_guardrail_key(key) {
                        harvest.guardrails.insert(key.clone(), safe(value));
                    }
                }
            }
        }
        // Cap the cache section after the scan, not during it: the source map
        // iterates in `HashMap` order, so dropping mid-scan would pick a
        // different surviving subset run to run. Truncating the sorted
        // `BTreeMap` keeps the retained set stable for a given input.
        //
        // Only the per-instance `ai_semantic_cache.<id>.*` entries are
        // truncated. The fixed-name producer keys (legacy `ai_cache_*` and
        // `request_deduplication.replayed`) are a closed set of four and are
        // not a cardinality axis, but they sort around the namespaced block —
        // `request_deduplication.replayed` sorts after all of it — so a plain
        // sorted truncation would discard the documented replay marker first
        // while keeping an eleventh cache instance's status. Retaining them
        // first keeps the cap at 32 total entries and keeps the record's
        // per-request signals present regardless of chain width.
        if harvest.cache.len() > MAX_CACHE_TELEMETRY_ENTRIES {
            let fixed_name_entries = harvest
                .cache
                .keys()
                .filter(|key| !is_namespaced_cache_telemetry_key(key.as_str()))
                .count();
            let namespaced_budget = MAX_CACHE_TELEMETRY_ENTRIES.saturating_sub(fixed_name_entries);
            let boundary = harvest
                .cache
                .keys()
                .filter(|key| is_namespaced_cache_telemetry_key(key.as_str()))
                .nth(namespaced_budget)
                .cloned();
            if let Some(boundary) = boundary {
                harvest.cache.retain(|key, _| {
                    !is_namespaced_cache_telemetry_key(key.as_str()) || *key < boundary
                });
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
        response: ResponseCapture,
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
        let request_body_omitted_reason = staging.and_then(|s| s.request_body_omitted_reason);
        let request_hash = staging.and_then(|s| s.request_hash.clone());
        // Request-derived model/tool values were already redacted over their
        // full observed strings and then bounded while staging (or while
        // harvesting `ai_model`). Do not run the redactor again here: custom
        // replacements may expand an already-bounded value and violate the
        // queued-record memory contract. `full_body` deliberately staged the
        // bounded raw value instead.
        let (tool_names, tool_names_truncated, tool_names_omitted, tool_names_hash) = if harvests {
            let tool_names = staging.map(|s| s.tool_names.clone()).unwrap_or_default();
            let tool_names_truncated = staging.map(|s| s.tool_names_truncated).unwrap_or(false);
            let tool_names_omitted = staging.map(|s| s.tool_names_omitted).unwrap_or(0);
            let tool_names_hash = staging.and_then(|s| s.tool_names_hash.clone());
            (
                tool_names,
                tool_names_truncated,
                tool_names_omitted,
                tool_names_hash,
            )
        } else {
            (Vec::new(), false, 0, None)
        };

        let (model, model_truncated, model_hash) = if harvests {
            let (model, model_truncated, model_hash) =
                if let Some(value) = staging.and_then(|s| s.request_model.clone()) {
                    (
                        Some(value),
                        staging.map(|s| s.request_model_truncated).unwrap_or(false),
                        staging.and_then(|s| s.request_model_hash.clone()),
                    )
                } else {
                    (harvest.model, harvest.model_truncated, harvest.model_hash)
                };
            (model, model_truncated, model_hash)
        } else {
            (None, false, None)
        };
        let provider = if harvests { harvest.provider } else { None };
        let path = self.resolve_export_path(&envelope);
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
            path,
            model,
            provider,
            status_code: envelope.status_code,
            mode: self.mode.as_str(),
            sampled,
            capture_reason: reason,
            request_hash,
            response_hash: response.hash,
            response_hash_scope: response.hash_scope,
            response_hash_bytes: response.hash_bytes,
            request_body_truncated: request_truncated,
            response_body_truncated: response.truncated,
            request_body: request_excerpt,
            response_body: response.excerpt,
            request_body_omitted_reason,
            response_body_omitted_reason: response.omitted_reason,
            tokens: harvest.tokens,
            cache: harvest.cache,
            guardrails: harvest.guardrails,
            tool_names,
            model_truncated,
            model_hash,
            tool_names_truncated,
            tool_names_omitted,
            tool_names_hash,
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
        if !self.capture.response
            || (flag(&ctx.metadata, MD_CANDIDATE) && !self.has_staged_candidate(&ctx.metadata))
        {
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
        // (via `capture_staged_request` for an already-classified candidate, or
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

    fn enforces_finalized_request_policy(&self) -> bool {
        true
    }

    fn start_background_tasks(&self) -> Result<(), String> {
        // Materialize every custom header (resolving `${secret:NAME}` references
        // against `FERRUM_TRANSCRIPT_SINK_SECRET_*`) BEFORE the batching worker
        // starts. A missing, empty, or invalid secret/header value fails
        // activation here, so the generation is never published and admission
        // never begins healthy under a predictable invalid-auth/routing header
        // config — instead of silently dropping the field and sending the first
        // batch unauthenticated. Runs on serving nodes only (CP/admin config
        // validation never starts background tasks), so secrets that live on the
        // data plane are not required at CP admission time.
        let materialized = materialize_sink_headers(&self.custom_header_specs)?;
        let mut flush_config = self.flush_config.clone();
        flush_config.custom_headers = Arc::new(materialized);
        let healthy = Arc::clone(&self.sink_healthy);
        let hooks = LoggerHooks {
            on_failed_batch: Some(Arc::new(
                move |_batch: Arc<[QueuedAuditRecord]>, _error: String| {
                    healthy.store(false, Ordering::Relaxed);
                },
            )),
            ..LoggerHooks::default()
        };
        self.logger.start_with_hooks(
            "ai_transcript_audit",
            self.batch_config,
            hooks,
            move |batch| {
                let flush_config = flush_config.clone();
                async move { send_batch(&flush_config, &batch).await }
            },
        )
    }

    fn commit_background_tasks(&self) {
        self.logger.commit();
        let id = *self.status_id.get_or_init(|| {
            NEXT_STATUS_ID
                .fetch_add(1, Ordering::Relaxed)
                .saturating_add(1)
        });
        register_status_snapshot(
            id,
            StatusSource {
                base: self.status_snapshot_for_id(id),
                retained_budget: Arc::clone(&self.retained_budget),
                stream_reservations_expired: Arc::clone(&self.stream_reservations_expired),
                sink_healthy: Arc::clone(&self.sink_healthy),
            },
        );
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
        let stage_result = self.stage_candidate(ctx, body.as_bytes(), BodyPhase::Provisional);
        ctx.metadata.insert("request_body".to_string(), body);
        if !matches!(stage_result, PluginResult::Continue) {
            return stage_result;
        }
        self.request_phase_commit_admission(ctx)
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
        // Staged (cheaply) in `before_proxy`: these are the backend-visible
        // bytes, so this is where the transaction's single capture pass runs.
        if flag(&ctx.metadata, MD_CANDIDATE) && self.has_staged_candidate(&ctx.metadata) {
            self.capture_staged_request(ctx, body);
            // Capture may flip `MD_STREAM_REQUEST`. Re-evaluate whether a later
            // response/stream gate will reserve, or whether request-time
            // reservation must run now (conservative maybe-stream with
            // streaming capture off has no later buffered gate).
            return self.request_phase_commit_admission(ctx);
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
        let stage_result = self.stage_candidate(ctx, body, BodyPhase::Final);
        if !matches!(stage_result, PluginResult::Continue) {
            return stage_result;
        }
        self.request_phase_commit_admission(ctx)
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
    /// response-body hooks never run. Capture the staged request from the final
    /// `request_body` so the record reflects the provider-visible (redacted)
    /// request, not the pre-redaction prompt/hash. The normal backend path
    /// already captured the backend-visible request in the final-body hook
    /// (`MD_FINAL_REQ_SEEN`), so skip there to avoid reverting it from carried
    /// pre-transform metadata; `AuditStaging::captured` is the second, stateful
    /// guard that keeps this to one capture pass per transaction.
    async fn after_proxy(
        &self,
        ctx: &mut RequestContext,
        response_status: u16,
        response_headers: &mut HashMap<String, String>,
    ) -> PluginResult {
        if !self.active
            || !flag(&ctx.metadata, MD_CANDIDATE)
            || !self.has_staged_candidate(&ctx.metadata)
        {
            return PluginResult::Continue;
        }
        if !flag(&ctx.metadata, MD_FINAL_REQ_SEEN)
            && let Some(body) = ctx.metadata.remove("request_body")
        {
            self.capture_staged_request(ctx, body.as_bytes());
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
        if flag(&ctx.metadata, MD_STREAM_REQUEST) && self.capture.streaming != StreamingCapture::Off
        {
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
        if !flag(&ctx.metadata, MD_CANDIDATE) || !self.has_staged_candidate(&ctx.metadata) {
            self.staging.remove(&record_id);
            return PluginResult::Continue;
        }

        // On synthetic short-circuits, downstream `before_proxy` plugins may
        // have updated `ctx.metadata["request_body"]` and then returned a
        // synthetic 2xx before the final request-body hook could run. Capture
        // from that live metadata before consuming staging. This is also the
        // last-resort capture for a synthetic 2xx that never reached a
        // request-side capture hook, so the record does not ship without its
        // keyed request hash. Still gated on the synthetic marker: on the normal
        // backend path the final-body hook already saw the backend-visible bytes
        // and the carried `request_body` metadata may be the intentionally
        // preserved pre-transform body, which must not re-drive AI
        // classification or the `stream` marker. `AuditStaging::captured` is the
        // second guard that keeps the expensive pass to one per transaction when
        // both this hook and `after_proxy` see the same short-circuit.
        if flag(&ctx.metadata, SYNTHETIC_SHORT_CIRCUIT_METADATA_KEY)
            && let Some(body) = ctx.metadata.remove("request_body")
        {
            self.capture_staged_request(ctx, body.as_bytes());
            ctx.metadata.insert("request_body".to_string(), body);
        }

        // Peek (do not consume) the staging entry for the fail-closed gate. The
        // observe-only committed hook consumes it after every validator has run.
        // The roll is read from THIS instance's staging entry only, never from
        // the shared peer-writable `MD_SAMPLE_HIT` key (see `owned_sample_hit`).
        let Some(sample_hit) = self.owned_sample_hit(&ctx.metadata) else {
            return PluginResult::Continue;
        };
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

        // The single atomic `remove` IS the instance-scoped commit capability: it
        // both proves this instance staged the request (a peer instance's shared
        // `MD_CANDIDATE` marker yields nothing here) and consumes the staging
        // permit exactly once, so a duplicated or retried commit hook cannot emit
        // a second, staging-less record. Do not reintroduce a
        // `has_staged_candidate` pre-check: that would only re-open a
        // check-then-act window without changing the outcome.
        let Some(mut staging) = self.take_staging_for_consumption(&record_id) else {
            return;
        };
        let sample_hit = staging.sample_hit;
        let (emit, reason) = self.emit_decision(
            sample_hit,
            guardrail_fired(&ctx.metadata),
            response_status >= 400,
        );
        ctx.metadata
            .insert(MD_SAMPLED.to_string(), bool_str(sample_hit));

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
        if export_precluded(Some(&staging)) {
            // `sampling.max_records_per_minute` was already saturated when the
            // backend-visible request body arrived, so the request side was
            // never hashed or excerpted and this record cannot ship. Do not pay
            // response-side hashing/redaction/assembly for it either.
            ctx.metadata.insert(
                MD_SINK_STATUS.to_string(),
                if request_rejected_for_sink {
                    "rejected".to_string()
                } else {
                    "dropped".to_string()
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
        let shaped = if captures_response_body {
            self.shape_body(body, self.limits.max_response_bytes)
        } else {
            ShapedBody::default()
        };
        // A buffered body is complete by construction, so its digest always
        // covers every observed byte.
        let response = ResponseCapture {
            excerpt: shaped.excerpt,
            truncated: shaped.truncated,
            omitted_reason: shaped.omitted_reason,
            hash_scope: response_hash.as_ref().map(|_| HASH_SCOPE_FULL),
            hash_bytes: response_hash.as_ref().map(|_| body.len() as u64),
            hash: response_hash,
        };
        let envelope = self.envelope_from_ctx(ctx, response_status);
        let record = self.build_record(
            &record_id,
            envelope,
            &ctx.metadata,
            Some(&staging),
            response,
            sample_hit,
            reason,
            Some(response_headers),
        );
        let status = match self.enqueue(record, Some(&mut staging)) {
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
        // A scan-limited request may only be *conservatively* marked as a
        // stream. When streaming capture is disabled, its request-phase
        // fail-closed reservation must likewise survive stream selection so
        // the eventual log fallback cannot lose the audit record after the
        // response has committed.
        let fallback_reservation = self.capture.streaming == StreamingCapture::Off
            && flag(&ctx.metadata, MD_STREAM_REQUEST)
            && self.staging.get(record_id).is_some_and(|staging| {
                staging.commit_permit.is_some() && staging.commit_lease.is_some()
            });
        if self.stream_commit_selected(ctx, response_status, content_type)
            || self.stream_inspector_selected(ctx, response_status, content_type)
            || fallback_reservation
        {
            self.arm_stream_reservation(record_id);
            return;
        }
        if let Some(mut staging) = self.staging.get_mut(record_id) {
            staging.commit_permit.take();
            staging.commit_lease.take();
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
        let record_id = ctx.metadata.get(MD_RECORD_ID)?.clone();
        // Shares the exact applicability predicate used to start the
        // reservation clock in `on_response_stream_selected`.
        if !self.stream_inspector_selected(ctx, response_status, content_type) {
            return None;
        }
        // Re-read through the owning map after the applicability check. If a
        // concurrent expiry sweep consumed staging in between, inspector
        // creation fails closed instead of borrowing the shared sample marker.
        // A fail-closed stream already owns the full retained-record lease in
        // staging; fail-open capture reserves the same ceiling here before its
        // inspector can retain one response byte.
        let (sample_hit, staging_has_record_lease, reservation_started, deadline_control) = {
            let staging = self.staging.get(&record_id)?;
            (
                staging.sample_hit,
                staging.commit_lease.is_some(),
                staging.stream_active_since,
                staging
                    .stream_deadline
                    .as_ref()
                    .map(|owner| Arc::clone(&owner.control)),
            )
        };
        let record_lease = if staging_has_record_lease {
            None
        } else {
            Some(self.reserve_commit_lease()?)
        };

        let request_handoff = ctx.response_stream_handoff();
        let now = Instant::now();
        let max_reservation = self.limits.max_stream_reservation;
        let reservation_deadline = reservation_started
            .unwrap_or(now)
            .checked_add(max_reservation)
            .unwrap_or(now);
        let pending_permit = Arc::clone(&self.pending_stream_permits)
            .try_acquire_owned()
            .ok()?;
        let slot = Arc::new(StreamSlot {
            capture: Mutex::new(StreamCaptureLifecycle::Active(StreamCaptureWork {
                accumulated: Vec::new(),
                hasher: self.redactor.keyed_hasher(),
                hashed_bytes: 0,
                hash_capped: false,
                truncated: false,
                redaction_scan_limited: false,
            })),
            sample_hit,
            record_lease: Mutex::new(record_lease),
            downstream_terminated: AtomicBool::new(false),
            revoked: AtomicBool::new(false),
            inspector_dropped: AtomicBool::new(false),
            detached_after_revocation: AtomicBool::new(false),
            fallback_published: AtomicBool::new(false),
            uses_request_handoff: request_handoff.is_some(),
            pending_permit: Mutex::new(Some(pending_permit)),
        });
        // Register before the first chunk. An idle stream can expire without
        // ever producing bytes, and the sweeper must still be able to revoke
        // the inspector before it releases staging/queue accounting.
        self.pending_streams
            .insert(record_id.clone(), Arc::clone(&slot));
        // Selection may expire while this concrete factory acquires its
        // fail-open byte lease and pending-slot permit. Never publish an
        // inspector after the staging-owned deadline has fired or the staging
        // capability has otherwise disappeared.
        if let Some(control) = deadline_control {
            let still_owned = self.staging.get(&record_id).is_some_and(|staging| {
                staging
                    .stream_deadline
                    .as_ref()
                    .is_some_and(|owner| Arc::ptr_eq(&owner.control, &control))
            }) && control.is_armed();
            if !still_owned {
                slot.revoke();
                self.pending_streams
                    .remove_if(&record_id, |_, current| Arc::ptr_eq(current, &slot));
                slot.release_pending_permit();
                drop(slot.take_record_lease());
                return None;
            }
        }
        Some(Box::new(AuditStreamInspector {
            record_id,
            slot,
            pending_streams: Arc::clone(&self.pending_streams),
            staging: Arc::clone(&self.staging),
            stream_reservations_expired: Arc::clone(&self.stream_reservations_expired),
            redactor: Arc::clone(&self.redactor),
            mode: self.mode,
            max_bytes: self.limits.max_stream_capture_bytes,
            max_scan_bytes: self.limits.max_redaction_scan_bytes,
            // `capped` (default) stops keyed hashing at the documented capture
            // bound so an indefinitely long stream cannot keep an audit HMAC
            // running for the life of the connection; `full` is the explicit
            // opt-in for a whole-stream digest.
            hash_budget: match self.capture.stream_hash {
                StreamHashScope::Capped => Some(self.limits.max_stream_capture_bytes),
                StreamHashScope::Full => None,
            },
            request_handoff,
            stream_handoff_id: self.stream_handoff_id,
            reservation_deadline,
            max_reservation,
            drop_notified: false,
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
        let slot = ctx
            .response_stream_handoff()
            .and_then(|handoff| handoff.take::<StreamSlot>(self.stream_handoff_id))
            .or_else(|| {
                self.pending_streams
                    .get(&record_id)
                    .map(|slot| Arc::clone(slot.value()))
            });
        let Some(slot) = slot else {
            return; // not a stream we teed
        };
        let Some(claimed) = slot.claim_terminal() else {
            return;
        };
        // A sweeper can publish the revoked handoff between the first remove
        // and the terminal claim. Clear that same-slot marker as part of the
        // claim so no lost duplicate remains in the bounded handoff map.
        self.pending_streams
            .remove_if(&record_id, |_, current| Arc::ptr_eq(current, &slot));
        slot.release_pending_permit();
        let revoked = matches!(&claimed, ClaimedStreamCapture::Revoked);
        // Keep the staging-owned deadline armed until this hook actually
        // consumes staging below or the immediate transaction-log fallback
        // does. If terminal processing or that fallback is cancelled, expiry
        // still releases the retained permit/leases at the original selection
        // deadline.
        let downstream_terminated = slot.downstream_terminated.load(Ordering::Relaxed);
        let sample_hit = if revoked {
            // Revocation invalidates both sides of body evidence for this audit
            // record. Keep the terminal envelope/decision only. The sampling
            // roll comes from the single-fire slot capability created from this
            // instance's staging entry; never fall back to shared metadata
            // after expiry has released the staging owner.
            ctx.metadata.remove(MD_REQUEST_HASH);
            ctx.metadata.remove(MD_RESPONSE_HASH);
            slot.sample_hit
        } else {
            // Normal terminal handling still requires this instance's live
            // staging entry. Do not fall back to the shared peer-writable
            // `MD_SAMPLE_HIT` key.
            let Some(sample_hit) = self.owned_sample_hit(&ctx.metadata) else {
                // Expiry can win after terminal slot claim but before this
                // staging read. Released evidence must not survive into normal
                // transaction metadata as though the claim completed.
                ctx.metadata.remove(MD_REQUEST_HASH);
                ctx.metadata.remove(MD_RESPONSE_HASH);
                return;
            };
            sample_hit
        };
        let errored = response_status >= 400 || !outcome.body_completed;
        let guardrail = guardrail_fired(&ctx.metadata) || downstream_terminated;
        let response = if revoked || downstream_terminated {
            ResponseCapture {
                truncated: true,
                ..ResponseCapture::default()
            }
        } else {
            match claimed {
                ClaimedStreamCapture::Captured(captured) => ResponseCapture {
                    excerpt: captured.response_excerpt,
                    truncated: captured.response_truncated,
                    omitted_reason: captured.response_body_omitted_reason,
                    hash_scope: Some(captured.response_hash_scope),
                    hash_bytes: Some(captured.response_hash_bytes),
                    hash: Some(captured.response_hash),
                },
                // Abnormal end: on_end never ran.
                ClaimedStreamCapture::Abnormal => ResponseCapture {
                    truncated: true,
                    ..ResponseCapture::default()
                },
                ClaimedStreamCapture::Revoked => ResponseCapture::default(),
            }
        };
        let hash = response.hash.clone();
        if let Some(response_hash) = hash.as_ref() {
            ctx.metadata
                .insert(MD_RESPONSE_HASH.to_string(), response_hash.clone());
        }
        let (emit, reason) = self.emit_decision(sample_hit, guardrail, errored);
        if !emit {
            if revoked {
                // Do not let the transaction-log fallback consume request-side
                // staging after a terminal/sweeper race.
                self.staging.remove(&record_id);
                ctx.metadata
                    .insert(MD_SINK_STATUS.to_string(), "skipped".to_string());
                return;
            }
            // Match the buffered path: the response evidence is finalized, but
            // no record was emitted at this hook. Keep staging for the immediate
            // log fallback to consume and mark the sink status non-terminal.
            ctx.metadata
                .insert(MD_SINK_STATUS.to_string(), "deferred".to_string());
            return;
        }

        // A response already being streamed cannot run a new rejecting
        // admission, so stream-terminal enqueue is best-effort. Normal
        // termination atomically consumes the instance-scoped staging commit
        // capability. Expiry already consumed that entry while releasing every
        // staging/queue/byte owner, so its single-fire claimed slot is the only
        // body-free capability allowed to continue.
        let mut staging = if revoked {
            None
        } else {
            let Some(staging) = self.take_staging_for_consumption(&record_id) else {
                // The staging-owned deadline won after slot claim. Never retain
                // or publish the claimed response hash after its commit
                // capability and byte owners were revoked.
                ctx.metadata.remove(MD_REQUEST_HASH);
                ctx.metadata.remove(MD_RESPONSE_HASH);
                return;
            };
            Some(staging)
        };
        if let Some(staging) = staging.as_mut() {
            if export_precluded(Some(staging)) {
                // Capture admission dropped this record on the request side; skip
                // assembly and report the limiter's terminal outcome.
                ctx.metadata
                    .insert(MD_SINK_STATUS.to_string(), "dropped".to_string());
                return;
            }
            if staging.commit_lease.is_none() {
                // Fail-open stream capture reserved the full retained-record charge
                // before copying bytes. Transfer that same lease into enqueue so
                // the capture and queued phases cannot open an accounting gap or
                // require a second worst-case reservation.
                staging.commit_lease = slot.take_record_lease();
            }
        }
        let envelope = self.envelope_from_ctx(ctx, response_status);
        let record = self.build_record(
            &record_id,
            envelope,
            &ctx.metadata,
            staging.as_ref(),
            response,
            sample_hit,
            reason,
            None,
        );
        // Expiry already revoked the reservation contract and uses ordinary
        // best-effort admission; never resurrect a released commit permit or
        // byte lease.
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
        let Some(mut staging) = self.take_staging_for_consumption(&record_id) else {
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
        if export_precluded(Some(&staging)) {
            // Capture admission dropped this record on the request side.
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
            ResponseCapture::default(),
            sample_hit,
            reason,
            None,
        );
        let _ = self.enqueue(record, Some(&mut staging));
    }
}

/// Tees streaming (SSE) response bytes into a bounded, revocable accumulator
/// while forwarding every chunk unchanged, and applies the configured capped
/// or full keyed HMAC until reservation expiry.
struct AuditStreamInspector {
    record_id: String,
    slot: Arc<StreamSlot>,
    pending_streams: Arc<DashMap<String, Arc<StreamSlot>>>,
    staging: Arc<DashMap<String, AuditStaging>>,
    stream_reservations_expired: Arc<AtomicU64>,
    redactor: Arc<PiiRedactor>,
    mode: AuditMode,
    max_bytes: usize,
    max_scan_bytes: usize,
    /// `Some(limit)` stops keyed hashing after `limit` bytes; `None` hashes the
    /// whole stream (explicit `capture.stream_hash: full` opt-in).
    hash_budget: Option<usize>,
    request_handoff: Option<ResponseStreamHandoff>,
    stream_handoff_id: u64,
    reservation_deadline: Instant,
    max_reservation: Duration,
    drop_notified: bool,
}

impl AuditStreamInspector {
    fn revoke_if_expired(&self) -> bool {
        if Instant::now() < self.reservation_deadline {
            return false;
        }
        // Use the same cleanup transaction as the deadline task and repair
        // sweep. Revoking only the capture here would let a terminal hook race
        // ahead of staging/lease removal, retain the old commit capability,
        // and later allow the log fallback to emit a duplicate.
        expire_stream_reservation(
            &self.record_id,
            &self.pending_streams,
            &self.staging,
            &self.stream_reservations_expired,
            self.max_reservation,
        );
        true
    }

    fn notify_drop(&mut self) {
        if self.drop_notified {
            return;
        }
        self.drop_notified = true;
        if !self.revoke_if_expired() {
            self.slot.finish_abnormally();
        }
        self.slot.inspector_dropped.store(true, Ordering::Release);
        if let Some(handoff) = self.request_handoff.as_ref() {
            // Keep the live-map reference until the terminal hook consumes it.
            // If that hook is lost, the reservation sweep can still find and
            // revoke this completed/abnormal slot before releasing accounting.
            // An already-expired slot was detached by its deadline owner or the
            // repair sweep and exists only in this request-owned handoff.
            handoff.publish(self.stream_handoff_id, Arc::clone(&self.slot));
        } else {
            publish_revoked_fallback_if_ready(&self.record_id, &self.slot, &self.pending_streams);
        }
    }
}

impl Drop for AuditStreamInspector {
    fn drop(&mut self) {
        self.notify_drop();
    }
}

#[async_trait]
impl ResponseStreamInspector for AuditStreamInspector {
    async fn on_chunk(&mut self, chunk: &[u8]) -> ResponseStreamAction {
        if self.revoke_if_expired() {
            return ResponseStreamAction::Forward(Bytes::copy_from_slice(chunk));
        }
        let mut capture = self.slot.lock_capture();
        if let StreamCaptureLifecycle::Active(work) = &mut *capture {
            // Bound audit CPU, not just audit memory: once the keyed digest has
            // covered its budget, further bytes are irrelevant to the record
            // we can emit. A revoked slot never enters this branch, including
            // `stream_hash: full`, so expiry stops all later HMAC work.
            match self.hash_budget {
                None => {
                    work.hasher.update(chunk);
                    work.hashed_bytes = work.hashed_bytes.saturating_add(chunk.len() as u64);
                }
                Some(limit) => {
                    let hashed = work.hashed_bytes as usize;
                    if hashed < limit {
                        let take = (limit - hashed).min(chunk.len());
                        work.hasher.update(&chunk[..take]);
                        work.hashed_bytes = work.hashed_bytes.saturating_add(take as u64);
                        if take < chunk.len() {
                            work.hash_capped = true;
                        }
                    } else if !chunk.is_empty() {
                        work.hash_capped = true;
                    }
                }
            }

            // Redacted streams must stop copying at the independent scan bound,
            // even when max_stream_capture_bytes is larger. Hashing keeps its
            // configured capped/full semantics until lifecycle revocation.
            let accumulation_limit = if self.mode.redacts_body() {
                self.max_bytes.min(self.max_scan_bytes)
            } else {
                self.max_bytes
            };
            if work.accumulated.len() < accumulation_limit {
                let remaining = accumulation_limit - work.accumulated.len();
                let take = remaining.min(chunk.len());
                work.accumulated.extend_from_slice(&chunk[..take]);
                if take < chunk.len() {
                    work.truncated = true;
                    if self.mode.redacts_body() && self.max_scan_bytes < self.max_bytes {
                        work.redaction_scan_limited = true;
                    }
                }
            } else if !chunk.is_empty() {
                work.truncated = true;
                if self.mode.redacts_body() && self.max_scan_bytes < self.max_bytes {
                    work.redaction_scan_limited = true;
                }
            }
        }
        drop(capture);
        // Tee: forward the bytes exactly as received, never altering the stream.
        ResponseStreamAction::Forward(Bytes::copy_from_slice(chunk))
    }

    async fn on_end(&mut self) -> ResponseStreamAction {
        if self.revoke_if_expired() {
            return ResponseStreamAction::Forward(Bytes::new());
        }
        let mut capture = self.slot.lock_capture();
        let prior = std::mem::replace(&mut *capture, StreamCaptureLifecycle::Claimed);
        match prior {
            StreamCaptureLifecycle::Active(mut work) => {
                // Finalization stays under the per-stream mutex. This is a
                // bounded, one-shot redaction pass; holding the lock ensures
                // the sweeper cannot release accounting while the Vec is
                // temporarily moved out for final shaping.
                if work.hash_capped {
                    work.hasher.update(PARTIAL_STREAM_HASH_DOMAIN);
                    work.hasher.update(&work.hashed_bytes.to_be_bytes());
                }
                let response_hash = work.hasher.finalize_hex();
                let shaped = if work.redaction_scan_limited {
                    ShapedBody::omitted(OMIT_REASON_REDACTION_SCAN_LIMIT)
                } else if work.truncated && self.mode.redacts_body() {
                    ShapedBody::omitted(OMIT_REASON_STREAM_TRUNCATION)
                } else {
                    shape_bytes(
                        self.mode,
                        &self.redactor,
                        &work.accumulated,
                        self.max_bytes,
                        self.max_scan_bytes,
                    )
                };
                *capture = StreamCaptureLifecycle::Complete(Some(StreamCaptured {
                    response_excerpt: shaped.excerpt,
                    response_truncated: work.truncated,
                    response_body_omitted_reason: shaped.omitted_reason,
                    response_hash,
                    response_hash_scope: if work.hash_capped {
                        HASH_SCOPE_PARTIAL
                    } else {
                        HASH_SCOPE_FULL
                    },
                    response_hash_bytes: work.hashed_bytes,
                }));
            }
            other => *capture = other,
        }
        ResponseStreamAction::Forward(Bytes::new())
    }

    fn on_downstream_terminated(&mut self) {
        self.slot.mark_downstream_terminated();
    }

    fn on_before_drop(&mut self) {
        self.notify_drop();
    }
}

// ---- sink ----

async fn send_batch(cfg: &HttpFlushConfig, batch: &[QueuedAuditRecord]) -> Result<(), String> {
    let entry_count = batch.len();
    let body = build_batch_body(batch);
    let mut request = cfg
        .http_client
        .get()
        .post(&cfg.endpoint_url)
        .header(CONTENT_TYPE, "application/json")
        .body(body);
    // Headers were fully validated and materialized at activation
    // (`materialize_sink_headers`), so there is no per-batch env expansion,
    // template parsing, or fallible construction here — a required header can
    // never be silently skipped while the batch is still sent.
    for (name, value) in cfg.custom_headers.iter() {
        request = request.header(name.clone(), value.clone());
    }
    // `execute_redacted`, not `execute`: the configured collector endpoint may
    // embed a credential in its path or query, and both the shared client's
    // diagnostics (egress denial, retry, slow call) and the `Err` rendered
    // below would otherwise carry the complete URL. The request itself still
    // goes to `endpoint_url`.
    let response = cfg
        .http_client
        .execute_redacted(request, "ai_transcript_audit", &cfg.endpoint_url_for_logs)
        .await;
    // Sink health is derived from the raw collector response, NOT from the
    // shared `handle_http_batch_response` result: that helper treats a
    // non-retryable non-2xx (401/403/413, e.g. an expired sink token) as a
    // discarded-but-Ok batch so the other logging sinks do not retry it, but
    // for this plugin every record in that batch was silently lost — under
    // `on_sink_error: reject` the sink must go unhealthy so audited traffic
    // stops flowing unaudited. Recovery keeps the existing probe model: the
    // next fully acknowledged batch send flips `sink_healthy` back to true.
    let response = match response {
        Ok(response) => response,
        Err(err) => {
            cfg.sink_healthy.store(false, Ordering::Relaxed);
            return Err(format!("ai_transcript_audit batch failed: {err}"));
        }
    };
    let status = response.status();
    // Headers alone do not prove delivery. Drain and validate the
    // acknowledgement under an explicit byte bound and timeout FIRST, then
    // publish health from the complete outcome — a 2xx whose ACK stalls,
    // overruns its bound, or fails transport is an ambiguous delivery and must
    // not leave fail-closed admission believing the sink is healthy.
    let ack = drain_and_validate_ack(&cfg.ack, response).await;
    let result = classify_batch_delivery(cfg, entry_count, status, ack);
    // Keep every entry lease alive until the request body and acknowledgement
    // are finished. Releasing earlier would let new queue admissions consume
    // the bytes while reqwest still retains the contiguous batch. The shared
    // logger also retains the master `Arc<[QueuedAuditRecord]>` across retries;
    // this attempt's borrow ends with the function.
    let _ = batch;
    result
}

/// Assemble one JSON array from already-serialized entries.
///
/// Capacity is exact, so Vec growth cannot retain an uncharged spare buffer.
/// The original `batch` remains borrowed/alive for the complete HTTP attempt;
/// the shared logger Arc-shares that batch across retries without cloning
/// each entry's immutable `Bytes`.
fn build_batch_body(batch: &[QueuedAuditRecord]) -> Vec<u8> {
    let framing = if batch.is_empty() {
        2
    } else {
        batch.len().saturating_add(1)
    };
    let total = batch.iter().fold(framing, |bytes, entry| {
        bytes.saturating_add(entry.json.len())
    });
    let mut body = Vec::with_capacity(total);
    body.push(b'[');
    for (index, entry) in batch.iter().enumerate() {
        if index != 0 {
            body.push(b',');
        }
        body.extend_from_slice(entry.as_bytes());
    }
    body.push(b']');
    body
}

/// Compiled-in acknowledgement failure classes. These strings are the ONLY
/// acknowledgement detail that reaches logs or errors — collector response
/// bytes are never buffered into a diagnostic, so a collector cannot echo
/// captured transcript content back into gateway logs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum AckFailure {
    LimitExceeded,
    Timeout,
    TransportFailure,
    NotJsonObject,
    ReportedFailures,
}

impl AckFailure {
    fn diagnostic(self) -> &'static str {
        match self {
            Self::LimitExceeded => "acknowledgement body exceeded sink.ack_max_bytes",
            Self::Timeout => "acknowledgement body drain timed out (sink.ack_timeout_ms)",
            Self::TransportFailure => "acknowledgement body transport failure",
            Self::NotJsonObject => "acknowledgement body was not a JSON object",
            Self::ReportedFailures => "acknowledgement body reported rejected records",
        }
    }
}

/// Read the collector acknowledgement under `ack.max_bytes` / `ack.timeout` and
/// apply the configured validation policy. Never retains or logs body bytes.
async fn drain_and_validate_ack(
    ack: &AckConfig,
    response: reqwest::Response,
) -> Result<u64, AckFailure> {
    if response
        .content_length()
        .is_some_and(|length| length > ack.max_bytes as u64)
    {
        return Err(AckFailure::LimitExceeded);
    }
    match ack.policy {
        AckPolicy::Drain => {
            match tokio::time::timeout(
                ack.timeout,
                measure_response_body_bounded(response, ack.max_bytes),
            )
            .await
            {
                Err(_) => Err(AckFailure::Timeout),
                Ok(Ok(bytes)) => {
                    // The response (and its pooled connection) dropped when the
                    // measure future completed; let the idle-pool reclaim run
                    // before the worker issues the next batch.
                    tokio::task::yield_now().await;
                    Ok(bytes)
                }
                Ok(Err(BoundedReadError::LimitExceeded { .. })) => Err(AckFailure::LimitExceeded),
                Ok(Err(BoundedReadError::Stream(_))) => Err(AckFailure::TransportFailure),
            }
        }
        AckPolicy::Json => {
            match tokio::time::timeout(
                ack.timeout,
                read_response_body_bounded(response, ack.max_bytes),
            )
            .await
            {
                Err(_) => Err(AckFailure::Timeout),
                Ok(Ok(bytes)) => {
                    let len = bytes.len() as u64;
                    validate_ack_json(&bytes)?;
                    tokio::task::yield_now().await;
                    Ok(len)
                }
                Ok(Err(BoundedReadError::LimitExceeded { .. })) => Err(AckFailure::LimitExceeded),
                Ok(Err(BoundedReadError::Stream(_))) => Err(AckFailure::TransportFailure),
            }
        }
    }
}

/// Field names a collector may use to report per-record failures inside an
/// otherwise-2xx acknowledgement.
const ACK_FAILURE_COUNT_KEYS: &[&str] = &["errors", "failed", "rejected", "error_count"];

/// `ack_policy: json` contract: the acknowledgement must be a JSON object that
/// does not report rejected records. No value from the body is ever surfaced.
fn validate_ack_json(bytes: &[u8]) -> Result<(), AckFailure> {
    let Ok(Value::Object(ack)) = serde_json::from_slice::<Value>(bytes) else {
        return Err(AckFailure::NotJsonObject);
    };
    for key in ACK_FAILURE_COUNT_KEYS {
        match ack.get(*key) {
            None | Some(Value::Null) => {}
            Some(Value::Number(count)) if count.as_u64() == Some(0) => {}
            Some(Value::Array(entries)) if entries.is_empty() => {}
            Some(Value::Bool(false)) => {}
            Some(_) => return Err(AckFailure::ReportedFailures),
        }
    }
    match ack.get("status") {
        None => {}
        Some(Value::String(status))
            if matches!(
                status.to_ascii_lowercase().as_str(),
                "ok" | "success" | "accepted" | "created"
            ) => {}
        // A present non-string or non-affirmative status is ambiguous and must
        // not be treated as acknowledgement success. Diagnostics stay
        // fixed-cardinality (no response bytes).
        Some(_) => return Err(AckFailure::ReportedFailures),
    }
    Ok(())
}

/// Publish sink health from the COMPLETE delivery outcome and return the
/// batch verdict.
///
/// Hysteresis/recovery contract:
/// - health goes false on any ambiguous or failed delivery (transport error,
///   non-2xx status, or a 2xx whose acknowledgement did not validate) with no
///   damping — fail-closed admission must react on the first failure;
/// - health goes true only after a 2xx whose acknowledgement fully drained and
///   validated. Each retry attempt re-publishes, so a batch that succeeds on
///   attempt N restores health at attempt N and not before.
fn classify_batch_delivery(
    cfg: &HttpFlushConfig,
    entry_count: usize,
    status: reqwest::StatusCode,
    ack: Result<u64, AckFailure>,
) -> Result<(), String> {
    let healthy = status.is_success() && ack.is_ok();
    cfg.sink_healthy.store(healthy, Ordering::Relaxed);

    if !status.is_success() {
        let detail = ack.err().map(AckFailure::diagnostic);
        if status.is_client_error()
            && status != reqwest::StatusCode::REQUEST_TIMEOUT
            && status != reqwest::StatusCode::TOO_MANY_REQUESTS
        {
            tracing::warn!(
                "ai_transcript_audit batch discarded due to {} response ({} entries lost){}",
                status,
                entry_count,
                detail.map(|d| format!("; {d}")).unwrap_or_default(),
            );
            return Ok(());
        }
        return Err(format!(
            "ai_transcript_audit batch failed with status {status}{}",
            detail.map(|d| format!("; {d}")).unwrap_or_default(),
        ));
    }

    match ack {
        Ok(_) => Ok(()),
        // A 2xx we could not fully acknowledge is not a delivery. Return an
        // error so the batch is retried under the configured retry policy
        // instead of being silently accounted as sent.
        Err(failure) => Err(format!(
            "ai_transcript_audit batch acknowledgement failed after status {status}; {}",
            failure.diagnostic(),
        )),
    }
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

/// True when capture admission already decided this record cannot be exported
/// (see [`AuditStaging::capture_skipped`]). The request side was never hashed or
/// excerpted, so no record should be assembled, hashed further, or enqueued.
fn export_precluded(staging: Option<&AuditStaging>) -> bool {
    match staging {
        Some(staged) => staged.capture_skipped.is_some(),
        None => false,
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

/// Aggregate UTF-8 bytes of the retained tool-name set.
fn tool_names_bytes(names: &[String]) -> usize {
    names.iter().map(String::len).sum()
}

/// Retained bytes charged for one staged candidate: its excerpt, bounded model
/// and tool-name strings, and a fixed allowance for the record id, keyed
/// hashes, and collection headers held alongside them.
fn staged_retained_bytes(excerpt_bytes: usize, model_bytes: usize, tool_bytes: usize) -> usize {
    excerpt_bytes
        .saturating_add(model_bytes)
        .saturating_add(tool_bytes)
        .saturating_add(STAGING_ENTRY_OVERHEAD_BYTES)
}

/// A shaped body excerpt plus the evidence fields that describe what was, and
/// was not, exported.
#[derive(Default)]
struct ShapedBody {
    excerpt: Option<String>,
    truncated: bool,
    /// Compiled-in reason the excerpt was withheld. Never a captured value.
    omitted_reason: Option<&'static str>,
}

impl ShapedBody {
    fn omitted(reason: &'static str) -> Self {
        Self {
            excerpt: None,
            truncated: true,
            omitted_reason: Some(reason),
        }
    }
}

/// Shape a captured payload into an excerpt.
///
/// Ordering matters for `redacted_body`: redaction runs over the buffered
/// payload first and the redacted text is capped afterwards, so a sensitive
/// value straddling the `max_bytes` boundary can never leak as an unmatched
/// raw prefix. That ordering is only safe while the *input* is bounded — the
/// exported cap otherwise bounds output text but not the parse/scan/copy work
/// behind it, so a huge JSON tail beyond the exported prefix could force a
/// full-body redaction pass for a few kilobytes of excerpt. `max_scan_bytes`
/// is that independent hard processing bound: above it the excerpt is withheld
/// (fail closed with an explicit reason) rather than scanned, because a
/// prefix-only redaction of a truncated body can cut through an unmatched
/// secret and a raw prefix is exactly what redaction exists to prevent.
///
/// (`full_body` is the deliberate raw-capture opt-in, so it caps first — on a
/// UTF-8 boundary — and never scans beyond the cap at all.)
fn shape_bytes(
    mode: AuditMode,
    redactor: &PiiRedactor,
    raw: &[u8],
    max_bytes: usize,
    max_scan_bytes: usize,
) -> ShapedBody {
    if !mode.captures_body() {
        return ShapedBody::default();
    }
    let mut truncated = raw.len() > max_bytes;
    let shaped = if mode.redacts_body() {
        if raw.len() > max_scan_bytes {
            return ShapedBody::omitted(OMIT_REASON_REDACTION_SCAN_LIMIT);
        }
        redact_body_decoded_json_strings(redactor, raw)
    } else {
        // Cut the raw bytes on a UTF-8 boundary so the capped excerpt stays
        // valid text instead of ending in a replacement character.
        String::from_utf8_lossy(utf8_prefix(raw, max_bytes)).into_owned()
    };
    let shaped = if shaped.len() > max_bytes {
        truncated = true;
        truncate_on_char_boundary(shaped, max_bytes)
    } else {
        shaped
    };
    ShapedBody {
        excerpt: Some(shaped),
        truncated,
        omitted_reason: None,
    }
}

/// Largest prefix of `raw` that is at most `max_bytes` long and does not split
/// a UTF-8 sequence. Invalid input degrades to the plain byte prefix (the
/// caller renders it lossily either way).
fn utf8_prefix(raw: &[u8], max_bytes: usize) -> &[u8] {
    if raw.len() <= max_bytes {
        return raw;
    }
    let candidate = &raw[..max_bytes];
    match std::str::from_utf8(candidate) {
        Ok(_) => candidate,
        Err(error) => {
            // `error_len().is_none()` means the slice ends mid-sequence; cut
            // back to the last complete character. A genuinely invalid byte
            // (`error_len().is_some()`) is not a boundary problem, so keep the
            // full prefix and let lossy decoding mark it.
            if error.error_len().is_none() {
                &candidate[..error.valid_up_to()]
            } else {
                candidate
            }
        }
    }
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

/// Identity used to correlate reassembled SSE fragments across deltas.
///
/// The three key spaces are deliberately disjoint, and each one encodes exactly
/// how much identity the provider actually asserted:
///
/// * [`ReassemblySlot::Indexed`] — a provider-declared valid unsigned `index`.
///   This is the only assertion of identity trusted *across* frames, so it is
///   the only slot whose fragments are concatenated over the whole stream.
/// * [`ReassemblySlot::Positional`] — array position of an entry that carried
///   no `index` at all. Position identifies an entry only *within* the delta
///   that carried it; it is never treated as asserted cross-frame identity.
/// * [`ReassemblySlot::Unattributed`] — a monotonically increasing occurrence
///   ordinal for an entry whose `index` was present but not a valid unsigned
///   integer (string, float, negative, `null`, oversized, object). Every such
///   occurrence gets its **own** ordinal, so two unrelated malformed indices
///   can never share a bucket: a malformed index is an absence of identity, not
///   a shared identity. Collapsing them into one bucket (as a single `None` key
///   would) lets a backend concatenate a complete sensitive JSON argument with
///   unrelated junk, break the JSON, and thereby escape the recursive
///   sensitive-key redaction that depends on the value parsing.
///
/// Fragments in the non-`Indexed` spaces are still captured and redacted —
/// dropping them would let a malformed index hide payload from the audit record
/// entirely — but once their identity is ambiguous their payload is withheld
/// rather than joined on a guess or exported piecemeal (see
/// [`AMBIGUOUS_COMPLETION_TEXT`] and [`AMBIGUOUS_TOOL_CALL_ARGUMENTS`]).
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum ReassemblySlot {
    /// Provider-declared `index`.
    Indexed(u64),
    /// Array position of an `index`-less entry within a single delta.
    Positional(u64),
    /// Occurrence ordinal of an entry whose `index` was present but malformed.
    Unattributed(u64),
}

/// Placeholder exported in place of completion text whose owning choice could
/// not be identified. Withholding is deliberate: the fragments cannot be safely
/// joined (they may belong to different choices) and they cannot be safely
/// exported apart either, because a sensitive JSON key and its value can be
/// split across them and would then escape JSON-key redaction.
const AMBIGUOUS_COMPLETION_TEXT: &str = "[REDACTED:ambiguous_choice]";

/// Placeholder exported in place of tool-call arguments whose owning call could
/// not be identified. Same reasoning as [`AMBIGUOUS_COMPLETION_TEXT`].
const AMBIGUOUS_TOOL_CALL_ARGUMENTS: &str = "[REDACTED:ambiguous_tool_call]";

/// Output key for a choice bucket. A provider index renders as the bare number;
/// the other two spaces carry compiled-in prefixes, so no unidentified bucket
/// can ever render as — or collide with — an index the provider declared.
fn choice_slot_label(slot: ReassemblySlot) -> String {
    match slot {
        ReassemblySlot::Indexed(index) => index.to_string(),
        ReassemblySlot::Positional(position) => format!("position:{position}"),
        ReassemblySlot::Unattributed(occurrence) => format!("unattributed:{occurrence}"),
    }
}

#[derive(Default)]
struct ReassembledChoice {
    content: String,
    tool_calls: BTreeMap<ReassemblySlot, ReassembledToolCall>,
    /// Number of non-empty `delta.tool_calls` arrays applied to this choice.
    /// Counted per applied array rather than per SSE frame so that several
    /// `choices` entries collapsing onto the same choice bucket are recognized
    /// as separate, uncorrelatable contributions. Empty arrays are ignored:
    /// they contribute no correlatable fragment and must not poison a later
    /// single unambiguous indexless call into withholding.
    tool_call_deltas: usize,
    /// Whether any applied tool-call entry lacked a usable provider `index`
    /// (absent → positional, or malformed → unattributed).
    saw_unidentified_tool_call: bool,
    /// Occurrence counter backing [`ReassemblySlot::Unattributed`] tool calls
    /// within this choice.
    unattributed_tool_calls: u64,
    finish_reason: Option<String>,
}

impl ReassembledChoice {
    /// True when this choice's tool-call arguments cannot be attributed to a
    /// specific call with confidence.
    ///
    /// A single delta is always unambiguous: its array entries are distinct
    /// calls by construction and nothing is joined across frames. Once a second
    /// delta contributes to a choice that has any unidentified entry, no
    /// fragment in the choice is trustworthy — the unidentified entry may
    /// continue any earlier call (indexed or not), and conversely an earlier
    /// fragment may be the prefix whose value half arrives in a differently
    /// keyed slot. Both directions are handled by withholding every argument
    /// fragment in the choice.
    fn tool_call_identity_ambiguous(&self) -> bool {
        self.saw_unidentified_tool_call && self.tool_call_deltas > 1
    }
}

/// True when a choice bucket does not rest on provider-asserted identity.
///
/// An indexed bucket is asserted and correlates across frames. A positional
/// bucket is asserted only *within* the one delta that carried it, so it stays
/// trustworthy only while the stream contains no other choice-bearing delta:
/// the moment a second delta exists, some fragment in it — positional or
/// indexed — may be the other half of this bucket's text, and exporting the two
/// halves apart lets a sensitive JSON key and its value escape the recursive
/// key redaction that only runs when the value parses. That is why the test is
/// stream-wide (`multi_delta_stream`) rather than per-bucket: a per-bucket
/// delta count misses a positional bucket whose continuation landed in a
/// *different* bucket, which is exactly the mixed indexed/indexless stream a
/// hostile provider can construct. An unattributed bucket is never asserted at
/// all: it holds exactly one occurrence and its neighbour fragments live in
/// other buckets, so a key/value split across them could never be redacted as
/// JSON.
fn choice_identity_ambiguous(slot: ReassemblySlot, multi_delta_stream: bool) -> bool {
    match slot {
        ReassemblySlot::Indexed(_) => false,
        ReassemblySlot::Positional(_) => multi_delta_stream,
        ReassemblySlot::Unattributed(_) => true,
    }
}

/// Reassemble captured OpenAI `chat.completion.chunk` SSE frames by choice.
/// Text and tool-call fragments are concatenated in frame order, including
/// fragmented arguments, before the caller applies sensitive-field and pattern
/// redaction. Uniformly parseable tool-call-only streams use this path too.
///
/// Optional provider-controlled fields are classified by whether a malformed
/// value can be safely ignored:
///
/// * **Ignorable** — `finish_reason`, `delta`, `delta.content`, `tool_calls`,
///   `id`, `type`, `function`, `function.name`, `function.arguments`. A
///   malformed value here carries no attribution meaning, so it is skipped
///   rather than aborting reassembly. Aborting would fall back to per-frame
///   redaction, which cannot see a secret or PII value split across adjacent
///   fragments — the malformed field would become a redaction-bypass primitive.
///   Malformed payload-bearing values (`content`, `arguments`) are dropped, not
///   coerced to text: splicing a serialized non-string between two real
///   fragments would break the very cross-fragment match this path exists for.
/// * **Identity-bearing** — `choices[].index` and `tool_calls[].index`. These
///   decide which bucket a fragment joins, so a malformed value is neither
///   coerced to `0` nor dropped: it routes to a per-occurrence unattributed
///   bucket (see [`ReassemblySlot`]) so it can neither concatenate onto an
///   unrelated choice or call nor vanish from the record.
///
/// Nothing here ever returns to the raw per-frame fallback because of
/// ambiguous optional identity: per-frame redaction cannot see a value split
/// across adjacent fragments, so a provider that could force it would hold a
/// redaction-bypass primitive. Ambiguity is answered by *withholding* the
/// affected payload behind a fixed compiled-in placeholder plus an evidence
/// flag, never by guessing an attribution and never by exporting the fragments
/// separately.
///
/// Every ignored or re-routed field is reported in the excerpt's
/// `malformed_fields` list so degraded fidelity is visible to the audit
/// consumer instead of silent. That list holds only compiled-in field paths,
/// never provider values, so it cannot become a secret-bearing diagnostic, and
/// it is bounded by the number of distinct field paths below.
fn reassemble_openai_sse_deltas(raw: &[u8]) -> Option<Value> {
    let text = std::str::from_utf8(raw).ok()?;
    let mut per_choice: BTreeMap<ReassemblySlot, ReassembledChoice> = BTreeMap::new();
    let mut unattributed_choices: u64 = 0;
    // Number of deltas (frames) that carried at least one `choices[]` entry.
    // Counted per frame, not per entry, because entries inside one array are
    // distinct choices by construction while separate frames are not.
    let mut choice_deltas: usize = 0;
    let mut malformed_fields: BTreeSet<&'static str> = BTreeSet::new();
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
            if let Some(choices) = frame.get("choices")
                && !choices.is_null()
            {
                malformed_fields.insert("choices");
            }
            continue;
        };
        if !choices.is_empty() {
            choice_deltas = choice_deltas.saturating_add(1);
        }
        for (choice_position, choice) in choices.iter().enumerate() {
            // Identity-bearing: a present-but-malformed index must not collapse
            // onto choice 0 (that would concatenate unrelated completions), must
            // not share one bucket with every *other* malformed index (same
            // concatenation, one step removed), and must not abort reassembly.
            // Each malformed occurrence therefore gets its own ordinal. An
            // *absent* index is keyed by position, which identifies the entry
            // within its own delta only.
            let slot = match choice.get("index") {
                None => ReassemblySlot::Positional(choice_position as u64),
                Some(index) => match index.as_u64() {
                    Some(index) => ReassemblySlot::Indexed(index),
                    None => {
                        malformed_fields.insert("choices[].index");
                        let occurrence = unattributed_choices;
                        unattributed_choices = occurrence.saturating_add(1);
                        ReassemblySlot::Unattributed(occurrence)
                    }
                },
            };
            let accumulated = per_choice.entry(slot).or_default();
            if let Some(finish_reason) = choice.get("finish_reason")
                && !finish_reason.is_null()
            {
                if let Some(finish_reason) = finish_reason.as_str() {
                    accumulated.finish_reason = Some(finish_reason.to_string());
                } else {
                    // Ignorable: keep any previously observed valid reason
                    // rather than overwriting it with a guess.
                    malformed_fields.insert("choices[].finish_reason");
                }
            }
            let Some(delta) = choice.get("delta") else {
                continue;
            };
            let Some(delta) = delta.as_object() else {
                if !delta.is_null() {
                    malformed_fields.insert("choices[].delta");
                }
                continue;
            };
            if let Some(content) = delta.get("content")
                && !content.is_null()
            {
                if let Some(content) = content.as_str() {
                    accumulated.content.push_str(content);
                } else {
                    malformed_fields.insert("choices[].delta.content");
                }
            }
            if let Some(tool_calls) = delta.get("tool_calls") {
                let Some(tool_calls) = tool_calls.as_array() else {
                    if !tool_calls.is_null() {
                        malformed_fields.insert("choices[].delta.tool_calls");
                    }
                    continue;
                };
                // Only non-empty arrays contribute tool-call identity. An empty
                // `tool_calls: []` is a no-op delta: counting it would let a
                // provider poison a later single unambiguous indexless call into
                // withholding without introducing any correlatable fragment.
                if tool_calls.is_empty() {
                    continue;
                }
                accumulated.tool_call_deltas = accumulated.tool_call_deltas.saturating_add(1);
                for (position, tool_call) in tool_calls.iter().enumerate() {
                    let Some(tool_call) = tool_call.as_object() else {
                        if !tool_call.is_null() {
                            malformed_fields.insert("choices[].delta.tool_calls[]");
                        }
                        continue;
                    };
                    // Identity-bearing, same reasoning as the choice index: an
                    // absent index is positional (intra-delta identity only) and
                    // a malformed one takes its own occurrence ordinal, so it
                    // can neither continue an unrelated call nor be dropped from
                    // the record. Either way the choice is marked unidentified,
                    // which withholds its arguments once a second delta lands.
                    let slot = match tool_call.get("index") {
                        None => {
                            accumulated.saw_unidentified_tool_call = true;
                            ReassemblySlot::Positional(position as u64)
                        }
                        Some(index) => match index.as_u64() {
                            Some(index) => ReassemblySlot::Indexed(index),
                            None => {
                                malformed_fields.insert("choices[].delta.tool_calls[].index");
                                accumulated.saw_unidentified_tool_call = true;
                                let occurrence = accumulated.unattributed_tool_calls;
                                accumulated.unattributed_tool_calls = occurrence.saturating_add(1);
                                ReassemblySlot::Unattributed(occurrence)
                            }
                        },
                    };
                    let call = accumulated.tool_calls.entry(slot).or_default();
                    if let Some(id) = tool_call.get("id")
                        && !id.is_null()
                    {
                        if let Some(id) = id.as_str() {
                            merge_sse_scalar_fragment(&mut call.id, id);
                        } else {
                            malformed_fields.insert("choices[].delta.tool_calls[].id");
                        }
                    }
                    if let Some(call_type) = tool_call.get("type")
                        && !call_type.is_null()
                    {
                        if let Some(call_type) = call_type.as_str() {
                            merge_sse_scalar_fragment(&mut call.call_type, call_type);
                        } else {
                            malformed_fields.insert("choices[].delta.tool_calls[].type");
                        }
                    }
                    if let Some(function) = tool_call.get("function")
                        && !function.is_null()
                    {
                        let Some(function) = function.as_object() else {
                            malformed_fields.insert("choices[].delta.tool_calls[].function");
                            continue;
                        };
                        if let Some(name) = function.get("name")
                            && !name.is_null()
                        {
                            if let Some(name) = name.as_str() {
                                merge_sse_scalar_fragment(&mut call.name, name);
                            } else {
                                malformed_fields
                                    .insert("choices[].delta.tool_calls[].function.name");
                            }
                        }
                        if let Some(arguments) = function.get("arguments")
                            && !arguments.is_null()
                        {
                            if let Some(arguments) = arguments.as_str() {
                                call.arguments.push_str(arguments);
                            } else {
                                malformed_fields
                                    .insert("choices[].delta.tool_calls[].function.arguments");
                            }
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
    // Choice identity is a stream-level property: once any bucket rests on a
    // guess, a sensitive key in one bucket may have its value half in another,
    // so no bucket's payload can be exported. Withholding (rather than joining
    // on a guess, or exporting the halves apart) is the only answer that leaks
    // neither direction.
    let multi_delta_stream = choice_deltas > 1;
    let choices_ambiguous = per_choice
        .keys()
        .any(|slot| choice_identity_ambiguous(*slot, multi_delta_stream));
    let mut completion_text = serde_json::Map::new();
    let mut response_tool_calls = serde_json::Map::new();
    let mut finish_reasons = serde_json::Map::new();
    for (choice_slot, choice) in per_choice {
        let choice_key = choice_slot_label(choice_slot);
        let tool_calls_ambiguous = choices_ambiguous || choice.tool_call_identity_ambiguous();
        if !choice.content.is_empty() {
            let content = if choices_ambiguous {
                AMBIGUOUS_COMPLETION_TEXT.to_string()
            } else {
                choice.content
            };
            completion_text.insert(choice_key.clone(), Value::String(content));
        }
        if !choice.tool_calls.is_empty() {
            let mut calls = Vec::with_capacity(choice.tool_calls.len());
            for (slot, call) in choice.tool_calls {
                let mut call_json = serde_json::Map::new();
                // Only a provider-declared index is exported as `index`; the
                // other spaces are labelled for what they are, so the record
                // never implies an identity the provider did not assert.
                let unidentified = match slot {
                    ReassemblySlot::Indexed(index) => {
                        call_json.insert("index".to_string(), Value::from(index));
                        false
                    }
                    ReassemblySlot::Positional(position) => {
                        call_json.insert("position".to_string(), Value::from(position));
                        true
                    }
                    ReassemblySlot::Unattributed(occurrence) => {
                        call_json.insert("index_unattributed".to_string(), Value::Bool(true));
                        call_json.insert("occurrence".to_string(), Value::from(occurrence));
                        true
                    }
                };
                // Under ambiguous identity the scalar fragments of an
                // unidentified call may have been co-located with an unrelated
                // call, so only provider-indexed identity survives.
                let withhold_identity = tool_calls_ambiguous && unidentified;
                if !withhold_identity {
                    if !call.id.is_empty() {
                        call_json.insert("id".to_string(), Value::String(call.id));
                    }
                    if !call.call_type.is_empty() {
                        call_json.insert("type".to_string(), Value::String(call.call_type));
                    }
                }
                let name = if withhold_identity {
                    String::new()
                } else {
                    call.name
                };
                let withhold_arguments = tool_calls_ambiguous && !call.arguments.is_empty();
                let arguments = if withhold_arguments {
                    AMBIGUOUS_TOOL_CALL_ARGUMENTS.to_string()
                } else {
                    call.arguments
                };
                if withhold_arguments {
                    call_json.insert("arguments_withheld".to_string(), Value::Bool(true));
                }
                if !name.is_empty() || !arguments.is_empty() {
                    let mut function = serde_json::Map::new();
                    if !name.is_empty() {
                        function.insert("name".to_string(), Value::String(name));
                    }
                    if !arguments.is_empty() {
                        function.insert("arguments".to_string(), Value::String(arguments));
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
    let completion_text_present = !completion_text.is_empty();
    if completion_text_present {
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
    if choices_ambiguous {
        // Fixed-schema evidence: the consumer learns the excerpt was withheld
        // for identity reasons rather than silently seeing a shorter record.
        annotated.insert("choice_identity_ambiguous".to_string(), Value::Bool(true));
        if completion_text_present {
            annotated.insert("completion_text_withheld".to_string(), Value::Bool(true));
        }
    }
    if !malformed_fields.is_empty() {
        // Compiled-in field paths only, never provider values: the audit
        // consumer learns that some optional fields were malformed and skipped
        // (or re-routed to `unattributed`) without the record itself becoming a
        // channel for the malformed content. Omitted entirely for well-formed
        // streams, so the documented shape is unchanged in the normal case.
        let reported: Vec<Value> = malformed_fields
            .into_iter()
            .map(|field| Value::String(field.to_string()))
            .collect();
        annotated.insert("malformed_fields".to_string(), Value::Array(reported));
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

/// Maximum number of cache-telemetry entries exported into one record's
/// `cache` section. Every admitted key is grammar-checked, so the only
/// remaining growth axis is the number of `ai_semantic_cache` instances on a
/// proxy. The cap keeps a misconfigured or future many-instance chain from
/// widening the record and the collector's key space without bound. Truncation
/// runs after the scan against the sorted `BTreeMap`, so the surviving subset
/// is stable rather than `HashMap`-iteration-order dependent, and it applies
/// only to the per-instance axis: the four fixed-name producer keys are
/// retained first so a wide cache chain cannot displace the record's
/// `request_deduplication.replayed` marker.
const MAX_CACHE_TELEMETRY_ENTRIES: usize = 32;

/// Longest cache-telemetry value retained. Every admitted value is already
/// constrained to a fixed enum or a bounded decimal, so this is a belt-and-braces
/// ceiling on the numeric arm rather than a truncation path.
const MAX_CACHE_TELEMETRY_VALUE_BYTES: usize = 32;

/// The single `request_deduplication` telemetry key. Kept separate from the
/// cache grammar: dedup replay is a different producer with a different
/// meaning, and a bare `starts_with("request_deduplication.")` would export
/// any future request-private staging that plugin adds under its namespace.
const DEDUP_REPLAYED_KEY: &str = "request_deduplication.replayed";

/// Decimal digits in `u64::MAX`; the producer's instance id is a plain `u64`.
const MAX_INSTANCE_ID_DIGITS: usize = 20;

/// Canonicalize one of the three cache telemetry field names.
///
/// `cache_key` is deliberately absent. It is not telemetry: it is the SHA-256
/// fingerprint of the normalized prompt (plus, per config, the consumer and
/// model identity) that `before_proxy` stages for the store hook. It survives
/// to record-assembly time on every miss whose store is skipped (SSE,
/// non-JSON, oversized, unparseable, synthetic short-circuit) and — because
/// `ai_transcript_audit` (2740) runs its final-body hook before
/// `ai_semantic_cache` (4057) clears staging — on ordinary misses too.
/// Exporting it would ship a stable, offline-checkable fingerprint of user
/// prompt content to the audit collector even in `hash`/`metadata` modes,
/// which exist precisely to avoid that.
fn cache_telemetry_field(suffix: &str) -> Option<&'static str> {
    match suffix {
        "cache_status" => Some("cache_status"),
        "cache_match" => Some("cache_match"),
        "cache_similarity" => Some("cache_similarity"),
        _ => None,
    }
}

/// Match `ai_semantic_cache.<instance_id>.<suffix>` against the producer's
/// exact key grammar and return the telemetry suffix.
///
/// `ai_semantic_cache` namespaces its per-request staging as
/// `ai_semantic_cache.` plus the instance's process-unique decimal `u64` id,
/// `.`, and the suffix (`staging_metadata_key` in
/// `src/plugins/ai_semantic_cache.rs`).
/// Matching the full grammar rather than the prefix alone keeps the exported
/// key space equal to the authoritative producer schema: an unrelated key that
/// merely starts with the namespace cannot smuggle arbitrary metadata into an
/// audit record, and the instance id stays in the key so multi-instance
/// provenance is not collapsed.
fn semantic_cache_telemetry_suffix(key: &str) -> Option<&'static str> {
    let rest = key.strip_prefix("ai_semantic_cache.")?;
    let (instance_id, suffix) = rest.split_once('.')?;
    if instance_id.is_empty()
        || instance_id.len() > MAX_INSTANCE_ID_DIGITS
        || (instance_id.len() > 1 && instance_id.starts_with('0'))
        || !instance_id.bytes().all(|byte| byte.is_ascii_digit())
        || instance_id.parse::<u64>().is_err()
    {
        return None;
    }
    cache_telemetry_field(suffix)
}

/// True for an admitted key on the per-instance `ai_semantic_cache.<id>.*`
/// axis — the only part of the `cache` section whose width grows with the
/// number of configured cache instances, and therefore the only part the
/// entry cap truncates.
fn is_namespaced_cache_telemetry_key(key: &str) -> bool {
    semantic_cache_telemetry_suffix(key).is_some()
}

/// Classify a metadata key as exportable cache telemetry, returning the
/// producer-schema suffix that governs its value domain.
fn cache_telemetry_suffix(key: &str) -> Option<&'static str> {
    if key == DEDUP_REPLAYED_KEY {
        return Some("replayed");
    }
    // Legacy `ai_cache_status` is the namespaced `cache_status` field with an
    // `ai_` prefix, so the two spellings share one value domain.
    if let Some(legacy) = key.strip_prefix("ai_")
        && let Some(suffix) = cache_telemetry_field(legacy)
    {
        return Some(suffix);
    }
    semantic_cache_telemetry_suffix(key)
}

/// Reject values outside the producer's domain for a telemetry suffix.
///
/// The producers emit fixed tokens (`HIT` / `MISS` / `BYPASS`, `semantic`) and
/// a `{:.6}`-formatted similarity in `[0, 1]`. Validating the value as well as
/// the key means the `cache` section cannot carry an unbounded or
/// attacker-shaped string even if some future writer reuses a telemetry key.
fn cache_telemetry_value_admitted(suffix: &str, value: &str) -> bool {
    if value.len() > MAX_CACHE_TELEMETRY_VALUE_BYTES {
        return false;
    }
    match suffix {
        "cache_status" => matches!(value, "HIT" | "MISS" | "BYPASS"),
        "cache_match" => value == "semantic",
        "cache_similarity" => cache_similarity_value_admitted(value),
        "replayed" => matches!(value, "true" | "false"),
        _ => false,
    }
}

/// Admit only the exact `format!("{similarity:.6}")` spelling the semantic
/// cache producer writes for similarities in `[0, 1]`.
///
/// `f64::from_str` would also accept short forms (`0.95`), signs (`+1.0`), and
/// exponents (`1e0`). Those are not producer output and would widen the
/// collector's observed value space past the documented fixed six-fraction
/// decimal, so they are dropped here.
fn cache_similarity_value_admitted(value: &str) -> bool {
    let bytes = value.as_bytes();
    if bytes.len() != 8 || bytes[1] != b'.' {
        return false;
    }
    match bytes[0] {
        b'0' => bytes[2..].iter().all(u8::is_ascii_digit),
        b'1' => &bytes[2..] == b"000000",
        _ => false,
    }
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

fn extract_model_bounded(
    json: &Value,
    redactor: &PiiRedactor,
    redact_before_bound: bool,
) -> BoundedModel {
    let Some(raw) = json.get("model").and_then(Value::as_str) else {
        return BoundedModel::default();
    };
    bound_model_str(raw, redactor, redact_before_bound)
}

/// Bound a request-derived model string for staging/export.
///
/// Ordering matters for every mode except the explicit `full_body` raw-capture
/// opt-in: redaction runs over the FULL observed string first and the retained
/// UTF-8-safe prefix is selected afterwards, so a sensitive token straddling
/// the `MAX_MODEL_BYTES` ceiling can never leak as an unmatched raw prefix.
/// Truncation evidence always hashes the original unredacted value; staging
/// never retains raw excess bytes. `full_body` deliberately keeps the bounded
/// raw prefix.
fn bound_model_str(raw: &str, redactor: &PiiRedactor, redact_before_bound: bool) -> BoundedModel {
    if raw.is_empty() {
        return BoundedModel::default();
    }
    if redact_before_bound {
        // Temporary full-string redaction is request-scoped; the retained
        // value below is hard-bounded for staging and queued records.
        let redacted = redactor.redact(raw);
        let mut truncated = raw.len() > MAX_MODEL_BYTES;
        let retained = if redacted.len() > MAX_MODEL_BYTES {
            truncated = true;
            truncate_str_ref(&redacted, MAX_MODEL_BYTES).to_string()
        } else {
            redacted
        };
        let hash = if truncated {
            Some(redactor.keyed_hash_hex(raw.as_bytes()))
        } else {
            None
        };
        return BoundedModel {
            value: Some(retained),
            truncated,
            hash,
        };
    }
    if raw.len() <= MAX_MODEL_BYTES {
        return BoundedModel {
            value: Some(raw.to_string()),
            truncated: false,
            hash: None,
        };
    }
    // Hash the full original without retaining excess bytes in staging/records.
    let hash = redactor.keyed_hash_hex(raw.as_bytes());
    let prefix = truncate_str_ref(raw, MAX_MODEL_BYTES);
    BoundedModel {
        value: Some(prefix.to_string()),
        truncated: true,
        hash: Some(hash),
    }
}

/// Cap non-model metadata strings that are still request-derived publisher
/// values so a hostile `ai_provider` cannot bypass excerpt budgets.
fn bound_short_metadata(raw: &str) -> String {
    truncate_str_ref(raw, MAX_MODEL_BYTES).to_string()
}

/// Bound request-derived tool/function names for staging/export.
///
/// Same redact-then-bound ordering as [`bound_model_str`] for protected modes:
/// each observed name is redacted in full before the per-name / aggregate
/// UTF-8-safe admit decision, while truncation evidence hashes the original
/// unredacted names. `full_body` retains bounded raw prefixes.
fn extract_tool_names_bounded(
    json: &Value,
    redactor: &PiiRedactor,
    redact_before_bound: bool,
) -> BoundedToolNames {
    let mut hasher = redactor.keyed_hasher();
    let mut names = Vec::new();
    let mut aggregate_bytes = 0usize;
    let mut omitted = 0u32;
    let mut truncated = false;
    let mut saw_any = false;

    for key in ["tools", "functions"] {
        let Some(entries) = json.get(key).and_then(Value::as_array) else {
            continue;
        };
        for entry in entries {
            let Some(name) = entry
                .get("function")
                .and_then(|function| function.get("name"))
                .and_then(Value::as_str)
                .or_else(|| entry.get("name").and_then(Value::as_str))
            else {
                continue;
            };
            saw_any = true;
            // Evidence hash covers every observed name before any admit/omit,
            // without cloning the raw excess into the retained set.
            hasher.update(name.as_bytes());
            hasher.update(&[0]);

            // Protected modes: redact the full name first (temporary), then
            // select the retained UTF-8-safe prefix. full_body keeps raw.
            // Truncation evidence is driven by the original unredacted length.
            if name.len() > MAX_TOOL_NAME_BYTES {
                truncated = true;
            }
            let redacted;
            let candidate = if redact_before_bound {
                redacted = redactor.redact(name);
                redacted.as_str()
            } else {
                name
            };
            let admitted = if candidate.len() > MAX_TOOL_NAME_BYTES {
                truncated = true;
                truncate_str_ref(candidate, MAX_TOOL_NAME_BYTES)
            } else {
                candidate
            };

            if names.len() >= MAX_TOOL_NAMES
                || aggregate_bytes.saturating_add(admitted.len()) > MAX_TOOL_NAMES_AGGREGATE_BYTES
            {
                truncated = true;
                omitted = omitted.saturating_add(1);
                continue;
            }
            aggregate_bytes = aggregate_bytes.saturating_add(admitted.len());
            names.push(admitted.to_string());
        }
    }

    if !saw_any {
        return BoundedToolNames::default();
    }

    names.sort();
    names.dedup();
    let hash = if truncated {
        Some(hasher.finalize_hex())
    } else {
        // Drop the hasher without exporting a hash when nothing was truncated.
        let _ = hasher.finalize_hex();
        None
    };
    BoundedToolNames {
        names,
        truncated,
        omitted,
        hash,
    }
}

/// Truncate `text` to at most `max_bytes` without splitting a UTF-8 code point,
/// returning a borrowed prefix so hostile inputs are not fully owned first.
fn truncate_str_ref(text: &str, max_bytes: usize) -> &str {
    if text.len() <= max_bytes {
        return text;
    }
    let mut end = max_bytes;
    while end > 0 && !text.is_char_boundary(end) {
        end -= 1;
    }
    &text[..end]
}

fn admit_limits_config(limits_obj: &Value) -> Result<LimitsConfig, String> {
    let max_request_bytes = cfg_positive_usize_capped(
        limits_obj,
        "max_request_bytes",
        65536,
        "limits",
        HARD_MAX_REQUEST_BYTES,
    )?;
    let max_response_bytes = cfg_positive_usize_capped(
        limits_obj,
        "max_response_bytes",
        65536,
        "limits",
        HARD_MAX_RESPONSE_BYTES,
    )?;
    let max_stream_capture_bytes = cfg_positive_usize_capped(
        limits_obj,
        "max_stream_capture_bytes",
        65536,
        "limits",
        HARD_MAX_STREAM_CAPTURE_BYTES,
    )?;
    let aggregate = max_request_bytes
        .saturating_add(max_response_bytes)
        .saturating_add(max_stream_capture_bytes);
    if aggregate > HARD_MAX_CAPTURE_BYTES_AGGREGATE {
        return Err(format!(
            "ai_transcript_audit: sum of 'limits.max_request_bytes' + \
             'limits.max_response_bytes' + 'limits.max_stream_capture_bytes' \
             ({aggregate}) must be <= {HARD_MAX_CAPTURE_BYTES_AGGREGATE}"
        ));
    }
    let max_redaction_scan_bytes = cfg_positive_usize_capped(
        limits_obj,
        "max_redaction_scan_bytes",
        DEFAULT_MAX_REDACTION_SCAN_BYTES,
        "limits",
        HARD_MAX_REDACTION_SCAN_BYTES,
    )?;
    if max_redaction_scan_bytes < MIN_REDACTION_SCAN_BYTES {
        return Err(format!(
            "ai_transcript_audit: 'limits.max_redaction_scan_bytes' must be >= \
             {MIN_REDACTION_SCAN_BYTES}"
        ));
    }
    let max_stream_reservation_secs = cfg_u64(
        limits_obj,
        "max_stream_reservation_secs",
        DEFAULT_MAX_STREAM_RESERVATION_SECS,
        "limits",
    )?;
    if !(MIN_STREAM_RESERVATION_SECS..=HARD_MAX_STREAM_RESERVATION_SECS)
        .contains(&max_stream_reservation_secs)
    {
        return Err(format!(
            "ai_transcript_audit: 'limits.max_stream_reservation_secs' must be between \
             {MIN_STREAM_RESERVATION_SECS} and {HARD_MAX_STREAM_RESERVATION_SECS}"
        ));
    }

    let mut limits = LimitsConfig {
        max_request_bytes,
        max_response_bytes,
        max_stream_capture_bytes,
        max_redaction_scan_bytes,
        // Placeholders; resolved below once the per-record contract is known.
        max_entry_bytes: 0,
        buffer_max_bytes: 0,
        max_stream_reservation: Duration::from_secs(max_stream_reservation_secs),
    };

    // Aggregate retained-byte admission. A record-count queue bound alone lets
    // `buffer_capacity` x attacker-shaped record bytes accumulate whenever the
    // collector slows down, so admission is (count AND bytes).
    let min_entry_bytes = limits.min_entry_bytes();
    let max_entry_bytes = cfg_positive_usize_capped(
        limits_obj,
        "max_entry_bytes",
        min_entry_bytes.min(HARD_MAX_RECORD_ENTRY_BYTES),
        "limits",
        HARD_MAX_RECORD_ENTRY_BYTES,
    )?;
    if max_entry_bytes < min_entry_bytes {
        return Err(format!(
            "ai_transcript_audit: 'limits.max_entry_bytes' ({max_entry_bytes}) must be >= \
             {min_entry_bytes}, the worst-case serialized JSON contract implied by the configured \
             capture limits; a smaller value could make a record within that contract \
             inadmissible"
        ));
    }
    let buffer_max_bytes = cfg_positive_usize_capped(
        limits_obj,
        "buffer_max_bytes",
        DEFAULT_RETAINED_BUFFER_MAX_BYTES,
        "limits",
        HARD_MAX_RETAINED_BUFFER_BYTES,
    )?;
    if buffer_max_bytes < MIN_RETAINED_BUFFER_BYTES {
        return Err(format!(
            "ai_transcript_audit: 'limits.buffer_max_bytes' must be >= {MIN_RETAINED_BUFFER_BYTES}"
        ));
    }
    let max_entry_retained_bytes = accounted_record_bytes(max_entry_bytes);
    if buffer_max_bytes < max_entry_retained_bytes {
        return Err(format!(
            "ai_transcript_audit: 'limits.buffer_max_bytes' ({buffer_max_bytes}) must be >= \
             the maximum retained charge for 'limits.max_entry_bytes' \
             ({max_entry_retained_bytes}); otherwise no record could ever be admitted"
        ));
    }
    limits.max_entry_bytes = max_entry_bytes;
    limits.buffer_max_bytes = buffer_max_bytes;
    Ok(limits)
}

fn cfg_positive_usize_capped(
    obj: &Value,
    key: &str,
    default: usize,
    ctx: &str,
    hard_max: usize,
) -> Result<usize, String> {
    let value = cfg_positive_usize(obj, key, default, ctx)?;
    if value > hard_max {
        return Err(format!(
            "ai_transcript_audit: '{ctx}.{key}' must be <= {hard_max} (deployment hard maximum)"
        ));
    }
    Ok(value)
}

static NEXT_STATUS_ID: AtomicU64 = AtomicU64::new(0);

/// Live status source for one committed instance. Admitted ceilings are frozen
/// at commit; retention/expiry/health gauges are read through shared atomics so
/// authenticated `/health` reports the current state rather than a stale copy.
struct StatusSource {
    base: AiTranscriptAuditSnapshot,
    retained_budget: Arc<ByteBudget>,
    stream_reservations_expired: Arc<AtomicU64>,
    sink_healthy: Arc<AtomicBool>,
}

impl StatusSource {
    fn render(&self) -> AiTranscriptAuditSnapshot {
        let mut snapshot = self.base.clone();
        snapshot.retained_bytes = self.retained_budget.used() as u64;
        snapshot.retained_byte_drops = self.retained_budget.drops_total();
        snapshot.stream_reservations_expired =
            self.stream_reservations_expired.load(Ordering::Relaxed);
        snapshot.sink_healthy = self.sink_healthy.load(Ordering::Relaxed);
        snapshot
    }
}

fn active_status_snapshots() -> &'static Mutex<BTreeMap<u64, StatusSource>> {
    static SNAPSHOTS: OnceLock<Mutex<BTreeMap<u64, StatusSource>>> = OnceLock::new();
    SNAPSHOTS.get_or_init(|| Mutex::new(BTreeMap::new()))
}

fn register_status_snapshot(id: u64, source: StatusSource) {
    let mut guard = match active_status_snapshots().lock() {
        Ok(guard) => guard,
        Err(poisoned) => poisoned.into_inner(),
    };
    guard.insert(id, source);
}

fn unregister_status_snapshot(id: u64) {
    let mut guard = match active_status_snapshots().lock() {
        Ok(guard) => guard,
        Err(poisoned) => poisoned.into_inner(),
    };
    guard.remove(&id);
}

/// Authenticated diagnostics snapshots for every committed transcript-audit
/// instance. Values are numeric admitted ceilings only — never body content.
pub fn snapshots() -> Vec<AiTranscriptAuditSnapshot> {
    let guard = match active_status_snapshots().lock() {
        Ok(guard) => guard,
        Err(poisoned) => poisoned.into_inner(),
    };
    guard.values().map(StatusSource::render).collect()
}

impl Drop for AiTranscriptAudit {
    fn drop(&mut self) {
        if let Some(id) = self.status_id.get() {
            unregister_status_snapshot(*id);
        }
    }
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

/// Whether every byte of `text` is legal inside an HTTP header value
/// (visible ASCII, space, or HTAB, plus obs-text). Rejects the CR/LF/NUL and
/// other control bytes that would make `HeaderValue::from_str` fail, so a
/// literal template segment can be validated at config parse independently of
/// the (unknown) secret bytes.
fn is_header_value_safe(text: &str) -> bool {
    text.bytes()
        .all(|byte| byte == b'\t' || (0x20..=0x7e).contains(&byte) || byte >= 0x80)
}

/// Push a validated literal segment (skipping empty runs). A literal that
/// carries bytes illegal in a header value is a hard config error.
fn push_literal_segment(
    segments: &mut Vec<HeaderSegment>,
    text: &str,
    display_name: &str,
) -> Result<(), String> {
    if text.is_empty() {
        return Ok(());
    }
    if !is_header_value_safe(text) {
        return Err(format!(
            "ai_transcript_audit: sink.custom_headers['{display_name}'] value contains bytes \
             that are invalid in an HTTP header value"
        ));
    }
    segments.push(HeaderSegment::Literal(text.to_string()));
    Ok(())
}

/// Parse a single custom-header value template into literal/secret segments.
///
/// The only secret syntax is `${secret:NAME}`, which resolves
/// `FERRUM_TRANSCRIPT_SINK_SECRET_<NAME>` at activation. `NAME` is uppercase
/// `[A-Z_][A-Z0-9_]*`. Any other `${...}` form — including a bare
/// `${SOME_VAR}` process-environment reference — is a hard error, so unrelated
/// environment secrets can never be interpolated and a malformed reference can
/// never be silently emitted as literal text.
fn parse_header_template(template: &str, display_name: &str) -> Result<Vec<HeaderSegment>, String> {
    let mut segments: Vec<HeaderSegment> = Vec::new();
    let mut rest = template;
    while let Some(start) = rest.find("${") {
        push_literal_segment(&mut segments, &rest[..start], display_name)?;
        let after = &rest[start + 2..];
        let Some(end) = after.find('}') else {
            return Err(format!(
                "ai_transcript_audit: sink.custom_headers['{display_name}'] has an unterminated \
                 '${{...}}' reference; only '${{secret:NAME}}' references are supported"
            ));
        };
        let inner = &after[..end];
        let Some(suffix) = inner.strip_prefix("secret:") else {
            return Err(format!(
                "ai_transcript_audit: sink.custom_headers['{display_name}'] uses an unsupported \
                 reference '${{{inner}}}'; only '${{secret:NAME}}' is permitted (it resolves \
                 the {SINK_SECRET_ENV_PREFIX}NAME environment variable and cannot read any other \
                 process environment variable)"
            ));
        };
        if !is_valid_secret_suffix(suffix) {
            return Err(format!(
                "ai_transcript_audit: sink.custom_headers['{display_name}'] secret reference name \
                 '{suffix}' must be uppercase [A-Z_][A-Z0-9_]* (it resolves \
                 {SINK_SECRET_ENV_PREFIX}{suffix})"
            ));
        }
        segments.push(HeaderSegment::Secret(format!(
            "{SINK_SECRET_ENV_PREFIX}{suffix}"
        )));
        rest = &after[end + 1..];
    }
    push_literal_segment(&mut segments, rest, display_name)?;
    if segments.is_empty() {
        return Err(format!(
            "ai_transcript_audit: sink.custom_headers['{display_name}'] value must not be empty"
        ));
    }
    Ok(segments)
}

/// Secret-reference name charset: uppercase letters/underscore, then also
/// digits. Mirrors env-var naming and keeps the resolved name inside the
/// `FERRUM_TRANSCRIPT_SINK_SECRET_` namespace with no way to escape it.
fn is_valid_secret_suffix(suffix: &str) -> bool {
    let mut bytes = suffix.bytes();
    let Some(first) = bytes.next() else {
        return false;
    };
    if !(first == b'_' || first.is_ascii_uppercase()) {
        return false;
    }
    bytes.all(|byte| byte == b'_' || byte.is_ascii_uppercase() || byte.is_ascii_digit())
}

/// Resolve every [`CustomHeaderSpec`] against the environment into concrete
/// headers. Called once at background-task activation. A secret that is unset
/// or empty, or a value that is not a legal `HeaderValue`, is a hard error so
/// activation fails closed. The resolved secret value is never logged or placed
/// in any error message; produced values are marked sensitive.
fn materialize_sink_headers(
    specs: &[CustomHeaderSpec],
) -> Result<Vec<(HeaderName, HeaderValue)>, String> {
    let mut out = Vec::with_capacity(specs.len());
    for spec in specs {
        let mut value = String::new();
        for segment in &spec.segments {
            match segment {
                HeaderSegment::Literal(text) => value.push_str(text),
                HeaderSegment::Secret(env_name) => {
                    let resolved = std::env::var(env_name).map_err(|_| {
                        format!(
                            "ai_transcript_audit: sink.custom_headers['{}'] requires environment \
                             variable {env_name}, which is not set",
                            spec.display_name
                        )
                    })?;
                    if resolved.is_empty() {
                        return Err(format!(
                            "ai_transcript_audit: sink.custom_headers['{}'] environment variable \
                             {env_name} is set but empty",
                            spec.display_name
                        ));
                    }
                    value.push_str(&resolved);
                }
            }
        }
        // A purely-literal empty value is rejected at parse; this guards the
        // case where every segment resolved but combined to empty.
        if value.is_empty() {
            return Err(format!(
                "ai_transcript_audit: sink.custom_headers['{}'] materialized to an empty value",
                spec.display_name
            ));
        }
        let mut header_value = HeaderValue::from_str(&value).map_err(|_| {
            format!(
                "ai_transcript_audit: sink.custom_headers['{}'] materialized to a value that is \
                 not a valid HTTP header",
                spec.display_name
            )
        })?;
        header_value.set_sensitive(true);
        out.push((spec.name.clone(), header_value));
    }
    Ok(out)
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

/// Parse and statically validate `sink.custom_headers`. Header names and value
/// templates (literal + `${secret:NAME}` segments) are validated here at config
/// admission (CP/admin-safe: no environment is read). Secrets are resolved only
/// later, at activation, by [`materialize_sink_headers`].
fn parse_sink_headers(obj: &Value) -> Result<Vec<CustomHeaderSpec>, String> {
    let mut out: Vec<CustomHeaderSpec> = Vec::new();
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
        let segments = parse_header_template(value, key)?;
        out.retain(|spec| spec.name != name);
        out.push(CustomHeaderSpec {
            name,
            display_name: key.clone(),
            segments,
        });
    }
    Ok(out)
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

fn cfg_positive_usize(obj: &Value, key: &str, default: usize, ctx: &str) -> Result<usize, String> {
    match obj.get(key) {
        None | Some(Value::Null) => Ok(default),
        Some(value) => {
            let number = value.as_u64().ok_or_else(|| {
                format!("ai_transcript_audit: '{ctx}.{key}' must be a positive integer")
            })?;
            if number == 0 {
                return Err(format!(
                    "ai_transcript_audit: '{ctx}.{key}' must be greater than 0"
                ));
            }
            Ok(usize::try_from(number).unwrap_or(usize::MAX))
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
