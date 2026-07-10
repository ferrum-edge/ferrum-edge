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
//! Runs at priority `AI_TRANSCRIPT_AUDIT` (2924): before reject-capable AI
//! guardrails so blocked prompts can still be staged for
//! `always_capture_on_guardrail`, and before `ai_semantic_cache` (2980) /
//! `ai_federation` (4060) so cache hits and federated requests are still
//! observable. The audit candidate is staged in `before_proxy` over the
//! prebuffered request body (so terminate-and-respond plugins downstream cannot
//! consume the transaction unaudited, and so the proxy's response buffering /
//! dispatch decisions can see the candidate markers), then refreshed with the
//! final backend-visible body in `on_final_request_body_with_context` after
//! request redaction/transforms ran.
//!
//! This plugin is **not** a security boundary on its own — it observes and
//! redacts, it does not enforce. Pair it with `ai_prompt_shield`,
//! `ai_semantic_firewall`, `ai_response_guard`, and the tool governance in
//! `ai_semantic_firewall` for enforcement.

use std::collections::{BTreeMap, HashMap};
use std::sync::Arc;
use std::sync::Mutex;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

use async_trait::async_trait;
use bytes::Bytes;
use dashmap::DashMap;
use http::header::{HeaderName, HeaderValue};
use serde::Serialize;
use serde_json::Value;
use sha2::{Digest, Sha256};
use tracing::warn;

use super::utils::ai_pii::{KeyedBodyHasher, PiiRedactor};
use super::utils::body_transform::is_json_content_type;
use super::utils::metadata_redaction::{REDACTED_PLACEHOLDER, is_sensitive_metadata_key};
use super::utils::{
    BatchConfigDefaults, BatchingLogger, LoggerHooks, PluginHttpClient, build_batch_config,
    handle_http_batch_response, parse_http_endpoint, validate_batch_config,
};
use super::{
    HTTP_ONLY_PROTOCOLS, Plugin, PluginResult, ProxyProtocol, RequestContext, ResponseStreamAction,
    ResponseStreamInspector, TransactionSummary,
};
use crate::proxy::SYNTHETIC_SHORT_CIRCUIT_METADATA_KEY;

/// Schema version stamped onto every emitted record.
const RECORD_VERSION: u32 = 1;

/// Above this many staged entries, opportunistically drop expired orphans (a
/// request that never reached the `log` hook). The common path removes staging
/// at emit/log time, so this only guards pathological cases.
const STAGING_SWEEP_THRESHOLD: usize = 512;

// Metadata keys written into `ctx.metadata` (small strings only — never bodies).
// These flow into the transaction log via the summary metadata.
const MD_RECORD_ID: &str = "ai_transcript_audit.record_id";
const MD_CANDIDATE: &str = "ai_transcript_audit.candidate";
const MD_SAMPLED: &str = "ai_transcript_audit.sampled";
const MD_SAMPLE_HIT: &str = "ai_transcript_audit.sample_hit";
const MD_REQUEST_HASH: &str = "ai_transcript_audit.request_hash";
const MD_RESPONSE_HASH: &str = "ai_transcript_audit.response_hash";
const MD_SINK_STATUS: &str = "ai_transcript_audit.sink_status";
const MD_STREAM_MARKER: &str = "ai_transcript_audit.stream_marker";
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
    captured_at: Instant,
    sample_hit: bool,
    request_excerpt: Option<String>,
    request_truncated: bool,
    request_hash: Option<String>,
    request_model: Option<String>,
    tool_names: Vec<String>,
}

/// Response bytes captured by the streaming inspector, handed to
/// `on_response_stream_terminated` for record assembly (which has `ctx` and so
/// can harvest response-side guardrail metadata).
struct StreamCaptured {
    response_excerpt: Option<String>,
    response_truncated: bool,
    response_hash: String,
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
    request_body_truncated: bool,
    response_body_truncated: bool,
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
    /// Header name + `${VAR}`-expandable value template. The template (not the
    /// resolved secret) is stored, so a config dump never leaks the token.
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
    logger: BatchingLogger<AuditRecord>,
    endpoint_hostname: String,
    namespace: String,
    staging: Arc<DashMap<String, AuditStaging>>,
    pending_streams: Arc<DashMap<String, Arc<StreamSlot>>>,
    rate_limiter: Arc<RecordsPerMinute>,
    sink_healthy: Arc<AtomicBool>,
    /// `true` when at least one capture path is enabled (validated in `new`).
    active: bool,
    staging_ttl: Duration,
}

impl AiTranscriptAudit {
    pub fn new(config: &Value, http_client: PluginHttpClient) -> Result<Self, String> {
        if !config.is_object() {
            return Err("ai_transcript_audit: config must be an object".to_string());
        }
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
        let limits_obj = cfg_object(config, "limits", "limits")?.unwrap_or(&empty);
        let limits = LimitsConfig {
            max_request_bytes: cfg_positive_usize(
                limits_obj,
                "max_request_bytes",
                65536,
                "limits",
            )?,
            max_response_bytes: cfg_positive_usize(
                limits_obj,
                "max_response_bytes",
                65536,
                "limits",
            )?,
            max_stream_capture_bytes: cfg_positive_usize(
                limits_obj,
                "max_stream_capture_bytes",
                65536,
                "limits",
            )?,
        };

        // ---- privacy ----
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
        let custom_headers = parse_sink_headers(sink_obj)?;
        let batch_defaults = BatchConfigDefaults {
            batch_size_key: "batch_size",
            batch_size: 50,
            flush_interval_ms: 1000,
            min_flush_interval_ms: 100,
            buffer_capacity: 10000,
            max_retries: 3,
            retry_delay_ms: 1000,
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

        // ---- background worker ----
        let shard_amount = http_client.pool_shard_amount();
        let sink_healthy = Arc::new(AtomicBool::new(true));
        let flush_config = HttpFlushConfig {
            endpoint_url,
            custom_headers,
            http_client,
            sink_healthy: Arc::clone(&sink_healthy),
        };
        let hooks = LoggerHooks {
            on_failed_batch: {
                let healthy = Arc::clone(&sink_healthy);
                Some(Arc::new(move |_batch: Vec<AuditRecord>, _error: String| {
                    healthy.store(false, Ordering::Relaxed);
                }))
            },
            ..LoggerHooks::default()
        };
        let logger = BatchingLogger::spawn_with_hooks(
            build_batch_config(sink_obj, "ai_transcript_audit", batch_defaults),
            hooks,
            move |batch| {
                let flush_config = flush_config.clone();
                async move { send_batch(&flush_config, batch).await }
            },
        );

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
            logger,
            endpoint_hostname,
            namespace,
            staging: Arc::new(DashMap::with_shard_amount(shard_amount)),
            pending_streams: Arc::new(DashMap::with_shard_amount(shard_amount)),
            rate_limiter: Arc::new(RecordsPerMinute::new(sampling.max_records_per_minute)),
            sink_healthy,
            active,
            staging_ttl: Duration::from_secs(60 * 60),
        })
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

    fn enqueue(&self, record: AuditRecord) -> SinkOutcome {
        if !self.rate_limiter.try_acquire() {
            return SinkOutcome::Dropped;
        }
        if self.logger.try_send(record) {
            SinkOutcome::Queued
        } else if self.on_buffer_full == BufferFullPolicy::Reject {
            SinkOutcome::Rejected
        } else {
            SinkOutcome::Dropped
        }
    }

    fn sweep_staging(&self) {
        if self.staging.len() < STAGING_SWEEP_THRESHOLD {
            return;
        }
        let now = Instant::now();
        let ttl = self.staging_ttl;
        self.staging
            .retain(|_, staging| now.duration_since(staging.captured_at) < ttl);
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
    fn stage_candidate(&self, ctx: &mut RequestContext, body: &[u8]) {
        if body.is_empty() {
            if !flag(&ctx.metadata, MD_CANDIDATE) {
                ctx.metadata
                    .insert(MD_CANDIDATE.to_string(), "false".to_string());
            }
            return;
        }
        let parsed: Option<Value> = serde_json::from_slice(body).ok();
        let is_ai = parsed.as_ref().is_some_and(json_looks_like_ai_request);
        if !is_ai {
            if !flag(&ctx.metadata, MD_CANDIDATE) {
                ctx.metadata
                    .insert(MD_CANDIDATE.to_string(), "false".to_string());
            }
            return;
        }

        let record_id = ctx
            .metadata
            .get(MD_RECORD_ID)
            .cloned()
            .unwrap_or_else(|| uuid::Uuid::new_v4().to_string());
        let sample_hit = sample_from_record_id(&record_id) < self.sampling.rate;
        // Exported body hashes are keyed HMAC-SHA256 (same key as the redaction
        // placeholders): a plain SHA-256 of a mostly-predictable body (a fixed
        // chat JSON wrapper around one secret) would be an offline brute-force
        // oracle for the secret in every mode, including hash_only.
        let request_hash = self.redactor.keyed_hash_hex(body);

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

        // Mark every staged AI candidate for potential stream capture. The
        // marker alone does not force anything: `forces_reqwest_dispatch` and
        // `response_stream_inspector` apply the `sampled`-mode tee gate
        // (`stream_tee_wanted`) at dispatch/response time, when the request-side
        // guardrails (2925–2975, which run after this plugin's staging at 2924)
        // have already published their metadata. Non-AI JSON POSTs are never
        // marked, so they stay on the native-H3 path.
        if self.capture.streaming != StreamingCapture::Off {
            self.mark_stream_capture(ctx);
        }

        let request_model = parsed.as_ref().and_then(extract_model);
        let tool_names = if self.capture.tool_calls {
            parsed.as_ref().map(extract_tool_names).unwrap_or_default()
        } else {
            Vec::new()
        };
        let (request_excerpt, request_truncated) = if self.capture.request {
            self.shape_body(body, self.limits.max_request_bytes)
        } else {
            (None, false)
        };

        self.sweep_staging();
        self.staging.insert(
            record_id,
            AuditStaging {
                captured_at: Instant::now(),
                sample_hit,
                request_excerpt,
                request_truncated,
                request_hash: Some(request_hash),
                request_model,
                tool_names,
            },
        );
    }

    /// Refresh an already-staged candidate with the FINAL backend-visible
    /// request body (request transforms run after `before_proxy`, where the
    /// candidate was staged). No-op when the body is unchanged, so the common
    /// no-transform path costs one keyed-hash pass.
    fn refresh_staged_request(&self, ctx: &mut RequestContext, body: &[u8]) {
        let Some(record_id) = ctx.metadata.get(MD_RECORD_ID).cloned() else {
            return;
        };
        let request_hash = self.redactor.keyed_hash_hex(body);
        if ctx
            .metadata
            .get(MD_REQUEST_HASH)
            .is_some_and(|existing| *existing == request_hash)
        {
            return;
        }
        let parsed: Option<Value> = serde_json::from_slice(body).ok();
        if let Some(mut staged) = self.staging.get_mut(&record_id) {
            let (request_excerpt, request_truncated) = if self.capture.request {
                self.shape_body(body, self.limits.max_request_bytes)
            } else {
                (None, false)
            };
            staged.request_excerpt = request_excerpt;
            staged.request_truncated = request_truncated;
            staged.request_hash = Some(request_hash.clone());
            staged.request_model = parsed.as_ref().and_then(extract_model);
            if self.capture.tool_calls {
                staged.tool_names = parsed.as_ref().map(extract_tool_names).unwrap_or_default();
            }
        }
        ctx.metadata
            .insert(MD_REQUEST_HASH.to_string(), request_hash);
    }

    fn stream_marker_key(&self) -> String {
        format!("{MD_STREAM_MARKER}.{:p}", self)
    }

    fn mark_stream_capture(&self, ctx: &mut RequestContext) {
        ctx.metadata
            .insert(MD_STREAM_MARKER.to_string(), "true".to_string());
        ctx.metadata
            .insert(self.stream_marker_key(), "true".to_string());
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
    /// dispatch/response time — because the guardrail plugins at 2925–2975 run
    /// AFTER staging at 2924 but BEFORE the proxy's dispatch decision, so
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
                    if key.starts_with("ai_cache") {
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
            request_body_truncated: request_truncated,
            response_body_truncated: response_truncated,
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
        // the common SSE success case. The marker is derived from the
        // pre-transform body because this decision is made before request-body
        // transforms run; a later transformer that rewrites `stream` cannot be
        // reflected here (same ordering limit as the AI-candidate
        // classification; proxy-core follow-up: issue #2055).
        if flag(&ctx.metadata, MD_STREAM_REQUEST) {
            return false;
        }
        match ctx.metadata.get(MD_CANDIDATE).map(String::as_str) {
            Some("true") => true,
            // `before_proxy` classified the pre-transform body as non-AI. This
            // decision is locked in before `on_final_request_body_with_context`
            // could re-stage a candidate that a later request-body transformer
            // (ordered after priority 2924) turned into an AI payload, so such a
            // request's *buffered* response body is not captured. That is a
            // deliberate tradeoff: buffering every JSON POST response instead
            // would re-introduce the over-buffering of ordinary non-AI traffic a
            // prior review flagged. The stream marker has the same pre-transform
            // limit: only bodies that classified as AI at staging time are
            // marked for stream inspection (proxy-core follow-up: issue #2055).
            // The transaction is still audited request-side via the `log`
            // fallback.
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

    fn warmup_hostnames(&self) -> Vec<String> {
        vec![self.endpoint_hostname.clone()]
    }

    // ---- request body capture ----

    fn requires_request_body_buffering(&self) -> bool {
        self.active
    }

    /// The request body must be prebuffered before `before_proxy` so the
    /// candidate is staged **before**:
    /// - `before_proxy` terminators (`ai_federation`, `ai_semantic_cache`
    ///   hits) consume it and short-circuit — their transactions must still
    ///   be audited via the response/log hooks;
    /// - the proxy's response stream-vs-buffer decision runs (it reads
    ///   `ai_transcript_audit.candidate` via `should_buffer_response_body`);
    /// - `forces_reqwest_dispatch` is evaluated ahead of backend dispatch (it
    ///   reads the stream marker written during staging).
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
        self.stage_candidate(ctx, body.as_bytes());
        ctx.metadata.insert("request_body".to_string(), body);
        PluginResult::Continue
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
        if let Some("true") = ctx.metadata.get(MD_CANDIDATE).map(String::as_str) {
            self.refresh_staged_request(ctx, body);
            return PluginResult::Continue;
        }
        // Fallback for paths where the body was not available before
        // `before_proxy` (e.g. non-UTF-8 metadata skip above).
        let is_json = headers
            .get("content-type")
            .is_some_and(|content_type| is_json_content_type(content_type));
        if !is_json {
            ctx.metadata
                .insert(MD_CANDIDATE.to_string(), "false".to_string());
            return PluginResult::Continue;
        }
        self.stage_candidate(ctx, body);
        PluginResult::Continue
    }

    // ---- reject-path request refresh ----

    fn applies_after_proxy_on_reject(&self) -> bool {
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
        _response_status: u16,
        _response_headers: &mut HashMap<String, String>,
    ) -> PluginResult {
        if !self.active
            || flag(&ctx.metadata, MD_FINAL_REQ_SEEN)
            || !flag(&ctx.metadata, MD_CANDIDATE)
        {
            return PluginResult::Continue;
        }
        if let Some(body) = ctx.metadata.remove("request_body") {
            self.refresh_staged_request(ctx, body.as_bytes());
            ctx.metadata.insert("request_body".to_string(), body);
        }
        PluginResult::Continue
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
        response_status: u16,
        response_headers: &HashMap<String, String>,
        body: &[u8],
    ) -> PluginResult {
        // `capture.response` gates buffered *JSON* responses. A buffered SSE body
        // can still reach this hook when streaming capture is enabled but the
        // proxy (or another plugin) buffered the event stream instead of
        // streaming it — the streaming inspector never ran, so this is the only
        // path left to attach the response transcript. Honor the streaming
        // policy (`response_body_capture_allowed` already permits SSE) even when
        // buffered JSON capture is off.
        let buffered_sse_capture = self.capture.streaming != StreamingCapture::Off
            && response_headers
                .get("content-type")
                .is_some_and(|content_type| is_event_stream(content_type));
        if !self.capture.response && !buffered_sse_capture {
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

        let captures_response_body = response_body_capture_allowed(self.capture, response_headers);
        let response_hash = captures_response_body.then(|| self.redactor.keyed_hash_hex(body));

        // Peek (do not consume) the staging entry to make the emit decision.
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

        if let Some(response_hash) = response_hash.as_ref() {
            ctx.metadata
                .insert(MD_RESPONSE_HASH.to_string(), response_hash.clone());
        }
        // The transaction-log `sampled` flag carries the sampling ROLL (matching
        // the exported record's `sampled` field), not the emit decision —
        // `sink_status` already conveys whether a record was emitted.
        ctx.metadata
            .insert(MD_SAMPLED.to_string(), bool_str(sample_hit));

        if !emit {
            // Leave the staging entry in place. A later same-phase validator
            // (`body_validator` 2950, `openapi_validator` 2960) can still turn
            // this response into a 4xx/5xx after us; the `log` fallback then
            // re-evaluates `always_capture_on_error` against the final
            // client-visible status and is the only path that can emit that
            // plugin-generated error. Discarding staging here would drop it.
            // The stamped status is deliberately non-terminal: `log()` runs
            // after the summary metadata was captured and cannot rewrite it,
            // so a terminal "skipped" would lie whenever the fallback later
            // emits. `deferred` = no record was emitted at response time, but
            // one may still be emitted via the log fallback — correlate by
            // `record_id` against the collector.
            ctx.metadata
                .insert(MD_SINK_STATUS.to_string(), "deferred".to_string());
            return PluginResult::Continue;
        }
        // A response hook is emitting now, so consume the staging entry to keep
        // the `log` fallback from emitting a duplicate. Accepted limitation: a
        // later same-phase validator (2950/2960) that replaces the response
        // AFTER this emit leaves the exported record with the backend
        // status/body; the transaction log carries the client-visible status
        // plus `record_id` for correlation. No hook exists that has the final
        // status, the body, and fail-closed rejection at once — proxy-core
        // follow-up: issue #2056.
        let staging = self.staging.remove(&record_id).map(|(_, value)| value);
        let (response_excerpt, response_truncated) = if captures_response_body {
            self.shape_body(body, self.limits.max_response_bytes)
        } else {
            (None, false)
        };
        // Fail-closed stance while the sink is unhealthy: the client request
        // is rejected, but the record is still built and enqueued below. The
        // background flush of those queued records is the recovery probe — a
        // successful batch send flips `sink_healthy` back to true. Without
        // this, one transient sink outage would reject audited traffic
        // forever (nothing would ever enqueue, so nothing could ever flush).
        let sink_unhealthy_reject = self.on_sink_error == SinkErrorPolicy::Reject
            && !self.sink_healthy.load(Ordering::Relaxed);

        // When we are about to fail closed, the client-visible outcome is the 503
        // from `reject_audit_unavailable()`, not the backend status — stamp that
        // on the record so the collector does not read a fail-closed outage as a
        // successful 2xx transaction.
        let record_status = if sink_unhealthy_reject {
            503
        } else {
            response_status
        };
        let envelope = self.envelope_from_ctx(ctx, record_status);
        let record = self.build_record(
            &record_id,
            envelope,
            &ctx.metadata,
            staging.as_ref(),
            response_excerpt,
            response_truncated,
            response_hash,
            sample_hit,
            reason,
            Some(response_headers),
        );
        let status = match self.enqueue(record) {
            SinkOutcome::Queued => "queued",
            SinkOutcome::Dropped => "dropped",
            SinkOutcome::Rejected => "rejected",
        };
        if sink_unhealthy_reject || status == "rejected" {
            ctx.metadata
                .insert(MD_SINK_STATUS.to_string(), "rejected".to_string());
            return reject_audit_unavailable();
        }
        ctx.metadata
            .insert(MD_SINK_STATUS.to_string(), status.to_string());
        PluginResult::Continue
    }

    // ---- streaming (SSE) response capture ----

    fn requires_response_stream_hooks(&self) -> bool {
        self.capture.streaming != StreamingCapture::Off
    }

    fn forces_reqwest_dispatch(&self, ctx: &RequestContext) -> bool {
        self.capture.streaming != StreamingCapture::Off
            && flag(&ctx.metadata, &self.stream_marker_key())
            && self.stream_tee_wanted(&ctx.metadata)
    }

    fn response_stream_inspector(
        &self,
        ctx: &RequestContext,
        response_status: u16,
        content_type: Option<&str>,
    ) -> Option<Box<dyn ResponseStreamInspector>> {
        if self.capture.streaming == StreamingCapture::Off
            || !flag(&ctx.metadata, &self.stream_marker_key())
        {
            return None;
        }
        if !content_type.is_some_and(is_event_stream) {
            return None;
        }
        // In `sampled` mode the marker alone is not enough: only tee streams
        // that won the sampling roll or that a request-side guardrail flagged
        // (see `stream_tee_wanted`).
        if !self.stream_tee_wanted(&ctx.metadata) {
            return None;
        }
        let record_id = ctx.metadata.get(MD_RECORD_ID)?.clone();
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
            hasher: self.redactor.keyed_hasher(),
            redactor: Arc::clone(&self.redactor),
            mode: self.mode,
            max_bytes: self.limits.max_stream_capture_bytes,
            accumulated: Vec::new(),
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
        let downstream_terminated = slot.downstream_terminated.load(Ordering::Relaxed);
        let captured = slot.captured.lock().ok().and_then(|mut guard| guard.take());
        let sample_hit = self
            .staging
            .get(&record_id)
            .map(|staging| staging.sample_hit)
            .unwrap_or_else(|| flag(&ctx.metadata, MD_SAMPLE_HIT));
        let errored = response_status >= 400 || !outcome.body_completed;
        let guardrail = guardrail_fired(&ctx.metadata) || downstream_terminated;
        let (excerpt, truncated, hash) = if downstream_terminated {
            (None, true, None)
        } else {
            match captured {
                Some(captured) => (
                    captured.response_excerpt,
                    captured.response_truncated,
                    Some(captured.response_hash),
                ),
                None => (None, true, None), // abnormal end: on_end never ran
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

        // A response already being streamed cannot be rejected, so the
        // fail-closed sink stance only applies to buffered responses.
        let staging = self.staging.remove(&record_id).map(|(_, value)| value);
        let envelope = self.envelope_from_ctx(ctx, response_status);
        let record = self.build_record(
            &record_id,
            envelope,
            &ctx.metadata,
            staging.as_ref(),
            excerpt,
            truncated,
            hash,
            sample_hit,
            reason,
            None,
        );
        let status = match self.enqueue(record) {
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
        if !flag(&summary.metadata, MD_CANDIDATE) {
            return;
        }
        let Some(record_id) = summary.metadata.get(MD_RECORD_ID).cloned() else {
            return;
        };
        // Emit here only if no response hook already did (staging still present).
        let Some((_, staging)) = self.staging.remove(&record_id) else {
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
            sample_hit,
            reason,
            None,
        );
        let _ = self.enqueue(record);
    }
}

/// Tees streaming (SSE) response bytes into a bounded accumulator while
/// forwarding every chunk unchanged, and hashes the full stream incrementally
/// with the redactor's keyed HMAC (same key as the buffered body hashes).
struct AuditStreamInspector {
    record_id: String,
    slot: Arc<StreamSlot>,
    pending_streams: Arc<DashMap<String, Arc<StreamSlot>>>,
    redactor: Arc<PiiRedactor>,
    mode: AuditMode,
    max_bytes: usize,
    accumulated: Vec<u8>,
    hasher: KeyedBodyHasher,
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
}

#[async_trait]
impl ResponseStreamInspector for AuditStreamInspector {
    async fn on_chunk(&mut self, chunk: &[u8]) -> ResponseStreamAction {
        self.ensure_registered();
        self.hasher.update(chunk);
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
        let response_hash =
            std::mem::replace(&mut self.hasher, self.redactor.keyed_hasher()).finalize_hex();
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

async fn send_batch(cfg: &HttpFlushConfig, batch: Vec<AuditRecord>) -> Result<(), String> {
    let entry_count = batch.len();
    let mut request = cfg.http_client.get().post(&cfg.endpoint_url).json(&batch);
    for (name, template) in &cfg.custom_headers {
        let value = expand_env_vars(template);
        match HeaderValue::from_str(&value) {
            Ok(header_value) => request = request.header(name.clone(), header_value),
            Err(_) => warn!(
                header = %name,
                "ai_transcript_audit: dropping custom header with an invalid value after env expansion"
            ),
        }
    }
    let response = cfg
        .http_client
        .execute(request, "ai_transcript_audit")
        .await;
    // Sink health is derived from the raw collector response, NOT from the
    // shared `handle_http_batch_response` result: that helper treats a
    // non-retryable non-2xx (401/403/413, e.g. an expired ${AUDIT_TOKEN}) as a
    // discarded-but-Ok batch so the other logging sinks do not retry it, but
    // for this plugin every record in that batch was silently lost — under
    // `on_sink_error: reject` the sink must go unhealthy so audited traffic
    // stops flowing unaudited. Recovery keeps the existing probe model: the
    // next successful batch send flips `sink_healthy` back to true.
    match response {
        Ok(resp) => {
            cfg.sink_healthy
                .store(resp.status().is_success(), Ordering::Relaxed);
            handle_http_batch_response("ai_transcript_audit", entry_count, Ok(resp))
        }
        Err(err) => {
            cfg.sink_healthy.store(false, Ordering::Relaxed);
            handle_http_batch_response("ai_transcript_audit", entry_count, Err(err))
        }
    }
}

// ---- free helpers ----

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
/// Ordering matters for `redacted_body`: redaction runs over the FULL buffered
/// payload first and the redacted text is capped afterwards, so a sensitive
/// value straddling the `max_bytes` boundary can never leak as an unmatched
/// raw prefix. (`full_body` deliberately captures raw excerpts, so it caps
/// first and skips the extra scan.)
fn shape_bytes(
    mode: AuditMode,
    redactor: &PiiRedactor,
    raw: &[u8],
    max_bytes: usize,
) -> (Option<String>, bool) {
    if !mode.captures_body() {
        return (None, false);
    }
    let mut truncated = raw.len() > max_bytes;
    let shaped = if mode.redacts_body() {
        redact_body_decoded_json_strings(redactor, raw)
    } else {
        String::from_utf8_lossy(&raw[..raw.len().min(max_bytes)]).into_owned()
    };
    let shaped = if shaped.len() > max_bytes {
        truncated = true;
        truncate_on_char_boundary(shaped, max_bytes)
    } else {
        shaped
    };
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

/// Reassemble captured OpenAI `chat.completion.chunk` SSE frames into
/// per-choice completion text (`choices[].delta.content`, keyed by choice
/// `index`, concatenated in frame order), so redaction runs over the full
/// completion instead of per-frame fragments a split PII value would evade.
///
/// Returns the annotated excerpt object
/// `{"sse_reassembled": true, "object": "chat.completion.chunk",
///   "completion_text": {"<choice index>": "<text>"}}`, or `None` when the
/// frames are not uniformly parseable OpenAI chunks (or carry no
/// `delta.content` at all) — callers then fall back to per-frame redaction of
/// the raw frames.
fn reassemble_openai_sse_deltas(raw: &[u8]) -> Option<Value> {
    let text = std::str::from_utf8(raw).ok()?;
    let mut per_choice: BTreeMap<u64, String> = BTreeMap::new();
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
            if let Some(content) = choice
                .get("delta")
                .and_then(|delta| delta.get("content"))
                .and_then(Value::as_str)
            {
                per_choice.entry(index).or_default().push_str(content);
            }
        }
    }
    if per_choice.is_empty() {
        // Valid chunks but no text deltas (e.g. a tool-call-only stream):
        // reassembly would export an empty excerpt and drop the tool-call
        // frames, so keep the per-frame capture.
        return None;
    }
    let mut completion_text = serde_json::Map::with_capacity(per_choice.len());
    for (index, content) in per_choice {
        completion_text.insert(index.to_string(), Value::String(content));
    }
    let mut annotated = serde_json::Map::with_capacity(3);
    annotated.insert("sse_reassembled".to_string(), Value::Bool(true));
    annotated.insert(
        "object".to_string(),
        Value::String("chat.completion.chunk".to_string()),
    );
    annotated.insert(
        "completion_text".to_string(),
        Value::Object(completion_text),
    );
    Some(Value::Object(annotated))
}

fn redact_json_value_strings(redactor: &PiiRedactor, value: &mut Value) {
    match value {
        Value::String(text) => {
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
                redact_json_value_strings(redactor, value);
            }
        }
        Value::Object(map) => {
            let entries = std::mem::take(map);
            for (key, mut value) in entries {
                redact_json_value_strings(redactor, &mut value);
                map.insert(redactor.redact(&key), value);
            }
        }
        Value::Null | Value::Bool(_) => {}
    }
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
    ];
    PREFIXES.iter().any(|prefix| key.starts_with(prefix))
}

fn extract_model(json: &Value) -> Option<String> {
    json.get("model")
        .and_then(|value| value.as_str())
        .map(str::to_string)
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

/// Expand `${NAME}` occurrences from the process environment (unset/unknown ->
/// empty). Malformed `${...}` is left literal. Applied lazily at send time so
/// the resolved secret is never stored in config.
fn expand_env_vars(template: &str) -> String {
    if !template.contains("${") {
        return template.to_string();
    }
    let mut out = String::with_capacity(template.len());
    let mut rest = template;
    while let Some(start) = rest.find("${") {
        out.push_str(&rest[..start]);
        let after = &rest[start + 2..];
        if let Some(end) = after.find('}') {
            let name = &after[..end];
            if is_valid_env_name(name) {
                if let Ok(value) = std::env::var(name) {
                    out.push_str(&value);
                }
                rest = &after[end + 1..];
                continue;
            }
        }
        out.push_str("${");
        rest = after;
    }
    out.push_str(rest);
    out
}

fn is_valid_env_name(name: &str) -> bool {
    !name.is_empty()
        && name.bytes().enumerate().all(|(index, byte)| {
            byte == b'_' || byte.is_ascii_alphabetic() || (index > 0 && byte.is_ascii_digit())
        })
}

// ---- config parsing helpers ----

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
        out.retain(|(existing, _)| *existing != name);
        out.push((name, value.to_string()));
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
