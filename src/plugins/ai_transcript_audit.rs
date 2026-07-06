//! AI transcript audit — controlled AI payload capture for compliance.
//!
//! Captures AI request/response payloads (after redaction), canonical hashes,
//! model/provider, token metadata, guardrail decisions, tool names, and cache
//! metadata, then exports them asynchronously to an HTTP collector in batches
//! via the shared [`BatchingLogger`]/[`PluginHttpClient`] framework. The proxy
//! hot path only enqueues records non-blockingly; a background task drains the
//! queue. Unless the operator opts into a fail-closed policy (`on_buffer_full`
//! /`on_sink_error` = `reject`) the plugin never blocks or rejects traffic.
//!
//! Runs at priority `AI_TRANSCRIPT_AUDIT` (2979): after `ai_request_guard`
//! (2975) so request-guard defaults/transforms are visible, and before
//! `ai_semantic_cache` (2980) / `ai_federation` (2985) so cache hits and
//! federated requests are still observable.
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

use super::utils::ai_pii::PiiRedactor;
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
        let placeholder =
            cfg_str(redaction_obj, "placeholder", "redaction")?.unwrap_or("[REDACTED:{type}]");
        let hash_redacted = cfg_bool(redaction_obj, "hash_redacted_values", true, "redaction")?;
        let redactor = PiiRedactor::from_config(
            &builtins,
            &custom,
            placeholder,
            hash_redacted,
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
            staging_ttl: Duration::from_secs(60),
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
                "ai_provider" | "ai_federation_provider" => {
                    if harvest.provider.is_none() {
                        harvest.provider = Some(value.clone());
                    }
                }
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
        let tool_names = if harvests {
            staging.map(|s| s.tool_names.clone()).unwrap_or_default()
        } else {
            Vec::new()
        };

        let model = if harvests {
            req_model.or(harvest.model)
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

    fn should_buffer_request_body(&self, ctx: &RequestContext) -> bool {
        self.active
            && ctx.method == "POST"
            && ctx
                .headers
                .get("content-type")
                .is_some_and(|content_type| is_json_content_type(content_type))
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
        let is_json = headers
            .get("content-type")
            .is_some_and(|content_type| is_json_content_type(content_type));
        if !is_json || body.is_empty() {
            ctx.metadata
                .insert(MD_CANDIDATE.to_string(), "false".to_string());
            return PluginResult::Continue;
        }
        let parsed: Option<Value> = serde_json::from_slice(body).ok();
        let is_ai = parsed.as_ref().is_some_and(json_looks_like_ai_request);
        if !is_ai {
            ctx.metadata
                .insert(MD_CANDIDATE.to_string(), "false".to_string());
            return PluginResult::Continue;
        }

        let record_id = uuid::Uuid::new_v4().to_string();
        let sample_hit = sample_from_record_id(&record_id) < self.sampling.rate;
        let request_hash = sha256_hex(body);

        ctx.metadata
            .insert(MD_RECORD_ID.to_string(), record_id.clone());
        ctx.metadata
            .insert(MD_CANDIDATE.to_string(), "true".to_string());
        ctx.metadata
            .insert(MD_SAMPLE_HIT.to_string(), bool_str(sample_hit));
        ctx.metadata
            .insert(MD_REQUEST_HASH.to_string(), request_hash.clone());

        // Force the response onto the stream-inspection path when streaming
        // capture might apply to this request.
        let stream_wanted = match self.capture.streaming {
            StreamingCapture::Off => false,
            StreamingCapture::On => true,
            StreamingCapture::Sampled => {
                sample_hit || self.sampling.always_on_guardrail || self.sampling.always_on_error
            }
        };
        if stream_wanted {
            ctx.metadata
                .insert(MD_STREAM_MARKER.to_string(), "true".to_string());
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
                request_excerpt,
                request_truncated,
                request_hash: Some(request_hash),
                request_model,
                tool_names,
            },
        );

        PluginResult::Continue
    }

    // ---- buffered response capture ----

    fn requires_response_body_buffering(&self) -> bool {
        self.capture.response
    }

    fn should_buffer_response_body(&self, ctx: &RequestContext) -> bool {
        self.capture.response && flag(&ctx.metadata, MD_CANDIDATE)
    }

    fn should_buffer_response_body_for_content_type(
        &self,
        ctx: &RequestContext,
        content_type: Option<&str>,
        _response_status: u16,
        _response_headers: &HashMap<String, String>,
    ) -> bool {
        if !self.capture.response || !flag(&ctx.metadata, MD_CANDIDATE) {
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
        if !self.capture.response {
            return PluginResult::Continue;
        }
        let Some(record_id) = ctx.metadata.get(MD_RECORD_ID).cloned() else {
            return PluginResult::Continue;
        };
        if !flag(&ctx.metadata, MD_CANDIDATE) {
            self.staging.remove(&record_id);
            return PluginResult::Continue;
        }

        let response_hash = sha256_hex(body);
        let (response_excerpt, response_truncated) =
            self.shape_body(body, self.limits.max_response_bytes);

        let sample_hit = flag(&ctx.metadata, MD_SAMPLE_HIT);
        let (emit, reason) = self.emit_decision(
            sample_hit,
            guardrail_fired(&ctx.metadata),
            response_status >= 400,
        );

        ctx.metadata
            .insert(MD_RESPONSE_HASH.to_string(), response_hash.clone());
        ctx.metadata.insert(MD_SAMPLED.to_string(), bool_str(emit));

        let staging = self.staging.remove(&record_id).map(|(_, value)| value);
        if !emit {
            ctx.metadata
                .insert(MD_SINK_STATUS.to_string(), "skipped".to_string());
            return PluginResult::Continue;
        }
        if self.on_sink_error == SinkErrorPolicy::Reject
            && !self.sink_healthy.load(Ordering::Relaxed)
        {
            ctx.metadata
                .insert(MD_SINK_STATUS.to_string(), "rejected".to_string());
            return reject_audit_unavailable();
        }

        let envelope = self.envelope_from_ctx(ctx, response_status);
        let record = self.build_record(
            &record_id,
            envelope,
            &ctx.metadata,
            staging.as_ref(),
            response_excerpt,
            response_truncated,
            Some(response_hash),
            emit,
            reason,
            Some(response_headers),
        );
        match self.enqueue(record) {
            SinkOutcome::Queued => {
                ctx.metadata
                    .insert(MD_SINK_STATUS.to_string(), "queued".to_string());
                PluginResult::Continue
            }
            SinkOutcome::Dropped => {
                ctx.metadata
                    .insert(MD_SINK_STATUS.to_string(), "dropped".to_string());
                PluginResult::Continue
            }
            SinkOutcome::Rejected => {
                ctx.metadata
                    .insert(MD_SINK_STATUS.to_string(), "rejected".to_string());
                reject_audit_unavailable()
            }
        }
    }

    // ---- streaming (SSE) response capture ----

    fn requires_response_stream_hooks(&self) -> bool {
        self.capture.streaming != StreamingCapture::Off
    }

    fn forces_reqwest_dispatch(&self, ctx: &RequestContext) -> bool {
        self.capture.streaming != StreamingCapture::Off && flag(&ctx.metadata, MD_STREAM_MARKER)
    }

    fn response_stream_inspector(
        &self,
        ctx: &RequestContext,
        response_status: u16,
        content_type: Option<&str>,
    ) -> Option<Box<dyn ResponseStreamInspector>> {
        if self.capture.streaming == StreamingCapture::Off
            || !(200..300).contains(&response_status)
            || !flag(&ctx.metadata, MD_STREAM_MARKER)
        {
            return None;
        }
        if !content_type.is_some_and(is_event_stream) {
            return None;
        }
        let record_id = ctx.metadata.get(MD_RECORD_ID)?.clone();

        let slot = Arc::new(StreamSlot {
            captured: Mutex::new(None),
        });
        self.pending_streams
            .insert(record_id.clone(), Arc::clone(&slot));

        Some(Box::new(AuditStreamInspector {
            slot,
            redactor: Arc::clone(&self.redactor),
            mode: self.mode,
            max_bytes: self.limits.max_stream_capture_bytes,
            accumulated: Vec::new(),
            hasher: Sha256::new(),
            truncated: false,
        }))
    }

    async fn on_response_stream_terminated(
        &self,
        ctx: &RequestContext,
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
        let captured = slot.captured.lock().ok().and_then(|mut guard| guard.take());
        let staging = self.staging.remove(&record_id).map(|(_, value)| value);

        let sample_hit = flag(&ctx.metadata, MD_SAMPLE_HIT);
        let errored = response_status >= 400 || !outcome.body_completed;
        let (emit, reason) =
            self.emit_decision(sample_hit, guardrail_fired(&ctx.metadata), errored);
        if !emit {
            return;
        }

        // A response already being streamed cannot be rejected, so the
        // fail-closed sink stance only applies to buffered responses.
        let (excerpt, truncated, hash) = match captured {
            Some(captured) => (
                captured.response_excerpt,
                captured.response_truncated,
                Some(captured.response_hash),
            ),
            None => (None, true, None), // abnormal end: on_end never ran
        };
        let envelope = self.envelope_from_ctx(ctx, response_status);
        let record = self.build_record(
            &record_id,
            envelope,
            &ctx.metadata,
            staging.as_ref(),
            excerpt,
            truncated,
            hash,
            emit,
            reason,
            None,
        );
        let _ = self.enqueue(record);
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

        let sample_hit = flag(&summary.metadata, MD_SAMPLE_HIT);
        let errored = summary.response_status_code >= 400;
        let (emit, reason) =
            self.emit_decision(sample_hit, guardrail_fired(&summary.metadata), errored);
        if !emit {
            return;
        }
        let envelope = self.envelope_from_summary(summary);
        let record = self.build_record(
            &record_id,
            envelope,
            &summary.metadata,
            Some(&staging),
            None,
            false,
            None,
            emit,
            reason,
            None,
        );
        let _ = self.enqueue(record);
    }
}

/// Tees streaming (SSE) response bytes into a bounded accumulator while
/// forwarding every chunk unchanged, and hashes the full stream.
struct AuditStreamInspector {
    slot: Arc<StreamSlot>,
    redactor: Arc<PiiRedactor>,
    mode: AuditMode,
    max_bytes: usize,
    accumulated: Vec<u8>,
    hasher: Sha256,
    truncated: bool,
}

#[async_trait]
impl ResponseStreamInspector for AuditStreamInspector {
    async fn on_chunk(&mut self, chunk: &[u8]) -> ResponseStreamAction {
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
        let digest = std::mem::replace(&mut self.hasher, Sha256::new()).finalize();
        let response_hash = hex::encode(digest);
        let (response_excerpt, _) =
            shape_bytes(self.mode, &self.redactor, &self.accumulated, self.max_bytes);
        if let Ok(mut guard) = self.slot.captured.lock() {
            *guard = Some(StreamCaptured {
                response_excerpt,
                response_truncated: self.truncated,
                response_hash,
            });
        }
        ResponseStreamAction::Forward(Bytes::new())
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
    let result = handle_http_batch_response(
        "ai_transcript_audit",
        entry_count,
        cfg.http_client
            .execute(request, "ai_transcript_audit")
            .await,
    );
    if result.is_ok() {
        cfg.sink_healthy.store(true, Ordering::Relaxed);
    }
    result
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

/// Cap `raw` to `max_bytes`, then (for `redacted_body`) redact PII. Returns the
/// shaped excerpt (or `None` for non-body modes) and whether it was truncated.
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
    let capped = &raw[..raw.len().min(max_bytes)];
    let text = String::from_utf8_lossy(capped);
    let shaped = if mode.redacts_body() {
        redactor.redact(&text)
    } else {
        text.into_owned()
    };
    (Some(shaped), truncated)
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
        "ai_response_guard_redacted",
        "ai_shield_redacted",
    ];
    if FIRED_TRUE_KEYS
        .iter()
        .any(|key| metadata.get(*key).is_some_and(|value| value == "true"))
    {
        return true;
    }
    for key in [
        "ai_shield_warnings",
        "ai_response_guard_warning",
        "ai_request_guard.uninspectable_body",
    ] {
        if metadata.get(key).is_some_and(|value| !value.is_empty()) {
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
    false
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

fn sha256_hex(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
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
