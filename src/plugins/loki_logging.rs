//! Loki access logging plugin — batched async log shipping to Grafana Loki.
//!
//! Serializes `TransactionSummary` and `StreamTransactionSummary` entries and
//! sends them to Loki's push API (`/loki/api/v1/push`) in batches. Uses
//! `BatchingLogger<LokiEntry>` to decouple the proxy hot path from network I/O.
//!
//! Loki-specific features:
//! - **Labels**: Low-cardinality indexed labels (service, environment, proxy
//!   ID, status class, per-instance emitter) configurable via `labels` map in
//!   plugin config.
//! - **Structured log lines**: Full transaction details serialized as JSON
//!   strings inside Loki `values` entries.
//! - **Batching by label set**: Entries are grouped by their label fingerprint
//!   so each Loki stream gets multiple values per push.
//! - **Gzip compression**: Optional request body compression via
//!   `Content-Encoding: gzip` (enabled by default).
//! - **Custom headers**: Supports `X-Scope-OrgID` for multi-tenant Loki and
//!   arbitrary extra headers.
//! - **Authentication**: `Authorization` header for Bearer/Basic auth.

use async_trait::async_trait;
use bytes::Bytes;
use http::header::{HeaderName, HeaderValue};
use ring::rand::{SecureRandom, SystemRandom};
use serde_json::Value;
use std::collections::BTreeMap;
use std::collections::HashMap;
use std::io::Write;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, LazyLock};
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tracing::warn;

use crate::config::types::MAX_ID_LENGTH;

use super::utils::byte_budget::{
    BoundedPayloadWriter, JSON_REEMBEDDED_WORST_CASE_EXPANSION, JSON_STRING_WORST_CASE_EXPANSION,
    PayloadMaterializationError, ProcessByteReservation, ReservedPayload, RetainedByteCeiling,
    materialize_reserved_payload, process_ceiling, record_batch_materialization_fallback,
    record_batch_materialization_loss,
};
use super::utils::log_schema::{SchemaCapabilities, SchemaView, SummarySchema, resolve_schema};
use super::utils::{
    BatchConfig, BatchConfigDefaults, DeferredBatchingLogger, HttpBatchDrainOutcome,
    MAX_BATCH_RETRIES, MAX_BATCH_RETRY_DELAY_MS, PluginHttpClient, RetryPolicy, build_batch_config,
    drain_http_batch_response_body, parse_custom_headers, parse_http_endpoint,
    validate_batch_config,
};
use super::{Plugin, StreamTransactionSummary, TransactionSummary};

/// Fixed sink label for shared retained-byte diagnostics and metrics.
const LOKI_PLUGIN_NAME: &str = "loki_logging";

pub const LOKI_LOGGING_CONFIG_KEYS: &[&str] = &[
    "authorization_header",
    "batch_size",
    "buffer_capacity",
    "buffer_max_bytes",
    "custom_headers",
    "endpoint_url",
    "flush_interval_ms",
    "gzip",
    "include_proxy_id_label",
    "include_status_class_label",
    "labels",
    "max_entry_bytes",
    "max_retries",
    "retry_delay_ms",
    "schema",
    "schema_ref",
];

pub const LOKI_DEFAULT_MAX_ENTRY_BYTES: usize = 64 * 1024;
pub const LOKI_MAX_MAX_ENTRY_BYTES: usize = 1024 * 1024;
pub const LOKI_DEFAULT_BUFFER_MAX_BYTES: usize = 16 * 1024 * 1024;
pub const LOKI_MAX_BUFFER_MAX_BYTES: usize = 256 * 1024 * 1024;
// Retain sink-local exports for OpenAPI/runtime parity tests. Production uses
// the authoritative shared constants directly.
#[allow(dead_code)]
pub const LOKI_MAX_RETRIES: u64 = MAX_BATCH_RETRIES;
#[allow(dead_code)]
pub const LOKI_MAX_RETRY_DELAY_MS: u64 = MAX_BATCH_RETRY_DELAY_MS;
pub const LOKI_MAX_CUSTOM_HEADER_NAME_BYTES: usize = u16::MAX as usize;

const LOKI_MIN_RESOURCE_BYTES: usize = 1024;
const LOKI_MAX_LABEL_NAME_CHARS: usize = 1024;
const LOKI_MAX_LABEL_VALUE_CHARS: usize = 2048;
const LOKI_DROP_WARN_EVERY: u64 = 100;
const LOKI_EMITTER_LABEL: &str = "ferrum_emitter";
// Random prefix (32 hex bytes), separator, and fixed-width u64 counter (16 hex bytes).
// A fixed width keeps construction-time and runtime label accounting identical.
const LOKI_EMITTER_VALUE_BYTES: usize = 16 * 2 + 1 + std::mem::size_of::<u64>() * 2;
const LOKI_MIN_PROXY_ID: &str = "0";
const LOKI_WORST_CASE_STREAM_PROTOCOL: &str = "dtls";
const LOKI_MIN_TIMESTAMP: &str = "1970-01-01T00:00:00+00:00";

static LOKI_EMITTER_PREFIX: LazyLock<Result<[u8; 16], ()>> = LazyLock::new(|| {
    let mut bytes = [0_u8; 16];
    SystemRandom::new()
        .fill(&mut bytes)
        .map(|()| bytes)
        .map_err(|_| ())
});
static NEXT_LOKI_EMITTER_ID: AtomicU64 = AtomicU64::new(0);

/// A log entry with pre-computed labels and a JSON log line.
#[derive(Clone)]
struct LokiEntry {
    /// Sorted label key-value pairs (deterministic ordering for grouping).
    labels: Arc<BTreeMap<String, String>>,
    /// JSON-serialized log line.
    line: Arc<str>,
    /// Keeps the retained-content byte reservation alive through retries.
    _lease: Arc<LokiByteLease>,
}

#[derive(Clone)]
struct LokiFlushConfig {
    endpoint_url: String,
    endpoint_url_for_logs: String,
    authorization_header: Option<HeaderValue>,
    custom_headers: Vec<(HeaderName, HeaderValue)>,
    http_client: PluginHttpClient,
    gzip: bool,
    retry: RetryPolicy,
    last_timestamp_ns: Arc<AtomicU64>,
    /// Ceiling the batch's JSON and gzip representations are charged to. Always
    /// the process ceiling in production; a test-owned ceiling under test.
    ceiling: &'static RetainedByteCeiling,
}

type LokiProvisionalAdmission = (Arc<str>, BTreeMap<String, String>, Arc<LokiByteLease>);

struct LokiByteLease {
    used_bytes: Arc<AtomicUsize>,
    /// Current retained charge. Atomic so a provisional reservation can shrink
    /// race-safely against `Drop` without temporarily releasing the whole lease.
    bytes: AtomicUsize,
    /// Matching reservation against the process-wide observability ceiling, so
    /// multiple Loki instances cannot multiply past the process total.
    process: ProcessByteReservation,
}

impl LokiByteLease {
    /// Reduce this lease from its provisional charge to the exact retained
    /// charge. Never releases-and-reacquires; only subtracts the unused delta.
    /// No-op when `new_bytes` is not strictly smaller than the current charge.
    fn shrink_to(&self, new_bytes: usize) {
        let mut current = self.bytes.load(Ordering::Acquire);
        while new_bytes < current {
            match self.bytes.compare_exchange_weak(
                current,
                new_bytes,
                Ordering::AcqRel,
                Ordering::Acquire,
            ) {
                Ok(_) => {
                    self.used_bytes
                        .fetch_sub(current - new_bytes, Ordering::AcqRel);
                    self.process.shrink_to(new_bytes);
                    return;
                }
                Err(observed) => current = observed,
            }
        }
    }

    fn charged_bytes(&self) -> usize {
        self.bytes.load(Ordering::Acquire)
    }
}

impl Drop for LokiByteLease {
    fn drop(&mut self) {
        let bytes = self.bytes.swap(0, Ordering::AcqRel);
        if bytes != 0 {
            self.used_bytes.fetch_sub(bytes, Ordering::AcqRel);
        }
    }
}

struct LokiByteBudget {
    used_bytes: Arc<AtomicUsize>,
    max_bytes: usize,
    dropped_count: AtomicU64,
    ceiling: &'static RetainedByteCeiling,
}

impl LokiByteBudget {
    fn with_ceiling(max_bytes: usize, ceiling: &'static RetainedByteCeiling) -> Self {
        Self {
            used_bytes: Arc::new(AtomicUsize::new(0)),
            max_bytes,
            dropped_count: AtomicU64::new(0),
            ceiling,
        }
    }

    fn used(&self) -> usize {
        self.used_bytes.load(Ordering::Acquire)
    }

    fn try_acquire(&self, bytes: usize) -> Option<Arc<LokiByteLease>> {
        // Process ceiling first: a failed aggregate reservation must never
        // leave per-instance bytes held.
        let Some(process) = self.ceiling.try_acquire(bytes) else {
            self.record_drop("process-wide retained-byte ceiling exhausted");
            return None;
        };
        let reserved = self
            .used_bytes
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |used| {
                used.checked_add(bytes)
                    .filter(|next| *next <= self.max_bytes)
            });
        if reserved.is_err() {
            drop(process);
            self.record_drop("retained-content byte budget exhausted");
            return None;
        }

        Some(Arc::new(LokiByteLease {
            used_bytes: Arc::clone(&self.used_bytes),
            bytes: AtomicUsize::new(bytes),
            process,
        }))
    }

    fn record_drop(&self, reason: &str) {
        let dropped = self.dropped_count.fetch_add(1, Ordering::Relaxed) + 1;
        if dropped == 1 || dropped.is_multiple_of(LOKI_DROP_WARN_EVERY) {
            warn!(
                plugin = "loki_logging",
                "Loki logging: dropping entry because {} ({} dropped total; logging every {} drops)",
                reason,
                dropped,
                LOKI_DROP_WARN_EVERY,
            );
        }
    }
}

struct BoundedJsonWriter {
    bytes: Vec<u8>,
    max_bytes: usize,
    limit_exceeded: bool,
}

#[derive(Default)]
struct CountingJsonWriter {
    bytes: usize,
}

impl Write for CountingJsonWriter {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.bytes = self
            .bytes
            .checked_add(buf.len())
            .ok_or_else(|| std::io::Error::other("serialized Loki entry size overflowed"))?;
        Ok(buf.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

impl BoundedJsonWriter {
    fn new(max_bytes: usize) -> Self {
        Self {
            bytes: Vec::with_capacity(max_bytes.min(4096)),
            max_bytes,
            limit_exceeded: false,
        }
    }
}

impl Write for BoundedJsonWriter {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        if buf.len() > self.max_bytes.saturating_sub(self.bytes.len()) {
            self.limit_exceeded = true;
            return Err(std::io::Error::other(
                "serialized Loki entry exceeded its byte limit",
            ));
        }
        self.bytes.extend_from_slice(buf);
        Ok(buf.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

/// Static labels applied to every log entry, from plugin config.
#[derive(Clone)]
struct LabelConfig {
    /// Static labels merged into every entry (e.g., service, env).
    static_labels: BTreeMap<String, String>,
    /// Whether to add `proxy_id` as a label (default true).
    include_proxy_id: bool,
    /// Whether to add status class (2xx/3xx/4xx/5xx) as a label (default true).
    include_status_class: bool,
}

impl LabelConfig {
    fn build_http_labels(&self, summary: &TransactionSummary) -> BTreeMap<String, String> {
        let mut labels = self.static_labels.clone();
        if self.include_proxy_id
            && let Some(ref proxy_id) = summary.proxy_id
        {
            labels.insert("proxy_id".to_string(), proxy_id.clone());
        }
        if self.include_status_class {
            labels.insert(
                "status_class".to_string(),
                status_class(summary.response_status_code),
            );
        }
        labels
    }

    fn build_stream_labels(&self, summary: &StreamTransactionSummary) -> BTreeMap<String, String> {
        let mut labels = self.static_labels.clone();
        if self.include_proxy_id {
            labels.insert("proxy_id".to_string(), summary.proxy_id.clone());
        }
        labels.insert("protocol".to_string(), summary.protocol.clone());
        labels
    }
}

pub struct LokiLogging {
    batch_config: BatchConfig,
    flush_config: LokiFlushConfig,
    logger: DeferredBatchingLogger<LokiEntry>,
    endpoint_hostname: String,
    label_config: LabelConfig,
    schema: Option<Arc<SummarySchema>>,
    byte_budget: Arc<LokiByteBudget>,
    max_entry_bytes: usize,
}

impl LokiLogging {
    pub fn new(config: &Value, http_client: PluginHttpClient) -> Result<Self, String> {
        Self::new_with_ceiling(config, http_client, process_ceiling())
    }

    /// Construct an instance whose queue *and* batch materialization charge
    /// `ceiling`. External tests pass their own leaked ceiling so end-to-end
    /// reservation-ownership assertions stay exact while other tests in the same
    /// binary reserve against the process-global counter.
    // The binary target only calls `new`; external tests reach this through
    // `_test_support`.
    #[allow(dead_code)]
    pub(crate) fn new_with_ceiling(
        config: &Value,
        http_client: PluginHttpClient,
        ceiling: &'static RetainedByteCeiling,
    ) -> Result<Self, String> {
        let Some(config_object) = config.as_object() else {
            return Err("loki_logging: config must be an object".to_string());
        };

        if config_object.contains_key("include_listen_path_label") {
            return Err(
                "loki_logging: 'include_listen_path_label' was removed; use 'include_proxy_id_label'"
                    .to_string(),
            );
        }
        validate_known_config_fields(config_object)?;

        let (endpoint_url, endpoint_hostname) =
            parse_http_endpoint(config, "loki_logging", http_client.backend_allow_ips())?;
        let parsed_endpoint = url::Url::parse(&endpoint_url)
            .map_err(|_| "loki_logging: invalid 'endpoint_url'".to_string())?;
        if !parsed_endpoint.username().is_empty() || parsed_endpoint.password().is_some() {
            return Err(
                "loki_logging: 'endpoint_url' must not contain user information; use authorization_header or custom_headers"
                    .to_string(),
            );
        }
        let endpoint_url_for_logs = redacted_endpoint_url(&parsed_endpoint);
        let gzip = optional_bool(config, "gzip")?.unwrap_or(true);

        // Parse static labels from config.
        let mut static_labels = BTreeMap::new();
        if let Some(labels) = config.get("labels") {
            let labels_obj = labels
                .as_object()
                .ok_or_else(|| "loki_logging: 'labels' must be an object".to_string())?;
            for (key, value) in labels_obj {
                validate_loki_label_name(key)?;
                let label = value
                    .as_str()
                    .ok_or_else(|| format!("loki_logging: 'labels.{key}' must be a string"))?;
                if label.chars().count() > LOKI_MAX_LABEL_VALUE_CHARS {
                    return Err(format!(
                        "loki_logging: 'labels.{key}' must be at most {LOKI_MAX_LABEL_VALUE_CHARS} characters"
                    ));
                }
                static_labels.insert(key.clone(), label.to_string());
            }
        }
        if !static_labels.contains_key("service") {
            static_labels.insert("service".to_string(), "ferrum-edge".to_string());
        }

        static_labels.insert(LOKI_EMITTER_LABEL.to_string(), next_loki_emitter_id()?);
        let include_proxy_id = optional_bool(config, "include_proxy_id_label")?.unwrap_or(true);
        let include_status_class =
            optional_bool(config, "include_status_class_label")?.unwrap_or(true);

        let label_config = LabelConfig {
            static_labels,
            include_proxy_id,
            include_status_class,
        };

        validate_custom_header_name_lengths(config)?;
        let custom_headers = parse_custom_headers(config, "loki_logging")?;

        let authorization_header = match optional_non_empty_string(config, "authorization_header")?
        {
            Some(value) => Some(HeaderValue::from_str(&value).map_err(|error| {
                format!("loki_logging: invalid authorization_header value: {error}")
            })?),
            None => None,
        };

        // Config remains `max_retries`; the shared retry policy counts the
        // initial attempt plus those retries.
        let batch_defaults = BatchConfigDefaults {
            batch_size_key: "batch_size",
            batch_size: 100,
            flush_interval_ms: 1000,
            min_flush_interval_ms: 100,
            buffer_capacity: 10000,
            max_retries: 3,
            retry_delay_ms: 1000,
            min_retry_delay_ms: 1,
        };
        validate_batch_config(config, "loki_logging", batch_defaults)?;
        let (max_entry_bytes, buffer_max_bytes, retry) =
            validate_loki_resource_config(config, batch_defaults)?;
        let schema = resolve_schema(config, "loki_logging", SchemaCapabilities::BASE)?;
        validate_minimum_entry_budget(&label_config, schema.as_deref(), max_entry_bytes)?;
        let mut batch_config = build_batch_config(config, "loki_logging", batch_defaults)?;
        batch_config.retry = retry;
        let flush_config = LokiFlushConfig {
            endpoint_url,
            endpoint_url_for_logs,
            authorization_header,
            custom_headers,
            http_client,
            gzip,
            retry: batch_config.retry,
            last_timestamp_ns: Arc::new(AtomicU64::new(0)),
            ceiling,
        };
        // Loki retries inside `send_batch` so we reuse the same serialized +
        // gzipped body bytes across attempts. The deferred worker therefore
        // uses a single-attempt shared retry policy.
        let batch_config = BatchConfig {
            retry: RetryPolicy::fixed(1, Duration::from_millis(0)),
            ..batch_config
        };

        Ok(Self {
            batch_config,
            flush_config,
            logger: DeferredBatchingLogger::new(),
            endpoint_hostname,
            label_config,
            schema,
            byte_budget: Arc::new(LokiByteBudget::with_ceiling(buffer_max_bytes, ceiling)),
            max_entry_bytes,
        })
    }

    fn queue_entry<T, F>(&self, value: &T, kind: &str, build_labels: F)
    where
        T: serde::Serialize,
        F: FnOnce() -> BTreeMap<String, String>,
    {
        // Slot first, then provisional aggregate bytes, then serialize/labels.
        let Some(permit) = self.logger.try_reserve() else {
            return;
        };
        let Some((line, labels, lease)) = admit_under_byte_budget(
            &self.byte_budget,
            self.max_entry_bytes,
            value,
            kind,
            build_labels,
        ) else {
            return;
        };
        permit.send(LokiEntry {
            labels: Arc::new(labels),
            line,
            _lease: lease,
        });
    }

    /// Build labels for an HTTP/gRPC/WebSocket transaction.
    fn build_http_labels(&self, summary: &TransactionSummary) -> BTreeMap<String, String> {
        self.label_config.build_http_labels(summary)
    }

    /// Build labels for a TCP/UDP stream transaction.
    fn build_stream_labels(&self, summary: &StreamTransactionSummary) -> BTreeMap<String, String> {
        self.label_config.build_stream_labels(summary)
    }
}

fn optional_bool(config: &Value, key: &str) -> Result<Option<bool>, String> {
    match config.get(key) {
        Some(value) => value
            .as_bool()
            .map(Some)
            .ok_or_else(|| format!("loki_logging: '{key}' must be a boolean")),
        None => Ok(None),
    }
}

fn optional_non_empty_string(config: &Value, key: &str) -> Result<Option<String>, String> {
    match config.get(key) {
        Some(value) => {
            let value = value
                .as_str()
                .ok_or_else(|| format!("loki_logging: '{key}' must be a string"))?;
            if value.trim().is_empty() {
                return Err(format!("loki_logging: '{key}' must not be empty"));
            }
            if value.trim() != value {
                return Err(format!(
                    "loki_logging: '{key}' must not have leading or trailing whitespace"
                ));
            }
            Ok(Some(value.to_string()))
        }
        None => Ok(None),
    }
}

fn validate_custom_header_name_lengths(config: &Value) -> Result<(), String> {
    let Some(headers) = config.get("custom_headers") else {
        return Ok(());
    };
    let headers = headers
        .as_object()
        .ok_or_else(|| "loki_logging: 'custom_headers' must be an object".to_string())?;
    if let Some(name) = headers
        .keys()
        .find(|name| name.len() > LOKI_MAX_CUSTOM_HEADER_NAME_BYTES)
    {
        return Err(format!(
            "loki_logging: custom_headers name is {} bytes; maximum is {LOKI_MAX_CUSTOM_HEADER_NAME_BYTES}",
            name.len()
        ));
    }
    Ok(())
}

fn validate_known_config_fields(config: &serde_json::Map<String, Value>) -> Result<(), String> {
    let mut unknown = config
        .keys()
        .filter(|key| !LOKI_LOGGING_CONFIG_KEYS.contains(&key.as_str()))
        .collect::<Vec<_>>();
    unknown.sort_unstable();
    if let Some(key) = unknown.first() {
        return Err(format!(
            "loki_logging: unknown configuration field 'config.{key}'"
        ));
    }
    Ok(())
}

fn bounded_u64(
    config: &Value,
    key: &str,
    default: u64,
    minimum: u64,
    maximum: u64,
) -> Result<u64, String> {
    let value = match config.get(key) {
        None => default,
        Some(value) => value
            .as_u64()
            .ok_or_else(|| format!("loki_logging: '{key}' must be an integer"))?,
    };
    if !(minimum..=maximum).contains(&value) {
        return Err(format!(
            "loki_logging: '{key}' must be between {minimum} and {maximum}"
        ));
    }
    Ok(value)
}

fn validate_loki_resource_config(
    config: &Value,
    defaults: BatchConfigDefaults,
) -> Result<(usize, usize, RetryPolicy), String> {
    // Batch size / flush / buffer / max_retries / retry_delay_ms are admitted by
    // the shared validator before this helper runs. Re-read the resolved values
    // (absent → defaults) without a second drifting range contract.
    let max_retries = config
        .get("max_retries")
        .and_then(Value::as_u64)
        .unwrap_or(defaults.max_retries);
    let retry_delay_ms = config
        .get("retry_delay_ms")
        .and_then(Value::as_u64)
        .unwrap_or(defaults.retry_delay_ms);
    let max_entry_bytes = bounded_u64(
        config,
        "max_entry_bytes",
        LOKI_DEFAULT_MAX_ENTRY_BYTES as u64,
        LOKI_MIN_RESOURCE_BYTES as u64,
        LOKI_MAX_MAX_ENTRY_BYTES as u64,
    )? as usize;
    let buffer_max_bytes = bounded_u64(
        config,
        "buffer_max_bytes",
        LOKI_DEFAULT_BUFFER_MAX_BYTES as u64,
        LOKI_MIN_RESOURCE_BYTES as u64,
        LOKI_MAX_BUFFER_MAX_BYTES as u64,
    )? as usize;
    if buffer_max_bytes < max_entry_bytes {
        return Err(
            "loki_logging: 'buffer_max_bytes' must be greater than or equal to 'max_entry_bytes'"
                .to_string(),
        );
    }

    let delay = Duration::from_millis(retry_delay_ms);
    Ok((
        max_entry_bytes,
        buffer_max_bytes,
        RetryPolicy {
            max_attempts: (max_retries as u32).saturating_add(1),
            delay,
            max_delay: Duration::from_millis(
                retry_delay_ms
                    .saturating_mul(8)
                    .min(MAX_BATCH_RETRY_DELAY_MS),
            ),
            jitter: true,
        },
    ))
}

fn next_loki_emitter_id() -> Result<String, String> {
    let prefix = LOKI_EMITTER_PREFIX.as_ref().map_err(|_| {
        "loki_logging: failed to generate the per-instance emitter label".to_string()
    })?;
    let instance_id = NEXT_LOKI_EMITTER_ID
        .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |value| {
            value.checked_add(1)
        })
        .map_err(|_| "loki_logging: emitter label counter exhausted".to_string())?;
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut value = String::with_capacity(LOKI_EMITTER_VALUE_BYTES);
    for &byte in prefix {
        value.push(HEX[(byte >> 4) as usize] as char);
        value.push(HEX[(byte & 0x0f) as usize] as char);
    }
    value.push('-');
    for byte in instance_id.to_be_bytes() {
        value.push(HEX[(byte >> 4) as usize] as char);
        value.push(HEX[(byte & 0x0f) as usize] as char);
    }
    Ok(value)
}

/// Structurally redacted collector URL for diagnostics (path/query omitted).
///
/// Delegates to the shared sink helper so every HTTP-backed log sink renders
/// one identical form. Retained as a named item because Loki's flush config and
/// unit tests refer to it directly.
pub(crate) fn redacted_endpoint_url(endpoint: &url::Url) -> String {
    super::utils::redacted_endpoint_url(endpoint)
}

fn is_valid_loki_label_name(name: &str) -> bool {
    let mut chars = name.chars();
    match chars.next() {
        Some(first) if first == '_' || first.is_ascii_alphabetic() => {}
        _ => return false,
    }
    chars.all(|ch| ch == '_' || ch.is_ascii_alphanumeric())
}

fn validate_loki_label_name(name: &str) -> Result<(), String> {
    if name.chars().count() > LOKI_MAX_LABEL_NAME_CHARS
        || !is_valid_loki_label_name(name)
        || name.starts_with("__")
        || name == LOKI_EMITTER_LABEL
    {
        return Err(format!(
            "loki_logging: invalid or reserved label name '{name}'"
        ));
    }
    Ok(())
}

fn retained_entry_bytes(line_bytes: usize, labels: &BTreeMap<String, String>) -> Option<usize> {
    labels.iter().try_fold(line_bytes, |total, (key, value)| {
        total.checked_add(key.len())?.checked_add(value.len())
    })
}

/// Acquire a provisional `max_entry_bytes` lease, serialize under the per-entry
/// bound, build labels, then shrink the lease to the exact retained charge
/// (JSON line + labels). Returns `None` without invoking the serializer or
/// label builder when the aggregate gate denies.
fn admit_under_byte_budget<T, F>(
    byte_budget: &LokiByteBudget,
    max_entry_bytes: usize,
    value: &T,
    kind: &str,
    build_labels: F,
) -> Option<LokiProvisionalAdmission>
where
    T: serde::Serialize,
    F: FnOnce() -> BTreeMap<String, String>,
{
    let lease = byte_budget.try_acquire(max_entry_bytes)?;
    let mut writer = BoundedJsonWriter::new(max_entry_bytes);
    if let Err(error) = serde_json::to_writer(&mut writer, value) {
        if writer.limit_exceeded {
            byte_budget.record_drop("serialized entry exceeded max_entry_bytes");
        } else {
            warn!("Loki logging: failed to serialize {kind}: {error}");
        }
        return None;
    }
    let labels = build_labels();
    let Some(retained_bytes) = retained_entry_bytes(writer.bytes.len(), &labels) else {
        byte_budget.record_drop("entry and labels exceeded byte accounting range");
        return None;
    };
    if retained_bytes > max_entry_bytes {
        byte_budget.record_drop("entry and labels exceeded max_entry_bytes");
        return None;
    }
    lease.shrink_to(retained_bytes);
    match String::from_utf8(writer.bytes) {
        Ok(line) => Some((Arc::<str>::from(line), labels, lease)),
        Err(error) => {
            warn!("Loki logging: serialized {kind} was not UTF-8: {error}");
            None
        }
    }
}

fn serialized_entry_bytes<T: serde::Serialize>(value: &T, kind: &str) -> Result<usize, String> {
    let mut writer = CountingJsonWriter::default();
    serde_json::to_writer(&mut writer, value)
        .map_err(|error| format!("loki_logging: failed to measure minimum {kind}: {error}"))?;
    Ok(writer.bytes)
}

fn minimum_http_summary() -> TransactionSummary {
    TransactionSummary {
        namespace: LOKI_MIN_PROXY_ID.to_string(),
        timestamp_received: LOKI_MIN_TIMESTAMP.to_string(),
        client_ip: "::".to_string(),
        http_method: "A".to_string(),
        request_path: "/".to_string(),
        proxy_id: Some(LOKI_MIN_PROXY_ID.to_string()),
        response_status_code: u16::MAX,
        ..TransactionSummary::default()
    }
}

fn minimum_stream_summary() -> StreamTransactionSummary {
    StreamTransactionSummary {
        namespace: LOKI_MIN_PROXY_ID.to_string(),
        proxy_id: LOKI_MIN_PROXY_ID.to_string(),
        proxy_lifecycle_generation: None,
        proxy_name: None,
        client_ip: "::".to_string(),
        consumer_username: None,
        auth_method: None,
        backend_target: "a:1".to_string(),
        backend_resolved_ip: None,
        protocol: LOKI_WORST_CASE_STREAM_PROTOCOL.to_string(),
        listen_port: 1,
        duration_ms: 0.0,
        bytes_sent: 0,
        bytes_received: 0,
        connection_error: None,
        error_class: None,
        disconnect_direction: None,
        disconnect_cause: None,
        timestamp_connected: LOKI_MIN_TIMESTAMP.to_string(),
        timestamp_disconnected: LOKI_MIN_TIMESTAMP.to_string(),
        sni_hostname: None,
        metadata: HashMap::new(),
    }
}

fn validate_minimum_entry_budget(
    label_config: &LabelConfig,
    schema: Option<&SummarySchema>,
    max_entry_bytes: usize,
) -> Result<(), String> {
    let http_summary = minimum_http_summary();
    let http_line_bytes = match schema.filter(|schema| schema.applies_to_http()) {
        Some(schema) => serialized_entry_bytes(
            &SchemaView {
                summary: &http_summary,
                schema,
            },
            "HTTP entry",
        )?,
        None => serialized_entry_bytes(&http_summary, "HTTP entry")?,
    };
    let mut http_label_summary = http_summary.clone();
    http_label_summary.proxy_id = Some("a".repeat(MAX_ID_LENGTH));
    let http_labels = label_config.build_http_labels(&http_label_summary);
    let http_retained_bytes = retained_entry_bytes(http_line_bytes, &http_labels);

    let stream_summary = minimum_stream_summary();
    let stream_line_bytes = match schema.filter(|schema| schema.applies_to_stream()) {
        Some(schema) => serialized_entry_bytes(
            &SchemaView {
                summary: &stream_summary,
                schema,
            },
            "stream entry",
        )?,
        None => serialized_entry_bytes(&stream_summary, "stream entry")?,
    };
    let mut stream_label_summary = stream_summary.clone();
    stream_label_summary.proxy_id = "a".repeat(MAX_ID_LENGTH);
    let stream_labels = label_config.build_stream_labels(&stream_label_summary);
    let stream_retained_bytes = retained_entry_bytes(stream_line_bytes, &stream_labels);

    let minimum_retained_bytes = http_retained_bytes
        .zip(stream_retained_bytes)
        .map(|(http, stream)| http.max(stream))
        .ok_or_else(|| {
            "loki_logging: minimum entry retained-byte accounting overflowed".to_string()
        })?;
    if minimum_retained_bytes > max_entry_bytes {
        return Err(format!(
            "loki_logging: 'max_entry_bytes' must fit a minimum serialized HTTP and stream entry plus configured, reserved, and worst-case dynamic label values (requires at least {minimum_retained_bytes} bytes, configured {max_entry_bytes})"
        ));
    }
    Ok(())
}

/// Observations from [`probe_loki_provisional_admission_for_test`].
#[derive(Debug, Clone, Copy)]
#[allow(dead_code)] // field reads happen only in `_test_support` wrappers
pub(crate) struct LokiProvisionalAdmissionProbe {
    /// Whether admission returned a queued line/lease.
    pub(crate) admitted: bool,
    /// Whether the custom `Serialize` implementation ran.
    pub(crate) serialize_called: bool,
    /// Whether the label-construction closure ran.
    pub(crate) labels_called: bool,
    /// Lease charge after a successful shrink (exact retained size).
    pub(crate) charged_after_admit: Option<usize>,
    /// Per-instance budget used after a successful admit.
    pub(crate) budget_used_after_admit: usize,
    /// Isolated ceiling used after a successful admit.
    pub(crate) ceiling_used_after_admit: usize,
    /// Per-instance budget used after the admitted lease drops.
    pub(crate) budget_used_after_drop: usize,
    /// Isolated ceiling used after the admitted lease drops.
    pub(crate) ceiling_used_after_drop: usize,
}

/// Deterministic hot-path admission probe for external unit tests.
///
/// Reserves against an isolated [`RetainedByteCeiling`]. When `hold_bytes` is
/// `Some`, that many bytes are held first so the provisional `max_entry_bytes`
/// reservation is refused — serialization and label construction must not run.
/// On success the provisional lease shrinks to the exact retained size and is
/// fully released when the returned lease drops.
#[allow(dead_code)] // reached via `_test_support` from the external test crate
pub(crate) fn probe_loki_provisional_admission_for_test(
    ceiling: &'static RetainedByteCeiling,
    buffer_max_bytes: usize,
    max_entry_bytes: usize,
    hold_bytes: Option<usize>,
) -> LokiProvisionalAdmissionProbe {
    use std::sync::atomic::AtomicBool;

    let budget = LokiByteBudget::with_ceiling(buffer_max_bytes, ceiling);
    let _hold = hold_bytes.and_then(|bytes| budget.try_acquire(bytes));

    let serialize_called = AtomicBool::new(false);
    let labels_called = AtomicBool::new(false);

    struct Probe<'a>(&'a AtomicBool);
    impl serde::Serialize for Probe<'_> {
        fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
            self.0.store(true, Ordering::SeqCst);
            serializer.serialize_str("probe")
        }
    }

    let admitted = admit_under_byte_budget(
        &budget,
        max_entry_bytes,
        &Probe(&serialize_called),
        "probe",
        || {
            labels_called.store(true, Ordering::SeqCst);
            let mut labels = BTreeMap::new();
            labels.insert("service".to_string(), "ferrum-edge".to_string());
            labels
        },
    );

    let serialize_ran = serialize_called.load(Ordering::SeqCst);
    let labels_ran = labels_called.load(Ordering::SeqCst);

    match admitted {
        Some((_line, _labels, lease)) => {
            let charged_after_admit = lease.charged_bytes();
            let budget_used_after_admit = budget.used();
            let ceiling_used_after_admit = ceiling.used();
            drop(lease);
            LokiProvisionalAdmissionProbe {
                admitted: true,
                serialize_called: serialize_ran,
                labels_called: labels_ran,
                charged_after_admit: Some(charged_after_admit),
                budget_used_after_admit,
                ceiling_used_after_admit,
                budget_used_after_drop: budget.used(),
                ceiling_used_after_drop: ceiling.used(),
            }
        }
        None => LokiProvisionalAdmissionProbe {
            admitted: false,
            serialize_called: serialize_ran,
            labels_called: labels_ran,
            charged_after_admit: None,
            budget_used_after_admit: budget.used(),
            ceiling_used_after_admit: ceiling.used(),
            budget_used_after_drop: budget.used(),
            ceiling_used_after_drop: ceiling.used(),
        },
    }
}

/// Observations from [`probe_loki_batch_materialization_for_test`].
#[derive(Debug, Clone, Copy)]
#[allow(dead_code)] // field reads happen only in `_test_support` wrappers
pub(crate) struct LokiMaterializationProbe {
    /// Ceiling bytes held by the queued entries alone.
    pub(crate) queued_bytes: usize,
    /// Ceiling bytes held while the queued entries and the wire body coexist.
    /// Must exceed `queued_bytes`: that difference is the batch representation
    /// the ceiling previously never saw.
    pub(crate) peak_bytes: usize,
    /// Ceiling bytes after the body (and every retry handle) drops.
    pub(crate) after_body_dropped_bytes: usize,
    /// Ceiling bytes once the queued entries release too. Must be zero.
    pub(crate) after_release_bytes: usize,
    /// `true` when the ceiling refused the batch representation.
    pub(crate) refused: bool,
    pub(crate) rejections: u64,
    /// `Content-Encoding` chosen for the materialized body.
    pub(crate) content_encoding: Option<&'static str>,
    /// Whole allocation of the label-grouping order index for this batch. It is
    /// reserved *inside* the write, so it is charged on top of `peak_bytes` and
    /// released before `peak_bytes` is observed.
    pub(crate) grouping_bytes: usize,
}

/// Build one synthetic queued batch for the probes below.
///
/// `distinct_label_sets` is the attacker-controlled dimension: a hostile client
/// can manufacture a new dynamic label set per entry, which is exactly what the
/// old grouping representation scaled with.
#[allow(dead_code)] // reached only from the probes below
fn probe_loki_batch_for_test(
    budget: &LokiByteBudget,
    entry_count: usize,
    line_bytes: usize,
    distinct_label_sets: usize,
) -> Option<Vec<LokiEntry>> {
    // A hostile line: already-JSON text made entirely of quotes, so every byte
    // doubles when it is re-embedded as a JSON string value.
    let line: Arc<str> = Arc::from("\"".repeat(line_bytes));
    let label_sets: Vec<Arc<BTreeMap<String, String>>> = (0..distinct_label_sets.max(1))
        .map(|index| {
            let mut labels = BTreeMap::new();
            labels.insert("service".to_string(), "ferrum-edge".to_string());
            // Fixed width so every label set costs the same retained bytes.
            labels.insert("stream".to_string(), format!("{index:016x}"));
            Arc::new(labels)
        })
        .collect();

    let mut batch = Vec::with_capacity(entry_count);
    for index in 0..entry_count {
        let labels = label_sets.get(index % label_sets.len())?;
        let retained = retained_entry_bytes(line.len(), labels.as_ref())?;
        batch.push(LokiEntry {
            labels: Arc::clone(labels),
            line: Arc::clone(&line),
            _lease: budget.try_acquire(retained)?,
        });
    }
    Some(batch)
}

/// Deterministic batch-materialization probe for external unit tests.
///
/// Queues `entry_count` entries of `line_bytes` each, spread over
/// `distinct_label_sets` label sets, through a real [`LokiByteBudget`] bound to
/// `ceiling`, then materializes the wire body while those leases are still held.
#[allow(dead_code)] // reached via `_test_support` from the external test crate
pub(crate) fn probe_loki_batch_materialization_for_test(
    ceiling: &'static RetainedByteCeiling,
    entry_count: usize,
    line_bytes: usize,
    gzip: bool,
    distinct_label_sets: usize,
) -> Option<LokiMaterializationProbe> {
    let budget = LokiByteBudget::with_ceiling(LOKI_MAX_BUFFER_MAX_BYTES, ceiling);
    let batch = probe_loki_batch_for_test(&budget, entry_count, line_bytes, distinct_label_sets)?;
    let grouping_bytes = loki_grouping_byte_bound(batch.len())?;
    let queued_bytes = ceiling.used();

    let cfg = LokiFlushConfig {
        endpoint_url: "http://127.0.0.1:3100/loki/api/v1/push".to_string(),
        endpoint_url_for_logs: "http://127.0.0.1:3100/loki/api/v1/push".to_string(),
        authorization_header: None,
        custom_headers: Vec::new(),
        http_client: PluginHttpClient::default(),
        gzip,
        retry: RetryPolicy::fixed(1, Duration::from_millis(0)),
        last_timestamp_ns: Arc::new(AtomicU64::new(0)),
        ceiling,
    };

    match build_loki_body(&cfg, &batch) {
        Ok((payload, content_encoding)) => {
            let peak_bytes = ceiling.used();
            drop(payload);
            let after_body_dropped_bytes = ceiling.used();
            drop(batch);
            Some(LokiMaterializationProbe {
                queued_bytes,
                peak_bytes,
                after_body_dropped_bytes,
                after_release_bytes: ceiling.used(),
                refused: false,
                rejections: ceiling.rejections(),
                content_encoding,
                grouping_bytes,
            })
        }
        Err(_) => {
            let peak_bytes = ceiling.used();
            drop(batch);
            Some(LokiMaterializationProbe {
                queued_bytes,
                peak_bytes,
                after_body_dropped_bytes: peak_bytes,
                after_release_bytes: ceiling.used(),
                refused: true,
                rejections: ceiling.rejections(),
                content_encoding: None,
                grouping_bytes,
            })
        }
    }
}

/// Deterministic grouping-semantics probe: returns the exact wire JSON a batch
/// of `entry_count` entries spread over `distinct_label_sets` label sets
/// produces, so an external test can pin stream grouping, per-stream entry
/// order, and timestamp monotonicity with many distinct label sets.
#[allow(dead_code)] // reached via `_test_support` from the external test crate
pub(crate) fn probe_loki_payload_json_for_test(
    entry_count: usize,
    distinct_label_sets: usize,
) -> Option<String> {
    let budget = LokiByteBudget::with_ceiling(LOKI_MAX_BUFFER_MAX_BYTES, process_ceiling());
    let batch = probe_loki_batch_for_test(&budget, entry_count, 8, distinct_label_sets)?;
    let mut out: Vec<u8> = Vec::new();
    write_loki_payload(&batch, &AtomicU64::new(0), process_ceiling(), &mut out).ok()?;
    String::from_utf8(out).ok()
}

/// Map an HTTP status code to its class string (low cardinality).
fn status_class(status: u16) -> String {
    match status {
        200..=299 => "2xx".to_string(),
        300..=399 => "3xx".to_string(),
        400..=499 => "4xx".to_string(),
        500..=599 => "5xx".to_string(),
        _ => "other".to_string(),
    }
}

#[async_trait]
impl Plugin for LokiLogging {
    fn name(&self) -> &str {
        "loki_logging"
    }

    fn priority(&self) -> u16 {
        super::priority::LOKI_LOGGING
    }

    fn supported_protocols(&self) -> &'static [super::ProxyProtocol] {
        super::ALL_PROTOCOLS
    }

    fn start_background_tasks(&self) -> Result<(), String> {
        let flush_config = self.flush_config.clone();
        self.logger
            .start("loki_logging", self.batch_config, move |batch| {
                let flush_config = flush_config.clone();
                async move { send_batch(&flush_config, &batch).await }
            })
    }

    fn commit_background_tasks(&self) {
        self.logger.commit();
    }

    async fn on_stream_disconnect(&self, summary: &StreamTransactionSummary) {
        match self.schema.as_ref().filter(|s| s.applies_to_stream()) {
            Some(schema) => {
                self.queue_entry(&SchemaView { summary, schema }, "stream summary", || {
                    self.build_stream_labels(summary)
                })
            }
            None => self.queue_entry(summary, "stream summary", || {
                self.build_stream_labels(summary)
            }),
        }
    }

    async fn log(&self, summary: &TransactionSummary) {
        match self.schema.as_ref().filter(|s| s.applies_to_http()) {
            Some(schema) => self.queue_entry(
                &SchemaView { summary, schema },
                "transaction summary",
                || self.build_http_labels(summary),
            ),
            None => self.queue_entry(summary, "transaction summary", || {
                self.build_http_labels(summary)
            }),
        }
    }

    fn warmup_hostnames(&self) -> Vec<String> {
        vec![self.endpoint_hostname.clone()]
    }
}

/// Fixed `{"streams":[]}` envelope allowance.
const LOKI_PAYLOAD_ENVELOPE_BYTES: usize = 32;
/// Per-stream-group framing allowance: `,{"stream":`, `,"values":[`, `]}`.
const LOKI_STREAM_FRAMING_BYTES: usize = 32;
/// Per-entry framing allowance: `,["<20-digit ns timestamp>",` plus `]`.
const LOKI_ENTRY_FRAMING_BYTES: usize = 32;
/// Worst-case gzip expansion: DEFLATE falls back to stored blocks, costing five
/// bytes of block header per 65535 input bytes, plus the fixed gzip header and
/// trailer.
const LOKI_GZIP_STORED_BLOCK_SPAN: usize = 65_535;
const LOKI_GZIP_FIXED_OVERHEAD_BYTES: usize = 64;

/// Conservative upper bound on the serialized Loki push payload for `batch`.
///
/// Every log line is already valid JSON, so re-embedding it as a JSON string
/// value can at most double it. Label keys and values are raw strings and get
/// the full six-byte `\u00XX` worst case. Grouping writes each label set once per
/// group, so charging every entry for its own labels is conservative.
fn loki_payload_byte_bound(batch: &[LokiEntry]) -> Option<usize> {
    let mut total = LOKI_PAYLOAD_ENVELOPE_BYTES;
    for entry in batch {
        let mut entry_bound = entry
            .line
            .len()
            .checked_mul(JSON_REEMBEDDED_WORST_CASE_EXPANSION)?;
        for (key, value) in entry.labels.iter() {
            entry_bound = entry_bound.checked_add(
                key.len()
                    .checked_add(value.len())?
                    .checked_mul(JSON_STRING_WORST_CASE_EXPANSION)?,
            )?;
        }
        total = total
            .checked_add(entry_bound)?
            .checked_add(LOKI_ENTRY_FRAMING_BYTES)?
            .checked_add(LOKI_STREAM_FRAMING_BYTES)?;
    }
    Some(total)
}

fn loki_gzip_byte_bound(input_len: usize) -> Option<usize> {
    input_len
        .checked_add((input_len / LOKI_GZIP_STORED_BLOCK_SPAN).checked_mul(5)?)?
        .checked_add(LOKI_GZIP_FIXED_OVERHEAD_BYTES)
}

fn write_loki_str<W: Write>(out: &mut W, text: &str) -> Result<(), String> {
    out.write_all(text.as_bytes())
        .map_err(|error| format!("failed to write Loki payload: {error}"))
}

/// Bytes one entry of the label-grouping order index occupies.
const LOKI_GROUPING_ENTRY_BYTES: usize = std::mem::size_of::<usize>();

/// Whole allocation of the label-grouping order index for `entry_count`
/// entries. `Vec::with_capacity` never grows past this, so reserving it once
/// covers the index for its entire (function-scoped) life.
fn loki_grouping_byte_bound(entry_count: usize) -> Option<usize> {
    entry_count.checked_mul(LOKI_GROUPING_ENTRY_BYTES)
}

/// Entry sitting at `position` of the grouping order index.
fn loki_entry_at<'batch>(
    batch: &'batch [LokiEntry],
    order: &[usize],
    position: usize,
) -> Option<&'batch LokiEntry> {
    order.get(position).and_then(|index| batch.get(*index))
}

/// Fixed diagnostic for an order-index/batch mismatch, which the construction
/// above makes unreachable but which must not panic if it ever happens.
fn loki_grouping_desynchronized() -> String {
    "Loki logging: label grouping index desynchronized".to_string()
}

/// Group entries by label set and stream the Loki push payload straight into
/// `out`.
///
/// There is deliberately no intermediate `serde_json::Value` and no per-group
/// container. Grouping is a single `usize` order index — one element per entry,
/// independent of how many *distinct* label sets an attacker can manufacture —
/// whose whole allocation is reserved against `ceiling` before it exists and
/// released when this function returns. Entries are ordered by label set with
/// ties broken by queue position, so equal label sets form one contiguous run:
/// each stream is emitted once, per-stream entry order is the original queue
/// order, and the output is deterministic for a given batch. The label maps
/// themselves are borrowed from the queued entries and never cloned, so the only
/// batch-*byte*-sized representation that exists is the caller's reserved output
/// buffer.
fn write_loki_payload<W: Write>(
    batch: &[LokiEntry],
    last_timestamp_ns: &AtomicU64,
    ceiling: &'static RetainedByteCeiling,
    out: &mut W,
) -> Result<(), String> {
    let grouping_bytes = loki_grouping_byte_bound(batch.len()).ok_or_else(|| {
        PayloadMaterializationError::BoundOverflowed
            .reason()
            .to_string()
    })?;
    let _grouping_reservation = ceiling.try_acquire(grouping_bytes).ok_or_else(|| {
        PayloadMaterializationError::CeilingExhausted
            .reason()
            .to_string()
    })?;
    let mut order: Vec<usize> = Vec::with_capacity(batch.len());
    order.extend(0..batch.len());
    // `sort_unstable_by` allocates nothing (the stable sort would allocate an
    // uncharged temporary); the index tiebreak makes it stable in effect.
    order.sort_unstable_by(|left, right| match (batch.get(*left), batch.get(*right)) {
        (Some(first), Some(second)) => first
            .labels
            .as_ref()
            .cmp(second.labels.as_ref())
            .then_with(|| left.cmp(right)),
        // Unreachable: `order` holds exactly `0..batch.len()`.
        _ => std::cmp::Ordering::Equal,
    });

    write_loki_str(&mut *out, "{\"streams\":[")?;
    let mut position = 0usize;
    let mut group_index = 0usize;
    while position < order.len() {
        let labels = loki_entry_at(batch, &order, position)
            .ok_or_else(loki_grouping_desynchronized)?
            .labels
            .as_ref();
        let mut group_end = position.saturating_add(1);
        while let Some(entry) = loki_entry_at(batch, &order, group_end) {
            if entry.labels.as_ref() != labels {
                break;
            }
            group_end = group_end.saturating_add(1);
        }

        if group_index > 0 {
            write_loki_str(&mut *out, ",")?;
        }
        write_loki_str(&mut *out, "{\"stream\":")?;
        serde_json::to_writer(&mut *out, labels)
            .map_err(|error| format!("Loki logging: failed to serialize labels: {error}"))?;
        write_loki_str(&mut *out, ",\"values\":[")?;
        for value_position in position..group_end {
            let entry = loki_entry_at(batch, &order, value_position)
                .ok_or_else(loki_grouping_desynchronized)?;
            if value_position > position {
                write_loki_str(&mut *out, ",")?;
            }
            write_loki_str(&mut *out, "[\"")?;
            write_loki_str(&mut *out, &next_loki_timestamp_ns(last_timestamp_ns)?)?;
            write_loki_str(&mut *out, "\",")?;
            serde_json::to_writer(&mut *out, entry.line.as_ref())
                .map_err(|error| format!("Loki logging: failed to serialize log line: {error}"))?;
            write_loki_str(&mut *out, "]")?;
        }
        write_loki_str(&mut *out, "]}")?;
        position = group_end;
        group_index = group_index.saturating_add(1);
    }
    write_loki_str(&mut *out, "]}")?;
    Ok(())
}

fn next_loki_timestamp_ns(last_timestamp_ns: &AtomicU64) -> Result<String, String> {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| "Loki logging: system clock is before the Unix epoch".to_string())?;
    let now = u64::try_from(now.as_nanos())
        .map_err(|_| "Loki logging: system clock exceeds Loki timestamp range".to_string())?;
    let mut previous = last_timestamp_ns.load(Ordering::Acquire);
    loop {
        let next =
            now.max(previous.checked_add(1).ok_or_else(|| {
                "Loki logging: monotonic timestamp counter exhausted".to_string()
            })?);
        match last_timestamp_ns.compare_exchange_weak(
            previous,
            next,
            Ordering::AcqRel,
            Ordering::Acquire,
        ) {
            Ok(_) => return Ok(next.to_string()),
            Err(observed) => previous = observed,
        }
    }
}

/// Send a batch of entries to Loki.
async fn send_batch(cfg: &LokiFlushConfig, batch: &[LokiEntry]) -> Result<(), String> {
    let entry_count = batch.len();
    let (payload, content_encoding) = match build_loki_body(cfg, batch) {
        Ok(body) => body,
        Err(error) => {
            // Fixed-label, sampled loss accounting: under a saturated ceiling
            // this path fires once per batch, so it must not warn once per
            // batch. The record-scale counter is separate from the ceiling's
            // reservation-rejection counter.
            record_batch_materialization_loss(LOKI_PLUGIN_NAME, entry_count as u64, error.reason());
            return Ok(());
        }
    };
    // The reserved payload is now the only per-attempt attacker-shaped
    // representation. Queued entries remain under the shared logger's Arc
    // across BatchingLogger retries; this borrow ends with the attempt.
    let _ = batch;
    let attempts = cfg.retry.max_attempts.max(1);

    for attempt in 1..=attempts {
        match send_batch_once(cfg, payload.bytes(), content_encoding).await {
            LokiAttemptOutcome::Delivered => return Ok(()),
            LokiAttemptOutcome::Terminal(error) => {
                warn!(
                    plugin = "loki_logging",
                    "Loki logging: batch discarded after terminal delivery failure ({} entries lost): {}",
                    entry_count,
                    error,
                );
                return Ok(());
            }
            LokiAttemptOutcome::Retryable(error) if attempt < attempts => {
                warn!(
                    plugin = "loki_logging",
                    "Loki logging: batch flush failed (attempt {}/{}): {}",
                    attempt,
                    attempts,
                    error,
                );
                tokio::time::sleep(cfg.retry.backoff_delay(attempt)).await;
            }
            LokiAttemptOutcome::Retryable(error) => {
                warn!(
                    plugin = "loki_logging",
                    "Loki logging: batch discarded after {} attempts ({} entries lost): {}",
                    attempts,
                    entry_count,
                    error,
                );
                return Ok(());
            }
        }
    }

    Ok(())
}

/// Materialize the batch's wire body under the process-wide retained-byte
/// ceiling.
///
/// Both representations that can coexist with the still-charged queued entries —
/// the serialized JSON buffer and, with gzip enabled, the compressed output — are
/// reserved before a single byte is written and stay charged for as long as the
/// returned payload (and every retry handle taken from it) lives. A refused
/// reservation returns a fixed-label error so the batch is dropped with loss
/// accounting instead of being materialized outside the ceiling.
fn build_loki_body(
    cfg: &LokiFlushConfig,
    batch: &[LokiEntry],
) -> Result<(ReservedPayload, Option<&'static str>), PayloadMaterializationError> {
    let bound =
        loki_payload_byte_bound(batch).ok_or(PayloadMaterializationError::BoundOverflowed)?;
    let json = materialize_reserved_payload(cfg.ceiling, bound, |writer| {
        write_loki_payload(batch, &cfg.last_timestamp_ns, cfg.ceiling, writer)
    })?;

    if !cfg.gzip {
        return Ok((json, None));
    }
    let Some(gzip_bound) = loki_gzip_byte_bound(json.len()) else {
        record_batch_materialization_fallback(
            LOKI_PLUGIN_NAME,
            PayloadMaterializationError::BoundOverflowed.reason(),
        );
        return Ok((json, None));
    };
    // The compressed buffer coexists with the JSON buffer until `json` is
    // dropped below, so it gets its own reservation rather than reusing one.
    // Bound the result to a `let` so the closure's borrow of `json` ends before
    // the uncompressed fallback moves it.
    let compressed = materialize_reserved_payload(cfg.ceiling, gzip_bound, |writer| {
        gzip_into(json.as_slice(), writer)
    });
    match compressed {
        Ok(compressed) => Ok((compressed, Some("gzip"))),
        Err(error) => {
            // Complete delivery in a degraded representation, not a loss. The
            // diagnostic is sampled by the shared accounting helper so a
            // saturated ceiling cannot warn once per batch indefinitely.
            record_batch_materialization_fallback(LOKI_PLUGIN_NAME, error.reason());
            Ok((json, None))
        }
    }
}

enum LokiAttemptOutcome {
    Delivered,
    Retryable(String),
    Terminal(String),
}

fn loki_drain_diagnostic(drain: HttpBatchDrainOutcome) -> String {
    match drain {
        HttpBatchDrainOutcome::Complete(bytes) => format!("{bytes} response bytes discarded"),
        other => other.diagnostic().to_string(),
    }
}

async fn send_batch_once(
    cfg: &LokiFlushConfig,
    body_bytes: Bytes,
    content_encoding: Option<&'static str>,
) -> LokiAttemptOutcome {
    let mut req = cfg
        .http_client
        .get()
        .post(&cfg.endpoint_url)
        .header("Content-Type", "application/json")
        .body(body_bytes);

    if let Some(encoding) = content_encoding {
        req = req.header("Content-Encoding", encoding);
    }
    if let Some(auth) = &cfg.authorization_header {
        req = req.header("Authorization", auth.clone());
    }
    for (key, value) in &cfg.custom_headers {
        req = req.header(key.clone(), value.clone());
    }

    let response = match cfg
        .http_client
        .execute_redacted(req, "loki_logging", &cfg.endpoint_url_for_logs)
        .await
    {
        Ok(response) => response,
        Err(error) => return LokiAttemptOutcome::Retryable(error),
    };
    let status = response.status();
    // Shared HTTP batch helper: bounded discard drain before status classification.
    let drain = drain_http_batch_response_body(response).await;
    classify_loki_response(status, drain)
}

fn classify_loki_response(
    status: http::StatusCode,
    drain: HttpBatchDrainOutcome,
) -> LokiAttemptOutcome {
    if status.as_u16() == 204 {
        // A received 204 is Loki's committed success signal. Retrying merely
        // because connection cleanup failed can duplicate an already-ingested
        // batch, so the bounded drain is best-effort after this status.
        return LokiAttemptOutcome::Delivered;
    }
    let drain_diagnostic = loki_drain_diagnostic(drain);
    if status.as_u16() == 260 {
        return LokiAttemptOutcome::Terminal(format!(
            "Loki blocked ingestion with status 260; {drain_diagnostic}"
        ));
    }
    if status.as_u16() == 408 || status.as_u16() == 429 || status.is_server_error() {
        return LokiAttemptOutcome::Retryable(format!(
            "Loki returned retryable status {}; {drain_diagnostic}",
            status.as_u16()
        ));
    }
    if status.is_success() {
        return match drain {
            HttpBatchDrainOutcome::Complete(0) => LokiAttemptOutcome::Delivered,
            HttpBatchDrainOutcome::Complete(bytes) => LokiAttemptOutcome::Terminal(format!(
                "Loki-compatible receiver returned status {} with an unexpected non-empty response ({bytes} bytes discarded)",
                status.as_u16()
            )),
            _ => LokiAttemptOutcome::Terminal(format!(
                "Loki-compatible receiver returned status {} but an empty response could not be confirmed: {drain_diagnostic}",
                status.as_u16()
            )),
        };
    }

    LokiAttemptOutcome::Terminal(format!(
        "Loki returned non-success status {}; {drain_diagnostic}",
        status.as_u16()
    ))
}

/// Gzip-compress `input` straight into the caller's reserved buffer.
///
/// Compressing into the bounded writer means the compressed output never lives
/// in a second uncharged `Vec`.
fn gzip_into(input: &[u8], out: &mut BoundedPayloadWriter) -> Result<(), String> {
    use flate2::Compression;
    use flate2::write::GzEncoder;

    let mut encoder = GzEncoder::new(out, Compression::fast());
    encoder
        .write_all(input)
        .map_err(|error| format!("gzip write failed: {error}"))?;
    encoder
        .finish()
        .map_err(|error| format!("gzip finish failed: {error}"))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::plugins::utils::PluginHttpClient;
    use serde_json::json;

    fn client() -> PluginHttpClient {
        PluginHttpClient::default()
    }

    fn must<T, E: std::fmt::Display>(result: Result<T, E>, context: &str) -> T {
        match result {
            Ok(value) => value,
            Err(error) => panic!("{context}: {error}"),
        }
    }

    fn make_summary(status: u16, proxy_id: Option<&str>) -> TransactionSummary {
        TransactionSummary {
            namespace: "ferrum".to_string(),
            timestamp_received: "2026-04-01T00:00:00Z".to_string(),
            client_ip: "10.0.0.1".to_string(),
            http_method: "GET".to_string(),
            request_path: "/t".to_string(),
            proxy_id: proxy_id.map(str::to_owned),
            response_status_code: status,
            latency_total_ms: 1.0,
            latency_gateway_processing_ms: 1.0,
            ..TransactionSummary::default()
        }
    }

    // Pure construction no longer spawns a flush worker. Label helpers below
    // only need the compiled config, so they remain usable without activation.
    #[test]
    fn label_include_proxy_id_key_controls_proxy_id_label() {
        let plugin = LokiLogging::new(
            &json!({
                "endpoint_url": "http://127.0.0.1:1/loki/api/v1/push",
                "include_proxy_id_label": false,
                "include_status_class_label": false,
            }),
            client(),
        );
        let plugin = must(plugin, "loki_logging config should be valid");
        let summary = make_summary(500, Some("p-1"));
        let labels = plugin.build_http_labels(&summary);
        assert!(!labels.contains_key("proxy_id"));
        assert!(!labels.contains_key("status_class"));
    }

    #[test]
    fn removed_listen_path_key_is_rejected() {
        let result = LokiLogging::new(
            &json!({
                "endpoint_url": "http://127.0.0.1:1/loki/api/v1/push",
                "include_listen_path_label": false,
            }),
            client(),
        );
        let err = result.err().expect("removed key should be rejected");
        assert!(err.contains("include_listen_path_label"), "got: {err}");
    }

    #[tokio::test]
    async fn label_default_includes_proxy_id() {
        let plugin = LokiLogging::new(
            &json!({ "endpoint_url": "http://127.0.0.1:1/loki/api/v1/push" }),
            client(),
        );
        let plugin = must(plugin, "loki_logging config should be valid");
        let summary = make_summary(200, Some("p-3"));
        let labels = plugin.build_http_labels(&summary);
        assert_eq!(labels.get("proxy_id").map(String::as_str), Some("p-3"));
        assert_eq!(labels.get("status_class").map(String::as_str), Some("2xx"));
    }

    #[test]
    fn label_name_validation_matches_loki_shape() {
        assert!(is_valid_loki_label_name("service"));
        assert!(is_valid_loki_label_name("_tenant"));
        assert!(is_valid_loki_label_name("env_1"));
        assert!(!is_valid_loki_label_name(""));
        assert!(!is_valid_loki_label_name("1env"));
        assert!(!is_valid_loki_label_name("bad-label"));
        assert!(validate_loki_label_name("__internal").is_err());
        assert!(validate_loki_label_name(LOKI_EMITTER_LABEL).is_err());
    }

    #[test]
    fn committed_204_is_delivered_after_transport_drain_failure() {
        assert!(matches!(
            classify_loki_response(
                http::StatusCode::NO_CONTENT,
                HttpBatchDrainOutcome::TransportFailure,
            ),
            LokiAttemptOutcome::Delivered
        ));
    }

    #[test]
    fn build_loki_payload_groups_entries_by_label_set() {
        let mut labels_a = BTreeMap::new();
        labels_a.insert("service".to_string(), "ferrum-edge".to_string());
        labels_a.insert("proxy_id".to_string(), "p-1".to_string());

        let mut labels_b = BTreeMap::new();
        labels_b.insert("service".to_string(), "ferrum-edge".to_string());
        labels_b.insert("proxy_id".to_string(), "p-2".to_string());

        let budget = LokiByteBudget::with_ceiling(4096, process_ceiling());
        let batch = [
            LokiEntry {
                labels: Arc::new(labels_a.clone()),
                line: Arc::from(r#"{"a":1}"#),
                _lease: budget.try_acquire(10).expect("test byte lease"),
            },
            LokiEntry {
                labels: Arc::new(labels_a),
                line: Arc::from(r#"{"a":2}"#),
                _lease: budget.try_acquire(10).expect("test byte lease"),
            },
            LokiEntry {
                labels: Arc::new(labels_b),
                line: Arc::from(r#"{"b":1}"#),
                _lease: budget.try_acquire(10).expect("test byte lease"),
            },
        ];
        let mut out: Vec<u8> = Vec::new();
        write_loki_payload(&batch, &AtomicU64::new(0), process_ceiling(), &mut out)
            .expect("payload");
        let payload: Value = serde_json::from_slice(&out).expect("payload is valid JSON");

        let Some(streams) = payload["streams"].as_array() else {
            panic!("payload should include streams array");
        };
        assert_eq!(streams.len(), 2);
        let value_counts: Vec<usize> = streams
            .iter()
            .map(|stream| {
                let Some(values) = stream["values"].as_array() else {
                    panic!("stream should include values array");
                };
                values.len()
            })
            .collect();
        assert!(value_counts.contains(&2));
        assert!(value_counts.contains(&1));
    }
}
