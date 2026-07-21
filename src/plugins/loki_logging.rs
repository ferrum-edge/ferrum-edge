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

use super::utils::log_schema::{SchemaCapabilities, SchemaView, SummarySchema, resolve_schema};
use super::utils::{
    BatchConfig, BatchConfigDefaults, DeferredBatchingLogger, HttpBatchDrainOutcome, MAX_BATCH_SIZE,
    MAX_BUFFER_CAPACITY, PluginHttpClient, RetryPolicy, build_batch_config,
    drain_http_batch_response_body, parse_custom_headers, parse_http_endpoint,
    validate_batch_config,
};
use super::{Plugin, StreamTransactionSummary, TransactionSummary};

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
pub const LOKI_MAX_RETRIES: u64 = 10;
pub const LOKI_MAX_RETRY_DELAY_MS: u64 = 60_000;
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
}

struct LokiByteLease {
    used_bytes: Arc<AtomicUsize>,
    bytes: usize,
}

impl Drop for LokiByteLease {
    fn drop(&mut self) {
        self.used_bytes.fetch_sub(self.bytes, Ordering::AcqRel);
    }
}

struct LokiByteBudget {
    used_bytes: Arc<AtomicUsize>,
    max_bytes: usize,
    dropped_count: AtomicU64,
}

impl LokiByteBudget {
    fn new(max_bytes: usize) -> Self {
        Self {
            used_bytes: Arc::new(AtomicUsize::new(0)),
            max_bytes,
            dropped_count: AtomicU64::new(0),
        }
    }

    fn try_acquire(&self, bytes: usize) -> Option<Arc<LokiByteLease>> {
        let reserved = self
            .used_bytes
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |used| {
                used.checked_add(bytes)
                    .filter(|next| *next <= self.max_bytes)
            });
        if reserved.is_err() {
            self.record_drop("retained-content byte budget exhausted");
            return None;
        }

        Some(Arc::new(LokiByteLease {
            used_bytes: Arc::clone(&self.used_bytes),
            bytes,
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
        };
        validate_batch_config(config, "loki_logging", batch_defaults)?;
        let (max_entry_bytes, buffer_max_bytes, retry) =
            validate_loki_resource_config(config, batch_defaults)?;
        let schema = resolve_schema(config, "loki_logging", SchemaCapabilities::BASE)?;
        validate_minimum_entry_budget(&label_config, schema.as_deref(), max_entry_bytes)?;
        let mut batch_config = build_batch_config(config, "loki_logging", batch_defaults);
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
            byte_budget: Arc::new(LokiByteBudget::new(buffer_max_bytes)),
            max_entry_bytes,
        })
    }

    fn queue_entry<T, F>(&self, value: &T, kind: &str, build_labels: F)
    where
        T: serde::Serialize,
        F: FnOnce() -> BTreeMap<String, String>,
    {
        let Some(permit) = self.logger.try_reserve() else {
            return;
        };

        let mut writer = BoundedJsonWriter::new(self.max_entry_bytes);
        if let Err(error) = serde_json::to_writer(&mut writer, value) {
            if writer.limit_exceeded {
                self.byte_budget
                    .record_drop("serialized entry exceeded max_entry_bytes");
            } else {
                warn!("Loki logging: failed to serialize {kind}: {error}");
            }
            return;
        }
        let labels = build_labels();
        let Some(retained_bytes) = retained_entry_bytes(writer.bytes.len(), &labels) else {
            self.byte_budget
                .record_drop("entry and labels exceeded byte accounting range");
            return;
        };
        if retained_bytes > self.max_entry_bytes {
            self.byte_budget
                .record_drop("entry and labels exceeded max_entry_bytes");
            return;
        }
        let Some(lease) = self.byte_budget.try_acquire(retained_bytes) else {
            return;
        };
        let line = match String::from_utf8(writer.bytes) {
            Ok(line) => Arc::<str>::from(line),
            Err(error) => {
                warn!("Loki logging: serialized {kind} was not UTF-8: {error}");
                return;
            }
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
    bounded_u64(
        config,
        defaults.batch_size_key,
        defaults.batch_size,
        1,
        MAX_BATCH_SIZE as u64,
    )?;
    bounded_u64(
        config,
        "flush_interval_ms",
        defaults.flush_interval_ms,
        defaults.min_flush_interval_ms,
        u64::MAX,
    )?;
    bounded_u64(
        config,
        "buffer_capacity",
        defaults.buffer_capacity,
        1,
        MAX_BUFFER_CAPACITY as u64,
    )?;
    let max_retries = bounded_u64(
        config,
        "max_retries",
        defaults.max_retries,
        0,
        LOKI_MAX_RETRIES,
    )?;
    let retry_delay_ms = bounded_u64(
        config,
        "retry_delay_ms",
        defaults.retry_delay_ms,
        1,
        LOKI_MAX_RETRY_DELAY_MS,
    )?;
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
                    .min(LOKI_MAX_RETRY_DELAY_MS),
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

pub(crate) fn redacted_endpoint_url(endpoint: &url::Url) -> String {
    let host = match endpoint.host() {
        Some(url::Host::Domain(host)) => host.to_string(),
        Some(url::Host::Ipv4(host)) => host.to_string(),
        Some(url::Host::Ipv6(host)) => format!("[{host}]"),
        None => "redacted-host".to_string(),
    };
    let port = endpoint
        .port()
        .map(|port| format!(":{port}"))
        .unwrap_or_default();
    format!("{}://{}{}/redacted", endpoint.scheme(), host, port)
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
                async move { send_batch(&flush_config, batch).await }
            })
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

/// Group entries by label set and build the Loki push payload.
fn build_loki_payload(batch: &[LokiEntry], last_timestamp_ns: &AtomicU64) -> Result<Value, String> {
    let mut streams: HashMap<BTreeMap<String, String>, Vec<(String, String)>> = HashMap::new();

    for entry in batch {
        let stream = streams.entry(entry.labels.as_ref().clone()).or_default();
        stream.push((
            next_loki_timestamp_ns(last_timestamp_ns)?,
            entry.line.to_string(),
        ));
    }

    let streams_array: Vec<Value> = streams
        .into_iter()
        .map(|(labels, values)| {
            let values_array: Vec<Value> = values
                .into_iter()
                .map(|(timestamp, line)| serde_json::json!([timestamp, line]))
                .collect();
            serde_json::json!({
                "stream": labels,
                "values": values_array,
            })
        })
        .collect();

    Ok(serde_json::json!({ "streams": streams_array }))
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
async fn send_batch(cfg: &LokiFlushConfig, batch: Vec<LokiEntry>) -> Result<(), String> {
    let entry_count = batch.len();
    let (body_bytes, content_encoding) = match build_loki_body(cfg, &batch) {
        Ok(body) => body,
        Err(error) => {
            warn!(
                plugin = "loki_logging",
                "Loki logging: batch discarded before delivery ({} entries lost): {}",
                entry_count,
                error,
            );
            return Ok(());
        }
    };
    let attempts = cfg.retry.max_attempts.max(1);

    for attempt in 1..=attempts {
        match send_batch_once(cfg, body_bytes.clone(), content_encoding).await {
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

fn build_loki_body(
    cfg: &LokiFlushConfig,
    batch: &[LokiEntry],
) -> Result<(Bytes, Option<&'static str>), String> {
    let payload = build_loki_payload(batch, &cfg.last_timestamp_ns)?;

    if cfg.gzip {
        match gzip_json(&payload) {
            Ok(compressed) => Ok((Bytes::from(compressed), Some("gzip"))),
            Err(error) => {
                warn!("Loki logging: gzip compression failed, sending uncompressed: {error}");
                Ok((Bytes::from(json_payload_bytes(&payload)?), None))
            }
        }
    } else {
        Ok((Bytes::from(json_payload_bytes(&payload)?), None))
    }
}

fn json_payload_bytes(payload: &Value) -> Result<Vec<u8>, String> {
    serde_json::to_vec(payload)
        .map_err(|error| format!("Loki logging: failed to serialize payload: {error}"))
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

/// Gzip-compress a JSON value.
fn gzip_json(value: &Value) -> Result<Vec<u8>, std::io::Error> {
    use flate2::Compression;
    use flate2::write::GzEncoder;
    use std::io::Write;

    let json_bytes = serde_json::to_vec(value)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
    let mut encoder = GzEncoder::new(Vec::new(), Compression::fast());
    encoder.write_all(&json_bytes)?;
    encoder.finish()
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

        let budget = LokiByteBudget::new(4096);
        let payload = build_loki_payload(
            &[
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
            ],
            &AtomicU64::new(0),
        )
        .expect("payload");

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
