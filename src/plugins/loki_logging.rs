//! Loki access logging plugin — batched async log shipping to Grafana Loki.
//!
//! Serializes `TransactionSummary` and `StreamTransactionSummary` entries and
//! sends them to Loki's push API (`/loki/api/v1/push`) in batches. Uses
//! `BatchingLogger<LokiEntry>` to decouple the proxy hot path from network I/O.
//!
//! Loki-specific features:
//! - **Labels**: Low-cardinality indexed labels (service, environment, proxy
//!   listen path, status class) configurable via `labels` map in plugin config.
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
use serde_json::Value;
use std::collections::BTreeMap;
use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;
use tracing::warn;

use super::utils::log_schema::{SchemaView, SummarySchema, resolve_schema};
use super::utils::{
    BatchConfig, BatchConfigDefaults, BatchingLogger, PluginHttpClient, RetryPolicy,
    build_batch_config, handle_http_batch_response, parse_custom_headers, parse_http_endpoint,
    validate_batch_config,
};
use super::{Plugin, StreamTransactionSummary, TransactionSummary};

/// A log entry with pre-computed labels and a JSON log line.
#[derive(Clone)]
struct LokiEntry {
    /// Sorted label key-value pairs (deterministic ordering for grouping).
    labels: BTreeMap<String, String>,
    /// Nanosecond epoch timestamp as a string.
    timestamp_ns: String,
    /// JSON-serialized log line.
    line: String,
}

#[derive(Clone)]
struct LokiFlushConfig {
    endpoint_url: String,
    authorization_header: Option<HeaderValue>,
    custom_headers: Vec<(HeaderName, HeaderValue)>,
    http_client: PluginHttpClient,
    gzip: bool,
    retry: RetryPolicy,
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

pub struct LokiLogging {
    logger: BatchingLogger<LokiEntry>,
    endpoint_hostname: String,
    label_config: LabelConfig,
    schema: Option<Arc<SummarySchema>>,
}

impl LokiLogging {
    pub fn new(config: &Value, http_client: PluginHttpClient) -> Result<Self, String> {
        if !config.is_object() {
            return Err("loki_logging: config must be an object".to_string());
        }

        let (endpoint_url, endpoint_hostname) = parse_http_endpoint(config, "loki_logging")?;
        let gzip = optional_bool(config, "gzip")?.unwrap_or(true);

        // Parse static labels from config.
        let mut static_labels = BTreeMap::new();
        if let Some(labels) = config.get("labels") {
            let labels_obj = labels
                .as_object()
                .ok_or_else(|| "loki_logging: 'labels' must be an object".to_string())?;
            for (key, value) in labels_obj {
                if !is_valid_loki_label_name(key) {
                    return Err(format!("loki_logging: invalid label name '{key}'"));
                }
                let label = value
                    .as_str()
                    .ok_or_else(|| format!("loki_logging: 'labels.{key}' must be a string"))?;
                static_labels.insert(key.clone(), label.to_string());
            }
        }
        if !static_labels.contains_key("service") {
            static_labels.insert("service".to_string(), "ferrum-edge".to_string());
        }

        if config.get("include_listen_path_label").is_some() {
            return Err(
                "loki_logging: 'include_listen_path_label' was removed; use 'include_proxy_id_label'"
                    .to_string(),
            );
        }
        let include_proxy_id = optional_bool(config, "include_proxy_id_label")?.unwrap_or(true);
        let include_status_class =
            optional_bool(config, "include_status_class_label")?.unwrap_or(true);

        let label_config = LabelConfig {
            static_labels,
            include_proxy_id,
            include_status_class,
        };

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
        let batch_config = build_batch_config(config, "loki_logging", batch_defaults);
        let flush_config = LokiFlushConfig {
            endpoint_url,
            authorization_header,
            custom_headers,
            http_client,
            gzip,
            retry: batch_config.retry,
        };
        let logger = BatchingLogger::spawn(
            // Loki retries inside `send_batch` so we can reuse the same
            // serialized + gzipped body bytes across attempts.
            BatchConfig {
                retry: RetryPolicy {
                    max_attempts: 1,
                    delay: Duration::from_millis(0),
                },
                ..batch_config
            },
            move |batch| {
                let flush_config = flush_config.clone();
                async move { send_batch(&flush_config, batch).await }
            },
        );

        let schema = resolve_schema(config, "loki_logging")?;
        Ok(Self {
            logger,
            endpoint_hostname,
            label_config,
            schema,
        })
    }

    fn queue_entry<T: serde::Serialize>(
        &self,
        value: &T,
        labels: BTreeMap<String, String>,
        timestamp: &str,
        kind: &str,
    ) {
        let line = match serde_json::to_string(value) {
            Ok(line) => line,
            Err(error) => {
                warn!("Loki logging: failed to serialize {kind}: {error}");
                return;
            }
        };
        self.logger.try_send(LokiEntry {
            labels,
            timestamp_ns: timestamp_nanos_from_rfc3339(timestamp),
            line,
        });
    }

    /// Build labels for an HTTP/gRPC/WebSocket transaction.
    fn build_http_labels(&self, summary: &TransactionSummary) -> BTreeMap<String, String> {
        let mut labels = self.label_config.static_labels.clone();
        if self.label_config.include_proxy_id
            && let Some(ref proxy_id) = summary.proxy_id
        {
            labels.insert("proxy_id".to_string(), proxy_id.clone());
        }
        if self.label_config.include_status_class {
            labels.insert(
                "status_class".to_string(),
                status_class(summary.response_status_code),
            );
        }
        labels
    }

    /// Build labels for a TCP/UDP stream transaction.
    fn build_stream_labels(&self, summary: &StreamTransactionSummary) -> BTreeMap<String, String> {
        let mut labels = self.label_config.static_labels.clone();
        if self.label_config.include_proxy_id {
            labels.insert("proxy_id".to_string(), summary.proxy_id.clone());
        }
        labels.insert("protocol".to_string(), summary.protocol.clone());
        labels
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
                .ok_or_else(|| format!("loki_logging: '{key}' must be a string"))?
                .trim();
            if value.is_empty() {
                return Err(format!("loki_logging: '{key}' must not be empty"));
            }
            Ok(Some(value.to_string()))
        }
        None => Ok(None),
    }
}

fn is_valid_loki_label_name(name: &str) -> bool {
    let mut chars = name.chars();
    match chars.next() {
        Some(first) if first == '_' || first.is_ascii_alphabetic() => {}
        _ => return false,
    }
    chars.all(|ch| ch == '_' || ch.is_ascii_alphanumeric())
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

/// Parse an RFC3339 timestamp string into a nanosecond epoch string for Loki.
/// Falls back to the current time if parsing fails.
fn timestamp_nanos_from_rfc3339(ts: &str) -> String {
    use chrono::DateTime;
    match DateTime::parse_from_rfc3339(ts) {
        Ok(dt) => {
            let secs = dt.timestamp();
            let nanos = dt.timestamp_subsec_nanos();
            format!("{}{:09}", secs, nanos)
        }
        Err(_) => {
            let now = chrono::Utc::now();
            format!("{}{:09}", now.timestamp(), now.timestamp_subsec_nanos())
        }
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

    async fn on_stream_disconnect(&self, summary: &StreamTransactionSummary) {
        let labels = self.build_stream_labels(summary);
        let ts = &summary.timestamp_disconnected;
        match self.schema.as_ref().filter(|s| s.applies_to_stream()) {
            Some(schema) => self.queue_entry(
                &SchemaView { summary, schema },
                labels,
                ts,
                "stream summary",
            ),
            None => self.queue_entry(summary, labels, ts, "stream summary"),
        }
    }

    async fn log(&self, summary: &TransactionSummary) {
        let labels = self.build_http_labels(summary);
        let ts = &summary.timestamp_received;
        match self.schema.as_ref().filter(|s| s.applies_to_http()) {
            Some(schema) => self.queue_entry(
                &SchemaView { summary, schema },
                labels,
                ts,
                "transaction summary",
            ),
            None => self.queue_entry(summary, labels, ts, "transaction summary"),
        }
    }

    fn warmup_hostnames(&self) -> Vec<String> {
        vec![self.endpoint_hostname.clone()]
    }
}

/// Group entries by label set and build the Loki push payload.
fn build_loki_payload(batch: &[LokiEntry]) -> Value {
    let mut streams: HashMap<BTreeMap<String, String>, Vec<(String, String)>> = HashMap::new();

    for entry in batch {
        let stream = streams.entry(entry.labels.clone()).or_default();
        stream.push((entry.timestamp_ns.clone(), entry.line.clone()));
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

    serde_json::json!({ "streams": streams_array })
}

/// Send a batch of entries to Loki.
async fn send_batch(cfg: &LokiFlushConfig, batch: Vec<LokiEntry>) -> Result<(), String> {
    let entry_count = batch.len();
    let (body_bytes, content_encoding) = build_loki_body(cfg, &batch);
    let attempts = cfg.retry.max_attempts.max(1);

    for attempt in 1..=attempts {
        match send_batch_once(cfg, entry_count, body_bytes.clone(), content_encoding).await {
            Ok(()) => return Ok(()),
            Err(error) if attempt < attempts => {
                warn!(
                    plugin = "loki_logging",
                    "Loki logging: batch flush failed (attempt {}/{}): {}",
                    attempt,
                    attempts,
                    error,
                );
                tokio::time::sleep(cfg.retry.delay).await;
            }
            Err(error) => {
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

fn build_loki_body(cfg: &LokiFlushConfig, batch: &[LokiEntry]) -> (Bytes, Option<&'static str>) {
    let payload = build_loki_payload(batch);

    if cfg.gzip {
        match gzip_json(&payload) {
            Ok(compressed) => (Bytes::from(compressed), Some("gzip")),
            Err(error) => {
                warn!("Loki logging: gzip compression failed, sending uncompressed: {error}");
                (Bytes::from(json_payload_bytes(&payload)), None)
            }
        }
    } else {
        (Bytes::from(json_payload_bytes(&payload)), None)
    }
}

fn json_payload_bytes(payload: &Value) -> Vec<u8> {
    match serde_json::to_vec(payload) {
        Ok(raw) => raw,
        Err(error) => {
            warn!("Loki logging: failed to serialize payload: {error}");
            Vec::new()
        }
    }
}

async fn send_batch_once(
    cfg: &LokiFlushConfig,
    entry_count: usize,
    body_bytes: Bytes,
    content_encoding: Option<&'static str>,
) -> Result<(), String> {
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

    handle_http_batch_response(
        "Loki logging",
        entry_count,
        cfg.http_client.execute(req, "loki_logging").await,
    )
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

    // `LokiLogging::new` spawns a `BatchingLogger` flush task via
    // `tokio::spawn`, which panics under plain `#[test]` because no Tokio
    // reactor is running. The test bodies themselves are synchronous (no
    // awaits) but need to execute inside a tokio runtime so `tokio::spawn`
    // can register the flush task — `#[tokio::test]` provides that runtime.
    #[tokio::test]
    async fn label_include_proxy_id_key_controls_proxy_id_label() {
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

    #[tokio::test]
    async fn removed_listen_path_key_is_rejected() {
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
    }

    #[test]
    fn build_loki_payload_groups_entries_by_label_set() {
        let mut labels_a = BTreeMap::new();
        labels_a.insert("service".to_string(), "ferrum-edge".to_string());
        labels_a.insert("proxy_id".to_string(), "p-1".to_string());

        let mut labels_b = BTreeMap::new();
        labels_b.insert("service".to_string(), "ferrum-edge".to_string());
        labels_b.insert("proxy_id".to_string(), "p-2".to_string());

        let payload = build_loki_payload(&[
            LokiEntry {
                labels: labels_a.clone(),
                timestamp_ns: "1000".to_string(),
                line: r#"{"a":1}"#.to_string(),
            },
            LokiEntry {
                labels: labels_a,
                timestamp_ns: "1001".to_string(),
                line: r#"{"a":2}"#.to_string(),
            },
            LokiEntry {
                labels: labels_b,
                timestamp_ns: "2000".to_string(),
                line: r#"{"b":1}"#.to_string(),
            },
        ]);

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
