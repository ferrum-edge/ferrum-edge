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
use serde_json::Value;
use std::collections::BTreeMap;
use std::collections::HashMap;
use std::time::Duration;
use tracing::warn;

use super::utils::{
    BatchConfig, BatchConfigDefaults, BatchingLogger, PluginHttpClient, RetryPolicy,
    build_batch_config, handle_http_batch_response, parse_http_endpoint,
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
    authorization_header: Option<String>,
    custom_headers: Vec<(String, String)>,
    http_client: PluginHttpClient,
    gzip: bool,
    retry: RetryPolicy,
}

/// Static labels applied to every log entry, from plugin config.
#[derive(Clone)]
struct LabelConfig {
    /// Static labels merged into every entry (e.g., service, env).
    static_labels: BTreeMap<String, String>,
    /// Whether to add `proxy_id` as a label (default true). Controlled by
    /// `include_proxy_id_label` (preferred) or the legacy
    /// `include_listen_path_label` name for backward compatibility.
    include_proxy_id: bool,
    /// Whether to add status class (2xx/3xx/4xx/5xx) as a label (default true).
    include_status_class: bool,
}

pub struct LokiLogging {
    logger: BatchingLogger<LokiEntry>,
    endpoint_hostname: String,
    label_config: LabelConfig,
}

impl LokiLogging {
    pub fn new(config: &Value, http_client: PluginHttpClient) -> Result<Self, String> {
        let (endpoint_url, endpoint_hostname) = parse_http_endpoint(config, "loki_logging")?;
        let gzip = config["gzip"].as_bool().unwrap_or(true);

        // Parse static labels from config.
        let mut static_labels = BTreeMap::new();
        if let Some(labels_obj) = config["labels"].as_object() {
            for (key, value) in labels_obj {
                if let Some(label) = value.as_str() {
                    static_labels.insert(key.clone(), label.to_string());
                }
            }
        }
        if !static_labels.contains_key("service") {
            static_labels.insert("service".to_string(), "ferrum-edge".to_string());
        }

        let include_proxy_id = config["include_proxy_id_label"]
            .as_bool()
            .or_else(|| config["include_listen_path_label"].as_bool())
            .unwrap_or(true);
        let include_status_class = config["include_status_class_label"]
            .as_bool()
            .unwrap_or(true);

        let label_config = LabelConfig {
            static_labels,
            include_proxy_id,
            include_status_class,
        };

        let mut custom_headers = Vec::new();
        if let Some(headers_obj) = config["custom_headers"].as_object() {
            for (key, value) in headers_obj {
                if let Some(header) = value.as_str() {
                    custom_headers.push((key.clone(), header.to_string()));
                }
            }
        }

        // Config remains `max_retries`; the shared retry policy counts the
        // initial attempt plus those retries.
        let batch_config = build_batch_config(
            config,
            "loki_logging",
            BatchConfigDefaults {
                batch_size_key: "batch_size",
                batch_size: 100,
                flush_interval_ms: 1000,
                min_flush_interval_ms: 100,
                buffer_capacity: 10000,
                max_retries: 3,
                retry_delay_ms: 1000,
            },
        );
        let flush_config = LokiFlushConfig {
            endpoint_url,
            authorization_header: config["authorization_header"]
                .as_str()
                .map(|value| value.to_string()),
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

        Ok(Self {
            logger,
            endpoint_hostname,
            label_config,
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
            && let Some(ref proxy_id) = summary.matched_proxy_id
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
        self.queue_entry(
            summary,
            self.build_stream_labels(summary),
            &summary.timestamp_disconnected,
            "stream summary",
        );
    }

    async fn log(&self, summary: &TransactionSummary) {
        self.queue_entry(
            summary,
            self.build_http_labels(summary),
            &summary.timestamp_received,
            "transaction summary",
        );
    }

    fn warmup_hostnames(&self) -> Vec<String> {
        vec![self.endpoint_hostname.clone()]
    }
}

/// Labels + accumulated (timestamp, log-line) pairs for a single Loki stream.
type LokiStream = (BTreeMap<String, String>, Vec<(String, String)>);

/// Group entries by label set and build the Loki push payload.
fn build_loki_payload(batch: &[LokiEntry]) -> Value {
    let mut streams: HashMap<String, LokiStream> = HashMap::new();

    for entry in batch {
        let key = serde_json::to_string(&entry.labels).unwrap_or_default();
        let stream = streams
            .entry(key)
            .or_insert_with(|| (entry.labels.clone(), Vec::new()));
        stream
            .1
            .push((entry.timestamp_ns.clone(), entry.line.clone()));
    }

    let streams_array: Vec<Value> = streams
        .into_values()
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
                let raw = serde_json::to_vec(&payload).unwrap_or_default();
                (Bytes::from(raw), None)
            }
        }
    } else {
        let raw = serde_json::to_vec(&payload).unwrap_or_default();
        (Bytes::from(raw), None)
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
        req = req.header("Authorization", auth);
    }
    for (key, value) in &cfg.custom_headers {
        req = req.header(key.as_str(), value.as_str());
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

    fn make_summary(status: u16, proxy_id: Option<&str>) -> TransactionSummary {
        TransactionSummary {
            namespace: "ferrum".to_string(),
            timestamp_received: "2026-04-01T00:00:00Z".to_string(),
            client_ip: "10.0.0.1".to_string(),
            http_method: "GET".to_string(),
            request_path: "/t".to_string(),
            matched_proxy_id: proxy_id.map(str::to_owned),
            response_status_code: status,
            latency_total_ms: 1.0,
            latency_gateway_processing_ms: 1.0,
            ..TransactionSummary::default()
        }
    }

    #[test]
    fn label_legacy_key_controls_proxy_id_label() {
        // Backward compat: `include_listen_path_label` (old name) must still
        // suppress the `proxy_id` label when callers explicitly set it false.
        let plugin = LokiLogging::new(
            &json!({
                "endpoint_url": "http://127.0.0.1:1/loki/api/v1/push",
                "include_listen_path_label": false,
                "include_status_class_label": false,
            }),
            client(),
        )
        .unwrap();
        let summary = make_summary(200, Some("p-1"));
        let labels = plugin.build_http_labels(&summary);
        assert!(!labels.contains_key("proxy_id"));
        assert!(!labels.contains_key("status_class"));
    }

    #[test]
    fn label_new_key_takes_precedence_over_legacy() {
        // When both keys are set with opposing values, the new
        // `include_proxy_id_label` wins.
        let plugin = LokiLogging::new(
            &json!({
                "endpoint_url": "http://127.0.0.1:1/loki/api/v1/push",
                "include_proxy_id_label": true,
                "include_listen_path_label": false,
            }),
            client(),
        )
        .unwrap();
        let summary = make_summary(500, Some("p-2"));
        let labels = plugin.build_http_labels(&summary);
        assert_eq!(labels.get("proxy_id").map(String::as_str), Some("p-2"));
    }

    #[test]
    fn label_default_includes_proxy_id() {
        let plugin = LokiLogging::new(
            &json!({ "endpoint_url": "http://127.0.0.1:1/loki/api/v1/push" }),
            client(),
        )
        .unwrap();
        let summary = make_summary(200, Some("p-3"));
        let labels = plugin.build_http_labels(&summary);
        assert_eq!(labels.get("proxy_id").map(String::as_str), Some("p-3"));
        assert_eq!(labels.get("status_class").map(String::as_str), Some("2xx"));
    }
}
