//! Loki access logging plugin — batched async log shipping to Grafana Loki.
//!
//! Serializes `TransactionSummary` and `StreamTransactionSummary` entries and
//! sends them to Loki's push API (`/loki/api/v1/push`) in batches. Uses an
//! mpsc channel to decouple the proxy hot path from network I/O: the `log()`
//! hook enqueues the entry (non-blocking), and a background task drains the
//! channel in configurable batch sizes with a flush interval timer.
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
use serde_json::Value;
use std::collections::BTreeMap;
use std::collections::HashMap;
use tokio::sync::mpsc;
use tokio::time::Duration;
use tracing::warn;
use url::Url;

use super::utils::PluginHttpClient;
use super::{Plugin, StreamTransactionSummary, TransactionSummary};

/// A log entry with pre-computed labels and a JSON log line.
struct LokiEntry {
    /// Sorted label key-value pairs (deterministic ordering for grouping).
    labels: BTreeMap<String, String>,
    /// Nanosecond epoch timestamp as a string.
    timestamp_ns: String,
    /// JSON-serialized log line.
    line: String,
}

struct LokiBatchConfig {
    endpoint_url: String,
    authorization_header: Option<String>,
    custom_headers: Vec<(String, String)>,
    http_client: PluginHttpClient,
    batch_size: usize,
    flush_interval: Duration,
    max_retries: u32,
    retry_delay: Duration,
    gzip: bool,
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
    sender: mpsc::Sender<LokiEntry>,
    endpoint_hostname: Option<String>,
    label_config: LabelConfig,
}

impl LokiLogging {
    pub fn new(config: &Value, http_client: PluginHttpClient) -> Result<Self, String> {
        let endpoint_url = config["endpoint_url"]
            .as_str()
            .filter(|s| !s.is_empty())
            .ok_or_else(|| {
                "loki_logging: 'endpoint_url' is required — logs will have nowhere to send"
                    .to_string()
            })?
            .to_string();
        let parsed_url = Url::parse(&endpoint_url)
            .map_err(|e| format!("loki_logging: invalid 'endpoint_url': {e}"))?;
        match parsed_url.scheme() {
            "http" | "https" => {}
            scheme => {
                return Err(format!(
                    "loki_logging: 'endpoint_url' must use http:// or https:// (got '{scheme}')"
                ));
            }
        }
        if parsed_url.host_str().is_none() {
            return Err(
                "loki_logging: 'endpoint_url' must include a hostname or IP address".to_string(),
            );
        }

        let batch_size = config["batch_size"].as_u64().unwrap_or(100).max(1) as usize;
        let flush_interval_ms = config["flush_interval_ms"]
            .as_u64()
            .unwrap_or(1000)
            .max(100);
        let buffer_capacity = config["buffer_capacity"].as_u64().unwrap_or(10000).max(1) as usize;
        let gzip = config["gzip"].as_bool().unwrap_or(true);

        // Parse static labels from config.
        let mut static_labels = BTreeMap::new();
        if let Some(labels_obj) = config["labels"].as_object() {
            for (k, v) in labels_obj {
                if let Some(val) = v.as_str() {
                    static_labels.insert(k.clone(), val.to_string());
                }
            }
        }
        // Default "service" label if not provided.
        if !static_labels.contains_key("service") {
            static_labels.insert("service".to_string(), "ferrum-edge".to_string());
        }

        // Prefer the new `include_proxy_id_label` key; fall back to the legacy
        // `include_listen_path_label` (which also controlled the `proxy_id`
        // label — the old name was misleading) for backward compatibility.
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

        // Parse custom headers (e.g., X-Scope-OrgID for multi-tenant Loki).
        let mut custom_headers = Vec::new();
        if let Some(headers_obj) = config["custom_headers"].as_object() {
            for (k, v) in headers_obj {
                if let Some(val) = v.as_str() {
                    custom_headers.push((k.clone(), val.to_string()));
                }
            }
        }

        let batch_config = LokiBatchConfig {
            endpoint_url,
            authorization_header: config["authorization_header"]
                .as_str()
                .map(|s| s.to_string()),
            custom_headers,
            http_client,
            batch_size,
            flush_interval: Duration::from_millis(flush_interval_ms),
            max_retries: config["max_retries"].as_u64().unwrap_or(3) as u32,
            retry_delay: Duration::from_millis(config["retry_delay_ms"].as_u64().unwrap_or(1000)),
            gzip,
        };

        let endpoint_hostname = parsed_url.host_str().map(|h| h.to_string());

        let (sender, receiver) = mpsc::channel(buffer_capacity);
        tokio::spawn(flush_loop(receiver, batch_config));

        Ok(Self {
            sender,
            endpoint_hostname,
            label_config,
        })
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
        let labels = self.build_stream_labels(summary);
        let line = match serde_json::to_string(summary) {
            Ok(l) => l,
            Err(e) => {
                warn!("Loki logging: failed to serialize stream summary: {e}");
                return;
            }
        };
        let entry = LokiEntry {
            labels,
            timestamp_ns: timestamp_nanos_from_rfc3339(&summary.timestamp_disconnected),
            line,
        };
        if self.sender.try_send(entry).is_err() {
            warn!("Loki logging buffer full — dropping stream log entry");
        }
    }

    async fn log(&self, summary: &TransactionSummary) {
        let labels = self.build_http_labels(summary);
        let line = match serde_json::to_string(summary) {
            Ok(l) => l,
            Err(e) => {
                warn!("Loki logging: failed to serialize transaction summary: {e}");
                return;
            }
        };
        let entry = LokiEntry {
            labels,
            timestamp_ns: timestamp_nanos_from_rfc3339(&summary.timestamp_received),
            line,
        };
        if self.sender.try_send(entry).is_err() {
            warn!("Loki logging buffer full — dropping log entry");
        }
    }

    fn warmup_hostnames(&self) -> Vec<String> {
        self.endpoint_hostname
            .as_ref()
            .map(|h| vec![h.clone()])
            .unwrap_or_default()
    }
}

/// Background task that drains the channel and flushes batches to Loki.
async fn flush_loop(mut receiver: mpsc::Receiver<LokiEntry>, cfg: LokiBatchConfig) {
    if cfg.endpoint_url.is_empty() {
        while receiver.recv().await.is_some() {}
        return;
    }

    let mut buffer: Vec<LokiEntry> = Vec::with_capacity(cfg.batch_size);
    let mut timer = tokio::time::interval(cfg.flush_interval);
    // The first tick completes immediately — consume it so the first real
    // flush waits for one full interval.
    timer.tick().await;

    loop {
        tokio::select! {
            biased;

            msg = receiver.recv() => {
                match msg {
                    Some(entry) => {
                        buffer.push(entry);
                        if buffer.len() >= cfg.batch_size {
                            let batch = std::mem::take(&mut buffer);
                            send_batch(&cfg, batch).await;
                        }
                    }
                    None => {
                        if !buffer.is_empty() {
                            let batch = std::mem::take(&mut buffer);
                            send_batch(&cfg, batch).await;
                        }
                        break;
                    }
                }
            }

            _ = timer.tick() => {
                if !buffer.is_empty() {
                    let batch = std::mem::take(&mut buffer);
                    send_batch(&cfg, batch).await;
                }
            }
        }
    }
}

/// Labels + accumulated (timestamp, log-line) pairs for a single Loki stream.
type LokiStream = (BTreeMap<String, String>, Vec<(String, String)>);

/// Group entries by label set and build the Loki push payload.
fn build_loki_payload(batch: &[LokiEntry]) -> Value {
    // Group by label set. BTreeMap serializes to a deterministic key, so we
    // use its JSON representation as the grouping key.
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
                .map(|(ts, line)| serde_json::json!([ts, line]))
                .collect();
            serde_json::json!({
                "stream": labels,
                "values": values_array,
            })
        })
        .collect();

    serde_json::json!({ "streams": streams_array })
}

/// Send a batch of entries to Loki, with retries.
async fn send_batch(cfg: &LokiBatchConfig, batch: Vec<LokiEntry>) {
    let total_attempts = cfg.max_retries + 1;
    let entry_count = batch.len();

    let payload = build_loki_payload(&batch);

    // Pre-serialize and optionally gzip the body so retries reuse the same bytes.
    let (body_bytes, content_encoding) = if cfg.gzip {
        match gzip_json(&payload) {
            Ok(compressed) => (compressed, Some("gzip")),
            Err(e) => {
                warn!("Loki logging: gzip compression failed, sending uncompressed: {e}");
                let raw = serde_json::to_vec(&payload).unwrap_or_default();
                (raw, None)
            }
        }
    } else {
        let raw = serde_json::to_vec(&payload).unwrap_or_default();
        (raw, None)
    };

    for attempt in 1..=total_attempts {
        let mut req = cfg
            .http_client
            .get()
            .post(&cfg.endpoint_url)
            .header("Content-Type", "application/json")
            .body(body_bytes.clone());

        if let Some(encoding) = content_encoding {
            req = req.header("Content-Encoding", encoding);
        }
        if let Some(auth) = &cfg.authorization_header {
            req = req.header("Authorization", auth);
        }
        for (key, value) in &cfg.custom_headers {
            req = req.header(key.as_str(), value.as_str());
        }

        match cfg.http_client.execute(req, "loki_logging").await {
            Ok(response) if response.status().is_success() => return,
            Ok(response) => {
                let status = response.status();
                warn!(
                    "Loki logging batch failed with status {} (attempt {}/{})",
                    status, attempt, total_attempts,
                );
                // 4xx is a client error (bad payload, auth) — retrying won't
                // fix it. Exceptions: 408 (Request Timeout) and 429 (Too Many
                // Requests) are transient throttling signals (Loki uses 429
                // for ingestion rate-limits) and should be retried within the
                // configured budget.
                if status.is_client_error()
                    && status != reqwest::StatusCode::REQUEST_TIMEOUT
                    && status != reqwest::StatusCode::TOO_MANY_REQUESTS
                {
                    warn!(
                        "Loki logging batch discarded due to {} response ({} entries lost)",
                        status, entry_count,
                    );
                    return;
                }
            }
            Err(e) => {
                warn!(
                    "Loki logging batch failed: {} (attempt {}/{})",
                    e, attempt, total_attempts,
                );
            }
        }
        if attempt < total_attempts {
            tokio::time::sleep(cfg.retry_delay).await;
        }
    }

    warn!(
        "Loki logging batch discarded after {} attempts ({} entries lost)",
        total_attempts, entry_count,
    );
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
