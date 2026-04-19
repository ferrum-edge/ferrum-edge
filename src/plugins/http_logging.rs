//! HTTP access logging plugin — batched async log shipping.
//!
//! Serializes `TransactionSummary` entries and sends them to a remote HTTP
//! endpoint in batches. Uses `BatchingLogger<LogEntry>` to decouple the proxy
//! hot path from network I/O: the `log()` hook enqueues the entry
//! non-blockingly, and a shared background task drains the queue in
//! configurable batch sizes with a flush interval timer.
//!
//! Supports both HTTP and stream (TCP/UDP) transaction summaries via the
//! `LogEntry` union type, and uses the shared `PluginHttpClient` for
//! connection pooling and DNS cache integration.

use async_trait::async_trait;
use http::header::{HeaderName, HeaderValue};
use serde_json::Value;
use tracing::warn;

use super::utils::{
    BatchConfigDefaults, BatchingLogger, PluginHttpClient, SummaryLogEntry, build_batch_config,
    handle_http_batch_response, parse_http_endpoint,
};
use super::{Plugin, StreamTransactionSummary, TransactionSummary};

#[derive(Clone)]
struct HttpFlushConfig {
    endpoint_url: String,
    custom_headers: Vec<(HeaderName, HeaderValue)>,
    http_client: PluginHttpClient,
}

pub struct HttpLogging {
    logger: BatchingLogger<SummaryLogEntry>,
    endpoint_hostname: String,
}

impl HttpLogging {
    pub fn new(config: &Value, http_client: PluginHttpClient) -> Result<Self, String> {
        let (endpoint_url, endpoint_hostname) = parse_http_endpoint(config, "http_logging")?;

        // Build custom headers list from the `custom_headers` object.
        // Header names are validated and normalized to lowercase per RFC 7230.
        // Duplicate header names (case-insensitive) are deduplicated — last value wins.
        let mut custom_headers: Vec<(HeaderName, HeaderValue)> = Vec::new();
        if let Some(map) = config["custom_headers"].as_object() {
            for (key, value) in map {
                let Some(v) = value.as_str() else {
                    warn!("http_logging: custom_headers['{key}'] has non-string value, skipping");
                    continue;
                };
                let header_name = HeaderName::from_bytes(key.as_bytes()).map_err(|e| {
                    format!("http_logging: invalid custom_headers name '{key}': {e}")
                })?;
                let header_value = HeaderValue::from_str(v).map_err(|e| {
                    format!("http_logging: invalid custom_headers value for '{key}': {e}")
                })?;
                custom_headers.retain(|(existing, _)| *existing != header_name);
                custom_headers.push((header_name, header_value));
            }
        }

        let flush_config = HttpFlushConfig {
            endpoint_url,
            custom_headers,
            http_client,
        };
        let logger = BatchingLogger::spawn(
            // Config remains `max_retries`; the shared retry policy counts the
            // initial attempt plus those retries.
            build_batch_config(
                config,
                "http_logging",
                BatchConfigDefaults {
                    batch_size_key: "batch_size",
                    batch_size: 50,
                    flush_interval_ms: 1000,
                    min_flush_interval_ms: 100,
                    buffer_capacity: 10000,
                    max_retries: 3,
                    retry_delay_ms: 1000,
                },
            ),
            move |batch| {
                let flush_config = flush_config.clone();
                async move { send_batch(&flush_config, batch).await }
            },
        );

        Ok(Self {
            logger,
            endpoint_hostname,
        })
    }
}

#[async_trait]
impl Plugin for HttpLogging {
    fn name(&self) -> &str {
        "http_logging"
    }

    fn priority(&self) -> u16 {
        super::priority::HTTP_LOGGING
    }

    fn supported_protocols(&self) -> &'static [super::ProxyProtocol] {
        super::ALL_PROTOCOLS
    }

    async fn on_stream_disconnect(&self, summary: &StreamTransactionSummary) {
        self.logger.try_send(summary.into());
    }

    async fn log(&self, summary: &TransactionSummary) {
        self.logger.try_send(summary.into());
    }

    fn warmup_hostnames(&self) -> Vec<String> {
        vec![self.endpoint_hostname.clone()]
    }
}

async fn send_batch(cfg: &HttpFlushConfig, batch: Vec<SummaryLogEntry>) -> Result<(), String> {
    let entry_count = batch.len();
    let mut req = cfg.http_client.get().post(&cfg.endpoint_url).json(&batch);
    for (name, value) in &cfg.custom_headers {
        req = req.header(name.clone(), value.clone());
    }

    handle_http_batch_response(
        "HTTP logging",
        entry_count,
        cfg.http_client.execute(req, "http_logging").await,
    )
}
