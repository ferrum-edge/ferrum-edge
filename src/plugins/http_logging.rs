//! HTTP access logging plugin — batched async log shipping.
//!
//! Serializes `TransactionSummary` entries and sends them to a remote HTTP
//! endpoint in batches. Uses an mpsc channel to decouple the proxy hot path
//! from network I/O: the `log()` hook enqueues the entry (non-blocking), and
//! a background task drains the channel in configurable batch sizes with a
//! flush interval timer. Failed batches are retried with configurable delay.
//!
//! Supports both HTTP and stream (TCP/UDP) transaction summaries via the
//! `LogEntry` union type, and uses the shared `PluginHttpClient` for
//! connection pooling and DNS cache integration.

use async_trait::async_trait;
use http::header::{HeaderName, HeaderValue};
use serde_json::Value;
use tokio::sync::mpsc;
use tokio::time::Duration;
use tracing::warn;
use url::Url;

use super::utils::PluginHttpClient;
use super::{Plugin, StreamTransactionSummary, TransactionSummary};

/// Union type for log entries sent through the batched channel.
#[derive(Clone, serde::Serialize)]
#[serde(untagged)]
enum LogEntry {
    Http(TransactionSummary),
    Stream(StreamTransactionSummary),
}

struct BatchConfig {
    endpoint_url: String,
    custom_headers: Vec<(HeaderName, HeaderValue)>,
    http_client: PluginHttpClient,
    batch_size: usize,
    flush_interval: Duration,
    max_retries: u32,
    retry_delay: Duration,
}

pub struct HttpLogging {
    sender: mpsc::Sender<LogEntry>,
    endpoint_hostname: Option<String>,
}

impl HttpLogging {
    pub fn new(config: &Value, http_client: PluginHttpClient) -> Result<Self, String> {
        let endpoint_url = config["endpoint_url"]
            .as_str()
            .filter(|s| !s.is_empty())
            .ok_or_else(|| {
                "http_logging: 'endpoint_url' is required — logs will have nowhere to send"
                    .to_string()
            })?
            .to_string();
        let parsed_url = Url::parse(&endpoint_url)
            .map_err(|e| format!("http_logging: invalid 'endpoint_url': {e}"))?;
        match parsed_url.scheme() {
            "http" | "https" => {}
            scheme => {
                return Err(format!(
                    "http_logging: 'endpoint_url' must use http:// or https:// (got '{scheme}')"
                ));
            }
        }
        if parsed_url.host_str().is_none() {
            return Err(
                "http_logging: 'endpoint_url' must include a hostname or IP address".to_string(),
            );
        }

        let batch_size = config["batch_size"].as_u64().unwrap_or(50).max(1) as usize;
        let flush_interval_ms = config["flush_interval_ms"]
            .as_u64()
            .unwrap_or(1000)
            .max(100);
        let buffer_capacity = config["buffer_capacity"].as_u64().unwrap_or(10000).max(1) as usize;

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
                // Deduplicate case-insensitively — last value wins.
                custom_headers.retain(|(k, _)| *k != header_name);
                custom_headers.push((header_name, header_value));
            }
        }

        let batch_config = BatchConfig {
            endpoint_url,
            custom_headers,
            http_client,
            batch_size,
            flush_interval: Duration::from_millis(flush_interval_ms),
            max_retries: config["max_retries"].as_u64().unwrap_or(3) as u32,
            retry_delay: Duration::from_millis(config["retry_delay_ms"].as_u64().unwrap_or(1000)),
        };

        let endpoint_hostname = parsed_url.host_str().map(|h| h.to_string());

        let (sender, receiver) = mpsc::channel(buffer_capacity);
        tokio::spawn(flush_loop(receiver, batch_config));

        Ok(Self {
            sender,
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
        if self
            .sender
            .try_send(LogEntry::Stream(summary.clone()))
            .is_err()
        {
            warn!("HTTP logging buffer full — dropping stream log entry");
        }
    }

    async fn log(&self, summary: &TransactionSummary) {
        if self
            .sender
            .try_send(LogEntry::Http(summary.clone()))
            .is_err()
        {
            warn!("HTTP logging buffer full — dropping log entry");
        }
    }

    fn warmup_hostnames(&self) -> Vec<String> {
        self.endpoint_hostname
            .as_ref()
            .map(|h| vec![h.clone()])
            .unwrap_or_default()
    }
}

async fn flush_loop(mut receiver: mpsc::Receiver<LogEntry>, cfg: BatchConfig) {
    if cfg.endpoint_url.is_empty() {
        // Drain the channel without sending anything.
        while receiver.recv().await.is_some() {}
        return;
    }

    let mut buffer: Vec<LogEntry> = Vec::with_capacity(cfg.batch_size);
    let mut timer = tokio::time::interval(cfg.flush_interval);
    // The first tick completes immediately — consume it so the first real
    // flush waits for one full interval.
    timer.tick().await;

    loop {
        tokio::select! {
            biased;

            msg = receiver.recv() => {
                match msg {
                    Some(summary) => {
                        buffer.push(summary);
                        if buffer.len() >= cfg.batch_size {
                            let batch = std::mem::take(&mut buffer);
                            send_batch(&cfg, batch).await;
                        }
                    }
                    None => {
                        // Channel closed — flush remaining entries and exit.
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

async fn send_batch(cfg: &BatchConfig, batch: Vec<LogEntry>) {
    let total_attempts = cfg.max_retries + 1;
    let entry_count = batch.len();

    for attempt in 1..=total_attempts {
        let mut req = cfg.http_client.get().post(&cfg.endpoint_url).json(&batch);
        for (name, value) in &cfg.custom_headers {
            req = req.header(name.clone(), value.clone());
        }
        match cfg.http_client.execute(req, "http_logging").await {
            Ok(response) if response.status().is_success() => return,
            Ok(response) => {
                let status = response.status();
                warn!(
                    "HTTP logging batch failed with status {} (attempt {}/{})",
                    status, attempt, total_attempts,
                );
                // 4xx is a client error — retrying a malformed/unauthorized
                // payload just delays the drop. Bail immediately, except for
                // 408 (Request Timeout) and 429 (Too Many Requests) which are
                // transient and worth retrying within the configured budget.
                if status.is_client_error()
                    && status != reqwest::StatusCode::REQUEST_TIMEOUT
                    && status != reqwest::StatusCode::TOO_MANY_REQUESTS
                {
                    warn!(
                        "HTTP logging batch discarded due to {} response ({} entries lost)",
                        status, entry_count,
                    );
                    return;
                }
            }
            Err(e) => {
                warn!(
                    "HTTP logging batch failed: {} (attempt {}/{})",
                    e, attempt, total_attempts,
                );
            }
        }
        if attempt < total_attempts {
            tokio::time::sleep(cfg.retry_delay).await;
        }
    }

    warn!(
        "HTTP logging batch discarded after {} attempts ({} entries lost)",
        total_attempts, entry_count,
    );
    // `batch` is dropped here, freeing memory.
}
