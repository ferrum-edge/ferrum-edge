//! HTTP access logging plugin — batched async log shipping.
//!
//! Serializes `TransactionSummary` entries and sends them to a remote HTTP
//! endpoint in batches. Uses `BatchingLogger<LogEntry>` to decouple the proxy
//! hot path from network I/O: the `log()` hook enqueues the entry
//! non-blockingly, and a shared background task drains the queue in
//! configurable batch sizes with a flush interval timer.
//!
//! Construction is runtime-free. The flush worker is staged from
//! [`Plugin::start_background_tasks`] and released from
//! [`Plugin::commit_background_tasks`] after the plugin-cache generation that
//! owns this instance is atomically installed.
//!
//! Supports both HTTP and stream (TCP/UDP) transaction summaries via the
//! `LogEntry` union type, and uses the shared `PluginHttpClient` for
//! connection pooling and DNS cache integration.

use std::sync::Arc;

use async_trait::async_trait;
use http::header::{HeaderName, HeaderValue};
use serde_json::Value;

use super::utils::log_schema::{
    SchemaCapabilities, SummaryLogEntryBatchView, SummarySchema, resolve_schema,
};
use super::utils::{
    BatchConfig, BatchConfigDefaults, DeferredBatchingLogger, PluginHttpClient, SummaryLogEntry,
    build_batch_config, handle_http_batch_response, parse_custom_headers, parse_http_endpoint,
    validate_batch_config,
};
use super::{Plugin, StreamTransactionSummary, TransactionSummary};

#[derive(Clone)]
struct HttpFlushConfig {
    endpoint_url: String,
    custom_headers: Vec<(HeaderName, HeaderValue)>,
    http_client: PluginHttpClient,
    schema: Option<Arc<SummarySchema>>,
}

pub struct HttpLogging {
    batch_config: BatchConfig,
    flush_config: HttpFlushConfig,
    logger: DeferredBatchingLogger<SummaryLogEntry>,
    endpoint_hostname: String,
}

impl HttpLogging {
    pub fn new(config: &Value, http_client: PluginHttpClient) -> Result<Self, String> {
        if !config.is_object() {
            return Err("http_logging: config must be an object".to_string());
        }

        let (endpoint_url, endpoint_hostname) =
            parse_http_endpoint(config, "http_logging", http_client.backend_allow_ips())?;

        let custom_headers = parse_custom_headers(config, "http_logging")?;

        let batch_defaults = BatchConfigDefaults {
            batch_size_key: "batch_size",
            batch_size: 50,
            flush_interval_ms: 1000,
            min_flush_interval_ms: 100,
            buffer_capacity: 10000,
            max_retries: 3,
            retry_delay_ms: 1000,
        };
        validate_batch_config(config, "http_logging", batch_defaults)?;

        let schema = resolve_schema(config, "http_logging", SchemaCapabilities::BASE)?;
        let flush_config = HttpFlushConfig {
            endpoint_url,
            custom_headers,
            http_client,
            schema,
        };

        Ok(Self {
            batch_config: build_batch_config(config, "http_logging", batch_defaults),
            flush_config,
            logger: DeferredBatchingLogger::new(),
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

    fn start_background_tasks(&self) -> Result<(), String> {
        let flush_config = self.flush_config.clone();
        // Config remains `max_retries`; the shared retry policy counts the
        // initial attempt plus those retries.
        self.logger
            .start("http_logging", self.batch_config, move |batch| {
                let flush_config = flush_config.clone();
                async move { send_batch(&flush_config, batch).await }
            })
    }

    fn commit_background_tasks(&self) {
        self.logger.commit();
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
    let view = SummaryLogEntryBatchView {
        entries: &batch,
        schema: cfg.schema.as_deref(),
    };
    let mut req = cfg.http_client.get().post(&cfg.endpoint_url).json(&view);
    for (name, value) in &cfg.custom_headers {
        req = req.header(name.clone(), value.clone());
    }

    handle_http_batch_response(
        "HTTP logging",
        entry_count,
        cfg.http_client.execute(req, "http_logging").await,
    )
    .await
}
