//! HTTP access logging plugin — batched async log shipping.
//!
//! Serializes `TransactionSummary` entries and sends them to a remote HTTP
//! endpoint in batches. Uses `BatchingLogger<QueuedSummaryPayload>` to decouple
//! the proxy hot path from network I/O: the `log()` hook reserves a queue slot
//! and retained-byte lease before serialization, then enqueues the bounded
//! payload non-blockingly. A shared background task drains the queue in
//! configurable batch sizes with a flush interval timer.
//!
//! Construction is runtime-free. The flush worker is staged from
//! [`Plugin::start_background_tasks`] and released from
//! [`Plugin::commit_background_tasks`] after the plugin-cache generation that
//! owns this instance is atomically installed.
//!
//! Supports both HTTP and stream (TCP/UDP) transaction summaries, and uses the
//! shared `PluginHttpClient` for connection pooling and DNS cache integration.

use std::sync::Arc;

use async_trait::async_trait;
use http::header::{HeaderName, HeaderValue};
use serde_json::Value;

use super::utils::log_schema::{SchemaCapabilities, SummarySchema, resolve_schema};
use super::utils::{
    BatchConfig, BatchConfigDefaults, ByteBudget, DeferredBatchingLogger, PluginHttpClient,
    QueuedSummaryPayload, admit_byte_limits, admit_http_summary, admit_stream_summary,
    assemble_json_array, build_batch_config, handle_http_batch_response_redacted,
    parse_custom_headers, parse_http_endpoint, redacted_endpoint_url_str, validate_batch_config,
};
use super::{Plugin, StreamTransactionSummary, TransactionSummary};

#[derive(Clone)]
struct HttpFlushConfig {
    /// Complete configured URL. Used **only** to build the outbound request —
    /// vendor integrations such as Sumo Logic (path token) and Mezmo (`apikey`
    /// query parameter) legitimately carry a reusable credential here.
    endpoint_url: String,
    /// Structurally redacted rendering of [`Self::endpoint_url`] for every
    /// diagnostic surface: egress denial, DNS/TLS/connect failure, retry,
    /// slow-call, and batch-failure error strings.
    endpoint_url_for_logs: String,
    custom_headers: Vec<(HeaderName, HeaderValue)>,
    http_client: PluginHttpClient,
}

pub struct HttpLogging {
    batch_config: BatchConfig,
    flush_config: HttpFlushConfig,
    logger: DeferredBatchingLogger<QueuedSummaryPayload>,
    endpoint_hostname: String,
    schema: Option<Arc<SummarySchema>>,
    byte_budget: Arc<ByteBudget>,
    max_entry_bytes: usize,
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
            min_retry_delay_ms: 0,
        };
        validate_batch_config(config, "http_logging", batch_defaults)?;
        let limits = admit_byte_limits(config, "http_logging")?;

        let schema = resolve_schema(config, "http_logging", SchemaCapabilities::BASE)?;
        let flush_config = HttpFlushConfig {
            endpoint_url_for_logs: redacted_endpoint_url_str(&endpoint_url),
            endpoint_url,
            custom_headers,
            http_client,
        };

        Ok(Self {
            batch_config: build_batch_config(config, "http_logging", batch_defaults)?,
            flush_config,
            logger: DeferredBatchingLogger::new(),
            endpoint_hostname,
            schema,
            byte_budget: Arc::new(ByteBudget::new_observability(
                "http_logging",
                limits.buffer_max_bytes,
            )),
            max_entry_bytes: limits.max_entry_bytes,
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
                async move { send_batch(&flush_config, &batch).await }
            })
    }

    fn commit_background_tasks(&self) {
        self.logger.commit();
    }

    async fn on_stream_disconnect(&self, summary: &StreamTransactionSummary) {
        admit_stream_summary(
            &self.logger,
            &self.byte_budget,
            self.max_entry_bytes,
            summary,
            self.schema.as_deref(),
        );
    }

    async fn log(&self, summary: &TransactionSummary) {
        admit_http_summary(
            &self.logger,
            &self.byte_budget,
            self.max_entry_bytes,
            summary,
            self.schema.as_deref(),
        );
    }

    fn warmup_hostnames(&self) -> Vec<String> {
        vec![self.endpoint_hostname.clone()]
    }
}

async fn send_batch(cfg: &HttpFlushConfig, batch: &[QueuedSummaryPayload]) -> Result<(), String> {
    let entry_count = batch.len();
    let body = assemble_json_array(batch);
    let mut req = cfg
        .http_client
        .get()
        .post(&cfg.endpoint_url)
        .header(http::header::CONTENT_TYPE, "application/json")
        .body(body);
    for (name, value) in &cfg.custom_headers {
        req = req.header(name.clone(), value.clone());
    }

    // `execute_redacted`, not `execute`: the configured endpoint may embed a
    // collector credential in its path or query, and the shared client's
    // egress-denial, retry, and slow-call diagnostics would otherwise record
    // the complete URL. The request itself still goes to `endpoint_url`.
    handle_http_batch_response_redacted(
        "HTTP logging",
        entry_count,
        cfg.http_client
            .execute_redacted(req, "http_logging", &cfg.endpoint_url_for_logs)
            .await,
    )
    .await
}
