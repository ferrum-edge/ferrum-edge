//! OpenTelemetry Tracing Plugin
//!
//! Provides W3C Trace Context propagation (traceparent/tracestate headers)
//! and exports spans to an OTLP-compatible collector via HTTP/JSON.
//!
//! When no endpoint is configured, the plugin runs in propagation-only mode:
//! it generates/propagates trace context headers without exporting spans.
//!
//! Optionally exports spans to an OTLP-compatible collector via HTTP/JSON
//! (OTLP/HTTP with JSON encoding, per the OpenTelemetry specification).

use async_trait::async_trait;
use http::header::{HeaderName, HeaderValue};
use serde_json::Value;
use std::collections::{BTreeMap, HashMap};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use tokio::runtime::Handle;
use tokio::sync::mpsc;
use tokio::time::Duration;
use tracing::{debug, warn};
use url::{Host, Url};
use uuid::Uuid;

use crate::modes::mesh::config::TracingProvider;

use super::mesh::mesh_trace_attributes;
use super::utils::PluginHttpClient;
use super::{Plugin, PluginResult, RequestContext, StreamTransactionSummary, TransactionSummary};

const TRACEPARENT_HEADER: &str = "traceparent";
const TRACESTATE_HEADER: &str = "tracestate";

pub struct OtelTracing {
    /// Service name for spans.
    service_name: String,
    /// Whether to generate trace IDs for requests without traceparent.
    generate_trace_id: bool,
    /// OTLP span exporter (if endpoint is configured).
    exporter: Option<Arc<dyn TraceExporter>>,
}

/// OTLP-flavoured span kind. Mirrored to Zipkin / Datadog payloads with each
/// provider's preferred string form (`SERVER` / `CLIENT` for Zipkin v2,
/// lowercase under `meta["span.kind"]` for Datadog). OTLP itself emits the
/// raw enum integer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum SpanKind {
    /// OTLP enum value 2.
    Server,
    /// OTLP enum value 3.
    Client,
}

impl SpanKind {
    /// OTLP enum encoding (`opentelemetry.proto.trace.v1.Span.SpanKind`).
    pub(crate) fn otlp_code(self) -> u8 {
        match self {
            Self::Server => 2,
            Self::Client => 3,
        }
    }

    /// Zipkin v2 wire form (`"SERVER"` / `"CLIENT"`).
    pub(crate) fn zipkin_str(self) -> &'static str {
        match self {
            Self::Server => "SERVER",
            Self::Client => "CLIENT",
        }
    }

    /// Datadog `meta["span.kind"]` form (`"server"` / `"client"`).
    pub(crate) fn datadog_str(self) -> &'static str {
        match self {
            Self::Server => "server",
            Self::Client => "client",
        }
    }
}

/// Internal span data collected during the request lifecycle.
#[derive(Clone)]
pub(crate) struct SpanData {
    pub(crate) trace_id: String,
    pub(crate) span_id: String,
    pub(crate) parent_span_id: String,
    pub(crate) service_name: String,
    pub(crate) span_name: String,
    pub(crate) span_kind: u8,
    /// Typed span kind used to render provider-specific encodings. Kept
    /// alongside the legacy `span_kind` integer so call sites that haven't
    /// migrated still produce SERVER spans.
    pub(crate) span_kind_typed: SpanKind,
    pub(crate) http_method: String,
    pub(crate) http_url: String,
    pub(crate) http_status_code: Option<u16>,
    pub(crate) client_ip: String,
    pub(crate) duration_ms: f64,
    pub(crate) gateway_processing_ms: f64,
    pub(crate) backend_ttfb_ms: f64,
    pub(crate) backend_ms: f64,
    pub(crate) plugin_execution_ms: f64,
    pub(crate) gateway_overhead_ms: f64,
    pub(crate) consumer: Option<String>,
    pub(crate) timestamp_received: String,
    // Rich attributes from TransactionSummary
    pub(crate) user_agent: Option<String>,
    pub(crate) proxy_id: Option<String>,
    pub(crate) matched_route: Option<String>,
    pub(crate) backend_target: Option<String>,
    pub(crate) backend_resolved_ip: Option<String>,
    pub(crate) error_class: Option<String>,
    pub(crate) response_streamed: bool,
    pub(crate) client_disconnected: bool,
    pub(crate) mesh_attributes: Vec<(String, String)>,
    pub(crate) stream_protocol: Option<String>,
    pub(crate) stream_listen_port: Option<u16>,
    pub(crate) stream_bytes_sent: Option<u64>,
    pub(crate) stream_bytes_received: Option<u64>,
}

/// Queue-backed span exporter used by tracing plugins.
pub(crate) trait TraceExporter: Send + Sync {
    fn provider_name(&self) -> &'static str;
    fn hostname(&self) -> Option<&str>;
    fn try_export(&self, span: SpanData) -> Result<(), String>;
}

pub(crate) struct GeneratedTraceContext {
    pub(crate) trace_id: String,
    pub(crate) span_id: String,
    pub(crate) traceparent: String,
}

pub(crate) struct ParsedTraceParent<'a> {
    pub(crate) version: &'a str,
    pub(crate) trace_id: &'a str,
    pub(crate) parent_span_id: &'a str,
    pub(crate) flags: &'a str,
}

impl SpanData {
    pub(crate) fn from_transaction_summary(
        summary: &TransactionSummary,
        service_name: &str,
    ) -> Option<Self> {
        Self::from_transaction_summary_with_kind(summary, service_name, SpanKind::Server)
    }

    pub(crate) fn from_transaction_summary_with_kind(
        summary: &TransactionSummary,
        service_name: &str,
        kind: SpanKind,
    ) -> Option<Self> {
        let trace_id = summary.metadata.get("trace_id")?.clone();
        let span_id = summary.metadata.get("span_id")?.clone();
        let parent_span_id = summary
            .metadata
            .get("parent_span_id")
            .cloned()
            .unwrap_or_default();
        Some(Self {
            trace_id,
            span_id,
            parent_span_id,
            service_name: service_name.to_string(),
            span_name: format!("{} {}", summary.http_method, summary.request_path),
            span_kind: kind.otlp_code(),
            span_kind_typed: kind,
            http_method: summary.http_method.clone(),
            http_url: summary.request_path.clone(),
            http_status_code: Some(summary.response_status_code),
            client_ip: summary.client_ip.clone(),
            duration_ms: summary.latency_total_ms,
            gateway_processing_ms: summary.latency_gateway_processing_ms,
            backend_ttfb_ms: summary.latency_backend_ttfb_ms,
            backend_ms: summary.latency_backend_total_ms,
            plugin_execution_ms: summary.latency_plugin_execution_ms,
            gateway_overhead_ms: summary.latency_gateway_overhead_ms,
            consumer: summary.consumer_username.clone(),
            timestamp_received: summary.timestamp_received.clone(),
            user_agent: summary.request_user_agent.clone(),
            proxy_id: summary.proxy_id.clone(),
            matched_route: summary.proxy_name.clone(),
            backend_target: summary.backend_target.clone(),
            backend_resolved_ip: summary.backend_resolved_ip.clone(),
            error_class: summary.error_class.as_ref().map(|e| format!("{e:?}")),
            response_streamed: summary.response_streamed,
            client_disconnected: summary.client_disconnected,
            mesh_attributes: mesh_trace_attributes(&summary.metadata),
            stream_protocol: None,
            stream_listen_port: None,
            stream_bytes_sent: None,
            stream_bytes_received: None,
        })
    }

    pub(crate) fn from_stream_summary(
        summary: &StreamTransactionSummary,
        service_name: &str,
    ) -> Option<Self> {
        Self::from_stream_summary_with_kind(summary, service_name, SpanKind::Server)
    }

    pub(crate) fn from_stream_summary_with_kind(
        summary: &StreamTransactionSummary,
        service_name: &str,
        kind: SpanKind,
    ) -> Option<Self> {
        let trace_id = summary.metadata.get("trace_id")?.clone();
        let span_id = summary.metadata.get("span_id")?.clone();
        let parent_span_id = summary
            .metadata
            .get("parent_span_id")
            .cloned()
            .unwrap_or_default();
        let span_name = format!("{} {}", summary.protocol, summary.backend_target);
        Some(Self {
            trace_id,
            span_id,
            parent_span_id,
            service_name: service_name.to_string(),
            span_name,
            span_kind: kind.otlp_code(),
            span_kind_typed: kind,
            http_method: summary.protocol.clone(),
            http_url: summary.backend_target.clone(),
            http_status_code: None,
            client_ip: summary.client_ip.clone(),
            duration_ms: summary.duration_ms,
            gateway_processing_ms: 0.0,
            backend_ttfb_ms: 0.0,
            backend_ms: summary.duration_ms,
            plugin_execution_ms: 0.0,
            gateway_overhead_ms: 0.0,
            consumer: summary.consumer_username.clone(),
            timestamp_received: summary.timestamp_connected.clone(),
            user_agent: None,
            proxy_id: Some(summary.proxy_id.clone()),
            matched_route: summary.proxy_name.clone(),
            backend_target: Some(summary.backend_target.clone()),
            backend_resolved_ip: summary.backend_resolved_ip.clone(),
            error_class: summary.error_class.as_ref().map(|e| format!("{e:?}")),
            response_streamed: false,
            client_disconnected: summary.connection_error.is_some(),
            mesh_attributes: mesh_trace_attributes(&summary.metadata),
            stream_protocol: Some(summary.protocol.clone()),
            stream_listen_port: Some(summary.listen_port),
            stream_bytes_sent: Some(summary.bytes_sent),
            stream_bytes_received: Some(summary.bytes_received),
        })
    }
}

impl OtelTracing {
    pub fn new_with_http_client(
        config: &Value,
        http_client: PluginHttpClient,
    ) -> Result<Self, String> {
        let service_name = string_config(config, "service_name", "ferrum-edge")?;
        let generate_trace_id = bool_config(config, "generate_trace_id", true)?;

        let deployment_environment = optional_string_config(config, "deployment_environment")?;

        // Endpoint is optional — when absent, plugin runs in propagation-only mode
        let endpoint = optional_string_config(config, "endpoint")?;

        let exporter = if let Some(endpoint) = endpoint {
            let options =
                TraceExporterOptions::from_config(config, service_name.clone(), http_client)?;
            let authorization = optional_string_config(config, "authorization")?;
            let custom_headers = parse_custom_headers(config.get("headers"))?;
            Some(Arc::new(OtlpTraceExporter::new(
                endpoint,
                authorization,
                custom_headers,
                options.with_deployment_environment(deployment_environment),
            )?) as Arc<dyn TraceExporter>)
        } else {
            None
        };

        Ok(Self {
            service_name,
            generate_trace_id,
            exporter,
        })
    }

    /// Generate a W3C trace context without reparsing the generated header.
    pub(crate) fn generate_trace_context() -> GeneratedTraceContext {
        let trace_id = Self::generate_trace_id();
        let span_id = Self::generate_span_id();
        let traceparent = build_traceparent("00", &trace_id, &span_id, "01");
        GeneratedTraceContext {
            trace_id,
            span_id,
            traceparent,
        }
    }

    /// Parse a traceparent header into (version, trace_id, parent_span_id, flags).
    pub(crate) fn parse_traceparent(value: &str) -> Option<ParsedTraceParent<'_>> {
        let mut parts = value.split('-');
        let version = parts.next()?;
        let trace_id = parts.next()?;
        let parent_span_id = parts.next()?;
        let flags = parts.next()?;
        if parts.next().is_some() {
            return None;
        }

        if version.len() != 2
            || trace_id.len() != 32
            || parent_span_id.len() != 16
            || flags.len() != 2
            || version.eq_ignore_ascii_case("ff")
            || !version.chars().all(|c| c.is_ascii_hexdigit())
            || !trace_id.chars().all(|c| c.is_ascii_hexdigit())
            || !parent_span_id.chars().all(|c| c.is_ascii_hexdigit())
            || !flags.chars().all(|c| c.is_ascii_hexdigit())
            || trace_id.chars().all(|c| c == '0')
            || parent_span_id.chars().all(|c| c == '0')
        {
            return None;
        }

        Some(ParsedTraceParent {
            version,
            trace_id,
            parent_span_id,
            flags,
        })
    }

    /// Generate a new trace ID.
    pub(crate) fn generate_trace_id() -> String {
        hex_encode(Uuid::new_v4().as_bytes())
    }

    /// Generate a new span ID for the gateway hop.
    pub(crate) fn generate_span_id() -> String {
        hex_encode(&Uuid::new_v4().as_bytes()[..8])
    }
}

#[async_trait]
impl Plugin for OtelTracing {
    fn name(&self) -> &str {
        "otel_tracing"
    }

    fn priority(&self) -> u16 {
        super::priority::OTEL_TRACING
    }

    fn supported_protocols(&self) -> &'static [super::ProxyProtocol] {
        super::ALL_PROTOCOLS
    }

    fn modifies_request_headers(&self) -> bool {
        true
    }

    async fn on_stream_connect(
        &self,
        ctx: &mut super::StreamConnectionContext,
    ) -> super::PluginResult {
        if self.generate_trace_id {
            let trace_id = Self::generate_trace_id();
            let span_id = Self::generate_span_id();
            ctx.insert_metadata("trace_id".to_string(), trace_id);
            ctx.insert_metadata("span_id".to_string(), span_id);
        }
        super::PluginResult::Continue
    }

    async fn on_stream_disconnect(&self, summary: &StreamTransactionSummary) {
        let trace_id = match summary.metadata.get("trace_id") {
            Some(id) => id,
            None => return,
        };
        let span_id = summary
            .metadata
            .get("span_id")
            .map(|s| s.as_str())
            .unwrap_or("");

        tracing::info!(
            target: "otel",
            service_name = %self.service_name,
            trace_id = %trace_id,
            span_id = %span_id,
            protocol = %summary.protocol,
            proxy_id = %summary.proxy_id,
            client_ip = %summary.client_ip,
            backend_target = %summary.backend_target,
            duration_ms = %summary.duration_ms,
            bytes_sent = %summary.bytes_sent,
            bytes_received = %summary.bytes_received,
            "stream trace"
        );

        if let Some(exporter) = &self.exporter
            && let Some(span_data) = SpanData::from_stream_summary(summary, &self.service_name)
            && let Err(error) = exporter.try_export(span_data)
        {
            warn!(
                "{} export buffer full — dropping span: {}",
                exporter.provider_name(),
                error
            );
        }
    }

    async fn on_request_received(&self, ctx: &mut RequestContext) -> PluginResult {
        // Extract or generate trace context
        let traceparent = if let Some(existing) = ctx.headers.get(TRACEPARENT_HEADER) {
            if let Some(parsed) = Self::parse_traceparent(existing) {
                // Store incoming trace context
                ctx.metadata
                    .insert("trace_id".to_string(), parsed.trace_id.to_string());
                ctx.metadata.insert(
                    "parent_span_id".to_string(),
                    parsed.parent_span_id.to_string(),
                );

                // Generate new span ID for the gateway
                let gateway_span = Self::generate_span_id();
                ctx.metadata
                    .insert("span_id".to_string(), gateway_span.clone());

                build_traceparent(parsed.version, parsed.trace_id, &gateway_span, parsed.flags)
            } else {
                if !self.generate_trace_id {
                    return PluginResult::Continue;
                }

                let generated = Self::generate_trace_context();
                ctx.metadata
                    .insert("trace_id".to_string(), generated.trace_id);
                ctx.metadata
                    .insert("span_id".to_string(), generated.span_id);
                generated.traceparent
            }
        } else if self.generate_trace_id {
            let generated = Self::generate_trace_context();
            ctx.metadata
                .insert("trace_id".to_string(), generated.trace_id);
            ctx.metadata
                .insert("span_id".to_string(), generated.span_id);
            generated.traceparent
        } else {
            return PluginResult::Continue;
        };

        ctx.metadata
            .insert(TRACEPARENT_HEADER.to_string(), traceparent);

        // Preserve tracestate if present
        if let Some(tracestate) = ctx.headers.get(TRACESTATE_HEADER) {
            ctx.metadata
                .insert(TRACESTATE_HEADER.to_string(), tracestate.clone());
        }

        PluginResult::Continue
    }

    async fn before_proxy(
        &self,
        ctx: &mut RequestContext,
        headers: &mut HashMap<String, String>,
    ) -> PluginResult {
        // Inject traceparent into outgoing request
        if let Some(traceparent) = ctx.metadata.get(TRACEPARENT_HEADER) {
            headers.insert(TRACEPARENT_HEADER.to_string(), traceparent.clone());
        }
        if let Some(tracestate) = ctx.metadata.get(TRACESTATE_HEADER) {
            headers.insert(TRACESTATE_HEADER.to_string(), tracestate.clone());
        }
        PluginResult::Continue
    }

    async fn after_proxy(
        &self,
        ctx: &mut RequestContext,
        _response_status: u16,
        response_headers: &mut HashMap<String, String>,
    ) -> PluginResult {
        // Echo traceparent to the client
        if let Some(traceparent) = ctx.metadata.get(TRACEPARENT_HEADER) {
            response_headers.insert(TRACEPARENT_HEADER.to_string(), traceparent.clone());
        }
        PluginResult::Continue
    }

    fn applies_after_proxy_on_reject(&self) -> bool {
        true
    }

    async fn log(&self, summary: &TransactionSummary) {
        let trace_id = match summary.metadata.get("trace_id") {
            Some(id) => id,
            None => return,
        };

        let span_id = summary
            .metadata
            .get("span_id")
            .map(|s| s.as_str())
            .unwrap_or("");
        let parent_span_id = summary
            .metadata
            .get("parent_span_id")
            .map(|s| s.as_str())
            .unwrap_or("");

        // Always emit structured log
        tracing::info!(
            target: "otel",
            service_name = %self.service_name,
            trace_id = %trace_id,
            span_id = %span_id,
            parent_span_id = %parent_span_id,
            http_method = %summary.http_method,
            http_url = %summary.request_path,
            http_status_code = %summary.response_status_code,
            http_client_ip = %summary.client_ip,
            duration_ms = %summary.latency_total_ms,
            backend_ms = %summary.latency_backend_total_ms,
            "request trace"
        );

        // Send to OTLP exporter if configured
        if let Some(exporter) = &self.exporter
            && let Some(span_data) = SpanData::from_transaction_summary(summary, &self.service_name)
            && let Err(error) = exporter.try_export(span_data)
        {
            warn!(
                "{} export buffer full — dropping span: {}",
                exporter.provider_name(),
                error
            );
        }
    }

    fn warmup_hostnames(&self) -> Vec<String> {
        self.exporter
            .as_ref()
            .and_then(|exporter| exporter.hostname().map(ToOwned::to_owned))
            .map(|hostname| vec![hostname])
            .unwrap_or_default()
    }
}

// ─── OTLP HTTP/JSON Exporter ───────────────────────────────────────────

#[derive(Clone)]
pub(crate) struct TraceExporterOptions {
    http_client: PluginHttpClient,
    batch_size: usize,
    flush_interval: Duration,
    buffer_capacity: usize,
    max_retries: u32,
    retry_delay: Duration,
    service_name: String,
    deployment_environment: Option<String>,
}

impl TraceExporterOptions {
    pub(crate) fn from_config(
        config: &Value,
        service_name: String,
        http_client: PluginHttpClient,
    ) -> Result<Self, String> {
        Ok(Self {
            http_client,
            batch_size: usize_config(config, "batch_size", 50, 1)?,
            flush_interval: Duration::from_millis(u64_config(
                config,
                "flush_interval_ms",
                5000,
                100,
            )?),
            buffer_capacity: usize_config(config, "buffer_capacity", 10000, 1)?,
            max_retries: u32_config(config, "max_retries", 2, 0)?,
            retry_delay: Duration::from_millis(u64_config(config, "retry_delay_ms", 1000, 0)?),
            service_name,
            deployment_environment: optional_string_config(config, "deployment_environment")?,
        })
    }

    fn with_deployment_environment(mut self, deployment_environment: Option<String>) -> Self {
        self.deployment_environment = deployment_environment;
        self
    }
}

#[derive(Clone, Copy)]
enum TracePayloadKind {
    Otlp,
    Zipkin,
    Datadog,
}

struct TraceHttpExporterConfig {
    provider_name: &'static str,
    endpoint: String,
    authorization: Option<String>,
    custom_headers: Vec<(String, String)>,
    http_client: PluginHttpClient,
    batch_size: usize,
    flush_interval: Duration,
    max_retries: u32,
    retry_delay: Duration,
    service_name: String,
    deployment_environment: Option<String>,
    payload_kind: TracePayloadKind,
}

struct BufferedTraceExporter {
    provider_name: &'static str,
    hostname: String,
    sender: mpsc::Sender<SpanData>,
    started: AtomicBool,
    // Cold-path only: try_export() reaches this only before the deferred
    // exporter task starts, then the AtomicBool gates all steady-state calls.
    deferred_start: Mutex<Option<(mpsc::Receiver<SpanData>, TraceHttpExporterConfig)>>,
}

impl BufferedTraceExporter {
    fn new(cfg: TraceHttpExporterConfig, buffer_capacity: usize) -> Result<Self, String> {
        let hostname = validate_endpoint_for_provider(cfg.provider_name, &cfg.endpoint)?;
        let (sender, receiver) = mpsc::channel(buffer_capacity);
        let provider_name = cfg.provider_name;
        let (started, deferred_start) = if let Ok(handle) = Handle::try_current() {
            handle.spawn(trace_export_flush_loop(receiver, cfg));
            (true, Mutex::new(None))
        } else {
            (false, Mutex::new(Some((receiver, cfg))))
        };
        Ok(Self {
            provider_name,
            hostname,
            sender,
            started: AtomicBool::new(started),
            deferred_start,
        })
    }

    fn ensure_started(&self) -> Result<(), String> {
        if self.started.load(Ordering::Acquire) {
            return Ok(());
        }
        let mut deferred = self
            .deferred_start
            .lock()
            .map_err(|_| "trace exporter deferred startup lock poisoned".to_string())?;
        if self.started.load(Ordering::Acquire) {
            return Ok(());
        }
        let Some((receiver, cfg)) = deferred.take() else {
            self.started.store(true, Ordering::Release);
            return Ok(());
        };
        match Handle::try_current() {
            Ok(handle) => {
                handle.spawn(trace_export_flush_loop(receiver, cfg));
                self.started.store(true, Ordering::Release);
                Ok(())
            }
            Err(error) => {
                *deferred = Some((receiver, cfg));
                Err(format!(
                    "trace exporter flush task has no Tokio runtime: {error}"
                ))
            }
        }
    }
}

impl TraceExporter for BufferedTraceExporter {
    fn provider_name(&self) -> &'static str {
        self.provider_name
    }

    fn hostname(&self) -> Option<&str> {
        Some(&self.hostname)
    }

    fn try_export(&self, span: SpanData) -> Result<(), String> {
        if !self.started.load(Ordering::Acquire) {
            self.ensure_started()?;
        }
        self.sender.try_send(span).map_err(|e| e.to_string())
    }
}

pub(crate) struct OtlpTraceExporter {
    inner: BufferedTraceExporter,
}

pub(crate) struct ZipkinTraceExporter {
    inner: BufferedTraceExporter,
}

pub(crate) struct DatadogTraceExporter {
    inner: BufferedTraceExporter,
}

pub(crate) struct LightstepTraceExporter {
    inner: BufferedTraceExporter,
}

macro_rules! impl_trace_exporter_delegate {
    ($ty:ty) => {
        impl TraceExporter for $ty {
            fn provider_name(&self) -> &'static str {
                self.inner.provider_name()
            }

            fn hostname(&self) -> Option<&str> {
                self.inner.hostname()
            }

            fn try_export(&self, span: SpanData) -> Result<(), String> {
                self.inner.try_export(span)
            }
        }
    };
}

impl OtlpTraceExporter {
    pub(crate) fn new(
        endpoint: String,
        authorization: Option<String>,
        custom_headers: Vec<(String, String)>,
        options: TraceExporterOptions,
    ) -> Result<Self, String> {
        let cfg = TraceHttpExporterConfig::from_options(
            "OTLP",
            endpoint,
            authorization,
            custom_headers,
            TracePayloadKind::Otlp,
            &options,
        );
        Ok(Self {
            inner: BufferedTraceExporter::new(cfg, options.buffer_capacity)?,
        })
    }
}

impl ZipkinTraceExporter {
    pub(crate) fn new(endpoint: String, options: TraceExporterOptions) -> Result<Self, String> {
        let cfg = TraceHttpExporterConfig::from_options(
            "Zipkin",
            endpoint,
            None,
            Vec::new(),
            TracePayloadKind::Zipkin,
            &options,
        );
        Ok(Self {
            inner: BufferedTraceExporter::new(cfg, options.buffer_capacity)?,
        })
    }
}

impl DatadogTraceExporter {
    pub(crate) fn new(
        agent_url: String,
        service_name: String,
        mut options: TraceExporterOptions,
    ) -> Result<Self, String> {
        options.service_name = service_name;
        let cfg = TraceHttpExporterConfig::from_options(
            "Datadog",
            datadog_traces_endpoint(&agent_url)?,
            None,
            Vec::new(),
            TracePayloadKind::Datadog,
            &options,
        );
        Ok(Self {
            inner: BufferedTraceExporter::new(cfg, options.buffer_capacity)?,
        })
    }
}

impl LightstepTraceExporter {
    pub(crate) fn new(
        collector_url: String,
        access_token: String,
        options: TraceExporterOptions,
    ) -> Result<Self, String> {
        let cfg = TraceHttpExporterConfig::from_options(
            "Lightstep",
            collector_url,
            Some(format!("Bearer {access_token}")),
            Vec::new(),
            TracePayloadKind::Otlp,
            &options,
        );
        Ok(Self {
            inner: BufferedTraceExporter::new(cfg, options.buffer_capacity)?,
        })
    }
}

impl_trace_exporter_delegate!(OtlpTraceExporter);
impl_trace_exporter_delegate!(ZipkinTraceExporter);
impl_trace_exporter_delegate!(DatadogTraceExporter);
impl_trace_exporter_delegate!(LightstepTraceExporter);

impl TraceHttpExporterConfig {
    fn from_options(
        provider_name: &'static str,
        endpoint: String,
        authorization: Option<String>,
        custom_headers: Vec<(String, String)>,
        payload_kind: TracePayloadKind,
        options: &TraceExporterOptions,
    ) -> Self {
        Self {
            provider_name,
            endpoint,
            authorization,
            custom_headers,
            http_client: options.http_client.clone(),
            batch_size: options.batch_size,
            flush_interval: options.flush_interval,
            max_retries: options.max_retries,
            retry_delay: options.retry_delay,
            service_name: options.service_name.clone(),
            deployment_environment: options.deployment_environment.clone(),
            payload_kind,
        }
    }
}

pub(crate) fn trace_exporters_from_providers(
    providers: &[TracingProvider],
    default_service_name: &str,
    config: &Value,
    http_client: PluginHttpClient,
) -> Result<Vec<Arc<dyn TraceExporter>>, String> {
    if providers.is_empty() {
        return Ok(Vec::new());
    }
    let service_name = string_config(config, "service_name", default_service_name)?;
    let options = TraceExporterOptions::from_config(config, service_name.clone(), http_client)?;
    providers
        .iter()
        .map(|provider| match provider {
            TracingProvider::Zipkin { url } => Ok(Arc::new(ZipkinTraceExporter::new(
                url.clone(),
                options.clone(),
            )?) as Arc<dyn TraceExporter>),
            TracingProvider::Datadog { agent_url, service } => {
                let provider_service = service.clone().unwrap_or_else(|| service_name.clone());
                Ok(Arc::new(DatadogTraceExporter::new(
                    agent_url.clone(),
                    provider_service,
                    options.clone(),
                )?) as Arc<dyn TraceExporter>)
            }
            TracingProvider::Lightstep {
                collector_url,
                access_token_env,
            } => {
                let access_token = std::env::var(access_token_env).map_err(|error| {
                    format!(
                        "Lightstep access token env var '{access_token_env}' is not set or unreadable: {error}"
                    )
                })?;
                Ok(Arc::new(LightstepTraceExporter::new(
                    collector_url.clone(),
                    access_token,
                    options.clone(),
                )?) as Arc<dyn TraceExporter>)
            }
            TracingProvider::OpenTelemetry { endpoint } => Ok(Arc::new(OtlpTraceExporter::new(
                endpoint.clone(),
                None,
                Vec::new(),
                options.clone(),
            )?)
                as Arc<dyn TraceExporter>),
        })
        .collect()
}

/// Parse custom headers from the `headers` config field.
/// Accepts an object like `{"x-honeycomb-team": "abc", "X-Scope-OrgID": "123"}`.
fn parse_custom_headers(value: Option<&Value>) -> Result<Vec<(String, String)>, String> {
    let Some(value) = value else {
        return Ok(Vec::new());
    };
    let Value::Object(map) = value else {
        if value.is_null() {
            return Ok(Vec::new());
        }
        return Err("otel_tracing: 'headers' must be an object".to_string());
    };

    let mut headers = Vec::with_capacity(map.len());
    for (key, value) in map {
        if HeaderName::from_bytes(key.as_bytes()).is_err() {
            return Err(format!(
                "otel_tracing: 'headers' contains an invalid HTTP header name: {key:?}"
            ));
        }
        let Some(value) = value.as_str() else {
            return Err(format!(
                "otel_tracing: 'headers.{key}' must be a string value"
            ));
        };
        if HeaderValue::from_str(value).is_err() {
            return Err(format!(
                "otel_tracing: 'headers.{key}' contains characters not permitted in HTTP header values"
            ));
        }
        headers.push((key.clone(), value.to_string()));
    }
    Ok(headers)
}

async fn trace_export_flush_loop(
    mut receiver: mpsc::Receiver<SpanData>,
    cfg: TraceHttpExporterConfig,
) {
    let mut buffer: Vec<SpanData> = Vec::with_capacity(cfg.batch_size);
    let mut timer = tokio::time::interval(cfg.flush_interval);
    timer.tick().await; // skip first immediate tick

    loop {
        tokio::select! {
            biased;

            msg = receiver.recv() => {
                match msg {
                    Some(span) => {
                        buffer.push(span);
                        if buffer.len() >= cfg.batch_size {
                            send_trace_batch(&cfg, &buffer).await;
                            buffer.clear();
                        }
                    }
                    None => {
                        if !buffer.is_empty() {
                            send_trace_batch(&cfg, &buffer).await;
                        }
                        break;
                    }
                }
            }

            _ = timer.tick() => {
                if !buffer.is_empty() {
                    send_trace_batch(&cfg, &buffer).await;
                    buffer.clear();
                }
            }
        }
    }
}

async fn send_trace_batch(cfg: &TraceHttpExporterConfig, batch: &[SpanData]) {
    let total_attempts = cfg.max_retries + 1;
    let entry_count = batch.len();
    let payload = match cfg.payload_kind {
        TracePayloadKind::Otlp => build_otlp_payload(
            &cfg.service_name,
            cfg.deployment_environment.as_deref(),
            batch,
        ),
        TracePayloadKind::Zipkin => build_zipkin_payload(&cfg.service_name, batch),
        TracePayloadKind::Datadog => build_datadog_payload(&cfg.service_name, batch),
    };

    for attempt in 1..=total_attempts {
        let request = match cfg.payload_kind {
            TracePayloadKind::Datadog => cfg.http_client.get().put(&cfg.endpoint),
            _ => cfg.http_client.get().post(&cfg.endpoint),
        };
        let mut req = request
            .header("Content-Type", "application/json")
            .json(&payload);

        if let Some(auth) = &cfg.authorization {
            req = req.header("Authorization", auth);
        }

        for (key, value) in &cfg.custom_headers {
            req = req.header(key.as_str(), value.as_str());
        }

        match cfg.http_client.execute(req, "otel_export").await {
            Ok(response) if response.status().is_success() => return,
            Ok(response) => {
                let status = response.status();
                warn!(
                    "{} export failed with status {} (attempt {}/{})",
                    cfg.provider_name, status, attempt, total_attempts,
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
                        "{} export batch discarded due to {} response ({} spans lost)",
                        cfg.provider_name, status, entry_count,
                    );
                    return;
                }
            }
            Err(e) => {
                warn!(
                    "{} export failed: {} (attempt {}/{})",
                    cfg.provider_name, e, attempt, total_attempts,
                );
            }
        }
        if attempt < total_attempts {
            tokio::time::sleep(cfg.retry_delay).await;
        }
    }

    warn!(
        "{} export batch discarded after {} attempts ({} spans lost)",
        cfg.provider_name, total_attempts, entry_count,
    );
}

/// Build an OTLP/HTTP JSON payload conforming to the OpenTelemetry
/// Trace Export specification.
///
/// Format: ExportTraceServiceRequest with ResourceSpans → ScopeSpans → Spans.
/// See: https://opentelemetry.io/docs/specs/otlp/#otlphttp-request
fn build_otlp_payload(
    service_name: &str,
    deployment_environment: Option<&str>,
    spans: &[SpanData],
) -> Value {
    let otlp_spans: Vec<Value> = spans
        .iter()
        .map(|s| {
            // Convert trace_id (32 hex) and span_id (16 hex) to base64 byte arrays
            let trace_id_bytes = hex_to_base64(&s.trace_id);
            let span_id_bytes = hex_to_base64(&s.span_id);
            let parent_span_bytes = if s.parent_span_id.is_empty() {
                String::new()
            } else {
                hex_to_base64(&s.parent_span_id)
            };

            // Parse start time from ISO 8601 timestamp
            let start_ns = timestamp_nanos(&s.timestamp_received);
            let end_ns = start_ns + (s.duration_ms.max(0.0) * 1_000_000.0) as i64;

            let mut attributes = vec![
                otlp_attribute("http.request.method", &s.http_method),
                otlp_attribute("url.path", &s.http_url),
                otlp_attribute("client.address", &s.client_ip),
                otlp_attribute("service.name", &s.service_name),
                otlp_attribute_double("gateway.latency.total_ms", s.duration_ms),
                otlp_attribute_double("gateway.latency.processing_ms", s.gateway_processing_ms),
                otlp_attribute_double("gateway.latency.backend_ttfb_ms", s.backend_ttfb_ms),
            ];

            if let Some(status_code) = s.http_status_code {
                attributes.push(otlp_attribute_int(
                    "http.response.status_code",
                    status_code as i64,
                ));
            }
            if s.backend_ms >= 0.0 {
                attributes.push(otlp_attribute_double(
                    "gateway.latency.backend_total_ms",
                    s.backend_ms,
                ));
            }
            attributes.push(otlp_attribute_double(
                "gateway.plugin_execution_ms",
                s.plugin_execution_ms,
            ));
            attributes.push(otlp_attribute_double(
                "gateway.overhead_ms",
                s.gateway_overhead_ms,
            ));
            if let Some(ref consumer) = s.consumer {
                attributes.push(otlp_attribute("enduser.id", consumer));
            }
            if let Some(ref ua) = s.user_agent {
                attributes.push(otlp_attribute("user_agent.original", ua));
            }
            if let Some(ref proxy_id) = s.proxy_id {
                attributes.push(otlp_attribute("gateway.proxy.id", proxy_id));
            }
            if let Some(ref route) = s.matched_route {
                attributes.push(otlp_attribute("http.route", route));
            }
            if let Some(ref target) = s.backend_target {
                attributes.push(otlp_attribute("server.address", target));
            }
            if let Some(ref resolved) = s.backend_resolved_ip {
                attributes.push(otlp_attribute("server.socket.address", resolved));
            }
            if let Some(ref protocol) = s.stream_protocol {
                attributes.push(otlp_attribute("network.protocol.name", protocol));
            }
            if let Some(port) = s.stream_listen_port {
                attributes.push(otlp_attribute_int("server.port", port as i64));
            }
            if let Some(bytes) = s.stream_bytes_sent {
                attributes.push(otlp_attribute_int(
                    "gateway.stream.bytes_sent",
                    bytes as i64,
                ));
            }
            if let Some(bytes) = s.stream_bytes_received {
                attributes.push(otlp_attribute_int(
                    "gateway.stream.bytes_received",
                    bytes as i64,
                ));
            }
            if s.response_streamed {
                attributes.push(otlp_attribute_bool("gateway.response.streamed", true));
            }
            if s.client_disconnected {
                attributes.push(otlp_attribute_bool("gateway.client.disconnected", true));
            }
            for (key, value) in &s.mesh_attributes {
                attributes.push(otlp_attribute(key, value));
            }

            // Build span events for error conditions
            let mut events = Vec::new();
            if let Some(ref error_class) = s.error_class {
                events.push(serde_json::json!({
                    "name": "exception",
                    "timeUnixNano": end_ns.to_string(),
                    "attributes": [
                        otlp_attribute("exception.type", "GatewayError"),
                        otlp_attribute("exception.message", error_class),
                    ]
                }));
            }
            if s.client_disconnected {
                events.push(serde_json::json!({
                    "name": "client.disconnect",
                    "timeUnixNano": end_ns.to_string(),
                    "attributes": []
                }));
            }

            let status_code = if s.http_status_code.is_some_and(|code| code >= 500) {
                2 // ERROR
            } else {
                1 // OK (includes 4xx — client errors are not server errors)
            };

            let mut span = serde_json::json!({
                "traceId": trace_id_bytes,
                "spanId": span_id_bytes,
                "name": s.span_name.clone(),
                "kind": s.span_kind,
                "startTimeUnixNano": start_ns.to_string(),
                "endTimeUnixNano": end_ns.to_string(),
                "attributes": attributes,
                "status": {
                    "code": status_code
                }
            });

            if !parent_span_bytes.is_empty() {
                span["parentSpanId"] = Value::String(parent_span_bytes);
            }
            if !events.is_empty() {
                span["events"] = Value::Array(events);
            }

            span
        })
        .collect();

    // Build resource attributes
    let mut resource_attributes = vec![otlp_attribute("service.name", service_name)];
    resource_attributes.push(otlp_attribute("service.version", env!("CARGO_PKG_VERSION")));
    resource_attributes.push(otlp_attribute("telemetry.sdk.name", "ferrum-edge"));
    resource_attributes.push(otlp_attribute(
        "telemetry.sdk.version",
        env!("CARGO_PKG_VERSION"),
    ));
    if let Some(env) = deployment_environment {
        resource_attributes.push(otlp_attribute("deployment.environment", env));
    }

    serde_json::json!({
        "resourceSpans": [{
            "resource": {
                "attributes": resource_attributes
            },
            "scopeSpans": [{
                "scope": {
                    "name": "ferrum-edge",
                    "version": env!("CARGO_PKG_VERSION")
                },
                "spans": otlp_spans
            }]
        }]
    })
}

fn build_zipkin_payload(service_name: &str, spans: &[SpanData]) -> Value {
    let zipkin_spans: Vec<Value> = spans
        .iter()
        .map(|span| {
            let start_us = timestamp_micros(&span.timestamp_received);
            let duration_us = (span.duration_ms.max(0.0) * 1_000.0) as i64;
            let mut tags = serde_json::Map::new();
            insert_tag(&mut tags, "http.method", &span.http_method);
            insert_tag(&mut tags, "http.path", &span.http_url);
            if let Some(status_code) = span.http_status_code {
                insert_tag(&mut tags, "http.status_code", &status_code.to_string());
            }
            insert_tag(&mut tags, "client.ip", &span.client_ip);
            insert_tag(
                &mut tags,
                "gateway.latency.total_ms",
                &span.duration_ms.to_string(),
            );
            if let Some(ref proxy_id) = span.proxy_id {
                insert_tag(&mut tags, "gateway.proxy.id", proxy_id);
            }
            if let Some(ref route) = span.matched_route {
                insert_tag(&mut tags, "http.route", route);
            }
            if let Some(ref target) = span.backend_target {
                insert_tag(&mut tags, "server.address", target);
            }
            if let Some(ref protocol) = span.stream_protocol {
                insert_tag(&mut tags, "network.protocol.name", protocol);
            }
            for (key, value) in &span.mesh_attributes {
                insert_tag(&mut tags, key, value);
            }

            let mut value = serde_json::json!({
                "traceId": span.trace_id.clone(),
                "id": span.span_id.clone(),
                "name": span.span_name.clone(),
                "kind": span.span_kind_typed.zipkin_str(),
                "timestamp": start_us,
                "duration": duration_us,
                "localEndpoint": {
                    "serviceName": service_name
                },
                "tags": tags,
            });
            if !span.parent_span_id.is_empty() {
                value["parentId"] = Value::String(span.parent_span_id.clone());
            }
            value
        })
        .collect();
    Value::Array(zipkin_spans)
}

fn build_datadog_payload(service_name: &str, spans: &[SpanData]) -> Value {
    let mut traces: BTreeMap<&str, Vec<Value>> = BTreeMap::new();
    for span in spans {
        traces
            .entry(span.trace_id.as_str())
            .or_default()
            .push(datadog_span_value(service_name, span));
    }
    Value::Array(
        traces
            .into_values()
            .map(Value::Array)
            .collect::<Vec<Value>>(),
    )
}

fn datadog_span_value(service_name: &str, span: &SpanData) -> Value {
    let start_ns = timestamp_nanos(&span.timestamp_received);
    let duration_ns = (span.duration_ms.max(0.0) * 1_000_000.0) as i64;
    let mut meta = serde_json::Map::new();
    insert_tag(&mut meta, "span.kind", span.span_kind_typed.datadog_str());
    insert_tag(&mut meta, "http.method", &span.http_method);
    insert_tag(&mut meta, "http.url", &span.http_url);
    insert_tag(&mut meta, "client.ip", &span.client_ip);
    if let Some(high_trace_bits) = datadog_high_trace_id(&span.trace_id) {
        insert_tag(&mut meta, "_dd.p.tid", high_trace_bits);
    }
    if let Some(ref proxy_id) = span.proxy_id {
        insert_tag(&mut meta, "gateway.proxy.id", proxy_id);
    }
    if let Some(ref route) = span.matched_route {
        insert_tag(&mut meta, "http.route", route);
    }
    if let Some(ref target) = span.backend_target {
        insert_tag(&mut meta, "server.address", target);
    }
    if let Some(ref protocol) = span.stream_protocol {
        insert_tag(&mut meta, "network.protocol.name", protocol);
    }
    for (key, value) in &span.mesh_attributes {
        insert_tag(&mut meta, key, value);
    }

    let mut metrics = serde_json::Map::new();
    metrics.insert(
        "_sampling_priority_v1".to_string(),
        serde_json::json!(1.0_f64),
    );
    metrics.insert(
        "gateway.latency.total_ms".to_string(),
        serde_json::json!(span.duration_ms),
    );
    if let Some(status_code) = span.http_status_code {
        metrics.insert(
            "http.status_code".to_string(),
            serde_json::json!(status_code as i64),
        );
    }

    serde_json::json!({
        "trace_id": hex_low_u64(&span.trace_id),
        "span_id": hex_low_u64(&span.span_id),
        "parent_id": hex_low_u64(&span.parent_span_id),
        "name": "ferrum.edge.request",
        "resource": span.span_name.clone(),
        "service": service_name,
        "type": "web",
        "start": start_ns,
        "duration": duration_ns,
        "meta": meta,
        "metrics": metrics,
    })
}

fn insert_tag(map: &mut serde_json::Map<String, Value>, key: &str, value: &str) {
    map.insert(key.to_string(), Value::String(value.to_string()));
}

fn timestamp_nanos(timestamp: &str) -> i64 {
    if timestamp.is_empty() {
        return 0;
    }
    match chrono::DateTime::parse_from_rfc3339(timestamp) {
        Ok(dt) => match dt.timestamp_nanos_opt() {
            Some(nanos) => nanos,
            None => {
                debug!(
                    timestamp,
                    "trace timestamp outside nanosecond range; using unix epoch fallback"
                );
                0
            }
        },
        Err(error) => {
            debug!(
                timestamp,
                %error,
                "invalid trace timestamp; using unix epoch fallback"
            );
            0
        }
    }
}

fn timestamp_micros(timestamp: &str) -> i64 {
    timestamp_nanos(timestamp) / 1_000
}

fn hex_low_u64(hex: &str) -> u64 {
    let start = hex.len().saturating_sub(16);
    u64::from_str_radix(&hex[start..], 16).unwrap_or(0)
}

fn datadog_high_trace_id(hex: &str) -> Option<&str> {
    if hex.len() != 32 {
        return None;
    }
    let high = &hex[..16];
    high.chars().any(|ch| ch != '0').then_some(high)
}

fn string_config(config: &Value, key: &str, default: &str) -> Result<String, String> {
    match config.get(key) {
        None | Some(Value::Null) => Ok(default.to_string()),
        Some(Value::String(value)) => {
            let trimmed = value.trim();
            if trimmed.is_empty() {
                Err(format!("otel_tracing: '{key}' must be a non-empty string"))
            } else {
                Ok(trimmed.to_string())
            }
        }
        Some(other) => Err(format!(
            "otel_tracing: '{key}' must be a string, got: {other}"
        )),
    }
}

fn optional_string_config(config: &Value, key: &str) -> Result<Option<String>, String> {
    match config.get(key) {
        None | Some(Value::Null) => Ok(None),
        Some(Value::String(value)) => {
            let trimmed = value.trim();
            if trimmed.is_empty() {
                Ok(None)
            } else {
                Ok(Some(trimmed.to_string()))
            }
        }
        Some(other) => Err(format!(
            "otel_tracing: '{key}' must be a string, got: {other}"
        )),
    }
}

fn bool_config(config: &Value, key: &str, default: bool) -> Result<bool, String> {
    match config.get(key) {
        None | Some(Value::Null) => Ok(default),
        Some(Value::Bool(value)) => Ok(*value),
        Some(other) => Err(format!(
            "otel_tracing: '{key}' must be a boolean, got: {other}"
        )),
    }
}

fn u64_config(config: &Value, key: &str, default: u64, min: u64) -> Result<u64, String> {
    match config.get(key) {
        None | Some(Value::Null) => Ok(default.max(min)),
        Some(Value::Number(value)) => value
            .as_u64()
            .map(|n| n.max(min))
            .ok_or_else(|| format!("otel_tracing: '{key}' must be a non-negative integer")),
        Some(other) => Err(format!(
            "otel_tracing: '{key}' must be a non-negative integer, got: {other}"
        )),
    }
}

fn usize_config(config: &Value, key: &str, default: usize, min: usize) -> Result<usize, String> {
    let value = u64_config(config, key, default as u64, min as u64)?;
    usize::try_from(value).map_err(|_| format!("otel_tracing: '{key}' is too large"))
}

fn u32_config(config: &Value, key: &str, default: u32, min: u32) -> Result<u32, String> {
    let value = u64_config(config, key, default as u64, min as u64)?;
    u32::try_from(value).map_err(|_| format!("otel_tracing: '{key}' is too large"))
}

fn validate_endpoint_for_provider(provider_name: &str, endpoint: &str) -> Result<String, String> {
    let url = Url::parse(endpoint)
        .map_err(|e| format!("{provider_name}: 'endpoint' must be a valid URL: {e}"))?;
    match url.scheme() {
        "http" | "https" => {}
        scheme => {
            return Err(format!(
                "{provider_name}: 'endpoint' scheme must be http or https, got: {scheme}"
            ));
        }
    }
    if !has_non_empty_authority(endpoint) {
        return Err(format!(
            "{provider_name}: 'endpoint' must include a hostname"
        ));
    }
    normalized_url_hostname(&url)
        .ok_or_else(|| format!("{provider_name}: 'endpoint' must include a hostname"))
}

fn datadog_traces_endpoint(agent_url: &str) -> Result<String, String> {
    let mut url = Url::parse(agent_url)
        .map_err(|e| format!("Datadog: 'agent_url' must be a valid URL: {e}"))?;
    match url.scheme() {
        "http" | "https" => {}
        scheme => {
            return Err(format!(
                "Datadog: 'agent_url' scheme must be http or https, got: {scheme}"
            ));
        }
    }
    if !has_non_empty_authority(agent_url) || normalized_url_hostname(&url).is_none() {
        return Err("Datadog: 'agent_url' must include a hostname".to_string());
    }
    let path = url.path().trim_end_matches('/');
    if path.is_empty() || path == "/" {
        url.set_path("/v0.3/traces");
    } else if path != "/v0.3/traces" {
        let mut combined = String::with_capacity(path.len() + "/v0.3/traces".len());
        combined.push_str(path);
        combined.push_str("/v0.3/traces");
        url.set_path(&combined);
    }
    Ok(url.to_string())
}

fn has_non_empty_authority(raw_url: &str) -> bool {
    raw_url
        .split_once("://")
        .and_then(|(_, rest)| rest.split(['/', '?', '#']).next())
        .is_some_and(|authority| !authority.is_empty())
}

fn normalized_url_hostname(url: &Url) -> Option<String> {
    match url.host()? {
        Host::Domain(host) if !host.is_empty() => Some(host.to_string()),
        Host::Ipv4(host) => Some(host.to_string()),
        Host::Ipv6(host) => Some(host.to_string()),
        _ => None,
    }
}

pub(crate) fn build_traceparent(
    version: &str,
    trace_id: &str,
    span_id: &str,
    flags: &str,
) -> String {
    let mut traceparent =
        String::with_capacity(version.len() + trace_id.len() + span_id.len() + flags.len() + 3);
    traceparent.push_str(version);
    traceparent.push('-');
    traceparent.push_str(trace_id);
    traceparent.push('-');
    traceparent.push_str(span_id);
    traceparent.push('-');
    traceparent.push_str(flags);
    traceparent
}

pub(crate) fn ensure_trace_metadata(
    metadata: &mut HashMap<String, String>,
    headers: &HashMap<String, String>,
) {
    if metadata.contains_key("trace_id") && metadata.contains_key("span_id") {
        return;
    }

    if let Some(existing) = header_value_case_insensitive(headers, TRACEPARENT_HEADER)
        && let Some(parsed) = OtelTracing::parse_traceparent(existing)
    {
        metadata.insert("trace_id".to_string(), parsed.trace_id.to_string());
        metadata.insert(
            "parent_span_id".to_string(),
            parsed.parent_span_id.to_string(),
        );
        let span_id = OtelTracing::generate_span_id();
        metadata.insert("span_id".to_string(), span_id.clone());
        metadata.insert(
            TRACEPARENT_HEADER.to_string(),
            build_traceparent(parsed.version, parsed.trace_id, &span_id, parsed.flags),
        );
        return;
    }

    let generated = OtelTracing::generate_trace_context();
    metadata.insert("trace_id".to_string(), generated.trace_id);
    metadata.insert("span_id".to_string(), generated.span_id);
    metadata.insert(TRACEPARENT_HEADER.to_string(), generated.traceparent);
}

/// Return true only when metadata carries an affirmative sampling decision.
///
/// Missing `trace_sampled` and traceparent flags are treated as not sampled;
/// callers that want fallback local sampling should apply it explicitly.
pub(crate) fn trace_is_sampled(metadata: &HashMap<String, String>) -> bool {
    if let Some(value) = metadata.get("trace_sampled") {
        return value.eq_ignore_ascii_case("true");
    }
    metadata
        .get(TRACEPARENT_HEADER)
        .and_then(|value| OtelTracing::parse_traceparent(value))
        .and_then(|parsed| u8::from_str_radix(parsed.flags, 16).ok())
        .is_some_and(|flags| flags & 0x01 == 0x01)
}

fn header_value_case_insensitive<'a>(
    headers: &'a HashMap<String, String>,
    name: &str,
) -> Option<&'a str> {
    headers.get(name).map(String::as_str).or_else(|| {
        headers
            .iter()
            .find(|(key, _)| key.eq_ignore_ascii_case(name))
            .map(|(_, value)| value.as_str())
    })
}

fn hex_encode(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        output.push(HEX[(byte >> 4) as usize] as char);
        output.push(HEX[(byte & 0x0f) as usize] as char);
    }
    output
}

fn otlp_attribute(key: &str, value: &str) -> Value {
    serde_json::json!({
        "key": key,
        "value": { "stringValue": value }
    })
}

fn otlp_attribute_int(key: &str, value: i64) -> Value {
    serde_json::json!({
        "key": key,
        "value": { "intValue": value.to_string() }
    })
}

fn otlp_attribute_double(key: &str, value: f64) -> Value {
    serde_json::json!({
        "key": key,
        "value": { "doubleValue": value }
    })
}

fn otlp_attribute_bool(key: &str, value: bool) -> Value {
    serde_json::json!({
        "key": key,
        "value": { "boolValue": value }
    })
}

/// Convert a hex string to base64-encoded bytes (OTLP/HTTP JSON encoding).
///
/// Per the OpenTelemetry spec, `traceId` (16 bytes / 32 hex chars) and
/// `spanId` (8 bytes / 16 hex chars) are JSON-encoded as base64-standard
/// strings. Callers in this module always pass even-length hex (validated
/// upstream by `parse_traceparent` / produced by `generate_traceparent`),
/// but the implementation is robust against odd-length input — the trailing
/// half-byte is dropped rather than panicking on a slice out of bounds.
fn hex_to_base64(hex: &str) -> String {
    use base64::Engine;
    use base64::engine::general_purpose::STANDARD;

    let bytes: Vec<u8> = (0..hex.len())
        .step_by(2)
        .filter_map(|i| {
            let end = i + 2;
            if end > hex.len() {
                return None;
            }
            u8::from_str_radix(&hex[i..end], 16).ok()
        })
        .collect();

    STANDARD.encode(&bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_span(trace_id: &str, span_id: &str) -> SpanData {
        SpanData {
            trace_id: trace_id.to_string(),
            span_id: span_id.to_string(),
            parent_span_id: String::new(),
            service_name: "ferrum-edge".to_string(),
            span_name: "GET /api".to_string(),
            span_kind: 2,
            span_kind_typed: SpanKind::Server,
            http_method: "GET".to_string(),
            http_url: "/api".to_string(),
            http_status_code: Some(200),
            client_ip: "127.0.0.1".to_string(),
            duration_ms: 10.0,
            gateway_processing_ms: 1.0,
            backend_ttfb_ms: 2.0,
            backend_ms: 3.0,
            plugin_execution_ms: 1.0,
            gateway_overhead_ms: 1.0,
            consumer: None,
            timestamp_received: "2025-01-01T00:00:00Z".to_string(),
            user_agent: None,
            proxy_id: Some("proxy-a".to_string()),
            matched_route: Some("api".to_string()),
            backend_target: None,
            backend_resolved_ip: None,
            error_class: None,
            response_streamed: false,
            client_disconnected: false,
            mesh_attributes: Vec::new(),
            stream_protocol: None,
            stream_listen_port: None,
            stream_bytes_sent: None,
            stream_bytes_received: None,
        }
    }

    fn test_trace_http_exporter_config() -> TraceHttpExporterConfig {
        TraceHttpExporterConfig {
            provider_name: "workload_metrics",
            endpoint: "http://collector:4318/v1/traces".to_string(),
            authorization: None,
            custom_headers: Vec::new(),
            http_client: PluginHttpClient::default(),
            batch_size: 16,
            flush_interval: Duration::from_secs(60),
            max_retries: 0,
            retry_delay: Duration::from_millis(1),
            service_name: "ferrum-edge".to_string(),
            deployment_environment: None,
            payload_kind: TracePayloadKind::Otlp,
        }
    }

    #[test]
    fn buffered_trace_exporter_defers_start_without_runtime() {
        let exporter = BufferedTraceExporter::new(test_trace_http_exporter_config(), 8)
            .expect("exporter config accepted");

        assert!(!exporter.started.load(Ordering::Acquire));
        assert!(
            exporter
                .try_export(test_span(
                    "4bf92f3577b34da6a3ce929d0e0e4736",
                    "00f067aa0ba902b7"
                ))
                .is_err(),
            "enqueue should report missing runtime instead of silently dropping deferred startup"
        );
        assert!(
            !exporter.started.load(Ordering::Acquire),
            "failed deferred startup must stay retryable"
        );
    }

    #[tokio::test]
    async fn buffered_trace_exporter_marks_started_when_runtime_available() {
        let exporter = BufferedTraceExporter::new(test_trace_http_exporter_config(), 8)
            .expect("exporter config accepted");

        assert!(
            exporter.started.load(Ordering::Acquire),
            "exporter constructed inside a runtime should enter steady-state without per-span locking"
        );
    }

    #[test]
    fn hex_to_base64_decodes_even_length_input() {
        // Standard 16-byte trace_id (32 hex chars).
        let hex = "4bf92f3577b34da6a3ce929d0e0e4736";
        let encoded = hex_to_base64(hex);
        // base64.b64encode(bytes.fromhex(...)) == "S/kvNXezTaajzpKdDg5HNg=="
        assert_eq!(encoded, "S/kvNXezTaajzpKdDg5HNg==");
    }

    #[test]
    fn hex_to_base64_decodes_8_byte_span_id() {
        // Standard 8-byte span_id (16 hex chars).
        let hex = "00f067aa0ba902b7";
        let encoded = hex_to_base64(hex);
        assert_eq!(encoded, "APBnqgupArc=");
    }

    #[test]
    fn hex_to_base64_handles_empty_input() {
        assert_eq!(hex_to_base64(""), "");
    }

    #[test]
    fn hex_to_base64_handles_odd_length_without_panic() {
        // Defensive: odd-length should not panic. The trailing half-byte
        // is dropped (the final iteration would slice past hex.len() and
        // is filtered out via the `end > hex.len()` guard).
        let _ = hex_to_base64("abc");
        let _ = hex_to_base64("4bf92f3577b34da6a3ce929d0e0e473");
    }

    #[test]
    fn hex_to_base64_invalid_chars_filtered() {
        // Non-hex chars are filtered out via from_str_radix Err.
        let encoded = hex_to_base64("XX");
        assert_eq!(encoded, ""); // no valid bytes decoded
    }

    #[test]
    fn datadog_payload_groups_spans_by_trace_and_preserves_128_bit_id() {
        let trace_a = "4bf92f3577b34da6a3ce929d0e0e4736";
        let trace_b = "0000000000000000000000000000002a";
        let payload = build_datadog_payload(
            "ferrum-edge",
            &[
                test_span(trace_a, "00f067aa0ba902b7"),
                test_span(trace_b, "00f067aa0ba902b8"),
                test_span(trace_a, "00f067aa0ba902b9"),
            ],
        );

        let traces = payload.as_array().expect("datadog trace array");
        assert_eq!(traces.len(), 2);
        assert!(
            traces
                .iter()
                .any(|trace| trace.as_array().unwrap().len() == 2)
        );
        assert!(
            traces
                .iter()
                .any(|trace| trace.as_array().unwrap().len() == 1)
        );

        let first_trace_span = traces
            .iter()
            .flat_map(|trace| trace.as_array().unwrap())
            .find(|span| span["meta"]["_dd.p.tid"] == "4bf92f3577b34da6")
            .expect("128-bit trace high bits preserved");
        assert_eq!(
            first_trace_span["trace_id"],
            serde_json::json!(0xa3ce_929d_0e0e_4736_u64)
        );

        let low_only_span = traces
            .iter()
            .flat_map(|trace| trace.as_array().unwrap())
            .find(|span| span["trace_id"] == serde_json::json!(42_u64))
            .expect("low-only trace present");
        assert!(low_only_span["meta"].get("_dd.p.tid").is_none());
    }

    #[test]
    fn otlp_payload_includes_mesh_identity_attributes() {
        let span = SpanData {
            trace_id: "4bf92f3577b34da6a3ce929d0e0e4736".to_string(),
            span_id: "00f067aa0ba902b7".to_string(),
            parent_span_id: String::new(),
            service_name: "ferrum-edge".to_string(),
            span_name: "GET /".to_string(),
            span_kind: 2,
            span_kind_typed: SpanKind::Server,
            http_method: "GET".to_string(),
            http_url: "/".to_string(),
            http_status_code: Some(200),
            client_ip: "127.0.0.1".to_string(),
            duration_ms: 10.0,
            gateway_processing_ms: 1.0,
            backend_ttfb_ms: 2.0,
            backend_ms: 3.0,
            plugin_execution_ms: 1.0,
            gateway_overhead_ms: 1.0,
            consumer: None,
            timestamp_received: "2025-01-01T00:00:00Z".to_string(),
            user_agent: None,
            proxy_id: Some("proxy-a".to_string()),
            matched_route: Some("payments".to_string()),
            backend_target: None,
            backend_resolved_ip: None,
            error_class: None,
            response_streamed: false,
            client_disconnected: false,
            mesh_attributes: vec![
                (
                    "mesh.source.principal".to_string(),
                    "spiffe://cluster.local/ns/default/sa/frontend".to_string(),
                ),
                (
                    "mesh.destination.service".to_string(),
                    "payments".to_string(),
                ),
            ],
            stream_protocol: None,
            stream_listen_port: None,
            stream_bytes_sent: None,
            stream_bytes_received: None,
        };

        let payload = build_otlp_payload("ferrum-edge", None, &[span]);
        let attributes = payload["resourceSpans"][0]["scopeSpans"][0]["spans"][0]["attributes"]
            .as_array()
            .unwrap();

        assert!(attributes.iter().any(|attribute| {
            attribute["key"] == "mesh.source.principal"
                && attribute["value"]["stringValue"]
                    == "spiffe://cluster.local/ns/default/sa/frontend"
        }));
        assert!(attributes.iter().any(|attribute| {
            attribute["key"] == "mesh.destination.service"
                && attribute["value"]["stringValue"] == "payments"
        }));
    }
}
