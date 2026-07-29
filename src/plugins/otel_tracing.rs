//! OpenTelemetry Tracing Plugin
//!
//! Provides W3C Trace Context propagation (`traceparent`/`tracestate`) and
//! exports spans to OTLP/Zipkin/Datadog collectors via HTTP/JSON.
//!
//! When no endpoint is configured, the plugin runs in propagation-only mode:
//! it generates/propagates trace context without exporting spans.
//!
//! Security and contract notes:
//! - Trace-context trust is explicit and fail-closed (`trace_context_trust`).
//! - Parent-based sampling is honored; root sampling is configurable.
//! - Span names use low-cardinality route/proxy identifiers, never raw paths.
//!   HTTP methods in span names are bounded to the standard set (`_OTHER`
//!   for extensions); `http.request.method` retains the observed token.
//! - Exporter queues are count- and byte-bounded; diagnostics use redacted URLs.

use async_trait::async_trait;
use http::header::{HeaderName, HeaderValue};
use serde_json::Value;
use std::collections::{BTreeMap, HashMap};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, OnceLock};
use tokio::runtime::Handle;
use tokio::sync::{mpsc, watch};
use tokio::time::Duration;
use tracing::{debug, warn};
use url::{Host, Url};
use uuid::Uuid;

use crate::modes::mesh::config::TracingProvider;
use crate::observability_delivery::DeliveryWorkerControl;
use crate::util::accept_backoff::LogRateLimiter;
use crate::util::unknown_keys::reject_unknown_keys;

use super::mesh::mesh_trace_attributes;
use super::utils::PluginHttpClient;
use super::utils::byte_budget::{
    JSON_STRING_WORST_CASE_EXPANSION, PayloadMaterializationError, ProcessByteReservation,
    ReservedPayload, RetainedByteCeiling, materialize_reserved_payload, process_ceiling,
    record_batch_materialization_loss,
};
use super::{
    Direction, DisconnectCause, Plugin, PluginResult, RequestContext, StreamTransactionSummary,
    TransactionSummary, WsDisconnectContext,
};

const TRACEPARENT_HEADER: &str = "traceparent";
const TRACESTATE_HEADER: &str = "tracestate";
const SUPPORTED_TRACEPARENT_VERSION: &str = "00";

const ALLOWED_CONFIG_KEYS: &[&str] = &[
    "endpoint",
    "service_name",
    "deployment_environment",
    "generate_trace_id",
    "headers",
    "authorization",
    "batch_size",
    "flush_interval_ms",
    "buffer_capacity",
    "buffer_max_bytes",
    "max_attribute_bytes",
    "max_retries",
    "retry_delay_ms",
    "trace_context_trust",
    "root_sampling",
    "root_sampling_ratio",
    "include_url_path",
];

const MIN_BATCH_SIZE: u64 = 1;
const MAX_BATCH_SIZE: u64 = 10_000;
const DEFAULT_BATCH_SIZE: u64 = 50;
const MIN_FLUSH_INTERVAL_MS: u64 = 100;
const MAX_FLUSH_INTERVAL_MS: u64 = 600_000;
const DEFAULT_FLUSH_INTERVAL_MS: u64 = 5_000;
const MIN_BUFFER_CAPACITY: u64 = 1;
const MAX_BUFFER_CAPACITY: u64 = 100_000;
const DEFAULT_BUFFER_CAPACITY: u64 = 10_000;
const MIN_BUFFER_MAX_BYTES: u64 = 64 * 1024;
const MAX_BUFFER_MAX_BYTES: u64 = 256 * 1024 * 1024;
const DEFAULT_BUFFER_MAX_BYTES: u64 = 16 * 1024 * 1024;
const MIN_MAX_ATTRIBUTE_BYTES: u64 = 64;
const MAX_MAX_ATTRIBUTE_BYTES: u64 = 16_384;
const DEFAULT_MAX_ATTRIBUTE_BYTES: u64 = 2_048;
const MIN_MAX_RETRIES: u64 = 0;
const MAX_MAX_RETRIES: u64 = 10;
const DEFAULT_MAX_RETRIES: u64 = 2;
const MIN_RETRY_DELAY_MS: u64 = 0;
const MAX_RETRY_DELAY_MS: u64 = 60_000;
const DEFAULT_RETRY_DELAY_MS: u64 = 1_000;
const MAX_PARTIAL_SUCCESS_MESSAGE_BYTES: usize = 512;
const MAX_OTLP_SUCCESS_BODY_BYTES: usize = 64 * 1024;
const MAX_URL_PATH_BYTES: usize = 512;

/// Whether inbound W3C parents are trusted as span parents.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum TraceContextTrust {
    /// Adopt a valid inbound `traceparent` as parent (trusted mesh/internal).
    Trusted,
    /// Fail closed: generate a fresh root; never parent under caller-chosen IDs.
    Untrusted,
}

/// Root-trace sampling when no trusted parent supplies a decision.
#[derive(Debug, Clone, Copy, PartialEq)]
pub(crate) enum RootSampling {
    AlwaysOn,
    AlwaysOff,
    Ratio(f64),
}

pub struct OtelTracing {
    service_name: String,
    generate_trace_id: bool,
    trace_context_trust: TraceContextTrust,
    root_sampling: RootSampling,
    include_url_path: bool,
    max_attribute_bytes: usize,
    exporter: Option<Arc<dyn TraceExporter>>,
    export_drop_log_limiter: Mutex<LogRateLimiter>,
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
    pub(crate) fn otlp_code(self) -> u8 {
        match self {
            Self::Server => 2,
            Self::Client => 3,
        }
    }

    pub(crate) fn zipkin_str(self) -> &'static str {
        match self {
            Self::Server => "SERVER",
            Self::Client => "CLIENT",
        }
    }

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
    pub(crate) span_kind_typed: SpanKind,
    pub(crate) http_method: String,
    pub(crate) http_url: String,
    pub(crate) http_status_code: Option<u16>,
    pub(crate) grpc_status: Option<u32>,
    pub(crate) client_ip: String,
    pub(crate) duration_ms: f64,
    pub(crate) gateway_processing_ms: f64,
    pub(crate) backend_ttfb_ms: f64,
    pub(crate) backend_ms: f64,
    pub(crate) plugin_execution_ms: f64,
    pub(crate) gateway_overhead_ms: f64,
    pub(crate) consumer: Option<String>,
    pub(crate) timestamp_received: String,
    pub(crate) user_agent: Option<String>,
    pub(crate) proxy_id: Option<String>,
    pub(crate) matched_route: Option<String>,
    pub(crate) namespace: Option<String>,
    /// Client-facing server address (host only) for SERVER spans.
    pub(crate) server_address: Option<String>,
    pub(crate) server_port: Option<u16>,
    /// Upstream selection for gateway-scoped attributes (never `server.address`).
    pub(crate) backend_target: Option<String>,
    pub(crate) backend_host: Option<String>,
    pub(crate) backend_port: Option<u16>,
    pub(crate) backend_resolved_ip: Option<String>,
    pub(crate) error_class: Option<String>,
    pub(crate) body_error_class: Option<String>,
    pub(crate) body_completed: bool,
    pub(crate) response_streamed: bool,
    pub(crate) client_disconnected: bool,
    pub(crate) otlp_error: bool,
    pub(crate) mesh_attributes: Vec<(String, String)>,
    pub(crate) stream_protocol: Option<String>,
    pub(crate) stream_listen_port: Option<u16>,
    pub(crate) stream_bytes_sent: Option<u64>,
    pub(crate) stream_bytes_received: Option<u64>,
    pub(crate) disconnect_direction: Option<String>,
    pub(crate) disconnect_cause: Option<String>,
    pub(crate) stream_io_side: Option<String>,
    pub(crate) ws_frames_client_to_backend: Option<u64>,
    pub(crate) ws_frames_backend_to_client: Option<u64>,
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
    pub(crate) sampled: bool,
    pub(crate) traceparent: String,
}

pub(crate) struct ParsedTraceParent<'a> {
    pub(crate) trace_id: &'a str,
    pub(crate) parent_span_id: &'a str,
    pub(crate) flags: &'a str,
}

impl SpanData {
    pub(crate) fn from_transaction_summary(
        summary: &TransactionSummary,
        service_name: &str,
        include_url_path: bool,
        max_attribute_bytes: usize,
    ) -> Option<Self> {
        Self::from_transaction_summary_with_kind(
            summary,
            service_name,
            SpanKind::Server,
            include_url_path,
            max_attribute_bytes,
        )
    }

    pub(crate) fn from_transaction_summary_with_kind(
        summary: &TransactionSummary,
        service_name: &str,
        kind: SpanKind,
        include_url_path: bool,
        max_attribute_bytes: usize,
    ) -> Option<Self> {
        let (trace_id, span_id, parent_span_id) = take_w3c_trace_ids(
            summary.metadata.get("trace_id")?,
            summary.metadata.get("span_id")?,
            summary
                .metadata
                .get("parent_span_id")
                .map(String::as_str)
                .unwrap_or(""),
        )?;
        let (server_address, server_port) = server_authority_from_metadata(&summary.metadata);
        let (backend_host, backend_port) = summary
            .backend_target
            .as_deref()
            .map(parse_backend_host_port)
            .unwrap_or((None, None));
        let backend_target =
            gateway_backend_target(backend_host.as_deref(), backend_port, max_attribute_bytes);
        let grpc_status = summary.grpc_status();
        let otlp_error = http_span_is_error(summary);
        let http_url = if include_url_path {
            truncate_attr(
                &summary.request_path,
                MAX_URL_PATH_BYTES.min(max_attribute_bytes),
            )
        } else {
            String::new()
        };
        Some(Self {
            trace_id,
            span_id,
            parent_span_id,
            service_name: service_name.to_string(),
            span_name: http_span_name(summary),
            span_kind: kind.otlp_code(),
            span_kind_typed: kind,
            http_method: truncate_attr(&summary.http_method, 32),
            http_url,
            http_status_code: Some(summary.response_status_code),
            grpc_status,
            client_ip: truncate_attr(&summary.client_ip, 64),
            duration_ms: summary.latency_total_ms,
            gateway_processing_ms: summary.latency_gateway_processing_ms,
            backend_ttfb_ms: summary.latency_backend_ttfb_ms,
            backend_ms: summary.latency_backend_total_ms,
            plugin_execution_ms: summary.latency_plugin_execution_ms,
            gateway_overhead_ms: summary.latency_gateway_overhead_ms,
            consumer: summary
                .consumer_username
                .as_deref()
                .map(|v| truncate_attr(v, max_attribute_bytes)),
            timestamp_received: summary.timestamp_received.clone(),
            user_agent: summary
                .request_user_agent
                .as_deref()
                .map(|v| truncate_attr(v, max_attribute_bytes)),
            proxy_id: summary
                .proxy_id
                .as_deref()
                .map(|v| truncate_attr(v, max_attribute_bytes)),
            matched_route: summary
                .proxy_name
                .as_deref()
                .map(|v| truncate_attr(v, max_attribute_bytes)),
            namespace: Some(truncate_attr(&summary.namespace, max_attribute_bytes)),
            server_address: server_address.map(|v| truncate_attr(&v, max_attribute_bytes)),
            server_port,
            backend_target,
            backend_host: backend_host.map(|v| truncate_attr(&v, max_attribute_bytes)),
            backend_port,
            backend_resolved_ip: summary
                .backend_resolved_ip
                .as_deref()
                .map(|v| truncate_attr(v, 64)),
            error_class: summary.error_class.as_ref().map(|e| format!("{e:?}")),
            body_error_class: summary.body_error_class.as_ref().map(|e| format!("{e:?}")),
            body_completed: summary.body_completed,
            response_streamed: summary.response_streamed,
            client_disconnected: summary.client_disconnected,
            otlp_error,
            mesh_attributes: bounded_mesh_attributes(&summary.metadata, max_attribute_bytes),
            stream_protocol: None,
            stream_listen_port: None,
            stream_bytes_sent: None,
            stream_bytes_received: None,
            disconnect_direction: None,
            disconnect_cause: None,
            stream_io_side: None,
            ws_frames_client_to_backend: None,
            ws_frames_backend_to_client: None,
        })
    }

    pub(crate) fn from_stream_summary(
        summary: &StreamTransactionSummary,
        service_name: &str,
        max_attribute_bytes: usize,
    ) -> Option<Self> {
        Self::from_stream_summary_with_kind(
            summary,
            service_name,
            SpanKind::Server,
            max_attribute_bytes,
        )
    }

    pub(crate) fn from_stream_summary_with_kind(
        summary: &StreamTransactionSummary,
        service_name: &str,
        kind: SpanKind,
        max_attribute_bytes: usize,
    ) -> Option<Self> {
        let (trace_id, span_id, parent_span_id) = take_w3c_trace_ids(
            summary.metadata.get("trace_id")?,
            summary.metadata.get("span_id")?,
            summary
                .metadata
                .get("parent_span_id")
                .map(String::as_str)
                .unwrap_or(""),
        )?;
        let (backend_host, backend_port) = parse_backend_host_port(&summary.backend_target);
        let backend_target =
            gateway_backend_target(backend_host.as_deref(), backend_port, max_attribute_bytes);
        let otlp_error = summary.error_class.is_some()
            || summary.connection_error.is_some()
            || summary
                .disconnect_cause
                .is_some_and(|cause| cause != DisconnectCause::GracefulShutdown);
        let route = summary
            .proxy_name
            .as_deref()
            .unwrap_or(summary.protocol.as_str());
        Some(Self {
            trace_id,
            span_id,
            parent_span_id,
            service_name: service_name.to_string(),
            span_name: format!("{} {}", summary.protocol, route),
            span_kind: kind.otlp_code(),
            span_kind_typed: kind,
            http_method: truncate_attr(&summary.protocol, 32),
            http_url: String::new(),
            http_status_code: None,
            grpc_status: None,
            client_ip: truncate_attr(&summary.client_ip, 64),
            duration_ms: summary.duration_ms,
            gateway_processing_ms: 0.0,
            backend_ttfb_ms: 0.0,
            backend_ms: summary.duration_ms,
            plugin_execution_ms: 0.0,
            gateway_overhead_ms: 0.0,
            consumer: summary
                .consumer_username
                .as_deref()
                .map(|v| truncate_attr(v, max_attribute_bytes)),
            timestamp_received: summary.timestamp_connected.clone(),
            user_agent: None,
            proxy_id: Some(truncate_attr(&summary.proxy_id, max_attribute_bytes)),
            matched_route: summary
                .proxy_name
                .as_deref()
                .map(|v| truncate_attr(v, max_attribute_bytes)),
            namespace: Some(truncate_attr(&summary.namespace, max_attribute_bytes)),
            server_address: None,
            server_port: Some(summary.listen_port),
            backend_target,
            backend_host: backend_host.map(|v| truncate_attr(&v, max_attribute_bytes)),
            backend_port,
            backend_resolved_ip: summary
                .backend_resolved_ip
                .as_deref()
                .map(|v| truncate_attr(v, 64)),
            error_class: summary.error_class.as_ref().map(|e| format!("{e:?}")),
            body_error_class: None,
            body_completed: true,
            response_streamed: false,
            client_disconnected: matches!(
                summary.disconnect_cause,
                Some(DisconnectCause::RecvError)
            ),
            otlp_error,
            mesh_attributes: bounded_mesh_attributes(&summary.metadata, max_attribute_bytes),
            stream_protocol: Some(summary.protocol.clone()),
            stream_listen_port: Some(summary.listen_port),
            stream_bytes_sent: Some(summary.bytes_sent),
            stream_bytes_received: Some(summary.bytes_received),
            disconnect_direction: summary
                .disconnect_direction
                .map(direction_label)
                .map(str::to_string),
            disconnect_cause: summary
                .disconnect_cause
                .map(disconnect_cause_label)
                .map(str::to_string),
            stream_io_side: None,
            ws_frames_client_to_backend: None,
            ws_frames_backend_to_client: None,
        })
    }

    pub(crate) fn from_ws_disconnect(
        ctx: &WsDisconnectContext,
        service_name: &str,
        max_attribute_bytes: usize,
    ) -> Option<Self> {
        let raw_trace_id = ctx.metadata.get("trace_id")?;
        // Never reuse the HTTP upgrade span identity for the session span.
        let span_id = OtelTracing::generate_span_id();
        let raw_parent = ctx
            .metadata
            .get("span_id")
            .map(String::as_str)
            .unwrap_or("");
        let (trace_id, span_id, parent_span_id) =
            take_w3c_trace_ids(raw_trace_id, &span_id, raw_parent)?;
        let (backend_host, backend_port) = parse_backend_host_port(&ctx.backend_target);
        let backend_target =
            gateway_backend_target(backend_host.as_deref(), backend_port, max_attribute_bytes);
        let disconnect_cause = websocket_disconnect_cause(ctx);
        let otlp_error = ctx.error_class.is_some();
        let route = ctx.proxy_name.as_deref().unwrap_or("websocket");
        Some(Self {
            trace_id,
            span_id,
            parent_span_id,
            service_name: service_name.to_string(),
            span_name: format!("WEBSOCKET {route}"),
            span_kind: SpanKind::Server.otlp_code(),
            span_kind_typed: SpanKind::Server,
            http_method: "WEBSOCKET".to_string(),
            http_url: String::new(),
            http_status_code: None,
            grpc_status: None,
            client_ip: truncate_attr(&ctx.client_ip, 64),
            duration_ms: ctx.duration_ms,
            gateway_processing_ms: 0.0,
            backend_ttfb_ms: 0.0,
            backend_ms: ctx.duration_ms,
            plugin_execution_ms: 0.0,
            gateway_overhead_ms: 0.0,
            consumer: ctx
                .consumer_username
                .as_deref()
                .map(|v| truncate_attr(v, max_attribute_bytes)),
            timestamp_received: timestamp_before_now(ctx.duration_ms),
            user_agent: None,
            proxy_id: Some(truncate_attr(&ctx.proxy_id, max_attribute_bytes)),
            matched_route: ctx
                .proxy_name
                .as_deref()
                .map(|v| truncate_attr(v, max_attribute_bytes)),
            namespace: Some(truncate_attr(&ctx.namespace, max_attribute_bytes)),
            server_address: None,
            server_port: Some(ctx.listen_port),
            backend_target,
            backend_host: backend_host.map(|v| truncate_attr(&v, max_attribute_bytes)),
            backend_port,
            backend_resolved_ip: None,
            error_class: ctx.error_class.as_ref().map(|e| format!("{e:?}")),
            body_error_class: None,
            body_completed: true,
            response_streamed: false,
            client_disconnected: websocket_client_disconnected(ctx),
            otlp_error,
            mesh_attributes: bounded_mesh_attributes(&ctx.metadata, max_attribute_bytes),
            stream_protocol: Some("websocket".to_string()),
            stream_listen_port: Some(ctx.listen_port),
            stream_bytes_sent: Some(ctx.bytes_client_to_backend),
            stream_bytes_received: Some(ctx.bytes_backend_to_client),
            disconnect_direction: ctx.direction.map(direction_label).map(str::to_string),
            disconnect_cause: Some(disconnect_cause_label(disconnect_cause).to_string()),
            stream_io_side: ctx.io_side.map(stream_io_side_label).map(str::to_string),
            ws_frames_client_to_backend: Some(ctx.frames_client_to_backend),
            ws_frames_backend_to_client: Some(ctx.frames_backend_to_client),
        })
    }

    fn approx_queued_bytes(&self) -> usize {
        self.trace_id.len()
            + self.span_id.len()
            + self.parent_span_id.len()
            + self.service_name.len()
            + self.span_name.len()
            + self.http_method.len()
            + self.http_url.len()
            + self.client_ip.len()
            + self.timestamp_received.len()
            + self.consumer.as_ref().map(String::len).unwrap_or(0)
            + self.user_agent.as_ref().map(String::len).unwrap_or(0)
            + self.proxy_id.as_ref().map(String::len).unwrap_or(0)
            + self.matched_route.as_ref().map(String::len).unwrap_or(0)
            + self.namespace.as_ref().map(String::len).unwrap_or(0)
            + self.server_address.as_ref().map(String::len).unwrap_or(0)
            + self.backend_target.as_ref().map(String::len).unwrap_or(0)
            + self.backend_host.as_ref().map(String::len).unwrap_or(0)
            + self
                .backend_resolved_ip
                .as_ref()
                .map(String::len)
                .unwrap_or(0)
            + self.error_class.as_ref().map(String::len).unwrap_or(0)
            + self.body_error_class.as_ref().map(String::len).unwrap_or(0)
            + self
                .disconnect_direction
                .as_ref()
                .map(String::len)
                .unwrap_or(0)
            + self.disconnect_cause.as_ref().map(String::len).unwrap_or(0)
            + self.stream_io_side.as_ref().map(String::len).unwrap_or(0)
            + self
                .mesh_attributes
                .iter()
                .map(|(k, v)| k.len() + v.len())
                .sum::<usize>()
            + 256
    }
}

impl OtelTracing {
    pub fn new_with_http_client(
        config: &Value,
        http_client: PluginHttpClient,
    ) -> Result<Self, String> {
        let config_object = config
            .as_object()
            .ok_or_else(|| "otel_tracing: configuration must be a JSON object".to_string())?;
        reject_unknown_keys(
            config_object,
            "config",
            ALLOWED_CONFIG_KEYS,
            "otel_tracing: ",
        )?;

        let service_name = string_config(config, "service_name", "ferrum-edge")?;
        let generate_trace_id = bool_config(config, "generate_trace_id", true)?;
        let include_url_path = bool_config(config, "include_url_path", true)?;
        let trace_context_trust = parse_trace_context_trust(config)?;
        let root_sampling = parse_root_sampling(config)?;
        let max_attribute_bytes = usize_config_range(
            config,
            "max_attribute_bytes",
            DEFAULT_MAX_ATTRIBUTE_BYTES,
            MIN_MAX_ATTRIBUTE_BYTES,
            MAX_MAX_ATTRIBUTE_BYTES,
        )?;

        let endpoint = optional_string_config(config, "endpoint")?;
        let authorization = optional_string_config(config, "authorization")?;
        let custom_headers = parse_custom_headers(config.get("headers"))?;
        // Validate exporter controls even in propagation-only mode. A stored
        // typo or invalid queue setting must not become latent until an
        // endpoint is added later.
        let options = TraceExporterOptions::from_config(config, service_name.clone(), http_client)?;

        let exporter = if let Some(endpoint) = endpoint {
            Some(Arc::new(OtlpTraceExporter::new(
                endpoint,
                authorization,
                custom_headers,
                options,
            )?) as Arc<dyn TraceExporter>)
        } else {
            None
        };

        Ok(Self {
            service_name,
            generate_trace_id,
            trace_context_trust,
            root_sampling,
            include_url_path,
            max_attribute_bytes,
            exporter,
            export_drop_log_limiter: Mutex::new(LogRateLimiter::new()),
        })
    }

    /// Generate a W3C trace context without reparsing the generated header.
    pub(crate) fn generate_trace_context(sampled: bool) -> GeneratedTraceContext {
        let trace_id = Self::generate_trace_id();
        let span_id = Self::generate_span_id();
        let flags = if sampled { "01" } else { "00" };
        let traceparent =
            build_traceparent(SUPPORTED_TRACEPARENT_VERSION, &trace_id, &span_id, flags);
        GeneratedTraceContext {
            trace_id,
            span_id,
            sampled,
            traceparent,
        }
    }

    /// Parse a W3C `traceparent` header.
    ///
    /// Wire fields must be lowercase hex. Version `00` requires exactly four
    /// dash-separated fields. Higher versions accept additional fields without
    /// interpreting them. Callers must emit
    /// [`SUPPORTED_TRACEPARENT_VERSION`] (`00`) on the wire.
    pub(crate) fn parse_traceparent(value: &str) -> Option<ParsedTraceParent<'_>> {
        let value = value.trim();
        if value.is_empty() {
            return None;
        }
        let mut parts = value.split('-');
        let version = parts.next()?;
        let trace_id = parts.next()?;
        let parent_span_id = parts.next()?;
        let flags = parts.next()?;

        if !is_lowercase_hex(version, 2)
            || !is_lowercase_hex(trace_id, 32)
            || !is_lowercase_hex(parent_span_id, 16)
            || !is_lowercase_hex(flags, 2)
            || version == "ff"
            || trace_id.chars().all(|c| c == '0')
            || parent_span_id.chars().all(|c| c == '0')
        {
            return None;
        }

        if version == "00" {
            if parts.next().is_some() {
                return None;
            }
        } else {
            // Forward-compatible: ignore unknown trailing fields.
            let _ = parts.count();
        }

        Some(ParsedTraceParent {
            trace_id,
            parent_span_id,
            flags,
        })
    }

    pub(crate) fn generate_trace_id() -> String {
        hex_encode(Uuid::new_v4().as_bytes())
    }

    pub(crate) fn generate_span_id() -> String {
        hex_encode(&Uuid::new_v4().as_bytes()[..8])
    }

    fn decide_root_sampled(&self) -> bool {
        match self.root_sampling {
            RootSampling::AlwaysOn => true,
            RootSampling::AlwaysOff => false,
            RootSampling::Ratio(ratio) => sample_ratio(ratio),
        }
    }

    fn store_sampling(metadata: &mut HashMap<String, String>, sampled: bool) {
        metadata.insert(
            "trace_sampled".to_string(),
            if sampled { "true" } else { "false" }.to_string(),
        );
    }

    fn apply_generated_root(&self, ctx_metadata: &mut HashMap<String, String>) -> String {
        let sampled = self.decide_root_sampled();
        let generated = Self::generate_trace_context(sampled);
        ctx_metadata.insert("trace_id".to_string(), generated.trace_id);
        ctx_metadata.insert("span_id".to_string(), generated.span_id);
        ctx_metadata.remove("parent_span_id");
        Self::store_sampling(ctx_metadata, generated.sampled);
        generated.traceparent
    }

    fn maybe_export(&self, span: SpanData) {
        if let Some(exporter) = &self.exporter
            && let Err(error) = exporter.try_export(span)
        {
            let now_ms = crate::socket_opts::monotonic_now_ms();
            let suppressed = match self.export_drop_log_limiter.lock() {
                Ok(mut limiter) => limiter.on_event(now_ms),
                Err(poisoned) => poisoned.into_inner().on_event(now_ms),
            };
            if let Some(suppressed) = suppressed {
                warn!(
                    provider = exporter.provider_name(),
                    suppressed = suppressed,
                    error = %error,
                    "trace export buffer rejected a span"
                );
            }
        }
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

    fn requires_ws_disconnect_hooks(&self) -> bool {
        true
    }

    async fn on_stream_connect(
        &self,
        ctx: &mut super::StreamConnectionContext,
    ) -> super::PluginResult {
        if self.generate_trace_id {
            let sampled = self.decide_root_sampled();
            let generated = Self::generate_trace_context(sampled);
            ctx.insert_metadata("trace_id".to_string(), generated.trace_id);
            ctx.insert_metadata("span_id".to_string(), generated.span_id);
            ctx.insert_metadata(
                "trace_sampled".to_string(),
                if generated.sampled {
                    "true".to_string()
                } else {
                    "false".to_string()
                },
            );
            ctx.insert_metadata(TRACEPARENT_HEADER.to_string(), generated.traceparent);
        }
        super::PluginResult::Continue
    }

    async fn on_stream_disconnect(&self, summary: &StreamTransactionSummary) {
        let Some(trace_id) = summary.metadata.get("trace_id") else {
            return;
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
            namespace = %summary.namespace,
            client_ip = %summary.client_ip,
            duration_ms = %summary.duration_ms,
            bytes_sent = %summary.bytes_sent,
            bytes_received = %summary.bytes_received,
            "stream trace"
        );

        if !trace_is_sampled(&summary.metadata) {
            return;
        }
        if let Some(span_data) =
            SpanData::from_stream_summary(summary, &self.service_name, self.max_attribute_bytes)
        {
            self.maybe_export(span_data);
        }
    }

    async fn on_ws_disconnect(&self, ctx: &WsDisconnectContext) {
        let Some(trace_id) = ctx.metadata.get("trace_id") else {
            return;
        };
        tracing::info!(
            target: "otel",
            service_name = %self.service_name,
            trace_id = %trace_id,
            proxy_id = %ctx.proxy_id,
            namespace = %ctx.namespace,
            duration_ms = %ctx.duration_ms,
            "websocket session trace"
        );
        if !trace_is_sampled(&ctx.metadata) {
            return;
        }
        if let Some(span_data) =
            SpanData::from_ws_disconnect(ctx, &self.service_name, self.max_attribute_bytes)
        {
            self.maybe_export(span_data);
        }
    }

    async fn on_request_received(&self, ctx: &mut RequestContext) -> PluginResult {
        // Capture bounded client-facing authority for SERVER span attributes.
        if let Some(port) = ctx.frontend_listen_port {
            ctx.metadata
                .insert("frontend_listen_port".to_string(), port.to_string());
        }
        if let Some((address, port)) = ctx
            .request_authority
            .as_deref()
            .or_else(|| {
                ctx.headers
                    .get("host")
                    .or_else(|| {
                        ctx.headers
                            .iter()
                            .find(|(k, _)| k.eq_ignore_ascii_case("host"))
                            .map(|(_, v)| v)
                    })
                    .map(String::as_str)
            })
            .and_then(parse_host_header_authority)
        {
            ctx.metadata
                .insert("server_address".to_string(), truncate_attr(&address, 256));
            if let Some(port) = port {
                ctx.metadata
                    .insert("server_port".to_string(), port.to_string());
            }
        }

        let incoming = unique_header_value_case_insensitive(&ctx.headers, TRACEPARENT_HEADER)
            .ok()
            .flatten()
            .map(str::to_owned);
        let incoming_tracestate =
            unique_header_value_case_insensitive(&ctx.headers, TRACESTATE_HEADER)
                .ok()
                .flatten()
                .map(str::to_owned);
        // A companion state is valid only when this hook accepts the parent.
        // Clear any pre-existing metadata value before adjudicating the wire
        // headers so another plugin cannot accidentally preserve stale state.
        ctx.metadata.remove(TRACESTATE_HEADER);

        let traceparent = match incoming.as_deref().and_then(Self::parse_traceparent) {
            Some(parsed) => {
                let parent_sampled = flags_sampled(parsed.flags);
                match self.trace_context_trust {
                    TraceContextTrust::Trusted => {
                        let gateway_span = Self::generate_span_id();
                        ctx.metadata
                            .insert("trace_id".to_string(), parsed.trace_id.to_string());
                        ctx.metadata.insert(
                            "parent_span_id".to_string(),
                            parsed.parent_span_id.to_string(),
                        );
                        ctx.metadata
                            .insert("span_id".to_string(), gateway_span.clone());
                        Self::store_sampling(&mut ctx.metadata, parent_sampled);
                        if let Some(tracestate) = incoming_tracestate {
                            ctx.metadata
                                .insert(TRACESTATE_HEADER.to_string(), tracestate);
                        }
                        build_traceparent(
                            SUPPORTED_TRACEPARENT_VERSION,
                            parsed.trace_id,
                            &gateway_span,
                            if parent_sampled { "01" } else { "00" },
                        )
                    }
                    TraceContextTrust::Untrusted => {
                        // Fail closed: create a fresh root and retain none of the
                        // attacker-chosen identity as exported trace material.
                        if !self.generate_trace_id {
                            return PluginResult::Continue;
                        }
                        // Drop companion tracestate — parent was not trusted.
                        self.apply_generated_root(&mut ctx.metadata)
                    }
                }
            }
            None => {
                // Invalid/absent parent: never carry companion tracestate into a new trace.
                if !self.generate_trace_id {
                    return PluginResult::Continue;
                }
                self.apply_generated_root(&mut ctx.metadata)
            }
        };

        ctx.metadata
            .insert(TRACEPARENT_HEADER.to_string(), traceparent);

        PluginResult::Continue
    }

    async fn before_proxy(
        &self,
        ctx: &mut RequestContext,
        headers: &mut HashMap<String, String>,
    ) -> PluginResult {
        // Request headers are case-insensitive but represented as a String map.
        // Remove every casing first so invalid/untrusted caller context cannot
        // survive when generation is disabled, and so replacement never leaves
        // duplicate wire fields.
        headers.retain(|name, _| {
            !name.eq_ignore_ascii_case(TRACEPARENT_HEADER)
                && !name.eq_ignore_ascii_case(TRACESTATE_HEADER)
        });
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
        if let Some(traceparent) = ctx.metadata.get(TRACEPARENT_HEADER) {
            response_headers.insert(TRACEPARENT_HEADER.to_string(), traceparent.clone());
        }
        PluginResult::Continue
    }

    fn applies_after_proxy_on_reject(&self) -> bool {
        true
    }

    fn owns_deadline_response_header(&self, ctx: &RequestContext, name: &str) -> bool {
        name.eq_ignore_ascii_case(TRACEPARENT_HEADER)
            && ctx.metadata.contains_key(TRACEPARENT_HEADER)
    }

    /// `after_proxy` echoes the gateway-authored `traceparent`. A backend that
    /// echoes the identical value back (the normal W3C propagation case) makes
    /// that write invisible to observed-mutation reconciliation, so without this
    /// declaration a backend `traceparent` TRAILER would land after the write
    /// and hand the client a trace context the gateway did not author.
    fn response_trailer_policy(&self) -> super::ResponseTrailerPolicy<'_> {
        super::ResponseTrailerPolicy::Names(&super::TRACEPARENT_RESPONSE_POLICY_NAMES)
    }

    async fn log(&self, summary: &TransactionSummary) {
        let Some(trace_id) = summary.metadata.get("trace_id") else {
            return;
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

        tracing::info!(
            target: "otel",
            service_name = %self.service_name,
            trace_id = %trace_id,
            span_id = %span_id,
            parent_span_id = %parent_span_id,
            namespace = %summary.namespace,
            http_method = %summary.http_method,
            http_status_code = %summary.response_status_code,
            http_client_ip = %summary.client_ip,
            duration_ms = %summary.latency_total_ms,
            backend_ms = %summary.latency_backend_total_ms,
            "request trace"
        );

        if !trace_is_sampled(&summary.metadata) {
            return;
        }

        if let Some(span_data) = SpanData::from_transaction_summary(
            summary,
            &self.service_name,
            self.include_url_path,
            self.max_attribute_bytes,
        ) {
            self.maybe_export(span_data);
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
    buffer_max_bytes: usize,
    max_retries: u32,
    retry_delay: Duration,
    service_name: String,
    deployment_environment: Option<String>,
    /// Retained-byte ceiling every exporter built from these options charges.
    ceiling: &'static RetainedByteCeiling,
}

impl TraceExporterOptions {
    /// Rebind these options to an explicit ceiling. External tests use this so
    /// batch-materialization assertions run against their own leaked ceiling.
    // The binary target always keeps the process ceiling from `from_config`.
    #[allow(dead_code)]
    pub(crate) fn with_ceiling(mut self, ceiling: &'static RetainedByteCeiling) -> Self {
        self.ceiling = ceiling;
        self
    }

    pub(crate) fn from_config(
        config: &Value,
        service_name: String,
        http_client: PluginHttpClient,
    ) -> Result<Self, String> {
        Ok(Self {
            http_client,
            batch_size: usize_config_range(
                config,
                "batch_size",
                DEFAULT_BATCH_SIZE,
                MIN_BATCH_SIZE,
                MAX_BATCH_SIZE,
            )?,
            flush_interval: Duration::from_millis(u64_config_range(
                config,
                "flush_interval_ms",
                DEFAULT_FLUSH_INTERVAL_MS,
                MIN_FLUSH_INTERVAL_MS,
                MAX_FLUSH_INTERVAL_MS,
            )?),
            buffer_capacity: usize_config_range(
                config,
                "buffer_capacity",
                DEFAULT_BUFFER_CAPACITY,
                MIN_BUFFER_CAPACITY,
                MAX_BUFFER_CAPACITY,
            )?,
            buffer_max_bytes: usize_config_range(
                config,
                "buffer_max_bytes",
                DEFAULT_BUFFER_MAX_BYTES,
                MIN_BUFFER_MAX_BYTES,
                MAX_BUFFER_MAX_BYTES,
            )?,
            max_retries: u32_config_range(
                config,
                "max_retries",
                DEFAULT_MAX_RETRIES,
                MIN_MAX_RETRIES,
                MAX_MAX_RETRIES,
            )?,
            retry_delay: Duration::from_millis(u64_config_range(
                config,
                "retry_delay_ms",
                DEFAULT_RETRY_DELAY_MS,
                MIN_RETRY_DELAY_MS,
                MAX_RETRY_DELAY_MS,
            )?),
            service_name,
            deployment_environment: optional_string_config(config, "deployment_environment")?,
            ceiling: process_ceiling(),
        })
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
    endpoint_for_logs: String,
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
    /// Ceiling the queued spans *and* every batch representation built from them
    /// are charged to. Always the process ceiling in production.
    ceiling: &'static RetainedByteCeiling,
}

struct QueuedSpan {
    span: SpanData,
    bytes: usize,
    /// Matching reservation against the process-wide observability ceiling.
    /// Held for exactly as long as the span is retained (queue plus the
    /// worker's in-flight batch), so multiple exporters cannot multiply past
    /// the process total.
    process: ProcessByteReservation,
}

struct BufferedTraceExporter {
    provider_name: &'static str,
    hostname: String,
    sender: mpsc::Sender<QueuedSpan>,
    queued_bytes: Arc<AtomicUsize>,
    queued_spans: Arc<AtomicUsize>,
    buffer_max_bytes: usize,
    started: AtomicBool,
    worker: OnceLock<Arc<DeliveryWorkerControl>>,
    deferred_start: Mutex<Option<(mpsc::Receiver<QueuedSpan>, TraceHttpExporterConfig)>>,
    ceiling: &'static RetainedByteCeiling,
}

impl BufferedTraceExporter {
    fn new(
        cfg: TraceHttpExporterConfig,
        buffer_capacity: usize,
        buffer_max_bytes: usize,
    ) -> Result<Self, String> {
        let hostname = validate_endpoint_for_provider(cfg.provider_name, &cfg.endpoint)?;
        let (sender, receiver) = mpsc::channel(buffer_capacity);
        let provider_name = cfg.provider_name;
        let queued_bytes = Arc::new(AtomicUsize::new(0));
        let ceiling = cfg.ceiling;
        Ok(Self {
            provider_name,
            hostname,
            sender,
            queued_bytes,
            queued_spans: Arc::new(AtomicUsize::new(0)),
            buffer_max_bytes,
            started: AtomicBool::new(false),
            worker: OnceLock::new(),
            deferred_start: Mutex::new(Some((receiver, cfg))),
            ceiling,
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
                let pending_spans = Arc::clone(&self.queued_spans);
                let (worker, close_rx) = DeliveryWorkerControl::new("otel_tracing", move || {
                    pending_spans.load(Ordering::Relaxed) as u64
                });
                if self.worker.set(Arc::clone(&worker)).is_err() {
                    *deferred = Some((receiver, cfg));
                    return Err("trace exporter lifecycle worker already started".to_string());
                }
                let completion = worker.completion();
                let worker_drain_control = Arc::clone(&worker);
                let queued_bytes = Arc::clone(&self.queued_bytes);
                let queued_spans = Arc::clone(&self.queued_spans);
                let task = handle.spawn(async move {
                    let mut completion = completion;
                    trace_export_flush_loop(
                        receiver,
                        cfg,
                        queued_bytes,
                        queued_spans,
                        worker_drain_control,
                        close_rx,
                    )
                    .await;
                    completion.complete();
                });
                worker
                    .install_abort_handle(task.abort_handle())
                    .map_err(|error| error.to_string())?;
                drop(task);
                crate::observability_delivery::register_worker(worker);
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

    /// Reserve `bytes` against the process ceiling first, then this exporter's
    /// own queued-byte budget. Returning the process reservation to the caller
    /// keeps release tied to the span's actual retention lifetime; a failed
    /// per-instance reservation drops it here so nothing leaks.
    fn try_reserve_queued_bytes(&self, bytes: usize) -> Result<ProcessByteReservation, String> {
        let process = self.ceiling.try_acquire(bytes).ok_or_else(|| {
            format!(
                "process-wide observability retained-byte ceiling exceeded (+{bytes} > {})",
                self.ceiling.max()
            )
        })?;
        self.queued_bytes
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |current| {
                current
                    .checked_add(bytes)
                    .filter(|next| *next <= self.buffer_max_bytes)
            })
            .map(|_| process)
            .map_err(|current| {
                format!(
                    "queued byte budget exceeded ({current}+{bytes} > {})",
                    self.buffer_max_bytes
                )
            })
    }
}

impl Drop for BufferedTraceExporter {
    fn drop(&mut self) {
        if let Some(worker) = self.worker.get() {
            worker.close_admission();
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
        let worker = self
            .worker
            .get()
            .ok_or_else(|| "trace exporter worker is unavailable".to_string())?;
        let Some(_admission) = worker.try_admit() else {
            return Err("trace exporter is shutting down".to_string());
        };
        self.queued_spans.fetch_add(1, Ordering::Relaxed);
        let bytes = span.approx_queued_bytes();
        let process = match self.try_reserve_queued_bytes(bytes) {
            Ok(process) => process,
            Err(error) => {
                decrement_queued_spans(&self.queued_spans, 1);
                return Err(error);
            }
        };
        match self.sender.try_send(QueuedSpan {
            span,
            bytes,
            process,
        }) {
            Ok(()) => Ok(()),
            Err(error) => {
                // The rejected `QueuedSpan` carries the process reservation and
                // releases it on drop; only the per-instance charge is manual.
                self.queued_bytes.fetch_sub(bytes, Ordering::AcqRel);
                decrement_queued_spans(&self.queued_spans, 1);
                Err(error.to_string())
            }
        }
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
        )?;
        Ok(Self {
            inner: BufferedTraceExporter::new(
                cfg,
                options.buffer_capacity,
                options.buffer_max_bytes,
            )?,
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
        )?;
        Ok(Self {
            inner: BufferedTraceExporter::new(
                cfg,
                options.buffer_capacity,
                options.buffer_max_bytes,
            )?,
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
        )?;
        Ok(Self {
            inner: BufferedTraceExporter::new(
                cfg,
                options.buffer_capacity,
                options.buffer_max_bytes,
            )?,
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
        )?;
        Ok(Self {
            inner: BufferedTraceExporter::new(
                cfg,
                options.buffer_capacity,
                options.buffer_max_bytes,
            )?,
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
    ) -> Result<Self, String> {
        let parsed = Url::parse(&endpoint)
            .map_err(|e| format!("{provider_name}: 'endpoint' must be a valid URL: {e}"))?;
        if !parsed.username().is_empty() || parsed.password().is_some() {
            return Err(format!(
                "{provider_name}: 'endpoint' must not contain user information; use authorization or headers"
            ));
        }
        let endpoint_for_logs = redacted_endpoint_url(&parsed);
        Ok(Self {
            provider_name,
            endpoint,
            endpoint_for_logs,
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
            ceiling: options.ceiling,
        })
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

/// Observations from [`probe_trace_batch_materialization_for_test`].
#[derive(Debug, Clone, Copy)]
#[allow(dead_code)] // field reads happen only in `_test_support` wrappers
pub(crate) struct TraceMaterializationProbe {
    /// Ceiling bytes held by the queued spans alone.
    pub(crate) queued_bytes: usize,
    /// Ceiling bytes held while the queued spans and the materialized body
    /// coexist. Must exceed `queued_bytes` — that difference is the batch
    /// representation the ceiling previously never saw.
    pub(crate) peak_bytes: usize,
    /// Ceiling bytes after the body (and every retry handle) is dropped.
    pub(crate) after_body_dropped_bytes: usize,
    /// Ceiling bytes after the queued spans release too. Must be zero.
    pub(crate) after_release_bytes: usize,
    /// `true` when the ceiling refused the batch representation.
    pub(crate) refused: bool,
    pub(crate) rejections: u64,
}

/// Deterministic batch-materialization probe for external unit tests.
///
/// Charges `span_count` synthetic spans to `ceiling` exactly as the exporter
/// queue does, then materializes one export body while those reservations are
/// still held, so an external test can pin that the body is charged, released on
/// drop, and refused rather than materialized when the ceiling is exhausted.
#[allow(dead_code)] // reached via `_test_support` from the external test crate
pub(crate) fn probe_trace_batch_materialization_for_test(
    ceiling: &'static RetainedByteCeiling,
    span_count: usize,
    attribute_bytes: usize,
) -> Option<TraceMaterializationProbe> {
    let cfg = TraceHttpExporterConfig {
        provider_name: "OTLP",
        endpoint: "http://127.0.0.1:4318/v1/traces".to_string(),
        endpoint_for_logs: "http://127.0.0.1:4318/v1/traces".to_string(),
        authorization: None,
        custom_headers: Vec::new(),
        http_client: PluginHttpClient::default(),
        batch_size: span_count.max(1),
        flush_interval: Duration::from_secs(3600),
        max_retries: 0,
        retry_delay: Duration::from_millis(1),
        service_name: "ferrum-edge".to_string(),
        deployment_environment: None,
        payload_kind: TracePayloadKind::Otlp,
        ceiling,
    };

    let mut spans = Vec::with_capacity(span_count);
    let mut reservations = Vec::with_capacity(span_count);
    for index in 0..span_count {
        let span = probe_span_for_test(index, attribute_bytes);
        reservations.push(ceiling.try_acquire(span.approx_queued_bytes())?);
        spans.push(span);
    }
    let queued_bytes = ceiling.used();

    match materialize_trace_body(&cfg, &spans) {
        Ok(body) => {
            let peak_bytes = ceiling.used();
            drop(body);
            let after_body_dropped_bytes = ceiling.used();
            drop(reservations);
            Some(TraceMaterializationProbe {
                queued_bytes,
                peak_bytes,
                after_body_dropped_bytes,
                after_release_bytes: ceiling.used(),
                refused: false,
                rejections: ceiling.rejections(),
            })
        }
        Err(error) => {
            let peak_bytes = ceiling.used();
            drop(reservations);
            Some(TraceMaterializationProbe {
                queued_bytes,
                peak_bytes,
                after_body_dropped_bytes: peak_bytes,
                after_release_bytes: ceiling.used(),
                refused: matches!(error, PayloadMaterializationError::CeilingExhausted),
                rejections: ceiling.rejections(),
            })
        }
    }
}

#[allow(dead_code)] // reached only from the probe above
fn probe_span_for_test(index: usize, attribute_bytes: usize) -> SpanData {
    SpanData {
        trace_id: format!("{index:032x}"),
        span_id: format!("{index:016x}"),
        parent_span_id: String::new(),
        service_name: "ferrum-edge".to_string(),
        span_name: "GET probe".to_string(),
        span_kind: 2,
        span_kind_typed: SpanKind::Server,
        http_method: "GET".to_string(),
        // Attacker-shaped field: escaped six-fold by the JSON body bound.
        http_url: "\"".repeat(attribute_bytes),
        http_status_code: Some(200),
        grpc_status: None,
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
        proxy_id: Some("proxy-probe".to_string()),
        matched_route: Some("probe".to_string()),
        namespace: Some("ferrum".to_string()),
        server_address: Some("edge.example".to_string()),
        server_port: Some(443),
        backend_target: None,
        backend_host: None,
        backend_port: None,
        backend_resolved_ip: None,
        error_class: None,
        body_error_class: None,
        body_completed: true,
        response_streamed: false,
        client_disconnected: false,
        otlp_error: false,
        mesh_attributes: Vec::new(),
        stream_protocol: None,
        stream_listen_port: None,
        stream_bytes_sent: None,
        stream_bytes_received: None,
        disconnect_direction: None,
        disconnect_cause: None,
        stream_io_side: None,
        ws_frames_client_to_backend: None,
        ws_frames_backend_to_client: None,
    }
}

pub(crate) fn validate_trace_provider_endpoints(
    providers: &[TracingProvider],
) -> Result<(), String> {
    for provider in providers {
        match provider {
            TracingProvider::Zipkin { url } => {
                validate_endpoint_for_provider("Zipkin", url)?;
            }
            TracingProvider::Datadog { agent_url, .. } => {
                let endpoint = datadog_traces_endpoint(agent_url)?;
                validate_endpoint_for_provider("Datadog", &endpoint)?;
            }
            TracingProvider::Lightstep { collector_url, .. } => {
                validate_endpoint_for_provider("Lightstep", collector_url)?;
            }
            TracingProvider::OpenTelemetry { endpoint } => {
                validate_endpoint_for_provider("OTLP", endpoint)?;
            }
        }
    }
    Ok(())
}

fn parse_custom_headers(value: Option<&Value>) -> Result<Vec<(String, String)>, String> {
    let Some(value) = value else {
        return Ok(Vec::new());
    };
    let Value::Object(map) = value else {
        if value.is_null() {
            return Err("otel_tracing: 'headers' must be a non-null object".to_string());
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
    mut receiver: mpsc::Receiver<QueuedSpan>,
    cfg: TraceHttpExporterConfig,
    queued_bytes: Arc<AtomicUsize>,
    queued_spans: Arc<AtomicUsize>,
    worker: Arc<DeliveryWorkerControl>,
    mut close_rx: watch::Receiver<bool>,
) {
    let mut buffer: Vec<SpanData> = Vec::with_capacity(cfg.batch_size);
    // Process-ceiling reservations for the spans currently in `buffer`. They
    // are held for the whole retention window (queue plus in-flight batch) and
    // released together with the per-exporter charge after each send.
    let mut reservations: Vec<ProcessByteReservation> = Vec::with_capacity(cfg.batch_size);
    let mut buffered_bytes = 0usize;
    let mut timer = tokio::time::interval(cfg.flush_interval);
    let mut closing = *close_rx.borrow();
    if closing {
        worker.wait_for_admissions().await;
        receiver.close();
    }
    timer.tick().await;

    loop {
        tokio::select! {
            biased;

            _ = close_rx.changed(), if !closing => {
                closing = true;
                worker.wait_for_admissions().await;
                receiver.close();
            }

            msg = receiver.recv() => {
                match msg {
                    Some(queued) => {
                        buffered_bytes = buffered_bytes.saturating_add(queued.bytes);
                        buffer.push(queued.span);
                        reservations.push(queued.process);
                        if buffer.len() >= cfg.batch_size {
                            let span_count = buffer.len();
                            send_trace_batch(&cfg, &buffer).await;
                            queued_bytes.fetch_sub(buffered_bytes, Ordering::AcqRel);
                            decrement_queued_spans(&queued_spans, span_count);
                            buffer.clear();
                            reservations.clear();
                            buffered_bytes = 0;
                        }
                    }
                    None => {
                        if !buffer.is_empty() {
                            let span_count = buffer.len();
                            send_trace_batch(&cfg, &buffer).await;
                            queued_bytes.fetch_sub(buffered_bytes, Ordering::AcqRel);
                            decrement_queued_spans(&queued_spans, span_count);
                            reservations.clear();
                        }
                        break;
                    }
                }
            }

            _ = timer.tick() => {
                if !buffer.is_empty() {
                    let span_count = buffer.len();
                    send_trace_batch(&cfg, &buffer).await;
                    queued_bytes.fetch_sub(buffered_bytes, Ordering::AcqRel);
                    decrement_queued_spans(&queued_spans, span_count);
                    buffer.clear();
                    reservations.clear();
                    buffered_bytes = 0;
                }
            }
        }
    }
}

fn decrement_queued_spans(queued_spans: &AtomicUsize, count: usize) {
    let _ = queued_spans.fetch_update(Ordering::Relaxed, Ordering::Relaxed, |value| {
        Some(value.saturating_sub(count))
    });
}

/// Heap a `serde_json::Value` tree costs for one exported span on top of the
/// span's own retained strings: a map or array node plus an owned key `String`
/// for every fixed attribute, event, and envelope field the exporter emits.
const TRACE_SPAN_VALUE_OVERHEAD_BYTES: usize = 16_384;
/// Serialized bytes one span's fixed JSON structure costs: attribute key names,
/// numeric fields, status and event objects, and the per-attribute wrapper around
/// each operator-named mesh attribute.
const TRACE_SPAN_JSON_OVERHEAD_BYTES: usize = 8_192;
/// Fixed resource/scope envelope emitted once per request body.
const TRACE_PAYLOAD_ENVELOPE_BYTES: usize = 4_096;

/// Conservative upper bound on the intermediate `serde_json::Value` tree for
/// `batch`. Every retained span string is cloned into the tree exactly once.
fn trace_value_byte_bound(batch: &[SpanData]) -> Option<usize> {
    let mut total = TRACE_PAYLOAD_ENVELOPE_BYTES;
    for span in batch {
        total = total
            .checked_add(span.approx_queued_bytes())?
            .checked_add(TRACE_SPAN_VALUE_OVERHEAD_BYTES)?;
    }
    Some(total)
}

/// Conservative upper bound on the serialized request body for `batch`. Span
/// strings are raw, so JSON escaping can expand each byte six-fold.
fn trace_body_byte_bound(batch: &[SpanData]) -> Option<usize> {
    let mut total = TRACE_PAYLOAD_ENVELOPE_BYTES;
    for span in batch {
        total = total
            .checked_add(
                span.approx_queued_bytes()
                    .checked_mul(JSON_STRING_WORST_CASE_EXPANSION)?,
            )?
            .checked_add(TRACE_SPAN_JSON_OVERHEAD_BYTES)?;
    }
    Some(total)
}

/// Reserve, build, and serialize one slice's request body under `cfg.ceiling`.
///
/// Both attacker-shaped copies that coexist with the still-charged queued spans —
/// the intermediate `Value` tree and the serialized body — are reserved *before*
/// they are materialized. The tree and its reservation die before the body is
/// delivered, so the retry loop holds exactly one bounded, immutable payload and
/// never re-serializes.
fn materialize_trace_body(
    cfg: &TraceHttpExporterConfig,
    batch: &[SpanData],
) -> Result<ReservedPayload, PayloadMaterializationError> {
    let value_bound =
        trace_value_byte_bound(batch).ok_or(PayloadMaterializationError::BoundOverflowed)?;
    let body_bound =
        trace_body_byte_bound(batch).ok_or(PayloadMaterializationError::BoundOverflowed)?;
    let value_reservation = cfg
        .ceiling
        .try_acquire(value_bound)
        .ok_or(PayloadMaterializationError::CeilingExhausted)?;
    let payload = match cfg.payload_kind {
        TracePayloadKind::Otlp => build_otlp_payload(
            &cfg.service_name,
            cfg.deployment_environment.as_deref(),
            batch,
        ),
        TracePayloadKind::Zipkin => build_zipkin_payload(&cfg.service_name, batch),
        TracePayloadKind::Datadog => build_datadog_payload(&cfg.service_name, batch),
    };
    let body = materialize_reserved_payload(cfg.ceiling, body_bound, |writer| {
        serde_json::to_writer(writer, &payload).map_err(|error| error.to_string())
    });
    drop(payload);
    drop(value_reservation);
    body
}

async fn send_trace_batch(cfg: &TraceHttpExporterConfig, batch: &[SpanData]) {
    // Materialize and deliver in slices small enough that each slice's reserved
    // batch representation fits under the ceiling. Trace export has no
    // cross-span batch semantics, so halving a refused slice preserves delivery
    // instead of dropping every span of a large `batch_size` outright.
    let mut start = 0usize;
    // Slice width carried across iterations. Restarting every slice at the full
    // remaining length would re-walk the same halving ladder — and re-count the
    // same ceiling rejections — for every span once a width has been refused.
    let mut window = batch.len().max(1);
    // Loss is aggregated across the whole flush and then handed to the shared
    // fixed-label accounting helper, which counts the lost *spans* separately
    // from the ceiling's refused-*reservation* counter and samples its warning.
    // Emitting one warning per refused slice would produce up to one line per
    // span while the ceiling is saturated, which is exactly when the process is
    // already under memory pressure.
    let mut lost_spans = 0usize;
    let mut loss_reason: Option<&'static str> = None;
    while start < batch.len() {
        let mut end = batch.len().min(start.saturating_add(window));
        loop {
            let slice = &batch[start..end];
            match materialize_trace_body(cfg, slice) {
                Ok(body) => {
                    window = end - start;
                    deliver_trace_payload(cfg, body, slice.len()).await;
                    start = end;
                    break;
                }
                Err(PayloadMaterializationError::CeilingExhausted) if end - start > 1 => {
                    end = start + (end - start) / 2;
                }
                Err(error) => {
                    lost_spans += end - start;
                    if loss_reason.is_none() {
                        loss_reason = Some(error.reason());
                    }
                    window = end - start;
                    start = end;
                    break;
                }
            }
        }
    }
    if let Some(reason) = loss_reason {
        record_batch_materialization_loss(cfg.provider_name, lost_spans as u64, reason);
    }
}

async fn deliver_trace_payload(
    cfg: &TraceHttpExporterConfig,
    body: ReservedPayload,
    entry_count: usize,
) {
    let total_attempts = cfg.max_retries + 1;

    for attempt in 1..=total_attempts {
        let request = match cfg.payload_kind {
            TracePayloadKind::Datadog => cfg.http_client.get().put(&cfg.endpoint),
            _ => cfg.http_client.get().post(&cfg.endpoint),
        };
        // One bounded serialization, reused across attempts: `bytes()` is a
        // refcount bump on the reserved payload, not another copy.
        let mut req = request
            .header("Content-Type", "application/json")
            .body(body.bytes());

        if let Some(auth) = &cfg.authorization {
            req = req.header("Authorization", auth);
        }

        for (key, value) in &cfg.custom_headers {
            req = req.header(key.as_str(), value.as_str());
        }

        match cfg
            .http_client
            .execute_redacted(req, "otel_export", &cfg.endpoint_for_logs)
            .await
        {
            Ok(response) if response.status().is_success() => {
                if matches!(cfg.payload_kind, TracePayloadKind::Otlp) {
                    handle_otlp_partial_success(cfg, response, entry_count).await;
                }
                return;
            }
            Ok(response) => {
                let status = response.status();
                warn!(
                    "{} export failed with status {} for {} (attempt {}/{})",
                    cfg.provider_name, status, cfg.endpoint_for_logs, attempt, total_attempts,
                );
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

async fn handle_otlp_partial_success(
    cfg: &TraceHttpExporterConfig,
    mut response: reqwest::Response,
    entry_count: usize,
) {
    let content_type = response
        .headers()
        .get(reqwest::header::CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .map(str::to_owned);
    let mut body = Vec::new();
    loop {
        let chunk = match response.chunk().await {
            Ok(Some(chunk)) => chunk,
            Ok(None) => break,
            Err(error) => {
                warn!(
                    provider = cfg.provider_name,
                    endpoint = %cfg.endpoint_for_logs,
                    %error,
                    "OTLP success body could not be read"
                );
                return;
            }
        };
        if body.len().saturating_add(chunk.len()) > MAX_OTLP_SUCCESS_BODY_BYTES {
            warn!(
                provider = cfg.provider_name,
                endpoint = %cfg.endpoint_for_logs,
                limit_bytes = MAX_OTLP_SUCCESS_BODY_BYTES,
                "OTLP success body exceeded the bounded response limit"
            );
            return;
        }
        body.extend_from_slice(&chunk);
    }
    if body.is_empty() {
        return;
    }
    if !content_type
        .as_deref()
        .map(otlp_json_content_type)
        .unwrap_or(true)
    {
        warn!(
            provider = cfg.provider_name,
            endpoint = %cfg.endpoint_for_logs,
            body_bytes = body.len(),
            "OTLP success body used a non-JSON content type"
        );
        return;
    }
    let Ok(value) = serde_json::from_slice::<Value>(&body) else {
        warn!(
            provider = cfg.provider_name,
            endpoint = %cfg.endpoint_for_logs,
            body_bytes = body.len(),
            "OTLP success body was not valid JSON"
        );
        return;
    };
    let Some(partial_value) = value
        .get("partialSuccess")
        .or_else(|| value.get("partial_success"))
    else {
        return;
    };
    if partial_value.is_null() {
        return;
    }
    let Some(partial) = partial_value.as_object() else {
        warn!(
            provider = cfg.provider_name,
            endpoint = %cfg.endpoint_for_logs,
            body_bytes = body.len(),
            "OTLP partial-success field was not a JSON object"
        );
        return;
    };
    let rejected_value = partial
        .get("rejectedSpans")
        .or_else(|| partial.get("rejected_spans"));
    let rejected = match rejected_value {
        None | Some(Value::Null) => 0,
        Some(value) => match value
            .as_u64()
            .or_else(|| value.as_i64().and_then(|number| u64::try_from(number).ok()))
            .or_else(|| value.as_str().and_then(|number| number.parse::<u64>().ok()))
        {
            Some(rejected) => rejected,
            None => {
                warn!(
                    provider = cfg.provider_name,
                    endpoint = %cfg.endpoint_for_logs,
                    body_bytes = body.len(),
                    "OTLP partial-success rejected-spans field was invalid"
                );
                return;
            }
        },
    };
    let message_value = partial
        .get("errorMessage")
        .or_else(|| partial.get("error_message"));
    let message = match message_value {
        None | Some(Value::Null) => "",
        Some(Value::String(message)) => message.as_str(),
        Some(_) => {
            warn!(
                provider = cfg.provider_name,
                endpoint = %cfg.endpoint_for_logs,
                body_bytes = body.len(),
                "OTLP partial-success error-message field was invalid"
            );
            return;
        }
    };
    let message = bounded_log_value(message, MAX_PARTIAL_SUCCESS_MESSAGE_BYTES);
    if rejected > 0 || !message.is_empty() {
        warn!(
            provider = cfg.provider_name,
            endpoint = %cfg.endpoint_for_logs,
            rejected_spans = rejected,
            batch_spans = entry_count,
            error_message = %message,
            "OTLP partial success"
        );
    }
}

fn otlp_json_content_type(content_type: &str) -> bool {
    let media_type = content_type
        .split(';')
        .next()
        .unwrap_or("")
        .trim()
        .to_ascii_lowercase();
    media_type == "application/json" || media_type.ends_with("+json")
}

fn bounded_log_value(value: &str, max_bytes: usize) -> String {
    let mut output = String::with_capacity(value.len().min(max_bytes));
    for character in value.chars() {
        let character = if character.is_control() {
            ' '
        } else {
            character
        };
        if output.len().saturating_add(character.len_utf8()) > max_bytes {
            break;
        }
        output.push(character);
    }
    output
}

fn build_otlp_payload(
    service_name: &str,
    deployment_environment: Option<&str>,
    spans: &[SpanData],
) -> Value {
    let otlp_spans: Vec<Value> = spans
        .iter()
        .map(|s| {
            let trace_id_bytes = hex_to_base64(&s.trace_id);
            let span_id_bytes = hex_to_base64(&s.span_id);
            let parent_span_bytes = if s.parent_span_id.is_empty() {
                String::new()
            } else {
                hex_to_base64(&s.parent_span_id)
            };

            let start_ns = timestamp_nanos(&s.timestamp_received);
            let end_ns = start_ns + (s.duration_ms.max(0.0) * 1_000_000.0) as i64;

            let mut attributes = vec![
                otlp_attribute("http.request.method", &s.http_method),
                otlp_attribute("client.address", &s.client_ip),
                otlp_attribute("service.name", &s.service_name),
                otlp_attribute_double("gateway.latency.total_ms", s.duration_ms),
                otlp_attribute_double("gateway.latency.backend_ttfb_ms", s.backend_ttfb_ms),
            ];
            // Omit LATENCY_UNKNOWN_MS (-1) sentinel values rather than exporting
            // them as concrete timing observations (matches backend_total_ms).
            if s.gateway_processing_ms >= 0.0 {
                attributes.push(otlp_attribute_double(
                    "gateway.latency.processing_ms",
                    s.gateway_processing_ms,
                ));
            }
            if !s.http_url.is_empty() {
                attributes.push(otlp_attribute("url.path", &s.http_url));
            }

            if let Some(status_code) = s.http_status_code {
                attributes.push(otlp_attribute_int(
                    "http.response.status_code",
                    status_code as i64,
                ));
            }
            if let Some(grpc_status) = s.grpc_status {
                attributes.push(otlp_attribute_int(
                    "rpc.grpc.status_code",
                    grpc_status as i64,
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
            if s.gateway_overhead_ms >= 0.0 {
                attributes.push(otlp_attribute_double(
                    "gateway.overhead_ms",
                    s.gateway_overhead_ms,
                ));
            }
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
            if let Some(ref namespace) = s.namespace {
                attributes.push(otlp_attribute("ferrum.namespace", namespace));
            }
            if let Some(ref address) = s.server_address {
                attributes.push(otlp_attribute("server.address", address));
            }
            if let Some(port) = s.server_port.or(s.stream_listen_port) {
                attributes.push(otlp_attribute_int("server.port", port as i64));
            }
            if let Some(ref host) = s.backend_host {
                attributes.push(otlp_attribute("gateway.backend.address", host));
            }
            if let Some(port) = s.backend_port {
                attributes.push(otlp_attribute_int("gateway.backend.port", port as i64));
            }
            if let Some(ref target) = s.backend_target {
                attributes.push(otlp_attribute("gateway.backend.target", target));
            }
            if let Some(ref resolved) = s.backend_resolved_ip {
                attributes.push(otlp_attribute("gateway.backend.resolved_address", resolved));
            }
            if let Some(ref protocol) = s.stream_protocol {
                attributes.push(otlp_attribute("network.protocol.name", protocol));
            }
            if let Some(bytes) = s.stream_bytes_sent {
                attributes.push(otlp_attribute_int(
                    "gateway.stream.bytes_sent",
                    u64_to_i64(bytes),
                ));
            }
            if let Some(bytes) = s.stream_bytes_received {
                attributes.push(otlp_attribute_int(
                    "gateway.stream.bytes_received",
                    u64_to_i64(bytes),
                ));
            }
            if let Some(frames) = s.ws_frames_client_to_backend {
                attributes.push(otlp_attribute_int(
                    "gateway.websocket.frames_client_to_backend",
                    u64_to_i64(frames),
                ));
            }
            if let Some(frames) = s.ws_frames_backend_to_client {
                attributes.push(otlp_attribute_int(
                    "gateway.websocket.frames_backend_to_client",
                    u64_to_i64(frames),
                ));
            }
            if let Some(ref direction) = s.disconnect_direction {
                attributes.push(otlp_attribute("gateway.disconnect.direction", direction));
            }
            if let Some(ref cause) = s.disconnect_cause {
                attributes.push(otlp_attribute("gateway.disconnect.cause", cause));
            }
            if let Some(ref io_side) = s.stream_io_side {
                attributes.push(otlp_attribute("gateway.disconnect.io_side", io_side));
            }
            if s.response_streamed {
                attributes.push(otlp_attribute_bool("gateway.response.streamed", true));
            }
            if s.client_disconnected {
                attributes.push(otlp_attribute_bool("gateway.client.disconnected", true));
            }
            if let Some(ref body_error) = s.body_error_class {
                attributes.push(otlp_attribute("gateway.body.error_class", body_error));
            }
            if let Some(ref error_class) = s.error_class {
                attributes.push(otlp_attribute("gateway.error.class", error_class));
            }
            if s.response_streamed {
                attributes.push(otlp_attribute_bool(
                    "gateway.body.completed",
                    s.body_completed,
                ));
            }
            for (key, value) in &s.mesh_attributes {
                attributes.push(otlp_attribute(key, value));
            }

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
            if let Some(ref body_error) = s.body_error_class {
                events.push(serde_json::json!({
                    "name": "exception",
                    "timeUnixNano": end_ns.to_string(),
                    "attributes": [
                        otlp_attribute("exception.type", "BodyError"),
                        otlp_attribute("exception.message", body_error),
                    ]
                }));
            }
            if let Some(grpc_status) = s.grpc_status.filter(|status| *status != 0) {
                events.push(serde_json::json!({
                    "name": "exception",
                    "timeUnixNano": end_ns.to_string(),
                    "attributes": [
                        otlp_attribute("exception.type", "GrpcStatus"),
                        otlp_attribute("exception.message", &format!("grpc-status {grpc_status}")),
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
            if let Some(ref cause) = s.disconnect_cause {
                let mut disconnect_attributes =
                    vec![otlp_attribute("gateway.disconnect.cause", cause)];
                if let Some(ref direction) = s.disconnect_direction {
                    disconnect_attributes
                        .push(otlp_attribute("gateway.disconnect.direction", direction));
                }
                if let Some(ref io_side) = s.stream_io_side {
                    disconnect_attributes
                        .push(otlp_attribute("gateway.disconnect.io_side", io_side));
                }
                events.push(serde_json::json!({
                    "name": "gateway.disconnect",
                    "timeUnixNano": end_ns.to_string(),
                    "attributes": disconnect_attributes
                }));
            }

            let status_code = if s.otlp_error { 2 } else { 1 };

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

fn push_common_tags(tags: &mut serde_json::Map<String, Value>, span: &SpanData) {
    insert_tag(tags, "http.method", &span.http_method);
    if !span.http_url.is_empty() {
        insert_tag(tags, "http.path", &span.http_url);
    }
    if let Some(status_code) = span.http_status_code {
        insert_tag(tags, "http.status_code", &status_code.to_string());
    }
    if let Some(grpc_status) = span.grpc_status {
        insert_tag(tags, "rpc.grpc.status_code", &grpc_status.to_string());
    }
    insert_tag(tags, "client.ip", &span.client_ip);
    insert_tag(
        tags,
        "gateway.latency.total_ms",
        &span.duration_ms.to_string(),
    );
    if let Some(ref proxy_id) = span.proxy_id {
        insert_tag(tags, "gateway.proxy.id", proxy_id);
    }
    if let Some(ref route) = span.matched_route {
        insert_tag(tags, "http.route", route);
    }
    if let Some(ref namespace) = span.namespace {
        insert_tag(tags, "ferrum.namespace", namespace);
    }
    if let Some(ref address) = span.server_address {
        insert_tag(tags, "server.address", address);
    }
    if let Some(port) = span.server_port.or(span.stream_listen_port) {
        insert_tag(tags, "server.port", &port.to_string());
    }
    if let Some(ref host) = span.backend_host {
        insert_tag(tags, "gateway.backend.address", host);
    }
    if let Some(port) = span.backend_port {
        insert_tag(tags, "gateway.backend.port", &port.to_string());
    }
    if let Some(ref target) = span.backend_target {
        insert_tag(tags, "gateway.backend.target", target);
    }
    if let Some(ref resolved) = span.backend_resolved_ip {
        insert_tag(tags, "gateway.backend.resolved_address", resolved);
    }
    if let Some(ref protocol) = span.stream_protocol {
        insert_tag(tags, "network.protocol.name", protocol);
    }
    if let Some(bytes) = span.stream_bytes_sent {
        insert_tag(tags, "gateway.stream.bytes_sent", &bytes.to_string());
    }
    if let Some(bytes) = span.stream_bytes_received {
        insert_tag(tags, "gateway.stream.bytes_received", &bytes.to_string());
    }
    if let Some(frames) = span.ws_frames_client_to_backend {
        insert_tag(
            tags,
            "gateway.websocket.frames_client_to_backend",
            &frames.to_string(),
        );
    }
    if let Some(frames) = span.ws_frames_backend_to_client {
        insert_tag(
            tags,
            "gateway.websocket.frames_backend_to_client",
            &frames.to_string(),
        );
    }
    if let Some(ref direction) = span.disconnect_direction {
        insert_tag(tags, "gateway.disconnect.direction", direction);
    }
    if let Some(ref cause) = span.disconnect_cause {
        insert_tag(tags, "gateway.disconnect.cause", cause);
    }
    if let Some(ref io_side) = span.stream_io_side {
        insert_tag(tags, "gateway.disconnect.io_side", io_side);
    }
    if let Some(ref error_class) = span.error_class {
        insert_tag(tags, "gateway.error.class", error_class);
    }
    if let Some(ref body_error_class) = span.body_error_class {
        insert_tag(tags, "gateway.body.error_class", body_error_class);
    }
    if span.response_streamed {
        insert_tag(tags, "gateway.response.streamed", "true");
        insert_tag(
            tags,
            "gateway.body.completed",
            if span.body_completed { "true" } else { "false" },
        );
    }
    if span.client_disconnected {
        insert_tag(tags, "gateway.client.disconnected", "true");
    }
    for (key, value) in &span.mesh_attributes {
        insert_tag(tags, key, value);
    }
}

fn build_zipkin_payload(service_name: &str, spans: &[SpanData]) -> Value {
    let zipkin_spans: Vec<Value> = spans
        .iter()
        .map(|span| {
            let start_us = timestamp_micros(&span.timestamp_received);
            let duration_us = (span.duration_ms.max(0.0) * 1_000.0) as i64;
            let mut tags = serde_json::Map::new();
            push_common_tags(&mut tags, span);
            if span.otlp_error {
                let reason = span
                    .error_class
                    .as_deref()
                    .or(span.body_error_class.as_deref())
                    .unwrap_or("true");
                insert_tag(&mut tags, "error", reason);
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
    push_common_tags(&mut meta, span);
    if let Some(high_trace_bits) = datadog_high_trace_id(&span.trace_id) {
        insert_tag(&mut meta, "_dd.p.tid", high_trace_bits);
    }

    let mut metrics = serde_json::Map::new();
    // Sampled exports only reach Datadog; keep sampling priority affirmative.
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
    if span.otlp_error {
        metrics.insert("error".to_string(), serde_json::json!(1.0_f64));
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
        "error": if span.otlp_error { 1 } else { 0 },
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

fn timestamp_before_now(duration_ms: f64) -> String {
    let now = chrono::Utc::now();
    let bounded_ms = if duration_ms.is_finite() {
        duration_ms.clamp(0.0, i64::MAX as f64 / 1_000.0)
    } else {
        0.0
    };
    now.checked_sub_signed(chrono::Duration::microseconds(
        (bounded_ms * 1_000.0) as i64,
    ))
    .unwrap_or(now)
    .to_rfc3339()
}

fn u64_to_i64(value: u64) -> i64 {
    i64::try_from(value).unwrap_or(i64::MAX)
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
        None => Ok(default.to_string()),
        Some(Value::Null) => Err(format!("otel_tracing: '{key}' must be a non-null string")),
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
        None => Ok(None),
        Some(Value::Null) => Err(format!("otel_tracing: '{key}' must be a non-null string")),
        Some(Value::String(value)) => {
            let trimmed = value.trim();
            if trimmed.is_empty() {
                Err(format!("otel_tracing: '{key}' must be a non-empty string"))
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
        None => Ok(default),
        Some(Value::Null) => Err(format!("otel_tracing: '{key}' must be a non-null boolean")),
        Some(Value::Bool(value)) => Ok(*value),
        Some(other) => Err(format!(
            "otel_tracing: '{key}' must be a boolean, got: {other}"
        )),
    }
}

fn u64_config_range(
    config: &Value,
    key: &str,
    default: u64,
    min: u64,
    max: u64,
) -> Result<u64, String> {
    let value = match config.get(key) {
        None => default,
        Some(Value::Null) => {
            return Err(format!(
                "otel_tracing: '{key}' must be a non-null non-negative integer"
            ));
        }
        Some(Value::Number(value)) => value
            .as_u64()
            .ok_or_else(|| format!("otel_tracing: '{key}' must be a non-negative integer"))?,
        Some(other) => {
            return Err(format!(
                "otel_tracing: '{key}' must be a non-negative integer, got: {other}"
            ));
        }
    };
    if value < min || value > max {
        return Err(format!(
            "otel_tracing: '{key}' must be between {min} and {max}, got: {value}"
        ));
    }
    Ok(value)
}

fn usize_config_range(
    config: &Value,
    key: &str,
    default: u64,
    min: u64,
    max: u64,
) -> Result<usize, String> {
    let value = u64_config_range(config, key, default, min, max)?;
    usize::try_from(value).map_err(|_| format!("otel_tracing: '{key}' is too large"))
}

fn u32_config_range(
    config: &Value,
    key: &str,
    default: u64,
    min: u64,
    max: u64,
) -> Result<u32, String> {
    let value = u64_config_range(config, key, default, min, max)?;
    u32::try_from(value).map_err(|_| format!("otel_tracing: '{key}' is too large"))
}

fn parse_trace_context_trust(config: &Value) -> Result<TraceContextTrust, String> {
    match config.get("trace_context_trust") {
        None => Ok(TraceContextTrust::Untrusted),
        Some(Value::Null) => {
            Err("otel_tracing: 'trace_context_trust' must be a non-null string".to_string())
        }
        Some(Value::String(value)) => match value.trim().to_ascii_lowercase().as_str() {
            "untrusted" => Ok(TraceContextTrust::Untrusted),
            "trusted" => Ok(TraceContextTrust::Trusted),
            other => Err(format!(
                "otel_tracing: 'trace_context_trust' must be 'trusted' or 'untrusted', got: {other}"
            )),
        },
        Some(other) => Err(format!(
            "otel_tracing: 'trace_context_trust' must be a string, got: {other}"
        )),
    }
}

fn parse_root_sampling(config: &Value) -> Result<RootSampling, String> {
    let mode = match config.get("root_sampling") {
        None => "always_on".to_string(),
        Some(Value::Null) => {
            return Err("otel_tracing: 'root_sampling' must be a non-null string".to_string());
        }
        Some(Value::String(value)) => value.trim().to_ascii_lowercase(),
        Some(other) => {
            return Err(format!(
                "otel_tracing: 'root_sampling' must be a string, got: {other}"
            ));
        }
    };
    let configured_ratio = match config.get("root_sampling_ratio") {
        None => None,
        Some(Value::Null) => {
            return Err(
                "otel_tracing: 'root_sampling_ratio' must be a non-null number".to_string(),
            );
        }
        Some(Value::Number(n)) => {
            let ratio = n.as_f64().ok_or_else(|| {
                "otel_tracing: 'root_sampling_ratio' must be a number between 0.0 and 1.0"
                    .to_string()
            })?;
            if !ratio.is_finite() || !(0.0..=1.0).contains(&ratio) {
                return Err(format!(
                    "otel_tracing: 'root_sampling_ratio' must be between 0.0 and 1.0, got: {ratio}"
                ));
            }
            Some(ratio)
        }
        Some(other) => {
            return Err(format!(
                "otel_tracing: 'root_sampling_ratio' must be a number, got: {other}"
            ));
        }
    };
    if configured_ratio.is_some() && mode != "ratio" {
        return Err(format!(
            "otel_tracing: 'root_sampling_ratio' requires root_sampling=ratio \
             (got root_sampling={mode})"
        ));
    }
    match mode.as_str() {
        "always_on" => Ok(RootSampling::AlwaysOn),
        "always_off" => Ok(RootSampling::AlwaysOff),
        "ratio" => {
            let ratio = configured_ratio.ok_or_else(|| {
                "otel_tracing: 'root_sampling_ratio' is required when root_sampling=ratio"
                    .to_string()
            })?;
            Ok(RootSampling::Ratio(ratio))
        }
        other => Err(format!(
            "otel_tracing: 'root_sampling' must be always_on, always_off, or ratio, got: {other}"
        )),
    }
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
    if !url.username().is_empty() || url.password().is_some() {
        return Err(format!(
            "{provider_name}: 'endpoint' must not contain user information; use authorization or headers"
        ));
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
    if !url.username().is_empty() || url.password().is_some() {
        return Err("Datadog: 'agent_url' must not contain user information".to_string());
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

/// Structurally redacted collector URL for diagnostics (path/query omitted).
///
/// Delegates to the shared sink helper so every HTTP-backed collector renders
/// one identical form. Retained as a named item because the exporter config and
/// unit tests refer to it directly.
pub(crate) fn redacted_endpoint_url(endpoint: &Url) -> String {
    super::utils::redacted_endpoint_url(endpoint)
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
        if !metadata.contains_key("trace_sampled") {
            let sampled = metadata
                .get(TRACEPARENT_HEADER)
                .and_then(|value| OtelTracing::parse_traceparent(value))
                .map(|parsed| flags_sampled(parsed.flags))
                .unwrap_or(true);
            metadata.insert(
                "trace_sampled".to_string(),
                if sampled { "true" } else { "false" }.to_string(),
            );
        }
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
        let sampled = flags_sampled(parsed.flags);
        metadata.insert(
            "trace_sampled".to_string(),
            if sampled { "true" } else { "false" }.to_string(),
        );
        metadata.insert(
            TRACEPARENT_HEADER.to_string(),
            build_traceparent(
                SUPPORTED_TRACEPARENT_VERSION,
                parsed.trace_id,
                &span_id,
                if sampled { "01" } else { "00" },
            ),
        );
        return;
    }

    let generated = OtelTracing::generate_trace_context(true);
    metadata.insert("trace_id".to_string(), generated.trace_id);
    metadata.insert("span_id".to_string(), generated.span_id);
    metadata.insert("trace_sampled".to_string(), "true".to_string());
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

fn unique_header_value_case_insensitive<'a>(
    headers: &'a HashMap<String, String>,
    name: &str,
) -> Result<Option<&'a str>, ()> {
    let mut value = None;
    for (key, candidate) in headers {
        if key.eq_ignore_ascii_case(name) {
            if value.is_some() {
                return Err(());
            }
            value = Some(candidate.as_str());
        }
    }
    Ok(value)
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

fn is_lowercase_hex(value: &str, expected_len: usize) -> bool {
    value.len() == expected_len
        && value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

/// Accept only W3C-shaped lowercase hex IDs before export helpers slice by
/// byte offset (non-hex / non-ASCII values would panic mid-char).
fn take_w3c_trace_ids(
    trace_id: &str,
    span_id: &str,
    parent_span_id: &str,
) -> Option<(String, String, String)> {
    if !is_lowercase_hex(trace_id, 32) || !is_lowercase_hex(span_id, 16) {
        warn_invalid_trace_identity();
        return None;
    }
    if !parent_span_id.is_empty() && !is_lowercase_hex(parent_span_id, 16) {
        warn_invalid_trace_identity();
        return None;
    }
    Some((
        trace_id.to_string(),
        span_id.to_string(),
        parent_span_id.to_string(),
    ))
}

fn warn_invalid_trace_identity() {
    static LIMITER: OnceLock<Mutex<LogRateLimiter>> = OnceLock::new();
    let limiter = LIMITER.get_or_init(|| Mutex::new(LogRateLimiter::new()));
    let now_ms = crate::socket_opts::monotonic_now_ms();
    let suppressed = match limiter.lock() {
        Ok(mut limiter) => limiter.on_event(now_ms),
        Err(poisoned) => poisoned.into_inner().on_event(now_ms),
    };
    if let Some(suppressed) = suppressed {
        warn!(
            suppressed,
            "dropping span with non-hex trace_id/span_id metadata"
        );
    }
}

fn flags_sampled(flags: &str) -> bool {
    u8::from_str_radix(flags, 16)
        .map(|flags| flags & 0x01 == 0x01)
        .unwrap_or(false)
}

fn sample_ratio(ratio: f64) -> bool {
    if ratio <= 0.0 {
        return false;
    }
    if ratio >= 1.0 {
        return true;
    }
    let random = Uuid::new_v4().as_u128() as f64 / (u128::MAX as f64);
    random < ratio
}

/// Mesh trace attributes with every value bounded by `max_attribute_bytes`.
///
/// Attribute *names* are already bounded (gateway-set `mesh.*` keys, plus at
/// most 32 operator-named custom keys of <= 128 bytes). Their values come from
/// request metadata and can be attacker-shaped, so they get the same
/// per-attribute ceiling and `...` truncation marker as every other span
/// string field.
fn bounded_mesh_attributes(
    metadata: &HashMap<String, String>,
    max_attribute_bytes: usize,
) -> Vec<(String, String)> {
    mesh_trace_attributes(metadata)
        .into_iter()
        .map(|(key, value)| {
            let bounded = truncate_attr(&value, max_attribute_bytes);
            (key, bounded)
        })
        .collect()
}

fn truncate_attr(value: &str, max_bytes: usize) -> String {
    if value.len() <= max_bytes {
        return value.to_string();
    }
    const MARKER: &str = "...";
    if max_bytes == 0 {
        return String::new();
    }
    let marker = &MARKER[..MARKER.len().min(max_bytes)];
    let mut end = max_bytes - marker.len();
    while end > 0 && !value.is_char_boundary(end) {
        end -= 1;
    }
    let mut out = value[..end].to_string();
    out.push_str(marker);
    out
}

fn http_span_name(summary: &TransactionSummary) -> String {
    let method = http_method_for_span_name(&summary.http_method);
    if let Some(route) = summary.proxy_name.as_deref().filter(|v| !v.is_empty()) {
        format!("{method} {route}")
    } else if let Some(proxy_id) = summary.proxy_id.as_deref().filter(|v| !v.is_empty()) {
        format!("{method} {proxy_id}")
    } else {
        method.to_string()
    }
}

/// Bound span-name method tokens to the HTTP registry set (OTel `_OTHER`).
fn http_method_for_span_name(method: &str) -> &'static str {
    if method.eq_ignore_ascii_case("GET") {
        "GET"
    } else if method.eq_ignore_ascii_case("HEAD") {
        "HEAD"
    } else if method.eq_ignore_ascii_case("POST") {
        "POST"
    } else if method.eq_ignore_ascii_case("PUT") {
        "PUT"
    } else if method.eq_ignore_ascii_case("DELETE") {
        "DELETE"
    } else if method.eq_ignore_ascii_case("CONNECT") {
        "CONNECT"
    } else if method.eq_ignore_ascii_case("OPTIONS") {
        "OPTIONS"
    } else if method.eq_ignore_ascii_case("TRACE") {
        "TRACE"
    } else if method.eq_ignore_ascii_case("PATCH") {
        "PATCH"
    } else {
        "_OTHER"
    }
}

fn http_span_is_error(summary: &TransactionSummary) -> bool {
    // Nonzero gRPC status is always an error (#2585), even over HTTP 200/4xx.
    if summary.grpc_status().is_some_and(|status| status != 0) {
        return true;
    }
    let status = summary.response_status_code;
    // OTel SERVER semconv: HTTP 4xx is not span ERROR (incl. gateway rejects).
    if (400..500).contains(&status) {
        return false;
    }
    // HTTP 5xx and terminal transport/body failures (status 0, disconnect, …).
    status >= 500 || summary.is_terminal_failure()
}

fn server_authority_from_metadata(
    metadata: &HashMap<String, String>,
) -> (Option<String>, Option<u16>) {
    let address = metadata.get("server_address").cloned();
    let port = metadata
        .get("server_port")
        .or_else(|| metadata.get("frontend_listen_port"))
        .and_then(|v| v.parse().ok());
    (address, port)
}

fn parse_host_header_authority(host: &str) -> Option<(String, Option<u16>)> {
    let host = host.trim();
    if host.is_empty()
        || host.len() > 256
        || host
            .chars()
            .any(|character| character.is_control() || character.is_whitespace())
        || host.contains(['/', '?', '#', '@', '\\'])
    {
        return None;
    }
    if let Some(rest) = host.strip_prefix('[') {
        let end = rest.find(']')?;
        let address = rest[..end].parse::<std::net::Ipv6Addr>().ok()?.to_string();
        let suffix = &rest[end + 1..];
        let port = if suffix.is_empty() {
            None
        } else {
            Some(suffix.strip_prefix(':')?.parse().ok()?)
        };
        return Some((address, port));
    }
    if host.contains('[') || host.contains(']') {
        return None;
    }
    let (address, port) = match host.rsplit_once(':') {
        Some((address, port)) if !address.contains(':') => {
            if address.is_empty() {
                return None;
            }
            (address, Some(port.parse().ok()?))
        }
        _ if host.parse::<std::net::Ipv6Addr>().is_ok() => (host, None),
        _ if host.contains(':') => return None,
        _ => (host, None),
    };
    if address.is_empty() {
        return None;
    }
    let address = if let Ok(ip) = address.parse::<std::net::IpAddr>() {
        ip.to_string()
    } else {
        match Host::parse(address) {
            Ok(Host::Domain(domain)) if !domain.is_empty() => domain.to_ascii_lowercase(),
            _ => return None,
        }
    };
    Some((address, port))
}

fn parse_backend_host_port(target: &str) -> (Option<String>, Option<u16>) {
    if target.contains("://") {
        let Ok(url) = Url::parse(target) else {
            return (None, None);
        };
        let host = match url.host() {
            Some(Host::Domain(host)) => Some(host.to_string()),
            Some(Host::Ipv4(host)) => Some(host.to_string()),
            Some(Host::Ipv6(host)) => Some(host.to_string()),
            None => None,
        };
        let port = url.port().or_else(|| match url.scheme() {
            "https" | "wss" => Some(443),
            "http" | "ws" => Some(80),
            _ => None,
        });
        return (host, port);
    }
    parse_host_header_authority(target)
        .map(|(host, port)| (Some(host), port))
        .unwrap_or((None, None))
}

fn gateway_backend_target(
    host: Option<&str>,
    port: Option<u16>,
    max_attribute_bytes: usize,
) -> Option<String> {
    let host = host?.trim();
    if host.is_empty() {
        return None;
    }
    let mut target = String::with_capacity(host.len() + 8);
    if host.contains(':') && !host.starts_with('[') {
        target.push('[');
        target.push_str(host);
        target.push(']');
    } else {
        target.push_str(host);
    }
    if let Some(port) = port {
        target.push(':');
        target.push_str(&port.to_string());
    }
    Some(truncate_attr(&target, max_attribute_bytes))
}

const fn direction_label(direction: Direction) -> &'static str {
    match direction {
        Direction::ClientToBackend => "client_to_backend",
        Direction::BackendToClient => "backend_to_client",
        Direction::Unknown => "unknown",
    }
}

const fn disconnect_cause_label(cause: DisconnectCause) -> &'static str {
    match cause {
        DisconnectCause::IdleTimeout => "idle_timeout",
        DisconnectCause::RecvError => "recv_error",
        DisconnectCause::BackendError => "backend_error",
        DisconnectCause::GracefulShutdown => "graceful_shutdown",
    }
}

const fn stream_io_side_label(side: crate::proxy::tcp_proxy::StreamIoSide) -> &'static str {
    match side {
        crate::proxy::tcp_proxy::StreamIoSide::Read => "read",
        crate::proxy::tcp_proxy::StreamIoSide::Write => "write",
    }
}

fn websocket_disconnect_cause(ctx: &WsDisconnectContext) -> DisconnectCause {
    let Some(error_class) = ctx.error_class else {
        return DisconnectCause::GracefulShutdown;
    };
    match ctx.direction {
        Some(direction) => crate::proxy::tcp_proxy::disconnect_cause_for_failure(
            direction,
            &error_class,
            ctx.io_side,
        ),
        None if error_class == crate::retry::ErrorClass::ReadWriteTimeout => {
            DisconnectCause::IdleTimeout
        }
        None => DisconnectCause::RecvError,
    }
}

fn websocket_client_disconnected(ctx: &WsDisconnectContext) -> bool {
    matches!(
        (ctx.direction, ctx.io_side),
        (
            Some(Direction::ClientToBackend),
            Some(crate::proxy::tcp_proxy::StreamIoSide::Read)
        ) | (
            Some(Direction::BackendToClient),
            Some(crate::proxy::tcp_proxy::StreamIoSide::Write)
        )
    )
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
            span_name: "GET api".to_string(),
            span_kind: 2,
            span_kind_typed: SpanKind::Server,
            http_method: "GET".to_string(),
            http_url: "/api".to_string(),
            http_status_code: Some(200),
            grpc_status: None,
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
            namespace: Some("ferrum".to_string()),
            server_address: Some("edge.example".to_string()),
            server_port: Some(443),
            backend_target: None,
            backend_host: None,
            backend_port: None,
            backend_resolved_ip: None,
            error_class: None,
            body_error_class: None,
            body_completed: true,
            response_streamed: false,
            client_disconnected: false,
            otlp_error: false,
            mesh_attributes: Vec::new(),
            stream_protocol: None,
            stream_listen_port: None,
            stream_bytes_sent: None,
            stream_bytes_received: None,
            disconnect_direction: None,
            disconnect_cause: None,
            stream_io_side: None,
            ws_frames_client_to_backend: None,
            ws_frames_backend_to_client: None,
        }
    }

    fn test_trace_http_exporter_config() -> TraceHttpExporterConfig {
        TraceHttpExporterConfig {
            provider_name: "workload_metrics",
            endpoint: "http://collector:4318/v1/traces".to_string(),
            endpoint_for_logs: "http://collector:4318/redacted".to_string(),
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
            ceiling: process_ceiling(),
        }
    }

    #[test]
    fn buffered_trace_exporter_defers_start_without_runtime() {
        let exporter =
            BufferedTraceExporter::new(test_trace_http_exporter_config(), 8, 1024 * 1024)
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
    async fn buffered_trace_exporter_starts_deferred_worker_when_runtime_available() {
        let exporter =
            BufferedTraceExporter::new(test_trace_http_exporter_config(), 8, 1024 * 1024)
                .expect("exporter config accepted");

        assert!(
            !exporter.started.load(Ordering::Acquire),
            "construction should remain side-effect free until the exporter is used"
        );
        exporter
            .ensure_started()
            .expect("runtime should start the deferred lifecycle worker");
        assert!(
            exporter.started.load(Ordering::Acquire),
            "successful deferred startup should enter steady state"
        );
    }

    #[test]
    fn buffered_trace_exporter_reserves_byte_budget_atomically() {
        let exporter = Arc::new(
            BufferedTraceExporter::new(test_trace_http_exporter_config(), 32, 1_024)
                .expect("exporter config accepted"),
        );
        let barrier = Arc::new(std::sync::Barrier::new(33));
        let mut workers = Vec::new();
        for _ in 0..32 {
            let exporter = Arc::clone(&exporter);
            let barrier = Arc::clone(&barrier);
            workers.push(std::thread::spawn(move || {
                barrier.wait();
                exporter.try_reserve_queued_bytes(128).is_ok()
            }));
        }
        barrier.wait();
        let admitted = workers
            .into_iter()
            .map(|worker| worker.join().expect("reservation worker did not panic"))
            .filter(|ok| *ok)
            .count();
        assert_eq!(admitted, 8);
        assert_eq!(exporter.queued_bytes.load(Ordering::Acquire), 1_024);
    }

    #[test]
    fn hex_to_base64_decodes_even_length_input() {
        let hex = "4bf92f3577b34da6a3ce929d0e0e4736";
        let encoded = hex_to_base64(hex);
        assert_eq!(encoded, "S/kvNXezTaajzpKdDg5HNg==");
    }

    #[test]
    fn hex_to_base64_decodes_8_byte_span_id() {
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
        let _ = hex_to_base64("abc");
        let _ = hex_to_base64("4bf92f3577b34da6a3ce929d0e0e473");
    }

    #[test]
    fn hex_to_base64_invalid_chars_filtered() {
        let encoded = hex_to_base64("XX");
        assert_eq!(encoded, "");
    }

    #[test]
    fn attribute_truncation_never_exceeds_the_configured_byte_cap() {
        assert_eq!(truncate_attr("abcdef", 5), "ab...");
        assert_eq!(truncate_attr("éééé", 5), "é...");
        assert_eq!(truncate_attr("abcdef", 2), "..");
        assert_eq!(truncate_attr("abcdef", 0), "");
        for max_bytes in 0..=8 {
            assert!(truncate_attr("ééééé", max_bytes).len() <= max_bytes);
        }
    }

    #[test]
    fn parse_traceparent_rejects_uppercase_and_accepts_future_version_extensions() {
        assert!(
            OtelTracing::parse_traceparent(
                "00-4BF92F3577B34DA6A3CE929D0E0E4736-00F067AA0BA902B7-01"
            )
            .is_none()
        );
        let parsed = OtelTracing::parse_traceparent(
            "01-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01-extra",
        )
        .expect("future version with extension");
        assert_eq!(parsed.trace_id, "4bf92f3577b34da6a3ce929d0e0e4736");
        assert!(
            OtelTracing::parse_traceparent(
                "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01-extra"
            )
            .is_none()
        );
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
    fn zipkin_and_datadog_preserve_backend_and_disconnect_tag_parity() {
        let mut span = test_span("4bf92f3577b34da6a3ce929d0e0e4736", "00f067aa0ba902b7");
        span.backend_target = Some("api.internal:8443".to_string());
        span.backend_host = Some("api.internal".to_string());
        span.backend_port = Some(8443);
        span.backend_resolved_ip = Some("10.0.0.42".to_string());
        span.stream_protocol = Some("websocket".to_string());
        span.stream_bytes_sent = Some(1_024);
        span.stream_bytes_received = Some(2_048);
        span.ws_frames_client_to_backend = Some(7);
        span.ws_frames_backend_to_client = Some(11);
        span.disconnect_direction = Some("client_to_backend".to_string());
        span.disconnect_cause = Some("recv_error".to_string());
        span.stream_io_side = Some("read".to_string());
        span.error_class = Some("connection_reset".to_string());
        span.client_disconnected = true;

        let zipkin = build_zipkin_payload("ferrum-edge", std::slice::from_ref(&span));
        let datadog = build_datadog_payload("ferrum-edge", &[span]);
        for tags in [&zipkin[0]["tags"], &datadog[0][0]["meta"]] {
            assert_eq!(tags["gateway.backend.target"], "api.internal:8443");
            assert_eq!(tags["gateway.backend.address"], "api.internal");
            assert_eq!(tags["gateway.backend.port"], "8443");
            assert_eq!(tags["gateway.backend.resolved_address"], "10.0.0.42");
            assert_eq!(tags["gateway.disconnect.direction"], "client_to_backend");
            assert_eq!(tags["gateway.disconnect.cause"], "recv_error");
            assert_eq!(tags["gateway.disconnect.io_side"], "read");
            assert_eq!(tags["gateway.error.class"], "connection_reset");
            assert_eq!(tags["gateway.client.disconnected"], "true");
            assert_eq!(tags["gateway.websocket.frames_client_to_backend"], "7");
            assert_eq!(tags["gateway.websocket.frames_backend_to_client"], "11");
        }
    }

    #[test]
    fn otlp_payload_includes_mesh_identity_attributes() {
        let mut span = test_span("4bf92f3577b34da6a3ce929d0e0e4736", "00f067aa0ba902b7");
        span.span_name = "GET /".to_string();
        span.http_url = "/".to_string();
        span.matched_route = Some("payments".to_string());
        span.mesh_attributes = vec![
            (
                "mesh.source.principal".to_string(),
                "spiffe://cluster.local/ns/default/sa/frontend".to_string(),
            ),
            (
                "mesh.destination.service".to_string(),
                "payments".to_string(),
            ),
        ];

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
        assert!(attributes.iter().any(|attribute| {
            attribute["key"] == "ferrum.namespace" && attribute["value"]["stringValue"] == "ferrum"
        }));
        assert!(attributes.iter().any(|attribute| {
            attribute["key"] == "server.address"
                && attribute["value"]["stringValue"] == "edge.example"
        }));
    }

    #[test]
    fn server_address_never_contains_backend_url_path() {
        let (host, port) = parse_backend_host_port("https://api.internal:8443/v1/orders");
        assert_eq!(host.as_deref(), Some("api.internal"));
        assert_eq!(port, Some(8443));
        assert_eq!(
            gateway_backend_target(host.as_deref(), port, 256).as_deref(),
            Some("api.internal:8443")
        );
        let (host6, port6) = parse_backend_host_port("http://[2001:db8::1]:8080/path");
        assert_eq!(host6.as_deref(), Some("2001:db8::1"));
        assert_eq!(port6, Some(8080));
        assert_eq!(
            gateway_backend_target(host6.as_deref(), port6, 256).as_deref(),
            Some("[2001:db8::1]:8080")
        );
        let (credential_host, credential_port) =
            parse_backend_host_port("https://user:secret@api.internal/orders?token=secret");
        assert_eq!(credential_host.as_deref(), Some("api.internal"));
        assert_eq!(credential_port, Some(443));
        assert_eq!(
            gateway_backend_target(credential_host.as_deref(), credential_port, 256).as_deref(),
            Some("api.internal:443")
        );
        assert_eq!(
            parse_backend_host_port("https://[not-an-ip/path"),
            (None, None)
        );
        assert_eq!(
            parse_backend_host_port("api.internal:8443"),
            (Some("api.internal".to_string()), Some(8443))
        );
        for malformed_bare_target in [
            "user:secret@api.internal:8443",
            "api.internal:8443/path",
            "api.internal:8443?token=secret",
            "api.internal:not-a-port",
        ] {
            assert_eq!(
                parse_backend_host_port(malformed_bare_target),
                (None, None),
                "{malformed_bare_target}"
            );
        }
    }

    #[test]
    fn host_header_authority_is_role_safe_and_structurally_valid() {
        assert_eq!(
            parse_host_header_authority("Edge.Example:8443"),
            Some(("edge.example".to_string(), Some(8443)))
        );
        assert_eq!(
            parse_host_header_authority("[2001:db8::1]:443"),
            Some(("2001:db8::1".to_string(), Some(443)))
        );
        for invalid in [
            "user:secret@edge.example",
            "https://edge.example/path",
            "edge.example?token=secret",
            "edge.example#fragment",
            "edge.example:not-a-port",
            "[2001:db8::1]trailing",
            "bad host",
        ] {
            assert_eq!(parse_host_header_authority(invalid), None, "{invalid}");
        }
    }
}
