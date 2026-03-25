//! OpenTelemetry Tracing Plugin
//!
//! Provides W3C Trace Context propagation (traceparent/tracestate headers)
//! and emits structured trace data via the `log()` hook.
//! Generates trace IDs for requests that don't already carry them.
//!
//! Optionally exports spans to an OTLP-compatible collector via HTTP/JSON
//! (OTLP/HTTP with JSON encoding, per the OpenTelemetry specification).

use async_trait::async_trait;
use serde_json::Value;
use std::collections::HashMap;
use tokio::sync::mpsc;
use tokio::time::Duration;
use tracing::warn;
use url::Url;
use uuid::Uuid;

use super::utils::PluginHttpClient;
use super::{Plugin, PluginResult, RequestContext, TransactionSummary};

pub struct OtelTracing {
    /// Service name for spans.
    service_name: String,
    /// Whether to generate trace IDs for requests without traceparent.
    generate_trace_id: bool,
    /// OTLP span sender (if endpoint is configured).
    otlp_sender: Option<mpsc::Sender<SpanData>>,
    /// OTLP endpoint hostname for DNS warmup.
    otlp_hostname: Option<String>,
}

/// Internal span data collected during the request lifecycle.
#[derive(Clone)]
struct SpanData {
    trace_id: String,
    span_id: String,
    parent_span_id: String,
    service_name: String,
    http_method: String,
    http_url: String,
    http_status_code: u16,
    client_ip: String,
    duration_ms: f64,
    backend_ms: f64,
    consumer: Option<String>,
    timestamp_received: String,
}

impl OtelTracing {
    pub fn new_with_http_client(
        config: &Value,
        http_client: PluginHttpClient,
    ) -> Result<Self, String> {
        let service_name = config["service_name"]
            .as_str()
            .unwrap_or("ferrum-gateway")
            .to_string();
        let generate_trace_id = config["generate_trace_id"].as_bool().unwrap_or(true);

        let endpoint = config["endpoint"]
            .as_str()
            .filter(|s| !s.is_empty())
            .ok_or_else(|| {
                "otel_tracing: 'endpoint' is required — traces will have nowhere to export"
                    .to_string()
            })?
            .to_string();

        let batch_size = config["batch_size"].as_u64().unwrap_or(50).max(1) as usize;
        let flush_interval_ms = config["flush_interval_ms"]
            .as_u64()
            .unwrap_or(5000)
            .max(100);
        let buffer_capacity = config["buffer_capacity"].as_u64().unwrap_or(10000).max(1) as usize;

        let otlp_hostname = Url::parse(&endpoint)
            .ok()
            .and_then(|u| u.host_str().map(|h| h.to_string()));

        let authorization = config["authorization"].as_str().map(|s| s.to_string());

        let (sender, receiver) = mpsc::channel(buffer_capacity);

        let otlp_config = OtlpConfig {
            endpoint,
            authorization,
            http_client,
            batch_size,
            flush_interval: Duration::from_millis(flush_interval_ms),
            max_retries: config["max_retries"].as_u64().unwrap_or(2) as u32,
            retry_delay: Duration::from_millis(config["retry_delay_ms"].as_u64().unwrap_or(1000)),
            service_name: service_name.clone(),
        };

        tokio::spawn(otlp_flush_loop(receiver, otlp_config));

        Ok(Self {
            service_name,
            generate_trace_id,
            otlp_sender: Some(sender),
            otlp_hostname,
        })
    }

    /// Generate a W3C traceparent header value.
    fn generate_traceparent() -> String {
        let trace_id = Uuid::new_v4().as_simple().to_string();
        let span_id = &Uuid::new_v4().as_simple().to_string()[..16];
        format!("00-{}-{}-01", trace_id, span_id)
    }

    /// Parse a traceparent header into (version, trace_id, parent_span_id, flags).
    fn parse_traceparent(value: &str) -> Option<(String, String, String, String)> {
        let parts: Vec<&str> = value.split('-').collect();
        if parts.len() != 4 {
            return None;
        }
        Some((
            parts[0].to_string(),
            parts[1].to_string(),
            parts[2].to_string(),
            parts[3].to_string(),
        ))
    }

    /// Generate a new span ID for the gateway hop.
    fn generate_span_id() -> String {
        Uuid::new_v4().as_simple().to_string()[..16].to_string()
    }
}

pub const OTEL_TRACING_PRIORITY: u16 = 25;

#[async_trait]
impl Plugin for OtelTracing {
    fn name(&self) -> &str {
        "otel_tracing"
    }

    fn priority(&self) -> u16 {
        OTEL_TRACING_PRIORITY
    }

    fn modifies_request_headers(&self) -> bool {
        true
    }

    async fn on_request_received(&self, ctx: &mut RequestContext) -> PluginResult {
        // Extract or generate trace context
        let traceparent = if let Some(existing) = ctx.headers.get("traceparent") {
            if let Some((version, trace_id, _parent_span, flags)) =
                Self::parse_traceparent(existing)
            {
                // Store incoming trace context
                ctx.metadata
                    .insert("trace_id".to_string(), trace_id.clone());
                ctx.metadata
                    .insert("parent_span_id".to_string(), _parent_span.clone());

                // Generate new span ID for the gateway
                let gateway_span = Self::generate_span_id();
                ctx.metadata
                    .insert("span_id".to_string(), gateway_span.clone());

                format!("{}-{}-{}-{}", version, trace_id, gateway_span, flags)
            } else {
                Self::generate_traceparent()
            }
        } else if self.generate_trace_id {
            let traceparent = Self::generate_traceparent();
            if let Some((_, trace_id, span_id, _)) = Self::parse_traceparent(&traceparent) {
                ctx.metadata.insert("trace_id".to_string(), trace_id);
                ctx.metadata.insert("span_id".to_string(), span_id);
            }
            traceparent
        } else {
            return PluginResult::Continue;
        };

        ctx.metadata.insert("traceparent".to_string(), traceparent);

        // Preserve tracestate if present
        if let Some(tracestate) = ctx.headers.get("tracestate") {
            ctx.metadata
                .insert("tracestate".to_string(), tracestate.clone());
        }

        PluginResult::Continue
    }

    async fn before_proxy(
        &self,
        ctx: &mut RequestContext,
        headers: &mut HashMap<String, String>,
    ) -> PluginResult {
        // Inject traceparent into outgoing request
        if let Some(traceparent) = ctx.metadata.get("traceparent") {
            headers.insert("traceparent".to_string(), traceparent.clone());
        }
        if let Some(tracestate) = ctx.metadata.get("tracestate") {
            headers.insert("tracestate".to_string(), tracestate.clone());
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
        if let Some(traceparent) = ctx.metadata.get("traceparent") {
            response_headers.insert("traceparent".to_string(), traceparent.clone());
        }
        PluginResult::Continue
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

        // Always emit structured log (existing behavior)
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
        if let Some(ref sender) = self.otlp_sender {
            let span_data = SpanData {
                trace_id: trace_id.clone(),
                span_id: span_id.to_string(),
                parent_span_id: parent_span_id.to_string(),
                service_name: self.service_name.clone(),
                http_method: summary.http_method.clone(),
                http_url: summary.request_path.clone(),
                http_status_code: summary.response_status_code,
                client_ip: summary.client_ip.clone(),
                duration_ms: summary.latency_total_ms,
                backend_ms: summary.latency_backend_total_ms,
                consumer: summary.consumer_username.clone(),
                timestamp_received: summary.timestamp_received.clone(),
            };

            if sender.try_send(span_data).is_err() {
                warn!("OTLP export buffer full — dropping span");
            }
        }
    }

    fn warmup_hostnames(&self) -> Vec<String> {
        self.otlp_hostname
            .as_ref()
            .map(|h| vec![h.clone()])
            .unwrap_or_default()
    }
}

// ─── OTLP HTTP/JSON Exporter ───────────────────────────────────────────

struct OtlpConfig {
    endpoint: String,
    authorization: Option<String>,
    http_client: PluginHttpClient,
    batch_size: usize,
    flush_interval: Duration,
    max_retries: u32,
    retry_delay: Duration,
    service_name: String,
}

async fn otlp_flush_loop(mut receiver: mpsc::Receiver<SpanData>, cfg: OtlpConfig) {
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
                            let batch = std::mem::take(&mut buffer);
                            send_otlp_batch(&cfg, batch).await;
                        }
                    }
                    None => {
                        if !buffer.is_empty() {
                            let batch = std::mem::take(&mut buffer);
                            send_otlp_batch(&cfg, batch).await;
                        }
                        break;
                    }
                }
            }

            _ = timer.tick() => {
                if !buffer.is_empty() {
                    let batch = std::mem::take(&mut buffer);
                    send_otlp_batch(&cfg, batch).await;
                }
            }
        }
    }
}

async fn send_otlp_batch(cfg: &OtlpConfig, batch: Vec<SpanData>) {
    let total_attempts = cfg.max_retries + 1;
    let entry_count = batch.len();
    let payload = build_otlp_payload(&cfg.service_name, &batch);

    for attempt in 1..=total_attempts {
        let mut req = cfg
            .http_client
            .get()
            .post(&cfg.endpoint)
            .header("Content-Type", "application/json")
            .json(&payload);

        if let Some(auth) = &cfg.authorization {
            req = req.header("Authorization", auth);
        }

        match req.send().await {
            Ok(response) if response.status().is_success() => return,
            Ok(response) => {
                warn!(
                    "OTLP export failed with status {} (attempt {}/{})",
                    response.status(),
                    attempt,
                    total_attempts,
                );
            }
            Err(e) => {
                warn!(
                    "OTLP export failed: {} (attempt {}/{})",
                    e, attempt, total_attempts,
                );
            }
        }
        if attempt < total_attempts {
            tokio::time::sleep(cfg.retry_delay).await;
        }
    }

    warn!(
        "OTLP export batch discarded after {} attempts ({} spans lost)",
        total_attempts, entry_count,
    );
}

/// Build an OTLP/HTTP JSON payload conforming to the OpenTelemetry
/// Trace Export specification.
///
/// Format: ExportTraceServiceRequest with ResourceSpans → ScopeSpans → Spans.
/// See: https://opentelemetry.io/docs/specs/otlp/#otlphttp-request
fn build_otlp_payload(service_name: &str, spans: &[SpanData]) -> Value {
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
            let start_ns = chrono::DateTime::parse_from_rfc3339(&s.timestamp_received)
                .map(|dt| dt.timestamp_nanos_opt().unwrap_or(0))
                .unwrap_or(0);
            let end_ns = start_ns + (s.duration_ms * 1_000_000.0) as i64;

            let mut attributes = vec![
                otlp_attribute("http.method", &s.http_method),
                otlp_attribute("http.url", &s.http_url),
                otlp_attribute_int("http.status_code", s.http_status_code as i64),
                otlp_attribute("net.peer.ip", &s.client_ip),
                otlp_attribute("service.name", &s.service_name),
            ];

            if s.backend_ms >= 0.0 {
                attributes.push(otlp_attribute_double("backend.duration_ms", s.backend_ms));
            }
            if let Some(ref consumer) = s.consumer {
                attributes.push(otlp_attribute("consumer.username", consumer));
            }

            let mut span = serde_json::json!({
                "traceId": trace_id_bytes,
                "spanId": span_id_bytes,
                "name": format!("{} {}", s.http_method, s.http_url),
                "kind": 2, // SPAN_KIND_SERVER
                "startTimeUnixNano": start_ns.to_string(),
                "endTimeUnixNano": end_ns.to_string(),
                "attributes": attributes,
                "status": {
                    "code": if s.http_status_code >= 400 { 2 } else { 1 } // ERROR or OK
                }
            });

            if !parent_span_bytes.is_empty() {
                span["parentSpanId"] = Value::String(parent_span_bytes);
            }

            span
        })
        .collect();

    serde_json::json!({
        "resourceSpans": [{
            "resource": {
                "attributes": [
                    otlp_attribute("service.name", service_name)
                ]
            },
            "scopeSpans": [{
                "scope": {
                    "name": "ferrum-gateway",
                    "version": env!("CARGO_PKG_VERSION")
                },
                "spans": otlp_spans
            }]
        }]
    })
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

/// Convert a hex string to base64-encoded bytes (OTLP format).
fn hex_to_base64(hex: &str) -> String {
    use base64::Engine;
    use base64::engine::general_purpose::STANDARD;

    let bytes: Vec<u8> = (0..hex.len())
        .step_by(2)
        .filter_map(|i| u8::from_str_radix(&hex[i..i.min(hex.len()).max(i + 2)], 16).ok())
        .collect();

    STANDARD.encode(&bytes)
}
