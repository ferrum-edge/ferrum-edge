//! OpenTelemetry Tracing Plugin
//!
//! Provides W3C Trace Context propagation (traceparent/tracestate headers)
//! and emits structured trace data via the `log()` hook.
//! Generates trace IDs for requests that don't already carry them.

use async_trait::async_trait;
use serde_json::Value;
use std::collections::HashMap;
use uuid::Uuid;

use super::{Plugin, PluginResult, RequestContext, TransactionSummary};

pub struct OtelTracing {
    /// Service name for spans.
    service_name: String,
    /// Whether to generate trace IDs for requests without traceparent.
    generate_trace_id: bool,
}

impl OtelTracing {
    pub fn new(config: &Value) -> Self {
        let service_name = config["service_name"]
            .as_str()
            .unwrap_or("ferrum-gateway")
            .to_string();
        let generate_trace_id = config["generate_trace_id"].as_bool().unwrap_or(true);

        Self {
            service_name,
            generate_trace_id,
        }
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
        // Emit structured trace log
        if let Some(trace_id) = summary.metadata.get("trace_id") {
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
                http_method = %summary.http_method,
                http_url = %summary.request_path,
                http_status_code = %summary.response_status_code,
                http_client_ip = %summary.client_ip,
                duration_ms = %summary.latency_total_ms,
                backend_ms = %summary.latency_backend_total_ms,
                "request trace"
            );
        }
    }
}
