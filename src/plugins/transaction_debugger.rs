//! Transaction debugger plugin — detailed per-request diagnostics.
//!
//! Emits debug output via `tracing::debug!` on the `transaction_debug` target,
//! showing the request/response lifecycle: matched proxy, consumer identity,
//! plugin execution timing, backend connection details, and optionally
//! request/response body logging markers. Sensitive headers (Authorization,
//! Cookie, API keys) are automatically redacted. Intended for development and
//! troubleshooting — should not be enabled in production due to information
//! disclosure risk.

use async_trait::async_trait;
use serde_json::Value;
use std::collections::HashMap;

use super::{Plugin, PluginResult, RequestContext, StreamTransactionSummary, TransactionSummary};

/// Headers that contain sensitive credentials and must be redacted in debug output.
const SENSITIVE_HEADERS: &[&str] = &[
    "authorization",
    "proxy-authorization",
    "cookie",
    "set-cookie",
    "x-api-key",
    "x-auth-token",
    "x-csrf-token",
    "x-xsrf-token",
    "www-authenticate",
    "x-forwarded-authorization",
];

/// Redaction placeholder for sensitive header values.
const REDACTED: &str = "***REDACTED***";

pub struct TransactionDebugger {
    log_request_body: bool,
    log_response_body: bool,
    /// Additional header names (lowercase) to redact beyond the built-in list.
    extra_redacted_headers: Vec<String>,
}

impl TransactionDebugger {
    pub fn new(config: &Value) -> Result<Self, String> {
        let extra_redacted_headers = config["redacted_headers"]
            .as_array()
            .map(|arr| {
                arr.iter()
                    .filter_map(|v| v.as_str().map(|s| s.to_lowercase()))
                    .collect()
            })
            .unwrap_or_default();

        Ok(Self {
            log_request_body: config["log_request_body"].as_bool().unwrap_or(false),
            log_response_body: config["log_response_body"].as_bool().unwrap_or(false),
            extra_redacted_headers,
        })
    }

    /// Returns true if the given header name should be redacted.
    /// Header names are already lowercased by hyper, and SENSITIVE_HEADERS
    /// and extra_redacted_headers are stored lowercase — no conversion needed.
    fn is_sensitive(&self, header_name: &str) -> bool {
        SENSITIVE_HEADERS.contains(&header_name)
            || self.extra_redacted_headers.iter().any(|h| h == header_name)
    }

    /// Create a redacted copy of headers for safe logging.
    fn redact_headers(&self, headers: &HashMap<String, String>) -> HashMap<String, String> {
        headers
            .iter()
            .map(|(k, v)| {
                if self.is_sensitive(k) {
                    (k.clone(), REDACTED.to_string())
                } else {
                    (k.clone(), v.clone())
                }
            })
            .collect()
    }
}

#[async_trait]
impl Plugin for TransactionDebugger {
    fn name(&self) -> &str {
        "transaction_debugger"
    }

    fn priority(&self) -> u16 {
        super::priority::TRANSACTION_DEBUGGER
    }

    fn supported_protocols(&self) -> &'static [super::ProxyProtocol] {
        super::ALL_PROTOCOLS
    }

    async fn on_request_received(&self, ctx: &mut RequestContext) -> PluginResult {
        let safe_headers = self.redact_headers(&ctx.headers);
        tracing::debug!(target: "transaction_debug", method = %ctx.method, path = %ctx.path, client_ip = %ctx.client_ip, headers = ?safe_headers, "Incoming request");
        if self.log_request_body {
            tracing::debug!(target: "transaction_debug", "Request body logging enabled");
        }
        PluginResult::Continue
    }

    async fn after_proxy(
        &self,
        ctx: &mut RequestContext,
        response_status: u16,
        response_headers: &mut HashMap<String, String>,
    ) -> PluginResult {
        let safe_headers = self.redact_headers(response_headers);
        tracing::debug!(target: "transaction_debug", status = response_status, method = %ctx.method, path = %ctx.path, headers = ?safe_headers, "Backend response");
        if self.log_response_body {
            tracing::debug!(target: "transaction_debug", "Response body logging enabled");
        }
        PluginResult::Continue
    }

    async fn on_stream_disconnect(&self, summary: &StreamTransactionSummary) {
        if let Some(ref error) = summary.connection_error {
            tracing::debug!(
                target: "transaction_debug",
                protocol = %summary.protocol,
                proxy_id = %summary.proxy_id,
                listen_port = %summary.listen_port,
                backend_target = %summary.backend_target,
                error = %error,
                duration_ms = summary.duration_ms,
                bytes_sent = summary.bytes_sent,
                bytes_received = summary.bytes_received,
                "Stream disconnected with error",
            );
        } else {
            tracing::debug!(
                target: "transaction_debug",
                protocol = %summary.protocol,
                proxy_id = %summary.proxy_id,
                listen_port = %summary.listen_port,
                backend_target = %summary.backend_target,
                duration_ms = summary.duration_ms,
                bytes_sent = summary.bytes_sent,
                bytes_received = summary.bytes_received,
                "Stream disconnected",
            );
        }
    }

    async fn log(&self, summary: &TransactionSummary) {
        if let Some(ref error_class) = summary.error_class {
            tracing::debug!(
                target: "transaction_debug",
                method = %summary.http_method,
                path = %summary.request_path,
                status = summary.response_status_code,
                error_class = %error_class,
                latency_total_ms = summary.latency_total_ms,
                latency_plugin_ms = summary.latency_plugin_execution_ms,
                latency_gw_overhead_ms = summary.latency_gateway_overhead_ms,
                "Transaction completed with error",
            );
        } else {
            tracing::debug!(
                target: "transaction_debug",
                method = %summary.http_method,
                path = %summary.request_path,
                status = summary.response_status_code,
                latency_total_ms = summary.latency_total_ms,
                latency_plugin_ms = summary.latency_plugin_execution_ms,
                latency_gw_overhead_ms = summary.latency_gateway_overhead_ms,
                "Transaction completed",
            );
        }
    }
}
