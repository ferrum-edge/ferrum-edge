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
    pub fn new(config: &Value) -> Self {
        let extra_redacted_headers = config["redacted_headers"]
            .as_array()
            .map(|arr| {
                arr.iter()
                    .filter_map(|v| v.as_str().map(|s| s.to_lowercase()))
                    .collect()
            })
            .unwrap_or_default();

        Self {
            log_request_body: config["log_request_body"].as_bool().unwrap_or(false),
            log_response_body: config["log_response_body"].as_bool().unwrap_or(false),
            extra_redacted_headers,
        }
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
        println!("[DEBUG] === Incoming Request ===");
        println!("[DEBUG] {} {} from {}", ctx.method, ctx.path, ctx.client_ip);
        println!("[DEBUG] Headers: {:?}", safe_headers);
        if self.log_request_body {
            println!("[DEBUG] (Request body logging enabled)");
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
        println!("[DEBUG] === Backend Response ===");
        println!(
            "[DEBUG] Status: {} for {} {}",
            response_status, ctx.method, ctx.path
        );
        println!("[DEBUG] Response Headers: {:?}", safe_headers);
        if self.log_response_body {
            println!("[DEBUG] (Response body logging enabled)");
        }
        PluginResult::Continue
    }

    async fn on_stream_disconnect(&self, summary: &StreamTransactionSummary) {
        if let Some(ref error) = summary.connection_error {
            println!(
                "[DEBUG] Stream: {} {}:{} -> {} [{}] ({:.0}ms, {} bytes in, {} bytes out)",
                summary.protocol,
                summary.proxy_id,
                summary.listen_port,
                summary.backend_target,
                error,
                summary.duration_ms,
                summary.bytes_sent,
                summary.bytes_received,
            );
        } else {
            println!(
                "[DEBUG] Stream: {} {}:{} -> {} ({:.0}ms, {} bytes in, {} bytes out)",
                summary.protocol,
                summary.proxy_id,
                summary.listen_port,
                summary.backend_target,
                summary.duration_ms,
                summary.bytes_sent,
                summary.bytes_received,
            );
        }
    }

    async fn log(&self, summary: &TransactionSummary) {
        if let Some(ref error_class) = summary.error_class {
            println!(
                "[DEBUG] Transaction: {} {} -> {} [{}] ({}ms total, {:.2}ms plugins, {:.2}ms gw overhead)",
                summary.http_method,
                summary.request_path,
                summary.response_status_code,
                error_class,
                summary.latency_total_ms,
                summary.latency_plugin_execution_ms,
                summary.latency_gateway_overhead_ms,
            );
        } else {
            println!(
                "[DEBUG] Transaction: {} {} -> {} ({}ms total, {:.2}ms plugins, {:.2}ms gw overhead)",
                summary.http_method,
                summary.request_path,
                summary.response_status_code,
                summary.latency_total_ms,
                summary.latency_plugin_execution_ms,
                summary.latency_gateway_overhead_ms,
            );
        }
    }
}
