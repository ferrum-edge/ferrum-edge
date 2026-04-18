//! Correlation ID / Request ID Plugin
//!
//! Generates a unique request ID for every request and propagates it
//! through the proxy chain. If the client sends one, it is preserved.

use async_trait::async_trait;
use serde_json::Value;
use std::collections::HashMap;
use uuid::Uuid;

use super::{Plugin, PluginResult, RequestContext};

pub struct CorrelationId {
    header_name: String,
    echo_downstream: bool,
}

impl CorrelationId {
    pub fn new(config: &Value) -> Result<Self, String> {
        // Reject explicit non-string values for `header_name` so a misconfiguration
        // (e.g., setting an integer) does not silently fall back to the default.
        let header_name = match config.get("header_name") {
            None => "x-request-id".to_string(),
            Some(Value::Null) => "x-request-id".to_string(),
            Some(Value::String(s)) => {
                let trimmed = s.trim();
                if trimmed.is_empty() {
                    return Err(
                        "correlation_id: 'header_name' must be a non-empty string".to_string()
                    );
                }
                if !is_valid_http_header_name(trimmed) {
                    return Err(format!(
                        "correlation_id: 'header_name' contains characters not permitted in HTTP header names (RFC 7230 token): {trimmed:?}"
                    ));
                }
                trimmed.to_lowercase()
            }
            Some(other) => {
                return Err(format!(
                    "correlation_id: 'header_name' must be a string, got: {}",
                    other
                ));
            }
        };

        let echo_downstream = match config.get("echo_downstream") {
            None | Some(Value::Null) => true,
            Some(Value::Bool(b)) => *b,
            Some(other) => {
                return Err(format!(
                    "correlation_id: 'echo_downstream' must be a boolean, got: {}",
                    other
                ));
            }
        };

        Ok(Self {
            header_name,
            echo_downstream,
        })
    }
}

/// Validate an HTTP header name per RFC 7230 §3.2.6 token grammar.
/// A token is one or more printable ASCII characters from the tchar set
/// (excludes separators like `:`, `(`, `)`, `<`, `>`, `@`, etc.).
fn is_valid_http_header_name(name: &str) -> bool {
    if name.is_empty() {
        return false;
    }
    name.bytes().all(|b| {
        matches!(b,
            b'!' | b'#' | b'$' | b'%' | b'&' | b'\'' | b'*' | b'+' | b'-' | b'.' | b'^' | b'_' | b'`' | b'|' | b'~'
            | b'0'..=b'9'
            | b'A'..=b'Z'
            | b'a'..=b'z'
        )
    })
}

#[async_trait]
impl Plugin for CorrelationId {
    fn name(&self) -> &str {
        "correlation_id"
    }

    fn priority(&self) -> u16 {
        super::priority::CORRELATION_ID
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
        let id = Uuid::new_v4().to_string();
        ctx.insert_metadata("request_id".to_string(), id);
        super::PluginResult::Continue
    }

    async fn on_request_received(&self, ctx: &mut RequestContext) -> PluginResult {
        let request_id = if let Some(existing) = ctx.headers.get(&self.header_name) {
            if existing.len() <= 256 {
                existing.clone()
            } else {
                let id = Uuid::new_v4().to_string();
                ctx.headers.insert(self.header_name.clone(), id.clone());
                id
            }
        } else {
            let id = Uuid::new_v4().to_string();
            ctx.headers.insert(self.header_name.clone(), id.clone());
            id
        };

        // Store in metadata for logging plugins
        ctx.metadata.insert("request_id".to_string(), request_id);

        PluginResult::Continue
    }

    async fn before_proxy(
        &self,
        ctx: &mut RequestContext,
        headers: &mut HashMap<String, String>,
    ) -> PluginResult {
        // Ensure the correlation ID header is in the outgoing request
        if let Some(request_id) = ctx.metadata.get("request_id") {
            headers.insert(self.header_name.clone(), request_id.clone());
        }
        PluginResult::Continue
    }

    async fn after_proxy(
        &self,
        ctx: &mut RequestContext,
        _response_status: u16,
        response_headers: &mut HashMap<String, String>,
    ) -> PluginResult {
        if self.echo_downstream
            && let Some(request_id) = ctx.metadata.get("request_id")
        {
            response_headers.insert(self.header_name.clone(), request_id.clone());
        }
        PluginResult::Continue
    }

    fn applies_after_proxy_on_reject(&self) -> bool {
        self.echo_downstream
    }
}
