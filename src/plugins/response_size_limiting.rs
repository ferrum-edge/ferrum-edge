//! Response Size Limiting Plugin
//!
//! Enforces per-proxy response body size limits that are lower than the global
//! `FERRUM_MAX_RESPONSE_BODY_SIZE_BYTES`. Rejects responses that exceed the
//! configured `max_bytes` with HTTP 502 Bad Gateway.
//!
//! Two enforcement paths:
//! 1. **Content-Length fast path** (`after_proxy`): rejects immediately when the
//!    backend response Content-Length header declares a body larger than allowed.
//! 2. **Buffered body check** (`on_response_body`): when response buffering is
//!    active (either from `require_buffered_check: true` or because another plugin
//!    requires buffering), the actual byte length is verified before the response
//!    reaches the client.
//!
//! Set `require_buffered_check: true` to force response body buffering so that
//! chunked/streaming responses without Content-Length are also checked. This adds
//! memory overhead — only enable when needed.

use async_trait::async_trait;
use serde_json::Value;
use std::collections::HashMap;
use tracing::debug;

use super::{Plugin, PluginResult, RequestContext};

pub struct ResponseSizeLimiting {
    max_bytes: u64,
    require_buffered_check: bool,
}

impl ResponseSizeLimiting {
    pub fn new(config: &Value) -> Self {
        let max_bytes = config["max_bytes"].as_u64().unwrap_or(0);
        let require_buffered_check = config["require_buffered_check"].as_bool().unwrap_or(false);

        if max_bytes == 0 {
            tracing::warn!(
                "response_size_limiting: 'max_bytes' not configured or zero — plugin will have no effect"
            );
        }

        Self {
            max_bytes,
            require_buffered_check,
        }
    }
}

#[async_trait]
impl Plugin for ResponseSizeLimiting {
    fn name(&self) -> &str {
        "response_size_limiting"
    }

    fn priority(&self) -> u16 {
        super::priority::RESPONSE_SIZE_LIMITING
    }

    fn supported_protocols(&self) -> &'static [super::ProxyProtocol] {
        super::HTTP_GRPC_PROTOCOLS
    }

    fn requires_response_body_buffering(&self) -> bool {
        self.require_buffered_check && self.max_bytes > 0
    }

    async fn after_proxy(
        &self,
        _ctx: &mut RequestContext,
        _response_status: u16,
        response_headers: &mut HashMap<String, String>,
    ) -> PluginResult {
        if self.max_bytes == 0 {
            return PluginResult::Continue;
        }

        // Fast path: check Content-Length response header
        if let Some(cl) = response_headers.get("content-length")
            && let Ok(len) = cl.parse::<u64>()
            && len > self.max_bytes
        {
            debug!(
                plugin = "response_size_limiting",
                content_length = len,
                max_bytes = self.max_bytes,
                "Response rejected: Content-Length exceeds limit"
            );
            return PluginResult::Reject {
                status_code: 502,
                body: format!(
                    r#"{{"error":"Response body too large","limit":{}}}"#,
                    self.max_bytes
                ),
                headers: HashMap::new(),
            };
        }

        PluginResult::Continue
    }

    async fn on_response_body(
        &self,
        _ctx: &mut RequestContext,
        _response_status: u16,
        _response_headers: &HashMap<String, String>,
        body: &[u8],
    ) -> PluginResult {
        if self.max_bytes == 0 {
            return PluginResult::Continue;
        }

        let len = body.len() as u64;
        if len > self.max_bytes {
            debug!(
                plugin = "response_size_limiting",
                body_len = len,
                max_bytes = self.max_bytes,
                "Response rejected: buffered body exceeds limit"
            );
            return PluginResult::Reject {
                status_code: 502,
                body: format!(
                    r#"{{"error":"Response body too large","limit":{}}}"#,
                    self.max_bytes
                ),
                headers: HashMap::new(),
            };
        }

        PluginResult::Continue
    }
}
