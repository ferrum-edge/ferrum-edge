//! Request Size Limiting Plugin
//!
//! Enforces per-proxy request body size limits that are lower than the global
//! `FERRUM_MAX_REQUEST_BODY_SIZE_BYTES`. Rejects requests that exceed the
//! configured `max_bytes` with HTTP 413 Payload Too Large.
//!
//! Two enforcement paths:
//! 1. **Content-Length fast path** (`on_request_received`): rejects immediately
//!    when the header declares a body larger than allowed — zero body I/O.
//! 2. **Buffered body check** (`before_proxy`): if another plugin caused the
//!    request body to be buffered (stored in `ctx.metadata["request_body"]`),
//!    the actual byte length is verified before proxying.
//! 3. **Final buffered body check** (`on_final_request_body`): re-checks the
//!    body after request transforms so the backend-visible payload still
//!    respects the configured limit.
//!
//! For chunked/streaming requests without Content-Length where no other plugin
//! buffers the body, the global limit still applies at the proxy layer.

use async_trait::async_trait;
use serde_json::Value;
use std::collections::HashMap;
use tracing::debug;

use super::{Plugin, PluginResult, RequestContext};

pub struct RequestSizeLimiting {
    max_bytes: u64,
}

impl RequestSizeLimiting {
    pub fn new(config: &Value) -> Result<Self, String> {
        let max_bytes = config["max_bytes"].as_u64().unwrap_or(0);

        if max_bytes == 0 {
            return Err(
                "request_size_limiting: 'max_bytes' is required and must be greater than zero"
                    .to_string(),
            );
        }

        Ok(Self { max_bytes })
    }
}

#[async_trait]
impl Plugin for RequestSizeLimiting {
    fn name(&self) -> &str {
        "request_size_limiting"
    }

    fn priority(&self) -> u16 {
        super::priority::REQUEST_SIZE_LIMITING
    }

    fn supported_protocols(&self) -> &'static [super::ProxyProtocol] {
        super::HTTP_GRPC_PROTOCOLS
    }

    async fn on_request_received(&self, ctx: &mut RequestContext) -> PluginResult {
        if self.max_bytes == 0 {
            return PluginResult::Continue;
        }

        // Fast path: check Content-Length header without reading the body
        if let Some(cl) = ctx.headers.get("content-length")
            && let Ok(len) = cl.parse::<u64>()
            && len > self.max_bytes
        {
            debug!(
                plugin = "request_size_limiting",
                content_length = len,
                max_bytes = self.max_bytes,
                "Request rejected: Content-Length exceeds limit"
            );
            return PluginResult::Reject {
                status_code: 413,
                body: format!(
                    r#"{{"error":"Request body too large","limit":{}}}"#,
                    self.max_bytes
                ),
                headers: HashMap::new(),
            };
        }

        PluginResult::Continue
    }

    async fn before_proxy(
        &self,
        ctx: &mut RequestContext,
        _headers: &mut HashMap<String, String>,
    ) -> PluginResult {
        if self.max_bytes == 0 {
            return PluginResult::Continue;
        }

        // If another plugin caused the body to be buffered, check actual size
        if let Some(body) = ctx.metadata.get("request_body") {
            let len = body.len() as u64;
            if len > self.max_bytes {
                debug!(
                    plugin = "request_size_limiting",
                    body_len = len,
                    max_bytes = self.max_bytes,
                    "Request rejected: buffered body exceeds limit"
                );
                return PluginResult::Reject {
                    status_code: 413,
                    body: format!(
                        r#"{{"error":"Request body too large","limit":{}}}"#,
                        self.max_bytes
                    ),
                    headers: HashMap::new(),
                };
            }
        }

        PluginResult::Continue
    }

    async fn on_final_request_body(
        &self,
        _headers: &HashMap<String, String>,
        body: &[u8],
    ) -> PluginResult {
        if self.max_bytes == 0 {
            return PluginResult::Continue;
        }

        let len = body.len() as u64;
        if len > self.max_bytes {
            debug!(
                plugin = "request_size_limiting",
                body_len = len,
                max_bytes = self.max_bytes,
                "Request rejected: final request body exceeds limit"
            );
            return PluginResult::Reject {
                status_code: 413,
                body: format!(
                    r#"{{"error":"Request body too large","limit":{}}}"#,
                    self.max_bytes
                ),
                headers: HashMap::new(),
            };
        }

        PluginResult::Continue
    }
}
