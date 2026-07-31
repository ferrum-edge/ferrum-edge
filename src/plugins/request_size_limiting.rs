//! Request Size Limiting Plugin
//!
//! Enforces per-proxy request body size limits that are lower than the global
//! `FERRUM_MAX_REQUEST_BODY_SIZE_BYTES`. Rejects requests that exceed the
//! configured `max_bytes` with HTTP 413 Payload Too Large.
//!
//! Enforcement paths:
//! 1. **Content-Length fast path** (`on_request_received`): rejects immediately
//!    when the header declares a body larger than allowed — zero body I/O.
//! 2. **Buffered body check** (`before_proxy`): if another plugin caused the
//!    request body to be buffered (stored in `ctx.metadata["request_body"]`),
//!    the actual byte length is verified before proxying.
//! 3. **Final buffered body check** (`on_final_request_body`): re-checks the
//!    body after request transforms so the backend-visible payload still
//!    respects the configured limit.
//!
//! The proxy core also folds this route ceiling into every request collector
//! and streaming adapter, so chunked or unknown-length bodies are bounded even
//! when no plugin buffers them.

use async_trait::async_trait;
use serde_json::Value;
use std::collections::HashMap;
use tracing::debug;

use super::utils::size_limit::{
    ContentLengthRefusal, SizeLimiter, content_length_refusal, reject_with_limit,
    required_positive_u64,
};
use super::{Plugin, PluginResult, RequestContext};

pub struct RequestSizeLimiting {
    max_bytes: u64,
}

impl RequestSizeLimiting {
    pub fn new(config: &Value) -> Result<Self, String> {
        if !config.is_object() {
            return Err("request_size_limiting: config must be an object".to_string());
        }

        let max_bytes = required_positive_u64(config, "max_bytes", "request_size_limiting")?;

        Ok(Self { max_bytes })
    }

    fn buffered_request_body_len(ctx: &RequestContext) -> Option<u64> {
        ctx.metadata
            .get("request_body_size_bytes")
            .and_then(|value| value.parse::<u64>().ok())
            .or_else(|| {
                ctx.metadata
                    .get("request_body")
                    .map(|body| body.len() as u64)
            })
    }
}

impl SizeLimiter for RequestSizeLimiting {
    fn plugin_name(&self) -> &'static str {
        "request_size_limiting"
    }

    fn max_size_bytes(&self) -> u128 {
        self.max_bytes as u128
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

    /// This plugin's enforcement decision is taken in the final request-body
    /// phase, over the exact backend-visible representation. Composition
    /// admission refuses to pair it with a plugin that egresses the request
    /// before finalization (GHSA-4vr5-4wm3-x5xv).
    fn enforces_finalized_request_policy(&self) -> bool {
        true
    }

    fn supported_protocols(&self) -> &'static [super::ProxyProtocol] {
        super::HTTP_GRPC_PROTOCOLS
    }

    /// Publish the configured ceiling to the proxy core so unbuffered H1/H2,
    /// H3, and streaming-gRPC uploads are bounded at this route's limit instead
    /// of only at the generally larger global one (`GHSA-xrfj-852f-645j`).
    ///
    /// Without this the hooks below can only decide on a declared
    /// `Content-Length` or on a body some *other* plugin happened to buffer, so
    /// a chunked or unknown-length upload was forwarded up to the global ceiling
    /// — and to no bound at all when the global was disabled.
    fn enforced_request_body_limit(&self) -> Option<u64> {
        self.is_enabled().then_some(self.max_bytes)
    }

    async fn on_request_received(&self, ctx: &mut RequestContext) -> PluginResult {
        if !self.is_enabled() {
            return PluginResult::Continue;
        }

        // Fast path: check Content-Length header without reading the body.
        // Repeated identical values arrive comma-folded in this map, so parse
        // every member; a fold that cannot be reduced to one agreed value is
        // refused rather than treated as an absent length.
        match content_length_refusal(&ctx.headers, self.max_size_bytes()) {
            Some(ContentLengthRefusal::OverLimit(len)) => {
                debug!(
                    plugin = self.plugin_name(),
                    content_length = len,
                    max_bytes = self.max_size_bytes(),
                    "Request rejected: Content-Length exceeds limit"
                );
                return reject_with_limit(413, "Request body too large", self.max_size_bytes());
            }
            Some(ContentLengthRefusal::Ambiguous) => {
                debug!(
                    plugin = self.plugin_name(),
                    max_bytes = self.max_size_bytes(),
                    "Request rejected: Content-Length is ambiguous"
                );
                return reject_with_limit(
                    400,
                    "Request Content-Length is ambiguous",
                    self.max_size_bytes(),
                );
            }
            None => {}
        }

        PluginResult::Continue
    }

    async fn before_proxy(
        &self,
        ctx: &mut RequestContext,
        _headers: &mut HashMap<String, String>,
    ) -> PluginResult {
        if !self.is_enabled() {
            return PluginResult::Continue;
        }

        // If another plugin caused the body to be buffered, check actual size
        if let Some(len) = Self::buffered_request_body_len(ctx)
            && self.exceeds_limit(len as u128)
        {
            debug!(
                plugin = self.plugin_name(),
                body_len = len,
                max_bytes = self.max_size_bytes(),
                "Request rejected: buffered body exceeds limit"
            );
            return reject_with_limit(413, "Request body too large", self.max_size_bytes());
        }

        PluginResult::Continue
    }

    async fn on_final_request_body(
        &self,
        _headers: &HashMap<String, String>,
        body: &[u8],
    ) -> PluginResult {
        if !self.is_enabled() {
            return PluginResult::Continue;
        }

        let len = body.len() as u64;
        if self.exceeds_limit(len as u128) {
            debug!(
                plugin = self.plugin_name(),
                body_len = len,
                max_bytes = self.max_size_bytes(),
                "Request rejected: final request body exceeds limit"
            );
            return reject_with_limit(413, "Request body too large", self.max_size_bytes());
        }

        PluginResult::Continue
    }
}
