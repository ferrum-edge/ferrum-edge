//! Response Size Limiting Plugin
//!
//! Enforces per-proxy response body size limits that are lower than the global
//! `FERRUM_MAX_RESPONSE_BODY_SIZE_BYTES`. Rejects responses that exceed the
//! configured `max_bytes` with HTTP 502 Bad Gateway.
//!
//! Two enforcement paths:
//! 1. **Content-Length fast path** (`after_proxy`): rejects immediately when the
//!    backend response Content-Length header declares a transferable body larger
//!    than allowed. Bodyless responses (`HEAD`, `1xx`, `204`/`205`/`304`) skip
//!    this check because their Content-Length describes a representation, not
//!    transferred body bytes.
//! 2. **Final body check** (`on_final_response_body`): when response buffering is
//!    active (either from `require_buffered_check: true` or because another plugin
//!    requires buffering), the final client-visible byte length is verified after
//!    any body transforms have run.
//!
//! Set `require_buffered_check: true` to force response body buffering so that
//! chunked/streaming responses without Content-Length are also checked. This adds
//! memory overhead — only enable when needed.

use async_trait::async_trait;
use serde_json::Value;
use std::collections::HashMap;
use tracing::debug;

use super::utils::size_limit::{
    SizeLimiter, reject_with_limit, required_positive_u64,
    transferable_content_length_over_limit,
};
use super::utils::sse::{is_text_event_stream_media_type, original_response_is_event_stream};
use super::{Plugin, PluginResult, RequestContext};

pub struct ResponseSizeLimiting {
    max_bytes: u64,
    require_buffered_check: bool,
}

impl ResponseSizeLimiting {
    pub fn new(config: &Value) -> Result<Self, String> {
        if !config.is_object() {
            return Err("response_size_limiting: config must be an object".to_string());
        }

        let max_bytes = required_positive_u64(config, "max_bytes", "response_size_limiting")?;
        let require_buffered_check = match config.get("require_buffered_check") {
            Some(Value::Bool(value)) => *value,
            Some(Value::Null) | None => false,
            Some(_) => {
                return Err(
                    "response_size_limiting: 'require_buffered_check' must be a boolean"
                        .to_string(),
                );
            }
        };

        Ok(Self {
            max_bytes,
            require_buffered_check,
        })
    }
}

impl SizeLimiter for ResponseSizeLimiting {
    fn plugin_name(&self) -> &'static str {
        "response_size_limiting"
    }

    fn max_size_bytes(&self) -> u128 {
        self.max_bytes as u128
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
        self.require_buffered_check && self.is_enabled()
    }

    fn should_buffer_response_body(&self, _ctx: &RequestContext) -> bool {
        // A request Accept value cannot waive the configured route ceiling.
        // Buffer ordinary responses conservatively until pristine backend
        // headers are available.
        self.require_buffered_check && self.is_enabled()
    }

    fn may_release_response_body_under_retries(&self, ctx: &RequestContext) -> bool {
        self.should_buffer_response_body(ctx)
    }

    fn should_release_response_body_under_retries(
        &self,
        ctx: &RequestContext,
        _response_status: u16,
        response_headers: &HashMap<String, String>,
    ) -> bool {
        self.should_buffer_response_body(ctx)
            && original_response_is_event_stream(ctx, response_headers)
    }

    fn should_release_response_body_before_content_type_rewrite(
        &self,
        ctx: &RequestContext,
        _response_status: u16,
        response_headers: &HashMap<String, String>,
    ) -> bool {
        self.should_buffer_response_body(ctx)
            && original_response_is_event_stream(ctx, response_headers)
    }

    fn should_buffer_response_body_for_content_type(
        &self,
        ctx: &RequestContext,
        content_type: Option<&str>,
        _response_status: u16,
        _response_headers: &HashMap<String, String>,
    ) -> bool {
        self.should_buffer_response_body(ctx)
            && !content_type.is_some_and(is_text_event_stream_media_type)
    }

    async fn after_proxy(
        &self,
        ctx: &mut RequestContext,
        response_status: u16,
        response_headers: &mut HashMap<String, String>,
    ) -> PluginResult {
        if !self.is_enabled() {
            return PluginResult::Continue;
        }

        // Fast path: reject oversized Content-Length only when the response can
        // transfer a body. HEAD / 1xx / 204 / 205 / 304 may advertise a
        // representation length while sending zero body bytes.
        if let Some(len) = transferable_content_length_over_limit(
            &ctx.method,
            response_status,
            response_headers,
            self.max_size_bytes(),
        ) {
            debug!(
                plugin = self.plugin_name(),
                content_length = len,
                max_bytes = self.max_size_bytes(),
                "Response rejected: Content-Length exceeds limit"
            );
            return reject_with_limit(502, "Response body too large", self.max_size_bytes());
        }

        if self.require_buffered_check && original_response_is_event_stream(ctx, response_headers) {
            // The strict route limit is a whole-body policy. Until it has an
            // event-aware streaming counter, fail before committing headers
            // rather than silently fall back to the generally larger global
            // streaming ceiling or collect an unbounded event stream.
            return reject_with_limit(
                502,
                "Streaming response size cannot be verified",
                self.max_size_bytes(),
            );
        }

        PluginResult::Continue
    }

    async fn on_final_response_body(
        &self,
        _ctx: &mut RequestContext,
        _response_status: u16,
        _response_headers: &HashMap<String, String>,
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
                "Response rejected: buffered body exceeds limit"
            );
            return reject_with_limit(502, "Response body too large", self.max_size_bytes());
        }

        PluginResult::Continue
    }
}
