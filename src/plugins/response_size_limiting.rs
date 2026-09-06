//! Response Size Limiting Plugin
//!
//! Enforces per-proxy response body size limits that are lower than the global
//! `FERRUM_MAX_RESPONSE_BODY_SIZE_BYTES`. Rejects responses that exceed the
//! configured `max_bytes` with HTTP 502 Bad Gateway.
//!
//! Enforcement paths:
//! 1. **Content-Length fast path** (`after_proxy`): rejects immediately when the
//!    backend response Content-Length header declares a transferable body larger
//!    than allowed. Bodyless responses (`HEAD`, `1xx`, `204`/`205`/`304`) skip
//!    this check because their Content-Length describes a representation, not
//!    transferred body bytes.
//! 2. **Final body check** (`on_final_response_body`): when response buffering is
//!    active (either from `require_buffered_check: true` or because another plugin
//!    requires buffering), the final client-visible byte length is verified after
//!    any body transforms have run.
//! 3. **Core and synthetic checks**: every response collector/streaming adapter
//!    uses the effective route ceiling, and already-buffered gateway-generated
//!    responses are checked independently of the body-hook scheduling gate.
//!
//! Unknown-length streaming responses are always bounded frame by frame by the
//! core ceiling. Set `require_buffered_check: true` only when the policy must
//! prove the complete final post-transform size before committing a response;
//! this adds route-bounded buffering overhead and refuses indefinite SSE streams
//! whose complete size cannot be proven.

use async_trait::async_trait;
use serde_json::{Map, Value};
use std::collections::HashMap;
use tracing::debug;

use super::utils::size_limit::{
    ContentLengthRefusal, SizeLimiter, reject_with_limit, required_positive_u64,
    transferable_content_length_refusal,
};
use super::utils::sse::{is_text_event_stream_media_type, original_response_is_event_stream};
use super::utils::synthetic_response::{
    request_method_omits_response_body, synthetic_response_omits_body,
};
use super::{Plugin, PluginResult, RequestContext};
use crate::util::unknown_keys::reject_unknown_keys;

/// Authoritative closed set of top-level `response_size_limiting` configuration keys.
const RESPONSE_SIZE_LIMITING_CONFIG_KEYS: &[&str] = &["max_bytes", "require_buffered_check"];

pub struct ResponseSizeLimiting {
    max_bytes: u64,
    require_buffered_check: bool,
}

impl ResponseSizeLimiting {
    pub fn new(config: &Value) -> Result<Self, String> {
        let Some(config_obj) = config.as_object() else {
            return Err("response_size_limiting: config must be an object".to_string());
        };
        reject_unknown_keys(
            config_obj,
            "config",
            RESPONSE_SIZE_LIMITING_CONFIG_KEYS,
            "response_size_limiting: ",
        )?;

        let max_bytes = required_positive_u64(config, "max_bytes", "response_size_limiting")?;
        let require_buffered_check = optional_bool(config_obj, "require_buffered_check")?;

        Ok(Self {
            max_bytes,
            require_buffered_check,
        })
    }
}

fn optional_bool(config: &Map<String, Value>, key: &str) -> Result<bool, String> {
    match config.get(key) {
        None => Ok(false),
        Some(Value::Bool(value)) => Ok(*value),
        Some(_) => Err(format!("response_size_limiting: '{key}' must be a boolean")),
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

    /// Publish the configured ceiling to the proxy core (`GHSA-xrfj-852f-645j`).
    ///
    /// This is deliberately independent of `require_buffered_check`. It gives the
    /// core two things the hooks below cannot express:
    /// 1. strict buffered collection aborts at *this* limit rather than
    ///    retaining up to the larger global allowance before the final check, so
    ///    concurrent requests cannot amplify retained memory to nearly the
    ///    global allowance each; and
    /// 2. a default (non-buffering) instance still governs an already-buffered
    ///    synthetic body, which previously required some other plugin to
    ///    independently activate the response body-hook gate.
    fn enforced_response_body_limit(&self) -> Option<u64> {
        self.is_enabled().then_some(self.max_bytes)
    }

    fn should_buffer_response_body(&self, ctx: &RequestContext) -> bool {
        // A request Accept value cannot waive the configured route ceiling.
        // Buffer ordinary responses conservatively until pristine backend
        // headers are available.
        self.require_buffered_check
            && self.is_enabled()
            && !request_method_omits_response_body(&ctx.method)
    }

    fn may_release_response_body_under_retries(&self, ctx: &RequestContext) -> bool {
        self.should_buffer_response_body(ctx)
    }

    fn should_release_response_body_under_retries(
        &self,
        ctx: &RequestContext,
        response_status: u16,
        response_headers: &HashMap<String, String>,
    ) -> bool {
        self.should_buffer_response_body(ctx)
            && (synthetic_response_omits_body(&ctx.method, response_status)
                || original_response_is_event_stream(ctx, response_headers))
    }

    fn should_release_response_body_before_content_type_rewrite(
        &self,
        ctx: &RequestContext,
        response_status: u16,
        response_headers: &HashMap<String, String>,
    ) -> bool {
        self.should_buffer_response_body(ctx)
            && (synthetic_response_omits_body(&ctx.method, response_status)
                || original_response_is_event_stream(ctx, response_headers))
    }

    fn should_buffer_response_body_for_content_type(
        &self,
        ctx: &RequestContext,
        content_type: Option<&str>,
        response_status: u16,
        _response_headers: &HashMap<String, String>,
    ) -> bool {
        self.should_buffer_response_body(ctx)
            && !synthetic_response_omits_body(&ctx.method, response_status)
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
        // Hyper accepts a backend response whose `Content-Length` repeats with
        // identical values, and the shared collector folds those repeats with
        // `", "`. Parse every member so a coalesced declaration cannot read as
        // an absent length and skip this bound.
        match transferable_content_length_refusal(
            &ctx.method,
            response_status,
            response_headers,
            self.max_size_bytes(),
        ) {
            Some(ContentLengthRefusal::OverLimit(len)) => {
                debug!(
                    plugin = self.plugin_name(),
                    content_length = len,
                    max_bytes = self.max_size_bytes(),
                    "Response rejected: Content-Length exceeds limit"
                );
                return reject_with_limit(502, "Response body too large", self.max_size_bytes());
            }
            Some(ContentLengthRefusal::Ambiguous) => {
                debug!(
                    plugin = self.plugin_name(),
                    max_bytes = self.max_size_bytes(),
                    "Response rejected: Content-Length is ambiguous"
                );
                return reject_with_limit(
                    502,
                    "Response Content-Length is ambiguous",
                    self.max_size_bytes(),
                );
            }
            None => {}
        }

        if self.require_buffered_check
            && !synthetic_response_omits_body(&ctx.method, response_status)
            && original_response_is_event_stream(ctx, response_headers)
        {
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
        ctx: &mut RequestContext,
        response_status: u16,
        _response_headers: &HashMap<String, String>,
        body: &[u8],
    ) -> PluginResult {
        if !self.is_enabled() || synthetic_response_omits_body(&ctx.method, response_status) {
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
