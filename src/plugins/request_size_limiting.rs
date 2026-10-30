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
//!
//! Every `413` carries the gateway's one request-body-size body
//! ([`REQUEST_BODY_TOO_LARGE_BODY`]), the same body the proxy core writes when
//! a streaming upload overruns this ceiling, so the client contract does not
//! depend on which enforcement point fired. The limit, the observed size, and
//! the rejecting instance go to request metadata (and from there to the
//! transaction log) instead of the response body. That metadata is always
//! recorded by the `Content-Length` and buffered-body refusals. On every
//! protocol, the final-body refusal records it only when its hook is handed a
//! request context. The native-H3 preparation paths and the H3 cross-protocol
//! bridge always pass one. The H1/H2 ladders and the native-H3 buffered ladder
//! pass one only when another plugin on the route asks for the final-body
//! context (`needs_final_request_body_context`). This plugin does not ask, so it
//! never adds a per-request context clone; a final-body `413` decided without a
//! context carries no `request_size_limiting.*` metadata.

use async_trait::async_trait;
use serde_json::Value;
use std::collections::HashMap;
use std::sync::Arc;
use tracing::debug;

use super::utils::size_limit::{
    ContentLengthRefusal, SizeLimiter, content_length_refusal, required_positive_u64,
};
use super::{Plugin, PluginResult, RequestContext};
use crate::util::body_limit::REQUEST_BODY_TOO_LARGE_BODY;
use crate::util::unknown_keys::reject_unknown_keys;

/// Authoritative closed set of top-level `request_size_limiting` configuration keys.
const REQUEST_SIZE_LIMITING_CONFIG_KEYS: &[&str] = &["max_bytes"];

/// `400` body for a declared `Content-Length` that cannot be reduced to one
/// agreed value.
pub const AMBIGUOUS_CONTENT_LENGTH_BODY: &str =
    r#"{"error":"Request Content-Length is ambiguous"}"#;

/// Request metadata key naming why this plugin refused the request: one of
/// `content_length_over_limit`, `content_length_ambiguous`,
/// `buffered_body_over_limit`, or `final_body_over_limit`.
pub const REJECTION_REASON_METADATA_KEY: &str = "request_size_limiting.reason";
/// Request metadata key holding the rejecting instance's plugin-config id
/// (`standalone` for a directly constructed instance).
pub const REJECTION_INSTANCE_METADATA_KEY: &str = "request_size_limiting.instance";
/// Request metadata key holding the rejecting instance's `max_bytes`.
pub const REJECTION_LIMIT_METADATA_KEY: &str = "request_size_limiting.limit_bytes";
/// Request metadata key holding the observed size in bytes: the declared
/// `Content-Length`, or the buffered/final body length. Absent for an
/// ambiguous `Content-Length`, which has no single observed size.
pub const REJECTION_OBSERVED_METADATA_KEY: &str = "request_size_limiting.observed_bytes";

/// Instance identity reported for an instance built without a plugin-config id
/// (config validation and direct construction).
const STANDALONE_INSTANCE_ID: &str = "standalone";

/// Fixed-cardinality reason recorded in [`REJECTION_REASON_METADATA_KEY`].
#[derive(Debug, Clone, Copy)]
enum RejectionReason {
    ContentLengthOverLimit,
    ContentLengthAmbiguous,
    BufferedBodyOverLimit,
    FinalBodyOverLimit,
}

impl RejectionReason {
    fn as_str(self) -> &'static str {
        match self {
            Self::ContentLengthOverLimit => "content_length_over_limit",
            Self::ContentLengthAmbiguous => "content_length_ambiguous",
            Self::BufferedBodyOverLimit => "buffered_body_over_limit",
            Self::FinalBodyOverLimit => "final_body_over_limit",
        }
    }
}

pub struct RequestSizeLimiting {
    max_bytes: u64,
    /// Stable plugin-config id published in rejection metadata.
    instance_id: Arc<str>,
}

impl RequestSizeLimiting {
    pub fn new(config: &Value) -> Result<Self, String> {
        Self::new_with_config_id(config, None)
    }

    /// Build an instance that reports `config_id` (the plugin-config resource
    /// id) as its identity in rejection metadata. `None` reports `standalone`;
    /// a blank id is refused.
    pub fn new_with_config_id(config: &Value, config_id: Option<&str>) -> Result<Self, String> {
        let Some(config_obj) = config.as_object() else {
            return Err("request_size_limiting: config must be an object".to_string());
        };
        reject_unknown_keys(
            config_obj,
            "config",
            REQUEST_SIZE_LIMITING_CONFIG_KEYS,
            "request_size_limiting: `config`: ",
        )?;

        let max_bytes = required_positive_u64(config, "max_bytes", "request_size_limiting")?;

        // The factory contract: a supplied id must be usable, so a blank one
        // fails closed (as `request_mirror` does) rather than masquerading as
        // an unnamed instance. Only an absent id reports `standalone`.
        let instance_id: Arc<str> = match config_id {
            Some(id) if id.trim().is_empty() => {
                return Err("request_size_limiting: plugin_config_id must not be blank".to_string());
            }
            Some(id) => Arc::from(id.trim()),
            None => Arc::from(STANDALONE_INSTANCE_ID),
        };

        Ok(Self {
            max_bytes,
            instance_id,
        })
    }

    /// Record which instance refused the request, why, against which limit,
    /// and (when one exists) the observed size. Cold path: runs only on a
    /// rejection.
    fn record_rejection(
        &self,
        ctx: &mut RequestContext,
        reason: RejectionReason,
        observed_bytes: Option<u64>,
    ) {
        ctx.metadata.insert(
            REJECTION_REASON_METADATA_KEY.to_string(),
            reason.as_str().to_string(),
        );
        ctx.metadata.insert(
            REJECTION_INSTANCE_METADATA_KEY.to_string(),
            self.instance_id.to_string(),
        );
        ctx.metadata.insert(
            REJECTION_LIMIT_METADATA_KEY.to_string(),
            self.max_bytes.to_string(),
        );
        match observed_bytes {
            Some(observed) => {
                ctx.metadata.insert(
                    REJECTION_OBSERVED_METADATA_KEY.to_string(),
                    observed.to_string(),
                );
            }
            None => {
                ctx.metadata.remove(REJECTION_OBSERVED_METADATA_KEY);
            }
        }
    }

    /// The final-body decision shared by both final-body hooks: the body length
    /// when it exceeds the limit.
    fn final_body_overrun(&self, body: &[u8]) -> Option<u64> {
        let len = body.len() as u64;
        if self.exceeds_limit(len as u128) {
            debug!(
                plugin = self.plugin_name(),
                body_len = len,
                max_bytes = self.max_size_bytes(),
                "Request rejected: final request body exceeds limit"
            );
            Some(len)
        } else {
            None
        }
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

/// The shared request-body-size `413`.
fn reject_too_large() -> PluginResult {
    PluginResult::Reject {
        status_code: 413,
        body: REQUEST_BODY_TOO_LARGE_BODY.to_string(),
        headers: HashMap::new(),
    }
}

/// The fail-closed `400` for an ambiguous declared `Content-Length`.
fn reject_ambiguous_content_length() -> PluginResult {
    PluginResult::Reject {
        status_code: 400,
        body: AMBIGUOUS_CONTENT_LENGTH_BODY.to_string(),
        headers: HashMap::new(),
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

    fn lifecycle_hooks(&self) -> crate::plugins::PluginHooks {
        crate::plugins::PluginHooks::ON_REQUEST_RECEIVED | crate::plugins::PluginHooks::BEFORE_PROXY
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
                self.record_rejection(ctx, RejectionReason::ContentLengthOverLimit, Some(len));
                return reject_too_large();
            }
            Some(ContentLengthRefusal::Ambiguous) => {
                debug!(
                    plugin = self.plugin_name(),
                    max_bytes = self.max_size_bytes(),
                    "Request rejected: Content-Length is ambiguous"
                );
                self.record_rejection(ctx, RejectionReason::ContentLengthAmbiguous, None);
                return reject_ambiguous_content_length();
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
            self.record_rejection(ctx, RejectionReason::BufferedBodyOverLimit, Some(len));
            return reject_too_large();
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

        if self.final_body_overrun(body).is_some() {
            reject_too_large()
        } else {
            PluginResult::Continue
        }
    }

    /// Same decision as [`Self::on_final_request_body`], plus rejection
    /// metadata whenever the final-body stage runs with a request context.
    /// The plugin does not request that context itself
    /// (`needs_final_request_body_context` stays `false`), so routes without
    /// another context-needing plugin pay no per-request context clone for it.
    async fn on_final_request_body_with_context(
        &self,
        ctx: &mut RequestContext,
        _headers: &HashMap<String, String>,
        body: &[u8],
    ) -> PluginResult {
        if !self.is_enabled() {
            return PluginResult::Continue;
        }

        match self.final_body_overrun(body) {
            Some(len) => {
                self.record_rejection(ctx, RejectionReason::FinalBodyOverLimit, Some(len));
                reject_too_large()
            }
            None => PluginResult::Continue,
        }
    }
}
