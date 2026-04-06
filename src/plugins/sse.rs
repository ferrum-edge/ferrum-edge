//! SSE (Server-Sent Events) stream handler plugin.
//!
//! Validates that inbound requests meet SSE client criteria, shapes the
//! request for the upstream backend, and ensures proper SSE response headers
//! for streaming delivery back to the client.
//!
//! ## SSE protocol basics
//!
//! SSE (RFC 8895 / W3C EventSource) is a one-way server→client streaming
//! protocol over plain HTTP. The client (typically `EventSource` in a browser)
//! sends a GET request with `Accept: text/event-stream`, and the server holds
//! the connection open, pushing `data:` frames as `text/event-stream` chunks.
//!
//! ## Plugin lifecycle
//!
//! 1. **`on_request_received`** — Validates inbound SSE client criteria:
//!    - Method must be GET (SSE is read-only, no request body)
//!    - `Accept` header must include `text/event-stream`
//!    - Optionally validates `Last-Event-ID` format for reconnection
//!    - Rejects non-conforming requests with 405 (wrong method) or 406 (wrong Accept)
//!
//! 2. **`before_proxy`** — Shapes the request for the upstream backend:
//!    - Strips `Accept-Encoding` to prevent compressed chunked responses that
//!      break SSE framing (SSE relies on line-delimited text over chunked transfer)
//!    - Forwards `Last-Event-ID` as a header so the backend can resume the stream
//!    - Stores the original `Accept` value in metadata for the response phase
//!
//! 3. **`after_proxy`** — Sets proper SSE response headers:
//!    - `Cache-Control: no-cache` (SSE streams must not be cached)
//!    - `Connection: keep-alive` (long-lived streaming connection)
//!    - `X-Accel-Buffering: no` (disables nginx/ALB response buffering)
//!    - Strips `Content-Length` (SSE streams are indefinite)
//!    - Optionally forces `Content-Type: text/event-stream` on non-SSE backends
//!
//! 4. **`transform_response_body`** — Optionally wraps non-SSE upstream
//!    responses into `data: ...\n\n` SSE event framing (buffered responses only).
//!
//! ## Config
//!
//! ```json
//! {
//!   "require_accept_header": true,
//!   "require_get_method": true,
//!   "strip_accept_encoding": true,
//!   "add_no_buffering_header": true,
//!   "strip_content_length": true,
//!   "retry_ms": 3000,
//!   "force_sse_content_type": false,
//!   "wrap_non_sse_responses": false
//! }
//! ```

use async_trait::async_trait;
use serde_json::Value;
use std::collections::HashMap;
use tracing::{debug, warn};

use super::{PluginResult, RequestContext};

pub struct SsePlugin {
    // ── Request validation ───────────────────────────────────────────────
    /// Require `Accept: text/event-stream` header. Default: true.
    require_accept_header: bool,
    /// Require GET method (SSE is read-only). Default: true.
    require_get_method: bool,

    // ── Request shaping ──────────────────────────────────────────────────
    /// Strip `Accept-Encoding` to prevent compressed chunked responses that
    /// break SSE line-delimited framing. Default: true.
    strip_accept_encoding: bool,

    // ── Response shaping ─────────────────────────────────────────────────
    /// Add `X-Accel-Buffering: no` to disable upstream proxy buffering. Default: true.
    add_no_buffering_header: bool,
    /// Strip `Content-Length` from SSE responses (streams are indefinite). Default: true.
    strip_content_length: bool,
    /// Reconnection interval hint (ms). When set, stored in metadata and
    /// prepended as `retry: <ms>\n` when wrapping responses. Default: none.
    retry_ms: Option<u64>,
    /// Force `Content-Type: text/event-stream` even if the backend returns
    /// a different content type. Default: false.
    force_sse_content_type: bool,
    /// Wrap non-SSE response bodies in `data: ...\n\n` SSE event framing.
    /// Only applies to buffered responses. Default: false.
    wrap_non_sse_responses: bool,
}

impl SsePlugin {
    pub fn new(config: &Value) -> Result<Self, String> {
        let require_accept_header = config["require_accept_header"].as_bool().unwrap_or(true);
        let require_get_method = config["require_get_method"].as_bool().unwrap_or(true);
        let strip_accept_encoding = config["strip_accept_encoding"].as_bool().unwrap_or(true);
        let add_no_buffering_header = config["add_no_buffering_header"].as_bool().unwrap_or(true);
        let strip_content_length = config["strip_content_length"].as_bool().unwrap_or(true);
        let retry_ms = config["retry_ms"].as_u64();
        let force_sse_content_type = config["force_sse_content_type"].as_bool().unwrap_or(false);
        let wrap_non_sse_responses = config["wrap_non_sse_responses"].as_bool().unwrap_or(false);

        Ok(Self {
            require_accept_header,
            require_get_method,
            strip_accept_encoding,
            add_no_buffering_header,
            strip_content_length,
            retry_ms,
            force_sse_content_type,
            wrap_non_sse_responses,
        })
    }

    /// Returns true if the `Accept` header includes `text/event-stream`.
    fn accepts_event_stream(accept: &str) -> bool {
        accept
            .split(',')
            .any(|part| part.trim().to_lowercase().starts_with("text/event-stream"))
    }

    /// Returns true if the response `Content-Type` is `text/event-stream`.
    fn is_sse_content_type(content_type: &str) -> bool {
        content_type.to_lowercase().starts_with("text/event-stream")
    }
}

#[async_trait]
impl super::Plugin for SsePlugin {
    fn name(&self) -> &str {
        "sse"
    }

    fn priority(&self) -> u16 {
        super::priority::SSE
    }

    fn supported_protocols(&self) -> &'static [super::ProxyProtocol] {
        super::HTTP_ONLY_PROTOCOLS
    }

    fn modifies_request_headers(&self) -> bool {
        self.strip_accept_encoding
    }

    fn requires_response_body_buffering(&self) -> bool {
        self.wrap_non_sse_responses
    }

    fn applies_after_proxy_on_reject(&self) -> bool {
        false
    }

    // ── Phase 1: Validate inbound SSE client request ─────────────────────

    async fn on_request_received(&self, ctx: &mut RequestContext) -> PluginResult {
        // SSE is a read-only protocol — only GET is valid.
        if self.require_get_method && ctx.method != "GET" {
            warn!(
                plugin = "sse",
                method = %ctx.method,
                "SSE request rejected: method must be GET"
            );
            return PluginResult::Reject {
                status_code: 405,
                body: r#"{"error":"SSE requires GET method"}"#.to_string(),
                headers: HashMap::from([("allow".to_string(), "GET".to_string())]),
            };
        }

        // A conforming SSE client sends Accept: text/event-stream.
        if self.require_accept_header {
            let accepts_sse = ctx
                .headers
                .get("accept")
                .is_some_and(|v| Self::accepts_event_stream(v));

            if !accepts_sse {
                warn!(
                    plugin = "sse",
                    accept = ?ctx.headers.get("accept"),
                    "SSE request rejected: Accept header must include text/event-stream"
                );
                return PluginResult::Reject {
                    status_code: 406,
                    body: r#"{"error":"Accept header must include text/event-stream"}"#.to_string(),
                    headers: HashMap::new(),
                };
            }
        }

        // Stash Last-Event-ID in metadata so before_proxy can forward it and
        // the backend can resume the stream from the correct position.
        if let Some(last_id) = ctx.headers.get("last-event-id") {
            ctx.metadata
                .insert("sse:last_event_id".to_string(), last_id.clone());
            debug!(plugin = "sse", last_event_id = %last_id, "SSE reconnection with Last-Event-ID");
        }

        debug!(plugin = "sse", "SSE client request validated");
        PluginResult::Continue
    }

    // ── Phase 2: Shape request for backend ───────────────────────────────

    async fn before_proxy(
        &self,
        ctx: &mut RequestContext,
        headers: &mut HashMap<String, String>,
    ) -> PluginResult {
        // Save original Accept for the response phase.
        // Read from `headers` param — ctx.headers may be empty when the handler
        // uses the zero-clone fast path (std::mem::take).
        if let Some(accept) = headers.get("accept") {
            ctx.metadata
                .insert("sse:original_accept".to_string(), accept.clone());
        }

        // Strip Accept-Encoding to prevent the backend from gzip-compressing
        // the SSE stream. Compressed chunked responses break SSE's
        // line-delimited text framing — the EventSource parser expects raw
        // UTF-8 lines, not a zlib bitstream.
        if self.strip_accept_encoding {
            headers.remove("accept-encoding");
        }

        // Ensure Last-Event-ID is forwarded as a header. Some clients send it
        // only as a query parameter; the metadata stash from on_request_received
        // ensures it's always available. The header takes precedence if both exist.
        if let Some(last_id) = ctx.metadata.get("sse:last_event_id") {
            headers
                .entry("last-event-id".to_string())
                .or_insert_with(|| last_id.clone());
        }

        debug!(plugin = "sse", "SSE request shaped for backend");
        PluginResult::Continue
    }

    // ── Phase 3: Set SSE response headers ────────────────────────────────

    async fn after_proxy(
        &self,
        ctx: &mut RequestContext,
        _response_status: u16,
        response_headers: &mut HashMap<String, String>,
    ) -> PluginResult {
        let is_sse = response_headers
            .get("content-type")
            .is_some_and(|ct| Self::is_sse_content_type(ct));

        // If the backend didn't return SSE and we're not forcing, nothing to do.
        if !is_sse && !self.force_sse_content_type {
            return PluginResult::Continue;
        }

        // Force Content-Type to text/event-stream if the backend returned
        // something else (e.g., application/json from a generic endpoint).
        if self.force_sse_content_type && !is_sse {
            response_headers.insert("content-type".to_string(), "text/event-stream".to_string());
            debug!(plugin = "sse", "forced Content-Type to text/event-stream");
        }

        // SSE streams must not be cached — stale events are meaningless.
        response_headers.insert("cache-control".to_string(), "no-cache".to_string());

        // Keep-alive signals that this is a long-lived streaming connection.
        response_headers.insert("connection".to_string(), "keep-alive".to_string());

        // Disable reverse-proxy buffering (nginx X-Accel-Buffering, AWS ALB, etc.).
        // Without this, intermediary proxies may buffer the entire response before
        // forwarding, defeating the purpose of streaming.
        if self.add_no_buffering_header {
            response_headers.insert("x-accel-buffering".to_string(), "no".to_string());
        }

        // SSE streams are indefinite — Content-Length is meaningless and can
        // confuse clients into closing the connection after N bytes.
        if self.strip_content_length {
            response_headers.remove("content-length");
        }

        // Store retry hint in metadata for transform_response_body.
        if let Some(retry) = self.retry_ms {
            ctx.metadata
                .insert("sse:retry_ms".to_string(), retry.to_string());
        }

        debug!(plugin = "sse", "SSE response headers applied");
        PluginResult::Continue
    }

    // ── Phase 4: Optionally wrap non-SSE body into SSE framing ───────────

    async fn transform_response_body(
        &self,
        body: &[u8],
        content_type: Option<&str>,
        _response_headers: &HashMap<String, String>,
    ) -> Option<Vec<u8>> {
        if !self.wrap_non_sse_responses || body.is_empty() {
            return None;
        }

        // Don't double-wrap a response that's already SSE.
        if let Some(ct) = content_type
            && Self::is_sse_content_type(ct)
        {
            return None;
        }

        // Build the SSE event. Per the spec, multi-line data uses one
        // `data:` field per line, and a blank line terminates the event.
        let body_str = String::from_utf8_lossy(body);
        let mut output = Vec::with_capacity(body.len() + 64);

        // Prepend `retry:` field if configured — tells the EventSource client
        // how long to wait before reconnecting after a disconnect.
        if let Some(retry) = self.retry_ms {
            output.extend_from_slice(b"retry: ");
            output.extend_from_slice(retry.to_string().as_bytes());
            output.push(b'\n');
        }

        for line in body_str.lines() {
            output.extend_from_slice(b"data: ");
            output.extend_from_slice(line.as_bytes());
            output.push(b'\n');
        }
        // Blank line terminates the event.
        output.push(b'\n');

        debug!(
            plugin = "sse",
            original_bytes = body.len(),
            wrapped_bytes = output.len(),
            "wrapped response into SSE event"
        );
        Some(output)
    }
}
