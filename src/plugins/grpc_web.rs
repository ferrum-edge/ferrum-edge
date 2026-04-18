//! gRPC-Web protocol translation plugin.
//!
//! Translates between gRPC-Web (browser-compatible, RFC: github.com/grpc/grpc/blob/master/doc/PROTOCOL-WEB.md)
//! and native gRPC (HTTP/2) wire formats. Enables browser clients to call gRPC
//! backends through the gateway without a dedicated gRPC-Web proxy like Envoy or
//! grpc-web-proxy.
//!
//! Supports both encoding modes:
//! - **Binary** (`application/grpc-web`, `application/grpc-web+proto`): same
//!   length-prefixed framing as native gRPC, passthrough on request path.
//! - **Text** (`application/grpc-web-text`, `application/grpc-web-text+proto`):
//!   base64-encoded binary frames, decoded on request and re-encoded on response.
//!
//! ## Request path (gRPC-Web → native gRPC)
//!
//! 1. Detect `application/grpc-web*` content-type
//! 2. Rewrite content-type to `application/grpc` for the backend
//! 3. Text mode: base64-decode the request body
//!
//! ## Response path (native gRPC → gRPC-Web)
//!
//! 1. Collect response data frames from the backend
//! 2. Embed gRPC trailers (grpc-status, grpc-message, plus any custom metadata)
//!    as a length-prefixed trailer frame (flag byte 0x80) appended to the body
//! 3. Text mode: base64-encode the entire response body
//! 4. Rewrite response content-type to the original gRPC-Web variant
//!
//! ## Configuration
//!
//! ```json
//! {
//!   "name": "grpc_web",
//!   "config": {
//!     "expose_headers": ["custom-header-bin"]
//!   }
//! }
//! ```
//!
//! - `expose_headers` (optional): Additional response headers to include in
//!   `Access-Control-Expose-Headers` for browser CORS compatibility. The plugin
//!   always exposes `grpc-status` and `grpc-message`.

use async_trait::async_trait;
use base64::Engine;
use base64::engine::general_purpose::STANDARD as BASE64;
use serde_json::Value;
use std::collections::HashMap;
use tracing::debug;

use super::{HTTP_GRPC_PROTOCOLS, Plugin, PluginResult, ProxyProtocol, RequestContext};

/// Metadata key storing the original gRPC-Web mode ("text" or "binary").
const META_GRPC_WEB_MODE: &str = "grpc_web_mode";
/// Metadata key storing the original content-type for response rewriting.
const META_GRPC_WEB_ORIGINAL_CT: &str = "grpc_web_original_ct";

/// Internal proxy header injected by `before_proxy` so that `transform_request_body`
/// (which lacks access to `ctx.metadata`) can deterministically identify the
/// gRPC-Web encoding mode. Stripped before reaching the backend by the gateway's
/// hop-by-hop header removal.
const HEADER_GRPC_WEB_MODE: &str = "x-grpc-web-mode";

/// gRPC frame flag: data frame.
pub(crate) const GRPC_FRAME_DATA: u8 = 0x00;
/// gRPC frame flag: trailer frame (used in gRPC-Web to embed trailers in body).
pub(crate) const GRPC_FRAME_TRAILER: u8 = 0x80;

/// Returns a header map with `content-type: application/grpc` for gRPC error responses.
fn grpc_content_type_header() -> HashMap<String, String> {
    let mut h = HashMap::new();
    h.insert("content-type".to_string(), "application/grpc".to_string());
    h
}

pub struct GrpcWebPlugin {
    expose_headers: Vec<String>,
}

impl GrpcWebPlugin {
    pub fn new(config: &Value) -> Result<Self, String> {
        let expose_headers = config["expose_headers"]
            .as_array()
            .map(|arr| {
                arr.iter()
                    .filter_map(|v| v.as_str().map(|s| s.to_lowercase()))
                    .collect()
            })
            .unwrap_or_default();

        Ok(Self { expose_headers })
    }
}

/// Check if a content-type indicates a gRPC-Web request.
pub(crate) fn is_grpc_web_content_type(ct: &str) -> bool {
    let ct_lower = ct.trim().to_lowercase();
    ct_lower.starts_with("application/grpc-web")
}

/// Check if a gRPC-Web content-type uses text (base64) encoding.
pub(crate) fn is_grpc_web_text(ct: &str) -> bool {
    let ct_lower = ct.trim().to_lowercase();
    ct_lower.starts_with("application/grpc-web-text")
}

/// Build a gRPC-Web trailer frame from response headers.
///
/// The trailer frame format is:
/// - 1 byte: 0x80 (trailer flag)
/// - 4 bytes: big-endian u32 length of trailer payload
/// - N bytes: trailer payload (HTTP header encoding: `key: value\r\n`)
pub(crate) fn build_trailer_frame(response_headers: &HashMap<String, String>) -> Vec<u8> {
    let mut trailer_payload = Vec::new();
    for (key, value) in response_headers {
        // Include grpc-* trailers and any custom trailing metadata
        if key.starts_with("grpc-") || key.ends_with("-bin") {
            trailer_payload.extend_from_slice(key.as_bytes());
            trailer_payload.extend_from_slice(b": ");
            trailer_payload.extend_from_slice(value.as_bytes());
            trailer_payload.extend_from_slice(b"\r\n");
        }
    }

    // If no trailers found, still emit a minimal frame with grpc-status: 0
    if trailer_payload.is_empty() {
        trailer_payload.extend_from_slice(b"grpc-status: 0\r\n");
    }

    let len = trailer_payload.len() as u32;
    let mut frame = Vec::with_capacity(5 + trailer_payload.len());
    frame.push(GRPC_FRAME_TRAILER);
    frame.extend_from_slice(&len.to_be_bytes());
    frame.extend(trailer_payload);
    frame
}

/// Parse gRPC length-prefixed frames from a byte buffer.
///
/// Returns a list of (flag, payload) tuples. Used to separate data frames
/// from trailer frames in gRPC-Web responses.
#[allow(dead_code)]
pub(crate) fn parse_grpc_frames(data: &[u8]) -> Vec<(u8, Vec<u8>)> {
    let mut frames = Vec::new();
    let mut pos = 0;
    while pos + 5 <= data.len() {
        let flag = data[pos];
        let len = u32::from_be_bytes([data[pos + 1], data[pos + 2], data[pos + 3], data[pos + 4]])
            as usize;
        pos += 5;
        if pos + len > data.len() {
            break;
        }
        frames.push((flag, data[pos..pos + len].to_vec()));
        pos += len;
    }
    frames
}

/// Map an original gRPC-Web content-type to the response content-type.
///
/// Preserves the +proto suffix if present.
pub(crate) fn response_content_type(original_ct: &str) -> &'static str {
    let ct_lower = original_ct.trim().to_lowercase();
    if ct_lower.starts_with("application/grpc-web-text") {
        if ct_lower.contains("+proto") {
            "application/grpc-web-text+proto"
        } else {
            "application/grpc-web-text"
        }
    } else if ct_lower.contains("+proto") {
        "application/grpc-web+proto"
    } else {
        "application/grpc-web"
    }
}

#[async_trait]
impl Plugin for GrpcWebPlugin {
    fn name(&self) -> &str {
        "grpc_web"
    }

    fn priority(&self) -> u16 {
        super::priority::GRPC_WEB
    }

    fn supported_protocols(&self) -> &'static [ProxyProtocol] {
        HTTP_GRPC_PROTOCOLS
    }

    fn modifies_request_headers(&self) -> bool {
        true
    }

    fn modifies_request_body(&self) -> bool {
        true
    }

    fn should_buffer_request_body(&self, ctx: &RequestContext) -> bool {
        // Only buffer for text mode (needs base64 decoding).
        // Binary mode body is already native gRPC framing.
        ctx.metadata
            .get(META_GRPC_WEB_MODE)
            .is_some_and(|m| m == "text")
    }

    fn requires_response_body_buffering(&self) -> bool {
        // Both binary and text modes require response buffering because HTTP/2
        // trailers from the backend (grpc-status, grpc-message) must be embedded
        // as a length-prefixed trailer frame (0x80) in the response body — this
        // is the core gRPC-Web wire format difference from native gRPC. Text mode
        // additionally needs base64 encoding of the complete body.
        true
    }

    async fn on_request_received(&self, ctx: &mut RequestContext) -> PluginResult {
        // Always strip the internal mode marker from inbound headers so a client
        // cannot spoof it. The plugin re-injects it in `before_proxy` only when
        // `on_request_received` confirmed a genuine gRPC-Web request via the
        // content-type. Without this, a client could send a non-gRPC-Web request
        // with `x-grpc-web-mode: text` and trigger base64-decode of the body in
        // `transform_request_body`, which the gateway would then forward in
        // mangled form.
        ctx.headers.remove(HEADER_GRPC_WEB_MODE);

        let content_type = match ctx.headers.get("content-type") {
            Some(ct) => ct.clone(),
            None => return PluginResult::Continue,
        };

        if !is_grpc_web_content_type(&content_type) {
            return PluginResult::Continue;
        }

        let mode = if is_grpc_web_text(&content_type) {
            "text"
        } else {
            "binary"
        };

        debug!(
            plugin = "grpc_web",
            mode = mode,
            original_ct = %content_type,
            "Detected gRPC-Web request"
        );

        // Store original info for response path
        ctx.metadata
            .insert(META_GRPC_WEB_MODE.to_string(), mode.to_string());
        ctx.metadata
            .insert(META_GRPC_WEB_ORIGINAL_CT.to_string(), content_type.clone());

        // Rewrite content-type so downstream plugins and the gRPC proxy
        // treat this as a native gRPC request.
        ctx.headers
            .insert("content-type".to_string(), "application/grpc".to_string());

        PluginResult::Continue
    }

    async fn before_proxy(
        &self,
        ctx: &mut RequestContext,
        headers: &mut HashMap<String, String>,
    ) -> PluginResult {
        // Only act if this was a gRPC-Web request
        let mode = match ctx.metadata.get(META_GRPC_WEB_MODE) {
            Some(m) => m.clone(),
            None => return PluginResult::Continue,
        };

        // Ensure outgoing content-type is native gRPC
        headers.insert("content-type".to_string(), "application/grpc".to_string());

        // Inject mode marker so transform_request_body (which lacks ctx access)
        // can deterministically identify text vs binary mode.
        headers.insert(HEADER_GRPC_WEB_MODE.to_string(), mode);

        // Remove headers that are gRPC-Web specific and shouldn't reach the backend
        headers.remove("x-grpc-web");

        PluginResult::Continue
    }

    async fn transform_request_body(
        &self,
        body: &[u8],
        _content_type: Option<&str>,
        request_headers: &HashMap<String, String>,
    ) -> Option<Vec<u8>> {
        // Only transform text mode (base64-encoded). The mode marker was injected
        // by before_proxy so we have a deterministic signal — no heuristics.
        let is_text = request_headers
            .get(HEADER_GRPC_WEB_MODE)
            .is_some_and(|m| m == "text");

        if !is_text || body.is_empty() {
            return None;
        }

        // Base64 decode — gRPC-Web text mode uses standard base64.
        // On failure, return the raw body unchanged; on_final_request_body will
        // reject it with a 400 after validating gRPC framing.
        match BASE64.decode(body) {
            Ok(decoded) => {
                debug!(
                    plugin = "grpc_web",
                    original_len = body.len(),
                    decoded_len = decoded.len(),
                    "Base64-decoded gRPC-Web text request body"
                );
                Some(decoded)
            }
            Err(e) => {
                debug!(
                    plugin = "grpc_web",
                    error = %e,
                    "Failed to base64-decode gRPC-Web text request body"
                );
                // Return None to pass through; on_final_request_body will catch
                // the invalid framing and reject with 400.
                None
            }
        }
    }

    async fn on_final_request_body(
        &self,
        headers: &HashMap<String, String>,
        body: &[u8],
    ) -> PluginResult {
        // Only validate text mode requests — binary mode bodies are native gRPC.
        let is_text = headers
            .get(HEADER_GRPC_WEB_MODE)
            .is_some_and(|m| m == "text");

        if !is_text {
            return PluginResult::Continue;
        }

        // Validate that the body (post-transform) has valid gRPC length-prefixed
        // framing. If base64 decode failed or produced garbage, reject early with
        // a clear error rather than sending corrupt data to the backend.
        if body.len() < 5 {
            return PluginResult::Reject {
                status_code: 400,
                body:
                    r#"{"error":"Invalid gRPC-Web text request: body too short for gRPC framing"}"#
                        .to_string(),
                headers: grpc_content_type_header(),
            };
        }

        let flag = body[0];
        if flag != GRPC_FRAME_DATA && flag != GRPC_FRAME_TRAILER {
            return PluginResult::Reject {
                status_code: 400,
                body: r#"{"error":"Invalid gRPC-Web text request: invalid base64 encoding or corrupted gRPC framing"}"#.to_string(),
                headers: grpc_content_type_header(),
            };
        }

        PluginResult::Continue
    }

    async fn after_proxy(
        &self,
        ctx: &mut RequestContext,
        _response_status: u16,
        response_headers: &mut HashMap<String, String>,
    ) -> PluginResult {
        let original_ct = match ctx.metadata.get(META_GRPC_WEB_ORIGINAL_CT) {
            Some(ct) => ct.clone(),
            None => return PluginResult::Continue,
        };

        // Rewrite response content-type to the gRPC-Web variant
        let resp_ct = response_content_type(&original_ct);
        response_headers.insert("content-type".to_string(), resp_ct.to_string());

        // Signal to clients that this is a gRPC-Web response
        response_headers.insert("x-grpc-web".to_string(), "1".to_string());

        // Add CORS-friendly expose headers so browsers can read gRPC metadata.
        // We MUST set this whether or not the backend already returned an
        // expose-headers value — gRPC-Web is intrinsically a browser protocol
        // and grpc-status/grpc-message are unreadable from JavaScript without it.
        // (Previously this branch was a no-op when the backend didn't emit
        // access-control-expose-headers, which broke browser clients on backends
        // that didn't already configure CORS.)
        let mut expose = vec![
            "grpc-status".to_string(),
            "grpc-message".to_string(),
            "grpc-status-details-bin".to_string(),
        ];
        expose.extend(self.expose_headers.iter().cloned());

        let combined = match response_headers.get("access-control-expose-headers") {
            Some(existing) => {
                let existing_lower = existing.to_lowercase();
                let mut out = existing.clone();
                for h in &expose {
                    if !existing_lower
                        .split(',')
                        .any(|tok| tok.trim().eq_ignore_ascii_case(h))
                    {
                        out.push_str(", ");
                        out.push_str(h);
                    }
                }
                out
            }
            None => expose.join(", "),
        };
        response_headers.insert("access-control-expose-headers".to_string(), combined);

        debug!(
            plugin = "grpc_web",
            response_ct = resp_ct,
            "Rewrote response headers for gRPC-Web"
        );

        PluginResult::Continue
    }

    async fn transform_response_body(
        &self,
        body: &[u8],
        _content_type: Option<&str>,
        response_headers: &HashMap<String, String>,
    ) -> Option<Vec<u8>> {
        // Only transform if response content-type is gRPC-Web (set by after_proxy)
        let ct = response_headers.get("content-type")?;
        if !is_grpc_web_content_type(ct) {
            return None;
        }

        let is_text = is_grpc_web_text(ct);

        // Build the gRPC-Web response:
        // 1. Keep existing data frames from the body
        // 2. Append a trailer frame with gRPC status metadata
        let mut output = Vec::with_capacity(body.len() + 64);

        // Copy the original response body (data frames)
        output.extend_from_slice(body);

        // Build and append trailer frame from response headers
        let trailer_frame = build_trailer_frame(response_headers);
        output.extend(trailer_frame);

        // For text mode, base64-encode the entire output
        if is_text {
            let encoded = BASE64.encode(&output);
            debug!(
                plugin = "grpc_web",
                binary_len = output.len(),
                encoded_len = encoded.len(),
                "Base64-encoded gRPC-Web text response body"
            );
            Some(encoded.into_bytes())
        } else {
            debug!(
                plugin = "grpc_web",
                body_len = output.len(),
                "Built gRPC-Web binary response with trailer frame"
            );
            Some(output)
        }
    }
}
