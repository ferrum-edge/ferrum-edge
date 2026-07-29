//! Correlation ID / Request ID Plugin
//!
//! Generates a unique request ID for every request and propagates it
//! through the proxy chain. If the client sends one, it is preserved.

use async_trait::async_trait;
use serde_json::Value;
use std::collections::HashMap;
use uuid::Uuid;

use super::{Plugin, PluginResult, RequestContext};

const INSTANCE_METADATA_PREFIX: &str = "correlation_id.instance.";

const RESERVED_HEADER_NAMES: &[&str] = &[
    "api-key",
    "authentication-info",
    "authorization",
    "connection",
    "content-encoding",
    "content-length",
    "cookie",
    "early-data",
    "expect",
    "forwarded",
    "grpc-message",
    "grpc-status",
    "grpc-status-details-bin",
    "host",
    "keep-alive",
    "proxy-authenticate",
    "proxy-authentication-info",
    "proxy-authorization",
    "proxy-connection",
    "sec-websocket-accept",
    "sec-websocket-extensions",
    "sec-websocket-key",
    "sec-websocket-protocol",
    "sec-websocket-version",
    "set-cookie",
    "te",
    "traceparent",
    "tracestate",
    "trailer",
    "transfer-encoding",
    "upgrade",
    "via",
    "www-authenticate",
    "x-api-key",
    "x-auth-token",
    "x-csrf-token",
    "x-ferrum-original-content-encoding",
    "x-forwarded-authorization",
    "x-forwarded-for",
    "x-forwarded-host",
    "x-forwarded-proto",
    "x-goog-api-key",
    "x-grpc-web-mode",
    "x-xsrf-token",
];

pub struct CorrelationId {
    header_name: String,
    instance_metadata_key: String,
    echo_downstream: bool,
    /// `[header_name]` when `echo_downstream` is on, empty otherwise.
    /// Precomputed so `Plugin::response_trailer_policy` can hand out a bounded
    /// slice without allocating per request.
    echoed_header_names: Vec<String>,
}

impl CorrelationId {
    pub fn new(config: &Value) -> Result<Self, String> {
        Self::new_with_real_ip_header(config, None)
    }

    pub(crate) fn new_with_real_ip_header(
        config: &Value,
        real_ip_header: Option<&str>,
    ) -> Result<Self, String> {
        let object = config
            .as_object()
            .ok_or_else(|| "correlation_id: config must be a JSON object".to_string())?;
        let mut unknown_keys: Vec<&str> = object
            .keys()
            .map(String::as_str)
            .filter(|key| !matches!(*key, "header_name" | "echo_downstream"))
            .collect();
        if !unknown_keys.is_empty() {
            unknown_keys.sort_unstable();
            return Err(format!(
                "correlation_id: unknown config field(s): {}",
                unknown_keys.join(", ")
            ));
        }

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
                let lower = trimmed.to_ascii_lowercase();
                if is_reserved_header_name(&lower) {
                    return Err(format!(
                        "correlation_id: 'header_name' is protocol-managed or security-sensitive and cannot be used for correlation IDs: {trimmed:?}"
                    ));
                }
                lower
            }
            Some(other) => {
                return Err(format!(
                    "correlation_id: 'header_name' must be a string, got: {}",
                    other
                ));
            }
        };

        if real_ip_header.is_some_and(|configured| header_name.eq_ignore_ascii_case(configured)) {
            return Err(format!(
                "correlation_id: 'header_name' conflicts with the effective FERRUM_REAL_IP_HEADER client-attribution header and cannot be used for correlation IDs: {header_name:?}"
            ));
        }

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

        let instance_metadata_key = format!("{INSTANCE_METADATA_PREFIX}{header_name}");
        let echoed_header_names = if echo_downstream {
            vec![header_name.clone()]
        } else {
            Vec::new()
        };
        Ok(Self {
            header_name,
            instance_metadata_key,
            echo_downstream,
            echoed_header_names,
        })
    }

    fn request_id<'a>(&self, ctx: &'a RequestContext) -> Option<&'a str> {
        ctx.correlation_id(&self.instance_metadata_key)
    }
}

pub(crate) fn is_reserved_header_name(name: &str) -> bool {
    RESERVED_HEADER_NAMES.contains(&name)
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

/// Validate an untrusted inbound correlation id value.
///
/// Accepts a non-empty value composed solely of ASCII alphanumerics and a
/// small allowlist (`-`, `_`, `.`). This covers UUIDs, ULIDs, and typical
/// trace/span ids while rejecting control characters (HTAB, DEL), obs-text
/// (0x80-0xFF), spaces, and other non-token bytes that `http::HeaderValue`
/// permits but that should not be reflected into logs/headers verbatim.
fn is_valid_correlation_id(value: &str) -> bool {
    !value.is_empty()
        && value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.'))
}

#[async_trait]
impl Plugin for CorrelationId {
    fn name(&self) -> &str {
        "correlation_id"
    }

    fn correlation_id_header_name(&self) -> Option<&str> {
        Some(&self.header_name)
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
        ctx.publish_correlation_id(&self.instance_metadata_key, id);
        super::PluginResult::Continue
    }

    async fn on_request_received(&self, ctx: &mut RequestContext) -> PluginResult {
        let request_id = if let Some(existing) = ctx.headers.get(&self.header_name) {
            // Preserve the client-supplied id only when it is both within the
            // length cap AND made up of safe correlation-id characters. The
            // inbound value is untrusted and is reflected downstream, forwarded
            // upstream, and projected into `ctx.metadata["request_id"]` for
            // logging sinks. `http::HeaderValue` already blocks CR/LF/NUL, but
            // it legally permits HTAB, DEL (0x7F), and obs-text (0x80-0xFF),
            // which could pollute a plain-text log sink or a downstream consumer
            // expecting a token. Reject those by regenerating a fresh UUID —
            // mirroring the over-length branch and the RFC 7230 strictness
            // already applied to `header_name`. (Finding #69.)
            if existing.len() <= 256 && is_valid_correlation_id(existing) {
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

        // Keep each authoritative instance value in private lifecycle state
        // across phase-separated execution. Public metadata is a compatibility
        // projection only. The first instance in configured lifecycle order
        // also owns the canonical consumer-facing request ID.
        ctx.publish_correlation_id(&self.instance_metadata_key, request_id);

        PluginResult::Continue
    }

    async fn before_proxy(
        &self,
        ctx: &mut RequestContext,
        headers: &mut HashMap<String, String>,
    ) -> PluginResult {
        // Ensure the correlation ID header is in the outgoing request
        if let Some(request_id) = self.request_id(ctx) {
            headers.insert(self.header_name.clone(), request_id.to_string());
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
            && let Some(request_id) = self.request_id(ctx)
        {
            response_headers.insert(self.header_name.clone(), request_id.to_string());
        }
        PluginResult::Continue
    }

    fn apply_websocket_handshake_response_headers(
        &self,
        ctx: &RequestContext,
        _response_status: u16,
        response_headers: &mut HashMap<String, String>,
    ) {
        if self.echo_downstream
            && let Some(request_id) = self.request_id(ctx)
        {
            response_headers.insert(self.header_name.clone(), request_id.to_string());
        }
    }

    fn applies_after_proxy_on_reject(&self) -> bool {
        self.echo_downstream
    }

    fn owns_deadline_response_header(&self, ctx: &RequestContext, name: &str) -> bool {
        self.echo_downstream
            && self.request_id(ctx).is_some()
            && name.eq_ignore_ascii_case(&self.header_name)
    }

    /// The echoed correlation ID is the gateway's own value, and a client that
    /// reads a different one from a backend trailer loses the ability to
    /// correlate at all. A backend that echoes the identical request ID (the
    /// common case — it was sent upstream in `before_proxy`) makes the
    /// `after_proxy` write invisible to observed-mutation reconciliation, so the
    /// declaration is the only signal that binds the trailer channel here.
    fn response_trailer_policy(&self) -> super::ResponseTrailerPolicy<'_> {
        super::ResponseTrailerPolicy::Names(&self.echoed_header_names)
    }
}
