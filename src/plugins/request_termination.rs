//! Request Termination / Mocking Plugin
//!
//! Returns a canned response without proxying to the backend.
//! Useful for maintenance mode, mocking APIs, or blocking specific paths.
//! Supports JSON, XML, and plain text response bodies with configurable
//! content type and HTTP status code.
//!
//! The response body and `content-type` value are computed **once** at
//! construction time so the request hot path only does string clones —
//! no per-request `format!()`, no `String::replace()` chains, no JSON/XML
//! escape work.

use async_trait::async_trait;
use serde_json::Value;
use std::collections::HashMap;

use super::{Plugin, PluginResult, RequestContext};

#[derive(Debug, Clone)]
enum Trigger {
    Always,
    PathPrefix(String),
    HeaderMatch { header: String, value: String },
}

pub struct RequestTermination {
    status_code: u16,
    /// Pre-computed `content-type` header value.
    content_type: String,
    /// Pre-rendered response body. Built once from `body`, `message`,
    /// `content_type`, and `status_code` at construction time so the hot path
    /// never re-renders it.
    body: String,
    trigger: Trigger,
}

impl RequestTermination {
    pub fn new(config: &Value) -> Result<Self, String> {
        let status_code = config["status_code"]
            .as_u64()
            .map(|c| c as u16)
            .filter(|&c| (100..=599).contains(&c))
            .unwrap_or(503);
        let content_type = config["content_type"]
            .as_str()
            .unwrap_or("application/json")
            .to_string();
        let raw_body = config["body"].as_str().unwrap_or("");
        let message = config["message"].as_str();

        // Pre-render the response body so the hot path skips format!/replace.
        let body = if !raw_body.is_empty() {
            raw_body.to_string()
        } else {
            render_default_body(&content_type, status_code, message)
        };

        let trigger = if let Some(path) = config["trigger"]["path_prefix"].as_str() {
            Trigger::PathPrefix(path.to_string())
        } else if let Some(header) = config["trigger"]["header"].as_str() {
            let value = config["trigger"]["header_value"]
                .as_str()
                .unwrap_or("")
                .to_string();
            Trigger::HeaderMatch {
                header: header.to_lowercase(),
                value,
            }
        } else {
            Trigger::Always
        };

        Ok(Self {
            status_code,
            content_type,
            body,
            trigger,
        })
    }
}

/// Render the default response body for a given content type. Performed once
/// at construction time — never on the hot path.
fn render_default_body(content_type: &str, status_code: u16, message: Option<&str>) -> String {
    let msg = message.unwrap_or("Service unavailable");

    match classify_media_type(content_type) {
        MediaType::Json => {
            // serde_json::to_string produces a fully-spec-compliant JSON string
            // literal (quoted, with control chars / non-ASCII / backslashes / quotes
            // all escaped). Infallible for `&str` input.
            let encoded = serde_json::to_string(msg).unwrap_or_else(|_| "\"\"".to_string());
            format!(r#"{{"message":{},"status_code":{}}}"#, encoded, status_code)
        }
        MediaType::Xml => {
            let escaped = xml_escape(msg);
            format!(
                r#"<?xml version="1.0"?><response><message>{}</message><status_code>{}</status_code></response>"#,
                escaped, status_code
            )
        }
        MediaType::Other => msg.to_string(),
    }
}

enum MediaType {
    Json,
    Xml,
    Other,
}

/// Classifies the subtype of an RFC 6838 media type string. Handles structured
/// suffixes (`application/hal+json`, `application/vnd.api+xml`) and parameter
/// stripping (`; charset=utf-8`), without matching bogus types like
/// `application/notjson`.
fn classify_media_type(content_type: &str) -> MediaType {
    // Strip parameters after ';', trim whitespace.
    let head = content_type
        .split(';')
        .next()
        .unwrap_or(content_type)
        .trim();
    // Extract subtype after '/'.
    let subtype = head.rsplit('/').next().unwrap_or(head).trim();
    // Match exact subtype or RFC 6838 structured suffix (`+json`, `+xml`).
    let sub_lower = subtype.to_ascii_lowercase();
    if sub_lower == "json" || sub_lower.ends_with("+json") {
        MediaType::Json
    } else if sub_lower == "xml" || sub_lower.ends_with("+xml") {
        MediaType::Xml
    } else {
        MediaType::Other
    }
}

/// Minimal XML character-content escaping. `'` (apos) is intentionally not
/// escaped — the message is rendered as element character content, where only
/// `&`, `<`, `>` are required, plus `"` to be safe in case the operator wraps
/// the rendered body in an attribute.
fn xml_escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for ch in s.chars() {
        match ch {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            _ => out.push(ch),
        }
    }
    out
}

#[async_trait]
impl Plugin for RequestTermination {
    fn name(&self) -> &str {
        "request_termination"
    }

    fn priority(&self) -> u16 {
        super::priority::REQUEST_TERMINATION
    }

    fn supported_protocols(&self) -> &'static [super::ProxyProtocol] {
        super::HTTP_FAMILY_PROTOCOLS
    }

    async fn on_request_received(&self, ctx: &mut RequestContext) -> PluginResult {
        let should_terminate = match &self.trigger {
            Trigger::Always => true,
            Trigger::PathPrefix(prefix) => ctx.path.starts_with(prefix.as_str()),
            Trigger::HeaderMatch { header, value } => ctx
                .headers
                .get(header.as_str())
                .is_some_and(|v| value.is_empty() || v == value),
        };

        if should_terminate {
            let mut headers = HashMap::with_capacity(1);
            headers.insert("content-type".to_string(), self.content_type.clone());

            return PluginResult::Reject {
                status_code: self.status_code,
                body: self.body.clone(),
                headers,
            };
        }

        PluginResult::Continue
    }
}
