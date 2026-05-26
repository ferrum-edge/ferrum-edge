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
use http::header::{HeaderName, HeaderValue};
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
        let status_code = parse_status_code(config)?;
        let content_type = parse_content_type(config)?;
        let raw_body = optional_string(config, "body")?;
        let message = optional_string(config, "message")?;

        // Pre-render the response body so the hot path skips format!/replace.
        let body = if let Some(raw_body) = raw_body {
            raw_body
        } else {
            render_default_body(&content_type, status_code, message.as_deref())
        };

        let trigger = parse_trigger(config)?;

        Ok(Self {
            status_code,
            content_type,
            body,
            trigger,
        })
    }
}

fn parse_status_code(config: &Value) -> Result<u16, String> {
    match config.get("status_code") {
        None | Some(Value::Null) => Ok(503),
        Some(Value::Number(value)) => {
            let Some(code) = value.as_u64() else {
                return Err(
                    "request_termination: 'status_code' must be an integer from 100 to 599"
                        .to_string(),
                );
            };
            if !(100..=599).contains(&code) {
                return Err(format!(
                    "request_termination: 'status_code' must be from 100 to 599, got {code}"
                ));
            }
            u16::try_from(code)
                .map_err(|_| "request_termination: 'status_code' is too large".to_string())
        }
        Some(other) => Err(format!(
            "request_termination: 'status_code' must be an integer from 100 to 599, got: {other}"
        )),
    }
}

fn parse_content_type(config: &Value) -> Result<String, String> {
    match config.get("content_type") {
        None | Some(Value::Null) => Ok("application/json".to_string()),
        Some(Value::String(value)) => {
            let trimmed = value.trim();
            if trimmed.is_empty() {
                return Err(
                    "request_termination: 'content_type' must be a non-empty string".to_string(),
                );
            }
            HeaderValue::from_str(trimmed).map_err(|_| {
                "request_termination: 'content_type' contains characters not permitted in HTTP header values"
                    .to_string()
            })?;
            Ok(trimmed.to_string())
        }
        Some(other) => Err(format!(
            "request_termination: 'content_type' must be a string, got: {other}"
        )),
    }
}

fn optional_string(config: &Value, key: &str) -> Result<Option<String>, String> {
    match config.get(key) {
        None | Some(Value::Null) => Ok(None),
        Some(Value::String(value)) => Ok(Some(value.clone())),
        Some(other) => Err(format!(
            "request_termination: '{key}' must be a string, got: {other}"
        )),
    }
}

fn parse_trigger(config: &Value) -> Result<Trigger, String> {
    let Some(trigger) = config.get("trigger") else {
        return Ok(Trigger::Always);
    };
    if trigger.is_null() {
        return Ok(Trigger::Always);
    }
    let Value::Object(trigger) = trigger else {
        return Err("request_termination: 'trigger' must be an object".to_string());
    };

    let has_path = trigger.contains_key("path_prefix");
    let has_header = trigger.contains_key("header");
    if has_path && has_header {
        return Err(
            "request_termination: 'trigger' must set only one of 'path_prefix' or 'header'"
                .to_string(),
        );
    }

    if let Some(value) = trigger.get("path_prefix") {
        let path = value.as_str().ok_or_else(|| {
            format!("request_termination: 'trigger.path_prefix' must be a string, got: {value}")
        })?;
        if path.is_empty() {
            return Err(
                "request_termination: 'trigger.path_prefix' must be a non-empty string".to_string(),
            );
        }
        // The trigger matches against `ctx.path`, the parsed request target
        // from `req.uri().path()`. A live request target is either origin-form
        // (rooted at '/') or — for a server-wide `OPTIONS *` — asterisk-form,
        // which the `http` crate exposes as the path "*". Either way it carries
        // no control characters, since CR/LF never survive request-line
        // parsing. A prefix that is neither rooted at '/' nor exactly "*" can
        // never prefix any live request path, so reject it here instead of
        // letting the plugin silently never fire.
        if path != "*" && !path.starts_with('/') {
            return Err(
                "request_termination: 'trigger.path_prefix' must start with '/' or be \"*\" (asterisk-form OPTIONS target)"
                    .to_string(),
            );
        }
        if path.chars().any(char::is_control) {
            return Err(
                "request_termination: 'trigger.path_prefix' must not contain control characters"
                    .to_string(),
            );
        }
        return Ok(Trigger::PathPrefix(path.to_string()));
    }

    if let Some(value) = trigger.get("header") {
        let header = value.as_str().ok_or_else(|| {
            format!("request_termination: 'trigger.header' must be a string, got: {value}")
        })?;
        let header = header.trim();
        if header.is_empty() {
            return Err(
                "request_termination: 'trigger.header' must be a non-empty string".to_string(),
            );
        }
        let header = HeaderName::from_bytes(header.as_bytes())
            .map_err(|_| {
                "request_termination: 'trigger.header' contains an invalid HTTP header name"
                    .to_string()
            })?
            .as_str()
            .to_string();
        let value = match trigger.get("header_value") {
            None | Some(Value::Null) => String::new(),
            Some(Value::String(value)) => value.clone(),
            Some(other) => {
                return Err(format!(
                    "request_termination: 'trigger.header_value' must be a string, got: {other}"
                ));
            }
        };
        return Ok(Trigger::HeaderMatch { header, value });
    }

    Err("request_termination: 'trigger' must set 'path_prefix' or 'header'".to_string())
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
