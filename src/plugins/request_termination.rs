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
//!
//! Configuration must be a JSON object with only the documented keys.
//! Unknown top-level or `trigger` keys are rejected. Status codes must be
//! final (200–599); informational statuses including `101` are rejected.
//! Statuses `204`/`205`/`304` force an empty body. Header triggers evaluate
//! raw multi-value field lines (including non-UTF-8 presence) rather than the
//! lossy materialized map.

use async_trait::async_trait;
use http::header::{HeaderName, HeaderValue};
use serde_json::{Map, Value};
use std::collections::HashMap;

use super::{Plugin, PluginResult, RequestContext};

/// Every accepted top-level configuration property.
pub const REQUEST_TERMINATION_CONFIG_KEYS: &[&str] =
    &["status_code", "content_type", "body", "message", "trigger"];

/// Every accepted key inside `trigger`.
pub const REQUEST_TERMINATION_TRIGGER_KEYS: &[&str] = &["path_prefix", "header", "header_value"];

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
    /// never re-renders it. Empty for 204/205/304.
    body: String,
    trigger: Trigger,
}

impl RequestTermination {
    pub fn new(config: &Value) -> Result<Self, String> {
        let config = config.as_object().ok_or_else(|| {
            format!(
                "request_termination: config must be a JSON object; allowed keys: {}",
                REQUEST_TERMINATION_CONFIG_KEYS.join(", ")
            )
        })?;
        reject_unknown_keys(
            config,
            "config",
            REQUEST_TERMINATION_CONFIG_KEYS,
            "request_termination",
        )?;

        let status_code = parse_status_code(config)?;
        let content_type = parse_content_type(config)?;
        let raw_body = optional_string(config, "body")?;
        let message = optional_string(config, "message")?;
        let no_body_status =
            super::utils::synthetic_response::status_forbids_response_body(status_code);

        // Pre-render the response body so the hot path skips format!/replace.
        let body = if no_body_status {
            if let Some(raw) = raw_body.as_ref()
                && !raw.is_empty()
            {
                return Err(format!(
                    "request_termination: status {status_code} cannot carry a response body; omit 'body' or set it to \"\""
                ));
            }
            String::new()
        } else if let Some(raw_body) = raw_body {
            // Explicit body — including "" — is authoritative and suppresses
            // `message`. Field absence (not empty string) selects the default
            // renderer.
            raw_body
        } else {
            if matches!(classify_media_type(&content_type), MediaType::Xml) {
                validate_xml_1_0_message(message.as_deref().unwrap_or("Service unavailable"))?;
            }
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

fn reject_unknown_keys(
    object: &Map<String, Value>,
    path: &str,
    allowed: &[&str],
    plugin: &str,
) -> Result<(), String> {
    let mut unknown: Vec<&str> = object
        .keys()
        .filter(|key| !allowed.contains(&key.as_str()))
        .map(String::as_str)
        .collect();
    if unknown.is_empty() {
        return Ok(());
    }
    unknown.sort_unstable();
    Err(format!(
        "{plugin}: unknown config key(s) under '{path}': {}; allowed keys: {}",
        unknown.join(", "),
        allowed.join(", ")
    ))
}

fn parse_status_code(config: &Map<String, Value>) -> Result<u16, String> {
    match config.get("status_code") {
        None => Ok(503),
        Some(Value::Number(value)) => {
            let Some(code) = value.as_u64() else {
                return Err(
                    "request_termination: 'status_code' must be an integer from 200 to 599"
                        .to_string(),
                );
            };
            if !(200..=599).contains(&code) {
                return Err(format!(
                    "request_termination: 'status_code' must be a final response from 200 to 599 \
                     (informational statuses including 101 are rejected), got {code}"
                ));
            }
            u16::try_from(code)
                .map_err(|_| "request_termination: 'status_code' is too large".to_string())
        }
        Some(other) => Err(format!(
            "request_termination: 'status_code' must be an integer from 200 to 599, got: {other}"
        )),
    }
}

fn parse_content_type(config: &Map<String, Value>) -> Result<String, String> {
    match config.get("content_type") {
        None => Ok("application/json".to_string()),
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

fn optional_string(config: &Map<String, Value>, key: &str) -> Result<Option<String>, String> {
    match config.get(key) {
        None => Ok(None),
        Some(Value::String(value)) => Ok(Some(value.clone())),
        Some(other) => Err(format!(
            "request_termination: '{key}' must be a string, got: {other}"
        )),
    }
}

fn parse_trigger(config: &Map<String, Value>) -> Result<Trigger, String> {
    let Some(trigger) = config.get("trigger") else {
        return Ok(Trigger::Always);
    };
    let Value::Object(trigger) = trigger else {
        return Err("request_termination: 'trigger' must be an object".to_string());
    };
    reject_unknown_keys(
        trigger,
        "trigger",
        REQUEST_TERMINATION_TRIGGER_KEYS,
        "request_termination",
    )?;

    let has_path = trigger.contains_key("path_prefix");
    let has_header = trigger.contains_key("header");
    let has_header_value = trigger.contains_key("header_value");
    if has_path && (has_header || has_header_value) {
        return Err(
            "request_termination: 'trigger' must set only one of 'path_prefix' or 'header'; \
             'header_value' is valid only with 'header'"
                .to_string(),
        );
    }
    if has_header_value && !has_header {
        return Err(
            "request_termination: 'trigger.header_value' requires 'trigger.header'".to_string(),
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
        // `ctx.path` is the canonical policy path, so the prefix must be
        // written in that same alphabet or it can never fire. `/%61dmin` is
        // not a stricter spelling of `/admin` — it is a rule that matches
        // nothing, which is the silent-bypass shape this canonicalization
        // exists to remove (advisory GHSA-69xf-42xm-4w4f). The asterisk-form
        // target has no escapes and passes through unchanged.
        if let Some(reason) = crate::policy_path::non_canonical_policy_path_reason(path) {
            return Err(format!(
                "request_termination: 'trigger.path_prefix' must already be a canonical policy \
                 path ({reason}); request paths are canonicalized before plugins run, so a \
                 non-canonical prefix can never match"
            ));
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
            None => String::new(),
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

/// XML 1.0 character legality for character content (XML 1.0 §2.2).
fn is_xml_1_0_char(c: char) -> bool {
    matches!(c, '\t' | '\n' | '\r')
        || ('\u{20}'..='\u{D7FF}').contains(&c)
        || ('\u{E000}'..='\u{FFFD}').contains(&c)
        || ('\u{10000}'..='\u{10FFFF}').contains(&c)
}

fn validate_xml_1_0_message(message: &str) -> Result<(), String> {
    if let Some(bad) = message.chars().find(|c| !is_xml_1_0_char(*c)) {
        return Err(format!(
            "request_termination: 'message' contains U+{:04X}, which is not a valid XML 1.0 character \
             when content_type selects XML rendering",
            bad as u32
        ));
    }
    Ok(())
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

/// Header-trigger evaluation over raw multi-value field lines.
///
/// * Presence (`header_value` empty): any field line — including non-UTF-8 —
///   counts as present.
/// * Exact value: any individual field line whose bytes equal the configured
///   value matches. Never compares against a comma-folded serialization.
///
/// When raw headers are unavailable (unit-test harnesses that only populate
/// `ctx.headers`), falls back to the materialized map.
fn header_trigger_matches(ctx: &RequestContext, header: &str, expected: &str) -> bool {
    if ctx.has_raw_headers() {
        for value in ctx.raw_header_value_bytes(header) {
            if expected.is_empty() {
                // Presence-only: any field line, including non-UTF-8, matches.
                return true;
            }
            if value == expected.as_bytes() {
                // Exact match against an individual field line — never against
                // a comma-folded serialization of repeated lines.
                return true;
            }
        }
        return false;
    }

    ctx.headers
        .get(header)
        .is_some_and(|v| expected.is_empty() || v == expected)
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
            Trigger::HeaderMatch { header, value } => {
                header_trigger_matches(ctx, header.as_str(), value.as_str())
            }
        };

        if !should_terminate {
            return PluginResult::Continue;
        }

        // Extended CONNECT (and classic CONNECT) treat a 2xx as tunnel
        // establishment. Never reinterpret a canned ordinary body as tunnel
        // bytes — fail closed with a non-success rejection instead.
        let (status_code, body, content_type) = if ctx.method.eq_ignore_ascii_case("CONNECT")
            && (200..300).contains(&self.status_code)
        {
            (
                403u16,
                "{\"message\":\"CONNECT termination requires a non-success status\",\"status_code\":403}"
                    .to_string(),
                "application/json".to_string(),
            )
        } else {
            (
                self.status_code,
                self.body.clone(),
                self.content_type.clone(),
            )
        };

        let mut headers = HashMap::with_capacity(1);
        headers.insert("content-type".to_string(), content_type);

        PluginResult::Reject {
            status_code,
            body,
            headers,
        }
    }
}
