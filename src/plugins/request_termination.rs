//! Request Termination / Mocking Plugin
//!
//! Returns a canned response without proxying to the backend.
//! Useful for maintenance mode, mocking APIs, or blocking specific paths.
//! Supports JSON, XML, and plain text response bodies with configurable
//! content type and HTTP status code.
//!
//! The response body, `content-type`, and every configured response header are
//! computed **once** at construction time. The body is held as shared
//! [`Bytes`], so a matching request costs a reference-count bump for the body
//! plus the clone of the precomputed header map that the owned
//! [`PluginResult`] contract requires — no per-request body copy (HEAD
//! included), `format!()`, `String::replace()` chain, or JSON/XML parse or
//! escape work.
//!
//! When `content_type` classifies as JSON and `message` is a complete,
//! unambiguous JSON value, that value is the response body (not string-escaped
//! inside the legacy `{message,status_code}` envelope). Malformed or
//! parser-ambiguous JSON, and every non-JSON content type, keep the documented
//! fail-safe renderer: JSON envelope, XML envelope, or plain text.
//!
//! Configuration must be a JSON object with only the documented keys.
//! Unknown top-level or `trigger` keys are rejected. Status codes must be
//! final (200–599); informational statuses including `101` are rejected.
//! Statuses `204`/`205`/`304` force an empty body. Header triggers evaluate
//! raw multi-value field lines (including non-UTF-8 presence) rather than the
//! lossy materialized map, comparing the RFC 9110 field value (surrounding
//! SP/HTAB stripped) so the same logical header matches identically on
//! HTTP/1.1, HTTP/2, and HTTP/3.
//!
//! The plugin runs in `on_request_received` at priority 125, before IP
//! restriction, authentication, authorization, rate limiting, and the WAF. A
//! termination is therefore served to unauthenticated callers; post-auth
//! mocking belongs to `response_mock` (`before_proxy`).

use async_trait::async_trait;
use bytes::Bytes;
use http::header::{HeaderName, HeaderValue};
use serde_json::{Map, Value};
use std::collections::HashMap;

use super::{Plugin, PluginResult, RequestContext};
use crate::config::types::{HttpFlavor, HttpWireTransport};

/// Every accepted top-level configuration property.
pub const REQUEST_TERMINATION_CONFIG_KEYS: &[&str] = &[
    "status_code",
    "content_type",
    "body",
    "message",
    "headers",
    "trigger",
];

/// Every accepted key inside `trigger`.
pub const REQUEST_TERMINATION_TRIGGER_KEYS: &[&str] = &["path_prefix", "header", "header_value"];

/// Most response headers one instance may configure under `headers`.
pub const REQUEST_TERMINATION_MAX_HEADERS: usize = 32;

/// Longest configured response header value, in bytes. Values are visible
/// ASCII, so this is also the character count the published schema bounds.
pub const REQUEST_TERMINATION_MAX_HEADER_VALUE_BYTES: usize = 4096;

/// Response header names that carry credentials or an authentication
/// challenge. A canned response must never mint a session cookie or stand in
/// for the gateway's own `WWW-Authenticate` challenge.
const CREDENTIAL_RESPONSE_HEADER_NAMES: &[&str] = &[
    "authentication-info",
    "authorization",
    "proxy-authentication-info",
    "proxy-authorization",
    "set-cookie",
    "set-cookie2",
    "www-authenticate",
];

/// Exact gateway-owned response header names (gateway error contract).
const GATEWAY_OWNED_RESPONSE_HEADER_NAMES: &[&str] =
    &["x-gateway-error", "x-gateway-upstream-status"];

/// Gateway-owned response header families: `x-ferrum-*` carries diagnostics
/// and internal gRPC-Web bridge markers, and `grpc-*` is gRPC status metadata
/// that the reject normalizer reads (a configured `grpc-status: 0` would turn
/// the termination into a successful RPC).
const GATEWAY_OWNED_RESPONSE_HEADER_PREFIXES: &[&str] = &["x-ferrum-", "grpc-"];

/// Fail-closed body for a 2xx termination of a CONNECT / Extended CONNECT
/// request.
const CONNECT_REFUSAL_BODY: &[u8] =
    b"{\"message\":\"CONNECT termination requires a non-success status\",\"status_code\":403}";

#[derive(Debug, Clone)]
enum Trigger {
    Always,
    PathPrefix(String),
    HeaderMatch { header: String, value: String },
}

pub struct RequestTermination {
    status_code: u16,
    /// Pre-rendered response body. Built once from `body`, `message`,
    /// `content_type`, and `status_code` at construction time and shared by
    /// reference count, so the hot path never re-renders or copies it. Empty
    /// for 204/205/304.
    body: Bytes,
    /// Pre-computed response headers: `content-type` plus every validated
    /// `headers` entry, keyed by lowercase name.
    headers: HashMap<String, String>,
    /// Pre-computed headers for the fail-closed CONNECT refusal.
    connect_refusal_headers: HashMap<String, String>,
    trigger: Trigger,
}

impl RequestTermination {
    pub fn new(config: &Value) -> Result<Self, String> {
        let config = config.as_object().ok_or_else(|| {
            format!(
                "request_termination: config must be a JSON object; allowed keys: `{}`",
                REQUEST_TERMINATION_CONFIG_KEYS.join("`, `")
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
                    "request_termination: `status_code` \"{status_code}\" cannot carry a response body; omit `body` or set it to an empty string"
                ));
            }
            String::new()
        } else if let Some(raw_body) = raw_body {
            // Explicit body — including "" — is authoritative and suppresses
            // `message`. Field absence (not empty string) selects the default
            // renderer.
            raw_body
        } else {
            let rendered_message = message.as_deref().unwrap_or("Service unavailable");
            if matches!(classify_media_type(&content_type), MediaType::Xml) {
                validate_xml_1_0_message(rendered_message)?;
            }
            render_default_body(&content_type, status_code, rendered_message)
        };

        let configured_headers = parse_response_headers(config)?;
        let trigger = parse_trigger(config)?;

        let mut headers = HashMap::with_capacity(1 + configured_headers.len());
        headers.insert("content-type".to_string(), content_type);
        headers.extend(configured_headers);

        let mut connect_refusal_headers = HashMap::with_capacity(1);
        connect_refusal_headers.insert("content-type".to_string(), "application/json".to_string());

        Ok(Self {
            status_code,
            body: Bytes::from(body),
            headers,
            connect_refusal_headers,
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
        "{plugin}: unknown config key(s) under `{path}`: {:?}; allowed keys: `{}`",
        unknown.join(", "),
        allowed.join("`, `")
    ))
}

fn parse_status_code(config: &Map<String, Value>) -> Result<u16, String> {
    match config.get("status_code") {
        None => Ok(503),
        Some(value) => {
            let Some(code) = json_u64(value) else {
                return Err(format!(
                    "request_termination: `status_code` must be an integer from 200 to 599, \
                     got: {value:?}",
                    value = value.to_string()
                ));
            };
            if !(200..=599).contains(&code) {
                return Err(format!(
                    "request_termination: `status_code` must be a final response from 200 to 599 \
                     (informational statuses including 101 are rejected), got \"{code}\""
                ));
            }
            u16::try_from(code)
                .map_err(|_| "request_termination: `status_code` is too large".to_string())
        }
    }
}

fn parse_content_type(config: &Map<String, Value>) -> Result<String, String> {
    match config.get("content_type") {
        None => Ok("application/json".to_string()),
        Some(Value::String(value)) => {
            // Visible ASCII plus SP/HTAB only — the published schema's
            // alphabet. `HeaderValue` alone would also admit obs-text bytes,
            // which the admin schema refuses.
            if !value.bytes().all(is_visible_ascii_or_ows) {
                return Err(
                    "request_termination: `content_type` must contain only visible ASCII \
                     characters, spaces, and horizontal tabs"
                        .to_string(),
                );
            }
            let trimmed = trim_ows_str(value);
            if trimmed.is_empty() {
                return Err(
                    "request_termination: `content_type` must be a non-empty string".to_string(),
                );
            }
            Ok(trimmed.to_string())
        }
        Some(other) => Err(format!(
            "request_termination: `content_type` must be a string, got: {other:?}",
            other = other.to_string()
        )),
    }
}

fn optional_string(config: &Map<String, Value>, key: &str) -> Result<Option<String>, String> {
    match config.get(key) {
        None => Ok(None),
        Some(Value::String(value)) => Ok(Some(value.clone())),
        Some(other) => Err(format!(
            "request_termination: `{key}` must be a string, got: {other:?}",
            other = other.to_string()
        )),
    }
}

fn parse_trigger(config: &Map<String, Value>) -> Result<Trigger, String> {
    let Some(trigger) = config.get("trigger") else {
        return Ok(Trigger::Always);
    };
    let Value::Object(trigger) = trigger else {
        return Err("request_termination: `trigger` must be an object".to_string());
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
            "request_termination: `trigger` must set only one of `path_prefix` or `header`; \
             `header_value` is valid only with `header`"
                .to_string(),
        );
    }
    if has_header_value && !has_header {
        return Err(
            "request_termination: `trigger.header_value` requires `trigger.header`".to_string(),
        );
    }

    if let Some(value) = trigger.get("path_prefix") {
        let path = value.as_str().ok_or_else(|| {
            format!(
                "request_termination: `trigger.path_prefix` must be a string, got: {value:?}",
                value = value.to_string()
            )
        })?;
        if path.is_empty() {
            return Err(
                "request_termination: `trigger.path_prefix` must be a non-empty string".to_string(),
            );
        }
        // The trigger matches against `ctx.path`, the parsed request target
        // from `req.uri().path()`. A live request target is either origin-form
        // (rooted at '/') or — for a server-wide `OPTIONS *` — asterisk-form,
        // which the `http` crate exposes as the path "*". Either way it carries
        // no control characters, since CR/LF never survive request-line
        // parsing. A prefix that is neither rooted at '/' nor exactly "*" can
        // never prefix any live request path, so reject it here instead of
        // letting the plugin silently never fire. A query delimiter, fragment
        // delimiter, or literal space is likewise unreachable: `ctx.path` is
        // `Uri::path()`, which has already been split from the query and cannot
        // contain those bytes.
        if path != "*" && !path.starts_with('/') {
            return Err(
                "request_termination: `trigger.path_prefix` must start with `/` or be `*` (asterisk-form OPTIONS target)"
                    .to_string(),
            );
        }
        if path.chars().any(char::is_control) {
            return Err(
                "request_termination: `trigger.path_prefix` must not contain control characters"
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
                "request_termination: `trigger.path_prefix` must already be a canonical policy \
                 path ({reason}); request paths are canonicalized before plugins run, so a \
                 non-canonical prefix can never match"
            ));
        }
        if let Some(reason) = unreachable_parsed_path_prefix_reason(path) {
            return Err(format!(
                "request_termination: `trigger.path_prefix` {reason}"
            ));
        }
        return Ok(Trigger::PathPrefix(path.to_string()));
    }

    if let Some(value) = trigger.get("header") {
        let header = value.as_str().ok_or_else(|| {
            format!(
                "request_termination: `trigger.header` must be a string, got: {value:?}",
                value = value.to_string()
            )
        })?;
        let header = header.trim();
        if header.is_empty() {
            return Err(
                "request_termination: `trigger.header` must be a non-empty string".to_string(),
            );
        }
        let header = HeaderName::from_bytes(header.as_bytes())
            .map_err(|_| {
                "request_termination: `trigger.header` contains an invalid HTTP header name"
                    .to_string()
            })?
            .as_str()
            .to_string();
        let value = match trigger.get("header_value") {
            None => String::new(),
            Some(Value::String(value)) => parse_header_trigger_value(value)?,
            Some(other) => {
                return Err(format!(
                    "request_termination: `trigger.header_value` must be a string, got: {other:?}",
                    other = other.to_string()
                ));
            }
        };
        return Ok(Trigger::HeaderMatch { header, value });
    }

    Err("request_termination: `trigger` must set `path_prefix` or `header`".to_string())
}

/// Validate `trigger.header_value` and return its RFC 9110 field value.
///
/// The value must be a legal field value (no control character other than
/// HTAB), or the trigger could never fire on any transport. Surrounding
/// SP/HTAB is stripped, matching how the match side compares wire values. A
/// non-empty value that is only whitespace is refused instead of silently
/// becoming a presence match.
fn parse_header_trigger_value(value: &str) -> Result<String, String> {
    if value.is_empty() {
        return Ok(String::new());
    }
    HeaderValue::from_str(value).map_err(|_| {
        "request_termination: `trigger.header_value` contains characters not permitted in an \
         HTTP field value (control characters other than horizontal tab); the trigger could \
         never match"
            .to_string()
    })?;
    let trimmed = trim_ows_str(value);
    if trimmed.is_empty() {
        return Err(
            "request_termination: `trigger.header_value` must not be only whitespace; omit it \
             (or set it to an empty string) to match header presence"
                .to_string(),
        );
    }
    Ok(trimmed.to_string())
}

/// Parse the optional `headers` object into validated, lowercase-named
/// response headers. Construction-time only.
fn parse_response_headers(config: &Map<String, Value>) -> Result<Vec<(String, String)>, String> {
    let Some(value) = config.get("headers") else {
        return Ok(Vec::new());
    };
    let Value::Object(map) = value else {
        return Err(
            "request_termination: `headers` must be an object mapping header names \
             to string values"
                .to_string(),
        );
    };
    if map.len() > REQUEST_TERMINATION_MAX_HEADERS {
        return Err(format!(
            "request_termination: `headers` accepts at most \
             {REQUEST_TERMINATION_MAX_HEADERS} entries"
        ));
    }
    let mut parsed: Vec<(String, String)> = Vec::with_capacity(map.len());
    for (name, value) in map {
        let header = HeaderName::from_bytes(name.as_bytes()).map_err(|_| {
            format!("request_termination: `headers` key {name:?} is not a valid HTTP field name")
        })?;
        // `HeaderName` normalizes to lowercase.
        let lower = header.as_str();
        if let Some(reason) = reserved_response_header_reason(lower) {
            return Err(format!(
                "request_termination: `headers` key {name:?} {reason}"
            ));
        }
        if parsed.iter().any(|(existing, _)| existing == lower) {
            return Err(format!(
                "request_termination: `headers` key {name:?} is configured more than once \
                 (header names are case-insensitive)"
            ));
        }
        let Value::String(value) = value else {
            return Err(format!(
                "request_termination: `headers` value for {name:?} must be a string"
            ));
        };
        if let Some(reason) = response_header_value_problem(value) {
            return Err(format!(
                "request_termination: `headers` value for {name:?} {reason}"
            ));
        }
        parsed.push((lower.to_string(), value.clone()));
    }
    Ok(parsed)
}

/// Why a lowercase response header name may not be configured, or `None`.
fn reserved_response_header_reason(lower: &str) -> Option<&'static str> {
    if crate::proxy::headers::is_protocol_managed_plugin_response_destination(lower) {
        return Some(
            "is protocol-managed (hop-by-hop or framing) and cannot be configured; the gateway \
             derives framing from the canned body, status, and method",
        );
    }
    if lower == "content-type" {
        return Some("is set by `content_type`; configure the media type there");
    }
    if CREDENTIAL_RESPONSE_HEADER_NAMES.contains(&lower) {
        return Some(
            "carries credentials or an authentication challenge and cannot be set on a canned \
             response",
        );
    }
    if GATEWAY_OWNED_RESPONSE_HEADER_NAMES.contains(&lower)
        || GATEWAY_OWNED_RESPONSE_HEADER_PREFIXES
            .iter()
            .any(|prefix| lower.starts_with(prefix))
    {
        return Some(
            "is gateway-owned (gateway error, diagnostic, or gRPC status metadata) and cannot \
             be configured",
        );
    }
    None
}

/// Why a configured response header value is invalid, or `None`.
fn response_header_value_problem(value: &str) -> Option<&'static str> {
    if value.len() > REQUEST_TERMINATION_MAX_HEADER_VALUE_BYTES {
        return Some("exceeds the 4096-byte limit");
    }
    if !value.bytes().all(is_visible_ascii_or_ows) {
        return Some("must contain only visible ASCII characters, spaces, and horizontal tabs");
    }
    let bytes = value.as_bytes();
    if matches!(bytes.first(), Some(b' ' | b'\t')) || matches!(bytes.last(), Some(b' ' | b'\t')) {
        return Some("must not have leading or trailing whitespace");
    }
    None
}

/// HTAB, SP, or a visible ASCII character (`0x21..=0x7E`).
#[inline]
fn is_visible_ascii_or_ows(byte: u8) -> bool {
    byte == b'\t' || (0x20..=0x7E).contains(&byte)
}

/// Strip RFC 9110 optional whitespace (SP / HTAB) from both ends.
#[inline]
fn trim_ows_str(value: &str) -> &str {
    value.trim_matches(|c: char| c == ' ' || c == '\t')
}

/// Strip RFC 9110 optional whitespace (SP / HTAB) from both ends of a raw
/// field line. Allocation-free.
#[inline]
fn trim_ows_bytes(mut bytes: &[u8]) -> &[u8] {
    while let [b' ' | b'\t', rest @ ..] = bytes {
        bytes = rest;
    }
    while let [rest @ .., b' ' | b'\t'] = bytes {
        bytes = rest;
    }
    bytes
}

fn json_u64(value: &Value) -> Option<u64> {
    let Value::Number(n) = value else {
        return None;
    };
    n.as_u64().or_else(|| {
        let n = n.as_f64()?;
        (n.is_finite() && n.fract() == 0.0 && n >= 0.0).then_some(n as u64)
    })
}

/// Why a configured path prefix can never prefix `Uri::path()` even when it is
/// already a canonical policy-path spelling. `*` is the asterisk-form target
/// and is not a URI path.
fn unreachable_parsed_path_prefix_reason(path: &str) -> Option<&'static str> {
    if path == "*" {
        return None;
    }
    if path.contains('?') {
        return Some(
            "must not contain a query delimiter (`?`); request paths are the parsed URI path, \
             so a prefix with a query can never match",
        );
    }
    if path.contains(' ') {
        return Some(
            "must not contain a literal space; request-target parsing rejects spaces, so the \
             prefix can never match",
        );
    }
    if path.contains('#') {
        return Some(
            "must not contain a fragment delimiter (`#`); request paths are the parsed URI path, \
             so a prefix with a fragment can never match",
        );
    }
    // `http::uri::PathAndQuery` refuses these three bytes literally, and the
    // canonicalizer refuses their percent escapes (`%3C`, `%3E`, `%60`), so
    // no admitted request path can contain one. Literal `"`, `{`, `}`, `[`,
    // `]`, `^`, `|`, and UTF-8 are admitted by the parser and stay valid.
    if path.bytes().any(|byte| matches!(byte, b'<' | b'>' | b'`')) {
        return Some(
            "must not contain `<`, `>`, or a backtick; request-target parsing refuses them \
             literally and canonicalization refuses their escapes, so the prefix can never match",
        );
    }
    None
}

/// Render the default response body for a given content type. Performed once
/// at construction time — never on the hot path.
fn render_default_body(content_type: &str, status_code: u16, message: &str) -> String {
    match classify_media_type(content_type) {
        MediaType::Json => render_json_body(status_code, message),
        MediaType::Xml => {
            let escaped = xml_escape(message);
            format!(
                r#"<?xml version="1.0"?><response><message>{}</message><status_code>{}</status_code></response>"#,
                escaped, status_code
            )
        }
        MediaType::Other => message.to_string(),
    }
}

/// JSON default-body renderer.
///
/// A complete, unambiguous JSON `message` is emitted as the body (compact
/// serialization of the parsed value). Anything else — malformed JSON,
/// duplicate object members, scanner/parser divergence, or a plain-text
/// phrase such as the default `"Service unavailable"` — fails safe into the
/// legacy `{message,status_code}` envelope so the response remains valid JSON.
fn render_json_body(status_code: u16, message: &str) -> String {
    json_passthrough_body(message).unwrap_or_else(|| json_message_envelope(status_code, message))
}

/// Parse `message` as one JSON value and return its compact serialization.
///
/// Construction-time only. Duplicate-key and other parser-ambiguous documents
/// are treated as not-passthrough so the emitted body cannot depend on which
/// JSON parser a client uses. Never panics on hostile input.
fn json_passthrough_body(message: &str) -> Option<String> {
    if crate::util::json_dup_keys::str_ambiguity(message).is_some() {
        return None;
    }
    let value: Value = serde_json::from_str(message).ok()?;
    serde_json::to_string(&value).ok()
}

fn json_message_envelope(status_code: u16, message: &str) -> String {
    // serde_json::to_string produces a fully-spec-compliant JSON string
    // literal (quoted, with control chars / non-ASCII / backslashes / quotes
    // all escaped). Infallible for `&str` input; the empty-string fallback
    // keeps construction panic-free if that ever changes.
    let encoded = serde_json::to_string(message).unwrap_or_else(|_| "\"\"".to_string());
    format!(r#"{{"message":{},"status_code":{}}}"#, encoded, status_code)
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
            "request_termination: `message` contains \"U+{:04X}\", which is not a valid XML 1.0 character \
             when `content_type` selects XML rendering",
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
/// * Exact value: any individual field line whose RFC 9110 field value (bytes
///   with surrounding SP/HTAB stripped) equals the configured value matches.
///   HTTP/1.1 parsing already strips that whitespace while HPACK/QPACK deliver
///   it verbatim, so trimming here keeps the match transport-independent.
///   Never compares against a comma-folded serialization.
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
            if trim_ows_bytes(value) == expected.as_bytes() {
                // Exact match against an individual field line — never against
                // a comma-folded serialization of repeated lines.
                return true;
            }
        }
        return false;
    }

    ctx.headers
        .get(header)
        .is_some_and(|v| expected.is_empty() || trim_ows_str(v) == expected)
}

#[async_trait]
impl Plugin for RequestTermination {
    fn name(&self) -> &str {
        "request_termination"
    }

    fn priority(&self) -> u16 {
        super::priority::REQUEST_TERMINATION
    }

    fn lifecycle_hooks(&self) -> crate::plugins::PluginHooks {
        crate::plugins::PluginHooks::ON_REQUEST_RECEIVED
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

        // Classic CONNECT and H2/H3 WebSocket Extended CONNECT treat a 2xx as
        // tunnel establishment. Never reinterpret a canned ordinary body as
        // tunnel bytes — fail closed with a non-success rejection instead.
        let is_extended_connect_websocket =
            matches!(ctx.request_http_flavor(), HttpFlavor::WebSocket)
                && matches!(
                    ctx.request_wire_transport(),
                    Some(HttpWireTransport::Http2 | HttpWireTransport::Http3)
                );
        let is_tunnel = ctx.method.eq_ignore_ascii_case("CONNECT") || is_extended_connect_websocket;
        if is_tunnel && (200..300).contains(&self.status_code) {
            return PluginResult::RejectBinary {
                status_code: 403,
                body: Bytes::from_static(CONNECT_REFUSAL_BODY),
                headers: self.connect_refusal_headers.clone(),
            };
        }

        // `Bytes::clone` shares the pre-rendered allocation (HEAD included:
        // the shared finalizer omits DATA but still needs the representation
        // length). The header map is cloned because `PluginResult` owns it.
        PluginResult::RejectBinary {
            status_code: self.status_code,
            body: self.body.clone(),
            headers: self.headers.clone(),
        }
    }
}
