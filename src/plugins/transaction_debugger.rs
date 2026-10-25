//! Transaction debugger plugin — detailed per-request diagnostics.
//!
//! Emits debug output via `tracing::debug!` on the `transaction_debug` target,
//! showing the request/response lifecycle: matched proxy, consumer identity,
//! plugin execution timing, backend connection details, and authoritative
//! terminal state. Sensitive headers (Authorization, Cookie, API keys) are
//! automatically redacted. Intended for development and troubleshooting —
//! should not be enabled in production due to information disclosure risk.
//!
//! # Bounded body capture (issue #3316)
//!
//! `log_request_body` / `log_response_body` are opt-in, default-off switches
//! that emit a **bounded, redacted sample** of the request or response body.
//! The capture design is deliberately conservative:
//!
//! * **Bounded.** `max_request_body_bytes` / `max_response_body_bytes` default
//!   to [`DEFAULT_BODY_CAPTURE_BYTES`] and are hard-capped at
//!   [`MAX_BODY_CAPTURE_BYTES`] at construction. The rendered field is
//!   additionally capped at [`MAX_RENDERED_BODY_BYTES`] after escaping, so
//!   Unicode/control escaping cannot expand a capture without limit.
//! * **Bounded by the actual body, not by a declared length.** `Content-Length`
//!   is only an admission screen. Both final body hooks re-check the real
//!   post-transform `body.len()` against the configured cap *before* any
//!   full-body UTF-8 scan, parse, redaction, or allocation, and fail closed with
//!   a content-free `over_capture_limit` omission when it does not fit. A stale
//!   or lying header, or a transform that grows the body, therefore cannot make
//!   the debugger walk an oversized payload. The header can overstate the
//!   message as well — a `HEAD` or `304` response declares a length it never
//!   sends — so an actually empty slice reports the same fixed `empty_body`
//!   reason the header screen uses rather than being handed to the renderer,
//!   where a structured family would call an absent body malformed.
//! * **Never forces a stream to buffer.** Both buffering predicates return
//!   `false` unless the message declares a `Content-Length` that fits inside the
//!   configured cap, declares an identity `Content-Encoding`, and declares a
//!   capturable textual `Content-Type`. gRPC, SSE (`text/event-stream`),
//!   WebSocket upgrades, chunked/unknown-length, encoded, oversized, and binary
//!   traffic keep streaming exactly as they do with capture disabled. They also
//!   return `false` when the `transaction_debug` DEBUG target is not enabled,
//!   because no capture record could be emitted for the buffered bytes. On a
//!   retry-enabled proxy the same screen runs through
//!   `should_release_response_body_under_retries`, so a response the debugger
//!   will not sample is released after headers instead of being held for the
//!   retry window.
//!
//! One behavior does change while response capture is enabled: on the buffered
//! HTTP/3 path the proxy drops backend-controlled response trailers for any
//! response a body-processing plugin chain handled (issue #2941), and this
//! debugger joins that chain when `log_response_body` is on. That is inherent to
//! the shared two-tier gate, not specific to capture eligibility, and is one
//! more reason capture is a troubleshooting opt-in rather than a production
//! default.
//! * **Captured after normalization/transformation.** The request sample is
//!   taken in `on_final_request_body` (backend-visible bytes, after every
//!   request transform) and the response sample in `on_final_response_body`
//!   (client-visible bytes, after every response transform).
//! * **Redacted before rendering.** JSON objects and form bodies are redacted
//!   per field; credential-shaped string values (`Bearer …`, `Basic …`,
//!   compact JWS/JWE tokens recognized by a base64url-decoded JSON protected
//!   header rather than a literal `eyJ` prefix, well-known provider API-key and
//!   AWS access-key shapes, and PEM private-key blocks) are replaced anywhere
//!   they appear, including in header values. Structured families without
//!   a sound structure-aware redactor (XML, GraphQL) are *not* capturable at
//!   all, and a body that claims to be JSON but does not parse renders as
//!   [`BODY_MALFORMED_MARKER`] rather than falling back to a partial rendering
//!   that could split a key from its value across lines. `text/plain` is the one
//!   deliberately coarse family: it has no field grammar, so it gets
//!   operator-opt-in line-level redaction where any line holding a sensitive
//!   marker is replaced wholesale. Payloads that are not valid UTF-8 — including
//!   a valid prefix followed by an incomplete multibyte sequence, which at a
//!   final body hook is malformed rather than truncated — are never dumped and
//!   render as [`BODY_BINARY_MARKER`].
//! * **Explicit provenance.** Every request/response emits exactly one capture
//!   record whose `capture` field distinguishes `captured`, `truncated`,
//!   `binary`, and `omitted` (with a stable `reason`), so an absent body sample
//!   is never confused with an empty one. The header-phase and final-body hooks
//!   share a private per-request, per-instance flag (`CaptureRecordState`),
//!   so a capture decision that flips between them (a transform that grows,
//!   empties, or relabels the body) still yields exactly one record.
//! * **Targeted.** `capture_request_header` / `capture_request_header_value`,
//!   `capture_sample_rate`, and `capture_expires_at` narrow capture to the
//!   requests an operator is debugging and switch it off on schedule. A request
//!   outside the target never buffers and reports a content-free
//!   `not_selected` / `capture_expired` omission.
//! * **Opt-in prefix sampling.** `capture_body_prefix` admits `text/plain` and
//!   form bodies whose declared length exceeds the cap (up to
//!   [`MAX_PREFIX_SOURCE_BYTES`]) and renders a redacted prefix of complete
//!   lines / pairs, marked `truncated`. JSON keeps the whole-document rule.
//!
//! No captured bytes are written into `ctx.metadata` or the transaction
//! summary: the sample exists only on the `transaction_debug` tracing target.
//! The only state retained across hooks is the content-free record flag above.

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use http::header::HeaderName;
use serde::ser::SerializeMap;
use serde_json::Value;
use std::collections::HashMap;
use std::fmt::Write as _;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use super::{
    Direction, DisconnectCause, Plugin, PluginResult, RequestContext, StreamTransactionSummary,
    TransactionSummary, WsDisconnectContext,
};
use crate::plugins::utils::auth_flow::constant_time_eq;
use crate::plugins::utils::log_schema::view::{
    MetadataNested, emit_timestamp, extract_host_from_url, serialize_schema_metadata, status_class,
};
use crate::plugins::utils::log_schema::{
    DerivedKind, EmittedKeys, MetadataPolicy, SchemaCapabilities, SchemaSerializable, SchemaView,
    SummarySchema, TimestampFormat, resolve_schema,
};
use crate::plugins::utils::metadata_redaction::{
    REDACTED_PLACEHOLDER, is_sensitive_header_name, is_sensitive_metadata_key,
    is_sensitive_name_by_listed_rules, metadata_value_is_redacted,
};
use crate::proxy::tcp_proxy::StreamIoSide;
use crate::retry::ErrorClass;

/// Headers that contain sensitive credentials and must be redacted in debug output.
const SENSITIVE_HEADERS: &[&str] = &[
    "authorization",
    "proxy-authorization",
    "cookie",
    "set-cookie",
    "api-key",
    "x-api-key",
    "x-goog-api-key",
    "x-auth-token",
    "x-csrf-token",
    "x-xsrf-token",
    "www-authenticate",
    "x-forwarded-authorization",
    "last-event-id",
];

/// Redaction placeholder for sensitive header values.
const REDACTED: &str = "***REDACTED***";

/// Closed configuration surface. Kept in lockstep with the OpenAPI
/// `TransactionDebuggerConfig` schema (`openapi_yaml_tests`).
pub const TRANSACTION_DEBUGGER_CONFIG_KEYS: &[&str] = &[
    "capture_body_prefix",
    "capture_expires_at",
    "capture_request_header",
    "capture_request_header_value",
    "capture_sample_rate",
    "log_request_body",
    "log_response_body",
    "max_request_body_bytes",
    "max_response_body_bytes",
    "redacted_body_fields",
    "redacted_headers",
    "safe_text_fields",
    "schema",
    "schema_ref",
];

/// Default per-direction body capture budget in bytes.
pub const DEFAULT_BODY_CAPTURE_BYTES: u64 = 1024;

/// Hard per-direction ceiling for a configured body capture budget. Values
/// above this are rejected at construction rather than silently clamped.
pub const MAX_BODY_CAPTURE_BYTES: u64 = 8192;

/// Absolute ceiling for the rendered (redacted + escaped) body field.
///
/// The maximum expansion per source byte is 8 output bytes: a single-byte
/// C0/C1 control character renders as `\u{XXXX}`. A maximal capture therefore
/// escapes to at most `8 * MAX_BODY_CAPTURE_BYTES`. The ceiling is dimensioned
/// to exactly that worst case: escaping can touch it but — with the exact
/// per-segment bound in `escape_for_diagnostics` — can never exceed it. The
/// compile-time assertion below keeps the two constants from drifting apart.
pub const MAX_RENDERED_BODY_BYTES: usize = 64 * 1024;

const _: () = assert!(MAX_RENDERED_BODY_BYTES == 8 * MAX_BODY_CAPTURE_BYTES as usize);

/// Largest declared `Content-Length` that `capture_body_prefix` admits to the
/// buffered path for a prefix sample. Larger, unknown-length, and JSON bodies
/// keep streaming exactly as they do without prefix sampling.
pub const MAX_PREFIX_SOURCE_BYTES: u64 = 1024 * 1024;

/// Maximum length of `capture_request_header_value`.
pub const MAX_CAPTURE_SELECTOR_VALUE_BYTES: usize = 256;

/// Number of base64url characters of a compact-serialization segment decoded
/// when deciding whether it is a JOSE protected header (48 decoded bytes).
const MAX_JOSE_HEADER_PREFIX_CHARS: usize = 64;

/// Process-unique instance ids, so sibling debugger instances on one proxy
/// keep independent per-request capture-record state.
static NEXT_TRANSACTION_DEBUGGER_INSTANCE_ID: AtomicU64 = AtomicU64::new(1);

/// Maximum number of lines retained by unstructured-text redaction.
const MAX_TEXT_REDACTION_LINES: usize = 256;

/// Maximum JSON nesting depth walked by field redaction.
const MAX_JSON_REDACTION_DEPTH: usize = 64;

/// Rendered stand-in for a body that is not valid UTF-8. Binary payloads are
/// never dumped, not even base64-encoded.
pub const BODY_BINARY_MARKER: &str = "<non-utf8-body-omitted>";

/// Rendered stand-in for a body that declared a structured media type but could
/// not be parsed as that structure. Falling back to line-level text redaction
/// would leak a value whose credential-bearing key sits on a different line, so
/// a malformed structured body is never partially rendered.
pub const BODY_MALFORMED_MARKER: &str = "<malformed-structured-body-omitted>";

/// Rendered stand-in for a body whose actual length exceeds the effective
/// capture ceiling. Content-free by construction.
pub const BODY_OVER_LIMIT_MARKER: &str = "<over-capture-limit-body-omitted>";

/// Rendered stand-in for a JSON subtree deeper than [`MAX_JSON_REDACTION_DEPTH`].
const BODY_DEPTH_MARKER: &str = "***DEPTH-LIMIT***";

/// `capture` field value for a record that carries no sample. Kept as a
/// constant so the omission record renders the field exactly like the captured
/// record's `CapturedBody::state` instead of quoting only one of the two.
const BODY_CAPTURE_OMITTED: &str = "omitted";

/// Substrings that make a body field name (or an unstructured text line)
/// credential-bearing. Matched case-insensitively against the lowercased name.
const SENSITIVE_BODY_KEY_SUBSTRINGS: &[&str] = &[
    "password",
    "passwd",
    "passphrase",
    "secret",
    "token",
    "apikey",
    "api_key",
    "api-key",
    "credential",
    "private_key",
    "privatekey",
    "access_key",
    "secret_key",
    "authorization",
    "session",
    "signature",
    "assertion",
];

/// Short field names that are credential-bearing only as an exact match, so a
/// benign name such as `pinned` or `keyboard` is not redacted away.
const SENSITIVE_BODY_KEY_EXACT: &[&str] = &[
    "auth",
    "code",
    "cookie",
    "embeddingkey",
    "jwt",
    "key",
    "otp",
    "pin",
    "pwd",
    "sig",
];

#[derive(Clone, Copy, PartialEq, Eq)]
enum JsonBodyRedactionContext {
    Normal,
    DataSourceItem,
}

fn compact_json_field_key(key: &str) -> String {
    key.chars()
        .filter(|ch| ch.is_ascii_alphanumeric())
        .map(|ch| ch.to_ascii_lowercase())
        .collect()
}

fn is_azure_data_sources_field(key: &str) -> bool {
    compact_json_field_key(key) == "datasources"
}

fn is_azure_parameters_field(key: &str) -> bool {
    compact_json_field_key(key) == "parameters"
}

fn wholesale_redact_data_source_parameters(value: &mut Value) {
    match value {
        Value::Object(map) => {
            for entry in map.values_mut() {
                *entry = Value::String(REDACTED.to_string());
            }
        }
        _ => *value = Value::String(REDACTED.to_string()),
    }
}

/// Capturable textual body families. Everything outside this set is skipped.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BodyKind {
    /// `application/json`, `text/json`, or any `+json` structured suffix.
    Json,
    /// `application/x-www-form-urlencoded`.
    Form,
    /// `text/plain` only. Unstructured text has no field grammar, so this
    /// family gets deliberately coarse line-level redaction and is an explicit
    /// operator opt-in. Structured families that would need a structure-aware
    /// redactor Ferrum does not implement (XML, GraphQL) are not capturable.
    Text,
}

impl BodyKind {
    /// Stable label emitted in the `body_kind` diagnostic field.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Json => "json",
            Self::Form => "form",
            Self::Text => "text",
        }
    }
}

/// Whether the current message is eligible for a bounded body capture, and if
/// not, the stable operator-visible reason.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BodyCaptureDecision {
    /// Capture up to `max_bytes` of a `kind` body.
    Capture { kind: BodyKind, max_bytes: usize },
    /// Do not capture. The reason is a fixed, non-echoing label.
    Skip(&'static str),
}

impl BodyCaptureDecision {
    /// `Some(reason)` when this message will not be captured.
    pub const fn skip_reason(self) -> Option<&'static str> {
        match self {
            Self::Capture { .. } => None,
            Self::Skip(reason) => Some(reason),
        }
    }

    /// Whether this message is eligible for capture.
    pub const fn is_capture(self) -> bool {
        matches!(self, Self::Capture { .. })
    }
}

/// A rendered, bounded, redacted body sample.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CapturedBody {
    /// `captured`, `truncated`, `binary`, or `omitted` (malformed structured
    /// body, or a body past the effective capture ceiling — both content-free).
    pub state: &'static str,
    /// Body family the sample was redacted as (`binary` for non-UTF-8,
    /// `omitted` for a body past the effective capture ceiling).
    pub kind: &'static str,
    /// Byte length of the complete post-transform body.
    pub original_bytes: usize,
    /// Whether the sample omits part of the body (byte cap, line cap, or the
    /// rendered ceiling).
    pub truncated: bool,
    /// Redacted, escaped, bounded rendering.
    pub rendered: String,
}

/// Per-request, per-instance capture-record bookkeeping.
///
/// The header-phase hooks (`before_proxy` / `after_proxy`) and the final body
/// hooks evaluate the capture decision over different header maps, and a body
/// transform between them can flip it. Whichever hook emits a direction's
/// record first sets that direction's flag, and every later hook for the same
/// direction is a no-op, so a flip yields exactly one record instead of zero or
/// two. Content-free by construction: nothing here describes the body.
#[derive(Debug, Clone, Copy, Default)]
pub(crate) struct CaptureRecordState {
    pub(crate) request_emitted: bool,
    pub(crate) response_emitted: bool,
}

/// Direction of one capture record.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CaptureDirection {
    Request,
    Response,
}

impl CaptureDirection {
    const fn as_str(self) -> &'static str {
        match self {
            Self::Request => "request",
            Self::Response => "response",
        }
    }
}

pub struct TransactionDebugger {
    /// Process-unique id keying this instance's per-request
    /// `CaptureRecordState`.
    instance_id: u64,
    /// Additional header names (lowercase) to redact beyond the built-in list.
    extra_redacted_headers: Vec<String>,
    /// Additional body field names (lowercase) to redact.
    redacted_body_fields: Vec<String>,
    /// Field names (lowercase) whose `name=value` / `name: value` lines may be
    /// rendered in `text/plain` bodies. Every other assignment line is
    /// dropped (fail closed, issue #6619).
    safe_text_fields: Vec<String>,
    log_request_body: bool,
    log_response_body: bool,
    max_request_body_bytes: usize,
    max_response_body_bytes: usize,
    /// Render a redacted prefix of an over-cap `text/plain` / form body
    /// instead of a content-free omission.
    capture_body_prefix: bool,
    /// Requests received at or after this instant are not captured.
    capture_expires_at: Option<DateTime<Utc>>,
    /// Lowercase request header that must be present for a capture.
    capture_request_header: Option<String>,
    /// Exact value `capture_request_header` must carry, when configured.
    capture_request_header_value: Option<String>,
    /// Requests whose sample point is at or above this threshold are not
    /// captured. `None` selects every request (`capture_sample_rate` 1).
    capture_sample_threshold: Option<u64>,
    /// Compiled terminal-diagnostic projection, resolved once at construction
    /// (inline `schema:` or global-first `schema_ref:`). `None` keeps the
    /// pre-existing `tracing` field emission byte-for-byte and allocation-free.
    schema: Option<Arc<SummarySchema>>,
}

/// Whether every `=` / `:` on a text line follows a field name the operator
/// declared safe (issue #6619). Fails closed per delimiter: a missing, empty,
/// quoted, or unparseable name (`(hsm_pin): 1`, `"note": 1`, `hsm_piné=1`)
/// makes the whole line unsafe, as does any undeclared name. Whitespace around
/// the delimiter is allowed (`note = 1`).
fn assignment_names_all_safe(line: &str, is_safe: impl Fn(&str) -> bool) -> bool {
    line.match_indices(['=', ':'])
        .all(|(offset, _)| assignment_field_name(line, offset).is_some_and(&is_safe))
}

/// A field name the text parser can judge: non-empty ASCII letters, digits,
/// `_`, `-` and `.` only.
fn is_clean_text_field_name(name: &str) -> bool {
    !name.is_empty()
        && name
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-' | b'.'))
}

/// The unquoted field name assigned at `offset` (an `=` / `:` in `line`):
/// the whole token back to the previous whitespace or assignment / prose
/// separator, Unicode and punctuation included. `None` when the name is empty
/// or quoted; quoted names are never declared safe, so their lines drop.
fn assignment_field_name(line: &str, offset: usize) -> Option<&str> {
    let before = line[..offset].trim_end();
    if before.ends_with(['"', '\'']) {
        return None;
    }
    // `char_indices` keeps the start on a character boundary.
    let start = before
        .char_indices()
        .rev()
        .find(|(_, ch)| {
            ch.is_whitespace()
                || matches!(
                    ch,
                    '&' | ';' | ',' | '=' | ':' | '{' | '}' | '(' | ')' | '"' | '\''
                )
        })
        .map_or(0, |(index, ch)| index + ch.len_utf8());
    let name = &before[start..];
    (!name.is_empty()).then_some(name)
}

impl TransactionDebugger {
    pub fn new(config: &Value) -> Result<Self, String> {
        let object = config
            .as_object()
            .ok_or_else(|| "transaction_debugger: config must be an object".to_string())?;
        let schema = resolve_schema(
            config,
            "transaction_debugger",
            SchemaCapabilities::TRANSACTION_DEBUGGER,
        )?;
        let mut unknown_keys: Vec<&str> = object
            .keys()
            .map(String::as_str)
            .filter(|key| !TRANSACTION_DEBUGGER_CONFIG_KEYS.contains(key))
            .collect();
        if !unknown_keys.is_empty() {
            unknown_keys.sort_unstable();
            return Err(format!(
                "transaction_debugger: unknown configuration keys at `config`: {:?}",
                unknown_keys.join(", ")
            ));
        }

        let mut extra_redacted_headers =
            optional_header_names(config, "redacted_headers")?.unwrap_or_default();

        let log_request_body = optional_bool(config, "log_request_body")?.unwrap_or(false);
        let log_response_body = optional_bool(config, "log_response_body")?.unwrap_or(false);
        let max_request_body_bytes =
            optional_capture_budget(config, "max_request_body_bytes", log_request_body)?;
        let max_response_body_bytes =
            optional_capture_budget(config, "max_response_body_bytes", log_response_body)?;
        let capture_enabled = log_request_body || log_response_body;

        let capture_body_prefix = optional_bool(config, "capture_body_prefix")?.unwrap_or(false);
        if capture_body_prefix && !capture_enabled {
            return Err(
                "transaction_debugger: `capture_body_prefix` requires `log_request_body` or \
                 `log_response_body` to be true"
                    .to_string(),
            );
        }
        let capture_sample_threshold = optional_capture_sample_threshold(config, capture_enabled)?;
        let capture_expires_at = optional_capture_expiry(config, capture_enabled)?;
        let capture_request_header = optional_capture_header(config, capture_enabled)?;
        let capture_request_header_value =
            optional_capture_header_value(config, capture_request_header.is_some())?;
        // A configured selector value is an operator-chosen token: keep it out
        // of the header dumps like any other credential-bearing header.
        if capture_request_header_value.is_some()
            && let Some(name) = capture_request_header.as_ref()
            && !extra_redacted_headers.contains(name)
        {
            extra_redacted_headers.push(name.clone());
        }

        let redacted_body_fields =
            optional_body_field_names(config, "redacted_body_fields")?.unwrap_or_default();
        if !redacted_body_fields.is_empty() && !(log_request_body || log_response_body) {
            return Err(
                "transaction_debugger: `redacted_body_fields` requires `log_request_body` or \
                 `log_response_body` to be true"
                    .to_string(),
            );
        }

        let safe_text_fields =
            optional_body_field_names(config, "safe_text_fields")?.unwrap_or_default();
        if !safe_text_fields.is_empty() && !(log_request_body || log_response_body) {
            return Err(
                "transaction_debugger: `safe_text_fields` requires `log_request_body` or \
                 `log_response_body` to be true"
                    .to_string(),
            );
        }

        let plugin = Self {
            instance_id: NEXT_TRANSACTION_DEBUGGER_INSTANCE_ID.fetch_add(1, Ordering::Relaxed),
            extra_redacted_headers,
            redacted_body_fields,
            safe_text_fields: Vec::new(),
            log_request_body,
            log_response_body,
            max_request_body_bytes,
            max_response_body_bytes,
            capture_body_prefix,
            capture_expires_at,
            capture_request_header,
            capture_request_header_value,
            capture_sample_threshold,
            schema,
        };
        // Deny layer: a credential-shaped or unparseable name cannot be
        // declared safe.
        for (idx, name) in safe_text_fields.iter().enumerate() {
            if !is_clean_text_field_name(name) {
                return Err(format!(
                    "transaction_debugger: `safe_text_fields[{idx}]` must contain only ASCII letters, digits, `_`, `-` and `.`"
                ));
            }
            if plugin.is_sensitive_body_key(name) || is_sensitive_header_name(name) {
                return Err(format!(
                    "transaction_debugger: `safe_text_fields[{idx}]` names a credential-bearing field and cannot be declared safe"
                ));
            }
        }
        Ok(Self {
            safe_text_fields,
            ..plugin
        })
    }

    /// The compiled diagnostic projection, if one is configured.
    #[allow(dead_code)] // used only by external unit tests; dead in the production binary
    pub fn schema(&self) -> Option<&Arc<SummarySchema>> {
        self.schema.as_ref()
    }

    /// Project one HTTP terminal diagnostic exactly as `log` would.
    ///
    /// Test seam: the production path writes the result into a `tracing` event,
    /// which external tests cannot inspect without a subscriber.
    #[doc(hidden)]
    #[allow(dead_code)] // used only by external unit tests; dead in the production binary
    pub fn project_http_for_tests(&self, summary: &TransactionSummary) -> Option<String> {
        let schema = self.schema.as_ref().filter(|s| s.applies_to_http())?;
        Self::render(
            schema,
            &DebugHttpRecord {
                summary,
                outcome: Self::classify_http_outcome(summary),
            },
        )
    }

    /// Project one stream terminal diagnostic exactly as `on_stream_disconnect`
    /// would. Test seam; see [`Self::project_http_for_tests`].
    #[doc(hidden)]
    #[allow(dead_code)] // used only by external unit tests; dead in the production binary
    pub fn project_stream_for_tests(&self, summary: &StreamTransactionSummary) -> Option<String> {
        let schema = self.schema.as_ref().filter(|s| s.applies_to_stream())?;
        Self::render(
            schema,
            &DebugStreamRecord {
                summary,
                outcome: Self::classify_stream_outcome(summary),
            },
        )
    }

    /// Project one WebSocket terminal diagnostic exactly as `on_ws_disconnect`
    /// would. Test seam; see [`Self::project_http_for_tests`].
    #[doc(hidden)]
    #[allow(dead_code)] // used only by external unit tests; dead in the production binary
    pub fn project_ws_for_tests(&self, summary: &WsDisconnectContext) -> Option<String> {
        let schema = self
            .schema
            .as_ref()
            .filter(|s| s.applies_to_websocket_disconnect())?;
        Self::render(
            schema,
            &DebugWsRecord {
                summary,
                outcome: Self::classify_ws_outcome(summary),
            },
        )
    }

    /// Render `record` through the configured schema.
    ///
    /// Only reached when a schema is configured; serialization failure is
    /// impossible for these record types (no map keys are non-strings, no
    /// non-finite floats reach here — latency/duration values are already
    /// finite), but the debugger is diagnostic-only so a failure degrades to a
    /// one-line warning rather than dropping the record silently.
    fn render<T: SchemaSerializable>(schema: &SummarySchema, record: &T) -> Option<String> {
        match serde_json::to_string(&SchemaView {
            summary: record,
            schema,
        }) {
            Ok(rendered) => Some(rendered),
            Err(error) => {
                tracing::warn!(
                    target: "transaction_debug",
                    "transaction_debugger: schema projection failed: {error}"
                );
                None
            }
        }
    }

    /// Whether bounded request-body capture is enabled.
    #[allow(dead_code)] // used only by external unit tests; dead in the production binary
    pub const fn log_request_body(&self) -> bool {
        self.log_request_body
    }

    /// Whether bounded response-body capture is enabled.
    #[allow(dead_code)] // used only by external unit tests; dead in the production binary
    pub const fn log_response_body(&self) -> bool {
        self.log_response_body
    }

    /// Effective request-body capture budget in bytes.
    #[allow(dead_code)] // used only by external unit tests; dead in the production binary
    pub const fn max_request_body_bytes(&self) -> usize {
        self.max_request_body_bytes
    }

    /// Effective response-body capture budget in bytes.
    #[allow(dead_code)] // used only by external unit tests; dead in the production binary
    pub const fn max_response_body_bytes(&self) -> usize {
        self.max_response_body_bytes
    }

    /// Whether over-cap `text/plain` / form bodies render a redacted prefix.
    #[allow(dead_code)] // used only by external unit tests; dead in the production binary
    pub const fn capture_body_prefix(&self) -> bool {
        self.capture_body_prefix
    }

    /// Why this request is outside the operator's capture target, as a fixed
    /// omission reason, or `None` when it is selected.
    ///
    /// Evaluated only from request state that no later hook rewrites for this
    /// purpose — the receive timestamp, the immediate peer address, and the
    /// selector header — so the buffering predicates and both emission hooks
    /// reach the same answer for one request. Expiry is judged against the
    /// request's receive time, so a request admitted just before the deadline
    /// is still captured in both directions.
    fn capture_selection_skip(&self, ctx: &RequestContext) -> Option<&'static str> {
        if self
            .capture_expires_at
            .is_some_and(|expires_at| ctx.timestamp_received >= expires_at)
        {
            return Some("capture_expired");
        }
        if let Some(name) = self.capture_request_header.as_deref() {
            let Some(value) = header_value(&ctx.headers, name) else {
                return Some("not_selected");
            };
            if let Some(expected) = self.capture_request_header_value.as_deref()
                && !constant_time_eq(value.trim().as_bytes(), expected.as_bytes())
            {
                return Some("not_selected");
            }
        }
        if let Some(threshold) = self.capture_sample_threshold
            && request_sample_point(ctx) >= threshold
        {
            return Some("not_selected");
        }
        None
    }

    /// Whether targeting is configured. Targeting is judged from the request
    /// context, so the context-free final request hook captures nothing then.
    fn capture_targeting_configured(&self) -> bool {
        self.capture_expires_at.is_some()
            || self.capture_request_header.is_some()
            || self.capture_sample_threshold.is_some()
    }

    /// Whether this instance already emitted `direction`'s capture record for
    /// the request.
    fn capture_record_emitted(&self, ctx: &RequestContext, direction: CaptureDirection) -> bool {
        ctx.plugin_state()
            .and_then(|state| {
                state
                    .transaction_debugger_capture_records
                    .get(&self.instance_id)
            })
            .is_some_and(|records| match direction {
                CaptureDirection::Request => records.request_emitted,
                CaptureDirection::Response => records.response_emitted,
            })
    }

    fn mark_capture_record_emitted(&self, ctx: &mut RequestContext, direction: CaptureDirection) {
        let records = ctx
            .plugin_state_mut()
            .transaction_debugger_capture_records
            .entry(self.instance_id)
            .or_default();
        match direction {
            CaptureDirection::Request => records.request_emitted = true,
            CaptureDirection::Response => records.response_emitted = true,
        }
    }

    /// Request-direction decision including targeting.
    fn request_capture_decision_for(
        &self,
        ctx: &RequestContext,
        headers: &HashMap<String, String>,
    ) -> BodyCaptureDecision {
        if !self.log_request_body {
            return BodyCaptureDecision::Skip("disabled");
        }
        if let Some(reason) = self.capture_selection_skip(ctx) {
            return BodyCaptureDecision::Skip(reason);
        }
        self.request_body_capture_decision(headers)
    }

    /// Response-direction decision including targeting and the request-shape
    /// exclusion.
    fn response_capture_decision_for(
        &self,
        ctx: &RequestContext,
        headers: &HashMap<String, String>,
    ) -> BodyCaptureDecision {
        if !self.log_response_body {
            return BodyCaptureDecision::Skip("disabled");
        }
        if let Some(reason) = self.capture_selection_skip(ctx) {
            return BodyCaptureDecision::Skip(reason);
        }
        if !self.request_shape_allows_response_capture(ctx) {
            return BodyCaptureDecision::Skip("protocol_excluded");
        }
        self.response_body_capture_decision(headers)
    }

    /// Stable terminal classification derived from the final HTTP/gRPC summary.
    ///
    /// A proven client abort — `client_disconnected` together with the
    /// `ClientDisconnect` class, which core stamps on every pre-header
    /// cancellation terminal (status 499 / gRPC `CANCELLED`) — is a client
    /// disconnect, not a dispatch failure. Neither signal alone proves it: a
    /// gateway deadline or authorization terminal carries the same
    /// health-neutral class with the flag unset, and a genuine transport error
    /// still wins over a later body-phase disconnect.
    pub fn classify_http_outcome(summary: &TransactionSummary) -> &'static str {
        if summary.client_disconnected
            && matches!(summary.error_class, Some(ErrorClass::ClientDisconnect))
        {
            "client_disconnected"
        } else if summary.error_class.is_some() {
            "dispatch_error"
        } else if summary.client_disconnected {
            "client_disconnected"
        } else if summary.body_error_class.is_some() {
            "body_error"
        } else if summary.response_streamed && !summary.body_completed {
            "body_incomplete"
        } else if summary.metadata.contains_key("rejection_phase") {
            "rejected"
        } else if summary.metadata.contains_key("mirror_error") {
            "mirror_error"
        } else if summary.grpc_status().is_some_and(|status| status != 0) {
            "grpc_error"
        } else {
            "completed"
        }
    }

    /// Stable terminal classification derived from typed stream teardown state.
    pub fn classify_stream_outcome(summary: &StreamTransactionSummary) -> &'static str {
        if matches!(summary.disconnect_cause, Some(DisconnectCause::IdleTimeout)) {
            "idle_timeout"
        } else if summary.connection_error.is_some()
            || summary.error_class.is_some()
            || summary.disconnect_direction.is_some()
            || matches!(
                summary.disconnect_cause,
                Some(
                    DisconnectCause::RecvError
                        | DisconnectCause::BackendError
                        | DisconnectCause::GatewayPolicy
                )
            )
        {
            "stream_error"
        } else if matches!(
            summary.disconnect_cause,
            Some(DisconnectCause::GracefulShutdown)
        ) {
            "graceful_shutdown"
        } else {
            "completed"
        }
    }

    /// Stable terminal classification derived from WebSocket teardown state.
    pub fn classify_ws_outcome(summary: &WsDisconnectContext) -> &'static str {
        // Core relay paths derive all three fields from one failure tuple, but keep each
        // public typed signal authoritative so a partial context cannot look completed.
        if summary.error_class.is_some() || summary.direction.is_some() || summary.io_side.is_some()
        {
            "websocket_error"
        } else {
            "completed"
        }
    }

    /// Returns true if the given header name should be redacted.
    /// Header names are normally lowercased by hyper, but tests/custom callers
    /// may provide different ASCII casing; compare case-insensitively without
    /// allocating.
    fn is_sensitive(&self, ctx: &RequestContext, header_name: &str) -> bool {
        SENSITIVE_HEADERS
            .iter()
            .any(|h| header_name.eq_ignore_ascii_case(h))
            || self
                .extra_redacted_headers
                .iter()
                .any(|h| header_name.eq_ignore_ascii_case(h))
            || ctx.request_header_requires_redaction(header_name)
            // Class-based fallback (issue #6619): a header whose NAME looks
            // like a credential under the shared metadata decision (listed
            // substrings, token / API-key spellings, operator
            // `FERRUM_LOG_REDACT_METADATA_KEYS` extras, and credential-class
            // names such as `x-session-id`, `x-csrf` or `x-private-key`) is
            // redacted even when it is not on the fixed list. Headers never take
            // the metadata-only outcome exemption.
            || is_sensitive_header_name(header_name)
    }

    /// Create a redacted copy of headers for safe logging.
    fn redact_headers(
        &self,
        ctx: &RequestContext,
        headers: &HashMap<String, String>,
    ) -> HashMap<String, String> {
        headers
            .iter()
            .map(|(k, v)| {
                // A credential-shaped value is redacted whatever the header is
                // called (`Location: …X-Amz-Credential=AKIA…`).
                if self.is_sensitive(ctx, k) || looks_like_credential(v) {
                    (k.clone(), REDACTED.to_string())
                } else {
                    (k.clone(), v.clone())
                }
            })
            .collect()
    }

    /// Eligibility of the current request for a bounded body capture.
    ///
    /// Evaluated from request headers only, so it is identical at the
    /// buffering decision and at emission time. Any answer other than
    /// `Capture` leaves the request on its ordinary streaming path.
    pub fn request_body_capture_decision(
        &self,
        headers: &HashMap<String, String>,
    ) -> BodyCaptureDecision {
        if !self.log_request_body {
            return BodyCaptureDecision::Skip("disabled");
        }
        if header_value(headers, "upgrade").is_some() {
            return BodyCaptureDecision::Skip("protocol_excluded");
        }
        capture_decision(
            headers,
            self.max_request_body_bytes,
            self.capture_body_prefix,
        )
    }

    /// Eligibility of the current response for a bounded body capture.
    pub fn response_body_capture_decision(
        &self,
        headers: &HashMap<String, String>,
    ) -> BodyCaptureDecision {
        if !self.log_response_body {
            return BodyCaptureDecision::Skip("disabled");
        }
        capture_decision(
            headers,
            self.max_response_body_bytes,
            self.capture_body_prefix,
        )
    }

    /// Whether the request shape rules out response capture before backend
    /// response headers are known. Long-lived and streaming request flavors
    /// must never be pinned onto the buffered path by the debugger.
    fn request_shape_allows_response_capture(&self, ctx: &RequestContext) -> bool {
        // Authoritative typed provenance first. The protocol flavor is stamped
        // on the protocol entry path before any plugin runs, so it survives
        // header mutation by an earlier plugin and it witnesses H2/H3 Extended
        // CONNECT WebSockets, which carry no `Upgrade` header at all.
        if ctx.is_native_grpc_request() || ctx.has_websocket_response_boundary() {
            return false;
        }
        // Conservative header screen retained on top: it covers gRPC-Web and
        // H1 `Upgrade` shapes that are not a distinct typed flavor, plus direct
        // unit callers that construct a `RequestContext` without stamping one.
        if header_value(&ctx.headers, "upgrade").is_some() {
            return false;
        }
        if header_value(&ctx.headers, "content-type").is_some_and(is_grpc_content_type) {
            return false;
        }
        if header_value(&ctx.headers, "accept")
            .is_some_and(|accept| contains_ignore_ascii_case(accept, "text/event-stream"))
        {
            return false;
        }
        true
    }

    /// Render a bounded, redacted sample of `body`.
    ///
    /// Redaction runs over the complete post-transform body first and the
    /// byte cap is applied to the redacted rendering, so a truncated capture
    /// can never expose a secret that a full capture would have removed.
    ///
    /// The work this does is bounded before it starts: a body longer than the
    /// effective ceiling (`max_bytes`, itself never allowed above
    /// [`MAX_BODY_CAPTURE_BYTES`], so a direct caller cannot widen it) is never
    /// scanned, parsed, redacted, or allocated from — it returns a content-free
    /// omission. The final hooks apply the same rule and emit the ordinary
    /// `over_capture_limit` omission record instead of calling this at all.
    ///
    /// The hooks also screen out an actually empty body first, so `body` here
    /// is non-empty on every production path. A direct caller that passes an
    /// empty slice still gets a content-free answer, but a structured family
    /// reports it through [`BODY_MALFORMED_MARKER`] — an empty document is not
    /// parseable as the structure it declared.
    pub fn render_captured_body(
        &self,
        body: &[u8],
        kind: BodyKind,
        max_bytes: usize,
    ) -> CapturedBody {
        let original_bytes = body.len();
        let effective_cap = max_bytes.min(MAX_BODY_CAPTURE_BYTES as usize);
        if original_bytes > effective_cap {
            return CapturedBody {
                state: "omitted",
                kind: "omitted",
                original_bytes,
                truncated: false,
                rendered: BODY_OVER_LIMIT_MARKER.to_string(),
            };
        }
        // A final body hook receives the complete byte slice, so an incomplete
        // multibyte tail is malformed UTF-8 rather than a capture artifact.
        // Every invalid body — prefix-valid or not — renders as the marker.
        let Ok(text) = std::str::from_utf8(body) else {
            return CapturedBody {
                state: "binary",
                kind: "binary",
                original_bytes,
                truncated: false,
                rendered: BODY_BINARY_MARKER.to_string(),
            };
        };

        let (redacted, dropped_lines) = match kind {
            BodyKind::Json => match serde_json::from_str::<Value>(text) {
                Ok(mut value) => {
                    self.redact_json_value(&mut value, 0, JsonBodyRedactionContext::Normal);
                    match serde_json::to_string(&value) {
                        Ok(rendered) => (rendered, false),
                        // Serializing an already-parsed, redacted document
                        // cannot fail; fail closed rather than degrade to a
                        // weaker redactor if it somehow does.
                        Err(_) => return malformed_structured_body(kind, original_bytes),
                    }
                }
                // A body that claims JSON but does not parse has no structure to
                // redact. Line-level fallback would redact a `"password":` line
                // while logging the value on the next line, so fail closed to a
                // fixed content-free marker instead.
                Err(_) => return malformed_structured_body(kind, original_bytes),
            },
            BodyKind::Form => (self.redact_form_body(text), false),
            BodyKind::Text => self.redact_text_lines(text),
        };

        let (slice, byte_capped) = truncate_on_char_boundary(&redacted, effective_cap);
        let (rendered, render_capped) = escape_for_diagnostics(slice);
        let truncated = byte_capped || render_capped || dropped_lines;
        CapturedBody {
            state: if truncated { "truncated" } else { "captured" },
            kind: kind.as_str(),
            original_bytes,
            truncated,
            rendered,
        }
    }

    /// Render a bounded, redacted prefix of a body longer than the capture cap
    /// (`capture_body_prefix`). A body that fits is rendered whole by
    /// [`Self::render_captured_body`].
    ///
    /// Only families whose redaction unit is self-delimiting get a prefix:
    /// `text/plain` keeps the complete lines and a form body the complete
    /// `&`-separated pairs that fit inside the cap; the unit cut by the cap is
    /// dropped rather than rendered half-redacted. Only the first `max_bytes`
    /// (never above [`MAX_BODY_CAPTURE_BYTES`]) are ever scanned. JSON needs
    /// the whole document to know which key a value belongs to, so it returns
    /// `None`, as does a window holding no complete unit; the caller reports
    /// those as the ordinary content-free `over_capture_limit` omission.
    pub fn render_captured_prefix(
        &self,
        body: &[u8],
        kind: BodyKind,
        max_bytes: usize,
    ) -> Option<CapturedBody> {
        let effective_cap = max_bytes.min(MAX_BODY_CAPTURE_BYTES as usize);
        if body.len() <= effective_cap {
            return Some(self.render_captured_body(body, kind, max_bytes));
        }
        let separator = match kind {
            BodyKind::Json => return None,
            BodyKind::Form => b'&',
            BodyKind::Text => b'\n',
        };
        let window = body.get(..effective_cap)?;
        let end = window.iter().rposition(|byte| *byte == separator)?;
        if end == 0 {
            return None;
        }
        let original_bytes = body.len();
        // Cut at an ASCII separator, so a valid UTF-8 body never splits a
        // multibyte character here; anything else is binary.
        let Ok(text) = std::str::from_utf8(window.get(..end)?) else {
            return Some(CapturedBody {
                state: "binary",
                kind: "binary",
                original_bytes,
                truncated: false,
                rendered: BODY_BINARY_MARKER.to_string(),
            });
        };
        let redacted = match kind {
            BodyKind::Json => return None,
            BodyKind::Form => self.redact_form_body(text),
            BodyKind::Text => self.redact_text_lines(text).0,
        };
        let (slice, _) = truncate_on_char_boundary(&redacted, effective_cap);
        let (rendered, _) = escape_for_diagnostics(slice);
        Some(CapturedBody {
            state: "truncated",
            kind: kind.as_str(),
            original_bytes,
            truncated: true,
            rendered,
        })
    }

    /// The record a final body hook emits for an admitted (`Capture`)
    /// decision, after re-checking the actual body.
    fn final_body_record(
        &self,
        body: &[u8],
        kind: BodyKind,
        max_bytes: usize,
        decision: BodyCaptureDecision,
    ) -> (BodyCaptureDecision, Option<CapturedBody>) {
        // `Content-Length` admitted this message, but the actual body is what
        // gets walked. A stale/lying header or a transform that grew the body
        // must not widen the capture ceiling, so fail closed before any UTF-8
        // scan, parse, or allocation — unless prefix sampling is on, which
        // scans at most the cap.
        if body.len() > max_bytes {
            if self.capture_body_prefix
                && let Some(sample) = self.render_captured_prefix(body, kind, max_bytes)
            {
                return (decision, Some(sample));
            }
            return (BodyCaptureDecision::Skip("over_capture_limit"), None);
        }
        // The declared length can overstate the message too (a `HEAD` / `304`
        // response, or a transform that emptied the body). Report the fixed
        // `empty_body` reason the header screen uses rather than handing an
        // empty slice to the renderer, where a structured family would report
        // it as a *malformed* body the peer never sent.
        if body.is_empty() {
            return (BodyCaptureDecision::Skip("empty_body"), None);
        }
        (
            decision,
            Some(self.render_captured_body(body, kind, max_bytes)),
        )
    }

    /// Whether a body field name (or an unstructured text line) is
    /// credential-bearing under the built-in list, the operator's
    /// `redacted_body_fields` / `redacted_headers`, and the central metadata
    /// sensitivity classifier (which carries `FERRUM_LOG_REDACT_METADATA_KEYS`).
    fn is_sensitive_body_key(&self, key: &str) -> bool {
        let lowered = key.to_ascii_lowercase();
        let matches_marker = SENSITIVE_BODY_KEY_SUBSTRINGS
            .iter()
            .any(|marker| lowered.contains(marker));
        matches_marker
            || SENSITIVE_BODY_KEY_EXACT.iter().any(|name| lowered == *name)
            || SENSITIVE_HEADERS.iter().any(|name| lowered == *name)
            || self.extra_redacted_headers.contains(&lowered)
            || self.redacted_body_fields.contains(&lowered)
            // Also the original spelling: lowercasing first erases the
            // camelCase boundaries the classifier segments on (`hsmPin`).
            || is_sensitive_metadata_key(key)
            || is_sensitive_metadata_key(&lowered)
    }

    /// Whether a parsed `text/plain` field name may keep its line: a clean
    /// ASCII name declared in `safe_text_fields` that the deny layer does not
    /// match.
    fn is_safe_text_field(&self, name: &str) -> bool {
        is_clean_text_field_name(name)
            && self
                .safe_text_fields
                .iter()
                .any(|safe| name.eq_ignore_ascii_case(safe))
            && !self.is_sensitive_body_key(name)
            && !is_sensitive_header_name(name)
    }

    /// Whether an unstructured line carries any sensitive marker. Line-level
    /// matching is deliberately coarse: unstructured text has no field grammar,
    /// so a line that mentions a credential marker is dropped wholesale.
    fn line_is_sensitive(&self, line: &str) -> bool {
        let lowered = line.to_ascii_lowercase();
        let matches_marker = SENSITIVE_BODY_KEY_SUBSTRINGS
            .iter()
            .any(|marker| lowered.contains(marker));
        matches_marker
            || SENSITIVE_HEADERS.iter().any(|name| lowered.contains(name))
            || self
                .extra_redacted_headers
                .iter()
                .any(|n| lowered.contains(n))
            || self
                .redacted_body_fields
                .iter()
                .any(|n| lowered.contains(n))
            // Free text: the listed rules only. The credential-class
            // classifier is for key names and would drop prose such as
            // `auth_method=jwt_auth` (issue #6619).
            || is_sensitive_name_by_listed_rules(&lowered)
            // Fail closed: a line with any `=` / `:` is rendered only when
            // every delimiter follows a clean field name declared in
            // `safe_text_fields` (issue #6619). Missing, quoted, unknown,
            // unparseable, or credential-shaped names (`(hsm_pin): …`,
            // `"note": …`, `hsm_piné=…`, `key_private=…`) drop the line.
            || !assignment_names_all_safe(line, |name| self.is_safe_text_field(name))
            || lowered.contains("bearer ")
            || lowered.contains("basic ")
            || lowered.contains("eyj")
            // Field-independent value shapes: compact JOSE tokens whatever
            // their header spelling, provider API keys, AWS access keys, and
            // PEM private-key markers.
            || looks_like_credential(line)
    }

    fn redact_json_value(&self, value: &mut Value, depth: usize, ctx: JsonBodyRedactionContext) {
        if depth > MAX_JSON_REDACTION_DEPTH {
            *value = Value::String(BODY_DEPTH_MARKER.to_string());
            return;
        }
        match value {
            Value::Object(map) => {
                let keys = map.keys().cloned().collect::<Vec<_>>();
                for key in keys {
                    let Some(entry) = map.get_mut(&key) else {
                        continue;
                    };
                    if self.is_sensitive_body_key(&key) {
                        *entry = Value::String(REDACTED.to_string());
                    } else if ctx == JsonBodyRedactionContext::DataSourceItem
                        && is_azure_parameters_field(&key)
                    {
                        wholesale_redact_data_source_parameters(entry);
                    } else if ctx == JsonBodyRedactionContext::Normal
                        && is_azure_data_sources_field(&key)
                    {
                        // The provider's conventional shape is an array of
                        // data-source items, but a captured body is arbitrary
                        // JSON and this name proves no type invariant. Every
                        // other shape is traversed as a single data-source item
                        // instead of falling out of the branch untouched: a
                        // recognized container name must never bypass the
                        // ordinary member-name and credential-string visitor.
                        match entry {
                            Value::Array(sources) => {
                                for source in sources.iter_mut() {
                                    self.redact_json_value(
                                        source,
                                        depth + 1,
                                        JsonBodyRedactionContext::DataSourceItem,
                                    );
                                }
                            }
                            other => self.redact_json_value(
                                other,
                                depth + 1,
                                JsonBodyRedactionContext::DataSourceItem,
                            ),
                        }
                    } else {
                        let next_ctx = if ctx == JsonBodyRedactionContext::DataSourceItem {
                            JsonBodyRedactionContext::DataSourceItem
                        } else {
                            JsonBodyRedactionContext::Normal
                        };
                        self.redact_json_value(entry, depth + 1, next_ctx);
                    }
                }
            }
            Value::Array(items) => {
                for entry in items.iter_mut() {
                    self.redact_json_value(entry, depth + 1, ctx);
                }
            }
            Value::String(text) if looks_like_credential(text) => {
                *text = REDACTED.to_string();
            }
            _ => {}
        }
    }

    fn redact_form_body(&self, text: &str) -> String {
        let mut out = String::with_capacity(text.len());
        for (index, pair) in text.split('&').enumerate() {
            if index > 0 {
                out.push('&');
            }
            match pair.split_once('=') {
                Some((raw_key, raw_value)) => {
                    out.push_str(raw_key);
                    out.push('=');
                    if self.is_sensitive_body_key(&decode_form_component(raw_key))
                        || looks_like_credential(&decode_form_component(raw_value))
                    {
                        out.push_str(REDACTED);
                    } else {
                        out.push_str(raw_value);
                    }
                }
                // A bare token carries no field name to classify; keep the
                // credential screen so a raw bearer value cannot slip through.
                None => {
                    if self.is_sensitive_body_key(&decode_form_component(pair))
                        || looks_like_credential(&decode_form_component(pair))
                    {
                        out.push_str(REDACTED);
                    } else {
                        out.push_str(pair);
                    }
                }
            }
        }
        out
    }

    /// Line-level redaction for unstructured text. Returns the redacted text
    /// and whether lines beyond [`MAX_TEXT_REDACTION_LINES`] were dropped.
    ///
    /// Only reachable for `text/plain`, whose coarse, whole-line replacement is
    /// documented as an operator opt-in. It is never used as a fallback for a
    /// structured family.
    fn redact_text_lines(&self, text: &str) -> (String, bool) {
        let mut out = String::with_capacity(text.len());
        let mut dropped = false;
        // The base64 body lines of a PEM private key carry no marker of their
        // own, so a `-----BEGIN … PRIVATE KEY-----` line redacts every line
        // through its `-----END` line (or the end of the text).
        let mut in_private_key_block = false;
        for (index, line) in text.lines().enumerate() {
            if index >= MAX_TEXT_REDACTION_LINES {
                dropped = true;
                break;
            }
            if index > 0 {
                out.push('\n');
            }
            let redact = if in_private_key_block {
                if contains_ignore_ascii_case(line, "-----END") {
                    in_private_key_block = false;
                }
                true
            } else if contains_private_key_marker(line) {
                in_private_key_block = contains_ignore_ascii_case(line, "-----BEGIN")
                    && !contains_ignore_ascii_case(line, "-----END");
                true
            } else {
                self.line_is_sensitive(line)
            };
            if redact {
                out.push_str(REDACTED);
            } else {
                out.push_str(line);
            }
        }
        (out, dropped)
    }

    /// Shared implementation of both final request-body hooks.
    ///
    /// `ctx`, when the proxy supplies it, is the authoritative source of the
    /// request method and path. The hook header map is the backend-visible one
    /// and carries `:method` / `:path` only on the gRPC and H3 body-transform
    /// paths, so it is the fallback rather than the primary source.
    ///
    /// With a context this hook owns the request record whenever
    /// `before_proxy` has not already emitted one: an admitted request whose
    /// final body is oversized, empty, or no longer capturable reports that
    /// omission here. The context-free hook cannot see that state (nor the
    /// targeting inputs), so it keeps the header-phase split — it only reports
    /// an admitted body — and captures nothing when targeting is configured.
    fn capture_final_request_body(
        &self,
        mut ctx: Option<&mut RequestContext>,
        headers: &HashMap<String, String>,
        body: &[u8],
    ) -> PluginResult {
        if !self.log_request_body || !capture_output_enabled() {
            return PluginResult::Continue;
        }
        let decision = match ctx.as_deref() {
            Some(hook_ctx) => {
                if self.capture_record_emitted(hook_ctx, CaptureDirection::Request) {
                    return PluginResult::Continue;
                }
                self.request_capture_decision_for(hook_ctx, headers)
            }
            None => {
                if self.capture_targeting_configured() {
                    return PluginResult::Continue;
                }
                self.request_body_capture_decision(headers)
            }
        };
        let (record, sample) = match decision {
            BodyCaptureDecision::Capture { kind, max_bytes } => {
                self.final_body_record(body, kind, max_bytes, decision)
            }
            BodyCaptureDecision::Skip(_) if ctx.is_none() => return PluginResult::Continue,
            skip @ BodyCaptureDecision::Skip(_) => (skip, None),
        };
        let (method, path) = match ctx.as_deref() {
            Some(hook_ctx) => (hook_ctx.method.as_str(), hook_ctx.path.as_str()),
            None => (
                header_value(headers, ":method").unwrap_or("-"),
                header_value(headers, ":path").unwrap_or("-"),
            ),
        };
        self.emit_body_capture(
            CaptureDirection::Request,
            method,
            path,
            record,
            sample.as_ref(),
        );
        if let Some(hook_ctx) = ctx.as_deref_mut() {
            self.mark_capture_record_emitted(hook_ctx, CaptureDirection::Request);
        }
        PluginResult::Continue
    }

    /// Emit one capture record for a direction. `decision` describes what the
    /// buffering predicates concluded; `captured` is present only when the body
    /// was actually available.
    fn emit_body_capture(
        &self,
        direction: CaptureDirection,
        method: &str,
        path: &str,
        decision: BodyCaptureDecision,
        captured: Option<&CapturedBody>,
    ) {
        let direction = direction.as_str();
        match (decision, captured) {
            (BodyCaptureDecision::Capture { .. }, Some(sample)) => {
                tracing::debug!(
                    target: "transaction_debug",
                    direction = %direction,
                    capture = %sample.state,
                    body_kind = %sample.kind,
                    body_bytes = sample.original_bytes,
                    truncated = sample.truncated,
                    method = %method,
                    path = %path,
                    body = %sample.rendered,
                    "Bounded body capture",
                );
            }
            (BodyCaptureDecision::Skip(reason), _) => {
                tracing::debug!(
                    target: "transaction_debug",
                    direction = %direction,
                    capture = %BODY_CAPTURE_OMITTED,
                    reason = %reason,
                    method = %method,
                    path = %path,
                    "Bounded body capture omitted",
                );
            }
            (BodyCaptureDecision::Capture { .. }, None) => {}
        }
    }
}

#[async_trait]
impl Plugin for TransactionDebugger {
    fn name(&self) -> &str {
        "transaction_debugger"
    }

    fn priority(&self) -> u16 {
        super::priority::TRANSACTION_DEBUGGER
    }

    fn supported_protocols(&self) -> &'static [super::ProxyProtocol] {
        super::ALL_PROTOCOLS
    }

    async fn on_request_received(&self, ctx: &mut RequestContext) -> PluginResult {
        if tracing::enabled!(target: "transaction_debug", tracing::Level::DEBUG) {
            let safe_headers = self.redact_headers(ctx, &ctx.headers);
            tracing::debug!(target: "transaction_debug", method = %ctx.method, path = %ctx.path, client_ip = %ctx.client_ip, headers = ?safe_headers, "Incoming request");
        }
        PluginResult::Continue
    }

    fn requires_request_body_buffering(&self) -> bool {
        self.log_request_body
    }

    fn should_buffer_request_body(&self, ctx: &RequestContext) -> bool {
        self.log_request_body
            && capture_output_enabled()
            && self
                .request_capture_decision_for(ctx, &ctx.headers)
                .is_capture()
    }

    /// The capture reads the body from the `on_final_request_body` parameter,
    /// so the debugger never asks for the extra UTF-8 copy in
    /// `ctx.metadata["request_body"]`.
    fn needs_request_body_text(&self) -> bool {
        false
    }

    fn requires_response_body_buffering(&self) -> bool {
        self.log_response_body
    }

    fn should_buffer_response_body(&self, ctx: &RequestContext) -> bool {
        self.log_response_body
            && capture_output_enabled()
            && self.capture_selection_skip(ctx).is_none()
            && self.request_shape_allows_response_capture(ctx)
    }

    fn should_buffer_response_body_for_content_type(
        &self,
        ctx: &RequestContext,
        _content_type: Option<&str>,
        _response_status: u16,
        response_headers: &HashMap<String, String>,
    ) -> bool {
        self.should_buffer_response_body(ctx)
            && self
                .response_body_capture_decision(response_headers)
                .is_capture()
    }

    /// A retry-enabled proxy keeps every response buffered unless each active
    /// buffering plugin explicitly opts a concrete response out once headers
    /// arrive. Without this pair the retry path would never consult
    /// [`Plugin::should_buffer_response_body_for_content_type`], so enabling
    /// `log_response_body` would pin SSE and every other long-lived,
    /// unknown-length, or encoded response onto the buffered path — exactly what
    /// the capture design promises never to do.
    fn may_release_response_body_under_retries(&self, ctx: &RequestContext) -> bool {
        self.should_buffer_response_body(ctx)
    }

    /// Release, after headers, every response this debugger will not sample.
    ///
    /// The capture screen is complete from the response headers alone, so the
    /// only responses kept buffered — and therefore still mid-body retryable —
    /// are the small, identity-encoded, known-length textual ones that are
    /// actually going to be captured.
    fn should_release_response_body_under_retries(
        &self,
        ctx: &RequestContext,
        _response_status: u16,
        response_headers: &HashMap<String, String>,
    ) -> bool {
        self.should_buffer_response_body(ctx)
            && !self
                .response_body_capture_decision(response_headers)
                .is_capture()
    }

    async fn before_proxy(
        &self,
        ctx: &mut RequestContext,
        headers: &mut HashMap<String, String>,
    ) -> PluginResult {
        // Emit the omission record for a request that will keep streaming. The
        // capture record itself is emitted by `on_final_request_body`, which
        // only runs once the body has actually been buffered.
        if self.log_request_body
            && capture_output_enabled()
            && !self.capture_record_emitted(ctx, CaptureDirection::Request)
        {
            let decision = self.request_capture_decision_for(ctx, headers);
            if decision.skip_reason().is_some() {
                self.emit_body_capture(
                    CaptureDirection::Request,
                    &ctx.method,
                    &ctx.path,
                    decision,
                    None,
                );
                self.mark_capture_record_emitted(ctx, CaptureDirection::Request);
            }
        }
        PluginResult::Continue
    }

    async fn on_final_request_body(
        &self,
        headers: &HashMap<String, String>,
        body: &[u8],
    ) -> PluginResult {
        self.capture_final_request_body(None, headers, body)
    }

    /// The hook-visible header map is the backend-visible one; only the gRPC
    /// and H3 body-transform paths synthesize `:path` / `:method` into it. The
    /// context carries both unconditionally, so opting in here is what keeps a
    /// request capture record correlatable with its request on H1/H2. Gated on
    /// the capture switch so a disabled debugger never asks the proxy to build
    /// the hook context clone.
    fn needs_final_request_body_context(&self) -> bool {
        self.log_request_body
    }

    async fn on_final_request_body_with_context(
        &self,
        ctx: &mut RequestContext,
        headers: &HashMap<String, String>,
        body: &[u8],
    ) -> PluginResult {
        self.capture_final_request_body(Some(ctx), headers, body)
    }

    async fn after_proxy(
        &self,
        ctx: &mut RequestContext,
        response_status: u16,
        response_headers: &mut HashMap<String, String>,
    ) -> PluginResult {
        if tracing::enabled!(target: "transaction_debug", tracing::Level::DEBUG) {
            let safe_headers = self.redact_headers(ctx, response_headers);
            tracing::debug!(target: "transaction_debug", status = response_status, method = %ctx.method, path = %ctx.path, headers = ?safe_headers, "Backend response");
            if self.log_response_body
                && !self.capture_record_emitted(ctx, CaptureDirection::Response)
            {
                let decision = self.response_capture_decision_for(ctx, response_headers);
                if decision.skip_reason().is_some() {
                    self.emit_body_capture(
                        CaptureDirection::Response,
                        &ctx.method,
                        &ctx.path,
                        decision,
                        None,
                    );
                    self.mark_capture_record_emitted(ctx, CaptureDirection::Response);
                }
            }
        }
        PluginResult::Continue
    }

    async fn on_final_response_body(
        &self,
        ctx: &mut RequestContext,
        _response_status: u16,
        response_headers: &HashMap<String, String>,
        body: &[u8],
    ) -> PluginResult {
        if !self.log_response_body || !capture_output_enabled() {
            return PluginResult::Continue;
        }
        // `after_proxy` already reported this response (an omission), or a
        // re-invocation of this hook already emitted it.
        if self.capture_record_emitted(ctx, CaptureDirection::Response) {
            return PluginResult::Continue;
        }
        // The final, client-visible header map is authoritative here: a
        // response transform syncs `Content-Length` / `Content-Type` before
        // this hook, so a decision that flipped since `after_proxy` reports
        // the final reason (`over_capture_limit`, `empty_body`, …) instead of
        // leaving the response with no record at all.
        let decision = self.response_capture_decision_for(ctx, response_headers);
        let (record, sample) = match decision {
            BodyCaptureDecision::Capture { kind, max_bytes } => {
                self.final_body_record(body, kind, max_bytes, decision)
            }
            skip @ BodyCaptureDecision::Skip(_) => (skip, None),
        };
        self.emit_body_capture(
            CaptureDirection::Response,
            &ctx.method,
            &ctx.path,
            record,
            sample.as_ref(),
        );
        self.mark_capture_record_emitted(ctx, CaptureDirection::Response);
        PluginResult::Continue
    }

    async fn on_stream_disconnect(&self, summary: &StreamTransactionSummary) {
        if !tracing::enabled!(target: "transaction_debug", tracing::Level::DEBUG) {
            return;
        }
        // A schema whose `summary_type` excludes this entry kind falls back to
        // the native diagnostic, matching every log-shipping plugin.
        if let Some(schema) = self
            .schema
            .as_ref()
            .filter(|schema| schema.applies_to_stream())
        {
            let record = DebugStreamRecord {
                summary,
                outcome: Self::classify_stream_outcome(summary),
            };
            if let Some(rendered) = Self::render(schema, &record) {
                tracing::debug!(
                    target: "transaction_debug",
                    record = %rendered,
                    "Stream terminal diagnostic",
                );
            }
            return;
        }
        let outcome = Self::classify_stream_outcome(summary);
        let error_class = summary.error_class.map(|class| class.as_str());
        let disconnect_direction = summary.disconnect_direction.map(direction_label);
        let disconnect_cause = summary.disconnect_cause.map(disconnect_cause_label);
        let request_id = selected_metadata_value(&summary.metadata, "request_id");
        let trace_id = selected_metadata_value(&summary.metadata, "trace_id");
        tracing::debug!(
            target: "transaction_debug",
            outcome = %outcome,
            namespace = %summary.namespace,
            protocol = %summary.protocol,
            proxy_id = %summary.proxy_id,
            proxy_name = %summary.proxy_name.as_deref().unwrap_or("-"),
            client_ip = %summary.client_ip,
            listen_port = summary.listen_port,
            backend_target = %summary.backend_target,
            backend_resolved_ip = %summary.backend_resolved_ip.as_deref().unwrap_or("-"),
            consumer_username = %summary.consumer_username.as_deref().unwrap_or("-"),
            auth_method = %summary.auth_method.unwrap_or("-"),
            connection_error = %summary.connection_error.as_deref().unwrap_or("-"),
            error_class = %error_class.unwrap_or("-"),
            disconnect_direction = %disconnect_direction.unwrap_or("-"),
            disconnect_cause = %disconnect_cause.unwrap_or("-"),
            duration_ms = summary.duration_ms,
            bytes_sent = summary.bytes_sent,
            bytes_received = summary.bytes_received,
            timestamp_connected = %summary.timestamp_connected,
            timestamp_disconnected = %summary.timestamp_disconnected,
            sni_hostname = %summary.sni_hostname.as_deref().unwrap_or("-"),
            request_id = %request_id.unwrap_or("-"),
            trace_id = %trace_id.unwrap_or("-"),
            "Stream terminal diagnostic",
        );
    }

    async fn log(&self, summary: &TransactionSummary) {
        if !tracing::enabled!(target: "transaction_debug", tracing::Level::DEBUG) {
            return;
        }
        if let Some(schema) = self
            .schema
            .as_ref()
            .filter(|schema| schema.applies_to_http())
        {
            let record = DebugHttpRecord {
                summary,
                outcome: Self::classify_http_outcome(summary),
            };
            if let Some(rendered) = Self::render(schema, &record) {
                tracing::debug!(
                    target: "transaction_debug",
                    record = %rendered,
                    "Transaction terminal diagnostic",
                );
            }
            return;
        }
        let outcome = Self::classify_http_outcome(summary);
        let error_class = summary.error_class.map(|class| class.as_str());
        let body_error_class = summary.body_error_class.map(|class| class.as_str());
        let rejection_phase = selected_metadata_value(&summary.metadata, "rejection_phase");
        let grpc_status = selected_metadata_value(&summary.metadata, "grpc_status");
        let request_id = selected_metadata_value(&summary.metadata, "request_id");
        let trace_id = selected_metadata_value(&summary.metadata, "trace_id");
        tracing::debug!(
            target: "transaction_debug",
            outcome = %outcome,
            namespace = %summary.namespace,
            timestamp_received = %summary.timestamp_received,
            client_ip = %summary.client_ip,
            method = %summary.http_method,
            path = %summary.request_path,
            status = summary.response_status_code,
            proxy_id = %summary.proxy_id.as_deref().unwrap_or("-"),
            proxy_name = %summary.proxy_name.as_deref().unwrap_or("-"),
            backend_target = %summary.backend_target.as_deref().unwrap_or("-"),
            backend_resolved_ip = %summary.backend_resolved_ip.as_deref().unwrap_or("-"),
            consumer_username = %summary.consumer_username.as_deref().unwrap_or("-"),
            auth_method = %summary.auth_method.unwrap_or("-"),
            error_class = %error_class.unwrap_or("-"),
            body_error_class = %body_error_class.unwrap_or("-"),
            response_streamed = summary.response_streamed,
            body_completed = summary.body_completed,
            client_disconnected = summary.client_disconnected,
            bytes_sent = summary.bytes_sent,
            bytes_received = summary.bytes_received,
            rejection_phase = %rejection_phase.unwrap_or("-"),
            grpc_status = %grpc_status.unwrap_or("-"),
            request_id = %request_id.unwrap_or("-"),
            trace_id = %trace_id.unwrap_or("-"),
            latency_total_ms = summary.latency_total_ms,
            latency_backend_ttfb_ms = summary.latency_backend_ttfb_ms,
            latency_backend_total_ms = summary.latency_backend_total_ms,
            latency_plugin_ms = summary.latency_plugin_execution_ms,
            latency_gw_overhead_ms = summary.latency_gateway_overhead_ms,
            "Transaction terminal diagnostic",
        );
    }

    fn requires_ws_disconnect_hooks(&self) -> bool {
        true
    }

    async fn on_ws_disconnect(&self, summary: &WsDisconnectContext) {
        if !tracing::enabled!(target: "transaction_debug", tracing::Level::DEBUG) {
            return;
        }
        if let Some(schema) = self
            .schema
            .as_ref()
            .filter(|schema| schema.applies_to_websocket_disconnect())
        {
            let record = DebugWsRecord {
                summary,
                outcome: Self::classify_ws_outcome(summary),
            };
            if let Some(rendered) = Self::render(schema, &record) {
                tracing::debug!(
                    target: "transaction_debug",
                    record = %rendered,
                    "WebSocket terminal diagnostic",
                );
            }
            return;
        }
        let outcome = Self::classify_ws_outcome(summary);
        let direction = summary.direction.map(direction_label);
        let io_side = summary.io_side.map(stream_io_side_label);
        let error_class = summary.error_class.map(|class| class.as_str());
        let request_id = selected_metadata_value(&summary.metadata, "request_id");
        let trace_id = selected_metadata_value(&summary.metadata, "trace_id");
        tracing::debug!(
            target: "transaction_debug",
            outcome = %outcome,
            namespace = %summary.namespace,
            proxy_id = %summary.proxy_id,
            proxy_name = %summary.proxy_name.as_deref().unwrap_or("-"),
            client_ip = %summary.client_ip,
            listen_port = summary.listen_port,
            backend_target = %summary.backend_target,
            consumer_username = %summary.consumer_username.as_deref().unwrap_or("-"),
            auth_method = %summary.auth_method.unwrap_or("-"),
            duration_ms = summary.duration_ms,
            frames_client_to_backend = summary.frames_client_to_backend,
            frames_backend_to_client = summary.frames_backend_to_client,
            bytes_client_to_backend = summary.bytes_client_to_backend,
            bytes_backend_to_client = summary.bytes_backend_to_client,
            disconnect_direction = %direction.unwrap_or("-"),
            io_side = %io_side.unwrap_or("-"),
            error_class = %error_class.unwrap_or("-"),
            request_id = %request_id.unwrap_or("-"),
            trace_id = %trace_id.unwrap_or("-"),
            "WebSocket terminal diagnostic",
        );
    }
}

// ---------------------------------------------------------------------------
// Schema-projected terminal diagnostics
// ---------------------------------------------------------------------------
//
// These record views exist ONLY when an operator configures `schema:` /
// `schema_ref:`. They are faithful projections of the default diagnostic
// records: the same field names, the same values, and the same `"-"`
// placeholder for an absent optional. That keeps `omit` / `rename` / `order`
// operating on exactly what the default record emits, so a schema is a
// projection of the documented output rather than a second, subtly different
// record shape.
//
// The one field the default records do not carry is `metadata`. The default
// diagnostic hand-picks `request_id` / `trace_id` out of the summary metadata;
// the projected record additionally exposes the full map as a native
// `metadata` field so the shared `nested` / `omit` / `flatten` policy is
// available here as on every log-shipping sink. Every path routes through
// `serialize_redacted_metadata` / `flatten_metadata`, so sensitive keys are
// redacted and `_dedup_*` lifecycle keys are stripped even when the outer field
// is renamed or the map is flattened.

/// Emit an optional string as the default diagnostic does: the value, or the
/// `"-"` placeholder when absent.
fn emit_optional<S: SerializeMap>(
    out_key: &str,
    value: Option<&str>,
    map: &mut S,
) -> Result<(), S::Error> {
    map.serialize_entry(out_key, value.unwrap_or("-"))
}

/// HTTP / gRPC terminal diagnostic under a compiled schema.
pub(crate) struct DebugHttpRecord<'a> {
    pub(crate) summary: &'a TransactionSummary,
    pub(crate) outcome: &'static str,
}

impl<'a> SchemaSerializable for DebugHttpRecord<'a> {
    fn owns_native(&self, source: &str) -> bool {
        crate::plugins::utils::log_schema::DEBUG_HTTP_FIELDS
            .iter()
            .any(|f| f.name == source)
    }

    fn serialize_native<S>(
        &self,
        source: &'static str,
        out_key: &str,
        ts_format: TimestampFormat,
        map: &mut S,
    ) -> Result<(), S::Error>
    where
        S: SerializeMap,
    {
        let summary = self.summary;
        match source {
            "outcome" => map.serialize_entry(out_key, self.outcome),
            "namespace" => map.serialize_entry(out_key, &summary.namespace),
            "timestamp_received" => {
                emit_timestamp(out_key, &summary.timestamp_received, ts_format, map)
            }
            "client_ip" => map.serialize_entry(out_key, &summary.client_ip),
            "method" => map.serialize_entry(out_key, &summary.http_method),
            "path" => map.serialize_entry(out_key, &summary.request_path),
            "status" => map.serialize_entry(out_key, &summary.response_status_code),
            "proxy_id" => emit_optional(out_key, summary.proxy_id.as_deref(), map),
            "proxy_name" => emit_optional(out_key, summary.proxy_name.as_deref(), map),
            "backend_target" => emit_optional(out_key, summary.backend_target.as_deref(), map),
            "backend_resolved_ip" => {
                emit_optional(out_key, summary.backend_resolved_ip.as_deref(), map)
            }
            "consumer_username" => {
                emit_optional(out_key, summary.consumer_username.as_deref(), map)
            }
            "auth_method" => emit_optional(out_key, summary.auth_method, map),
            "error_class" => emit_optional(out_key, summary.error_class.map(|c| c.as_str()), map),
            "body_error_class" => {
                emit_optional(out_key, summary.body_error_class.map(|c| c.as_str()), map)
            }
            "response_streamed" => map.serialize_entry(out_key, &summary.response_streamed),
            "body_completed" => map.serialize_entry(out_key, &summary.body_completed),
            "client_disconnected" => map.serialize_entry(out_key, &summary.client_disconnected),
            "bytes_sent" => map.serialize_entry(out_key, &summary.bytes_sent),
            "bytes_received" => map.serialize_entry(out_key, &summary.bytes_received),
            "rejection_phase" => emit_optional(
                out_key,
                selected_metadata_value(&summary.metadata, "rejection_phase"),
                map,
            ),
            "grpc_status" => emit_optional(
                out_key,
                selected_metadata_value(&summary.metadata, "grpc_status"),
                map,
            ),
            "request_id" => emit_optional(
                out_key,
                selected_metadata_value(&summary.metadata, "request_id"),
                map,
            ),
            "trace_id" => emit_optional(
                out_key,
                selected_metadata_value(&summary.metadata, "trace_id"),
                map,
            ),
            "latency_total_ms" => map.serialize_entry(out_key, &summary.latency_total_ms),
            "latency_backend_ttfb_ms" => {
                map.serialize_entry(out_key, &summary.latency_backend_ttfb_ms)
            }
            "latency_backend_total_ms" => {
                map.serialize_entry(out_key, &summary.latency_backend_total_ms)
            }
            "latency_plugin_ms" => {
                map.serialize_entry(out_key, &summary.latency_plugin_execution_ms)
            }
            "latency_gw_overhead_ms" => {
                map.serialize_entry(out_key, &summary.latency_gateway_overhead_ms)
            }
            "metadata" => map.serialize_entry(out_key, &MetadataNested(&summary.metadata)),
            // Fields owned by another entry kind in a `both`/ws schema.
            _ => Ok(()),
        }
    }

    fn serialize_derived<S>(
        &self,
        kind: DerivedKind,
        out_key: &str,
        map: &mut S,
    ) -> Result<bool, S::Error>
    where
        S: SerializeMap,
    {
        match kind {
            DerivedKind::StatusClass => {
                map.serialize_entry(out_key, status_class(self.summary.response_status_code))?;
                Ok(true)
            }
            DerivedKind::BackendHost => match self
                .summary
                .backend_target
                .as_deref()
                .and_then(extract_host_from_url)
            {
                Some(host) => {
                    map.serialize_entry(out_key, host)?;
                    Ok(true)
                }
                None => Ok(false),
            },
            DerivedKind::SummaryKind => {
                map.serialize_entry(out_key, "http")?;
                Ok(true)
            }
            DerivedKind::Outcome => {
                let is_error =
                    self.summary.response_status_code >= 500 || self.summary.is_terminal_failure();
                map.serialize_entry(out_key, if is_error { "error" } else { "ok" })?;
                Ok(true)
            }
        }
    }

    fn serialize_metadata<S>(
        &self,
        policy: &MetadataPolicy,
        emitted: &EmittedKeys<'_>,
        map: &mut S,
    ) -> Result<(), S::Error>
    where
        S: SerializeMap,
    {
        serialize_schema_metadata(&self.summary.metadata, policy, emitted, map)
    }
}

/// Stream (TCP/UDP/DTLS) terminal diagnostic under a compiled schema.
pub(crate) struct DebugStreamRecord<'a> {
    pub(crate) summary: &'a StreamTransactionSummary,
    pub(crate) outcome: &'static str,
}

impl<'a> SchemaSerializable for DebugStreamRecord<'a> {
    fn owns_native(&self, source: &str) -> bool {
        crate::plugins::utils::log_schema::DEBUG_STREAM_FIELDS
            .iter()
            .any(|f| f.name == source)
    }

    fn serialize_native<S>(
        &self,
        source: &'static str,
        out_key: &str,
        ts_format: TimestampFormat,
        map: &mut S,
    ) -> Result<(), S::Error>
    where
        S: SerializeMap,
    {
        let summary = self.summary;
        match source {
            "outcome" => map.serialize_entry(out_key, self.outcome),
            "namespace" => map.serialize_entry(out_key, &summary.namespace),
            "protocol" => map.serialize_entry(out_key, &summary.protocol),
            "proxy_id" => map.serialize_entry(out_key, &summary.proxy_id),
            "proxy_name" => emit_optional(out_key, summary.proxy_name.as_deref(), map),
            "client_ip" => map.serialize_entry(out_key, &summary.client_ip),
            "listen_port" => map.serialize_entry(out_key, &summary.listen_port),
            "backend_target" => map.serialize_entry(out_key, &summary.backend_target),
            "backend_resolved_ip" => {
                emit_optional(out_key, summary.backend_resolved_ip.as_deref(), map)
            }
            "consumer_username" => {
                emit_optional(out_key, summary.consumer_username.as_deref(), map)
            }
            "auth_method" => emit_optional(out_key, summary.auth_method, map),
            "connection_error" => emit_optional(out_key, summary.connection_error.as_deref(), map),
            "error_class" => emit_optional(out_key, summary.error_class.map(|c| c.as_str()), map),
            "disconnect_direction" => emit_optional(
                out_key,
                summary.disconnect_direction.map(direction_label),
                map,
            ),
            "disconnect_cause" => emit_optional(
                out_key,
                summary.disconnect_cause.map(disconnect_cause_label),
                map,
            ),
            "duration_ms" => map.serialize_entry(out_key, &summary.duration_ms),
            "bytes_sent" => map.serialize_entry(out_key, &summary.bytes_sent),
            "bytes_received" => map.serialize_entry(out_key, &summary.bytes_received),
            "timestamp_connected" => {
                emit_timestamp(out_key, &summary.timestamp_connected, ts_format, map)
            }
            "timestamp_disconnected" => {
                emit_timestamp(out_key, &summary.timestamp_disconnected, ts_format, map)
            }
            "sni_hostname" => emit_optional(out_key, summary.sni_hostname.as_deref(), map),
            "request_id" => emit_optional(
                out_key,
                selected_metadata_value(&summary.metadata, "request_id"),
                map,
            ),
            "trace_id" => emit_optional(
                out_key,
                selected_metadata_value(&summary.metadata, "trace_id"),
                map,
            ),
            "metadata" => map.serialize_entry(out_key, &MetadataNested(&summary.metadata)),
            _ => Ok(()),
        }
    }

    fn serialize_derived<S>(
        &self,
        kind: DerivedKind,
        out_key: &str,
        map: &mut S,
    ) -> Result<bool, S::Error>
    where
        S: SerializeMap,
    {
        match kind {
            DerivedKind::StatusClass => {
                map.serialize_entry(out_key, "none")?;
                Ok(true)
            }
            DerivedKind::BackendHost => match extract_host_from_url(&self.summary.backend_target) {
                Some(host) => {
                    map.serialize_entry(out_key, host)?;
                    Ok(true)
                }
                None => Ok(false),
            },
            DerivedKind::SummaryKind => {
                map.serialize_entry(out_key, "stream")?;
                Ok(true)
            }
            DerivedKind::Outcome => {
                let is_error = self.summary.connection_error.is_some()
                    || self.summary.error_class.is_some()
                    || matches!(
                        self.summary.disconnect_cause,
                        Some(DisconnectCause::BackendError)
                    );
                map.serialize_entry(out_key, if is_error { "error" } else { "ok" })?;
                Ok(true)
            }
        }
    }

    fn serialize_metadata<S>(
        &self,
        policy: &MetadataPolicy,
        emitted: &EmittedKeys<'_>,
        map: &mut S,
    ) -> Result<(), S::Error>
    where
        S: SerializeMap,
    {
        serialize_schema_metadata(&self.summary.metadata, policy, emitted, map)
    }
}

/// WebSocket-disconnect terminal diagnostic under a compiled schema.
pub(crate) struct DebugWsRecord<'a> {
    pub(crate) summary: &'a WsDisconnectContext,
    pub(crate) outcome: &'static str,
}

impl<'a> SchemaSerializable for DebugWsRecord<'a> {
    fn owns_native(&self, source: &str) -> bool {
        crate::plugins::utils::log_schema::DEBUG_WS_FIELDS
            .iter()
            .any(|f| f.name == source)
    }

    fn serialize_native<S>(
        &self,
        source: &'static str,
        out_key: &str,
        _ts_format: TimestampFormat,
        map: &mut S,
    ) -> Result<(), S::Error>
    where
        S: SerializeMap,
    {
        let summary = self.summary;
        match source {
            "outcome" => map.serialize_entry(out_key, self.outcome),
            "namespace" => map.serialize_entry(out_key, &summary.namespace),
            "proxy_id" => map.serialize_entry(out_key, &summary.proxy_id),
            "proxy_name" => emit_optional(out_key, summary.proxy_name.as_deref(), map),
            "client_ip" => map.serialize_entry(out_key, &summary.client_ip),
            "listen_port" => map.serialize_entry(out_key, &summary.listen_port),
            "backend_target" => map.serialize_entry(out_key, &summary.backend_target),
            "consumer_username" => {
                emit_optional(out_key, summary.consumer_username.as_deref(), map)
            }
            "auth_method" => emit_optional(out_key, summary.auth_method, map),
            "duration_ms" => map.serialize_entry(out_key, &summary.duration_ms),
            "frames_client_to_backend" => {
                map.serialize_entry(out_key, &summary.frames_client_to_backend)
            }
            "frames_backend_to_client" => {
                map.serialize_entry(out_key, &summary.frames_backend_to_client)
            }
            "bytes_client_to_backend" => {
                map.serialize_entry(out_key, &summary.bytes_client_to_backend)
            }
            "bytes_backend_to_client" => {
                map.serialize_entry(out_key, &summary.bytes_backend_to_client)
            }
            "disconnect_direction" => {
                emit_optional(out_key, summary.direction.map(direction_label), map)
            }
            "io_side" => emit_optional(out_key, summary.io_side.map(stream_io_side_label), map),
            "error_class" => emit_optional(out_key, summary.error_class.map(|c| c.as_str()), map),
            "request_id" => emit_optional(
                out_key,
                selected_metadata_value(&summary.metadata, "request_id"),
                map,
            ),
            "trace_id" => emit_optional(
                out_key,
                selected_metadata_value(&summary.metadata, "trace_id"),
                map,
            ),
            "metadata" => map.serialize_entry(out_key, &MetadataNested(&summary.metadata)),
            _ => Ok(()),
        }
    }

    fn serialize_derived<S>(
        &self,
        kind: DerivedKind,
        out_key: &str,
        map: &mut S,
    ) -> Result<bool, S::Error>
    where
        S: SerializeMap,
    {
        match kind {
            DerivedKind::StatusClass => {
                map.serialize_entry(out_key, "none")?;
                Ok(true)
            }
            DerivedKind::BackendHost => match extract_host_from_url(&self.summary.backend_target) {
                Some(host) => {
                    map.serialize_entry(out_key, host)?;
                    Ok(true)
                }
                None => Ok(false),
            },
            DerivedKind::SummaryKind => {
                map.serialize_entry(out_key, "websocket_disconnect")?;
                Ok(true)
            }
            DerivedKind::Outcome => {
                let is_error = self.summary.error_class.is_some();
                map.serialize_entry(out_key, if is_error { "error" } else { "ok" })?;
                Ok(true)
            }
        }
    }

    fn serialize_metadata<S>(
        &self,
        policy: &MetadataPolicy,
        emitted: &EmittedKeys<'_>,
        map: &mut S,
    ) -> Result<(), S::Error>
    where
        S: SerializeMap,
    {
        serialize_schema_metadata(&self.summary.metadata, policy, emitted, map)
    }
}

fn selected_metadata_value<'a, MS: std::hash::BuildHasher>(
    metadata: &'a HashMap<String, String, MS>,
    key: &str,
) -> Option<&'a str> {
    metadata.get(key).map(|value| {
        if metadata_value_is_redacted(key) {
            REDACTED_PLACEHOLDER
        } else {
            value.as_str()
        }
    })
}

const fn direction_label(direction: Direction) -> &'static str {
    match direction {
        Direction::ClientToBackend => "client_to_backend",
        Direction::BackendToClient => "backend_to_client",
        Direction::Unknown => "unknown",
    }
}

const fn disconnect_cause_label(cause: DisconnectCause) -> &'static str {
    match cause {
        DisconnectCause::IdleTimeout => "idle_timeout",
        DisconnectCause::RecvError => "recv_error",
        DisconnectCause::BackendError => "backend_error",
        DisconnectCause::GracefulShutdown => "graceful_shutdown",
        DisconnectCause::GatewayPolicy => "gateway_policy",
    }
}

const fn stream_io_side_label(side: StreamIoSide) -> &'static str {
    match side {
        StreamIoSide::Read => "read",
        StreamIoSide::Write => "write",
    }
}

/// Whether any capture record could actually be emitted right now.
///
/// Capture output exists only on the `transaction_debug` DEBUG target, so when
/// that target is not enabled there is no record for a buffered body to end up
/// in. The per-request buffering predicates consult this so eligible bodies are
/// released to streaming instead of being buffered for nothing. The config-level
/// `requires_*_body_buffering()` capability is deliberately left untouched: it
/// must keep describing what the configuration can ask for, independent of the
/// current log filter.
///
/// The admin log-level reloader can flip this between hooks. Both outcomes are
/// benign and stateless — either a body is buffered and no record is emitted, or
/// it streams and no record is emitted — so no cross-hook state is carried to
/// make the two agree.
fn capture_output_enabled() -> bool {
    tracing::enabled!(target: "transaction_debug", tracing::Level::DEBUG)
}

/// Case-insensitive header lookup that does not allocate.
fn header_value<'a>(headers: &'a HashMap<String, String>, name: &str) -> Option<&'a str> {
    headers
        .iter()
        .find(|(key, _)| key.eq_ignore_ascii_case(name))
        .map(|(_, value)| value.as_str())
}

/// Allocation-free ASCII-case-insensitive substring test. Used on the hot path
/// instead of lowercasing a whole header value to search inside it.
fn contains_ignore_ascii_case(haystack: &str, needle: &str) -> bool {
    let (haystack, needle) = (haystack.as_bytes(), needle.as_bytes());
    if needle.is_empty() {
        return true;
    }
    if haystack.len() < needle.len() {
        return false;
    }
    haystack
        .windows(needle.len())
        .any(|window| window.eq_ignore_ascii_case(needle))
}

fn ends_with_ignore_ascii_case(value: &str, suffix: &str) -> bool {
    match value.len().checked_sub(suffix.len()) {
        Some(start) => value.as_bytes()[start..].eq_ignore_ascii_case(suffix.as_bytes()),
        None => false,
    }
}

/// Media type without parameters, trimmed.
fn base_media_type(content_type: &str) -> &str {
    content_type
        .split(';')
        .next()
        .unwrap_or(content_type)
        .trim()
}

fn is_grpc_content_type(content_type: &str) -> bool {
    const GRPC: &str = "application/grpc";
    let base = base_media_type(content_type);
    match base.as_bytes().get(..GRPC.len()) {
        Some(prefix) => prefix.eq_ignore_ascii_case(GRPC.as_bytes()),
        None => false,
    }
}

/// Map a media type to the capturable body family, or `None` when the media
/// type is outside the debugger's safe-capture allow-list.
fn capturable_body_kind(content_type: &str) -> Option<BodyKind> {
    let base = base_media_type(content_type);
    if base.eq_ignore_ascii_case("application/json")
        || base.eq_ignore_ascii_case("text/json")
        || ends_with_ignore_ascii_case(base, "+json")
    {
        return Some(BodyKind::Json);
    }
    if base.eq_ignore_ascii_case("application/x-www-form-urlencoded") {
        return Some(BodyKind::Form);
    }
    // `text/plain` is the only unstructured family on the allow-list. XML and
    // GraphQL are deliberately excluded: their secrets live in structural
    // positions (element text, variable values) that line-level redaction
    // cannot reach, and Ferrum has no bounded structure-aware redactor for
    // either, so claiming a control here would be claiming one that cannot be
    // enforced.
    if base.eq_ignore_ascii_case("text/plain") {
        return Some(BodyKind::Text);
    }
    None
}

/// Shared request/response capture eligibility over a header map.
///
/// Every rejection keeps the message on its ordinary path: an unknown-length,
/// encoded, oversized, streaming, or non-textual message is never pinned onto
/// the buffered path just because the debugger is enabled. The one widening is
/// the explicit `capture_body_prefix` opt-in (`prefix`), which admits a
/// prefix-renderable family (`text/plain`, form) whose declared length exceeds
/// the cap but not [`MAX_PREFIX_SOURCE_BYTES`].
fn capture_decision(
    headers: &HashMap<String, String>,
    max_bytes: usize,
    prefix: bool,
) -> BodyCaptureDecision {
    let Some(content_type) = header_value(headers, "content-type") else {
        return BodyCaptureDecision::Skip("no_content_type");
    };
    if is_grpc_content_type(content_type)
        || base_media_type(content_type).eq_ignore_ascii_case("text/event-stream")
    {
        return BodyCaptureDecision::Skip("protocol_excluded");
    }
    let Some(kind) = capturable_body_kind(content_type) else {
        return BodyCaptureDecision::Skip("content_type_excluded");
    };
    if header_value(headers, "content-encoding")
        .is_some_and(|encoding| !encoding.trim().eq_ignore_ascii_case("identity"))
    {
        return BodyCaptureDecision::Skip("content_encoding");
    }
    let Some(declared_length) =
        header_value(headers, "content-length").and_then(|value| value.trim().parse::<u64>().ok())
    else {
        return BodyCaptureDecision::Skip("unknown_length");
    };
    if declared_length == 0 {
        return BodyCaptureDecision::Skip("empty_body");
    }
    if declared_length > max_bytes as u64 {
        if prefix && kind != BodyKind::Json && declared_length <= MAX_PREFIX_SOURCE_BYTES {
            return BodyCaptureDecision::Capture { kind, max_bytes };
        }
        return BodyCaptureDecision::Skip("over_capture_limit");
    }
    BodyCaptureDecision::Capture { kind, max_bytes }
}

/// Content-free rendering for a structured body that could not be parsed as the
/// structure it declared.
fn malformed_structured_body(kind: BodyKind, original_bytes: usize) -> CapturedBody {
    CapturedBody {
        state: "omitted",
        kind: kind.as_str(),
        original_bytes,
        truncated: false,
        rendered: BODY_MALFORMED_MARKER.to_string(),
    }
}

/// Truncate to at most `max_bytes` on a character boundary. Returns the slice
/// and whether anything was dropped.
fn truncate_on_char_boundary(text: &str, max_bytes: usize) -> (&str, bool) {
    if text.len() <= max_bytes {
        return (text, false);
    }
    let mut end = max_bytes;
    while end > 0 && !text.is_char_boundary(end) {
        end -= 1;
    }
    (&text[..end], true)
}

/// Bidirectional/invisible formatting characters that can spoof a log line.
const fn is_spoofing_control(ch: char) -> bool {
    matches!(
        ch,
        '\u{061C}'
            | '\u{200B}'..='\u{200F}'
            | '\u{2028}'..='\u{202E}'
            | '\u{2060}'
            | '\u{2066}'..='\u{2069}'
            | '\u{FEFF}'
    )
}

/// Escape control and bidi-spoofing characters and cap the rendered length.
///
/// One source character can expand into several output bytes, so the output is
/// additionally bounded by [`MAX_RENDERED_BODY_BYTES`]. The bound is exact on
/// every path: a segment is appended only when the *whole* encoded segment
/// still fits, so the ceiling can be reached but never overshot. Returns the
/// rendered string and whether the render ceiling truncated it.
fn escape_for_diagnostics(text: &str) -> (String, bool) {
    let mut out = String::with_capacity(text.len());
    let mut capped = false;
    let mut char_buf = [0u8; 4];
    let mut escape_buf = String::with_capacity(10);
    for ch in text.chars() {
        let segment: &str = match ch {
            '\n' => "\\n",
            '\r' => "\\r",
            '\t' => "\\t",
            '\\' => "\\\\",
            ch if ch.is_control() || is_spoofing_control(ch) => {
                escape_buf.clear();
                let _ = write!(escape_buf, "\\u{{{:04x}}}", ch as u32);
                escape_buf.as_str()
            }
            ch => ch.encode_utf8(&mut char_buf),
        };
        if out.len() + segment.len() > MAX_RENDERED_BODY_BYTES {
            capped = true;
            break;
        }
        out.push_str(segment);
    }
    (out, capped)
}

/// Whether a string value is credential-shaped regardless of the field name
/// that carried it: an HTTP auth scheme, a compact JWS/JWE token, a
/// well-known provider API key or AWS access key, or a PEM private key.
///
/// Every screen is a single linear pass over bounded input (a header value or
/// at most a capture-sized body), with no regex and no allocation.
fn looks_like_credential(value: &str) -> bool {
    let trimmed = value.trim();
    contains_ignore_ascii_case(trimmed, "bearer ")
        || contains_ignore_ascii_case(trimmed, "basic ")
        || contains_private_key_marker(trimmed)
        || contains_provider_secret(trimmed)
        || contains_compact_jose(trimmed)
}

/// A PEM private-key armor line (`-----BEGIN [RSA |EC |OPENSSH |ENCRYPTED |PGP ]PRIVATE KEY…`).
fn contains_private_key_marker(value: &str) -> bool {
    value.contains("-----") && contains_ignore_ascii_case(value, "PRIVATE KEY")
}

/// AWS access-key-id type prefixes; each is followed by 16 uppercase
/// alphanumerics.
const AWS_ACCESS_KEY_PREFIXES: &[&str] = &[
    "AKIA", "ASIA", "ABIA", "ACCA", "AGPA", "AIDA", "AIPA", "ANPA", "ANVA", "APKA", "AROA",
];

/// Well-known provider secret prefixes and the minimum token length at which a
/// prefixed token is treated as a credential.
const PROVIDER_SECRET_PREFIXES: &[(&str, usize)] = &[
    // GitHub classic and fine-grained tokens.
    ("ghp_", 40),
    ("gho_", 40),
    ("ghu_", 40),
    ("ghs_", 40),
    ("ghr_", 40),
    ("github_pat_", 40),
    // GitLab personal access tokens.
    ("glpat-", 26),
    // Slack bot/user/app/refresh tokens.
    ("xoxa-", 15),
    ("xoxb-", 15),
    ("xoxe-", 15),
    ("xoxp-", 15),
    ("xoxr-", 15),
    ("xoxs-", 15),
    // OpenAI / Anthropic style `sk-…` keys.
    ("sk-", 32),
    // Stripe secret and restricted keys.
    ("sk_live_", 24),
    ("sk_test_", 24),
    ("rk_live_", 24),
    ("rk_test_", 24),
    // Google API keys.
    ("AIza", 39),
    // npm access tokens.
    ("npm_", 40),
];

/// Whether `value` contains a token shaped like an AWS access key id or a
/// well-known provider API key. Tokens are maximal runs of
/// `[A-Za-z0-9_-]`, so a key embedded in a URL query, a JSON string, or prose
/// is still found, and a prefix inside a longer word (`task-…`) is not.
fn contains_provider_secret(value: &str) -> bool {
    value
        .split(|ch: char| !(ch.is_ascii_alphanumeric() || matches!(ch, '-' | '_')))
        .any(is_provider_secret_token)
}

fn is_provider_secret_token(token: &str) -> bool {
    let bytes = token.as_bytes();
    if bytes.len() == 20
        && AWS_ACCESS_KEY_PREFIXES
            .iter()
            .any(|prefix| token.starts_with(prefix))
        && bytes
            .iter()
            .skip(4)
            .all(|byte| byte.is_ascii_uppercase() || byte.is_ascii_digit())
    {
        return true;
    }
    PROVIDER_SECRET_PREFIXES
        .iter()
        .any(|(prefix, min_len)| bytes.len() >= *min_len && token.starts_with(prefix))
}

/// Whether `value` contains a compact JWS/JWE serialization.
///
/// Each maximal base64url/compact-token run is scanned once. Re-scanning the
/// full suffix per candidate would make an attacker-shaped captured value
/// quadratic even though the total capture is byte-bounded.
fn contains_compact_jose(value: &str) -> bool {
    value
        .split(|ch: char| !(ch.is_ascii_alphanumeric() || matches!(ch, '-' | '_' | '.' | '=')))
        .any(token_is_compact_jose)
}

fn token_is_compact_jose(token: &str) -> bool {
    // Fast path: the common `eyJ…` header (`{"` encoded) anywhere in the run,
    // followed by at least two dots.
    if let Some(start) = token.find("eyJ") {
        let candidate = &token[start..];
        if candidate.len() >= 20
            && candidate
                .bytes()
                .filter(|byte| *byte == b'.')
                .nth(1)
                .is_some()
        {
            return true;
        }
    }
    // Structural rule. RFC 7515 permits whitespace inside the JSON protected
    // header (`{ "alg": … }` encodes as `eyAi…`, `{\n…` as `ewo…`), so the
    // literal prefix alone misses valid tokens. Any segment followed by at
    // least two more `.`-separated segments whose base64url decoding opens a
    // JSON object (`{`, optional JSON whitespace, `"`) is a compact header.
    let total_dots = token.bytes().filter(|byte| *byte == b'.').count();
    if total_dots < 2 {
        return false;
    }
    for (index, segment) in token.split('.').enumerate() {
        if total_dots - index < 2 {
            break;
        }
        // The header may follow an `=` delimiter (`note=<token>` in text);
        // base64url padding `=` only ever trails a segment.
        let unpadded = segment.trim_end_matches('=');
        let header = unpadded.rsplit_once('=').map_or(unpadded, |(_, tail)| tail);
        if segment_decodes_to_json_object_start(header) {
            return true;
        }
    }
    false
}

/// The 6-bit value of one base64url character.
const fn base64url_sextet(byte: u8) -> Option<u8> {
    match byte {
        b'A'..=b'Z' => Some(byte - b'A'),
        b'a'..=b'z' => Some(byte - b'a' + 26),
        b'0'..=b'9' => Some(byte - b'0' + 52),
        b'-' => Some(62),
        b'_' => Some(63),
        _ => None,
    }
}

/// Whether a base64url segment decodes to the start of a JSON object: optional
/// JSON whitespace, `{`, optional JSON whitespace, `"`. Decodes at most
/// [`MAX_JOSE_HEADER_PREFIX_CHARS`] characters; a window that is exhausted
/// while still inside whitespace after `{` fails closed (treated as a header).
fn segment_decodes_to_json_object_start(segment: &str) -> bool {
    let bytes = segment.as_bytes();
    let window = &bytes[..bytes.len().min(MAX_JOSE_HEADER_PREFIX_CHARS)];
    let mut acc: u32 = 0;
    let mut bits: u32 = 0;
    let mut opened = false;
    for &byte in window {
        let Some(sextet) = base64url_sextet(byte) else {
            return false;
        };
        acc = (acc << 6) | u32::from(sextet);
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            let decoded = ((acc >> bits) & 0xFF) as u8;
            acc &= (1u32 << bits) - 1;
            match decoded {
                b' ' | b'\t' | b'\n' | b'\r' => {}
                b'{' if !opened => opened = true,
                b'"' if opened => return true,
                _ => return false,
            }
        }
    }
    opened && window.len() == MAX_JOSE_HEADER_PREFIX_CHARS
}

/// Deterministic per-request sample point for `capture_sample_rate`.
///
/// Derived from the request's receive timestamp and immediate peer address,
/// which every hook (and the final-body hook context clone) sees unchanged, so
/// the buffering predicates and both emission hooks agree. FNV-1a folded
/// through the splitmix64 finalizer for an even spread.
fn request_sample_point(ctx: &RequestContext) -> u64 {
    let seconds = ctx.timestamp_received.timestamp().to_le_bytes();
    let nanos = ctx
        .timestamp_received
        .timestamp_subsec_nanos()
        .to_le_bytes();
    let mut hash: u64 = 0xcbf2_9ce4_8422_2325;
    for byte in seconds
        .iter()
        .chain(nanos.iter())
        .chain(ctx.direct_client_ip.as_bytes())
    {
        hash ^= u64::from(*byte);
        hash = hash.wrapping_mul(0x0000_0100_0000_01b3);
    }
    hash ^= hash >> 30;
    hash = hash.wrapping_mul(0xbf58_476d_1ce4_e5b9);
    hash ^= hash >> 27;
    hash = hash.wrapping_mul(0x94d0_49bb_1331_11eb);
    hash ^ (hash >> 31)
}

/// Decode one `application/x-www-form-urlencoded` component for sensitivity
/// classification only. The rendered output keeps the original encoding.
fn decode_form_component(component: &str) -> String {
    let plus_decoded = component.replace('+', " ");
    percent_encoding::percent_decode_str(&plus_decoded)
        .decode_utf8_lossy()
        .into_owned()
}

fn optional_bool(config: &Value, field: &'static str) -> Result<Option<bool>, String> {
    match config.get(field) {
        None => Ok(None),
        Some(Value::Null) => Err(format!(
            "transaction_debugger: `{field}` must be a boolean; null is not allowed"
        )),
        Some(value) => value
            .as_bool()
            .map(Some)
            .ok_or_else(|| format!("transaction_debugger: `{field}` must be a boolean")),
    }
}

/// Parse `capture_sample_rate` (a number in `(0, 1]`) into the sample-point
/// threshold below which a request is captured. `None` selects every request.
fn optional_capture_sample_threshold(
    config: &Value,
    capture_enabled: bool,
) -> Result<Option<u64>, String> {
    const FIELD: &str = "capture_sample_rate";
    let rate = match config.get(FIELD) {
        None => return Ok(None),
        Some(Value::Null) => {
            return Err(format!(
                "transaction_debugger: `{FIELD}` must be a number; null is not allowed"
            ));
        }
        Some(value) => value
            .as_f64()
            .ok_or_else(|| format!("transaction_debugger: `{FIELD}` must be a number"))?,
    };
    if !capture_enabled {
        return Err(format!(
            "transaction_debugger: `{FIELD}` requires `log_request_body` or `log_response_body` to be true"
        ));
    }
    if !rate.is_finite() || rate <= 0.0 || rate > 1.0 {
        return Err(format!(
            "transaction_debugger: `{FIELD}` must be greater than 0 and at most 1"
        ));
    }
    if rate >= 1.0 {
        return Ok(None);
    }
    // `rate` is strictly inside (0, 1), so the product stays inside the u64
    // range; `as` saturates in any case.
    Ok(Some((rate * u64::MAX as f64) as u64))
}

/// Parse `capture_expires_at` (an RFC 3339 timestamp). A past instant is
/// accepted: stored configuration must keep loading after the window closes,
/// and capture is simply off for requests received from then on.
fn optional_capture_expiry(
    config: &Value,
    capture_enabled: bool,
) -> Result<Option<DateTime<Utc>>, String> {
    const FIELD: &str = "capture_expires_at";
    let raw = match config.get(FIELD) {
        None => return Ok(None),
        Some(Value::String(raw)) => raw,
        Some(Value::Null) => {
            return Err(format!(
                "transaction_debugger: `{FIELD}` must be an RFC 3339 timestamp; null is not allowed"
            ));
        }
        Some(_) => {
            return Err(format!(
                "transaction_debugger: `{FIELD}` must be an RFC 3339 timestamp string"
            ));
        }
    };
    if !capture_enabled {
        return Err(format!(
            "transaction_debugger: `{FIELD}` requires `log_request_body` or `log_response_body` to be true"
        ));
    }
    DateTime::parse_from_rfc3339(raw)
        .map(|instant| Some(instant.with_timezone(&Utc)))
        .map_err(|_| format!("transaction_debugger: `{FIELD}` must be an RFC 3339 timestamp"))
}

/// Parse `capture_request_header` into a lowercase header name.
fn optional_capture_header(
    config: &Value,
    capture_enabled: bool,
) -> Result<Option<String>, String> {
    const FIELD: &str = "capture_request_header";
    let raw = match config.get(FIELD) {
        None => return Ok(None),
        Some(Value::String(raw)) => raw,
        Some(Value::Null) => {
            return Err(format!(
                "transaction_debugger: `{FIELD}` must be a string; null is not allowed"
            ));
        }
        Some(_) => {
            return Err(format!("transaction_debugger: `{FIELD}` must be a string"));
        }
    };
    if !capture_enabled {
        return Err(format!(
            "transaction_debugger: `{FIELD}` requires `log_request_body` or `log_response_body` to be true"
        ));
    }
    if raw.is_empty() {
        return Err(format!("transaction_debugger: `{FIELD}` must not be empty"));
    }
    let lowered = raw.to_ascii_lowercase();
    let name = HeaderName::from_bytes(lowered.as_bytes())
        .map_err(|_| format!("transaction_debugger: `{FIELD}` is not a valid HTTP header name"))?;
    Ok(Some(name.as_str().to_string()))
}

/// Parse `capture_request_header_value`: 1–[`MAX_CAPTURE_SELECTOR_VALUE_BYTES`]
/// visible ASCII characters (inner spaces allowed) without surrounding
/// whitespace. The value is never echoed in an error.
fn optional_capture_header_value(
    config: &Value,
    header_configured: bool,
) -> Result<Option<String>, String> {
    const FIELD: &str = "capture_request_header_value";
    let raw = match config.get(FIELD) {
        None => return Ok(None),
        Some(Value::String(raw)) => raw,
        Some(Value::Null) => {
            return Err(format!(
                "transaction_debugger: `{FIELD}` must be a string; null is not allowed"
            ));
        }
        Some(_) => {
            return Err(format!("transaction_debugger: `{FIELD}` must be a string"));
        }
    };
    if !header_configured {
        return Err(format!(
            "transaction_debugger: `{FIELD}` requires `capture_request_header`"
        ));
    }
    let bytes = raw.as_bytes();
    let valid = !bytes.is_empty()
        && bytes.len() <= MAX_CAPTURE_SELECTOR_VALUE_BYTES
        && bytes.iter().all(|byte| (0x20..=0x7e).contains(byte))
        && bytes.first() != Some(&b' ')
        && bytes.last() != Some(&b' ');
    if !valid {
        return Err(format!(
            "transaction_debugger: `{FIELD}` must be 1-{MAX_CAPTURE_SELECTOR_VALUE_BYTES} visible ASCII characters without leading or trailing spaces"
        ));
    }
    Ok(Some(raw.clone()))
}

/// Parse a per-direction capture budget. Out-of-range values are rejected
/// rather than clamped so OpenAPI, docs, and runtime admission stay identical,
/// and a budget without its capture switch is rejected as inert configuration.
fn optional_capture_budget(
    config: &Value,
    field: &'static str,
    capture_enabled: bool,
) -> Result<usize, String> {
    let raw = match config.get(field) {
        None => return Ok(DEFAULT_BODY_CAPTURE_BYTES as usize),
        Some(Value::Null) => {
            return Err(format!(
                "transaction_debugger: `{field}` must be a positive integer; null is not allowed"
            ));
        }
        Some(value) => value
            .as_u64()
            .ok_or_else(|| format!("transaction_debugger: `{field}` must be a positive integer"))?,
    };
    let switch = if field == "max_request_body_bytes" {
        "log_request_body"
    } else {
        "log_response_body"
    };
    if !capture_enabled {
        return Err(format!(
            "transaction_debugger: `{field}` requires `{switch}` to be true"
        ));
    }
    if raw == 0 {
        return Err(format!(
            "transaction_debugger: `{field}` must be greater than zero"
        ));
    }
    if raw > MAX_BODY_CAPTURE_BYTES {
        return Err(format!(
            "transaction_debugger: `{field}` must be <= {MAX_BODY_CAPTURE_BYTES} (got \"{raw}\")"
        ));
    }
    Ok(raw as usize)
}

fn optional_body_field_names(
    config: &Value,
    field: &'static str,
) -> Result<Option<Vec<String>>, String> {
    let Some(value) = config.get(field) else {
        return Ok(None);
    };
    let Some(values) = value.as_array() else {
        return Err(format!("transaction_debugger: `{field}` must be an array"));
    };
    let mut names = Vec::with_capacity(values.len());
    for (idx, value) in values.iter().enumerate() {
        let Some(raw) = value.as_str() else {
            return Err(format!(
                "transaction_debugger: `{field}[{idx}]` must be a string"
            ));
        };
        let trimmed = raw.trim();
        if trimmed.is_empty() {
            return Err(format!(
                "transaction_debugger: `{field}[{idx}]` must not be empty"
            ));
        }
        if trimmed.chars().count() > 128 {
            return Err(format!(
                "transaction_debugger: `{field}[{idx}]` must be at most 128 characters"
            ));
        }
        names.push(trimmed.to_ascii_lowercase());
    }
    Ok(Some(names))
}

fn optional_header_names(
    config: &Value,
    field: &'static str,
) -> Result<Option<Vec<String>>, String> {
    let Some(value) = config.get(field) else {
        return Ok(None);
    };
    let Some(values) = value.as_array() else {
        return Err(format!("transaction_debugger: `{field}` must be an array"));
    };
    let mut headers = Vec::with_capacity(values.len());
    for (idx, value) in values.iter().enumerate() {
        let Some(raw) = value.as_str() else {
            return Err(format!(
                "transaction_debugger: `{field}[{idx}]` must be a string"
            ));
        };
        if raw.is_empty() {
            return Err(format!(
                "transaction_debugger: `{field}[{idx}]` must not be empty"
            ));
        }
        let raw = raw.to_ascii_lowercase();
        let name = HeaderName::from_bytes(raw.as_bytes()).map_err(|_| {
            format!("transaction_debugger: `{field}[{idx}]` is not a valid HTTP header name")
        })?;
        headers.push(name.as_str().to_string());
    }
    Ok(Some(headers))
}
