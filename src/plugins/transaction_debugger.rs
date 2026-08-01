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
//!   JWT-shaped) are replaced anywhere they appear. Structured families without
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
//!   is never confused with an empty one.
//!
//! No captured bytes are written into `ctx.metadata` or the transaction
//! summary: the sample exists only on the `transaction_debug` tracing target and
//! is not retained across hooks.

use async_trait::async_trait;
use http::header::HeaderName;
use serde::ser::SerializeMap;
use serde_json::Value;
use std::collections::{HashMap, HashSet};
use std::fmt::Write as _;
use std::sync::Arc;

use super::{
    Direction, DisconnectCause, Plugin, PluginResult, RequestContext, StreamTransactionSummary,
    TransactionSummary, WsDisconnectContext,
};
use crate::plugins::utils::log_schema::view::{
    MetadataNested, emit_timestamp, extract_host_from_url, serialize_schema_metadata, status_class,
};
use crate::plugins::utils::log_schema::{
    DerivedKind, MetadataPolicy, SchemaCapabilities, SchemaSerializable, SchemaView, SummarySchema,
    TimestampFormat, resolve_schema,
};
use crate::plugins::utils::metadata_redaction::{REDACTED_PLACEHOLDER, is_sensitive_metadata_key};
use crate::proxy::tcp_proxy::StreamIoSide;

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
    "log_request_body",
    "log_response_body",
    "max_request_body_bytes",
    "max_response_body_bytes",
    "redacted_body_fields",
    "redacted_headers",
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
    "auth", "code", "cookie", "jwt", "key", "otp", "pin", "pwd", "sig",
];

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

pub struct TransactionDebugger {
    /// Additional header names (lowercase) to redact beyond the built-in list.
    extra_redacted_headers: Vec<String>,
    /// Additional body field names (lowercase) to redact.
    redacted_body_fields: Vec<String>,
    log_request_body: bool,
    log_response_body: bool,
    max_request_body_bytes: usize,
    max_response_body_bytes: usize,
    /// Compiled terminal-diagnostic projection, resolved once at construction
    /// (inline `schema:` or global-first `schema_ref:`). `None` keeps the
    /// pre-existing `tracing` field emission byte-for-byte and allocation-free.
    schema: Option<Arc<SummarySchema>>,
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
                "transaction_debugger: unknown configuration keys: {}",
                unknown_keys.join(", ")
            ));
        }

        let extra_redacted_headers =
            optional_header_names(config, "redacted_headers")?.unwrap_or_default();

        let log_request_body = optional_bool(config, "log_request_body")?.unwrap_or(false);
        let log_response_body = optional_bool(config, "log_response_body")?.unwrap_or(false);
        let max_request_body_bytes =
            optional_capture_budget(config, "max_request_body_bytes", log_request_body)?;
        let max_response_body_bytes =
            optional_capture_budget(config, "max_response_body_bytes", log_response_body)?;

        let redacted_body_fields =
            optional_body_field_names(config, "redacted_body_fields")?.unwrap_or_default();
        if !redacted_body_fields.is_empty() && !(log_request_body || log_response_body) {
            return Err(
                "transaction_debugger: 'redacted_body_fields' requires 'log_request_body' or \
                 'log_response_body' to be true"
                    .to_string(),
            );
        }

        Ok(Self {
            extra_redacted_headers,
            redacted_body_fields,
            log_request_body,
            log_response_body,
            max_request_body_bytes,
            max_response_body_bytes,
            schema,
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

    /// Stable terminal classification derived from the final HTTP/gRPC summary.
    pub fn classify_http_outcome(summary: &TransactionSummary) -> &'static str {
        if summary.error_class.is_some() {
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
                Some(DisconnectCause::RecvError | DisconnectCause::BackendError)
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
                if self.is_sensitive(ctx, k) {
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
        capture_decision(headers, self.max_request_body_bytes)
    }

    /// Eligibility of the current response for a bounded body capture.
    pub fn response_body_capture_decision(
        &self,
        headers: &HashMap<String, String>,
    ) -> BodyCaptureDecision {
        if !self.log_response_body {
            return BodyCaptureDecision::Skip("disabled");
        }
        capture_decision(headers, self.max_response_body_bytes)
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
                    self.redact_json_value(&mut value, 0);
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
            || is_sensitive_metadata_key(&lowered)
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
            || is_sensitive_metadata_key(&lowered)
            || lowered.contains("bearer ")
            || lowered.contains("basic ")
            || lowered.contains("eyj")
    }

    fn redact_json_value(&self, value: &mut Value, depth: usize) {
        if depth > MAX_JSON_REDACTION_DEPTH {
            *value = Value::String(BODY_DEPTH_MARKER.to_string());
            return;
        }
        match value {
            Value::Object(map) => {
                for (key, entry) in map.iter_mut() {
                    if self.is_sensitive_body_key(key) {
                        *entry = Value::String(REDACTED.to_string());
                    } else {
                        self.redact_json_value(entry, depth + 1);
                    }
                }
            }
            Value::Array(items) => {
                for entry in items.iter_mut() {
                    self.redact_json_value(entry, depth + 1);
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
        for (index, line) in text.lines().enumerate() {
            if index >= MAX_TEXT_REDACTION_LINES {
                dropped = true;
                break;
            }
            if index > 0 {
                out.push('\n');
            }
            if self.line_is_sensitive(line) {
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
    fn capture_final_request_body(
        &self,
        ctx: Option<&RequestContext>,
        headers: &HashMap<String, String>,
        body: &[u8],
    ) -> PluginResult {
        if !self.log_request_body
            || !tracing::enabled!(target: "transaction_debug", tracing::Level::DEBUG)
        {
            return PluginResult::Continue;
        }
        let decision = self.request_body_capture_decision(headers);
        if let BodyCaptureDecision::Capture { kind, max_bytes } = decision {
            let method = ctx
                .map(|hook_ctx| hook_ctx.method.as_str())
                .or_else(|| header_value(headers, ":method"))
                .unwrap_or("-");
            let path = ctx
                .map(|hook_ctx| hook_ctx.path.as_str())
                .or_else(|| header_value(headers, ":path"))
                .unwrap_or("-");
            // `Content-Length` admitted this message, but the backend-visible
            // body is what actually gets walked. A stale/lying header or a
            // transform that grew the body must not widen the capture ceiling,
            // so fail closed before any UTF-8 scan, parse, or allocation.
            if body.len() > max_bytes {
                self.emit_body_capture(
                    "request",
                    method,
                    path,
                    BodyCaptureDecision::Skip("over_capture_limit"),
                    None,
                );
                return PluginResult::Continue;
            }
            // The declared length can overstate the message too, and there is
            // nothing to sample when it does. Report the same fixed
            // `empty_body` reason the header screen uses rather than handing an
            // empty slice to the renderer, where a structured family would
            // report it as a *malformed* body the peer never sent.
            if body.is_empty() {
                self.emit_body_capture(
                    "request",
                    method,
                    path,
                    BodyCaptureDecision::Skip("empty_body"),
                    None,
                );
                return PluginResult::Continue;
            }
            let sample = self.render_captured_body(body, kind, max_bytes);
            self.emit_body_capture("request", method, path, decision, Some(&sample));
        }
        PluginResult::Continue
    }

    /// Emit one capture record for a direction. `decision` describes what the
    /// buffering predicates concluded; `captured` is present only when the body
    /// was actually available.
    fn emit_body_capture(
        &self,
        direction: &'static str,
        method: &str,
        path: &str,
        decision: BodyCaptureDecision,
        captured: Option<&CapturedBody>,
    ) {
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
                .request_body_capture_decision(&ctx.headers)
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
            && tracing::enabled!(target: "transaction_debug", tracing::Level::DEBUG)
        {
            let decision = self.request_body_capture_decision(headers);
            if decision.skip_reason().is_some() {
                self.emit_body_capture("request", &ctx.method, &ctx.path, decision, None);
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
            if self.log_response_body {
                let decision = if self.request_shape_allows_response_capture(ctx) {
                    self.response_body_capture_decision(response_headers)
                } else {
                    BodyCaptureDecision::Skip("protocol_excluded")
                };
                if decision.skip_reason().is_some() {
                    self.emit_body_capture("response", &ctx.method, &ctx.path, decision, None);
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
        if !self.log_response_body
            || !tracing::enabled!(target: "transaction_debug", tracing::Level::DEBUG)
        {
            return PluginResult::Continue;
        }
        if !self.request_shape_allows_response_capture(ctx) {
            return PluginResult::Continue;
        }
        let decision = self.response_body_capture_decision(response_headers);
        if let BodyCaptureDecision::Capture { kind, max_bytes } = decision {
            // Same fail-closed rule as the request side: the client-visible
            // body, not the declared length, bounds the work done here.
            if body.len() > max_bytes {
                self.emit_body_capture(
                    "response",
                    &ctx.method,
                    &ctx.path,
                    BodyCaptureDecision::Skip("over_capture_limit"),
                    None,
                );
                return PluginResult::Continue;
            }
            // A `HEAD` or `304` response legitimately declares the length of a
            // body it does not send, so the actual client-visible slice is
            // empty even though the header screen admitted it. Report the fixed
            // `empty_body` reason instead of letting the structured renderer
            // call an absent body malformed.
            if body.is_empty() {
                self.emit_body_capture(
                    "response",
                    &ctx.method,
                    &ctx.path,
                    BodyCaptureDecision::Skip("empty_body"),
                    None,
                );
                return PluginResult::Continue;
            }
            let sample = self.render_captured_body(body, kind, max_bytes);
            self.emit_body_capture("response", &ctx.method, &ctx.path, decision, Some(&sample));
        }
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
        emitted: &mut HashSet<String>,
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
        emitted: &mut HashSet<String>,
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
        emitted: &mut HashSet<String>,
        map: &mut S,
    ) -> Result<(), S::Error>
    where
        S: SerializeMap,
    {
        serialize_schema_metadata(&self.summary.metadata, policy, emitted, map)
    }
}

fn selected_metadata_value<'a>(
    metadata: &'a HashMap<String, String>,
    key: &str,
) -> Option<&'a str> {
    metadata.get(key).map(|value| {
        if is_sensitive_metadata_key(key) {
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
/// the buffered path just because the debugger is enabled.
fn capture_decision(headers: &HashMap<String, String>, max_bytes: usize) -> BodyCaptureDecision {
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
/// that carried it.
fn looks_like_credential(value: &str) -> bool {
    let trimmed = value.trim();
    if contains_ignore_ascii_case(trimmed, "bearer ")
        || contains_ignore_ascii_case(trimmed, "basic ")
    {
        return true;
    }
    // JWT / JWS compact serialization: `eyJ…` header, at least two dots.
    //
    // Scan each maximal base64url/compact-token run once. Re-scanning the full
    // suffix for every `eyJ` occurrence would make an attacker-shaped captured
    // value quadratic even though the total capture is byte-bounded.
    trimmed
        .split(|ch: char| !(ch.is_ascii_alphanumeric() || matches!(ch, '-' | '_' | '.' | '=')))
        .any(|token| {
            let Some(start) = token.find("eyJ") else {
                return false;
            };
            let candidate = &token[start..];
            if candidate.len() < 20 {
                return false;
            }
            let mut dots = 0u8;
            for byte in candidate.bytes() {
                if byte == b'.' {
                    dots += 1;
                    if dots == 2 {
                        return true;
                    }
                }
            }
            false
        })
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
            "transaction_debugger: '{field}' must be a boolean; null is not allowed"
        )),
        Some(value) => value
            .as_bool()
            .map(Some)
            .ok_or_else(|| format!("transaction_debugger: '{field}' must be a boolean")),
    }
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
                "transaction_debugger: '{field}' must be a positive integer; null is not allowed"
            ));
        }
        Some(value) => value
            .as_u64()
            .ok_or_else(|| format!("transaction_debugger: '{field}' must be a positive integer"))?,
    };
    let switch = if field == "max_request_body_bytes" {
        "log_request_body"
    } else {
        "log_response_body"
    };
    if !capture_enabled {
        return Err(format!(
            "transaction_debugger: '{field}' requires '{switch}' to be true"
        ));
    }
    if raw == 0 {
        return Err(format!(
            "transaction_debugger: '{field}' must be greater than zero"
        ));
    }
    if raw > MAX_BODY_CAPTURE_BYTES {
        return Err(format!(
            "transaction_debugger: '{field}' must be <= {MAX_BODY_CAPTURE_BYTES} (got {raw})"
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
        return Err(format!("transaction_debugger: '{field}' must be an array"));
    };
    let mut names = Vec::with_capacity(values.len());
    for (idx, value) in values.iter().enumerate() {
        let Some(raw) = value.as_str() else {
            return Err(format!(
                "transaction_debugger: '{field}[{idx}]' must be a string"
            ));
        };
        let trimmed = raw.trim();
        if trimmed.is_empty() {
            return Err(format!(
                "transaction_debugger: '{field}[{idx}]' must not be empty"
            ));
        }
        if trimmed.chars().count() > 128 {
            return Err(format!(
                "transaction_debugger: '{field}[{idx}]' must be at most 128 characters"
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
        return Err(format!("transaction_debugger: '{field}' must be an array"));
    };
    let mut headers = Vec::with_capacity(values.len());
    for (idx, value) in values.iter().enumerate() {
        let Some(raw) = value.as_str() else {
            return Err(format!(
                "transaction_debugger: '{field}[{idx}]' must be a string"
            ));
        };
        if raw.is_empty() {
            return Err(format!(
                "transaction_debugger: '{field}[{idx}]' must not be empty"
            ));
        }
        let raw = raw.to_ascii_lowercase();
        let name = HeaderName::from_bytes(raw.as_bytes()).map_err(|_| {
            format!("transaction_debugger: '{field}[{idx}]' is not a valid HTTP header name")
        })?;
        headers.push(name.as_str().to_string());
    }
    Ok(Some(headers))
}
