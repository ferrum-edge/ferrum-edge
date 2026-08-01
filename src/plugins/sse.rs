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
//!    - Bounds `Last-Event-ID` for reconnection (treated as sensitive)
//!    - Rejects non-conforming requests with 405 (wrong method) or 406 (wrong Accept)
//!
//! 2. **`before_proxy`** — Shapes the request for the upstream backend:
//!    - Strips `Accept-Encoding` to prevent compressed chunked responses that
//!      break SSE framing (SSE relies on line-delimited text over chunked transfer)
//!    - Forwards `Last-Event-ID` as a header so the backend can resume the stream
//!
//! 3. **`after_proxy`** — Sets proper SSE response headers:
//!    - Conservatively merges `Cache-Control` with `no-cache` without weakening
//!      origin `private` / `no-store` / `no-transform` / extensions
//!    - Does **not** emit HTTP/1-only `Connection: keep-alive` (illegal on H2/H3;
//!      unnecessary on HTTP/1.1 persistent connections)
//!    - `X-Accel-Buffering: no` (disables nginx/ALB response buffering)
//!    - Strips `Content-Length` (SSE streams are indefinite)
//!    - Relabels non-SSE responses as `text/event-stream` when forcing and/or
//!      when wrapping will convert the body
//!
//! 4. **`transform_response_body`** — Optionally wraps non-SSE upstream
//!    responses into `data: ...\n\n` SSE event framing (buffered responses only),
//!    preserving terminal line-break semantics for EventSource `MessageEvent.data`.
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
//!
//! Unknown keys and non-object configs are rejected. Explicit JSON `null`
//! members are rejected (missing keys keep defaults). `wrap_non_sse_responses`
//! implies a client-visible `text/event-stream` media type for responses that
//! are wrapped.

use async_trait::async_trait;
use serde_json::{Map, Value};
use std::collections::HashMap;
use tracing::{debug, warn};

use super::utils::policy_digest;
use super::utils::sse::is_text_event_stream_media_type;
use super::{PluginResult, RequestContext};
use crate::util::http_headers::headers_have_cache_control_directive;
use crate::util::unknown_keys::reject_unknown_keys;

/// Request-scoped metadata key holding the raw `Last-Event-ID` for backend
/// forwarding. Stripped from transaction-log metadata; never interpolate into
/// diagnostics.
pub const LAST_EVENT_ID_METADATA_KEY: &str = "sse:last_event_id";

/// Request-scoped flag set by `after_proxy` when a non-SSE backend response
/// should be wrapped. Body transforms key off this rather than the (possibly
/// already relabeled) client-facing `Content-Type`.
const WRAP_NON_SSE_METADATA_KEY: &str = "sse:wrap_non_sse";

/// Request-scoped provenance marker set when an SSE plugin relabels an
/// originally non-SSE response. A later SSE instance must not mistake that
/// relabelled media type for a genuine upstream event stream and skip wrapping.
const RELABELLED_NON_SSE_METADATA_KEY: &str = "sse:relabeled_non_sse";

/// Maximum accepted `Last-Event-ID` byte length (hostile-input bound).
pub const MAX_LAST_EVENT_ID_BYTES: usize = 1024;

const SSE_CONFIG_KEYS: &[&str] = &[
    "require_accept_header",
    "require_get_method",
    "strip_accept_encoding",
    "add_no_buffering_header",
    "strip_content_length",
    "retry_ms",
    "force_sse_content_type",
    "wrap_non_sse_responses",
];

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
    /// Reconnection interval hint (ms). When set, stored in metadata.
    retry_ms_text: Option<String>,
    /// Pre-built `retry: <ms>\n` field used when wrapping responses.
    retry_field: Option<Vec<u8>>,
    /// Force `Content-Type: text/event-stream` even if the backend returns
    /// a different content type. Default: false.
    force_sse_content_type: bool,
    /// Wrap non-SSE response bodies in `data: ...\n\n` SSE event framing.
    /// Only applies to buffered responses. Implies client-visible
    /// `text/event-stream` for wrapped responses. Default: false.
    wrap_non_sse_responses: bool,

    /// Content-derived digest of this instance's whole accepted static config,
    /// used as replay provenance (see `response_presentation_policy`).
    ///
    /// Computed once at construction from the canonical form of the validated
    /// configuration, so it covers every present and future static knob without
    /// an enumeration that could silently fall behind a new field. Only the
    /// digest is ever exposed; the source config is not retained.
    static_policy_digest: [u8; 32],

    /// Canonical response-header field names this instance's `after_proxy`
    /// policy owns, precomputed at construction for
    /// `Plugin::response_trailer_policy`. Bounded by the four fields the
    /// response-shaping block can touch and never rebuilt per request.
    trailer_policy_names: Vec<String>,
}

/// Domain separator and schema version for [`SsePlugin`] replay provenance.
/// Bumping the version invalidates every previously persisted representation
/// rather than letting an old digest match new semantics.
const STATIC_POLICY_DIGEST_DOMAIN: &str = "ferrum.plugin.sse.static.v1";

impl SsePlugin {
    pub fn new(config: &Value) -> Result<Self, String> {
        let Some(config_obj) = config.as_object() else {
            return Err(format!(
                "sse: config must be an object, got: {}",
                value_kind(config)
            ));
        };
        reject_unknown_keys(config_obj, "config", SSE_CONFIG_KEYS, "sse: ")?;

        let require_accept_header = bool_config(config_obj, "require_accept_header", true)?;
        let require_get_method = bool_config(config_obj, "require_get_method", true)?;
        let strip_accept_encoding = bool_config(config_obj, "strip_accept_encoding", true)?;
        let add_no_buffering_header = bool_config(config_obj, "add_no_buffering_header", true)?;
        let strip_content_length = bool_config(config_obj, "strip_content_length", true)?;
        let retry_ms = optional_positive_u64_config(config_obj, "retry_ms")?;
        let force_sse_content_type = bool_config(config_obj, "force_sse_content_type", false)?;
        let wrap_non_sse_responses = bool_config(config_obj, "wrap_non_sse_responses", false)?;
        let retry_ms_text = retry_ms.map(|retry| retry.to_string());
        let retry_field = retry_ms_text.as_ref().map(|retry| {
            let mut field = Vec::with_capacity("retry: \n".len() + retry.len());
            field.extend_from_slice(b"retry: ");
            field.extend_from_slice(retry.as_bytes());
            field.push(b'\n');
            field
        });

        // Digest the accepted configuration as a whole. Every knob that shapes
        // the wrapped client representation (`wrap_non_sse_responses`,
        // `retry_ms`, `force_sse_content_type`) is in here by construction.
        let static_policy_digest =
            policy_digest::static_config_digest(STATIC_POLICY_DIGEST_DOMAIN, config);

        // Response-header fields this instance's `after_proxy` owns. Declared so
        // a protocol path that forwards backend TRAILERS cannot let the backend
        // re-open the decision after the fact. `content-length` is the load-
        // bearing case: `strip_content_length` removes it from the INITIAL map,
        // which is a no-op — and therefore invisible to observed-mutation
        // reconciliation — when the backend only ever sends the field as a
        // trailer, yet forwarding that trailer hands the client exactly the
        // indefinite-stream length this plugin exists to suppress.
        // `cache-control` and `x-accel-buffering` are gateway writes a trailer
        // copy would contradict; `content-type` is only owned when this instance
        // can actually relabel it.
        let mut trailer_policy_names = Vec::with_capacity(4);
        if force_sse_content_type || wrap_non_sse_responses {
            trailer_policy_names.push("content-type".to_string());
        }
        trailer_policy_names.push("cache-control".to_string());
        if add_no_buffering_header {
            trailer_policy_names.push("x-accel-buffering".to_string());
        }
        if strip_content_length {
            trailer_policy_names.push("content-length".to_string());
        }

        Ok(Self {
            require_accept_header,
            require_get_method,
            strip_accept_encoding,
            add_no_buffering_header,
            strip_content_length,
            retry_ms_text,
            retry_field,
            force_sse_content_type,
            wrap_non_sse_responses,
            static_policy_digest,
            trailer_policy_names,
        })
    }

    /// Returns true if the `Accept` header includes `text/event-stream`.
    fn accepts_event_stream(accept: &str) -> bool {
        accept
            .split(',')
            .any(|part| is_text_event_stream_media_type(part.trim()))
    }

    /// Returns true if the response `Content-Type` is `text/event-stream`.
    fn is_sse_content_type(content_type: &str) -> bool {
        is_text_event_stream_media_type(content_type.trim())
    }

    /// Wrap normalized text into one SSE event, preserving terminal newlines,
    /// inside a ceiling-bounded sink.
    ///
    /// `None` means the framed event would not fit the retained-response ceiling
    /// this response is being rewritten under; the refusal happens while the
    /// event is being written, so the oversized buffer is never allocated
    /// (GHSA-pwcm-6rh8-f2gh).
    ///
    /// Every byte is written THROUGH the sink: the lossy UTF-8 decode and the
    /// CR/CRLF normalization run incrementally over the input, so no complete
    /// `String` copy of the (attacker-chosen) body is ever materialised beside
    /// the bounded output. The observable framing is unchanged — see
    /// [`write_lossy_sse_data`] for the exact equivalence.
    fn wrap_body_as_sse_event(&self, body: &[u8], ceiling: usize) -> Option<Vec<u8>> {
        use crate::proxy::response_buffer_budget::BoundedResponseBodySink;
        let mut output = BoundedResponseBodySink::with_ceiling(ceiling);

        if let Some(retry_field) = &self.retry_field
            && !output.push(retry_field)
        {
            return None;
        }

        // Per the WHATWG EventSource algorithm, each `data:` field appends its
        // value plus LF to the data buffer, then dispatch removes exactly one
        // trailing LF. A payload that itself ends in LF therefore requires an
        // empty final `data:` field — which is exactly the empty final piece a
        // plain LF split yields, so the incremental writer below needs no
        // separate trailing-newline step. An EMPTY body is the one case where
        // the two differ (a split would still yield one empty piece), and it
        // must emit no `data:` field at all, matching `str::lines()`.
        if !body.is_empty() {
            if !output.push(SSE_DATA_FIELD_PREFIX) {
                return None;
            }
            if !write_lossy_sse_data(&mut output, body) {
                return None;
            }
            if !output.push(b"\n") {
                return None;
            }
        }
        // Blank line terminates the event.
        if !output.push(b"\n") {
            return None;
        }
        output.finish()
    }
}

/// The `data: ` field prefix each normalized line is emitted under.
const SSE_DATA_FIELD_PREFIX: &[u8] = b"data: ";

/// UTF-8 encoding of U+FFFD REPLACEMENT CHARACTER, the byte sequence
/// `String::from_utf8_lossy` substitutes for each maximal invalid subpart.
const UTF8_REPLACEMENT_CHARACTER: &[u8] = &[0xEF, 0xBF, 0xBD];

/// Write `body` into `output` as the values of one or more `data:` fields,
/// decoding lossily and normalizing line endings as it goes.
///
/// The caller has already written the first `data: ` prefix; this writes each
/// field value and, at every line break, the `\n` that closes the field plus the
/// `data: ` prefix that opens the next one. The caller writes the final `\n`.
///
/// Equivalence with the previous two-copy implementation
/// (`String::from_utf8_lossy(body).replace("\r\n", "\n").replace('\r', "\n")`
/// then `lines()`):
///
/// * lossy decoding substitutes one U+FFFD per maximal invalid subpart, which is
///   exactly `Utf8Error::error_len()` (and one for an incomplete trailing
///   sequence), so the decode is byte-identical;
/// * `\r\n` and a lone `\r` both collapse to a single `\n`. CR and LF are ASCII,
///   so a `\r\n` pair can never straddle a valid/invalid segment boundary: a
///   segment that ends in `\r` is followed by an invalid byte, which is a lone
///   CR under both implementations;
/// * splitting the normalized text on `\n` and emitting every piece — including
///   a trailing empty one — is `lines()` plus the explicit
///   "ends with newline ⇒ emit an empty `data:` field" step, for every non-empty
///   body. The caller special-cases the empty body.
///
/// No bare CR reaches the wire, so the field-injection boundary protection is
/// preserved.
fn write_lossy_sse_data(
    output: &mut crate::proxy::response_buffer_budget::BoundedResponseBodySink,
    body: &[u8],
) -> bool {
    let mut rest = body;
    loop {
        match std::str::from_utf8(rest) {
            Ok(valid) => return write_normalized_sse_text(output, valid.as_bytes()),
            Err(error) => {
                let (valid, invalid) = rest.split_at(error.valid_up_to());
                if !write_normalized_sse_text(output, valid) {
                    return false;
                }
                if !output.push(UTF8_REPLACEMENT_CHARACTER) {
                    return false;
                }
                match error.error_len() {
                    Some(len) => rest = &invalid[len..],
                    // An incomplete trailing sequence: one replacement
                    // character and nothing after it, as lossy decoding does.
                    None => return true,
                }
            }
        }
    }
}

/// Write one valid-UTF-8 run, closing and re-opening a `data:` field at each
/// `\r\n`, lone `\r`, or `\n`.
///
/// Operates on bytes: CR and LF are ASCII, and every continuation byte of a
/// multi-byte UTF-8 sequence is `>= 0x80`, so scanning for them cannot split a
/// character.
fn write_normalized_sse_text(
    output: &mut crate::proxy::response_buffer_budget::BoundedResponseBodySink,
    text: &[u8],
) -> bool {
    let mut start = 0;
    let mut index = 0;
    while index < text.len() {
        let byte = text[index];
        if byte != b'\r' && byte != b'\n' {
            index += 1;
            continue;
        }
        if !output.push(&text[start..index])
            || !output.push(b"\n")
            || !output.push(SSE_DATA_FIELD_PREFIX)
        {
            return false;
        }
        index += if byte == b'\r' && text.get(index + 1) == Some(&b'\n') {
            2
        } else {
            1
        };
        start = index;
    }
    output.push(&text[start..])
}

/// Remove SSE lifecycle/control metadata from operator-visible transaction logs
/// while preserving safe correlation hints. Raw `Last-Event-ID` must never reach
/// logging sinks. Correlation keys intentionally avoid the `last_event_id`
/// substring so default metadata redaction does not blank them.
pub fn redact_sse_log_metadata(metadata: &mut HashMap<String, String>) {
    if let Some(raw) = metadata.remove(LAST_EVENT_ID_METADATA_KEY) {
        metadata.insert("sse:leid_present".to_string(), "1".to_string());
        metadata.insert("sse:leid_bytes".to_string(), raw.len().to_string());
    }
    metadata.remove(WRAP_NON_SSE_METADATA_KEY);
    metadata.remove(RELABELLED_NON_SSE_METADATA_KEY);
}

fn value_kind(value: &Value) -> &'static str {
    match value {
        Value::Null => "null",
        Value::Bool(_) => "boolean",
        Value::Number(_) => "number",
        Value::String(_) => "string",
        Value::Array(_) => "array",
        Value::Object(_) => "object",
    }
}

fn bool_config(config: &Map<String, Value>, key: &str, default: bool) -> Result<bool, String> {
    match config.get(key) {
        None => Ok(default),
        Some(Value::Bool(value)) => Ok(*value),
        Some(other) => Err(format!(
            "sse: '{key}' must be a boolean, got: {}",
            value_kind(other)
        )),
    }
}

fn optional_positive_u64_config(
    config: &Map<String, Value>,
    key: &str,
) -> Result<Option<u64>, String> {
    match config.get(key) {
        None => Ok(None),
        Some(Value::Number(number)) => match number.as_u64() {
            Some(value) if value > 0 => Ok(Some(value)),
            Some(_) => Err(format!("sse: '{key}' must be greater than zero")),
            None => Err(format!(
                "sse: '{key}' must be an unsigned integer, got: {number}"
            )),
        },
        Some(other) => Err(format!(
            "sse: '{key}' must be an unsigned integer, got: {}",
            value_kind(other)
        )),
    }
}

/// Conservatively ensure SSE responses carry `no-cache` without weakening the
/// origin `Cache-Control` contract. Never replaces the existing field; only
/// appends `no-cache` when that directive name is not already present as a
/// top-level token (quoted-string interiors are skipped).
fn ensure_sse_cache_control(response_headers: &mut HashMap<String, String>) {
    if headers_have_cache_control_directive(response_headers, "no-cache") {
        // Preserve the origin value verbatim (duplicates, extensions,
        // private/no-store/no-transform, quoted forms, malformed tokens).
        return;
    }

    if let Some(existing) = response_headers
        .iter_mut()
        .find_map(|(name, value)| name.eq_ignore_ascii_case("cache-control").then_some(value))
    {
        if !existing.trim_end().is_empty() && !existing.trim_end().ends_with(',') {
            existing.push_str(", ");
        } else if !existing.is_empty() && !existing.ends_with(' ') {
            existing.push(' ');
        }
        existing.push_str("no-cache");
    } else {
        response_headers.insert("cache-control".to_string(), "no-cache".to_string());
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
        true
    }

    fn requires_response_body_buffering(&self) -> bool {
        self.wrap_non_sse_responses
    }

    /// SSE wrapping is a presentation policy a finalized replay skips, so this
    /// instance enrolls in replay provenance.
    ///
    /// `after_proxy` still runs on a replay and can relabel the response
    /// `Content-Type` to `text/event-stream`, but the wrapping body transform
    /// below is suppressed. A representation retained before
    /// `wrap_non_sse_responses` (or `retry_ms`) was configured would therefore
    /// be delivered unwrapped — or wrapped under superseded framing — while
    /// labelled as an event stream. Enrollment is unconditional, including for
    /// an instance that is not currently wrapping: whether wrapping is on is
    /// itself the policy a stored representation must be bound to, and a
    /// conditional contribution would make the per-proxy digest depend on live
    /// request state rather than static configuration.
    ///
    /// `Static` is accurate: the wrapped framing is a pure function of accepted
    /// configuration and the instance holds no interior mutable state.
    fn response_presentation_policy(&self) -> Option<super::ResponsePresentationPolicy> {
        Some(super::ResponsePresentationPolicy::Static(
            self.static_policy_digest,
        ))
    }

    fn should_buffer_response_body_for_content_type(
        &self,
        _ctx: &RequestContext,
        content_type: Option<&str>,
        response_status: u16,
        _response_headers: &HashMap<String, String>,
    ) -> bool {
        self.wrap_non_sse_responses
            && super::response_body_rewrite_allowed(response_status)
            && !content_type.is_some_and(Self::is_sse_content_type)
    }

    fn should_release_response_body_before_content_type_rewrite(
        &self,
        _ctx: &RequestContext,
        response_status: u16,
        _response_headers: &HashMap<String, String>,
    ) -> bool {
        self.wrap_non_sse_responses && !super::response_body_rewrite_allowed(response_status)
    }

    fn applies_after_proxy_on_reject(&self) -> bool {
        false
    }

    /// SSE response shaping binds the trailer section: `strip_content_length`
    /// is a REMOVAL that is a no-op on the initial header map whenever the
    /// backend sends `content-length` only as a trailer, so nothing in the
    /// observed-mutation witness can see it, and forwarding that trailer would
    /// hand the client the exact bounded length the plugin removed. The
    /// gateway's `cache-control` / `x-accel-buffering` / relabeled
    /// `content-type` writes are declared for the mirror-image reason: a trailer
    /// copy would leave the client holding two conflicting values for a field
    /// the gateway owns, and an idempotent write (backend already sent the same
    /// value) is invisible to the witness too.
    fn response_trailer_policy(&self) -> super::ResponseTrailerPolicy<'_> {
        super::ResponseTrailerPolicy::Names(&self.trailer_policy_names)
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

        // Stash Last-Event-ID for backend forwarding only. The value is
        // origin-defined opaque UTF-8 and is treated as sensitive: never
        // interpolate it into diagnostics, and omit/redact it from transaction
        // logs (see `redact_sse_log_metadata` + metadata redaction defaults).
        if let Some(last_id) = ctx.headers.get("last-event-id") {
            if last_id.len() > MAX_LAST_EVENT_ID_BYTES {
                warn!(
                    plugin = "sse",
                    last_event_id_len = last_id.len(),
                    max_bytes = MAX_LAST_EVENT_ID_BYTES,
                    "SSE request rejected: Last-Event-ID exceeds maximum length"
                );
                return PluginResult::Reject {
                    status_code: 400,
                    body: r#"{"error":"Last-Event-ID exceeds maximum length"}"#.to_string(),
                    headers: HashMap::new(),
                };
            }
            ctx.metadata
                .insert(LAST_EVENT_ID_METADATA_KEY.to_string(), last_id.clone());
            debug!(
                plugin = "sse",
                last_event_id_len = last_id.len(),
                "SSE reconnection with Last-Event-ID"
            );
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
        if let Some(last_id) = ctx.metadata.get(LAST_EVENT_ID_METADATA_KEY) {
            headers
                .entry("last-event-id".to_string())
                .or_insert_with(|| last_id.clone());
        }

        debug!(plugin = "sse", "SSE request shaped for backend");
        PluginResult::Continue
    }

    // ── Phase 3: Set SSE response headers ────────────────────────────────

    fn may_modify_response_content_type(
        &self,
        _ctx: &RequestContext,
        response_content_type: Option<&str>,
    ) -> bool {
        // `after_proxy` rewrites the response `Content-Type` to
        // `text/event-stream` when forcing OR when wrapping a non-SSE body.
        // Mirror that condition so the proxy's buffer/stream downgrade keys off
        // the final client-visible type.
        (self.force_sse_content_type || self.wrap_non_sse_responses)
            && !response_content_type.is_some_and(Self::is_sse_content_type)
    }

    async fn after_proxy(
        &self,
        ctx: &mut RequestContext,
        response_status: u16,
        response_headers: &mut HashMap<String, String>,
    ) -> PluginResult {
        let is_sse = response_headers
            .get("content-type")
            .is_some_and(|ct| Self::is_sse_content_type(ct));
        let was_relabelled_non_sse = ctx
            .metadata
            .get(RELABELLED_NON_SSE_METADATA_KEY)
            .is_some_and(|value| value == "1");
        let origin_was_sse = is_sse && !was_relabelled_non_sse;

        // For a non-SSE backend response, wrapping/forcing depends on the
        // configured body wrapper running. Preserved 206/226 bytes cannot be
        // wrapped, so do not relabel them as an SSE event stream.
        let wrap_allowed =
            self.wrap_non_sse_responses && super::response_body_rewrite_allowed(response_status);
        if !origin_was_sse && self.wrap_non_sse_responses && !wrap_allowed {
            return PluginResult::Continue;
        }

        let will_wrap = !origin_was_sse && wrap_allowed;
        let will_force = !is_sse && self.force_sse_content_type;

        // If the backend didn't return SSE and we're neither wrapping nor
        // forcing, nothing to do.
        if !is_sse && !will_wrap && !will_force {
            return PluginResult::Continue;
        }

        if will_wrap {
            // Coordinate body wrapping with the original backend type even after
            // we relabel the client-facing Content-Type below.
            ctx.metadata
                .insert(WRAP_NON_SSE_METADATA_KEY.to_string(), "1".to_string());
        }

        if !is_sse && (will_wrap || will_force) {
            ctx.metadata
                .insert(RELABELLED_NON_SSE_METADATA_KEY.to_string(), "1".to_string());
        }

        // Wrapping implies a browser-consumable EventSource media type.
        // Force alone also relabels. Genuine upstream SSE keeps its type.
        if (will_wrap || will_force) && !is_sse {
            response_headers.insert("content-type".to_string(), "text/event-stream".to_string());
            debug!(plugin = "sse", "set Content-Type to text/event-stream");
        }

        // Conservatively merge Cache-Control: add no-cache without removing
        // private / no-store / no-transform / extensions / duplicates.
        ensure_sse_cache_control(response_headers);

        // Do not emit `Connection: keep-alive`. Connection-specific fields are
        // forbidden on HTTP/2 and HTTP/3 (RFC 9113 §8.6 / RFC 9114 §4.2), and
        // HTTP/1.1 persistence does not require an explicit keep-alive token.

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
        if let Some(retry) = &self.retry_ms_text {
            ctx.metadata
                .insert("sse:retry_ms".to_string(), retry.clone());
        }

        debug!(plugin = "sse", "SSE response headers applied");
        PluginResult::Continue
    }

    // ── Phase 4: Optionally wrap non-SSE body into SSE framing ───────────

    async fn transform_response_body_with_context(
        &self,
        ctx: &mut RequestContext,
        body: &[u8],
        content_type: Option<&str>,
        _response_headers: &HashMap<String, String>,
    ) -> crate::plugins::ResponseBodyTransformOutcome {
        use crate::plugins::ResponseBodyTransformOutcome;

        if !self.wrap_non_sse_responses || body.is_empty() {
            return ResponseBodyTransformOutcome::Unchanged;
        }

        // This is a one-shot request decision. Multiple `sse` instances can
        // run on one proxy; only the first configured wrapper may consume the
        // original non-SSE body. Leaving the shared marker in metadata would
        // make every later instance wrap the already-framed event again.
        let wrap_requested = ctx
            .metadata
            .remove(WRAP_NON_SSE_METADATA_KEY)
            .is_some_and(|v| v == "1");
        if wrap_requested {
            ctx.metadata.remove(RELABELLED_NON_SSE_METADATA_KEY);
        }

        // Don't double-wrap a genuine upstream SSE response. When after_proxy
        // already decided to wrap (and may have relabeled Content-Type), honor
        // that request-scoped decision instead of the mutated media type.
        // Direct callers without after_proxy still wrap only when the supplied
        // type is not already SSE.
        if !wrap_requested && content_type.is_some_and(Self::is_sse_content_type) {
            return ResponseBodyTransformOutcome::Unchanged;
        }

        // Built inside a sink sized to this response's retained ceiling, so an
        // event that would exceed it is refused during construction rather than
        // allocated and rejected afterwards (GHSA-pwcm-6rh8-f2gh). Optional SSE
        // wrapping leaves the original body in place on refusal — it is not a
        // security policy rewrite.
        let Some(output) =
            self.wrap_body_as_sse_event(body, ctx.retained_response_body_ceiling())
        else {
            return ResponseBodyTransformOutcome::Unchanged;
        };
        debug!(
            plugin = "sse",
            original_bytes = body.len(),
            wrapped_bytes = output.len(),
            "wrapped response into SSE event"
        );
        ResponseBodyTransformOutcome::Replaced(output)
    }

    async fn transform_response_body(
        &self,
        body: &[u8],
        content_type: Option<&str>,
        response_headers: &HashMap<String, String>,
    ) -> crate::plugins::ResponseBodyTransformOutcome {
        // Fallback when no request context is available (legacy callers).
        let mut ctx =
            RequestContext::new("0.0.0.0".to_string(), "GET".to_string(), "/".to_string());
        self.transform_response_body_with_context(&mut ctx, body, content_type, response_headers)
            .await
    }
}
