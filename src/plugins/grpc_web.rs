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
//! Message-format suffixes (`+proto`, `+json`, `+thrift`, or another supported
//! custom `+subtype`) are preserved on the negotiated response `Content-Type`.
//!
//! ## Request path (gRPC-Web → native gRPC)
//!
//! 1. Detect `application/grpc-web*` content-type
//! 2. Negotiate the response media type from `Accept` (see below)
//! 3. Rewrite content-type to `application/grpc` for the backend
//! 4. Text mode: base64-decode the request body
//! 5. Split a terminal body trailer frame (`0x80`) off the message frames,
//!    validate it, and stage it for conversion into native HTTP/2 request
//!    trailers at the end of the backend-bound body (see
//!    [`split_request_trailer_frame`])
//!
//! ## Response path (native gRPC → gRPC-Web)
//!
//! 1. Forward backend response DATA incrementally
//! 2. Embed gRPC trailers (`grpc-status`, `grpc-message`, binary `*-bin`
//!    metadata, and valid ASCII custom trailing metadata) as exactly one final
//!    length-prefixed trailer DATA frame (flag byte 0x80). Hop-by-hop,
//!    forbidden, pseudo, connection-listed, and invalid names/values are
//!    excluded; only backend-trailer provenance (when recorded) is embedded
//! 3. Text mode: base64-encode each runtime flush independently
//! 4. Rewrite response content-type to the **negotiated** gRPC-Web variant
//!
//! ## Response media-type negotiation
//!
//! Request-body decoding follows request `Content-Type`. Response encoding and
//! the client-visible response `Content-Type` follow `Accept` negotiation
//! ([PROTOCOL-WEB.md](https://github.com/grpc/grpc/blob/master/doc/PROTOCOL-WEB.md)):
//!
//! - Absent or empty `Accept` defaults to the request `Content-Type`'s mode and
//!   message-format suffix (binary vs text, including `+proto` / `+json` / …).
//! - Lists, parameters, quality values (`q=`), and wildcards (`*/*`,
//!   `application/*`) are honored with specificity and explicit-over-wildcard
//!   rules matching RFC 9110 content negotiation.
//! - A present `Accept` that is structurally malformed, or that refuses every
//!   gRPC-Web representation the gateway can produce, fails closed with HTTP
//!   `406 Not Acceptable`.
//!
//! When the backend (or an intermediary) returns a response without a present,
//! numeric `grpc-status`, the trailer frame synthesizes status from the official
//! HTTP-to-gRPC client mapping
//! (<https://github.com/grpc/grpc/blob/master/doc/http-grpc-status-mapping.md>).
//! A valid supplied `grpc-status` remains authoritative. The client-visible HTTP
//! status is left unchanged — Ferrum does not rewrite it to 200 on this path —
//! so intermediaries that inspect the wire status still see the backend/HTTP
//! failure while gRPC-Web clients read the mapped code from the body trailer.
//!
//! ## Configuration
//!
//! Config must be a JSON object. Explicit `null`, arrays, scalars, and booleans
//! are rejected (`grpc_web: config must be an object`). Unknown object keys are
//! rejected with path-qualified diagnostics (and spelling suggestions when the
//! typo is close). Empty `{}` is valid and uses defaults.
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
//!
//! ## Multiple instances
//!
//! Several `grpc_web` configs may be attached to one proxy (for example two
//! proxy-scoped instances that replace a shadowed global, or distinct
//! `priority_override` values). Request/response body translation is
//! non-idempotent, so the first effective instance in configured order claims
//! ownership and performs detection, text decode, content-type rewrite, and
//! trailer-frame / base64 body translation exactly once. Sibling instances keep
//! namespaced per-instance staging and contribute only their `expose_headers`
//! union. Shared request staging is owner-scoped so instances cannot collide or
//! overwrite each other's translation state. Reload snapshots remain atomic:
//! an in-flight request sees one plugin generation end-to-end.

use async_trait::async_trait;
use base64::Engine;
use base64::engine::general_purpose::STANDARD as BASE64;
use bytes::Bytes;
use http::header::HeaderName;
use serde_json::Value;
use std::collections::{BTreeMap, HashMap, HashSet};
use std::sync::atomic::{AtomicU64, Ordering};
use tracing::debug;

use crate::proxy::headers::{
    is_backend_response_strip_header, is_proxy_owned_forwarding_header,
    parse_connection_listed_from_str_map,
};
use crate::util::unknown_keys::reject_unknown_keys;

use super::{
    BufferedInitialResponseHeaderPolicyState, HTTP_GRPC_PROTOCOLS, Plugin, PluginResult,
    ProxyProtocol, RequestContext,
};

/// Authoritative top-level keys accepted by [`GrpcWebPlugin::new`].
pub const GRPC_WEB_CONFIG_KEYS: &[&str] = &["expose_headers"];

/// Process-wide counter so each constructed `grpc_web` instance gets a unique
/// id for namespaced request staging and translation ownership.
static INSTANCE_ID_COUNTER: AtomicU64 = AtomicU64::new(1);

/// Metadata key storing the original gRPC-Web mode ("text" or "binary").
/// Written once by the translation owner; read by proxy/H3 dispatch helpers.
const META_GRPC_WEB_MODE: &str = "grpc_web_mode";
/// Metadata key storing the negotiated gRPC-Web response content-type.
pub(crate) const META_GRPC_WEB_ORIGINAL_CT: &str = "grpc_web_original_ct";
/// Metadata key storing the backend HTTP status observed in `after_proxy`.
///
/// `transform_response_body` cannot see response status directly, so the
/// status is stashed here for HTTP→gRPC trailer synthesis when `grpc-status`
/// is absent. Written only by the translation owner.
pub(crate) const META_GRPC_WEB_HTTP_STATUS: &str = "grpc_web_http_status";
/// Metadata marker for this plugin's own failed Accept negotiation. Frontend
/// classification may already have retained the request representation for
/// unrelated early errors; this marker prevents later response hooks from
/// turning the intentional HTTP 406 into a gRPC-Web response.
const META_GRPC_WEB_ACCEPT_REJECTED: &str = "grpc_web_accept_rejected";
/// Gateway-internal response marker carried only on the plugin's own Accept
/// negotiation rejection. The shared rejection normalizer consumes it to keep
/// this protocol-level failure as HTTP 406 instead of translating it into an
/// HTTP-200 gRPC status response.
pub(crate) const HEADER_GRPC_WEB_ACCEPT_REJECTED: &str = "x-ferrum-grpc-web-accept-rejected";
/// Metadata key listing backend trailer names (newline-separated, sorted) that
/// may be embedded in the gRPC-Web body trailer frame.
///
/// Present (including empty) only when proxy core recorded trailer provenance
/// for a translated request. Absent in unit-level helpers and gateway-authored
/// error builders that construct the trailer map explicitly. When present, the
/// frame encoder embeds only those names plus reserved gRPC terminal metadata
/// — never indiscriminately copying initial response headers from the merged
/// plugin view.
const META_GRPC_WEB_TRAILER_NAMES: &str = "grpc_web_trailer_names";
/// Base64-encoded JSON map of trailer names that were also present in the
/// backend's initial headers. Each entry stores `[initial_value, trailer_value]`
/// so the body-frame encoder can retain the true trailer value without
/// bypassing a response hook that rewrote or removed the merged view.
const META_GRPC_WEB_SHADOWED_TRAILERS: &str = "grpc_web_shadowed_trailers";
/// Internal response-header bridge for trailer-name provenance on dispatch
/// paths that only hold `&RequestContext` (sidecar mesh-mTLS). `after_proxy`
/// promotes this into [`META_GRPC_WEB_TRAILER_NAMES`] and strips it before the
/// client-visible header map is finalized.
pub(crate) const HEADER_GRPC_WEB_TRAILER_NAMES: &str = "x-ferrum-grpc-web-trailer-names";
/// Internal response-header bridge for [`META_GRPC_WEB_SHADOWED_TRAILERS`].
/// The payload is base64 so arbitrary printable trailer metadata never becomes
/// header syntax while it crosses the sidecar mesh-mTLS dispatch boundary.
pub(crate) const HEADER_GRPC_WEB_SHADOWED_TRAILERS: &str = "x-ferrum-grpc-web-shadowed-trailers";

/// Response fields `after_proxy` owns, in the bounded form
/// `Plugin::response_trailer_policy` hands to the plugin cache. Built once per
/// process; never allocated per request.
///
/// The two internal bridge names lead: `after_proxy` REMOVES them from the
/// initial map precisely so gateway trailer provenance never reaches a client,
/// and that removal is a no-op — invisible to observed-mutation reconciliation —
/// when a backend supplies the same name as a TRAILER instead.
static GRPC_WEB_RESPONSE_POLICY_NAMES: std::sync::LazyLock<Vec<String>> =
    std::sync::LazyLock::new(|| {
        vec![
            HEADER_GRPC_WEB_TRAILER_NAMES.to_string(),
            HEADER_GRPC_WEB_SHADOWED_TRAILERS.to_string(),
            "content-type".to_string(),
            "x-grpc-web".to_string(),
            "vary".to_string(),
            "access-control-expose-headers".to_string(),
        ]
    });

/// Ferrum-owned gRPC-Web bridge headers that must never reach a client.
#[inline]
pub(crate) fn is_internal_grpc_web_bridge_header(name: &str) -> bool {
    name.eq_ignore_ascii_case(HEADER_GRPC_WEB_TRAILER_NAMES)
        || name.eq_ignore_ascii_case(HEADER_GRPC_WEB_SHADOWED_TRAILERS)
        || name.eq_ignore_ascii_case(HEADER_GRPC_WEB_ACCEPT_REJECTED)
}

/// True when reject headers carry the Accept-negotiation failure marker.
///
/// Callers on H1/H2/H3 must keep that rejection as HTTP `406` JSON rather than
/// rewriting it into an HTTP-200 gRPC / gRPC-Web status response.
#[inline]
pub(crate) fn reject_headers_mark_accept_not_acceptable(
    headers: &std::collections::HashMap<String, String>,
) -> bool {
    headers
        .keys()
        .any(|name| name.eq_ignore_ascii_case(HEADER_GRPC_WEB_ACCEPT_REJECTED))
}

/// Instance id (decimal) of the `grpc_web` instance that claimed translation
/// for this request. Present only after a successful `on_request_received`
/// claim — never inferred from plugin-writable client input.
const META_GRPC_WEB_OWNER: &str = "grpc_web.owner";
/// Set after the owner performed request-body translation once: text-mode
/// base64 decode, terminal trailer-frame split, or both. Also set when the
/// trailer frame was rejected, so a second pass cannot re-run the parse and
/// overwrite the staged diagnostic.
const META_GRPC_WEB_REQUEST_DECODED: &str = "grpc_web.request_decoded";
/// Base64-encoded JSON array of `[name, value]` request trailer pairs split
/// off the request body by the translation owner. Consumed by the gRPC
/// dispatch paths via [`staged_request_trailers`], which re-validates every
/// entry (`ctx.metadata` is plugin-writable, so being present is not proof of
/// provenance).
const META_GRPC_WEB_REQUEST_TRAILERS: &str = "grpc_web.request_trailers";
/// Diagnostic recorded when the request trailer frame failed validation.
/// `transform_request_body_with_context` cannot reject, so the owner's
/// `on_final_request_body_with_context` reads this and fails the request
/// closed with the field-specific message before backend dispatch.
const META_GRPC_WEB_REQUEST_TRAILER_ERROR: &str = "grpc_web.request_trailer_error";
/// Set after the owner appends the trailer frame (and base64-encodes in text
/// mode) once. Prevents sibling instances from re-framing the body.
const META_GRPC_WEB_RESPONSE_TRANSLATED: &str = "grpc_web.response_translated";
/// Prefix for per-instance namespaced staging keys:
/// `grpc_web.instance.{id}.mode`.
const INSTANCE_META_PREFIX: &str = "grpc_web.instance.";

/// Internal proxy header injected by the translation owner's `before_proxy` so
/// the legacy `transform_request_body` path (no request context) can identify
/// text vs binary mode. Production buffering uses
/// [`Plugin::transform_request_body_with_context`], which reads owner-scoped
/// metadata instead of this shared header. Always stripped on ingress so a
/// client cannot spoof it; hop-by-hop removal also drops it before the backend.
const HEADER_GRPC_WEB_MODE: &str = "x-grpc-web-mode";
const APPLICATION_GRPC_WEB: &str = "application/grpc-web";
const APPLICATION_GRPC_WEB_TEXT: &str = "application/grpc-web-text";
const BASE_EXPOSE_HEADERS: [&str; 3] = ["grpc-status", "grpc-message", "grpc-status-details-bin"];
/// The gRPC-Web expose list every generated error representation must carry, so
/// a browser can read the terminal metadata out of the body trailer frame.
/// Authoritative in `finalize_grpc_web_error_response_headers`, which seeds the
/// merge from this constant rather than from whatever ended up in the header map.
pub(crate) const BASE_EXPOSE_HEADERS_VALUE: &str =
    "grpc-status, grpc-message, grpc-status-details-bin";

/// gRPC frame flag: data frame.
pub(crate) const GRPC_FRAME_DATA: u8 = 0x00;
/// gRPC frame flag: trailer frame (used in gRPC-Web to embed trailers in body).
pub(crate) const GRPC_FRAME_TRAILER: u8 = 0x80;
/// gRPC frame flag: data frame whose payload carries a per-message content
/// coding (the wire spec's `Compressed-Flag` set to 1).
pub(crate) const GRPC_FRAME_DATA_COMPRESSED: u8 = 0x01;
/// gRPC frame flag: gRPC-Web trailer frame with `Compressed-Flag` set.
pub(crate) const GRPC_FRAME_TRAILER_COMPRESSED: u8 = 0x81;

/// Which framing grammar a buffered response body is allowed to use.
///
/// The three gRPC representations are NOT interchangeable on the wire, and the
/// buffered representation gate has to judge a body against the one the client
/// is actually being served rather than against their union:
///
/// * **Native gRPC** (`application/grpc`) carries only DATA frames in the body.
///   Terminal metadata rides in HTTP trailers, so a `0x80`/`0x81` trailer frame
///   in the body is not native gRPC — accepting one lets a non-RPC byte string
///   masquerade as framing and skip the fail-closed rejection.
/// * **gRPC-Web binary** may embed exactly one terminal trailer frame, and the
///   protocol places it LAST. A trailer followed by more data is malformed.
/// * **gRPC-Web text** is the base64 encoding of the binary grammar above. Only
///   a text-mode client receives base64, so base64 is a legal body ONLY there;
///   treating it as framing on a native or binary request is what let a
///   base64-of-frames payload bypass the `unparseable_document` rejection.
///
/// The gating is one-directional by design. Text mode accepts base64 framing OR
/// the binary framing it encodes, because the retained text marker records the
/// CLIENT's representation and does not by itself prove the backend answered in
/// it — an H3 pass-through deployment retains the marker for error shaping while
/// dispatching natively, so its buffered body can legitimately still be raw
/// frames at gate time. Accepting the encoded form there costs nothing (framing
/// is not a document any field rule could redact) while refusing it would turn
/// valid RPC replies into `502`s. Native and binary mode, by contrast, have no
/// path on which base64 is a body they could ever serve, so base64 there stays
/// an unprovable representation and fails closed.
///
/// Chosen from immutable request state by
/// [`client_grpc_framing_representation`], never from a rewritable header.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum GrpcFramingRepresentation {
    /// `application/grpc`: DATA frames only, trailers on the wire.
    Native,
    /// `application/grpc-web*`: DATA frames plus an optional final trailer frame.
    WebBinary,
    /// `application/grpc-web-text*`: base64 of the [`Self::WebBinary`] grammar.
    WebText,
}

/// Whether `data` is EXACTLY a non-empty sequence of complete gRPC
/// length-prefixed frames under `representation`'s grammar, with nothing left
/// over.
///
/// This is a total structural parse, not a sniff: every frame must carry a flag
/// byte the representation admits, declare a length that fits inside the
/// remaining bytes, and the last frame must end precisely at the end of the
/// buffer. Truncated, padded, misordered, or mode-illegal framing answers
/// `false`, which keeps those bodies CLAIMED so the gate fails closed on them.
///
/// It exists so the buffered representation gate can tell framed gRPC apart from
/// a bare document when NO `Content-Type` was ever stamped or left on the
/// response, without falling back to the request flavor alone. The two answers
/// cannot collide: a valid binary frame begins with `0x00`, `0x01`, `0x80`, or
/// `0x81`, and base64 excludes `{`, `[`, and `"`, so classifying a frame
/// sequence as framed never costs a redaction a field rule could have applied.
pub(crate) fn bytes_are_complete_grpc_frames(
    data: &[u8],
    representation: GrpcFramingRepresentation,
) -> bool {
    match representation {
        GrpcFramingRepresentation::Native => binary_frames_are_complete(data, false),
        GrpcFramingRepresentation::WebBinary => binary_frames_are_complete(data, true),
        // Text mode is the ONLY representation where base64 is a legal body, and
        // it also still admits the binary framing that base64 encodes — see the
        // one-directional gating note on [`GrpcFramingRepresentation`].
        GrpcFramingRepresentation::WebText => {
            bytes_are_grpc_web_text_frames(data) || binary_frames_are_complete(data, true)
        }
    }
}

/// The binary frame-sequence grammar, parameterized by whether a terminal
/// trailer frame is legal.
///
/// `trailer_frame_allowed` is the whole difference between the native and
/// gRPC-Web binary representations. When it is set, a trailer frame is accepted
/// at most once and only as the FINAL frame: `pos` must land exactly on
/// `data.len()` after it, so `DATA TRAILER DATA` and `TRAILER TRAILER` stay
/// unframed and therefore claimed.
fn binary_frames_are_complete(data: &[u8], trailer_frame_allowed: bool) -> bool {
    let mut pos = 0usize;
    let mut frames = 0usize;
    while pos < data.len() {
        if data.len() - pos < 5 {
            return false;
        }
        // One place classifies the flag octet: a byte outside the four the wire
        // spec defines is not a frame header at all.
        let is_trailer = match data[pos] {
            GRPC_FRAME_DATA | GRPC_FRAME_DATA_COMPRESSED => false,
            GRPC_FRAME_TRAILER | GRPC_FRAME_TRAILER_COMPRESSED => true,
            _ => return false,
        };
        if is_trailer && !trailer_frame_allowed {
            return false;
        }
        let length =
            u32::from_be_bytes([data[pos + 1], data[pos + 2], data[pos + 3], data[pos + 4]]);
        let header_end = pos + 5;
        // Compare against the REMAINING bytes rather than adding to `pos`, so a
        // 4 GiB declared length cannot wrap on a 32-bit target.
        let Ok(length) = usize::try_from(length) else {
            return false;
        };
        if length > data.len() - header_end {
            return false;
        }
        pos = header_end + length;
        frames += 1;
        // A trailer frame terminates the message. Anything after it — another
        // trailer, more data, or trailing padding — is not a body this gateway
        // can prove is a complete RPC reply.
        if is_trailer {
            return pos == data.len();
        }
    }
    frames > 0
}

/// Validate the complete backend-bound gRPC-Web request envelope.
///
/// Request bodies may contain one or more native gRPC DATA frames. By the time
/// this runs on the owner path, any terminal gRPC-Web trailer frame has already
/// been split off by [`split_request_trailer_frame`] and staged as native
/// HTTP/2 request trailers, so a `0x80`/`0x81` byte still present here is a
/// duplicate, misordered, or unclaimable trailer frame and is rejected rather
/// than forwarded as message bytes. The legacy no-context hook has nowhere to
/// stage trailers and therefore rejects every trailer frame outright.
/// A compressed DATA frame is valid only when the request declares one
/// non-identity `grpc-encoding`; uncompressed frames remain legal when an
/// encoding is declared because compression is selected per message.
fn validate_grpc_web_request_frames(
    data: &[u8],
    headers: &HashMap<String, String>,
) -> Result<(), &'static str> {
    if data.is_empty() {
        return Err("body does not contain a gRPC message frame");
    }

    let compressed_encoding_declared = grpc_encoding_allows_compressed_frames(headers);
    let mut pos = 0usize;
    while pos < data.len() {
        let remaining = data.len() - pos;
        if remaining < 5 {
            return Err("truncated gRPC frame header or trailing bytes");
        }

        match data[pos] {
            GRPC_FRAME_DATA => {}
            GRPC_FRAME_DATA_COMPRESSED if compressed_encoding_declared => {}
            GRPC_FRAME_DATA_COMPRESSED => {
                return Err("compressed gRPC frame requires a non-identity grpc-encoding");
            }
            GRPC_FRAME_TRAILER | GRPC_FRAME_TRAILER_COMPRESSED => {
                return Err("unexpected gRPC-Web trailer frame in the message stream");
            }
            _ => return Err("unsupported gRPC frame flag"),
        }

        let declared =
            u32::from_be_bytes([data[pos + 1], data[pos + 2], data[pos + 3], data[pos + 4]]);
        let header_end = pos
            .checked_add(5)
            .ok_or("gRPC frame header offset overflow")?;
        let payload_len =
            usize::try_from(declared).map_err(|_| "gRPC frame length exceeds this platform")?;
        if payload_len > data.len() - header_end {
            return Err("truncated gRPC frame payload");
        }
        pos = header_end
            .checked_add(payload_len)
            .ok_or("gRPC frame payload offset overflow")?;
    }

    Ok(())
}

fn grpc_encoding_allows_compressed_frames(headers: &HashMap<String, String>) -> bool {
    let mut values = headers.iter().filter_map(|(name, value)| {
        name.eq_ignore_ascii_case("grpc-encoding")
            .then_some(value.trim())
    });
    let Some(value) = values.next() else {
        return false;
    };
    values.next().is_none()
        && !value.is_empty()
        && !value.eq_ignore_ascii_case("identity")
        && !value.contains(',')
        && value.bytes().all(|byte| {
            byte.is_ascii_alphanumeric()
                || matches!(
                    byte,
                    b'!' | b'#'
                        | b'$'
                        | b'%'
                        | b'&'
                        | b'\''
                        | b'*'
                        | b'+'
                        | b'-'
                        | b'.'
                        | b'^'
                        | b'_'
                        | b'`'
                        | b'|'
                        | b'~'
                )
        })
}

fn invalid_grpc_web_request(error: &str) -> PluginResult {
    // The diagnostics are gateway-authored constants, but the trailer-frame
    // failure travels through plugin-writable `ctx.metadata` before it lands
    // here — escape unconditionally so no reachable path can inject JSON.
    let error = crate::plugins::utils::json_escape::escape_json_string(error);
    PluginResult::Reject {
        status_code: 400,
        body: format!("{{\"error\":\"Invalid gRPC-Web request: {error}\"}}"),
        headers: grpc_content_type_header(),
    }
}

// ── Request-side trailer frames ─────────────────────────────────────────────
//
// gRPC-Web clients encode end-of-stream metadata as a final `0x80` frame in the
// request body, because a browser transport cannot emit HTTP/2 trailers. Ferrum
// splits that frame off the message frames, validates it, and re-emits it as a
// real HTTP/2 TRAILERS block at the end of the backend-bound request body, so
// the backend sees the native gRPC representation. Nothing is folded into the
// initial HEADERS block: request metadata that arrives at end-of-stream is not
// interchangeable with metadata the gateway already authenticated, authorized,
// and forwarded, and quietly promoting it would let a trailer contradict a
// decision that has already been made.

/// Maximum accepted payload length of a request-side gRPC-Web trailer frame.
///
/// The frame rides inside the request body, so it is already bounded by the
/// gRPC receive ceiling (`FERRUM_MAX_GRPC_RECV_SIZE_BYTES`) and by request-body
/// buffering. This second, much smaller bound exists because the block does not
/// stay body bytes: it becomes an HTTP/2 header block the backend must hold
/// decoded, so a client must not be able to spend the whole body budget there.
pub(crate) const MAX_REQUEST_TRAILER_BLOCK_BYTES: usize = 8 * 1024;
/// Maximum number of trailer entries accepted from one request trailer frame.
pub(crate) const MAX_REQUEST_TRAILER_ENTRIES: usize = 64;
/// Maximum length of a single request trailer name.
const MAX_REQUEST_TRAILER_NAME_BYTES: usize = 128;
/// Maximum length of a single request trailer value.
const MAX_REQUEST_TRAILER_VALUE_BYTES: usize = 4096;
/// Maximum base64-encoded JSON staging size for one validated trailer block.
///
/// JSON escaping can at most double the accepted 8 KiB wire payload; the
/// remaining factor covers tuple punctuation and base64 expansion. Check this
/// before decoding plugin-writable metadata so a forged staging value cannot
/// trigger an unbounded allocation.
const MAX_REQUEST_TRAILER_STAGING_BYTES: usize = 4 * MAX_REQUEST_TRAILER_BLOCK_BYTES;

const ERR_TRAILER_COMPRESSED: &str =
    "compressed gRPC-Web request trailer frames are not defined by the protocol";
const ERR_TRAILER_WITHOUT_MESSAGE: &str =
    "gRPC-Web request trailer frame without a preceding message frame";
const ERR_TRAILER_NOT_FINAL: &str =
    "gRPC-Web request trailer frame must be the last frame in the body";
const ERR_TRAILER_BLOCK_TOO_LARGE: &str = "gRPC-Web request trailer block is too large";
const ERR_TRAILER_BLOCK_EMPTY: &str = "gRPC-Web request trailer frame carries no trailer metadata";
const ERR_TRAILER_LINE_UNTERMINATED: &str = "gRPC-Web request trailer line is not CRLF-terminated";
const ERR_TRAILER_LINE_MALFORMED: &str = "malformed gRPC-Web request trailer line";
const ERR_TRAILER_PSEUDO_HEADER: &str =
    "gRPC-Web request trailer frame must not carry a pseudo-header";
const ERR_TRAILER_NAME_INVALID: &str = "invalid gRPC-Web request trailer name";
const ERR_TRAILER_NAME_FORBIDDEN: &str =
    "gRPC-Web request trailer name is not allowed at end of stream";
const ERR_TRAILER_NAME_TOO_LONG: &str = "gRPC-Web request trailer name is too long";
const ERR_TRAILER_VALUE_INVALID: &str = "invalid gRPC-Web request trailer value";
const ERR_TRAILER_VALUE_TOO_LONG: &str = "gRPC-Web request trailer value is too long";
const ERR_TRAILER_BIN_VALUE_INVALID: &str = "gRPC-Web request binary trailer value is not base64";
const ERR_TRAILER_TOO_MANY_ENTRIES: &str = "too many gRPC-Web request trailer entries";
const ERR_TRAILER_STAGING_FAILED: &str = "failed to stage validated gRPC-Web request trailers";

/// A validated terminal trailer frame split off a gRPC-Web request body.
pub(crate) struct RequestTrailerFrame {
    /// Offset where the trailer frame starts — i.e. the exclusive end of the
    /// backend-bound message-frame bytes.
    pub(crate) data_end: usize,
    /// Validated `(lowercase name, value)` pairs in wire order. Duplicate names
    /// are preserved as separate entries (gRPC multi-value metadata).
    pub(crate) trailers: Vec<(String, String)>,
}

/// Split and validate a terminal gRPC-Web trailer frame from a decoded request
/// body.
///
/// Returns `Ok(None)` when the body carries no trailer frame, including when it
/// is structurally malformed in a way that is not trailer-specific (short
/// header, truncated payload, unknown flag). Those defects stay the property of
/// [`validate_grpc_web_request_frames`], which owns their diagnostics and runs
/// on the same bytes immediately afterwards — reporting them twice, in two
/// wordings, is how the two validators would drift.
///
/// Everything trailer-specific fails closed here with a field-specific message:
///
/// * `0x81` (`Compressed-Flag` set on a trailer frame) has no meaning in the
///   gRPC-Web wire format — the trailer block is never message-encoded — so it
///   is refused rather than guessed at.
/// * A trailer frame that is not the FINAL frame is refused. This is the single
///   check that covers DATA-after-trailers and a second trailer frame: after a
///   valid trailer frame the parse must land exactly on the end of the buffer.
/// * A trailer frame with no preceding message frame is refused, keeping the
///   pre-existing "a request body is at least one message" contract intact
///   rather than dispatching a trailers-only upload the envelope validator
///   would then reject as an empty body.
pub(crate) fn split_request_trailer_frame(
    data: &[u8],
) -> Result<Option<RequestTrailerFrame>, &'static str> {
    let mut pos = 0usize;
    let mut data_frames = 0usize;
    while pos < data.len() {
        if data.len() - pos < 5 {
            return Ok(None);
        }
        let flag = data[pos];
        let declared =
            u32::from_be_bytes([data[pos + 1], data[pos + 2], data[pos + 3], data[pos + 4]]);
        let Ok(payload_len) = usize::try_from(declared) else {
            return Ok(None);
        };
        let header_end = pos + 5;
        // Compare against the REMAINING bytes so a 4 GiB declared length cannot
        // wrap on a 32-bit target.
        if payload_len > data.len() - header_end {
            return Ok(None);
        }
        match flag {
            GRPC_FRAME_DATA | GRPC_FRAME_DATA_COMPRESSED => {
                data_frames += 1;
                pos = header_end + payload_len;
                continue;
            }
            GRPC_FRAME_TRAILER_COMPRESSED => return Err(ERR_TRAILER_COMPRESSED),
            GRPC_FRAME_TRAILER => {}
            _ => return Ok(None),
        }
        if data_frames == 0 {
            return Err(ERR_TRAILER_WITHOUT_MESSAGE);
        }
        if payload_len > MAX_REQUEST_TRAILER_BLOCK_BYTES {
            return Err(ERR_TRAILER_BLOCK_TOO_LARGE);
        }
        if header_end + payload_len != data.len() {
            return Err(ERR_TRAILER_NOT_FINAL);
        }
        let trailers = parse_request_trailer_block(&data[header_end..])?;
        return Ok(Some(RequestTrailerFrame {
            data_end: pos,
            trailers,
        }));
    }
    Ok(None)
}

/// Parse the `name: value\r\n` block carried by a request trailer frame.
///
/// The grammar is total and strict: every line must be CRLF-terminated, must
/// contain a colon, and must survive the gRPC Custom-Metadata name charset and
/// ASCII-Value checks the response direction already applies. A bare CR or LF,
/// a leading `:`, whitespace around the name, an over-long name/value, or more
/// than [`MAX_REQUEST_TRAILER_ENTRIES`] entries fails the whole frame — a
/// partially accepted trailer block is exactly the shape a smuggling attempt
/// wants.
fn parse_request_trailer_block(payload: &[u8]) -> Result<Vec<(String, String)>, &'static str> {
    if payload.is_empty() {
        return Err(ERR_TRAILER_BLOCK_EMPTY);
    }
    let mut trailers: Vec<(String, String)> = Vec::new();
    let mut rest = payload;
    while !rest.is_empty() {
        let Some(eol) = rest.windows(2).position(|window| window == b"\r\n") else {
            return Err(ERR_TRAILER_LINE_UNTERMINATED);
        };
        let (line, tail) = rest.split_at(eol);
        rest = &tail[2..];
        if line.is_empty() {
            return Err(ERR_TRAILER_LINE_MALFORMED);
        }
        // A bare CR or LF inside a line would let one wire line present itself
        // as two field lines to a lenient downstream parser.
        if line.iter().any(|byte| *byte == b'\r' || *byte == b'\n') {
            return Err(ERR_TRAILER_LINE_MALFORMED);
        }
        if line[0] == b':' {
            return Err(ERR_TRAILER_PSEUDO_HEADER);
        }
        let Some(colon) = line.iter().position(|byte| *byte == b':') else {
            return Err(ERR_TRAILER_LINE_MALFORMED);
        };
        let (raw_name, raw_value) = line.split_at(colon);
        let raw_value = &raw_value[1..];
        if raw_name.len() > MAX_REQUEST_TRAILER_NAME_BYTES {
            return Err(ERR_TRAILER_NAME_TOO_LONG);
        }
        if raw_value.len() > MAX_REQUEST_TRAILER_VALUE_BYTES {
            return Err(ERR_TRAILER_VALUE_TOO_LONG);
        }
        let Ok(name) = std::str::from_utf8(raw_name) else {
            return Err(ERR_TRAILER_NAME_INVALID);
        };
        // `name : value` is a smuggling shape, not a field line (RFC 9110 §5.1).
        if name.bytes().any(|byte| byte == b' ' || byte == b'\t') {
            return Err(ERR_TRAILER_NAME_INVALID);
        }
        let name = name.to_ascii_lowercase();
        if !is_grpc_metadata_name(&name) {
            return Err(ERR_TRAILER_NAME_INVALID);
        }
        if is_forbidden_grpc_web_request_trailer_name(&name) {
            return Err(ERR_TRAILER_NAME_FORBIDDEN);
        }
        let Ok(value) = std::str::from_utf8(raw_value) else {
            return Err(ERR_TRAILER_VALUE_INVALID);
        };
        let value = value.trim_matches(|ch| ch == ' ' || ch == '\t');
        if !is_valid_trailer_value(value) {
            return Err(ERR_TRAILER_VALUE_INVALID);
        }
        if name.ends_with("-bin") && !is_base64_metadata_value(value) {
            return Err(ERR_TRAILER_BIN_VALUE_INVALID);
        }
        trailers.push((name, value.to_string()));
        if trailers.len() > MAX_REQUEST_TRAILER_ENTRIES {
            return Err(ERR_TRAILER_TOO_MANY_ENTRIES);
        }
    }
    if trailers.is_empty() {
        return Err(ERR_TRAILER_BLOCK_EMPTY);
    }
    Ok(trailers)
}

/// Request-side counterpart to [`is_forbidden_grpc_web_trailer_name`].
///
/// End-of-stream metadata must not be able to restate anything the gateway has
/// already decided or forwarded: connection/framing control, initial-only gRPC
/// call parameters, response terminal status, credentials and gateway identity
/// assertions that authentication and authorization already consumed from the
/// header block, or Ferrum-owned forwarding identity (`X-Forwarded-*` and RFC
/// 7239 `Forwarded`). The initial header block already carries the
/// gateway-authored forwarding identity; a trailer must not restate or
/// contradict it for backends that read trailing metadata. `Forwarded` is
/// rejected unconditionally (`is_proxy_owned_forwarding_header(name, true)`)
/// even when primary generation is disabled on a route — trailer parsing has
/// no config object, and failing closed is correct.
#[inline]
fn is_forbidden_grpc_web_request_trailer_name(name: &str) -> bool {
    name.starts_with(':')
        // PROTOCOL-HTTP2 reserves the entire grpc-* namespace. Known request
        // and response control fields are listed below for documentation, but
        // an unknown future control field must fail closed too.
        || name.starts_with("grpc-")
        || is_internal_grpc_web_bridge_header(name)
        || name == HEADER_GRPC_WEB_MODE
        // Reserved gateway assertions the gRPC header merge re-adds from
        // trusted plugin state only.
        || name.starts_with("x-consumer-")
        || name.starts_with("x-ferrum-")
        // Gateway-owned forwarding identity: reuse the canonical strip
        // predicate so this list cannot drift from primary dispatch.
        || is_proxy_owned_forwarding_header(name, true)
        || matches!(
            name,
            // Framing / connection control.
            "connection"
                | "keep-alive"
                | "proxy-connection"
                | "proxy-authenticate"
                | "proxy-authorization"
                | "transfer-encoding"
                | "upgrade"
                | "te"
                | "trailer"
                | "content-length"
                | "content-type"
                | "content-encoding"
                | "host"
                // Initial-metadata-only gRPC call parameters. Honoring these at
                // end of stream is always too late and lets a trailer
                // contradict the validated header block.
                | "grpc-timeout"
                | "grpc-encoding"
                | "grpc-accept-encoding"
                | "grpc-message-type"
                | "user-agent"
                | "x-grpc-web"
                // Response-side terminal metadata has no request meaning.
                | "grpc-status"
                | "grpc-message"
                | "grpc-status-details-bin"
                // Credentials and gateway-authoritative results.
                | "authorization"
                | "cookie"
                | "x-api-key"
                | "x-geo-country"
        )
}

/// Whether a `-bin` gRPC metadata value is base64, with or without padding.
///
/// The gRPC wire spec permits producers to omit padding on binary metadata, so
/// both dialects are accepted; anything else is refused rather than forwarded
/// as an unreadable binary field.
pub(crate) fn is_base64_metadata_value(value: &str) -> bool {
    !value.is_empty()
        && (BASE64.decode(value).is_ok()
            || base64::engine::general_purpose::STANDARD_NO_PAD
                .decode(value)
                .is_ok())
}

/// Serialize validated request trailers for owner-scoped request staging.
fn encode_request_trailers(trailers: &[(String, String)]) -> Result<String, &'static str> {
    serde_json::to_vec(trailers)
        .map(|raw| BASE64.encode(raw))
        .map_err(|_| ERR_TRAILER_STAGING_FAILED)
}

/// Decode the staged request trailer block into a native HTTP/2 trailer map.
///
/// Called by the gRPC dispatch paths with the request metadata map. Every entry
/// is re-validated: `ctx.metadata` is writable by any plugin, so the staged
/// block being present is not evidence that this plugin wrote it. Any anomaly
/// answers `None` (dispatch without trailers) rather than forwarding a block
/// this function cannot prove is the one the owner validated.
pub(crate) fn staged_request_trailers(
    metadata: &HashMap<String, String>,
) -> Option<http::HeaderMap> {
    let encoded = metadata.get(META_GRPC_WEB_REQUEST_TRAILERS)?;
    if encoded.len() > MAX_REQUEST_TRAILER_STAGING_BYTES {
        return None;
    }
    let raw = BASE64.decode(encoded).ok()?;
    let parsed: Vec<(String, String)> = serde_json::from_slice(&raw).ok()?;
    if parsed.is_empty() || parsed.len() > MAX_REQUEST_TRAILER_ENTRIES {
        return None;
    }
    let mut map = http::HeaderMap::with_capacity(parsed.len());
    let mut reconstructed_wire_bytes = 0usize;
    for (name, value) in parsed {
        reconstructed_wire_bytes = reconstructed_wire_bytes
            .checked_add(name.len())?
            .checked_add(value.len())?
            // `: ` plus CRLF.
            .checked_add(4)?;
        if !is_grpc_metadata_name(&name)
            || is_forbidden_grpc_web_request_trailer_name(&name)
            || name.len() > MAX_REQUEST_TRAILER_NAME_BYTES
            || value.len() > MAX_REQUEST_TRAILER_VALUE_BYTES
            || reconstructed_wire_bytes > MAX_REQUEST_TRAILER_BLOCK_BYTES
            || !is_valid_trailer_value(&value)
            || (name.ends_with("-bin") && !is_base64_metadata_value(&value))
        {
            return None;
        }
        let header_name = HeaderName::from_bytes(name.as_bytes()).ok()?;
        let header_value = http::HeaderValue::from_str(&value).ok()?;
        map.append(header_name, header_value);
    }
    Some(map)
}

/// Whether `data` is a gRPC-Web **text**-mode body: standard base64 whose decoded
/// octets are exactly a complete gRPC-Web binary frame sequence.
///
/// Text mode base64-encodes the whole framed body, so its wire bytes are ASCII
/// and [`binary_frames_are_complete`] cannot recognize them directly. The cheap
/// alphabet/length pre-scan runs first so an ordinary JSON document — whose
/// leading `{`, `[`, or `"` is outside the base64 alphabet — never reaches the
/// decoder. As with the binary case there is no collision to worry about: a body
/// that base64-decodes to valid frames is not a JSON document a field rule could
/// have redacted.
///
/// The encoding is decoded segment-wise by [`decode_grpc_web_text_body`] because
/// a text-mode producer may flush — and therefore pad — at frame or chunk
/// boundaries, so in-stream `=` is valid rather than a defect.
///
/// Reachable ONLY through [`GrpcFramingRepresentation::WebText`]. A native or
/// binary gRPC-Web response body is not base64, so base64-shaped bytes there are
/// an unprovable representation rather than framing.
fn bytes_are_grpc_web_text_frames(data: &[u8]) -> bool {
    decode_grpc_web_text_body(data)
        .is_some_and(|decoded| binary_frames_are_complete(&decoded, true))
}

/// Decode a gRPC-Web **text** body that may be a CONCATENATION of independently
/// padded base64 segments, or `None` when the bytes are not a total base64 parse.
///
/// A text-mode producer is free to flush at frame or chunk boundaries, and every
/// flush emits its own complete base64 run — trailing `=` padding included. So a
/// valid text body is `segment+`, where a segment ends at the first group that
/// carries padding, and interior `=` is ordinary in-stream padding rather than
/// corruption. Demanding ONE padded run (strip a single trailing `=`/`==`, then
/// reject any remaining `=`) misclassified those bodies as unframed; with a
/// response body rule configured, the representation gate then claimed a real
/// gRPC-Web reply it could not parse as a document and replaced it with a `502`.
///
/// The parse stays TOTAL, which is what keeps the gate fail-closed: the length
/// must be a whole number of 4-character groups, padding may appear only in a
/// group's last two positions (and `=` in the third position forces `=` in the
/// fourth), every other character must be in the standard alphabet, and each
/// segment must itself decode. Anything else answers `None`, leaving the body
/// claimed. A JSON document still never reaches the decoder — `{`, `[`, and `"`
/// are outside the alphabet, so the very first group rejects.
fn is_base64_alphabet(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || byte == b'+' || byte == b'/'
}

fn decode_grpc_web_text_body(data: &[u8]) -> Option<Vec<u8>> {
    if data.is_empty() || !data.len().is_multiple_of(4) {
        return None;
    }

    let mut decoded = Vec::with_capacity(data.len() / 4 * 3);
    let mut segment_start = 0usize;
    let mut pos = 0usize;
    while pos < data.len() {
        let group = &data[pos..pos + 4];
        if !is_base64_alphabet(group[0]) || !is_base64_alphabet(group[1]) {
            return None;
        }
        let padded = match (group[2], group[3]) {
            (b'=', b'=') => true,
            // `=` in the third position is padding, so the fourth must be `=`
            // too. `A=BC` is not a base64 group in any dialect.
            (b'=', _) => return None,
            (third, b'=') if is_base64_alphabet(third) => true,
            (third, fourth) if is_base64_alphabet(third) && is_base64_alphabet(fourth) => false,
            _ => return None,
        };
        pos += 4;
        if padded {
            // Padding closes this flush. Decode it on its own so the next group,
            // if any, is read as a fresh segment rather than as trailing garbage.
            decoded.extend(BASE64.decode(&data[segment_start..pos]).ok()?);
            segment_start = pos;
        }
    }
    if segment_start < data.len() {
        decoded.extend(BASE64.decode(&data[segment_start..]).ok()?);
    }
    Some(decoded)
}

/// Returns a header map with `content-type: application/grpc` for gRPC error responses.
fn grpc_content_type_header() -> HashMap<String, String> {
    let mut h = HashMap::new();
    h.insert("content-type".to_string(), "application/grpc".to_string());
    h
}

/// Provenance context for building a gRPC-Web trailer frame from a response.
///
/// Groups the backend trailer provenance that `transform_grpc_web_response_body`
/// forwards to `build_trailer_frame_with_full_provenance`, keeping the
/// provenance boundary explicit at the transform entry point.
struct TrailerFrameProvenance<'a> {
    http_status: Option<u16>,
    trailer_name_allowlist: Option<&'a HashSet<String>>,
    shadowed_trailers: Option<&'a HashMap<String, [String; 2]>>,
    policy_state: Option<&'a BufferedInitialResponseHeaderPolicyState>,
}

pub struct GrpcWebPlugin {
    /// Process-unique id for this constructed instance. Folded into namespaced
    /// metadata keys and the request-scoped translation owner marker so two
    /// co-located instances never share staging or suppress each other.
    instance_id_str: String,
    /// `grpc_web.instance.{id}.mode` — per-instance copy of the claimed mode.
    instance_mode_key: String,
    expose_headers: Vec<String>,
    expose_headers_value: String,
}

impl GrpcWebPlugin {
    pub fn new(config: &Value) -> Result<Self, String> {
        // Build-out policy: require an explicit object. `null` is not an alias
        // for `{}` — omit the plugin or pass `{}` / a full object instead.
        let object = config
            .as_object()
            .ok_or_else(|| "grpc_web: config must be an object".to_string())?;
        reject_unknown_keys(object, "config", GRPC_WEB_CONFIG_KEYS, "grpc_web: ")?;

        let mut expose_headers = BASE_EXPOSE_HEADERS
            .iter()
            .map(|header| (*header).to_string())
            .collect::<Vec<_>>();
        expose_headers.extend(parse_expose_headers(config)?);
        let expose_headers_value = expose_headers.join(", ");

        let instance_id = INSTANCE_ID_COUNTER.fetch_add(1, Ordering::Relaxed);
        let instance_id_str = instance_id.to_string();
        let instance_mode_key = format!("{INSTANCE_META_PREFIX}{instance_id}.mode");

        Ok(Self {
            instance_id_str,
            instance_mode_key,
            expose_headers,
            expose_headers_value,
        })
    }

    fn is_translation_owner(&self, ctx: &RequestContext) -> bool {
        ctx.metadata
            .get(META_GRPC_WEB_OWNER)
            .is_some_and(|owner| owner == &self.instance_id_str)
    }

    /// Mode for the owned translation. Both the namespaced owner value and the
    /// shared proxy/H3 marker must be present and equal; missing or divergent
    /// staging fails closed instead of borrowing another instance's state.
    fn owned_translation_mode<'a>(&self, ctx: &'a RequestContext) -> Option<&'a str> {
        let owned = ctx.metadata.get(&self.instance_mode_key)?.as_str();
        let shared = ctx.metadata.get(META_GRPC_WEB_MODE)?.as_str();
        if owned != shared {
            return None;
        }
        match owned {
            "text" | "binary" => Some(owned),
            _ => None,
        }
    }

    fn merge_expose_headers(&self, response_headers: &mut HashMap<String, String>) {
        let combined = match response_headers.get("access-control-expose-headers") {
            Some(existing) => {
                let mut out = existing.clone();
                for h in &self.expose_headers {
                    if !existing
                        .split(',')
                        .any(|tok| tok.trim().eq_ignore_ascii_case(h))
                    {
                        out.push_str(", ");
                        out.push_str(h);
                    }
                }
                out
            }
            None => self.expose_headers_value.clone(),
        };
        response_headers.insert("access-control-expose-headers".to_string(), combined);
    }

    /// Frame a gRPC-Web response body inside a `ceiling`-bounded sink.
    ///
    /// The output is the input plus one trailer frame (and, in text mode, the
    /// base64 armouring of both), so it has a finite bound derived from bytes
    /// that are already charged — but the bound is ENFORCED rather than assumed:
    /// every append goes through the sink, which refuses the write that would
    /// carry the buffer past the retained ceiling instead of allocating it
    /// (GHSA-pwcm-6rh8-f2gh). A capacity refusal returns
    /// [`crate::plugins::ResponseBodyTransformOutcome::CapacityRefused`] so the
    /// shared transform loop can install the body-framed capacity terminal
    /// rather than treating the miss as an ordinary no-op (which would forward
    /// a native body under the already-relabeled gRPC-Web Content-Type).
    fn transform_grpc_web_response_body(
        &self,
        body: &[u8],
        _content_type: Option<&str>,
        response_headers: &HashMap<String, String>,
        provenance: TrailerFrameProvenance,
        ceiling: usize,
    ) -> crate::plugins::ResponseBodyTransformOutcome {
        use crate::plugins::ResponseBodyTransformOutcome;

        // Only transform if response content-type is gRPC-Web (set by after_proxy)
        let Some(ct) = response_headers.get("content-type") else {
            return ResponseBodyTransformOutcome::Unchanged;
        };
        if !is_grpc_web_content_type(ct) {
            return ResponseBodyTransformOutcome::Unchanged;
        }

        let is_text = is_grpc_web_text(ct);

        // Build the gRPC-Web response:
        // 1. Keep existing data frames from the body
        // 2. Append a trailer frame with gRPC status metadata
        //
        // Text mode base64-expands by 4/3, so the BINARY pre-image is measured
        // under the base64 pre-image of the ceiling while the armoured bytes are
        // written straight into a sink bounded by the ceiling itself. Nothing
        // holds a second complete copy of the encoded replacement.
        let binary_ceiling = if is_text { ceiling / 4 * 3 } else { ceiling };
        use crate::proxy::response_buffer_budget::BoundedResponseBodySink;

        // The trailer payload is emitted TWICE and retained neither time
        // (GHSA-pwcm-6rh8-f2gh). The frame header declares the payload length,
        // so the length must be known before the payload can be written; the
        // counting pass below establishes it under the room the data frames and
        // the frame header leave, WITHOUT holding a single trailer value, and
        // the writing pass then emits the payload straight into the final
        // bounded destination (the binary sink, or the base64 encoder streaming
        // into the text sink). Neither a complete trailer payload nor a complete
        // binary preimage is ever resident beside the output.
        //
        // When the backend omitted a valid grpc-status, the writer synthesizes
        // from the stashed HTTP status (official client mapping). Provenance
        // (when recorded) keeps initial-header-only fields out of the body
        // trailer block. Both passes read the same immutable header map, so they
        // produce identical bytes; the written length is re-checked below
        // anyway, so a disagreement fails closed instead of shipping a frame
        // whose declared length lies.
        let Some(payload_ceiling) = binary_ceiling
            .checked_sub(body.len())
            .and_then(|room| room.checked_sub(GRPC_FRAME_HEADER_BYTES))
        else {
            return ResponseBodyTransformOutcome::CapacityRefused;
        };
        let mut counted = CountingTrailerPayloadSink::with_ceiling(payload_ceiling);
        if !write_trailer_frame_payload(
            &mut counted,
            response_headers,
            provenance.http_status,
            provenance.trailer_name_allowlist,
            provenance.shadowed_trailers,
            provenance.policy_state,
        ) {
            return ResponseBodyTransformOutcome::CapacityRefused;
        }
        let payload_len_usize = counted.len;
        let Ok(payload_len) = u32::try_from(payload_len_usize) else {
            return ResponseBodyTransformOutcome::CapacityRefused;
        };
        let mut frame_header = [0u8; GRPC_FRAME_HEADER_BYTES];
        frame_header[0] = GRPC_FRAME_TRAILER;
        frame_header[1..].copy_from_slice(&payload_len.to_be_bytes());
        let binary_len = body.len() + frame_header.len() + payload_len_usize;

        let mut output = BoundedResponseBodySink::with_ceiling(ceiling);
        if is_text {
            // Stream the base64 armouring straight into the bounded sink from
            // the FIRST encoded byte: the encoder writes through the ceiling, so
            // neither the binary concatenation nor a complete encoded `String`
            // is ever materialised beside the output.
            let engine = BASE64;
            {
                use std::io::Write;
                let mut encoder = base64::write::EncoderWriter::new(&mut output, &engine);
                if encoder.write_all(body).is_err()
                    || encoder.write_all(&frame_header).is_err()
                    || !write_trailer_frame_payload(
                        &mut WriterTrailerPayloadSink(&mut encoder),
                        response_headers,
                        provenance.http_status,
                        provenance.trailer_name_allowlist,
                        provenance.shadowed_trailers,
                        provenance.policy_state,
                    )
                    || encoder.finish().is_err()
                {
                    return ResponseBodyTransformOutcome::CapacityRefused;
                }
            }
            let Some(encoded) = output.finish() else {
                return ResponseBodyTransformOutcome::CapacityRefused;
            };
            // Padded standard base64 is a pure function of the preimage length,
            // so this proves the writing pass emitted exactly the payload the
            // counting pass declared in the frame header.
            let Some(expected_len) = binary_len.div_ceil(3).checked_mul(4) else {
                return ResponseBodyTransformOutcome::CapacityRefused;
            };
            if encoded.len() != expected_len {
                return ResponseBodyTransformOutcome::CapacityRefused;
            }
            debug!(
                plugin = "grpc_web",
                instance = %self.instance_id_str,
                binary_len,
                encoded_len = encoded.len(),
                "Base64-encoded gRPC-Web text response body"
            );
            ResponseBodyTransformOutcome::Replaced(encoded)
        } else {
            for segment in [body, &frame_header[..]] {
                if !output.push(segment) {
                    return ResponseBodyTransformOutcome::CapacityRefused;
                }
            }
            if !write_trailer_frame_payload(
                &mut output,
                response_headers,
                provenance.http_status,
                provenance.trailer_name_allowlist,
                provenance.shadowed_trailers,
                provenance.policy_state,
            ) {
                return ResponseBodyTransformOutcome::CapacityRefused;
            }
            if output.len() != binary_len {
                return ResponseBodyTransformOutcome::CapacityRefused;
            }
            let Some(framed) = output.finish() else {
                return ResponseBodyTransformOutcome::CapacityRefused;
            };
            debug!(
                plugin = "grpc_web",
                instance = %self.instance_id_str,
                body_len = framed.len(),
                "Built gRPC-Web binary response with trailer frame"
            );
            ResponseBodyTransformOutcome::Replaced(framed)
        }
    }
}

fn parse_expose_headers(config: &Value) -> Result<Vec<String>, String> {
    let Some(value) = config.get("expose_headers") else {
        return Ok(Vec::new());
    };
    if value.is_null() {
        return Ok(Vec::new());
    }

    let headers = value
        .as_array()
        .ok_or_else(|| format!("grpc_web: 'expose_headers' must be an array, got: {value}"))?;

    let mut seen = HashSet::with_capacity(headers.len());
    let mut parsed = Vec::with_capacity(headers.len());
    for (idx, raw) in headers.iter().enumerate() {
        let header = raw.as_str().ok_or_else(|| {
            format!("grpc_web: 'expose_headers[{idx}]' must be a string, got: {raw}")
        })?;
        let header = header.trim();
        if header.is_empty() {
            return Err(format!(
                "grpc_web: 'expose_headers[{idx}]' must not be empty"
            ));
        }
        let header_name = HeaderName::from_bytes(header.as_bytes()).map_err(|_| {
            format!("grpc_web: 'expose_headers[{idx}]' is not a valid HTTP header name")
        })?;
        let normalized = header_name.as_str().to_string();
        if seen.insert(normalized.clone()) {
            parsed.push(normalized);
        }
    }
    Ok(parsed)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum GrpcWebMode {
    Binary,
    Text,
}

/// Parsed gRPC-Web media type (request Content-Type or Accept entry).
#[derive(Clone, Debug, Eq, PartialEq)]
struct GrpcWebMediaType {
    mode: GrpcWebMode,
    /// Lowercased message-format subtype without the leading `+`, when present.
    format_suffix: Option<String>,
}

/// Why Accept negotiation refused to select a response media type.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum GrpcWebAcceptError {
    /// The Accept header could not be parsed as a media-type list.
    Malformed,
    /// No acceptable gRPC-Web representation remains after applying q-values.
    NotAcceptable,
}

#[inline]
fn is_ows(byte: u8) -> bool {
    matches!(byte, b' ' | b'\t')
}

#[inline]
fn trim_ows(mut value: &[u8]) -> &[u8] {
    while value.first().is_some_and(|byte| is_ows(*byte)) {
        value = &value[1..];
    }
    while value.last().is_some_and(|byte| is_ows(*byte)) {
        value = &value[..value.len() - 1];
    }
    value
}

#[inline]
fn is_tchar(byte: u8) -> bool {
    byte.is_ascii_alphanumeric()
        || matches!(
            byte,
            b'!' | b'#'
                | b'$'
                | b'%'
                | b'&'
                | b'\''
                | b'*'
                | b'+'
                | b'-'
                | b'.'
                | b'^'
                | b'_'
                | b'`'
                | b'|'
                | b'~'
        )
}

#[inline]
fn is_suffix_tchar(byte: u8) -> bool {
    // The gRPC-Web media type permits one optional `+subtype`. Treat another
    // `+` as a second suffix boundary rather than part of that subtype so
    // deceptive values cannot grow arbitrary valid-looking tails.
    byte != b'+' && is_tchar(byte)
}

fn valid_grpc_web_parameters(mut value: &[u8]) -> bool {
    while !value.is_empty() {
        while value.first().is_some_and(|byte| is_ows(*byte)) {
            value = &value[1..];
        }
        if value.first() != Some(&b';') {
            return false;
        }
        value = &value[1..];
        while value.first().is_some_and(|byte| is_ows(*byte)) {
            value = &value[1..];
        }

        let name_len = value.iter().take_while(|byte| is_tchar(**byte)).count();
        if name_len == 0 {
            return false;
        }
        value = &value[name_len..];
        while value.first().is_some_and(|byte| is_ows(*byte)) {
            value = &value[1..];
        }
        if value.first() != Some(&b'=') {
            return false;
        }
        value = &value[1..];
        while value.first().is_some_and(|byte| is_ows(*byte)) {
            value = &value[1..];
        }

        if value.first() == Some(&b'"') {
            value = &value[1..];
            let mut closed = false;
            let mut index = 0;
            while index < value.len() {
                match value[index] {
                    b'"' => {
                        value = &value[index + 1..];
                        closed = true;
                        break;
                    }
                    b'\\' => {
                        index += 1;
                        if index >= value.len()
                            || !(value[index] == b'\t'
                                || value[index] == b' '
                                || value[index].is_ascii_graphic()
                                || value[index] >= 0x80)
                        {
                            return false;
                        }
                    }
                    byte if byte == b'\t'
                        || byte == b' '
                        || byte == b'!'
                        || (b'#'..=b'[').contains(&byte)
                        || (b']'..=b'~').contains(&byte)
                        || byte >= 0x80 => {}
                    _ => return false,
                }
                index += 1;
            }
            if !closed {
                return false;
            }
        } else {
            let value_len = value.iter().take_while(|byte| is_tchar(**byte)).count();
            if value_len == 0 {
                return false;
            }
            value = &value[value_len..];
        }

        while value.first().is_some_and(|byte| is_ows(*byte)) {
            value = &value[1..];
        }
        if !value.is_empty() && value.first() != Some(&b';') {
            return false;
        }
    }
    true
}

/// Parse a quality value per RFC 9110 §12.4.2 (`q` / `Q`).
///
/// Returns `None` when the parameter is present but not a valid weight — callers
/// treat that as a malformed Accept list and fail closed.
fn parse_q_weight(raw: &[u8]) -> Option<u16> {
    let text = std::str::from_utf8(trim_ows(raw)).ok()?;
    if text.is_empty() {
        return None;
    }
    // RFC 9110: 0-1 with at most 3 decimal digits.
    let mut parts = text.splitn(2, '.');
    let whole = parts.next()?;
    if !matches!(whole, "0" | "1") {
        return None;
    }
    let frac = parts.next().unwrap_or("");
    if frac.len() > 3 || !frac.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    if whole == "1" && !frac.is_empty() && !frac.bytes().all(|b| b == b'0') {
        return None;
    }
    if whole == "1" {
        return Some(1000);
    }
    let mut thousandths = 0u16;
    for (index, digit) in frac.bytes().enumerate() {
        let place = match index {
            0 => 100,
            1 => 10,
            _ => 1,
        };
        thousandths += u16::from(digit - b'0') * place;
    }
    Some(thousandths)
}

fn parameter_q_weight(parameters: &[u8]) -> Result<u16, GrpcWebAcceptError> {
    let mut value = parameters;
    let mut quality: Option<u16> = None;
    while !value.is_empty() {
        while value.first().is_some_and(|byte| is_ows(*byte)) {
            value = &value[1..];
        }
        if value.first() != Some(&b';') {
            return Err(GrpcWebAcceptError::Malformed);
        }
        value = &value[1..];
        while value.first().is_some_and(|byte| is_ows(*byte)) {
            value = &value[1..];
        }

        let name_len = value.iter().take_while(|byte| is_tchar(**byte)).count();
        if name_len == 0 {
            return Err(GrpcWebAcceptError::Malformed);
        }
        let name = &value[..name_len];
        value = &value[name_len..];
        while value.first().is_some_and(|byte| is_ows(*byte)) {
            value = &value[1..];
        }
        if value.first() != Some(&b'=') {
            return Err(GrpcWebAcceptError::Malformed);
        }
        value = &value[1..];
        while value.first().is_some_and(|byte| is_ows(*byte)) {
            value = &value[1..];
        }

        let (param_value, rest) = if value.first() == Some(&b'"') {
            value = &value[1..];
            let mut index = 0;
            let mut closed = false;
            while index < value.len() {
                match value[index] {
                    b'"' => {
                        closed = true;
                        break;
                    }
                    b'\\' => {
                        index += 1;
                        if index >= value.len() {
                            return Err(GrpcWebAcceptError::Malformed);
                        }
                    }
                    _ => {}
                }
                index += 1;
            }
            if !closed {
                return Err(GrpcWebAcceptError::Malformed);
            }
            (&value[..index], &value[index + 1..])
        } else {
            let value_len = value.iter().take_while(|byte| is_tchar(**byte)).count();
            if value_len == 0 {
                return Err(GrpcWebAcceptError::Malformed);
            }
            (&value[..value_len], &value[value_len..])
        };
        value = rest;

        if name.eq_ignore_ascii_case(b"q") {
            if quality.is_some() {
                return Err(GrpcWebAcceptError::Malformed);
            }
            quality = Some(parse_q_weight(param_value).ok_or(GrpcWebAcceptError::Malformed)?);
        }

        while value.first().is_some_and(|byte| is_ows(*byte)) {
            value = &value[1..];
        }
        if !value.is_empty() && value.first() != Some(&b';') {
            return Err(GrpcWebAcceptError::Malformed);
        }
    }
    Ok(quality.unwrap_or(1000))
}

fn grpc_web_media_type(ct: &str) -> Option<GrpcWebMediaType> {
    let value = trim_ows(ct.as_bytes());
    let parameter_start = value.iter().position(|byte| *byte == b';');
    let (essence, parameters) = match parameter_start {
        Some(index) => (trim_ows(&value[..index]), &value[index..]),
        None => (value, &[][..]),
    };
    if !valid_grpc_web_parameters(parameters) {
        return None;
    }

    let classify = |base: &[u8], mode| {
        let prefix = essence.get(..base.len())?;
        if !prefix.eq_ignore_ascii_case(base) {
            return None;
        }
        let suffix = &essence[base.len()..];
        if suffix.is_empty() {
            return Some(GrpcWebMediaType {
                mode,
                format_suffix: None,
            });
        }
        let subtype = suffix.strip_prefix(b"+")?;
        if subtype.is_empty() || !subtype.iter().all(|byte| is_suffix_tchar(*byte)) {
            return None;
        }
        let format_suffix = std::str::from_utf8(subtype)
            .ok()
            .map(|s| s.to_ascii_lowercase());
        Some(GrpcWebMediaType {
            mode,
            format_suffix,
        })
    };

    classify(APPLICATION_GRPC_WEB_TEXT.as_bytes(), GrpcWebMode::Text)
        .or_else(|| classify(APPLICATION_GRPC_WEB.as_bytes(), GrpcWebMode::Binary))
}

fn canonical_grpc_web_content_type(media: &GrpcWebMediaType) -> String {
    let base = match media.mode {
        GrpcWebMode::Binary => APPLICATION_GRPC_WEB,
        GrpcWebMode::Text => APPLICATION_GRPC_WEB_TEXT,
    };
    match &media.format_suffix {
        Some(suffix) => format!("{base}+{suffix}"),
        None => base.to_string(),
    }
}

fn ensure_vary_accept(headers: &mut HashMap<String, String>) {
    match headers.get("vary") {
        Some(existing)
            if existing.trim() == "*"
                || existing
                    .split(',')
                    .any(|token| token.trim().eq_ignore_ascii_case("accept")) => {}
        Some(existing) => {
            let mut merged = String::with_capacity(existing.len() + ", Accept".len());
            merged.push_str(existing);
            if !existing.trim().is_empty() {
                merged.push_str(", ");
            }
            merged.push_str("Accept");
            headers.insert("vary".to_string(), merged);
        }
        None => {
            headers.insert("vary".to_string(), "Accept".to_string());
        }
    }
}

/// Specificity rank for Accept matching: exact > type wildcard > full wildcard.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
enum AcceptSpecificity {
    FullWildcard = 0,
    TypeWildcard = 1,
    Exact = 2,
}

#[derive(Clone, Copy, Debug)]
enum AcceptRangeKind {
    Exact(GrpcWebMode),
    ApplicationWildcard,
    FullWildcard,
}

struct AcceptRange {
    kind: AcceptRangeKind,
    /// When the Accept entry names a `+suffix`, that suffix is preferred.
    format_suffix: Option<String>,
    quality: u16,
    specificity: AcceptSpecificity,
}

fn parse_accept_range(entry: &str) -> Result<Option<AcceptRange>, GrpcWebAcceptError> {
    let value = trim_ows(entry.as_bytes());
    if value.is_empty() {
        return Ok(None);
    }
    let parameter_start = value.iter().position(|byte| *byte == b';');
    let (essence, parameters) = match parameter_start {
        Some(index) => (trim_ows(&value[..index]), &value[index..]),
        None => (value, &[][..]),
    };
    if essence.is_empty() {
        return Err(GrpcWebAcceptError::Malformed);
    }
    let quality = parameter_q_weight(parameters)?;

    if essence == b"*/*" {
        return Ok(Some(AcceptRange {
            kind: AcceptRangeKind::FullWildcard,
            format_suffix: None,
            quality,
            specificity: AcceptSpecificity::FullWildcard,
        }));
    }
    if essence.eq_ignore_ascii_case(b"application/*") {
        return Ok(Some(AcceptRange {
            kind: AcceptRangeKind::ApplicationWildcard,
            format_suffix: None,
            quality,
            specificity: AcceptSpecificity::TypeWildcard,
        }));
    }

    // Exact gRPC-Web types only — lookalikes such as application/grpc-website
    // must not participate in negotiation.
    let Some(media) = grpc_web_media_type(
        // Re-parse with parameters stripped for the media-type helper; quality
        // was already extracted above. Reconstruct essence alone.
        std::str::from_utf8(essence).map_err(|_| GrpcWebAcceptError::Malformed)?,
    ) else {
        // Non-gRPC-Web types are ignored for selection (they do not make the
        // list malformed); they simply cannot win.
        return Ok(None);
    };
    Ok(Some(AcceptRange {
        kind: AcceptRangeKind::Exact(media.mode),
        format_suffix: media.format_suffix,
        quality,
        specificity: AcceptSpecificity::Exact,
    }))
}

fn split_accept_list(accept: &str) -> Result<Vec<&str>, GrpcWebAcceptError> {
    // Commas inside quoted parameter values are rare for Accept; still scan so
    // a quoted comma cannot split an entry. Fail closed on an unclosed quote.
    let bytes = accept.as_bytes();
    let mut entries = Vec::new();
    let mut start = 0usize;
    let mut index = 0usize;
    let mut in_quotes = false;
    let mut escaped = false;
    while index < bytes.len() {
        let byte = bytes[index];
        if in_quotes {
            if escaped {
                escaped = false;
            } else if byte == b'\\' {
                escaped = true;
            } else if byte == b'"' {
                in_quotes = false;
            }
        } else if byte == b'"' {
            in_quotes = true;
        } else if byte == b',' {
            entries.push(
                std::str::from_utf8(&bytes[start..index])
                    .map_err(|_| GrpcWebAcceptError::Malformed)?,
            );
            start = index + 1;
        }
        index += 1;
    }
    if in_quotes || escaped {
        return Err(GrpcWebAcceptError::Malformed);
    }
    entries.push(std::str::from_utf8(&bytes[start..]).map_err(|_| GrpcWebAcceptError::Malformed)?);
    Ok(entries)
}

/// Negotiate the client-facing gRPC-Web response media type from request
/// `Content-Type` and optional `Accept`.
///
/// See the module docs for defaults and the fail-closed `406` cases.
pub fn negotiate_response_media_type(
    request_content_type: &str,
    accept: Option<&str>,
) -> Result<String, GrpcWebAcceptError> {
    let request = grpc_web_media_type(request_content_type).ok_or(GrpcWebAcceptError::Malformed)?;
    let default = canonical_grpc_web_content_type(&request);

    let Some(accept) = accept.map(str::trim).filter(|value| !value.is_empty()) else {
        return Ok(default);
    };

    let mut ranges = Vec::new();
    for entry in split_accept_list(accept)? {
        if let Some(range) = parse_accept_range(entry)? {
            ranges.push(range);
        }
    }
    if ranges.is_empty() {
        // Accept listed only non-gRPC-Web types — nothing we can produce.
        return Err(GrpcWebAcceptError::NotAcceptable);
    }

    // Candidate representations are the request message format in both wire
    // modes. Accept selects the wire encoding; Ferrum does not transcode the
    // message payload between proto/json/thrift/custom formats. Treat an absent
    // request suffix as the protocol's implicit `+proto`, while allowing an
    // explicit Accept `+proto` to make that suffix visible on the response.
    let request_effective_format = request.format_suffix.as_deref().unwrap_or("proto");
    let mut candidates = vec![
        GrpcWebMediaType {
            mode: GrpcWebMode::Binary,
            format_suffix: request.format_suffix.clone(),
        },
        GrpcWebMediaType {
            mode: GrpcWebMode::Text,
            format_suffix: request.format_suffix.clone(),
        },
    ];
    for range in &ranges {
        if let AcceptRangeKind::Exact(mode) = range.kind {
            let candidate_suffix = range
                .format_suffix
                .clone()
                .or_else(|| request.format_suffix.clone());
            if candidate_suffix.as_deref().unwrap_or("proto") != request_effective_format {
                continue;
            }
            let candidate = GrpcWebMediaType {
                mode,
                format_suffix: candidate_suffix,
            };
            if !candidates.contains(&candidate) {
                candidates.push(candidate);
            }
        }
    }

    let mut best: Option<(u16, AcceptSpecificity, bool, usize, GrpcWebMediaType)> = None;
    for candidate in candidates {
        // RFC 9110 selection is per representation: the most specific matching
        // range supplies its quality. The later entry wins only when the same
        // representation has duplicate ranges at equal specificity.
        let mut controlling: Option<(AcceptSpecificity, usize, u16)> = None;
        for (index, range) in ranges.iter().enumerate() {
            let matches = match range.kind {
                AcceptRangeKind::Exact(mode) => {
                    mode == candidate.mode
                        && range
                            .format_suffix
                            .as_deref()
                            .or(request.format_suffix.as_deref())
                            == candidate.format_suffix.as_deref()
                }
                AcceptRangeKind::ApplicationWildcard | AcceptRangeKind::FullWildcard => true,
            };
            if !matches {
                continue;
            }
            if controlling
                .as_ref()
                .is_none_or(|(specificity, previous_index, _)| {
                    range.specificity > *specificity
                        || (range.specificity == *specificity && index > *previous_index)
                })
            {
                controlling = Some((range.specificity, index, range.quality));
            }
        }
        let Some((specificity, index, quality)) = controlling else {
            continue;
        };
        if quality == 0 {
            continue;
        }
        let matches_request_mode = candidate.mode == request.mode;
        let replace = best.as_ref().is_none_or(
            |(best_quality, best_specificity, best_matches_request, best_index, _)| {
                quality > *best_quality
                    || (quality == *best_quality && specificity > *best_specificity)
                    || (quality == *best_quality
                        && specificity == *best_specificity
                        && matches_request_mode
                        && !*best_matches_request)
                    || (quality == *best_quality
                        && specificity == *best_specificity
                        && matches_request_mode == *best_matches_request
                        && index < *best_index)
            },
        );
        if replace {
            best = Some((quality, specificity, matches_request_mode, index, candidate));
        }
    }

    best.map(|(_, _, _, _, media)| canonical_grpc_web_content_type(&media))
        .ok_or(GrpcWebAcceptError::NotAcceptable)
}

/// Check if a content-type indicates a gRPC-Web request.
pub(crate) fn is_grpc_web_content_type(ct: &str) -> bool {
    grpc_web_media_type(ct).is_some()
}

/// Check if a gRPC-Web content-type uses text (base64) encoding.
pub(crate) fn is_grpc_web_text(ct: &str) -> bool {
    grpc_web_media_type(ct).is_some_and(|media_type| media_type.mode == GrpcWebMode::Text)
}

/// True when the `grpc_web` plugin translated this request from gRPC-Web to
/// native gRPC framing. The marker is stamped only by `on_request_received`
/// after verifying the ORIGINAL client content-type is `application/grpc-web*`
/// (the spoofable inbound `x-grpc-web-mode` header is stripped there first),
/// so a client cannot inject it.
///
/// Dispatch paths use this to tell a translated gRPC-Web request apart from
/// native gRPC: by dispatch time both carry `content-type: application/grpc`
/// (rewritten in `before_proxy`), but a translated response must convert the
/// backend's terminal trailers (`grpc-status` / `grpc-message`) into one
/// gRPC-Web body frame while native gRPC relays them on the wire.
pub fn request_is_grpc_web_translated(ctx: &RequestContext) -> bool {
    ctx.metadata.contains_key(META_GRPC_WEB_MODE)
}

/// Retain a recognized client representation for gateway-generated errors
/// without claiming that request translation occurred. H3 uses this for
/// pass-through deployments that intentionally omit the `grpc_web` plugin:
/// policy and error shaping remain gRPC-Web-aware, while backend dispatch
/// stays on the original plain-HTTP transport because the mode marker above is
/// absent.
///
/// When `Accept` is present and valid, the retained type is the negotiated
/// response media type (so early errors match what a successful response would
/// have used). On Accept failure the request Content-Type canonical form is
/// retained so other gateway errors still have a browser-safe shape; the
/// `grpc_web` plugin itself fails closed with `406` when translation is enabled.
#[allow(dead_code)] // Called through `_test_support` in special test-hook builds.
pub(crate) fn retain_client_content_type_for_errors(ctx: &mut RequestContext, content_type: &str) {
    if !is_grpc_web_content_type(content_type) {
        return;
    }
    let accept = request_accept_header(ctx);
    let retained = match accept
        .and_then(|accept| negotiate_response_media_type(content_type, accept.as_deref()))
    {
        Ok(negotiated) => negotiated,
        Err(_) => response_content_type(content_type),
    };
    retain_negotiated_response_content_type(ctx, &retained);
}

fn combine_accept_header_values<'a>(
    values: impl IntoIterator<Item = &'a [u8]>,
    max_bytes: usize,
) -> Result<Option<String>, GrpcWebAcceptError> {
    let mut combined = String::new();
    for value in values {
        let value = std::str::from_utf8(value).map_err(|_| GrpcWebAcceptError::Malformed)?;
        let separator_len = if combined.is_empty() { 0 } else { 1 };
        if combined
            .len()
            .checked_add(separator_len)
            .and_then(|length| length.checked_add(value.len()))
            .is_none_or(|length| length > max_bytes)
        {
            return Err(GrpcWebAcceptError::Malformed);
        }
        if !combined.is_empty() {
            combined.push(',');
        }
        combined.push_str(value);
    }
    Ok((!combined.is_empty()).then_some(combined))
}

fn request_accept_header(ctx: &RequestContext) -> Result<Option<String>, GrpcWebAcceptError> {
    if ctx.has_raw_headers() {
        return combine_accept_header_values(ctx.raw_header_value_bytes("accept"), usize::MAX);
    }
    Ok(ctx.headers.get("accept").cloned())
}

/// Negotiate from every `Accept` field line in an HTTP header map. Frontend
/// early-error classification uses this same parser as the plugin request hook
/// so duplicate field lines, invalid bytes, and list semantics cannot diverge.
pub(crate) fn negotiate_response_media_type_from_headers(
    request_content_type: &str,
    headers: &http::HeaderMap,
    max_accept_bytes: usize,
) -> Result<String, GrpcWebAcceptError> {
    let accept = combine_accept_header_values(
        headers
            .get_all(http::header::ACCEPT)
            .iter()
            .map(|value| value.as_bytes()),
        max_accept_bytes,
    )?;
    negotiate_response_media_type(request_content_type, accept.as_deref())
}

/// Store an already-negotiated (or defaulted) gRPC-Web response media type for
/// gateway-generated error shaping and the buffered representation gate.
pub(crate) fn retain_negotiated_response_content_type(
    ctx: &mut RequestContext,
    response_content_type: &str,
) {
    if is_grpc_web_content_type(response_content_type) {
        ctx.metadata.insert(
            META_GRPC_WEB_ORIGINAL_CT.to_string(),
            self::response_content_type(response_content_type),
        );
    }
}

pub(crate) fn client_uses_grpc_web(ctx: &RequestContext) -> bool {
    retained_response_content_type(ctx).is_some()
}

/// Which gRPC framing grammar this request's buffered response body may use, or
/// `None` for traffic that is not gRPC at all.
///
/// Decided entirely from immutable request state — the request's HTTP flavor,
/// the translation marker, and the retained client content type — because every
/// live header the response carries has already passed through `after_proxy` and
/// can name whatever a rule rewrote it to.
///
/// The ordering is load-bearing, and it is about WHEN the representation gate
/// runs relative to this plugin's own re-encoding:
///
/// * A **translated** gRPC-Web request (`META_GRPC_WEB_MODE` present) reached the
///   backend as `application/grpc`, so the backend answered in NATIVE framing.
///   This plugin appends the trailer frame and base64-encodes in
///   `transform_response_body` — plugin phase 9, AFTER the gate — so at gate time
///   the bytes are still native, in text mode exactly as in binary mode.
/// * A **retained-only** gRPC-Web request (`META_GRPC_WEB_ORIGINAL_CT` without
///   the mode marker) is the pass-through deployment that intentionally omits
///   this plugin's translation: the backend saw the client's own gRPC-Web type
///   and answered in that representation, so the retained type — text or binary
///   — is the grammar of the bytes the gate is looking at.
/// * Otherwise a native gRPC request answers in native framing, and anything
///   else is not gRPC and has no framing to preserve.
pub(crate) fn client_grpc_framing_representation(
    ctx: &RequestContext,
) -> Option<GrpcFramingRepresentation> {
    if request_is_grpc_web_translated(ctx) {
        return Some(GrpcFramingRepresentation::Native);
    }
    if let Some(retained) = retained_response_content_type(ctx) {
        return Some(if is_grpc_web_text(retained) {
            GrpcFramingRepresentation::WebText
        } else {
            GrpcFramingRepresentation::WebBinary
        });
    }
    ctx.is_native_grpc_request()
        .then_some(GrpcFramingRepresentation::Native)
}

/// The negotiated (or defaulted) client-facing gRPC-Web response media type.
///
/// Stored already-canonical by [`retain_client_content_type_for_errors`] /
/// `on_request_received`, so callers must not re-derive it from request
/// `Content-Type` alone — that would ignore Accept negotiation.
pub(crate) fn retained_response_content_type(ctx: &RequestContext) -> Option<&str> {
    if ctx.metadata.contains_key(META_GRPC_WEB_ACCEPT_REJECTED) {
        return None;
    }
    ctx.metadata
        .get(META_GRPC_WEB_ORIGINAL_CT)
        .map(String::as_str)
}

pub struct GrpcWebErrorResponse {
    pub headers: HashMap<String, String>,
    pub body: Vec<u8>,
    terminal_headers: HashMap<String, String>,
}

/// Rebuild a synthesized error's body trailer frame after finalized rejection
/// metadata has been merged into its temporary header map. Preserve the
/// originally selected status/message when decorators contribute no terminal
/// fields, while letting case-insensitive finalized fields replace them.
pub(crate) fn rebuild_error_body_from_headers(response: &mut GrpcWebErrorResponse) {
    let response_ct = response
        .headers
        .get("content-type")
        .map(String::as_str)
        .unwrap_or(APPLICATION_GRPC_WEB);
    let mut trailer_headers = response.terminal_headers.clone();
    for (name, value) in &response.headers {
        if is_valid_trailer_header(name).is_none() {
            continue;
        }
        if let Some(existing) = trailer_headers
            .keys()
            .find(|existing| existing.eq_ignore_ascii_case(name))
            .cloned()
        {
            trailer_headers.remove(&existing);
        }
        trailer_headers.insert(name.clone(), value.clone());
    }
    let mut body = build_trailer_frame(&trailer_headers, None);
    if is_grpc_web_text(response_ct) {
        body = BASE64.encode(&body).into_bytes();
    }
    response.body = body;
}

/// Build the client-visible gRPC-Web error shape for an early gateway refusal
/// that happens before normal response hooks can run.
pub fn error_response_for_content_type(
    response_ct: &str,
    status: u32,
    message: &str,
) -> GrpcWebErrorResponse {
    let response_ct = response_content_type(response_ct);
    let mut headers = HashMap::with_capacity(4);
    headers.insert("content-type".to_string(), response_ct.clone());
    headers.insert("x-grpc-web".to_string(), "1".to_string());
    headers.insert(
        "access-control-expose-headers".to_string(),
        BASE_EXPOSE_HEADERS_VALUE.to_string(),
    );
    ensure_vary_accept(&mut headers);

    // gRPC-Web carries terminal metadata in its body trailer frame, never as
    // native response headers. Keep a separate trailer map so an early gateway
    // refusal has the same client-visible shape as a transformed backend
    // response.
    let trailer_headers = HashMap::from([
        ("grpc-status".to_string(), status.to_string()),
        ("grpc-message".to_string(), message.to_string()),
    ]);
    let mut body = build_trailer_frame(&trailer_headers, None);
    if is_grpc_web_text(&response_ct) {
        body = BASE64.encode(&body).into_bytes();
    }
    GrpcWebErrorResponse {
        headers,
        body,
        terminal_headers: trailer_headers,
    }
}

/// Build the client-visible gRPC-Web error shape for a recognized request that
/// happens before normal response hooks can run. The retained representation
/// may belong to a translated request or an intentional H3 pass-through.
pub fn translated_error_response(
    ctx: &RequestContext,
    status: u32,
    message: &str,
) -> Option<GrpcWebErrorResponse> {
    let response_ct = retained_response_content_type(ctx)?;
    Some(error_response_for_content_type(
        response_ct,
        status,
        message,
    ))
}

/// Whether `name` is a reserved gRPC terminal-status metadata key.
#[inline]
fn is_reserved_grpc_web_terminal_metadata(name: &str) -> bool {
    matches!(
        name,
        "grpc-status" | "grpc-message" | "grpc-status-details-bin"
    )
}

/// HTTP / gateway fields that may appear in the merged response-header view
/// but must never be copied into the gRPC-Web body trailer frame.
#[inline]
fn is_forbidden_grpc_web_trailer_name(name: &str) -> bool {
    // Pseudo-headers are rejected by `HeaderName::from_bytes` already; keep an
    // explicit `:` guard for defense in depth if a non-normalized key arrives.
    name.starts_with(':')
        || is_backend_response_strip_header(name)
        || matches!(
            name,
            "content-type"
                | "content-length"
                | "content-encoding"
                | "content-disposition"
                | "content-range"
                | "set-cookie"
                | "set-cookie2"
                | "host"
                | "accept"
                | "accept-encoding"
                | "user-agent"
                | "date"
                | "server"
                | "vary"
                | "via"
                | "location"
                | "x-grpc-web"
                | "access-control-allow-origin"
                | "access-control-allow-credentials"
                | "access-control-allow-headers"
                | "access-control-allow-methods"
                | "access-control-expose-headers"
                | "access-control-max-age"
                | "access-control-request-headers"
                | "access-control-request-method"
        )
        || is_internal_grpc_web_bridge_header(name)
}

/// gRPC Custom-Metadata header-name charset (PROTOCOL-HTTP2): `0-9` / `a-z` /
/// `_` / `-` / `.`. Stricter than the HTTP token set so hostile names that
/// survive `HeaderName` parsing still cannot enter the trailer frame.
#[inline]
pub(crate) fn is_grpc_metadata_name(name: &str) -> bool {
    !name.is_empty()
        && name
            .bytes()
            .all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'z' | b'_' | b'-' | b'.'))
}

fn is_valid_trailer_header(key: &str) -> Option<HeaderName> {
    let header = HeaderName::from_bytes(key.trim().as_bytes()).ok()?;
    let normalized = header.as_str();
    if is_forbidden_grpc_web_trailer_name(normalized) || !is_grpc_metadata_name(normalized) {
        None
    } else {
        Some(header)
    }
}

/// gRPC ASCII-Value (PROTOCOL-HTTP2): space and printable ASCII only. Also
/// rejects embedded CR/LF so a hostile trailer cannot smuggle header lines
/// into the gRPC-Web trailer block.
pub(crate) fn is_valid_trailer_value(value: &str) -> bool {
    value.bytes().all(|b| (0x20..=0x7E).contains(&b))
}

/// Encode backend trailer names for gRPC-Web body-frame provenance.
fn encode_trailer_names_for_frame(trailers: &HashMap<String, String>) -> String {
    let mut names: Vec<&str> = trailers.keys().map(String::as_str).collect();
    names.sort_unstable();
    names.join("\n")
}

/// Record the backend trailer names that may be embedded in the gRPC-Web body
/// trailer frame for a translated request.
///
/// Callers pass the backend trailer map *after* hop-by-hop collection. An empty
/// map still records provenance (empty allowlist) so initial-header-only fields
/// in the merged plugin view cannot leak into the frame. Unit helpers that never
/// call this keep the metadata key absent and therefore unrestricted beyond the
/// ordinary name/value safety filters.
pub fn record_backend_trailer_names_for_frame(
    metadata: &mut HashMap<String, String>,
    trailers: &HashMap<String, String>,
) {
    metadata.insert(
        META_GRPC_WEB_TRAILER_NAMES.to_string(),
        encode_trailer_names_for_frame(trailers),
    );
    // A names-only caller has no same-name initial/trailer collisions to
    // preserve. Still install a valid empty collision map so a missing payload
    // can unambiguously mean corrupt/incomplete internal provenance later.
    metadata.insert(
        META_GRPC_WEB_SHADOWED_TRAILERS.to_string(),
        BASE64.encode(b"{}"),
    );
}

fn encode_shadowed_trailers_for_frame(
    response_headers: &HashMap<String, String>,
    trailers: &HashMap<String, String>,
) -> String {
    let shadowed = trailers
        .iter()
        .filter_map(|(name, trailer_value)| {
            response_headers.get(name).and_then(|initial_value| {
                (!is_reserved_grpc_web_terminal_metadata(name))
                    .then(|| (name.clone(), [initial_value.clone(), trailer_value.clone()]))
            })
        })
        .collect::<BTreeMap<_, _>>();
    match serde_json::to_vec(&shadowed) {
        Ok(encoded) => BASE64.encode(encoded),
        // String-keyed/string-valued JSON serialization has no data-dependent
        // failure mode. Keep the boundary fail-closed if that invariant ever
        // changes: an empty map cannot introduce a backend value into a frame.
        Err(_) => BASE64.encode(b"{}"),
    }
}

fn shadowed_trailers_from_metadata(
    metadata: &HashMap<String, String>,
) -> Option<HashMap<String, [String; 2]>> {
    let encoded = metadata.get(META_GRPC_WEB_SHADOWED_TRAILERS)?;
    decode_shadowed_trailers_payload(encoded)
}

/// Record both the backend trailer allowlist and collision provenance needed
/// to preserve a true trailer value when the same name also appeared in the
/// backend's initial headers.
pub fn record_backend_trailer_provenance_for_frame(
    metadata: &mut HashMap<String, String>,
    response_headers: &HashMap<String, String>,
    trailers: &HashMap<String, String>,
) {
    record_backend_trailer_names_for_frame(metadata, trailers);
    metadata.insert(
        META_GRPC_WEB_SHADOWED_TRAILERS.to_string(),
        encode_shadowed_trailers_for_frame(response_headers, trailers),
    );
}

/// Embed trailer-name provenance in a response-header bridge for dispatch paths
/// that cannot mutate `RequestContext` (sidecar mesh-mTLS). [`GrpcWebPlugin::after_proxy`]
/// promotes the value into metadata and strips the bridge header.
pub fn bridge_backend_trailer_names_for_frame(
    response_headers: &mut HashMap<String, String>,
    trailers: &HashMap<String, String>,
) {
    response_headers.insert(
        HEADER_GRPC_WEB_TRAILER_NAMES.to_string(),
        encode_trailer_names_for_frame(trailers),
    );
    response_headers.insert(
        HEADER_GRPC_WEB_SHADOWED_TRAILERS.to_string(),
        BASE64.encode(b"{}"),
    );
}

/// Bridge full trailer provenance through a response-header-only dispatch
/// boundary. Both internal headers are removed by `after_proxy`.
pub fn bridge_backend_trailer_provenance_for_frame(
    response_headers: &mut HashMap<String, String>,
    trailers: &HashMap<String, String>,
) {
    let shadowed = encode_shadowed_trailers_for_frame(response_headers, trailers);
    bridge_backend_trailer_names_for_frame(response_headers, trailers);
    response_headers.insert(HEADER_GRPC_WEB_SHADOWED_TRAILERS.to_string(), shadowed);
}

/// Reconstructed backend initial-header / trailer split from bridged
/// provenance on the merged response-header map.
///
/// Returned by [`capture_bridged_trailer_split_for_policy`] so callers can
/// track genuine initial headers separately from application trailers.
pub struct BridgedTrailerSplit {
    pub initial_headers: HashMap<String, String>,
    pub trailers: HashMap<String, String>,
    pub shadowed_keys: HashSet<String>,
}

/// Reconstruct the backend initial-header / trailer split from bridged
/// provenance still present on the merged response-header map.
///
/// Used by the mesh-mTLS translated path before `after_proxy` promotes the
/// bridge headers into metadata, so [`BufferedInitialResponseHeaderPolicyState`]
/// can track genuine initial headers separately from application trailers.
pub fn capture_bridged_trailer_split_for_policy(
    response_headers: &HashMap<String, String>,
) -> Option<BridgedTrailerSplit> {
    let encoded_names = response_headers.get(HEADER_GRPC_WEB_TRAILER_NAMES)?;
    // Collision provenance is always installed alongside trailer names by the
    // bridge helpers. Missing or undecodable payloads are incomplete/corrupt
    // internal state — fail closed like
    // `transform_response_body_with_context` so a same-name initial header is
    // never substituted for the true trailer value.
    let Some(encoded_shadowed) = response_headers.get(HEADER_GRPC_WEB_SHADOWED_TRAILERS) else {
        return Some(fail_closed_bridged_trailer_split(
            response_headers,
            encoded_names,
        ));
    };
    let Some(shadowed) = decode_shadowed_trailers_payload(encoded_shadowed.as_str()) else {
        return Some(fail_closed_bridged_trailer_split(
            response_headers,
            encoded_names,
        ));
    };
    let mut trailers = HashMap::new();
    let mut shadowed_keys = HashSet::new();
    for name in encoded_names.split('\n').filter(|name| !name.is_empty()) {
        if let Some([_, trailer_value]) = shadowed.get(name) {
            trailers.insert(name.to_string(), trailer_value.clone());
            shadowed_keys.insert(name.to_string());
        } else if let Some(value) = response_headers.get(name).cloned().or_else(|| {
            response_headers
                .iter()
                .find(|(key, _)| key.eq_ignore_ascii_case(name))
                .map(|(_, value)| value.clone())
        }) {
            trailers.insert(name.to_string(), value);
        }
    }
    let mut initial = response_headers.clone();
    initial.remove(HEADER_GRPC_WEB_TRAILER_NAMES);
    initial.remove(HEADER_GRPC_WEB_SHADOWED_TRAILERS);
    for name in trailers.keys() {
        if let Some([initial_value, _]) = shadowed.get(name) {
            initial.insert(name.clone(), initial_value.clone());
        } else {
            initial.retain(|key, _| !key.eq_ignore_ascii_case(name));
        }
    }
    Some(BridgedTrailerSplit {
        initial_headers: initial,
        trailers,
        shadowed_keys,
    })
}

/// Reconstruct a bridged split when collision provenance is missing/corrupt.
///
/// Only reserved terminal metadata may be treated as trailers; application
/// trailer names listed in the allowlist are removed from the initial-header
/// view without being re-sourced from merged header values.
fn fail_closed_bridged_trailer_split(
    response_headers: &HashMap<String, String>,
    encoded_names: &str,
) -> BridgedTrailerSplit {
    let mut trailers = HashMap::new();
    for name in encoded_names.split('\n').filter(|name| !name.is_empty()) {
        if !is_reserved_grpc_web_terminal_metadata(name) {
            continue;
        }
        if let Some(value) = response_headers.get(name).cloned().or_else(|| {
            response_headers
                .iter()
                .find(|(key, _)| key.eq_ignore_ascii_case(name))
                .map(|(_, value)| value.clone())
        }) {
            trailers.insert(name.to_string(), value);
        }
    }
    let mut initial = response_headers.clone();
    initial.remove(HEADER_GRPC_WEB_TRAILER_NAMES);
    initial.remove(HEADER_GRPC_WEB_SHADOWED_TRAILERS);
    for name in encoded_names.split('\n').filter(|name| !name.is_empty()) {
        initial.retain(|key, _| !key.eq_ignore_ascii_case(name));
    }
    BridgedTrailerSplit {
        initial_headers: initial,
        trailers,
        shadowed_keys: HashSet::new(),
    }
}

/// Move mesh-mTLS trailer provenance out of the response-header map before
/// response hooks run. The collision payload can contain application metadata
/// values and therefore must become redacted request-local metadata before a
/// debugger or custom hook can observe the backend response headers.
pub fn promote_bridged_trailer_provenance(
    metadata: &mut HashMap<String, String>,
    response_headers: &mut HashMap<String, String>,
) {
    if let Some(encoded) = response_headers.remove(HEADER_GRPC_WEB_TRAILER_NAMES) {
        metadata.insert(META_GRPC_WEB_TRAILER_NAMES.to_string(), encoded);
    }
    if let Some(encoded) = response_headers.remove(HEADER_GRPC_WEB_SHADOWED_TRAILERS) {
        metadata.insert(META_GRPC_WEB_SHADOWED_TRAILERS.to_string(), encoded);
    }
}

fn decode_shadowed_trailers_payload(encoded: &str) -> Option<HashMap<String, [String; 2]>> {
    let decoded = BASE64.decode(encoded).ok()?;
    serde_json::from_slice(&decoded).ok()
}

fn trailer_name_allowlist_from_metadata(
    metadata: &HashMap<String, String>,
) -> Option<HashSet<String>> {
    metadata.get(META_GRPC_WEB_TRAILER_NAMES).map(|encoded| {
        encoded
            .split('\n')
            .filter(|name| !name.is_empty())
            .map(str::to_string)
            .collect()
    })
}

/// Official HTTP→gRPC client mapping for responses that omit `grpc-status`.
///
/// Spec: <https://github.com/grpc/grpc/blob/master/doc/http-grpc-status-mapping.md>.
/// Used only when a numeric `grpc-status` is absent; a valid supplied status
/// remains authoritative. This is intentionally distinct from the gateway's
/// reject-path mapper (`http_reject_status_to_grpc_status`), which chooses
/// richer codes for Ferrum-authored refusals.
pub(crate) fn http_response_status_to_grpc_status(http_status: u16) -> u32 {
    match http_status {
        400 => 13,                   // INTERNAL
        401 => 16,                   // UNAUTHENTICATED
        403 => 7,                    // PERMISSION_DENIED
        404 => 12,                   // UNIMPLEMENTED
        429 | 502 | 503 | 504 => 14, // UNAVAILABLE
        _ => 2,                      // UNKNOWN (includes HTTP 200)
    }
}

/// Build a gRPC-Web trailer frame from response headers.
///
/// The trailer frame format is:
/// - 1 byte: 0x80 (trailer flag)
/// - 4 bytes: big-endian u32 length of trailer payload
/// - N bytes: trailer payload (HTTP header encoding: `key: value\r\n`)
///
/// When no present, numeric `grpc-status` exists, synthesize one from
/// `http_status` via [`http_response_status_to_grpc_status`]. Passing `None`
/// is equivalent to HTTP 200 (UNKNOWN), matching the mapping doc's default
/// for a completed response that still lacks status.
///
/// Valid ASCII custom trailing metadata is preserved alongside `grpc-*` and
/// `*-bin` fields, subject to hop-by-hop / forbidden / pseudo / connection-
/// listed exclusions and printable-ASCII value checks. Duplicate values stored
/// as newline-separated entries (gRPC multi-value metadata) emit as separate
/// `key: value\r\n` lines. Encoding order is sorted by lowercase header name
/// for deterministic frames.
pub(crate) fn build_trailer_frame(
    response_headers: &HashMap<String, String>,
    http_status: Option<u16>,
) -> Vec<u8> {
    build_trailer_frame_with_provenance(response_headers, http_status, None)
}

/// Build one terminal gRPC-Web DATA frame for a streaming response.
///
/// DATA emitted before this frame is relayed incrementally. The caller passes
/// only genuine backend trailers (or a Trailers-Only initial-header snapshot),
/// so initial response metadata cannot be copied into the terminal block.
/// Text mode deliberately base64-encodes this frame as its own padded segment;
/// the gRPC-Web protocol permits padding at runtime flush boundaries.
pub(crate) fn build_streaming_trailer_data(
    trailers: &HashMap<String, String>,
    http_status: u16,
    text_mode: bool,
) -> (Bytes, u32) {
    let grpc_status = trailers
        .get("grpc-status")
        .filter(|value| !value.contains('\r'))
        .and_then(|value| {
            value
                .split('\n')
                .find_map(|occurrence| occurrence.trim().parse::<u32>().ok())
        })
        .unwrap_or_else(|| http_response_status_to_grpc_status(http_status));
    let frame = build_trailer_frame(trailers, Some(http_status));
    let data = if text_mode {
        Bytes::from(BASE64.encode(frame))
    } else {
        Bytes::from(frame)
    };
    (data, grpc_status)
}

/// Encode one streaming gRPC DATA chunk for the selected gRPC-Web transport.
///
/// Binary mode is zero-copy. Text mode emits a self-contained base64 segment
/// so arbitrary backend chunk boundaries stay independently flushable and the
/// adapter never retains an unbounded tail.
pub(crate) fn encode_streaming_data(data: Bytes, text_mode: bool) -> Bytes {
    if text_mode {
        Bytes::from(BASE64.encode(data))
    } else {
        data
    }
}

/// Separate initial terminal metadata from the client-visible header map.
///
/// A genuine Trailers-Only response uses its pristine END_STREAM HEADERS block
/// as terminal provenance. Response hooks may remove or sanitize those fields,
/// but a later gateway-authored initial header must not become trailing
/// application metadata merely because the response has no DATA. Reserved
/// terminal fields are removed from ordinary initial headers on every
/// translated stream, including malformed non-ended responses.
pub(crate) fn take_streaming_initial_terminal_metadata(
    response_headers: &mut HashMap<String, String>,
    body_ended: bool,
    pristine_terminal_names: Option<&HashSet<String>>,
) -> HashMap<String, String> {
    let mut terminal = HashMap::new();
    if body_ended && let Some(pristine_terminal_names) = pristine_terminal_names {
        for (name, value) in response_headers.iter() {
            if pristine_terminal_names.contains(name) {
                terminal.insert(name.clone(), value.clone());
            }
        }
    }
    let application_terminal_names = terminal
        .keys()
        .filter(|name| {
            !is_reserved_grpc_web_terminal_metadata(name)
                && is_valid_trailer_header(name).is_some()
                && !is_forbidden_grpc_web_trailer_name(name)
        })
        .cloned()
        .collect::<Vec<_>>();
    for name in application_terminal_names {
        response_headers.remove(&name);
    }
    for name in ["grpc-status", "grpc-message", "grpc-status-details-bin"] {
        if let Some(value) = response_headers.remove(name)
            && body_ended
            && pristine_terminal_names.is_some_and(|names| names.contains(name))
        {
            terminal.insert(name.to_string(), value);
        }
    }
    terminal
}

/// Like [`build_trailer_frame`], optionally restricting embedded names to a
/// backend-trailer provenance allowlist (plus reserved gRPC terminal keys).
pub(crate) fn build_trailer_frame_with_provenance(
    response_headers: &HashMap<String, String>,
    http_status: Option<u16>,
    trailer_name_allowlist: Option<&HashSet<String>>,
) -> Vec<u8> {
    build_trailer_frame_with_full_provenance(
        response_headers,
        http_status,
        trailer_name_allowlist,
        None,
        None,
    )
}

/// Resolve the trailer value that should enter the gRPC-Web body frame.
///
/// Mirrors [`crate::proxy::grpc_proxy::reconcile_grpc_trailers_from_view`]:
/// a final initial-header policy set/override restores the pre-policy
/// application trailer, a final policy removal suppresses ordinary trailers
/// (reserved terminal metadata stays trailer-authoritative), and a later
/// genuine rewrite/removal (no remaining policy outcome) follows the live
/// merged view — including shadowed-name restoration while untouched.
///
/// The returned slice borrows from `view_value`, `shadowed_trailers`, or
/// `policy_state` — never a cloned upstream-controlled value — so the
/// two-pass trailer writer can emit each field straight through without
/// materialising a complete would-be payload segment beside the sink.
fn resolve_trailer_frame_value<'a>(
    name: &str,
    view_value: Option<&'a str>,
    shadowed_trailers: Option<&'a HashMap<String, [String; 2]>>,
    policy_state: Option<&'a BufferedInitialResponseHeaderPolicyState>,
) -> Option<&'a str> {
    if let Some((pre_policy_value, final_policy_value_present)) = policy_state
        .and_then(|state| state.application_trailer_initial_response_policy_outcome(name))
    {
        if !final_policy_value_present && !is_reserved_grpc_web_terminal_metadata(name) {
            return None;
        }
        if let Some(pre_policy_value) = pre_policy_value {
            if let Some([initial_value, trailer_value]) =
                shadowed_trailers.and_then(|shadowed| shadowed.get(name))
            {
                // Same-name collision: when the pre-policy outcome is the
                // genuine initial header, keep the true backend trailer.
                if initial_value.as_str() == pre_policy_value {
                    return Some(trailer_value.as_str());
                }
            }
            return Some(pre_policy_value);
        }
        return None;
    }
    let view_value = view_value?;
    // The compatibility view keeps an initial-header value when a backend
    // supplied the same name in HEADERS and TRAILERS. Use the true trailer
    // value only while that view is untouched. A hook-rewritten value wins,
    // and a removed name stays removed.
    if let Some([_initial_value, trailer_value]) = shadowed_trailers
        .and_then(|shadowed| shadowed.get(name))
        .filter(|[initial_value, _]| initial_value.as_str() == view_value)
    {
        return Some(trailer_value.as_str());
    }
    Some(view_value)
}

/// Outcome of a ceiling-bounded gRPC-Web trailer-frame reconciliation.
///
/// The charged original body stays alive for [`SyncTranslatedTrailerOutcome::Unchanged`]
/// and [`SyncTranslatedTrailerOutcome::NoRewrite`]. A
/// [`SyncTranslatedTrailerOutcome::Replaced`] buffer is built entirely through
/// a [`crate::proxy::response_buffer_budget::BoundedResponseBodySink`] and is
/// ready for [`crate::proxy::response_buffer_budget::ResponseTransformWindow::charge`].
#[derive(Debug)]
pub(crate) enum SyncTranslatedTrailerOutcome {
    /// Trailer suffix already matched the reconciled trailers; keep the original.
    Unchanged,
    /// Replacement bytes constructed under the retained ceiling.
    Replaced(Vec<u8>),
    /// Not gRPC-Web, malformed frames, or corrupt text armouring — leave the
    /// original body untouched.
    NoRewrite,
    /// Replacement admission failed, a write would have exceeded the retained
    /// ceiling, or u32/arithmetic overflow occurred while measuring the frame.
    Overflow,
}

/// Replace any trailing gRPC-Web trailer frame(s) in a buffered body with a
/// frame built from already-reconciled wire trailers.
///
/// Called after [`crate::proxy::grpc_proxy::reconcile_grpc_trailers_from_view`]
/// and *before* [`crate::proxy::grpc_proxy::discard_grpc_application_trailers_after_body_rewrite`]
/// so body-framed trailers match native H2/H3 policy semantics — including
/// ASCII/binary custom metadata — even when the transform-phase draft frame
/// still saw the post-policy merged view. Callers that discard application
/// trailers first leave only reserved terminal keys and rebuild a sparse frame.
///
/// Test-facing wrapper around [`sync_translated_body_trailer_frame_into`]: uses a
/// generous ceiling so behavioural unit tests that do not exercise the budget
/// keep working. Production final reconciliation goes through
/// [`crate::proxy::store_charged_grpc_web_reframed_body`], which reserves a real
/// transform window and publishes only a sink-built replacement
/// (GHSA-pwcm-6rh8-f2gh).
#[allow(dead_code)] // reached via `_test_support` from the external test crate
pub(crate) fn sync_translated_body_trailer_frame_from_trailers(
    body: &mut Vec<u8>,
    content_type: Option<&str>,
    reconciled_trailers: &HashMap<String, String>,
    http_status: Option<u16>,
) -> bool {
    let ceiling = body
        .len()
        .saturating_mul(2)
        .saturating_add(16 * 1024)
        .max(16 * 1024);
    match sync_translated_body_trailer_frame_into(
        body.as_slice(),
        content_type,
        reconciled_trailers,
        http_status,
        ceiling,
        || true,
    ) {
        SyncTranslatedTrailerOutcome::Unchanged => true,
        SyncTranslatedTrailerOutcome::Replaced(rebuilt) => {
            *body = rebuilt;
            true
        }
        SyncTranslatedTrailerOutcome::NoRewrite | SyncTranslatedTrailerOutcome::Overflow => false,
    }
}

/// Ceiling-bounded trailer-frame sync over an immutable collected body.
///
/// Binary and text modes validate a complete frame sequence and replace only the
/// contiguous trailer-frame suffix at end of stream. Construction writes from
/// the first replacement byte into a [`BoundedResponseBodySink`]; text mode
/// stream-decodes with a fixed scratch and stream-encodes through
/// [`base64::write::EncoderWriter`] so neither a decoded binary preimage, a
/// separately built trailer frame, nor a complete encoded `String` is ever
/// resident beside the output (GHSA-pwcm-6rh8-f2gh).
///
/// `admit_replacement` is invoked only after a rewrite is proven necessary and
/// immediately before the bounded sink can allocate. Production uses it to
/// reserve the covering aggregate-budget window; test-only callers admit
/// directly while exercising construction bounds.
pub(crate) fn sync_translated_body_trailer_frame_into(
    body: &[u8],
    content_type: Option<&str>,
    reconciled_trailers: &HashMap<String, String>,
    http_status: Option<u16>,
    ceiling: usize,
    admit_replacement: impl FnOnce() -> bool,
) -> SyncTranslatedTrailerOutcome {
    use crate::proxy::response_buffer_budget::BoundedResponseBodySink;

    let Some(content_type) = content_type.filter(|ct| is_grpc_web_content_type(ct)) else {
        return SyncTranslatedTrailerOutcome::NoRewrite;
    };
    let is_text = is_grpc_web_text(content_type);

    let Some((suffix_start, binary_len)) = (if is_text {
        scan_text_grpc_web_trailer_suffix(body)
    } else {
        trailing_trailer_suffix_start(body).map(|start| (start, body.len()))
    }) else {
        // The body transform always emits a complete trailing frame. Refuse to
        // invent frames when that invariant cannot be proven.
        return SyncTranslatedTrailerOutcome::NoRewrite;
    };

    // Measure the rebuilt trailer payload without retaining it. The counting
    // ceiling is the gRPC u32 frame-length domain (not the output sink): identity
    // short-circuit must not become a capacity refusal, and the bounded sink
    // still refuses any over-ceiling write during a real rebuild.
    let mut counted = CountingTrailerPayloadSink::with_ceiling(u32::MAX as usize);
    if !write_trailer_frame_payload(
        &mut counted,
        reconciled_trailers,
        http_status,
        None,
        None,
        None,
    ) {
        return SyncTranslatedTrailerOutcome::Overflow;
    }
    let payload_len_usize = counted.len;
    let Ok(payload_len) = u32::try_from(payload_len_usize) else {
        return SyncTranslatedTrailerOutcome::Overflow;
    };
    let mut frame_header = [0u8; GRPC_FRAME_HEADER_BYTES];
    frame_header[0] = GRPC_FRAME_TRAILER;
    frame_header[1..].copy_from_slice(&payload_len.to_be_bytes());
    let Some(expected_frame_len) = GRPC_FRAME_HEADER_BYTES.checked_add(payload_len_usize) else {
        return SyncTranslatedTrailerOutcome::Overflow;
    };
    let Some(existing_suffix_len) = binary_len.checked_sub(suffix_start) else {
        return SyncTranslatedTrailerOutcome::NoRewrite;
    };

    // Identity short-circuit: when hooks/policy left the trailer frame
    // byte-identical, keep the existing body (and avoid a text-mode re-encode).
    if existing_suffix_len == expected_frame_len
        && trailer_suffix_matches_reconciled(
            body,
            is_text,
            suffix_start,
            &frame_header,
            reconciled_trailers,
            http_status,
        )
    {
        return SyncTranslatedTrailerOutcome::Unchanged;
    }

    // Refuse a rebuild that cannot fit under the retained ceiling before the
    // sink materialises any replacement bytes.
    let binary_ceiling = if is_text { ceiling / 4 * 3 } else { ceiling };
    let Some(rebuild_binary_len) = suffix_start.checked_add(expected_frame_len) else {
        return SyncTranslatedTrailerOutcome::Overflow;
    };
    if rebuild_binary_len > binary_ceiling {
        return SyncTranslatedTrailerOutcome::Overflow;
    }
    if is_text {
        let Some(encoded_len) = rebuild_binary_len.div_ceil(3).checked_mul(4) else {
            return SyncTranslatedTrailerOutcome::Overflow;
        };
        if encoded_len > ceiling {
            return SyncTranslatedTrailerOutcome::Overflow;
        }
    } else if rebuild_binary_len > ceiling {
        return SyncTranslatedTrailerOutcome::Overflow;
    }

    // The caller reserves the covering aggregate-budget window only once a
    // replacement is proven necessary, and immediately before the sink can
    // make its first allocation. NoRewrite/Unchanged therefore cannot become
    // spurious capacity refusals under aggregate pressure.
    if !admit_replacement() {
        return SyncTranslatedTrailerOutcome::Overflow;
    }
    let mut output = BoundedResponseBodySink::with_ceiling(ceiling);
    let rebuilt_ok = if is_text {
        rebuild_text_grpc_web_trailer_suffix(
            body,
            suffix_start,
            &frame_header,
            reconciled_trailers,
            http_status,
            &mut output,
        )
    } else {
        rebuild_binary_grpc_web_trailer_suffix(
            body,
            suffix_start,
            &frame_header,
            reconciled_trailers,
            http_status,
            &mut output,
        )
    };
    if !rebuilt_ok || output.overflowed() {
        return SyncTranslatedTrailerOutcome::Overflow;
    }
    match output.finish() {
        Some(rebuilt) => SyncTranslatedTrailerOutcome::Replaced(rebuilt),
        None => SyncTranslatedTrailerOutcome::Overflow,
    }
}

/// Stream-decode standard base64 with a fixed 3-byte scratch and drive `consume`
/// for every decoded group. Rejects alphabet / padding / length errors.
///
/// `consume` returns `false` to abort early as a hard failure (caller maps that
/// to malformed or mismatch). No O(body) allocation is retained.
fn stream_decode_base64_groups(encoded: &[u8], mut consume: impl FnMut(&[u8]) -> bool) -> bool {
    if encoded.is_empty() {
        return true;
    }
    if !encoded.len().is_multiple_of(4) {
        return false;
    }
    let mut scratch = [0u8; 3];
    let mut pos = 0usize;
    while pos < encoded.len() {
        let group = &encoded[pos..pos + 4];
        if !is_base64_alphabet(group[0]) || !is_base64_alphabet(group[1]) {
            return false;
        }
        match (group[2], group[3]) {
            (b'=', b'=') => {}
            (b'=', _) => return false,
            (third, b'=') if is_base64_alphabet(third) => {}
            (third, fourth) if is_base64_alphabet(third) && is_base64_alphabet(fourth) => {}
            _ => return false,
        }
        let Ok(decoded_len) = BASE64.decode_slice(group, &mut scratch) else {
            return false;
        };
        if !consume(&scratch[..decoded_len]) {
            return false;
        }
        pos += 4;
        // Padding closes a flush segment; subsequent groups remain valid input
        // (gRPC-Web text permits padding at runtime flush boundaries).
    }
    true
}

/// Locate the trailer-frame suffix start and total binary length of a gRPC-Web
/// text body by streaming the base64 armouring through a fixed scratch.
fn scan_text_grpc_web_trailer_suffix(encoded: &[u8]) -> Option<(usize, usize)> {
    let mut scanner = GrpcWebFrameScanner::new();
    let ok = stream_decode_base64_groups(encoded, |decoded| scanner.push(decoded));
    if !ok || !scanner.finish() {
        return None;
    }
    Some((scanner.suffix_start?, scanner.binary_len))
}

/// Incremental gRPC/gRPC-Web frame scanner used over stream-decoded bytes.
struct GrpcWebFrameScanner {
    header: [u8; GRPC_FRAME_HEADER_BYTES],
    header_filled: usize,
    /// Binary offset of the first byte of the frame header currently being
    /// assembled. Meaningful only while `header_filled > 0`.
    header_frame_start: usize,
    payload_remaining: usize,
    current_flag: u8,
    in_payload: bool,
    binary_len: usize,
    suffix_start: Option<usize>,
    malformed: bool,
}

impl GrpcWebFrameScanner {
    fn new() -> Self {
        Self {
            header: [0u8; GRPC_FRAME_HEADER_BYTES],
            header_filled: 0,
            header_frame_start: 0,
            payload_remaining: 0,
            current_flag: 0,
            in_payload: false,
            binary_len: 0,
            suffix_start: None,
            malformed: false,
        }
    }

    fn push(&mut self, bytes: &[u8]) -> bool {
        if self.malformed {
            return false;
        }
        for &byte in bytes {
            if !self.push_byte(byte) {
                self.malformed = true;
                return false;
            }
        }
        true
    }

    fn push_byte(&mut self, byte: u8) -> bool {
        let offset = self.binary_len;
        self.binary_len = match self.binary_len.checked_add(1) {
            Some(n) => n,
            None => return false,
        };
        if !self.in_payload {
            if self.header_filled == 0 {
                self.header_frame_start = offset;
            }
            self.header[self.header_filled] = byte;
            self.header_filled += 1;
            if self.header_filled < GRPC_FRAME_HEADER_BYTES {
                return true;
            }
            self.current_flag = self.header[0];
            let len = u32::from_be_bytes([
                self.header[1],
                self.header[2],
                self.header[3],
                self.header[4],
            ]) as usize;
            self.payload_remaining = len;
            self.header_filled = 0;
            self.in_payload = true;
            if self.current_flag == GRPC_FRAME_TRAILER {
                if self.suffix_start.is_none() {
                    self.suffix_start = Some(self.header_frame_start);
                }
            } else {
                self.suffix_start = None;
            }
            if self.payload_remaining == 0 {
                self.in_payload = false;
            }
            return true;
        }
        self.payload_remaining -= 1;
        if self.payload_remaining == 0 {
            self.in_payload = false;
        }
        true
    }

    fn finish(&self) -> bool {
        !self.malformed
            && !self.in_payload
            && self.header_filled == 0
            && self.suffix_start.is_some()
    }
}

/// Compare an existing trailer-frame suffix against the reconciled trailers
/// without retaining a rebuilt frame or a decoded body copy.
fn trailer_suffix_matches_reconciled(
    body: &[u8],
    is_text: bool,
    suffix_start: usize,
    frame_header: &[u8; GRPC_FRAME_HEADER_BYTES],
    reconciled_trailers: &HashMap<String, String>,
    http_status: Option<u16>,
) -> bool {
    if is_text {
        let mut header_pos = 0usize;
        let mut binary_pos = 0usize;
        let header_ok = stream_decode_base64_groups(body, |decoded| {
            for &byte in decoded {
                if binary_pos < suffix_start {
                    binary_pos = binary_pos.saturating_add(1);
                    continue;
                }
                if header_pos < GRPC_FRAME_HEADER_BYTES {
                    if byte != frame_header[header_pos] {
                        return false;
                    }
                    header_pos += 1;
                    binary_pos = binary_pos.saturating_add(1);
                    continue;
                }
                // Payload bytes are compared by the pull-comparer below; stop
                // this scan once the header has been validated.
                return true;
            }
            true
        });
        if !header_ok || header_pos != GRPC_FRAME_HEADER_BYTES {
            return false;
        }
        let payload_start = match suffix_start.checked_add(GRPC_FRAME_HEADER_BYTES) {
            Some(n) => n,
            None => return false,
        };
        let mut iter = Base64DecodedByteIter::skipping(body, payload_start);
        let mut cmp = PullByteComparer {
            iter: &mut iter,
            mismatch: false,
        };
        if !write_trailer_frame_payload(
            &mut cmp,
            reconciled_trailers,
            http_status,
            None,
            None,
            None,
        ) {
            return false;
        }
        !cmp.mismatch && iter.next().is_none()
    } else {
        if suffix_start > body.len() {
            return false;
        }
        let suffix = &body[suffix_start..];
        if suffix.len() < GRPC_FRAME_HEADER_BYTES
            || suffix[..GRPC_FRAME_HEADER_BYTES] != frame_header[..]
        {
            return false;
        }
        let mut cmp = ObservedSliceComparer {
            observed: &suffix[GRPC_FRAME_HEADER_BYTES..],
            pos: 0,
            mismatch: false,
        };
        if !write_trailer_frame_payload(
            &mut cmp,
            reconciled_trailers,
            http_status,
            None,
            None,
            None,
        ) {
            return false;
        }
        !cmp.mismatch && cmp.pos == cmp.observed.len()
    }
}

/// Pull-comparer: [`write_trailer_frame_payload`] expected bytes against an
/// observed byte iterator (text-mode stream decode).
struct PullByteComparer<'a, I: Iterator<Item = u8>> {
    iter: &'a mut I,
    mismatch: bool,
}

impl<I: Iterator<Item = u8>> TrailerPayloadSink for PullByteComparer<'_, I> {
    fn append(&mut self, bytes: &[u8]) -> bool {
        if self.mismatch {
            return false;
        }
        for &expected in bytes {
            match self.iter.next() {
                Some(observed) if observed == expected => {}
                _ => {
                    self.mismatch = true;
                    return false;
                }
            }
        }
        true
    }
}

/// Slice comparer for binary-mode trailer payloads (random access, no copy).
struct ObservedSliceComparer<'a> {
    observed: &'a [u8],
    pos: usize,
    mismatch: bool,
}

impl TrailerPayloadSink for ObservedSliceComparer<'_> {
    fn append(&mut self, bytes: &[u8]) -> bool {
        if self.mismatch {
            return false;
        }
        let Some(end) = self.pos.checked_add(bytes.len()) else {
            self.mismatch = true;
            return false;
        };
        if end > self.observed.len() || self.observed[self.pos..end] != *bytes {
            self.mismatch = true;
            return false;
        }
        self.pos = end;
        true
    }
}

/// Fixed-scratch iterator over standard-base64-decoded bytes, optionally
/// skipping a binary prefix so callers can address a trailer payload region
/// without retaining a decoded body.
struct Base64DecodedByteIter<'a> {
    encoded: &'a [u8],
    enc_pos: usize,
    scratch: [u8; 3],
    scratch_len: usize,
    scratch_pos: usize,
    binary_emitted: usize,
    skip_until: usize,
    failed: bool,
}

impl<'a> Base64DecodedByteIter<'a> {
    fn skipping(encoded: &'a [u8], skip_until: usize) -> Self {
        Self {
            encoded,
            enc_pos: 0,
            scratch: [0u8; 3],
            scratch_len: 0,
            scratch_pos: 0,
            binary_emitted: 0,
            skip_until,
            failed: false,
        }
    }

    fn refill(&mut self) -> bool {
        if self.failed {
            return false;
        }
        if self.enc_pos >= self.encoded.len() {
            return false;
        }
        if self.enc_pos + 4 > self.encoded.len() || !self.encoded.len().is_multiple_of(4) {
            self.failed = true;
            return false;
        }
        let group = &self.encoded[self.enc_pos..self.enc_pos + 4];
        if !is_base64_alphabet(group[0]) || !is_base64_alphabet(group[1]) {
            self.failed = true;
            return false;
        }
        match (group[2], group[3]) {
            (b'=', b'=') => {}
            (b'=', _) => {
                self.failed = true;
                return false;
            }
            (third, b'=') if is_base64_alphabet(third) => {}
            (third, fourth) if is_base64_alphabet(third) && is_base64_alphabet(fourth) => {}
            _ => {
                self.failed = true;
                return false;
            }
        }
        match BASE64.decode_slice(group, &mut self.scratch) {
            Ok(n) => {
                self.scratch_len = n;
                self.scratch_pos = 0;
                self.enc_pos += 4;
                true
            }
            Err(_) => {
                self.failed = true;
                false
            }
        }
    }
}

impl Iterator for Base64DecodedByteIter<'_> {
    type Item = u8;

    fn next(&mut self) -> Option<u8> {
        loop {
            if self.failed {
                return None;
            }
            if self.scratch_pos < self.scratch_len {
                let byte = self.scratch[self.scratch_pos];
                self.scratch_pos += 1;
                let at = self.binary_emitted;
                self.binary_emitted = self.binary_emitted.saturating_add(1);
                if at < self.skip_until {
                    continue;
                }
                return Some(byte);
            }
            if !self.refill() {
                return None;
            }
        }
    }
}

fn rebuild_binary_grpc_web_trailer_suffix(
    body: &[u8],
    suffix_start: usize,
    frame_header: &[u8; GRPC_FRAME_HEADER_BYTES],
    reconciled_trailers: &HashMap<String, String>,
    http_status: Option<u16>,
    output: &mut crate::proxy::response_buffer_budget::BoundedResponseBodySink,
) -> bool {
    if suffix_start > body.len() {
        return false;
    }
    if !output.push(&body[..suffix_start]) {
        return false;
    }
    if !output.push(frame_header) {
        return false;
    }
    write_trailer_frame_payload(output, reconciled_trailers, http_status, None, None, None)
}

fn rebuild_text_grpc_web_trailer_suffix(
    encoded: &[u8],
    suffix_start: usize,
    frame_header: &[u8; GRPC_FRAME_HEADER_BYTES],
    reconciled_trailers: &HashMap<String, String>,
    http_status: Option<u16>,
    output: &mut crate::proxy::response_buffer_budget::BoundedResponseBodySink,
) -> bool {
    use std::io::Write;
    let engine = BASE64;
    {
        let mut encoder = base64::write::EncoderWriter::new(&mut *output, &engine);
        let mut binary_pos = 0usize;
        let prefix_ok = stream_decode_base64_groups(encoded, |decoded| {
            if binary_pos >= suffix_start {
                return true;
            }
            let remaining = suffix_start - binary_pos;
            let take = remaining.min(decoded.len());
            if encoder.write_all(&decoded[..take]).is_err() {
                return false;
            }
            binary_pos = binary_pos.saturating_add(take);
            true
        });
        if !prefix_ok || binary_pos != suffix_start {
            return false;
        }
        if encoder.write_all(frame_header).is_err() {
            return false;
        }
        if !write_trailer_frame_payload(
            &mut WriterTrailerPayloadSink(&mut encoder),
            reconciled_trailers,
            http_status,
            None,
            None,
            None,
        ) {
            return false;
        }
        if encoder.finish().is_err() {
            return false;
        }
    }
    true
}

/// Locate the start of the contiguous trailer-frame suffix that reaches
/// end-of-stream on a fully valid gRPC/gRPC-Web frame sequence.
///
/// Returns `None` when the stream is malformed (length overrun / trailing
/// garbage) or does not end in a trailer frame — matching the fail-closed
/// contract of the previous quadratic truncate loop without mutating `data`.
fn trailing_trailer_suffix_start(data: &[u8]) -> Option<usize> {
    let mut pos = 0;
    let mut suffix_start: Option<usize> = None;
    while pos + 5 <= data.len() {
        let flag = data[pos];
        let len = u32::from_be_bytes([data[pos + 1], data[pos + 2], data[pos + 3], data[pos + 4]])
            as usize;
        let frame_start = pos;
        pos += 5;
        if pos + len > data.len() {
            return None;
        }
        if flag == GRPC_FRAME_TRAILER {
            if suffix_start.is_none() {
                suffix_start = Some(frame_start);
            }
        } else {
            // A data (or non-trailer) frame ends any trailer suffix so far.
            suffix_start = None;
        }
        pos += len;
    }
    if pos != data.len() {
        return None;
    }
    suffix_start
}

/// Drop trailing gRPC-Web trailer frames (flag `0x80`) from a binary body so a
/// reconciled frame can replace the transform-phase draft.
///
/// Single O(n) scan: identify the contiguous trailer-frame suffix at EOS and
/// truncate once. Malformed streams leave `data` untouched and return `false`.
#[allow(dead_code)] // reached via `_test_support` from the external test crate
pub(crate) fn truncate_trailing_trailer_frames(data: &mut Vec<u8>) -> bool {
    let Some(start) = trailing_trailer_suffix_start(data) else {
        return false;
    };
    data.truncate(start);
    true
}

/// Append-only sink for the trailer-frame payload.
///
/// The payload is built exactly once, by [`write_trailer_frame_payload`], for
/// two very different destinations: the gateway-authored error frames (which are
/// fixed-shape and unbounded by construction) and the retained producer frame,
/// whose upstream-controlled trailer values must not be able to materialise a
/// complete over-ceiling `Vec` before the output bound applies
/// (GHSA-pwcm-6rh8-f2gh). One writer, two sinks — so the two can never drift.
trait TrailerPayloadSink {
    /// `false` means the append was refused and nothing was written.
    fn append(&mut self, bytes: &[u8]) -> bool;
}

impl TrailerPayloadSink for Vec<u8> {
    fn append(&mut self, bytes: &[u8]) -> bool {
        self.extend_from_slice(bytes);
        true
    }
}

impl TrailerPayloadSink for crate::proxy::response_buffer_budget::BoundedResponseBodySink {
    fn append(&mut self, bytes: &[u8]) -> bool {
        self.push(bytes)
    }
}

/// Measure the trailer payload without retaining a byte of it.
///
/// The frame header carries the payload LENGTH, so the length has to be known
/// before the payload can be written — and the retained-response bound
/// (GHSA-pwcm-6rh8-f2gh) forbids learning it by building the payload first and
/// measuring it afterwards, because that complete payload is upstream-controlled
/// and would be resident beside the output sink. So the payload is emitted
/// TWICE from the same writer: once into this counter, once into the final
/// bounded destination. Both passes read the same immutable header map, so they
/// cannot disagree — and the caller re-checks the written length anyway.
///
/// The counter is itself bounded, so a header block that could not fit the frame
/// is refused during the counting pass rather than after it.
struct CountingTrailerPayloadSink {
    len: usize,
    ceiling: usize,
    overflowed: bool,
}

impl CountingTrailerPayloadSink {
    fn with_ceiling(ceiling: usize) -> Self {
        Self {
            len: 0,
            ceiling,
            overflowed: false,
        }
    }
}

impl TrailerPayloadSink for CountingTrailerPayloadSink {
    fn append(&mut self, bytes: &[u8]) -> bool {
        if self.overflowed {
            return false;
        }
        // Checked, not saturating: an arithmetic overflow is an impossible total
        // and must fail closed rather than wrap into an affordable length.
        let Some(next) = self.len.checked_add(bytes.len()) else {
            self.overflowed = true;
            return false;
        };
        if next > self.ceiling {
            self.overflowed = true;
            return false;
        }
        self.len = next;
        true
    }
}

/// Write the payload straight through an [`std::io::Write`] — the base64
/// encoder that streams into the text-mode output sink.
///
/// The encoder writes armoured bytes into the ceiling-bounded sink as they are
/// produced, so neither a complete binary preimage nor a complete encoded
/// `String` is ever materialised beside the output.
struct WriterTrailerPayloadSink<'w, W: std::io::Write>(&'w mut W);

impl<W: std::io::Write> TrailerPayloadSink for WriterTrailerPayloadSink<'_, W> {
    fn append(&mut self, bytes: &[u8]) -> bool {
        self.0.write_all(bytes).is_ok()
    }
}

/// Bytes of the gRPC frame header: one compressed flag plus a 4-byte
/// big-endian message length.
const GRPC_FRAME_HEADER_BYTES: usize = 5;

fn build_trailer_frame_with_full_provenance(
    response_headers: &HashMap<String, String>,
    http_status: Option<u16>,
    trailer_name_allowlist: Option<&HashSet<String>>,
    shadowed_trailers: Option<&HashMap<String, [String; 2]>>,
    policy_state: Option<&BufferedInitialResponseHeaderPolicyState>,
) -> Vec<u8> {
    let mut payload: Vec<u8> = Vec::new();
    // A `Vec` sink never refuses, so this is total for the gateway-authored
    // callers; the bounded producer path uses `write_trailer_frame_payload`
    // directly against a ceiling-bounded sink.
    write_trailer_frame_payload(
        &mut payload,
        response_headers,
        http_status,
        trailer_name_allowlist,
        shadowed_trailers,
        policy_state,
    );
    let mut frame = Vec::with_capacity(GRPC_FRAME_HEADER_BYTES + payload.len());
    frame.push(GRPC_FRAME_TRAILER);
    frame.extend_from_slice(&(payload.len() as u32).to_be_bytes());
    frame.extend(payload);
    frame
}

/// Write the trailer-frame payload (the `name: value\r\n` block that follows the
/// 5-byte frame header) into `payload`.
///
/// Returns `false` only when the sink refused a write, which the bounded
/// producer path treats as "no translation" and fails closed on.
///
/// Nothing eligible is RETAINED here: names are sorted up front (a stable sort
/// over names alone reproduces exactly what a stable sort over `(name, value)`
/// pairs produced, because every occurrence a candidate contributes carries that
/// candidate's name), and each field's value is borrowed from the immutable
/// inputs, emitted straight through, and dropped before the next one is
/// resolved. That is what lets the bounded producer path run this writer against
/// a counter and then against the final sink without ever holding a complete
/// trailer payload or a cloned upstream-controlled value (GHSA-pwcm-6rh8-f2gh).
fn write_trailer_frame_payload<'a, S: TrailerPayloadSink>(
    payload: &mut S,
    response_headers: &'a HashMap<String, String>,
    http_status: Option<u16>,
    trailer_name_allowlist: Option<&HashSet<String>>,
    shadowed_trailers: Option<&'a HashMap<String, [String; 2]>>,
    policy_state: Option<&'a BufferedInitialResponseHeaderPolicyState>,
) -> bool {
    let connection_listed = parse_connection_listed_from_str_map(response_headers);
    // Candidate names are the live view plus any allowlisted trailer that a
    // final initial-header policy removed from the compatibility view.
    // Reserved terminal metadata must still frame from the pre-policy trailer
    // outcome (matching `reconcile_grpc_trailers_from_view`).
    let mut candidate_names: Vec<String> = response_headers
        .keys()
        .filter_map(|key| is_valid_trailer_header(key).map(|name| name.as_str().to_string()))
        .collect();
    if let Some(allowlist) = trailer_name_allowlist {
        for name in allowlist {
            if is_valid_trailer_header(name).is_some()
                && !candidate_names.iter().any(|existing| existing == name)
            {
                candidate_names.push(name.clone());
            }
        }
    }
    // Deterministic ordering: sort by name, and keep relative occurrence order
    // for duplicates of the same name. Sorting the NAMES (stably) before
    // resolution is equivalent to the previous stable sort of resolved
    // `(name, value)` pairs — all of a candidate's occurrences share its name
    // and stay contiguous either way — and it is what removes the retained
    // pair vector.
    candidate_names.sort();

    let mut has_grpc_status = false;
    for name in candidate_names {
        if connection_listed
            .iter()
            .any(|listed| listed.eq_ignore_ascii_case(&name))
        {
            continue;
        }
        if let Some(allowlist) = trailer_name_allowlist
            && !allowlist.contains(&name)
            && !is_reserved_grpc_web_terminal_metadata(&name)
        {
            continue;
        }
        let view_value = response_headers.get(&name).map(String::as_str).or_else(|| {
            response_headers
                .iter()
                .find(|(key, _)| key.eq_ignore_ascii_case(&name))
                .map(|(_, value)| value.as_str())
        });
        let Some(value) =
            resolve_trailer_frame_value(&name, view_value, shadowed_trailers, policy_state)
        else {
            continue;
        };
        // Multi-value gRPC metadata is stored LF-joined in the string map (see
        // `collect_buffered_grpc_trailers`). A carriage return can only come
        // from a malformed value, not that representation; reject the entire
        // field before splitting so `line\r\ninjected` cannot turn its suffix
        // into a second, apparently valid metadata occurrence.
        if value.contains('\r') {
            continue;
        }
        // Emit each occurrence as its own trailer line and retain the ordinary
        // printable-ASCII check for every LF-separated value. The occurrence is
        // written straight through and never accumulated.
        for occurrence in value.split('\n') {
            if !is_valid_trailer_value(occurrence) {
                continue;
            }
            if name == "grpc-status" {
                // Only a present, numeric grpc-status is a valid terminal
                // status. An empty (`grpc-status:`) or non-numeric
                // (`grpc-status: abc`) value is malformed — skip forwarding it
                // so the synthesized mapped status below is emitted instead of
                // passing a bogus status (or duplicating it).
                let Ok(code) = occurrence.trim().parse::<u32>() else {
                    continue;
                };
                // Prefer the first valid grpc-status when duplicates are present.
                if has_grpc_status {
                    continue;
                }
                has_grpc_status = true;
                // Emit the normalized (parsed) value, not the raw header, so the
                // forwarded frame is self-consistent with what was validated
                // (e.g. any surrounding OWS is dropped).
                if !payload.append(b"grpc-status: ")
                    || !payload.append(code.to_string().as_bytes())
                    || !payload.append(b"\r\n")
                {
                    return false;
                }
                continue;
            }
            if !payload.append(name.as_bytes())
                || !payload.append(b": ")
                || !payload.append(occurrence.as_bytes())
                || !payload.append(b"\r\n")
            {
                return false;
            }
        }
    }

    // A backend response without a present, numeric grpc-status is malformed /
    // non-gRPC. Apply the official client HTTP→gRPC mapping so intermediaries
    // that return 401/403/404/429/502/503/504 without grpc-status do not
    // collapse to UNKNOWN and break retry classification.
    if !has_grpc_status {
        let mapped = http_response_status_to_grpc_status(http_status.unwrap_or(200));
        if !payload.append(b"grpc-status: ")
            || !payload.append(mapped.to_string().as_bytes())
            || !payload.append(b"\r\n")
        {
            return false;
        }
    }
    true
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

/// Map an original gRPC-Web content-type to the canonical response content-type.
///
/// Preserves any supported message-format suffix (`+proto`, `+json`, `+thrift`,
/// or another valid `+subtype`). Unrecognized inputs fall back to binary
/// `application/grpc-web` rather than reflecting hostile values.
pub(crate) fn response_content_type(original_ct: &str) -> String {
    match grpc_web_media_type(original_ct) {
        Some(media) => canonical_grpc_web_content_type(&media),
        None => APPLICATION_GRPC_WEB.to_string(),
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

    fn enforces_finalized_request_policy(&self) -> bool {
        true
    }

    fn modifies_request_headers(&self) -> bool {
        true
    }

    fn modifies_request_body(&self) -> bool {
        true
    }

    fn needs_final_request_body_context(&self) -> bool {
        // H1/H2 creates the mutable body-hook context only for plugins that opt
        // in here. Multi-instance text decode and final framing validation must
        // see the owner/once metadata just like the H3 path does.
        true
    }

    fn should_buffer_request_body(&self, ctx: &RequestContext) -> bool {
        // gRPC-Web does not support client/request streaming. Buffer both
        // owned modes so binary passthrough and decoded text traverse the same
        // complete-envelope validation boundary before backend dispatch.
        // Native gRPC requests have no owner marker and remain streaming.
        ctx.metadata
            .get(META_GRPC_WEB_MODE)
            .is_some_and(|mode| mode == "text" || mode == "binary")
    }

    fn requires_response_body_buffering(&self) -> bool {
        // The shared streaming adapter relays DATA incrementally and converts
        // the terminal native trailer block into one body-framed gRPC-Web
        // trailer. Explicit buffer mode and other body plugins may still select
        // the slice-based transform below.
        false
    }

    fn should_buffer_response_body(&self, _ctx: &RequestContext) -> bool {
        false
    }

    fn should_buffer_response_body_for_content_type(
        &self,
        _ctx: &RequestContext,
        _content_type: Option<&str>,
        _response_status: u16,
        _response_headers: &HashMap<String, String>,
    ) -> bool {
        false
    }

    fn should_release_response_body_before_content_type_rewrite(
        &self,
        _ctx: &RequestContext,
        _response_status: u16,
        _response_headers: &HashMap<String, String>,
    ) -> bool {
        false
    }

    async fn on_request_received(&self, ctx: &mut RequestContext) -> PluginResult {
        // Always strip the internal mode marker from inbound headers so a client
        // cannot spoof it. The translation owner re-injects it in `before_proxy`
        // only after confirming a genuine gRPC-Web request via the content-type.
        // Without this, a client could send a non-gRPC-Web request with
        // `x-grpc-web-mode: text` and trigger base64-decode of the body in
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

        // First effective instance in configured order owns translation. A
        // later instance must not overwrite shared staging or re-claim when the
        // content-type is somehow still gRPC-Web (fail closed).
        if let Some(owner) = ctx.metadata.get(META_GRPC_WEB_OWNER) {
            debug!(
                plugin = "grpc_web",
                instance = %self.instance_id_str,
                owner = %owner,
                "Skipping gRPC-Web claim; another instance already owns translation"
            );
            return PluginResult::Continue;
        }

        // Request decoding mode follows Content-Type only.
        let mode = if is_grpc_web_text(&content_type) {
            "text"
        } else {
            "binary"
        };

        // Response encoding follows Accept negotiation (default: request CT).
        // Negotiate before claiming ownership so a 406 does not leave a
        // half-owned translation claim for later hooks to honor.
        let accept = request_accept_header(ctx);
        let response_ct = match accept
            .and_then(|accept| negotiate_response_media_type(&content_type, accept.as_deref()))
        {
            Ok(negotiated) => negotiated,
            Err(err) => {
                debug!(
                    plugin = "grpc_web",
                    instance = %self.instance_id_str,
                    ?err,
                    "Rejecting gRPC-Web request: Accept negotiation failed"
                );
                ctx.metadata
                    .insert(META_GRPC_WEB_ACCEPT_REJECTED.to_string(), "1".to_string());
                return PluginResult::Reject {
                    status_code: 406,
                    body:
                        r#"{"error":"Not Acceptable: no supported gRPC-Web response media type"}"#
                            .to_string(),
                    headers: HashMap::from([
                        ("content-type".to_string(), "application/json".to_string()),
                        ("vary".to_string(), "Accept".to_string()),
                        (HEADER_GRPC_WEB_ACCEPT_REJECTED.to_string(), "1".to_string()),
                    ]),
                };
            }
        };

        debug!(
            plugin = "grpc_web",
            instance = %self.instance_id_str,
            mode = mode,
            original_ct = %content_type,
            response_ct = %response_ct,
            "Detected gRPC-Web request; claiming translation ownership"
        );

        // Canonical shared markers for proxy/H3 consumers, plus namespaced
        // per-instance staging so siblings cannot collide on mode state.
        // `META_GRPC_WEB_ORIGINAL_CT` stores the negotiated response media type
        // (already canonical), not the request Content-Type.
        ctx.metadata.insert(
            META_GRPC_WEB_OWNER.to_string(),
            self.instance_id_str.clone(),
        );
        ctx.metadata
            .insert(META_GRPC_WEB_MODE.to_string(), mode.to_string());
        ctx.metadata
            .insert(META_GRPC_WEB_ORIGINAL_CT.to_string(), response_ct);
        ctx.metadata
            .insert(self.instance_mode_key.clone(), mode.to_string());

        // Rewrite content-type so downstream plugins and the gRPC proxy
        // treat this as a native gRPC request. Sibling instances then see
        // `application/grpc` and do not attempt a second claim.
        ctx.headers
            .insert("content-type".to_string(), "application/grpc".to_string());

        PluginResult::Continue
    }

    async fn before_proxy(
        &self,
        ctx: &mut RequestContext,
        headers: &mut HashMap<String, String>,
    ) -> PluginResult {
        // Only the translation owner injects shared request staging. Followers
        // must not rewrite headers or plant `x-grpc-web-mode` (that shared
        // marker would otherwise collide across instances).
        if !self.is_translation_owner(ctx) {
            return PluginResult::Continue;
        }

        let Some(mode) = self.owned_translation_mode(ctx).map(str::to_string) else {
            debug!(
                plugin = "grpc_web",
                instance = %self.instance_id_str,
                "Fail closed: translation owner missing or malformed mode staging"
            );
            return PluginResult::Continue;
        };

        // Ensure outgoing content-type is native gRPC
        headers.insert("content-type".to_string(), "application/grpc".to_string());

        // Compatibility marker for the legacy no-context transform path.
        // Production uses `transform_request_body_with_context` + metadata.
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
        // Legacy path without request context: honor the owner-injected mode
        // marker only. Multi-instance production traffic uses
        // `transform_request_body_with_context`, which gates on ownership and
        // the once-decoded flag.
        let is_text = request_headers
            .get(HEADER_GRPC_WEB_MODE)
            .is_some_and(|m| m == "text");

        if !is_text || body.is_empty() {
            return None;
        }

        // Base64 decode — gRPC-Web text mode uses standard base64 and may
        // concatenate independently padded flush segments.
        // On failure, return the raw body unchanged; on_final_request_body will
        // reject it with a 400 after validating gRPC framing.
        match decode_grpc_web_text_body(body) {
            Some(decoded) => {
                debug!(
                    plugin = "grpc_web",
                    instance = %self.instance_id_str,
                    original_len = body.len(),
                    decoded_len = decoded.len(),
                    "Base64-decoded gRPC-Web text request body"
                );
                Some(decoded)
            }
            None => {
                debug!(
                    plugin = "grpc_web",
                    instance = %self.instance_id_str,
                    "Failed to base64-decode gRPC-Web text request body"
                );
                // Return None to pass through; on_final_request_body will catch
                // the invalid framing and reject with 400.
                None
            }
        }
    }

    async fn transform_request_body_with_context(
        &self,
        ctx: &mut RequestContext,
        body: &[u8],
        _content_type: Option<&str>,
        _request_headers: &HashMap<String, String>,
    ) -> Option<Vec<u8>> {
        if !self.is_translation_owner(ctx) {
            return None;
        }
        // Exactly-once translation across the effective instance chain.
        if ctx.metadata.contains_key(META_GRPC_WEB_REQUEST_DECODED) {
            return None;
        }
        // Copy the mode out before touching `ctx.metadata` below.
        let is_text = match self.owned_translation_mode(ctx) {
            Some(mode) => mode == "text",
            None => {
                debug!(
                    plugin = "grpc_web",
                    instance = %self.instance_id_str,
                    "Fail closed: refusing request-body decode without valid mode staging"
                );
                return None;
            }
        };
        if body.is_empty() {
            return None;
        }

        // Decode from owner-scoped metadata, not the shared `x-grpc-web-mode`
        // staging header — siblings must never collide on that header.
        let decoded = if is_text {
            match decode_grpc_web_text_body(body) {
                Some(decoded) => {
                    debug!(
                        plugin = "grpc_web",
                        instance = %self.instance_id_str,
                        original_len = body.len(),
                        decoded_len = decoded.len(),
                        "Base64-decoded gRPC-Web text request body"
                    );
                    Some(decoded)
                }
                None => {
                    debug!(
                        plugin = "grpc_web",
                        instance = %self.instance_id_str,
                        "Failed to base64-decode gRPC-Web text request body"
                    );
                    // Leave the body untouched; the envelope validator rejects
                    // the undecodable bytes with a 400 before dispatch.
                    return None;
                }
            }
        } else {
            None
        };
        let framed = decoded.as_deref().unwrap_or(body);

        // Split the terminal trailer frame, if any, off the message frames. The
        // backend-bound body keeps only DATA; the trailer block is staged for
        // conversion into a real HTTP/2 TRAILERS frame at dispatch.
        let split = match split_request_trailer_frame(framed) {
            Ok(split) => split,
            Err(error) => {
                debug!(
                    plugin = "grpc_web",
                    instance = %self.instance_id_str,
                    reason = error,
                    "Rejecting gRPC-Web request trailer frame"
                );
                // This hook cannot reject. Stage the diagnostic and mark the
                // request translated so `on_final_request_body_with_context`
                // fails it closed with a field-specific message.
                ctx.metadata.insert(
                    META_GRPC_WEB_REQUEST_TRAILER_ERROR.to_string(),
                    error.to_string(),
                );
                ctx.metadata.insert(
                    META_GRPC_WEB_REQUEST_DECODED.to_string(),
                    self.instance_id_str.clone(),
                );
                return None;
            }
        };

        let stripped = match split {
            Some(frame) => {
                debug!(
                    plugin = "grpc_web",
                    instance = %self.instance_id_str,
                    trailer_count = frame.trailers.len(),
                    data_len = frame.data_end,
                    "Converted gRPC-Web request trailer frame to native gRPC trailers"
                );
                let encoded = match encode_request_trailers(&frame.trailers) {
                    Ok(encoded) => encoded,
                    Err(error) => {
                        ctx.metadata.insert(
                            META_GRPC_WEB_REQUEST_TRAILER_ERROR.to_string(),
                            error.to_string(),
                        );
                        ctx.metadata.insert(
                            META_GRPC_WEB_REQUEST_DECODED.to_string(),
                            self.instance_id_str.clone(),
                        );
                        return None;
                    }
                };
                ctx.metadata
                    .insert(META_GRPC_WEB_REQUEST_TRAILERS.to_string(), encoded);
                Some(framed[..frame.data_end].to_vec())
            }
            None => None,
        };
        // `framed` borrows `decoded`; that borrow ends above so the text-mode
        // decode can be moved out below.
        let output = match stripped {
            Some(output) => output,
            // Nothing to strip: forward the decoded bytes in text mode, and
            // leave a binary body untouched.
            None => decoded?,
        };

        ctx.metadata.insert(
            META_GRPC_WEB_REQUEST_DECODED.to_string(),
            self.instance_id_str.clone(),
        );
        Some(output)
    }

    async fn on_final_request_body(
        &self,
        headers: &HashMap<String, String>,
        body: &[u8],
    ) -> PluginResult {
        // Legacy path: validate when the owner-injected mode marker names a
        // recognized gRPC-Web transport. Production uses the owner-scoped
        // context path below.
        let Some(mode) = headers.get(HEADER_GRPC_WEB_MODE).map(String::as_str) else {
            return PluginResult::Continue;
        };
        if mode != "text" && mode != "binary" {
            return PluginResult::Continue;
        }

        validate_grpc_web_request_frames(body, headers)
            .map_or_else(invalid_grpc_web_request, |()| PluginResult::Continue)
    }

    async fn on_final_request_body_with_context(
        &self,
        ctx: &mut RequestContext,
        headers: &HashMap<String, String>,
        body: &[u8],
    ) -> PluginResult {
        // Only the translation owner validates gRPC-Web framing. Followers
        // must not re-validate (or reject) after the owner's decode.
        if !self.is_translation_owner(ctx) {
            return PluginResult::Continue;
        }
        let Some(mode) = self.owned_translation_mode(ctx) else {
            debug!(
                plugin = "grpc_web",
                instance = %self.instance_id_str,
                "Fail closed: translation owner missing mode staging at final request body"
            );
            return PluginResult::Continue;
        };
        if mode != "text" && mode != "binary" {
            return PluginResult::Continue;
        }
        // A trailer frame that failed validation in the body transform is a
        // terminal client error: reject with its field-specific diagnostic
        // before the request can reach the backend without its trailers.
        if let Some(error) = ctx.metadata.get(META_GRPC_WEB_REQUEST_TRAILER_ERROR) {
            return invalid_grpc_web_request(error);
        }
        validate_grpc_web_request_frames(body, headers)
            .map_or_else(invalid_grpc_web_request, |()| PluginResult::Continue)
    }

    fn may_modify_response_content_type(
        &self,
        ctx: &RequestContext,
        _response_content_type: Option<&str>,
    ) -> bool {
        // `after_proxy` relabels the response `Content-Type` to the gRPC-Web
        // variant exactly when `on_request_received` recorded the original
        // gRPC-Web content-type — independent of the backend response type, so
        // the request marker alone is the precise signal. Signal that so an
        // already-buffered response is inspected against its final gRPC-Web
        // representation instead of trusting the backend's
        // `application/grpc` header for the content-type refinement decision.
        retained_response_content_type(ctx).is_some()
    }

    /// An untranslated gRPC-Web request keeps the Plain wire flavor and can
    /// therefore reach a trailer-forwarding HTTP/3 relay while this
    /// `after_proxy` still runs its unconditional bridge-header strip. Declaring
    /// the bounded owned set keeps that strip — and the negotiated
    /// `content-type` / `x-grpc-web` / `vary` /
    /// `access-control-expose-headers` writes — binding on the trailer section
    /// instead of only the initial header map.
    fn response_trailer_policy(&self) -> super::ResponseTrailerPolicy<'_> {
        super::ResponseTrailerPolicy::Names(&GRPC_WEB_RESPONSE_POLICY_NAMES)
    }

    async fn after_proxy(
        &self,
        ctx: &mut RequestContext,
        response_status: u16,
        response_headers: &mut HashMap<String, String>,
    ) -> PluginResult {
        // Always strip the internal trailer-name bridge header first so a
        // preserved 206/226 (or any early-return path) cannot leak provenance
        // metadata to the client. Promote into request metadata when present
        // so a later allowed rewrite can still honor trailer provenance.
        if let Some(encoded) = response_headers.remove(HEADER_GRPC_WEB_TRAILER_NAMES) {
            ctx.metadata
                .insert(META_GRPC_WEB_TRAILER_NAMES.to_string(), encoded);
        }
        if let Some(encoded) = response_headers.remove(HEADER_GRPC_WEB_SHADOWED_TRAILERS) {
            ctx.metadata
                .insert(META_GRPC_WEB_SHADOWED_TRAILERS.to_string(), encoded);
        }

        if ctx.metadata.contains_key(META_GRPC_WEB_ACCEPT_REJECTED) {
            return PluginResult::Continue;
        }

        // The shared lifecycle cannot embed trailers or base64-rewrite a
        // preserved 206/226 representation. Leave its native headers coherent
        // with the untouched bytes instead of falsely labelling it gRPC-Web.
        if !super::response_body_rewrite_allowed(response_status) {
            return PluginResult::Continue;
        }

        // Require a claimed translation owner. Retained-only client content
        // types (H3 pass-through without this plugin's claim) must not be
        // rewritten by a co-located instance, and missing ownership is fail
        // closed rather than inferred from response content-type alone.
        if !ctx.metadata.contains_key(META_GRPC_WEB_OWNER) {
            return PluginResult::Continue;
        }

        let Some(original_ct) = ctx.metadata.get(META_GRPC_WEB_ORIGINAL_CT).cloned() else {
            debug!(
                plugin = "grpc_web",
                instance = %self.instance_id_str,
                "Fail closed: translation owner present without original content-type staging"
            );
            return PluginResult::Continue;
        };

        let is_owner = self.is_translation_owner(ctx);

        if is_owner {
            // Stash the backend HTTP status for trailer-frame synthesis. A valid
            // backend `grpc-status` stays authoritative; the mapper only runs when
            // that status is absent/malformed. The client-visible HTTP status is
            // intentionally not rewritten here (see module docs). Only the owner
            // writes this shared key so siblings cannot overwrite it.
            ctx.metadata.insert(
                META_GRPC_WEB_HTTP_STATUS.to_string(),
                response_status.to_string(),
            );

            // Rewrite response content-type to the negotiated gRPC-Web variant
            // (already canonical in metadata from Accept negotiation).
            let resp_ct = original_ct;
            response_headers.insert("content-type".to_string(), resp_ct.clone());

            // Signal to clients that this is a gRPC-Web response
            response_headers.insert("x-grpc-web".to_string(), "1".to_string());
            ensure_vary_accept(response_headers);

            debug!(
                plugin = "grpc_web",
                instance = %self.instance_id_str,
                response_ct = %resp_ct,
                "Rewrote response headers for gRPC-Web"
            );
        }

        // Every effective instance contributes its expose_headers union so a
        // multi-instance composition (distinct priority_override / scoped
        // duplicates) remains CORS-complete for browsers.
        self.merge_expose_headers(response_headers);

        // The expose list is the ONE field here whose gateway contribution a
        // deadline rebuild could lose. `content-type` and `x-grpc-web` are
        // regenerated by the gRPC-Web error builder itself, but the expose list
        // is only merged from what provenance retained
        // (`merge_grpc_web_expose_headers`), so a backend that pre-populated the
        // identical combined list would make this insert invisible to net-diff
        // mutation tracking and the DEADLINE_EXCEEDED response would carry only
        // the base list — browsers could not read the operator-configured
        // trailer headers.
        //
        // Whole-field ownership is the wrong instrument: the live value may also
        // carry backend-only tokens this plugin merely preserved, and claiming
        // the field would cross them onto the synthesized response. Declaring
        // the configured elements as authored retires exactly one backend
        // baseline occurrence each, so the ordinary occurrence partition credits
        // the gateway's configured list and nothing else.
        //
        // Gated on provenance being tracked so the common path never builds the
        // borrowed element slice. Applies to every gRPC-Web surface — binary and
        // text, H1/H2/H3 — because all of them run this one `after_proxy`.
        if ctx.has_buffered_deadline_response_header_provenance() {
            let authored = self
                .expose_headers
                .iter()
                .map(String::as_str)
                .collect::<Vec<_>>();
            ctx.record_deadline_authored_response_header_elements(
                "access-control-expose-headers",
                &authored,
                response_headers,
            );
        }

        PluginResult::Continue
    }

    async fn transform_response_body(
        &self,
        body: &[u8],
        content_type: Option<&str>,
        response_headers: &HashMap<String, String>,
    ) -> crate::plugins::ResponseBodyTransformOutcome {
        // Legacy/no-context path used by focused framing unit tests. Production
        // buffering calls `transform_response_body_with_context`, which enforces
        // owner + exactly-once translation and applies backend-trailer provenance.
        self.transform_grpc_web_response_body(
            body,
            content_type,
            response_headers,
            TrailerFrameProvenance {
                http_status: None,
                trailer_name_allowlist: None,
                shadowed_trailers: None,
                policy_state: None,
            },
            crate::proxy::response_buffer_budget::buffered_response_body_ceiling(0),
        )
    }

    async fn transform_response_body_with_context(
        &self,
        ctx: &mut RequestContext,
        body: &[u8],
        content_type: Option<&str>,
        response_headers: &HashMap<String, String>,
    ) -> crate::plugins::ResponseBodyTransformOutcome {
        use crate::plugins::ResponseBodyTransformOutcome;

        // Non-owners and already-translated bodies must not append another
        // trailer frame or re-base64-encode text mode output.
        if !self.is_translation_owner(ctx) {
            return ResponseBodyTransformOutcome::Unchanged;
        }
        if ctx.metadata.contains_key(META_GRPC_WEB_RESPONSE_TRANSLATED) {
            return ResponseBodyTransformOutcome::Unchanged;
        }
        // Fail closed: do not invent a gRPC-Web body from content-type alone
        // when owner mode staging is missing or malformed.
        if self.owned_translation_mode(ctx).is_none() {
            debug!(
                plugin = "grpc_web",
                instance = %self.instance_id_str,
                "Fail closed: refusing response translation without valid mode staging"
            );
            return ResponseBodyTransformOutcome::Unchanged;
        }

        let http_status = ctx
            .metadata
            .get(META_GRPC_WEB_HTTP_STATUS)
            .and_then(|value| value.parse::<u16>().ok());
        let mut allowlist = trailer_name_allowlist_from_metadata(&ctx.metadata);
        let shadowed_trailers = shadowed_trailers_from_metadata(&ctx.metadata);
        if allowlist.is_some() && shadowed_trailers.is_none() {
            // Corrupt internal provenance must not fall back to framing a
            // same-name initial header. Every core and names-only recorder
            // installs a collision payload, so absence is incomplete internal
            // state. Retain only reserved terminal metadata.
            allowlist = Some(HashSet::new());
        }
        let translated = self.transform_grpc_web_response_body(
            body,
            content_type,
            response_headers,
            TrailerFrameProvenance {
                http_status,
                trailer_name_allowlist: allowlist.as_ref(),
                shadowed_trailers: shadowed_trailers.as_ref(),
                policy_state: ctx.buffered_initial_response_header_policy(),
            },
            ctx.retained_response_body_ceiling(),
        );
        match &translated {
            ResponseBodyTransformOutcome::Replaced(_) => {
                ctx.metadata.insert(
                    META_GRPC_WEB_RESPONSE_TRANSLATED.to_string(),
                    self.instance_id_str.clone(),
                );
            }
            ResponseBodyTransformOutcome::Unchanged
            | ResponseBodyTransformOutcome::CapacityRefused => {}
        }
        translated
    }
}
