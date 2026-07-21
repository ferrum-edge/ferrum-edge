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
//!
//! ## Response path (native gRPC → gRPC-Web)
//!
//! 1. Collect response data frames from the backend
//! 2. Embed gRPC trailers (grpc-status, grpc-message, plus any custom metadata)
//!    as a length-prefixed trailer frame (flag byte 0x80) appended to the body
//! 3. Text mode: base64-encode the entire response body
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

use async_trait::async_trait;
use base64::Engine;
use base64::engine::general_purpose::STANDARD as BASE64;
use http::header::HeaderName;
use serde_json::Value;
use std::collections::{HashMap, HashSet};
use tracing::debug;

use crate::util::unknown_keys::reject_unknown_keys;

use super::{HTTP_GRPC_PROTOCOLS, Plugin, PluginResult, ProxyProtocol, RequestContext};

/// Authoritative top-level keys accepted by [`GrpcWebPlugin::new`].
pub const GRPC_WEB_CONFIG_KEYS: &[&str] = &["expose_headers"];

/// Metadata key storing the original gRPC-Web mode ("text" or "binary").
const META_GRPC_WEB_MODE: &str = "grpc_web_mode";
/// Metadata key storing the negotiated gRPC-Web response content-type.
const META_GRPC_WEB_ORIGINAL_CT: &str = "grpc_web_original_ct";
/// Metadata key storing the backend HTTP status observed in `after_proxy`.
///
/// `transform_response_body` cannot see response status directly, so the
/// status is stashed here for HTTP→gRPC trailer synthesis when `grpc-status`
/// is absent.
const META_GRPC_WEB_HTTP_STATUS: &str = "grpc_web_http_status";

/// Internal proxy header injected by `before_proxy` so that `transform_request_body`
/// (which lacks access to `ctx.metadata`) can deterministically identify the
/// gRPC-Web encoding mode. Stripped before reaching the backend by the gateway's
/// hop-by-hop header removal.
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
fn decode_grpc_web_text_body(data: &[u8]) -> Option<Vec<u8>> {
    fn is_base64_alphabet(byte: u8) -> bool {
        byte.is_ascii_alphanumeric() || byte == b'+' || byte == b'/'
    }

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

pub struct GrpcWebPlugin {
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

        Ok(Self {
            expose_headers,
            expose_headers_value,
        })
    }

    fn transform_grpc_web_response_body(
        &self,
        body: &[u8],
        _content_type: Option<&str>,
        response_headers: &HashMap<String, String>,
        http_status: Option<u16>,
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

        // Build and append trailer frame from response headers. When the
        // backend omitted a valid grpc-status, synthesize from the stashed
        // HTTP status (official client mapping).
        let trailer_frame = build_trailer_frame(response_headers, http_status);
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
fn parse_q_weight(raw: &[u8]) -> Option<f32> {
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
    let value: f32 = text.parse().ok().filter(|v: &f32| v.is_finite())?;
    if !(0.0..=1.0).contains(&value) {
        return None;
    }
    Some(value)
}

fn parameter_q_weight(parameters: &[u8]) -> Result<f32, GrpcWebAcceptError> {
    let mut value = parameters;
    let mut quality: Option<f32> = None;
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
    Ok(quality.unwrap_or(1.0))
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
    quality: f32,
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

    // Last exact entry wins per mode (quality + Accept-supplied suffix).
    let mut exact_binary: Option<(f32, Option<String>)> = None;
    let mut exact_text: Option<(f32, Option<String>)> = None;
    let mut best_wildcard: Option<(f32, AcceptSpecificity)> = None;
    for range in &ranges {
        match range.kind {
            AcceptRangeKind::Exact(GrpcWebMode::Binary) => {
                exact_binary = Some((range.quality, range.format_suffix.clone()));
            }
            AcceptRangeKind::Exact(GrpcWebMode::Text) => {
                exact_text = Some((range.quality, range.format_suffix.clone()));
            }
            AcceptRangeKind::ApplicationWildcard | AcceptRangeKind::FullWildcard => {
                if range.quality <= 0.0 {
                    continue;
                }
                let replace = match best_wildcard {
                    None => true,
                    Some((best_q, best_spec)) => {
                        range.quality > best_q
                            || (range.quality == best_q && range.specificity > best_spec)
                    }
                };
                if replace {
                    best_wildcard = Some((range.quality, range.specificity));
                }
            }
        }
    }

    let mut best: Option<(f32, AcceptSpecificity, bool, GrpcWebMediaType)> = None;
    let mut consider =
        |quality: f32, specificity: AcceptSpecificity, mode: GrpcWebMode, suffix: Option<String>| {
            if quality <= 0.0 {
                return;
            }
            let format_suffix = suffix.or_else(|| request.format_suffix.clone());
            let candidate = GrpcWebMediaType {
                mode,
                format_suffix,
            };
            let matches_request_mode = mode == request.mode;
            let replace = match &best {
                None => true,
                Some((best_q, best_spec, best_match, _)) => {
                    quality > *best_q
                        || (quality == *best_q && specificity > *best_spec)
                        || (quality == *best_q
                            && specificity == *best_spec
                            && matches_request_mode
                            && !*best_match)
                }
            };
            if replace {
                best = Some((quality, specificity, matches_request_mode, candidate));
            }
        };

    if let Some((quality, suffix)) = exact_binary {
        consider(quality, AcceptSpecificity::Exact, GrpcWebMode::Binary, suffix);
    }
    if let Some((quality, suffix)) = exact_text {
        consider(quality, AcceptSpecificity::Exact, GrpcWebMode::Text, suffix);
    }
    // Wildcards fill only modes that have no exact Accept entry.
    if let Some((quality, specificity)) = best_wildcard {
        if exact_binary.is_none() {
            consider(quality, specificity, GrpcWebMode::Binary, None);
        }
        if exact_text.is_none() {
            consider(quality, specificity, GrpcWebMode::Text, None);
        }
    }

    best.map(|(_, _, _, media)| canonical_grpc_web_content_type(&media))
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
/// (rewritten in `before_proxy`), but a translated response MUST buffer — the
/// plugin re-encodes the backend's terminal trailers (`grpc-status` /
/// `grpc-message`) INTO the gRPC-Web response body — while a native gRPC
/// response must NOT buffer (its trailers have to relay on the wire).
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
pub(crate) fn retain_client_content_type_for_errors(ctx: &mut RequestContext, content_type: &str) {
    if !is_grpc_web_content_type(content_type) {
        return;
    }
    let accept = ctx
        .headers
        .get("accept")
        .map(String::as_str)
        .or_else(|| ctx.raw_header_get("accept"));
    let retained = match negotiate_response_media_type(content_type, accept) {
        Ok(negotiated) => negotiated,
        Err(_) => response_content_type(content_type),
    };
    retain_negotiated_response_content_type(ctx, &retained);
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
    ctx.metadata.contains_key(META_GRPC_WEB_ORIGINAL_CT)
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
    let mut headers = HashMap::with_capacity(3);
    headers.insert("content-type".to_string(), response_ct.clone());
    headers.insert("x-grpc-web".to_string(), "1".to_string());
    headers.insert(
        "access-control-expose-headers".to_string(),
        BASE_EXPOSE_HEADERS_VALUE.to_string(),
    );

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

fn is_valid_trailer_header(key: &str) -> Option<HeaderName> {
    let header = HeaderName::from_bytes(key.trim().as_bytes()).ok()?;
    let normalized = header.as_str();
    if normalized.starts_with("grpc-") || normalized.ends_with("-bin") {
        Some(header)
    } else {
        None
    }
}

fn is_valid_trailer_value(value: &str) -> bool {
    !value.bytes().any(|b| b == b'\r' || b == b'\n')
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
pub(crate) fn build_trailer_frame(
    response_headers: &HashMap<String, String>,
    http_status: Option<u16>,
) -> Vec<u8> {
    let mut trailer_payload = Vec::new();
    let mut has_grpc_status = false;
    for (key, value) in response_headers {
        // Include grpc-* trailers and any custom trailing metadata
        if let Some(header_name) = is_valid_trailer_header(key)
            && is_valid_trailer_value(value)
        {
            if header_name.as_str() == "grpc-status" {
                // Only a present, numeric grpc-status is a valid terminal
                // status. An empty (`grpc-status:`) or non-numeric
                // (`grpc-status: abc`) value is malformed — skip forwarding it
                // so the synthesized mapped status below is emitted instead of
                // passing a bogus status (or duplicating it).
                let Ok(code) = value.trim().parse::<u32>() else {
                    continue;
                };
                has_grpc_status = true;
                // Emit the normalized (parsed) value, not the raw header, so the
                // forwarded frame is self-consistent with what was validated
                // (e.g. any surrounding OWS is dropped).
                trailer_payload.extend_from_slice(b"grpc-status: ");
                trailer_payload.extend_from_slice(code.to_string().as_bytes());
                trailer_payload.extend_from_slice(b"\r\n");
                continue;
            }
            trailer_payload.extend_from_slice(header_name.as_str().as_bytes());
            trailer_payload.extend_from_slice(b": ");
            trailer_payload.extend_from_slice(value.as_bytes());
            trailer_payload.extend_from_slice(b"\r\n");
        }
    }

    // A backend response without a present, numeric grpc-status is malformed /
    // non-gRPC. Apply the official client HTTP→gRPC mapping so intermediaries
    // that return 401/403/404/429/502/503/504 without grpc-status do not
    // collapse to UNKNOWN and break retry classification.
    if !has_grpc_status {
        let mapped = http_response_status_to_grpc_status(http_status.unwrap_or(200));
        trailer_payload.extend_from_slice(b"grpc-status: ");
        trailer_payload.extend_from_slice(mapped.to_string().as_bytes());
        trailer_payload.extend_from_slice(b"\r\n");
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

    fn should_buffer_response_body(&self, ctx: &RequestContext) -> bool {
        ctx.metadata.contains_key(META_GRPC_WEB_MODE)
    }

    fn should_buffer_response_body_for_content_type(
        &self,
        ctx: &RequestContext,
        _content_type: Option<&str>,
        response_status: u16,
        _response_headers: &HashMap<String, String>,
    ) -> bool {
        self.should_buffer_response_body(ctx)
            && super::response_body_rewrite_allowed(response_status)
    }

    fn should_release_response_body_before_content_type_rewrite(
        &self,
        ctx: &RequestContext,
        response_status: u16,
        _response_headers: &HashMap<String, String>,
    ) -> bool {
        self.should_buffer_response_body(ctx)
            && !super::response_body_rewrite_allowed(response_status)
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

        // Request decoding mode follows Content-Type only.
        let mode = if is_grpc_web_text(&content_type) {
            "text"
        } else {
            "binary"
        };

        // Response encoding follows Accept negotiation (default: request CT).
        let accept = ctx.headers.get("accept").map(String::as_str);
        let response_ct = match negotiate_response_media_type(&content_type, accept) {
            Ok(negotiated) => negotiated,
            Err(err) => {
                debug!(
                    plugin = "grpc_web",
                    ?err,
                    accept = ?accept,
                    "Rejecting gRPC-Web request: Accept negotiation failed"
                );
                return PluginResult::Reject {
                    status_code: 406,
                    body: r#"{"error":"Not Acceptable: no supported gRPC-Web response media type"}"#
                        .to_string(),
                    headers: HashMap::from([(
                        "content-type".to_string(),
                        "application/json".to_string(),
                    )]),
                };
            }
        };

        debug!(
            plugin = "grpc_web",
            mode = mode,
            original_ct = %content_type,
            response_ct = %response_ct,
            "Detected gRPC-Web request"
        );

        // Store request decode mode and negotiated response media type.
        ctx.metadata
            .insert(META_GRPC_WEB_MODE.to_string(), mode.to_string());
        ctx.metadata
            .insert(META_GRPC_WEB_ORIGINAL_CT.to_string(), response_ct);

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

    fn may_modify_response_content_type(
        &self,
        ctx: &RequestContext,
        _response_content_type: Option<&str>,
    ) -> bool {
        // `after_proxy` relabels the response `Content-Type` to the gRPC-Web
        // variant exactly when `on_request_received` recorded the original
        // gRPC-Web content-type — independent of the backend response type, so
        // the request marker alone is the precise signal. (gRPC-Web responses
        // are already unconditionally buffered to embed trailers, so this never
        // newly pins a streaming body.) Signal that so the proxy keeps the body
        // buffered for final-response inspection instead of trusting the
        // backend's `application/grpc` header for the buffer/stream decision.
        ctx.metadata.contains_key(META_GRPC_WEB_ORIGINAL_CT)
    }

    async fn after_proxy(
        &self,
        ctx: &mut RequestContext,
        response_status: u16,
        response_headers: &mut HashMap<String, String>,
    ) -> PluginResult {
        // The shared lifecycle cannot embed trailers or base64-rewrite a
        // preserved 206/226 representation. Leave its native headers coherent
        // with the untouched bytes instead of falsely labelling it gRPC-Web.
        if !super::response_body_rewrite_allowed(response_status) {
            return PluginResult::Continue;
        }

        let original_ct = match ctx.metadata.get(META_GRPC_WEB_ORIGINAL_CT) {
            Some(ct) => ct.clone(),
            None => return PluginResult::Continue,
        };

        // Stash the backend HTTP status for trailer-frame synthesis. A valid
        // backend `grpc-status` stays authoritative; the mapper only runs when
        // that status is absent/malformed. The client-visible HTTP status is
        // intentionally not rewritten here (see module docs).
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

        // Add CORS-friendly expose headers so browsers can read gRPC metadata.
        // We MUST set this whether or not the backend already returned an
        // expose-headers value — gRPC-Web is intrinsically a browser protocol
        // and grpc-status/grpc-message are unreadable from JavaScript without it.
        // (Previously this branch was a no-op when the backend didn't emit
        // access-control-expose-headers, which broke browser clients on backends
        // that didn't already configure CORS.)
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

        debug!(
            plugin = "grpc_web",
            response_ct = %resp_ct,
            "Rewrote response headers for gRPC-Web"
        );

        PluginResult::Continue
    }

    async fn transform_response_body(
        &self,
        body: &[u8],
        content_type: Option<&str>,
        response_headers: &HashMap<String, String>,
    ) -> Option<Vec<u8>> {
        self.transform_grpc_web_response_body(body, content_type, response_headers, None)
    }

    async fn transform_response_body_with_context(
        &self,
        ctx: &mut RequestContext,
        body: &[u8],
        content_type: Option<&str>,
        response_headers: &HashMap<String, String>,
    ) -> Option<Vec<u8>> {
        let http_status = ctx
            .metadata
            .get(META_GRPC_WEB_HTTP_STATUS)
            .and_then(|value| value.parse::<u16>().ok());
        self.transform_grpc_web_response_body(body, content_type, response_headers, http_status)
    }
}
