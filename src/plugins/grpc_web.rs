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
//! ## Request path (gRPC-Web → native gRPC)
//!
//! 1. Detect `application/grpc-web*` content-type
//! 2. Rewrite content-type to `application/grpc` for the backend
//! 3. Text mode: base64-decode the request body
//!
//! ## Response path (native gRPC → gRPC-Web)
//!
//! 1. Collect response data frames from the backend
//! 2. Embed gRPC trailers (`grpc-status`, `grpc-message`, binary `*-bin`
//!    metadata, and valid ASCII custom trailing metadata) as a length-prefixed
//!    trailer frame (flag byte 0x80) appended to the body. Hop-by-hop,
//!    forbidden, pseudo, connection-listed, and invalid names/values are
//!    excluded; only backend-trailer provenance (when recorded) is embedded
//! 3. Text mode: base64-encode the entire response body
//! 4. Rewrite response content-type to the original gRPC-Web variant
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
use std::collections::{BTreeMap, HashMap, HashSet};
use tracing::debug;

use crate::proxy::headers::{
    is_backend_response_strip_header, parse_connection_listed_from_str_map,
};
use crate::util::unknown_keys::reject_unknown_keys;

use super::{HTTP_GRPC_PROTOCOLS, Plugin, PluginResult, ProxyProtocol, RequestContext};

/// Authoritative top-level keys accepted by [`GrpcWebPlugin::new`].
pub const GRPC_WEB_CONFIG_KEYS: &[&str] = &["expose_headers"];

/// Metadata key storing the original gRPC-Web mode ("text" or "binary").
const META_GRPC_WEB_MODE: &str = "grpc_web_mode";
/// Metadata key storing the original content-type for response rewriting.
const META_GRPC_WEB_ORIGINAL_CT: &str = "grpc_web_original_ct";
/// Metadata key storing the backend HTTP status observed in `after_proxy`.
///
/// `transform_response_body` cannot see response status directly, so the
/// status is stashed here for HTTP→gRPC trailer synthesis when `grpc-status`
/// is absent.
const META_GRPC_WEB_HTTP_STATUS: &str = "grpc_web_http_status";
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
const HEADER_GRPC_WEB_TRAILER_NAMES: &str = "x-ferrum-grpc-web-trailer-names";
/// Internal response-header bridge for [`META_GRPC_WEB_SHADOWED_TRAILERS`].
/// The payload is base64 so arbitrary printable trailer metadata never becomes
/// header syntax while it crosses the sidecar mesh-mTLS dispatch boundary.
const HEADER_GRPC_WEB_SHADOWED_TRAILERS: &str = "x-ferrum-grpc-web-shadowed-trailers";

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
        trailer_name_allowlist: Option<&HashSet<String>>,
        shadowed_trailers: Option<&HashMap<String, [String; 2]>>,
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
        // HTTP status (official client mapping). Provenance (when recorded)
        // keeps initial-header-only fields out of the body trailer block.
        let trailer_frame = build_trailer_frame_with_full_provenance(
            response_headers,
            http_status,
            trailer_name_allowlist,
            shadowed_trailers,
        );
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

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct GrpcWebMediaType {
    mode: GrpcWebMode,
    proto_suffix: bool,
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
                proto_suffix: false,
            });
        }
        let subtype = suffix.strip_prefix(b"+")?;
        if subtype.is_empty() || !subtype.iter().all(|byte| is_suffix_tchar(*byte)) {
            return None;
        }
        Some(GrpcWebMediaType {
            mode,
            proto_suffix: subtype.eq_ignore_ascii_case(b"proto"),
        })
    };

    classify(APPLICATION_GRPC_WEB_TEXT.as_bytes(), GrpcWebMode::Text)
        .or_else(|| classify(APPLICATION_GRPC_WEB.as_bytes(), GrpcWebMode::Binary))
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
pub(crate) fn retain_client_content_type_for_errors(ctx: &mut RequestContext, content_type: &str) {
    if grpc_web_media_type(content_type).is_some() {
        ctx.metadata.insert(
            META_GRPC_WEB_ORIGINAL_CT.to_string(),
            response_content_type(content_type).to_string(),
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

pub(crate) fn retained_response_content_type(ctx: &RequestContext) -> Option<&'static str> {
    ctx.metadata
        .get(META_GRPC_WEB_ORIGINAL_CT)
        .map(|content_type| response_content_type(content_type))
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
    headers.insert("content-type".to_string(), response_ct.to_string());
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
    if is_grpc_web_text(response_ct) {
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
    let original_ct = ctx.metadata.get(META_GRPC_WEB_ORIGINAL_CT)?;
    let response_ct = response_content_type(original_ct);
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
                | "x-ferrum-grpc-web-trailer-names"
                | "x-ferrum-grpc-web-shadowed-trailers"
        )
}

/// gRPC Custom-Metadata header-name charset (PROTOCOL-HTTP2): `0-9` / `a-z` /
/// `_` / `-` / `.`. Stricter than the HTTP token set so hostile names that
/// survive `HeaderName` parsing still cannot enter the trailer frame.
#[inline]
fn is_grpc_metadata_name(name: &str) -> bool {
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
fn is_valid_trailer_value(value: &str) -> bool {
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
}

fn encode_shadowed_trailers_for_frame(
    response_headers: &HashMap<String, String>,
    trailers: &HashMap<String, String>,
) -> String {
    let shadowed = trailers
        .iter()
        .filter_map(|(name, trailer_value)| {
            response_headers.get(name).and_then(|initial_value| {
                (!is_reserved_grpc_web_terminal_metadata(name)).then(|| {
                    (
                        name.clone(),
                        [initial_value.clone(), trailer_value.clone()],
                    )
                })
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
    let decoded = BASE64.decode(encoded).ok()?;
    serde_json::from_slice(&decoded).ok()
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
}

/// Bridge full trailer provenance through a response-header-only dispatch
/// boundary. Both internal headers are removed by `after_proxy`.
pub fn bridge_backend_trailer_provenance_for_frame(
    response_headers: &mut HashMap<String, String>,
    trailers: &HashMap<String, String>,
) {
    let shadowed = encode_shadowed_trailers_for_frame(response_headers, trailers);
    bridge_backend_trailer_names_for_frame(response_headers, trailers);
    response_headers.insert(
        HEADER_GRPC_WEB_SHADOWED_TRAILERS.to_string(),
        shadowed,
    );
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
    )
}

fn build_trailer_frame_with_full_provenance(
    response_headers: &HashMap<String, String>,
    http_status: Option<u16>,
    trailer_name_allowlist: Option<&HashSet<String>>,
    shadowed_trailers: Option<&HashMap<String, [String; 2]>>,
) -> Vec<u8> {
    let connection_listed = parse_connection_listed_from_str_map(response_headers);
    let mut eligible: Vec<(String, String)> = Vec::new();
    for (key, value) in response_headers {
        let Some(header_name) = is_valid_trailer_header(key) else {
            continue;
        };
        let name = header_name.as_str();
        if connection_listed
            .iter()
            .any(|listed| listed.eq_ignore_ascii_case(name))
        {
            continue;
        }
        if let Some(allowlist) = trailer_name_allowlist
            && !allowlist.contains(name)
            && !is_reserved_grpc_web_terminal_metadata(name)
        {
            continue;
        }
        // The compatibility view keeps an initial-header value when a backend
        // supplied the same name in HEADERS and TRAILERS. Use the true trailer
        // value only while that view is untouched. A hook-rewritten value wins,
        // and iteration over the live view means a removed name stays removed.
        let value = shadowed_trailers
            .and_then(|shadowed| shadowed.get(name))
            .filter(|[initial_value, _]| initial_value == value)
            .map(|[_, trailer_value]| trailer_value)
            .unwrap_or(value);
        // Multi-value gRPC metadata is stored newline-joined in the string map
        // (see `collect_buffered_grpc_trailers`). Emit each occurrence as its
        // own trailer line; reject any occurrence that fails value safety so a
        // single hostile duplicate cannot smuggle CR/LF past the filter.
        for occurrence in value.split('\n') {
            if is_valid_trailer_value(occurrence) {
                eligible.push((name.to_string(), occurrence.to_string()));
            }
        }
    }
    // Deterministic ordering: sort by name, then keep relative occurrence
    // order for duplicates of the same name (stable sort).
    eligible.sort_by(|a, b| a.0.cmp(&b.0));

    let mut trailer_payload = Vec::new();
    let mut has_grpc_status = false;
    for (name, value) in eligible {
        if name == "grpc-status" {
            // Only a present, numeric grpc-status is a valid terminal
            // status. An empty (`grpc-status:`) or non-numeric
            // (`grpc-status: abc`) value is malformed — skip forwarding it
            // so the synthesized mapped status below is emitted instead of
            // passing a bogus status (or duplicating it).
            let Ok(code) = value.trim().parse::<u32>() else {
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
            trailer_payload.extend_from_slice(b"grpc-status: ");
            trailer_payload.extend_from_slice(code.to_string().as_bytes());
            trailer_payload.extend_from_slice(b"\r\n");
            continue;
        }
        trailer_payload.extend_from_slice(name.as_bytes());
        trailer_payload.extend_from_slice(b": ");
        trailer_payload.extend_from_slice(value.as_bytes());
        trailer_payload.extend_from_slice(b"\r\n");
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

/// Map an original gRPC-Web content-type to the response content-type.
///
/// Preserves the +proto suffix if present.
pub(crate) fn response_content_type(original_ct: &str) -> &'static str {
    match grpc_web_media_type(original_ct) {
        Some(GrpcWebMediaType {
            mode: GrpcWebMode::Text,
            proto_suffix: true,
        }) => "application/grpc-web-text+proto",
        Some(GrpcWebMediaType {
            mode: GrpcWebMode::Text,
            proto_suffix: false,
        }) => "application/grpc-web-text",
        Some(GrpcWebMediaType {
            mode: GrpcWebMode::Binary,
            proto_suffix: true,
        }) => "application/grpc-web+proto",
        Some(GrpcWebMediaType {
            mode: GrpcWebMode::Binary,
            proto_suffix: false,
        }) => "application/grpc-web",
        None => {
            // Callers classify before reaching this mapper. Keep the fallback
            // fixed rather than reflecting an unrecognized Content-Type.
            "application/grpc-web"
        }
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

        let mode = if is_grpc_web_text(&content_type) {
            "text"
        } else {
            "binary"
        };

        debug!(
            plugin = "grpc_web",
            mode = mode,
            original_ct = %content_type,
            "Detected gRPC-Web request"
        );

        // Store original info for response path
        ctx.metadata
            .insert(META_GRPC_WEB_MODE.to_string(), mode.to_string());
        ctx.metadata
            .insert(META_GRPC_WEB_ORIGINAL_CT.to_string(), content_type.clone());

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

        // Rewrite response content-type to the gRPC-Web variant
        let resp_ct = response_content_type(&original_ct);
        response_headers.insert("content-type".to_string(), resp_ct.to_string());

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
            response_ct = resp_ct,
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
        self.transform_grpc_web_response_body(
            body,
            content_type,
            response_headers,
            None,
            None,
            None,
        )
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
        let mut allowlist = trailer_name_allowlist_from_metadata(&ctx.metadata);
        let shadowed_trailers = shadowed_trailers_from_metadata(&ctx.metadata);
        if ctx
            .metadata
            .contains_key(META_GRPC_WEB_SHADOWED_TRAILERS)
            && shadowed_trailers.is_none()
        {
            // Corrupt internal provenance must not fall back to framing a
            // same-name initial header. Retain only reserved terminal metadata.
            allowlist = Some(HashSet::new());
        }
        self.transform_grpc_web_response_body(
            body,
            content_type,
            response_headers,
            http_status,
            allowlist.as_ref(),
            shadowed_trailers.as_ref(),
        )
    }
}
