//! Compression plugin — compresses response bodies and decompresses request bodies.
//!
//! Supports gzip and brotli algorithms. Response compression is negotiated via
//! the client's `Accept-Encoding` header (RFC 9110 §12.5.3). Request
//! decompression is opt-in and decompresses `Content-Encoding: gzip|br` request
//! bodies before other plugins inspect them.
//!
//! Modeled after Envoy's compressor filter: content-type whitelist, minimum
//! content length, ETag awareness, no double-compression, and `Vary` header
//! injection.

use async_trait::async_trait;
use serde_json::Value;
use std::collections::HashMap;
use std::fmt;
use std::io::{Read, Write};
use tracing::{debug, error, warn};

use super::{Plugin, PluginResult, RequestContext};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Algorithm {
    Gzip,
    Brotli,
}

impl fmt::Display for Algorithm {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.content_encoding())
    }
}

impl Algorithm {
    fn content_encoding(&self) -> &'static str {
        match self {
            Algorithm::Gzip => "gzip",
            Algorithm::Brotli => "br",
        }
    }
}

/// Default MIME types eligible for compression (matches Envoy's defaults + common API types).
const DEFAULT_CONTENT_TYPES: &[&str] = &[
    "application/json",
    "application/javascript",
    "application/xml",
    "application/xhtml+xml",
    "text/html",
    "text/plain",
    "text/css",
    "text/xml",
    "text/javascript",
    "image/svg+xml",
];

/// HTTP status codes that should never be compressed (no body or cache-only).
const UNCOMPRESSIBLE_STATUS_CODES: &[u16] = &[204, 304];

const REJECTION_RESPONSE_METADATA_KEY: &str = "ferrum:rejection_response";

struct CompressionConfig {
    /// Enabled algorithms in server-preference order (used to break q-value ties).
    algorithms: Vec<Algorithm>,

    // -- Response compression --
    min_content_length: usize,
    content_types: Vec<String>,
    disable_on_etag: bool,
    /// Remove `Accept-Encoding` from the backend request so the backend always
    /// sends an uncompressed response for us to compress.
    remove_accept_encoding: bool,

    // -- Request decompression --
    decompress_request: bool,
    /// Zip-bomb protection: reject decompressed request bodies exceeding this.
    max_decompressed_request_size: usize,

    // -- Algorithm tuning --
    gzip_level: u32,
    brotli_quality: u32,
}

pub struct CompressionPlugin {
    config: CompressionConfig,
}

impl CompressionPlugin {
    pub fn new(config: &Value) -> Result<Self, String> {
        let default_config = Value::Object(serde_json::Map::new());
        let config = if config.is_null() {
            &default_config
        } else if config.is_object() {
            config
        } else {
            return Err("compression: config must be an object".to_string());
        };

        // Parse `algorithms` strictly. Unknown values are rejected (no silent
        // skip) so configuration typos surface immediately at load time
        // instead of producing a partially-functional plugin.
        let algorithms: Vec<Algorithm> = match config.get("algorithms") {
            Some(Value::Array(arr)) => {
                let mut algos = Vec::with_capacity(arr.len());
                for (idx, v) in arr.iter().enumerate() {
                    match v.as_str() {
                        Some("gzip") => algos.push(Algorithm::Gzip),
                        Some("br") | Some("brotli") => algos.push(Algorithm::Brotli),
                        Some(other) => {
                            return Err(format!(
                                "compression: algorithms[{idx}]: unknown algorithm '{other}' (expected 'gzip' or 'br')"
                            ));
                        }
                        None => {
                            return Err(format!("compression: algorithms[{idx}] must be a string"));
                        }
                    }
                }
                algos
            }
            Some(Value::Null) | None => vec![Algorithm::Gzip, Algorithm::Brotli],
            Some(_) => {
                return Err("compression: 'algorithms' must be an array of strings".to_string());
            }
        };

        let content_types = parse_content_types(config)?;

        let min_content_length = optional_usize(config, "min_content_length")?.unwrap_or(256);

        let disable_on_etag = optional_bool(config, "disable_on_etag")?.unwrap_or(false);

        let remove_accept_encoding =
            optional_bool(config, "remove_accept_encoding")?.unwrap_or(true);

        let decompress_request = optional_bool(config, "decompress_request")?.unwrap_or(false);

        let max_decompressed_request_size =
            optional_positive_usize(config, "max_decompressed_request_size")?
                .unwrap_or(10 * 1024 * 1024);

        let gzip_level = optional_u64(config, "gzip_level")?
            .map(|value| {
                if value > 9 {
                    Err("compression: 'gzip_level' must be between 0 and 9".to_string())
                } else {
                    Ok(value as u32)
                }
            })
            .transpose()?
            .unwrap_or(6);

        let brotli_quality = optional_u64(config, "brotli_quality")?
            .map(|value| {
                if value > 11 {
                    Err("compression: 'brotli_quality' must be between 0 and 11".to_string())
                } else {
                    Ok(value as u32)
                }
            })
            .transpose()?
            .unwrap_or(4);

        if algorithms.is_empty() {
            return Err(
                "compression: no valid algorithms configured — plugin will have no effect"
                    .to_string(),
            );
        }

        Ok(Self {
            config: CompressionConfig {
                algorithms,
                min_content_length,
                content_types,
                disable_on_etag,
                remove_accept_encoding,
                decompress_request,
                max_decompressed_request_size,
                gzip_level,
                brotli_quality,
            },
        })
    }

    /// Parse `Accept-Encoding` and select the best algorithm from our configured set.
    ///
    /// Selection: highest q-value wins. Ties broken by server preference order
    /// (the `algorithms` config array). Wildcard `*` matches all configured
    /// algorithms at whatever q-value `*` carries, but per RFC 9110 §12.5.3 a
    /// more specific entry takes precedence over `*` — so an explicit
    /// `gzip;q=0` excludes gzip even when `*` is present with `q>0`.
    ///
    /// This is a two-pass parse rather than a single fused loop: pass 1 records
    /// each codec's explicit q-value (when its exact token appears, capturing
    /// `q=0` refusals) and the wildcard q-value; pass 2 resolves each configured
    /// algorithm's effective q (explicit wins over wildcard) and applies the
    /// `q <= 0` not-acceptable gate and the highest-q / server-preference
    /// tie-break.
    fn select_algorithm(&self, accept_encoding: &str) -> Option<Algorithm> {
        // Pass 1: scan every token once, recording the explicit q-value for each
        // codec we support and the wildcard q-value. `None` means "no explicit
        // entry for this codec". Later duplicate tokens overwrite earlier ones
        // (last value wins), matching the previous single-loop behaviour for
        // repeated identical tokens.
        let mut explicit_gzip: Option<f32> = None;
        let mut explicit_br: Option<f32> = None;
        let mut wildcard: Option<f32> = None;

        for part in accept_encoding.split(',') {
            let part = part.trim();
            if part.is_empty() {
                continue;
            }

            let (encoding, quality) = parse_encoding_quality(part);
            if encoding.eq_ignore_ascii_case("gzip") {
                explicit_gzip = Some(quality);
            } else if encoding.eq_ignore_ascii_case("br") {
                explicit_br = Some(quality);
            } else if encoding == "*" {
                wildcard = Some(quality);
            }
        }

        // Pass 2: resolve each configured algorithm's effective q (its explicit
        // entry wins over the wildcard) and pick the best one.
        let mut best: Option<(Algorithm, f32, usize)> = None; // (algo, q, server_pref_index)
        for (pref_idx, &algo) in self.config.algorithms.iter().enumerate() {
            let explicit = match algo {
                Algorithm::Gzip => explicit_gzip,
                Algorithm::Brotli => explicit_br,
            };
            // Explicit entry takes precedence over the wildcard fallback.
            let effective_q = match explicit.or(wildcard) {
                Some(q) => q,
                None => continue,
            };
            if effective_q <= 0.0 {
                continue;
            }

            let dominated = best.is_some_and(|(_, best_q, best_pref)| {
                effective_q < best_q || (effective_q == best_q && pref_idx >= best_pref)
            });
            if !dominated {
                best = Some((algo, effective_q, pref_idx));
            }
        }

        best.map(|(algo, _, _)| algo)
    }

    /// Check if the content type is eligible for compression.
    fn is_compressible_content_type(&self, content_type: &str) -> bool {
        self.config.content_types.iter().any(|content_type_rule| {
            contains_ascii_case_insensitive(content_type, content_type_rule)
        })
    }

    fn compress(&self, algo: Algorithm, data: &[u8]) -> Result<Vec<u8>, String> {
        match algo {
            Algorithm::Gzip => self.compress_gzip(data),
            Algorithm::Brotli => self.compress_brotli(data),
        }
    }

    fn compress_gzip(&self, data: &[u8]) -> Result<Vec<u8>, String> {
        use flate2::Compression;
        use flate2::write::GzEncoder;

        let mut encoder = GzEncoder::new(
            Vec::with_capacity(data.len() / 2),
            Compression::new(self.config.gzip_level),
        );
        encoder
            .write_all(data)
            .map_err(|e| format!("gzip compression write failed: {e}"))?;
        encoder
            .finish()
            .map_err(|e| format!("gzip compression finish failed: {e}"))
    }

    fn compress_brotli(&self, data: &[u8]) -> Result<Vec<u8>, String> {
        let mut output = Vec::with_capacity(data.len() / 2);
        let params = brotli::enc::BrotliEncoderParams {
            quality: self.config.brotli_quality as i32,
            ..Default::default()
        };
        brotli::BrotliCompress(&mut &data[..], &mut output, &params)
            .map_err(|e| format!("brotli compression failed: {e}"))?;
        Ok(output)
    }

    fn decompress(&self, encoding: &str, data: &[u8], max_size: usize) -> Result<Vec<u8>, String> {
        match encoding {
            "gzip" => self.decompress_gzip(data, max_size),
            "br" => self.decompress_brotli(data, max_size),
            other => Err(format!("unsupported content-encoding: {other}")),
        }
    }

    fn decompress_gzip(&self, data: &[u8], max_size: usize) -> Result<Vec<u8>, String> {
        use flate2::read::MultiGzDecoder;

        // `MultiGzDecoder` (not `GzDecoder`) decodes every member of a
        // concatenated multi-member gzip stream (RFC 1952 §2.2 permits
        // concatenation). `GzDecoder` stops after the first member and would
        // silently truncate a valid multi-member request body. The
        // `read_with_limit` cap still bounds total expansion.
        let mut decoder = MultiGzDecoder::new(data);
        read_with_limit(&mut decoder, max_size, "gzip")
    }

    fn decompress_brotli(&self, data: &[u8], max_size: usize) -> Result<Vec<u8>, String> {
        let mut reader = brotli::Decompressor::new(data, 4096);
        read_with_limit(&mut reader, max_size, "brotli")
    }
}

fn optional_bool(config: &Value, field: &'static str) -> Result<Option<bool>, String> {
    match config.get(field) {
        Some(Value::Bool(value)) => Ok(Some(*value)),
        Some(Value::Null) | None => Ok(None),
        Some(_) => Err(format!("compression: '{field}' must be a boolean")),
    }
}

fn optional_u64(config: &Value, field: &'static str) -> Result<Option<u64>, String> {
    match config.get(field) {
        Some(Value::Number(value)) => value
            .as_u64()
            .ok_or_else(|| format!("compression: '{field}' must be an unsigned integer"))
            .map(Some),
        Some(Value::Null) | None => Ok(None),
        Some(_) => Err(format!(
            "compression: '{field}' must be an unsigned integer"
        )),
    }
}

fn optional_usize(config: &Value, field: &'static str) -> Result<Option<usize>, String> {
    let Some(value) = optional_u64(config, field)? else {
        return Ok(None);
    };
    usize::try_from(value)
        .map(Some)
        .map_err(|_| format!("compression: '{field}' is too large"))
}

fn optional_positive_usize(config: &Value, field: &'static str) -> Result<Option<usize>, String> {
    let Some(value) = optional_usize(config, field)? else {
        return Ok(None);
    };
    if value == 0 {
        return Err(format!("compression: '{field}' must be greater than zero"));
    }
    Ok(Some(value))
}

fn parse_content_types(config: &Value) -> Result<Vec<String>, String> {
    let Some(value) = config.get("content_types") else {
        return Ok(DEFAULT_CONTENT_TYPES
            .iter()
            .map(|content_type| (*content_type).to_string())
            .collect());
    };
    let Some(values) = value.as_array() else {
        return Err("compression: 'content_types' must be an array".to_string());
    };
    if values.is_empty() {
        return Err("compression: 'content_types' must not be empty".to_string());
    }

    let mut content_types = Vec::with_capacity(values.len());
    for (index, value) in values.iter().enumerate() {
        let Some(content_type) = value.as_str() else {
            return Err(format!(
                "compression: 'content_types[{index}]' must be a string"
            ));
        };
        if content_type.is_empty() {
            return Err(format!(
                "compression: 'content_types[{index}]' must not be empty"
            ));
        }
        if !content_type.is_ascii() {
            return Err(format!(
                "compression: 'content_types[{index}]' must contain only ASCII"
            ));
        }
        content_types.push(content_type.to_ascii_lowercase());
    }

    Ok(content_types)
}

fn contains_ascii_case_insensitive(haystack: &str, needle: &str) -> bool {
    let needle = needle.as_bytes();
    !needle.is_empty()
        && haystack
            .as_bytes()
            .windows(needle.len())
            .any(|window| window.eq_ignore_ascii_case(needle))
}

fn supported_request_encoding(value: &str) -> Option<&'static str> {
    if value.eq_ignore_ascii_case("gzip") {
        Some("gzip")
    } else if value.eq_ignore_ascii_case("br") {
        Some("br")
    } else {
        None
    }
}

fn comma_header_contains_token(value: &str, token: &str) -> bool {
    value
        .split(',')
        .any(|part| part.trim().eq_ignore_ascii_case(token))
}

fn cache_control_has_directive(value: &str, directive: &str) -> bool {
    value.split(',').any(|part| {
        let part = part.trim();
        let directive_name = part
            .split_once('=')
            .map(|(name, _)| name.trim())
            .unwrap_or(part);
        directive_name.eq_ignore_ascii_case(directive)
    })
}

/// Read from `reader` into a `Vec`, enforcing a maximum decompressed size.
fn read_with_limit(
    reader: &mut dyn Read,
    max_size: usize,
    algo_name: &str,
) -> Result<Vec<u8>, String> {
    let mut output = Vec::with_capacity(8192);
    let mut buf = [0u8; 8192];
    loop {
        let n = reader
            .read(&mut buf)
            .map_err(|e| format!("{algo_name} decompression failed: {e}"))?;
        if n == 0 {
            break;
        }
        output.extend_from_slice(&buf[..n]);
        if output.len() > max_size {
            return Err(format!(
                "decompressed request body exceeds max size of {max_size} bytes"
            ));
        }
    }
    Ok(output)
}

/// Parse a single `Accept-Encoding` token like `gzip;q=0.8` or `br`.
///
/// Returns the encoding token and its effective quality value, clamped to
/// `0.0..=1.0` per RFC 9110 §12.4.2. A `q=`/`Q=` parameter that is present but
/// unparseable (e.g. `gzip;q=abc`, `gzip;q=`) or non-finite (e.g. `gzip;q=NaN`,
/// `gzip;q=inf`) is treated as **not acceptable** (`q = 0.0`) rather than
/// silently defaulting to the maximum preference of `1.0` — a malformed weight
/// must not let a codec win the selection or poison the tie-break math. A token
/// with no `q=` parameter at all defaults to `q = 1.0` as the spec requires.
fn parse_encoding_quality(token: &str) -> (&str, f32) {
    // Split on ';' and look for q= parameter
    if let Some(semi_idx) = token.find(';') {
        let encoding = token[..semi_idx].trim();
        let params = token[semi_idx + 1..].trim();
        // Find q= (could be "q=0.8" or " q=0.8")
        for param in params.split(';') {
            let param = param.trim();
            if let Some(stripped) = param
                .strip_prefix("q=")
                .or_else(|| param.strip_prefix("Q="))
            {
                // A q-parameter is present: its value is authoritative. Parse
                // and clamp to [0.0, 1.0]; reject unparseable/non-finite values
                // as q=0.0 (not acceptable). Do NOT fall through to the q=1.0
                // default — that is only for tokens with no q-parameter.
                let q = stripped
                    .trim()
                    .parse::<f32>()
                    .ok()
                    .filter(|value| value.is_finite())
                    .map(|value| value.clamp(0.0, 1.0))
                    .unwrap_or(0.0);
                return (encoding, q);
            }
        }
        (encoding, 1.0)
    } else {
        (token.trim(), 1.0)
    }
}

#[async_trait]
impl Plugin for CompressionPlugin {
    fn name(&self) -> &str {
        "compression"
    }

    fn priority(&self) -> u16 {
        super::priority::COMPRESSION
    }

    fn supported_protocols(&self) -> &'static [super::ProxyProtocol] {
        super::HTTP_ONLY_PROTOCOLS
    }

    fn modifies_request_headers(&self) -> bool {
        self.config.remove_accept_encoding || self.config.decompress_request
    }

    fn modifies_request_body(&self) -> bool {
        self.config.decompress_request
    }

    fn should_buffer_request_body(&self, ctx: &RequestContext) -> bool {
        self.config.decompress_request && ctx.headers.contains_key("content-encoding")
    }

    /// Buffer the request body before `before_proxy` runs so the decompression
    /// can be validated (and a malformed body cleanly rejected) before the
    /// Content-Encoding/Content-Length headers are stripped. Without this the
    /// body would only become available in `transform_request_body`, which
    /// cannot reject. This stays gated by `should_buffer_request_body`, so only
    /// requests that actually carry a `Content-Encoding` header buffer early.
    fn requires_request_body_before_before_proxy(&self) -> bool {
        self.config.decompress_request
    }

    /// The validation in `before_proxy` decompresses arbitrary (possibly
    /// non-UTF-8) bytes, so it reads `ctx.request_body_bytes` rather than the
    /// UTF-8 `ctx.metadata["request_body"]` view.
    fn needs_request_body_bytes(&self) -> bool {
        self.config.decompress_request
    }

    fn requires_response_body_buffering(&self) -> bool {
        !self.config.algorithms.is_empty()
    }

    fn should_buffer_response_body(&self, ctx: &RequestContext) -> bool {
        // Skip response buffering when the client doesn't accept any encoding
        // we support — there's nothing to compress.
        !self.config.algorithms.is_empty() && ctx.headers.contains_key("accept-encoding")
    }

    fn should_buffer_response_body_for_content_type(
        &self,
        ctx: &RequestContext,
        content_type: Option<&str>,
        response_status: u16,
        response_headers: &HashMap<String, String>,
    ) -> bool {
        // Mirror the `after_proxy` skip checks that are knowable from the
        // response headers so we never pin a body onto the buffered path that
        // we are going to decline to compress. Range responses (`206` or any
        // `Content-Range`) are skipped there to preserve byte-offset semantics,
        // so they must stream instead of being fully collected (which would also
        // risk tripping the response body size limit on large ranged downloads).
        //
        // On paths that run `after_proxy` *before* this refine decision (e.g.
        // the H3 cross-protocol path stamps `RANGE_RESPONSE_METADATA_KEY` from
        // the pristine headers, then runs `after_proxy`, then refines), an
        // earlier-ordered hook such as `response_transformer` (ordering 4000)
        // can strip `Content-Range` from a non-206 response before this check
        // sees it. `after_proxy` already honors the stamped marker, so honor it
        // here too; otherwise the partial body stays pinned on the buffered path
        // (uncompressed, since `transform_response_body` is buffered-only) and
        // can trip the response body size limit instead of streaming.
        if response_status == 206
            || response_headers.contains_key("content-range")
            || ctx
                .metadata
                .contains_key(crate::proxy::RANGE_RESPONSE_METADATA_KEY)
        {
            return false;
        }
        if response_headers
            .get("cache-control")
            .is_some_and(|value| cache_control_has_directive(value, "no-transform"))
        {
            return false;
        }
        self.should_buffer_response_body(ctx)
            && content_type.is_some_and(|ct| self.is_compressible_content_type(ct))
    }

    fn applies_after_proxy_on_reject(&self) -> bool {
        true
    }

    async fn before_proxy(
        &self,
        ctx: &mut RequestContext,
        headers: &mut HashMap<String, String>,
    ) -> PluginResult {
        // Always drop any client-supplied value of the gateway-internal marker.
        // Without this, a client could set `x-ferrum-original-content-encoding: gzip`
        // on a plaintext body and trick `transform_request_body` into attempting
        // decompression (wasted CPU; with a crafted gzip-bomb payload, bounded by
        // `max_decompressed_request_size` but still unnecessary work).
        headers.remove("x-ferrum-original-content-encoding");

        // Save original Accept-Encoding before we potentially strip it.
        // Read from `headers` param — ctx.headers may be empty when the handler
        // uses the zero-clone fast path (std::mem::take).
        if let Some(ae) = headers.get("accept-encoding") {
            ctx.metadata
                .insert("compression:accept_encoding".to_string(), ae.clone());
        }

        // Strip Accept-Encoding from the backend request so the backend
        // sends an uncompressed response (we'll compress it ourselves).
        if self.config.remove_accept_encoding {
            headers.remove("accept-encoding");
        }

        // For request decompression: save the Content-Encoding value before
        // removing it, so transform_request_body can find it. The private header
        // x-ferrum-original-content-encoding is used because transform_request_body
        // receives the same headers map (with content-encoding already removed).
        if self.config.decompress_request
            && let Some(ce) = headers.get("content-encoding")
            && let Some(encoding) = supported_request_encoding(ce)
        {
            // Validate that the body actually decompresses BEFORE stripping the
            // Content-Encoding/Content-Length headers. Stripping is gated on
            // successful decompression so we never forward a body whose headers
            // and contents disagree (RFC 9110 §8.4): if we removed
            // Content-Encoding but left the body compressed (because decode
            // later failed in transform_request_body, which has no way to
            // reject), the backend would receive a gzip/brotli blob mislabeled
            // as plaintext and emit confusing 400s / mis-parsed data instead of
            // a clean gateway rejection.
            //
            // The body is buffered before before_proxy (see
            // `requires_request_body_before_before_proxy`) and exposed binary
            // safe via `ctx.request_body_bytes`. We only have it on the buffered
            // request path; if it is absent (e.g. an HBONE CONNECT tunnel where
            // pre-before_proxy buffering is skipped) we fall back to the prior
            // best-effort behaviour and let transform_request_body handle it.
            if let Some(body) = ctx.request_body_bytes.as_ref() {
                let decode_result = if body.is_empty() {
                    Err("empty compressed request body".to_string())
                } else {
                    self.decompress(encoding, body, self.config.max_decompressed_request_size)
                        .map(|_| ())
                };
                if let Err(e) = decode_result {
                    // Reject with a protocol-appropriate gateway error. The proxy
                    // normalizes this to a trailers-only gRPC error for
                    // application/grpc and a plain 400 otherwise. The detailed
                    // cause is logged, not leaked to the client.
                    warn!("compression: rejecting request with undecodable {encoding} body: {e}");
                    return PluginResult::Reject {
                        status_code: 400,
                        body: r#"{"error":"Malformed compressed request body"}"#.to_string(),
                        headers: HashMap::new(),
                    };
                }
            }

            ctx.metadata.insert(
                "compression:request_encoding".to_string(),
                encoding.to_string(),
            );
            headers.remove("content-encoding");
            headers.insert(
                "x-ferrum-original-content-encoding".to_string(),
                encoding.to_string(),
            );
            // Content-Length will be wrong after decompression; remove it
            // so the backend uses chunked transfer or recalculates.
            headers.remove("content-length");
        }

        PluginResult::Continue
    }

    async fn after_proxy(
        &self,
        ctx: &mut RequestContext,
        response_status: u16,
        response_headers: &mut HashMap<String, String>,
    ) -> PluginResult {
        // Rejection handling currently re-runs only `after_proxy` header hooks,
        // not response-body transforms. Do not commit a Content-Encoding there
        // unless/until the rejection path can also compress the reject body.
        if ctx.metadata.contains_key(REJECTION_RESPONSE_METADATA_KEY) {
            return PluginResult::Continue;
        }

        // Skip uncompressible status codes.
        if UNCOMPRESSIBLE_STATUS_CODES.contains(&response_status) {
            return PluginResult::Continue;
        }

        // Range responses carry byte offsets for the original representation.
        // Compressing them changes those byte positions and corrupts range
        // semantics, even if a backend sends Content-Range with a non-206
        // status. Range responses are also streamed (see
        // `should_buffer_response_body_for_content_type`), so committing a
        // `Content-Encoding` here would mislabel an uncompressed body whose
        // `transform_response_body` (buffered-only) never runs. The live
        // headers may already have been rewritten by an earlier-ordered hook
        // (e.g. `response_transformer` removing `Content-Range`), so also honor
        // the original backend range decision captured before `after_proxy`.
        if response_status == 206
            || response_headers.contains_key("content-range")
            || ctx
                .metadata
                .contains_key(crate::proxy::RANGE_RESPONSE_METADATA_KEY)
        {
            return PluginResult::Continue;
        }

        // RFC 9111 no-transform forbids an intermediary from transforming the
        // payload representation, including content-coding compression.
        if response_headers
            .get("cache-control")
            .is_some_and(|value| cache_control_has_directive(value, "no-transform"))
        {
            return PluginResult::Continue;
        }

        // Skip if response already has Content-Encoding (don't double-compress).
        if response_headers.contains_key("content-encoding") {
            return PluginResult::Continue;
        }

        // Skip if ETag present and disable_on_etag is set.
        if self.config.disable_on_etag && response_headers.contains_key("etag") {
            return PluginResult::Continue;
        }

        // Check Content-Type against whitelist.
        let compressible = response_headers
            .get("content-type")
            .is_some_and(|ct| self.is_compressible_content_type(ct));
        if !compressible {
            return PluginResult::Continue;
        }

        // Check Content-Length against minimum (if known).
        if let Some(cl) = response_headers.get("content-length")
            && let Ok(len) = cl.parse::<usize>()
            && len < self.config.min_content_length
        {
            return PluginResult::Continue;
        }

        // Select algorithm based on client's Accept-Encoding.
        let accept_encoding = ctx
            .metadata
            .get("compression:accept_encoding")
            .or_else(|| ctx.headers.get("accept-encoding"));

        let algorithm = match accept_encoding.and_then(|ae| self.select_algorithm(ae)) {
            Some(algo) => algo,
            None => return PluginResult::Continue,
        };

        // Record the decision for transform_response_body.
        ctx.metadata.insert(
            "compression:algorithm".to_string(),
            algorithm.content_encoding().to_string(),
        );

        // Set Content-Encoding. Remove Content-Length (it's stale after compression).
        response_headers.insert(
            "content-encoding".to_string(),
            algorithm.content_encoding().to_string(),
        );
        response_headers.remove("content-length");

        // Add Vary: Accept-Encoding so caches distinguish compressed variants.
        match response_headers.get("vary") {
            Some(existing) => {
                // Don't duplicate if already present.
                if !comma_header_contains_token(existing, "accept-encoding") {
                    let mut updated = String::with_capacity(existing.len() + 17);
                    updated.push_str(existing);
                    updated.push_str(", Accept-Encoding");
                    response_headers.insert("vary".to_string(), updated);
                }
            }
            None => {
                response_headers.insert("vary".to_string(), "Accept-Encoding".to_string());
            }
        }

        PluginResult::Continue
    }

    async fn transform_request_body(
        &self,
        body: &[u8],
        _content_type: Option<&str>,
        request_headers: &HashMap<String, String>,
    ) -> Option<Vec<u8>> {
        if !self.config.decompress_request || body.is_empty() {
            return None;
        }

        // Check Content-Encoding to decide how to decompress. The original
        // header was removed in before_proxy and saved under the private key
        // x-ferrum-original-content-encoding so the backend doesn't see it.
        let encoding = request_headers
            .get("x-ferrum-original-content-encoding")
            .or_else(|| request_headers.get("content-encoding"))
            .and_then(|v| supported_request_encoding(v))?;

        match self.decompress(encoding, body, self.config.max_decompressed_request_size) {
            Ok(decompressed) => {
                debug!(
                    "compression: decompressed request body from {} to {} bytes ({})",
                    body.len(),
                    decompressed.len(),
                    encoding
                );
                Some(decompressed)
            }
            Err(e) => {
                // On the normal buffered path `before_proxy` already validated
                // decodability and rejected a malformed body before stripping
                // Content-Encoding, so this branch is only reachable on the rare
                // path where the body was not buffered before before_proxy (e.g.
                // an HBONE CONNECT tunnel). There we cannot reject from this
                // hook, so we leave the body unchanged (returning `None`) as a
                // best-effort fallback.
                warn!("compression: request decompression failed: {e}");
                None
            }
        }
    }

    async fn transform_response_body(
        &self,
        body: &[u8],
        _content_type: Option<&str>,
        response_headers: &HashMap<String, String>,
    ) -> Option<Vec<u8>> {
        // The algorithm decision was made in `after_proxy` and recorded in
        // the `Content-Encoding` response header. If `after_proxy` did not
        // commit to an encoding, do nothing.
        let encoding = response_headers.get("content-encoding")?;

        let algo = match encoding.as_str() {
            "gzip" => Algorithm::Gzip,
            "br" => Algorithm::Brotli,
            _ => return None,
        };

        if response_headers
            .get("cache-control")
            .is_some_and(|value| cache_control_has_directive(value, "no-transform"))
        {
            return None;
        }

        // CRITICAL: once `after_proxy` set `Content-Encoding`, the response
        // is committed to that encoding. We MUST NOT short-circuit here on
        // body size — doing so would leave the client with a body labelled
        // `Content-Encoding: gzip` that is actually plaintext, which every
        // conformant client will reject as a decoding error.
        //
        // The minimum-length gate runs in `after_proxy` for the known-CL
        // case. When CL is unknown (chunked / streamed responses), we
        // accept that the rare tiny chunked body will be compressed needlessly
        // — far cheaper than serving a malformed response.

        match self.compress(algo, body) {
            Ok(compressed) => {
                debug!(
                    "compression: compressed response body from {} to {} bytes ({}, {:.1}% reduction)",
                    body.len(),
                    compressed.len(),
                    encoding,
                    if body.is_empty() {
                        0.0
                    } else {
                        (1.0 - compressed.len() as f64 / body.len() as f64) * 100.0
                    },
                );
                Some(compressed)
            }
            Err(e) => {
                // `flate2`/`brotli` writing to a `Vec` is effectively
                // infallible in practice, so this branch is unreachable in
                // production. If it ever does fire, the response headers
                // already commit us to a Content-Encoding that we cannot
                // honour — the client will see a corrupt body. Log loudly
                // so operators notice rather than silently downgrading.
                error!(
                    "compression: encoder failure for committed Content-Encoding '{}' — \
                     response will be malformed: {e}",
                    encoding
                );
                None
            }
        }
    }
}
