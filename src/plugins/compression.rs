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
use tracing::{debug, warn};

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
        let algorithms = config["algorithms"]
            .as_array()
            .map(|arr| {
                arr.iter()
                    .filter_map(|v| match v.as_str()? {
                        "gzip" => Some(Algorithm::Gzip),
                        "br" | "brotli" => Some(Algorithm::Brotli),
                        other => {
                            warn!("compression: unknown algorithm '{}', skipping", other);
                            None
                        }
                    })
                    .collect()
            })
            .unwrap_or_else(|| vec![Algorithm::Gzip, Algorithm::Brotli]);

        let content_types = config["content_types"]
            .as_array()
            .map(|arr| {
                arr.iter()
                    .filter_map(|v| v.as_str().map(|s| s.to_lowercase()))
                    .collect()
            })
            .unwrap_or_else(|| {
                DEFAULT_CONTENT_TYPES
                    .iter()
                    .map(|s| (*s).to_string())
                    .collect()
            });

        let min_content_length = config["min_content_length"].as_u64().unwrap_or(256) as usize;

        let disable_on_etag = config["disable_on_etag"].as_bool().unwrap_or(false);

        let remove_accept_encoding = config["remove_accept_encoding"].as_bool().unwrap_or(true);

        let decompress_request = config["decompress_request"].as_bool().unwrap_or(false);

        let max_decompressed_request_size = config["max_decompressed_request_size"]
            .as_u64()
            .unwrap_or(10 * 1024 * 1024) as usize;

        let gzip_level = config["gzip_level"]
            .as_u64()
            .map(|v| v.min(9) as u32)
            .unwrap_or(6);

        let brotli_quality = config["brotli_quality"]
            .as_u64()
            .map(|v| v.min(11) as u32)
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
    /// algorithms at whatever q-value `*` carries.
    fn select_algorithm(&self, accept_encoding: &str) -> Option<Algorithm> {
        let mut best: Option<(Algorithm, f32, usize)> = None; // (algo, q, server_pref_index)

        for part in accept_encoding.split(',') {
            let part = part.trim();
            if part.is_empty() {
                continue;
            }

            let (encoding, quality) = parse_encoding_quality(part);
            if quality <= 0.0 {
                continue;
            }

            for (pref_idx, &algo) in self.config.algorithms.iter().enumerate() {
                let matches = match algo {
                    Algorithm::Gzip => encoding.eq_ignore_ascii_case("gzip"),
                    Algorithm::Brotli => encoding.eq_ignore_ascii_case("br"),
                };
                if !matches && encoding != "*" {
                    continue;
                }

                let dominated = best.is_some_and(|(_, best_q, best_pref)| {
                    quality < best_q || (quality == best_q && pref_idx >= best_pref)
                });
                if !dominated {
                    best = Some((algo, quality, pref_idx));
                }
            }
        }

        best.map(|(algo, _, _)| algo)
    }

    /// Check if the content type is eligible for compression.
    fn is_compressible_content_type(&self, content_type: &str) -> bool {
        let ct_lower = content_type.to_lowercase();
        self.config
            .content_types
            .iter()
            .any(|t| ct_lower.contains(t.as_str()))
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
        use flate2::read::GzDecoder;

        let mut decoder = GzDecoder::new(data);
        read_with_limit(&mut decoder, max_size, "gzip")
    }

    fn decompress_brotli(&self, data: &[u8], max_size: usize) -> Result<Vec<u8>, String> {
        let mut reader = brotli::Decompressor::new(data, 4096);
        read_with_limit(&mut reader, max_size, "brotli")
    }
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
                && let Ok(q) = stripped.trim().parse::<f32>()
            {
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

    fn requires_response_body_buffering(&self) -> bool {
        !self.config.algorithms.is_empty()
    }

    async fn before_proxy(
        &self,
        ctx: &mut RequestContext,
        headers: &mut HashMap<String, String>,
    ) -> PluginResult {
        // Save original Accept-Encoding before we potentially strip it.
        if let Some(ae) = ctx.headers.get("accept-encoding") {
            ctx.metadata
                .insert("compression:accept_encoding".to_string(), ae.clone());
        }

        // Strip Accept-Encoding from the backend request so the backend
        // sends an uncompressed response (we'll compress it ourselves).
        if self.config.remove_accept_encoding {
            headers.remove("accept-encoding");
        }

        // For request decompression: remove Content-Encoding from the backend
        // request headers since we'll decompress the body before forwarding.
        if self.config.decompress_request
            && let Some(ce) = headers.get("content-encoding")
        {
            let ce_lower = ce.to_lowercase();
            if ce_lower == "gzip" || ce_lower == "br" {
                ctx.metadata
                    .insert("compression:request_encoding".to_string(), ce_lower);
                headers.remove("content-encoding");
                // Content-Length will be wrong after decompression; remove it
                // so the backend uses chunked transfer or recalculates.
                headers.remove("content-length");
            }
        }

        PluginResult::Continue
    }

    async fn after_proxy(
        &self,
        ctx: &mut RequestContext,
        response_status: u16,
        response_headers: &mut HashMap<String, String>,
    ) -> PluginResult {
        // Skip uncompressible status codes.
        if UNCOMPRESSIBLE_STATUS_CODES.contains(&response_status) {
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
                if !existing.to_lowercase().contains("accept-encoding") {
                    let updated = format!("{existing}, Accept-Encoding");
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

        // Check Content-Encoding to decide how to decompress.
        let encoding = request_headers
            .get("content-encoding")
            .map(|v| v.to_lowercase())?;

        match self.decompress(&encoding, body, self.config.max_decompressed_request_size) {
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
        // The algorithm decision was made in after_proxy and recorded in
        // the Content-Encoding response header.
        let encoding = response_headers.get("content-encoding")?;

        let algo = match encoding.as_str() {
            "gzip" => Algorithm::Gzip,
            "br" => Algorithm::Brotli,
            _ => return None,
        };

        // Don't compress tiny bodies — the overhead exceeds savings.
        if body.len() < self.config.min_content_length {
            return None;
        }

        match self.compress(algo, body) {
            Ok(compressed) => {
                debug!(
                    "compression: compressed response body from {} to {} bytes ({}, {:.1}% reduction)",
                    body.len(),
                    compressed.len(),
                    encoding,
                    (1.0 - compressed.len() as f64 / body.len() as f64) * 100.0,
                );
                Some(compressed)
            }
            Err(e) => {
                warn!("compression: response compression failed, sending uncompressed: {e}");
                None
            }
        }
    }
}
