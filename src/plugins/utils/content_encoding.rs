//! Bounded decoding for plugin inspection of HTTP content codings.
//!
//! This utility never mutates the caller's body or headers. It is intended for
//! observability/security inspection paths that need a plaintext view while the
//! encoded representation must remain client-visible. The compression plugin
//! reuses the same parser/decoder for opt-in request decompression.

use std::borrow::Cow;
use std::io::Read;

/// Hard limits for one decoding operation.
#[derive(Debug, Clone, Copy)]
pub struct DecodeLimits {
    /// Maximum bytes produced by each decoded layer.
    pub max_decoded_bytes: usize,
    /// Maximum aggregate bytes produced across all decoded layers.
    pub max_cumulative_bytes: usize,
    /// Maximum number of content-coding layers.
    pub max_codings: usize,
    /// Maximum decoded/raw size ratio for each layer and for the final
    /// plaintext versus the original coded body. `0` disables the ratio check
    /// (absolute byte caps still apply).
    pub max_amplification_ratio: u32,
}

/// True when `value` is an HTTP `token` (RFC 9110 §5.6.2).
fn is_http_token(value: &str) -> bool {
    !value.is_empty()
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

/// Parse `Content-Encoding` as an ordered `#content-coding` list (RFC 9110 §8.4).
///
/// Members are trimmed for optional whitespace (OWS). Empty tokens, non-token
/// members, and parameters are rejected. Supported tokens are `gzip`, `x-gzip`
/// (normalized to `gzip`), `br`, and `identity` (case-insensitive).
pub fn parse_content_codings(header: &str) -> Result<Vec<String>, String> {
    let mut codings = Vec::new();
    for raw in header.split(',') {
        let coding = raw.trim();
        if coding.is_empty() {
            return Err("content-encoding contains an empty coding".to_string());
        }
        if coding.contains(';') {
            return Err(format!(
                "content-encoding coding '{coding}' contains unsupported parameters"
            ));
        }
        if !coding.is_ascii() || !is_http_token(coding) {
            return Err(format!(
                "content-encoding coding '{coding}' is not a valid HTTP token"
            ));
        }
        let coding = coding.to_ascii_lowercase();
        let canonical = match coding.as_str() {
            "gzip" | "x-gzip" => "gzip".to_string(),
            "br" => "br".to_string(),
            "identity" => "identity".to_string(),
            _ => return Err(format!("unsupported content-encoding '{coding}'")),
        };
        codings.push(canonical);
    }
    if codings.is_empty() {
        return Err("content-encoding contains no coding members".to_string());
    }
    Ok(codings)
}

/// Decode a complete `Content-Encoding` chain for inspection.
///
/// Codings are parsed as an HTTP `#content-coding` list (RFC 9110 §8.4) and
/// removed in reverse application order. `gzip` / `x-gzip`, `br`, and
/// `identity`-only lists are supported case-insensitively. Empty tokens,
/// non-token members, parameters, unsupported codings, mixed `identity`, too
/// many layers, trailing data, concatenated streams, truncation, absolute
/// limit overruns, and raw-to-decoded amplification overruns are rejected.
/// Every decoded layer is capped by `max_decoded_bytes`, and the sum of all
/// decoded layer sizes is capped by `max_cumulative_bytes`.
pub fn decode_content_encoding<'a>(
    header: Option<&str>,
    body: &'a [u8],
    limits: DecodeLimits,
) -> Result<Cow<'a, [u8]>, String> {
    let Some(header) = header else {
        return Ok(Cow::Borrowed(body));
    };

    let codings = parse_content_codings(header)?;
    if codings.len() > limits.max_codings {
        return Err(format!(
            "content-encoding has more than {} coding layers",
            limits.max_codings
        ));
    }

    if codings.iter().all(|coding| coding == "identity") {
        return Ok(Cow::Borrowed(body));
    }
    if codings.iter().any(|coding| coding == "identity") {
        return Err("identity content-encoding cannot be combined with other codings".to_string());
    }

    let original_raw_len = body.len();
    let mut current = Cow::Borrowed(body);
    let mut cumulative = 0usize;
    for coding in codings.iter().rev() {
        let layer_input_len = current.len();
        let decoded = match coding.as_str() {
            "gzip" => decode_gzip_member(
                current.as_ref(),
                limits.max_decoded_bytes,
                limits.max_amplification_ratio,
            )?,
            "br" => decode_brotli_stream(
                current.as_ref(),
                limits.max_decoded_bytes,
                limits.max_amplification_ratio,
            )?,
            _ => return Err(format!("unsupported content-encoding '{coding}'")),
        };
        enforce_amplification(
            layer_input_len,
            decoded.len(),
            limits.max_amplification_ratio,
        )?;
        cumulative = cumulative
            .checked_add(decoded.len())
            .ok_or_else(|| "decoded content-encoding work overflowed".to_string())?;
        if cumulative > limits.max_cumulative_bytes {
            return Err(format!(
                "decoded content-encoding work exceeds {} bytes",
                limits.max_cumulative_bytes
            ));
        }
        current = Cow::Owned(decoded);
    }

    enforce_amplification(
        original_raw_len,
        current.len(),
        limits.max_amplification_ratio,
    )?;

    Ok(current)
}

fn enforce_amplification(
    raw_len: usize,
    decoded_len: usize,
    max_amplification_ratio: u32,
) -> Result<(), String> {
    if max_amplification_ratio == 0 || raw_len == 0 {
        return Ok(());
    }
    let Some(limit) = raw_len.checked_mul(max_amplification_ratio as usize) else {
        // raw * ratio overflows usize; absolute layer/cumulative caps still apply.
        return Ok(());
    };
    if decoded_len > limit {
        return Err(format!(
            "decoded content-encoding amplification exceeds {max_amplification_ratio}:1"
        ));
    }
    Ok(())
}

fn decode_gzip_member(
    input: &[u8],
    max_bytes: usize,
    max_amplification_ratio: u32,
) -> Result<Vec<u8>, String> {
    let mut decoder = flate2::bufread::GzDecoder::new(input);
    let decoded = read_bounded(
        &mut decoder,
        max_bytes,
        input.len(),
        max_amplification_ratio,
        "gzip",
    )?;
    if !decoder.into_inner().is_empty() {
        return Err("gzip content contains trailing or concatenated data".to_string());
    }
    Ok(decoded)
}

fn decode_brotli_stream(
    input: &[u8],
    max_bytes: usize,
    max_amplification_ratio: u32,
) -> Result<Vec<u8>, String> {
    use brotli::{BrotliDecompressStream, BrotliResult, BrotliState, HeapAlloc, HuffmanCode};

    let mut state = BrotliState::new(
        HeapAlloc::<u8>::new(0),
        HeapAlloc::<u32>::new(0),
        HeapAlloc::<HuffmanCode>::new(HuffmanCode::default()),
    );
    let mut available_in = input.len();
    let mut input_offset = 0usize;
    let mut decoded = Vec::with_capacity(input.len().min(max_bytes));
    let mut chunk = [0u8; 8192];

    loop {
        let mut available_out = chunk.len();
        let mut output_offset = 0usize;
        let mut total_out = 0usize;
        let result = BrotliDecompressStream(
            &mut available_in,
            &mut input_offset,
            input,
            &mut available_out,
            &mut output_offset,
            &mut chunk,
            &mut total_out,
            &mut state,
        );

        if decoded
            .len()
            .checked_add(output_offset)
            .is_none_or(|size| size > max_bytes)
        {
            return Err(format!("brotli decoded content exceeds {max_bytes} bytes"));
        }
        decoded.extend_from_slice(&chunk[..output_offset]);
        enforce_amplification(input.len(), decoded.len(), max_amplification_ratio)?;

        match result {
            BrotliResult::ResultSuccess => {
                if available_in != 0 || input_offset != input.len() {
                    return Err("brotli content contains trailing or concatenated data".to_string());
                }
                return Ok(decoded);
            }
            BrotliResult::NeedsMoreOutput => continue,
            BrotliResult::NeedsMoreInput => {
                return Err("brotli content is truncated".to_string());
            }
            BrotliResult::ResultFailure => {
                return Err("brotli decompression failed".to_string());
            }
        }
    }
}

fn read_bounded(
    reader: &mut dyn Read,
    max_bytes: usize,
    raw_len: usize,
    max_amplification_ratio: u32,
    coding: &str,
) -> Result<Vec<u8>, String> {
    let mut decoded = Vec::with_capacity(8192.min(max_bytes));
    let mut chunk = [0u8; 8192];
    loop {
        let read = reader
            .read(&mut chunk)
            .map_err(|error| format!("{coding} decompression failed: {error}"))?;
        if read == 0 {
            return Ok(decoded);
        }
        if decoded
            .len()
            .checked_add(read)
            .is_none_or(|size| size > max_bytes)
        {
            return Err(format!(
                "{coding} decoded content exceeds {max_bytes} bytes"
            ));
        }
        decoded.extend_from_slice(&chunk[..read]);
        enforce_amplification(raw_len, decoded.len(), max_amplification_ratio)?;
    }
}
