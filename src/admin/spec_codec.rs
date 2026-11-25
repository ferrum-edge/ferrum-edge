//! gzip + sha256 helpers for the OpenAPI/Swagger spec admin API.
//!
//! These utilities are used by the admin API when storing and retrieving
//! OpenAPI specs. The spec content is gzip-compressed before storage and
//! a SHA-256 digest of the **uncompressed** bytes is recorded for integrity
//! verification.

use crate::fips::approved::Sha256;
use flate2::Compression;
use flate2::read::GzDecoder;
use flate2::write::GzEncoder;
use std::io::{Read, Write};

/// Compress `input` bytes using gzip at the default compression level (6).
///
/// Returns the compressed bytes. The caller is responsible for recording
/// `input.len()` as the `uncompressed_size` and storing the result as
/// `spec_content` with `content_encoding = "gzip"`.
pub fn compress_gzip(input: &[u8]) -> std::io::Result<Vec<u8>> {
    let mut encoder = GzEncoder::new(Vec::new(), Compression::default());
    encoder.write_all(input)?;
    encoder.finish()
}

/// Decompress gzip-compressed `input` bytes, returning an error if the
/// decompressed output would exceed `max_output` bytes.
///
/// # Errors
///
/// Returns an `io::Error` of kind `Other` with message
/// `"decompressed size exceeds max_output cap"` when the limit is reached.
/// The caller should surface this as a 500 with a generic
/// `"spec content corrupt or oversized"` message — operators investigate via
/// the DB directly.
pub fn decompress_gzip_capped(input: &[u8], max_output: usize) -> std::io::Result<Vec<u8>> {
    let mut decoder = GzDecoder::new(input);
    let mut buf = Vec::new();
    let max_u64 = u64::try_from(max_output).unwrap_or(u64::MAX);
    if let Some(limit) = max_u64.checked_add(1) {
        decoder.take(limit).read_to_end(&mut buf)?;
        if buf.len() > max_output {
            return Err(std::io::Error::other(
                "decompressed size exceeds max_output cap",
            ));
        }
    } else {
        // `max_output == u64::MAX as usize`: read up to `max_u64` bytes without
        // overflowing `max_u64 + 1`, then probe one additional byte.
        (&mut decoder).take(max_u64).read_to_end(&mut buf)?;
        let mut extra = [0u8; 1];
        if decoder.read(&mut extra)? > 0 {
            return Err(std::io::Error::other(
                "decompressed size exceeds max_output cap",
            ));
        }
    }
    Ok(buf)
}

/// Stream gzip-decompressed `input` bytes into `writer` in bounded 8 KiB
/// chunks, failing with `ErrorKind::Other` before writing past `max_output`
/// bytes so callers can enforce live per-connection byte budgets during
/// decompression rather than only after buffering the full output.
///
/// If `writer` switches to discard-and-count mode upon soft budget exhaustion,
/// this loop keeps draining through EOF or `max_output` in the 8 KiB stack
/// buffer so permanent gzip corruption or `> max_output` errors still win over
/// retryable budget rejection.
pub(crate) fn decompress_gzip_capped_to_writer<W: Write>(
    input: &[u8],
    max_output: usize,
    writer: &mut W,
) -> std::io::Result<()> {
    let mut decoder = GzDecoder::new(input);
    let mut chunk = [0u8; 8 * 1024];
    let mut total: usize = 0;
    loop {
        let read = decoder.read(&mut chunk)?;
        if read == 0 {
            return Ok(());
        }
        total = total.saturating_add(read);
        if total > max_output {
            return Err(std::io::Error::other(
                "decompressed size exceeds max_output cap",
            ));
        }
        writer.write_all(&chunk[..read])?;
    }
}

/// Streaming `Read` adapter over `GzDecoder<R>` that fails closed with
/// `ErrorKind::Other` if decompressed output exceeds `max_output` bytes.
pub(crate) struct CappedGzipReader<R: Read> {
    decoder: GzDecoder<R>,
    remaining: usize,
}

impl<R: Read> CappedGzipReader<R> {
    pub(crate) fn new(input: R, max_output: usize) -> Self {
        Self {
            decoder: GzDecoder::new(input),
            remaining: max_output,
        }
    }
}

impl<R: Read> Read for CappedGzipReader<R> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        if buf.is_empty() {
            return Ok(0);
        }
        let read = self.decoder.read(buf)?;
        if read > self.remaining {
            return Err(std::io::Error::other(
                "decompressed size exceeds max_output cap",
            ));
        }
        self.remaining -= read;
        Ok(read)
    }
}

/// Compute the SHA-256 digest of `input` and return it as a lowercase hex
/// string (64 characters).
///
/// The digest is computed over the **uncompressed** spec bytes so that the
/// hash remains stable regardless of the compression level used.
pub fn sha256_hex(input: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(input);
    hex::encode(hasher.finalize())
}

#[cfg(test)]
mod tests {
    use super::{compress_gzip, decompress_gzip_capped, sha256_hex};

    /// Generous cap for round-trip tests — comfortably above any test input below.
    const TEST_DECOMPRESS_CAP: usize = 16 * 1024 * 1024;

    #[test]
    fn roundtrip_preserves_bytes() {
        let input = b"hello, ferrum-edge spec!";
        let compressed = compress_gzip(input).expect("compress failed");
        let decompressed =
            decompress_gzip_capped(&compressed, TEST_DECOMPRESS_CAP).expect("decompress failed");
        assert_eq!(decompressed, input);
    }

    #[test]
    fn roundtrip_handles_large_input() {
        // 5 MiB of pseudo-random-ish bytes (deterministic via index arithmetic)
        let input: Vec<u8> = (0u64..5 * 1024 * 1024)
            .map(|i| {
                (i.wrapping_mul(6364136223846793005)
                    .wrapping_add(1442695040888963407)
                    >> 56) as u8
            })
            .collect();
        let compressed = compress_gzip(&input).expect("compress failed");
        let decompressed =
            decompress_gzip_capped(&compressed, TEST_DECOMPRESS_CAP).expect("decompress failed");
        assert_eq!(decompressed, input);
    }

    #[test]
    fn roundtrip_handles_empty() {
        let input: &[u8] = &[];
        let compressed = compress_gzip(input).expect("compress failed on empty");
        let decompressed = decompress_gzip_capped(&compressed, TEST_DECOMPRESS_CAP)
            .expect("decompress failed on empty");
        assert_eq!(decompressed, input);
    }

    #[test]
    fn compression_actually_compresses() {
        // 100 KiB of repeating "abcd" — highly compressible
        let input: Vec<u8> = b"abcd".iter().cycle().take(100 * 1024).copied().collect();
        let compressed = compress_gzip(&input).expect("compress failed");
        assert!(
            compressed.len() < input.len(),
            "compressed ({} bytes) should be smaller than input ({} bytes)",
            compressed.len(),
            input.len()
        );
    }

    #[test]
    fn sha256_hex_is_64_chars_lowercase() {
        // SHA-256("hello") = known digest
        let digest = sha256_hex(b"hello");
        assert_eq!(digest.len(), 64, "SHA-256 hex digest must be 64 characters");
        assert!(
            digest
                .chars()
                .all(|c| c.is_ascii_hexdigit() && !c.is_uppercase()),
            "digest must be lowercase hex: {}",
            digest
        );
        // Known value — verified against `echo -n 'hello' | sha256sum`
        assert_eq!(
            digest,
            "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824"
        );
    }

    #[test]
    fn sha256_hex_changes_with_input() {
        let a = sha256_hex(b"hello");
        let b = sha256_hex(b"world");
        assert_ne!(a, b, "different inputs must produce different digests");
    }

    /// Compressing a large block of zeros produces a tiny gzip stream.
    /// `decompress_gzip_capped` with a cap smaller than the decompressed size
    /// must return an error.  This guards against bomb-ratio rows in the DB
    /// expanding to GB on every admin GET (M3).
    #[test]
    fn decompress_caps_oversized_output() {
        // 4 MiB of zeros — compresses to ~a few KB.
        let input: Vec<u8> = vec![0u8; 4 * 1024 * 1024];
        let compressed = compress_gzip(&input).expect("compress failed");

        // Cap at 1 MiB — the decompressed output (4 MiB) exceeds the cap.
        let cap = 1024 * 1024;
        let result = decompress_gzip_capped(&compressed, cap);
        assert!(
            result.is_err(),
            "decompress_gzip_capped must error when decompressed size exceeds cap"
        );
        let err = result.unwrap_err();
        assert!(
            err.to_string().contains("exceeds max_output cap"),
            "error message must mention cap; got: {err}"
        );
    }

    /// `decompress_gzip_capped` with a cap at or above the decompressed size
    /// must succeed and return the full bytes.
    #[test]
    fn decompress_capped_within_limit_succeeds() {
        let input = b"hello, ferrum-edge spec!";
        let compressed = compress_gzip(input).expect("compress failed");
        let result =
            decompress_gzip_capped(&compressed, 1024).expect("decompress within cap must succeed");
        assert_eq!(result, input);
    }
}
