//! gzip + sha256 helpers for the OpenAPI/Swagger spec admin API.
//!
//! These utilities are used by the admin API when storing and retrieving
//! OpenAPI specs. The spec content is gzip-compressed before storage and
//! a SHA-256 digest of the **uncompressed** bytes is recorded for integrity
//! verification.

use flate2::Compression;
use flate2::read::GzDecoder;
use flate2::write::GzEncoder;
use sha2::{Digest, Sha256};
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

/// Decompress gzip-compressed `input` bytes.
///
/// Returns the original uncompressed bytes. Used when the admin API needs
/// to serve the raw spec to a client (e.g., `GET /api-specs/:id/raw`).
pub fn decompress_gzip(input: &[u8]) -> std::io::Result<Vec<u8>> {
    let mut decoder = GzDecoder::new(input);
    let mut buf = Vec::new();
    decoder.read_to_end(&mut buf)?;
    Ok(buf)
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
    use super::{compress_gzip, decompress_gzip, sha256_hex};

    #[test]
    fn roundtrip_preserves_bytes() {
        let input = b"hello, ferrum-edge spec!";
        let compressed = compress_gzip(input).expect("compress failed");
        let decompressed = decompress_gzip(&compressed).expect("decompress failed");
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
        let decompressed = decompress_gzip(&compressed).expect("decompress failed");
        assert_eq!(decompressed, input);
    }

    #[test]
    fn roundtrip_handles_empty() {
        let input: &[u8] = &[];
        let compressed = compress_gzip(input).expect("compress failed on empty");
        let decompressed = decompress_gzip(&compressed).expect("decompress failed on empty");
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
}
