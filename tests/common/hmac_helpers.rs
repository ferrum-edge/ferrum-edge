//! Shared HMAC test helpers for functional tests that exercise HMAC
//! authentication (auth/ACL, credential rotation, etc.).

use base64::Engine;
use hmac::{Hmac, KeyInit, Mac};
use sha2::{Digest, Sha256};

type HmacSha256 = Hmac<Sha256>;

/// `Authorization` header for one `ferrum-hmac-v2` request with an empty
/// query, signed over `digest_header` with a fresh nonce.
///
/// Every call mints a new nonce, so each request built from it is single-use
/// on its own; resending the returned header is a replay.
pub fn hmac_v2_authorization(
    method: &str,
    path: &str,
    date: &str,
    username: &str,
    authority: &str,
    secret: &str,
    digest_header: &str,
) -> String {
    let nonce = fresh_hmac_v2_nonce();
    hmac_v2_authorization_header(
        &HmacV2Request {
            method,
            path,
            date,
            username,
            authority,
            secret,
            digest_header,
            nonce: &nonce,
        },
        None,
    )
}

/// A process-unique 32-hex-character nonce (wall-clock nanoseconds plus a
/// counter), so concurrently built requests never share one.
fn fresh_hmac_v2_nonce() -> String {
    use std::sync::atomic::{AtomicU64, Ordering};
    static NEXT: AtomicU64 = AtomicU64::new(0);
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |elapsed| elapsed.as_nanos() as u64);
    format!("{nanos:016x}{:016x}", NEXT.fetch_add(1, Ordering::Relaxed))
}

/// Fields signed by the `ferrum-hmac-v2` base.
pub struct HmacV2Request<'a> {
    pub method: &'a str,
    pub path: &'a str,
    pub date: &'a str,
    pub username: &'a str,
    pub authority: &'a str,
    pub secret: &'a str,
    pub digest_header: &'a str,
    /// The nonce bound into the signature.
    pub nonce: &'a str,
}

/// Compute a `ferrum-hmac-v2` signature.
///
/// The profile version is the base's first field and the nonce its trailing
/// bound field, so the signature verifies only as `ferrum-hmac-v2` with this
/// exact nonce.
pub fn hmac_v2_signature(request: &HmacV2Request<'_>) -> String {
    let signing_string = format!(
        "ferrum-hmac-v2\n{}\n{}\n{}\n{}\n{}\n\n{}\n{}\n{}",
        ferrum_edge::config::types::DEFAULT_NAMESPACE,
        request.username,
        request.authority,
        request.method,
        request.path,
        request.date,
        request.digest_header,
        request.nonce
    );
    let mut mac = HmacSha256::new_from_slice(request.secret.as_bytes())
        .expect("Failed to create HMAC instance");
    mac.update(signing_string.as_bytes());
    base64::engine::general_purpose::STANDARD.encode(mac.finalize().into_bytes())
}

/// Build a `ferrum-hmac-v2` `Authorization` header value.
///
/// `declared_nonce` is what goes on the wire; it defaults to the signed nonce.
/// Passing a different value is how a test proves the nonce is actually bound:
/// swapping it without recomputing the signature must fail authentication.
pub fn hmac_v2_authorization_header(
    request: &HmacV2Request<'_>,
    declared_nonce: Option<&str>,
) -> String {
    let signature = hmac_v2_signature(request);
    let nonce = declared_nonce.unwrap_or(request.nonce);
    let username = request.username;
    format!(
        r#"hmac username="{username}", algorithm="hmac-sha256", nonce="{nonce}", signature="{signature}""#
    )
}

/// A 32-character lowercase-hex nonce — exactly the 128-bit minimum the v2
/// wire form admits for the hex spelling.
pub fn hmac_v2_nonce(seed: u64) -> String {
    format!("{seed:032x}")
}

/// Return the canonical authority used to sign a request sent to `url`.
pub fn hmac_authority_from_url(url: &str) -> String {
    let parsed = reqwest::Url::parse(url).expect("test HMAC URL must be valid");
    let raw_host = parsed.host_str().expect("test HMAC URL must have a host");
    let host = if raw_host.contains(':') {
        format!("[{raw_host}]")
    } else {
        raw_host.to_ascii_lowercase()
    };
    parsed
        .port()
        .map_or(host.clone(), |port| format!("{host}:{port}"))
}

/// Return the SHA-256 digest header value for an empty body.
pub fn empty_digest_header() -> String {
    legacy_digest_sha256_header(&[])
}

/// RFC 3230 `Digest` SHA-256 value for `body` (`sha-256=<standard-base64>`).
fn legacy_digest_sha256_header(body: &[u8]) -> String {
    format!(
        "sha-256={}",
        base64::engine::general_purpose::STANDARD.encode(Sha256::digest(body))
    )
}

/// RFC 9530 `Content-Digest` SHA-256 structured field for `body`.
///
/// The value is `sha-256=:<standard-base64>:`. It is not valid on a legacy
/// `Digest` header, and a legacy `Digest` value is not valid on `Content-Digest`.
pub fn content_digest_sha256_header(body: &[u8]) -> String {
    format!(
        "sha-256=:{}:",
        base64::engine::general_purpose::STANDARD.encode(Sha256::digest(body))
    )
}
