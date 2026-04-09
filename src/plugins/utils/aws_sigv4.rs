//! Shared AWS SigV4 request signing.
//!
//! This module provides a reusable SigV4 implementation for any AWS service.
//! Used by `serverless_function` (Lambda) and `ai_federation` (Bedrock).

use hmac::{Hmac, KeyInit, Mac};
use sha2::{Digest, Sha256};
use url::Url;

type HmacSha256 = Hmac<Sha256>;

/// AWS credentials and region for SigV4 signing.
#[derive(Debug, Clone)]
pub struct AwsSigV4Config {
    pub region: String,
    pub access_key_id: String,
    pub secret_access_key: String,
    pub session_token: Option<String>,
}

/// URI-encode a string per AWS SigV4 rules.
/// When `encode_slash` is false, forward slashes are preserved (for URI paths).
pub fn uri_encode(input: &str, encode_slash: bool) -> String {
    let mut result = String::with_capacity(input.len() * 2);
    for byte in input.bytes() {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                result.push(byte as char);
            }
            b'/' if !encode_slash => {
                result.push('/');
            }
            _ => {
                result.push_str(&format!("%{:02X}", byte));
            }
        }
    }
    result
}

/// SHA-256 hash of data, returned as lowercase hex.
pub fn sha256_hex(data: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(data);
    hex::encode(hasher.finalize())
}

/// HMAC-SHA256 keyed hash.
pub fn hmac_sha256(key: &[u8], data: &[u8]) -> Vec<u8> {
    let mut mac = HmacSha256::new_from_slice(key).expect("HMAC-SHA256 accepts any key length");
    mac.update(data);
    mac.finalize().into_bytes().to_vec()
}

/// Derive the SigV4 signing key:
/// `HMAC(HMAC(HMAC(HMAC("AWS4"+secret, date), region), service), "aws4_request")`
pub fn derive_signing_key(secret: &str, date_stamp: &str, region: &str, service: &str) -> Vec<u8> {
    let k_date = hmac_sha256(format!("AWS4{}", secret).as_bytes(), date_stamp.as_bytes());
    let k_region = hmac_sha256(&k_date, region.as_bytes());
    let k_service = hmac_sha256(&k_region, service.as_bytes());
    hmac_sha256(&k_service, b"aws4_request")
}

/// Sign an AWS API request using SigV4.
///
/// Returns the headers that must be added to the request (`authorization`,
/// `x-amz-date`, `x-amz-content-sha256`, and optionally `x-amz-security-token`).
///
/// # Parameters
/// - `config` — AWS credentials and region
/// - `service` — AWS service name (e.g. `"lambda"`, `"bedrock"`)
/// - `method` — HTTP method (e.g. `"POST"`)
/// - `url_str` — Full request URL
/// - `content_type` — Content-Type header value (included in signed headers)
/// - `payload` — Request body bytes
/// - `now` — Current UTC timestamp (parameterized for deterministic testing)
pub fn sign_request(
    config: &AwsSigV4Config,
    service: &str,
    method: &str,
    url_str: &str,
    content_type: &str,
    payload: &[u8],
    now: &chrono::DateTime<chrono::Utc>,
) -> Vec<(String, String)> {
    let date_stamp = now.format("%Y%m%d").to_string();
    let amz_date = now.format("%Y%m%dT%H%M%SZ").to_string();

    let parsed_url = match Url::parse(url_str) {
        Ok(u) => u,
        Err(_) => return Vec::new(),
    };

    let host = match parsed_url.host_str() {
        Some(h) => h.to_string(),
        None => return Vec::new(),
    };

    let canonical_uri = uri_encode(parsed_url.path(), false);
    let canonical_querystring = parsed_url.query().unwrap_or("");

    let payload_hash = sha256_hex(payload);

    // Canonical headers (must be sorted alphabetically by header name).
    // When a session token is present, x-amz-security-token is included.
    let (canonical_headers, signed_headers) = if config.session_token.is_some() {
        (
            format!(
                "content-type:{}\nhost:{}\nx-amz-content-sha256:{}\nx-amz-date:{}\nx-amz-security-token:{}\n",
                content_type,
                host,
                payload_hash,
                amz_date,
                config.session_token.as_deref().unwrap_or_default()
            ),
            "content-type;host;x-amz-content-sha256;x-amz-date;x-amz-security-token",
        )
    } else {
        (
            format!(
                "content-type:{}\nhost:{}\nx-amz-content-sha256:{}\nx-amz-date:{}\n",
                content_type, host, payload_hash, amz_date
            ),
            "content-type;host;x-amz-content-sha256;x-amz-date",
        )
    };

    let canonical_request = format!(
        "{}\n{}\n{}\n{}\n{}\n{}",
        method,
        canonical_uri,
        canonical_querystring,
        canonical_headers,
        signed_headers,
        payload_hash
    );

    let credential_scope = format!("{}/{}/{}/aws4_request", date_stamp, config.region, service);
    let string_to_sign = format!(
        "AWS4-HMAC-SHA256\n{}\n{}\n{}",
        amz_date,
        credential_scope,
        sha256_hex(canonical_request.as_bytes())
    );

    let signing_key = derive_signing_key(
        &config.secret_access_key,
        &date_stamp,
        &config.region,
        service,
    );
    let signature = hex::encode(hmac_sha256(&signing_key, string_to_sign.as_bytes()));

    let authorization = format!(
        "AWS4-HMAC-SHA256 Credential={}/{}, SignedHeaders={}, Signature={}",
        config.access_key_id, credential_scope, signed_headers, signature
    );

    let mut headers = vec![
        ("authorization".to_string(), authorization),
        ("x-amz-date".to_string(), amz_date),
        ("x-amz-content-sha256".to_string(), payload_hash),
    ];

    if let Some(ref token) = config.session_token {
        headers.push(("x-amz-security-token".to_string(), token.clone()));
    }

    headers
}
