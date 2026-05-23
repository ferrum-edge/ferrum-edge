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
    const HEX: &[u8; 16] = b"0123456789ABCDEF";
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
                result.push('%');
                result.push(HEX[(byte >> 4) as usize] as char);
                result.push(HEX[(byte & 0x0f) as usize] as char);
            }
        }
    }
    result
}

fn uri_encode_query_component(input: &str) -> String {
    const HEX: &[u8; 16] = b"0123456789ABCDEF";

    let bytes = input.as_bytes();
    let mut result = String::with_capacity(input.len() * 2);
    let mut idx = 0;
    while idx < bytes.len() {
        let byte = bytes[idx];
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                result.push(byte as char);
                idx += 1;
            }
            b'%' if idx + 2 < bytes.len()
                && bytes[idx + 1].is_ascii_hexdigit()
                && bytes[idx + 2].is_ascii_hexdigit() =>
            {
                result.push('%');
                result.push((bytes[idx + 1] as char).to_ascii_uppercase());
                result.push((bytes[idx + 2] as char).to_ascii_uppercase());
                idx += 3;
            }
            _ => {
                result.push('%');
                result.push(HEX[(byte >> 4) as usize] as char);
                result.push(HEX[(byte & 0x0f) as usize] as char);
                idx += 1;
            }
        }
    }
    result
}

fn canonical_query_string(raw_query: &str) -> String {
    if raw_query.is_empty() {
        return String::new();
    }

    let mut pairs = raw_query
        .split('&')
        .map(|part| {
            let (name, value) = part.split_once('=').unwrap_or((part, ""));
            (
                uri_encode_query_component(name),
                uri_encode_query_component(value),
            )
        })
        .collect::<Vec<_>>();
    pairs.sort();

    let mut canonical = String::new();
    for (idx, (name, value)) in pairs.iter().enumerate() {
        if idx > 0 {
            canonical.push('&');
        }
        canonical.push_str(name);
        canonical.push('=');
        canonical.push_str(value);
    }
    canonical
}

/// SHA-256 hash of data, returned as lowercase hex.
pub fn sha256_hex(data: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(data);
    hex::encode(hasher.finalize())
}

/// HMAC-SHA256 keyed hash.
pub fn hmac_sha256(key: &[u8], data: &[u8]) -> Result<Vec<u8>, String> {
    let mut mac = HmacSha256::new_from_slice(key)
        .map_err(|_| "HMAC-SHA256 rejected a key length that should be accepted".to_string())?;
    mac.update(data);
    Ok(mac.finalize().into_bytes().to_vec())
}

/// Derive the SigV4 signing key:
/// `HMAC(HMAC(HMAC(HMAC("AWS4"+secret, date), region), service), "aws4_request")`
pub fn derive_signing_key(
    secret: &str,
    date_stamp: &str,
    region: &str,
    service: &str,
) -> Result<Vec<u8>, String> {
    let k_date = hmac_sha256(format!("AWS4{}", secret).as_bytes(), date_stamp.as_bytes())?;
    let k_region = hmac_sha256(&k_date, region.as_bytes())?;
    let k_service = hmac_sha256(&k_region, service.as_bytes())?;
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
) -> Result<Vec<(String, String)>, String> {
    let date_stamp = now.format("%Y%m%d").to_string();
    let amz_date = now.format("%Y%m%dT%H%M%SZ").to_string();

    let parsed_url =
        Url::parse(url_str).map_err(|e| format!("AWS SigV4 invalid request URL: {e}"))?;

    let host = parsed_url
        .host_str()
        .ok_or_else(|| "AWS SigV4 request URL must include a host".to_string())?
        .to_string();

    let canonical_uri = uri_encode(parsed_url.path(), false);
    let canonical_querystring = canonical_query_string(parsed_url.query().unwrap_or(""));

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
    )?;
    let signature = hex::encode(hmac_sha256(&signing_key, string_to_sign.as_bytes())?);

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

    Ok(headers)
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::TimeZone;

    fn config() -> AwsSigV4Config {
        AwsSigV4Config {
            region: "us-east-1".to_string(),
            access_key_id: "AKIAIOSFODNN7EXAMPLE".to_string(),
            secret_access_key: "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY".to_string(),
            session_token: None,
        }
    }

    fn now() -> chrono::DateTime<chrono::Utc> {
        chrono::Utc
            .with_ymd_and_hms(2024, 1, 15, 12, 0, 0)
            .single()
            .expect("fixed timestamp should be valid")
    }

    fn authorization_for(url: &str) -> String {
        sign_request(
            &config(),
            "lambda",
            "POST",
            url,
            "application/json",
            b"{}",
            &now(),
        )
        .expect("signing should succeed")
        .into_iter()
        .find(|(name, _)| name == "authorization")
        .map(|(_, value)| value)
        .expect("authorization header should be present")
    }

    #[test]
    fn uri_encode_uses_sigv4_unreserved_set_and_uppercase_hex() {
        assert_eq!(uri_encode("AZaz09-_.~", true), "AZaz09-_.~");
        assert_eq!(uri_encode(" /+☃", true), "%20%2F%2B%E2%98%83");
        assert_eq!(uri_encode("/path/segment", false), "/path/segment");
        assert_eq!(uri_encode("/path/segment", true), "%2Fpath%2Fsegment");
    }

    #[test]
    fn canonical_query_string_sorts_names_and_values() {
        assert_eq!(
            canonical_query_string("z=last&a=2&a=1&empty&space=a%20b&plus=a+b&slash=a/b"),
            "a=1&a=2&empty=&plus=a%2Bb&slash=a%2Fb&space=a%20b&z=last"
        );
    }

    #[test]
    fn canonical_query_string_normalizes_percent_hex_case() {
        assert_eq!(
            canonical_query_string("token=a%2fb&literal_percent=%"),
            "literal_percent=%25&token=a%2Fb"
        );
    }

    #[test]
    fn sign_request_is_independent_of_query_parameter_order() {
        let one = authorization_for(
            "https://lambda.us-east-1.amazonaws.com/2015-03-31/functions/my-function/invocations?b=2&a=1",
        );
        let two = authorization_for(
            "https://lambda.us-east-1.amazonaws.com/2015-03-31/functions/my-function/invocations?a=1&b=2",
        );

        assert_eq!(one, two);
    }

    #[test]
    fn sign_request_signature_changes_when_query_value_changes() {
        let one = authorization_for(
            "https://lambda.us-east-1.amazonaws.com/2015-03-31/functions/my-function/invocations?a=1",
        );
        let two = authorization_for(
            "https://lambda.us-east-1.amazonaws.com/2015-03-31/functions/my-function/invocations?a=2",
        );

        assert_ne!(one, two);
    }
}
