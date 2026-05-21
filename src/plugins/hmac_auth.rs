//! HMAC Authentication Plugin
//!
//! Validates HMAC-signed requests where the client signs the request
//! with a shared secret. Supports hmac-sha256 and hmac-sha512.
//!
//! Expected Authorization header format:
//!   hmac username="<username>", algorithm="hmac-sha256", signature="<base64-sig>"
//!
//! ## Signing string
//!
//! The signature is computed over four newline-separated fields:
//!
//!   ```text
//!   {METHOD}\n{PATH}\n{DATE}\n{DIGEST_HEADER_VALUE}
//!   ```
//!
//! The client must also include a `Digest:` (RFC 3230) or `Content-Digest:`
//! (RFC 9421) header whose value matches the SHA-256 / SHA-512 of the request
//! body, formatted as `sha-256=<base64>` or `sha-512=<base64>`. The plugin
//! verifies that the digest matches the actual buffered body bytes; tampering
//! with either the body or the digest header invalidates the HMAC.
//!
//! Consumer credentials should include:
//!   { "hmac_auth": { "secret": "<shared-secret>" } }

use async_trait::async_trait;
use base64::Engine as _;
use hmac::{Hmac, KeyInit, Mac};
use serde_json::Value;
use sha2::{Digest, Sha256, Sha512};
use tracing::{debug, warn};

use super::utils::auth_flow::{
    self, AuthMechanism, ExtractedCredential, VerifyOutcome, constant_time_eq,
};
use super::{RequestContext, strip_auth_scheme};
use crate::consumer_index::ConsumerIndex;

type HmacSha256 = Hmac<Sha256>;
type HmacSha512 = Hmac<Sha512>;

pub struct HmacAuth {
    clock_skew_seconds: u64,
}

impl HmacAuth {
    pub fn new(config: &Value) -> Result<Self, String> {
        let config_obj = config
            .as_object()
            .ok_or_else(|| format!("hmac_auth: config must be an object, got: {config}"))?;
        let clock_skew_seconds = parse_u64_field(
            config_obj.get("clock_skew_seconds"),
            "clock_skew_seconds",
            300,
        )?;
        if config_obj.get("require_digest").is_some() {
            return Err(
                "hmac_auth: 'require_digest' was removed; request digests are always required"
                    .to_string(),
            );
        }

        Ok(Self { clock_skew_seconds })
    }

    fn hmac_matches(secret: &[u8], data: &[u8], algorithm: &str, expected: &[u8]) -> bool {
        match algorithm {
            "hmac-sha512" => {
                let Ok(mut mac) = HmacSha512::new_from_slice(secret) else {
                    return false;
                };
                mac.update(data);
                let computed = mac.finalize().into_bytes();
                constant_time_eq(&computed, expected)
            }
            "hmac-sha256" => {
                let Ok(mut mac) = HmacSha256::new_from_slice(secret) else {
                    return false;
                };
                mac.update(data);
                let computed = mac.finalize().into_bytes();
                constant_time_eq(&computed, expected)
            }
            _ => false,
        }
    }

    /// Validate that the Date header is within the allowed clock skew window.
    fn validate_date(&self, date_str: &str) -> bool {
        if date_str.is_empty() {
            // No Date header means no replay protection — reject
            return false;
        }

        // Parse HTTP-date format (RFC 7231): "Sun, 06 Nov 1994 08:49:37 GMT"
        if let Ok(parsed) = chrono::DateTime::parse_from_rfc2822(date_str) {
            let now = chrono::Utc::now();
            let diff = (now - parsed.with_timezone(&chrono::Utc))
                .num_seconds()
                .unsigned_abs();
            diff <= self.clock_skew_seconds
        } else if let Ok(parsed) = chrono::DateTime::parse_from_rfc3339(date_str) {
            let now = chrono::Utc::now();
            let diff = (now - parsed.with_timezone(&chrono::Utc))
                .num_seconds()
                .unsigned_abs();
            diff <= self.clock_skew_seconds
        } else {
            warn!("hmac_auth: unparseable Date header: {}", date_str);
            false
        }
    }

    /// Verify that the `Digest:` header value matches the SHA-256/SHA-512 of
    /// `body`. The header format is `<algo>=<base64>` per RFC 3230 §4.3.2,
    /// where `<algo>` is `sha-256` or `sha-512` (case-insensitive).
    ///
    /// Multiple comma-separated entries are accepted; verification succeeds
    /// if any one entry matches. Algorithms other than sha-256/sha-512 are
    /// silently ignored (per RFC 3230, the receiver picks).
    pub(crate) fn verify_body_digest(digest_header: &str, body: &[u8]) -> bool {
        for entry in digest_header.split(',') {
            let entry = entry.trim();
            // Strip RFC 9421 sf-string quotes if present (e.g. `sha-256=:base64:`).
            let Some((algo_raw, value_raw)) = entry.split_once('=') else {
                continue;
            };
            let algo = algo_raw.trim().to_ascii_lowercase();
            // RFC 9421 Content-Digest uses ":<base64>:" structured-field byte sequence.
            let value = value_raw.trim().trim_matches(':').trim_matches('"');

            let Ok(decoded) = base64::engine::general_purpose::STANDARD.decode(value) else {
                continue;
            };

            let actual = match algo.as_str() {
                "sha-256" | "sha256" => {
                    let mut hasher = Sha256::new();
                    hasher.update(body);
                    hasher.finalize().to_vec()
                }
                "sha-512" | "sha512" => {
                    let mut hasher = Sha512::new();
                    hasher.update(body);
                    hasher.finalize().to_vec()
                }
                _ => continue,
            };

            if constant_time_eq(&decoded, &actual) {
                return true;
            }
        }
        false
    }

    /// Look up the digest header on the request. Prefers RFC 9421
    /// `Content-Digest` and falls back to RFC 3230 `Digest`.
    fn extract_digest_header(ctx: &RequestContext) -> Option<String> {
        if let Some(value) = ctx.headers.get("content-digest") {
            return Some(value.clone());
        }
        ctx.headers.get("digest").cloned()
    }
}

#[async_trait]
impl AuthMechanism for HmacAuth {
    fn mechanism_name(&self) -> &'static str {
        "hmac_auth"
    }

    fn extract(&self, ctx: &RequestContext) -> ExtractedCredential {
        let Some(auth_header) = ctx.headers.get("authorization") else {
            return ExtractedCredential::Missing;
        };

        let Some(params_str) = strip_auth_scheme(auth_header, "hmac") else {
            return ExtractedCredential::InvalidFormat(
                r#"{"error":"Invalid HMAC authorization format"}"#.to_string(),
            );
        };

        let mut username = None;
        let mut algorithm = None;
        let mut signature = None;

        for part in params_str.split(',') {
            let part = part.trim();
            if let Some((key, value)) = part.split_once('=') {
                let key = key.trim();
                let value = value.trim().trim_matches('"');
                match key {
                    "username" => username = Some(value.to_string()),
                    "algorithm" => algorithm = Some(value.to_string()),
                    "signature" => signature = Some(value.to_string()),
                    _ => {}
                }
            }
        }

        let Some(username) = username else {
            return ExtractedCredential::InvalidFormat(
                r#"{"error":"Missing username in HMAC authorization"}"#.to_string(),
            );
        };

        let algorithm = algorithm
            .unwrap_or_else(|| "hmac-sha256".to_string())
            .to_ascii_lowercase();
        if !matches!(algorithm.as_str(), "hmac-sha256" | "hmac-sha512") {
            return ExtractedCredential::InvalidFormat(
                r#"{"error":"Unsupported HMAC algorithm"}"#.to_string(),
            );
        }

        let Some(signature) = signature else {
            return ExtractedCredential::InvalidFormat(
                r#"{"error":"Missing signature in HMAC authorization"}"#.to_string(),
            );
        };

        // Enforce digest presence at extraction so we surface the clearest
        // error before consumer lookup. The actual body-vs-digest comparison
        // happens in `verify` once we have the buffered body.
        //
        // HBONE CONNECT keeps the request body streaming so the upgrade handle
        // remains available for relay; request-body bytes are therefore not
        // available at authenticate time. Fail closed for this shape.
        let is_hbone_connect = ctx.method.eq_ignore_ascii_case("CONNECT")
            && ctx
                .metadata
                .get("request_protocol")
                .is_some_and(|protocol| protocol.eq_ignore_ascii_case("hbone"));
        if is_hbone_connect
            && ctx.request_body_bytes.is_none()
            && !ctx.metadata.contains_key("request_body")
        {
            return ExtractedCredential::InvalidFormat(
                r#"{"error":"HBONE CONNECT is incompatible with hmac_auth request-body digest verification"}"#.to_string(),
            );
        }
        let digest_header = match Self::extract_digest_header(ctx) {
            Some(header) => header,
            None => {
                return ExtractedCredential::InvalidFormat(
                    r#"{"error":"Missing required Digest header"}"#.to_string(),
                );
            }
        };

        ExtractedCredential::HmacAuth {
            username,
            algorithm,
            signature,
            date: ctx.headers.get("date").cloned().unwrap_or_default(),
            method: ctx.method.clone(),
            path: ctx.path.clone(),
            digest_header,
            // Prefer binary-safe bytes; fall back to UTF-8 metadata for older
            // buffering paths. Empty body (GET/HEAD) → empty Vec.
            request_body: ctx
                .request_body_bytes
                .as_ref()
                .map(|b| b.to_vec())
                .or_else(|| {
                    ctx.metadata
                        .get("request_body")
                        .map(|s| s.as_bytes().to_vec())
                })
                .unwrap_or_default(),
        }
    }

    async fn verify(
        &self,
        credential: ExtractedCredential,
        consumer_index: &ConsumerIndex,
    ) -> VerifyOutcome {
        let ExtractedCredential::HmacAuth {
            username,
            algorithm,
            signature,
            date,
            method,
            path,
            digest_header,
            request_body,
        } = credential
        else {
            return VerifyOutcome::NotApplicable;
        };

        if !self.validate_date(&date) {
            return VerifyOutcome::Invalid(
                r#"{"error":"Missing or expired Date header"}"#.to_string(),
            );
        }

        // Verify that the Digest header matches the actual request body.
        // Done before consumer lookup so a tampered body fails fast and the
        // error message is independent of whether the consumer exists.
        if !Self::verify_body_digest(&digest_header, &request_body) {
            debug!("hmac_auth: digest header does not match request body");
            return VerifyOutcome::Invalid(
                r#"{"error":"Digest header does not match request body"}"#.to_string(),
            );
        }

        let consumer = match consumer_index.find_by_identity(&username) {
            Some(consumer) => consumer,
            None => {
                debug!("hmac_auth: consumer '{}' not found", username);
                return VerifyOutcome::ConsumerNotFound(
                    r#"{"error":"Invalid credentials"}"#.to_string(),
                );
            }
        };

        let hmac_entries = consumer.credential_entries("hmac_auth");
        if hmac_entries.is_empty() {
            return VerifyOutcome::VerificationFailed(
                r#"{"error":"Invalid credentials"}"#.to_string(),
            );
        }

        // Tampering with the digest header itself (without re-signing with
        // the secret) breaks the HMAC because the digest value is signed.
        let signing_string = build_signing_string(&method, &path, &date, &digest_header);

        let expected_signature = match base64::engine::general_purpose::STANDARD.decode(&signature)
        {
            Ok(signature) => signature,
            Err(_) => {
                debug!("hmac_auth: signature is not valid base64");
                return VerifyOutcome::VerificationFailed(
                    r#"{"error":"Invalid signature"}"#.to_string(),
                );
            }
        };

        for hmac_cred in &hmac_entries {
            if let Some(secret) = hmac_cred.get("secret").and_then(|secret| secret.as_str())
                && Self::hmac_matches(
                    secret.as_bytes(),
                    signing_string.as_bytes(),
                    &algorithm,
                    &expected_signature,
                )
            {
                return VerifyOutcome::consumer(consumer);
            }
        }

        debug!("hmac_auth: signature mismatch for user '{}'", username);
        VerifyOutcome::VerificationFailed(r#"{"error":"Invalid signature"}"#.to_string())
    }
}

auth_flow::impl_auth_plugin!(
    HmacAuth,
    "hmac_auth",
    super::priority::HMAC_AUTH,
    crate::plugins::HTTP_FAMILY_PROTOCOLS,
    auth_flow::run_auth;

    fn requires_request_body_before_authenticate(&self) -> bool {
        true
    }

    fn should_buffer_request_body(&self, _ctx: &crate::plugins::RequestContext) -> bool {
        true
    }

    fn needs_request_body_bytes(&self) -> bool {
        true
    }
);

fn parse_u64_field(value: Option<&Value>, field: &str, default_value: u64) -> Result<u64, String> {
    let Some(value) = value else {
        return Ok(default_value);
    };
    value
        .as_u64()
        .ok_or_else(|| format!("hmac_auth: '{field}' must be an unsigned integer, got: {value}"))
}

fn build_signing_string(method: &str, path: &str, date: &str, digest_header: &str) -> String {
    let mut signing_string =
        String::with_capacity(method.len() + path.len() + date.len() + digest_header.len() + 3);
    signing_string.push_str(method);
    signing_string.push('\n');
    signing_string.push_str(path);
    signing_string.push('\n');
    signing_string.push_str(date);
    signing_string.push('\n');
    signing_string.push_str(digest_header);
    signing_string
}

#[cfg(test)]
mod tests {
    //! Inline tests for `pub(crate)` helpers. Public API tests live in
    //! `tests/unit/plugins/hmac_auth_tests.rs`.

    use super::HmacAuth;
    use base64::Engine as _;
    use sha2::{Digest, Sha256, Sha512};

    fn sha256_digest_header(body: &[u8]) -> String {
        let mut hasher = Sha256::new();
        hasher.update(body);
        format!(
            "sha-256={}",
            base64::engine::general_purpose::STANDARD.encode(hasher.finalize())
        )
    }

    fn sha512_digest_header(body: &[u8]) -> String {
        let mut hasher = Sha512::new();
        hasher.update(body);
        format!(
            "sha-512={}",
            base64::engine::general_purpose::STANDARD.encode(hasher.finalize())
        )
    }

    #[test]
    fn verify_body_digest_accepts_correct_sha256() {
        let body = b"hello world";
        let digest = sha256_digest_header(body);
        assert!(HmacAuth::verify_body_digest(&digest, body));
    }

    #[test]
    fn verify_body_digest_accepts_correct_sha512() {
        let body = b"hello world";
        let digest = sha512_digest_header(body);
        assert!(HmacAuth::verify_body_digest(&digest, body));
    }

    #[test]
    fn verify_body_digest_rejects_wrong_body() {
        let body = b"hello world";
        let digest = sha256_digest_header(body);
        assert!(!HmacAuth::verify_body_digest(&digest, b"hello WORLD"));
    }

    #[test]
    fn verify_body_digest_rejects_unknown_algorithm() {
        let body = b"hello world";
        // sha-1 is not supported by the verifier.
        let digest = "sha-1=abc123==";
        assert!(!HmacAuth::verify_body_digest(digest, body));
    }

    #[test]
    fn verify_body_digest_rejects_garbage_value() {
        let body = b"hello world";
        let digest = "sha-256=not-valid-base64!!!";
        assert!(!HmacAuth::verify_body_digest(digest, body));
    }

    #[test]
    fn verify_body_digest_handles_empty_body() {
        let body = b"";
        let digest = sha256_digest_header(body);
        assert!(HmacAuth::verify_body_digest(&digest, body));
    }

    #[test]
    fn verify_body_digest_accepts_multiple_entries() {
        // Per RFC 3230 the receiver picks any matching entry. The first one
        // is unsupported (md5), the second is correct sha-256.
        let body = b"hello";
        let valid = sha256_digest_header(body);
        let combined = format!("md5=ignored, {}", valid);
        assert!(HmacAuth::verify_body_digest(&combined, body));
    }

    #[test]
    fn verify_body_digest_accepts_rfc9421_quoted_form() {
        // RFC 9421 wraps the byte sequence in `:base64:` (structured field).
        let body = b"hello";
        let mut hasher = Sha256::new();
        hasher.update(body);
        let b64 = base64::engine::general_purpose::STANDARD.encode(hasher.finalize());
        let digest = format!("sha-256=:{}:", b64);
        assert!(HmacAuth::verify_body_digest(&digest, body));
    }
}
