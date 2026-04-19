//! HMAC Authentication Plugin
//!
//! Validates HMAC-signed requests where the client signs the request
//! with a shared secret. Supports hmac-sha256 and hmac-sha512.
//!
//! Expected Authorization header format:
//!   hmac username="<username>", algorithm="hmac-sha256", signature="<base64-sig>"
//!
//! The signature is computed over: HTTP method + \n + path + \n + date header value
//!
//! Consumer credentials should include:
//!   { "hmac_auth": { "secret": "<shared-secret>" } }

use async_trait::async_trait;
use base64::Engine as _;
use hmac::{Hmac, KeyInit, Mac};
use serde_json::Value;
use sha2::{Sha256, Sha512};
use std::collections::HashMap;
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
        let clock_skew_seconds = config["clock_skew_seconds"].as_u64().unwrap_or(300);

        Ok(Self { clock_skew_seconds })
    }

    fn compute_hmac(secret: &[u8], data: &[u8], algorithm: &str) -> Option<Vec<u8>> {
        match algorithm {
            "hmac-sha512" => {
                let mut mac = HmacSha512::new_from_slice(secret).ok()?;
                mac.update(data);
                Some(mac.finalize().into_bytes().to_vec())
            }
            "hmac-sha256" => {
                let mut mac = HmacSha256::new_from_slice(secret).ok()?;
                mac.update(data);
                Some(mac.finalize().into_bytes().to_vec())
            }
            _ => None,
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
}

#[async_trait]
impl AuthMechanism for HmacAuth {
    fn mechanism_name(&self) -> &str {
        "hmac_auth"
    }

    fn extract(
        &self,
        ctx: &RequestContext,
        headers: &HashMap<String, String>,
    ) -> ExtractedCredential {
        let Some(auth_header) = headers.get("authorization") else {
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

        ExtractedCredential::HmacAuth {
            username,
            algorithm,
            signature,
            date: headers.get("date").cloned().unwrap_or_default(),
            method: ctx.method.clone(),
            path: ctx.path.clone(),
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
        } = credential
        else {
            return VerifyOutcome::NotApplicable;
        };

        if !self.validate_date(&date) {
            return VerifyOutcome::Invalid(
                r#"{"error":"Missing or expired Date header"}"#.to_string(),
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

        let signing_string = format!("{}\n{}\n{}", method, path, date);

        for hmac_cred in &hmac_entries {
            if let Some(secret) = hmac_cred.get("secret").and_then(|secret| secret.as_str())
                && let Some(expected_mac) =
                    Self::compute_hmac(secret.as_bytes(), signing_string.as_bytes(), &algorithm)
            {
                let expected_sig = base64::engine::general_purpose::STANDARD.encode(&expected_mac);
                if constant_time_eq(signature.as_bytes(), expected_sig.as_bytes()) {
                    return VerifyOutcome::consumer(consumer);
                }
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
    auth_flow::run_auth
);
