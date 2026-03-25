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
use hmac::{Hmac, Mac};
use serde_json::Value;
use sha2::{Sha256, Sha512};
use std::collections::HashMap;
use tracing::{debug, warn};

use super::{Plugin, PluginResult, RequestContext};
use crate::consumer_index::ConsumerIndex;

type HmacSha256 = Hmac<Sha256>;
type HmacSha512 = Hmac<Sha512>;

pub struct HmacAuth {
    clock_skew_seconds: u64,
}

impl HmacAuth {
    pub fn new(config: &Value) -> Self {
        let clock_skew_seconds = config["clock_skew_seconds"].as_u64().unwrap_or(300);

        Self { clock_skew_seconds }
    }

    fn compute_hmac(secret: &[u8], data: &[u8], algorithm: &str) -> Option<Vec<u8>> {
        match algorithm {
            "hmac-sha512" => {
                let mut mac = HmacSha512::new_from_slice(secret).ok()?;
                mac.update(data);
                Some(mac.finalize().into_bytes().to_vec())
            }
            _ => {
                // Default to hmac-sha256
                let mut mac = HmacSha256::new_from_slice(secret).ok()?;
                mac.update(data);
                Some(mac.finalize().into_bytes().to_vec())
            }
        }
    }

    /// Constant-time comparison of two byte slices to prevent timing attacks.
    fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
        if a.len() != b.len() {
            return false;
        }
        let mut result: u8 = 0;
        for (x, y) in a.iter().zip(b.iter()) {
            result |= x ^ y;
        }
        result == 0
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
impl Plugin for HmacAuth {
    fn name(&self) -> &str {
        "hmac_auth"
    }

    fn is_auth_plugin(&self) -> bool {
        true
    }

    fn priority(&self) -> u16 {
        super::priority::HMAC_AUTH
    }

    async fn authenticate(
        &self,
        ctx: &mut RequestContext,
        consumer_index: &ConsumerIndex,
    ) -> PluginResult {
        let auth_header = match ctx.headers.get("authorization") {
            Some(h) => h.clone(),
            None => {
                return PluginResult::Reject {
                    status_code: 401,
                    body: r#"{"error":"Missing Authorization header"}"#.to_string(),
                    headers: HashMap::new(),
                };
            }
        };

        // Parse: hmac username="...", algorithm="...", signature="..."
        if !auth_header.to_lowercase().starts_with("hmac ") {
            return PluginResult::Reject {
                status_code: 401,
                body: r#"{"error":"Invalid HMAC authorization format"}"#.to_string(),
                headers: HashMap::new(),
            };
        }

        let params_str = &auth_header[5..];
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

        let username = match username {
            Some(u) => u,
            None => {
                return PluginResult::Reject {
                    status_code: 401,
                    body: r#"{"error":"Missing username in HMAC authorization"}"#.to_string(),
                    headers: HashMap::new(),
                };
            }
        };

        let algorithm = algorithm.unwrap_or_else(|| "hmac-sha256".to_string());

        let signature = match signature {
            Some(s) => s,
            None => {
                return PluginResult::Reject {
                    status_code: 401,
                    body: r#"{"error":"Missing signature in HMAC authorization"}"#.to_string(),
                    headers: HashMap::new(),
                };
            }
        };

        // Validate Date header for replay protection
        let date = ctx.headers.get("date").cloned().unwrap_or_default();
        if !self.validate_date(&date) {
            return PluginResult::Reject {
                status_code: 401,
                body: r#"{"error":"Missing or expired Date header"}"#.to_string(),
                headers: HashMap::new(),
            };
        }

        // Look up consumer by username
        let consumer = match consumer_index.find_by_identity(&username) {
            Some(c) => c,
            None => {
                debug!("hmac_auth: consumer '{}' not found", username);
                return PluginResult::Reject {
                    status_code: 401,
                    body: r#"{"error":"Invalid credentials"}"#.to_string(),
                    headers: HashMap::new(),
                };
            }
        };

        // Get HMAC secret from consumer credentials
        let secret = match consumer.credentials.get("hmac_auth") {
            Some(cred) => match cred.get("secret").and_then(|s| s.as_str()) {
                Some(s) => s.to_string(),
                None => {
                    return PluginResult::Reject {
                        status_code: 401,
                        body: r#"{"error":"Invalid credentials"}"#.to_string(),
                        headers: HashMap::new(),
                    };
                }
            },
            None => {
                return PluginResult::Reject {
                    status_code: 401,
                    body: r#"{"error":"Invalid credentials"}"#.to_string(),
                    headers: HashMap::new(),
                };
            }
        };

        // Build the signing string: METHOD\nPATH\nDATE
        let signing_string = format!("{}\n{}\n{}", ctx.method, ctx.path, date);

        // Compute expected signature using the requested algorithm
        let expected_mac =
            match Self::compute_hmac(secret.as_bytes(), signing_string.as_bytes(), &algorithm) {
                Some(mac) => mac,
                None => {
                    warn!("hmac_auth: failed to create HMAC for user '{}'", username);
                    return PluginResult::Reject {
                        status_code: 401,
                        body: r#"{"error":"Invalid credentials"}"#.to_string(),
                        headers: HashMap::new(),
                    };
                }
            };
        let expected_sig = base64::engine::general_purpose::STANDARD.encode(&expected_mac);

        // Constant-time comparison to prevent timing attacks
        if !Self::constant_time_eq(signature.as_bytes(), expected_sig.as_bytes()) {
            debug!("hmac_auth: signature mismatch for user '{}'", username);
            return PluginResult::Reject {
                status_code: 401,
                body: r#"{"error":"Invalid signature"}"#.to_string(),
                headers: HashMap::new(),
            };
        }

        // Authentication successful
        if ctx.identified_consumer.is_none() {
            debug!("hmac_auth: identified consumer '{}'", consumer.username);
            ctx.identified_consumer = Some((*consumer).clone());
        }
        PluginResult::Continue
    }
}
