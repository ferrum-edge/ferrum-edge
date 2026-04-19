//! HTTP Basic Authentication plugin with dual hash verification.
//!
//! Supports two password hash formats:
//! - **HMAC-SHA256** (`hmac_sha256:<hex>`) — ~1μs verification using a server secret.
//!   This is the recommended format for high-throughput gateways.
//! - **bcrypt** (`$2b$...` / `$2a$...`) — ~100ms verification, always available as
//!   a backward-compatible fallback.
//!
//! The HMAC-SHA256 fast path eliminates bcrypt's per-request CPU overhead and
//! removes timing side-channels that could be used for username enumeration
//! (bcrypt's variable-time comparison leaks whether a username exists).
//!
//! The server secret (`FERRUM_BASIC_AUTH_HMAC_SECRET`) MUST be set to a unique,
//! random value in production. The default value is public and insecure.

use async_trait::async_trait;
use base64::Engine;
use hmac::{Hmac, KeyInit, Mac};
use serde_json::Value;
use sha2::Sha256;
use std::collections::HashMap;
use tracing::{debug, error, warn};

use crate::consumer_index::ConsumerIndex;

use super::utils::auth_flow::{
    self, AuthMechanism, ExtractedCredential, VerifyOutcome, constant_time_eq,
};
use super::{RequestContext, strip_auth_scheme};

type HmacSha256 = Hmac<Sha256>;

/// Default HMAC secret used when FERRUM_BASIC_AUTH_HMAC_SECRET is not set.
/// This enables HMAC-SHA256 mode by default for performance (~1μs vs ~100ms bcrypt)
/// and eliminates bcrypt timing side-channels for username enumeration.
///
/// IMPORTANT: Operators MUST override this in production by setting
/// FERRUM_BASIC_AUTH_HMAC_SECRET to a unique, random value. Using the default
/// means any attacker who knows it can compute valid HMAC hashes.
pub const DEFAULT_HMAC_SECRET: &str = "ferrum-edge-change-me-in-production";

pub struct BasicAuth {
    /// Pre-computed HMAC key from FERRUM_BASIC_AUTH_HMAC_SECRET (or default).
    /// Password hashes prefixed with `hmac_sha256:` are verified using
    /// HMAC-SHA256 (~1μs). Bcrypt hashes ($2b$/$2a$) are always supported
    /// as a fallback regardless of this setting.
    hmac_secret: Vec<u8>,
}

impl BasicAuth {
    pub fn new(_config: &Value) -> Result<Self, String> {
        use crate::config::conf_file::resolve_ferrum_var;

        let (hmac_secret, is_default) = match resolve_ferrum_var("FERRUM_BASIC_AUTH_HMAC_SECRET")
            .filter(|s| !s.is_empty())
        {
            Some(s) => (s.into_bytes(), false),
            None => {
                error!(
                    "basic_auth: FERRUM_BASIC_AUTH_HMAC_SECRET is not set — using insecure default. \
                     Set this to a unique, random value in production to secure HMAC-SHA256 password verification."
                );
                (DEFAULT_HMAC_SECRET.as_bytes().to_vec(), true)
            }
        };

        if !is_default {
            debug!("basic_auth: HMAC-SHA256 configured with custom secret");
        }

        Ok(Self { hmac_secret })
    }

    /// Verify a password against a stored hash.
    ///
    /// Supports two formats:
    /// - `hmac_sha256:<hex>` — HMAC-SHA256 with server secret (~1μs)
    /// - `$2b$...` / `$2a$...` — bcrypt (~100ms, always available, backward compatible)
    fn verify_password(&self, password: &str, stored_hash: &str) -> bool {
        if let Some(hex_hash) = stored_hash.strip_prefix("hmac_sha256:") {
            // HMAC-SHA256 verification
            let Ok(mut mac) = HmacSha256::new_from_slice(&self.hmac_secret) else {
                warn!("basic_auth: failed to create HMAC instance");
                return false;
            };
            mac.update(password.as_bytes());
            let computed = hex::encode(mac.finalize().into_bytes());

            // Constant-time comparison to prevent timing attacks
            constant_time_eq(computed.as_bytes(), hex_hash.as_bytes())
        } else {
            // Bcrypt fallback (handles $2b$, $2a$, $2y$ prefixes)
            bcrypt::verify(password, stored_hash).unwrap_or(false)
        }
    }
}

#[async_trait]
impl AuthMechanism for BasicAuth {
    fn mechanism_name(&self) -> &str {
        "basic_auth"
    }

    fn extract(
        &self,
        _ctx: &RequestContext,
        headers: &HashMap<String, String>,
    ) -> ExtractedCredential {
        let Some(auth_header) = headers.get("authorization") else {
            return ExtractedCredential::Missing;
        };

        let Some(encoded) = strip_auth_scheme(auth_header, "Basic") else {
            return ExtractedCredential::InvalidFormat(
                r#"{"error":"Invalid Basic auth format"}"#.into(),
            );
        };

        let decoded = match base64::engine::general_purpose::STANDARD.decode(encoded) {
            Ok(decoded) => decoded,
            Err(_) => {
                return ExtractedCredential::InvalidFormat(
                    r#"{"error":"Invalid base64 in Basic auth"}"#.into(),
                );
            }
        };

        let credential_str = match String::from_utf8(decoded) {
            Ok(credential_str) => credential_str,
            Err(_) => {
                return ExtractedCredential::InvalidFormat(
                    r#"{"error":"Invalid UTF-8 in Basic auth"}"#.into(),
                );
            }
        };

        let parts: Vec<&str> = credential_str.splitn(2, ':').collect();
        if parts.len() != 2 {
            return ExtractedCredential::InvalidFormat(
                r#"{"error":"Invalid Basic auth format"}"#.into(),
            );
        }

        ExtractedCredential::BasicAuth {
            username: parts[0].to_string(),
            password: parts[1].to_string(),
        }
    }

    async fn verify(
        &self,
        credential: ExtractedCredential,
        consumer_index: &ConsumerIndex,
    ) -> VerifyOutcome {
        let ExtractedCredential::BasicAuth { username, password } = credential else {
            return VerifyOutcome::NotApplicable;
        };

        let Some(consumer) = consumer_index.find_by_username(&username) else {
            return VerifyOutcome::ConsumerNotFound(r#"{"error":"Invalid credentials"}"#.into());
        };

        for basic_creds in consumer.credential_entries("basicauth") {
            if let Some(stored_hash) = basic_creds.get("password_hash").and_then(|s| s.as_str())
                && self.verify_password(&password, stored_hash)
            {
                return VerifyOutcome::consumer(consumer);
            }
        }

        VerifyOutcome::VerificationFailed(r#"{"error":"Invalid credentials"}"#.into())
    }
}

auth_flow::impl_auth_plugin!(
    BasicAuth,
    "basic_auth",
    super::priority::BASIC_AUTH,
    crate::plugins::HTTP_FAMILY_PROTOCOLS,
    auth_flow::run_auth
);
