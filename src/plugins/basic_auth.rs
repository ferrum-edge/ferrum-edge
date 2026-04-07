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

use super::{Plugin, PluginResult, RequestContext, strip_auth_scheme};

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

/// Constant-time byte comparison to prevent timing side-channels.
fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

#[async_trait]
impl Plugin for BasicAuth {
    fn name(&self) -> &str {
        "basic_auth"
    }

    fn is_auth_plugin(&self) -> bool {
        true
    }

    fn priority(&self) -> u16 {
        super::priority::BASIC_AUTH
    }

    fn supported_protocols(&self) -> &'static [super::ProxyProtocol] {
        super::HTTP_FAMILY_PROTOCOLS
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
                    body: r#"{"error":"Missing Authorization header"}"#.into(),
                    headers: HashMap::new(),
                };
            }
        };

        let encoded = match strip_auth_scheme(&auth_header, "Basic") {
            Some(encoded) => encoded,
            None => {
                return PluginResult::Reject {
                    status_code: 401,
                    body: r#"{"error":"Invalid Basic auth format"}"#.into(),
                    headers: HashMap::new(),
                };
            }
        };
        let decoded = match base64::engine::general_purpose::STANDARD.decode(encoded) {
            Ok(d) => d,
            Err(_) => {
                return PluginResult::Reject {
                    status_code: 401,
                    body: r#"{"error":"Invalid base64 in Basic auth"}"#.into(),
                    headers: HashMap::new(),
                };
            }
        };

        let credential_str = match String::from_utf8(decoded) {
            Ok(s) => s,
            Err(_) => {
                return PluginResult::Reject {
                    status_code: 401,
                    body: r#"{"error":"Invalid UTF-8 in Basic auth"}"#.into(),
                    headers: HashMap::new(),
                };
            }
        };

        let parts: Vec<&str> = credential_str.splitn(2, ':').collect();
        if parts.len() != 2 {
            return PluginResult::Reject {
                status_code: 401,
                body: r#"{"error":"Invalid Basic auth format"}"#.into(),
                headers: HashMap::new(),
            };
        }

        let username = parts[0];
        let password = parts[1];

        // O(1) lookup by username via ConsumerIndex
        if let Some(consumer) = consumer_index.find_by_username(username)
            && let Some(basic_creds) = consumer.credentials.get("basicauth")
            && let Some(stored_hash) = basic_creds.get("password_hash").and_then(|s| s.as_str())
            && self.verify_password(password, stored_hash)
        {
            if ctx.identified_consumer.is_none() {
                debug!("basic_auth: identified consumer '{}'", consumer.username);
                ctx.identified_consumer = Some(consumer);
            }
            return PluginResult::Continue;
        }

        PluginResult::Reject {
            status_code: 401,
            body: r#"{"error":"Invalid credentials"}"#.into(),
            headers: HashMap::new(),
        }
    }
}
