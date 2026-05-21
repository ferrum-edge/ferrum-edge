//! HTTP Basic Authentication plugin with HMAC-SHA256 password verification.
//!
//! Supports `hmac_sha256:<hex>` password hashes using a server secret.
//! This keeps verification fast and avoids variable-time password-hash
//! work on the request path.
//!
//! The server secret (`FERRUM_BASIC_AUTH_HMAC_SECRET`) MUST be set to a
//! unique, random value. The plugin rejects construction if the secret
//! is missing or empty — there is no insecure default.

use async_trait::async_trait;
use base64::Engine;
use hmac::{Hmac, KeyInit, Mac};
use serde_json::Value;
use sha2::Sha256;
use tracing::{debug, warn};

use crate::consumer_index::ConsumerIndex;

use super::utils::auth_flow::{
    self, AuthMechanism, ExtractedCredential, VerifyOutcome, constant_time_eq,
};
use super::{RequestContext, strip_auth_scheme};

type HmacSha256 = Hmac<Sha256>;

pub struct BasicAuth {
    /// Pre-computed HMAC key from FERRUM_BASIC_AUTH_HMAC_SECRET.
    hmac_secret: Vec<u8>,
}

impl BasicAuth {
    pub fn new(config: &Value) -> Result<Self, String> {
        use crate::config::conf_file::resolve_ferrum_var;

        match config {
            Value::Null => {}
            Value::Object(obj) if obj.is_empty() => {}
            Value::Object(_) => {
                return Err("basic_auth: no configuration fields are supported".to_string());
            }
            other => {
                return Err(format!(
                    "basic_auth: config must be an object, got: {other}"
                ));
            }
        }

        let hmac_secret = resolve_ferrum_var("FERRUM_BASIC_AUTH_HMAC_SECRET")
            .filter(|s| !s.is_empty())
            .ok_or_else(|| {
                "basic_auth: FERRUM_BASIC_AUTH_HMAC_SECRET must be set to a unique, random value \
                 (>= 32 characters recommended). The plugin cannot operate without a secret."
                    .to_string()
            })?;

        debug!("basic_auth: HMAC-SHA256 configured with operator-provided secret");

        Ok(Self {
            hmac_secret: hmac_secret.into_bytes(),
        })
    }

    /// Verify a password against a stored hash.
    ///
    /// Supports `hmac_sha256:<hex>` — HMAC-SHA256 with the server secret.
    fn verify_password(&self, password: &str, stored_hash: &str) -> bool {
        let Some(hex_hash) = stored_hash.strip_prefix("hmac_sha256:") else {
            return false;
        };
        let Ok(mut mac) = HmacSha256::new_from_slice(&self.hmac_secret) else {
            warn!("basic_auth: failed to create HMAC instance");
            return false;
        };
        mac.update(password.as_bytes());
        let computed = mac.finalize().into_bytes();
        let mut expected = [0u8; 32];
        if hex::decode_to_slice(hex_hash, &mut expected).is_err() {
            return false;
        }

        constant_time_eq(&computed, &expected)
    }
}

#[async_trait]
impl AuthMechanism for BasicAuth {
    fn mechanism_name(&self) -> &'static str {
        "basic_auth"
    }

    fn extract(&self, ctx: &RequestContext) -> ExtractedCredential {
        let Some(auth_header) = ctx.headers.get("authorization") else {
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

        let Some((username, password)) = credential_str.split_once(':') else {
            return ExtractedCredential::InvalidFormat(
                r#"{"error":"Invalid Basic auth format"}"#.into(),
            );
        };

        ExtractedCredential::BasicAuth {
            username: username.to_string(),
            password: password.to_string(),
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
