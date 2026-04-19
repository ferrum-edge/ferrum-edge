//! JWT authentication plugin with two-phase token verification.
//!
//! Uses a two-phase decode approach:
//! 1. **Insecure decode** — peek at the unverified claims to extract the consumer
//!    identity (via `consumer_claim_field`, default `"sub"`). This is safe because
//!    the identity is only used to look up the consumer's signing secret.
//! 2. **Full verification** — decode again with the consumer's secret to validate
//!    the signature and expiration. Only after this succeeds is the consumer trusted.
//!
//! This design allows each consumer to have their own JWT secret (stored in
//! `consumer.credentials["jwt"]["secret"]`), avoiding a single shared secret.
//!
//! Token location is configurable via `token_lookup` (default `"header:Authorization"`).
//! Supports `"header:<name>"` and `"query:<name>"` extraction modes.

use async_trait::async_trait;
use jsonwebtoken::{Algorithm, DecodingKey, Validation, dangerous::insecure_decode, decode};
use serde_json::Value;
use std::collections::HashMap;
use tracing::debug;

use crate::consumer_index::ConsumerIndex;

use super::utils::auth_flow::{self, AuthMechanism, ExtractedCredential, VerifyOutcome};
use super::{RequestContext, strip_auth_scheme};

/// Unsafe validation that skips signature verification, used only to extract
/// claims before looking up the consumer's secret for proper verification.
fn decode_claims_only(token: &str) -> Option<serde_json::Value> {
    insecure_decode::<serde_json::Value>(token)
        .ok()
        .map(|td| td.claims)
}

pub struct JwtAuth {
    token_lookup: String,
    consumer_claim_field: String,
}

impl JwtAuth {
    pub fn new(config: &Value) -> Result<Self, String> {
        Ok(Self {
            token_lookup: config["token_lookup"]
                .as_str()
                .unwrap_or("header:Authorization")
                .to_string(),
            consumer_claim_field: config["consumer_claim_field"]
                .as_str()
                .unwrap_or("sub")
                .to_string(),
        })
    }

    fn extract_token(
        &self,
        ctx: &RequestContext,
        headers: &HashMap<String, String>,
    ) -> Option<String> {
        if self.token_lookup.starts_with("header:") {
            let header_name = &self.token_lookup["header:".len()..];
            headers.get(&header_name.to_lowercase()).map(|v| {
                strip_auth_scheme(v, "Bearer")
                    .unwrap_or(v.as_str())
                    .to_string()
            })
        } else if self.token_lookup.starts_with("query:") {
            let param_name = &self.token_lookup["query:".len()..];
            ctx.query_params.get(param_name).cloned()
        } else {
            headers
                .get("authorization")
                .and_then(|v| strip_auth_scheme(v, "Bearer").map(str::to_string))
        }
    }
}

#[async_trait]
impl AuthMechanism for JwtAuth {
    fn mechanism_name(&self) -> &str {
        "jwt_auth"
    }

    fn extract(
        &self,
        ctx: &RequestContext,
        headers: &HashMap<String, String>,
    ) -> ExtractedCredential {
        match self.extract_token(ctx, headers) {
            Some(token) => ExtractedCredential::BearerToken(token),
            None => ExtractedCredential::Missing,
        }
    }

    async fn verify(
        &self,
        credential: ExtractedCredential,
        consumer_index: &ConsumerIndex,
    ) -> VerifyOutcome {
        let ExtractedCredential::BearerToken(token) = credential else {
            return VerifyOutcome::NotApplicable;
        };

        // O(1) lookup: decode claims without verification to extract identity,
        // then look up the consumer by identity and verify with their secret only.
        let claims = match decode_claims_only(&token) {
            Some(claims) => claims,
            None => {
                debug!("jwt_auth: failed to decode JWT structure");
                return VerifyOutcome::Invalid(r#"{"error":"Invalid JWT token"}"#.into());
            }
        };

        let identity = match claims
            .get(&self.consumer_claim_field)
            .and_then(|value| value.as_str())
        {
            Some(identity) => identity,
            None => {
                debug!(
                    "jwt_auth: JWT missing identity claim '{}'",
                    self.consumer_claim_field
                );
                return VerifyOutcome::Invalid(r#"{"error":"JWT missing identity claim"}"#.into());
            }
        };

        let consumer = match consumer_index.find_by_identity(identity) {
            Some(consumer) => consumer,
            None => {
                debug!("jwt_auth: no consumer found for identity '{}'", identity);
                return VerifyOutcome::ConsumerNotFound(r#"{"error":"Invalid JWT token"}"#.into());
            }
        };

        let jwt_entries = consumer.credential_entries("jwt");
        if jwt_entries.is_empty() {
            debug!(
                "jwt_auth: consumer '{}' has no JWT secret configured",
                consumer.username
            );
            return VerifyOutcome::VerificationFailed(r#"{"error":"Invalid JWT token"}"#.into());
        }

        let mut validation = Validation::new(Algorithm::HS256);
        validation.validate_exp = true;
        validation.required_spec_claims.clear();

        for jwt_cred in &jwt_entries {
            if let Some(secret) = jwt_cred.get("secret").and_then(|secret| secret.as_str()) {
                let key = DecodingKey::from_secret(secret.as_bytes());
                if decode::<serde_json::Value>(&token, &key, &validation).is_ok() {
                    return VerifyOutcome::consumer(consumer);
                }
            }
        }

        debug!("jwt_auth: signature verification failed for all secrets");
        VerifyOutcome::VerificationFailed(r#"{"error":"Invalid JWT token"}"#.into())
    }
}

auth_flow::impl_auth_plugin!(
    JwtAuth,
    "jwt_auth",
    super::priority::JWT_AUTH,
    crate::plugins::HTTP_FAMILY_PROTOCOLS,
    auth_flow::run_auth
);
