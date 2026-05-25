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

use std::collections::HashSet;

use async_trait::async_trait;
use jsonwebtoken::{Algorithm, DecodingKey, Validation, dangerous::insecure_decode, decode};
use serde_json::Value;
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
    token_lookup: TokenLookup,
    consumer_claim_field: String,
    validation: Validation,
    require_nbf: bool,
}

enum TokenLookup {
    Header {
        lower_name: String,
        original_name: String,
    },
    Query(String),
}

impl JwtAuth {
    pub fn new(config: &Value) -> Result<Self, String> {
        let config_obj = config
            .as_object()
            .ok_or_else(|| format!("jwt_auth: config must be an object, got: {config}"))?;
        let token_lookup = parse_token_lookup(config_obj.get("token_lookup"))?;
        let consumer_claim_field = parse_non_empty_string(
            config_obj.get("consumer_claim_field"),
            "consumer_claim_field",
            "sub",
        )?;
        let require_exp =
            parse_optional_bool(config_obj.get("require_exp"), "require_exp")?.unwrap_or(true);
        // `nbf` is optional per RFC 7519 §4.1.5 and most issuers omit it, so it
        // must not be required by default — doing so rejects otherwise-valid
        // tokens. Operators can opt in with `require_nbf: true`. (`validate_nbf`
        // below still rejects a token whose `nbf` is in the future when present.)
        let require_nbf =
            parse_optional_bool(config_obj.get("require_nbf"), "require_nbf")?.unwrap_or(false);
        let expected_issuers = parse_expected_issuers(config_obj)?;
        let audiences = parse_string_array(config_obj.get("audiences"), "audiences")?;
        let leeway_secs = parse_optional_u64(config_obj.get("leeway_secs"), "leeway_secs", 0)?;
        if leeway_secs > 300 {
            return Err("jwt_auth: 'leeway_secs' must be <= 300".to_string());
        }

        let mut validation = Validation::new(Algorithm::HS256);
        validation.validate_exp = true;
        validation.validate_nbf = true;
        validation.leeway = leeway_secs;
        if require_exp {
            validation.required_spec_claims = HashSet::from(["exp".to_string()]);
        } else {
            validation.required_spec_claims.clear();
        }
        if !expected_issuers.is_empty() {
            validation.set_issuer(&expected_issuers);
        }
        if !audiences.is_empty() {
            validation.set_audience(&audiences);
        } else {
            validation.validate_aud = false;
        }

        Ok(Self {
            token_lookup,
            consumer_claim_field,
            validation,
            require_nbf,
        })
    }

    fn extract_token(&self, ctx: &RequestContext) -> Option<String> {
        match &self.token_lookup {
            TokenLookup::Header {
                lower_name,
                original_name,
            } => ctx
                .headers
                .get(lower_name.as_str())
                .or_else(|| ctx.headers.get(original_name.as_str()))
                .map(|v| {
                    strip_auth_scheme(v, "Bearer")
                        .unwrap_or(v.as_str())
                        .to_string()
                }),
            TokenLookup::Query(param_name) => ctx.query_params.get(param_name.as_str()).cloned(),
        }
    }
}

#[async_trait]
impl AuthMechanism for JwtAuth {
    fn mechanism_name(&self) -> &'static str {
        "jwt_auth"
    }

    fn extract(&self, ctx: &RequestContext) -> ExtractedCredential {
        match self.extract_token(ctx) {
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

        for jwt_cred in &jwt_entries {
            if let Some(secret) = jwt_cred.get("secret").and_then(|secret| secret.as_str()) {
                let key = DecodingKey::from_secret(secret.as_bytes());
                if let Ok(token_data) = decode::<serde_json::Value>(&token, &key, &self.validation)
                {
                    if self.require_nbf && token_data.claims.get("nbf").is_none() {
                        debug!("jwt_auth: JWT missing required nbf claim");
                        return VerifyOutcome::Invalid(
                            r#"{"error":"JWT missing nbf claim"}"#.into(),
                        );
                    }
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

fn parse_token_lookup(value: Option<&Value>) -> Result<TokenLookup, String> {
    let raw = parse_non_empty_string(value, "token_lookup", "header:Authorization")?;
    if let Some(name) = raw.strip_prefix("header:") {
        let name = name.trim();
        if name.is_empty() {
            return Err("jwt_auth: 'token_lookup' header name must not be empty".to_string());
        }
        Ok(TokenLookup::Header {
            lower_name: name.to_ascii_lowercase(),
            original_name: name.to_string(),
        })
    } else if let Some(name) = raw.strip_prefix("query:") {
        let name = name.trim();
        if name.is_empty() {
            return Err("jwt_auth: 'token_lookup' query name must not be empty".to_string());
        }
        Ok(TokenLookup::Query(name.to_string()))
    } else {
        Err("jwt_auth: 'token_lookup' must use 'header:<name>' or 'query:<name>'".to_string())
    }
}

fn parse_non_empty_string(
    value: Option<&Value>,
    field: &str,
    default_value: &str,
) -> Result<String, String> {
    let Some(value) = value else {
        return Ok(default_value.to_string());
    };
    let raw = value
        .as_str()
        .ok_or_else(|| format!("jwt_auth: '{field}' must be a string, got: {value}"))?;
    let value = raw.trim();
    if value.is_empty() {
        return Err(format!("jwt_auth: '{field}' must not be empty"));
    }
    Ok(value.to_string())
}

fn parse_optional_bool(value: Option<&Value>, field: &str) -> Result<Option<bool>, String> {
    value
        .map(|value| {
            value
                .as_bool()
                .ok_or_else(|| format!("jwt_auth: '{field}' must be a boolean, got: {value}"))
        })
        .transpose()
}

fn parse_expected_issuers(config: &serde_json::Map<String, Value>) -> Result<Vec<String>, String> {
    let expected_issuer = config.get("expected_issuer");
    let expected_issuers = config.get("expected_issuers");
    if expected_issuer.is_some() && expected_issuers.is_some() {
        return Err(
            "jwt_auth: 'expected_issuer' and 'expected_issuers' are mutually exclusive".to_string(),
        );
    }

    if let Some(value) = expected_issuer {
        return Ok(vec![parse_required_string(value, "expected_issuer")?]);
    }

    parse_string_array(expected_issuers, "expected_issuers")
}

fn parse_string_array(value: Option<&Value>, field: &str) -> Result<Vec<String>, String> {
    let Some(value) = value else {
        return Ok(Vec::new());
    };
    let arr = value
        .as_array()
        .ok_or_else(|| format!("jwt_auth: '{field}' must be an array of strings, got: {value}"))?;
    let mut values = Vec::with_capacity(arr.len());
    for (idx, item) in arr.iter().enumerate() {
        let parsed = parse_required_string(item, &format!("{field}[{idx}]"))?;
        values.push(parsed);
    }
    Ok(values)
}

fn parse_required_string(value: &Value, field: &str) -> Result<String, String> {
    let raw = value
        .as_str()
        .ok_or_else(|| format!("jwt_auth: '{field}' must be a string, got: {value}"))?;
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return Err(format!("jwt_auth: '{field}' must not be empty"));
    }
    Ok(trimmed.to_string())
}

fn parse_optional_u64(value: Option<&Value>, field: &str, default: u64) -> Result<u64, String> {
    let Some(value) = value else {
        return Ok(default);
    };
    value
        .as_u64()
        .ok_or_else(|| format!("jwt_auth: '{field}' must be an unsigned integer, got: {value}"))
}
