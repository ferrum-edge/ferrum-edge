//! API key authentication plugin.
//!
//! Extracts an API key from a configurable location (header or query parameter)
//! and looks up the corresponding consumer via the `ConsumerIndex` for O(1)
//! credential matching. Provides transport-level authentication only — the key
//! is transmitted in plaintext, so TLS is required in production.
//!
//! Default key location: `header:X-API-Key`. Configurable via `key_location`
//! in the plugin config (e.g., `"query:api_key"` for query parameter extraction).

use async_trait::async_trait;
use serde_json::Value;
use std::collections::HashMap;

use crate::consumer_index::ConsumerIndex;

use super::RequestContext;
use super::utils::auth_flow::{self, AuthMechanism, ExtractedCredential, VerifyOutcome};

pub struct KeyAuth {
    /// Pre-lowercased header name for header-based key extraction.
    /// Avoids a per-request `to_lowercase()` allocation.
    header_name_lower: Option<String>,
    /// Original (non-lowered) header name for case-sensitive fallback lookup.
    header_name_original: Option<String>,
    /// Query parameter name for query-based key extraction.
    query_param_name: Option<String>,
}

impl KeyAuth {
    pub fn new(config: &Value) -> Result<Self, String> {
        let key_location = config["key_location"]
            .as_str()
            .unwrap_or("header:X-API-Key")
            .to_string();

        let (header_name_lower, header_name_original, query_param_name) =
            if let Some(name) = key_location.strip_prefix("header:") {
                (Some(name.to_lowercase()), Some(name.to_string()), None)
            } else if let Some(name) = key_location.strip_prefix("query:") {
                (None, None, Some(name.to_string()))
            } else {
                (None, None, None)
            };

        Ok(Self {
            header_name_lower,
            header_name_original,
            query_param_name,
        })
    }

    fn extract_key(
        &self,
        ctx: &RequestContext,
        headers: &HashMap<String, String>,
    ) -> Option<String> {
        if let Some(ref lower) = self.header_name_lower {
            headers
                .get(lower.as_str())
                .or_else(|| {
                    self.header_name_original
                        .as_ref()
                        .and_then(|orig| headers.get(orig.as_str()))
                })
                .cloned()
        } else if let Some(ref param) = self.query_param_name {
            ctx.query_params.get(param.as_str()).cloned()
        } else {
            headers
                .get("x-api-key")
                .or_else(|| headers.get("X-API-Key"))
                .cloned()
        }
    }
}

#[async_trait]
impl AuthMechanism for KeyAuth {
    fn mechanism_name(&self) -> &str {
        "key_auth"
    }

    fn extract(
        &self,
        ctx: &RequestContext,
        headers: &HashMap<String, String>,
    ) -> ExtractedCredential {
        match self.extract_key(ctx, headers) {
            Some(key) => ExtractedCredential::ApiKey(key),
            None => ExtractedCredential::Missing,
        }
    }

    async fn verify(
        &self,
        credential: ExtractedCredential,
        consumer_index: &ConsumerIndex,
    ) -> VerifyOutcome {
        let ExtractedCredential::ApiKey(api_key) = credential else {
            return VerifyOutcome::NotApplicable;
        };

        // Reject empty / whitespace-only keys before hitting the index. This
        // prevents a misconfigured consumer (with an empty `key` value) from
        // accidentally matching every request that sends a blank header, and
        // gives clients a clearer error than a generic "Invalid API key".
        if api_key.trim().is_empty() {
            return VerifyOutcome::Invalid(r#"{"error":"Missing API key"}"#.into());
        }

        match consumer_index.find_by_api_key(&api_key) {
            Some(consumer) => VerifyOutcome::consumer(consumer),
            None => VerifyOutcome::ConsumerNotFound(r#"{"error":"Invalid API key"}"#.into()),
        }
    }
}

auth_flow::impl_auth_plugin!(
    KeyAuth,
    "key_auth",
    super::priority::KEY_AUTH,
    crate::plugins::HTTP_FAMILY_PROTOCOLS,
    auth_flow::run_auth
);
