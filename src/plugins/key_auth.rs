//! API key authentication plugin.
//!
//! Extracts an API key from a configurable location (header or query parameter)
//! and looks up the corresponding consumer via the `ConsumerIndex` for O(1)
//! credential matching. Provides transport-level authentication only — the key
//! reaches the gateway in plaintext, so TLS is required in production.
//! Configured credential locations are removed before backend forwarding by
//! default after the request authenticates, including when another mechanism
//! wins a multi-auth chain.
//!
//! Default key location: `header:X-API-Key`. Configurable via `key_location`
//! in the plugin config (e.g., `"query:api_key"` for query parameter extraction).
//! Location values are whitespace-sensitive and are never trimmed.

use async_trait::async_trait;
use http::header::HeaderName;
use serde_json::Value;

use crate::consumer_index::ConsumerIndex;

use super::RequestContext;
use super::utils::auth_flow::{self, AuthMechanism, ExtractedCredential, VerifyOutcome};
use super::utils::header_extract::{ConfiguredUtf8HeaderLookup, lookup_configured_header_utf8};
use super::utils::token_extract::STRIP_QUERY_PARAM_METADATA_PREFIX;

const INVALID_API_KEY_FORMAT_BODY: &str = r#"{"error":"Invalid API key format"}"#;

enum HeaderCredentialExtract {
    Missing,
    Present(String),
    InvalidFormat,
}

pub struct KeyAuth {
    /// Pre-lowercased header name for header-based key extraction.
    /// Avoids a per-request `to_lowercase()` allocation.
    header_name_lower: Option<String>,
    /// Original (non-lowered) header name for case-sensitive fallback lookup.
    header_name_original: Option<String>,
    /// Query parameter name for query-based key extraction.
    query_param_name: Option<String>,
    /// Precomputed metadata key used to strip the configured query parameter.
    strip_query_metadata_key: Option<String>,
    /// Configured request headers that diagnostics and policy calls must omit.
    request_headers_to_redact: Vec<String>,
    /// Remove the configured credential location before the backend request.
    hide_credentials: bool,
}

impl KeyAuth {
    pub fn new(config: &Value) -> Result<Self, String> {
        let config_obj = config.as_object().ok_or_else(|| {
            format!(
                "key_auth: config must be an object, got: {config:?}",
                config = config.to_string()
            )
        })?;
        let mut unknown_fields: Vec<&str> = config_obj
            .keys()
            .map(String::as_str)
            .filter(|key| !matches!(*key, "key_location" | "hide_credentials"))
            .collect();
        unknown_fields.sort_unstable();
        if !unknown_fields.is_empty() {
            return Err(format!(
                "key_auth: unknown configuration field(s): {:?}; allowed fields are `key_location` and `hide_credentials`",
                unknown_fields.join(", ")
            ));
        }

        let hide_credentials = match config_obj.get("hide_credentials") {
            Some(value) => value
                .as_bool()
                .ok_or_else(|| "key_auth: `hide_credentials` must be a boolean".to_string())?,
            None => true,
        };
        let key_location = match config_obj.get("key_location") {
            Some(value) => value.as_str().ok_or_else(|| {
                format!(
                    "key_auth: `key_location` must be a string, got: {value:?}",
                    value = value.to_string()
                )
            })?,
            None => "header:X-API-Key",
        };
        if key_location.is_empty() {
            return Err("key_auth: `key_location` must not be empty".to_string());
        }
        if key_location.trim() != key_location {
            return Err(
                "key_auth: `key_location` must not have leading or trailing whitespace".to_string(),
            );
        }

        let (
            header_name_lower,
            header_name_original,
            query_param_name,
            strip_query_metadata_key,
            request_headers_to_redact,
        ) = if let Some(name) = key_location.strip_prefix("header:") {
            if name.is_empty() {
                return Err("key_auth: `key_location` header name must not be empty".to_string());
            }
            let normalized_name = name.to_ascii_lowercase();
            let header_name = HeaderName::from_bytes(normalized_name.as_bytes()).map_err(|_| {
                "key_auth: `key_location` header name is not a valid HTTP header name".to_string()
            })?;
            let canonical_name = header_name.as_str().to_string();
            (
                Some(canonical_name.clone()),
                Some(name.to_string()),
                None,
                None,
                vec![canonical_name],
            )
        } else if let Some(name) = key_location.strip_prefix("query:") {
            if name.is_empty() {
                return Err("key_auth: `key_location` query name must not be empty".to_string());
            }
            if name.chars().any(char::is_whitespace) {
                return Err(
                    "key_auth: `key_location` query name must not contain whitespace".to_string(),
                );
            }
            let mut strip_key =
                String::with_capacity(STRIP_QUERY_PARAM_METADATA_PREFIX.len() + name.len());
            strip_key.push_str(STRIP_QUERY_PARAM_METADATA_PREFIX);
            strip_key.push_str(name);
            (
                None,
                None,
                Some(name.to_string()),
                Some(strip_key),
                Vec::new(),
            )
        } else {
            return Err(
                "key_auth: `key_location` must use `header:<name>` or `query:<name>`".to_string(),
            );
        };

        Ok(Self {
            header_name_lower,
            header_name_original,
            query_param_name,
            strip_query_metadata_key,
            request_headers_to_redact,
            hide_credentials,
        })
    }

    fn extract_key_credential(&self, ctx: &RequestContext) -> HeaderCredentialExtract {
        if let Some(ref lower) = self.header_name_lower {
            let original = self.header_name_original.as_deref();
            let lookup = lookup_configured_header_utf8(ctx, lower.as_str(), original);
            utf8_header_lookup_to_extract(lookup)
        } else if let Some(ref param) = self.query_param_name {
            match ctx.query_params.get(param.as_str()) {
                Some(key) => HeaderCredentialExtract::Present(key.clone()),
                None => HeaderCredentialExtract::Missing,
            }
        } else {
            let lookup = lookup_configured_header_utf8(ctx, "x-api-key", Some("X-API-Key"));
            utf8_header_lookup_to_extract(lookup)
        }
    }
}

fn utf8_header_lookup_to_extract(
    lookup: ConfiguredUtf8HeaderLookup<'_>,
) -> HeaderCredentialExtract {
    match lookup {
        ConfiguredUtf8HeaderLookup::Value(key) => {
            HeaderCredentialExtract::Present(key.into_owned())
        }
        ConfiguredUtf8HeaderLookup::Absent => HeaderCredentialExtract::Missing,
        ConfiguredUtf8HeaderLookup::InvalidUtf8 => HeaderCredentialExtract::InvalidFormat,
    }
}

#[async_trait]
impl AuthMechanism for KeyAuth {
    fn mechanism_name(&self) -> &'static str {
        "key_auth"
    }

    fn extract(&self, ctx: &RequestContext) -> ExtractedCredential {
        match self.extract_key_credential(ctx) {
            HeaderCredentialExtract::Present(key) => ExtractedCredential::ApiKey(key),
            HeaderCredentialExtract::Missing => ExtractedCredential::Missing,
            HeaderCredentialExtract::InvalidFormat => {
                ExtractedCredential::InvalidFormat(INVALID_API_KEY_FORMAT_BODY.into())
            }
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
    auth_flow::run_auth;

    fn mark_query_credentials_for_redaction(&self, ctx: &mut crate::plugins::RequestContext) {
        if let Some(name) = self.query_param_name.as_deref()
            && ctx.query_params.contains_key(name)
        {
            crate::plugins::utils::token_extract::mark_query_credential_metadata(ctx, name);
            if self.hide_credentials
                && let Some(metadata_key) = &self.strip_query_metadata_key
            {
                ctx.metadata
                    .insert(metadata_key.clone(), "true".to_string());
            }
        }
    }

    fn request_headers_to_redact(&self) -> &[String] {
        &self.request_headers_to_redact
    }

    fn modifies_request_headers(&self) -> bool {
        self.hide_credentials && self.header_name_lower.is_some()
    }

    /// `hide_credentials` removes only the configured key header.
    fn modified_request_header_names(&self) -> Option<Vec<String>> {
        Some(self.header_name_lower.iter().cloned().collect())
    }

    /// `authenticate` marks a query credential for stripping from the
    /// forwarded query, and `before_proxy` removes it.
    fn modifies_request_query(&self) -> bool {
        self.hide_credentials && self.query_param_name.is_some()
    }

    async fn before_proxy(
        &self,
        ctx: &mut crate::plugins::RequestContext,
        headers: &mut std::collections::HashMap<String, String>,
    ) -> crate::plugins::PluginResult {
        if !self.hide_credentials {
            return crate::plugins::PluginResult::Continue;
        }

        if let Some(header_name) = self.header_name_lower.as_deref() {
            headers.remove(header_name);
            if let Some(original) = self.header_name_original.as_deref()
                && original != header_name
            {
                headers.remove(original);
            }
        }
        if let Some(name) = self.query_param_name.as_deref()
            && ctx.query_params.remove(name).is_some()
            && let Some(metadata_key) = &self.strip_query_metadata_key
        {
            ctx.metadata
                .insert(metadata_key.clone(), "true".to_string());
        }
        crate::plugins::PluginResult::Continue
    }

    fn requires_decoded_query_params(&self) -> bool {
        self.query_param_name.is_some()
    }
);
