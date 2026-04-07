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
use tracing::debug;

use crate::consumer_index::ConsumerIndex;

use super::{Plugin, PluginResult, RequestContext};

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

    fn extract_key(&self, ctx: &RequestContext) -> Option<String> {
        if let Some(ref lower) = self.header_name_lower {
            ctx.headers
                .get(lower.as_str())
                .or_else(|| {
                    self.header_name_original
                        .as_ref()
                        .and_then(|orig| ctx.headers.get(orig.as_str()))
                })
                .cloned()
        } else if let Some(ref param) = self.query_param_name {
            ctx.query_params.get(param.as_str()).cloned()
        } else {
            ctx.headers
                .get("x-api-key")
                .or_else(|| ctx.headers.get("X-API-Key"))
                .cloned()
        }
    }
}

#[async_trait]
impl Plugin for KeyAuth {
    fn name(&self) -> &str {
        "key_auth"
    }

    fn is_auth_plugin(&self) -> bool {
        true
    }

    fn priority(&self) -> u16 {
        super::priority::KEY_AUTH
    }

    fn supported_protocols(&self) -> &'static [super::ProxyProtocol] {
        super::HTTP_FAMILY_PROTOCOLS
    }

    async fn authenticate(
        &self,
        ctx: &mut RequestContext,
        consumer_index: &ConsumerIndex,
    ) -> PluginResult {
        let api_key = match self.extract_key(ctx) {
            Some(k) => k,
            None => {
                return PluginResult::Reject {
                    status_code: 401,
                    body: r#"{"error":"Missing API key"}"#.into(),
                    headers: HashMap::new(),
                };
            }
        };

        // O(1) lookup by API key via ConsumerIndex
        if let Some(consumer) = consumer_index.find_by_api_key(&api_key) {
            if ctx.identified_consumer.is_none() {
                debug!("key_auth: identified consumer '{}'", consumer.username);
                ctx.identified_consumer = Some(consumer);
            }
            return PluginResult::Continue;
        }

        PluginResult::Reject {
            status_code: 401,
            body: r#"{"error":"Invalid API key"}"#.into(),
            headers: HashMap::new(),
        }
    }
}
