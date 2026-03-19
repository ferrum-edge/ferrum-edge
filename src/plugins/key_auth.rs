use async_trait::async_trait;
use serde_json::Value;
use tracing::debug;

use crate::consumer_index::ConsumerIndex;

use super::{Plugin, PluginResult, RequestContext};

pub struct KeyAuth {
    key_location: String,
}

impl KeyAuth {
    pub fn new(config: &Value) -> Self {
        Self {
            key_location: config["key_location"]
                .as_str()
                .unwrap_or("header:X-API-Key")
                .to_string(),
        }
    }

    fn extract_key(&self, ctx: &RequestContext) -> Option<String> {
        if self.key_location.starts_with("header:") {
            let header_name = &self.key_location["header:".len()..];
            ctx.headers
                .get(&header_name.to_lowercase())
                .or_else(|| ctx.headers.get(header_name))
                .cloned()
        } else if self.key_location.starts_with("query:") {
            let param_name = &self.key_location["query:".len()..];
            ctx.query_params.get(param_name).cloned()
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
                };
            }
        };

        // O(1) lookup by API key via ConsumerIndex
        if let Some(consumer) = consumer_index.find_by_api_key(&api_key) {
            if ctx.identified_consumer.is_none() {
                debug!("key_auth: identified consumer '{}'", consumer.username);
                ctx.identified_consumer = Some((*consumer).clone());
            }
            return PluginResult::Continue;
        }

        PluginResult::Reject {
            status_code: 401,
            body: r#"{"error":"Invalid API key"}"#.into(),
        }
    }
}
