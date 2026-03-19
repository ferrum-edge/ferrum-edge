use async_trait::async_trait;
use jsonwebtoken::{Algorithm, DecodingKey, Validation, decode};
use serde_json::Value;
use tracing::debug;

use crate::consumer_index::ConsumerIndex;

use super::{Plugin, PluginResult, RequestContext};

pub struct JwtAuth {
    token_lookup: String,
    consumer_claim_field: String,
}

impl JwtAuth {
    pub fn new(config: &Value) -> Self {
        Self {
            token_lookup: config["token_lookup"]
                .as_str()
                .unwrap_or("header:Authorization")
                .to_string(),
            consumer_claim_field: config["consumer_claim_field"]
                .as_str()
                .unwrap_or("sub")
                .to_string(),
        }
    }

    fn extract_token(&self, ctx: &RequestContext) -> Option<String> {
        if self.token_lookup.starts_with("header:") {
            let header_name = &self.token_lookup["header:".len()..];
            ctx.headers.get(&header_name.to_lowercase()).map(|v| {
                if v.starts_with("Bearer ") || v.starts_with("bearer ") {
                    v[7..].to_string()
                } else {
                    v.clone()
                }
            })
        } else if self.token_lookup.starts_with("query:") {
            let param_name = &self.token_lookup["query:".len()..];
            ctx.query_params.get(param_name).cloned()
        } else {
            ctx.headers.get("authorization").and_then(|v| {
                if v.starts_with("Bearer ") || v.starts_with("bearer ") {
                    Some(v[7..].to_string())
                } else {
                    None
                }
            })
        }
    }
}

#[async_trait]
impl Plugin for JwtAuth {
    fn name(&self) -> &str {
        "jwt_auth"
    }

    async fn authenticate(
        &self,
        ctx: &mut RequestContext,
        consumer_index: &ConsumerIndex,
    ) -> PluginResult {
        let token = match self.extract_token(ctx) {
            Some(t) => t,
            None => {
                debug!("jwt_auth: no token found");
                return PluginResult::Reject {
                    status_code: 401,
                    body: r#"{"error":"Missing JWT token"}"#.into(),
                };
            }
        };

        // Must try each consumer's JWT secret to verify (inherently O(n) for decoding)
        let consumers = consumer_index.consumers();
        for consumer in consumers.iter() {
            if let Some(jwt_creds) = consumer.credentials.get("jwt")
                && let Some(secret) = jwt_creds.get("secret").and_then(|s| s.as_str())
            {
                let key = DecodingKey::from_secret(secret.as_bytes());
                let mut validation = Validation::new(Algorithm::HS256);
                validation.validate_exp = false;
                validation.required_spec_claims.clear();

                if let Ok(token_data) = decode::<serde_json::Value>(&token, &key, &validation) {
                    // Check if the claim field matches consumer
                    if let Some(claim_val) = token_data.claims.get(&self.consumer_claim_field) {
                        let claim_str = claim_val.as_str().unwrap_or("");
                        if claim_str == consumer.username || claim_str == consumer.id {
                            if ctx.identified_consumer.is_none() {
                                debug!("jwt_auth: identified consumer '{}'", consumer.username);
                                ctx.identified_consumer = Some((**consumer).clone());
                            }
                            return PluginResult::Continue;
                        }
                    }
                }
            }
        }

        debug!("jwt_auth: no matching consumer found");
        PluginResult::Reject {
            status_code: 401,
            body: r#"{"error":"Invalid JWT token"}"#.into(),
        }
    }
}
