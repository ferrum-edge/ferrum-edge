use async_trait::async_trait;
use base64::Engine;
use serde_json::Value;
use tracing::debug;

use crate::consumer_index::ConsumerIndex;

use super::{Plugin, PluginResult, RequestContext};

pub struct BasicAuth;

impl BasicAuth {
    pub fn new(_config: &Value) -> Self {
        Self
    }
}

#[async_trait]
impl Plugin for BasicAuth {
    fn name(&self) -> &str {
        "basic_auth"
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
                };
            }
        };

        if !auth_header.starts_with("Basic ") && !auth_header.starts_with("basic ") {
            return PluginResult::Reject {
                status_code: 401,
                body: r#"{"error":"Invalid Basic auth format"}"#.into(),
            };
        }

        let encoded = &auth_header[6..];
        let decoded = match base64::engine::general_purpose::STANDARD.decode(encoded) {
            Ok(d) => d,
            Err(_) => {
                return PluginResult::Reject {
                    status_code: 401,
                    body: r#"{"error":"Invalid base64 in Basic auth"}"#.into(),
                };
            }
        };

        let credential_str = match String::from_utf8(decoded) {
            Ok(s) => s,
            Err(_) => {
                return PluginResult::Reject {
                    status_code: 401,
                    body: r#"{"error":"Invalid UTF-8 in Basic auth"}"#.into(),
                };
            }
        };

        let parts: Vec<&str> = credential_str.splitn(2, ':').collect();
        if parts.len() != 2 {
            return PluginResult::Reject {
                status_code: 401,
                body: r#"{"error":"Invalid Basic auth format"}"#.into(),
            };
        }

        let username = parts[0];
        let password = parts[1];

        // O(1) lookup by username via ConsumerIndex
        if let Some(consumer) = consumer_index.find_by_username(username)
            && let Some(basic_creds) = consumer.credentials.get("basicauth")
            && let Some(hashed) = basic_creds.get("password_hash").and_then(|s| s.as_str())
        {
            // Verify bcrypt hash
            if bcrypt::verify(password, hashed).unwrap_or(false) {
                if ctx.identified_consumer.is_none() {
                    debug!("basic_auth: identified consumer '{}'", consumer.username);
                    ctx.identified_consumer = Some((*consumer).clone());
                }
                return PluginResult::Continue;
            }
        }

        PluginResult::Reject {
            status_code: 401,
            body: r#"{"error":"Invalid credentials"}"#.into(),
        }
    }
}
