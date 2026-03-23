use async_trait::async_trait;
use jsonwebtoken::{Algorithm, DecodingKey, Validation, decode};
use serde_json::Value;
use std::collections::HashMap;
use tracing::{debug, warn};
use url::Url;

use crate::consumer_index::ConsumerIndex;

use super::utils::PluginHttpClient;
use super::{Plugin, PluginResult, RequestContext};

pub struct OAuth2Auth {
    validation_mode: String,
    introspection_url: Option<String>,
    jwks_uri: Option<String>,
    expected_issuer: Option<String>,
    expected_audience: Option<String>,
    http_client: PluginHttpClient,
}

impl OAuth2Auth {
    pub fn new(config: &Value, http_client: PluginHttpClient) -> Self {
        Self {
            validation_mode: config["validation_mode"]
                .as_str()
                .unwrap_or("jwks")
                .to_string(),
            introspection_url: config["introspection_url"].as_str().map(|s| s.to_string()),
            jwks_uri: config["jwks_uri"].as_str().map(|s| s.to_string()),
            expected_issuer: config["expected_issuer"].as_str().map(|s| s.to_string()),
            expected_audience: config["expected_audience"].as_str().map(|s| s.to_string()),
            http_client,
        }
    }

    fn extract_bearer_token(ctx: &RequestContext) -> Option<String> {
        ctx.headers.get("authorization").and_then(|v| {
            if v.starts_with("Bearer ") || v.starts_with("bearer ") {
                Some(v[7..].to_string())
            } else {
                None
            }
        })
    }
}

#[async_trait]
impl Plugin for OAuth2Auth {
    fn name(&self) -> &str {
        "oauth2_auth"
    }

    fn is_auth_plugin(&self) -> bool {
        true
    }

    fn priority(&self) -> u16 {
        super::priority::OAUTH2_AUTH
    }

    async fn authenticate(
        &self,
        ctx: &mut RequestContext,
        consumer_index: &ConsumerIndex,
    ) -> PluginResult {
        let token = match Self::extract_bearer_token(ctx) {
            Some(t) => t,
            None => {
                return PluginResult::Reject {
                    status_code: 401,
                    body: r#"{"error":"Missing Bearer token"}"#.into(),
                    headers: HashMap::new(),
                };
            }
        };

        match self.validation_mode.as_str() {
            "introspection" => {
                // Token introspection via HTTP POST
                if let Some(ref url) = self.introspection_url {
                    match self
                        .http_client
                        .get()
                        .post(url)
                        .form(&[("token", &token)])
                        .send()
                        .await
                    {
                        Ok(resp) => {
                            if let Ok(body) = resp.json::<Value>().await {
                                let active = body["active"].as_bool().unwrap_or(false);
                                if active {
                                    // O(1) lookup by subject via ConsumerIndex
                                    if let Some(sub) = body["sub"].as_str()
                                        && let Some(consumer) = consumer_index.find_by_identity(sub)
                                    {
                                        if ctx.identified_consumer.is_none() {
                                            ctx.identified_consumer = Some((*consumer).clone());
                                        }
                                        return PluginResult::Continue;
                                    }
                                    // Token is active but subject not found — reject
                                    warn!(
                                        "OAuth2: token active but subject not found in consumers"
                                    );
                                    return PluginResult::Reject {
                                        status_code: 401,
                                        body: r#"{"error":"Unknown token subject"}"#.into(),
                                        headers: HashMap::new(),
                                    };
                                }
                            }
                        }
                        Err(e) => {
                            warn!("OAuth2 introspection failed: {}", e);
                        }
                    }
                }
                PluginResult::Reject {
                    status_code: 401,
                    body: r#"{"error":"Token introspection failed"}"#.into(),
                    headers: HashMap::new(),
                }
            }
            _ => {
                // For JWKS-based validation, try consumer OAuth2 credentials with local secrets
                debug!(
                    "OAuth2 JWKS validation mode, jwks_uri: {:?}",
                    self.jwks_uri()
                );
                let consumers = consumer_index.consumers();
                for consumer in consumers.iter() {
                    if let Some(oauth_creds) = consumer.credentials.get("oauth2")
                        && let Some(secret) = oauth_creds.get("secret").and_then(|s| s.as_str())
                    {
                        let key = DecodingKey::from_secret(secret.as_bytes());
                        let mut validation = Validation::new(Algorithm::HS256);
                        validation.validate_exp = true;
                        validation.required_spec_claims.clear();

                        if let Some(ref iss) = self.expected_issuer {
                            validation.set_issuer(&[iss]);
                        }
                        if let Some(ref aud) = self.expected_audience {
                            validation.set_audience(&[aud]);
                        }

                        if let Ok(_token_data) = decode::<Value>(&token, &key, &validation) {
                            if ctx.identified_consumer.is_none() {
                                debug!("oauth2_auth: identified consumer '{}'", consumer.username);
                                ctx.identified_consumer = Some((**consumer).clone());
                            }
                            return PluginResult::Continue;
                        }
                    }
                }

                PluginResult::Reject {
                    status_code: 401,
                    body: r#"{"error":"Invalid OAuth2 token"}"#.into(),
                    headers: HashMap::new(),
                }
            }
        }
    }

    fn warmup_hostnames(&self) -> Vec<String> {
        let mut hosts = Vec::new();
        if let Some(ref url) = self.introspection_url
            && let Some(host) = Self::hostname_from_url(url)
        {
            hosts.push(host);
        }
        if let Some(ref url) = self.jwks_uri
            && let Some(host) = Self::hostname_from_url(url)
        {
            hosts.push(host);
        }
        hosts
    }
}

impl OAuth2Auth {
    /// Get the JWKS URI for this OAuth2 configuration (if configured)
    pub fn jwks_uri(&self) -> Option<&str> {
        self.jwks_uri.as_deref()
    }

    /// Extract the hostname from a URL string, if parseable.
    fn hostname_from_url(url: &str) -> Option<String> {
        Url::parse(url)
            .ok()
            .and_then(|u| u.host_str().map(|h| h.to_string()))
    }
}
