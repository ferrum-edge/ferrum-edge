use arc_swap::ArcSwap;
use async_trait::async_trait;
use jsonwebtoken::{Algorithm, DecodingKey, Validation, decode, decode_header};
use serde_json::Value;
use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;
use tracing::{debug, info, warn};
use url::Url;

use crate::consumer_index::ConsumerIndex;

use super::jwks_store::JwksKeyStore;
use super::utils::PluginHttpClient;
use super::{Plugin, PluginResult, RequestContext};

/// OAuth2 authentication plugin.
///
/// Validates Bearer tokens via one of two modes:
///
/// **JWKS mode** (default): Validates JWTs using public keys fetched from the
/// Identity Provider's JWKS endpoint. The IdP's keys are cached locally and
/// refreshed periodically. Supports RSA (RS256/384/512) and EC (ES256/384).
/// A configurable JWT claim (default: `sub`) is used to look up the consumer
/// in the gateway's consumer index.
///
/// Configuration:
/// - `jwks_uri`: Direct URL to the IdP's JWKS endpoint
/// - `discovery_url`: OIDC discovery URL (e.g. `https://idp.example.com/.well-known/openid-configuration`).
///   The plugin fetches this to auto-discover the `jwks_uri`. Takes precedence over `jwks_uri`.
/// - `consumer_claim`: JWT claim used to identify the consumer (default: `"sub"`).
///   Common alternatives: `"email"`, `"preferred_username"`, `"user_id"`, or any
///   custom claim your IdP includes in the token. The value of this claim is matched
///   against the consumer's `username`, `id`, or `custom_id` via `ConsumerIndex`.
/// - `expected_issuer`: Reject tokens whose `iss` claim doesn't match
/// - `expected_audience`: Reject tokens whose `aud` claim doesn't match
/// - `jwks_refresh_interval_secs`: How often to refresh keys (default: 300)
///
/// **Introspection mode**: Validates opaque tokens by POSTing to the IdP's
/// introspection endpoint (RFC 7662). The configured `consumer_claim` field
/// in the introspection response is used to look up the consumer.
///
/// Configuration:
/// - `introspection_url`: URL to the IdP's introspection endpoint
/// - `introspection_auth`: Authorization header for the introspection request
pub struct OAuth2Auth {
    validation_mode: String,
    introspection_url: Option<String>,
    introspection_auth: Option<String>,
    jwks_uri: Option<String>,
    discovery_url: Option<String>,
    expected_issuer: Option<String>,
    expected_audience: Option<String>,
    /// JWT claim (or introspection response field) used to identify the consumer.
    /// Defaults to `"sub"`. The value is matched against consumer username, id,
    /// or custom_id via `ConsumerIndex::find_by_identity()`.
    consumer_claim: String,
    http_client: PluginHttpClient,
    /// Remote JWKS key store — populated immediately when `jwks_uri` is configured,
    /// or asynchronously after OIDC discovery when `discovery_url` is configured.
    /// Uses ArcSwap so the discovery background task can populate it after construction.
    jwks_store: Arc<ArcSwap<Option<JwksKeyStore>>>,
    /// Handle for the background JWKS refresh task.
    _refresh_handle: Option<tokio::task::JoinHandle<()>>,
}

/// Default JWKS refresh interval: 5 minutes.
const JWKS_REFRESH_INTERVAL_SECS: u64 = 300;

impl OAuth2Auth {
    pub fn new(config: &Value, http_client: PluginHttpClient) -> Result<Self, String> {
        let jwks_uri = config["jwks_uri"].as_str().map(|s| s.to_string());
        let discovery_url = config["discovery_url"].as_str().map(|s| s.to_string());
        let introspection_url = config["introspection_url"].as_str().map(|s| s.to_string());
        let validation_mode = config["validation_mode"]
            .as_str()
            .unwrap_or("jwks")
            .to_string();

        // Validate: at least one endpoint must be configured
        if validation_mode == "introspection" && introspection_url.is_none() {
            return Err(
                "oauth2_auth: validation_mode is 'introspection' but 'introspection_url' is not set"
                    .to_string(),
            );
        }
        if validation_mode != "introspection" && jwks_uri.is_none() && discovery_url.is_none() {
            return Err(
                "oauth2_auth: JWKS mode requires either 'jwks_uri' or 'discovery_url' to be set"
                    .to_string(),
            );
        }
        let refresh_interval_secs = config["jwks_refresh_interval_secs"]
            .as_u64()
            .unwrap_or(JWKS_REFRESH_INTERVAL_SECS);

        let jwks_store_slot: Arc<ArcSwap<Option<JwksKeyStore>>> =
            Arc::new(ArcSwap::from_pointee(None));

        let refresh_handle = if let Some(ref uri) = jwks_uri {
            // Explicit jwks_uri — create store immediately
            let store = JwksKeyStore::new(uri.clone(), http_client.clone());
            let handle = store.start_background_refresh(Duration::from_secs(refresh_interval_secs));
            jwks_store_slot.store(Arc::new(Some(store)));
            Some(handle)
        } else if let Some(ref disc_url) = discovery_url {
            // OIDC discovery — fetch jwks_uri asynchronously, then create store
            let slot = jwks_store_slot.clone();
            let client = http_client.clone();
            let url = disc_url.clone();
            let interval = refresh_interval_secs;
            tokio::spawn(async move {
                match discover_jwks_uri(&client, &url).await {
                    Ok(uri) => {
                        info!("OAuth2 OIDC discovery: resolved jwks_uri={}", uri);
                        let store = JwksKeyStore::new(uri, client);
                        // Eagerly fetch keys before making the store visible
                        if let Err(e) = store.fetch_keys().await {
                            warn!("OAuth2 OIDC: initial JWKS fetch failed: {}", e);
                        }
                        store.start_background_refresh(Duration::from_secs(interval));
                        slot.store(Arc::new(Some(store)));
                    }
                    Err(e) => {
                        warn!(
                            "OAuth2 OIDC discovery failed: {} — JWKS validation will be unavailable",
                            e
                        );
                    }
                }
            });
            None
        } else {
            None
        };

        Ok(Self {
            validation_mode,
            introspection_url,
            introspection_auth: config["introspection_auth"].as_str().map(|s| s.to_string()),
            jwks_uri,
            discovery_url,
            expected_issuer: config["expected_issuer"].as_str().map(|s| s.to_string()),
            expected_audience: config["expected_audience"].as_str().map(|s| s.to_string()),
            consumer_claim: config["consumer_claim"]
                .as_str()
                .unwrap_or("sub")
                .to_string(),
            http_client,
            jwks_store: jwks_store_slot,
            _refresh_handle: refresh_handle,
        })
    }

    /// Eagerly fetch JWKS keys if a store is configured.
    /// Called by tests to pre-populate the key store before assertions.
    #[allow(dead_code)] // Used by tests
    pub async fn warmup_jwks(&self) {
        let guard = self.jwks_store.load();
        if let Some(ref store) = **guard {
            match store.fetch_keys().await {
                Ok(count) => {
                    info!(
                        "OAuth2 JWKS warmup: fetched {} keys from {:?}",
                        count, self.jwks_uri
                    );
                }
                Err(e) => warn!(
                    "OAuth2 JWKS warmup failed: {} — will retry in background",
                    e
                ),
            }
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

    /// Validate a JWT using remote JWKS public keys from the Identity Provider.
    ///
    /// Returns `Some(claims)` if validation succeeds, `None` if it fails
    /// or no JWKS keys are available.
    fn validate_with_jwks(&self, token: &str) -> Option<Value> {
        let guard = self.jwks_store.load();
        let store = guard.as_ref().as_ref()?;

        if !store.has_keys() {
            warn!("OAuth2 JWKS: no keys available — IdP keys may not have been fetched yet");
            return None;
        }

        // Extract the kid from the JWT header to find the right key
        let header = decode_header(token).ok()?;

        if let Some(kid) = &header.kid {
            // Look up the specific key by kid
            if let Some(cached_key) = store.get_key(kid) {
                return self.try_decode_with_key(
                    token,
                    &cached_key.decoding_key,
                    cached_key.algorithm,
                );
            }
            debug!("JWKS key not found for kid={}, trying all keys", kid);
        }

        // No kid in header or kid not found — try all cached keys
        let all_keys = store.all_keys();
        for cached_key in all_keys.values() {
            if let Some(claims) =
                self.try_decode_with_key(token, &cached_key.decoding_key, cached_key.algorithm)
            {
                return Some(claims);
            }
        }

        None
    }

    /// Try to decode a JWT with a specific key and algorithm.
    fn try_decode_with_key(
        &self,
        token: &str,
        key: &DecodingKey,
        algorithm: Algorithm,
    ) -> Option<Value> {
        let mut validation = Validation::new(algorithm);
        validation.validate_exp = true;
        validation.required_spec_claims.clear();

        if let Some(ref iss) = self.expected_issuer {
            validation.set_issuer(&[iss]);
        }
        if let Some(ref aud) = self.expected_audience {
            validation.set_audience(&[aud]);
        }

        decode::<Value>(token, key, &validation)
            .ok()
            .map(|td| td.claims)
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
                // Token introspection via HTTP POST (RFC 7662)
                if let Some(ref url) = self.introspection_url {
                    let mut req = self.http_client.get().post(url).form(&[("token", &token)]);

                    if let Some(ref auth) = self.introspection_auth {
                        req = req.header("Authorization", auth);
                    }

                    match req.send().await {
                        Ok(resp) => {
                            if let Ok(body) = resp.json::<Value>().await {
                                let active = body["active"].as_bool().unwrap_or(false);
                                if active {
                                    // O(1) lookup by configured claim via ConsumerIndex
                                    if let Some(identity) = body[&self.consumer_claim].as_str()
                                        && let Some(consumer) =
                                            consumer_index.find_by_identity(identity)
                                    {
                                        if ctx.identified_consumer.is_none() {
                                            ctx.identified_consumer = Some((*consumer).clone());
                                        }
                                        return PluginResult::Continue;
                                    }
                                    // Token is active but identity not found — reject
                                    warn!(
                                        "OAuth2 introspection: claim '{}' not found or not mapped to a consumer",
                                        self.consumer_claim
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
            other => {
                if other != "jwks" {
                    warn!(
                        "OAuth2: unrecognized validation_mode '{}', defaulting to JWKS",
                        other,
                    );
                }
                // JWKS mode: validate JWT using the IdP's public keys
                debug!(
                    "OAuth2 JWKS validation mode, jwks_uri: {:?}",
                    self.jwks_uri()
                );

                if self.jwks_store.load().is_none() {
                    // Store not yet populated — either no jwks_uri/discovery_url configured,
                    // or OIDC discovery is still in progress
                    if self.discovery_url.is_some() {
                        warn!("OAuth2 JWKS: OIDC discovery still in progress, rejecting request");
                    } else {
                        warn!("OAuth2 JWKS: no jwks_uri or discovery_url configured");
                    }
                    return PluginResult::Reject {
                        status_code: 500,
                        body: r#"{"error":"OAuth2 plugin misconfigured or not yet ready"}"#.into(),
                        headers: HashMap::new(),
                    };
                }

                match self.validate_with_jwks(&token) {
                    Some(claims) => {
                        // Token validated via IdP's public keys — look up consumer
                        // by the configured claim (defaults to "sub")
                        if let Some(identity) =
                            claims.get(&self.consumer_claim).and_then(|s| s.as_str())
                        {
                            if let Some(consumer) = consumer_index.find_by_identity(identity) {
                                if ctx.identified_consumer.is_none() {
                                    debug!(
                                        "oauth2_auth: identified consumer '{}' via JWKS (claim '{}'='{}')",
                                        consumer.username, self.consumer_claim, identity
                                    );
                                    ctx.identified_consumer = Some((*consumer).clone());
                                }
                                return PluginResult::Continue;
                            }
                            warn!(
                                "OAuth2 JWKS: token valid but claim '{}'='{}' not found in consumers",
                                self.consumer_claim, identity
                            );
                        } else {
                            warn!(
                                "OAuth2 JWKS: token valid but claim '{}' not present in token",
                                self.consumer_claim
                            );
                        }
                        PluginResult::Reject {
                            status_code: 401,
                            body: r#"{"error":"Unknown token subject"}"#.into(),
                            headers: HashMap::new(),
                        }
                    }
                    None => PluginResult::Reject {
                        status_code: 401,
                        body: r#"{"error":"Invalid OAuth2 token"}"#.into(),
                        headers: HashMap::new(),
                    },
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
        if let Some(ref url) = self.discovery_url
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

/// Fetch the OIDC discovery document and extract the `jwks_uri` field.
///
/// Standard OIDC discovery endpoints return a JSON document with a `jwks_uri`
/// field pointing to the Identity Provider's JWKS endpoint.
/// See: https://openid.net/specs/openid-connect-discovery-1_0.html
async fn discover_jwks_uri(
    http_client: &PluginHttpClient,
    discovery_url: &str,
) -> Result<String, String> {
    let response = http_client
        .get()
        .get(discovery_url)
        .send()
        .await
        .map_err(|e| format!("OIDC discovery request failed: {}", e))?;

    if !response.status().is_success() {
        return Err(format!(
            "OIDC discovery endpoint returned HTTP {}",
            response.status()
        ));
    }

    let body: Value = response
        .json()
        .await
        .map_err(|e| format!("OIDC discovery response parse failed: {}", e))?;

    body["jwks_uri"]
        .as_str()
        .map(|s| s.to_string())
        .ok_or_else(|| "OIDC discovery document missing 'jwks_uri' field".to_string())
}
