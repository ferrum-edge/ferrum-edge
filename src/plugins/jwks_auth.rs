use arc_swap::ArcSwap;
use async_trait::async_trait;
use jsonwebtoken::{Algorithm, Validation, decode, decode_header};
use serde_json::Value;
use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;
use tracing::{debug, info, warn};
use url::Url;

use crate::consumer_index::ConsumerIndex;

use super::utils::jwks_cache::get_or_create_jwks_store;
use super::utils::jwks_store::JwksKeyStore;
use super::utils::PluginHttpClient;
use super::{Plugin, PluginResult, RequestContext};

/// Default JWKS refresh interval: 5 minutes.
const DEFAULT_JWKS_REFRESH_INTERVAL_SECS: u64 = 300;

/// JWKS authentication plugin.
///
/// Validates Bearer tokens using public keys fetched from one or more
/// Identity Provider JWKS endpoints. Supports RSA (RS256/384/512) and
/// EC (ES256/384) algorithms.
///
/// ## Key features
///
/// - **Multiple identity providers**: Configure an array of `providers`,
///   each with its own issuer, JWKS URI, audience, and claim-based
///   authorization rules.
/// - **Claim-based authorization**: Per-provider `required_scopes` and
///   `required_roles` filter requests without needing a separate ACL plugin.
/// - **Consumer-optional flow**: When no matching `Consumer` exists in the
///   gateway, the plugin still sets `authenticated_identity` on the request
///   context for downstream use (logging, rate limiting, consumer header).
/// - **Shared JWKS cache**: Stores keyed by resolved `jwks_uri` are shared
///   across plugin instances — no duplicate fetches or refresh tasks.
///
/// ## Configuration
///
/// ```json
/// {
///   "providers": [
///     {
///       "issuer": "https://auth.example.com",
///       "jwks_uri": "https://auth.example.com/.well-known/jwks.json",
///       "audience": "my-api",
///       "required_scopes": ["read:data"],
///       "required_roles": ["admin"],
///       "scope_claim": "scp",
///       "role_claim": "realm_access.roles"
///     }
///   ],
///   "scope_claim": "scope",
///   "role_claim": "roles",
///   "consumer_identity_claim": "sub",
///   "consumer_header_claim": "email",
///   "jwks_refresh_interval_secs": 300
/// }
/// ```
pub struct JwksAuth {
    providers: Vec<JwksProvider>,
    /// Global default: JWT claim path containing scopes (default: `"scope"`).
    global_scope_claim: String,
    /// Global default: JWT claim path containing roles (default: `"roles"`).
    global_role_claim: String,
    /// JWT claim used for ConsumerIndex lookup and rate-limit key (default: `"sub"`).
    consumer_identity_claim: String,
    /// JWT claim value sent as `X-Consumer-Username` header to the backend.
    /// Defaults to `consumer_identity_claim` if not set separately.
    consumer_header_claim: String,
}

/// A single identity provider configuration.
struct JwksProvider {
    /// Expected `iss` claim value. Used to match incoming tokens to this provider.
    issuer: Option<String>,
    /// Expected `aud` claim value.
    audience: Option<String>,
    /// Scopes that must be present in the token (all required).
    required_scopes: Vec<String>,
    /// Roles that must be present in the token (any one suffices).
    required_roles: Vec<String>,
    /// Per-provider override for the scope claim path.
    scope_claim: Option<String>,
    /// Per-provider override for the role claim path.
    role_claim: Option<String>,
    /// The JWKS key store (shared via global cache).
    jwks_store: Arc<ArcSwap<Option<Arc<JwksKeyStore>>>>,
}

impl JwksAuth {
    pub fn new(config: &Value, http_client: PluginHttpClient) -> Result<Self, String> {
        let refresh_interval_secs = config["jwks_refresh_interval_secs"]
            .as_u64()
            .unwrap_or(DEFAULT_JWKS_REFRESH_INTERVAL_SECS);
        let refresh_interval = Duration::from_secs(refresh_interval_secs);

        let global_scope_claim = config["scope_claim"]
            .as_str()
            .unwrap_or("scope")
            .to_string();
        let global_role_claim = config["role_claim"].as_str().unwrap_or("roles").to_string();
        let consumer_identity_claim = config["consumer_identity_claim"]
            .as_str()
            .unwrap_or("sub")
            .to_string();
        let consumer_header_claim = config["consumer_header_claim"]
            .as_str()
            .unwrap_or(&consumer_identity_claim)
            .to_string();

        let providers_val = &config["providers"];
        let Some(providers_arr) = providers_val.as_array() else {
            return Err("jwks_auth: 'providers' must be a non-empty array".to_string());
        };
        if providers_arr.is_empty() {
            return Err("jwks_auth: 'providers' array must not be empty".to_string());
        }

        let mut providers = Vec::with_capacity(providers_arr.len());

        for (idx, prov_cfg) in providers_arr.iter().enumerate() {
            let jwks_uri = prov_cfg["jwks_uri"].as_str().map(|s| s.to_string());
            let discovery_url = prov_cfg["discovery_url"].as_str().map(|s| s.to_string());

            if jwks_uri.is_none() && discovery_url.is_none() {
                return Err(format!(
                    "jwks_auth: provider[{}] requires either 'jwks_uri' or 'discovery_url'",
                    idx
                ));
            }

            let issuer = prov_cfg["issuer"].as_str().map(|s| s.to_string());
            let audience = prov_cfg["audience"].as_str().map(|s| s.to_string());

            let required_scopes = parse_string_array(&prov_cfg["required_scopes"]);
            let required_roles = parse_string_array(&prov_cfg["required_roles"]);

            let scope_claim = prov_cfg["scope_claim"].as_str().map(|s| s.to_string());
            let role_claim = prov_cfg["role_claim"].as_str().map(|s| s.to_string());

            let jwks_store_slot: Arc<ArcSwap<Option<Arc<JwksKeyStore>>>> =
                Arc::new(ArcSwap::from_pointee(None));

            if let Some(ref uri) = jwks_uri {
                // Direct jwks_uri — get-or-create shared store immediately
                let store = get_or_create_jwks_store(uri, &http_client, refresh_interval);
                jwks_store_slot.store(Arc::new(Some(store)));
            } else if let Some(ref disc_url) = discovery_url {
                // OIDC discovery — resolve jwks_uri asynchronously
                let slot = jwks_store_slot.clone();
                let client = http_client.clone();
                let url = disc_url.clone();
                let interval = refresh_interval;
                tokio::spawn(async move {
                    match discover_jwks_uri(&client, &url).await {
                        Ok(uri) => {
                            info!("jwks_auth OIDC discovery: resolved jwks_uri={}", uri);
                            let store = get_or_create_jwks_store(&uri, &client, interval);
                            // Eagerly fetch keys before making the store visible
                            if let Err(e) = store.fetch_keys().await {
                                warn!("jwks_auth OIDC: initial JWKS fetch failed: {}", e);
                            }
                            slot.store(Arc::new(Some(store)));
                        }
                        Err(e) => {
                            warn!(
                                "jwks_auth OIDC discovery failed: {} — provider will be unavailable",
                                e
                            );
                        }
                    }
                });
            }

            providers.push(JwksProvider {
                issuer,
                audience,
                required_scopes,
                required_roles,
                scope_claim,
                role_claim,
                jwks_store: jwks_store_slot,
            });
        }

        Ok(Self {
            providers,
            global_scope_claim,
            global_role_claim,
            consumer_identity_claim,
            consumer_header_claim,
        })
    }

    /// Eagerly fetch JWKS keys for all providers that have stores ready.
    /// Called by tests to pre-populate key stores before assertions.
    #[allow(dead_code)]
    pub async fn warmup_jwks(&self) {
        for prov in &self.providers {
            let guard = prov.jwks_store.load();
            if let Some(ref store) = **guard {
                match store.fetch_keys().await {
                    Ok(count) => {
                        info!("jwks_auth warmup: fetched {} keys", count);
                    }
                    Err(e) => warn!("jwks_auth warmup failed: {} — will retry in background", e),
                }
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

    /// Try to validate a token against all configured providers.
    ///
    /// Returns `Ok((claims, provider_index))` on first successful validation,
    /// or `Err(status_code, body)` if no provider validates the token.
    async fn validate_token(&self, token: &str) -> Result<(Value, usize), (u16, &'static str)> {
        // Peek at the unverified issuer to try matching a specific provider first
        let unverified_issuer = peek_issuer(token);

        // If we have an issuer, try matching providers with that issuer first
        if let Some(ref iss) = unverified_issuer {
            for (idx, prov) in self.providers.iter().enumerate() {
                if prov.issuer.as_deref() == Some(iss.as_str())
                    && let Some(claims) = try_validate_with_provider(prov, token).await
                {
                    return Ok((claims, idx));
                }
            }
        }

        // Fall through: try all providers (handles no-issuer tokens or issuer mismatch)
        for (idx, prov) in self.providers.iter().enumerate() {
            if let Some(claims) = try_validate_with_provider(prov, token).await {
                return Ok((claims, idx));
            }
        }

        Err((401, r#"{"error":"Invalid or unrecognized JWT"}"#))
    }

    /// Check required_scopes and required_roles for a matched provider.
    fn check_claims_authorization(
        &self,
        claims: &Value,
        provider: &JwksProvider,
    ) -> Result<(), (u16, String)> {
        // Check required scopes
        if !provider.required_scopes.is_empty() {
            let scope_claim_path = provider
                .scope_claim
                .as_deref()
                .unwrap_or(&self.global_scope_claim);
            let token_scopes = extract_claim_values(claims, scope_claim_path);

            for required in &provider.required_scopes {
                if !token_scopes.iter().any(|s| s == required) {
                    return Err((
                        403,
                        format!(
                            r#"{{"error":"Insufficient scope","required":"{}"}}"#,
                            html_escape(required)
                        ),
                    ));
                }
            }
        }

        // Check required roles (any one match suffices)
        if !provider.required_roles.is_empty() {
            let role_claim_path = provider
                .role_claim
                .as_deref()
                .unwrap_or(&self.global_role_claim);
            let token_roles = extract_claim_values(claims, role_claim_path);

            let has_match = provider
                .required_roles
                .iter()
                .any(|r| token_roles.iter().any(|tr| tr == r));

            if !has_match {
                return Err((403, r#"{"error":"Insufficient role"}"#.to_string()));
            }
        }

        Ok(())
    }
}

#[async_trait]
impl Plugin for JwksAuth {
    fn name(&self) -> &str {
        "jwks_auth"
    }

    fn is_auth_plugin(&self) -> bool {
        true
    }

    fn priority(&self) -> u16 {
        super::priority::JWKS_AUTH
    }

    fn supported_protocols(&self) -> &'static [super::ProxyProtocol] {
        super::HTTP_FAMILY_PROTOCOLS
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

        // 1. Validate JWT against configured providers
        let (claims, provider_idx) = match self.validate_token(&token).await {
            Ok(result) => result,
            Err((status, body)) => {
                return PluginResult::Reject {
                    status_code: status,
                    body: body.into(),
                    headers: HashMap::new(),
                };
            }
        };

        let provider = &self.providers[provider_idx];

        // 2. Check required_scopes / required_roles
        if let Err((status, body)) = self.check_claims_authorization(&claims, provider) {
            return PluginResult::Reject {
                status_code: status,
                body,
                headers: HashMap::new(),
            };
        }

        // 3. Extract consumer identity claim
        let identity = extract_claim_string(&claims, &self.consumer_identity_claim);
        let header_value = if self.consumer_header_claim == self.consumer_identity_claim {
            identity.clone()
        } else {
            extract_claim_string(&claims, &self.consumer_header_claim).or_else(|| identity.clone())
        };

        // 4. Set authenticated identity on context (always, even without Consumer)
        if let Some(ref id) = identity {
            ctx.authenticated_identity = Some(id.clone());
        }
        if let Some(ref hv) = header_value {
            ctx.authenticated_identity_header = Some(hv.clone());
        }

        // 5. Optionally look up Consumer in index (for ACL plugin compat)
        if let Some(ref id) = identity {
            if let Some(consumer) = consumer_index.find_by_identity(id) {
                if ctx.identified_consumer.is_none() {
                    debug!(
                        "jwks_auth: identified consumer '{}' via claim '{}'='{}'",
                        consumer.username, self.consumer_identity_claim, id
                    );
                    ctx.identified_consumer = Some((*consumer).clone());
                }
            } else {
                debug!(
                    "jwks_auth: no consumer found for '{}'='{}' — using external identity",
                    self.consumer_identity_claim, id
                );
            }
        } else {
            warn!(
                "jwks_auth: token valid but claim '{}' not present",
                self.consumer_identity_claim
            );
        }

        PluginResult::Continue
    }

    fn warmup_hostnames(&self) -> Vec<String> {
        let mut hosts = Vec::new();
        for prov in &self.providers {
            let guard = prov.jwks_store.load();
            if let Some(ref store) = **guard
                && let Some(host) = hostname_from_url(store.jwks_uri())
            {
                hosts.push(host);
            }
        }
        hosts
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Try to validate a JWT against a single provider's JWKS store.
async fn try_validate_with_provider(provider: &JwksProvider, token: &str) -> Option<Value> {
    let guard = provider.jwks_store.load();
    let store = guard.as_ref().as_ref()?;

    if !store.has_keys()
        && let Err(e) = store.fetch_keys().await
    {
        debug!("jwks_auth: on-demand JWKS fetch failed: {}", e);
        return None;
    }

    let header = decode_header(token).ok()?;

    // Build validation params for this provider
    let build_validation = |algorithm: Algorithm| -> Validation {
        let mut validation = Validation::new(algorithm);
        validation.validate_exp = true;
        validation.required_spec_claims.clear();
        if let Some(ref iss) = provider.issuer {
            validation.set_issuer(&[iss]);
        }
        if let Some(ref aud) = provider.audience {
            validation.set_audience(&[aud]);
        }
        validation
    };

    // Try specific kid first
    if let Some(kid) = &header.kid {
        if let Some(cached_key) = store.get_key(kid) {
            let validation = build_validation(cached_key.algorithm);
            if let Ok(td) = decode::<Value>(token, &cached_key.decoding_key, &validation) {
                return Some(td.claims);
            }
        }
        debug!("JWKS key not found for kid={}, trying all keys", kid);
    }

    // Fallback: try all cached keys
    let all_keys = store.all_keys();
    for cached_key in all_keys.values() {
        let validation = build_validation(cached_key.algorithm);
        if let Ok(td) = decode::<Value>(token, &cached_key.decoding_key, &validation) {
            return Some(td.claims);
        }
    }

    None
}

/// Peek at the `iss` claim without signature verification.
///
/// Used to route the token to the correct provider before doing real validation.
fn peek_issuer(token: &str) -> Option<String> {
    // Decode the payload segment (second part) without verification
    let parts: Vec<&str> = token.split('.').collect();
    if parts.len() != 3 {
        return None;
    }
    use base64::Engine;
    let payload_bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(parts[1])
        .ok()?;
    let payload: Value = serde_json::from_slice(&payload_bytes).ok()?;
    payload
        .get("iss")
        .and_then(|v| v.as_str())
        .map(|s| s.to_string())
}

/// Extract values from a JWT claim, supporting:
/// - Space-delimited strings: `"read:data write:data"` → `["read:data", "write:data"]`
/// - Arrays of strings: `["admin", "editor"]` → `["admin", "editor"]`
/// - Nested dot-notation paths: `"realm_access.roles"` navigates `{"realm_access": {"roles": [...]}}`
pub fn extract_claim_values(claims: &Value, claim_path: &str) -> Vec<String> {
    let value = resolve_claim_path(claims, claim_path);
    let Some(value) = value else {
        return Vec::new();
    };
    normalize_claim_to_vec(value)
}

/// Resolve a dot-notation path like `"realm_access.roles"` through nested JSON.
fn resolve_claim_path<'a>(claims: &'a Value, path: &str) -> Option<&'a Value> {
    let mut current = claims;
    for segment in path.split('.') {
        current = current.get(segment)?;
    }
    Some(current)
}

/// Normalize a claim value to a Vec<String>:
/// - String → split on spaces
/// - Array → collect string elements
/// - Other → empty
fn normalize_claim_to_vec(value: &Value) -> Vec<String> {
    match value {
        Value::String(s) => s.split_whitespace().map(|s| s.to_string()).collect(),
        Value::Array(arr) => arr
            .iter()
            .filter_map(|v| v.as_str().map(|s| s.to_string()))
            .collect(),
        _ => Vec::new(),
    }
}

/// Extract a single string value from a claim path.
fn extract_claim_string(claims: &Value, claim_path: &str) -> Option<String> {
    let value = resolve_claim_path(claims, claim_path)?;
    value.as_str().map(|s| s.to_string())
}

/// Parse a JSON value as an array of strings, or empty vec if not present/valid.
fn parse_string_array(val: &Value) -> Vec<String> {
    val.as_array()
        .map(|arr| {
            arr.iter()
                .filter_map(|v| v.as_str().map(|s| s.to_string()))
                .collect()
        })
        .unwrap_or_default()
}

/// Escape characters that could cause JSON injection in error response bodies.
fn html_escape(s: &str) -> String {
    s.replace('\\', "\\\\")
        .replace('"', "\\\"")
        .replace('<', "\\u003c")
        .replace('>', "\\u003e")
}

/// Fetch the OIDC discovery document and extract the `jwks_uri` field.
async fn discover_jwks_uri(
    http_client: &PluginHttpClient,
    discovery_url: &str,
) -> Result<String, String> {
    let req = http_client.get().get(discovery_url);
    let response = http_client
        .execute(req, "jwks_auth_oidc_discovery")
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

/// Extract the hostname from a URL string, if parseable.
fn hostname_from_url(url: &str) -> Option<String> {
    Url::parse(url)
        .ok()
        .and_then(|u| u.host_str().map(|h| h.to_string()))
}
