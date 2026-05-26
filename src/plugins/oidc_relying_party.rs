use std::collections::{HashMap, HashSet};
use std::fmt;
use std::net::IpAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use arc_swap::ArcSwap;
use async_trait::async_trait;
use base64::Engine;
use dashmap::DashMap;
use jsonwebtoken::{Algorithm, EncodingKey, Header, encode};
use ring::rand::{SecureRandom, SystemRandom};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value, json};
use sha2::{Digest, Sha256};
use tracing::{info, warn};
use url::{Host, Url};

use crate::consumer_index::ConsumerIndex;

use super::utils::PluginHttpClient;
use super::utils::auth_flow::{VerifyOutcome, constant_time_eq};
use super::utils::claim_header_fanout::{
    ClaimHeaderMapping, apply_claim_headers_from_metadata, emit_claim_headers_to_metadata,
    parse_claim_headers,
};
use super::utils::claim_resolver::extract_claim_string;
use super::utils::jwks_cache::get_or_create_jwks_store;
use super::utils::jwks_store::JwksKeyStore;
use super::utils::jwt_verifier::{JwtVerifyParams, verify_jwt_with_jwks};
use super::utils::scope_role_check::{self, ScopeRoleRequirements};
use super::{PluginResult, RequestContext};

const CLAIM_HEADER_METADATA_PREFIX: &str = "oidc_rp.claim_header.";
const DEFAULT_JWKS_REFRESH_INTERVAL: Duration = Duration::from_secs(900);

pub struct OidcRelyingParty {
    provider: Arc<ProviderRuntime>,
    session: Arc<SessionRuntime>,
    behavior: Arc<BehaviorConfig>,
}

struct ProviderRuntime {
    issuer: String,
    discovery: Arc<ArcSwap<Option<DiscoveryDoc>>>,
    jwks_store: Arc<ArcSwap<Option<Arc<JwksKeyStore>>>>,
    client_id: String,
    client_auth: OidcClientAuth,
    scopes: Vec<String>,
    audiences: Vec<String>,
    redirect_uri: String,
    callback_path: String,
    logout_path: String,
    post_logout_redirect_uri: Option<String>,
    consumer_identity_claim: String,
    consumer_header_claim: String,
    claim_headers: Vec<ClaimHeaderMapping>,
    required_scopes: Vec<String>,
    required_roles: Vec<String>,
    scope_claim: String,
    role_claim: String,
    id_token_clock_skew: Duration,
    http_client: PluginHttpClient,
    warmup_hostnames: Vec<String>,
}

#[derive(Clone)]
struct DiscoveryDoc {
    authorization_endpoint: String,
    token_endpoint: String,
    userinfo_endpoint: Option<String>,
    jwks_uri: String,
    end_session_endpoint: Option<String>,
}

struct SessionRuntime {
    codec: super::utils::session_cookie::SessionCookieCodec,
    cookie_name: String,
    cookie_attrs: String,
    max_cookie_bytes: usize,
    ttl: Duration,
    idle_ttl: Duration,
    state_cache: Arc<StateCache>,
}

struct BehaviorConfig {
    challenge_html_status: u16,
    challenge_api_status: u16,
    html_accept_substrings: Vec<String>,
    state_ttl: Duration,
    refresh_skew: Duration,
    rp_initiated_logout: bool,
    post_login_redirect_param: Option<String>,
    post_login_default_path: String,
    trusted_redirect_hosts: Vec<String>,
}

enum OidcClientAuth {
    Basic {
        client_secret: SecretString,
    },
    Post {
        client_secret: SecretString,
    },
    PrivateKeyJwt {
        encoding_key: EncodingKey,
        alg: Algorithm,
        kid: Option<String>,
    },
    None,
}

#[derive(Clone)]
struct SecretString(String);

impl SecretString {
    fn expose(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for SecretString {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("[REDACTED]")
    }
}

impl fmt::Display for SecretString {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("[REDACTED]")
    }
}

#[derive(Clone)]
struct FlowState {
    code_verifier: String,
    nonce: String,
    original_url: String,
    expires_at: Instant,
}

struct StateCache {
    entries: DashMap<String, FlowState>,
    max_entries: usize,
    ttl: Duration,
}

#[derive(Serialize, Deserialize)]
struct SessionPayload {
    version: u8,
    sub: String,
    id_token_b64: String,
    access_token_b64: String,
    refresh_token_b64: Option<String>,
    expires_at_unix: i64,
    refresh_after_unix: i64,
    issued_at_unix: i64,
    last_touch_unix: i64,
    nonce: String,
    claims: Value,
}

#[derive(Deserialize)]
struct TokenResponse {
    access_token: String,
    id_token: String,
    token_type: String,
    #[serde(default)]
    refresh_token: Option<String>,
    #[serde(default)]
    expires_in: Option<i64>,
}

impl OidcRelyingParty {
    pub fn new(config: &Value, http_client: PluginHttpClient) -> Result<Self, String> {
        let config_obj = config.as_object().ok_or_else(|| {
            format!("oidc_relying_party: config must be an object, got: {config}")
        })?;
        let providers = config_obj
            .get("providers")
            .and_then(Value::as_array)
            .ok_or_else(|| {
                "oidc_relying_party: 'providers' must be a non-empty array".to_string()
            })?;
        if providers.len() != 1 {
            return Err(
                "oidc_relying_party: exactly one provider is supported per plugin instance"
                    .to_string(),
            );
        }
        let provider_obj = providers[0]
            .as_object()
            .ok_or_else(|| "oidc_relying_party: provider[0] must be an object".to_string())?;
        let session_obj = config_obj
            .get("session")
            .and_then(Value::as_object)
            .ok_or_else(|| "oidc_relying_party: 'session' object is required".to_string())?;
        let behavior_obj = config_obj.get("behavior").and_then(Value::as_object);

        let issuer = required_string(provider_obj, "issuer", "provider[0]")?;
        let discovery_url = optional_string(provider_obj, "discovery_url", "provider[0]")?;
        let authorization_endpoint =
            optional_string(provider_obj, "authorization_endpoint", "provider[0]")?;
        let token_endpoint = optional_string(provider_obj, "token_endpoint", "provider[0]")?;
        let userinfo_endpoint = optional_string(provider_obj, "userinfo_endpoint", "provider[0]")?;
        let jwks_uri = optional_string(provider_obj, "jwks_uri", "provider[0]")?;
        let end_session_endpoint =
            optional_string(provider_obj, "end_session_endpoint", "provider[0]")?;
        let explicit_complete =
            authorization_endpoint.is_some() && token_endpoint.is_some() && jwks_uri.is_some();
        if discovery_url.is_none() && !explicit_complete {
            return Err(
                "oidc_relying_party: provider[0] requires discovery_url or explicit authorization_endpoint, token_endpoint, and jwks_uri"
                    .to_string(),
            );
        }
        if discovery_url.is_some()
            && (authorization_endpoint.is_some() || token_endpoint.is_some() || jwks_uri.is_some())
        {
            return Err(
                "oidc_relying_party: provider[0] discovery_url conflicts with explicit endpoints"
                    .to_string(),
            );
        }
        let discovery_url = discovery_url
            .map(|url| validate_url_string(&url, "provider[0].discovery_url"))
            .transpose()?;
        let authorization_endpoint = authorization_endpoint
            .map(|url| validate_url_string(&url, "provider[0].authorization_endpoint"))
            .transpose()?;
        let token_endpoint = token_endpoint
            .map(|url| validate_url_string(&url, "provider[0].token_endpoint"))
            .transpose()?;
        let userinfo_endpoint = userinfo_endpoint
            .map(|url| validate_url_string(&url, "provider[0].userinfo_endpoint"))
            .transpose()?;
        let jwks_uri = jwks_uri
            .map(|url| validate_url_string(&url, "provider[0].jwks_uri"))
            .transpose()?;
        let end_session_endpoint = end_session_endpoint
            .map(|url| validate_url_string(&url, "provider[0].end_session_endpoint"))
            .transpose()?;

        let client_id = required_string(provider_obj, "client_id", "provider[0]")?;
        let scopes = parse_string_array(provider_obj, "scopes", "provider[0]")?;
        if scopes.is_empty() || !scopes.iter().any(|scope| scope == "openid") {
            return Err("oidc_relying_party: provider[0].scopes must include 'openid'".to_string());
        }
        let redirect_uri = required_string(provider_obj, "redirect_uri", "provider[0]")?;
        validate_redirect_uri(&redirect_uri)?;
        let callback_path = optional_string(provider_obj, "callback_path", "provider[0]")?
            .unwrap_or_else(|| "/oauth/callback".to_string());
        validate_path_only(&callback_path, "callback_path")?;
        let redirect_path = Url::parse(&redirect_uri)
            .map_err(|e| format!("oidc_relying_party: redirect_uri is invalid: {e}"))?
            .path()
            .to_string();
        if redirect_path != callback_path {
            return Err(
                "oidc_relying_party: redirect_uri path must equal callback_path".to_string(),
            );
        }
        let logout_path = optional_string(provider_obj, "logout_path", "provider[0]")?
            .unwrap_or_else(|| "/oauth/logout".to_string());
        validate_path_only(&logout_path, "logout_path")?;

        let discovery_doc = if let (Some(auth), Some(token), Some(jwks)) = (
            authorization_endpoint.clone(),
            token_endpoint.clone(),
            jwks_uri.clone(),
        ) {
            Some(DiscoveryDoc {
                authorization_endpoint: auth,
                token_endpoint: token,
                userinfo_endpoint,
                jwks_uri: jwks,
                end_session_endpoint,
            })
        } else {
            None
        };
        let discovery = Arc::new(ArcSwap::from_pointee(discovery_doc.clone()));

        let cookie_name = optional_string(session_obj, "cookie_name", "session")?
            .unwrap_or_else(|| "ferrum_session".to_string());
        let store = optional_string(session_obj, "store", "session")?
            .unwrap_or_else(|| "cookie".to_string());
        if store != "cookie" {
            return Err("oidc_relying_party: session.store must be 'cookie'".to_string());
        }
        let encryption_secret = required_string(session_obj, "encryption_secret", "session")?;
        let previous_secret =
            optional_string(session_obj, "encryption_secret_previous", "session")?;
        let ttl_secs = optional_u64(session_obj, "ttl_secs", 3600)?;
        let idle_ttl_secs = optional_u64(session_obj, "idle_ttl_secs", 1800)?;
        let max_cookie_bytes = optional_u64(session_obj, "max_cookie_bytes", 8000)?;
        if max_cookie_bytes > 8000 {
            return Err("oidc_relying_party: session.max_cookie_bytes must be <= 8000".to_string());
        }
        let secure = optional_bool(session_obj, "secure")?.unwrap_or(true);
        let http_only = optional_bool(session_obj, "http_only")?.unwrap_or(true);
        let same_site = optional_string(session_obj, "same_site", "session")?
            .unwrap_or_else(|| "lax".to_string())
            .to_ascii_lowercase();
        if !matches!(same_site.as_str(), "strict" | "lax" | "none") {
            return Err(
                "oidc_relying_party: session.same_site must be strict, lax, or none".to_string(),
            );
        }
        if same_site == "none" && !secure {
            return Err("oidc_relying_party: SameSite=None requires secure=true".to_string());
        }
        let domain = optional_string(session_obj, "domain", "session")?;
        let path =
            optional_string(session_obj, "path", "session")?.unwrap_or_else(|| "/".to_string());
        let cookie_attrs =
            build_cookie_attrs(secure, http_only, &same_site, domain.as_deref(), &path);
        let session = Arc::new(SessionRuntime {
            codec: super::utils::session_cookie::SessionCookieCodec::new(
                &encryption_secret,
                previous_secret.as_deref(),
                max_cookie_bytes as usize,
            )?,
            cookie_name,
            cookie_attrs,
            max_cookie_bytes: max_cookie_bytes as usize,
            ttl: Duration::from_secs(ttl_secs),
            idle_ttl: Duration::from_secs(idle_ttl_secs),
            state_cache: Arc::new(StateCache::new(
                50_000,
                Duration::from_secs(optional_behavior_u64(behavior_obj, "state_ttl_secs", 600)?),
                http_client.pool_shard_amount(),
            )),
        });

        let post_login_redirect_param =
            optional_behavior_string(behavior_obj, "post_login_redirect_param")?;
        let trusted_redirect_hosts =
            parse_behavior_string_array(behavior_obj, "trusted_redirect_hosts")?;
        if post_login_redirect_param.is_some() && trusted_redirect_hosts.is_empty() {
            return Err("oidc_relying_party: behavior.trusted_redirect_hosts is required when post_login_redirect_param is set".to_string());
        }
        let refresh_skew_secs = optional_behavior_u64(behavior_obj, "refresh_skew_secs", 30)?;
        if refresh_skew_secs > ttl_secs / 2 {
            return Err(
                "oidc_relying_party: behavior.refresh_skew_secs must be <= session.ttl_secs / 2"
                    .to_string(),
            );
        }

        let behavior = Arc::new(BehaviorConfig {
            challenge_html_status: parse_status(
                optional_behavior_u64(behavior_obj, "challenge_html_status", 302)?,
                &[302, 303, 307],
                "challenge_html_status",
            )?,
            challenge_api_status: parse_status(
                optional_behavior_u64(behavior_obj, "challenge_api_status", 401)?,
                &[401, 403],
                "challenge_api_status",
            )?,
            html_accept_substrings: parse_behavior_string_array(
                behavior_obj,
                "html_accept_substrings",
            )?
            .into_iter()
            .collect::<Vec<_>>()
            .pipe_default(vec!["text/html".to_string()]),
            state_ttl: session.state_cache.ttl,
            refresh_skew: Duration::from_secs(refresh_skew_secs),
            rp_initiated_logout: optional_behavior_bool(behavior_obj, "rp_initiated_logout")?
                .unwrap_or(true),
            post_login_redirect_param,
            post_login_default_path: optional_behavior_string(
                behavior_obj,
                "post_login_default_path",
            )?
            .unwrap_or_else(|| "/".to_string()),
            trusted_redirect_hosts,
        });

        let client_auth = parse_client_auth(
            provider_obj,
            token_endpoint.as_deref().or(discovery_url.as_deref()),
        )?;
        let jwks_store = Arc::new(ArcSwap::from_pointee(jwks_uri.as_ref().map(|uri| {
            get_or_create_jwks_store(uri, &http_client, DEFAULT_JWKS_REFRESH_INTERVAL)
        })));
        if let Some(url) = discovery_url.clone() {
            spawn_oidc_discovery(
                discovery.clone(),
                jwks_store.clone(),
                http_client.clone(),
                url,
            );
        }

        let provider = Arc::new(ProviderRuntime {
            issuer,
            discovery,
            jwks_store,
            client_id,
            client_auth,
            scopes,
            audiences: parse_string_array(provider_obj, "audiences", "provider[0]")?,
            redirect_uri,
            callback_path,
            logout_path,
            post_logout_redirect_uri: optional_string(
                provider_obj,
                "post_logout_redirect_uri",
                "provider[0]",
            )?,
            consumer_identity_claim: optional_string(
                provider_obj,
                "consumer_identity_claim",
                "provider[0]",
            )?
            .unwrap_or_else(|| "sub".to_string()),
            consumer_header_claim: optional_string(
                provider_obj,
                "consumer_header_claim",
                "provider[0]",
            )?
            .unwrap_or_else(|| "sub".to_string()),
            claim_headers: parse_claim_headers(
                provider_obj,
                "claim_headers",
                "oidc_relying_party",
                CLAIM_HEADER_METADATA_PREFIX,
            )?,
            required_scopes: parse_string_array(provider_obj, "required_scopes", "provider[0]")?,
            required_roles: parse_string_array(provider_obj, "required_roles", "provider[0]")?,
            scope_claim: optional_string(provider_obj, "scope_claim", "provider[0]")?
                .unwrap_or_else(|| "scope".to_string()),
            role_claim: optional_string(provider_obj, "role_claim", "provider[0]")?
                .unwrap_or_else(|| "roles".to_string()),
            id_token_clock_skew: Duration::from_secs(optional_u64(
                provider_obj,
                "id_token_clock_skew_secs",
                60,
            )?),
            http_client,
            warmup_hostnames: discovery_url
                .and_then(|url| hostname_from_url(&url))
                .into_iter()
                .collect(),
        });

        Ok(Self {
            provider,
            session,
            behavior,
        })
    }

    async fn handle_callback(&self, ctx: &mut RequestContext) -> PluginResult {
        if let Some(error) = ctx.query_params.get("error") {
            return reject(400, format!(r#"{{"error":"{}"}}"#, escape_json(error)));
        }
        let Some(state) = ctx.query_params.get("state").cloned() else {
            return reject(400, r#"{"error":"Missing state"}"#.to_string());
        };
        let Some(flow) = self.session.state_cache.take(&state) else {
            return reject(400, r#"{"error":"Invalid state"}"#.to_string());
        };
        let Some(code) = ctx.query_params.get("code").cloned() else {
            return reject(400, r#"{"error":"Missing code"}"#.to_string());
        };
        let Some(discovery) = self.provider.discovery.load().as_ref().as_ref().cloned() else {
            return reject(400, r#"{"error":"OIDC discovery unavailable"}"#.to_string());
        };
        let token = match self
            .exchange_code(&discovery, &code, &flow.code_verifier)
            .await
        {
            Ok(token) => token,
            Err(body) => return reject(400, body),
        };
        let claims = match self.verify_id_token(&token.id_token, &flow.nonce).await {
            Ok(claims) => claims,
            Err(body) => return reject(400, body),
        };
        let merged_claims = if let Some(userinfo_endpoint) = &discovery.userinfo_endpoint {
            match self
                .fetch_userinfo(userinfo_endpoint, &token.access_token)
                .await
            {
                Ok(Some(userinfo)) => {
                    match merge_claims(claims.clone(), userinfo, &self.provider) {
                        Ok(claims) => claims,
                        Err(body) => return reject(400, body),
                    }
                }
                Ok(None) => claims,
                Err(error) => {
                    warn!(
                        plugin = "oidc_relying_party",
                        error = %error,
                        "OIDC userinfo fetch failed; continuing with ID token claims only"
                    );
                    claims
                }
            }
        } else {
            claims
        };
        let now = chrono::Utc::now().timestamp();
        let expires_at = now
            + token
                .expires_in
                .unwrap_or(self.session.ttl.as_secs() as i64);
        let payload = SessionPayload {
            version: 1,
            sub: extract_claim_string(&merged_claims, "sub").unwrap_or_default(),
            id_token_b64: token.id_token,
            access_token_b64: token.access_token,
            refresh_token_b64: token.refresh_token,
            expires_at_unix: expires_at,
            refresh_after_unix: expires_at - self.behavior.refresh_skew.as_secs() as i64,
            issued_at_unix: now,
            last_touch_unix: now,
            nonce: flow.nonce,
            claims: merged_claims,
        };
        let cookie = match self.seal_session_cookie(&payload) {
            Ok(cookie) => cookie,
            Err(body) => return reject(400, body),
        };
        redirect(
            302,
            &self.sanitize_redirect(&flow.original_url),
            Some(cookie),
        )
    }

    async fn exchange_code(
        &self,
        discovery: &DiscoveryDoc,
        code: &str,
        code_verifier: &str,
    ) -> Result<TokenResponse, String> {
        let mut params = vec![
            ("grant_type".to_string(), "authorization_code".to_string()),
            ("code".to_string(), code.to_string()),
            (
                "redirect_uri".to_string(),
                self.provider.redirect_uri.clone(),
            ),
            ("client_id".to_string(), self.provider.client_id.clone()),
            ("code_verifier".to_string(), code_verifier.to_string()),
        ];
        let mut request = self
            .provider
            .http_client
            .get()
            .post(&discovery.token_endpoint)
            .timeout(Duration::from_secs(10));
        match &self.provider.client_auth {
            OidcClientAuth::Basic { client_secret } => {
                request =
                    request.basic_auth(&self.provider.client_id, Some(client_secret.expose()));
            }
            OidcClientAuth::Post { client_secret } => {
                params.push((
                    "client_secret".to_string(),
                    client_secret.expose().to_string(),
                ));
            }
            OidcClientAuth::PrivateKeyJwt {
                encoding_key,
                alg,
                kid,
            } => {
                let assertion = build_client_assertion(
                    &self.provider.client_id,
                    &discovery.token_endpoint,
                    encoding_key,
                    *alg,
                    kid,
                )?;
                params.push((
                    "client_assertion_type".to_string(),
                    "urn:ietf:params:oauth:client-assertion-type:jwt-bearer".to_string(),
                ));
                params.push(("client_assertion".to_string(), assertion));
            }
            OidcClientAuth::None => {}
        }
        let response = self
            .provider
            .http_client
            .execute(with_form_body(request, &params), "oidc_rp_token")
            .await
            .map_err(|_| r#"{"error":"Token exchange failed"}"#.to_string())?;
        if !response.status().is_success() {
            return Err(r#"{"error":"Token exchange failed"}"#.to_string());
        }
        let token: TokenResponse = response
            .json()
            .await
            .map_err(|_| r#"{"error":"Token response parse failed"}"#.to_string())?;
        if !token.token_type.eq_ignore_ascii_case("bearer") {
            return Err(r#"{"error":"Invalid token type"}"#.to_string());
        }
        Ok(token)
    }

    async fn verify_id_token(&self, id_token: &str, nonce: &str) -> Result<Value, String> {
        let guard = self.provider.jwks_store.load();
        let Some(store) = guard.as_ref().as_ref().cloned() else {
            return Err(r#"{"error":"JWKS unavailable"}"#.to_string());
        };
        if !store.has_keys() {
            store
                .fetch_keys_if_empty()
                .await
                .map_err(|_| r#"{"error":"JWKS unavailable"}"#.to_string())?;
        }
        let audiences = if self.provider.audiences.is_empty() {
            vec![self.provider.client_id.clone()]
        } else {
            self.provider.audiences.clone()
        };
        let Some(claims) = verify_jwt_with_jwks(
            id_token,
            &store,
            &JwtVerifyParams {
                issuer: Some(&self.provider.issuer),
                audiences: &audiences,
                require_exp: true,
                leeway_secs: self.provider.id_token_clock_skew.as_secs(),
                validate_nbf: false,
            },
        )
        .await
        else {
            return Err(r#"{"error":"Invalid ID token"}"#.to_string());
        };
        let token_nonce = claims
            .get("nonce")
            .and_then(Value::as_str)
            .ok_or_else(|| r#"{"error":"Invalid ID token nonce"}"#.to_string())?;
        if !constant_time_eq(token_nonce.as_bytes(), nonce.as_bytes()) {
            return Err(r#"{"error":"Invalid ID token nonce"}"#.to_string());
        }
        Ok(claims)
    }

    async fn fetch_userinfo(
        &self,
        endpoint: &str,
        access_token: &str,
    ) -> Result<Option<Value>, String> {
        let response = self
            .provider
            .http_client
            .execute(
                self.provider
                    .http_client
                    .get()
                    .get(endpoint)
                    .bearer_auth(access_token),
                "oidc_rp_userinfo",
            )
            .await
            .map_err(|error| format!("userinfo request failed: {error}"))?;
        if !response.status().is_success() {
            return Err(format!("userinfo returned HTTP {}", response.status()));
        }
        response
            .json()
            .await
            .map(Some)
            .map_err(|error| format!("userinfo parse failed: {error}"))
    }

    fn authenticate_session(
        &self,
        ctx: &mut RequestContext,
        consumer_index: &ConsumerIndex,
    ) -> PluginResult {
        let Some(cookie_value) = cookie_value(ctx, &self.session.cookie_name) else {
            return self.challenge(ctx, false);
        };
        let Some(payload) = self.open_session(cookie_value) else {
            return self.challenge(ctx, true);
        };
        let now = chrono::Utc::now().timestamp();
        if now > payload.issued_at_unix + self.session.ttl.as_secs() as i64
            || now > payload.last_touch_unix + self.session.idle_ttl.as_secs() as i64
        {
            return self.challenge(ctx, true);
        }
        if let Err((status, body)) = scope_role_check::check(
            &payload.claims,
            &ScopeRoleRequirements {
                required_scopes: &self.provider.required_scopes,
                required_roles: &self.provider.required_roles,
                scope_claim: &self.provider.scope_claim,
                role_claim: &self.provider.role_claim,
                plugin_name: "oidc_relying_party",
            },
        ) {
            return reject(status, body);
        }
        emit_claim_headers_to_metadata(ctx, &payload.claims, &self.provider.claim_headers, ",");
        let outcome = self.resolve_identity(&payload.claims, consumer_index);
        apply_verify_outcome(ctx, outcome)
    }

    fn resolve_identity(&self, claims: &Value, consumer_index: &ConsumerIndex) -> VerifyOutcome {
        let identity = extract_claim_string(claims, &self.provider.consumer_identity_claim);
        let header = if self.provider.consumer_header_claim == self.provider.consumer_identity_claim
        {
            identity.clone()
        } else {
            extract_claim_string(claims, &self.provider.consumer_header_claim)
                .or_else(|| identity.clone())
        };
        let consumer = identity
            .as_deref()
            .and_then(|id| consumer_index.find_by_identity(id));
        VerifyOutcome::success(consumer, identity, header)
    }

    fn challenge(&self, ctx: &mut RequestContext, clear: bool) -> PluginResult {
        if is_browser_request(ctx, &self.behavior) {
            let (state, flow) = match self.create_flow(ctx) {
                Ok(flow) => flow,
                Err(body) => return reject(503, body),
            };
            let location = self.authorization_url(&state, &flow);
            let cookie = clear.then(|| self.clear_cookie());
            redirect(self.behavior.challenge_html_status, &location, cookie)
        } else {
            let mut headers = HashMap::new();
            headers.insert(
                "www-authenticate".to_string(),
                r#"Bearer realm="oidc", error="invalid_token""#.to_string(),
            );
            if clear {
                headers.insert("set-cookie".to_string(), self.clear_cookie());
            }
            PluginResult::Reject {
                status_code: self.behavior.challenge_api_status,
                body: r#"{"error":"Authentication required"}"#.to_string(),
                headers,
            }
        }
    }

    fn create_flow(&self, ctx: &RequestContext) -> Result<(String, FlowState), String> {
        let state = random_b64(32)?;
        let code_verifier = random_b64(64)?;
        let nonce = random_b64(32)?;
        let original_url = original_url(ctx, &self.behavior);
        let flow = FlowState {
            code_verifier,
            nonce,
            original_url,
            expires_at: Instant::now() + self.behavior.state_ttl,
        };
        self.session
            .state_cache
            .insert(state.clone(), flow.clone())?;
        Ok((state, flow))
    }

    fn authorization_url(&self, state: &str, flow: &FlowState) -> String {
        let Some(discovery) = self.provider.discovery.load().as_ref().as_ref().cloned() else {
            return self.behavior.post_login_default_path.clone();
        };
        let challenge = pkce_challenge(&flow.code_verifier);
        let Ok(mut url) = Url::parse(&discovery.authorization_endpoint) else {
            return self.behavior.post_login_default_path.clone();
        };
        url.query_pairs_mut()
            .append_pair("response_type", "code")
            .append_pair("client_id", &self.provider.client_id)
            .append_pair("redirect_uri", &self.provider.redirect_uri)
            .append_pair("scope", &self.provider.scopes.join(" "))
            .append_pair("state", state)
            .append_pair("nonce", &flow.nonce)
            .append_pair("code_challenge", &challenge)
            .append_pair("code_challenge_method", "S256");
        url.to_string()
    }

    fn seal_session_cookie(&self, payload: &SessionPayload) -> Result<String, String> {
        let bytes = serde_json::to_vec(payload)
            .map_err(|_| r#"{"error":"Session creation failed"}"#.to_string())?;
        let estimated_cookie_value_len = encoded_session_cookie_len(bytes.len());
        if estimated_cookie_value_len.saturating_mul(4) >= self.session.max_cookie_bytes * 3 {
            warn!(
                plugin = "oidc_relying_party",
                estimated_cookie_value_len,
                max_cookie_bytes = self.session.max_cookie_bytes,
                "OIDC sealed session cookie is near max_cookie_bytes"
            );
        }
        let value = self.session.codec.seal(&bytes).map_err(|error| {
            warn!(
                plugin = "oidc_relying_party",
                error = %error,
                max_cookie_bytes = self.session.max_cookie_bytes,
                "OIDC sealed session cookie exceeded max_cookie_bytes"
            );
            r#"{"error":"Session creation failed"}"#.to_string()
        })?;
        Ok(format!(
            "{}={}; {}",
            self.session.cookie_name, value, self.session.cookie_attrs
        ))
    }

    fn open_session(&self, value: &str) -> Option<SessionPayload> {
        let bytes = self.session.codec.open(value)?;
        serde_json::from_slice(&bytes).ok()
    }

    fn clear_cookie(&self) -> String {
        format!(
            "{}=; Max-Age=0; {}",
            self.session.cookie_name, self.session.cookie_attrs
        )
    }

    fn sanitize_redirect(&self, original: &str) -> String {
        let Ok(parsed) = Url::parse(original) else {
            return self.behavior.post_login_default_path.clone();
        };
        let Some(host) = parsed.host_str() else {
            return self.behavior.post_login_default_path.clone();
        };
        if self
            .behavior
            .trusted_redirect_hosts
            .iter()
            .any(|trusted| trusted == host)
        {
            original.to_string()
        } else {
            self.behavior.post_login_default_path.clone()
        }
    }
}

#[async_trait]
impl super::Plugin for OidcRelyingParty {
    fn name(&self) -> &str {
        "oidc_relying_party"
    }
    fn is_auth_plugin(&self) -> bool {
        true
    }
    fn priority(&self) -> u16 {
        super::priority::OIDC_RELYING_PARTY
    }
    fn supported_protocols(&self) -> &'static [super::ProxyProtocol] {
        crate::plugins::HTTP_FAMILY_PROTOCOLS
    }
    async fn on_request_received(&self, ctx: &mut RequestContext) -> PluginResult {
        if ctx.path == self.provider.callback_path {
            self.handle_callback(ctx).await
        } else if ctx.path == self.provider.logout_path {
            let mut headers = HashMap::new();
            headers.insert("set-cookie".to_string(), self.clear_cookie());
            if self.behavior.rp_initiated_logout
                && let Some(discovery) = self.provider.discovery.load().as_ref().as_ref()
                && let Some(end_session) = &discovery.end_session_endpoint
            {
                let mut location = end_session.clone();
                if let Some(redirect_uri) = &self.provider.post_logout_redirect_uri
                    && let Ok(mut url) = Url::parse(end_session)
                {
                    url.query_pairs_mut()
                        .append_pair("post_logout_redirect_uri", redirect_uri)
                        .append_pair("client_id", &self.provider.client_id);
                    location = url.to_string();
                }
                headers.insert("location".to_string(), location);
                return PluginResult::Reject {
                    status_code: 302,
                    body: String::new(),
                    headers,
                };
            }
            PluginResult::Reject {
                status_code: 200,
                body: "<html><body>Logged out</body></html>".to_string(),
                headers,
            }
        } else {
            PluginResult::Continue
        }
    }
    async fn authenticate(
        &self,
        ctx: &mut RequestContext,
        consumer_index: &ConsumerIndex,
    ) -> PluginResult {
        self.authenticate_session(ctx, consumer_index)
    }
    fn modifies_request_headers(&self) -> bool {
        !self.provider.claim_headers.is_empty()
    }
    async fn before_proxy(
        &self,
        ctx: &mut RequestContext,
        headers: &mut HashMap<String, String>,
    ) -> PluginResult {
        apply_claim_headers_from_metadata(ctx, headers, CLAIM_HEADER_METADATA_PREFIX);
        PluginResult::Continue
    }
    fn warmup_hostnames(&self) -> Vec<String> {
        let mut hosts = self.provider.warmup_hostnames.clone();
        if let Some(discovery) = self.provider.discovery.load().as_ref().as_ref() {
            for url in [
                &discovery.authorization_endpoint,
                &discovery.token_endpoint,
                &discovery.jwks_uri,
            ] {
                if let Some(host) = hostname_from_url(url)
                    && !hosts.iter().any(|known| known == &host)
                {
                    hosts.push(host);
                }
            }
        }
        hosts
    }
    fn requires_decoded_query_params(&self) -> bool {
        true
    }
}

impl StateCache {
    fn new(max_entries: usize, ttl: Duration, shard_amount: usize) -> Self {
        Self {
            entries: DashMap::with_shard_amount(shard_amount),
            max_entries,
            ttl,
        }
    }
    fn insert(&self, state: String, flow: FlowState) -> Result<(), String> {
        self.evict_expired();
        if self.entries.len() >= self.max_entries {
            return Err(r#"{"error":"OIDC state cache full"}"#.to_string());
        }
        self.entries.insert(state, flow);
        Ok(())
    }
    fn take(&self, state: &str) -> Option<FlowState> {
        let (_, flow) = self.entries.remove(state)?;
        (flow.expires_at > Instant::now()).then_some(flow)
    }
    fn evict_expired(&self) {
        let now = Instant::now();
        self.entries.retain(|_, flow| flow.expires_at > now);
    }
}

trait PipeDefault {
    fn pipe_default(self, default: Vec<String>) -> Vec<String>;
}
impl PipeDefault for Vec<String> {
    fn pipe_default(self, default: Vec<String>) -> Vec<String> {
        if self.is_empty() { default } else { self }
    }
}

fn parse_client_auth(
    config: &Map<String, Value>,
    auth_endpoint: Option<&str>,
) -> Result<OidcClientAuth, String> {
    let auth = config
        .get("client_auth")
        .and_then(Value::as_object)
        .cloned()
        .unwrap_or_default();
    match auth
        .get("method")
        .and_then(Value::as_str)
        .unwrap_or("client_secret_basic")
    {
        "client_secret_basic" => Ok(OidcClientAuth::Basic {
            client_secret: SecretString(required_string(&auth, "client_secret", "client_auth")?),
        }),
        "client_secret_post" => Ok(OidcClientAuth::Post {
            client_secret: SecretString(required_string(&auth, "client_secret", "client_auth")?),
        }),
        "private_key_jwt" => {
            let pem = required_string(&auth, "private_key_pem", "client_auth")?;
            let alg = match auth
                .get("private_key_jwt_alg")
                .and_then(Value::as_str)
                .unwrap_or("RS256")
            {
                "RS256" => Algorithm::RS256,
                "RS384" => Algorithm::RS384,
                "RS512" => Algorithm::RS512,
                "ES256" => Algorithm::ES256,
                "ES384" => Algorithm::ES384,
                "EdDSA" => Algorithm::EdDSA,
                _ => return Err("oidc_relying_party: unsupported private_key_jwt_alg".to_string()),
            };
            let encoding_key = match alg {
                Algorithm::ES256 | Algorithm::ES384 => EncodingKey::from_ec_pem(pem.as_bytes())
                    .map_err(|e| format!("oidc_relying_party: invalid EC private key PEM: {e}"))?,
                Algorithm::EdDSA => EncodingKey::from_ed_pem(pem.as_bytes()).map_err(|e| {
                    format!("oidc_relying_party: invalid EdDSA private key PEM: {e}")
                })?,
                _ => EncodingKey::from_rsa_pem(pem.as_bytes())
                    .map_err(|e| format!("oidc_relying_party: invalid RSA private key PEM: {e}"))?,
            };
            let kid = auth
                .get("private_key_jwt_kid")
                .and_then(Value::as_str)
                .map(str::trim)
                .filter(|value| !value.is_empty())
                .map(ToOwned::to_owned);
            Ok(OidcClientAuth::PrivateKeyJwt {
                encoding_key,
                alg,
                kid,
            })
        }
        "none" => {
            if auth_endpoint.is_some_and(|url| {
                Url::parse(url)
                    .ok()
                    .and_then(|parsed| parsed.host_str().map(ToOwned::to_owned))
                    .is_none_or(|host| !is_local_auth_host(&host))
            }) {
                return Err(
                    "oidc_relying_party: client_auth.method='none' is only allowed for localhost or loopback token endpoints"
                        .to_string(),
                );
            }
            Ok(OidcClientAuth::None)
        }
        _ => Err("oidc_relying_party: unsupported client_auth.method".to_string()),
    }
}

fn build_client_assertion(
    client_id: &str,
    audience: &str,
    key: &EncodingKey,
    alg: Algorithm,
    kid: &Option<String>,
) -> Result<String, String> {
    let now = chrono::Utc::now().timestamp();
    let mut header = Header::new(alg);
    header.kid = kid.clone();
    encode(
        &header,
        &json!({
            "iss": client_id,
            "sub": client_id,
            "aud": audience,
            "iat": now,
            "exp": now + 300,
            "jti": uuid::Uuid::new_v4().to_string()
        }),
        key,
    )
    .map_err(|e| format!("oidc_relying_party: client assertion failed: {e}"))
}

fn with_form_body(
    builder: reqwest::RequestBuilder,
    params: &[(String, String)],
) -> reqwest::RequestBuilder {
    let mut serializer = url::form_urlencoded::Serializer::new(String::new());
    for (key, value) in params {
        serializer.append_pair(key, value);
    }
    builder
        .header("content-type", "application/x-www-form-urlencoded")
        .body(serializer.finish())
}

fn apply_verify_outcome(ctx: &mut RequestContext, outcome: VerifyOutcome) -> PluginResult {
    match outcome {
        VerifyOutcome::Success {
            consumer,
            external_identity,
            external_identity_header,
        } => {
            let consumer_identified = consumer.is_some();
            let external_identity_identified = external_identity.is_some();
            if let Some(consumer) = consumer
                && ctx.identified_consumer.is_none()
            {
                ctx.identified_consumer = Some(consumer);
            }
            if let Some(identity) = external_identity {
                ctx.authenticated_identity = Some(identity);
            }
            if let Some(header) = external_identity_header {
                ctx.authenticated_identity_header = Some(header);
            }
            if ctx.auth_method.is_none() && (consumer_identified || external_identity_identified) {
                ctx.auth_method = Some("oidc_relying_party");
            }
            PluginResult::Continue
        }
        VerifyOutcome::Forbidden(body) => reject(403, body),
        VerifyOutcome::Invalid(body)
        | VerifyOutcome::InvalidFormat(body)
        | VerifyOutcome::ConsumerNotFound(body)
        | VerifyOutcome::VerificationFailed(body) => reject(401, body),
        VerifyOutcome::Internal(body) => reject(500, body),
        VerifyOutcome::NotApplicable => PluginResult::Continue,
    }
}

fn required_string(
    config: &Map<String, Value>,
    field: &str,
    scope: &str,
) -> Result<String, String> {
    optional_string(config, field, scope)?
        .ok_or_else(|| format!("oidc_relying_party: {scope}.{field} is required"))
}

fn optional_string(
    config: &Map<String, Value>,
    field: &str,
    scope: &str,
) -> Result<Option<String>, String> {
    let Some(value) = config.get(field) else {
        return Ok(None);
    };
    if value.is_null() {
        return Ok(None);
    }
    let raw = value
        .as_str()
        .ok_or_else(|| format!("oidc_relying_party: {scope}.{field} must be a string"))?;
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return Err(format!(
            "oidc_relying_party: {scope}.{field} must not be empty"
        ));
    }
    Ok(Some(trimmed.to_string()))
}

fn optional_u64(config: &Map<String, Value>, field: &str, default: u64) -> Result<u64, String> {
    config
        .get(field)
        .map(|value| {
            value
                .as_u64()
                .ok_or_else(|| format!("oidc_relying_party: {field} must be an unsigned integer"))
        })
        .transpose()
        .map(|value| value.unwrap_or(default))
}

fn optional_bool(config: &Map<String, Value>, field: &str) -> Result<Option<bool>, String> {
    config
        .get(field)
        .map(|value| {
            value
                .as_bool()
                .ok_or_else(|| format!("oidc_relying_party: {field} must be a boolean"))
        })
        .transpose()
}

fn parse_string_array(
    config: &Map<String, Value>,
    field: &str,
    scope: &str,
) -> Result<Vec<String>, String> {
    let Some(value) = config.get(field) else {
        return Ok(Vec::new());
    };
    let arr = value
        .as_array()
        .ok_or_else(|| format!("oidc_relying_party: {scope}.{field} must be an array"))?;
    let mut values = Vec::with_capacity(arr.len());
    for (idx, item) in arr.iter().enumerate() {
        let raw = item.as_str().ok_or_else(|| {
            format!("oidc_relying_party: {scope}.{field}[{idx}] must be a string")
        })?;
        let trimmed = raw.trim();
        if trimmed.is_empty() {
            return Err(format!(
                "oidc_relying_party: {scope}.{field}[{idx}] must not be empty"
            ));
        }
        values.push(trimmed.to_string());
    }
    Ok(values)
}

fn optional_behavior_u64(
    config: Option<&Map<String, Value>>,
    field: &str,
    default: u64,
) -> Result<u64, String> {
    config
        .and_then(|cfg| cfg.get(field))
        .map(|value| {
            value.as_u64().ok_or_else(|| {
                format!("oidc_relying_party: behavior.{field} must be an unsigned integer")
            })
        })
        .transpose()
        .map(|value| value.unwrap_or(default))
}

fn optional_behavior_bool(
    config: Option<&Map<String, Value>>,
    field: &str,
) -> Result<Option<bool>, String> {
    config
        .and_then(|cfg| cfg.get(field))
        .map(|value| {
            value
                .as_bool()
                .ok_or_else(|| format!("oidc_relying_party: behavior.{field} must be a boolean"))
        })
        .transpose()
}

fn optional_behavior_string(
    config: Option<&Map<String, Value>>,
    field: &str,
) -> Result<Option<String>, String> {
    let Some(value) = config.and_then(|cfg| cfg.get(field)) else {
        return Ok(None);
    };
    if value.is_null() {
        return Ok(None);
    }
    let raw = value
        .as_str()
        .ok_or_else(|| format!("oidc_relying_party: behavior.{field} must be a string"))?;
    if raw.trim().is_empty() {
        return Err(format!(
            "oidc_relying_party: behavior.{field} must not be empty"
        ));
    }
    Ok(Some(raw.trim().to_string()))
}

fn parse_behavior_string_array(
    config: Option<&Map<String, Value>>,
    field: &str,
) -> Result<Vec<String>, String> {
    let Some(value) = config.and_then(|cfg| cfg.get(field)) else {
        return Ok(Vec::new());
    };
    let arr = value
        .as_array()
        .ok_or_else(|| format!("oidc_relying_party: behavior.{field} must be an array"))?;
    let mut values = Vec::with_capacity(arr.len());
    for item in arr {
        let raw = item.as_str().ok_or_else(|| {
            format!("oidc_relying_party: behavior.{field} entries must be strings")
        })?;
        if raw.trim().is_empty() || !raw.is_ascii() {
            return Err(format!(
                "oidc_relying_party: behavior.{field} entries must be non-empty ASCII"
            ));
        }
        values.push(raw.trim().to_string());
    }
    Ok(values)
}

fn parse_status(value: u64, allowed: &[u16], field: &str) -> Result<u16, String> {
    let status = u16::try_from(value)
        .map_err(|_| format!("oidc_relying_party: behavior.{field} is invalid"))?;
    if allowed.contains(&status) {
        Ok(status)
    } else {
        Err(format!("oidc_relying_party: behavior.{field} is invalid"))
    }
}

fn validate_redirect_uri(uri: &str) -> Result<(), String> {
    let parsed =
        Url::parse(uri).map_err(|e| format!("oidc_relying_party: redirect_uri invalid: {e}"))?;
    let host = parsed.host_str().unwrap_or_default();
    if parsed.scheme() != "https" && !matches!(host, "localhost" | "127.0.0.1" | "::1") {
        return Err("oidc_relying_party: redirect_uri must be https except localhost".to_string());
    }
    Ok(())
}

fn validate_url_string(raw: &str, field: &str) -> Result<String, String> {
    let parsed =
        Url::parse(raw).map_err(|e| format!("oidc_relying_party: {field} invalid: {e}"))?;
    match parsed.scheme() {
        "http" | "https" => {}
        scheme => {
            return Err(format!(
                "oidc_relying_party: {field} must use http or https, got {scheme}"
            ));
        }
    }
    if parsed.host_str().is_none() {
        return Err(format!(
            "oidc_relying_party: {field} must include a hostname"
        ));
    }
    Ok(raw.trim().to_string())
}

fn validate_discovered_url(discovery_url: &str, raw: &str, field: &str) -> Result<String, String> {
    let discovery = Url::parse(discovery_url)
        .map_err(|e| format!("oidc_relying_party: discovery_url invalid: {e}"))?;
    let parsed = Url::parse(raw)
        .map_err(|e| format!("oidc_relying_party: discovery {field} invalid: {e}"))?;
    match parsed.scheme() {
        "http" | "https" => {}
        scheme => {
            return Err(format!(
                "oidc_relying_party: discovery {field} must use http or https, got {scheme}"
            ));
        }
    }
    let discovery_host = discovery
        .host_str()
        .ok_or_else(|| "oidc_relying_party: discovery_url must include a hostname".to_string())?;
    let endpoint_host = parsed
        .host_str()
        .ok_or_else(|| format!("oidc_relying_party: discovery {field} must include a hostname"))?;
    if !endpoint_host.eq_ignore_ascii_case(discovery_host) {
        return Err(format!(
            "oidc_relying_party: discovery {field} host must match discovery_url host"
        ));
    }
    Ok(raw.trim().to_string())
}

fn is_local_auth_host(hostname: &str) -> bool {
    hostname.eq_ignore_ascii_case("localhost")
        || hostname
            .parse::<IpAddr>()
            .is_ok_and(|address| address.is_loopback())
}

fn validate_path_only(path: &str, field: &str) -> Result<(), String> {
    if !path.starts_with('/') || path.contains('?') || path.contains('#') {
        return Err(format!(
            "oidc_relying_party: provider[0].{field} must be a path-only value"
        ));
    }
    Ok(())
}

fn build_cookie_attrs(
    secure: bool,
    http_only: bool,
    same_site: &str,
    domain: Option<&str>,
    path: &str,
) -> String {
    let mut attrs = format!("Path={path}; SameSite={same_site}");
    if let Some(domain) = domain {
        attrs.push_str("; Domain=");
        attrs.push_str(domain);
    }
    if secure {
        attrs.push_str("; Secure");
    }
    if http_only {
        attrs.push_str("; HttpOnly");
    }
    attrs
}

fn encoded_session_cookie_len(plaintext_len: usize) -> usize {
    let sealed_len = 12 + plaintext_len + 16;
    sealed_len.div_ceil(3) * 4
}

fn is_browser_request(ctx: &RequestContext, behavior: &BehaviorConfig) -> bool {
    matches!(ctx.method.as_str(), "GET" | "HEAD")
        && ctx.headers.get("accept").is_some_and(|accept| {
            behavior
                .html_accept_substrings
                .iter()
                .any(|needle| accept.contains(needle))
        })
}

fn cookie_value<'a>(ctx: &'a RequestContext, name: &str) -> Option<&'a str> {
    let cookie = ctx.headers.get("cookie")?;
    for part in cookie.split(';') {
        let (cookie_name, value) = part.trim().split_once('=')?;
        if cookie_name == name {
            return Some(value);
        }
    }
    None
}

fn original_url(ctx: &RequestContext, behavior: &BehaviorConfig) -> String {
    if let Some(param) = &behavior.post_login_redirect_param
        && let Some(value) = ctx.query_params.get(param)
    {
        if value.starts_with('/') && !value.starts_with("//") {
            let scheme = frontend_scheme(ctx);
            let host = request_host(ctx);
            return format!("{scheme}://{host}{value}");
        }
        return value.clone();
    }
    let scheme = frontend_scheme(ctx);
    let host = request_host(ctx);
    format!("{scheme}://{host}{}", ctx.path)
}

fn frontend_scheme(ctx: &RequestContext) -> &str {
    ctx.metadata
        .get("ferrum.frontend_scheme")
        .map(String::as_str)
        .unwrap_or("http")
}

fn request_host(ctx: &RequestContext) -> &str {
    ctx.headers
        .get("host")
        .map(String::as_str)
        .unwrap_or("localhost")
}

fn random_b64(len: usize) -> Result<String, String> {
    let mut bytes = vec![0u8; len];
    SystemRandom::new()
        .fill(&mut bytes)
        .map_err(|_| r#"{"error":"Random generation failed"}"#.to_string())?;
    Ok(base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes))
}

fn pkce_challenge(verifier: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(verifier.as_bytes());
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(hasher.finalize())
}

fn merge_claims(
    id_claims: Value,
    userinfo: Value,
    provider: &ProviderRuntime,
) -> Result<Value, String> {
    let protected = protected_userinfo_claim_keys(provider);
    merge_claims_with_protected_keys(id_claims, userinfo, &protected)
}

fn merge_claims_with_protected_keys(
    mut id_claims: Value,
    userinfo: Value,
    protected: &HashSet<&str>,
) -> Result<Value, String> {
    if let Some(userinfo_sub) = userinfo.get("sub").and_then(Value::as_str) {
        let Some(id_sub) = id_claims.get("sub").and_then(Value::as_str) else {
            return Err(r#"{"error":"Userinfo subject mismatch"}"#.to_string());
        };
        if !constant_time_eq(id_sub.as_bytes(), userinfo_sub.as_bytes()) {
            return Err(r#"{"error":"Userinfo subject mismatch"}"#.to_string());
        }
    }
    if let (Some(id), Some(userinfo)) = (id_claims.as_object_mut(), userinfo.as_object()) {
        for (key, value) in userinfo {
            if protected.contains(key.as_str()) {
                continue;
            }
            id.insert(key.clone(), value.clone());
        }
    }
    Ok(id_claims)
}

fn protected_userinfo_claim_keys(provider: &ProviderRuntime) -> HashSet<&str> {
    let mut keys = HashSet::from([
        "iss",
        "sub",
        "aud",
        "exp",
        "iat",
        "nbf",
        "nonce",
        "auth_time",
        "azp",
        "at_hash",
        "c_hash",
    ]);
    keys.insert(top_level_claim_key(&provider.scope_claim));
    keys.insert(top_level_claim_key(&provider.role_claim));
    keys.insert(top_level_claim_key(&provider.consumer_identity_claim));
    keys.insert(top_level_claim_key(&provider.consumer_header_claim));
    keys
}

fn top_level_claim_key(path: &str) -> &str {
    path.split(['.', '[']).next().unwrap_or(path)
}

fn redirect(status_code: u16, location: &str, set_cookie: Option<String>) -> PluginResult {
    let mut headers = HashMap::from([
        ("location".to_string(), location.to_string()),
        ("cache-control".to_string(), "no-store".to_string()),
    ]);
    if let Some(cookie) = set_cookie {
        headers.insert("set-cookie".to_string(), cookie);
    }
    PluginResult::Reject {
        status_code,
        body: String::new(),
        headers,
    }
}

fn reject(status_code: u16, body: String) -> PluginResult {
    PluginResult::Reject {
        status_code,
        body,
        headers: HashMap::new(),
    }
}

fn hostname_from_url(url: &str) -> Option<String> {
    let parsed = Url::parse(url).ok()?;
    Some(match parsed.host()? {
        Host::Domain(hostname) => hostname.to_string(),
        Host::Ipv4(address) => address.to_string(),
        Host::Ipv6(address) => address.to_string(),
    })
}

fn escape_json(value: &str) -> String {
    value.replace('\\', "\\\\").replace('"', "\\\"")
}

fn spawn_oidc_discovery(
    discovery_slot: Arc<ArcSwap<Option<DiscoveryDoc>>>,
    jwks_slot: Arc<ArcSwap<Option<Arc<JwksKeyStore>>>>,
    http_client: PluginHttpClient,
    discovery_url: String,
) {
    tokio::spawn(async move {
        const INITIAL_BACKOFF_SECS: u64 = 2;
        const MAX_BACKOFF_SECS: u64 = 300;
        let mut attempt: u32 = 0;
        loop {
            if attempt > 0 {
                let backoff = Duration::from_secs(
                    INITIAL_BACKOFF_SECS
                        .saturating_mul(1u64 << (attempt - 1).min(7))
                        .min(MAX_BACKOFF_SECS),
                );
                tokio::time::sleep(backoff).await;
            }
            match fetch_discovery(&http_client, &discovery_url).await {
                Ok(doc) => {
                    let store = get_or_create_jwks_store(
                        &doc.jwks_uri,
                        &http_client,
                        DEFAULT_JWKS_REFRESH_INTERVAL,
                    );
                    jwks_slot.store(Arc::new(Some(store)));
                    discovery_slot.store(Arc::new(Some(doc)));
                    info!(
                        plugin = "oidc_relying_party",
                        "OIDC discovery resolved endpoints"
                    );
                    return;
                }
                Err(error) => {
                    warn!(plugin = "oidc_relying_party", error = %error, "OIDC discovery failed");
                    attempt = attempt.saturating_add(1);
                }
            }
        }
    });
}

async fn fetch_discovery(
    http_client: &PluginHttpClient,
    discovery_url: &str,
) -> Result<DiscoveryDoc, String> {
    let response = http_client
        .execute(http_client.get().get(discovery_url), "oidc_rp_discovery")
        .await
        .map_err(|e| format!("discovery request failed: {e}"))?;
    if !response.status().is_success() {
        return Err(format!("discovery returned HTTP {}", response.status()));
    }
    let body: Value = response
        .json()
        .await
        .map_err(|e| format!("discovery parse failed: {e}"))?;
    let authorization_endpoint = body
        .get("authorization_endpoint")
        .and_then(Value::as_str)
        .ok_or_else(|| "missing authorization_endpoint".to_string())
        .and_then(|url| validate_discovered_url(discovery_url, url, "authorization_endpoint"))?;
    let token_endpoint = body
        .get("token_endpoint")
        .and_then(Value::as_str)
        .ok_or_else(|| "missing token_endpoint".to_string())
        .and_then(|url| validate_discovered_url(discovery_url, url, "token_endpoint"))?;
    let userinfo_endpoint = body
        .get("userinfo_endpoint")
        .and_then(Value::as_str)
        .map(|url| validate_discovered_url(discovery_url, url, "userinfo_endpoint"))
        .transpose()?;
    let jwks_uri = body
        .get("jwks_uri")
        .and_then(Value::as_str)
        .ok_or_else(|| "missing jwks_uri".to_string())
        .and_then(|url| validate_discovered_url(discovery_url, url, "jwks_uri"))?;
    let end_session_endpoint = body
        .get("end_session_endpoint")
        .and_then(Value::as_str)
        .map(|url| validate_discovered_url(discovery_url, url, "end_session_endpoint"))
        .transpose()?;
    Ok(DiscoveryDoc {
        authorization_endpoint,
        token_endpoint,
        userinfo_endpoint,
        jwks_uri,
        end_session_endpoint,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn userinfo_cannot_override_reserved_id_token_claims() {
        let protected = HashSet::from(["sub", "iss", "scope", "roles"]);
        let merged = merge_claims_with_protected_keys(
            json!({
                "sub": "user-1",
                "iss": "https://issuer.example.com",
                "scope": "read",
                "roles": ["admin"],
                "email": "old@example.com"
            }),
            json!({
                "sub": "user-1",
                "iss": "https://evil.example.com",
                "scope": "admin",
                "roles": ["root"],
                "email": "new@example.com"
            }),
            &protected,
        )
        .expect("matching sub should merge");

        assert_eq!(merged["sub"], "user-1");
        assert_eq!(merged["iss"], "https://issuer.example.com");
        assert_eq!(merged["scope"], "read");
        assert_eq!(merged["roles"], json!(["admin"]));
        assert_eq!(merged["email"], "new@example.com");
    }

    #[test]
    fn userinfo_sub_must_match_id_token_sub() {
        let protected = HashSet::from(["sub"]);
        assert!(
            merge_claims_with_protected_keys(
                json!({"sub": "user-1"}),
                json!({"sub": "user-2"}),
                &protected,
            )
            .is_err()
        );
    }

    #[test]
    fn discovered_urls_must_stay_on_discovery_host() {
        assert!(
            validate_discovered_url(
                "https://issuer.example.com/.well-known/openid-configuration",
                "https://evil.example.com/token",
                "token_endpoint",
            )
            .is_err()
        );
        assert!(
            validate_discovered_url(
                "https://issuer.example.com/.well-known/openid-configuration",
                "file:///etc/passwd",
                "jwks_uri",
            )
            .is_err()
        );
    }

    #[test]
    fn path_relative_redirect_param_resolves_against_current_host() {
        let behavior = BehaviorConfig {
            challenge_html_status: 302,
            challenge_api_status: 401,
            html_accept_substrings: vec!["text/html".to_string()],
            state_ttl: Duration::from_secs(600),
            refresh_skew: Duration::from_secs(30),
            rp_initiated_logout: true,
            post_login_redirect_param: Some("rd".to_string()),
            post_login_default_path: "/".to_string(),
            trusted_redirect_hosts: vec!["app.example.com".to_string()],
        };
        let mut ctx = RequestContext::new("127.0.0.1".into(), "GET".into(), "/login".into());
        ctx.headers
            .insert("host".to_string(), "app.example.com".to_string());
        ctx.metadata
            .insert("ferrum.frontend_scheme".to_string(), "https".to_string());
        ctx.query_params
            .insert("rd".to_string(), "/protected".to_string());
        assert_eq!(
            original_url(&ctx, &behavior),
            "https://app.example.com/protected"
        );
    }
}
