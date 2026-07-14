use std::collections::{HashMap, HashSet};
use std::fmt;
use std::net::IpAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
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
    ClaimHeaderMapping, apply_claim_headers_from_context, emit_claim_headers_to_context,
    parse_claim_headers,
};
use super::utils::claim_resolver::extract_claim_string;
use super::utils::jwks_cache::get_or_create_jwks_store;
use super::utils::jwks_store::JwksKeyStore;
use super::utils::jwt_verifier::{JwtVerifyParams, verify_jwt_with_jwks};
use super::utils::response_body::read_response_body_bounded;
use super::utils::scope_role_check::{self, ScopeRoleRequirements};
use super::{PluginResult, RequestContext};

const CLAIM_HEADER_METADATA_PREFIX: &str = "oidc_rp.claim_header.";
const DEFAULT_JWKS_REFRESH_INTERVAL: Duration = Duration::from_secs(900);
const DEFAULT_ID_TOKEN_CLOCK_SKEW_SECS: u64 = 60;
const DEFAULT_SESSION_TTL_SECS: u64 = 3600;
const DEFAULT_SESSION_IDLE_TTL_SECS: u64 = 1800;
const DEFAULT_SESSION_MAX_COOKIE_BYTES: u64 = 8000;
const DEFAULT_STATE_TTL_SECS: u64 = 600;
const DEFAULT_STATE_CACHE_MAX_ENTRIES: usize = 10_000;
const DEFAULT_STATE_CACHE_MAX_ENTRIES_PER_SOURCE: usize = 32;
const DEFAULT_REFRESH_SKEW_SECS: u64 = 30;
const DEFAULT_CHALLENGE_HTML_STATUS: u64 = 302;
const DEFAULT_CHALLENGE_API_STATUS: u64 = 401;
const MAX_STATE_TTL_SECS: u64 = 3600;
const STATE_EXPIRY_BUCKET_SECS: u64 = 1;
const SESSION_PAYLOAD_VERSION: u8 = 2;
const MAX_TOKEN_RESPONSE_BYTES: usize = 256 * 1024;
const MAX_USERINFO_RESPONSE_BYTES: usize = 256 * 1024;
const MAX_DISCOVERY_RESPONSE_BYTES: usize = 256 * 1024;
const CONFIG_FIELDS: &[&str] = &["providers", "session", "behavior"];
const PROVIDER_FIELDS: &[&str] = &[
    "issuer",
    "discovery_url",
    "authorization_endpoint",
    "token_endpoint",
    "userinfo_endpoint",
    "jwks_uri",
    "end_session_endpoint",
    "client_id",
    "client_auth",
    "redirect_uri",
    "callback_path",
    "logout_path",
    "post_logout_redirect_uri",
    "scopes",
    "audiences",
    "required_scopes",
    "required_roles",
    "scope_claim",
    "role_claim",
    "consumer_identity_claim",
    "consumer_header_claim",
    "claim_headers",
    "id_token_clock_skew_secs",
];
const CLIENT_AUTH_FIELDS: &[&str] = &[
    "method",
    "client_secret",
    "private_key_pem",
    "private_key_jwt_alg",
    "private_key_jwt_kid",
];
const SESSION_FIELDS: &[&str] = &[
    "encryption_secret",
    "encryption_secret_previous",
    "cookie_name",
    "store",
    "ttl_secs",
    "idle_ttl_secs",
    "max_cookie_bytes",
    "secure",
    "http_only",
    "same_site",
    "domain",
    "path",
];
const BEHAVIOR_FIELDS: &[&str] = &[
    "state_ttl_secs",
    "state_cache_max_entries",
    "state_cache_max_entries_per_source",
    "post_login_redirect_param",
    "trusted_redirect_hosts",
    "refresh_skew_secs",
    "challenge_html_status",
    "challenge_api_status",
    "html_accept_substrings",
    "rp_initiated_logout",
    "post_login_default_path",
];
/// Carries a re-sealed rolling-session cookie from `authenticate` to
/// `after_proxy`, which appends it as `Set-Cookie` on the proxied response. The
/// key contains "cookie" so transaction-log metadata redaction masks its value.
const SESSION_SET_COOKIE_METADATA_KEY: &str = "oidc_rp.session_set_cookie";
/// On refresh failure, defer the next attempt by this many seconds so a flaky
/// token endpoint is not retried on every request until the session reaches its
/// ttl/idle bound.
const REFRESH_RETRY_BACKOFF_SECS: i64 = 30;

pub struct OidcRelyingParty {
    provider: Arc<ProviderRuntime>,
    session: Arc<SessionRuntime>,
    behavior: Arc<BehaviorConfig>,
    discovery_task: Option<tokio::task::JoinHandle<()>>,
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
    context_id: String,
    correlation_cookie_name_prefix: String,
    correlation_cookie_attrs: String,
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
    browser_binding_hash: [u8; 32],
    source_ip: String,
    expires_at: Instant,
}

struct StateCache {
    entries: DashMap<String, FlowState>,
    expiry_buckets: DashMap<u64, Arc<DashMap<String, ()>>>,
    per_source_entries: DashMap<String, usize>,
    active_entries: AtomicUsize,
    last_evicted_bucket: AtomicU64,
    origin: Instant,
    max_entries: usize,
    max_entries_per_source: usize,
    shard_amount: usize,
    ttl: Duration,
}

#[derive(Clone, Serialize, Deserialize)]
struct SessionPayload {
    version: u8,
    #[serde(default)]
    context_id: String,
    sub: String,
    id_token_b64: String,
    access_token_b64: String,
    refresh_token_b64: Option<String>,
    expires_at_unix: i64,
    #[serde(default)]
    claims_expires_at_unix: i64,
    refresh_after_unix: i64,
    issued_at_unix: i64,
    last_touch_unix: i64,
    nonce: String,
    claims: Value,
}

#[derive(Serialize)]
struct NormalizedSessionContextSeed {
    version: u8,
    provider: NormalizedProviderContext,
    session: NormalizedSessionContext,
    behavior: NormalizedBehaviorContext,
}

#[derive(Serialize)]
struct NormalizedProviderContext {
    issuer: String,
    discovery_url: Option<String>,
    authorization_endpoint: Option<String>,
    token_endpoint: Option<String>,
    userinfo_endpoint: Option<String>,
    jwks_uri: Option<String>,
    end_session_endpoint: Option<String>,
    client_id: String,
    client_auth: NormalizedClientAuthContext,
    redirect_uri: String,
    callback_path: String,
    logout_path: String,
    post_logout_redirect_uri: Option<String>,
    scopes: Vec<String>,
    audiences: Vec<String>,
    required_scopes: Vec<String>,
    required_roles: Vec<String>,
    scope_claim: String,
    role_claim: String,
    consumer_identity_claim: String,
    consumer_header_claim: String,
    claim_headers: Vec<NormalizedClaimHeaderContext>,
    id_token_clock_skew_secs: u64,
}

#[derive(Serialize)]
struct NormalizedClientAuthContext {
    method: String,
    private_key_jwt_alg: Option<String>,
    private_key_jwt_kid: Option<String>,
}

#[derive(Serialize)]
struct NormalizedClaimHeaderContext {
    claim_path: String,
    metadata_key: String,
}

#[derive(Serialize)]
struct NormalizedSessionContext {
    store: String,
    ttl_secs: u64,
    idle_ttl_secs: u64,
    max_cookie_bytes: u64,
    secure: bool,
    http_only: bool,
    same_site: String,
    domain: Option<String>,
    path: String,
}

#[derive(Serialize)]
struct NormalizedBehaviorContext {
    state_ttl_secs: u64,
    state_cache_max_entries: u64,
    state_cache_max_entries_per_source: u64,
    post_login_redirect_param: Option<String>,
    trusted_redirect_hosts: Vec<String>,
    refresh_skew_secs: u64,
    challenge_html_status: u64,
    challenge_api_status: u64,
    html_accept_substrings: Vec<String>,
    rp_initiated_logout: bool,
    post_login_default_path: String,
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

/// Token endpoint response for `grant_type=refresh_token`. Unlike the
/// authorization-code response, the `id_token` is optional (OIDC Core 12.2: a
/// provider MAY omit it) and a rotated `refresh_token` MAY be returned.
#[derive(Deserialize)]
struct RefreshTokenResponse {
    access_token: String,
    #[serde(default)]
    id_token: Option<String>,
    token_type: String,
    #[serde(default)]
    refresh_token: Option<String>,
    #[serde(default)]
    expires_in: Option<i64>,
}

/// Result of a `maybe_refresh_session` attempt. `mutated` drives cookie re-sealing;
/// `refreshed` is true only when the token endpoint returned and we validated a
/// fresh ID token, so the freshness gate can tell fresh claims apart from access
/// token rotation, a deferred failure, or the no-refresh-token / not-yet-due
/// cases (all of which leave claims stale).
#[derive(Clone, Copy)]
struct RefreshOutcome {
    mutated: bool,
    refreshed: bool,
}

impl RefreshOutcome {
    const UNCHANGED: Self = Self {
        mutated: false,
        refreshed: false,
    };
}

impl OidcRelyingParty {
    pub fn new(config: &Value, http_client: PluginHttpClient) -> Result<Self, String> {
        Self::new_internal(config, http_client, true)
    }

    pub(crate) fn validate_config(
        config: &Value,
        http_client: PluginHttpClient,
    ) -> Result<(), String> {
        Self::new_internal(config, http_client, false).map(drop)
    }

    fn new_internal(
        config: &Value,
        http_client: PluginHttpClient,
        start_background_tasks: bool,
    ) -> Result<Self, String> {
        let config_obj = config.as_object().ok_or_else(|| {
            format!("oidc_relying_party: config must be an object, got: {config}")
        })?;
        reject_unknown_fields(config_obj, CONFIG_FIELDS, "config")?;
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
        reject_unknown_fields(provider_obj, PROVIDER_FIELDS, "provider[0]")?;
        let session_obj = config_obj
            .get("session")
            .and_then(Value::as_object)
            .ok_or_else(|| "oidc_relying_party: 'session' object is required".to_string())?;
        reject_unknown_fields(session_obj, SESSION_FIELDS, "session")?;
        let behavior_obj = match config_obj.get("behavior") {
            Some(Value::Null) | None => None,
            Some(value) => Some(
                value
                    .as_object()
                    .ok_or_else(|| "oidc_relying_party: behavior must be an object".to_string())?,
            ),
        };
        if let Some(behavior_obj) = behavior_obj {
            reject_unknown_fields(behavior_obj, BEHAVIOR_FIELDS, "behavior")?;
        }
        if let Some(client_auth) = provider_obj.get("client_auth") {
            let client_auth = client_auth.as_object().ok_or_else(|| {
                "oidc_relying_party: provider[0].client_auth must be an object".to_string()
            })?;
            reject_unknown_fields(client_auth, CLIENT_AUTH_FIELDS, "provider[0].client_auth")?;
        }

        let issuer = validate_url_string(
            &required_string(provider_obj, "issuer", "provider[0]")?,
            "provider[0].issuer",
        )?;
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

        let context_seed = session_context_seed(provider_obj, session_obj, behavior_obj)?;
        let cookie_name = optional_string(session_obj, "cookie_name", "session")?
            .unwrap_or_else(|| derived_cookie_name("ferrum_session", &context_seed));
        let session_context = session_context_id(&context_seed, &cookie_name);
        let session_context_id =
            base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(session_context);
        let mut session_aad = b"ferrum-edge/oidc-session/v2\0".to_vec();
        session_aad.extend_from_slice(&session_context);
        let correlation_cookie_name_prefix =
            derived_cookie_name("ferrum_oidc_state", &session_context);
        let store = optional_string(session_obj, "store", "session")?
            .unwrap_or_else(|| "cookie".to_string());
        if store != "cookie" {
            return Err("oidc_relying_party: session.store must be 'cookie'".to_string());
        }
        let encryption_secret = required_string(session_obj, "encryption_secret", "session")?;
        let previous_secret =
            optional_string(session_obj, "encryption_secret_previous", "session")?;
        let ttl_secs = optional_u64(session_obj, "ttl_secs", DEFAULT_SESSION_TTL_SECS)?;
        let idle_ttl_secs =
            optional_u64(session_obj, "idle_ttl_secs", DEFAULT_SESSION_IDLE_TTL_SECS)?;
        let max_cookie_bytes = optional_u64(
            session_obj,
            "max_cookie_bytes",
            DEFAULT_SESSION_MAX_COOKIE_BYTES,
        )?;
        if max_cookie_bytes > DEFAULT_SESSION_MAX_COOKIE_BYTES {
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
        let state_ttl = Duration::from_secs(optional_behavior_u64(
            behavior_obj,
            "state_ttl_secs",
            DEFAULT_STATE_TTL_SECS,
        )?);
        if state_ttl.is_zero() {
            return Err(
                "oidc_relying_party: behavior.state_ttl_secs must be greater than zero".to_string(),
            );
        }
        if state_ttl.as_secs() > MAX_STATE_TTL_SECS {
            return Err(format!(
                "oidc_relying_party: behavior.state_ttl_secs must be <= {MAX_STATE_TTL_SECS}"
            ));
        }
        let state_cache_max_entries = behavior_usize(
            behavior_obj,
            "state_cache_max_entries",
            DEFAULT_STATE_CACHE_MAX_ENTRIES,
        )?;
        let state_cache_max_entries_per_source = behavior_usize(
            behavior_obj,
            "state_cache_max_entries_per_source",
            DEFAULT_STATE_CACHE_MAX_ENTRIES_PER_SOURCE,
        )?;
        if state_cache_max_entries_per_source > state_cache_max_entries {
            return Err(
                "oidc_relying_party: behavior.state_cache_max_entries_per_source must not exceed state_cache_max_entries"
                    .to_string(),
            );
        }
        let session = Arc::new(SessionRuntime {
            codec: super::utils::session_cookie::SessionCookieCodec::new_with_aad(
                &encryption_secret,
                previous_secret.as_deref(),
                max_cookie_bytes as usize,
                &session_aad,
            )?,
            cookie_name,
            cookie_attrs,
            context_id: session_context_id,
            correlation_cookie_name_prefix,
            correlation_cookie_attrs: build_cookie_attrs(
                secure,
                true,
                "Lax",
                domain.as_deref(),
                &callback_path,
            ),
            max_cookie_bytes: max_cookie_bytes as usize,
            ttl: Duration::from_secs(ttl_secs),
            idle_ttl: Duration::from_secs(idle_ttl_secs),
            state_cache: Arc::new(StateCache::new(
                state_cache_max_entries,
                state_cache_max_entries_per_source,
                state_ttl,
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
        let refresh_skew_secs =
            optional_behavior_u64(behavior_obj, "refresh_skew_secs", DEFAULT_REFRESH_SKEW_SECS)?;
        if refresh_skew_secs > ttl_secs / 2 {
            return Err(
                "oidc_relying_party: behavior.refresh_skew_secs must be <= session.ttl_secs / 2"
                    .to_string(),
            );
        }

        let behavior = Arc::new(BehaviorConfig {
            challenge_html_status: parse_status(
                optional_behavior_u64(
                    behavior_obj,
                    "challenge_html_status",
                    DEFAULT_CHALLENGE_HTML_STATUS,
                )?,
                &[302, 303, 307],
                "challenge_html_status",
            )?,
            challenge_api_status: parse_status(
                optional_behavior_u64(
                    behavior_obj,
                    "challenge_api_status",
                    DEFAULT_CHALLENGE_API_STATUS,
                )?,
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
        // Validate like the other endpoint fields so a malformed or insecure
        // value is rejected at config load instead of being forwarded to the
        // IdP and browser at logout. Do this before starting runtime workers so
        // rejected plugin configs have no background side effects.
        let post_logout_redirect_uri =
            optional_string(provider_obj, "post_logout_redirect_uri", "provider[0]")?
                .map(|url| validate_url_string(&url, "provider[0].post_logout_redirect_uri"))
                .transpose()?;
        let initial_jwks_store = if start_background_tasks {
            jwks_uri.as_ref().map(|uri| {
                get_or_create_jwks_store(uri, &http_client, DEFAULT_JWKS_REFRESH_INTERVAL)
            })
        } else {
            None
        };
        let jwks_store = Arc::new(ArcSwap::from_pointee(initial_jwks_store));
        let discovery_task = if start_background_tasks {
            discovery_url.clone().map(|url| {
                spawn_oidc_discovery(
                    discovery.clone(),
                    jwks_store.clone(),
                    http_client.clone(),
                    url,
                )
            })
        } else {
            None
        };

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
            post_logout_redirect_uri,
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
                DEFAULT_ID_TOKEN_CLOCK_SKEW_SECS,
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
            discovery_task,
        })
    }

    async fn handle_callback(&self, ctx: &mut RequestContext) -> PluginResult {
        let Some(state) = ctx.query_params.get("state").cloned() else {
            return self.callback_reject(400, r#"{"error":"Missing state"}"#.to_string(), None);
        };
        let correlation_cookie_name = self.correlation_cookie_name(&state);
        let Some(browser_binding) = cookie_value(ctx, &correlation_cookie_name) else {
            return self.callback_reject(
                400,
                r#"{"error":"Invalid state"}"#.to_string(),
                Some(&state),
            );
        };
        let browser_binding_hash: [u8; 32] = Sha256::digest(browser_binding.as_bytes()).into();
        let Some(flow) = self
            .session
            .state_cache
            .take_bound(&state, &browser_binding_hash)
        else {
            return self.callback_reject(
                400,
                r#"{"error":"Invalid state"}"#.to_string(),
                Some(&state),
            );
        };
        if let Some(error) = ctx.query_params.get("error") {
            return self.callback_reject(400, json!({"error": error}).to_string(), Some(&state));
        };
        let Some(code) = ctx.query_params.get("code").cloned() else {
            return self.callback_reject(
                400,
                r#"{"error":"Missing code"}"#.to_string(),
                Some(&state),
            );
        };
        let Some(discovery) = self.provider.discovery.load().as_ref().as_ref().cloned() else {
            return self.callback_reject(
                400,
                r#"{"error":"OIDC discovery unavailable"}"#.to_string(),
                Some(&state),
            );
        };
        let token = match self
            .exchange_code(&discovery, &code, &flow.code_verifier)
            .await
        {
            Ok(token) => token,
            Err(body) => return self.callback_reject(400, body, Some(&state)),
        };
        let claims = match self.verify_id_token(&token.id_token, &flow.nonce).await {
            Ok(claims) => claims,
            Err(body) => return self.callback_reject(400, body, Some(&state)),
        };
        let merged_claims = if let Some(userinfo_endpoint) = &discovery.userinfo_endpoint {
            match self
                .fetch_userinfo(userinfo_endpoint, &token.access_token)
                .await
            {
                Ok(Some(userinfo)) => {
                    match merge_claims(claims.clone(), userinfo, &self.provider) {
                        Ok(claims) => claims,
                        Err(body) => return self.callback_reject(400, body, Some(&state)),
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
        let claims_expires_at = claim_expiry(&merged_claims).unwrap_or(expires_at);
        let Ok(sub) = required_subject(&merged_claims, "ID token") else {
            return self.callback_reject(
                400,
                r#"{"error":"Invalid ID token"}"#.to_string(),
                Some(&state),
            );
        };
        let payload = SessionPayload {
            version: SESSION_PAYLOAD_VERSION,
            context_id: self.session.context_id.clone(),
            sub: sub.to_string(),
            id_token_b64: token.id_token,
            access_token_b64: token.access_token,
            refresh_token_b64: token.refresh_token,
            expires_at_unix: expires_at,
            claims_expires_at_unix: claims_expires_at,
            refresh_after_unix: next_refresh_after(
                expires_at.min(claims_expires_at),
                now,
                self.behavior.refresh_skew.as_secs() as i64,
            ),
            issued_at_unix: now,
            last_touch_unix: now,
            nonce: flow.nonce,
            claims: merged_claims,
        };
        let cookie = match self.seal_session_cookie(&payload) {
            Ok(cookie) => cookie,
            Err(body) => return self.callback_reject(400, body, Some(&state)),
        };
        redirect(
            302,
            &self.sanitize_redirect(&flow.original_url),
            Some(join_set_cookies(
                cookie,
                self.clear_correlation_cookie(&state),
            )),
        )
    }

    async fn exchange_code(
        &self,
        discovery: &DiscoveryDoc,
        code: &str,
        code_verifier: &str,
    ) -> Result<TokenResponse, String> {
        let params = vec![
            ("grant_type".to_string(), "authorization_code".to_string()),
            ("code".to_string(), code.to_string()),
            (
                "redirect_uri".to_string(),
                self.provider.redirect_uri.clone(),
            ),
            ("client_id".to_string(), self.provider.client_id.clone()),
            ("code_verifier".to_string(), code_verifier.to_string()),
        ];
        let response = self
            .post_token_endpoint(&discovery.token_endpoint, params)
            .await
            .map_err(|_| r#"{"error":"Token exchange failed"}"#.to_string())?;
        if !response.status().is_success() {
            return Err(r#"{"error":"Token exchange failed"}"#.to_string());
        }
        let token: TokenResponse = read_bounded_json(response, MAX_TOKEN_RESPONSE_BYTES)
            .await
            .map_err(|_| r#"{"error":"Token response parse failed"}"#.to_string())?;
        if !token.token_type.eq_ignore_ascii_case("bearer") {
            return Err(r#"{"error":"Invalid token type"}"#.to_string());
        }
        Ok(token)
    }

    /// POST `application/x-www-form-urlencoded` `params` to the token endpoint,
    /// applying the configured client authentication. Shared by the
    /// authorization-code exchange and the refresh-token grant so both stay in
    /// lockstep on client-auth handling.
    async fn post_token_endpoint(
        &self,
        token_endpoint: &str,
        mut params: Vec<(String, String)>,
    ) -> Result<reqwest::Response, String> {
        let mut request = self
            .provider
            .http_client
            .get()
            .post(token_endpoint)
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
                    token_endpoint,
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
        self.provider
            .http_client
            .execute(with_form_body(request, &params), "oidc_rp_token")
            .await
            .map_err(|_| r#"{"error":"Token endpoint request failed"}"#.to_string())
    }

    /// Validate an ID token's signature and `iss`/`aud`/`exp` against the
    /// provider JWKS. Nonce and subject binding are layered on by the callers.
    async fn verify_id_token_jwks(&self, id_token: &str) -> Result<Value, String> {
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
        let mut audiences = self.provider.audiences.clone();
        if !audiences
            .iter()
            .any(|audience| audience == &self.provider.client_id)
        {
            audiences.push(self.provider.client_id.clone());
        }
        let claims = verify_jwt_with_jwks(
            id_token,
            &store,
            &JwtVerifyParams {
                issuer: Some(&self.provider.issuer),
                audiences: &audiences,
                require_exp: true,
                leeway_secs: self.provider.id_token_clock_skew.as_secs(),
                validate_nbf: true,
            },
        )
        .await
        .ok_or_else(|| r#"{"error":"Invalid ID token"}"#.to_string())?;
        validate_oidc_audience_and_azp(
            &claims,
            &self.provider.client_id,
            &self.provider.audiences,
        )?;
        Ok(claims)
    }

    async fn verify_id_token(&self, id_token: &str, nonce: &str) -> Result<Value, String> {
        let claims = self.verify_id_token_jwks(id_token).await?;
        required_subject(&claims, "ID token")?;
        let token_nonce = claims
            .get("nonce")
            .and_then(Value::as_str)
            .ok_or_else(|| r#"{"error":"Invalid ID token nonce"}"#.to_string())?;
        if !constant_time_eq(token_nonce.as_bytes(), nonce.as_bytes()) {
            return Err(r#"{"error":"Invalid ID token nonce"}"#.to_string());
        }
        Ok(claims)
    }

    /// Validate an ID token returned by a refresh-token grant. Per OIDC Core
    /// 12.2 the refreshed ID token (when present) MUST bind to the same subject,
    /// and if it carries a `nonce` it MUST equal the original. It is NOT required
    /// to carry a nonce, so absence is accepted.
    async fn verify_refreshed_id_token(
        &self,
        id_token: &str,
        expected_sub: &str,
        expected_nonce: &str,
    ) -> Result<Value, String> {
        let claims = self.verify_id_token_jwks(id_token).await?;
        let sub = required_subject(&claims, "Refreshed ID token")?;
        if !constant_time_eq(sub.as_bytes(), expected_sub.as_bytes()) {
            return Err(r#"{"error":"Refreshed ID token subject mismatch"}"#.to_string());
        }
        if let Some(nonce_claim) = claims.get("nonce") {
            let Some(token_nonce) = nonce_claim.as_str() else {
                return Err(r#"{"error":"Refreshed ID token nonce mismatch"}"#.to_string());
            };
            if !constant_time_eq(token_nonce.as_bytes(), expected_nonce.as_bytes()) {
                return Err(r#"{"error":"Refreshed ID token nonce mismatch"}"#.to_string());
            }
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
        read_bounded_json(response, MAX_USERINFO_RESPONSE_BYTES)
            .await
            .map(Some)
            .map_err(|error| format!("userinfo parse failed: {error}"))
    }

    async fn run_session_auth(
        &self,
        ctx: &mut RequestContext,
        consumer_index: &ConsumerIndex,
    ) -> PluginResult {
        let Some(cookie_value) = cookie_value(ctx, &self.session.cookie_name) else {
            return self.challenge(ctx, false);
        };
        let Some(mut payload) = self.open_session(cookie_value) else {
            return self.challenge(ctx, true);
        };
        let now = chrono::Utc::now().timestamp();
        if now > payload.issued_at_unix + self.session.ttl.as_secs() as i64
            || now > payload.last_touch_unix + self.session.idle_ttl.as_secs() as i64
        {
            return self.challenge(ctx, true);
        }

        let leeway = self.provider.id_token_clock_skew.as_secs() as i64;
        let claims_expires_at = effective_claims_expires_at(&payload);
        let backfilled_claims_expiry = payload.claims_expires_at_unix <= 0;
        if backfilled_claims_expiry {
            payload.claims_expires_at_unix = claims_expires_at;
        }
        let claims_expired_before_refresh = now > claims_expires_at.saturating_add(leeway);
        if claims_expired_before_refresh && payload.refresh_token_b64.is_some() {
            payload.refresh_after_unix = now;
        }

        // Keep the session live: refresh tokens when due (which also re-derives
        // claims from any new ID token), then slide the idle window. Any change
        // is re-sealed and emitted as a `Set-Cookie` by `after_proxy`.
        let refresh = self.maybe_refresh_session(&mut payload, now).await;

        // Token-freshness gate: the ID token was validly verified at login, but
        // its claims must not be served as live authorization past their
        // effective expiry. If they are still expired after any forced/due
        // refresh attempt, fail closed and force re-auth rather than emitting
        // stale claim headers and scope/role decisions.
        let claims_expires_at = effective_claims_expires_at(&payload);
        if now > claims_expires_at.saturating_add(leeway) {
            return self.challenge(ctx, true);
        }

        let mut mutated = refresh.mutated || refresh.refreshed || backfilled_claims_expiry;
        mutated |= self.maybe_slide_session(&mut payload, now);
        if mutated {
            match self.seal_session_cookie(&payload) {
                Ok(cookie) => {
                    ctx.metadata
                        .insert(SESSION_SET_COOKIE_METADATA_KEY.to_string(), cookie);
                }
                Err(error) => {
                    warn!(
                        plugin = "oidc_relying_party",
                        error = %error,
                        "failed to re-seal rolling session cookie; serving with the existing session"
                    );
                }
            }
        }

        // Authorize against the effective (possibly refreshed) claims.
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
        emit_claim_headers_to_context(ctx, &payload.claims, &self.provider.claim_headers, ",");
        let outcome = self.resolve_identity(&payload.claims, consumer_index);
        apply_verify_outcome(ctx, outcome)
    }

    /// Advance the sliding idle window. To keep the response `Set-Cookie` (and the
    /// re-seal cost) off the per-request hot path, `last_touch` advances only once
    /// half the idle window has elapsed since the last update — so an active
    /// session re-seals at most ~twice per idle window while a session idle for
    /// `idle_ttl` still expires. The absolute `ttl` cap is enforced separately.
    fn maybe_slide_session(&self, payload: &mut SessionPayload, now: i64) -> bool {
        let idle = self.session.idle_ttl.as_secs() as i64;
        if idle <= 0 {
            return false;
        }
        let touch_interval = (idle / 2).max(1);
        if now - payload.last_touch_unix >= touch_interval {
            payload.last_touch_unix = now;
            true
        } else {
            false
        }
    }

    /// Refresh the access/ID tokens via `grant_type=refresh_token` once the access
    /// token is within `refresh_skew` of expiry. Reports whether the payload changed
    /// (and therefore needs re-sealing) and, separately, whether a refresh actually
    /// produced freshly validated claims — the two differ on the deferred-failure
    /// branch and on refresh responses that rotate access tokens without returning
    /// a new ID token. The freshness gate in `run_session_auth` relies on that
    /// distinction. Failures are non-fatal here:
    /// the next attempt is deferred by `REFRESH_RETRY_BACKOFF_SECS` so a flaky token
    /// endpoint is not retried on every request, and the freshness gate decides
    /// whether the still-expired session may keep serving.
    async fn maybe_refresh_session(
        &self,
        payload: &mut SessionPayload,
        now: i64,
    ) -> RefreshOutcome {
        if now < payload.refresh_after_unix {
            return RefreshOutcome::UNCHANGED;
        }
        let Some(refresh_token) = payload.refresh_token_b64.clone() else {
            return RefreshOutcome::UNCHANGED;
        };
        let Some(discovery) = self.provider.discovery.load().as_ref().as_ref().cloned() else {
            return RefreshOutcome::UNCHANGED;
        };
        match self
            .refresh_tokens(&discovery, &refresh_token, payload, now)
            .await
        {
            Ok(claims_refreshed) => RefreshOutcome {
                mutated: true,
                refreshed: claims_refreshed,
            },
            Err(error) => {
                warn!(
                    plugin = "oidc_relying_party",
                    error = %error,
                    "OIDC token refresh failed; the freshness gate decides whether the existing session may keep serving"
                );
                payload.refresh_after_unix = now + REFRESH_RETRY_BACKOFF_SECS;
                RefreshOutcome {
                    mutated: true,
                    refreshed: false,
                }
            }
        }
    }

    async fn refresh_tokens(
        &self,
        discovery: &DiscoveryDoc,
        refresh_token: &str,
        payload: &mut SessionPayload,
        now: i64,
    ) -> Result<bool, String> {
        let params = vec![
            ("grant_type".to_string(), "refresh_token".to_string()),
            ("refresh_token".to_string(), refresh_token.to_string()),
            ("client_id".to_string(), self.provider.client_id.clone()),
        ];
        let response = self
            .post_token_endpoint(&discovery.token_endpoint, params)
            .await?;
        if !response.status().is_success() {
            return Err(r#"{"error":"Token refresh failed"}"#.to_string());
        }
        let token: RefreshTokenResponse = read_bounded_json(response, MAX_TOKEN_RESPONSE_BYTES)
            .await
            .map_err(|_| r#"{"error":"Token refresh response parse failed"}"#.to_string())?;
        if !token.token_type.eq_ignore_ascii_case("bearer") {
            return Err(r#"{"error":"Invalid refresh token type"}"#.to_string());
        }
        let existing_claims_expires_at = stored_claims_expires_at(payload);
        let expires_at = expires_at_for_token(&token, now, self.session.ttl);
        // A refreshed ID token is optional; when present, re-validate it (bound to
        // the same subject, nonce only if carried) and adopt its claims so
        // scope/role checks and claim headers track current authorization.
        let claims_refreshed = if let Some(id_token) = token.id_token.as_deref() {
            let id_claims = self
                .verify_refreshed_id_token(id_token, &payload.sub, &payload.nonce)
                .await?;
            // Re-merge UserInfo with the new access token, mirroring the login
            // callback, so non-protected claims that only come from the UserInfo
            // endpoint (e.g. an `email` used in `claim_headers`) survive a refresh
            // instead of being reduced to ID-token-only claims.
            let merged = if let Some(userinfo_endpoint) = &discovery.userinfo_endpoint {
                match self
                    .fetch_userinfo(userinfo_endpoint, &token.access_token)
                    .await
                {
                    Ok(Some(userinfo)) => merge_claims(id_claims, userinfo, &self.provider)?,
                    Ok(None) => id_claims,
                    Err(error) => {
                        warn!(
                            plugin = "oidc_relying_party",
                            error = %error,
                            "OIDC userinfo fetch failed during refresh; keeping refreshed ID token claims"
                        );
                        id_claims
                    }
                }
            } else {
                id_claims
            };
            payload.sub = required_subject(&merged, "Refreshed ID token")?.to_string();
            payload.id_token_b64 = id_token.to_string();
            payload.claims_expires_at_unix = claim_expiry(&merged).unwrap_or(expires_at);
            payload.claims = merged;
            true
        } else {
            payload.claims_expires_at_unix = existing_claims_expires_at.min(expires_at);
            false
        };
        payload.access_token_b64 = token.access_token;
        if let Some(rotated) = token.refresh_token {
            payload.refresh_token_b64 = Some(rotated);
        }
        payload.expires_at_unix = expires_at;
        payload.refresh_after_unix = next_refresh_after(
            expires_at.min(payload.claims_expires_at_unix),
            now,
            self.behavior.refresh_skew.as_secs() as i64,
        );
        payload.last_touch_unix = now;
        Ok(claims_refreshed)
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
            let (state, flow, browser_binding) = match self.create_flow(ctx) {
                Ok(flow) => flow,
                Err(body) => return reject(503, body),
            };
            // Fail closed when no absolute IdP authorization URL can be built
            // (discovery not loaded yet or a malformed authorization_endpoint).
            // Redirecting to the relative post_login_default_path would send the
            // browser back to the protected app root and loop. Drop the just-inserted
            // state slot so an outage cannot exhaust the state cache.
            let Some(location) = self.authorization_url(&state, &flow) else {
                self.session.state_cache.take(&state);
                return reject(503, r#"{"error":"OIDC discovery unavailable"}"#.to_string());
            };
            let correlation_cookie = self.correlation_cookie(&state, &browser_binding);
            let cookie = if clear {
                join_set_cookies(correlation_cookie, self.clear_cookie())
            } else {
                correlation_cookie
            };
            redirect(self.behavior.challenge_html_status, &location, Some(cookie))
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

    fn create_flow(&self, ctx: &RequestContext) -> Result<(String, FlowState, String), String> {
        let state = random_b64(32)?;
        let code_verifier = random_b64(64)?;
        let nonce = random_b64(32)?;
        let browser_binding = random_b64(32)?;
        let browser_binding_hash: [u8; 32] = Sha256::digest(browser_binding.as_bytes()).into();
        let original_url = original_url(ctx, &self.behavior);
        let flow = FlowState {
            code_verifier,
            nonce,
            original_url,
            browser_binding_hash,
            source_ip: ctx.client_ip.clone(),
            expires_at: Instant::now() + self.behavior.state_ttl,
        };
        self.session
            .state_cache
            .insert(state.clone(), flow.clone())?;
        Ok((state, flow, browser_binding))
    }

    /// Build the absolute IdP authorization URL for a browser challenge. Returns
    /// `None` when discovery has not loaded yet or the discovered
    /// `authorization_endpoint` fails to parse, so the caller fails closed instead
    /// of redirecting the browser to the protected app root (which would loop).
    fn authorization_url(&self, state: &str, flow: &FlowState) -> Option<String> {
        let discovery = self.provider.discovery.load().as_ref().as_ref().cloned()?;
        let challenge = pkce_challenge(&flow.code_verifier);
        let mut url = Url::parse(&discovery.authorization_endpoint).ok()?;
        url.query_pairs_mut()
            .append_pair("response_type", "code")
            .append_pair("client_id", &self.provider.client_id)
            .append_pair("redirect_uri", &self.provider.redirect_uri)
            .append_pair("scope", &self.provider.scopes.join(" "))
            .append_pair("state", state)
            .append_pair("nonce", &flow.nonce)
            .append_pair("code_challenge", &challenge)
            .append_pair("code_challenge_method", "S256");
        Some(url.to_string())
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
        let payload: SessionPayload = serde_json::from_slice(&bytes).ok()?;
        if payload.version != SESSION_PAYLOAD_VERSION
            || !constant_time_eq(
                payload.context_id.as_bytes(),
                self.session.context_id.as_bytes(),
            )
        {
            return None;
        }
        Some(payload)
    }

    fn clear_cookie(&self) -> String {
        format!(
            "{}=; Max-Age=0; {}",
            self.session.cookie_name, self.session.cookie_attrs
        )
    }

    fn correlation_cookie_name(&self, state: &str) -> String {
        let state_hash: [u8; 32] = Sha256::digest(state.as_bytes()).into();
        derived_cookie_name(&self.session.correlation_cookie_name_prefix, &state_hash)
    }

    fn correlation_cookie(&self, state: &str, value: &str) -> String {
        format!(
            "{}={value}; Max-Age={}; {}",
            self.correlation_cookie_name(state),
            self.behavior.state_ttl.as_secs(),
            self.session.correlation_cookie_attrs
        )
    }

    fn clear_correlation_cookie(&self, state: &str) -> String {
        format!(
            "{}=; Max-Age=0; {}",
            self.correlation_cookie_name(state),
            self.session.correlation_cookie_attrs
        )
    }

    fn callback_reject(
        &self,
        status_code: u16,
        body: String,
        correlation_state: Option<&str>,
    ) -> PluginResult {
        let mut headers = HashMap::new();
        if let Some(state) = correlation_state {
            headers.insert(
                "set-cookie".to_string(),
                self.clear_correlation_cookie(state),
            );
        }
        PluginResult::Reject {
            status_code,
            body,
            headers,
        }
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

impl Drop for OidcRelyingParty {
    fn drop(&mut self) {
        if let Some(task) = self.discovery_task.take() {
            task.abort();
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
            // The shared proxy deliberately defers query materialization until
            // after this phase. The callback is the one request-received hook
            // that needs decoded parameters, so materialize here once; the
            // later shared call is idempotent and the raw query remains intact.
            ctx.materialize_query_params();
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
        self.run_session_auth(ctx, consumer_index).await
    }
    fn modifies_request_headers(&self) -> bool {
        !self.provider.claim_headers.is_empty()
    }
    async fn before_proxy(
        &self,
        ctx: &mut RequestContext,
        headers: &mut HashMap<String, String>,
    ) -> PluginResult {
        apply_claim_headers_from_context(ctx, headers, CLAIM_HEADER_METADATA_PREFIX);
        PluginResult::Continue
    }
    async fn after_proxy(
        &self,
        ctx: &mut RequestContext,
        _response_status: u16,
        response_headers: &mut HashMap<String, String>,
    ) -> PluginResult {
        // Emit the rolling-session cookie re-sealed during `authenticate`.
        // Appended (newline-joined) so a backend `Set-Cookie` is preserved; the
        // downstream response builder splits these back into separate headers.
        if let Some(cookie) = ctx.metadata.remove(SESSION_SET_COOKIE_METADATA_KEY) {
            response_headers
                .entry("set-cookie".to_string())
                .and_modify(|existing| {
                    existing.push('\n');
                    existing.push_str(&cookie);
                })
                .or_insert(cookie);
        }
        PluginResult::Continue
    }
    fn applies_after_proxy_on_reject(&self) -> bool {
        // A token refresh may have rotated the upstream refresh token before a
        // later plugin rejected the request; the client must still receive the
        // re-sealed cookie so it does not keep replaying a now-invalid token.
        true
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
    fn active_jwks_uris(&self) -> Vec<String> {
        self.provider
            .jwks_store
            .load()
            .as_ref()
            .as_ref()
            .filter(|store| store.is_refreshable())
            .map(|store| vec![store.jwks_uri().to_string()])
            .unwrap_or_default()
    }
    fn active_jwks_refresh_requirements(&self) -> Vec<(String, Duration)> {
        self.active_jwks_uris()
            .into_iter()
            .map(|uri| (uri, DEFAULT_JWKS_REFRESH_INTERVAL))
            .collect()
    }
}

impl StateCache {
    fn new(
        max_entries: usize,
        max_entries_per_source: usize,
        ttl: Duration,
        shard_amount: usize,
    ) -> Self {
        Self {
            entries: DashMap::with_shard_amount(shard_amount),
            expiry_buckets: DashMap::with_shard_amount(shard_amount),
            per_source_entries: DashMap::with_shard_amount(shard_amount),
            active_entries: AtomicUsize::new(0),
            last_evicted_bucket: AtomicU64::new(0),
            origin: Instant::now(),
            max_entries,
            max_entries_per_source,
            shard_amount,
            ttl,
        }
    }
    fn insert(&self, state: String, flow: FlowState) -> Result<(), String> {
        self.evict_expired();
        if self
            .active_entries
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |active| {
                (active < self.max_entries).then_some(active + 1)
            })
            .is_err()
        {
            return Err(r#"{"error":"OIDC state cache full"}"#.to_string());
        }
        if !self.reserve_source(&flow.source_ip) {
            decrement_atomic(&self.active_entries);
            return Err(r#"{"error":"Too many pending OIDC logins"}"#.to_string());
        }
        let expiry_bucket = self.bucket_for(flow.expires_at);
        if let Some(replaced) = self.entries.insert(state.clone(), flow) {
            decrement_atomic(&self.active_entries);
            self.release_source(&replaced.source_ip);
            self.remove_expiry_record(&state, replaced.expires_at);
        }
        self.expiry_buckets
            .entry(expiry_bucket)
            .or_insert_with(|| Arc::new(DashMap::with_shard_amount(self.shard_amount)))
            .insert(state, ());
        Ok(())
    }
    fn take(&self, state: &str) -> Option<FlowState> {
        let (_, flow) = self.entries.remove(state)?;
        self.remove_expiry_record(state, flow.expires_at);
        decrement_atomic(&self.active_entries);
        self.release_source(&flow.source_ip);
        (flow.expires_at > Instant::now()).then_some(flow)
    }

    fn take_bound(&self, state: &str, browser_binding_hash: &[u8]) -> Option<FlowState> {
        let now = Instant::now();
        let (_, flow) = self.entries.remove_if(state, |_, flow| {
            flow.expires_at <= now
                || constant_time_eq(&flow.browser_binding_hash, browser_binding_hash)
        })?;
        self.remove_expiry_record(state, flow.expires_at);
        decrement_atomic(&self.active_entries);
        self.release_source(&flow.source_ip);
        (flow.expires_at > now
            && constant_time_eq(&flow.browser_binding_hash, browser_binding_hash))
        .then_some(flow)
    }

    fn evict_expired(&self) {
        let now = Instant::now();
        let current_bucket = self.bucket_for(now);
        let previous = self
            .last_evicted_bucket
            .swap(current_bucket, Ordering::AcqRel);
        if current_bucket <= previous {
            return;
        }

        // Normal traffic advances zero or one bucket and performs O(1)
        // cleanup. After a long idle period, scan only the bounded bucket
        // index instead of looping through every empty wall-clock bucket.
        if current_bucket - previous > 1024 {
            let expired: Vec<u64> = self
                .expiry_buckets
                .iter()
                .filter_map(|entry| (*entry.key() < current_bucket).then_some(*entry.key()))
                .collect();
            for bucket in expired {
                self.evict_bucket(bucket, now);
            }
        } else {
            for bucket in previous..current_bucket {
                self.evict_bucket(bucket, now);
            }
        }
    }

    fn evict_bucket(&self, bucket: u64, now: Instant) {
        let Some((_, states)) = self.expiry_buckets.remove(&bucket) else {
            return;
        };
        for state in states.iter() {
            if let Some((_, flow)) = self
                .entries
                .remove_if(state.key(), |_, flow| flow.expires_at <= now)
            {
                decrement_atomic(&self.active_entries);
                self.release_source(&flow.source_ip);
            }
        }
    }

    fn remove_expiry_record(&self, state: &str, expires_at: Instant) {
        if let Some(states) = self.expiry_buckets.get(&self.bucket_for(expires_at)) {
            states.remove(state);
        }
    }

    fn bucket_for(&self, instant: Instant) -> u64 {
        instant
            .checked_duration_since(self.origin)
            .unwrap_or_default()
            .as_secs()
            / STATE_EXPIRY_BUCKET_SECS
    }

    fn reserve_source(&self, source_ip: &str) -> bool {
        use dashmap::mapref::entry::Entry;

        match self.per_source_entries.entry(source_ip.to_string()) {
            Entry::Occupied(mut entry) => {
                if *entry.get() >= self.max_entries_per_source {
                    false
                } else {
                    *entry.get_mut() += 1;
                    true
                }
            }
            Entry::Vacant(entry) => {
                entry.insert(1);
                true
            }
        }
    }

    fn release_source(&self, source_ip: &str) {
        let remove = if let Some(mut entry) = self.per_source_entries.get_mut(source_ip) {
            let count = entry.value_mut();
            *count = count.saturating_sub(1);
            *count == 0
        } else {
            false
        };
        if remove {
            self.per_source_entries
                .remove_if(source_ip, |_, count| *count == 0);
        }
    }
}

fn decrement_atomic(value: &AtomicUsize) {
    let _ = value.fetch_update(Ordering::AcqRel, Ordering::Acquire, |current| {
        (current > 0).then_some(current - 1)
    });
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

async fn read_bounded_json<T>(response: reqwest::Response, max_bytes: usize) -> Result<T, String>
where
    T: serde::de::DeserializeOwned,
{
    let body = read_response_body_bounded(response, max_bytes)
        .await
        .map_err(|error| error.to_string())?;
    serde_json::from_slice(&body).map_err(|error| error.to_string())
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

fn reject_unknown_fields(
    config: &Map<String, Value>,
    allowed: &[&str],
    scope: &str,
) -> Result<(), String> {
    if let Some(field) = config
        .keys()
        .find(|field| !allowed.contains(&field.as_str()))
    {
        return Err(format!(
            "oidc_relying_party: unknown field '{scope}.{field}'"
        ));
    }
    Ok(())
}

fn session_context_seed(
    provider: &Map<String, Value>,
    session: &Map<String, Value>,
    behavior: Option<&Map<String, Value>>,
) -> Result<[u8; 32], String> {
    let mut claim_headers = parse_claim_headers(
        provider,
        "claim_headers",
        "oidc_relying_party",
        CLAIM_HEADER_METADATA_PREFIX,
    )?
    .into_iter()
    .map(|mapping| NormalizedClaimHeaderContext {
        claim_path: mapping.claim_path,
        metadata_key: mapping.metadata_key,
    })
    .collect::<Vec<_>>();
    claim_headers.sort_unstable_by(|left, right| {
        left.claim_path
            .cmp(&right.claim_path)
            .then_with(|| left.metadata_key.cmp(&right.metadata_key))
    });

    let html_accept_substrings = parse_behavior_string_array(behavior, "html_accept_substrings")?
        .pipe_default(vec!["text/html".to_string()]);
    let normalized = NormalizedSessionContextSeed {
        version: SESSION_PAYLOAD_VERSION,
        provider: NormalizedProviderContext {
            issuer: required_string(provider, "issuer", "provider[0]")?,
            discovery_url: optional_string(provider, "discovery_url", "provider[0]")?,
            authorization_endpoint: optional_string(
                provider,
                "authorization_endpoint",
                "provider[0]",
            )?,
            token_endpoint: optional_string(provider, "token_endpoint", "provider[0]")?,
            userinfo_endpoint: optional_string(provider, "userinfo_endpoint", "provider[0]")?,
            jwks_uri: optional_string(provider, "jwks_uri", "provider[0]")?,
            end_session_endpoint: optional_string(provider, "end_session_endpoint", "provider[0]")?,
            client_id: required_string(provider, "client_id", "provider[0]")?,
            client_auth: normalized_client_auth_context(provider),
            redirect_uri: required_string(provider, "redirect_uri", "provider[0]")?,
            callback_path: optional_string(provider, "callback_path", "provider[0]")?
                .unwrap_or_else(|| "/oauth/callback".to_string()),
            logout_path: optional_string(provider, "logout_path", "provider[0]")?
                .unwrap_or_else(|| "/oauth/logout".to_string()),
            post_logout_redirect_uri: optional_string(
                provider,
                "post_logout_redirect_uri",
                "provider[0]",
            )?,
            scopes: parse_string_array(provider, "scopes", "provider[0]")?,
            audiences: parse_string_array(provider, "audiences", "provider[0]")?,
            required_scopes: parse_string_array(provider, "required_scopes", "provider[0]")?,
            required_roles: parse_string_array(provider, "required_roles", "provider[0]")?,
            scope_claim: optional_string(provider, "scope_claim", "provider[0]")?
                .unwrap_or_else(|| "scope".to_string()),
            role_claim: optional_string(provider, "role_claim", "provider[0]")?
                .unwrap_or_else(|| "roles".to_string()),
            consumer_identity_claim: optional_string(
                provider,
                "consumer_identity_claim",
                "provider[0]",
            )?
            .unwrap_or_else(|| "sub".to_string()),
            consumer_header_claim: optional_string(
                provider,
                "consumer_header_claim",
                "provider[0]",
            )?
            .unwrap_or_else(|| "sub".to_string()),
            claim_headers,
            id_token_clock_skew_secs: optional_u64(
                provider,
                "id_token_clock_skew_secs",
                DEFAULT_ID_TOKEN_CLOCK_SKEW_SECS,
            )?,
        },
        session: NormalizedSessionContext {
            store: optional_string(session, "store", "session")?
                .unwrap_or_else(|| "cookie".to_string()),
            ttl_secs: optional_u64(session, "ttl_secs", DEFAULT_SESSION_TTL_SECS)?,
            idle_ttl_secs: optional_u64(session, "idle_ttl_secs", DEFAULT_SESSION_IDLE_TTL_SECS)?,
            max_cookie_bytes: optional_u64(
                session,
                "max_cookie_bytes",
                DEFAULT_SESSION_MAX_COOKIE_BYTES,
            )?,
            secure: optional_bool(session, "secure")?.unwrap_or(true),
            http_only: optional_bool(session, "http_only")?.unwrap_or(true),
            same_site: optional_string(session, "same_site", "session")?
                .unwrap_or_else(|| "lax".to_string())
                .to_ascii_lowercase(),
            domain: optional_string(session, "domain", "session")?,
            path: optional_string(session, "path", "session")?.unwrap_or_else(|| "/".to_string()),
        },
        behavior: NormalizedBehaviorContext {
            state_ttl_secs: optional_behavior_u64(
                behavior,
                "state_ttl_secs",
                DEFAULT_STATE_TTL_SECS,
            )?,
            state_cache_max_entries: optional_behavior_u64(
                behavior,
                "state_cache_max_entries",
                DEFAULT_STATE_CACHE_MAX_ENTRIES as u64,
            )?,
            state_cache_max_entries_per_source: optional_behavior_u64(
                behavior,
                "state_cache_max_entries_per_source",
                DEFAULT_STATE_CACHE_MAX_ENTRIES_PER_SOURCE as u64,
            )?,
            post_login_redirect_param: optional_behavior_string(
                behavior,
                "post_login_redirect_param",
            )?,
            trusted_redirect_hosts: parse_behavior_string_array(
                behavior,
                "trusted_redirect_hosts",
            )?,
            refresh_skew_secs: optional_behavior_u64(
                behavior,
                "refresh_skew_secs",
                DEFAULT_REFRESH_SKEW_SECS,
            )?,
            challenge_html_status: optional_behavior_u64(
                behavior,
                "challenge_html_status",
                DEFAULT_CHALLENGE_HTML_STATUS,
            )?,
            challenge_api_status: optional_behavior_u64(
                behavior,
                "challenge_api_status",
                DEFAULT_CHALLENGE_API_STATUS,
            )?,
            html_accept_substrings,
            rp_initiated_logout: optional_behavior_bool(behavior, "rp_initiated_logout")?
                .unwrap_or(true),
            post_login_default_path: optional_behavior_string(behavior, "post_login_default_path")?
                .unwrap_or_else(|| "/".to_string()),
        },
    };
    // Struct field order plus the sorted claim-header list make the byte
    // representation deterministic, independent of input object key order.
    let serialized = serde_json::to_vec(&normalized)
        .map_err(|_| "oidc_relying_party: failed to derive session context".to_string())?;
    Ok(Sha256::digest(serialized).into())
}

fn normalized_client_auth_context(provider: &Map<String, Value>) -> NormalizedClientAuthContext {
    let client_auth = provider.get("client_auth").and_then(Value::as_object);
    let method = client_auth
        .and_then(|auth| auth.get("method"))
        .and_then(Value::as_str)
        .unwrap_or("client_secret_basic")
        .to_string();
    let is_private_key_jwt = method == "private_key_jwt";
    NormalizedClientAuthContext {
        method,
        private_key_jwt_alg: is_private_key_jwt.then(|| {
            client_auth
                .and_then(|auth| auth.get("private_key_jwt_alg"))
                .and_then(Value::as_str)
                .unwrap_or("RS256")
                .to_string()
        }),
        private_key_jwt_kid: if is_private_key_jwt {
            client_auth
                .and_then(|auth| auth.get("private_key_jwt_kid"))
                .and_then(Value::as_str)
                .map(str::trim)
                .filter(|value| !value.is_empty())
                .map(ToOwned::to_owned)
        } else {
            None
        },
    }
}

fn session_context_id(seed: &[u8; 32], cookie_name: &str) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(b"ferrum-edge/oidc-session-context/v2\0");
    hasher.update(seed);
    hasher.update((cookie_name.len() as u64).to_be_bytes());
    hasher.update(cookie_name.as_bytes());
    hasher.finalize().into()
}

fn derived_cookie_name(prefix: &str, context_seed: &[u8; 32]) -> String {
    let encoded = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(context_seed);
    let suffix: String = encoded.chars().take(12).collect();
    format!("{prefix}_{suffix}")
}

fn behavior_usize(
    config: Option<&Map<String, Value>>,
    field: &str,
    default: usize,
) -> Result<usize, String> {
    let raw = optional_behavior_u64(config, field, default as u64)?;
    if raw == 0 {
        return Err(format!(
            "oidc_relying_party: behavior.{field} must be greater than zero"
        ));
    }
    usize::try_from(raw).map_err(|_| format!("oidc_relying_party: behavior.{field} is too large"))
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
    let host = parsed
        .host_str()
        .ok_or_else(|| "oidc_relying_party: redirect_uri must include a hostname".to_string())?;
    match parsed.scheme() {
        "https" => {}
        "http" if is_local_auth_host(host) => {}
        "http" => {
            return Err(
                "oidc_relying_party: redirect_uri must use https except for literal loopback or localhost"
                    .to_string(),
            );
        }
        scheme => {
            return Err(format!(
                "oidc_relying_party: redirect_uri must use http or https, got {scheme}"
            ));
        }
    }
    Ok(())
}

fn validate_url_string(raw: &str, field: &str) -> Result<String, String> {
    let parsed =
        Url::parse(raw).map_err(|e| format!("oidc_relying_party: {field} invalid: {e}"))?;
    let host = parsed
        .host_str()
        .ok_or_else(|| format!("oidc_relying_party: {field} must include a hostname"))?;
    match parsed.scheme() {
        "https" => {}
        "http" if is_local_auth_host(host) => {}
        "http" => {
            return Err(format!(
                "oidc_relying_party: {field} must use https except for literal loopback or localhost"
            ));
        }
        scheme => {
            return Err(format!(
                "oidc_relying_party: {field} must use http or https, got {scheme}"
            ));
        }
    }
    Ok(raw.trim().to_string())
}

fn validate_discovered_url(discovery_url: &str, raw: &str, field: &str) -> Result<String, String> {
    let discovery = Url::parse(discovery_url)
        .map_err(|e| format!("oidc_relying_party: discovery_url invalid: {e}"))?;
    let parsed = Url::parse(raw)
        .map_err(|e| format!("oidc_relying_party: discovery {field} invalid: {e}"))?;
    let endpoint_host = parsed
        .host_str()
        .ok_or_else(|| format!("oidc_relying_party: discovery {field} must include a hostname"))?;
    match parsed.scheme() {
        "https" => {}
        "http" if is_local_auth_host(endpoint_host) => {}
        "http" => {
            return Err(format!(
                "oidc_relying_party: discovery {field} must use https except for literal loopback or localhost"
            ));
        }
        scheme => {
            return Err(format!(
                "oidc_relying_party: discovery {field} must use http or https, got {scheme}"
            ));
        }
    }
    let discovery_host = discovery
        .host_str()
        .ok_or_else(|| "oidc_relying_party: discovery_url must include a hostname".to_string())?;
    if !endpoint_host.eq_ignore_ascii_case(discovery_host) {
        return Err(format!(
            "oidc_relying_party: discovery {field} host must match discovery_url host"
        ));
    }
    if parsed.scheme() != discovery.scheme()
        || parsed.port_or_known_default() != discovery.port_or_known_default()
    {
        return Err(format!(
            "oidc_relying_party: discovery {field} scheme and port must match discovery_url"
        ));
    }
    Ok(raw.trim().to_string())
}

fn is_local_auth_host(hostname: &str) -> bool {
    let literal = hostname
        .strip_prefix('[')
        .and_then(|hostname| hostname.strip_suffix(']'))
        .unwrap_or(hostname);
    literal.eq_ignore_ascii_case("localhost")
        || literal
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

/// Schedule the next proactive refresh `refresh_skew` before the earliest
/// token/claim expiry passed by the caller, but never sooner than
/// `REFRESH_RETRY_BACKOFF_SECS` from now. The floor stops a refresh storm when
/// a provider issues very short-lived access tokens or ID-token claims (so
/// `expires_at - refresh_skew` would already be in the past).
fn next_refresh_after(expires_at_unix: i64, now: i64, refresh_skew_secs: i64) -> i64 {
    (expires_at_unix - refresh_skew_secs).max(now + REFRESH_RETRY_BACKOFF_SECS)
}

fn expires_at_for_token(token: &RefreshTokenResponse, now: i64, session_ttl: Duration) -> i64 {
    now + token.expires_in.unwrap_or(session_ttl.as_secs() as i64)
}

fn claim_expiry(claims: &Value) -> Option<i64> {
    claims.get("exp").and_then(Value::as_i64)
}

fn required_subject<'a>(claims: &'a Value, token_kind: &str) -> Result<&'a str, String> {
    claims
        .get("sub")
        .and_then(Value::as_str)
        .filter(|subject| !subject.trim().is_empty())
        .ok_or_else(|| format!(r#"{{"error":"{token_kind} missing subject"}}"#))
}

fn validate_oidc_audience_and_azp(
    claims: &Value,
    client_id: &str,
    configured_audiences: &[String],
) -> Result<(), String> {
    let mut audiences = Vec::new();
    match claims.get("aud") {
        Some(Value::String(audience)) if !audience.is_empty() => audiences.push(audience.as_str()),
        Some(Value::Array(values)) => {
            for value in values {
                let Some(audience) = value.as_str().filter(|audience| !audience.is_empty()) else {
                    return Err(r#"{"error":"Invalid ID token audience"}"#.to_string());
                };
                audiences.push(audience);
            }
        }
        _ => return Err(r#"{"error":"Invalid ID token audience"}"#.to_string()),
    }
    if audiences.is_empty() || !audiences.contains(&client_id) {
        return Err(r#"{"error":"Invalid ID token audience"}"#.to_string());
    }
    if !configured_audiences.is_empty()
        && !configured_audiences
            .iter()
            .any(|expected| audiences.contains(&expected.as_str()))
    {
        return Err(r#"{"error":"Invalid ID token audience"}"#.to_string());
    }

    let azp = claims.get("azp");
    if audiences.len() > 1 || azp.is_some() {
        let Some(authorized_party) = azp.and_then(Value::as_str) else {
            return Err(r#"{"error":"Invalid ID token authorized party"}"#.to_string());
        };
        if !constant_time_eq(authorized_party.as_bytes(), client_id.as_bytes()) {
            return Err(r#"{"error":"Invalid ID token authorized party"}"#.to_string());
        }
    }
    Ok(())
}

fn effective_claims_expires_at(payload: &SessionPayload) -> i64 {
    stored_claims_expires_at(payload).min(payload.expires_at_unix)
}

fn stored_claims_expires_at(payload: &SessionPayload) -> i64 {
    if payload.claims_expires_at_unix > 0 {
        payload.claims_expires_at_unix
    } else {
        claim_expiry(&payload.claims).unwrap_or(payload.expires_at_unix)
    }
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
        // Skip segments without '=' (valueless cookies, trailing separators)
        // instead of aborting the scan: a sibling cookie lacking '=' before the
        // session cookie would otherwise hide it and trigger a spurious re-auth.
        let Some((cookie_name, value)) = part.trim().split_once('=') else {
            continue;
        };
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
    let mut original = format!("{scheme}://{host}{}", ctx.path);
    if let Some(raw_query) = ctx.raw_query_string() {
        original.push('?');
        original.push_str(raw_query);
    }
    original
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
    let Some(userinfo_obj) = userinfo.as_object() else {
        return Err(r#"{"error":"Userinfo subject mismatch"}"#.to_string());
    };
    let Some(userinfo_sub) = userinfo_obj
        .get("sub")
        .and_then(Value::as_str)
        .filter(|subject| !subject.trim().is_empty())
    else {
        return Err(r#"{"error":"Userinfo subject mismatch"}"#.to_string());
    };
    let Some(id_sub) = id_claims
        .get("sub")
        .and_then(Value::as_str)
        .filter(|subject| !subject.trim().is_empty())
    else {
        return Err(r#"{"error":"Userinfo subject mismatch"}"#.to_string());
    };
    if !constant_time_eq(id_sub.as_bytes(), userinfo_sub.as_bytes()) {
        return Err(r#"{"error":"Userinfo subject mismatch"}"#.to_string());
    }
    if let Some(id) = id_claims.as_object_mut() {
        for (key, value) in userinfo_obj {
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

fn join_set_cookies(mut first: String, second: String) -> String {
    first.push('\n');
    first.push_str(&second);
    first
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

fn spawn_oidc_discovery(
    discovery_slot: Arc<ArcSwap<Option<DiscoveryDoc>>>,
    jwks_slot: Arc<ArcSwap<Option<Arc<JwksKeyStore>>>>,
    http_client: PluginHttpClient,
    discovery_url: String,
) -> tokio::task::JoinHandle<()> {
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
    })
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
    let body: Value = read_bounded_json(response, MAX_DISCOVERY_RESPONSE_BYTES)
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
    use crate::consumer_index::ConsumerIndex;
    use crate::plugins::Plugin;
    use serde_json::json;
    use std::collections::HashMap;
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

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
    fn userinfo_requires_a_non_empty_string_subject() {
        let protected = HashSet::from(["sub"]);
        for userinfo in [
            json!({"email": "unbound@example.com"}),
            json!({"sub": null, "email": "unbound@example.com"}),
            json!({"sub": [], "email": "unbound@example.com"}),
            json!({"sub": "", "email": "unbound@example.com"}),
            json!([{"sub": "user-1"}]),
        ] {
            assert!(
                merge_claims_with_protected_keys(json!({"sub": "user-1"}), userinfo, &protected,)
                    .is_err()
            );
        }
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
    fn discovered_urls_cannot_change_scheme_or_effective_port() {
        let discovery = "https://issuer.example.com/.well-known/openid-configuration";
        for endpoint in [
            "http://issuer.example.com/token",
            "https://issuer.example.com:8443/token",
        ] {
            assert!(validate_discovered_url(discovery, endpoint, "token_endpoint").is_err());
        }
        assert_eq!(
            validate_discovered_url(
                discovery,
                "https://issuer.example.com/token",
                "token_endpoint",
            )
            .expect("same-origin HTTPS endpoint"),
            "https://issuer.example.com/token"
        );
    }

    #[test]
    fn direct_provider_urls_allow_http_only_for_literal_loopback_or_localhost() {
        for allowed in [
            "http://localhost:8080/token",
            "http://127.0.0.1:8080/token",
            "http://[::1]:8080/token",
            "https://idp.example.com/token",
        ] {
            assert!(validate_url_string(allowed, "token_endpoint").is_ok());
        }
        for denied in [
            "http://idp.example.com/token",
            "http://127.0.0.1.example.com/token",
            "ftp://localhost/token",
        ] {
            assert!(validate_url_string(denied, "token_endpoint").is_err());
        }
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

    fn default_redirect_behavior() -> BehaviorConfig {
        BehaviorConfig {
            challenge_html_status: 302,
            challenge_api_status: 401,
            html_accept_substrings: vec!["text/html".to_string()],
            state_ttl: Duration::from_secs(600),
            refresh_skew: Duration::from_secs(30),
            rp_initiated_logout: true,
            post_login_redirect_param: None,
            post_login_default_path: "/".to_string(),
            trusted_redirect_hosts: vec!["app.example.com".to_string()],
        }
    }

    #[test]
    fn default_original_url_preserves_raw_query_exactly() {
        let mut ctx = RequestContext::new("127.0.0.1".into(), "GET".into(), "/orders".into());
        ctx.headers
            .insert("host".to_string(), "app.example.com".to_string());
        ctx.metadata
            .insert("ferrum.frontend_scheme".to_string(), "https".to_string());
        ctx.set_raw_query_string(
            "filter=open&page=2&tag=a&tag=b&encoded=%2Fkeep%20raw".to_string(),
        );
        ctx.materialize_query_params();

        assert_eq!(
            original_url(&ctx, &default_redirect_behavior()),
            "https://app.example.com/orders?filter=open&page=2&tag=a&tag=b&encoded=%2Fkeep%20raw"
        );
    }

    #[test]
    fn default_original_url_without_query_has_no_question_mark() {
        let mut ctx = RequestContext::new("127.0.0.1".into(), "GET".into(), "/orders".into());
        ctx.headers
            .insert("host".to_string(), "app.example.com".to_string());
        ctx.metadata
            .insert("ferrum.frontend_scheme".to_string(), "https".to_string());

        assert_eq!(
            original_url(&ctx, &default_redirect_behavior()),
            "https://app.example.com/orders"
        );
    }

    #[test]
    fn cookie_value_skips_segments_without_equals() {
        let mut ctx = RequestContext::new("127.0.0.1".into(), "GET".into(), "/".into());
        // A valueless sibling cookie precedes the session cookie; it must not
        // abort the scan.
        ctx.headers.insert(
            "cookie".to_string(),
            "consent; ferrum_session=abc123; theme=dark".to_string(),
        );
        assert_eq!(cookie_value(&ctx, "ferrum_session"), Some("abc123"));
    }

    #[test]
    fn cookie_value_absent_returns_none() {
        let mut ctx = RequestContext::new("127.0.0.1".into(), "GET".into(), "/".into());
        ctx.headers
            .insert("cookie".to_string(), "theme=dark; consent".to_string());
        assert_eq!(cookie_value(&ctx, "ferrum_session"), None);
    }

    fn plugin_config_without_optional_defaults(redirect_uri: &str) -> Value {
        json!({
            "providers": [{
                "issuer": "https://idp.example.com",
                "client_id": "client-1",
                "authorization_endpoint": "https://idp.example.com/authorize",
                "token_endpoint": "https://idp.example.com/token",
                "jwks_uri": "https://idp.example.com/jwks",
                "scopes": ["openid"],
                "redirect_uri": redirect_uri,
                "client_auth": {"client_secret": "shhh"}
            }],
            "session": {
                "encryption_secret": "0123456789012345678901234567890123"
            }
        })
    }

    fn build_plugin_without_workers(config: &Value) -> OidcRelyingParty {
        OidcRelyingParty::new_internal(config, PluginHttpClient::default(), false)
            .expect("OIDC test config is valid")
    }

    #[test]
    fn concurrent_browser_challenges_keep_distinct_state_bindings() {
        let config =
            plugin_config_without_optional_defaults("https://app.example.com/oauth/callback");
        let plugin = build_plugin_without_workers(&config);
        let mut ctx = RequestContext::new("127.0.0.1".into(), "GET".into(), "/app".into());
        ctx.headers
            .insert("accept".to_string(), "text/html".to_string());

        let mut issue_challenge = || {
            let PluginResult::Reject {
                status_code,
                headers,
                ..
            } = plugin.challenge(&mut ctx, false)
            else {
                panic!("browser challenge must redirect");
            };
            assert_eq!(status_code, 302);
            let location = headers.get("location").expect("challenge location");
            let state = Url::parse(location)
                .expect("absolute authorization URL")
                .query_pairs()
                .find_map(|(name, value)| (name == "state").then(|| value.into_owned()))
                .expect("state query parameter");
            let cookie_pair = headers
                .get("set-cookie")
                .expect("correlation cookie")
                .split(';')
                .next()
                .expect("cookie pair");
            let (name, value) = cookie_pair.split_once('=').expect("named cookie");
            (state, name.to_string(), value.to_string())
        };

        let first = issue_challenge();
        let second = issue_challenge();
        assert_ne!(first.0, second.0);
        assert_ne!(first.1, second.1, "each state needs its own cookie name");
        assert_eq!(first.1, plugin.correlation_cookie_name(&first.0));
        assert_eq!(second.1, plugin.correlation_cookie_name(&second.0));

        let mut callback =
            RequestContext::new("127.0.0.1".into(), "GET".into(), "/oauth/callback".into());
        callback.headers.insert(
            "cookie".to_string(),
            format!("{}={}; {}={}", first.1, first.2, second.1, second.2),
        );
        assert_eq!(cookie_value(&callback, &first.1), Some(first.2.as_str()));
        assert_eq!(cookie_value(&callback, &second.1), Some(second.2.as_str()));

        let first_hash: [u8; 32] = Sha256::digest(first.2.as_bytes()).into();
        let second_hash: [u8; 32] = Sha256::digest(second.2.as_bytes()).into();
        assert!(
            plugin
                .session
                .state_cache
                .take_bound(&first.0, &first_hash)
                .is_some()
        );
        assert!(
            plugin
                .session
                .state_cache
                .take_bound(&second.0, &second_hash)
                .is_some(),
            "consuming one browser-bound flow must not evict its sibling"
        );
    }

    #[test]
    fn session_context_is_stable_across_omitted_and_explicit_defaults() {
        let omitted_config =
            plugin_config_without_optional_defaults("https://app.example.com/oauth/callback");
        let explicit_config = json!({
            "providers": [{
                "issuer": "https://idp.example.com",
                "discovery_url": null,
                "authorization_endpoint": "https://idp.example.com/authorize",
                "token_endpoint": "https://idp.example.com/token",
                "userinfo_endpoint": null,
                "jwks_uri": "https://idp.example.com/jwks",
                "end_session_endpoint": null,
                "client_id": "client-1",
                "client_auth": {
                    "method": "client_secret_basic",
                    "client_secret": "shhh"
                },
                "redirect_uri": "https://app.example.com/oauth/callback",
                "callback_path": "/oauth/callback",
                "logout_path": "/oauth/logout",
                "post_logout_redirect_uri": null,
                "scopes": ["openid"],
                "audiences": [],
                "required_scopes": [],
                "required_roles": [],
                "scope_claim": "scope",
                "role_claim": "roles",
                "consumer_identity_claim": "sub",
                "consumer_header_claim": "sub",
                "claim_headers": {},
                "id_token_clock_skew_secs": 60
            }],
            "session": {
                "encryption_secret": "0123456789012345678901234567890123",
                "encryption_secret_previous": null,
                "store": "cookie",
                "ttl_secs": 3600,
                "idle_ttl_secs": 1800,
                "max_cookie_bytes": 8000,
                "secure": true,
                "http_only": true,
                "same_site": "lax",
                "domain": null,
                "path": "/"
            },
            "behavior": {
                "state_ttl_secs": 600,
                "state_cache_max_entries": 10000,
                "state_cache_max_entries_per_source": 32,
                "post_login_redirect_param": null,
                "trusted_redirect_hosts": [],
                "refresh_skew_secs": 30,
                "challenge_html_status": 302,
                "challenge_api_status": 401,
                "html_accept_substrings": [],
                "rp_initiated_logout": true,
                "post_login_default_path": "/"
            }
        });
        let omitted = build_plugin_without_workers(&omitted_config);
        let explicit = build_plugin_without_workers(&explicit_config);

        assert_eq!(omitted.session.cookie_name, explicit.session.cookie_name);
        assert_eq!(omitted.session.context_id, explicit.session.context_id);

        let now = chrono::Utc::now().timestamp();
        let mut payload = session_payload(now - 10, now - 10, None, now + 1000);
        payload.context_id = omitted.session.context_id.clone();
        let cookie = omitted
            .seal_session_cookie(&payload)
            .expect("omitted-default context seals");
        assert!(
            explicit
                .open_session(sealed_cookie_value(&cookie))
                .is_some(),
            "an explicitly defaulted reload must retain the same session AAD"
        );
    }

    #[test]
    fn localhost_http_callback_honors_insecure_correlation_cookie_setting() {
        for redirect_uri in [
            "http://localhost/oauth/callback",
            "http://127.0.0.1/oauth/callback",
            "http://[::1]/oauth/callback",
        ] {
            let mut config = plugin_config_without_optional_defaults(redirect_uri);
            config["session"]["secure"] = Value::Bool(false);
            let plugin = build_plugin_without_workers(&config);
            let correlation_cookie = plugin.correlation_cookie("state", "browser-binding");

            assert!(!plugin.session.cookie_attrs.contains("; Secure"));
            assert!(
                !correlation_cookie.contains("; Secure"),
                "local HTTP callback cookie must match session.secure=false for {redirect_uri}"
            );
            assert!(correlation_cookie.contains("; HttpOnly"));
            assert!(correlation_cookie.contains("SameSite=Lax"));
        }
    }

    #[test]
    fn next_refresh_after_floors_at_backoff() {
        // Normal: refresh `refresh_skew` before expiry.
        assert_eq!(next_refresh_after(4600, 1000, 30), 4570);
        // Very short-lived token: floored at now + backoff to avoid a refresh storm.
        assert_eq!(
            next_refresh_after(1005, 1000, 30),
            1000 + REFRESH_RETRY_BACKOFF_SECS
        );
    }

    #[test]
    fn oidc_audience_and_authorized_party_rules_fail_closed() {
        let configured = vec!["api://orders".to_string()];
        assert!(
            validate_oidc_audience_and_azp(
                &json!({"aud": ["client-1", "api://orders"], "azp": "client-1"}),
                "client-1",
                &configured,
            )
            .is_ok()
        );
        for claims in [
            json!({"aud": "other-client"}),
            json!({"aud": ["client-1", "api://orders"]}),
            json!({"aud": ["client-1", "api://orders"], "azp": "other-client"}),
            json!({"aud": ["client-1"], "azp": 7}),
            json!({"aud": ["client-1"]}),
        ] {
            let result = validate_oidc_audience_and_azp(&claims, "client-1", &configured);
            if claims == json!({"aud": ["client-1"]}) {
                assert!(
                    result.is_err(),
                    "configured resource audience is also required"
                );
            } else {
                assert!(result.is_err(), "claims should be rejected: {claims}");
            }
        }
    }

    #[test]
    fn id_token_subject_must_be_a_non_empty_string() {
        assert_eq!(
            required_subject(&json!({"sub": "user-1"}), "ID token").ok(),
            Some("user-1")
        );
        for claims in [
            json!({}),
            json!({"sub": null}),
            json!({"sub": 7}),
            json!({"sub": ""}),
            json!({"sub": "   "}),
        ] {
            assert!(required_subject(&claims, "ID token").is_err());
        }
    }

    fn build_plugin(token_endpoint: &str) -> OidcRelyingParty {
        build_plugin_with_client(token_endpoint, "client-1")
    }

    fn build_plugin_with_client(token_endpoint: &str, client_id: &str) -> OidcRelyingParty {
        OidcRelyingParty::new(
            &json!({
                "providers": [{
                    "issuer": "https://idp.example.com",
                    "client_id": client_id,
                    "authorization_endpoint": "https://idp.example.com/authorize",
                    "token_endpoint": token_endpoint,
                    "jwks_uri": "https://idp.example.com/jwks",
                    "scopes": ["openid", "offline_access"],
                    "redirect_uri": "https://app.example.com/oauth/callback",
                    "callback_path": "/oauth/callback",
                    "client_auth": {"method": "client_secret_basic", "client_secret": "shhh"}
                }],
                "session": {
                    "encryption_secret": "0123456789012345678901234567890123",
                    "ttl_secs": 3600,
                    "idle_ttl_secs": 1800
                }
            }),
            PluginHttpClient::default(),
        )
        .expect("oidc plugin config is valid")
    }

    fn session_payload(
        issued: i64,
        last_touch: i64,
        refresh_token: Option<&str>,
        refresh_after: i64,
    ) -> SessionPayload {
        SessionPayload {
            version: SESSION_PAYLOAD_VERSION,
            context_id: String::new(),
            sub: "user-1".to_string(),
            id_token_b64: "old-id".to_string(),
            access_token_b64: "old-at".to_string(),
            refresh_token_b64: refresh_token.map(str::to_string),
            expires_at_unix: refresh_after + 30,
            claims_expires_at_unix: refresh_after + 30,
            refresh_after_unix: refresh_after,
            issued_at_unix: issued,
            last_touch_unix: last_touch,
            nonce: "nonce-1".to_string(),
            claims: json!({"sub": "user-1"}),
        }
    }

    fn ctx_with_session(plugin: &OidcRelyingParty, payload: &SessionPayload) -> RequestContext {
        let mut payload = payload.clone();
        payload.version = SESSION_PAYLOAD_VERSION;
        payload.context_id = plugin.session.context_id.clone();
        let set_cookie = plugin.seal_session_cookie(&payload).expect("seal session");
        // "name=value; attrs..." -> request "Cookie: name=value".
        let cookie_pair = set_cookie.split(';').next().unwrap().to_string();
        let mut ctx = RequestContext::new("127.0.0.1".into(), "GET".into(), "/app".into());
        ctx.headers.insert("cookie".to_string(), cookie_pair);
        ctx
    }

    fn emitted_session_payload(
        plugin: &OidcRelyingParty,
        response_headers: &HashMap<String, String>,
    ) -> Option<SessionPayload> {
        let set_cookie = response_headers.get("set-cookie")?;
        let prefix = format!("{}=", plugin.session.cookie_name);
        let cookie = set_cookie
            .split('\n')
            .find(|c| c.trim_start().starts_with(&prefix))?;
        let value = cookie.split(';').next()?.split_once('=')?.1;
        plugin.open_session(value)
    }

    fn sealed_cookie_value(set_cookie: &str) -> &str {
        set_cookie
            .split(';')
            .next()
            .and_then(|pair| pair.split_once('='))
            .map(|(_, value)| value)
            .expect("sealed cookie value")
    }

    #[tokio::test]
    async fn session_cookie_is_bound_to_provider_context_and_version() {
        let first = build_plugin_with_client("https://idp.example.com/token", "client-1");
        let second = build_plugin_with_client("https://idp.example.com/token", "client-2");
        assert_ne!(first.session.cookie_name, second.session.cookie_name);
        assert_ne!(first.session.context_id, second.session.context_id);

        let now = chrono::Utc::now().timestamp();
        let mut payload = session_payload(now - 10, now - 10, None, now + 1000);
        payload.context_id = first.session.context_id.clone();
        let first_cookie = first
            .seal_session_cookie(&payload)
            .expect("first context seals");
        assert!(
            second
                .open_session(sealed_cookie_value(&first_cookie))
                .is_none(),
            "a shared secret must not make cookies portable across client contexts"
        );

        payload.version = SESSION_PAYLOAD_VERSION.saturating_add(1);
        let wrong_version = first
            .seal_session_cookie(&payload)
            .expect("test payload seals");
        assert!(
            first
                .open_session(sealed_cookie_value(&wrong_version))
                .is_none(),
            "unknown payload versions must fail closed"
        );
    }

    fn flow_for(source_ip: &str, expires_at: Instant) -> FlowState {
        FlowState {
            code_verifier: "verifier".to_string(),
            nonce: "nonce".to_string(),
            original_url: "https://app.example.com/".to_string(),
            browser_binding_hash: [7; 32],
            source_ip: source_ip.to_string(),
            expires_at,
        }
    }

    #[test]
    fn state_cache_capacity_reservation_is_atomic_under_concurrency() {
        let cache = Arc::new(StateCache::new(10, 10, Duration::from_secs(600), 16));
        let mut workers = Vec::new();
        for idx in 0..40 {
            let cache = Arc::clone(&cache);
            workers.push(std::thread::spawn(move || {
                cache
                    .insert(
                        format!("state-{idx}"),
                        flow_for(
                            &format!("192.0.2.{idx}"),
                            Instant::now() + Duration::from_secs(60),
                        ),
                    )
                    .is_ok()
            }));
        }
        let admitted = workers
            .into_iter()
            .map(|worker| worker.join().expect("worker completes"))
            .filter(|admitted| *admitted)
            .count();

        assert_eq!(admitted, 10);
        assert_eq!(cache.active_entries.load(Ordering::Acquire), 10);
        assert_eq!(cache.entries.len(), 10);
    }

    #[test]
    fn state_cache_releases_global_and_source_capacity_on_take() {
        let cache = StateCache::new(1, 1, Duration::from_secs(600), 16);
        cache
            .insert(
                "first".to_string(),
                flow_for("192.0.2.1", Instant::now() + Duration::from_secs(60)),
            )
            .expect("first flow admitted");
        assert!(
            cache
                .insert(
                    "blocked".to_string(),
                    flow_for("192.0.2.2", Instant::now() + Duration::from_secs(60)),
                )
                .is_err()
        );
        assert!(cache.take("first").is_some());
        cache
            .insert(
                "replacement".to_string(),
                flow_for("192.0.2.1", Instant::now() + Duration::from_secs(60)),
            )
            .expect("released capacity is reusable");
    }

    fn discovery_config(discovery_url: &str) -> Value {
        json!({
            "providers": [{
                "issuer": "http://127.0.0.1:9",
                "discovery_url": discovery_url,
                "client_id": "client-1",
                "scopes": ["openid"],
                "redirect_uri": "http://localhost/oauth/callback",
                "callback_path": "/oauth/callback",
                "client_auth": {"method": "client_secret_basic", "client_secret": "secret"}
            }],
            "session": {
                "encryption_secret": "0123456789012345678901234567890123"
            }
        })
    }

    #[tokio::test]
    async fn validation_skips_workers_and_runtime_drop_aborts_discovery() {
        let config = discovery_config("http://127.0.0.1:9/.well-known/openid-configuration");
        let validated = OidcRelyingParty::new_internal(&config, PluginHttpClient::default(), false)
            .expect("shape-only validation succeeds");
        assert!(validated.discovery_task.is_none());
        assert!(validated.provider.jwks_store.load().is_none());
        validated
            .provider
            .jwks_store
            .store(Arc::new(Some(Arc::new(JwksKeyStore::new(
                "http://127.0.0.1:9/jwks".to_string(),
                PluginHttpClient::default(),
            )))));
        assert_eq!(
            validated.active_jwks_uris(),
            vec!["http://127.0.0.1:9/jwks".to_string()]
        );

        let runtime = OidcRelyingParty::new_internal(&config, PluginHttpClient::default(), true)
            .expect("runtime construction succeeds");
        let abort_handle = runtime
            .discovery_task
            .as_ref()
            .expect("runtime discovery task")
            .abort_handle();
        drop(runtime);
        for _ in 0..10 {
            if abort_handle.is_finished() {
                break;
            }
            tokio::task::yield_now().await;
        }
        assert!(abort_handle.is_finished());
    }

    // tokio runtime required: building the plugin spawns the background JWKS
    // refresh task even though maybe_slide_session itself is synchronous.
    #[tokio::test]
    async fn maybe_slide_respects_touch_interval() {
        // idle_ttl 1800 -> touch_interval 900.
        let plugin = build_plugin("https://idp.example.com/token");
        let now = 100_000;
        let mut stale = session_payload(now - 2000, now - 1000, None, now + 100_000);
        assert!(plugin.maybe_slide_session(&mut stale, now));
        assert_eq!(stale.last_touch_unix, now);

        let mut fresh = session_payload(now - 2000, now - 100, None, now + 100_000);
        assert!(!plugin.maybe_slide_session(&mut fresh, now));
        assert_eq!(fresh.last_touch_unix, now - 100);
    }

    #[tokio::test]
    async fn active_session_slides_and_emits_rolling_cookie() {
        let plugin = build_plugin("https://idp.example.com/token");
        let now = chrono::Utc::now().timestamp();
        // last_touch 1000s ago (> touch_interval 900) but within idle/absolute ttl;
        // no refresh token so only the slide path runs.
        let payload = session_payload(now - 1000, now - 1000, None, now + 100_000);
        let mut ctx = ctx_with_session(&plugin, &payload);
        assert!(matches!(
            plugin
                .authenticate(&mut ctx, &ConsumerIndex::new(&[]))
                .await,
            PluginResult::Continue
        ));
        let mut response_headers = HashMap::new();
        plugin
            .after_proxy(&mut ctx, 200, &mut response_headers)
            .await;
        let rolled = emitted_session_payload(&plugin, &response_headers)
            .expect("rolling session cookie emitted");
        assert!(rolled.last_touch_unix >= now);
    }

    #[tokio::test]
    async fn fresh_session_is_not_re_sealed() {
        let plugin = build_plugin("https://idp.example.com/token");
        let now = chrono::Utc::now().timestamp();
        let payload = session_payload(now - 100, now - 100, None, now + 100_000);
        let mut ctx = ctx_with_session(&plugin, &payload);
        assert!(matches!(
            plugin
                .authenticate(&mut ctx, &ConsumerIndex::new(&[]))
                .await,
            PluginResult::Continue
        ));
        let mut response_headers = HashMap::new();
        plugin
            .after_proxy(&mut ctx, 200, &mut response_headers)
            .await;
        assert!(!response_headers.contains_key("set-cookie"));
    }

    #[tokio::test]
    async fn idle_expired_session_challenges() {
        let plugin = build_plugin("https://idp.example.com/token");
        let now = chrono::Utc::now().timestamp();
        // last_touch 2000s ago > idle_ttl 1800 -> re-auth. Non-browser request -> 401.
        let payload = session_payload(now - 2500, now - 2000, None, now + 100_000);
        let mut ctx = ctx_with_session(&plugin, &payload);
        match plugin
            .authenticate(&mut ctx, &ConsumerIndex::new(&[]))
            .await
        {
            PluginResult::Reject { status_code, .. } => assert_eq!(status_code, 401),
            other => panic!("expected challenge reject, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn due_refresh_updates_tokens_and_re_seals() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/token"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "access_token": "new-at",
                "token_type": "Bearer",
                "refresh_token": "rt-2",
                "expires_in": 3600
            })))
            .mount(&server)
            .await;
        let plugin = build_plugin(&format!("{}/token", server.uri()));
        let now = chrono::Utc::now().timestamp();
        // refresh_after in the past -> due; refresh token present; session live.
        let payload = session_payload(now - 100, now - 100, Some("rt-1"), now - 10);
        let mut ctx = ctx_with_session(&plugin, &payload);
        assert!(matches!(
            plugin
                .authenticate(&mut ctx, &ConsumerIndex::new(&[]))
                .await,
            PluginResult::Continue
        ));
        let mut response_headers = HashMap::new();
        plugin
            .after_proxy(&mut ctx, 200, &mut response_headers)
            .await;
        let refreshed = emitted_session_payload(&plugin, &response_headers)
            .expect("refreshed session cookie emitted");
        assert_eq!(refreshed.access_token_b64, "new-at");
        assert_eq!(refreshed.refresh_token_b64.as_deref(), Some("rt-2"));
        assert!(refreshed.refresh_after_unix > now);
    }

    #[tokio::test]
    async fn oversized_provider_json_responses_are_rejected_before_deserialization() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/token"))
            .respond_with(ResponseTemplate::new(200).set_body_bytes(vec![
                b' ';
                MAX_TOKEN_RESPONSE_BYTES
                    + 1
            ]))
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path("/userinfo"))
            .respond_with(ResponseTemplate::new(200).set_body_bytes(vec![
                b' ';
                MAX_USERINFO_RESPONSE_BYTES
                    + 1
            ]))
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path("/.well-known/openid-configuration"))
            .respond_with(ResponseTemplate::new(200).set_body_bytes(vec![
                b' ';
                MAX_DISCOVERY_RESPONSE_BYTES
                    + 1
            ]))
            .mount(&server)
            .await;

        let plugin = build_plugin(&format!("{}/token", server.uri()));
        let discovery = plugin
            .provider
            .discovery
            .load()
            .as_ref()
            .as_ref()
            .cloned()
            .expect("explicit discovery document");
        assert!(
            plugin
                .exchange_code(&discovery, "code", "verifier")
                .await
                .is_err()
        );
        assert!(
            plugin
                .fetch_userinfo(&format!("{}/userinfo", server.uri()), "access-token")
                .await
                .is_err()
        );
        assert!(
            fetch_discovery(
                &PluginHttpClient::default(),
                &format!("{}/.well-known/openid-configuration", server.uri()),
            )
            .await
            .is_err()
        );
    }

    #[tokio::test]
    async fn expired_claims_with_refresh_without_id_token_re_challenge() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/token"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "access_token": "new-at",
                "token_type": "Bearer",
                "refresh_token": "rt-2",
                "expires_in": 3600
            })))
            .mount(&server)
            .await;
        let plugin = build_plugin(&format!("{}/token", server.uri()));
        let now = chrono::Utc::now().timestamp();
        let payload = session_payload(now - 2500, now - 100, Some("rt-1"), now - 200);
        assert!(payload.expires_at_unix < now - 60);
        let mut ctx = ctx_with_session(&plugin, &payload);

        match plugin
            .authenticate(&mut ctx, &ConsumerIndex::new(&[]))
            .await
        {
            PluginResult::Reject { status_code, .. } => assert_eq!(status_code, 401),
            other => panic!("expected challenge reject, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn failed_refresh_keeps_session_and_backs_off() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/token"))
            .respond_with(
                ResponseTemplate::new(400).set_body_json(json!({"error":"invalid_grant"})),
            )
            .mount(&server)
            .await;
        let plugin = build_plugin(&format!("{}/token", server.uri()));
        let now = chrono::Utc::now().timestamp();
        let payload = session_payload(now - 100, now - 100, Some("rt-1"), now - 10);
        let mut ctx = ctx_with_session(&plugin, &payload);
        // Refresh failure is non-fatal: the existing session still authenticates.
        assert!(matches!(
            plugin
                .authenticate(&mut ctx, &ConsumerIndex::new(&[]))
                .await,
            PluginResult::Continue
        ));
        let mut response_headers = HashMap::new();
        plugin
            .after_proxy(&mut ctx, 200, &mut response_headers)
            .await;
        let after = emitted_session_payload(&plugin, &response_headers)
            .expect("session re-sealed with deferred refresh");
        // Tokens unchanged, next refresh deferred so the IdP is not hammered.
        assert_eq!(after.access_token_b64, "old-at");
        assert_eq!(after.refresh_token_b64.as_deref(), Some("rt-1"));
        assert!(after.refresh_after_unix >= now + REFRESH_RETRY_BACKOFF_SECS - 5);
    }

    #[tokio::test]
    async fn after_proxy_preserves_backend_set_cookie() {
        let plugin = build_plugin("https://idp.example.com/token");
        let mut ctx = RequestContext::new("127.0.0.1".into(), "GET".into(), "/app".into());
        ctx.metadata.insert(
            SESSION_SET_COOKIE_METADATA_KEY.to_string(),
            "ferrum_session=rolled; Path=/; HttpOnly".to_string(),
        );
        let mut response_headers =
            HashMap::from([("set-cookie".to_string(), "backend=1; Path=/".to_string())]);
        plugin
            .after_proxy(&mut ctx, 200, &mut response_headers)
            .await;
        let value = response_headers
            .get("set-cookie")
            .expect("set-cookie present");
        assert!(value.contains("backend=1"));
        assert!(value.contains("ferrum_session=rolled"));
        assert!(value.contains('\n'), "cookies must be newline-joined");
        // Metadata is consumed so it does not linger into logging.
        assert!(!ctx.metadata.contains_key(SESSION_SET_COOKIE_METADATA_KEY));
    }

    fn sign_rs256(claims: &Value) -> String {
        use jsonwebtoken::{Algorithm, EncodingKey, Header, encode};
        let mut header = Header::new(Algorithm::RS256);
        header.kid = Some("test-key-1".to_string());
        encode(
            &header,
            claims,
            &EncodingKey::from_rsa_pem(include_bytes!("../../tests/fixtures/test_rsa_private.pem"))
                .unwrap(),
        )
        .unwrap()
    }

    /// Build an RS256 JWKS document from an SPKI public-key PEM fixture so the
    /// refresh path can validate a freshly signed ID token without a live IdP.
    fn rsa_jwks_from_public_pem(pem: &[u8]) -> Value {
        use base64::Engine;
        use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
        let pem = std::str::from_utf8(pem).unwrap();
        let der: Vec<u8> = STANDARD
            .decode(
                pem.lines()
                    .filter(|line| !line.starts_with("-----"))
                    .collect::<String>(),
            )
            .unwrap();
        let (n, e) = rsa_spki_modulus_exponent(&der);
        json!({"keys": [{
            "kty": "RSA",
            "kid": "test-key-1",
            "use": "sig",
            "alg": "RS256",
            "n": URL_SAFE_NO_PAD.encode(&n),
            "e": URL_SAFE_NO_PAD.encode(&e),
        }]})
    }

    fn rsa_spki_modulus_exponent(der: &[u8]) -> (Vec<u8>, Vec<u8>) {
        fn asn1_len(d: &[u8]) -> (usize, usize) {
            if d[0] < 0x80 {
                (d[0] as usize, 1)
            } else {
                let nb = (d[0] & 0x7f) as usize;
                let mut len = 0usize;
                for &b in &d[1..=nb] {
                    len = (len << 8) | b as usize;
                }
                (len, 1 + nb)
            }
        }
        let mut p = 0;
        assert_eq!(der[p], 0x30); // outer SEQUENCE
        p += 1;
        let (_, c) = asn1_len(&der[p..]);
        p += c;
        assert_eq!(der[p], 0x30); // AlgorithmIdentifier SEQUENCE
        p += 1;
        let (algo, c) = asn1_len(&der[p..]);
        p += c + algo;
        assert_eq!(der[p], 0x03); // BIT STRING
        p += 1;
        let (_, c) = asn1_len(&der[p..]);
        p += c + 1; // skip the unused-bits byte
        assert_eq!(der[p], 0x30); // RSAPublicKey SEQUENCE
        p += 1;
        let (_, c) = asn1_len(&der[p..]);
        p += c;
        assert_eq!(der[p], 0x02); // modulus INTEGER
        p += 1;
        let (n_len, c) = asn1_len(&der[p..]);
        p += c;
        let mut n = der[p..p + n_len].to_vec();
        p += n_len;
        if n.first() == Some(&0) {
            n.remove(0); // drop the ASN.1 sign byte
        }
        assert_eq!(der[p], 0x02); // exponent INTEGER
        p += 1;
        let (e_len, c) = asn1_len(&der[p..]);
        p += c;
        let e = der[p..p + e_len].to_vec();
        (n, e)
    }

    #[tokio::test]
    async fn id_token_validation_rejects_future_nbf_missing_sub_and_bad_azp() {
        let server = MockServer::start().await;
        let jwks =
            rsa_jwks_from_public_pem(include_bytes!("../../tests/fixtures/test_rsa_public.pem"));
        Mock::given(method("GET"))
            .and(path("/jwks"))
            .respond_with(ResponseTemplate::new(200).set_body_json(jwks))
            .mount(&server)
            .await;
        let plugin = OidcRelyingParty::new(
            &json!({
                "providers": [{
                    "issuer": "https://idp.example.com",
                    "client_id": "client-1",
                    "authorization_endpoint": "https://idp.example.com/authorize",
                    "token_endpoint": "https://idp.example.com/token",
                    "jwks_uri": format!("{}/jwks", server.uri()),
                    "scopes": ["openid"],
                    "redirect_uri": "https://app.example.com/oauth/callback",
                    "callback_path": "/oauth/callback",
                    "client_auth": {"method": "client_secret_basic", "client_secret": "shhh"}
                }],
                "session": {
                    "encryption_secret": "0123456789012345678901234567890123"
                }
            }),
            PluginHttpClient::default(),
        )
        .expect("OIDC config");
        let now = chrono::Utc::now().timestamp();

        let future_nbf = sign_rs256(&json!({
            "iss": "https://idp.example.com",
            "aud": "client-1",
            "sub": "user-1",
            "nonce": "nonce-1",
            "exp": now + 3600,
            "nbf": now + 600,
        }));
        assert!(
            plugin
                .verify_id_token(&future_nbf, "nonce-1")
                .await
                .is_err()
        );

        let missing_sub = sign_rs256(&json!({
            "iss": "https://idp.example.com",
            "aud": "client-1",
            "nonce": "nonce-1",
            "exp": now + 3600,
        }));
        assert!(
            plugin
                .verify_id_token(&missing_sub, "nonce-1")
                .await
                .is_err()
        );

        let wrong_azp = sign_rs256(&json!({
            "iss": "https://idp.example.com",
            "aud": ["client-1", "api://orders"],
            "azp": "other-client",
            "sub": "user-1",
            "nonce": "nonce-1",
            "exp": now + 3600,
        }));
        assert!(plugin.verify_id_token(&wrong_azp, "nonce-1").await.is_err());
    }

    #[tokio::test]
    async fn refresh_re_merges_userinfo_claims() {
        // Regression: a refresh that returns a new ID token must not drop claims
        // that only come from UserInfo (e.g. an `email` used in claim_headers).
        let now = chrono::Utc::now().timestamp();
        let jwks =
            rsa_jwks_from_public_pem(include_bytes!("../../tests/fixtures/test_rsa_public.pem"));
        let id_token = sign_rs256(&json!({
            "iss": "https://idp.example.com",
            "aud": "client-1",
            "sub": "user-1",
            "exp": now + 3600,
        }));

        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/token"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "access_token": "new-at",
                "token_type": "Bearer",
                "refresh_token": "rt-2",
                "expires_in": 3600,
                "id_token": id_token,
            })))
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path("/jwks"))
            .respond_with(ResponseTemplate::new(200).set_body_json(jwks))
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path("/userinfo"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "sub": "user-1",
                "email": "refreshed@example.com",
            })))
            .mount(&server)
            .await;

        let plugin = OidcRelyingParty::new(
            &json!({
                "providers": [{
                    "issuer": "https://idp.example.com",
                    "client_id": "client-1",
                    "authorization_endpoint": "https://idp.example.com/authorize",
                    "token_endpoint": format!("{}/token", server.uri()),
                    "jwks_uri": format!("{}/jwks", server.uri()),
                    "userinfo_endpoint": format!("{}/userinfo", server.uri()),
                    "scopes": ["openid", "offline_access"],
                    "redirect_uri": "https://app.example.com/oauth/callback",
                    "callback_path": "/oauth/callback",
                    "client_auth": {"method": "client_secret_basic", "client_secret": "shhh"},
                    "claim_headers": {"email": "X-User-Email"}
                }],
                "session": {
                    "encryption_secret": "0123456789012345678901234567890123",
                    "ttl_secs": 3600,
                    "idle_ttl_secs": 1800
                }
            }),
            PluginHttpClient::default(),
        )
        .expect("oidc plugin config is valid");

        // Session with no UserInfo claim yet and refresh due.
        let payload = session_payload(now - 100, now - 100, Some("rt-1"), now - 10);
        let mut ctx = ctx_with_session(&plugin, &payload);
        assert!(matches!(
            plugin
                .authenticate(&mut ctx, &ConsumerIndex::new(&[]))
                .await,
            PluginResult::Continue
        ));
        let mut response_headers = HashMap::new();
        plugin
            .after_proxy(&mut ctx, 200, &mut response_headers)
            .await;
        let refreshed = emitted_session_payload(&plugin, &response_headers)
            .expect("refreshed session cookie emitted");
        assert_eq!(
            refreshed.claims.get("email").and_then(Value::as_str),
            Some("refreshed@example.com"),
            "UserInfo-only claim must survive a token refresh"
        );
        assert_eq!(refreshed.access_token_b64, "new-at");
    }

    // Finding #6 regression: a session whose access/ID token has expired must not
    // keep serving cached claims when no refresh token is available. Before the
    // freshness gate this returned Continue (stale authorization) for the full
    // absolute ttl; now it re-challenges.
    #[tokio::test]
    async fn expired_token_without_refresh_token_re_challenges() {
        let plugin = build_plugin("https://idp.example.com/token");
        let now = chrono::Utc::now().timestamp();
        // Within absolute/idle ttl, but expires_at_unix is well past now+leeway
        // (default id_token_clock_skew is 60s; refresh_after + 30 = now - 170), and
        // there is no refresh token so maybe_refresh_session cannot refresh.
        let payload = session_payload(now - 100, now - 100, None, now - 200);
        assert!(
            payload.expires_at_unix < now - 60,
            "fixture must place the token past expiry + leeway"
        );
        let mut ctx = ctx_with_session(&plugin, &payload);
        match plugin
            .authenticate(&mut ctx, &ConsumerIndex::new(&[]))
            .await
        {
            // Non-browser request -> 401 challenge, cookie cleared.
            PluginResult::Reject {
                status_code,
                headers,
                ..
            } => {
                assert_eq!(status_code, 401);
                assert!(
                    headers
                        .get("set-cookie")
                        .is_some_and(|c| c.contains("Max-Age=0")),
                    "expired session cookie must be cleared on re-challenge"
                );
            }
            other => panic!("expected re-challenge on expired token, got {other:?}"),
        }
    }

    // Finding #6: a session still within token expiry keeps its
    // validly-verified-at-login behavior even without a refresh token.
    #[tokio::test]
    async fn unexpired_token_without_refresh_token_still_authenticates() {
        let plugin = build_plugin("https://idp.example.com/token");
        let now = chrono::Utc::now().timestamp();
        // expires_at_unix = now + 100_030 (refresh_after + 30), comfortably in future.
        let payload = session_payload(now - 100, now - 100, None, now + 100_000);
        assert!(payload.expires_at_unix > now);
        let mut ctx = ctx_with_session(&plugin, &payload);
        assert!(matches!(
            plugin
                .authenticate(&mut ctx, &ConsumerIndex::new(&[]))
                .await,
            PluginResult::Continue
        ));
    }

    // Finding #36 regression: during a discovery outage a browser challenge must
    // fail closed with 503 rather than 302-redirecting to the relative
    // post_login_default_path (the protected app root), which would loop. The
    // wasted state-cache slot must also be reclaimed.
    #[tokio::test]
    async fn browser_challenge_fails_closed_when_discovery_unavailable() {
        let plugin = build_plugin("https://idp.example.com/token");
        // Simulate a discovery outage: clear the loaded discovery snapshot.
        plugin.provider.discovery.store(Arc::new(None));
        let mut ctx = RequestContext::new("127.0.0.1".into(), "GET".into(), "/app".into());
        ctx.headers
            .insert("accept".to_string(), "text/html".to_string());
        let before = plugin.session.state_cache.entries.len();
        match plugin.challenge(&mut ctx, false) {
            PluginResult::Reject {
                status_code,
                body,
                headers,
            } => {
                assert_eq!(status_code, 503);
                assert_eq!(body, r#"{"error":"OIDC discovery unavailable"}"#);
                assert!(
                    !headers.contains_key("location"),
                    "must not redirect to the app root during a discovery outage"
                );
            }
            other => panic!("expected 503 fail-closed, got {other:?}"),
        }
        assert_eq!(
            plugin.session.state_cache.entries.len(),
            before,
            "the unused state slot must be reclaimed on the fail-closed path"
        );
    }

    // Finding #36: when discovery is loaded, a browser challenge still 302-redirects
    // to the absolute IdP authorization URL (no regression to the happy path).
    #[tokio::test]
    async fn browser_challenge_redirects_to_idp_when_discovery_loaded() {
        let plugin = build_plugin("https://idp.example.com/token");
        let mut ctx = RequestContext::new("127.0.0.1".into(), "GET".into(), "/app".into());
        ctx.headers
            .insert("accept".to_string(), "text/html".to_string());
        match plugin.challenge(&mut ctx, false) {
            PluginResult::Reject {
                status_code,
                headers,
                ..
            } => {
                assert_eq!(status_code, 302);
                let location = headers.get("location").expect("location header");
                assert!(
                    location.starts_with("https://idp.example.com/authorize?"),
                    "must redirect to the IdP authorization endpoint, got {location}"
                );
            }
            other => panic!("expected 302 redirect to IdP, got {other:?}"),
        }
    }

    // Finding #35: post_logout_redirect_uri is validated like the other endpoints.
    // tokio runtime required: building the plugin spawns the background JWKS task.
    #[tokio::test]
    async fn invalid_post_logout_redirect_uri_is_rejected_at_construction() {
        for bad in [
            "javascript:alert(1)",
            "/relative/path",
            "not a url",
            "http://", // no host
        ] {
            let result = OidcRelyingParty::new(
                &json!({
                    "providers": [{
                        "issuer": "https://idp.example.com",
                        "client_id": "client-1",
                        "authorization_endpoint": "https://idp.example.com/authorize",
                        "token_endpoint": "https://idp.example.com/token",
                        "jwks_uri": "https://idp.example.com/jwks",
                        "scopes": ["openid"],
                        "redirect_uri": "https://app.example.com/oauth/callback",
                        "callback_path": "/oauth/callback",
                        "post_logout_redirect_uri": bad,
                        "client_auth": {"method": "client_secret_basic", "client_secret": "shhh"}
                    }],
                    "session": {"encryption_secret": "0123456789012345678901234567890123"}
                }),
                PluginHttpClient::default(),
            );
            assert!(
                result.is_err(),
                "post_logout_redirect_uri {bad:?} should be rejected"
            );
        }
    }

    // Finding #35: a valid https post_logout_redirect_uri is accepted.
    #[tokio::test]
    async fn valid_post_logout_redirect_uri_is_accepted() {
        let result = OidcRelyingParty::new(
            &json!({
                "providers": [{
                    "issuer": "https://idp.example.com",
                    "client_id": "client-1",
                    "authorization_endpoint": "https://idp.example.com/authorize",
                    "token_endpoint": "https://idp.example.com/token",
                    "jwks_uri": "https://idp.example.com/jwks",
                    "scopes": ["openid"],
                    "redirect_uri": "https://app.example.com/oauth/callback",
                    "callback_path": "/oauth/callback",
                    "post_logout_redirect_uri": "https://app.example.com/goodbye",
                    "client_auth": {"method": "client_secret_basic", "client_secret": "shhh"}
                }],
                "session": {"encryption_secret": "0123456789012345678901234567890123"}
            }),
            PluginHttpClient::default(),
        );
        assert!(
            result.is_ok(),
            "valid https post_logout_redirect_uri should be accepted"
        );
    }
}
