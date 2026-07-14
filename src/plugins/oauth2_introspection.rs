use std::collections::HashMap;
use std::fmt;
use std::net::IpAddr;
use std::sync::{Arc, Mutex, OnceLock};
use std::time::{Duration, Instant};

use arc_swap::ArcSwap;
use async_trait::async_trait;
use base64::Engine as _;
use dashmap::DashMap;
use http::HeaderValue;
use http::header::{AUTHORIZATION, HeaderName};
use jsonwebtoken::{Algorithm, EncodingKey, Header, encode};
use serde_json::{Map, Value, json};
use tokio::sync::{OnceCell, Semaphore};
use tracing::{debug, info, warn};
use url::{Host, Url};

use crate::consumer_index::ConsumerIndex;

use super::utils::PluginHttpClient;
use super::utils::auth_flow::{ExtractedCredential, VerifyOutcome};
use super::utils::claim_header_fanout::{
    ClaimHeaderMapping, apply_claim_headers_from_context, emit_claim_headers_to_context,
    parse_claim_headers,
};
use super::utils::claim_resolver::{extract_claim_string, parse_claim_path_value};
use super::utils::introspection_cache::{CacheLookup, IntrospectionCache, TokenKey};
use super::utils::response_body::read_response_body_bounded;
use super::utils::scope_role_check::{self, ScopeRoleRequirements};
use super::utils::token_extract::{
    STRIP_QUERY_PARAM_METADATA_PREFIX, TokenHeaderLocation, TokenLocation, TokenLocationExtract,
    extract_authorization_bearer, extract_from_location,
};
use super::{PluginResult, RequestContext};

const STRIP_AUTHORIZATION_METADATA_KEY: &str = "oauth2_introspection.strip_authorization";
const STRIP_HEADER_METADATA_PREFIX: &str = "oauth2_introspection.strip_header.";
const CLAIM_HEADER_METADATA_PREFIX: &str = "oauth2_introspection.claim_header.";
const MAX_PROVIDERS: usize = 16;
const MAX_TOKEN_BYTES: usize = 8 * 1024;
const MAX_INTROSPECTION_RESPONSE_BYTES: usize = 64 * 1024;
const MAX_DISCOVERY_RESPONSE_BYTES: usize = 128 * 1024;
const MAX_PROVIDER_CONCURRENT_INTROSPECTIONS: usize = 32;
const MAX_GLOBAL_CONCURRENT_INTROSPECTIONS: usize = 128;

static GLOBAL_INTROSPECTION_LIMIT: OnceLock<Arc<Semaphore>> = OnceLock::new();

fn global_introspection_limit() -> Arc<Semaphore> {
    Arc::clone(
        GLOBAL_INTROSPECTION_LIMIT
            .get_or_init(|| Arc::new(Semaphore::new(MAX_GLOBAL_CONCURRENT_INTROSPECTIONS))),
    )
}

type InFlightResult = Result<Arc<Value>, IntrospectionDecision>;
type InFlightCell = OnceCell<InFlightResult>;

struct InFlightEntryGuard {
    entries: Arc<DashMap<TokenKey, Arc<InFlightCell>>>,
    key: TokenKey,
    cell: Arc<InFlightCell>,
}

impl Drop for InFlightEntryGuard {
    fn drop(&mut self) {
        self.entries
            .remove_if(&self.key, |_, current| Arc::ptr_eq(current, &self.cell));
    }
}

pub struct Oauth2Introspection {
    providers: Vec<IntrospectionProvider>,
    http_client: PluginHttpClient,
    global_introspection_limit: Arc<Semaphore>,
    global_scope_claim: String,
    global_role_claim: String,
    consumer_identity_claim: String,
    consumer_header_claim: String,
    strip_authorization_on_success: bool,
    has_custom_query_token_locations: bool,
    allow_provider_fanout: bool,
    discovery_tasks: Mutex<Option<Vec<tokio::task::JoinHandle<()>>>>,
}

struct IntrospectionProvider {
    issuer: Option<String>,
    introspection_endpoint: Arc<ArcSwap<Option<String>>>,
    discovery_url: Option<String>,
    assertion_audience: Option<String>,
    audiences: Vec<String>,
    token_locations: Vec<TokenLocation>,
    required_scopes: Vec<String>,
    required_roles: Vec<String>,
    scope_claim: Option<String>,
    role_claim: Option<String>,
    consumer_identity_claim: Option<String>,
    consumer_header_claim: Option<String>,
    forward_original_token: bool,
    client_auth: ClientAuth,
    cache: Arc<IntrospectionCache>,
    request_timeout: Duration,
    token_hint_param: Option<String>,
    claim_headers: Vec<ClaimHeaderMapping>,
    warmup_hostnames: Vec<String>,
    introspection_limit: Arc<Semaphore>,
    in_flight: Arc<DashMap<TokenKey, Arc<InFlightCell>>>,
}

enum ClientAuth {
    Basic {
        authorization: HeaderValue,
    },
    Post {
        client_id: String,
        client_secret: SecretString,
    },
    PrivateKeyJwt {
        client_id: String,
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

impl Drop for Oauth2Introspection {
    fn drop(&mut self) {
        let tasks = match self.discovery_tasks.get_mut() {
            Ok(tasks) => tasks,
            Err(poisoned) => poisoned.into_inner(),
        };
        if let Some(tasks) = tasks.take() {
            for task in tasks {
                task.abort();
            }
        }
    }
}

enum Oauth2ExtractedCredential {
    BearerToken {
        token: String,
        candidates: Vec<ProviderCandidate>,
    },
    InvalidFormat(String),
    Missing,
}

#[derive(Clone, Copy)]
struct ProviderCandidate {
    provider_idx: usize,
    source: CredentialSource,
}

#[derive(Clone, Copy)]
enum CredentialSource {
    Authorization,
    ProviderLocation(usize),
}

impl Oauth2Introspection {
    pub fn new(config: &Value, http_client: PluginHttpClient) -> Result<Self, String> {
        let config_obj = config.as_object().ok_or_else(|| {
            format!("oauth2_introspection: config must be an object, got: {config}")
        })?;
        reject_unknown_keys(
            config_obj,
            &[
                "providers",
                "scope_claim",
                "role_claim",
                "consumer_identity_claim",
                "consumer_header_claim",
                "allow_provider_fanout",
            ],
            "oauth2_introspection",
        )?;
        let allow_provider_fanout =
            optional_top_level_bool(config_obj, "allow_provider_fanout", "oauth2_introspection")?
                .unwrap_or(false);
        let global_scope_claim =
            optional_claim_path(config_obj, "scope_claim", "scope", "oauth2_introspection")?;
        let global_role_claim =
            optional_claim_path(config_obj, "role_claim", "roles", "oauth2_introspection")?;
        let consumer_identity_claim = optional_claim_path(
            config_obj,
            "consumer_identity_claim",
            "username",
            "oauth2_introspection",
        )?;
        let consumer_header_claim = match config_obj.get("consumer_header_claim") {
            Some(value) => {
                parse_claim_path_value("consumer_header_claim", value, "oauth2_introspection")?
            }
            None => consumer_identity_claim.clone(),
        };

        let providers_val = config_obj.get("providers").unwrap_or(&Value::Null);
        let Some(providers_arr) = providers_val.as_array() else {
            return Err("oauth2_introspection: 'providers' must be a non-empty array".to_string());
        };
        if providers_arr.is_empty() {
            return Err("oauth2_introspection: 'providers' array must not be empty".to_string());
        }
        if providers_arr.len() > MAX_PROVIDERS {
            return Err(format!(
                "oauth2_introspection: 'providers' must contain at most {MAX_PROVIDERS} entries"
            ));
        }

        let shard_amount = http_client.pool_shard_amount();
        let mut providers = Vec::with_capacity(providers_arr.len());
        for (idx, prov_cfg) in providers_arr.iter().enumerate() {
            let prov_obj = prov_cfg.as_object().ok_or_else(|| {
                format!("oauth2_introspection: provider[{idx}] must be an object, got: {prov_cfg}")
            })?;
            reject_unknown_keys(
                prov_obj,
                &[
                    "introspection_endpoint",
                    "discovery_url",
                    "issuer",
                    "audiences",
                    "client_auth",
                    "from_headers",
                    "from_params",
                    "forward_original_token",
                    "positive_cache_ttl_secs",
                    "negative_cache_ttl_secs",
                    "request_timeout_ms",
                    "max_cache_entries",
                    "token_hint_param",
                    "required_scopes",
                    "required_roles",
                    "scope_claim",
                    "role_claim",
                    "consumer_identity_claim",
                    "consumer_header_claim",
                    "claim_headers",
                ],
                &format!("oauth2_introspection: provider[{idx}]"),
            )?;

            let endpoint = parse_url_field(prov_obj, "introspection_endpoint", idx)?;
            let discovery = parse_url_field(prov_obj, "discovery_url", idx)?;
            if endpoint.is_none() && discovery.is_none() {
                return Err(format!(
                    "oauth2_introspection: provider[{idx}] requires 'introspection_endpoint' or 'discovery_url'"
                ));
            }
            if endpoint.is_some() && discovery.is_some() {
                return Err(format!(
                    "oauth2_introspection: provider[{idx}] must not configure both 'introspection_endpoint' and 'discovery_url'"
                ));
            }

            let issuer = optional_non_empty_string(prov_obj, "issuer", idx)?;
            // Canonicalize audiences so equivalent policies behave identically.
            let mut audiences = parse_string_array(prov_obj, "audiences", idx)?;
            audiences.sort();
            audiences.dedup();
            let required_scopes = parse_string_array(prov_obj, "required_scopes", idx)?;
            let required_roles = parse_string_array(prov_obj, "required_roles", idx)?;
            let scope_claim = optional_provider_claim_path(prov_obj, "scope_claim", idx)?;
            let role_claim = optional_provider_claim_path(prov_obj, "role_claim", idx)?;
            let consumer_identity_claim =
                optional_provider_claim_path(prov_obj, "consumer_identity_claim", idx)?;
            let consumer_header_claim =
                optional_provider_claim_path(prov_obj, "consumer_header_claim", idx)?;
            let token_locations = parse_token_locations(prov_obj, idx)?;
            let forward_original_token =
                optional_provider_bool(prov_obj, "forward_original_token", idx)?.unwrap_or(true);
            let positive_cache_ttl_secs =
                ranged_provider_u64(prov_obj, "positive_cache_ttl_secs", idx, 60, 0, 86_400)?;
            let negative_cache_ttl_secs =
                ranged_provider_u64(prov_obj, "negative_cache_ttl_secs", idx, 10, 0, 300)?;
            let request_timeout_ms =
                ranged_provider_u64(prov_obj, "request_timeout_ms", idx, 5_000, 100, 30_000)?;
            let max_cache_entries =
                ranged_provider_usize(prov_obj, "max_cache_entries", idx, 10_000, 100, 1_000_000)?;
            let token_hint_param = optional_nullable_string(prov_obj, "token_hint_param", idx)?;
            let claim_headers = parse_claim_headers(
                prov_obj,
                "claim_headers",
                "oauth2_introspection",
                CLAIM_HEADER_METADATA_PREFIX,
            )?;
            let client_auth =
                parse_client_auth(prov_obj, idx, endpoint.as_ref().or(discovery.as_ref()))?;

            let endpoint_slot = Arc::new(ArcSwap::from_pointee(
                endpoint.as_ref().map(|parsed| parsed.url.clone()),
            ));
            let cache = Arc::new(IntrospectionCache::new(
                max_cache_entries,
                Duration::from_secs(positive_cache_ttl_secs),
                Duration::from_secs(negative_cache_ttl_secs),
                shard_amount,
            ));
            let mut warmup_hostnames = Vec::new();
            if let Some(endpoint) = endpoint.as_ref() {
                warmup_hostnames.push(endpoint.hostname.clone());
            }
            if let Some(discovery) = discovery.as_ref()
                && !warmup_hostnames
                    .iter()
                    .any(|host| host == &discovery.hostname)
            {
                warmup_hostnames.push(discovery.hostname.clone());
            }

            providers.push(IntrospectionProvider {
                assertion_audience: issuer.clone(),
                issuer,
                introspection_endpoint: endpoint_slot,
                discovery_url: discovery.as_ref().map(|parsed| parsed.url.clone()),
                audiences,
                token_locations,
                required_scopes,
                required_roles,
                scope_claim,
                role_claim,
                consumer_identity_claim,
                consumer_header_claim,
                forward_original_token,
                client_auth,
                cache,
                request_timeout: Duration::from_millis(request_timeout_ms),
                token_hint_param,
                claim_headers,
                warmup_hostnames,
                introspection_limit: Arc::new(Semaphore::new(
                    MAX_PROVIDER_CONCURRENT_INTROSPECTIONS,
                )),
                in_flight: Arc::new(DashMap::with_shard_amount(shard_amount)),
            });
        }

        if !allow_provider_fanout {
            let mut location_owners: HashMap<String, usize> = HashMap::new();
            for (provider_idx, provider) in providers.iter().enumerate() {
                if provider.token_locations.is_empty() {
                    register_provider_location(
                        &mut location_owners,
                        "authorization-bearer".to_string(),
                        provider_idx,
                    )?;
                }
                for location in &provider.token_locations {
                    register_provider_location(
                        &mut location_owners,
                        token_location_routing_key(location),
                        provider_idx,
                    )?;
                }
            }
        }

        let strip_authorization_on_success = providers
            .iter()
            .any(|provider| !provider.forward_original_token);
        let has_custom_query_token_locations = providers.iter().any(|provider| {
            provider
                .token_locations
                .iter()
                .any(|location| matches!(location, TokenLocation::QueryParam(_)))
        });

        Ok(Self {
            providers,
            http_client,
            global_introspection_limit: global_introspection_limit(),
            global_scope_claim,
            global_role_claim,
            consumer_identity_claim,
            consumer_header_claim,
            strip_authorization_on_success,
            has_custom_query_token_locations,
            allow_provider_fanout,
            discovery_tasks: Mutex::new(None),
        })
    }

    async fn authenticate_request(
        &self,
        ctx: &mut RequestContext,
        consumer_index: &ConsumerIndex,
    ) -> PluginResult {
        match self.extract_credential(ctx) {
            Oauth2ExtractedCredential::Missing => {
                debug!("oauth2_introspection: no credential present");
                PluginResult::Continue
            }
            Oauth2ExtractedCredential::InvalidFormat(body) => {
                reject_bearer(401, body, "invalid_request")
            }
            Oauth2ExtractedCredential::BearerToken { token, candidates } => {
                if token.len() > MAX_TOKEN_BYTES {
                    return reject_bearer(
                        401,
                        r#"{"error":"Bearer token exceeds maximum length"}"#.to_string(),
                        "invalid_request",
                    );
                }
                let (claims, candidate) = match self.validate_token(&token, &candidates).await {
                    Ok(result) => result,
                    Err(rejection) => return rejection.into_plugin_result(),
                };
                let provider = &self.providers[candidate.provider_idx];
                if let Err((status, body)) = self.check_claims_authorization(&claims, provider) {
                    return reject(status, body);
                }
                self.emit_claim_headers(ctx, &claims, provider);
                if !provider.forward_original_token {
                    self.mark_original_token_stripping_metadata(ctx, &token, candidate);
                }
                let outcome = self.resolve_identity(&claims, provider, consumer_index);
                apply_verify_outcome(ctx, outcome, "oauth2_introspection")
            }
        }
    }

    async fn validate_token(
        &self,
        token: &str,
        candidates: &[ProviderCandidate],
    ) -> Result<(Arc<Value>, ProviderCandidate), IntrospectionRejection> {
        // Fan-out is only reachable after explicit shared-trust opt-in or when
        // the request carried the same token in multiple provider-specific
        // locations. If no provider accepts, an unavailable candidate takes
        // precedence: that provider might have accepted the token if healthy,
        // so reporting an authoritative invalid-token result would be false.
        let mut first_auth_error: Option<IntrospectionDecision> = None;
        let mut provider_unavailable = false;
        for &candidate in candidates {
            let Some(provider) = self.providers.get(candidate.provider_idx) else {
                continue;
            };
            match self
                .introspect_with_provider(token, provider, candidate.provider_idx)
                .await
            {
                Ok(claims) => return Ok((claims, candidate)),
                Err(IntrospectionDecision::Unavailable) => provider_unavailable = true,
                Err(decision) => {
                    if first_auth_error.is_none() {
                        first_auth_error = Some(decision);
                    }
                }
            }
        }
        if provider_unavailable {
            return Err(IntrospectionDecision::Unavailable.into_rejection());
        }
        Err(first_auth_error
            .unwrap_or_else(|| {
                IntrospectionDecision::Unauthorized(
                    r#"{"error":"Invalid or unrecognized token"}"#.to_string(),
                )
            })
            .into_rejection())
    }

    async fn introspect_with_provider(
        &self,
        token: &str,
        provider: &IntrospectionProvider,
        provider_idx: usize,
    ) -> Result<Arc<Value>, IntrospectionDecision> {
        let now = Instant::now();
        match provider.cache.get(token, now) {
            CacheLookup::Active(claims) => return Ok(claims),
            CacheLookup::Negative => return Err(IntrospectionDecision::Inactive),
            CacheLookup::Miss => {}
        }

        let token_key = TokenKey::from_token(token);
        let proposed = Arc::new(InFlightCell::new());
        let cell = provider
            .in_flight
            .entry(token_key.clone())
            .or_insert_with(|| Arc::clone(&proposed))
            .clone();
        let _cleanup = Arc::ptr_eq(&cell, &proposed).then(|| InFlightEntryGuard {
            entries: Arc::clone(&provider.in_flight),
            key: token_key,
            cell: Arc::clone(&cell),
        });
        cell.get_or_init(|| self.introspect_uncached(token, provider, provider_idx))
            .await
            .clone()
    }

    async fn introspect_uncached(
        &self,
        token: &str,
        provider: &IntrospectionProvider,
        provider_idx: usize,
    ) -> Result<Arc<Value>, IntrospectionDecision> {
        let now = Instant::now();
        // Another completed request can populate the cache between the caller's
        // initial lookup and installation of a new in-flight cell.
        match provider.cache.get(token, now) {
            CacheLookup::Active(claims) => return Ok(claims),
            CacheLookup::Negative => return Err(IntrospectionDecision::Inactive),
            CacheLookup::Miss => {}
        }

        let guard = provider.introspection_endpoint.load();
        let Some(endpoint) = guard.as_ref().as_ref().cloned() else {
            warn!(
                plugin = "oauth2_introspection",
                provider_idx, "introspection endpoint unresolved"
            );
            return Err(IntrospectionDecision::Unavailable);
        };

        let _provider_permit = provider
            .introspection_limit
            .clone()
            .try_acquire_owned()
            .map_err(|_| {
                warn!(
                    plugin = "oauth2_introspection",
                    provider_idx, "provider introspection concurrency limit reached"
                );
                IntrospectionDecision::Unavailable
            })?;
        let _global_permit = self
            .global_introspection_limit
            .clone()
            .try_acquire_owned()
            .map_err(|_| {
                warn!(
                    plugin = "oauth2_introspection",
                    provider_idx, "global introspection concurrency limit reached"
                );
                IntrospectionDecision::Unavailable
            })?;

        let mut params: Vec<(String, String)> = vec![("token".to_string(), token.to_string())];
        if let Some(hint) = &provider.token_hint_param {
            params.push(("token_type_hint".to_string(), hint.clone()));
        }
        let request = match &provider.client_auth {
            ClientAuth::Basic { authorization } => self
                .http_client
                .get()
                .post(&endpoint)
                .timeout(provider.request_timeout)
                .header(AUTHORIZATION, authorization.clone())
                .with_form_body(&params)?,
            ClientAuth::Post {
                client_id,
                client_secret,
            } => {
                params.push(("client_id".to_string(), client_id.clone()));
                params.push((
                    "client_secret".to_string(),
                    client_secret.expose().to_string(),
                ));
                self.http_client
                    .get()
                    .post(&endpoint)
                    .timeout(provider.request_timeout)
                    .with_form_body(&params)?
            }
            ClientAuth::PrivateKeyJwt {
                client_id,
                encoding_key,
                alg,
                kid,
            } => {
                let assertion_audience = provider
                    .assertion_audience
                    .as_deref()
                    .unwrap_or(endpoint.as_str());
                let assertion =
                    build_client_assertion(client_id, assertion_audience, encoding_key, *alg, kid)
                        .map_err(|_| IntrospectionDecision::Unavailable)?;
                params.push(("client_id".to_string(), client_id.clone()));
                params.push((
                    "client_assertion_type".to_string(),
                    "urn:ietf:params:oauth:client-assertion-type:jwt-bearer".to_string(),
                ));
                params.push(("client_assertion".to_string(), assertion));
                self.http_client
                    .get()
                    .post(&endpoint)
                    .timeout(provider.request_timeout)
                    .with_form_body(&params)?
            }
            ClientAuth::None => self
                .http_client
                .get()
                .post(&endpoint)
                .timeout(provider.request_timeout)
                .with_form_body(&params)?,
        };

        let response = self
            .http_client
            .execute(request, "oauth2_introspection")
            .await
            .map_err(|e| {
                warn!(
                    plugin = "oauth2_introspection",
                    provider_idx,
                    error_class = %crate::retry::classify_reqwest_error(&e),
                    "token introspection transport failure"
                );
                IntrospectionDecision::Unavailable
            })?;
        if !response.status().is_success() {
            warn!(
                plugin = "oauth2_introspection",
                provider_idx,
                status = response.status().as_u16(),
                "token introspection endpoint returned non-success"
            );
            return Err(IntrospectionDecision::Unavailable);
        }
        let body = read_response_body_bounded(response, MAX_INTROSPECTION_RESPONSE_BYTES)
            .await
            .map_err(|e| {
                warn!(
                    plugin = "oauth2_introspection",
                    provider_idx,
                    error = %e,
                    "token introspection response body read failed"
                );
                IntrospectionDecision::Unavailable
            })?;
        let claims: Value = serde_json::from_slice(&body).map_err(|e| {
            warn!(
                plugin = "oauth2_introspection",
                provider_idx,
                error = %e,
                "token introspection response parse failed"
            );
            IntrospectionDecision::Unavailable
        })?;
        match claims.get("active").and_then(Value::as_bool) {
            Some(true) => {}
            Some(false) => {
                provider.cache.insert_negative(token, now);
                return Err(IntrospectionDecision::Inactive);
            }
            None => {
                warn!(
                    plugin = "oauth2_introspection",
                    provider_idx,
                    "token introspection response has a missing or non-boolean active member"
                );
                return Err(IntrospectionDecision::Unavailable);
            }
        }
        if claims.get("cnf").is_some() {
            return Err(IntrospectionDecision::Unauthorized(
                r#"{"error":"Sender-constrained tokens are not supported"}"#.to_string(),
            ));
        }
        match claims.get("token_type") {
            None => {}
            Some(Value::String(token_type)) if token_type.eq_ignore_ascii_case("bearer") => {}
            Some(Value::String(_)) => {
                return Err(IntrospectionDecision::Unauthorized(
                    r#"{"error":"Unsupported introspected token type"}"#.to_string(),
                ));
            }
            Some(_) => {
                warn!(
                    plugin = "oauth2_introspection",
                    provider_idx, "token introspection response has a non-string token_type member"
                );
                return Err(IntrospectionDecision::Unavailable);
            }
        }
        if let Some(issuer) = &provider.issuer
            && claims.get("iss").and_then(Value::as_str) != Some(issuer.as_str())
        {
            return Err(IntrospectionDecision::Unauthorized(
                r#"{"error":"Invalid token issuer"}"#.to_string(),
            ));
        }
        if !audience_matches(&claims, &provider.audiences) {
            return Err(IntrospectionDecision::Unauthorized(
                r#"{"error":"Invalid token audience"}"#.to_string(),
            ));
        }
        let exp = claims.get("exp").and_then(Value::as_i64);
        let claims = Arc::new(claims);
        provider
            .cache
            .insert_active(token, claims.clone(), now, exp);
        Ok(claims)
    }

    fn check_claims_authorization(
        &self,
        claims: &Value,
        provider: &IntrospectionProvider,
    ) -> Result<(), (u16, String)> {
        let scope_claim = provider
            .scope_claim
            .as_deref()
            .unwrap_or(&self.global_scope_claim);
        let role_claim = provider
            .role_claim
            .as_deref()
            .unwrap_or(&self.global_role_claim);
        scope_role_check::check(
            claims,
            &ScopeRoleRequirements {
                required_scopes: &provider.required_scopes,
                required_roles: &provider.required_roles,
                scope_claim,
                role_claim,
                plugin_name: "oauth2_introspection",
            },
        )
    }

    fn resolve_identity(
        &self,
        claims: &Value,
        provider: &IntrospectionProvider,
        consumer_index: &ConsumerIndex,
    ) -> VerifyOutcome {
        let identity_claim = provider
            .consumer_identity_claim
            .as_deref()
            .unwrap_or(&self.consumer_identity_claim);
        let header_claim = provider
            .consumer_header_claim
            .as_deref()
            .unwrap_or(&self.consumer_header_claim);
        let identity = extract_claim_string(claims, identity_claim);
        let header_value = if header_claim == identity_claim {
            identity.clone()
        } else {
            extract_claim_string(claims, header_claim).or_else(|| identity.clone())
        };
        let consumer = identity
            .as_deref()
            .and_then(|id| consumer_index.find_by_identity(id));
        VerifyOutcome::success(consumer, identity, header_value)
    }

    fn emit_claim_headers(
        &self,
        ctx: &mut RequestContext,
        claims: &Value,
        provider: &IntrospectionProvider,
    ) {
        if provider.claim_headers.is_empty() {
            return;
        }
        emit_claim_headers_to_context(ctx, claims, &provider.claim_headers, ",");
    }

    fn mark_original_token_stripping_metadata(
        &self,
        ctx: &mut RequestContext,
        accepted_token: &str,
        candidate: ProviderCandidate,
    ) {
        let Some(provider) = self.providers.get(candidate.provider_idx) else {
            warn!(
                plugin = "oauth2_introspection",
                provider_idx = candidate.provider_idx,
                "accepted token provider no longer exists"
            );
            return;
        };
        mark_credential_source_stripping_metadata(ctx, provider, candidate.source);

        // A client can repeat one credential in several supported locations.
        // Stripping only the location selected during routing would leave an
        // equivalent copy available to the backend, so remove every configured
        // occurrence of the accepted token while preserving unrelated values.
        if authorization_bearer_matches(ctx, accepted_token) {
            mark_authorization_stripping_metadata(ctx);
        }
        for provider in &self.providers {
            for location in &provider.token_locations {
                if token_location_matches(location, ctx, accepted_token) {
                    mark_token_location_stripping_metadata(ctx, location);
                }
            }
        }
    }

    fn extract_credential(&self, ctx: &RequestContext) -> Oauth2ExtractedCredential {
        let mut first_invalid_format = None;
        for (idx, provider) in self.providers.iter().enumerate() {
            for (location_idx, location) in provider.token_locations.iter().enumerate() {
                match extract_provider_token_location(location, ctx) {
                    TokenLocationExtract::Missing => {}
                    TokenLocationExtract::Credential(ExtractedCredential::InvalidFormat(body)) => {
                        first_invalid_format.get_or_insert(body);
                    }
                    TokenLocationExtract::Credential(ExtractedCredential::BearerToken(token)) => {
                        if self.allow_provider_fanout && is_authorization_bearer_location(location)
                        {
                            let candidates = self
                                .providers
                                .iter()
                                .enumerate()
                                .map(|(provider_idx, provider)| ProviderCandidate {
                                    provider_idx,
                                    source: provider_location_extracting_token(
                                        &provider.token_locations,
                                        ctx,
                                        &token,
                                    )
                                    .map(CredentialSource::ProviderLocation)
                                    .unwrap_or(CredentialSource::Authorization),
                                })
                                .collect();
                            return Oauth2ExtractedCredential::BearerToken { token, candidates };
                        }
                        let mut candidates = vec![ProviderCandidate {
                            provider_idx: idx,
                            source: CredentialSource::ProviderLocation(location_idx),
                        }];
                        if self.allow_provider_fanout {
                            for (other_idx, other_provider) in self.providers.iter().enumerate() {
                                if other_idx != idx
                                    && let Some(other_location_idx) =
                                        provider_location_extracting_token(
                                            &other_provider.token_locations,
                                            ctx,
                                            &token,
                                        )
                                {
                                    candidates.push(ProviderCandidate {
                                        provider_idx: other_idx,
                                        source: CredentialSource::ProviderLocation(
                                            other_location_idx,
                                        ),
                                    });
                                }
                            }
                        }
                        candidates.sort_unstable_by_key(|candidate| candidate.provider_idx);
                        candidates.dedup_by_key(|candidate| candidate.provider_idx);
                        return Oauth2ExtractedCredential::BearerToken { token, candidates };
                    }
                    TokenLocationExtract::Credential(_) => {}
                }
            }
        }

        match extract_authorization_bearer(ctx) {
            ExtractedCredential::Missing => first_invalid_format
                .map(Oauth2ExtractedCredential::InvalidFormat)
                .unwrap_or(Oauth2ExtractedCredential::Missing),
            ExtractedCredential::InvalidFormat(body) => first_invalid_format
                .map(Oauth2ExtractedCredential::InvalidFormat)
                .unwrap_or(Oauth2ExtractedCredential::InvalidFormat(body)),
            ExtractedCredential::BearerToken(token) => {
                let provider_indices: Vec<usize> = if self.allow_provider_fanout {
                    (0..self.providers.len()).collect()
                } else {
                    self.providers
                        .iter()
                        .enumerate()
                        .filter_map(|(idx, provider)| {
                            provider.token_locations.is_empty().then_some(idx)
                        })
                        .collect()
                };
                let provider_indices = if provider_indices.is_empty() && self.providers.len() == 1 {
                    vec![0]
                } else {
                    provider_indices
                };
                if provider_indices.is_empty() {
                    return Oauth2ExtractedCredential::InvalidFormat(
                        r#"{"error":"Bearer token does not identify an introspection provider"}"#
                            .to_string(),
                    );
                }
                Oauth2ExtractedCredential::BearerToken {
                    token,
                    candidates: provider_indices
                        .into_iter()
                        .map(|provider_idx| ProviderCandidate {
                            provider_idx,
                            source: CredentialSource::Authorization,
                        })
                        .collect(),
                }
            }
            _ => Oauth2ExtractedCredential::Missing,
        }
    }
}

fn provider_location_extracting_token(
    token_locations: &[TokenLocation],
    ctx: &RequestContext,
    expected_token: &str,
) -> Option<usize> {
    token_locations
        .iter()
        .enumerate()
        .find_map(
            |(location_idx, location)| match extract_provider_token_location(location, ctx) {
                TokenLocationExtract::Credential(ExtractedCredential::BearerToken(token))
                    if token == expected_token =>
                {
                    Some(location_idx)
                }
                _ => None,
            },
        )
}

fn extract_provider_token_location(
    location: &TokenLocation,
    ctx: &RequestContext,
) -> TokenLocationExtract {
    if is_authorization_bearer_location(location) {
        return match extract_authorization_bearer(ctx) {
            ExtractedCredential::Missing => TokenLocationExtract::Missing,
            credential => TokenLocationExtract::Credential(credential),
        };
    }
    extract_from_location(location, ctx)
}

fn register_provider_location(
    location_owners: &mut HashMap<String, usize>,
    key: String,
    provider_idx: usize,
) -> Result<(), String> {
    if let Some(previous_provider_idx) = location_owners.insert(key, provider_idx)
        && previous_provider_idx != provider_idx
    {
        return Err(
            "oauth2_introspection: provider token locations must be distinct unless 'allow_provider_fanout' explicitly enables a shared trust boundary"
                .to_string(),
        );
    }
    Ok(())
}

fn token_location_routing_key(location: &TokenLocation) -> String {
    match location {
        TokenLocation::Header(_) if is_authorization_bearer_location(location) => {
            "authorization-bearer".to_string()
        }
        TokenLocation::Header(header) => {
            let prefix = header.prefix.as_deref().unwrap_or("");
            let mut key = String::with_capacity(
                "header:".len() + header.name.len() + prefix.len().saturating_add(1),
            );
            key.push_str("header:");
            key.push_str(&header.name);
            key.push(':');
            key.push_str(prefix);
            key
        }
        TokenLocation::QueryParam(name) => {
            let mut key = String::with_capacity("query:".len() + name.len());
            key.push_str("query:");
            key.push_str(name);
            key
        }
    }
}

fn is_authorization_bearer_location(location: &TokenLocation) -> bool {
    let TokenLocation::Header(header) = location else {
        return false;
    };
    header.name.eq_ignore_ascii_case("authorization")
        && header
            .prefix
            .as_deref()
            .and_then(|prefix| prefix.strip_suffix(' '))
            .is_some_and(|scheme| scheme.eq_ignore_ascii_case("bearer"))
}

#[derive(Clone)]
enum IntrospectionDecision {
    Inactive,
    Unauthorized(String),
    Unavailable,
}

impl IntrospectionDecision {
    fn into_rejection(self) -> IntrospectionRejection {
        match self {
            Self::Inactive => IntrospectionRejection::bearer(
                401,
                r#"{"error":"Inactive token"}"#.to_string(),
                "invalid_token",
            ),
            Self::Unauthorized(body) => IntrospectionRejection::bearer(401, body, "invalid_token"),
            Self::Unavailable => IntrospectionRejection::plain(
                503,
                r#"{"error":"Token introspection unavailable"}"#.to_string(),
            ),
        }
    }
}

struct IntrospectionRejection {
    status_code: u16,
    body: String,
    bearer_error: Option<&'static str>,
}

impl IntrospectionRejection {
    fn plain(status_code: u16, body: String) -> Self {
        Self {
            status_code,
            body,
            bearer_error: None,
        }
    }

    fn bearer(status_code: u16, body: String, error: &'static str) -> Self {
        Self {
            status_code,
            body,
            bearer_error: Some(error),
        }
    }

    fn into_plugin_result(self) -> PluginResult {
        match self.bearer_error {
            Some(error) => reject_bearer(self.status_code, self.body, error),
            None => reject(self.status_code, self.body),
        }
    }
}

trait FormBodyExt {
    fn with_form_body(
        self,
        params: &[(String, String)],
    ) -> Result<reqwest::RequestBuilder, IntrospectionDecision>;
}

impl FormBodyExt for reqwest::RequestBuilder {
    fn with_form_body(
        self,
        params: &[(String, String)],
    ) -> Result<reqwest::RequestBuilder, IntrospectionDecision> {
        let mut serializer = url::form_urlencoded::Serializer::new(String::new());
        for (key, value) in params {
            serializer.append_pair(key, value);
        }
        let body = serializer.finish();
        Ok(self
            .header("content-type", "application/x-www-form-urlencoded")
            .body(body))
    }
}

#[async_trait]
impl super::Plugin for Oauth2Introspection {
    fn name(&self) -> &str {
        "oauth2_introspection"
    }

    fn is_auth_plugin(&self) -> bool {
        true
    }

    fn authentication_challenge(&self) -> Option<&'static str> {
        Some("Bearer")
    }

    fn start_background_tasks(&self) -> Result<(), String> {
        let mut task_slot = self
            .discovery_tasks
            .lock()
            .map_err(|_| "oauth2_introspection: discovery task state lock poisoned".to_string())?;
        if task_slot.is_some() {
            return Ok(());
        }

        let discoveries: Vec<_> = self
            .providers
            .iter()
            .filter_map(|provider| {
                provider.discovery_url.as_ref().map(|discovery_url| {
                    (
                        Arc::clone(&provider.introspection_endpoint),
                        discovery_url.clone(),
                    )
                })
            })
            .collect();
        if discoveries.is_empty() {
            *task_slot = Some(Vec::new());
            return Ok(());
        }

        let runtime = tokio::runtime::Handle::try_current().map_err(|_| {
            "oauth2_introspection: live discovery startup requires a Tokio runtime".to_string()
        })?;
        let tasks = discoveries
            .into_iter()
            .map(|(endpoint_slot, discovery_url)| {
                spawn_discovery_task(
                    &runtime,
                    endpoint_slot,
                    self.http_client.clone(),
                    discovery_url,
                )
            })
            .collect();
        *task_slot = Some(tasks);
        Ok(())
    }

    fn priority(&self) -> u16 {
        super::priority::OAUTH2_INTROSPECTION
    }

    fn supported_protocols(&self) -> &'static [super::ProxyProtocol] {
        crate::plugins::HTTP_FAMILY_PROTOCOLS
    }

    async fn authenticate(
        &self,
        ctx: &mut RequestContext,
        consumer_index: &ConsumerIndex,
    ) -> PluginResult {
        self.authenticate_request(ctx, consumer_index).await
    }

    fn modifies_request_headers(&self) -> bool {
        self.strip_authorization_on_success
            || self
                .providers
                .iter()
                .any(|provider| !provider.claim_headers.is_empty())
    }

    async fn before_proxy(
        &self,
        ctx: &mut RequestContext,
        headers: &mut HashMap<String, String>,
    ) -> PluginResult {
        let strip_authorization = ctx
            .metadata
            .remove(STRIP_AUTHORIZATION_METADATA_KEY)
            .is_some();
        let strip_headers: Vec<String> = ctx
            .metadata
            .keys()
            .filter_map(|key| key.strip_prefix(STRIP_HEADER_METADATA_PREFIX))
            .map(ToOwned::to_owned)
            .collect();
        if strip_authorization || !strip_headers.is_empty() {
            headers.retain(|name, _| {
                let strip_current = (strip_authorization
                    && name.eq_ignore_ascii_case("authorization"))
                    || strip_headers
                        .iter()
                        .any(|header| name.eq_ignore_ascii_case(header));
                !strip_current
            });
        }
        for header in strip_headers {
            ctx.metadata
                .remove(&format!("{STRIP_HEADER_METADATA_PREFIX}{header}"));
        }
        apply_claim_headers_from_context(ctx, headers, CLAIM_HEADER_METADATA_PREFIX);
        PluginResult::Continue
    }

    fn warmup_hostnames(&self) -> Vec<String> {
        let mut hosts = Vec::new();
        for provider in &self.providers {
            hosts.extend(provider.warmup_hostnames.iter().cloned());
            let guard = provider.introspection_endpoint.load();
            if let Some(endpoint) = guard.as_ref().as_ref()
                && let Some(host) = hostname_from_url(endpoint)
                && !hosts.iter().any(|known| known == &host)
            {
                hosts.push(host);
            }
        }
        hosts
    }

    fn requires_decoded_query_params(&self) -> bool {
        self.has_custom_query_token_locations
    }
}

fn apply_verify_outcome(
    ctx: &mut RequestContext,
    outcome: VerifyOutcome,
    auth_method: &'static str,
) -> PluginResult {
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
            if let Some(external_identity) = external_identity {
                ctx.authenticated_identity = Some(external_identity);
            }
            if let Some(external_identity_header) = external_identity_header {
                ctx.authenticated_identity_header = Some(external_identity_header);
            }
            if ctx.auth_method.is_none() && (consumer_identified || external_identity_identified) {
                ctx.auth_method = Some(auth_method);
            }
            PluginResult::Continue
        }
        VerifyOutcome::Forbidden(body) => reject(403, body),
        VerifyOutcome::InvalidFormat(body) => reject_bearer(401, body, "invalid_request"),
        VerifyOutcome::Invalid(body)
        | VerifyOutcome::ConsumerNotFound(body)
        | VerifyOutcome::VerificationFailed(body) => reject_bearer(401, body, "invalid_token"),
        VerifyOutcome::Internal(body) => reject(500, body),
        VerifyOutcome::NotApplicable => PluginResult::Continue,
    }
}

fn parse_client_auth(
    config: &Map<String, Value>,
    provider_idx: usize,
    endpoint: Option<&ParsedEndpoint>,
) -> Result<ClientAuth, String> {
    let auth = match config.get("client_auth") {
        Some(value) => value.as_object().cloned().ok_or_else(|| {
            format!("oauth2_introspection: provider[{provider_idx}].client_auth must be an object")
        })?,
        None => Map::new(),
    };
    reject_unknown_keys(
        &auth,
        &[
            "method",
            "client_id",
            "client_secret",
            "private_key_pem",
            "private_key_jwt_alg",
            "private_key_jwt_kid",
        ],
        &format!("oauth2_introspection: provider[{provider_idx}].client_auth"),
    )?;
    let method = match auth.get("method") {
        Some(value) => value.as_str().ok_or_else(|| {
            format!(
                "oauth2_introspection: provider[{provider_idx}].client_auth.method must be a string"
            )
        })?,
        None => "client_secret_basic",
    }
    .trim();
    let client_id = match auth.get("client_id") {
        Some(value) => Some(
            value
                .as_str()
                .ok_or_else(|| {
                    format!(
                        "oauth2_introspection: provider[{provider_idx}].client_auth.client_id must be a string"
                    )
                })?
                .trim(),
        ),
        None => None,
    }
    .filter(|value| !value.is_empty())
    .map(ToOwned::to_owned);

    // Credentialed methods transmit client credentials to the provider:
    // `client_secret_basic` puts Base64(client_id:client_secret) in the
    // Authorization header, `client_secret_post` puts `client_secret` in the
    // form body, and `private_key_jwt` puts a signed `client_assertion` (a
    // bearer credential the IdP accepts) in the form body. Reject configs that
    // would send any of these over plaintext to a non-loopback host. Loopback
    // `http://` is still permitted for local development, mirroring the
    // `method='none'` gate below.
    if matches!(
        method,
        "client_secret_basic" | "client_secret_post" | "private_key_jwt"
    ) && endpoint.is_some_and(is_insecure_credentialed_endpoint)
    {
        return Err(format!(
            "oauth2_introspection: provider[{provider_idx}].client_auth.method='{method}' requires an https introspection_endpoint/discovery_url (http is only allowed for localhost or loopback endpoints)"
        ));
    }

    match method {
        "client_secret_basic" => {
            let client_id = client_id.ok_or_else(|| {
                format!(
                    "oauth2_introspection: provider[{provider_idx}].client_auth.client_id is required"
                )
            })?;
            let client_secret = required_auth_string(
                &auth,
                "client_secret",
                provider_idx,
            )?;
            Ok(ClientAuth::Basic {
                authorization: oauth_basic_authorization_header(&client_id, &client_secret)?,
            })
        }
        "client_secret_post" => Ok(ClientAuth::Post {
            client_id: client_id.ok_or_else(|| {
                format!(
                    "oauth2_introspection: provider[{provider_idx}].client_auth.client_id is required"
                )
            })?,
            client_secret: SecretString(required_auth_string(
                &auth,
                "client_secret",
                provider_idx,
            )?),
        }),
        "private_key_jwt" => {
            let client_id = client_id.ok_or_else(|| {
                format!(
                    "oauth2_introspection: provider[{provider_idx}].client_auth.client_id is required"
                )
            })?;
            let pem = required_auth_string(&auth, "private_key_pem", provider_idx)?;
            let alg = parse_private_key_alg(auth.get("private_key_jwt_alg"), provider_idx)?;
            let encoding_key = match alg {
                Algorithm::RS256 | Algorithm::RS384 | Algorithm::RS512 => {
                    EncodingKey::from_rsa_pem(pem.as_bytes()).map_err(|e| {
                        format!(
                            "oauth2_introspection: provider[{provider_idx}].client_auth.private_key_pem is invalid RSA PEM: {e}"
                        )
                    })?
                }
                Algorithm::ES256 | Algorithm::ES384 => {
                    EncodingKey::from_ec_pem(pem.as_bytes()).map_err(|e| {
                        format!(
                            "oauth2_introspection: provider[{provider_idx}].client_auth.private_key_pem is invalid EC PEM: {e}"
                        )
                    })?
                }
                Algorithm::EdDSA => EncodingKey::from_ed_pem(pem.as_bytes()).map_err(|e| {
                    format!(
                        "oauth2_introspection: provider[{provider_idx}].client_auth.private_key_pem is invalid EdDSA PEM: {e}"
                    )
                })?,
                _ => {
                    return Err(format!(
                        "oauth2_introspection: provider[{provider_idx}].client_auth.private_key_jwt_alg is unsupported"
                    ));
                }
            };
            let kid = match auth.get("private_key_jwt_kid") {
                Some(value) => Some(value.as_str().ok_or_else(|| {
                    format!(
                        "oauth2_introspection: provider[{provider_idx}].client_auth.private_key_jwt_kid must be a string"
                    )
                })?),
                None => None,
            }
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .map(ToOwned::to_owned);
            Ok(ClientAuth::PrivateKeyJwt {
                client_id,
                encoding_key,
                alg,
                kid,
            })
        }
        "none" => {
            if endpoint.is_some_and(|endpoint| !is_local_introspection_host(&endpoint.hostname)) {
                return Err(format!(
                    "oauth2_introspection: provider[{provider_idx}].client_auth.method='none' is only allowed for localhost or loopback endpoints"
                ));
            }
            Ok(ClientAuth::None)
        }
        _ => Err(format!(
            "oauth2_introspection: provider[{provider_idx}].client_auth.method is unsupported"
        )),
    }
}

fn required_auth_string(
    auth: &Map<String, Value>,
    field: &str,
    provider_idx: usize,
) -> Result<String, String> {
    let value = auth.get(field).ok_or_else(|| {
        format!("oauth2_introspection: provider[{provider_idx}].client_auth.{field} is required")
    })?;
    let raw = value.as_str().ok_or_else(|| {
        format!(
            "oauth2_introspection: provider[{provider_idx}].client_auth.{field} must be a string"
        )
    })?;
    if raw.is_empty() {
        return Err(format!(
            "oauth2_introspection: provider[{provider_idx}].client_auth.{field} must not be empty"
        ));
    }
    Ok(raw.to_string())
}

fn oauth_basic_authorization_header(
    client_id: &str,
    client_secret: &str,
) -> Result<HeaderValue, String> {
    let encoded_client_id = oauth_form_encode_component(client_id)?;
    let encoded_client_secret = oauth_form_encode_component(client_secret)?;
    let mut credential = String::with_capacity(
        encoded_client_id
            .len()
            .saturating_add(encoded_client_secret.len())
            .saturating_add(1),
    );
    credential.push_str(&encoded_client_id);
    credential.push(':');
    credential.push_str(&encoded_client_secret);
    let encoded = base64::engine::general_purpose::STANDARD.encode(credential.as_bytes());
    let mut value = String::with_capacity("Basic ".len().saturating_add(encoded.len()));
    value.push_str("Basic ");
    value.push_str(&encoded);
    let mut header = HeaderValue::from_bytes(value.as_bytes())
        .map_err(|_| "oauth2_introspection: failed to encode client credentials".to_string())?;
    header.set_sensitive(true);
    Ok(header)
}

fn oauth_form_encode_component(value: &str) -> Result<String, String> {
    let mut serializer = url::form_urlencoded::Serializer::new(String::new());
    serializer.append_pair("value", value);
    serializer
        .finish()
        .strip_prefix("value=")
        .map(ToOwned::to_owned)
        .ok_or_else(|| "oauth2_introspection: failed to form-encode client credentials".to_string())
}

fn parse_private_key_alg(value: Option<&Value>, provider_idx: usize) -> Result<Algorithm, String> {
    let algorithm = match value {
        Some(value) => value.as_str().ok_or_else(|| {
            format!(
                "oauth2_introspection: provider[{provider_idx}].client_auth.private_key_jwt_alg must be a string"
            )
        })?,
        None => "RS256",
    };
    match algorithm {
        "RS256" => Ok(Algorithm::RS256),
        "RS384" => Ok(Algorithm::RS384),
        "RS512" => Ok(Algorithm::RS512),
        "ES256" => Ok(Algorithm::ES256),
        "ES384" => Ok(Algorithm::ES384),
        "EdDSA" => Ok(Algorithm::EdDSA),
        _ => Err(format!(
            "oauth2_introspection: provider[{provider_idx}].client_auth.private_key_jwt_alg is unsupported"
        )),
    }
}

fn build_client_assertion(
    client_id: &str,
    endpoint: &str,
    encoding_key: &EncodingKey,
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
            "aud": endpoint,
            "iat": now,
            "exp": now + 300,
            "jti": uuid::Uuid::new_v4().to_string()
        }),
        encoding_key,
    )
    .map_err(|e| format!("client assertion signing failed: {e}"))
}

fn parse_token_locations(
    config: &Map<String, Value>,
    provider_idx: usize,
) -> Result<Vec<TokenLocation>, String> {
    let mut locations = Vec::new();
    if let Some(value) = config.get("from_headers") {
        let headers = value.as_array().ok_or_else(|| {
            format!(
                "oauth2_introspection: 'provider[{provider_idx}].from_headers' must be an array"
            )
        })?;
        for (idx, header) in headers.iter().enumerate() {
            let object = header.as_object().ok_or_else(|| {
                format!(
                    "oauth2_introspection: 'provider[{provider_idx}].from_headers[{idx}]' must be an object"
                )
            })?;
            reject_unknown_keys(
                object,
                &["name", "prefix"],
                &format!("oauth2_introspection: provider[{provider_idx}].from_headers[{idx}]"),
            )?;
            let raw_name = object.get("name").and_then(Value::as_str).ok_or_else(|| {
                format!(
                    "oauth2_introspection: 'provider[{provider_idx}].from_headers[{idx}].name' is required"
                )
            })?;
            let name = raw_name.trim().to_ascii_lowercase();
            if name.is_empty() {
                return Err(format!(
                    "oauth2_introspection: 'provider[{provider_idx}].from_headers[{idx}].name' must not be empty"
                ));
            }
            let name = HeaderName::from_bytes(name.as_bytes())
                .map_err(|e| {
                    format!(
                        "oauth2_introspection: 'provider[{provider_idx}].from_headers[{idx}].name' is invalid: {e}"
                    )
                })?
                .as_str()
                .to_string();
            let prefix = match object.get("prefix") {
                Some(Value::String(raw)) if raw.is_empty() => None,
                Some(Value::String(raw)) => Some(raw.clone()),
                Some(Value::Null) | None => None,
                Some(_value) => {
                    return Err(format!(
                        "oauth2_introspection: 'provider[{provider_idx}].from_headers[{idx}].prefix' must be a string"
                    ));
                }
            };
            locations.push(TokenLocation::Header(TokenHeaderLocation { name, prefix }));
        }
    }
    for param in parse_string_array(config, "from_params", provider_idx)? {
        locations.push(TokenLocation::QueryParam(param));
    }
    Ok(locations)
}

fn optional_claim_path(
    config: &Map<String, Value>,
    field: &str,
    default_value: &str,
    plugin: &str,
) -> Result<String, String> {
    match config.get(field) {
        Some(value) => parse_claim_path_value(field, value, plugin),
        None => Ok(default_value.to_string()),
    }
}

fn reject_unknown_keys(
    object: &Map<String, Value>,
    allowed: &[&str],
    path: &str,
) -> Result<(), String> {
    if let Some(unknown) = object.keys().find(|key| !allowed.contains(&key.as_str())) {
        return Err(format!("{path} contains unknown field '{unknown}'"));
    }
    Ok(())
}

fn optional_top_level_bool(
    config: &Map<String, Value>,
    field: &str,
    plugin: &str,
) -> Result<Option<bool>, String> {
    config
        .get(field)
        .map(|value| {
            value
                .as_bool()
                .ok_or_else(|| format!("{plugin}: '{field}' must be a boolean"))
        })
        .transpose()
}

fn optional_provider_claim_path(
    config: &Map<String, Value>,
    field: &str,
    provider_idx: usize,
) -> Result<Option<String>, String> {
    let Some(value) = config.get(field) else {
        return Ok(None);
    };
    parse_claim_path_value(
        &format!("provider[{provider_idx}].{field}"),
        value,
        "oauth2_introspection",
    )
    .map(Some)
}

fn optional_non_empty_string(
    config: &Map<String, Value>,
    field: &str,
    provider_idx: usize,
) -> Result<Option<String>, String> {
    let Some(value) = config.get(field) else {
        return Ok(None);
    };
    let raw = value.as_str().ok_or_else(|| {
        format!(
            "oauth2_introspection: 'provider[{provider_idx}].{field}' must be a string, got: {value}"
        )
    })?;
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return Err(format!(
            "oauth2_introspection: 'provider[{provider_idx}].{field}' must not be empty"
        ));
    }
    Ok(Some(trimmed.to_string()))
}

fn optional_provider_bool(
    config: &Map<String, Value>,
    field: &str,
    provider_idx: usize,
) -> Result<Option<bool>, String> {
    config
        .get(field)
        .map(|value| {
            value.as_bool().ok_or_else(|| {
                format!(
                    "oauth2_introspection: 'provider[{provider_idx}].{field}' must be a boolean"
                )
            })
        })
        .transpose()
}

fn optional_nullable_string(
    config: &Map<String, Value>,
    field: &str,
    provider_idx: usize,
) -> Result<Option<String>, String> {
    let Some(value) = config.get(field) else {
        return Ok(None);
    };
    if value.is_null() {
        return Ok(None);
    }
    let raw = value.as_str().ok_or_else(|| {
        format!("oauth2_introspection: 'provider[{provider_idx}].{field}' must be a string or null")
    })?;
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return Err(format!(
            "oauth2_introspection: 'provider[{provider_idx}].{field}' must not be empty"
        ));
    }
    Ok(Some(trimmed.to_string()))
}

fn parse_string_array(
    config: &Map<String, Value>,
    field: &str,
    provider_idx: usize,
) -> Result<Vec<String>, String> {
    let Some(value) = config.get(field) else {
        return Ok(Vec::new());
    };
    let arr = value.as_array().ok_or_else(|| {
        format!("oauth2_introspection: 'provider[{provider_idx}].{field}' must be an array")
    })?;
    let mut values = Vec::with_capacity(arr.len());
    for (idx, entry) in arr.iter().enumerate() {
        let raw = entry.as_str().ok_or_else(|| {
            format!(
                "oauth2_introspection: 'provider[{provider_idx}].{field}[{idx}]' must be a string"
            )
        })?;
        let trimmed = raw.trim();
        if trimmed.is_empty() {
            return Err(format!(
                "oauth2_introspection: 'provider[{provider_idx}].{field}[{idx}]' must not be empty"
            ));
        }
        values.push(trimmed.to_string());
    }
    Ok(values)
}

fn ranged_provider_u64(
    config: &Map<String, Value>,
    field: &str,
    provider_idx: usize,
    default_value: u64,
    min: u64,
    max: u64,
) -> Result<u64, String> {
    let value = config
        .get(field)
        .map(|value| {
            value.as_u64().ok_or_else(|| {
                format!(
                    "oauth2_introspection: 'provider[{provider_idx}].{field}' must be an unsigned integer"
                )
            })
        })
        .transpose()?
        .unwrap_or(default_value);
    if value < min || value > max {
        return Err(format!(
            "oauth2_introspection: 'provider[{provider_idx}].{field}' must be between {min} and {max}"
        ));
    }
    Ok(value)
}

fn ranged_provider_usize(
    config: &Map<String, Value>,
    field: &str,
    provider_idx: usize,
    default_value: usize,
    min: usize,
    max: usize,
) -> Result<usize, String> {
    let value = ranged_provider_u64(
        config,
        field,
        provider_idx,
        default_value as u64,
        min as u64,
        max as u64,
    )?;
    usize::try_from(value).map_err(|_| {
        format!("oauth2_introspection: 'provider[{provider_idx}].{field}' is too large")
    })
}

struct ParsedEndpoint {
    url: String,
    hostname: String,
    scheme: String,
}

fn parse_url_field(
    config: &Map<String, Value>,
    field: &str,
    provider_idx: usize,
) -> Result<Option<ParsedEndpoint>, String> {
    let Some(value) = config.get(field) else {
        return Ok(None);
    };
    let raw = value.as_str().ok_or_else(|| {
        format!("oauth2_introspection: 'provider[{provider_idx}].{field}' must be a URL string")
    })?;
    let url = raw.trim();
    if url.is_empty() {
        return Err(format!(
            "oauth2_introspection: 'provider[{provider_idx}].{field}' must not be empty"
        ));
    }
    let parsed = Url::parse(url).map_err(|e| {
        format!("oauth2_introspection: 'provider[{provider_idx}].{field}' is invalid: {e}")
    })?;
    match parsed.scheme() {
        "http" | "https" => {}
        scheme => {
            return Err(format!(
                "oauth2_introspection: 'provider[{provider_idx}].{field}' must use http or https, got: {scheme}"
            ));
        }
    }
    let hostname = hostname_from_parsed_url(&parsed).ok_or_else(|| {
        format!("oauth2_introspection: 'provider[{provider_idx}].{field}' must include a hostname")
    })?;
    Ok(Some(ParsedEndpoint {
        url: url.to_string(),
        hostname,
        scheme: parsed.scheme().to_string(),
    }))
}

fn hostname_from_parsed_url(parsed: &Url) -> Option<String> {
    Some(match parsed.host()? {
        Host::Domain(hostname) => hostname.to_string(),
        Host::Ipv4(address) => address.to_string(),
        Host::Ipv6(address) => address.to_string(),
    })
}

fn hostname_from_url(url: &str) -> Option<String> {
    Url::parse(url)
        .ok()
        .and_then(|parsed| hostname_from_parsed_url(&parsed))
}

fn is_local_introspection_host(hostname: &str) -> bool {
    hostname.eq_ignore_ascii_case("localhost")
        || hostname
            .parse::<IpAddr>()
            .is_ok_and(|address| address.is_loopback())
}

/// True when the endpoint would transmit client credentials over plaintext to a
/// non-loopback host (`http://` scheme + remote host). Loopback `http://` is
/// permitted for local development, mirroring the `client_auth.method='none'`
/// gate. The scheme comparison is case-insensitive because `url` lowercases
/// schemes on parse, but we stay defensive.
fn is_insecure_credentialed_endpoint(endpoint: &ParsedEndpoint) -> bool {
    endpoint.scheme.eq_ignore_ascii_case("http") && !is_local_introspection_host(&endpoint.hostname)
}

fn audience_matches(claims: &Value, audiences: &[String]) -> bool {
    if audiences.is_empty() {
        return true;
    }
    match claims.get("aud") {
        Some(Value::String(aud)) => audiences.iter().any(|expected| expected == aud),
        Some(Value::Array(values)) => values
            .iter()
            .filter_map(Value::as_str)
            .any(|aud| audiences.iter().any(|expected| expected.as_str() == aud)),
        _ => false,
    }
}

fn mark_credential_source_stripping_metadata(
    ctx: &mut RequestContext,
    provider: &IntrospectionProvider,
    source: CredentialSource,
) {
    match source {
        CredentialSource::Authorization => mark_authorization_stripping_metadata(ctx),
        CredentialSource::ProviderLocation(location_idx) => {
            let Some(location) = provider.token_locations.get(location_idx) else {
                warn!(
                    plugin = "oauth2_introspection",
                    location_idx, "accepted token source no longer exists"
                );
                return;
            };
            mark_token_location_stripping_metadata(ctx, location);
        }
    }
}

fn authorization_bearer_matches(ctx: &RequestContext, expected_token: &str) -> bool {
    ctx.headers
        .get("authorization")
        .and_then(|value| value.split_once(' '))
        .is_some_and(|(scheme, token)| {
            scheme.eq_ignore_ascii_case("bearer") && token == expected_token
        })
}

fn token_location_matches(
    location: &TokenLocation,
    ctx: &RequestContext,
    expected_token: &str,
) -> bool {
    if is_authorization_bearer_location(location) {
        return authorization_bearer_matches(ctx, expected_token);
    }
    match location {
        TokenLocation::Header(header) => ctx.headers.get(&header.name).is_some_and(|value| {
            let token = match header.prefix.as_deref() {
                Some(prefix) => value.strip_prefix(prefix),
                None => Some(value.as_str()),
            };
            token == Some(expected_token)
        }),
        TokenLocation::QueryParam(name) => ctx
            .query_params
            .get(name)
            .is_some_and(|token| token == expected_token),
    }
}

fn mark_authorization_stripping_metadata(ctx: &mut RequestContext) {
    ctx.metadata.insert(
        STRIP_AUTHORIZATION_METADATA_KEY.to_string(),
        "true".to_string(),
    );
}

fn mark_token_location_stripping_metadata(ctx: &mut RequestContext, location: &TokenLocation) {
    match location {
        TokenLocation::Header(header) => {
            ctx.metadata.insert(
                format!("{STRIP_HEADER_METADATA_PREFIX}{}", header.name),
                "true".to_string(),
            );
        }
        TokenLocation::QueryParam(name) => {
            ctx.metadata.insert(
                format!("{STRIP_QUERY_PARAM_METADATA_PREFIX}{name}"),
                "true".to_string(),
            );
            ctx.query_params.remove(name);
        }
    }
}

fn reject(status_code: u16, body: String) -> PluginResult {
    PluginResult::Reject {
        status_code,
        body,
        headers: HashMap::new(),
    }
}

fn reject_bearer(status_code: u16, body: String, error: &'static str) -> PluginResult {
    let mut headers = HashMap::new();
    headers.insert(
        "www-authenticate".to_string(),
        format!(r#"Bearer error="{error}""#),
    );
    PluginResult::Reject {
        status_code,
        body,
        headers,
    }
}

fn spawn_discovery_task(
    runtime: &tokio::runtime::Handle,
    endpoint_slot: Arc<ArcSwap<Option<String>>>,
    http_client: PluginHttpClient,
    discovery_url: String,
) -> tokio::task::JoinHandle<()> {
    runtime.spawn(async move {
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
            match discover_introspection_endpoint(&http_client, &discovery_url).await {
                Ok(endpoint) => {
                    info!(
                        plugin = "oauth2_introspection",
                        "OIDC discovery resolved introspection endpoint"
                    );
                    endpoint_slot.store(Arc::new(Some(endpoint)));
                    return;
                }
                Err(error) => {
                    warn!(
                        plugin = "oauth2_introspection",
                        error = %error,
                        "OIDC discovery failed"
                    );
                    attempt = attempt.saturating_add(1);
                }
            }
        }
    })
}

async fn discover_introspection_endpoint(
    http_client: &PluginHttpClient,
    discovery_url: &str,
) -> Result<String, String> {
    let response = http_client
        .execute(
            http_client.get().get(discovery_url),
            "oauth2_introspection_discovery",
        )
        .await
        .map_err(|e| format!("discovery request failed: {e}"))?;
    if !response.status().is_success() {
        return Err(format!("discovery returned HTTP {}", response.status()));
    }
    let bytes = read_response_body_bounded(response, MAX_DISCOVERY_RESPONSE_BYTES)
        .await
        .map_err(|e| format!("discovery response body read failed: {e}"))?;
    let body: Value =
        serde_json::from_slice(&bytes).map_err(|e| format!("discovery parse failed: {e}"))?;
    let endpoint = body
        .get("introspection_endpoint")
        .and_then(Value::as_str)
        .ok_or_else(|| "discovery document missing introspection_endpoint".to_string())?;
    validate_discovered_endpoint(discovery_url, endpoint, "introspection_endpoint")
}

fn validate_discovered_endpoint(
    discovery_url: &str,
    endpoint: &str,
    field: &str,
) -> Result<String, String> {
    let discovery = Url::parse(discovery_url)
        .map_err(|e| format!("discovery_url should already be valid: {e}"))?;
    let parsed = Url::parse(endpoint).map_err(|e| format!("discovery {field} is invalid: {e}"))?;
    match parsed.scheme() {
        "http" | "https" => {}
        scheme => {
            return Err(format!(
                "discovery {field} must use http or https, got: {scheme}"
            ));
        }
    }
    let discovery_host = hostname_from_parsed_url(&discovery)
        .ok_or_else(|| "discovery_url must include a hostname".to_string())?;
    let endpoint_host = hostname_from_parsed_url(&parsed)
        .ok_or_else(|| format!("discovery {field} must include a hostname"))?;
    // A non-loopback discovered endpoint must be https: client credentials may
    // be sent to it, and an https discovery document advertising a plaintext
    // introspection endpoint would otherwise downgrade the credential exchange
    // to cleartext. Loopback http stays allowed for local development, mirroring
    // the config-load gate in `parse_client_auth`.
    if parsed.scheme().eq_ignore_ascii_case("http") && !is_local_introspection_host(&endpoint_host)
    {
        return Err(format!(
            "discovery {field} must use https for non-loopback hosts"
        ));
    }
    if !endpoint_host.eq_ignore_ascii_case(&discovery_host) {
        return Err(format!(
            "discovery {field} host must match discovery_url host"
        ));
    }
    if !parsed.scheme().eq_ignore_ascii_case(discovery.scheme())
        || parsed.port_or_known_default() != discovery.port_or_known_default()
    {
        return Err(format!(
            "discovery {field} origin must match discovery_url origin"
        ));
    }
    Ok(endpoint.trim().to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn local_introspection_host_accepts_loopback_and_localhost_only() {
        assert!(is_local_introspection_host("localhost"));
        assert!(is_local_introspection_host("127.42.0.9"));
        assert!(is_local_introspection_host("::1"));
        assert!(!is_local_introspection_host("idp.local"));
        assert!(!is_local_introspection_host("auth.example.com"));
    }

    #[test]
    fn discovered_introspection_endpoint_must_match_discovery_host() {
        assert!(
            validate_discovered_endpoint(
                "https://issuer.example.com/.well-known/openid-configuration",
                "https://issuer.example.com/introspect",
                "introspection_endpoint",
            )
            .is_ok()
        );
        assert!(
            validate_discovered_endpoint(
                "https://issuer.example.com/.well-known/openid-configuration",
                "https://evil.example.com/introspect",
                "introspection_endpoint",
            )
            .is_err()
        );
        assert!(
            validate_discovered_endpoint(
                "https://issuer.example.com/.well-known/openid-configuration",
                "file:///etc/passwd",
                "introspection_endpoint",
            )
            .is_err()
        );
    }

    #[test]
    fn private_key_jwt_accepts_eddsa_alg_name() {
        assert_eq!(
            parse_private_key_alg(Some(&Value::String("EdDSA".to_string())), 0).unwrap(),
            Algorithm::EdDSA
        );
    }

    #[test]
    fn oauth_basic_header_is_form_encoded_and_sensitive() {
        let header = oauth_basic_authorization_header("client:id", "s%cret").unwrap();
        assert_eq!(header.as_bytes(), b"Basic Y2xpZW50JTNBaWQ6cyUyNWNyZXQ=");
        assert!(header.is_sensitive());
    }

    #[test]
    fn discovery_downgrade_to_http_remote_endpoint_is_rejected() {
        // An https discovery document must not be allowed to downgrade the
        // credential exchange to a plaintext non-loopback introspection
        // endpoint (finding #34 bypass via discovery).
        assert!(
            validate_discovered_endpoint(
                "https://issuer.example.com/.well-known/openid-configuration",
                "http://issuer.example.com/introspect",
                "introspection_endpoint",
            )
            .is_err()
        );
        // Loopback http remains acceptable for local development.
        assert!(
            validate_discovered_endpoint(
                "http://localhost:9000/.well-known/openid-configuration",
                "http://localhost:9000/introspect",
                "introspection_endpoint",
            )
            .is_ok()
        );
    }

    #[test]
    fn discovered_endpoint_requires_exact_effective_origin() {
        assert!(
            validate_discovered_endpoint(
                "https://issuer.example.com/.well-known/openid-configuration",
                "https://issuer.example.com:443/introspect",
                "introspection_endpoint",
            )
            .is_ok()
        );
        assert!(
            validate_discovered_endpoint(
                "https://issuer.example.com/.well-known/openid-configuration",
                "https://issuer.example.com:8443/introspect",
                "introspection_endpoint",
            )
            .is_err()
        );
        assert!(
            validate_discovered_endpoint(
                "https://[2001:db8::1]:443/.well-known/openid-configuration",
                "https://[2001:db8::1]/introspect",
                "introspection_endpoint",
            )
            .is_ok()
        );
        assert!(
            validate_discovered_endpoint(
                "https://[2001:db8::1]:443/.well-known/openid-configuration",
                "https://[2001:db8::1]:9443/introspect",
                "introspection_endpoint",
            )
            .is_err()
        );
    }
}
