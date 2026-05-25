use std::collections::HashMap;
use std::fmt;
use std::net::IpAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use arc_swap::ArcSwap;
use async_trait::async_trait;
use http::header::HeaderName;
use jsonwebtoken::{Algorithm, EncodingKey, Header, encode};
use serde_json::{Map, Value, json};
use tracing::{debug, info, warn};
use url::{Host, Url};

use crate::consumer_index::ConsumerIndex;

use super::utils::PluginHttpClient;
use super::utils::auth_flow::{ExtractedCredential, VerifyOutcome};
use super::utils::claim_header_fanout::{
    ClaimHeaderMapping, apply_claim_headers_from_metadata, emit_claim_headers_to_metadata,
    parse_claim_headers,
};
use super::utils::claim_resolver::{extract_claim_string, parse_claim_path_value};
use super::utils::introspection_cache::{
    CacheLookup, IntrospectionCache, get_or_create_introspection_cache,
};
use super::utils::scope_role_check::{self, ScopeRoleRequirements};
use super::utils::token_extract::{
    TokenHeaderLocation, TokenLocation, TokenLocationExtract, extract_authorization_bearer,
    extract_from_location, mark_original_token_stripping_metadata as mark_token_stripping_metadata,
    provider_locations_extract_token,
};
use super::{PluginResult, RequestContext};

const STRIP_AUTHORIZATION_METADATA_KEY: &str = "oauth2_introspection.strip_authorization";
const STRIP_HEADER_METADATA_PREFIX: &str = "oauth2_introspection.strip_header.";
const STRIP_QUERY_PARAM_METADATA_PREFIX: &str = "oauth2_introspection.strip_query_param.";
const CLAIM_HEADER_METADATA_PREFIX: &str = "oauth2_introspection.claim_header.";

pub struct Oauth2Introspection {
    providers: Vec<IntrospectionProvider>,
    http_client: PluginHttpClient,
    global_scope_claim: String,
    global_role_claim: String,
    consumer_identity_claim: String,
    consumer_header_claim: String,
    strip_authorization_on_success: bool,
    has_custom_query_token_locations: bool,
}

struct IntrospectionProvider {
    issuer: Option<String>,
    introspection_endpoint: Arc<ArcSwap<Option<String>>>,
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
}

enum ClientAuth {
    Basic {
        client_id: String,
        client_secret: SecretString,
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

impl ClientAuth {
    fn client_id_for_cache(&self) -> &str {
        match self {
            Self::Basic { client_id, .. }
            | Self::Post { client_id, .. }
            | Self::PrivateKeyJwt { client_id, .. } => client_id,
            Self::None => "none",
        }
    }
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

enum Oauth2ExtractedCredential {
    BearerToken {
        token: String,
        provider_indices: Vec<usize>,
    },
    InvalidFormat(String),
    Missing,
}

impl Oauth2Introspection {
    pub fn new(config: &Value, http_client: PluginHttpClient) -> Result<Self, String> {
        let config_obj = config.as_object().ok_or_else(|| {
            format!("oauth2_introspection: config must be an object, got: {config}")
        })?;
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

        let shard_amount = http_client.pool_shard_amount();
        let mut providers = Vec::with_capacity(providers_arr.len());
        for (idx, prov_cfg) in providers_arr.iter().enumerate() {
            let prov_obj = prov_cfg.as_object().ok_or_else(|| {
                format!("oauth2_introspection: provider[{idx}] must be an object, got: {prov_cfg}")
            })?;

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
            let audiences = parse_string_array(prov_obj, "audiences", idx)?;
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
            if let Some(discovery) = discovery.as_ref() {
                spawn_discovery_task(
                    endpoint_slot.clone(),
                    http_client.clone(),
                    discovery.url.clone(),
                );
            }

            let cache_key = format!(
                "{}|{}",
                endpoint
                    .as_ref()
                    .map(|parsed| parsed.url.as_str())
                    .or_else(|| discovery.as_ref().map(|parsed| parsed.url.as_str()))
                    .unwrap_or("pending"),
                client_auth.client_id_for_cache()
            );
            let cache = get_or_create_introspection_cache(
                &cache_key,
                max_cache_entries,
                Duration::from_secs(positive_cache_ttl_secs),
                Duration::from_secs(negative_cache_ttl_secs),
                shard_amount,
            );
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
            });
        }

        let strip_authorization_on_success = providers.iter().any(|provider| {
            !provider.forward_original_token
                && (provider.token_locations.is_empty()
                    || provider
                        .token_locations
                        .iter()
                        .any(|location| matches!(location, TokenLocation::Header(_))))
        });
        let has_custom_query_token_locations = providers.iter().any(|provider| {
            provider
                .token_locations
                .iter()
                .any(|location| matches!(location, TokenLocation::QueryParam(_)))
        });

        Ok(Self {
            providers,
            http_client,
            global_scope_claim,
            global_role_claim,
            consumer_identity_claim,
            consumer_header_claim,
            strip_authorization_on_success,
            has_custom_query_token_locations,
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
            Oauth2ExtractedCredential::InvalidFormat(body) => reject(401, body),
            Oauth2ExtractedCredential::BearerToken {
                token,
                provider_indices,
            } => {
                let (claims, provider_idx) =
                    match self.validate_token(&token, &provider_indices).await {
                        Ok(result) => result,
                        Err((status, body)) => return reject(status, body),
                    };
                let provider = &self.providers[provider_idx];
                if let Err((status, body)) = self.check_claims_authorization(&claims, provider) {
                    return reject(status, body);
                }
                self.emit_claim_headers(ctx, &claims, provider);
                if !provider.forward_original_token {
                    mark_original_token_stripping_metadata(ctx, provider);
                }
                let outcome = self.resolve_identity(&claims, provider, consumer_index);
                apply_verify_outcome(ctx, outcome, "oauth2_introspection")
            }
        }
    }

    async fn validate_token(
        &self,
        token: &str,
        provider_indices: &[usize],
    ) -> Result<(Arc<Value>, usize), (u16, String)> {
        for &idx in provider_indices {
            let Some(provider) = self.providers.get(idx) else {
                continue;
            };
            match self.introspect_with_provider(token, provider, idx).await {
                Ok(claims) => return Ok((claims, idx)),
                Err(IntrospectionDecision::Inactive) => {
                    return Err((401, r#"{"error":"Inactive token"}"#.to_string()));
                }
                Err(IntrospectionDecision::Unauthorized(body)) => return Err((401, body)),
                Err(IntrospectionDecision::Unavailable) => {
                    return Err((
                        401,
                        r#"{"error":"Token introspection unavailable"}"#.to_string(),
                    ));
                }
            }
        }
        Err((
            401,
            r#"{"error":"Invalid or unrecognized token"}"#.to_string(),
        ))
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

        let guard = provider.introspection_endpoint.load();
        let Some(endpoint) = guard.as_ref().as_ref().cloned() else {
            warn!(
                plugin = "oauth2_introspection",
                provider_idx, "introspection endpoint unresolved"
            );
            return Err(IntrospectionDecision::Unavailable);
        };

        let mut params: Vec<(String, String)> = vec![("token".to_string(), token.to_string())];
        if let Some(hint) = &provider.token_hint_param {
            params.push(("token_type_hint".to_string(), hint.clone()));
        }
        let request = match &provider.client_auth {
            ClientAuth::Basic {
                client_id,
                client_secret,
            } => self
                .http_client
                .get()
                .post(&endpoint)
                .timeout(provider.request_timeout)
                .basic_auth(client_id, Some(client_secret.expose()))
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
        let claims: Value = response.json().await.map_err(|e| {
            warn!(
                plugin = "oauth2_introspection",
                provider_idx,
                error = %e,
                "token introspection response parse failed"
            );
            IntrospectionDecision::Unavailable
        })?;
        if claims.get("active").and_then(Value::as_bool) != Some(true) {
            provider.cache.insert_negative(token, now);
            return Err(IntrospectionDecision::Inactive);
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
        emit_claim_headers_to_metadata(ctx, claims, &provider.claim_headers, ",");
    }

    fn extract_credential(&self, ctx: &RequestContext) -> Oauth2ExtractedCredential {
        let mut first_invalid_format = None;
        for (idx, provider) in self.providers.iter().enumerate() {
            for location in &provider.token_locations {
                match extract_from_location(location, ctx) {
                    TokenLocationExtract::Missing => {}
                    TokenLocationExtract::Credential(ExtractedCredential::InvalidFormat(body)) => {
                        first_invalid_format.get_or_insert(body);
                    }
                    TokenLocationExtract::Credential(ExtractedCredential::BearerToken(token)) => {
                        let mut provider_indices = vec![idx];
                        for (other_idx, other_provider) in self.providers.iter().enumerate() {
                            if other_idx != idx
                                && provider_locations_extract_token(
                                    &other_provider.token_locations,
                                    ctx,
                                    &token,
                                )
                            {
                                provider_indices.push(other_idx);
                            }
                        }
                        provider_indices.sort_unstable();
                        provider_indices.dedup();
                        return Oauth2ExtractedCredential::BearerToken {
                            token,
                            provider_indices,
                        };
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
                let provider_indices = (0..self.providers.len()).collect();
                Oauth2ExtractedCredential::BearerToken {
                    token,
                    provider_indices,
                }
            }
            _ => Oauth2ExtractedCredential::Missing,
        }
    }
}

enum IntrospectionDecision {
    Inactive,
    Unauthorized(String),
    Unavailable,
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
        apply_claim_headers_from_metadata(ctx, headers, CLAIM_HEADER_METADATA_PREFIX);
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
        VerifyOutcome::Invalid(body)
        | VerifyOutcome::InvalidFormat(body)
        | VerifyOutcome::ConsumerNotFound(body)
        | VerifyOutcome::VerificationFailed(body) => reject(401, body),
        VerifyOutcome::Internal(body) => reject(500, body),
        VerifyOutcome::NotApplicable => PluginResult::Continue,
    }
}

fn parse_client_auth(
    config: &Map<String, Value>,
    provider_idx: usize,
    endpoint: Option<&ParsedEndpoint>,
) -> Result<ClientAuth, String> {
    let auth = config
        .get("client_auth")
        .and_then(Value::as_object)
        .cloned()
        .unwrap_or_default();
    let method = auth
        .get("method")
        .and_then(Value::as_str)
        .unwrap_or("client_secret_basic")
        .trim();
    let client_id = auth
        .get("client_id")
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(ToOwned::to_owned);
    match method {
        "client_secret_basic" => Ok(ClientAuth::Basic {
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
            let kid = auth
                .get("private_key_jwt_kid")
                .and_then(Value::as_str)
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

fn parse_private_key_alg(value: Option<&Value>, provider_idx: usize) -> Result<Algorithm, String> {
    match value.and_then(Value::as_str).unwrap_or("RS256") {
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

fn mark_original_token_stripping_metadata(
    ctx: &mut RequestContext,
    provider: &IntrospectionProvider,
) {
    mark_token_stripping_metadata(
        ctx,
        &provider.token_locations,
        STRIP_AUTHORIZATION_METADATA_KEY,
        STRIP_HEADER_METADATA_PREFIX,
        STRIP_QUERY_PARAM_METADATA_PREFIX,
    );
}

fn reject(status_code: u16, body: String) -> PluginResult {
    PluginResult::Reject {
        status_code,
        body,
        headers: HashMap::new(),
    }
}

fn spawn_discovery_task(
    endpoint_slot: Arc<ArcSwap<Option<String>>>,
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
    });
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
    let body: Value = response
        .json()
        .await
        .map_err(|e| format!("discovery parse failed: {e}"))?;
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
    if !endpoint_host.eq_ignore_ascii_case(&discovery_host) {
        return Err(format!(
            "discovery {field} host must match discovery_url host"
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
}
