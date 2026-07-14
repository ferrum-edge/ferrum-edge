use arc_swap::ArcSwap;
use async_trait::async_trait;
use http::header::HeaderName;
use serde_json::Map;
use serde_json::Value;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tracing::{debug, info, warn};
use url::{Host, Url};

use crate::consumer_index::ConsumerIndex;

use super::utils::PluginHttpClient;
use super::utils::auth_flow::constant_time_eq;
use super::utils::auth_flow::{AuthMechanism, ExtractedCredential, VerifyOutcome};
use super::utils::cert_hash::sha256_base64url_no_pad;
use super::utils::claim_header_fanout::{
    ClaimHeaderMapping, apply_claim_headers_from_context, emit_claim_headers_to_context,
    parse_claim_headers, parse_separator,
};
use super::utils::claim_resolver::{extract_claim_string, parse_claim_path_value};
use super::utils::dpop::{self, DpopJtiCache, DpopVerifyInput};
use super::utils::jwks_cache::{
    get_or_create_jwks_store, last_discovered_jwks_uri, remember_discovered_jwks_uri,
    retire_jwks_store_if_unreferenced,
};
use super::utils::jwks_store::{JwksKeyStore, redacted_jwks_uri};
use super::utils::jwt_verifier::{JwtVerifyParams, peek_unverified_issuer, verify_jwt_with_jwks};
use super::utils::response_body::read_response_body_bounded;
use super::utils::scope_role_check::{self, ScopeRoleRequirements};
use super::utils::token_extract::{
    STRIP_QUERY_PARAM_METADATA_PREFIX, TokenHeaderLocation, TokenLocation, TokenLocationExtract,
    extract_authorization_bearer, extract_from_location,
    mark_original_token_stripping_metadata as mark_token_stripping_metadata,
    provider_locations_extract_token,
};
use super::{JwtAuthAttributeValue, PluginResult, RequestContext};

/// Default JWKS refresh interval: 15 minutes.
pub const DEFAULT_JWKS_REFRESH_INTERVAL_SECS: u64 = 900;
pub const DEFAULT_DPOP_JTI_CACHE_MAX_ENTRIES: usize = 10_000;
const MAX_DISCOVERY_RESPONSE_BYTES: usize = 128 * 1024;
const MAX_DISCOVERED_JWKS_URI_BYTES: usize = 8 * 1024;
const STRIP_AUTHORIZATION_METADATA_KEY: &str = "jwks_auth.strip_authorization";
const STRIP_HEADER_METADATA_PREFIX: &str = "jwks_auth.strip_header.";
const CLAIM_HEADER_METADATA_PREFIX: &str = "jwks_auth.claim_header.";

/// JWKS authentication plugin.
///
/// Validates Bearer tokens using public keys fetched from one or more
/// Identity Provider JWKS endpoints. Supports RSA (RS256/384/512) and
/// EC (ES256/384) algorithms.
///
/// ## Key features
///
/// - **Multiple identity providers**: Configure an array of `providers`,
///   each with its own issuer, JWKS source, audiences, and claim-based
///   authorization rules.
/// - **Claim-based authorization**: Per-provider `required_scopes` and
///   `required_roles` filter requests without needing a separate ACL plugin.
/// - **Consumer-optional flow**: When no matching `Consumer` exists in the
///   gateway, the plugin still sets `authenticated_identity` on the request
///   context for downstream use (logging, rate limiting, consumer header).
/// - **Shared JWKS cache**: Stores keyed by resolved `jwks_uri` are shared
///   across plugin instances — no duplicate fetches or refresh tasks.
/// - **Small provider sets**: Token extraction is intentionally linear over
///   configured providers and their token locations. Mesh and direct gateway
///   configurations are expected to keep JWT provider/location cardinality low.
///
/// ## Configuration
///
/// ```json
/// {
///   "providers": [
///     {
///       "issuer": "https://auth.example.com",
///       "jwks_uri": "https://auth.example.com/.well-known/jwks.json",
///       "audiences": ["my-api", "my-other-api"],
///       "required_scopes": ["read:data"],
///       "required_roles": ["admin"],
///       "scope_claim": "scp",
///       "role_claim": "realm_access.roles",
///       "consumer_identity_claim": "preferred_username",
///       "consumer_header_claim": "email"
///     }
///   ],
///   "scope_claim": "scope",
///   "role_claim": "roles",
///   "consumer_identity_claim": "sub",
///   "consumer_header_claim": "email",
///   "jwks_refresh_interval_secs": 900
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
    claim_headers: Vec<ClaimHeaderMapping>,
    claim_headers_separator: String,
    strip_authorization_on_success: bool,
    has_custom_query_token_locations: bool,
    emit_mesh_request_principal_metadata: bool,
    http_client: PluginHttpClient,
    refresh_interval: Duration,
    discovery_tasks: Mutex<Option<Vec<tokio::task::JoinHandle<()>>>>,
}

/// A single identity provider configuration.
struct JwksProvider {
    /// Expected `iss` claim value. Used to match incoming tokens to this provider.
    issuer: Option<String>,
    /// Accepted `aud` claim values. jsonwebtoken treats this as OR matching.
    audiences: Vec<String>,
    /// Configured token extraction locations.
    token_locations: Vec<TokenLocation>,
    /// Scopes that must be present in the token (all required).
    required_scopes: Vec<String>,
    /// Roles that must be present in the token (any one suffices).
    required_roles: Vec<String>,
    /// Per-provider override for the scope claim path.
    scope_claim: Option<String>,
    /// Per-provider override for the role claim path.
    role_claim: Option<String>,
    /// Per-provider override for the consumer identity claim.
    consumer_identity_claim: Option<String>,
    /// Per-provider override for the consumer header claim.
    consumer_header_claim: Option<String>,
    /// Whether to forward the original token-bearing header or query param upstream.
    forward_original_token: bool,
    /// Whether this provider requires tokens to include an `exp` claim.
    require_exp: bool,
    /// Claim values to forward as backend request headers for this provider.
    claim_headers: Vec<ClaimHeaderMapping>,
    /// Per-provider array separator for claim header fan-out.
    claim_headers_separator: Option<String>,
    /// Require RFC 8705 mTLS sender-constrained access tokens.
    require_mtls_binding: bool,
    /// Require RFC 9449 DPoP proof JWTs.
    require_dpop: bool,
    /// Allowed DPoP proof clock skew.
    dpop_clock_skew: Duration,
    /// Bounded replay cache for DPoP proof JTIs.
    dpop_jti_cache: Option<Arc<DpopJtiCache>>,
    /// The JWKS key store (shared via global cache).
    jwks_store: Arc<ArcSwap<Option<Arc<JwksKeyStore>>>>,
    jwks_source: JwksSource,
    /// Outbound hosts used by direct JWKS or discovery URLs.
    warmup_hostnames: Vec<String>,
}

enum JwksSource {
    Inline,
    Direct(String),
    Discovery(String),
}

const CONFIG_FIELDS: &[&str] = &[
    "providers",
    "scope_claim",
    "role_claim",
    "consumer_identity_claim",
    "consumer_header_claim",
    "claim_headers",
    "claim_headers_separator",
    "emit_mesh_request_principal_metadata",
    "require_exp",
    "jwks_refresh_interval_secs",
];

const PROVIDER_FIELDS: &[&str] = &[
    "jwks_uri",
    "discovery_url",
    "jwks",
    "issuer",
    "audience",
    "audiences",
    "from_headers",
    "from_params",
    "forward_original_token",
    "require_exp",
    "required_scopes",
    "required_roles",
    "scope_claim",
    "role_claim",
    "consumer_identity_claim",
    "consumer_header_claim",
    "claim_headers",
    "claim_headers_separator",
    "require_mtls_binding",
    "require_dpop",
    "dpop_clock_skew_secs",
    "dpop_jti_cache_max_entries",
    "dpop_jti_ttl_secs",
];

impl Drop for JwksAuth {
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

impl JwksAuth {
    pub fn new(config: &Value, http_client: PluginHttpClient) -> Result<Self, String> {
        let config_obj = config
            .as_object()
            .ok_or_else(|| format!("jwks_auth: config must be an object, got: {config}"))?;
        reject_unknown_fields(config_obj, CONFIG_FIELDS, "config")?;

        let refresh_interval_secs = optional_u64(
            config_obj,
            "jwks_refresh_interval_secs",
            DEFAULT_JWKS_REFRESH_INTERVAL_SECS,
        )?;
        if refresh_interval_secs == 0 {
            return Err(
                "jwks_auth: 'jwks_refresh_interval_secs' must be greater than 0".to_string(),
            );
        }
        let refresh_interval = Duration::from_secs(refresh_interval_secs);

        let global_scope_claim = optional_claim_path(config_obj, "scope_claim", "scope")?;
        let global_role_claim = optional_claim_path(config_obj, "role_claim", "roles")?;
        let consumer_identity_claim =
            optional_claim_path(config_obj, "consumer_identity_claim", "sub")?;
        let global_require_exp = optional_bool(config_obj, "require_exp")?.unwrap_or(true);
        let consumer_header_claim = match config_obj.get("consumer_header_claim") {
            Some(value) => parse_claim_path_value("consumer_header_claim", value, "jwks_auth")?,
            None => consumer_identity_claim.clone(),
        };
        let claim_headers = parse_claim_headers(
            config_obj,
            "claim_headers",
            "jwks_auth",
            CLAIM_HEADER_METADATA_PREFIX,
        )?;
        let claim_headers_separator =
            parse_separator(config_obj, "claim_headers_separator", "jwks_auth", ",")?;
        let emit_mesh_request_principal_metadata =
            optional_bool(config_obj, "emit_mesh_request_principal_metadata")?.unwrap_or(false);
        let shard_amount = http_client.pool_shard_amount();

        let providers_val = config_obj.get("providers").unwrap_or(&Value::Null);
        let Some(providers_arr) = providers_val.as_array() else {
            return Err("jwks_auth: 'providers' must be a non-empty array".to_string());
        };
        if providers_arr.is_empty() {
            return Err("jwks_auth: 'providers' array must not be empty".to_string());
        }

        let mut providers = Vec::with_capacity(providers_arr.len());

        for (idx, prov_cfg) in providers_arr.iter().enumerate() {
            let prov_obj = prov_cfg.as_object().ok_or_else(|| {
                format!("jwks_auth: provider[{idx}] must be an object, got: {prov_cfg}")
            })?;
            reject_unknown_fields(prov_obj, PROVIDER_FIELDS, &format!("provider[{idx}]"))?;

            let jwks_endpoint = parse_url_field(prov_obj, "jwks_uri", idx)?;
            let discovery_endpoint = parse_url_field(prov_obj, "discovery_url", idx)?;
            let inline_jwks = parse_inline_jwks(prov_obj, idx)?;
            let jwks_uri = jwks_endpoint.as_ref().map(|endpoint| endpoint.url.clone());
            let discovery_url = discovery_endpoint
                .as_ref()
                .map(|endpoint| endpoint.url.clone());

            let configured_jwks_sources = usize::from(jwks_uri.is_some())
                + usize::from(discovery_url.is_some())
                + usize::from(inline_jwks.is_some());
            if configured_jwks_sources == 0 {
                return Err(format!(
                    "jwks_auth: provider[{}] requires one of 'jwks_uri', 'discovery_url', or 'jwks'",
                    idx
                ));
            }
            if configured_jwks_sources > 1 {
                return Err(format!(
                    "jwks_auth: provider[{}] must configure exactly one of 'jwks_uri', 'discovery_url', or 'jwks'",
                    idx
                ));
            }

            let issuer = optional_non_empty_string(prov_obj, "issuer", idx)?;
            let audiences = parse_audiences(prov_obj, idx)?;
            let token_locations = parse_token_locations(prov_obj, idx)?;

            let required_scopes = parse_string_array(prov_obj, "required_scopes", idx)?;
            let required_roles = parse_string_array(prov_obj, "required_roles", idx)?;

            let scope_claim = optional_provider_claim_path(prov_obj, "scope_claim", idx)?;
            let role_claim = optional_provider_claim_path(prov_obj, "role_claim", idx)?;
            let prov_consumer_identity_claim =
                optional_provider_claim_path(prov_obj, "consumer_identity_claim", idx)?;
            let prov_consumer_header_claim =
                optional_provider_claim_path(prov_obj, "consumer_header_claim", idx)?;
            let forward_original_token =
                optional_provider_bool(prov_obj, "forward_original_token", idx)?.unwrap_or(true);
            let provider_require_exp =
                optional_bool(prov_obj, "require_exp")?.unwrap_or(global_require_exp);
            let provider_claim_headers = parse_claim_headers(
                prov_obj,
                "claim_headers",
                "jwks_auth",
                CLAIM_HEADER_METADATA_PREFIX,
            )?;
            let provider_claim_headers_separator =
                optional_provider_string(prov_obj, "claim_headers_separator", idx)?;
            let require_mtls_binding =
                optional_provider_bool(prov_obj, "require_mtls_binding", idx)?.unwrap_or(false);
            let require_dpop =
                optional_provider_bool(prov_obj, "require_dpop", idx)?.unwrap_or(false);
            let dpop_clock_skew_secs =
                optional_provider_u64(prov_obj, "dpop_clock_skew_secs", idx)?.unwrap_or(30);
            if dpop_clock_skew_secs > 300 {
                return Err(format!(
                    "jwks_auth: 'provider[{idx}].dpop_clock_skew_secs' must be <= 300"
                ));
            }
            let dpop_jti_ttl_secs =
                optional_provider_u64(prov_obj, "dpop_jti_ttl_secs", idx)?.unwrap_or(300);
            if dpop_jti_ttl_secs < dpop_clock_skew_secs.saturating_mul(2) {
                return Err(format!(
                    "jwks_auth: 'provider[{idx}].dpop_jti_ttl_secs' must be at least twice dpop_clock_skew_secs"
                ));
            }
            let dpop_jti_cache_max_entries =
                optional_provider_usize(prov_obj, "dpop_jti_cache_max_entries", idx)?
                    .unwrap_or(DEFAULT_DPOP_JTI_CACHE_MAX_ENTRIES);
            if dpop_jti_cache_max_entries == 0 {
                return Err(format!(
                    "jwks_auth: 'provider[{idx}].dpop_jti_cache_max_entries' must be greater than 0"
                ));
            }
            let dpop_jti_cache = require_dpop.then(|| {
                Arc::new(DpopJtiCache::new(
                    dpop_jti_cache_max_entries,
                    Duration::from_secs(dpop_jti_ttl_secs),
                    shard_amount,
                ))
            });

            let mut warmup_hostnames = Vec::new();
            if let Some(endpoint) = jwks_endpoint.as_ref() {
                warmup_hostnames.push(endpoint.hostname.clone());
            }
            if let Some(endpoint) = discovery_endpoint.as_ref()
                && !warmup_hostnames
                    .iter()
                    .any(|host| host == &endpoint.hostname)
            {
                warmup_hostnames.push(endpoint.hostname.clone());
            }

            let jwks_store_slot: Arc<ArcSwap<Option<Arc<JwksKeyStore>>>> =
                Arc::new(ArcSwap::from_pointee(None));

            let jwks_source = if let Some(ref jwks_json) = inline_jwks {
                let store = JwksKeyStore::from_inline_jwks(jwks_json)?;
                jwks_store_slot.store(Arc::new(Some(Arc::new(store))));
                JwksSource::Inline
            } else if let Some(ref uri) = jwks_uri {
                // Pure construction keeps a local, non-refreshing-yet store so
                // offline validation needs no Tokio runtime. Runtime startup
                // replaces it with the process-wide shared store.
                let store = JwksKeyStore::new(uri.clone(), http_client.clone());
                jwks_store_slot.store(Arc::new(Some(Arc::new(store))));
                JwksSource::Direct(uri.clone())
            } else if let Some(ref disc_url) = discovery_url {
                JwksSource::Discovery(disc_url.clone())
            } else {
                return Err(format!(
                    "jwks_auth: provider[{idx}] has no usable JWKS source"
                ));
            };

            providers.push(JwksProvider {
                issuer,
                audiences,
                token_locations,
                required_scopes,
                required_roles,
                scope_claim,
                role_claim,
                consumer_identity_claim: prov_consumer_identity_claim,
                consumer_header_claim: prov_consumer_header_claim,
                forward_original_token,
                require_exp: provider_require_exp,
                claim_headers: provider_claim_headers,
                claim_headers_separator: provider_claim_headers_separator,
                require_mtls_binding,
                require_dpop,
                dpop_clock_skew: Duration::from_secs(dpop_clock_skew_secs),
                dpop_jti_cache,
                jwks_store: jwks_store_slot,
                jwks_source,
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
            global_scope_claim,
            global_role_claim,
            consumer_identity_claim,
            consumer_header_claim,
            claim_headers,
            claim_headers_separator,
            strip_authorization_on_success,
            has_custom_query_token_locations,
            emit_mesh_request_principal_metadata,
            http_client,
            refresh_interval,
            discovery_tasks: Mutex::new(None),
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

    fn resolve_identity(
        &self,
        claims: &Value,
        provider: &JwksProvider,
        consumer_index: &ConsumerIndex,
    ) -> VerifyOutcome {
        let effective_identity_claim = provider
            .consumer_identity_claim
            .as_deref()
            .unwrap_or(&self.consumer_identity_claim);
        let effective_header_claim = provider
            .consumer_header_claim
            .as_deref()
            .unwrap_or(&self.consumer_header_claim);

        let identity = extract_claim_string(claims, effective_identity_claim);
        let header_value = if effective_header_claim == effective_identity_claim {
            identity.clone()
        } else {
            extract_claim_string(claims, effective_header_claim).or_else(|| identity.clone())
        };

        let consumer = if let Some(ref id) = identity {
            match consumer_index.find_by_identity(id) {
                Some(consumer) => {
                    debug!(
                        "jwks_auth: identified consumer '{}' via claim '{}'='{}'",
                        consumer.username, effective_identity_claim, id
                    );
                    Some(consumer)
                }
                None => {
                    debug!(
                        "jwks_auth: no consumer found for '{}'='{}' — using external identity",
                        effective_identity_claim, id
                    );
                    None
                }
            }
        } else {
            warn!(
                "jwks_auth: token valid but claim '{}' not present",
                effective_identity_claim
            );
            None
        };

        VerifyOutcome::success(consumer, identity, header_value)
    }

    /// Try to validate a token against the allowed configured providers.
    ///
    /// Returns `Ok((claims, provider_index))` on first successful validation,
    /// or `Err(status_code, body)` if no provider validates the token.
    async fn validate_token_for_providers(
        &self,
        token: &str,
        provider_indices: &[usize],
    ) -> Result<(Value, usize), (u16, &'static str)> {
        if provider_indices.is_empty() {
            return Err((401, r#"{"error":"Invalid or unrecognized JWT"}"#));
        }

        // Peek at the unverified issuer to try matching a specific provider first
        let unverified_issuer = peek_unverified_issuer(token);

        // If we have an issuer, try matching providers with that issuer first
        if let Some(ref iss) = unverified_issuer {
            for &idx in provider_indices {
                let Some(prov) = self.providers.get(idx) else {
                    continue;
                };
                if prov.issuer.as_deref() == Some(iss.as_str())
                    && let Some(claims) = try_validate_with_provider(prov, token).await
                {
                    return Ok((claims, idx));
                }
            }
        }

        // Fall through: try all providers (handles no-issuer tokens or issuer mismatch)
        for &idx in provider_indices {
            let Some(prov) = self.providers.get(idx) else {
                continue;
            };
            if let Some(claims) = try_validate_with_provider(prov, token).await {
                return Ok((claims, idx));
            }
        }

        Err((401, r#"{"error":"Invalid or unrecognized JWT"}"#))
    }

    /// Try to validate a token against all configured providers.
    async fn validate_token(&self, token: &str) -> Result<(Value, usize), (u16, &'static str)> {
        let provider_indices: Vec<usize> = (0..self.providers.len()).collect();
        self.validate_token_for_providers(token, &provider_indices)
            .await
    }

    /// Check required_scopes and required_roles for a matched provider.
    fn check_claims_authorization(
        &self,
        claims: &Value,
        provider: &JwksProvider,
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
                plugin_name: "jwks_auth",
            },
        )
    }

    fn check_sender_constraints(
        &self,
        ctx: &RequestContext,
        claims: &Value,
        provider: &JwksProvider,
        token: &str,
    ) -> Result<(), (u16, String)> {
        if provider.require_mtls_binding {
            let Some(cert_der) = ctx.tls_client_cert_der.as_ref() else {
                return Err((401, r#"{"error":"mTLS binding mismatch"}"#.to_string()));
            };
            let Some(expected_thumbprint) = extract_claim_string(claims, "cnf.x5t#S256") else {
                return Err((401, r#"{"error":"mTLS binding mismatch"}"#.to_string()));
            };
            let actual_thumbprint = sha256_base64url_no_pad(cert_der.as_slice());
            if !constant_time_eq(actual_thumbprint.as_bytes(), expected_thumbprint.as_bytes()) {
                return Err((401, r#"{"error":"mTLS binding mismatch"}"#.to_string()));
            }
        }

        if provider.require_dpop {
            let Some(proof) = ctx.headers.get("dpop") else {
                return Err((401, r#"{"error":"DPoP proof required"}"#.to_string()));
            };
            let Some(cache) = provider.dpop_jti_cache.as_ref() else {
                return Err((401, r#"{"error":"DPoP proof required"}"#.to_string()));
            };
            let Some(host) = ctx
                .headers
                .get("host")
                .or_else(|| ctx.headers.get(":authority"))
            else {
                return Err((401, r#"{"error":"DPoP URL mismatch"}"#.to_string()));
            };
            let scheme = ctx
                .metadata
                .get("ferrum.frontend_scheme")
                .map(String::as_str)
                .unwrap_or("http");
            let Some(htu) = dpop::canonical_htu(scheme, host, &ctx.path) else {
                return Err((401, r#"{"error":"DPoP URL mismatch"}"#.to_string()));
            };
            if let Err(reason) = dpop::verify(DpopVerifyInput {
                proof,
                access_token: token,
                access_token_claims: claims,
                method: &ctx.method,
                htu: &htu,
                clock_skew: provider.dpop_clock_skew,
                cache,
            }) {
                let body = if reason == "DPoP replay" {
                    r#"{"error":"DPoP replay"}"#
                } else {
                    r#"{"error":"DPoP validation failed"}"#
                };
                return Err((401, body.to_string()));
            }
        }

        Ok(())
    }

    fn emit_claim_headers(
        &self,
        ctx: &mut RequestContext,
        claims: &Value,
        provider: &JwksProvider,
    ) {
        let mappings = if provider.claim_headers.is_empty() {
            &self.claim_headers
        } else {
            &provider.claim_headers
        };
        if mappings.is_empty() {
            return;
        }
        let separator = provider
            .claim_headers_separator
            .as_deref()
            .unwrap_or(&self.claim_headers_separator);
        emit_claim_headers_to_context(ctx, claims, mappings, separator);
    }

    async fn authenticate_request(
        &self,
        ctx: &mut RequestContext,
        consumer_index: &ConsumerIndex,
    ) -> PluginResult {
        let credential = self.extract_jwks_credential(ctx);

        match credential {
            JwksExtractedCredential::Missing => {
                debug!("jwks_auth: no credential present");
                if self.emit_mesh_request_principal_metadata {
                    ctx.metadata.insert(
                        "mesh_request_auth.permissive_missing_token".to_string(),
                        "true".to_string(),
                    );
                }
                PluginResult::Continue
            }
            JwksExtractedCredential::InvalidFormat(body) => reject(401, body),
            JwksExtractedCredential::BearerToken {
                token,
                provider_indices,
            } => {
                let (claims, provider_idx) = match self
                    .validate_token_for_providers(&token, &provider_indices)
                    .await
                {
                    Ok(result) => result,
                    Err((status, body)) => return reject(status, body.to_string()),
                };

                let provider = &self.providers[provider_idx];
                if let Err((status, body)) =
                    self.check_sender_constraints(ctx, &claims, provider, &token)
                {
                    return reject(status, body);
                }
                if let Err((status, body)) = self.check_claims_authorization(&claims, provider) {
                    return reject(status, body);
                }

                match self.resolve_identity(&claims, provider, consumer_index) {
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
                            debug!("jwks_auth: identified consumer '{}'", consumer.username);
                            ctx.identified_consumer = Some(consumer);
                        }

                        if let Some(external_identity) = external_identity {
                            ctx.authenticated_identity = Some(external_identity);
                        }
                        if let Some(external_identity_header) = external_identity_header {
                            ctx.authenticated_identity_header = Some(external_identity_header);
                        }

                        if ctx.auth_method.is_none()
                            && (consumer_identified || external_identity_identified)
                        {
                            ctx.auth_method = Some("jwks_auth");
                        }
                        if self.emit_mesh_request_principal_metadata {
                            set_mesh_request_principal_metadata(&claims, ctx);
                        }
                        self.emit_claim_headers(ctx, &claims, provider);

                        if !provider.forward_original_token {
                            mark_original_token_stripping_metadata(ctx, provider);
                        }
                        PluginResult::Continue
                    }
                    VerifyOutcome::NotApplicable => PluginResult::Continue,
                    VerifyOutcome::InvalidFormat(body)
                    | VerifyOutcome::Invalid(body)
                    | VerifyOutcome::ConsumerNotFound(body)
                    | VerifyOutcome::VerificationFailed(body) => reject(401, body),
                    VerifyOutcome::Forbidden(body) => reject(403, body),
                    VerifyOutcome::Internal(body) => reject(500, body),
                }
            }
        }
    }

    fn extract_jwks_credential(&self, ctx: &RequestContext) -> JwksExtractedCredential {
        let mut first_invalid_format: Option<String> = None;
        for (idx, provider) in self.providers.iter().enumerate() {
            if provider.token_locations.is_empty() {
                continue;
            }

            for location in &provider.token_locations {
                match extract_from_location(location, ctx) {
                    TokenLocationExtract::Missing => {}
                    TokenLocationExtract::Credential(ExtractedCredential::InvalidFormat(body)) => {
                        first_invalid_format.get_or_insert(body);
                    }
                    TokenLocationExtract::Credential(ExtractedCredential::BearerToken(token)) => {
                        let mut provider_indices = Vec::with_capacity(1);
                        provider_indices.push(idx);
                        for (other_idx, other_provider) in self.providers.iter().enumerate() {
                            if other_idx != idx
                                && !other_provider.token_locations.is_empty()
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
                        return JwksExtractedCredential::BearerToken {
                            token,
                            provider_indices,
                        };
                    }
                    TokenLocationExtract::Credential(_) => {}
                }
            }
        }

        let provider_indices: Vec<usize> = self
            .providers
            .iter()
            .enumerate()
            .filter_map(|(idx, provider)| provider.token_locations.is_empty().then_some(idx))
            .collect();
        if provider_indices.is_empty() {
            return first_invalid_format
                .map(JwksExtractedCredential::InvalidFormat)
                .unwrap_or(JwksExtractedCredential::Missing);
        }

        match extract_authorization_bearer(ctx) {
            ExtractedCredential::Missing => first_invalid_format
                .map(JwksExtractedCredential::InvalidFormat)
                .unwrap_or(JwksExtractedCredential::Missing),
            ExtractedCredential::InvalidFormat(body) => first_invalid_format
                .map(JwksExtractedCredential::InvalidFormat)
                .unwrap_or(JwksExtractedCredential::InvalidFormat(body)),
            ExtractedCredential::BearerToken(token) => JwksExtractedCredential::BearerToken {
                token,
                provider_indices,
            },
            ExtractedCredential::ApiKey(_)
            | ExtractedCredential::BasicAuth { .. }
            | ExtractedCredential::HmacAuth(_)
            | ExtractedCredential::MtlsCert { .. } => JwksExtractedCredential::Missing,
        }
    }
}

#[async_trait]
impl AuthMechanism for JwksAuth {
    fn mechanism_name(&self) -> &'static str {
        "jwks_auth"
    }

    fn extract(&self, ctx: &RequestContext) -> ExtractedCredential {
        match self.extract_jwks_credential(ctx) {
            JwksExtractedCredential::Missing => ExtractedCredential::Missing,
            JwksExtractedCredential::InvalidFormat(body) => {
                ExtractedCredential::InvalidFormat(body)
            }
            JwksExtractedCredential::BearerToken { token, .. } => {
                ExtractedCredential::BearerToken(token)
            }
        }
    }

    async fn verify(
        &self,
        credential: ExtractedCredential,
        consumer_index: &ConsumerIndex,
    ) -> VerifyOutcome {
        let ExtractedCredential::BearerToken(token) = credential else {
            return VerifyOutcome::NotApplicable;
        };

        let (claims, provider_idx) = match self.validate_token(&token).await {
            Ok(result) => result,
            Err((status, body)) => {
                return if status == 403 {
                    VerifyOutcome::Forbidden(body.to_string())
                } else {
                    VerifyOutcome::InvalidFormat(body.to_string())
                };
            }
        };

        let provider = &self.providers[provider_idx];
        if let Err((status, body)) = self.check_claims_authorization(&claims, provider) {
            return if status == 403 {
                VerifyOutcome::Forbidden(body)
            } else {
                VerifyOutcome::Invalid(body)
            };
        }

        self.resolve_identity(&claims, provider, consumer_index)
    }
}

enum JwksExtractedCredential {
    BearerToken {
        token: String,
        provider_indices: Vec<usize>,
    },
    InvalidFormat(String),
    Missing,
}

fn mark_original_token_stripping_metadata(ctx: &mut RequestContext, provider: &JwksProvider) {
    mark_token_stripping_metadata(
        ctx,
        &provider.token_locations,
        STRIP_AUTHORIZATION_METADATA_KEY,
        STRIP_HEADER_METADATA_PREFIX,
        STRIP_QUERY_PARAM_METADATA_PREFIX,
    );
}

#[async_trait]
impl super::Plugin for JwksAuth {
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
        crate::plugins::HTTP_FAMILY_PROTOCOLS
    }

    fn start_background_tasks(&self) -> Result<(), String> {
        let mut task_slot = self
            .discovery_tasks
            .lock()
            .map_err(|_| "jwks_auth: discovery task state lock poisoned".to_string())?;
        if task_slot.is_some() {
            return Ok(());
        }

        let has_remote_source = self
            .providers
            .iter()
            .any(|provider| !matches!(&provider.jwks_source, JwksSource::Inline));
        if !has_remote_source {
            *task_slot = Some(Vec::new());
            return Ok(());
        }

        let runtime = tokio::runtime::Handle::try_current()
            .map_err(|_| "jwks_auth: live JWKS startup requires a Tokio runtime".to_string())?;
        let mut tasks = Vec::new();
        for provider in &self.providers {
            match &provider.jwks_source {
                JwksSource::Inline => {}
                JwksSource::Direct(uri) => {
                    let store =
                        get_or_create_jwks_store(uri, &self.http_client, self.refresh_interval);
                    provider.jwks_store.store(Arc::new(Some(store)));
                }
                JwksSource::Discovery(discovery_url) => {
                    // Equivalent replacement generations acquire the last
                    // validated store synchronously. Rediscovery still runs,
                    // but an IdP outage cannot erase usable verification keys.
                    if let Some(uri) = last_discovered_jwks_uri(discovery_url) {
                        let store = get_or_create_jwks_store(
                            &uri,
                            &self.http_client,
                            self.refresh_interval,
                        );
                        provider.jwks_store.store(Arc::new(Some(store)));
                    }
                    tasks.push(spawn_discovery_task(
                        &runtime,
                        Arc::clone(&provider.jwks_store),
                        self.http_client.clone(),
                        discovery_url.clone(),
                        self.refresh_interval,
                    ));
                }
            }
        }
        *task_slot = Some(tasks);
        Ok(())
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
            || !self.claim_headers.is_empty()
            || self
                .providers
                .iter()
                .any(|provider| !provider.claim_headers.is_empty())
    }

    async fn before_proxy(
        &self,
        ctx: &mut RequestContext,
        headers: &mut std::collections::HashMap<String, String>,
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
        for prov in &self.providers {
            hosts.extend(prov.warmup_hostnames.iter().cloned());
            let guard = prov.jwks_store.load();
            if let Some(ref store) = **guard
                && store.is_refreshable()
                && let Some(host) = hostname_from_url(store.jwks_uri())
                && !hosts.iter().any(|known| known == &host)
            {
                hosts.push(host);
            }
        }
        hosts
    }

    fn active_jwks_uris(&self) -> Vec<String> {
        let mut uris = Vec::new();
        for prov in &self.providers {
            let guard = prov.jwks_store.load();
            if let Some(ref store) = **guard
                && store.is_refreshable()
            {
                uris.push(store.jwks_uri().to_string());
            }
        }
        uris
    }

    fn active_jwks_refresh_requirements(&self) -> Vec<(String, Duration)> {
        self.active_jwks_uris()
            .into_iter()
            .map(|uri| (uri, self.refresh_interval))
            .collect()
    }

    fn requires_decoded_query_params(&self) -> bool {
        self.has_custom_query_token_locations
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn spawn_discovery_task(
    runtime: &tokio::runtime::Handle,
    slot: Arc<ArcSwap<Option<Arc<JwksKeyStore>>>>,
    client: PluginHttpClient,
    discovery_url: String,
    refresh_interval: Duration,
) -> tokio::task::JoinHandle<()> {
    runtime.spawn(async move {
        const INITIAL_BACKOFF_SECS: u64 = 2;
        const MAX_BACKOFF_SECS: u64 = 300;

        let mut attempt: u32 = 0;
        loop {
            if attempt > 0 {
                let backoff_secs = INITIAL_BACKOFF_SECS
                    .saturating_mul(1u64 << (attempt - 1).min(7))
                    .min(MAX_BACKOFF_SECS);
                let backoff = Duration::from_secs(backoff_secs);
                warn!(
                    "jwks_auth OIDC discovery attempt {} failed — retrying in {:?}",
                    attempt, backoff
                );
                tokio::time::sleep(backoff).await;
            }

            match discover_jwks_uri(&client, &discovery_url).await {
                Ok(uri) => {
                    info!(
                        "jwks_auth OIDC discovery resolved a JWKS endpoint at {}",
                        redacted_jwks_uri(&uri)
                    );
                    let store = get_or_create_jwks_store(&uri, &client, refresh_interval);
                    let previous = slot.load().as_ref().as_ref().cloned();

                    if previous
                        .as_ref()
                        .is_some_and(|current| current.jwks_uri() == uri)
                    {
                        remember_discovered_jwks_uri(&discovery_url, &uri);
                        return;
                    }

                    let previous_has_keys = previous.as_ref().is_some_and(|store| store.has_keys());
                    if previous_has_keys {
                        match store.fetch_keys_if_empty().await {
                            Ok(_) if store.has_keys() => {}
                            Ok(_) => {
                                warn!(
                                    "jwks_auth OIDC: discovered replacement JWKS endpoint has no usable keys; retaining last-known-good store"
                                );
                                drop(store);
                                retire_jwks_store_if_unreferenced(&uri);
                                attempt = attempt.saturating_add(1);
                                continue;
                            }
                            Err(error) => {
                                warn!(
                                    "jwks_auth OIDC: replacement JWKS fetch failed: {}; retaining last-known-good store",
                                    error
                                );
                                drop(store);
                                retire_jwks_store_if_unreferenced(&uri);
                                attempt = attempt.saturating_add(1);
                                continue;
                            }
                        }
                    }

                    let previous_uri = previous
                        .as_ref()
                        .map(|current| current.jwks_uri().to_string());
                    slot.store(Arc::new(Some(Arc::clone(&store))));
                    remember_discovered_jwks_uri(&discovery_url, &uri);

                    if !previous_has_keys
                        && let Err(error) = store.fetch_keys_if_empty().await
                    {
                        warn!("jwks_auth OIDC: initial JWKS fetch failed: {}", error);
                    }

                    drop(previous);
                    if let Some(previous_uri) = previous_uri
                        && previous_uri != uri
                    {
                        retire_jwks_store_if_unreferenced(&previous_uri);
                    }
                    return;
                }
                Err(error) => {
                    warn!(
                        "jwks_auth OIDC discovery attempt {} failed: {} — will keep retrying in background",
                        attempt + 1,
                        error
                    );
                }
            }
            attempt = attempt.saturating_add(1);
        }
    })
}

/// Try to validate a JWT against a single provider's JWKS store.
async fn try_validate_with_provider(provider: &JwksProvider, token: &str) -> Option<Value> {
    let guard = provider.jwks_store.load();
    let store = guard.as_ref().as_ref()?;
    verify_jwt_with_jwks(
        token,
        store,
        &JwtVerifyParams {
            issuer: provider.issuer.as_deref(),
            audiences: &provider.audiences,
            require_exp: provider.require_exp,
            leeway_secs: 0,
            validate_nbf: false,
        },
    )
    .await
}

/// Parse a JSON value as an array of strings, or empty vec if not present/valid.
struct ParsedEndpoint {
    url: String,
    hostname: String,
}

fn reject_unknown_fields(
    config: &Map<String, Value>,
    allowed: &[&str],
    context: &str,
) -> Result<(), String> {
    for field in config.keys() {
        if !allowed.contains(&field.as_str()) {
            return Err(format!("jwks_auth: unknown field '{field}' in {context}"));
        }
    }
    Ok(())
}

fn optional_u64(
    config: &Map<String, Value>,
    field: &str,
    default_value: u64,
) -> Result<u64, String> {
    let Some(value) = config.get(field) else {
        return Ok(default_value);
    };
    value
        .as_u64()
        .ok_or_else(|| format!("jwks_auth: '{field}' must be an unsigned integer, got: {value}"))
}

fn optional_bool(config: &Map<String, Value>, field: &str) -> Result<Option<bool>, String> {
    config
        .get(field)
        .map(|value| {
            value
                .as_bool()
                .ok_or_else(|| format!("jwks_auth: '{field}' must be a boolean, got: {value}"))
        })
        .transpose()
}

fn optional_claim_path(
    config: &Map<String, Value>,
    field: &str,
    default_value: &str,
) -> Result<String, String> {
    match config.get(field) {
        Some(value) => parse_claim_path_value(field, value, "jwks_auth"),
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
        "jwks_auth",
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
        format!("jwks_auth: 'provider[{provider_idx}].{field}' must be a string, got: {value}")
    })?;
    let value = raw.trim();
    if value.is_empty() {
        return Err(format!(
            "jwks_auth: 'provider[{provider_idx}].{field}' must not be empty"
        ));
    }
    Ok(Some(value.to_string()))
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
        format!("jwks_auth: 'provider[{provider_idx}].{field}' must be a URL string, got: {value}")
    })?;
    let url = raw.trim();
    if url.is_empty() {
        return Err(format!(
            "jwks_auth: 'provider[{provider_idx}].{field}' must not be empty"
        ));
    }
    let parsed = Url::parse(url).map_err(|e| {
        format!("jwks_auth: 'provider[{provider_idx}].{field}' is not a valid URL: {e}")
    })?;
    if !parsed.username().is_empty() || parsed.password().is_some() {
        return Err(format!(
            "jwks_auth: 'provider[{provider_idx}].{field}' must not contain URL userinfo"
        ));
    }
    match parsed.scheme() {
        "https" => {}
        "http" if is_local_auth_endpoint(&parsed) => {}
        "http" => {
            return Err(format!(
                "jwks_auth: 'provider[{provider_idx}].{field}' must use https except for literal loopback or localhost"
            ));
        }
        scheme => {
            return Err(format!(
                "jwks_auth: 'provider[{provider_idx}].{field}' must use http or https, got: {scheme}"
            ));
        }
    }
    if !has_non_empty_authority(url) {
        return Err(format!(
            "jwks_auth: 'provider[{provider_idx}].{field}' must include a hostname"
        ));
    }
    let hostname = hostname_from_parsed_url(&parsed).ok_or_else(|| {
        format!("jwks_auth: 'provider[{provider_idx}].{field}' must include a hostname")
    })?;
    Ok(Some(ParsedEndpoint {
        url: url.to_string(),
        hostname,
    }))
}

fn is_local_auth_endpoint(parsed: &Url) -> bool {
    match parsed.host() {
        Some(Host::Domain(hostname)) => hostname.eq_ignore_ascii_case("localhost"),
        Some(Host::Ipv4(address)) => address.is_loopback(),
        Some(Host::Ipv6(address)) => address.is_loopback(),
        None => false,
    }
}

fn hostname_from_parsed_url(parsed: &Url) -> Option<String> {
    let host = parsed.host()?;
    Some(match host {
        Host::Domain(hostname) => hostname.to_string(),
        Host::Ipv4(address) => address.to_string(),
        Host::Ipv6(address) => address.to_string(),
    })
}

fn has_non_empty_authority(url: &str) -> bool {
    let Some((_, after_scheme)) = url.split_once(':') else {
        return false;
    };
    let Some(authority_and_path) = after_scheme.strip_prefix("//") else {
        return false;
    };
    let authority_end = authority_and_path
        .find(['/', '?', '#'])
        .unwrap_or(authority_and_path.len());

    authority_end > 0
}

fn parse_inline_jwks(
    config: &Map<String, Value>,
    provider_idx: usize,
) -> Result<Option<String>, String> {
    let Some(value) = config.get("jwks") else {
        return Ok(None);
    };

    match value {
        Value::String(raw) => {
            let jwks = raw.trim();
            if jwks.is_empty() {
                return Err(format!(
                    "jwks_auth: 'provider[{provider_idx}].jwks' must not be empty"
                ));
            }
            Ok(Some(jwks.to_string()))
        }
        Value::Object(_) => serde_json::to_string(value)
            .map(Some)
            .map_err(|e| format!("jwks_auth: 'provider[{provider_idx}].jwks' is invalid: {e}")),
        _ => Err(format!(
            "jwks_auth: 'provider[{provider_idx}].jwks' must be a JWKS JSON string or object, got: {value}"
        )),
    }
}

fn parse_audiences(
    config: &Map<String, Value>,
    provider_idx: usize,
) -> Result<Vec<String>, String> {
    let legacy_audience = optional_non_empty_string(config, "audience", provider_idx)?;
    let mut audiences = parse_string_array(config, "audiences", provider_idx)?;

    if let Some(audience) = legacy_audience
        && !audiences.iter().any(|known| known == &audience)
    {
        audiences.push(audience);
    }

    Ok(audiences)
}

fn parse_string_array(
    config: &Map<String, Value>,
    field: &str,
    provider_idx: usize,
) -> Result<Vec<String>, String> {
    let Some(value) = config.get(field) else {
        return Ok(Vec::new());
    };
    let Some(arr) = value.as_array() else {
        return Err(format!(
            "jwks_auth: 'provider[{provider_idx}].{field}' must be an array of strings, got: {value}"
        ));
    };
    let mut values = Vec::with_capacity(arr.len());
    for (idx, entry) in arr.iter().enumerate() {
        let raw = entry.as_str().ok_or_else(|| {
            format!(
                "jwks_auth: 'provider[{provider_idx}].{field}[{idx}]' must be a string, got: {entry}"
            )
        })?;
        let value = raw.trim();
        if value.is_empty() {
            return Err(format!(
                "jwks_auth: 'provider[{provider_idx}].{field}[{idx}]' must not be empty"
            ));
        }
        values.push(value.to_string());
    }
    Ok(values)
}

fn parse_token_locations(
    config: &Map<String, Value>,
    provider_idx: usize,
) -> Result<Vec<TokenLocation>, String> {
    let mut locations = Vec::new();

    if let Some(value) = config.get("from_headers") {
        let headers = value.as_array().ok_or_else(|| {
            format!(
                "jwks_auth: 'provider[{provider_idx}].from_headers' must be an array of objects, got: {value}"
            )
        })?;
        locations.reserve(headers.len());
        for (idx, header) in headers.iter().enumerate() {
            let object = header.as_object().ok_or_else(|| {
                format!(
                    "jwks_auth: 'provider[{provider_idx}].from_headers[{idx}]' must be an object, got: {header}"
                )
            })?;
            reject_unknown_fields(
                object,
                &["name", "prefix"],
                &format!("provider[{provider_idx}].from_headers[{idx}]"),
            )?;
            let name_value = object.get("name").ok_or_else(|| {
                format!(
                    "jwks_auth: 'provider[{provider_idx}].from_headers[{idx}].name' is required"
                )
            })?;
            let raw_name = name_value.as_str().ok_or_else(|| {
                format!(
                    "jwks_auth: 'provider[{provider_idx}].from_headers[{idx}].name' must be a string, got: {name_value}"
                )
            })?;
            let name = raw_name.trim().to_ascii_lowercase();
            if name.is_empty() {
                return Err(format!(
                    "jwks_auth: 'provider[{provider_idx}].from_headers[{idx}].name' must not be empty"
                ));
            }
            let name = HeaderName::from_bytes(name.as_bytes())
                .map_err(|e| {
                    format!(
                        "jwks_auth: 'provider[{provider_idx}].from_headers[{idx}].name' is not a valid HTTP header name: {e}"
                    )
                })?
                .as_str()
                .to_string();
            let prefix = match object.get("prefix") {
                Some(Value::String(raw)) if raw.is_empty() => None,
                Some(Value::String(raw)) => Some(raw.clone()),
                Some(Value::Null) | None => None,
                Some(value) => {
                    return Err(format!(
                        "jwks_auth: 'provider[{provider_idx}].from_headers[{idx}].prefix' must be a string, got: {value}"
                    ));
                }
            };

            locations.push(TokenLocation::Header(TokenHeaderLocation { name, prefix }));
        }
    }

    let params = parse_string_array(config, "from_params", provider_idx)?;
    locations.extend(params.into_iter().map(TokenLocation::QueryParam));

    Ok(locations)
}

fn optional_provider_bool(
    config: &Map<String, Value>,
    field: &str,
    provider_idx: usize,
) -> Result<Option<bool>, String> {
    let Some(value) = config.get(field) else {
        return Ok(None);
    };
    value
        .as_bool()
        .ok_or_else(|| {
            format!("jwks_auth: 'provider[{provider_idx}].{field}' must be a boolean, got: {value}")
        })
        .map(Some)
}

fn optional_provider_string(
    config: &Map<String, Value>,
    field: &str,
    provider_idx: usize,
) -> Result<Option<String>, String> {
    let Some(value) = config.get(field) else {
        return Ok(None);
    };
    let raw = value.as_str().ok_or_else(|| {
        format!("jwks_auth: 'provider[{provider_idx}].{field}' must be a string, got: {value}")
    })?;
    if raw.is_empty() {
        return Err(format!(
            "jwks_auth: 'provider[{provider_idx}].{field}' must not be empty"
        ));
    }
    Ok(Some(raw.to_string()))
}

fn optional_provider_u64(
    config: &Map<String, Value>,
    field: &str,
    provider_idx: usize,
) -> Result<Option<u64>, String> {
    let Some(value) = config.get(field) else {
        return Ok(None);
    };
    value
        .as_u64()
        .ok_or_else(|| {
            format!(
                "jwks_auth: 'provider[{provider_idx}].{field}' must be an unsigned integer, got: {value}"
            )
        })
        .map(Some)
}

fn optional_provider_usize(
    config: &Map<String, Value>,
    field: &str,
    provider_idx: usize,
) -> Result<Option<usize>, String> {
    let Some(value) = optional_provider_u64(config, field, provider_idx)? else {
        return Ok(None);
    };
    usize::try_from(value)
        .map(Some)
        .map_err(|_| format!("jwks_auth: 'provider[{provider_idx}].{field}' is too large"))
}

fn reject(status_code: u16, body: String) -> PluginResult {
    PluginResult::Reject {
        status_code,
        body,
        headers: std::collections::HashMap::new(),
    }
}

/// Fetch the OIDC discovery document and extract a validated `jwks_uri`.
///
/// The discovery document is fetched from the operator-configured
/// `discovery_url`, but its `jwks_uri` field is attacker-controlled if the
/// IdP is spoofed, compromised, or the discovery response is tampered with in
/// transit. Fetching that URL unvalidated is a server-side request forgery
/// (SSRF) vector: it could steer the gateway at an internal service or a cloud
/// metadata endpoint (e.g. `http://169.254.169.254/...`) from inside the trust
/// boundary. We therefore screen the discovered URI before returning it, and
/// the caller treats any rejection as a normal discovery failure (fail closed:
/// retried in the background, no store created). The DNS-layer IP screening on
/// `PluginHttpClient` is a backstop, not a substitute, so the host is validated
/// here too.
async fn discover_jwks_uri(
    http_client: &PluginHttpClient,
    discovery_url: &str,
) -> Result<String, String> {
    let redacted_discovery_url = redacted_jwks_uri(discovery_url);
    let req = http_client.get().get(discovery_url);
    let response = http_client
        .execute_redacted(req, "jwks_auth_oidc_discovery", &redacted_discovery_url)
        .await
        .map_err(|e| format!("OIDC discovery request failed: {e}"))?;

    if !response.status().is_success() {
        return Err(format!(
            "OIDC discovery endpoint returned HTTP {}",
            response.status()
        ));
    }

    let body = read_response_body_bounded(response, MAX_DISCOVERY_RESPONSE_BYTES)
        .await
        .map_err(|e| format!("OIDC discovery response rejected: {e}"))?;
    let body: Value = serde_json::from_slice(&body)
        .map_err(|e| format!("OIDC discovery response parse failed: {e}"))?;

    let jwks_uri = body["jwks_uri"]
        .as_str()
        .ok_or_else(|| "OIDC discovery document missing 'jwks_uri' field".to_string())?;
    if jwks_uri.len() > MAX_DISCOVERED_JWKS_URI_BYTES {
        return Err(format!(
            "OIDC discovery jwks_uri exceeds {MAX_DISCOVERED_JWKS_URI_BYTES} bytes"
        ));
    }

    validate_discovered_jwks_uri(jwks_uri, discovery_url)
}

/// Validate a `jwks_uri` extracted from an OIDC discovery document against SSRF.
///
/// Hardening, in order:
/// 1. The URI must parse as a URL with a non-empty hostname.
/// 2. The scheme must be `http` or `https`. The same-origin rule below ensures
///    that a discovered URL cannot weaken the configured discovery transport;
///    non-URL schemes (e.g. `file:`, `gopher:`) are rejected.
/// 3. The discovered JWKS URL must use the same origin as the `discovery_url`:
///    scheme, host, and effective port must match. This blocks a spoofed or
///    tampered discovery document from redirecting the gateway to an attacker-
///    chosen host, downgrading HTTPS discovery to cleartext JWKS, or pivoting
///    to a different service on the same host through an unexpected port.
///    Operators whose IdP serves JWKS from a different origin than discovery
///    (e.g. Google: `accounts.google.com` vs `www.googleapis.com`) should
///    configure `jwks_uri` directly instead of `discovery_url`.
///
/// OIDC discovery and the follow-on JWKS fetch use the no-redirect plugin HTTP
/// client path. The validated URL is therefore the URL actually fetched rather
/// than only the first hop before an automatic 3xx follow.
fn validate_discovered_jwks_uri(jwks_uri: &str, discovery_url: &str) -> Result<String, String> {
    let parsed = Url::parse(jwks_uri).map_err(|e| {
        format!("OIDC discovery returned an invalid jwks_uri (not a valid URL): {e}")
    })?;

    if !parsed.username().is_empty() || parsed.password().is_some() {
        return Err("OIDC discovery returned a jwks_uri containing userinfo".to_string());
    }

    match parsed.scheme() {
        "http" | "https" => {}
        scheme => {
            return Err(format!(
                "OIDC discovery returned a jwks_uri with disallowed scheme '{scheme}' (must be http or https)"
            ));
        }
    }

    let discovery = Url::parse(discovery_url)
        .map_err(|e| format!("OIDC discovery_url is not parseable for jwks_uri comparison: {e}"))?;
    let jwks_origin = origin_from_parsed_url(&parsed).ok_or_else(|| {
        "OIDC discovery returned a jwks_uri without a parseable origin".to_string()
    })?;
    let discovery_origin = origin_from_parsed_url(&discovery).ok_or_else(|| {
        "OIDC discovery_url has no parseable origin for jwks_uri comparison".to_string()
    })?;

    if discovery_origin.scheme == "https" && jwks_origin.scheme == "http" {
        return Err(
            "OIDC discovery returned a jwks_uri that downgrades HTTPS discovery to HTTP"
                .to_string(),
        );
    }

    if jwks_origin != discovery_origin {
        return Err(format!(
            "OIDC discovery returned a jwks_uri origin '{}' that does not match the discovery_url origin '{}'",
            jwks_origin.display(),
            discovery_origin.display()
        ));
    }

    Ok(jwks_uri.to_string())
}

#[derive(Debug, Eq, PartialEq)]
struct UrlOrigin {
    scheme: String,
    host: String,
    port: u16,
}

impl UrlOrigin {
    fn display(&self) -> String {
        format!("{}://{}:{}", self.scheme, self.host, self.port)
    }
}

fn origin_from_parsed_url(parsed: &Url) -> Option<UrlOrigin> {
    Some(UrlOrigin {
        scheme: parsed.scheme().to_ascii_lowercase(),
        host: hostname_from_parsed_url(parsed)?.to_ascii_lowercase(),
        port: parsed.port_or_known_default()?,
    })
}

/// Set `mesh.request_principal` metadata to `{iss}/{sub}` when both claims are
/// present, plus the JWT-derived attributes consumed by mesh
/// `AuthorizationPolicy` `when:` conditions (`request.auth.audiences` and
/// `request.auth.claims[...]`).
///
/// Only emitted when the auto-injected mesh `RequestAuthentication` plugin set
/// `emit_mesh_request_principal_metadata`, so non-mesh `jwks_auth` instances
/// pay nothing. Audience and claim attributes are stored on dedicated
/// `RequestContext` fields, not generic metadata, so they do not flow into
/// transaction logs. Claim fan-out is bounded by the number of string /
/// string-array leaves in the already-validated token; nested object claims are
/// materialized only at leaf paths so nested Istio condition keys remain
/// addressable without serializing whole objects.
fn set_mesh_request_principal_metadata(claims: &Value, ctx: &mut RequestContext) {
    if let (Some(iss), Some(sub)) = (
        claims.get("iss").and_then(|v| v.as_str()),
        claims.get("sub").and_then(|v| v.as_str()),
    ) {
        ctx.metadata
            .insert("mesh.request_principal".to_string(), format!("{iss}/{sub}"));
    }

    // `request.auth.audiences` — string or string-array form.
    if let Some(aud) = claims.get("aud")
        && let Some(audiences) = string_scalar_or_array(aud)
    {
        ctx.mesh_request_auth_audiences = audiences;
    }

    // `request.auth.claims[<name>]` — scalar claims and string arrays only.
    // Nested objects are emitted with Istio's bracket path encoding, e.g.
    // `request.auth.claims[realm_access][roles]` is stored under
    // `realm_access][roles`. Claim-name segments containing bracket syntax
    // are skipped so a top-level claim literally named `realm_access][roles`
    // cannot masquerade as a nested path.
    if let Some(obj) = claims.as_object() {
        for (name, value) in obj {
            if claim_path_segment_is_ambiguous(name) {
                continue;
            }
            set_mesh_claim_attribute(name, value, ctx);
        }
    }
}

/// Render a single JWT claim leaf into the string form Istio uses for
/// `request.auth.claims[...]` matching. String claims render directly; string
/// arrays stay as lists so one item containing a comma does not broaden policy
/// matching. Objects and non-string leaves are skipped by this leaf renderer;
/// object traversal happens in [`set_mesh_claim_attribute`].
fn render_claim_leaf_attribute_value(value: &Value) -> Option<JwtAuthAttributeValue> {
    match value {
        Value::String(s) => Some(JwtAuthAttributeValue::Scalar(s.clone())),
        Value::Array(_) => string_scalar_or_array(value).map(JwtAuthAttributeValue::StringList),
        Value::Bool(_) | Value::Number(_) | Value::Null | Value::Object(_) => None,
    }
}

fn set_mesh_claim_attribute(path: &str, value: &Value, ctx: &mut RequestContext) {
    if let Some(rendered) = render_claim_leaf_attribute_value(value) {
        ctx.mesh_request_auth_claims
            .insert(path.to_string(), rendered);
        return;
    }

    let Value::Object(obj) = value else {
        return;
    };

    for (name, nested) in obj {
        if claim_path_segment_is_ambiguous(name) {
            continue;
        }
        let mut nested_path = String::with_capacity(path.len() + name.len() + 2);
        nested_path.push_str(path);
        nested_path.push_str("][");
        nested_path.push_str(name);
        set_mesh_claim_attribute(&nested_path, nested, ctx);
    }
}

fn claim_path_segment_is_ambiguous(segment: &str) -> bool {
    segment.contains('[') || segment.contains(']')
}

/// Extract a JSON value that is either a single string scalar or an array of
/// strings. Returns `None` for other shapes.
fn string_scalar_or_array(value: &Value) -> Option<Vec<String>> {
    match value {
        Value::String(s) => Some(vec![s.clone()]),
        Value::Array(items) => {
            let parts: Vec<String> = items
                .iter()
                .map(|item| item.as_str().map(str::to_string))
                .collect::<Option<Vec<_>>>()?;
            if parts.is_empty() { None } else { Some(parts) }
        }
        _ => None,
    }
}

/// Extract the hostname from a URL string, if parseable.
fn hostname_from_url(url: &str) -> Option<String> {
    Url::parse(url)
        .ok()
        .and_then(|u| hostname_from_parsed_url(&u))
}

#[cfg(test)]
mod configuration_tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn dpop_replay_cache_uses_published_default_capacity() {
        let plugin = JwksAuth::new(
            &json!({
                "providers": [{
                    "jwks": {"keys": []},
                    "require_dpop": true
                }]
            }),
            PluginHttpClient::default(),
        )
        .expect("valid inline provider");

        let capacity = plugin.providers[0]
            .dpop_jti_cache
            .as_ref()
            .map(|cache| cache.max_entries());
        assert_eq!(capacity, Some(DEFAULT_DPOP_JTI_CACHE_MAX_ENTRIES));
    }
}
