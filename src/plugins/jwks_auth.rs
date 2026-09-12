use arc_swap::ArcSwap;
use async_trait::async_trait;
use http::header::HeaderName;
use serde_json::Map;
use serde_json::Value;
use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tracing::{debug, info, warn};
use url::{Host, Url};

use crate::consumer_index::ConsumerIndex;

use super::utils::PluginHttpClient;
use super::utils::auth_attempt::AuthenticationAttempt;
use super::utils::auth_flow::constant_time_eq;
use super::utils::auth_flow::{
    AuthMechanism, ExtractedCredential, VerifyOutcome, commit_authentication_attempt,
    credential_deadline_from_claims, nonblank_identity,
};
use super::utils::cert_hash::sha256_base64url_no_pad;
use super::utils::claim_header_fanout::{
    ClaimHeaderDestinations, ClaimHeaderMapping, apply_claim_headers_from_context,
    emit_claim_headers_to_attempt, emit_output_claim_headers_to_attempt, parse_claim_header_list,
    parse_claim_headers, parse_separator,
};
use super::utils::claim_resolver::{
    extract_claim_string, extract_claim_string_exact, parse_claim_path_value,
};
use super::utils::dpop::{
    self, DPOP_MARKER_RETENTION_SECONDS, DPOP_REPLAY_PROFILE, DpopVerifyInput,
    MAX_DPOP_CLOCK_SKEW_SECS,
};
use super::utils::header_extract::{ConfiguredHeaderLookup, lookup_configured_header};
use super::utils::jwks_cache::{
    DiscoveryStoreCandidate, JwksRefreshRequirement, LateActiveRequirement,
    clear_late_active_requirement, get_or_create_jwks_store, last_discovered_jwks_uri,
    publish_late_active_requirement, remember_discovered_jwks_uri,
    retire_jwks_store_if_unreferenced,
};
pub use super::utils::jwks_store::{
    DEFAULT_JWKS_MAX_STALE_SECONDS, DEFAULT_KID_MISS_REFRESH_COOLDOWN_SECONDS,
    MAX_JWKS_MAX_STALE_SECONDS, MAX_KID_MISS_REFRESH_COOLDOWN_SECONDS,
};
use super::utils::jwks_store::{JwksKeyStore, redacted_jwks_uri};
use super::utils::jwt_verifier::{JwtVerifyParams, peek_unverified_issuer, verify_jwt_with_jwks};
use super::utils::redis_rate_limiter::{
    REDIS_PLUGIN_CONFIG_KEYS, RedisConfig, RedisRateLimitClient,
};
use super::utils::replay_authority::{
    ReplayAdmission, ReplayAuthority, ReplayDomain, ReplayMarker, ReplayScope,
    validate_scope_backend,
};
use super::utils::replay_partition::PartitionHasher;
use super::utils::response_body::read_response_body_bounded;
use super::utils::scope_role_check::{self, ScopeRoleRequirements};
use super::utils::token_extract::{
    STRIP_QUERY_PARAM_METADATA_PREFIX, TokenHeaderLocation, TokenLocation, TokenLocationExtract,
    extract_authorization_bearer, extract_authorization_dpop, extract_from_location,
    mark_present_query_credential_locations, provider_locations_extract_token,
    stage_original_token_stripping as stage_token_stripping,
};
use super::{JwtAuthAttributeValue, PluginResult, RequestContext};

/// Default JWKS refresh interval: 15 minutes.
pub const DEFAULT_JWKS_REFRESH_INTERVAL_SECS: u64 = 900;
pub const MAX_JWKS_REFRESH_INTERVAL_SECS: u64 = MAX_JWKS_MAX_STALE_SECONDS;
/// Default capacity of a `dpop_replay_scope: process` lane.
///
/// Markers are retained for the fixed `DPOP_MARKER_RETENTION_SECONDS` horizon,
/// so this bounds sustained authenticated DPoP throughput on a process lane at
/// roughly `capacity / retention` proofs per second. Over-provisioning surfaces
/// as fail-closed `401`s (see `ReplayAdmission::CapacityRefused`), never as a
/// silently reusable proof; `shared` scope moves the cost into Redis.
pub const DEFAULT_DPOP_REPLAY_MAX_ENTRIES: usize = 100_000;
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
/// - **Header `kid` is binding**: A missing, empty, or unknown JWT `kid` is
///   rejected with the same generic 401 as any other invalid token. A known
///   `kid` selects only that trusted key; there is no all-keys fallback.
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
    /// Complete gateway-owned destination set across the plugin-level mappings
    /// and every provider override. Precomputed so `before_proxy` can sanitize
    /// without walking the provider list.
    claim_header_destinations: ClaimHeaderDestinations,
    strip_authorization_on_success: bool,
    has_custom_query_token_locations: bool,
    /// Providers that may accept an access token presented under the RFC 9449
    /// `DPoP` authorization scheme (§7.1).
    ///
    /// Precomputed so the request path never walks the provider list to answer
    /// it. Membership requires `require_dpop` — a `DPoP`-scheme presentation
    /// asserts a key-bound token, so admitting one against a provider that
    /// validates no proof would accept a sender-constrained token as a plain
    /// bearer — and requires the `Authorization` header to be one of the
    /// provider's token locations (explicitly, with no prefix, or by default).
    dpop_authorization_scheme_providers: Vec<usize>,
    request_headers_to_redact: Vec<String>,
    emit_mesh_request_principal_metadata: bool,
    http_client: PluginHttpClient,
    refresh_interval: Duration,
    /// Minimum spacing between on-demand JWKS refetches triggered by a token
    /// naming an unknown `kid`. `Duration::ZERO` disables the behaviour.
    kid_miss_cooldown: Duration,
    discovery_tasks: Mutex<Option<Vec<tokio::task::JoinHandle<()>>>>,
    discovery_owner_live: Arc<AtomicBool>,
    /// Set by `commit_background_tasks` once this generation is published.
    /// Only a committed generation may contribute to readiness and metrics.
    discovery_owner_committed: Arc<AtomicBool>,
    discovery_publication_gate: Arc<Mutex<()>>,
}

/// A single identity provider configuration.
struct JwksProvider {
    /// Expected `iss` claim value. Used to match incoming tokens to this provider.
    issuer: Option<String>,
    /// Accepted `aud` claim values. jsonwebtoken treats this as OR matching.
    /// When non-empty, `aud` must be present; `set_audience` alone does not
    /// require presence.
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
    /// Istio `RequestAuthentication.jwtRules[].outputClaimToHeaders` projection
    /// (issue #4277). Independent of `claim_headers`: these destinations are
    /// ALWAYS staged for this provider (they never merely override the
    /// plugin-level map), and they share the same gateway-owned destination
    /// set, so every declared header is stripped from the inbound request
    /// before validation and re-asserted only from a validated claim.
    output_claim_headers: Vec<ClaimHeaderMapping>,
    /// Require RFC 8705 mTLS sender-constrained access tokens.
    require_mtls_binding: bool,
    /// Require RFC 9449 DPoP proof JWTs.
    require_dpop: bool,
    /// Allowed DPoP proof clock skew.
    dpop_clock_skew: Duration,
    /// Stable protection-domain identity for this provider's DPoP proofs.
    ///
    /// Precomputed at construction from `{namespace, jwks_auth, config id,
    /// semantic provider identity}` so no request path hashes configuration,
    /// and so an equivalent reload — and every replica of the same policy —
    /// derives the same domain and therefore the same replay lane / shared
    /// keyspace. The sub-domain is [`dpop_provider_identity`], a digest of the
    /// provider's exact `issuer` realm, **not** its JWKS contents, key ids,
    /// array position, or source URL: reordering, rotating keys, or changing
    /// a JWKS endpoint must not move a provider into a fresh replay lane and
    /// reopen a proof it already accepted.
    dpop_replay_domain: Option<ReplayDomain>,
    /// Single-use authority this provider's proofs are claimed against.
    ///
    /// Owned by the shared registry rather than by this plugin generation, so a
    /// plugin-cache rebuild inherits live markers instead of starting empty.
    dpop_replay: Option<Arc<ReplayAuthority>>,
    /// The JWKS key store (shared via global cache).
    jwks_store: Arc<ArcSwap<Option<Arc<JwksKeyStore>>>>,
    /// Maximum monotonic age of the last validated non-empty remote JWKS.
    max_stale: Duration,
    /// This provider's contribution to the shared-cache active set when its
    /// store is resolved asynchronously after publication. Shared with the
    /// discovery task, but always cleared by [`JwksAuth::drop`] so an aborted
    /// task cannot keep a retired generation's store visible.
    late_active: Arc<Mutex<Option<LateActiveRequirement>>>,
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
    "jwks_max_stale_seconds",
    "kid_miss_refresh_cooldown_seconds",
];

/// Complete root allowlist: the plugin's own fields plus the shared Redis
/// fields that back `dpop_replay_scope: shared`.
///
/// Unioned rather than duplicated so a new key in
/// [`REDIS_PLUGIN_CONFIG_KEYS`] cannot silently become an unknown field here.
fn root_config_fields() -> Vec<&'static str> {
    let mut allowed = CONFIG_FIELDS.to_vec();
    allowed.extend_from_slice(REDIS_PLUGIN_CONFIG_KEYS);
    allowed
}

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
    "output_claim_headers",
    "require_mtls_binding",
    "require_dpop",
    "dpop_clock_skew_secs",
    "dpop_replay_scope",
    "dpop_replay_max_entries",
    "jwks_max_stale_seconds",
];

/// Provider fields removed by the shared replay-authority migration, with the
/// replacement named explicitly. Rejected rather than ignored: a config that
/// still carries `dpop_jti_ttl_secs` was written believing it controls how long
/// a proof stays single-use, and silently dropping it would leave that operator
/// with an unexamined retention contract.
const REMOVED_PROVIDER_FIELDS: &[(&str, &str)] = &[
    (
        "dpop_jti_ttl_secs",
        "replay retention is no longer configurable — every marker is retained for a fixed \
         horizon that dominates the widest admissible clock skew, so no reload can shorten an \
         already-admitted proof's protection",
    ),
    (
        "dpop_jti_cache_max_entries",
        "renamed to 'dpop_replay_max_entries'; it now bounds a process replay lane that never \
         evicts an unexpired marker (at capacity the request is refused instead)",
    ),
];

impl Drop for JwksAuth {
    fn drop(&mut self) {
        let _publication = match self.discovery_publication_gate.lock() {
            Ok(guard) => guard,
            Err(poisoned) => poisoned.into_inner(),
        };
        self.discovery_owner_live.store(false, Ordering::Release);
        {
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

        // A plugin generation can be discarded after its discovery task
        // published a candidate into the local slot but before the generation
        // itself was committed. Release those local owners and retire only
        // entries that no other committed provider still uses.
        for provider in &self.providers {
            if matches!(&provider.jwks_source, JwksSource::Inline) {
                continue;
            }
            // Drop this generation's active contribution before retiring. The
            // discovery task holds an `Arc` to the same slot and `abort()` is
            // not synchronous, so relying on the task's reference to go away
            // would leave a retired generation visible in readiness/metrics.
            clear_late_active_requirement(&provider.late_active);
            let current = provider.jwks_store.swap(Arc::new(None));
            let jwks_uri = current
                .as_ref()
                .as_ref()
                .filter(|store| store.is_refreshable())
                .map(|store| store.jwks_uri().to_string());
            drop(current);
            if let Some(jwks_uri) = jwks_uri {
                retire_jwks_store_if_unreferenced(&jwks_uri);
            }
        }
    }
}

impl JwksAuth {
    /// Construct without a stable policy identity.
    ///
    /// Admin config validation and direct/test construction take this path. A
    /// `dpop_replay_scope: process` provider then gets a **private** lane keyed
    /// by the standalone placeholder id, so a validation call can neither read,
    /// mutate, nor consume a live proxy's replay history. A `shared` provider
    /// constructs a detached fail-closed authority: construction never publishes
    /// a process readiness dependency or arms a Redis recovery task. Live
    /// readiness is published from
    /// [`crate::plugins::Plugin::commit_background_tasks`].
    #[allow(dead_code)] // exercised by external unit tests
    pub fn new(config: &Value, http_client: PluginHttpClient) -> Result<Self, String> {
        Self::new_with_config_id(config, http_client, None)
    }

    /// Construct with the configured plugin-config resource id.
    ///
    /// That id — together with the namespace and each provider's exact issuer
    /// realm ([`dpop_provider_identity`]) — is the stable protection-domain
    /// identity. Production `PluginCache` must pass it:
    /// with `None`, every reload generation would own a private replay lane and
    /// a rebuilt plugin would accept a proof it had already admitted.
    pub fn new_with_config_id(
        config: &Value,
        http_client: PluginHttpClient,
        plugin_config_id: Option<&str>,
    ) -> Result<Self, String> {
        let config_obj = config
            .as_object()
            .ok_or_else(|| format!("jwks_auth: config must be an object, got: {config}"))?;
        reject_unknown_fields(config_obj, &root_config_fields(), "config")?;

        // A blank id would collapse every jwks_auth config in a namespace onto
        // one replay domain; fail closed rather than merge them.
        if plugin_config_id.is_some_and(|config_id| config_id.trim().is_empty()) {
            return Err("jwks_auth: plugin config id must not be blank".to_string());
        }
        let namespace = http_client.namespace().to_string();
        let policy_config_id = plugin_config_id
            .unwrap_or(STANDALONE_JWKS_AUTH_CONFIG_ID)
            .to_string();
        // Redis fields are parsed and range-validated whether or not a provider
        // activates them, matching every other Redis-backed plugin: toggling a
        // provider to `shared` later cannot suddenly activate a malformed URL,
        // a wrong scalar type, or a zero connection bound.
        let default_redis_prefix = default_dpop_redis_key_prefix(&namespace, &policy_config_id);
        let redis_config = RedisConfig::from_plugin_config(config, &default_redis_prefix)?;
        let redis_configured = redis_config.is_some();
        // One client per plugin generation, shared by every `shared` provider:
        // the marker already binds each provider's semantic identity, so
        // distinct providers cannot collide inside one keyspace and equivalent
        // providers deliberately converge on one. Classification-only logging
        // so connection/auth/topology failures cannot emit backend text or the
        // operator key prefix.
        let shared_replay_client = match redis_config {
            Some(redis_config) => Some(Arc::new(RedisRateLimitClient::for_replay_authority(
                redis_config,
                http_client.dns_cache().cloned(),
                http_client.tls_no_verify(),
                http_client.tls_ca_bundle_path(),
            )?)),
            None => None,
        };

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
        if refresh_interval_secs > MAX_JWKS_REFRESH_INTERVAL_SECS {
            return Err(format!(
                "jwks_auth: 'jwks_refresh_interval_secs' must be <= {MAX_JWKS_REFRESH_INTERVAL_SECS}"
            ));
        }
        let refresh_interval = Duration::from_secs(refresh_interval_secs);
        // An unknown `kid` is the observable shape of an identity-provider key
        // rotation, so the store refetches out of band at most once per this
        // window. `0` disables the behaviour and restores the previous
        // refresh-interval-only recovery latency.
        let kid_miss_refresh_cooldown_seconds = optional_u64(
            config_obj,
            "kid_miss_refresh_cooldown_seconds",
            DEFAULT_KID_MISS_REFRESH_COOLDOWN_SECONDS,
        )?;
        if kid_miss_refresh_cooldown_seconds > MAX_KID_MISS_REFRESH_COOLDOWN_SECONDS {
            return Err(format!(
                "jwks_auth: 'kid_miss_refresh_cooldown_seconds' must be <= {MAX_KID_MISS_REFRESH_COOLDOWN_SECONDS}"
            ));
        }
        let kid_miss_cooldown = Duration::from_secs(kid_miss_refresh_cooldown_seconds);
        let default_max_stale_seconds = optional_u64(
            config_obj,
            "jwks_max_stale_seconds",
            DEFAULT_JWKS_MAX_STALE_SECONDS,
        )?;
        validate_max_stale_seconds("jwks_max_stale_seconds", default_max_stale_seconds)?;

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
        let mut declared_dpop_scopes: Vec<ReplayScope> = Vec::new();
        // Equivalent providers (same exact issuer) converge on one replay
        // domain. They may share that domain only when they agree on
        // `require_dpop`, `require_mtls_binding`, `required_scopes`,
        // `required_roles`, and when DPoP is required, on replay scope/store
        // and process-lane capacity. Matching order, a reload, or a rolling
        // replica would otherwise pick which sibling validates the token and
        // which sender-constraint or scope/role gate applies. Track the first
        // admission per issuer realm so a disagreement is refused
        // order-independently, without binding JWKS contents, source URL, or
        // replay scope/capacity into the replay identity (that would reopen
        // live proofs on an ordinary key rotation or cap edit).
        let mut equivalent_provider_replay: HashMap<String, EquivalentProviderReplayAdmission> =
            HashMap::new();

        for (idx, prov_cfg) in providers_arr.iter().enumerate() {
            let prov_obj = prov_cfg.as_object().ok_or_else(|| {
                format!("jwks_auth: provider[{idx}] must be an object, got: {prov_cfg}")
            })?;
            reject_removed_provider_fields(prov_obj, idx)?;
            reject_unknown_fields(prov_obj, PROVIDER_FIELDS, &format!("provider[{idx}]"))?;

            let jwks_endpoint = parse_url_field(prov_obj, "jwks_uri", idx)?;
            let discovery_endpoint = parse_url_field(prov_obj, "discovery_url", idx)?;
            let inline_jwks = parse_inline_jwks(prov_obj, idx)?;
            let provider_max_stale_seconds =
                optional_provider_u64(prov_obj, "jwks_max_stale_seconds", idx)?
                    .unwrap_or(default_max_stale_seconds);
            validate_max_stale_seconds(
                &format!("provider[{idx}].jwks_max_stale_seconds"),
                provider_max_stale_seconds,
            )?;
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
            if inline_jwks.is_some() && prov_obj.contains_key("jwks_max_stale_seconds") {
                return Err(format!(
                    "jwks_auth: 'provider[{idx}].jwks_max_stale_seconds' applies only to remote JWKS sources"
                ));
            }
            if inline_jwks.is_none() && refresh_interval_secs > provider_max_stale_seconds {
                return Err(format!(
                    "jwks_auth: 'jwks_refresh_interval_secs' must be <= the effective provider[{idx}] jwks_max_stale_seconds"
                ));
            }
            let provider_max_stale = Duration::from_secs(provider_max_stale_seconds);

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
            let provider_output_claim_headers = parse_claim_header_list(
                prov_obj,
                "output_claim_headers",
                "jwks_auth",
                CLAIM_HEADER_METADATA_PREFIX,
            )?;
            let effective_claim_headers = if provider_claim_headers.is_empty() {
                claim_headers.as_slice()
            } else {
                provider_claim_headers.as_slice()
            };
            if let Some(duplicate) = provider_output_claim_headers.iter().find(|output| {
                effective_claim_headers
                    .iter()
                    .any(|mapping| mapping.destination_header == output.destination_header)
            }) {
                return Err(format!(
                    "jwks_auth: provider[{idx}] maps header '{}' through both \
                     'claim_headers' and 'output_claim_headers'; a destination may be asserted \
                     from exactly one claim mapping family",
                    duplicate.destination_header
                ));
            }
            let require_mtls_binding =
                optional_provider_bool(prov_obj, "require_mtls_binding", idx)?.unwrap_or(false);
            let require_dpop =
                optional_provider_bool(prov_obj, "require_dpop", idx)?.unwrap_or(false);
            if require_dpop && issuer.is_none() {
                return Err(format!(
                    "jwks_auth: 'provider[{idx}].issuer' is required when 'require_dpop' is true \
                     — DPoP replay is bound to an exact issuer realm, so a blank or omitted \
                     issuer cannot isolate or preserve single-use proofs across key or source \
                     rotation"
                ));
            }
            let dpop_clock_skew_secs =
                optional_provider_u64(prov_obj, "dpop_clock_skew_secs", idx)?.unwrap_or(30);
            if dpop_clock_skew_secs > MAX_DPOP_CLOCK_SKEW_SECS {
                return Err(format!(
                    "jwks_auth: 'provider[{idx}].dpop_clock_skew_secs' must be <= {MAX_DPOP_CLOCK_SKEW_SECS}"
                ));
            }
            let dpop_replay_max_entries =
                optional_provider_usize(prov_obj, "dpop_replay_max_entries", idx)?
                    .unwrap_or(DEFAULT_DPOP_REPLAY_MAX_ENTRIES);
            if dpop_replay_max_entries == 0 {
                return Err(format!(
                    "jwks_auth: 'provider[{idx}].dpop_replay_max_entries' must be greater than 0"
                ));
            }

            // The replay scope has no default. A gateway cannot observe its own
            // replica count, so "is process-local replay state sufficient?" is
            // an explicit, auditable operator declaration. Defaulting it would
            // reinstate "one replay per replica" for every multi-replica
            // deployment that simply set `require_dpop: true`.
            let declared_scope = match optional_provider_string(prov_obj, "dpop_replay_scope", idx)?
            {
                Some(value) => Some(ReplayScope::parse(
                    "jwks_auth",
                    &format!("provider[{idx}].dpop_replay_scope"),
                    &value,
                )?),
                None => None,
            };
            if require_dpop && declared_scope.is_none() {
                return Err(format!(
                    "jwks_auth: 'provider[{idx}].dpop_replay_scope' is required when \
                     'require_dpop' is true — use 'shared' together with sync_mode: 'redis' for \
                     any deployment running more than one gateway replica, or 'process' to \
                     declare a single-process deployment whose replay protection is not \
                     cross-replica"
                ));
            }
            if !require_dpop && declared_scope.is_some() {
                return Err(format!(
                    "jwks_auth: 'provider[{idx}].dpop_replay_scope' is only meaningful with \
                     'require_dpop': true"
                ));
            }
            if let Some(scope) = declared_scope {
                declared_dpop_scopes.push(scope);
            }

            // The DPoP protection sub-domain is a **semantic** issuer realm,
            // never the provider's position in the array, JWKS document, or
            // source URL. An array index makes reordering a security event;
            // hashing JWKS contents or the source endpoint makes an ordinary
            // key rotation or URI change reopen every live proof. See
            // [`dpop_provider_identity`]. Identity is computed for every
            // provider that declares an issuer, including those that do not
            // require DPoP, so a bearer-only sibling for the same issuer
            // cannot skip the proof the DPoP provider exists to demand.
            let provider_identity = issuer.as_deref().map(dpop_provider_identity);
            if let Some(identity) = provider_identity.as_ref() {
                let admission = EquivalentProviderReplayAdmission {
                    idx,
                    require_dpop,
                    scope: declared_scope,
                    process_capacity: dpop_replay_max_entries,
                    require_mtls_binding,
                    required_scopes: required_scopes.clone(),
                    required_roles: required_roles.clone(),
                    scope_claim: scope_claim
                        .clone()
                        .unwrap_or_else(|| global_scope_claim.clone()),
                    role_claim: role_claim
                        .clone()
                        .unwrap_or_else(|| global_role_claim.clone()),
                };
                if let Some(earlier) = equivalent_provider_replay.get(identity) {
                    reject_equivalent_provider_replay_disagreement(earlier, &admission)?;
                } else {
                    equivalent_provider_replay.insert(identity.clone(), admission);
                }
            }
            let dpop_replay_domain = match (require_dpop, provider_identity.as_ref()) {
                (true, Some(identity)) => Some(ReplayDomain::new(
                    DPOP_REPLAY_PROFILE,
                    &namespace,
                    "jwks_auth",
                    &policy_config_id,
                    identity,
                )),
                _ => None,
            };
            let dpop_replay = match (declared_scope, dpop_replay_domain.as_ref()) {
                (Some(ReplayScope::Process), Some(domain)) => {
                    Some(Arc::new(ReplayAuthority::process(
                        "jwks_auth",
                        domain,
                        dpop_replay_max_entries,
                        Duration::from_secs(DPOP_MARKER_RETENTION_SECONDS),
                        shard_amount,
                    )?))
                }
                (Some(ReplayScope::Shared), Some(_)) => {
                    // `validate_scope_backend` below rejects `shared` without a
                    // Redis backend, so an absent client here cannot silently
                    // become a process lane.
                    shared_replay_client.as_ref().map(|client| {
                        let retention = Duration::from_secs(DPOP_MARKER_RETENTION_SECONDS);
                        // Detached until `commit_background_tasks`. Later
                        // providers in this loop may still fail validation, and
                        // the candidate itself may never be installed.
                        Arc::new(ReplayAuthority::shared(Arc::clone(client), retention))
                    })
                }
                _ => None,
            };

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
                store.configure_trust_policy(refresh_interval, provider_max_stale);
                store.configure_kid_miss_cooldown(kid_miss_cooldown);
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
                output_claim_headers: provider_output_claim_headers,
                require_mtls_binding,
                require_dpop,
                dpop_clock_skew: Duration::from_secs(dpop_clock_skew_secs),
                dpop_replay_domain,
                dpop_replay,
                jwks_store: jwks_store_slot,
                max_stale: provider_max_stale,
                late_active: Arc::new(Mutex::new(None)),
                jwks_source,
                warmup_hostnames,
            });
        }

        // Scope/backend coherence is a plugin-level decision, not a per-provider
        // one: one Redis client backs every `shared` provider. `shared` without
        // a backend would silently be process-local — the exact "multi-replica
        // production configuration falls back to local acceptance" failure — and
        // a provisioned backend no provider consults is equally a
        // misconfiguration.
        if !declared_dpop_scopes.is_empty() || redis_configured {
            let effective_scope = if declared_dpop_scopes.contains(&ReplayScope::Shared) {
                ReplayScope::Shared
            } else {
                ReplayScope::Process
            };
            validate_scope_backend(
                "jwks_auth",
                "provider[].dpop_replay_scope",
                effective_scope,
                redis_configured,
            )?;
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
        // RFC 9449 §7.1 presents a DPoP-bound access token as
        // `Authorization: DPoP <token>` beside the proof header, and that is
        // what conformant clients send. Accepting it is gated on a provider
        // that actually requires a proof: matching a `DPoP`-scheme credential
        // against a bearer-only provider would strip the sender constraint the
        // scheme announces. The `Bearer` form stays accepted for every
        // provider, which is the migration shape RFC 9449 §7.1 permits.
        let dpop_authorization_scheme_providers: Vec<usize> = providers
            .iter()
            .enumerate()
            .filter(|(_, provider)| {
                provider.require_dpop
                    && (provider.token_locations.is_empty()
                        || provider
                            .token_locations
                            .iter()
                            .any(|location| match location {
                                TokenLocation::Header(header) => {
                                    header.name.eq_ignore_ascii_case("authorization")
                                        && header.prefix.is_none()
                                }
                                TokenLocation::QueryParam(_) => false,
                            }))
            })
            .map(|(idx, _)| idx)
            .collect();
        let mut request_headers_to_redact = Vec::new();
        for provider in &providers {
            if provider.token_locations.is_empty()
                && !request_headers_to_redact
                    .iter()
                    .any(|known: &String| known == "authorization")
            {
                request_headers_to_redact.push("authorization".to_string());
            }
            for location in &provider.token_locations {
                let TokenLocation::Header(header) = location else {
                    continue;
                };
                if !request_headers_to_redact
                    .iter()
                    .any(|known| known.eq_ignore_ascii_case(&header.name))
                {
                    request_headers_to_redact.push(header.name.clone());
                }
            }
        }

        // Both mapping families contribute to the owned destination set: an
        // `output_claim_headers` destination must be stripped from every
        // inbound request, including the requests that never authenticate.
        let claim_header_destinations = ClaimHeaderDestinations::from_mapping_groups(
            std::iter::once(claim_headers.as_slice()).chain(providers.iter().flat_map(
                |provider| {
                    [
                        provider.claim_headers.as_slice(),
                        provider.output_claim_headers.as_slice(),
                    ]
                },
            )),
        );

        Ok(Self {
            providers,
            global_scope_claim,
            global_role_claim,
            consumer_identity_claim,
            consumer_header_claim,
            claim_headers,
            claim_headers_separator,
            claim_header_destinations,
            strip_authorization_on_success,
            has_custom_query_token_locations,
            dpop_authorization_scheme_providers,
            request_headers_to_redact,
            emit_mesh_request_principal_metadata,
            http_client,
            refresh_interval,
            kid_miss_cooldown,
            discovery_tasks: Mutex::new(None),
            discovery_owner_live: Arc::new(AtomicBool::new(true)),
            discovery_owner_committed: Arc::new(AtomicBool::new(false)),
            discovery_publication_gate: Arc::new(Mutex::new(())),
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

    /// This generation's contribution to a shared JWKS store's effective
    /// policy, including the unknown-`kid` on-demand refetch cooldown.
    fn shared_store_requirement(&self, max_stale: Duration) -> JwksRefreshRequirement {
        JwksRefreshRequirement::new(self.refresh_interval, max_stale)
            .with_kid_miss_cooldown(self.kid_miss_cooldown)
    }

    /// Live remote JWKS stores backing this plugin's providers. Test-only
    /// visibility for the unknown-`kid` on-demand refetch contracts.
    #[doc(hidden)]
    #[allow(dead_code)] // exercised by external unit tests
    pub fn remote_jwks_stores_for_test(&self) -> Vec<Arc<JwksKeyStore>> {
        self.providers
            .iter()
            .filter_map(|provider| {
                provider
                    .jwks_store
                    .load()
                    .as_ref()
                    .as_ref()
                    .filter(|store| store.is_refreshable())
                    .cloned()
            })
            .collect()
    }

    /// Per-provider process replay-lane capacities (`None` when DPoP is not
    /// required or the provider claims against the shared authority).
    /// Test-only visibility for default-contract regressions and for proving
    /// a reloaded generation enforces its own admitted cap.
    #[doc(hidden)]
    #[allow(dead_code)] // exercised by external unit tests
    pub fn dpop_replay_lane_capacities(&self) -> Vec<Option<usize>> {
        self.providers
            .iter()
            .map(|provider| {
                provider.dpop_replay.as_ref().and_then(|authority| {
                    crate::plugins::utils::replay_authority::process_max_entries(authority)
                })
            })
            .collect()
    }

    /// Per-provider replay-authority modes (`None` when DPoP is not required).
    /// Test-only visibility for scope/reload contracts.
    #[doc(hidden)]
    #[allow(dead_code)] // exercised by external unit tests
    pub fn dpop_replay_modes(&self) -> Vec<Option<&'static str>> {
        self.providers
            .iter()
            .map(|provider| provider.dpop_replay.as_ref().map(|a| a.mode()))
            .collect()
    }

    /// Whether any provider's shared Redis recovery checker has been armed.
    /// Test support for proving construction stays detached until commit.
    #[doc(hidden)]
    #[allow(dead_code)] // exercised by external unit tests
    pub fn shared_replay_recovery_started_for_test(&self) -> bool {
        self.providers.iter().any(|provider| {
            provider
                .dpop_replay
                .as_ref()
                .is_some_and(|authority| authority.recovery_checker_started_for_test())
        })
    }

    /// Per-provider protection-domain digests. Test-only visibility for the
    /// "equivalent reload / equivalent replica converge, distinct policies
    /// isolate" contracts.
    #[doc(hidden)]
    #[allow(dead_code)] // exercised by external unit tests
    pub fn dpop_replay_domain_markers(&self, jkt: &str, jti: &str) -> Vec<Option<[u8; 32]>> {
        self.providers
            .iter()
            .map(|provider| {
                provider
                    .dpop_replay_domain
                    .as_ref()
                    .map(|domain| domain.marker(&[jkt.as_bytes(), jti.as_bytes()]).digest())
            })
            .collect()
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

        let identity = nonblank_identity(extract_claim_string(claims, effective_identity_claim));
        let header_value = if effective_header_claim == effective_identity_claim {
            identity.clone()
        } else {
            extract_claim_string_exact(claims, effective_header_claim).or_else(|| identity.clone())
        };

        let consumer = if let Some(ref id) = identity {
            match consumer_index.find_by_identity(id) {
                Some(consumer) => {
                    debug!(
                        "jwks_auth: identified consumer '{}' via configured identity claim",
                        consumer.username
                    );
                    Some(consumer)
                }
                None => {
                    debug!(
                        "jwks_auth: no consumer mapping found for configured identity claim — using external principal"
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
            .with_credential_deadline(credential_deadline_from_claims(claims, 0))
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

    /// Validate RFC 8705 mTLS binding and RFC 9449 DPoP proof cryptography and
    /// claims.
    ///
    /// Returns the DPoP replay marker still to be claimed, when the provider
    /// requires a proof. The claim itself is deliberately **not** made here:
    /// it is an `async` operation against a possibly shared authority and it
    /// must happen strictly after signature, `htm`/`htu`/`iat`/`exp`/`ath`, and
    /// token-key binding validation, so unauthenticated garbage can never
    /// consume replay capacity or a shared-backend round trip. The single
    /// caller ([`Self::admit_sender_constraints`]) performs it immediately.
    fn check_sender_constraints(
        &self,
        ctx: &RequestContext,
        claims: &Value,
        provider: &JwksProvider,
        token: &str,
    ) -> Result<Option<ReplayMarker>, (u16, String)> {
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

        if !provider.require_dpop {
            return Ok(None);
        }

        // RFC 9449 DPoP proofs are compact JWTs (base64url), visible ASCII. A
        // present `dpop` field line that is not visible ASCII is malformed proof
        // material, not a missing proof.
        let proof = match lookup_configured_header(ctx, "dpop", None) {
            ConfiguredHeaderLookup::Absent => {
                return Err((401, r#"{"error":"DPoP proof required"}"#.to_string()));
            }
            ConfiguredHeaderLookup::PresentNonMaterialized => {
                return Err((401, r#"{"error":"Invalid DPoP proof"}"#.to_string()));
            }
            ConfiguredHeaderLookup::Value(proof) => proof,
        };
        // A `require_dpop` provider always carries a domain and an authority:
        // construction rejects the configuration otherwise. Fail closed rather
        // than admit a proof that would not be made single-use.
        let Some(domain) = provider.dpop_replay_domain.as_ref() else {
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
        match dpop::verify(DpopVerifyInput {
            proof: &proof,
            access_token: token,
            access_token_claims: claims,
            method: &ctx.method,
            htu: &htu,
            clock_skew: provider.dpop_clock_skew,
            domain,
        }) {
            Ok(marker) => Ok(Some(marker)),
            Err(_) => Err((401, r#"{"error":"DPoP validation failed"}"#.to_string())),
        }
    }

    /// Claim a validated DPoP proof for exactly one request.
    ///
    /// The claim is the last admission step, run after signature/claim
    /// validation *and* after scope/role authorization, so neither
    /// unauthenticated garbage nor an authorization rejection can consume
    /// replay capacity. Its outcome maps to fixed client-visible bodies with no
    /// backend detail: a replay, a capacity refusal, and an unavailable
    /// authority are all terminal. There is no path from any of them to
    /// acceptance.
    async fn admit_dpop_marker(
        &self,
        provider: &JwksProvider,
        marker: ReplayMarker,
    ) -> Result<(), (u16, String)> {
        let Some(authority) = provider.dpop_replay.as_ref() else {
            // Unreachable for an admitted configuration (construction requires a
            // declared scope and a backend for `shared`), but a missing
            // authority must refuse rather than accept an unclaimed proof.
            warn!("jwks_auth: DPoP replay authority is not configured; rejecting proof");
            return Err((
                401,
                r#"{"error":"DPoP replay protection unavailable"}"#.to_string(),
            ));
        };
        match authority.admit(&marker).await {
            ReplayAdmission::Admitted => Ok(()),
            ReplayAdmission::Replay => Err((401, r#"{"error":"DPoP replay"}"#.to_string())),
            ReplayAdmission::CapacityRefused => {
                warn!(
                    classification = ReplayAdmission::CapacityRefused.classification(),
                    mode = authority.mode(),
                    "jwks_auth: DPoP replay state is at capacity; refusing the request rather \
                     than discarding a live replay marker"
                );
                Err((
                    503,
                    r#"{"error":"DPoP replay protection is at capacity"}"#.to_string(),
                ))
            }
            ReplayAdmission::AuthorityUnavailable => {
                warn!(
                    classification = ReplayAdmission::AuthorityUnavailable.classification(),
                    mode = authority.mode(),
                    "jwks_auth: DPoP replay authority is unavailable; failing closed without \
                     local fallback"
                );
                Err((
                    503,
                    r#"{"error":"DPoP replay protection unavailable"}"#.to_string(),
                ))
            }
        }
    }

    fn stage_claim_headers(
        &self,
        attempt: &mut AuthenticationAttempt,
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
        emit_claim_headers_to_attempt(attempt, claims, mappings, separator);
    }

    /// Stage this provider's Istio `outputClaimToHeaders` destinations from the
    /// VALIDATED claim set (issue #4277). Always additive to
    /// [`Self::stage_claim_headers`]: the two families are separate contracts,
    /// and an operator-configured `claim_headers` map must not silence a
    /// mesh-translated output header (or the reverse).
    fn stage_output_claim_headers(
        &self,
        attempt: &mut AuthenticationAttempt,
        claims: &Value,
        provider: &JwksProvider,
    ) {
        if provider.output_claim_headers.is_empty() {
            return;
        }
        let separator = provider
            .claim_headers_separator
            .as_deref()
            .unwrap_or(&self.claim_headers_separator);
        emit_output_claim_headers_to_attempt(
            attempt,
            claims,
            &provider.output_claim_headers,
            separator,
        );
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
                ..
            } => {
                let (claims, provider_idx) = match self
                    .validate_token_for_providers(&token, &provider_indices)
                    .await
                {
                    Ok(result) => result,
                    Err((status, body)) => return reject(status, body.to_string()),
                };

                let provider = &self.providers[provider_idx];
                // Cryptographic + claim validation first, then authorization,
                // then the single-use claim. Deferring the claim to last means
                // a request rejected for insufficient scopes never burns the
                // client's proof, while an unauthenticated proof still never
                // reaches replay state at all.
                let pending_dpop_marker =
                    match self.check_sender_constraints(ctx, &claims, provider, &token) {
                        Ok(marker) => marker,
                        Err((status, body)) => return reject(status, body),
                    };
                if let Err((status, body)) = self.check_claims_authorization(&claims, provider) {
                    return reject(status, body);
                }
                if let Some(marker) = pending_dpop_marker {
                    let admission = self.admit_dpop_marker(provider, marker).await;
                    if let Err((status, body)) = admission {
                        return reject(status, body);
                    }
                }

                // Everything after the claim is staging plus one commit, and no
                // identity, header, or token mutation is published before that
                // commit — a rejected claim above therefore never reaches
                // backend dispatch and never mutates the request.
                //
                // `commit_authentication_attempt` can still refuse (an identity
                // claim over the 512-byte boundary limit), which would consume
                // the proof's single use. That refusal is a deterministic
                // property of the *token*, not of the request: a token whose
                // identity claim is over-long can never authenticate here at
                // all, so the burnt `jti` buys nothing. It is also not
                // attacker-reachable against a victim, because a proof is bound
                // to the victim's JWK thumbprint and an attacker cannot mint one
                // for a key it does not hold.
                let mut attempt = AuthenticationAttempt::new();
                if self.emit_mesh_request_principal_metadata {
                    stage_mesh_request_principal_metadata(&claims, &mut attempt);
                }
                self.stage_claim_headers(&mut attempt, &claims, provider);
                self.stage_output_claim_headers(&mut attempt, &claims, provider);
                if !provider.forward_original_token {
                    stage_original_token_stripping(&mut attempt, provider);
                }

                match commit_authentication_attempt(
                    ctx,
                    attempt,
                    self.resolve_identity(&claims, provider, consumer_index),
                    "jwks_auth",
                    true,
                ) {
                    Ok(_) => PluginResult::Continue,
                    Err(VerifyOutcome::InvalidFormat(body))
                    | Err(VerifyOutcome::Invalid(body))
                    | Err(VerifyOutcome::ConsumerNotFound(body))
                    | Err(VerifyOutcome::VerificationFailed(body)) => reject(401, body),
                    Err(VerifyOutcome::Forbidden(body)) => reject(403, body),
                    Err(VerifyOutcome::Internal(body)) => reject(500, body),
                    Err(VerifyOutcome::Success { .. }) | Err(VerifyOutcome::NotApplicable) => {
                        PluginResult::Continue
                    }
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
                            dpop_scheme: false,
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
        if !provider_indices.is_empty() {
            match extract_authorization_bearer(ctx) {
                ExtractedCredential::BearerToken(token) => {
                    return JwksExtractedCredential::BearerToken {
                        token,
                        provider_indices,
                        dpop_scheme: false,
                    };
                }
                ExtractedCredential::InvalidFormat(body) => {
                    first_invalid_format.get_or_insert(body);
                }
                ExtractedCredential::Missing
                | ExtractedCredential::ApiKey(_)
                | ExtractedCredential::BasicAuth { .. }
                | ExtractedCredential::HmacAuth(_)
                | ExtractedCredential::MtlsCert { .. } => {}
            }
        }

        // RFC 9449 §7.1: a DPoP-bound access token is presented under the
        // `DPoP` scheme. It is read only after every `Bearer` location has
        // declined, and only against providers that require a proof, so the
        // scheme can never authenticate without `check_sender_constraints`
        // validating and claiming that proof.
        if !self.dpop_authorization_scheme_providers.is_empty() {
            match extract_authorization_dpop(ctx) {
                ExtractedCredential::BearerToken(token) => {
                    return JwksExtractedCredential::BearerToken {
                        token,
                        provider_indices: self.dpop_authorization_scheme_providers.clone(),
                        dpop_scheme: true,
                    };
                }
                ExtractedCredential::InvalidFormat(body) => {
                    first_invalid_format.get_or_insert(body);
                }
                ExtractedCredential::Missing
                | ExtractedCredential::ApiKey(_)
                | ExtractedCredential::BasicAuth { .. }
                | ExtractedCredential::HmacAuth(_)
                | ExtractedCredential::MtlsCert { .. } => {}
            }
        }

        first_invalid_format
            .map(JwksExtractedCredential::InvalidFormat)
            .unwrap_or(JwksExtractedCredential::Missing)
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
            JwksExtractedCredential::BearerToken {
                token,
                dpop_scheme: false,
                ..
            } => ExtractedCredential::BearerToken(token),
            // This mechanism path runs no sender-constraint check, so a
            // `DPoP`-scheme presentation must not reach it as a plain bearer
            // token. The plugin's own `authenticate` is the only entry point
            // that validates and claims the proof.
            JwksExtractedCredential::BearerToken {
                dpop_scheme: true, ..
            } => ExtractedCredential::Missing,
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
        /// The token arrived under the RFC 9449 `DPoP` authorization scheme
        /// rather than `Bearer`, so `provider_indices` names only providers
        /// that require and validate a proof.
        dpop_scheme: bool,
    },
    InvalidFormat(String),
    Missing,
}

fn stage_original_token_stripping(attempt: &mut AuthenticationAttempt, provider: &JwksProvider) {
    stage_token_stripping(
        attempt,
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
                    let store = get_or_create_jwks_store(
                        uri,
                        &self.http_client,
                        self.shared_store_requirement(provider.max_stale),
                    );
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
                            self.shared_store_requirement(provider.max_stale),
                        );
                        provider.jwks_store.store(Arc::new(Some(store)));
                    }
                    tasks.push(spawn_discovery_task(
                        &runtime,
                        Arc::clone(&provider.jwks_store),
                        Arc::clone(&provider.late_active),
                        self.http_client.clone(),
                        discovery_url.clone(),
                        self.shared_store_requirement(provider.max_stale),
                        Arc::clone(&self.discovery_owner_live),
                        Arc::clone(&self.discovery_owner_committed),
                        Arc::clone(&self.discovery_publication_gate),
                    ));
                }
            }
        }
        *task_slot = Some(tasks);
        Ok(())
    }

    fn commit_background_tasks(&self) {
        // Serialize against a discovery task publishing concurrently so exactly
        // one of the two registers this generation's contribution: whichever
        // runs second observes the other's result under the same gate.
        let _publication = match self.discovery_publication_gate.lock() {
            Ok(guard) => guard,
            Err(poisoned) => poisoned.into_inner(),
        };
        self.discovery_owner_committed
            .store(true, Ordering::Release);
        for provider in &self.providers {
            // Shared replay readiness is a live-state publication: register the
            // Redis client and arm recovery only after this generation is
            // installed. Idempotent across providers that share one client.
            if let Some(authority) = provider.dpop_replay.as_ref() {
                authority.activate();
            }
            // Direct and inline sources are already in the slot when the
            // publication reconciliation collects requirements; only an
            // asynchronously resolved store can arrive too late for it.
            if !matches!(&provider.jwks_source, JwksSource::Discovery(_)) {
                continue;
            }
            let guard = provider.jwks_store.load();
            let Some(store) = guard
                .as_ref()
                .as_ref()
                .filter(|store| store.is_refreshable())
            else {
                continue;
            };
            publish_late_active_requirement(
                &provider.late_active,
                store.jwks_uri(),
                self.shared_store_requirement(provider.max_stale),
            );
        }
    }

    async fn authenticate(
        &self,
        ctx: &mut RequestContext,
        consumer_index: &ConsumerIndex,
    ) -> PluginResult {
        self.authenticate_request(ctx, consumer_index).await
    }

    fn mark_query_credentials_for_redaction(&self, ctx: &mut RequestContext) {
        for provider in &self.providers {
            mark_present_query_credential_locations(ctx, &provider.token_locations);
        }
    }

    fn request_headers_to_redact(&self) -> &[String] {
        &self.request_headers_to_redact
    }

    fn modifies_request_headers(&self) -> bool {
        self.strip_authorization_on_success
            || !self.claim_headers.is_empty()
            || self.providers.iter().any(|provider| {
                !provider.claim_headers.is_empty() || !provider.output_claim_headers.is_empty()
            })
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
        apply_claim_headers_from_context(ctx, headers, &self.claim_header_destinations);
        PluginResult::Continue
    }

    fn warmup_hostnames(&self) -> Vec<String> {
        let mut hosts = Vec::new();
        for prov in &self.providers {
            hosts.extend(prov.warmup_hostnames.iter().cloned());
            // A shared DPoP replay authority is dialed on the authentication
            // path, so its endpoint belongs in gateway DNS warmup like any
            // other plugin egress.
            if let Some(authority) = prov.dpop_replay.as_ref() {
                for host in authority.warmup_hostnames() {
                    if !hosts.iter().any(|known| known == &host) {
                        hosts.push(host);
                    }
                }
            }
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

    fn active_jwks_refresh_requirements(&self) -> Vec<(String, JwksRefreshRequirement)> {
        self.providers
            .iter()
            .filter_map(|provider| {
                let store = provider.jwks_store.load();
                store
                    .as_ref()
                    .as_ref()
                    .filter(|store| store.is_refreshable())
                    .map(|store| {
                        (
                            store.jwks_uri().to_string(),
                            self.shared_store_requirement(provider.max_stale),
                        )
                    })
            })
            .collect()
    }

    fn requires_decoded_query_params(&self) -> bool {
        self.has_custom_query_token_locations
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

#[allow(clippy::too_many_arguments)]
fn spawn_discovery_task(
    runtime: &tokio::runtime::Handle,
    slot: Arc<ArcSwap<Option<Arc<JwksKeyStore>>>>,
    late_active: Arc<Mutex<Option<LateActiveRequirement>>>,
    client: PluginHttpClient,
    discovery_url: String,
    requirement: JwksRefreshRequirement,
    owner_live: Arc<AtomicBool>,
    owner_committed: Arc<AtomicBool>,
    publication_gate: Arc<Mutex<()>>,
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
                    let mut candidate =
                        DiscoveryStoreCandidate::acquire(&uri, &client, requirement);
                    let Some(store) = candidate.store().cloned() else {
                        warn!(
                            "jwks_auth OIDC: discovery candidate disappeared before publication"
                        );
                        return;
                    };
                    let previous = slot.load().as_ref().as_ref().cloned();

                    if previous
                        .as_ref()
                        .is_some_and(|current| current.jwks_uri() == uri)
                    {
                        let _publication = match publication_gate.lock() {
                            Ok(guard) => guard,
                            Err(poisoned) => poisoned.into_inner(),
                        };
                        if !owner_live.load(Ordering::Acquire) {
                            return;
                        }
                        remember_discovered_jwks_uri(&discovery_url, &uri);
                        if owner_committed.load(Ordering::Acquire) {
                            publish_late_active_requirement(
                                &late_active,
                                &uri,
                                requirement,
                            );
                        }
                        candidate.publish();
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
                                attempt = attempt.saturating_add(1);
                                continue;
                            }
                            Err(error) => {
                                warn!(
                                    "jwks_auth OIDC: replacement JWKS fetch failed: {}; retaining last-known-good store",
                                    error
                                );
                                drop(store);
                                attempt = attempt.saturating_add(1);
                                continue;
                            }
                        }
                    }

                    let previous_uri = previous
                        .as_ref()
                        .map(|current| current.jwks_uri().to_string());
                    {
                        let _publication = match publication_gate.lock() {
                            Ok(guard) => guard,
                            Err(poisoned) => poisoned.into_inner(),
                        };
                        if !owner_live.load(Ordering::Acquire) {
                            return;
                        }
                        slot.store(Arc::new(Some(Arc::clone(&store))));
                        remember_discovered_jwks_uri(&discovery_url, &uri);
                        // The store is now the authenticator's verification
                        // source, so a committed generation must expose it —
                        // and its exact max-stale deadline — immediately. A
                        // replacement moves this provider's contribution off
                        // the previous URI without touching a co-tenant.
                        if owner_committed.load(Ordering::Acquire) {
                            publish_late_active_requirement(
                                &late_active,
                                &uri,
                                requirement,
                            );
                        }
                    }

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
                    let _publication = match publication_gate.lock() {
                        Ok(guard) => guard,
                        Err(poisoned) => poisoned.into_inner(),
                    };
                    if !owner_live.load(Ordering::Acquire) {
                        clear_late_active_requirement(&late_active);
                        let discarded = slot.swap(Arc::new(None));
                        drop(discarded);
                        return;
                    }
                    candidate.publish();
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

/// Try to validate a JWT against a single provider's current trusted JWKS.
///
/// Key selection is the JWT header `kid` via [`verify_jwt_with_jwks`]: missing,
/// empty, and unknown identifiers fail closed, and a matching `kid` binds
/// verification to that one key.
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
            // JWT `exp`/`nbf` use this surface's existing 0-second leeway.
            // DPoP `dpop_clock_skew` is a separate proof-validation contract.
            leeway_secs: 0,
            // `nbf` stays optional (not a required claim). When present it
            // must be enforced so a pre-minted credential cannot authenticate
            // before its not-before instant.
            validate_nbf: true,
        },
    )
    .await
}

/// Parse a JSON value as an array of strings, or empty vec if not present/valid.
struct ParsedEndpoint {
    url: String,
    hostname: String,
}

/// Plugin-config id used when no stable resource id is supplied (Admin config
/// validation and direct/test construction).
///
/// Distinct from any real id, so a validation-constructed instance can never
/// join a live policy's replay lane or Redis keyspace.
pub const STANDALONE_JWKS_AUTH_CONFIG_ID: &str = "__standalone__";

/// Default Redis key prefix for shared DPoP replay markers:
/// `{namespace}:jwks_auth:{plugin-config-id}`.
///
/// The config-id component isolates independent policies inside one namespace
/// while every replica of the *same* policy keeps claiming against the same
/// keyspace — which is the whole point of the shared scope. An explicit
/// `redis_key_prefix` remains the documented opt-in for deliberately sharing a
/// keyspace across policies.
fn default_dpop_redis_key_prefix(namespace: &str, plugin_config_id: &str) -> String {
    let mut prefix = String::with_capacity(namespace.len() + plugin_config_id.len() + 12);
    prefix.push_str(namespace);
    prefix.push_str(":jwks_auth:");
    prefix.push_str(plugin_config_id);
    prefix
}

/// Reject provider fields the shared replay authority removed, naming the
/// replacement. See [`REMOVED_PROVIDER_FIELDS`].
fn reject_removed_provider_fields(config: &Map<String, Value>, idx: usize) -> Result<(), String> {
    for (removed, guidance) in REMOVED_PROVIDER_FIELDS {
        if config.contains_key(*removed) {
            return Err(format!(
                "jwks_auth: 'provider[{idx}].{removed}' was removed — {guidance}"
            ));
        }
    }
    Ok(())
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

fn validate_max_stale_seconds(field: &str, value: u64) -> Result<(), String> {
    if value == 0 {
        return Err(format!(
            "jwks_auth: '{field}' must be greater than 0; unlimited stale trust cannot be enabled"
        ));
    }
    if value > MAX_JWKS_MAX_STALE_SECONDS {
        return Err(format!(
            "jwks_auth: '{field}' must be <= {MAX_JWKS_MAX_STALE_SECONDS}"
        ));
    }
    Ok(())
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

/// First-seen admission for one issuer-realm identity.
///
/// Equivalent providers share a replay domain, so a later sibling is admitted
/// only when it agrees with this record. The earlier index is kept for
/// diagnostics; JWKS contents, source URL, scope, and capacity stay out of
/// the domain identity.
struct EquivalentProviderReplayAdmission {
    idx: usize,
    require_dpop: bool,
    scope: Option<ReplayScope>,
    process_capacity: usize,
    require_mtls_binding: bool,
    required_scopes: Vec<String>,
    required_roles: Vec<String>,
    /// EFFECTIVE claim path the scope gate reads for this provider: its own
    /// `scope_claim` override, else the plugin-level default. The resolved
    /// value is recorded rather than the override, so `scope_claim: "scope"`
    /// and an omitted override under the default `scope` are the same gate.
    scope_claim: String,
    /// EFFECTIVE claim path the role gate reads, resolved the same way.
    role_claim: String,
}

/// Refuse an equivalent provider that would split DPoP or authorization authority.
///
/// A token that verifies against this issuer realm is matched to the first
/// succeeding provider. If that pair disagrees on `require_dpop`, matching
/// order is an authentication bypass (one sibling demands a single-use proof
/// and the other accepts the bearer alone). The same bypass applies when one
/// sibling requires RFC 8705 certificate binding or a stricter scope/role gate
/// and the other does not. Requiring the same VALUES is not enough: the claim
/// PATH those values are read from is per provider, so two siblings that both
/// require `admin` while reading it from `delegated` and from `scope` are two
/// different gates, and matching order again decides which one applies. If both
/// require DPoP but disagree on
/// `dpop_replay_scope`, the same proof is claimed in the process store by one
/// sibling and in Redis by the other — exactly the cross-authority replay the
/// issuer-realm identity exists to prevent. Process-lane capacity stays a
/// same-scope equality rule so matching order cannot pick which cap applies.
fn reject_equivalent_provider_replay_disagreement(
    earlier: &EquivalentProviderReplayAdmission,
    later: &EquivalentProviderReplayAdmission,
) -> Result<(), String> {
    let earlier_idx = earlier.idx;
    let idx = later.idx;
    if earlier.require_dpop != later.require_dpop {
        return Err(format!(
            "jwks_auth: equivalent providers must agree on 'require_dpop'; \
             provider[{earlier_idx}] and provider[{idx}] share one issuer \
             realm with incompatible DPoP requirements"
        ));
    }
    if later.require_dpop && earlier.scope != later.scope {
        return Err(format!(
            "jwks_auth: equivalent DPoP providers must declare the same \
             'dpop_replay_scope'; provider[{earlier_idx}] and \
             provider[{idx}] share one replay domain with incompatible \
             replay authorities"
        ));
    }
    if later.require_dpop
        && later.scope == Some(ReplayScope::Process)
        && earlier.process_capacity != later.process_capacity
    {
        return Err(format!(
            "jwks_auth: equivalent DPoP providers must declare the same \
             'dpop_replay_max_entries'; provider[{earlier_idx}] and \
             provider[{idx}] share one replay domain with incompatible \
             capacities"
        ));
    }
    if earlier.require_mtls_binding != later.require_mtls_binding {
        return Err(format!(
            "jwks_auth: equivalent providers must agree on 'require_mtls_binding'; \
             provider[{earlier_idx}] and provider[{idx}] share one issuer \
             realm with incompatible certificate-binding requirements"
        ));
    }
    if earlier.required_scopes != later.required_scopes {
        return Err(format!(
            "jwks_auth: equivalent providers must agree on 'required_scopes'; \
             provider[{earlier_idx}] and provider[{idx}] share one issuer \
             realm with incompatible scope requirements"
        ));
    }
    // The lists are equal here, so an empty one means neither sibling gates on
    // scopes at all and the claim path is inert; a non-empty one means both
    // gate on it and must read it from the same place.
    if !later.required_scopes.is_empty() && earlier.scope_claim != later.scope_claim {
        return Err(format!(
            "jwks_auth: equivalent providers that require scopes must agree on \
             'scope_claim'; provider[{earlier_idx}] and provider[{idx}] share one \
             issuer realm but read their required scopes from different claim paths"
        ));
    }
    if earlier.required_roles != later.required_roles {
        return Err(format!(
            "jwks_auth: equivalent providers must agree on 'required_roles'; \
             provider[{earlier_idx}] and provider[{idx}] share one issuer \
             realm with incompatible role requirements"
        ));
    }
    if !later.required_roles.is_empty() && earlier.role_claim != later.role_claim {
        return Err(format!(
            "jwks_auth: equivalent providers that require roles must agree on \
             'role_claim'; provider[{earlier_idx}] and provider[{idx}] share one \
             issuer realm but read their required roles from different claim paths"
        ));
    }
    Ok(())
}

/// Deterministic, bounded **semantic identity** of one DPoP issuer realm,
/// used as its replay protection sub-domain.
///
/// # Why not the array index
///
/// The provider's position in `providers` is not an identity. Reordering an
/// otherwise unchanged list, or inserting/deleting an unrelated provider ahead
/// of it, moves a provider into a *fresh* replay lane (or, worse, onto another
/// provider's lane) while its live markers stay where nothing consults them. A
/// proof that was already accepted is then admitted a second time — the exact
/// property `require_dpop` exists to deny. The identity below is stable across
/// reorder, reload, restart, and every replica of one policy.
///
/// # Why not the JWKS document or source URL
///
/// Hashing the inline JWKS, a key id, array position, or remote source
/// endpoint makes an ordinary trust-source rotation a security event: adding,
/// removing, or reordering keys, or changing `jwks_uri` / `discovery_url`
/// while the same previously accepted access token + DPoP proof remains valid
/// under the replacement provider, creates a fresh replay domain. The exact
/// proof is then claimable again. Exact-JWKS equality also misses overlapping
/// providers: two entries with the same issuer and overlapping accepted
/// signing keys can select different process/shared authorities after reorder.
///
/// # What it binds
///
/// The provider's **exact `issuer` realm**. `require_dpop` providers must
/// declare a nonblank issuer, so the replay sub-domain has a stable semantic
/// identity that survives key-set and source-endpoint rotation. Issuer
/// matching remains exact: an issuer is not a URL endpoint and is not
/// normalized here. Providers in one policy that share that exact issuer
/// share one replay realm even when their JWKS sources, audiences, or key sets
/// differ or overlap; they must therefore agree on `require_dpop`,
/// `require_mtls_binding`, `required_scopes`, and `required_roles` — plus the
/// effective `scope_claim` / `role_claim` those requirements are read from,
/// whenever the matching requirement list is non-empty — and when
/// DPoP is required they must agree on replay scope and process capacity. A
/// non-DPoP sibling for the same issuer is refused as a bearer-only bypass.
/// Different exact issuers remain isolated.
///
/// # What it deliberately does not bind
///
/// JWKS contents, key ids, source kind, source URL, `audiences`, claim/header
/// locations, `forward_original_token`, `jwks_max_stale_seconds`,
/// `dpop_replay_max_entries`, `dpop_replay_scope`, and
/// `dpop_clock_skew_secs`. Folding any of those in would reopen live proofs
/// on an ordinary authorization, key, or endpoint edit. The fixed retention
/// horizon already dominates the widest admissible skew, so a skew change can
/// never outrun a marker. Capacity and replay scope are instead enforced at
/// admission so matching order cannot pick which authority a proof is claimed
/// against.
///
/// No raw issuer, JWKS URI, discovery URL, or JWK material is retained: the
/// issuer is written through [`PartitionHasher`]'s length-prefixed framing
/// and only the digest leaves this function.
fn dpop_provider_identity(issuer: &str) -> String {
    let mut hasher = PartitionHasher::new("ferrum-edge/jwks-auth/dpop-provider-identity/v2");
    hasher.text("provider.issuer", issuer);
    hasher.hex()
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
    let client = http_client
        .get()
        .map_err(|e| format!("OIDC discovery request failed: {e}"))?;
    let req = client.get(discovery_url);
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
fn stage_mesh_request_principal_metadata(claims: &Value, attempt: &mut AuthenticationAttempt) {
    if let (Some(iss), Some(sub)) = (
        claims.get("iss").and_then(|v| v.as_str()),
        claims.get("sub").and_then(|v| v.as_str()),
    ) {
        attempt
            .stage_principal_metadata("mesh.request_principal".to_string(), format!("{iss}/{sub}"));
    }

    // `request.auth.audiences` — string or string-array form.
    if let Some(aud) = claims.get("aud")
        && let Some(audiences) = string_scalar_or_array(aud)
    {
        attempt.stage_mesh_request_auth_audiences(audiences);
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
            stage_mesh_claim_attribute(name, value, attempt);
        }
    }
}

/// Render a single JWT claim leaf into the string form Istio uses for
/// `request.auth.claims[...]` matching. String claims render directly; string
/// arrays stay as lists so one item containing a comma does not broaden policy
/// matching. Objects and non-string leaves are skipped by this leaf renderer;
/// object traversal happens in [`stage_mesh_claim_attribute`].
fn render_claim_leaf_attribute_value(value: &Value) -> Option<JwtAuthAttributeValue> {
    match value {
        Value::String(s) => Some(JwtAuthAttributeValue::Scalar(s.clone())),
        Value::Array(_) => string_scalar_or_array(value).map(JwtAuthAttributeValue::StringList),
        Value::Bool(_) | Value::Number(_) | Value::Null | Value::Object(_) => None,
    }
}

fn stage_mesh_claim_attribute(path: &str, value: &Value, attempt: &mut AuthenticationAttempt) {
    if let Some(rendered) = render_claim_leaf_attribute_value(value) {
        attempt.stage_mesh_request_auth_claim(path.to_string(), rendered);
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
        stage_mesh_claim_attribute(&nested_path, nested, attempt);
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
