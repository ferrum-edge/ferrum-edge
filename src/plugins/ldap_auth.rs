//! LDAP Authentication plugin with optional Active Directory group filtering.
//!
//! Authenticates requests by extracting HTTP Basic credentials and validating
//! them against an LDAP directory via a bind operation. Supports two modes:
//!
//! - **Direct bind**: Uses a `bind_dn_template` with `{username}` placeholder
//!   to construct the bind DN directly. Faster, no service account needed.
//! - **Search-then-bind**: Uses a service account to search for the user's DN,
//!   then binds as that user. More flexible (supports any search filter).
//!
//! Exactly one mode may be configured, and both require
//! `canonical_identity_attribute`: the Ferrum identity is always read off the
//! directory entry that authenticated, never taken from the client-presented
//! login (which directories match case- and whitespace-insensitively).
//!
//! Optionally checks LDAP/AD group membership after authentication. When
//! `required_groups` is set, the user must belong to at least one of the
//! listed groups (OR logic) for authentication to succeed.
//!
//! Successful authentications can be cached in-memory (keyed by a random-key
//! HMAC over username + password) to avoid hitting the LDAP server on every
//! request.
//!
//! ## TLS integration
//!
//! Both `ldaps://` and STARTTLS connections use rustls (matching the gateway's
//! TLS stack everywhere else). The plugin respects:
//! - `FERRUM_TLS_CA_BUNDLE_PATH` — custom CA bundle for verifying the LDAP
//!   server certificate. When set, the rustls trust store is built from this
//!   bundle ALONE (CA exclusivity per CLAUDE.md "TLS Architecture") — public
//!   CAs in the system / webpki bundle are NOT trusted, preventing a
//!   public-CA-issued certificate from MITM-ing the LDAP connection.
//! - `FERRUM_TLS_NO_VERIFY` — skip TLS certificate verification (testing only)
//! - `FERRUM_TLS_CRL_FILE_PATH` — gateway CRL list. When configured (and
//!   verification is not disabled), revoked LDAP server certificates are
//!   rejected via `build_server_verifier_with_crls()`, giving `ldaps://` /
//!   STARTTLS the same revocation guarantees as the proxy backend, DTLS,
//!   frontend mTLS, and rustls logging-sink surfaces.
//!
//! Every connection performs an uncached A+AAAA lookup, screens the complete
//! answer set and each imminent dial under the gateway backend egress policy,
//! and gives `ldap3` the screened socket together with the original URL. This
//! closes DNS-rebinding windows without replacing the hostname used for TLS
//! certificate and SNI verification.

use crate::fips::approved::HmacSha256;
use crate::fips::backend::rand::SecureRandom;
use async_trait::async_trait;
use base64::Engine;
use dashmap::DashMap;
use ldap3::{
    Ldap, LdapConnAsync, LdapConnSettings, Scope, SearchEntry, SearchOptions, StdStream,
    parse_filter,
};
use rustls::ClientConfig;
#[cfg(test)]
use rustls::pki_types::CertificateDer;
use rustls::pki_types::CertificateRevocationListDer;
use serde_json::Map;
use serde_json::Value;
use std::collections::{HashMap, HashSet};
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, Instant};
use tokio::net::TcpStream;
use tokio::sync::Semaphore;
use tracing::{debug, warn};
use url::{Host, Url};
use zeroize::Zeroizing;

use crate::consumer_index::ConsumerIndex;
use crate::dns::{DnsCache, DnsConfig};
use crate::tls::source::{CertSource, MaterialKind, load_material_blocking};

use super::utils::PluginHttpClient;
use super::utils::auth_flow::{self, AuthMechanism, ExtractedCredential, VerifyOutcome};
use super::utils::header_extract::{ConfiguredHeaderLookup, lookup_configured_header};
use super::{RequestContext, strip_auth_scheme};

pub const LDAP_AUTH_DEFAULT_CACHE_TTL_SECONDS: u64 = 0;
pub const LDAP_AUTH_MAX_CACHE_TTL_SECONDS: u64 = 86_400;
pub const LDAP_AUTH_DEFAULT_MAX_CACHE_ENTRIES: usize = 10_000;
/// Upper bound on `max_cache_entries`. The cache holds one canonical identity
/// per admitted credential, so an unbounded configured maximum is a memory
/// commitment the operator cannot see; every other `ldap_auth` resource knob
/// is bounded the same way.
pub const LDAP_AUTH_MAX_CACHE_ENTRIES_LIMIT: usize = 1_000_000;

/// `WWW-Authenticate` challenge advertised for rejected/absent credentials.
const LDAP_AUTH_BASIC_CHALLENGE: &str = r#"Basic realm="ferrum-edge", charset="UTF-8""#;

const LDAP_AUTH_DEFAULT_CONNECT_TIMEOUT_SECONDS: u64 = 5;
const LDAP_AUTH_MAX_CONNECT_TIMEOUT_SECONDS: u64 = 300;
const LDAP_AUTH_DEFAULT_REQUEST_TIMEOUT_SECONDS: u64 = 15;
const LDAP_AUTH_MAX_REQUEST_TIMEOUT_SECONDS: u64 = 300;
const LDAP_AUTH_DEFAULT_MAX_CONCURRENT_REQUESTS: usize = 64;
const LDAP_AUTH_MAX_CONCURRENT_REQUESTS: usize = 1_024;
const LDAP_AUTH_USER_SEARCH_SIZE_LIMIT: i32 = 2;
const LDAP_AUTH_GROUP_SEARCH_SIZE_LIMIT: i32 = 1_000;

#[derive(Clone, Copy, Eq, Hash, PartialEq)]
struct CacheKey([u8; 32]);

struct CacheEntry {
    expires_at: Instant,
    canonical_identity: String,
}

struct AuthenticatedUser {
    dn: String,
    canonical_identity: String,
}

/// Outcome of an LDAP authentication attempt, distinguishing a genuine
/// credential-negative result (wrong password / user not found) from a
/// backend or configuration failure (directory unreachable, service-account
/// bind rejected, search RPC error).
///
/// `verify()` maps `Credential` to `VerifyOutcome::Invalid` (HTTP 401) and
/// `Backend` to `VerifyOutcome::Internal` (HTTP 500), mirroring the existing
/// group-membership path so the two paths are consistent. Returning 401 for a
/// directory outage or misconfigured service account would tell the client its
/// credentials are wrong — prompting credential re-submission and masking the
/// operational problem (finding #32). Each variant carries the specific cause
/// for the `warn!` log only; the client always sees a generic message.
enum AuthError {
    /// The presented credentials were rejected, or the user does not exist.
    /// Maps to 401.
    Credential(String),
    /// The directory was unreachable, the service account failed/was rejected,
    /// or a search RPC failed. Operational/config problem, not the client's
    /// fault. Maps to 500.
    Backend(String),
}

impl AuthError {
    /// The specific cause, for operator-facing `warn!` logs only — never sent
    /// to the client.
    fn log_message(&self) -> &str {
        match self {
            AuthError::Credential(msg) | AuthError::Backend(msg) => msg,
        }
    }
}

fn classify_user_bind_result(result: ldap3::LdapResult, context: &str) -> Result<(), AuthError> {
    match result.rc {
        0 => Ok(()),
        49 => Err(AuthError::Credential(format!(
            "ldap_auth: {context} rejected: {result}"
        ))),
        _ => Err(AuthError::Backend(format!(
            "ldap_auth: {context} failed with directory result: {result}"
        ))),
    }
}

pub struct LdapAuth {
    ldap_url: String,
    /// Direct bind: "uid={username},ou=users,dc=example,dc=com"
    bind_dn_template: Option<String>,
    /// Search-then-bind base DN
    search_base_dn: Option<String>,
    /// Search filter with {username} placeholder, e.g. "(&(objectClass=person)(sAMAccountName={username}))"
    search_filter: Option<String>,
    /// Attribute returned by search-then-bind and used as the Ferrum identity
    /// and username-based group-authorization value.
    canonical_identity_attribute: Option<String>,
    /// Service account for search-then-bind
    service_account_dn: Option<String>,
    service_account_password: Option<String>,
    /// Group membership filtering
    group_base_dn: Option<String>,
    group_filter: Option<String>,
    required_groups: Vec<String>,
    required_group_lookup: HashSet<String>,
    group_attribute: String,
    /// Use STARTTLS on ldap:// connections
    starttls: bool,
    /// LDAP connection timeout
    connect_timeout: Duration,
    /// Server-side time limit applied to each LDAP search.
    search_time_limit_seconds: i32,
    /// Strict wall-clock deadline for one complete uncached authentication.
    request_timeout: Duration,
    /// Immediate admission bound for uncached LDAP authentication work.
    ldap_concurrency: Arc<Semaphore>,
    /// Cache TTL for successful auth results (0 = disabled)
    cache_ttl: Duration,
    /// In-memory cache keyed by a process-random HMAC over username + password.
    cache: Arc<DashMap<CacheKey, CacheEntry>>,
    cache_entries: AtomicUsize,
    /// Zeroized on drop. A full-memory compromise can still recover this key.
    cache_hmac_key: Option<Zeroizing<[u8; 32]>>,
    /// Maximum entries in the auth result cache. Prevents unbounded growth
    /// from brute-force attempts with unique credentials. Default: 10000.
    max_cache_entries: usize,
    /// Whether to try mapping to a gateway Consumer via consumer_index
    consumer_mapping: bool,
    /// Remove the verified `Authorization: Basic` credential from the backend
    /// request. Default `true`, matching `key_auth`.
    hide_credentials: bool,
    /// Request headers whose values carry reusable credentials and must be
    /// omitted from diagnostics and policy calls.
    request_headers_to_redact: Vec<String>,
    /// Pre-built rustls `ClientConfig` for LDAP TLS connections.
    /// Integrates `FERRUM_TLS_CA_BUNDLE_PATH` (exclusive trust) and
    /// `FERRUM_TLS_NO_VERIFY`. `Arc` so reuse across reconnects is cheap and
    /// matches `LdapConnSettings::set_config()`'s expected type.
    tls_config: Option<Arc<ClientConfig>>,
    /// Whether to skip TLS verification (passed to ldap3 for IP-address handling).
    tls_no_verify: bool,
    /// Configured hostname retained for DNS and TLS hostname/SNI verification.
    ldap_hostname: String,
    ldap_port: u16,
    /// Resolver with a cache-bypassing dial path. In production this is the
    /// gateway's shared resolver; cache-less test/validation clients receive a
    /// private resolver carrying the same backend policy.
    dns_cache: DnsCache,
    /// Active backend policy rechecked immediately before each socket opens.
    backend_egress_policy: crate::config::BackendEgressPolicy,
    /// Plaintext loopback endpoints are admitted without the development-only
    /// override, but their actual dial-time answers must remain loopback.
    plaintext_requires_loopback: bool,
}

impl LdapAuth {
    pub fn new(config: &Value, http_client: PluginHttpClient) -> Result<Self, String> {
        let config_obj = config
            .as_object()
            .ok_or_else(|| "ldap_auth: config must be an object".to_string())?;
        reject_unknown_config_keys(config_obj)?;

        let ldap_url = parse_required_ldap_url(config_obj)?.to_owned();
        let parsed_ldap_url = Url::parse(&ldap_url)
            .map_err(|e| format!("ldap_auth: 'ldap_url' is not a valid URL: {e}"))?;

        if !parsed_ldap_url.username().is_empty() || parsed_ldap_url.password().is_some() {
            return Err(
                "ldap_auth: 'ldap_url' must not contain embedded credentials; use the service account fields"
                    .to_string(),
            );
        }

        // Decide the scheme from the RAW value, not from `Url::parse`, which
        // case-folds it: the published contract (and every `ldap_url` pattern
        // in `openapi.yaml`) is a lowercase scheme, so `LDAP://` must be
        // refused here rather than silently admitted by the gateway and
        // rejected by schema validation.
        let is_ldaps = if ldap_url.starts_with("ldaps://") {
            true
        } else if ldap_url.starts_with("ldap://") {
            false
        } else {
            return Err(
                "ldap_auth: 'ldap_url' must start with 'ldap://' or 'ldaps://'".to_string(),
            );
        };
        if !has_non_empty_authority(&ldap_url) {
            return Err("ldap_auth: 'ldap_url' must include a hostname".to_string());
        }
        let ldap_hostname = ldap_url_hostname(&parsed_ldap_url)?;
        let ldap_port = parsed_ldap_url
            .port()
            .unwrap_or(if is_ldaps { 636 } else { 389 });

        let bind_dn_template = parse_optional_string(config_obj, "bind_dn_template")?;

        let search_base_dn = parse_optional_string(config_obj, "search_base_dn")?;

        let search_filter = parse_optional_string(config_obj, "search_filter")?;

        let canonical_identity_attribute =
            parse_optional_string(config_obj, "canonical_identity_attribute")?;

        let service_account_dn = parse_optional_string(config_obj, "service_account_dn")?;

        let service_account_password =
            parse_optional_secret_string(config_obj, "service_account_password")?;

        // Validate: must have either bind_dn_template or search-then-bind config
        let has_direct_bind = bind_dn_template.is_some();
        let has_search_bind = search_base_dn.is_some() && search_filter.is_some();

        if !has_direct_bind && !has_search_bind {
            return Err(
                "ldap_auth: must configure either 'bind_dn_template' for direct bind, \
                 or both 'search_base_dn' and 'search_filter' for search-then-bind"
                    .to_string(),
            );
        }

        // Direct bind and search-then-bind are alternatives, not layers. Taking
        // the direct-bind branch while a search block is configured would leave
        // the search keys silently inert, so refuse the ambiguous shape outright.
        if has_direct_bind && (search_base_dn.is_some() || search_filter.is_some()) {
            return Err(
                "ldap_auth: 'bind_dn_template' (direct bind) cannot be combined with the \
                 search-then-bind keys 'search_base_dn'/'search_filter'; configure exactly \
                 one authentication mode"
                    .to_string(),
            );
        }

        if has_search_bind && (service_account_dn.is_none() || service_account_password.is_none()) {
            return Err(
                "ldap_auth: search-then-bind mode requires 'service_account_dn' and \
                 'service_account_password'"
                    .to_string(),
            );
        }

        if canonical_identity_attribute.is_none() {
            return Err(
                "ldap_auth: both bind modes require 'canonical_identity_attribute' so the authenticated directory entry, not the presented username, defines the Ferrum identity"
                    .to_string(),
            );
        }

        if let Some(ref tmpl) = bind_dn_template
            && !tmpl.contains("{username}")
        {
            return Err(
                "ldap_auth: 'bind_dn_template' must contain '{username}' placeholder".to_string(),
            );
        }

        if let Some(ref f) = search_filter {
            if !f.contains("{username}") {
                return Err(
                    "ldap_auth: 'search_filter' must contain '{username}' placeholder".to_string(),
                );
            }
            validate_ldap_filter_syntax(f, "search_filter")?;
        }

        // Group filtering config
        let group_base_dn = parse_optional_string(config_obj, "group_base_dn")?;

        let group_filter = parse_optional_string(config_obj, "group_filter")?;
        if let Some(ref f) = group_filter {
            validate_ldap_filter_syntax(f, "group_filter")?;
        }

        let required_groups = parse_string_array(config_obj, "required_groups")?;
        let required_group_lookup = required_groups
            .iter()
            .map(|group| group.to_lowercase())
            .collect();

        if !required_groups.is_empty() && group_base_dn.is_none() {
            return Err(
                "ldap_auth: 'group_base_dn' is required when 'required_groups' is set".to_string(),
            );
        }

        if !required_groups.is_empty()
            && group_filter.as_ref().is_some_and(|filter| {
                !filter.contains("{user_dn}") && !filter.contains("{username}")
            })
        {
            return Err(
                "ldap_auth: 'group_filter' must contain '{user_dn}' or '{username}' when 'required_groups' is set"
                    .to_string(),
            );
        }

        // Finding #33: when group enforcement is configured but no service
        // account is available, the group-membership search runs over an
        // ANONYMOUS-bound connection. Many directories deny anonymous reads of
        // group objects / `member` attributes, so the search silently returns
        // zero entries and a legitimately entitled user gets a 403. Surface
        // this dependency on directory ACLs at config time rather than as
        // silent denials at request time. (Search-then-bind already mandates a
        // service account above, so this only fires for direct-bind configs.)
        if !required_groups.is_empty()
            && (service_account_dn.is_none() || service_account_password.is_none())
        {
            warn!(
                "ldap_auth: 'required_groups' is set without a service account \
                 ('service_account_dn'/'service_account_password'); the group-membership search \
                 will use an ANONYMOUS bind. Group enforcement will only work if the directory \
                 permits anonymous reads of group objects — otherwise entitled users will be \
                 denied (403). Configure a service account to avoid relying on directory ACLs."
            );
        }

        let group_attribute =
            parse_optional_string(config_obj, "group_attribute")?.unwrap_or_else(|| "cn".into());

        let starttls = parse_bool(config_obj, "starttls", false)?;

        if starttls && is_ldaps {
            return Err(
                "ldap_auth: 'starttls' cannot be used with 'ldaps://' URLs (STARTTLS is for upgrading ldap:// connections)"
                    .to_string(),
            );
        }

        let connect_timeout_secs = parse_u64(
            config_obj,
            "connect_timeout_seconds",
            LDAP_AUTH_DEFAULT_CONNECT_TIMEOUT_SECONDS,
        )?;
        if connect_timeout_secs == 0 {
            return Err(
                "ldap_auth: 'connect_timeout_seconds' must be greater than zero".to_string(),
            );
        }
        if connect_timeout_secs > LDAP_AUTH_MAX_CONNECT_TIMEOUT_SECONDS {
            return Err(format!(
                "ldap_auth: 'connect_timeout_seconds' must not exceed {LDAP_AUTH_MAX_CONNECT_TIMEOUT_SECONDS}"
            ));
        }
        let search_time_limit_seconds = i32::try_from(connect_timeout_secs).map_err(|_| {
            "ldap_auth: 'connect_timeout_seconds' cannot be represented as an LDAP search time limit"
                .to_string()
        })?;

        let default_request_timeout_secs =
            LDAP_AUTH_DEFAULT_REQUEST_TIMEOUT_SECONDS.max(connect_timeout_secs);
        let request_timeout_secs = parse_u64(
            config_obj,
            "request_timeout_seconds",
            default_request_timeout_secs,
        )?;
        if request_timeout_secs == 0 {
            return Err(
                "ldap_auth: 'request_timeout_seconds' must be greater than zero".to_string(),
            );
        }
        if request_timeout_secs > LDAP_AUTH_MAX_REQUEST_TIMEOUT_SECONDS {
            return Err(format!(
                "ldap_auth: 'request_timeout_seconds' must not exceed {LDAP_AUTH_MAX_REQUEST_TIMEOUT_SECONDS}"
            ));
        }

        let max_concurrent_requests = parse_usize(
            config_obj,
            "max_concurrent_requests",
            LDAP_AUTH_DEFAULT_MAX_CONCURRENT_REQUESTS,
        )?;
        if max_concurrent_requests == 0 {
            return Err(
                "ldap_auth: 'max_concurrent_requests' must be greater than zero".to_string(),
            );
        }
        if max_concurrent_requests > LDAP_AUTH_MAX_CONCURRENT_REQUESTS {
            return Err(format!(
                "ldap_auth: 'max_concurrent_requests' must not exceed {LDAP_AUTH_MAX_CONCURRENT_REQUESTS}"
            ));
        }

        let cache_ttl_secs = parse_u64(
            config_obj,
            "cache_ttl_seconds",
            LDAP_AUTH_DEFAULT_CACHE_TTL_SECONDS,
        )?;
        if cache_ttl_secs > LDAP_AUTH_MAX_CACHE_TTL_SECONDS {
            return Err(format!(
                "ldap_auth: 'cache_ttl_seconds' must not exceed {LDAP_AUTH_MAX_CACHE_TTL_SECONDS}"
            ));
        }

        let max_cache_entries = parse_usize(
            config_obj,
            "max_cache_entries",
            LDAP_AUTH_DEFAULT_MAX_CACHE_ENTRIES,
        )?;
        if max_cache_entries == 0 {
            return Err("ldap_auth: 'max_cache_entries' must be greater than zero".to_string());
        }
        if max_cache_entries > LDAP_AUTH_MAX_CACHE_ENTRIES_LIMIT {
            return Err(format!(
                "ldap_auth: 'max_cache_entries' must not exceed {LDAP_AUTH_MAX_CACHE_ENTRIES_LIMIT}"
            ));
        }

        let consumer_mapping = parse_bool(config_obj, "consumer_mapping", true)?;

        // Basic credentials are a reusable directory password, typically the
        // user's corporate password. Removing them from the backend request by
        // default keeps them inside the gateway trust boundary; `key_auth`
        // established the same default for its reusable API keys.
        let hide_credentials = parse_bool(config_obj, "hide_credentials", true)?;

        let allow_plaintext = parse_bool(config_obj, "allow_plaintext", false)?;
        let plaintext_requires_loopback = !is_ldaps && !starttls && !allow_plaintext;
        if !is_ldaps && !starttls && !is_loopback_ldap_endpoint(&parsed_ldap_url) {
            if !allow_plaintext {
                return Err(
                    "ldap_auth: non-loopback 'ldap://' endpoints require STARTTLS or LDAPS; set 'allow_plaintext: true' only for an isolated development environment"
                        .to_string(),
                );
            }
            warn!(
                "ldap_auth: ALLOWING PLAINTEXT LDAP to a non-loopback endpoint; service-account and user passwords have no transport confidentiality ('allow_plaintext: true' is development-only)"
            );
        }

        let cache_hmac_key = if cache_ttl_secs == 0 {
            None
        } else {
            let mut key = Zeroizing::new([0u8; 32]);
            crate::fips::backend::rand::SystemRandom::new()
                .fill(key.as_mut())
                .map_err(|_| "ldap_auth: failed to generate cache HMAC key".to_string())?;
            Some(key)
        };
        let cache_shard_amount = http_client.pool_shard_amount();
        let backend_egress_policy = http_client.backend_allow_ips().clone();
        let dns_cache = http_client.dns_cache().cloned().unwrap_or_else(|| {
            DnsCache::new(DnsConfig {
                backend_allow_ips: backend_egress_policy.clone(),
                ..DnsConfig::default()
            })
        });

        // Build rustls TLS config respecting gateway settings, including the
        // gateway's parsed CRL list (`FERRUM_TLS_CRL_FILE_PATH`) so revoked LDAP
        // server certificates are rejected — parity with the proxy backend /
        // DTLS / rustls logging-sink surfaces (finding #84).
        let tls_no_verify = http_client.tls_no_verify();
        let needs_tls = is_ldaps || starttls;
        let tls_config = if needs_tls {
            Some(build_ldap_tls_config(
                tls_no_verify,
                http_client.tls_ca_bundle_path(),
                http_client.tls_crls(),
            )?)
        } else {
            None
        };

        Ok(Self {
            ldap_url,
            bind_dn_template,
            search_base_dn,
            search_filter,
            canonical_identity_attribute,
            service_account_dn,
            service_account_password,
            group_base_dn,
            group_filter,
            required_groups,
            required_group_lookup,
            group_attribute,
            starttls,
            connect_timeout: Duration::from_secs(connect_timeout_secs),
            search_time_limit_seconds,
            request_timeout: Duration::from_secs(request_timeout_secs),
            ldap_concurrency: Arc::new(Semaphore::new(max_concurrent_requests)),
            cache_ttl: Duration::from_secs(cache_ttl_secs),
            cache: Arc::new(DashMap::with_shard_amount(cache_shard_amount)),
            cache_entries: AtomicUsize::new(0),
            cache_hmac_key,
            max_cache_entries,
            consumer_mapping,
            hide_credentials,
            request_headers_to_redact: vec!["authorization".to_string()],
            tls_config,
            tls_no_verify,
            ldap_hostname,
            ldap_port,
            dns_cache,
            backend_egress_policy,
            plaintext_requires_loopback,
        })
    }

    /// Build an opaque cache key using the per-instance random HMAC key.
    fn cache_key(&self, username: &str, password: &str) -> Option<CacheKey> {
        let key = self.cache_hmac_key.as_deref()?;
        let Ok(mut mac) = HmacSha256::new_from_slice(key) else {
            warn!("ldap_auth: failed to initialize cache HMAC");
            return None;
        };
        let username_len = u64::try_from(username.len()).ok()?;
        mac.update(username_len.to_be_bytes());
        mac.update(username.as_bytes());
        mac.update(password.as_bytes());
        let digest = mac.finalize().into_bytes();
        let mut cache_key = [0u8; 32];
        cache_key.copy_from_slice(&digest);
        Some(CacheKey(cache_key))
    }

    /// Check if a successful auth result is cached and still valid.
    fn check_cache(&self, username: &str, password: &str) -> Option<String> {
        if self.cache_ttl.is_zero() {
            return None;
        }
        let key = self.cache_key(username, password)?;
        if let Some(entry) = self.cache.get(&key) {
            if Instant::now() < entry.expires_at {
                return Some(entry.canonical_identity.clone());
            }
            // Expired — remove the entry
            drop(entry);
            if self.cache.remove(&key).is_some() {
                self.release_cache_slot();
            }
        }
        None
    }

    /// Cache a successful authentication result.
    fn set_cache(&self, username: &str, password: &str, canonical_identity: &str) {
        if self.cache_ttl.is_zero() {
            return;
        }
        let Some(key) = self.cache_key(username, password) else {
            return;
        };
        let Some(expires_at) = Instant::now().checked_add(self.cache_ttl) else {
            warn!("ldap_auth: cache expiry could not be represented; skipping cache admission");
            return;
        };
        let new_entry = || CacheEntry {
            expires_at,
            canonical_identity: canonical_identity.to_string(),
        };

        if let Some(mut existing) = self.cache.get_mut(&key) {
            *existing = new_entry();
            return;
        }

        if !self.try_reserve_cache_slot() {
            // Bounded replacement: evict at most one entry instead of scanning
            // the entire map on every saturated-cache miss.
            if !self.evict_one_cache_entry() || !self.try_reserve_cache_slot() {
                return;
            }
        }

        match self.cache.entry(key) {
            dashmap::mapref::entry::Entry::Occupied(mut occupied) => {
                occupied.insert(new_entry());
                self.release_cache_slot();
            }
            dashmap::mapref::entry::Entry::Vacant(vacant) => {
                vacant.insert(new_entry());
            }
        }
    }

    fn release_cache_slot(&self) {
        if self
            .cache_entries
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |current| {
                current.checked_sub(1)
            })
            .is_err()
        {
            warn!("ldap_auth: cache entry accounting underflow prevented");
        }
    }

    fn try_reserve_cache_slot(&self) -> bool {
        let mut current = self.cache_entries.load(Ordering::Acquire);
        loop {
            if current >= self.max_cache_entries {
                return false;
            }
            match self.cache_entries.compare_exchange_weak(
                current,
                current + 1,
                Ordering::AcqRel,
                Ordering::Acquire,
            ) {
                Ok(_) => return true,
                Err(observed) => current = observed,
            }
        }
    }

    fn evict_one_cache_entry(&self) -> bool {
        let victim = self.cache.iter().next().map(|entry| *entry.key());
        let Some(victim) = victim else {
            return false;
        };
        if self.cache.remove(&victim).is_some() {
            self.release_cache_slot();
            true
        } else {
            false
        }
    }

    /// Connect to the LDAP server with configured settings.
    ///
    /// A connection failure is a backend/infrastructure problem (directory
    /// unreachable, TLS handshake failure), not a credential problem, so it is
    /// surfaced as [`AuthError::Backend`].
    async fn connect(&self) -> Result<ldap3::Ldap, AuthError> {
        tokio::time::timeout(self.connect_timeout, self.connect_with_policy())
            .await
            .map_err(|_| {
                AuthError::Backend(
                    "ldap_auth: DNS resolution or connection establishment timed out".to_string(),
                )
            })?
    }

    async fn connect_with_policy(&self) -> Result<ldap3::Ldap, AuthError> {
        let candidates = self
            .dns_cache
            .resolve_all_fresh(&self.ldap_hostname)
            .await
            .map_err(|error| {
                AuthError::Backend(format!(
                    "ldap_auth: dial-time DNS resolution failed: {error}"
                ))
            })?;

        // Validate the complete answer set before opening any socket. A mixed
        // allowed/denied response fails closed instead of letting an allowed
        // decoy make the answer look safe while a client later selects a denied
        // candidate.
        for &candidate in &candidates {
            self.screen_dial_candidate(candidate)?;
        }

        let mut last_connect_error = None;
        for candidate in candidates {
            // Keep the active-policy check immediately adjacent to the actual
            // dial. This is intentionally repeated after the whole-set screen.
            self.screen_dial_candidate(candidate)?;
            let socket_addr = SocketAddr::new(candidate, self.ldap_port);
            match TcpStream::connect(socket_addr).await {
                Ok(stream) => {
                    let std_stream = stream.into_std().map_err(|error| {
                        AuthError::Backend(format!(
                            "ldap_auth: failed to prepare screened connection: {error}"
                        ))
                    })?;
                    return self.connect_ldap_over_stream(std_stream).await;
                }
                Err(error) => last_connect_error = Some((socket_addr, error)),
            }
        }

        match last_connect_error {
            Some((socket_addr, error)) => Err(AuthError::Backend(format!(
                "ldap_auth: all screened connection candidates failed; last dial to {socket_addr} failed: {error}"
            ))),
            None => Err(AuthError::Backend(
                "ldap_auth: dial-time DNS resolution returned no connection candidates".to_string(),
            )),
        }
    }

    fn screen_dial_candidate(&self, candidate: IpAddr) -> Result<(), AuthError> {
        if let Some(reason) = self.backend_egress_policy.deny_reason(&candidate) {
            return Err(AuthError::Backend(format!(
                "ldap_auth: dial candidate {candidate} denied by backend egress policy: {reason}"
            )));
        }
        if self.plaintext_requires_loopback && !candidate.is_loopback() {
            return Err(AuthError::Backend(format!(
                "ldap_auth: plaintext loopback endpoint resolved to non-loopback address {candidate}"
            )));
        }
        Ok(())
    }

    async fn connect_ldap_over_stream(
        &self,
        stream: std::net::TcpStream,
    ) -> Result<ldap3::Ldap, AuthError> {
        let mut settings = LdapConnSettings::new()
            .set_conn_timeout(self.connect_timeout)
            .set_starttls(self.starttls)
            .set_no_tls_verify(self.tls_no_verify)
            .set_std_stream(StdStream::Tcp(stream));

        if let Some(ref config) = self.tls_config {
            settings = settings.set_config(config.clone());
        }

        // Supplying the original URL together with the preconnected concrete
        // socket makes ldap3 use `ldap_hostname` for rustls ServerName/SNI. The
        // screened IP is never substituted into the TLS identity.
        let (conn, ldap) = LdapConnAsync::with_settings(settings, &self.ldap_url)
            .await
            .map_err(|e| AuthError::Backend(format!("ldap_auth: connection failed: {e}")))?;

        // Drive the connection in the background
        ldap3::drive!(conn);

        Ok(ldap)
    }

    /// Authenticate a user via direct bind or search-then-bind.
    /// Returns the user's DN and canonical Ferrum identity on success.
    ///
    /// Errors are classified ([`AuthError`]) so that a rejected user bind /
    /// "user not found" surfaces as a 401 while a directory outage, a failed
    /// service-account bind, or a search RPC error surfaces as a 500 (finding
    /// #32). A bind that *fails* (transport / RPC error) is a backend problem;
    /// a bind that is *rejected* (LDAP returned a non-success result code for
    /// the end user's credentials) is the genuine invalid-credential case.
    async fn authenticate_user(
        &self,
        username: &str,
        password: &str,
    ) -> Result<AuthenticatedUser, AuthError> {
        let mut ldap = self.connect().await?;

        let authenticated_user = if let Some(ref template) = self.bind_dn_template {
            // Direct bind: substitute DN-escaped username into template (RFC 4514)
            let dn = template.replace("{username}", &escape_dn_value(username));
            let bind_result = ldap
                .with_timeout(self.connect_timeout)
                .simple_bind(&dn, password)
                .await
                .map_err(|e| AuthError::Backend(format!("ldap_auth: bind failed: {e}")))?;
            classify_user_bind_result(bind_result, "bind")?;

            // The presented login is not an identity. Directories match and fold
            // login attributes case- and whitespace-insensitively, so one
            // account would otherwise mint an unbounded set of distinct Ferrum
            // principals. Read the canonical attribute off the entry that
            // actually authenticated, over that entry's own bound connection,
            // exactly as search-then-bind does.
            let canonical_identity = self.read_canonical_identity(&mut ldap, &dn).await?;
            let _ = ldap.with_timeout(self.connect_timeout).unbind().await;
            AuthenticatedUser {
                dn,
                canonical_identity,
            }
        } else {
            // Search-then-bind: find user DN via service account
            let service_dn = self.service_account_dn.as_deref().unwrap_or_default();
            let service_pw = self.service_account_password.as_deref().unwrap_or_default();

            // A failed/rejected service-account bind is an operator
            // misconfiguration, never the end user's fault — classify both as
            // backend errors so the client is not told its credentials are wrong.
            ldap.with_timeout(self.connect_timeout)
                .simple_bind(service_dn, service_pw)
                .await
                .map_err(|e| {
                    AuthError::Backend(format!("ldap_auth: service account bind failed: {e}"))
                })?
                .success()
                .map_err(|e| {
                    AuthError::Backend(format!("ldap_auth: service account bind rejected: {e}"))
                })?;

            let search_base = self.search_base_dn.as_deref().unwrap_or_default();
            let filter = self
                .search_filter
                .as_deref()
                .unwrap_or_default()
                .replace("{username}", &escape_filter_value(username));
            let canonical_identity_attribute =
                self.canonical_identity_attribute.as_deref().ok_or_else(|| {
                    AuthError::Backend(
                        "ldap_auth: canonical identity attribute is missing in search-then-bind mode"
                            .to_string(),
                    )
                })?;

            let search_result = ldap
                .with_search_options(
                    SearchOptions::new()
                        .sizelimit(LDAP_AUTH_USER_SEARCH_SIZE_LIMIT)
                        .timelimit(self.search_time_limit_seconds),
                )
                .with_timeout(self.connect_timeout)
                // The DN is part of every LDAP search result, not a regular
                // attribute. Request only the configured canonical identity
                // attribute; `SearchEntry::dn` still carries the bind target.
                .search(
                    search_base,
                    Scope::Subtree,
                    &filter,
                    vec![canonical_identity_attribute],
                )
                .await
                .map_err(|e| AuthError::Backend(format!("ldap_auth: user search failed: {e}")))?;

            if search_result.1.rc == 4 && search_result.0.len() >= 2 {
                return Err(AuthError::Credential(
                    "ldap_auth: user search was ambiguous".to_string(),
                ));
            }

            let (rs, _result) = search_result
                .success()
                .map_err(|e| AuthError::Backend(format!("ldap_auth: user search error: {e}")))?;

            let result_entry = match rs.len() {
                0 => {
                    return Err(AuthError::Credential(
                        "ldap_auth: user not found".to_string(),
                    ));
                }
                1 => rs.into_iter().next().ok_or_else(|| {
                    AuthError::Backend(
                        "ldap_auth: user result disappeared after uniqueness check".to_string(),
                    )
                })?,
                _ => {
                    return Err(AuthError::Credential(
                        "ldap_auth: user search was ambiguous".to_string(),
                    ));
                }
            };
            let entry = SearchEntry::construct(result_entry);
            let canonical_identity = unique_ldap_attribute_value(
                &entry.attrs,
                canonical_identity_attribute,
                "canonical identity",
            )?
            .ok_or_else(|| {
                AuthError::Backend(format!(
                    "ldap_auth: user search result is missing canonical identity attribute '{canonical_identity_attribute}'"
                ))
            })?;
            let user_dn = entry.dn;

            // Unbind the service account, re-connect and bind as the user
            let _ = ldap.with_timeout(self.connect_timeout).unbind().await;

            let mut user_ldap = self.connect().await?;
            let user_bind_result = user_ldap
                .with_timeout(self.connect_timeout)
                .simple_bind(&user_dn, password)
                .await
                .map_err(|e| AuthError::Backend(format!("ldap_auth: user bind failed: {e}")))?;
            classify_user_bind_result(user_bind_result, "user bind")?;

            let _ = user_ldap.with_timeout(self.connect_timeout).unbind().await;
            AuthenticatedUser {
                dn: user_dn,
                canonical_identity,
            }
        };

        Ok(authenticated_user)
    }

    /// Read the configured canonical identity attribute off an already
    /// authenticated entry with a base-scope search on that entry's own DN.
    ///
    /// Used by direct bind, where the presented login never becomes the Ferrum
    /// identity. Failures are [`AuthError::Backend`]: the credentials were
    /// already accepted, so an unreadable or ambiguous canonical value is a
    /// directory/configuration problem, and the flow fails closed rather than
    /// falling back to the client-supplied string.
    async fn read_canonical_identity(
        &self,
        ldap: &mut Ldap,
        entry_dn: &str,
    ) -> Result<String, AuthError> {
        let Some(attribute) = self.canonical_identity_attribute.as_deref() else {
            return Err(AuthError::Backend(
                "ldap_auth: canonical identity attribute is missing in direct-bind mode"
                    .to_string(),
            ));
        };

        let (entries, _result) = ldap
            .with_search_options(
                SearchOptions::new()
                    .sizelimit(LDAP_AUTH_USER_SEARCH_SIZE_LIMIT)
                    .timelimit(self.search_time_limit_seconds),
            )
            .with_timeout(self.connect_timeout)
            .search(entry_dn, Scope::Base, "(objectClass=*)", vec![attribute])
            .await
            .map_err(|e| {
                AuthError::Backend(format!("ldap_auth: canonical identity search failed: {e}"))
            })?
            .success()
            .map_err(|e| {
                AuthError::Backend(format!("ldap_auth: canonical identity search error: {e}"))
            })?;

        let result_entry = match entries.len() {
            0 => {
                return Err(AuthError::Backend(
                    "ldap_auth: the bound entry returned no canonical identity result".to_string(),
                ));
            }
            1 => entries.into_iter().next().ok_or_else(|| {
                AuthError::Backend(
                    "ldap_auth: canonical identity entry disappeared after uniqueness check"
                        .to_string(),
                )
            })?,
            _ => {
                return Err(AuthError::Backend(
                    "ldap_auth: base-scope canonical identity search returned multiple entries"
                        .to_string(),
                ));
            }
        };

        let entry = SearchEntry::construct(result_entry);
        let canonical_identity =
            unique_ldap_attribute_value(&entry.attrs, attribute, "canonical identity")?;
        canonical_identity.ok_or_else(|| {
            AuthError::Backend(format!(
                "ldap_auth: the bound entry is missing canonical identity attribute '{attribute}'"
            ))
        })
    }

    /// Check if the authenticated user belongs to at least one of the required groups.
    ///
    /// All failures here (connect, group-check bind, search RPC) are
    /// backend/infrastructure problems, surfaced as [`AuthError::Backend`] →
    /// 500. A successful search that simply matches no group is `Ok(false)`
    /// (the user is genuinely not entitled → 403).
    async fn check_group_membership(
        &self,
        user_dn: &str,
        canonical_identity: &str,
    ) -> Result<bool, AuthError> {
        if self.required_groups.is_empty() {
            return Ok(true);
        }

        let group_base = self.group_base_dn.as_deref().unwrap_or_default();

        let filter = self.group_search_filter(user_dn, canonical_identity);

        // Bind with the service account when one is configured; otherwise the
        // group search runs over an ANONYMOUS-bound connection. Many directories
        // deny or restrict anonymous reads of group `member` attributes, in
        // which case the search returns zero entries and a legitimately
        // entitled user is wrongly denied (403). Operators are warned at
        // startup (see `new()`) when group enforcement relies on anonymous
        // search; finding #33.
        let mut ldap = self.connect().await?;
        let used_service_account = if let (Some(dn), Some(pw)) =
            (&self.service_account_dn, &self.service_account_password)
        {
            ldap.with_timeout(self.connect_timeout)
                .simple_bind(dn, pw)
                .await
                .map_err(|e| {
                    AuthError::Backend(format!("ldap_auth: group check bind failed: {e}"))
                })?
                .success()
                .map_err(|e| {
                    AuthError::Backend(format!("ldap_auth: group check bind rejected: {e}"))
                })?;
            true
        } else {
            false
        };

        let search_result = ldap
            .with_search_options(
                SearchOptions::new()
                    .sizelimit(LDAP_AUTH_GROUP_SEARCH_SIZE_LIMIT)
                    .timelimit(self.search_time_limit_seconds),
            )
            .with_timeout(self.connect_timeout)
            .search(
                group_base,
                Scope::Subtree,
                &filter,
                vec![self.group_attribute.as_str()],
            )
            .await
            .map_err(|e| AuthError::Backend(format!("ldap_auth: group search failed: {e}")))?;

        let result_code = search_result.1.rc;
        if result_code != 0 && result_code != 4 {
            let _ = ldap.with_timeout(self.connect_timeout).unbind().await;
            return Err(AuthError::Backend(format!(
                "ldap_auth: group search error: {}",
                search_result.1
            )));
        }
        let size_limit_exceeded = result_code == 4;
        let rs = search_result.0;

        // A zero-entry result is ambiguous: the user may genuinely belong to no
        // group, OR the directory may have silently returned nothing because an
        // anonymous (no service account) search of group objects is restricted
        // by directory ACLs. Surface that distinction so operators can tell an
        // entitlement denial from a misconfigured search permission (finding #33).
        if rs.is_empty() && !used_service_account {
            warn!(
                "ldap_auth: group search for user '{}' under '{}' returned no entries over an \
                 anonymous bind; this is either a genuine no-membership result or the directory \
                 restricts anonymous reads of group objects — configure 'service_account_dn'/\
                 'service_account_password' if groups are not being matched",
                canonical_identity, group_base
            );
        }

        let mut membership_result = Ok(false);
        for result_entry in rs {
            let entry = SearchEntry::construct(result_entry);
            let is_required_group = match self.entry_matches_required_group(&entry) {
                Ok(is_match) => is_match,
                Err(error) => {
                    membership_result = Err(error);
                    break;
                }
            };
            if !is_required_group {
                continue;
            }

            // The built-in filter itself is the membership proof. A custom
            // filter may contain static branches that also return this group,
            // so re-check the exact returned entry with a server-side,
            // schema-aware membership predicate before authorizing it.
            if self.group_filter.is_none() {
                membership_result = Ok(true);
                break;
            }
            match self
                .returned_group_proves_membership(&mut ldap, &entry.dn, user_dn, canonical_identity)
                .await
            {
                Ok(true) => {
                    membership_result = Ok(true);
                    break;
                }
                Ok(false) => {}
                Err(error) => {
                    membership_result = Err(error);
                    break;
                }
            }
        }

        let _ = ldap.with_timeout(self.connect_timeout).unbind().await;
        if membership_result? {
            return Ok(true);
        }

        if size_limit_exceeded {
            return Err(AuthError::Backend(
                "ldap_auth: group search exceeded the configured size limit before proving required membership"
                    .to_string(),
            ));
        }

        Ok(false)
    }

    fn group_search_filter(&self, user_dn: &str, canonical_identity: &str) -> String {
        // Group authorization must use the authenticated account identity, not
        // the client-presented login value, which may be an alias or a
        // case/whitespace variant of the directory entry's own attribute.
        match self.group_filter.as_ref() {
            Some(filter) => {
                let mut resolved_filter = filter.clone();
                if filter.contains("{user_dn}") {
                    let escaped_user_dn = escape_filter_value(user_dn);
                    resolved_filter = resolved_filter.replace("{user_dn}", &escaped_user_dn);
                }
                if filter.contains("{username}") {
                    let escaped_identity = escape_filter_value(canonical_identity);
                    resolved_filter = resolved_filter.replace("{username}", &escaped_identity);
                }
                resolved_filter
            }
            None => group_membership_filter(user_dn, canonical_identity),
        }
    }

    fn entry_matches_required_group(&self, entry: &SearchEntry) -> Result<bool, AuthError> {
        if let Some(group_names) =
            ldap_attribute_values(&entry.attrs, &self.group_attribute, "group")?
            && group_names
                .iter()
                .any(|name| self.required_group_lookup.contains(&name.to_lowercase()))
        {
            return Ok(true);
        }

        // Fall back to the entry's OWN relative distinguished name when the
        // directory did not return the group-name attribute. Only the first
        // RDN may name the entry: scanning the whole DN for a `cn=` component
        // would let `uid=visitors,cn=admins,ou=groups,...` — an entry merely
        // nested UNDER a required group — satisfy the `admins` gate, and a
        // naive comma split would do the same for an RDN whose value contains
        // an escaped comma (`ou=visitors\,cn=admins,...`). Whoever can create
        // or name entries under `group_base_dn` would otherwise mint gateway
        // group membership without touching the real group object.
        let Some(rdn) = parse_first_rdn(&entry.dn) else {
            return Ok(false);
        };
        // The fallback stands in for the missing attribute, so the RDN must be
        // typed with that attribute (or `cn`, the conventional group naming
        // attribute this fallback has always accepted).
        let group_attribute = self.group_attribute.as_str();
        for ava in &rdn {
            let attribute = ava.attribute_type.as_str();
            if !attribute.eq_ignore_ascii_case(group_attribute)
                && !attribute.eq_ignore_ascii_case("cn")
            {
                continue;
            }
            let value = ava.value.to_lowercase();
            if self.required_group_lookup.contains(&value) {
                return Ok(true);
            }
        }
        Ok(false)
    }

    async fn returned_group_proves_membership(
        &self,
        ldap: &mut Ldap,
        group_dn: &str,
        user_dn: &str,
        canonical_identity: &str,
    ) -> Result<bool, AuthError> {
        let membership_filter = group_membership_filter(user_dn, canonical_identity);
        let (entries, _result) = ldap
            .with_search_options(
                SearchOptions::new()
                    .sizelimit(1)
                    .timelimit(self.search_time_limit_seconds),
            )
            .with_timeout(self.connect_timeout)
            .search(group_dn, Scope::Base, &membership_filter, vec!["1.1"])
            .await
            .map_err(|e| {
                AuthError::Backend(format!(
                    "ldap_auth: returned group membership verification failed: {e}"
                ))
            })?
            .success()
            .map_err(|e| {
                AuthError::Backend(format!(
                    "ldap_auth: returned group membership verification error: {e}"
                ))
            })?;

        match entries.len() {
            0 => Ok(false),
            1 => Ok(true),
            _ => Err(AuthError::Backend(
                "ldap_auth: base-scope group membership verification returned multiple entries"
                    .to_string(),
            )),
        }
    }
}

fn group_membership_filter(user_dn: &str, canonical_identity: &str) -> String {
    let escaped_user_dn = escape_filter_value(user_dn);
    let escaped_identity = escape_filter_value(canonical_identity);
    format!(
        "(|(member={escaped_user_dn})(uniqueMember={escaped_user_dn})(memberUid={escaped_identity}))"
    )
}

fn ldap_attribute_values<'a>(
    attrs: &'a HashMap<String, Vec<String>>,
    attribute: &str,
    purpose: &str,
) -> Result<Option<&'a Vec<String>>, AuthError> {
    let mut match_values = None;
    for (name, values) in attrs {
        if name.eq_ignore_ascii_case(attribute) {
            if match_values.is_some() {
                return Err(AuthError::Backend(format!(
                    "ldap_auth: directory returned duplicate case-variant {purpose} attributes for '{attribute}'"
                )));
            }
            match_values = Some(values);
        }
    }
    Ok(match_values)
}

fn unique_ldap_attribute_value(
    attrs: &HashMap<String, Vec<String>>,
    attribute: &str,
    purpose: &str,
) -> Result<Option<String>, AuthError> {
    let Some(values) = ldap_attribute_values(attrs, attribute, purpose)? else {
        return Ok(None);
    };
    if values.len() != 1 {
        return Err(AuthError::Backend(format!(
            "ldap_auth: directory must return exactly one {purpose} value for '{attribute}'"
        )));
    }
    let Some(value) = values.first() else {
        return Err(AuthError::Backend(format!(
            "ldap_auth: directory returned no {purpose} value for '{attribute}'"
        )));
    };
    let value = value.trim();
    if value.is_empty() {
        return Err(AuthError::Backend(format!(
            "ldap_auth: directory returned an empty {purpose} value for '{attribute}'"
        )));
    }
    Ok(Some(value.to_string()))
}

fn reject_unknown_config_keys(config: &Map<String, Value>) -> Result<(), String> {
    const KNOWN_KEYS: [&str; 20] = [
        "ldap_url",
        "bind_dn_template",
        "search_base_dn",
        "search_filter",
        "canonical_identity_attribute",
        "service_account_dn",
        "service_account_password",
        "group_base_dn",
        "group_filter",
        "required_groups",
        "group_attribute",
        "starttls",
        "allow_plaintext",
        "connect_timeout_seconds",
        "request_timeout_seconds",
        "max_concurrent_requests",
        "cache_ttl_seconds",
        "max_cache_entries",
        "consumer_mapping",
        "hide_credentials",
    ];
    for key in config.keys() {
        if !KNOWN_KEYS.contains(&key.as_str()) {
            return Err(format!("ldap_auth: unknown config key '{key}'"));
        }
    }
    Ok(())
}

fn parse_required_ldap_url(config: &Map<String, Value>) -> Result<&str, String> {
    let Some(value) = config.get("ldap_url") else {
        return Err(
            "ldap_auth: 'ldap_url' is required (e.g. \"ldap://ldap.example.com:389\" or \"ldaps://ldap.example.com:636\")"
                .to_string(),
        );
    };
    let raw = value
        .as_str()
        .ok_or_else(|| format!("ldap_auth: 'ldap_url' must be a string, got: {value}"))?;
    if raw.is_empty() {
        return Err("ldap_auth: 'ldap_url' must not be empty".to_string());
    }
    // Trimming here would admit a padded value that `openapi.yaml` rejects and
    // that no directory URL legitimately carries.
    if raw.trim() != raw {
        return Err(
            "ldap_auth: 'ldap_url' must not have leading or trailing whitespace".to_string(),
        );
    }
    Ok(raw)
}

fn is_loopback_ldap_endpoint(parsed: &Url) -> bool {
    match parsed.host() {
        Some(Host::Ipv4(address)) => address.is_loopback(),
        Some(Host::Ipv6(address)) => address.is_loopback(),
        Some(Host::Domain(hostname)) => {
            let hostname = hostname.trim_end_matches('.');
            hostname
                .parse::<std::net::IpAddr>()
                .is_ok_and(|address| address.is_loopback())
                || hostname.eq_ignore_ascii_case("localhost")
                || hostname.to_ascii_lowercase().ends_with(".localhost")
        }
        None => false,
    }
}

fn ldap_url_hostname(parsed: &Url) -> Result<String, String> {
    let host = parsed
        .host()
        .ok_or_else(|| "ldap_auth: 'ldap_url' must include a hostname".to_string())?;

    Ok(match host {
        Host::Domain(hostname) => hostname.to_string(),
        Host::Ipv4(address) => address.to_string(),
        Host::Ipv6(address) => address.to_string(),
    })
}

fn has_non_empty_authority(ldap_url: &str) -> bool {
    let Some((_, after_scheme)) = ldap_url.split_once(':') else {
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

fn parse_optional_string(
    config: &Map<String, Value>,
    field: &str,
) -> Result<Option<String>, String> {
    let Some(value) = config.get(field) else {
        return Ok(None);
    };
    let raw = value
        .as_str()
        .ok_or_else(|| format!("ldap_auth: '{field}' must be a string, got: {value}"))?;
    let value = raw.trim();
    if value.is_empty() {
        return Err(format!("ldap_auth: '{field}' must not be empty"));
    }
    Ok(Some(value.to_string()))
}

/// Parse a secret config value VERBATIM.
///
/// A password is an opaque string the directory compares byte for byte, so it
/// is never trimmed the way [`parse_optional_string`] trims identifiers:
/// silently dropping surrounding whitespace would make a legitimate secret
/// fail every service-account bind and surface as a directory outage (`500`)
/// rather than as a configuration error. Only a genuinely empty value is
/// rejected — an empty simple-bind password requests an anonymous bind.
fn parse_optional_secret_string(
    config: &Map<String, Value>,
    field: &str,
) -> Result<Option<String>, String> {
    let Some(value) = config.get(field) else {
        return Ok(None);
    };
    let raw = value
        .as_str()
        .ok_or_else(|| format!("ldap_auth: '{field}' must be a string"))?;
    if raw.is_empty() {
        return Err(format!("ldap_auth: '{field}' must not be empty"));
    }
    Ok(Some(raw.to_string()))
}

fn parse_bool(
    config: &Map<String, Value>,
    field: &str,
    default_value: bool,
) -> Result<bool, String> {
    let Some(value) = config.get(field) else {
        return Ok(default_value);
    };
    value
        .as_bool()
        .ok_or_else(|| format!("ldap_auth: '{field}' must be a boolean, got: {value}"))
}

fn parse_u64(config: &Map<String, Value>, field: &str, default_value: u64) -> Result<u64, String> {
    let Some(value) = config.get(field) else {
        return Ok(default_value);
    };
    value
        .as_u64()
        .ok_or_else(|| format!("ldap_auth: '{field}' must be an unsigned integer, got: {value}"))
}

fn parse_usize(
    config: &Map<String, Value>,
    field: &str,
    default_value: usize,
) -> Result<usize, String> {
    let raw = parse_u64(config, field, default_value as u64)?;
    usize::try_from(raw).map_err(|_| format!("ldap_auth: '{field}' is too large"))
}

fn parse_string_array(config: &Map<String, Value>, field: &str) -> Result<Vec<String>, String> {
    let Some(value) = config.get(field) else {
        return Ok(Vec::new());
    };
    let arr = value
        .as_array()
        .ok_or_else(|| format!("ldap_auth: '{field}' must be an array of strings, got: {value}"))?;
    arr.iter()
        .map(|item| {
            let raw = item.as_str().ok_or_else(|| {
                format!("ldap_auth: '{field}' entries must be strings, got: {item}")
            })?;
            let value = raw.trim();
            if value.is_empty() {
                return Err(format!("ldap_auth: '{field}' entries must not be empty"));
            }
            Ok(value.to_string())
        })
        .collect()
}

/// Build a rustls `ClientConfig` for LDAP connections.
///
/// Integrates with gateway TLS settings while honouring the project-wide
/// "CA exclusivity" rule (CLAUDE.md "TLS Architecture"):
///
/// - `FERRUM_TLS_CA_BUNDLE_PATH` set: builds the trust store from
///   `RootCertStore::empty()` and adds ONLY the PEM certs from this bundle.
///   The system / webpki public-CA roots are NOT trusted, so a
///   public-CA-issued certificate cannot MITM the LDAP connection — the same
///   guarantee the proxy backend paths and `PluginHttpClient` provide.
///
/// - `FERRUM_TLS_CA_BUNDLE_PATH` unset: falls back to webpki bundled roots.
///   This matches the proxy backend paths' webpki fallback (rather than
///   `rustls-platform-verifier`) so behaviour is consistent across all
///   gateway TLS surfaces on Linux containers.
///
/// - `FERRUM_TLS_NO_VERIFY` set: installs the shared [`crate::tls::NoVerifier`]
///   custom certificate verifier (mirroring the proxy backend / WebSocket /
///   gRPC paths) which accepts every cert presented.
///
/// CRL: when `FERRUM_TLS_NO_VERIFY` is not set, the verifier is built via
/// [`crate::tls::build_server_verifier_with_crls()`] with the gateway's parsed
/// CRL list (`crls`, sourced from `PluginHttpClient::tls_crls()`). Revoked LDAP
/// server certificates are rejected, matching the proxy backend / DTLS /
/// frontend mTLS / rustls logging-sink surfaces. An empty `crls` slice yields a
/// plain WebPki verifier (no behavioural change vs. the previous root-store
/// verifier).
fn build_ldap_tls_config(
    no_verify: bool,
    ca_bundle_path: Option<&str>,
    crls: &[CertificateRevocationListDer<'static>],
) -> Result<Arc<ClientConfig>, String> {
    // ldap3's `tls-rustls-ring` feature forwards `rustls/ring`, which selects
    // the ring crypto provider for TLS primitives but DOES NOT install it as
    // the rustls global default. Anywhere we hand a `ClientConfig` to ldap3
    // we therefore have to construct it via `with_provider(ring)` so the
    // builder doesn't fall back to the (uninstalled) global default and
    // panic at first use. The gateway's own startup installs ring at
    // `main.rs::install_default()`, but that only matters for code paths
    // that go through the global accessor — `ClientConfig::builder()`
    // without `with_provider()` would also work in production but breaks
    // unit tests that exercise `LdapAuth::new()` before `install_default()`
    // has run. Always supplying the provider explicitly avoids that ordering
    // hazard.
    let provider = Arc::new(crate::fips::base_crypto_provider());
    let builder = ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .map_err(|e| format!("ldap_auth: failed to build rustls client config: {e}"))?;

    // An explicit CA remains a configuration requirement when verification is
    // disabled. Materialize it before branching so no-verify cannot hide a
    // malformed, empty, or unusable custom trust store.
    let custom_root_store = ca_bundle_path
        .map(|ca_path| build_ldap_root_store(Some(ca_path)))
        .transpose()?;

    let config = if no_verify {
        warn!("ldap_auth: TLS certificate verification DISABLED (FERRUM_TLS_NO_VERIFY=true)");
        builder
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(crate::tls::NoVerifier))
            .with_no_client_auth()
    } else {
        // Build a WebPki verifier from the (CA-exclusive) trust store and apply
        // the gateway's parsed CRL list so revoked LDAP server certificates are
        // rejected, matching the proxy backend / DTLS / frontend mTLS / rustls
        // logging-sink surfaces (finding #84). When no CRL is configured this is
        // equivalent to the default root-store verifier. The shared
        // `tls::crl_policy` applied inside `build_server_verifier_with_crls`
        // retains unknown-status tolerance, so certs from CAs without a matching
        // CRL are still accepted.
        let root_store = custom_root_store.unwrap_or_else(|| {
            rustls::RootCertStore::from_iter(webpki_roots::TLS_SERVER_ROOTS.iter().cloned())
        });
        let verifier = crate::tls::build_server_verifier_with_crls(root_store, crls)
            .map_err(|e| format!("ldap_auth: failed to build TLS verifier: {e}"))?;
        builder.with_webpki_verifier(verifier).with_no_client_auth()
    };

    Ok(Arc::new(config))
}

/// Build the LDAP TLS trust store, enforcing CA exclusivity when a custom CA
/// is configured. Returns `RootCertStore::empty()` + the bundle's certs when
/// a path is supplied; otherwise webpki bundled roots.
fn build_ldap_root_store(ca_bundle_path: Option<&str>) -> Result<rustls::RootCertStore, String> {
    let Some(ca_path) = ca_bundle_path else {
        // No custom CA — fall back to webpki bundled roots, matching the
        // proxy backend path. We deliberately do NOT mix in OS roots: the
        // gateway runs server-side, the LDAP server is internal, and the
        // operator opted into "ferrum's TLS stack".
        return Ok(rustls::RootCertStore::from_iter(
            webpki_roots::TLS_SERVER_ROOTS.iter().cloned(),
        ));
    };

    let source = CertSource::parse(ca_path, MaterialKind::CaBundle);
    let ca_material = load_material_blocking(&source, MaterialKind::CaBundle)
        .map_err(|e| format!("ldap_auth: failed to load CA bundle: {e}"))?;
    let source_id = ca_material.display_source_id.clone();
    let root_store = crate::tls::root_cert_store_from_pem_bundle(
        ca_material.bytes.expose_secret(),
        "ldap_auth CA bundle",
        &source_id,
    )
    .map_err(|error| error.to_string())?;

    debug!(
        "ldap_auth: loaded {} CA certificate(s) from '{}' (CA exclusivity enforced)",
        root_store.len(),
        source_id
    );
    Ok(root_store)
}

/// Escape a string for use in an LDAP DN value (RFC 4514 §2.4).
///
/// Characters that have special meaning in a DN — `,`, `+`, `"`, `\`, `<`, `>`, `;`
/// — are backslash-escaped. Leading/trailing spaces and a leading `#` are also escaped.
pub fn escape_dn_value(input: &str) -> String {
    let mut out = String::with_capacity(input.len() + 8);
    // `input.len()` is a *byte* length but `enumerate()` yields a *character*
    // index. For inputs containing multi-byte UTF-8 characters they disagree
    // and `i == input.len() - 1` never matches the actual last character, so
    // the trailing-space escape silently never fires. Compare against the
    // character count instead.
    let total_chars = input.chars().count();
    for (i, ch) in input.chars().enumerate() {
        let is_last = i + 1 == total_chars;
        let needs_escape = matches!(ch, ',' | '+' | '"' | '\\' | '<' | '>' | ';')
            || (i == 0 && (ch == ' ' || ch == '#'))
            || (is_last && ch == ' ');
        if needs_escape {
            out.push('\\');
        }
        out.push(ch);
    }
    out
}

/// Substitutes used to syntax-check a configured filter template at admission.
///
/// Both are ordinary RFC 4515 assertion values built from characters that need
/// no escaping, so a template that parses with them substituted also parses
/// with the escaped runtime value in their place.
const LDAP_FILTER_VALIDATION_USERNAME: &str = "ferrumfiltervalidation";
const LDAP_FILTER_VALIDATION_USER_DN: &str = "cn=ferrumfiltervalidation,ou=users,dc=example,dc=com";

/// Reject a configured filter template that is not a well-formed RFC 4515
/// search filter.
///
/// `ldap_auth` fails closed, so a malformed filter such as `(uid={username}`
/// would otherwise pass `validate`, the admin API, and startup, and then turn
/// every request on the route into a `500` once the directory rejects the
/// filter. `ldap3::parse_filter` is the same grammar `ldap3` applies to the
/// filter this plugin sends, so admitting here means the wire filter is
/// well-formed.
fn validate_ldap_filter_syntax(filter: &str, field: &str) -> Result<(), String> {
    let resolved = filter
        .replace("{username}", LDAP_FILTER_VALIDATION_USERNAME)
        .replace("{user_dn}", LDAP_FILTER_VALIDATION_USER_DN);
    if parse_filter(&resolved).is_err() {
        return Err(format!(
            "ldap_auth: '{field}' is not a valid RFC 4515 LDAP search filter"
        ));
    }
    Ok(())
}

/// Escape a string for use in an LDAP search filter value (RFC 4515 §3).
///
/// The five characters `*`, `(`, `)`, `\`, and NUL are hex-escaped as `\xx`.
/// All other characters — including multi-byte UTF-8 — are passed through
/// unchanged. Iterate over `char`s (not bytes): a byte loop with `byte as char`
/// would re-encode each UTF-8 continuation byte as its own code point,
/// corrupting non-ASCII values so the directory search never matches the entry.
/// The five escaped characters are all single-byte ASCII, so injection
/// protection is unaffected.
pub fn escape_filter_value(input: &str) -> String {
    let mut out = String::with_capacity(input.len() + 8);
    for ch in input.chars() {
        match ch {
            '*' => out.push_str("\\2a"),
            '(' => out.push_str("\\28"),
            ')' => out.push_str("\\29"),
            '\\' => out.push_str("\\5c"),
            '\0' => out.push_str("\\00"),
            _ => out.push(ch),
        }
    }
    out
}

/// RFC 4514 `special` characters plus `ESC` itself: the set a lone backslash
/// may escape without a following hex pair.
const DN_ESCAPABLE_SPECIALS: [char; 10] = ['\\', '"', '+', ',', ';', '<', '>', ' ', '#', '='];

/// One attribute type / value pair of a relative distinguished name.
struct RdnAttributeValue {
    attribute_type: String,
    value: String,
}

/// Parse the leading relative distinguished name of `dn` per RFC 4514.
///
/// Returns every attribute/value pair of the FIRST RDN only (a multi-valued
/// RDN such as `cn=admins+ou=eng` yields two), honoring `\`-escaped separators
/// and `\XX` hex escapes so a value containing a comma or plus cannot be split
/// into a different DN shape. Returns `None` — never a partial guess — for any
/// DN this parser cannot represent as text, including the RFC 4514 `#`
/// hex-encoded BER value form, so callers fail closed.
fn parse_first_rdn(dn: &str) -> Option<Vec<RdnAttributeValue>> {
    let mut pairs = Vec::new();
    let mut current = String::new();
    let mut escaped = false;
    for ch in dn.chars() {
        if escaped {
            current.push('\\');
            current.push(ch);
            escaped = false;
            continue;
        }
        match ch {
            '\\' => escaped = true,
            // RFC 4514 separates RDNs with ','; RFC 2253 also allowed ';'.
            // Either one ends the entry's own RDN.
            ',' | ';' => break,
            '+' => pairs.push(std::mem::take(&mut current)),
            _ => current.push(ch),
        }
    }
    if escaped {
        // Trailing lone escape: the DN is malformed.
        return None;
    }
    pairs.push(current);

    let mut parsed = Vec::with_capacity(pairs.len());
    for pair in pairs {
        parsed.push(parse_rdn_pair(&pair)?);
    }
    Some(parsed)
}

/// Split one `type=value` pair of an RDN at its first unescaped `=`.
fn parse_rdn_pair(pair: &str) -> Option<RdnAttributeValue> {
    let mut escaped = false;
    let mut separator = None;
    for (index, ch) in pair.char_indices() {
        if escaped {
            escaped = false;
            continue;
        }
        match ch {
            '\\' => escaped = true,
            '=' => {
                separator = Some(index);
                break;
            }
            _ => {}
        }
    }
    let separator = separator?;
    let attribute_type = pair[..separator].trim();
    if attribute_type.is_empty() {
        return None;
    }
    Some(RdnAttributeValue {
        attribute_type: attribute_type.to_string(),
        value: unescape_rdn_value(&pair[separator + 1..])?,
    })
}

/// Decode the RFC 4514 escaping of an RDN attribute value.
///
/// Unescaped leading and trailing spaces are layout, not value; escaped ones
/// (`\ ` or `\20`) belong to the value and are preserved.
fn unescape_rdn_value(raw: &str) -> Option<String> {
    if raw.trim_start().starts_with('#') {
        // Hex-encoded BER value: not comparable as text.
        return None;
    }
    // Each decoded byte is tagged with whether an escape produced it, so
    // trimming cannot drop a deliberately escaped space.
    let mut decoded: Vec<(u8, bool)> = Vec::with_capacity(raw.len());
    let mut chars = raw.chars();
    while let Some(ch) = chars.next() {
        if ch != '\\' {
            let mut buffer = [0u8; 4];
            for byte in ch.encode_utf8(&mut buffer).bytes() {
                decoded.push((byte, false));
            }
            continue;
        }
        // RFC 4514 `pair = ESC ( ESC / special / hexpair )`. No `special` is a
        // hex digit, so a hex digit here always begins a hex pair.
        let escaped = chars.next()?;
        match escaped.to_digit(16) {
            Some(high) => {
                let low = chars.next()?.to_digit(16)?;
                decoded.push((u8::try_from(high * 16 + low).ok()?, true));
            }
            None => {
                if !DN_ESCAPABLE_SPECIALS.contains(&escaped) {
                    return None;
                }
                decoded.push((u8::try_from(escaped).ok()?, true));
            }
        }
    }

    let mut start = 0;
    while start < decoded.len() && decoded[start] == (b' ', false) {
        start += 1;
    }
    let mut end = decoded.len();
    while end > start && decoded[end - 1] == (b' ', false) {
        end -= 1;
    }
    let mut bytes = Vec::with_capacity(end - start);
    for (byte, _) in &decoded[start..end] {
        bytes.push(*byte);
    }
    String::from_utf8(bytes).ok()
}

#[async_trait]
impl AuthMechanism for LdapAuth {
    fn mechanism_name(&self) -> &'static str {
        "ldap_auth"
    }

    /// `ldap_auth` consumes RFC 7617 `Authorization: Basic` credentials, so an
    /// unauthenticated request must be answered with the `Basic` challenge
    /// (RFC 9110 section 11.6.1) — clients that drive Basic authentication off
    /// the challenge never prompt for credentials otherwise. Same value as
    /// `basic_auth`.
    fn authentication_challenge(&self) -> Option<&'static str> {
        Some(LDAP_AUTH_BASIC_CHALLENGE)
    }

    fn extract(&self, ctx: &RequestContext) -> ExtractedCredential {
        // Same contract as `basic_auth`: Basic credentials are base64 (visible
        // ASCII). A present but non-materialized `Authorization` line is invalid,
        // not missing.
        let auth_header = match lookup_configured_header(ctx, "authorization", None) {
            ConfiguredHeaderLookup::Absent => return ExtractedCredential::Missing,
            ConfiguredHeaderLookup::PresentNonMaterialized => {
                return ExtractedCredential::InvalidFormat(
                    r#"{"error":"Invalid Authorization header"}"#.into(),
                );
            }
            ConfiguredHeaderLookup::Value(header) => header,
        };

        let encoded = match strip_auth_scheme(&auth_header, "Basic") {
            Some(encoded) => encoded,
            None => {
                return ExtractedCredential::InvalidFormat(
                    r#"{"error":"Invalid Basic auth format"}"#.into(),
                );
            }
        };

        let decoded = match base64::engine::general_purpose::STANDARD.decode(encoded) {
            Ok(decoded) => decoded,
            Err(_) => {
                return ExtractedCredential::InvalidFormat(
                    r#"{"error":"Invalid base64 in Basic auth"}"#.into(),
                );
            }
        };

        let credential_str = match String::from_utf8(decoded) {
            Ok(credentials) => credentials,
            Err(_) => {
                return ExtractedCredential::InvalidFormat(
                    r#"{"error":"Invalid UTF-8 in Basic auth"}"#.into(),
                );
            }
        };

        let Some((username, password)) = credential_str.split_once(':') else {
            return ExtractedCredential::InvalidFormat(
                r#"{"error":"Invalid Basic auth format"}"#.into(),
            );
        };

        if username.is_empty() {
            return ExtractedCredential::InvalidFormat(
                r#"{"error":"Username must not be empty"}"#.into(),
            );
        }

        if password.is_empty() {
            return ExtractedCredential::InvalidFormat(
                r#"{"error":"Password must not be empty"}"#.into(),
            );
        }

        ExtractedCredential::BasicAuth {
            username: username.to_string(),
            password: password.to_string(),
        }
    }

    async fn verify(
        &self,
        credential: ExtractedCredential,
        consumer_index: &ConsumerIndex,
    ) -> VerifyOutcome {
        let ExtractedCredential::BasicAuth { username, password } = credential else {
            return VerifyOutcome::NotApplicable;
        };
        let password = Zeroizing::new(password);

        // Check cache first
        if let Some(canonical_identity) = self.check_cache(&username, &password) {
            debug!("ldap_auth: cache hit for user '{}'", username);
            return self.identity_outcome(&canonical_identity, consumer_index);
        }

        let _permit = match self.ldap_concurrency.try_acquire() {
            Ok(permit) => permit,
            Err(_) => {
                warn!("ldap_auth: maximum concurrent authentication work reached");
                return VerifyOutcome::Internal(
                    r#"{"error":"LDAP authentication temporarily unavailable"}"#.into(),
                );
            }
        };

        match tokio::time::timeout(
            self.request_timeout,
            self.verify_uncached(&username, &password, consumer_index),
        )
        .await
        {
            Ok(outcome) => outcome,
            Err(_) => {
                warn!("ldap_auth: authentication exceeded the configured wall-clock deadline");
                VerifyOutcome::Internal(
                    r#"{"error":"LDAP authentication temporarily unavailable"}"#.into(),
                )
            }
        }
    }
}

auth_flow::impl_auth_plugin!(
    LdapAuth,
    "ldap_auth",
    super::priority::LDAP_AUTH,
    crate::plugins::HTTP_FAMILY_PROTOCOLS,
    auth_flow::run_auth_external_identity;
    fn warmup_hostnames(&self) -> Vec<String> {
        vec![self.ldap_hostname.clone()]
    }

    fn request_headers_to_redact(&self) -> &[String] {
        &self.request_headers_to_redact
    }

    fn modifies_request_headers(&self) -> bool {
        self.hide_credentials
    }

    async fn before_proxy(
        &self,
        _ctx: &mut crate::plugins::RequestContext,
        headers: &mut std::collections::HashMap<String, String>,
    ) -> crate::plugins::PluginResult {
        if self.hide_credentials {
            // Removal is unconditional at this point, so a chain where another
            // mechanism authenticated the request still cannot leak the Basic
            // password upstream. Only the `Basic` scheme this plugin consumes
            // is removed: an `Authorization` header carrying another scheme
            // belongs to a different policy and must reach the backend intact.
            headers.retain(|name, value| {
                let is_basic_credential = name.eq_ignore_ascii_case("authorization")
                    && crate::plugins::strip_auth_scheme(value, "Basic").is_some();
                !is_basic_credential
            });
        }
        crate::plugins::PluginResult::Continue
    }
);

impl LdapAuth {
    async fn verify_uncached(
        &self,
        presented_username: &str,
        password: &str,
        consumer_index: &ConsumerIndex,
    ) -> VerifyOutcome {
        // Authenticate against LDAP. Distinguish a genuine credential failure
        // (401) from a backend/config failure (500); see finding #32. The
        // client always receives a generic message — the specific cause is only
        // logged via `warn!`.
        let authenticated_user = match self.authenticate_user(presented_username, password).await {
            Ok(user) => user,
            Err(AuthError::Credential(e)) => {
                warn!("{}", e);
                return VerifyOutcome::Invalid(r#"{"error":"LDAP authentication failed"}"#.into());
            }
            Err(AuthError::Backend(e)) => {
                warn!("{}", e);
                return VerifyOutcome::Internal(
                    r#"{"error":"LDAP authentication temporarily unavailable"}"#.into(),
                );
            }
        };

        if !self.required_groups.is_empty() {
            match self
                .check_group_membership(
                    &authenticated_user.dn,
                    &authenticated_user.canonical_identity,
                )
                .await
            {
                Ok(true) => {}
                Ok(false) => {
                    warn!(
                        "ldap_auth: user '{}' is not a member of any required group",
                        authenticated_user.canonical_identity
                    );
                    return VerifyOutcome::Forbidden(
                        r#"{"error":"User is not a member of any required group"}"#.into(),
                    );
                }
                Err(e) => {
                    warn!("{}", e.log_message());
                    return VerifyOutcome::Internal(
                        r#"{"error":"LDAP group membership check failed"}"#.into(),
                    );
                }
            }
        }

        self.set_cache(
            presented_username,
            password,
            &authenticated_user.canonical_identity,
        );

        debug!(
            "ldap_auth: authenticated canonical identity '{}'",
            authenticated_user.canonical_identity
        );
        self.identity_outcome(&authenticated_user.canonical_identity, consumer_index)
    }

    /// Build the auth result for a successfully authenticated LDAP user.
    fn identity_outcome(&self, username: &str, consumer_index: &ConsumerIndex) -> VerifyOutcome {
        let consumer = if self.consumer_mapping {
            consumer_index.find_by_identity(username)
        } else {
            None
        };

        if let Some(ref consumer) = consumer {
            debug!(
                "ldap_auth: mapped LDAP user '{}' to consumer '{}'",
                username, consumer.username
            );
        }

        VerifyOutcome::success(
            consumer,
            Some(username.to_string()),
            Some(username.to_string()),
        )
    }
}

#[cfg(test)]
mod tests {
    //! Inline tests for private TLS-config helpers. Lives here per CLAUDE.md
    //! "Test Placement": private fns are tested via inline `#[cfg(test)]`
    //! modules — they cannot be promoted to `pub` solely for external testing.

    use super::*;
    use rcgen::{BasicConstraints, CertificateParams, IsCa, Issuer, KeyPair, KeyUsagePurpose};
    use rustls::pki_types::ServerName;
    use std::io::Write;
    use std::sync::Once;
    use tempfile::NamedTempFile;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::{TcpListener, TcpStream};
    use tokio_rustls::{TlsAcceptor, TlsConnector};

    static INIT_CRYPTO: Once = Once::new();

    fn ensure_crypto_provider() {
        INIT_CRYPTO.call_once(|| {
            let _ = crate::fips::base_crypto_provider().install_default();
        });
    }

    fn must<T, E: std::fmt::Display>(result: Result<T, E>, context: &str) -> T {
        match result {
            Ok(value) => value,
            Err(error) => panic!("{context}: {error}"),
        }
    }

    fn must_some<T>(value: Option<T>, context: &str) -> T {
        match value {
            Some(value) => value,
            None => panic!("{context}"),
        }
    }

    fn cached_test_plugin(max_cache_entries: usize) -> LdapAuth {
        must(
            LdapAuth::new(
                &serde_json::json!({
                    "ldap_url": "ldap://127.0.0.1:389",
                    "bind_dn_template": "uid={username},dc=example,dc=com",
                    "canonical_identity_attribute": "uid",
                    "cache_ttl_seconds": 60,
                    "max_cache_entries": max_cache_entries
                }),
                PluginHttpClient::default(),
            ),
            "build cached LDAP plugin",
        )
    }

    #[test]
    fn raised_connect_timeout_raises_the_default_whole_flow_deadline() {
        let plugin = must(
            LdapAuth::new(
                &serde_json::json!({
                    "ldap_url": "ldap://127.0.0.1:389",
                    "bind_dn_template": "uid={username},dc=example,dc=com",
                    "canonical_identity_attribute": "uid",
                    "connect_timeout_seconds": 60
                }),
                PluginHttpClient::default(),
            ),
            "build LDAP plugin with raised operation timeout",
        );

        assert_eq!(plugin.request_timeout, Duration::from_secs(60));
    }

    #[test]
    fn group_username_placeholder_uses_the_authenticated_canonical_identity() {
        let plugin = must(
            LdapAuth::new(
                &serde_json::json!({
                    "ldap_url": "ldap://127.0.0.1:389",
                    "search_base_dn": "ou=users,dc=example,dc=com",
                    "search_filter": "(mail={username})",
                    "canonical_identity_attribute": "entryUUID",
                    "service_account_dn": "cn=admin,dc=example,dc=com",
                    "service_account_password": "service-secret",
                    "group_base_dn": "ou=groups,dc=example,dc=com",
                    "group_filter": "(memberUid={username})",
                    "required_groups": ["admins"]
                }),
                PluginHttpClient::default(),
            ),
            "build search-bind LDAP plugin",
        );

        assert_eq!(
            plugin.group_search_filter(
                "entryUUID=immutable-id,ou=users,dc=example,dc=com",
                "immutable-id",
            ),
            "(memberUid=immutable-id)"
        );
    }

    #[test]
    fn cache_key_is_random_keyed_hmac_not_bare_password_digest() {
        let first = cached_test_plugin(4);
        let second = cached_test_plugin(4);
        let first_key = must_some(first.cache_key("alice", "password"), "first cache key");
        let second_key = must_some(second.cache_key("alice", "password"), "second cache key");
        let bare_password_digest = crate::fips::approved::Sha256::digest(b"password");

        assert_ne!(first_key.0, bare_password_digest);
        assert_ne!(first_key.0, second_key.0);
    }

    #[test]
    fn saturated_cache_replaces_one_entry_and_preserves_hard_cap() {
        let plugin = cached_test_plugin(4);
        for index in 0..100 {
            let username = format!("user-{index}");
            plugin.set_cache(&username, "password", &username);
            assert!(plugin.cache.len() <= 4);
            assert!(plugin.cache_entries.load(Ordering::Acquire) <= 4);
        }

        assert_eq!(plugin.cache.len(), 4);
        assert_eq!(plugin.cache_entries.load(Ordering::Acquire), 4);
        assert_eq!(
            plugin.check_cache("user-99", "password").as_deref(),
            Some("user-99")
        );
    }

    #[test]
    fn concurrent_cache_admission_never_exceeds_hard_cap() {
        let plugin = Arc::new(cached_test_plugin(8));
        std::thread::scope(|scope| {
            for worker in 0..32 {
                let plugin = Arc::clone(&plugin);
                scope.spawn(move || {
                    for item in 0..32 {
                        let username = format!("worker-{worker}-item-{item}");
                        plugin.set_cache(&username, "password", &username);
                    }
                });
            }
        });

        assert!(plugin.cache.len() <= 8);
        assert_eq!(
            plugin.cache_entries.load(Ordering::Acquire),
            plugin.cache.len()
        );
    }

    #[test]
    fn unrepresentable_cache_expiry_is_skipped_without_panicking() {
        let mut plugin = cached_test_plugin(4);
        plugin.cache_ttl = Duration::MAX;
        plugin.set_cache("alice", "password", "alice");
        assert!(plugin.cache.is_empty());
        assert_eq!(plugin.cache_entries.load(Ordering::Acquire), 0);
    }

    #[test]
    fn case_variant_duplicate_ldap_attributes_fail_closed() {
        let attrs = HashMap::from([
            ("sAMAccountName".to_string(), vec!["admins".to_string()]),
            ("samaccountname".to_string(), vec!["guests".to_string()]),
        ]);
        let result = ldap_attribute_values(&attrs, "SAMACCOUNTNAME", "group");
        assert!(result.is_err());
    }

    struct TestCa {
        cert_pem: String,
        issuer: Issuer<'static, KeyPair>,
    }

    fn generate_test_ca(cn: &str) -> TestCa {
        let key_pair = must(
            KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256),
            "generate CA key",
        );
        let mut params = must(
            CertificateParams::new(Vec::<String>::new()),
            "build CA params",
        );
        params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        params
            .distinguished_name
            .push(rcgen::DnType::CommonName, cn);
        params.key_usages.push(KeyUsagePurpose::KeyCertSign);
        params.key_usages.push(KeyUsagePurpose::DigitalSignature);
        // `CrlSign` lets this CA also sign CRLs (required by rcgen for the CRL
        // revocation test); harmless for the CA-exclusivity tests.
        params.key_usages.push(KeyUsagePurpose::CrlSign);
        let cert = must(params.self_signed(&key_pair), "self-sign CA");
        TestCa {
            cert_pem: cert.pem(),
            issuer: Issuer::new(params, key_pair),
        }
    }

    /// Generate a leaf certificate (cert PEM + key PEM) signed by `ca` for the
    /// given SANs. Used to stand up a TLS listener in CA-exclusivity tests.
    fn generate_signed_leaf(ca: &TestCa, cn: &str, sans: &[&str]) -> (String, String) {
        let key_pair = must(
            KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256),
            "generate leaf key",
        );
        let mut params = must(
            CertificateParams::new(sans.iter().map(|s| s.to_string()).collect::<Vec<_>>()),
            "build leaf params",
        );
        params
            .distinguished_name
            .push(rcgen::DnType::CommonName, cn);
        let cert = must(params.signed_by(&key_pair, &ca.issuer), "sign leaf");
        (cert.pem(), key_pair.serialize_pem())
    }

    fn write_pem_to_temp(pem: &str) -> NamedTempFile {
        let mut f = must(NamedTempFile::new(), "create temp CA file");
        must(f.write_all(pem.as_bytes()), "write CA PEM");
        f
    }

    /// Build a rustls server `ServerConfig` from leaf PEM cert + PEM key.
    fn build_server_config(cert_pem: &str, key_pem: &str) -> Arc<rustls::ServerConfig> {
        let certs: Vec<CertificateDer<'static>> = must(
            rustls_pemfile::certs(&mut cert_pem.as_bytes()).collect::<Result<Vec<_>, _>>(),
            "parse leaf cert",
        );
        let key: rustls::pki_types::PrivateKeyDer<'static> = must_some(
            must(
                rustls_pemfile::private_key(&mut key_pem.as_bytes()),
                "parse private key",
            ),
            "private key should be present",
        );
        let provider = Arc::new(crate::fips::base_crypto_provider());
        let builder = must(
            rustls::ServerConfig::builder_with_provider(provider)
                .with_safe_default_protocol_versions(),
            "configure TLS protocol versions",
        );
        let cfg = must(
            builder.with_no_client_auth().with_single_cert(certs, key),
            "build TLS server cert config",
        );
        Arc::new(cfg)
    }

    /// Stand up a one-shot TLS listener on 127.0.0.1, return the bound port +
    /// the listener task handle (which completes after one accepted handshake).
    async fn spawn_oneshot_tls_server(
        server_cfg: Arc<rustls::ServerConfig>,
    ) -> (u16, tokio::task::JoinHandle<()>) {
        let listener = must(TcpListener::bind("127.0.0.1:0").await, "bind TLS server");
        let port = must(listener.local_addr(), "read TLS server local addr").port();
        let acceptor = TlsAcceptor::from(server_cfg);
        let task = tokio::spawn(async move {
            if let Ok((stream, _)) = listener.accept().await {
                let _ = acceptor.accept(stream).await; // ignore - test asserts on client side
            }
        });
        (port, task)
    }

    async fn dial_with_config(port: u16, client_cfg: Arc<ClientConfig>) -> std::io::Result<()> {
        let connector = TlsConnector::from(client_cfg);
        let stream = TcpStream::connect(("127.0.0.1", port)).await?;
        let server_name =
            ServerName::try_from("localhost").map_err(|e| std::io::Error::other(e.to_string()))?;
        let mut tls = connector.connect(server_name, stream).await?;
        // Drive the handshake to completion via a tiny round-trip, otherwise some
        // failures only surface on first I/O.
        let _ = tls.write_all(b"x").await;
        let mut buf = [0u8; 1];
        let _ = tls.read(&mut buf).await;
        Ok(())
    }

    #[test]
    fn no_verify_returns_arc_clientconfig() {
        ensure_crypto_provider();
        let cfg = must(
            build_ldap_tls_config(true, None, &[]),
            "build no-verify config",
        );
        // Cheap structural smoke check: must be an Arc<ClientConfig>.
        let _: &ClientConfig = cfg.as_ref();
    }

    #[test]
    fn missing_ca_bundle_path_falls_back_to_webpki() {
        ensure_crypto_provider();
        let cfg = must(
            build_ldap_tls_config(false, None, &[]),
            "build webpki config",
        );
        let _: &ClientConfig = cfg.as_ref();
    }

    #[test]
    fn empty_ca_bundle_rejected() {
        ensure_crypto_provider();
        let f = must(NamedTempFile::new(), "create empty temp CA file");
        let err = build_ldap_tls_config(false, f.path().to_str(), &[]).unwrap_err();
        assert!(
            err.contains("no valid PEM certificates"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn no_verify_still_rejects_empty_declared_ca_bundle() {
        ensure_crypto_provider();
        let f = must(NamedTempFile::new(), "create empty temp CA file");
        let err = build_ldap_tls_config(true, f.path().to_str(), &[]).unwrap_err();
        assert!(
            err.contains("no valid PEM certificates"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn missing_ca_bundle_file_rejected() {
        ensure_crypto_provider();
        let err = build_ldap_tls_config(false, Some("/nonexistent/path/ca.pem"), &[]).unwrap_err();
        assert!(err.contains("failed to read"), "unexpected error: {err}");
    }

    /// Proves CA exclusivity: a config built with CA-A successfully completes a
    /// TLS handshake against a server whose cert is signed by CA-A.
    #[tokio::test(flavor = "current_thread")]
    async fn custom_ca_accepts_matching_cert() {
        ensure_crypto_provider();
        let ca_a = generate_test_ca("Test CA A");
        let (leaf_pem, leaf_key_pem) = generate_signed_leaf(&ca_a, "localhost", &["localhost"]);

        let ca_file = write_pem_to_temp(&ca_a.cert_pem);
        let client_cfg = must(
            build_ldap_tls_config(false, ca_file.path().to_str(), &[]),
            "build client config",
        );

        let server_cfg = build_server_config(&leaf_pem, &leaf_key_pem);
        let (port, _task) = spawn_oneshot_tls_server(server_cfg).await;

        let result = dial_with_config(port, client_cfg).await;
        assert!(
            result.is_ok(),
            "handshake should succeed against matching CA, got: {result:?}"
        );
    }

    /// Proves CA exclusivity: a config built with CA-A REJECTS a server cert
    /// signed by CA-B. If the system / webpki public roots were leaking into
    /// the trust store (the native-tls regression we're fixing), this test
    /// would still fail — but for the wrong reason — because both CA-A and
    /// CA-B are private and not in any public root program. The point of the
    /// test is the positive direction: when we trust CA-A and the server
    /// uses CA-B, we explicitly fail.
    #[tokio::test(flavor = "current_thread")]
    async fn custom_ca_rejects_mismatched_cert() {
        ensure_crypto_provider();
        let ca_a = generate_test_ca("Test CA A");
        let ca_b = generate_test_ca("Test CA B");
        let (leaf_pem_b, leaf_key_pem_b) = generate_signed_leaf(&ca_b, "localhost", &["localhost"]);

        // Build config trusting only CA-A; server presents CA-B-signed cert.
        let ca_file = write_pem_to_temp(&ca_a.cert_pem);
        let client_cfg = must(
            build_ldap_tls_config(false, ca_file.path().to_str(), &[]),
            "build client config",
        );

        let server_cfg = build_server_config(&leaf_pem_b, &leaf_key_pem_b);
        let (port, _task) = spawn_oneshot_tls_server(server_cfg).await;

        let result = dial_with_config(port, client_cfg).await;
        assert!(
            result.is_err(),
            "handshake should FAIL when server cert is signed by an untrusted CA"
        );
    }

    /// Proves CA exclusivity at the trust-store layer (no handshake):
    /// `RootCertStore::empty()` + the configured bundle is the ENTIRE trust
    /// store. We verify this by counting roots in the constructed store and
    /// asserting it matches the bundle's cert count exactly — i.e. the
    /// system / webpki roots (~150) were NOT mixed in.
    #[test]
    fn custom_ca_excludes_webpki_roots() {
        ensure_crypto_provider();
        let ca = generate_test_ca("Test CA Exclusive");
        let ca_file = write_pem_to_temp(&ca.cert_pem);
        let store = must(
            build_ldap_root_store(ca_file.path().to_str()),
            "build custom trust store",
        );
        // Single CA in bundle → exactly 1 trust anchor.
        assert_eq!(
            store.len(),
            1,
            "Custom CA must produce a single-anchor trust store; \
             a value > 1 indicates webpki / system roots leaked in"
        );

        // Sanity: the no-CA path falls back to webpki bundled roots, which
        // is many anchors — proves our test setup wasn't trivially passing.
        let webpki_store = must(build_ldap_root_store(None), "build webpki trust store");
        assert!(
            webpki_store.len() > 10,
            "webpki fallback should populate many trust anchors"
        );
    }

    /// Generate a leaf cert (PEM cert + PEM key) signed by `ca` with an explicit
    /// serial number, so a CRL can reference it. Mirrors `generate_signed_leaf`.
    fn generate_signed_leaf_with_serial(
        ca: &TestCa,
        cn: &str,
        sans: &[&str],
        serial: u64,
    ) -> (String, String) {
        let key_pair = must(
            KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256),
            "generate leaf key",
        );
        let mut params = must(
            CertificateParams::new(sans.iter().map(|s| s.to_string()).collect::<Vec<_>>()),
            "build leaf params",
        );
        params
            .distinguished_name
            .push(rcgen::DnType::CommonName, cn);
        params.serial_number = Some(rcgen::SerialNumber::from(serial));
        let cert = must(params.signed_by(&key_pair, &ca.issuer), "sign leaf");
        (cert.pem(), key_pair.serialize_pem())
    }

    /// Build a CRL signed by `ca` revoking the given certificate serial.
    fn build_crl_revoking(ca: &TestCa, serial: u64) -> CertificateRevocationListDer<'static> {
        use rcgen::{
            CertificateRevocationListParams, RevocationReason, RevokedCertParams, SerialNumber,
        };
        use time::{Duration as TimeDuration, OffsetDateTime};

        let now = OffsetDateTime::now_utc();
        let params = CertificateRevocationListParams {
            this_update: now,
            next_update: now + TimeDuration::days(7),
            crl_number: SerialNumber::from(1u64),
            issuing_distribution_point: None,
            revoked_certs: vec![RevokedCertParams {
                serial_number: SerialNumber::from(serial),
                revocation_time: now,
                reason_code: Some(RevocationReason::KeyCompromise),
                invalidity_date: None,
            }],
            key_identifier_method: rcgen::KeyIdMethod::Sha256,
        };
        let crl = must(params.signed_by(&ca.issuer), "sign CRL");
        crl.der().clone()
    }

    /// Finding #84: with a gateway CRL configured, a revoked LDAP server
    /// certificate is REJECTED during the TLS handshake; without the CRL the
    /// same (otherwise valid, CA-trusted) certificate is ACCEPTED. The
    /// before/after contrast proves the CRL — not some other validation step —
    /// is what blocks the revoked cert.
    #[tokio::test(flavor = "current_thread")]
    async fn crl_rejects_revoked_server_cert() {
        ensure_crypto_provider();
        const REVOKED_SERIAL: u64 = 0x5151;

        let ca = generate_test_ca("Test CA CRL");
        let (leaf_pem, leaf_key_pem) =
            generate_signed_leaf_with_serial(&ca, "localhost", &["localhost"], REVOKED_SERIAL);
        let ca_file = write_pem_to_temp(&ca.cert_pem);
        let crl = build_crl_revoking(&ca, REVOKED_SERIAL);

        // Without a CRL: the CA-signed cert is trusted, handshake succeeds.
        let cfg_no_crl = must(
            build_ldap_tls_config(false, ca_file.path().to_str(), &[]),
            "build no-CRL config",
        );
        let server_cfg = build_server_config(&leaf_pem, &leaf_key_pem);
        let (port, _task) = spawn_oneshot_tls_server(server_cfg).await;
        let ok = dial_with_config(port, cfg_no_crl).await;
        assert!(
            ok.is_ok(),
            "handshake should SUCCEED without a CRL (baseline), got: {ok:?}"
        );

        // With the CRL revoking this serial: handshake must fail.
        let cfg_with_crl = must(
            build_ldap_tls_config(false, ca_file.path().to_str(), std::slice::from_ref(&crl)),
            "build CRL config",
        );
        let server_cfg = build_server_config(&leaf_pem, &leaf_key_pem);
        let (port, _task) = spawn_oneshot_tls_server(server_cfg).await;
        let revoked = dial_with_config(port, cfg_with_crl).await;
        assert!(
            revoked.is_err(),
            "handshake must FAIL when the server cert is revoked by the CRL"
        );
    }
}
