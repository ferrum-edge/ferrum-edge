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
//! Optionally checks LDAP/AD group membership after authentication. When
//! `required_groups` is set, the user must belong to at least one of the
//! listed groups (OR logic) for authentication to succeed.
//!
//! Successful authentications can be cached in-memory (keyed by username +
//! password hash) to avoid hitting the LDAP server on every request.
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

use async_trait::async_trait;
use base64::Engine;
use dashmap::DashMap;
use ldap3::{LdapConnAsync, LdapConnSettings, Scope, SearchEntry};
use rustls::ClientConfig;
use rustls::pki_types::{CertificateDer, CertificateRevocationListDer};
use serde_json::Map;
use serde_json::Value;
use std::collections::HashSet;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tracing::{debug, warn};
use url::{Host, Url};

use crate::consumer_index::ConsumerIndex;
use crate::tls::source::{CertSource, MaterialKind, load_material_blocking};

use super::utils::PluginHttpClient;
use super::utils::auth_flow::{self, AuthMechanism, ExtractedCredential, VerifyOutcome};
use super::{RequestContext, strip_auth_scheme};

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
    /// Cache TTL for successful auth results (0 = disabled)
    cache_ttl: Duration,
    /// In-memory cache: key = "username\0sha256(password)" -> expiry instant
    cache: Arc<DashMap<String, Instant>>,
    /// Maximum entries in the auth result cache. Prevents unbounded growth
    /// from brute-force attempts with unique credentials. Default: 10000.
    max_cache_entries: usize,
    /// Whether to try mapping to a gateway Consumer via consumer_index
    consumer_mapping: bool,
    /// Pre-built rustls `ClientConfig` for LDAP TLS connections.
    /// Integrates `FERRUM_TLS_CA_BUNDLE_PATH` (exclusive trust) and
    /// `FERRUM_TLS_NO_VERIFY`. `Arc` so reuse across reconnects is cheap and
    /// matches `LdapConnSettings::set_config()`'s expected type.
    tls_config: Option<Arc<ClientConfig>>,
    /// Whether to skip TLS verification (passed to ldap3 for IP-address handling).
    tls_no_verify: bool,
    /// Extracted hostname from ldap_url for DNS pre-warming.
    ldap_hostname: Option<String>,
}

impl LdapAuth {
    pub fn new(config: &Value, http_client: PluginHttpClient) -> Result<Self, String> {
        let config_obj = config
            .as_object()
            .ok_or_else(|| format!("ldap_auth: config must be an object, got: {config}"))?;

        let ldap_url = parse_required_ldap_url(config_obj)?.to_owned();
        let parsed_ldap_url = Url::parse(&ldap_url)
            .map_err(|e| format!("ldap_auth: 'ldap_url' is not a valid URL: {e}"))?;

        let is_ldaps = match parsed_ldap_url.scheme() {
            "ldap" => false,
            "ldaps" => true,
            _ => {
                return Err(
                    "ldap_auth: 'ldap_url' must start with 'ldap://' or 'ldaps://'".to_string(),
                );
            }
        };
        if !has_non_empty_authority(&ldap_url) {
            return Err("ldap_auth: 'ldap_url' must include a hostname".to_string());
        }
        let ldap_hostname = Some(ldap_url_hostname(&parsed_ldap_url)?);

        let bind_dn_template = parse_optional_string(config_obj, "bind_dn_template")?;

        let search_base_dn = parse_optional_string(config_obj, "search_base_dn")?;

        let search_filter = parse_optional_string(config_obj, "search_filter")?;

        let service_account_dn = parse_optional_string(config_obj, "service_account_dn")?;

        let service_account_password =
            parse_optional_string(config_obj, "service_account_password")?;

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

        if has_search_bind && (service_account_dn.is_none() || service_account_password.is_none()) {
            return Err(
                "ldap_auth: search-then-bind mode requires 'service_account_dn' and \
                 'service_account_password'"
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

        if let Some(ref f) = search_filter
            && !f.contains("{username}")
        {
            return Err(
                "ldap_auth: 'search_filter' must contain '{username}' placeholder".to_string(),
            );
        }

        // Group filtering config
        let group_base_dn = parse_optional_string(config_obj, "group_base_dn")?;

        let group_filter = parse_optional_string(config_obj, "group_filter")?;

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

        let connect_timeout_secs = parse_u64(config_obj, "connect_timeout_seconds", 5)?;
        if connect_timeout_secs == 0 {
            return Err(
                "ldap_auth: 'connect_timeout_seconds' must be greater than zero".to_string(),
            );
        }

        let cache_ttl_secs = parse_u64(config_obj, "cache_ttl_seconds", 0)?;

        let max_cache_entries = parse_usize(config_obj, "max_cache_entries", 10_000)?;
        if max_cache_entries == 0 {
            return Err("ldap_auth: 'max_cache_entries' must be greater than zero".to_string());
        }

        let consumer_mapping = parse_bool(config_obj, "consumer_mapping", true)?;

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
            service_account_dn,
            service_account_password,
            group_base_dn,
            group_filter,
            required_groups,
            required_group_lookup,
            group_attribute,
            starttls,
            connect_timeout: Duration::from_secs(connect_timeout_secs),
            cache_ttl: Duration::from_secs(cache_ttl_secs),
            cache: Arc::new(DashMap::new()),
            max_cache_entries,
            consumer_mapping,
            tls_config,
            tls_no_verify,
            ldap_hostname,
        })
    }

    /// Build a cache key from username + password (hashed for safety).
    fn cache_key(username: &str, password: &str) -> String {
        use sha2::{Digest, Sha256};
        let mut hasher = Sha256::new();
        hasher.update(password.as_bytes());
        let hash = hex::encode(hasher.finalize());
        format!("{}\0{}", username, hash)
    }

    /// Check if a successful auth result is cached and still valid.
    fn check_cache(&self, username: &str, password: &str) -> bool {
        if self.cache_ttl.is_zero() {
            return false;
        }
        let key = Self::cache_key(username, password);
        if let Some(expiry) = self.cache.get(&key) {
            if Instant::now() < *expiry {
                return true;
            }
            // Expired — remove the entry
            drop(expiry);
            self.cache.remove(&key);
        }
        false
    }

    /// Cache a successful authentication result.
    fn set_cache(&self, username: &str, password: &str) {
        if self.cache_ttl.is_zero() {
            return;
        }
        // Enforce max size: evict expired entries first, then skip if still at capacity
        if self.cache.len() >= self.max_cache_entries {
            self.evict_expired();
            if self.cache.len() >= self.max_cache_entries {
                return;
            }
        }
        let key = Self::cache_key(username, password);
        self.cache.insert(key, Instant::now() + self.cache_ttl);
    }

    /// Remove all expired entries from the cache.
    fn evict_expired(&self) {
        let now = Instant::now();
        self.cache.retain(|_, expiry| now < *expiry);
    }

    /// Connect to the LDAP server with configured settings.
    ///
    /// A connection failure is a backend/infrastructure problem (directory
    /// unreachable, TLS handshake failure), not a credential problem, so it is
    /// surfaced as [`AuthError::Backend`].
    async fn connect(&self) -> Result<ldap3::Ldap, AuthError> {
        let mut settings = LdapConnSettings::new()
            .set_conn_timeout(self.connect_timeout)
            .set_starttls(self.starttls)
            .set_no_tls_verify(self.tls_no_verify);

        if let Some(ref config) = self.tls_config {
            settings = settings.set_config(config.clone());
        }

        let (conn, mut ldap) = LdapConnAsync::with_settings(settings, &self.ldap_url)
            .await
            .map_err(|e| AuthError::Backend(format!("ldap_auth: connection failed: {e}")))?;

        // Drive the connection in the background
        ldap3::drive!(conn);

        // Set operation timeout to match connect timeout
        ldap.with_timeout(self.connect_timeout);

        Ok(ldap)
    }

    /// Authenticate a user via direct bind or search-then-bind.
    /// Returns the user's DN on success.
    ///
    /// Errors are classified ([`AuthError`]) so that a rejected user bind /
    /// "user not found" surfaces as a 401 while a directory outage, a failed
    /// service-account bind, or a search RPC error surfaces as a 500 (finding
    /// #32). A bind that *fails* (transport / RPC error) is a backend problem;
    /// a bind that is *rejected* (LDAP returned a non-success result code for
    /// the end user's credentials) is the genuine invalid-credential case.
    async fn authenticate_user(&self, username: &str, password: &str) -> Result<String, AuthError> {
        let mut ldap = self.connect().await?;

        let user_dn = if let Some(ref template) = self.bind_dn_template {
            // Direct bind: substitute DN-escaped username into template (RFC 4514)
            let dn = template.replace("{username}", &escape_dn_value(username));
            let bind_result = ldap
                .simple_bind(&dn, password)
                .await
                .map_err(|e| AuthError::Backend(format!("ldap_auth: bind failed: {e}")))?;
            classify_user_bind_result(bind_result, "bind")?;
            dn
        } else {
            // Search-then-bind: find user DN via service account
            let service_dn = self.service_account_dn.as_deref().unwrap_or_default();
            let service_pw = self.service_account_password.as_deref().unwrap_or_default();

            // A failed/rejected service-account bind is an operator
            // misconfiguration, never the end user's fault — classify both as
            // backend errors so the client is not told its credentials are wrong.
            ldap.simple_bind(service_dn, service_pw)
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

            let (rs, _result) = ldap
                // The DN is part of every LDAP search result, not a regular
                // attribute. Request no attributes; `SearchEntry::dn` still
                // carries the bind target and avoids servers rejecting a
                // pseudo-attribute request for "dn".
                .search(search_base, Scope::Subtree, &filter, Vec::<&str>::new())
                .await
                .map_err(|e| AuthError::Backend(format!("ldap_auth: user search failed: {e}")))?
                .success()
                .map_err(|e| AuthError::Backend(format!("ldap_auth: user search error: {e}")))?;

            if rs.is_empty() {
                return Err(AuthError::Credential(
                    "ldap_auth: user not found".to_string(),
                ));
            }

            let entry = SearchEntry::construct(rs.into_iter().next().ok_or_else(|| {
                AuthError::Backend("ldap_auth: user not found after non-empty check".to_string())
            })?);
            let user_dn = entry.dn;

            // Unbind the service account, re-connect and bind as the user
            let _ = ldap.unbind().await;

            let mut user_ldap = self.connect().await?;
            let user_bind_result = user_ldap
                .simple_bind(&user_dn, password)
                .await
                .map_err(|e| AuthError::Backend(format!("ldap_auth: user bind failed: {e}")))?;
            classify_user_bind_result(user_bind_result, "user bind")?;

            let _ = user_ldap.unbind().await;
            user_dn
        };

        let _ = ldap.unbind().await;
        Ok(user_dn)
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
        username: &str,
    ) -> Result<bool, AuthError> {
        if self.required_groups.is_empty() {
            return Ok(true);
        }

        let group_base = self.group_base_dn.as_deref().unwrap_or_default();

        // Default filter checks both `member` (AD/static groups) and `memberUid` (posixGroup).
        // DN values in filters must be filter-escaped (RFC 4515), not DN-escaped.
        let escaped_user_dn = escape_filter_value(user_dn);
        let escaped_username = escape_filter_value(username);
        let default_filter = format!(
            "(|(member={escaped_user_dn})(uniqueMember={escaped_user_dn})(memberUid={escaped_username}))"
        );
        let filter = self
            .group_filter
            .as_ref()
            .map(|f| {
                f.replace("{user_dn}", &escaped_user_dn)
                    .replace("{username}", &escaped_username)
            })
            .unwrap_or(default_filter);

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
            ldap.simple_bind(dn, pw)
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

        let (rs, _result) = ldap
            .search(
                group_base,
                Scope::Subtree,
                &filter,
                vec![self.group_attribute.as_str()],
            )
            .await
            .map_err(|e| AuthError::Backend(format!("ldap_auth: group search failed: {e}")))?
            .success()
            .map_err(|e| AuthError::Backend(format!("ldap_auth: group search error: {e}")))?;

        let _ = ldap.unbind().await;

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
                username, group_base
            );
        }

        for result_entry in rs {
            let entry = SearchEntry::construct(result_entry);
            if let Some(group_names) = entry.attrs.get(&self.group_attribute) {
                for name in group_names {
                    if self.required_group_lookup.contains(&name.to_lowercase()) {
                        return Ok(true);
                    }
                }
            }
            // Also check the DN's CN component as a fallback
            if let Some(cn) = extract_cn_from_dn(&entry.dn)
                && self.required_group_lookup.contains(&cn.to_lowercase())
            {
                return Ok(true);
            }
        }

        Ok(false)
    }
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
    let value = raw.trim();
    if value.is_empty() {
        return Err("ldap_auth: 'ldap_url' must not be empty".to_string());
    }
    Ok(value)
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
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let builder = ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .map_err(|e| format!("ldap_auth: failed to build rustls client config: {e}"))?;

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
        // equivalent to the default root-store verifier. `build_server_verifier_with_crls`
        // uses `allow_unknown_revocation_status() + only_check_end_entity_revocation()`
        // so certs from CAs without a matching CRL are still accepted.
        let root_store = build_ldap_root_store(ca_bundle_path)?;
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
    let source_id = ca_material.source_id.clone();

    // Parse only X.509 entries; tolerate other PEM blocks (private keys, etc.)
    // by ignoring them, but log them so operators can spot malformed bundles.
    let mut certs: Vec<CertificateDer<'static>> = Vec::new();
    let mut reader = ca_material.bytes.expose_secret();
    for item in std::iter::from_fn(move || rustls_pemfile::read_one(&mut reader).transpose()) {
        match item {
            Ok(rustls_pemfile::Item::X509Certificate(cert_der)) => {
                certs.push(cert_der);
            }
            Ok(_) => {} // Skip non-cert PEM items
            Err(e) => {
                warn!(
                    "ldap_auth: skipping malformed PEM item in '{}': {e}",
                    source_id
                );
            }
        }
    }

    // CA exclusivity: empty store, then load only the configured bundle.
    let mut root_store = rustls::RootCertStore::empty();
    let (added, ignored) = root_store.add_parsable_certificates(certs);

    if added == 0 {
        return Err(format!(
            "ldap_auth: no valid CA certificates found in '{}'",
            source_id
        ));
    }
    if ignored > 0 {
        warn!(
            "ldap_auth: ignored {} invalid CA certificate(s) while loading '{}'",
            ignored, source_id
        );
    }
    debug!(
        "ldap_auth: loaded {} CA certificate(s) from '{}' (CA exclusivity enforced)",
        added, source_id
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

/// Extract the CN value from a distinguished name.
/// e.g. "CN=Domain Admins,OU=Groups,DC=example,DC=com" -> "Domain Admins"
fn extract_cn_from_dn(dn: &str) -> Option<&str> {
    for component in dn.split(',') {
        let trimmed = component.trim();
        if let Some(rest) = trimmed
            .strip_prefix("CN=")
            .or_else(|| trimmed.strip_prefix("cn="))
        {
            return Some(rest);
        }
    }
    None
}

#[async_trait]
impl AuthMechanism for LdapAuth {
    fn mechanism_name(&self) -> &'static str {
        "ldap_auth"
    }

    fn extract(&self, ctx: &RequestContext) -> ExtractedCredential {
        let auth_header = match ctx.headers.get("authorization") {
            Some(header) => header,
            None => return ExtractedCredential::Missing,
        };

        let encoded = match strip_auth_scheme(auth_header, "Basic") {
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

        // Check cache first
        if self.check_cache(&username, &password) {
            debug!("ldap_auth: cache hit for user '{}'", username);
            return self.identity_outcome(&username, consumer_index);
        }

        // Authenticate against LDAP. Distinguish a genuine credential failure
        // (401) from a backend/config failure (500); see finding #32. The
        // client always receives a generic message — the specific cause is only
        // logged via `warn!`.
        let user_dn = match self.authenticate_user(&username, &password).await {
            Ok(dn) => dn,
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

        // Check group membership if required
        if !self.required_groups.is_empty() {
            match self.check_group_membership(&user_dn, &username).await {
                Ok(true) => {}
                Ok(false) => {
                    warn!(
                        "ldap_auth: user '{}' is not a member of any required group",
                        username
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

        // Cache successful auth
        self.set_cache(&username, &password);

        debug!("ldap_auth: authenticated user '{}'", username);
        self.identity_outcome(&username, consumer_index)
    }
}

auth_flow::impl_auth_plugin!(
    LdapAuth,
    "ldap_auth",
    super::priority::LDAP_AUTH,
    crate::plugins::HTTP_FAMILY_PROTOCOLS,
    auth_flow::run_auth_external_identity;
    fn warmup_hostnames(&self) -> Vec<String> {
        self.ldap_hostname
            .as_ref()
            .map(|h| vec![h.clone()])
            .unwrap_or_default()
    }
);

impl LdapAuth {
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
            let _ = rustls::crypto::ring::default_provider().install_default();
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
        let provider = Arc::new(rustls::crypto::ring::default_provider());
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
            err.contains("no valid CA certificates"),
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
