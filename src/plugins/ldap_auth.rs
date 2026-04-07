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
//! Both `ldaps://` and STARTTLS connections use native-tls (OpenSSL). The
//! plugin respects:
//! - `FERRUM_TLS_CA_BUNDLE_PATH` — custom CA bundle for verifying the LDAP
//!   server certificate
//! - `FERRUM_TLS_NO_VERIFY` — skip TLS certificate verification (testing only)
//!
//! This is a non-rustls TLS path (ldap3 uses native-tls internally), similar
//! to the kafka_logging plugin which uses librdkafka/OpenSSL. CRL checking is
//! not applied — use the LDAP server's own revocation mechanisms.

use async_trait::async_trait;
use base64::Engine;
use dashmap::DashMap;
use ldap3::{LdapConnAsync, LdapConnSettings, Scope, SearchEntry};
use serde_json::Value;
use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tracing::{debug, warn};

use crate::consumer_index::ConsumerIndex;

use super::utils::PluginHttpClient;
use super::{Plugin, PluginResult, RequestContext, strip_auth_scheme};

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
    group_attribute: String,
    /// Use STARTTLS on ldap:// connections
    starttls: bool,
    /// LDAP connection timeout
    connect_timeout: Duration,
    /// Cache TTL for successful auth results (0 = disabled)
    cache_ttl: Duration,
    /// In-memory cache: key = "username\0sha256(password)" -> expiry instant
    cache: Arc<DashMap<String, Instant>>,
    /// Whether to try mapping to a gateway Consumer via consumer_index
    consumer_mapping: bool,
    /// Pre-built native-tls connector for LDAP TLS connections.
    /// Integrates `FERRUM_TLS_CA_BUNDLE_PATH` and `FERRUM_TLS_NO_VERIFY`.
    tls_connector: Option<native_tls::TlsConnector>,
    /// Whether to skip TLS verification (passed to ldap3 for IP-address handling).
    tls_no_verify: bool,
}

impl LdapAuth {
    pub fn new(config: &Value, http_client: PluginHttpClient) -> Result<Self, String> {
        let ldap_url = config
            .get("ldap_url")
            .and_then(|v| v.as_str())
            .filter(|s| !s.is_empty())
            .ok_or_else(|| {
                "ldap_auth: 'ldap_url' is required (e.g. \"ldap://ldap.example.com:389\" or \"ldaps://ldap.example.com:636\")".to_string()
            })?
            .to_string();

        if !ldap_url.starts_with("ldap://") && !ldap_url.starts_with("ldaps://") {
            return Err(
                "ldap_auth: 'ldap_url' must start with 'ldap://' or 'ldaps://'".to_string(),
            );
        }

        let bind_dn_template = config
            .get("bind_dn_template")
            .and_then(|v| v.as_str())
            .filter(|s| !s.is_empty())
            .map(|s| s.to_string());

        let search_base_dn = config
            .get("search_base_dn")
            .and_then(|v| v.as_str())
            .filter(|s| !s.is_empty())
            .map(|s| s.to_string());

        let search_filter = config
            .get("search_filter")
            .and_then(|v| v.as_str())
            .filter(|s| !s.is_empty())
            .map(|s| s.to_string());

        let service_account_dn = config
            .get("service_account_dn")
            .and_then(|v| v.as_str())
            .filter(|s| !s.is_empty())
            .map(|s| s.to_string());

        let service_account_password = config
            .get("service_account_password")
            .and_then(|v| v.as_str())
            .filter(|s| !s.is_empty())
            .map(|s| s.to_string());

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
        let group_base_dn = config
            .get("group_base_dn")
            .and_then(|v| v.as_str())
            .filter(|s| !s.is_empty())
            .map(|s| s.to_string());

        let group_filter = config
            .get("group_filter")
            .and_then(|v| v.as_str())
            .filter(|s| !s.is_empty())
            .map(|s| s.to_string());

        let required_groups: Vec<String> = config
            .get("required_groups")
            .and_then(|v| v.as_array())
            .map(|arr| {
                arr.iter()
                    .filter_map(|v| v.as_str())
                    .filter(|s| !s.is_empty())
                    .map(|s| s.to_string())
                    .collect()
            })
            .unwrap_or_default();

        if !required_groups.is_empty() && group_base_dn.is_none() {
            return Err(
                "ldap_auth: 'group_base_dn' is required when 'required_groups' is set".to_string(),
            );
        }

        let group_attribute = config
            .get("group_attribute")
            .and_then(|v| v.as_str())
            .unwrap_or("cn")
            .to_string();

        let starttls = config
            .get("starttls")
            .and_then(|v| v.as_bool())
            .unwrap_or(false);

        if starttls && ldap_url.starts_with("ldaps://") {
            return Err(
                "ldap_auth: 'starttls' cannot be used with 'ldaps://' URLs (STARTTLS is for upgrading ldap:// connections)"
                    .to_string(),
            );
        }

        let connect_timeout_secs = config
            .get("connect_timeout_seconds")
            .and_then(|v| v.as_u64())
            .unwrap_or(5);

        let cache_ttl_secs = config
            .get("cache_ttl_seconds")
            .and_then(|v| v.as_u64())
            .unwrap_or(0);

        let consumer_mapping = config
            .get("consumer_mapping")
            .and_then(|v| v.as_bool())
            .unwrap_or(true);

        // Build TLS connector respecting gateway settings
        let tls_no_verify = http_client.tls_no_verify();
        let needs_tls = ldap_url.starts_with("ldaps://") || starttls;
        let tls_connector = if needs_tls {
            Some(build_ldap_tls_connector(
                tls_no_verify,
                http_client.tls_ca_bundle_path(),
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
            group_attribute,
            starttls,
            connect_timeout: Duration::from_secs(connect_timeout_secs),
            cache_ttl: Duration::from_secs(cache_ttl_secs),
            cache: Arc::new(DashMap::new()),
            consumer_mapping,
            tls_connector,
            tls_no_verify,
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
        let key = Self::cache_key(username, password);
        self.cache.insert(key, Instant::now() + self.cache_ttl);
    }

    /// Connect to the LDAP server with configured settings.
    async fn connect(&self) -> Result<ldap3::Ldap, String> {
        let mut settings = LdapConnSettings::new()
            .set_conn_timeout(self.connect_timeout)
            .set_starttls(self.starttls)
            .set_no_tls_verify(self.tls_no_verify);

        if let Some(ref connector) = self.tls_connector {
            settings = settings.set_connector(connector.clone());
        }

        let (conn, mut ldap) = LdapConnAsync::with_settings(settings, &self.ldap_url)
            .await
            .map_err(|e| format!("ldap_auth: connection failed: {e}"))?;

        // Drive the connection in the background
        ldap3::drive!(conn);

        // Set operation timeout to match connect timeout
        ldap.with_timeout(self.connect_timeout);

        Ok(ldap)
    }

    /// Authenticate a user via direct bind or search-then-bind.
    /// Returns the user's DN on success.
    async fn authenticate_user(&self, username: &str, password: &str) -> Result<String, String> {
        let mut ldap = self.connect().await?;

        let user_dn = if let Some(ref template) = self.bind_dn_template {
            // Direct bind: substitute username into template
            let dn = template.replace("{username}", username);
            ldap.simple_bind(&dn, password)
                .await
                .map_err(|e| format!("ldap_auth: bind failed: {e}"))?
                .success()
                .map_err(|e| format!("ldap_auth: bind rejected: {e}"))?;
            dn
        } else {
            // Search-then-bind: find user DN via service account
            let service_dn = self.service_account_dn.as_deref().unwrap_or_default();
            let service_pw = self.service_account_password.as_deref().unwrap_or_default();

            ldap.simple_bind(service_dn, service_pw)
                .await
                .map_err(|e| format!("ldap_auth: service account bind failed: {e}"))?
                .success()
                .map_err(|e| format!("ldap_auth: service account bind rejected: {e}"))?;

            let search_base = self.search_base_dn.as_deref().unwrap_or_default();
            let filter = self
                .search_filter
                .as_deref()
                .unwrap_or_default()
                .replace("{username}", username);

            let (rs, _result) = ldap
                .search(search_base, Scope::Subtree, &filter, vec!["dn"])
                .await
                .map_err(|e| format!("ldap_auth: user search failed: {e}"))?
                .success()
                .map_err(|e| format!("ldap_auth: user search error: {e}"))?;

            if rs.is_empty() {
                return Err("ldap_auth: user not found".to_string());
            }

            let entry = SearchEntry::construct(rs.into_iter().next().unwrap());
            let user_dn = entry.dn;

            // Unbind the service account, re-connect and bind as the user
            let _ = ldap.unbind().await;

            let mut user_ldap = self.connect().await?;
            user_ldap
                .simple_bind(&user_dn, password)
                .await
                .map_err(|e| format!("ldap_auth: user bind failed: {e}"))?
                .success()
                .map_err(|e| format!("ldap_auth: user bind rejected: {e}"))?;

            let _ = user_ldap.unbind().await;
            user_dn
        };

        let _ = ldap.unbind().await;
        Ok(user_dn)
    }

    /// Check if the authenticated user belongs to at least one of the required groups.
    async fn check_group_membership(&self, user_dn: &str, username: &str) -> Result<bool, String> {
        if self.required_groups.is_empty() {
            return Ok(true);
        }

        let group_base = self.group_base_dn.as_deref().unwrap_or_default();

        // Default filter checks both `member` (AD/static groups) and `memberUid` (posixGroup)
        let default_filter =
            format!("(|(member={user_dn})(uniqueMember={user_dn})(memberUid={username}))");
        let filter = self
            .group_filter
            .as_ref()
            .map(|f| {
                f.replace("{user_dn}", user_dn)
                    .replace("{username}", username)
            })
            .unwrap_or(default_filter);

        // Use service account if available, otherwise anonymous bind
        let mut ldap = self.connect().await?;
        if let (Some(dn), Some(pw)) = (&self.service_account_dn, &self.service_account_password) {
            ldap.simple_bind(dn, pw)
                .await
                .map_err(|e| format!("ldap_auth: group check bind failed: {e}"))?
                .success()
                .map_err(|e| format!("ldap_auth: group check bind rejected: {e}"))?;
        }

        let (rs, _result) = ldap
            .search(
                group_base,
                Scope::Subtree,
                &filter,
                vec![self.group_attribute.as_str()],
            )
            .await
            .map_err(|e| format!("ldap_auth: group search failed: {e}"))?
            .success()
            .map_err(|e| format!("ldap_auth: group search error: {e}"))?;

        let _ = ldap.unbind().await;

        // Check if any returned group matches the required list
        let required_lower: Vec<String> = self
            .required_groups
            .iter()
            .map(|g| g.to_lowercase())
            .collect();

        for result_entry in rs {
            let entry = SearchEntry::construct(result_entry);
            if let Some(group_names) = entry.attrs.get(&self.group_attribute) {
                for name in group_names {
                    if required_lower.contains(&name.to_lowercase()) {
                        return Ok(true);
                    }
                }
            }
            // Also check the DN's CN component as a fallback
            if let Some(cn) = extract_cn_from_dn(&entry.dn)
                && required_lower.contains(&cn.to_lowercase())
            {
                return Ok(true);
            }
        }

        Ok(false)
    }
}

/// Build a native-tls `TlsConnector` for LDAP connections.
///
/// Integrates with gateway TLS settings:
/// - `FERRUM_TLS_CA_BUNDLE_PATH` → loads PEM CA certs as trusted roots
/// - `FERRUM_TLS_NO_VERIFY` → disables server certificate verification
fn build_ldap_tls_connector(
    no_verify: bool,
    ca_bundle_path: Option<&str>,
) -> Result<native_tls::TlsConnector, String> {
    let mut builder = native_tls::TlsConnector::builder();

    if no_verify {
        warn!("ldap_auth: TLS certificate verification DISABLED (FERRUM_TLS_NO_VERIFY=true)");
        builder.danger_accept_invalid_certs(true);
        builder.danger_accept_invalid_hostnames(true);
    }

    if let Some(ca_path) = ca_bundle_path {
        let ca_data = std::fs::read(ca_path)
            .map_err(|e| format!("ldap_auth: failed to read CA bundle '{}': {e}", ca_path))?;

        // Parse PEM certificates and add each as a root
        let mut added = 0;
        let mut reader = &ca_data[..];
        for item in std::iter::from_fn(move || rustls_pemfile::read_one(&mut reader).transpose()) {
            match item {
                Ok(rustls_pemfile::Item::X509Certificate(cert_der)) => {
                    let cert = native_tls::Certificate::from_der(&cert_der)
                        .map_err(|e| format!("ldap_auth: invalid CA cert in '{}': {e}", ca_path))?;
                    builder.add_root_certificate(cert);
                    added += 1;
                }
                Ok(_) => {} // Skip non-cert PEM items
                Err(e) => {
                    warn!(
                        "ldap_auth: skipping malformed PEM item in '{}': {e}",
                        ca_path
                    );
                }
            }
        }

        if added == 0 {
            return Err(format!(
                "ldap_auth: no valid CA certificates found in '{}'",
                ca_path
            ));
        }
        debug!(
            "ldap_auth: loaded {} CA certificate(s) from '{}'",
            added, ca_path
        );
    }

    builder
        .build()
        .map_err(|e| format!("ldap_auth: failed to build TLS connector: {e}"))
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
impl Plugin for LdapAuth {
    fn name(&self) -> &str {
        "ldap_auth"
    }

    fn is_auth_plugin(&self) -> bool {
        true
    }

    fn priority(&self) -> u16 {
        super::priority::LDAP_AUTH
    }

    fn supported_protocols(&self) -> &'static [super::ProxyProtocol] {
        super::HTTP_FAMILY_PROTOCOLS
    }

    async fn authenticate(
        &self,
        ctx: &mut RequestContext,
        consumer_index: &ConsumerIndex,
    ) -> PluginResult {
        // Extract Basic auth credentials
        let auth_header = match ctx.headers.get("authorization") {
            Some(h) => h.clone(),
            None => {
                return PluginResult::Reject {
                    status_code: 401,
                    body: r#"{"error":"Missing Authorization header"}"#.into(),
                    headers: HashMap::new(),
                };
            }
        };

        let encoded = match strip_auth_scheme(&auth_header, "Basic") {
            Some(encoded) => encoded,
            None => {
                return PluginResult::Reject {
                    status_code: 401,
                    body: r#"{"error":"Invalid Basic auth format"}"#.into(),
                    headers: HashMap::new(),
                };
            }
        };

        let decoded = match base64::engine::general_purpose::STANDARD.decode(encoded) {
            Ok(d) => d,
            Err(_) => {
                return PluginResult::Reject {
                    status_code: 401,
                    body: r#"{"error":"Invalid base64 in Basic auth"}"#.into(),
                    headers: HashMap::new(),
                };
            }
        };

        let credential_str = match String::from_utf8(decoded) {
            Ok(s) => s,
            Err(_) => {
                return PluginResult::Reject {
                    status_code: 401,
                    body: r#"{"error":"Invalid UTF-8 in Basic auth"}"#.into(),
                    headers: HashMap::new(),
                };
            }
        };

        let parts: Vec<&str> = credential_str.splitn(2, ':').collect();
        if parts.len() != 2 {
            return PluginResult::Reject {
                status_code: 401,
                body: r#"{"error":"Invalid Basic auth format"}"#.into(),
                headers: HashMap::new(),
            };
        }

        let username = parts[0];
        let password = parts[1];

        if username.is_empty() {
            return PluginResult::Reject {
                status_code: 401,
                body: r#"{"error":"Username must not be empty"}"#.into(),
                headers: HashMap::new(),
            };
        }

        // Check cache first
        if self.check_cache(username, password) {
            debug!("ldap_auth: cache hit for user '{}'", username);
            self.set_identity(ctx, username, consumer_index);
            return PluginResult::Continue;
        }

        // Authenticate against LDAP
        let user_dn = match self.authenticate_user(username, password).await {
            Ok(dn) => dn,
            Err(e) => {
                warn!("{}", e);
                return PluginResult::Reject {
                    status_code: 401,
                    body: r#"{"error":"LDAP authentication failed"}"#.into(),
                    headers: HashMap::new(),
                };
            }
        };

        // Check group membership if required
        if !self.required_groups.is_empty() {
            match self.check_group_membership(&user_dn, username).await {
                Ok(true) => {}
                Ok(false) => {
                    warn!(
                        "ldap_auth: user '{}' is not a member of any required group",
                        username
                    );
                    return PluginResult::Reject {
                        status_code: 403,
                        body: r#"{"error":"User is not a member of any required group"}"#.into(),
                        headers: HashMap::new(),
                    };
                }
                Err(e) => {
                    warn!("{}", e);
                    return PluginResult::Reject {
                        status_code: 500,
                        body: r#"{"error":"LDAP group membership check failed"}"#.into(),
                        headers: HashMap::new(),
                    };
                }
            }
        }

        // Cache successful auth
        self.set_cache(username, password);

        debug!("ldap_auth: authenticated user '{}'", username);
        self.set_identity(ctx, username, consumer_index);
        PluginResult::Continue
    }
}

impl LdapAuth {
    /// Set the identity on the request context. If consumer_mapping is enabled,
    /// attempt to find a matching gateway Consumer. Always set authenticated_identity.
    fn set_identity(
        &self,
        ctx: &mut RequestContext,
        username: &str,
        consumer_index: &ConsumerIndex,
    ) {
        ctx.authenticated_identity = Some(username.to_string());
        ctx.authenticated_identity_header = Some(username.to_string());

        if self.consumer_mapping
            && let Some(consumer) = consumer_index.find_by_identity(username)
            && ctx.identified_consumer.is_none()
        {
            debug!(
                "ldap_auth: mapped LDAP user '{}' to consumer '{}'",
                username, consumer.username
            );
            ctx.identified_consumer = Some(consumer);
        }
    }
}
