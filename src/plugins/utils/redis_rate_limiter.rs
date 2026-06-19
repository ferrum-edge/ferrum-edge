//! Shared Redis-backed rate limiting client for plugins.
//!
//! When a rate limiting plugin is configured with `"sync_mode": "redis"`, it uses
//! this shared client to store counters in Redis instead of in-memory DashMaps.
//! This enables centralized rate limiting across multiple data plane instances.
//!
//! # Redis protocol compatibility
//!
//! Uses the standard Redis protocol (RESP), so it works with Redis, Valkey,
//! DragonflyDB, KeyDB, Garnet, or any RESP-compatible server.
//!
//! # Algorithm
//!
//! Uses a **two-window weighted approximation** for sliding window rate limiting:
//!
//! 1. Two fixed windows are maintained: the current window and the previous window.
//! 2. The effective count = `prev_count * (1 - elapsed_fraction) + current_count`.
//! 3. This provides smooth rate limiting without boundary bursts.
//!
//! This is the same approach used by Cloudflare, Kong, and Nginx — no Lua scripts,
//! just native Redis `INCR`/`GET`/`EXPIRE` commands pipelined for efficiency.
//!
//! # DNS
//!
//! When the gateway's `DnsCache` is available, Redis hostnames are resolved through
//! it — sharing the pre-warmed cache, TTL management, stale-while-revalidate, and
//! background refresh with all other gateway DNS lookups. The resolved IP is used
//! for non-TLS connections; TLS connections keep the original hostname for SNI but
//! pre-warm the DNS cache entry.
//!
//! # TLS
//!
//! Supports TLS via `rediss://` URL scheme (note the double-s). CA verification
//! and skip-verify are inherited from the gateway-level TLS settings.
//!
//! # Resilience
//!
//! If Redis becomes unreachable, the client marks itself unavailable and the
//! plugin falls back to local in-memory rate limiting. A background task
//! periodically pings Redis to detect recovery.

use crate::dns::DnsCache;
use crate::tls::source::{CertSource, MaterialKind, load_material_blocking};
use arc_swap::ArcSwap;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;
use tracing::{info, warn};
use url::{Host, Url};

/// Configuration parsed from a plugin's JSON config for Redis connectivity.
///
/// TLS verification uses the gateway-level settings (`FERRUM_TLS_CA_BUNDLE_PATH`,
/// `FERRUM_TLS_NO_VERIFY`) rather than per-plugin overrides, ensuring all outbound
/// connections share a single CA trust chain.
#[derive(Debug, Clone)]
#[allow(dead_code)] // pool_size, connect_timeout_seconds reserved for connection tuning
pub struct RedisConfig {
    /// Redis connection URL (e.g., `redis://host:6379/0` or `rediss://host:6380/0` for TLS).
    pub url: String,
    /// Enable TLS for the Redis connection. When true and the URL uses `redis://`,
    /// it is automatically upgraded to `rediss://`.
    pub tls: bool,
    /// Key prefix for all Redis keys (e.g., `"ferrum:rate_limiting"`).
    pub key_prefix: String,
    /// Connection pool size (number of multiplexed connections).
    pub pool_size: usize,
    /// Redis connection timeout in seconds.
    pub connect_timeout_seconds: u64,
    /// Interval in seconds for health check pings when Redis is marked unavailable.
    pub health_check_interval_seconds: u64,
    /// Redis username for ACL-based authentication (Redis 6+).
    ///
    /// When set, the value is injected into the parsed connection info before the
    /// client connects, overriding any user-info component already present in
    /// [`RedisConfig::url`]. To prefer URL-embedded credentials, leave this `None`
    /// and encode the userinfo directly in the URL (e.g., `redis://user:pass@host`).
    pub username: Option<String>,
    /// Redis password for authentication.
    ///
    /// When set, the value is injected into the parsed connection info before the
    /// client connects, overriding any user-info component already present in
    /// [`RedisConfig::url`]. To prefer URL-embedded credentials, leave this `None`
    /// and encode the userinfo directly in the URL (e.g., `redis://:pass@host`).
    pub password: Option<String>,
}

impl RedisConfig {
    /// Parse Redis configuration from a plugin's JSON config.
    ///
    /// Returns `Ok(None)` if `sync_mode` is absent or `"local"`.
    pub fn from_plugin_config(
        config: &serde_json::Value,
        default_prefix: &str,
    ) -> Result<Option<Self>, String> {
        let object = config
            .as_object()
            .ok_or_else(|| format!("redis rate limiter config must be an object, got: {config}"))?;

        let sync_mode = parse_optional_string(object, "sync_mode")?
            .unwrap_or("local")
            .to_ascii_lowercase();
        match sync_mode.as_str() {
            "local" => return Ok(None),
            "redis" => {}
            other => {
                return Err(format!(
                    "redis rate limiter: 'sync_mode' must be 'local' or 'redis', got: {other:?}"
                ));
            }
        }

        let url = parse_optional_string(object, "redis_url")?.ok_or_else(|| {
            "redis rate limiter: 'redis_url' is required when sync_mode='redis'".to_string()
        })?;
        if url.is_empty() {
            return Err(
                "redis rate limiter: 'redis_url' must be non-empty when sync_mode='redis'"
                    .to_string(),
            );
        }
        validate_redis_url(url)?;

        let tls = parse_optional_bool(object, "redis_tls")?.unwrap_or(false);
        let key_prefix = parse_optional_string(object, "redis_key_prefix")?
            .unwrap_or(default_prefix)
            .to_string();
        if key_prefix.is_empty() {
            return Err("redis rate limiter: 'redis_key_prefix' must be non-empty".to_string());
        }

        let pool_size = parse_optional_u64(object, "redis_pool_size")?.unwrap_or(4);
        if pool_size == 0 {
            return Err(
                "redis rate limiter: 'redis_pool_size' must be greater than zero".to_string(),
            );
        }
        let pool_size = usize::try_from(pool_size)
            .map_err(|_| "redis rate limiter: 'redis_pool_size' is too large".to_string())?;

        let connect_timeout_seconds =
            parse_optional_u64(object, "redis_connect_timeout_seconds")?.unwrap_or(5);
        if connect_timeout_seconds == 0 {
            return Err(
                "redis rate limiter: 'redis_connect_timeout_seconds' must be greater than zero"
                    .to_string(),
            );
        }

        let health_check_interval_seconds =
            parse_optional_u64(object, "redis_health_check_interval_seconds")?.unwrap_or(5);
        if health_check_interval_seconds == 0 {
            return Err(
                "redis rate limiter: 'redis_health_check_interval_seconds' must be greater than zero"
                    .to_string(),
            );
        }

        let username = parse_optional_string(object, "redis_username")?.map(ToString::to_string);
        let password = parse_optional_string(object, "redis_password")?.map(ToString::to_string);

        Ok(Some(RedisConfig {
            url: url.to_string(),
            tls,
            key_prefix,
            pool_size,
            connect_timeout_seconds,
            health_check_interval_seconds,
            username,
            password,
        }))
    }

    /// Build the effective Redis URL, upgrading to TLS scheme if needed.
    fn effective_url(&self) -> String {
        if self.tls && self.url.starts_with("redis://") {
            self.url.replacen("redis://", "rediss://", 1)
        } else {
            self.url.clone()
        }
    }

    /// Extract the hostname from the Redis URL for DNS pre-warming.
    ///
    /// Parses the URL to extract just the hostname (no port, no scheme).
    /// Returns `None` if the URL cannot be parsed or uses an IP address directly.
    pub fn hostname(&self) -> Option<String> {
        let url = Url::parse(&self.effective_url()).ok()?;
        let host = normalized_url_hostname(&url)?;

        // Skip if it's already an IP address
        if host.parse::<std::net::IpAddr>().is_ok() {
            return None;
        }

        Some(host)
    }

    /// Build a Redis URL with a resolved IP address substituted for the hostname.
    ///
    /// For non-TLS connections, replacing the hostname with a resolved IP avoids
    /// the redis crate doing its own DNS resolution, ensuring all DNS goes through
    /// the gateway's shared cache.
    ///
    /// For TLS connections, the hostname must be preserved for SNI verification,
    /// so this returns the original URL unchanged.
    pub(crate) fn url_with_resolved_ip(&self, resolved_ip: std::net::IpAddr) -> String {
        let url = self.effective_url();

        // Don't replace hostname for TLS — SNI needs the original hostname
        if url.starts_with("rediss://") {
            return url;
        }

        let mut parsed = match Url::parse(&url) {
            Ok(parsed) => parsed,
            Err(_) => return url,
        };

        if parsed.host_str().is_none() {
            return url;
        }

        if parsed.set_ip_host(resolved_ip).is_err() {
            return url;
        }

        parsed.to_string()
    }
}

fn validate_redis_url(raw_url: &str) -> Result<(), String> {
    let parsed = Url::parse(raw_url)
        .map_err(|e| format!("redis rate limiter: 'redis_url' must be a valid URL: {e}"))?;
    match parsed.scheme() {
        "redis" | "rediss" => {}
        scheme => {
            return Err(format!(
                "redis rate limiter: 'redis_url' scheme must be redis or rediss, got: {scheme}"
            ));
        }
    }
    if !has_non_empty_authority(raw_url) || normalized_url_hostname(&parsed).is_none() {
        return Err("redis rate limiter: 'redis_url' must include a hostname".to_string());
    }
    Ok(())
}

fn has_non_empty_authority(raw_url: &str) -> bool {
    raw_url
        .split_once("://")
        .and_then(|(_, rest)| rest.split(['/', '?', '#']).next())
        .is_some_and(|authority| !authority.is_empty())
}

fn normalized_url_hostname(url: &Url) -> Option<String> {
    match url.host()? {
        Host::Domain(host) if !host.is_empty() => Some(host.to_string()),
        Host::Ipv4(host) => Some(host.to_string()),
        Host::Ipv6(host) => Some(host.to_string()),
        _ => None,
    }
}

fn parse_optional_string<'a>(
    object: &'a serde_json::Map<String, serde_json::Value>,
    field: &str,
) -> Result<Option<&'a str>, String> {
    object
        .get(field)
        .map(|value| {
            value
                .as_str()
                .ok_or_else(|| format!("redis rate limiter: '{field}' must be a string"))
        })
        .transpose()
}

fn parse_optional_bool(
    object: &serde_json::Map<String, serde_json::Value>,
    field: &str,
) -> Result<Option<bool>, String> {
    object
        .get(field)
        .map(|value| {
            value
                .as_bool()
                .ok_or_else(|| format!("redis rate limiter: '{field}' must be a boolean"))
        })
        .transpose()
}

fn parse_optional_u64(
    object: &serde_json::Map<String, serde_json::Value>,
    field: &str,
) -> Result<Option<u64>, String> {
    object
        .get(field)
        .map(|value| {
            value
                .as_u64()
                .ok_or_else(|| format!("redis rate limiter: '{field}' must be an integer"))
        })
        .transpose()
}

/// A Redis-backed rate limiter client shared across plugin instances.
///
/// Provides atomic counter operations for rate limiting using native Redis
/// commands (no Lua scripts). Automatically falls back to local mode when
/// Redis is unreachable and recovers when connectivity is restored.
///
/// When a `DnsCache` is provided, Redis hostnames are resolved through the
/// gateway's shared DNS cache. On connection failure, the connection is cleared
/// so the next attempt re-resolves DNS (handling IP changes gracefully).
pub struct RedisRateLimitClient {
    /// The Redis connection manager (auto-reconnecting, multiplexed).
    /// Uses ArcSwap for lock-free reads on the hot path. The connect_mutex
    /// serializes connection establishment on the slow path only.
    connection: ArcSwap<Option<redis::aio::ConnectionManager>>,
    /// Mutex for serializing connection establishment (slow path only).
    connect_mutex: tokio::sync::Mutex<()>,
    /// Configuration for connecting to Redis.
    config: RedisConfig,
    /// The gateway's shared DNS cache for resolving Redis hostnames.
    dns_cache: Option<DnsCache>,
    /// Whether Redis is currently reachable.
    available: Arc<AtomicBool>,
    /// Whether the background health checker has been started.
    health_checker_started: AtomicBool,
    /// Gateway-level TLS no-verify setting (`FERRUM_TLS_NO_VERIFY`).
    tls_no_verify: bool,
    /// Pre-read CA bundle PEM bytes from `FERRUM_TLS_CA_BUNDLE_PATH`.
    /// Loaded once at construction to avoid filesystem reads on every connection.
    tls_ca_bundle_pem: Option<Vec<u8>>,
}

impl RedisRateLimitClient {
    /// Create a new Redis rate limit client.
    ///
    /// The connection is established lazily on first use to avoid blocking
    /// the plugin constructor (which is synchronous).
    ///
    /// TLS settings are inherited from the gateway's global configuration
    /// (`FERRUM_TLS_CA_BUNDLE_PATH`, `FERRUM_TLS_NO_VERIFY`) so all outbound
    /// connections share a single CA trust chain.
    ///
    /// When `dns_cache` is provided, Redis hostnames are resolved through the
    /// gateway's shared DNS cache instead of the system resolver.
    pub fn new(
        config: RedisConfig,
        dns_cache: Option<DnsCache>,
        tls_no_verify: bool,
        tls_ca_bundle_path: Option<&str>,
    ) -> Self {
        let tls_ca_bundle_pem = if !tls_no_verify {
            tls_ca_bundle_path.and_then(|path| {
                let source = CertSource::parse(path, MaterialKind::CaBundle);
                match load_material_blocking(&source, MaterialKind::CaBundle) {
                    Ok(material) => Some(material.bytes.expose_secret().to_vec()),
                    Err(e) => {
                        warn!(
                            error = %e,
                            "Failed to load CA bundle for Redis TLS — using system root CAs"
                        );
                        None
                    }
                }
            })
        } else {
            None
        };

        Self {
            connection: ArcSwap::from_pointee(None),
            connect_mutex: tokio::sync::Mutex::new(()),
            config,
            dns_cache,
            available: Arc::new(AtomicBool::new(true)),
            health_checker_started: AtomicBool::new(false),
            tls_no_verify,
            tls_ca_bundle_pem,
        }
    }

    /// Whether Redis is currently available.
    ///
    /// This is an O(1) atomic load — safe to call on every request.
    pub fn is_available(&self) -> bool {
        self.available.load(Ordering::Relaxed)
    }

    /// Resolve the Redis hostname via the gateway's DNS cache and build the
    /// connection URL with the resolved IP (for non-TLS) or the original
    /// hostname (for TLS, to preserve SNI).
    async fn resolve_url(&self) -> String {
        if let Some(ref dns_cache) = self.dns_cache
            && let Some(hostname) = self.config.hostname()
        {
            match dns_cache.resolve(&hostname, None, None).await {
                Ok(ip) => {
                    return self.config.url_with_resolved_ip(ip);
                }
                Err(e) => {
                    warn!(
                        hostname = %hostname,
                        error = %e,
                        "DNS cache resolution failed for Redis host — using hostname directly"
                    );
                }
            }
        }
        self.config.effective_url()
    }

    /// Build a Redis client with proper TLS configuration.
    ///
    /// When TLS is enabled (`rediss://` URL), applies:
    /// - Custom CA bundle from `FERRUM_TLS_CA_BUNDLE_PATH` via `build_with_tls`
    /// - Skip-verify from `FERRUM_TLS_NO_VERIFY` via `#insecure` URL fragment
    ///
    /// ACL credentials from [`RedisConfig::username`] / [`RedisConfig::password`]
    /// are injected into the parsed [`redis::ConnectionInfo`] so that both the
    /// plain and TLS code paths perform `AUTH` / `HELLO` with the configured
    /// principal. When set, these fields override any user-info already encoded
    /// in [`RedisConfig::url`].
    pub(crate) fn build_client(&self, url: &str) -> Result<redis::Client, redis::RedisError> {
        let is_tls = url.starts_with("rediss://");

        // Parse the URL into ConnectionInfo so we can inject ACL credentials.
        // The URL parser already handles user:pass@host, db numbers, and the
        // #insecure fragment; we only override credentials when the operator
        // configured `redis_username` / `redis_password` explicitly.
        let conn_info_url = if is_tls && self.tls_no_verify && !url.contains('#') {
            // Append #insecure so the URL parser sets ConnectionAddr::TcpTls.insecure = true
            format!("{url}#insecure")
        } else {
            url.to_string()
        };

        let conn_info = self.build_connection_info(&conn_info_url)?;

        if is_tls && (self.tls_ca_bundle_pem.is_some() || self.tls_no_verify) {
            redis::Client::build_with_tls(
                conn_info,
                redis::TlsCertificates {
                    client_tls: None,
                    root_cert: self.tls_ca_bundle_pem.clone(),
                },
            )
        } else {
            redis::Client::open(conn_info)
        }
    }

    /// Parse a Redis URL into a [`redis::ConnectionInfo`] with ACL credentials
    /// from [`RedisConfig`] overriding any URL-embedded user-info.
    fn build_connection_info(&self, url: &str) -> Result<redis::ConnectionInfo, redis::RedisError> {
        use redis::IntoConnectionInfo;

        let mut conn_info = url.into_connection_info()?;

        if self.config.username.is_some() || self.config.password.is_some() {
            // Clone the parsed redis settings (preserves db number, protocol, etc.)
            // and override only the username/password before reinstalling them.
            let mut redis_settings = conn_info.redis_settings().clone();
            if let Some(username) = self.config.username.as_deref() {
                redis_settings = redis_settings.set_username(username);
            }
            if let Some(password) = self.config.password.as_deref() {
                redis_settings = redis_settings.set_password(password);
            }
            conn_info = conn_info.set_redis_settings(redis_settings);
        }

        Ok(conn_info)
    }

    /// Get or create the Redis connection, establishing it lazily.
    ///
    /// Fast path (hot): lock-free `ArcSwap::load()` — O(1) atomic load.
    /// Slow path (cold): `Mutex`-guarded connection establishment with double-check.
    async fn get_connection(&self) -> Option<redis::aio::ConnectionManager> {
        // Fast path: lock-free read via ArcSwap
        let guard = self.connection.load();
        if let Some(ref conn) = **guard {
            return Some(conn.clone());
        }
        drop(guard);

        // Slow path: serialize connection establishment
        let _lock = self.connect_mutex.lock().await;

        // Double-check after acquiring mutex
        let guard = self.connection.load();
        if let Some(ref conn) = **guard {
            return Some(conn.clone());
        }
        drop(guard);

        let url = self.resolve_url().await;
        let client = match self.build_client(&url) {
            Ok(c) => c,
            Err(e) => {
                warn!(
                    redis_url = %self.config.url,
                    error = %e,
                    "Failed to create Redis client for rate limiting"
                );
                self.mark_unavailable();
                self.start_health_checker_if_needed();
                return None;
            }
        };

        let connect_timeout = Duration::from_secs(self.config.connect_timeout_seconds);
        match tokio::time::timeout(connect_timeout, redis::aio::ConnectionManager::new(client))
            .await
        {
            Ok(Ok(manager)) => {
                self.available.store(true, Ordering::Relaxed);
                info!(
                    redis_url = %self.config.url,
                    key_prefix = %self.config.key_prefix,
                    "Redis rate limiting connected"
                );
                self.start_health_checker_if_needed();
                self.connection.store(Arc::new(Some(manager.clone())));
                Some(manager)
            }
            Ok(Err(e)) => {
                warn!(
                    redis_url = %self.config.url,
                    error = %e,
                    "Failed to connect to Redis for rate limiting — falling back to local"
                );
                self.mark_unavailable();
                self.start_health_checker_if_needed();
                None
            }
            Err(_) => {
                warn!(
                    redis_url = %self.config.url,
                    timeout_seconds = self.config.connect_timeout_seconds,
                    "Timed out connecting to Redis for rate limiting — falling back to local"
                );
                self.mark_unavailable();
                self.start_health_checker_if_needed();
                None
            }
        }
    }

    /// Clear the cached connection so the next `get_connection()` call
    /// re-resolves DNS and creates a fresh connection.
    fn clear_connection(&self) {
        self.connection.store(Arc::new(None));
    }

    /// Mark Redis as unavailable and clear the connection for re-resolution.
    fn mark_unavailable(&self) {
        self.available.store(false, Ordering::Relaxed);
        self.clear_connection();
    }

    /// Start a background task that periodically pings Redis to detect recovery.
    fn start_health_checker_if_needed(&self) {
        if self.health_checker_started.swap(true, Ordering::Relaxed) {
            return; // Already started
        }

        let available = self.available.clone();
        let config = self.config.clone();
        let dns_cache = self.dns_cache.clone();
        let interval = Duration::from_secs(self.config.health_check_interval_seconds);
        let tls_no_verify = self.tls_no_verify;
        let tls_ca_bundle_pem = self.tls_ca_bundle_pem.clone();

        tokio::spawn(async move {
            loop {
                tokio::time::sleep(interval).await;

                // Resolve the Redis hostname via the shared DNS cache
                let url = if let Some(ref dns_cache) = dns_cache
                    && let Some(hostname) = config.hostname()
                {
                    match dns_cache.resolve(&hostname, None, None).await {
                        Ok(ip) => config.url_with_resolved_ip(ip),
                        Err(_) => config.effective_url(),
                    }
                } else {
                    config.effective_url()
                };

                // Build the client with TLS settings matching the main connection.
                // ACL credentials from `config.username` / `config.password` are
                // injected via ConnectionInfo so health-check pings authenticate
                // with the same principal as the main connection.
                let result: Result<(), redis::RedisError> = async {
                    use redis::IntoConnectionInfo;
                    let is_tls = url.starts_with("rediss://");
                    let conn_info_url = if is_tls && tls_no_verify && !url.contains('#') {
                        format!("{url}#insecure")
                    } else {
                        url.clone()
                    };
                    let mut conn_info = conn_info_url.as_str().into_connection_info()?;
                    if config.username.is_some() || config.password.is_some() {
                        let mut redis_settings = conn_info.redis_settings().clone();
                        if let Some(u) = config.username.as_deref() {
                            redis_settings = redis_settings.set_username(u);
                        }
                        if let Some(p) = config.password.as_deref() {
                            redis_settings = redis_settings.set_password(p);
                        }
                        conn_info = conn_info.set_redis_settings(redis_settings);
                    }
                    let client = if is_tls && (tls_ca_bundle_pem.is_some() || tls_no_verify) {
                        redis::Client::build_with_tls(
                            conn_info,
                            redis::TlsCertificates {
                                client_tls: None,
                                root_cert: tls_ca_bundle_pem.clone(),
                            },
                        )?
                    } else {
                        redis::Client::open(conn_info)?
                    };
                    let mut conn = client.get_multiplexed_async_connection().await?;
                    redis::cmd("PING").query_async::<String>(&mut conn).await?;
                    Ok::<(), redis::RedisError>(())
                }
                .await;

                let was_available = available.load(Ordering::Relaxed);
                match result {
                    Ok(()) => {
                        if !was_available {
                            info!(
                                "Redis rate limiting recovered — switching back from local fallback"
                            );
                        }
                        available.store(true, Ordering::Relaxed);
                    }
                    Err(_) => {
                        if was_available {
                            warn!(
                                "Redis rate limiting health check failed — falling back to local"
                            );
                        }
                        available.store(false, Ordering::Relaxed);
                    }
                }
            }
        });
    }

    /// Increment a counter and set expiry. Returns the new count.
    ///
    /// Uses a Redis pipeline to send `INCR` + `EXPIRE` in a single round-trip.
    /// This is the core primitive for fixed-window rate limiting.
    pub async fn incr_with_expire(&self, key: &str, ttl_seconds: u64) -> Result<i64, ()> {
        let mut conn = self.get_connection().await.ok_or(())?;

        let result: Result<(i64,), redis::RedisError> = redis::pipe()
            .atomic()
            .cmd("INCR")
            .arg(key)
            .cmd("EXPIRE")
            .arg(key)
            .arg(ttl_seconds as i64)
            .ignore()
            .query_async(&mut conn)
            .await;

        match result {
            Ok((count,)) => {
                self.available.store(true, Ordering::Relaxed);
                Ok(count)
            }
            Err(e) => {
                warn!(
                    key = %key,
                    error = %e,
                    "Redis INCR+EXPIRE failed — falling back to local rate limiting"
                );
                self.mark_unavailable();
                Err(())
            }
        }
    }

    /// Read the previous sliding-window bucket, increment the current bucket,
    /// and set the current bucket expiry in one Redis transaction.
    ///
    /// The caller makes its allow/deny decision from the returned post-INCR
    /// current count, tying admission to the mutation even when many gateway
    /// instances race on the same key.
    pub async fn sliding_window_increment(
        &self,
        previous_key: &str,
        current_key: &str,
        ttl_seconds: u64,
    ) -> Result<(i64, i64), ()> {
        let mut conn = self.get_connection().await.ok_or(())?;

        let result: Result<(Option<i64>, i64), redis::RedisError> = redis::pipe()
            .atomic()
            .cmd("GET")
            .arg(previous_key)
            .cmd("INCR")
            .arg(current_key)
            .cmd("EXPIRE")
            .arg(current_key)
            .arg(ttl_seconds as i64)
            .ignore()
            .query_async(&mut conn)
            .await;

        match result {
            Ok((previous_count, current_count)) => {
                self.available.store(true, Ordering::Relaxed);
                Ok((previous_count.unwrap_or(0), current_count))
            }
            Err(e) => {
                warn!(
                    previous_key = %previous_key,
                    current_key = %current_key,
                    error = %e,
                    "Redis sliding-window GET+INCR+EXPIRE transaction failed — falling back to local rate limiting"
                );
                self.mark_unavailable();
                Err(())
            }
        }
    }

    /// Increment a counter by a specific amount and set expiry. Returns the new total.
    ///
    /// Uses a Redis pipeline to send `INCRBY` + `EXPIRE` in a single round-trip.
    /// Used by the AI token rate limiter where each request may consume a variable
    /// number of tokens.
    pub async fn incrby_with_expire(
        &self,
        key: &str,
        amount: i64,
        ttl_seconds: u64,
    ) -> Result<i64, ()> {
        let mut conn = self.get_connection().await.ok_or(())?;

        let result: Result<(i64,), redis::RedisError> = redis::pipe()
            .atomic()
            .cmd("INCRBY")
            .arg(key)
            .arg(amount)
            .cmd("EXPIRE")
            .arg(key)
            .arg(ttl_seconds as i64)
            .ignore()
            .query_async(&mut conn)
            .await;

        match result {
            Ok((count,)) => {
                self.available.store(true, Ordering::Relaxed);
                Ok(count)
            }
            Err(e) => {
                warn!(
                    key = %key,
                    error = %e,
                    "Redis INCRBY+EXPIRE failed — falling back to local rate limiting"
                );
                self.mark_unavailable();
                Err(())
            }
        }
    }

    /// Increment one counter by 1 and another by a specific amount in a single
    /// pipelined round-trip. Returns `(new_count, new_total)`.
    pub async fn incr_and_incrby_with_expire(
        &self,
        count_key: &str,
        total_key: &str,
        amount: i64,
        ttl_seconds: u64,
    ) -> Result<(i64, i64), ()> {
        let mut conn = self.get_connection().await.ok_or(())?;

        let result: Result<(i64, i64), redis::RedisError> = redis::pipe()
            .atomic()
            .cmd("INCR")
            .arg(count_key)
            .cmd("INCRBY")
            .arg(total_key)
            .arg(amount)
            .cmd("EXPIRE")
            .arg(count_key)
            .arg(ttl_seconds as i64)
            .ignore()
            .cmd("EXPIRE")
            .arg(total_key)
            .arg(ttl_seconds as i64)
            .ignore()
            .query_async(&mut conn)
            .await;

        match result {
            Ok((count, total)) => {
                self.available.store(true, Ordering::Relaxed);
                Ok((count, total))
            }
            Err(e) => {
                warn!(
                    count_key = %count_key,
                    total_key = %total_key,
                    error = %e,
                    "Redis INCR+INCRBY+EXPIRE pipeline failed — falling back to local rate limiting"
                );
                self.mark_unavailable();
                Err(())
            }
        }
    }

    /// Get two counters in a single pipelined round-trip. Returns (0, 0) for missing keys.
    ///
    /// Used by the AI token rate limiter to fetch both the previous and current
    /// window counters without two separate round-trips.
    pub async fn get_two_counters(&self, key1: &str, key2: &str) -> Result<(i64, i64), ()> {
        let mut conn = self.get_connection().await.ok_or(())?;

        let result: Result<(Option<i64>, Option<i64>), redis::RedisError> = redis::pipe()
            .cmd("GET")
            .arg(key1)
            .cmd("GET")
            .arg(key2)
            .query_async(&mut conn)
            .await;

        match result {
            Ok((v1, v2)) => {
                self.available.store(true, Ordering::Relaxed);
                Ok((v1.unwrap_or(0), v2.unwrap_or(0)))
            }
            Err(e) => {
                warn!(
                    error = %e,
                    "Redis GET+GET pipeline failed — falling back to local rate limiting"
                );
                self.mark_unavailable();
                Err(())
            }
        }
    }

    /// Get a raw byte value from Redis.
    ///
    /// Used by plugins that need arbitrary key-value storage (e.g., request
    /// deduplication, AI semantic cache) rather than rate limiting counters.
    pub async fn get_bytes(&self, key: &str) -> Result<Option<Vec<u8>>, ()> {
        let mut conn = self.get_connection().await.ok_or(())?;

        let result: Result<Option<Vec<u8>>, redis::RedisError> =
            redis::cmd("GET").arg(key).query_async(&mut conn).await;

        match result {
            Ok(val) => {
                self.available.store(true, Ordering::Relaxed);
                Ok(val)
            }
            Err(e) => {
                warn!(
                    key = %key,
                    error = %e,
                    "Redis GET failed"
                );
                self.mark_unavailable();
                Err(())
            }
        }
    }

    /// Set a raw byte value in Redis with a TTL.
    ///
    /// Uses a pipelined `SET` + `EXPIRE` in a single round-trip.
    /// Used by plugins that need arbitrary key-value storage.
    pub async fn set_bytes_with_expire(
        &self,
        key: &str,
        value: &[u8],
        ttl_seconds: u64,
    ) -> Result<(), ()> {
        let mut conn = self.get_connection().await.ok_or(())?;

        let result: Result<(), redis::RedisError> = redis::pipe()
            .atomic()
            .cmd("SET")
            .arg(key)
            .arg(value)
            .ignore()
            .cmd("EXPIRE")
            .arg(key)
            .arg(ttl_seconds as i64)
            .ignore()
            .query_async(&mut conn)
            .await;

        match result {
            Ok(()) => {
                self.available.store(true, Ordering::Relaxed);
                Ok(())
            }
            Err(e) => {
                warn!(
                    key = %key,
                    error = %e,
                    "Redis SET+EXPIRE failed"
                );
                self.mark_unavailable();
                Err(())
            }
        }
    }

    /// Set a raw byte value only if the key does not already exist, with a TTL.
    ///
    /// Returns `Ok(true)` when the caller acquired the key, `Ok(false)` when an
    /// existing key prevented the write, and `Err(())` when Redis is unavailable.
    pub async fn set_bytes_nx_with_expire(
        &self,
        key: &str,
        value: &[u8],
        ttl_seconds: u64,
    ) -> Result<bool, ()> {
        let mut conn = self.get_connection().await.ok_or(())?;

        let result: Result<Option<String>, redis::RedisError> = redis::cmd("SET")
            .arg(key)
            .arg(value)
            .arg("NX")
            .arg("EX")
            .arg(ttl_seconds as i64)
            .query_async(&mut conn)
            .await;

        match result {
            Ok(value) => {
                self.available.store(true, Ordering::Relaxed);
                Ok(value.is_some())
            }
            Err(e) => {
                warn!(
                    key = %key,
                    error = %e,
                    "Redis SET NX EX failed"
                );
                self.mark_unavailable();
                Err(())
            }
        }
    }

    /// Delete a key only when its current byte value exactly matches `expected`.
    ///
    /// Uses optimistic transactions (`WATCH` + `MULTI`/`EXEC`) instead of Lua so
    /// RESP-compatible Redis backends that do not support scripting can still
    /// use ownership-token lock release.
    pub async fn delete_if_value_matches(&self, key: &str, expected: &[u8]) -> Result<bool, ()> {
        let mut conn = self.get_connection().await.ok_or(())?;

        let watch_result: Result<(), redis::RedisError> =
            redis::cmd("WATCH").arg(key).query_async(&mut conn).await;
        if let Err(e) = watch_result {
            warn!(
                key = %key,
                error = %e,
                "Redis WATCH failed"
            );
            self.mark_unavailable();
            return Err(());
        }

        let current: Result<Option<Vec<u8>>, redis::RedisError> =
            redis::cmd("GET").arg(key).query_async(&mut conn).await;
        match current {
            Ok(Some(current)) if current == expected => {}
            Ok(_) => {
                let _: Result<(), redis::RedisError> =
                    redis::cmd("UNWATCH").query_async(&mut conn).await;
                self.available.store(true, Ordering::Relaxed);
                return Ok(false);
            }
            Err(e) => {
                warn!(
                    key = %key,
                    error = %e,
                    "Redis compare-delete GET failed"
                );
                self.mark_unavailable();
                return Err(());
            }
        }

        let result: Result<Option<(i64,)>, redis::RedisError> = redis::pipe()
            .atomic()
            .cmd("DEL")
            .arg(key)
            .query_async(&mut conn)
            .await;

        match result {
            Ok(Some((deleted,))) => {
                self.available.store(true, Ordering::Relaxed);
                Ok(deleted > 0)
            }
            Ok(None) => {
                self.available.store(true, Ordering::Relaxed);
                Ok(false)
            }
            Err(e) => {
                warn!(
                    key = %key,
                    error = %e,
                    "Redis compare-delete transaction failed"
                );
                self.mark_unavailable();
                Err(())
            }
        }
    }

    /// Build a full Redis key with the configured prefix.
    pub fn make_key(&self, components: &[&str]) -> String {
        let mut key = self.config.key_prefix.clone();
        for component in components {
            key.push(':');
            key.push_str(component);
        }
        key
    }

    /// Compute the window index for a given epoch time and window duration.
    ///
    /// Window index = `epoch_seconds / window_seconds`. All gateway instances
    /// sharing the same Redis will use the same window boundaries since they
    /// share the system epoch clock.
    pub fn window_index(window_seconds: u64) -> u64 {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        now / window_seconds.max(1)
    }

    /// Compute the elapsed fraction within the current window (0.0 to 1.0).
    ///
    /// Used for the sliding window weighted approximation.
    pub fn elapsed_fraction(window_seconds: u64) -> f64 {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        let window = window_seconds.max(1);
        (now % window) as f64 / window as f64
    }

    /// Return the Redis hostname for DNS pre-warming, if applicable.
    pub fn warmup_hostname(&self) -> Option<String> {
        self.config.hostname()
    }
}

impl std::fmt::Debug for RedisRateLimitClient {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RedisRateLimitClient")
            .field("key_prefix", &self.config.key_prefix)
            .field("available", &self.available.load(Ordering::Relaxed))
            .finish()
    }
}
