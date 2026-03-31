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
//! Supports TLS via `rediss://` URL scheme (note the double-s). Custom CA certs
//! and skip-verify are configurable per plugin instance.
//!
//! # Resilience
//!
//! If Redis becomes unreachable, the client marks itself unavailable and the
//! plugin falls back to local in-memory rate limiting. A background task
//! periodically pings Redis to detect recovery.

use crate::dns::DnsCache;
use arc_swap::ArcSwap;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;
use tracing::{info, warn};

/// Configuration parsed from a plugin's JSON config for Redis connectivity.
///
/// TLS verification uses the gateway-level settings (`FERRUM_TLS_CA_BUNDLE_PATH`,
/// `FERRUM_TLS_NO_VERIFY`) rather than per-plugin overrides, ensuring all outbound
/// connections share a single CA trust chain.
#[derive(Debug, Clone)]
#[allow(dead_code)] // pool_size, connect_timeout_seconds, username, password reserved for connection tuning
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
    pub username: Option<String>,
    /// Redis password for authentication.
    pub password: Option<String>,
}

impl RedisConfig {
    /// Parse Redis configuration from a plugin's JSON config.
    ///
    /// Returns `None` if `sync_mode` is not `"redis"` or if `redis_url` is missing.
    pub fn from_plugin_config(config: &serde_json::Value, default_prefix: &str) -> Option<Self> {
        let sync_mode = config["sync_mode"].as_str().unwrap_or("local");
        if sync_mode != "redis" {
            return None;
        }

        let url = config["redis_url"].as_str().map(|s| s.to_string())?;
        if url.is_empty() {
            warn!(
                "sync_mode is 'redis' but redis_url is empty — falling back to local rate limiting"
            );
            return None;
        }

        let tls = config["redis_tls"].as_bool().unwrap_or(false);
        let key_prefix = config["redis_key_prefix"]
            .as_str()
            .unwrap_or(default_prefix)
            .to_string();
        let pool_size = config["redis_pool_size"].as_u64().unwrap_or(4) as usize;
        let connect_timeout_seconds = config["redis_connect_timeout_seconds"]
            .as_u64()
            .unwrap_or(5);
        let health_check_interval_seconds = config["redis_health_check_interval_seconds"]
            .as_u64()
            .unwrap_or(5);
        let username = config["redis_username"].as_str().map(|s| s.to_string());
        let password = config["redis_password"].as_str().map(|s| s.to_string());

        Some(RedisConfig {
            url,
            tls,
            key_prefix,
            pool_size,
            connect_timeout_seconds,
            health_check_interval_seconds,
            username,
            password,
        })
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
        let url = self.effective_url();
        // Strip scheme (redis:// or rediss://)
        let after_scheme = url
            .strip_prefix("rediss://")
            .or_else(|| url.strip_prefix("redis://"))?;
        // Strip credentials (user:pass@)
        let after_auth = after_scheme
            .rsplit_once('@')
            .map(|(_, rest)| rest)
            .unwrap_or(after_scheme);
        // IPv6 bracket notation (e.g., [::1]:6379) — always an IP, return None
        if after_auth.starts_with('[') {
            return None;
        }
        // Extract host (before : or / or end of string)
        let host = after_auth
            .split_once(':')
            .map(|(h, _)| h)
            .or_else(|| after_auth.split_once('/').map(|(h, _)| h))
            .unwrap_or(after_auth);

        if host.is_empty() {
            return None;
        }

        // Skip if it's already an IP address
        if host.parse::<std::net::IpAddr>().is_ok() {
            return None;
        }

        Some(host.to_string())
    }

    /// Build a Redis URL with a resolved IP address substituted for the hostname.
    ///
    /// For non-TLS connections, replacing the hostname with a resolved IP avoids
    /// the redis crate doing its own DNS resolution, ensuring all DNS goes through
    /// the gateway's shared cache.
    ///
    /// For TLS connections, the hostname must be preserved for SNI verification,
    /// so this returns the original URL unchanged.
    fn url_with_resolved_ip(&self, resolved_ip: std::net::IpAddr) -> String {
        let url = self.effective_url();

        // Don't replace hostname for TLS — SNI needs the original hostname
        if url.starts_with("rediss://") {
            return url;
        }

        if let Some(hostname) = self.hostname() {
            // IPv6 resolved addresses need bracket notation in URLs
            let ip_str = match resolved_ip {
                std::net::IpAddr::V6(v6) => format!("[{v6}]"),
                std::net::IpAddr::V4(v4) => v4.to_string(),
            };
            url.replacen(&hostname, &ip_str, 1)
        } else {
            url
        }
    }
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
            tls_ca_bundle_path.and_then(|path| match std::fs::read(path) {
                Ok(pem) => Some(pem),
                Err(e) => {
                    warn!(
                        path = %path,
                        error = %e,
                        "Failed to read CA bundle for Redis TLS — using system root CAs"
                    );
                    None
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
    fn build_client(&self, url: &str) -> Result<redis::Client, redis::RedisError> {
        let is_tls = url.starts_with("rediss://");

        if is_tls && (self.tls_ca_bundle_pem.is_some() || self.tls_no_verify) {
            // Apply TLS customization via the redis crate's build_with_tls API
            let effective_url = if self.tls_no_verify {
                // Append #insecure fragment to skip TLS cert verification
                if url.contains('#') {
                    url.to_string()
                } else {
                    format!("{url}#insecure")
                }
            } else {
                url.to_string()
            };

            redis::Client::build_with_tls(
                effective_url.as_str(),
                redis::TlsCertificates {
                    client_tls: None,
                    root_cert: self.tls_ca_bundle_pem.clone(),
                },
            )
        } else {
            redis::Client::open(url)
        }
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
                self.start_health_checker_if_needed();
                return None;
            }
        };

        match redis::aio::ConnectionManager::new(client).await {
            Ok(manager) => {
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
            Err(e) => {
                warn!(
                    redis_url = %self.config.url,
                    error = %e,
                    "Failed to connect to Redis for rate limiting — falling back to local"
                );
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

                // Build the client with TLS settings matching the main connection
                let result: Result<(), redis::RedisError> = async {
                    let is_tls = url.starts_with("rediss://");
                    let client = if is_tls && (tls_ca_bundle_pem.is_some() || tls_no_verify) {
                        let effective_url = if tls_no_verify {
                            if url.contains('#') {
                                url.clone()
                            } else {
                                format!("{url}#insecure")
                            }
                        } else {
                            url.clone()
                        };
                        redis::Client::build_with_tls(
                            effective_url.as_str(),
                            redis::TlsCertificates {
                                client_tls: None,
                                root_cert: tls_ca_bundle_pem.clone(),
                            },
                        )?
                    } else {
                        redis::Client::open(url.as_str())?
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

    /// Sliding window approximation using two fixed windows.
    ///
    /// Fetches the previous window's count and increments the current window's count
    /// in a single pipeline round-trip. Returns the weighted approximation result.
    ///
    /// The caller computes: `effective = prev * (1 - elapsed_fraction) + current`
    /// to get a smooth sliding window estimate.
    pub async fn sliding_window_check(
        &self,
        prev_key: &str,
        curr_key: &str,
        ttl_seconds: u64,
        elapsed_fraction: f64,
        limit: u64,
    ) -> Result<SlidingWindowResult, ()> {
        let mut conn = self.get_connection().await.ok_or(())?;

        // Pipeline: GET prev + INCR curr + EXPIRE curr
        let result: Result<(Option<i64>, i64), redis::RedisError> = redis::pipe()
            .atomic()
            .cmd("GET")
            .arg(prev_key)
            .cmd("INCR")
            .arg(curr_key)
            .cmd("EXPIRE")
            .arg(curr_key)
            .arg(ttl_seconds as i64)
            .ignore()
            .query_async(&mut conn)
            .await;

        match result {
            Ok((prev_count, curr_count)) => {
                self.available.store(true, Ordering::Relaxed);
                let prev = prev_count.unwrap_or(0) as f64;
                let weighted = prev * (1.0 - elapsed_fraction) + curr_count as f64;

                Ok(SlidingWindowResult {
                    allowed: weighted <= limit as f64,
                    remaining: (limit as f64 - weighted).max(0.0) as u64,
                })
            }
            Err(e) => {
                warn!(
                    error = %e,
                    "Redis sliding window check failed — falling back to local rate limiting"
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

/// Result of a sliding window rate limit check.
pub struct SlidingWindowResult {
    /// Whether the request is allowed (weighted count <= limit).
    pub allowed: bool,
    /// Approximate remaining requests before the limit is reached.
    pub remaining: u64,
}

impl std::fmt::Debug for RedisRateLimitClient {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RedisRateLimitClient")
            .field("key_prefix", &self.config.key_prefix)
            .field("available", &self.available.load(Ordering::Relaxed))
            .finish()
    }
}
