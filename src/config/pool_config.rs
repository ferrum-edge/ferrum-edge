//! Global connection pool configuration
//! Provides environment variable defaults and proxy-level overrides

use std::env;

/// Minimum allowed value for `max_idle_per_host`.
///
/// Setting this too low causes excessive connection churn under load — each
/// request that cannot reuse an idle connection must open a new TCP connection
/// to the backend, dramatically increasing latency and error rates.
pub const MIN_IDLE_PER_HOST: usize = 4;

/// Maximum allowed value for `max_idle_per_host`.
///
/// Excessively high values waste memory (each idle connection holds a kernel
/// socket buffer) and file descriptors.  On most systems the practical ceiling
/// is the per-process file-descriptor limit (`ulimit -n`), but values above
/// 1024 rarely help because the backend itself becomes the bottleneck.
pub const MAX_IDLE_PER_HOST: usize = 1024;

/// Global connection pool configuration from environment variables
#[derive(Debug, Clone)]
pub struct PoolConfig {
    pub max_idle_per_host: usize,
    pub idle_timeout_seconds: u64,
    pub enable_http_keep_alive: bool,
    /// Controls HTTP/2 keep-alive PING frames on backend connections.
    /// When true, reqwest sends periodic PING frames to keep HTTP/2 connections alive.
    /// HTTP/2 itself is auto-negotiated via ALPN on HTTPS connections — this does NOT
    /// force h2c (cleartext HTTP/2) via http2_prior_knowledge().
    pub enable_http2: bool,
    /// Number of parallel backend HTTP/2 connections to keep per host.
    /// A small shard set reduces lock contention on a single multiplexed h2 sender
    /// under high concurrency while still preserving connection reuse.
    pub http2_connections_per_host: usize,
    pub tcp_keepalive_seconds: u64,
    pub http2_keep_alive_interval_seconds: u64,
    pub http2_keep_alive_timeout_seconds: u64,
}

impl Default for PoolConfig {
    fn default() -> Self {
        Self {
            max_idle_per_host: 64,
            idle_timeout_seconds: 90,
            enable_http_keep_alive: true,
            enable_http2: true,
            http2_connections_per_host: std::thread::available_parallelism()
                .map(|n| n.get().clamp(2, 8))
                .unwrap_or(4),
            tcp_keepalive_seconds: 60,
            http2_keep_alive_interval_seconds: 30,
            http2_keep_alive_timeout_seconds: 45, // More reasonable timeout comparable to HTTP read timeout
        }
    }
}

impl PoolConfig {
    /// Create pool configuration from environment variables with defaults
    pub fn from_env() -> Self {
        let mut config = Self::default();

        // Read from environment variables
        if let Ok(val) = env::var("FERRUM_POOL_MAX_IDLE_PER_HOST")
            && let Ok(parsed) = val.parse::<usize>()
        {
            config.max_idle_per_host = parsed;
        }

        if let Ok(val) = env::var("FERRUM_POOL_IDLE_TIMEOUT_SECONDS")
            && let Ok(parsed) = val.parse::<u64>()
        {
            config.idle_timeout_seconds = parsed;
        }

        if let Ok(val) = env::var("FERRUM_POOL_ENABLE_HTTP_KEEP_ALIVE") {
            config.enable_http_keep_alive = val.parse::<bool>().unwrap_or(true);
        }

        if let Ok(val) = env::var("FERRUM_POOL_ENABLE_HTTP2") {
            config.enable_http2 = val.parse::<bool>().unwrap_or(true);
        }

        if let Ok(val) = env::var("FERRUM_POOL_HTTP2_CONNECTIONS_PER_HOST")
            && let Ok(parsed) = val.parse::<usize>()
        {
            config.http2_connections_per_host = parsed.max(1);
        }

        if let Ok(val) = env::var("FERRUM_POOL_TCP_KEEPALIVE_SECONDS")
            && let Ok(parsed) = val.parse::<u64>()
        {
            config.tcp_keepalive_seconds = parsed;
        }

        if let Ok(val) = env::var("FERRUM_POOL_HTTP2_KEEP_ALIVE_INTERVAL_SECONDS")
            && let Ok(parsed) = val.parse::<u64>()
        {
            config.http2_keep_alive_interval_seconds = parsed;
        }

        if let Ok(val) = env::var("FERRUM_POOL_HTTP2_KEEP_ALIVE_TIMEOUT_SECONDS")
            && let Ok(parsed) = val.parse::<u64>()
        {
            config.http2_keep_alive_timeout_seconds = parsed;
        }

        // Validate HTTP/2 timeout is reasonable compared to HTTP read timeout
        if config.http2_keep_alive_timeout_seconds < 10 {
            tracing::warn!(
                "HTTP/2 keep-alive timeout ({}s) is very low, consider increasing to 30-45s",
                config.http2_keep_alive_timeout_seconds
            );
        }

        // Validate and clamp max_idle_per_host
        config.max_idle_per_host =
            Self::validate_max_idle_per_host(config.max_idle_per_host, "global");

        config
    }

    /// Apply proxy-level overrides to this global configuration
    pub fn apply_proxy_overrides(&self, proxy: &crate::config::types::Proxy) -> PoolConfig {
        let mut config = self.clone();

        // Apply proxy-level overrides if present
        if let Some(val) = proxy.pool_max_idle_per_host {
            config.max_idle_per_host = val;
        }

        if let Some(val) = proxy.pool_idle_timeout_seconds {
            config.idle_timeout_seconds = val;
        }

        if let Some(val) = proxy.pool_enable_http_keep_alive {
            config.enable_http_keep_alive = val;
        }

        if let Some(val) = proxy.pool_enable_http2 {
            config.enable_http2 = val;
        }

        if let Some(val) = proxy.pool_tcp_keepalive_seconds {
            config.tcp_keepalive_seconds = val;
        }

        if let Some(val) = proxy.pool_http2_keep_alive_interval_seconds {
            config.http2_keep_alive_interval_seconds = val;
        }

        if let Some(val) = proxy.pool_http2_keep_alive_timeout_seconds {
            config.http2_keep_alive_timeout_seconds = val;
        }

        // Validate the final max_idle_per_host after overrides
        config.max_idle_per_host =
            Self::validate_max_idle_per_host(config.max_idle_per_host, &proxy.id);

        config
    }

    /// Get configuration for a specific proxy (global defaults + proxy overrides)
    pub fn for_proxy(&self, proxy: &crate::config::types::Proxy) -> PoolConfig {
        self.apply_proxy_overrides(proxy)
    }

    /// Validate and clamp `max_idle_per_host` to the allowed range, logging
    /// a warning when the value is adjusted.
    pub fn validate_max_idle_per_host(value: usize, source: &str) -> usize {
        if value < MIN_IDLE_PER_HOST {
            tracing::warn!(
                "pool_max_idle_per_host={} for '{}' is below the minimum ({}). \
                 Values this low cause excessive connection churn under load, \
                 leading to high latency and errors. Clamping to {}.",
                value,
                source,
                MIN_IDLE_PER_HOST,
                MIN_IDLE_PER_HOST,
            );
            MIN_IDLE_PER_HOST
        } else if value > MAX_IDLE_PER_HOST {
            tracing::warn!(
                "pool_max_idle_per_host={} for '{}' exceeds the maximum ({}). \
                 Very high values waste file descriptors and memory without \
                 improving performance. Clamping to {}.",
                value,
                source,
                MAX_IDLE_PER_HOST,
                MAX_IDLE_PER_HOST,
            );
            MAX_IDLE_PER_HOST
        } else {
            value
        }
    }
}
