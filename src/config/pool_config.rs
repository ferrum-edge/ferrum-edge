//! Global connection pool configuration
//! Provides environment variable defaults and proxy-level overrides

use std::env;

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
    pub tcp_keepalive_seconds: u64,
    pub http2_keep_alive_interval_seconds: u64,
    pub http2_keep_alive_timeout_seconds: u64,
}

impl Default for PoolConfig {
    fn default() -> Self {
        Self {
            max_idle_per_host: 10,
            idle_timeout_seconds: 90,
            enable_http_keep_alive: true,
            enable_http2: true,
            tcp_keepalive_seconds: 60,
            http2_keep_alive_interval_seconds: 30,
            http2_keep_alive_timeout_seconds: 45,  // More reasonable timeout comparable to HTTP read timeout
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
            tracing::warn!("HTTP/2 keep-alive timeout ({}s) is very low, consider increasing to 30-45s", config.http2_keep_alive_timeout_seconds);
        }
        
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
        
        config
    }
    
    /// Get configuration for a specific proxy (global defaults + proxy overrides)
    pub fn for_proxy(&self, proxy: &crate::config::types::Proxy) -> PoolConfig {
        self.apply_proxy_overrides(proxy)
    }
}