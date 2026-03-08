//! Global connection pool configuration
//! Provides environment variable defaults and proxy-level overrides

use std::env;

/// Global connection pool configuration from environment variables
#[derive(Debug, Clone)]
pub struct PoolConfig {
    pub max_idle_per_host: usize,
    pub idle_timeout_seconds: u64,
    pub enable_http_keep_alive: bool,
    pub enable_http2: bool,
}

impl Default for PoolConfig {
    fn default() -> Self {
        Self {
            max_idle_per_host: 10,
            idle_timeout_seconds: 90,
            enable_http_keep_alive: true,
            enable_http2: true,
        }
    }
}

impl PoolConfig {
    /// Create pool configuration from environment variables with defaults
    pub fn from_env() -> Self {
        let mut config = Self::default();
        
        // Read from environment variables
        if let Ok(val) = env::var("FERRUM_POOL_MAX_IDLE_PER_HOST") {
            if let Ok(parsed) = val.parse::<usize>() {
                config.max_idle_per_host = parsed;
            }
        }
        
        if let Ok(val) = env::var("FERRUM_POOL_IDLE_TIMEOUT_SECONDS") {
            if let Ok(parsed) = val.parse::<u64>() {
                config.idle_timeout_seconds = parsed;
            }
        }
        
        if let Ok(val) = env::var("FERRUM_POOL_ENABLE_HTTP_KEEP_ALIVE") {
            config.enable_http_keep_alive = val.parse::<bool>().unwrap_or(true);
        }
        
        if let Ok(val) = env::var("FERRUM_POOL_ENABLE_HTTP2") {
            config.enable_http2 = val.parse::<bool>().unwrap_or(true);
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
        
        config
    }
    
    /// Get configuration for a specific proxy (global defaults + proxy overrides)
    pub fn for_proxy(&self, proxy: &crate::config::types::Proxy) -> PoolConfig {
        self.apply_proxy_overrides(proxy)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::types::{Proxy, BackendProtocol, AuthMode};
    use chrono::Utc;
    
    fn create_test_proxy() -> Proxy {
        Proxy {
            id: "test".to_string(),
            name: None,
            listen_path: "/test".to_string(),
            backend_protocol: BackendProtocol::Http,
            backend_host: "localhost".to_string(),
            backend_port: 3000,
            backend_path: None,
            strip_listen_path: true,
            preserve_host_header: false,
            backend_connect_timeout_ms: 5000,
            backend_read_timeout_ms: 30000,
            backend_write_timeout_ms: 30000,
            backend_tls_client_cert_path: None,
            backend_tls_client_key_path: None,
            backend_tls_verify_server_cert: true,
            backend_tls_server_ca_cert_path: None,
            dns_override: None,
            dns_cache_ttl_seconds: None,
            auth_mode: AuthMode::Single,
            plugins: vec![],
            pool_max_idle_per_host: None,
            pool_idle_timeout_seconds: None,
            pool_enable_http_keep_alive: None,
            pool_enable_http2: None,
            created_at: Utc::now(),
            updated_at: Utc::now(),
        }
    }
    
    #[test]
    fn test_default_config() {
        let config = PoolConfig::default();
        assert_eq!(config.max_idle_per_host, 10);
        assert_eq!(config.idle_timeout_seconds, 90);
        assert!(config.enable_http_keep_alive);
        assert!(config.enable_http2);
    }
    
    #[test]
    fn test_proxy_overrides() {
        let global = PoolConfig::default();
        let mut proxy = create_test_proxy();
        
        // Apply overrides
        proxy.pool_max_idle_per_host = Some(25);
        proxy.pool_enable_http2 = Some(false);
        
        let config = global.for_proxy(&proxy);
        assert_eq!(config.max_idle_per_host, 25);
        assert_eq!(config.idle_timeout_seconds, 90); // unchanged
        assert!(config.enable_http_keep_alive); // unchanged
        assert!(!config.enable_http2); // overridden
    }
    
    #[test]
    fn test_no_overrides() {
        let global = PoolConfig::default();
        let proxy = create_test_proxy();
        
        let config = global.for_proxy(&proxy);
        assert_eq!(config.max_idle_per_host, global.max_idle_per_host);
        assert_eq!(config.idle_timeout_seconds, global.idle_timeout_seconds);
        assert_eq!(config.enable_http_keep_alive, global.enable_http_keep_alive);
        assert_eq!(config.enable_http2, global.enable_http2);
    }
}
