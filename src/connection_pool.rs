//! Connection pool manager for HTTP/HTTPS/WebSocket clients
//! Provides efficient connection reuse and keep-alive support

use crate::config::types::{Proxy, BackendProtocol};
use crate::config::PoolConfig;
use dashmap::DashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::RwLock;
use anyhow::Result;

/// Connection pool entry with client and last used timestamp
#[derive(Clone)]
struct PoolEntry {
    client: reqwest::Client,
    last_used: Arc<RwLock<Instant>>,
}

/// Connection pool manager for reusing HTTP clients
pub struct ConnectionPool {
    /// Map of (host, port, protocol) -> pooled client
    pools: Arc<DashMap<String, PoolEntry>>,
    /// Configuration for pool cleanup
    cleanup_interval: Duration,
    global_config: PoolConfig,
    /// Global mTLS configuration
    global_mtls_config: crate::config::EnvConfig,
}

impl ConnectionPool {
    /// Create a new connection pool manager with global configuration
    pub fn new(global_config: PoolConfig, mtls_config: crate::config::EnvConfig) -> Self {
        let pool = Self {
            pools: Arc::new(DashMap::new()),
            cleanup_interval: Duration::from_secs(30),
            global_config,
            global_mtls_config: mtls_config,
        };
        
        // Start cleanup task
        pool.start_cleanup_task();
        pool
    }

    /// Get or create a client for the given proxy using global defaults + proxy overrides
    pub async fn get_client(&self, proxy: &Proxy, resolved_ip: Option<std::net::IpAddr>) -> Result<reqwest::Client> {
        // Get effective configuration (global defaults + proxy overrides)
        let config = self.global_config.for_proxy(proxy);
        
        let pool_key = self.create_pool_key(proxy, resolved_ip, &config);
        
        // Try to get existing client from pool
        if let Some(entry) = self.pools.get(&pool_key) {
            // Update last used time
            *entry.last_used.write().await = Instant::now();
            return Ok(entry.client.clone());
        }

        // Create new client with effective configuration
        let client = self.create_client(proxy, resolved_ip, &config).await?;
        
        // Add to pool if we haven't reached the limit
        let host_entries: Vec<_> = self.pools.iter()
            .filter(|entry| entry.key().starts_with(&format!("{}:{}:", proxy.backend_host, proxy.backend_port)))
            .collect();
            
        if host_entries.len() < config.max_idle_per_host {
            let entry = PoolEntry {
                client: client.clone(),
                last_used: Arc::new(RwLock::new(Instant::now())),
            };
            self.pools.insert(pool_key, entry);
        }

        Ok(client)
    }

    /// Create a new reqwest client with the given configuration
    async fn create_client(&self, proxy: &Proxy, resolved_ip: Option<std::net::IpAddr>, config: &PoolConfig) -> Result<reqwest::Client> {
        let mut client_builder = reqwest::Client::builder()
            .connect_timeout(Duration::from_millis(proxy.backend_connect_timeout_ms))
            .timeout(Duration::from_millis(proxy.backend_read_timeout_ms))
            .danger_accept_invalid_certs(!proxy.backend_tls_verify_server_cert)
            .pool_max_idle_per_host(config.max_idle_per_host)
            .pool_idle_timeout(Duration::from_secs(config.idle_timeout_seconds))
            .http2_keep_alive_interval(Duration::from_secs(30))
            .http2_keep_alive_timeout(Duration::from_secs(10))
            .tcp_keepalive(Duration::from_secs(60));

        // Enable HTTP/2 if configured
        if config.enable_http2 {
            client_builder = client_builder.http2_prior_knowledge();
        }

        // Enable HTTP keep-alive
        if config.enable_http_keep_alive {
            client_builder = client_builder.tcp_keepalive(Duration::from_secs(60));
        }

        // Configure WebSocket support
        if matches!(proxy.backend_protocol, BackendProtocol::Ws | BackendProtocol::Wss) {
            client_builder = client_builder.http2_prior_knowledge(); // WebSockets work better with HTTP/1.1
        }

        // Add client certificate for mTLS (proxy-specific overrides take priority)
        let cert_path = proxy.backend_tls_client_cert_path.as_ref()
            .or_else(|| self.global_mtls_config.backend_tls_client_cert_path.as_ref());
        let key_path = proxy.backend_tls_client_key_path.as_ref()
            .or_else(|| self.global_mtls_config.backend_tls_client_key_path.as_ref());

        if let (Some(cert_path), Some(key_path)) = (cert_path, key_path) {
            // Load client certificate and key
            let cert_pem = std::fs::read_to_string(cert_path)
                .map_err(|e| anyhow::anyhow!("Failed to read client certificate from {}: {}", cert_path, e))?;
            let key_pem = std::fs::read_to_string(key_path)
                .map_err(|e| anyhow::anyhow!("Failed to read client key from {}: {}", key_path, e))?;
            
            // Parse certificate and key
            let combined_pem = format!("{}\n{}", cert_pem, key_pem);
            let identity = reqwest::Identity::from_pem(combined_pem.as_bytes())
                .map_err(|e| anyhow::anyhow!("Failed to parse client certificate/key: {}", e))?;
            
            client_builder = client_builder.identity(identity);
        }

        // If we have a resolved IP, configure the client to use it
        if let Some(ip) = resolved_ip {
            let socket_addr = SocketAddr::new(ip, proxy.backend_port);
            client_builder = client_builder.resolve(&proxy.backend_host, socket_addr);
        }

        let client = client_builder.build()?;
        Ok(client)
    }

    /// Create pool key for caching clients
    fn create_pool_key(&self, proxy: &Proxy, resolved_ip: Option<std::net::IpAddr>, config: &PoolConfig) -> String {
        let ip_str = resolved_ip.map(|ip| ip.to_string()).unwrap_or_default();
        format!("{}:{}:{}:{}:{}:{}", 
            proxy.backend_host, 
            proxy.backend_port, 
            proxy.backend_protocol as u8,
            config.max_idle_per_host,
            config.idle_timeout_seconds,
            ip_str
        )
    }

    /// Start background cleanup task for idle connections
    fn start_cleanup_task(&self) {
        let pools = self.pools.clone();
        let idle_timeout = Duration::from_secs(self.global_config.idle_timeout_seconds);
        let interval = self.cleanup_interval;

        tokio::spawn(async move {
            let mut cleanup_timer = tokio::time::interval(interval);
            
            loop {
                cleanup_timer.tick().await;
                
                let now = Instant::now();
                let mut keys_to_remove = Vec::new();
                
                // Find expired entries
                for entry in pools.iter() {
                    let last_used = *entry.last_used.read().await;
                    if now.duration_since(last_used) > idle_timeout {
                        keys_to_remove.push(entry.key().clone());
                    }
                }
                
                // Remove expired entries
                for key in keys_to_remove {
                    pools.remove(&key);
                }
            }
        });
    }

    /// Get pool statistics for monitoring
    pub fn get_stats(&self) -> PoolStats {
        let total_pools = self.pools.len();
        let mut entries_per_host = std::collections::HashMap::new();
        
        for entry in self.pools.iter() {
            let key_parts: Vec<&str> = entry.key().split(':').collect();
            if key_parts.len() >= 2 {
                let host_port = format!("{}:{}", key_parts[0], key_parts[1]);
                *entries_per_host.entry(host_port).or_insert(0) += 1;
            }
        }
        
        PoolStats {
            total_pools,
            entries_per_host,
            max_idle_per_host: self.global_config.max_idle_per_host,
            idle_timeout_seconds: self.global_config.idle_timeout_seconds,
        }
    }

    /// Clear all pooled connections
    pub fn clear(&self) {
        self.pools.clear();
    }
}

/// Connection pool statistics
#[derive(Debug, Clone)]
pub struct PoolStats {
    pub total_pools: usize,
    pub entries_per_host: std::collections::HashMap<String, usize>,
    pub max_idle_per_host: usize,
    pub idle_timeout_seconds: u64,
}

impl std::fmt::Display for PoolStats {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        writeln!(f, "Connection Pool Statistics:")?;
        writeln!(f, "  Total pooled connections: {}", self.total_pools)?;
        writeln!(f, "  Max idle per host: {}", self.max_idle_per_host)?;
        writeln!(f, "  Idle timeout: {}s", self.idle_timeout_seconds)?;
        writeln!(f, "  Connections per host:")?;
        for (host, count) in &self.entries_per_host {
            writeln!(f, "    {}: {}", host, count)?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::types::{AuthMode};
    use crate::config::PoolConfig;
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

    #[tokio::test]
    async fn test_connection_pool_creation() {
        let global_config = PoolConfig::default();
        let env_config = crate::config::EnvConfig {
            mode: crate::config::OperatingMode::File,
            log_level: "info".to_string(),
            proxy_http_port: 8000,
            proxy_https_port: 8443,
            proxy_tls_cert_path: None,
            proxy_tls_key_path: None,
            admin_http_port: 9000,
            admin_https_port: 9443,
            admin_tls_cert_path: None,
            admin_tls_key_path: None,
            admin_jwt_secret: None,
            db_type: None,
            db_url: None,
            db_poll_interval: 30,
            db_poll_check_interval: 5,
            db_incremental_polling: true,
            file_config_path: None,
            cp_grpc_listen_addr: None,
            cp_grpc_jwt_secret: None,
            dp_cp_grpc_url: None,
            dp_grpc_auth_token: None,
            max_header_size_bytes: 16384,
            max_body_size_bytes: 10485760,
            dns_cache_ttl_seconds: 300,
            dns_overrides: std::collections::HashMap::new(),
            backend_tls_client_cert_path: None,
            backend_tls_client_key_path: None,
        };
        let pool = ConnectionPool::new(global_config, env_config);
        let proxy = create_test_proxy();
        
        let client1 = pool.get_client(&proxy, None).await.unwrap();
        let client2 = pool.get_client(&proxy, None).await.unwrap();
        
        // Should reuse the same client
        let stats = pool.get_stats();
        assert_eq!(stats.total_pools, 1);
    }

    #[tokio::test]
    async fn test_pool_stats() {
        let global_config = PoolConfig::default();
        let env_config = crate::config::EnvConfig {
            mode: crate::config::OperatingMode::File,
            log_level: "info".to_string(),
            proxy_http_port: 8000,
            proxy_https_port: 8443,
            proxy_tls_cert_path: None,
            proxy_tls_key_path: None,
            admin_http_port: 9000,
            admin_https_port: 9443,
            admin_tls_cert_path: None,
            admin_tls_key_path: None,
            admin_jwt_secret: None,
            db_type: None,
            db_url: None,
            db_poll_interval: 30,
            db_poll_check_interval: 5,
            db_incremental_polling: true,
            file_config_path: None,
            cp_grpc_listen_addr: None,
            cp_grpc_jwt_secret: None,
            dp_cp_grpc_url: None,
            dp_grpc_auth_token: None,
            max_header_size_bytes: 16384,
            max_body_size_bytes: 10485760,
            dns_cache_ttl_seconds: 300,
            dns_overrides: std::collections::HashMap::new(),
            backend_tls_client_cert_path: None,
            backend_tls_client_key_path: None,
        };
        let pool = ConnectionPool::new(global_config, env_config);
        let proxy = create_test_proxy();
        
        let _client = pool.get_client(&proxy, None).await.unwrap();
        let stats = pool.get_stats();
        
        assert!(stats.total_pools > 0);
        assert_eq!(stats.max_idle_per_host, 10);
        assert_eq!(stats.idle_timeout_seconds, 90);
    }
}
