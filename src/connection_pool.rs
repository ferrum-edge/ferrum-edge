//! Connection pool manager for HTTP/HTTPS/WebSocket clients
//! Provides efficient connection reuse and keep-alive support

use crate::config::PoolConfig;
use crate::config::types::Proxy;
use anyhow::Result;
use dashmap::DashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;
use tracing::warn;

/// Connection pool entry with client and last used timestamp.
/// Uses atomic u64 (epoch millis) instead of RwLock<Instant> to avoid
/// deadlocks when the cleanup task iterates DashMap while get_client inserts.
#[derive(Clone)]
struct PoolEntry {
    client: reqwest::Client,
    last_used_epoch_ms: Arc<AtomicU64>,
}

fn now_epoch_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
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
    pub async fn get_client(
        &self,
        proxy: &Proxy,
        resolved_ip: Option<std::net::IpAddr>,
    ) -> Result<reqwest::Client> {
        // Get effective configuration (global defaults + proxy overrides)
        let config = self.global_config.for_proxy(proxy);

        let pool_key = self.create_pool_key(proxy, resolved_ip, &config);

        // Try to get existing client from pool
        if let Some(entry) = self.pools.get(&pool_key) {
            // Update last used time (atomic, no lock needed)
            entry
                .last_used_epoch_ms
                .store(now_epoch_ms(), Ordering::Relaxed);
            return Ok(entry.client.clone());
        }

        // Create new client with effective configuration
        let client = self.create_client(proxy, resolved_ip, &config).await?;

        // Add to pool if we haven't reached the limit
        let host_entries: Vec<_> = self
            .pools
            .iter()
            .filter(|entry| {
                entry
                    .key()
                    .starts_with(&format!("{}:{}:", proxy.backend_host, proxy.backend_port))
            })
            .collect();

        if host_entries.len() < config.max_idle_per_host {
            let entry = PoolEntry {
                client: client.clone(),
                last_used_epoch_ms: Arc::new(AtomicU64::new(now_epoch_ms())),
            };
            self.pools.insert(pool_key, entry);
        }

        Ok(client)
    }

    /// Create a new reqwest client with the given configuration
    async fn create_client(
        &self,
        proxy: &Proxy,
        resolved_ip: Option<std::net::IpAddr>,
        config: &PoolConfig,
    ) -> Result<reqwest::Client> {
        let mut client_builder = reqwest::Client::builder()
            .connect_timeout(Duration::from_millis(proxy.backend_connect_timeout_ms))
            .timeout(Duration::from_millis(proxy.backend_read_timeout_ms))
            .danger_accept_invalid_certs(!proxy.backend_tls_verify_server_cert)
            .pool_max_idle_per_host(config.max_idle_per_host)
            .pool_idle_timeout(Duration::from_secs(config.idle_timeout_seconds));

        // Enable TCP keep-alive if configured (detects dead backend connections)
        if config.enable_http_keep_alive {
            client_builder =
                client_builder.tcp_keepalive(Duration::from_secs(config.tcp_keepalive_seconds));
        }

        // Configure HTTP/2 keep-alive settings. These are applied when reqwest
        // auto-negotiates HTTP/2 via ALPN on HTTPS connections. We intentionally
        // do NOT call http2_prior_knowledge() — that forces h2c (cleartext HTTP/2)
        // which breaks backends that only speak HTTP/1.1.
        if config.enable_http2 {
            client_builder = client_builder
                .http2_keep_alive_interval(Duration::from_secs(
                    config.http2_keep_alive_interval_seconds,
                ))
                .http2_keep_alive_timeout(Duration::from_secs(
                    config.http2_keep_alive_timeout_seconds,
                ));
        }

        // Add custom CA bundle for server certificate verification (unless no_verify is set)
        if !self.global_mtls_config.backend_tls_no_verify {
            if let Some(ca_bundle_path) = &self.global_mtls_config.backend_tls_ca_bundle_path {
                let ca_pem = std::fs::read_to_string(ca_bundle_path).map_err(|e| {
                    anyhow::anyhow!("Failed to read CA bundle from {}: {}", ca_bundle_path, e)
                })?;
                let certificate = reqwest::Certificate::from_pem(ca_pem.as_bytes())
                    .map_err(|e| anyhow::anyhow!("Failed to parse CA bundle: {}", e))?;
                client_builder = client_builder.add_root_certificate(certificate);
            }
        } else {
            // Danger: Disable certificate verification (for testing only)
            warn!("Backend TLS certificate verification DISABLED (testing mode)");
            client_builder = client_builder.danger_accept_invalid_certs(true);
        }

        // Add client certificate for mTLS (proxy-specific overrides take priority)
        let cert_path = proxy.backend_tls_client_cert_path.as_ref().or(self
            .global_mtls_config
            .backend_tls_client_cert_path
            .as_ref());
        let key_path = proxy
            .backend_tls_client_key_path
            .as_ref()
            .or(self.global_mtls_config.backend_tls_client_key_path.as_ref());

        if let (Some(cert_path), Some(key_path)) = (cert_path, key_path) {
            // Load client certificate and key
            let cert_pem = std::fs::read_to_string(cert_path).map_err(|e| {
                anyhow::anyhow!(
                    "Failed to read client certificate from {}: {}",
                    cert_path,
                    e
                )
            })?;
            let key_pem = std::fs::read_to_string(key_path).map_err(|e| {
                anyhow::anyhow!("Failed to read client key from {}: {}", key_path, e)
            })?;

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
    fn create_pool_key(
        &self,
        proxy: &Proxy,
        resolved_ip: Option<std::net::IpAddr>,
        config: &PoolConfig,
    ) -> String {
        let ip_str = resolved_ip.map(|ip| ip.to_string()).unwrap_or_default();
        format!(
            "{}:{}:{}:{}:{}:{}",
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
        let idle_timeout_ms = self.global_config.idle_timeout_seconds * 1000;
        let interval = self.cleanup_interval;

        tokio::spawn(async move {
            let mut cleanup_timer = tokio::time::interval(interval);

            loop {
                cleanup_timer.tick().await;

                let now = now_epoch_ms();
                let mut keys_to_remove = Vec::new();

                // Find expired entries — all reads are atomic, no async locks held
                // during DashMap iteration, preventing deadlocks with get_client.
                for entry in pools.iter() {
                    let last_used = entry.last_used_epoch_ms.load(Ordering::Relaxed);
                    if now.saturating_sub(last_used) > idle_timeout_ms {
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
    #[allow(dead_code)]
    pub fn get_stats(&self) -> PoolStats {
        PoolStats {
            total_pools: self.pools.len(),
            entries_per_host: std::collections::HashMap::new(),
            max_idle_per_host: self.global_config.max_idle_per_host,
            idle_timeout_seconds: self.global_config.idle_timeout_seconds,
        }
    }

    /// Get TLS configuration for HTTP/3 backend connections.
    ///
    /// Configures ALPN with `h3` protocol and ensures TLS 1.3 is available
    /// (required for QUIC/HTTP/3).
    pub fn get_tls_config_for_backend(&self, _proxy: &Proxy) -> Arc<rustls::ClientConfig> {
        let mut client_config = rustls::ClientConfig::builder()
            .with_root_certificates(rustls::RootCertStore::from_iter(
                webpki_roots::TLS_SERVER_ROOTS.iter().cloned(),
            ))
            .with_no_client_auth();

        // HTTP/3 requires ALPN protocol "h3"
        client_config.alpn_protocols = vec![b"h3".to_vec()];

        Arc::new(client_config)
    }

    /// Clear all pooled connections
    #[allow(dead_code)]
    pub fn clear(&self) {
        self.pools.clear();
    }
}

/// Connection pool statistics
#[allow(dead_code)]
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
