//! Connection pool manager for HTTP/HTTPS/WebSocket clients
//! Provides efficient connection reuse and keep-alive support

use crate::config::PoolConfig;
use crate::config::types::Proxy;
use crate::dns::{DnsCache, DnsCacheResolver};
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

/// Connection pool manager for reusing HTTP clients.
///
/// All `reqwest::Client` instances created by this pool use a custom DNS
/// resolver ([`DnsCacheResolver`]) that transparently routes all hostname
/// lookups through the gateway's [`DnsCache`]. This ensures DNS resolution
/// is off the hot request path for both single-backend and load-balanced
/// proxies — the cache is pre-warmed at startup and continuously refreshed
/// in the background.
pub struct ConnectionPool {
    /// Map of (host, port, protocol) -> pooled client
    pools: Arc<DashMap<String, PoolEntry>>,
    /// Configuration for pool cleanup
    cleanup_interval: Duration,
    global_config: PoolConfig,
    /// Global mTLS configuration
    global_mtls_config: crate::config::EnvConfig,
    /// DNS cache used as the custom resolver for all reqwest clients
    dns_cache: DnsCache,
}

impl ConnectionPool {
    /// Create a new connection pool manager with global configuration.
    ///
    /// The `dns_cache` is used as the DNS resolver for every `reqwest::Client`
    /// created by this pool, ensuring all DNS lookups go through the warmed
    /// and background-refreshed cache rather than hitting DNS on the hot path.
    pub fn new(
        global_config: PoolConfig,
        mtls_config: crate::config::EnvConfig,
        dns_cache: DnsCache,
    ) -> Self {
        let cleanup_secs = mtls_config.pool_cleanup_interval_seconds;
        let pool = Self {
            pools: Arc::new(DashMap::new()),
            cleanup_interval: Duration::from_secs(cleanup_secs.max(1)),
            global_config,
            global_mtls_config: mtls_config,
            dns_cache,
        };

        // Start cleanup task
        pool.start_cleanup_task();
        pool
    }

    /// Get or create a client for the given proxy using global defaults + proxy overrides.
    ///
    /// For single-backend proxies, the pool key uses `backend_host:backend_port`.
    /// For upstream-backed proxies, the pool key uses `upstream_id` instead —
    /// the proxy's `backend_host:port` is ignored since routing is determined
    /// by the upstream's targets. `reqwest::Client` internally pools TCP
    /// connections by URL host:port, so different targets within an upstream
    /// automatically get separate connections and TLS sessions.
    ///
    /// All clients use the gateway's DNS cache as their resolver, so DNS
    /// lookups are served from the warmed cache — never hitting DNS on the
    /// hot request path.
    pub async fn get_client(&self, proxy: &Proxy) -> Result<reqwest::Client> {
        // Get effective configuration (global defaults + proxy overrides)
        let config = self.global_config.for_proxy(proxy);

        let pool_key = self.create_pool_key(proxy);

        // Try to get existing client from pool
        if let Some(entry) = self.pools.get(&pool_key) {
            // Update last used time (atomic, no lock needed)
            entry
                .last_used_epoch_ms
                .store(now_epoch_ms(), Ordering::Relaxed);
            return Ok(entry.client.clone());
        }

        // Create new client with effective configuration.
        // reqwest::Client has its own internal connection pool, so we only need
        // one Client per unique pool key. Always cache it for reuse.
        let client = self.create_client(proxy, &config).await?;

        let entry = PoolEntry {
            client: client.clone(),
            last_used_epoch_ms: Arc::new(AtomicU64::new(now_epoch_ms())),
        };
        self.pools.insert(pool_key, entry);

        Ok(client)
    }

    /// Create a new reqwest client with the given configuration.
    ///
    /// Every client uses [`DnsCacheResolver`] as its DNS resolver, so all
    /// hostname lookups go through the gateway's DNS cache. For proxies
    /// with a `dns_override`, a static `resolve()` hint is additionally
    /// set to pin the backend host to the override IP.
    async fn create_client(&self, proxy: &Proxy, config: &PoolConfig) -> Result<reqwest::Client> {
        // Create the custom DNS resolver wrapping our DnsCache
        let dns_resolver = Arc::new(DnsCacheResolver::new(self.dns_cache.clone()));

        let mut client_builder = reqwest::Client::builder()
            .dns_resolver(dns_resolver)
            .connect_timeout(Duration::from_millis(proxy.backend_connect_timeout_ms))
            .timeout(Duration::from_millis(proxy.backend_read_timeout_ms))
            .tcp_nodelay(true)
            .danger_accept_invalid_certs(
                !proxy.backend_tls_verify_server_cert || self.global_mtls_config.tls_no_verify,
            )
            .pool_max_idle_per_host(config.max_idle_per_host)
            .pool_idle_timeout(Duration::from_secs(config.idle_timeout_seconds));

        // Enable TCP keep-alive if configured (detects dead backend connections)
        if config.enable_http_keep_alive {
            client_builder =
                client_builder.tcp_keepalive(Duration::from_secs(config.tcp_keepalive_seconds));
        }

        // Configure HTTP/2 keep-alive and flow-control settings. These are applied
        // when reqwest auto-negotiates HTTP/2 via ALPN on HTTPS connections. We
        // intentionally do NOT call http2_prior_knowledge() — that forces h2c
        // (cleartext HTTP/2) which breaks backends that only speak HTTP/1.1.
        if config.enable_http2 {
            client_builder = client_builder
                .http2_keep_alive_interval(Duration::from_secs(
                    config.http2_keep_alive_interval_seconds,
                ))
                .http2_keep_alive_timeout(Duration::from_secs(
                    config.http2_keep_alive_timeout_seconds,
                ))
                .http2_initial_stream_window_size(config.http2_initial_stream_window_size)
                .http2_initial_connection_window_size(config.http2_initial_connection_window_size)
                .http2_adaptive_window(config.http2_adaptive_window)
                .http2_max_frame_size(config.http2_max_frame_size);
        }

        // Add custom CA bundle for server certificate verification (unless no_verify is set)
        if !self.global_mtls_config.tls_no_verify {
            if let Some(ca_bundle_path) = &self.global_mtls_config.tls_ca_bundle_path {
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

        // If the proxy has a static DNS override, set a resolve hint so the
        // override IP takes priority over the DnsCacheResolver for this
        // specific hostname. This preserves backward compatibility with
        // per-proxy dns_override configuration.
        if let Some(ref dns_override) = proxy.dns_override
            && let Ok(ip) = dns_override.parse::<std::net::IpAddr>()
        {
            let socket_addr = SocketAddr::new(ip, proxy.backend_port);
            client_builder = client_builder.resolve(&proxy.backend_host, socket_addr);
        }

        let client = client_builder.build()?;
        Ok(client)
    }

    /// Create pool key for caching clients.
    ///
    /// ⚠️  CRITICAL — DO NOT add fields to this key without careful analysis.
    /// Adding fields causes pool fragmentation: N proxies with different values
    /// create N separate reqwest::Client instances instead of sharing one,
    /// which destroys connection reuse and causes P95 latency regressions.
    ///
    /// Only includes fields that affect connection *routing* — destination,
    /// protocol, and DNS override.  Configuration-only fields like
    /// `idle_timeout_seconds` and `max_idle_per_host` are intentionally
    /// excluded: they control cleanup/sizing policy but don't change how
    /// connections are created or routed.  `max_idle_per_host` is global-only
    /// (set via `FERRUM_POOL_MAX_IDLE_PER_HOST`) so all clients sharing a
    /// destination use the same pool ceiling, maximizing connection reuse.
    ///
    /// All upstream targets in the same proxy share one pool entry because
    /// `reqwest::Client` handles per-host connection pooling internally —
    /// different target hostnames in the URL get separate TCP connections
    /// and TLS sessions (with correct SNI) automatically.
    fn create_pool_key(&self, proxy: &Proxy) -> String {
        let override_str = proxy.dns_override.as_deref().unwrap_or_default();
        // When the proxy uses an upstream for load balancing, key by upstream_id
        // instead of backend_host:port. The upstream defines the actual targets;
        // backend_host:port is ignored for routing. reqwest internally pools
        // TCP connections per URL host:port, so different targets within the
        // same upstream get separate connections automatically.
        let destination = if let Some(ref upstream_id) = proxy.upstream_id {
            format!("upstream:{}", upstream_id)
        } else {
            format!("{}:{}", proxy.backend_host, proxy.backend_port)
        };
        format!(
            "{}:{}:{}",
            destination, proxy.backend_protocol as u8, override_str
        )
    }

    /// Start background cleanup task for idle connections
    fn start_cleanup_task(&self) {
        let pools = self.pools.clone();
        let idle_timeout_ms = self.global_config.idle_timeout_seconds.saturating_mul(1000);
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

    /// Get the global pool configuration.
    pub fn global_pool_config(&self) -> &PoolConfig {
        &self.global_config
    }

    /// Get pool statistics for monitoring
    #[allow(dead_code)]
    pub fn get_stats(&self) -> PoolStats {
        let mut entries_per_host = std::collections::HashMap::new();
        for entry in self.pools.iter() {
            entries_per_host.insert(entry.key().clone(), 1usize);
        }
        PoolStats {
            total_pools: self.pools.len(),
            entries_per_host,
            max_idle_per_host: self.global_config.max_idle_per_host,
            idle_timeout_seconds: self.global_config.idle_timeout_seconds,
        }
    }

    /// Get TLS configuration for HTTP/3 backend connections.
    ///
    /// Configures ALPN with `h3` protocol and ensures TLS 1.3 is available
    /// (required for QUIC/HTTP/3). Respects proxy-specific TLS settings
    /// for custom CA bundles and mTLS client certificates.
    pub fn get_tls_config_for_backend(&self, proxy: &Proxy) -> Arc<rustls::ClientConfig> {
        use rustls_pemfile::certs;
        use std::io::BufReader;

        // Build root certificate store, using proxy CA or system roots
        let mut root_store =
            rustls::RootCertStore::from_iter(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());

        // Add proxy-specific CA certificate if configured
        if let Some(ref ca_path) = proxy.backend_tls_server_ca_cert_path
            && let Ok(ca_file) = std::fs::File::open(ca_path)
        {
            let ca_certs: Vec<_> = certs(&mut BufReader::new(ca_file))
                .filter_map(|r| r.ok())
                .collect();
            let (added, _) = root_store.add_parsable_certificates(ca_certs);
            if added > 0 {
                tracing::debug!(
                    "Added {} CA certificates from {} for HTTP/3 backend",
                    added,
                    ca_path
                );
            }
        }

        // Build client config with optional mTLS
        let mut client_config = if let (Some(cert_path), Some(key_path)) = (
            &proxy.backend_tls_client_cert_path,
            &proxy.backend_tls_client_key_path,
        ) {
            // mTLS: load client certificate and key
            match (
                std::fs::File::open(cert_path),
                std::fs::File::open(key_path),
            ) {
                (Ok(cert_file), Ok(key_file)) => {
                    let client_certs: Vec<_> = certs(&mut BufReader::new(cert_file))
                        .filter_map(|r| r.ok())
                        .collect();
                    let client_keys: Vec<_> =
                        rustls_pemfile::pkcs8_private_keys(&mut BufReader::new(key_file))
                            .filter_map(|r| r.ok())
                            .collect();
                    if let Some(key) = client_keys.into_iter().next() {
                        rustls::ClientConfig::builder()
                            .with_root_certificates(root_store)
                            .with_client_auth_cert(client_certs, rustls::pki_types::PrivateKeyDer::Pkcs8(key))
                            .unwrap_or_else(|e| {
                                tracing::warn!("Failed to configure mTLS for HTTP/3: {}, falling back to no client auth", e);
                                rustls::ClientConfig::builder()
                                    .with_root_certificates(rustls::RootCertStore::from_iter(
                                        webpki_roots::TLS_SERVER_ROOTS.iter().cloned(),
                                    ))
                                    .with_no_client_auth()
                            })
                    } else {
                        tracing::warn!("No private keys found in {} for HTTP/3 mTLS", key_path);
                        rustls::ClientConfig::builder()
                            .with_root_certificates(root_store)
                            .with_no_client_auth()
                    }
                }
                _ => {
                    tracing::warn!("Failed to open mTLS certificate files for HTTP/3");
                    rustls::ClientConfig::builder()
                        .with_root_certificates(root_store)
                        .with_no_client_auth()
                }
            }
        } else {
            rustls::ClientConfig::builder()
                .with_root_certificates(root_store)
                .with_no_client_auth()
        };

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
