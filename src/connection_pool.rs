//! Connection pool manager for HTTP/HTTPS/WebSocket backend clients.
//!
//! Provides `reqwest::Client` reuse keyed by connection identity (destination,
//! protocol, DNS override, TLS trust, mTLS credentials). Each unique key gets
//! one `reqwest::Client` which internally manages its own TCP connection pool.
//!
//! All clients use the gateway's shared `DnsCache` as their resolver, keeping
//! DNS lookups off the hot request path. A background cleanup task evicts idle
//! pool entries based on configurable timeout.
//!
//! **Pool key design**: Only includes fields that affect connection *identity*.
//! Adding unnecessary fields (timeouts, pool sizes) causes fragmentation and
//! P95 regressions. Uses `|` as delimiter (not `:`) to avoid IPv6 ambiguity.

use crate::config::PoolConfig;
use crate::config::types::Proxy;
use crate::dns::{DnsCache, DnsCacheResolver};
use crate::tls::TlsPolicy;
use crate::tls::backend::BackendTlsConfigBuilder;
use anyhow::Result;
use dashmap::DashMap;
use std::net::SocketAddr;
use std::path::Path;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

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
    /// TLS hardening policy for backend connections (cipher suites, protocol versions).
    /// When set, reqwest clients use a pre-configured rustls `ClientConfig` with the
    /// same cipher suites and protocol versions as inbound listeners.
    tls_policy: Option<Arc<TlsPolicy>>,
    /// Certificate Revocation Lists for backend TLS verification.
    crls: crate::tls::CrlList,
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
        tls_policy: Option<Arc<TlsPolicy>>,
        crls: crate::tls::CrlList,
    ) -> Self {
        let cleanup_secs = mtls_config.pool_cleanup_interval_seconds;
        let pool = Self {
            pools: Arc::new(DashMap::new()),
            cleanup_interval: Duration::from_secs(cleanup_secs.max(1)),
            global_config,
            global_mtls_config: mtls_config,
            dns_cache,
            tls_policy,
            crls,
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
        // Write pool key into a thread-local buffer to avoid allocating a new
        // String on every request. The buffer is cleared and reused across calls
        // within the same tokio worker thread — only one `get_client` runs at a
        // time per thread, so there's no aliasing concern.
        thread_local! {
            static KEY_BUF: std::cell::RefCell<String> = std::cell::RefCell::new(String::with_capacity(128));
        }

        // Build the key in the thread-local buffer and do the DashMap lookup
        // while still borrowing it, avoiding a String allocation on cache hits.
        let cached = KEY_BUF.with(|buf| {
            let mut buf = buf.borrow_mut();
            self.write_pool_key(&mut buf, proxy);
            if let Some(entry) = self.pools.get(&*buf) {
                entry
                    .last_used_epoch_ms
                    .store(now_epoch_ms(), Ordering::Relaxed);
                return Some(entry.client.clone());
            }
            None
        });

        if let Some(client) = cached {
            return Ok(client);
        }

        // Cache miss — need to create a new client. Allocate the key String
        // only on this cold path (first request per unique proxy config).
        let config = self.global_config.for_proxy(proxy);
        let pool_key = self.create_pool_key(proxy);
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

        let mut client_builder = BackendTlsConfigBuilder {
            proxy,
            policy: self.tls_policy.as_deref(),
            global_ca: self
                .global_mtls_config
                .tls_ca_bundle_path
                .as_deref()
                .map(Path::new),
            global_no_verify: self.global_mtls_config.tls_no_verify,
            global_client_cert: self
                .global_mtls_config
                .backend_tls_client_cert_path
                .as_deref()
                .map(Path::new),
            global_client_key: self
                .global_mtls_config
                .backend_tls_client_key_path
                .as_deref()
                .map(Path::new),
            crls: &self.crls,
        }
        .build_reqwest()
        .map_err(|e| anyhow::anyhow!("Failed to build reqwest backend TLS config: {}", e))?
        .dns_resolver(dns_resolver)
        .connect_timeout(Duration::from_millis(proxy.backend_connect_timeout_ms))
        .timeout(Duration::from_millis(proxy.backend_read_timeout_ms))
        .tcp_nodelay(true)
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
    /// Only includes fields that affect connection *identity* — destination,
    /// protocol, DNS override, TLS trust (CA cert, verify flag), and mTLS
    /// client credentials. Configuration-only fields like `idle_timeout_seconds`
    /// and `max_idle_per_host` are intentionally excluded: they control
    /// cleanup/sizing policy but don't change how connections are created or
    /// routed. `max_idle_per_host` is global-only (set via
    /// `FERRUM_POOL_MAX_IDLE_PER_HOST`) so all clients sharing a destination
    /// use the same pool ceiling, maximizing connection reuse.
    ///
    /// All upstream targets in the same proxy share one pool entry because
    /// `reqwest::Client` handles per-host connection pooling internally —
    /// different target hostnames in the URL get separate TCP connections
    /// and TLS sessions (with correct SNI) automatically.
    ///
    /// Uses `|` as field delimiter (invalid in hostnames per RFC 952, cannot
    /// appear in IP addresses or port numbers) to prevent key collisions
    /// from fields containing `:` (e.g., IPv6 addresses, file paths).
    fn create_pool_key(&self, proxy: &Proxy) -> String {
        let mut key = String::with_capacity(128);
        self.write_pool_key(&mut key, proxy);
        key
    }

    /// Write the pool key into the provided buffer, avoiding intermediate
    /// `format!()` allocations on the hot path. Uses `write!()` which writes
    /// directly into the String's existing capacity.
    fn write_pool_key(&self, buf: &mut String, proxy: &Proxy) {
        use std::fmt::Write;
        buf.clear();

        // When the proxy uses an upstream for load balancing, key by upstream_id
        // instead of backend_host:port. The upstream defines the actual targets;
        // backend_host:port is ignored for routing. reqwest internally pools
        // TCP connections per URL host:port, so different targets within the
        // same upstream get separate connections automatically.
        //
        // Prefix with "u=" or "d=" to prevent namespace collisions (e.g., a
        // backend_host of "upstream" with port matching an upstream_id).
        if let Some(ref upstream_id) = proxy.upstream_id {
            let _ = write!(buf, "u={}|", upstream_id);
        } else {
            let _ = write!(buf, "d={}:{}|", proxy.backend_host, proxy.backend_port);
        }
        let _ = write!(buf, "{}|", proxy.backend_protocol as u8);
        // Include per-proxy DNS override, CA cert path, mTLS client cert path,
        // and verify flag. These affect connection identity — see doc comment
        // on create_pool_key for the full rationale.
        buf.push_str(proxy.dns_override.as_deref().unwrap_or_default());
        buf.push('|');
        buf.push_str(
            proxy
                .resolved_tls
                .server_ca_cert_path
                .as_deref()
                .unwrap_or_default(),
        );
        buf.push('|');
        buf.push_str(
            proxy
                .resolved_tls
                .client_cert_path
                .as_deref()
                .or(self
                    .global_mtls_config
                    .backend_tls_client_cert_path
                    .as_deref())
                .unwrap_or_default(),
        );
        buf.push('|');
        // Include verify flag — a proxy with verification disabled must not
        // share a client with one that requires verification.
        let verify =
            proxy.resolved_tls.verify_server_cert && !self.global_mtls_config.tls_no_verify;
        buf.push(if verify { '1' } else { '0' });
    }

    /// Expose the pool key for warmup deduplication.
    ///
    /// Uses the same key format as `create_pool_key()` so warmup targets are
    /// deduplicated identically to runtime pool entries.
    pub fn pool_key_for_warmup(&self, proxy: &Proxy) -> String {
        self.create_pool_key(proxy)
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
    /// for custom CA bundles and mTLS client certificates. Uses the TLS
    /// policy's cipher suites and key exchange groups for outbound connections.
    pub fn get_tls_config_for_backend(
        &self,
        proxy: &Proxy,
    ) -> Result<Arc<rustls::ClientConfig>, anyhow::Error> {
        let mut client_config = BackendTlsConfigBuilder {
            proxy,
            policy: self.tls_policy.as_deref(),
            global_ca: self
                .global_mtls_config
                .tls_ca_bundle_path
                .as_deref()
                .map(Path::new),
            global_no_verify: self.global_mtls_config.tls_no_verify,
            global_client_cert: self
                .global_mtls_config
                .backend_tls_client_cert_path
                .as_deref()
                .map(Path::new),
            global_client_key: self
                .global_mtls_config
                .backend_tls_client_key_path
                .as_deref()
                .map(Path::new),
            crls: &self.crls,
        }
        .build_rustls_quic()
        .map_err(|e| anyhow::anyhow!("Failed to build HTTP/3 backend TLS config: {}", e))?;

        // HTTP/3 requires ALPN protocol "h3"
        client_config.alpn_protocols = vec![b"h3".to_vec()];

        Ok(Arc::new(client_config))
    }

    /// Clear all pooled connections
    #[allow(dead_code)]
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
