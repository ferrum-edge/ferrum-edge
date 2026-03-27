//! HTTP/3 client with connection pooling for proxying requests to QUIC backends.
//!
//! Maintains a shared `quinn::Endpoint` (bound once at startup) and pools QUIC
//! connections per backend `host:port`. Connections are reused across requests
//! and cleaned up when idle, matching the behaviour of the HTTP/2 and gRPC pools.
//!
//! Pool configuration (max connections, idle timeout, keepalive) is driven by
//! the same `PoolConfig` used by the HTTP/1.1, HTTP/2, and gRPC pools, including
//! per-proxy overrides from `pool_*` fields on `Proxy`.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::time::Duration;

use bytes::Buf;
use dashmap::DashMap;
use http::Request;
use quinn::crypto::rustls::QuicClientConfig;
use tracing::{debug, warn};

use crate::config::PoolConfig;
use crate::config::types::Proxy;
use crate::dns::DnsCache;

fn now_epoch_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}

/// A pooled QUIC connection with last-used tracking.
struct Http3PoolEntry {
    connection: quinn::Connection,
    last_used_epoch_ms: Arc<AtomicU64>,
}

/// A slot holding multiple QUIC connections to the same backend.
/// Round-robin selection distributes load across connections.
struct Http3PoolSlot {
    entries: Vec<Http3PoolEntry>,
    counter: AtomicUsize,
}

/// HTTP/3 connection pool for QUIC backends.
///
/// Maintains a single `quinn::Endpoint` and pools QUIC connections per backend.
/// Multiple connections per backend (up to `max_idle_per_host`) are maintained
/// and selected via round-robin.
///
/// Honors the same configuration as the HTTP pool:
/// - Global `PoolConfig` from environment variables
/// - Per-proxy overrides (`pool_*` fields on `Proxy`)
/// - Background idle connection cleanup
pub struct Http3ConnectionPool {
    /// Shared QUIC endpoint (bound once, reused for all connections)
    endpoint: quinn::Endpoint,
    /// Pooled connections keyed by `host:port`
    entries: Arc<DashMap<String, Http3PoolSlot>>,
    /// Global pool configuration
    global_pool_config: PoolConfig,
    /// Global TLS/mTLS configuration
    global_env_config: crate::config::EnvConfig,
}

impl Http3ConnectionPool {
    /// Create a new HTTP/3 connection pool.
    ///
    /// Binds a single UDP endpoint that will be shared across all QUIC connections.
    pub fn new(
        global_pool_config: PoolConfig,
        global_env_config: crate::config::EnvConfig,
    ) -> Result<Self, anyhow::Error> {
        // Bind to any available local UDP port
        let endpoint = quinn::Endpoint::client("0.0.0.0:0".parse()?)?;

        let pool = Self {
            endpoint,
            entries: Arc::new(DashMap::new()),
            global_pool_config,
            global_env_config,
        };

        pool.start_cleanup_task();
        Ok(pool)
    }

    /// Pool key — kept minimal to avoid fragmentation.
    fn pool_key(host: &str, port: u16) -> String {
        format!("{}:{}", host, port)
    }

    /// Build a TLS config for the given proxy with ALPN h3.
    fn build_tls_config(&self, proxy: &Proxy) -> Arc<rustls::ClientConfig> {
        use rustls_pemfile::certs;
        use std::io::BufReader;

        // Build root certificate store
        let mut root_store =
            rustls::RootCertStore::from_iter(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());

        // Add custom CA bundle if configured
        if !self.global_env_config.tls_no_verify
            && let Some(ca_bundle_path) = &self.global_env_config.tls_ca_bundle_path
            && let Ok(ca_pem) = std::fs::read(ca_bundle_path)
        {
            let mut reader = BufReader::new(&ca_pem[..]);
            let ca_certs: Vec<_> = certs(&mut reader).flatten().collect();
            let (added, _) = root_store.add_parsable_certificates(ca_certs);
            if added > 0 {
                debug!(
                    "http3_pool: loaded {} CA certs from {}",
                    added, ca_bundle_path
                );
            }
        }

        // Add proxy-specific CA certificate if configured
        if let Some(ref ca_path) = proxy.backend_tls_server_ca_cert_path
            && let Ok(ca_file) = std::fs::File::open(ca_path)
        {
            let ca_certs: Vec<_> = certs(&mut BufReader::new(ca_file)).flatten().collect();
            let (added, _) = root_store.add_parsable_certificates(ca_certs);
            if added > 0 {
                debug!("http3_pool: loaded {} CA certs from {}", added, ca_path);
            }
        }

        // Build client config with optional mTLS
        let cert_path = proxy
            .backend_tls_client_cert_path
            .as_ref()
            .or(self.global_env_config.backend_tls_client_cert_path.as_ref());
        let key_path = proxy
            .backend_tls_client_key_path
            .as_ref()
            .or(self.global_env_config.backend_tls_client_key_path.as_ref());

        let mut client_config = if let (Some(cert_path), Some(key_path)) = (cert_path, key_path) {
            match (
                std::fs::File::open(cert_path),
                std::fs::File::open(key_path),
            ) {
                (Ok(cert_file), Ok(key_file)) => {
                    let client_certs: Vec<_> =
                        certs(&mut BufReader::new(cert_file)).flatten().collect();
                    let client_keys: Vec<_> =
                        rustls_pemfile::pkcs8_private_keys(&mut BufReader::new(key_file))
                            .flatten()
                            .collect();
                    if let Some(key) = client_keys.into_iter().next() {
                        rustls::ClientConfig::builder()
                            .with_root_certificates(root_store)
                            .with_client_auth_cert(
                                client_certs,
                                rustls::pki_types::PrivateKeyDer::Pkcs8(key),
                            )
                            .unwrap_or_else(|e| {
                                warn!("http3_pool: mTLS config failed: {}, falling back", e);
                                rustls::ClientConfig::builder()
                                    .with_root_certificates(rustls::RootCertStore::from_iter(
                                        webpki_roots::TLS_SERVER_ROOTS.iter().cloned(),
                                    ))
                                    .with_no_client_auth()
                            })
                    } else {
                        rustls::ClientConfig::builder()
                            .with_root_certificates(root_store)
                            .with_no_client_auth()
                    }
                }
                _ => rustls::ClientConfig::builder()
                    .with_root_certificates(root_store)
                    .with_no_client_auth(),
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

    /// Get or create a QUIC connection to the backend.
    ///
    /// Connections are selected via round-robin across the pool slot. The pool
    /// grows lazily up to `max_idle_per_host`.
    async fn get_connection(
        &self,
        proxy: &Proxy,
        host: &str,
        port: u16,
        dns_cache: &DnsCache,
    ) -> Result<quinn::Connection, anyhow::Error> {
        let key = Self::pool_key(host, port);

        // Fast path: read-only round-robin selection from existing slot
        if let Some(slot) = self.entries.get(&key) {
            let len = slot.entries.len();
            if len > 0 {
                for _ in 0..len {
                    let idx = slot.counter.fetch_add(1, Ordering::Relaxed) % len;
                    let entry = &slot.entries[idx];
                    // QUIC connections have a close_reason when they're dead
                    if entry.connection.close_reason().is_none() {
                        entry
                            .last_used_epoch_ms
                            .store(now_epoch_ms(), Ordering::Relaxed);
                        return Ok(entry.connection.clone());
                    }
                }
            }
            drop(slot);
        }

        // Slow path: create a new QUIC connection
        let connection = self.create_connection(proxy, host, port, dns_cache).await?;
        let pool_config = self.global_pool_config.for_proxy(proxy);

        let mut slot = self.entries.entry(key).or_insert_with(|| Http3PoolSlot {
            entries: Vec::with_capacity(pool_config.max_idle_per_host.min(32)),
            counter: AtomicUsize::new(0),
        });

        // Clean out closed connections
        slot.entries
            .retain(|e| e.connection.close_reason().is_none());

        // Add the new connection if under the cap
        if slot.entries.len() < pool_config.max_idle_per_host {
            slot.entries.push(Http3PoolEntry {
                connection: connection.clone(),
                last_used_epoch_ms: Arc::new(AtomicU64::new(now_epoch_ms())),
            });
        }

        Ok(connection)
    }

    /// Create a new QUIC connection to the backend.
    async fn create_connection(
        &self,
        proxy: &Proxy,
        host: &str,
        port: u16,
        dns_cache: &DnsCache,
    ) -> Result<quinn::Connection, anyhow::Error> {
        // Resolve via DNS cache
        let target_host = match dns_cache
            .resolve(
                host,
                proxy.dns_override.as_deref(),
                proxy.dns_cache_ttl_seconds,
            )
            .await
        {
            Ok(ip) => ip.to_string(),
            Err(_) => host.to_string(),
        };

        let addr = resolve_backend_addr(&target_host, port).await?;

        // Build TLS config for this proxy
        let tls_config = self.build_tls_config(proxy);
        let quic_client_config = QuicClientConfig::try_from(tls_config).map_err(|e| {
            anyhow::anyhow!(
                "Failed to create QUIC client config (ensure TLS 1.3 cipher suites are available): {}",
                e
            )
        })?;

        let client_config = quinn::ClientConfig::new(Arc::new(quic_client_config));

        let connect_timeout = Duration::from_millis(proxy.backend_connect_timeout_ms);

        debug!(
            "http3_pool: connecting to {}:{} (resolved: {})",
            host, port, addr
        );

        let connection = tokio::time::timeout(connect_timeout, async {
            // Use runtime config on the shared endpoint for this connection
            self.endpoint
                .connect_with(client_config, addr, host)?
                .await
                .map_err(|e| anyhow::anyhow!("QUIC connection failed: {}", e))
        })
        .await
        .map_err(|_| {
            anyhow::anyhow!(
                "QUIC connect timeout after {}ms to {}:{}",
                proxy.backend_connect_timeout_ms,
                host,
                port
            )
        })??;

        Ok(connection)
    }

    /// Send an HTTP/3 request using a pooled QUIC connection.
    pub async fn request(
        &self,
        proxy: &Proxy,
        method: &str,
        backend_url: &str,
        headers: Vec<(http::header::HeaderName, http::header::HeaderValue)>,
        body: bytes::Bytes,
        dns_cache: &DnsCache,
    ) -> Result<(u16, Vec<u8>, HashMap<String, String>), anyhow::Error> {
        let uri: http::Uri = backend_url
            .parse()
            .map_err(|e| anyhow::anyhow!("Invalid backend URL: {}", e))?;

        let host = uri.host().unwrap_or(&proxy.backend_host);
        let port = uri.port_u16().unwrap_or(proxy.backend_port);
        let path_and_query = uri.path_and_query().map(|pq| pq.as_str()).unwrap_or("/");

        // Get a pooled QUIC connection
        let connection = self.get_connection(proxy, host, port, dns_cache).await?;

        // Create HTTP/3 session over the QUIC connection
        let (mut driver, mut send_request) =
            h3::client::new(h3_quinn::Connection::new(connection)).await?;

        // Drive the connection in background
        tokio::spawn(async move {
            let err = futures_util::future::poll_fn(|cx| driver.poll_close(cx)).await;
            debug!("HTTP/3 connection driver closed: {}", err);
        });

        // Build the request
        let req_method: http::Method = method
            .parse()
            .map_err(|_| anyhow::anyhow!("Invalid HTTP method: {}", method))?;

        let mut req_builder = Request::builder().method(req_method).uri(path_and_query);

        for (name, value) in &headers {
            match name.as_str() {
                "connection" | "transfer-encoding" | "keep-alive" | "upgrade" => continue,
                _ => {
                    req_builder = req_builder.header(name, value);
                }
            }
        }

        let req = req_builder.body(())?;

        // Send request
        let mut stream = send_request.send_request(req).await?;

        if !body.is_empty() {
            stream.send_data(body).await?;
        }
        stream.finish().await?;

        // Receive response
        let response = stream.recv_response().await?;
        let status = response.status().as_u16();

        let mut response_headers = HashMap::new();
        for (name, value) in response.headers() {
            if let Ok(value_str) = value.to_str() {
                response_headers.insert(name.as_str().to_string(), value_str.to_string());
            }
        }

        let mut response_body = Vec::new();
        while let Some(chunk) = stream.recv_data().await? {
            response_body.extend_from_slice(chunk.chunk());
        }

        Ok((status, response_body, response_headers))
    }

    /// Start background cleanup task that evicts idle and closed connections.
    fn start_cleanup_task(&self) {
        let entries = self.entries.clone();
        let idle_timeout_ms = self
            .global_pool_config
            .idle_timeout_seconds
            .saturating_mul(1000);

        tokio::spawn(async move {
            let mut cleanup_timer = tokio::time::interval(Duration::from_secs(30));

            loop {
                cleanup_timer.tick().await;

                let now = now_epoch_ms();
                let mut empty_keys = Vec::new();

                for mut slot in entries.iter_mut() {
                    slot.entries.retain(|entry| {
                        let last_used = entry.last_used_epoch_ms.load(Ordering::Relaxed);
                        let idle_ms = now.saturating_sub(last_used);
                        entry.connection.close_reason().is_none() && idle_ms <= idle_timeout_ms
                    });

                    if slot.entries.is_empty() {
                        empty_keys.push(slot.key().clone());
                    }
                }

                for key in &empty_keys {
                    entries.remove(key);
                }

                if !empty_keys.is_empty() {
                    debug!(
                        "http3_pool cleanup: removed {} empty slots",
                        empty_keys.len()
                    );
                }
            }
        });
    }
}

/// Resolve a hostname:port to a SocketAddr.
async fn resolve_backend_addr(host: &str, port: u16) -> Result<SocketAddr, anyhow::Error> {
    // First try parsing as an IP address directly (no DNS needed)
    if let Ok(ip) = host.parse::<std::net::IpAddr>() {
        return Ok(SocketAddr::new(ip, port));
    }

    // DNS lookup
    let addr = tokio::net::lookup_host(format!("{}:{}", host, port))
        .await
        .map_err(|e| anyhow::anyhow!("DNS resolution failed for {}:{}: {}", host, port, e))?
        .next()
        .ok_or_else(|| {
            anyhow::anyhow!("DNS resolution returned no addresses for {}:{}", host, port)
        })?;

    Ok(addr)
}
