pub mod body;
pub mod client_ip;
pub mod grpc_proxy;
pub mod stream_listener;
pub mod tcp_proxy;
pub mod udp_proxy;

use arc_swap::ArcSwap;
use bytes::Bytes;
use futures_util::{SinkExt, StreamExt};
use http_body_util::BodyExt;
use hyper::body::Incoming;
use hyper::service::service_fn;
use hyper::{Request, Response, StatusCode, upgrade::OnUpgrade, upgrade::Upgraded};
use hyper_util::rt::TokioIo;
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Instant;
use tokio::net::TcpListener;
use tokio_tungstenite::tungstenite::client::IntoClientRequest;
use tokio_tungstenite::tungstenite::protocol::{Message, WebSocketConfig};
use tokio_tungstenite::{
    WebSocketStream, connect_async_tls_with_config, tungstenite::handshake::derive_accept_key,
};
use tracing::{debug, error, info, trace, warn};

use crate::circuit_breaker::CircuitBreakerCache;
use crate::config::PoolConfig;
use crate::config::types::{
    AuthMode, BackendProtocol, GatewayConfig, Proxy, ResponseBodyMode, UpstreamTarget,
};
use crate::connection_pool::ConnectionPool;
use crate::consumer_index::ConsumerIndex;
use crate::dns::DnsCache;
use crate::health_check::HealthChecker;
use crate::http3::client::Http3Client;
use crate::load_balancer::LoadBalancerCache;
use crate::plugin_cache::PluginCache;
use crate::plugins::{
    Plugin, PluginResult, RequestContext, TransactionSummary, priority as plugin_priority,
};
use crate::retry;
use crate::retry::ResponseBody;
use crate::router_cache::RouterCache;

pub use self::body::ProxyBody;
use self::grpc_proxy::{GrpcConnectionPool, GrpcProxyError};

/// Check if the request is a WebSocket upgrade request
fn is_websocket_upgrade(req: &Request<Incoming>) -> bool {
    let headers = req.headers();
    let connection = headers.get("connection").and_then(|v| v.to_str().ok());
    let upgrade = headers.get("upgrade").and_then(|v| v.to_str().ok());
    let sec_key = headers
        .get("sec-websocket-key")
        .and_then(|v| v.to_str().ok());
    let sec_version = headers
        .get("sec-websocket-version")
        .and_then(|v| v.to_str().ok());

    connection.is_some_and(|conn| conn.to_lowercase().contains("upgrade"))
        && upgrade.is_some_and(|up| up.to_lowercase() == "websocket")
        && sec_key.is_some()
        && (sec_version == Some("13"))
}

/// Shared state for the proxy engine.
#[derive(Clone)]
pub struct ProxyState {
    pub config: Arc<ArcSwap<GatewayConfig>>,
    pub dns_cache: DnsCache,
    pub connection_pool: Arc<ConnectionPool>,
    pub router_cache: Arc<RouterCache>,
    pub plugin_cache: Arc<PluginCache>,
    pub consumer_index: Arc<ConsumerIndex>,
    pub request_count: Arc<AtomicU64>,
    pub status_counts: Arc<dashmap::DashMap<u16, AtomicU64>>,
    /// gRPC-specific HTTP/2 connection pool (h2c + h2 with trailer support)
    pub grpc_pool: Arc<GrpcConnectionPool>,
    /// Load balancer cache for upstream target selection.
    pub load_balancer_cache: Arc<LoadBalancerCache>,
    /// Health checker for upstream targets.
    pub health_checker: Arc<HealthChecker>,
    /// Circuit breaker cache for proxy-level circuit breaking.
    pub circuit_breaker_cache: Arc<CircuitBreakerCache>,
    /// Pre-computed Alt-Svc header value for HTTP/3 advertisement.
    /// `None` when HTTP/3 is disabled; avoids a `format!()` allocation per response.
    pub alt_svc_header: Option<String>,
    /// Environment config for backend TLS settings (WebSocket, etc.)
    pub env_config: Arc<crate::config::EnvConfig>,
    // Size limits
    pub max_header_size_bytes: usize,
    pub max_single_header_size_bytes: usize,
    pub max_body_size_bytes: usize,
    pub max_response_body_size_bytes: usize,
    /// Parsed trusted proxy CIDRs for X-Forwarded-For client IP resolution.
    /// Pre-parsed from `env_config.trusted_proxies` to avoid re-parsing on every request.
    pub trusted_proxies: Arc<client_ip::TrustedProxies>,
    /// Manages TCP/UDP stream proxy listeners (dedicated port per proxy).
    pub stream_listener_manager: Arc<stream_listener::StreamListenerManager>,
}

impl ProxyState {
    pub fn new(
        config: GatewayConfig,
        dns_cache: DnsCache,
        env_config: crate::config::EnvConfig,
    ) -> Result<Self, anyhow::Error> {
        let alt_svc_header = if env_config.enable_http3 {
            Some(format!("h3=\":{}\"; ma=86400", env_config.proxy_https_port))
        } else {
            None
        };
        let max_header_size_bytes = env_config.max_header_size_bytes;
        let max_single_header_size_bytes = env_config.max_single_header_size_bytes;
        let max_body_size_bytes = env_config.max_body_size_bytes;
        let max_response_body_size_bytes = env_config.max_response_body_size_bytes;
        let trusted_proxies = Arc::new(client_ip::TrustedProxies::parse(
            &env_config.trusted_proxies,
        ));
        // Create connection pools with global configuration from environment
        let global_pool_config = PoolConfig::from_env();
        let grpc_pool = Arc::new(GrpcConnectionPool::new(
            global_pool_config.clone(),
            env_config.clone(),
        ));
        let env_config_arc = Arc::new(env_config.clone());
        let connection_pool = Arc::new(ConnectionPool::new(
            global_pool_config.clone(),
            env_config,
            dns_cache.clone(),
        ));
        // Build router cache with pre-sorted route table for fast prefix matching
        let router_cache = Arc::new(RouterCache::new(&config, 10_000));
        // Pre-resolve plugins per proxy (fixes rate_limiting state persistence bug).
        // All plugins that make outbound HTTP calls share a pooled client configured
        // with the gateway's connection pool settings (keepalive, idle timeout, etc.).
        let plugin_http_client =
            crate::plugins::PluginHttpClient::new(&global_pool_config, dns_cache.clone());
        let plugin_cache = Arc::new(
            PluginCache::with_http_client(&config, plugin_http_client)
                .map_err(|e| anyhow::anyhow!("{}", e))?,
        );
        // Build credential-indexed consumer lookup for O(1) auth
        let consumer_index = Arc::new(ConsumerIndex::new(&config.consumers));
        // Build load balancer cache for upstream target selection
        let load_balancer_cache = Arc::new(LoadBalancerCache::new(&config));
        // Initialize health checker with the gateway's pool settings so active
        // probes share connection tuning (keep-alive, idle timeout, HTTP/2) with
        // regular proxy traffic.
        let mut health_checker = HealthChecker::with_pool_config(&global_pool_config);
        health_checker.start(&config);
        let health_checker = Arc::new(health_checker);
        // Circuit breaker cache
        let circuit_breaker_cache = Arc::new(CircuitBreakerCache::new());

        let config_arc = Arc::new(ArcSwap::new(Arc::new(config)));

        // Parse stream proxy bind address
        let stream_bind_addr: std::net::IpAddr = env_config_arc
            .stream_proxy_bind_address
            .parse()
            .unwrap_or(std::net::IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED));

        let stream_listener_manager = Arc::new(stream_listener::StreamListenerManager::new(
            stream_bind_addr,
            config_arc.clone(),
            dns_cache.clone(),
            load_balancer_cache.clone(),
            None, // Frontend TLS for stream proxies is configured per-listener in reconcile()
        ));

        // Reconcile stream proxy listeners (TCP/UDP) at startup so that any
        // stream proxies in the initial config begin accepting connections
        // immediately, without waiting for a config reload event.
        let slm_startup = stream_listener_manager.clone();
        tokio::spawn(async move {
            slm_startup.reconcile().await;
        });

        Ok(Self {
            config: config_arc,
            dns_cache,
            connection_pool,
            router_cache,
            plugin_cache,
            consumer_index,
            load_balancer_cache,
            health_checker,
            circuit_breaker_cache,
            request_count: Arc::new(AtomicU64::new(0)),
            status_counts: Arc::new(dashmap::DashMap::new()),
            grpc_pool,
            alt_svc_header,
            env_config: env_config_arc,
            max_header_size_bytes,
            max_single_header_size_bytes,
            max_body_size_bytes,
            max_response_body_size_bytes,
            trusted_proxies,
            stream_listener_manager,
        })
    }

    /// Apply a new configuration, using incremental (surgical) updates when
    /// possible to avoid disrupting the hot request path.
    ///
    /// The delta between the old and new config is computed first. If nothing
    /// changed, this is a no-op. For typical admin API edits (1-2 resources),
    /// only the affected cache entries are updated while the rest of the
    /// caches — including stateful plugin instances, warm path caches, and
    /// load balancer counters — remain completely untouched.
    ///
    /// Falls back to a full rebuild only on the very first config load (when
    /// there is no previous config to diff against).
    /// Update the proxy configuration. Returns `true` if changes were applied.
    pub fn update_config(&self, new_config: GatewayConfig) -> bool {
        use crate::config_delta::ConfigDelta;

        let old_config = self.config.load_full();

        // If this is the initial load (old config empty, new config has data),
        // do a full rebuild of all caches instead of computing a delta.
        let old_is_empty = old_config.proxies.is_empty()
            && old_config.consumers.is_empty()
            && old_config.plugin_configs.is_empty()
            && old_config.upstreams.is_empty();
        let new_is_empty = new_config.proxies.is_empty()
            && new_config.consumers.is_empty()
            && new_config.plugin_configs.is_empty()
            && new_config.upstreams.is_empty();

        if old_is_empty && !new_is_empty {
            self.router_cache.rebuild(&new_config);
            if let Err(e) = self.plugin_cache.rebuild(&new_config) {
                error!(
                    "Config reload rejected — security plugin validation failed: {}",
                    e
                );
                return false;
            }
            self.consumer_index.rebuild(&new_config.consumers);
            self.load_balancer_cache.rebuild(&new_config);

            // DNS warmup for all hostnames in the new config
            let mut hostnames: Vec<(String, Option<String>, Option<u64>)> = new_config
                .proxies
                .iter()
                .map(|p| {
                    (
                        p.backend_host.clone(),
                        p.dns_override.clone(),
                        p.dns_cache_ttl_seconds,
                    )
                })
                .collect();
            for upstream in &new_config.upstreams {
                for target in &upstream.targets {
                    hostnames.push((target.host.clone(), None, None));
                }
            }
            if !hostnames.is_empty() {
                let dns = self.dns_cache.clone();
                tokio::spawn(async move {
                    dns.warmup(hostnames).await;
                });
            }

            self.config.store(Arc::new(new_config));

            // Reconcile stream proxy listeners (TCP/UDP)
            let slm = self.stream_listener_manager.clone();
            tokio::spawn(async move {
                slm.reconcile().await;
            });

            info!(
                "Proxy configuration loaded (full build: router + plugins + consumers + load balancers)"
            );
            return true;
        }

        // Both empty — nothing to do
        if old_is_empty && new_is_empty {
            return false;
        }

        let delta = ConfigDelta::compute(&old_config, &new_config);

        if delta.is_empty() {
            debug!("Config poll: no changes detected, skipping update");
            // Still update loaded_at timestamp
            self.config.store(Arc::new(new_config));
            return false;
        }

        // --- RouterCache: rebuild route table, surgically invalidate path cache ---
        let affected_paths = delta.affected_listen_paths(&old_config);
        self.router_cache.apply_delta(&new_config, &affected_paths);

        // --- PluginCache: only rebuild plugins for affected proxies ---
        let proxy_ids_to_rebuild = delta.proxy_ids_needing_plugin_rebuild(&new_config);
        let rebuild_globals = delta
            .added_plugin_configs
            .iter()
            .chain(delta.modified_plugin_configs.iter())
            .any(|pc| pc.scope == crate::config::types::PluginScope::Global)
            || !delta.removed_plugin_config_ids.is_empty();
        self.plugin_cache.apply_delta(
            &new_config,
            &proxy_ids_to_rebuild,
            &delta.removed_proxy_ids,
            rebuild_globals,
        );

        // --- ConsumerIndex: surgical add/remove/update ---
        self.consumer_index.apply_delta(
            &delta.added_consumers,
            &delta.removed_consumer_ids,
            &delta.modified_consumers,
        );

        // --- LoadBalancerCache: only rebuild changed upstreams ---
        self.load_balancer_cache.apply_delta(
            &new_config,
            &delta.added_upstreams,
            &delta.removed_upstream_ids,
            &delta.modified_upstreams,
        );

        // --- CircuitBreakerCache: prune breakers for deleted proxies ---
        if !delta.removed_proxy_ids.is_empty() {
            self.circuit_breaker_cache.prune(&delta.removed_proxy_ids);
        }

        // --- DNS warmup for new/modified hostnames ---
        // Collect backend hostnames from added/modified proxies and upstreams
        // so the DNS cache is warm before the first request hits them.
        let mut new_hostnames: Vec<(String, Option<String>, Option<u64>)> = Vec::new();
        for proxy in delta
            .added_proxies
            .iter()
            .chain(delta.modified_proxies.iter())
        {
            new_hostnames.push((
                proxy.backend_host.clone(),
                proxy.dns_override.clone(),
                proxy.dns_cache_ttl_seconds,
            ));
        }
        for upstream in delta
            .added_upstreams
            .iter()
            .chain(delta.modified_upstreams.iter())
        {
            for target in &upstream.targets {
                new_hostnames.push((target.host.clone(), None, None));
            }
        }
        if !new_hostnames.is_empty() {
            let dns = self.dns_cache.clone();
            tokio::spawn(async move {
                dns.warmup(new_hostnames).await;
            });
        }

        // Clear cached pool keys when proxy settings change
        // Swap the canonical config last (readers may still be using old caches
        // via ArcSwap snapshots until they finish their current request)
        self.config.store(Arc::new(new_config));

        // Reconcile stream proxy listeners if any proxies changed
        let stream_proxies_changed = delta
            .added_proxies
            .iter()
            .chain(delta.modified_proxies.iter())
            .any(|p| p.backend_protocol.is_stream_proxy())
            || !delta.removed_proxy_ids.is_empty();
        if stream_proxies_changed {
            let slm = self.stream_listener_manager.clone();
            tokio::spawn(async move {
                slm.reconcile().await;
            });
        }

        // Log a concise summary of what changed
        let total_changes = delta.added_proxies.len()
            + delta.removed_proxy_ids.len()
            + delta.modified_proxies.len()
            + delta.added_consumers.len()
            + delta.removed_consumer_ids.len()
            + delta.modified_consumers.len()
            + delta.added_plugin_configs.len()
            + delta.removed_plugin_config_ids.len()
            + delta.modified_plugin_configs.len()
            + delta.added_upstreams.len()
            + delta.removed_upstream_ids.len()
            + delta.modified_upstreams.len();
        info!(
            "Config updated incrementally: {} changes (proxies: +{} -{} ~{}, consumers: +{} -{} ~{}, plugins: +{} -{} ~{}, upstreams: +{} -{} ~{}, {} proxy plugin lists rebuilt)",
            total_changes,
            delta.added_proxies.len(),
            delta.removed_proxy_ids.len(),
            delta.modified_proxies.len(),
            delta.added_consumers.len(),
            delta.removed_consumer_ids.len(),
            delta.modified_consumers.len(),
            delta.added_plugin_configs.len(),
            delta.removed_plugin_config_ids.len(),
            delta.modified_plugin_configs.len(),
            delta.added_upstreams.len(),
            delta.removed_upstream_ids.len(),
            delta.modified_upstreams.len(),
            proxy_ids_to_rebuild.len(),
        );
        true
    }

    /// Apply an incremental config update from the database polling loop.
    ///
    /// Unlike `update_config()` which takes a full `GatewayConfig` and diffs it
    /// against the current config, this method receives pre-computed changes
    /// directly from the DB layer's `load_incremental_config()`. This avoids
    /// loading and diffing the full config on every poll cycle.
    ///
    /// Returns `true` if changes were applied.
    pub fn apply_incremental(&self, result: crate::config::db_loader::IncrementalResult) -> bool {
        if result.is_empty() {
            return false;
        }

        // Patch the stored GatewayConfig: clone current, apply mutations, store
        let mut new_config = (*self.config.load_full()).clone();

        // Remove deleted resources
        if !result.removed_proxy_ids.is_empty() {
            let removed: std::collections::HashSet<&str> = result
                .removed_proxy_ids
                .iter()
                .map(|s| s.as_str())
                .collect();
            new_config
                .proxies
                .retain(|p| !removed.contains(p.id.as_str()));
        }
        if !result.removed_consumer_ids.is_empty() {
            let removed: std::collections::HashSet<&str> = result
                .removed_consumer_ids
                .iter()
                .map(|s| s.as_str())
                .collect();
            new_config
                .consumers
                .retain(|c| !removed.contains(c.id.as_str()));
        }
        if !result.removed_plugin_config_ids.is_empty() {
            let removed: std::collections::HashSet<&str> = result
                .removed_plugin_config_ids
                .iter()
                .map(|s| s.as_str())
                .collect();
            new_config
                .plugin_configs
                .retain(|pc| !removed.contains(pc.id.as_str()));
        }
        if !result.removed_upstream_ids.is_empty() {
            let removed: std::collections::HashSet<&str> = result
                .removed_upstream_ids
                .iter()
                .map(|s| s.as_str())
                .collect();
            new_config
                .upstreams
                .retain(|u| !removed.contains(u.id.as_str()));
        }

        // Upsert added/modified resources (replace existing by ID, or append new)
        for proxy in &result.added_or_modified_proxies {
            if let Some(existing) = new_config.proxies.iter_mut().find(|p| p.id == proxy.id) {
                *existing = proxy.clone();
            } else {
                new_config.proxies.push(proxy.clone());
            }
        }
        for consumer in &result.added_or_modified_consumers {
            if let Some(existing) = new_config
                .consumers
                .iter_mut()
                .find(|c| c.id == consumer.id)
            {
                *existing = consumer.clone();
            } else {
                new_config.consumers.push(consumer.clone());
            }
        }
        for pc in &result.added_or_modified_plugin_configs {
            if let Some(existing) = new_config.plugin_configs.iter_mut().find(|p| p.id == pc.id) {
                *existing = pc.clone();
            } else {
                new_config.plugin_configs.push(pc.clone());
            }
        }
        for upstream in &result.added_or_modified_upstreams {
            if let Some(existing) = new_config
                .upstreams
                .iter_mut()
                .find(|u| u.id == upstream.id)
            {
                *existing = upstream.clone();
            } else {
                new_config.upstreams.push(upstream.clone());
            }
        }

        new_config.loaded_at = result.poll_timestamp;

        // Build a ConfigDelta to feed into existing cache apply_delta() methods.
        // For incremental results, we treat all changed resources as "modified"
        // since the DB layer doesn't distinguish adds from modifications.
        // The cache apply_delta methods handle both cases correctly.
        let old_config = self.config.load_full();

        // Use ConfigDelta::compute against old + new to get proper add/modify/remove classification
        let delta = crate::config_delta::ConfigDelta::compute(&old_config, &new_config);

        // --- RouterCache ---
        let affected_paths = delta.affected_listen_paths(&old_config);
        self.router_cache.apply_delta(&new_config, &affected_paths);

        // --- PluginCache ---
        let proxy_ids_to_rebuild = delta.proxy_ids_needing_plugin_rebuild(&new_config);
        let rebuild_globals = delta
            .added_plugin_configs
            .iter()
            .chain(delta.modified_plugin_configs.iter())
            .any(|pc| pc.scope == crate::config::types::PluginScope::Global)
            || !delta.removed_plugin_config_ids.is_empty();
        self.plugin_cache.apply_delta(
            &new_config,
            &proxy_ids_to_rebuild,
            &delta.removed_proxy_ids,
            rebuild_globals,
        );

        // --- ConsumerIndex ---
        self.consumer_index.apply_delta(
            &delta.added_consumers,
            &delta.removed_consumer_ids,
            &delta.modified_consumers,
        );

        // --- LoadBalancerCache ---
        self.load_balancer_cache.apply_delta(
            &new_config,
            &delta.added_upstreams,
            &delta.removed_upstream_ids,
            &delta.modified_upstreams,
        );

        // --- CircuitBreakerCache ---
        if !delta.removed_proxy_ids.is_empty() {
            self.circuit_breaker_cache.prune(&delta.removed_proxy_ids);
        }

        // --- DNS warmup for new/modified hostnames ---
        let mut new_hostnames: Vec<(String, Option<String>, Option<u64>)> = Vec::new();
        for proxy in delta
            .added_proxies
            .iter()
            .chain(delta.modified_proxies.iter())
        {
            new_hostnames.push((
                proxy.backend_host.clone(),
                proxy.dns_override.clone(),
                proxy.dns_cache_ttl_seconds,
            ));
        }
        for upstream in delta
            .added_upstreams
            .iter()
            .chain(delta.modified_upstreams.iter())
        {
            for target in &upstream.targets {
                new_hostnames.push((target.host.clone(), None, None));
            }
        }
        if !new_hostnames.is_empty() {
            let dns = self.dns_cache.clone();
            tokio::spawn(async move {
                dns.warmup(new_hostnames).await;
            });
        }

        // Store updated config
        self.config.store(Arc::new(new_config));

        // Reconcile stream proxy listeners if any proxies changed
        let stream_proxies_changed = delta
            .added_proxies
            .iter()
            .chain(delta.modified_proxies.iter())
            .any(|p| p.backend_protocol.is_stream_proxy())
            || !delta.removed_proxy_ids.is_empty();
        if stream_proxies_changed {
            let slm = self.stream_listener_manager.clone();
            tokio::spawn(async move {
                slm.reconcile().await;
            });
        }

        info!(
            "Incremental config applied: proxies: +{} -{} ~{}, consumers: +{} -{} ~{}, plugins: +{} -{} ~{}, upstreams: +{} -{} ~{}",
            delta.added_proxies.len(),
            delta.removed_proxy_ids.len(),
            delta.modified_proxies.len(),
            delta.added_consumers.len(),
            delta.removed_consumer_ids.len(),
            delta.modified_consumers.len(),
            delta.added_plugin_configs.len(),
            delta.removed_plugin_config_ids.len(),
            delta.modified_plugin_configs.len(),
            delta.added_upstreams.len(),
            delta.removed_upstream_ids.len(),
            delta.modified_upstreams.len(),
        );
        true
    }

    pub fn current_config(&self) -> Arc<GatewayConfig> {
        self.config.load_full()
    }
}

/// Handle a plain HTTP TCP connection (HTTP/1.1 and HTTP/2 cleartext via h2c).
///
/// Uses hyper-util's auto builder which accepts both HTTP/1.1 and HTTP/2
/// connections. h2c (cleartext HTTP/2) is required for gRPC clients that
/// connect without TLS.
async fn handle_connection(
    stream: tokio::net::TcpStream,
    remote_addr: SocketAddr,
    state: ProxyState,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    // Set TCP keepalive on inbound connection to detect stale clients
    set_tcp_keepalive(&stream);

    // Use TokioIo to adapt the TCP stream for hyper
    let io = TokioIo::new(stream);

    // Use auto builder to support both HTTP/1.1 and HTTP/2 cleartext (h2c).
    // This is needed for gRPC clients that use h2c prior knowledge.
    let mut builder =
        hyper_util::server::conn::auto::Builder::new(hyper_util::rt::TokioExecutor::new());
    builder.http1().max_buf_size(state.max_header_size_bytes);
    builder
        .http2()
        .max_header_list_size(state.max_header_size_bytes as u32);

    // WebSocket requests flow through handle_proxy_request so that authentication
    // and authorization plugins execute before the upgrade handshake.
    let svc = service_fn(move |req: Request<Incoming>| {
        let state = state.clone();
        let addr = remote_addr;
        async move { handle_proxy_request(req, state, addr, false).await }
    });
    if let Err(e) = builder.serve_connection_with_upgrades(io, svc).await {
        let err_string = e.to_string();
        if is_client_disconnect_error(&err_string) {
            debug!(
                remote_addr = %remote_addr.ip(),
                error_kind = "client_disconnect",
                error = %e,
                "Client disconnected before response completed"
            );
        } else {
            debug!(error = %e, "Connection error");
        }
    }

    Ok(())
}

/// Check if a hyper connection error indicates a client disconnect.
fn is_client_disconnect_error(err: &str) -> bool {
    err.contains("connection reset")
        || err.contains("broken pipe")
        || err.contains("connection abort")
        || err.contains("not connected")
        || err.contains("early eof")
        || err.contains("incomplete message")
        || err.contains("connection closed before")
}

/// Set TCP keepalive on a stream to detect dead connections.
fn set_tcp_keepalive(stream: &tokio::net::TcpStream) {
    use std::os::fd::AsFd;
    // Disable Nagle's algorithm for lower latency on small responses
    let _ = stream.set_nodelay(true);
    let fd = stream.as_fd();
    let socket = socket2::SockRef::from(&fd);
    let keepalive = socket2::TcpKeepalive::new().with_time(std::time::Duration::from_secs(60));
    if let Err(e) = socket.set_tcp_keepalive(&keepalive) {
        debug!("Failed to set TCP keepalive: {}", e);
    }
}

/// Handle WebSocket requests AFTER authentication and authorization plugins have run
async fn handle_websocket_request_authenticated(
    req: Request<Incoming>,
    state: ProxyState,
    remote_addr: SocketAddr,
    proxy: Arc<Proxy>,
    ctx: RequestContext,
    plugins: Arc<Vec<Arc<dyn Plugin>>>,
) -> Result<Response<ProxyBody>, hyper::Error> {
    info!(
        "WebSocket upgrade request authenticated for proxy: {} from: {}",
        proxy.id,
        remote_addr.ip()
    );

    // Build backend URL using the standard URL builder (respects strip_listen_path, backend_path, query)
    let query_string = req.uri().query().unwrap_or("");
    let backend_url = build_websocket_backend_url(&proxy, &ctx.path, query_string);

    // Get the upgrade parts from the request
    let (mut parts, _body) = req.into_parts();

    // Extract the OnUpgrade future
    let on_upgrade = match parts.extensions.remove::<OnUpgrade>() {
        Some(on_upgrade) => on_upgrade,
        None => {
            error!("Failed to extract OnUpgrade extension from WebSocket request");
            return Ok(build_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                r#"{"error":"Internal server error during WebSocket upgrade"}"#,
            ));
        }
    };

    // Collect client headers to forward to backend
    let client_headers = collect_forwardable_headers(&parts.headers);

    // Connect to backend BEFORE sending 101 to client.
    // If the backend is unreachable, we return 502 instead of a premature 101.
    let env_config = state.env_config.clone();
    let backend_ws_stream =
        match connect_websocket_backend(&backend_url, &proxy, &env_config, &client_headers).await {
            Ok(stream) => stream,
            Err(e) => {
                error!(
                    proxy_id = %proxy.id,
                    backend_url = %backend_url,
                    error_kind = "connect_failure",
                    error = %e,
                    "WebSocket backend connection failed"
                );
                state.request_count.fetch_add(1, Ordering::Relaxed);
                record_status(&state, 502);
                return Ok(build_response(
                    StatusCode::BAD_GATEWAY,
                    r#"{"error":"Backend WebSocket connection failed"}"#,
                ));
            }
        };

    // Backend verified — now record 101 and log
    state.request_count.fetch_add(1, Ordering::Relaxed);
    record_status(&state, 101);

    // Measure total latency from when the request was received
    let total_ms = (chrono::Utc::now() - ctx.timestamp_received)
        .num_milliseconds()
        .max(0) as f64;

    // Resolve backend IP from DNS cache for WebSocket tx log
    let ws_resolved_ip = state
        .dns_cache
        .resolve(
            &proxy.backend_host,
            proxy.dns_override.as_deref(),
            proxy.dns_cache_ttl_seconds,
        )
        .await
        .ok()
        .map(|ip| ip.to_string());

    let summary = TransactionSummary {
        timestamp_received: ctx.timestamp_received.to_rfc3339(),
        client_ip: ctx.client_ip.clone(),
        consumer_username: ctx.identified_consumer.as_ref().map(|c| c.username.clone()),
        http_method: "GET".to_string(),
        request_path: ctx.path.clone(),
        matched_proxy_id: Some(proxy.id.clone()),
        matched_proxy_name: proxy.name.clone(),
        backend_target_url: Some(strip_query_params(&backend_url).to_string()),
        backend_resolved_ip: ws_resolved_ip,
        response_status_code: 101,
        latency_total_ms: total_ms,
        latency_gateway_processing_ms: total_ms,
        latency_backend_ttfb_ms: 0.0,
        latency_backend_total_ms: 0.0,
        request_user_agent: ctx.headers.get("user-agent").cloned(),
        response_streamed: false,
        client_disconnected: false,
        metadata: ctx.metadata.clone(),
    };

    for plugin in plugins.iter() {
        plugin.log(&summary).await;
    }

    // Create the upgrade response with proper headers
    let upgrade_response = Response::builder()
        .status(StatusCode::SWITCHING_PROTOCOLS)
        .header("upgrade", "websocket")
        .header("connection", "upgrade")
        .header(
            "sec-websocket-accept",
            derive_accept_key(
                parts
                    .headers
                    .get("sec-websocket-key")
                    .and_then(|k| k.to_str().ok())
                    .unwrap_or("")
                    .as_bytes(),
            ),
        )
        .body(ProxyBody::empty())
        .unwrap_or_else(|_| Response::new(ProxyBody::empty()));

    // Spawn bidirectional forwarding task (awaits client upgrade, then proxies)
    let proxy_id = proxy.id.clone();
    tokio::spawn(async move {
        match on_upgrade.await {
            Ok(upgraded) => {
                if let Err(e) = run_websocket_proxy(upgraded, backend_ws_stream, &proxy_id).await {
                    error!("WebSocket proxying error for {}: {}", proxy_id, e);
                }
            }
            Err(e) => {
                error!(
                    "Failed to upgrade WebSocket connection for {}: {}",
                    proxy_id, e
                );
            }
        }
    });

    info!(
        "WebSocket upgrade response sent for authenticated connection: {} -> {}",
        proxy.id, backend_url
    );

    Ok(upgrade_response)
}

/// Collect headers from the client request that should be forwarded to the backend WebSocket.
/// Hop-by-hop headers and WebSocket handshake headers are excluded.
fn collect_forwardable_headers(headers: &hyper::HeaderMap) -> Vec<(String, String)> {
    /// Headers that must not be forwarded (hop-by-hop + WS handshake).
    const SKIP_HEADERS: &[&str] = &[
        "connection",
        "upgrade",
        "sec-websocket-key",
        "sec-websocket-version",
        "sec-websocket-accept",
        "host",
        "transfer-encoding",
        "te",
        "trailer",
        "keep-alive",
        "proxy-authorization",
        "proxy-connection",
    ];

    headers
        .iter()
        .filter_map(|(name, value)| {
            // hyper already lowercases header names per HTTP/2 spec
            let name_str = name.as_str();
            if SKIP_HEADERS.contains(&name_str) {
                return None;
            }
            value
                .to_str()
                .ok()
                .map(|v| (name_str.to_string(), v.to_string()))
        })
        .collect()
}

/// Build a WebSocket backend URL with the proper ws:// or wss:// scheme,
/// respecting strip_listen_path, backend_path, and query string.
fn build_websocket_backend_url(proxy: &Proxy, incoming_path: &str, query_string: &str) -> String {
    let scheme = match proxy.backend_protocol {
        BackendProtocol::Ws => "ws",
        BackendProtocol::Wss => "wss",
        _ => "ws", // fallback, should not happen
    };

    let remaining_path = if proxy.strip_listen_path {
        incoming_path.strip_prefix(&proxy.listen_path).unwrap_or("")
    } else {
        incoming_path
    };

    let backend_path = proxy.backend_path.as_deref().unwrap_or("");
    let full_path = format!("{}{}", backend_path, remaining_path);
    let full_path = if full_path.is_empty() {
        "/".to_string()
    } else if !full_path.starts_with('/') {
        format!("/{}", full_path)
    } else {
        full_path
    };

    let base = format!(
        "{}://{}:{}{}",
        scheme, proxy.backend_host, proxy.backend_port, full_path
    );

    if query_string.is_empty() {
        base
    } else {
        format!("{}?{}", base, query_string)
    }
}

/// Build a rustls TLS connector for WebSocket backends that respects
/// proxy-level and global TLS settings (CA bundles, client certs, cert verification).
fn build_websocket_tls_connector(
    proxy: &Proxy,
    env_config: &crate::config::EnvConfig,
) -> Option<tokio_tungstenite::Connector> {
    // Only build a TLS connector for wss:// backends
    if proxy.backend_protocol != BackendProtocol::Wss {
        return None;
    }

    // Determine if we should skip server cert verification
    let skip_verify = env_config.backend_tls_no_verify || !proxy.backend_tls_verify_server_cert;

    // Build root certificate store
    let mut root_store =
        rustls::RootCertStore::from_iter(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());

    // Add custom CA bundle (proxy-level takes priority over global)
    let ca_path = proxy
        .backend_tls_server_ca_cert_path
        .as_ref()
        .or(env_config.backend_tls_ca_bundle_path.as_ref());
    if let Some(ca_path) = ca_path {
        match std::fs::read(ca_path) {
            Ok(ca_pem) => {
                let mut cursor = std::io::Cursor::new(ca_pem);
                let certs = rustls_pemfile::certs(&mut cursor);
                for cert in certs.flatten() {
                    if let Err(e) = root_store.add(cert) {
                        warn!("Failed to add CA certificate for WebSocket TLS: {}", e);
                    }
                }
            }
            Err(e) => {
                warn!(
                    "Failed to read CA bundle '{}' for WebSocket TLS: {}",
                    ca_path, e
                );
            }
        }
    }

    // Build client config
    let builder = rustls::ClientConfig::builder().with_root_certificates(root_store);

    // Add client certificate for mTLS (proxy-level overrides take priority)
    let cert_path = proxy
        .backend_tls_client_cert_path
        .as_ref()
        .or(env_config.backend_tls_client_cert_path.as_ref());
    let key_path = proxy
        .backend_tls_client_key_path
        .as_ref()
        .or(env_config.backend_tls_client_key_path.as_ref());

    let mut client_config = if let (Some(cert_path), Some(key_path)) = (cert_path, key_path) {
        match (std::fs::read(cert_path), std::fs::read(key_path)) {
            (Ok(cert_pem), Ok(key_pem)) => {
                let certs: Vec<_> = rustls_pemfile::certs(&mut std::io::Cursor::new(&cert_pem))
                    .flatten()
                    .collect();
                let key = rustls_pemfile::private_key(&mut std::io::Cursor::new(&key_pem))
                    .ok()
                    .flatten();
                match key {
                    Some(key) => match builder.clone().with_client_auth_cert(certs, key) {
                        Ok(config) => config,
                        Err(e) => {
                            warn!("Failed to configure WebSocket mTLS client cert: {}", e);
                            builder.with_no_client_auth()
                        }
                    },
                    None => {
                        warn!("No private key found in '{}' for WebSocket mTLS", key_path);
                        builder.with_no_client_auth()
                    }
                }
            }
            _ => {
                warn!("Failed to read client cert/key for WebSocket mTLS");
                builder.with_no_client_auth()
            }
        }
    } else {
        builder.with_no_client_auth()
    };

    // Disable server certificate verification if configured
    if skip_verify {
        warn!(
            "WebSocket backend TLS certificate verification DISABLED for proxy {}",
            proxy.id
        );
        client_config
            .dangerous()
            .set_certificate_verifier(Arc::new(NoVerifier));
    }

    Some(tokio_tungstenite::Connector::Rustls(Arc::new(
        client_config,
    )))
}

/// A certificate verifier that accepts all server certificates (for testing/dev).
#[derive(Debug)]
struct NoVerifier;

impl rustls::client::danger::ServerCertVerifier for NoVerifier {
    fn verify_server_cert(
        &self,
        _end_entity: &rustls::pki_types::CertificateDer<'_>,
        _intermediates: &[rustls::pki_types::CertificateDer<'_>],
        _server_name: &rustls::pki_types::ServerName<'_>,
        _ocsp_response: &[u8],
        _now: rustls::pki_types::UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &rustls::pki_types::CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &rustls::pki_types::CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        rustls::crypto::ring::default_provider()
            .signature_verification_algorithms
            .supported_schemes()
    }
}

/// Connect to backend WebSocket server before sending 101 to client.
/// Returns the connected backend stream, or an error if the backend is unreachable.
async fn connect_websocket_backend(
    backend_url: &str,
    proxy: &Proxy,
    env_config: &crate::config::EnvConfig,
    client_headers: &[(String, String)],
) -> Result<
    WebSocketStream<tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>>,
    Box<dyn std::error::Error + Send + Sync>,
> {
    let ws_config = WebSocketConfig {
        max_frame_size: Some(16 << 20),
        max_message_size: Some(64 << 20),
        ..Default::default()
    };

    let mut ws_request = backend_url.into_client_request()?;
    for (name, value) in client_headers {
        if let (Ok(header_name), Ok(header_value)) = (
            hyper::header::HeaderName::from_bytes(name.as_bytes()),
            hyper::header::HeaderValue::from_str(value),
        ) {
            ws_request.headers_mut().insert(header_name, header_value);
        }
    }

    let connector = build_websocket_tls_connector(proxy, env_config);
    let connect_timeout = std::time::Duration::from_millis(proxy.backend_connect_timeout_ms);
    let connect_future =
        connect_async_tls_with_config(ws_request, Some(ws_config), false, connector);

    let (backend_ws_stream, backend_response) =
        match tokio::time::timeout(connect_timeout, connect_future).await {
            Ok(result) => result?,
            Err(_) => {
                error!(
                    proxy_id = %proxy.id,
                    backend_url = %backend_url,
                    timeout_ms = proxy.backend_connect_timeout_ms,
                    error_kind = "connect_timeout",
                    "WebSocket backend connect timeout"
                );
                return Err(format!(
                    "WebSocket backend connect timeout ({}ms) for proxy {}",
                    proxy.backend_connect_timeout_ms, proxy.id
                )
                .into());
            }
        };

    debug!("Connected to backend WebSocket server: {}", backend_url);
    debug!("Backend response status: {}", backend_response.status());

    Ok(backend_ws_stream)
}

/// Run bidirectional WebSocket proxying between upgraded client and connected backend.
async fn run_websocket_proxy(
    upgraded: Upgraded,
    backend_ws_stream: WebSocketStream<tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>>,
    proxy_id: &str,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let ws_config = WebSocketConfig {
        max_frame_size: Some(16 << 20),
        max_message_size: Some(64 << 20),
        ..Default::default()
    };

    let ws_stream = WebSocketStream::from_raw_socket(
        TokioIo::new(upgraded),
        tokio_tungstenite::tungstenite::protocol::Role::Server,
        Some(ws_config),
    )
    .await;

    // Split streams for bidirectional communication
    let (mut ws_sink, mut ws_stream) = ws_stream.split();
    let (mut backend_sink, mut backend_stream) = backend_ws_stream.split();

    // Forward messages from client to backend
    let client_to_backend = async move {
        debug!("Starting client -> backend message forwarding");
        while let Some(msg) = ws_stream.next().await {
            match msg {
                Ok(Message::Text(text)) => {
                    trace!("Client -> Backend: Text message");
                    if let Err(e) = backend_sink.send(Message::Text(text)).await {
                        error!("Failed to send text to backend: {}", e);
                        break;
                    }
                }
                Ok(Message::Binary(data)) => {
                    trace!(bytes = data.len(), "Client -> Backend: Binary message");
                    if let Err(e) = backend_sink.send(Message::Binary(data)).await {
                        error!("Failed to send binary to backend: {}", e);
                        break;
                    }
                }
                Ok(Message::Ping(data)) => {
                    trace!("Client -> Backend: Ping");
                    if let Err(e) = backend_sink.send(Message::Ping(data)).await {
                        error!("Failed to send ping to backend: {}", e);
                        break;
                    }
                }
                Ok(Message::Close(close_frame)) => {
                    debug!("Client sent close frame");
                    if let Err(e) = backend_sink.send(Message::Close(close_frame)).await {
                        error!("Failed to send close to backend: {}", e);
                    }
                    break;
                }
                Ok(Message::Pong(_data)) => {
                    trace!("Client -> Backend: Pong");
                }
                Ok(Message::Frame(_)) => {
                    trace!("Client -> Backend: Frame");
                }
                Err(e) => {
                    error!("Error receiving from client: {}", e);
                    break;
                }
            }
        }
        debug!("Client -> backend forwarding completed");
    };

    // Forward messages from backend to client
    let backend_to_client = async move {
        debug!("Starting backend -> client message forwarding");
        while let Some(msg) = backend_stream.next().await {
            match msg {
                Ok(Message::Text(text)) => {
                    trace!("Backend -> Client: Text message");
                    if let Err(e) = ws_sink.send(Message::Text(text)).await {
                        error!("Failed to send text to client: {}", e);
                        break;
                    }
                }
                Ok(Message::Binary(data)) => {
                    trace!(bytes = data.len(), "Backend -> Client: Binary message");
                    if let Err(e) = ws_sink.send(Message::Binary(data)).await {
                        error!("Failed to send binary to client: {}", e);
                        break;
                    }
                }
                Ok(Message::Ping(data)) => {
                    trace!("Backend -> Client: Ping");
                    if let Err(e) = ws_sink.send(Message::Ping(data)).await {
                        error!("Failed to send ping to client: {}", e);
                        break;
                    }
                }
                Ok(Message::Close(close_frame)) => {
                    debug!("Backend sent close frame");
                    if let Err(e) = ws_sink.send(Message::Close(close_frame)).await {
                        error!("Failed to send close to client: {}", e);
                    }
                    break;
                }
                Ok(Message::Pong(_data)) => {
                    trace!("Backend -> Client: Pong");
                }
                Ok(Message::Frame(_)) => {
                    trace!("Backend -> Client: Frame");
                }
                Err(e) => {
                    error!("Error receiving from backend: {}", e);
                    break;
                }
            }
        }
        debug!("Backend -> client forwarding completed");
    };

    // Wait for either direction to complete
    tokio::select! {
        _ = client_to_backend => {
            debug!("Client to backend stream completed first");
        }
        _ = backend_to_client => {
            debug!("Backend to client stream completed first");
        }
    }

    debug!("WebSocket proxy connection closed for {}", proxy_id);
    Ok(())
}

/// Start the proxy HTTP listener with dual-path handling.
pub async fn start_proxy_listener(
    addr: SocketAddr,
    state: ProxyState,
    shutdown: tokio::sync::watch::Receiver<bool>,
) -> Result<(), anyhow::Error> {
    start_proxy_listener_with_tls(addr, state, shutdown, None).await
}

/// Start the proxy listener with optional TLS and client certificate verification.
pub async fn start_proxy_listener_with_tls(
    addr: SocketAddr,
    state: ProxyState,
    shutdown: tokio::sync::watch::Receiver<bool>,
    tls_config: Option<Arc<rustls::ServerConfig>>,
) -> Result<(), anyhow::Error> {
    let listener = TcpListener::bind(addr).await?;
    info!("Proxy listener started on {}", addr);

    let mut shutdown_rx = shutdown;

    loop {
        tokio::select! {
            result = listener.accept() => {
                match result {
                    Ok((stream, remote_addr)) => {
                        let state = state.clone();
                        let tls_config = tls_config.clone();

                        tokio::spawn(async move {
                            let result = if let Some(tls_config) = tls_config {
                                // Handle TLS connection with client certificate verification
                                handle_tls_connection(stream, remote_addr, state, tls_config).await
                            } else {
                                // Handle plain HTTP connection
                                handle_connection(stream, remote_addr, state).await
                            };

                            if let Err(e) = result {
                                debug!("Connection handling error: {}", e);
                            }
                        });
                    }
                    Err(e) => {
                        error!("Failed to accept connection: {}", e);
                    }
                }
            }
            _ = shutdown_rx.changed() => {
                info!("Proxy listener shutting down");
                return Ok(());
            }
        }
    }
}

/// Handle TLS connections with HTTP/1.1 and HTTP/2 auto-negotiation via ALPN.
async fn handle_tls_connection(
    stream: tokio::net::TcpStream,
    remote_addr: SocketAddr,
    state: ProxyState,
    tls_config: Arc<rustls::ServerConfig>,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    use tokio_rustls::TlsAcceptor;

    // Set TCP keepalive on inbound connection
    set_tcp_keepalive(&stream);

    let acceptor = TlsAcceptor::from(tls_config);
    let tls_stream = match acceptor.accept(stream).await {
        Ok(stream) => {
            info!("TLS connection established from {}", remote_addr.ip());
            stream
        }
        Err(e) => {
            warn!("TLS handshake failed from {}: {}", remote_addr.ip(), e);
            return Err(e.into());
        }
    };

    // Convert TLS stream to TokioIo for hyper
    let io = hyper_util::rt::TokioIo::new(tls_stream);

    // Use hyper-util's auto builder which negotiates HTTP/1.1 or HTTP/2 via ALPN.
    // HTTP/2 clients get multiplexed streams; HTTP/1.1 clients get upgrade support.
    let mut builder =
        hyper_util::server::conn::auto::Builder::new(hyper_util::rt::TokioExecutor::new());
    builder.http1().max_buf_size(state.max_header_size_bytes);
    builder
        .http2()
        .max_header_list_size(state.max_header_size_bytes as u32);

    // WebSocket requests flow through handle_proxy_request so that authentication
    // and authorization plugins execute before the upgrade handshake.
    let svc = service_fn(move |req: hyper::Request<hyper::body::Incoming>| {
        let state = state.clone();
        let addr = remote_addr;
        async move { handle_proxy_request(req, state, addr, true).await }
    });
    if let Err(e) = builder.serve_connection_with_upgrades(io, svc).await {
        let err_string = e.to_string();
        if is_client_disconnect_error(&err_string) {
            debug!(
                remote_addr = %remote_addr.ip(),
                error_kind = "client_disconnect",
                error = %e,
                "Client disconnected before response completed (TLS)"
            );
        } else {
            error!(
                remote_addr = %remote_addr.ip(),
                error = %e,
                "HTTP connection error over TLS"
            );
        }
    }

    Ok(())
}

/// Run logging plugins for a rejected request.
///
/// When a plugin (auth, access control, rate limiting, etc.) rejects a request,
/// logging plugins (stdout_logging, http_logging, transaction_debugger) must still
/// execute so that rejected traffic is visible in log sinks like Splunk, stdout, etc.
/// Only plugins in the Logging priority band (9000+) are invoked here.
pub async fn log_rejected_request(
    plugins: &[Arc<dyn Plugin>],
    ctx: &RequestContext,
    status_code: u16,
    start_time: Instant,
    rejection_phase: &str,
) {
    let logging_plugins: Vec<&Arc<dyn Plugin>> = plugins
        .iter()
        .filter(|p| p.priority() >= plugin_priority::STDOUT_LOGGING)
        .collect();

    if logging_plugins.is_empty() {
        return;
    }

    let total_ms = start_time.elapsed().as_secs_f64() * 1000.0;
    let proxy = ctx.matched_proxy.as_ref();

    let mut metadata = ctx.metadata.clone();
    metadata.insert("rejection_phase".to_string(), rejection_phase.to_string());

    let summary = TransactionSummary {
        timestamp_received: ctx.timestamp_received.to_rfc3339(),
        client_ip: ctx.client_ip.clone(),
        consumer_username: ctx.identified_consumer.as_ref().map(|c| c.username.clone()),
        http_method: ctx.method.clone(),
        request_path: ctx.path.clone(),
        matched_proxy_id: proxy.map(|p| p.id.clone()),
        matched_proxy_name: proxy.and_then(|p| p.name.clone()),
        backend_target_url: proxy.map(|p| {
            let url = build_backend_url(p, &ctx.path, "");
            strip_query_params(&url).to_string()
        }),
        backend_resolved_ip: None,
        response_status_code: status_code,
        latency_total_ms: total_ms,
        latency_gateway_processing_ms: total_ms,
        latency_backend_ttfb_ms: -1.0,
        latency_backend_total_ms: -1.0,
        request_user_agent: ctx.headers.get("user-agent").cloned(),
        response_streamed: false,
        client_disconnected: false,
        metadata,
    };

    for plugin in &logging_plugins {
        plugin.log(&summary).await;
    }
}

/// Handle a single proxy request.
pub async fn handle_proxy_request(
    req: Request<Incoming>,
    state: ProxyState,
    remote_addr: SocketAddr,
    is_tls: bool,
) -> Result<Response<ProxyBody>, hyper::Error> {
    let start_time = Instant::now();

    let method = req.method().as_str().to_owned();
    let path = req.uri().path().to_string();
    let query_string = req.uri().query().unwrap_or("").to_string();

    let socket_ip = remote_addr.ip().to_string();

    // Build request context — pass cloned socket_ip to ctx (client_ip may be
    // overwritten by trusted-proxy resolution below). method and path keep
    // separate ownership for use in backend URL building and logging.
    let mut ctx = RequestContext::new(socket_ip.clone(), method.clone(), path.clone());

    // Validate and extract headers with size limits
    let mut total_header_size: usize = 0;
    for (name, value) in req.headers() {
        let header_size = name.as_str().len() + value.len();
        if header_size > state.max_single_header_size_bytes {
            record_request(&state, 431);
            // Escape header name to prevent JSON injection from client-controlled data
            let escaped_name = name.as_str().replace('\\', "\\\\").replace('"', "\\\"");
            return Ok(build_response(
                StatusCode::REQUEST_HEADER_FIELDS_TOO_LARGE,
                &format!(
                    r#"{{"error":"Request header '{}' exceeds maximum size of {} bytes"}}"#,
                    escaped_name, state.max_single_header_size_bytes
                ),
            ));
        }
        total_header_size += header_size;
        if let Ok(v) = value.to_str() {
            // hyper's HeaderName is already lowercase-normalized, so
            // name.as_str() returns a lowercase &str — skip to_lowercase()
            // to avoid a per-header String allocation on the hot path.
            ctx.headers.insert(name.as_str().to_owned(), v.to_owned());
        }
    }
    if total_header_size > state.max_header_size_bytes {
        record_request(&state, 431);
        return Ok(build_response(
            StatusCode::REQUEST_HEADER_FIELDS_TOO_LARGE,
            r#"{"error":"Total request headers exceed maximum size"}"#,
        ));
    }

    // Resolve real client IP using trusted proxy configuration.
    // Parse the socket IP once and reuse the parsed value to avoid redundant
    // parsing across the real-IP-header check and the XFF walk.
    if !state.trusted_proxies.is_empty() {
        let socket_addr: Option<std::net::IpAddr> = socket_ip.parse().ok();
        let resolved = if let Some(ref real_ip_header) = state.env_config.real_ip_header {
            // real_ip_header is pre-lowercased at config load time — no allocation needed
            let header_val = ctx.headers.get(real_ip_header.as_str());
            if let Some(val) = header_val {
                // Validate the direct connection is from a trusted proxy before
                // trusting this header
                if socket_addr.is_some_and(|ip| state.trusted_proxies.contains(&ip)) {
                    val.trim().to_string()
                } else {
                    socket_ip.to_string()
                }
            } else if let Some(ref addr) = socket_addr {
                client_ip::resolve_client_ip_parsed(
                    &socket_ip,
                    addr,
                    ctx.headers.get("x-forwarded-for").map(|s| s.as_str()),
                    &state.trusted_proxies,
                )
            } else {
                socket_ip.to_string()
            }
        } else if let Some(ref addr) = socket_addr {
            client_ip::resolve_client_ip_parsed(
                &socket_ip,
                addr,
                ctx.headers.get("x-forwarded-for").map(|s| s.as_str()),
                &state.trusted_proxies,
            )
        } else {
            socket_ip.to_string()
        };
        ctx.client_ip = resolved;
    }

    // Parse query params (skip when empty — most requests have no query string)
    if !query_string.is_empty() {
        for pair in query_string.split('&') {
            if let Some((k, v)) = pair.split_once('=') {
                ctx.query_params.insert(k.to_string(), v.to_string());
            }
        }
    }

    // Route: longest prefix match via router cache (O(1) cache hit, pre-sorted fallback)
    let matched_proxy = state.router_cache.find_proxy(&path);

    let proxy = match matched_proxy {
        Some(p) => p,
        None => {
            debug!(path = %path, client_ip = %ctx.client_ip, "No route matched for request path");
            state.request_count.fetch_add(1, Ordering::Relaxed);
            record_status(&state, 404);
            return Ok(build_response(
                StatusCode::NOT_FOUND,
                r#"{"error":"Not Found"}"#,
            ));
        }
    };

    ctx.matched_proxy = Some(Arc::clone(&proxy));
    debug!(proxy_id = %proxy.id, method = %method, path = %path, client_ip = %ctx.client_ip, "Request routed to proxy");

    // Get pre-resolved plugins from cache (O(1) lookup, no per-request allocation)
    let plugins = state.plugin_cache.get_plugins(&proxy.id);

    // Execute on_request_received hooks (skip iteration when no plugins configured)
    if !plugins.is_empty() {
        for plugin in plugins.iter() {
            match plugin.on_request_received(&mut ctx).await {
                PluginResult::Reject {
                    status_code,
                    body,
                    headers,
                } => {
                    log_rejected_request(
                        &plugins,
                        &ctx,
                        status_code,
                        start_time,
                        "on_request_received",
                    )
                    .await;
                    record_request(&state, status_code);
                    return Ok(build_reject_response(
                        StatusCode::from_u16(status_code)
                            .unwrap_or(StatusCode::INTERNAL_SERVER_ERROR),
                        &body,
                        &headers,
                    ));
                }
                PluginResult::Continue => {}
            }
        }
    }

    // Authentication phase
    let auth_plugins: Vec<&Arc<dyn Plugin>> =
        plugins.iter().filter(|p| p.is_auth_plugin()).collect();

    match proxy.auth_mode {
        AuthMode::Multi => {
            // Execute auth plugins; first success (consumer identified) stops iteration.
            // If all fail and auth plugins were configured, reject with 401.
            let mut last_reject: Option<(u16, String, HashMap<String, String>)> = None;
            for auth_plugin in &auth_plugins {
                match auth_plugin
                    .authenticate(&mut ctx, &state.consumer_index)
                    .await
                {
                    PluginResult::Reject {
                        status_code,
                        body,
                        headers,
                    } => {
                        last_reject = Some((status_code, body, headers));
                    }
                    PluginResult::Continue => {
                        if ctx.identified_consumer.is_some() {
                            last_reject = None;
                            break;
                        }
                    }
                }
            }
            if let Some((status_code, body, headers)) = last_reject
                .filter(|_| !auth_plugins.is_empty() && ctx.identified_consumer.is_none())
            {
                log_rejected_request(&plugins, &ctx, status_code, start_time, "authenticate").await;
                record_request(&state, status_code);
                return Ok(build_reject_response(
                    StatusCode::from_u16(status_code).unwrap_or(StatusCode::UNAUTHORIZED),
                    &body,
                    &headers,
                ));
            }
        }
        AuthMode::Single => {
            // Execute auth plugins sequentially; first failure rejects
            for auth_plugin in &auth_plugins {
                match auth_plugin
                    .authenticate(&mut ctx, &state.consumer_index)
                    .await
                {
                    PluginResult::Reject {
                        status_code,
                        body,
                        headers,
                    } => {
                        log_rejected_request(
                            &plugins,
                            &ctx,
                            status_code,
                            start_time,
                            "authenticate",
                        )
                        .await;
                        record_request(&state, status_code);
                        return Ok(build_reject_response(
                            StatusCode::from_u16(status_code).unwrap_or(StatusCode::UNAUTHORIZED),
                            &body,
                            &headers,
                        ));
                    }
                    PluginResult::Continue => {}
                }
            }
        }
    }

    // Authorization phase (access_control, rate_limiting by consumer, etc.)
    if !plugins.is_empty() {
        for plugin in plugins.iter() {
            match plugin.authorize(&mut ctx).await {
                PluginResult::Reject {
                    status_code,
                    body,
                    headers,
                } => {
                    log_rejected_request(&plugins, &ctx, status_code, start_time, "authorize")
                        .await;
                    record_request(&state, status_code);
                    return Ok(build_reject_response(
                        StatusCode::from_u16(status_code).unwrap_or(StatusCode::FORBIDDEN),
                        &body,
                        &headers,
                    ));
                }
                PluginResult::Continue => {}
            }
        }
    }

    // before_proxy hooks — only clone headers if at least one plugin modifies them.
    // When no plugin modifies headers, pass &mut ctx.headers directly to avoid
    // an expensive per-request HashMap clone on the hot path.
    let needs_header_clone =
        !plugins.is_empty() && plugins.iter().any(|p| p.modifies_request_headers());
    let mut owned_proxy_headers: Option<HashMap<String, String>> = None;
    if needs_header_clone {
        let mut cloned = ctx.headers.clone();
        for plugin in plugins.iter() {
            match plugin.before_proxy(&mut ctx, &mut cloned).await {
                PluginResult::Reject {
                    status_code,
                    body,
                    headers,
                } => {
                    log_rejected_request(&plugins, &ctx, status_code, start_time, "before_proxy")
                        .await;
                    record_request(&state, status_code);
                    return Ok(build_reject_response(
                        StatusCode::from_u16(status_code)
                            .unwrap_or(StatusCode::INTERNAL_SERVER_ERROR),
                        &body,
                        &headers,
                    ));
                }
                PluginResult::Continue => {}
            }
        }
        owned_proxy_headers = Some(cloned);
    } else if !plugins.is_empty() {
        // Run before_proxy hooks that don't modify headers (e.g., body_validator).
        // No plugin modifies headers, so swap headers out of ctx temporarily to
        // satisfy the borrow checker without cloning — zero allocation hot path.
        let mut tmp_headers = std::mem::take(&mut ctx.headers);
        for plugin in plugins.iter() {
            match plugin.before_proxy(&mut ctx, &mut tmp_headers).await {
                PluginResult::Reject {
                    status_code,
                    body,
                    headers,
                } => {
                    ctx.headers = tmp_headers;
                    log_rejected_request(&plugins, &ctx, status_code, start_time, "before_proxy")
                        .await;
                    record_request(&state, status_code);
                    return Ok(build_reject_response(
                        StatusCode::from_u16(status_code)
                            .unwrap_or(StatusCode::INTERNAL_SERVER_ERROR),
                        &body,
                        &headers,
                    ));
                }
                PluginResult::Continue => {}
            }
        }
        ctx.headers = tmp_headers;
    }
    let proxy_headers: &HashMap<String, String> =
        owned_proxy_headers.as_ref().unwrap_or(&ctx.headers);

    // Check if this is a WebSocket upgrade request and the proxy supports WebSocket
    // This check happens AFTER authentication and authorization plugins have run
    if is_websocket_upgrade(&req)
        && matches!(
            proxy.backend_protocol,
            BackendProtocol::Ws | BackendProtocol::Wss
        )
    {
        return handle_websocket_request_authenticated(
            req,
            state,
            remote_addr,
            proxy,
            ctx,
            plugins,
        )
        .await;
    }

    // Check if this is a gRPC request and the proxy supports gRPC
    if grpc_proxy::is_grpc_request(&req)
        && matches!(
            proxy.backend_protocol,
            BackendProtocol::Grpc | BackendProtocol::Grpcs
        )
    {
        let backend_url = build_backend_url(&proxy, &path, &query_string);
        let backend_start = Instant::now();

        let grpc_result = grpc_proxy::proxy_grpc_request(
            req,
            &proxy,
            &backend_url,
            &state.grpc_pool,
            &state.dns_cache,
            proxy_headers,
        )
        .await;

        let backend_total_ms = backend_start.elapsed().as_secs_f64() * 1000.0;

        match grpc_result {
            Ok(grpc_resp) => {
                let mut response_headers: HashMap<String, String> = grpc_resp.headers;

                // Forward trailers as response headers (gRPC Trailers-Only encoding)
                for (k, v) in &grpc_resp.trailers {
                    response_headers.insert(k.clone(), v.clone());
                }

                // after_proxy hooks
                for plugin in plugins.iter() {
                    if let PluginResult::Reject { status_code, .. } = plugin
                        .after_proxy(&mut ctx, grpc_resp.status, &mut response_headers)
                        .await
                    {
                        warn!(
                            "after_proxy plugin '{}' returned Reject (status {}), but response is already committed",
                            plugin.name(),
                            status_code,
                        );
                    }
                }

                let total_ms = start_time.elapsed().as_secs_f64() * 1000.0;
                let gateway_processing_ms = total_ms - backend_total_ms;

                // Log phase
                if !plugins.is_empty() {
                    // Resolve backend IP from DNS cache for gRPC tx log
                    let grpc_resolved_ip = state
                        .dns_cache
                        .resolve(
                            &proxy.backend_host,
                            proxy.dns_override.as_deref(),
                            proxy.dns_cache_ttl_seconds,
                        )
                        .await
                        .ok()
                        .map(|ip| ip.to_string());

                    let summary = TransactionSummary {
                        timestamp_received: ctx.timestamp_received.to_rfc3339(),
                        client_ip: ctx.client_ip.clone(),
                        consumer_username: ctx
                            .identified_consumer
                            .as_ref()
                            .map(|c| c.username.clone()),
                        http_method: method,
                        request_path: path,
                        matched_proxy_id: Some(proxy.id.clone()),
                        matched_proxy_name: proxy.name.clone(),
                        backend_target_url: Some(strip_query_params(&backend_url).to_string()),
                        backend_resolved_ip: grpc_resolved_ip,
                        response_status_code: grpc_resp.status,
                        latency_total_ms: total_ms,
                        latency_gateway_processing_ms: gateway_processing_ms,
                        latency_backend_ttfb_ms: backend_total_ms,
                        latency_backend_total_ms: backend_total_ms,
                        request_user_agent: ctx.headers.get("user-agent").cloned(),
                        response_streamed: false,
                        client_disconnected: false,
                        metadata: ctx.metadata.clone(),
                    };
                    for plugin in plugins.iter() {
                        plugin.log(&summary).await;
                    }
                }

                record_request(&state, grpc_resp.status);

                // Build gRPC response with headers and trailers
                let mut resp_builder = Response::builder()
                    .status(StatusCode::from_u16(grpc_resp.status).unwrap_or(StatusCode::OK));
                for (k, v) in &response_headers {
                    resp_builder = resp_builder.header(k.as_str(), v.as_str());
                }

                return Ok(resp_builder
                    .body(ProxyBody::full(Bytes::from(grpc_resp.body)))
                    .unwrap_or_else(|_| {
                        grpc_proxy::build_grpc_error_response(
                            grpc_proxy::grpc_status::UNAVAILABLE,
                            "Internal gateway error",
                        )
                    }));
            }
            Err(e) => {
                let (grpc_code, msg) = match &e {
                    GrpcProxyError::BackendUnavailable(m) => {
                        (grpc_proxy::grpc_status::UNAVAILABLE, m.as_str())
                    }
                    GrpcProxyError::BackendTimeout(m) => {
                        (grpc_proxy::grpc_status::DEADLINE_EXCEEDED, m.as_str())
                    }
                    GrpcProxyError::Internal(m) => {
                        (grpc_proxy::grpc_status::UNAVAILABLE, m.as_str())
                    }
                };
                log_rejected_request(&plugins, &ctx, 200, start_time, "grpc_backend_error").await;
                record_request(&state, 200); // gRPC errors use HTTP 200
                return Ok(grpc_proxy::build_grpc_error_response(grpc_code, msg));
            }
        }
    }

    // Resolve upstream target if load balancing is configured
    let (upstream_target, upstream_is_fallback) = if let Some(upstream_id) = &proxy.upstream_id {
        let hash_key = ctx.client_ip.clone(); // Default hash key for consistent hashing
        match state.load_balancer_cache.select_target(
            upstream_id,
            &hash_key,
            Some(&state.health_checker.unhealthy_targets),
        ) {
            Some(selection) => {
                if selection.is_fallback {
                    warn!(
                        proxy_id = %proxy.id,
                        upstream_id = %upstream_id,
                        target_host = %selection.target.host,
                        target_port = selection.target.port,
                        "All upstream targets unhealthy, using fallback target"
                    );
                } else {
                    debug!(
                        proxy_id = %proxy.id,
                        upstream_id = %upstream_id,
                        target_host = %selection.target.host,
                        target_port = selection.target.port,
                        "Upstream target selected"
                    );
                }
                (Some(selection.target), selection.is_fallback)
            }
            None => {
                warn!(proxy_id = %proxy.id, upstream_id = %upstream_id, "No upstream target available");
                (None, false)
            }
        }
    } else {
        (None, false)
    };

    // Circuit breaker check
    let circuit_breaker = if let Some(cb_config) = &proxy.circuit_breaker {
        match state
            .circuit_breaker_cache
            .can_execute(&proxy.id, cb_config)
        {
            Ok(cb) => Some(cb),
            Err(_) => {
                warn!(proxy_id = %proxy.id, "Request rejected: circuit breaker open");
                log_rejected_request(&plugins, &ctx, 503, start_time, "circuit_breaker_open").await;
                record_request(&state, 503);
                return Ok(build_response(
                    StatusCode::SERVICE_UNAVAILABLE,
                    r#"{"error":"Service temporarily unavailable (circuit breaker open)"}"#,
                ));
            }
        }
    } else {
        None
    };

    // Build backend URL (using upstream target if available)
    let (effective_host, effective_port) = if let Some(ref target) = upstream_target {
        (target.host.as_str(), target.port)
    } else {
        (proxy.backend_host.as_str(), proxy.backend_port)
    };

    let backend_url =
        build_backend_url_with_target(&proxy, &path, &query_string, effective_host, effective_port);
    let backend_start = Instant::now();

    // Track connection for least-connections load balancing
    if let (Some(upstream_id), Some(target)) = (&proxy.upstream_id, &upstream_target) {
        state
            .load_balancer_cache
            .record_connection_start(upstream_id, target);
    }

    // Determine response body mode: stream by default, buffer when required.
    // A plugin that needs the full body (e.g., response body transformation)
    // forces buffering regardless of the proxy configuration.
    let should_stream = match proxy.response_body_mode {
        ResponseBodyMode::Buffer => false,
        ResponseBodyMode::Stream => !state
            .plugin_cache
            .requires_response_body_buffering(&proxy.id),
    };

    // Perform the backend request with retry logic
    let backend_resp = if let Some(retry_config) = &proxy.retry {
        let mut attempt = 0u32;
        let mut current_target = upstream_target.clone();
        let mut current_url = backend_url.clone();
        let mut result = proxy_to_backend(
            &state,
            &proxy,
            &current_url,
            &method,
            proxy_headers,
            req,
            upstream_target.as_ref(),
            should_stream,
            &ctx.client_ip,
            is_tls,
        )
        .await;

        while retry::should_retry(retry_config, &method, &result, attempt) {
            let delay = retry::retry_delay(retry_config, attempt);
            tokio::time::sleep(delay).await;
            attempt += 1;

            // Try a different target on retry if load balancing is configured
            if let (Some(upstream_id), Some(prev_target)) = (&proxy.upstream_id, &current_target)
                && let Some(next) = state.load_balancer_cache.select_next_target(
                    upstream_id,
                    &ctx.client_ip,
                    prev_target,
                    Some(&state.health_checker.unhealthy_targets),
                )
            {
                current_url = build_backend_url_with_target(
                    &proxy,
                    &path,
                    &query_string,
                    &next.host,
                    next.port,
                );
                current_target = Some(next);
            }

            warn!(
                proxy_id = %proxy.id,
                attempt = attempt,
                max_retries = retry_config.max_retries,
                connection_error = result.connection_error,
                "Retrying backend request"
            );

            // Build a minimal request for retry (body was consumed on first attempt).
            // The final retry attempt uses streaming if configured.
            let is_last_attempt = attempt >= retry_config.max_retries;
            result = proxy_to_backend_retry(
                &state,
                &proxy,
                &current_url,
                &method,
                proxy_headers,
                current_target.as_ref(),
                should_stream && is_last_attempt,
                &ctx.client_ip,
                is_tls,
            )
            .await;
        }
        result
    } else {
        proxy_to_backend(
            &state,
            &proxy,
            &backend_url,
            &method,
            proxy_headers,
            req,
            upstream_target.as_ref(),
            should_stream,
            &ctx.client_ip,
            is_tls,
        )
        .await
    };
    let response_status = backend_resp.status_code;
    let response_body = backend_resp.body;
    let mut response_headers = backend_resp.headers;
    let backend_resolved_ip = backend_resp.backend_resolved_ip;

    debug!(
        proxy_id = %proxy.id,
        status = response_status,
        connection_error = backend_resp.connection_error,
        "Backend response received"
    );

    // End connection tracking for least-connections
    if let (Some(upstream_id), Some(target)) = (&proxy.upstream_id, &upstream_target) {
        state
            .load_balancer_cache
            .record_connection_end(upstream_id, target);
    }

    // Record circuit breaker result: successes reset failure counters (Closed state)
    // and count toward recovery threshold (Half-Open state). Failures increment
    // the failure counter and may trip the breaker.
    if let Some(cb) = &circuit_breaker {
        if cb.config().failure_status_codes.contains(&response_status) {
            cb.record_failure(response_status);
        } else {
            cb.record_success();
        }
    }

    // Passive health check reporting (O(1) upstream lookup via index)
    if let (Some(upstream_id), Some(target)) = (&proxy.upstream_id, &upstream_target)
        && let Some(upstream) = state.load_balancer_cache.get_upstream(upstream_id)
        && let Some(hc) = &upstream.health_checks
    {
        state.health_checker.report_response(
            target,
            response_status,
            backend_resp.connection_error,
            hc.passive.as_ref(),
        );
    }

    let backend_elapsed = backend_start.elapsed().as_secs_f64() * 1000.0;
    let backend_ttfb_ms = backend_elapsed;
    // For buffered responses, backend_elapsed includes full body download (accurate total).
    // For streaming responses, the body is still being sent to the client at log time,
    // so we mark total as unknown (-1.0) to avoid silently reporting TTFB as total.
    let is_streaming_response = matches!(&response_body, ResponseBody::Streaming(_));
    let backend_total_ms = if is_streaming_response {
        -1.0
    } else {
        backend_elapsed
    };

    // after_proxy hooks (these only modify headers, not the body,
    // so they are compatible with both streaming and buffered modes)
    if !plugins.is_empty() {
        for plugin in plugins.iter() {
            if let PluginResult::Reject { status_code, .. } = plugin
                .after_proxy(&mut ctx, response_status, &mut response_headers)
                .await
            {
                warn!(
                    "after_proxy plugin '{}' returned Reject (status {}), but response is already committed",
                    plugin.name(),
                    status_code,
                );
            }
        }
    }

    let total_ms = start_time.elapsed().as_secs_f64() * 1000.0;
    let gateway_processing_ms = total_ms - backend_total_ms;

    // Log phase — skip TransactionSummary construction when no plugins need it
    if !plugins.is_empty() {
        let summary = TransactionSummary {
            timestamp_received: ctx.timestamp_received.to_rfc3339(),
            client_ip: ctx.client_ip.clone(),
            consumer_username: ctx.identified_consumer.as_ref().map(|c| c.username.clone()),
            http_method: method,
            request_path: path,
            matched_proxy_id: Some(proxy.id.clone()),
            matched_proxy_name: proxy.name.clone(),
            backend_target_url: Some(strip_query_params(&backend_url).to_string()),
            backend_resolved_ip,
            response_status_code: response_status,
            latency_total_ms: total_ms,
            latency_gateway_processing_ms: gateway_processing_ms,
            latency_backend_ttfb_ms: backend_ttfb_ms,
            latency_backend_total_ms: backend_total_ms,
            request_user_agent: ctx.headers.get("user-agent").cloned(),
            response_streamed: is_streaming_response,
            client_disconnected: false,
            metadata: ctx.metadata.clone(),
        };

        for plugin in plugins.iter() {
            plugin.log(&summary).await;
        }
    }

    record_request(&state, response_status);

    // Build final response
    let mut resp_builder = Response::builder()
        .status(StatusCode::from_u16(response_status).unwrap_or(StatusCode::BAD_GATEWAY));

    for (k, v) in &response_headers {
        if k == "set-cookie" {
            // Set-Cookie values were stored newline-separated to avoid RFC-violating
            // comma folding. Emit each value as a separate header line.
            for cookie_val in v.split('\n') {
                resp_builder = resp_builder.header("set-cookie", cookie_val);
            }
        } else {
            resp_builder = resp_builder.header(k.as_str(), v.as_str());
        }
    }

    // Add gateway error categorization headers so clients and ops teams
    // can distinguish different failure modes:
    //   X-Gateway-Error: connection_failure | backend_timeout | backend_error
    //   X-Gateway-Upstream-Status: degraded (when routing via all-unhealthy fallback)
    if backend_resp.connection_error {
        resp_builder = resp_builder.header("X-Gateway-Error", "connection_failure");
    } else if response_status == 504 {
        resp_builder = resp_builder.header("X-Gateway-Error", "backend_timeout");
    } else if response_status >= 500 {
        resp_builder = resp_builder.header("X-Gateway-Error", "backend_error");
    }

    if upstream_is_fallback {
        resp_builder = resp_builder.header("X-Gateway-Upstream-Status", "degraded");
    }

    // Advertise HTTP/3 availability via pre-computed Alt-Svc header
    if let Some(ref alt_svc) = state.alt_svc_header {
        resp_builder = resp_builder.header("alt-svc", alt_svc.as_str());
    }

    // Build response body: either stream from backend or return buffered data.
    // When FERRUM_ENABLE_STREAMING_LATENCY_TRACKING=true, streaming responses are
    // wrapped with a TrackedBody that records the final transfer time via a shared
    // atomic. A deferred task reads it after read_timeout + 5s to emit a
    // supplementary log with accurate backend_total_ms.
    // Default (false): streaming responses pass through with zero tracking overhead.
    let body = match response_body {
        ResponseBody::Streaming(resp) if state.env_config.enable_streaming_latency_tracking => {
            let (tracked_body, metrics) = ProxyBody::streaming_tracked(resp, backend_start);

            // Spawn a lightweight deferred task to log the final streaming latency.
            // Wakes once after read_timeout + 5s buffer, reads one atomic, emits one log line.
            let deferred_proxy_id = proxy.id.clone();
            let deferred_backend_url = strip_query_params(&backend_url).to_string();
            let read_timeout_ms = proxy.backend_read_timeout_ms;
            tokio::spawn(async move {
                tokio::time::sleep(std::time::Duration::from_millis(read_timeout_ms + 5_000)).await;
                let completed = metrics.completed();
                let total_ms = metrics.last_frame_elapsed_ms().unwrap_or(-1.0);
                if completed {
                    debug!(
                        proxy_id = %deferred_proxy_id,
                        backend_url = %deferred_backend_url,
                        backend_total_ms = total_ms,
                        "Streaming response completed"
                    );
                } else {
                    warn!(
                        proxy_id = %deferred_proxy_id,
                        backend_url = %deferred_backend_url,
                        backend_last_frame_ms = total_ms,
                        "Streaming response incomplete (client disconnect or timeout)"
                    );
                }
            });

            tracked_body
        }
        ResponseBody::Streaming(resp) => ProxyBody::streaming(resp),
        ResponseBody::Buffered(data) => ProxyBody::full(Bytes::from(data)),
    };

    Ok(resp_builder
        .body(body)
        .unwrap_or_else(|_| Response::new(ProxyBody::from_string("Internal Server Error"))))
}

/// Build the backend URL based on proxy config and path forwarding logic.
pub fn build_backend_url(proxy: &Proxy, incoming_path: &str, query_string: &str) -> String {
    build_backend_url_with_target(
        proxy,
        incoming_path,
        query_string,
        &proxy.backend_host,
        proxy.backend_port,
    )
}

/// Build backend URL using a specific host and port (for load-balanced targets).
///
/// Uses a single `String` buffer to avoid intermediate allocations from
/// multiple `format!` calls.
pub fn build_backend_url_with_target(
    proxy: &Proxy,
    incoming_path: &str,
    query_string: &str,
    host: &str,
    port: u16,
) -> String {
    use std::fmt::Write;

    let scheme = match proxy.backend_protocol {
        BackendProtocol::Http | BackendProtocol::Ws | BackendProtocol::Grpc => "http",
        BackendProtocol::Https
        | BackendProtocol::Wss
        | BackendProtocol::H3
        | BackendProtocol::Grpcs => "https",
        // Stream proxies (TCP/UDP) don't use HTTP URL building, but provide a sensible default
        BackendProtocol::Tcp | BackendProtocol::Udp => "http",
        BackendProtocol::TcpTls | BackendProtocol::Dtls => "https",
    };

    let remaining_path = if proxy.strip_listen_path {
        incoming_path.strip_prefix(&proxy.listen_path).unwrap_or("")
    } else {
        incoming_path
    };

    let backend_path = proxy.backend_path.as_deref().unwrap_or("");

    // Combine backend_path and remaining_path, ensuring a leading '/'
    let full_path = if backend_path.is_empty() && remaining_path.is_empty() {
        "/".to_string()
    } else {
        let combined = format!("{}{}", backend_path, remaining_path);
        if combined.starts_with('/') {
            combined
        } else {
            format!("/{}", combined)
        }
    };

    // Build URL in a single buffer with pre-allocated capacity
    let capacity = scheme.len()
        + 3
        + host.len()
        + 6
        + full_path.len()
        + if query_string.is_empty() {
            0
        } else {
            1 + query_string.len()
        };
    let mut url = String::with_capacity(capacity);
    let _ = write!(url, "{}://{}:{}{}", scheme, host, port, full_path);

    if !query_string.is_empty() {
        url.push('?');
        url.push_str(query_string);
    }

    url
}

/// Retry a backend request without a body (body was consumed on the first attempt).
/// For idempotent methods (GET, HEAD, DELETE, OPTIONS) this is safe.
#[allow(clippy::too_many_arguments)]
async fn proxy_to_backend_retry(
    state: &ProxyState,
    proxy: &Proxy,
    backend_url: &str,
    method: &str,
    headers: &HashMap<String, String>,
    upstream_target: Option<&UpstreamTarget>,
    stream_response: bool,
    client_ip: &str,
    is_tls: bool,
) -> retry::BackendResponse {
    // All reqwest clients use our DnsCacheResolver, so DNS resolution is
    // always served from the warmed cache — never hitting DNS on the hot path.
    // For both single-backend and load-balanced proxies, the client transparently
    // resolves hostnames through the DNS cache.
    let effective_host = upstream_target
        .map(|t| t.host.as_str())
        .unwrap_or(&proxy.backend_host);

    // Resolve backend IP from DNS cache (O(1) cached lookup).
    let resolved_ip = state
        .dns_cache
        .resolve(
            effective_host,
            proxy.dns_override.as_deref(),
            proxy.dns_cache_ttl_seconds,
        )
        .await
        .ok()
        .map(|ip| ip.to_string());

    let client = match state.connection_pool.get_client(proxy).await {
        Ok(client) => client,
        Err(e) => {
            error!("Failed to get client from pool for retry: {}", e);
            return retry::BackendResponse {
                status_code: 502,
                body: ResponseBody::Buffered(
                    format!(r#"{{"error":"Backend unavailable: {}"}}"#, e).into_bytes(),
                ),
                headers: HashMap::new(),
                connection_error: true,
                backend_resolved_ip: resolved_ip.clone(),
            };
        }
    };

    let req_method = match method {
        "GET" => reqwest::Method::GET,
        "POST" => reqwest::Method::POST,
        "PUT" => reqwest::Method::PUT,
        "DELETE" => reqwest::Method::DELETE,
        "PATCH" => reqwest::Method::PATCH,
        "HEAD" => reqwest::Method::HEAD,
        "OPTIONS" => reqwest::Method::OPTIONS,
        other => match reqwest::Method::from_bytes(other.as_bytes()) {
            Ok(m) => m,
            Err(_) => {
                warn!("Invalid HTTP method on retry: {}", other);
                return retry::BackendResponse {
                    status_code: 405,
                    body: ResponseBody::Buffered(
                        r#"{"error":"Method Not Allowed"}"#.as_bytes().to_vec(),
                    ),
                    headers: HashMap::new(),
                    connection_error: false,
                    backend_resolved_ip: resolved_ip.clone(),
                };
            }
        },
    };

    let mut req_builder = client.request(req_method, backend_url);

    // Forward headers, stripping hop-by-hop headers per RFC 7230 Section 6.1
    for (k, v) in headers {
        match k.as_str() {
            "host" => {
                if proxy.preserve_host_header {
                    req_builder = req_builder.header("Host", v.as_str());
                } else {
                    // Use upstream target host when load balancing, so SNI-based
                    // ingress routers see the correct Host header for the target.
                    req_builder = req_builder.header("Host", effective_host);
                }
            }
            // Hop-by-hop headers per RFC 7230 Section 6.1
            "connection"
            | "transfer-encoding"
            | "keep-alive"
            | "te"
            | "trailer"
            | "proxy-authorization"
            | "proxy-connection"
            | "upgrade" => continue,
            _ => {
                req_builder = req_builder.header(k.as_str(), v.as_str());
            }
        }
    }

    // Add proxy headers with real client IP
    if let Some(xff) = headers.get("x-forwarded-for") {
        req_builder = req_builder.header("X-Forwarded-For", format!("{}, {}", xff, client_ip));
    } else {
        req_builder = req_builder.header("X-Forwarded-For", client_ip);
    }
    req_builder = req_builder.header("X-Forwarded-Proto", if is_tls { "https" } else { "http" });
    if let Some(host) = headers.get("host") {
        req_builder = req_builder.header("X-Forwarded-Host", host.as_str());
    }

    match req_builder.send().await {
        Ok(response) => {
            let status = response.status().as_u16();
            let mut resp_headers = HashMap::new();
            collect_response_headers(response.headers(), &mut resp_headers);
            if stream_response {
                retry::BackendResponse {
                    status_code: status,
                    body: ResponseBody::Streaming(response),
                    headers: resp_headers,
                    connection_error: false,
                    backend_resolved_ip: resolved_ip.clone(),
                }
            } else {
                let body = response.bytes().await.unwrap_or_default().to_vec();
                retry::BackendResponse {
                    status_code: status,
                    body: ResponseBody::Buffered(body),
                    headers: resp_headers,
                    connection_error: false,
                    backend_resolved_ip: resolved_ip.clone(),
                }
            }
        }
        Err(e) => {
            let is_connect = e.is_connect();
            let is_timeout = e.is_timeout();
            let error_kind = if is_connect {
                "connect_failure"
            } else if is_timeout {
                "read_timeout"
            } else {
                "request_error"
            };
            error!(
                proxy_id = %proxy.id,
                backend_url = %backend_url,
                error_kind = error_kind,
                error = %e,
                "Backend retry request failed"
            );
            retry::BackendResponse {
                status_code: 502,
                body: ResponseBody::Buffered(
                    r#"{"error":"Backend unavailable"}"#.as_bytes().to_vec(),
                ),
                headers: HashMap::new(),
                connection_error: is_connect || is_timeout,
                backend_resolved_ip: resolved_ip.clone(),
            }
        }
    }
}

/// Proxy the request to the backend.
#[allow(clippy::too_many_arguments)]
async fn proxy_to_backend(
    state: &ProxyState,
    proxy: &Proxy,
    backend_url: &str,
    method: &str,
    headers: &HashMap<String, String>,
    original_req: Request<Incoming>,
    upstream_target: Option<&UpstreamTarget>,
    stream_response: bool,
    client_ip: &str,
    is_tls: bool,
) -> retry::BackendResponse {
    // All reqwest clients use our DnsCacheResolver, so DNS resolution is
    // always served from the warmed cache — never hitting DNS on the hot path.
    // For both single-backend and load-balanced proxies, the client transparently
    // resolves hostnames through the DNS cache.
    let effective_host = upstream_target
        .map(|t| t.host.as_str())
        .unwrap_or(&proxy.backend_host);

    // Resolve backend IP from DNS cache (O(1) cached lookup, <1μs).
    // This is the same cache reqwest will use internally via DnsCacheResolver,
    // so the IP will match the actual connection target.
    let resolved_ip = state
        .dns_cache
        .resolve(
            effective_host,
            proxy.dns_override.as_deref(),
            proxy.dns_cache_ttl_seconds,
        )
        .await
        .ok()
        .map(|ip| ip.to_string());

    // Handle HTTP/3 backend requests differently (always buffered — h3 crate
    // doesn't expose a streaming body API compatible with reqwest::Response)
    if matches!(proxy.backend_protocol, BackendProtocol::H3) {
        let (status, body, hdrs) = proxy_to_backend_http3(
            state,
            proxy,
            backend_url,
            method,
            headers,
            original_req,
            client_ip,
        )
        .await;
        return retry::BackendResponse {
            status_code: status,
            body: ResponseBody::Buffered(body),
            headers: hdrs,
            connection_error: false,
            backend_resolved_ip: resolved_ip.clone(),
        };
    }

    // Get client from connection pool for HTTP/1.1 and HTTP/2.
    // The client uses our DnsCacheResolver for transparent DNS cache lookups.
    // All upstream targets share one reqwest::Client since it handles
    // per-host pooling and SNI internally.
    let client = match state.connection_pool.get_client(proxy).await {
        Ok(client) => client,
        Err(e) => {
            error!("Failed to get client from pool: {}", e);
            // Fallback to creating new client
            reqwest::Client::builder()
                .connect_timeout(std::time::Duration::from_millis(
                    proxy.backend_connect_timeout_ms,
                ))
                .timeout(std::time::Duration::from_millis(
                    proxy.backend_read_timeout_ms,
                ))
                .danger_accept_invalid_certs(!proxy.backend_tls_verify_server_cert)
                .build()
                .unwrap_or_else(|_| reqwest::Client::new())
        }
    };

    let req_method = match method {
        "GET" => reqwest::Method::GET,
        "POST" => reqwest::Method::POST,
        "PUT" => reqwest::Method::PUT,
        "DELETE" => reqwest::Method::DELETE,
        "PATCH" => reqwest::Method::PATCH,
        "HEAD" => reqwest::Method::HEAD,
        "OPTIONS" => reqwest::Method::OPTIONS,
        other => match reqwest::Method::from_bytes(other.as_bytes()) {
            Ok(m) => m,
            Err(_) => {
                warn!("Invalid HTTP method: {}", other);
                return retry::BackendResponse {
                    status_code: 405,
                    body: ResponseBody::Buffered(
                        r#"{"error":"Method Not Allowed"}"#.as_bytes().to_vec(),
                    ),
                    headers: HashMap::new(),
                    connection_error: false,
                    backend_resolved_ip: resolved_ip.clone(),
                };
            }
        },
    };

    let mut req_builder = client.request(req_method, backend_url);

    // Forward headers, stripping hop-by-hop headers per RFC 7230 Section 6.1
    for (k, v) in headers {
        match k.as_str() {
            "host" => {
                if proxy.preserve_host_header {
                    req_builder = req_builder.header("Host", v.as_str());
                } else {
                    // Use upstream target host when load balancing, so SNI-based
                    // ingress routers see the correct Host header for the target.
                    req_builder = req_builder.header("Host", effective_host);
                }
            }
            // Hop-by-hop headers per RFC 7230 Section 6.1
            "connection"
            | "transfer-encoding"
            | "keep-alive"
            | "te"
            | "trailer"
            | "proxy-authorization"
            | "proxy-connection"
            | "upgrade" => continue,
            _ => {
                req_builder = req_builder.header(k.as_str(), v.as_str());
            }
        }
    }

    // Add proxy headers
    if let Some(xff) = headers.get("x-forwarded-for") {
        req_builder = req_builder.header("X-Forwarded-For", format!("{}, {}", xff, client_ip));
    } else {
        req_builder = req_builder.header("X-Forwarded-For", client_ip);
    }
    req_builder = req_builder.header("X-Forwarded-Proto", if is_tls { "https" } else { "http" });
    if let Some(host) = headers.get("host") {
        req_builder = req_builder.header("X-Forwarded-Host", host.as_str());
    }

    // Fast path: skip body collection for methods that typically have no body
    let has_body = !matches!(method, "GET" | "HEAD" | "DELETE" | "OPTIONS");

    if has_body {
        // Enforce request body size limit via Content-Length fast path
        if state.max_body_size_bytes > 0
            && let Some(content_length) = headers.get("content-length")
            && let Ok(len) = content_length.parse::<usize>()
            && len > state.max_body_size_bytes
        {
            return retry::BackendResponse {
                status_code: 413,
                body: ResponseBody::Buffered(
                    r#"{"error":"Request body exceeds maximum size"}"#.as_bytes().to_vec(),
                ),
                headers: HashMap::new(),
                connection_error: false,
                backend_resolved_ip: resolved_ip.clone(),
            };
        }

        // Collect and forward body with size limit.
        // Skip body collection for methods that typically carry no body to avoid
        // unnecessary Limited wrapper overhead on the hot path (GET health checks, etc.).
        let has_body = !matches!(method, "GET" | "HEAD" | "OPTIONS")
            || headers.contains_key("content-length")
            || headers.get("transfer-encoding").is_some();

        let body_bytes = if !has_body {
            // Fast path: skip body collection entirely for bodyless requests
            Vec::new()
        } else if state.max_body_size_bytes > 0 {
            let limited =
                http_body_util::Limited::new(original_req.into_body(), state.max_body_size_bytes);
            match limited.collect().await {
                Ok(collected) => collected.to_bytes().to_vec(),
                Err(_) => {
                    return retry::BackendResponse {
                        status_code: 413,
                        body: ResponseBody::Buffered(
                            r#"{"error":"Request body exceeds maximum size"}"#.as_bytes().to_vec(),
                        ),
                        headers: HashMap::new(),
                        connection_error: false,
                        backend_resolved_ip: resolved_ip.clone(),
                    };
                }
            }
        } else {
            match original_req.into_body().collect().await {
                Ok(collected) => collected.to_bytes().to_vec(),
                Err(e) => {
                    error!(
                        proxy_id = %proxy.id,
                        backend_url = %backend_url,
                        error_kind = "client_disconnect",
                        error = %e,
                        "Client disconnected while sending request body"
                    );
                    return retry::BackendResponse {
                        status_code: 499,
                        body: ResponseBody::Buffered(
                            r#"{"error":"Client disconnected"}"#.as_bytes().to_vec(),
                        ),
                        headers: HashMap::new(),
                        connection_error: true,
                        backend_resolved_ip: resolved_ip.clone(),
                    };
                }
            }
        };

        if !body_bytes.is_empty() {
            req_builder = req_builder.body(body_bytes);
        }
    }

    // Send
    match req_builder.send().await {
        Ok(response) => {
            let status = response.status().as_u16();
            let mut resp_headers = HashMap::new();
            collect_response_headers(response.headers(), &mut resp_headers);

            // Enforce response body size limit
            if state.max_response_body_size_bytes > 0 {
                // Fast path: check Content-Length header from backend
                let content_length = response
                    .headers()
                    .get("content-length")
                    .and_then(|v| v.to_str().ok())
                    .and_then(|v| v.parse::<usize>().ok());

                if let Some(len) = content_length
                    && len > state.max_response_body_size_bytes
                {
                    warn!(
                        "Backend response body ({} bytes) exceeds limit ({} bytes)",
                        len, state.max_response_body_size_bytes
                    );
                    return retry::BackendResponse {
                        status_code: 502,
                        body: ResponseBody::Buffered(
                            r#"{"error":"Backend response body exceeds maximum size"}"#
                                .as_bytes()
                                .to_vec(),
                        ),
                        headers: HashMap::new(),
                        connection_error: false,
                        backend_resolved_ip: resolved_ip.clone(),
                    };
                }

                // When streaming is requested and Content-Length is present and within
                // limits, we can safely stream. If there's no Content-Length we must
                // buffer to enforce the size limit.
                if stream_response && content_length.is_some() {
                    return retry::BackendResponse {
                        status_code: status,
                        body: ResponseBody::Streaming(response),
                        headers: resp_headers,
                        connection_error: false,
                        backend_resolved_ip: resolved_ip.clone(),
                    };
                }

                // Buffer: stream-collect with size limit
                let max_size = state.max_response_body_size_bytes;
                match collect_response_with_limit(response, max_size).await {
                    Ok((resp_body, _)) => retry::BackendResponse {
                        status_code: status,
                        body: ResponseBody::Buffered(resp_body),
                        headers: resp_headers,
                        connection_error: false,
                        backend_resolved_ip: resolved_ip.clone(),
                    },
                    Err(err_body) => retry::BackendResponse {
                        status_code: 502,
                        body: ResponseBody::Buffered(err_body),
                        headers: HashMap::new(),
                        connection_error: false,
                        backend_resolved_ip: resolved_ip.clone(),
                    },
                }
            } else if stream_response {
                // No size limit and streaming requested — pass through directly
                retry::BackendResponse {
                    status_code: status,
                    body: ResponseBody::Streaming(response),
                    headers: resp_headers,
                    connection_error: false,
                    backend_resolved_ip: resolved_ip.clone(),
                }
            } else {
                let body = response.bytes().await.unwrap_or_default().to_vec();
                retry::BackendResponse {
                    status_code: status,
                    body: ResponseBody::Buffered(body),
                    headers: resp_headers,
                    connection_error: false,
                    backend_resolved_ip: resolved_ip.clone(),
                }
            }
        }
        Err(e) => {
            let is_connect = e.is_connect();
            let is_timeout = e.is_timeout();
            let error_kind = if is_connect {
                "connect_failure"
            } else if is_timeout {
                "read_timeout"
            } else {
                "request_error"
            };
            error!(
                proxy_id = %proxy.id,
                backend_url = %backend_url,
                error_kind = error_kind,
                error = %e,
                "Backend request failed"
            );
            retry::BackendResponse {
                status_code: 502,
                body: ResponseBody::Buffered(
                    r#"{"error":"Backend unavailable"}"#.as_bytes().to_vec(),
                ),
                headers: HashMap::new(),
                connection_error: is_connect || is_timeout,
                backend_resolved_ip: resolved_ip.clone(),
            }
        }
    }
}

/// Collect a response body with a size limit, returning Err with error body if exceeded.
async fn collect_response_with_limit(
    response: reqwest::Response,
    max_size: usize,
) -> Result<(Vec<u8>, usize), Vec<u8>> {
    use futures_util::StreamExt as _;
    let mut body = Vec::new();
    let mut stream = response.bytes_stream();
    while let Some(chunk_result) = stream.next().await {
        match chunk_result {
            Ok(chunk) => {
                if body.len() + chunk.len() > max_size {
                    warn!(
                        "Backend response truncated: exceeded {} byte limit",
                        max_size
                    );
                    return Err(r#"{"error":"Backend response body exceeds maximum size"}"#
                        .as_bytes()
                        .to_vec());
                }
                body.extend_from_slice(&chunk);
            }
            Err(e) => {
                error!("Error reading backend response: {}", e);
                return Err(r#"{"error":"Backend response read error"}"#.as_bytes().to_vec());
            }
        }
    }
    let len = body.len();
    Ok((body, len))
}

fn strip_query_params(url: &str) -> &str {
    url.split('?').next().unwrap_or(url)
}

fn record_status(state: &ProxyState, status: u16) {
    // Fast path: get() uses a read lock (shared), which is much cheaper than
    // entry() which always takes a write lock. Since status codes are a small
    // fixed set, the entry almost always exists after the first request.
    if let Some(counter) = state.status_counts.get(&status) {
        counter.fetch_add(1, Ordering::Relaxed);
    } else {
        state
            .status_counts
            .entry(status)
            .or_insert_with(|| AtomicU64::new(0))
            .fetch_add(1, Ordering::Relaxed);
    }
}

fn record_request(state: &ProxyState, status: u16) {
    state.request_count.fetch_add(1, Ordering::Relaxed);
    record_status(state, status);
}

/// Collect backend response headers into a HashMap.
///
/// RFC 7230 Section 3.2.2 allows folding multi-valued headers with commas,
/// **except** `Set-Cookie` (RFC 6265) which must be emitted as separate header
/// lines. We store multiple Set-Cookie values separated by `\n` so they can be
/// split back into individual headers when building the downstream response.
fn collect_response_headers(
    source: &reqwest::header::HeaderMap,
    target: &mut HashMap<String, String>,
) {
    target.reserve(source.keys_len());
    for (k, v) in source {
        if let Ok(vs) = v.to_str() {
            let key = k.as_str().to_string();
            if k == "set-cookie" {
                target
                    .entry(key)
                    .and_modify(|existing: &mut String| {
                        existing.push('\n');
                        existing.push_str(vs);
                    })
                    .or_insert_with(|| vs.to_string());
            } else {
                target
                    .entry(key)
                    .and_modify(|existing: &mut String| {
                        existing.push_str(", ");
                        existing.push_str(vs);
                    })
                    .or_insert_with(|| vs.to_string());
            }
        }
    }
}

fn build_response(status: StatusCode, body: &str) -> Response<ProxyBody> {
    // Response::builder with a valid status and static header name cannot fail
    Response::builder()
        .status(status)
        .header("Content-Type", "application/json")
        .body(ProxyBody::from_string(body))
        .unwrap_or_else(|_| {
            Response::new(ProxyBody::from_string(
                r#"{"error":"Internal server error"}"#,
            ))
        })
}

fn build_reject_response(
    status: StatusCode,
    body: &str,
    headers: &HashMap<String, String>,
) -> Response<ProxyBody> {
    let mut resp = build_response(status, body);
    for (k, v) in headers {
        if let (Ok(name), Ok(val)) = (
            hyper::header::HeaderName::from_bytes(k.as_bytes()),
            hyper::header::HeaderValue::from_str(v),
        ) {
            resp.headers_mut().insert(name, val);
        }
    }
    resp
}

/// Proxy the request to an HTTP/3 backend.
async fn proxy_to_backend_http3(
    state: &ProxyState,
    proxy: &Proxy,
    backend_url: &str,
    method: &str,
    headers: &HashMap<String, String>,
    original_req: Request<Incoming>,
    client_ip: &str,
) -> (u16, Vec<u8>, HashMap<String, String>) {
    debug!(proxy_id = %proxy.id, backend_url = %backend_url, "Proxying request to HTTP/3 backend");

    // Create HTTP/3 client with TLS configuration
    let tls_config = state.connection_pool.get_tls_config_for_backend(proxy);
    let http3_client = match Http3Client::new(tls_config) {
        Ok(client) => client,
        Err(e) => {
            error!(
                proxy_id = %proxy.id,
                backend_url = %backend_url,
                error_kind = "client_creation",
                error = %e,
                "Failed to create HTTP/3 client"
            );
            let body = r#"{"error":"HTTP/3 client creation failed"}"#;
            return (502, body.as_bytes().to_vec(), HashMap::new());
        }
    };

    // Read request body with size limit
    let (_parts, body) = original_req.into_parts();
    let request_body = if state.max_body_size_bytes > 0 {
        // Check Content-Length fast path
        if let Some(content_length) = headers.get("content-length")
            && let Ok(len) = content_length.parse::<usize>()
            && len > state.max_body_size_bytes
        {
            return (
                413,
                r#"{"error":"Request body exceeds maximum size"}"#.as_bytes().to_vec(),
                HashMap::new(),
            );
        }
        let limited = http_body_util::Limited::new(body, state.max_body_size_bytes);
        match limited.collect().await {
            Ok(collected) => collected.to_bytes(),
            Err(_) => {
                return (
                    413,
                    r#"{"error":"Request body exceeds maximum size"}"#.as_bytes().to_vec(),
                    HashMap::new(),
                );
            }
        }
    } else {
        match body.collect().await {
            Ok(collected) => collected.to_bytes(),
            Err(e) => {
                error!(
                    proxy_id = %proxy.id,
                    backend_url = %backend_url,
                    error_kind = "client_disconnect",
                    error = %e,
                    "Client disconnected while sending request body (HTTP/3)"
                );
                Bytes::new()
            }
        }
    };

    // Convert headers to HTTP/3 format
    let mut http3_headers: Vec<(hyper::header::HeaderName, hyper::header::HeaderValue)> =
        Vec::new();
    for (name, value) in headers {
        if name == "connection" || name == "transfer-encoding" {
            continue;
        }
        if let (Ok(header_name), Ok(header_value)) = (name.parse(), value.parse()) {
            http3_headers.push((header_name, header_value));
        } else {
            debug!("Skipping invalid HTTP/3 header: {}={}", name, value);
        }
    }

    // Add X-Forwarded-* headers (matching HTTP/1.1 and HTTP/2 paths)
    if let Some(xff) = headers.get("x-forwarded-for") {
        if let Ok(v) = format!("{}, {}", xff, client_ip).parse() {
            http3_headers.push((hyper::header::HeaderName::from_static("x-forwarded-for"), v));
        }
    } else if let Ok(v) = client_ip.parse() {
        http3_headers.push((hyper::header::HeaderName::from_static("x-forwarded-for"), v));
    }
    if let Ok(v) = "https".parse() {
        http3_headers.push((
            hyper::header::HeaderName::from_static("x-forwarded-proto"),
            v,
        ));
    }
    if let Some(host) = headers.get("host")
        && let Ok(v) = host.parse()
    {
        http3_headers.push((
            hyper::header::HeaderName::from_static("x-forwarded-host"),
            v,
        ));
    }

    // Make HTTP/3 request
    match http3_client
        .request(proxy, method, backend_url, http3_headers, request_body)
        .await
    {
        Ok(response) => {
            debug!(proxy_id = %proxy.id, status = response.0, "HTTP/3 backend request successful");
            (response.0, response.1, response.2)
        }
        Err(e) => {
            let error_kind =
                if e.to_string().contains("timeout") || e.to_string().contains("timed out") {
                    "read_timeout"
                } else if e.to_string().contains("connect") || e.to_string().contains("refused") {
                    "connect_failure"
                } else {
                    "request_error"
                };
            error!(
                proxy_id = %proxy.id,
                backend_url = %backend_url,
                error_kind = error_kind,
                error = %e,
                "HTTP/3 backend request failed"
            );
            (
                502,
                r#"{"error":"HTTP/3 backend request failed"}"#.as_bytes().to_vec(),
                HashMap::new(),
            )
        }
    }
}
