//! Health checking for upstream targets.
//!
//! Supports active health checks (periodic HTTP probes) and passive health
//! checks (monitoring response status codes from proxied requests).
//!
//! **Active health checks** are shared across all proxies referencing the same
//! upstream — the probe result (TCP SYN, HTTP GET, gRPC Check) is the same
//! regardless of which proxy routes through the upstream.
//!
//! **Passive health checks** are isolated per-proxy via a two-level index:
//! `proxy_id → (host:port → state)`. Each proxy tracks its own failure counters
//! and unhealthy state, so proxy A sending large payloads that trigger 500s
//! cannot poison the health view for proxy B sending small payloads that succeed.
//!
//! Active health checks share a single `reqwest::Client` configured with the
//! gateway's global connection pool settings (keep-alive, idle timeout, HTTP/2,
//! TCP keep-alive) and the shared DNS cache so that probe connections behave
//! like real proxy traffic and benefit from connection reuse and cached DNS
//! resolution across targets.

mod grpc_health_v1 {
    tonic::include_proto!("grpc.health.v1");
}

use crate::config::pool_config::PoolConfig;
use crate::config::types::{
    ActiveHealthCheck, GatewayConfig, HealthProbeType, PassiveHealthCheck, UpstreamTarget,
};
use crate::dns::{DnsCache, DnsCacheResolver};
use crate::load_balancer::LoadBalancerCache;
use dashmap::DashMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicU32, AtomicU64, Ordering};
use std::time::Duration;
use tracing::{debug, info, warn};

/// Wait for a shutdown signal on a watch channel.
async fn wait_for_shutdown(mut rx: tokio::sync::watch::Receiver<bool>) {
    while !*rx.borrow() {
        if rx.changed().await.is_err() {
            return;
        }
    }
}

/// Build a key for active health state: "upstream_id::host:port".
/// Shared across all proxies referencing the same upstream.
fn active_target_key(upstream_id: &str, target: &UpstreamTarget) -> String {
    format!("{}::{}:{}", upstream_id, target.host, target.port)
}

/// Build a plain "host:port" key for passive health state lookups.
fn host_port_key(target: &UpstreamTarget) -> String {
    format!("{}:{}", target.host, target.port)
}

/// Maximum entries in the recent_failures DashMap per target.
/// Prevents unbounded memory growth during cascading failure scenarios
/// where failure rate vastly exceeds the window cleanup rate.
const MAX_RECENT_FAILURES_PER_TARGET: usize = 1000;

/// Health state for a single target.
struct TargetHealth {
    consecutive_successes: AtomicU32,
    consecutive_failures: AtomicU32,
    /// Recent failure timestamps (epoch ms) for passive windowed counting.
    /// Key is a monotonic counter, value is the timestamp.
    /// Bounded to MAX_RECENT_FAILURES_PER_TARGET entries.
    recent_failures: dashmap::DashMap<u64, u64>,
    failure_counter: AtomicU64,
}

impl TargetHealth {
    fn new() -> Self {
        Self {
            consecutive_successes: AtomicU32::new(0),
            consecutive_failures: AtomicU32::new(0),
            recent_failures: DashMap::new(),
            failure_counter: AtomicU64::new(0),
        }
    }
}

/// Per-proxy passive health state for a set of targets.
///
/// Wraps `unhealthy` and `states` DashMaps keyed by `host:port`. One instance
/// exists per proxy that has passive health checks configured, stored in the
/// outer `DashMap<proxy_id, Arc<ProxyHealthState>>`.
pub struct ProxyHealthState {
    /// host:port → epoch_ms when marked unhealthy.
    pub unhealthy: DashMap<String, u64>,
    /// host:port → failure/success tracking state.
    states: DashMap<String, Arc<TargetHealth>>,
}

impl ProxyHealthState {
    fn new() -> Self {
        Self {
            unhealthy: DashMap::new(),
            states: DashMap::new(),
        }
    }
}

/// Manages health state for all upstream targets.
///
/// Health state is split into two independent layers:
///
/// - **Active** (shared per-upstream): Periodic probe results (HTTP/TCP/UDP/gRPC)
///   keyed by `upstream_id::host:port`. When an active probe marks a target
///   unhealthy, ALL proxies using that upstream see it as unavailable — correct
///   because the target is genuinely unreachable.
///
/// - **Passive** (isolated per-proxy): Two-level index
///   `proxy_id → Arc<ProxyHealthState>` where `ProxyHealthState` contains
///   `host:port`-keyed DashMaps for unhealthy status and failure counters.
///   When proxy A's requests trigger 500s, only proxy A's inner map is
///   affected. Proxy B has its own `ProxyHealthState` (or none if it hasn't
///   seen any failures).
///
/// Target selection checks both layers — a target is considered unhealthy if it
/// appears in EITHER the active map (upstream-wide) OR the calling proxy's
/// passive inner map.
pub struct HealthChecker {
    /// Active unhealthy targets: "upstream_id::host:port" → epoch_ms.
    /// Written by active health check probes, shared across all proxies.
    pub active_unhealthy_targets: Arc<DashMap<String, u64>>,
    /// Active probe health state, keyed by "upstream_id::host:port".
    active_target_states: Arc<DashMap<String, Arc<TargetHealth>>>,
    /// Per-proxy passive health state: proxy_id → Arc<ProxyHealthState>.
    /// Two-level index: outer DashMap partitions by proxy_id (one lookup),
    /// inner DashMaps use plain "host:port" keys (shorter, less contention).
    pub passive_health: Arc<DashMap<String, Arc<ProxyHealthState>>>,
    /// Shared HTTP client for active health check probes, configured with
    /// the gateway's connection pool settings for proper keep-alive and reuse.
    http_client: Arc<reqwest::Client>,
    /// Active check abort handles.
    active_check_handles: Vec<tokio::task::JoinHandle<()>>,
    /// Optional reference to the load balancer cache for recording active
    /// probe latencies (used by least-latency algorithm). Set via
    /// `set_load_balancer_cache()` after construction.
    lb_cache: Option<Arc<LoadBalancerCache>>,
}

impl Default for HealthChecker {
    fn default() -> Self {
        Self::without_dns_cache(&PoolConfig::default())
    }
}

impl HealthChecker {
    /// Create a health checker using default pool settings and no DNS cache.
    ///
    /// Prefer [`with_pool_config`] in production to inherit the gateway's
    /// tuned connection pool settings and DNS cache. Kept for tests and
    /// integration code that constructs `HealthChecker` without a full config.
    #[allow(dead_code)]
    pub fn new() -> Self {
        Self::default()
    }

    /// Create a health checker with an HTTP client configured from the
    /// gateway's global pool settings and shared DNS cache.
    pub fn with_pool_config(pool_config: &PoolConfig, dns_cache: DnsCache) -> Self {
        let client = build_health_check_client(pool_config, dns_cache);
        Self {
            active_unhealthy_targets: Arc::new(DashMap::new()),
            active_target_states: Arc::new(DashMap::new()),
            passive_health: Arc::new(DashMap::new()),
            http_client: Arc::new(client),
            active_check_handles: Vec::new(),
            lb_cache: None,
        }
    }

    /// Create a health checker without DNS cache (for tests).
    fn without_dns_cache(pool_config: &PoolConfig) -> Self {
        let mut builder = reqwest::Client::builder()
            .pool_max_idle_per_host(pool_config.max_idle_per_host)
            .pool_idle_timeout(Duration::from_secs(pool_config.idle_timeout_seconds))
            .danger_accept_invalid_certs(true);

        if pool_config.enable_http_keep_alive {
            builder = builder.tcp_keepalive(Duration::from_secs(pool_config.tcp_keepalive_seconds));
        }

        if pool_config.enable_http2 {
            builder = builder
                .http2_keep_alive_interval(Duration::from_secs(
                    pool_config.http2_keep_alive_interval_seconds,
                ))
                .http2_keep_alive_timeout(Duration::from_secs(
                    pool_config.http2_keep_alive_timeout_seconds,
                ));
        }

        let client = match builder.build() {
            Ok(client) => client,
            Err(e) => {
                tracing::error!(
                    "Failed to build health check HTTP client: {}. \
                     Falling back to default client.",
                    e
                );
                reqwest::Client::new()
            }
        };

        Self {
            active_unhealthy_targets: Arc::new(DashMap::new()),
            active_target_states: Arc::new(DashMap::new()),
            passive_health: Arc::new(DashMap::new()),
            http_client: Arc::new(client),
            active_check_handles: Vec::new(),
            lb_cache: None,
        }
    }

    /// Set a reference to the load balancer cache so active health check probes
    /// can record their RTT for least-latency load balancing.
    pub fn set_load_balancer_cache(&mut self, lb_cache: Arc<LoadBalancerCache>) {
        self.lb_cache = Some(lb_cache);
    }

    /// Start health checks for all upstreams in the config.
    pub fn start(&mut self, config: &GatewayConfig) {
        self.start_with_shutdown(config, None);
    }

    /// Start health checks with an optional shutdown signal.
    pub fn start_with_shutdown(
        &mut self,
        config: &GatewayConfig,
        shutdown_rx: Option<tokio::sync::watch::Receiver<bool>>,
    ) {
        // Cancel any existing active check tasks
        for handle in self.active_check_handles.drain(..) {
            handle.abort();
        }

        for upstream in &config.upstreams {
            if let Some(hc_config) = &upstream.health_checks {
                // Start active health checks
                if let Some(active) = &hc_config.active {
                    for target in &upstream.targets {
                        let handle = self.start_active_check(
                            target,
                            active,
                            &upstream.id,
                            shutdown_rx.clone(),
                        );
                        self.active_check_handles.push(handle);
                    }
                }

                // Start passive recovery timer if passive health checks are
                // configured with a non-zero healthy_after_seconds.
                if let Some(passive) = &hc_config.passive
                    && passive.healthy_after_seconds > 0
                {
                    let handle = self.start_passive_recovery_timer(
                        &upstream.targets,
                        passive.healthy_after_seconds,
                        shutdown_rx.clone(),
                    );
                    self.active_check_handles.push(handle);
                }
            }
        }
    }

    /// Get or create the per-proxy passive health state.
    ///
    /// Fast-path: `get()` with borrowed `&str` (zero allocation, read lock).
    /// Cold-path: `entry()` with owned `String` (one allocation, write lock) —
    /// only on the first request from a new proxy_id.
    fn get_proxy_state(&self, proxy_id: &str) -> Arc<ProxyHealthState> {
        if let Some(existing) = self.passive_health.get(proxy_id) {
            return existing.value().clone();
        }
        self.passive_health
            .entry(proxy_id.to_owned())
            .or_insert_with(|| Arc::new(ProxyHealthState::new()))
            .clone()
    }

    /// Report a response from a proxied request (passive health checking).
    ///
    /// Writes to the per-proxy passive health state via the two-level index:
    /// `proxy_id → ProxyHealthState → host:port`. This ensures proxy A's
    /// failures cannot affect proxy B's health view, even when both proxies
    /// share the same upstream.
    pub fn report_response(
        &self,
        proxy_id: &str,
        target: &UpstreamTarget,
        status_code: u16,
        connection_error: bool,
        passive_config: Option<&PassiveHealthCheck>,
    ) {
        let config = match passive_config {
            Some(c) => c,
            None => return,
        };

        let proxy_state = self.get_proxy_state(proxy_id);
        let hp_key = host_port_key(target);

        // Get or create target health state within this proxy's partition
        let state = if let Some(existing) = proxy_state.states.get(&hp_key) {
            existing.clone()
        } else {
            proxy_state
                .states
                .entry(hp_key.clone())
                .or_insert_with(|| Arc::new(TargetHealth::new()))
                .clone()
        };

        if connection_error || config.unhealthy_status_codes.contains(&status_code) {
            state.consecutive_successes.store(0, Ordering::Relaxed);
            state.consecutive_failures.fetch_add(1, Ordering::Relaxed);

            let now_ms = now_epoch_ms();
            let counter = state.failure_counter.fetch_add(1, Ordering::Relaxed);
            state.recent_failures.insert(counter, now_ms);

            // Clean old failures outside the window
            let window_start = now_ms.saturating_sub(config.unhealthy_window_seconds * 1000);
            state
                .recent_failures
                .retain(|_, &mut ts| ts >= window_start);

            // Hard cap: prevent unbounded memory growth
            if state.recent_failures.len() > MAX_RECENT_FAILURES_PER_TARGET {
                let excess = state.recent_failures.len() - MAX_RECENT_FAILURES_PER_TARGET;
                let mut to_remove: Vec<u64> = state
                    .recent_failures
                    .iter()
                    .map(|entry| *entry.key())
                    .collect();
                to_remove.sort_unstable();
                for key in to_remove.into_iter().take(excess) {
                    state.recent_failures.remove(&key);
                }
            }

            let failures_in_window = state.recent_failures.len() as u32;
            if failures_in_window >= config.unhealthy_threshold
                && !proxy_state.unhealthy.contains_key(&hp_key)
            {
                warn!(
                    "Passive health check: marking target {} as unhealthy for proxy {} ({} failures in {}s window)",
                    hp_key, proxy_id, failures_in_window, config.unhealthy_window_seconds
                );
                proxy_state.unhealthy.insert(hp_key, now_epoch_ms());
            }
        } else {
            let failures = state.consecutive_failures.load(Ordering::Relaxed);
            state.consecutive_successes.fetch_add(1, Ordering::Relaxed);
            if failures > 0 {
                state.consecutive_failures.store(0, Ordering::Relaxed);
            }

            if proxy_state.unhealthy.contains_key(&hp_key) {
                let successes = state.consecutive_successes.load(Ordering::Relaxed);
                if successes >= 1 {
                    info!(
                        "Passive health check: marking target {} as healthy again for proxy {}",
                        hp_key, proxy_id
                    );
                    proxy_state.unhealthy.remove(&hp_key);
                    state.recent_failures.clear();
                }
            }
        }
    }

    /// Remove health state for targets no longer in the active target list.
    ///
    /// Called from the service discovery loop after `update_targets()` to
    /// prevent unbounded growth of the health DashMaps when targets are
    /// dynamically removed. This runs in a background task, NOT on the
    /// proxy hot path.
    pub fn remove_stale_targets(&self, upstream_id: &str, current_targets: &[UpstreamTarget]) {
        // Active: exact key match on "upstream_id::host:port"
        let active_keys: std::collections::HashSet<String> = current_targets
            .iter()
            .map(|t| active_target_key(upstream_id, t))
            .collect();
        self.active_unhealthy_targets
            .retain(|key, _| active_keys.contains(key));
        self.active_target_states
            .retain(|key, _| active_keys.contains(key));

        // Passive: for each proxy's inner map, retain only current host:port targets
        let hp_set: std::collections::HashSet<String> =
            current_targets.iter().map(host_port_key).collect();
        for entry in self.passive_health.iter() {
            let proxy_state = entry.value();
            proxy_state
                .unhealthy
                .retain(|hp, _| hp_set.contains(hp.as_str()));
            proxy_state
                .states
                .retain(|hp, _| hp_set.contains(hp.as_str()));
        }
    }

    /// Remove passive health state for proxies that have been deleted from
    /// config. Prevents the outer `passive_health` DashMap from growing
    /// unboundedly as proxies are added and removed over the gateway's lifetime.
    /// Called from `ProxyState::update_config()` alongside circuit breaker pruning.
    pub fn prune_removed_proxies(&self, removed_proxy_ids: &[String]) {
        for id in removed_proxy_ids {
            self.passive_health.remove(id);
        }
    }

    /// Start a background timer that automatically restores passively-marked
    /// unhealthy targets after `healthy_after_seconds`.
    fn start_passive_recovery_timer(
        &self,
        targets: &[UpstreamTarget],
        healthy_after_seconds: u64,
        shutdown_rx: Option<tokio::sync::watch::Receiver<bool>>,
    ) -> tokio::task::JoinHandle<()> {
        let passive_health = self.passive_health.clone();
        let hp_keys: std::collections::HashSet<String> =
            targets.iter().map(host_port_key).collect();
        let check_interval = Duration::from_secs(std::cmp::max(healthy_after_seconds / 4, 1));
        let recovery_ms = healthy_after_seconds * 1000;

        tokio::spawn(async move {
            let mut timer = tokio::time::interval(check_interval);

            loop {
                if let Some(ref rx) = shutdown_rx {
                    tokio::select! {
                        _ = timer.tick() => {}
                        _ = wait_for_shutdown(rx.clone()) => {
                            info!("Passive recovery timer shutting down");
                            return;
                        }
                    }
                } else {
                    timer.tick().await;
                }

                let now = now_epoch_ms();

                // Iterate each proxy's passive state
                for entry in passive_health.iter() {
                    let proxy_id = entry.key();
                    let proxy_state = entry.value();

                    // Collect keys to recover within this proxy's map
                    let to_recover: Vec<String> = proxy_state
                        .unhealthy
                        .iter()
                        .filter(|e| {
                            hp_keys.contains(e.key().as_str())
                                && now.saturating_sub(*e.value()) >= recovery_ms
                        })
                        .map(|e| e.key().clone())
                        .collect();

                    for hp in &to_recover {
                        if proxy_state.unhealthy.remove(hp).is_some() {
                            info!(
                                "Passive recovery timer: restoring target {} for proxy {} after {}s cooldown",
                                hp, proxy_id, healthy_after_seconds
                            );
                            if let Some(state) = proxy_state.states.get(hp) {
                                state.consecutive_failures.store(0, Ordering::Relaxed);
                                state.consecutive_successes.store(0, Ordering::Relaxed);
                                state.recent_failures.clear();
                            }
                        }
                    }
                }
            }
        })
    }

    /// Start an active health check background task for a target.
    fn start_active_check(
        &self,
        target: &UpstreamTarget,
        config: &ActiveHealthCheck,
        upstream_id: &str,
        shutdown_rx: Option<tokio::sync::watch::Receiver<bool>>,
    ) -> tokio::task::JoinHandle<()> {
        let key = active_target_key(upstream_id, target);
        let interval = Duration::from_secs(config.interval_seconds);
        let timeout = Duration::from_millis(config.timeout_ms);
        let healthy_threshold = config.healthy_threshold;
        let unhealthy_threshold = config.unhealthy_threshold;
        let unhealthy_targets = self.active_unhealthy_targets.clone();
        let target_states = self.active_target_states.clone();

        let probe_type = config.probe_type;
        let host = target.host.clone();
        let port = target.port;
        let healthy_status_codes = config.healthy_status_codes.clone();
        let client = self.http_client.clone();
        let scheme = if config.use_tls { "https" } else { "http" };
        let url = format!("{}://{}:{}{}", scheme, host, port, config.http_path);
        let udp_payload = config
            .udp_probe_payload
            .as_deref()
            .and_then(|hex| hex::decode(hex).ok())
            .unwrap_or_default();
        let use_tls = config.use_tls;
        let grpc_service_name = config.grpc_service_name.clone().unwrap_or_default();

        let probe_target = target.clone();
        let lb_cache = self.lb_cache.clone();
        let upstream_id_owned = upstream_id.to_owned();

        tokio::spawn(async move {
            let mut timer = tokio::time::interval(interval);

            loop {
                if let Some(ref rx) = shutdown_rx {
                    tokio::select! {
                        _ = timer.tick() => {}
                        _ = wait_for_shutdown(rx.clone()) => {
                            info!("Active health check for {} shutting down", key);
                            return;
                        }
                    }
                } else {
                    timer.tick().await;
                }

                let state = target_states
                    .entry(key.clone())
                    .or_insert_with(|| Arc::new(TargetHealth::new()))
                    .clone();

                let probe_start = std::time::Instant::now();
                let probe_success = match probe_type {
                    HealthProbeType::Http => {
                        http_probe(&client, &url, timeout, &healthy_status_codes).await
                    }
                    HealthProbeType::Tcp => tcp_probe(&host, port, timeout).await,
                    HealthProbeType::Udp => udp_probe(&host, port, timeout, &udp_payload).await,
                    HealthProbeType::Grpc => {
                        grpc_probe(&host, port, timeout, use_tls, &grpc_service_name).await
                    }
                };

                if probe_success {
                    state.consecutive_failures.store(0, Ordering::Relaxed);
                    let successes = state.consecutive_successes.fetch_add(1, Ordering::Relaxed) + 1;

                    if let Some(ref cache) = lb_cache {
                        let latency_us = probe_start.elapsed().as_micros() as u64;
                        cache.record_latency(&upstream_id_owned, &probe_target, latency_us);
                    }

                    if successes >= healthy_threshold && unhealthy_targets.remove(&key).is_some() {
                        info!(
                            "Active health check: target {} is healthy ({:?} probe)",
                            key, probe_type
                        );
                        if let Some(ref cache) = lb_cache {
                            cache.reset_recovered_target_latency(&upstream_id_owned, &probe_target);
                        }
                    }
                } else {
                    state.consecutive_successes.store(0, Ordering::Relaxed);
                    let failures = state.consecutive_failures.fetch_add(1, Ordering::Relaxed) + 1;

                    if failures >= unhealthy_threshold {
                        let key_ref = key.clone();
                        unhealthy_targets.entry(key.clone()).or_insert_with(|| {
                            warn!(
                                "Active health check: target {} is unhealthy ({:?} probe)",
                                key_ref, probe_type
                            );
                            now_epoch_ms()
                        });
                    }
                }
            }
        })
    }
}

impl Drop for HealthChecker {
    fn drop(&mut self) {
        for handle in &self.active_check_handles {
            handle.abort();
        }
    }
}

/// HTTP health probe — sends a GET request and checks the status code.
async fn http_probe(
    client: &reqwest::Client,
    url: &str,
    timeout: Duration,
    healthy_status_codes: &[u16],
) -> bool {
    match client.get(url).timeout(timeout).send().await {
        Ok(resp) => {
            let status = resp.status().as_u16();
            if healthy_status_codes.is_empty() {
                (200..300).contains(&status)
            } else {
                healthy_status_codes.contains(&status)
            }
        }
        Err(e) => {
            debug!("HTTP health probe failed for {}: {}", url, e);
            false
        }
    }
}

/// TCP health probe — attempts a TCP connection within the timeout.
async fn tcp_probe(host: &str, port: u16, timeout: Duration) -> bool {
    let addr = format!("{}:{}", host, port);
    match tokio::time::timeout(timeout, tokio::net::TcpStream::connect(&addr)).await {
        Ok(Ok(_stream)) => true,
        Ok(Err(e)) => {
            debug!("TCP health probe connection failed for {}: {}", addr, e);
            false
        }
        Err(_) => {
            debug!("TCP health probe timed out for {}", addr);
            false
        }
    }
}

/// UDP health probe — sends a payload and waits for any response within the timeout.
async fn udp_probe(host: &str, port: u16, timeout: Duration, payload: &[u8]) -> bool {
    let addr = format!("{}:{}", host, port);
    let bind_addr = if host.parse::<std::net::Ipv6Addr>().is_ok() {
        "[::]:0"
    } else {
        "0.0.0.0:0"
    };
    let socket = match tokio::net::UdpSocket::bind(bind_addr).await {
        Ok(s) => s,
        Err(e) => {
            debug!("UDP health probe: failed to bind socket: {}", e);
            return false;
        }
    };

    if let Err(e) = socket.connect(&addr).await {
        debug!("UDP health probe: failed to connect to {}: {}", addr, e);
        return false;
    }

    let data = if payload.is_empty() { &[0u8] } else { payload };
    if let Err(e) = socket.send(data).await {
        debug!("UDP health probe: failed to send to {}: {}", addr, e);
        return false;
    }

    let mut buf = [0u8; 1];
    match tokio::time::timeout(timeout, socket.recv(&mut buf)).await {
        Ok(Ok(_)) => true,
        Ok(Err(e)) => {
            debug!("UDP health probe: recv error from {}: {}", addr, e);
            false
        }
        Err(_) => {
            debug!("UDP health probe timed out for {}", addr);
            false
        }
    }
}

/// gRPC health probe — performs a unary grpc.health.v1.Health/Check RPC.
async fn grpc_probe(
    host: &str,
    port: u16,
    timeout: Duration,
    use_tls: bool,
    service_name: &str,
) -> bool {
    let scheme = if use_tls { "https" } else { "http" };
    let endpoint_url = format!("{}://{}:{}", scheme, host, port);

    let endpoint = match tonic::transport::Endpoint::from_shared(endpoint_url) {
        Ok(ep) => ep.timeout(timeout).connect_timeout(timeout),
        Err(e) => {
            debug!(
                "gRPC health probe: invalid endpoint for {}:{}: {}",
                host, port, e
            );
            return false;
        }
    };

    let endpoint = if use_tls {
        let tls_config = tonic::transport::ClientTlsConfig::new().with_enabled_roots();
        match endpoint.tls_config(tls_config) {
            Ok(ep) => ep,
            Err(e) => {
                debug!(
                    "gRPC health probe: TLS config error for {}:{}: {}",
                    host, port, e
                );
                return false;
            }
        }
    } else {
        endpoint
    };

    let channel = match tokio::time::timeout(timeout, endpoint.connect()).await {
        Ok(Ok(ch)) => ch,
        Ok(Err(e)) => {
            debug!(
                "gRPC health probe: connect failed for {}:{}: {}",
                host, port, e
            );
            return false;
        }
        Err(_) => {
            debug!("gRPC health probe: connect timed out for {}:{}", host, port);
            return false;
        }
    };

    let mut client = grpc_health_v1::health_client::HealthClient::new(channel);
    let request = tonic::Request::new(grpc_health_v1::HealthCheckRequest {
        service: service_name.to_string(),
    });

    match tokio::time::timeout(timeout, client.check(request)).await {
        Ok(Ok(response)) => {
            let status = response.into_inner().status;
            status == grpc_health_v1::health_check_response::ServingStatus::Serving as i32
        }
        Ok(Err(e)) => {
            debug!("gRPC health probe: RPC failed for {}:{}: {}", host, port, e);
            false
        }
        Err(_) => {
            debug!("gRPC health probe: RPC timed out for {}:{}", host, port);
            false
        }
    }
}

fn build_health_check_client(pool_config: &PoolConfig, dns_cache: DnsCache) -> reqwest::Client {
    let resolver = DnsCacheResolver::new(dns_cache);
    let mut builder = reqwest::Client::builder()
        .pool_max_idle_per_host(pool_config.max_idle_per_host)
        .pool_idle_timeout(Duration::from_secs(pool_config.idle_timeout_seconds))
        .danger_accept_invalid_certs(true)
        .dns_resolver(Arc::new(resolver));

    if pool_config.enable_http_keep_alive {
        builder = builder.tcp_keepalive(Duration::from_secs(pool_config.tcp_keepalive_seconds));
    }

    if pool_config.enable_http2 {
        builder = builder
            .http2_keep_alive_interval(Duration::from_secs(
                pool_config.http2_keep_alive_interval_seconds,
            ))
            .http2_keep_alive_timeout(Duration::from_secs(
                pool_config.http2_keep_alive_timeout_seconds,
            ));
    }

    match builder.build() {
        Ok(client) => client,
        Err(e) => {
            tracing::error!(
                "Failed to build health check HTTP client: {}. \
                 Falling back to default client (pool/TLS/keepalive settings will not apply).",
                e
            );
            reqwest::Client::new()
        }
    }
}

fn now_epoch_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}

/// Public wrapper around [`grpc_probe`] for use in unit/integration tests.
#[doc(hidden)]
#[allow(dead_code)]
pub async fn grpc_probe_for_test(
    host: &str,
    port: u16,
    timeout: Duration,
    use_tls: bool,
    service_name: &str,
) -> bool {
    grpc_probe(host, port, timeout, use_tls, service_name).await
}
