//! Health checking for upstream targets.
//!
//! Supports active health checks (periodic HTTP probes) and passive health
//! checks (monitoring response status codes from proxied requests).
//!
//! Active health checks share a single `reqwest::Client` configured with the
//! gateway's global connection pool settings (keep-alive, idle timeout, HTTP/2,
//! TCP keep-alive) so that probe connections behave like real proxy traffic and
//! benefit from connection reuse across targets.

use crate::config::pool_config::PoolConfig;
use crate::config::types::{
    ActiveHealthCheck, GatewayConfig, HealthProbeType, PassiveHealthCheck, UpstreamTarget,
};
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

fn target_key(target: &UpstreamTarget) -> String {
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

/// Manages health state for all upstream targets.
pub struct HealthChecker {
    /// Set of unhealthy target keys ("host:port") → epoch_ms when marked unhealthy.
    pub unhealthy_targets: Arc<DashMap<String, u64>>,
    /// Per-target health state.
    target_states: Arc<DashMap<String, Arc<TargetHealth>>>,
    /// Shared HTTP client for active health check probes, configured with
    /// the gateway's connection pool settings for proper keep-alive and reuse.
    http_client: Arc<reqwest::Client>,
    /// Active check abort handles.
    active_check_handles: Vec<tokio::task::JoinHandle<()>>,
}

impl Default for HealthChecker {
    fn default() -> Self {
        Self::with_pool_config(&PoolConfig::default())
    }
}

impl HealthChecker {
    /// Create a health checker using default pool settings.
    ///
    /// Prefer [`with_pool_config`] in production to inherit the gateway's
    /// tuned connection pool settings. Kept for tests and integration code
    /// that constructs `HealthChecker` without a full `PoolConfig`.
    #[allow(dead_code)]
    pub fn new() -> Self {
        Self::default()
    }

    /// Create a health checker with an HTTP client configured from the
    /// gateway's global pool settings.
    ///
    /// The shared client inherits keep-alive, idle timeout, HTTP/2, and
    /// TCP keep-alive settings so that health probe connections behave
    /// like real proxy traffic and benefit from connection reuse.
    pub fn with_pool_config(pool_config: &PoolConfig) -> Self {
        let client = build_health_check_client(pool_config);
        Self {
            unhealthy_targets: Arc::new(DashMap::new()),
            target_states: Arc::new(DashMap::new()),
            http_client: Arc::new(client),
            active_check_handles: Vec::new(),
        }
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
                        let handle = self.start_active_check(target, active, shutdown_rx.clone());
                        self.active_check_handles.push(handle);
                    }
                }

                // Start passive recovery timer if passive health checks are
                // configured with a non-zero healthy_after_seconds. This
                // automatically restores unhealthy targets after a cooldown
                // period, preventing the "all targets unhealthy forever"
                // death spiral when only passive checks are configured.
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

    /// Report a response from a proxied request (passive health checking).
    ///
    /// `connection_error` should be `true` when the failure was a TCP
    /// connection error, read timeout, or similar transport-level failure
    /// (as opposed to a valid HTTP response from the backend). Connection
    /// errors always count as failures regardless of `unhealthy_status_codes`.
    pub fn report_response(
        &self,
        target: &UpstreamTarget,
        status_code: u16,
        connection_error: bool,
        passive_config: Option<&PassiveHealthCheck>,
    ) {
        let config = match passive_config {
            Some(c) => c,
            None => return,
        };

        let key = target_key(target);
        let state = self
            .target_states
            .entry(key.clone())
            .or_insert_with(|| Arc::new(TargetHealth::new()))
            .clone();

        // Connection errors (TCP refused, timeout, DNS failure) always count
        // as failures — they indicate the target is unreachable, regardless
        // of what status codes are in the unhealthy list.
        if connection_error || config.unhealthy_status_codes.contains(&status_code) {
            state.consecutive_successes.store(0, Ordering::Relaxed);
            state.consecutive_failures.fetch_add(1, Ordering::Relaxed);

            // Record failure timestamp for windowed counting
            let now_ms = now_epoch_ms();
            let counter = state.failure_counter.fetch_add(1, Ordering::Relaxed);
            state.recent_failures.insert(counter, now_ms);

            // Clean old failures outside the window
            let window_start = now_ms.saturating_sub(config.unhealthy_window_seconds * 1000);
            state
                .recent_failures
                .retain(|_, &mut ts| ts >= window_start);

            // Hard cap: if failure rate exceeds cleanup rate (cascading failure),
            // evict oldest entries to prevent unbounded memory growth.
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
            if failures_in_window >= config.unhealthy_threshold {
                // Use entry API for atomic check-and-insert to avoid TOCTOU race
                // where two threads both see "not unhealthy" and both insert/log.
                let key_ref = key.clone();
                self.unhealthy_targets
                    .entry(key)
                    .or_insert_with(|| {
                        warn!(
                            "Passive health check: marking target {} as unhealthy ({} failures in {}s window)",
                            key_ref, failures_in_window, config.unhealthy_window_seconds
                        );
                        now_epoch_ms()
                    });
            }
        } else {
            let failures = state.consecutive_failures.load(Ordering::Relaxed);
            state.consecutive_successes.fetch_add(1, Ordering::Relaxed);
            if failures > 0 {
                state.consecutive_failures.store(0, Ordering::Relaxed);
            }

            // If target was unhealthy and now succeeding, mark healthy
            if self.unhealthy_targets.contains_key(&key) {
                let successes = state.consecutive_successes.load(Ordering::Relaxed);
                // Require 1 success to recover from passive failure
                if successes >= 1 {
                    info!(
                        "Passive health check: marking target {} as healthy again",
                        key
                    );
                    self.unhealthy_targets.remove(&key);
                    state.recent_failures.clear();
                }
            }
        }
    }

    /// Start a background timer that automatically restores passively-marked
    /// unhealthy targets after `healthy_after_seconds`.
    ///
    /// This prevents the "all targets unhealthy forever" death spiral when
    /// only passive health checks are configured. Once the cooldown period
    /// elapses, the target is restored to the rotation (like a circuit
    /// breaker half-open state). If it immediately fails again, passive
    /// health checks will re-mark it unhealthy.
    fn start_passive_recovery_timer(
        &self,
        targets: &[UpstreamTarget],
        healthy_after_seconds: u64,
        shutdown_rx: Option<tokio::sync::watch::Receiver<bool>>,
    ) -> tokio::task::JoinHandle<()> {
        let unhealthy_targets = self.unhealthy_targets.clone();
        let target_states = self.target_states.clone();
        let target_keys: Vec<String> = targets.iter().map(target_key).collect();
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

                for key in &target_keys {
                    // Use remove_if for atomic check-and-remove to avoid TOCTOU race
                    // where the key could be re-added between our get() and remove().
                    let removed = unhealthy_targets
                        .remove_if(key, |_, marked_at| {
                            now.saturating_sub(*marked_at) >= recovery_ms
                        })
                        .is_some();

                    if removed {
                        info!(
                            "Passive recovery timer: restoring target {} after {}s cooldown",
                            key, healthy_after_seconds
                        );
                        // Reset failure counters so the target gets a clean slate
                        if let Some(state) = target_states.get(key) {
                            state.consecutive_failures.store(0, Ordering::Relaxed);
                            state.consecutive_successes.store(0, Ordering::Relaxed);
                            state.recent_failures.clear();
                        }
                    }
                }
            }
        })
    }

    /// Start an active health check background task for a target.
    ///
    /// Uses the shared `http_client` (configured with the gateway's pool
    /// settings) instead of creating a per-target client. The per-probe
    /// timeout from `ActiveHealthCheck::timeout_ms` is applied at the
    /// request level so each probe respects its configured timeout while
    /// the underlying connections benefit from pooling and keep-alive.
    fn start_active_check(
        &self,
        target: &UpstreamTarget,
        config: &ActiveHealthCheck,
        shutdown_rx: Option<tokio::sync::watch::Receiver<bool>>,
    ) -> tokio::task::JoinHandle<()> {
        let key = target_key(target);
        let interval = Duration::from_secs(config.interval_seconds);
        let timeout = Duration::from_millis(config.timeout_ms);
        let healthy_threshold = config.healthy_threshold;
        let unhealthy_threshold = config.unhealthy_threshold;
        let unhealthy_targets = self.unhealthy_targets.clone();
        let target_states = self.target_states.clone();

        // Build probe-specific state
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

                let probe_success = match probe_type {
                    HealthProbeType::Http => {
                        http_probe(&client, &url, timeout, &healthy_status_codes).await
                    }
                    HealthProbeType::Tcp => tcp_probe(&host, port, timeout).await,
                    HealthProbeType::Udp => udp_probe(&host, port, timeout, &udp_payload).await,
                };

                if probe_success {
                    state.consecutive_failures.store(0, Ordering::Relaxed);
                    let successes = state.consecutive_successes.fetch_add(1, Ordering::Relaxed) + 1;

                    if successes >= healthy_threshold && unhealthy_targets.remove(&key).is_some() {
                        info!(
                            "Active health check: target {} is healthy ({:?} probe)",
                            key, probe_type
                        );
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
                // Default: any 2xx is healthy
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
/// Success means the target accepted the connection (SYN-ACK).
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
/// A response (any data) means the target is alive. Timeout means unhealthy.
async fn udp_probe(host: &str, port: u16, timeout: Duration, payload: &[u8]) -> bool {
    let addr = format!("{}:{}", host, port);
    let socket = match tokio::net::UdpSocket::bind("0.0.0.0:0").await {
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

    // Send probe payload (or a single zero byte if no payload configured)
    let data = if payload.is_empty() { &[0u8] } else { payload };
    if let Err(e) = socket.send(data).await {
        debug!("UDP health probe: failed to send to {}: {}", addr, e);
        return false;
    }

    // Wait for any response
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

/// Build a shared `reqwest::Client` for active health check probes using the
/// gateway's global pool configuration.
///
/// The client inherits:
/// - `pool_max_idle_per_host` — connection reuse across periodic probes
/// - `pool_idle_timeout` — stale probe connections cleaned up automatically
/// - TCP keep-alive — detects dead connections between probe intervals
/// - HTTP/2 keep-alive — multiplexed probe streams stay healthy
///
/// TLS verification is relaxed for health probes since backends may use
/// self-signed certs in internal environments. The per-probe timeout is
/// applied at the request level in `start_active_check`, not here.
fn build_health_check_client(pool_config: &PoolConfig) -> reqwest::Client {
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

    builder.build().unwrap_or_else(|e| {
        tracing::error!(
            "Failed to build health check HTTP client: {}, using default",
            e
        );
        reqwest::Client::new()
    })
}

fn now_epoch_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}
