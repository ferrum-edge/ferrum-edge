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
use crate::config::types::{ActiveHealthCheck, GatewayConfig, PassiveHealthCheck, UpstreamTarget};
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
            if failures_in_window >= config.unhealthy_threshold
                && !self.unhealthy_targets.contains_key(&key)
            {
                warn!(
                    "Passive health check: marking target {} as unhealthy ({} failures in {}s window)",
                    key, failures_in_window, config.unhealthy_window_seconds
                );
                self.unhealthy_targets.insert(key, now_epoch_ms());
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
                    if let Some(entry) = unhealthy_targets.get(key) {
                        let marked_at = *entry.value();
                        if now.saturating_sub(marked_at) >= recovery_ms {
                            info!(
                                "Passive recovery timer: restoring target {} after {}s cooldown",
                                key, healthy_after_seconds
                            );
                            drop(entry); // Release DashMap ref before removing
                            unhealthy_targets.remove(key);

                            // Reset failure counters so the target gets a clean slate
                            if let Some(state) = target_states.get(key) {
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
        let scheme = if config.use_tls { "https" } else { "http" };
        let url = format!(
            "{}://{}:{}{}",
            scheme, target.host, target.port, config.http_path
        );
        let interval = Duration::from_secs(config.interval_seconds);
        let timeout = Duration::from_millis(config.timeout_ms);
        let healthy_threshold = config.healthy_threshold;
        let unhealthy_threshold = config.unhealthy_threshold;
        let healthy_status_codes = config.healthy_status_codes.clone();
        let unhealthy_targets = self.unhealthy_targets.clone();
        let target_states = self.target_states.clone();
        let client = self.http_client.clone();

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

                // Apply per-probe timeout at request level; the shared client
                // handles pooling, keep-alive, and connection reuse.
                let result = client.get(&url).timeout(timeout).send().await;

                match result {
                    Ok(resp) => {
                        let status = resp.status().as_u16();
                        if healthy_status_codes.contains(&status) {
                            state.consecutive_failures.store(0, Ordering::Relaxed);
                            let successes =
                                state.consecutive_successes.fetch_add(1, Ordering::Relaxed) + 1;

                            if unhealthy_targets.contains_key(&key)
                                && successes >= healthy_threshold
                            {
                                info!(
                                    "Active health check: target {} is healthy (status {})",
                                    key, status
                                );
                                unhealthy_targets.remove(&key);
                            }
                        } else {
                            state.consecutive_successes.store(0, Ordering::Relaxed);
                            let failures =
                                state.consecutive_failures.fetch_add(1, Ordering::Relaxed) + 1;

                            if !unhealthy_targets.contains_key(&key)
                                && failures >= unhealthy_threshold
                            {
                                warn!(
                                    "Active health check: target {} is unhealthy (status {})",
                                    key, status
                                );
                                unhealthy_targets.insert(key.clone(), now_epoch_ms());
                            }
                        }
                    }
                    Err(e) => {
                        state.consecutive_successes.store(0, Ordering::Relaxed);
                        let failures =
                            state.consecutive_failures.fetch_add(1, Ordering::Relaxed) + 1;

                        debug!("Active health check failed for {}: {}", key, e);

                        if !unhealthy_targets.contains_key(&key) && failures >= unhealthy_threshold
                        {
                            warn!(
                                "Active health check: target {} is unhealthy (connection error)",
                                key
                            );
                            unhealthy_targets.insert(key.clone(), now_epoch_ms());
                        }
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::types::PassiveHealthCheck;

    fn make_target(host: &str, port: u16) -> UpstreamTarget {
        UpstreamTarget {
            host: host.to_string(),
            port,
            weight: 1,
            tags: std::collections::HashMap::new(),
        }
    }

    #[test]
    fn test_passive_health_marks_unhealthy() {
        let checker = HealthChecker::new();
        let target = make_target("backend1", 8080);
        let config = PassiveHealthCheck {
            unhealthy_status_codes: vec![500, 502, 503],
            unhealthy_threshold: 3,
            unhealthy_window_seconds: 60,
            healthy_after_seconds: 30,
        };

        // Report 3 failures
        for _ in 0..3 {
            checker.report_response(&target, 500, false, Some(&config));
        }

        assert!(checker.unhealthy_targets.contains_key("backend1:8080"));
    }

    #[test]
    fn test_passive_health_recovers() {
        let checker = HealthChecker::new();
        let target = make_target("backend1", 8080);
        let config = PassiveHealthCheck {
            unhealthy_status_codes: vec![500],
            unhealthy_threshold: 2,
            unhealthy_window_seconds: 60,
            healthy_after_seconds: 30,
        };

        // Mark unhealthy
        for _ in 0..2 {
            checker.report_response(&target, 500, false, Some(&config));
        }
        assert!(checker.unhealthy_targets.contains_key("backend1:8080"));

        // Recovery
        checker.report_response(&target, 200, false, Some(&config));
        assert!(!checker.unhealthy_targets.contains_key("backend1:8080"));
    }

    #[test]
    fn test_success_does_not_mark_unhealthy() {
        let checker = HealthChecker::new();
        let target = make_target("backend1", 8080);
        let config = PassiveHealthCheck {
            unhealthy_status_codes: vec![500],
            unhealthy_threshold: 3,
            unhealthy_window_seconds: 60,
            healthy_after_seconds: 30,
        };

        for _ in 0..100 {
            checker.report_response(&target, 200, false, Some(&config));
        }

        assert!(!checker.unhealthy_targets.contains_key("backend1:8080"));
    }

    #[test]
    fn test_connection_error_counts_as_failure_regardless_of_status_codes() {
        let checker = HealthChecker::new();
        let target = make_target("backend1", 8080);
        // Only 500 is in the unhealthy list — 502 is NOT
        let config = PassiveHealthCheck {
            unhealthy_status_codes: vec![500],
            unhealthy_threshold: 2,
            unhealthy_window_seconds: 60,
            healthy_after_seconds: 30,
        };

        // Report connection errors with status 502 (synthetic from proxy).
        // Even though 502 is NOT in unhealthy_status_codes, connection_error=true
        // should still count as a failure.
        for _ in 0..2 {
            checker.report_response(&target, 502, true, Some(&config));
        }

        assert!(
            checker.unhealthy_targets.contains_key("backend1:8080"),
            "Connection errors should mark target unhealthy even if status code is not in unhealthy list"
        );
    }

    #[test]
    fn test_connection_error_recovery_on_success() {
        let checker = HealthChecker::new();
        let target = make_target("backend1", 8080);
        let config = PassiveHealthCheck {
            unhealthy_status_codes: vec![500],
            unhealthy_threshold: 2,
            unhealthy_window_seconds: 60,
            healthy_after_seconds: 30,
        };

        // Mark unhealthy via connection errors
        for _ in 0..2 {
            checker.report_response(&target, 502, true, Some(&config));
        }
        assert!(checker.unhealthy_targets.contains_key("backend1:8080"));

        // A successful response should recover it
        checker.report_response(&target, 200, false, Some(&config));
        assert!(!checker.unhealthy_targets.contains_key("backend1:8080"));
    }
}
