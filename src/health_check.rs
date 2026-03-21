//! Health checking for upstream targets.
//!
//! Supports active health checks (periodic HTTP probes) and passive health
//! checks (monitoring response status codes from proxied requests).

use crate::config::types::{ActiveHealthCheck, GatewayConfig, PassiveHealthCheck, UpstreamTarget};
use dashmap::DashMap;
use std::sync::atomic::{AtomicU32, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tracing::{debug, info, warn};

fn target_key(target: &UpstreamTarget) -> String {
    format!("{}:{}", target.host, target.port)
}

/// Health state for a single target.
struct TargetHealth {
    consecutive_successes: AtomicU32,
    consecutive_failures: AtomicU32,
    /// Recent failure timestamps (epoch ms) for passive windowed counting.
    /// Key is a monotonic counter, value is the timestamp.
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
    /// Set of unhealthy target keys ("host:port").
    pub unhealthy_targets: Arc<DashMap<String, ()>>,
    /// Per-target health state.
    target_states: Arc<DashMap<String, Arc<TargetHealth>>>,
    /// Active check abort handles.
    active_check_handles: Vec<tokio::task::JoinHandle<()>>,
}

impl Default for HealthChecker {
    fn default() -> Self {
        Self::new()
    }
}

impl HealthChecker {
    pub fn new() -> Self {
        Self {
            unhealthy_targets: Arc::new(DashMap::new()),
            target_states: Arc::new(DashMap::new()),
            active_check_handles: Vec::new(),
        }
    }

    /// Start health checks for all upstreams in the config.
    pub fn start(&mut self, config: &GatewayConfig) {
        // Cancel any existing active check tasks
        for handle in self.active_check_handles.drain(..) {
            handle.abort();
        }

        for upstream in &config.upstreams {
            if let Some(hc_config) = &upstream.health_checks {
                // Start active health checks
                if let Some(active) = &hc_config.active {
                    for target in &upstream.targets {
                        let handle = self.start_active_check(target, active);
                        self.active_check_handles.push(handle);
                    }
                }
            }
        }
    }

    /// Report a response from a proxied request (passive health checking).
    pub fn report_response(
        &self,
        target: &UpstreamTarget,
        status_code: u16,
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

        if config.unhealthy_status_codes.contains(&status_code) {
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

            let failures_in_window = state.recent_failures.len() as u32;
            if failures_in_window >= config.unhealthy_threshold
                && !self.unhealthy_targets.contains_key(&key)
            {
                warn!(
                    "Passive health check: marking target {} as unhealthy ({} failures in {}s window)",
                    key, failures_in_window, config.unhealthy_window_seconds
                );
                self.unhealthy_targets.insert(key, ());
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

    /// Start an active health check background task for a target.
    fn start_active_check(
        &self,
        target: &UpstreamTarget,
        config: &ActiveHealthCheck,
    ) -> tokio::task::JoinHandle<()> {
        let key = target_key(target);
        let url = format!("http://{}:{}{}", target.host, target.port, config.http_path);
        let interval = Duration::from_secs(config.interval_seconds);
        let timeout = Duration::from_millis(config.timeout_ms);
        let healthy_threshold = config.healthy_threshold;
        let unhealthy_threshold = config.unhealthy_threshold;
        let healthy_status_codes = config.healthy_status_codes.clone();
        let unhealthy_targets = self.unhealthy_targets.clone();
        let target_states = self.target_states.clone();

        tokio::spawn(async move {
            let client = reqwest::Client::builder()
                .timeout(timeout)
                .danger_accept_invalid_certs(true)
                .build()
                .unwrap_or_else(|_| reqwest::Client::new());

            let mut timer = tokio::time::interval(interval);

            loop {
                timer.tick().await;

                let state = target_states
                    .entry(key.clone())
                    .or_insert_with(|| Arc::new(TargetHealth::new()))
                    .clone();

                let result = client.get(&url).send().await;

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
                                unhealthy_targets.insert(key.clone(), ());
                            }
                        }
                    }
                    Err(e) => {
                        state.consecutive_successes.store(0, Ordering::Relaxed);
                        let failures =
                            state.consecutive_failures.fetch_add(1, Ordering::Relaxed) + 1;

                        debug!("Active health check failed for {}: {}", key, e);

                        if !unhealthy_targets.contains_key(&key)
                            && failures >= unhealthy_threshold
                        {
                            warn!(
                                "Active health check: target {} is unhealthy (connection error)",
                                key
                            );
                            unhealthy_targets.insert(key.clone(), ());
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
        };

        // Report 3 failures
        for _ in 0..3 {
            checker.report_response(&target, 500, Some(&config));
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
        };

        // Mark unhealthy
        for _ in 0..2 {
            checker.report_response(&target, 500, Some(&config));
        }
        assert!(checker.unhealthy_targets.contains_key("backend1:8080"));

        // Recovery
        checker.report_response(&target, 200, Some(&config));
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
        };

        for _ in 0..100 {
            checker.report_response(&target, 200, Some(&config));
        }

        assert!(!checker.unhealthy_targets.contains_key("backend1:8080"));
    }
}
