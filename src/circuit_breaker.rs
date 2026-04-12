//! Circuit breaker for preventing cascading failures.
//!
//! Implements a three-state circuit breaker pattern:
//! - **Closed**: Normal operation, requests pass through.
//! - **Open**: After repeated failures, requests are rejected with 503.
//! - **Half-Open**: After a timeout, a limited number of probe requests are allowed.

use crate::config::types::CircuitBreakerConfig;
use dashmap::DashMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicU8, AtomicU32, AtomicU64, Ordering};
use tracing::{info, warn};

const STATE_CLOSED: u8 = 0;
const STATE_OPEN: u8 = 1;
const STATE_HALF_OPEN: u8 = 2;

/// Circuit breaker state for a single proxy or target.
pub struct CircuitBreaker {
    state: AtomicU8,
    failure_count: AtomicU32,
    success_count: AtomicU32,
    last_failure_epoch_ms: AtomicU64,
    half_open_in_flight: AtomicU32,
    config: CircuitBreakerConfig,
}

/// Error returned when the circuit is open.
#[derive(Debug)]
pub struct CircuitOpenError;

impl std::fmt::Display for CircuitOpenError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Circuit breaker is open")
    }
}

impl CircuitBreaker {
    pub fn new(config: CircuitBreakerConfig) -> Self {
        Self {
            state: AtomicU8::new(STATE_CLOSED),
            failure_count: AtomicU32::new(0),
            success_count: AtomicU32::new(0),
            last_failure_epoch_ms: AtomicU64::new(0),
            half_open_in_flight: AtomicU32::new(0),
            config,
        }
    }

    /// Check if a request can proceed. Returns Err if circuit is open.
    pub fn can_execute(&self) -> Result<(), CircuitOpenError> {
        // Acquire pairs with the Release in record_failure() when transitioning
        // CLOSED → OPEN, ensuring visibility of last_failure_epoch_ms and
        // failure_count. Using Relaxed here would risk stale reads on ARM/weak-
        // memory architectures, allowing requests to leak through after the
        // circuit opens. The ~5-15ns cost of Acquire is acceptable given that
        // circuit breaker checks are not the bottleneck at scale.
        let state = self.state.load(Ordering::Acquire);
        match state {
            STATE_CLOSED => Ok(()),
            STATE_OPEN => {
                // Check if timeout has elapsed
                let now = now_epoch_ms();
                let last_failure = self.last_failure_epoch_ms.load(Ordering::Relaxed);
                let timeout_ms = self.config.timeout_seconds.saturating_mul(1000);

                if now.saturating_sub(last_failure) >= timeout_ms {
                    // Attempt transition to half-open (only one thread wins the CAS)
                    match self.state.compare_exchange(
                        STATE_OPEN,
                        STATE_HALF_OPEN,
                        Ordering::AcqRel,
                        Ordering::Acquire,
                    ) {
                        Ok(_) => {
                            // CAS winner: initialize half-open state
                            self.half_open_in_flight.store(1, Ordering::Relaxed);
                            self.success_count.store(0, Ordering::Relaxed);
                            info!("Circuit breaker transitioning from Open to Half-Open");
                            Ok(())
                        }
                        Err(current) => {
                            // CAS loser: another thread already transitioned.
                            // Fall through to handle the current state.
                            if current == STATE_HALF_OPEN {
                                // Use CAS loop to atomically claim a slot
                                loop {
                                    let in_flight =
                                        self.half_open_in_flight.load(Ordering::Acquire);
                                    if in_flight >= self.config.half_open_max_requests {
                                        return Err(CircuitOpenError);
                                    }
                                    match self.half_open_in_flight.compare_exchange_weak(
                                        in_flight,
                                        in_flight + 1,
                                        Ordering::AcqRel,
                                        Ordering::Acquire,
                                    ) {
                                        Ok(_) => return Ok(()),
                                        Err(_) => continue,
                                    }
                                }
                            } else {
                                // State changed to something else (e.g. Closed)
                                Ok(())
                            }
                        }
                    }
                } else {
                    Err(CircuitOpenError)
                }
            }
            STATE_HALF_OPEN => {
                // Use CAS loop to atomically claim a slot without exceeding the limit.
                loop {
                    let current = self.half_open_in_flight.load(Ordering::Acquire);
                    if current >= self.config.half_open_max_requests {
                        return Err(CircuitOpenError);
                    }
                    match self.half_open_in_flight.compare_exchange_weak(
                        current,
                        current + 1,
                        Ordering::AcqRel,
                        Ordering::Acquire,
                    ) {
                        Ok(_) => return Ok(()),
                        Err(_) => continue,
                    }
                }
            }
            _ => Ok(()),
        }
    }

    /// Record a successful response, transitioning from half-open to closed
    /// after enough successes reach the configured threshold.
    #[allow(dead_code)] // Public API — called by retry/proxy logic when circuit is half-open
    pub fn record_success(&self) {
        let state = self.state.load(Ordering::Acquire);
        match state {
            STATE_HALF_OPEN => {
                // Decrement in-flight counter so new probe requests can be admitted
                let _ = self.half_open_in_flight.fetch_update(
                    Ordering::SeqCst,
                    Ordering::SeqCst,
                    |v| v.checked_sub(1),
                );
                // Re-check state: another thread may have reopened the circuit
                // between our initial load and now.
                if self.state.load(Ordering::Acquire) != STATE_HALF_OPEN {
                    return;
                }
                let successes = self.success_count.fetch_add(1, Ordering::Relaxed) + 1;
                if successes >= self.config.success_threshold {
                    // Use CAS to transition: only one thread should close the circuit
                    if self
                        .state
                        .compare_exchange(
                            STATE_HALF_OPEN,
                            STATE_CLOSED,
                            Ordering::SeqCst,
                            Ordering::Relaxed,
                        )
                        .is_ok()
                    {
                        info!("Circuit breaker closing (recovered)");
                        self.failure_count.store(0, Ordering::Relaxed);
                        self.success_count.store(0, Ordering::Relaxed);
                        self.half_open_in_flight.store(0, Ordering::Relaxed);
                    }
                }
            }
            STATE_CLOSED => {
                // Reset failure count on success
                if self.failure_count.load(Ordering::Relaxed) > 0 {
                    self.failure_count.store(0, Ordering::Relaxed);
                }
            }
            _ => {}
        }
    }

    /// Record a failed response.
    ///
    /// `connection_error` indicates whether this was a connection-level failure
    /// (TCP refused, DNS, TLS handshake, connect timeout) rather than an actual
    /// HTTP response from the backend. When `true`, the failure is controlled by
    /// `trip_on_connection_errors` independently of `failure_status_codes`.
    pub fn record_failure(&self, status_code: u16, connection_error: bool) {
        if connection_error {
            if !self.config.trip_on_connection_errors {
                return;
            }
        } else if !self.config.failure_status_codes.contains(&status_code) {
            // Non-failure status codes are neutral — don't treat as success or failure
            return;
        }

        let state = self.state.load(Ordering::Acquire);
        self.last_failure_epoch_ms
            .store(now_epoch_ms(), Ordering::Relaxed);

        match state {
            STATE_CLOSED => {
                let failures = self.failure_count.fetch_add(1, Ordering::Relaxed) + 1;
                if failures >= self.config.failure_threshold {
                    warn!("Circuit breaker opening after {} failures", failures);
                    self.state.store(STATE_OPEN, Ordering::Release);
                }
            }
            STATE_HALF_OPEN => {
                // Decrement in-flight before reopening
                let _ = self.half_open_in_flight.fetch_update(
                    Ordering::SeqCst,
                    Ordering::SeqCst,
                    |v| v.checked_sub(1),
                );
                warn!("Circuit breaker reopening (probe failed)");
                self.state.store(STATE_OPEN, Ordering::SeqCst);
                self.success_count.store(0, Ordering::Relaxed);
                self.half_open_in_flight.store(0, Ordering::Relaxed);
            }
            _ => {}
        }
    }

    /// Get the config for this circuit breaker.
    pub fn config(&self) -> &CircuitBreakerConfig {
        &self.config
    }

    /// Current failure count (for metrics).
    pub fn failure_count(&self) -> u32 {
        self.failure_count.load(Ordering::Relaxed)
    }

    /// Current success count (for metrics).
    pub fn success_count(&self) -> u32 {
        self.success_count.load(Ordering::Relaxed)
    }

    /// Current state name (for metrics/logging).
    pub fn state_name(&self) -> &'static str {
        match self.state.load(Ordering::Relaxed) {
            STATE_CLOSED => "closed",
            STATE_OPEN => "open",
            STATE_HALF_OPEN => "half_open",
            _ => "unknown",
        }
    }
}

/// Build the cache key for a circuit breaker.
///
/// When an upstream target is provided, the breaker is scoped to that specific
/// target (`proxy_id::host:port`) so each target tracks failures independently.
/// Without a target, the key is just the proxy ID (direct backend proxies).
fn circuit_breaker_key(proxy_id: &str, target_key: Option<&str>) -> String {
    match target_key {
        Some(tk) => format!("{proxy_id}::{tk}"),
        None => proxy_id.to_string(),
    }
}

/// Build a target key string from host and port (e.g. `"10.0.0.1:8080"`).
pub fn target_key(host: &str, port: u16) -> String {
    format!("{host}:{port}")
}

/// Cache of circuit breakers, keyed per-proxy for direct backends or
/// per-target (`proxy_id::host:port`) for upstream load-balanced targets.
pub struct CircuitBreakerCache {
    breakers: DashMap<String, Arc<CircuitBreaker>>,
    max_entries: usize,
}

impl Default for CircuitBreakerCache {
    fn default() -> Self {
        Self::with_max_entries(10_000)
    }
}

impl CircuitBreakerCache {
    #[allow(dead_code)]
    pub fn new() -> Self {
        Self::with_max_entries(10_000)
    }

    pub fn with_max_entries(max_entries: usize) -> Self {
        Self {
            breakers: DashMap::new(),
            max_entries,
        }
    }

    /// Get or create a circuit breaker for a proxy (or proxy+target).
    ///
    /// `target_key` should be `Some("host:port")` when the proxy uses an upstream,
    /// or `None` for direct backend proxies.
    /// If the config has changed, replaces the breaker with a fresh one.
    pub fn get_or_create(
        &self,
        proxy_id: &str,
        target_key: Option<&str>,
        config: &CircuitBreakerConfig,
    ) -> Arc<CircuitBreaker> {
        let key = circuit_breaker_key(proxy_id, target_key);
        if let Some(existing) = self.breakers.get(&key)
            && existing.config() == config
        {
            return existing.clone();
        }
        // Enforce max entries: if at capacity and this is a genuinely new key,
        // skip creating a breaker. Existing keys are always replaced (config change).
        if self.breakers.len() >= self.max_entries && !self.breakers.contains_key(&key) {
            warn!(
                "Circuit breaker cache at capacity ({}), skipping new entry for {}",
                self.max_entries, key
            );
            // Return a transient breaker that won't be cached
            return Arc::new(CircuitBreaker::new(config.clone()));
        }
        let cb = Arc::new(CircuitBreaker::new(config.clone()));
        self.breakers.insert(key, cb.clone());
        cb
    }

    /// Check if a request can proceed for a given proxy (or proxy+target).
    ///
    /// `target_key` should be `Some("host:port")` when the proxy uses an upstream,
    /// or `None` for direct backend proxies.
    pub fn can_execute(
        &self,
        proxy_id: &str,
        target_key: Option<&str>,
        config: &CircuitBreakerConfig,
    ) -> Result<Arc<CircuitBreaker>, CircuitOpenError> {
        let cb = self.get_or_create(proxy_id, target_key, config);
        cb.can_execute()?;
        Ok(cb)
    }

    /// Snapshot of all circuit breaker states for metrics.
    pub fn snapshot(&self) -> Vec<(String, &'static str, u32, u32)> {
        self.breakers
            .iter()
            .map(|entry| {
                let cb = entry.value();
                (
                    entry.key().clone(),
                    cb.state_name(),
                    cb.failure_count(),
                    cb.success_count(),
                )
            })
            .collect()
    }

    /// Remove circuit breakers for proxies that no longer exist in config.
    /// Removes both direct-backend keys (`proxy_id`) and per-target keys
    /// (`proxy_id::host:port`) for each removed proxy.
    pub fn prune(&self, removed_proxy_ids: &[String]) {
        self.breakers.retain(|key, _| {
            !removed_proxy_ids.iter().any(|id| {
                // Match exact proxy_id key or proxy_id:: prefix for target-scoped keys
                key == id || key.starts_with(&format!("{id}::"))
            })
        });
    }

    /// Remove circuit breakers for upstream targets that no longer exist.
    /// This prevents unbounded growth from target churn (e.g., Kubernetes
    /// pod cycling where old pod IPs accumulate as stale breaker entries).
    pub fn prune_stale_targets(&self, active_target_keys: &std::collections::HashSet<String>) {
        self.breakers.retain(|key, _| {
            // Direct-backend keys (no "::") are managed by prune() via proxy removal
            if !key.contains("::") {
                return true;
            }
            active_target_keys.contains(key)
        });
    }

    /// Current number of entries in the cache.
    #[allow(dead_code)]
    pub fn len(&self) -> usize {
        self.breakers.len()
    }

    /// Whether the cache is empty.
    #[allow(dead_code)]
    pub fn is_empty(&self) -> bool {
        self.breakers.is_empty()
    }
}

fn now_epoch_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}
