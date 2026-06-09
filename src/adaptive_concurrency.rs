//! Adaptive backend concurrency limiter.
//!
//! The limiter answers one question on the backend dispatch path: is the
//! selected destination currently healthy enough to accept one more in-flight
//! request? It is intentionally plugin-owned so proxy, proxy-group, and global
//! plugin scopes control how state is shared.

use std::hash::{Hash, Hasher};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::time::Duration;

use crossbeam_utils::CachePadded;
use dashmap::DashMap;
use dashmap::mapref::entry::Entry;

use crate::config::types::{Proxy, UpstreamTarget};
use crate::plugins::{BackendAdmissionOutcome, BackendAdmissionPermit};
use crate::retry::ErrorClass;

const EWMA_PREVIOUS_WEIGHT: u64 = 8;
const EWMA_SAMPLE_WEIGHT: u64 = 2;
const EWMA_WEIGHT_SUM: u64 = EWMA_PREVIOUS_WEIGHT + EWMA_SAMPLE_WEIGHT;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AdaptiveConcurrencyKeyBy {
    /// Separate limit per proxy and selected backend endpoint.
    Proxy,
    /// Separate limit per upstream and selected backend endpoint; direct
    /// backends fall back to proxy-target scoping.
    Upstream,
    /// Shared limit per backend endpoint across every proxy using this plugin
    /// instance.
    Backend,
}

#[derive(Clone, Debug)]
pub struct AdaptiveConcurrencyConfig {
    pub key_by: AdaptiveConcurrencyKeyBy,
    pub max_tracked_keys: usize,
    pub min_limit: u64,
    pub initial_limit: u64,
    pub max_limit: u64,
    pub min_samples: u64,
    pub target_latency_multiplier: f64,
    pub decrease_ratio: f64,
    pub increase_step: u64,
    pub shadow_mode: bool,
    pub expose_headers: bool,
}

#[derive(Clone, Debug, Eq)]
pub struct AdaptiveConcurrencyKey {
    // `Arc<str>` (not `String`): the scope is request-independent and resolved
    // through a per-proxy cache, so building a key on the hot path is a refcount
    // bump rather than a fresh allocation. `Hash`/`PartialEq` below stay
    // content-based (`Arc<str>` hashes/compares the `str`), so distinct `Arc`
    // instances carrying the same scope still collide/compare equal.
    scope: Arc<str>,
    host: String,
    port: u16,
}

impl PartialEq for AdaptiveConcurrencyKey {
    fn eq(&self, other: &Self) -> bool {
        self.scope == other.scope && self.host == other.host && self.port == other.port
    }
}

impl Hash for AdaptiveConcurrencyKey {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.scope.hash(state);
        self.host.hash(state);
        self.port.hash(state);
    }
}

struct AdaptiveConcurrencyState {
    in_flight: CachePadded<AtomicU64>,
    limit: CachePadded<AtomicU64>,
    baseline_latency_us: AtomicU64,
    latency_ewma_us: AtomicU64,
    samples: AtomicU64,
    rejections: AtomicU64,
}

impl AdaptiveConcurrencyState {
    fn new(initial_limit: u64) -> Self {
        Self {
            in_flight: CachePadded::new(AtomicU64::new(0)),
            limit: CachePadded::new(AtomicU64::new(initial_limit)),
            baseline_latency_us: AtomicU64::new(0),
            latency_ewma_us: AtomicU64::new(0),
            samples: AtomicU64::new(0),
            rejections: AtomicU64::new(0),
        }
    }
}

pub struct AdaptiveConcurrencyLimiter {
    inner: DashMap<AdaptiveConcurrencyKey, Arc<AdaptiveConcurrencyState>>,
    /// Per-proxy scope cache for `proxy` scoping, keyed by `proxy.id` (unique and
    /// stable per proxy). Bounded by the number of proxies using this plugin
    /// instance and rebuilt with the plugin on reload, so it needs no eviction.
    /// `upstream` scoping is intentionally not cached here — see `resolve_scope`.
    scope_cache: DashMap<Box<str>, Arc<str>>,
    /// Shared scope for `key_by = backend_target` (a single constant string).
    backend_scope: Arc<str>,
    tracked_keys: AtomicUsize,
}

impl AdaptiveConcurrencyLimiter {
    pub fn new(shards: usize) -> Self {
        Self {
            inner: DashMap::with_shard_amount(shards),
            // `scope_cache.get()` runs on the backend-dispatch hot path for
            // proxy scoping, so honor the operator's configured shard count
            // (pool_shard_amount) like `inner` rather than DashMap's default,
            // keeping per-shard lock contention bounded under load.
            scope_cache: DashMap::with_shard_amount(shards),
            backend_scope: Arc::from("backend"),
            tracked_keys: AtomicUsize::new(0),
        }
    }

    pub fn tracked_keys_count(&self) -> usize {
        self.inner.len()
    }

    pub fn try_acquire(
        &self,
        proxy: &Proxy,
        target: Option<&UpstreamTarget>,
        config: Arc<AdaptiveConcurrencyConfig>,
    ) -> Result<Arc<AdaptiveConcurrencyPermit>, AdaptiveConcurrencyLimitExceeded> {
        let key = build_key(self.resolve_scope(proxy, config.key_by), proxy, target);
        let state = match self.inner.entry(key) {
            Entry::Occupied(entry) => Arc::clone(entry.get()),
            Entry::Vacant(entry) => match self.reserve_key_slot(config.max_tracked_keys) {
                Ok(()) => {
                    let state = Arc::new(AdaptiveConcurrencyState::new(config.initial_limit));
                    entry.insert(Arc::clone(&state));
                    state
                }
                Err(_) => {
                    // Key-cardinality cap reached. Fail OPEN with a per-request,
                    // untracked state rather than rejecting: `max_tracked_keys`
                    // only bounds the limiter's own memory, so a target beyond
                    // the cap must still be admitted (never black-holed by a
                    // blanket 503), and `shadow_mode` must never reject at all.
                    // This state is NOT inserted into the map (memory stays
                    // bounded) and dies with the permit, so overflow targets run
                    // without adaptive limiting until churn frees a tracked slot
                    // or a reload rebuilds the plugin. Starting at `in_flight = 0`
                    // it always admits the request below.
                    drop(entry);
                    Arc::new(AdaptiveConcurrencyState::new(config.initial_limit))
                }
            },
        };

        loop {
            let current = state.in_flight.load(Ordering::Relaxed);
            let limit = state.limit.load(Ordering::Acquire);
            if current >= limit && !config.shadow_mode {
                state.rejections.fetch_add(1, Ordering::Relaxed);
                return Err(AdaptiveConcurrencyLimitExceeded {
                    current_in_flight: current,
                    limit,
                });
            }

            match state.in_flight.compare_exchange_weak(
                current,
                current.saturating_add(1),
                Ordering::AcqRel,
                Ordering::Relaxed,
            ) {
                Ok(_) => {
                    return Ok(Arc::new(AdaptiveConcurrencyPermit {
                        state,
                        config,
                        recorded: AtomicBool::new(false),
                    }));
                }
                Err(_) => continue,
            }
        }
    }

    fn reserve_key_slot(
        &self,
        max_tracked_keys: usize,
    ) -> Result<(), AdaptiveConcurrencyLimitExceeded> {
        let mut current = self.tracked_keys.load(Ordering::Acquire);
        loop {
            if current >= max_tracked_keys {
                return Err(AdaptiveConcurrencyLimitExceeded {
                    current_in_flight: current as u64,
                    limit: max_tracked_keys as u64,
                });
            }
            match self.tracked_keys.compare_exchange_weak(
                current,
                current + 1,
                Ordering::AcqRel,
                Ordering::Acquire,
            ) {
                Ok(_) => return Ok(()),
                Err(observed) => current = observed,
            }
        }
    }

    #[allow(dead_code)]
    pub fn snapshot(
        &self,
        proxy: &Proxy,
        target: Option<&UpstreamTarget>,
        key_by: AdaptiveConcurrencyKeyBy,
    ) -> Option<AdaptiveConcurrencySnapshot> {
        let key = build_key(self.resolve_scope(proxy, key_by), proxy, target);
        self.inner
            .get(&key)
            .map(|entry| AdaptiveConcurrencySnapshot::from_state(key, entry.value()))
    }

    /// Resolve the scope component of the key for `proxy` under `key_by`.
    /// `backend` scoping returns one shared constant. `proxy` scoping caches a
    /// reused `Arc<str>` per `proxy.id` — which uniquely and stably identifies
    /// the proxy, so the cached `proxy:{ns}:{id}` scope never goes stale.
    /// `upstream` scoping is computed per call: its `upstream:{ns}:{upstream_id}`
    /// depends on the proxy's upstream, which can change across a reload while a
    /// shared (global/proxy_group) limiter instance — and this cache — is
    /// preserved, so caching it by `proxy.id` would serve a stale upstream scope
    /// (and keying by `upstream_id` alone could collide across namespaces). The
    /// string is short, and the admission path already allocates the full key in
    /// `build_key`.
    fn resolve_scope(&self, proxy: &Proxy, key_by: AdaptiveConcurrencyKeyBy) -> Arc<str> {
        match key_by {
            AdaptiveConcurrencyKeyBy::Backend => Arc::clone(&self.backend_scope),
            AdaptiveConcurrencyKeyBy::Upstream => Arc::from(compute_scope_string(proxy, key_by)),
            AdaptiveConcurrencyKeyBy::Proxy => {
                if let Some(cached) = self.scope_cache.get(proxy.id.as_str()) {
                    return Arc::clone(cached.value());
                }
                let scope: Arc<str> = Arc::from(compute_scope_string(proxy, key_by));
                self.scope_cache
                    .insert(proxy.id.as_str().into(), Arc::clone(&scope));
                scope
            }
        }
    }
}

#[allow(dead_code)]
#[derive(Clone, Debug)]
pub struct AdaptiveConcurrencySnapshot {
    pub key: AdaptiveConcurrencyKey,
    pub in_flight: u64,
    pub limit: u64,
    pub baseline_latency_us: u64,
    pub latency_ewma_us: u64,
    pub samples: u64,
    pub rejections: u64,
}

impl AdaptiveConcurrencySnapshot {
    fn from_state(key: AdaptiveConcurrencyKey, state: &AdaptiveConcurrencyState) -> Self {
        Self {
            key,
            in_flight: state.in_flight.load(Ordering::Relaxed),
            limit: state.limit.load(Ordering::Acquire),
            baseline_latency_us: state.baseline_latency_us.load(Ordering::Acquire),
            latency_ewma_us: state.latency_ewma_us.load(Ordering::Acquire),
            samples: state.samples.load(Ordering::Acquire),
            rejections: state.rejections.load(Ordering::Relaxed),
        }
    }
}

#[derive(Clone, Debug)]
pub struct AdaptiveConcurrencyLimitExceeded {
    pub current_in_flight: u64,
    pub limit: u64,
}

pub struct AdaptiveConcurrencyPermit {
    state: Arc<AdaptiveConcurrencyState>,
    config: Arc<AdaptiveConcurrencyConfig>,
    recorded: AtomicBool,
}

impl AdaptiveConcurrencyPermit {
    /// Feed one healthy backend sample into the limiter.
    ///
    /// `backend_elapsed` is the dispatch-relative backend latency. For buffered
    /// responses it is the full backend round trip; for streamed responses it is
    /// TTFB (headers), recorded at body completion — so for streaming backends
    /// the latency signal is TTFB while the slot is held for the whole body.
    /// That asymmetry is acceptable because a streamed slot is still transient
    /// (it frees when the body completes), unlike a WebSocket session, which is
    /// why streaming keeps `allow_increase = true` rather than using the holding
    /// variant.
    ///
    /// Heuristic caveat: `baseline_latency_us` is a monotonically-decreasing
    /// minimum that never decays back up, so a single unusually-fast response
    /// (a tiny 200, a 304, a cache hit) permanently lowers `target_latency` and
    /// can keep the limit pinned low. A windowed/decaying minimum would avoid
    /// this; it is left as a documented sensitivity for now.
    fn record_success_latency(&self, backend_elapsed: Duration, allow_increase: bool) {
        let latency_us = (backend_elapsed.as_micros() as u64).max(1);
        update_min(&self.state.baseline_latency_us, latency_us);
        let ewma = update_ewma(&self.state.latency_ewma_us, latency_us);
        let samples = self.state.samples.fetch_add(1, Ordering::AcqRel) + 1;
        if samples < self.config.min_samples {
            return;
        }

        let baseline = self.state.baseline_latency_us.load(Ordering::Acquire);
        if baseline == 0 {
            return;
        }
        let target_latency = (baseline as f64 * self.config.target_latency_multiplier)
            .round()
            .max(1.0) as u64;
        let current_limit = self.state.limit.load(Ordering::Acquire);
        let current_in_flight = self.state.in_flight.load(Ordering::Acquire);
        if ewma > target_latency {
            decrease_limit(&self.state.limit, &self.config);
        } else if allow_increase && current_in_flight >= current_limit {
            increase_limit(&self.state.limit, &self.config);
        }
    }

    /// Shared outcome accounting. `allow_increase` is `false` for long-lived
    /// admissions (WebSocket sessions) whose in-flight slot is still held when
    /// the outcome is recorded: every concurrent handshake then observes
    /// `in_flight >= limit`, so growing the limit there would ratchet it up to
    /// `max_limit` and defeat the in-flight session cap.
    fn record(&self, outcome: BackendAdmissionOutcome, allow_increase: bool) {
        if self.recorded.swap(true, Ordering::AcqRel) {
            return;
        }
        // Client-/gateway-side outcomes do not reflect backend health: release
        // the slot without feeding a latency, growth, or shrink signal. An
        // oversized *client* upload surfaces as a gateway 413
        // (`RequestBodyTooLarge`) and a client abort as `ClientDisconnect`;
        // neither is the backend's fault, so they must not train the limiter.
        if matches!(
            outcome.error_class,
            Some(ErrorClass::ClientDisconnect | ErrorClass::RequestBodyTooLarge)
        ) {
            return;
        }
        // Backend faults shrink the limit. An oversized *backend* response
        // (`ResponseBodyTooLarge`) is a backend fault even when the status line
        // looked healthy before the overflow was detected, so it must not be
        // counted as a fast success.
        if outcome.connection_error
            || outcome.response_status >= 500
            || outcome.error_class == Some(ErrorClass::ResponseBodyTooLarge)
        {
            decrease_limit(&self.state.limit, &self.config);
            return;
        }
        self.record_success_latency(outcome.backend_elapsed, allow_increase);
    }
}

impl BackendAdmissionPermit for AdaptiveConcurrencyPermit {
    fn record_backend_outcome(&self, outcome: BackendAdmissionOutcome) {
        self.record(outcome, true);
    }

    fn record_backend_outcome_holding(&self, outcome: BackendAdmissionOutcome) {
        self.record(outcome, false);
    }
}

impl Drop for AdaptiveConcurrencyPermit {
    fn drop(&mut self) {
        self.state.in_flight.fetch_sub(1, Ordering::AcqRel);
    }
}

fn build_key(
    scope: Arc<str>,
    proxy: &Proxy,
    target: Option<&UpstreamTarget>,
) -> AdaptiveConcurrencyKey {
    // Only host/port vary per request; `scope` is resolved (and cached) by the
    // caller via `resolve_scope`.
    let (host, port) = target
        .map(|target| (target.host.as_str(), target.port))
        .unwrap_or((proxy.backend_host.as_str(), proxy.backend_port));

    AdaptiveConcurrencyKey {
        scope,
        host: host.to_string(),
        port,
    }
}

fn compute_scope_string(proxy: &Proxy, key_by: AdaptiveConcurrencyKeyBy) -> String {
    match key_by {
        AdaptiveConcurrencyKeyBy::Proxy => scoped_proxy(proxy),
        AdaptiveConcurrencyKeyBy::Upstream => proxy
            .upstream_id
            .as_deref()
            .map(|upstream_id| {
                let mut scope = String::with_capacity(
                    "upstream::".len() + proxy.namespace.len() + upstream_id.len(),
                );
                scope.push_str("upstream:");
                scope.push_str(&proxy.namespace);
                scope.push(':');
                scope.push_str(upstream_id);
                scope
            })
            .unwrap_or_else(|| scoped_proxy(proxy)),
        // `backend` scope is served as a shared constant by `resolve_scope` and
        // never reaches this function in practice.
        AdaptiveConcurrencyKeyBy::Backend => "backend".to_string(),
    }
}

fn scoped_proxy(proxy: &Proxy) -> String {
    let mut scope = String::with_capacity("proxy::".len() + proxy.namespace.len() + proxy.id.len());
    scope.push_str("proxy:");
    scope.push_str(&proxy.namespace);
    scope.push(':');
    scope.push_str(&proxy.id);
    scope
}

fn update_min(atomic: &AtomicU64, candidate: u64) {
    let mut current = atomic.load(Ordering::Acquire);
    loop {
        if current != 0 && current <= candidate {
            return;
        }
        match atomic.compare_exchange(current, candidate, Ordering::AcqRel, Ordering::Acquire) {
            Ok(_) => return,
            Err(observed) => current = observed,
        }
    }
}

fn update_ewma(atomic: &AtomicU64, sample: u64) -> u64 {
    let mut current = atomic.load(Ordering::Acquire);
    loop {
        let next = if current == 0 {
            sample
        } else {
            current
                .saturating_mul(EWMA_PREVIOUS_WEIGHT)
                .saturating_add(sample.saturating_mul(EWMA_SAMPLE_WEIGHT))
                / EWMA_WEIGHT_SUM
        };
        match atomic.compare_exchange(current, next, Ordering::AcqRel, Ordering::Acquire) {
            Ok(_) => return next,
            Err(observed) => current = observed,
        }
    }
}

fn decrease_limit(limit: &AtomicU64, config: &AdaptiveConcurrencyConfig) {
    let mut current = limit.load(Ordering::Acquire);
    loop {
        let decreased = ((current as f64) * config.decrease_ratio).floor() as u64;
        let next = decreased.max(config.min_limit).min(config.max_limit);
        if next >= current {
            return;
        }
        match limit.compare_exchange(current, next, Ordering::AcqRel, Ordering::Acquire) {
            Ok(_) => return,
            Err(observed) => current = observed,
        }
    }
}

fn increase_limit(limit: &AtomicU64, config: &AdaptiveConcurrencyConfig) {
    let mut current = limit.load(Ordering::Acquire);
    loop {
        if current >= config.max_limit {
            return;
        }
        let next = current
            .saturating_add(config.increase_step)
            .max(config.min_limit)
            .min(config.max_limit);
        if next == current {
            return;
        }
        match limit.compare_exchange(current, next, Ordering::AcqRel, Ordering::Acquire) {
            Ok(_) => return,
            Err(observed) => current = observed,
        }
    }
}
