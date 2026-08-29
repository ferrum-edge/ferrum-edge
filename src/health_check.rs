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
    ActiveHealthCheck, BackendTlsConfig, GatewayConfig, HealthProbeType, MAX_TARGETS_PER_UPSTREAM,
    PassiveHealthCheck, Upstream, UpstreamTarget,
};
use crate::dns::{DnsCache, DnsCacheResolver};
use crate::load_balancer::{
    LoadBalancerCache, target_host_port_key, target_key, write_target_host_port_key,
};
use crate::tls::backend::SanAllowListVerifier;
use crate::tls::source::{CertSource, MaterialKind, load_material_blocking};
use crate::tls::{backend_client_config_builder, build_server_verifier_with_crls};
use dashmap::DashMap;
use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use std::sync::Mutex;
use std::sync::atomic::{AtomicU32, AtomicU64, Ordering};
use std::time::Duration;
use tokio::task::AbortHandle;
use tracing::{debug, info, warn};

// Thread-local buffer for formatting "host:port" keys in `report_response()`;
// avoids a `String` allocation on every proxied response (hot path).
thread_local! {
    static HP_KEY_BUF: std::cell::RefCell<String> =
        std::cell::RefCell::new(String::with_capacity(64));
    /// Scratch buffer for namespace-qualified passive-health outer keys.
    static PASSIVE_PROXY_KEY_BUF: std::cell::RefCell<String> =
        std::cell::RefCell::new(String::with_capacity(64));
    /// Scratch buffer for namespace-qualified active-probe upstream keys on
    /// the proxy hot path (`has_running_active_probes`).
    static ACTIVE_PROBE_UPSTREAM_KEY_BUF: std::cell::RefCell<String> =
        std::cell::RefCell::new(String::with_capacity(64));
}

/// Wait for a shutdown signal on a watch channel.
async fn wait_for_shutdown(mut rx: tokio::sync::watch::Receiver<bool>) {
    while !*rx.borrow() {
        if rx.changed().await.is_err() {
            return;
        }
    }
}

fn format_probe_socket_addr(host: &str, port: u16) -> String {
    if !host.starts_with('[') && host.parse::<std::net::Ipv6Addr>().is_ok() {
        format!("[{}]:{}", host, port)
    } else {
        format!("{}:{}", host, port)
    }
}

fn format_probe_url(scheme: &str, host: &str, port: u16, path: &str) -> String {
    let host = if !host.starts_with('[') && host.parse::<std::net::Ipv6Addr>().is_ok() {
        format!("[{}]", host)
    } else {
        host.to_string()
    };
    format!("{}://{}:{}{}", scheme, host, port, path)
}

fn grpc_probe_urls(
    scheme: &str,
    original_host: &str,
    dial_addr: &str,
    port: u16,
) -> (String, String) {
    (
        format_probe_url(scheme, dial_addr, port, ""),
        format_probe_url(scheme, original_host, port, ""),
    )
}

/// Authority a probe must present to the backend: the REAL target, never the
/// TLS server name. Mirrors what a plain `format_probe_url` client would put in
/// `Host` / `:authority`, including the default-port elision reqwest performs.
fn probe_authority(scheme: &str, host: &str, port: u16) -> String {
    let rendered = if !host.starts_with('[') && host.parse::<std::net::Ipv6Addr>().is_ok() {
        format!("[{host}]")
    } else {
        host.to_string()
    };
    let default_port = match scheme {
        "https" => 443,
        _ => 80,
    };
    if port == default_port {
        rendered
    } else {
        format!("{rendered}:{port}")
    }
}

/// Effective backend TLS server name for a probe.
///
/// A backend covered by `backend_tls_sni` (Gateway API `BackendTLSPolicy`
/// `validation.hostname`, an Istio DestinationRule TLS overlay, or the upstream
/// field directly) presents a certificate valid for THAT name, not for the
/// target host the gateway dials. A probe that verifies against the target host
/// therefore marks a perfectly healthy backend unhealthy — request traffic
/// succeeds while the probe fails. Use the same identity request traffic uses.
///
/// Returns the bracket-stripped form: rustls/tonic want a bare DNS name, and
/// `validate_backend_tls_sni` already guarantees an override is a hostname and
/// never an IP literal.
fn probe_tls_server_name<'a>(tls_config: &'a BackendTlsConfig, host: &'a str) -> &'a str {
    let name = tls_config.sni.as_deref().unwrap_or(host);
    match name.strip_prefix('[').and_then(|i| i.strip_suffix(']')) {
        Some(bare) => bare,
        None => name,
    }
}

fn load_probe_tls_material(
    source_value: &str,
    kind: MaterialKind,
    label: &str,
) -> Result<Vec<u8>, String> {
    let source = CertSource::parse(source_value, kind);
    load_material_blocking(&source, kind)
        .map(|material| material.bytes.expose_secret().to_vec())
        .map_err(|e| format!("{label}: {e}"))
}

fn load_probe_tls_certificates(
    source_value: &str,
    kind: MaterialKind,
    label: &str,
) -> Result<Vec<rustls::pki_types::CertificateDer<'static>>, String> {
    let source = CertSource::parse(source_value, kind);
    let material =
        load_material_blocking(&source, kind).map_err(|error| format!("{label}: {error}"))?;
    crate::tls::parse_pem_certificate_bundle(
        material.bytes.expose_secret(),
        label,
        &material.display_source_id,
    )
    .map_err(|error| error.to_string())
}

fn load_probe_tls_root_store(
    source_value: &str,
    label: &str,
) -> Result<rustls::RootCertStore, String> {
    let source = CertSource::parse(source_value, MaterialKind::CaBundle);
    let material = load_material_blocking(&source, MaterialKind::CaBundle)
        .map_err(|error| format!("{label}: {error}"))?;
    crate::tls::root_cert_store_from_pem_bundle(
        material.bytes.expose_secret(),
        label,
        &material.display_source_id,
    )
    .map_err(|error| error.to_string())
}

/// Re-export the cap from types so runtime and validation share one value.
use crate::config::types::MAX_RECENT_FAILURES_PER_TARGET;

/// Bounded ring of recent failure timestamps for one target.
///
/// Replaces the previous `DashMap<u64, u64>` + per-failure `retain` / sort /
/// eviction path. A circular buffer of at most
/// [`MAX_RECENT_FAILURES_PER_TARGET`] epoch-ms timestamps gives:
///
/// - O(1) amortized record: each timestamp is written once and expired once
/// - No heap allocation after the first failure (the slot `Vec` is sized to
///   the cap once and reused)
/// - Exact sliding-window counts, so the unhealthy-threshold decision matches
///   the previous map. When the in-window count would exceed the cap this
///   returns the capped count; `unhealthy_threshold` is validated `<=` the
///   cap, so the boolean decision is identical
///
/// Stored behind a per-target [`Mutex`]. The critical section is a handful of
/// integer ops and replaces a sharded DashMap `retain` over the whole window
/// plus a 1000-entry sort on the request path. Concurrent reporters for the
/// *same* target serialize here; different targets do not share a lock. This
/// stays per-proxy isolated because each [`ProxyHealthState`] owns its own
/// `TargetHealth` rows.
struct RecentFailureRing {
    /// Circular buffer. Empty until the first `record` so active-probe-only
    /// `TargetHealth` rows do not pay the cap.
    slots: Vec<u64>,
    /// Index of the oldest stored timestamp.
    head: usize,
    /// Number of valid timestamps currently stored (`<= slots.len()`).
    len: usize,
}

impl RecentFailureRing {
    fn new() -> Self {
        Self {
            slots: Vec::new(),
            head: 0,
            len: 0,
        }
    }

    fn ensure_slots(&mut self) {
        if !self.slots.is_empty() {
            return;
        }
        self.slots.resize(MAX_RECENT_FAILURES_PER_TARGET, 0);
    }

    /// Push `now_ms`, drop expired and over-cap oldest entries, return the
    /// in-window count. O(1) amortized; no allocation after the first call.
    fn record(&mut self, now_ms: u64, window_start: u64) -> usize {
        self.ensure_slots();
        self.expire_before(window_start);
        if self.len == MAX_RECENT_FAILURES_PER_TARGET {
            self.pop_front();
        }
        self.push_back(now_ms);
        self.len
    }

    fn expire_before(&mut self, window_start: u64) {
        while !self.is_empty() && self.front() < window_start {
            self.pop_front();
        }
    }

    fn front(&self) -> u64 {
        self.slots[self.head]
    }

    fn pop_front(&mut self) {
        let cap = self.slots.len();
        self.head += 1;
        if self.head == cap {
            self.head = 0;
        }
        self.len -= 1;
    }

    fn push_back(&mut self, ts: u64) {
        let cap = self.slots.len();
        let mut idx = self.head + self.len;
        if idx >= cap {
            idx -= cap;
        }
        self.slots[idx] = ts;
        self.len += 1;
    }

    fn clear(&mut self) {
        self.head = 0;
        self.len = 0;
    }

    fn len(&self) -> usize {
        self.len
    }

    fn is_empty(&self) -> bool {
        self.len == 0
    }

    fn slot_capacity(&self) -> usize {
        self.slots.len()
    }
}

/// Health state for a single target.
struct TargetHealth {
    consecutive_successes: AtomicU32,
    consecutive_failures: AtomicU32,
    /// Recent failure timestamps (epoch ms) for passive windowed counting.
    /// Bounded to MAX_RECENT_FAILURES_PER_TARGET entries.
    recent_failures: Mutex<RecentFailureRing>,
}

impl TargetHealth {
    fn new() -> Self {
        Self {
            consecutive_successes: AtomicU32::new(0),
            consecutive_failures: AtomicU32::new(0),
            recent_failures: Mutex::new(RecentFailureRing::new()),
        }
    }

    fn lock_recent_failures(&self) -> std::sync::MutexGuard<'_, RecentFailureRing> {
        self.recent_failures
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }
}

#[cfg(test)]
#[allow(clippy::items_after_test_module)]
mod recent_failure_ring_tests {
    //! Private ring-buffer accounting. External tests cannot see this type;
    //! keep the reference comparison here rather than widening the runtime API.
    use super::*;

    /// Old DashMap semantics: keep timestamps `>= window_start` in insert
    /// order, then drop the oldest until at most CAP remain.
    fn reference_in_window(stamps: &[u64], window_start: u64) -> Vec<u64> {
        let mut kept: Vec<u64> = stamps
            .iter()
            .copied()
            .filter(|&ts| ts >= window_start)
            .collect();
        if kept.len() > MAX_RECENT_FAILURES_PER_TARGET {
            let excess = kept.len() - MAX_RECENT_FAILURES_PER_TARGET;
            kept.drain(..excess);
        }
        kept
    }

    fn record_all(ring: &mut RecentFailureRing, stamps: &[u64], window_ms: u64) -> Vec<usize> {
        stamps
            .iter()
            .enumerate()
            .map(|(i, &now_ms)| {
                let window_start = now_ms.saturating_sub(window_ms);
                let prefix = &stamps[..=i];
                let expected = reference_in_window(prefix, window_start);
                let got = ring.record(now_ms, window_start);
                assert_eq!(
                    got,
                    expected.len(),
                    "ring count diverged from retain+cap at i={i}"
                );
                assert_eq!(ring.len(), expected.len());
                got
            })
            .collect()
    }

    #[test]
    fn threshold_decision_matches_retain_and_cap_for_representative_sequences() {
        let window_ms = 10_000;
        let threshold = 3usize;

        // Tight cluster: three in-window failures trip; two do not.
        let cluster = [1_000u64, 1_100, 1_200];
        let mut ring = RecentFailureRing::new();
        let counts = record_all(&mut ring, &cluster, window_ms);
        assert!(counts[0] < threshold);
        assert!(counts[1] < threshold);
        assert!(counts[2] >= threshold);

        // Window expiry: two old failures must not combine with a later one.
        let mut ring = RecentFailureRing::new();
        let expired = [0u64, 1, 12_000];
        let counts = record_all(&mut ring, &expired, window_ms);
        assert!(counts[1] < threshold);
        assert_eq!(counts[2], 1);
        assert!(counts[2] < threshold);

        // Mix of in-window and expired timestamps, then a wrap past the cap.
        let mut stamps = vec![0u64; MAX_RECENT_FAILURES_PER_TARGET + 50];
        for (i, slot) in stamps.iter_mut().enumerate() {
            *slot = i as u64;
        }
        // Shift the tail far enough that the first CAP entries expire.
        for slot in stamps.iter_mut().skip(MAX_RECENT_FAILURES_PER_TARGET) {
            *slot += 20_000;
        }
        let mut ring = RecentFailureRing::new();
        let counts = record_all(&mut ring, &stamps, window_ms);
        let last = *counts.last().unwrap();
        assert_eq!(last, 50);
        assert!(last < MAX_RECENT_FAILURES_PER_TARGET);
        assert_eq!(ring.slot_capacity(), MAX_RECENT_FAILURES_PER_TARGET,);
    }

    #[test]
    fn ring_stays_capped_and_does_not_grow_past_max() {
        let mut ring = RecentFailureRing::new();
        let window_start = 0;
        for i in 0..(MAX_RECENT_FAILURES_PER_TARGET * 5) {
            let count = ring.record(i as u64, window_start);
            assert!(count <= MAX_RECENT_FAILURES_PER_TARGET);
            assert_eq!(ring.slot_capacity(), MAX_RECENT_FAILURES_PER_TARGET,);
        }
        assert_eq!(ring.len(), MAX_RECENT_FAILURES_PER_TARGET);
    }

    #[test]
    fn clear_resets_len_but_keeps_the_capped_allocation() {
        let mut ring = RecentFailureRing::new();
        assert_eq!(ring.slot_capacity(), 0);
        ring.record(1, 0);
        assert_eq!(ring.len(), 1);
        assert_eq!(ring.slot_capacity(), MAX_RECENT_FAILURES_PER_TARGET,);
        ring.clear();
        assert_eq!(ring.len(), 0);
        assert_eq!(ring.slot_capacity(), MAX_RECENT_FAILURES_PER_TARGET,);
        ring.record(2, 0);
        assert_eq!(ring.len(), 1);
        assert_eq!(ring.slot_capacity(), MAX_RECENT_FAILURES_PER_TARGET,);
    }
}

/// Passive-ejection record stored per `(proxy_id, host:port)`.
///
/// Captures the **effective** recovery deadline from the per-port / subset /
/// upstream policy that caused the ejection, so automatic recovery honors that
/// cooldown even across config reloads and never cross-applies another proxy's
/// timer to this entry.
#[derive(Debug, Clone)]
pub struct PassiveEjection {
    /// Epoch ms when the target was marked unhealthy (used by max-ejection
    /// readmit ordering and admin metrics).
    pub ejected_at_ms: u64,
    /// Epoch ms when the automatic recovery timer may clear this entry.
    /// Equal to `ejected_at_ms` when `auto_recover` is false (unused).
    pub recover_at_ms: u64,
    /// Whether the automatic recovery scanner should clear this entry once
    /// `recover_at_ms` is reached. `false` when the ejecting policy had
    /// `healthy_after_seconds == 0` (timer recovery disabled; success-based
    /// recovery still applies).
    pub auto_recover: bool,
    /// Upstream that owned the dispatch when this target was ejected — used to
    /// reset least-latency warm-up state on timer/success recovery without a
    /// global host:port scan across unrelated balancers.
    pub upstream_id: String,
    /// Target host at ejection time (for least-latency reset on timer recovery).
    pub host: String,
    /// Target port at ejection time (for least-latency reset on timer recovery).
    pub port: u16,
}

impl PassiveEjection {
    /// Build an ejection record from the effective passive policy that caused it.
    pub fn from_policy(
        upstream_id: &str,
        target: &UpstreamTarget,
        healthy_after_seconds: u64,
        now_ms: u64,
    ) -> Self {
        let auto_recover = healthy_after_seconds > 0;
        let recover_at_ms = if auto_recover {
            now_ms.saturating_add(healthy_after_seconds.saturating_mul(1000))
        } else {
            now_ms
        };
        Self {
            ejected_at_ms: now_ms,
            recover_at_ms,
            auto_recover,
            upstream_id: upstream_id.to_owned(),
            host: target.host.clone(),
            port: target.port,
        }
    }
}

/// Per-proxy passive health state for a set of targets.
///
/// Wraps `unhealthy` and `states` DashMaps keyed by `host:port`. One instance
/// exists per proxy that has passive health checks configured, stored in the
/// outer `DashMap<proxy_id, Arc<ProxyHealthState>>`.
pub struct ProxyHealthState {
    /// host:port → ejection record (deadline + owning upstream).
    pub unhealthy: DashMap<String, PassiveEjection>,
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
    /// Default HTTP client for active health check probes (no mTLS).
    /// Used when the upstream has no TLS config.
    ///
    /// `None` when every fail-closed builder path failed: HTTP probes then
    /// fail closed (report unhealthy) rather than panicking or inheriting
    /// ambient proxies via the ambient-proxy-aware default constructor.
    default_http_client: Option<Arc<reqwest::Client>>,
    /// JoinHandles for the current generation of active-check /
    /// passive-recovery tasks. Modes may drain these via
    /// [`Self::take_active_check_handles`] so they can `await` them during
    /// graceful shutdown. Reload visibility does **not** depend on this
    /// vec — see `active_check_aborts`.
    ///
    /// Wrapped in `Mutex` so [`Self::start_with_shutdown`] and
    /// [`Self::restart_with_shutdown`] can re-spawn probe tasks on config
    /// reload without requiring `&mut self` (the gateway holds an
    /// `Arc<HealthChecker>` for the lifetime of `ProxyState`). Touched only
    /// at startup, config reload, and drop — never on the proxy hot path,
    /// so the lock is uncontested.
    active_check_handles: Mutex<Vec<tokio::task::JoinHandle<()>>>,
    /// AbortHandles for every live active-check / passive-recovery task,
    /// including generations whose `JoinHandle`s were drained by
    /// [`Self::take_active_check_handles`].
    ///
    /// `HealthChecker` is the single lifecycle owner for cancel: reload and
    /// drop always abort through this list, so the production
    /// `start_with_shutdown` → `take_active_check_handles` →
    /// `restart_with_shutdown` sequence cannot orphan the startup
    /// generation. Modes still own the drained `JoinHandle`s for await.
    active_check_aborts: Mutex<Vec<AbortHandle>>,
    /// Monotonic generation for spawned active probe tasks.
    ///
    /// Bumped at the start of every [`Self::start_with_shutdown`] (including
    /// reload) before prior tasks are aborted. Each active probe captures its
    /// generation at spawn and refuses to dial or mutate health state once
    /// the checker has advanced, so a mid-flight stale probe cannot
    /// reintroduce removed targets or apply retired policy after replacement.
    task_generation: Arc<AtomicU64>,
    /// Orders reload generation rollover against publication of active-probe
    /// and passive-recovery results.
    ///
    /// A generation check by itself has a check-then-mutate window: reload can
    /// advance the generation after the check but before the stale task updates
    /// shared counters or health maps. Probe/recovery publication takes a read
    /// guard and re-checks its generation under that guard; reload takes the
    /// write guard before advancing either generation. This is a cold-path
    /// lifecycle lock and is never touched by proxied requests.
    lifecycle_publish_guard: Arc<std::sync::RwLock<()>>,
    /// Monotonic generation for the gateway-scoped passive recovery scanner.
    ///
    /// Bumped on every [`Self::start_with_shutdown`] /
    /// [`Self::restart_with_shutdown`]. Modes often
    /// [`Self::take_active_check_handles`] at startup, so a later reload cannot
    /// abort the previously taken scanner JoinHandle via that vec — AbortHandles
    /// retain cancel ownership, and this generation fence makes a stale scanner
    /// exit on its next tick if it races past abort (or after passive recovery
    /// has been disabled).
    passive_recovery_generation: Arc<AtomicU64>,
    /// Optional reference to the load balancer cache for recording active
    /// probe latencies (used by least-latency algorithm). Set via
    /// `set_load_balancer_cache()` after construction.
    lb_cache: Option<Arc<LoadBalancerCache>>,
    /// Global pool config for building per-upstream TLS clients.
    pool_config: PoolConfig,
    /// DNS cache for building per-upstream TLS clients.
    dns_cache: Option<DnsCache>,
    /// Global TLS CA bundle path (fallback when upstream has no CA config).
    global_tls_ca_bundle_path: Option<String>,
    /// Global backend mTLS client cert path (fallback).
    global_backend_tls_client_cert_path: Option<String>,
    /// Global backend mTLS client key path (fallback).
    global_backend_tls_client_key_path: Option<String>,
    /// Global TLS no-verify flag.
    global_tls_no_verify: bool,
    /// Per-upstream probe generation, keyed by namespaced upstream key.
    ///
    /// An SD-driven target-set change bumps only this cell so probes for other
    /// upstreams keep running. Full config reload still bumps
    /// [`Self::task_generation`] and retires every probe.
    upstream_probe_generation: DashMap<String, Arc<AtomicU64>>,
    /// AbortHandles for live probes grouped by namespaced upstream key.
    /// Targeted abort for [`Self::restart_upstream_probes`] without cancelling
    /// other upstreams or the passive-recovery scanner.
    upstream_probe_aborts: Mutex<HashMap<String, Vec<AbortHandle>>>,
    /// Last shutdown receiver passed to [`Self::start_with_shutdown`], cloned
    /// into SD-spawned replacement probes.
    probe_shutdown_rx: Mutex<Option<tokio::sync::watch::Receiver<bool>>>,
    /// Namespaced upstream keys that currently have at least one live active
    /// probe task. Read on the proxy hot path to decide whether passive TTFB
    /// sampling is suppressed.
    active_probe_upstreams: DashMap<String, ()>,
    /// Active-probe spec recorded by [`Self::start_with_shutdown`] so service
    /// discovery can restart probes without re-reading GatewayConfig.
    active_probe_specs: DashMap<String, Arc<ActiveProbeSpec>>,
    /// Host:port identity set last spawned per upstream; used to skip a
    /// no-op SD restart when the live set did not change.
    upstream_probe_target_keys: DashMap<String, HashSet<String>>,
}

/// Per-upstream active-probe configuration captured at start/reload.
struct ActiveProbeSpec {
    active: ActiveHealthCheck,
    tls: BackendTlsConfig,
}

/// Probe TLS server verifier: plain webpki, or the same SAN-pinning wrapper
/// the data path uses (`SanAllowListVerifier`).
#[derive(Debug)]
enum ProbeServerVerifier {
    /// No SAN allow-list was configured, so probes use the plain webpki
    /// verifier the builder installs by default. Carries no payload: every
    /// consumer treats this variant as "not SAN-pinned" and installs nothing,
    /// unlike `SanAllowList`, whose verifier IS installed.
    WebPki,
    SanAllowList(Arc<SanAllowListVerifier>),
}

/// Per-active-check identity and lifecycle inputs for `start_active_check`.
struct ActiveCheckStartParams<'a> {
    target: &'a UpstreamTarget,
    upstream_namespace: &'a str,
    upstream_id: &'a str,
    shutdown_rx: Option<&'a tokio::sync::watch::Receiver<bool>>,
    generation: u64,
    upstream_generation: u64,
    upstream_generation_cell: Arc<AtomicU64>,
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
    ///
    /// The default client is built with TLS verification ENABLED. If the
    /// operator has set `FERRUM_TLS_NO_VERIFY=true`, the default client is
    /// rebuilt by [`set_global_tls_config`] before traffic flows.
    pub fn with_pool_config(pool_config: &PoolConfig, dns_cache: DnsCache) -> Self {
        let client = accept_health_check_client(
            build_health_check_client(pool_config, Some(dns_cache.clone()), false)
                .map_err(HealthCheckClientError::from),
            "default health-check HTTP client",
        );
        Self {
            active_unhealthy_targets: Arc::new(DashMap::new()),
            active_target_states: Arc::new(DashMap::new()),
            passive_health: Arc::new(DashMap::new()),
            default_http_client: client,
            active_check_handles: Mutex::new(Vec::new()),
            active_check_aborts: Mutex::new(Vec::new()),
            task_generation: Arc::new(AtomicU64::new(0)),
            lifecycle_publish_guard: Arc::new(std::sync::RwLock::new(())),
            passive_recovery_generation: Arc::new(AtomicU64::new(0)),
            lb_cache: None,
            pool_config: pool_config.clone(),
            dns_cache: Some(dns_cache),
            global_tls_ca_bundle_path: None,
            global_backend_tls_client_cert_path: None,
            global_backend_tls_client_key_path: None,
            global_tls_no_verify: false,
            upstream_probe_generation: DashMap::new(),
            upstream_probe_aborts: Mutex::new(HashMap::new()),
            probe_shutdown_rx: Mutex::new(None),
            active_probe_upstreams: DashMap::new(),
            active_probe_specs: DashMap::new(),
            upstream_probe_target_keys: DashMap::new(),
        }
    }

    /// Set global TLS config from the env config so health check clients
    /// can fall back to global mTLS credentials and CA bundles.
    ///
    /// When `tls_no_verify` is true, the default HTTPS probe client is
    /// rebuilt with `danger_accept_invalid_certs(true)` — TLS verification
    /// is opt-in via `FERRUM_TLS_NO_VERIFY`, never silently disabled.
    pub fn set_global_tls_config(
        &mut self,
        tls_ca_bundle_path: Option<String>,
        backend_tls_client_cert_path: Option<String>,
        backend_tls_client_key_path: Option<String>,
        tls_no_verify: bool,
    ) {
        self.global_tls_ca_bundle_path = tls_ca_bundle_path;
        self.global_backend_tls_client_cert_path = backend_tls_client_cert_path;
        self.global_backend_tls_client_key_path = backend_tls_client_key_path;
        self.global_tls_no_verify = tls_no_verify;

        // Rebuild the default client when no-verify is set so HTTPS probes
        // through the no-TLS-config path honour the operator opt-in.
        if tls_no_verify {
            self.default_http_client = accept_health_check_client(
                build_health_check_client(&self.pool_config, self.dns_cache.clone(), tls_no_verify)
                    .map_err(HealthCheckClientError::from),
                "default health-check HTTP client (tls_no_verify rebuild)",
            );
        }
    }

    /// Create a health checker without DNS cache (for tests).
    fn without_dns_cache(pool_config: &PoolConfig) -> Self {
        let client = accept_health_check_client(
            build_health_check_client(pool_config, None, false)
                .map_err(HealthCheckClientError::from),
            "default health-check HTTP client",
        );
        Self {
            active_unhealthy_targets: Arc::new(DashMap::new()),
            active_target_states: Arc::new(DashMap::new()),
            passive_health: Arc::new(DashMap::new()),
            default_http_client: client,
            active_check_handles: Mutex::new(Vec::new()),
            active_check_aborts: Mutex::new(Vec::new()),
            task_generation: Arc::new(AtomicU64::new(0)),
            lifecycle_publish_guard: Arc::new(std::sync::RwLock::new(())),
            passive_recovery_generation: Arc::new(AtomicU64::new(0)),
            lb_cache: None,
            pool_config: pool_config.clone(),
            dns_cache: None,
            global_tls_ca_bundle_path: None,
            global_backend_tls_client_cert_path: None,
            global_backend_tls_client_key_path: None,
            global_tls_no_verify: false,
            upstream_probe_generation: DashMap::new(),
            upstream_probe_aborts: Mutex::new(HashMap::new()),
            probe_shutdown_rx: Mutex::new(None),
            active_probe_upstreams: DashMap::new(),
            active_probe_specs: DashMap::new(),
            upstream_probe_target_keys: DashMap::new(),
        }
    }

    /// Set a reference to the load balancer cache so active health check probes
    /// can record their RTT for least-latency load balancing.
    pub fn set_load_balancer_cache(&mut self, lb_cache: Arc<LoadBalancerCache>) {
        self.lb_cache = Some(lb_cache);
    }

    /// Start health checks for all upstreams in the config.
    #[allow(dead_code)]
    pub fn start(&self, config: &GatewayConfig) {
        self.start_with_shutdown(config, None);
    }

    /// Drain the spawned active-check / passive-recovery `JoinHandle`s out
    /// of the checker so callers can await them in their per-mode
    /// background-drain phase.
    ///
    /// `start_with_shutdown` records every spawned task in
    /// `active_check_handles` **and** `active_check_aborts`. Modes call this
    /// immediately after `ProxyState::new` to take ownership of the
    /// `JoinHandle`s and `await` them alongside DNS / metrics / overload
    /// tasks. The shutdown receiver passed into `start_with_shutdown` lets
    /// each spawned loop observe shutdown via `tokio::select!` and exit
    /// cleanly before the await completes.
    ///
    /// Taking handles does **not** detach cancel ownership: AbortHandles
    /// stay with `HealthChecker` so a later [`Self::restart_with_shutdown`]
    /// (or `Drop`) can still abort the drained startup generation. Without
    /// that retained cancel path, reload would only see an empty handle
    /// list, spawn a replacement generation, and leave the startup probes
    /// / passive-recovery timers running with stale targets and policy.
    pub fn take_active_check_handles(&self) -> Vec<tokio::task::JoinHandle<()>> {
        let mut guard = match self.active_check_handles.lock() {
            Ok(g) => g,
            Err(poisoned) => poisoned.into_inner(),
        };
        std::mem::take(&mut *guard)
    }

    /// Start health checks with an optional shutdown signal.
    ///
    /// Aborts any previously spawned active-check / passive-recovery tasks
    /// (including generations whose `JoinHandle`s were drained via
    /// [`Self::take_active_check_handles`]) before re-spawning, so this is
    /// also the entry point used by [`Self::restart_with_shutdown`] on
    /// config reload. Active probe state (`active_unhealthy_targets`,
    /// `active_target_states`) is intentionally preserved across the restart
    /// so consecutive_successes/failures counters carry over and the next
    /// probe tick continues from current state — avoiding probe flapping
    /// during reload. Generation gating inside each task refuses stale dials
    /// and stale health mutations as soon as the generation advances, which is
    /// why [`Self::restart_with_shutdown`] prunes removed targets only after
    /// this call returns.
    pub fn start_with_shutdown(
        &self,
        config: &GatewayConfig,
        shutdown_rx: Option<tokio::sync::watch::Receiver<bool>>,
    ) {
        // Advance both generations while excluding result publication. A task
        // that was already publishing finishes before rollover; a task that
        // reaches publication afterward observes the new generation and exits
        // without mutating shared health state.
        let publish_guard = match self.lifecycle_publish_guard.write() {
            Ok(guard) => guard,
            Err(poisoned) => poisoned.into_inner(),
        };
        let generation = self
            .task_generation
            .fetch_add(1, Ordering::AcqRel)
            .wrapping_add(1);
        let recovery_generation = self
            .passive_recovery_generation
            .fetch_add(1, Ordering::AcqRel)
            .wrapping_add(1);

        // Cancel every prior generation via AbortHandles (covers drained
        // startup handles) and any JoinHandles still owned here.
        let old_aborts: Vec<AbortHandle> = {
            let mut guard = match self.active_check_aborts.lock() {
                Ok(g) => g,
                Err(poisoned) => poisoned.into_inner(),
            };
            std::mem::take(&mut *guard)
        };
        for abort in old_aborts {
            abort.abort();
        }
        let old_handles: Vec<tokio::task::JoinHandle<()>> = {
            let mut guard = match self.active_check_handles.lock() {
                Ok(g) => g,
                Err(poisoned) => poisoned.into_inner(),
            };
            std::mem::take(&mut *guard)
        };
        for handle in old_handles {
            handle.abort();
        }
        let old_upstream_aborts: HashMap<String, Vec<AbortHandle>> = {
            let mut guard = match self.upstream_probe_aborts.lock() {
                Ok(g) => g,
                Err(poisoned) => poisoned.into_inner(),
            };
            std::mem::take(&mut *guard)
        };
        for abort in old_upstream_aborts.into_values().flatten() {
            abort.abort();
        }
        self.active_probe_upstreams.clear();
        self.upstream_probe_target_keys.clear();
        self.active_probe_specs.clear();

        {
            let mut slot = match self.probe_shutdown_rx.lock() {
                Ok(g) => g,
                Err(poisoned) => poisoned.into_inner(),
            };
            *slot = shutdown_rx.clone();
        }

        drop(publish_guard);

        let mut new_handles: Vec<tokio::task::JoinHandle<()>> = Vec::new();
        let mut new_aborts: Vec<AbortHandle> = Vec::new();
        for upstream in &config.upstreams {
            if let Some(active) = upstream
                .health_checks
                .as_ref()
                .and_then(|hc| hc.active.as_ref())
            {
                let tls_config = BackendTlsConfig::from_upstream(upstream);
                let targets = self.effective_probe_targets(upstream);
                let (handles, aborts) = self.spawn_active_probes_for_upstream(
                    &upstream.namespace,
                    &upstream.id,
                    &targets,
                    active,
                    &tls_config,
                    shutdown_rx.as_ref(),
                    generation,
                );
                new_handles.extend(handles);
                new_aborts.extend(aborts);
            }
        }

        // One gateway-scoped passive recovery scanner recovers each ejection
        // from its own stored deadline. Per-upstream timers keyed on static
        // host:port sets cannot honor per-port/subset-only policies, SD-only
        // targets, or independent cooldowns for proxies sharing an endpoint.
        let pending_passive_recovery = self.passive_health.iter().any(|proxy| {
            proxy
                .value()
                .unhealthy
                .iter()
                .any(|entry| entry.value().auto_recover)
        });
        if config_needs_passive_recovery(config) || pending_passive_recovery {
            let handle =
                self.start_passive_recovery_scanner(shutdown_rx.clone(), recovery_generation);
            new_aborts.push(handle.abort_handle());
            new_handles.push(handle);
        }

        match self.active_check_handles.lock() {
            Ok(mut guard) => *guard = new_handles,
            Err(poisoned) => *poisoned.into_inner() = new_handles,
        }
        match self.active_check_aborts.lock() {
            Ok(mut guard) => *guard = new_aborts,
            Err(poisoned) => *poisoned.into_inner() = new_aborts,
        }
    }

    /// Restart probe tasks to match `new_config`.
    ///
    /// Called from [`crate::proxy::ProxyState::update_config`] and
    /// [`crate::proxy::ProxyState::apply_incremental`] after the canonical
    /// config swap so that:
    ///
    /// - Upstreams added on reload get probe tasks spawned.
    /// - Upstreams removed on reload have their probe tasks aborted (no
    ///   leaked timers probing dead targets).
    /// - Upstreams whose `interval` / `timeout` / `unhealthy_threshold` /
    ///   probe_type / TLS config / etc. changed pick up the new config —
    ///   the old task is aborted and a fresh one is spawned with the new
    ///   parameters.
    ///
    /// Stale entries in `active_unhealthy_targets` and `active_target_states`
    /// for fully removed upstreams or removed targets are pruned so they
    /// don't accumulate in the shared maps over the gateway's lifetime.
    /// (`remove_stale_targets` is normally invoked from the service-discovery
    /// path on dynamic target changes; this call covers the static-config
    /// reload path so the two layers stay consistent.)
    ///
    /// We deliberately do a **full restart** rather than a per-upstream diff
    /// because (a) reloads are rare (DB poll cycle, CP push, file SIGHUP)
    /// and (b) the persistent `active_unhealthy_targets` / `active_target_states`
    /// DashMaps carry consecutive-success/failure counters across the brief
    /// abort + re-spawn window, so a target that was "unhealthy" before the
    /// reload stays unhealthy until the next probe tick recovers it normally.
    /// No flapping.
    pub fn restart_with_shutdown(
        &self,
        new_config: &GatewayConfig,
        shutdown_rx: Option<tokio::sync::watch::Receiver<bool>>,
    ) {
        // Retire the previous generation and spawn the replacement FIRST.
        // `start_with_shutdown` advances `task_generation` before aborting,
        // so every prior probe task is fenced (and aborted) before the prune
        // below runs. Pruning first would leave the whole spawn phase —
        // which builds per-upstream TLS clients and can touch the
        // filesystem — as a window in which a still-running old-generation
        // probe could re-insert a target that was just removed.
        self.start_with_shutdown(new_config, shutdown_rx);

        // Prune active-probe state for upstreams / targets that are no longer
        // in the config so the shared maps don't accumulate stale entries.
        // The replacement generation only ever writes keys that are in
        // `active_keys`, so running this after the spawn cannot drop live
        // state. Active probes defer `target_states` / `unhealthy` entry until
        // after the post-dial generation fence and re-check generation while
        // holding the DashMap entry lock, so a retired mid-flight probe cannot
        // resurrect a just-pruned key in the TOCTOU between fence and insert.
        let active_keys: std::collections::HashSet<String> = new_config
            .upstreams
            .iter()
            .flat_map(|u| {
                let upstream_key =
                    crate::config::db_backend::namespaced_runtime_key(&u.namespace, &u.id);
                self.effective_probe_targets(u)
                    .into_iter()
                    .map(move |t| target_key(&upstream_key, &t))
                    .collect::<Vec<_>>()
            })
            .collect();
        self.active_unhealthy_targets
            .retain(|key, _| active_keys.contains(key));
        self.active_target_states
            .retain(|key, _| active_keys.contains(key));
    }

    /// True when this checker currently has at least one spawned active-probe
    /// loop for `upstream_id`. Used by the data path to suppress passive TTFB
    /// sampling only when active probes are actually running — not merely
    /// configured on an SD-only upstream that has no live endpoints yet.
    pub fn has_running_active_probes(&self, namespace: &str, upstream_id: &str) -> bool {
        ACTIVE_PROBE_UPSTREAM_KEY_BUF.with(|buf| {
            let mut key = buf.borrow_mut();
            crate::config::db_backend::write_namespaced_runtime_key(
                &mut key,
                namespace,
                upstream_id,
            );
            self.active_probe_upstreams.contains_key(key.as_str())
        })
    }

    /// Restart active probes for one upstream after service discovery publishes
    /// a merged target set. Looks up the probe spec captured at
    /// [`HealthChecker::start_with_shutdown`]. No-ops when the upstream has no
    /// stored active-check spec.
    pub fn restart_upstream_probes_for_discovered(
        &self,
        namespace: &str,
        upstream_id: &str,
        targets: &[UpstreamTarget],
    ) {
        let spec_key = crate::config::db_backend::namespaced_runtime_key(namespace, upstream_id);
        let spec = self
            .active_probe_specs
            .get(&spec_key)
            .map(|entry| Arc::clone(entry.value()));
        match spec {
            Some(spec) => self.restart_upstream_probes(
                namespace,
                upstream_id,
                targets,
                spec.active.clone(),
                spec.tls.clone(),
            ),
            None => {
                self.abort_upstream_probe_tasks(&spec_key);
                self.active_probe_upstreams.remove(&spec_key);
                self.upstream_probe_target_keys.remove(&spec_key);
            }
        }
    }

    /// Restart active probes for one upstream without bumping the global
    /// `task_generation`. Other upstreams keep running. Probe count is capped
    /// at [`MAX_TARGETS_PER_UPSTREAM`] so discovered-endpoint churn cannot
    /// unbounded-fan-out probe tasks.
    pub fn restart_upstream_probes(
        &self,
        namespace: &str,
        upstream_id: &str,
        targets: &[UpstreamTarget],
        active: ActiveHealthCheck,
        tls: BackendTlsConfig,
    ) {
        let spec_key = crate::config::db_backend::namespaced_runtime_key(namespace, upstream_id);
        self.active_probe_specs.insert(
            spec_key.clone(),
            Arc::new(ActiveProbeSpec {
                active: active.clone(),
                tls: tls.clone(),
            }),
        );

        let bounded = bound_probe_targets(targets);
        if bounded.len() < targets.len() {
            tracing::warn!(
                upstream_id = %upstream_id,
                discovered = targets.len(),
                capped = bounded.len(),
                max = MAX_TARGETS_PER_UPSTREAM,
                "capping active health-check probes for discovered targets"
            );
        }

        let new_keys = probe_target_identity_keys(bounded);
        if self
            .upstream_probe_target_keys
            .get(&spec_key)
            .is_some_and(|entry| entry.value() == &new_keys)
            && self.active_probe_upstreams.contains_key(&spec_key)
        {
            self.remove_stale_targets(namespace, upstream_id, targets);
            return;
        }

        let _lifecycle = match self.lifecycle_publish_guard.write() {
            Ok(guard) => guard,
            Err(poisoned) => poisoned.into_inner(),
        };
        self.bump_upstream_probe_generation(&spec_key);
        self.abort_upstream_probe_tasks(&spec_key);
        drop(_lifecycle);

        let shutdown_rx = match self.probe_shutdown_rx.lock() {
            Ok(guard) => guard.clone(),
            Err(poisoned) => poisoned.into_inner().clone(),
        };
        let generation = self.task_generation.load(Ordering::Acquire);
        let (handles, aborts) = self.spawn_active_probes_for_upstream(
            namespace,
            upstream_id,
            bounded,
            &active,
            &tls,
            shutdown_rx.as_ref(),
            generation,
        );

        match self.active_check_handles.lock() {
            Ok(mut list) => {
                list.retain(|h| !h.is_finished());
                list.extend(handles);
            }
            Err(poisoned) => {
                let mut list = poisoned.into_inner();
                list.retain(|h| !h.is_finished());
                list.extend(handles);
            }
        }
        match self.active_check_aborts.lock() {
            Ok(mut list) => {
                list.retain(|h| !h.is_finished());
                list.extend(aborts);
            }
            Err(poisoned) => {
                let mut list = poisoned.into_inner();
                list.retain(|h| !h.is_finished());
                list.extend(aborts);
            }
        }

        self.remove_stale_targets(namespace, upstream_id, targets);
    }

    #[allow(clippy::too_many_arguments)]
    fn spawn_active_probes_for_upstream(
        &self,
        namespace: &str,
        upstream_id: &str,
        targets: &[UpstreamTarget],
        active: &ActiveHealthCheck,
        tls: &BackendTlsConfig,
        shutdown_rx: Option<&tokio::sync::watch::Receiver<bool>>,
        generation: u64,
    ) -> (Vec<tokio::task::JoinHandle<()>>, Vec<AbortHandle>) {
        let spec_key = crate::config::db_backend::namespaced_runtime_key(namespace, upstream_id);
        self.active_probe_specs.insert(
            spec_key.clone(),
            Arc::new(ActiveProbeSpec {
                active: active.clone(),
                tls: tls.clone(),
            }),
        );

        let gen_cell = self
            .upstream_probe_generation
            .entry(spec_key.clone())
            .or_insert_with(|| Arc::new(AtomicU64::new(0)))
            .clone();
        let upstream_generation = gen_cell.load(Ordering::Acquire);

        let probe_pins_dial_host = active.use_tls
            && tls.sni.is_some()
            && matches!(active.probe_type, HealthProbeType::Http);
        let upstream_client = if probe_pins_dial_host {
            None
        } else {
            self.build_upstream_health_client(tls, active.use_tls, None)
        };

        let mut new_handles: Vec<tokio::task::JoinHandle<()>> = Vec::with_capacity(targets.len());
        let mut new_aborts: Vec<AbortHandle> = Vec::with_capacity(targets.len());
        for target in targets {
            let target_client = if probe_pins_dial_host {
                self.build_upstream_health_client(tls, active.use_tls, Some(target.host.as_str()))
            } else {
                upstream_client.clone()
            };
            let start = ActiveCheckStartParams {
                target,
                upstream_namespace: namespace,
                upstream_id,
                shutdown_rx,
                generation,
                upstream_generation,
                upstream_generation_cell: Arc::clone(&gen_cell),
            };
            let handle = self.start_active_check(start, active, target_client.as_ref(), tls);
            new_aborts.push(handle.abort_handle());
            new_handles.push(handle);
        }

        let new_keys = probe_target_identity_keys(targets);
        if new_aborts.is_empty() {
            match self.upstream_probe_aborts.lock() {
                Ok(mut map) => {
                    map.remove(&spec_key);
                }
                Err(poisoned) => {
                    poisoned.into_inner().remove(&spec_key);
                }
            }
            self.active_probe_upstreams.remove(&spec_key);
            self.upstream_probe_target_keys.remove(&spec_key);
            return (new_handles, new_aborts);
        }

        match self.upstream_probe_aborts.lock() {
            Ok(mut map) => {
                map.insert(spec_key.clone(), new_aborts.clone());
            }
            Err(poisoned) => {
                poisoned
                    .into_inner()
                    .insert(spec_key.clone(), new_aborts.clone());
            }
        }
        self.active_probe_upstreams.insert(spec_key.clone(), ());
        self.upstream_probe_target_keys.insert(spec_key, new_keys);
        (new_handles, new_aborts)
    }

    fn abort_upstream_probe_tasks(&self, spec_key: &str) {
        let aborted = match self.upstream_probe_aborts.lock() {
            Ok(mut map) => map.remove(spec_key).unwrap_or_default(),
            Err(poisoned) => poisoned.into_inner().remove(spec_key).unwrap_or_default(),
        };
        for handle in aborted {
            handle.abort();
        }
        match self.active_check_aborts.lock() {
            Ok(mut list) => list.retain(|h| !h.is_finished()),
            Err(poisoned) => poisoned.into_inner().retain(|h| !h.is_finished()),
        }
        match self.active_check_handles.lock() {
            Ok(mut list) => list.retain(|h| !h.is_finished()),
            Err(poisoned) => poisoned.into_inner().retain(|h| !h.is_finished()),
        }
    }

    fn bump_upstream_probe_generation(&self, spec_key: &str) {
        self.upstream_probe_generation
            .entry(spec_key.to_string())
            .or_insert_with(|| Arc::new(AtomicU64::new(0)))
            .fetch_add(1, Ordering::AcqRel);
    }

    fn effective_probe_targets(&self, upstream: &Upstream) -> Vec<UpstreamTarget> {
        let live = self
            .lb_cache
            .as_ref()
            .and_then(|cache| cache.get_upstream(&upstream.namespace, &upstream.id));
        let source: &[UpstreamTarget] = match live.as_ref() {
            Some(live) if !live.targets.is_empty() => live.targets.as_slice(),
            _ => &upstream.targets,
        };
        let bounded = bound_probe_targets(source);
        if bounded.len() < source.len() {
            tracing::warn!(
                upstream_id = %upstream.id,
                discovered = source.len(),
                capped = bounded.len(),
                max = MAX_TARGETS_PER_UPSTREAM,
                "capping active health-check probes"
            );
        }
        bounded.to_vec()
    }
}

fn bound_probe_targets(targets: &[UpstreamTarget]) -> &[UpstreamTarget] {
    if targets.len() > MAX_TARGETS_PER_UPSTREAM {
        &targets[..MAX_TARGETS_PER_UPSTREAM]
    } else {
        targets
    }
}

fn probe_target_identity_keys(targets: &[UpstreamTarget]) -> HashSet<String> {
    targets.iter().map(target_host_port_key).collect()
}

fn probe_generation_retired(
    generation_cell: &AtomicU64,
    generation: u64,
    upstream_generation_cell: &AtomicU64,
    upstream_generation: u64,
) -> bool {
    generation_cell.load(Ordering::Acquire) != generation
        || upstream_generation_cell.load(Ordering::Acquire) != upstream_generation
}

impl HealthChecker {
    /// Get or create the per-proxy passive health state.
    ///
    /// Fast-path: `get()` with a thread-local `namespace|id` key (zero allocation
    /// beyond the reusable buffer, read lock). Cold-path: `entry()` with owned
    /// `String` (one allocation, write lock) — only on the first request from a
    /// new proxy identity.
    fn get_proxy_state(&self, namespace: &str, proxy_id: &str) -> Arc<ProxyHealthState> {
        PASSIVE_PROXY_KEY_BUF.with(|buf| {
            let mut key = buf.borrow_mut();
            crate::config::db_backend::write_namespaced_runtime_key(&mut key, namespace, proxy_id);
            if let Some(existing) = self.passive_health.get(key.as_str()) {
                return existing.value().clone();
            }
            self.passive_health
                .entry(key.clone())
                .or_insert_with(|| Arc::new(ProxyHealthState::new()))
                .clone()
        })
    }

    /// Read-only per-proxy passive health state, or `None` when the proxy has no
    /// recorded passive state yet.
    ///
    /// Unlike [`get_proxy_state`](Self::get_proxy_state) this never inserts, so
    /// dispatch-time health context construction cannot create empty partitions
    /// for proxies that have never reported a response. Zero allocation beyond
    /// the reusable thread-local key buffer; the returned `Arc` is cloned out so
    /// the buffer borrow is released before the caller uses it.
    pub(crate) fn passive_state(
        &self,
        namespace: &str,
        proxy_id: &str,
    ) -> Option<Arc<ProxyHealthState>> {
        PASSIVE_PROXY_KEY_BUF.with(|buf| {
            let mut key = buf.borrow_mut();
            crate::config::db_backend::write_namespaced_runtime_key(&mut key, namespace, proxy_id);
            self.passive_health
                .get(key.as_str())
                .map(|entry| entry.value().clone())
        })
    }

    /// Report a response from a proxied request (passive health checking).
    ///
    /// Writes to the per-proxy passive health state via the two-level index:
    /// `namespace|proxy_id → ProxyHealthState → host:port`. This ensures proxy A's
    /// failures cannot affect proxy B's health view, even when both proxies
    /// share the same upstream — including across namespaces.
    ///
    /// `upstream_id` is recorded on new ejections so automatic / success-based
    /// recovery can reset least-latency state for the owning balancer without
    /// scanning unrelated proxies by host:port.
    #[allow(clippy::too_many_arguments)]
    pub fn report_response(
        &self,
        namespace: &str,
        proxy_id: &str,
        upstream_id: &str,
        target: &UpstreamTarget,
        status_code: u16,
        connection_error: bool,
        passive_config: Option<&PassiveHealthCheck>,
    ) {
        let config = match passive_config {
            Some(c) => c,
            None => return,
        };

        let proxy_state = self.get_proxy_state(namespace, proxy_id);

        // Format "host:port" into a thread-local buffer to avoid a String
        // allocation on every proxied response. DashMap lookups use &str
        // (zero-alloc hot path); only DashMap inserts (rare cold path) clone.
        HP_KEY_BUF.with(|buf| {
            let mut buf = buf.borrow_mut();
            buf.clear();
            write_target_host_port_key(&mut buf, target);

            // Get or create target health state within this proxy's partition.
            // Fast path: get() uses a shared read lock (most requests hit this).
            let state = if let Some(existing) = proxy_state.states.get(buf.as_str()) {
                existing.clone()
            } else {
                // Cold path: first encounter of this target — allocate key for insert.
                proxy_state
                    .states
                    .entry(buf.clone())
                    .or_insert_with(|| Arc::new(TargetHealth::new()))
                    .clone()
            };

            if connection_error || config.unhealthy_status_codes.contains(&status_code) {
                state.consecutive_successes.store(0, Ordering::Relaxed);
                state.consecutive_failures.fetch_add(1, Ordering::Relaxed);

                let now_ms = now_epoch_ms();
                let window_start =
                    now_ms.saturating_sub(config.unhealthy_window_seconds * 1000);
                // Per-target mutex: a handful of integer ops. Replaces the
                // previous DashMap insert + full-window retain + cap-eviction
                // sort on this path. Concurrent reporters for this same
                // target serialize here so the in-window count is exact.
                let failures_in_window = {
                    let mut ring = state.lock_recent_failures();
                    ring.record(now_ms, window_start)
                } as u32;

                if failures_in_window >= config.unhealthy_threshold
                    && !proxy_state.unhealthy.contains_key(buf.as_str())
                {
                    warn!(
                        "Passive health check: marking target {} as unhealthy for proxy {} ({} failures in {}s window)",
                        buf.as_str(), proxy_id, failures_in_window, config.unhealthy_window_seconds
                    );
                    // Cold path: threshold breach — allocate key for insert.
                    // Capture the effective policy's recovery deadline on the
                    // entry itself so reloads / other proxies cannot change it.
                    proxy_state.unhealthy.insert(
                        buf.clone(),
                        PassiveEjection::from_policy(
                            upstream_id,
                            target,
                            config.healthy_after_seconds,
                            now_epoch_ms(),
                        ),
                    );
                }
            } else {
                let failures = state.consecutive_failures.load(Ordering::Relaxed);
                state.consecutive_successes.fetch_add(1, Ordering::Relaxed);
                if failures > 0 {
                    state.consecutive_failures.store(0, Ordering::Relaxed);
                }

                if proxy_state.unhealthy.contains_key(buf.as_str()) {
                    let successes = state.consecutive_successes.load(Ordering::Relaxed);
                    if successes >= 1 {
                        info!(
                            "Passive health check: marking target {} as healthy again for proxy {}",
                            buf.as_str(), proxy_id
                        );
                        if let Some((_, ejection)) = proxy_state.unhealthy.remove(buf.as_str()) {
                            state.lock_recent_failures().clear();
                            self.reset_latency_after_passive_recovery(
                                namespace,
                                &ejection.upstream_id,
                                target,
                            );
                        }
                    }
                }
            }
        });
    }

    /// Remove health state for targets no longer in the active target list.
    ///
    /// Called from the service discovery loop after `update_targets()` to
    /// prevent unbounded growth of the health DashMaps when targets are
    /// dynamically removed. This runs in a background task, NOT on the
    /// proxy hot path.
    pub fn remove_stale_targets(
        &self,
        namespace: &str,
        upstream_id: &str,
        current_targets: &[UpstreamTarget],
    ) {
        // Active: exact key match on "namespace|upstream_id::host:port".
        // Only filter entries belonging to THIS upstream (prefix match) —
        // other upstreams' entries must be preserved.
        let upstream_key =
            crate::config::db_backend::namespaced_runtime_key(namespace, upstream_id);
        let active_keys: std::collections::HashSet<String> = current_targets
            .iter()
            .map(|t| target_key(&upstream_key, t))
            .collect();
        self.active_unhealthy_targets.retain(|key, _| {
            key.split_once("::")
                .map(|(key_upstream_id, _)| {
                    key_upstream_id != upstream_key.as_str() || active_keys.contains(key)
                })
                .unwrap_or(true)
        });
        self.active_target_states.retain(|key, _| {
            key.split_once("::")
                .map(|(key_upstream_id, _)| {
                    key_upstream_id != upstream_key.as_str() || active_keys.contains(key)
                })
                .unwrap_or(true)
        });

        // Passive health is NOT cleaned here. Passive state is keyed by
        // proxy_id → host:port, and this method only knows about a single
        // upstream — it cannot determine which proxies reference this
        // upstream, so filtering all proxies' inner maps against this
        // upstream's target set would incorrectly delete passive health
        // entries for targets belonging to other upstreams. Passive health
        // is cleaned by `prune_removed_proxies()` when proxies are deleted,
        // by `remove_stale_passive_targets_for_proxy()` when the caller knows
        // which proxies reference this upstream, and by the passive recovery
        // timer for individual target entries.
    }

    /// Remove passive health entries for one proxy whose current upstream
    /// target set changed.
    ///
    /// Passive state is partitioned by proxy (`proxy_id -> host:port`), so a
    /// single-upstream caller must identify the referencing proxy before
    /// pruning. This preserves unrelated proxies that point at other upstreams
    /// while still bounding stale inner-map growth when service discovery or
    /// config reloads remove targets from an upstream.
    pub fn remove_stale_passive_targets_for_proxy(
        &self,
        namespace: &str,
        proxy_id: &str,
        current_targets: &[UpstreamTarget],
    ) {
        let key = crate::config::db_backend::namespaced_runtime_key(namespace, proxy_id);
        let Some(proxy_state) = self.passive_health.get(&key).map(|entry| entry.clone()) else {
            return;
        };
        let current_keys: std::collections::HashSet<String> =
            current_targets.iter().map(target_host_port_key).collect();
        proxy_state
            .unhealthy
            .retain(|key, _| current_keys.contains(key));
        proxy_state
            .states
            .retain(|key, _| current_keys.contains(key));
    }

    /// Remove passive health state for proxies that have been deleted from
    /// config. Prevents the outer `passive_health` DashMap from growing
    /// unboundedly as proxies are added and removed over the gateway's lifetime.
    /// Called from `ProxyState::update_config()` alongside circuit breaker pruning.
    pub fn prune_removed_proxies(
        &self,
        removed_proxies: &[crate::config::db_backend::NamespacedResourceId],
    ) {
        for resource in removed_proxies {
            let key = resource.runtime_key();
            self.passive_health.remove(&key);
        }
    }

    /// Return the number of currently-spawned probe / passive-recovery tasks.
    ///
    /// Counts unfinished AbortHandles so drained (taken) startup generations
    /// remain visible until reload/drop aborts them. This includes both active
    /// probe tasks (one per upstream target with an `active` health check
    /// configured) and the optional gateway-scoped passive recovery scanner
    /// (at most one, when any effective passive policy has a non-zero
    /// `healthy_after_seconds` or a pending auto-recover ejection remains).
    /// Intended for tests
    /// asserting that [`Self::start_with_shutdown`] /
    /// [`Self::restart_with_shutdown`] correctly aborts old handles and
    /// spawns new ones on config reload — including the production
    /// `start → take → restart` ownership sequence. The runtime crate itself
    /// doesn't call it (the gateway uses operator metrics like
    /// `active_unhealthy_targets` for observability), hence
    /// `#[allow(dead_code)]`.
    #[doc(hidden)]
    #[allow(dead_code)]
    pub fn active_task_count(&self) -> usize {
        match self.active_check_aborts.lock() {
            Ok(g) => g.iter().filter(|a| !a.is_finished()).count(),
            Err(p) => p.into_inner().iter().filter(|a| !a.is_finished()).count(),
        }
    }

    /// Test-only view of whether one active-probe state key is present.
    #[doc(hidden)]
    #[allow(dead_code)]
    pub fn has_active_target_state_for_test(&self, key: &str) -> bool {
        self.active_target_states.contains_key(key)
    }

    /// Test-only count of timestamps stored in the per-target passive
    /// failure ring. Used to prove the hard cap holds after many failures.
    #[doc(hidden)]
    #[allow(dead_code)]
    pub fn passive_recent_failure_len_for_test(
        &self,
        namespace: &str,
        proxy_id: &str,
        host_port: &str,
    ) -> usize {
        let Some(proxy_state) = self.passive_state(namespace, proxy_id) else {
            return 0;
        };
        let Some(state) = proxy_state.states.get(host_port) else {
            return 0;
        };
        state.lock_recent_failures().len()
    }

    /// Test-only allocated slot count of the per-target passive failure ring.
    /// Zero before the first failure; the cap after the ring is sized.
    #[doc(hidden)]
    #[allow(dead_code)]
    pub fn passive_recent_failure_slot_cap_for_test(
        &self,
        namespace: &str,
        proxy_id: &str,
        host_port: &str,
    ) -> usize {
        let Some(proxy_state) = self.passive_state(namespace, proxy_id) else {
            return 0;
        };
        let Some(state) = proxy_state.states.get(host_port) else {
            return 0;
        };
        state.lock_recent_failures().slot_capacity()
    }

    /// Run one passive-recovery pass: clear every auto-recoverable ejection
    /// whose stored deadline has elapsed, scoped to that proxy entry only.
    ///
    /// Deterministic external unit tests backdate `recover_at_ms` and call this
    /// without sleeping the background scanner. The scanner itself invokes
    /// [`recover_due_passive_ejections_inner`] on cloned `Arc`s because the
    /// spawned task cannot hold `&self`. The binary target still treats unused
    /// `pub` methods as dead code, hence the narrow allow (same pattern as
    /// [`Self::active_task_count`]).
    #[doc(hidden)]
    #[allow(dead_code)]
    pub fn recover_due_passive_ejections(&self) {
        recover_due_passive_ejections_inner(&self.passive_health, self.lb_cache.as_ref());
    }

    fn reset_latency_after_passive_recovery(
        &self,
        namespace: &str,
        upstream_id: &str,
        target: &UpstreamTarget,
    ) {
        reset_latency_after_passive_recovery_inner(
            self.lb_cache.as_ref(),
            namespace,
            upstream_id,
            target,
        );
    }

    /// Start a background scanner that restores passively-ejected targets
    /// once each entry's stored recovery deadline elapses.
    fn start_passive_recovery_scanner(
        &self,
        shutdown_rx: Option<tokio::sync::watch::Receiver<bool>>,
        generation: u64,
    ) -> tokio::task::JoinHandle<()> {
        let passive_health = self.passive_health.clone();
        let lb_cache = self.lb_cache.clone();
        let recovery_generation = Arc::clone(&self.passive_recovery_generation);
        let lifecycle_publish_guard = Arc::clone(&self.lifecycle_publish_guard);
        // Fixed 1s tick: per-entry deadlines already encode the effective
        // healthy_after_seconds, so the scanner does not need a per-upstream
        // interval and must not outlive reload/shutdown ownership.
        let check_interval = Duration::from_secs(1);

        tokio::spawn(async move {
            let mut timer = tokio::time::interval(check_interval);
            // Skip the immediate first tick so a brand-new ejection is not
            // scanned before its deadline can possibly be due.
            timer.tick().await;

            loop {
                if recovery_generation.load(Ordering::Acquire) != generation {
                    info!(
                        "Passive recovery scanner exiting after reload generation fence (was {generation})"
                    );
                    return;
                }

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

                {
                    let _publish_guard = match lifecycle_publish_guard.read() {
                        Ok(guard) => guard,
                        Err(poisoned) => poisoned.into_inner(),
                    };
                    if recovery_generation.load(Ordering::Acquire) != generation {
                        info!(
                            "Passive recovery scanner exiting after reload generation fence (was {generation})"
                        );
                        return;
                    }
                    recover_due_passive_ejections_inner(&passive_health, lb_cache.as_ref());
                }
            }
        })
    }

    /// Build a per-upstream HTTP client with the upstream's TLS config.
    /// Falls back to global TLS settings when the upstream doesn't specify them.
    ///
    /// HTTPS probes (`use_tls = true`) ALWAYS route through the TLS-aware
    /// builder so the trust store is constructed in-house from the upstream's
    /// CA / global CA / webpki roots — never the default client (which only
    /// applies when the operator has explicitly opted into no-verify, and
    /// even then only on plaintext probes by construction). HTTP probes can
    /// safely reuse the default client.
    ///
    /// Returns `None` when client construction fails closed; HTTP probes then
    /// report unhealthy without dialing (TCP/UDP/gRPC probes do not need this
    /// client).
    ///
    /// `dial_host_pin` is `Some(target_host)` only for a `backend_tls_sni`
    /// HTTPS probe, which is therefore built per TARGET rather than per upstream
    /// (the pin names the one target this client may dial). See
    /// [`build_health_check_client_with_tls`].
    fn build_upstream_health_client(
        &self,
        tls_config: &BackendTlsConfig,
        use_tls: bool,
        dial_host_pin: Option<&str>,
    ) -> Option<Arc<reqwest::Client>> {
        let has_tls_config = tls_config.client_cert_path.is_some()
            || tls_config.client_key_path.is_some()
            || tls_config.server_ca_cert_path.is_some()
            || !tls_config.san_allow_list.is_empty()
            || !tls_config.verify_server_cert
            || self.global_tls_ca_bundle_path.is_some()
            || self.global_backend_tls_client_cert_path.is_some()
            || self.global_tls_no_verify;

        if !use_tls && !has_tls_config {
            return self.default_http_client.clone();
        }

        accept_health_check_client(
            build_health_check_client_with_tls(
                &self.pool_config,
                self.dns_cache.clone(),
                tls_config,
                &self.global_tls_ca_bundle_path,
                HealthCheckClientIdentityPaths {
                    cert: &self.global_backend_tls_client_cert_path,
                    key: &self.global_backend_tls_client_key_path,
                },
                self.global_tls_no_verify,
                dial_host_pin,
            ),
            "upstream TLS health-check HTTP client",
        )
    }

    /// Start an active health check background task for a target.
    fn start_active_check(
        &self,
        start: ActiveCheckStartParams<'_>,
        config: &ActiveHealthCheck,
        upstream_client: Option<&Arc<reqwest::Client>>,
        tls_config: &BackendTlsConfig,
    ) -> tokio::task::JoinHandle<()> {
        // Destructure by value: taking `start` by reference would bind
        // `target` as `&&UpstreamTarget`, and `target.clone()` below would
        // then clone the *reference* into the `'static` spawn (E0521).
        let ActiveCheckStartParams {
            target,
            upstream_namespace,
            upstream_id,
            shutdown_rx,
            generation,
            upstream_generation,
            upstream_generation_cell,
        } = start;
        let shutdown_rx = shutdown_rx.cloned();
        let upstream_key =
            crate::config::db_backend::namespaced_runtime_key(upstream_namespace, upstream_id);
        let key = target_key(&upstream_key, target);
        let interval = Duration::from_secs(config.interval_seconds);
        let timeout = Duration::from_millis(config.timeout_ms);
        let healthy_threshold = config.healthy_threshold;
        let unhealthy_threshold = config.unhealthy_threshold;
        let unhealthy_targets = self.active_unhealthy_targets.clone();
        let target_states = self.active_target_states.clone();
        let task_generation = self.task_generation.clone();
        let lifecycle_publish_guard = Arc::clone(&self.lifecycle_publish_guard);

        let probe_type = config.probe_type;
        let host = target.host.clone();
        let port = target.port;
        let healthy_status_codes = config.healthy_status_codes.clone();
        let client = upstream_client.cloned();
        let scheme = if config.use_tls { "https" } else { "http" };
        // A backend covered by `backend_tls_sni` presents a certificate for the
        // OVERRIDE, not for the target host, so the probe must offer the same
        // server name request traffic does or it reports a healthy backend as
        // unhealthy. reqwest derives the server name from the URL host and has
        // no per-request hook, so the override goes in the probe URL's authority
        // — exactly as on the proxy path
        // (`crate::proxy::backend_tls_sni_reqwest_dial`) — while the client
        // built for this target pins its resolver to the real target host, so
        // the override is never resolved and the socket cannot leave that
        // target's egress-screened candidate set. That client is also restricted
        // to HTTP/1.1 (`build_health_check_client_with_tls`), which is what makes
        // the explicit `Host` below authoritative: over HTTP/2 the authority
        // would be rebuilt from the URI, i.e. from the server name.
        let probe_server_name = if config.use_tls {
            tls_config.sni.as_deref()
        } else {
            None
        };
        let url = format_probe_url(
            scheme,
            probe_server_name.unwrap_or(host.as_str()),
            port,
            &config.http_path,
        );
        // ...and the backend must still see its OWN authority, never the server
        // name. Sent explicitly because hyper-util only derives `Host` from the
        // URL when the request carries none, and PRESERVED because the SNI probe
        // client speaks HTTP/1.1 only — `Host` is a header there, not a value the
        // transport recomputes from the URI. Absent (and byte-identical to
        // today's probe) whenever no override is configured.
        let host_header = probe_server_name.map(|_| probe_authority(scheme, &host, port));
        let udp_payload = config
            .udp_probe_payload
            .as_deref()
            .and_then(|hex| hex::decode(hex).ok())
            .unwrap_or_default();
        let use_tls = config.use_tls;
        let grpc_service_name = config.grpc_service_name.clone().unwrap_or_default();

        let probe_target = target.clone();
        let lb_cache = self.lb_cache.clone();
        let upstream_namespace_owned = upstream_namespace.to_owned();
        let upstream_id_owned = upstream_id.to_owned();
        let probe_tls_config = tls_config.clone();
        let probe_global_ca = self.global_tls_ca_bundle_path.clone();
        let probe_global_cert = self.global_backend_tls_client_cert_path.clone();
        let probe_global_key = self.global_backend_tls_client_key_path.clone();
        let probe_no_verify = self.global_tls_no_verify;
        // Screen the probe target against the backend egress policy so active
        // health checks never dial a denied address (an SSRF/port-scan vector via
        // the health probe). reqwest skips the resolver for IP literals and the
        // TCP/UDP/gRPC probes connect directly, so screen the literal here; the
        // DNS cache (below) additionally screens hostnames for the non-HTTP
        // probes (HTTP hostnames go through reqwest's DnsCacheResolver).
        let probe_egress_policy = self.dns_cache.as_ref().map(|c| c.backend_allow_ips());
        let probe_dns_cache = self.dns_cache.clone();

        tokio::spawn(async move {
            let is_retired = || {
                probe_generation_retired(
                    task_generation.as_ref(),
                    generation,
                    upstream_generation_cell.as_ref(),
                    upstream_generation,
                )
            };
            let mut timer = tokio::time::interval(interval);

            loop {
                if is_retired() {
                    return;
                }
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
                if is_retired() {
                    return;
                }

                let probe_start = std::time::Instant::now();
                // A target whose literal IP is denied by the egress policy is
                // never dialed; treat it as a failed probe (unhealthy) instead.
                let egress_denied = probe_egress_policy.as_ref().and_then(|policy| {
                    // Screen with the parser that matches how THIS probe dials.
                    // HTTP probes go through reqwest (URL canonicalization), so a
                    // non-canonical literal like `2852039166` must be screened as
                    // an IP. TCP/UDP/gRPC probes resolve through `DnsCache`
                    // (canonical literals only; everything else is real DNS, then
                    // the resolved address is policy-checked), so use the
                    // canonical-only parser — otherwise a numeric service name such
                    // as `111` is wrongly canonicalized to `0.0.0.111` and the
                    // target is marked unhealthy without ever resolving.
                    let literal = match probe_type {
                        HealthProbeType::Http => crate::config::types::egress_literal_ip(&host),
                        HealthProbeType::Tcp | HealthProbeType::Udp | HealthProbeType::Grpc => {
                            crate::config::types::stream_literal_ip(&host)
                        }
                    };
                    literal.and_then(|ip| policy.deny_reason(&ip))
                });
                let probe_outcome = if let Some(reason) = egress_denied {
                    warn!(
                        target = %host,
                        reason = %reason,
                        "Health probe target blocked by backend egress policy; marking unhealthy without dialing"
                    );
                    ProbeOutcome::failure(format!("egress policy denied: {reason}"))
                } else {
                    match probe_type {
                        HealthProbeType::Http => {
                            // reqwest routes hostnames through the
                            // DnsCacheResolver (which screens); literal IPs skip
                            // it and were screened by `egress_denied` above.
                            match client.as_ref() {
                                Some(client) => {
                                    http_probe(
                                        client,
                                        &url,
                                        host_header.as_deref(),
                                        timeout,
                                        &healthy_status_codes,
                                    )
                                    .await
                                }
                                None => {
                                    warn!(
                                        target = %host,
                                        "HTTP health probe fail-closed: health-check client unavailable"
                                    );
                                    ProbeOutcome::failure(
                                        "health-check HTTP client construction failed",
                                    )
                                }
                            }
                        }
                        // TCP/UDP/gRPC dial directly (TcpStream/UdpSocket/tonic),
                        // bypassing the DnsCacheResolver, so resolve through the
                        // gateway DNS cache here to enforce the egress policy on
                        // the complete answer set. Each candidate was screened
                        // independently; direct probes rotate and fail over within
                        // the configured probe timeout. gRPC keeps the original
                        // hostname for TLS SNI and HTTP/2 authority.
                        HealthProbeType::Tcp | HealthProbeType::Udp | HealthProbeType::Grpc => {
                            // Strip URI brackets: `DnsCache` only
                            // recognizes UNbracketed IP literals, so a bracketed
                            // IPv6 target (`[::1]`, `[fd00::1]`) would fall through
                            // to DNS and flap unhealthy. Bare hostnames pass through
                            // unchanged (the legacy tcp/udp probe handled brackets
                            // via `format_probe_socket_addr`).
                            let resolve_host = host
                                .strip_prefix('[')
                                .and_then(|h| h.strip_suffix(']'))
                                .unwrap_or(host.as_str());
                            match probe_dns_cache.as_ref() {
                                Some(cache) => {
                                    match cache.resolve_candidates(resolve_host, None, None).await {
                                        Ok(candidates) => match probe_type {
                                            HealthProbeType::Tcp => {
                                                tcp_probe_candidates(&candidates, port, timeout)
                                                    .await
                                            }
                                            HealthProbeType::Udp => {
                                                udp_probe_candidates(
                                                    &candidates,
                                                    port,
                                                    timeout,
                                                    &udp_payload,
                                                )
                                                .await
                                            }
                                            _ => {
                                                grpc_probe_candidates(
                                                    &candidates,
                                                    &host,
                                                    port,
                                                    timeout,
                                                    use_tls,
                                                    &grpc_service_name,
                                                    &probe_tls_config,
                                                    probe_global_ca.as_deref(),
                                                    probe_global_cert.as_deref(),
                                                    probe_global_key.as_deref(),
                                                    probe_no_verify,
                                                )
                                                .await
                                            }
                                        },
                                        Err(e) => {
                                            warn!(
                                                target = %host,
                                                error = %e,
                                                "Health probe target blocked or unresolvable by backend egress policy; marking unhealthy"
                                            );
                                            ProbeOutcome::failure(format!(
                                                "dns resolve or egress screen failed: {e}"
                                            ))
                                        }
                                    }
                                }
                                // No DNS cache wired (e.g. tests): fall back to the
                                // legacy direct dial.
                                None => match probe_type {
                                    HealthProbeType::Tcp => tcp_probe(&host, port, timeout).await,
                                    HealthProbeType::Udp => {
                                        udp_probe(&host, port, timeout, &udp_payload).await
                                    }
                                    _ => {
                                        // No DNS cache to screen/pin an IP; dial the
                                        // hostname directly (legacy behavior).
                                        grpc_probe(
                                            &host,
                                            &host,
                                            port,
                                            timeout,
                                            use_tls,
                                            &grpc_service_name,
                                            &probe_tls_config,
                                            probe_global_ca.as_deref(),
                                            probe_global_cert.as_deref(),
                                            probe_global_key.as_deref(),
                                            probe_no_verify,
                                        )
                                        .await
                                    }
                                },
                            }
                        }
                    }
                };

                // Serialize publication against reload generation rollover,
                // then re-check under the guard. This closes the
                // check-then-mutate window for shared counters, maps, and the
                // latency cache; a retired probe cannot publish after reload.
                let _publish_guard = match lifecycle_publish_guard.read() {
                    Ok(guard) => guard,
                    Err(poisoned) => poisoned.into_inner(),
                };
                if is_retired() {
                    return;
                }

                // Defer entry until after the probe and re-check generation
                // while holding the DashMap entry lock, so prune cannot race a
                // pre-insert fence and leave a resurrected removed-target key.
                let state = {
                    use dashmap::mapref::entry::Entry;
                    match target_states.entry(key.clone()) {
                        Entry::Occupied(entry) => {
                            if is_retired() {
                                return;
                            }
                            entry.get().clone()
                        }
                        Entry::Vacant(entry) => {
                            if is_retired() {
                                return;
                            }
                            entry.insert(Arc::new(TargetHealth::new())).clone()
                        }
                    }
                };

                if is_retired() {
                    return;
                }

                if probe_outcome.success {
                    state.consecutive_failures.store(0, Ordering::Relaxed);
                    let successes = state.consecutive_successes.fetch_add(1, Ordering::Relaxed) + 1;

                    // Shared TargetHealth / LB cache intentionally survive reload.
                    // Bail before side effects if this probe retired mid-mutation so
                    // a drained generation cannot publish latency or clear marks
                    // under replacement policy.
                    if is_retired() {
                        return;
                    }

                    if let Some(ref cache) = lb_cache {
                        let latency_us = probe_start.elapsed().as_micros() as u64;
                        cache.record_latency(
                            &upstream_namespace_owned,
                            &upstream_id_owned,
                            &probe_target,
                            latency_us,
                        );
                    }

                    if successes >= healthy_threshold {
                        // Only clear unhealthy under the still-current
                        // generation so a retired success cannot drop a mark
                        // the replacement probe just wrote.
                        let removed = unhealthy_targets.remove_if(&key, |_, _| !is_retired());
                        if removed.is_some() {
                            info!(
                                "Active health check: target {} is healthy ({:?} probe)",
                                key, probe_type
                            );
                            if let Some(ref cache) = lb_cache {
                                cache.reset_recovered_target_latency(
                                    &upstream_namespace_owned,
                                    &upstream_id_owned,
                                    &probe_target,
                                );
                            }
                        }
                    }
                } else {
                    state.consecutive_successes.store(0, Ordering::Relaxed);
                    let failures = state.consecutive_failures.fetch_add(1, Ordering::Relaxed) + 1;

                    if is_retired() {
                        return;
                    }

                    if failures >= unhealthy_threshold {
                        let elapsed_ms = probe_start.elapsed().as_millis() as u64;
                        let last_failure =
                            probe_outcome.failure.as_deref().unwrap_or("probe failed");
                        // Insert under the entry lock with only a generation
                        // re-check in between — never log while holding the
                        // DashMap shard (logging can stall concurrent prune /
                        // probe ownership on the same shard).
                        let inserted = {
                            use dashmap::mapref::entry::Entry;
                            match unhealthy_targets.entry(key.clone()) {
                                Entry::Occupied(_) => false,
                                Entry::Vacant(entry) => {
                                    if is_retired() {
                                        return;
                                    }
                                    entry.insert(now_epoch_ms());
                                    true
                                }
                            }
                        };
                        if inserted {
                            warn!(
                                target = %key,
                                probe_type = ?probe_type,
                                failures = failures,
                                unhealthy_threshold = unhealthy_threshold,
                                elapsed_ms = elapsed_ms,
                                last_failure = %last_failure,
                                "Active health check: target is unhealthy"
                            );
                        }
                    }
                }
                drop(_publish_guard);
            }
        })
    }
}

impl Drop for HealthChecker {
    fn drop(&mut self) {
        // Best-effort: if the lock is poisoned (panic during start), still
        // abort whatever handles we can recover so spawned tasks don't leak
        // past the HealthChecker. `get_mut` avoids a lock entirely since
        // we have unique access via `&mut self` in Drop.
        //
        // Abort via AbortHandles first so generations whose JoinHandles were
        // drained by `take_active_check_handles` are still cancelled.
        let aborts = self.active_check_aborts.get_mut();
        let aborts = match aborts {
            Ok(v) => v,
            Err(poisoned) => poisoned.into_inner(),
        };
        for abort in aborts.iter() {
            abort.abort();
        }
        let handles = self.active_check_handles.get_mut();
        let handles = match handles {
            Ok(v) => v,
            Err(poisoned) => poisoned.into_inner(),
        };
        for handle in handles.iter() {
            handle.abort();
        }
        let upstream_aborts = self.upstream_probe_aborts.get_mut();
        let upstream_aborts = match upstream_aborts {
            Ok(map) => map,
            Err(poisoned) => poisoned.into_inner(),
        };
        for abort in upstream_aborts.values().flatten() {
            abort.abort();
        }
    }
}

struct ProbeOutcome {
    success: bool,
    failure: Option<String>,
}

impl ProbeOutcome {
    fn success() -> Self {
        Self {
            success: true,
            failure: None,
        }
    }

    fn failure(reason: impl Into<String>) -> Self {
        Self {
            success: false,
            failure: Some(reason.into()),
        }
    }
}

fn sanitized_http_probe_failure(error: &reqwest::Error) -> &'static str {
    if error.is_timeout() {
        "http request timed out"
    } else if error.is_connect() {
        "http connection failed"
    } else if error.is_builder() {
        "http request build failed"
    } else if error.is_redirect() {
        "http redirect failed"
    } else if error.is_body() {
        "http request body failed"
    } else if error.is_decode() {
        "http response decode failed"
    } else if error.is_request() {
        "http request failed"
    } else {
        "http probe failed"
    }
}

/// HTTP health probe — sends a GET request and checks the status code.
///
/// `host_header` is set only when the URL authority is a backend TLS server-name
/// override, so the backend still receives its own authority rather than the
/// server name.
async fn http_probe(
    client: &reqwest::Client,
    url: &str,
    host_header: Option<&str>,
    timeout: Duration,
    healthy_status_codes: &[u16],
) -> ProbeOutcome {
    let mut request = client.get(url).timeout(timeout);
    if let Some(host_header) = host_header {
        request = request.header(reqwest::header::HOST, host_header);
    }
    match request.send().await {
        Ok(resp) => {
            let status = resp.status().as_u16();
            let healthy = if healthy_status_codes.is_empty() {
                (200..300).contains(&status)
            } else {
                healthy_status_codes.contains(&status)
            };
            if healthy {
                ProbeOutcome::success()
            } else {
                ProbeOutcome::failure(format!("http status {status}"))
            }
        }
        Err(e) => {
            let failure = sanitized_http_probe_failure(&e);
            if crate::retry::is_port_exhaustion(&e) {
                tracing::error!(failure = failure, "HTTP health probe: PORT EXHAUSTION");
            } else {
                debug!(failure = failure, "HTTP health probe failed");
            }
            ProbeOutcome::failure(failure)
        }
    }
}

/// TCP health probe — attempts a TCP connection within the timeout.
async fn tcp_probe(host: &str, port: u16, timeout: Duration) -> ProbeOutcome {
    let addr = format_probe_socket_addr(host, port);
    match tokio::time::timeout(timeout, tokio::net::TcpStream::connect(&addr)).await {
        Ok(Ok(_stream)) => ProbeOutcome::success(),
        Ok(Err(e)) => {
            if crate::retry::is_port_exhaustion(&e) {
                tracing::error!(
                    "TCP health probe: PORT EXHAUSTION connecting to {}: {}",
                    addr,
                    e
                );
            } else {
                debug!("TCP health probe connection failed for {}: {}", addr, e);
            }
            ProbeOutcome::failure(format!("tcp connect failed: {e}"))
        }
        Err(_) => {
            debug!("TCP health probe timed out for {}", addr);
            ProbeOutcome::failure("tcp connect timed out")
        }
    }
}

async fn tcp_probe_candidates(
    candidates: &crate::dns::ResolvedAddresses,
    port: u16,
    timeout: Duration,
) -> ProbeOutcome {
    match crate::dns::connect_candidates(candidates, port, timeout, |addr| {
        tokio::net::TcpStream::connect(addr)
    })
    .await
    {
        Ok((_stream, _addr)) => ProbeOutcome::success(),
        Err(crate::dns::CandidateConnectError::Failed { source, .. }) => {
            ProbeOutcome::failure(format!("tcp connect failed: {source}"))
        }
        Err(crate::dns::CandidateConnectError::TimedOut { .. }) => {
            ProbeOutcome::failure("tcp connect timed out")
        }
    }
}

/// UDP health probe — sends a payload and waits for any response within the timeout.
async fn udp_probe(host: &str, port: u16, timeout: Duration, payload: &[u8]) -> ProbeOutcome {
    let addr = format_probe_socket_addr(host, port);
    let bind_addr = if host.parse::<std::net::Ipv6Addr>().is_ok() {
        "[::]:0"
    } else {
        "0.0.0.0:0"
    };
    let socket = match tokio::net::UdpSocket::bind(bind_addr).await {
        Ok(s) => s,
        Err(e) => {
            debug!("UDP health probe: failed to bind socket: {}", e);
            return ProbeOutcome::failure(format!("udp bind failed: {e}"));
        }
    };

    if let Err(e) = socket.connect(&addr).await {
        debug!("UDP health probe: failed to connect to {}: {}", addr, e);
        return ProbeOutcome::failure(format!("udp connect failed: {e}"));
    }

    let data = if payload.is_empty() { &[0u8] } else { payload };
    if let Err(e) = socket.send(data).await {
        debug!("UDP health probe: failed to send to {}: {}", addr, e);
        return ProbeOutcome::failure(format!("udp send failed: {e}"));
    }

    let mut buf = [0u8; 1];
    match tokio::time::timeout(timeout, socket.recv(&mut buf)).await {
        Ok(Ok(_)) => ProbeOutcome::success(),
        Ok(Err(e)) => {
            debug!("UDP health probe: recv error from {}: {}", addr, e);
            ProbeOutcome::failure(format!("udp recv failed: {e}"))
        }
        Err(_) => {
            debug!("UDP health probe timed out for {}", addr);
            ProbeOutcome::failure("udp recv timed out")
        }
    }
}

async fn udp_probe_candidates(
    candidates: &crate::dns::ResolvedAddresses,
    port: u16,
    timeout: Duration,
    payload: &[u8],
) -> ProbeOutcome {
    let data = if payload.is_empty() { &[0u8] } else { payload };
    match crate::dns::connect_candidates(candidates, port, timeout, |addr| async move {
        let bind_addr = if addr.is_ipv6() {
            "[::]:0"
        } else {
            "0.0.0.0:0"
        };
        let socket = tokio::net::UdpSocket::bind(bind_addr).await?;
        socket.connect(addr).await?;
        socket.send(data).await?;
        let mut buf = [0u8; 1];
        socket.recv(&mut buf).await?;
        Ok::<(), std::io::Error>(())
    })
    .await
    {
        Ok(((), _addr)) => ProbeOutcome::success(),
        Err(crate::dns::CandidateConnectError::Failed { source, .. }) => {
            ProbeOutcome::failure(format!("udp probe failed: {source}"))
        }
        Err(crate::dns::CandidateConnectError::TimedOut { .. }) => {
            ProbeOutcome::failure("udp probe timed out")
        }
    }
}

#[allow(clippy::too_many_arguments)]
async fn grpc_probe_candidates(
    candidates: &crate::dns::ResolvedAddresses,
    host: &str,
    port: u16,
    timeout: Duration,
    use_tls: bool,
    service_name: &str,
    tls_config: &BackendTlsConfig,
    global_ca_path: Option<&str>,
    global_cert_path: Option<&str>,
    global_key_path: Option<&str>,
    global_no_verify: bool,
) -> ProbeOutcome {
    match crate::dns::connect_candidates(candidates, port, timeout, |addr| {
        let dial_addr = addr.ip().to_string();
        async move {
            let outcome = grpc_probe(
                host,
                &dial_addr,
                port,
                timeout,
                use_tls,
                service_name,
                tls_config,
                global_ca_path,
                global_cert_path,
                global_key_path,
                global_no_verify,
            )
            .await;
            if outcome.success {
                Ok(())
            } else {
                Err(outcome
                    .failure
                    .unwrap_or_else(|| "grpc probe failed".to_string()))
            }
        }
    })
    .await
    {
        Ok(((), _addr)) => ProbeOutcome::success(),
        Err(crate::dns::CandidateConnectError::Failed { source, .. }) => {
            ProbeOutcome::failure(source)
        }
        Err(crate::dns::CandidateConnectError::TimedOut { .. }) => {
            ProbeOutcome::failure("grpc connect timed out")
        }
    }
}

/// gRPC health probe — performs a unary grpc.health.v1.Health/Check RPC.
///
/// When `use_tls` is true, the probe configures TLS using the upstream's
/// `BackendTlsConfig` (client certs, CA bundle, verify flag) so that health
/// checks authenticate to backends the same way proxy traffic does.
#[allow(clippy::too_many_arguments)]
async fn grpc_probe(
    host: &str,
    dial_addr: &str,
    port: u16,
    timeout: Duration,
    use_tls: bool,
    service_name: &str,
    tls_config: &BackendTlsConfig,
    global_ca_path: Option<&str>,
    global_cert_path: Option<&str>,
    global_key_path: Option<&str>,
    global_no_verify: bool,
) -> ProbeOutcome {
    let scheme = if use_tls { "https" } else { "http" };
    // Dial the pre-screened address (`dial_addr` = the resolved IP from the
    // health loop) so tonic does not re-resolve `host` and risk a split-DNS /
    // rebind to a denied address between the egress screen and the dial. TLS
    // SNI and the cert hostname still come from `host` (see `domain_name`).
    let (endpoint_url, origin_url) = grpc_probe_urls(scheme, host, dial_addr, port);

    let endpoint = match tonic::transport::Endpoint::from_shared(endpoint_url) {
        Ok(ep) => {
            let ep = ep.timeout(timeout).connect_timeout(timeout);
            // We dial `dial_addr` (the screened IP), but tonic otherwise derives
            // the HTTP/2 `:authority` from that URI. Override the origin with the
            // original host so a virtual-hosted / H2-multiplexed backend routes
            // the health RPC the same as normal proxy traffic to the hostname.
            match origin_url.parse::<http::Uri>() {
                Ok(origin) => ep.origin(origin),
                Err(_) => ep,
            }
        }
        Err(e) => {
            debug!(
                "gRPC health probe: invalid endpoint for {}:{}: {}",
                host, port, e
            );
            return ProbeOutcome::failure(format!("grpc invalid endpoint: {e}"));
        }
    };

    let skip_verify = use_tls
        && (!tls_config.verify_server_cert
            || (global_no_verify && tls_config.allows_global_no_verify()));

    if skip_verify && !tls_config.san_allow_list.is_empty() {
        warn!(
            san_allow_list_entries = tls_config.san_allow_list.len(),
            "gRPC health probe: backend TLS SAN allow-list is configured but \
             certificate verification is disabled; SAN allow-list will not be enforced"
        );
    }

    // When skip_verify is true, tonic's ClientTlsConfig doesn't support disabling
    // cert verification. Build a rustls ClientConfig directly with NoVerifier
    // (same pattern as grpc_proxy.rs) and use connect_with_connector.
    // Identity-pinned backends (`backend_tls_san_allow_list`) take the same
    // rustls connector path so the probe reuses `SanAllowListVerifier`.
    let channel = if skip_verify {
        match build_grpc_probe_channel_no_verify(
            &endpoint,
            host,
            timeout,
            tls_config,
            global_ca_path,
            global_cert_path,
            global_key_path,
        )
        .await
        {
            Ok(ch) => ch,
            Err(e) => {
                let is_exhaustion = crate::retry::is_port_exhaustion(e.as_ref())
                    || crate::retry::is_port_exhaustion_message(&e.to_string());
                if is_exhaustion {
                    tracing::error!(
                        "gRPC health probe: PORT EXHAUSTION connecting to {}:{}: {}",
                        host,
                        port,
                        e
                    );
                } else {
                    debug!(
                        "gRPC health probe: connect failed for {}:{}: {}",
                        host, port, e
                    );
                }
                return ProbeOutcome::failure(format!("grpc connect failed: {e}"));
            }
        }
    } else if use_tls && !tls_config.san_allow_list.is_empty() {
        match build_grpc_probe_channel_san_pinned(
            &endpoint,
            host,
            timeout,
            tls_config,
            global_ca_path,
            global_cert_path,
            global_key_path,
        )
        .await
        {
            Ok(ch) => ch,
            Err(e) => {
                let is_exhaustion = crate::retry::is_port_exhaustion(e.as_ref())
                    || crate::retry::is_port_exhaustion_message(&e.to_string());
                if is_exhaustion {
                    tracing::error!(
                        "gRPC health probe: PORT EXHAUSTION connecting to {}:{}: {}",
                        host,
                        port,
                        e
                    );
                } else {
                    debug!(
                        "gRPC health probe: SAN-pinned connect failed for {}:{}: {}",
                        host, port, e
                    );
                }
                return ProbeOutcome::failure(format!("grpc connect failed: {e}"));
            }
        }
    } else if use_tls {
        // SNI / cert hostname is the EFFECTIVE backend TLS identity — the
        // configured `backend_tls_sni` override when present, else the original
        // `host` — even though we dial the pre-screened IP via `dial_addr`. The
        // `origin`/authority above deliberately keeps the real target so the
        // backend still sees its own `:authority`, exactly as for proxy traffic.
        // rustls/tonic want a BARE SNI host, not a URI-bracketed IPv6 literal
        // (`[fd00::1]`), which `probe_tls_server_name` strips.
        let sni_host = probe_tls_server_name(tls_config, host);
        let mut tonic_tls = tonic::transport::ClientTlsConfig::new().domain_name(sni_host);

        // Load CA certs (upstream → global → system roots). `system://` resolves
        // to `None` here so the probe pins the built-in roots and deliberately
        // skips the cluster-global bundle.
        if let Some(ca_path) = tls_config.effective_ca_source(global_ca_path) {
            match load_probe_tls_material(ca_path, MaterialKind::CaBundle, "gRPC health probe CA") {
                Ok(pem) => {
                    let cert = tonic::transport::Certificate::from_pem(pem);
                    tonic_tls = tonic_tls.ca_certificate(cert);
                }
                Err(e) => {
                    // The configured CA is the sole trust anchor. Proceeding
                    // without it leaves tonic on its default roots, so a
                    // publicly-trusted certificate would pass a probe for a
                    // backend pinned to a private CA. Fail the probe instead.
                    return ProbeOutcome::failure(format!(
                        "gRPC health probe: configured backend CA is the sole trust anchor but could not be loaded ({e})"
                    ));
                }
            }
        } else {
            tonic_tls = tonic_tls.with_enabled_roots();
        }

        // Load mTLS client identity. Fail-closed, matching the no-verify gRPC
        // branch (`build_grpc_probe_channel_no_verify`) and the HTTP probe: a
        // configured identity that cannot be loaded must fail the probe rather
        // than silently downgrade it to an anonymous handshake the backend
        // answers differently than it answers proxy traffic. Errors carry the
        // loader's source identifier and failure class, never key material.
        let cert_path = tls_config.client_cert_path.as_deref().or(global_cert_path);
        let key_path = tls_config.client_key_path.as_deref().or(global_key_path);
        match (cert_path, key_path) {
            (Some(cert_path), Some(key_path)) => {
                let pair = load_probe_tls_material(
                    cert_path,
                    MaterialKind::Cert,
                    "gRPC health probe client cert",
                )
                .and_then(|cert_pem| {
                    load_probe_tls_material(
                        key_path,
                        MaterialKind::Key,
                        "gRPC health probe client key",
                    )
                    .map(|key_pem| (cert_pem, key_pem))
                });
                match pair {
                    Ok((cert_pem, key_pem)) => {
                        let identity = tonic::transport::Identity::from_pem(cert_pem, key_pem);
                        tonic_tls = tonic_tls.identity(identity);
                    }
                    Err(e) => {
                        return ProbeOutcome::failure(format!(
                            "gRPC health probe: configured backend mTLS client identity could not be loaded ({e})"
                        ));
                    }
                }
            }
            (Some(_), None) | (None, Some(_)) => {
                return ProbeOutcome::failure(
                    "gRPC health probe: backend mTLS client certificate and private key must be configured together"
                        .to_string(),
                );
            }
            (None, None) => {}
        }

        let endpoint = match endpoint.tls_config(tonic_tls) {
            Ok(ep) => ep,
            Err(e) => {
                debug!(
                    "gRPC health probe: TLS config error for {}:{}: {}",
                    host, port, e
                );
                return ProbeOutcome::failure(format!("grpc tls config failed: {e}"));
            }
        };
        match tokio::time::timeout(timeout, endpoint.connect()).await {
            Ok(Ok(ch)) => ch,
            Ok(Err(e)) => {
                let err_ref: &(dyn std::error::Error + 'static) = &e;
                let is_exhaustion = crate::retry::is_port_exhaustion(err_ref)
                    || crate::retry::is_port_exhaustion_message(&e.to_string());
                if is_exhaustion {
                    tracing::error!(
                        "gRPC health probe: PORT EXHAUSTION connecting to {}:{}: {}",
                        host,
                        port,
                        e
                    );
                } else {
                    debug!(
                        "gRPC health probe: connect failed for {}:{}: {}",
                        host, port, e
                    );
                }
                return ProbeOutcome::failure(format!("grpc connect failed: {e}"));
            }
            Err(_) => {
                debug!("gRPC health probe: connect timed out for {}:{}", host, port);
                return ProbeOutcome::failure("grpc connect timed out");
            }
        }
    } else {
        match tokio::time::timeout(timeout, endpoint.connect()).await {
            Ok(Ok(ch)) => ch,
            Ok(Err(e)) => {
                let err_ref: &(dyn std::error::Error + 'static) = &e;
                let is_exhaustion = crate::retry::is_port_exhaustion(err_ref)
                    || crate::retry::is_port_exhaustion_message(&e.to_string());
                if is_exhaustion {
                    tracing::error!(
                        "gRPC health probe: PORT EXHAUSTION connecting to {}:{}: {}",
                        host,
                        port,
                        e
                    );
                } else {
                    debug!(
                        "gRPC health probe: connect failed for {}:{}: {}",
                        host, port, e
                    );
                }
                return ProbeOutcome::failure(format!("grpc connect failed: {e}"));
            }
            Err(_) => {
                debug!("gRPC health probe: connect timed out for {}:{}", host, port);
                return ProbeOutcome::failure("grpc connect timed out");
            }
        }
    };

    let mut client = grpc_health_v1::health_client::HealthClient::new(channel);
    let request = tonic::Request::new(grpc_health_v1::HealthCheckRequest {
        service: service_name.to_string(),
    });

    match tokio::time::timeout(timeout, client.check(request)).await {
        Ok(Ok(response)) => {
            let status = response.into_inner().status;
            if status == grpc_health_v1::health_check_response::ServingStatus::Serving as i32 {
                ProbeOutcome::success()
            } else {
                ProbeOutcome::failure(format!("grpc serving status {status}"))
            }
        }
        Ok(Err(e)) => {
            debug!("gRPC health probe: RPC failed for {}:{}: {}", host, port, e);
            ProbeOutcome::failure(format!("grpc rpc failed: {e}"))
        }
        Err(_) => {
            debug!("gRPC health probe: RPC timed out for {}:{}", host, port);
            ProbeOutcome::failure("grpc rpc timed out")
        }
    }
}

/// Build a tonic gRPC channel with TLS verification disabled (NoVerifier).
///
/// Tonic's `ClientTlsConfig` doesn't expose a skip-verify API, so we build
/// the rustls `ClientConfig` directly (same pattern as `grpc_proxy.rs`) and
/// use `connect_with_connector` to provide a custom TLS connector.
#[allow(clippy::too_many_arguments)]
async fn build_grpc_probe_channel_no_verify(
    endpoint: &tonic::transport::Endpoint,
    host: &str,
    timeout: Duration,
    tls_config: &BackendTlsConfig,
    global_ca_path: Option<&str>,
    global_cert_path: Option<&str>,
    global_key_path: Option<&str>,
) -> Result<tonic::transport::Channel, Box<dyn std::error::Error + Send + Sync>> {
    use rustls::pki_types::ServerName;
    use tokio_rustls::TlsConnector;

    // Build root cert store (still needed for mTLS client auth builder)
    let ca_path = tls_config.effective_ca_source(global_ca_path);
    let root_store = if let Some(ca_path) = ca_path {
        load_probe_tls_root_store(ca_path, "gRPC health probe CA").map_err(std::io::Error::other)?
    } else {
        rustls::RootCertStore::from_iter(webpki_roots::TLS_SERVER_ROOTS.iter().cloned())
    };

    // Build client config with optional mTLS
    let cert_path = tls_config.client_cert_path.as_deref().or(global_cert_path);
    let key_path = tls_config.client_key_path.as_deref().or(global_key_path);
    let builder = rustls::ClientConfig::builder().with_root_certificates(root_store);
    let mut client_config = match (cert_path, key_path) {
        (Some(cert_path), Some(key_path)) => {
            let certs = load_probe_tls_certificates(
                cert_path,
                MaterialKind::Cert,
                "gRPC health probe client cert",
            )
            .map_err(std::io::Error::other)?;
            let key_source = CertSource::parse(key_path, MaterialKind::Key);
            let key_material =
                load_material_blocking(&key_source, MaterialKind::Key).map_err(|error| {
                    std::io::Error::other(format!("gRPC health probe client key: {error}"))
                })?;
            let key = crate::tls::parse_pem_private_key(
                key_material.bytes.expose_secret(),
                "gRPC health probe client key",
                &key_material.display_source_id,
            )
            .map_err(std::io::Error::other)?;
            builder.with_client_auth_cert(certs, key)?
        }
        (None, None) => builder.with_no_client_auth(),
        _ => {
            return Err(std::io::Error::other(
                "gRPC health probe mTLS client certificate and private key must be configured together",
            )
            .into());
        }
    };

    // Disable server cert verification
    client_config
        .dangerous()
        .set_certificate_verifier(Arc::new(crate::tls::NoVerifier));
    client_config.alpn_protocols = vec![b"h2".to_vec()];

    let tls_connector = TlsConnector::from(Arc::new(client_config));
    // Same effective backend TLS identity the verifying branch uses: the
    // configured `backend_tls_sni` override when present, else the target host.
    // Only the server NAME changes — the socket still goes to the pre-screened
    // address in `uri`, and tonic's `origin` still carries the real authority.
    let host_owned = probe_tls_server_name(tls_config, host).to_string();

    let connector = tower::service_fn(move |uri: http::Uri| {
        let tls_connector = tls_connector.clone();
        let host = host_owned.clone();
        async move {
            let addr = format_probe_socket_addr(
                uri.host().unwrap_or("127.0.0.1"),
                uri.port_u16().unwrap_or(443),
            );
            let tcp = tokio::net::TcpStream::connect(&addr).await?;
            // Fail closed on an unusable server name rather than handshaking
            // with whatever rustls would otherwise infer.
            let server_name = ServerName::try_from(host)
                .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidInput, e))?;
            let tls = tls_connector.connect(server_name, tcp).await?;
            Ok::<_, std::io::Error>(hyper_util::rt::TokioIo::new(tls))
        }
    });

    let channel =
        tokio::time::timeout(timeout, endpoint.connect_with_connector(connector)).await??;
    Ok(channel)
}

/// Build a tonic gRPC channel that verifies the peer with the same
/// [`SanAllowListVerifier`] the data path uses.
#[allow(clippy::too_many_arguments)]
async fn build_grpc_probe_channel_san_pinned(
    endpoint: &tonic::transport::Endpoint,
    host: &str,
    timeout: Duration,
    tls_config: &BackendTlsConfig,
    global_ca_path: Option<&str>,
    global_cert_path: Option<&str>,
    global_key_path: Option<&str>,
) -> Result<tonic::transport::Channel, Box<dyn std::error::Error + Send + Sync>> {
    use rustls::pki_types::ServerName;
    use tokio_rustls::TlsConnector;

    let verifier = match build_probe_server_verifier(tls_config, global_ca_path) {
        Ok(ProbeServerVerifier::SanAllowList(verifier)) => verifier,
        Ok(ProbeServerVerifier::WebPki) => {
            return Err(std::io::Error::other(
                "gRPC health probe SAN allow-list was empty after verifier build",
            )
            .into());
        }
        Err(error) => return Err(std::io::Error::other(error.to_string()).into()),
    };

    let cert_path = tls_config.client_cert_path.as_deref().or(global_cert_path);
    let key_path = tls_config.client_key_path.as_deref().or(global_key_path);
    let builder =
        backend_client_config_builder(None).map_err(|e| std::io::Error::other(e.to_string()))?;
    let builder = builder
        .dangerous()
        .with_custom_certificate_verifier(verifier);
    let mut client_config = match (cert_path, key_path) {
        (Some(cert_path), Some(key_path)) => {
            let certs = load_probe_tls_certificates(
                cert_path,
                MaterialKind::Cert,
                "gRPC health probe client cert",
            )
            .map_err(std::io::Error::other)?;
            let key_source = CertSource::parse(key_path, MaterialKind::Key);
            let key_material =
                load_material_blocking(&key_source, MaterialKind::Key).map_err(|error| {
                    std::io::Error::other(format!("gRPC health probe client key: {error}"))
                })?;
            let key = crate::tls::parse_pem_private_key(
                key_material.bytes.expose_secret(),
                "gRPC health probe client key",
                &key_material.display_source_id,
            )
            .map_err(std::io::Error::other)?;
            builder.with_client_auth_cert(certs, key)?
        }
        (None, None) => builder.with_no_client_auth(),
        _ => {
            return Err(std::io::Error::other(
                "gRPC health probe mTLS client certificate and private key must be configured together",
            )
            .into());
        }
    };
    client_config.alpn_protocols = vec![b"h2".to_vec()];
    crate::tls::apply_client_session_resumption(&mut client_config, None);

    let tls_connector = TlsConnector::from(Arc::new(client_config));
    let host_owned = probe_tls_server_name(tls_config, host).to_string();

    let connector = tower::service_fn(move |uri: http::Uri| {
        let tls_connector = tls_connector.clone();
        let host = host_owned.clone();
        async move {
            let addr = format_probe_socket_addr(
                uri.host().unwrap_or("127.0.0.1"),
                uri.port_u16().unwrap_or(443),
            );
            let tcp = tokio::net::TcpStream::connect(&addr).await?;
            let server_name = ServerName::try_from(host)
                .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidInput, e))?;
            let tls = tls_connector.connect(server_name, tcp).await?;
            Ok::<_, std::io::Error>(hyper_util::rt::TokioIo::new(tls))
        }
    });

    let channel =
        tokio::time::timeout(timeout, endpoint.connect_with_connector(connector)).await??;
    Ok(channel)
}

fn build_health_check_client(
    pool_config: &PoolConfig,
    dns_cache: Option<DnsCache>,
    no_verify: bool,
) -> Result<reqwest::Client, reqwest::Error> {
    if no_verify {
        warn!("health_check: TLS certificate verification DISABLED (FERRUM_TLS_NO_VERIFY=true)");
    }

    let mut builder = reqwest::Client::builder()
        .no_proxy()
        .pool_max_idle_per_host(pool_config.max_idle_per_host)
        .pool_idle_timeout(Duration::from_secs(pool_config.idle_timeout_seconds))
        // Do not follow redirects on health probes: a 3xx from an allowed host to
        // an IP literal (e.g. http://169.254.169.254/) skips the DnsCacheResolver
        // and the one-time egress screen, bouncing the probe to a denied address.
        .redirect(reqwest::redirect::Policy::none())
        .danger_accept_invalid_certs(no_verify);

    if let Some(dns_cache) = dns_cache.clone() {
        let resolver = DnsCacheResolver::new(dns_cache);
        builder = builder.dns_resolver(Arc::new(resolver));
    }

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
        Ok(client) => Ok(client),
        Err(e) => {
            tracing::error!(
                "Failed to build health check HTTP client: {}. \
                 Falling back to a minimal DNS-cached client (pool/TLS/keepalive settings will not apply).",
                e
            );
            build_dns_cached_fallback_client(dns_cache, "health check")
        }
    }
}

/// Why a health-check HTTP client could not be produced.
///
/// Split from a bare `reqwest::Error` because the two failures are not the same
/// event: a builder failure is degraded-but-neutral, while an unusable
/// exclusive CA is a *trust policy* failure that must never be downgraded into
/// "build something that verifies against different roots".
#[derive(Debug)]
enum HealthCheckClientError {
    /// `reqwest` refused to build the client.
    Build(reqwest::Error),
    /// A configured exclusive backend CA could not be loaded or parsed.
    ///
    /// Ferrum's documented CA exclusivity (`docs/backend_mtls.md`) makes a
    /// configured CA the *sole* trust anchor. Continuing without it would build
    /// a probe client that trusts the public webpki roots instead, so a backend
    /// presenting any publicly-trusted certificate would pass health checks for
    /// an upstream pinned to a private CA — the probe would then keep marking a
    /// target healthy that proxy traffic correctly refuses.
    ///
    /// Reachable through Gateway API `BackendTLSPolicy`: a `caCertificateRefs`
    /// Secret projects a `k8s://…#ca.crt` source whose load happens here, not
    /// at translation time, and can fail afterwards (Secret deleted, RBAC
    /// revoked, API server unavailable).
    ExclusiveTrustUnavailable(String),
    /// A configured backend mTLS client identity could not be loaded or parsed.
    ///
    /// A health probe must authenticate to the backend exactly as proxy traffic
    /// does. Continuing without the configured certificate/key produces an
    /// *anonymous* probe: a backend enforcing client authentication rejects it
    /// (so the probe reports a failure the operator cannot explain from the
    /// backend's perspective), and a backend that merely *prefers* client certs
    /// answers the anonymous probe successfully while refusing real proxy
    /// traffic — marking a target healthy that no request can actually use.
    ///
    /// A half-configured pair (cert without key, or key without cert) is the
    /// same fault: it is an operator error that must surface, never an implicit
    /// "authenticate anonymously".
    ClientIdentityUnavailable(String),
    /// A `backend_tls_sni` probe was requested but the dial cannot be pinned to
    /// the real target, because this checker has no DNS cache wired.
    ///
    /// The probe URL's host is the overridden TLS server name, so without the
    /// pin reqwest would resolve THAT name and dial wherever it points —
    /// off the egress-screened candidate set for the target being probed.
    DialPinUnavailable,
    /// `backend_tls_san_allow_list` could not be installed on the probe
    /// verifier (invalid entries or the inner webpki verifier failed to build).
    /// Fail closed: a probe that cannot pin identity must not dial unpinned.
    SanPinningUnavailable(String),
}

impl std::fmt::Display for HealthCheckClientError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Build(error) => write!(f, "{error}"),
            // `details` carries a source identifier and loader message, never
            // material: `MaterialError` reports `display_source_id`, so no PEM
            // or secret bytes reach this string.
            Self::ExclusiveTrustUnavailable(details) => write!(
                f,
                "configured backend CA is the sole trust anchor but could not be used ({details})"
            ),
            // Same disclosure contract as above: `details` names the source
            // identifier and failure class, never key or certificate material.
            Self::ClientIdentityUnavailable(details) => write!(
                f,
                "configured backend mTLS client identity could not be used ({details})"
            ),
            Self::DialPinUnavailable => write!(
                f,
                "backend TLS server-name override requires a DNS cache to pin the probe dial to the real target"
            ),
            Self::SanPinningUnavailable(details) => write!(
                f,
                "backend TLS SAN allow-list could not be applied ({details})"
            ),
        }
    }
}

impl From<reqwest::Error> for HealthCheckClientError {
    fn from(error: reqwest::Error) -> Self {
        Self::Build(error)
    }
}

/// Build a minimal `reqwest::Client` that still uses the gateway's DNS cache.
///
/// Used as a fallback when a fully-configured builder fails (e.g., due to
/// invalid TLS material). Keeps the DNS cache attached so health probes /
/// plugin calls do not silently fall through to system DNS — every probe
/// would otherwise burn an ephemeral port through a fresh OS resolver.
///
/// If even this minimal builder fails, retry a bare no-proxy/no-redirect client.
/// If that also fails, return `Err` so callers fail closed (HTTP probes report
/// unhealthy) rather than panicking or falling back to the ambient-proxy-aware
/// default constructor.
fn build_dns_cached_fallback_client(
    dns_cache: Option<DnsCache>,
    context: &'static str,
) -> Result<reqwest::Client, reqwest::Error> {
    // Carry the no-redirect policy into the degraded fallback too: a 3xx to an
    // IP literal would otherwise skip the DnsCacheResolver and the egress screen,
    // bouncing the probe to a denied address (same rationale as the primary
    // builders).
    let mut builder = reqwest::Client::builder()
        .no_proxy()
        .redirect(reqwest::redirect::Policy::none());
    if let Some(dns_cache) = dns_cache {
        let resolver = DnsCacheResolver::new(dns_cache);
        builder = builder.dns_resolver(Arc::new(resolver));
    }
    match builder.build() {
        Ok(client) => Ok(client),
        Err(e) => {
            tracing::error!(
                "Failed to build minimal DNS-cached fallback {} client: {}. \
                 Retrying a redirect-disabled minimal client as a last resort — DNS will bypass the gateway cache.",
                context,
                e
            );
            // Last resort: still disable redirects and ambient proxies. Never
            // fall back to the ambient-proxy-aware default constructor and never
            // panic — propagate the error so HTTP probes fail closed.
            match reqwest::Client::builder()
                .no_proxy()
                .redirect(reqwest::redirect::Policy::none())
                .build()
            {
                Ok(client) => Ok(client),
                Err(e2) => {
                    tracing::error!(
                        "Failed to build fail-closed minimal {} client: {}. \
                         HTTP health probes will fail closed without a usable client.",
                        context,
                        e2
                    );
                    Err(e2)
                }
            }
        }
    }
}

/// Accept a built health-check client or log and return `None` so probes fail closed.
fn accept_health_check_client(
    result: Result<reqwest::Client, HealthCheckClientError>,
    context: &str,
) -> Option<Arc<reqwest::Client>> {
    match result {
        Ok(client) => Some(Arc::new(client)),
        Err(e) => {
            tracing::error!(
                "Fail-closed: {context} unavailable ({e}); affected HTTP health probes will report unhealthy"
            );
            None
        }
    }
}

/// Install the probe's dial identity on a health-check client builder: the DNS
/// resolver, and — for a `backend_tls_sni` probe — the HTTP/1.1-only
/// restriction that keeps its explicit `Host` header authoritative.
///
/// Both halves are one decision. A pinned probe's URL host is the overridden TLS
/// server name, so:
///
/// * the resolver must answer every name by resolving the REAL target, or
///   reqwest would resolve the override and dial wherever it points; and
/// * ALPN must exclude `h2`, or HTTP/2 would rebuild `:authority` from that same
///   URL and show the backend the override instead of the target being probed.
///
/// Split out of [`build_health_check_client_with_tls`] so the pairing can be
/// asserted on a `ClientBuilder` (whose `Debug` reports `http1_only`) rather
/// than only observed on the wire.
fn apply_probe_dial_identity(
    builder: reqwest::ClientBuilder,
    dns_cache: Option<DnsCache>,
    dial_host_pin: Option<&str>,
) -> Result<reqwest::ClientBuilder, HealthCheckClientError> {
    match (dns_cache, dial_host_pin) {
        (Some(dns_cache), Some(pin)) => {
            let resolver = DnsCacheResolver::with_hostname_pin(dns_cache, pin);
            Ok(builder.dns_resolver(Arc::new(resolver)).http1_only())
        }
        (Some(dns_cache), None) => {
            let resolver = DnsCacheResolver::new(dns_cache);
            Ok(builder.dns_resolver(Arc::new(resolver)))
        }
        // A server-name override with no DNS cache to pin would let reqwest's
        // own resolver look up the SNI hostname and dial wherever it points.
        // That is the escape this must never allow, so fail closed instead.
        (None, Some(_)) => Err(HealthCheckClientError::DialPinUnavailable),
        (None, None) => Ok(builder),
    }
}

/// Global client-certificate and private-key paths are one atomic identity.
/// Bundling them keeps the TLS client builder's argument list below clippy's
/// complexity threshold and makes it harder for call sites to swap the pair.
#[derive(Clone, Copy)]
struct HealthCheckClientIdentityPaths<'a> {
    cert: &'a Option<String>,
    key: &'a Option<String>,
}

/// Build the probe server verifier using the same wrapping the data path uses.
fn build_probe_server_verifier(
    tls_config: &BackendTlsConfig,
    global_ca_path: Option<&str>,
) -> Result<ProbeServerVerifier, HealthCheckClientError> {
    let root_store = if let Some(ca_path) = tls_config.effective_ca_source(global_ca_path) {
        load_probe_tls_root_store(ca_path, "Health check CA")
            .map_err(HealthCheckClientError::ExclusiveTrustUnavailable)?
    } else {
        rustls::RootCertStore::from_iter(webpki_roots::TLS_SERVER_ROOTS.iter().cloned())
    };
    let inner = build_server_verifier_with_crls(root_store, &[]).map_err(|e| {
        HealthCheckClientError::SanPinningUnavailable(format!(
            "failed to build probe server verifier: {e}"
        ))
    })?;
    if tls_config.san_allow_list.is_empty() {
        Ok(ProbeServerVerifier::WebPki)
    } else {
        let wrapped = SanAllowListVerifier::new(inner, tls_config.san_allow_list.clone())
            .map_err(|e| HealthCheckClientError::SanPinningUnavailable(e.to_string()))?;
        Ok(ProbeServerVerifier::SanAllowList(Arc::new(wrapped)))
    }
}

fn load_probe_rustls_client_auth(
    tls_config: &BackendTlsConfig,
    global_identity: HealthCheckClientIdentityPaths<'_>,
) -> Result<ProbeRustlsClientAuth, HealthCheckClientError> {
    let cert_path = tls_config
        .client_cert_path
        .as_ref()
        .or(global_identity.cert.as_ref());
    let key_path = tls_config
        .client_key_path
        .as_ref()
        .or(global_identity.key.as_ref());
    match (cert_path, key_path) {
        (Some(cert_path), Some(key_path)) => {
            let certs = load_probe_tls_certificates(
                cert_path,
                MaterialKind::Cert,
                "Health check client cert",
            )
            .map_err(HealthCheckClientError::ClientIdentityUnavailable)?;
            let key_source = CertSource::parse(key_path, MaterialKind::Key);
            let key_material =
                load_material_blocking(&key_source, MaterialKind::Key).map_err(|error| {
                    HealthCheckClientError::ClientIdentityUnavailable(error.to_string())
                })?;
            let key = crate::tls::parse_pem_private_key(
                key_material.bytes.expose_secret(),
                "Health check client key",
                &key_material.display_source_id,
            )
            .map_err(|e| HealthCheckClientError::ClientIdentityUnavailable(e.to_string()))?;
            Ok(ProbeRustlsClientAuth::Materialized { certs, key })
        }
        (Some(_), None) => Err(HealthCheckClientError::ClientIdentityUnavailable(
            "a backend mTLS client certificate is configured without a matching private key"
                .to_string(),
        )),
        (None, Some(_)) => Err(HealthCheckClientError::ClientIdentityUnavailable(
            "a backend mTLS private key is configured without a matching client certificate"
                .to_string(),
        )),
        (None, None) => Ok(ProbeRustlsClientAuth::None),
    }
}

enum ProbeRustlsClientAuth {
    None,
    Materialized {
        certs: Vec<rustls::pki_types::CertificateDer<'static>>,
        key: rustls::pki_types::PrivateKeyDer<'static>,
    },
}

/// HTTP probe client that installs [`SanAllowListVerifier`] via preconfigured
/// rustls. Empty-list probes keep the reqwest `tls_certs_only` path.
fn build_health_check_client_with_san_pinning(
    pool_config: &PoolConfig,
    dns_cache: Option<DnsCache>,
    tls_config: &BackendTlsConfig,
    global_ca_path: &Option<String>,
    global_identity: HealthCheckClientIdentityPaths<'_>,
    dial_host_pin: Option<&str>,
) -> Result<reqwest::Client, HealthCheckClientError> {
    let verifier = match build_probe_server_verifier(tls_config, global_ca_path.as_deref())? {
        ProbeServerVerifier::SanAllowList(verifier) => verifier,
        ProbeServerVerifier::WebPki => {
            return Err(HealthCheckClientError::SanPinningUnavailable(
                "SAN allow-list was empty after verifier build".to_string(),
            ));
        }
    };
    let client_auth = load_probe_rustls_client_auth(tls_config, global_identity)?;
    let builder = backend_client_config_builder(None)
        .map_err(|e| HealthCheckClientError::SanPinningUnavailable(e.to_string()))?;
    let builder = builder
        .dangerous()
        .with_custom_certificate_verifier(verifier);
    let mut rustls_config = match client_auth {
        ProbeRustlsClientAuth::None => builder.with_no_client_auth(),
        ProbeRustlsClientAuth::Materialized { certs, key } => {
            builder.with_client_auth_cert(certs, key).map_err(|e| {
                HealthCheckClientError::ClientIdentityUnavailable(format!(
                    "invalid client certificate/key pair: {e}"
                ))
            })?
        }
    };
    if dial_host_pin.is_some() || !pool_config.enable_http2 {
        rustls_config.alpn_protocols = vec![b"http/1.1".to_vec()];
    } else {
        rustls_config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
    }
    crate::tls::apply_client_session_resumption(&mut rustls_config, None);

    let mut builder = reqwest::Client::builder()
        .no_proxy()
        .pool_max_idle_per_host(pool_config.max_idle_per_host)
        .pool_idle_timeout(Duration::from_secs(pool_config.idle_timeout_seconds))
        .redirect(reqwest::redirect::Policy::none())
        .use_preconfigured_tls(rustls_config);
    builder = apply_probe_dial_identity(builder, dns_cache, dial_host_pin)?;
    if pool_config.enable_http_keep_alive {
        builder = builder.tcp_keepalive(Duration::from_secs(pool_config.tcp_keepalive_seconds));
    }
    if pool_config.enable_http2 && dial_host_pin.is_none() {
        builder = builder
            .http2_keep_alive_interval(Duration::from_secs(
                pool_config.http2_keep_alive_interval_seconds,
            ))
            .http2_keep_alive_timeout(Duration::from_secs(
                pool_config.http2_keep_alive_timeout_seconds,
            ));
    }
    builder.build().map_err(|e| {
        HealthCheckClientError::SanPinningUnavailable(format!(
            "SAN-pinned health-check HTTP client could not be built: {e}"
        ))
    })
}

/// Build a health check HTTP client with upstream-specific TLS configuration.
///
/// Configures the client with the upstream's CA bundle, client cert/key for mTLS,
/// and verify settings — so health probes authenticate the same way proxy traffic does.
///
/// `dial_host_pin` is set only for a `backend_tls_sni` probe, whose URL host is
/// the overridden TLS server name (reqwest derives the rustls server name from
/// the URL and exposes no per-request hook — the same constraint the proxy path
/// documents on `crate::proxy::backend_tls_sni_reqwest_dial`). The pin makes the
/// resolver answer every name by resolving the REAL target instead, so the
/// server name is never itself resolved and the socket cannot leave the
/// egress-screened candidate set for that target.
///
/// A pinned client is additionally restricted to **HTTP/1.1**, for the same
/// reason the proxy's SNI dial is. The probe carries the real target authority
/// in an explicit `Host` header, which hyper-util preserves on HTTP/1.1 — but
/// HTTP/2 derives `:authority` from the URI, i.e. from the server name, so an
/// h2-negotiated probe would present the OVERRIDE as its authority and measure
/// a request the backend never receives from proxy traffic. `http1_only()` is
/// load-bearing here rather than a hint: the empty-SAN builder does not use
/// `use_preconfigured_tls`, so reqwest itself derives the client's ALPN from
/// the version preference and advertises `http/1.1` alone (see
/// `vendor/reqwest-0.13.3-ferrum-patched/src/async_impl/client.rs`), which means
/// an h2-capable backend cannot select h2 on this connection. Identity-pinned
/// probes (`backend_tls_san_allow_list`) take the preconfigured-rustls path so
/// they can install [`SanAllowListVerifier`]; their ALPN is set on that config.
/// Probes without an override keep the default h2-capable client: their URL
/// already names the real target, so there is no authority to lose.
///
/// The resolver + ALPN half of that contract lives in
/// [`apply_probe_dial_identity`] so it can be asserted directly.
fn build_health_check_client_with_tls(
    pool_config: &PoolConfig,
    dns_cache: Option<DnsCache>,
    tls_config: &BackendTlsConfig,
    global_ca_path: &Option<String>,
    global_identity: HealthCheckClientIdentityPaths<'_>,
    global_no_verify: bool,
    dial_host_pin: Option<&str>,
) -> Result<reqwest::Client, HealthCheckClientError> {
    let skip_verify = !tls_config.verify_server_cert
        || (global_no_verify && tls_config.allows_global_no_verify());

    if skip_verify && !tls_config.san_allow_list.is_empty() {
        warn!(
            san_allow_list_entries = tls_config.san_allow_list.len(),
            "Health-check probe: backend TLS SAN allow-list is configured but \
             certificate verification is disabled; SAN allow-list will not be enforced"
        );
    }
    if !skip_verify && !tls_config.san_allow_list.is_empty() {
        return build_health_check_client_with_san_pinning(
            pool_config,
            dns_cache,
            tls_config,
            global_ca_path,
            global_identity,
            dial_host_pin,
        );
    }

    let mut builder = reqwest::Client::builder()
        .no_proxy()
        .pool_max_idle_per_host(pool_config.max_idle_per_host)
        .pool_idle_timeout(Duration::from_secs(pool_config.idle_timeout_seconds))
        // Do not follow redirects on health probes: a 3xx to an IP literal skips
        // the DnsCacheResolver and the egress screen (see build_health_check_client).
        .redirect(reqwest::redirect::Policy::none())
        .danger_accept_invalid_certs(skip_verify);

    builder = apply_probe_dial_identity(builder, dns_cache.clone(), dial_host_pin)?;

    // Load CA bundle (upstream → global → system roots). `system://` resolves to
    // `None` here so the probe pins the built-in roots and deliberately skips
    // the cluster-global bundle.
    let ca_path = tls_config.effective_ca_source(global_ca_path.as_deref());
    if let Some(ca_path) = ca_path {
        // A configured CA is EXCLUSIVE: it replaces the trust store rather than
        // adding to it. So there is no "continue without it" outcome here — a
        // client built after a failed load would verify against the public
        // webpki roots, which is a different (and weaker) trust policy than the
        // one configured. Fail closed instead and let the probe report
        // unhealthy.
        //
        // This holds even when `skip_verify` is set. Explicitly configured
        // material that cannot be loaded or parsed is a *configuration* fault,
        // and the repository's atomic TLS-material invariant says such a fault
        // must surface rather than be absorbed. Reading it as "no-verify makes
        // the CA moot" conflated two independent operator statements — "do not
        // verify the peer" and "here is the trust anchor" — and let a deleted
        // Secret, revoked RBAC, or corrupt `ca.crt` pass silently on exactly the
        // deployments least able to detect it. `skip_verify` still governs
        // *verification*; it does not license ignoring named material.
        //
        // `from_pem_bundle` accepts multi-certificate bundles; a root plus
        // intermediates is the ordinary shape of a Kubernetes `ca.crt`.
        let ca_bundle = load_probe_tls_material(ca_path, MaterialKind::CaBundle, "Health check CA")
            .and_then(|ca_data| {
                reqwest::Certificate::from_pem_bundle(&ca_data)
                    .map_err(|e| format!("Health check CA: failed to parse CA bundle: {e}"))
            })
            .and_then(|certs| {
                // An empty trust store would reject every handshake anyway;
                // reporting it here keeps the cause legible.
                if certs.is_empty() {
                    Err("Health check CA: bundle contains no certificates".to_string())
                } else {
                    Ok(certs)
                }
            });
        match ca_bundle {
            Ok(ca_certs) => {
                // reqwest 0.13: `tls_certs_only` replaces the trust store entirely,
                // matching the project's "CA exclusivity" rule (no webpki mixing
                // when a custom CA is provided).
                builder = builder.tls_certs_only(ca_certs);
            }
            Err(details) => {
                return Err(HealthCheckClientError::ExclusiveTrustUnavailable(details));
            }
        }
    }

    // Load mTLS client identity
    let cert_path = tls_config
        .client_cert_path
        .as_ref()
        .or(global_identity.cert.as_ref());
    let key_path = tls_config
        .client_key_path
        .as_ref()
        .or(global_identity.key.as_ref());
    // A configured backend mTLS identity is mandatory for the probe, exactly as
    // it is for proxy traffic: every failure below is fail-closed rather than
    // warn-and-continue, because an anonymous probe measures a different
    // handshake than the one real requests perform. None of these arms
    // interpolate certificate or key bytes — `load_probe_tls_material` reports
    // through `MaterialError`, which carries `display_source_id` and a failure
    // class only, and `reqwest::Identity::from_pem` errors describe the parse
    // failure, not the input.
    match (cert_path, key_path) {
        (Some(cert_path), Some(key_path)) => {
            let material =
                load_probe_tls_material(cert_path, MaterialKind::Cert, "Health check client cert")
                    .and_then(|cert_data| {
                        load_probe_tls_material(
                            key_path,
                            MaterialKind::Key,
                            "Health check client key",
                        )
                        .map(|key_data| (cert_data, key_data))
                    })
                    .and_then(|(cert_data, key_data)| {
                        let mut combined = cert_data;
                        combined.extend_from_slice(b"\n");
                        combined.extend_from_slice(&key_data);
                        reqwest::Identity::from_pem(&combined).map_err(|e| {
                            format!(
                                "Health check client identity: failed to parse cert/key pair: {e}"
                            )
                        })
                    });
            match material {
                Ok(identity) => {
                    builder = builder.identity(identity);
                }
                Err(details) => {
                    return Err(HealthCheckClientError::ClientIdentityUnavailable(details));
                }
            }
        }
        // A half-configured pair cannot authenticate. Silently skipping it built
        // an anonymous probe for an upstream the operator explicitly gave an
        // identity to, so report the misconfiguration instead.
        (Some(_), None) => {
            return Err(HealthCheckClientError::ClientIdentityUnavailable(
                "a backend mTLS client certificate is configured without a matching private key"
                    .to_string(),
            ));
        }
        (None, Some(_)) => {
            return Err(HealthCheckClientError::ClientIdentityUnavailable(
                "a backend mTLS private key is configured without a matching client certificate"
                    .to_string(),
            ));
        }
        (None, None) => {}
    }

    if pool_config.enable_http_keep_alive {
        builder = builder.tcp_keepalive(Duration::from_secs(pool_config.tcp_keepalive_seconds));
    }

    // An SNI-override probe is HTTP/1.1-only by construction (see above), so the
    // HTTP/2 keepalive settings have nothing to govern on it.
    if pool_config.enable_http2 && dial_host_pin.is_none() {
        builder = builder
            .http2_keep_alive_interval(Duration::from_secs(
                pool_config.http2_keep_alive_interval_seconds,
            ))
            .http2_keep_alive_timeout(Duration::from_secs(
                pool_config.http2_keep_alive_timeout_seconds,
            ));
    }

    // The minimal fallback carries neither a trust store nor a client identity,
    // so it verifies against the default roots and connects anonymously. That is
    // only acceptable when this upstream named no exclusive CA and no client
    // identity in the first place; otherwise it is the same downgrade the arms
    // above refuse, just later. `skip_verify` is deliberately NOT an escape here
    // either — see the CA block for why disabling verification does not license
    // discarding explicitly configured material.
    //
    // A `dial_host_pin` disqualifies the fallback outright, whatever material was
    // named: the minimal client carries neither the hostname pin nor the H1-only
    // restriction, so it would resolve the SNI hostname from the probe URL and
    // dial wherever THAT points — the exact escape `DialPinUnavailable` exists to
    // refuse. Fail closed instead and let the probe report unhealthy.
    let has_explicit_material =
        ca_path.is_some() || cert_path.is_some() || key_path.is_some() || dial_host_pin.is_some();
    match builder.build() {
        Ok(client) => Ok(client),
        Err(e) if !has_explicit_material => {
            tracing::error!(
                "Failed to build TLS health check HTTP client: {}. \
                 Falling back to a minimal DNS-cached client (TLS-specific settings will not apply).",
                e
            );
            build_dns_cached_fallback_client(dns_cache, "TLS health check")
                .map_err(HealthCheckClientError::from)
        }
        Err(e) => Err(HealthCheckClientError::ExclusiveTrustUnavailable(format!(
            "TLS health check client could not be built with the configured backend TLS material: {e}"
        ))),
    }
}

/// True when any effective passive policy in `config` enables automatic
/// recovery (`healthy_after_seconds > 0`), including per-port and subset-only
/// overlays that are not present on the base upstream health_checks block.
fn config_needs_passive_recovery(config: &GatewayConfig) -> bool {
    fn passive_recovers(passive: Option<&PassiveHealthCheck>) -> bool {
        passive.is_some_and(|p| p.healthy_after_seconds > 0)
    }

    for upstream in &config.upstreams {
        if passive_recovers(
            upstream
                .health_checks
                .as_ref()
                .and_then(|hc| hc.passive.as_ref()),
        ) {
            return true;
        }
        for override_config in upstream.port_overrides.values() {
            if passive_recovers(override_config.passive_health_check.as_ref()) {
                return true;
            }
        }
        for subset in upstream.resolved_subset_tls.values() {
            if passive_recovers(subset.passive_health_check.as_ref()) {
                return true;
            }
        }
    }
    for proxy in &config.proxies {
        if let Some(overrides) = proxy.dispatch_port_overrides.as_ref() {
            for override_config in overrides.values() {
                if passive_recovers(override_config.passive_health_check.as_ref()) {
                    return true;
                }
            }
        }
    }
    false
}

fn reset_latency_after_passive_recovery_inner(
    lb_cache: Option<&Arc<LoadBalancerCache>>,
    namespace: &str,
    upstream_id: &str,
    target: &UpstreamTarget,
) {
    if upstream_id.is_empty() {
        return;
    }
    if let Some(cache) = lb_cache {
        cache.reset_recovered_target_latency(namespace, upstream_id, target);
    }
}

fn recover_due_passive_ejections_inner(
    passive_health: &DashMap<String, Arc<ProxyHealthState>>,
    lb_cache: Option<&Arc<LoadBalancerCache>>,
) {
    let now = now_epoch_ms();

    let any_unhealthy = passive_health
        .iter()
        .any(|entry| !entry.value().unhealthy.is_empty());
    if !any_unhealthy {
        return;
    }

    for entry in passive_health.iter() {
        let proxy_key = entry.key();
        // Passive partitions are keyed `namespace|proxy_id`; reuse the namespace
        // so least-latency reset cannot touch a same-id balancer in another
        // tenant.
        let namespace = proxy_key
            .split_once('|')
            .map(|(ns, _)| ns)
            .unwrap_or(proxy_key.as_str());
        let proxy_state = entry.value();

        let to_recover: Vec<(String, PassiveEjection)> = proxy_state
            .unhealthy
            .iter()
            .filter(|e| {
                let ejection = e.value();
                ejection.auto_recover && now >= ejection.recover_at_ms
            })
            .map(|e| (e.key().clone(), e.value().clone()))
            .collect();

        for (hp, ejection) in &to_recover {
            let removed = match proxy_state.unhealthy.remove(hp) {
                Some((_, current))
                    if current.auto_recover
                        && now >= current.recover_at_ms
                        && current.recover_at_ms == ejection.recover_at_ms =>
                {
                    Some(current)
                }
                Some((key, current)) => {
                    // Newer re-ejection won the race — keep its own deadline.
                    proxy_state.unhealthy.insert(key, current);
                    None
                }
                None => None,
            };
            let Some(current) = removed else {
                continue;
            };

            info!(
                "Passive recovery timer: restoring target {} for proxy {} after cooldown (upstream {})",
                hp, proxy_key, current.upstream_id
            );
            if let Some(state) = proxy_state.states.get(hp) {
                state.consecutive_failures.store(0, Ordering::Relaxed);
                state.consecutive_successes.store(0, Ordering::Relaxed);
                state.lock_recent_failures().clear();
            }

            // Seed least-latency sample count past warm-up so passive recovery
            // cannot restore an unconditional biased-best state.
            let recovered = UpstreamTarget {
                host: current.host.clone(),
                port: current.port,
                service_port_policy_key: None,
                weight: 1,
                tags: Default::default(),
                locality: None,
                path: None,
            };
            reset_latency_after_passive_recovery_inner(
                lb_cache,
                namespace,
                &current.upstream_id,
                &recovered,
            );
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
    let default_tls = BackendTlsConfig::default_verify();
    grpc_probe(
        host,
        host,
        port,
        timeout,
        use_tls,
        service_name,
        &default_tls,
        None,
        None,
        None,
        false,
    )
    .await
    .success
}

#[cfg(test)]
mod tests {
    //! Inline tests for private health-check helpers.
    //!
    //! `build_health_check_client` is intentionally private and these tests
    //! sit inline so they can exercise it directly. Promoting it to `pub`
    //! to enable an external test would widen the public API for no reason —
    //! per CLAUDE.md private fns belong in inline `#[cfg(test)] mod tests`.
    use super::*;
    use crate::dns::DnsConfig;
    use rcgen::{BasicConstraints, CertificateParams, IsCa, Issuer, KeyPair, KeyUsagePurpose};
    use rustls::ServerConfig;
    use rustls::client::danger::ServerCertVerifier;
    use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, UnixTime};
    use std::sync::Mutex;
    use std::sync::Once;
    use std::time::Duration;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::{TcpListener, UdpSocket};
    use tokio_rustls::TlsAcceptor;
    use wiremock::MockServer;

    static ENV_LOCK: Mutex<()> = Mutex::new(());

    /// Bare probe builder for tests that exercise `apply_probe_dial_identity`
    /// directly.
    ///
    /// The policy-governed builder guard in
    /// `tests/unit/plugins/plugin_http_client_tests.rs` reads this file as
    /// source text, so every `reqwest::Client::builder()` chain in it — test
    /// chains included — must carry the ambient-proxy opt-out the production
    /// constructors install. Constructing it here keeps that true in one place
    /// instead of relying on each call site to remember.
    fn probe_test_builder() -> reqwest::ClientBuilder {
        reqwest::Client::builder().no_proxy()
    }

    struct ProxyEnvGuard {
        saved: Vec<(&'static str, Option<std::ffi::OsString>)>,
    }

    impl ProxyEnvGuard {
        fn point_all_at(proxy_url: &str) -> Self {
            const PROXY_KEYS: &[&str] = &[
                "HTTP_PROXY",
                "HTTPS_PROXY",
                "ALL_PROXY",
                "http_proxy",
                "https_proxy",
                "all_proxy",
                "NO_PROXY",
                "no_proxy",
            ];
            let saved = PROXY_KEYS
                .iter()
                .map(|&key| (key, std::env::var_os(key)))
                .collect();
            for &key in &PROXY_KEYS[..6] {
                // SAFETY: ENV_LOCK serialises test access to the process-global env.
                unsafe { std::env::set_var(key, proxy_url) };
            }
            for &key in &PROXY_KEYS[6..] {
                // SAFETY: ENV_LOCK serialises test access to the process-global env.
                unsafe { std::env::remove_var(key) };
            }
            Self { saved }
        }
    }

    impl Drop for ProxyEnvGuard {
        fn drop(&mut self) {
            for (key, value) in &self.saved {
                // SAFETY: ENV_LOCK is held for the caller's lifetime.
                unsafe {
                    match value {
                        Some(value) => std::env::set_var(*key, value),
                        None => std::env::remove_var(*key),
                    }
                }
            }
        }
    }

    static INIT_CRYPTO: Once = Once::new();

    fn ensure_crypto_provider() {
        INIT_CRYPTO.call_once(|| {
            let _ = crate::fips::base_crypto_provider().install_default();
        });
    }

    /// Spawn a self-signed HTTPS server on 127.0.0.1:<random> that responds
    /// to any inbound HTTP request with `200 OK`. Returns the bound port.
    async fn spawn_self_signed_https_server() -> u16 {
        ensure_crypto_provider();

        let key_pair = KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).unwrap();
        let params = CertificateParams::new(vec!["localhost".to_string()]).unwrap();
        let cert = params.self_signed(&key_pair).unwrap();
        let cert_der = CertificateDer::from(cert.der().to_vec());
        let key_der =
            PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key_pair.serialize_der().to_vec()));

        let server_config = ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(vec![cert_der], key_der)
            .unwrap();
        let acceptor = TlsAcceptor::from(Arc::new(server_config));

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();

        tokio::spawn(async move {
            loop {
                let Ok((stream, _)) = listener.accept().await else {
                    break;
                };
                let acceptor = acceptor.clone();
                tokio::spawn(async move {
                    let Ok(mut tls) = acceptor.accept(stream).await else {
                        return;
                    };
                    let mut buf = [0u8; 1024];
                    let _ = tls.read(&mut buf).await;
                    let _ = tls
                        .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok")
                        .await;
                    let _ = tls.shutdown().await;
                });
            }
        });

        port
    }

    async fn spawn_ipv6_plain_http_server() -> u16 {
        let addr =
            std::net::SocketAddr::new(std::net::IpAddr::V6(std::net::Ipv6Addr::LOCALHOST), 0);
        let listener = TcpListener::bind(addr).await.unwrap();
        let port = listener.local_addr().unwrap().port();

        tokio::spawn(async move {
            let Ok((mut stream, _)) = listener.accept().await else {
                return;
            };
            let mut buf = [0u8; 1024];
            let _ = stream.read(&mut buf).await;
            let _ = stream
                .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok")
                .await;
            let _ = stream.shutdown().await;
        });

        port
    }

    #[test]
    fn probe_address_formatting_brackets_ipv6_literals() {
        assert_eq!(format_probe_socket_addr("::1", 8443), "[::1]:8443");
        assert_eq!(
            format_probe_url("https", "::1", 8443, "/health"),
            "https://[::1]:8443/health"
        );
        assert_eq!(
            format_probe_url("http", "backend.local", 8080, "/health"),
            "http://backend.local:8080/health"
        );
    }

    #[test]
    fn grpc_probe_dials_candidate_but_preserves_original_authority() {
        let (endpoint, origin) = grpc_probe_urls("https", "backend.internal", "192.0.2.25", 8443);
        assert_eq!(endpoint, "https://192.0.2.25:8443");
        assert_eq!(origin, "https://backend.internal:8443");
    }

    // -----------------------------------------------------------------------
    // Probes use the EFFECTIVE backend TLS server-name identity.
    //
    // `probe_tls_server_name` / `probe_authority` are private, so these stay
    // inline. The dial itself is covered by the candidate/authority tests above
    // and the pinned-client fail-closed test below.
    // -----------------------------------------------------------------------

    #[test]
    fn probe_server_name_follows_the_configured_backend_tls_sni() {
        let mut tls = BackendTlsConfig::default_verify();
        let target_only = probe_tls_server_name(&tls, "pod-a.internal");
        assert_eq!(
            target_only, "pod-a.internal",
            "without an override the probe keeps verifying the target host"
        );

        tls.sni = Some("backend.example.com".to_string());
        let overridden = probe_tls_server_name(&tls, "pod-a.internal");
        assert_eq!(
            overridden, "backend.example.com",
            "a covered backend serves a certificate for the override name"
        );
        // Every target of the upstream resolves to the same server name — a
        // per-upstream identity, not a per-target one.
        let other_target = probe_tls_server_name(&tls, "pod-b.internal");
        assert_eq!(other_target, "backend.example.com");
    }

    #[test]
    fn probe_server_name_strips_ipv6_brackets_for_rustls() {
        // rustls/tonic want a bare name. An override is validated to be a DNS
        // hostname, so this only ever applies to the target-host fallback.
        let tls = BackendTlsConfig::default_verify();
        let bare = probe_tls_server_name(&tls, "[fd00::1]");
        assert_eq!(bare, "fd00::1");
    }

    #[test]
    fn probe_authority_names_the_real_target_not_the_server_name() {
        // What the backend must see in `Host` when the URL authority carries
        // the TLS server name instead.
        let explicit = probe_authority("https", "pod-a.internal", 8443);
        assert_eq!(explicit, "pod-a.internal:8443");
        // Default ports are elided, matching what reqwest would have derived.
        let https_default = probe_authority("https", "pod-a.internal", 443);
        assert_eq!(https_default, "pod-a.internal");
        let http_default = probe_authority("http", "pod-a.internal", 80);
        assert_eq!(http_default, "pod-a.internal");
        // IPv6 targets stay bracketed: a URI authority requires it.
        let v6 = probe_authority("https", "fd00::1", 8443);
        assert_eq!(v6, "[fd00::1]:8443");
        let v6_bracketed = probe_authority("https", "[fd00::1]", 8443);
        assert_eq!(v6_bracketed, "[fd00::1]:8443");
    }

    #[test]
    fn sni_probe_url_carries_the_server_name_and_keeps_the_probe_path() {
        // The pairing dispatch performs: URL authority = server name (so
        // reqwest presents it as SNI and verifies against it), `Host` = the
        // real target.
        let mut tls = BackendTlsConfig::default_verify();
        tls.sni = Some("backend.example.com".to_string());
        let server_name = probe_tls_server_name(&tls, "pod-a.internal");
        let url = format_probe_url("https", server_name, 8443, "/healthz");
        assert_eq!(url, "https://backend.example.com:8443/healthz");
        let authority = probe_authority("https", "pod-a.internal", 8443);
        assert_eq!(authority, "pod-a.internal:8443");
    }

    #[tokio::test]
    async fn grpc_no_verify_probe_rejects_mixed_client_chain_before_connect() {
        ensure_crypto_provider();
        let dir = tempfile::tempdir().expect("tempdir");
        let cert_path = dir.path().join("client-chain.pem");
        let key_path = dir.path().join("client-key.pem");
        let key_pair = KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).expect("generate key");
        let params = CertificateParams::new(vec!["client.local".to_string()]).expect("cert params");
        let certificate = params.self_signed(&key_pair).expect("self-sign cert");
        std::fs::write(
            &cert_path,
            format!(
                "{}-----BEGIN CERTIFICATE-----\n!!!!\n-----END CERTIFICATE-----\n",
                certificate.pem()
            ),
        )
        .expect("write mixed client chain");
        std::fs::write(&key_path, key_pair.serialize_pem()).expect("write client key");

        let mut tls_config = BackendTlsConfig::default_verify();
        tls_config.client_cert_path = Some(cert_path.to_string_lossy().into_owned());
        tls_config.client_key_path = Some(key_path.to_string_lossy().into_owned());
        tls_config.verify_server_cert = false;
        let endpoint = tonic::transport::Endpoint::from_static("https://127.0.0.1:9");

        let error = build_grpc_probe_channel_no_verify(
            &endpoint,
            "localhost",
            Duration::from_millis(50),
            &tls_config,
            None,
            None,
            None,
        )
        .await
        .expect_err("a malformed client-chain record must fail before dialing")
        .to_string();
        assert!(
            error.contains("gRPC health probe client cert"),
            "got: {error}"
        );
        assert!(error.contains("record #2"), "got: {error}");
    }

    #[tokio::test]
    async fn grpc_no_verify_probe_rejects_all_malformed_client_chain_before_connect() {
        ensure_crypto_provider();
        let dir = tempfile::tempdir().expect("tempdir");
        let cert_path = dir.path().join("client-chain.pem");
        let key_path = dir.path().join("client-key.pem");
        let key_pair = KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).expect("generate key");
        std::fs::write(
            &cert_path,
            b"-----BEGIN CERTIFICATE-----\n!!!!\n-----END CERTIFICATE-----\n",
        )
        .expect("write malformed client chain");
        std::fs::write(&key_path, key_pair.serialize_pem()).expect("write client key");

        let mut tls_config = BackendTlsConfig::default_verify();
        tls_config.client_cert_path = Some(cert_path.to_string_lossy().into_owned());
        tls_config.client_key_path = Some(key_path.to_string_lossy().into_owned());
        tls_config.verify_server_cert = false;
        let endpoint = tonic::transport::Endpoint::from_static("https://127.0.0.1:9");

        let error = build_grpc_probe_channel_no_verify(
            &endpoint,
            "localhost",
            Duration::from_millis(50),
            &tls_config,
            None,
            None,
            None,
        )
        .await
        .expect_err("an all-malformed client chain must fail before dialing")
        .to_string();
        assert!(error.contains("record #1"), "got: {error}");
    }

    #[tokio::test]
    async fn tcp_probe_connects_to_ipv6_literal() {
        let addr =
            std::net::SocketAddr::new(std::net::IpAddr::V6(std::net::Ipv6Addr::LOCALHOST), 0);
        let listener = TcpListener::bind(addr).await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let accept = tokio::spawn(async move {
            let _ = listener.accept().await.unwrap();
        });

        assert!(tcp_probe("::1", port, Duration::from_secs(2)).await.success);
        accept.await.unwrap();
    }

    #[tokio::test]
    async fn udp_probe_connects_to_ipv6_literal() {
        let addr =
            std::net::SocketAddr::new(std::net::IpAddr::V6(std::net::Ipv6Addr::LOCALHOST), 0);
        let socket = UdpSocket::bind(addr).await.unwrap();
        let port = socket.local_addr().unwrap().port();
        let responder = tokio::spawn(async move {
            let mut buf = [0u8; 16];
            let (_, peer) = socket.recv_from(&mut buf).await.unwrap();
            socket.send_to(b"o", peer).await.unwrap();
        });

        assert!(
            udp_probe("::1", port, Duration::from_secs(2), b"p")
                .await
                .success
        );
        responder.await.unwrap();
    }

    #[tokio::test(flavor = "current_thread")]
    async fn build_health_check_client_ignores_ambient_proxy_environment() {
        let proxy = MockServer::start().await;
        let pool_config = PoolConfig::default();
        let client = {
            let _env_lock = ENV_LOCK
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            let _proxy_env = ProxyEnvGuard::point_all_at(&proxy.uri());
            build_health_check_client(&pool_config, None, false)
                .expect("health-check client should build")
        };

        let _ = client
            .get("http://198.51.100.1:9/no-proxy-canary")
            .timeout(Duration::from_millis(200))
            .send()
            .await;

        assert_eq!(
            proxy.received_requests().await.unwrap_or_default().len(),
            0,
            "ambient proxy variables must not receive health-check traffic"
        );
    }

    #[tokio::test(flavor = "current_thread")]
    async fn build_health_check_client_with_tls_ignores_ambient_proxy_environment() {
        let proxy = MockServer::start().await;
        let pool_config = PoolConfig::default();
        let tls_config = BackendTlsConfig::default_verify();
        let client = {
            let _env_lock = ENV_LOCK
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            let _proxy_env = ProxyEnvGuard::point_all_at(&proxy.uri());
            build_health_check_client_with_tls(
                &pool_config,
                None,
                &tls_config,
                &None,
                HealthCheckClientIdentityPaths {
                    cert: &None,
                    key: &None,
                },
                false,
                None,
            )
            .expect("TLS health-check client should build")
        };

        let _ = client
            .get("http://198.51.100.1:9/no-proxy-canary")
            .timeout(Duration::from_millis(200))
            .send()
            .await;

        assert_eq!(
            proxy.received_requests().await.unwrap_or_default().len(),
            0,
            "TLS-configured health-check clients must ignore ambient proxies"
        );
    }

    #[tokio::test(flavor = "current_thread")]
    async fn build_dns_cached_fallback_client_ignores_ambient_proxy_environment() {
        let proxy = MockServer::start().await;
        let client = {
            let _env_lock = ENV_LOCK
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            let _proxy_env = ProxyEnvGuard::point_all_at(&proxy.uri());
            build_dns_cached_fallback_client(None, "test")
                .expect("fallback health-check client should build")
        };

        let _ = client
            .get("http://198.51.100.1:9/no-proxy-canary")
            .timeout(Duration::from_millis(200))
            .send()
            .await;

        assert_eq!(
            proxy.received_requests().await.unwrap_or_default().len(),
            0,
            "degraded health-check fallback clients must ignore ambient proxies"
        );
    }

    #[tokio::test]
    async fn http_probe_connects_to_ipv6_literal() {
        let port = spawn_ipv6_plain_http_server().await;
        let client = reqwest::Client::new();
        let url = format_probe_url("http", "::1", port, "/health");

        assert!(
            http_probe(&client, &url, None, Duration::from_secs(2), &[200])
                .await
                .success
        );
    }

    /// Default-built health-check client (verify ON) MUST reject a
    /// self-signed cert. Regression for the unconditional
    /// `danger_accept_invalid_certs(true)` bypass.
    #[tokio::test]
    async fn build_health_check_client_default_rejects_self_signed_cert() {
        let port = spawn_self_signed_https_server().await;
        let pool_config = PoolConfig::default();

        let client = build_health_check_client(&pool_config, None, false)
            .expect("default health-check client should build");
        let result = client
            .get(format!("https://127.0.0.1:{}/", port))
            .timeout(Duration::from_secs(5))
            .send()
            .await;

        assert!(
            result.is_err(),
            "default health-check client must reject self-signed certs (verify ON), \
             got: {:?}",
            result.map(|r| r.status())
        );
    }

    /// When the operator opts into `FERRUM_TLS_NO_VERIFY=true` the same
    /// probe SHOULD succeed against the self-signed server. Confirms the
    /// new `no_verify` parameter is plumbed end-to-end.
    #[tokio::test]
    async fn build_health_check_client_no_verify_accepts_self_signed_cert() {
        let port = spawn_self_signed_https_server().await;
        let pool_config = PoolConfig::default();

        let client = build_health_check_client(&pool_config, None, true)
            .expect("no_verify health-check client should build");
        let result = client
            .get(format!("https://127.0.0.1:{}/", port))
            .timeout(Duration::from_secs(5))
            .send()
            .await;

        let response =
            result.expect("no_verify=true health-check client must accept self-signed certs");
        assert!(response.status().is_success());
    }

    /// `set_global_tls_config(tls_no_verify=true)` should rebuild the
    /// default client so probes through the no-TLS-config path also honour
    /// the operator opt-in. Without the rebuild, the original default
    /// client (built with `no_verify=false` in the constructor) would still
    /// reject the self-signed cert.
    #[tokio::test]
    async fn set_global_tls_config_no_verify_rebuilds_default_client() {
        let port = spawn_self_signed_https_server().await;
        let pool_config = PoolConfig::default();
        let mut checker = HealthChecker::without_dns_cache(&pool_config);

        // Before opt-in: default client must reject.
        let pre = checker
            .default_http_client
            .as_ref()
            .expect("default health-check client should be present")
            .get(format!("https://127.0.0.1:{}/", port))
            .timeout(Duration::from_secs(5))
            .send()
            .await;
        assert!(pre.is_err(), "default client should reject before opt-in");

        // Opt in via global flag.
        checker.set_global_tls_config(None, None, None, true);

        // After opt-in: rebuilt default client must accept.
        let post = checker
            .default_http_client
            .as_ref()
            .expect("rebuilt default health-check client should be present")
            .get(format!("https://127.0.0.1:{}/", port))
            .timeout(Duration::from_secs(5))
            .send()
            .await
            .expect("default client should accept after no_verify opt-in");
        assert!(post.status().is_success());
    }

    #[test]
    fn fallback_client_builds_with_dns_cache() {
        // Verify the helper produces a usable client when a DNS cache is
        // provided — i.e., the minimal builder configuration with only the
        // resolver attached actually succeeds.
        let dns_cache = DnsCache::new(DnsConfig::default());
        let _client = build_dns_cached_fallback_client(Some(dns_cache), "test")
            .expect("fallback client with DNS cache should build");
        // No panic, no ambient-proxy last-resort path: success.
    }

    #[test]
    fn fallback_client_builds_without_dns_cache() {
        // Verify the helper still succeeds when no DNS cache is available
        // (this exercises the `from_pool_config` cache-less code path).
        let _client = build_dns_cached_fallback_client(None, "test")
            .expect("fallback client without DNS cache should build");
    }

    #[test]
    fn build_health_check_client_returns_usable_client() {
        // Sanity check the happy path: build with a DNS cache and verify
        // the returned client can issue a request (we send to an unroutable
        // address; the DNS lookup is what matters here, not the eventual
        // connect failure).
        let dns_cache = DnsCache::new(DnsConfig::default());
        let pool_config = PoolConfig::default();
        let _client = build_health_check_client(&pool_config, Some(dns_cache), false)
            .expect("health-check client should build");
    }

    #[tokio::test]
    async fn fallback_client_uses_dns_cache_resolver() {
        // `.invalid` cannot resolve through system DNS. The request can reach
        // this listener only when the fallback client uses the supplied cache's
        // static override, making resolver attachment observable without a
        // wall-clock race on asynchronous cache population.
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind fallback resolver test listener");
        let port = listener.local_addr().expect("listener address").port();
        let hostname = "fallback-health-resolver.invalid";
        let dns_cache = DnsCache::new(DnsConfig {
            global_overrides: std::collections::HashMap::from([(
                hostname.to_string(),
                "127.0.0.1".to_string(),
            )]),
            ..DnsConfig::default()
        });
        let client = build_dns_cached_fallback_client(Some(dns_cache), "test")
            .expect("fallback client should build");

        let server = tokio::spawn(async move {
            let (mut socket, _) = tokio::time::timeout(Duration::from_secs(30), listener.accept())
                .await
                .expect("fallback resolver connection timed out")
                .expect("accept fallback resolver connection");
            let mut request = [0u8; 1024];
            let request_len = socket
                .read(&mut request)
                .await
                .expect("read fallback resolver request");
            assert!(
                request
                    .get(..request_len)
                    .is_some_and(|bytes| bytes.starts_with(b"GET ")),
                "fallback resolver listener did not receive an HTTP request"
            );
            socket
                .write_all(
                    b"HTTP/1.1 204 No Content\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
                )
                .await
                .expect("write fallback resolver response");
        });

        let response = tokio::time::timeout(
            Duration::from_secs(30),
            client.get(format!("http://{hostname}:{port}/")).send(),
        )
        .await
        .expect("fallback resolver request timed out")
        .expect("fallback client must resolve the override-only hostname");
        assert_eq!(response.status(), reqwest::StatusCode::NO_CONTENT);
        server.await.expect("fallback resolver test server failed");
    }

    #[test]
    fn accept_health_check_client_preserves_built_client() {
        let client =
            build_dns_cached_fallback_client(None, "test").expect("fallback client should build");
        assert!(
            accept_health_check_client(Ok(client), "test").is_some(),
            "successful builds must remain available to HTTP probes"
        );
    }

    // -----------------------------------------------------------------------
    // Explicit backend TLS material is mandatory for HTTP probes.
    //
    // `build_health_check_client_with_tls` is private, so these stay inline.
    // A path under a fresh temp dir that was never created is guaranteed
    // unloadable without depending on ambient filesystem state.
    // -----------------------------------------------------------------------

    fn unloadable_path(name: &str) -> String {
        std::env::temp_dir()
            .join(format!("ferrum-health-probe-absent-{name}"))
            .to_string_lossy()
            .into_owned()
    }

    fn tls_client_result(
        tls_config: &BackendTlsConfig,
        global_no_verify: bool,
    ) -> Result<reqwest::Client, HealthCheckClientError> {
        build_health_check_client_with_tls(
            &PoolConfig::default(),
            None,
            tls_config,
            &None,
            HealthCheckClientIdentityPaths {
                cert: &None,
                key: &None,
            },
            global_no_verify,
            None,
        )
    }

    /// A server-name override with no DNS cache to pin the dial must fail
    /// closed: reqwest would otherwise resolve the SNI hostname from the probe
    /// URL and dial wherever it points, off the target's screened candidates.
    #[test]
    fn probe_client_fails_closed_when_the_dial_cannot_be_pinned() {
        let mut tls = BackendTlsConfig::default_verify();
        tls.sni = Some("backend.example.com".to_string());
        let built = build_health_check_client_with_tls(
            &PoolConfig::default(),
            None,
            &tls,
            &None,
            HealthCheckClientIdentityPaths {
                cert: &None,
                key: &None,
            },
            false,
            Some("pod-a.internal"),
        );
        let pin_missing = matches!(built, Err(HealthCheckClientError::DialPinUnavailable));
        assert!(
            pin_missing,
            "an unpinnable SNI probe must not build a client that resolves the server name"
        );
    }

    /// A pinned (SNI-override) probe client must be HTTP/1.1-only.
    ///
    /// The probe puts the server name in the URL authority and the REAL target
    /// in an explicit `Host` header. HTTP/2 rebuilds `:authority` from the URI,
    /// so an h2-negotiated probe would present the override instead — measuring
    /// a request proxy traffic never makes. `ClientBuilder`'s `Debug` reports
    /// `http1_only` exactly when the version preference is HTTP/1, which is the
    /// same field that restricts the client's advertised ALPN to `http/1.1`.
    /// The wire-level counterpart (an h2-advertising backend that only speaks
    /// raw H1) lives in
    /// `tests/integration/gateway_api_backend_tls_policy_tests.rs`.
    #[test]
    fn sni_probe_dial_identity_is_restricted_to_http1() {
        let dns_cache = DnsCache::new(DnsConfig::default());

        let pinned = apply_probe_dial_identity(
            probe_test_builder(),
            Some(dns_cache.clone()),
            Some("pod-a.internal"),
        )
        .expect("pinned SNI probe builder");
        assert!(
            format!("{pinned:?}").contains("http1_only"),
            "an SNI-override probe must not be able to negotiate h2: {pinned:?}"
        );

        // A probe without an override keeps the ordinary h2-capable client: its
        // URL already names the real target, so there is no authority to lose.
        let unpinned = apply_probe_dial_identity(probe_test_builder(), Some(dns_cache), None)
            .expect("ordinary probe builder");
        assert!(
            !format!("{unpinned:?}").contains("http1_only"),
            "a probe without a server-name override must not be narrowed to H1: {unpinned:?}"
        );

        // And the pin itself stays mandatory: no cache, no client.
        let unpinnable =
            apply_probe_dial_identity(probe_test_builder(), None, Some("pod-a.internal"));
        assert!(
            matches!(unpinnable, Err(HealthCheckClientError::DialPinUnavailable)),
            "an unpinnable SNI probe must not build a builder at all"
        );
    }

    #[test]
    fn probe_client_fails_closed_when_configured_ca_cannot_be_loaded() {
        let mut tls = BackendTlsConfig::default_verify();
        tls.server_ca_cert_path = Some(unloadable_path("ca"));
        assert!(
            matches!(
                tls_client_result(&tls, false),
                Err(HealthCheckClientError::ExclusiveTrustUnavailable(_))
            ),
            "an unloadable exclusive CA must not fall back to the default roots"
        );
    }

    #[test]
    fn probe_client_fails_closed_on_unloadable_ca_even_without_verification() {
        // The defect this pins: `verify_server_cert: false` used to downgrade an
        // unloadable CA to a warning and build a client on the default roots.
        // Explicitly named material that cannot be loaded is a configuration
        // fault in both verification modes.
        let mut tls = BackendTlsConfig::default_verify();
        tls.server_ca_cert_path = Some(unloadable_path("ca-noverify"));
        tls.verify_server_cert = false;
        assert!(
            matches!(
                tls_client_result(&tls, false),
                Err(HealthCheckClientError::ExclusiveTrustUnavailable(_))
            ),
            "per-upstream no-verify must not absorb an unloadable configured CA"
        );

        // Same through the global `FERRUM_TLS_NO_VERIFY` opt-in.
        let mut global = BackendTlsConfig::default_verify();
        global.server_ca_cert_path = Some(unloadable_path("ca-global-noverify"));
        assert!(
            matches!(
                tls_client_result(&global, true),
                Err(HealthCheckClientError::ExclusiveTrustUnavailable(_))
            ),
            "global no-verify must not absorb an unloadable configured CA"
        );
    }

    #[test]
    fn probe_client_fails_closed_when_configured_identity_cannot_be_loaded() {
        let mut tls = BackendTlsConfig::default_verify();
        tls.client_cert_path = Some(unloadable_path("cert"));
        tls.client_key_path = Some(unloadable_path("key"));
        assert!(
            matches!(
                tls_client_result(&tls, false),
                Err(HealthCheckClientError::ClientIdentityUnavailable(_))
            ),
            "an unloadable client identity must not produce an anonymous probe"
        );
    }

    #[test]
    fn probe_client_fails_closed_on_unloadable_identity_even_without_verification() {
        let mut tls = BackendTlsConfig::default_verify();
        tls.client_cert_path = Some(unloadable_path("cert-noverify"));
        tls.client_key_path = Some(unloadable_path("key-noverify"));
        tls.verify_server_cert = false;
        assert!(
            matches!(
                tls_client_result(&tls, false),
                Err(HealthCheckClientError::ClientIdentityUnavailable(_))
            ),
            "no-verify governs server verification, not whether the probe authenticates"
        );
    }

    #[test]
    fn probe_client_fails_closed_on_half_configured_identity() {
        let mut cert_only = BackendTlsConfig::default_verify();
        cert_only.client_cert_path = Some(unloadable_path("cert-only"));
        assert!(
            matches!(
                tls_client_result(&cert_only, false),
                Err(HealthCheckClientError::ClientIdentityUnavailable(_))
            ),
            "a client certificate without a key must fail rather than be ignored"
        );

        let mut key_only = BackendTlsConfig::default_verify();
        key_only.client_key_path = Some(unloadable_path("key-only"));
        assert!(
            matches!(
                tls_client_result(&key_only, false),
                Err(HealthCheckClientError::ClientIdentityUnavailable(_))
            ),
            "a private key without a certificate must fail rather than be ignored"
        );
    }

    #[test]
    fn probe_client_error_text_names_no_material() {
        let mut tls = BackendTlsConfig::default_verify();
        tls.client_cert_path = Some(unloadable_path("cert-redaction"));
        tls.client_key_path = Some(unloadable_path("key-redaction"));
        let rendered = tls_client_result(&tls, false)
            .err()
            .map(|e| e.to_string())
            .unwrap_or_default();
        for marker in ["BEGIN CERTIFICATE", "BEGIN PRIVATE KEY", "BEGIN RSA"] {
            assert!(
                !rendered.contains(marker),
                "probe TLS diagnostics must never carry credential material: {rendered}"
            );
        }
    }

    #[test]
    fn probe_client_builds_when_no_backend_tls_material_is_configured() {
        // The ordinary case must stay unaffected: no CA, no identity, so there is
        // nothing explicit to fail closed on.
        assert!(
            tls_client_result(&BackendTlsConfig::default_verify(), false).is_ok(),
            "an upstream with no configured backend TLS material still gets a probe client"
        );
    }

    /// Pin the fail-closed contract in source: the health-check fallback must
    /// not panic and must not fall back to the ambient-proxy-aware default
    /// constructor.
    #[test]
    fn health_check_fallback_source_fails_closed_without_panic_or_client_new() {
        let source = include_str!("health_check.rs");
        let start = source
            .find("fn build_dns_cached_fallback_client(")
            .expect("fallback helper present");
        let rest = &source[start..];
        let end = rest
            .find("\nfn accept_health_check_client(")
            .expect("accept helper follows fallback");
        let helper = &rest[..end];
        assert!(
            helper.contains("Result<reqwest::Client, reqwest::Error>"),
            "fallback helper must return Result so construction failure propagates"
        );
        assert!(
            helper.contains(".no_proxy()"),
            "fallback helper must disable ambient proxies"
        );
        assert!(
            !helper.contains("panic!"),
            "fallback helper must not panic on construction failure"
        );
        assert!(
            !helper.contains("unwrap_or_else"),
            "fallback helper must not unwrap fallible builds into panic or ambient-proxy defaults"
        );
        // Ignore comments/docs: only executable lines may not call the ambient
        // default constructor (which inherits HTTP_PROXY/HTTPS_PROXY/ALL_PROXY).
        let code_mentions_default_ctor = helper.lines().any(|line| {
            let trimmed = line.trim_start();
            !trimmed.starts_with("//")
                && !trimmed.starts_with("///")
                && !trimmed.starts_with('*')
                && trimmed.contains("Client::new()")
        });
        assert!(
            !code_mentions_default_ctor,
            "fallback helper must not re-enable ambient proxies via Client::new()"
        );
        assert!(
            source.contains("health-check HTTP client construction failed"),
            "HTTP probes must fail closed when the client is unavailable"
        );
        assert!(
            source.contains("default_http_client: Option<Arc<reqwest::Client>>"),
            "construction failure must be representable without panicking"
        );
    }

    #[test]
    fn bound_probe_targets_caps_at_max_targets_per_upstream() {
        let targets: Vec<UpstreamTarget> = (0..=MAX_TARGETS_PER_UPSTREAM)
            .map(|i| UpstreamTarget {
                host: format!("h{i}.local"),
                port: 8080,
                service_port_policy_key: None,
                weight: 1,
                tags: std::collections::HashMap::new(),
                locality: None,
                path: None,
            })
            .collect();
        assert_eq!(targets.len(), MAX_TARGETS_PER_UPSTREAM + 1);
        assert_eq!(
            bound_probe_targets(&targets).len(),
            MAX_TARGETS_PER_UPSTREAM
        );
    }

    #[test]
    fn probe_server_verifier_uses_plain_webpki_when_san_allow_list_empty() {
        ensure_crypto_provider();
        let verifier = build_probe_server_verifier(&BackendTlsConfig::default_verify(), None)
            .expect("empty SAN list must still build a verifier");
        assert!(matches!(verifier, ProbeServerVerifier::WebPki));
    }

    #[test]
    fn probe_server_verifier_wraps_when_san_allow_list_configured() {
        ensure_crypto_provider();
        let mut tls = BackendTlsConfig::default_verify();
        tls.san_allow_list = vec!["localhost".to_string()];
        let verifier =
            build_probe_server_verifier(&tls, None).expect("configured SAN list must wrap");
        assert!(matches!(verifier, ProbeServerVerifier::SanAllowList(_)));
    }

    #[test]
    fn probe_server_verifier_rejects_peer_not_in_allow_list() {
        ensure_crypto_provider();
        let ca_key = KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).unwrap();
        let mut ca_params = CertificateParams::new(Vec::<String>::new()).unwrap();
        ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        ca_params
            .distinguished_name
            .push(rcgen::DnType::CommonName, "Probe SAN CA");
        ca_params.key_usages.push(KeyUsagePurpose::KeyCertSign);
        ca_params.key_usages.push(KeyUsagePurpose::DigitalSignature);
        let ca_cert = ca_params.self_signed(&ca_key).unwrap();
        let issuer = Issuer::new(ca_params, ca_key);

        let allowed_key = KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).unwrap();
        let allowed_params = CertificateParams::new(vec!["localhost".to_string()]).unwrap();
        let allowed_cert = allowed_params.signed_by(&allowed_key, &issuer).unwrap();
        let allowed_der = CertificateDer::from(allowed_cert.der().to_vec());

        let other_key = KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).unwrap();
        let other_params = CertificateParams::new(vec!["other.example".to_string()]).unwrap();
        let other_cert = other_params.signed_by(&other_key, &issuer).unwrap();
        let other_der = CertificateDer::from(other_cert.der().to_vec());

        let dir = tempfile::TempDir::new().unwrap();
        let ca_path = dir.path().join("ca.pem");
        std::fs::write(&ca_path, ca_cert.pem()).unwrap();

        let mut tls = BackendTlsConfig::default_verify();
        tls.server_ca_cert_path = Some(ca_path.display().to_string());
        tls.san_allow_list = vec!["localhost".to_string()];
        let verifier =
            build_probe_server_verifier(&tls, None).expect("SAN-pinned verifier must build");
        let ProbeServerVerifier::SanAllowList(verifier) = verifier else {
            panic!("configured SAN list must wrap SanAllowListVerifier");
        };

        let localhost = rustls::pki_types::ServerName::try_from("localhost").unwrap();
        let other_name = rustls::pki_types::ServerName::try_from("other.example").unwrap();
        verifier
            .verify_server_cert(&allowed_der, &[], &localhost, &[], UnixTime::now())
            .expect("allow-listed SAN must pass");
        assert!(
            verifier
                .verify_server_cert(&other_der, &[], &other_name, &[], UnixTime::now())
                .is_err(),
            "peer whose SAN is not in the allow-list must be rejected"
        );
    }

    #[test]
    fn probe_client_builds_when_san_allow_list_is_configured() {
        let mut tls = BackendTlsConfig::default_verify();
        tls.san_allow_list = vec!["localhost".to_string()];
        assert!(
            tls_client_result(&tls, false).is_ok(),
            "a valid SAN allow-list must produce a preconfigured probe client"
        );
    }

    #[test]
    fn probe_client_fails_closed_on_invalid_san_allow_list_entry() {
        let mut tls = BackendTlsConfig::default_verify();
        tls.san_allow_list = vec!["https://not-spiffe.example".to_string()];
        assert!(
            matches!(
                tls_client_result(&tls, false),
                Err(HealthCheckClientError::SanPinningUnavailable(_))
            ),
            "an invalid SAN allow-list must not build an unpinned probe client"
        );
    }
}
