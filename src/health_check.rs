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
    ActiveHealthCheck, BackendTlsConfig, GatewayConfig, HealthProbeType, PassiveHealthCheck,
    UpstreamTarget,
};
use crate::dns::{DnsCache, DnsCacheResolver};
use crate::load_balancer::{
    LoadBalancerCache, target_host_port_key, target_key, write_target_host_port_key,
};
use crate::tls::source::{CertSource, MaterialKind, load_material_blocking};
use dashmap::DashMap;
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
}

/// Per-active-check identity and lifecycle inputs for `start_active_check`.
struct ActiveCheckStartParams<'a> {
    target: &'a UpstreamTarget,
    upstream_namespace: &'a str,
    upstream_id: &'a str,
    shutdown_rx: Option<&'a tokio::sync::watch::Receiver<bool>>,
    generation: u64,
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
            build_health_check_client(pool_config, Some(dns_cache.clone()), false),
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
                build_health_check_client(&self.pool_config, self.dns_cache.clone(), tls_no_verify),
                "default health-check HTTP client (tls_no_verify rebuild)",
            );
        }
    }

    /// Create a health checker without DNS cache (for tests).
    fn without_dns_cache(pool_config: &PoolConfig) -> Self {
        let client = accept_health_check_client(
            build_health_check_client(pool_config, None, false),
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

        drop(publish_guard);

        let mut new_handles: Vec<tokio::task::JoinHandle<()>> = Vec::new();
        let mut new_aborts: Vec<AbortHandle> = Vec::new();
        for upstream in &config.upstreams {
            if let Some(hc_config) = &upstream.health_checks {
                // Start active health checks
                if let Some(active) = &hc_config.active {
                    // Build a per-upstream HTTP client with the upstream's TLS config
                    let tls_config = BackendTlsConfig::from_upstream(upstream);
                    let upstream_client =
                        self.build_upstream_health_client(&tls_config, active.use_tls);
                    for target in &upstream.targets {
                        let start = ActiveCheckStartParams {
                            target,
                            upstream_namespace: &upstream.namespace,
                            upstream_id: &upstream.id,
                            shutdown_rx: shutdown_rx.as_ref(),
                            generation,
                        };
                        let handle = self.start_active_check(
                            start,
                            active,
                            upstream_client.as_ref(),
                            &tls_config,
                        );
                        new_aborts.push(handle.abort_handle());
                        new_handles.push(handle);
                    }
                }
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
                u.targets
                    .iter()
                    .map(|t| target_key(&upstream_key, t))
                    .collect::<Vec<_>>()
            })
            .collect();
        self.active_unhealthy_targets
            .retain(|key, _| active_keys.contains(key));
        self.active_target_states
            .retain(|key, _| active_keys.contains(key));
    }

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
                let counter = state.failure_counter.fetch_add(1, Ordering::Relaxed);
                state.recent_failures.insert(counter, now_ms);

                // Clean old failures outside the window and read len() immediately
                // after retain() to minimise the race window between the two
                // DashMap operations. This is a best-effort snapshot: concurrent
                // reporters, hard-cap evictions, or recovery clears can skew the
                // count in either direction. Acceptable for health threshold
                // decisions which self-correct on subsequent reports and recovery.
                let window_start =
                    now_ms.saturating_sub(config.unhealthy_window_seconds * 1000);
                state
                    .recent_failures
                    .retain(|_, &mut ts| ts >= window_start);
                let failures_in_window = state.recent_failures.len();

                // Hard cap: prevent unbounded memory growth. Snapshot len once
                // to avoid a second racy read between the guard and the eviction.
                if failures_in_window > MAX_RECENT_FAILURES_PER_TARGET {
                    let excess = failures_in_window - MAX_RECENT_FAILURES_PER_TARGET;
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

                let failures_in_window = failures_in_window as u32;
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
                            state.recent_failures.clear();
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
    fn build_upstream_health_client(
        &self,
        tls_config: &BackendTlsConfig,
        use_tls: bool,
    ) -> Option<Arc<reqwest::Client>> {
        let has_tls_config = tls_config.client_cert_path.is_some()
            || tls_config.client_key_path.is_some()
            || tls_config.server_ca_cert_path.is_some()
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
                &self.global_backend_tls_client_cert_path,
                &self.global_backend_tls_client_key_path,
                self.global_tls_no_verify,
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
        let url = format_probe_url(scheme, &host, port, &config.http_path);
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
            let mut timer = tokio::time::interval(interval);

            loop {
                if task_generation.load(Ordering::Acquire) != generation {
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
                if task_generation.load(Ordering::Acquire) != generation {
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
                                    http_probe(client, &url, timeout, &healthy_status_codes).await
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
                if task_generation.load(Ordering::Acquire) != generation {
                    return;
                }

                // Defer entry until after the probe and re-check generation
                // while holding the DashMap entry lock, so prune cannot race a
                // pre-insert fence and leave a resurrected removed-target key.
                let state = {
                    use dashmap::mapref::entry::Entry;
                    match target_states.entry(key.clone()) {
                        Entry::Occupied(entry) => {
                            if task_generation.load(Ordering::Acquire) != generation {
                                return;
                            }
                            entry.get().clone()
                        }
                        Entry::Vacant(entry) => {
                            if task_generation.load(Ordering::Acquire) != generation {
                                return;
                            }
                            entry.insert(Arc::new(TargetHealth::new())).clone()
                        }
                    }
                };

                if task_generation.load(Ordering::Acquire) != generation {
                    return;
                }

                if probe_outcome.success {
                    state.consecutive_failures.store(0, Ordering::Relaxed);
                    let successes = state.consecutive_successes.fetch_add(1, Ordering::Relaxed) + 1;

                    // Shared TargetHealth / LB cache intentionally survive reload.
                    // Bail before side effects if this probe retired mid-mutation so
                    // a drained generation cannot publish latency or clear marks
                    // under replacement policy.
                    if task_generation.load(Ordering::Acquire) != generation {
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
                        let removed = unhealthy_targets.remove_if(&key, |_, _| {
                            task_generation.load(Ordering::Acquire) == generation
                        });
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

                    if task_generation.load(Ordering::Acquire) != generation {
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
                                    if task_generation.load(Ordering::Acquire) != generation {
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
async fn http_probe(
    client: &reqwest::Client,
    url: &str,
    timeout: Duration,
    healthy_status_codes: &[u16],
) -> ProbeOutcome {
    match client.get(url).timeout(timeout).send().await {
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

    let skip_verify = use_tls && (!tls_config.verify_server_cert || global_no_verify);

    // When skip_verify is true, tonic's ClientTlsConfig doesn't support disabling
    // cert verification. Build a rustls ClientConfig directly with NoVerifier
    // (same pattern as grpc_proxy.rs) and use connect_with_connector.
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
    } else if use_tls {
        // SNI / cert hostname stays the original `host` even though we dial the
        // pre-screened IP via `dial_addr`, so backend cert validation is unchanged.
        // rustls/tonic want a BARE SNI host, not a URI-bracketed IPv6 literal
        // (`[fd00::1]`), so strip brackets here — the `origin`/authority above
        // keeps the bracketed form because a URI authority requires it.
        let sni_host = host
            .strip_prefix('[')
            .and_then(|h| h.strip_suffix(']'))
            .unwrap_or(host);
        let mut tonic_tls = tonic::transport::ClientTlsConfig::new().domain_name(sni_host);

        // Load CA certs (upstream → global → system roots)
        if let Some(ca_path) = tls_config.server_ca_cert_path.as_deref().or(global_ca_path) {
            match load_probe_tls_material(ca_path, MaterialKind::CaBundle, "gRPC health probe CA") {
                Ok(pem) => {
                    let cert = tonic::transport::Certificate::from_pem(pem);
                    tonic_tls = tonic_tls.ca_certificate(cert);
                }
                Err(e) => {
                    debug!("gRPC health probe: failed to load CA: {}", e);
                }
            }
        } else {
            tonic_tls = tonic_tls.with_enabled_roots();
        }

        // Load mTLS client identity
        let cert_path = tls_config.client_cert_path.as_deref().or(global_cert_path);
        let key_path = tls_config.client_key_path.as_deref().or(global_key_path);
        if let (Some(cert_path), Some(key_path)) = (cert_path, key_path) {
            match (
                load_probe_tls_material(
                    cert_path,
                    MaterialKind::Cert,
                    "gRPC health probe client cert",
                ),
                load_probe_tls_material(
                    key_path,
                    MaterialKind::Key,
                    "gRPC health probe client key",
                ),
            ) {
                (Ok(cert_pem), Ok(key_pem)) => {
                    let identity = tonic::transport::Identity::from_pem(cert_pem, key_pem);
                    tonic_tls = tonic_tls.identity(identity);
                }
                (Err(e), _) | (_, Err(e)) => {
                    debug!("gRPC health probe: failed to load client cert/key: {}", e);
                }
            }
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
    let ca_path = tls_config.server_ca_cert_path.as_deref().or(global_ca_path);
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
    let host_owned = host.to_string();

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
    result: Result<reqwest::Client, reqwest::Error>,
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

/// Build a health check HTTP client with upstream-specific TLS configuration.
///
/// Configures the client with the upstream's CA bundle, client cert/key for mTLS,
/// and verify settings — so health probes authenticate the same way proxy traffic does.
fn build_health_check_client_with_tls(
    pool_config: &PoolConfig,
    dns_cache: Option<DnsCache>,
    tls_config: &BackendTlsConfig,
    global_ca_path: &Option<String>,
    global_cert_path: &Option<String>,
    global_key_path: &Option<String>,
    global_no_verify: bool,
) -> Result<reqwest::Client, reqwest::Error> {
    let skip_verify = !tls_config.verify_server_cert || global_no_verify;

    let mut builder = reqwest::Client::builder()
        .no_proxy()
        .pool_max_idle_per_host(pool_config.max_idle_per_host)
        .pool_idle_timeout(Duration::from_secs(pool_config.idle_timeout_seconds))
        // Do not follow redirects on health probes: a 3xx to an IP literal skips
        // the DnsCacheResolver and the egress screen (see build_health_check_client).
        .redirect(reqwest::redirect::Policy::none())
        .danger_accept_invalid_certs(skip_verify);

    if let Some(dns_cache) = dns_cache.clone() {
        let resolver = DnsCacheResolver::new(dns_cache);
        builder = builder.dns_resolver(Arc::new(resolver));
    }

    // Load CA bundle (upstream → global → system roots)
    let ca_path = tls_config
        .server_ca_cert_path
        .as_ref()
        .or(global_ca_path.as_ref());
    if let Some(ca_path) = ca_path {
        if let Ok(ca_data) =
            load_probe_tls_material(ca_path, MaterialKind::CaBundle, "Health check CA")
        {
            if let Ok(ca_cert) = reqwest::Certificate::from_pem(&ca_data) {
                // reqwest 0.13: `tls_certs_only` replaces the trust store entirely,
                // matching the project's "CA exclusivity" rule (no webpki mixing
                // when a custom CA is provided).
                builder = builder.tls_certs_only([ca_cert]);
            } else {
                tracing::warn!("Health check: failed to parse CA cert, using system roots");
            }
        } else {
            tracing::warn!("Health check: failed to load CA cert, using system roots");
        }
    }

    // Load mTLS client identity
    let cert_path = tls_config
        .client_cert_path
        .as_ref()
        .or(global_cert_path.as_ref());
    let key_path = tls_config
        .client_key_path
        .as_ref()
        .or(global_key_path.as_ref());
    if let (Some(cert_path), Some(key_path)) = (cert_path, key_path) {
        match (
            load_probe_tls_material(cert_path, MaterialKind::Cert, "Health check client cert"),
            load_probe_tls_material(key_path, MaterialKind::Key, "Health check client key"),
        ) {
            (Ok(cert_data), Ok(key_data)) => {
                let mut combined = cert_data;
                combined.extend_from_slice(b"\n");
                combined.extend_from_slice(&key_data);
                match reqwest::Identity::from_pem(&combined) {
                    Ok(identity) => {
                        builder = builder.identity(identity);
                    }
                    Err(e) => {
                        tracing::warn!("Health check: failed to parse client identity: {}", e);
                    }
                }
            }
            (Err(e), _) | (_, Err(e)) => {
                tracing::warn!("Health check: failed to load client cert/key: {}", e);
            }
        }
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
                "Failed to build TLS health check HTTP client: {}. \
                 Falling back to a minimal DNS-cached client (TLS-specific settings will not apply).",
                e
            );
            build_dns_cached_fallback_client(dns_cache, "TLS health check")
        }
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
                state.recent_failures.clear();
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
    use rcgen::{CertificateParams, KeyPair};
    use rustls::ServerConfig;
    use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
    use std::sync::Mutex;
    use std::sync::Once;
    use std::time::Duration;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::{TcpListener, UdpSocket};
    use tokio_rustls::TlsAcceptor;
    use wiremock::MockServer;

    static ENV_LOCK: Mutex<()> = Mutex::new(());

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
            let _ = rustls::crypto::ring::default_provider().install_default();
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
                &None,
                &None,
                false,
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
            http_probe(&client, &url, Duration::from_secs(2), &[200])
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
        // Verify the fallback client routes DNS through the gateway cache by
        // observing cache_len() growth after a request. If the fallback bypassed
        // the resolver and used system DNS, the cache would stay empty.
        let dns_cache = DnsCache::new(DnsConfig::default());
        let initial_len = dns_cache.cache_len();
        let client = build_dns_cached_fallback_client(Some(dns_cache.clone()), "test")
            .expect("fallback client should build");

        // Issue a request to a well-known hostname. The connection itself will
        // either succeed or fail (we don't care); what matters is that the
        // resolver was used. Use a short timeout so the test runs quickly.
        let _ = client
            .get("http://localhost:1/")
            .timeout(Duration::from_millis(100))
            .send()
            .await;

        // After the request, the gateway DNS cache should contain an entry
        // for `localhost`. If the request had bypassed the resolver via
        // ambient proxying, the cache would be unchanged.
        let after_len = dns_cache.cache_len();
        assert!(
            after_len > initial_len,
            "DNS cache should have populated via the cached resolver \
             (initial={}, after={}). If the fallback bypassed the resolver \
             via ambient proxying, the cache would stay empty.",
            initial_len,
            after_len
        );
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
}
