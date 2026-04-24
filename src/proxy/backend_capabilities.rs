//! Backend capability registry keyed by deduplicated backend target identity.
//!
//! The request hot path consults this registry to decide whether plain HTTPS
//! traffic should use the native HTTP/3 pool, the direct HTTP/2 pool, or the
//! generic reqwest path. Capabilities are learned at startup and refreshed by
//! a background task so protocol discovery stays out of the hot proxy path.

use dashmap::DashMap;
use std::cell::RefCell;
use std::fmt::Write;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use crate::config::types::{BackendScheme, Proxy, UpstreamTarget};

thread_local! {
    /// Reused per-thread buffer for capability-key lookups on the request hot
    /// path. Mirrors the zero-allocation strategy used by `HTTP2_POOL_KEY_BUF`
    /// so `BackendCapabilityRegistry::get()` adds no per-request allocation.
    static CAPABILITY_KEY_BUF: RefCell<String> = RefCell::new(String::with_capacity(192));
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProtocolSupport {
    Unknown,
    Supported,
    Unsupported,
}

impl ProtocolSupport {
    #[inline]
    pub fn is_supported(self) -> bool {
        matches!(self, Self::Supported)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PlainHttpCapabilities {
    pub h1: ProtocolSupport,
    pub h2_tls: ProtocolSupport,
    pub h3: ProtocolSupport,
}

impl Default for PlainHttpCapabilities {
    fn default() -> Self {
        Self {
            h1: ProtocolSupport::Unknown,
            h2_tls: ProtocolSupport::Unknown,
            h3: ProtocolSupport::Unknown,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct GrpcTransportCapabilities {
    pub h2_tls: ProtocolSupport,
    pub h2c: ProtocolSupport,
}

impl Default for GrpcTransportCapabilities {
    fn default() -> Self {
        Self {
            h2_tls: ProtocolSupport::Unknown,
            h2c: ProtocolSupport::Unknown,
        }
    }
}

#[derive(Debug, Clone)]
pub struct BackendCapabilityRecord {
    pub plain_http: PlainHttpCapabilities,
    pub grpc_transport: GrpcTransportCapabilities,
    pub last_probe_at_unix_secs: u64,
    pub last_probe_error: Option<String>,
}

impl Default for BackendCapabilityRecord {
    fn default() -> Self {
        Self {
            plain_http: PlainHttpCapabilities::default(),
            grpc_transport: GrpcTransportCapabilities::default(),
            last_probe_at_unix_secs: now_unix_secs(),
            last_probe_error: None,
        }
    }
}

#[derive(Debug, Clone)]
pub struct BackendCapabilityProbeTarget {
    pub key: String,
    /// Proxy clone with `backend_host` / `backend_port` rebased to the probe
    /// target. Probe helpers that take `&Proxy` read `.backend_host` /
    /// `.backend_port` directly — no separate host/port fields needed.
    pub proxy: Proxy,
}

impl BackendCapabilityProbeTarget {
    pub fn from_proxy(proxy: &Proxy, target: Option<&UpstreamTarget>) -> Self {
        let mut probe_proxy = proxy.clone();
        if let Some(target) = target {
            probe_proxy.backend_host = target.host.clone();
            probe_proxy.backend_port = target.port;
        }
        let key = capability_key(&probe_proxy);
        Self {
            key,
            proxy: probe_proxy,
        }
    }

    #[inline]
    pub fn host(&self) -> &str {
        &self.proxy.backend_host
    }

    #[inline]
    pub fn port(&self) -> u16 {
        self.proxy.backend_port
    }

    #[inline]
    pub fn scheme(&self) -> BackendScheme {
        self.proxy.backend_scheme.unwrap_or(BackendScheme::Https)
    }
}

#[derive(Debug, Default)]
pub struct BackendCapabilityRegistry {
    entries: DashMap<String, Arc<BackendCapabilityRecord>>,
}

impl BackendCapabilityRegistry {
    pub fn new() -> Self {
        Self::default()
    }

    /// Hot-path lookup. Builds the key in a thread-local buffer — no
    /// per-request `Proxy` clone and no per-request `String` allocation on
    /// repeat calls from the same thread.
    pub fn get(
        &self,
        proxy: &Proxy,
        target: Option<&UpstreamTarget>,
    ) -> Option<Arc<BackendCapabilityRecord>> {
        CAPABILITY_KEY_BUF.with(|buf| {
            let mut buf = buf.borrow_mut();
            buf.clear();
            write_capability_key(&mut buf, proxy, target);
            self.entries
                .get(buf.as_str())
                .map(|entry| entry.value().clone())
        })
    }

    pub fn upsert(&self, key: String, record: BackendCapabilityRecord) {
        self.entries
            .entry(key)
            .and_modify(|entry| *entry = Arc::new(record.clone()))
            .or_insert_with(|| Arc::new(record));
    }

    /// Downgrade the cached H3 classification for a backend target to
    /// `Unsupported` after an observed H3 connection / protocol failure.
    /// No-op when the target has no cached record (the next periodic refresh
    /// will classify it from scratch).
    ///
    /// Called from the proxy hot path after a 502 with a connection-class
    /// error from the native H3 backend pool, so subsequent requests skip
    /// the H3 pool and route via the cross-protocol bridge instead of
    /// repeatedly failing against a backend whose QUIC listener rolled back
    /// between refresh cycles.
    pub fn mark_h3_unsupported(&self, proxy: &Proxy, target: Option<&UpstreamTarget>) {
        let key = capability_key_for_proxy_target(proxy, target);
        if let Some(mut entry) = self.entries.get_mut(&key)
            && !matches!(entry.plain_http.h3, ProtocolSupport::Unsupported)
        {
            let mut new_record = (**entry).clone();
            new_record.plain_http.h3 = ProtocolSupport::Unsupported;
            new_record.last_probe_at_unix_secs = now_unix_secs();
            new_record.last_probe_error =
                Some("H3 downgraded after connection/protocol failure on request path".to_string());
            *entry = Arc::new(new_record);
        }
    }

    pub fn retain_keys(&self, active_keys: &std::collections::HashSet<String>) {
        self.entries.retain(|key, _| active_keys.contains(key));
    }

    #[cfg(test)]
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    #[cfg(test)]
    pub fn contains_key(&self, key: &str) -> bool {
        self.entries.contains_key(key)
    }
}

/// Compute an owned capability key from a proxy + optional target. Cold path —
/// used once per unique probe target during setup. The request hot path should
/// go through `BackendCapabilityRegistry::get()` to reuse the thread-local
/// buffer.
pub fn capability_key_for_proxy_target(proxy: &Proxy, target: Option<&UpstreamTarget>) -> String {
    let mut buf = String::with_capacity(192);
    write_capability_key(&mut buf, proxy, target);
    buf
}

/// Compute an owned capability key from a proxy that already reflects its
/// target's host/port (i.e., a `BackendCapabilityProbeTarget.proxy`).
pub fn capability_key(proxy: &Proxy) -> String {
    capability_key_for_proxy_target(proxy, None)
}

/// Write the capability key into `buf`. Callers clear the buffer first if
/// they're reusing one (see `BackendCapabilityRegistry::get`).
///
/// Key shape: `scheme|host|port|dns_override|ca|mtls_cert|mtls_key|verify`.
/// `|` delimiter matches the pool-key conventions in the rest of the code.
fn write_capability_key(buf: &mut String, proxy: &Proxy, target: Option<&UpstreamTarget>) {
    let scheme = proxy.backend_scheme.unwrap_or(BackendScheme::Https);
    let (host, port) = match target {
        Some(t) => (t.host.as_str(), t.port),
        None => (proxy.backend_host.as_str(), proxy.backend_port),
    };
    let _ = write!(
        buf,
        "{}|{}|{}|{}|",
        scheme.to_scheme_str(),
        host,
        port,
        proxy.dns_override.as_deref().unwrap_or_default(),
    );
    buf.push_str(
        proxy
            .resolved_tls
            .server_ca_cert_path
            .as_deref()
            .unwrap_or_default(),
    );
    buf.push('|');
    buf.push_str(
        proxy
            .resolved_tls
            .client_cert_path
            .as_deref()
            .unwrap_or_default(),
    );
    buf.push('|');
    buf.push_str(
        proxy
            .resolved_tls
            .client_key_path
            .as_deref()
            .unwrap_or_default(),
    );
    buf.push('|');
    buf.push(if proxy.resolved_tls.verify_server_cert {
        '1'
    } else {
        '0'
    });
}

#[inline]
pub fn now_unix_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::SystemTime::UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .unwrap_or(0)
}

pub type SharedBackendCapabilityRegistry = Arc<BackendCapabilityRegistry>;

/// Single-flight + coalesce guard for `refresh_backend_capabilities`.
///
/// Callers flip `pending` to request a refresh. The first caller also flips
/// `running` and spawns the refresh task; subsequent callers leave `running`
/// alone and exit — the running task drains `pending` in a loop and then
/// uses a handoff-safe `try_finish()` that atomically re-checks `pending`
/// before releasing the runner role, so work queued mid-finish cannot be
/// orphaned. Invariants:
///
/// - At most one refresh task in flight at any moment.
/// - If a caller sets `pending` after the running task's last
///   `take_pending()` but before the runner releases `running`, the
///   runner observes the new pending flag in `try_finish()` and either
///   re-acquires the runner role itself or hands off to a freshly-spawned
///   task — no silent work loss.
#[derive(Debug, Default)]
pub struct RefreshCoalescer {
    running: AtomicBool,
    pending: AtomicBool,
}

impl RefreshCoalescer {
    pub fn new() -> Self {
        Self::default()
    }

    /// Mark refresh work as needed. Returns `true` if the caller just
    /// transitioned to the "runner" role and must drive the refresh loop
    /// in a spawned task; `false` means an existing runner will absorb
    /// this request.
    pub fn request(&self) -> bool {
        self.pending.store(true, Ordering::Release);
        !self.running.swap(true, Ordering::AcqRel)
    }

    /// Consume one pending flag. Returns `true` when a refresh should run,
    /// `false` when the inner drain loop has caught up.
    pub fn take_pending(&self) -> bool {
        self.pending.swap(false, Ordering::AcqRel)
    }

    /// Attempt to release the runner role. Returns `true` if the caller is
    /// truly done and should exit; `false` if a concurrent `request()`
    /// queued work during the finish window and the caller has re-acquired
    /// the runner role (must loop back to `take_pending()`).
    ///
    /// Guarantees no orphaned `pending` flag: every path leaves either
    /// `running=false, pending=false` (truly idle), or `running=true` with
    /// *some* task (this one or a freshly-spawned one) responsible for
    /// draining.
    pub fn try_finish(&self) -> bool {
        // Release the runner role. Any concurrent `request()` from here
        // onward sees `running=false` and spawns a fresh runner, so the
        // only race is with a caller that already passed its
        // `running.swap` *before* this store (i.e. coalesced while we
        // were still running).
        self.running.store(false, Ordering::Release);
        if !self.pending.load(Ordering::Acquire) {
            return true;
        }
        // Pending is set and we just cleared `running`. Try to re-acquire
        // the runner role. `swap` returns the old value:
        // - old was `false` (we set it true): WE re-acquired → return
        //   `false` so the caller loops back and drains.
        // - old was `true` (a fresh `request()` already became the new
        //   runner): they own the drain → return `true` so the caller
        //   exits cleanly.
        self.running.swap(true, Ordering::AcqRel)
    }
}

pub type SharedRefreshCoalescer = Arc<RefreshCoalescer>;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::types::{
        AuthMode, BackendScheme, BackendTlsConfig, DispatchKind, Proxy, ResponseBodyMode,
    };
    use chrono::Utc;

    fn minimal_proxy() -> Proxy {
        let now = Utc::now();
        Proxy {
            id: "p1".to_string(),
            namespace: crate::config::types::default_namespace(),
            name: None,
            hosts: vec![],
            listen_path: Some("/".to_string()),
            backend_scheme: Some(BackendScheme::Https),
            dispatch_kind: DispatchKind::from(BackendScheme::Https),
            backend_host: "backend.test".to_string(),
            backend_port: 443,
            backend_path: None,
            strip_listen_path: true,
            preserve_host_header: false,
            backend_connect_timeout_ms: 5_000,
            backend_read_timeout_ms: 30_000,
            backend_write_timeout_ms: 30_000,
            backend_tls_client_cert_path: None,
            backend_tls_client_key_path: None,
            backend_tls_verify_server_cert: true,
            backend_tls_server_ca_cert_path: None,
            resolved_tls: BackendTlsConfig::default_verify(),
            dns_override: None,
            dns_cache_ttl_seconds: None,
            auth_mode: AuthMode::Single,
            plugins: vec![],
            pool_idle_timeout_seconds: None,
            pool_enable_http_keep_alive: None,
            pool_enable_http2: None,
            pool_tcp_keepalive_seconds: None,
            pool_http2_keep_alive_interval_seconds: None,
            pool_http2_keep_alive_timeout_seconds: None,
            pool_http2_initial_stream_window_size: None,
            pool_http2_initial_connection_window_size: None,
            pool_http2_adaptive_window: None,
            pool_http2_max_frame_size: None,
            pool_http2_max_concurrent_streams: None,
            pool_http3_connections_per_backend: None,
            upstream_id: None,
            circuit_breaker: None,
            retry: None,
            response_body_mode: ResponseBodyMode::default(),
            listen_port: None,
            frontend_tls: false,
            passthrough: false,
            udp_idle_timeout_seconds: 60,
            tcp_idle_timeout_seconds: Some(300),
            allowed_methods: None,
            allowed_ws_origins: vec![],
            udp_max_response_amplification_factor: None,
            created_at: now,
            updated_at: now,
        }
    }

    #[test]
    fn registry_get_returns_none_before_upsert() {
        let registry = BackendCapabilityRegistry::new();
        let proxy = minimal_proxy();
        assert!(registry.get(&proxy, None).is_none());
    }

    #[test]
    fn registry_upsert_stores_and_get_reads_same_key() {
        let registry = BackendCapabilityRegistry::new();
        let proxy = minimal_proxy();
        let key = capability_key(&proxy);
        let mut record = BackendCapabilityRecord::default();
        record.plain_http.h2_tls = ProtocolSupport::Supported;
        record.plain_http.h3 = ProtocolSupport::Supported;
        registry.upsert(key, record);

        let fetched = registry.get(&proxy, None).expect("entry should exist");
        assert!(fetched.plain_http.h2_tls.is_supported());
        assert!(fetched.plain_http.h3.is_supported());
        assert!(!fetched.plain_http.h1.is_supported());
    }

    #[test]
    fn registry_upsert_overwrites_existing_entry() {
        let registry = BackendCapabilityRegistry::new();
        let proxy = minimal_proxy();
        let key = capability_key(&proxy);

        let mut first = BackendCapabilityRecord::default();
        first.plain_http.h2_tls = ProtocolSupport::Supported;
        registry.upsert(key.clone(), first);

        let mut second = BackendCapabilityRecord::default();
        second.plain_http.h2_tls = ProtocolSupport::Unsupported;
        second.plain_http.h1 = ProtocolSupport::Supported;
        registry.upsert(key, second);

        let fetched = registry.get(&proxy, None).unwrap();
        assert!(!fetched.plain_http.h2_tls.is_supported());
        assert!(fetched.plain_http.h1.is_supported());
    }

    #[test]
    fn registry_retain_keys_prunes_inactive_entries() {
        let registry = BackendCapabilityRegistry::new();
        let proxy = minimal_proxy();
        let key = capability_key(&proxy);
        registry.upsert(key.clone(), BackendCapabilityRecord::default());

        let mut active = std::collections::HashSet::new();
        active.insert("some-other-key".to_string());
        registry.retain_keys(&active);

        assert!(registry.get(&proxy, None).is_none());
        assert!(registry.is_empty());
    }

    #[test]
    fn registry_mark_h3_unsupported_downgrades_supported_entry() {
        let registry = BackendCapabilityRegistry::new();
        let proxy = minimal_proxy();
        let key = capability_key(&proxy);
        let mut record = BackendCapabilityRecord::default();
        record.plain_http.h3 = ProtocolSupport::Supported;
        record.plain_http.h2_tls = ProtocolSupport::Supported;
        registry.upsert(key, record);

        registry.mark_h3_unsupported(&proxy, None);

        let fetched = registry.get(&proxy, None).expect("entry must exist");
        assert_eq!(fetched.plain_http.h3, ProtocolSupport::Unsupported);
        assert!(
            fetched.last_probe_error.is_some(),
            "downgrade should stamp last_probe_error for operator visibility"
        );
        // H2 classification must NOT be affected — only H3 was observed broken.
        assert!(fetched.plain_http.h2_tls.is_supported());
    }

    #[test]
    fn registry_mark_h3_unsupported_is_noop_when_no_cached_entry() {
        let registry = BackendCapabilityRegistry::new();
        let proxy = minimal_proxy();
        // No upsert — mark_h3_unsupported must not panic or create a phantom entry.
        registry.mark_h3_unsupported(&proxy, None);
        assert!(registry.get(&proxy, None).is_none());
    }

    #[test]
    fn registry_mark_h3_unsupported_is_idempotent() {
        let registry = BackendCapabilityRegistry::new();
        let proxy = minimal_proxy();
        let key = capability_key(&proxy);
        let mut record = BackendCapabilityRecord::default();
        record.plain_http.h3 = ProtocolSupport::Unsupported;
        registry.upsert(key, record);

        // Second downgrade should be a cheap no-op — no allocation, no replacement.
        registry.mark_h3_unsupported(&proxy, None);
        let fetched = registry.get(&proxy, None).unwrap();
        assert_eq!(fetched.plain_http.h3, ProtocolSupport::Unsupported);
    }

    #[test]
    fn registry_retain_keys_keeps_active_entries() {
        let registry = BackendCapabilityRegistry::new();
        let proxy = minimal_proxy();
        let key = capability_key(&proxy);
        registry.upsert(key.clone(), BackendCapabilityRecord::default());

        let mut active = std::collections::HashSet::new();
        active.insert(key.clone());
        registry.retain_keys(&active);

        assert!(registry.contains_key(&key));
    }

    #[test]
    fn refresh_coalescer_first_request_becomes_runner() {
        let coalescer = RefreshCoalescer::new();
        assert!(
            coalescer.request(),
            "first request should transition to runner role"
        );
    }

    #[test]
    fn refresh_coalescer_subsequent_request_coalesces() {
        let coalescer = RefreshCoalescer::new();
        assert!(coalescer.request());
        // Runner hasn't finished yet — a second request must NOT spawn a new
        // runner; instead the in-flight one will absorb via take_pending().
        assert!(!coalescer.request());
        assert!(!coalescer.request());
    }

    #[test]
    fn refresh_coalescer_drains_pending_requests_across_iterations() {
        let coalescer = RefreshCoalescer::new();
        assert!(coalescer.request());
        // Simulate a runner loop:
        assert!(coalescer.take_pending(), "first drain sees pending=true");

        // While the refresh is "running", another caller arrives:
        assert!(!coalescer.request(), "coalesced call does not re-spawn");

        // Runner's next iteration still sees pending.
        assert!(
            coalescer.take_pending(),
            "pending re-set during refresh must be observed"
        );
        // No more pending now.
        assert!(!coalescer.take_pending());
        assert!(coalescer.try_finish(), "idle runner finishes cleanly");

        // After finish, a new request becomes a fresh runner.
        assert!(coalescer.request());
    }

    #[test]
    fn refresh_coalescer_try_finish_detects_coalesced_mid_finish_request() {
        // Regression test for the handoff race: a caller that coalesced
        // between the runner's last `take_pending()` and its release of
        // the runner role must not be stranded.
        let coalescer = RefreshCoalescer::new();
        assert!(coalescer.request(), "initial runner");
        assert!(coalescer.take_pending(), "drain initial work");
        assert!(!coalescer.take_pending(), "no more work");

        // Simulate a caller that races the runner's finish: they set
        // `pending` and swap `running`, observing running=true (still set
        // by the current runner) and so coalesce.
        assert!(
            !coalescer.request(),
            "caller mid-finish coalesces with the running runner"
        );

        // Now the runner calls try_finish. It must observe the
        // just-coalesced pending flag and re-acquire the runner role
        // rather than leaving it stranded.
        assert!(
            !coalescer.try_finish(),
            "try_finish must not release when pending is set; it re-acquires the runner role"
        );
        assert!(
            coalescer.take_pending(),
            "re-acquired runner drains the coalesced pending flag"
        );
        assert!(!coalescer.take_pending(), "no further work");
        assert!(coalescer.try_finish(), "final try_finish releases cleanly");
    }

    #[test]
    fn refresh_coalescer_try_finish_idle_case_exits_cleanly() {
        // Straight happy-path: no one queued work during the finish window,
        // so try_finish must release the runner role and return `true`.
        let coalescer = RefreshCoalescer::new();
        assert!(coalescer.request());
        assert!(coalescer.take_pending());
        assert!(!coalescer.take_pending());
        assert!(coalescer.try_finish(), "idle try_finish exits cleanly");
        // A fresh request is now a new runner (running is released).
        assert!(
            coalescer.request(),
            "after try_finish, next request is runner"
        );
    }

    /// Stress test: race many `request()` calls against runner loops using
    /// `try_finish`. For every `request()` issued, at least one refresh
    /// must end up being counted — no pending flag may be orphaned.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn refresh_coalescer_no_orphaned_pending_under_contention() {
        use std::sync::atomic::AtomicU64;
        use std::sync::atomic::Ordering as AO;

        let coalescer = Arc::new(RefreshCoalescer::new());
        let refreshes = Arc::new(AtomicU64::new(0));
        let requests = Arc::new(AtomicU64::new(0));

        // Runner loop mimics `spawn_backend_capability_refresh`'s spawn
        // closure, with a lightweight "refresh" (just a counter bump).
        fn spawn_runner(
            coalescer: Arc<RefreshCoalescer>,
            refreshes: Arc<AtomicU64>,
        ) -> tokio::task::JoinHandle<()> {
            tokio::spawn(async move {
                loop {
                    while coalescer.take_pending() {
                        refreshes.fetch_add(1, AO::Relaxed);
                        // Yield to give other tasks a chance to race.
                        tokio::task::yield_now().await;
                    }
                    if coalescer.try_finish() {
                        break;
                    }
                }
            })
        }

        let mut handles = Vec::new();
        // Many concurrent requesters.
        for _ in 0..64 {
            let coalescer = coalescer.clone();
            let requests = requests.clone();
            let refreshes = refreshes.clone();
            handles.push(tokio::spawn(async move {
                for _ in 0..50 {
                    requests.fetch_add(1, AO::Relaxed);
                    if coalescer.request() {
                        // We became the runner — spawn the drain loop.
                        spawn_runner(coalescer.clone(), refreshes.clone());
                    }
                    tokio::task::yield_now().await;
                }
            }));
        }

        for h in handles {
            h.await.unwrap();
        }

        // Let any in-flight runners drain.
        for _ in 0..50 {
            tokio::task::yield_now().await;
            tokio::time::sleep(std::time::Duration::from_millis(1)).await;
        }

        // After quiescence:
        // 1. No pending flag may remain set.
        // 2. No runner role may remain held (otherwise a late caller would
        //    coalesce forever).
        assert!(
            !coalescer.pending.load(AO::Acquire),
            "pending flag leaked after quiescence"
        );
        assert!(
            !coalescer.running.load(AO::Acquire),
            "running flag leaked after quiescence"
        );
        // And: at least one refresh must have happened per requester
        // burst (coalescing allowed, but total loss of a flag is not).
        let r = refreshes.load(AO::Relaxed);
        let q = requests.load(AO::Relaxed);
        assert!(r >= 1, "no refreshes ran despite {q} requests");
        assert!(
            r <= q,
            "impossibly many refreshes ({r}) for {q} requests — sanity check"
        );
    }
}
