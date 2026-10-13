//! Cleanup-eviction recheck for `GenericPool` (issue #6178).
//!
//! The cleanup sweep first selects stale/unhealthy keys, then evicts them.
//! Between selection and removal a request can refresh the entry or replace
//! an unhealthy handle with a healthy one, so eviction must recheck the
//! current entry instead of removing on the stale selection alone.
//!
//! The test manager makes that interleaving deterministic: once armed, its
//! next `is_healthy` call (the sweep's selection pass) reports unhealthy,
//! and every later call reports healthy — exactly the state a concurrent
//! refresh/replacement would leave behind. With an unconditional remove the
//! entry is destroyed; with the recheck it survives.

use async_trait::async_trait;
use chrono::Utc;
use ferrum_edge::config::PoolConfig;
use ferrum_edge::config::types::{
    AuthMode, BackendScheme, BackendTlsConfig, DispatchKind, Proxy, ResponseBodyMode,
};
use ferrum_edge::pool::{GenericPool, PoolManager};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::time::Duration;

#[derive(Default)]
struct CleanupRecheckManager {
    destroys: AtomicUsize,
    /// Standing health answer when `fail_next_health_check` is not armed.
    healthy: AtomicBool,
    /// When armed, the next `is_healthy` call returns `false` exactly once.
    fail_next_health_check: AtomicBool,
}

#[async_trait]
impl PoolManager for CleanupRecheckManager {
    type Connection = String;

    fn build_key(&self, _proxy: &Proxy, host: &str, port: u16, shard: usize, buf: &mut String) {
        use std::fmt::Write;
        buf.clear();
        let _ = write!(buf, "{host}|{port}|{shard}");
    }

    async fn create(&self, key: &str, _proxy: &Proxy) -> anyhow::Result<Self::Connection> {
        Ok(key.to_string())
    }

    fn is_healthy(&self, _conn: &Self::Connection) -> bool {
        if self.fail_next_health_check.swap(false, Ordering::Relaxed) {
            return false;
        }
        self.healthy.load(Ordering::Relaxed)
    }

    fn destroy(&self, _conn: Self::Connection) {
        self.destroys.fetch_add(1, Ordering::Relaxed);
    }
}

fn test_proxy() -> Proxy {
    let now = Utc::now();
    Proxy {
        labels: Default::default(),
        id: "pool-cleanup-recheck-test".to_string(),
        namespace: ferrum_edge::config::types::default_namespace(),
        name: None,
        hosts: vec![],
        listen_path: Some("/pool".to_string()),
        backend_scheme: Some(BackendScheme::Http),
        dispatch_kind: DispatchKind::from(BackendScheme::Http),
        backend_host: "backend.example.com".to_string(),
        backend_port: 8080,
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
        dispatch_port_overrides: None,
        dispatch_port_override_fallback: None,
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
        h2_upgrade_policy: None,
        pool_max_requests_per_connection: None,
        pool_http1_max_pending_requests: None,
        upstream_id: None,
        upstream_subset: None,
        api_spec_id: None,
        circuit_breaker: None,
        retry: None,
        response_body_mode: ResponseBodyMode::default(),
        listen_port: None,
        frontend_tls: false,
        passthrough: false,
        udp_idle_timeout_seconds: 60,
        tcp_idle_timeout_seconds: Some(300),
        websocket_idle_timeout_seconds: None,
        websocket_permessage_deflate: Default::default(),
        allow_path_parameters: false,
        allowed_methods: None,
        allowed_ws_origins: vec![],
        udp_max_response_amplification_factor: None,
        stream_proxy_protocol: None,
        backend_proxy_protocol: None,
        stream_match: None,
        compiled_stream_match: None,
        created_at: now,
        updated_at: now,
        pending_limit_scope: None,
    }
}

#[tokio::test]
async fn cleanup_recheck_keeps_entry_healthy_again_before_removal() {
    let manager = Arc::new(CleanupRecheckManager {
        healthy: AtomicBool::new(true),
        ..Default::default()
    });
    // Long idle timeout (the PoolConfig default) so only the health half of
    // the eviction decision can fire; short cleanup interval so several
    // sweeps run inside the test.
    let pool = GenericPool::new(
        manager.clone(),
        PoolConfig::default(),
        Duration::from_millis(10),
        64,
    );
    let proxy = test_proxy();
    pool.get(&proxy, "backend.example.com", 443, 0)
        .await
        .expect("initial create succeeds");
    assert_eq!(pool.pool_size(), 1);

    // The next sweep's selection pass sees the entry as unhealthy and
    // selects its key; by removal time the entry reads healthy again, as
    // after a concurrent refresh/replacement.
    manager
        .fail_next_health_check
        .store(true, Ordering::Relaxed);
    tokio::time::sleep(Duration::from_millis(100)).await;

    assert_eq!(
        pool.pool_size(),
        1,
        "an entry healthy again at removal time must survive stale cleanup selection"
    );
    assert_eq!(
        manager.destroys.load(Ordering::Relaxed),
        0,
        "the surviving handle must not be destroyed"
    );
}

#[tokio::test]
async fn cleanup_still_evicts_entry_unhealthy_at_removal() {
    let manager = Arc::new(CleanupRecheckManager {
        healthy: AtomicBool::new(true),
        ..Default::default()
    });
    let pool = GenericPool::new(
        manager.clone(),
        PoolConfig::default(),
        Duration::from_millis(10),
        64,
    );
    let proxy = test_proxy();
    pool.get(&proxy, "backend.example.com", 443, 0)
        .await
        .expect("initial create succeeds");
    assert_eq!(pool.pool_size(), 1);

    // Unhealthy at selection and still unhealthy at removal: evicted.
    manager.healthy.store(false, Ordering::Relaxed);
    tokio::time::sleep(Duration::from_millis(100)).await;

    assert_eq!(pool.pool_size(), 0);
    assert_eq!(manager.destroys.load(Ordering::Relaxed), 1);
}
