//! Ambient-proxy isolation for policy-governed backend reqwest clients.

use chrono::Utc;
use ferrum_edge::config::PoolConfig;
use ferrum_edge::config::types::{
    AuthMode, BackendScheme, BackendTlsConfig, DispatchKind, Proxy, ResponseBodyMode,
};
use ferrum_edge::connection_pool::ConnectionPool;
use ferrum_edge::dns::{DnsCache, DnsConfig};
use futures_util::FutureExt as _;
use std::sync::Arc;
use std::time::Duration;
use wiremock::MockServer;

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
            // SAFETY: the repository-wide ENV_LOCK is held until the guard drops.
            unsafe { std::env::set_var(key, proxy_url) };
        }
        for &key in &PROXY_KEYS[6..] {
            // SAFETY: serialized by the same repository-wide ENV_LOCK.
            unsafe { std::env::remove_var(key) };
        }
        Self { saved }
    }
}

impl Drop for ProxyEnvGuard {
    fn drop(&mut self) {
        for (key, value) in &self.saved {
            // SAFETY: the caller still holds ENV_LOCK while this guard drops.
            unsafe {
                match value {
                    Some(value) => std::env::set_var(*key, value),
                    None => std::env::remove_var(*key),
                }
            }
        }
    }
}

fn minimal_proxy() -> Proxy {
    let now = Utc::now();
    Proxy {
        id: "test-proxy".to_string(),
        namespace: ferrum_edge::config::types::default_namespace(),
        name: None,
        hosts: vec![],
        listen_path: Some("/test".to_string()),
        backend_scheme: Some(BackendScheme::Http),
        dispatch_kind: DispatchKind::from(BackendScheme::Http),
        backend_host: "backend.example.com".to_string(),
        backend_port: 8080,
        backend_path: None,
        strip_listen_path: true,
        preserve_host_header: false,
        backend_connect_timeout_ms: 5000,
        backend_read_timeout_ms: 30000,
        backend_write_timeout_ms: 30000,
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
        allowed_methods: None,
        allowed_ws_origins: vec![],
        udp_max_response_amplification_factor: None,
        stream_proxy_protocol: None,
        created_at: now,
        updated_at: now,
    }
}

#[tokio::test(flavor = "current_thread")]
async fn connection_pool_backend_client_ignores_ambient_proxy_environment() {
    let proxy_server = MockServer::start().await;
    let dns = DnsCache::new(DnsConfig::default());
    let env_config = ferrum_edge::config::EnvConfig::default();
    let pool = ConnectionPool::new(
        PoolConfig::default(),
        env_config,
        dns,
        None,
        Arc::new(Vec::new()),
    );
    let proxy = minimal_proxy();

    let client = {
        let _env_lock = crate::unit::env_lock::ENV_LOCK
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let _proxy_env = ProxyEnvGuard::point_all_at(&proxy_server.uri());
        // Backend reqwest builders call `.no_proxy()`, but keep ambient proxy
        // variables set through the synchronous pool-miss path so a dropped
        // `.no_proxy()` fails CI. `now_or_never` avoids holding ENV_LOCK
        // across `.await` while the first client is created.
        pool.get_client(&proxy)
            .now_or_never()
            .expect("backend pool client creation should not yield while env is set")
            .expect("backend pool client should build")
    };

    let _ = client
        .get("http://198.51.100.1:9/no-proxy-canary")
        .timeout(Duration::from_millis(200))
        .send()
        .await;

    assert_eq!(
        proxy_server
            .received_requests()
            .await
            .unwrap_or_default()
            .len(),
        0,
        "ambient proxy variables must not receive backend dispatch traffic"
    );
}
