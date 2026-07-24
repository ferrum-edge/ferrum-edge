//! Behavioral coverage for GenericPool create-failure fan-out (#2950).
//!
//! External (non-inline) tests for: one-create fan-out, creator cancel/drop,
//! later independent retry, and pool-key isolation. Classification parity for
//! H2/gRPC/H3 adapters lives in `pool_create_failure_classification_tests.rs`.

use async_trait::async_trait;
use chrono::Utc;
use ferrum_edge::config::PoolConfig;
use ferrum_edge::config::types::{
    AuthMode, BackendScheme, BackendTlsConfig, DispatchKind, Proxy, ResponseBodyMode,
};
use ferrum_edge::pool::{GenericPool, PoolManager, SharedPoolCreateError};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::time::Duration;
use tokio::sync::Notify;

#[derive(Default)]
struct FanoutTestManager {
    attempts: AtomicUsize,
    creates: AtomicUsize,
    healthy: AtomicBool,
    fail_creates_remaining: AtomicUsize,
    create_delay: Duration,
}

#[async_trait]
impl PoolManager for FanoutTestManager {
    type Connection = String;

    fn build_key(&self, _proxy: &Proxy, host: &str, port: u16, shard: usize, buf: &mut String) {
        use std::fmt::Write;
        buf.clear();
        let _ = write!(buf, "{host}|{port}|{shard}");
    }

    async fn create(&self, key: &str, _proxy: &Proxy) -> anyhow::Result<Self::Connection> {
        if !self.create_delay.is_zero() {
            tokio::time::sleep(self.create_delay).await;
        }
        self.attempts.fetch_add(1, Ordering::Relaxed);
        if self
            .fail_creates_remaining
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |remaining| {
                (remaining > 0).then(|| remaining - 1)
            })
            .is_ok()
        {
            anyhow::bail!("synthetic create failure for {key}");
        }
        let generation = self.creates.fetch_add(1, Ordering::Relaxed) + 1;
        Ok(format!("{key}|gen={generation}"))
    }

    fn is_healthy(&self, _conn: &Self::Connection) -> bool {
        self.healthy.load(Ordering::Relaxed)
    }

    fn destroy(&self, _conn: Self::Connection) {}
}

fn test_proxy() -> Proxy {
    let now = Utc::now();
    Proxy {
        id: "pool-fanout-test".to_string(),
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
        allowed_methods: None,
        allowed_ws_origins: vec![],
        udp_max_response_amplification_factor: None,
        stream_proxy_protocol: None,
        created_at: now,
        updated_at: now,
    }
}

#[tokio::test(start_paused = true)]
async fn external_generic_pool_fans_out_one_create_failure_to_all_waiters() {
    let create_delay = Duration::from_millis(50);
    let manager = Arc::new(FanoutTestManager {
        healthy: AtomicBool::new(true),
        fail_creates_remaining: AtomicUsize::new(1),
        create_delay,
        ..Default::default()
    });
    let pool = GenericPool::new(
        manager.clone(),
        PoolConfig::default(),
        Duration::from_secs(60),
        64,
    );
    let proxy = test_proxy();
    let waiter_count = 16;

    let started = tokio::time::Instant::now();
    let mut tasks = Vec::new();
    for _ in 0..waiter_count {
        let pool = pool.clone();
        let proxy = proxy.clone();
        tasks.push(tokio::spawn(async move {
            pool.get(&proxy, "backend.example.com", 443, 0).await
        }));
    }

    let mut results = Vec::new();
    for task in tasks {
        results.push(task.await.unwrap());
    }
    let elapsed = started.elapsed();

    assert!(
        results.iter().all(|result| result.is_err()),
        "every coalesced waiter must observe the creation failure"
    );
    assert_eq!(
        manager.attempts.load(Ordering::Relaxed),
        1,
        "only one create attempt should run for the failed coalesced create"
    );
    assert_eq!(manager.creates.load(Ordering::Relaxed), 0);
    assert!(
        elapsed < create_delay.saturating_mul(3),
        "failure fan-out must not serially redial (elapsed {elapsed:?})"
    );
    assert!(
        elapsed >= create_delay,
        "waiters should wait for the single in-flight create (elapsed {elapsed:?})"
    );

    let shared_messages: Vec<&str> = results
        .iter()
        .filter_map(|result| {
            let err = result.as_ref().unwrap_err();
            err.downcast_ref::<SharedPoolCreateError>()
                .map(SharedPoolCreateError::message)
        })
        .collect();
    assert_eq!(
        shared_messages.len(),
        waiter_count - 1,
        "one creator must retain its original error while every waiter receives the shared error"
    );
    assert!(
        shared_messages.windows(2).all(|pair| pair[0] == pair[1]),
        "all waiters must receive the same shared failure payload: {shared_messages:?}"
    );
    assert!(
        !shared_messages[0].is_empty(),
        "shared failure message must be non-empty"
    );

    // Later independent request can succeed (no durable negative cache).
    let recovered = pool
        .get(&proxy, "backend.example.com", 443, 0)
        .await
        .expect("independent request after failed coalesced create should retry create");
    assert!(recovered.contains("gen=1"));
    assert_eq!(manager.attempts.load(Ordering::Relaxed), 2);
    assert_eq!(manager.creates.load(Ordering::Relaxed), 1);
}

#[tokio::test(start_paused = true)]
async fn external_generic_pool_create_failure_fanout_is_key_scoped() {
    let create_delay = Duration::from_millis(40);
    let manager = Arc::new(FanoutTestManager {
        healthy: AtomicBool::new(true),
        fail_creates_remaining: AtomicUsize::new(1),
        create_delay,
        ..Default::default()
    });
    let pool = GenericPool::new(
        manager.clone(),
        PoolConfig::default(),
        Duration::from_secs(60),
        64,
    );
    let proxy = test_proxy();

    let mut tasks = Vec::new();
    for _ in 0..8 {
        let pool = pool.clone();
        let proxy = proxy.clone();
        tasks.push(tokio::spawn(async move {
            pool.get(&proxy, "backend.example.com", 443, 0).await
        }));
    }
    for task in tasks {
        assert!(
            task.await.unwrap().is_err(),
            "shard-0 coalesced waiters must all observe the failure"
        );
    }
    assert_eq!(manager.attempts.load(Ordering::Relaxed), 1);

    let other = pool
        .get(&proxy, "backend.example.com", 443, 1)
        .await
        .expect("distinct key should create independently after peer-key failure");
    assert!(other.contains("|1|"));
    assert_eq!(manager.attempts.load(Ordering::Relaxed), 2);
    assert_eq!(manager.creates.load(Ordering::Relaxed), 1);
}

#[tokio::test]
async fn external_generic_pool_clears_pending_state_when_creator_is_cancelled() {
    let manager = Arc::new(FanoutTestManager {
        healthy: AtomicBool::new(true),
        ..Default::default()
    });
    let pool = GenericPool::new(manager, PoolConfig::default(), Duration::from_secs(60), 64);
    let key = "backend.example.com|443|0".to_string();
    let creator_started = Arc::new(Notify::new());
    let creator_blocked = Arc::new(Notify::new());

    let creator = {
        let pool = pool.clone();
        let key = key.clone();
        let creator_started = creator_started.clone();
        let creator_blocked = creator_blocked.clone();
        tokio::spawn(async move {
            pool.create_or_get_existing_owned(key, move |_key| {
                let creator_started = creator_started.clone();
                let creator_blocked = creator_blocked.clone();
                async move {
                    creator_started.notify_waiters();
                    creator_blocked.notified().await;
                    Ok::<_, anyhow::Error>("creator-cancelled".to_string())
                }
            })
            .await
        })
    };

    creator_started.notified().await;

    let waiter = {
        let pool = pool.clone();
        let key = key.clone();
        tokio::spawn(async move {
            pool.create_or_get_existing_owned(key, move |_key| async move {
                Ok::<_, anyhow::Error>("recovered-after-cancel".to_string())
            })
            .await
            .unwrap()
        })
    };

    // Creator is blocked inside create(); yield so the waiter can register on
    // the same pending entry before we abort. (Inline coverage additionally
    // probes pending Arc strong_count; that map is not part of the public API.)
    for _ in 0..256 {
        tokio::task::yield_now().await;
    }

    creator.abort();
    assert!(creator.await.unwrap_err().is_cancelled());

    let waiter_result = tokio::time::timeout(Duration::from_secs(1), waiter)
        .await
        .expect("waiter should be retried after creator cancellation")
        .unwrap();
    assert_eq!(waiter_result, "recovered-after-cancel");
    assert_eq!(pool.cached(&key).as_deref(), Some("recovered-after-cancel"));
}
