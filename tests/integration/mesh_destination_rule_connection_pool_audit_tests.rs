//! Black-box compatibility checks for DestinationRule connectionPool semantics.
//!
//! These tests intentionally observe real backend sockets instead of only
//! asserting serialized projection. They pin the unsupported cases that must be
//! reported as deferred rather than represented as effective resource limits.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use bytes::Bytes;
use chrono::Utc;
use ferrum_edge::config::types::{
    AuthMode, BackendScheme, DispatchKind, Proxy, ResolvedPortOverride,
};
use ferrum_edge::config::{EnvConfig, PoolConfig};
use ferrum_edge::connection_pool::ConnectionPool;
use ferrum_edge::dns::{DnsCache, DnsConfig};
use http_body_util::Full;
use hyper::body::Incoming;
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper::{Request, Response};
use hyper_util::rt::TokioIo;
use tokio::net::TcpListener;

fn proxy_for_backend(port: u16) -> Proxy {
    Proxy {
        id: "dr-connection-pool-audit".to_string(),
        namespace: ferrum_edge::config::types::default_namespace(),
        name: None,
        hosts: vec![],
        listen_path: Some("/".to_string()),
        backend_scheme: Some(BackendScheme::Http),
        dispatch_kind: DispatchKind::from(BackendScheme::Http),
        backend_host: "127.0.0.1".to_string(),
        backend_port: port,
        backend_path: None,
        strip_listen_path: false,
        preserve_host_header: false,
        backend_connect_timeout_ms: 5_000,
        backend_read_timeout_ms: 30_000,
        backend_write_timeout_ms: 30_000,
        backend_tls_client_cert_path: None,
        backend_tls_client_key_path: None,
        backend_tls_verify_server_cert: true,
        backend_tls_server_ca_cert_path: None,
        resolved_tls: Default::default(),
        dispatch_port_overrides: None,
        dispatch_port_override_fallback: None,
        dns_override: None,
        dns_cache_ttl_seconds: None,
        auth_mode: AuthMode::Single,
        plugins: vec![],
        pool_idle_timeout_seconds: Some(60),
        pool_enable_http_keep_alive: Some(true),
        pool_enable_http2: Some(false),
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
        response_body_mode: Default::default(),
        listen_port: None,
        frontend_tls: false,
        passthrough: false,
        udp_idle_timeout_seconds: 60,
        tcp_idle_timeout_seconds: Some(300),
        allowed_methods: None,
        allowed_ws_origins: vec![],
        udp_max_response_amplification_factor: None,
        created_at: Utc::now(),
        updated_at: Utc::now(),
    }
}

fn reqwest_pool() -> ConnectionPool {
    ConnectionPool::new(
        PoolConfig::default(),
        EnvConfig::default(),
        DnsCache::new(DnsConfig::default()),
        None,
        Arc::new(Vec::new()),
    )
}

async fn start_counting_h1_backend(
    response_delay: Duration,
) -> (SocketAddr, Arc<AtomicUsize>, tokio::task::JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind counting backend");
    let addr = listener.local_addr().expect("backend addr");
    let accepted = Arc::new(AtomicUsize::new(0));
    let accepted_for_task = accepted.clone();

    let handle = tokio::spawn(async move {
        while let Ok((socket, _peer)) = listener.accept().await {
            accepted_for_task.fetch_add(1, Ordering::SeqCst);
            let delay = response_delay;
            tokio::spawn(async move {
                let service = service_fn(move |_req: Request<Incoming>| async move {
                    if !delay.is_zero() {
                        tokio::time::sleep(delay).await;
                    }
                    Ok::<_, hyper::Error>(Response::new(Full::new(Bytes::from_static(b"ok"))))
                });
                let _ = http1::Builder::new()
                    .keep_alive(true)
                    .serve_connection(TokioIo::new(socket), service)
                    .await;
            });
        }
    });

    (addr, accepted, handle)
}

#[tokio::test]
async fn max_requests_per_connection_does_not_close_h1_backend_after_n_requests() {
    let (backend, accepted, _backend_task) = start_counting_h1_backend(Duration::ZERO).await;
    let mut proxy = proxy_for_backend(backend.port());
    proxy.pool_max_requests_per_connection = Some(2);

    let pool = reqwest_pool();
    let client = pool.get_client(&proxy).await.expect("reqwest client");
    let url = format!("http://{}:{}/audit", backend.ip(), backend.port());

    for _ in 0..5 {
        let response = client.get(&url).send().await.expect("backend response");
        assert_eq!(response.status(), reqwest::StatusCode::OK);
        let _ = response.bytes().await.expect("body");
    }

    assert_eq!(
        accepted.load(Ordering::SeqCst),
        1,
        "five sequential requests with pool_max_requests_per_connection=2 stayed on one reusable backend socket; close-after-N is not implemented"
    );
}

#[tokio::test]
async fn max_connections_is_not_silently_approximated_on_reqwest_h1_sockets() {
    let (backend, accepted, _backend_task) =
        start_counting_h1_backend(Duration::from_millis(150)).await;
    let mut proxy = proxy_for_backend(backend.port());
    proxy.dispatch_port_overrides = Some(HashMap::from([(
        backend.port(),
        ResolvedPortOverride {
            max_connections: Some(1),
            ..ResolvedPortOverride::default()
        },
    )]));

    let pool = reqwest_pool();
    let client = pool.get_client(&proxy).await.expect("reqwest client");
    let url = format!("http://{}:{}/slow", backend.ip(), backend.port());

    let (first, second) = tokio::join!(client.get(&url).send(), client.get(&url).send());
    assert_eq!(
        first.expect("first response").status(),
        reqwest::StatusCode::OK
    );
    assert_eq!(
        second.expect("second response").status(),
        reqwest::StatusCode::OK
    );

    assert!(
        accepted.load(Ordering::SeqCst) >= 2,
        "reqwest H1 opened multiple backend sockets despite a maxConnections=1 override; the cap is unsupported for this pooled transport and must remain documented/statused as such"
    );
}
