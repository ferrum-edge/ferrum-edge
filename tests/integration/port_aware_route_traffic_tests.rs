//! Production listener lifecycle for port-aware HTTP route identity (#3612).
//!
//! These tests drive `modes::file::serve` — the same entry point the binary
//! uses — so the Gateway API listener ports are bound by
//! `GatewayListenerManager`, not by the test. Nothing here pre-binds a
//! listener on the gateway's behalf: if the production code does not bind the
//! port, the request fails.
//!
//! Covered:
//! - two **same-protocol** listener ports serving identical `host` + path with
//!   listener-scoped routes,
//! - reload that **adds** a listener port,
//! - reload that **withdraws** a listener port — routing must fail closed
//!   immediately, before the socket finishes draining,
//! - reuse of a matching process-global proxy frontend without a duplicate
//!   bind, and refusal of a Gateway listener that collides with admin, and
//! - generation-bound admission before listener reconcile acknowledgement,
//!   including the ordinary-bind-failure Service remap distinction.

use std::time::Duration;

use bytes::Bytes;
use chrono::Utc;
use http_body_util::Full;
use hyper::body::Incoming;
use hyper::service::service_fn;
use hyper::{Request, Response};
use hyper_util::rt::TokioIo;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

use ferrum_edge::config::EnvConfig;
use ferrum_edge::config::env_config::OperatingMode;
use ferrum_edge::config::types::{AuthMode, BackendScheme, DispatchKind, GatewayConfig, Proxy};
use ferrum_edge::modes::file::{ServeOptions, serve};

const HOST: &str = "app.example.com";

fn port_scoped_proxy(id: &str, backend_port: u16, listen_port: Option<u16>) -> Proxy {
    Proxy {
        id: id.to_string(),
        namespace: ferrum_edge::config::types::default_namespace(),
        name: Some(format!("Port Aware {id}")),
        hosts: vec![HOST.to_string()],
        listen_path: Some("/api".to_string()),
        backend_scheme: Some(BackendScheme::Http),
        dispatch_kind: DispatchKind::from(BackendScheme::Http),
        backend_host: "127.0.0.1".to_string(),
        backend_port,
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
        resolved_tls: Default::default(),
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
        response_body_mode: Default::default(),
        listen_port,
        frontend_tls: false,
        passthrough: false,
        udp_idle_timeout_seconds: 60,
        tcp_idle_timeout_seconds: Some(300),
        websocket_idle_timeout_seconds: None,
        allowed_methods: None,
        allowed_ws_origins: vec![],
        udp_max_response_amplification_factor: None,
        stream_proxy_protocol: None,
        // Outbound PROXY protocol stays disabled: these are HTTP proxies, and
        // the fail-safe default is for the backend to see the gateway egress IP.
        backend_proxy_protocol: None,
        stream_match: None,
        compiled_stream_match: None,
        created_at: Utc::now(),
        updated_at: Utc::now(),
    }
}

fn config_with(proxies: Vec<Proxy>) -> GatewayConfig {
    GatewayConfig {
        version: "1".to_string(),
        proxies,
        loaded_at: Utc::now(),
        ..GatewayConfig::default()
    }
}

fn test_env_config(proxy_http_port: u16, admin_http_port: u16) -> EnvConfig {
    EnvConfig {
        mode: OperatingMode::File,
        log_level: "error".into(),
        proxy_http_port,
        proxy_https_port: 0,
        admin_http_port,
        admin_https_port: 0,
        admin_jwt_secret: Some("ferrum-edge-port-aware-test-secret-000000".to_string()),
        shutdown_drain_seconds: 0,
        max_connections: 0,
        pool_warmup_enabled: false,
        ..EnvConfig::default()
    }
}

fn serve_options(proxy_http: TcpListener, admin_http: TcpListener) -> ServeOptions {
    ServeOptions {
        proxy_http: Some(proxy_http),
        proxy_https: None,
        admin_http: Some(admin_http),
        admin_https: None,
        admin_jwt_manager: None,
        skip_initial_capability_refresh: true,
        background_drain_timeout: Some(Duration::from_millis(200)),
    }
}

async fn start_body_backend(body: &'static [u8]) -> (u16, tokio::task::JoinHandle<()>) {
    use hyper::server::conn::http1;
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let handle = tokio::spawn(async move {
        loop {
            let (stream, _) = match listener.accept().await {
                Ok(c) => c,
                Err(_) => break,
            };
            tokio::spawn(async move {
                let _ = stream.set_nodelay(true);
                let io = TokioIo::new(stream);
                let svc = service_fn(move |_req: Request<Incoming>| async move {
                    Ok::<_, hyper::Error>(
                        Response::builder()
                            .status(200)
                            .header("content-type", "text/plain")
                            .body(Full::new(Bytes::from_static(body)))
                            .unwrap(),
                    )
                });
                let _ = http1::Builder::new().serve_connection(io, svc).await;
            });
        }
    });
    tokio::time::sleep(Duration::from_millis(20)).await;
    (port, handle)
}

/// Reserve an ephemeral port number and release the socket so the gateway can
/// bind it itself. Whole-startup callers retry on a bind race.
async fn reserve_free_port() -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    drop(listener);
    port
}

const GATEWAY_LISTENER_STARTUP_ATTEMPTS: u32 = 3;

/// Successful startup for two same-protocol Gateway listener ports via
/// `file::serve`. Production still owns every Gateway listener bind.
struct TwoSameProtocolListenersStartup {
    handles: ferrum_edge::modes::file::ServeHandles,
    shutdown_tx: tokio::sync::watch::Sender<bool>,
    listener_a_port: u16,
    listener_b_port: u16,
    global_proxy_port: u16,
}

/// Start `file::serve` with two distinct Gateway listener ports, retrying the
/// whole startup when an ephemeral port reservation races before the manager
/// binds it.
async fn start_two_same_protocol_gateway_listeners(
    backend_a: u16,
    backend_b: u16,
) -> TwoSameProtocolListenersStartup {
    for attempt in 1..=GATEWAY_LISTENER_STARTUP_ATTEMPTS {
        let listener_a_port = reserve_free_port().await;
        let listener_b_port = reserve_free_port().await;
        if listener_a_port == listener_b_port {
            continue;
        }

        let config = config_with(vec![
            port_scoped_proxy("gw-a", backend_a, Some(listener_a_port)),
            port_scoped_proxy("gw-b", backend_b, Some(listener_b_port)),
        ]);
        config
            .validate_unique_listen_paths()
            .expect("distinct listener ports are independent route-table slots");

        let proxy_http = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let admin_http = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let global_proxy_port = proxy_http.local_addr().unwrap().port();
        let (shutdown_tx, _) = tokio::sync::watch::channel(false);

        let handles = match serve(
            test_env_config(0, 0),
            config,
            serve_options(proxy_http, admin_http),
            shutdown_tx.clone(),
        )
        .await
        {
            Ok(handles) => handles,
            Err(error) => {
                let _ = shutdown_tx.send(true);
                eprintln!(
                    "two-listener startup attempt {attempt}/{GATEWAY_LISTENER_STARTUP_ATTEMPTS} \
                     failed before serve returned: {error}"
                );
                if attempt == GATEWAY_LISTENER_STARTUP_ATTEMPTS {
                    panic!(
                        "file::serve failed after {GATEWAY_LISTENER_STARTUP_ATTEMPTS} attempts: \
                         {error}"
                    );
                }
                continue;
            }
        };

        let mut active = handles.gateway_listeners.active_ports().await;
        active.sort_unstable();
        let mut expected = vec![listener_a_port, listener_b_port];
        expected.sort_unstable();

        if active == expected {
            return TwoSameProtocolListenersStartup {
                handles,
                shutdown_tx,
                listener_a_port,
                listener_b_port,
                global_proxy_port,
            };
        }

        let bind_failures = handles.gateway_listeners.bind_failures();
        eprintln!(
            "two-listener startup attempt {attempt}/{GATEWAY_LISTENER_STARTUP_ATTEMPTS} \
             lost an ephemeral-port race: want active {expected:?}, actual {active:?}, \
             refusals: {bind_failures:?}"
        );
        let _ = shutdown_tx.send(true);
        tokio::time::timeout(Duration::from_secs(5), handles.join())
            .await
            .expect("a failed two-listener startup attempt must drain before retrying")
            .expect("a failed two-listener startup attempt must join cleanly before retrying");
        if attempt == GATEWAY_LISTENER_STARTUP_ATTEMPTS {
            panic!(
                "both Gateway listener ports must be bound by the gateway after \
                 {GATEWAY_LISTENER_STARTUP_ATTEMPTS} attempts; want {expected:?}, \
                 actual {active:?}, refusals: {bind_failures:?}"
            );
        }
    }

    panic!(
        "could not reserve two distinct Gateway listener ports in \
         {GATEWAY_LISTENER_STARTUP_ATTEMPTS} attempts"
    )
}

/// `Ok((status, body))`, or `Err` when the port is not accepting at all.
async fn try_http_get_host(
    port: u16,
    path: &str,
    host: &str,
) -> Result<(u16, String), std::io::Error> {
    let mut stream = tokio::net::TcpStream::connect(("127.0.0.1", port)).await?;
    let req = format!("GET {path} HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n");
    stream.write_all(req.as_bytes()).await?;
    let mut buf = Vec::new();
    stream.read_to_end(&mut buf).await?;
    let text = String::from_utf8_lossy(&buf);
    let status = text
        .split_whitespace()
        .nth(1)
        .and_then(|s| s.parse().ok())
        .unwrap_or(0);
    let body = text
        .split("\r\n\r\n")
        .nth(1)
        .unwrap_or("")
        .trim()
        .to_string();
    Ok((status, body))
}

async fn try_http_get(port: u16, path: &str) -> Result<(u16, String), std::io::Error> {
    try_http_get_host(port, path, HOST).await
}

async fn http_get(port: u16, path: &str) -> (u16, String) {
    try_http_get(port, path)
        .await
        .unwrap_or_else(|e| panic!("request to port {port} failed: {e}"))
}

async fn http_get_host(port: u16, path: &str, host: &str) -> (u16, String) {
    try_http_get_host(port, path, host)
        .await
        .unwrap_or_else(|e| panic!("request to port {port} host {host} failed: {e}"))
}

/// Two Gateway listener ports of the SAME protocol (both plaintext) carrying
/// the same `host` + `listen_path`. This is the exact case #3612 filed: it
/// must validate, both ports must be bound by the gateway itself, and each
/// must reach only its own backend.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn two_same_protocol_gateway_listeners_bind_and_route_independently() {
    let (backend_80, _b80) = start_body_backend(b"listener-a").await;
    let (backend_8080, _b8080) = start_body_backend(b"listener-b").await;

    let startup = start_two_same_protocol_gateway_listeners(backend_80, backend_8080).await;
    let TwoSameProtocolListenersStartup {
        handles,
        shutdown_tx,
        listener_a_port,
        listener_b_port,
        global_proxy_port,
    } = startup;

    let (status_a, body_a) = http_get(listener_a_port, "/api/x").await;
    assert_eq!(status_a, 200, "listener A must serve: {body_a}");
    assert_eq!(body_a, "listener-a");

    let (status_b, body_b) = http_get(listener_b_port, "/api/x").await;
    assert_eq!(status_b, 200, "listener B must serve: {body_b}");
    assert_eq!(body_b, "listener-b");

    // The global process bind is NOT a Gateway listener. With two same-class
    // listener ports the compatibility remap is off, so it fails closed rather
    // than guessing which listener the request meant.
    let (status_global, _) = http_get(global_proxy_port, "/api/x").await;
    assert_eq!(
        status_global, 404,
        "the global plaintext bind must not guess between two same-protocol Gateway listeners"
    );

    let _ = shutdown_tx.send(true);
    let _ = tokio::time::timeout(Duration::from_secs(5), handles.join()).await;
}

/// Reload lifecycle: a listener port added by a config update is bound without
/// a restart, and a listener port withdrawn by a later update stops routing
/// immediately (fail closed) and is unbound.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn gateway_listener_ports_follow_config_reload_add_and_withdraw() {
    let (backend_a, _ba) = start_body_backend(b"listener-a").await;
    let (backend_b, _bb) = start_body_backend(b"listener-b").await;

    let listener_a_port = reserve_free_port().await;
    let listener_b_port = reserve_free_port().await;
    assert_ne!(listener_a_port, listener_b_port);

    let proxy_http = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let admin_http = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let (shutdown_tx, _) = tokio::sync::watch::channel(false);
    let handles = serve(
        test_env_config(0, 0),
        config_with(vec![port_scoped_proxy(
            "gw-a",
            backend_a,
            Some(listener_a_port),
        )]),
        serve_options(proxy_http, admin_http),
        shutdown_tx.clone(),
    )
    .await
    .expect("file::serve starts");

    assert_eq!(
        handles.gateway_listeners.active_ports().await,
        vec![listener_a_port]
    );
    assert_eq!(http_get(listener_a_port, "/api/x").await.0, 200);
    assert!(
        try_http_get(listener_b_port, "/api/x").await.is_err(),
        "an undeclared listener port must not be bound"
    );

    // ── Update: add a second listener ────────────────────────────────────
    let outcome = handles.proxy_state.update_config(config_with(vec![
        port_scoped_proxy("gw-a", backend_a, Some(listener_a_port)),
        port_scoped_proxy("gw-b", backend_b, Some(listener_b_port)),
    ]));
    assert!(
        matches!(outcome, ferrum_edge::proxy::ConfigApplyOutcome::Applied),
        "reload must apply: {outcome:?}"
    );
    wait_for_listener_ports(&handles, &[listener_a_port, listener_b_port]).await;

    let (status_b, body_b) = http_get(listener_b_port, "/api/x").await;
    assert_eq!(status_b, 200, "the added listener must serve: {body_b}");
    assert_eq!(body_b, "listener-b");
    assert_eq!(http_get(listener_a_port, "/api/x").await.1, "listener-a");

    // ── Delete: withdraw the first listener ──────────────────────────────
    let outcome = handles
        .proxy_state
        .update_config(config_with(vec![port_scoped_proxy(
            "gw-b",
            backend_b,
            Some(listener_b_port),
        )]));
    assert!(
        matches!(outcome, ferrum_edge::proxy::ConfigApplyOutcome::Applied),
        "withdrawal must apply: {outcome:?}"
    );
    wait_for_listener_ports(&handles, &[listener_b_port]).await;

    // Routing is withdrawn by the config swap itself, so even if the socket
    // is still draining it can only answer 404 — never stale-route.
    if let Ok((status, _)) = try_http_get(listener_a_port, "/api/x").await {
        assert_eq!(
            status, 404,
            "a withdrawn listener must fail closed while its socket drains"
        );
    }
    assert_eq!(
        http_get(listener_b_port, "/api/x").await.1,
        "listener-b",
        "the surviving sibling listener keeps serving across the withdrawal"
    );

    let _ = shutdown_tx.send(true);
    let _ = tokio::time::timeout(Duration::from_secs(5), handles.join()).await;
}

/// A Gateway listener whose port and frontend class match the process-global
/// proxy socket is already served by that socket. The manager must neither
/// attempt a duplicate bind nor report a false failure.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn matching_global_proxy_port_already_serves_the_gateway_listener() {
    let (backend, _b) = start_body_backend(b"listener-a").await;

    let proxy_http = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let admin_http = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let global_proxy_port = proxy_http.local_addr().unwrap().port();

    let (shutdown_tx, _) = tokio::sync::watch::channel(false);
    let handles = serve(
        test_env_config(0, 0),
        config_with(vec![port_scoped_proxy(
            "gw-a",
            backend,
            Some(global_proxy_port),
        )]),
        serve_options(proxy_http, admin_http),
        shutdown_tx.clone(),
    )
    .await
    .expect("file::serve starts");

    assert!(
        handles.gateway_listeners.active_ports().await.is_empty(),
        "the manager must not duplicate the global proxy socket"
    );
    let failures = handles.gateway_listeners.bind_failures();
    assert!(
        failures
            .iter()
            .all(|failure| failure.port != global_proxy_port),
        "a same-class global frontend satisfies the listener, not a failure: {failures:?}"
    );
    assert_eq!(
        http_get(global_proxy_port, "/api/x").await,
        (200, "listener-a".to_string()),
        "the exact accepted port must route on the existing global frontend"
    );

    let _ = shutdown_tx.send(true);
    let _ = tokio::time::timeout(Duration::from_secs(5), handles.join()).await;
}

/// A Gateway listener that collides with a non-proxy reserved socket is still
/// refused and surfaced; the manager must never take over the admin frontend.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn gateway_listener_port_colliding_with_admin_is_refused() {
    let (backend, _b) = start_body_backend(b"listener-a").await;

    let proxy_http = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let admin_http = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let global_proxy_port = proxy_http.local_addr().unwrap().port();
    let admin_port = admin_http.local_addr().unwrap().port();

    let (shutdown_tx, _) = tokio::sync::watch::channel(false);
    let handles = serve(
        test_env_config(0, 0),
        config_with(vec![port_scoped_proxy("gw-a", backend, Some(admin_port))]),
        serve_options(proxy_http, admin_http),
        shutdown_tx.clone(),
    )
    .await
    .expect("file::serve starts");

    assert!(handles.gateway_listeners.active_ports().await.is_empty());
    let failures = handles.gateway_listeners.bind_failures();
    assert!(
        failures.iter().any(|failure| failure.port == admin_port),
        "the admin collision must be surfaced: {failures:?}"
    );
    assert_eq!(
        http_get(global_proxy_port, "/api/x").await.0,
        404,
        "a refused listener route must not escape through single-listener remapping"
    );

    let _ = shutdown_tx.send(true);
    let _ = tokio::time::timeout(Duration::from_secs(5), handles.join()).await;
}

/// An admission-refused listener must not poison an unrelated sibling listener,
/// and moving the collided route onto a free port withdraws the fail-closed
/// routing state for that generation.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn refused_gateway_listener_does_not_poison_sibling_and_recovers() {
    let (backend_refused, _br) = start_body_backend(b"listener-refused").await;
    let (backend_ok, _bo) = start_body_backend(b"listener-ok").await;

    let proxy_http = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let admin_http = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let admin_port = admin_http.local_addr().unwrap().port();
    let sibling_port = reserve_free_port().await;

    let mut refused = port_scoped_proxy("gw-refused", backend_refused, Some(admin_port));
    refused.hosts = vec![HOST.to_string()];
    let mut sibling = port_scoped_proxy("gw-ok", backend_ok, Some(sibling_port));
    sibling.hosts = vec!["ok.example.com".to_string()];

    let (shutdown_tx, _) = tokio::sync::watch::channel(false);
    let handles = serve(
        test_env_config(0, 0),
        config_with(vec![refused, sibling]),
        serve_options(proxy_http, admin_http),
        shutdown_tx.clone(),
    )
    .await
    .expect("file::serve starts");

    wait_for_listener_ports(&handles, &[sibling_port]).await;
    assert!(
        handles
            .gateway_listeners
            .bind_failures()
            .iter()
            .any(|failure| failure.port == admin_port),
        "the admin collision must remain surfaced"
    );
    let (ok_status, ok_body) = http_get_host(sibling_port, "/api/x", "ok.example.com").await;
    assert_eq!(
        ok_status, 200,
        "sibling listener must keep serving: {ok_body}"
    );
    assert_eq!(ok_body, "listener-ok");
    assert_eq!(
        http_get_host(sibling_port, "/api/x", HOST).await.0,
        404,
        "the refused route must not be reachable on the sibling listener port"
    );

    let recovered_port = reserve_free_port().await;
    let mut recovered = port_scoped_proxy("gw-refused", backend_refused, Some(recovered_port));
    recovered.hosts = vec![HOST.to_string()];
    let mut sibling = port_scoped_proxy("gw-ok", backend_ok, Some(sibling_port));
    sibling.hosts = vec!["ok.example.com".to_string()];
    let outcome = handles
        .proxy_state
        .update_config(config_with(vec![recovered, sibling]));
    assert!(
        matches!(outcome, ferrum_edge::proxy::ConfigApplyOutcome::Applied),
        "recovery publication must apply: {outcome:?}"
    );
    wait_for_listener_ports_and_withdrawn_failures(
        &handles,
        &[sibling_port, recovered_port],
        &[admin_port],
    )
    .await;
    assert_eq!(
        http_get(recovered_port, "/api/x").await,
        (200, "listener-refused".to_string()),
        "withdrawing the collision must restore the route on the new listen_port"
    );
    assert_eq!(
        http_get_host(sibling_port, "/api/x", "ok.example.com")
            .await
            .1,
        "listener-ok",
        "sibling must remain healthy across recovery"
    );

    let _ = shutdown_tx.send(true);
    let _ = tokio::time::timeout(Duration::from_secs(5), handles.join()).await;
}

/// A config publication that lands **between** the readiness reconcile and the
/// supervisor's first poll must still be applied.
///
/// The manager subscribes in `new()`, so the publication is already pending on
/// the receiver `run()` consumes. Subscribing inside `run()` instead would mark
/// it as already seen, and because the slow retry tick only reconciles when a
/// bind failure is outstanding, the socket set would stay stale indefinitely.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_config_publication_before_the_supervisor_starts_is_not_missed() {
    use ferrum_edge::dns::{DnsCache, DnsConfig};
    use ferrum_edge::proxy::ProxyState;
    use ferrum_edge::proxy::gateway_listener::{GatewayListenerManager, GatewayListenerTls};

    let (backend, _b) = start_body_backend(b"listener-a").await;
    let listener_port = reserve_free_port().await;

    let state = ProxyState::new(
        config_with(vec![]),
        DnsCache::new(DnsConfig::default()),
        test_env_config(0, 0),
        None,
        None,
    )
    .expect("proxy state")
    .0;

    let manager = std::sync::Arc::new(GatewayListenerManager::new(
        state.clone(),
        std::net::IpAddr::from([127, 0, 0, 1]),
        GatewayListenerTls::default(),
    ));

    // Readiness reconcile: nothing to bind yet.
    manager.reconcile().await;
    assert!(manager.active_ports().await.is_empty());

    // The publication happens HERE — after the readiness reconcile and before
    // the supervisor task exists.
    let outcome = state.update_config(config_with(vec![port_scoped_proxy(
        "gw-a",
        backend,
        Some(listener_port),
    )]));
    assert!(
        matches!(outcome, ferrum_edge::proxy::ConfigApplyOutcome::Applied),
        "publication must apply: {outcome:?}"
    );

    let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);
    let supervisor = tokio::spawn(manager.clone().run(shutdown_rx));

    let deadline = std::time::Instant::now() + Duration::from_secs(5);
    loop {
        if manager.active_ports().await == vec![listener_port] {
            break;
        }
        assert!(
            std::time::Instant::now() < deadline,
            "the publication made before the supervisor started was never reconciled; \
             failures {:?}",
            manager.bind_failures()
        );
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
    assert_eq!(http_get(listener_port, "/api/x").await.1, "listener-a");

    let _ = shutdown_tx.send(true);
    let _ = tokio::time::timeout(Duration::from_secs(5), supervisor).await;
}

/// Listener routing admission is part of the exact request/config generation:
/// publication starts fail-closed, an admission refusal stays unreachable, and
/// only the matching reconcile may enable the intentional Service remap for an
/// ordinary OS bind failure. The held socket makes the bind failure
/// deterministic; no timing sleep gates any assertion.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn listener_admission_is_generation_bound_before_reconcile_acknowledgement() {
    use ferrum_edge::dns::{DnsCache, DnsConfig};
    use ferrum_edge::proxy::ProxyState;
    use ferrum_edge::proxy::gateway_listener::{GatewayListenerManager, GatewayListenerTls};

    let global_proxy_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let global_proxy_port = global_proxy_listener.local_addr().unwrap().port();
    let admin_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let admin_port = admin_listener.local_addr().unwrap().port();
    let busy_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let busy_port = busy_listener.local_addr().unwrap().port();

    let state = ProxyState::new(
        config_with(vec![]),
        DnsCache::new(DnsConfig::default()),
        test_env_config(global_proxy_port, admin_port),
        None,
        None,
    )
    .expect("proxy state")
    .0;
    let manager = GatewayListenerManager::new(
        state.clone(),
        std::net::IpAddr::from([127, 0, 0, 1]),
        GatewayListenerTls::default(),
    );
    manager.reconcile().await;

    let outcome = state.update_config(config_with(vec![port_scoped_proxy(
        "admission-refused",
        1,
        Some(admin_port),
    )]));
    assert!(
        outcome.applied(),
        "refused generation must publish: {outcome:?}"
    );
    assert!(
        state
            .find_proxy_on_frontend_for_test(
                Some(HOST),
                "/api/window",
                Some(global_proxy_port),
                false,
            )
            .is_none(),
        "a newly published listener-scoped route must fail closed before reconcile"
    );
    let refused_failures = manager.reconcile().await;
    assert!(
        refused_failures
            .iter()
            .any(|failure| failure.port == admin_port),
        "the exact-generation admission refusal must be surfaced"
    );
    assert!(
        state
            .find_proxy_on_frontend_for_test(
                Some(HOST),
                "/api/window",
                Some(global_proxy_port),
                false,
            )
            .is_none(),
        "acknowledging a refused port must keep every remap path unreachable"
    );

    let outcome = state.update_config(config_with(vec![port_scoped_proxy(
        "ordinary-bind-failure",
        1,
        Some(busy_port),
    )]));
    assert!(
        outcome.applied(),
        "allowed generation must publish: {outcome:?}"
    );
    assert!(
        state
            .find_proxy_on_frontend_for_test(
                Some(HOST),
                "/api/window",
                Some(global_proxy_port),
                false,
            )
            .is_none(),
        "the replacement generation must be pending before its own reconcile"
    );
    let bind_failures = manager.reconcile().await;
    assert!(
        bind_failures
            .iter()
            .any(|failure| failure.port == busy_port),
        "the held socket must force an ordinary OS bind failure"
    );
    let remapped = state
        .find_proxy_on_frontend_for_test(Some(HOST), "/api/window", Some(global_proxy_port), false)
        .expect("matching-generation acknowledgement enables Service remap");
    assert_eq!(remapped.proxy.id, "ordinary-bind-failure");

    drop(global_proxy_listener);
    drop(admin_listener);
    drop(busy_listener);
    manager.shutdown_all().await;
}

/// An HTTP↔HTTPS class flip must never leave the retiring plaintext accept
/// loops running beside the new TLS ones.
///
/// With `FERRUM_ACCEPT_THREADS > 1` every accept loop binds the same port
/// through `SO_REUSEPORT`, so an overlap lets the kernel hand new connections
/// to whichever generation it likes — plaintext or TLS. Once `reconcile()`
/// returns, the plaintext generation must be gone.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_http_to_https_class_flip_retires_the_plaintext_accept_loops_first() {
    use ferrum_edge::dns::{DnsCache, DnsConfig};
    use ferrum_edge::proxy::ProxyState;
    use ferrum_edge::proxy::gateway_listener::{GatewayListenerManager, GatewayListenerTls};

    let _ = rustls::crypto::ring::default_provider().install_default();
    let (backend, _b) = start_body_backend(b"listener-a").await;
    let listener_port = reserve_free_port().await;

    let mut env = test_env_config(0, 0);
    // The whole point: several SO_REUSEPORT accept loops per listener.
    env.accept_threads = 4;

    let plaintext = config_with(vec![port_scoped_proxy(
        "gw-a",
        backend,
        Some(listener_port),
    )]);
    let state = ProxyState::new(
        plaintext.clone(),
        DnsCache::new(DnsConfig::default()),
        env,
        None,
        None,
    )
    .expect("proxy state")
    .0;

    let manager = GatewayListenerManager::new(
        state.clone(),
        std::net::IpAddr::from([127, 0, 0, 1]),
        GatewayListenerTls {
            static_config: Some(self_signed_server_config()),
            reload_slot: None,
        },
    );
    manager.reconcile().await;
    assert_eq!(manager.active_ports().await, vec![listener_port]);
    assert_eq!(
        http_get(listener_port, "/api/x").await.1,
        "listener-a",
        "the plaintext generation serves before the flip"
    );

    // Flip the same port to TLS.
    let mut tls_config = plaintext.clone();
    tls_config.http_tls_listen_ports.insert((
        ferrum_edge::config::types::default_namespace(),
        listener_port,
    ));
    let outcome = state.update_config(tls_config);
    assert!(
        matches!(outcome, ferrum_edge::proxy::ConfigApplyOutcome::Applied),
        "class flip must apply: {outcome:?}"
    );
    manager.reconcile().await;
    assert_eq!(manager.active_ports().await, vec![listener_port]);

    // Every plaintext accept socket is closed, so no cleartext request can be
    // answered on this port any more — the kernel has no old-generation socket
    // left to distribute to.
    for attempt in 0..20 {
        if let Ok((status, body)) = try_http_get(listener_port, "/api/x").await {
            assert_ne!(
                status, 200,
                "attempt {attempt}: a retired plaintext accept loop still served \
                 cleartext on a TLS listener port: {body}"
            );
        }
    }

    manager.shutdown_all().await;
}

fn self_signed_server_config() -> std::sync::Arc<rustls::ServerConfig> {
    let key_pair =
        rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).expect("generate key");
    let params = rcgen::CertificateParams::new(vec![HOST.to_string()]).expect("cert params");
    let cert = params.self_signed(&key_pair).expect("self-sign cert");
    let cert_pem = cert.pem();
    let mut cert_reader = cert_pem.as_bytes();
    let certs: Vec<_> = rustls_pemfile::certs(&mut cert_reader)
        .filter_map(Result::ok)
        .collect();
    let key_pem = key_pair.serialize_pem();
    let mut key_reader = key_pem.as_bytes();
    let private_key = rustls_pemfile::private_key(&mut key_reader)
        .expect("read private key")
        .expect("private key present");
    std::sync::Arc::new(
        rustls::ServerConfig::builder_with_provider(std::sync::Arc::new(
            rustls::crypto::ring::default_provider(),
        ))
        .with_safe_default_protocol_versions()
        .expect("protocol versions")
        .with_no_client_auth()
        .with_single_cert(certs, private_key)
        .expect("server config"),
    )
}

/// The supervisor reconciles asynchronously after a config publication, so
/// poll rather than sleeping a fixed interval.
async fn wait_for_listener_ports(
    handles: &ferrum_edge::modes::file::ServeHandles,
    expected: &[u16],
) {
    wait_for_listener_ports_and_withdrawn_failures(handles, expected, &[]).await;
}

/// Like [`wait_for_listener_ports`], but also waits until the lock-free
/// `bind_failures` snapshot no longer lists any of `withdrawn_failure_ports`.
/// Reconcile can insert a socket before it publishes the updated failure set.
async fn wait_for_listener_ports_and_withdrawn_failures(
    handles: &ferrum_edge::modes::file::ServeHandles,
    expected_active: &[u16],
    withdrawn_failure_ports: &[u16],
) {
    let mut want = expected_active.to_vec();
    want.sort_unstable();
    let deadline = std::time::Instant::now() + Duration::from_secs(5);
    loop {
        let mut active = handles.gateway_listeners.active_ports().await;
        active.sort_unstable();
        let failures = handles.gateway_listeners.bind_failures();
        let withdrawals_ok = withdrawn_failure_ports
            .iter()
            .all(|port| !failures.iter().any(|failure| failure.port == *port));
        if active == want && withdrawals_ok {
            return;
        }
        if std::time::Instant::now() >= deadline {
            panic!(
                "Gateway listener state never converged: want active {want:?}, actual {active:?}, \
                 want withdrawn failures {withdrawn_failure_ports:?}, failures {failures:?}"
            );
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
}
