//! Smoke tests for the scripted-backend scaffolding that don't require the
//! gateway binary — i.e., they exercise the backends + clients directly so
//! `cargo test --test integration_tests` covers the happy paths in under a
//! second.
//!
//! The full failure-mode acceptance suite lives under
//! `tests/functional/scripted_backend_tests.rs` (binary mode, `#[ignore]`).
//! See `tests/scaffolding/mod.rs` for the API docs.

use crate::scaffolding::backends::{
    HttpStep, RequestMatcher, ScriptedHttp1Backend, ScriptedTcpBackend, ScriptedTlsBackend,
    TcpStep, TlsConfig,
};
use crate::scaffolding::certs::TestCa;
use crate::scaffolding::clients::Http1Client;
use crate::scaffolding::file_mode_yaml_for_backend;
use crate::scaffolding::harness::GatewayHarness;
use crate::scaffolding::ports::reserve_port;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

#[tokio::test]
async fn scripted_tcp_backend_end_to_end() {
    let reservation = reserve_port().await.expect("port");
    let port = reservation.port;
    let backend = ScriptedTcpBackend::builder(reservation.into_listener())
        .step(TcpStep::ReadExact(5))
        .step(TcpStep::Write(b"world".to_vec()))
        .step(TcpStep::Drop)
        .spawn()
        .expect("spawn");
    let mut s = TcpStream::connect(("127.0.0.1", port))
        .await
        .expect("connect");
    s.write_all(b"hello").await.expect("write");
    let mut resp = Vec::new();
    s.read_to_end(&mut resp).await.expect("read");
    assert_eq!(resp, b"world");
    assert!(backend.received_contains(b"hello").await);
}

#[tokio::test]
async fn scripted_http1_backend_via_reqwest() {
    let reservation = reserve_port().await.expect("port");
    let port = reservation.port;
    let backend = ScriptedHttp1Backend::builder(reservation.into_listener())
        .step(HttpStep::ExpectRequest(RequestMatcher::method_path(
            "GET", "/ping",
        )))
        .step(HttpStep::RespondStatus {
            status: 200,
            reason: "OK".into(),
        })
        .step(HttpStep::RespondHeader {
            name: "Content-Length".into(),
            value: "4".into(),
        })
        .step(HttpStep::RespondBodyChunk(b"pong".to_vec()))
        .step(HttpStep::RespondBodyEnd)
        .spawn()
        .expect("spawn");

    let url = format!("http://127.0.0.1:{port}/ping");
    let client = Http1Client::insecure().expect("client");
    let resp = client.get(&url).await.expect("get");
    assert_eq!(resp.status, reqwest::StatusCode::OK);
    assert_eq!(resp.body_text(), "pong");
    // The matcher is only informational unless we assert — otherwise a test
    // expecting "GET /ping" would pass for any method/path the client sent.
    backend.assert_no_matcher_mismatches().await;
}

#[tokio::test]
async fn scripted_tls_backend_alpn_negotiation() {
    use rustls_pemfile::certs;
    let ca = TestCa::new("integration-test").expect("ca");
    let (cert_pem, key_pem) = ca.valid().expect("leaf");
    let reservation = reserve_port().await.expect("port");
    let port = reservation.port;

    let response_bytes: Vec<u8> =
        b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok".to_vec();
    let backend = ScriptedTlsBackend::builder(
        reservation.into_listener(),
        TlsConfig::new(cert_pem, key_pem).with_alpn(vec![b"http/1.1".to_vec()]),
    )
    .step(TcpStep::ReadUntil(b"\r\n\r\n".to_vec()))
    .step(TcpStep::Write(response_bytes))
    .step(TcpStep::Drop)
    .spawn()
    .expect("spawn");

    // Build a rustls client that advertises h2 first, then http/1.1.
    let mut root = rustls::RootCertStore::empty();
    let mut reader = ca.cert_pem.as_bytes();
    for cert in certs(&mut reader).filter_map(|c| c.ok()) {
        root.add(cert).expect("add ca");
    }
    let provider = rustls::crypto::ring::default_provider();
    let mut config = rustls::ClientConfig::builder_with_provider(Arc::new(provider))
        .with_safe_default_protocol_versions()
        .expect("versions")
        .with_root_certificates(root)
        .with_no_client_auth();
    config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
    let connector = tokio_rustls::TlsConnector::from(Arc::new(config));
    let tcp = TcpStream::connect(("127.0.0.1", port))
        .await
        .expect("tcp connect");
    let name =
        rustls::pki_types::ServerName::try_from("localhost".to_string()).expect("server name");
    let _tls = connector.connect(name, tcp).await.expect("handshake");

    // Wait briefly for the server to record the handshake.
    tokio::time::sleep(Duration::from_millis(50)).await;
    let alpn = backend.last_alpn().await;
    assert_eq!(
        alpn.as_deref(),
        Some(&b"http/1.1"[..]),
        "server picked http/1.1 from h2 → http/1.1 client ALPN offer"
    );
    assert_eq!(backend.handshakes_completed(), 1);
}

// ────────────────────────────────────────────────────────────────────────────
// In-process harness end-to-end. Confirms `HarnessMode::InProcess` boots the
// gateway as a tokio task, routes a real HTTP request through `ProxyState`,
// and reaches a scripted backend on `127.0.0.1:<port>` — all in well under a
// second. This test pins the in-process path so it can't silently regress to
// the binary path without the test failing fast.
//
// Lives in `tests/integration/` (not `tests/functional/`) precisely because
// it does NOT need the binary — that's the whole point of in-process mode.
// ────────────────────────────────────────────────────────────────────────────
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn in_process_harness_routes_request_to_scripted_backend() {
    let reservation = reserve_port().await.expect("reserve backend port");
    let backend_port = reservation.port;
    let _backend = ScriptedHttp1Backend::builder(reservation.into_listener())
        .step(HttpStep::ExpectRequest(RequestMatcher::method_path(
            "GET", "/ping",
        )))
        .step(HttpStep::RespondStatus {
            status: 200,
            reason: "OK".into(),
        })
        .step(HttpStep::RespondHeader {
            name: "Content-Length".into(),
            value: "4".into(),
        })
        .step(HttpStep::RespondBodyChunk(b"pong".to_vec()))
        .step(HttpStep::RespondBodyEnd)
        .spawn()
        .expect("spawn backend");

    let yaml = file_mode_yaml_for_backend(backend_port);
    let harness = GatewayHarness::builder()
        .mode_in_process()
        .file_config(yaml)
        .spawn()
        .await
        .expect("spawn in-process gateway");

    // Health endpoint should respond before the first proxy request — if it
    // doesn't we know the in-process serve() returned without binding.
    harness
        .wait_healthy(Duration::from_secs(5))
        .await
        .expect("gateway healthy");

    let client = harness.http_client().expect("client");
    let resp = client
        .get(&harness.proxy_url("/api/ping"))
        .await
        .expect("response");
    assert_eq!(resp.status, reqwest::StatusCode::OK);
    assert_eq!(resp.body_text(), "pong");
}

// ────────────────────────────────────────────────────────────────────────────
// Regression: env-var overrides must be applied BEFORE the YAML loader runs,
// otherwise the loader's namespace filter and `BackendAllowIps`-keyed field
// validation use the wrong values and an in-process test sees a different
// resource set than the binary-mode gateway would. Two proxies in different
// namespaces both claim `/api`; an `FERRUM_NAMESPACE=alt` override has to
// cause the loader to drop the `ferrum` proxy AND keep the `alt` one. If the
// fix regresses, the loader keeps the `ferrum` proxy (whose backend points
// at a closed port) and the request returns 502 — or the namespaces collide
// on `listen_path` and the loader fails outright.
// ────────────────────────────────────────────────────────────────────────────
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn in_process_harness_applies_namespace_override_before_loading_yaml() {
    let reservation = reserve_port().await.expect("reserve backend port");
    let backend_port = reservation.port;
    let _backend = ScriptedHttp1Backend::builder(reservation.into_listener())
        .step(HttpStep::ExpectRequest(RequestMatcher::method_path(
            "GET", "/ping",
        )))
        .step(HttpStep::RespondStatus {
            status: 200,
            reason: "OK".into(),
        })
        .step(HttpStep::RespondHeader {
            name: "Content-Length".into(),
            value: "4".into(),
        })
        .step(HttpStep::RespondBodyChunk(b"pong".to_vec()))
        .step(HttpStep::RespondBodyEnd)
        .spawn()
        .expect("spawn backend");

    // Two proxies, same listen_path, different namespaces. The active
    // namespace is `alt`, so only the `alt` proxy must survive the loader's
    // post-parse namespace filter. Loaded together with namespace `ferrum`
    // (the harness's old default), the cross-resource uniqueness validator
    // would reject the YAML for duplicate `listen_path: /api`.
    let yaml = serde_yaml::to_string(&serde_json::json!({
        "proxies": [
            {
                "id": "ferrum-proxy",
                "namespace": "ferrum",
                "listen_path": "/api",
                "backend_scheme": "http",
                "backend_host": "127.0.0.1",
                // Bogus port — if the loader keeps this proxy, the request
                // would route here and we'd see a 502.
                "backend_port": 1u16,
                "strip_listen_path": true,
                "backend_connect_timeout_ms": 500,
                "backend_read_timeout_ms": 5000,
                "backend_write_timeout_ms": 5000,
            },
            {
                "id": "alt-proxy",
                "namespace": "alt",
                "listen_path": "/api",
                "backend_scheme": "http",
                "backend_host": "127.0.0.1",
                "backend_port": backend_port,
                "strip_listen_path": true,
                "backend_connect_timeout_ms": 2000,
                "backend_read_timeout_ms": 5000,
                "backend_write_timeout_ms": 5000,
            },
        ],
        "consumers": [],
        "upstreams": [],
        "plugin_configs": [],
    }))
    .expect("serialize yaml");

    let harness = GatewayHarness::builder()
        .mode_in_process()
        .file_config(yaml)
        .env("FERRUM_NAMESPACE", "alt")
        .spawn()
        .await
        .expect("spawn in-process gateway");

    harness
        .wait_healthy(Duration::from_secs(5))
        .await
        .expect("gateway healthy");

    let client = harness.http_client().expect("client");
    let resp = client
        .get(&harness.proxy_url("/api/ping"))
        .await
        .expect("response");
    assert_eq!(
        resp.status,
        reqwest::StatusCode::OK,
        "namespace override should have routed to the alt-namespace proxy; \
         body was {:?}",
        resp.body_text(),
    );
    assert_eq!(resp.body_text(), "pong");
}

// ────────────────────────────────────────────────────────────────────────────
// Regression: a cold in-process harness (warmup off, the default) must NOT
// trigger the immediate backend-capability probe pass. The h2c probe opens a
// real TCP/h2c handshake against plaintext HTTP backends, which would
// consume the first `ExpectRequest` step on a scripted backend or otherwise
// inflate per-test connection counts. With the fix, the registry stays
// empty until either the first periodic refresh (24 h default) or an
// explicit `POST /backend-capabilities/refresh`.
// ────────────────────────────────────────────────────────────────────────────
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn in_process_harness_does_not_probe_backend_when_warmup_disabled() {
    let reservation = reserve_port().await.expect("reserve backend port");
    let backend_port = reservation.port;
    let _backend = ScriptedHttp1Backend::builder(reservation.into_listener())
        .step(HttpStep::ExpectRequest(RequestMatcher::method_path(
            "GET", "/ping",
        )))
        .step(HttpStep::RespondStatus {
            status: 200,
            reason: "OK".into(),
        })
        .step(HttpStep::RespondHeader {
            name: "Content-Length".into(),
            value: "4".into(),
        })
        .step(HttpStep::RespondBodyChunk(b"pong".to_vec()))
        .step(HttpStep::RespondBodyEnd)
        .spawn()
        .expect("spawn backend");

    let yaml = file_mode_yaml_for_backend(backend_port);
    let harness = GatewayHarness::builder()
        .mode_in_process()
        .file_config(yaml)
        .spawn()
        .await
        .expect("spawn in-process gateway");

    harness
        .wait_healthy(Duration::from_secs(5))
        .await
        .expect("gateway healthy");

    // Pre-request: with the cold harness fix, no probe has fired, so the
    // capability registry should be empty. Any non-empty entry here means
    // the immediate refresh ran (e.g. `serve()` regressed to passing
    // `run_initial_refresh = true` regardless of the harness's preference).
    let snapshot = harness
        .get_admin_json("/backend-capabilities")
        .await
        .expect("backend-capabilities");
    assert_eq!(
        snapshot["entries"]
            .as_array()
            .map(|a| a.len())
            .unwrap_or(usize::MAX),
        0,
        "cold harness must not pre-probe backends; got snapshot {snapshot:?}",
    );

    // The actual proxy request still works — and since the probe never
    // fired, the backend's first `ExpectRequest` step lines up with the
    // test's GET, not with stray h2c handshake bytes.
    let client = harness.http_client().expect("client");
    let resp = client
        .get(&harness.proxy_url("/api/ping"))
        .await
        .expect("response");
    assert_eq!(resp.status, reqwest::StatusCode::OK);
    assert_eq!(resp.body_text(), "pong");
}

// ────────────────────────────────────────────────────────────────────────────
// Regression: when `file::serve` is invoked with no HTTP/HTTPS/admin
// listeners (stream-only deployment — for example TCP/UDP-only proxies with
// `FERRUM_PROXY_HTTP_PORT=0` and no admin listeners), `ServeHandles::join`
// must keep the function alive on the shutdown channel instead of returning
// after the background-task drain.
//
// Pre-refactor `run()` had an explicit `wait_shutdown.changed().await` loop
// for this case; mixing every handle into one Vec lost it. Without the fix
// the binary would exit ~5 s after startup despite stream proxies still
// serving traffic.
// ────────────────────────────────────────────────────────────────────────────
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn serve_blocks_until_shutdown_when_no_listener_handles() {
    use ferrum_edge::admin::jwt_auth::{JwtConfig, JwtManager};
    use ferrum_edge::config::types::GatewayConfig;
    use ferrum_edge::config::{EnvConfig, OperatingMode};
    use ferrum_edge::modes::file::{self, ServeOptions};

    // Empty config — we don't need any proxy to serve traffic; we just
    // need `serve()` to bring up zero HTTP/admin listeners and hand back
    // a `ServeHandles` whose `listener_handles` Vec is empty.
    let config: GatewayConfig =
        serde_yaml::from_str("proxies: []\nconsumers: []\nupstreams: []\nplugin_configs: []\n")
            .expect("parse empty config");

    let env_config = EnvConfig {
        mode: OperatingMode::File,
        // All ports 0 → no plaintext listeners spawned.
        proxy_http_port: 0,
        proxy_https_port: 0,
        admin_http_port: 0,
        admin_https_port: 0,
        admin_jwt_secret: Some("regression-test-secret-32-chars-min-len".to_string()),
        admin_jwt_issuer: "regression-test".to_string(),
        // Skip the in-flight drain entirely so this test isn't gated on
        // `FERRUM_SHUTDOWN_DRAIN_SECONDS`'s default of 30 s.
        shutdown_drain_seconds: 0,
        pool_warmup_enabled: false,
        max_connections: 0,
        ..EnvConfig::default()
    };

    let opts = ServeOptions {
        // No pre-bound listeners. Combined with the all-zero ports above,
        // `serve()` must hand back a ServeHandles with empty
        // `listener_handles`.
        admin_jwt_manager: Some(JwtManager::new(JwtConfig {
            secret: env_config.admin_jwt_secret.clone().unwrap(),
            issuer: env_config.admin_jwt_issuer.clone(),
            max_ttl_seconds: 3600,
            algorithm: jsonwebtoken::Algorithm::HS256,
        })),
        skip_initial_capability_refresh: true,
        ..ServeOptions::default()
    };

    let (shutdown_tx, _) = tokio::sync::watch::channel(false);
    let handles = file::serve(env_config, config, opts, shutdown_tx.clone())
        .await
        .expect("serve() must succeed with all-zero ports");

    let join_task = tokio::spawn(async move { handles.join().await });

    // The bug surfaces at exactly the background-drain timeout
    // (`BACKGROUND_DRAIN_TIMEOUT` = 5 s in `src/modes/file.rs`):
    // pre-fix, the empty listener loop is a no-op, the drain is skipped
    // (`shutdown_drain_seconds = 0`), and `join_background_handles` falls
    // through after its 5 s timeout because the DNS / overload / metrics
    // tasks never see a shutdown signal. So we have to wait *past* that
    // 5 s mark to prove `join()` is genuinely blocking on shutdown
    // (with the fix) rather than just slow to time out (without it).
    //
    // 6 s wall-clock is the price of this regression test; lowering it
    // would require exposing the timeout constant to tests, which is a
    // worse trade than the slower test.
    tokio::time::sleep(Duration::from_millis(6_000)).await;
    assert!(
        !join_task.is_finished(),
        "join() returned before shutdown was signalled — stream-only \
         deployments would exit ~5 s after startup",
    );

    // Now signal shutdown and confirm `join()` returns promptly. Generous
    // 2 s timeout — the actual cost is one watch-channel notification
    // plus the DNS / overload / metrics tasks each observing
    // `shutdown_rx.changed()`.
    shutdown_tx.send(true).expect("shutdown_tx send");
    tokio::time::timeout(Duration::from_secs(2), join_task)
        .await
        .expect("join() did not complete within 2 s of shutdown")
        .expect("join_task panicked");
}
