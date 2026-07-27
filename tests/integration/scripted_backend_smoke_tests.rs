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

    let bytes_received: Vec<u8> =
        b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok".to_vec();
    let backend = ScriptedTlsBackend::builder(
        reservation.into_listener(),
        TlsConfig::new(cert_pem, key_pem).with_alpn(vec![b"http/1.1".to_vec()]),
    )
    .step(TcpStep::ReadUntil(b"\r\n\r\n".to_vec()))
    .step(TcpStep::Write(bytes_received))
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
        "version": "1",
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
    let config: GatewayConfig = serde_yaml::from_str(
        "version: '1'\nproxies: []\nconsumers: []\nupstreams: []\nplugin_configs: []\n",
    )
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

    // Override `BACKGROUND_DRAIN_TIMEOUT` (production default 5 s) to a
    // small test-friendly value so the regression check below can use a
    // proportional sleep. The bug we're guarding against is "join()
    // returns after only the background-drain timeout instead of waiting
    // for shutdown" — the asymmetry is what matters (sleep > drain
    // timeout), not the absolute wall-clock. With 200 ms here the test
    // drops from ~10.6 s to under 0.5 s without losing the regression
    // signal.
    let drain_timeout = Duration::from_millis(200);
    let opts = ServeOptions {
        // No pre-bound listeners. Combined with the all-zero ports above,
        // `serve()` must hand back a ServeHandles with empty
        // `listener_handles`.
        admin_jwt_manager: Some(JwtManager::new(JwtConfig {
            secret: env_config.admin_jwt_secret.clone().unwrap(),
            issuer: env_config.admin_jwt_issuer.clone(),
            audience: None,
            max_ttl_seconds: 3600,
            algorithm: jsonwebtoken::Algorithm::HS256,
        })),
        skip_initial_capability_refresh: true,
        background_drain_timeout: Some(drain_timeout),
        ..ServeOptions::default()
    };

    let (shutdown_tx, _) = tokio::sync::watch::channel(false);
    let handles = file::serve(env_config, config, opts, shutdown_tx.clone())
        .await
        .expect("serve() must succeed with all-zero ports");

    let join_task = tokio::spawn(async move { handles.join().await });

    // The bug surfaces at exactly the background-drain timeout: pre-fix,
    // the empty listener loop is a no-op, the drain is skipped
    // (`shutdown_drain_seconds = 0`), and `join_background_handles` falls
    // through after its 5 s timeout because the DNS / overload / metrics
    // tasks never see a shutdown signal. So we have to wait *past* the
    // drain timeout to prove `join()` is genuinely blocking on shutdown
    // (with the fix) rather than just slow to time out (without it).
    //
    // We use 3× the configured `drain_timeout` above as the proof
    // window — gives a comfortable margin over jitter / runtime
    // scheduling on slow CI runners while staying small in absolute
    // terms.
    tokio::time::sleep(drain_timeout * 3).await;
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
        .expect("join_task panicked")
        .expect("listener task panicked");
}

// ────────────────────────────────────────────────────────────────────────────
// Regression: an invalid `FERRUM_BACKEND_ALLOW_IPS` value passed via
// `.env(...)` to the in-process harness must surface as a spawn error,
// not silently default to the most-permissive `Both`. Pre-fix the
// harness mapped any unrecognised value (typo like `pubic`, or a
// completely invalid string) to `Both`, while binary-mode startup
// rejects the same value via `EnvValue::parse_env`. That mode-parity
// gap let tests pass against permissive behaviour the real gateway
// would never accept.
// ────────────────────────────────────────────────────────────────────────────
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn in_process_harness_rejects_invalid_backend_allow_ips_override() {
    let backend_port = reserve_port().await.expect("port").port;
    let yaml = file_mode_yaml_for_backend(backend_port);
    let result = GatewayHarness::builder()
        .mode_in_process()
        .file_config(yaml)
        // Typo of `public`. Binary mode would refuse this; the
        // in-process harness must too.
        .env("FERRUM_BACKEND_ALLOW_IPS", "pubic")
        .spawn()
        .await;

    let err = match result {
        Ok(_) => panic!(
            "harness must reject invalid FERRUM_BACKEND_ALLOW_IPS, not silently default to Both",
        ),
        Err(e) => e,
    };
    let msg = err.to_string();
    assert!(
        msg.contains("FERRUM_BACKEND_ALLOW_IPS"),
        "error must name the invalid env var; got {msg:?}",
    );
    assert!(
        msg.contains("pubic"),
        "error must include the invalid value so the operator knows what to fix; got {msg:?}",
    );
}

// ────────────────────────────────────────────────────────────────────────────
// Regression: `stop_and_collect_logs` on the in-process backend must signal
// shutdown without aborting the inner join task — same no-abort contract as
// `Drop`. Codex P2 #8 flagged that the prior implementation aborted, which
// detaches gateway tasks instead of draining them. Returns empty string in
// in-process mode (log capture isn't available) and does not panic.
// ────────────────────────────────────────────────────────────────────────────
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn in_process_stop_and_collect_logs_returns_empty_without_aborting_join() {
    let backend_port = reserve_port().await.expect("port").port;
    let _backend = ScriptedHttp1Backend::builder(
        reserve_port()
            .await
            .expect("backend reserve")
            .into_listener(),
    )
    .step(HttpStep::ExpectRequest(RequestMatcher::method_path(
        "GET", "/ping",
    )))
    .step(HttpStep::RespondStatus {
        status: 200,
        reason: "OK".into(),
    })
    .spawn()
    .expect("spawn backend");

    let yaml = file_mode_yaml_for_backend(backend_port);
    let mut harness = GatewayHarness::builder()
        .mode_in_process()
        .file_config(yaml)
        .spawn()
        .await
        .expect("spawn in-process gateway");
    harness
        .wait_healthy(Duration::from_secs(5))
        .await
        .expect("gateway healthy");

    // The contract for the in-process branch: returns the empty string
    // (log capture isn't available) and does not panic. Aborting the join
    // task here would silently work in this assertion, so the regression
    // is also covered by the explicit `let _ = b.join.take()` (no abort
    // call) in the body and the inline comment that documents why.
    let logs = harness.stop_and_collect_logs();
    assert_eq!(
        logs, "",
        "in-process stop_and_collect_logs must return empty string"
    );
    // Dropping the harness after stop_and_collect_logs already consumed
    // shutdown_tx must not panic — the Drop impl handles `take()` returning
    // None.
    drop(harness);
}

// ────────────────────────────────────────────────────────────────────────────
// Regression: chaining `.file_config(yaml).db_sqlite().mode_in_process()`
// must error at spawn rather than silently running file mode against a
// `db_sqlite()` request. Pre-fix the harness only checked for `file_yaml`,
// so the DB-mode intent (set by the later `.db_sqlite()`) was dropped on
// the floor — tests would appear to exercise DB mode while actually using
// file mode, hiding real differences in behaviour.
// ────────────────────────────────────────────────────────────────────────────
#[tokio::test]
async fn in_process_harness_rejects_db_mode_after_file_config() {
    let backend_port = reserve_port().await.expect("port").port;
    let yaml = file_mode_yaml_for_backend(backend_port);
    let result = GatewayHarness::builder()
        .file_config(yaml)
        // The DB call after file_config flips mode_kind to Database;
        // mode_in_process must reject this rather than silently running
        // file mode.
        .db_sqlite()
        .mode_in_process()
        .spawn()
        .await;

    let err = match result {
        Ok(_) => panic!(
            "harness must reject .file_config().db_sqlite().mode_in_process() — \
             not silently fall back to file mode",
        ),
        Err(e) => e,
    };
    let msg = err.to_string();
    assert!(
        msg.contains("file mode only") || msg.contains("file_config"),
        "error must explain that in-process supports file mode only; got {msg:?}",
    );
}

// ────────────────────────────────────────────────────────────────────────────
// Regression: when `serve()` errors out of late startup (e.g. a stream
// proxy can't bind because its `listen_port` is already taken), the
// previously-spawned proxy / admin / DNS / overload / metrics tasks must
// be drained before the error propagates. Without the cleanup the
// `JoinHandle`s drop unawaited, the underlying tasks orphan, and the
// in-process retry path in `GatewayHarnessBuilder::spawn_in_process`
// accumulates leftover listeners holding sockets across attempts.
//
// Test recipe: pre-bind the proxy/admin listeners and a third TCP socket
// on a "stream" port. Configure a TCP stream proxy on that occupied
// stream port. Call `serve()` directly — it must error. Then re-bind the
// proxy listener's port: with cleanup the previous listener task exits
// and the port is free; without cleanup the orphan task keeps the port
// and the rebind fails.
// ────────────────────────────────────────────────────────────────────────────
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn serve_drains_spawned_tasks_when_late_startup_fails() {
    use ferrum_edge::admin::jwt_auth::{JwtConfig, JwtManager};
    use ferrum_edge::config::types::GatewayConfig;
    use ferrum_edge::config::{EnvConfig, OperatingMode};
    use ferrum_edge::modes::file::{self, ServeOptions};

    // Reserve and bind the proxy + admin ports we'll hand to serve().
    let proxy_listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind proxy");
    let admin_listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind admin");
    let proxy_port = proxy_listener.local_addr().unwrap().port();
    let admin_port = admin_listener.local_addr().unwrap().port();

    // Occupy a stream port so the gateway's `initial_reconcile_stream_listeners`
    // bind fails. We hold this for the lifetime of the test so the
    // gateway's bind attempt can't race in.
    let stream_blocker = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind stream blocker");
    let stream_port = stream_blocker.local_addr().unwrap().port();

    // Config with a TCP stream proxy on the occupied stream port. Build
    // via serde_json so the indent / multi-line YAML pitfalls don't
    // creep in.
    let config_json = serde_json::json!({
        "version": "1",
        "proxies": [{
            "id": "stream-proxy",
            "backend_scheme": "tcp",
            "backend_host": "127.0.0.1",
            "backend_port": 65000_u16,
            "listen_port": stream_port,
        }],
        "consumers": [],
        "upstreams": [],
        "plugin_configs": [],
    });
    let mut config: GatewayConfig =
        serde_json::from_value(config_json).expect("deserialize config");
    // Ad-hoc deserialization doesn't run the loader pipeline, so the
    // proxy's `dispatch_kind` defaults to a non-stream variant — and
    // `initial_reconcile_stream_listeners` would skip it. Call the
    // resolver so the stream proxy is actually classified as a stream
    // and the bind probe runs against `stream_port`.
    config.resolve_dispatch_kind();

    let env_config = EnvConfig {
        mode: OperatingMode::File,
        proxy_http_port: proxy_port,
        proxy_https_port: 0,
        admin_http_port: admin_port,
        admin_https_port: 0,
        admin_jwt_secret: Some("regression-test-secret-32-chars-min-len".to_string()),
        admin_jwt_issuer: "regression-test".to_string(),
        shutdown_drain_seconds: 0,
        pool_warmup_enabled: false,
        max_connections: 0,
        // Match the blocker's bind address so the conflict is unambiguous
        // (0.0.0.0 vs 127.0.0.1 binding semantics differ across platforms;
        // pinning both to loopback removes the variability).
        proxy_bind_address: "127.0.0.1".to_string(),
        stream_proxy_bind_address: "127.0.0.1".to_string(),
        ..EnvConfig::default()
    };

    let opts = ServeOptions {
        proxy_http: Some(proxy_listener),
        admin_http: Some(admin_listener),
        admin_jwt_manager: Some(JwtManager::new(JwtConfig {
            secret: env_config.admin_jwt_secret.clone().unwrap(),
            issuer: env_config.admin_jwt_issuer.clone(),
            audience: None,
            max_ttl_seconds: 3600,
            algorithm: jsonwebtoken::Algorithm::HS256,
        })),
        skip_initial_capability_refresh: true,
        ..ServeOptions::default()
    };

    let (shutdown_tx, _) = tokio::sync::watch::channel(false);
    let result = file::serve(env_config, config, opts, shutdown_tx.clone()).await;

    let err = match result {
        Ok(_) => panic!("serve() must fail when stream port {stream_port} is already taken",),
        Err(e) => e,
    };
    assert!(
        err.to_string().to_lowercase().contains("listener")
            || err.to_string().to_lowercase().contains("bind")
            || err.to_string().to_lowercase().contains("port"),
        "error must surface the bind failure; got {err}",
    );

    // The critical assertion: port released. With cleanup the proxy
    // listener task observed shutdown, exited, and dropped its listener.
    // Without cleanup the orphan task still owns the listener and this
    // bind would fail with EADDRINUSE. A small grace lets the runtime
    // finish dropping the listener after the task exits — generous
    // compared to the actual cost.
    tokio::time::sleep(Duration::from_millis(100)).await;
    let rebind = tokio::net::TcpListener::bind(format!("127.0.0.1:{proxy_port}")).await;
    rebind.expect(
        "proxy port should be free after serve() failure cleaned up the orphan listener task",
    );
}

// ────────────────────────────────────────────────────────────────────────────
// Regression (PR #2722 / Codex): a pre-bound `ServeOptions.admin_https`
// socket without both admin TLS paths must be dropped before reserved-port
// calculation. Without the drop, `serve()` keeps the FD until shutdown and
// `effective_reserved_ports()` still reserves it — so a stream proxy on that
// port is rejected and the OS port stays occupied even though nothing serves
// HTTPS on it.
//
// Non-vacuous proof: configure a TCP stream proxy on the same port the
// unused admin HTTPS socket held. `serve()` succeeding means the port was
// neither reserved nor still owned by the prebound FD (reserved-port
// validation and stream bind would both fail otherwise). `bound.admin_https`
// must stay `None`. The deliberate exception — prebound + both TLS paths
// still served under port 0 — is unchanged; this test targets the no-TLS
// drop path only.
// ────────────────────────────────────────────────────────────────────────────
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn serve_drops_prebound_admin_https_without_tls_before_reserved_ports() {
    use ferrum_edge::admin::jwt_auth::{JwtConfig, JwtManager};
    use ferrum_edge::config::types::GatewayConfig;
    use ferrum_edge::config::{EnvConfig, OperatingMode};
    use ferrum_edge::modes::file::{self, ServeOptions};

    // Do not use an ephemeral port for this ownership-transfer test. `serve()`
    // intentionally drops the admin socket several seconds before the stream
    // manager rebinds it; under the highly parallel protocols-data-plane shard,
    // an unrelated outbound connection can acquire that just-released
    // ephemeral source port during the gap and make the assertion fail with
    // EADDRINUSE even though Ferrum released the FD correctly. Scan a bounded
    // non-ephemeral test range so the gap still proves release/rebind without
    // racing the kernel's ephemeral allocator.
    let mut admin_https_listener = None;
    for port in 20_000..30_000 {
        if let Ok(listener) = tokio::net::TcpListener::bind(("127.0.0.1", port)).await {
            admin_https_listener = Some(listener);
            break;
        }
    }
    let admin_https_listener =
        admin_https_listener.expect("bind prebound admin HTTPS outside the ephemeral range");
    let admin_https_port = admin_https_listener.local_addr().unwrap().port();

    // Stream proxy on the same port the unused admin HTTPS socket held.
    // If the prebound FD were still reserved or still bound, serve() fails.
    let config_json = serde_json::json!({
        "version": "1",
        "proxies": [{
            "id": "stream-on-former-admin-https",
            "backend_scheme": "tcp",
            "backend_host": "127.0.0.1",
            "backend_port": 65000_u16,
            "listen_port": admin_https_port,
        }],
        "consumers": [],
        "upstreams": [],
        "plugin_configs": [],
    });
    let mut config: GatewayConfig =
        serde_json::from_value(config_json).expect("deserialize config");
    config.resolve_dispatch_kind();

    let env_config = EnvConfig {
        mode: OperatingMode::File,
        proxy_http_port: 0,
        proxy_https_port: 0,
        admin_http_port: 0,
        // Port 0 plus a prebound socket: the documented exception path, but
        // without TLS material so the socket must be dropped unused.
        admin_https_port: 0,
        admin_tls_cert_path: None,
        admin_tls_key_path: None,
        admin_jwt_secret: Some("regression-test-secret-32-chars-min-len".to_string()),
        admin_jwt_issuer: "regression-test".to_string(),
        shutdown_drain_seconds: 0,
        pool_warmup_enabled: false,
        max_connections: 0,
        proxy_bind_address: "127.0.0.1".to_string(),
        stream_proxy_bind_address: "127.0.0.1".to_string(),
        ..EnvConfig::default()
    };

    let opts = ServeOptions {
        admin_https: Some(admin_https_listener),
        admin_jwt_manager: Some(JwtManager::new(JwtConfig {
            secret: env_config.admin_jwt_secret.clone().unwrap(),
            issuer: env_config.admin_jwt_issuer.clone(),
            audience: None,
            max_ttl_seconds: 3600,
            algorithm: jsonwebtoken::Algorithm::HS256,
        })),
        skip_initial_capability_refresh: true,
        background_drain_timeout: Some(Duration::from_millis(200)),
        ..ServeOptions::default()
    };

    let (shutdown_tx, _) = tokio::sync::watch::channel(false);
    let handles = file::serve(env_config, config, opts, shutdown_tx.clone())
        .await
        .expect(
            "serve() must accept a stream proxy on the former admin HTTPS port when \
             the prebound socket is dropped for missing TLS material",
        );

    assert!(
        handles.bound.admin_https.is_none(),
        "no-TLS prebound admin HTTPS must not be served; bound={:?}",
        handles.bound.admin_https
    );

    shutdown_tx.send(true).expect("shutdown_tx send");
    tokio::time::timeout(Duration::from_secs(2), handles.join())
        .await
        .expect("join() did not complete within 2 s of shutdown")
        .expect("listener task panicked");
}

// ────────────────────────────────────────────────────────────────────────────
// Regression (PR #2722 / Codex P2): after dropping an unusable prebound admin
// HTTPS FD (no TLS paths), `effective_reserved_ports` must not fall back to a
// nonzero `FERRUM_ADMIN_HTTPS_PORT`. On 41a977b2 the `take()` cleared
// `prebound.admin_https` and the helper reserved the env port (e.g. 9443), so
// a stream proxy on that env port was rejected even though no admin HTTPS
// listener starts without both TLS paths.
//
// Negative case: prebound without TLS + nonzero env admin HTTPS + stream proxy
// on the env port → serve() must succeed.
// Positive control: same env port / no TLS / no prebound → serve() must still
// reject the stream proxy (ordinary env reservation unchanged).
// ────────────────────────────────────────────────────────────────────────────
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn serve_drop_prebound_admin_https_without_tls_does_not_reserve_env_https_port() {
    use ferrum_edge::admin::jwt_auth::{JwtConfig, JwtManager};
    use ferrum_edge::config::types::GatewayConfig;
    use ferrum_edge::config::{EnvConfig, OperatingMode};
    use ferrum_edge::modes::file::{self, ServeOptions};

    // Ephemeral stand-in for a nonzero env admin HTTPS port (avoids hardcoding
    // 9443 and colliding with unrelated listeners on the host).
    let env_admin_https_port = {
        let probe = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("probe free port for env admin HTTPS");
        let port = probe.local_addr().unwrap().port();
        drop(probe);
        port
    };

    let admin_https_listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind prebound admin HTTPS");

    let config_json = serde_json::json!({
        "version": "1",
        "proxies": [{
            "id": "stream-on-env-admin-https",
            "backend_scheme": "tcp",
            "backend_host": "127.0.0.1",
            "backend_port": 65000_u16,
            "listen_port": env_admin_https_port,
        }],
        "consumers": [],
        "upstreams": [],
        "plugin_configs": [],
    });
    let mut config: GatewayConfig =
        serde_json::from_value(config_json).expect("deserialize config");
    config.resolve_dispatch_kind();

    let env_config = EnvConfig {
        mode: OperatingMode::File,
        proxy_http_port: 0,
        proxy_https_port: 0,
        admin_http_port: 0,
        // Nonzero env port + prebound FD without TLS: drop must not leave the
        // env port reserved.
        admin_https_port: env_admin_https_port,
        admin_tls_cert_path: None,
        admin_tls_key_path: None,
        admin_jwt_secret: Some("regression-test-secret-32-chars-min-len".to_string()),
        admin_jwt_issuer: "regression-test".to_string(),
        shutdown_drain_seconds: 0,
        pool_warmup_enabled: false,
        max_connections: 0,
        proxy_bind_address: "127.0.0.1".to_string(),
        stream_proxy_bind_address: "127.0.0.1".to_string(),
        ..EnvConfig::default()
    };

    let opts = ServeOptions {
        admin_https: Some(admin_https_listener),
        admin_jwt_manager: Some(JwtManager::new(JwtConfig {
            secret: env_config.admin_jwt_secret.clone().unwrap(),
            issuer: env_config.admin_jwt_issuer.clone(),
            audience: None,
            max_ttl_seconds: 3600,
            algorithm: jsonwebtoken::Algorithm::HS256,
        })),
        skip_initial_capability_refresh: true,
        background_drain_timeout: Some(Duration::from_millis(200)),
        ..ServeOptions::default()
    };

    let (shutdown_tx, _) = tokio::sync::watch::channel(false);
    let handles = file::serve(env_config, config, opts, shutdown_tx.clone())
        .await
        .expect(
            "serve() must accept a stream proxy on the env admin HTTPS port when a \
             no-TLS prebound admin HTTPS FD is dropped (env reservation suppressed)",
        );

    assert!(
        handles.bound.admin_https.is_none(),
        "no-TLS prebound admin HTTPS must not be served; bound={:?}",
        handles.bound.admin_https
    );

    shutdown_tx.send(true).expect("shutdown_tx send");
    tokio::time::timeout(Duration::from_secs(2), handles.join())
        .await
        .expect("join() did not complete within 2 s of shutdown")
        .expect("listener task panicked");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn serve_still_reserves_env_admin_https_port_without_prebound_drop() {
    use ferrum_edge::admin::jwt_auth::{JwtConfig, JwtManager};
    use ferrum_edge::config::types::GatewayConfig;
    use ferrum_edge::config::{EnvConfig, OperatingMode};
    use ferrum_edge::modes::file::{self, ServeOptions};

    let env_admin_https_port = {
        let probe = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("probe free port for env admin HTTPS");
        let port = probe.local_addr().unwrap().port();
        drop(probe);
        port
    };

    let config_json = serde_json::json!({
        "version": "1",
        "proxies": [{
            "id": "stream-on-env-admin-https",
            "backend_scheme": "tcp",
            "backend_host": "127.0.0.1",
            "backend_port": 65000_u16,
            "listen_port": env_admin_https_port,
        }],
        "consumers": [],
        "upstreams": [],
        "plugin_configs": [],
    });
    let mut config: GatewayConfig =
        serde_json::from_value(config_json).expect("deserialize config");
    config.resolve_dispatch_kind();

    let env_config = EnvConfig {
        mode: OperatingMode::File,
        proxy_http_port: 0,
        proxy_https_port: 0,
        admin_http_port: 0,
        // No prebound drop: nonzero env admin HTTPS must still be reserved
        // against stream proxies (ordinary env-fallback semantics).
        admin_https_port: env_admin_https_port,
        admin_tls_cert_path: None,
        admin_tls_key_path: None,
        admin_jwt_secret: Some("regression-test-secret-32-chars-min-len".to_string()),
        admin_jwt_issuer: "regression-test".to_string(),
        shutdown_drain_seconds: 0,
        pool_warmup_enabled: false,
        max_connections: 0,
        proxy_bind_address: "127.0.0.1".to_string(),
        stream_proxy_bind_address: "127.0.0.1".to_string(),
        ..EnvConfig::default()
    };

    let opts = ServeOptions {
        admin_jwt_manager: Some(JwtManager::new(JwtConfig {
            secret: env_config.admin_jwt_secret.clone().unwrap(),
            issuer: env_config.admin_jwt_issuer.clone(),
            audience: None,
            max_ttl_seconds: 3600,
            algorithm: jsonwebtoken::Algorithm::HS256,
        })),
        skip_initial_capability_refresh: true,
        background_drain_timeout: Some(Duration::from_millis(200)),
        ..ServeOptions::default()
    };

    let (shutdown_tx, _) = tokio::sync::watch::channel(false);
    // Match instead of expect_err: ServeHandles does not implement Debug, and
    // Result::expect_err requires Debug on the Ok type.
    let err = match file::serve(env_config, config, opts, shutdown_tx).await {
        Ok(_) => panic!(
            "serve() must still reject a stream proxy on the env admin HTTPS port when \
             no unusable prebound FD was dropped"
        ),
        Err(err) => err,
    };
    let msg = err.to_string();
    assert!(
        msg.to_lowercase().contains("stream proxy port conflicts")
            || msg.to_lowercase().contains("reserved"),
        "error must surface the reserved-port conflict; got {msg}",
    );
}

// ────────────────────────────────────────────────────────────────────────────
// Regression: `pool_warmup_enabled(...)` and `.env("FERRUM_POOL_WARMUP_ENABLED",
// ...)` must agree on last-wins ordering across binary AND in-process modes.
// Pre-fix the helper updated `inner` (binary subprocess env) but NOT
// `extra_env` (in-process apply_env_overrides input), so chaining
// `.env("...", "true").pool_warmup_enabled(false)` ended with warmup
// off in binary mode but on in in-process — same builder chain, different
// observable behaviour.
//
// We assert the post-`.pool_warmup_enabled(false)` reality via the
// backend-capability registry: warmup-off keeps the registry empty (matches
// the existing `in_process_harness_does_not_probe_backend_when_warmup_disabled`
// test). With the bug the stale `.env("...", "true")` would flip warmup back
// on inside `apply_env_overrides`, the registry would populate, and the
// assertion would fail.
// ────────────────────────────────────────────────────────────────────────────
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn in_process_pool_warmup_helper_wins_over_earlier_env_call() {
    let backend_port = reserve_port().await.expect("port").port;
    let _backend = ScriptedHttp1Backend::builder(
        reserve_port()
            .await
            .expect("backend reserve")
            .into_listener(),
    )
    .step(HttpStep::ExpectRequest(RequestMatcher::method_path(
        "GET", "/ping",
    )))
    .step(HttpStep::RespondStatus {
        status: 200,
        reason: "OK".into(),
    })
    .spawn()
    .expect("spawn backend");

    let yaml = file_mode_yaml_for_backend(backend_port);
    let harness = GatewayHarness::builder()
        .mode_in_process()
        .file_config(yaml)
        // Stale env first.
        .env("FERRUM_POOL_WARMUP_ENABLED", "true")
        // Then the helper. Last call must win.
        .pool_warmup_enabled(false)
        .spawn()
        .await
        .expect("spawn in-process gateway");
    harness
        .wait_healthy(Duration::from_secs(5))
        .await
        .expect("gateway healthy");

    // Cold registry == helper won (warmup off). Pre-fix the stale
    // .env("...", "true") would have made apply_env_overrides flip
    // warmup back on, and the registry would have at least one entry
    // from the startup probe.
    let snapshot = harness
        .get_admin_json("/backend-capabilities")
        .await
        .expect("backend-capabilities");
    let entry_count = snapshot["entries"]
        .as_array()
        .map(|a| a.len())
        .unwrap_or(usize::MAX);
    assert_eq!(
        entry_count, 0,
        "pool_warmup_enabled(false) must win over earlier .env(...) — \
         backend-capabilities snapshot was {snapshot:?}",
    );
}
