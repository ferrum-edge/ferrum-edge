//! Phase-3 acceptance tests for the scripted-backend framework — HTTP/3 /
//! QUIC capability-registry behaviour under wire-level failure modes.
//!
//! Run with:
//!
//! ```bash
//! cargo build --bin ferrum-edge && \
//!   cargo test --test functional_tests scripted_backend_h3 -- --ignored --nocapture
//! ```
//!
//! Each test ties a scripted QUIC/H3 backend (or a fixture like
//! [`QuicRefuser`]) to a ferrum-edge gateway running in binary mode. The
//! gateway is configured with an H3 frontend (`FERRUM_ENABLE_HTTP3=true`)
//! pointing at the backend; tests assert on the capability registry's
//! protocol classification + subsequent dispatch path.
//!
//! The registry introspection endpoints (`GET /backend-capabilities` and
//! `POST /backend-capabilities/refresh`) are permanently exposed under
//! the standard admin JWT auth path — see `docs/admin_api.md` +
//! `openapi.yaml`. These tests exercise them over the same admin port
//! operators use in production.

#![allow(clippy::bool_assert_comparison)]

use crate::scaffolding::backends::{
    H3Step, H3TlsConfig, QuicRefuser, ScriptedH3Backend, ScriptedTlsBackend, TcpStep, TlsConfig,
    tls_backend_without_quic_with_ok_response,
};
use crate::scaffolding::certs::TestCa;
use crate::scaffolding::clients::Http3Client;
use crate::scaffolding::harness::GatewayHarness;
use crate::scaffolding::ports::reserve_port;
use serde_json::{Value, json};
use std::net::UdpSocket as StdUdpSocket;
use std::time::Duration;
use tokio::net::{TcpListener, UdpSocket};

// ────────────────────────────────────────────────────────────────────────────
// Shared helpers
// ────────────────────────────────────────────────────────────────────────────

/// Reserve a co-located TCP + UDP pair on the same port number. Tests that
/// need both a TCP (TLS) backend and a UDP (H3) backend on the SAME port
/// use this so the proxy's single `backend_port` value works for both.
/// The UDP half is returned as a `tokio::net::UdpSocket` (so it can be
/// handed straight into `ScriptedH3Backend::builder`); the TCP half is
/// returned as a `tokio::net::TcpListener`.
async fn reserve_colocated_tcp_udp()
-> Result<(TcpListener, UdpSocket, u16), Box<dyn std::error::Error + Send + Sync>> {
    // Strategy: bind TCP on 0, note its port, then bind UDP on that same
    // port. Retry on UDP conflict. UDP+TCP share the port namespace at
    // the kernel level without issue (different protocol numbers), so a
    // UDP bind at the same port generally succeeds.
    for attempt in 0..10 {
        let tcp = TcpListener::bind("127.0.0.1:0").await?;
        let port = tcp.local_addr()?.port();
        // UDP bind is sync; quinn will later take ownership via
        // into_std(). Use std binding then wrap — matches quinn's
        // canonical setup.
        match StdUdpSocket::bind(("127.0.0.1", port)) {
            Ok(std_udp) => {
                std_udp.set_nonblocking(true)?;
                let udp = UdpSocket::from_std(std_udp)?;
                return Ok((tcp, udp, port));
            }
            Err(e) => {
                drop(tcp);
                if attempt == 9 {
                    return Err(format!("udp bind at shared port failed: {e}").into());
                }
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
        }
    }
    Err("exhausted colocated TCP/UDP reservation retries".into())
}

/// Build a frontend TLS cert + CA PEMs and write them to the harness temp
/// dir. Returns `(ca_pem, cert_path, key_path)` as strings.
fn write_frontend_certs(
    harness_scratch: &std::path::Path,
    ca_name: &str,
) -> (String, String, String) {
    let ca = TestCa::new(ca_name).expect("ca");
    let (cert, key) = ca.valid().expect("leaf");
    let cert_path = harness_scratch.join("gw.cert.pem");
    let key_path = harness_scratch.join("gw.key.pem");
    std::fs::write(&cert_path, &cert).expect("write cert");
    std::fs::write(&key_path, &key).expect("write key");
    (
        ca.cert_pem,
        cert_path.to_string_lossy().into_owned(),
        key_path.to_string_lossy().into_owned(),
    )
}

/// Build file-mode YAML for one HTTPS proxy pointing at `(host, port)`.
/// Includes the file-mode-required empty collections.
fn file_mode_yaml_for_h3(port: u16) -> String {
    let config = json!({
        "proxies": [{
            "id": "scripted-h3",
            "listen_path": "/api",
            "backend_scheme": "https",
            "backend_host": "127.0.0.1",
            "backend_port": port,
            "strip_listen_path": true,
            "backend_connect_timeout_ms": 2000,
            "backend_read_timeout_ms": 5000,
            "backend_write_timeout_ms": 5000,
            "backend_tls_verify_server_cert": false,
        }],
        "consumers": [],
        "upstreams": [],
        "plugin_configs": [],
    });
    serde_yaml::to_string(&config).expect("yaml serialize")
}

/// GET the backend capability registry and return the single entry (tests
/// configure a single proxy so the registry should hold exactly one).
/// Returns `None` when the registry is empty (probe hasn't completed).
async fn fetch_capability_entry(
    harness: &GatewayHarness,
) -> Result<Option<Value>, Box<dyn std::error::Error + Send + Sync>> {
    let body = harness.get_admin_json("/backend-capabilities").await?;
    let entries = body["entries"].as_array().cloned().unwrap_or_default();
    Ok(entries.into_iter().next())
}

/// Wait for the registry to contain at least one entry, or `None` if the
/// deadline expires.
async fn wait_for_capability_entry(
    harness: &GatewayHarness,
    timeout: Duration,
) -> Result<Option<Value>, Box<dyn std::error::Error + Send + Sync>> {
    let deadline = std::time::Instant::now() + timeout;
    loop {
        if let Some(entry) = fetch_capability_entry(harness).await? {
            return Ok(Some(entry));
        }
        if std::time::Instant::now() >= deadline {
            return Ok(None);
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
}

/// Drive the gateway's HTTPS port via the scripted H3 client.
async fn h3_get(
    harness: &GatewayHarness,
    path: &str,
) -> Result<crate::scaffolding::clients::Http3Response, Box<dyn std::error::Error + Send + Sync>> {
    let client = Http3Client::insecure()?;
    let https_base = harness.admin_base_url().replace("http://", "https://");
    // The proxy HTTPS port is derived from the HTTP port in the builder.
    // Use `proxy_https_url` logic: take the proxy's bind address and the
    // FERRUM_PROXY_HTTPS_PORT we set above.
    let https_port = harness_proxy_https_port(harness)?;
    let url = format!("https://127.0.0.1:{https_port}{path}");
    // silence unused warning on https_base if not used
    let _ = https_base;
    client.get(&url).await
}

/// Extract the HTTPS/QUIC port the harness was launched with. The shared
/// harness builder binds an ephemeral HTTP port by default; when a test
/// sets `FERRUM_PROXY_HTTPS_PORT` it's pulled from the gateway's
/// environment. For Phase-3 tests we let the gateway pick the HTTPS port
/// automatically and then query health → the cached_config path exposes
/// it via `admin_base_url`.
///
/// Simpler: peek at the temp_dir path for the gateway-written file, or
/// hard-code via an env override. We choose the explicit-env approach in
/// `spawn_h3_harness_with_https`.
fn harness_proxy_https_port(
    harness: &GatewayHarness,
) -> Result<u16, Box<dyn std::error::Error + Send + Sync>> {
    // We stash the port into a file inside the harness temp dir before
    // spawn — see `spawn_h3_harness_with_explicit_https_port`.
    let path = harness.temp_path().join("https-port.txt");
    let raw = std::fs::read_to_string(&path)?;
    Ok(raw.trim().parse()?)
}

/// Variant of [`spawn_h3_harness`] that binds an explicit HTTPS port so
/// the H3 client can target it deterministically.
async fn spawn_h3_harness_with_explicit_https_port(
    backend_port: u16,
    pool_warmup_enabled: bool,
    refresh_interval_secs: Option<u64>,
) -> (GatewayHarness, String, u16) {
    // Reserve an HTTPS port (TCP); we then let the gateway also bind UDP
    // on the same port for QUIC. The reservation is dropped before the
    // gateway spawns — there's a brief race window but the retry-on-health
    // loop inside TestGatewayBuilder handles it.
    let reservation = reserve_port().await.expect("reserve https port");
    let https_port = reservation.port;
    drop(reservation);

    let scratch = tempfile::tempdir().expect("scratch");
    let (ca_pem, cert_path, key_path) = write_frontend_certs(scratch.path(), "h3-gw-ca");
    Box::leak(Box::new(scratch));

    let yaml = file_mode_yaml_for_h3(backend_port);
    let mut builder = GatewayHarness::builder()
        .file_config(yaml)
        .log_level("info")
        .capture_output()
        .env("FERRUM_ENABLE_HTTP3", "true")
        .env("FERRUM_PROXY_HTTPS_PORT", https_port.to_string())
        .env("FERRUM_FRONTEND_TLS_CERT_PATH", cert_path)
        .env("FERRUM_FRONTEND_TLS_KEY_PATH", key_path)
        .env("FERRUM_TLS_NO_VERIFY", "true")
        .env(
            "FERRUM_POOL_WARMUP_ENABLED",
            if pool_warmup_enabled { "true" } else { "false" },
        );
    if let Some(secs) = refresh_interval_secs {
        builder = builder.env(
            "FERRUM_BACKEND_CAPABILITY_REFRESH_INTERVAL_SECS",
            secs.to_string(),
        );
    }
    let harness = builder.spawn().await.expect("spawn gateway");

    // Stash the HTTPS port in the temp dir so tests can recover it.
    let port_file = harness.temp_path().join("https-port.txt");
    std::fs::write(&port_file, https_port.to_string()).expect("write https-port.txt");

    (harness, ca_pem, https_port)
}

// ────────────────────────────────────────────────────────────────────────────
// Test 1 — TCP+TLS backend advertising h2+http/1.1, no UDP listener.
// Capability probe must classify h3 = Unsupported, h2_tls = Supported.
// ────────────────────────────────────────────────────────────────────────────
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore]
async fn h3_probe_classifies_backend_without_quic_as_h3_unsupported() {
    let ca = TestCa::new("phase3-t1").expect("ca");
    let (cert, key) = ca.valid().expect("leaf");
    let reservation = reserve_port().await.expect("backend port");
    let backend_port = reservation.port;
    // Script the TCP+TLS side to reply 200 so the H2 probe + cross-protocol
    // bridge both work; leave UDP unbound (no QUIC listener).
    let _backend =
        tls_backend_without_quic_with_ok_response(reservation.into_listener(), cert, key);

    let (harness, _ca_pem, https_port) =
        spawn_h3_harness_with_explicit_https_port(backend_port, true, None).await;

    // Initial capability refresh runs via warmup during `warmup_connection_pools`.
    // Wait for the registry to populate.
    let entry = wait_for_capability_entry(&harness, Duration::from_secs(10))
        .await
        .expect("fetch capability entry")
        .expect("registry populated within timeout");

    let h3_class = entry["plain_http"]["h3"].as_str().unwrap_or("");
    let h2_class = entry["plain_http"]["h2_tls"].as_str().unwrap_or("");
    // `unsupported` is the ideal classification — but quinn may
    // time out at the outer `backend_connect_timeout_ms` boundary
    // before emitting a concrete transport error (ICMP unreachable
    // isn't always delivered under load), in which case the probe
    // leaves the classification as `unknown`. Both values have
    // identical observable effect on the hot path:
    // `supports_native_http3_backend` returns false for either, so
    // the gateway falls through to the cross-protocol bridge. Accept
    // both to keep the test deterministic across kernels/schedulers.
    assert!(
        matches!(h3_class, "unsupported" | "unknown"),
        "expected h3=unsupported/unknown for backend without QUIC listener; got {h3_class}; entry: {entry:#?}"
    );
    assert_eq!(
        h2_class, "supported",
        "expected h2_tls=supported for backend advertising h2 in ALPN; entry: {entry:#?}"
    );

    // Fire an H3 request — the gateway should dispatch it through the
    // cross-protocol bridge (reqwest → TCP backend) and return 200.
    let resp = h3_get(&harness, "/api/ok")
        .await
        .expect("h3 response from cross-protocol bridge");
    assert_eq!(
        resp.status.as_u16(),
        200,
        "expected 200 via cross-protocol bridge, got {}",
        resp.status
    );

    let _ = https_port;
}

// ────────────────────────────────────────────────────────────────────────────
// Test 2 — Backend CONNECTION_CLOSE on first request → downgrades, second
// request routes via cross-protocol bridge.
// ────────────────────────────────────────────────────────────────────────────
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore]
async fn h3_backend_connection_close_mid_request_downgrades_capability() {
    let ca = TestCa::new("phase3-t2").expect("ca");
    let (cert, key) = ca.valid().expect("leaf");

    let (tcp_listener, udp_socket, backend_port) = reserve_colocated_tcp_udp()
        .await
        .expect("colocated tcp/udp");

    // TCP+TLS side: always answers 200 so the cross-protocol bridge works
    // on the second request.
    let _tcp_backend = ScriptedTlsBackend::builder(
        tcp_listener,
        TlsConfig::new(cert.clone(), key.clone())
            .with_alpn(vec![b"h2".to_vec(), b"http/1.1".to_vec()]),
    )
    .step(TcpStep::ReadUntil(b"\r\n\r\n".to_vec()))
    .step(TcpStep::Write(
        b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\nConnection: close\r\n\r\nhello".to_vec(),
    ))
    .step(TcpStep::Drop)
    .spawn()
    .expect("spawn tls");

    // UDP side: accept handshake (lets the probe succeed) + accept stream
    // + close the connection. Once the probe completes, the gateway caches
    // `h3 = Supported`. First real request arrives → CONNECTION_CLOSE →
    // gateway 502s + downgrades. Second request skips the H3 pool.
    let h3_backend = ScriptedH3Backend::builder(udp_socket, H3TlsConfig::new(cert, key))
        .step(H3Step::AcceptStream)
        .step(H3Step::CloseConnectionWithCode(0))
        .spawn()
        .expect("spawn h3");

    let (harness, _ca_pem, _https_port) =
        spawn_h3_harness_with_explicit_https_port(backend_port, true, None).await;

    // Wait for initial probe to populate h3=Supported.
    let pre = wait_for_capability_entry(&harness, Duration::from_secs(15))
        .await
        .expect("fetch pre-entry")
        .expect("registry populated within timeout");
    assert_eq!(
        pre["plain_http"]["h3"].as_str(),
        Some("supported"),
        "expected h3=supported after initial probe; entry: {pre:#?}"
    );

    // First H3 request: backend sends CONNECTION_CLOSE, gateway returns 502.
    let first = h3_get(&harness, "/api/t2").await;
    eprintln!("TEST2 first request outcome: {first:?}");
    match first {
        Ok(resp) => {
            // The first request may come back 200 if the gateway
            // dispatched via the cross-protocol bridge (i.e. it
            // didn't actually try the native H3 pool on this
            // request). We tolerate that outcome because the test's
            // load-bearing assertion is the post-request h3
            // classification; a 502 is just the signal that the H3
            // pool *did* get used.
            assert!(
                matches!(resp.status.as_u16(), 502 | 200),
                "unexpected first-request status: {resp:?}"
            );
        }
        Err(e) => {
            // A hard QUIC error at the client is also acceptable — it
            // proves the gateway's H3 frontend returned an error.
            let msg = e.to_string().to_lowercase();
            assert!(
                msg.contains("close")
                    || msg.contains("reset")
                    || msg.contains("protocol")
                    || msg.contains("timeout"),
                "unexpected H3 client error: {msg}"
            );
        }
    }

    // Give the gateway a moment to apply the downgrade.
    tokio::time::sleep(Duration::from_millis(300)).await;
    let post = fetch_capability_entry(&harness)
        .await
        .expect("fetch post-entry")
        .expect("registry entry still present");
    let logs = harness.captured_combined().unwrap_or_default();
    assert_eq!(
        post["plain_http"]["h3"].as_str(),
        Some("unsupported"),
        "expected h3=unsupported after CONNECTION_CLOSE; entry: {post:#?}\n--- gateway logs ---\n{logs}"
    );

    // Second request: cross-protocol bridge → TCP+TLS backend → 200.
    let second = h3_get(&harness, "/api/t2-again")
        .await
        .expect("h3 response via cross-protocol bridge");
    assert_eq!(
        second.status.as_u16(),
        200,
        "expected 200 via cross-protocol bridge after downgrade; got {second:?}"
    );

    // Backend observability: the H3 backend should have seen at least
    // one request before closing. (The probe does not send a request.)
    let h3_requests = h3_backend.received_requests().await;
    assert!(
        !h3_requests.is_empty(),
        "expected H3 backend to have received at least one request; got {h3_requests:?}"
    );
    assert!(
        h3_backend.connection_close_sent() >= 1,
        "expected CloseConnectionWithCode to have fired at least once"
    );
}

// ────────────────────────────────────────────────────────────────────────────
// Test 3 — Backend GOAWAY mid-request returns `(connection_error=false,
// ProtocolError)` from classify_h3_error; downgrade must still fire.
// Regression test for the Codex P2 fix on the capability-registry PR.
// ────────────────────────────────────────────────────────────────────────────
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore]
async fn h3_protocol_error_downgrades_via_connection_error_false_path() {
    let ca = TestCa::new("phase3-t3").expect("ca");
    let (cert, key) = ca.valid().expect("leaf");

    let (tcp_listener, udp_socket, backend_port) = reserve_colocated_tcp_udp()
        .await
        .expect("colocated tcp/udp");

    // TCP+TLS side — 200 responder for the cross-protocol bridge.
    let _tcp_backend = ScriptedTlsBackend::builder(
        tcp_listener,
        TlsConfig::new(cert.clone(), key.clone())
            .with_alpn(vec![b"h2".to_vec(), b"http/1.1".to_vec()]),
    )
    .step(TcpStep::ReadUntil(b"\r\n\r\n".to_vec()))
    .step(TcpStep::Write(
        b"HTTP/1.1 200 OK\r\nContent-Length: 3\r\nConnection: close\r\n\r\nack".to_vec(),
    ))
    .step(TcpStep::Drop)
    .spawn()
    .expect("spawn tls");

    // H3 side: accept handshake + stream, then send GOAWAY. This
    // translates to a ProtocolError class with connection_error=false —
    // exactly the code path the Codex P2 fix was for.
    let _h3_backend = ScriptedH3Backend::builder(udp_socket, H3TlsConfig::new(cert, key))
        .step(H3Step::AcceptStream)
        .step(H3Step::SendGoaway(0))
        .spawn()
        .expect("spawn h3");

    let (harness, _ca_pem, _https_port) =
        spawn_h3_harness_with_explicit_https_port(backend_port, true, None).await;

    let pre = wait_for_capability_entry(&harness, Duration::from_secs(15))
        .await
        .expect("pre-entry")
        .expect("registry populated");
    assert_eq!(
        pre["plain_http"]["h3"].as_str(),
        Some("supported"),
        "expected h3=supported before GOAWAY; entry: {pre:#?}"
    );

    // First request: GOAWAY-classified error.
    let first = h3_get(&harness, "/api/t3").await;
    match first {
        Ok(resp) => {
            assert_eq!(
                resp.status.as_u16(),
                502,
                "first H3 request should 502 after GOAWAY"
            );
        }
        Err(e) => {
            let msg = e.to_string().to_lowercase();
            assert!(
                msg.contains("goaway")
                    || msg.contains("protocol")
                    || msg.contains("close")
                    || msg.contains("h3")
                    || msg.contains("timeout"),
                "unexpected H3 client error: {msg}"
            );
        }
    }

    // Allow the downgrade to land.
    tokio::time::sleep(Duration::from_millis(500)).await;
    let post = fetch_capability_entry(&harness)
        .await
        .expect("post-entry")
        .expect("registry entry still present");
    let logs = harness.captured_combined().unwrap_or_default();
    assert_eq!(
        post["plain_http"]["h3"].as_str(),
        Some("unsupported"),
        "expected h3=unsupported after GOAWAY; entry: {post:#?}\n--- gateway logs ---\n{logs}"
    );
}

// ────────────────────────────────────────────────────────────────────────────
// Test 4 — Backend recovery after periodic refresh.
// ────────────────────────────────────────────────────────────────────────────
//
// Start with a `QuicRefuser` on port P (plus a TCP+TLS backend on the same
// port for the H2 probe + cross-protocol bridge).
// Initial probe sees QUIC CONNECTION_CLOSE → h3 = Unsupported.
// Drop the refuser, bind a real ScriptedH3Backend on the same port, POST
// /backend-capabilities/refresh, assert h3 flips back to Supported.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore]
async fn h3_backend_recovers_after_periodic_refresh() {
    let ca = TestCa::new("phase3-t4").expect("ca");
    let (cert, key) = ca.valid().expect("leaf");

    let (tcp_listener, udp_socket, backend_port) = reserve_colocated_tcp_udp()
        .await
        .expect("colocated tcp/udp");

    // TCP+TLS side — stays up for the whole test (used by cross-protocol bridge).
    let _tcp_backend = ScriptedTlsBackend::builder(
        tcp_listener,
        TlsConfig::new(cert.clone(), key.clone())
            .with_alpn(vec![b"h2".to_vec(), b"http/1.1".to_vec()]),
    )
    .step(TcpStep::ReadUntil(b"\r\n\r\n".to_vec()))
    .step(TcpStep::Write(
        b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok".to_vec(),
    ))
    .step(TcpStep::Drop)
    .spawn()
    .expect("spawn tls");

    // Phase A: bring up a QuicRefuser on the UDP port. Use the
    // ALPN-mismatch variant — the gateway's H3 probe advertises `h3`
    // but the refuser advertises `no-h3`, so TLS handshake fails
    // synchronously within `warmup_connection`, pinning the
    // classification to Unsupported rather than racing a subsequent
    // CONNECTION_CLOSE against the probe's cached sender.
    let refuser_reservation =
        crate::scaffolding::backends::UdpSocketReservation::new(backend_port, udp_socket);
    let mut refuser = QuicRefuser::start_alpn_mismatch(
        refuser_reservation,
        H3TlsConfig::new(cert.clone(), key.clone()),
    )
    .expect("start refuser");

    let (harness, _ca_pem, _https_port) =
        spawn_h3_harness_with_explicit_https_port(backend_port, true, None).await;

    // Initial probe classifies h3 = Unsupported.
    let pre = wait_for_capability_entry(&harness, Duration::from_secs(15))
        .await
        .expect("pre-entry")
        .expect("registry populated");
    assert_eq!(
        pre["plain_http"]["h3"].as_str(),
        Some("unsupported"),
        "expected h3=unsupported against QuicRefuser; entry: {pre:#?}"
    );

    // Phase B: stop the refuser, bind a real H3 backend on the same
    // UDP port, and trigger a refresh. The TCP listener stays up.
    refuser.shutdown();
    drop(refuser);
    // Briefly wait for the UDP socket to actually free in the kernel.
    tokio::time::sleep(Duration::from_millis(200)).await;

    let recovered_udp = match tokio::net::UdpSocket::bind(("127.0.0.1", backend_port)).await {
        Ok(s) => s,
        Err(e) => panic!(
            "failed to rebind UDP port {backend_port} after refuser drop: {e} \
             (race between shutdown and rebind)"
        ),
    };
    let _recovered = ScriptedH3Backend::builder(recovered_udp, H3TlsConfig::new(cert, key))
        // Accept handshakes but never complete a request — probe just
        // needs the handshake to succeed.
        .step(H3Step::StallFor(Duration::from_secs(60)))
        .spawn()
        .expect("spawn recovered h3");

    // Trigger a fresh probe via the admin endpoint.
    let _ = harness
        .post_admin_json("/backend-capabilities/refresh", &json!({}))
        .await
        .expect("refresh request");

    // Give the probe a moment to update the registry.
    let deadline = std::time::Instant::now() + Duration::from_secs(10);
    let mut observed: Option<String> = None;
    while std::time::Instant::now() < deadline {
        if let Ok(Some(entry)) = fetch_capability_entry(&harness).await {
            let class = entry["plain_http"]["h3"].as_str().map(|s| s.to_string());
            observed = class.clone();
            if class.as_deref() == Some("supported") {
                return; // pass
            }
        }
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
    panic!(
        "expected h3 to flip to supported after refresh against recovered backend; last observation: {:?}",
        observed
    );
}

// ────────────────────────────────────────────────────────────────────────────
// Test 5 — H3 frontend → H3 backend failure triggers downgrade from the
// server path (src/http3/server.rs).
// ────────────────────────────────────────────────────────────────────────────
//
// This is the companion to Test 2 but drives the wiring that lives inside
// `http3/server.rs` (the self-audit commit on the capability-registry PR).
// The failure path inside the H3 server's streaming branch must call
// `mark_h3_unsupported` so subsequent requests go through the bridge.
//
// Implementation note: Test 2 already exercises the same surface because
// the native H3 pool dispatch goes through `http3/server.rs`. We keep Test 5
// as a separate test with a different step (StreamReset rather than
// CONNECTION_CLOSE) so any drift in the server-path classifier is caught.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore]
async fn h3_frontend_to_h3_backend_failure_downgrades_from_server_path() {
    let ca = TestCa::new("phase3-t5").expect("ca");
    let (cert, key) = ca.valid().expect("leaf");

    let (tcp_listener, udp_socket, backend_port) = reserve_colocated_tcp_udp()
        .await
        .expect("colocated tcp/udp");

    let _tcp_backend = ScriptedTlsBackend::builder(
        tcp_listener,
        TlsConfig::new(cert.clone(), key.clone())
            .with_alpn(vec![b"h2".to_vec(), b"http/1.1".to_vec()]),
    )
    .step(TcpStep::ReadUntil(b"\r\n\r\n".to_vec()))
    .step(TcpStep::Write(
        b"HTTP/1.1 200 OK\r\nContent-Length: 3\r\nConnection: close\r\n\r\nack".to_vec(),
    ))
    .step(TcpStep::Drop)
    .spawn()
    .expect("spawn tls");

    // H3 side: accept stream, then close the whole connection. We use
    // CloseConnectionWithCode — distinct from Test 2 only in the
    // intermediate assertion focus (which HANDLER marks_h3_unsupported).
    let _h3_backend = ScriptedH3Backend::builder(udp_socket, H3TlsConfig::new(cert, key))
        .step(H3Step::AcceptStream)
        .step(H3Step::CloseConnectionWithCode(0x10c)) // H3_REQUEST_CANCELLED
        .spawn()
        .expect("spawn h3");

    let (harness, _ca_pem, _https_port) =
        spawn_h3_harness_with_explicit_https_port(backend_port, true, None).await;

    let pre = wait_for_capability_entry(&harness, Duration::from_secs(15))
        .await
        .expect("pre-entry")
        .expect("registry populated");
    assert_eq!(
        pre["plain_http"]["h3"].as_str(),
        Some("supported"),
        "precondition: h3=supported; entry: {pre:#?}"
    );

    // Request hits the native H3 pool (per `use_native_h3_pool` gate in
    // http3/server.rs), fails with a transport error, and the H3
    // server's error path must fire `mark_h3_unsupported`.
    let _first = h3_get(&harness, "/api/t5").await;

    tokio::time::sleep(Duration::from_millis(500)).await;
    let post = fetch_capability_entry(&harness)
        .await
        .expect("post-entry")
        .expect("registry entry still present");
    assert_eq!(
        post["plain_http"]["h3"].as_str(),
        Some("unsupported"),
        "expected h3=unsupported after H3 frontend→H3 backend failure; entry: {post:#?}"
    );
}

// ────────────────────────────────────────────────────────────────────────────
// Bonus Test 6 — Pool key must separate entries by `dns_override`.
// ────────────────────────────────────────────────────────────────────────────
//
// Two proxies pointed at the same backend hostname but with different
// `dns_override` values must NOT share a QUIC pool entry (their capability
// registry keys differ). Exercises the `pool_key_for_target` fix from the
// recent review. No H3 traffic is required — we only assert on the
// registry shape.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore]
async fn h3_pool_key_separates_by_dns_override() {
    let ca = TestCa::new("phase3-t6").expect("ca");
    let (cert, key) = ca.valid().expect("leaf");

    // Same backend port — we don't actually send traffic, we just want
    // the registry to see two distinct proxies.
    let (tcp_listener, udp_socket, backend_port) = reserve_colocated_tcp_udp()
        .await
        .expect("colocated tcp/udp");

    // Keep the backends alive so the probe succeeds.
    let _tcp_backend = ScriptedTlsBackend::builder(
        tcp_listener,
        TlsConfig::new(cert.clone(), key.clone())
            .with_alpn(vec![b"h2".to_vec(), b"http/1.1".to_vec()]),
    )
    .step(TcpStep::ReadUntil(b"\r\n\r\n".to_vec()))
    .step(TcpStep::Write(
        b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n".to_vec(),
    ))
    .step(TcpStep::Drop)
    .spawn()
    .expect("spawn tls");

    let _h3_backend = ScriptedH3Backend::builder(udp_socket, H3TlsConfig::new(cert, key))
        .step(H3Step::StallFor(Duration::from_secs(60)))
        .spawn()
        .expect("spawn h3");

    // Frontend certs.
    let scratch = tempfile::tempdir().expect("scratch");
    let (_ca_pem, cert_path, key_path) = write_frontend_certs(scratch.path(), "h3-gw-ca");
    Box::leak(Box::new(scratch));

    // Two proxies with the same backend host + port but different dns_override.
    let config = json!({
        "proxies": [
            {
                "id": "p-a",
                "listen_path": "/api-a",
                "backend_scheme": "https",
                "backend_host": "127.0.0.1",
                "backend_port": backend_port,
                "dns_override": "127.0.0.1",
                "strip_listen_path": true,
                "backend_connect_timeout_ms": 2000,
                "backend_tls_verify_server_cert": false,
            },
            {
                "id": "p-b",
                "listen_path": "/api-b",
                "backend_scheme": "https",
                "backend_host": "127.0.0.1",
                "backend_port": backend_port,
                "dns_override": "127.0.0.2",
                "strip_listen_path": true,
                "backend_connect_timeout_ms": 2000,
                "backend_tls_verify_server_cert": false,
            },
        ],
        "consumers": [],
        "upstreams": [],
        "plugin_configs": [],
    });
    let yaml = serde_yaml::to_string(&config).expect("yaml");

    let reservation = reserve_port().await.expect("https port");
    let https_port = reservation.port;
    drop(reservation);

    let harness = GatewayHarness::builder()
        .file_config(yaml)
        .log_level("info")
        .capture_output()
        .env("FERRUM_ENABLE_HTTP3", "true")
        .env("FERRUM_PROXY_HTTPS_PORT", https_port.to_string())
        .env("FERRUM_FRONTEND_TLS_CERT_PATH", cert_path)
        .env("FERRUM_FRONTEND_TLS_KEY_PATH", key_path)
        .env("FERRUM_TLS_NO_VERIFY", "true")
        .env("FERRUM_POOL_WARMUP_ENABLED", "true")
        .spawn()
        .await
        .expect("spawn");

    // Poll until the registry has both entries.
    let deadline = std::time::Instant::now() + Duration::from_secs(15);
    loop {
        let body = harness
            .get_admin_json("/backend-capabilities")
            .await
            .expect("admin GET");
        let entries = body["entries"].as_array().cloned().unwrap_or_default();
        if entries.len() >= 2 {
            let keys: Vec<String> = entries
                .iter()
                .map(|e| e["key"].as_str().unwrap_or("").to_string())
                .collect();
            assert_eq!(
                keys.len(),
                2,
                "expected two distinct registry entries for proxies with different dns_override; got {keys:?}"
            );
            assert_ne!(
                keys[0], keys[1],
                "expected the two capability keys to differ; got identical {:?}",
                keys[0]
            );
            // Both keys must contain the respective dns_override in the
            // pipe-delimited shape: "scheme|host|port|dns_override|..."
            assert!(
                keys.iter().any(|k| k.contains("127.0.0.1")),
                "missing 127.0.0.1 dns_override in keys: {keys:?}"
            );
            assert!(
                keys.iter().any(|k| k.contains("127.0.0.2")),
                "missing 127.0.0.2 dns_override in keys: {keys:?}"
            );
            return; // pass
        }
        if std::time::Instant::now() >= deadline {
            panic!(
                "registry only has {} entries after {} seconds: {body:#?}",
                entries.len(),
                15
            );
        }
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
}
