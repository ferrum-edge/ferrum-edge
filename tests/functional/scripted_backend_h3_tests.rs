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
//!
//! Step-vocabulary audit: every `H3Step` variant is exercised in this file.
//! The connection-phase test covers `RejectHandshake`, `DropInitialPacket`,
//! and explicit `AcceptHandshake`; the mid-body fault matrix covers
//! `SendStreamReset` and `SendGoaway` before the declared body completes.

#![allow(clippy::bool_assert_comparison)]

use crate::scaffolding::backends::{
    H3Step, H3TlsConfig, QuicRefuser, ScriptedH3Backend, ScriptedTlsBackend, TcpStep, TlsConfig,
    tls_backend_without_quic_with_ok_response,
};
use crate::scaffolding::certs::TestCa;
use crate::scaffolding::clients::{GetOptions, Http2Client, Http3Client};
use crate::scaffolding::harness::GatewayHarness;
use crate::scaffolding::ports::{reserve_colocated_tcp_udp, reserve_port};
use serde_json::{Value, json};
use std::time::Duration;

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
        "version": "1",
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

fn file_mode_yaml_for_h3_with_terminal_security(port: u16, remove_terminal: bool) -> String {
    let security_config = if remove_terminal {
        json!({
            "set": {"X-Security-Policy": "gateway-enforced"},
            "remove": ["Grpc-Status", "Grpc-Message", "Grpc-Status-Details-Bin"],
        })
    } else {
        json!({
            "override_existing": true,
            "set": {
                "X-Security-Policy": "gateway-enforced",
                "Grpc-Status": "0",
                "Grpc-Message": "policy override",
                "Grpc-Status-Details-Bin": "hostile",
            },
            "remove": [],
        })
    };
    let config = json!({
        "version": "1",
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
            "auth_mode": "single",
            "plugins": [
                {"plugin_config_id": "native-h3-key-auth"},
                {"plugin_config_id": "native-h3-chargeback"}
            ],
        }],
        "consumers": [{
            "id": "native-h3-chargeback-consumer",
            "username": "native-h3-chargeback-user",
            "credentials": {
                "keyauth": [{"key": "native-h3-chargeback-key-99887766"}]
            }
        }],
        "upstreams": [],
        "plugin_configs": [
            {
                "id": "native-h3-key-auth",
                "plugin_name": "key_auth",
                "scope": "proxy",
                "proxy_id": "scripted-h3",
                "enabled": true,
                "config": {"key_location": "header:x-api-key"},
            },
            {
                "id": "native-h3-chargeback",
                "plugin_name": "api_chargeback",
                "scope": "proxy",
                "proxy_id": "scripted-h3",
                "enabled": true,
                "config": {
                    "pricing_tiers": [
                        {"status_codes": [403], "price_per_call": 0.007}
                    ],
                    "render_cache_ttl_seconds": 0,
                    "cache_invalidation_min_age_ms": 0,
                    "cleanup_interval_seconds": 0,
                },
            },
            {
                "id": "native-h3-terminal-security",
                "plugin_name": "security_headers",
                "scope": "global",
                "enabled": true,
                "config": security_config,
            },
            {
                "id": "native-h3-errors-only",
                "plugin_name": "stdout_logging",
                "scope": "global",
                "enabled": true,
                "config": {"filter": {"errors_only": true}},
            }
        ],
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

/// Wait for the single capability entry's H3 class to match `expected`.
async fn wait_for_h3_class(
    harness: &GatewayHarness,
    expected: &str,
    timeout: Duration,
) -> Result<Option<Value>, Box<dyn std::error::Error + Send + Sync>> {
    let deadline = tokio::time::Instant::now() + timeout;
    loop {
        if let Some(entry) = fetch_capability_entry(harness).await?
            && entry["plain_http"]["h3"].as_str() == Some(expected)
        {
            return Ok(Some(entry));
        }
        if tokio::time::Instant::now() >= deadline {
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
    spawn_h3_harness_with_explicit_https_port_and_config(
        file_mode_yaml_for_h3(backend_port),
        pool_warmup_enabled,
        refresh_interval_secs,
    )
    .await
}

async fn spawn_h3_harness_with_explicit_https_port_and_config(
    yaml: String,
    pool_warmup_enabled: bool,
    refresh_interval_secs: Option<u64>,
) -> (GatewayHarness, String, u16) {
    const STARTUP_ATTEMPTS: u32 = 3;
    let mut last_error = None;
    for attempt in 1..=STARTUP_ATTEMPTS {
        // A fixed env-pinned HTTPS/QUIC port cannot be reused after a failed
        // startup. Retry the complete harness with a fresh port and scratch
        // directory, matching the chunked-harness stabilization in PR #2065.
        let reservation = reserve_port().await.expect("reserve https port");
        let https_port = reservation.port;
        drop(reservation);

        let scratch = tempfile::tempdir().expect("scratch");
        let (ca_pem, cert_path, key_path) = write_frontend_certs(scratch.path(), "h3-gw-ca");
        let mut builder = GatewayHarness::builder()
            .file_config(yaml.clone())
            .log_level("info")
            .capture_output()
            .max_attempts(1)
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

        match builder.spawn().await {
            Ok(harness) => {
                Box::leak(Box::new(scratch));
                let port_file = harness.temp_path().join("https-port.txt");
                std::fs::write(&port_file, https_port.to_string()).expect("write https-port.txt");
                return (harness, ca_pem, https_port);
            }
            Err(error) => {
                eprintln!(
                    "H3 harness startup attempt {attempt}/{STARTUP_ATTEMPTS} failed: {error}"
                );
                last_error = Some(error.to_string());
                if attempt < STARTUP_ATTEMPTS {
                    tokio::time::sleep(Duration::from_secs(1)).await;
                }
            }
        }
    }
    panic!(
        "H3 harness failed after {STARTUP_ATTEMPTS} fresh-port attempts: {}",
        last_error.unwrap_or_else(|| "no startup error recorded".to_string())
    );
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

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore]
async fn h3_quic_phase_failures_are_observable_and_recoverable() {
    for (name, connection_step) in [
        ("reject-handshake", H3Step::RejectHandshake),
        ("drop-initial", H3Step::DropInitialPacket),
    ] {
        let ca = TestCa::new(&format!("phase-h3-{name}")).expect("ca");
        let (cert, key) = ca.valid().expect("leaf");
        let (tcp_res, udp_res) = reserve_colocated_tcp_udp()
            .await
            .expect("colocated tcp/udp");
        let backend_port = tcp_res.port;

        let _tcp_backend = ScriptedTlsBackend::builder(
            tcp_res.into_listener(),
            TlsConfig::new(cert.clone(), key.clone())
                .with_alpn(vec![b"h2".to_vec(), b"http/1.1".to_vec()]),
        )
        .step(TcpStep::ReadUntil(b"\r\n\r\n".to_vec()))
        .step(TcpStep::Write(
            b"HTTP/1.1 200 OK\r\nContent-Length: 6\r\nConnection: close\r\n\r\nbridge".to_vec(),
        ))
        .step(TcpStep::Drop)
        .spawn()
        .expect("spawn TLS sidecar");

        let h3_backend =
            ScriptedH3Backend::builder(udp_res.into_socket(), H3TlsConfig::new(cert, key))
                .steps([
                    connection_step,
                    H3Step::AcceptHandshake,
                    H3Step::AcceptStream,
                    H3Step::RespondHeaders(vec![
                        (":status", "200".into()),
                        ("content-length", "2".into()),
                    ]),
                    H3Step::RespondData(bytes::Bytes::from_static(b"ok")),
                    H3Step::StallFor(Duration::from_millis(100)),
                ])
                .spawn()
                .expect("spawn H3 backend");

        let harness = GatewayHarness::builder()
            .mode_in_process()
            .file_config(file_mode_yaml_for_h3(backend_port))
            .pool_warmup_enabled(true)
            .env("FERRUM_TLS_NO_VERIFY", "true")
            .spawn()
            .await
            .expect("spawn gateway");

        tokio::time::timeout(Duration::from_secs(8), async {
            loop {
                let observed = match name {
                    "reject-handshake" => h3_backend.refused_handshakes() == 1,
                    "drop-initial" => h3_backend.dropped_initial_packets() == 1,
                    _ => false,
                };
                if observed {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(50)).await;
            }
        })
        .await
        .unwrap_or_else(|_| panic!("{name} was not consumed by the QUIC capability probe"));

        // The open UDP socket proves this was a QUIC connection-phase failure,
        // not the no-listener/ECONNREFUSED family. An explicit refresh then
        // opens a second connection and executes `AcceptHandshake`.
        tokio::time::timeout(
            Duration::from_secs(5),
            harness.post_admin_json("/backend-capabilities/refresh", &json!({})),
        )
        .await
        .expect("refresh request bounded")
        .expect("refresh request");
        let entry = wait_for_h3_class(&harness, "supported", Duration::from_secs(10))
            .await
            .expect("capability lookup")
            .unwrap_or_else(|| panic!("{name} did not recover to h3=supported"));

        let client = harness.http_client().expect("HTTP client");
        let response = tokio::time::timeout(
            Duration::from_secs(5),
            client.get(&harness.proxy_url("/api/phase")),
        )
        .await
        .expect("post-refresh request bounded")
        .expect("post-refresh response");
        assert_eq!(response.status.as_u16(), 200, "entry={entry:#?}");
        assert_eq!(response.body_text(), "ok");

        let requests = h3_backend.received_requests().await;
        assert!(
            requests.iter().any(|request| request.path == "/phase"),
            "{name} recovery must execute the explicit H3 handshake/stream script; requests={requests:?}"
        );
    }
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

    let (tcp_res, udp_res) = reserve_colocated_tcp_udp()
        .await
        .expect("colocated tcp/udp");
    let backend_port = tcp_res.port;

    // TCP+TLS side: always answers 200 so the cross-protocol bridge works
    // on the second request.
    let _tcp_backend = ScriptedTlsBackend::builder(
        tcp_res.into_listener(),
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
    let h3_backend = ScriptedH3Backend::builder(udp_res.into_socket(), H3TlsConfig::new(cert, key))
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
// Test 3 — Backend non-graceful close mid-request returns
// `(connection_error=false, transport error class)`; downgrade must still fire.
// Regression test for the Codex P2 fix on the capability-registry PR.
// ────────────────────────────────────────────────────────────────────────────
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore]
async fn h3_non_graceful_close_downgrades_via_connection_error_false_path() {
    let ca = TestCa::new("phase3-t3").expect("ca");
    let (cert, key) = ca.valid().expect("leaf");

    let (tcp_res, udp_res) = reserve_colocated_tcp_udp()
        .await
        .expect("colocated tcp/udp");
    let backend_port = tcp_res.port;

    // TCP+TLS side — 200 responder for the cross-protocol bridge.
    let _tcp_backend = ScriptedTlsBackend::builder(
        tcp_res.into_listener(),
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

    // H3 side: accept handshake + stream, then close the connection with
    // a non-graceful H3 application code. The request has reached the
    // wire (`connection_error=false`), but the error class is still a
    // transport-class H3 failure, so the cached H3 capability must be
    // downgraded. Do not use GOAWAY / H3_NO_ERROR here: that is now
    // intentionally treated as graceful and must not downgrade the cache.
    let _h3_backend =
        ScriptedH3Backend::builder(udp_res.into_socket(), H3TlsConfig::new(cert, key))
            .step(H3Step::AcceptStream)
            .step(H3Step::CloseConnectionWithCode(0x10c))
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
        "expected h3=supported before non-graceful close; entry: {pre:#?}"
    );

    // First request: non-graceful H3 close.
    let first = h3_get(&harness, "/api/t3").await;
    match first {
        Ok(resp) => {
            assert_eq!(
                resp.status.as_u16(),
                502,
                "first H3 request should 502 after non-graceful close"
            );
        }
        Err(e) => {
            let msg = e.to_string().to_lowercase();
            assert!(
                msg.contains("reset")
                    || msg.contains("goaway")
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
        "expected h3=unsupported after non-graceful close; entry: {post:#?}\n--- gateway logs ---\n{logs}"
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

    let (tcp_res, udp_res) = reserve_colocated_tcp_udp()
        .await
        .expect("colocated tcp/udp");
    let backend_port = tcp_res.port;

    // TCP+TLS side — stays up for the whole test (used by cross-protocol bridge).
    let _tcp_backend = ScriptedTlsBackend::builder(
        tcp_res.into_listener(),
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
    let mut refuser =
        QuicRefuser::start_alpn_mismatch(udp_res, H3TlsConfig::new(cert.clone(), key.clone()))
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

    let (tcp_res, udp_res) = reserve_colocated_tcp_udp()
        .await
        .expect("colocated tcp/udp");
    let backend_port = tcp_res.port;

    let _tcp_backend = ScriptedTlsBackend::builder(
        tcp_res.into_listener(),
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
    let _h3_backend =
        ScriptedH3Backend::builder(udp_res.into_socket(), H3TlsConfig::new(cert, key))
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
    let (tcp_res, udp_res) = reserve_colocated_tcp_udp()
        .await
        .expect("colocated tcp/udp");
    let backend_port = tcp_res.port;

    // Keep the backends alive so the probe succeeds.
    let _tcp_backend = ScriptedTlsBackend::builder(
        tcp_res.into_listener(),
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

    let _h3_backend =
        ScriptedH3Backend::builder(udp_res.into_socket(), H3TlsConfig::new(cert, key))
            .step(H3Step::StallFor(Duration::from_secs(60)))
            .spawn()
            .expect("spawn h3");

    // Frontend certs.
    let scratch = tempfile::tempdir().expect("scratch");
    let (_ca_pem, cert_path, key_path) = write_frontend_certs(scratch.path(), "h3-gw-ca");
    Box::leak(Box::new(scratch));

    // Two proxies with the same backend host + port but different dns_override.
    let config = json!({
        "version": "1",
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

// ────────────────────────────────────────────────────────────────────────────
// Test 7 — H3 client sends only `:authority` (no explicit Host); gateway
// must synthesize a Host header for the forwarded request.
// ────────────────────────────────────────────────────────────────────────────
//
// Real H3 clients (curl, Chromium, Firefox) typically send only the H3
// `:authority` pseudo-header — they do NOT add an explicit `Host` header.
// The h3 crate parks `:authority` on `req.uri().authority()` and does
// not insert it into `req.headers()`. Without server-side synthesis, the
// gateway forwards no Host to the backend, breaking virtual hosting on
// the upstream. This test pins the synthesis behavior in place across
// both `preserve_host_header` settings.
//
// Wire shape: H3 → cross-protocol bridge → TLS HTTP/1.1 backend. We use
// the cross-protocol bridge because it surfaces a recordable HTTP/1.1
// request line + Host header on the wire (`ScriptedTlsBackend::received_bytes`),
// which is the simplest way to make the Host visible to the test.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore]
async fn h3_client_without_host_header_synthesizes_from_authority_preserve_false() {
    let ca = TestCa::new("phase-host-1").expect("ca");
    let (cert, key) = ca.valid().expect("leaf");

    let backend_reservation = reserve_port().await.expect("reserve backend port");
    let backend_port = backend_reservation.port;

    // TLS backend speaks HTTP/1.1 only — forces the cross-protocol bridge.
    // Each connection: read request, send 200, drop.
    let backend = ScriptedTlsBackend::builder(
        backend_reservation.into_listener(),
        TlsConfig::new(cert.clone(), key.clone()).with_alpn(vec![b"http/1.1".to_vec()]),
    )
    .step(TcpStep::ReadUntil(b"\r\n\r\n".to_vec()))
    .step(TcpStep::Write(
        b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok".to_vec(),
    ))
    .step(TcpStep::Drop)
    .spawn()
    .expect("spawn tls");

    // Default proxy → preserve_host_header is `false`: the backend Host
    // should be the upstream target host, NOT the client's `:authority`.
    let yaml = file_mode_yaml_for_h3(backend_port);
    let reservation = reserve_port().await.expect("reserve https port");
    let https_port = reservation.port;
    drop(reservation);

    let scratch = tempfile::tempdir().expect("scratch");
    let (_ca_pem, cert_path, key_path) = write_frontend_certs(scratch.path(), "h3-gw-host1");
    Box::leak(Box::new(scratch));

    let _harness = GatewayHarness::builder()
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
        .expect("spawn gateway");

    // Drive the H3 frontend with the canonical "no explicit Host" wire
    // shape. The bug-fixed gateway must still emit a Host to the backend.
    let client = Http3Client::insecure().expect("h3 client");
    let url = format!("https://127.0.0.1:{https_port}/api/x");
    let resp = client
        .get_with_options(
            &url,
            crate::scaffolding::clients::GetOptions {
                host_header: crate::scaffolding::clients::HostHeader::Auto,
                ..Default::default()
            },
        )
        .await
        .expect("h3 response");
    assert_eq!(
        resp.status.as_u16(),
        200,
        "expected 200, got {}",
        resp.status
    );

    // Backend wire bytes — extract the Host header that came alongside our
    // GET. The backend may also have logged a HEAD probe from pool warmup
    // (on a different ephemeral port); we scan for the GET prelude
    // explicitly so the assertion is unambiguous.
    let bytes = backend.received_bytes().await;
    let prelude = String::from_utf8_lossy(&bytes);
    let host_value = host_for_method(&prelude, "GET");
    assert!(
        host_value.is_some(),
        "backend received no Host header for the GET request.\n\
         prelude:\n{prelude}"
    );
    // preserve_host_header=false: backend Host should be the upstream target host.
    // For the default config in `file_mode_yaml_for_h3`, that's "127.0.0.1".
    assert_eq!(
        host_value.as_deref(),
        Some("127.0.0.1"),
        "preserve_host_header=false: backend Host should be the upstream target host (127.0.0.1).\n\
         prelude:\n{prelude}"
    );
}

/// Extract the `Host:` header value from the FIRST request in `prelude`
/// whose request-line method matches `method`. The gateway may run a
/// pool-warmup probe (HEAD) before the test's request lands, so plain
/// "first host: line" scans are ambiguous. The reqwest backend connections
/// each terminate in `Connection: close` so request preludes are
/// concatenated without interleaving.
fn host_for_method(prelude: &str, method: &str) -> Option<String> {
    let lines: Vec<&str> = prelude.lines().collect();
    let mut idx = 0;
    while idx < lines.len() {
        if lines[idx].starts_with(&format!("{method} ")) {
            // Found the request line — scan subsequent lines for Host.
            for line in lines.iter().skip(idx + 1) {
                if line.is_empty() {
                    return None;
                }
                if line.to_ascii_lowercase().starts_with("host:") {
                    return line.split_once(':').map(|(_, v)| v.trim().to_string());
                }
            }
            return None;
        }
        idx += 1;
    }
    None
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore]
async fn h3_client_without_host_header_synthesizes_from_authority_preserve_true() {
    let ca = TestCa::new("phase-host-2").expect("ca");
    let (cert, key) = ca.valid().expect("leaf");

    let backend_reservation = reserve_port().await.expect("reserve backend port");
    let backend_port = backend_reservation.port;
    let backend = ScriptedTlsBackend::builder(
        backend_reservation.into_listener(),
        TlsConfig::new(cert.clone(), key.clone()).with_alpn(vec![b"http/1.1".to_vec()]),
    )
    .step(TcpStep::ReadUntil(b"\r\n\r\n".to_vec()))
    .step(TcpStep::Write(
        b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok".to_vec(),
    ))
    .step(TcpStep::Drop)
    .spawn()
    .expect("spawn tls");

    // preserve_host_header=true: backend Host should be the H3 client's
    // `:authority` value. Without the synthesis fix, no Host is emitted.
    let config = json!({
        "version": "1",
        "proxies": [{
            "id": "scripted-h3-preserve",
            "listen_path": "/api",
            "backend_scheme": "https",
            "backend_host": "127.0.0.1",
            "backend_port": backend_port,
            "strip_listen_path": true,
            "preserve_host_header": true,
            "backend_connect_timeout_ms": 2000,
            "backend_read_timeout_ms": 5000,
            "backend_write_timeout_ms": 5000,
            "backend_tls_verify_server_cert": false,
        }],
        "consumers": [],
        "upstreams": [],
        "plugin_configs": [],
    });
    let yaml = serde_yaml::to_string(&config).expect("yaml");
    let reservation = reserve_port().await.expect("reserve https port");
    let https_port = reservation.port;
    drop(reservation);
    let scratch = tempfile::tempdir().expect("scratch");
    let (_ca_pem, cert_path, key_path) = write_frontend_certs(scratch.path(), "h3-gw-host2");
    Box::leak(Box::new(scratch));

    let _harness = GatewayHarness::builder()
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
        .expect("spawn gateway");

    let client = Http3Client::insecure().expect("h3 client");
    let url = format!("https://127.0.0.1:{https_port}/api/x");
    let resp = client
        .get_with_options(
            &url,
            crate::scaffolding::clients::GetOptions {
                host_header: crate::scaffolding::clients::HostHeader::Auto,
                ..Default::default()
            },
        )
        .await
        .expect("h3 response");
    assert_eq!(
        resp.status.as_u16(),
        200,
        "expected 200, got {}",
        resp.status
    );

    let bytes = backend.received_bytes().await;
    let prelude = String::from_utf8_lossy(&bytes);
    let host_value = host_for_method(&prelude, "GET");
    let expected = format!("127.0.0.1:{https_port}");
    assert_eq!(
        host_value.as_deref(),
        Some(expected.as_str()),
        "preserve_host_header=true: backend Host should equal client's `:authority` ({expected}).\n\
         prelude:\n{prelude}"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore]
async fn h3_client_explicit_host_matches_authority_preserved() {
    // When the H3 client sends an explicit Host header that matches
    // `:authority` (the safe shape required by RFC 9114 §4.3.1 when both
    // are present), the synthesis path is a no-op. preserve_host_header=true
    // forwards the explicit Host unchanged.
    let ca = TestCa::new("phase-host-3").expect("ca");
    let (cert, key) = ca.valid().expect("leaf");
    let backend_reservation = reserve_port().await.expect("reserve backend port");
    let backend_port = backend_reservation.port;
    let backend = ScriptedTlsBackend::builder(
        backend_reservation.into_listener(),
        TlsConfig::new(cert.clone(), key.clone()).with_alpn(vec![b"http/1.1".to_vec()]),
    )
    .step(TcpStep::ReadUntil(b"\r\n\r\n".to_vec()))
    .step(TcpStep::Write(
        b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok".to_vec(),
    ))
    .step(TcpStep::Drop)
    .spawn()
    .expect("spawn tls");

    let config = json!({
        "version": "1",
        "proxies": [{
            "id": "scripted-h3-preserve-explicit",
            "listen_path": "/api",
            "backend_scheme": "https",
            "backend_host": "127.0.0.1",
            "backend_port": backend_port,
            "strip_listen_path": true,
            "preserve_host_header": true,
            "backend_connect_timeout_ms": 2000,
            "backend_read_timeout_ms": 5000,
            "backend_write_timeout_ms": 5000,
            "backend_tls_verify_server_cert": false,
        }],
        "consumers": [],
        "upstreams": [],
        "plugin_configs": [],
    });
    let yaml = serde_yaml::to_string(&config).expect("yaml");
    let reservation = reserve_port().await.expect("reserve https port");
    let https_port = reservation.port;
    drop(reservation);
    let scratch = tempfile::tempdir().expect("scratch");
    let (_ca_pem, cert_path, key_path) = write_frontend_certs(scratch.path(), "h3-gw-host3");
    Box::leak(Box::new(scratch));

    let _harness = GatewayHarness::builder()
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
        .expect("spawn gateway");

    let client = Http3Client::insecure().expect("h3 client");
    let url = format!("https://127.0.0.1:{https_port}/api/x");
    let resp = client
        .get_with_options(
            &url,
            crate::scaffolding::clients::GetOptions {
                host_header: crate::scaffolding::clients::HostHeader::SameAsAuthority,
                ..Default::default()
            },
        )
        .await
        .expect("h3 response");
    assert_eq!(resp.status.as_u16(), 200);

    let bytes = backend.received_bytes().await;
    let prelude = String::from_utf8_lossy(&bytes);
    let host_value = host_for_method(&prelude, "GET");
    let expected = format!("127.0.0.1:{https_port}");
    assert_eq!(
        host_value.as_deref(),
        Some(expected.as_str()),
        "preserve_host_header=true with matching Host + :authority: backend should see the unchanged Host.\n\
         prelude:\n{prelude}"
    );
}

// ────────────────────────────────────────────────────────────────────────────
// Codex P1 regression — Use SELECTED upstream-target host on synthesis path.
//
// PR #492's first synthesis fix populated `Host` from `:authority` for H3
// clients that didn't send an explicit Host. But on the H3 NATIVE pool path,
// `build_h3_backend_headers` then rewrote Host with `proxy.backend_host` when
// `preserve_host_header=false` — while `request_with_target*` still routed
// to `upstream_target.host`. For upstream-backed proxies where those
// differ (the common case: `backend_host` is a template fallback,
// load-balanced targets are the real backends), the H3 connection went to
// `upstream_target.host` while the synthesized Host pointed at
// `proxy.backend_host`. Strict virtual-host routing on the upstream
// rejected those requests; common clients (curl, Chromium, reqwest) all
// sent only `:authority`, so the bug applied to the realistic majority.
//
// This test pins the fix: the synthesized Host MUST equal the
// SELECTED target's host on an upstream-backed H3 native-pool dispatch.
// ────────────────────────────────────────────────────────────────────────────
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore]
async fn h3_native_pool_synthesizes_host_from_upstream_target_not_proxy_backend_host() {
    let ca = TestCa::new("phase-host-codex-p1").expect("ca");
    let (cert, key) = ca.valid().expect("leaf");

    // Colocated TCP+UDP so the capability probe reaches both transports
    // and classifies h3 = Supported (gateway then takes the native H3 pool).
    let (tcp_res, udp_res) = reserve_colocated_tcp_udp()
        .await
        .expect("colocated tcp/udp");
    let backend_port = tcp_res.port;

    // TCP+TLS sidecar for the capability probe (advertises h2+http/1.1).
    // It's never actually hit by the test request — that lands on H3.
    let _tcp_backend = ScriptedTlsBackend::builder(
        tcp_res.into_listener(),
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

    // Real H3 backend that records the inbound `:authority` + headers.
    // Accept stream, send 200 + 2-byte body, then hold the connection open
    // briefly before the implicit script-end drop.
    //
    // The StallFor is load-bearing: without it, the script's end-of-loop
    // drop closes the connection immediately after `RespondData`, which on
    // Linux + io_uring (CI) coalesces the CONNECTION_CLOSE(H3_NO_ERROR)
    // into the same UDP burst as the HEADERS+DATA+FIN. quinn then surfaces
    // the close to the gateway's H3 client BEFORE h3 finishes parsing the
    // HEADERS frame, so `recv_response()` returns
    // `Err(ApplicationClose: H3_NO_ERROR)` — the gateway 502s and
    // `mark_h3_unsupported` fires, and this Host-header assertion never
    // gets the chance to run. Same coalescing race the PR's
    // `drain_h3_response_body` recovery handles at `recv_data`, but at the
    // `recv_response` boundary instead — which can't be made transparent
    // (there are no synthesizable headers). 50ms is comfortably more than
    // any plausible single-host gateway read latency for an empty path.
    let h3_backend = ScriptedH3Backend::builder(udp_res.into_socket(), H3TlsConfig::new(cert, key))
        .step(H3Step::AcceptStream)
        .step(H3Step::RespondHeaders(vec![
            (":status", "200".to_string()),
            ("content-length", "2".to_string()),
            ("content-type", "text/plain".to_string()),
        ]))
        .step(H3Step::RespondData(bytes::Bytes::from_static(b"ok")))
        .step(H3Step::StallFor(Duration::from_millis(50)))
        .spawn()
        .expect("spawn h3 backend");

    // Upstream-backed proxy. `backend_host` is a TEMPLATE fallback that's
    // syntactically valid and resolvable but DIFFERS from the upstream
    // target's host. Without the Codex P1 fix, the synthesized Host would
    // end up as "localhost" while the H3 connection lands at "127.0.0.1".
    // With the fix, the synthesized Host = upstream target host = "127.0.0.1".
    let config = json!({
        "version": "1",
        "proxies": [{
            "id": "h3-codex-p1",
            "listen_path": "/api",
            "backend_scheme": "https",
            "backend_host": "localhost",
            "backend_port": backend_port,
            "upstream_id": "lb",
            "strip_listen_path": true,
            "preserve_host_header": false,
            "backend_connect_timeout_ms": 2000,
            "backend_read_timeout_ms": 5000,
            "backend_write_timeout_ms": 5000,
            "backend_tls_verify_server_cert": false,
        }],
        "upstreams": [{
            "id": "lb",
            "name": "lb",
            "targets": [{
                "host": "127.0.0.1",
                "port": backend_port,
                "weight": 1,
            }],
            "algorithm": "round_robin",
        }],
        "consumers": [],
        "plugin_configs": [],
    });
    let yaml = serde_yaml::to_string(&config).expect("yaml");

    let reservation = reserve_port().await.expect("reserve https port");
    let https_port = reservation.port;
    drop(reservation);

    let scratch = tempfile::tempdir().expect("scratch");
    let (_ca_pem, cert_path, key_path) = write_frontend_certs(scratch.path(), "h3-gw-codex-p1");
    Box::leak(Box::new(scratch));

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
        .expect("spawn gateway");

    // Wait for capability classification — gateway must see h3=supported
    // before it'll route via the native H3 pool.
    let _ = wait_for_capability_entry(&harness, Duration::from_secs(15))
        .await
        .expect("registry populated");

    // H3 client sends only `:authority` (no explicit Host). Mimics curl,
    // Chromium, Firefox, reqwest defaults.
    let client = Http3Client::insecure().expect("h3 client");
    let url = format!("https://127.0.0.1:{https_port}/api/x");
    let resp = client
        .get_with_options(
            &url,
            crate::scaffolding::clients::GetOptions {
                host_header: crate::scaffolding::clients::HostHeader::Auto,
                ..Default::default()
            },
        )
        .await
        .expect("h3 response");
    if resp.status.as_u16() != 200 {
        let logs = harness.captured_combined().unwrap_or_default();
        let entry = fetch_capability_entry(&harness).await.ok().flatten();
        panic!(
            "expected 200 from H3 native pool; got {} \n--- registry: {:?}\n--- logs: ---\n{}",
            resp.status, entry, logs
        );
    }

    // The H3 backend recorded the request — assert the Host the gateway
    // forwarded equals the SELECTED upstream-target host.
    let received = h3_backend.received_requests().await;
    let req = received
        .iter()
        .find(|r| r.method == "GET")
        .expect("backend must have received a GET");
    let host = req
        .headers
        .iter()
        .find(|(k, _)| k.eq_ignore_ascii_case("host"))
        .map(|(_, v)| v.as_str())
        .expect("backend must have received a Host header");
    assert_eq!(
        host, "127.0.0.1",
        "preserve_host_header=false on upstream-backed H3 native-pool dispatch: \
         synthesized Host MUST equal SELECTED upstream-target host (127.0.0.1), \
         NOT the proxy's template `backend_host` (\"localhost\"). \
         Without the Codex P1 fix on PR #492, this assertion fails — the H3 \
         connection lands at 127.0.0.1 while the Host header points at the \
         template, breaking virtual-host routing on the backend. \
         Recorded request: method={} authority={:?} host_header={host}",
        req.method, req.authority,
    );
}

// ────────────────────────────────────────────────────────────────────────────
// Test 11 — H1 frontend → native H3 backend must preserve frontend protocol
// metadata in X-Forwarded-Proto, Via, and Forwarded.
// ────────────────────────────────────────────────────────────────────────────
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore]
async fn h1_frontend_to_native_h3_backend_uses_frontend_forwarding_metadata() {
    let ca = TestCa::new("phase-h1-to-h3-metadata").expect("ca");
    let (cert, key) = ca.valid().expect("leaf");

    let (tcp_res, udp_res) = reserve_colocated_tcp_udp()
        .await
        .expect("colocated tcp/udp");
    let backend_port = tcp_res.port;

    // Capability probing needs the colocated TCP+TLS side to answer; the
    // actual test request should go to the H3 backend once h3=supported.
    let _tcp_backend = ScriptedTlsBackend::builder(
        tcp_res.into_listener(),
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

    let h3_backend = ScriptedH3Backend::builder(udp_res.into_socket(), H3TlsConfig::new(cert, key))
        .step(H3Step::AcceptStream)
        .step(H3Step::RespondHeaders(vec![
            (":status", "200".to_string()),
            ("content-length", "2".to_string()),
            ("content-type", "text/plain".to_string()),
        ]))
        .step(H3Step::RespondData(bytes::Bytes::from_static(b"ok")))
        .step(H3Step::StallFor(Duration::from_millis(50)))
        .spawn()
        .expect("spawn h3 backend");

    let harness = GatewayHarness::builder()
        .file_config(file_mode_yaml_for_h3(backend_port))
        .log_level("info")
        .capture_output()
        // Let file mode run its initial capability refresh, but avoid pool
        // warmup issuing an extra H3 request before this regression's GET.
        .env("FERRUM_POOL_WARMUP_ENABLED", "false")
        .env("FERRUM_ADD_VIA_HEADER", "true")
        .env("FERRUM_ADD_FORWARDED_HEADER", "true")
        .spawn()
        .await
        .expect("spawn gateway");

    let entry = wait_for_capability_entry(&harness, Duration::from_secs(15))
        .await
        .expect("fetch capability entry")
        .expect("registry populated within timeout");
    assert_eq!(
        entry["plain_http"]["h3"].as_str(),
        Some("supported"),
        "expected h3=supported so the request uses the native H3 backend path; entry: {entry:#?}"
    );

    let client = reqwest::Client::builder()
        .http1_only()
        .build()
        .expect("reqwest client");
    let resp = client
        .get(harness.proxy_url("/api/metadata"))
        .header(reqwest::header::HOST, "edge.example")
        .send()
        .await
        .expect("request through gateway");
    if resp.status().as_u16() != 200 {
        let logs = harness.captured_combined().unwrap_or_default();
        panic!(
            "expected 200 from H1 frontend to native H3 backend; got {}\n--- registry: {entry:#?}\n--- logs ---\n{}",
            resp.status(),
            logs
        );
    }

    let received = h3_backend.received_requests().await;
    let req = received
        .iter()
        .find(|r| r.method == "GET")
        .expect("H3 backend must have received the frontend GET");
    let header = |name: &str| {
        req.headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.as_str())
    };

    assert_eq!(header("x-forwarded-proto"), Some("http"));
    assert_eq!(header("via"), Some("1.1 ferrum-edge"));
    let forwarded = header("forwarded").expect("Forwarded header should be present");
    assert!(
        forwarded.contains("for=127.0.0.1")
            && forwarded.contains("proto=http")
            && forwarded.contains("host=edge.example"),
        "Forwarded header should describe the H1 frontend request, got {forwarded:?}; \
         recorded request: {req:#?}"
    );
}

// A request transformer can introduce `stream: true` only in the final request
// body. Dispatch preference and response buffering must be re-evaluated from
// that finalized context before an H3-capable backend transport is committed.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore]
async fn transformer_added_stream_marker_reclassifies_h3_capable_dispatch() {
    const DENIED_SSE: &str = concat!(
        "data: {\"choices\":[{\"index\":0,\"delta\":{\"tool_calls\":[{\"index\":0,\"id\":\"call_1\",\"function\":{\"name\":\"rm_rf\",\"arguments\":\"{\\\"path\\\":\\\"/etc\\\"}\"}}]}}]}\n\n",
        "data: {\"choices\":[{\"index\":0,\"delta\":{},\"finish_reason\":\"tool_calls\"}]}\n\n",
        "data: [DONE]\n\n",
    );

    let ca = TestCa::new("h3-post-transform-dispatch").expect("ca");
    let (cert, key) = ca.valid().expect("leaf");
    let (tcp_res, udp_res) = reserve_colocated_tcp_udp()
        .await
        .expect("colocated tcp/udp");
    let backend_port = tcp_res.port;

    let response = format!(
        "HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
        DENIED_SSE.len(),
        DENIED_SSE
    );
    let _tcp_backend = ScriptedTlsBackend::builder(
        tcp_res.into_listener(),
        TlsConfig::new(cert.clone(), key.clone()).with_alpn(vec![b"http/1.1".to_vec()]),
    )
    .step(TcpStep::ReadUntil(b"\r\n\r\n".to_vec()))
    .step(TcpStep::Write(response.into_bytes()))
    .step(TcpStep::Drop)
    .spawn()
    .expect("spawn tls backend");

    let h3_backend = ScriptedH3Backend::builder(udp_res.into_socket(), H3TlsConfig::new(cert, key))
        .step(H3Step::AcceptStream)
        .step(H3Step::RespondHeaders(vec![
            (":status", "200".to_string()),
            ("content-type", "text/event-stream".to_string()),
            ("content-length", DENIED_SSE.len().to_string()),
        ]))
        .step(H3Step::RespondData(bytes::Bytes::from_static(
            DENIED_SSE.as_bytes(),
        )))
        .spawn()
        .expect("spawn h3 backend");

    let config = json!({
        "version": "1",
        "proxies": [{
            "id": "post-transform-h3",
            "listen_path": "/ai",
            "backend_scheme": "https",
            "backend_host": "localhost",
            "backend_port": backend_port,
            "strip_listen_path": true,
            "backend_tls_verify_server_cert": false,
            "plugins": [
                {"plugin_config_id": "transformer"},
                {"plugin_config_id": "governor"}
            ]
        }],
        "consumers": [],
        "upstreams": [],
        "plugin_configs": [
            {
                "id": "transformer",
                "proxy_id": "post-transform-h3",
                "plugin_name": "request_transformer",
                "scope": "proxy",
                "enabled": true,
                "config": {"rules": [{
                    "operation": "add",
                    "target": "body",
                    "key": "stream",
                    "value": true
                }]}
            },
            {
                "id": "governor",
                "proxy_id": "post-transform-h3",
                "plugin_name": "ai_tool_governor",
                "scope": "proxy",
                "enabled": true,
                "config": {
                    "mode": "enforce",
                    "tools": {"rm_rf": {"action": "deny"}},
                    "default_action": "allow",
                    "inspect": {
                        "response_tool_calls": false,
                        "streaming_response_tool_calls": true
                    }
                }
            }
        ]
    });
    let harness = GatewayHarness::builder()
        .file_config(serde_yaml::to_string(&config).expect("yaml"))
        .pool_warmup_enabled(true)
        .env("FERRUM_MAX_REQUEST_BODY_SIZE_BYTES", "0")
        .env("FERRUM_MAX_RESPONSE_BODY_SIZE_BYTES", "0")
        .spawn()
        .await
        .expect("spawn gateway");

    let entry = wait_for_capability_entry(&harness, Duration::from_secs(15))
        .await
        .expect("capability entry")
        .expect("registry populated");
    assert_eq!(entry["plain_http"]["h3"].as_str(), Some("supported"));

    let response = reqwest::Client::builder()
        .http1_only()
        .build()
        .expect("client")
        .post(harness.proxy_url("/ai/v1/chat/completions"))
        .header("content-type", "application/json")
        .body(r#"{"model":"test","messages":[]}"#)
        .send()
        .await
        .expect("request through gateway");
    assert_eq!(response.status(), reqwest::StatusCode::OK);
    assert!(response.headers().get("content-length").is_none());
    let body = response.text().await.expect("response body");
    assert!(
        body.contains("ai_tool_governor_tool_blocked"),
        "transformed streaming request must be governed: {body}"
    );
    assert!(!body.contains("/etc"), "held frames leaked: {body}");

    let received = h3_backend.received_requests().await;
    assert!(
        !received.iter().any(|request| request.method == "POST"),
        "post-transform reqwest preference was frozen before final-body hooks: {received:#?}"
    );
}

// A bodyless request has no request-body marker that could prefer reqwest. Once
// capability warmup proves the backend H3-capable, its SSE response must still
// run through the native-H3 `StreamingH3` inspector arm. The Content-Length
// assertion also covers the split between the preserved backend length (used
// for graceful-close classification) and the stripped client-visible header.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore]
async fn bodyless_native_h3_sse_response_is_governed() {
    const DENIED_SSE: &str = concat!(
        "data: {\"choices\":[{\"index\":0,\"delta\":{\"tool_calls\":[{\"index\":0,\"id\":\"call_1\",\"function\":{\"name\":\"rm_rf\",\"arguments\":\"{\\\"path\\\":\\\"/etc\\\"}\"}}]}}]}\n\n",
        "data: {\"choices\":[{\"index\":0,\"delta\":{},\"finish_reason\":\"tool_calls\"}]}\n\n",
        "data: [DONE]\n\n",
    );

    let ca = TestCa::new("h3-bodyless-governor").expect("ca");
    let (cert, key) = ca.valid().expect("leaf");
    let (tcp_res, udp_res) = reserve_colocated_tcp_udp()
        .await
        .expect("colocated tcp/udp");
    let backend_port = tcp_res.port;

    // Keep the TCP side available to the concurrent H2 capability probe. The
    // functional request must still land on the QUIC backend, asserted below.
    let _tcp_backend = ScriptedTlsBackend::builder(
        tcp_res.into_listener(),
        TlsConfig::new(cert.clone(), key.clone())
            .with_alpn(vec![b"h2".to_vec(), b"http/1.1".to_vec()]),
    )
    .step(TcpStep::ReadUntil(b"\r\n\r\n".to_vec()))
    .step(TcpStep::Write(
        b"HTTP/1.1 503 Service Unavailable\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
            .to_vec(),
    ))
    .step(TcpStep::Drop)
    .spawn()
    .expect("spawn tls probe backend");

    let h3_backend = ScriptedH3Backend::builder(udp_res.into_socket(), H3TlsConfig::new(cert, key))
        .step(H3Step::AcceptStream)
        .step(H3Step::RespondHeaders(vec![
            (":status", "200".to_string()),
            ("content-type", "text/event-stream".to_string()),
            ("content-length", DENIED_SSE.len().to_string()),
        ]))
        .step(H3Step::RespondData(bytes::Bytes::from_static(
            DENIED_SSE.as_bytes(),
        )))
        // Keep the scripted connection alive long enough for the gateway to
        // parse HEADERS and attach the response inspector before script-end
        // teardown can race recv_response() on CI.
        .step(H3Step::StallFor(Duration::from_millis(50)))
        .spawn()
        .expect("spawn h3 backend");

    let config = json!({
        "version": "1",
        "proxies": [{
            "id": "native-h3-governor",
            "listen_path": "/events",
            "backend_scheme": "https",
            "backend_host": "localhost",
            "backend_port": backend_port,
            "strip_listen_path": true,
            "backend_tls_verify_server_cert": false,
            "plugins": [{"plugin_config_id": "governor"}]
        }],
        "consumers": [],
        "upstreams": [],
        "plugin_configs": [{
            "id": "governor",
            "proxy_id": "native-h3-governor",
            "plugin_name": "ai_tool_governor",
            "scope": "proxy",
            "enabled": true,
            "config": {
                "mode": "enforce",
                "tools": {"rm_rf": {"action": "deny"}},
                "default_action": "allow",
                "inspect": {
                    "response_tool_calls": false,
                    "streaming_response_tool_calls": true
                }
            }
        }]
    });
    let harness = GatewayHarness::builder()
        .file_config(serde_yaml::to_string(&config).expect("yaml"))
        // Initial capability refresh establishes h3=supported without issuing
        // a request. Pool warmup would consume this fixture's single scripted
        // H3 stream before the regression GET reaches it.
        .pool_warmup_enabled(false)
        .env("FERRUM_MAX_REQUEST_BODY_SIZE_BYTES", "0")
        .env("FERRUM_MAX_RESPONSE_BODY_SIZE_BYTES", "0")
        .spawn()
        .await
        .expect("spawn gateway");

    let entry = wait_for_capability_entry(&harness, Duration::from_secs(15))
        .await
        .expect("capability entry")
        .expect("registry populated");
    assert_eq!(
        entry["plain_http"]["h3"].as_str(),
        Some("supported"),
        "precondition: native-H3 streaming arm requires h3=supported; entry: {entry:#?}"
    );

    let response = reqwest::Client::builder()
        .http1_only()
        .build()
        .expect("client")
        .get(harness.proxy_url("/events/live"))
        .send()
        .await
        .expect("bodyless request");
    assert_eq!(response.status(), reqwest::StatusCode::OK);
    assert!(
        response.headers().get("content-length").is_none(),
        "an attached inspector may cut or transform the body"
    );
    let body = response.text().await.expect("response body");
    assert!(
        body.contains("ai_tool_governor_tool_blocked"),
        "governor must terminate the native-H3 stream: {body}"
    );
    assert!(
        !body.contains("/etc"),
        "held denied tool-call frames must not leak: {body}"
    );

    let received = h3_backend.received_requests().await;
    assert!(
        received
            .iter()
            .any(|request| request.method == "GET" && request.path == "/live"),
        "bodyless GET must reach the native H3 backend; received: {received:#?}"
    );
}

// ────────────────────────────────────────────────────────────────────────────
// Test 12 — STREAMING H3 response path recovers a graceful QUIC close that
// arrives AFTER a complete Content-Length body.
//
// Positive coverage for the recovery gate in `H3FrameSource::poll_frame`
// (`src/proxy/body.rs`, the `Poll::Ready(Err(err))` arm): a connection-level
// graceful close (`GOAWAY`/`RemoteClosing` here) that follows a COMPLETE body
// must NOT surface as a spurious mid-stream error — it must emit clean EOS,
// mirroring the buffered `drain_h3_response_body` path. A unit test can't reach
// this: the vendored `h3::error::StreamError` is `#[non_exhaustive]` and
// unconstructible downstream, so no mock can synthesize a graceful close.
//
// Wiring that forces the STREAMING `direct_streaming_h3_body` builder (the one
// that owns `H3FrameSource`), NOT the buffered drain:
//   * H2 (h2c) frontend → native H3 backend, so dispatch runs through
//     `handle_proxy_request_inner` → `ResponseBody::StreamingH3` → `H3FrameSource`
//     rather than the H3-frontend `src/http3/server.rs` loop (which has its own
//     inline recovery and is already covered).
//   * `FERRUM_RESPONSE_BUFFER_CUTOFF_BYTES=0` + `FERRUM_MAX_RESPONSE_BODY_SIZE_BYTES=0`
//     select `direct_streaming_h3_body` (the `response_buffer_cutoff == 0 &&
//     max_response_body_size == 0` arm in `mod.rs:~11391`), so the body is
//     `DirectH3Body` over `H3FrameSource`.
//
// Why an H2 frontend (not H1): when the recovery gate is NOT taken, the
// gateway's frontend body errors AFTER the complete body. On HTTP/1.1 hyper
// has already written the full Content-Length, treats the response as framed,
// and silently swallows the trailing error — so an H1 client cannot observe
// recovery success vs failure. On HTTP/2 the body must reach a clean
// `END_STREAM`; a trailing body error makes hyper emit `RST_STREAM` instead,
// which the H2 client surfaces as a body-read error. The H2 frontend is thus
// what makes this a real positive guard for the branch (verified: with the gate
// stubbed off, the H2 read fails; with it live, the read succeeds).
//
// Backend script (same proven shape as the integration tests
// `h3_goaway_after_complete_body_is_treated_as_graceful` /
// `h3_buffered_response_survives_graceful_close_race`):
//   AcceptStream → RespondHeaders(200, content-length=N) → RespondData(N) →
//   StallFor(50ms) → SendGoaway(0).
// `SendGoaway` skips `stream.finish()`, so there is NO FIN — the gateway's H3
// `recv_data()` yields the full N bytes, then on the NEXT poll hits
// `Err(RemoteClosing)` at the recv_DATA boundary. That is exactly the gate.
// The 50ms stall is load-bearing: it keeps the GOAWAY out of the HEADERS+DATA
// UDP burst so `recv_response()` parses headers (and the body streams) before
// the close arrives — otherwise the close races to the recv_RESPONSE boundary
// (a different, unrecoverable 502 path) and this assertion never runs.
//
// Assert: H2 client gets 200 AND the full N-byte body with a clean stream end.
// ────────────────────────────────────────────────────────────────────────────
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore]
async fn h2_frontend_streaming_h3_recovers_graceful_goaway_after_complete_body() {
    let ca = TestCa::new("phase-h3-stream-goaway-recover").expect("ca");
    let (cert, key) = ca.valid().expect("leaf");

    let (tcp_res, udp_res) = reserve_colocated_tcp_udp()
        .await
        .expect("colocated tcp/udp");
    let backend_port = tcp_res.port;

    // Capability probing needs the colocated TCP+TLS side to answer; the
    // actual test request lands on the H3 backend once h3=supported.
    let _tcp_backend = ScriptedTlsBackend::builder(
        tcp_res.into_listener(),
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

    // Deterministic body so we can assert exact bytes. 4 KiB exercises a
    // real streamed data frame (vs a trivial 2-byte payload) while staying
    // a single H3 DATA frame from the scripted backend.
    let body_len = 4096usize;
    let body: bytes::Bytes = bytes::Bytes::from(vec![b'h'; body_len]);

    let h3_backend = ScriptedH3Backend::builder(udp_res.into_socket(), H3TlsConfig::new(cert, key))
        .step(H3Step::AcceptStream)
        .step(H3Step::RespondHeaders(vec![
            (":status", "200".to_string()),
            ("content-length", body_len.to_string()),
            ("content-type", "application/octet-stream".to_string()),
        ]))
        .step(H3Step::RespondData(body.clone()))
        // Let HEADERS+DATA propagate and the gateway parse the response +
        // stream the body BEFORE the graceful close, so the close lands at
        // the recv_DATA boundary (not recv_response). See the integration
        // tests `h3_goaway_after_complete_body_is_treated_as_graceful` etc.
        .step(H3Step::StallFor(Duration::from_millis(50)))
        // GOAWAY = graceful "no new streams"; in-progress streams complete.
        // Skips `stream.finish()`, so recv_data hits Err(RemoteClosing) after
        // the complete body — the streaming recovery gate must emit clean EOS.
        .step(H3Step::SendGoaway(0))
        .spawn()
        .expect("spawn h3 backend");

    let harness = GatewayHarness::builder()
        .file_config(file_mode_yaml_for_h3(backend_port))
        .log_level("info")
        .capture_output()
        // Avoid pool warmup consuming the scripted backend's single
        // connection script before this regression's GET.
        .env("FERRUM_POOL_WARMUP_ENABLED", "false")
        // Force the STREAMING `direct_streaming_h3_body` builder: both
        // cutoff and the size limit must be 0 to take the direct-stream arm
        // (see `mod.rs:~11391`). Otherwise the coalescing/size-limited arms
        // run — still `H3FrameSource`, but we pin the direct path explicitly.
        .env("FERRUM_RESPONSE_BUFFER_CUTOFF_BYTES", "0")
        .env("FERRUM_MAX_RESPONSE_BODY_SIZE_BYTES", "0")
        .spawn()
        .await
        .expect("spawn gateway");

    let entry = wait_for_capability_entry(&harness, Duration::from_secs(15))
        .await
        .expect("fetch capability entry")
        .expect("registry populated within timeout");
    assert_eq!(
        entry["plain_http"]["h3"].as_str(),
        Some("supported"),
        "expected h3=supported so the request uses the native H3 backend path; entry: {entry:#?}"
    );

    // h2c (HTTP/2 prior-knowledge) frontend client. `Http2Client::get` reads
    // the whole body via `resp.bytes()`, so a trailing `RST_STREAM` from a
    // failed recovery (no clean END_STREAM) surfaces as a `reqwest::Error`
    // rather than a successful read — the detective signal for this branch.
    let client = Http2Client::h2c_prior_knowledge().expect("h2 client");
    let resp = match client.get(&harness.proxy_url("/api/stream")).await {
        Ok(resp) => resp,
        Err(e) => {
            let logs = harness.captured_combined().unwrap_or_default();
            panic!(
                "streaming H3 response failed over the H2 frontend after a graceful \
                 GOAWAY (the recovery gate should have emitted clean EOS so the H2 \
                 stream ends with END_STREAM, not RST_STREAM): {e}\n--- registry: \
                 {entry:#?}\n--- logs ---\n{logs}"
            );
        }
    };
    if resp.status.as_u16() != 200 {
        let logs = harness.captured_combined().unwrap_or_default();
        panic!(
            "expected 200 from H2 frontend to streaming H3 backend after graceful \
             GOAWAY; got {}\n--- registry: {entry:#?}\n--- logs ---\n{logs}",
            resp.status
        );
    }
    if resp.body_bytes.len() != body_len || resp.body_bytes.as_ref() != body.as_ref() {
        let logs = harness.captured_combined().unwrap_or_default();
        panic!(
            "expected the full {body_len}-byte streaming body with clean EOS; got \
             {} bytes\n--- logs ---\n{logs}",
            resp.body_bytes.len()
        );
    }

    // Sanity: the H3 backend actually received the proxied GET (i.e. the
    // request took the native H3 path, not a fallback).
    let received = h3_backend.received_requests().await;
    assert!(
        received.iter().any(|r| r.method == "GET"),
        "H3 backend must have received the frontend GET; recorded: {received:#?}"
    );
}

// ────────────────────────────────────────────────────────────────────────────
// Tests 13–14 — H1/H2 frontend → native H3 backend RESPONSE STREAMING downgrade.
//
// When a response-body plugin (here `compression`) is active and the client
// offers `accept-encoding`, the base decision is to BUFFER the response
// (`should_stream_response_body` == false). For a `206`/`Content-Range` (or SSE)
// body that the plugin would release, the reqwest / direct-H2 backend paths
// already DOWNGRADE buffer→stream via `refine_stream_response_for_content_type`
// once the response headers are known. The H1/H2-frontend → native-H3-backend
// path used to be unable to: the H3 pool's buffered `request()` drained the
// whole body internally before exposing headers, so a large ranged H3 download
// was buffered (and could trip the response-size limit into a `502
// ResponseBodyTooLarge`) and backend trailers were dropped.
//
// These tests pin the fix: `proxy_to_backend_http3` now calls the STREAMING H3
// pool API on the buffered branch, runs the same `refine_*` downgrade, and
// streams the response (forwarding backend trailers via `H3FrameSource`). They
// reuse the proven h2c-frontend → native-H3-backend wiring from Test 12.
// ────────────────────────────────────────────────────────────────────────────

/// File-mode YAML for one HTTPS proxy at `(127.0.0.1, port)` with a
/// proxy-scoped `compression` plugin. compression buffers the response by
/// default (when the client offers `accept-encoding`), forcing the buffered
/// dispatch decision these tests need to exercise the downgrade.
fn file_mode_yaml_for_h3_with_compression(port: u16) -> String {
    file_mode_yaml_for_h3_with_compression_and_read_timeout(port, 5000)
}

fn file_mode_yaml_for_h3_with_compression_and_read_timeout(
    port: u16,
    backend_read_timeout_ms: u64,
) -> String {
    let config = json!({
        "version": "1",
        "proxies": [{
            "id": "scripted-h3",
            "listen_path": "/api",
            "backend_scheme": "https",
            "backend_host": "127.0.0.1",
            "backend_port": port,
            "strip_listen_path": true,
            "backend_connect_timeout_ms": 2000,
            "backend_read_timeout_ms": backend_read_timeout_ms,
            "backend_write_timeout_ms": 5000,
            "backend_tls_verify_server_cert": false,
            "plugins": [{ "plugin_config_id": "compress-1" }],
        }],
        "consumers": [],
        "upstreams": [],
        "plugin_configs": [
            {
                "id": "compress-1",
                "proxy_id": "scripted-h3",
                "plugin_name": "compression",
                "scope": "proxy",
                "enabled": true,
                "config": { "algorithms": ["gzip"] },
            },
            {
                "id": "h3-access-log",
                "plugin_name": "stdout_logging",
                "scope": "global",
                "enabled": true,
                "config": {},
            }
        ],
    });
    serde_yaml::to_string(&config).expect("yaml serialize")
}

/// Minimal response captured by [`raw_h2c_request`].
struct RawH2Response {
    status: u16,
    headers: std::collections::HashMap<String, String>,
    body: Vec<u8>,
    /// Response trailers (lower-cased names), populated from the H2 trailers
    /// frame. reqwest discards trailers, so the tests can't use `Http2Client`.
    trailers: std::collections::HashMap<String, String>,
    /// `Some` when the body stream ended with an error (e.g. a `RST_STREAM`
    /// after a mid-stream size-limit truncation) instead of a clean END_STREAM.
    body_error: Option<String>,
}

/// Drive a single raw h2c (HTTP/2 prior-knowledge over cleartext) request to
/// the gateway and capture status, headers, body, AND trailers. The status +
/// headers are read as soon as the response head arrives, so a request whose
/// body later truncates (size-limit `RST_STREAM`) still surfaces its `206`
/// status — the signal that the response STREAMED rather than being rejected
/// as a buffered `502`.
async fn raw_h2c_request(
    url: &str,
    method: &str,
    extra_headers: &[(&str, &str)],
) -> Result<RawH2Response, Box<dyn std::error::Error + Send + Sync>> {
    use http_body_util::{BodyExt, Empty};
    use hyper::client::conn::http2;
    use hyper_util::rt::{TokioExecutor, TokioIo};

    let uri: hyper::Uri = url.parse()?;
    let authority = uri.authority().ok_or("url missing authority")?.to_string();
    let addr: std::net::SocketAddr = authority.parse()?;
    let stream = tokio::net::TcpStream::connect(addr).await?;
    let _ = stream.set_nodelay(true);
    let io = TokioIo::new(stream);

    let (mut sender, conn) = http2::handshake(TokioExecutor::new(), io).await?;
    let conn_task = tokio::spawn(async move {
        let _ = conn.await;
    });

    let mut builder = hyper::Request::builder().method(method).uri(url);
    for (k, v) in extra_headers {
        builder = builder.header(*k, *v);
    }
    let req = builder.body(Empty::<bytes::Bytes>::new())?;
    let resp = tokio::time::timeout(Duration::from_secs(15), sender.send_request(req)).await??;

    let status = resp.status().as_u16();
    let mut headers = std::collections::HashMap::new();
    for (k, v) in resp.headers() {
        if let Ok(s) = v.to_str() {
            headers.insert(k.as_str().to_ascii_lowercase(), s.to_string());
        }
    }

    let mut body = Vec::new();
    let mut trailers = std::collections::HashMap::new();
    let mut body_error = None;
    let mut incoming = resp.into_body();
    loop {
        match tokio::time::timeout(Duration::from_secs(15), incoming.frame()).await {
            Ok(Some(Ok(frame))) => {
                if let Some(data) = frame.data_ref() {
                    body.extend_from_slice(data);
                } else if let Some(tr) = frame.trailers_ref() {
                    for (k, v) in tr {
                        if let Ok(s) = v.to_str() {
                            trailers.insert(k.as_str().to_ascii_lowercase(), s.to_string());
                        }
                    }
                }
            }
            Ok(Some(Err(e))) => {
                body_error = Some(e.to_string());
                break;
            }
            Ok(None) => break,
            Err(_) => {
                body_error = Some("body read timed out".to_string());
                break;
            }
        }
    }
    conn_task.abort();

    Ok(RawH2Response {
        status,
        headers,
        body,
        trailers,
        body_error,
    })
}

/// Spawn the colocated TCP+TLS capability sidecar + scripted H3 backend +
/// gateway (compression-enabled), wait for `h3 = supported`, and return the
/// harness + backend handle. Shared by tests 13–14.
async fn spawn_h3_streaming_downgrade_harness(
    ca_name: &str,
    h3_steps: Vec<H3Step>,
    extra_env: &[(&str, &str)],
) -> (GatewayHarness, ScriptedH3Backend) {
    spawn_h3_streaming_downgrade_harness_with_read_timeout(ca_name, h3_steps, extra_env, 5000).await
}

async fn spawn_h3_streaming_downgrade_harness_with_read_timeout(
    ca_name: &str,
    h3_steps: Vec<H3Step>,
    extra_env: &[(&str, &str)],
    backend_read_timeout_ms: u64,
) -> (GatewayHarness, ScriptedH3Backend) {
    let ca = TestCa::new(ca_name).expect("ca");
    let (cert, key) = ca.valid().expect("leaf");

    let (tcp_res, udp_res) = reserve_colocated_tcp_udp()
        .await
        .expect("colocated tcp/udp");
    let backend_port = tcp_res.port;

    // TCP+TLS sidecar answers the capability probe (advertises h2+http/1.1);
    // the real request lands on the H3 backend once h3=supported.
    let _tcp_backend = ScriptedTlsBackend::builder(
        tcp_res.into_listener(),
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
    // Keep the sidecar alive for the whole test (probe may re-run).
    Box::leak(Box::new(_tcp_backend));

    let h3_backend = ScriptedH3Backend::builder(udp_res.into_socket(), H3TlsConfig::new(cert, key))
        .steps(h3_steps)
        .spawn()
        .expect("spawn h3 backend");

    let mut builder = GatewayHarness::builder()
        .file_config(file_mode_yaml_for_h3_with_compression_and_read_timeout(
            backend_port,
            backend_read_timeout_ms,
        ))
        .log_level("info")
        .capture_output()
        // Avoid pool warmup issuing an extra H3 request before the test's GET.
        .env("FERRUM_POOL_WARMUP_ENABLED", "false");
    for (k, v) in extra_env {
        builder = builder.env(*k, *v);
    }
    let harness = builder.spawn().await.expect("spawn gateway");

    let entry = wait_for_capability_entry(&harness, Duration::from_secs(15))
        .await
        .expect("fetch capability entry")
        .expect("registry populated within timeout");
    assert_eq!(
        entry["plain_http"]["h3"].as_str(),
        Some("supported"),
        "expected h3=supported so the request uses the native H3 backend path; entry: {entry:#?}"
    );

    (harness, h3_backend)
}

async fn spawn_h3_frontend_refined_buffering_harness(
    ca_name: &str,
    h3_steps: Vec<H3Step>,
    extra_env: &[(&str, &str)],
) -> (GatewayHarness, ScriptedH3Backend, u16) {
    let ca = TestCa::new(ca_name).expect("ca");
    let (cert, key) = ca.valid().expect("leaf");

    let (tcp_res, udp_res) = reserve_colocated_tcp_udp()
        .await
        .expect("colocated tcp/udp");
    let backend_port = tcp_res.port;

    let _tcp_backend = ScriptedTlsBackend::builder(
        tcp_res.into_listener(),
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
    Box::leak(Box::new(_tcp_backend));

    let h3_backend = ScriptedH3Backend::builder(udp_res.into_socket(), H3TlsConfig::new(cert, key))
        .steps(h3_steps)
        .spawn()
        .expect("spawn h3 backend");

    let reservation = reserve_port().await.expect("reserve https port");
    let https_port = reservation.port;
    drop(reservation);

    let scratch = tempfile::tempdir().expect("scratch");
    let (_ca_pem, cert_path, key_path) =
        write_frontend_certs(scratch.path(), "h3-gw-refined-buffering");
    Box::leak(Box::new(scratch));

    let mut builder = GatewayHarness::builder()
        .file_config(file_mode_yaml_for_h3_with_compression(backend_port))
        .log_level("info")
        .capture_output()
        .env("FERRUM_ENABLE_HTTP3", "true")
        .env("FERRUM_PROXY_HTTPS_PORT", https_port.to_string())
        .env("FERRUM_FRONTEND_TLS_CERT_PATH", cert_path)
        .env("FERRUM_FRONTEND_TLS_KEY_PATH", key_path)
        .env("FERRUM_TLS_NO_VERIFY", "true")
        .env("FERRUM_POOL_WARMUP_ENABLED", "true");
    for (k, v) in extra_env {
        builder = builder.env(*k, *v);
    }
    let harness = builder.spawn().await.expect("spawn gateway");

    let entry = wait_for_capability_entry(&harness, Duration::from_secs(15))
        .await
        .expect("fetch capability entry")
        .expect("registry populated within timeout");
    assert_eq!(
        entry["plain_http"]["h3"].as_str(),
        Some("supported"),
        "expected h3=supported so the H3 frontend uses the native H3 backend path; entry: {entry:#?}"
    );

    (harness, h3_backend, https_port)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore]
async fn h3_mid_body_reset_and_goaway_surface_protocol_error_family() {
    for (name, terminal_step) in [
        ("reset-stream", H3Step::SendStreamReset(0x10c)),
        ("goaway", H3Step::SendGoaway(0)),
    ] {
        let declared_len = 64usize;
        let prefix = bytes::Bytes::from_static(b"partial-");
        let (harness, h3_backend) = spawn_h3_streaming_downgrade_harness(
            &format!("phase-h3-{name}"),
            vec![
                H3Step::AcceptStream,
                H3Step::RespondHeaders(vec![
                    (":status", "206".to_string()),
                    (
                        "content-range",
                        format!("bytes 0-{}/{declared_len}", declared_len - 1),
                    ),
                    ("content-length", declared_len.to_string()),
                    ("content-type", "text/plain".to_string()),
                ]),
                H3Step::RespondData(prefix.clone()),
                H3Step::StallFor(Duration::from_millis(50)),
                terminal_step,
            ],
            &[("FERRUM_MAX_RESPONSE_BODY_SIZE_BYTES", "0")],
        )
        .await;

        let response = tokio::time::timeout(
            Duration::from_secs(5),
            raw_h2c_request(
                &harness.proxy_url(&format!("/api/{name}")),
                "GET",
                &[("accept-encoding", "gzip"), ("range", "bytes=0-63")],
            ),
        )
        .await
        .unwrap_or_else(|_| panic!("{name} response hung past the outer timeout"))
        .unwrap_or_else(|error| panic!("{name} raw H2 client error: {error}"));

        assert_eq!(
            response.status, 206,
            "{name} should fail after the streaming response head; response body_error={:?}",
            response.body_error
        );
        assert_eq!(response.body.as_slice(), prefix.as_ref());
        assert!(
            response.body_error.is_some(),
            "{name} must terminate the partial body with an error, not clean END_STREAM"
        );

        let logs = harness
            .wait_for_log_contains(
                |logs| logs.contains("\"body_error_class\":\"protocol_error\""),
                Duration::from_secs(5),
            )
            .await;
        assert!(
            logs.contains("\"body_error_class\":\"protocol_error\""),
            "{name} must classify as the H3 protocol-error family; logs:\n{logs}"
        );
        assert!(
            !logs.contains("\"body_error_class\":\"connection_reset\""),
            "{name} was falsely classified as a connection reset instead of a stream protocol error; logs:\n{logs}"
        );

        let capability = fetch_capability_entry(&harness)
            .await
            .expect("capability lookup")
            .expect("capability entry");
        assert_eq!(
            capability["plain_http"]["h3"].as_str(),
            Some("supported"),
            "{name} is a post-headers stream fault and must not falsely downgrade the backend's H3 capability; capability={capability:#?}"
        );
        let requests = h3_backend.received_requests().await;
        assert!(
            requests
                .iter()
                .any(|request| request.path == format!("/{name}")),
            "{name} request did not reach the native H3 backend; requests={requests:?}"
        );
        assert!(
            h3_backend.step_errors().await.is_empty(),
            "{name} script errors: {:?}",
            h3_backend.step_errors().await
        );
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore]
async fn h3_native_pool_partial_data_read_timeout_returns_timeout_without_downgrade() {
    let prefix = bytes::Bytes::from_static(b"partial-");
    let (harness, h3_backend) = spawn_h3_streaming_downgrade_harness_with_read_timeout(
        "phase-h3-partial-read-timeout",
        vec![
            H3Step::AcceptStream,
            H3Step::RespondHeaders(vec![
                (":status", "200".to_string()),
                ("content-length", "64".to_string()),
                ("content-type", "text/plain".to_string()),
            ]),
            H3Step::RespondData(prefix),
            H3Step::StallFor(Duration::from_secs(30)),
        ],
        // A bounded (non-zero, <= 32 MiB) response-body limit keeps the
        // compression plugin on the buffered collect path. Response compression
        // is disabled when the gateway limit is unlimited (0) or above the
        // 32 MiB compression ceiling, and only the buffered collect converts a
        // mid-body backend read timeout into a pre-commit 504 Backend timeout
        // instead of a committed partial 200.
        &[("FERRUM_MAX_RESPONSE_BODY_SIZE_BYTES", "1048576")],
        200,
    )
    .await;

    let response = tokio::time::timeout(
        Duration::from_secs(4),
        raw_h2c_request(
            &harness.proxy_url("/api/partial-timeout"),
            "GET",
            &[("accept-encoding", "gzip")],
        ),
    )
    .await
    .expect("native-H3 read timeout must beat the scripted 30s stall")
    .expect("gateway timeout response");

    assert_eq!(response.status, 504, "response={:?}", response.body);
    assert!(
        String::from_utf8_lossy(&response.body).contains("Backend timeout"),
        "unexpected timeout body: {:?}",
        response.body
    );
    let entry = fetch_capability_entry(&harness)
        .await
        .expect("capability lookup")
        .expect("capability entry");
    assert_eq!(
        entry["plain_http"]["h3"].as_str(),
        Some("supported"),
        "a response read timeout proves latency, not loss of H3 capability; entry={entry:#?}"
    );
    let requests = h3_backend.received_requests().await;
    assert!(
        requests
            .iter()
            .any(|request| request.path == "/partial-timeout"),
        "timeout request did not reach the native H3 backend; requests={requests:?}"
    );
}

// ────────────────────────────────────────────────────────────────────────────
// Test 13 — H3 frontend refined-buffered drain rejects a clean FIN that arrives
// before the declared Content-Length is satisfied.
//
// The compression plugin plus `accept-encoding` makes the initial response-body
// decision buffered. A plain `200 text/plain` response stays buffered after the
// content-type refinement, so the H3 frontend runs
// `collect_h3_open_response_body` in `src/http3/server.rs`. Pre-fix that drain
// broke on `recv_data() == Ok(None)` and forwarded a short 2-byte body as a
// complete 200 despite `Content-Length: 5`.
// ────────────────────────────────────────────────────────────────────────────
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore]
async fn h3_frontend_refined_buffered_rejects_truncated_content_length_fin() {
    let declared_len = 5usize;
    let actual = bytes::Bytes::from_static(b"ok");

    let (harness, h3_backend, https_port) = spawn_h3_frontend_refined_buffering_harness(
        "phase-h3-refined-buffered-truncated-cl",
        vec![
            H3Step::AcceptStream,
            H3Step::RespondHeaders(vec![
                (":status", "200".to_string()),
                ("content-length", declared_len.to_string()),
                ("content-type", "text/plain".to_string()),
            ]),
            H3Step::RespondData(actual),
            H3Step::RespondTrailers(vec![("x-backend-finished", "true".to_string())]),
            H3Step::StallFor(Duration::from_millis(100)),
        ],
        // A bounded (non-zero, <= 32 MiB) response-body limit keeps the
        // compression plugin on the refined-buffered collect path. Response
        // compression is disabled when the gateway limit is unlimited (0) or
        // above the 32 MiB compression ceiling, and only the buffered collect
        // (`collect_h3_open_response_body`) rejects a short Content-Length FIN
        // as a pre-commit 502 truncation instead of forwarding a committed 200.
        &[("FERRUM_MAX_RESPONSE_BODY_SIZE_BYTES", "1048576")],
    )
    .await;

    let client = Http3Client::insecure().expect("h3 client");
    let url = format!("https://127.0.0.1:{https_port}/api/truncated-cl");
    let resp = client
        .get_with_options(
            &url,
            GetOptions::default().header("accept-encoding", "gzip"),
        )
        .await
        .unwrap_or_else(|err| {
            let logs = harness.captured_combined().unwrap_or_default();
            panic!("h3 request failed: {err}\n--- logs ---\n{logs}");
        });

    let logs = harness.captured_combined().unwrap_or_default();
    assert_eq!(
        resp.status.as_u16(),
        502,
        "short Content-Length-delimited H3 body must surface as 502, not a complete 200; body={:?}\n--- logs ---\n{logs}",
        String::from_utf8_lossy(&resp.body_bytes)
    );
    assert!(
        String::from_utf8_lossy(&resp.body_bytes).contains("HTTP/3 backend response truncated"),
        "expected truncation error body; got {:?}\n--- logs ---\n{logs}",
        String::from_utf8_lossy(&resp.body_bytes)
    );

    let received = h3_backend.received_requests().await;
    assert!(
        received.iter().any(|r| r.path == "/truncated-cl"),
        "backend should have received the real test request; received={received:?}"
    );
}

// ────────────────────────────────────────────────────────────────────────────
// Test 14 — a 206 the buffered (compression) decision would have buffered is
// DOWNGRADED to streaming, delivering the full body AND forwarding backend
// trailers to the H2 downstream client (with hop-by-hop trailer names stripped).
// Pre-fix this path drained the body buffered and dropped the trailers.
// ────────────────────────────────────────────────────────────────────────────
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore]
async fn h2c_frontend_h3_backend_206_buffered_decision_streams_and_forwards_trailers() {
    let body_len = 512usize;
    let body = bytes::Bytes::from(vec![b'r'; body_len]);

    let (harness, h3_backend) = spawn_h3_streaming_downgrade_harness(
        "phase-h3-206-trailers",
        vec![
            H3Step::AcceptStream,
            // 206 + Content-Range WITH Content-Length. The Content-Length is
            // load-bearing: the backend drops the QUIC connection
            // (H3_NO_ERROR) at end-of-script, and `H3FrameSource`'s
            // graceful-close recovery only treats that close as a clean EOS
            // when the body is provably complete — which needs a
            // Content-Length (see `is_response_body_complete`). Without it the
            // streamed body ends in an error instead of clean END_STREAM.
            H3Step::RespondHeaders(vec![
                (":status", "206".to_string()),
                (
                    "content-range",
                    format!("bytes 0-{}/{}", body_len - 1, body_len * 8),
                ),
                ("content-length", body_len.to_string()),
                ("content-type", "text/plain".to_string()),
            ]),
            H3Step::RespondData(body.clone()),
            // Let HEADERS+DATA reach the gateway + stream to the client before
            // the trailers, mirroring the proven streaming-test shape.
            H3Step::StallFor(Duration::from_millis(50)),
            H3Step::RespondTrailers(vec![
                ("x-backend-checksum", "sha256-deadbeef".to_string()),
                // Hop-by-hop trailer name — must be stripped before forwarding.
                ("transfer-encoding", "chunked".to_string()),
            ]),
            // Keep the connection open briefly so trailers propagate before the
            // implicit end-of-script connection drop.
            H3Step::StallFor(Duration::from_millis(100)),
        ],
        // Unlimited response size: this test is about the downgrade + trailer
        // forwarding, so the full body + trailers must arrive cleanly.
        &[("FERRUM_MAX_RESPONSE_BODY_SIZE_BYTES", "0")],
    )
    .await;

    let resp = raw_h2c_request(
        &harness.proxy_url("/api/range"),
        "GET",
        // No explicit Host: the H2 `:authority` is set from the request URI
        // (127.0.0.1:<port>); an extra mismatched Host would trip
        // `check_host_authority_consistency` (400) before routing.
        &[("accept-encoding", "gzip"), ("range", "bytes=0-511")],
    )
    .await
    .unwrap_or_else(|e| {
        let logs = harness.captured_combined().unwrap_or_default();
        panic!("raw h2c request failed: {e}\n--- logs ---\n{logs}");
    });

    let logs = harness.captured_combined().unwrap_or_default();
    assert_eq!(
        resp.status, 206,
        "expected the 206 to STREAM (not a buffered 502); headers={:?} body_error={:?}\n--- logs ---\n{logs}",
        resp.headers, resp.body_error
    );
    assert!(
        resp.body_error.is_none(),
        "expected a clean stream end; body_error={:?}\n--- logs ---\n{logs}",
        resp.body_error
    );
    assert_eq!(
        resp.body.len(),
        body_len,
        "expected the full {body_len}-byte body; got {}",
        resp.body.len()
    );
    assert_eq!(
        resp.body.as_slice(),
        body.as_ref(),
        "downstream body must match the backend body byte-for-byte"
    );
    assert_eq!(
        resp.trailers.get("x-backend-checksum").map(String::as_str),
        Some("sha256-deadbeef"),
        "backend trailer must be forwarded to the H2 downstream client (the buffered \
         decision was downgraded to streaming); trailers={:?}",
        resp.trailers
    );
    assert!(
        !resp.trailers.contains_key("transfer-encoding"),
        "hop-by-hop trailer name must be stripped before forwarding; trailers={:?}",
        resp.trailers
    );

    let received = h3_backend.received_requests().await;
    assert!(
        received.iter().any(|r| r.method == "GET"),
        "H3 backend must have received the GET; recorded: {received:#?}"
    );
}

// ────────────────────────────────────────────────────────────────────────────
// Test 15 — trailer HEADERS delivered before a delayed FIN survive the
// H3 trailer-phase read-timeout collapse.
// ────────────────────────────────────────────────────────────────────────────
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore]
async fn h2c_frontend_h3_backend_forwards_trailers_when_fin_is_delayed_past_timeout() {
    let body_len = 128usize;
    let body = bytes::Bytes::from(vec![b't'; body_len]);

    let (harness, h3_backend) = spawn_h3_streaming_downgrade_harness_with_read_timeout(
        "phase-h3-delayed-fin-trailers",
        vec![
            H3Step::AcceptStream,
            H3Step::RespondHeaders(vec![
                (":status", "206".to_string()),
                (
                    "content-range",
                    format!("bytes 0-{}/{}", body_len - 1, body_len * 8),
                ),
                ("content-length", body_len.to_string()),
                ("content-type", "text/plain".to_string()),
            ]),
            H3Step::RespondData(body.clone()),
            H3Step::RespondTrailersWithoutFin(vec![
                ("x-backend-checksum", "sha256-delayed-fin".to_string()),
                ("transfer-encoding", "chunked".to_string()),
            ]),
            // Keep the stream open past the 25 ms backend read timeout. Pre-fix,
            // h3 had the trailer HEADERS buffered internally but withheld them
            // until FIN, so the gateway's timeout collapse emitted clean EOS and
            // dropped the trailers.
            H3Step::StallFor(Duration::from_millis(200)),
        ],
        &[("FERRUM_MAX_RESPONSE_BODY_SIZE_BYTES", "0")],
        25,
    )
    .await;

    let resp = raw_h2c_request(
        &harness.proxy_url("/api/delayed-fin-trailers"),
        "GET",
        &[("accept-encoding", "gzip"), ("range", "bytes=0-127")],
    )
    .await
    .unwrap_or_else(|e| {
        let logs = harness.captured_combined().unwrap_or_default();
        panic!("raw h2c request failed: {e}\n--- logs ---\n{logs}");
    });

    let logs = harness.captured_combined().unwrap_or_default();
    assert_eq!(
        resp.status, 206,
        "expected delayed-FIN trailered response to stay successful; headers={:?} body_error={:?}\n--- logs ---\n{logs}",
        resp.headers, resp.body_error
    );
    assert!(
        resp.body_error.is_none(),
        "expected delayed-FIN trailer timeout to end cleanly; body_error={:?}\n--- logs ---\n{logs}",
        resp.body_error
    );
    assert_eq!(resp.body.as_slice(), body.as_ref());
    assert_eq!(
        resp.trailers.get("x-backend-checksum").map(String::as_str),
        Some("sha256-delayed-fin"),
        "backend trailer buffered before delayed FIN must be forwarded; trailers={:?}\n--- logs ---\n{logs}",
        resp.trailers
    );
    assert!(
        !resp.trailers.contains_key("transfer-encoding"),
        "hop-by-hop trailer name must be stripped before forwarding; trailers={:?}",
        resp.trailers
    );

    let received = h3_backend.received_requests().await;
    assert!(
        received.iter().any(|r| r.path == "/delayed-fin-trailers"),
        "H3 backend must have received the delayed-FIN request; recorded: {received:#?}"
    );
}

// ────────────────────────────────────────────────────────────────────────────
// Test 16 — a LARGE 206 (no Content-Length) under a small response-size limit
// is STREAMED (status 206 reaches the client) instead of being converted into a
// buffered `502 ResponseBodyTooLarge`. The streamed body is then truncated at
// the limit (a mid-stream `RST_STREAM`), but the `206` status proves the
// response started streaming — pre-fix the buffered drain rejected it with a
// 502 before any bytes/headers reached the client.
// ────────────────────────────────────────────────────────────────────────────
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore]
async fn h2c_frontend_h3_backend_large_206_streams_not_buffered_502() {
    // Keep `LIMIT` and the env string below in lock-step.
    const LIMIT: usize = 4096;
    const LIMIT_ENV: &str = "4096";
    // First chunk is UNDER the limit, second chunk pushes cumulative OVER it.
    let first_chunk = bytes::Bytes::from(vec![b'd'; 2048]);
    let second_chunk = bytes::Bytes::from(vec![b'e'; 4096]);

    let (harness, h3_backend) = spawn_h3_streaming_downgrade_harness(
        "phase-h3-large-206",
        vec![
            H3Step::AcceptStream,
            // 206 with NO Content-Length: the declared-length pre-stream reject
            // can't fire, so the downgrade must stream and the incremental
            // size-limit applies WHILE streaming (truncating mid-body) rather
            // than rejecting up front with a buffered 502.
            H3Step::RespondHeaders(vec![
                (":status", "206".to_string()),
                ("content-range", format!("bytes 0-12287/{}", 64 * 1024)),
                ("content-type", "application/octet-stream".to_string()),
            ]),
            // First (under-limit) chunk, then a stall so the gateway's coalescer
            // flushes the 206 headers + this chunk to the client BEFORE the
            // over-limit chunk trips the size guard. Without that flush, the
            // size error would surface on the first body poll (before headers)
            // and reset the stream with no status — masking the "streamed, not
            // buffered-502" signal.
            H3Step::RespondData(first_chunk),
            H3Step::StallFor(Duration::from_millis(60)),
            // This chunk pushes cumulative bytes past the limit → mid-stream
            // truncation (RST_STREAM), NOT a pre-stream buffered 502.
            H3Step::RespondData(second_chunk),
            H3Step::StallFor(Duration::from_millis(100)),
        ],
        &[("FERRUM_MAX_RESPONSE_BODY_SIZE_BYTES", LIMIT_ENV)],
    )
    .await;

    let resp = raw_h2c_request(
        &harness.proxy_url("/api/big-range"),
        "GET",
        // No explicit Host (see the trailers test): the URI sets `:authority`.
        &[("accept-encoding", "gzip"), ("range", "bytes=0-")],
    )
    .await
    .unwrap_or_else(|e| {
        let logs = harness.captured_combined().unwrap_or_default();
        panic!("raw h2c request failed: {e}\n--- logs ---\n{logs}");
    });

    let logs = harness.captured_combined().unwrap_or_default();
    // The KEY assertion: the client sees 206 (streaming started), NOT a buffered
    // 502 ResponseBodyTooLarge. Pre-fix the H3 buffered drain produced the 502.
    assert_eq!(
        resp.status, 206,
        "large H3-backend range response must STREAM (status 206) instead of being \
         converted into a buffered 502; got {} headers={:?} body_error={:?}\n--- logs ---\n{logs}",
        resp.status, resp.headers, resp.body_error
    );
    // The body is bounded by the incremental size limit (the stream is cut once
    // it would exceed the cap), so the client received at most ~`limit` bytes
    // and the stream ended with an error rather than a clean END_STREAM.
    assert!(
        resp.body.len() <= LIMIT,
        "streamed body must be bounded by the incremental size limit ({LIMIT}); got {}",
        resp.body.len()
    );

    let received = h3_backend.received_requests().await;
    assert!(
        received.iter().any(|r| r.method == "GET"),
        "H3 backend must have received the GET; recorded: {received:#?}"
    );
}

// ════════════════════════════════════════════════════════════════════════════
// Native H3 gRPC dispatch (`dispatch_grpc_native_h3`).
//
// A gRPC request received over the H3 frontend, whose concrete backend is
// proven H3-capable, is streamed directly over the native QUIC backend pool —
// NOT the H2-only gRPC pool. Because the scripted H3 backend speaks only QUIC
// (no h2/h2c listener of its own), a successful gRPC round-trip PROVES native
// H3 dispatch: the cross-protocol H2 gRPC bridge could never reach it. Each
// test additionally asserts the H3 backend actually recorded the proxied gRPC
// POST.
// ════════════════════════════════════════════════════════════════════════════

/// Length-prefixed gRPC message frame: `[compressed:1][len:u32 BE][payload]`.
fn grpc_frame(payload: &[u8]) -> Vec<u8> {
    let mut frame = Vec::with_capacity(5 + payload.len());
    frame.push(0u8); // not compressed
    frame.extend_from_slice(&(payload.len() as u32).to_be_bytes());
    frame.extend_from_slice(payload);
    frame
}

/// Send a unary gRPC POST over the H3 frontend (`content-type: application/grpc`)
/// and return the buffered response (status + headers + body + trailers).
async fn h3_grpc_post(
    harness: &GatewayHarness,
    path: &str,
    request_frame: Vec<u8>,
) -> Result<crate::scaffolding::clients::Http3Response, Box<dyn std::error::Error + Send + Sync>> {
    h3_grpc_post_with_headers(harness, path, request_frame, &[]).await
}

async fn h3_grpc_post_with_headers(
    harness: &GatewayHarness,
    path: &str,
    request_frame: Vec<u8>,
    extra_headers: &[(&str, &str)],
) -> Result<crate::scaffolding::clients::Http3Response, Box<dyn std::error::Error + Send + Sync>> {
    let client = Http3Client::insecure()?;
    let https_port = harness_proxy_https_port(harness)?;
    let url = format!("https://127.0.0.1:{https_port}{path}");
    let mut opts = crate::scaffolding::clients::GetOptions::default()
        .method(http::Method::POST)
        .header("content-type", "application/grpc")
        .header("te", "trailers")
        .body(bytes::Bytes::from(request_frame));
    for (name, value) in extra_headers {
        opts = opts.header(*name, *value);
    }
    client.get_with_options(&url, opts).await
}

/// Build the colocated TCP+TLS (h2 ALPN) capability-probe backend used by the
/// native-H3 gRPC tests so the capability registry can classify the target as
/// H3-capable before traffic. The real gRPC request lands on the H3 backend.
fn spawn_grpc_probe_tcp_backend(
    listener: tokio::net::TcpListener,
    cert: String,
    key: String,
) -> crate::scaffolding::backends::ScriptedTlsBackend {
    ScriptedTlsBackend::builder(
        listener,
        TlsConfig::new(cert, key).with_alpn(vec![b"h2".to_vec(), b"http/1.1".to_vec()]),
    )
    .step(TcpStep::ReadUntil(b"\r\n\r\n".to_vec()))
    .step(TcpStep::Write(
        b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n".to_vec(),
    ))
    .step(TcpStep::Drop)
    .spawn()
    .expect("spawn tls probe backend")
}

// ────────────────────────────────────────────────────────────────────────────
// Unary gRPC over native H3: body framing + `grpc-status`/`grpc-message`
// trailers must be preserved end to end.
// ────────────────────────────────────────────────────────────────────────────
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore]
async fn h3_native_grpc_unary_preserves_body_and_trailers() {
    let ca = TestCa::new("phase-h3-grpc-unary").expect("ca");
    let (cert, key) = ca.valid().expect("leaf");

    let (tcp_res, udp_res) = reserve_colocated_tcp_udp()
        .await
        .expect("colocated tcp/udp");
    let backend_port = tcp_res.port;

    let _tcp_backend =
        spawn_grpc_probe_tcp_backend(tcp_res.into_listener(), cert.clone(), key.clone());

    let reply_frame = grpc_frame(b"pong-from-h3-grpc");

    // The script is consumed once per QUIC connection; the capability probe and
    // the real request each get a fresh copy. Each serves a gRPC unary response:
    // HEADERS(200, application/grpc) -> DATA(one framed message) -> terminal
    // TRAILERS(grpc-status: 0, grpc-message: OK).
    let h3_backend = ScriptedH3Backend::builder(udp_res.into_socket(), H3TlsConfig::new(cert, key))
        .step(H3Step::AcceptStream)
        .step(H3Step::RespondHeaders(vec![
            (":status", "200".to_string()),
            ("content-type", "application/grpc".to_string()),
        ]))
        .step(H3Step::RespondData(bytes::Bytes::from(reply_frame.clone())))
        .step(H3Step::RespondTrailers(vec![
            ("grpc-status", "0".to_string()),
            ("grpc-message", "OK".to_string()),
        ]))
        // Keep the connection open after the trailers + FIN so the gateway reads
        // the complete trailered response before the script-end connection drop
        // (see `H3Step::RespondTrailers`). CI can schedule the H3 poll after a
        // short 100ms grace window under shard load.
        .step(H3Step::StallFor(Duration::from_secs(1)))
        .spawn()
        .expect("spawn h3 backend");

    let (harness, _ca_pem, _https_port) =
        spawn_h3_harness_with_explicit_https_port(backend_port, false, Some(1)).await;

    let entry = wait_for_capability_entry(&harness, Duration::from_secs(15))
        .await
        .expect("fetch capability entry")
        .expect("registry populated within timeout");
    assert_eq!(
        entry["plain_http"]["h3"].as_str(),
        Some("supported"),
        "expected h3=supported so the gRPC request uses the native H3 backend path; entry: {entry:#?}"
    );

    let resp = match h3_grpc_post(&harness, "/api/echo.Echo/Unary", grpc_frame(b"ping")).await {
        Ok(resp) => resp,
        Err(e) => {
            let logs = harness.captured_combined().unwrap_or_default();
            panic!("native H3 gRPC unary request failed: {e}\n--- logs ---\n{logs}");
        }
    };

    let logs = harness.captured_combined().unwrap_or_default();
    assert_eq!(
        resp.status.as_u16(),
        200,
        "gRPC over native H3 must return HTTP 200; got {}\n--- logs ---\n{logs}",
        resp.status
    );
    assert_eq!(
        resp.headers
            .get("content-type")
            .and_then(|v| v.to_str().ok()),
        Some("application/grpc"),
        "content-type must be preserved as application/grpc; headers: {:#?}",
        resp.headers
    );
    assert_eq!(
        resp.grpc_status(),
        Some(0),
        "grpc-status trailer must be forwarded; trailers: {:#?}\n--- logs ---\n{logs}",
        resp.trailers
    );
    assert_eq!(
        resp.grpc_message().as_deref(),
        Some("OK"),
        "grpc-message trailer must be forwarded; trailers: {:#?}",
        resp.trailers
    );
    assert_eq!(
        resp.body_bytes.as_ref(),
        reply_frame.as_slice(),
        "gRPC response body frame must be forwarded byte-for-byte"
    );

    // Proves native H3 dispatch: the H3-only backend recorded the proxied gRPC
    // POST. The H2 gRPC bridge could never have reached this QUIC-only backend.
    let received = h3_backend.received_requests().await;
    assert!(
        received
            .iter()
            .any(|r| r.method == "POST" && r.path.ends_with("/echo.Echo/Unary")),
        "H3 backend must have received the proxied gRPC POST (native H3 dispatch); \
         recorded: {received:#?}\n--- logs ---\n{logs}"
    );
}

async fn assert_h3_native_grpc_trailers_only_preserves_terminal_metadata(remove_terminal: bool) {
    let ca = TestCa::new("phase-h3-grpc-trailers-only").expect("ca");
    let (cert, key) = ca.valid().expect("leaf");

    let (tcp_res, udp_res) = reserve_colocated_tcp_udp()
        .await
        .expect("colocated tcp/udp");
    let backend_port = tcp_res.port;
    let _tcp_backend =
        spawn_grpc_probe_tcp_backend(tcp_res.into_listener(), cert.clone(), key.clone());

    let h3_backend = ScriptedH3Backend::builder(udp_res.into_socket(), H3TlsConfig::new(cert, key))
        .step(H3Step::AcceptStream)
        .step(H3Step::RespondHeadersEndStream(vec![
            (":status", "200".to_string()),
            ("content-type", "application/grpc".to_string()),
            ("grpc-status", "7".to_string()),
            ("grpc-message", "permission denied".to_string()),
            ("grpc-status-details-bin", "AQID".to_string()),
        ]))
        .step(H3Step::StallFor(Duration::from_secs(1)))
        .spawn()
        .expect("spawn h3 backend");

    let config = file_mode_yaml_for_h3_with_terminal_security(backend_port, remove_terminal);
    let (harness, _ca_pem, _https_port) =
        spawn_h3_harness_with_explicit_https_port_and_config(config, false, Some(1)).await;
    let entry = wait_for_capability_entry(&harness, Duration::from_secs(15))
        .await
        .expect("fetch capability entry")
        .expect("registry populated within timeout");
    assert_eq!(
        entry["plain_http"]["h3"].as_str(),
        Some("supported"),
        "expected native H3 dispatch; entry: {entry:#?}"
    );

    let resp = match h3_grpc_post_with_headers(
        &harness,
        "/api/echo.Echo/Denied",
        grpc_frame(b"ping"),
        &[("x-api-key", "native-h3-chargeback-key-99887766")],
    )
    .await
    {
        Ok(resp) => resp,
        Err(error) => {
            let logs = harness.captured_combined().unwrap_or_default();
            panic!("native H3 Trailers-Only request failed: {error}\n--- logs ---\n{logs}");
        }
    };
    let logs = harness.captured_combined().unwrap_or_default();
    assert_eq!(
        resp.status.as_u16(),
        200,
        "unexpected status; logs:\n{logs}"
    );
    assert!(
        resp.body_bytes.is_empty(),
        "Trailers-Only body must be empty"
    );
    assert_eq!(
        resp.headers
            .get("x-security-policy")
            .and_then(|value| value.to_str().ok()),
        Some("gateway-enforced")
    );
    assert!(
        resp.headers.get("grpc-status").is_none(),
        "native H3 relays terminal metadata on the trailer channel"
    );
    assert_eq!(
        resp.grpc_status(),
        Some(7),
        "trailers: {:#?}",
        resp.trailers
    );
    assert_eq!(resp.grpc_message().as_deref(), Some("permission denied"));
    assert_eq!(
        resp.trailers
            .as_ref()
            .and_then(|trailers| trailers.get("grpc-status-details-bin"))
            .and_then(|value| value.to_str().ok()),
        Some("AQID")
    );

    let logs = harness
        .wait_for_log_contains(
            |logs| {
                logs.lines().any(|line| {
                    serde_json::from_str::<Value>(line).is_ok_and(|entry| {
                        entry["proxy_id"] == "scripted-h3" && entry["grpc_status"] == 7
                    })
                })
            },
            Duration::from_secs(5),
        )
        .await;
    let access_logs: Vec<Value> = logs
        .lines()
        .filter_map(|line| serde_json::from_str::<Value>(line).ok())
        .filter(|entry| entry["proxy_id"] == "scripted-h3")
        .collect();
    assert_eq!(
        access_logs.len(),
        1,
        "native H3 errors_only must emit the status-7 terminal failure; logs:\n{logs}"
    );
    assert_eq!(access_logs[0]["response_status_code"], 200);
    assert_eq!(access_logs[0]["grpc_status"], 7);

    let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    let charges = loop {
        let charges = harness
            .get_admin_json("/charges?format=json")
            .await
            .expect("fetch native H3 chargeback JSON");
        if charges["consumers"]["native-h3-chargeback-user"]["proxies"]["scripted-h3"]["by_status"]
            ["403"]["calls"]
            .as_u64()
            == Some(1)
        {
            break charges;
        }
        assert!(
            tokio::time::Instant::now() < deadline,
            "native H3 chargeback did not settle: {charges:#?}"
        );
        tokio::time::sleep(Duration::from_millis(100)).await;
    };
    let by_status =
        &charges["consumers"]["native-h3-chargeback-user"]["proxies"]["scripted-h3"]["by_status"];
    let denied_charge = by_status["403"]["charges"]
        .as_f64()
        .expect("status 403 charge");
    assert!((denied_charge - 0.007).abs() < 1e-12);
    assert!(
        by_status.get("200").is_none(),
        "terminal gRPC status 7 must not be billed as HTTP 200: {charges:#?}"
    );

    let received = h3_backend.received_requests().await;
    assert!(
        received
            .iter()
            .any(|request| request.method == "POST" && request.path.ends_with("/echo.Echo/Denied")),
        "H3-only backend must receive the proxied request; received: {received:#?}\nlogs:\n{logs}"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore]
async fn h3_native_grpc_trailers_only_resists_hostile_terminal_set() {
    assert_h3_native_grpc_trailers_only_preserves_terminal_metadata(false).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore]
async fn h3_native_grpc_trailers_only_resists_terminal_removal() {
    assert_h3_native_grpc_trailers_only_preserves_terminal_metadata(true).await;
}

// ────────────────────────────────────────────────────────────────────────────
// Server-streaming gRPC over native H3: every DATA frame is relayed in order
// and the terminal `grpc-status` trailer is preserved.
// ────────────────────────────────────────────────────────────────────────────
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore]
async fn h3_native_grpc_server_streaming_preserves_frames_and_trailers() {
    let ca = TestCa::new("phase-h3-grpc-stream").expect("ca");
    let (cert, key) = ca.valid().expect("leaf");

    let (tcp_res, udp_res) = reserve_colocated_tcp_udp()
        .await
        .expect("colocated tcp/udp");
    let backend_port = tcp_res.port;

    let _tcp_backend =
        spawn_grpc_probe_tcp_backend(tcp_res.into_listener(), cert.clone(), key.clone());

    let frame_a = grpc_frame(b"stream-msg-1");
    let frame_b = grpc_frame(b"stream-msg-2");
    let frame_c = grpc_frame(b"stream-msg-3");
    let mut expected_body = Vec::new();
    expected_body.extend_from_slice(&frame_a);
    expected_body.extend_from_slice(&frame_b);
    expected_body.extend_from_slice(&frame_c);

    let h3_backend = ScriptedH3Backend::builder(udp_res.into_socket(), H3TlsConfig::new(cert, key))
        .step(H3Step::AcceptStream)
        .step(H3Step::RespondHeaders(vec![
            (":status", "200".to_string()),
            ("content-type", "application/grpc".to_string()),
        ]))
        .step(H3Step::RespondData(bytes::Bytes::from(frame_a.clone())))
        .step(H3Step::RespondData(bytes::Bytes::from(frame_b.clone())))
        .step(H3Step::RespondData(bytes::Bytes::from(frame_c.clone())))
        .step(H3Step::RespondTrailers(vec![(
            "grpc-status",
            "0".to_string(),
        )]))
        // Keep the connection open after the trailers + FIN so the gateway reads
        // the complete trailered response before the script-end connection drop
        // (see `H3Step::RespondTrailers`). CI can schedule the H3 poll after a
        // short 100ms grace window under shard load.
        .step(H3Step::StallFor(Duration::from_secs(1)))
        .spawn()
        .expect("spawn h3 backend");

    let (harness, _ca_pem, _https_port) =
        spawn_h3_harness_with_explicit_https_port(backend_port, false, Some(1)).await;

    let entry = wait_for_capability_entry(&harness, Duration::from_secs(15))
        .await
        .expect("fetch capability entry")
        .expect("registry populated within timeout");
    assert_eq!(
        entry["plain_http"]["h3"].as_str(),
        Some("supported"),
        "expected h3=supported for native H3 gRPC server-streaming; entry: {entry:#?}"
    );

    let resp = match h3_grpc_post(&harness, "/api/echo.Echo/ServerStream", grpc_frame(b"go")).await
    {
        Ok(resp) => resp,
        Err(e) => {
            let logs = harness.captured_combined().unwrap_or_default();
            panic!("native H3 gRPC server-streaming request failed: {e}\n--- logs ---\n{logs}");
        }
    };

    let logs = harness.captured_combined().unwrap_or_default();
    let received = h3_backend.received_requests().await;
    let backend_errors = h3_backend.step_errors().await;
    assert_eq!(resp.status.as_u16(), 200, "status; --- logs ---\n{logs}");
    assert_eq!(
        resp.trailer("grpc-status"),
        Some("0"),
        "grpc-status trailer must be forwarded after the streamed frames; \
         headers: {:#?}\ntrailers: {:#?}\nbackend requests: {received:#?}\n\
         backend errors: {backend_errors:#?}\n--- logs ---\n{logs}",
        resp.headers,
        resp.trailers
    );
    assert_eq!(
        resp.body_bytes.as_ref(),
        expected_body.as_slice(),
        "all server-streaming gRPC frames must be relayed in order, byte-for-byte"
    );

    assert!(
        received
            .iter()
            .any(|r| r.method == "POST" && r.path.ends_with("/echo.Echo/ServerStream")),
        "H3 backend must have received the proxied gRPC POST (native H3 dispatch); \
         recorded: {received:#?}\n--- logs ---\n{logs}"
    );
}
