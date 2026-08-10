//! Functional coverage for port-aware Gateway API routes (issue #3612).
//!
//! Everything here runs against the **real `ferrum-edge` binary**. The Gateway
//! API listener ports are bound by the gateway's own listener lifecycle — the
//! test only reserves free port numbers and then releases them — so a
//! regression that stops binding those ports fails these tests rather than
//! being papered over by a helper.
//!
//! Covered:
//! - two **same-protocol** listener ports (`:A` and `:B`, both plaintext)
//!   carrying identical `host` + `listen_path`, each reaching only its own
//!   backend, with the global process bind failing closed;
//! - an HTTP listener and an HTTPS listener on **distinct** ports, each
//!   reaching only its own backend on the correct protocol;
//! - SIGHUP reload that adds a listener port and withdraws another;
//! - two **TLS** listener ports with HTTP/3 enabled, served over both TCP and
//!   QUIC, with the QUIC socket following a SIGHUP withdrawal.
//!
//! Run with:
//!   cargo build --bin ferrum-edge
//!   cargo test --test functional_tests -- --ignored functional_port_aware_routes --nocapture

use crate::common::TestGateway;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::task::JoinHandle;
use tokio::time::sleep;

const HOST: &str = "app.example.com";

async fn spawn_backend(identifier: &'static str) -> (u16, JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let handle = tokio::spawn(async move {
        loop {
            if let Ok((mut stream, _)) = listener.accept().await {
                tokio::spawn(async move {
                    let mut buf = vec![0u8; 4096];
                    let _ = stream.read(&mut buf).await.unwrap_or(0);
                    let response = format!(
                        "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nContent-Type: text/plain\r\nConnection: close\r\n\r\n{}",
                        identifier.len(),
                        identifier
                    );
                    let _ = stream.write_all(response.as_bytes()).await;
                    let _ = stream.shutdown().await;
                });
            }
        }
    });
    (port, handle)
}

/// Reserve an ephemeral port number, then release the socket so the gateway
/// binds it itself. The gateway's readiness barrier is what proves it won the
/// race; a lost race shows up as an explicit "never bound" failure below.
async fn reserve_free_port() -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    drop(listener);
    port
}

async fn get_on_port(client: &reqwest::Client, port: u16, path: &str) -> (u16, String) {
    let resp = client
        .get(format!("http://127.0.0.1:{port}{path}"))
        .header("Host", HOST)
        .send()
        .await
        .unwrap_or_else(|e| panic!("HTTP GET to port {port} failed: {e}"));
    let status = resp.status().as_u16();
    let body = resp.text().await.unwrap_or_default();
    (status, body)
}

async fn get_on_tls_port(client: &reqwest::Client, port: u16, path: &str) -> (u16, String) {
    let resp = client
        .get(format!("https://127.0.0.1:{port}{path}"))
        .header("Host", HOST)
        .send()
        .await
        .unwrap_or_else(|e| panic!("HTTPS GET to port {port} failed: {e}"));
    let status = resp.status().as_u16();
    let body = resp.text().await.unwrap_or_default();
    (status, body)
}

/// Poll until the gateway is accepting on `port`, or fail with a clear
/// "never bound" message. The listener lifecycle is asynchronous relative to
/// process readiness, so a bounded poll is correct here — a sleep is not.
async fn wait_until_listening(port: u16, what: &str) {
    let deadline = std::time::Instant::now() + Duration::from_secs(10);
    loop {
        if tokio::net::TcpStream::connect(("127.0.0.1", port))
            .await
            .is_ok()
        {
            return;
        }
        if std::time::Instant::now() >= deadline {
            panic!("gateway never bound {what} on port {port}");
        }
        sleep(Duration::from_millis(100)).await;
    }
}

async fn wait_until_not_listening(port: u16, what: &str) {
    let deadline = std::time::Instant::now() + Duration::from_secs(10);
    loop {
        if tokio::net::TcpStream::connect(("127.0.0.1", port))
            .await
            .is_err()
        {
            return;
        }
        if std::time::Instant::now() >= deadline {
            panic!("gateway never released {what} on port {port}");
        }
        sleep(Duration::from_millis(100)).await;
    }
}

fn plaintext_proxy(id: &str, listen_port: u16, backend_port: u16) -> String {
    format!(
        r#"
  - id: "{id}"
    hosts: ["{HOST}"]
    listen_path: "/api"
    listen_port: {listen_port}
    backend_scheme: http
    backend_host: "127.0.0.1"
    backend_port: {backend_port}
    strip_listen_path: true"#
    )
}

/// The exact case #3612 filed: one hostname and one path, two listeners of the
/// same protocol. Both must be bound by the binary and route independently.
#[ignore]
#[tokio::test(flavor = "multi_thread")]
async fn functional_port_aware_routes_two_same_protocol_listeners() {
    let (backend_a, _ha) = spawn_backend("listener-a").await;
    let (backend_b, _hb) = spawn_backend("listener-b").await;
    let port_a = reserve_free_port().await;
    let port_b = reserve_free_port().await;
    assert_ne!(port_a, port_b);

    let config = format!(
        r#"
version: "1"
proxies:{}{}
consumers: []
plugin_configs: []
"#,
        plaintext_proxy("gw-a", port_a, backend_a),
        plaintext_proxy("gw-b", port_b, backend_b),
    );

    let gateway = TestGateway::builder()
        .mode_file(config)
        .reserve_listener_port(port_a)
        .reserve_listener_port(port_b)
        .log_level("warn")
        .spawn()
        .await
        .expect("start gateway");
    let client = reqwest::Client::new();

    wait_until_listening(port_a, "Gateway listener A").await;
    wait_until_listening(port_b, "Gateway listener B").await;

    let (status_a, body_a) = get_on_port(&client, port_a, "/api/x").await;
    assert_eq!(status_a, 200, "listener A must serve: {body_a}");
    assert_eq!(body_a, "listener-a");

    let (status_b, body_b) = get_on_port(&client, port_b, "/api/x").await;
    assert_eq!(status_b, 200, "listener B must serve: {body_b}");
    assert_eq!(body_b, "listener-b");

    // With two same-protocol listener ports the compatibility remap is off, so
    // the global process bind is not a stand-in for either listener.
    let resp = client
        .get(gateway.proxy_url("/api/x"))
        .header("Host", HOST)
        .send()
        .await
        .expect("global bind answers");
    assert_eq!(
        resp.status().as_u16(),
        404,
        "the global plaintext bind must not guess between two same-protocol listeners"
    );
}

/// HTTP and HTTPS Gateway listeners on distinct ports, each with its own
/// backend. Proves the listener's TLS class — not its port number — decides
/// which frontend serves it, through the real binary.
#[ignore]
#[tokio::test(flavor = "multi_thread")]
async fn functional_port_aware_routes_http_and_https_listeners() {
    let (plain_backend, _hp) = spawn_backend("plain-backend").await;
    let (tls_backend, _ht) = spawn_backend("tls-backend").await;
    let plain_port = reserve_free_port().await;
    let tls_port = reserve_free_port().await;
    assert_ne!(plain_port, tls_port);

    // `http_tls_listen_ports` is namespace-qualified: the entry is the
    // `(namespace, port)` pair the listener was admitted under.
    let config = format!(
        r#"
version: "1"
http_tls_listen_ports:
  - ["ferrum", {tls_port}]
proxies:{}{}
consumers: []
plugin_configs: []
"#,
        plaintext_proxy("gw-plain", plain_port, plain_backend),
        plaintext_proxy("gw-tls", tls_port, tls_backend),
    );

    let gateway = TestGateway::builder()
        .mode_file(config)
        .reserve_listener_port(plain_port)
        .reserve_listener_port(tls_port)
        .log_level("warn")
        .env("FERRUM_FRONTEND_TLS_CERT_PATH", "tests/certs/server.crt")
        .env("FERRUM_FRONTEND_TLS_KEY_PATH", "tests/certs/server.key")
        .spawn()
        .await
        .expect("start gateway");

    wait_until_listening(plain_port, "plaintext Gateway listener").await;
    wait_until_listening(tls_port, "TLS Gateway listener").await;

    let client = reqwest::Client::builder()
        .danger_accept_invalid_certs(true)
        // These helpers connect to the loopback socket while routing by an
        // explicit Host header. HTTP/2 would also send the loopback URI as
        // `:authority`, correctly tripping Ferrum's authority-conflict guard;
        // this test is about listener TLS classification, so keep it on H1.
        .http1_only()
        .build()
        .expect("build TLS client");

    let (status_plain, body_plain) = get_on_port(&client, plain_port, "/api/x").await;
    assert_eq!(status_plain, 200, "HTTP listener must serve: {body_plain}");
    assert_eq!(body_plain, "plain-backend");

    let (status_tls, body_tls) = get_on_tls_port(&client, tls_port, "/api/x").await;
    assert_eq!(status_tls, 200, "HTTPS listener must serve: {body_tls}");
    assert_eq!(body_tls, "tls-backend");

    // Cross-protocol must fail closed. A plaintext request to the TLS
    // listener's socket either fails at the transport (the socket speaks TLS)
    // or is refused — it must never be served by the TLS-scoped route.
    let plaintext_to_tls_listener = client
        .get(format!("http://127.0.0.1:{tls_port}/api/x"))
        .header("Host", HOST)
        .send()
        .await;
    match plaintext_to_tls_listener {
        Err(_) => {}
        Ok(response) => assert_ne!(
            response.status().as_u16(),
            200,
            "a plaintext request must never be served by the TLS listener's route"
        ),
    }

    // The gateway's own plaintext bind is not a Gateway listener. Exactly one
    // plaintext listener port is declared, so the documented single-listener
    // compatibility remap admits it — assert that documented behaviour rather
    // than leaving the surface untested.
    let global = client
        .get(gateway.proxy_url("/api/x"))
        .header("Host", HOST)
        .send()
        .await
        .expect("global plaintext bind answers");
    let status_global = global.status().as_u16();
    let body_global = global.text().await.unwrap_or_default();
    assert_eq!(
        status_global, 200,
        "with one plaintext listener port the global bind remaps onto it: {body_global}"
    );
    assert_eq!(body_global, "plain-backend");
}

/// Reload lifecycle through SIGHUP on the real binary: add a listener port,
/// then withdraw one and prove the withdrawn port stops routing.
#[cfg(unix)]
#[ignore]
#[tokio::test(flavor = "multi_thread")]
async fn functional_port_aware_routes_reload_adds_and_withdraws_listeners() {
    let (backend_a, _ha) = spawn_backend("listener-a").await;
    let (backend_b, _hb) = spawn_backend("listener-b").await;
    let port_a = reserve_free_port().await;
    let port_b = reserve_free_port().await;
    assert_ne!(port_a, port_b);

    let initial = format!(
        r#"
version: "1"
proxies:{}
consumers: []
plugin_configs: []
"#,
        plaintext_proxy("gw-a", port_a, backend_a),
    );

    let gateway = TestGateway::builder()
        .mode_file(initial)
        .reserve_listener_port(port_a)
        .reserve_listener_port(port_b)
        .log_level("warn")
        .spawn()
        .await
        .expect("start gateway");
    let client = reqwest::Client::new();

    wait_until_listening(port_a, "Gateway listener A").await;
    assert_eq!(get_on_port(&client, port_a, "/api/x").await.1, "listener-a");
    assert!(
        tokio::net::TcpStream::connect(("127.0.0.1", port_b))
            .await
            .is_err(),
        "an undeclared listener port must not be bound"
    );

    let config_path = gateway
        .config_path
        .as_ref()
        .expect("file-mode harness must populate config_path");

    // ── Reload 1: add listener B ─────────────────────────────────────────
    let with_both = format!(
        r#"
version: "1"
proxies:{}{}
consumers: []
plugin_configs: []
"#,
        plaintext_proxy("gw-a", port_a, backend_a),
        plaintext_proxy("gw-b", port_b, backend_b),
    );
    std::fs::write(config_path, with_both).expect("rewrite config");
    sighup(&gateway);
    wait_until_listening(port_b, "added Gateway listener B").await;

    assert_eq!(get_on_port(&client, port_b, "/api/x").await.1, "listener-b");
    assert_eq!(
        get_on_port(&client, port_a, "/api/x").await.1,
        "listener-a",
        "adding a listener must not disturb the existing one"
    );

    // ── Reload 2: withdraw listener A ────────────────────────────────────
    let only_b = format!(
        r#"
version: "1"
proxies:{}
consumers: []
plugin_configs: []
"#,
        plaintext_proxy("gw-b", port_b, backend_b),
    );
    std::fs::write(config_path, only_b).expect("rewrite config");
    sighup(&gateway);
    wait_until_not_listening(port_a, "withdrawn Gateway listener A").await;

    assert_eq!(
        get_on_port(&client, port_b, "/api/x").await.1,
        "listener-b",
        "the surviving sibling listener keeps serving across the withdrawal"
    );
}

#[cfg(unix)]
fn sighup(gateway: &TestGateway) {
    let pid = gateway.pid().expect("gateway still running");
    let _ = std::process::Command::new("kill")
        .args(["-HUP", &pid.to_string()])
        .output();
}

/// Two **TLS** Gateway listener ports with HTTP/3 enabled.
///
/// The single process-global QUIC socket cannot serve either of them (the
/// single-listener protocol remap is off with two same-class ports), so each
/// TLS listener port must get its own QUIC socket. This drives the real binary
/// over HTTP/1.1-or-2 **and** HTTP/3 on both ports, and then withdraws one
/// listener by SIGHUP to prove the QUIC socket follows the lifecycle.
///
/// The routes are keyed on the `127.0.0.1` authority the clients actually send,
/// so no `Host` header is added: HTTP/2 and HTTP/3 reject a `Host` that
/// disagrees with `:authority`, and the point here is the listener port, not
/// host matching.
#[cfg(unix)]
#[ignore]
#[tokio::test(flavor = "multi_thread")]
async fn functional_port_aware_routes_two_tls_listeners_serve_http3() {
    use crate::scaffolding::clients::{GetOptions, Http3Client};

    let (backend_a, _ha) = spawn_backend("tls-a").await;
    let (backend_b, _hb) = spawn_backend("tls-b").await;
    let port_a = reserve_free_port().await;
    let port_b = reserve_free_port().await;
    assert_ne!(port_a, port_b);

    let both = format!(
        r#"
version: "1"
http_tls_listen_ports:
  - ["ferrum", {port_a}]
  - ["ferrum", {port_b}]
proxies:{}{}
consumers: []
plugin_configs: []
"#,
        loopback_proxy("gw-a", port_a, backend_a),
        loopback_proxy("gw-b", port_b, backend_b),
    );

    let gateway = TestGateway::builder()
        .mode_file(both)
        .reserve_listener_port(port_a)
        .reserve_listener_port(port_b)
        .log_level("warn")
        .env("FERRUM_ENABLE_HTTP3", "true")
        .env("FERRUM_FRONTEND_TLS_CERT_PATH", "tests/certs/server.crt")
        .env("FERRUM_FRONTEND_TLS_KEY_PATH", "tests/certs/server.key")
        .spawn()
        .await
        .expect("start gateway");

    wait_until_listening(port_a, "TLS Gateway listener A").await;
    wait_until_listening(port_b, "TLS Gateway listener B").await;

    let client = reqwest::Client::builder()
        .danger_accept_invalid_certs(true)
        .build()
        .expect("build TLS client");
    assert_eq!(tls_body(&client, port_a, "/api/x").await, "tls-a");
    assert_eq!(tls_body(&client, port_b, "/api/x").await, "tls-b");

    // HTTP/3 on BOTH TLS listener ports — the case a single global UDP socket
    // cannot cover.
    assert_eq!(h3_body(port_a, "/api/x").await, "tls-a");
    assert_eq!(h3_body(port_b, "/api/x").await, "tls-b");

    // ── Withdraw listener B ──────────────────────────────────────────────
    let config_path = gateway
        .config_path
        .as_ref()
        .expect("file-mode harness must populate config_path");
    let only_a = format!(
        r#"
version: "1"
http_tls_listen_ports:
  - ["ferrum", {port_a}]
proxies:{}
consumers: []
plugin_configs: []
"#,
        loopback_proxy("gw-a", port_a, backend_a),
    );
    std::fs::write(config_path, only_a).expect("rewrite config");
    sighup(&gateway);
    wait_until_not_listening(port_b, "withdrawn TLS Gateway listener B").await;

    // The withdrawn port's QUIC socket goes with it; the survivor keeps
    // serving HTTP/3.
    let deadline = std::time::Instant::now() + Duration::from_secs(10);
    loop {
        let client = Http3Client::insecure().expect("H3 client");
        let attempt = client
            .get_with_options(
                &format!("https://127.0.0.1:{port_b}/api/x"),
                GetOptions::default(),
            )
            .await;
        if attempt.is_err() {
            break;
        }
        assert!(
            std::time::Instant::now() < deadline,
            "the withdrawn TLS listener kept serving HTTP/3"
        );
        sleep(Duration::from_millis(100)).await;
    }
    assert_eq!(h3_body(port_a, "/api/x").await, "tls-a");
}

/// A route keyed on the loopback authority the test clients send.
#[cfg(unix)]
fn loopback_proxy(id: &str, listen_port: u16, backend_port: u16) -> String {
    format!(
        r#"
  - id: "{id}"
    hosts: ["127.0.0.1"]
    listen_path: "/api"
    listen_port: {listen_port}
    backend_scheme: http
    backend_host: "127.0.0.1"
    backend_port: {backend_port}
    strip_listen_path: true"#
    )
}

#[cfg(unix)]
async fn tls_body(client: &reqwest::Client, port: u16, path: &str) -> String {
    let response = client
        .get(format!("https://127.0.0.1:{port}{path}"))
        .send()
        .await
        .unwrap_or_else(|e| panic!("HTTPS GET to port {port} failed: {e}"));
    assert_eq!(
        response.status().as_u16(),
        200,
        "TLS Gateway listener port {port} must serve"
    );
    response.text().await.unwrap_or_default()
}

/// One HTTP/3 GET against a Gateway listener port, retried until the QUIC
/// socket is accepting (listener bind is asynchronous relative to readiness).
#[cfg(unix)]
async fn h3_body(port: u16, path: &str) -> String {
    use crate::scaffolding::clients::{GetOptions, Http3Client};

    let url = format!("https://127.0.0.1:{port}{path}");
    let deadline = std::time::Instant::now() + Duration::from_secs(15);
    loop {
        let client = Http3Client::insecure().expect("H3 client");
        match client.get_with_options(&url, GetOptions::default()).await {
            Ok(response) => {
                assert_eq!(
                    response.status.as_u16(),
                    200,
                    "HTTP/3 on Gateway listener port {port} must serve"
                );
                return String::from_utf8_lossy(&response.body_bytes).to_string();
            }
            Err(error) => {
                assert!(
                    std::time::Instant::now() < deadline,
                    "HTTP/3 never reached Gateway listener port {port}: {error}"
                );
                sleep(Duration::from_millis(150)).await;
            }
        }
    }
}
