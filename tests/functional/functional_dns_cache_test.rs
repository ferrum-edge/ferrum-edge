//! Functional test for DNS cache behavior (P2-2).
//!
//! Exercises the shared `DnsCache` layer in `src/dns/mod.rs` via the reqwest
//! backend path and verifies:
//! - Hostname-based backends (`localhost`) resolve correctly and proxy traffic
//! - Unresolvable hostnames return a 5xx without crashing the gateway
//! - Per-proxy `dns_cache_ttl_seconds` is accepted and does not break startup
//! - `FERRUM_DNS_MIN_TTL_SECONDS` and `FERRUM_DNS_REFRESH_THRESHOLD_PERCENT`
//!   env vars are accepted at startup without breaking the gateway
//!
//! We intentionally do NOT stand up a custom DNS stub server — writing a
//! correct UDP DNS responder in-test would be non-trivial and brittle across
//! platforms. Instead, we rely on `localhost` (always in /etc/hosts) for the
//! positive path and an `.invalid` TLD (RFC 6761 guarantees NXDOMAIN) for the
//! negative path. This gives realistic end-to-end coverage of the DNS cache
//! wrapping `reqwest::Client` without requiring network access.
//!
//! TODO (future): Implement a UDP DNS stub server using `tokio::net::UdpSocket`
//! that returns one IP before TTL expiry and a different IP after. Combined
//! with `FERRUM_DNS_RESOLVER_ADDRESS=127.0.0.1:<stub_port>`, this would prove
//! that TTL-based refresh and per-proxy `dns_cache_ttl_seconds` actually honor
//! the configured values. See `src/dns/mod.rs` for the refresh + SWR flow.
//!
//! Run with:
//!   cargo build --bin ferrum-edge
//!   cargo test --test functional_tests -- --ignored functional_dns_cache --nocapture

use std::time::Duration;
use tempfile::TempDir;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::time::sleep;

// ============================================================================
// Identified echo backend
// ============================================================================

/// Start an HTTP echo server on a pre-bound listener that responds with a
/// fixed identifier in the body. Used to prove WHICH backend served a request.
async fn start_identified_echo_server(listener: TcpListener, identifier: String) {
    loop {
        if let Ok((mut stream, _)) = listener.accept().await {
            let body = identifier.clone();
            tokio::spawn(async move {
                let mut buf = vec![0u8; 4096];
                let _n = stream.read(&mut buf).await.unwrap_or(0);

                let response = format!(
                    "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nContent-Type: text/plain\r\nConnection: close\r\n\r\n{}",
                    body.len(),
                    body
                );
                let _ = stream.write_all(response.as_bytes()).await;
                let _ = stream.shutdown().await;
            });
        }
    }
}

/// Bind `127.0.0.1:0`, spawn the identified echo server, return `(port, handle)`.
async fn spawn_backend(identifier: &str) -> (u16, tokio::task::JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let id = identifier.to_string();
    let handle = tokio::spawn(async move {
        start_identified_echo_server(listener, id).await;
    });
    (port, handle)
}

// ============================================================================
// Gateway helpers
// ============================================================================

fn gateway_binary_path() -> &'static str {
    if std::path::Path::new("./target/debug/ferrum-edge").exists() {
        "./target/debug/ferrum-edge"
    } else if std::path::Path::new("./target/release/ferrum-edge").exists() {
        "./target/release/ferrum-edge"
    } else {
        panic!("ferrum-edge binary not found. Run `cargo build --bin ferrum-edge` first.");
    }
}

fn start_gateway_in_file_mode(
    config_path: &str,
    http_port: u16,
    admin_port: u16,
    extra_env: &[(&str, &str)],
) -> std::process::Child {
    let binary_path = gateway_binary_path();

    let mut cmd = std::process::Command::new(binary_path);
    cmd.env("FERRUM_MODE", "file")
        .env("FERRUM_FILE_CONFIG_PATH", config_path)
        .env("FERRUM_PROXY_HTTP_PORT", http_port.to_string())
        .env("FERRUM_ADMIN_HTTP_PORT", admin_port.to_string())
        .env("FERRUM_LOG_LEVEL", "warn");

    for (k, v) in extra_env {
        cmd.env(k, v);
    }

    cmd.stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()
        .expect("Failed to start gateway binary")
}

async fn wait_for_gateway(admin_port: u16) -> bool {
    let client = reqwest::Client::new();
    let health_url = format!("http://127.0.0.1:{}/health", admin_port);

    for _ in 0..60 {
        if let Ok(resp) = client.get(&health_url).send().await
            && resp.status().is_success()
        {
            return true;
        }
        sleep(Duration::from_millis(250)).await;
    }
    false
}

async fn ephemeral_port() -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    drop(listener);
    port
}

/// Start the gateway with retry to handle ephemeral port races.
/// Fresh ports per attempt; gateway is killed before retry.
async fn start_gateway_with_retry(
    config_path: &str,
    extra_env: &[(&str, &str)],
) -> (std::process::Child, u16, u16) {
    const MAX_ATTEMPTS: u32 = 3;
    for attempt in 1..=MAX_ATTEMPTS {
        let proxy_port = ephemeral_port().await;
        let admin_port = ephemeral_port().await;

        let mut child = start_gateway_in_file_mode(config_path, proxy_port, admin_port, extra_env);

        if wait_for_gateway(admin_port).await {
            return (child, proxy_port, admin_port);
        }

        eprintln!(
            "Gateway startup attempt {}/{} failed (proxy_port={}, admin_port={})",
            attempt, MAX_ATTEMPTS, proxy_port, admin_port
        );
        let _ = child.kill();
        let _ = child.wait();

        if attempt < MAX_ATTEMPTS {
            sleep(Duration::from_secs(1)).await;
        }
    }
    panic!("Gateway did not start after {} attempts", MAX_ATTEMPTS);
}

async fn get_with_body(client: &reqwest::Client, url: &str) -> (u16, String) {
    let resp = client
        .get(url)
        .send()
        .await
        .expect("HTTP GET should complete (even on backend failure)");
    let status = resp.status().as_u16();
    let body = resp.text().await.unwrap_or_default();
    (status, body)
}

// ============================================================================
// Test 1: Hostname-based backend via `localhost`
// ============================================================================
//
// Proves the DNS cache path works end-to-end for a real hostname. `localhost`
// is guaranteed to resolve to 127.0.0.1 (RFC 6761) via /etc/hosts, so this
// test does not depend on external DNS. The DnsCacheResolver wrapping the
// reqwest client must pre-warm + cache the lookup for the backend host.

#[ignore]
#[tokio::test(flavor = "multi_thread")]
async fn functional_dns_cache_localhost_hostname() {
    let temp_dir = TempDir::new().expect("Failed to create temp directory");

    let (backend_port, h_backend) = spawn_backend("backend-localhost").await;
    sleep(Duration::from_millis(200)).await;

    let config_path = temp_dir.path().join("config.yaml");
    let config_content = format!(
        r#"
proxies:
  - id: "localhost-proxy"
    listen_path: "/api"
    backend_protocol: http
    backend_host: "localhost"
    backend_port: {backend_port}
    strip_listen_path: false

consumers: []
plugin_configs: []
"#
    );
    std::fs::write(&config_path, config_content).expect("write config");

    let (mut gw, proxy_port, _admin_port) =
        start_gateway_with_retry(config_path.to_str().unwrap(), &[]).await;
    let client = reqwest::Client::new();

    // First request: DNS lookup happens (or was pre-warmed at startup)
    let (status, body) =
        get_with_body(&client, &format!("http://127.0.0.1:{proxy_port}/api/v1")).await;
    assert_eq!(status, 200, "localhost hostname must resolve and proxy");
    assert_eq!(body, "backend-localhost", "request must reach backend");

    // Second request: should hit the DNS cache (cache serves the same IP)
    let (status, body) =
        get_with_body(&client, &format!("http://127.0.0.1:{proxy_port}/api/v2")).await;
    assert_eq!(status, 200, "second request via DNS cache must succeed");
    assert_eq!(body, "backend-localhost", "cached resolution must be valid");

    // Third request: proves repeated cache hits work
    let (status, body) =
        get_with_body(&client, &format!("http://127.0.0.1:{proxy_port}/api/v3")).await;
    assert_eq!(status, 200);
    assert_eq!(body, "backend-localhost");

    let _ = gw.kill();
    let _ = gw.wait();
    h_backend.abort();
}

// ============================================================================
// Test 2: Unresolvable hostname returns 5xx without crashing
// ============================================================================
//
// RFC 6761 guarantees that `.invalid` is NXDOMAIN. A proxy configured to use
// such a backend must return a 5xx (502/503/504) and — critically — other
// proxies on the same gateway must continue serving normally. This exercises
// the "failed resolution" path in `src/dns/mod.rs`, which caches negative
// responses via `FERRUM_DNS_ERROR_TTL` and continues to serve other routes.

#[ignore]
#[tokio::test(flavor = "multi_thread")]
async fn functional_dns_cache_unresolvable_hostname_is_isolated() {
    let temp_dir = TempDir::new().expect("Failed to create temp directory");

    let (good_port, h_good) = spawn_backend("backend-good").await;
    sleep(Duration::from_millis(200)).await;

    let config_path = temp_dir.path().join("config.yaml");
    let config_content = format!(
        r#"
proxies:
  - id: "broken-dns-proxy"
    listen_path: "/broken"
    backend_protocol: http
    backend_host: "this-host-does-not-exist-k5k5k5k5k5.invalid"
    backend_port: 80
    strip_listen_path: false

  - id: "good-proxy"
    listen_path: "/good"
    backend_protocol: http
    backend_host: "127.0.0.1"
    backend_port: {good_port}
    strip_listen_path: false

consumers: []
plugin_configs: []
"#
    );
    std::fs::write(&config_path, config_content).expect("write config");

    let (mut gw, proxy_port, _admin_port) =
        start_gateway_with_retry(config_path.to_str().unwrap(), &[]).await;
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(10))
        .build()
        .unwrap();

    // Broken-DNS proxy should return a 5xx, NOT crash the gateway.
    let (status, _body) =
        get_with_body(&client, &format!("http://127.0.0.1:{proxy_port}/broken")).await;
    assert!(
        (500..=599).contains(&status),
        "unresolvable backend must return 5xx, got {status}"
    );

    // Good proxy must still serve normally — proves DNS failure is isolated
    // to the affected proxy and does not poison the shared cache for others.
    let (status, body) =
        get_with_body(&client, &format!("http://127.0.0.1:{proxy_port}/good")).await;
    assert_eq!(
        status, 200,
        "good proxy must be unaffected by failed DNS on another proxy"
    );
    assert_eq!(body, "backend-good");

    // Request the broken route again — gateway must still be healthy.
    let (status, _body) =
        get_with_body(&client, &format!("http://127.0.0.1:{proxy_port}/broken")).await;
    assert!(
        (500..=599).contains(&status),
        "repeat request to broken backend must still return 5xx, got {status}"
    );

    // Good proxy STILL works after second broken request.
    let (status, body) =
        get_with_body(&client, &format!("http://127.0.0.1:{proxy_port}/good")).await;
    assert_eq!(status, 200, "good proxy still works after broken retries");
    assert_eq!(body, "backend-good");

    let _ = gw.kill();
    let _ = gw.wait();
    h_good.abort();
}

// ============================================================================
// Test 3: Per-proxy `dns_cache_ttl_seconds` field is accepted
// ============================================================================
//
// The `Proxy.dns_cache_ttl_seconds` field overrides the global TTL and native
// record TTL for a specific proxy. This test proves the config parser accepts
// the field and the gateway starts + routes correctly when it is set. It does
// NOT prove the value is actually honored (that would require a DNS stub) but
// it guards against regressions in deserialization and validation.

#[ignore]
#[tokio::test(flavor = "multi_thread")]
async fn functional_dns_cache_per_proxy_ttl_override_accepted() {
    let temp_dir = TempDir::new().expect("Failed to create temp directory");

    let (backend_port, h_backend) = spawn_backend("backend-per-proxy-ttl").await;
    sleep(Duration::from_millis(200)).await;

    let config_path = temp_dir.path().join("config.yaml");
    let config_content = format!(
        r#"
proxies:
  - id: "ttl-override-proxy"
    listen_path: "/ttl"
    backend_protocol: http
    backend_host: "localhost"
    backend_port: {backend_port}
    dns_cache_ttl_seconds: 5
    strip_listen_path: false

consumers: []
plugin_configs: []
"#
    );
    std::fs::write(&config_path, config_content).expect("write config");

    let (mut gw, proxy_port, admin_port) =
        start_gateway_with_retry(config_path.to_str().unwrap(), &[]).await;
    let client = reqwest::Client::new();

    // Gateway must have started successfully (already verified by wait_for_gateway).
    let health_url = format!("http://127.0.0.1:{admin_port}/health");
    let resp = client.get(&health_url).send().await.unwrap();
    assert!(resp.status().is_success(), "health should remain green");

    // Proxy must route correctly even with the custom TTL override.
    let (status, body) =
        get_with_body(&client, &format!("http://127.0.0.1:{proxy_port}/ttl/hello")).await;
    assert_eq!(
        status, 200,
        "proxy with dns_cache_ttl_seconds override must still route"
    );
    assert_eq!(body, "backend-per-proxy-ttl");

    let _ = gw.kill();
    let _ = gw.wait();
    h_backend.abort();
}

// ============================================================================
// Test 4: DNS cache env vars accepted at startup
// ============================================================================
//
// Proves `FERRUM_DNS_MIN_TTL_SECONDS`, `FERRUM_DNS_REFRESH_THRESHOLD_PERCENT`,
// and `FERRUM_DNS_ERROR_TTL` are parsed correctly and do not break the gateway.
// Regression guard for env-var parsing in `src/config/env_config.rs`.

#[ignore]
#[tokio::test(flavor = "multi_thread")]
async fn functional_dns_cache_env_vars_accepted() {
    let temp_dir = TempDir::new().expect("Failed to create temp directory");

    let (backend_port, h_backend) = spawn_backend("backend-env-tuning").await;
    sleep(Duration::from_millis(200)).await;

    let config_path = temp_dir.path().join("config.yaml");
    let config_content = format!(
        r#"
proxies:
  - id: "env-tuned-proxy"
    listen_path: "/env"
    backend_protocol: http
    backend_host: "localhost"
    backend_port: {backend_port}
    strip_listen_path: false

consumers: []
plugin_configs: []
"#
    );
    std::fs::write(&config_path, config_content).expect("write config");

    let extra_env: Vec<(&str, &str)> = vec![
        ("FERRUM_DNS_MIN_TTL_SECONDS", "3"),
        ("FERRUM_DNS_REFRESH_THRESHOLD_PERCENT", "80"),
        ("FERRUM_DNS_ERROR_TTL", "2"),
        ("FERRUM_DNS_STALE_TTL", "60"),
    ];

    let (mut gw, proxy_port, _admin_port) =
        start_gateway_with_retry(config_path.to_str().unwrap(), &extra_env).await;
    let client = reqwest::Client::new();

    let (status, body) =
        get_with_body(&client, &format!("http://127.0.0.1:{proxy_port}/env/ping")).await;
    assert_eq!(
        status, 200,
        "gateway must route with DNS env tuning applied"
    );
    assert_eq!(body, "backend-env-tuning");

    // Make several rapid requests; the cache must not thrash with a low min TTL.
    for i in 0..5 {
        let (status, body) = get_with_body(
            &client,
            &format!("http://127.0.0.1:{proxy_port}/env/iter{i}"),
        )
        .await;
        assert_eq!(status, 200, "iteration {i} must still hit backend");
        assert_eq!(body, "backend-env-tuning");
    }

    let _ = gw.kill();
    let _ = gw.wait();
    h_backend.abort();
}
