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
//! Run with:
//!   cargo build --bin ferrum-edge
//!   cargo test --test functional_tests -- --ignored functional_dns_cache --nocapture

use crate::common::TestGateway;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::task::JoinHandle;
use tokio::time::sleep;

// ============================================================================
// Plain-text identified backend (specific to these DNS-cache tests — asserts
// match on an exact string identifier in the response body, which does NOT
// match the JSON shape of `spawn_http_identifying` from echo_servers.rs).
// Listener is held inside the spawned task to avoid the bind-drop-rebind race.
// ============================================================================

async fn spawn_backend(identifier: &'static str) -> (u16, JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let handle = tokio::spawn(async move {
        loop {
            if let Ok((mut stream, _)) = listener.accept().await {
                tokio::spawn(async move {
                    let mut buf = vec![0u8; 4096];
                    let _n = stream.read(&mut buf).await.unwrap_or(0);

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

async fn get_with_body(client: &reqwest::Client, url: String) -> (u16, String) {
    let resp = client
        .get(&url)
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

#[ignore]
#[tokio::test(flavor = "multi_thread")]
async fn functional_dns_cache_localhost_hostname() {
    let (backend_port, h_backend) = spawn_backend("backend-localhost").await;

    let config = format!(
        r#"
proxies:
  - id: "localhost-proxy"
    listen_path: "/api"
    backend_scheme: http
    backend_host: "localhost"
    backend_port: {backend_port}
    strip_listen_path: false

consumers: []
plugin_configs: []
"#
    );

    let gw = TestGateway::builder()
        .mode_file(config)
        .log_level("warn")
        .spawn()
        .await
        .expect("start gateway");
    let client = reqwest::Client::new();

    // First request: DNS lookup happens (or was pre-warmed at startup)
    let (status, body) = get_with_body(&client, gw.proxy_url("/api/v1")).await;
    assert_eq!(status, 200, "localhost hostname must resolve and proxy");
    assert_eq!(body, "backend-localhost", "request must reach backend");

    // Second request: should hit the DNS cache
    let (status, body) = get_with_body(&client, gw.proxy_url("/api/v2")).await;
    assert_eq!(status, 200, "second request via DNS cache must succeed");
    assert_eq!(body, "backend-localhost", "cached resolution must be valid");

    // Third request: proves repeated cache hits work
    let (status, body) = get_with_body(&client, gw.proxy_url("/api/v3")).await;
    assert_eq!(status, 200);
    assert_eq!(body, "backend-localhost");

    h_backend.abort();
}

// ============================================================================
// Test 2: Unresolvable hostname returns 5xx without crashing
// ============================================================================

#[ignore]
#[tokio::test(flavor = "multi_thread")]
async fn functional_dns_cache_unresolvable_hostname_is_isolated() {
    let (good_port, h_good) = spawn_backend("backend-good").await;

    let config = format!(
        r#"
proxies:
  - id: "broken-dns-proxy"
    listen_path: "/broken"
    backend_scheme: http
    backend_host: "this-host-does-not-exist-k5k5k5k5k5.invalid"
    backend_port: 80
    strip_listen_path: false

  - id: "good-proxy"
    listen_path: "/good"
    backend_scheme: http
    backend_host: "127.0.0.1"
    backend_port: {good_port}
    strip_listen_path: false

consumers: []
plugin_configs: []
"#
    );

    let gw = TestGateway::builder()
        .mode_file(config)
        .log_level("warn")
        .spawn()
        .await
        .expect("start gateway");
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(10))
        .build()
        .unwrap();

    // Broken-DNS proxy should return a 5xx, NOT crash the gateway.
    let (status, _body) = get_with_body(&client, gw.proxy_url("/broken")).await;
    assert!(
        (500..=599).contains(&status),
        "unresolvable backend must return 5xx, got {status}"
    );

    // Good proxy must still serve normally — proves DNS failure is isolated
    // to the affected proxy and does not poison the shared cache for others.
    let (status, body) = get_with_body(&client, gw.proxy_url("/good")).await;
    assert_eq!(
        status, 200,
        "good proxy must be unaffected by failed DNS on another proxy"
    );
    assert_eq!(body, "backend-good");

    // Request the broken route again — gateway must still be healthy.
    let (status, _body) = get_with_body(&client, gw.proxy_url("/broken")).await;
    assert!(
        (500..=599).contains(&status),
        "repeat request to broken backend must still return 5xx, got {status}"
    );

    // Good proxy STILL works after second broken request.
    let (status, body) = get_with_body(&client, gw.proxy_url("/good")).await;
    assert_eq!(status, 200, "good proxy still works after broken retries");
    assert_eq!(body, "backend-good");

    h_good.abort();
}

// ============================================================================
// Test 3: Per-proxy `dns_cache_ttl_seconds` field is accepted
// ============================================================================

#[ignore]
#[tokio::test(flavor = "multi_thread")]
async fn functional_dns_cache_per_proxy_ttl_override_accepted() {
    let (backend_port, h_backend) = spawn_backend("backend-per-proxy-ttl").await;

    let config = format!(
        r#"
proxies:
  - id: "ttl-override-proxy"
    listen_path: "/ttl"
    backend_scheme: http
    backend_host: "localhost"
    backend_port: {backend_port}
    dns_cache_ttl_seconds: 5
    strip_listen_path: false

consumers: []
plugin_configs: []
"#
    );

    let gw = TestGateway::builder()
        .mode_file(config)
        .log_level("warn")
        .spawn()
        .await
        .expect("start gateway");
    let client = reqwest::Client::new();

    // Gateway must have started successfully (already verified by spawn).
    let resp = client.get(gw.admin_url("/health")).send().await.unwrap();
    assert!(resp.status().is_success(), "health should remain green");

    // Proxy must route correctly even with the custom TTL override.
    let (status, body) = get_with_body(&client, gw.proxy_url("/ttl/hello")).await;
    assert_eq!(
        status, 200,
        "proxy with dns_cache_ttl_seconds override must still route"
    );
    assert_eq!(body, "backend-per-proxy-ttl");

    // Wait at least the TTL + small margin so the refresh task has a chance
    // to re-resolve, then verify routing still works.
    sleep(Duration::from_secs(6)).await;
    let (status, body) = get_with_body(&client, gw.proxy_url("/ttl/again")).await;
    assert_eq!(status, 200, "proxy must still route after TTL window");
    assert_eq!(body, "backend-per-proxy-ttl");

    h_backend.abort();
}

// ============================================================================
// Test 4: DNS cache env vars accepted at startup
// ============================================================================

#[ignore]
#[tokio::test(flavor = "multi_thread")]
async fn functional_dns_cache_env_vars_accepted() {
    let (backend_port, h_backend) = spawn_backend("backend-env-tuning").await;

    let config = format!(
        r#"
proxies:
  - id: "env-tuned-proxy"
    listen_path: "/env"
    backend_scheme: http
    backend_host: "localhost"
    backend_port: {backend_port}
    strip_listen_path: false

consumers: []
plugin_configs: []
"#
    );

    let gw = TestGateway::builder()
        .mode_file(config)
        .log_level("warn")
        .env("FERRUM_DNS_MIN_TTL_SECONDS", "3")
        .env("FERRUM_DNS_REFRESH_THRESHOLD_PERCENT", "80")
        .env("FERRUM_DNS_ERROR_TTL", "2")
        .env("FERRUM_DNS_STALE_TTL", "60")
        .spawn()
        .await
        .expect("start gateway");
    let client = reqwest::Client::new();

    let (status, body) = get_with_body(&client, gw.proxy_url("/env/ping")).await;
    assert_eq!(
        status, 200,
        "gateway must route with DNS env tuning applied"
    );
    assert_eq!(body, "backend-env-tuning");

    // Make several rapid requests; the cache must not thrash with a low min TTL.
    for i in 0..5 {
        let (status, body) = get_with_body(&client, gw.proxy_url(&format!("/env/iter{i}"))).await;
        assert_eq!(status, 200, "iteration {i} must still hit backend");
        assert_eq!(body, "backend-env-tuning");
    }

    h_backend.abort();
}
