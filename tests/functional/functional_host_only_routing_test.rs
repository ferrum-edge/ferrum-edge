//! Functional test for host-only routing — HTTP-family proxies that route
//! purely on `hosts` with no `listen_path`.
//!
//! Exercises the new host-only tier in `src/router_cache.rs` and the updated
//! validation rules in `src/config/types.rs`:
//!
//! - Host-only proxy matches any path under its hosts.
//! - Host-only proxy + path-carrying proxy on the same host: path wins when
//!   it matches; host-only is fallback for non-matching paths.
//! - Two host-only proxies on disjoint hosts coexist.
//! - HTTP proxy with neither `hosts` nor `listen_path` is rejected at admin API.
//! - Stream proxy with a populated `listen_path` is rejected at admin API.
//! - Duplicate host-only on the same host is rejected (409).
//!
//! Run with:
//!   cargo build --bin ferrum-edge
//!   cargo test --test functional_tests -- --ignored functional_host_only_routing --nocapture

use crate::common::TestGateway;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::task::JoinHandle;

// ============================================================================
// Plain-text identified backend (these tests check for exact string bodies,
// which does not match the JSON shape of spawn_http_identifying).
// Listener owned by the spawned task.
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

async fn ephemeral_port() -> u16 {
    let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let p = l.local_addr().unwrap().port();
    drop(l);
    p
}

async fn get_with_host_header(client: &reqwest::Client, url: String, host: &str) -> (u16, String) {
    let resp = client
        .get(&url)
        .header("Host", host)
        .send()
        .await
        .expect("HTTP GET should complete");
    let status = resp.status().as_u16();
    let body = resp.text().await.unwrap_or_default();
    (status, body)
}

// ============================================================================
// Test 1: Host-only proxy routes ANY path under the matching host
// ============================================================================

#[ignore]
#[tokio::test(flavor = "multi_thread")]
async fn functional_host_only_routing_matches_any_path() {
    let (port_a, _h_a) = spawn_backend("backend-a").await;

    let config = format!(
        r#"
proxies:
  - id: "host-only-a"
    hosts: ["a.example.com"]
    backend_scheme: http
    backend_host: "127.0.0.1"
    backend_port: {port_a}
    strip_listen_path: true

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

    // Every path under the host hits backend-a
    for path in ["/", "/api", "/api/v1/users", "/nested/deeply/here"] {
        let (status, body) =
            get_with_host_header(&client, gw.proxy_url(path), "a.example.com").await;
        assert_eq!(status, 200, "host-only proxy should serve {}", path);
        assert_eq!(body, "backend-a", "path {} should route to backend-a", path);
    }

    // A different host (no match anywhere) returns 404
    let (status, _) = get_with_host_header(&client, gw.proxy_url("/api"), "other.host").await;
    assert_eq!(
        status, 404,
        "unmatched host should not route to the host-only proxy"
    );
}

// ============================================================================
// Test 2: Host-only + path-carrying proxy on the same host
// ============================================================================
//
// Within an exact-host tier, matching order is: prefix path → regex path →
// host-only fallback. A request whose path matches the path-carrying proxy
// goes there; a request with a different path falls through to host-only.

#[ignore]
#[tokio::test(flavor = "multi_thread")]
async fn functional_host_only_is_fallback_after_path_match() {
    let (port_api, _h_api) = spawn_backend("backend-api").await;
    let (port_fallback, _h_fallback) = spawn_backend("backend-fallback").await;

    let config = format!(
        r#"
proxies:
  - id: "path-api"
    hosts: ["shared.example.com"]
    listen_path: "/api"
    backend_scheme: http
    backend_host: "127.0.0.1"
    backend_port: {port_api}
    strip_listen_path: false

  - id: "host-only-fallback"
    hosts: ["shared.example.com"]
    backend_scheme: http
    backend_host: "127.0.0.1"
    backend_port: {port_fallback}
    strip_listen_path: true

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

    // /api/* goes to the path-carrying proxy
    let (status, body) =
        get_with_host_header(&client, gw.proxy_url("/api/v1"), "shared.example.com").await;
    assert_eq!(status, 200);
    assert_eq!(
        body, "backend-api",
        "matching path should win over host-only fallback"
    );

    // Other paths fall through to host-only
    let (status, body) =
        get_with_host_header(&client, gw.proxy_url("/other"), "shared.example.com").await;
    assert_eq!(status, 200);
    assert_eq!(
        body, "backend-fallback",
        "non-matching path should fall through to host-only fallback"
    );
}

// ============================================================================
// Test 3: Two host-only proxies on disjoint hosts
// ============================================================================

#[ignore]
#[tokio::test(flavor = "multi_thread")]
async fn functional_host_only_disjoint_hosts_coexist() {
    let (port_a, _h_a) = spawn_backend("backend-a").await;
    let (port_b, _h_b) = spawn_backend("backend-b").await;

    let config = format!(
        r#"
proxies:
  - id: "host-only-a"
    hosts: ["a.example.com"]
    backend_scheme: http
    backend_host: "127.0.0.1"
    backend_port: {port_a}
    strip_listen_path: true

  - id: "host-only-b"
    hosts: ["b.example.com"]
    backend_scheme: http
    backend_host: "127.0.0.1"
    backend_port: {port_b}
    strip_listen_path: true

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

    let (_, body_a) =
        get_with_host_header(&client, gw.proxy_url("/anywhere"), "a.example.com").await;
    assert_eq!(body_a, "backend-a");

    let (_, body_b) =
        get_with_host_header(&client, gw.proxy_url("/anywhere"), "b.example.com").await;
    assert_eq!(body_b, "backend-b");
}

// ============================================================================
// Test 4: Admin API rejects HTTP proxy with neither `hosts` nor `listen_path`
// ============================================================================

#[ignore]
#[tokio::test(flavor = "multi_thread")]
async fn functional_host_only_admin_rejects_neither_hosts_nor_listen_path() {
    use serde_json::json;

    let gw = TestGateway::builder()
        .mode_database_sqlite()
        .log_level("warn")
        .spawn()
        .await
        .expect("start gateway");

    let auth = gw.auth_header();
    let client = reqwest::Client::new();

    // 1) Neither hosts nor listen_path → 400
    let body_neither = json!({
        "id": "bad-catch-all",
        "backend_scheme": "http",
        "backend_host": "127.0.0.1",
        "backend_port": 3000,
    });
    let resp = client
        .post(gw.admin_url("/proxies"))
        .header("Authorization", &auth)
        .json(&body_neither)
        .send()
        .await
        .expect("create request");
    assert_eq!(
        resp.status().as_u16(),
        400,
        "proxy with neither hosts nor listen_path must be rejected"
    );

    // 2) Stream proxy with a populated listen_path → 400
    let body_stream_with_path = json!({
        "id": "bad-stream",
        "listen_path": "/not-allowed",
        "backend_scheme": "tcp",
        "backend_host": "127.0.0.1",
        "backend_port": 5432,
        "listen_port": ephemeral_port().await,
    });
    let resp = client
        .post(gw.admin_url("/proxies"))
        .header("Authorization", &auth)
        .json(&body_stream_with_path)
        .send()
        .await
        .expect("create request");
    assert_eq!(
        resp.status().as_u16(),
        400,
        "stream proxy with populated listen_path must be rejected"
    );

    // 3) Host-only succeeds
    let body_host_only = json!({
        "id": "host-only-ok",
        "hosts": ["ok.example.com"],
        "backend_scheme": "http",
        "backend_host": "127.0.0.1",
        "backend_port": 3000,
    });
    let resp = client
        .post(gw.admin_url("/proxies"))
        .header("Authorization", &auth)
        .json(&body_host_only)
        .send()
        .await
        .expect("create request");
    assert_eq!(
        resp.status().as_u16(),
        201,
        "host-only proxy should be accepted"
    );

    // 4) Duplicate host-only on same host → 409
    let body_duplicate = json!({
        "id": "host-only-dup",
        "hosts": ["ok.example.com"],
        "backend_scheme": "http",
        "backend_host": "127.0.0.1",
        "backend_port": 3001,
    });
    let resp = client
        .post(gw.admin_url("/proxies"))
        .header("Authorization", &auth)
        .json(&body_duplicate)
        .send()
        .await
        .expect("create request");
    assert_eq!(
        resp.status().as_u16(),
        409,
        "duplicate host-only on same host must conflict"
    );

    // 5) GET /proxies returns listen_path=null for the host-only proxy
    let resp = client
        .get(gw.admin_url("/proxies/host-only-ok"))
        .header("Authorization", &auth)
        .send()
        .await
        .expect("get request");
    assert_eq!(resp.status().as_u16(), 200);
    let body: serde_json::Value = resp.json().await.unwrap();
    assert!(
        body["listen_path"].is_null(),
        "host-only proxy listen_path should serialize as null, got {:?}",
        body["listen_path"]
    );
}
