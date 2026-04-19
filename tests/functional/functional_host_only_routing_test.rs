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

use std::time::Duration;
use tempfile::TempDir;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::time::sleep;

// ---- Identified echo backend ----

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

async fn spawn_backend(identifier: &str) -> (u16, tokio::task::JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let id = identifier.to_string();
    let handle = tokio::spawn(async move {
        start_identified_echo_server(listener, id).await;
    });
    (port, handle)
}

// ---- Gateway helpers ----

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
) -> std::process::Child {
    std::process::Command::new(gateway_binary_path())
        .env("FERRUM_MODE", "file")
        .env("FERRUM_FILE_CONFIG_PATH", config_path)
        .env("FERRUM_PROXY_HTTP_PORT", http_port.to_string())
        .env("FERRUM_ADMIN_HTTP_PORT", admin_port.to_string())
        .env("FERRUM_LOG_LEVEL", "warn")
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()
        .expect("Failed to start gateway binary")
}

async fn wait_for_gateway(admin_port: u16) -> bool {
    let client = reqwest::Client::new();
    let url = format!("http://127.0.0.1:{}/health", admin_port);
    for _ in 0..60 {
        if let Ok(resp) = client.get(&url).send().await
            && resp.status().is_success()
        {
            return true;
        }
        sleep(Duration::from_millis(250)).await;
    }
    false
}

async fn ephemeral_port() -> u16 {
    let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let p = l.local_addr().unwrap().port();
    drop(l);
    p
}

async fn start_gateway_with_retry(config_path: &str) -> (std::process::Child, u16, u16) {
    const MAX_ATTEMPTS: u32 = 3;
    for attempt in 1..=MAX_ATTEMPTS {
        let proxy_port = ephemeral_port().await;
        let admin_port = ephemeral_port().await;
        let mut child = start_gateway_in_file_mode(config_path, proxy_port, admin_port);
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

async fn get_with_host_header(client: &reqwest::Client, url: &str, host: &str) -> (u16, String) {
    let resp = client
        .get(url)
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
    let temp_dir = TempDir::new().expect("temp dir");

    let (port_a, _h_a) = spawn_backend("backend-a").await;
    sleep(Duration::from_millis(200)).await;

    let config = temp_dir.path().join("config.yaml");
    let yaml = format!(
        r#"
proxies:
  - id: "host-only-a"
    hosts: ["a.example.com"]
    backend_protocol: http
    backend_host: "127.0.0.1"
    backend_port: {port_a}
    strip_listen_path: true

consumers: []
plugin_configs: []
"#
    );
    std::fs::write(&config, yaml).expect("write config");

    let (mut gw, proxy_port, _admin_port) =
        start_gateway_with_retry(config.to_str().unwrap()).await;
    let client = reqwest::Client::new();
    let base = format!("http://127.0.0.1:{proxy_port}");

    // Every path under the host hits backend-a
    for path in ["/", "/api", "/api/v1/users", "/nested/deeply/here"] {
        let (status, body) =
            get_with_host_header(&client, &format!("{base}{path}"), "a.example.com").await;
        assert_eq!(status, 200, "host-only proxy should serve {}", path);
        assert_eq!(body, "backend-a", "path {} should route to backend-a", path);
    }

    // A different host (no match anywhere) returns 404
    let (status, _) = get_with_host_header(&client, &format!("{base}/api"), "other.host").await;
    assert_eq!(
        status, 404,
        "unmatched host should not route to the host-only proxy"
    );

    let _ = gw.kill();
    let _ = gw.wait();
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
    let temp_dir = TempDir::new().expect("temp dir");

    let (port_api, _h_api) = spawn_backend("backend-api").await;
    let (port_fallback, _h_fallback) = spawn_backend("backend-fallback").await;
    sleep(Duration::from_millis(200)).await;

    let config = temp_dir.path().join("config.yaml");
    let yaml = format!(
        r#"
proxies:
  - id: "path-api"
    hosts: ["shared.example.com"]
    listen_path: "/api"
    backend_protocol: http
    backend_host: "127.0.0.1"
    backend_port: {port_api}
    strip_listen_path: false

  - id: "host-only-fallback"
    hosts: ["shared.example.com"]
    backend_protocol: http
    backend_host: "127.0.0.1"
    backend_port: {port_fallback}
    strip_listen_path: true

consumers: []
plugin_configs: []
"#
    );
    std::fs::write(&config, yaml).expect("write config");

    let (mut gw, proxy_port, _admin_port) =
        start_gateway_with_retry(config.to_str().unwrap()).await;
    let client = reqwest::Client::new();
    let base = format!("http://127.0.0.1:{proxy_port}");

    // /api/* goes to the path-carrying proxy
    let (status, body) =
        get_with_host_header(&client, &format!("{base}/api/v1"), "shared.example.com").await;
    assert_eq!(status, 200);
    assert_eq!(
        body, "backend-api",
        "matching path should win over host-only fallback"
    );

    // Other paths fall through to host-only
    let (status, body) =
        get_with_host_header(&client, &format!("{base}/other"), "shared.example.com").await;
    assert_eq!(status, 200);
    assert_eq!(
        body, "backend-fallback",
        "non-matching path should fall through to host-only fallback"
    );

    let _ = gw.kill();
    let _ = gw.wait();
}

// ============================================================================
// Test 3: Two host-only proxies on disjoint hosts
// ============================================================================

#[ignore]
#[tokio::test(flavor = "multi_thread")]
async fn functional_host_only_disjoint_hosts_coexist() {
    let temp_dir = TempDir::new().expect("temp dir");

    let (port_a, _h_a) = spawn_backend("backend-a").await;
    let (port_b, _h_b) = spawn_backend("backend-b").await;
    sleep(Duration::from_millis(200)).await;

    let config = temp_dir.path().join("config.yaml");
    let yaml = format!(
        r#"
proxies:
  - id: "host-only-a"
    hosts: ["a.example.com"]
    backend_protocol: http
    backend_host: "127.0.0.1"
    backend_port: {port_a}
    strip_listen_path: true

  - id: "host-only-b"
    hosts: ["b.example.com"]
    backend_protocol: http
    backend_host: "127.0.0.1"
    backend_port: {port_b}
    strip_listen_path: true

consumers: []
plugin_configs: []
"#
    );
    std::fs::write(&config, yaml).expect("write config");

    let (mut gw, proxy_port, _admin_port) =
        start_gateway_with_retry(config.to_str().unwrap()).await;
    let client = reqwest::Client::new();
    let base = format!("http://127.0.0.1:{proxy_port}");

    let (_, body_a) =
        get_with_host_header(&client, &format!("{base}/anywhere"), "a.example.com").await;
    assert_eq!(body_a, "backend-a");

    let (_, body_b) =
        get_with_host_header(&client, &format!("{base}/anywhere"), "b.example.com").await;
    assert_eq!(body_b, "backend-b");

    let _ = gw.kill();
    let _ = gw.wait();
}

// ============================================================================
// Test 4: Admin API rejects HTTP proxy with neither `hosts` nor `listen_path`
// ============================================================================

#[ignore]
#[tokio::test(flavor = "multi_thread")]
async fn functional_host_only_admin_rejects_neither_hosts_nor_listen_path() {
    use jsonwebtoken::{EncodingKey, Header, encode};
    use serde_json::json;

    let temp_dir = TempDir::new().expect("temp dir");
    let db_path = temp_dir.path().join("admin.db");
    let jwt_secret = "functional-host-only-admin-secret-012345";
    let jwt_issuer = "ferrum-edge-host-only-functional";

    let http_port = ephemeral_port().await;
    let admin_port = ephemeral_port().await;

    let mut child = std::process::Command::new(gateway_binary_path())
        .env("FERRUM_MODE", "database")
        .env("FERRUM_ADMIN_JWT_SECRET", jwt_secret)
        .env("FERRUM_ADMIN_JWT_ISSUER", jwt_issuer)
        .env("FERRUM_DB_TYPE", "sqlite")
        .env(
            "FERRUM_DB_URL",
            format!("sqlite:{}?mode=rwc", db_path.to_string_lossy()),
        )
        .env("FERRUM_PROXY_HTTP_PORT", http_port.to_string())
        .env("FERRUM_ADMIN_HTTP_PORT", admin_port.to_string())
        .env("FERRUM_LOG_LEVEL", "warn")
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()
        .expect("spawn");

    if !wait_for_gateway(admin_port).await {
        let _ = child.kill();
        let _ = child.wait();
        panic!("gateway did not start");
    }

    // Mint an admin JWT
    let now = chrono::Utc::now();
    let claims = json!({
        "iss": jwt_issuer,
        "sub": "host-only-admin-test",
        "iat": now.timestamp(),
        "nbf": now.timestamp(),
        "exp": (now + chrono::Duration::seconds(3600)).timestamp(),
        "jti": uuid::Uuid::new_v4().to_string(),
    });
    let token = encode(
        &Header::new(jsonwebtoken::Algorithm::HS256),
        &claims,
        &EncodingKey::from_secret(jwt_secret.as_bytes()),
    )
    .unwrap();
    let auth = format!("Bearer {}", token);

    let client = reqwest::Client::new();
    let base = format!("http://127.0.0.1:{}", admin_port);

    // 1) Neither hosts nor listen_path → 400
    let body_neither = json!({
        "id": "bad-catch-all",
        "backend_protocol": "http",
        "backend_host": "127.0.0.1",
        "backend_port": 3000,
    });
    let resp = client
        .post(format!("{base}/proxies"))
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
        "backend_protocol": "tcp",
        "backend_host": "127.0.0.1",
        "backend_port": 5432,
        "listen_port": ephemeral_port().await,
    });
    let resp = client
        .post(format!("{base}/proxies"))
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
        "backend_protocol": "http",
        "backend_host": "127.0.0.1",
        "backend_port": 3000,
    });
    let resp = client
        .post(format!("{base}/proxies"))
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
        "backend_protocol": "http",
        "backend_host": "127.0.0.1",
        "backend_port": 3001,
    });
    let resp = client
        .post(format!("{base}/proxies"))
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
        .get(format!("{base}/proxies/host-only-ok"))
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

    let _ = child.kill();
    let _ = child.wait();
}
