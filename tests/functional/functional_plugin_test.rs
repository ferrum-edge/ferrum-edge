//! Functional Tests for Gateway Plugins (E2E)
//!
//! Tests plugins that have ZERO functional test coverage:
//! - Rate Limiting (sliding window + token bucket)
//! - CORS (preflight + actual request headers)
//! - IP Restriction (allow/deny modes)
//! - Request Termination (maintenance mode / canned responses)
//! - Correlation ID (generate + preserve)
//! - Request Size Limiting (413 rejection)
//! - Request Transformer (header add/remove)
//! - Response Transformer (header add/remove)
//! - Bot Detection (User-Agent filtering)
//!
//! All tests use database mode with SQLite + admin API to configure plugins.
//!
//! Run with: cargo test --test functional_tests -- --ignored --nocapture functional_plugin

use crate::common::TestGateway;
use bytes::Bytes;
use http_body_util::{BodyExt, Full};
use hyper::body::Incoming;
use hyper::service::service_fn;
use hyper::{Request, Response};
use hyper_util::rt::{TokioExecutor, TokioIo};
use serde_json::json;
use std::sync::Arc;
use std::time::{Duration, SystemTime};

// ============================================================================
// Test Harness — thin wrapper around TestGateway that keeps the plugin-specific
// helper methods (create_proxy / create_plugin / update_proxy / wait_for_route /
// wait_for_poll). The subprocess lifecycle + retry + JWT minting live in
// TestGateway; only the admin-API shortcuts are plugin-test-specific.
// ============================================================================

struct PluginTestHarness {
    gw: TestGateway,
    proxy_base_url: String,
    admin_base_url: String,
}

impl PluginTestHarness {
    async fn new() -> Result<Self, Box<dyn std::error::Error + Send + Sync>> {
        let gw = TestGateway::builder()
            .log_level("debug")
            .env("FERRUM_TRUSTED_PROXIES", "127.0.0.1")
            .spawn()
            .await?;
        Ok(Self {
            proxy_base_url: gw.proxy_base_url.clone(),
            admin_base_url: gw.admin_base_url.clone(),
            gw,
        })
    }

    fn auth_header(&self) -> String {
        self.gw.auth_header()
    }

    async fn create_proxy(
        &self,
        client: &reqwest::Client,
        proxy: &serde_json::Value,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let resp = client
            .post(format!("{}/proxies", self.admin_base_url))
            .header("Authorization", self.auth_header())
            .json(proxy)
            .send()
            .await?;
        assert!(
            resp.status().is_success(),
            "Failed to create proxy: {} - {}",
            resp.status(),
            resp.text().await.unwrap_or_default()
        );
        Ok(())
    }

    async fn create_plugin(
        &self,
        client: &reqwest::Client,
        plugin: &serde_json::Value,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let resp = client
            .post(format!("{}/plugins/config", self.admin_base_url))
            .header("Authorization", self.auth_header())
            .json(plugin)
            .send()
            .await?;
        assert!(
            resp.status().is_success(),
            "Failed to create plugin config: {} - {}",
            resp.status(),
            resp.text().await.unwrap_or_default()
        );
        Ok(())
    }

    async fn update_proxy(
        &self,
        client: &reqwest::Client,
        id: &str,
        proxy: &serde_json::Value,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let resp = client
            .put(format!("{}/proxies/{}", self.admin_base_url, id))
            .header("Authorization", self.auth_header())
            .json(proxy)
            .send()
            .await?;
        assert!(
            resp.status().is_success(),
            "Failed to update proxy: {} - {}",
            resp.status(),
            resp.text().await.unwrap_or_default()
        );
        Ok(())
    }

    /// Wait for DB poll to pick up config changes.
    /// Polls a known proxy path until the gateway returns a non-404 response,
    /// which proves the route has been registered by the DB poller.
    async fn wait_for_route(&self, path: &str) {
        let url = format!("{}{}/wait-for-route-probe", self.proxy_base_url, path);
        let client = reqwest::Client::new();
        let deadline = SystemTime::now() + Duration::from_secs(15);
        loop {
            if SystemTime::now() >= deadline {
                panic!(
                    "Gateway did not register route '{}' within 15 seconds",
                    path
                );
            }
            match client.get(&url).send().await {
                Ok(r) if r.status().as_u16() != 404 => return,
                _ => tokio::time::sleep(Duration::from_millis(250)).await,
            }
        }
    }

    /// Wait for DB poll to pick up config changes (fallback for tests that
    /// don't have a specific route to probe).
    async fn wait_for_poll(&self) {
        tokio::time::sleep(Duration::from_secs(3)).await;
    }

    /// Wait until a newly-created route can complete a proxied request.
    async fn get_until_success(&self, client: &reqwest::Client, path: &str) -> reqwest::Response {
        let url = format!("{}{}", self.proxy_base_url, path);
        let deadline = SystemTime::now() + Duration::from_secs(15);
        let mut last_observation = None;

        loop {
            if SystemTime::now() >= deadline {
                panic!(
                    "Gateway route '{}' did not return success within 15 seconds; {}",
                    path,
                    last_observation
                        .as_deref()
                        .unwrap_or("no attempts completed")
                );
            }

            match client.get(&url).send().await {
                Ok(resp) if resp.status().is_success() => return resp,
                Ok(resp) => {
                    last_observation = Some(format!("status={}", resp.status()));
                }
                Err(err) => {
                    last_observation = Some(format!("error={err}"));
                }
            }

            tokio::time::sleep(Duration::from_millis(250)).await;
        }
    }
}

// Drop impl omitted: `self.gw` is a TestGateway which kills the gateway
// subprocess on drop. The field ordering ensures `gw` drops after the URL
// strings, which don't care about drop order.

/// Echo backend that returns request headers as JSON response body.
/// Response body format: {"method":"GET","path":"/...","headers":{"key":"val",...}}
async fn start_header_echo_backend(
    port: u16,
) -> Result<tokio::task::JoinHandle<()>, Box<dyn std::error::Error>> {
    let listener = tokio::net::TcpListener::bind(format!("127.0.0.1:{}", port)).await?;
    let handle = tokio::spawn(async move {
        while let Ok((socket, _)) = listener.accept().await {
            tokio::spawn(async move {
                use tokio::io::{AsyncBufReadExt, AsyncWriteExt};
                let (reader, mut writer) = socket.into_split();
                let mut buf_reader = tokio::io::BufReader::new(reader);
                let mut request_line = String::new();

                if buf_reader.read_line(&mut request_line).await.is_err() {
                    return;
                }

                // Parse method and path from request line
                let parts: Vec<&str> = request_line.trim().split(' ').collect();
                let method = parts.first().unwrap_or(&"GET").to_string();
                let path = parts.get(1).unwrap_or(&"/").to_string();

                // Read headers
                let mut headers = serde_json::Map::new();
                let mut content_length: usize = 0;
                loop {
                    let mut line = String::new();
                    if buf_reader.read_line(&mut line).await.is_err() {
                        return;
                    }
                    if line == "\r\n" || line == "\n" {
                        break;
                    }
                    if let Some((key, val)) = line.trim().split_once(':') {
                        let key_lower = key.trim().to_lowercase();
                        let val_trimmed = val.trim().to_string();
                        if key_lower == "content-length" {
                            content_length = val_trimmed.parse().unwrap_or(0);
                        }
                        headers.insert(key_lower, serde_json::Value::String(val_trimmed));
                    }
                }

                // Read request body if present
                let mut request_body = String::new();
                if content_length > 0 {
                    let mut body_buf = vec![0u8; content_length];
                    if tokio::io::AsyncReadExt::read_exact(&mut buf_reader, &mut body_buf)
                        .await
                        .is_ok()
                    {
                        request_body = String::from_utf8_lossy(&body_buf).to_string();
                    }
                }

                let body = json!({
                    "method": method,
                    "path": path,
                    "headers": headers,
                    "body": request_body,
                });
                let body_str = body.to_string();

                let response = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                    body_str.len(),
                    body_str
                );
                let _ = writer.write_all(response.as_bytes()).await;
            });
        }
    });
    Ok(handle)
}

/// HTTPS + HTTP/2 echo backend that returns request headers and body as JSON.
async fn start_h2_tls_header_echo_backend(
    port: u16,
) -> Result<tokio::task::JoinHandle<()>, Box<dyn std::error::Error>> {
    let cert_pem = include_str!("../certs/server.crt");
    let key_pem = include_str!("../certs/server.key");

    let mut cert_reader = cert_pem.as_bytes();
    let certs: Vec<_> = rustls_pemfile::certs(&mut cert_reader)
        .filter_map(|cert| cert.ok())
        .collect();
    let mut key_reader = key_pem.as_bytes();
    let private_key =
        rustls_pemfile::private_key(&mut key_reader)?.ok_or("missing private key in test cert")?;

    let provider = rustls::crypto::ring::default_provider();
    let mut tls_config = rustls::ServerConfig::builder_with_provider(Arc::new(provider))
        .with_safe_default_protocol_versions()?
        .with_no_client_auth()
        .with_single_cert(certs, private_key)?;
    tls_config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];

    let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(tls_config));
    let listener = tokio::net::TcpListener::bind(format!("127.0.0.1:{}", port)).await?;
    let handle = tokio::spawn(async move {
        while let Ok((socket, _)) = listener.accept().await {
            let acceptor = acceptor.clone();
            tokio::spawn(async move {
                let tls_stream = match acceptor.accept(socket).await {
                    Ok(stream) => stream,
                    Err(_) => return,
                };
                let io = TokioIo::new(tls_stream);
                let builder = hyper_util::server::conn::auto::Builder::new(TokioExecutor::new());
                let service = service_fn(|req: Request<Incoming>| async move {
                    let method = req.method().to_string();
                    let path = req.uri().path().to_string();
                    let mut headers = serde_json::Map::new();
                    for (name, value) in req.headers() {
                        if let Ok(value_str) = value.to_str() {
                            headers.insert(
                                name.as_str().to_string(),
                                serde_json::Value::String(value_str.to_string()),
                            );
                        }
                    }
                    let body = req
                        .into_body()
                        .collect()
                        .await
                        .map(|collected| collected.to_bytes())
                        .unwrap_or_default();
                    let echoed = json!({
                        "method": method,
                        "path": path,
                        "headers": headers,
                        "body": String::from_utf8_lossy(&body).to_string(),
                    })
                    .to_string();
                    let response = Response::builder()
                        .status(200)
                        .header("content-type", "application/json")
                        .body(Full::new(Bytes::from(echoed)))
                        .unwrap();
                    Ok::<_, hyper::Error>(response)
                });

                let _ = builder.serve_connection(io, service).await;
            });
        }
    });
    tokio::time::sleep(Duration::from_millis(200)).await;
    Ok(handle)
}

/// Helper: set up a proxy with plugins, wait for poll, return proxy path
async fn setup_proxy_with_plugins(
    harness: &PluginTestHarness,
    client: &reqwest::Client,
    proxy_id: &str,
    listen_path: &str,
    backend_port: u16,
    plugins: Vec<serde_json::Value>,
) -> Result<(), Box<dyn std::error::Error>> {
    // Create proxy
    harness
        .create_proxy(
            client,
            &json!({
                "id": proxy_id,
                "listen_path": listen_path,
                "backend_scheme": "http",
                "backend_host": "localhost",
                "backend_port": backend_port,
                "strip_listen_path": true,
            }),
        )
        .await?;

    // Create plugin configs
    let mut plugin_refs = Vec::new();
    for plugin in &plugins {
        harness.create_plugin(client, plugin).await?;
        plugin_refs.push(json!({"plugin_config_id": plugin["id"].as_str().unwrap()}));
    }

    // Update proxy to add plugin references
    harness
        .update_proxy(
            client,
            proxy_id,
            &json!({
                "id": proxy_id,
                "listen_path": listen_path,
                "backend_scheme": "http",
                "backend_host": "localhost",
                "backend_port": backend_port,
                "strip_listen_path": true,
                "plugins": plugin_refs,
            }),
        )
        .await?;

    Ok(())
}

// ============================================================================
// Rate Limiting Test
// ============================================================================

#[tokio::test]
#[ignore]
async fn test_plugin_rate_limiting() {
    let harness = PluginTestHarness::new()
        .await
        .expect("Failed to create harness");

    let backend_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let backend_port = backend_listener.local_addr().unwrap().port();
    drop(backend_listener);
    let _backend = start_header_echo_backend(backend_port).await.unwrap();

    let client = reqwest::Client::new();

    // Configure rate limiting: 3 requests per 60 seconds (sliding window)
    setup_proxy_with_plugins(
        &harness,
        &client,
        "proxy-ratelimit",
        "/ratelimit",
        backend_port,
        vec![json!({
            "id": "plugin-ratelimit",
            "plugin_name": "rate_limiting",
            "scope": "proxy",
            "proxy_id": "proxy-ratelimit",
            "enabled": true,
            "config": {
                "expose_headers": true,
                "limits": [{"scope": "default", "window_seconds": 60, "max_requests": 3}]
            }
        })],
    )
    .await
    .unwrap();

    harness.wait_for_poll().await;

    // Send 3 requests — should all succeed
    for i in 1..=3 {
        let resp = client
            .get(format!("{}/ratelimit/test", harness.proxy_base_url))
            .send()
            .await
            .expect("Request failed");
        assert_eq!(
            resp.status().as_u16(),
            200,
            "Request {} should succeed, got {}",
            i,
            resp.status()
        );
    }

    // 4th request should be rate limited (429)
    let resp = client
        .get(format!("{}/ratelimit/test", harness.proxy_base_url))
        .send()
        .await
        .expect("Request failed");
    assert_eq!(
        resp.status().as_u16(),
        429,
        "4th request should be rate limited"
    );

    // Verify rate limit headers are present
    assert!(
        resp.headers().contains_key("x-ratelimit-limit")
            || resp.headers().contains_key("retry-after"),
        "Rate limit response should include rate limit headers"
    );
}

// ============================================================================
// CORS Plugin Test
// ============================================================================

#[tokio::test]
#[ignore]
async fn test_plugin_cors_preflight() {
    let harness = PluginTestHarness::new()
        .await
        .expect("Failed to create harness");

    let backend_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let backend_port = backend_listener.local_addr().unwrap().port();
    drop(backend_listener);
    let _backend = start_header_echo_backend(backend_port).await.unwrap();

    let client = reqwest::Client::new();

    setup_proxy_with_plugins(
        &harness,
        &client,
        "proxy-cors",
        "/cors",
        backend_port,
        vec![json!({
            "id": "plugin-cors",
            "plugin_name": "cors",
            "scope": "proxy",
            "proxy_id": "proxy-cors",
            "enabled": true,
            "config": {
                "allowed_origins": ["https://example.com", "https://app.test.com"],
                "allowed_methods": ["GET", "POST", "PUT", "DELETE"],
                "allowed_headers": ["Content-Type", "Authorization", "X-Custom-Header"],
                "exposed_headers": ["X-Request-Id"],
                "allow_credentials": true,
                "max_age": 3600
            }
        })],
    )
    .await
    .unwrap();

    harness.wait_for_poll().await;

    // Test 1: Preflight OPTIONS request from allowed origin
    let resp = client
        .request(
            reqwest::Method::OPTIONS,
            format!("{}/cors/api", harness.proxy_base_url),
        )
        .header("Origin", "https://example.com")
        .header("Access-Control-Request-Method", "POST")
        .header("Access-Control-Request-Headers", "Content-Type")
        .send()
        .await
        .expect("Preflight request failed");

    // Preflight should succeed (200 or 204)
    assert!(
        resp.status().is_success() || resp.status().as_u16() == 204,
        "Preflight should succeed, got {}",
        resp.status()
    );

    // Verify CORS response headers
    let headers = resp.headers();
    assert_eq!(
        headers
            .get("access-control-allow-origin")
            .map(|v| v.to_str().unwrap_or("")),
        Some("https://example.com"),
        "Should reflect allowed origin"
    );
    assert!(
        headers.contains_key("access-control-allow-methods"),
        "Should include allowed methods"
    );
    assert!(
        headers.contains_key("access-control-max-age"),
        "Should include max-age"
    );

    // Test 2: Preflight from disallowed origin
    let resp = client
        .request(
            reqwest::Method::OPTIONS,
            format!("{}/cors/api", harness.proxy_base_url),
        )
        .header("Origin", "https://evil.com")
        .header("Access-Control-Request-Method", "POST")
        .send()
        .await
        .expect("Preflight request failed");

    // Should not have Access-Control-Allow-Origin for disallowed origin
    let origin_header = resp
        .headers()
        .get("access-control-allow-origin")
        .map(|v| v.to_str().unwrap_or(""));
    assert!(
        origin_header.is_none() || origin_header == Some(""),
        "Should not allow disallowed origin, got: {:?}",
        origin_header
    );

    // Test 3: Actual cross-origin request from allowed origin
    let resp = client
        .get(format!("{}/cors/api", harness.proxy_base_url))
        .header("Origin", "https://example.com")
        .send()
        .await
        .expect("Request failed");

    assert!(resp.status().is_success());
    assert_eq!(
        resp.headers()
            .get("access-control-allow-origin")
            .map(|v| v.to_str().unwrap_or("")),
        Some("https://example.com"),
        "Actual request should include CORS origin"
    );
}

// ============================================================================
// IP Restriction Plugin Test
// ============================================================================

#[tokio::test]
#[ignore]
async fn test_plugin_ip_restriction() {
    let harness = PluginTestHarness::new()
        .await
        .expect("Failed to create harness");

    let backend_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let backend_port = backend_listener.local_addr().unwrap().port();
    drop(backend_listener);
    let _backend = start_header_echo_backend(backend_port).await.unwrap();

    let client = reqwest::Client::new();

    // Test 1: Allow mode — only allow 10.0.0.0/8 (not 127.0.0.1)
    setup_proxy_with_plugins(
        &harness,
        &client,
        "proxy-ip-deny",
        "/ip-deny",
        backend_port,
        vec![json!({
            "id": "plugin-ip-deny",
            "plugin_name": "ip_restriction",
            "scope": "proxy",
            "proxy_id": "proxy-ip-deny",
            "enabled": true,
            "config": {
                "allow": ["10.0.0.0/8"],
                "mode": "allow_first"
            }
        })],
    )
    .await
    .unwrap();

    // Test 2: Allow 127.0.0.1 explicitly
    setup_proxy_with_plugins(
        &harness,
        &client,
        "proxy-ip-allow",
        "/ip-allow",
        backend_port,
        vec![json!({
            "id": "plugin-ip-allow",
            "plugin_name": "ip_restriction",
            "scope": "proxy",
            "proxy_id": "proxy-ip-allow",
            "enabled": true,
            "config": {
                "allow": ["127.0.0.1"],
                "mode": "allow_first"
            }
        })],
    )
    .await
    .unwrap();

    // Test 3: Deny mode — deny 127.0.0.1
    setup_proxy_with_plugins(
        &harness,
        &client,
        "proxy-ip-deny-explicit",
        "/ip-deny-explicit",
        backend_port,
        vec![json!({
            "id": "plugin-ip-deny-explicit",
            "plugin_name": "ip_restriction",
            "scope": "proxy",
            "proxy_id": "proxy-ip-deny-explicit",
            "enabled": true,
            "config": {
                "deny": ["127.0.0.1"],
                "mode": "deny_first"
            }
        })],
    )
    .await
    .unwrap();

    harness.wait_for_poll().await;

    // Request to proxy that doesn't allow 127.0.0.1 should be forbidden
    let resp = client
        .get(format!("{}/ip-deny/test", harness.proxy_base_url))
        .send()
        .await
        .expect("Request failed");
    assert_eq!(
        resp.status().as_u16(),
        403,
        "Should be forbidden when IP not in allow list"
    );

    // Request to proxy that allows 127.0.0.1 should succeed
    let resp = client
        .get(format!("{}/ip-allow/test", harness.proxy_base_url))
        .send()
        .await
        .expect("Request failed");
    assert_eq!(
        resp.status().as_u16(),
        200,
        "Should succeed when IP in allow list"
    );

    // Request to proxy that explicitly denies 127.0.0.1 should be forbidden
    let resp = client
        .get(format!("{}/ip-deny-explicit/test", harness.proxy_base_url))
        .send()
        .await
        .expect("Request failed");
    assert_eq!(
        resp.status().as_u16(),
        403,
        "Should be forbidden when IP in deny list"
    );
}

// ============================================================================
// Request Termination Plugin Test
// ============================================================================

#[tokio::test]
#[ignore]
async fn test_plugin_request_termination() {
    let harness = PluginTestHarness::new()
        .await
        .expect("Failed to create harness");

    let backend_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let backend_port = backend_listener.local_addr().unwrap().port();
    drop(backend_listener);
    let _backend = start_header_echo_backend(backend_port).await.unwrap();

    let client = reqwest::Client::new();

    // Test 1: Always-trigger maintenance mode (503)
    setup_proxy_with_plugins(
        &harness,
        &client,
        "proxy-maintenance",
        "/maintenance",
        backend_port,
        vec![json!({
            "id": "plugin-maintenance",
            "plugin_name": "request_termination",
            "scope": "proxy",
            "proxy_id": "proxy-maintenance",
            "enabled": true,
            "config": {
                "status_code": 503,
                "content_type": "application/json",
                "message": "Service under maintenance"
            }
        })],
    )
    .await
    .unwrap();

    // Test 2: Custom status code (451) with custom body
    setup_proxy_with_plugins(
        &harness,
        &client,
        "proxy-blocked",
        "/blocked",
        backend_port,
        vec![json!({
            "id": "plugin-blocked",
            "plugin_name": "request_termination",
            "scope": "proxy",
            "proxy_id": "proxy-blocked",
            "enabled": true,
            "config": {
                "status_code": 451,
                "content_type": "text/plain",
                "body": "Unavailable for legal reasons"
            }
        })],
    )
    .await
    .unwrap();

    // Wait for the DB poller to register both routes before asserting
    harness.wait_for_route("/maintenance").await;
    harness.wait_for_route("/blocked").await;

    // Test maintenance mode returns 503
    let resp = client
        .get(format!("{}/maintenance/anything", harness.proxy_base_url))
        .send()
        .await
        .expect("Request failed");
    assert_eq!(resp.status().as_u16(), 503, "Should return 503");
    let body = resp.text().await.unwrap();
    assert!(
        body.contains("maintenance"),
        "Body should contain maintenance message, got: {}",
        body
    );

    // Test blocked returns 451 with custom body
    let resp = client
        .get(format!("{}/blocked/anything", harness.proxy_base_url))
        .send()
        .await
        .expect("Request failed");
    assert_eq!(resp.status().as_u16(), 451, "Should return 451");
    let body = resp.text().await.unwrap();
    assert_eq!(body, "Unavailable for legal reasons");

    // HEAD keeps representation metadata but must not carry content bytes.
    let get_resp = client
        .get(format!("{}/maintenance/anything", harness.proxy_base_url))
        .send()
        .await
        .expect("GET control request failed");
    assert_eq!(get_resp.status().as_u16(), 503);
    let get_body = get_resp.bytes().await.expect("GET body");
    assert!(get_body.windows(11).any(|w| w == b"maintenance"));
    let representation_len = get_body.len();

    let head_resp = client
        .head(format!("{}/maintenance/anything", harness.proxy_base_url))
        .send()
        .await
        .expect("HEAD request failed");
    assert_eq!(head_resp.status().as_u16(), 503);
    assert_eq!(
        head_resp
            .headers()
            .get("content-length")
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.parse::<usize>().ok()),
        Some(representation_len)
    );
    assert!(
        head_resp.bytes().await.expect("HEAD body").is_empty(),
        "HEAD must not receive response content"
    );
}

#[tokio::test]
#[ignore]
async fn test_plugin_request_termination_preserves_cors_preflight() {
    let harness = PluginTestHarness::new()
        .await
        .expect("Failed to create harness");

    let backend_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let backend_port = backend_listener.local_addr().unwrap().port();
    drop(backend_listener);
    let _backend = start_header_echo_backend(backend_port).await.unwrap();

    let client = reqwest::Client::new();

    setup_proxy_with_plugins(
        &harness,
        &client,
        "proxy-cors-maintenance",
        "/cors-maintenance",
        backend_port,
        vec![
            json!({
                "id": "plugin-cors-maintenance-cors",
                "plugin_name": "cors",
                "scope": "proxy",
                "proxy_id": "proxy-cors-maintenance",
                "enabled": true,
                "config": {
                    "allowed_origins": ["https://example.com"],
                    "allowed_methods": ["GET", "OPTIONS"],
                    "allowed_headers": ["Content-Type", "Authorization"],
                    "allow_credentials": true,
                    "max_age": 600
                }
            }),
            json!({
                "id": "plugin-cors-maintenance-termination",
                "plugin_name": "request_termination",
                "scope": "proxy",
                "proxy_id": "proxy-cors-maintenance",
                "enabled": true,
                "config": {
                    "status_code": 503,
                    "content_type": "application/json",
                    "message": "Service under maintenance"
                }
            }),
        ],
    )
    .await
    .unwrap();

    harness.wait_for_route("/cors-maintenance").await;

    let preflight = client
        .request(
            reqwest::Method::OPTIONS,
            format!("{}/cors-maintenance/api", harness.proxy_base_url),
        )
        .header("Origin", "https://example.com")
        .header("Access-Control-Request-Method", "GET")
        .header("Access-Control-Request-Headers", "Authorization")
        .send()
        .await
        .expect("Preflight request failed");

    assert_eq!(
        preflight.status().as_u16(),
        204,
        "CORS preflight should short-circuit before request termination"
    );
    assert_eq!(
        preflight
            .headers()
            .get("access-control-allow-origin")
            .map(|v| v.to_str().unwrap_or("")),
        Some("https://example.com"),
        "Preflight should still include CORS headers"
    );

    let maintenance = client
        .get(format!("{}/cors-maintenance/api", harness.proxy_base_url))
        .header("Origin", "https://example.com")
        .send()
        .await
        .expect("Maintenance request failed");

    assert_eq!(
        maintenance.status().as_u16(),
        503,
        "Non-preflight requests should still be terminated"
    );
    assert_eq!(
        maintenance
            .headers()
            .get("access-control-allow-origin")
            .map(|v| v.to_str().unwrap_or("")),
        Some("https://example.com"),
        "Gateway-generated rejection should still carry CORS headers for allowed origins"
    );
    let body = maintenance.text().await.unwrap();
    assert!(
        body.contains("Service under maintenance"),
        "Maintenance body should still come from request_termination, got: {}",
        body
    );
}

// ============================================================================
// Correlation ID Plugin Test
// ============================================================================

#[tokio::test]
#[ignore]
async fn test_plugin_correlation_id() {
    let harness = PluginTestHarness::new()
        .await
        .expect("Failed to create harness");

    let backend_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let backend_port = backend_listener.local_addr().unwrap().port();
    drop(backend_listener);
    let _backend = start_header_echo_backend(backend_port).await.unwrap();

    let client = reqwest::Client::new();

    setup_proxy_with_plugins(
        &harness,
        &client,
        "proxy-corrid",
        "/corrid",
        backend_port,
        vec![json!({
            "id": "plugin-corrid",
            "plugin_name": "correlation_id",
            "scope": "proxy",
            "proxy_id": "proxy-corrid",
            "enabled": true,
            "config": {
                "header_name": "x-request-id",
                "echo_downstream": true
            }
        })],
    )
    .await
    .unwrap();

    // Test 1: No correlation ID provided — should generate one
    let resp = harness.get_until_success(&client, "/corrid/test").await;

    let request_id = resp
        .headers()
        .get("x-request-id")
        .map(|v| v.to_str().unwrap_or("").to_string());
    assert!(
        request_id.is_some(),
        "Response should include generated x-request-id"
    );
    let id = request_id.unwrap();
    assert!(!id.is_empty(), "Generated request ID should not be empty");
    // Should be a valid UUID
    assert!(
        uuid::Uuid::parse_str(&id).is_ok(),
        "Generated ID should be a valid UUID: {}",
        id
    );

    // Test 2: Provide existing correlation ID — should be preserved
    let custom_id = "my-custom-request-id-12345";
    let resp = client
        .get(format!("{}/corrid/test", harness.proxy_base_url))
        .header("x-request-id", custom_id)
        .send()
        .await
        .expect("Request failed");
    assert!(resp.status().is_success());

    let echoed_id = resp
        .headers()
        .get("x-request-id")
        .map(|v| v.to_str().unwrap_or("").to_string());
    assert_eq!(
        echoed_id.as_deref(),
        Some(custom_id),
        "Existing correlation ID should be preserved"
    );

    // Verify the backend received the ID by checking echo response
    // Re-send to check backend received it
    let resp = client
        .get(format!("{}/corrid/test", harness.proxy_base_url))
        .header("x-request-id", custom_id)
        .send()
        .await
        .unwrap();
    let echo_body: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(
        echo_body["headers"]["x-request-id"].as_str().unwrap_or(""),
        custom_id,
        "Backend should receive the correlation ID header"
    );

    // Two configured trust domains must retain independent values across the
    // phase-separated request/response lifecycle. The later untrusted inbound
    // value must never overwrite the internal UUID.
    setup_proxy_with_plugins(
        &harness,
        &client,
        "proxy-corrid-multi",
        "/corrid-multi",
        backend_port,
        vec![
            json!({
                "id": "plugin-corrid-external",
                "plugin_name": "correlation_id",
                "scope": "proxy",
                "proxy_id": "proxy-corrid-multi",
                "enabled": true,
                "priority_override": 60,
                "config": {
                    "header_name": "x-external-correlation-id",
                    "echo_downstream": true
                }
            }),
            json!({
                "id": "plugin-corrid-internal",
                "plugin_name": "correlation_id",
                "scope": "proxy",
                "proxy_id": "proxy-corrid-multi",
                "enabled": true,
                "priority_override": 40,
                "config": {
                    "header_name": "x-internal-request-id",
                    "echo_downstream": true
                }
            }),
        ],
    )
    .await
    .unwrap();

    // The second database-backed route is admitted asynchronously. Prove the
    // poller has published it before exercising the multi-instance lifecycle.
    harness.wait_for_route("/corrid-multi").await;

    let attacker_id = "attacker-preserved-id";
    let response = client
        .get(format!("{}/corrid-multi/test", harness.proxy_base_url))
        .header("x-external-correlation-id", attacker_id)
        .send()
        .await
        .expect("multi-instance correlation request");
    assert!(response.status().is_success());
    let internal_id = response
        .headers()
        .get("x-internal-request-id")
        .and_then(|value| value.to_str().ok())
        .expect("internal response ID")
        .to_string();
    assert!(uuid::Uuid::parse_str(&internal_id).is_ok());
    assert_ne!(internal_id, attacker_id);
    assert_eq!(
        response
            .headers()
            .get("x-external-correlation-id")
            .and_then(|value| value.to_str().ok()),
        Some(attacker_id)
    );
    let echo_body: serde_json::Value = response.json().await.unwrap();
    assert_eq!(
        echo_body["headers"]["x-internal-request-id"]
            .as_str()
            .unwrap_or(""),
        internal_id
    );
    assert_eq!(
        echo_body["headers"]["x-external-correlation-id"]
            .as_str()
            .unwrap_or(""),
        attacker_id
    );
}

// ============================================================================
// Request Size Limiting Plugin Test
// ============================================================================

#[tokio::test]
#[ignore]
async fn test_plugin_request_size_limiting() {
    let harness = PluginTestHarness::new()
        .await
        .expect("Failed to create harness");

    let backend_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let backend_port = backend_listener.local_addr().unwrap().port();
    drop(backend_listener);
    let _backend = start_header_echo_backend(backend_port).await.unwrap();

    let client = reqwest::Client::new();

    // Limit to 100 bytes
    setup_proxy_with_plugins(
        &harness,
        &client,
        "proxy-sizelimit",
        "/sizelimit",
        backend_port,
        vec![json!({
            "id": "plugin-sizelimit",
            "plugin_name": "request_size_limiting",
            "scope": "proxy",
            "proxy_id": "proxy-sizelimit",
            "enabled": true,
            "config": {
                "max_bytes": 100
            }
        })],
    )
    .await
    .unwrap();

    harness.wait_for_poll().await;

    // Small body should pass
    let small_body = "hello world";
    let resp = client
        .post(format!("{}/sizelimit/test", harness.proxy_base_url))
        .body(small_body)
        .send()
        .await
        .expect("Request failed");
    assert_eq!(
        resp.status().as_u16(),
        200,
        "Small body should pass through"
    );

    // Large body should be rejected with 413
    let large_body = "x".repeat(200);
    let resp = client
        .post(format!("{}/sizelimit/test", harness.proxy_base_url))
        .header("Content-Length", large_body.len().to_string())
        .body(large_body)
        .send()
        .await
        .expect("Request failed");
    assert_eq!(
        resp.status().as_u16(),
        413,
        "Large body should be rejected with 413 Payload Too Large"
    );
}

#[tokio::test]
#[ignore]
async fn test_plugin_request_size_limiting_checks_transformed_body() {
    let harness = PluginTestHarness::new()
        .await
        .expect("Failed to create harness");

    let backend_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let backend_port = backend_listener.local_addr().unwrap().port();
    drop(backend_listener);
    let _backend = start_header_echo_backend(backend_port).await.unwrap();

    let client = reqwest::Client::new();

    setup_proxy_with_plugins(
        &harness,
        &client,
        "proxy-sizelimit-transform",
        "/sizelimit-transform",
        backend_port,
        vec![
            json!({
                "id": "plugin-sizelimit-transform-limit",
                "plugin_name": "request_size_limiting",
                "scope": "proxy",
                "proxy_id": "proxy-sizelimit-transform",
                "enabled": true,
                "config": {
                    "max_bytes": 20
                }
            }),
            json!({
                "id": "plugin-sizelimit-transform-transformer",
                "plugin_name": "request_transformer",
                "scope": "proxy",
                "proxy_id": "proxy-sizelimit-transform",
                "enabled": true,
                "config": {
                    "rules": [
                        {
                            "operation": "add",
                            "target": "body",
                            "key": "padding",
                            "value": "abcdefghijklmnopqrstuvwxyz"
                        }
                    ]
                }
            }),
        ],
    )
    .await
    .unwrap();

    harness.wait_for_poll().await;

    let resp = client
        .post(format!(
            "{}/sizelimit-transform/test",
            harness.proxy_base_url
        ))
        .header("content-type", "application/json")
        .json(&json!({"ok": true}))
        .send()
        .await
        .expect("Request failed");
    assert_eq!(
        resp.status().as_u16(),
        413,
        "Transformed body exceeding the limit should be rejected with 413"
    );
}

// ============================================================================
// Request Transformer Plugin Test
// ============================================================================

#[tokio::test]
#[ignore]
async fn test_plugin_response_size_limiting_fast_path() {
    let harness = PluginTestHarness::new()
        .await
        .expect("Failed to create harness");

    let backend_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let backend_port = backend_listener.local_addr().unwrap().port();
    drop(backend_listener);
    let _backend = start_header_echo_backend(backend_port).await.unwrap();

    let client = reqwest::Client::new();

    setup_proxy_with_plugins(
        &harness,
        &client,
        "proxy-response-sizelimit",
        "/response-sizelimit",
        backend_port,
        vec![json!({
            "id": "plugin-response-sizelimit",
            "plugin_name": "response_size_limiting",
            "scope": "proxy",
            "proxy_id": "proxy-response-sizelimit",
            "enabled": true,
            "config": {
                "max_bytes": 300
            }
        })],
    )
    .await
    .unwrap();

    harness.wait_for_route("/response-sizelimit").await;

    let small = client
        .get(format!("{}/response-sizelimit/ok", harness.proxy_base_url))
        .send()
        .await
        .expect("Request failed");
    assert_eq!(small.status().as_u16(), 200, "small response should pass");

    let large = client
        .get(format!(
            "{}/response-sizelimit/too-large",
            harness.proxy_base_url
        ))
        .header("X-Pad", "x".repeat(1024))
        .send()
        .await
        .expect("Request failed");
    assert_eq!(
        large.status().as_u16(),
        502,
        "oversized backend response should be rejected"
    );
    let body = large.text().await.unwrap();
    assert_eq!(
        body, r#"{"error":"Backend response body exceeds maximum size"}"#,
        "response should use the canonical backend-size rejection body"
    );
}

// ============================================================================
// Request Transformer Plugin Test
// ============================================================================

#[tokio::test]
#[ignore]
async fn test_plugin_body_validator_request_validation_without_transformer() {
    let harness = PluginTestHarness::new()
        .await
        .expect("Failed to create harness");

    let backend_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let backend_port = backend_listener.local_addr().unwrap().port();
    drop(backend_listener);
    let _backend = start_header_echo_backend(backend_port).await.unwrap();

    let client = reqwest::Client::new();

    setup_proxy_with_plugins(
        &harness,
        &client,
        "proxy-body-validator-request",
        "/body-validator-request",
        backend_port,
        vec![json!({
            "id": "plugin-body-validator-request",
            "plugin_name": "body_validator",
            "scope": "proxy",
            "proxy_id": "proxy-body-validator-request",
            "enabled": true,
            "config": {
                "required_fields": ["name"]
            }
        })],
    )
    .await
    .unwrap();

    harness.wait_for_route("/body-validator-request").await;

    let rejected = client
        .post(format!(
            "{}/body-validator-request/test",
            harness.proxy_base_url
        ))
        .header("content-type", "application/json")
        .json(&json!({"missing": "field"}))
        .send()
        .await
        .expect("Request failed");
    let rejected_status = rejected.status();
    let rejected_body = rejected.text().await.unwrap();
    assert_eq!(
        rejected_status,
        reqwest::StatusCode::BAD_REQUEST,
        "expected body_validator to reject before proxying, got status {} body {}",
        rejected_status,
        rejected_body
    );
    assert!(
        rejected_body.contains("Request body validation failed"),
        "expected request validator rejection, got: {}",
        rejected_body
    );

    let allowed = client
        .post(format!(
            "{}/body-validator-request/test",
            harness.proxy_base_url
        ))
        .header("content-type", "application/json")
        .json(&json!({"name": "alice"}))
        .send()
        .await
        .expect("Request failed");
    assert!(allowed.status().is_success());

    let echo_body: serde_json::Value = allowed.json().await.unwrap();
    assert_eq!(echo_body["body"], json!(r#"{"name":"alice"}"#));
}

#[tokio::test]
#[ignore]
async fn test_plugin_request_transformer() {
    let harness = PluginTestHarness::new()
        .await
        .expect("Failed to create harness");

    let backend_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let backend_port = backend_listener.local_addr().unwrap().port();
    drop(backend_listener);
    let _backend = start_header_echo_backend(backend_port).await.unwrap();

    let client = reqwest::Client::new();

    // Add a header and remove another
    setup_proxy_with_plugins(
        &harness,
        &client,
        "proxy-reqtransform",
        "/reqtransform",
        backend_port,
        vec![json!({
            "id": "plugin-reqtransform",
            "plugin_name": "request_transformer",
            "scope": "proxy",
            "proxy_id": "proxy-reqtransform",
            "enabled": true,
            "config": {
                "rules": [
                    {
                        "operation": "add",
                        "target": "header",
                        "key": "X-Added-By-Gateway",
                        "value": "ferrum"
                    },
                    {
                        "operation": "remove",
                        "target": "header",
                        "key": "X-Remove-Me"
                    }
                ]
            }
        })],
    )
    .await
    .unwrap();

    harness.wait_for_poll().await;

    // Send request with X-Remove-Me header
    let resp = client
        .get(format!("{}/reqtransform/test", harness.proxy_base_url))
        .header("X-Remove-Me", "this-should-be-gone")
        .send()
        .await
        .expect("Request failed");
    assert!(resp.status().is_success());

    let echo_body: serde_json::Value = resp.json().await.unwrap();
    let echo_headers = &echo_body["headers"];

    // Verify added header was received by backend
    assert_eq!(
        echo_headers["x-added-by-gateway"].as_str().unwrap_or(""),
        "ferrum",
        "Backend should receive the added header"
    );

    // Verify removed header was stripped
    assert!(
        echo_headers.get("x-remove-me").is_none() || echo_headers["x-remove-me"].is_null(),
        "Backend should NOT receive the removed header"
    );
}

#[tokio::test]
#[ignore]
async fn test_plugin_request_transformer_updates_body_content_length() {
    let harness = PluginTestHarness::new()
        .await
        .expect("Failed to create harness");

    let backend_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let backend_port = backend_listener.local_addr().unwrap().port();
    drop(backend_listener);
    let _backend = start_header_echo_backend(backend_port).await.unwrap();

    let client = reqwest::Client::new();

    setup_proxy_with_plugins(
        &harness,
        &client,
        "proxy-reqtransform-body",
        "/reqtransform-body",
        backend_port,
        vec![json!({
            "id": "plugin-reqtransform-body",
            "plugin_name": "request_transformer",
            "scope": "proxy",
            "proxy_id": "proxy-reqtransform-body",
            "enabled": true,
            "config": {
                "rules": [
                    {
                        "operation": "add",
                        "target": "body",
                        "key": "gateway_added",
                        "value": "transformed-by-ferrum"
                    }
                ]
            }
        })],
    )
    .await
    .unwrap();

    harness.wait_for_poll().await;

    let resp = client
        .post(format!("{}/reqtransform-body/test", harness.proxy_base_url))
        .header("content-type", "application/json")
        .json(&json!({"name": "alice"}))
        .send()
        .await
        .expect("Request failed");
    assert!(resp.status().is_success());

    let echo_body: serde_json::Value = resp.json().await.unwrap();
    let echoed_body = echo_body["body"].as_str().unwrap_or("");
    let transformed: serde_json::Value = serde_json::from_str(echoed_body).unwrap_or_else(|e| {
        panic!(
            "backend should receive valid transformed JSON: {} | body={} | headers={}",
            e, echoed_body, echo_body["headers"]
        )
    });

    assert_eq!(transformed["name"], "alice");
    assert_eq!(transformed["gateway_added"], "transformed-by-ferrum");

    let echoed_length = echo_body["headers"]["content-length"]
        .as_str()
        .expect("backend should receive content-length header")
        .parse::<usize>()
        .expect("content-length should be numeric");
    assert_eq!(
        echoed_length,
        echoed_body.len(),
        "forwarded content-length must match transformed body size"
    );
}

#[tokio::test]
#[ignore]
async fn test_plugin_request_transformer_body_rules_bypass_direct_h2_pool() {
    let harness = PluginTestHarness::new()
        .await
        .expect("Failed to create harness");

    let backend_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let backend_port = backend_listener.local_addr().unwrap().port();
    drop(backend_listener);
    let _backend = start_h2_tls_header_echo_backend(backend_port)
        .await
        .unwrap();

    let client = reqwest::Client::new();
    let proxy_id = "proxy-reqtransform-body-h2";
    let listen_path = "/reqtransform-body-h2";

    harness
        .create_proxy(
            &client,
            &json!({
                "id": proxy_id,
                "listen_path": listen_path,
                "backend_scheme": "https",
                "backend_host": "localhost",
                "backend_port": backend_port,
                "strip_listen_path": true,
                "pool_enable_http2": true,
                "backend_tls_verify_server_cert": false,
            }),
        )
        .await
        .unwrap();

    harness
        .create_plugin(
            &client,
            &json!({
                "id": "plugin-reqtransform-body-h2",
                "plugin_name": "request_transformer",
                "scope": "proxy",
                "proxy_id": proxy_id,
                "enabled": true,
                "config": {
                    "rules": [
                        {
                            "operation": "add",
                            "target": "body",
                            "key": "gateway_added",
                            "value": "transformed-by-ferrum"
                        }
                    ]
                }
            }),
        )
        .await
        .unwrap();

    harness
        .update_proxy(
            &client,
            proxy_id,
            &json!({
                "id": proxy_id,
                "listen_path": listen_path,
                "backend_scheme": "https",
                "backend_host": "localhost",
                "backend_port": backend_port,
                "strip_listen_path": true,
                "pool_enable_http2": true,
                "backend_tls_verify_server_cert": false,
                "plugins": [
                    {"plugin_config_id": "plugin-reqtransform-body-h2"}
                ],
            }),
        )
        .await
        .unwrap();

    harness.wait_for_poll().await;

    let resp = client
        .post(format!(
            "{}/reqtransform-body-h2/test",
            harness.proxy_base_url
        ))
        .header("content-type", "application/json")
        .json(&json!({"name": "alice"}))
        .send()
        .await
        .expect("Request failed");
    let status = resp.status();
    let resp_body = resp.text().await.unwrap_or_default();
    assert!(
        status.is_success(),
        "HTTPS/H2 request should succeed: status={} body={}",
        status,
        resp_body
    );

    let echo_body: serde_json::Value = serde_json::from_str(&resp_body).unwrap();
    let echoed_body = echo_body["body"].as_str().unwrap_or("");
    let transformed: serde_json::Value = serde_json::from_str(echoed_body).unwrap_or_else(|e| {
        panic!(
            "HTTPS/H2 backend should receive valid transformed JSON: {} | body={} | headers={}",
            e, echoed_body, echo_body["headers"]
        )
    });

    assert_eq!(transformed["name"], "alice");
    assert_eq!(transformed["gateway_added"], "transformed-by-ferrum");

    let echoed_length = echo_body["headers"]["content-length"]
        .as_str()
        .expect("HTTPS/H2 backend should receive content-length header")
        .parse::<usize>()
        .expect("content-length should be numeric");
    assert_eq!(
        echoed_length,
        echoed_body.len(),
        "forwarded content-length must match transformed HTTPS/H2 body size"
    );
}

#[tokio::test]
#[ignore]
async fn test_oidc_callback_materializes_query_in_production_pipeline() {
    let harness = PluginTestHarness::new()
        .await
        .expect("Failed to create harness");
    let backend_listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind backend port");
    let backend_port = backend_listener
        .local_addr()
        .expect("backend address")
        .port();
    drop(backend_listener);
    let _backend = start_header_echo_backend(backend_port)
        .await
        .expect("start backend");
    let admin_client = reqwest::Client::new();
    let redirect_uri = format!("{}/oauth/callback", harness.proxy_base_url);

    setup_proxy_with_plugins(
        &harness,
        &admin_client,
        "proxy-oidc-callback-query",
        "/",
        backend_port,
        vec![json!({
            "id": "plugin-oidc-callback-query",
            "plugin_name": "oidc_relying_party",
            "scope": "proxy",
            "proxy_id": "proxy-oidc-callback-query",
            "enabled": true,
            "config": {
                "providers": [{
                    "issuer": "http://127.0.0.1:9",
                    "authorization_endpoint": "http://127.0.0.1:9/authorize",
                    "token_endpoint": "http://127.0.0.1:9/token",
                    "jwks_uri": "http://127.0.0.1:9/jwks",
                    "client_id": "ferrum-gateway",
                    "client_auth": {
                        "method": "client_secret_basic",
                        "client_secret": "secret"
                    },
                    "scopes": ["openid"],
                    "redirect_uri": redirect_uri,
                    "callback_path": "/oauth/callback"
                }],
                "session": {
                    "encryption_secret": "01234567890123456789012345678901"
                }
            }
        })],
    )
    .await
    .expect("configure OIDC proxy");
    harness.wait_for_poll().await;

    let client = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .expect("callback client");
    let response = client
        .get(format!(
            "{}/oauth/callback?code=example&state=encoded%2Bstate",
            harness.proxy_base_url
        ))
        .send()
        .await
        .expect("callback response");
    assert_eq!(response.status(), reqwest::StatusCode::BAD_REQUEST);
    assert_eq!(
        response.text().await.expect("callback body"),
        r#"{"error":"Invalid state"}"#
    );

    let missing = client
        .get(format!(
            "{}/oauth/callback?code=example",
            harness.proxy_base_url
        ))
        .send()
        .await
        .expect("missing-state response");
    assert_eq!(missing.status(), reqwest::StatusCode::BAD_REQUEST);
    assert_eq!(
        missing.text().await.expect("missing-state body"),
        r#"{"error":"Missing state"}"#
    );
}

// ============================================================================
// Response Transformer Plugin Test
// ============================================================================

#[tokio::test]
#[ignore]
async fn test_plugin_response_transformer() {
    let harness = PluginTestHarness::new()
        .await
        .expect("Failed to create harness");

    let backend_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let backend_port = backend_listener.local_addr().unwrap().port();
    drop(backend_listener);
    let _backend = start_header_echo_backend(backend_port).await.unwrap();

    let client = reqwest::Client::new();

    // Add a response header
    setup_proxy_with_plugins(
        &harness,
        &client,
        "proxy-resptransform",
        "/resptransform",
        backend_port,
        vec![json!({
            "id": "plugin-resptransform",
            "plugin_name": "response_transformer",
            "scope": "proxy",
            "proxy_id": "proxy-resptransform",
            "enabled": true,
            "config": {
                "rules": [
                    {
                        "operation": "add",
                        "target": "header",
                        "key": "X-Gateway-Version",
                        "value": "ferrum-1.0"
                    },
                    {
                        "operation": "add",
                        "target": "header",
                        "key": "X-Powered-By",
                        "value": "ferrum-edge"
                    }
                ]
            }
        })],
    )
    .await
    .unwrap();

    harness.wait_for_route("/resptransform").await;

    let resp = client
        .get(format!("{}/resptransform/test", harness.proxy_base_url))
        .send()
        .await
        .expect("Request failed");
    assert!(resp.status().is_success());

    // Verify added response headers
    assert_eq!(
        resp.headers()
            .get("x-gateway-version")
            .map(|v| v.to_str().unwrap_or("")),
        Some("ferrum-1.0"),
        "Response should include X-Gateway-Version header"
    );
    assert_eq!(
        resp.headers()
            .get("x-powered-by")
            .map(|v| v.to_str().unwrap_or("")),
        Some("ferrum-edge"),
        "Response should include X-Powered-By header"
    );
}

// ============================================================================
// Bot Detection Plugin Test
// ============================================================================

#[tokio::test]
#[ignore]
async fn test_plugin_bot_detection() {
    let harness = PluginTestHarness::new()
        .await
        .expect("Failed to create harness");

    let backend_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let backend_port = backend_listener.local_addr().unwrap().port();
    drop(backend_listener);
    let _backend = start_header_echo_backend(backend_port).await.unwrap();

    let client = reqwest::Client::builder()
        .user_agent("") // Don't set default user agent
        .build()
        .unwrap();

    setup_proxy_with_plugins(
        &harness,
        &client,
        "proxy-botdetect",
        "/botdetect",
        backend_port,
        vec![json!({
            "id": "plugin-botdetect",
            "plugin_name": "bot_detection",
            "scope": "proxy",
            "proxy_id": "proxy-botdetect",
            "enabled": true,
            "config": {
                "blocked_patterns": ["FerrumAuditCrawler"],
                "custom_response_code": 451
            }
        })],
    )
    .await
    .unwrap();

    harness.wait_for_poll().await;

    // Normal browser user agent should pass
    let resp = client
        .get(format!("{}/botdetect/test", harness.proxy_base_url))
        .header(
            "User-Agent",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36",
        )
        .send()
        .await
        .expect("Request failed");
    assert_eq!(resp.status().as_u16(), 200, "Normal browser UA should pass");

    // Supplying a custom list replaces the built-in defaults.
    let resp = client
        .get(format!("{}/botdetect/test", harness.proxy_base_url))
        .header("User-Agent", "curl/7.68.0")
        .send()
        .await
        .expect("Request failed");
    assert_eq!(
        resp.status().as_u16(),
        200,
        "Built-in patterns should not mask the custom fixture"
    );

    // The configured unique agent receives the configured final JSON rejection.
    let resp = client
        .get(format!("{}/botdetect/test", harness.proxy_base_url))
        .header("User-Agent", "FerrumAuditCrawler/1.0")
        .send()
        .await
        .expect("Request failed");
    assert_eq!(
        resp.status().as_u16(),
        451,
        "Configured bot UA should receive the configured final status"
    );
    assert_eq!(
        resp.headers()
            .get(reqwest::header::CONTENT_TYPE)
            .and_then(|value| value.to_str().ok()),
        Some("application/json")
    );
    assert_eq!(
        resp.text().await.expect("bot rejection body"),
        r#"{"error":"Forbidden"}"#
    );
}

// ============================================================================
// Multiple Plugins on Same Proxy (Plugin Chain) Test
// ============================================================================

#[tokio::test]
#[ignore]
async fn test_plugin_chain_multiple_plugins() {
    let harness = PluginTestHarness::new()
        .await
        .expect("Failed to create harness");

    let backend_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let backend_port = backend_listener.local_addr().unwrap().port();
    drop(backend_listener);
    let _backend = start_header_echo_backend(backend_port).await.unwrap();

    let client = reqwest::Client::new();

    // Set up a proxy with correlation ID + request transformer + response transformer
    // This tests that multiple plugins in the chain work together
    let proxy_id = "proxy-chain";
    let listen_path = "/chain";

    harness
        .create_proxy(
            &client,
            &json!({
                "id": proxy_id,
                "listen_path": listen_path,
                "backend_scheme": "http",
                "backend_host": "localhost",
                "backend_port": backend_port,
                "strip_listen_path": true,
            }),
        )
        .await
        .unwrap();

    // Create multiple plugin configs
    let plugins = vec![
        json!({
            "id": "chain-corrid",
            "plugin_name": "correlation_id",
            "scope": "proxy",
            "proxy_id": proxy_id,
            "enabled": true,
            "config": {"header_name": "x-trace-id", "echo_downstream": true}
        }),
        json!({
            "id": "chain-reqtransform",
            "plugin_name": "request_transformer",
            "scope": "proxy",
            "proxy_id": proxy_id,
            "enabled": true,
            "config": {
                "rules": [{"operation": "add", "target": "header", "key": "X-Source", "value": "gateway"}]
            }
        }),
        json!({
            "id": "chain-resptransform",
            "plugin_name": "response_transformer",
            "scope": "proxy",
            "proxy_id": proxy_id,
            "enabled": true,
            "config": {
                "rules": [{"operation": "add", "target": "header", "key": "X-Served-By", "value": "ferrum"}]
            }
        }),
    ];

    for p in &plugins {
        harness.create_plugin(&client, p).await.unwrap();
    }

    harness
        .update_proxy(
            &client,
            proxy_id,
            &json!({
                "id": proxy_id,
                "listen_path": listen_path,
                "backend_scheme": "http",
                "backend_host": "localhost",
                "backend_port": backend_port,
                "strip_listen_path": true,
                "plugins": [
                    {"plugin_config_id": "chain-corrid"},
                    {"plugin_config_id": "chain-reqtransform"},
                    {"plugin_config_id": "chain-resptransform"},
                ]
            }),
        )
        .await
        .unwrap();

    harness.wait_for_poll().await;

    let resp = client
        .get(format!("{}/chain/test", harness.proxy_base_url))
        .send()
        .await
        .expect("Request failed");
    assert!(resp.status().is_success());

    // Response should have correlation ID
    let trace_id = resp
        .headers()
        .get("x-trace-id")
        .map(|v| v.to_str().unwrap_or("").to_string());
    assert!(
        trace_id.is_some() && !trace_id.as_ref().unwrap().is_empty(),
        "Should have x-trace-id header"
    );

    // Response should have response transformer header
    assert_eq!(
        resp.headers()
            .get("x-served-by")
            .map(|v| v.to_str().unwrap_or("")),
        Some("ferrum"),
        "Should have X-Served-By response header"
    );

    // Backend should have received request transformer header
    let echo_body: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(
        echo_body["headers"]["x-source"].as_str().unwrap_or(""),
        "gateway",
        "Backend should have received X-Source header from request transformer"
    );
}

/// Hosted transport coverage for the shared WAF body view policy. Keep this
/// under the existing plugin module so the functional shard selects it.
mod waf_wide_charset {
    use super::*;
    use http_body_util::{StreamBody, combinators::BoxBody};
    use hyper::body::Frame;
    use std::convert::Infallible;
    use std::sync::atomic::{AtomicUsize, Ordering};

    fn encode(text: &str, charset: &str, bom: bool) -> Vec<u8> {
        assert!(
            text.is_ascii(),
            "transport fixtures use ASCII policy markers"
        );
        let (width, big, prefix): (usize, bool, &[u8]) = match charset {
            "utf-16le" => (2, false, &[0xFF, 0xFE]),
            "utf-16be" => (2, true, &[0xFE, 0xFF]),
            "utf-32le" => (4, false, &[0xFF, 0xFE, 0, 0]),
            "utf-32be" => (4, true, &[0, 0, 0xFE, 0xFF]),
            "utf-8" => return text.as_bytes().to_vec(),
            _ => panic!("unknown fixture charset"),
        };
        let mut body = if bom { prefix.to_vec() } else { Vec::new() };
        for ch in text.chars() {
            let bytes = if big {
                (ch as u32).to_be_bytes()
            } else {
                (ch as u32).to_le_bytes()
            };
            body.extend_from_slice(if big {
                &bytes[4 - width..]
            } else {
                &bytes[..width]
            });
        }
        body
    }

    async fn backend_response(
        request: Request<Incoming>,
        hits: Arc<AtomicUsize>,
    ) -> Result<Response<BoxBody<Bytes, Infallible>>, Infallible> {
        let (parts, body) = request.into_parts();
        let received = body.collect().await.unwrap().to_bytes();
        hits.fetch_add(1, Ordering::SeqCst);
        let header = |name: &str| parts.headers.get(name).and_then(|v| v.to_str().ok());
        let status: u16 = header("x-fixture-status").unwrap_or("200").parse().unwrap();
        let bytes = if parts.method == http::Method::HEAD || matches!(status, 204 | 205 | 304) {
            Vec::new()
        } else if let Some(value) = header("x-fixture-value") {
            encode(
                value,
                header("x-fixture-charset").unwrap_or("utf-8"),
                header("x-fixture-bom") == Some("true"),
            )
        } else {
            received.to_vec()
        };
        let body = if header("x-fixture-chunked") == Some("true") {
            let frames: Vec<_> = bytes
                .chunks(3)
                .map(|chunk| Ok::<_, Infallible>(Frame::data(Bytes::copy_from_slice(chunk))))
                .collect();
            StreamBody::new(futures_util::stream::iter(frames)).boxed()
        } else {
            Full::new(Bytes::from(bytes)).boxed()
        };
        Ok(Response::builder()
            .status(status)
            .header(
                "content-type",
                header("x-fixture-type").unwrap_or("text/plain"),
            )
            .body(body)
            .unwrap())
    }

    async fn exercise(http2: bool) {
        let reservation = crate::scaffolding::ports::reserve_port().await.unwrap();
        let port = reservation.port;
        let listener = reservation.into_listener();
        let hits = Arc::new(AtomicUsize::new(0));
        let backend_hits = Arc::clone(&hits);
        let backend = tokio::spawn(async move {
            while let Ok((stream, _)) = listener.accept().await {
                let hits = Arc::clone(&backend_hits);
                tokio::spawn(async move {
                    let service =
                        service_fn(move |request| backend_response(request, Arc::clone(&hits)));
                    let _ = hyper::server::conn::http1::Builder::new()
                        .serve_connection(TokioIo::new(stream), service)
                        .await;
                });
            }
        });
        for mode in ["buffer", "stream"] {
            let config = json!({
                "version": "1",
                "proxies": [{
                    "id": "wide", "listen_path": "/", "backend_scheme": "http",
                    "backend_host": "127.0.0.1", "backend_port": port,
                    "strip_listen_path": false, "pool_enable_http2": false,
                    "response_body_mode": mode,
                    "plugins": [{"plugin_config_id": "wide-waf"}]
                }],
                "consumers": [], "upstreams": [],
                "plugin_configs": [{
                    "id": "wide-waf", "plugin_name": "waf", "scope": "proxy",
                    "proxy_id": "wide", "enabled": true,
                    "config": {
                        "include_default_rules": false,
                        "response_inspection": true, "response_body_inspection": true,
                        "custom_rules": [
                            {
                                "id": "WIDE-REQUEST", "name": "request marker",
                                "category": "custom", "severity": "high", "target": "body_text",
                                "match_kind": "contains", "pattern": "request-marker", "action": "enforce"
                            },
                            {
                                "id": "WIDE-RESPONSE", "name": "response marker",
                                "category": "custom", "severity": "high", "target": "response_body",
                                "match_kind": "contains", "pattern": "response-marker", "action": "enforce"
                            },
                            {
                                "id": "FE-ENCODING-001", "name": "encoding policy",
                                "category": "encoding_evasion", "severity": "medium", "target": "full_url",
                                "match_kind": "contains", "pattern": "unused-url-marker", "action": "enforce"
                            }
                        ]
                    }
                }]
            });
            let mut gateway = TestGateway::builder()
                .mode_file(serde_yaml::to_string(&config).unwrap())
                .env("FERRUM_POOL_WARMUP_ENABLED", "false")
                .log_level("warn")
                .spawn()
                .await
                .unwrap();
            let builder = reqwest::Client::builder().timeout(Duration::from_secs(10));
            let client = if http2 {
                builder.http2_prior_knowledge()
            } else {
                builder.http1_only()
            }
            .build()
            .unwrap();
            for charset in ["utf-8", "utf-16le", "utf-16be", "utf-32le", "utf-32be"] {
                for presentation in ["undeclared", "declared", "bom"] {
                    let content_type = if presentation == "declared" {
                        format!("application/json; charset={charset}")
                    } else {
                        "application/json".to_string()
                    };
                    let bom = presentation == "bom";
                    let before = hits.load(Ordering::SeqCst);
                    let body = encode(r#"{"value":"request%2Dmarker"}"#, charset, bom);
                    // Unknown-length uploads split code units across DATA/chunks.
                    let chunks: Vec<_> = body
                        .chunks(3)
                        .map(|chunk| Ok::<_, Infallible>(Bytes::copy_from_slice(chunk)))
                        .collect();
                    let response = client
                        .post(gateway.proxy_url("/inspect"))
                        .header("content-type", &content_type)
                        .body(reqwest::Body::wrap_stream(futures_util::stream::iter(
                            chunks,
                        )))
                        .send()
                        .await
                        .unwrap();
                    assert_eq!(
                        response.status(),
                        403,
                        "request {charset}/{presentation}/{mode}"
                    );
                    assert_eq!(
                        hits.load(Ordering::SeqCst),
                        before,
                        "blocked upload reached origin"
                    );

                    for value in ["response%2Dmarker", "value=%00", "ordinary response"] {
                        let before = hits.load(Ordering::SeqCst);
                        let response = client
                            .post(gateway.proxy_url("/inspect"))
                            .header("content-type", "text/plain; charset=utf-8")
                            .header("x-fixture-charset", charset)
                            .header("x-fixture-bom", if bom { "true" } else { "false" })
                            .header("x-fixture-type", &content_type)
                            .header("x-fixture-value", value)
                            .header(
                                "x-fixture-chunked",
                                if mode == "stream" { "true" } else { "false" },
                            )
                            .body("ordinary request")
                            .send()
                            .await
                            .unwrap();
                        assert_eq!(hits.load(Ordering::SeqCst), before + 1);
                        let benign = value == "ordinary response";
                        assert_eq!(response.status(), if benign { 200 } else { 403 });
                        let bytes = response.bytes().await.unwrap();
                        if benign {
                            assert_eq!(bytes.as_ref(), encode(value, charset, bom));
                        } else {
                            assert!(!bytes.windows(6).any(|window| window == b"marker"));
                        }
                    }
                }
                // Successful uploads prove byte preservation and origin reachability.
                let body = encode("ordinary request", charset, false);
                let before = hits.load(Ordering::SeqCst);
                let response = client
                    .post(gateway.proxy_url("/inspect"))
                    .header("content-type", "text/plain")
                    .body(body.clone())
                    .send()
                    .await
                    .unwrap();
                assert_eq!(response.status(), 200);
                assert_eq!(response.bytes().await.unwrap().as_ref(), body);
                assert_eq!(hits.load(Ordering::SeqCst), before + 1);
            }
            // Excluded media stays releasable even on a streaming route.
            let response = client
                .get(gateway.proxy_url("/inspect"))
                .header("x-fixture-type", "application/octet-stream")
                .header("x-fixture-charset", "utf-16le")
                .header("x-fixture-value", "response-marker")
                .header("x-fixture-chunked", "true")
                .send()
                .await
                .unwrap();
            assert_eq!(response.status(), 200);
            assert_eq!(
                response.bytes().await.unwrap().as_ref(),
                encode("response-marker", "utf-16le", false)
            );
            for (method, status) in [
                (reqwest::Method::HEAD, 200),
                (reqwest::Method::GET, 204),
                (reqwest::Method::GET, 205),
                (reqwest::Method::GET, 304),
            ] {
                let response = client
                    .request(method, gateway.proxy_url("/inspect"))
                    .header("x-fixture-type", "text/plain; charset=utf-7")
                    .header("x-fixture-status", status.to_string())
                    .send()
                    .await
                    .unwrap();
                assert_eq!(response.status(), status);
                assert!(response.bytes().await.unwrap().is_empty());
            }
            gateway.shutdown();
        }
        backend.abort();
    }

    #[tokio::test]
    #[ignore]
    async fn waf_wide_charset_http1_buffered_and_streaming() {
        exercise(false).await;
    }

    #[tokio::test]
    #[ignore]
    async fn waf_wide_charset_http2_buffered_and_streaming() {
        exercise(true).await;
    }
}
