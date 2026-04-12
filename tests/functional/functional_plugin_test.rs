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

use bytes::Bytes;
use chrono::Utc;
use http_body_util::{BodyExt, Full};
use hyper::body::Incoming;
use hyper::service::service_fn;
use hyper::{Request, Response};
use hyper_util::rt::{TokioExecutor, TokioIo};
use jsonwebtoken::{EncodingKey, Header, encode};
use serde_json::json;
use std::process::{Child, Command, Stdio};
use std::sync::Arc;
use std::time::{Duration, SystemTime};
use tempfile::TempDir;
use uuid::Uuid;

// ============================================================================
// Test Harness
// ============================================================================

struct PluginTestHarness {
    _temp_dir: TempDir,
    gateway_process: Option<Child>,
    proxy_base_url: String,
    admin_base_url: String,
    jwt_secret: String,
    jwt_issuer: String,
    #[allow(dead_code)]
    admin_port: u16,
    #[allow(dead_code)]
    proxy_port: u16,
}

impl PluginTestHarness {
    async fn new() -> Result<Self, Box<dyn std::error::Error>> {
        const MAX_ATTEMPTS: u32 = 3;
        let mut last_err = String::new();
        for attempt in 1..=MAX_ATTEMPTS {
            match Self::try_new().await {
                Ok(harness) => return Ok(harness),
                Err(e) => {
                    last_err = e.to_string();
                    eprintln!(
                        "Harness startup attempt {}/{} failed: {}",
                        attempt, MAX_ATTEMPTS, last_err
                    );
                    if attempt < MAX_ATTEMPTS {
                        tokio::time::sleep(std::time::Duration::from_secs(1)).await;
                    }
                }
            }
        }
        Err(format!(
            "Failed to create harness after {} attempts: {}",
            MAX_ATTEMPTS, last_err
        )
        .into())
    }

    async fn try_new() -> Result<Self, Box<dyn std::error::Error>> {
        let temp_dir = TempDir::new()?;
        let jwt_secret = "test-plugin-jwt-secret-12345".to_string();
        let jwt_issuer = "ferrum-edge-plugin-test".to_string();

        let admin_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
        let admin_port = admin_listener.local_addr()?.port();
        drop(admin_listener);

        let proxy_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
        let proxy_port = proxy_listener.local_addr()?.port();
        drop(proxy_listener);

        let db_url = format!(
            "sqlite:{}?mode=rwc",
            temp_dir.path().join("test.db").to_string_lossy()
        );

        // Build the gateway binary if not already built
        let build_status = Command::new("cargo")
            .args(["build", "--bin", "ferrum-edge"])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()?;
        if !build_status.success() {
            return Err("Failed to build ferrum-edge".into());
        }

        let binary_path = if std::path::Path::new("./target/debug/ferrum-edge").exists() {
            "./target/debug/ferrum-edge"
        } else {
            "./target/release/ferrum-edge"
        };

        let child = Command::new(binary_path)
            .env("FERRUM_MODE", "database")
            .env("FERRUM_ADMIN_JWT_SECRET", &jwt_secret)
            .env("FERRUM_ADMIN_JWT_ISSUER", &jwt_issuer)
            .env("FERRUM_DB_TYPE", "sqlite")
            .env("FERRUM_DB_URL", &db_url)
            .env("FERRUM_DB_POLL_INTERVAL", "2")
            .env("FERRUM_PROXY_HTTP_PORT", proxy_port.to_string())
            .env("FERRUM_ADMIN_HTTP_PORT", admin_port.to_string())
            .env("FERRUM_LOG_LEVEL", "debug")
            .env("FERRUM_TRUSTED_PROXIES", "127.0.0.1")
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()?;

        let proxy_base_url = format!("http://127.0.0.1:{}", proxy_port);
        let admin_base_url = format!("http://127.0.0.1:{}", admin_port);

        let mut harness = Self {
            _temp_dir: temp_dir,
            gateway_process: Some(child),
            proxy_base_url,
            admin_base_url,
            jwt_secret,
            jwt_issuer,
            admin_port,
            proxy_port,
        };

        match harness.wait_for_health().await {
            Ok(()) => Ok(harness),
            Err(e) => {
                if let Some(mut child) = harness.gateway_process.take() {
                    let _ = child.kill();
                    let _ = child.wait();
                }
                Err(e)
            }
        }
    }

    async fn wait_for_health(&self) -> Result<(), Box<dyn std::error::Error>> {
        let health_url = format!("{}/health", self.admin_base_url);
        let deadline = SystemTime::now() + Duration::from_secs(30);
        loop {
            if SystemTime::now() >= deadline {
                return Err("Gateway did not start within 30 seconds".into());
            }
            match reqwest::get(&health_url).await {
                Ok(r) if r.status().is_success() => return Ok(()),
                _ => tokio::time::sleep(Duration::from_millis(500)).await,
            }
        }
    }

    fn generate_admin_token(&self) -> String {
        let now = Utc::now();
        let claims = json!({
            "iss": self.jwt_issuer,
            "sub": "test-admin",
            "iat": now.timestamp(),
            "nbf": now.timestamp(),
            "exp": (now + chrono::Duration::seconds(3600)).timestamp(),
            "jti": Uuid::new_v4().to_string()
        });
        let header = Header::new(jsonwebtoken::Algorithm::HS256);
        let key = EncodingKey::from_secret(self.jwt_secret.as_bytes());
        encode(&header, &claims, &key).expect("Failed to encode admin JWT")
    }

    fn auth_header(&self) -> String {
        format!("Bearer {}", self.generate_admin_token())
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
}

impl Drop for PluginTestHarness {
    fn drop(&mut self) {
        if let Some(mut child) = self.gateway_process.take() {
            let _ = child.kill();
            let _ = child.wait();
        }
    }
}

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
                "backend_protocol": "http",
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
                "backend_protocol": "http",
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
                "window_seconds": 60,
                "max_requests": 3,
                "expose_headers": true
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

    harness.wait_for_poll().await;

    // Test 1: No correlation ID provided — should generate one
    let resp = client
        .get(format!("{}/corrid/test", harness.proxy_base_url))
        .send()
        .await
        .expect("Request failed");
    assert!(resp.status().is_success());

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

    harness.wait_for_poll().await;

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
    assert!(
        body.contains("Response body too large"),
        "response should explain the size rejection, got: {}",
        body
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

    harness.wait_for_poll().await;

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
                "backend_protocol": "https",
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
                "backend_protocol": "https",
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
                        "key": "X-Gateway-Version",
                        "value": "ferrum-1.0"
                    },
                    {
                        "operation": "add",
                        "key": "X-Powered-By",
                        "value": "ferrum-edge"
                    }
                ]
            }
        })],
    )
    .await
    .unwrap();

    harness.wait_for_poll().await;

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
                "deny": ["curl", "python-requests", "scrapy"],
                "mode": "deny"
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

    // Bot user agent should be blocked
    let resp = client
        .get(format!("{}/botdetect/test", harness.proxy_base_url))
        .header("User-Agent", "curl/7.68.0")
        .send()
        .await
        .expect("Request failed");
    assert_eq!(
        resp.status().as_u16(),
        403,
        "Bot UA (curl) should be blocked"
    );

    // Another blocked bot
    let resp = client
        .get(format!("{}/botdetect/test", harness.proxy_base_url))
        .header("User-Agent", "python-requests/2.28.1")
        .send()
        .await
        .expect("Request failed");
    assert_eq!(
        resp.status().as_u16(),
        403,
        "Bot UA (python-requests) should be blocked"
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
                "backend_protocol": "http",
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
                "rules": [{"operation": "add", "key": "X-Served-By", "value": "ferrum"}]
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
                "backend_protocol": "http",
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
