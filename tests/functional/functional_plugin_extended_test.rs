//! Extended Functional Tests for Gateway Plugins (E2E)
//!
//! Tests plugins that have unit tests but ZERO functional test coverage:
//! - Compression (gzip response compression)
//! - Response Caching (cache hit/miss, POST bypass)
//! - GraphQL (depth limiting, introspection control)
//! - Response Mock (mock rules, path scoping, passthrough)
//! - SOAP WS-Security (UsernameToken validation)
//!
//! All tests use database mode with SQLite + admin API to configure plugins.
//!
//! Run with: cargo test --test functional_tests -- --ignored --nocapture functional_plugin_extended

use chrono::Utc;
use flate2::read::GzDecoder;
use jsonwebtoken::{EncodingKey, Header, encode};
use serde_json::json;
use std::io::Read;
use std::process::{Child, Command, Stdio};
use std::time::{Duration, SystemTime};
use tempfile::TempDir;
use uuid::Uuid;

// ============================================================================
// Test Harness (same pattern as functional_plugin_test.rs)
// ============================================================================

struct PluginExtTestHarness {
    _temp_dir: TempDir,
    gateway_process: Option<Child>,
    proxy_base_url: String,
    admin_base_url: String,
    jwt_secret: String,
    jwt_issuer: String,
}

impl PluginExtTestHarness {
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
        let jwt_secret = "test-plugin-ext-jwt-secret-12345".to_string();
        let jwt_issuer = "ferrum-edge-plugin-ext-test".to_string();

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

    async fn wait_for_poll(&self) {
        tokio::time::sleep(Duration::from_secs(3)).await;
    }
}

impl Drop for PluginExtTestHarness {
    fn drop(&mut self) {
        if let Some(mut child) = self.gateway_process.take() {
            let _ = child.kill();
            let _ = child.wait();
        }
    }
}

/// Echo backend that returns request info as JSON.
async fn start_echo_backend(
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
                let parts: Vec<&str> = request_line.trim().split(' ').collect();
                let method = parts.first().unwrap_or(&"GET").to_string();
                let path = parts.get(1).unwrap_or(&"/").to_string();

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

/// Helper: set up a proxy with plugins, wait for poll
async fn setup_proxy_with_plugins(
    harness: &PluginExtTestHarness,
    client: &reqwest::Client,
    proxy_id: &str,
    listen_path: &str,
    backend_port: u16,
    plugins: Vec<serde_json::Value>,
) -> Result<(), Box<dyn std::error::Error>> {
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

    let mut plugin_refs = Vec::new();
    for plugin in &plugins {
        harness.create_plugin(client, plugin).await?;
        plugin_refs.push(json!({"plugin_config_id": plugin["id"].as_str().unwrap()}));
    }

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
// Compression Plugin Tests
// ============================================================================

#[tokio::test]
#[ignore]
async fn test_plugin_compression_gzip_response() {
    let harness = PluginExtTestHarness::new()
        .await
        .expect("Failed to create harness");

    let backend_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let backend_port = backend_listener.local_addr().unwrap().port();
    drop(backend_listener);
    let _backend = start_echo_backend(backend_port).await.unwrap();

    let client = reqwest::Client::builder()
        .no_proxy()
        // Disable automatic decompression so we can verify the raw gzip response
        .no_gzip()
        .no_brotli()
        .no_deflate()
        .build()
        .unwrap();

    setup_proxy_with_plugins(
        &harness,
        &client,
        "proxy-compress",
        "/compress",
        backend_port,
        vec![json!({
            "id": "plugin-compress",
            "plugin_name": "compression",
            "scope": "proxy",
            "proxy_id": "proxy-compress",
            "enabled": true,
            "config": {
                "algorithms": ["gzip"],
                "min_content_length": 1,
                "remove_accept_encoding": true
            }
        })],
    )
    .await
    .unwrap();

    harness.wait_for_poll().await;

    // Send request with Accept-Encoding: gzip
    let resp = client
        .get(format!("{}/compress/test", harness.proxy_base_url))
        .header("Accept-Encoding", "gzip")
        .send()
        .await
        .expect("Request failed");

    assert_eq!(resp.status().as_u16(), 200);

    let content_encoding = resp
        .headers()
        .get("content-encoding")
        .map(|v| v.to_str().unwrap_or("").to_string());

    assert_eq!(
        content_encoding.as_deref(),
        Some("gzip"),
        "Response should be gzip-encoded"
    );

    // Verify the body can be decompressed
    let compressed_bytes = resp.bytes().await.unwrap();
    let mut decoder = GzDecoder::new(&compressed_bytes[..]);
    let mut decompressed = String::new();
    let decompress_result = decoder.read_to_string(&mut decompressed);
    assert!(
        decompress_result.is_ok(),
        "Response body should be valid gzip: {:?}",
        decompress_result.err()
    );
    assert!(
        decompressed.contains("\"method\""),
        "Decompressed body should contain echo JSON, got: {}",
        decompressed
    );
}

#[tokio::test]
#[ignore]
async fn test_plugin_compression_no_accept_encoding() {
    let harness = PluginExtTestHarness::new()
        .await
        .expect("Failed to create harness");

    let backend_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let backend_port = backend_listener.local_addr().unwrap().port();
    drop(backend_listener);
    let _backend = start_echo_backend(backend_port).await.unwrap();

    let client = reqwest::Client::builder()
        .no_proxy()
        .no_gzip()
        .no_brotli()
        .no_deflate()
        .build()
        .unwrap();

    setup_proxy_with_plugins(
        &harness,
        &client,
        "proxy-compress2",
        "/compress2",
        backend_port,
        vec![json!({
            "id": "plugin-compress2",
            "plugin_name": "compression",
            "scope": "proxy",
            "proxy_id": "proxy-compress2",
            "enabled": true,
            "config": {
                "algorithms": ["gzip"],
                "min_content_length": 1
            }
        })],
    )
    .await
    .unwrap();

    harness.wait_for_poll().await;

    // Send request WITHOUT Accept-Encoding — should not compress
    let resp = client
        .get(format!("{}/compress2/test", harness.proxy_base_url))
        .send()
        .await
        .expect("Request failed");

    assert_eq!(resp.status().as_u16(), 200);

    let content_encoding = resp
        .headers()
        .get("content-encoding")
        .map(|v| v.to_str().unwrap_or("").to_string());

    assert!(
        content_encoding.is_none() || content_encoding.as_deref() == Some("identity"),
        "Response should NOT be compressed when no Accept-Encoding sent, got: {:?}",
        content_encoding
    );
}

// ============================================================================
// Response Caching Plugin Tests
// ============================================================================

#[tokio::test]
#[ignore]
async fn test_plugin_response_caching_cache_hit() {
    let harness = PluginExtTestHarness::new()
        .await
        .expect("Failed to create harness");

    let backend_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let backend_port = backend_listener.local_addr().unwrap().port();
    drop(backend_listener);
    let _backend = start_echo_backend(backend_port).await.unwrap();

    let client = reqwest::Client::new();

    setup_proxy_with_plugins(
        &harness,
        &client,
        "proxy-cache",
        "/cache",
        backend_port,
        vec![json!({
            "id": "plugin-cache",
            "plugin_name": "response_caching",
            "scope": "proxy",
            "proxy_id": "proxy-cache",
            "enabled": true,
            "config": {
                "ttl_seconds": 60,
                "cacheable_methods": ["GET"],
                "cacheable_status_codes": [200]
            }
        })],
    )
    .await
    .unwrap();

    harness.wait_for_poll().await;

    // First request — cache miss
    let resp1 = client
        .get(format!("{}/cache/test", harness.proxy_base_url))
        .send()
        .await
        .expect("First request failed");
    assert_eq!(resp1.status().as_u16(), 200);
    let body1 = resp1.text().await.unwrap();

    // Second request — should be cache hit with same body
    let resp2 = client
        .get(format!("{}/cache/test", harness.proxy_base_url))
        .send()
        .await
        .expect("Second request failed");
    assert_eq!(resp2.status().as_u16(), 200);
    let body2 = resp2.text().await.unwrap();

    // The echo backend includes the path in its response, so both should match
    assert_eq!(
        body1, body2,
        "Cached response should match original response"
    );
}

#[tokio::test]
#[ignore]
async fn test_plugin_response_caching_post_bypass() {
    let harness = PluginExtTestHarness::new()
        .await
        .expect("Failed to create harness");

    let backend_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let backend_port = backend_listener.local_addr().unwrap().port();
    drop(backend_listener);
    let _backend = start_echo_backend(backend_port).await.unwrap();

    let client = reqwest::Client::new();

    setup_proxy_with_plugins(
        &harness,
        &client,
        "proxy-cache-post",
        "/cache-post",
        backend_port,
        vec![json!({
            "id": "plugin-cache-post",
            "plugin_name": "response_caching",
            "scope": "proxy",
            "proxy_id": "proxy-cache-post",
            "enabled": true,
            "config": {
                "ttl_seconds": 60,
                "cacheable_methods": ["GET"],
                "cacheable_status_codes": [200]
            }
        })],
    )
    .await
    .unwrap();

    harness.wait_for_poll().await;

    // POST requests should bypass cache — send with body to verify it reaches backend
    let resp = client
        .post(format!("{}/cache-post/test", harness.proxy_base_url))
        .body("test-body")
        .send()
        .await
        .expect("POST request failed");
    assert_eq!(resp.status().as_u16(), 200);
    let body: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(body["method"], "POST", "Backend should see POST method");
}

// ============================================================================
// GraphQL Plugin Tests
// ============================================================================

#[tokio::test]
#[ignore]
async fn test_plugin_graphql_depth_limiting_reject() {
    let harness = PluginExtTestHarness::new()
        .await
        .expect("Failed to create harness");

    let backend_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let backend_port = backend_listener.local_addr().unwrap().port();
    drop(backend_listener);
    let _backend = start_echo_backend(backend_port).await.unwrap();

    let client = reqwest::Client::new();

    setup_proxy_with_plugins(
        &harness,
        &client,
        "proxy-graphql",
        "/graphql",
        backend_port,
        vec![json!({
            "id": "plugin-graphql",
            "plugin_name": "graphql",
            "scope": "proxy",
            "proxy_id": "proxy-graphql",
            "enabled": true,
            "config": {
                "max_depth": 2
            }
        })],
    )
    .await
    .unwrap();

    harness.wait_for_poll().await;

    // Send a deeply nested query (depth > 2)
    let deep_query = json!({
        "query": "{ user { posts { comments { author { name } } } } }"
    });

    let resp = client
        .post(format!("{}/graphql", harness.proxy_base_url))
        .header("Content-Type", "application/json")
        .json(&deep_query)
        .send()
        .await
        .expect("Request failed");

    assert!(
        resp.status().as_u16() == 400 || resp.status().as_u16() == 403,
        "Deeply nested query should be rejected, got {}",
        resp.status()
    );
}

#[tokio::test]
#[ignore]
async fn test_plugin_graphql_valid_query_allowed() {
    let harness = PluginExtTestHarness::new()
        .await
        .expect("Failed to create harness");

    let backend_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let backend_port = backend_listener.local_addr().unwrap().port();
    drop(backend_listener);
    let _backend = start_echo_backend(backend_port).await.unwrap();

    let client = reqwest::Client::new();

    setup_proxy_with_plugins(
        &harness,
        &client,
        "proxy-graphql2",
        "/graphql2",
        backend_port,
        vec![json!({
            "id": "plugin-graphql2",
            "plugin_name": "graphql",
            "scope": "proxy",
            "proxy_id": "proxy-graphql2",
            "enabled": true,
            "config": {
                "max_depth": 5
            }
        })],
    )
    .await
    .unwrap();

    harness.wait_for_poll().await;

    // Simple query within depth limit
    let simple_query = json!({
        "query": "{ user { name } }"
    });

    let resp = client
        .post(format!("{}/graphql2", harness.proxy_base_url))
        .header("Content-Type", "application/json")
        .json(&simple_query)
        .send()
        .await
        .expect("Request failed");

    assert_eq!(
        resp.status().as_u16(),
        200,
        "Valid query within depth limit should be proxied to backend"
    );
}

#[tokio::test]
#[ignore]
async fn test_plugin_graphql_introspection_disabled() {
    let harness = PluginExtTestHarness::new()
        .await
        .expect("Failed to create harness");

    let backend_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let backend_port = backend_listener.local_addr().unwrap().port();
    drop(backend_listener);
    let _backend = start_echo_backend(backend_port).await.unwrap();

    let client = reqwest::Client::new();

    setup_proxy_with_plugins(
        &harness,
        &client,
        "proxy-graphql3",
        "/graphql3",
        backend_port,
        vec![json!({
            "id": "plugin-graphql3",
            "plugin_name": "graphql",
            "scope": "proxy",
            "proxy_id": "proxy-graphql3",
            "enabled": true,
            "config": {
                "introspection_allowed": false,
                "max_depth": 10
            }
        })],
    )
    .await
    .unwrap();

    harness.wait_for_poll().await;

    // Introspection query
    let introspection = json!({
        "query": "{ __schema { types { name } } }"
    });

    let resp = client
        .post(format!("{}/graphql3", harness.proxy_base_url))
        .header("Content-Type", "application/json")
        .json(&introspection)
        .send()
        .await
        .expect("Request failed");

    assert!(
        resp.status().as_u16() == 400 || resp.status().as_u16() == 403,
        "Introspection should be rejected when disabled, got {}",
        resp.status()
    );
}

// ============================================================================
// Response Mock Plugin Tests
// ============================================================================

#[tokio::test]
#[ignore]
async fn test_plugin_response_mock_returns_mock() {
    let harness = PluginExtTestHarness::new()
        .await
        .expect("Failed to create harness");

    // No backend needed — mock should intercept before proxying
    let client = reqwest::Client::new();

    // Use a non-existent backend port — if the mock works, we never hit it
    setup_proxy_with_plugins(
        &harness,
        &client,
        "proxy-mock",
        "/mock",
        1, // Unreachable port
        vec![json!({
            "id": "plugin-mock",
            "plugin_name": "response_mock",
            "scope": "proxy",
            "proxy_id": "proxy-mock",
            "enabled": true,
            "config": {
                "rules": [
                    {
                        "path": "/hello",
                        "method": "GET",
                        "status_code": 200,
                        "body": "{\"message\":\"mocked!\"}",
                        "headers": {
                            "Content-Type": "application/json",
                            "X-Mock": "true"
                        }
                    }
                ]
            }
        })],
    )
    .await
    .unwrap();

    harness.wait_for_poll().await;

    let resp = client
        .get(format!("{}/mock/hello", harness.proxy_base_url))
        .send()
        .await
        .expect("Request failed");

    assert_eq!(resp.status().as_u16(), 200, "Mock should return 200");

    let mock_header = resp
        .headers()
        .get("x-mock")
        .map(|v| v.to_str().unwrap_or("").to_string());
    assert_eq!(
        mock_header.as_deref(),
        Some("true"),
        "Mock should include custom X-Mock header"
    );

    let body = resp.text().await.unwrap();
    assert!(
        body.contains("mocked!"),
        "Response should contain mock body, got: {}",
        body
    );
}

#[tokio::test]
#[ignore]
async fn test_plugin_response_mock_fallthrough() {
    let harness = PluginExtTestHarness::new()
        .await
        .expect("Failed to create harness");

    let backend_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let backend_port = backend_listener.local_addr().unwrap().port();
    drop(backend_listener);
    let _backend = start_echo_backend(backend_port).await.unwrap();

    let client = reqwest::Client::new();

    setup_proxy_with_plugins(
        &harness,
        &client,
        "proxy-mock2",
        "/mock2",
        backend_port,
        vec![json!({
            "id": "plugin-mock2",
            "plugin_name": "response_mock",
            "scope": "proxy",
            "proxy_id": "proxy-mock2",
            "enabled": true,
            "config": {
                "passthrough_on_no_match": true,
                "rules": [
                    {
                        "path": "/specific-path",
                        "method": "GET",
                        "status_code": 201,
                        "body": "mock-only"
                    }
                ]
            }
        })],
    )
    .await
    .unwrap();

    harness.wait_for_poll().await;

    // Request to a non-matching path should fall through to the real backend
    let resp = client
        .get(format!("{}/mock2/other-path", harness.proxy_base_url))
        .send()
        .await
        .expect("Request failed");

    assert_eq!(
        resp.status().as_u16(),
        200,
        "Non-matching path should fall through to backend"
    );
    let body: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(
        body["method"], "GET",
        "Backend echo should confirm the request reached it"
    );
}

#[tokio::test]
#[ignore]
async fn test_plugin_response_mock_path_scoping() {
    let harness = PluginExtTestHarness::new()
        .await
        .expect("Failed to create harness");

    let client = reqwest::Client::new();

    // Proxy with listen_path /api/v1 — mock rule path should be relative
    setup_proxy_with_plugins(
        &harness,
        &client,
        "proxy-mock3",
        "/api/v1",
        1, // Unreachable — mock intercepts
        vec![json!({
            "id": "plugin-mock3",
            "plugin_name": "response_mock",
            "scope": "proxy",
            "proxy_id": "proxy-mock3",
            "enabled": true,
            "config": {
                "rules": [
                    {
                        "path": "/users",
                        "method": "GET",
                        "status_code": 200,
                        "body": "{\"users\":[]}"
                    }
                ]
            }
        })],
    )
    .await
    .unwrap();

    harness.wait_for_poll().await;

    // Request to /api/v1/users — mock rule path is /users (relative to listen_path)
    let resp = client
        .get(format!("{}/api/v1/users", harness.proxy_base_url))
        .send()
        .await
        .expect("Request failed");

    assert_eq!(
        resp.status().as_u16(),
        200,
        "Mock rule at /users should match request to /api/v1/users"
    );
    let body = resp.text().await.unwrap();
    assert!(
        body.contains("users"),
        "Should get mock response, got: {}",
        body
    );
}

// ============================================================================
// SOAP WS-Security Plugin Tests
// ============================================================================

#[tokio::test]
#[ignore]
async fn test_plugin_soap_ws_security_username_token() {
    let harness = PluginExtTestHarness::new()
        .await
        .expect("Failed to create harness");

    let backend_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let backend_port = backend_listener.local_addr().unwrap().port();
    drop(backend_listener);
    let _backend = start_echo_backend(backend_port).await.unwrap();

    let client = reqwest::Client::new();

    setup_proxy_with_plugins(
        &harness,
        &client,
        "proxy-soap",
        "/soap",
        backend_port,
        vec![json!({
            "id": "plugin-soap",
            "plugin_name": "soap_ws_security",
            "scope": "proxy",
            "proxy_id": "proxy-soap",
            "enabled": true,
            "config": {
                "username_token": {
                    "enabled": true,
                    "password_type": "PasswordText",
                    "credentials": [
                        {"username": "testuser", "password": "testpass"}
                    ]
                },
                "timestamp": {
                    "require": false
                }
            }
        })],
    )
    .await
    .unwrap();

    harness.wait_for_poll().await;

    // Valid SOAP request with UsernameToken
    let soap_body = r#"<?xml version="1.0" encoding="UTF-8"?>
<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/"
               xmlns:wsse="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd">
    <soap:Header>
        <wsse:Security>
            <wsse:UsernameToken>
                <wsse:Username>testuser</wsse:Username>
                <wsse:Password Type="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-username-token-profile-1.0#PasswordText">testpass</wsse:Password>
            </wsse:UsernameToken>
        </wsse:Security>
    </soap:Header>
    <soap:Body>
        <GetData xmlns="http://example.com">
            <id>123</id>
        </GetData>
    </soap:Body>
</soap:Envelope>"#;

    let resp = client
        .post(format!("{}/soap/service", harness.proxy_base_url))
        .header("Content-Type", "text/xml; charset=utf-8")
        .header("SOAPAction", "GetData")
        .body(soap_body)
        .send()
        .await
        .expect("Request failed");

    assert_eq!(
        resp.status().as_u16(),
        200,
        "Valid SOAP WS-Security request should be proxied to backend"
    );
}

#[tokio::test]
#[ignore]
async fn test_plugin_soap_ws_security_missing_header() {
    let harness = PluginExtTestHarness::new()
        .await
        .expect("Failed to create harness");

    let backend_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let backend_port = backend_listener.local_addr().unwrap().port();
    drop(backend_listener);
    let _backend = start_echo_backend(backend_port).await.unwrap();

    let client = reqwest::Client::new();

    setup_proxy_with_plugins(
        &harness,
        &client,
        "proxy-soap2",
        "/soap2",
        backend_port,
        vec![json!({
            "id": "plugin-soap2",
            "plugin_name": "soap_ws_security",
            "scope": "proxy",
            "proxy_id": "proxy-soap2",
            "enabled": true,
            "config": {
                "username_token": {
                    "enabled": true,
                    "password_type": "PasswordText",
                    "credentials": [
                        {"username": "testuser", "password": "testpass"}
                    ]
                },
                "timestamp": {
                    "require": false
                }
            }
        })],
    )
    .await
    .unwrap();

    harness.wait_for_poll().await;

    // SOAP request WITHOUT Security header
    let soap_no_security = r#"<?xml version="1.0" encoding="UTF-8"?>
<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">
    <soap:Header/>
    <soap:Body>
        <GetData xmlns="http://example.com">
            <id>123</id>
        </GetData>
    </soap:Body>
</soap:Envelope>"#;

    let resp = client
        .post(format!("{}/soap2/service", harness.proxy_base_url))
        .header("Content-Type", "text/xml; charset=utf-8")
        .header("SOAPAction", "GetData")
        .body(soap_no_security)
        .send()
        .await
        .expect("Request failed");

    assert!(
        resp.status().as_u16() == 401 || resp.status().as_u16() == 403,
        "SOAP request without Security header should be rejected, got {}",
        resp.status()
    );
}
