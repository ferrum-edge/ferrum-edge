//! Comprehensive Functional Test for DATABASE MODE
//!
//! This test verifies the complete functionality of ferrum-gateway in database mode:
//! - Building the gateway binary
//! - Creating and using a temporary SQLite database
//! - Starting the gateway in database mode
//! - Admin API operations (proxies, consumers, plugins)
//! - Proxy routing and request forwarding
//! - Proxy CRUD operations with live updates
//! - Health and metrics endpoints
//!
//! Run with: cargo test --test functional_database_test -- --ignored --nocapture

use chrono::Utc;
use jsonwebtoken::{encode, EncodingKey, Header};
use serde_json::json;
use std::process::{Command, Child};
use std::time::{Duration, SystemTime};
use tempfile::TempDir;
use uuid::Uuid;

/// Test harness for database mode functional testing
struct DatabaseModeTestHarness {
    /// Temporary directory for database and logs
    temp_dir: TempDir,
    /// Gateway process handle
    gateway_process: Option<Child>,
    /// Base URLs for API endpoints
    proxy_base_url: String,
    admin_base_url: String,
    /// JWT configuration
    jwt_secret: String,
    jwt_issuer: String,
    /// Admin API port (randomized)
    admin_port: u16,
    /// Proxy port (randomized)
    proxy_port: u16,
}

impl DatabaseModeTestHarness {
    /// Create a new test harness with random ports
    async fn new() -> Result<Self, Box<dyn std::error::Error>> {
        let temp_dir = TempDir::new()?;
        let jwt_secret = "test-gateway-secret-key-12345".to_string();
        let jwt_issuer = "ferrum-gateway-test".to_string();

        // Get available ports by binding to 0
        let admin_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
        let admin_port = admin_listener.local_addr()?.port();
        drop(admin_listener);

        let proxy_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
        let proxy_port = proxy_listener.local_addr()?.port();
        drop(proxy_listener);

        let proxy_base_url = format!("http://127.0.0.1:{}", proxy_port);
        let admin_base_url = format!("http://127.0.0.1:{}", admin_port);

        Ok(Self {
            temp_dir,
            gateway_process: None,
            proxy_base_url,
            admin_base_url,
            jwt_secret,
            jwt_issuer,
            admin_port,
            proxy_port,
        })
    }

    /// Get path to temporary database
    fn db_path(&self) -> String {
        self.temp_dir
            .path()
            .join("test.db")
            .to_string_lossy()
            .to_string()
    }

    /// Start the gateway binary in database mode
    async fn start_gateway(&mut self) -> Result<(), Box<dyn std::error::Error>> {
        let db_url = format!("sqlite:{}?mode=rwc", self.db_path());

        // Build the gateway binary if not already built
        let build_status = Command::new("cargo")
            .args(["build"])
            .status()?;

        if !build_status.success() {
            return Err("Failed to build ferrum-gateway".into());
        }

        // Use debug binary (matches default `cargo test` profile)
        // Falls back to release if debug doesn't exist
        let binary_path = if std::path::Path::new("./target/debug/ferrum-gateway").exists() {
            "./target/debug/ferrum-gateway"
        } else {
            "./target/release/ferrum-gateway"
        };

        // Start the gateway process with database mode environment variables
        let child = Command::new(binary_path)
            .env("FERRUM_MODE", "database")
            .env("FERRUM_ADMIN_JWT_SECRET", &self.jwt_secret)
            .env("FERRUM_ADMIN_JWT_ISSUER", &self.jwt_issuer)
            .env("FERRUM_DB_TYPE", "sqlite")
            .env("FERRUM_DB_URL", &db_url)
            .env("FERRUM_DB_POLL_INTERVAL", "2") // 2 second poll interval
            .env("FERRUM_PROXY_HTTP_PORT", self.proxy_port.to_string())
            .env("FERRUM_ADMIN_HTTP_PORT", self.admin_port.to_string())
            .env("FERRUM_LOG_LEVEL", "info")
            .spawn()?;

        self.gateway_process = Some(child);

        // Wait for gateway to be ready
        self.wait_for_health().await?;

        Ok(())
    }

    /// Poll the health endpoint until gateway is ready (max 30 seconds)
    async fn wait_for_health(&self) -> Result<(), Box<dyn std::error::Error>> {
        let health_url = format!("{}/health", self.admin_base_url);
        let deadline = SystemTime::now() + Duration::from_secs(30);

        loop {
            if SystemTime::now() >= deadline {
                return Err("Gateway did not start within 30 seconds".into());
            }

            match reqwest::get(&health_url).await {
                Ok(response) if response.status().is_success() => {
                    println!("Gateway is ready!");
                    return Ok(());
                }
                _ => {
                    tokio::time::sleep(Duration::from_millis(500)).await;
                }
            }
        }
    }

    /// Generate a valid JWT token
    fn generate_token(&self) -> Result<String, Box<dyn std::error::Error>> {
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

        Ok(encode(&header, &claims, &key)?)
    }

    /// Get authorized HTTP client
    fn get_client(&self) -> Result<reqwest::Client, Box<dyn std::error::Error>> {
        Ok(reqwest::Client::new())
    }
}

impl Drop for DatabaseModeTestHarness {
    fn drop(&mut self) {
        // Kill gateway process
        if let Some(mut child) = self.gateway_process.take() {
            let _ = child.kill();
            let _ = child.wait();
        }
    }
}

/// Create a simple echo HTTP server for backend testing
async fn start_echo_backend(port: u16) -> Result<tokio::task::JoinHandle<()>, Box<dyn std::error::Error>> {
    let listener = tokio::net::TcpListener::bind(format!("127.0.0.1:{}", port)).await?;

    let handle = tokio::spawn(async move {
        while let Ok((socket, _)) = listener.accept().await {
            tokio::spawn(async move {
                use tokio::io::{AsyncBufReadExt, AsyncWriteExt};
                let (reader, mut writer) = socket.into_split();
                let mut buf_reader = tokio::io::BufReader::new(reader);
                let mut line = String::new();

                // Read request line
                if buf_reader.read_line(&mut line).await.is_err() {
                    return;
                }

                // Read headers until blank line
                let mut headers = String::new();
                loop {
                    line.clear();
                    if buf_reader.read_line(&mut line).await.is_err() {
                        return;
                    }
                    if line == "\r\n" || line == "\n" {
                        break;
                    }
                    headers.push_str(&line);
                }

                // Send simple 200 OK response
                let body = r#"{"status":"ok","echo":true}"#;
                let response = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                    body.len(),
                    body
                );
                let _ = writer.write_all(response.as_bytes()).await;
            });
        }
    });

    Ok(handle)
}

#[tokio::test]
#[ignore]
async fn test_database_mode_comprehensive() {
    println!("\n=== Starting Database Mode Functional Test ===\n");

    // Setup
    let mut harness = DatabaseModeTestHarness::new()
        .await
        .expect("Failed to create test harness");

    println!("Test harness created:");
    println!("  Database: {}", harness.db_path());
    println!("  Proxy URL: {}", harness.proxy_base_url);
    println!("  Admin URL: {}", harness.admin_base_url);

    // Start echo backend on a random port
    let backend_listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("Failed to bind backend listener");
    let backend_port = backend_listener.local_addr().expect("Failed to get address").port();
    drop(backend_listener);

    let _backend_handle = start_echo_backend(backend_port)
        .await
        .expect("Failed to start echo backend");

    println!("Echo backend started on port {}", backend_port);

    // Start gateway
    harness
        .start_gateway()
        .await
        .expect("Failed to start gateway");

    let client = harness.get_client().expect("Failed to create HTTP client");
    let token = harness.generate_token().expect("Failed to generate JWT token");
    let auth_header = format!("Bearer {}", token);

    // Test 1: Create a proxy via Admin API
    println!("\n--- Test 1: Create Proxy ---");
    let proxy_data = json!({
        "id": "test-proxy-1",
        "listen_path": "/test-path",
        "backend_protocol": "http",
        "backend_host": "localhost",
        "backend_port": backend_port,
        "strip_listen_path": true,
    });

    let response = client
        .post(format!("{}/proxies", harness.admin_base_url))
        .header("Authorization", &auth_header)
        .json(&proxy_data)
        .send()
        .await
        .expect("Failed to create proxy");

    assert!(
        response.status().is_success(),
        "Failed to create proxy: {}",
        response.status()
    );
    println!("✓ Proxy created successfully");

    // Wait for DB poll interval to pick up the new proxy
    println!("Waiting for proxy to be loaded from database...");
    tokio::time::sleep(Duration::from_secs(3)).await;

    // Test 2: Verify proxy exists via GET
    println!("\n--- Test 2: Get Proxy ---");
    let response = client
        .get(format!("{}/proxies/test-proxy-1", harness.admin_base_url))
        .header("Authorization", &auth_header)
        .send()
        .await
        .expect("Failed to get proxy");

    assert!(response.status().is_success(), "Failed to get proxy");
    let proxy_json: serde_json::Value = response
        .json()
        .await
        .expect("Failed to parse proxy response");
    assert_eq!(proxy_json["id"], "test-proxy-1");
    println!("✓ Proxy retrieved successfully");

    // Test 3: Send request through proxy
    println!("\n--- Test 3: Route Request Through Proxy ---");
    let proxy_response = client
        .get(format!("{}/test-path", harness.proxy_base_url))
        .send()
        .await
        .expect("Failed to send request through proxy");

    assert!(
        proxy_response.status().is_success(),
        "Proxy routing failed: {}",
        proxy_response.status()
    );
    let response_body: serde_json::Value = proxy_response
        .json()
        .await
        .expect("Failed to parse proxy response body");
    assert!(response_body["echo"].as_bool().unwrap_or(false));
    println!("✓ Request successfully routed through proxy");

    // Test 4: Update the proxy
    println!("\n--- Test 4: Update Proxy ---");
    let updated_proxy_data = json!({
        "id": "test-proxy-1",
        "listen_path": "/test-path",
        "backend_protocol": "http",
        "backend_host": "localhost",
        "backend_port": backend_port,
        "strip_listen_path": false, // Changed
    });

    let response = client
        .put(format!("{}/proxies/test-proxy-1", harness.admin_base_url))
        .header("Authorization", &auth_header)
        .json(&updated_proxy_data)
        .send()
        .await
        .expect("Failed to update proxy");

    assert!(response.status().is_success(), "Failed to update proxy");
    println!("✓ Proxy updated successfully");

    // Wait for DB poll to pick up the update
    tokio::time::sleep(Duration::from_secs(3)).await;

    // Verify update took effect
    let response = client
        .get(format!("{}/proxies/test-proxy-1", harness.admin_base_url))
        .header("Authorization", &auth_header)
        .send()
        .await
        .expect("Failed to get updated proxy");

    let proxy_json: serde_json::Value = response.json().await.expect("Failed to parse response");
    assert!(!proxy_json["strip_listen_path"].as_bool().unwrap_or(true));
    println!("✓ Proxy update verified");

    // Test 5: Create a consumer
    println!("\n--- Test 5: Create Consumer ---");
    let consumer_data = json!({
        "id": "test-consumer-1",
        "username": "testuser",
        "custom_id": "custom-123",
    });

    let response = client
        .post(format!("{}/consumers", harness.admin_base_url))
        .header("Authorization", &auth_header)
        .json(&consumer_data)
        .send()
        .await
        .expect("Failed to create consumer");

    assert!(
        response.status().is_success(),
        "Failed to create consumer: {}",
        response.status()
    );
    println!("✓ Consumer created successfully");

    // Test 6: Get consumer
    println!("\n--- Test 6: Get Consumer ---");
    let response = client
        .get(format!("{}/consumers/test-consumer-1", harness.admin_base_url))
        .header("Authorization", &auth_header)
        .send()
        .await
        .expect("Failed to get consumer");

    assert!(response.status().is_success(), "Failed to get consumer");
    let consumer_json: serde_json::Value = response.json().await.expect("Failed to parse response");
    assert_eq!(consumer_json["id"], "test-consumer-1");
    println!("✓ Consumer retrieved successfully");

    // Test 7: Create plugin config
    println!("\n--- Test 7: Create Plugin Config ---");
    let plugin_config_data = json!({
        "id": "test-plugin-1",
        "plugin_name": "rate-limiting",
        "scope": "proxy",
        "proxy_id": "test-proxy-1",
        "enabled": true,
        "config": {
            "requests": 10,
            "window": 60
        }
    });

    let response = client
        .post(format!("{}/plugins/config", harness.admin_base_url))
        .header("Authorization", &auth_header)
        .json(&plugin_config_data)
        .send()
        .await
        .expect("Failed to create plugin config");

    assert!(
        response.status().is_success(),
        "Failed to create plugin config: {}",
        response.status()
    );
    println!("✓ Plugin config created successfully");

    // Test 8: Get plugin config
    println!("\n--- Test 8: Get Plugin Config ---");
    let response = client
        .get(format!("{}/plugins/config/test-plugin-1", harness.admin_base_url))
        .header("Authorization", &auth_header)
        .send()
        .await
        .expect("Failed to get plugin config");

    assert!(response.status().is_success(), "Failed to get plugin config");
    let config_json: serde_json::Value = response.json().await.expect("Failed to parse response");
    assert_eq!(config_json["id"], "test-plugin-1");
    println!("✓ Plugin config retrieved successfully");

    // Test 9: Test health endpoint
    println!("\n--- Test 9: Health Endpoint ---");
    let response = client
        .get(format!("{}/health", harness.admin_base_url))
        .send()
        .await
        .expect("Failed to get health");

    assert!(response.status().is_success(), "Health check failed");
    let health_json: serde_json::Value = response.json().await.expect("Failed to parse health");
    assert_eq!(health_json["status"], "ok");
    println!("✓ Health endpoint working");

    // Test 10: Test metrics endpoint
    println!("\n--- Test 10: Metrics Endpoint ---");
    let response = client
        .get(format!("{}/admin/metrics", harness.admin_base_url))
        .header("Authorization", &auth_header)
        .send()
        .await
        .expect("Failed to get metrics");

    assert!(
        response.status().is_success(),
        "Metrics endpoint failed: {}",
        response.status()
    );
    println!("✓ Metrics endpoint working");

    // Test 11: Delete proxy
    println!("\n--- Test 11: Delete Proxy ---");
    let response = client
        .delete(format!("{}/proxies/test-proxy-1", harness.admin_base_url))
        .header("Authorization", &auth_header)
        .send()
        .await
        .expect("Failed to delete proxy");

    assert!(response.status().is_success(), "Failed to delete proxy");
    println!("✓ Proxy deleted successfully");

    // Wait for DB poll
    tokio::time::sleep(Duration::from_secs(3)).await;

    // Verify proxy is deleted (should get 404)
    println!("\n--- Test 12: Verify Proxy Deletion ---");
    let response = client
        .get(format!("{}/proxies/test-proxy-1", harness.admin_base_url))
        .header("Authorization", &auth_header)
        .send()
        .await
        .expect("Failed to check deleted proxy");

    assert_eq!(response.status(), 404, "Proxy should be deleted");
    println!("✓ Proxy deletion verified");

    // Test 13: Request to deleted proxy should fail
    println!("\n--- Test 13: Verify Deleted Proxy Not Routable ---");
    let response = client
        .get(format!("{}/test-path", harness.proxy_base_url))
        .send()
        .await;

    // Should either fail to connect or get 404
    assert!(
        response.is_err() || response.unwrap().status() == 404,
        "Deleted proxy should not be routable"
    );
    println!("✓ Deleted proxy is not routable");

    // Test 14: JWT authentication is required
    println!("\n--- Test 14: JWT Authentication Required ---");
    let response = client
        .get(format!("{}/proxies", harness.admin_base_url))
        .send() // No auth header
        .await
        .expect("Failed to send request without auth");

    assert_eq!(
        response.status(),
        401,
        "Request without auth should fail with 401"
    );
    println!("✓ JWT authentication is properly enforced");

    // Test 15: List proxies
    println!("\n--- Test 15: List Proxies ---");
    // Create another proxy first
    let proxy_data = json!({
        "id": "test-proxy-2",
        "listen_path": "/another-path",
        "backend_protocol": "http",
        "backend_host": "localhost",
        "backend_port": backend_port,
        "strip_listen_path": true,
    });

    client
        .post(format!("{}/proxies", harness.admin_base_url))
        .header("Authorization", &auth_header)
        .json(&proxy_data)
        .send()
        .await
        .expect("Failed to create second proxy");

    let response = client
        .get(format!("{}/proxies", harness.admin_base_url))
        .header("Authorization", &auth_header)
        .send()
        .await
        .expect("Failed to list proxies");

    assert!(response.status().is_success(), "Failed to list proxies");
    let proxies: serde_json::Value = response.json().await.expect("Failed to parse proxies");
    assert!(
        proxies.is_array(),
        "Proxies response should be an array"
    );
    println!("✓ Proxy listing works");

    println!("\n=== All Tests Passed ===\n");
}
