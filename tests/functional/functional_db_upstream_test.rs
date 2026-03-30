//! Functional test: Upstream load balancing in DATABASE MODE
//!
//! Verifies that proxies with upstream_id work correctly when the gateway
//! is running in database mode. This tests:
//! - Creating upstreams via Admin API
//! - Creating proxies linked to upstreams via upstream_id
//! - Round-robin load balancing across upstream targets
//! - upstream_id persistence (read back from DB matches what was written)
//!
//! Run with: cargo test --test functional_db_upstream_test -- --ignored --nocapture

use chrono::Utc;
use jsonwebtoken::{EncodingKey, Header, encode};
use serde_json::json;
use std::collections::HashMap;
use std::process::{Child, Command};
use std::time::{Duration, SystemTime};
use tempfile::TempDir;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use uuid::Uuid;

// ============================================================================
// Identifying Echo Server — each backend returns its own identity
// ============================================================================

async fn start_identifying_server(port: u16, name: &'static str) {
    let listener = TcpListener::bind(format!("127.0.0.1:{}", port))
        .await
        .unwrap_or_else(|_| panic!("Failed to bind server {} on port {}", name, port));

    loop {
        if let Ok((mut stream, _)) = listener.accept().await {
            let server_name = name;
            tokio::spawn(async move {
                let mut buf = vec![0u8; 4096];
                let n = stream.read(&mut buf).await.unwrap_or(0);
                let request = String::from_utf8_lossy(&buf[..n]).to_string();

                let path = request
                    .lines()
                    .next()
                    .and_then(|line| line.split_whitespace().nth(1))
                    .unwrap_or("/");

                let body = format!(r#"{{"server":"{}","path":"{}"}}"#, server_name, path);
                let response = format!(
                    "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nContent-Type: application/json\r\nConnection: close\r\n\r\n{}",
                    body.len(),
                    body
                );
                let _ = stream.write_all(response.as_bytes()).await;
                let _ = stream.shutdown().await;
            });
        }
    }
}

// ============================================================================
// Test Harness
// ============================================================================

struct DbUpstreamTestHarness {
    temp_dir: TempDir,
    gateway_process: Option<Child>,
    proxy_base_url: String,
    admin_base_url: String,
    jwt_secret: String,
    jwt_issuer: String,
    admin_port: u16,
    proxy_port: u16,
}

impl DbUpstreamTestHarness {
    async fn new() -> Result<Self, Box<dyn std::error::Error>> {
        let temp_dir = TempDir::new()?;
        let jwt_secret = "test-upstream-secret-key-12345".to_string();
        let jwt_issuer = "ferrum-edge-test".to_string();

        let admin_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
        let admin_port = admin_listener.local_addr()?.port();
        drop(admin_listener);

        let proxy_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
        let proxy_port = proxy_listener.local_addr()?.port();
        drop(proxy_listener);

        Ok(Self {
            temp_dir,
            gateway_process: None,
            proxy_base_url: format!("http://127.0.0.1:{}", proxy_port),
            admin_base_url: format!("http://127.0.0.1:{}", admin_port),
            jwt_secret,
            jwt_issuer,
            admin_port,
            proxy_port,
        })
    }

    fn db_path(&self) -> String {
        self.temp_dir
            .path()
            .join("test.db")
            .to_string_lossy()
            .to_string()
    }

    async fn start_gateway(&mut self) -> Result<(), Box<dyn std::error::Error>> {
        let db_url = format!("sqlite:{}?mode=rwc", self.db_path());

        let build_status = Command::new("cargo").args(["build"]).status()?;
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
            .env("FERRUM_ADMIN_JWT_SECRET", &self.jwt_secret)
            .env("FERRUM_ADMIN_JWT_ISSUER", &self.jwt_issuer)
            .env("FERRUM_DB_TYPE", "sqlite")
            .env("FERRUM_DB_URL", &db_url)
            .env("FERRUM_DB_POLL_INTERVAL", "2")
            .env("FERRUM_PROXY_HTTP_PORT", self.proxy_port.to_string())
            .env("FERRUM_ADMIN_HTTP_PORT", self.admin_port.to_string())
            .env("FERRUM_LOG_LEVEL", "info")
            .spawn()?;

        self.gateway_process = Some(child);
        self.wait_for_health().await?;
        Ok(())
    }

    async fn wait_for_health(&self) -> Result<(), Box<dyn std::error::Error>> {
        let health_url = format!("{}/health", self.admin_base_url);
        let deadline = SystemTime::now() + Duration::from_secs(30);

        loop {
            if SystemTime::now() >= deadline {
                return Err("Gateway did not start within 30 seconds".into());
            }
            match reqwest::get(&health_url).await {
                Ok(response) if response.status().is_success() => return Ok(()),
                _ => tokio::time::sleep(Duration::from_millis(500)).await,
            }
        }
    }

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
}

impl Drop for DbUpstreamTestHarness {
    fn drop(&mut self) {
        if let Some(mut child) = self.gateway_process.take() {
            let _ = child.kill();
            let _ = child.wait();
        }
    }
}

fn parse_server_name(body: &str) -> String {
    serde_json::from_str::<serde_json::Value>(body)
        .ok()
        .and_then(|v| v.get("server").and_then(|s| s.as_str()).map(String::from))
        .unwrap_or_default()
}

// ============================================================================
// Test: Upstream load balancing in database mode
// ============================================================================

#[tokio::test]
#[ignore]
async fn test_database_mode_upstream_load_balancing() {
    println!("\n=== Starting Database Mode Upstream Load Balancing Test ===\n");

    // Allocate ports for backend servers
    let mut backend_ports = Vec::new();
    for _ in 0..3 {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("Failed to bind backend listener");
        let port = listener.local_addr().unwrap().port();
        drop(listener);
        backend_ports.push(port);
    }

    // Start 3 identifying backend servers
    let s1_port = backend_ports[0];
    let s2_port = backend_ports[1];
    let s3_port = backend_ports[2];

    // We need 'static str for the server names, but we use ports to distinguish
    let s1 = tokio::spawn(start_identifying_server(s1_port, "server1"));
    let s2 = tokio::spawn(start_identifying_server(s2_port, "server2"));
    let s3 = tokio::spawn(start_identifying_server(s3_port, "server3"));
    tokio::time::sleep(Duration::from_millis(500)).await;

    println!(
        "Backend servers started on ports: {}, {}, {}",
        s1_port, s2_port, s3_port
    );

    // Start gateway in database mode
    let mut harness = DbUpstreamTestHarness::new()
        .await
        .expect("Failed to create test harness");

    println!("Test harness created:");
    println!("  Database: {}", harness.db_path());
    println!("  Proxy URL: {}", harness.proxy_base_url);
    println!("  Admin URL: {}", harness.admin_base_url);

    harness
        .start_gateway()
        .await
        .expect("Failed to start gateway");

    let client = reqwest::Client::new();
    let token = harness
        .generate_token()
        .expect("Failed to generate JWT token");
    let auth_header = format!("Bearer {}", token);

    // Step 1: Create an upstream with 3 targets via Admin API
    println!("\n--- Step 1: Create Upstream ---");
    let upstream_data = json!({
        "id": "upstream-rr-db",
        "name": "Round Robin DB Upstream",
        "algorithm": "round_robin",
        "targets": [
            { "host": "127.0.0.1", "port": s1_port, "weight": 1 },
            { "host": "127.0.0.1", "port": s2_port, "weight": 1 },
            { "host": "127.0.0.1", "port": s3_port, "weight": 1 }
        ]
    });

    let response = client
        .post(format!("{}/upstreams", harness.admin_base_url))
        .header("Authorization", &auth_header)
        .json(&upstream_data)
        .send()
        .await
        .expect("Failed to create upstream");

    assert!(
        response.status().is_success(),
        "Failed to create upstream: {}",
        response.status()
    );
    println!("Upstream created successfully");

    // Step 2: Verify upstream was persisted
    println!("\n--- Step 2: Verify Upstream ---");
    let response = client
        .get(format!(
            "{}/upstreams/upstream-rr-db",
            harness.admin_base_url
        ))
        .header("Authorization", &auth_header)
        .send()
        .await
        .expect("Failed to get upstream");

    assert!(response.status().is_success(), "Failed to get upstream");
    let upstream_json: serde_json::Value = response.json().await.expect("Failed to parse upstream");
    assert_eq!(upstream_json["id"], "upstream-rr-db");
    assert_eq!(upstream_json["targets"].as_array().unwrap().len(), 3);
    println!("Upstream verified: 3 targets configured");

    // Step 3: Create a proxy linked to the upstream via upstream_id
    println!("\n--- Step 3: Create Proxy with upstream_id ---");
    let proxy_data = json!({
        "id": "lb-proxy-db",
        "listen_path": "/lb-api",
        "backend_protocol": "http",
        "backend_host": "127.0.0.1",
        "backend_port": s1_port,
        "strip_listen_path": true,
        "upstream_id": "upstream-rr-db"
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
    println!("Proxy created with upstream_id = upstream-rr-db");

    // Step 4: Verify proxy has upstream_id persisted
    println!("\n--- Step 4: Verify Proxy upstream_id ---");
    let response = client
        .get(format!("{}/proxies/lb-proxy-db", harness.admin_base_url))
        .header("Authorization", &auth_header)
        .send()
        .await
        .expect("Failed to get proxy");

    assert!(response.status().is_success(), "Failed to get proxy");
    let proxy_json: serde_json::Value = response.json().await.expect("Failed to parse proxy");
    assert_eq!(proxy_json["id"], "lb-proxy-db");
    assert_eq!(
        proxy_json["upstream_id"], "upstream-rr-db",
        "upstream_id should be persisted and returned: got {:?}",
        proxy_json["upstream_id"]
    );
    println!("Proxy upstream_id verified: upstream-rr-db");

    // Step 5: Wait for DB poll to pick up the new proxy + upstream
    println!("\n--- Step 5: Waiting for DB poll to load proxy + upstream ---");
    tokio::time::sleep(Duration::from_secs(4)).await;

    // Step 6: Send requests through the proxy and verify load balancing
    println!("\n--- Step 6: Test Round-Robin Load Balancing ---");
    let mut counts: HashMap<String, u32> = HashMap::new();

    for i in 0..30 {
        let resp = client
            .get(format!("{}/lb-api/test-{}", harness.proxy_base_url, i))
            .send()
            .await;

        match resp {
            Ok(r) => {
                assert!(
                    r.status().is_success(),
                    "Request {} failed with status {}",
                    i,
                    r.status()
                );
                let body = r.text().await.unwrap_or_default();
                let server = parse_server_name(&body);
                if !server.is_empty() {
                    *counts.entry(server).or_insert(0) += 1;
                }
            }
            Err(e) => panic!("Request {} failed: {}", i, e),
        }
    }

    println!("Round-robin distribution: {:?}", counts);

    // Verify all 3 servers received traffic
    assert!(
        counts.len() == 3,
        "Expected traffic to 3 servers, got {:?}",
        counts
    );

    // Each server should get exactly 10 requests with round-robin
    for (server, count) in &counts {
        assert_eq!(
            *count, 10,
            "Server {} got {} requests, expected 10",
            server, count
        );
    }
    println!("Load balancing verified: even distribution across 3 backends");

    // Step 7: Update proxy to remove upstream_id, verify it goes direct
    println!("\n--- Step 7: Update Proxy — remove upstream_id ---");
    let updated_proxy_data = json!({
        "id": "lb-proxy-db",
        "listen_path": "/lb-api",
        "backend_protocol": "http",
        "backend_host": "127.0.0.1",
        "backend_port": s1_port,
        "strip_listen_path": true,
        "upstream_id": null
    });

    let response = client
        .put(format!("{}/proxies/lb-proxy-db", harness.admin_base_url))
        .header("Authorization", &auth_header)
        .json(&updated_proxy_data)
        .send()
        .await
        .expect("Failed to update proxy");

    assert!(
        response.status().is_success(),
        "Failed to update proxy: {}",
        response.status()
    );

    // Verify upstream_id is now null
    let response = client
        .get(format!("{}/proxies/lb-proxy-db", harness.admin_base_url))
        .header("Authorization", &auth_header)
        .send()
        .await
        .expect("Failed to get updated proxy");

    let proxy_json: serde_json::Value = response.json().await.expect("Failed to parse proxy");
    assert!(
        proxy_json["upstream_id"].is_null(),
        "upstream_id should be null after update, got {:?}",
        proxy_json["upstream_id"]
    );
    println!("Proxy upstream_id cleared successfully");

    // Wait for DB poll
    tokio::time::sleep(Duration::from_secs(4)).await;

    // Now all requests should go to server1 (the backend_host/port)
    println!("\n--- Step 8: Verify direct routing (no load balancing) ---");
    let mut direct_counts: HashMap<String, u32> = HashMap::new();
    for i in 0..10 {
        let resp = client
            .get(format!("{}/lb-api/direct-{}", harness.proxy_base_url, i))
            .send()
            .await;

        match resp {
            Ok(r) => {
                assert!(r.status().is_success(), "Direct request {} failed", i);
                let body = r.text().await.unwrap_or_default();
                let server = parse_server_name(&body);
                if !server.is_empty() {
                    *direct_counts.entry(server).or_insert(0) += 1;
                }
            }
            Err(e) => panic!("Direct request {} failed: {}", i, e),
        }
    }

    println!("Direct routing distribution: {:?}", direct_counts);
    assert_eq!(
        direct_counts.len(),
        1,
        "Expected traffic to 1 server only, got {:?}",
        direct_counts
    );
    assert_eq!(
        direct_counts.get("server1").copied().unwrap_or(0),
        10,
        "All 10 requests should go to server1"
    );
    println!("Direct routing verified: all traffic to server1");

    // Cleanup
    s1.abort();
    s2.abort();
    s3.abort();

    println!("\n=== All Database Mode Upstream Tests Passed ===\n");
}
