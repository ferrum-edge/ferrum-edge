//! MongoDB Functional Tests
//!
//! Verifies that ferrum-edge works correctly with MongoDB as the database backend:
//! - Plaintext MongoDB connection (no TLS)
//! - TLS-encrypted MongoDB connection
//! - mTLS MongoDB connection (client certificate authentication)
//! - Full Admin API CRUD lifecycle (proxies, consumers, plugins, upstreams)
//! - Proxy traffic routing through a MongoDB-backed gateway
//! - Health endpoint reports MongoDB connectivity
//!
//! Prerequisites:
//!   1. MongoDB running on localhost:27017 (plaintext test)
//!      - Docker: `docker run -d --name mongo-test -p 27017:27017 mongo:7`
//!   2. For TLS/mTLS tests: TLS-enabled MongoDB with certs
//!      - Run `tests/scripts/setup_mongo_tls.sh` (if available) or configure manually
//!   3. Build the gateway: `cargo build`
//!
//! Run with:
//!   cargo test --test functional_tests functional_mongodb -- --ignored --nocapture

use chrono::Utc;
use jsonwebtoken::{EncodingKey, Header, encode};
use serde_json::json;
use std::process::{Child, Command, Stdio};
use std::time::{Duration, SystemTime};
use uuid::Uuid;

/// Default MongoDB connection for local development / CI.
const DEFAULT_MONGO_URL: &str = "mongodb://localhost:27017/ferrum_test";
const DEFAULT_MONGO_DATABASE: &str = "ferrum_test";

/// Check if MongoDB is reachable at the expected address.
/// Returns false if MongoDB is down — tests will be skipped gracefully.
async fn mongodb_is_available(url: &str) -> bool {
    // Extract host:port from the MongoDB URL (mongodb://host:port/db)
    let host_port = url
        .strip_prefix("mongodb://")
        .or_else(|| url.strip_prefix("mongodb+srv://"))
        .and_then(|s| s.split('/').next())
        .and_then(|s| {
            // Strip credentials if present (user:pass@host:port)
            if s.contains('@') {
                s.split('@').next_back()
            } else {
                Some(s)
            }
        })
        .unwrap_or("localhost:27017");

    match tokio::net::TcpStream::connect(host_port).await {
        Ok(_) => true,
        Err(_) => {
            eprintln!(
                "MongoDB not available at {} — skipping MongoDB functional tests",
                host_port
            );
            false
        }
    }
}

/// Default certificate directory for TLS tests.
const DEFAULT_CERT_DIR: &str = "/tmp/ferrum-mongo-tls-certs";

/// Test harness for MongoDB functional testing.
struct MongoTestHarness {
    gateway_process: Option<Child>,
    proxy_base_url: String,
    admin_base_url: String,
    jwt_secret: String,
    jwt_issuer: String,
    admin_port: u16,
    proxy_port: u16,
}

impl MongoTestHarness {
    async fn new() -> Result<Self, Box<dyn std::error::Error>> {
        let jwt_secret = "mongo-test-secret-key-12345".to_string();
        let jwt_issuer = "ferrum-edge-mongo-test".to_string();

        let admin_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
        let admin_port = admin_listener.local_addr()?.port();
        drop(admin_listener);

        let proxy_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
        let proxy_port = proxy_listener.local_addr()?.port();
        drop(proxy_listener);

        Ok(Self {
            gateway_process: None,
            proxy_base_url: format!("http://127.0.0.1:{}", proxy_port),
            admin_base_url: format!("http://127.0.0.1:{}", admin_port),
            jwt_secret,
            jwt_issuer,
            admin_port,
            proxy_port,
        })
    }

    /// Start the gateway with plaintext MongoDB connection.
    /// Retries up to 3 times with fresh ports to handle ephemeral port races.
    async fn start_gateway_plaintext(
        &mut self,
        mongo_url: &str,
    ) -> Result<(), Box<dyn std::error::Error>> {
        const MAX_ATTEMPTS: u32 = 3;
        let mut last_err = String::new();
        for attempt in 1..=MAX_ATTEMPTS {
            match self.try_start_gateway_plaintext(mongo_url).await {
                Ok(()) => return Ok(()),
                Err(e) => {
                    last_err = e.to_string();
                    eprintln!(
                        "start_gateway_plaintext attempt {}/{} failed: {}",
                        attempt, MAX_ATTEMPTS, last_err
                    );
                    if attempt < MAX_ATTEMPTS {
                        self.reallocate_ports().await?;
                        tokio::time::sleep(std::time::Duration::from_secs(1)).await;
                    }
                }
            }
        }
        Err(format!(
            "Failed to start gateway (plaintext) after {} attempts: {}",
            MAX_ATTEMPTS, last_err
        )
        .into())
    }

    async fn try_start_gateway_plaintext(
        &mut self,
        mongo_url: &str,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let binary_path = find_binary()?;

        let child = Command::new(binary_path)
            .env("FERRUM_MODE", "database")
            .env("FERRUM_ADMIN_JWT_SECRET", &self.jwt_secret)
            .env("FERRUM_ADMIN_JWT_ISSUER", &self.jwt_issuer)
            .env("FERRUM_DB_TYPE", "mongodb")
            .env("FERRUM_DB_URL", mongo_url)
            .env("FERRUM_MONGO_DATABASE", DEFAULT_MONGO_DATABASE)
            .env("FERRUM_DB_POLL_INTERVAL", "2")
            .env("FERRUM_PROXY_HTTP_PORT", self.proxy_port.to_string())
            .env("FERRUM_ADMIN_HTTP_PORT", self.admin_port.to_string())
            .env("FERRUM_LOG_LEVEL", "info")
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()?;

        self.gateway_process = Some(child);
        match self.wait_for_health().await {
            Ok(()) => Ok(()),
            Err(e) => {
                if let Some(mut child) = self.gateway_process.take() {
                    let _ = child.kill();
                    let _ = child.wait();
                }
                Err(e)
            }
        }
    }

    /// Start the gateway with TLS-encrypted MongoDB connection.
    /// Retries up to 3 times with fresh ports to handle ephemeral port races.
    async fn start_gateway_tls(
        &mut self,
        mongo_url: &str,
        cert_dir: &str,
        insecure: bool,
    ) -> Result<(), Box<dyn std::error::Error>> {
        const MAX_ATTEMPTS: u32 = 3;
        let mut last_err = String::new();
        for attempt in 1..=MAX_ATTEMPTS {
            match self
                .try_start_gateway_tls(mongo_url, cert_dir, insecure)
                .await
            {
                Ok(()) => return Ok(()),
                Err(e) => {
                    last_err = e.to_string();
                    eprintln!(
                        "start_gateway_tls attempt {}/{} failed: {}",
                        attempt, MAX_ATTEMPTS, last_err
                    );
                    if attempt < MAX_ATTEMPTS {
                        self.reallocate_ports().await?;
                        tokio::time::sleep(std::time::Duration::from_secs(1)).await;
                    }
                }
            }
        }
        Err(format!(
            "Failed to start gateway (tls) after {} attempts: {}",
            MAX_ATTEMPTS, last_err
        )
        .into())
    }

    async fn try_start_gateway_tls(
        &mut self,
        mongo_url: &str,
        cert_dir: &str,
        insecure: bool,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let binary_path = find_binary()?;
        let ca_cert_path = format!("{}/ca.crt", cert_dir);

        let child = Command::new(binary_path)
            .env("FERRUM_MODE", "database")
            .env("FERRUM_ADMIN_JWT_SECRET", &self.jwt_secret)
            .env("FERRUM_ADMIN_JWT_ISSUER", &self.jwt_issuer)
            .env("FERRUM_DB_TYPE", "mongodb")
            .env("FERRUM_DB_URL", mongo_url)
            .env("FERRUM_MONGO_DATABASE", DEFAULT_MONGO_DATABASE)
            .env("FERRUM_DB_POLL_INTERVAL", "2")
            .env("FERRUM_PROXY_HTTP_PORT", self.proxy_port.to_string())
            .env("FERRUM_ADMIN_HTTP_PORT", self.admin_port.to_string())
            .env("FERRUM_LOG_LEVEL", "info")
            .env("FERRUM_DB_TLS_ENABLED", "true")
            .env("FERRUM_DB_TLS_CA_CERT_PATH", &ca_cert_path)
            .env(
                "FERRUM_DB_TLS_INSECURE",
                if insecure { "true" } else { "false" },
            )
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()?;

        self.gateway_process = Some(child);
        match self.wait_for_health().await {
            Ok(()) => Ok(()),
            Err(e) => {
                if let Some(mut child) = self.gateway_process.take() {
                    let _ = child.kill();
                    let _ = child.wait();
                }
                Err(e)
            }
        }
    }

    /// Start the gateway with mTLS MongoDB connection (client certificate auth).
    /// Retries up to 3 times with fresh ports to handle ephemeral port races.
    async fn start_gateway_mtls(
        &mut self,
        mongo_url: &str,
        cert_dir: &str,
    ) -> Result<(), Box<dyn std::error::Error>> {
        const MAX_ATTEMPTS: u32 = 3;
        let mut last_err = String::new();
        for attempt in 1..=MAX_ATTEMPTS {
            match self.try_start_gateway_mtls(mongo_url, cert_dir).await {
                Ok(()) => return Ok(()),
                Err(e) => {
                    last_err = e.to_string();
                    eprintln!(
                        "start_gateway_mtls attempt {}/{} failed: {}",
                        attempt, MAX_ATTEMPTS, last_err
                    );
                    if attempt < MAX_ATTEMPTS {
                        self.reallocate_ports().await?;
                        tokio::time::sleep(std::time::Duration::from_secs(1)).await;
                    }
                }
            }
        }
        Err(format!(
            "Failed to start gateway (mtls) after {} attempts: {}",
            MAX_ATTEMPTS, last_err
        )
        .into())
    }

    async fn try_start_gateway_mtls(
        &mut self,
        mongo_url: &str,
        cert_dir: &str,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let binary_path = find_binary()?;
        let ca_cert_path = format!("{}/ca.crt", cert_dir);
        let client_cert_path = format!("{}/client.crt", cert_dir);
        let client_key_path = format!("{}/client.key", cert_dir);

        let child = Command::new(binary_path)
            .env("FERRUM_MODE", "database")
            .env("FERRUM_ADMIN_JWT_SECRET", &self.jwt_secret)
            .env("FERRUM_ADMIN_JWT_ISSUER", &self.jwt_issuer)
            .env("FERRUM_DB_TYPE", "mongodb")
            .env("FERRUM_DB_URL", mongo_url)
            .env("FERRUM_MONGO_DATABASE", DEFAULT_MONGO_DATABASE)
            .env("FERRUM_DB_POLL_INTERVAL", "2")
            .env("FERRUM_PROXY_HTTP_PORT", self.proxy_port.to_string())
            .env("FERRUM_ADMIN_HTTP_PORT", self.admin_port.to_string())
            .env("FERRUM_LOG_LEVEL", "info")
            .env("FERRUM_DB_TLS_ENABLED", "true")
            .env("FERRUM_DB_TLS_CA_CERT_PATH", &ca_cert_path)
            .env("FERRUM_DB_TLS_CLIENT_CERT_PATH", &client_cert_path)
            .env("FERRUM_DB_TLS_CLIENT_KEY_PATH", &client_key_path)
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()?;

        self.gateway_process = Some(child);
        match self.wait_for_health().await {
            Ok(()) => Ok(()),
            Err(e) => {
                if let Some(mut child) = self.gateway_process.take() {
                    let _ = child.kill();
                    let _ = child.wait();
                }
                Err(e)
            }
        }
    }

    /// Reallocate ephemeral ports after a failed startup attempt.
    async fn reallocate_ports(&mut self) -> Result<(), Box<dyn std::error::Error>> {
        let admin_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
        self.admin_port = admin_listener.local_addr()?.port();
        drop(admin_listener);

        let proxy_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
        self.proxy_port = proxy_listener.local_addr()?.port();
        drop(proxy_listener);

        self.admin_base_url = format!("http://127.0.0.1:{}", self.admin_port);
        self.proxy_base_url = format!("http://127.0.0.1:{}", self.proxy_port);
        Ok(())
    }

    async fn wait_for_health(&self) -> Result<(), Box<dyn std::error::Error>> {
        let health_url = format!("{}/health", self.admin_base_url);
        let deadline = SystemTime::now() + Duration::from_secs(30);

        loop {
            if SystemTime::now() >= deadline {
                return Err("Gateway (mongodb) did not start within 30 seconds".into());
            }

            match reqwest::get(&health_url).await {
                Ok(response) if response.status().is_success() => {
                    println!("  Gateway (mongodb) is ready!");
                    return Ok(());
                }
                _ => {
                    tokio::time::sleep(Duration::from_millis(500)).await;
                }
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

impl Drop for MongoTestHarness {
    fn drop(&mut self) {
        if let Some(mut child) = self.gateway_process.take() {
            let _ = child.kill();
            let _ = child.wait();
        }
    }
}

fn find_binary() -> Result<&'static str, Box<dyn std::error::Error>> {
    if std::path::Path::new("./target/debug/ferrum-edge").exists() {
        Ok("./target/debug/ferrum-edge")
    } else if std::path::Path::new("./target/release/ferrum-edge").exists() {
        Ok("./target/release/ferrum-edge")
    } else {
        Err("ferrum-edge binary not found. Run `cargo build` first.".into())
    }
}

/// Create a simple echo HTTP server for backend testing.
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
                let mut line = String::new();

                if buf_reader.read_line(&mut line).await.is_err() {
                    return;
                }

                // Read headers until blank line
                loop {
                    line.clear();
                    if buf_reader.read_line(&mut line).await.is_err() {
                        return;
                    }
                    if line == "\r\n" || line == "\n" {
                        break;
                    }
                }

                let body = r#"{"status":"ok","backend":"echo","db":"mongodb"}"#;
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

/// Run the full CRUD + proxy routing test suite against a running harness.
async fn run_crud_and_proxy_tests(
    harness: &MongoTestHarness,
    backend_port: u16,
    test_prefix: &str,
) {
    let client = reqwest::Client::new();
    let token = harness.generate_token().expect("Failed to generate token");
    let auth_header = format!("Bearer {}", token);

    // Use unique IDs per test run to avoid conflicts
    let run_id = Uuid::new_v4().to_string()[..8].to_string();
    let proxy_id = format!("{}-proxy-{}", test_prefix, run_id);
    let consumer_id = format!("{}-consumer-{}", test_prefix, run_id);
    let plugin_id = format!("{}-plugin-{}", test_prefix, run_id);

    // Test 1: Health check reports MongoDB
    println!("\n--- {}: Health Check ---", test_prefix);
    let resp = client
        .get(format!("{}/health", harness.admin_base_url))
        .send()
        .await
        .expect("Health check failed");
    assert!(resp.status().is_success());
    let health: serde_json::Value = resp.json().await.expect("Parse health");
    assert_eq!(health["status"], "ok");
    assert_eq!(health["database"]["status"], "connected");
    assert_eq!(health["database"]["type"], "mongodb");
    println!("  OK: Health reports mongodb connected");

    // Test 2: Create proxy
    println!("\n--- {}: Create Proxy ---", test_prefix);
    let resp = client
        .post(format!("{}/proxies", harness.admin_base_url))
        .header("Authorization", &auth_header)
        .json(&json!({
            "id": &proxy_id,
            "name": format!("{}-test", test_prefix),
            "listen_path": format!("/mongo-test-{}", run_id),
            "backend_protocol": "http",
            "backend_host": "127.0.0.1",
            "backend_port": backend_port,
            "strip_listen_path": true,
        }))
        .send()
        .await
        .expect("Create proxy failed");
    assert!(
        resp.status().is_success(),
        "Create proxy: {}",
        resp.status()
    );
    println!("  OK: Proxy created");

    // Test 3: Read proxy back
    println!("\n--- {}: Get Proxy ---", test_prefix);
    let resp = client
        .get(format!("{}/proxies/{}", harness.admin_base_url, proxy_id))
        .header("Authorization", &auth_header)
        .send()
        .await
        .expect("Get proxy failed");
    let status = resp.status();
    let body = resp.text().await.unwrap_or_default();
    assert!(
        status.is_success(),
        "Get proxy failed with {}: {}",
        status,
        body
    );
    let proxy: serde_json::Value = serde_json::from_str(&body).expect("Parse proxy");
    assert_eq!(proxy["id"], proxy_id);
    println!("  OK: Proxy retrieved from MongoDB");

    // Test 4: Create consumer
    println!("\n--- {}: Create Consumer ---", test_prefix);
    let resp = client
        .post(format!("{}/consumers", harness.admin_base_url))
        .header("Authorization", &auth_header)
        .json(&json!({
            "id": &consumer_id,
            "username": format!("user-{}", run_id),
            "custom_id": format!("custom-{}", run_id),
        }))
        .send()
        .await
        .expect("Create consumer failed");
    assert!(
        resp.status().is_success(),
        "Create consumer: {}",
        resp.status()
    );
    println!("  OK: Consumer created");

    // Test 5: Read consumer back
    let resp = client
        .get(format!(
            "{}/consumers/{}",
            harness.admin_base_url, consumer_id
        ))
        .header("Authorization", &auth_header)
        .send()
        .await
        .expect("Get consumer failed");
    assert!(resp.status().is_success());
    let consumer: serde_json::Value = resp.json().await.expect("Parse consumer");
    assert_eq!(consumer["id"], consumer_id);
    println!("  OK: Consumer retrieved from MongoDB");

    // Test 6: Create plugin config
    println!("\n--- {}: Create Plugin Config ---", test_prefix);
    let resp = client
        .post(format!("{}/plugins/config", harness.admin_base_url))
        .header("Authorization", &auth_header)
        .json(&json!({
            "id": &plugin_id,
            "plugin_name": "rate_limiting",
            "scope": "proxy",
            "proxy_id": &proxy_id,
            "enabled": true,
            "config": {
                "requests_per_minute": 100,
                "limit_by": "ip"
            }
        }))
        .send()
        .await
        .expect("Create plugin config failed");
    assert!(
        resp.status().is_success(),
        "Create plugin: {}",
        resp.status()
    );
    println!("  OK: Plugin config created");

    // Test 7: Wait for DB poll and route through proxy
    println!("\n--- {}: Route Traffic Through Proxy ---", test_prefix);
    tokio::time::sleep(Duration::from_secs(3)).await;

    let resp = client
        .get(format!("{}/mongo-test-{}", harness.proxy_base_url, run_id))
        .send()
        .await
        .expect("Proxy request failed");
    assert!(
        resp.status().is_success(),
        "Proxy routing failed: {}",
        resp.status()
    );
    let body: serde_json::Value = resp.json().await.expect("Parse proxy response");
    assert_eq!(body["db"], "mongodb");
    println!("  OK: Traffic routed through MongoDB-backed proxy");

    // Test 8: Update proxy
    println!("\n--- {}: Update Proxy ---", test_prefix);
    let resp = client
        .put(format!("{}/proxies/{}", harness.admin_base_url, proxy_id))
        .header("Authorization", &auth_header)
        .json(&json!({
            "id": &proxy_id,
            "name": format!("{}-updated", test_prefix),
            "listen_path": format!("/mongo-test-{}", run_id),
            "backend_protocol": "http",
            "backend_host": "127.0.0.1",
            "backend_port": backend_port,
            "strip_listen_path": false,
        }))
        .send()
        .await
        .expect("Update proxy failed");
    assert!(
        resp.status().is_success(),
        "Update proxy: {}",
        resp.status()
    );
    println!("  OK: Proxy updated");

    // Test 9: Delete resources
    println!("\n--- {}: Delete Resources ---", test_prefix);
    let resp = client
        .delete(format!(
            "{}/plugins/config/{}",
            harness.admin_base_url, plugin_id
        ))
        .header("Authorization", &auth_header)
        .send()
        .await
        .expect("Delete plugin failed");
    assert!(resp.status().is_success(), "Delete plugin");

    let resp = client
        .delete(format!("{}/proxies/{}", harness.admin_base_url, proxy_id))
        .header("Authorization", &auth_header)
        .send()
        .await
        .expect("Delete proxy failed");
    assert!(resp.status().is_success(), "Delete proxy");

    let resp = client
        .delete(format!(
            "{}/consumers/{}",
            harness.admin_base_url, consumer_id
        ))
        .header("Authorization", &auth_header)
        .send()
        .await
        .expect("Delete consumer failed");
    assert!(resp.status().is_success(), "Delete consumer");
    println!("  OK: All resources deleted");

    // Verify deletion
    tokio::time::sleep(Duration::from_secs(1)).await;
    let resp = client
        .get(format!("{}/proxies/{}", harness.admin_base_url, proxy_id))
        .header("Authorization", &auth_header)
        .send()
        .await
        .expect("Get deleted proxy");
    assert_eq!(
        resp.status().as_u16(),
        404,
        "Proxy should be 404 after delete"
    );
    println!("  OK: Deletion verified");
}

// ==========================================================================
// Test: Plaintext MongoDB Connection
// ==========================================================================

#[tokio::test]
#[ignore]
async fn test_mongodb_plaintext_full_lifecycle() {
    println!("\n=== MongoDB Plaintext Functional Test ===\n");

    let mongo_url =
        std::env::var("FERRUM_TEST_MONGO_URL").unwrap_or_else(|_| DEFAULT_MONGO_URL.to_string());

    if !mongodb_is_available(&mongo_url).await {
        return;
    }

    // Start echo backend
    let backend_listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("Bind backend");
    let backend_port = backend_listener.local_addr().expect("Backend addr").port();
    drop(backend_listener);
    let _backend = start_echo_backend(backend_port).await.expect("Start echo");
    println!("Echo backend on port {}", backend_port);

    // Start gateway
    let mut harness = MongoTestHarness::new().await.expect("Create harness");
    harness
        .start_gateway_plaintext(&mongo_url)
        .await
        .expect("Start gateway with MongoDB");

    println!(
        "Gateway started (admin={}, proxy={})",
        harness.admin_port, harness.proxy_port
    );

    // Run full test suite
    run_crud_and_proxy_tests(&harness, backend_port, "plaintext").await;

    println!("\n=== MongoDB Plaintext Test PASSED ===\n");
}

// ==========================================================================
// Test: TLS MongoDB Connection
// ==========================================================================

#[tokio::test]
#[ignore]
async fn test_mongodb_tls_connection() {
    println!("\n=== MongoDB TLS Functional Test ===\n");

    let mongo_url = std::env::var("FERRUM_TEST_MONGO_TLS_URL")
        .unwrap_or_else(|_| "mongodb://localhost:27018/ferrum_test".to_string());
    let cert_dir = std::env::var("FERRUM_TEST_MONGO_CERT_DIR")
        .unwrap_or_else(|_| DEFAULT_CERT_DIR.to_string());

    if !std::path::Path::new(&format!("{}/ca.crt", cert_dir)).exists() {
        println!(
            "SKIP: TLS certs not found at {}. Run setup_mongo_tls.sh first.",
            cert_dir
        );
        return;
    }

    if !mongodb_is_available(&mongo_url).await {
        return;
    }

    let backend_listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("Bind backend");
    let backend_port = backend_listener.local_addr().expect("Backend addr").port();
    drop(backend_listener);
    let _backend = start_echo_backend(backend_port).await.expect("Start echo");

    let mut harness = MongoTestHarness::new().await.expect("Create harness");
    harness
        .start_gateway_tls(&mongo_url, &cert_dir, false)
        .await
        .expect("Start gateway with MongoDB TLS");

    run_crud_and_proxy_tests(&harness, backend_port, "tls").await;

    println!("\n=== MongoDB TLS Test PASSED ===\n");
}

// ==========================================================================
// Test: mTLS MongoDB Connection (Client Certificate Authentication)
// ==========================================================================

#[tokio::test]
#[ignore]
async fn test_mongodb_mtls_connection() {
    println!("\n=== MongoDB mTLS Functional Test ===\n");

    let mongo_url = std::env::var("FERRUM_TEST_MONGO_MTLS_URL")
        .unwrap_or_else(|_| "mongodb://localhost:27019/ferrum_test".to_string());
    let cert_dir = std::env::var("FERRUM_TEST_MONGO_CERT_DIR")
        .unwrap_or_else(|_| DEFAULT_CERT_DIR.to_string());

    if !std::path::Path::new(&format!("{}/client.crt", cert_dir)).exists() {
        println!(
            "SKIP: mTLS client certs not found at {}. Run setup_mongo_tls.sh first.",
            cert_dir
        );
        return;
    }

    if !mongodb_is_available(&mongo_url).await {
        return;
    }

    let backend_listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("Bind backend");
    let backend_port = backend_listener.local_addr().expect("Backend addr").port();
    drop(backend_listener);
    let _backend = start_echo_backend(backend_port).await.expect("Start echo");

    let mut harness = MongoTestHarness::new().await.expect("Create harness");
    harness
        .start_gateway_mtls(&mongo_url, &cert_dir)
        .await
        .expect("Start gateway with MongoDB mTLS");

    run_crud_and_proxy_tests(&harness, backend_port, "mtls").await;

    println!("\n=== MongoDB mTLS Test PASSED ===\n");
}
