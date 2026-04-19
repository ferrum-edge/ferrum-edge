//! Database TLS Functional Tests
//!
//! Verifies that ferrum-edge can connect to PostgreSQL, MySQL, and SQLite
//! databases with proper TLS configuration, perform Admin API CRUD operations,
//! and route proxy traffic through each database-backed mode.
//!
//! Prerequisites:
//!   1. Run `tests/scripts/setup_db_tls.sh` to start TLS-enabled DB containers
//!   2. Build the gateway: `cargo build`
//!
//! Run with:
//!   cargo test --test functional_tests functional_db_tls -- --ignored --nocapture

use crate::common::{DbType, TestGateway};
use chrono::Utc;
use jsonwebtoken::{EncodingKey, Header, encode};
use serde_json::json;
use std::process::Command;
use std::time::Duration;
use tempfile::TempDir;
use uuid::Uuid;

/// Default certificate directory used by setup_db_tls.sh
const DEFAULT_CERT_DIR: &str = "/tmp/ferrum-db-tls-certs";

/// Test harness for database TLS functional testing.
///
/// Manages a gateway process connected to a specific database type with TLS,
/// plus a local echo backend for proxy routing verification.
struct DbTlsTestHarness {
    temp_dir: TempDir,
    gw: Option<TestGateway>,
    proxy_base_url: String,
    admin_base_url: String,
    jwt_secret: String,
    jwt_issuer: String,
    db_type: String,
}

impl DbTlsTestHarness {
    async fn new(db_type: &str) -> Result<Self, Box<dyn std::error::Error>> {
        let temp_dir = TempDir::new()?;
        let jwt_secret = "db-tls-test-secret-key-1234567890".to_string();
        let jwt_issuer = "ferrum-edge-db-tls-test".to_string();

        Ok(Self {
            temp_dir,
            gw: None,
            proxy_base_url: String::new(),
            admin_base_url: String::new(),
            jwt_secret,
            jwt_issuer,
            db_type: db_type.to_string(),
        })
    }

    async fn start_gateway_with_envs(
        &mut self,
        db_url: &str,
        extra_env: Vec<(String, String)>,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let mut builder = TestGateway::builder()
            .mode_database(DbType::Custom {
                db_type: self.db_type.clone(),
                db_url: db_url.to_string(),
            })
            .jwt_secret(&self.jwt_secret)
            .jwt_issuer(&self.jwt_issuer)
            .db_poll_interval_seconds(2)
            .log_level("info");
        for (key, value) in extra_env {
            builder = builder.env(key, value);
        }
        let gw = builder.spawn().await?;
        self.proxy_base_url = gw.proxy_base_url.clone();
        self.admin_base_url = gw.admin_base_url.clone();
        self.gw = Some(gw);
        Ok(())
    }

    /// Start the gateway with TLS-enabled database connection, with retry for ephemeral port races.
    async fn start_gateway(
        &mut self,
        db_url: &str,
        cert_dir: &str,
        ssl_mode: &str,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let ca_cert_path = format!("{}/ca.crt", cert_dir);
        let mut extra_env = Vec::new();
        if self.db_type != "sqlite" {
            extra_env.push(("FERRUM_DB_SSL_MODE".to_string(), ssl_mode.to_string()));
            extra_env.push(("FERRUM_DB_SSL_ROOT_CERT".to_string(), ca_cert_path));
        }
        self.start_gateway_with_envs(db_url, extra_env).await
    }

    /// Start the gateway with the legacy TLS approach, with retry for ephemeral port races.
    async fn start_gateway_legacy_tls(
        &mut self,
        db_url: &str,
        cert_dir: &str,
        insecure: bool,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let ca_cert_path = format!("{}/ca.crt", cert_dir);
        self.start_gateway_with_envs(
            db_url,
            vec![
                ("FERRUM_DB_TLS_ENABLED".to_string(), "true".to_string()),
                ("FERRUM_DB_TLS_CA_CERT_PATH".to_string(), ca_cert_path),
                (
                    "FERRUM_DB_TLS_INSECURE".to_string(),
                    if insecure { "true" } else { "false" }.to_string(),
                ),
            ],
        )
        .await
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

/// Simple echo backend for proxy routing verification.
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

/// Check if a Docker container is running and healthy.
fn is_container_running(name: &str) -> bool {
    Command::new("docker")
        .args(["inspect", "--format", "{{.State.Running}}", name])
        .output()
        .map(|o| String::from_utf8_lossy(&o.stdout).trim() == "true")
        .unwrap_or(false)
}

/// Get the certificate directory from env or use default.
fn cert_dir() -> String {
    std::env::var("FERRUM_TEST_CERT_DIR").unwrap_or_else(|_| DEFAULT_CERT_DIR.to_string())
}

/// Run the full CRUD + proxy routing test suite against a running gateway.
async fn run_crud_and_proxy_tests(
    db_label: &str,
    admin_base_url: &str,
    proxy_base_url: &str,
    auth_header: &str,
    backend_port: u16,
) {
    let client = reqwest::Client::new();
    let test_id = Uuid::new_v4().to_string();
    let proxy_id = format!("tls-proxy-{}", &test_id[..8]);
    let consumer_id = format!("tls-consumer-{}", &test_id[..8]);
    let upstream_id = format!("tls-upstream-{}", &test_id[..8]);
    let plugin_id = format!("tls-plugin-{}", &test_id[..8]);

    // --- Create upstream ---
    println!("  [{db_label}] Creating upstream...");
    let upstream_data = json!({
        "id": upstream_id,
        "name": format!("tls-test-upstream-{}", &test_id[..8]),
        "targets": [
            {"host": "localhost", "port": backend_port, "weight": 100}
        ],
        "algorithm": "round_robin"
    });

    let response = client
        .post(format!("{}/upstreams", admin_base_url))
        .header("Authorization", auth_header)
        .json(&upstream_data)
        .send()
        .await
        .expect("Failed to create upstream");
    assert!(
        response.status().is_success(),
        "[{db_label}] Failed to create upstream: {} - {}",
        response.status(),
        response.text().await.unwrap_or_default()
    );
    println!("  [{db_label}] Upstream created");

    // --- Create proxy ---
    println!("  [{db_label}] Creating proxy...");
    let proxy_data = json!({
        "id": proxy_id,
        "listen_path": format!("/tls-test-{}", &test_id[..8]),
        "backend_protocol": "http",
        "backend_host": "localhost",
        "backend_port": backend_port,
        "strip_listen_path": true,
    });

    let response = client
        .post(format!("{}/proxies", admin_base_url))
        .header("Authorization", auth_header)
        .json(&proxy_data)
        .send()
        .await
        .expect("Failed to create proxy");
    assert!(
        response.status().is_success(),
        "[{db_label}] Failed to create proxy: {} - {}",
        response.status(),
        response.text().await.unwrap_or_default()
    );
    println!("  [{db_label}] Proxy created");

    // --- Read proxy back ---
    println!("  [{db_label}] Reading proxy...");
    let response = client
        .get(format!("{}/proxies/{}", admin_base_url, proxy_id))
        .header("Authorization", auth_header)
        .send()
        .await
        .expect("Failed to get proxy");
    assert!(
        response.status().is_success(),
        "[{db_label}] Failed to get proxy"
    );
    let proxy_json: serde_json::Value = response.json().await.expect("Failed to parse proxy");
    assert_eq!(proxy_json["id"], proxy_id);
    println!("  [{db_label}] Proxy read back successfully");

    // --- Create consumer ---
    println!("  [{db_label}] Creating consumer...");
    let consumer_data = json!({
        "id": consumer_id,
        "username": format!("tls-user-{}", &test_id[..8]),
        "custom_id": format!("tls-custom-{}", &test_id[..8]),
    });

    let response = client
        .post(format!("{}/consumers", admin_base_url))
        .header("Authorization", auth_header)
        .json(&consumer_data)
        .send()
        .await
        .expect("Failed to create consumer");
    assert!(
        response.status().is_success(),
        "[{db_label}] Failed to create consumer: {} - {}",
        response.status(),
        response.text().await.unwrap_or_default()
    );
    println!("  [{db_label}] Consumer created");

    // --- Read consumer back ---
    let response = client
        .get(format!("{}/consumers/{}", admin_base_url, consumer_id))
        .header("Authorization", auth_header)
        .send()
        .await
        .expect("Failed to get consumer");
    assert!(
        response.status().is_success(),
        "[{db_label}] Failed to get consumer"
    );
    let consumer_json: serde_json::Value = response.json().await.expect("Failed to parse consumer");
    assert_eq!(consumer_json["id"], consumer_id);
    println!("  [{db_label}] Consumer read back successfully");

    // --- Create plugin config ---
    println!("  [{db_label}] Creating plugin config...");
    let plugin_data = json!({
        "id": plugin_id,
        "plugin_name": "rate_limiting",
        "scope": "proxy",
        "proxy_id": proxy_id,
        "enabled": true,
        "config": {
            "requests_per_minute": 1000,
            "limit_by": "ip"
        }
    });

    let response = client
        .post(format!("{}/plugins/config", admin_base_url))
        .header("Authorization", auth_header)
        .json(&plugin_data)
        .send()
        .await
        .expect("Failed to create plugin config");
    assert!(
        response.status().is_success(),
        "[{db_label}] Failed to create plugin config: {} - {}",
        response.status(),
        response.text().await.unwrap_or_default()
    );
    println!("  [{db_label}] Plugin config created");

    // --- Read plugin config back ---
    let response = client
        .get(format!("{}/plugins/config/{}", admin_base_url, plugin_id))
        .header("Authorization", auth_header)
        .send()
        .await
        .expect("Failed to get plugin config");
    assert!(
        response.status().is_success(),
        "[{db_label}] Failed to get plugin config"
    );
    let plugin_json: serde_json::Value = response
        .json()
        .await
        .expect("Failed to parse plugin config");
    assert_eq!(plugin_json["id"], plugin_id);
    println!("  [{db_label}] Plugin config read back successfully");

    // --- Wait for DB poll and verify proxy routing ---
    println!("  [{db_label}] Waiting for DB poll to pick up proxy...");
    tokio::time::sleep(Duration::from_secs(3)).await;

    let listen_path = format!("/tls-test-{}", &test_id[..8]);
    let proxy_response = client
        .get(format!("{}{}", proxy_base_url, listen_path))
        .send()
        .await
        .expect("Failed to send request through proxy");
    assert!(
        proxy_response.status().is_success(),
        "[{db_label}] Proxy routing failed: {}",
        proxy_response.status()
    );
    let response_body: serde_json::Value = proxy_response
        .json()
        .await
        .expect("Failed to parse proxy response");
    assert!(response_body["echo"].as_bool().unwrap_or(false));
    println!("  [{db_label}] Proxy routing verified through TLS-connected database");

    // --- Update proxy ---
    println!("  [{db_label}] Updating proxy...");
    let updated_proxy = json!({
        "id": proxy_id,
        "listen_path": format!("/tls-test-{}", &test_id[..8]),
        "backend_protocol": "http",
        "backend_host": "localhost",
        "backend_port": backend_port,
        "strip_listen_path": false,
    });

    let response = client
        .put(format!("{}/proxies/{}", admin_base_url, proxy_id))
        .header("Authorization", auth_header)
        .json(&updated_proxy)
        .send()
        .await
        .expect("Failed to update proxy");
    assert!(
        response.status().is_success(),
        "[{db_label}] Failed to update proxy"
    );
    println!("  [{db_label}] Proxy updated");

    // --- Verify update ---
    let response = client
        .get(format!("{}/proxies/{}", admin_base_url, proxy_id))
        .header("Authorization", auth_header)
        .send()
        .await
        .expect("Failed to get updated proxy");
    let proxy_json: serde_json::Value = response.json().await.expect("Failed to parse");
    assert!(!proxy_json["strip_listen_path"].as_bool().unwrap_or(true));
    println!("  [{db_label}] Update verified");

    // --- List all resources ---
    println!("  [{db_label}] Listing resources...");
    for (endpoint, label) in &[
        ("proxies", "proxies"),
        ("consumers", "consumers"),
        ("upstreams", "upstreams"),
        ("plugins/config", "plugin configs"),
    ] {
        let response = client
            .get(format!("{}/{}", admin_base_url, endpoint))
            .header("Authorization", auth_header)
            .send()
            .await
            .unwrap_or_else(|_| panic!("Failed to list {label}"));
        assert!(
            response.status().is_success(),
            "[{db_label}] Failed to list {label}"
        );
        let items: serde_json::Value = response.json().await.expect("Failed to parse");
        assert!(
            items.is_array(),
            "[{db_label}] {label} response should be array"
        );
        println!(
            "  [{db_label}] Listed {} {label}",
            items.as_array().unwrap().len()
        );
    }

    // --- Cleanup: delete resources ---
    println!("  [{db_label}] Cleaning up resources...");
    let _ = client
        .delete(format!("{}/plugins/config/{}", admin_base_url, plugin_id))
        .header("Authorization", auth_header)
        .send()
        .await;
    let _ = client
        .delete(format!("{}/proxies/{}", admin_base_url, proxy_id))
        .header("Authorization", auth_header)
        .send()
        .await;
    let _ = client
        .delete(format!("{}/consumers/{}", admin_base_url, consumer_id))
        .header("Authorization", auth_header)
        .send()
        .await;
    let _ = client
        .delete(format!("{}/upstreams/{}", admin_base_url, upstream_id))
        .header("Authorization", auth_header)
        .send()
        .await;
    println!("  [{db_label}] Cleanup complete");
}

// ============================================================================
// PostgreSQL TLS Tests
// ============================================================================

#[tokio::test]
#[ignore]
async fn test_postgresql_tls_verify_full() {
    println!("\n=== PostgreSQL TLS (verify-full via FERRUM_DB_SSL_*) ===\n");

    if !is_container_running("ferrum-test-pg-tls") {
        println!("SKIPPED: ferrum-test-pg-tls container not running.");
        println!("Run: tests/scripts/setup_db_tls.sh");
        return;
    }

    let certs = cert_dir();
    assert!(
        std::path::Path::new(&format!("{}/ca.crt", certs)).exists(),
        "CA cert not found at {}/ca.crt",
        certs
    );

    let mut harness = DbTlsTestHarness::new("postgres")
        .await
        .expect("Failed to create harness");

    // Start echo backend
    let backend_listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("Failed to bind backend");
    let backend_port = backend_listener.local_addr().unwrap().port();
    drop(backend_listener);
    let _backend = start_echo_backend(backend_port).await.unwrap();

    let db_url = "postgres://ferrum:test-password@localhost:15432/ferrum";

    harness
        .start_gateway(db_url, &certs, "verify-full")
        .await
        .expect("Failed to start gateway with PostgreSQL TLS (verify-full)");

    let token = harness.generate_token().unwrap();
    let auth = format!("Bearer {}", token);

    run_crud_and_proxy_tests(
        "PostgreSQL/verify-full",
        &harness.admin_base_url,
        &harness.proxy_base_url,
        &auth,
        backend_port,
    )
    .await;

    println!("\n=== PostgreSQL TLS (verify-full) PASSED ===\n");
}

#[tokio::test]
#[ignore]
async fn test_postgresql_tls_require() {
    println!("\n=== PostgreSQL TLS (require — encrypted, no cert verification) ===\n");

    if !is_container_running("ferrum-test-pg-tls") {
        println!("SKIPPED: ferrum-test-pg-tls container not running.");
        println!("Run: tests/scripts/setup_db_tls.sh");
        return;
    }

    let mut harness = DbTlsTestHarness::new("postgres")
        .await
        .expect("Failed to create harness");

    let backend_listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("Failed to bind backend");
    let backend_port = backend_listener.local_addr().unwrap().port();
    drop(backend_listener);
    let _backend = start_echo_backend(backend_port).await.unwrap();

    let db_url = "postgres://ferrum:test-password@localhost:15432/ferrum";

    harness
        .start_gateway(db_url, &cert_dir(), "require")
        .await
        .expect("Failed to start gateway with PostgreSQL TLS (require)");

    let token = harness.generate_token().unwrap();
    let auth = format!("Bearer {}", token);

    run_crud_and_proxy_tests(
        "PostgreSQL/require",
        &harness.admin_base_url,
        &harness.proxy_base_url,
        &auth,
        backend_port,
    )
    .await;

    println!("\n=== PostgreSQL TLS (require) PASSED ===\n");
}

#[tokio::test]
#[ignore]
async fn test_postgresql_tls_legacy_insecure() {
    println!("\n=== PostgreSQL TLS (legacy FERRUM_DB_TLS_* with insecure=true) ===\n");

    if !is_container_running("ferrum-test-pg-tls") {
        println!("SKIPPED: ferrum-test-pg-tls container not running.");
        println!("Run: tests/scripts/setup_db_tls.sh");
        return;
    }

    let mut harness = DbTlsTestHarness::new("postgres")
        .await
        .expect("Failed to create harness");

    let backend_listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("Failed to bind backend");
    let backend_port = backend_listener.local_addr().unwrap().port();
    drop(backend_listener);
    let _backend = start_echo_backend(backend_port).await.unwrap();

    let db_url = "postgres://ferrum:test-password@localhost:15432/ferrum";

    harness
        .start_gateway_legacy_tls(db_url, &cert_dir(), true)
        .await
        .expect("Failed to start gateway with PostgreSQL legacy TLS");

    let token = harness.generate_token().unwrap();
    let auth = format!("Bearer {}", token);

    run_crud_and_proxy_tests(
        "PostgreSQL/legacy-insecure",
        &harness.admin_base_url,
        &harness.proxy_base_url,
        &auth,
        backend_port,
    )
    .await;

    println!("\n=== PostgreSQL TLS (legacy insecure) PASSED ===\n");
}

// ============================================================================
// MySQL TLS Tests
// ============================================================================

#[tokio::test]
#[ignore]
async fn test_mysql_tls_verify_identity() {
    println!("\n=== MySQL TLS (verify-full → VERIFY_IDENTITY via FERRUM_DB_SSL_*) ===\n");

    if !is_container_running("ferrum-test-mysql-tls") {
        println!("SKIPPED: ferrum-test-mysql-tls container not running.");
        println!("Run: tests/scripts/setup_db_tls.sh");
        return;
    }

    let certs = cert_dir();
    assert!(
        std::path::Path::new(&format!("{}/ca.crt", certs)).exists(),
        "CA cert not found"
    );

    let mut harness = DbTlsTestHarness::new("mysql")
        .await
        .expect("Failed to create harness");

    let backend_listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("Failed to bind backend");
    let backend_port = backend_listener.local_addr().unwrap().port();
    drop(backend_listener);
    let _backend = start_echo_backend(backend_port).await.unwrap();

    // sqlx MySQL URL format
    let db_url = "mysql://ferrum:test-password@localhost:13306/ferrum";

    harness
        .start_gateway(db_url, &certs, "verify-full")
        .await
        .expect("Failed to start gateway with MySQL TLS (verify-full)");

    let token = harness.generate_token().unwrap();
    let auth = format!("Bearer {}", token);

    run_crud_and_proxy_tests(
        "MySQL/verify-identity",
        &harness.admin_base_url,
        &harness.proxy_base_url,
        &auth,
        backend_port,
    )
    .await;

    println!("\n=== MySQL TLS (verify-identity) PASSED ===\n");
}

#[tokio::test]
#[ignore]
async fn test_mysql_tls_required() {
    println!("\n=== MySQL TLS (require → REQUIRED via FERRUM_DB_SSL_*) ===\n");

    if !is_container_running("ferrum-test-mysql-tls") {
        println!("SKIPPED: ferrum-test-mysql-tls container not running.");
        println!("Run: tests/scripts/setup_db_tls.sh");
        return;
    }

    let mut harness = DbTlsTestHarness::new("mysql")
        .await
        .expect("Failed to create harness");

    let backend_listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("Failed to bind backend");
    let backend_port = backend_listener.local_addr().unwrap().port();
    drop(backend_listener);
    let _backend = start_echo_backend(backend_port).await.unwrap();

    let db_url = "mysql://ferrum:test-password@localhost:13306/ferrum";

    harness
        .start_gateway(db_url, &cert_dir(), "require")
        .await
        .expect("Failed to start gateway with MySQL TLS (require)");

    let token = harness.generate_token().unwrap();
    let auth = format!("Bearer {}", token);

    run_crud_and_proxy_tests(
        "MySQL/required",
        &harness.admin_base_url,
        &harness.proxy_base_url,
        &auth,
        backend_port,
    )
    .await;

    println!("\n=== MySQL TLS (required) PASSED ===\n");
}

#[tokio::test]
#[ignore]
async fn test_mysql_tls_legacy_insecure() {
    println!("\n=== MySQL TLS (legacy FERRUM_DB_TLS_* with insecure=true) ===\n");

    if !is_container_running("ferrum-test-mysql-tls") {
        println!("SKIPPED: ferrum-test-mysql-tls container not running.");
        println!("Run: tests/scripts/setup_db_tls.sh");
        return;
    }

    let mut harness = DbTlsTestHarness::new("mysql")
        .await
        .expect("Failed to create harness");

    let backend_listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("Failed to bind backend");
    let backend_port = backend_listener.local_addr().unwrap().port();
    drop(backend_listener);
    let _backend = start_echo_backend(backend_port).await.unwrap();

    let db_url = "mysql://ferrum:test-password@localhost:13306/ferrum";

    harness
        .start_gateway_legacy_tls(db_url, &cert_dir(), true)
        .await
        .expect("Failed to start gateway with MySQL legacy TLS");

    let token = harness.generate_token().unwrap();
    let auth = format!("Bearer {}", token);

    run_crud_and_proxy_tests(
        "MySQL/legacy-insecure",
        &harness.admin_base_url,
        &harness.proxy_base_url,
        &auth,
        backend_port,
    )
    .await;

    println!("\n=== MySQL TLS (legacy insecure) PASSED ===\n");
}

// ============================================================================
// SQLite Test (no network TLS — verifies TLS params are harmlessly ignored)
// ============================================================================

#[tokio::test]
#[ignore]
async fn test_sqlite_ignores_tls_settings() {
    println!("\n=== SQLite (TLS settings are harmlessly ignored) ===\n");

    let mut harness = DbTlsTestHarness::new("sqlite")
        .await
        .expect("Failed to create harness");

    let backend_listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("Failed to bind backend");
    let backend_port = backend_listener.local_addr().unwrap().port();
    drop(backend_listener);
    let _backend = start_echo_backend(backend_port).await.unwrap();

    let db_path = harness.temp_dir.path().join("test.db");
    let db_url = format!("sqlite:{}?mode=rwc", db_path.display());

    // Start with SSL env vars set — they should be ignored for SQLite
    harness
        .start_gateway_with_envs(
            &db_url,
            vec![
                ("FERRUM_DB_SSL_MODE".to_string(), "verify-full".to_string()),
                (
                    "FERRUM_DB_SSL_ROOT_CERT".to_string(),
                    "/nonexistent/ca.crt".to_string(),
                ),
            ],
        )
        .await
        .expect("Gateway should start fine even with SSL vars set for SQLite");

    let token = harness.generate_token().unwrap();
    let auth = format!("Bearer {}", token);

    run_crud_and_proxy_tests(
        "SQLite/tls-ignored",
        &harness.admin_base_url,
        &harness.proxy_base_url,
        &auth,
        backend_port,
    )
    .await;

    println!("\n=== SQLite (TLS ignored) PASSED ===\n");
}

// ============================================================================
// Health endpoint TLS verification
// ============================================================================

#[tokio::test]
#[ignore]
async fn test_health_endpoint_shows_db_status() {
    println!("\n=== Health Endpoint with TLS DB ===\n");

    if !is_container_running("ferrum-test-pg-tls") {
        println!("SKIPPED: ferrum-test-pg-tls container not running.");
        return;
    }

    let mut harness = DbTlsTestHarness::new("postgres")
        .await
        .expect("Failed to create harness");

    let backend_listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("Failed to bind backend");
    let backend_port = backend_listener.local_addr().unwrap().port();
    drop(backend_listener);
    let _backend = start_echo_backend(backend_port).await.unwrap();

    let db_url = "postgres://ferrum:test-password@localhost:15432/ferrum";

    harness
        .start_gateway(db_url, &cert_dir(), "require")
        .await
        .expect("Failed to start gateway");

    let client = reqwest::Client::new();
    let response = client
        .get(format!("{}/health", harness.admin_base_url))
        .send()
        .await
        .expect("Failed to get health");
    assert!(response.status().is_success());

    let health: serde_json::Value = response.json().await.expect("Failed to parse health");
    assert_eq!(health["status"], "ok");
    println!("  Health check with TLS database: {}", health);

    println!("\n=== Health Endpoint with TLS DB PASSED ===\n");
}
