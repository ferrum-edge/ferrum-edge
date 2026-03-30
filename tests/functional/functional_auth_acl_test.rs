//! Comprehensive Functional Tests for Authentication, ACL, and Multi-Auth
//!
//! This test verifies end-to-end authentication and authorization flows:
//! - Key Auth: API key in header and query param
//! - Basic Auth: username:password with bcrypt hashing
//! - JWT Auth: HS256-signed tokens with consumer-specific secrets
//! - HMAC Auth: HMAC-signed requests with replay protection
//! - Access Control (ACL): Consumer allow/deny lists
//! - Multi-Auth mode: First-success-wins across multiple auth plugins
//!
//! Run with: cargo test --test functional_tests -- --ignored --nocapture functional_auth_acl

use base64::Engine;
use chrono::Utc;
use hmac::{Hmac, Mac};
use jsonwebtoken::{EncodingKey, Header, encode};
use serde_json::json;
use sha2::Sha256;
use std::process::{Child, Command};
use std::time::{Duration, SystemTime};
use tempfile::TempDir;
use uuid::Uuid;

type HmacSha256 = Hmac<Sha256>;

/// Test harness for auth/ACL functional testing
struct AuthTestHarness {
    temp_dir: TempDir,
    gateway_process: Option<Child>,
    proxy_base_url: String,
    admin_base_url: String,
    jwt_secret: String,
    jwt_issuer: String,
    admin_port: u16,
    proxy_port: u16,
}

impl AuthTestHarness {
    async fn new() -> Result<Self, Box<dyn std::error::Error>> {
        let temp_dir = TempDir::new()?;
        let jwt_secret = "test-admin-jwt-secret-key-12345".to_string();
        let jwt_issuer = "ferrum-edge-auth-test".to_string();

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
            .env("FERRUM_BASIC_AUTH_HMAC_SECRET", "test-hmac-server-secret")
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

    fn generate_admin_token(&self) -> Result<String, Box<dyn std::error::Error>> {
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

impl Drop for AuthTestHarness {
    fn drop(&mut self) {
        if let Some(mut child) = self.gateway_process.take() {
            let _ = child.kill();
            let _ = child.wait();
        }
    }
}

/// Simple echo HTTP server that returns request info
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

/// Helper: create a consumer via admin API
async fn create_consumer(
    client: &reqwest::Client,
    admin_url: &str,
    auth_header: &str,
    id: &str,
    username: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let data = json!({
        "id": id,
        "username": username,
        "custom_id": format!("{}-custom", username),
    });
    let resp = client
        .post(format!("{}/consumers", admin_url))
        .header("Authorization", auth_header)
        .json(&data)
        .send()
        .await?;
    assert!(
        resp.status().is_success(),
        "Failed to create consumer {}: {} - {}",
        id,
        resp.status(),
        resp.text().await.unwrap_or_default()
    );
    Ok(())
}

/// Helper: add credentials to a consumer
async fn add_credential(
    client: &reqwest::Client,
    admin_url: &str,
    auth_header: &str,
    consumer_id: &str,
    cred_type: &str,
    cred_data: &serde_json::Value,
) -> Result<(), Box<dyn std::error::Error>> {
    let resp = client
        .put(format!(
            "{}/consumers/{}/credentials/{}",
            admin_url, consumer_id, cred_type
        ))
        .header("Authorization", auth_header)
        .json(cred_data)
        .send()
        .await?;
    assert!(
        resp.status().is_success(),
        "Failed to add {} credential to {}: {} - {}",
        cred_type,
        consumer_id,
        resp.status(),
        resp.text().await.unwrap_or_default()
    );
    Ok(())
}

/// Helper: create a proxy via admin API
async fn create_proxy(
    client: &reqwest::Client,
    admin_url: &str,
    auth_header: &str,
    proxy_data: &serde_json::Value,
) -> Result<(), Box<dyn std::error::Error>> {
    let resp = client
        .post(format!("{}/proxies", admin_url))
        .header("Authorization", auth_header)
        .json(proxy_data)
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

/// Helper: create a plugin config via admin API
async fn create_plugin_config(
    client: &reqwest::Client,
    admin_url: &str,
    auth_header: &str,
    plugin_data: &serde_json::Value,
) -> Result<(), Box<dyn std::error::Error>> {
    let resp = client
        .post(format!("{}/plugins/config", admin_url))
        .header("Authorization", auth_header)
        .json(plugin_data)
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

/// Generate a consumer JWT token signed with the consumer's secret
fn generate_consumer_jwt(consumer_username: &str, secret: &str, exp_offset_secs: i64) -> String {
    let now = Utc::now();
    let claims = json!({
        "sub": consumer_username,
        "iat": now.timestamp(),
        "exp": (now + chrono::Duration::seconds(exp_offset_secs)).timestamp(),
    });
    let header = Header::new(jsonwebtoken::Algorithm::HS256);
    let key = EncodingKey::from_secret(secret.as_bytes());
    encode(&header, &claims, &key).expect("Failed to encode JWT")
}

/// Generate HMAC signature for a request
fn generate_hmac_signature(method: &str, path: &str, date: &str, secret: &str) -> String {
    let signing_string = format!("{}\n{}\n{}", method, path, date);
    let mut mac =
        HmacSha256::new_from_slice(secret.as_bytes()).expect("Failed to create HMAC instance");
    mac.update(signing_string.as_bytes());
    base64::engine::general_purpose::STANDARD.encode(mac.finalize().into_bytes())
}

#[tokio::test]
#[ignore]
async fn test_auth_acl_comprehensive() {
    println!("\n=== Starting Auth/ACL Functional Test ===\n");

    // --- Setup ---
    let mut harness = AuthTestHarness::new()
        .await
        .expect("Failed to create test harness");

    // Start echo backend
    let backend_listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("Failed to bind backend");
    let backend_port = backend_listener.local_addr().unwrap().port();
    drop(backend_listener);
    let _backend = start_echo_backend(backend_port)
        .await
        .expect("Failed to start echo backend");

    // Start gateway
    harness
        .start_gateway()
        .await
        .expect("Failed to start gateway");

    let client = reqwest::Client::new();
    let admin_token = harness
        .generate_admin_token()
        .expect("Failed to generate admin token");
    let auth_header = format!("Bearer {}", admin_token);
    let admin_url = &harness.admin_base_url;
    let proxy_url = &harness.proxy_base_url;

    // ==========================================
    // Create consumers with various credentials
    // ==========================================

    println!("\n--- Setup: Creating Consumers ---");

    // Consumer: alice (key_auth + jwt + basic_auth + hmac_auth — multi-credential consumer)
    create_consumer(&client, admin_url, &auth_header, "consumer-alice", "alice")
        .await
        .unwrap();
    add_credential(
        &client,
        admin_url,
        &auth_header,
        "consumer-alice",
        "keyauth",
        &json!({"key": "alice-api-key-secret-12345"}),
    )
    .await
    .unwrap();
    add_credential(
        &client,
        admin_url,
        &auth_header,
        "consumer-alice",
        "jwt",
        &json!({"secret": "alice-jwt-secret-key-999"}),
    )
    .await
    .unwrap();
    add_credential(
        &client,
        admin_url,
        &auth_header,
        "consumer-alice",
        "basicauth",
        &json!({"password": "alice-password-123"}),
    )
    .await
    .unwrap();
    add_credential(
        &client,
        admin_url,
        &auth_header,
        "consumer-alice",
        "hmac_auth",
        &json!({"secret": "alice-hmac-shared-secret"}),
    )
    .await
    .unwrap();

    // Consumer: bob (key_auth only — limited credentials)
    create_consumer(&client, admin_url, &auth_header, "consumer-bob", "bob")
        .await
        .unwrap();
    add_credential(
        &client,
        admin_url,
        &auth_header,
        "consumer-bob",
        "keyauth",
        &json!({"key": "bob-api-key-unique-67890"}),
    )
    .await
    .unwrap();

    // Consumer: charlie (jwt only — for ACL deny list testing)
    create_consumer(
        &client,
        admin_url,
        &auth_header,
        "consumer-charlie",
        "charlie",
    )
    .await
    .unwrap();
    add_credential(
        &client,
        admin_url,
        &auth_header,
        "consumer-charlie",
        "keyauth",
        &json!({"key": "charlie-api-key-blocked-11111"}),
    )
    .await
    .unwrap();

    println!(
        "✓ Consumers created: alice (keyauth+jwt+basic+hmac), bob (keyauth), charlie (keyauth)"
    );

    // ==========================================
    // Create proxies with various auth configs
    // ==========================================

    println!("\n--- Setup: Creating Proxies and Plugin Configs ---");

    // Step 1: Create all proxies first (without plugins)
    // Step 2: Create plugin configs (with proxy_id referencing existing proxies)
    // Step 3: Update proxies to add plugin references (populates junction table)
    //
    // This avoids the FK chicken-and-egg: proxy_plugins junction needs both
    // proxy and plugin_config to exist, and plugin_configs.proxy_id references proxies.

    // Create bare proxies
    for (id, path, auth_mode) in [
        ("proxy-keyauth", "/keyauth", "single"),
        ("proxy-basicauth", "/basicauth", "single"),
        ("proxy-jwtauth", "/jwtauth", "single"),
        ("proxy-hmacauth", "/hmacauth", "single"),
        ("proxy-keyauth-acl-allow", "/keyauth-acl-allow", "single"),
        ("proxy-keyauth-acl-deny", "/keyauth-acl-deny", "single"),
        ("proxy-multiauth", "/multiauth", "multi"),
        ("proxy-keyauth-query", "/keyauth-query", "single"),
        ("proxy-multiauth-acl", "/multiauth-acl", "multi"),
    ] {
        create_proxy(
            &client,
            admin_url,
            &auth_header,
            &json!({
                "id": id,
                "listen_path": path,
                "backend_protocol": "http",
                "backend_host": "localhost",
                "backend_port": backend_port,
                "strip_listen_path": true,
                "auth_mode": auth_mode,
            }),
        )
        .await
        .unwrap();
    }

    // Create all plugin configs (with proxy_id FK)
    let plugin_configs = vec![
        json!({
            "id": "plugin-keyauth",
            "plugin_name": "key_auth",
            "scope": "proxy",
            "proxy_id": "proxy-keyauth",
            "enabled": true,
            "config": {"key_location": "header:X-API-Key"}
        }),
        json!({
            "id": "plugin-basicauth",
            "plugin_name": "basic_auth",
            "scope": "proxy",
            "proxy_id": "proxy-basicauth",
            "enabled": true,
            "config": {}
        }),
        json!({
            "id": "plugin-jwtauth",
            "plugin_name": "jwt_auth",
            "scope": "proxy",
            "proxy_id": "proxy-jwtauth",
            "enabled": true,
            "config": {
                "token_lookup": "header:Authorization",
                "consumer_claim_field": "sub"
            }
        }),
        json!({
            "id": "plugin-hmacauth",
            "plugin_name": "hmac_auth",
            "scope": "proxy",
            "proxy_id": "proxy-hmacauth",
            "enabled": true,
            "config": {"clock_skew_seconds": 300}
        }),
        json!({
            "id": "plugin-keyauth-acl-allow",
            "plugin_name": "key_auth",
            "scope": "proxy",
            "proxy_id": "proxy-keyauth-acl-allow",
            "enabled": true,
            "config": {"key_location": "header:X-API-Key"}
        }),
        json!({
            "id": "plugin-acl-allow",
            "plugin_name": "access_control",
            "scope": "proxy",
            "proxy_id": "proxy-keyauth-acl-allow",
            "enabled": true,
            "config": {
                "allowed_consumers": ["alice", "bob"]
            }
        }),
        json!({
            "id": "plugin-keyauth-acl-deny",
            "plugin_name": "key_auth",
            "scope": "proxy",
            "proxy_id": "proxy-keyauth-acl-deny",
            "enabled": true,
            "config": {"key_location": "header:X-API-Key"}
        }),
        json!({
            "id": "plugin-acl-deny",
            "plugin_name": "access_control",
            "scope": "proxy",
            "proxy_id": "proxy-keyauth-acl-deny",
            "enabled": true,
            "config": {
                "disallowed_consumers": ["charlie"]
            }
        }),
        json!({
            "id": "plugin-multiauth-jwt",
            "plugin_name": "jwt_auth",
            "scope": "proxy",
            "proxy_id": "proxy-multiauth",
            "enabled": true,
            "config": {
                "token_lookup": "header:Authorization",
                "consumer_claim_field": "sub"
            }
        }),
        json!({
            "id": "plugin-multiauth-key",
            "plugin_name": "key_auth",
            "scope": "proxy",
            "proxy_id": "proxy-multiauth",
            "enabled": true,
            "config": {"key_location": "header:X-API-Key"}
        }),
        json!({
            "id": "plugin-keyauth-query",
            "plugin_name": "key_auth",
            "scope": "proxy",
            "proxy_id": "proxy-keyauth-query",
            "enabled": true,
            "config": {"key_location": "query:apikey"}
        }),
        json!({
            "id": "plugin-multiauth-acl-jwt",
            "plugin_name": "jwt_auth",
            "scope": "proxy",
            "proxy_id": "proxy-multiauth-acl",
            "enabled": true,
            "config": {
                "token_lookup": "header:Authorization",
                "consumer_claim_field": "sub"
            }
        }),
        json!({
            "id": "plugin-multiauth-acl-key",
            "plugin_name": "key_auth",
            "scope": "proxy",
            "proxy_id": "proxy-multiauth-acl",
            "enabled": true,
            "config": {"key_location": "header:X-API-Key"}
        }),
        json!({
            "id": "plugin-multiauth-acl",
            "plugin_name": "access_control",
            "scope": "proxy",
            "proxy_id": "proxy-multiauth-acl",
            "enabled": true,
            "config": {
                "allowed_consumers": ["alice"]
            }
        }),
    ];

    for pc in &plugin_configs {
        create_plugin_config(&client, admin_url, &auth_header, pc)
            .await
            .unwrap();
    }

    // Update proxies to add plugin references (populates proxy_plugins junction table)
    let proxy_plugin_map: Vec<(&str, &str, serde_json::Value)> = vec![
        (
            "proxy-keyauth",
            "/keyauth",
            json!([{"plugin_config_id": "plugin-keyauth"}]),
        ),
        (
            "proxy-basicauth",
            "/basicauth",
            json!([{"plugin_config_id": "plugin-basicauth"}]),
        ),
        (
            "proxy-jwtauth",
            "/jwtauth",
            json!([{"plugin_config_id": "plugin-jwtauth"}]),
        ),
        (
            "proxy-hmacauth",
            "/hmacauth",
            json!([{"plugin_config_id": "plugin-hmacauth"}]),
        ),
        (
            "proxy-keyauth-acl-allow",
            "/keyauth-acl-allow",
            json!([
                {"plugin_config_id": "plugin-keyauth-acl-allow"},
                {"plugin_config_id": "plugin-acl-allow"}
            ]),
        ),
        (
            "proxy-keyauth-acl-deny",
            "/keyauth-acl-deny",
            json!([
                {"plugin_config_id": "plugin-keyauth-acl-deny"},
                {"plugin_config_id": "plugin-acl-deny"}
            ]),
        ),
        (
            "proxy-keyauth-query",
            "/keyauth-query",
            json!([{"plugin_config_id": "plugin-keyauth-query"}]),
        ),
    ];

    for (id, path, plugins) in &proxy_plugin_map {
        let resp = client
            .put(format!("{}/proxies/{}", admin_url, id))
            .header("Authorization", &auth_header)
            .json(&json!({
                "id": id,
                "listen_path": path,
                "backend_protocol": "http",
                "backend_host": "localhost",
                "backend_port": backend_port,
                "strip_listen_path": true,
                "plugins": plugins,
            }))
            .send()
            .await
            .expect("Failed to update proxy");
        assert!(
            resp.status().is_success(),
            "Failed to update proxy {}: {} - {}",
            id,
            resp.status(),
            resp.text().await.unwrap_or_default()
        );
    }

    // Multi-auth proxies need auth_mode set
    for (id, path, plugins) in [
        (
            "proxy-multiauth",
            "/multiauth",
            json!([
                {"plugin_config_id": "plugin-multiauth-jwt"},
                {"plugin_config_id": "plugin-multiauth-key"}
            ]),
        ),
        (
            "proxy-multiauth-acl",
            "/multiauth-acl",
            json!([
                {"plugin_config_id": "plugin-multiauth-acl-jwt"},
                {"plugin_config_id": "plugin-multiauth-acl-key"},
                {"plugin_config_id": "plugin-multiauth-acl"}
            ]),
        ),
    ] {
        let resp = client
            .put(format!("{}/proxies/{}", admin_url, id))
            .header("Authorization", &auth_header)
            .json(&json!({
                "id": id,
                "listen_path": path,
                "backend_protocol": "http",
                "backend_host": "localhost",
                "backend_port": backend_port,
                "strip_listen_path": true,
                "auth_mode": "multi",
                "plugins": plugins,
            }))
            .send()
            .await
            .expect("Failed to update proxy");
        assert!(
            resp.status().is_success(),
            "Failed to update proxy {}: {} - {}",
            id,
            resp.status(),
            resp.text().await.unwrap_or_default()
        );
    }

    println!("✓ All proxies and plugin configs created");

    // Wait for DB poll to pick up all config
    println!("\nWaiting for config to be loaded from database...");
    tokio::time::sleep(Duration::from_secs(4)).await;

    // ==========================================
    // KEY AUTH TESTS
    // ==========================================

    println!("\n=== KEY AUTH TESTS ===");

    // Test 1: Key Auth — valid API key in header
    println!("\n--- Test 1: Key Auth — Valid API Key (header) ---");
    let resp = client
        .get(format!("{}/keyauth", proxy_url))
        .header("X-API-Key", "alice-api-key-secret-12345")
        .send()
        .await
        .expect("Request failed");
    assert!(
        resp.status().is_success(),
        "Key auth with valid key should succeed: {}",
        resp.status()
    );
    let body: serde_json::Value = resp.json().await.unwrap();
    assert!(body["echo"].as_bool().unwrap_or(false));
    println!("✓ Valid API key accepted");

    // Test 2: Key Auth — invalid API key
    println!("\n--- Test 2: Key Auth — Invalid API Key ---");
    let resp = client
        .get(format!("{}/keyauth", proxy_url))
        .header("X-API-Key", "wrong-key-does-not-exist")
        .send()
        .await
        .expect("Request failed");
    assert_eq!(resp.status(), 401, "Invalid API key should return 401");
    let body: serde_json::Value = resp.json().await.unwrap();
    assert!(body["error"].as_str().unwrap().contains("Invalid API key"));
    println!("✓ Invalid API key rejected with 401");

    // Test 3: Key Auth — missing API key
    println!("\n--- Test 3: Key Auth — Missing API Key ---");
    let resp = client
        .get(format!("{}/keyauth", proxy_url))
        .send()
        .await
        .expect("Request failed");
    assert_eq!(resp.status(), 401, "Missing API key should return 401");
    let body: serde_json::Value = resp.json().await.unwrap();
    assert!(body["error"].as_str().unwrap().contains("Missing API key"));
    println!("✓ Missing API key rejected with 401");

    // Test 4: Key Auth — different consumer (bob)
    println!("\n--- Test 4: Key Auth — Bob's API Key ---");
    let resp = client
        .get(format!("{}/keyauth", proxy_url))
        .header("X-API-Key", "bob-api-key-unique-67890")
        .send()
        .await
        .expect("Request failed");
    assert!(
        resp.status().is_success(),
        "Bob's key auth should succeed: {}",
        resp.status()
    );
    println!("✓ Bob's API key accepted");

    // Test 5: Key Auth — query param lookup
    println!("\n--- Test 5: Key Auth — Query Param Lookup ---");
    let resp = client
        .get(format!(
            "{}/keyauth-query?apikey=alice-api-key-secret-12345",
            proxy_url
        ))
        .send()
        .await
        .expect("Request failed");
    assert!(
        resp.status().is_success(),
        "Key auth via query param should succeed: {}",
        resp.status()
    );
    println!("✓ API key accepted via query parameter");

    // ==========================================
    // BASIC AUTH TESTS
    // ==========================================

    println!("\n=== BASIC AUTH TESTS ===");

    // Test 6: Basic Auth — valid credentials
    println!("\n--- Test 6: Basic Auth — Valid Credentials ---");
    let basic_cred = base64::engine::general_purpose::STANDARD.encode("alice:alice-password-123");
    let resp = client
        .get(format!("{}/basicauth", proxy_url))
        .header("Authorization", format!("Basic {}", basic_cred))
        .send()
        .await
        .expect("Request failed");
    assert!(
        resp.status().is_success(),
        "Basic auth with valid creds should succeed: {}",
        resp.status()
    );
    let body: serde_json::Value = resp.json().await.unwrap();
    assert!(body["echo"].as_bool().unwrap_or(false));
    println!("✓ Valid basic auth credentials accepted");

    // Test 7: Basic Auth — wrong password
    println!("\n--- Test 7: Basic Auth — Wrong Password ---");
    let bad_cred = base64::engine::general_purpose::STANDARD.encode("alice:wrong-password");
    let resp = client
        .get(format!("{}/basicauth", proxy_url))
        .header("Authorization", format!("Basic {}", bad_cred))
        .send()
        .await
        .expect("Request failed");
    assert_eq!(
        resp.status(),
        401,
        "Basic auth with wrong password should return 401"
    );
    println!("✓ Wrong password rejected with 401");

    // Test 8: Basic Auth — unknown user
    println!("\n--- Test 8: Basic Auth — Unknown User ---");
    let unknown_cred =
        base64::engine::general_purpose::STANDARD.encode("unknownuser:some-password");
    let resp = client
        .get(format!("{}/basicauth", proxy_url))
        .header("Authorization", format!("Basic {}", unknown_cred))
        .send()
        .await
        .expect("Request failed");
    assert_eq!(
        resp.status(),
        401,
        "Basic auth with unknown user should return 401"
    );
    println!("✓ Unknown user rejected with 401");

    // Test 9: Basic Auth — missing Authorization header
    println!("\n--- Test 9: Basic Auth — Missing Auth Header ---");
    let resp = client
        .get(format!("{}/basicauth", proxy_url))
        .send()
        .await
        .expect("Request failed");
    assert_eq!(
        resp.status(),
        401,
        "Basic auth without header should return 401"
    );
    println!("✓ Missing auth header rejected with 401");

    // Test 10: Basic Auth — malformed header (not Basic scheme)
    println!("\n--- Test 10: Basic Auth — Malformed Header ---");
    let resp = client
        .get(format!("{}/basicauth", proxy_url))
        .header("Authorization", "Bearer some-token")
        .send()
        .await
        .expect("Request failed");
    assert_eq!(
        resp.status(),
        401,
        "Basic auth with Bearer scheme should return 401"
    );
    println!("✓ Non-Basic scheme rejected with 401");

    // ==========================================
    // JWT AUTH TESTS
    // ==========================================

    println!("\n=== JWT AUTH TESTS ===");

    // Test 11: JWT Auth — valid token
    println!("\n--- Test 11: JWT Auth — Valid Token ---");
    let jwt_token = generate_consumer_jwt("alice", "alice-jwt-secret-key-999", 3600);
    let resp = client
        .get(format!("{}/jwtauth", proxy_url))
        .header("Authorization", format!("Bearer {}", jwt_token))
        .send()
        .await
        .expect("Request failed");
    assert!(
        resp.status().is_success(),
        "JWT auth with valid token should succeed: {}",
        resp.status()
    );
    let body: serde_json::Value = resp.json().await.unwrap();
    assert!(body["echo"].as_bool().unwrap_or(false));
    println!("✓ Valid JWT token accepted");

    // Test 12: JWT Auth — expired token
    println!("\n--- Test 12: JWT Auth — Expired Token ---");
    let expired_token = generate_consumer_jwt("alice", "alice-jwt-secret-key-999", -300);
    let resp = client
        .get(format!("{}/jwtauth", proxy_url))
        .header("Authorization", format!("Bearer {}", expired_token))
        .send()
        .await
        .expect("Request failed");
    assert_eq!(resp.status(), 401, "Expired JWT should return 401");
    println!("✓ Expired JWT token rejected with 401");

    // Test 13: JWT Auth — wrong secret (signed with different key)
    println!("\n--- Test 13: JWT Auth — Wrong Secret ---");
    let bad_jwt = generate_consumer_jwt("alice", "wrong-secret-not-matching", 3600);
    let resp = client
        .get(format!("{}/jwtauth", proxy_url))
        .header("Authorization", format!("Bearer {}", bad_jwt))
        .send()
        .await
        .expect("Request failed");
    assert_eq!(
        resp.status(),
        401,
        "JWT with wrong secret should return 401"
    );
    println!("✓ JWT with wrong secret rejected with 401");

    // Test 14: JWT Auth — unknown consumer (sub claim doesn't match anyone)
    println!("\n--- Test 14: JWT Auth — Unknown Consumer ---");
    let unknown_jwt = generate_consumer_jwt("nonexistent-user", "some-secret", 3600);
    let resp = client
        .get(format!("{}/jwtauth", proxy_url))
        .header("Authorization", format!("Bearer {}", unknown_jwt))
        .send()
        .await
        .expect("Request failed");
    assert_eq!(
        resp.status(),
        401,
        "JWT for unknown consumer should return 401"
    );
    println!("✓ JWT for unknown consumer rejected with 401");

    // Test 15: JWT Auth — missing token
    println!("\n--- Test 15: JWT Auth — Missing Token ---");
    let resp = client
        .get(format!("{}/jwtauth", proxy_url))
        .send()
        .await
        .expect("Request failed");
    assert_eq!(resp.status(), 401, "Missing JWT should return 401");
    println!("✓ Missing JWT token rejected with 401");

    // Test 16: JWT Auth — malformed token
    println!("\n--- Test 16: JWT Auth — Malformed Token ---");
    let resp = client
        .get(format!("{}/jwtauth", proxy_url))
        .header("Authorization", "Bearer not.a.valid.jwt")
        .send()
        .await
        .expect("Request failed");
    assert_eq!(resp.status(), 401, "Malformed JWT should return 401");
    println!("✓ Malformed JWT token rejected with 401");

    // ==========================================
    // HMAC AUTH TESTS
    // ==========================================

    println!("\n=== HMAC AUTH TESTS ===");

    // Test 17: HMAC Auth — valid signature
    println!("\n--- Test 17: HMAC Auth — Valid Signature ---");
    let date = Utc::now().to_rfc2822();
    let signature = generate_hmac_signature("GET", "/hmacauth", &date, "alice-hmac-shared-secret");
    let hmac_header = format!(
        "hmac username=\"alice\", algorithm=\"hmac-sha256\", signature=\"{}\"",
        signature
    );
    let resp = client
        .get(format!("{}/hmacauth", proxy_url))
        .header("Authorization", &hmac_header)
        .header("Date", &date)
        .send()
        .await
        .expect("Request failed");
    assert!(
        resp.status().is_success(),
        "HMAC auth with valid signature should succeed: {}",
        resp.status()
    );
    let body: serde_json::Value = resp.json().await.unwrap();
    assert!(body["echo"].as_bool().unwrap_or(false));
    println!("✓ Valid HMAC signature accepted");

    // Test 18: HMAC Auth — wrong secret (bad signature)
    println!("\n--- Test 18: HMAC Auth — Wrong Secret ---");
    let date = Utc::now().to_rfc2822();
    let bad_sig = generate_hmac_signature("GET", "/hmacauth", &date, "wrong-secret");
    let hmac_header = format!(
        "hmac username=\"alice\", algorithm=\"hmac-sha256\", signature=\"{}\"",
        bad_sig
    );
    let resp = client
        .get(format!("{}/hmacauth", proxy_url))
        .header("Authorization", &hmac_header)
        .header("Date", &date)
        .send()
        .await
        .expect("Request failed");
    assert_eq!(
        resp.status(),
        401,
        "HMAC with wrong secret should return 401"
    );
    println!("✓ HMAC with wrong secret rejected with 401");

    // Test 19: HMAC Auth — missing Date header (replay protection)
    println!("\n--- Test 19: HMAC Auth — Missing Date Header ---");
    let sig_no_date = generate_hmac_signature("GET", "/hmacauth", "", "alice-hmac-shared-secret");
    let hmac_header = format!(
        "hmac username=\"alice\", algorithm=\"hmac-sha256\", signature=\"{}\"",
        sig_no_date
    );
    let resp = client
        .get(format!("{}/hmacauth", proxy_url))
        .header("Authorization", &hmac_header)
        .send()
        .await
        .expect("Request failed");
    assert_eq!(
        resp.status(),
        401,
        "HMAC without Date header should return 401"
    );
    println!("✓ HMAC without Date header rejected with 401");

    // Test 20: HMAC Auth — unknown consumer
    println!("\n--- Test 20: HMAC Auth — Unknown Consumer ---");
    let date = Utc::now().to_rfc2822();
    let sig = generate_hmac_signature("GET", "/hmacauth", &date, "some-secret");
    let hmac_header = format!(
        "hmac username=\"nonexistent\", algorithm=\"hmac-sha256\", signature=\"{}\"",
        sig
    );
    let resp = client
        .get(format!("{}/hmacauth", proxy_url))
        .header("Authorization", &hmac_header)
        .header("Date", &date)
        .send()
        .await
        .expect("Request failed");
    assert_eq!(
        resp.status(),
        401,
        "HMAC for unknown consumer should return 401"
    );
    println!("✓ HMAC for unknown consumer rejected with 401");

    // Test 21: HMAC Auth — missing Authorization header
    println!("\n--- Test 21: HMAC Auth — Missing Auth Header ---");
    let resp = client
        .get(format!("{}/hmacauth", proxy_url))
        .header("Date", Utc::now().to_rfc2822())
        .send()
        .await
        .expect("Request failed");
    assert_eq!(
        resp.status(),
        401,
        "HMAC without auth header should return 401"
    );
    println!("✓ Missing HMAC auth header rejected with 401");

    // ==========================================
    // ACCESS CONTROL (ACL) TESTS
    // ==========================================

    println!("\n=== ACCESS CONTROL (ACL) TESTS ===");

    // Test 22: ACL allow list — allowed consumer (alice)
    println!("\n--- Test 22: ACL Allow List — Allowed Consumer (alice) ---");
    let resp = client
        .get(format!("{}/keyauth-acl-allow", proxy_url))
        .header("X-API-Key", "alice-api-key-secret-12345")
        .send()
        .await
        .expect("Request failed");
    assert!(
        resp.status().is_success(),
        "Alice should be allowed by ACL: {}",
        resp.status()
    );
    println!("✓ Alice allowed through ACL allow list");

    // Test 23: ACL allow list — allowed consumer (bob)
    println!("\n--- Test 23: ACL Allow List — Allowed Consumer (bob) ---");
    let resp = client
        .get(format!("{}/keyauth-acl-allow", proxy_url))
        .header("X-API-Key", "bob-api-key-unique-67890")
        .send()
        .await
        .expect("Request failed");
    assert!(
        resp.status().is_success(),
        "Bob should be allowed by ACL: {}",
        resp.status()
    );
    println!("✓ Bob allowed through ACL allow list");

    // Test 24: ACL allow list — disallowed consumer (charlie not in allow list)
    println!("\n--- Test 24: ACL Allow List — Disallowed Consumer (charlie) ---");
    let resp = client
        .get(format!("{}/keyauth-acl-allow", proxy_url))
        .header("X-API-Key", "charlie-api-key-blocked-11111")
        .send()
        .await
        .expect("Request failed");
    assert_eq!(
        resp.status(),
        403,
        "Charlie should be blocked by ACL allow list: {}",
        resp.status()
    );
    let body: serde_json::Value = resp.json().await.unwrap();
    assert!(body["error"].as_str().unwrap().contains("not allowed"));
    println!("✓ Charlie blocked by ACL allow list (403)");

    // Test 25: ACL deny list — allowed consumer (alice, not in deny list)
    println!("\n--- Test 25: ACL Deny List — Allowed Consumer (alice) ---");
    let resp = client
        .get(format!("{}/keyauth-acl-deny", proxy_url))
        .header("X-API-Key", "alice-api-key-secret-12345")
        .send()
        .await
        .expect("Request failed");
    assert!(
        resp.status().is_success(),
        "Alice should not be blocked by deny list: {}",
        resp.status()
    );
    println!("✓ Alice allowed (not in deny list)");

    // Test 26: ACL deny list — denied consumer (charlie in deny list)
    println!("\n--- Test 26: ACL Deny List — Denied Consumer (charlie) ---");
    let resp = client
        .get(format!("{}/keyauth-acl-deny", proxy_url))
        .header("X-API-Key", "charlie-api-key-blocked-11111")
        .send()
        .await
        .expect("Request failed");
    assert_eq!(
        resp.status(),
        403,
        "Charlie should be blocked by ACL deny list: {}",
        resp.status()
    );
    let body: serde_json::Value = resp.json().await.unwrap();
    assert!(body["error"].as_str().unwrap().contains("not allowed"));
    println!("✓ Charlie blocked by ACL deny list (403)");

    // Test 27: ACL deny list — bob is allowed (not in deny list)
    println!("\n--- Test 27: ACL Deny List — Bob Allowed ---");
    let resp = client
        .get(format!("{}/keyauth-acl-deny", proxy_url))
        .header("X-API-Key", "bob-api-key-unique-67890")
        .send()
        .await
        .expect("Request failed");
    assert!(
        resp.status().is_success(),
        "Bob should not be blocked by deny list: {}",
        resp.status()
    );
    println!("✓ Bob allowed (not in deny list)");

    // ==========================================
    // MULTI-AUTH MODE TESTS
    // ==========================================

    println!("\n=== MULTI-AUTH MODE TESTS ===");

    // Test 28: Multi-Auth — authenticate via JWT (first-success wins)
    println!("\n--- Test 28: Multi-Auth — JWT Authentication ---");
    let jwt_token = generate_consumer_jwt("alice", "alice-jwt-secret-key-999", 3600);
    let resp = client
        .get(format!("{}/multiauth", proxy_url))
        .header("Authorization", format!("Bearer {}", jwt_token))
        .send()
        .await
        .expect("Request failed");
    assert!(
        resp.status().is_success(),
        "Multi-auth via JWT should succeed: {}",
        resp.status()
    );
    let body: serde_json::Value = resp.json().await.unwrap();
    assert!(body["echo"].as_bool().unwrap_or(false));
    println!("✓ Multi-auth succeeded via JWT");

    // Test 29: Multi-Auth — authenticate via API key (fallback)
    println!("\n--- Test 29: Multi-Auth — API Key Authentication ---");
    let resp = client
        .get(format!("{}/multiauth", proxy_url))
        .header("X-API-Key", "alice-api-key-secret-12345")
        .send()
        .await
        .expect("Request failed");
    assert!(
        resp.status().is_success(),
        "Multi-auth via API key should succeed: {}",
        resp.status()
    );
    let body: serde_json::Value = resp.json().await.unwrap();
    assert!(body["echo"].as_bool().unwrap_or(false));
    println!("✓ Multi-auth succeeded via API key (fallback)");

    // Test 30: Multi-Auth — bob authenticates via API key (no JWT creds)
    println!("\n--- Test 30: Multi-Auth — Bob via API Key Only ---");
    let resp = client
        .get(format!("{}/multiauth", proxy_url))
        .header("X-API-Key", "bob-api-key-unique-67890")
        .send()
        .await
        .expect("Request failed");
    assert!(
        resp.status().is_success(),
        "Multi-auth for bob via API key should succeed: {}",
        resp.status()
    );
    println!("✓ Bob authenticated via API key in multi-auth mode");

    // Test 31: Multi-Auth — no credentials at all (all plugins fail)
    println!("\n--- Test 31: Multi-Auth — No Credentials ---");
    let resp = client
        .get(format!("{}/multiauth", proxy_url))
        .send()
        .await
        .expect("Request failed");
    assert_eq!(
        resp.status(),
        401,
        "Multi-auth with no credentials should return 401"
    );
    println!("✓ Multi-auth with no credentials rejected with 401");

    // Test 32: Multi-Auth — invalid credentials for all methods
    println!("\n--- Test 32: Multi-Auth — All Invalid Credentials ---");
    let bad_jwt = generate_consumer_jwt("alice", "wrong-secret", 3600);
    let resp = client
        .get(format!("{}/multiauth", proxy_url))
        .header("Authorization", format!("Bearer {}", bad_jwt))
        .header("X-API-Key", "wrong-key-12345")
        .send()
        .await
        .expect("Request failed");
    assert_eq!(
        resp.status(),
        401,
        "Multi-auth with all invalid creds should return 401"
    );
    println!("✓ Multi-auth with all invalid credentials rejected with 401");

    // ==========================================
    // MULTI-AUTH + ACL COMBINED TESTS
    // ==========================================

    println!("\n=== MULTI-AUTH + ACL COMBINED TESTS ===");

    // Test 33: Multi-Auth + ACL — alice via JWT (allowed)
    println!("\n--- Test 33: Multi-Auth + ACL — Alice via JWT (allowed) ---");
    let jwt_token = generate_consumer_jwt("alice", "alice-jwt-secret-key-999", 3600);
    let resp = client
        .get(format!("{}/multiauth-acl", proxy_url))
        .header("Authorization", format!("Bearer {}", jwt_token))
        .send()
        .await
        .expect("Request failed");
    assert!(
        resp.status().is_success(),
        "Alice should be allowed via JWT + ACL: {}",
        resp.status()
    );
    println!("✓ Alice allowed via JWT through multi-auth + ACL");

    // Test 34: Multi-Auth + ACL — alice via API key (allowed)
    println!("\n--- Test 34: Multi-Auth + ACL — Alice via API Key (allowed) ---");
    let resp = client
        .get(format!("{}/multiauth-acl", proxy_url))
        .header("X-API-Key", "alice-api-key-secret-12345")
        .send()
        .await
        .expect("Request failed");
    assert!(
        resp.status().is_success(),
        "Alice should be allowed via API key + ACL: {}",
        resp.status()
    );
    println!("✓ Alice allowed via API key through multi-auth + ACL");

    // Test 35: Multi-Auth + ACL — bob via API key (blocked by ACL — not in allowed list)
    println!("\n--- Test 35: Multi-Auth + ACL — Bob Blocked by ACL ---");
    let resp = client
        .get(format!("{}/multiauth-acl", proxy_url))
        .header("X-API-Key", "bob-api-key-unique-67890")
        .send()
        .await
        .expect("Request failed");
    assert_eq!(
        resp.status(),
        403,
        "Bob should be blocked by ACL in multi-auth: {}",
        resp.status()
    );
    println!("✓ Bob blocked by ACL allow list (403) despite valid auth");

    // ==========================================
    // CONSUMER CRUD VERIFICATION
    // ==========================================

    println!("\n=== CONSUMER CRUD VERIFICATION ===");

    // Test 36: Verify consumer credentials are redacted in API responses
    println!("\n--- Test 36: Consumer Credentials Redacted ---");
    let resp = client
        .get(format!("{}/consumers/consumer-alice", admin_url))
        .header("Authorization", &auth_header)
        .send()
        .await
        .expect("Request failed");
    assert!(resp.status().is_success());
    let consumer_json: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(consumer_json["username"], "alice");
    // Verify password_hash is redacted
    if let Some(basicauth) = consumer_json["credentials"]["basicauth"].as_object()
        && let Some(hash) = basicauth.get("password_hash")
    {
        assert_eq!(
            hash.as_str().unwrap(),
            "[REDACTED]",
            "Password hash should be redacted in API response"
        );
    }
    println!("✓ Consumer credentials properly redacted");

    // Test 37: List consumers
    println!("\n--- Test 37: List Consumers ---");
    let resp = client
        .get(format!("{}/consumers", admin_url))
        .header("Authorization", &auth_header)
        .send()
        .await
        .expect("Request failed");
    assert!(resp.status().is_success());
    let consumers: serde_json::Value = resp.json().await.unwrap();
    assert!(consumers.is_array());
    let consumers_arr = consumers.as_array().unwrap();
    assert!(
        consumers_arr.len() >= 3,
        "Should have at least 3 consumers (alice, bob, charlie)"
    );
    println!(
        "✓ Consumer listing works ({} consumers)",
        consumers_arr.len()
    );

    // Test 38: Delete credential and verify auth fails
    println!("\n--- Test 38: Delete Credential — Auth Should Fail ---");
    let resp = client
        .delete(format!(
            "{}/consumers/consumer-bob/credentials/keyauth",
            admin_url
        ))
        .header("Authorization", &auth_header)
        .send()
        .await
        .expect("Request failed");
    assert!(
        resp.status().is_success(),
        "Failed to delete credential: {}",
        resp.status()
    );

    // Wait for DB poll
    tokio::time::sleep(Duration::from_secs(4)).await;

    let resp = client
        .get(format!("{}/keyauth", proxy_url))
        .header("X-API-Key", "bob-api-key-unique-67890")
        .send()
        .await
        .expect("Request failed");
    assert_eq!(
        resp.status(),
        401,
        "Bob's deleted key should no longer work: {}",
        resp.status()
    );
    println!("✓ Deleted credential correctly rejected");

    // Test 39: Re-add credential and verify auth works again
    println!("\n--- Test 39: Re-add Credential — Auth Should Work ---");
    add_credential(
        &client,
        admin_url,
        &auth_header,
        "consumer-bob",
        "keyauth",
        &json!({"key": "bob-new-api-key-99999"}),
    )
    .await
    .unwrap();

    // Wait for DB poll
    tokio::time::sleep(Duration::from_secs(4)).await;

    let resp = client
        .get(format!("{}/keyauth", proxy_url))
        .header("X-API-Key", "bob-new-api-key-99999")
        .send()
        .await
        .expect("Request failed");
    assert!(
        resp.status().is_success(),
        "Bob's new key should work: {}",
        resp.status()
    );
    println!("✓ Re-added credential works correctly");

    // Test 40: Delete consumer and verify all auth fails
    println!("\n--- Test 40: Delete Consumer — All Auth Should Fail ---");
    let resp = client
        .delete(format!("{}/consumers/consumer-bob", admin_url))
        .header("Authorization", &auth_header)
        .send()
        .await
        .expect("Request failed");
    assert!(
        resp.status().is_success(),
        "Failed to delete consumer: {}",
        resp.status()
    );

    // Wait for DB poll
    tokio::time::sleep(Duration::from_secs(4)).await;

    let resp = client
        .get(format!("{}/keyauth", proxy_url))
        .header("X-API-Key", "bob-new-api-key-99999")
        .send()
        .await
        .expect("Request failed");
    assert_eq!(
        resp.status(),
        401,
        "Deleted consumer's key should not work: {}",
        resp.status()
    );
    println!("✓ Deleted consumer's credentials correctly invalidated");

    // Verify consumer is gone via admin API
    let resp = client
        .get(format!("{}/consumers/consumer-bob", admin_url))
        .header("Authorization", &auth_header)
        .send()
        .await
        .expect("Request failed");
    assert_eq!(resp.status(), 404, "Deleted consumer should return 404");
    println!("✓ Deleted consumer returns 404 from admin API");

    println!("\n=== All Auth/ACL Tests Passed ===\n");
}
