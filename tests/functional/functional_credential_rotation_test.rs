//! Functional Tests for Multi-Credential Rotation Lifecycle (E2E)
//!
//! Verifies the zero-downtime credential rotation workflow:
//! - `POST /consumers/:id/credentials/:type` — append a credential entry
//! - `DELETE /consumers/:id/credentials/:type/:index` — remove by index
//! - After append, BOTH credentials authenticate (overlap window)
//! - After delete, only the remaining credential authenticates
//! - Enforcement of `FERRUM_MAX_CREDENTIALS_PER_TYPE`
//!
//! Covers key_auth, JWT, HMAC rotation, plus the per-type limit.
//!
//! Run with: cargo test --test functional_tests -- --ignored --nocapture functional_credential_rotation

use base64::Engine;
use chrono::Utc;
use hmac::{Hmac, KeyInit, Mac};
use jsonwebtoken::{EncodingKey, Header, encode};
use serde_json::json;
use sha2::Sha256;
use std::process::{Child, Command, Stdio};
use std::time::{Duration, SystemTime};
use tempfile::TempDir;
use uuid::Uuid;

type HmacSha256 = Hmac<Sha256>;

// ============================================================================
// Test Harness
// ============================================================================

struct RotationTestHarness {
    _temp_dir: TempDir,
    gateway_process: Option<Child>,
    proxy_base_url: String,
    admin_base_url: String,
    jwt_secret: String,
    jwt_issuer: String,
    backend_port: u16,
    _backend_handle: Option<tokio::task::JoinHandle<()>>,
}

impl RotationTestHarness {
    async fn new() -> Result<Self, Box<dyn std::error::Error>> {
        // Retry harness creation up to 3 times to handle ephemeral port races.
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
                        tokio::time::sleep(Duration::from_secs(1)).await;
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
        let jwt_secret = "test-admin-rotation-jwt-secret-key-1234567890".to_string();
        let jwt_issuer = "ferrum-edge-rotation-test".to_string();

        let admin_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
        let admin_port = admin_listener.local_addr()?.port();
        drop(admin_listener);

        let proxy_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
        let proxy_port = proxy_listener.local_addr()?.port();
        drop(proxy_listener);

        // Backend echo server — hold the listener and pass it to the echo task
        // to avoid the drop-and-rebind race on the backend port.
        let backend_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
        let backend_port = backend_listener.local_addr()?.port();
        let backend_handle = start_echo_backend_on(backend_listener);

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
            .env("FERRUM_LOG_LEVEL", "info")
            .env("FERRUM_MAX_CREDENTIALS_PER_TYPE", "2")
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
            backend_port,
            _backend_handle: Some(backend_handle),
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

    fn admin_auth_header(&self) -> String {
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
        let token = encode(&header, &claims, &key).unwrap();
        format!("Bearer {}", token)
    }
}

impl Drop for RotationTestHarness {
    fn drop(&mut self) {
        if let Some(mut child) = self.gateway_process.take() {
            let _ = child.kill();
            let _ = child.wait();
        }
    }
}

/// Echo backend that always returns 200 JSON. Accepts a pre-bound listener to
/// avoid same-process port races.
fn start_echo_backend_on(listener: tokio::net::TcpListener) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        while let Ok((socket, _)) = listener.accept().await {
            tokio::spawn(async move {
                use tokio::io::{AsyncBufReadExt, AsyncWriteExt};
                let (reader, mut writer) = socket.into_split();
                let mut buf_reader = tokio::io::BufReader::new(reader);
                let mut line = String::new();
                if buf_reader.read_line(&mut line).await.is_err() {
                    return;
                }
                loop {
                    line.clear();
                    if buf_reader.read_line(&mut line).await.is_err() {
                        return;
                    }
                    if line == "\r\n" || line == "\n" {
                        break;
                    }
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
    })
}

// ============================================================================
// Helpers
// ============================================================================

async fn create_consumer(
    client: &reqwest::Client,
    admin_url: &str,
    auth: &str,
    id: &str,
    username: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let resp = client
        .post(format!("{}/consumers", admin_url))
        .header("Authorization", auth)
        .json(&json!({
            "id": id,
            "username": username,
            "custom_id": format!("{}-custom", username),
        }))
        .send()
        .await?;
    if !resp.status().is_success() {
        let status = resp.status();
        let body = resp.text().await.unwrap_or_default();
        return Err(format!("create_consumer({}) failed: {} {}", id, status, body).into());
    }
    Ok(())
}

async fn put_credential(
    client: &reqwest::Client,
    admin_url: &str,
    auth: &str,
    consumer_id: &str,
    cred_type: &str,
    cred: &serde_json::Value,
) -> Result<(), Box<dyn std::error::Error>> {
    let resp = client
        .put(format!(
            "{}/consumers/{}/credentials/{}",
            admin_url, consumer_id, cred_type
        ))
        .header("Authorization", auth)
        .json(cred)
        .send()
        .await?;
    if !resp.status().is_success() {
        let status = resp.status();
        let body = resp.text().await.unwrap_or_default();
        return Err(format!(
            "put_credential({}, {}) failed: {} {}",
            consumer_id, cred_type, status, body
        )
        .into());
    }
    Ok(())
}

async fn append_credential(
    client: &reqwest::Client,
    admin_url: &str,
    auth: &str,
    consumer_id: &str,
    cred_type: &str,
    cred: &serde_json::Value,
) -> Result<reqwest::Response, Box<dyn std::error::Error>> {
    let resp = client
        .post(format!(
            "{}/consumers/{}/credentials/{}",
            admin_url, consumer_id, cred_type
        ))
        .header("Authorization", auth)
        .json(cred)
        .send()
        .await?;
    Ok(resp)
}

async fn delete_credential_by_index(
    client: &reqwest::Client,
    admin_url: &str,
    auth: &str,
    consumer_id: &str,
    cred_type: &str,
    index: usize,
) -> Result<reqwest::Response, Box<dyn std::error::Error>> {
    let resp = client
        .delete(format!(
            "{}/consumers/{}/credentials/{}/{}",
            admin_url, consumer_id, cred_type, index
        ))
        .header("Authorization", auth)
        .send()
        .await?;
    Ok(resp)
}

async fn create_proxy(
    client: &reqwest::Client,
    admin_url: &str,
    auth: &str,
    id: &str,
    listen_path: &str,
    backend_port: u16,
) -> Result<(), Box<dyn std::error::Error>> {
    let resp = client
        .post(format!("{}/proxies", admin_url))
        .header("Authorization", auth)
        .json(&json!({
            "id": id,
            "listen_path": listen_path,
            "backend_protocol": "http",
            "backend_host": "localhost",
            "backend_port": backend_port,
            "strip_listen_path": true,
            "auth_mode": "single",
        }))
        .send()
        .await?;
    if !resp.status().is_success() {
        let status = resp.status();
        let body = resp.text().await.unwrap_or_default();
        return Err(format!("create_proxy({}) failed: {} {}", id, status, body).into());
    }
    Ok(())
}

async fn create_plugin_config(
    client: &reqwest::Client,
    admin_url: &str,
    auth: &str,
    plugin: &serde_json::Value,
) -> Result<(), Box<dyn std::error::Error>> {
    let resp = client
        .post(format!("{}/plugins/config", admin_url))
        .header("Authorization", auth)
        .json(plugin)
        .send()
        .await?;
    if !resp.status().is_success() {
        let status = resp.status();
        let body = resp.text().await.unwrap_or_default();
        return Err(format!("create_plugin_config failed: {} {}", status, body).into());
    }
    Ok(())
}

async fn attach_plugins(
    client: &reqwest::Client,
    admin_url: &str,
    auth: &str,
    proxy_id: &str,
    listen_path: &str,
    backend_port: u16,
    plugin_ids: &[&str],
) -> Result<(), Box<dyn std::error::Error>> {
    let plugins: Vec<serde_json::Value> = plugin_ids
        .iter()
        .map(|id| json!({"plugin_config_id": id}))
        .collect();
    let resp = client
        .put(format!("{}/proxies/{}", admin_url, proxy_id))
        .header("Authorization", auth)
        .json(&json!({
            "id": proxy_id,
            "listen_path": listen_path,
            "backend_protocol": "http",
            "backend_host": "localhost",
            "backend_port": backend_port,
            "strip_listen_path": true,
            "auth_mode": "single",
            "plugins": plugins,
        }))
        .send()
        .await?;
    if !resp.status().is_success() {
        let status = resp.status();
        let body = resp.text().await.unwrap_or_default();
        return Err(format!("attach_plugins({}) failed: {} {}", proxy_id, status, body).into());
    }
    Ok(())
}

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

fn generate_hmac_signature(method: &str, path: &str, date: &str, secret: &str) -> String {
    let signing_string = format!("{}\n{}\n{}", method, path, date);
    let mut mac =
        HmacSha256::new_from_slice(secret.as_bytes()).expect("Failed to create HMAC instance");
    mac.update(signing_string.as_bytes());
    base64::engine::general_purpose::STANDARD.encode(mac.finalize().into_bytes())
}

/// Config-poll settle delay. The gateway polls SQLite every 2s
/// (FERRUM_DB_POLL_INTERVAL=2). Wait a safety margin above that for the new
/// config (consumer/credential/proxy/plugin edits) to take effect on the
/// proxy hot path.
const CONFIG_SETTLE_SECS: u64 = 4;

// ============================================================================
// Test 1: key_auth rotation
// ============================================================================

#[tokio::test(flavor = "multi_thread")]
#[ignore]
async fn test_credential_rotation_key_auth() {
    let harness = RotationTestHarness::new()
        .await
        .expect("Failed to create harness");

    let client = reqwest::Client::new();
    let auth = harness.admin_auth_header();
    let admin_url = &harness.admin_base_url;
    let proxy_url = &harness.proxy_base_url;
    let backend_port = harness.backend_port;

    // ---- Setup: consumer + single key_auth credential ----
    create_consumer(&client, admin_url, &auth, "rot-keyauth-consumer", "rotuser")
        .await
        .unwrap();
    put_credential(
        &client,
        admin_url,
        &auth,
        "rot-keyauth-consumer",
        "keyauth",
        &json!({"key": "key1-original-api-key-aaaa"}),
    )
    .await
    .unwrap();

    // Proxy + key_auth plugin
    create_proxy(
        &client,
        admin_url,
        &auth,
        "rot-keyauth-proxy",
        "/rot-keyauth",
        backend_port,
    )
    .await
    .unwrap();
    create_plugin_config(
        &client,
        admin_url,
        &auth,
        &json!({
            "id": "rot-keyauth-plugin",
            "plugin_name": "key_auth",
            "scope": "proxy",
            "proxy_id": "rot-keyauth-proxy",
            "enabled": true,
            "config": {"key_location": "header:X-API-Key"}
        }),
    )
    .await
    .unwrap();
    attach_plugins(
        &client,
        admin_url,
        &auth,
        "rot-keyauth-proxy",
        "/rot-keyauth",
        backend_port,
        &["rot-keyauth-plugin"],
    )
    .await
    .unwrap();

    tokio::time::sleep(Duration::from_secs(CONFIG_SETTLE_SECS)).await;

    // ---- Initial state: key1 authenticates ----
    let resp = client
        .get(format!("{}/rot-keyauth", proxy_url))
        .header("X-API-Key", "key1-original-api-key-aaaa")
        .send()
        .await
        .expect("request failed");
    assert_eq!(
        resp.status().as_u16(),
        200,
        "key1 should authenticate before rotation"
    );

    // ---- Append second credential via POST ----
    let resp = append_credential(
        &client,
        admin_url,
        &auth,
        "rot-keyauth-consumer",
        "keyauth",
        &json!({"key": "key2-rotation-api-key-bbbb"}),
    )
    .await
    .unwrap();
    assert_eq!(
        resp.status().as_u16(),
        200,
        "append should succeed: {}",
        resp.text().await.unwrap_or_default()
    );

    // Confirm consumer now has an array of 2 keyauth creds
    let consumer: serde_json::Value = client
        .get(format!("{}/consumers/rot-keyauth-consumer", admin_url))
        .header("Authorization", &auth)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let kc = &consumer["credentials"]["keyauth"];
    assert!(
        kc.is_array() && kc.as_array().unwrap().len() == 2,
        "keyauth should be a 2-element array after append, got: {}",
        kc
    );

    tokio::time::sleep(Duration::from_secs(CONFIG_SETTLE_SECS)).await;

    // ---- Both credentials authenticate (rotation overlap) ----
    let r1 = client
        .get(format!("{}/rot-keyauth", proxy_url))
        .header("X-API-Key", "key1-original-api-key-aaaa")
        .send()
        .await
        .unwrap();
    assert_eq!(
        r1.status().as_u16(),
        200,
        "key1 should still authenticate after append"
    );
    let r2 = client
        .get(format!("{}/rot-keyauth", proxy_url))
        .header("X-API-Key", "key2-rotation-api-key-bbbb")
        .send()
        .await
        .unwrap();
    assert_eq!(
        r2.status().as_u16(),
        200,
        "key2 should authenticate after append"
    );

    // ---- Delete index 0 (the original key1) ----
    let resp = delete_credential_by_index(
        &client,
        admin_url,
        &auth,
        "rot-keyauth-consumer",
        "keyauth",
        0,
    )
    .await
    .unwrap();
    assert_eq!(
        resp.status().as_u16(),
        200,
        "delete of index 0 should succeed: {}",
        resp.text().await.unwrap_or_default()
    );

    tokio::time::sleep(Duration::from_secs(CONFIG_SETTLE_SECS)).await;

    // ---- key1 rejected (401), key2 still OK (200) ----
    let r1 = client
        .get(format!("{}/rot-keyauth", proxy_url))
        .header("X-API-Key", "key1-original-api-key-aaaa")
        .send()
        .await
        .unwrap();
    assert_eq!(
        r1.status().as_u16(),
        401,
        "key1 should be rejected after delete"
    );
    let r2 = client
        .get(format!("{}/rot-keyauth", proxy_url))
        .header("X-API-Key", "key2-rotation-api-key-bbbb")
        .send()
        .await
        .unwrap();
    assert_eq!(r2.status().as_u16(), 200, "key2 should still authenticate");
}

// ============================================================================
// Test 2: JWT rotation
// ============================================================================

#[tokio::test(flavor = "multi_thread")]
#[ignore]
async fn test_credential_rotation_jwt() {
    let harness = RotationTestHarness::new()
        .await
        .expect("Failed to create harness");

    let client = reqwest::Client::new();
    let auth = harness.admin_auth_header();
    let admin_url = &harness.admin_base_url;
    let proxy_url = &harness.proxy_base_url;
    let backend_port = harness.backend_port;

    // JWT secrets must be >= 32 chars (MIN_JWT_SECRET_LENGTH).
    let secret1 = "rotation-jwt-secret-one-aaaaaaaaaaaa"; // 35 chars
    let secret2 = "rotation-jwt-secret-two-bbbbbbbbbbbb"; // 35 chars

    // ---- Setup: consumer + one jwt credential ----
    create_consumer(&client, admin_url, &auth, "rot-jwt-consumer", "jwtrotuser")
        .await
        .unwrap();
    put_credential(
        &client,
        admin_url,
        &auth,
        "rot-jwt-consumer",
        "jwt",
        &json!({"secret": secret1, "iss": "test-iss"}),
    )
    .await
    .unwrap();

    create_proxy(
        &client,
        admin_url,
        &auth,
        "rot-jwt-proxy",
        "/rot-jwt",
        backend_port,
    )
    .await
    .unwrap();
    create_plugin_config(
        &client,
        admin_url,
        &auth,
        &json!({
            "id": "rot-jwt-plugin",
            "plugin_name": "jwt_auth",
            "scope": "proxy",
            "proxy_id": "rot-jwt-proxy",
            "enabled": true,
            "config": {
                "token_lookup": "header:Authorization",
                "consumer_claim_field": "sub"
            }
        }),
    )
    .await
    .unwrap();
    attach_plugins(
        &client,
        admin_url,
        &auth,
        "rot-jwt-proxy",
        "/rot-jwt",
        backend_port,
        &["rot-jwt-plugin"],
    )
    .await
    .unwrap();

    tokio::time::sleep(Duration::from_secs(CONFIG_SETTLE_SECS)).await;

    // ---- Initial: token signed with secret1 authenticates ----
    let token1 = generate_consumer_jwt("jwtrotuser", secret1, 3600);
    let resp = client
        .get(format!("{}/rot-jwt", proxy_url))
        .header("Authorization", format!("Bearer {}", token1))
        .send()
        .await
        .unwrap();
    assert_eq!(
        resp.status().as_u16(),
        200,
        "secret1 JWT should authenticate before rotation"
    );

    // ---- Append second jwt credential via POST ----
    let resp = append_credential(
        &client,
        admin_url,
        &auth,
        "rot-jwt-consumer",
        "jwt",
        &json!({"secret": secret2, "iss": "test-iss"}),
    )
    .await
    .unwrap();
    assert_eq!(
        resp.status().as_u16(),
        200,
        "append should succeed: {}",
        resp.text().await.unwrap_or_default()
    );

    tokio::time::sleep(Duration::from_secs(CONFIG_SETTLE_SECS)).await;

    // ---- Both secrets authenticate ----
    let t1 = generate_consumer_jwt("jwtrotuser", secret1, 3600);
    let r1 = client
        .get(format!("{}/rot-jwt", proxy_url))
        .header("Authorization", format!("Bearer {}", t1))
        .send()
        .await
        .unwrap();
    assert_eq!(
        r1.status().as_u16(),
        200,
        "secret1 JWT should still authenticate after append"
    );
    let t2 = generate_consumer_jwt("jwtrotuser", secret2, 3600);
    let r2 = client
        .get(format!("{}/rot-jwt", proxy_url))
        .header("Authorization", format!("Bearer {}", t2))
        .send()
        .await
        .unwrap();
    assert_eq!(
        r2.status().as_u16(),
        200,
        "secret2 JWT should authenticate after append"
    );

    // ---- Delete index 0 (original secret1 entry) ----
    let resp = delete_credential_by_index(&client, admin_url, &auth, "rot-jwt-consumer", "jwt", 0)
        .await
        .unwrap();
    assert_eq!(
        resp.status().as_u16(),
        200,
        "delete of index 0 should succeed: {}",
        resp.text().await.unwrap_or_default()
    );

    tokio::time::sleep(Duration::from_secs(CONFIG_SETTLE_SECS)).await;

    // ---- secret1 tokens now 401, secret2 tokens still 200 ----
    let t1 = generate_consumer_jwt("jwtrotuser", secret1, 3600);
    let r1 = client
        .get(format!("{}/rot-jwt", proxy_url))
        .header("Authorization", format!("Bearer {}", t1))
        .send()
        .await
        .unwrap();
    assert_eq!(
        r1.status().as_u16(),
        401,
        "secret1 JWT should be rejected after deletion"
    );
    let t2 = generate_consumer_jwt("jwtrotuser", secret2, 3600);
    let r2 = client
        .get(format!("{}/rot-jwt", proxy_url))
        .header("Authorization", format!("Bearer {}", t2))
        .send()
        .await
        .unwrap();
    assert_eq!(
        r2.status().as_u16(),
        200,
        "secret2 JWT should still authenticate"
    );
}

// ============================================================================
// Test 3: HMAC rotation
// ============================================================================

#[tokio::test(flavor = "multi_thread")]
#[ignore]
async fn test_credential_rotation_hmac() {
    let harness = RotationTestHarness::new()
        .await
        .expect("Failed to create harness");

    let client = reqwest::Client::new();
    let auth = harness.admin_auth_header();
    let admin_url = &harness.admin_base_url;
    let proxy_url = &harness.proxy_base_url;
    let backend_port = harness.backend_port;

    let secret1 = "hmac-rotation-secret-one-aaaa";
    let secret2 = "hmac-rotation-secret-two-bbbb";
    let username = "hmacrotuser";

    // ---- Setup: consumer + one hmac credential ----
    create_consumer(&client, admin_url, &auth, "rot-hmac-consumer", username)
        .await
        .unwrap();
    put_credential(
        &client,
        admin_url,
        &auth,
        "rot-hmac-consumer",
        "hmac_auth",
        &json!({"secret": secret1}),
    )
    .await
    .unwrap();

    create_proxy(
        &client,
        admin_url,
        &auth,
        "rot-hmac-proxy",
        "/rot-hmac",
        backend_port,
    )
    .await
    .unwrap();
    create_plugin_config(
        &client,
        admin_url,
        &auth,
        &json!({
            "id": "rot-hmac-plugin",
            "plugin_name": "hmac_auth",
            "scope": "proxy",
            "proxy_id": "rot-hmac-proxy",
            "enabled": true,
            "config": {"clock_skew_seconds": 300}
        }),
    )
    .await
    .unwrap();
    attach_plugins(
        &client,
        admin_url,
        &auth,
        "rot-hmac-proxy",
        "/rot-hmac",
        backend_port,
        &["rot-hmac-plugin"],
    )
    .await
    .unwrap();

    tokio::time::sleep(Duration::from_secs(CONFIG_SETTLE_SECS)).await;

    let hmac_url = format!("{}/rot-hmac", proxy_url);
    // Helper: send an HMAC-signed GET /rot-hmac request with the given secret.
    async fn send_hmac(
        client: &reqwest::Client,
        url: &str,
        username: &str,
        secret: &str,
    ) -> reqwest::Response {
        let date = Utc::now().to_rfc2822();
        let sig = generate_hmac_signature("GET", "/rot-hmac", &date, secret);
        let header = format!(
            "hmac username=\"{}\", algorithm=\"hmac-sha256\", signature=\"{}\"",
            username, sig
        );
        client
            .get(url)
            .header("Authorization", header)
            .header("Date", date)
            .send()
            .await
            .expect("hmac request failed")
    }

    // ---- Initial: secret1 authenticates ----
    let r = send_hmac(&client, &hmac_url, username, secret1).await;
    assert_eq!(
        r.status().as_u16(),
        200,
        "secret1 HMAC should authenticate before rotation"
    );

    // ---- Append second hmac credential ----
    let resp = append_credential(
        &client,
        admin_url,
        &auth,
        "rot-hmac-consumer",
        "hmac_auth",
        &json!({"secret": secret2}),
    )
    .await
    .unwrap();
    assert_eq!(
        resp.status().as_u16(),
        200,
        "hmac append should succeed: {}",
        resp.text().await.unwrap_or_default()
    );

    tokio::time::sleep(Duration::from_secs(CONFIG_SETTLE_SECS)).await;

    // ---- Both secrets authenticate ----
    let r1 = send_hmac(&client, &hmac_url, username, secret1).await;
    assert_eq!(
        r1.status().as_u16(),
        200,
        "secret1 HMAC should still authenticate after append"
    );
    let r2 = send_hmac(&client, &hmac_url, username, secret2).await;
    assert_eq!(
        r2.status().as_u16(),
        200,
        "secret2 HMAC should authenticate after append"
    );

    // ---- Delete index 0 (secret1) ----
    let resp = delete_credential_by_index(
        &client,
        admin_url,
        &auth,
        "rot-hmac-consumer",
        "hmac_auth",
        0,
    )
    .await
    .unwrap();
    assert_eq!(
        resp.status().as_u16(),
        200,
        "hmac delete of index 0 should succeed: {}",
        resp.text().await.unwrap_or_default()
    );

    tokio::time::sleep(Duration::from_secs(CONFIG_SETTLE_SECS)).await;

    // ---- secret1 now 401, secret2 still 200 ----
    let r1 = send_hmac(&client, &hmac_url, username, secret1).await;
    assert_eq!(
        r1.status().as_u16(),
        401,
        "secret1 HMAC should be rejected after deletion"
    );
    let r2 = send_hmac(&client, &hmac_url, username, secret2).await;
    assert_eq!(
        r2.status().as_u16(),
        200,
        "secret2 HMAC should still authenticate"
    );
}

// ============================================================================
// Test 4: Limit enforcement — FERRUM_MAX_CREDENTIALS_PER_TYPE
// ============================================================================

#[tokio::test(flavor = "multi_thread")]
#[ignore]
async fn test_credential_rotation_limit_enforcement() {
    // Harness sets FERRUM_MAX_CREDENTIALS_PER_TYPE=2.
    let harness = RotationTestHarness::new()
        .await
        .expect("Failed to create harness");

    let client = reqwest::Client::new();
    let auth = harness.admin_auth_header();
    let admin_url = &harness.admin_base_url;

    create_consumer(&client, admin_url, &auth, "rot-limit-consumer", "limituser")
        .await
        .unwrap();

    // Seed the first credential via PUT (sets initial entry).
    put_credential(
        &client,
        admin_url,
        &auth,
        "rot-limit-consumer",
        "keyauth",
        &json!({"key": "limit-key-1-aaaa"}),
    )
    .await
    .unwrap();

    // Append a second credential — should succeed (now at the limit of 2).
    let resp = append_credential(
        &client,
        admin_url,
        &auth,
        "rot-limit-consumer",
        "keyauth",
        &json!({"key": "limit-key-2-bbbb"}),
    )
    .await
    .unwrap();
    assert_eq!(
        resp.status().as_u16(),
        200,
        "second credential append should succeed (at the limit)"
    );

    // Append a third credential — must be rejected with 400.
    let resp = append_credential(
        &client,
        admin_url,
        &auth,
        "rot-limit-consumer",
        "keyauth",
        &json!({"key": "limit-key-3-cccc"}),
    )
    .await
    .unwrap();
    assert_eq!(
        resp.status().as_u16(),
        400,
        "third credential append should be rejected with 400"
    );
    let body = resp.text().await.unwrap_or_default();
    assert!(
        body.to_lowercase().contains("exceed")
            || body.to_lowercase().contains("limit")
            || body.to_lowercase().contains("credentials per type"),
        "error body should mention the limit, got: {}",
        body
    );

    // Verify stored state still has exactly 2 entries.
    let consumer: serde_json::Value = client
        .get(format!("{}/consumers/rot-limit-consumer", admin_url))
        .header("Authorization", &auth)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let kc = &consumer["credentials"]["keyauth"];
    assert!(
        kc.is_array() && kc.as_array().unwrap().len() == 2,
        "consumer should retain exactly 2 keyauth credentials, got: {}",
        kc
    );
}
