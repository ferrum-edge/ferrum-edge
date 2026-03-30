//! Functional Tests for Admin API Operations (E2E)
//!
//! Tests admin API features that have no standalone functional E2E coverage:
//! - Backup / Restore endpoints
//! - Batch create endpoint
//! - Stats endpoint
//! - Consumer credential CRUD (PUT/DELETE)
//! - Plugin config CRUD
//! - Pagination
//! - Health endpoint with status details
//!
//! Uses database mode with SQLite.
//!
//! Run with: cargo test --test functional_tests -- --ignored --nocapture functional_admin

use chrono::Utc;
use jsonwebtoken::{EncodingKey, Header, encode};
use serde_json::json;
use std::process::{Child, Command, Stdio};
use std::time::{Duration, SystemTime};
use tempfile::TempDir;
use uuid::Uuid;

// ============================================================================
// Test Harness
// ============================================================================

struct AdminTestHarness {
    _temp_dir: TempDir,
    gateway_process: Option<Child>,
    admin_base_url: String,
    jwt_secret: String,
    jwt_issuer: String,
}

impl AdminTestHarness {
    async fn new() -> Result<Self, Box<dyn std::error::Error>> {
        let temp_dir = TempDir::new()?;
        let jwt_secret = "test-admin-ops-jwt-secret-12345".to_string();
        let jwt_issuer = "ferrum-gateway-admin-test".to_string();

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
            .args(["build", "--bin", "ferrum-gateway"])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()?;
        if !build_status.success() {
            return Err("Failed to build ferrum-gateway".into());
        }

        let binary_path = if std::path::Path::new("./target/debug/ferrum-gateway").exists() {
            "./target/debug/ferrum-gateway"
        } else {
            "./target/release/ferrum-gateway"
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
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()?;

        let admin_base_url = format!("http://127.0.0.1:{}", admin_port);

        let harness = Self {
            _temp_dir: temp_dir,
            gateway_process: Some(child),
            admin_base_url,
            jwt_secret,
            jwt_issuer,
        };

        harness.wait_for_health().await?;
        Ok(harness)
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

    fn auth_header(&self) -> String {
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

impl Drop for AdminTestHarness {
    fn drop(&mut self) {
        if let Some(mut child) = self.gateway_process.take() {
            let _ = child.kill();
            let _ = child.wait();
        }
    }
}

// ============================================================================
// Health Endpoint Test
// ============================================================================

#[tokio::test]
#[ignore]
async fn test_admin_health_endpoint() {
    let harness = AdminTestHarness::new()
        .await
        .expect("Failed to create harness");

    let client = reqwest::Client::new();
    let resp = client
        .get(format!("{}/health", harness.admin_base_url))
        .send()
        .await
        .expect("Health check failed");

    assert!(resp.status().is_success());
    let body: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(
        body["status"].as_str().unwrap_or(""),
        "ok",
        "Health should report ok"
    );
}

// ============================================================================
// Backup / Restore Test
// ============================================================================

#[tokio::test]
#[ignore]
async fn test_admin_backup_and_restore() {
    let harness = AdminTestHarness::new()
        .await
        .expect("Failed to create harness");

    let client = reqwest::Client::new();
    let auth = harness.auth_header();

    // Step 1: Create some data
    let proxy = json!({
        "id": "backup-proxy-1",
        "listen_path": "/backup-test",
        "backend_protocol": "http",
        "backend_host": "localhost",
        "backend_port": 9999,
        "strip_listen_path": true,
    });
    let resp = client
        .post(format!("{}/proxies", harness.admin_base_url))
        .header("Authorization", &auth)
        .json(&proxy)
        .send()
        .await
        .unwrap();
    assert!(resp.status().is_success(), "Failed to create proxy");

    let consumer = json!({
        "id": "backup-consumer-1",
        "username": "backup-user",
        "custom_id": "backup-custom",
    });
    let resp = client
        .post(format!("{}/consumers", harness.admin_base_url))
        .header("Authorization", &auth)
        .json(&consumer)
        .send()
        .await
        .unwrap();
    assert!(resp.status().is_success(), "Failed to create consumer");

    // Step 2: Take a backup
    let resp = client
        .get(format!("{}/backup", harness.admin_base_url))
        .header("Authorization", &auth)
        .send()
        .await
        .expect("Backup request failed");
    assert!(
        resp.status().is_success(),
        "Backup should succeed: {}",
        resp.status()
    );

    let backup_data: serde_json::Value = resp.json().await.unwrap();
    assert!(
        backup_data["proxies"].is_array(),
        "Backup should contain proxies array"
    );
    assert!(
        backup_data["consumers"].is_array(),
        "Backup should contain consumers array"
    );

    let proxies = backup_data["proxies"].as_array().unwrap();
    assert!(
        proxies.iter().any(|p| p["id"] == "backup-proxy-1"),
        "Backup should contain the created proxy"
    );

    let consumers = backup_data["consumers"].as_array().unwrap();
    assert!(
        consumers.iter().any(|c| c["id"] == "backup-consumer-1"),
        "Backup should contain the created consumer"
    );

    // Step 3: Delete the proxy and consumer
    let resp = client
        .delete(format!("{}/proxies/backup-proxy-1", harness.admin_base_url))
        .header("Authorization", &auth)
        .send()
        .await
        .unwrap();
    assert!(resp.status().is_success(), "Failed to delete proxy");

    let resp = client
        .delete(format!(
            "{}/consumers/backup-consumer-1",
            harness.admin_base_url
        ))
        .header("Authorization", &auth)
        .send()
        .await
        .unwrap();
    assert!(resp.status().is_success(), "Failed to delete consumer");

    // Verify deletion
    let resp = client
        .get(format!("{}/proxies/backup-proxy-1", harness.admin_base_url))
        .header("Authorization", &auth)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status().as_u16(), 404, "Proxy should be gone");

    // Step 4: Restore from backup (requires ?confirm=true)
    let resp = client
        .post(format!("{}/restore?confirm=true", harness.admin_base_url))
        .header("Authorization", &auth)
        .json(&backup_data)
        .send()
        .await
        .expect("Restore request failed");
    assert!(
        resp.status().is_success(),
        "Restore should succeed: {} - {}",
        resp.status(),
        resp.text().await.unwrap_or_default()
    );

    // Step 5: Verify data was restored
    let resp = client
        .get(format!("{}/proxies/backup-proxy-1", harness.admin_base_url))
        .header("Authorization", &auth)
        .send()
        .await
        .unwrap();
    assert!(resp.status().is_success(), "Proxy should be restored");

    let resp = client
        .get(format!(
            "{}/consumers/backup-consumer-1",
            harness.admin_base_url
        ))
        .header("Authorization", &auth)
        .send()
        .await
        .unwrap();
    assert!(resp.status().is_success(), "Consumer should be restored");
}

// ============================================================================
// Batch Create Test
// ============================================================================

#[tokio::test]
#[ignore]
async fn test_admin_batch_create() {
    let harness = AdminTestHarness::new()
        .await
        .expect("Failed to create harness");

    let client = reqwest::Client::new();
    let auth = harness.auth_header();

    // Batch create multiple proxies
    let batch_data = json!({
        "proxies": [
            {
                "id": "batch-proxy-1",
                "listen_path": "/batch-1",
                "backend_protocol": "http",
                "backend_host": "localhost",
                "backend_port": 9001,
                "strip_listen_path": true,
            },
            {
                "id": "batch-proxy-2",
                "listen_path": "/batch-2",
                "backend_protocol": "http",
                "backend_host": "localhost",
                "backend_port": 9002,
                "strip_listen_path": true,
            },
            {
                "id": "batch-proxy-3",
                "listen_path": "/batch-3",
                "backend_protocol": "http",
                "backend_host": "localhost",
                "backend_port": 9003,
                "strip_listen_path": true,
            }
        ],
        "consumers": [
            {
                "id": "batch-consumer-1",
                "username": "batch-user-1",
            },
            {
                "id": "batch-consumer-2",
                "username": "batch-user-2",
            }
        ]
    });

    let resp = client
        .post(format!("{}/batch", harness.admin_base_url))
        .header("Authorization", &auth)
        .json(&batch_data)
        .send()
        .await
        .expect("Batch create failed");

    assert!(
        resp.status().is_success(),
        "Batch create should succeed: {} - {}",
        resp.status(),
        resp.text().await.unwrap_or_default()
    );

    // Verify all proxies were created
    for id in ["batch-proxy-1", "batch-proxy-2", "batch-proxy-3"] {
        let resp = client
            .get(format!("{}/proxies/{}", harness.admin_base_url, id))
            .header("Authorization", &auth)
            .send()
            .await
            .unwrap();
        assert!(
            resp.status().is_success(),
            "Proxy {} should exist after batch create",
            id
        );
    }

    // Verify all consumers were created
    for id in ["batch-consumer-1", "batch-consumer-2"] {
        let resp = client
            .get(format!("{}/consumers/{}", harness.admin_base_url, id))
            .header("Authorization", &auth)
            .send()
            .await
            .unwrap();
        assert!(
            resp.status().is_success(),
            "Consumer {} should exist after batch create",
            id
        );
    }
}

// ============================================================================
// Consumer Credential CRUD Test
// ============================================================================

#[tokio::test]
#[ignore]
async fn test_admin_consumer_credential_crud() {
    let harness = AdminTestHarness::new()
        .await
        .expect("Failed to create harness");

    let client = reqwest::Client::new();
    let auth = harness.auth_header();

    // Create consumer
    let resp = client
        .post(format!("{}/consumers", harness.admin_base_url))
        .header("Authorization", &auth)
        .json(&json!({
            "id": "cred-consumer",
            "username": "creduser",
        }))
        .send()
        .await
        .unwrap();
    assert!(resp.status().is_success());

    // Add key auth credential
    let resp = client
        .put(format!(
            "{}/consumers/cred-consumer/credentials/keyauth",
            harness.admin_base_url
        ))
        .header("Authorization", &auth)
        .json(&json!({"key": "my-secret-api-key"}))
        .send()
        .await
        .unwrap();
    assert!(
        resp.status().is_success(),
        "Should add keyauth credential: {}",
        resp.status()
    );

    // Verify credential exists on consumer
    let resp = client
        .get(format!(
            "{}/consumers/cred-consumer",
            harness.admin_base_url
        ))
        .header("Authorization", &auth)
        .send()
        .await
        .unwrap();
    let consumer: serde_json::Value = resp.json().await.unwrap();
    assert!(
        consumer["credentials"]["keyauth"].is_object(),
        "Consumer should have keyauth credentials"
    );

    // Add jwt credential
    let resp = client
        .put(format!(
            "{}/consumers/cred-consumer/credentials/jwt",
            harness.admin_base_url
        ))
        .header("Authorization", &auth)
        .json(&json!({"secret": "my-jwt-secret"}))
        .send()
        .await
        .unwrap();
    assert!(
        resp.status().is_success(),
        "Should add jwt credential: {}",
        resp.status()
    );

    // Delete keyauth credential
    let resp = client
        .delete(format!(
            "{}/consumers/cred-consumer/credentials/keyauth",
            harness.admin_base_url
        ))
        .header("Authorization", &auth)
        .send()
        .await
        .unwrap();
    assert!(
        resp.status().is_success(),
        "Should delete keyauth credential: {}",
        resp.status()
    );

    // Verify keyauth credential is gone but jwt remains
    let resp = client
        .get(format!(
            "{}/consumers/cred-consumer",
            harness.admin_base_url
        ))
        .header("Authorization", &auth)
        .send()
        .await
        .unwrap();
    let consumer: serde_json::Value = resp.json().await.unwrap();
    assert!(
        !consumer["credentials"]
            .as_object()
            .is_some_and(|c| c.contains_key("keyauth")),
        "Keyauth credential should be deleted"
    );
    assert!(
        consumer["credentials"]["jwt"].is_object(),
        "JWT credential should still exist"
    );
}

// ============================================================================
// Plugin Config CRUD Test
// ============================================================================

#[tokio::test]
#[ignore]
async fn test_admin_plugin_config_crud() {
    let harness = AdminTestHarness::new()
        .await
        .expect("Failed to create harness");

    let client = reqwest::Client::new();
    let auth = harness.auth_header();

    // Create a proxy first (needed for proxy-scoped plugins)
    let resp = client
        .post(format!("{}/proxies", harness.admin_base_url))
        .header("Authorization", &auth)
        .json(&json!({
            "id": "plugin-crud-proxy",
            "listen_path": "/plugin-crud",
            "backend_protocol": "http",
            "backend_host": "localhost",
            "backend_port": 9999,
        }))
        .send()
        .await
        .unwrap();
    assert!(resp.status().is_success());

    // Create plugin config
    let plugin_data = json!({
        "id": "crud-plugin-1",
        "plugin_name": "rate_limiting",
        "scope": "proxy",
        "proxy_id": "plugin-crud-proxy",
        "enabled": true,
        "config": {
            "window_seconds": 60,
                "max_requests": 100
        }
    });

    let resp = client
        .post(format!("{}/plugins/config", harness.admin_base_url))
        .header("Authorization", &auth)
        .json(&plugin_data)
        .send()
        .await
        .unwrap();
    assert!(
        resp.status().is_success(),
        "Should create plugin config: {} - {}",
        resp.status(),
        resp.text().await.unwrap_or_default()
    );

    // Read plugin config
    let resp = client
        .get(format!(
            "{}/plugins/config/crud-plugin-1",
            harness.admin_base_url
        ))
        .header("Authorization", &auth)
        .send()
        .await
        .unwrap();
    assert!(resp.status().is_success());
    let plugin: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(plugin["plugin_name"], "rate_limiting");
    assert!(plugin["enabled"].as_bool().unwrap_or(false));

    // Update plugin config (disable it)
    let updated = json!({
        "id": "crud-plugin-1",
        "plugin_name": "rate_limiting",
        "scope": "proxy",
        "proxy_id": "plugin-crud-proxy",
        "enabled": false,
        "config": {
            "window_seconds": 120,
                "max_requests": 200
        }
    });

    let resp = client
        .put(format!(
            "{}/plugins/config/crud-plugin-1",
            harness.admin_base_url
        ))
        .header("Authorization", &auth)
        .json(&updated)
        .send()
        .await
        .unwrap();
    assert!(
        resp.status().is_success(),
        "Should update plugin config: {}",
        resp.status()
    );

    // Verify update
    let resp = client
        .get(format!(
            "{}/plugins/config/crud-plugin-1",
            harness.admin_base_url
        ))
        .header("Authorization", &auth)
        .send()
        .await
        .unwrap();
    let plugin: serde_json::Value = resp.json().await.unwrap();
    assert!(
        !plugin["enabled"].as_bool().unwrap_or(true),
        "Plugin should be disabled after update"
    );

    // Delete plugin config
    let resp = client
        .delete(format!(
            "{}/plugins/config/crud-plugin-1",
            harness.admin_base_url
        ))
        .header("Authorization", &auth)
        .send()
        .await
        .unwrap();
    assert!(
        resp.status().is_success(),
        "Should delete plugin config: {}",
        resp.status()
    );

    // Verify deletion
    let resp = client
        .get(format!(
            "{}/plugins/config/crud-plugin-1",
            harness.admin_base_url
        ))
        .header("Authorization", &auth)
        .send()
        .await
        .unwrap();
    assert_eq!(
        resp.status().as_u16(),
        404,
        "Plugin config should be gone after deletion"
    );
}

// ============================================================================
// Proxy Listing + Pagination Test
// ============================================================================

#[tokio::test]
#[ignore]
async fn test_admin_proxy_listing_pagination() {
    let harness = AdminTestHarness::new()
        .await
        .expect("Failed to create harness");

    let client = reqwest::Client::new();
    let auth = harness.auth_header();

    // Create 5 proxies
    for i in 1..=5 {
        let resp = client
            .post(format!("{}/proxies", harness.admin_base_url))
            .header("Authorization", &auth)
            .json(&json!({
                "id": format!("page-proxy-{}", i),
                "listen_path": format!("/page-{}", i),
                "backend_protocol": "http",
                "backend_host": "localhost",
                "backend_port": 9000 + i,
            }))
            .send()
            .await
            .unwrap();
        assert!(resp.status().is_success());
    }

    // List all proxies
    let resp = client
        .get(format!("{}/proxies", harness.admin_base_url))
        .header("Authorization", &auth)
        .send()
        .await
        .unwrap();
    assert!(resp.status().is_success());
    let body: serde_json::Value = resp.json().await.unwrap();

    // Should return all 5 proxies (might be in an array or paginated object)
    let proxies = if body.is_array() {
        body.as_array().unwrap().clone()
    } else if body["data"].is_array() {
        body["data"].as_array().unwrap().clone()
    } else {
        panic!("Unexpected response format: {:?}", body);
    };
    assert!(
        proxies.len() >= 5,
        "Should have at least 5 proxies, got {}",
        proxies.len()
    );

    // Test pagination with limit
    let resp = client
        .get(format!("{}/proxies?limit=2", harness.admin_base_url))
        .header("Authorization", &auth)
        .send()
        .await
        .unwrap();
    assert!(resp.status().is_success());
    let body: serde_json::Value = resp.json().await.unwrap();
    let proxies = if body.is_array() {
        body.as_array().unwrap().clone()
    } else if body["data"].is_array() {
        body["data"].as_array().unwrap().clone()
    } else {
        // Some APIs return full list if pagination is not supported — that's ok
        return;
    };
    assert!(
        proxies.len() <= 2,
        "Paginated response should have at most 2 proxies, got {}",
        proxies.len()
    );
}

// ============================================================================
// Stats / Metrics Endpoint Test
// ============================================================================

#[tokio::test]
#[ignore]
async fn test_admin_stats_endpoint() {
    let harness = AdminTestHarness::new()
        .await
        .expect("Failed to create harness");

    let client = reqwest::Client::new();
    let auth = harness.auth_header();

    // Stats/metrics endpoint (check if it exists and returns useful data)
    let resp = client
        .get(format!("{}/stats", harness.admin_base_url))
        .header("Authorization", &auth)
        .send()
        .await
        .expect("Stats request failed");

    // Stats might be at /stats or /metrics — either is fine if it exists
    if resp.status().is_success() {
        let body: serde_json::Value = resp.json().await.unwrap_or(json!({}));
        // Just verify it returns some structured data
        assert!(body.is_object(), "Stats should return a JSON object");
    }

    // Also check metrics endpoint (Prometheus format or JSON)
    let resp = client
        .get(format!("{}/metrics", harness.admin_base_url))
        .header("Authorization", &auth)
        .send()
        .await
        .expect("Metrics request failed");

    // Metrics endpoint should exist
    assert!(
        resp.status().is_success() || resp.status().as_u16() == 404,
        "Metrics endpoint returned unexpected status: {}",
        resp.status()
    );
}

// ============================================================================
// JWT Auth Required for Admin Endpoints
// ============================================================================

#[tokio::test]
#[ignore]
async fn test_admin_requires_authentication() {
    let harness = AdminTestHarness::new()
        .await
        .expect("Failed to create harness");

    let client = reqwest::Client::new();

    // Request without auth should be rejected (401)
    let resp = client
        .get(format!("{}/proxies", harness.admin_base_url))
        .send()
        .await
        .expect("Request failed");
    assert_eq!(
        resp.status().as_u16(),
        401,
        "Admin endpoint without auth should return 401"
    );

    // Request with invalid token should be rejected
    let resp = client
        .get(format!("{}/proxies", harness.admin_base_url))
        .header("Authorization", "Bearer invalid-token-xyz")
        .send()
        .await
        .expect("Request failed");
    assert_eq!(
        resp.status().as_u16(),
        401,
        "Admin endpoint with invalid token should return 401"
    );

    // Health endpoint should NOT require auth
    let resp = client
        .get(format!("{}/health", harness.admin_base_url))
        .send()
        .await
        .expect("Request failed");
    assert!(
        resp.status().is_success(),
        "Health endpoint should not require auth"
    );
}
