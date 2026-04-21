//! Comprehensive Functional Test for DATABASE MODE
//!
//! This test verifies the complete functionality of ferrum-edge in database mode:
//! - Starting the gateway in database mode (via shared `TestGateway` harness)
//! - Admin API operations (proxies, consumers, plugins)
//! - Proxy routing and request forwarding
//! - Proxy CRUD operations with live updates
//! - Health and metrics endpoints
//!
//! Run with: cargo test --test functional_tests -- --ignored --nocapture functional_database

use crate::common::{TestGateway, spawn_http_echo};
use serde_json::json;
use std::time::Duration;

#[tokio::test]
#[ignore]
async fn test_database_mode_comprehensive() {
    println!("\n=== Starting Database Mode Functional Test ===\n");

    // Spawn echo backend (listener held inside the task — no bind-drop-rebind race)
    let backend = spawn_http_echo()
        .await
        .expect("Failed to start echo backend");
    println!("Echo backend started on port {}", backend.port);

    // Start gateway in database mode via the shared harness (handles 3-attempt
    // retry, fresh ports per attempt, JWT minting, Drop-kill on failure).
    let mut gateway = TestGateway::builder()
        .mode_database_sqlite()
        .jwt_issuer("ferrum-edge-test")
        .log_level("info")
        .db_poll_interval_seconds(2)
        .spawn()
        .await
        .expect("Failed to start gateway");

    println!("Test harness created:");
    println!("  Proxy URL: {}", gateway.proxy_url(""));
    println!("  Admin URL: {}", gateway.admin_url(""));

    let client = reqwest::Client::new();
    let auth_header = gateway.auth_header();

    // Test 1: Create a proxy via Admin API
    println!("\n--- Test 1: Create Proxy ---");
    let proxy_data = json!({
        "id": "test-proxy-1",
        "listen_path": "/test-path",
        "backend_scheme": "http",
        "backend_host": "localhost",
        "backend_port": backend.port,
        "strip_listen_path": true,
    });

    let response = client
        .post(gateway.admin_url("/proxies"))
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
        .get(gateway.admin_url("/proxies/test-proxy-1"))
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
        .get(gateway.proxy_url("/test-path"))
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
    // Shared echo returns {"echo":"<backend_path>"}. With strip_listen_path=true
    // the backend sees "/" (listen_path "/test-path" stripped).
    assert_eq!(
        response_body["echo"].as_str(),
        Some("/"),
        "Backend should receive stripped path, got {:?}",
        response_body["echo"]
    );
    println!("✓ Request successfully routed through proxy");

    // Test 4: Update the proxy
    println!("\n--- Test 4: Update Proxy ---");
    let updated_proxy_data = json!({
        "id": "test-proxy-1",
        "listen_path": "/test-path",
        "backend_scheme": "http",
        "backend_host": "localhost",
        "backend_port": backend.port,
        "strip_listen_path": false, // Changed
    });

    let response = client
        .put(gateway.admin_url("/proxies/test-proxy-1"))
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
        .get(gateway.admin_url("/proxies/test-proxy-1"))
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
        .post(gateway.admin_url("/consumers"))
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
        .get(gateway.admin_url("/consumers/test-consumer-1"))
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
        "plugin_name": "rate_limiting",
        "scope": "proxy",
        "proxy_id": "test-proxy-1",
        "enabled": true,
        "config": {
            "requests_per_minute": 100,
            "limit_by": "ip"
        }
    });

    let response = client
        .post(gateway.admin_url("/plugins/config"))
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
        .get(gateway.admin_url("/plugins/config/test-plugin-1"))
        .header("Authorization", &auth_header)
        .send()
        .await
        .expect("Failed to get plugin config");

    assert!(
        response.status().is_success(),
        "Failed to get plugin config"
    );
    let config_json: serde_json::Value = response.json().await.expect("Failed to parse response");
    assert_eq!(config_json["id"], "test-plugin-1");
    println!("✓ Plugin config retrieved successfully");

    // Test 9: Test health endpoint
    println!("\n--- Test 9: Health Endpoint ---");
    let response = client
        .get(gateway.admin_url("/health"))
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
        .get(gateway.admin_url("/admin/metrics"))
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
        .delete(gateway.admin_url("/proxies/test-proxy-1"))
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
        .get(gateway.admin_url("/proxies/test-proxy-1"))
        .header("Authorization", &auth_header)
        .send()
        .await
        .expect("Failed to check deleted proxy");

    assert_eq!(response.status(), 404, "Proxy should be deleted");
    println!("✓ Proxy deletion verified");

    // Test 13: Request to deleted proxy should fail
    println!("\n--- Test 13: Verify Deleted Proxy Not Routable ---");
    let response = client.get(gateway.proxy_url("/test-path")).send().await;

    // Should either fail to connect or get 404
    assert!(
        response.is_err() || response.unwrap().status() == 404,
        "Deleted proxy should not be routable"
    );
    println!("✓ Deleted proxy is not routable");

    // Test 14: JWT authentication is required
    println!("\n--- Test 14: JWT Authentication Required ---");
    let response = client
        .get(gateway.admin_url("/proxies"))
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
        "backend_scheme": "http",
        "backend_host": "localhost",
        "backend_port": backend.port,
        "strip_listen_path": true,
    });

    client
        .post(gateway.admin_url("/proxies"))
        .header("Authorization", &auth_header)
        .json(&proxy_data)
        .send()
        .await
        .expect("Failed to create second proxy");

    let response = client
        .get(gateway.admin_url("/proxies"))
        .header("Authorization", &auth_header)
        .send()
        .await
        .expect("Failed to list proxies");

    assert!(response.status().is_success(), "Failed to list proxies");
    let proxies: serde_json::Value = response.json().await.expect("Failed to parse proxies");
    assert!(proxies.is_array(), "Proxies response should be an array");
    println!("✓ Proxy listing works");

    gateway.shutdown();
    println!("\n=== All Tests Passed ===\n");
}
