//! Functional test: Upstream load balancing in DATABASE MODE
//!
//! Verifies that proxies with upstream_id work correctly when the gateway
//! is running in database mode. This tests:
//! - Creating upstreams via Admin API
//! - Creating proxies linked to upstreams via upstream_id
//! - Round-robin load balancing across upstream targets
//! - upstream_id persistence (read back from DB matches what was written)
//!
//! Run with: cargo test --test functional_tests -- --ignored --nocapture functional_db_upstream

use crate::common::{TestGateway, spawn_http_identifying};
use serde_json::json;
use std::collections::HashMap;
use std::time::Duration;

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

    // Start 3 identifying backend servers (listeners held by the harness — no
    // bind-drop-rebind race).
    let mut s1 = spawn_http_identifying("server1")
        .await
        .expect("Failed to spawn server1");
    let mut s2 = spawn_http_identifying("server2")
        .await
        .expect("Failed to spawn server2");
    let mut s3 = spawn_http_identifying("server3")
        .await
        .expect("Failed to spawn server3");

    println!(
        "Backend servers started on ports: {}, {}, {}",
        s1.port, s2.port, s3.port
    );

    // Start gateway in database mode.
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

    // Step 1: Create an upstream with 3 targets via Admin API
    println!("\n--- Step 1: Create Upstream ---");
    let upstream_data = json!({
        "id": "upstream-rr-db",
        "name": "Round Robin DB Upstream",
        "algorithm": "round_robin",
        "targets": [
            { "host": "127.0.0.1", "port": s1.port, "weight": 1 },
            { "host": "127.0.0.1", "port": s2.port, "weight": 1 },
            { "host": "127.0.0.1", "port": s3.port, "weight": 1 }
        ]
    });

    let response = client
        .post(gateway.admin_url("/upstreams"))
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
        .get(gateway.admin_url("/upstreams/upstream-rr-db"))
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
        "backend_port": s1.port,
        "strip_listen_path": true,
        "upstream_id": "upstream-rr-db"
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
    println!("Proxy created with upstream_id = upstream-rr-db");

    // Step 4: Verify proxy has upstream_id persisted
    println!("\n--- Step 4: Verify Proxy upstream_id ---");
    let response = client
        .get(gateway.admin_url("/proxies/lb-proxy-db"))
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
            .get(gateway.proxy_url(&format!("/lb-api/test-{}", i)))
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
        "backend_port": s1.port,
        "strip_listen_path": true,
        "upstream_id": null
    });

    let response = client
        .put(gateway.admin_url("/proxies/lb-proxy-db"))
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
        .get(gateway.admin_url("/proxies/lb-proxy-db"))
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
            .get(gateway.proxy_url(&format!("/lb-api/direct-{}", i)))
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
    gateway.shutdown();
    s1.abort();
    s2.abort();
    s3.abort();

    println!("\n=== All Database Mode Upstream Tests Passed ===\n");
}
