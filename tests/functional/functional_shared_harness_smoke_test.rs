//! Smoke tests for the shared `tests/common/` infrastructure.
//!
//! These tests are the living contract for the harness: they prove that
//! [`TestGateway`], the echo spawners, and the config builders can drive a
//! real `ferrum-edge` subprocess end-to-end. Later phases migrate existing
//! per-test harnesses to this shared code; if these smoke tests ever break,
//! every migrated test will break too — catch it here first.
//!
//! Run with:
//!   cargo build --bin ferrum-edge
//!   cargo test --test functional_tests -- --ignored functional_shared_harness_smoke
//!
//! Marked `#[ignore]` per CLAUDE.md convention for tests that spawn the
//! gateway binary.
//!
//! [`TestGateway`]: crate::common::TestGateway

use crate::common::{
    ConsumerBuilder, GatewayConfigBuilder, PluginConfigBuilder, ProxyBuilder, TestGateway,
    spawn_http_echo, spawn_http_identifying,
};
use serde_json::json;

// ─── Database mode ─────────────────────────────────────────────────────────

#[tokio::test]
#[ignore]
async fn test_harness_database_sqlite_admin_api_roundtrip() {
    // Echo backend with a held listener (no port race).
    let echo = spawn_http_echo().await.expect("spawn echo backend");

    // Default: database mode + SQLite in the harness temp dir.
    let gw = TestGateway::builder()
        .log_level("warn")
        .spawn()
        .await
        .expect("spawn gateway");

    let client = reqwest::Client::new();

    // Provision a proxy via the admin API.
    let proxy = ProxyBuilder::new("smoke-echo")
        .listen_path("/smoke")
        .backend("127.0.0.1", echo.port)
        .build();
    let resp = client
        .post(gw.admin_url("/proxies"))
        .header("Authorization", gw.auth_header())
        .json(&proxy)
        .send()
        .await
        .expect("POST /proxies");
    assert!(
        resp.status().is_success(),
        "create proxy failed: {}",
        resp.status()
    );

    // Give the DB poll a moment to pick up the new proxy.
    for _ in 0..30 {
        let r = client.get(gw.proxy_url("/smoke/hello")).send().await;
        if let Ok(r) = r
            && r.status().is_success()
        {
            let body: serde_json::Value = r.json().await.expect("echo json body");
            assert_eq!(body["echo"], "/hello");
            return;
        }
        tokio::time::sleep(std::time::Duration::from_millis(250)).await;
    }
    panic!("proxy never became routable after 7.5s");
}

#[tokio::test]
#[ignore]
async fn test_harness_database_consumer_and_plugin_config() {
    // Proves ConsumerBuilder + PluginConfigBuilder round-trip through the
    // admin API. Uses identifying echo so the success assertion is precise.
    let echo = spawn_http_identifying("smoke-backend")
        .await
        .expect("spawn identifying backend");

    let gw = TestGateway::builder()
        .log_level("warn")
        .spawn()
        .await
        .expect("spawn gateway");

    let client = reqwest::Client::new();

    // 1. Create a consumer with a keyauth credential.
    let consumer = ConsumerBuilder::new("smoke-con", "smoke-user")
        .credential("keyauth", json!({"key": "smoke-test-key-value"}))
        .build();
    client
        .post(gw.admin_url("/consumers"))
        .header("Authorization", gw.auth_header())
        .json(&consumer)
        .send()
        .await
        .expect("POST /consumers")
        .error_for_status()
        .expect("consumer create OK");

    // 2. Create a proxy.
    let proxy = ProxyBuilder::new("smoke-proxy")
        .listen_path("/api")
        .backend("127.0.0.1", echo.port)
        .build();
    client
        .post(gw.admin_url("/proxies"))
        .header("Authorization", gw.auth_header())
        .json(&proxy)
        .send()
        .await
        .expect("POST /proxies")
        .error_for_status()
        .expect("proxy create OK");

    // 3. Attach a key_auth plugin scoped to that proxy.
    let plugin = PluginConfigBuilder::new("smoke-keyauth", "key_auth")
        .scope("proxy")
        .proxy_id("smoke-proxy")
        .config_field("key_header", json!("X-API-Key"))
        .build();
    client
        .post(gw.admin_url("/plugins/config"))
        .header("Authorization", gw.auth_header())
        .json(&plugin)
        .send()
        .await
        .expect("POST /plugins/config")
        .error_for_status()
        .expect("plugin create OK");

    // 4. Wait for the proxy + plugin to become active, then send an
    //    authenticated request. The identifying echo confirms we hit the
    //    right backend.
    for _ in 0..30 {
        let r = client
            .get(gw.proxy_url("/api/ping"))
            .header("X-API-Key", "smoke-test-key-value")
            .send()
            .await;
        if let Ok(r) = r
            && r.status().is_success()
        {
            let body: serde_json::Value = r.json().await.expect("body json");
            assert_eq!(body["server"], "smoke-backend");
            return;
        }
        tokio::time::sleep(std::time::Duration::from_millis(250)).await;
    }
    panic!("authenticated proxy never became routable");
}

// ─── File mode ─────────────────────────────────────────────────────────────

#[tokio::test]
#[ignore]
async fn test_harness_file_mode_yaml_config() {
    // Proves GatewayConfigBuilder + TestGateway.mode_file end-to-end. No DB
    // involved — config is read from the YAML file the harness wrote.
    let echo = spawn_http_echo().await.expect("spawn echo backend");

    let cfg = GatewayConfigBuilder::new()
        .proxy(
            ProxyBuilder::new("file-mode-echo")
                .listen_path("/file")
                .backend("127.0.0.1", echo.port)
                .build(),
        )
        .build();
    let yaml = serde_yaml::to_string(&cfg).expect("serialise YAML");

    let gw = TestGateway::builder()
        .mode_file(yaml)
        .log_level("warn")
        .spawn()
        .await
        .expect("spawn gateway in file mode");

    let client = reqwest::Client::new();
    let resp = client
        .get(gw.proxy_url("/file/hi"))
        .send()
        .await
        .expect("GET /file/hi");
    assert!(
        resp.status().is_success(),
        "file-mode proxy should be routable immediately (no DB poll delay): {}",
        resp.status()
    );
    let body: serde_json::Value = resp.json().await.expect("echo body");
    assert_eq!(body["echo"], "/hi");
}
