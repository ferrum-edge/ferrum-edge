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
    probe_gateway_identity, scrub_gateway_capture_for_diagnostics, spawn_http_echo,
    spawn_http_identifying,
};
use serde_json::json;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

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
        .config_field("key_location", json!("header:X-API-Key"))
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

// ─── Process identity (issue #3428) ────────────────────────────────────────
//
// `ephemeral_port()` releases the listener before the child binds, so under
// parallel functional execution another gateway can claim either port. These
// tests are the contract for the ownership probe that closes that hole: a
// foreign listener — even one that answers `/health` as ready — must never be
// mistaken for the spawned child.

/// How a fake `/health` responder decides which tier to answer with.
#[derive(Clone)]
enum FakeHealthTier {
    /// Always the unauthenticated `status`+`ready` body — what a *foreign*
    /// gateway returns when probed with someone else's credential.
    AlwaysUnauthenticated,
    /// The authenticated detail tier, but only for this exact bearer token.
    DetailForToken(String),
}

/// Minimal HTTP/1.1 `/health` responder. Deliberately hand-rolled rather than
/// a real gateway so the test pins the *probe's* decision rule, independently
/// of how much of a gateway happens to have started.
async fn spawn_fake_health_listener(tier: FakeHealthTier) -> (u16, tokio::task::JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind fake health listener");
    let port = listener.local_addr().expect("fake listener addr").port();

    let handle = tokio::spawn(async move {
        loop {
            let Ok((mut stream, _)) = listener.accept().await else {
                return;
            };
            let tier = tier.clone();
            tokio::spawn(async move {
                let mut request = Vec::new();
                let mut chunk = [0u8; 1024];
                loop {
                    match stream.read(&mut chunk).await {
                        Ok(0) => break,
                        Ok(n) => {
                            request.extend_from_slice(&chunk[..n]);
                            if request.windows(4).any(|w| w == b"\r\n\r\n") {
                                break;
                            }
                        }
                        Err(_) => return,
                    }
                }
                let request = String::from_utf8_lossy(&request).into_owned();
                let authorized = match &tier {
                    FakeHealthTier::AlwaysUnauthenticated => false,
                    FakeHealthTier::DetailForToken(expected) => request.lines().any(|line| {
                        line.to_ascii_lowercase().starts_with("authorization:")
                            && line.trim().ends_with(&format!("Bearer {expected}"))
                    }),
                };
                // Both bodies say `ready: true`; only the detail tier carries
                // `cached_config`. That is exactly the ambiguity the probe has
                // to resolve.
                let body = if authorized {
                    r#"{"status":"ok","ready":true,"cached_config":{"available":true}}"#
                } else {
                    r#"{"status":"ok","ready":true}"#
                };
                let response = format!(
                    "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\n\
                     content-length: {}\r\nconnection: close\r\n\r\n{}",
                    body.len(),
                    body
                );
                let _ = stream.write_all(response.as_bytes()).await;
                let _ = stream.flush().await;
            });
        }
    });

    (port, handle)
}

/// A listener that answers `/health` as ready but does not hold this
/// instance's credential is rejected — this is the exact shape of the failure
/// in issue #3428, where a parallel gateway satisfied readiness on a released
/// port and then served its own configuration.
#[tokio::test]
#[ignore]
async fn test_harness_identity_rejects_foreign_ready_gateway() {
    let (port, listener) = spawn_fake_health_listener(FakeHealthTier::AlwaysUnauthenticated).await;

    let err = probe_gateway_identity(
        port,
        "ferrum-edge-harness-probe-under-test",
        Duration::from_secs(2),
    )
    .await
    .expect_err("a foreign ready gateway must not satisfy the ownership probe");
    let err = err.to_string();
    assert!(
        err.contains("unauthenticated tier"),
        "probe should report why the responder was rejected: {err}"
    );
    assert!(
        !err.contains("ferrum-edge-harness-probe-under-test"),
        "probe diagnostics must never echo the instance credential: {err}"
    );

    listener.abort();
}

/// The probe accepts a responder that proves it holds the instance credential,
/// and only that one. Two tokens against one listener isolates the credential
/// as the deciding factor.
#[tokio::test]
#[ignore]
async fn test_harness_identity_accepts_only_matching_credential() {
    let token = "ferrum-edge-harness-probe-matching-token";
    let (port, listener) =
        spawn_fake_health_listener(FakeHealthTier::DetailForToken(token.to_string())).await;

    probe_gateway_identity(port, token, Duration::from_secs(5))
        .await
        .expect("the listener holding this instance's credential must be accepted");

    probe_gateway_identity(port, "some-other-instances-token", Duration::from_secs(2))
        .await
        .expect_err("the same listener must be rejected for a different instance's credential");

    listener.abort();
}

/// A bare TCP accept is not identity. `wait_for_proxy_port` used to trust
/// exactly this much, which is why a stolen proxy port went undetected.
#[tokio::test]
#[ignore]
async fn test_harness_identity_rejects_bare_tcp_listener() {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let port = listener.local_addr().expect("addr").port();
    let accept_task = tokio::spawn(async move {
        while let Ok((stream, _)) = listener.accept().await {
            drop(stream);
        }
    });

    probe_gateway_identity(port, "any-token", Duration::from_secs(2))
        .await
        .expect_err("a listener that accepts and closes is not a gateway");

    accept_task.abort();
}

/// End-to-end: two real gateways started by the same harness are mutually
/// unidentifiable. Each proves ownership of its own admin port and neither can
/// prove ownership of the other's, so a test whose port was stolen by a sibling
/// gateway now fails its spawn barrier instead of silently talking to the wrong
/// configuration.
#[tokio::test]
#[ignore]
async fn test_harness_identity_distinguishes_two_real_gateways() {
    let first = TestGateway::builder()
        .log_level("warn")
        .spawn()
        .await
        .expect("spawn first gateway");
    let second = TestGateway::builder()
        .log_level("warn")
        .spawn()
        .await
        .expect("spawn second gateway");

    assert_ne!(
        first.admin_port, second.admin_port,
        "two live gateways must not share an admin port"
    );
    assert_ne!(
        first.observability_token, second.observability_token,
        "each spawn attempt must mint its own instance credential"
    );
    assert_ne!(
        first.jwt_secret, second.jwt_secret,
        "each spawn attempt must mint its own admin JWT secret"
    );

    // Each gateway identifies itself.
    probe_gateway_identity(
        first.admin_port,
        &first.observability_token,
        Duration::from_secs(10),
    )
    .await
    .expect("first gateway should identify itself");
    probe_gateway_identity(
        second.admin_port,
        &second.observability_token,
        Duration::from_secs(10),
    )
    .await
    .expect("second gateway should identify itself");

    // Neither can stand in for the other, even though both are ready and both
    // were started by the same builder defaults.
    probe_gateway_identity(
        second.admin_port,
        &first.observability_token,
        Duration::from_secs(2),
    )
    .await
    .expect_err("the second gateway must not satisfy the first gateway's identity probe");
    probe_gateway_identity(
        first.admin_port,
        &second.observability_token,
        Duration::from_secs(2),
    )
    .await
    .expect_err("the first gateway must not satisfy the second gateway's identity probe");

    // A foreign gateway also must not satisfy the other's admin JWT — the
    // second, independent identity factor.
    let client = reqwest::Client::new();
    let resp = client
        .get(second.admin_url("/proxies"))
        .header("Authorization", first.auth_header())
        .send()
        .await
        .expect("GET /proxies with the sibling gateway's token");
    assert_eq!(
        resp.status().as_u16(),
        401,
        "a sibling gateway's admin JWT must be rejected"
    );
}

/// Captured-output diagnostics must scrub secrets and URL userinfo, and stay
/// bounded, so failed spawn attempts remain actionable in hosted CI without
/// leaking credentials.
#[test]
fn harness_capture_diagnostics_scrub_secrets_and_bound_output() {
    let jwt_secret = "harness-jwt-secret-value-0123456789";
    let observability = "harness-obs-token-value-ABCDEFGH";
    let short_hmac = "xy";

    let sensitive = format!(
        "startup failed redis_url=redis://user:s3cret@127.0.0.1:6379/0 \
         jwt={jwt_secret} token={observability} hmac={short_hmac}"
    );
    let scrubbed_sensitive =
        scrub_gateway_capture_for_diagnostics(&sensitive, &[jwt_secret, observability, short_hmac]);

    assert!(
        !scrubbed_sensitive.contains(jwt_secret),
        "JWT secret must not appear in diagnostics: {scrubbed_sensitive}"
    );
    assert!(
        !scrubbed_sensitive.contains(observability),
        "observability token must not appear in diagnostics: {scrubbed_sensitive}"
    );
    assert!(
        !scrubbed_sensitive.contains(short_hmac),
        "short caller-provided secret must not appear in diagnostics: {scrubbed_sensitive}"
    );
    assert!(
        !scrubbed_sensitive.contains("user:s3cret@"),
        "Redis URL userinfo must be redacted: {scrubbed_sensitive}"
    );
    assert!(
        scrubbed_sensitive.contains("redis://***@127.0.0.1:6379/0"),
        "credential-bearing Redis URL should retain a redacted host form: {scrubbed_sensitive}"
    );

    let oversized = format!("{}{}", "x".repeat(20_000), sensitive);
    let scrubbed_oversized =
        scrub_gateway_capture_for_diagnostics(&oversized, &[jwt_secret, observability, short_hmac]);
    assert!(
        scrubbed_oversized.starts_with("…[truncated]…\n"),
        "oversized capture must be truncated from the front: {}",
        &scrubbed_oversized[..scrubbed_oversized.len().min(32)]
    );
    assert!(
        scrubbed_oversized.len() <= 16 * 1024 + "…[truncated]…\n".len(),
        "diagnostic capture must stay bounded, got {} bytes",
        scrubbed_oversized.len()
    );
    assert!(
        scrubbed_oversized.contains("redis://***@127.0.0.1:6379/0"),
        "trailing diagnostic content must survive truncation: {scrubbed_oversized}"
    );
    assert!(
        !scrubbed_oversized.contains(jwt_secret)
            && !scrubbed_oversized.contains(short_hmac)
            && !scrubbed_oversized.contains("user:s3cret@"),
        "truncated diagnostics must still scrub secrets: {scrubbed_oversized}"
    );
}
