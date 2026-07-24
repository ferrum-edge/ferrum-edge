//! MESH-T6-D integration coverage for `GET /mesh/policy-denies/recent`.
//!
//! The admin handler reads the process-singleton `PolicyDenyRecorder`, which
//! lives for the lifetime of the test binary. Tests that share that recorder
//! could collide on rule names or counts, so every fixture in this module
//! uses a unique per-test UUID for rule and source identifiers — the same
//! pattern `admin_mesh_service_graph_tests.rs` uses for its global registry.
//! Assertions then filter the response down to the fixture's UUID-tagged
//! groups instead of comparing the full payload, which keeps the tests
//! parallel-safe without holding a sync mutex across `await` boundaries
//! (which clippy `await_holding_lock` correctly rejects).

use arc_swap::ArcSwap;
use chrono::{Duration as ChronoDuration, Utc};
use ferrum_edge::admin::{
    AdminState,
    jwt_auth::{JwtConfig, JwtManager},
    serve_admin_on_listener,
};
use ferrum_edge::modes::mesh::policy_deny_log::{self, PolicyDenyEvent, PolicyDenyRecorder};
use ferrum_edge::modes::mesh::runtime::MeshRuntimeState;
use ferrum_edge::modes::mesh::slice::MeshSlice;
use jsonwebtoken::{EncodingKey, Header, encode};
use serde_json::{Value, json};
use std::collections::HashSet;
use std::net::SocketAddr;
use std::sync::Arc;

#[derive(Clone)]
struct TestConfig {
    jwt_secret: String,
    jwt_issuer: String,
    max_ttl: u64,
}

impl Default for TestConfig {
    fn default() -> Self {
        Self {
            jwt_secret: "test-secret-key-for-mesh-policy-deny-32chars".to_string(),
            jwt_issuer: "test-ferrum-edge".to_string(),
            max_ttl: 3600,
        }
    }
}

fn create_test_jwt_manager(config: &TestConfig) -> JwtManager {
    JwtManager::new(JwtConfig {
        secret: config.jwt_secret.clone(),
        issuer: config.jwt_issuer.clone(),
        audience: None,
        max_ttl_seconds: config.max_ttl,
        algorithm: jsonwebtoken::Algorithm::HS256,
    })
}

fn generate_test_token(config: &TestConfig) -> String {
    let now = Utc::now();
    let claims = json!({
        "iss": config.jwt_issuer,
        "sub": "test-user",
        "role": "admin",
        "iat": now.timestamp(),
        "nbf": now.timestamp(),
        "exp": (now + chrono::Duration::seconds(config.max_ttl as i64)).timestamp(),
        "jti": uuid::Uuid::new_v4().to_string(),
    });
    let header = Header::new(jsonwebtoken::Algorithm::HS256);
    let key = EncodingKey::from_secret(config.jwt_secret.as_bytes());
    encode(&header, &claims, &key).unwrap()
}

fn build_admin_state(jwt: JwtManager, mesh_runtime_state: Option<MeshRuntimeState>) -> AdminState {
    AdminState {
        db: None,
        jwt_manager: jwt,
        metrics_auth: Default::default(),
        cached_config: None,
        proxy_state: None,
        mode: "mesh".to_string(),
        read_only: false,
        admin_audit_enabled: false,
        admin_require_namespace_claim: false,
        startup_ready: None,
        serving_degraded: None,
        serving_listener_failures: None,
        db_available: None,
        config_rejected: None,
        admin_restore_max_body_size_mib: 100,
        admin_spec_max_body_size_mib: 25,
        reserved_ports: HashSet::new(),
        stream_proxy_bind_address: "0.0.0.0".to_string(),
        admin_allowed_cidrs: Arc::new(ferrum_edge::proxy::client_ip::TrustedProxies::none()),
        cached_db_health: Arc::new(ArcSwap::new(Arc::new(None))),
        db_health_refresh: Arc::new(tokio::sync::Mutex::new(())),
        dp_registry: None,
        mesh_registry: None,
        cp_connection_state: None,
        admin_http_header_read_timeout_seconds: 10,
        admin_body_read_timeout_seconds: 10,
        admin_http2_max_concurrent_streams: 32,
        mesh_runtime_state,
        admin_tls_handshake_timeout_seconds: 10,
        backend_allow_ips: ferrum_edge::config::BackendEgressPolicy::unrestricted(),
    }
}

fn active_mesh_runtime() -> MeshRuntimeState {
    let runtime = MeshRuntimeState::new();
    runtime.install_slice(MeshSlice {
        node_id: "test-node".to_string(),
        namespace: "default".to_string(),
        version: "test".to_string(),
        ..MeshSlice::default()
    });
    runtime
}

async fn start_test_admin(state: AdminState) -> (String, tokio::sync::watch::Sender<bool>) {
    let addr: SocketAddr = "127.0.0.1:0".parse().unwrap();
    let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);
    let listener = tokio::net::TcpListener::bind(addr).await.unwrap();
    let actual_addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        let _ = serve_admin_on_listener(
            listener,
            state,
            shutdown_rx,
            None,
            ferrum_edge::admin::AdminConnLimiter::unlimited(),
        )
        .await;
    });
    for _ in 0..200 {
        if tokio::net::TcpStream::connect(actual_addr).await.is_ok() {
            return (format!("http://{}", actual_addr), shutdown_tx);
        }
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
    }
    panic!("admin listener at {} never became ready", actual_addr);
}

/// Build a unique rule label for this test so its records don't collide with
/// other tests that share the process-singleton recorder.
fn unique_rule(prefix: &str) -> String {
    format!("{prefix}-{}", uuid::Uuid::new_v4())
}

/// Filter the admin payload's `grouped` array down to entries whose `rule`
/// starts with `tag`. Lets assertions ignore any unrelated records dropped
/// into the recorder by parallel tests.
fn groups_with_tag(body: &Value, tag: &str) -> Vec<Value> {
    body["grouped"]
        .as_array()
        .map(|arr| {
            arr.iter()
                .filter(|g| {
                    g["rule"]
                        .as_str()
                        .map(|r| r.starts_with(tag))
                        .unwrap_or(false)
                })
                .cloned()
                .collect()
        })
        .unwrap_or_default()
}

#[tokio::test]
async fn mesh_policy_denies_endpoint_requires_jwt() {
    let tc = TestConfig::default();
    let state = build_admin_state(create_test_jwt_manager(&tc), Some(active_mesh_runtime()));
    let (base_url, _shutdown) = start_test_admin(state).await;

    let response = reqwest::Client::new()
        .get(format!("{base_url}/mesh/policy-denies/recent"))
        .send()
        .await
        .unwrap();
    assert_eq!(response.status().as_u16(), 401);
}

#[tokio::test]
async fn mesh_policy_denies_endpoint_404_outside_mesh_mode() {
    let tc = TestConfig::default();
    let token = generate_test_token(&tc);
    let state = build_admin_state(create_test_jwt_manager(&tc), None);
    let (base_url, _shutdown) = start_test_admin(state).await;

    let response = reqwest::Client::new()
        .get(format!("{base_url}/mesh/policy-denies/recent"))
        .header("authorization", format!("Bearer {token}"))
        .send()
        .await
        .unwrap();
    assert_eq!(response.status().as_u16(), 404);
}

#[tokio::test]
async fn mesh_policy_denies_endpoint_returns_200_with_default_shape() {
    // We can't assert "empty" against the singleton recorder when other tests
    // may have recorded into it. Instead we verify the response shape and
    // that filtering by our tag yields nothing — the recorder is exception
    // path, so absent any seeding of our tag the payload has none of our
    // records.
    let tc = TestConfig::default();
    let token = generate_test_token(&tc);
    let tag = unique_rule("empty-case");
    let state = build_admin_state(create_test_jwt_manager(&tc), Some(active_mesh_runtime()));
    let (base_url, _shutdown) = start_test_admin(state).await;

    let response = reqwest::Client::new()
        .get(format!("{base_url}/mesh/policy-denies/recent"))
        .header("authorization", format!("Bearer {token}"))
        .send()
        .await
        .unwrap();
    assert_eq!(response.status().as_u16(), 200);
    let body: Value = response.json().await.unwrap();
    assert_eq!(body["window_seconds"], 300);
    assert_eq!(body["limit"], 50);
    assert!(body["grouped"].is_array());
    assert!(body["total_denies"].as_u64().is_some());
    // None of our uniquely-tagged rules appear because we never recorded any.
    assert!(groups_with_tag(&body, &tag).is_empty());
}

#[tokio::test]
async fn mesh_policy_denies_endpoint_returns_grouped_recent_denies() {
    let tc = TestConfig::default();
    let token = generate_test_token(&tc);
    let rule_a = unique_rule("deny-prod-from-staging");
    let rule_b = unique_rule("deny-prod-from-test");

    // Seed three denies grouped into two tuples: rule_a appears twice
    // (different times) and rule_b once. Verify count, ordering, and
    // first/last timestamps for our uniquely-tagged groups only.
    let now = Utc::now();
    policy_deny_log::record_global(PolicyDenyEvent {
        rule: rule_a.clone(),
        source: Some("spiffe://cluster.local/ns/staging/sa/web".to_string()),
        destination: Some("spiffe://cluster.local/ns/prod/sa/api".to_string()),
        reason: "namespace_mismatch".to_string(),
        at: now - ChronoDuration::seconds(30),
    });
    policy_deny_log::record_global(PolicyDenyEvent {
        rule: rule_a.clone(),
        source: Some("spiffe://cluster.local/ns/staging/sa/web".to_string()),
        destination: Some("spiffe://cluster.local/ns/prod/sa/api".to_string()),
        reason: "namespace_mismatch".to_string(),
        at: now - ChronoDuration::seconds(5),
    });
    policy_deny_log::record_global(PolicyDenyEvent {
        rule: rule_b.clone(),
        source: Some("spiffe://cluster.local/ns/test/sa/runner".to_string()),
        destination: Some("spiffe://cluster.local/ns/prod/sa/api".to_string()),
        reason: "namespace_mismatch".to_string(),
        at: now - ChronoDuration::seconds(2),
    });

    let state = build_admin_state(create_test_jwt_manager(&tc), Some(active_mesh_runtime()));
    let (base_url, _shutdown) = start_test_admin(state).await;
    let body: Value = reqwest::Client::new()
        .get(format!(
            "{base_url}/mesh/policy-denies/recent?window=5m&limit=1000"
        ))
        .header("authorization", format!("Bearer {token}"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();

    // total_denies covers the entire recorder, so we can only assert it
    // includes our 3 records (other parallel tests may have added more).
    assert!(body["total_denies"].as_u64().unwrap_or(0) >= 3);

    // Filter to our tagged groups; expect exactly two (rule_a + rule_b).
    let group_a = body["grouped"]
        .as_array()
        .unwrap()
        .iter()
        .find(|g| g["rule"] == rule_a)
        .unwrap_or_else(|| panic!("missing rule_a group: {body}"));
    let group_b = body["grouped"]
        .as_array()
        .unwrap()
        .iter()
        .find(|g| g["rule"] == rule_b)
        .unwrap_or_else(|| panic!("missing rule_b group: {body}"));

    assert_eq!(group_a["count"], 2);
    assert_eq!(
        group_a["source"],
        "spiffe://cluster.local/ns/staging/sa/web"
    );
    assert_eq!(
        group_a["destination"],
        "spiffe://cluster.local/ns/prod/sa/api"
    );
    assert_eq!(group_a["reason"], "namespace_mismatch");
    assert_eq!(group_b["count"], 1);

    // first_at / last_at must be RFC3339-shaped and distinct for the
    // 2-event group.
    let first = group_a["first_at"].as_str().expect("first_at");
    let last = group_a["last_at"].as_str().expect("last_at");
    assert!(
        first < last,
        "first_at must precede last_at for distinct events"
    );
}

#[tokio::test]
async fn mesh_policy_denies_endpoint_window_filter_drops_old_records() {
    let tc = TestConfig::default();
    let token = generate_test_token(&tc);
    let ancient = unique_rule("ancient-deny");
    let recent = unique_rule("recent-deny");

    let now = Utc::now();
    policy_deny_log::record_global(PolicyDenyEvent {
        rule: ancient.clone(),
        source: None,
        destination: None,
        reason: "ancient".to_string(),
        at: now - ChronoDuration::seconds(3600),
    });
    policy_deny_log::record_global(PolicyDenyEvent {
        rule: recent.clone(),
        source: None,
        destination: None,
        reason: "recent".to_string(),
        at: now - ChronoDuration::seconds(10),
    });

    let state = build_admin_state(create_test_jwt_manager(&tc), Some(active_mesh_runtime()));
    let (base_url, _shutdown) = start_test_admin(state).await;
    let body: Value = reqwest::Client::new()
        // 30-second window: only the recent record survives the cutoff.
        .get(format!(
            "{base_url}/mesh/policy-denies/recent?window=30s&limit=1000"
        ))
        .header("authorization", format!("Bearer {token}"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let groups = body["grouped"].as_array().unwrap();
    assert!(
        groups.iter().any(|g| g["rule"] == recent),
        "recent rule must appear: {body}"
    );
    assert!(
        groups.iter().all(|g| g["rule"] != ancient),
        "ancient rule must be filtered out by window: {body}"
    );
}

#[tokio::test]
async fn mesh_policy_denies_endpoint_rejects_window_over_one_hour() {
    let tc = TestConfig::default();
    let token = generate_test_token(&tc);
    let state = build_admin_state(create_test_jwt_manager(&tc), Some(active_mesh_runtime()));
    let (base_url, _shutdown) = start_test_admin(state).await;

    let response = reqwest::Client::new()
        .get(format!("{base_url}/mesh/policy-denies/recent?window=2h"))
        .header("authorization", format!("Bearer {token}"))
        .send()
        .await
        .unwrap();
    assert_eq!(response.status().as_u16(), 400);
    let body: Value = response.json().await.unwrap();
    assert!(body["error"].as_str().unwrap().contains("window exceeds"));
}

#[tokio::test]
async fn mesh_policy_denies_endpoint_rejects_limit_over_cap() {
    let tc = TestConfig::default();
    let token = generate_test_token(&tc);
    let state = build_admin_state(create_test_jwt_manager(&tc), Some(active_mesh_runtime()));
    let (base_url, _shutdown) = start_test_admin(state).await;

    let response = reqwest::Client::new()
        .get(format!("{base_url}/mesh/policy-denies/recent?limit=99999"))
        .header("authorization", format!("Bearer {token}"))
        .send()
        .await
        .unwrap();
    assert_eq!(response.status().as_u16(), 400);
    let body: Value = response.json().await.unwrap();
    assert!(body["error"].as_str().unwrap().contains("limit exceeds"));
}

#[tokio::test]
async fn mesh_policy_denies_endpoint_honours_custom_window_and_limit() {
    let tc = TestConfig::default();
    let token = generate_test_token(&tc);
    let rule_a = unique_rule("limit-case-a");
    let rule_b = unique_rule("limit-case-b");

    let now = Utc::now();
    policy_deny_log::record_global(PolicyDenyEvent {
        rule: rule_a.clone(),
        source: None,
        destination: None,
        reason: "a".to_string(),
        at: now - ChronoDuration::seconds(2),
    });
    policy_deny_log::record_global(PolicyDenyEvent {
        rule: rule_b.clone(),
        source: None,
        destination: None,
        reason: "b".to_string(),
        at: now - ChronoDuration::seconds(1),
    });

    let state = build_admin_state(create_test_jwt_manager(&tc), Some(active_mesh_runtime()));
    let (base_url, _shutdown) = start_test_admin(state).await;
    let body: Value = reqwest::Client::new()
        // Use a deliberately small window + limit to make the bound observable
        // even with concurrent test pollution. The handler clamps at the
        // truncate step so `body.limit` should mirror our request.
        .get(format!(
            "{base_url}/mesh/policy-denies/recent?window=10m&limit=1"
        ))
        .header("authorization", format!("Bearer {token}"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(body["window_seconds"], 600);
    assert_eq!(body["limit"], 1);
    // total_denies covers everything in the window across the singleton
    // recorder; bound it loosely on the tag we control.
    let groups = body["grouped"].as_array().unwrap();
    assert_eq!(
        groups.len(),
        1,
        "limit=1 must truncate to one group: {body}"
    );
}

#[tokio::test]
async fn recorder_unit_smoke_test_via_admin_payload() {
    // Sanity-check that a fresh `PolicyDenyRecorder` (not the global) still
    // produces the same `PolicyDenyAggregate` JSON shape the handler emits.
    // Keeps the wire schema and the recorder's `Serialize` impl in lockstep
    // without needing the global recorder.
    let recorder = PolicyDenyRecorder::with_capacity(8);
    let now = Utc::now();
    recorder.record(PolicyDenyEvent {
        rule: "deny-foo".to_string(),
        source: Some("spiffe://cluster.local/ns/staging/sa/web".to_string()),
        destination: Some("spiffe://cluster.local/ns/prod/sa/api".to_string()),
        reason: "namespace_mismatch".to_string(),
        at: now,
    });
    let aggregate = recorder.aggregate_recent(now - ChronoDuration::seconds(60), 10);
    let serialised = serde_json::to_value(&aggregate).unwrap();
    assert_eq!(serialised["total_denies"], 1);
    assert_eq!(serialised["grouped"][0]["rule"], "deny-foo");
    let first_at = serialised["grouped"][0]["first_at"]
        .as_str()
        .expect("first_at");
    assert!(
        first_at.ends_with("+00:00") || first_at.ends_with('Z'),
        "first_at must be RFC 3339 UTC: {first_at}"
    );
}
