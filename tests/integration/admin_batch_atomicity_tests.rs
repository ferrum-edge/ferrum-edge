//! `POST /batch` is all-or-nothing (issue #2401).
//!
//! The endpoint installs a validated dependency graph — consumers and upstreams,
//! then proxies, then plugin configs, then the proxy↔plugin associations. It used
//! to persist each family (and each bounded chunk inside a family) in its own
//! transaction, so a later failure left the earlier families durable and returned
//! `207 Multi-Status`. A retry then conflicted on the resources that had already
//! landed.
//!
//! These tests drive the SQL backend through a deterministic fault at **every**
//! dependency phase and **after a chunk boundary** inside every chunked phase,
//! and assert that nothing from the request survives — then that an unchanged
//! retry succeeds. The natural failure (a duplicate upstream) is covered too,
//! since that is the reproduction in the issue.
//!
//! Fault injection is keyed per namespace, so every test owns a unique namespace
//! and cannot perturb the others sharing this process.

use arc_swap::ArcSwap;
use chrono::Utc;
use ferrum_edge::_test_support::{
    AtomicBatchFault, AtomicBatchPhase, set_atomic_batch_chunk_size_for_test,
    set_atomic_batch_fault_for_test,
};
use ferrum_edge::{
    admin::{
        AdminState,
        jwt_auth::{JwtConfig, JwtManager},
        serve_admin_on_listener,
    },
    config::db_loader::{DatabaseStore, DbPoolConfig},
};
use jsonwebtoken::{EncodingKey, Header, encode};
use serde_json::{Value, json};
use std::net::SocketAddr;
use std::sync::Arc;
use tempfile::TempDir;

const JWT_SECRET: &str = "test-secret-key-for-batch-atomicity-32chars";
const JWT_ISSUER: &str = "test-ferrum-edge";

fn jwt_manager() -> JwtManager {
    JwtManager::new(JwtConfig {
        secret: JWT_SECRET.to_string(),
        issuer: JWT_ISSUER.to_string(),
        audience: None,
        max_ttl_seconds: 3600,
        algorithm: jsonwebtoken::Algorithm::HS256,
    })
}

fn admin_token() -> String {
    let now = Utc::now();
    let claims = json!({
        "iss": JWT_ISSUER,
        "sub": "batch-atomicity-admin",
        "role": "admin",
        "iat": now.timestamp(),
        "nbf": now.timestamp(),
        "exp": (now + chrono::Duration::seconds(3600)).timestamp(),
        "jti": uuid::Uuid::new_v4().to_string(),
    });
    encode(
        &Header::new(jsonwebtoken::Algorithm::HS256),
        &claims,
        &EncodingKey::from_secret(JWT_SECRET.as_bytes()),
    )
    .unwrap()
}

fn test_pool_config() -> DbPoolConfig {
    DbPoolConfig {
        max_connections: 4,
        min_connections: 0,
        acquire_timeout_seconds: 5,
        idle_timeout_seconds: 60,
        max_lifetime_seconds: 300,
        connect_timeout_seconds: 5,
        statement_timeout_seconds: 0,
    }
}

async fn make_store(dir: &TempDir) -> DatabaseStore {
    let db_path = dir
        .path()
        .join(format!("batch-atomicity-{}.db", uuid::Uuid::new_v4()));
    let url = format!("sqlite:{}?mode=rwc", db_path.to_string_lossy());
    DatabaseStore::connect_with_pool_config("sqlite", &url, test_pool_config())
        .await
        .expect("connect sqlite store")
}

fn admin_state(db: DatabaseStore) -> AdminState {
    AdminState {
        db: Some(Arc::new(db)),
        jwt_manager: jwt_manager(),
        metrics_auth: Default::default(),
        cached_config: None,
        proxy_state: None,
        mode: "database".to_string(),
        read_only: false,
        admin_audit_enabled: true,
        admin_audit_fallback_dir: Some(crate::common::isolated_audit_fallback_dir()),
        admin_require_namespace_claim: false,
        startup_ready: None,
        serving_degraded: None,
        serving_listener_failures: None,
        gateway_listener_status: None,
        gateway_listener_failure_fails_readiness: false,
        db_available: None,
        config_rejected: None,
        admin_restore_max_body_size_mib: 100,
        admin_spec_max_body_size_mib: 25,
        reserved_ports: std::collections::HashSet::new(),
        stream_proxy_bind_address: "0.0.0.0".to_string(),
        admin_allowed_cidrs: Arc::new(ferrum_edge::proxy::client_ip::TrustedProxies::none()),
        cached_db_health: Arc::new(ArcSwap::new(Arc::new(None))),
        db_health_refresh: Arc::new(tokio::sync::Mutex::new(())),
        dp_registry: None,
        mesh_registry: None,
        cp_connection_state: None,
        admin_http_header_read_timeout_seconds: 10,
        mesh_runtime_state: None,
        admin_tls_handshake_timeout_seconds: 10,
        admin_request_limits: Default::default(),
        backend_allow_ips: ferrum_edge::config::BackendEgressPolicy::unrestricted(),
        external_ref_policy: std::sync::Arc::new(
            ferrum_edge::admin::api_specs::ExternalRefProcessPolicy::default(),
        ),
        external_ref_loader: std::sync::Arc::new(
            ferrum_edge::admin::api_specs::DefaultExternalDocumentLoader::default(),
        ),
    }
}

async fn start_admin(state: AdminState) -> (String, tokio::sync::watch::Sender<bool>) {
    let addr: SocketAddr = "127.0.0.1:0".parse().unwrap();
    let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);
    let listener = tokio::net::TcpListener::bind(addr).await.unwrap();
    let actual = listener.local_addr().unwrap();
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
        if tokio::net::TcpStream::connect(actual).await.is_ok() {
            return (format!("http://{}", actual), shutdown_tx);
        }
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
    }
    panic!("admin listener at {} never became ready", actual);
}

async fn post_ns(base: &str, path: &str, namespace: &str, body: &Value) -> (u16, Value) {
    let response = reqwest::Client::new()
        .post(format!("{base}{path}"))
        .bearer_auth(admin_token())
        .header("X-Ferrum-Namespace", namespace)
        .json(body)
        .send()
        .await
        .expect("POST request");
    let status = response.status().as_u16();
    let body = response.json::<Value>().await.unwrap_or_else(|_| json!({}));
    (status, body)
}

async fn get_ns(base: &str, path: &str, namespace: &str) -> (u16, Value) {
    let response = reqwest::Client::new()
        .get(format!("{base}{path}"))
        .bearer_auth(admin_token())
        .header("X-Ferrum-Namespace", namespace)
        .send()
        .await
        .expect("GET request");
    let status = response.status().as_u16();
    let body = response.json::<Value>().await.unwrap_or_else(|_| json!({}));
    (status, body)
}

/// A graph that exercises every dependency phase: consumers and upstreams with
/// no dependencies, proxies referencing an in-batch upstream, a proxy-scoped
/// plugin config referencing an in-batch proxy, and an explicit proxy→plugin
/// association so the association phase has real work.
///
/// `id_prefix` must be unique per phase iteration inside one shared SQLite
/// store. Upstream/proxy/plugin primary keys are global (`id` alone), so
/// reusing the same ids across namespaces collides on retry after an earlier
/// phase's successful commit — exactly the false `409` these tests were
/// trapping as an atomicity failure.
fn graph_payload(count: usize, id_prefix: &str) -> Value {
    let consumers: Vec<Value> = (0..count)
        .map(|index| {
            json!({
                "id": format!("{id_prefix}-consumer-{index}"),
                "username": format!("{id_prefix}-user-{index}"),
            })
        })
        .collect();
    let upstreams: Vec<Value> = (0..count)
        .map(|index| {
            json!({
                "id": format!("{id_prefix}-upstream-{index}"),
                "name": format!("{id_prefix}-upstream-name-{index}"),
                "targets": [{"host": "10.0.0.10", "port": 8080, "weight": 100}],
                "algorithm": "round_robin",
            })
        })
        .collect();
    let proxies: Vec<Value> = (0..count)
        .map(|index| {
            json!({
                "id": format!("{id_prefix}-proxy-{index}"),
                "name": format!("{id_prefix}-proxy-name-{index}"),
                "listen_path": format!("/{id_prefix}/{index}"),
                "backend_scheme": "http",
                "backend_host": "127.0.0.1",
                "backend_port": 8080,
                "upstream_id": format!("{id_prefix}-upstream-{index}"),
                "plugins": [{
                    "plugin_config_id": format!("{id_prefix}-plugin-{index}"),
                }],
            })
        })
        .collect();
    let plugin_configs: Vec<Value> = (0..count)
        .map(|index| {
            json!({
                "id": format!("{id_prefix}-plugin-{index}"),
                "plugin_name": "request_size_limiting",
                "scope": "proxy",
                "proxy_id": format!("{id_prefix}-proxy-{index}"),
                "enabled": true,
                "config": {"max_bytes": 1048576},
            })
        })
        .collect();
    json!({
        "consumers": consumers,
        "upstreams": upstreams,
        "proxies": proxies,
        "plugin_configs": plugin_configs,
    })
}

/// Every list endpoint the batch could have written must be empty for this
/// namespace. `/backup` is used rather than four list calls so a resource that
/// landed without a matching change record is still visible.
async fn assert_namespace_empty(base: &str, namespace: &str, context: &str) {
    let (status, body) = get_ns(base, "/backup", namespace).await;
    assert_eq!(status, 200, "{context}: backup read failed: {body:?}");
    for family in ["proxies", "consumers", "plugin_configs", "upstreams"] {
        let items = body[family].as_array().map(Vec::len).unwrap_or(0);
        assert_eq!(
            items, 0,
            "{context}: {family} survived a failed atomic batch: {body:?}"
        );
    }
}

async fn assert_graph_present(base: &str, namespace: &str, count: usize, context: &str) {
    let (status, body) = get_ns(base, "/backup", namespace).await;
    assert_eq!(status, 200, "{context}: backup read failed: {body:?}");
    for family in ["proxies", "consumers", "plugin_configs", "upstreams"] {
        let items = body[family].as_array().map(Vec::len).unwrap_or(0);
        assert_eq!(
            items, count,
            "{context}: expected {count} {family} after a committed atomic batch: {body:?}"
        );
    }
    // The association phase is the last write in the transaction; a committed
    // graph must carry it.
    let proxies = body["proxies"].as_array().expect("proxies array");
    for proxy in proxies {
        let plugins = proxy["plugins"].as_array().map(Vec::len).unwrap_or(0);
        assert_eq!(
            plugins, 1,
            "{context}: committed proxy lost its plugin association: {proxy:?}"
        );
    }
}

/// Every phase, faulted before it writes anything: nothing durable, and the
/// unchanged payload still applies cleanly afterwards.
#[tokio::test]
async fn every_dependency_phase_fault_leaves_nothing_durable_and_retries_cleanly() {
    let tmp = TempDir::new().unwrap();
    let (base, _shutdown) = start_admin(admin_state(make_store(&tmp).await)).await;

    let phases = [
        ("consumers", AtomicBatchPhase::Consumers),
        ("upstreams", AtomicBatchPhase::Upstreams),
        ("proxies", AtomicBatchPhase::Proxies),
        ("plugin_configs", AtomicBatchPhase::PluginConfigs),
        (
            "proxy_plugin_associations",
            AtomicBatchPhase::ProxyPluginAssociations,
        ),
        (
            "admission_revalidation",
            AtomicBatchPhase::AdmissionRevalidation,
        ),
        ("commit", AtomicBatchPhase::Commit),
    ];

    for (label, phase) in phases {
        let namespace = format!("atomic-phase-{label}");
        set_atomic_batch_fault_for_test(&namespace, Some(AtomicBatchFault::new(phase, 0)));

        let payload = graph_payload(2, &format!("phase-{label}"));
        let (status, body) = post_ns(&base, "/batch", &namespace, &payload).await;
        assert_eq!(
            status, 503,
            "phase {label}: a faulted atomic batch must not report success: {body:?}"
        );
        assert!(
            body.get("created").is_none(),
            "phase {label}: a failed atomic batch must not report created counts: {body:?}"
        );
        assert_eq!(
            body["rollback"], "not_needed",
            "phase {label}: atomicity means there is nothing to roll back: {body:?}"
        );
        assert_namespace_empty(&base, &namespace, &format!("phase {label}")).await;

        // Idempotent retry: the identical payload applies once the injected
        // failure is gone, because the failed attempt left no conflicting rows.
        set_atomic_batch_fault_for_test(&namespace, None);
        let (status, body) = post_ns(&base, "/batch", &namespace, &payload).await;
        assert_eq!(
            status, 201,
            "phase {label}: retry after an atomic failure must succeed: {body:?}"
        );
        assert_eq!(body["created"]["consumers"], 2);
        assert_eq!(body["created"]["upstreams"], 2);
        assert_eq!(body["created"]["proxies"], 2);
        assert_eq!(body["created"]["plugin_configs"], 2);
        assert_graph_present(&base, &namespace, 2, &format!("phase {label} retry")).await;
    }
}

/// A failure *after* a chunk boundary is the case the old chunk-per-transaction
/// design could not roll back. Chunks are shrunk to 2 so a 3-record family
/// crosses a boundary, then the fault trips after the first completed chunk.
#[tokio::test]
async fn fault_after_chunk_boundary_leaves_nothing_durable_and_retries_cleanly() {
    let tmp = TempDir::new().unwrap();
    let (base, _shutdown) = start_admin(admin_state(make_store(&tmp).await)).await;

    let phases = [
        ("consumers", AtomicBatchPhase::Consumers),
        ("upstreams", AtomicBatchPhase::Upstreams),
        ("proxies", AtomicBatchPhase::Proxies),
        ("plugin_configs", AtomicBatchPhase::PluginConfigs),
        (
            "proxy_plugin_associations",
            AtomicBatchPhase::ProxyPluginAssociations,
        ),
    ];

    for (label, phase) in phases {
        let namespace = format!("atomic-chunk-{label}");
        set_atomic_batch_chunk_size_for_test(&namespace, Some(2));
        set_atomic_batch_fault_for_test(&namespace, Some(AtomicBatchFault::new(phase, 1)));

        // 3 records per family with a chunk size of 2: the first chunk of the
        // faulted phase completes, the second never runs.
        let payload = graph_payload(3, &format!("chunk-{label}"));
        let (status, body) = post_ns(&base, "/batch", &namespace, &payload).await;
        assert_eq!(
            status, 503,
            "phase {label}: a post-chunk-boundary fault must not report success: {body:?}"
        );
        assert_namespace_empty(
            &base,
            &namespace,
            &format!("phase {label} after chunk boundary"),
        )
        .await;

        set_atomic_batch_fault_for_test(&namespace, None);
        let (status, body) = post_ns(&base, "/batch", &namespace, &payload).await;
        assert_eq!(
            status, 201,
            "phase {label}: retry after a post-chunk-boundary failure must succeed: {body:?}"
        );
        assert_graph_present(&base, &namespace, 3, &format!("phase {label} chunk retry")).await;
        set_atomic_batch_chunk_size_for_test(&namespace, None);
    }
}

/// The reproduction from issue #2401: a new consumer ahead of an upstream whose
/// ID already exists. The consumer used to be committed and the response used to
/// be `207`; now the whole graph is refused with `409` and the namespace is
/// untouched, so the identical retry is not poisoned by a half-applied batch.
#[tokio::test]
async fn duplicate_resource_rejects_whole_graph_without_committing_earlier_families() {
    let tmp = TempDir::new().unwrap();
    let (base, _shutdown) = start_admin(admin_state(make_store(&tmp).await)).await;
    let namespace = "atomic-duplicate";

    let (status, body) = post_ns(
        &base,
        "/upstreams",
        namespace,
        &json!({
            "id": "atomic-duplicate-upstream",
            "name": "atomic-duplicate-upstream",
            "targets": [{"host": "10.0.0.10", "port": 8080, "weight": 100}],
            "algorithm": "round_robin",
        }),
    )
    .await;
    assert_eq!(status, 201, "upstream seed failed: {body:?}");

    let batch = json!({
        "consumers": [{
            "id": "atomic-duplicate-consumer",
            "username": "atomic-duplicate-user",
        }],
        "upstreams": [{
            "id": "atomic-duplicate-upstream",
            "name": "atomic-duplicate-upstream-again",
            "targets": [{"host": "10.0.0.11", "port": 8080, "weight": 100}],
            "algorithm": "round_robin",
        }],
    });
    let (status, body) = post_ns(&base, "/batch", namespace, &batch).await;
    assert_eq!(
        status, 409,
        "a duplicate inside the graph must reject the whole graph: {body:?}"
    );
    assert!(
        body.get("created").is_none(),
        "a rejected graph must not report created counts: {body:?}"
    );

    let (status, consumer) = get_ns(&base, "/consumers/atomic-duplicate-consumer", namespace).await;
    assert_eq!(
        status, 404,
        "the consumer ahead of the duplicate must not survive: {consumer:?}"
    );

    // No `batch_create` audit event: nothing was created, so there is no
    // mutation to attribute.
    let (status, audit) = get_ns(
        &base,
        "/audit?resource_type=gateway_config&action=batch_create",
        namespace,
    )
    .await;
    assert_eq!(status, 200, "audit read failed: {audit:?}");
    assert_eq!(
        audit["total"], 0,
        "a fully rejected batch must not write a batch_create audit event: {audit:?}"
    );

    // Retry is idempotent once the caller fixes the duplicate.
    let fixed = json!({
        "consumers": [{
            "id": "atomic-duplicate-consumer",
            "username": "atomic-duplicate-user",
        }],
        "upstreams": [{
            "id": "atomic-duplicate-upstream-2",
            "name": "atomic-duplicate-upstream-2",
            "targets": [{"host": "10.0.0.11", "port": 8080, "weight": 100}],
            "algorithm": "round_robin",
        }],
    });
    let (status, body) = post_ns(&base, "/batch", namespace, &fixed).await;
    assert_eq!(status, 201, "corrected retry must succeed: {body:?}");
    assert_eq!(body["created"]["consumers"], 1);
    assert_eq!(body["created"]["upstreams"], 1);
}

/// A committed graph writes exactly one `batch_create` audit event, and the
/// per-family counts in the diff describe the whole graph.
#[tokio::test]
async fn committed_graph_writes_one_audit_event_with_full_counts() {
    let tmp = TempDir::new().unwrap();
    let (base, _shutdown) = start_admin(admin_state(make_store(&tmp).await)).await;
    let namespace = "atomic-audit";

    let (status, body) = post_ns(&base, "/batch", namespace, &graph_payload(2, "audit")).await;
    assert_eq!(status, 201, "atomic batch failed: {body:?}");

    let mut audit = json!({});
    for _ in 0..100 {
        let (status, current) = get_ns(
            &base,
            "/audit?resource_type=gateway_config&action=batch_create",
            namespace,
        )
        .await;
        audit = current;
        if status == 200 && audit["total"].as_u64() == Some(1) {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
    }
    assert_eq!(audit["total"], 1, "audit events: {audit:?}");
    let event = &audit["items"].as_array().expect("audit items")[0];
    assert_eq!(event["action"], "batch_create");
    assert_eq!(event["diff"]["after"]["consumers"], 2);
    assert_eq!(event["diff"]["after"]["upstreams"], 2);
    assert_eq!(event["diff"]["after"]["proxies"], 2);
    assert_eq!(event["diff"]["after"]["plugin_configs"], 2);
}
