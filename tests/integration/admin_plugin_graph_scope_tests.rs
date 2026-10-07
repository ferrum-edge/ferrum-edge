//! Plugin-graph admission validates the write's neighborhood, not the whole
//! namespace (issue #6056).
//!
//! `POST /batch` and single Proxy/PluginConfig writes used to load and
//! revalidate every proxy and plugin config in the namespace, so each request
//! cost O(namespace). They now load only the proxies the write affects, their
//! plugin configs, every global, and every instance of a namespace-wide plugin
//! type. These tests pin the rejections that depend on resources the write does
//! not name, the full-graph fallback, and the SQL neighborhood query against
//! the reference definition.

use crate::scaffolding::port_registry::TestSocket;

use arc_swap::ArcSwap;
use chrono::Utc;
use ferrum_edge::{
    admin::{
        AdminState,
        jwt_auth::{JwtConfig, JwtManager},
        serve_admin_on_listener,
    },
    config::{
        batch_atomicity::AtomicBatchGraph,
        db_backend::{BatchConfigWriteMode, DatabaseBackend},
        db_loader::{DatabaseStore, DbPoolConfig},
        policy_graph_scope::PolicyGraphScope,
        types::{GatewayConfig, PluginAssociation, PluginConfig, PluginScope, Proxy},
    },
};
use jsonwebtoken::{EncodingKey, Header, encode};
use serde_json::{Value, json};
use std::net::SocketAddr;
use std::sync::Arc;
use tempfile::TempDir;

const JWT_SECRET: &str = "test-secret-key-for-plugin-graph-scope-32";
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
        "sub": "plugin-graph-scope-admin",
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

async fn make_store(dir: &TempDir) -> DatabaseStore {
    let db_path = dir
        .path()
        .join(format!("plugin-graph-scope-{}.db", uuid::Uuid::new_v4()));
    let url = format!("sqlite:{}?mode=rwc", db_path.to_string_lossy());
    DatabaseStore::connect_with_pool_config(
        "sqlite",
        &url,
        DbPoolConfig {
            max_connections: 4,
            min_connections: 0,
            acquire_timeout_seconds: 5,
            idle_timeout_seconds: 60,
            max_lifetime_seconds: 300,
            connect_timeout_seconds: 5,
            statement_timeout_seconds: 0,
        },
    )
    .await
    .expect("connect sqlite store")
}

fn admin_state(db: Arc<DatabaseStore>) -> AdminState {
    AdminState {
        db: Some(db),
        jwt_manager: jwt_manager(),
        metrics_auth: Default::default(),
        cached_config: None,
        proxy_state: None,
        mode: "database".to_string(),
        read_only: false,
        admin_audit_enabled: false,
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
        external_ref_policy: Arc::new(
            ferrum_edge::admin::api_specs::ExternalRefProcessPolicy::default(),
        ),
        external_ref_loader: Arc::new(
            ferrum_edge::admin::api_specs::DefaultExternalDocumentLoader::default(),
        ),
        runtime_config_apply: None,
    }
}

async fn start_admin(db: Arc<DatabaseStore>) -> (String, tokio::sync::watch::Sender<bool>) {
    let addr: SocketAddr = "127.0.0.1:0".parse().unwrap();
    let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);
    let listener = tokio::net::TcpListener::bind_test(addr).await.unwrap();
    let actual = listener.local_addr().unwrap();
    tokio::spawn(async move {
        let _ = serve_admin_on_listener(
            listener,
            admin_state(db),
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

async fn send(
    method: reqwest::Method,
    base: &str,
    path: &str,
    namespace: &str,
    body: &Value,
) -> (u16, Value) {
    let response = reqwest::Client::new()
        .request(method, format!("{base}{path}"))
        .bearer_auth(admin_token())
        .header("X-Ferrum-Namespace", namespace)
        .json(body)
        .send()
        .await
        .expect("admin request");
    let status = response.status().as_u16();
    let body = response.json::<Value>().await.unwrap_or_else(|_| json!({}));
    (status, body)
}

async fn post(base: &str, path: &str, namespace: &str, body: &Value) -> (u16, Value) {
    send(reqwest::Method::POST, base, path, namespace, body).await
}

fn http_proxy(id: &str, plugin_ids: &[&str]) -> Value {
    json!({
        "id": id,
        "listen_path": format!("/{id}"),
        "backend_scheme": "http",
        "backend_host": "127.0.0.1",
        "backend_port": 9,
        "plugins": plugin_ids
            .iter()
            .map(|plugin_id| json!({"plugin_config_id": plugin_id}))
            .collect::<Vec<_>>(),
    })
}

fn load_testing(id: &str, scope: &str, proxy_id: Option<&str>, enabled: bool) -> Value {
    let mut plugin = json!({
        "id": id,
        "plugin_name": "load_testing",
        "scope": scope,
        "enabled": enabled,
        "config": {
            "key": "plugin-graph-scope-load-test-key",
            "concurrent_clients": 1,
            "duration_seconds": 1,
            "gateway_port": 9,
            "request_timeout_ms": 200
        },
    });
    if let Some(proxy_id) = proxy_id {
        plugin["proxy_id"] = json!(proxy_id);
    }
    plugin
}

fn api_chargeback(id: &str, proxy_id: &str, max_entries: u64) -> Value {
    json!({
        "id": id,
        "plugin_name": "api_chargeback",
        "scope": "proxy",
        "proxy_id": proxy_id,
        "enabled": true,
        "config": {
            "pricing_tiers": [{"status_codes": [200], "price_per_call": 0.01}],
            "cleanup_interval_seconds": 0,
            "max_entries": max_entries
        },
    })
}

fn errors_text(body: &Value) -> String {
    body.to_string()
}

/// `api_chargeback` instances share one process-global registry, so every
/// enabled instance must agree on its tunables. The conflicting instance sits
/// on a proxy the write never names; the neighborhood must still carry it.
#[tokio::test]
async fn batch_api_chargeback_disagreeing_with_unnamed_proxy_instance_is_rejected() {
    let tmp = TempDir::new().unwrap();
    let (base, _shutdown) = start_admin(Arc::new(make_store(&tmp).await)).await;
    let namespace = "scope-chargeback";

    let (status, body) = post(
        &base,
        "/batch",
        namespace,
        &json!({ "proxies": [http_proxy("p1", &[]), http_proxy("p2", &[])] }),
    )
    .await;
    assert_eq!(status, 201, "seed proxies: {body}");
    let (status, body) = post(
        &base,
        "/batch",
        namespace,
        &json!({ "plugin_configs": [api_chargeback("charge-p1", "p1", 100)] }),
    )
    .await;
    assert_eq!(status, 201, "seed chargeback on p1: {body}");

    let (status, body) = post(
        &base,
        "/batch",
        namespace,
        &json!({ "plugin_configs": [api_chargeback("charge-p2", "p2", 200)] }),
    )
    .await;
    assert_eq!(status, 400, "disagreeing chargeback admitted: {body}");
    assert!(
        errors_text(&body).contains("shared render/cleanup tunables must match"),
        "unexpected rejection: {body}"
    );

    // An agreeing instance on the other proxy is still admitted.
    let (status, body) = post(
        &base,
        "/batch",
        namespace,
        &json!({ "plugin_configs": [api_chargeback("charge-p2", "p2", 100)] }),
    )
    .await;
    assert_eq!(status, 201, "agreeing chargeback rejected: {body}");
}

/// A proxy-scoped config in a batch is attached to its `proxy_id` by
/// persistence, so admission must compose it into that proxy's existing chain.
#[tokio::test]
async fn batch_proxy_scoped_plugin_is_composed_into_its_existing_proxy() {
    let tmp = TempDir::new().unwrap();
    let (base, _shutdown) = start_admin(Arc::new(make_store(&tmp).await)).await;
    let namespace = "scope-attach";

    let (status, body) = post(
        &base,
        "/batch",
        namespace,
        &json!({ "proxies": [http_proxy("p1", &[])] }),
    )
    .await;
    assert_eq!(status, 201, "seed proxy: {body}");
    let (status, body) = post(
        &base,
        "/batch",
        namespace,
        &json!({ "plugin_configs": [load_testing("lt-1", "proxy", Some("p1"), true)] }),
    )
    .await;
    assert_eq!(status, 201, "seed first load_testing: {body}");

    let (status, body) = post(
        &base,
        "/batch",
        namespace,
        &json!({ "plugin_configs": [load_testing("lt-2", "proxy", Some("p1"), true)] }),
    )
    .await;
    assert_eq!(
        status, 400,
        "second effective load_testing admitted: {body}"
    );
    assert!(
        errors_text(&body).contains("load_testing permits at most one effective instance"),
        "unexpected rejection: {body}"
    );
}

/// Enabling a proxy-group config changes the chain of every proxy associated
/// with it. The write names only the config; the conflict is on an associated
/// proxy the write never mentions.
#[tokio::test]
async fn enabling_proxy_group_plugin_rejects_conflict_on_unnamed_associated_proxy() {
    let tmp = TempDir::new().unwrap();
    let (base, _shutdown) = start_admin(Arc::new(make_store(&tmp).await)).await;
    let namespace = "scope-group";

    let (status, body) = post(
        &base,
        "/batch",
        namespace,
        &json!({
            "proxies": [http_proxy("p1", &["lt-group"]), http_proxy("p2", &["lt-group"])],
            "plugin_configs": [
                load_testing("lt-group", "proxy_group", None, false),
                load_testing("lt-local", "proxy", Some("p2"), true),
            ],
        }),
    )
    .await;
    assert_eq!(status, 201, "seed graph: {body}");

    let (status, body) = send(
        reqwest::Method::PUT,
        &base,
        "/plugins/config/lt-group",
        namespace,
        &load_testing("lt-group", "proxy_group", None, true),
    )
    .await;
    assert_eq!(
        status, 400,
        "group enable admitted a conflict on p2: {body}"
    );
    assert!(
        errors_text(&body).contains("proxy_id=\\\"p2\\\"")
            && errors_text(&body).contains("load_testing permits at most one effective instance"),
        "rejection must name the unnamed associated proxy: {body}"
    );
}

/// A global `tcp_connection_throttle` must keep protecting at least one TCP
/// proxy, which only the whole namespace can decide. Shadowing it on the only
/// TCP proxy leaves it attached to HTTP proxies alone.
#[tokio::test]
async fn global_tcp_connection_throttle_is_decided_on_the_full_graph() {
    let tmp = TempDir::new().unwrap();
    let (base, _shutdown) = start_admin(Arc::new(make_store(&tmp).await)).await;
    let namespace = "scope-tcp-throttle";

    let (status, body) = post(
        &base,
        "/batch",
        namespace,
        &json!({
            "proxies": [
                http_proxy("http-1", &[]),
                {
                    "id": "tcp-1",
                    "backend_scheme": "tcp",
                    "backend_host": "127.0.0.1",
                    "backend_port": 9,
                    "listen_port": 19461
                },
            ],
        }),
    )
    .await;
    assert_eq!(status, 201, "seed proxies: {body}");
    let (status, body) = post(
        &base,
        "/plugins/config",
        namespace,
        &json!({
            "id": "throttle-global",
            "plugin_name": "tcp_connection_throttle",
            "scope": "global",
            "enabled": true,
            "config": {"max_connections_per_key": 10}
        }),
    )
    .await;
    assert_eq!(status, 201, "seed global throttle: {body}");

    let (status, body) = post(
        &base,
        "/batch",
        namespace,
        &json!({
            "plugin_configs": [{
                "id": "throttle-tcp-1",
                "plugin_name": "tcp_connection_throttle",
                "scope": "proxy",
                "proxy_id": "tcp-1",
                "enabled": true,
                "config": {"max_connections_per_key": 5}
            }],
        }),
    )
    .await;
    assert_eq!(
        status, 400,
        "shadowing the global throttle on its only TCP proxy was admitted: {body}"
    );
    assert!(
        errors_text(&body).contains("has no TCP/TCP+TLS proxy to protect"),
        "unexpected rejection: {body}"
    );
}

/// The point of scoping: a conflict already stored on one proxy (here written
/// straight to the store, as an older release or a direct DB edit could) must
/// not block an unrelated write to another proxy. The full-graph validator
/// refused every plugin-graph write in the namespace instead.
#[tokio::test]
async fn unrelated_write_is_admitted_beside_a_stored_conflict_outside_its_neighborhood() {
    let tmp = TempDir::new().unwrap();
    let db = Arc::new(make_store(&tmp).await);
    let (base, _shutdown) = start_admin(Arc::clone(&db)).await;
    let namespace = "scope-unrelated";

    let (status, body) = post(
        &base,
        "/batch",
        namespace,
        &json!({ "proxies": [http_proxy("bad", &[]), http_proxy("good", &[])] }),
    )
    .await;
    assert_eq!(status, 201, "seed proxies: {body}");
    for id in ["lt-a", "lt-b"] {
        let plugin: PluginConfig =
            serde_json::from_value(load_testing(id, "proxy", Some("bad"), true)).unwrap();
        let plugin = PluginConfig {
            namespace: namespace.to_string(),
            ..plugin
        };
        db.create_plugin_config(&plugin).await.expect("seed plugin");
    }
    let mut bad = db
        .get_proxy(namespace, "bad")
        .await
        .unwrap()
        .expect("bad proxy");
    bad.plugins = vec![
        PluginAssociation {
            plugin_config_id: "lt-a".into(),
        },
        PluginAssociation {
            plugin_config_id: "lt-b".into(),
        },
    ];
    assert!(
        db.update_proxy(&bad).await.unwrap(),
        "attach seeded conflict"
    );
    let graph = db.load_namespace_policy_graph(namespace).await.unwrap();
    assert!(
        ferrum_edge::PluginCache::new(&graph).is_err(),
        "precondition: the stored graph must hold a composition conflict"
    );

    let (status, body) = post(
        &base,
        "/batch",
        namespace,
        &json!({ "plugin_configs": [load_testing("lt-good", "proxy", Some("good"), true)] }),
    )
    .await;
    assert_eq!(
        status, 201,
        "a write outside the conflicting proxy's neighborhood was refused: {body}"
    );

    // A write that does touch the conflicting proxy still sees it.
    let (status, body) = post(
        &base,
        "/batch",
        namespace,
        &json!({ "plugin_configs": [load_testing("lt-c", "proxy", Some("bad"), true)] }),
    )
    .await;
    assert_eq!(
        status, 400,
        "write to the conflicting proxy admitted: {body}"
    );
}

fn sorted_graph(mut graph: GatewayConfig) -> (Vec<Proxy>, Vec<PluginConfig>) {
    for proxy in &mut graph.proxies {
        proxy
            .plugins
            .sort_by(|a, b| a.plugin_config_id.cmp(&b.plugin_config_id));
    }
    graph.proxies.sort_by(|a, b| a.id.cmp(&b.id));
    graph.plugin_configs.sort_by(|a, b| a.id.cmp(&b.id));
    (graph.proxies, graph.plugin_configs)
}

fn ids<T>(items: &[T], id: impl Fn(&T) -> &str) -> Vec<String> {
    items.iter().map(|item| id(item).to_string()).collect()
}

fn in_namespace<T: serde::de::DeserializeOwned>(namespace: &str, mut value: Value) -> T {
    value["namespace"] = json!(namespace);
    serde_json::from_value(value).expect("resource fixture")
}

async fn seed_parity_graph(db: &dyn DatabaseBackend, namespace: &str, other: bool) {
    let rate_limit = |id: &str, scope: &str, proxy_id: Option<&str>| {
        let mut plugin = json!({
            "id": id,
            "plugin_name": "rate_limiting",
            "scope": scope,
            "enabled": true,
            "config": {"limits": [{"scope": "default", "requests_per_minute": 60}]},
        });
        if let Some(proxy_id) = proxy_id {
            plugin["proxy_id"] = json!(proxy_id);
        }
        plugin
    };
    let (proxies, plugins): (Vec<Value>, Vec<Value>) = if other {
        (
            vec![http_proxy("p1", &["group-a"])],
            vec![
                rate_limit("group-a", "proxy_group", None),
                rate_limit("other-global", "global", None),
            ],
        )
    } else {
        (
            vec![
                http_proxy("p1", &["group-a"]),
                http_proxy("p2", &["group-a", "group-b"]),
                // Proxy-scoped associations are listed explicitly so the fixture
                // does not depend on whether a backend's batch persistence
                // auto-attaches a config to its `proxy_id`.
                http_proxy("p3", &["local-p3"]),
                http_proxy("p4", &["local-p4"]),
                http_proxy("p5", &["charge-p5"]),
                http_proxy("p6", &["group-b", "local-p6"]),
            ],
            vec![
                rate_limit("global-rl", "global", None),
                rate_limit("group-a", "proxy_group", None),
                rate_limit("group-b", "proxy_group", None),
                rate_limit("local-p3", "proxy", Some("p3")),
                rate_limit("local-p4", "proxy", Some("p4")),
                rate_limit("local-p6", "proxy", Some("p6")),
                api_chargeback("charge-p5", "p5", 100),
            ],
        )
    };
    let proxies: Vec<Proxy> = proxies
        .into_iter()
        .map(|value| in_namespace(namespace, value))
        .collect();
    let plugins: Vec<PluginConfig> = plugins
        .into_iter()
        .map(|value| in_namespace(namespace, value))
        .collect();
    db.batch_create_config_graph_atomically(
        &AtomicBatchGraph {
            namespace,
            consumers: &[],
            upstreams: &[],
            proxies: &proxies,
            plugin_configs: &plugins,
            admission_lease: None,
        },
        &BatchConfigWriteMode::Admission,
    )
    .await
    .expect("seed parity graph");
}

/// Every backend's `load_namespace_policy_neighborhood` must return exactly
/// the reference definition, `PolicyGraphScope::restrict` over the full policy
/// graph. Shared with the PostgreSQL/MySQL/MongoDB live-store lane.
pub(crate) async fn assert_policy_neighborhood_matches_restricted_graph(db: &dyn DatabaseBackend) {
    let namespace = format!("scope-parity-{}", uuid::Uuid::new_v4().simple());
    seed_parity_graph(db, &namespace, false).await;
    // Another namespace's rows must never leak into the neighborhood.
    seed_parity_graph(db, &format!("{namespace}-other"), true).await;

    let full = db.load_namespace_policy_graph(&namespace).await.unwrap();
    let stored_proxy = |id: &str| {
        full.proxies
            .iter()
            .find(|proxy| proxy.id == id)
            .cloned()
            .unwrap()
    };
    let stored_plugin = |id: &str| {
        full.plugin_configs
            .iter()
            .find(|plugin| plugin.id == id)
            .cloned()
            .unwrap()
    };
    let new_local = PluginConfig {
        id: "new-local-p4".into(),
        ..stored_plugin("local-p4")
    };
    let scopes = [
        PolicyGraphScope::for_write(&[], &[], None).unwrap(),
        PolicyGraphScope::for_write(&[stored_proxy("p3")], &[], None).unwrap(),
        PolicyGraphScope::for_write(&[], &[stored_plugin("group-b")], None).unwrap(),
        PolicyGraphScope::for_write(&[], &[new_local], None).unwrap(),
        PolicyGraphScope::for_write(&[], &[], Some("group-a")).unwrap(),
        PolicyGraphScope::for_write(&[stored_proxy("p1")], &[], Some("missing")).unwrap(),
    ];
    for scope in &scopes {
        let scoped = db
            .load_namespace_policy_neighborhood(&namespace, scope)
            .await
            .unwrap();
        let (scoped_proxies, scoped_plugins) = sorted_graph(scoped);
        let (expected_proxies, expected_plugins) = sorted_graph(scope.restrict(full.clone()));
        assert_eq!(
            serde_json::to_value(&scoped_proxies).unwrap(),
            serde_json::to_value(&expected_proxies).unwrap(),
            "proxies differ for {scope:?}: got {:?}, want {:?}",
            ids(&scoped_proxies, |p| &p.id),
            ids(&expected_proxies, |p| &p.id),
        );
        assert_eq!(
            serde_json::to_value(&scoped_plugins).unwrap(),
            serde_json::to_value(&expected_plugins).unwrap(),
            "plugin configs differ for {scope:?}: got {:?}, want {:?}",
            ids(&scoped_plugins, |p| &p.id),
            ids(&expected_plugins, |p| &p.id),
        );
    }

    // Spot-check the definition itself on the group-b change: both associated
    // proxies, their configs, the global, and the namespace-wide chargeback.
    let (proxies, plugins) = sorted_graph(scopes[2].restrict(full.clone()));
    assert_eq!(ids(&proxies, |p| &p.id), ["p2", "p6"]);
    assert_eq!(
        ids(&plugins, |p| &p.id),
        ["charge-p5", "global-rl", "group-a", "group-b", "local-p6"]
    );
    for scope in &scopes {
        let scoped = db
            .load_namespace_policy_neighborhood(&namespace, scope)
            .await
            .unwrap();
        assert!(
            scoped
                .proxies
                .iter()
                .all(|proxy| proxy.namespace == namespace)
                && scoped
                    .plugin_configs
                    .iter()
                    .all(|plugin| plugin.namespace == namespace),
            "neighborhood leaked another namespace's rows for {scope:?}"
        );
    }
    assert!(
        PolicyGraphScope::for_write(&[], &[stored_plugin("global-rl")], None).is_none(),
        "a global write must take the full graph"
    );
}

#[tokio::test]
async fn sql_policy_neighborhood_matches_restricted_full_graph() {
    let tmp = TempDir::new().unwrap();
    let db = make_store(&tmp).await;
    assert_policy_neighborhood_matches_restricted_graph(&db).await;
}
