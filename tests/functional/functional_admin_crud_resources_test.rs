//! Functional admin CRUD resource coverage.
//!
//! Existing functional suites cover individual admin surfaces such as proxy
//! routing, plugin CRUD, backup/restore, Mongo connectivity, and file-mode
//! startup/reload. These tests fill the cross-resource gaps:
//! - full Proxy/Consumer/PluginConfig/Upstream CRUD on one SQL backend
//! - the same CRUD matrix on MongoDB
//! - upstream field variants, including health-check settings
//! - all available plugin config CRUD through the admin API
//! - OpenAPI spec CRUD and extracted runtime resources
//! - file-mode reload updates and deletes resource-backed runtime state while
//!   admin writes remain read-only

use crate::common::{DbType, TestGateway, spawn_http_identifying};
use ferrum_edge::plugins::available_plugins;
use reqwest::{Client, StatusCode};
use serde_json::{Value, json};
use std::time::{Duration, Instant};
use tokio::time::sleep;
use uuid::Uuid;

const DEFAULT_MONGO_URL: &str = "mongodb://localhost:27017/ferrum_test";
const PLUGIN_NAMES_UNDER_TEST: &[&str] = &[
    "transaction_log_schema",
    "stdout_logging",
    "http_logging",
    "tcp_logging",
    "kafka_logging",
    "ws_logging",
    "transaction_debugger",
    "jwks_auth",
    "oauth2_introspection",
    "oidc_relying_party",
    "jwt_auth",
    "key_auth",
    "basic_auth",
    "ldap_auth",
    "hmac_auth",
    "mtls_auth",
    "spiffe_identity",
    "mesh_authz",
    "opa",
    "mesh_outbound_registry",
    "compression",
    "cors",
    "security_headers",
    "access_control",
    "tcp_connection_throttle",
    "adaptive_concurrency",
    "ip_restriction",
    "bot_detection",
    "correlation_id",
    "request_transformer",
    "response_transformer",
    "mesh_route_dispatch",
    "graphql",
    "grpc_method_router",
    "grpc_deadline",
    "grpc_web",
    "rate_limiting",
    "request_size_limiting",
    "waf",
    "response_size_limiting",
    "body_validator",
    "openapi_validator",
    "request_termination",
    "response_caching",
    "response_mock",
    "serverless_function",
    "prometheus_metrics",
    "proxy_alerts",
    "otel_tracing",
    "ai_token_metrics",
    "ai_request_guard",
    "ai_rate_limiter",
    "ai_prompt_shield",
    "ai_prompt_compressor",
    "ai_response_guard",
    "ai_semantic_cache",
    "ai_semantic_firewall",
    "ai_tool_governor",
    "ai_transcript_audit",
    "ai_federation",
    "ai_stream_router",
    "mcp_gateway",
    "a2a_gateway",
    "ws_message_size_limiting",
    "ws_frame_logging",
    "ws_rate_limiting",
    "udp_rate_limiting",
    "udp_logging",
    "statsd_logging",
    "loki_logging",
    "sse",
    "request_mirror",
    "load_testing",
    "geo_restriction",
    "request_deduplication",
    "soap_ws_security",
    "spec_expose",
    "api_chargeback",
    "api_chargeback_sink",
    "workload_metrics",
    "__mesh_bpf_metrics",
    "fault_injection",
    "example_audit_plugin",
    "example_plugin",
];

struct MongoDatabaseCleanup {
    url: String,
    database: String,
}

impl MongoDatabaseCleanup {
    fn new(url: String, database: String) -> Self {
        Self { url, database }
    }
}

impl Drop for MongoDatabaseCleanup {
    fn drop(&mut self) {
        let url = self.url.clone();
        let database = self.database.clone();
        let handle = std::thread::spawn(move || {
            let Ok(runtime) = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
            else {
                eprintln!("failed to build runtime for MongoDB cleanup of {database}");
                return;
            };

            runtime.block_on(async move {
                match mongodb::Client::with_uri_str(&url).await {
                    Ok(client) => {
                        if let Err(error) = client.database(&database).drop().await {
                            eprintln!("failed to drop MongoDB test database {database}: {error}");
                        }
                    }
                    Err(error) => {
                        eprintln!("failed to connect for MongoDB test database cleanup: {error}");
                    }
                }
            });
        });
        let _ = handle.join();
    }
}

#[tokio::test]
#[ignore]
async fn test_admin_sqlite_runtime_resource_crud_matrix() {
    let backend_a = spawn_http_identifying("sql-crud-a")
        .await
        .expect("spawn sql backend a");
    let backend_b = spawn_http_identifying("sql-crud-b")
        .await
        .expect("spawn sql backend b");

    let gateway = TestGateway::builder()
        .mode_database_sqlite()
        .log_level("warn")
        .db_poll_interval_seconds(1)
        .spawn()
        .await
        .expect("spawn sqlite gateway");

    run_admin_resource_crud_matrix(
        &gateway,
        backend_a.port,
        backend_b.port,
        "sqlite",
        "sql-crud-a",
        "sql-crud-b",
    )
    .await;
    run_upstream_field_variant_crud(&gateway, backend_a.port, backend_b.port, "sqlite").await;
    run_api_spec_crud_bundle(
        &gateway,
        backend_a.port,
        backend_b.port,
        "sqlite",
        "sql-crud-a",
        "sql-crud-b",
    )
    .await;
    run_available_plugin_config_crud(&gateway, backend_a.port, "sqlite").await;
}

#[tokio::test]
#[ignore]
async fn test_admin_mongodb_runtime_resource_crud_matrix() {
    let mongo_url =
        std::env::var("FERRUM_TEST_MONGO_URL").unwrap_or_else(|_| DEFAULT_MONGO_URL.to_string());
    if !mongodb_is_available(&mongo_url).await {
        eprintln!("MongoDB is not available at {mongo_url}; skipping MongoDB CRUD matrix");
        return;
    }

    let backend_a = spawn_http_identifying("mongo-crud-a")
        .await
        .expect("spawn mongo backend a");
    let backend_b = spawn_http_identifying("mongo-crud-b")
        .await
        .expect("spawn mongo backend b");
    let mongo_database = format!("ferrum_crud_{}", Uuid::new_v4().simple());
    let _mongo_cleanup = MongoDatabaseCleanup::new(mongo_url.clone(), mongo_database.clone());

    let gateway = TestGateway::builder()
        .mode_database(DbType::Mongo(mongo_url))
        .env("FERRUM_MONGO_DATABASE", mongo_database)
        .log_level("warn")
        .db_poll_interval_seconds(1)
        .spawn()
        .await
        .expect("spawn mongodb gateway");

    run_admin_resource_crud_matrix(
        &gateway,
        backend_a.port,
        backend_b.port,
        "mongodb",
        "mongo-crud-a",
        "mongo-crud-b",
    )
    .await;
    run_upstream_field_variant_crud(&gateway, backend_a.port, backend_b.port, "mongodb").await;
    run_api_spec_crud_bundle(
        &gateway,
        backend_a.port,
        backend_b.port,
        "mongodb",
        "mongo-crud-a",
        "mongo-crud-b",
    )
    .await;
    run_available_plugin_config_crud(&gateway, backend_a.port, "mongodb").await;
}

#[tokio::test]
#[ignore]
async fn test_file_mode_reload_updates_and_deletes_runtime_resources() {
    let backend_a = spawn_http_identifying("file-crud-a")
        .await
        .expect("spawn file backend a");
    let backend_b = spawn_http_identifying("file-crud-b")
        .await
        .expect("spawn file backend b");

    let initial_config = file_mode_resource_config(backend_a.port, "old-file-key");
    let gateway = TestGateway::builder()
        .mode_file(initial_config)
        .log_level("warn")
        .spawn()
        .await
        .expect("spawn file gateway");

    let client = Client::new();
    let auth = gateway.auth_header();

    for path in [
        "/proxies/file-crud-proxy",
        "/upstreams/file-crud-upstream",
        "/consumers/file-crud-consumer",
        "/plugins/config/file-crud-key-auth",
    ] {
        let value = admin_get_json(&client, &gateway, path, &auth).await;
        assert_eq!(
            value["id"],
            path.rsplit('/').next().unwrap(),
            "file-mode admin GET should expose loaded resource at {path}"
        );
    }

    let forbidden = client
        .post(gateway.admin_url("/proxies"))
        .header("Authorization", &auth)
        .json(&json!({
            "id": "file-write-should-fail",
            "listen_path": "/forbidden",
            "backend_scheme": "http",
            "backend_host": "127.0.0.1",
            "backend_port": backend_a.port
        }))
        .send()
        .await
        .expect("POST /proxies in file mode");
    assert_status(
        forbidden,
        StatusCode::FORBIDDEN,
        "file-mode admin writes are read-only",
    )
    .await;

    wait_for_server_with_key(
        &client,
        &gateway.proxy_url("/file-crud/check"),
        Some("old-file-key"),
        "file-crud-a",
    )
    .await;

    let config_path = gateway
        .config_path
        .as_ref()
        .expect("file-mode harness exposes config path");
    std::fs::write(
        config_path,
        file_mode_resource_config(backend_b.port, "new-file-key"),
    )
    .expect("rewrite file-mode config");
    send_sighup(&gateway);

    wait_for_status_with_key(
        &client,
        &gateway.proxy_url("/file-crud/check"),
        Some("old-file-key"),
        StatusCode::UNAUTHORIZED,
    )
    .await;
    wait_for_server_with_key(
        &client,
        &gateway.proxy_url("/file-crud/check"),
        Some("new-file-key"),
        "file-crud-b",
    )
    .await;

    std::fs::write(config_path, empty_file_mode_config()).expect("clear file-mode config");
    send_sighup(&gateway);

    wait_for_status_with_key(
        &client,
        &gateway.proxy_url("/file-crud/check"),
        Some("new-file-key"),
        StatusCode::NOT_FOUND,
    )
    .await;

    let deleted = client
        .get(gateway.admin_url("/proxies/file-crud-proxy"))
        .header("Authorization", &auth)
        .send()
        .await
        .expect("GET deleted file proxy");
    assert_status(
        deleted,
        StatusCode::NOT_FOUND,
        "file-mode admin cache should drop deleted proxy after reload",
    )
    .await;
}

async fn run_admin_resource_crud_matrix(
    gateway: &TestGateway,
    backend_a_port: u16,
    backend_b_port: u16,
    prefix: &str,
    backend_a_name: &str,
    backend_b_name: &str,
) {
    let client = Client::new();
    let auth = gateway.auth_header();
    let suffix = Uuid::new_v4().simple().to_string();
    let suffix = &suffix[..8];
    let base = format!("{prefix}-{suffix}");
    let upstream_id = format!("{base}-upstream");
    let proxy_id = format!("{base}-proxy");
    let consumer_id = format!("{base}-consumer");
    let plugin_id = format!("{base}-plugin");
    let listen_path = format!("/{base}");

    let upstream = json!({
        "id": upstream_id,
        "name": format!("{base} upstream"),
        "algorithm": "round_robin",
        "targets": [{"host": "127.0.0.1", "port": backend_a_port, "weight": 1}]
    });
    admin_post_json(&client, gateway, "/upstreams", &auth, upstream).await;
    let value = admin_get_json(
        &client,
        gateway,
        &format!("/upstreams/{upstream_id}"),
        &auth,
    )
    .await;
    assert_eq!(value["targets"].as_array().unwrap().len(), 1);

    let updated_upstream = json!({
        "id": upstream_id,
        "name": format!("{base} upstream updated"),
        "algorithm": "round_robin",
        "targets": [{"host": "127.0.0.1", "port": backend_b_port, "weight": 1}]
    });
    admin_put_json(
        &client,
        gateway,
        &format!("/upstreams/{upstream_id}"),
        &auth,
        updated_upstream.clone(),
    )
    .await;
    let value = admin_get_json(
        &client,
        gateway,
        &format!("/upstreams/{upstream_id}"),
        &auth,
    )
    .await;
    assert_eq!(value["targets"][0]["port"], backend_b_port);

    admin_delete(
        &client,
        gateway,
        &format!("/upstreams/{upstream_id}"),
        &auth,
    )
    .await;
    assert_admin_not_found(
        &client,
        gateway,
        &format!("/upstreams/{upstream_id}"),
        &auth,
    )
    .await;
    admin_post_json(&client, gateway, "/upstreams", &auth, updated_upstream).await;

    let proxy = json!({
        "id": proxy_id,
        "listen_path": listen_path,
        "backend_scheme": "http",
        "backend_host": "127.0.0.1",
        "backend_port": backend_a_port,
        "strip_listen_path": true,
        "upstream_id": upstream_id
    });
    admin_post_json(&client, gateway, "/proxies", &auth, proxy).await;
    let value = admin_get_json(&client, gateway, &format!("/proxies/{proxy_id}"), &auth).await;
    assert_eq!(value["upstream_id"], upstream_id);

    let consumer = json!({
        "id": consumer_id,
        "username": format!("{base}-user"),
        "custom_id": format!("{base}-custom")
    });
    admin_post_json(&client, gateway, "/consumers", &auth, consumer).await;
    let value = admin_get_json(
        &client,
        gateway,
        &format!("/consumers/{consumer_id}"),
        &auth,
    )
    .await;
    assert_eq!(value["custom_id"], format!("{base}-custom"));

    let updated_consumer = json!({
        "id": consumer_id,
        "username": format!("{base}-user-renamed"),
        "custom_id": format!("{base}-custom-updated"),
        "acl_groups": ["crud-admins"]
    });
    admin_put_json(
        &client,
        gateway,
        &format!("/consumers/{consumer_id}"),
        &auth,
        updated_consumer,
    )
    .await;
    let value = admin_get_json(
        &client,
        gateway,
        &format!("/consumers/{consumer_id}"),
        &auth,
    )
    .await;
    assert_eq!(value["username"], format!("{base}-user-renamed"));
    assert_eq!(value["acl_groups"][0], "crud-admins");

    let plugin = json!({
        "id": plugin_id,
        "plugin_name": "rate_limiting",
        "scope": "proxy",
        "proxy_id": proxy_id,
        "enabled": true,
        "config": {
            "limit_by": "ip",
            "limits": [{"scope": "default", "requests_per_minute": 100}]
        }
    });
    admin_post_json(&client, gateway, "/plugins/config", &auth, plugin).await;
    let value = admin_get_json(
        &client,
        gateway,
        &format!("/plugins/config/{plugin_id}"),
        &auth,
    )
    .await;
    assert_eq!(value["enabled"], true);

    let updated_plugin = json!({
        "id": plugin_id,
        "plugin_name": "rate_limiting",
        "scope": "proxy",
        "proxy_id": proxy_id,
        "enabled": false,
        "config": {
            "limit_by": "ip",
            "limits": [{"scope": "default", "requests_per_minute": 200}]
        }
    });
    admin_put_json(
        &client,
        gateway,
        &format!("/plugins/config/{plugin_id}"),
        &auth,
        updated_plugin,
    )
    .await;
    let value = admin_get_json(
        &client,
        gateway,
        &format!("/plugins/config/{plugin_id}"),
        &auth,
    )
    .await;
    assert_eq!(value["enabled"], false);
    assert_eq!(value["config"]["limits"][0]["requests_per_minute"], 200);

    admin_delete(
        &client,
        gateway,
        &format!("/plugins/config/{plugin_id}"),
        &auth,
    )
    .await;
    assert_admin_not_found(
        &client,
        gateway,
        &format!("/plugins/config/{plugin_id}"),
        &auth,
    )
    .await;

    wait_for_server(
        &client,
        &gateway.proxy_url(&format!("{listen_path}/one")),
        backend_b_name,
    )
    .await;

    let updated_proxy = json!({
        "id": proxy_id,
        "listen_path": listen_path,
        "backend_scheme": "http",
        "backend_host": "127.0.0.1",
        "backend_port": backend_a_port,
        "strip_listen_path": false,
        "upstream_id": null
    });
    admin_put_json(
        &client,
        gateway,
        &format!("/proxies/{proxy_id}"),
        &auth,
        updated_proxy,
    )
    .await;
    let value = admin_get_json(&client, gateway, &format!("/proxies/{proxy_id}"), &auth).await;
    assert!(value["upstream_id"].is_null());
    assert_eq!(value["strip_listen_path"], false);

    wait_for_server(
        &client,
        &gateway.proxy_url(&format!("{listen_path}/two")),
        backend_a_name,
    )
    .await;

    admin_delete(
        &client,
        gateway,
        &format!("/consumers/{consumer_id}"),
        &auth,
    )
    .await;
    assert_admin_not_found(
        &client,
        gateway,
        &format!("/consumers/{consumer_id}"),
        &auth,
    )
    .await;

    admin_delete(&client, gateway, &format!("/proxies/{proxy_id}"), &auth).await;
    assert_admin_not_found(&client, gateway, &format!("/proxies/{proxy_id}"), &auth).await;
    wait_for_status(
        &client,
        &gateway.proxy_url(&format!("{listen_path}/gone")),
        StatusCode::NOT_FOUND,
    )
    .await;
}

async fn run_upstream_field_variant_crud(
    gateway: &TestGateway,
    backend_a_port: u16,
    backend_b_port: u16,
    prefix: &str,
) {
    let client = Client::new();
    let auth = gateway.auth_header();
    let suffix = Uuid::new_v4().simple().to_string();
    let suffix = &suffix[..8];
    let upstream_id = format!("{prefix}-{suffix}-variant-upstream");

    let upstream = json!({
        "id": upstream_id,
        "name": format!("{prefix}-{suffix} variant upstream"),
        "algorithm": "consistent_hashing",
        "hash_on": "cookie:ferrum-affinity",
        "hash_on_cookie_config": {
            "path": "/",
            "ttl_seconds": 180,
            "domain": "example.com",
            "http_only": true,
            "secure": true,
            "same_site": "Lax"
        },
        "targets": [
            {
                "host": "127.0.0.1",
                "port": backend_a_port,
                "weight": 2,
                "tags": {"version": "v1", "region": "east"},
                "locality": "us-east/us-east-1a/rack-a",
                "path": "/v1"
            },
            {
                "host": "127.0.0.1",
                "port": backend_b_port,
                "weight": 3,
                "tags": {"version": "v2", "region": "west"},
                "locality": "us-west/us-west-2a/rack-b",
                "path": "/v2"
            }
        ],
        "health_checks": {
            "active": {
                "http_path": "/ready",
                "interval_seconds": 60,
                "timeout_ms": 750,
                "healthy_threshold": 2,
                "unhealthy_threshold": 3,
                "healthy_status_codes": [200, 204],
                "probe_type": "http",
                "use_tls": false
            },
            "passive": {
                "unhealthy_status_codes": [500, 502, 503],
                "unhealthy_threshold": 4,
                "unhealthy_window_seconds": 30,
                "healthy_after_seconds": 5,
                "max_ejection_percent": 50,
                "gateway_error_codes": [502, 503, 504],
                "split_external_local_origin_errors": true
            }
        },
        "subsets": [
            {
                "name": "stable",
                "labels": {"version": "v1"},
                "traffic_policy": {"load_balancer_algorithm": "weighted_round_robin"}
            },
            {
                "name": "canary",
                "labels": {"version": "v2"},
                "traffic_policy": {"load_balancer_algorithm": "random"}
            }
        ],
        "backend_tls_verify_server_cert": false,
        "backend_tls_sni": "backend.example.com",
        "backend_tls_san_allow_list": [
            "backend.example.com",
            "127.0.0.1",
            "spiffe://example.test/ns/default/sa/backend"
        ]
    });
    admin_post_json(&client, gateway, "/upstreams", &auth, upstream).await;

    let value = admin_get_json(
        &client,
        gateway,
        &format!("/upstreams/{upstream_id}"),
        &auth,
    )
    .await;
    assert_eq!(value["algorithm"], "consistent_hashing");
    assert_eq!(value["hash_on"], "cookie:ferrum-affinity");
    assert_eq!(value["hash_on_cookie_config"]["same_site"], "Lax");
    assert_eq!(value["targets"][1]["tags"]["version"], "v2");
    assert_eq!(value["health_checks"]["active"]["probe_type"], "http");
    assert_eq!(
        value["health_checks"]["passive"]["gateway_error_codes"],
        json!([502, 503, 504])
    );
    assert_eq!(
        value["subsets"][0]["traffic_policy"]["load_balancer_algorithm"],
        "weighted_round_robin"
    );
    assert_eq!(value["backend_tls_sni"], "backend.example.com");
    assert_eq!(
        value["backend_tls_san_allow_list"][2],
        "spiffe://example.test/ns/default/sa/backend"
    );

    for algorithm in [
        "round_robin",
        "weighted_round_robin",
        "least_connections",
        "least_latency",
        "consistent_hashing",
        "random",
    ] {
        let hash_on = if algorithm == "consistent_hashing" {
            json!("header:x-user-id")
        } else {
            Value::Null
        };
        let updated = json!({
            "id": upstream_id,
            "name": format!("{prefix}-{suffix} algorithm {algorithm}"),
            "algorithm": algorithm,
            "hash_on": hash_on,
            "targets": [{"host": "127.0.0.1", "port": backend_a_port, "weight": 1}],
            "health_checks": {
                "passive": {
                    "unhealthy_status_codes": [500, 502],
                    "unhealthy_threshold": 2,
                    "unhealthy_window_seconds": 10,
                    "healthy_after_seconds": 1
                }
            },
            "backend_tls_verify_server_cert": true
        });
        admin_put_json(
            &client,
            gateway,
            &format!("/upstreams/{upstream_id}"),
            &auth,
            updated,
        )
        .await;
        let value = admin_get_json(
            &client,
            gateway,
            &format!("/upstreams/{upstream_id}"),
            &auth,
        )
        .await;
        assert_eq!(value["algorithm"], algorithm);
        if algorithm == "consistent_hashing" {
            assert_eq!(value["hash_on"], "header:x-user-id");
        } else {
            assert!(value["hash_on"].is_null());
        }
    }

    for (probe_type, extra_fields) in [
        ("http", json!({"http_path": "/ready"})),
        ("tcp", json!({})),
        ("udp", json!({"udp_probe_payload": "70696e67"})),
        ("grpc", json!({"grpc_service_name": "inventory.Health"})),
    ] {
        let mut active = json!({
            "http_path": "/ready",
            "interval_seconds": 60,
            "timeout_ms": 500,
            "healthy_threshold": 1,
            "unhealthy_threshold": 2,
            "healthy_status_codes": [200],
            "probe_type": probe_type,
            "use_tls": false
        });
        merge_json_object(&mut active, extra_fields);

        let updated = json!({
            "id": upstream_id,
            "name": format!("{prefix}-{suffix} health {probe_type}"),
            "algorithm": "round_robin",
            "targets": [{"host": "127.0.0.1", "port": backend_a_port, "weight": 1}],
            "health_checks": {
                "active": active,
                "passive": {
                    "unhealthy_status_codes": [500, 502, 503, 504],
                    "unhealthy_threshold": 3,
                    "unhealthy_window_seconds": 20,
                    "healthy_after_seconds": 2,
                    "max_ejection_percent": 25,
                    "split_external_local_origin_errors": false
                }
            }
        });
        admin_put_json(
            &client,
            gateway,
            &format!("/upstreams/{upstream_id}"),
            &auth,
            updated,
        )
        .await;
        let value = admin_get_json(
            &client,
            gateway,
            &format!("/upstreams/{upstream_id}"),
            &auth,
        )
        .await;
        assert_eq!(value["health_checks"]["active"]["probe_type"], probe_type);
    }

    admin_delete(
        &client,
        gateway,
        &format!("/upstreams/{upstream_id}"),
        &auth,
    )
    .await;
    assert_admin_not_found(
        &client,
        gateway,
        &format!("/upstreams/{upstream_id}"),
        &auth,
    )
    .await;
}

async fn run_api_spec_crud_bundle(
    gateway: &TestGateway,
    backend_a_port: u16,
    backend_b_port: u16,
    prefix: &str,
    backend_a_name: &str,
    backend_b_name: &str,
) {
    let client = Client::new();
    let auth = gateway.auth_header();
    let suffix = Uuid::new_v4().simple().to_string();
    let suffix = &suffix[..8];
    let proxy_id = format!("{prefix}-{suffix}-spec-proxy");
    let upstream_id = format!("{prefix}-{suffix}-spec-upstream");
    let plugin_v1_id = format!("{prefix}-{suffix}-spec-cors");
    let plugin_v2_id = format!("{prefix}-{suffix}-spec-correlation");
    let listen_path = format!("/{prefix}-{suffix}-spec");

    let title_v1 = format!("{prefix} CRUD Orders API");
    let spec_v1 = api_spec_document(ApiSpecFixture {
        title: &title_v1,
        version: "1.0.0",
        listen_path: &listen_path,
        proxy_id: &proxy_id,
        upstream_id: &upstream_id,
        backend_port: backend_a_port,
        plugin_id: &plugin_v1_id,
        plugin_name: "cors",
        plugin_config: json!({
            "allowed_origins": ["https://app.example.com"],
            "allowed_methods": ["GET"],
            "allowed_headers": ["authorization", "content-type"],
            "max_age": 60
        }),
        validate: true,
    });
    let created = admin_post_json(&client, gateway, "/api-specs", &auth, spec_v1).await;
    let spec_id = created["id"]
        .as_str()
        .expect("api spec create response has id")
        .to_string();
    assert_eq!(created["proxy_id"], proxy_id);

    let fetched = admin_get_json(&client, gateway, &format!("/api-specs/{spec_id}"), &auth).await;
    assert_eq!(
        fetched["info"]["title"],
        format!("{prefix} CRUD Orders API")
    );
    assert_eq!(fetched["x-ferrum-proxy"]["id"], proxy_id);

    let by_proxy = admin_get_json(
        &client,
        gateway,
        &format!("/api-specs/by-proxy/{proxy_id}"),
        &auth,
    )
    .await;
    assert_eq!(by_proxy["x-ferrum-upstream"]["id"], upstream_id);

    let listed = admin_get_json(&client, gateway, "/api-specs?limit=100", &auth).await;
    assert!(
        listed["items"]
            .as_array()
            .expect("api spec list items")
            .iter()
            .any(|item| item["id"] == spec_id),
        "api spec list should include {spec_id}: {listed}"
    );

    let proxy = admin_get_json(&client, gateway, &format!("/proxies/{proxy_id}"), &auth).await;
    assert_eq!(proxy["api_spec_id"], spec_id);
    assert_eq!(proxy["upstream_id"], upstream_id);
    let upstream = admin_get_json(
        &client,
        gateway,
        &format!("/upstreams/{upstream_id}"),
        &auth,
    )
    .await;
    assert_eq!(upstream["api_spec_id"], spec_id);
    assert_eq!(upstream["health_checks"]["active"]["http_path"], "/ready");
    let plugin = admin_get_json(
        &client,
        gateway,
        &format!("/plugins/config/{plugin_v1_id}"),
        &auth,
    )
    .await;
    assert_eq!(plugin["api_spec_id"], spec_id);
    assert_eq!(plugin["plugin_name"], "cors");
    assert_api_spec_generated_validator(&client, gateway, &auth, &spec_id, &proxy_id).await;

    wait_for_server(
        &client,
        &gateway.proxy_url(&format!("{listen_path}/orders/123")),
        backend_a_name,
    )
    .await;

    let title_v2 = format!("{prefix} CRUD Orders API v2");
    let spec_v2 = api_spec_document(ApiSpecFixture {
        title: &title_v2,
        version: "2.0.0",
        listen_path: &listen_path,
        proxy_id: &proxy_id,
        upstream_id: &upstream_id,
        backend_port: backend_b_port,
        plugin_id: &plugin_v2_id,
        plugin_name: "correlation_id",
        plugin_config: json!({"header_name": "x-ferrum-request-id", "echo_downstream": true}),
        validate: true,
    });
    let updated = admin_put_json(
        &client,
        gateway,
        &format!("/api-specs/{spec_id}"),
        &auth,
        spec_v2,
    )
    .await;
    assert_eq!(updated["id"], spec_id);
    assert_eq!(updated["proxy_id"], proxy_id);

    assert_admin_not_found(
        &client,
        gateway,
        &format!("/plugins/config/{plugin_v1_id}"),
        &auth,
    )
    .await;
    let plugin = admin_get_json(
        &client,
        gateway,
        &format!("/plugins/config/{plugin_v2_id}"),
        &auth,
    )
    .await;
    assert_eq!(plugin["plugin_name"], "correlation_id");
    let upstream = admin_get_json(
        &client,
        gateway,
        &format!("/upstreams/{upstream_id}"),
        &auth,
    )
    .await;
    assert_eq!(upstream["targets"][0]["port"], backend_b_port);

    wait_for_server(
        &client,
        &gateway.proxy_url(&format!("{listen_path}/orders/456")),
        backend_b_name,
    )
    .await;

    admin_delete(&client, gateway, &format!("/api-specs/{spec_id}"), &auth).await;
    assert_admin_not_found(&client, gateway, &format!("/api-specs/{spec_id}"), &auth).await;
    assert_admin_not_found(&client, gateway, &format!("/proxies/{proxy_id}"), &auth).await;
    assert_admin_not_found(
        &client,
        gateway,
        &format!("/upstreams/{upstream_id}"),
        &auth,
    )
    .await;
    assert_admin_not_found(
        &client,
        gateway,
        &format!("/plugins/config/{plugin_v2_id}"),
        &auth,
    )
    .await;
    wait_for_status(
        &client,
        &gateway.proxy_url(&format!("{listen_path}/orders/deleted")),
        StatusCode::NOT_FOUND,
    )
    .await;
}

async fn run_available_plugin_config_crud(gateway: &TestGateway, backend_port: u16, prefix: &str) {
    let client = Client::new();
    let auth = gateway.auth_header();
    let suffix = Uuid::new_v4().simple().to_string();
    let suffix = &suffix[..8];
    let base = format!("{prefix}-{suffix}-plugins");
    let dispatch_upstream_id = format!("{base}-dispatch-upstream");

    assert_eq!(
        sorted_strings(available_plugins()),
        sorted_strings(PLUGIN_NAMES_UNDER_TEST.to_vec()),
        "functional plugin CRUD fixtures must be updated when available plugins change"
    );

    let runtime_plugins = admin_get_json(&client, gateway, "/plugins", &auth).await;
    assert_eq!(
        sorted_json_strings(&runtime_plugins),
        sorted_strings(PLUGIN_NAMES_UNDER_TEST.to_vec()),
        "runtime /plugins response should match plugin CRUD fixture list"
    );

    admin_post_json(
        &client,
        gateway,
        "/upstreams",
        &auth,
        json!({
            "id": dispatch_upstream_id,
            "name": format!("{base} dispatch upstream"),
            "targets": [{"host": "127.0.0.1", "port": backend_port, "weight": 1}]
        }),
    )
    .await;

    let validator_proxy_id = format!("{base}-validator-proxy");
    let validator_upstream_id = format!("{base}-validator-upstream");
    let validator_listen_path = format!("/{base}-validator");
    let validator_title = format!("{base} validator host");
    let validator_plugin_id = format!("{base}-validator-cors");
    let validator_spec = api_spec_document(ApiSpecFixture {
        title: &validator_title,
        version: "1.0.0",
        listen_path: &validator_listen_path,
        proxy_id: &validator_proxy_id,
        upstream_id: &validator_upstream_id,
        backend_port,
        plugin_id: &validator_plugin_id,
        plugin_name: "cors",
        plugin_config: json!({"allowed_origins": ["*"]}),
        validate: false,
    });
    let validator_spec_created =
        admin_post_json(&client, gateway, "/api-specs", &auth, validator_spec).await;
    let validator_spec_id = validator_spec_created["id"]
        .as_str()
        .expect("validator api spec id")
        .to_string();

    let mut plugin_ids = Vec::new();
    for (idx, plugin_name) in PLUGIN_NAMES_UNDER_TEST.iter().enumerate() {
        let plugin_id = format!("{base}-p{idx}");
        let config = plugin_config_fixture(plugin_name, &dispatch_upstream_id);
        let (scope, proxy_id) = match *plugin_name {
            "openapi_validator" => ("proxy", Some(validator_proxy_id.as_str())),
            // These plugins own process-global registries, so the admin write
            // path and runtime rejecting contract both require global scope.
            "transaction_log_schema" | "prometheus_metrics" => ("global", None),
            _ => ("proxy_group", None),
        };

        let mut create_body = json!({
            "id": plugin_id,
            "plugin_name": plugin_name,
            "scope": scope,
            "enabled": false,
            "priority_override": idx as u16,
            "config": config
        });
        if let Some(proxy_id) = proxy_id {
            create_body["proxy_id"] = json!(proxy_id);
        }
        admin_post_json(
            &client,
            gateway,
            "/plugins/config",
            &auth,
            create_body.clone(),
        )
        .await;

        let value = admin_get_json(
            &client,
            gateway,
            &format!("/plugins/config/{plugin_id}"),
            &auth,
        )
        .await;
        assert_eq!(value["plugin_name"], *plugin_name);
        assert_eq!(value["scope"], scope);
        assert_eq!(value["enabled"], false);
        assert_eq!(value["priority_override"], idx as u16);
        assert_eq!(
            value["config"], create_body["config"],
            "plugin config should round-trip through admin CRUD for {plugin_name}"
        );

        let mut update_body = create_body;
        update_body["enabled"] = json!(true);
        update_body["priority_override"] = json!(1000 + idx as u16);
        admin_put_json(
            &client,
            gateway,
            &format!("/plugins/config/{plugin_id}"),
            &auth,
            update_body,
        )
        .await;
        let value = admin_get_json(
            &client,
            gateway,
            &format!("/plugins/config/{plugin_id}"),
            &auth,
        )
        .await;
        assert_eq!(value["enabled"], true);
        assert_eq!(value["priority_override"], 1000 + idx as u16);

        plugin_ids.push(plugin_id);
    }

    for plugin_id in plugin_ids {
        admin_delete(
            &client,
            gateway,
            &format!("/plugins/config/{plugin_id}"),
            &auth,
        )
        .await;
        assert_admin_not_found(
            &client,
            gateway,
            &format!("/plugins/config/{plugin_id}"),
            &auth,
        )
        .await;
    }

    admin_delete(
        &client,
        gateway,
        &format!("/api-specs/{validator_spec_id}"),
        &auth,
    )
    .await;
    admin_delete(
        &client,
        gateway,
        &format!("/upstreams/{dispatch_upstream_id}"),
        &auth,
    )
    .await;
}

/// Stable prefix of the admin API's DB-driven read-only 503 body. The health
/// probe result is cached for up to 15s (`DB_HEALTH_CACHE_TTL`), so a brief
/// database blip in the container environment can hold admin writes blocked
/// well after the database itself recovers; the retry window must exceed that
/// TTL (issue #2156).
const DB_UNAVAILABLE_MARKER: &str = "Database is currently unavailable";

/// Send an admin mutation, retrying only the transient DB-driven read-only
/// 503 until it clears. Every other response (success or failure) is returned
/// to the caller's normal assertion path on the first attempt, so real
/// regressions still fail immediately.
async fn send_retrying_db_unavailable<F, Fut>(mut send: F, context: &str) -> reqwest::Response
where
    F: FnMut() -> Fut,
    Fut: std::future::Future<Output = Result<reqwest::Response, reqwest::Error>>,
{
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(30);
    loop {
        let response = send()
            .await
            .unwrap_or_else(|err| panic!("{context}: {err}"));
        if response.status() != StatusCode::SERVICE_UNAVAILABLE {
            return response;
        }
        let body = response.text().await.unwrap_or_default();
        assert!(
            body.contains(DB_UNAVAILABLE_MARKER),
            "{context} failed with 503 Service Unavailable: {body}"
        );
        assert!(
            std::time::Instant::now() < deadline,
            "{context} still blocked by the DB-driven read-only guard after 30s: {body}"
        );
        tokio::time::sleep(std::time::Duration::from_millis(500)).await;
    }
}

async fn admin_post_json(
    client: &Client,
    gateway: &TestGateway,
    path: &str,
    auth: &str,
    body: Value,
) -> Value {
    let response = send_retrying_db_unavailable(
        || {
            client
                .post(gateway.admin_url(path))
                .header("Authorization", auth)
                .json(&body)
                .send()
        },
        &format!("POST {path}"),
    )
    .await;
    expect_json_success(response, &format!("POST {path}")).await
}

async fn admin_put_json(
    client: &Client,
    gateway: &TestGateway,
    path: &str,
    auth: &str,
    body: Value,
) -> Value {
    let response = send_retrying_db_unavailable(
        || {
            client
                .put(gateway.admin_url(path))
                .header("Authorization", auth)
                .json(&body)
                .send()
        },
        &format!("PUT {path}"),
    )
    .await;
    expect_json_success(response, &format!("PUT {path}")).await
}

async fn admin_get_json(client: &Client, gateway: &TestGateway, path: &str, auth: &str) -> Value {
    let response = client
        .get(gateway.admin_url(path))
        .header("Authorization", auth)
        .send()
        .await
        .unwrap_or_else(|err| panic!("GET {path}: {err}"));
    expect_json_success(response, &format!("GET {path}")).await
}

async fn admin_delete(client: &Client, gateway: &TestGateway, path: &str, auth: &str) {
    let response = send_retrying_db_unavailable(
        || {
            client
                .delete(gateway.admin_url(path))
                .header("Authorization", auth)
                .send()
        },
        &format!("DELETE {path}"),
    )
    .await;
    assert_success(response, &format!("DELETE {path}")).await;
}

async fn assert_admin_not_found(client: &Client, gateway: &TestGateway, path: &str, auth: &str) {
    let response = client
        .get(gateway.admin_url(path))
        .header("Authorization", auth)
        .send()
        .await
        .unwrap_or_else(|err| panic!("GET {path}: {err}"));
    assert_status(response, StatusCode::NOT_FOUND, &format!("GET {path}")).await;
}

async fn expect_json_success(response: reqwest::Response, context: &str) -> Value {
    let status = response.status();
    let body = response.text().await.unwrap_or_default();
    assert!(
        status.is_success(),
        "{context} failed with {status}: {body}"
    );
    if body.is_empty() {
        Value::Null
    } else {
        serde_json::from_str(&body).unwrap_or_else(|err| {
            panic!("{context} returned invalid JSON ({err}): {body}");
        })
    }
}

async fn assert_success(response: reqwest::Response, context: &str) {
    let status = response.status();
    let body = response.text().await.unwrap_or_default();
    assert!(
        status.is_success(),
        "{context} failed with {status}: {body}"
    );
}

async fn assert_status(response: reqwest::Response, expected: StatusCode, context: &str) {
    let status = response.status();
    let body = response.text().await.unwrap_or_default();
    assert_eq!(status, expected, "{context} returned {status}: {body}");
}

fn merge_json_object(target: &mut Value, overlay: Value) {
    let (Some(target), Value::Object(overlay)) = (target.as_object_mut(), overlay) else {
        return;
    };
    for (key, value) in overlay {
        target.insert(key, value);
    }
}

struct ApiSpecFixture<'a> {
    title: &'a str,
    version: &'a str,
    listen_path: &'a str,
    proxy_id: &'a str,
    upstream_id: &'a str,
    backend_port: u16,
    plugin_id: &'a str,
    plugin_name: &'a str,
    plugin_config: Value,
    validate: bool,
}

fn api_spec_document(input: ApiSpecFixture<'_>) -> Value {
    let operation_path = format!("{}/orders/{{order_id}}", input.listen_path);
    let mut paths = serde_json::Map::new();
    paths.insert(
        operation_path,
        json!({
            "get": {
                "tags": ["orders"],
                "parameters": [{
                    "name": "order_id",
                    "in": "path",
                    "required": true,
                    "schema": {"type": "string"}
                }],
                "responses": {
                    "200": {
                        "description": "order response",
                        "content": {
                            "application/json": {
                                "schema": {
                                    "type": "object",
                                    "properties": {
                                        "server": {"type": "string"}
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }),
    );

    let mut spec = json!({
        "openapi": "3.1.0",
        "info": {
            "title": input.title,
            "version": input.version,
            "description": "Functional CRUD coverage spec"
        },
        "tags": [{"name": "orders"}],
        "servers": [{"url": "https://api.example.com"}],
        "paths": Value::Object(paths),
        "x-ferrum-proxy": {
            "id": input.proxy_id,
            "listen_path": input.listen_path,
            "backend_scheme": "http",
            "backend_host": "127.0.0.1",
            "backend_port": input.backend_port,
            "strip_listen_path": true,
            "upstream_id": input.upstream_id
        },
        "x-ferrum-upstream": {
            "id": input.upstream_id,
            "name": format!("{} upstream", input.title),
            "algorithm": "least_connections",
            "targets": [{"host": "127.0.0.1", "port": input.backend_port, "weight": 1}],
            "health_checks": {
                "active": {
                    "http_path": "/ready",
                    "interval_seconds": 60,
                    "timeout_ms": 500,
                    "healthy_threshold": 1,
                    "unhealthy_threshold": 2,
                    "healthy_status_codes": [200],
                    "probe_type": "http"
                },
                "passive": {
                    "unhealthy_status_codes": [500, 502, 503],
                    "unhealthy_threshold": 2,
                    "unhealthy_window_seconds": 15,
                    "healthy_after_seconds": 3,
                    "max_ejection_percent": 50
                }
            }
        },
        "x-ferrum-plugins": [{
            "id": input.plugin_id,
            "plugin_name": input.plugin_name,
            "enabled": true,
            "priority_override": 750,
            "config": input.plugin_config
        }]
    });
    if input.validate {
        spec["x-ferrum-validate"] = json!(true);
    }
    spec
}

async fn assert_api_spec_generated_validator(
    client: &Client,
    gateway: &TestGateway,
    auth: &str,
    spec_id: &str,
    proxy_id: &str,
) {
    let listed = admin_get_json(client, gateway, "/plugins/config?limit=500", auth).await;
    assert!(
        listed["data"]
            .as_array()
            .expect("plugin config list items")
            .iter()
            .any(|item| item["api_spec_id"] == spec_id
                && item["proxy_id"] == proxy_id
                && item["plugin_name"] == "openapi_validator"),
        "api spec {spec_id} should create an openapi_validator plugin: {listed}"
    );
}

fn sorted_strings(values: Vec<&str>) -> Vec<String> {
    let mut values = values
        .into_iter()
        .map(ToString::to_string)
        .collect::<Vec<_>>();
    values.sort();
    values
}

fn sorted_json_strings(value: &Value) -> Vec<String> {
    let mut values = value
        .as_array()
        .expect("expected JSON array of strings")
        .iter()
        .map(|item| item.as_str().expect("plugin name string").to_string())
        .collect::<Vec<_>>();
    values.sort();
    values
}

fn plugin_config_fixture(plugin_name: &str, dispatch_upstream_id: &str) -> Value {
    match plugin_name {
        "transaction_log_schema" => json!({"schemas": {"default": {"summary_type": "both"}}}),
        "http_logging" => json!({"endpoint_url": "http://localhost:9200/logs"}),
        "tcp_logging" => json!({"host": "localhost", "port": 5140}),
        "kafka_logging" => json!({"broker_list": "localhost:9092", "topic": "test-logs"}),
        "ws_logging" => json!({"endpoint_url": "ws://localhost:9300/logs"}),
        "jwks_auth" => {
            json!({"providers": [{"jwks_uri": "http://127.0.0.1:9/.well-known/jwks.json"}]})
        }
        "oauth2_introspection" => json!({
            "providers": [{
                "introspection_endpoint": "http://127.0.0.1:9/introspect",
                "client_auth": {"method": "none"}
            }]
        }),
        "oidc_relying_party" => json!({
            "providers": [{
                "issuer": "https://issuer.example.com",
                "authorization_endpoint": "https://issuer.example.com/authorize",
                "token_endpoint": "https://issuer.example.com/token",
                "jwks_uri": "https://issuer.example.com/jwks",
                "client_id": "ferrum-gateway",
                "client_auth": {"method": "client_secret_basic", "client_secret": "secret"},
                "scopes": ["openid", "profile"],
                "redirect_uri": "https://app.example.com/oauth/callback",
                "callback_path": "/oauth/callback",
                "logout_path": "/oauth/logout"
            }],
            "session": {
                "store": "cookie",
                "encryption_secret": "01234567890123456789012345678901"
            },
            "behavior": {"trusted_redirect_hosts": ["app.example.com"]}
        }),
        "ldap_auth" => json!({
            "ldap_url": "ldaps://ldap.example.com:636",
            "bind_dn_template": "uid={username},ou=users,dc=example,dc=com"
        }),
        "opa" => json!({
            "opa_host": "http://127.0.0.1:8181",
            "policy_path": "ferrum/authz/allow"
        }),
        "mesh_outbound_registry" => json!({"registry": ["reviews.default.svc.cluster.local"]}),
        "cors" => json!({
            "allowed_origins": ["https://app.example.com"],
            "allowed_methods": ["GET", "POST"],
            "allowed_headers": ["authorization", "content-type"]
        }),
        "access_control" => json!({"allowed_consumers": ["testuser"]}),
        "tcp_connection_throttle" => json!({"max_connections_per_key": 10}),
        "ip_restriction" => json!({"allow": ["0.0.0.0/0"], "mode": "allow_first"}),
        "correlation_id" => json!({"header_name": "x-request-id", "echo_downstream": true}),
        "request_transformer" => {
            json!({"rules": [{"operation": "add", "target": "header", "key": "x-test", "value": "1"}]})
        }
        "response_transformer" => {
            json!({"rules": [{"operation": "add", "target": "header", "key": "x-test", "value": "1"}]})
        }
        "adaptive_concurrency" => json!({}),
        "mesh_route_dispatch" => json!({
            "rules": [{
                "match": {"methods": ["GET"]},
                "destination": {"upstream_id": dispatch_upstream_id}
            }]
        }),
        "graphql" => json!({"max_depth": 100}),
        "grpc_method_router" => json!({"allow_methods": ["test.Svc/Method"]}),
        "grpc_deadline" => json!({"max_deadline_ms": 30000}),
        "rate_limiting" => {
            json!({"limits": [{"scope": "default", "window_seconds": 60, "max_requests": 100}]})
        }
        "request_size_limiting" => json!({"max_bytes": 1048576}),
        "response_size_limiting" => json!({"max_bytes": 1048576}),
        "body_validator" => json!({"required_fields": ["name"]}),
        "openapi_validator" => json!({
            "operations": [{
                "method": "GET",
                "path_template": "/health",
                "path_regex": "^/health$",
                "responses": {
                    "200": {
                        "content": {
                            "application/json": {"type": "object"}
                        }
                    }
                }
            }]
        }),
        "response_caching" => json!({"ttl_seconds": 60}),
        "response_mock" => json!({"rules": [{"path": "/test", "body": "mock"}]}),
        "serverless_function" => {
            json!({"provider": "azure_functions", "function_url": "https://example.com/func"})
        }
        "proxy_alerts" => json!({
            "channels": {
                "ops": {"type": "slack", "webhook_url": "https://hooks.slack.com/x"}
            },
            "rules": [{
                "name": "r",
                "type": "error_rate",
                "status_codes": [500],
                "threshold_percent": 5.0,
                "channels": ["ops"]
            }]
        }),
        "otel_tracing" => json!({"endpoint": "http://localhost:4318/v1/traces"}),
        "ai_request_guard" => json!({"max_messages": 100}),
        "ai_rate_limiter" => json!({"token_limit": 100000}),
        "ai_response_guard" => json!({"pii_patterns": ["ssn"], "action": "reject"}),
        "ai_semantic_firewall" => json!({
            "provider": {
                "type": "openai_compatible_embeddings",
                "endpoint": "http://127.0.0.1:9/v1/embeddings",
                "request_timeout_ms": 100
            }
        }),
        "ai_tool_governor" => json!({
            "tools": { "github.create_pr": { "action": "allow" } }
        }),
        "ai_transcript_audit" => json!({
            "sink": {
                "endpoint_url": "http://localhost:9200/audit",
                "allow_insecure_loopback": true
            }
        }),
        "ai_federation" => {
            json!({"providers": [{"name": "test", "provider_type": "openai", "api_key": "sk-test"}]})
        }
        "ai_stream_router" => json!({
            "providers": [{
                "name": "test",
                "provider_type": "openai",
                "endpoint": "https://api.openai.com/v1/chat/completions",
                "api_key": "sk-test",
                "model_patterns": ["gpt-*"]
            }]
        }),
        "mcp_gateway" => json!({
            "mode": "transparent_proxy",
            "endpoint": {"path": "/mcp"},
            "servers": {
                "tools": {
                    "upstream_url": "http://mcp-gateway.example/mcp",
                    "namespace": "tools"
                }
            }
        }),
        "a2a_gateway" => json!({
            "mode": "transparent_proxy",
            "endpoint": {
                "path": "/a2a",
                "agent_card_path": "/.well-known/agent-card.json",
                "grpc_services": ["lf.a2a.v1.A2AService"]
            }
        }),
        "ws_message_size_limiting" => json!({"max_frame_bytes": 65536}),
        "ws_rate_limiting" => json!({"frames_per_second": 100}),
        "udp_rate_limiting" => json!({"datagrams_per_second": 1000}),
        "udp_logging" => json!({"host": "127.0.0.1", "port": 9514}),
        "statsd_logging" => json!({"host": "127.0.0.1", "port": 8125}),
        "loki_logging" => json!({"endpoint_url": "http://localhost:3100/loki/api/v1/push"}),
        "request_mirror" => json!({"mirror_host": "mirror.local"}),
        "load_testing" => {
            json!({
                "key": "test-load-key-0123456789abcdef!!",
                "concurrent_clients": 5,
                "duration_seconds": 10
            })
        }
        "geo_restriction" => {
            json!({"db_path": "/nonexistent/path/to/GeoLite2-Country.mmdb", "allow_countries": ["US"]})
        }
        "spec_expose" => json!({"spec_url": "https://example.com/openapi.yaml"}),
        "api_chargeback" => {
            json!({"pricing_tiers": [{"status_codes": [200], "price_per_call": 0.00001}]})
        }
        "api_chargeback_sink" => json!({
            "clickhouse": {
                "url": "http://127.0.0.1:8123",
                "database": "default",
                "table": "ferrum_charge_events"
            },
            "pricing_tiers": [{"status_codes": [200], "price_per_call": 0.00001}],
            "spool": {"enabled": false}
        }),
        "fault_injection" => json!({"abort": {"status_code": 503, "percentage": 50.0}}),
        "example_audit_plugin" => {
            json!({"log_request_headers": false, "retention_days": 7})
        }
        "example_plugin" => json!({"header_value": "functional-crud"}),
        _ => json!({}),
    }
}

async fn wait_for_server(client: &Client, url: &str, expected_server: &str) {
    wait_for_server_with_key(client, url, None, expected_server).await;
}

async fn wait_for_server_with_key(
    client: &Client,
    url: &str,
    key: Option<&str>,
    expected_server: &str,
) {
    let deadline = Instant::now() + Duration::from_secs(8);
    let mut last = String::from("no response yet");
    while Instant::now() < deadline {
        let mut request = client.get(url);
        if let Some(key) = key {
            request = request.header("X-Api-Key", key);
        }
        match request.send().await {
            Ok(response) => {
                let status = response.status();
                let body = response.text().await.unwrap_or_default();
                if status.is_success()
                    && let Some(server) = parse_server_name(&body)
                    && server == expected_server
                {
                    return;
                }
                last = format!("{status}: {body}");
            }
            Err(err) => last = err.to_string(),
        }
        sleep(Duration::from_millis(250)).await;
    }
    panic!("timed out waiting for {url} to route to {expected_server}; last observation: {last}");
}

async fn wait_for_status(client: &Client, url: &str, expected: StatusCode) {
    wait_for_status_with_key(client, url, None, expected).await;
}

async fn wait_for_status_with_key(
    client: &Client,
    url: &str,
    key: Option<&str>,
    expected: StatusCode,
) {
    let deadline = Instant::now() + Duration::from_secs(8);
    let mut last = String::from("no response yet");
    while Instant::now() < deadline {
        let mut request = client.get(url);
        if let Some(key) = key {
            request = request.header("X-Api-Key", key);
        }
        match request.send().await {
            Ok(response) => {
                let status = response.status();
                let body = response.text().await.unwrap_or_default();
                if status == expected {
                    return;
                }
                last = format!("{status}: {body}");
            }
            Err(err) => last = err.to_string(),
        }
        sleep(Duration::from_millis(250)).await;
    }
    panic!("timed out waiting for {url} to return {expected}; last observation: {last}");
}

fn parse_server_name(body: &str) -> Option<String> {
    serde_json::from_str::<Value>(body).ok().and_then(|value| {
        value
            .get("server")
            .and_then(Value::as_str)
            .map(str::to_string)
    })
}

fn file_mode_resource_config(backend_port: u16, key: &str) -> String {
    format!(
        r#"
version: "1"
upstreams:
  - id: "file-crud-upstream"
    name: "file-crud-upstream"
    algorithm: round_robin
    targets:
      - host: "127.0.0.1"
        port: {backend_port}
        weight: 1

proxies:
  - id: "file-crud-proxy"
    listen_path: "/file-crud"
    backend_scheme: http
    backend_host: "127.0.0.1"
    backend_port: {backend_port}
    strip_listen_path: true
    upstream_id: "file-crud-upstream"
    plugins:
      - plugin_config_id: "file-crud-key-auth"

consumers:
  - id: "file-crud-consumer"
    username: "file-crud-user"
    custom_id: "file-crud-custom"
    credentials:
      keyauth:
        - key: "{key}"

plugin_configs:
  - id: "file-crud-key-auth"
    plugin_name: "key_auth"
    scope: proxy
    proxy_id: "file-crud-proxy"
    enabled: true
    config:
      key_location: "header:X-Api-Key"
"#,
    )
}

fn empty_file_mode_config() -> &'static str {
    r#"
version: "1"
proxies: []
consumers: []
upstreams: []
plugin_configs: []
"#
}

fn send_sighup(gateway: &TestGateway) {
    #[cfg(unix)]
    {
        let pid = gateway.pid().expect("gateway process is running");
        let status = std::process::Command::new("kill")
            .args(["-HUP", &pid.to_string()])
            .status()
            .expect("send SIGHUP");
        assert!(status.success(), "kill -HUP {pid} failed with {status}");
    }

    #[cfg(not(unix))]
    panic!("file-mode SIGHUP reload functional test requires Unix");
}

async fn mongodb_is_available(url: &str) -> bool {
    let host_port = url
        .strip_prefix("mongodb://")
        .or_else(|| url.strip_prefix("mongodb+srv://"))
        .and_then(|value| value.split('/').next())
        .and_then(|value| value.split('@').next_back())
        .unwrap_or("localhost:27017");

    tokio::net::TcpStream::connect(host_port).await.is_ok()
}
