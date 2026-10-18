//! Namespace-scoped operators cannot point backend TLS material outside their
//! namespace.
//!
//! Where the JWT `ns` claim is an authorization boundary, the control plane
//! loads backend TLS references on write and every data plane later loads them
//! with its own credentials. An `operator` scoped to one namespace must
//! therefore not be able to name another namespace's Kubernetes Secret, a
//! secret-manager or managed store, or a file on the gateway's filesystem —
//! and the refusal must not depend on whether that material exists.

use arc_swap::ArcSwap;
use chrono::Utc;
use ferrum_edge::admin::{
    AdminState,
    jwt_auth::{JwtConfig, JwtManager},
    serve_admin_on_listener,
};
use ferrum_edge::config::db_backend::DatabaseBackend;
use ferrum_edge::config::db_loader::{DatabaseStore, DbPoolConfig};
use jsonwebtoken::{EncodingKey, Header, encode};
use serde_json::{Value, json};
use std::sync::Arc;
use tempfile::TempDir;

const JWT_SECRET: &str = "tenant-tls-reference-test-secret-key-0000";
const JWT_ISSUER: &str = "ferrum-edge-tenant-tls-reference-test";

fn jwt_manager() -> JwtManager {
    JwtManager::new(JwtConfig {
        secret: JWT_SECRET.to_string(),
        issuer: JWT_ISSUER.to_string(),
        audience: None,
        max_ttl_seconds: 3600,
        algorithm: jsonwebtoken::Algorithm::HS256,
    })
}

fn operator_token(namespaces: &[&str]) -> String {
    token("operator", namespaces)
}

fn token(role: &str, namespaces: &[&str]) -> String {
    token_with_claim(role, Some(namespaces))
}

fn token_with_claim(role: &str, namespaces: Option<&[&str]>) -> String {
    let now = Utc::now();
    let mut claims = json!({
        "iss": JWT_ISSUER,
        "sub": format!("tenant-a-{role}"),
        "role": role,
        "ns": namespaces,
        "iat": now.timestamp(),
        "nbf": now.timestamp(),
        "exp": (now + chrono::Duration::seconds(600)).timestamp(),
        "jti": uuid::Uuid::new_v4().to_string(),
    });
    if namespaces.is_none() {
        claims.as_object_mut().unwrap().remove("ns");
    }
    encode(
        &Header::new(jsonwebtoken::Algorithm::HS256),
        &claims,
        &EncodingKey::from_secret(JWT_SECRET.as_bytes()),
    )
    .unwrap()
}

async fn sqlite_store(temp_dir: &TempDir, file: &str) -> Arc<dyn DatabaseBackend> {
    let db_path = temp_dir.path().join(file);
    let db_url = format!("sqlite:{}?mode=rwc", db_path.to_string_lossy());
    let store = DatabaseStore::connect_with_pool_config("sqlite", &db_url, DbPoolConfig::default())
        .await
        .expect("SQLite store connects and migrates");
    Arc::new(store)
}

/// A multi-tenant control plane: writable Admin, `ns` claim enforced.
fn tenant_control_plane_state(db: Arc<dyn DatabaseBackend>) -> AdminState {
    AdminState {
        db: Some(db),
        jwt_manager: jwt_manager(),
        metrics_auth: Default::default(),
        cached_config: None,
        proxy_state: None,
        mode: "cp".to_string(),
        read_only: false,
        admin_audit_enabled: false,
        admin_audit_fallback_dir: Some(crate::isolated_audit_fallback_dir()),
        admin_require_namespace_claim: true,
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
        runtime_config_apply: None,
    }
}

async fn start_admin(state: AdminState) -> (String, tokio::sync::watch::Sender<bool>) {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);
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
        if tokio::net::TcpStream::connect(addr).await.is_ok() {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
    }
    (format!("http://{addr}"), shutdown_tx)
}

async fn post(base: &str, path: &str, token: &str, body: &Value) -> (u16, Value) {
    let request = reqwest::Client::new().post(format!("{base}{path}"));
    send(request, token, body).await
}

async fn put(base: &str, path: &str, token: &str, body: &Value) -> (u16, Value) {
    let request = reqwest::Client::new().put(format!("{base}{path}"));
    send(request, token, body).await
}

async fn send(request: reqwest::RequestBuilder, token: &str, body: &Value) -> (u16, Value) {
    let resp = request
        .bearer_auth(token)
        .header("X-Ferrum-Namespace", "tenant-a")
        .json(body)
        .send()
        .await
        .unwrap();
    let status = resp.status().as_u16();
    let body = resp.json().await.unwrap_or(Value::Null);
    (status, body)
}

fn upstream_with(field: &str, value: &str) -> Value {
    let mut body = json!({
        "id": "u-partner",
        "name": "partner",
        "targets": [{"host": "127.0.0.1", "port": 8443, "weight": 100}],
        "algorithm": "round_robin",
    });
    body[field] = json!(value);
    body
}

fn proxy_with(field: &str, value: &str) -> Value {
    let mut body = json!({
        "id": "p-partner",
        "listen_path": "/partner",
        "backend_scheme": "https",
        "backend_host": "127.0.0.1",
        "backend_port": 8443,
    });
    body[field] = json!(value);
    body
}

#[tokio::test]
async fn namespace_scoped_operator_cannot_reference_material_outside_its_namespace() {
    let temp_dir = TempDir::new().unwrap();
    let db = sqlite_store(&temp_dir, "tenant_tls_reference.db").await;
    let (base, _shutdown) = start_admin(tenant_control_plane_state(db)).await;
    let token = operator_token(&["tenant-a"]);

    let cases = [
        (
            "backend_tls_server_ca_cert_path",
            "k8s://tenant-b/db-mtls#ca.crt",
            "namespace of the resource",
        ),
        (
            "backend_tls_server_ca_cert_path",
            "vault://secret/data/tenant-b#ca",
            "secret-manager",
        ),
        (
            "backend_tls_server_ca_cert_path",
            "managed://ca-bundles/platform#ca",
            "secret-manager",
        ),
        (
            "backend_tls_server_ca_cert_path",
            "/etc/ferrum/platform/ca.pem",
            "gateway filesystem",
        ),
    ];
    for (field, value, reason) in cases {
        for (path, body) in [
            ("/upstreams", upstream_with(field, value)),
            ("/proxies", proxy_with(field, value)),
        ] {
            let (status, response) = post(&base, path, &token, &body).await;
            assert_eq!(status, 400, "{path} {value} must be refused: {response}");
            let error = response["error"].as_str().unwrap_or_default();
            assert!(
                error.contains(field) && error.contains(reason),
                "{path} {value} must be refused before any load ({reason:?}): {error}"
            );
            assert!(
                !error.contains(value) && !error.contains("tenant-b"),
                "the refusal must not echo the reference: {error}"
            );
        }
    }
}

/// A real self-signed CA, so an admitted reference also passes the load-time
/// validation that runs after the scope check.
fn ca_pem() -> String {
    use rcgen::{BasicConstraints, CertificateParams, IsCa, KeyPair};
    let key = KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).expect("ca key");
    let mut params = CertificateParams::new(vec!["ca.test".to_string()]).expect("ca params");
    params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    params.self_signed(&key).expect("ca cert").pem()
}

fn write_ca(temp_dir: &TempDir, file: &str) -> String {
    let path = temp_dir.path().join(file);
    std::fs::write(&path, ca_pem()).expect("write CA file");
    path.to_str().expect("utf-8 temp path").to_string()
}

fn named_upstream(id: &str, ca: &str) -> Value {
    json!({
        "id": id,
        "name": id,
        "targets": [{"host": "127.0.0.1", "port": 8443, "weight": 100}],
        "algorithm": "round_robin",
        "backend_tls_server_ca_cert_path": ca,
    })
}

fn is_scope_refusal(response: &Value) -> bool {
    let error = response["error"].as_str().unwrap_or_default();
    error.contains("namespace of the resource")
        || error.contains("secret-manager")
        || error.contains("gateway filesystem")
}

fn route_plugin_with_tls(id: &str, tls: Value) -> Value {
    json!({
        "id": id, "plugin_name": "mesh_route_dispatch", "scope": "proxy",
        "proxy_id": "p-partner", "enabled": true,
        "config": {"rules": [{
            "match": {"methods": ["GET"]},
            "destination": {"backend_host": "127.0.0.1", "backend_port": 8443, "backend_tls": tls}
        }]}
    })
}

#[tokio::test]
async fn namespace_claim_confines_route_plugin_tls_on_create_and_put() {
    let temp = TempDir::new().unwrap();
    for require in [false, true] {
        let db = sqlite_store(&temp, &format!("plugin-scope-{require}.db")).await;
        let mut state = tenant_control_plane_state(db);
        state.admin_require_namespace_claim = require;
        let (base, _shutdown) = start_admin(state).await;
        let operator = operator_token(&["tenant-a"]);
        let (status, response) = post(
            &base,
            "/proxies",
            &operator,
            &proxy_with("backend_tls_server_ca_cert_path", "system://"),
        )
        .await;
        assert!((200..300).contains(&status), "{response}");
        let own = json!({
            "client_cert_path": "k8s://tenant-a/material#tls.crt",
            "client_key_path": "k8s://tenant-a/material#tls.key",
            "server_ca_cert_path": "system://"
        });
        for field in ["client_cert_path", "client_key_path", "server_ca_cert_path"] {
            for value in [
                "k8s://tenant-b/material",
                "vault://secret/tenant-b",
                "managed://material/foreign",
                "/absent/platform/material.pem",
            ] {
                let id = format!("route-{field}");
                let mut foreign = own.clone();
                foreign[field] = json!(value);
                let forbidden = route_plugin_with_tls(&id, foreign);
                let (status, response) =
                    post(&base, "/plugins/config", &operator, &forbidden).await;
                assert_eq!(status, 400, "{require} {field}: {response}");
                assert!(is_scope_refusal(&response), "{response}");
                assert!(!response.to_string().contains(value), "{response}");
                let (status, response) = post(
                    &base,
                    "/plugins/config",
                    &operator,
                    &route_plugin_with_tls(&id, own.clone()),
                )
                .await;
                assert!(
                    (200..300).contains(&status),
                    "own references must pass without provider resolution: {response}"
                );
                let (status, response) = put(
                    &base,
                    &format!("/plugins/config/{id}?expected_proxy_ids="),
                    &operator,
                    &forbidden,
                )
                .await;
                assert_eq!(status, 400, "{require} {field}: {response}");
                assert!(is_scope_refusal(&response), "{response}");
                let response = reqwest::Client::new()
                    .delete(format!(
                        "{base}/plugins/config/{id}?expected_proxy_ids=p-partner"
                    ))
                    .bearer_auth(&operator)
                    .header("X-Ferrum-Namespace", "tenant-a")
                    .send()
                    .await
                    .unwrap();
                assert!(response.status().is_success());
            }
        }
        let stored = route_plugin_with_tls(
            "admin-route",
            json!({"server_ca_cert_path": "/admin/ca.pem"}),
        );
        let (status, response) = post(
            &base,
            "/plugins/config",
            &token("admin", &["tenant-a"]),
            &stored,
        )
        .await;
        assert!(
            (200..300).contains(&status),
            "admin material exemption: {response}"
        );
        let mut unrelated = stored.clone();
        unrelated["config"]["rules"][0]["match"] = json!({"methods": ["POST"]});
        let (status, response) = put(
            &base,
            "/plugins/config/admin-route?expected_proxy_ids=",
            &operator,
            &unrelated,
        )
        .await;
        assert!(
            (200..300).contains(&status),
            "exact stored field exemption: {response}"
        );
        let additional = unrelated["config"]["rules"][0].clone();
        unrelated["config"]["rules"]
            .as_array_mut()
            .unwrap()
            .push(additional);
        let (status, response) = put(
            &base,
            "/plugins/config/admin-route?expected_proxy_ids=",
            &operator,
            &unrelated,
        )
        .await;
        assert_eq!(
            status, 400,
            "a new rule must not inherit the stored exemption: {response}"
        );
        assert!(is_scope_refusal(&response), "{response}");
        if !require {
            let (status, response) = post(
                &base,
                "/plugins/config",
                &token_with_claim("operator", None),
                &route_plugin_with_tls(
                    "claimless-route",
                    json!({"server_ca_cert_path": "/admin/ca.pem"}),
                ),
            )
            .await;
            assert!(
                (200..300).contains(&status),
                "claimless global authority: {response}"
            );
        }
    }
}

fn udp_logging_plugin_with(id: &str, field: &str, value: &str) -> Value {
    let mut body = json!({
        "id": id, "plugin_name": "udp_logging", "scope": "proxy",
        "proxy_id": "p-partner", "enabled": true,
        "config": {"host": "127.0.0.1", "port": 5514, "dtls": true}
    });
    body["config"][field] = json!(value);
    if field == "dtls_cert_path" {
        body["config"]["dtls_key_path"] = json!("k8s://tenant-a/material#tls.key");
    } else if field == "dtls_key_path" {
        body["config"]["dtls_cert_path"] = json!("k8s://tenant-a/material#tls.crt");
    }
    body
}

/// `udp_logging` DTLS and `kafka_logging` SSL identity and trust are resolved
/// with the gateway's own credentials, so a namespace-claimed operator is confined there exactly as
/// for backend TLS, whether or not the claim is required.
#[tokio::test]
async fn namespace_claim_confines_udp_logging_dtls_material_on_create_and_put() {
    let temp = TempDir::new().unwrap();
    for require in [false, true] {
        let db = sqlite_store(&temp, &format!("udp-logging-scope-{require}.db")).await;
        let mut state = tenant_control_plane_state(db);
        state.admin_require_namespace_claim = require;
        let (base, _shutdown) = start_admin(state).await;
        let operator = operator_token(&["tenant-a"]);
        let (status, response) = post(
            &base,
            "/proxies",
            &operator,
            &proxy_with("backend_tls_server_ca_cert_path", "system://"),
        )
        .await;
        assert!((200..300).contains(&status), "{response}");
        let mut base_plugin = udp_logging_plugin_with("udp-base", "dtls_no_verify", "unused");
        base_plugin["config"]
            .as_object_mut()
            .unwrap()
            .remove("dtls_no_verify");
        let (status, response) = post(&base, "/plugins/config", &operator, &base_plugin).await;
        assert!(
            (200..300).contains(&status),
            "DTLS with an ephemeral identity needs no material: {response}"
        );
        for field in ["dtls_cert_path", "dtls_key_path", "dtls_ca_cert_path"] {
            for value in [
                "k8s://tenant-b/material",
                "vault://secret/tenant-b",
                "managed://material/foreign",
                "/absent/platform/material.pem",
            ] {
                let id = format!("udp-{field}");
                let forbidden = udp_logging_plugin_with(&id, field, value);
                let (status, response) =
                    post(&base, "/plugins/config", &operator, &forbidden).await;
                assert_eq!(status, 400, "{require} {field}: {response}");
                assert!(is_scope_refusal(&response), "{response}");
                assert!(!response.to_string().contains(value), "{response}");
                let mut replacement = udp_logging_plugin_with("udp-base", field, value);
                replacement["id"] = json!("udp-base");
                let (status, response) = put(
                    &base,
                    "/plugins/config/udp-base?expected_proxy_ids=",
                    &operator,
                    &replacement,
                )
                .await;
                assert_eq!(status, 400, "{require} PUT {field}: {response}");
                assert!(is_scope_refusal(&response), "{response}");
                assert!(!response.to_string().contains(value), "{response}");
            }
        }
        // `kafka_logging` shares the same sink admission table and write path
        // (the PUT arm is exercised above through `udp_logging`).
        for field in [
            "ssl_certificate_location",
            "ssl_key_location",
            "ssl_ca_location",
        ] {
            for value in ["k8s://tenant-b/material", "/absent/platform/material.pem"] {
                let mut forbidden = json!({
                    "id": format!("kafka-{field}"), "plugin_name": "kafka_logging",
                    "scope": "proxy", "proxy_id": "p-partner", "enabled": true,
                    "config": {
                        "bootstrap_servers": "127.0.0.1:9093",
                        "topic": "audit",
                        "security_protocol": "ssl"
                    }
                });
                forbidden["config"][field] = json!(value);
                let (status, response) =
                    post(&base, "/plugins/config", &operator, &forbidden).await;
                assert_eq!(status, 400, "{require} kafka {field}: {response}");
                assert!(is_scope_refusal(&response), "{response}");
                assert!(!response.to_string().contains(value), "{response}");
            }
        }
        if !require {
            let (_, response) = post(
                &base,
                "/plugins/config",
                &token_with_claim("operator", None),
                &udp_logging_plugin_with("claimless-udp", "dtls_ca_cert_path", "/admin/ca.pem"),
            )
            .await;
            assert!(
                !is_scope_refusal(&response),
                "claimless global authority is not namespace-confined: {response}"
            );
        }
    }
}

/// Default-deny: registered gateway-only fields, unsafe native-library keys
/// and unclassifiable (non-built-in) plugins are refused for a
/// namespace-claimed operator, whether or not the claim is required, while an
/// `admin` token is not namespace-confined.
#[tokio::test]
async fn namespace_claim_refuses_gateway_only_fields_and_unclassified_plugins() {
    let temp = TempDir::new().unwrap();
    for require in [false, true] {
        let db = sqlite_store(&temp, &format!("default-deny-{require}.db")).await;
        let mut state = tenant_control_plane_state(db);
        state.admin_require_namespace_claim = require;
        let (base, _shutdown) = start_admin(state).await;
        let operator = operator_token(&["tenant-a"]);
        let (status, response) = post(
            &base,
            "/proxies",
            &operator,
            &proxy_with("backend_tls_server_ca_cert_path", "system://"),
        )
        .await;
        assert!((200..300).contains(&status), "{response}");
        let plugin = |id: &str, name: &str, config: Value| {
            json!({
                "id": id, "plugin_name": name, "scope": "proxy",
                "proxy_id": "p-partner", "enabled": true, "config": config
            })
        };
        for (id, body, echoed) in [
            (
                "geo-db",
                plugin(
                    "geo-db",
                    "geo_restriction",
                    json!({"db_path": "/var/lib/platform/GeoIP2.mmdb", "allow_countries": ["US"]}),
                ),
                "/var/lib/platform/GeoIP2.mmdb",
            ),
            (
                "kafka-native",
                plugin(
                    "kafka-native",
                    "kafka_logging",
                    json!({
                        "bootstrap_servers": "127.0.0.1:9093",
                        "topic": "audit",
                        "security_protocol": "ssl",
                        "producer_config": {"linger.ms": "5", "ssl.providers": "/tmp/evil"}
                    }),
                ),
                "/tmp/evil",
            ),
            (
                "soap-trust",
                plugin(
                    "soap-trust",
                    "soap_ws_security",
                    json!({"x509_signature": {
                        "enabled": true,
                        "trusted_certs": ["k8s://tenant-b/idp#tls.crt"]
                    }}),
                ),
                "tenant-b",
            ),
            (
                "custom",
                plugin(
                    "custom",
                    "unregistered_custom_plugin",
                    json!({"library": "/opt/plugins/anything.so"}),
                ),
                "/opt/plugins/anything.so",
            ),
        ] {
            let (status, response) = post(&base, "/plugins/config", &operator, &body).await;
            assert_eq!(status, 400, "{require} {id}: {response}");
            assert!(is_scope_refusal(&response), "{id}: {response}");
            assert!(!response.to_string().contains(echoed), "{id}: {response}");
            let (_, response) = post(
                &base,
                "/plugins/config",
                &token("admin", &["tenant-a"]),
                &body,
            )
            .await;
            assert!(
                !is_scope_refusal(&response),
                "{id}: admin tokens are not namespace-confined: {response}"
            );
        }
    }
}

#[tokio::test]
async fn namespace_scoped_operator_keeps_material_it_may_reference() {
    let temp_dir = TempDir::new().unwrap();
    let db = sqlite_store(&temp_dir, "tenant_tls_reference_admitted.db").await;
    let (base, _shutdown) = start_admin(tenant_control_plane_state(db)).await;
    let token = operator_token(&["tenant-a"]);

    let inline_ca = ca_pem();
    for (id, ca) in [("u-inline", inline_ca.as_str()), ("u-system", "system://")] {
        let body = named_upstream(id, ca);
        let (status, response) = post(&base, "/upstreams", &token, &body).await;
        assert!(
            (200..300).contains(&status),
            "{id} must be admitted: {status} {response}"
        );
    }

    // The addressed namespace's own Secret passes the scope check; whatever
    // the load then reports, it is not a scope refusal.
    let own_secret = named_upstream("u-own-secret", "k8s://tenant-a/partner-ca#ca.crt");
    let (_, response) = post(&base, "/upstreams", &token, &own_secret).await;
    assert!(
        !is_scope_refusal(&response),
        "an own-namespace Secret must not be refused as out of scope: {response}"
    );
}

#[tokio::test]
async fn admin_tokens_and_claimless_unenforced_planes_are_unaffected() {
    let temp_dir = TempDir::new().unwrap();
    let ca_file = write_ca(&temp_dir, "platform-ca.pem");

    let db = sqlite_store(&temp_dir, "tenant_tls_reference_admin.db").await;
    let (base, _shutdown) = start_admin(tenant_control_plane_state(db)).await;
    let (status, response) = post(
        &base,
        "/upstreams",
        &operator_token(&["tenant-a"]),
        &named_upstream("u-operator", &ca_file),
    )
    .await;
    assert_eq!(
        status, 400,
        "an operator may not name a gateway file: {response}"
    );
    assert!(is_scope_refusal(&response), "{response}");

    let (status, response) = post(
        &base,
        "/upstreams",
        &token("admin", &["tenant-a"]),
        &named_upstream("u-admin", &ca_file),
    )
    .await;
    assert!(
        (200..300).contains(&status),
        "an admin token is not namespace-scoped for TLS material: {status} {response}"
    );

    // A claimless token on a plane that does not require claims remains global.
    let db = sqlite_store(&temp_dir, "tenant_tls_reference_unenforced.db").await;
    let mut state = tenant_control_plane_state(db);
    state.admin_require_namespace_claim = false;
    let (base, _shutdown_unenforced) = start_admin(state).await;
    let (status, response) = post(
        &base,
        "/upstreams",
        &token_with_claim("operator", None),
        &named_upstream("u-unenforced", &ca_file),
    )
    .await;
    assert!(
        (200..300).contains(&status),
        "enforcement off must leave operator writes unaffected: {status} {response}"
    );
}

#[tokio::test]
async fn an_update_may_keep_a_stored_value_but_not_introduce_a_new_one() {
    let temp_dir = TempDir::new().unwrap();
    let stored_ca = write_ca(&temp_dir, "stored-ca.pem");
    let other_ca = write_ca(&temp_dir, "other-ca.pem");
    let db = sqlite_store(&temp_dir, "tenant_tls_reference_update.db").await;
    let (base, _shutdown) = start_admin(tenant_control_plane_state(db)).await;

    let (status, response) = post(
        &base,
        "/upstreams",
        &token("admin", &["tenant-a"]),
        &named_upstream("u-partner", &stored_ca),
    )
    .await;
    assert!(
        (200..300).contains(&status),
        "an admin configures the material: {status} {response}"
    );

    // An unrelated operator update that carries the stored value unchanged is
    // admitted, and the stored value survives.
    let operator = operator_token(&["tenant-a"]);
    let mut unrelated = named_upstream("u-partner", &stored_ca);
    unrelated["algorithm"] = json!("least_connections");
    let (status, response) = put(&base, "/upstreams/u-partner", &operator, &unrelated).await;
    assert!(
        (200..300).contains(&status),
        "keeping the stored value must be admitted: {status} {response}"
    );
    assert_eq!(
        response["backend_tls_server_ca_cert_path"].as_str(),
        Some(stored_ca.as_str()),
        "the stored value must be preserved: {response}"
    );

    // Changing it to another gateway file is a new reference and is refused.
    let changed = named_upstream("u-partner", &other_ca);
    let (status, response) = put(&base, "/upstreams/u-partner", &operator, &changed).await;
    assert_eq!(
        status, 400,
        "a new gateway file must be refused: {response}"
    );
    assert!(is_scope_refusal(&response), "{response}");
}

#[tokio::test]
async fn present_namespace_claim_confines_tls_when_claim_requirement_is_off() {
    let temp = TempDir::new().unwrap();
    for require in [false, true] {
        let db = sqlite_store(&temp, &format!("scope-{require}.db")).await;
        let mut state = tenant_control_plane_state(db);
        state.admin_require_namespace_claim = require;
        let (base, _shutdown) = start_admin(state).await;
        let operator = operator_token(&["tenant-a"]);
        for field in [
            "backend_tls_client_cert_path",
            "backend_tls_client_key_path",
            "backend_tls_server_ca_cert_path",
        ] {
            for value in [
                "k8s://tenant-b/material",
                "vault://secret/data/tenant-b",
                "managed://certificates/platform",
                "/absent/platform/material.pem",
            ] {
                for (route, mut body) in [
                    ("/proxies", proxy_with(field, value)),
                    ("/upstreams", upstream_with(field, value)),
                ] {
                    let (status, response) = post(&base, route, &operator, &body).await;
                    assert_eq!(status, 400, "{require} {route} {field}: {response}");
                    assert!(is_scope_refusal(&response), "{response}");
                    assert!(!response.to_string().contains(value), "{response}");
                    // Create a legitimate resource, then verify PUT uses the same boundary.
                    body.as_object_mut().unwrap().remove(field);
                    body["backend_tls_server_ca_cert_path"] = json!("system://");
                    let (status, response) = post(&base, route, &operator, &body).await;
                    assert!((200..300).contains(&status), "{response}");
                    body[field] = json!(value);
                    let id = body["id"].as_str().unwrap();
                    let (status, response) =
                        put(&base, &format!("{route}/{id}"), &operator, &body).await;
                    assert_eq!(status, 400, "{require} {route} {field}: {response}");
                    assert!(is_scope_refusal(&response), "{response}");
                    // Remove it so the next matrix row can reuse the same id.
                    let response = reqwest::Client::new()
                        .delete(format!("{base}{route}/{id}"))
                        .bearer_auth(&operator)
                        .header("X-Ferrum-Namespace", "tenant-a")
                        .send()
                        .await
                        .unwrap();
                    assert!(response.status().is_success());
                }
            }
        }
    }
}

#[tokio::test]
async fn claimed_operator_keeps_admin_material_with_requirement_off_but_cannot_replace_it() {
    let temp = TempDir::new().unwrap();
    let stored = write_ca(&temp, "stored.pem");
    let other = write_ca(&temp, "other.pem");
    let db = sqlite_store(&temp, "stored-optional-claim.db").await;
    let mut state = tenant_control_plane_state(db);
    state.admin_require_namespace_claim = false;
    let (base, _shutdown) = start_admin(state).await;
    let admin = token("admin", &["tenant-a"]);
    let operator = operator_token(&["tenant-a"]);
    for (route, make) in [
        ("/proxies", proxy_with as fn(&str, &str) -> Value),
        ("/upstreams", upstream_with as fn(&str, &str) -> Value),
    ] {
        let mut body = make("backend_tls_server_ca_cert_path", &stored);
        let id = body["id"].as_str().unwrap().to_string();
        let (status, response) = post(&base, route, &admin, &body).await;
        assert!((200..300).contains(&status), "{response}");
        body["name"] = json!("unrelated change");
        let (status, response) = put(&base, &format!("{route}/{id}"), &operator, &body).await;
        assert!((200..300).contains(&status), "{response}");
        body["backend_tls_server_ca_cert_path"] = json!(&other);
        let (status, response) = put(&base, &format!("{route}/{id}"), &operator, &body).await;
        assert_eq!(status, 400, "{response}");
        assert!(is_scope_refusal(&response), "{response}");
    }
}
