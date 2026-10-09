//! Admin JWTs carrying an `ns` claim are limited to namespace routes.
//!
//! A token that names its namespaces is tenant-bounded whatever
//! `FERRUM_ADMIN_REQUIRE_NAMESPACE_CLAIM` says:
//!
//! - fleet-global routes (chargeback, metrics, cluster, capabilities, mesh
//!   fleet introspection and resets, TLS management, and any route not
//!   explicitly classified) answer `403`;
//! - the global allowlist (`GET /plugins`, the probe endpoints, the namespace
//!   registry, the diagnostic reference lookup) stays reachable, with the
//!   registry filtered to and authorized by the claim;
//! - `/health` and `/status` serve the bounded tenant tier (`status`, `ready`,
//!   `mode`, `admin_writes_enabled`, and the `namespace` serving block only
//!   when the claim admits the active namespace), `/overload` only `{level}`;
//! - `/metrics` refuses the token even from an allowlisted source IP;
//! - namespace-scoped routes accept only the claimed namespaces.
//!
//! A token without an `ns` claim keeps fleet-wide access.

use crate::scaffolding::port_registry::TestSocket;

use arc_swap::ArcSwap;
use ferrum_edge::admin::{
    AdminState, MetricsAuthPolicy,
    jwt_auth::{JwtConfig, JwtManager},
    serve_admin_on_listener,
};
use ferrum_edge::config::types::GatewayConfig;
use ferrum_edge::config::{EnvConfig, OperatingMode};
use ferrum_edge::dns::{DnsCache, DnsConfig};
use ferrum_edge::proxy::client_ip::TrustedProxies;
use jsonwebtoken::{EncodingKey, Header, encode};
use reqwest::Method;
use serde_json::{Value, json};
use std::net::SocketAddr;
use std::sync::Arc;

const JWT_SECRET: &str = "ns-claim-global-route-test-secret-0123456789";
const JWT_ISSUER: &str = "ferrum-edge-ns-claim-global-route-test";
const METRICS_TOKEN: &str = "ns-claim-global-route-metrics-token-0123456789";
const NS_CLAIM_REFUSAL: &str = "unavailable to admin JWTs with an `ns` claim";
const UNKNOWN_DIAGNOSTIC_REF: &str = "/diagnostics/v1/refs/fd1_00000000000000000000000000000000";

/// Fleet-global reads a namespace-bounded token must not reach. The last entry
/// is not a route at all: unclassified paths fail closed too.
const FLEET_GLOBAL_READS: &[&str] = &[
    "/charges",
    "/charges/sink/status",
    "/metrics",
    "/admin/metrics",
    "/metrics/runtime",
    "/cluster",
    "/config/apply-status",
    "/backend-capabilities",
    "/mesh/service-graph",
    "/mesh/slice-drift",
    "/mesh/federation",
    "/mesh/policy-denies/recent",
    "/node-waypoint/identities",
    "/service-waypoint/services",
    "/admin/tls/inventory",
    "/admin/tls/certificates",
    "/no-such-admin-route",
];

/// Top-level keys of the `/health` tenant tier when it carries the serving
/// block.
const TENANT_TIER_KEYS: &[&str] = &[
    "admin_writes_enabled",
    "mode",
    "namespace",
    "ready",
    "status",
];

/// Fleet-global mutations a namespace-bounded token must not reach.
const FLEET_GLOBAL_WRITES: &[&str] = &[
    "/mesh/config-revision/reset?confirm=true",
    "/backend-capabilities/refresh",
    "/admin/tls/ca-bundles",
    "/admin/tls/rotate/frontend",
];

fn jwt_manager() -> JwtManager {
    JwtManager::new(JwtConfig {
        secret: JWT_SECRET.to_string(),
        issuer: JWT_ISSUER.to_string(),
        audience: None,
        max_ttl_seconds: 3600,
        algorithm: jsonwebtoken::Algorithm::HS256,
    })
}

/// Mint a primary-key admin JWT with `additional` merged into its claims.
fn admin_token(additional: Value) -> String {
    let now = chrono::Utc::now();
    let mut claims = json!({
        "iss": JWT_ISSUER,
        "sub": "ns-claim-global-route-test",
        "role": "admin",
        "iat": now.timestamp(),
        "nbf": now.timestamp(),
        "exp": (now + chrono::Duration::seconds(600)).timestamp(),
        "jti": uuid::Uuid::new_v4().to_string(),
    });
    if let Some(additional) = additional.as_object() {
        for (key, value) in additional {
            claims[key.as_str()] = value.clone();
        }
    }
    encode(
        &Header::new(jsonwebtoken::Algorithm::HS256),
        &claims,
        &EncodingKey::from_secret(JWT_SECRET.as_bytes()),
    )
    .unwrap()
}

fn staging_token() -> String {
    admin_token(json!({"ns": "staging"}))
}

fn fleet_token() -> String {
    admin_token(json!({}))
}

fn registry_config() -> GatewayConfig {
    GatewayConfig {
        known_namespaces: vec![
            "ferrum".to_string(),
            "prod".to_string(),
            "staging".to_string(),
        ],
        ..GatewayConfig::default()
    }
}

fn admin_state(require_namespace_claim: bool) -> AdminState {
    AdminState {
        db: None,
        jwt_manager: jwt_manager(),
        metrics_auth: Arc::new(MetricsAuthPolicy {
            allowed_cidrs: TrustedProxies::none(),
            bearer_token: Some(METRICS_TOKEN.to_string()),
        }),
        proxy_state: None,
        cached_config: Some(Arc::new(ArcSwap::new(Arc::new(registry_config())))),
        mode: "file".to_string(),
        read_only: true,
        admin_audit_enabled: false,
        admin_audit_fallback_dir: Some(crate::common::isolated_audit_fallback_dir()),
        admin_require_namespace_claim: require_namespace_claim,
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
        admin_allowed_cidrs: Arc::new(TrustedProxies::none()),
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

/// A proxy state whose data plane routes `namespace`, so `/health` reports it
/// as `namespace.active`.
fn proxy_state(namespace: &str) -> ferrum_edge::proxy::ProxyState {
    let mut config = GatewayConfig::default();
    config.normalize_fields();
    let env_config = EnvConfig {
        mode: OperatingMode::Database,
        namespace: namespace.to_string(),
        ..Default::default()
    };
    let (state, _health_check_handles) = ferrum_edge::proxy::ProxyState::new(
        config,
        DnsCache::new(DnsConfig::default()),
        env_config,
        None,
        None,
    )
    .expect("ProxyState::new");
    state
}

/// Top-level keys of a JSON object body, sorted.
fn body_keys(reply: &Reply) -> Vec<String> {
    let mut keys: Vec<String> = reply
        .body
        .as_object()
        .map(|body| body.keys().cloned().collect())
        .unwrap_or_default();
    keys.sort();
    keys
}

async fn start_admin(state: AdminState) -> (String, tokio::sync::watch::Sender<bool>) {
    let addr: SocketAddr = "127.0.0.1:0".parse().unwrap();
    let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);
    let listener = tokio::net::TcpListener::bind_test(addr).await.unwrap();
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
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
    }
    (format!("http://{actual}"), shutdown_tx)
}

struct Reply {
    status: u16,
    body: Value,
    text: String,
}

async fn send(
    method: Method,
    base: &str,
    path: &str,
    bearer: &str,
    namespace: Option<&str>,
) -> Reply {
    let mut req = reqwest::Client::new()
        .request(method.clone(), format!("{base}{path}"))
        .bearer_auth(bearer);
    if method != Method::GET {
        req = req.json(&json!({}));
    }
    if let Some(ns) = namespace {
        req = req.header("X-Ferrum-Namespace", ns);
    }
    let resp = req.send().await.unwrap();
    let status = resp.status().as_u16();
    let text = resp.text().await.unwrap_or_default();
    Reply {
        status,
        body: serde_json::from_str(&text).unwrap_or(Value::Null),
        text,
    }
}

async fn get(base: &str, path: &str, bearer: &str, namespace: Option<&str>) -> Reply {
    send(Method::GET, base, path, bearer, namespace).await
}

fn listed_names(reply: &Reply) -> Vec<String> {
    let mut names: Vec<String> = reply.body["data"]
        .as_array()
        .cloned()
        .unwrap_or_default()
        .iter()
        .filter_map(|item| item.as_str().map(str::to_string))
        .collect();
    names.sort();
    names
}

fn assert_ns_claim_refusal(reply: &Reply, label: &str) {
    assert_eq!(reply.status, 403, "{label}: {}", reply.text);
    assert!(
        reply.text.contains(NS_CLAIM_REFUSAL),
        "{label} must be refused by the ns-claim global-route gate: {}",
        reply.text
    );
}

#[tokio::test]
async fn ns_claim_tokens_are_refused_on_fleet_global_routes_whatever_the_claim_flag() {
    for require_claim in [false, true] {
        let (base, _sd) = start_admin(admin_state(require_claim)).await;
        // Both claim shapes, each naming the namespace the header asks for.
        let both_token = admin_token(json!({"ns": ["staging", "prod"]}));
        let tokens = [
            ("ns=staging", staging_token()),
            ("ns=[staging,prod]", both_token),
        ];
        for (token_label, bearer) in &tokens {
            for path in FLEET_GLOBAL_READS {
                let label = format!("flag={require_claim} {token_label} GET {path}");
                let reply = get(&base, path, bearer, Some("staging")).await;
                assert_ns_claim_refusal(&reply, &label);
            }
            for path in FLEET_GLOBAL_WRITES {
                let label = format!("flag={require_claim} {token_label} POST {path}");
                let reply = send(Method::POST, &base, path, bearer, Some("staging")).await;
                assert_ns_claim_refusal(&reply, &label);
            }
        }
    }
}

#[tokio::test]
async fn ns_claim_refusal_cannot_be_bypassed_with_a_scope_claim() {
    let (base, _sd) = start_admin(admin_state(false)).await;
    let scoped = admin_token(json!({"ns": "staging", "scope": "diagnostics:read"}));
    for path in ["/charges", "/admin/metrics", "/cluster"] {
        let reply = get(&base, path, &scoped, None).await;
        assert_ns_claim_refusal(&reply, &format!("GET {path}"));
    }
}

#[tokio::test]
async fn claim_less_tokens_keep_fleet_global_access() {
    let (base, _sd) = start_admin(admin_state(false)).await;
    let fleet = fleet_token();
    for path in [
        "/charges",
        "/metrics",
        "/admin/metrics",
        "/metrics/runtime",
        "/cluster",
        "/backend-capabilities",
        "/plugins",
    ] {
        let reply = get(&base, path, &fleet, Some("staging")).await;
        assert_ne!(reply.status, 403, "GET {path}: {}", reply.text);
        assert!(!reply.text.contains(NS_CLAIM_REFUSAL), "GET {path}");
    }

    for path in ["/health", "/status"] {
        let reply = get(&base, path, &fleet, None).await;
        assert_eq!(reply.status, 200, "GET {path}: {}", reply.text);
        for detail in ["timestamp", "mode", "admin_writes_enabled"] {
            assert!(
                reply.body.get(detail).is_some(),
                "a fleet token keeps the detailed tier on {path}: {}",
                reply.text
            );
        }
    }

    let list = get(&base, "/namespaces", &fleet, None).await;
    assert_eq!(list.status, 200, "{}", list.text);
    assert_eq!(listed_names(&list), ["ferrum", "prod", "staging"]);
}

#[tokio::test]
async fn ns_claim_tokens_keep_the_global_allowlist() {
    let (base, _sd) = start_admin(admin_state(false)).await;
    let scoped = staging_token();

    let plugins = get(&base, "/plugins", &scoped, None).await;
    assert_eq!(plugins.status, 200, "{}", plugins.text);

    let live = get(&base, "/live", &scoped, None).await;
    assert_eq!(live.status, 200, "{}", live.text);

    // Probe endpoints answer with the tenant tier. This process has no data
    // plane, so the serving block names no namespace and is included.
    for path in ["/health", "/status"] {
        let reply = get(&base, path, &scoped, None).await;
        assert_eq!(reply.status, 200, "GET {path}: {}", reply.text);
        assert_eq!(
            body_keys(&reply),
            TENANT_TIER_KEYS,
            "GET {path} must serve only the tenant tier to an ns-claim token: {}",
            reply.text
        );
        assert_eq!(reply.body["namespace"]["active"], Value::Null);
        assert_eq!(reply.body["namespace"]["serving_scope"], "no-data-plane");
    }
    let overload = get(&base, "/overload", &scoped, None).await;
    assert_eq!(overload.status, 200, "{}", overload.text);
    assert_eq!(overload.body, json!({"level": "normal"}));

    // The diagnostic reference lookup authorizes the claim itself: the gate
    // lets it through, and an unknown reference is an ordinary 404.
    let diagnostic = admin_token(json!({"ns": "staging", "scope": "diagnostics:read"}));
    let lookup = get(&base, UNKNOWN_DIAGNOSTIC_REF, &diagnostic, None).await;
    assert_eq!(lookup.status, 404, "{}", lookup.text);

    // Registry writes pass the gate and reach the handler (this file-mode
    // instance then refuses every write as read-only).
    let create = send(Method::POST, &base, "/namespaces", &scoped, None).await;
    assert!(
        !create.text.contains(NS_CLAIM_REFUSAL),
        "registry writes are name-authorized, not refused as fleet-global: {}",
        create.text
    );
}

#[tokio::test]
async fn present_ns_claim_bounds_the_namespace_registry_with_the_flag_off() {
    let (base, _sd) = start_admin(admin_state(false)).await;
    let scoped = staging_token();

    let list = get(&base, "/namespaces", &scoped, None).await;
    assert_eq!(list.status, 200, "{}", list.text);
    assert_eq!(listed_names(&list), ["staging"], "{}", list.text);

    let own = get(&base, "/namespaces/staging", &scoped, None).await;
    assert_eq!(own.status, 200, "{}", own.text);

    for name in ["prod", "ferrum", "never-created"] {
        let path = format!("/namespaces/{name}");
        let other = get(&base, &path, &scoped, None).await;
        assert_eq!(other.status, 403, "GET {path}: {}", other.text);
        assert!(
            other.text.contains("does not authorize namespace"),
            "GET {path}: {}",
            other.text
        );
    }
}

#[tokio::test]
async fn present_ns_claim_bounds_namespace_scoped_routes_with_the_flag_off() {
    let (base, _sd) = start_admin(admin_state(false)).await;
    let scoped = staging_token();

    for path in ["/proxies", "/consumers", "/upstreams", "/plugins/config"] {
        let own = get(&base, path, &scoped, Some("staging")).await;
        assert_eq!(own.status, 200, "GET {path} (staging): {}", own.text);

        let other = get(&base, path, &scoped, Some("prod")).await;
        assert_eq!(other.status, 403, "GET {path} (prod): {}", other.text);
        assert!(
            other.text.contains("does not authorize namespace 'prod'"),
            "GET {path} (prod): {}",
            other.text
        );

        // Omitting the header selects the default namespace, also unclaimed.
        let default = get(&base, path, &scoped, None).await;
        assert_eq!(
            default.status, 403,
            "GET {path} (default): {}",
            default.text
        );
    }

    // Without a claim and with the flag off, the header stays a selector.
    let fleet = fleet_token();
    let other = get(&base, "/proxies", &fleet, Some("prod")).await;
    assert_eq!(other.status, 200, "{}", other.text);
}

/// The tenant tier reuses the detailed tier's top-level field names and shapes,
/// and carries the serving block only when the claim admits the namespace this
/// process routes. A claim-less token keeps the detailed tier and an
/// unauthenticated probe keeps `status` + `ready`.
#[tokio::test]
async fn tenant_health_tier_is_bounded_by_the_claim() {
    let mut state = admin_state(false);
    state.mode = "database".to_string();
    state.proxy_state = Some(proxy_state("staging"));
    let (base, _sd) = start_admin(state).await;

    let both = admin_token(json!({"ns": ["prod", "staging"]}));
    let covering = [("ns=staging", staging_token()), ("ns=[staging,prod]", both)];
    let not_covering = [
        ("ns=prod", admin_token(json!({"ns": "prod"}))),
        ("ns=[]", admin_token(json!({"ns": []}))),
    ];
    for path in ["/health", "/status"] {
        let detailed = get(&base, path, &fleet_token(), None).await;
        for detail in ["timestamp", "mode", "admin_writes_enabled", "namespace"] {
            assert!(
                detailed.body.get(detail).is_some(),
                "a claim-less token keeps the detailed tier on {path}: {}",
                detailed.text
            );
        }

        for (label, bearer) in &covering {
            let tenant = get(&base, path, bearer, None).await;
            assert_eq!(
                body_keys(&tenant),
                TENANT_TIER_KEYS,
                "{label} {path}: {}",
                tenant.text
            );
            for field in ["mode", "admin_writes_enabled", "namespace"] {
                assert_eq!(
                    tenant.body[field], detailed.body[field],
                    "{label} {path}: `{field}` must match the detailed tier exactly"
                );
            }
            assert_eq!(tenant.body["mode"], "database");
            assert_eq!(tenant.body["namespace"]["active"], "staging");
            assert_eq!(
                tenant.body["namespace"]["serving_scope"],
                "single-namespace-data-plane"
            );
            assert_eq!(
                tenant.body["namespace"]["data_plane_single_namespace"],
                true
            );
        }

        for (label, bearer) in &not_covering {
            let tenant = get(&base, path, bearer, None).await;
            assert_eq!(
                body_keys(&tenant),
                ["admin_writes_enabled", "mode", "ready", "status"],
                "{label} {path}: the serving block must not name an unclaimed namespace: {}",
                tenant.text
            );
            assert!(
                !tenant.text.contains("staging"),
                "{label} {path}: {}",
                tenant.text
            );
            assert_eq!(tenant.body["mode"], detailed.body["mode"]);
            assert_eq!(
                tenant.body["admin_writes_enabled"],
                detailed.body["admin_writes_enabled"]
            );
        }

        let anonymous = reqwest::Client::new()
            .get(format!("{base}{path}"))
            .send()
            .await
            .unwrap();
        let anonymous: Value = anonymous.json().await.unwrap();
        let mut keys: Vec<&String> = anonymous.as_object().unwrap().keys().collect();
        keys.sort();
        assert_eq!(
            keys,
            ["ready", "status"],
            "unauthenticated {path}: {anonymous}"
        );
    }
}

/// An allowlisted metrics source IP does not admit an `ns`-claim token to
/// `/metrics`: the CIDR allowance covers only scrapes without such a token. On
/// `/health` the allowlisted IP keeps granting the detail it grants on its own.
#[tokio::test]
async fn allowlisted_metrics_cidr_does_not_admit_an_ns_claim_token_to_metrics() {
    let mut state = admin_state(false);
    state.metrics_auth = Arc::new(MetricsAuthPolicy {
        allowed_cidrs: TrustedProxies::parse_strict("127.0.0.1/32,::1", "test")
            .expect("valid metrics CIDR list"),
        bearer_token: None,
    });
    let (base, _sd) = start_admin(state).await;
    let scoped = staging_token();

    let refused = get(&base, "/metrics", &scoped, None).await;
    assert_ns_claim_refusal(&refused, "GET /metrics from an allowlisted CIDR");

    let fleet = get(&base, "/metrics", &fleet_token(), None).await;
    assert_eq!(fleet.status, 200, "{}", fleet.text);
    let anonymous = reqwest::Client::new()
        .get(format!("{base}/metrics"))
        .send()
        .await
        .unwrap();
    assert_eq!(anonymous.status().as_u16(), 200);

    let health = get(&base, "/health", &scoped, None).await;
    assert!(
        health.body.get("timestamp").is_some(),
        "the allowlisted source IP keeps the detailed /health tier: {}",
        health.text
    );
}

/// Registry writes are name-authorized by a present claim with the flag off:
/// `PUT` (including a rename into an unclaimed name) and `DELETE` on a name
/// outside the claim answer `403` before the handler touches storage.
#[tokio::test]
async fn present_ns_claim_bounds_namespace_registry_writes_with_the_flag_off() {
    let mut state = admin_state(false);
    state.mode = "database".to_string();
    state.read_only = false;
    let (base, _sd) = start_admin(state).await;
    let scoped = staging_token();
    let client = reqwest::Client::new();

    let writes = [
        (Method::PUT, "/namespaces/prod", json!({"description": "x"})),
        (Method::PUT, "/namespaces/staging", json!({"name": "prod"})),
        (Method::DELETE, "/namespaces/prod", Value::Null),
    ];
    for (method, path, body) in writes {
        let mut req = client
            .request(method.clone(), format!("{base}{path}"))
            .bearer_auth(&scoped);
        if !body.is_null() {
            req = req.json(&body);
        }
        let resp = req.send().await.unwrap();
        let status = resp.status().as_u16();
        let text = resp.text().await.unwrap_or_default();
        assert_eq!(status, 403, "{method} {path}: {text}");
        assert!(
            text.contains("does not authorize namespace 'prod'"),
            "{method} {path} must be refused by the claim: {text}"
        );
    }
}
