//! Backend policy discovery: exact vocabulary, loaded policy, and JWT read gates.

use std::sync::Arc;

use ferrum_edge::admin::{
    AdminState, MetricsAuthPolicy,
    jwt_auth::{JwtConfig, JwtManager, ViewerNamespaceCeiling},
    serve_admin_on_listener,
};
use ferrum_edge::config::types::GatewayConfig;
use ferrum_edge::config::{BackendAllowIps, BackendEgressPolicy, EnvConfig, OperatingMode};
use ferrum_edge::dns::{DnsCache, DnsConfig};
use ferrum_edge::proxy::ProxyState;
use ferrum_edge::proxy::client_ip::TrustedProxies;
use jsonwebtoken::{Algorithm, EncodingKey, Header, encode};
use reqwest::StatusCode;
use serde_json::{Value, json};

use crate::scaffolding::port_registry::TestSocket;

const PRIMARY_SECRET: &str = "egress-primary-secret-0123456789abcdef";
const VIEWER_SECRET: &str = "egress-viewer-secret-0123456789abcdef";
const METRICS_TOKEN: &str = "egress-metrics-token-0123456789abcdef";
const ISSUER: &str = "egress-policy-test";
const PATH: &str = "/backend-egress-policy";

fn token(secret: &str, additional: Value) -> String {
    let now = chrono::Utc::now().timestamp();
    let mut claims = json!({
        "iss": ISSUER,
        "sub": "policy-reader",
        "role": "viewer",
        "iat": now,
        "nbf": now,
        "exp": now + 600,
        "jti": uuid::Uuid::new_v4().to_string(),
    });
    claims
        .as_object_mut()
        .unwrap()
        .extend(additional.as_object().unwrap().clone());
    encode(
        &Header::new(Algorithm::HS256),
        &claims,
        &EncodingKey::from_secret(secret.as_bytes()),
    )
    .unwrap()
}

fn admin_state(mode: &str, policy: BackendEgressPolicy) -> AdminState {
    AdminState {
        db: None,
        jwt_manager: JwtManager::new(JwtConfig {
            secret: PRIMARY_SECRET.to_string(),
            issuer: ISSUER.to_string(),
            audience: None,
            max_ttl_seconds: 3600,
            algorithm: Algorithm::HS256,
        }),
        metrics_auth: Default::default(),
        proxy_state: None,
        cached_config: None,
        mode: mode.to_string(),
        read_only: true,
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
        reserved_ports: Default::default(),
        stream_proxy_bind_address: "0.0.0.0".to_string(),
        admin_allowed_cidrs: Arc::new(TrustedProxies::none()),
        cached_db_health: Arc::new(arc_swap::ArcSwap::new(Arc::new(None))),
        db_health_refresh: Arc::new(tokio::sync::Mutex::new(())),
        dp_registry: None,
        mesh_registry: None,
        cp_connection_state: None,
        mesh_runtime_state: None,
        admin_http_header_read_timeout_seconds: 10,
        admin_tls_handshake_timeout_seconds: 10,
        admin_request_limits: Default::default(),
        backend_allow_ips: policy,
        external_ref_policy: Arc::new(
            ferrum_edge::admin::api_specs::ExternalRefProcessPolicy::default(),
        ),
        external_ref_loader: Arc::new(
            ferrum_edge::admin::api_specs::DefaultExternalDocumentLoader::default(),
        ),
        runtime_config_apply: None,
    }
}

fn proxy_state(mode: OperatingMode, policy: BackendEgressPolicy) -> ProxyState {
    let env = EnvConfig {
        mode,
        namespace: "staging".to_string(),
        backend_allow_ips: policy,
        ..Default::default()
    };
    let (proxy, _health_checks) = ProxyState::new(
        GatewayConfig::default(),
        DnsCache::new(DnsConfig::default()),
        env,
        None,
        None,
    )
    .unwrap();
    proxy
}

struct AdminHarness {
    base: String,
    shutdown: tokio::sync::watch::Sender<bool>,
    task: tokio::task::JoinHandle<()>,
}

impl AdminHarness {
    async fn start(state: AdminState) -> Self {
        let listener = tokio::net::TcpListener::bind_test("127.0.0.1:0".parse().unwrap())
            .await
            .unwrap();
        let addr = listener.local_addr().unwrap();
        let (shutdown, rx) = tokio::sync::watch::channel(false);
        let task = tokio::spawn(async move {
            serve_admin_on_listener(
                listener,
                state,
                rx,
                None,
                ferrum_edge::admin::AdminConnLimiter::unlimited(),
            )
            .await
            .unwrap();
        });
        Self {
            base: format!("http://{addr}"),
            shutdown,
            task,
        }
    }

    async fn get(&self, bearer: Option<&str>, namespace: Option<&str>) -> (StatusCode, Value) {
        let client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(10))
            .build()
            .unwrap();
        let mut request = client.get(format!("{}{PATH}", self.base));
        if let Some(bearer) = bearer {
            request = request.bearer_auth(bearer);
        }
        if let Some(namespace) = namespace {
            request = request.header("X-Ferrum-Namespace", namespace);
        }
        let response = request.send().await.unwrap();
        assert_eq!(response.headers()["cache-control"], "no-store");
        let status = response.status();
        (status, response.json().await.unwrap())
    }
}

impl Drop for AdminHarness {
    fn drop(&mut self) {
        let _ = self.shutdown.send(true);
        self.task.abort();
    }
}

fn default_response() -> Value {
    json!({
        "schema_version": 1,
        "ip_classification": "ferrum-private-reserved-v1",
        "namespace": "ferrum",
        "policy_scope": "process",
        "enforcement_scope": "admission-only",
        "mode": "both",
        "mode_allowed_ip_classes": ["public", "private-reserved"],
        "mode_blocked_ip_classes": [],
        "dangerous_ranges_blocked": true,
        "allow_cidr_overrides_present": false,
        "deny_cidr_overrides_present": false,
        "evaluation_order": ["allow-cidrs", "deny-cidrs", "dangerous-ranges", "ip-mode"],
        "public_only_guaranteed": false,
    })
}

fn assert_no_policy(body: &Value) {
    assert!(body.get("ip_classification").is_none(), "{body}");
    assert!(body.get("mode_allowed_ip_classes").is_none(), "{body}");
    assert!(body.get("public_only_guaranteed").is_none(), "{body}");
}

#[tokio::test]
async fn default_public_and_private_policies_have_exact_versioned_representations() {
    let reader = token(PRIMARY_SECRET, json!({}));
    for (mode, allowed, blocked, guaranteed) in [
        (
            BackendAllowIps::Both,
            json!(["public", "private-reserved"]),
            json!([]),
            false,
        ),
        (
            BackendAllowIps::Public,
            json!(["public"]),
            json!(["private-reserved"]),
            true,
        ),
        (
            BackendAllowIps::Private,
            json!(["private-reserved"]),
            json!(["public"]),
            false,
        ),
    ] {
        let mut expected = default_response();
        expected["mode"] = json!(mode.to_string());
        expected["mode_allowed_ip_classes"] = allowed;
        expected["mode_blocked_ip_classes"] = blocked;
        expected["public_only_guaranteed"] = json!(guaranteed);
        let state = admin_state("cp", BackendEgressPolicy::from_allow_ips(mode));
        let harness = AdminHarness::start(state).await;
        let (status, body) = harness.get(Some(&reader), None).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body, expected);
    }
}

#[tokio::test]
async fn overrides_are_bounded_and_public_only_proof_is_conservative() {
    let reader = token(PRIMARY_SECRET, json!({}));
    for (allow, deny, baseline, guaranteed) in [
        ("10.45.67.89/32", "10.45.67.89/32", true, false),
        ("8.8.8.8/32", "", true, false),
        ("", "10.45.67.89/32", true, true),
        ("", "", false, true),
    ] {
        let policy = BackendEgressPolicy::from_env(BackendAllowIps::Public, allow, deny, baseline)
            .unwrap();
        let harness = AdminHarness::start(admin_state("cp", policy)).await;
        let (status, body) = harness.get(Some(&reader), None).await;
        assert_eq!(status, StatusCode::OK);
        let mut expected = default_response();
        expected["mode"] = json!("public");
        expected["mode_allowed_ip_classes"] = json!(["public"]);
        expected["mode_blocked_ip_classes"] = json!(["private-reserved"]);
        expected["allow_cidr_overrides_present"] = json!(!allow.is_empty());
        expected["deny_cidr_overrides_present"] = json!(!deny.is_empty());
        expected["dangerous_ranges_blocked"] = json!(baseline);
        expected["public_only_guaranteed"] = json!(guaranteed);
        assert_eq!(body, expected);
        let serialized = body.to_string();
        for private_value in [
            "10.45.67.89",
            "8.8.8.8",
            PRIMARY_SECRET,
            VIEWER_SECRET,
            METRICS_TOKEN,
        ] {
            assert!(!serialized.contains(private_value));
        }
    }
    let state = admin_state("cp", BackendEgressPolicy::unrestricted());
    let harness = AdminHarness::start(state).await;
    let (_, body) = harness.get(Some(&reader), None).await;
    let mut expected = default_response();
    expected["dangerous_ranges_blocked"] = json!(false);
    assert_eq!(body, expected);
}

#[tokio::test]
async fn serving_modes_report_the_proxy_policy_and_selected_namespace_scope() {
    let reader = token(PRIMARY_SECRET, json!({"ns": ["staging", "other"]}));
    for (mode, operating_mode) in [
        ("database", OperatingMode::Database),
        ("file", OperatingMode::File),
        ("dp", OperatingMode::DataPlane),
        ("mesh", OperatingMode::Mesh),
    ] {
        // A divergent admin fallback must never misreport the dialer's policy.
        let mut state = admin_state(mode, BackendEgressPolicy::unrestricted());
        state.proxy_state = Some(proxy_state(
            operating_mode,
            BackendEgressPolicy::from_allow_ips(BackendAllowIps::Public),
        ));
        let harness = AdminHarness::start(state).await;
        let (status, body) = harness.get(Some(&reader), Some("staging")).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body["enforcement_scope"], "local-data-plane");
        assert_eq!(body["namespace"], "staging");
        assert_eq!(body["mode"], "public");
        assert_eq!(body["public_only_guaranteed"], true);
        assert_eq!(body["dangerous_ranges_blocked"], true);
        let (_, other) = harness.get(Some(&reader), Some("other")).await;
        assert_eq!(other["enforcement_scope"], "unserved-namespace");
    }
    let policy = BackendEgressPolicy::from_allow_ips(BackendAllowIps::Public);
    let harness = AdminHarness::start(admin_state("node_agent", policy)).await;
    let (_, body) = harness.get(Some(&reader), Some("staging")).await;
    assert_eq!(body["enforcement_scope"], "no-data-plane");
}

#[tokio::test]
async fn all_read_roles_work_but_jwt_and_namespace_authorization_are_required() {
    for (require_claim, read_only) in [(false, false), (false, true), (true, false), (true, true)] {
        let mut state = admin_state(
            "cp",
            BackendEgressPolicy::from_allow_ips(BackendAllowIps::Both),
        );
        state.admin_require_namespace_claim = require_claim;
        state.read_only = read_only;
        let harness = AdminHarness::start(state).await;
        for role in ["viewer", "operator", "admin"] {
            let reader = token(PRIMARY_SECRET, json!({"role": role, "ns": "staging"}));
            let (status, _) = harness.get(Some(&reader), Some("staging")).await;
            assert_eq!(status, StatusCode::OK);
            for namespace in [None, Some("prod")] {
                let (status, body) = harness.get(Some(&reader), namespace).await;
                assert_eq!(status, StatusCode::FORBIDDEN);
                assert_no_policy(&body);
            }
            let (status, body) = harness.get(Some(&reader), Some("bad namespace")).await;
            assert_eq!(status, StatusCode::BAD_REQUEST);
            assert_no_policy(&body);
        }
        let unscoped = token(PRIMARY_SECRET, json!({}));
        let (status, body) = harness.get(Some(&unscoped), None).await;
        assert_eq!(status.is_success(), !require_claim);
        if require_claim {
            assert_eq!(status, StatusCode::FORBIDDEN);
            assert_no_policy(&body);
        } else {
            assert_eq!(body, default_response());
        }
    }
}

#[tokio::test]
async fn viewer_key_namespace_ceiling_applies_to_policy_reads() {
    let mut state = admin_state(
        "cp",
        BackendEgressPolicy::from_allow_ips(BackendAllowIps::Both),
    );
    state.jwt_manager = state
        .jwt_manager
        .with_viewer_secret(VIEWER_SECRET.to_string())
        .unwrap()
        .with_viewer_namespace_ceiling(ViewerNamespaceCeiling::parse("staging").unwrap());
    let harness = AdminHarness::start(state).await;
    // A key holder cannot widen its ceiling by claiming admin or arbitrary ns.
    let reader = token(
        VIEWER_SECRET,
        json!({"role": "admin", "ns": ["staging", "prod"]}),
    );
    let (status, _) = harness.get(Some(&reader), Some("staging")).await;
    assert_eq!(status, StatusCode::OK);
    for namespace in [None, Some("prod")] {
        let (status, body) = harness.get(Some(&reader), namespace).await;
        assert_eq!(status, StatusCode::FORBIDDEN);
        assert_no_policy(&body);
    }
    let outside = token(VIEWER_SECRET, json!({"ns": "prod"}));
    let (status, body) = harness.get(Some(&outside), Some("staging")).await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    assert_no_policy(&body);
}

#[tokio::test]
async fn anonymous_metrics_credentials_and_invalid_jwts_never_disclose_policy() {
    let mut state = admin_state(
        "cp",
        BackendEgressPolicy::from_allow_ips(BackendAllowIps::Both),
    );
    state.metrics_auth = Arc::new(MetricsAuthPolicy {
        bearer_token: Some(METRICS_TOKEN.to_string()),
        allowed_cidrs: TrustedProxies::parse_strict("127.0.0.0/8", "test").unwrap(),
    });
    let harness = AdminHarness::start(state).await;
    let expired = chrono::Utc::now().timestamp() - 600;
    let invalid = [
        token(VIEWER_SECRET, json!({})),
        token(PRIMARY_SECRET, json!({"iss": "wrong-issuer"})),
        token(PRIMARY_SECRET, json!({"role": "unknown"})),
        token(PRIMARY_SECRET, json!({"role": null})),
        token(PRIMARY_SECRET, json!({"ns": 123})),
        token(PRIMARY_SECRET, json!({"aud": "other-audience"})),
        token(
            PRIMARY_SECRET,
            json!({"iat": expired - 600, "nbf": expired - 600, "exp": expired}),
        ),
        METRICS_TOKEN.to_string(),
    ];
    for bearer in std::iter::once(None).chain(invalid.iter().map(|value| Some(value.as_str()))) {
        let (status, body) = harness.get(bearer, None).await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);
        assert_no_policy(&body);
    }
    for path in ["/health", "/status"] {
        for bearer in [None, Some(METRICS_TOKEN)] {
            let client = reqwest::Client::new();
            let mut request = client.get(format!("{}{path}", harness.base));
            if let Some(bearer) = bearer {
                request = request.bearer_auth(bearer);
            }
            let body: Value = request.send().await.unwrap().json().await.unwrap();
            assert_no_policy(&body);
            assert!(body.get("backend_egress_policy").is_none());
        }
    }
}

#[tokio::test]
async fn only_the_exact_get_path_returns_metadata() {
    let state = admin_state(
        "cp",
        BackendEgressPolicy::from_allow_ips(BackendAllowIps::Both),
    );
    let harness = AdminHarness::start(state).await;
    let reader = token(PRIMARY_SECRET, json!({}));
    for (method, path) in [
        (reqwest::Method::POST, PATH),
        (reqwest::Method::PUT, PATH),
        (reqwest::Method::DELETE, PATH),
        (reqwest::Method::GET, "/backend-egress-policy/extra"),
        (reqwest::Method::GET, "/backend-egress-policy/"),
    ] {
        let response = reqwest::Client::new()
            .request(method, format!("{}{path}", harness.base))
            .bearer_auth(&reader)
            .send()
            .await
            .unwrap();
        assert!(!response.status().is_success());
        let body = response.json().await.unwrap();
        assert_no_policy(&body);
    }
}

#[test]
fn openapi_metadata_vocabulary_and_default_example_match_the_endpoint() {
    let spec: Value = serde_yaml::from_str(include_str!("../../openapi.yaml")).unwrap();
    let path = &spec["paths"][PATH];
    assert_eq!(
        path["parameters"][0]["$ref"],
        "#/components/parameters/XFerrumNamespace"
    );
    let get = &path["get"];
    assert_eq!(get["security"], json!([{"bearerAuth": []}]));
    for status in ["200", "400", "401", "403"] {
        assert!(get["responses"].get(status).is_some());
    }
    let content = &get["responses"]["200"]["content"]["application/json"];
    assert_eq!(
        content["schema"]["$ref"],
        "#/components/schemas/BackendEgressPolicyResponse"
    );
    assert_eq!(
        content["examples"]["defaultControlPlane"]["value"],
        default_response()
    );
    let schema = &spec["components"]["schemas"]["BackendEgressPolicyResponse"];
    assert_eq!(schema["additionalProperties"], false);
    let properties = schema["properties"].as_object().unwrap();
    let expected = default_response();
    for key in expected.as_object().unwrap().keys() {
        assert!(properties.contains_key(key));
        assert!(schema["required"].as_array().unwrap().contains(&json!(key)));
    }
    assert_eq!(properties.len(), expected.as_object().unwrap().len());
    assert_eq!(properties["schema_version"]["enum"], json!([1]));
    assert_eq!(
        properties["ip_classification"]["enum"],
        json!(["ferrum-private-reserved-v1"])
    );
    assert_eq!(
        properties["mode"]["enum"],
        json!(["both", "public", "private"])
    );
    assert_eq!(
        properties["enforcement_scope"]["enum"],
        json!(["local-data-plane", "unserved-namespace", "admission-only", "no-data-plane"])
    );
    let validator = jsonschema::draft202012::options().build(schema).unwrap();
    assert!(validator.is_valid(&expected));
    for (field, unknown) in [
        ("schema_version", json!(2)),
        ("ip_classification", json!("unknown")),
        ("enforcement_scope", json!("unknown")),
        ("mode", json!("unknown")),
        ("mode_allowed_ip_classes", json!(["unknown"])),
        (
            "evaluation_order",
            json!(["ip-mode", "deny-cidrs", "dangerous-ranges", "allow-cidrs"]),
        ),
    ] {
        let mut invalid = expected.clone();
        invalid[field] = unknown;
        assert!(!validator.is_valid(&invalid), "accepted unknown {field}");
    }
    let mut leaked = expected.clone();
    leaked["allow_cidrs"] = json!(["10.45.67.89/32"]);
    assert!(!validator.is_valid(&leaked));
    let docs = include_str!("../../docs/admin_api.md");
    assert!(docs.contains("### `GET /backend-egress-policy`"));
    assert!(docs.contains("ferrum-private-reserved-v1"));
}
