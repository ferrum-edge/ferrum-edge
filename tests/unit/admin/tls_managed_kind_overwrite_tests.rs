//! Route coverage for managed TLS global ID uniqueness / cross-kind overwrite.
//!
//! Managed certificates, CA bundles, CRLs, OCSP responses, and JWKS share one
//! ID map. Create-with-overwrite and typed PUT must reject cross-kind collisions
//! with a stable `409 Conflict` while same-kind replacement of referenced
//! records remains allowed under the existing reload contract.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use arc_swap::ArcSwap;
use base64::Engine as _;
use chrono::Utc;
use ferrum_edge::admin::{
    AdminState,
    jwt_auth::{JwtConfig, JwtManager},
};
use ferrum_edge::config::types::{
    AuthMode, BackendScheme, BackendTlsConfig, DispatchKind, GatewayConfig, Proxy, ResponseBodyMode,
};
use ferrum_edge::tls::managed::ManagedTlsMaterialKind;
use jsonwebtoken::{EncodingKey, Header, encode};
use rcgen::{
    BasicConstraints, CertificateParams, CertificateRevocationListParams, IsCa, KeyPair,
    KeyUsagePurpose, RevocationReason, RevokedCertParams, SerialNumber,
};
use serde_json::{Value, json};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use uuid::Uuid;

#[derive(Clone)]
struct TestConfig {
    jwt_secret: String,
    jwt_issuer: String,
    max_ttl: u64,
}

impl Default for TestConfig {
    fn default() -> Self {
        Self {
            jwt_secret: "test-secret-key-for-admin-api".to_string(),
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

fn create_test_admin_state(
    config: &TestConfig,
    cached_config: Option<Arc<ArcSwap<GatewayConfig>>>,
) -> AdminState {
    AdminState {
        db: None,
        jwt_manager: create_test_jwt_manager(config),
        metrics_auth: Default::default(),
        cached_config,
        proxy_state: None,
        mode: "test".to_string(),
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
        backend_allow_ips: ferrum_edge::config::BackendEgressPolicy::unrestricted(),
    }
}

fn generate_admin_token(config: &TestConfig) -> String {
    let now = Utc::now();
    let claims = json!({
        "iss": config.jwt_issuer,
        "sub": "admin-user",
        "role": "admin",
        "iat": now.timestamp(),
        "nbf": now.timestamp(),
        "exp": (now + chrono::Duration::seconds(config.max_ttl as i64)).timestamp(),
        "jti": Uuid::new_v4().to_string()
    });
    encode(
        &Header::new(jsonwebtoken::Algorithm::HS256),
        &claims,
        &EncodingKey::from_secret(config.jwt_secret.as_bytes()),
    )
    .expect("encode token")
}

async fn start_admin(state: AdminState) -> (SocketAddr, tokio::sync::watch::Sender<bool>) {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind admin");
    let addr = listener.local_addr().expect("addr");
    let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);
    tokio::spawn(async move {
        ferrum_edge::admin::serve_admin_on_listener(
            listener,
            state,
            shutdown_rx,
            None,
            ferrum_edge::admin::AdminConnLimiter::unlimited(),
        )
        .await
        .expect("admin serve");
    });
    (addr, shutdown_tx)
}

async fn send_raw_admin_request(
    addr: SocketAddr,
    method: &str,
    path: &str,
    token: &str,
    body: &str,
) -> String {
    let mut stream = tokio::net::TcpStream::connect(addr)
        .await
        .expect("connect admin");
    let request = format!(
        "{method} {path} HTTP/1.1\r\nHost: localhost\r\nAuthorization: Bearer {token}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    );
    stream
        .write_all(request.as_bytes())
        .await
        .expect("write request");
    let mut response = Vec::new();
    stream
        .read_to_end(&mut response)
        .await
        .expect("read response");
    String::from_utf8(response).expect("utf8 response")
}

fn raw_http_status(response: &str) -> u16 {
    response
        .split_whitespace()
        .nth(1)
        .and_then(|s| s.parse().ok())
        .expect("status code")
}

fn raw_http_json_body(response: &str) -> Value {
    let body = response
        .split("\r\n\r\n")
        .nth(1)
        .expect("response body")
        .trim();
    serde_json::from_str(body).unwrap_or_else(|error| {
        panic!("expected JSON body, got {body:?} ({error})");
    })
}

#[derive(Debug, Clone, Copy)]
enum Collection {
    Certificate,
    CaBundle,
    Crl,
    OcspResponse,
    Jwks,
}

impl Collection {
    const ALL: [Collection; 5] = [
        Collection::Certificate,
        Collection::CaBundle,
        Collection::Crl,
        Collection::OcspResponse,
        Collection::Jwks,
    ];

    fn kind(self) -> ManagedTlsMaterialKind {
        match self {
            Self::Certificate => ManagedTlsMaterialKind::Certificate,
            Self::CaBundle => ManagedTlsMaterialKind::CaBundle,
            Self::Crl => ManagedTlsMaterialKind::Crl,
            Self::OcspResponse => ManagedTlsMaterialKind::OcspResponse,
            Self::Jwks => ManagedTlsMaterialKind::Jwks,
        }
    }

    fn path(self) -> &'static str {
        match self {
            Self::Certificate => "/admin/tls/certificates",
            Self::CaBundle => "/admin/tls/ca-bundles",
            Self::Crl => "/admin/tls/crls",
            Self::OcspResponse => "/admin/tls/ocsp-responses",
            Self::Jwks => "/admin/tls/jwks",
        }
    }

    fn kind_str(self) -> &'static str {
        self.kind().as_str()
    }
}

struct MaterialFixtures {
    cert_pem: String,
    key_pem: String,
    ca_pem: String,
    crl_pem: String,
    ocsp_der_base64: String,
    jwks_json: String,
}

fn material_fixtures() -> MaterialFixtures {
    let ca_key = KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).expect("ca key");
    let mut ca_params = CertificateParams::new(vec!["ca.test".to_string()]).expect("ca params");
    ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    ca_params.key_usages = vec![
        KeyUsagePurpose::KeyCertSign,
        KeyUsagePurpose::CrlSign,
        KeyUsagePurpose::DigitalSignature,
    ];
    let ca_cert = ca_params.self_signed(&ca_key).expect("ca cert");
    let ca_pem = ca_cert.pem();
    let ca_issuer = rcgen::Issuer::new(ca_params, ca_key);

    let leaf_key = KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).expect("leaf key");
    let leaf_params = CertificateParams::new(vec!["localhost".to_string()]).expect("leaf params");
    let leaf_cert = leaf_params
        .signed_by(&leaf_key, &ca_issuer)
        .expect("leaf cert");

    let now = time::OffsetDateTime::now_utc();
    let crl_params = CertificateRevocationListParams {
        this_update: now,
        next_update: now + time::Duration::days(30),
        crl_number: SerialNumber::from(1u64),
        issuing_distribution_point: None,
        revoked_certs: vec![RevokedCertParams {
            serial_number: SerialNumber::from(99u64),
            revocation_time: now,
            reason_code: Some(RevocationReason::KeyCompromise),
            invalidity_date: None,
        }],
        key_identifier_method: rcgen::KeyIdMethod::Sha256,
    };
    let crl_pem = crl_params.signed_by(&ca_issuer).unwrap().pem().unwrap();

    MaterialFixtures {
        cert_pem: leaf_cert.pem(),
        key_pem: leaf_key.serialize_pem(),
        ca_pem,
        crl_pem,
        ocsp_der_base64: base64::engine::general_purpose::STANDARD
            .encode([0x30, 0x03, 0x0a, 0x01, 0x00]),
        jwks_json: r#"{"keys":[{"kty":"oct","k":"dGVzdA","kid":"fixture"}]}"#.to_string(),
    }
}

fn create_body(collection: Collection, id: &str, fixtures: &MaterialFixtures) -> String {
    match collection {
        Collection::Certificate => json!({
            "id": id,
            "name": id,
            "cert_pem": fixtures.cert_pem,
            "key_pem": fixtures.key_pem,
        })
        .to_string(),
        Collection::CaBundle => json!({
            "id": id,
            "name": id,
            "ca_bundle_pem": fixtures.ca_pem,
        })
        .to_string(),
        Collection::Crl => json!({
            "id": id,
            "name": id,
            "crl_pem": fixtures.crl_pem,
        })
        .to_string(),
        Collection::OcspResponse => json!({
            "id": id,
            "name": id,
            "ocsp_der_base64": fixtures.ocsp_der_base64,
        })
        .to_string(),
        Collection::Jwks => json!({
            "id": id,
            "name": id,
            "jwks_json": fixtures.jwks_json,
        })
        .to_string(),
    }
}

fn overwrite_body(collection: Collection, id: &str, fixtures: &MaterialFixtures) -> String {
    let mut value: Value = serde_json::from_str(&create_body(collection, id, fixtures)).unwrap();
    value
        .as_object_mut()
        .unwrap()
        .insert("allow_overwrite".to_string(), json!(true));
    value.to_string()
}

fn put_body(collection: Collection, fixtures: &MaterialFixtures) -> String {
    match collection {
        Collection::Certificate => json!({
            "cert_pem": fixtures.cert_pem,
            "key_pem": fixtures.key_pem,
        })
        .to_string(),
        Collection::CaBundle => json!({
            "ca_bundle_pem": fixtures.ca_pem,
        })
        .to_string(),
        Collection::Crl => json!({
            "crl_pem": fixtures.crl_pem,
        })
        .to_string(),
        Collection::OcspResponse => json!({
            "ocsp_der_base64": fixtures.ocsp_der_base64,
        })
        .to_string(),
        Collection::Jwks => json!({
            "jwks_json": fixtures.jwks_json,
        })
        .to_string(),
    }
}

fn assert_kind_conflict(body: &Value, id: &str, existing: Collection, requested: Collection) {
    let error = body["error"].as_str().expect("error string");
    let expected = format!(
        "managed TLS record '{id}' already exists with kind {}, cannot overwrite with kind {}",
        existing.kind_str(),
        requested.kind_str()
    );
    assert_eq!(error, expected);
}

fn https_proxy_referencing_ca(id: &str, ca_id: &str) -> Proxy {
    let now = Utc::now();
    Proxy {
        id: id.to_string(),
        namespace: ferrum_edge::config::types::default_namespace(),
        name: Some("referenced-ca-proxy".to_string()),
        hosts: vec![],
        listen_path: Some("/tls-ref".to_string()),
        backend_scheme: Some(BackendScheme::Https),
        dispatch_kind: DispatchKind::from(BackendScheme::Https),
        backend_host: "backend.example.com".to_string(),
        backend_port: 443,
        backend_path: None,
        strip_listen_path: true,
        preserve_host_header: false,
        backend_connect_timeout_ms: 5000,
        backend_read_timeout_ms: 30000,
        backend_write_timeout_ms: 30000,
        backend_tls_client_cert_path: None,
        backend_tls_client_key_path: None,
        backend_tls_verify_server_cert: true,
        backend_tls_server_ca_cert_path: Some(format!("managed://ca-bundles/{ca_id}")),
        resolved_tls: BackendTlsConfig::default_verify(),
        dispatch_port_overrides: None,
        dispatch_port_override_fallback: None,
        dns_override: None,
        dns_cache_ttl_seconds: None,
        auth_mode: AuthMode::Single,
        plugins: vec![],
        pool_idle_timeout_seconds: None,
        pool_enable_http_keep_alive: None,
        pool_enable_http2: None,
        pool_tcp_keepalive_seconds: None,
        pool_http2_keep_alive_interval_seconds: None,
        pool_http2_keep_alive_timeout_seconds: None,
        pool_http2_initial_stream_window_size: None,
        pool_http2_initial_connection_window_size: None,
        pool_http2_adaptive_window: None,
        pool_http2_max_frame_size: None,
        pool_http2_max_concurrent_streams: None,
        pool_http3_connections_per_backend: None,
        h2_upgrade_policy: None,
        pool_max_requests_per_connection: None,
        pool_http1_max_pending_requests: None,
        upstream_id: None,
        upstream_subset: None,
        api_spec_id: None,
        circuit_breaker: None,
        retry: None,
        response_body_mode: ResponseBodyMode::default(),
        listen_port: None,
        frontend_tls: false,
        passthrough: false,
        udp_idle_timeout_seconds: 60,
        tcp_idle_timeout_seconds: Some(300),
        websocket_idle_timeout_seconds: None,
        allowed_methods: None,
        allowed_ws_origins: vec![],
        udp_max_response_amplification_factor: None,
        stream_proxy_protocol: None,
        created_at: now,
        updated_at: now,
    }
}

#[tokio::test]
async fn pairwise_routes_reject_cross_kind_create_overwrite_and_put() {
    let config = TestConfig::default();
    let (addr, shutdown) = start_admin(create_test_admin_state(&config, None)).await;
    let token = generate_admin_token(&config);
    let fixtures = material_fixtures();

    for existing in Collection::ALL {
        for requested in Collection::ALL {
            if existing.kind_str() == requested.kind_str() {
                continue;
            }
            let id = format!("kind-{}-{}", Uuid::new_v4().simple(), existing.kind_str());

            let create = send_raw_admin_request(
                addr,
                "POST",
                existing.path(),
                &token,
                &create_body(existing, &id, &fixtures),
            )
            .await;
            assert_eq!(raw_http_status(&create), 201, "seed {existing:?}: {create}");

            let overwrite = send_raw_admin_request(
                addr,
                "POST",
                requested.path(),
                &token,
                &overwrite_body(requested, &id, &fixtures),
            )
            .await;
            assert_eq!(
                raw_http_status(&overwrite),
                409,
                "create-overwrite {existing:?}->{requested:?}: {overwrite}"
            );
            assert_kind_conflict(&raw_http_json_body(&overwrite), &id, existing, requested);

            let put = send_raw_admin_request(
                addr,
                "PUT",
                &format!("{}/{id}", requested.path()),
                &token,
                &put_body(requested, &fixtures),
            )
            .await;
            assert_eq!(
                raw_http_status(&put),
                409,
                "put {existing:?}->{requested:?}: {put}"
            );
            assert_kind_conflict(&raw_http_json_body(&put), &id, existing, requested);

            let get_existing = send_raw_admin_request(
                addr,
                "GET",
                &format!("{}/{id}", existing.path()),
                &token,
                "",
            )
            .await;
            assert_eq!(
                raw_http_status(&get_existing),
                200,
                "original retained for {existing:?}: {get_existing}"
            );

            let delete = send_raw_admin_request(
                addr,
                "DELETE",
                &format!("{}/{id}", existing.path()),
                &token,
                "",
            )
            .await;
            assert_eq!(raw_http_status(&delete), 200, "cleanup: {delete}");
        }
    }

    let _ = shutdown.send(true);
    tokio::time::sleep(Duration::from_millis(50)).await;
}

#[tokio::test]
async fn referenced_same_kind_replacement_succeeds_while_cross_kind_and_delete_conflict() {
    let config = TestConfig::default();
    let ca_id = format!("ref-ca-{}", Uuid::new_v4().simple());
    let gateway = GatewayConfig {
        proxies: vec![https_proxy_referencing_ca("ref-proxy", &ca_id)],
        ..GatewayConfig::default()
    };
    let (addr, shutdown) = start_admin(create_test_admin_state(
        &config,
        Some(Arc::new(ArcSwap::new(Arc::new(gateway)))),
    ))
    .await;
    let token = generate_admin_token(&config);
    let fixtures = material_fixtures();

    let create = send_raw_admin_request(
        addr,
        "POST",
        Collection::CaBundle.path(),
        &token,
        &create_body(Collection::CaBundle, &ca_id, &fixtures),
    )
    .await;
    assert_eq!(
        raw_http_status(&create),
        201,
        "create referenced CA: {create}"
    );

    let same_kind = send_raw_admin_request(
        addr,
        "PUT",
        &format!("{}/{ca_id}", Collection::CaBundle.path()),
        &token,
        &put_body(Collection::CaBundle, &fixtures),
    )
    .await;
    assert_eq!(
        raw_http_status(&same_kind),
        200,
        "same-kind replacement of referenced CA must succeed: {same_kind}"
    );
    assert_eq!(
        raw_http_json_body(&same_kind)["kind"].as_str(),
        Some("ca_bundle")
    );

    let cross_kind = send_raw_admin_request(
        addr,
        "PUT",
        &format!("{}/{ca_id}", Collection::Certificate.path()),
        &token,
        &put_body(Collection::Certificate, &fixtures),
    )
    .await;
    assert_eq!(
        raw_http_status(&cross_kind),
        409,
        "cross-kind overwrite of referenced CA must conflict: {cross_kind}"
    );
    assert_kind_conflict(
        &raw_http_json_body(&cross_kind),
        &ca_id,
        Collection::CaBundle,
        Collection::Certificate,
    );

    let delete = send_raw_admin_request(
        addr,
        "DELETE",
        &format!("{}/{ca_id}", Collection::CaBundle.path()),
        &token,
        "",
    )
    .await;
    assert_eq!(
        raw_http_status(&delete),
        409,
        "referenced CA delete must still conflict: {delete}"
    );
    let delete_body = raw_http_json_body(&delete);
    assert_eq!(
        delete_body["error"].as_str(),
        Some("managed TLS record is still referenced")
    );

    let _ = shutdown.send(true);
    tokio::time::sleep(Duration::from_millis(50)).await;
}
