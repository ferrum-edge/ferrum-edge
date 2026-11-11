//! End-to-end coverage for the SPIFFE trust-bundle federation poller (GAP-3C).
//!
//! These tests stand up a tiny tokio HTTPS responder and point the poller at
//! it. They drive the production `FederationPollerManager` (the same
//! reconcile/withdraw lifecycle the mesh runtime runs on every slice apply) so
//! the tests do not need a full mesh runtime. A `GET /mesh/federation` admin
//! exercise verifies the snapshot lands in the AdminState surface, and a
//! second mock-endpoint test verifies fail-open vs fail-closed semantics.

use crate::scaffolding::port_registry::TestSocket;

use arc_swap::ArcSwap;
use base64::Engine;
use chrono::Utc;
use ferrum_edge::admin::{
    AdminState,
    jwt_auth::{JwtConfig, JwtManager},
    serve_admin_on_listener,
};
use ferrum_edge::config::env_config::EnvConfig;
use ferrum_edge::config::types::GatewayConfig;
use ferrum_edge::dns::{DnsCache, DnsConfig};
use ferrum_edge::identity::TrustDomain;
use ferrum_edge::modes::mesh::config::{MultiClusterConfig, RemoteCluster};
use ferrum_edge::modes::mesh::federation::{
    FederationPollerConfig, FederationPollerManager, FederationStore,
};
use ferrum_edge::modes::mesh::runtime::MeshRuntimeState;
use ferrum_edge::plugins::PluginHttpClient;
use ferrum_edge::proxy::ProxyState;
use jsonwebtoken::{EncodingKey, Header, encode};
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use serde_json::{Value, json};
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::sync::watch;

const TEST_TRUST_DOMAIN: &str = "remote.example.com";

fn sample_cert_base64() -> String {
    base64::engine::general_purpose::STANDARD.encode([0xde, 0xad, 0xbe, 0xef])
}

fn td(value: &str) -> TrustDomain {
    TrustDomain::new(value).expect("valid trust domain")
}

struct MockFederationEndpoint {
    endpoint: String,
    request_count: Arc<AtomicUsize>,
    shutdown: watch::Sender<bool>,
    http_client: PluginHttpClient,
    _ca_dir: tempfile::TempDir,
}

fn generate_mock_federation_tls() -> (String, String, String) {
    use rcgen::{
        BasicConstraints, CertificateParams, DistinguishedName, IsCa, Issuer, KeyPair,
        KeyUsagePurpose,
    };

    let ca_key = KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).expect("ca key");
    let mut ca_params = CertificateParams::new(Vec::<String>::new()).expect("ca params");
    ca_params.distinguished_name = DistinguishedName::new();
    ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    ca_params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
    let ca_cert = ca_params.self_signed(&ca_key).expect("ca cert");
    let ca_pem = ca_cert.pem();
    let issuer = Issuer::new(ca_params, ca_key);

    let leaf_key = KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).expect("leaf key");
    let mut leaf_params =
        CertificateParams::new(vec!["127.0.0.1".to_string()]).expect("loopback leaf params");
    leaf_params.distinguished_name = DistinguishedName::new();
    leaf_params.is_ca = IsCa::ExplicitNoCa;
    let leaf_cert = leaf_params
        .signed_by(&leaf_key, &issuer)
        .expect("leaf cert");

    (ca_pem, leaf_cert.pem(), leaf_key.serialize_pem())
}

fn mock_federation_server_config(cert_pem: &str, key_pem: &str) -> rustls::ServerConfig {
    let cert_chain: Vec<_> = CertificateDer::pem_slice_iter(cert_pem.as_bytes())
        .filter_map(|cert| cert.ok())
        .collect();
    let private_key = PrivateKeyDer::from_pem_slice(key_pem.as_bytes()).expect("parse private key");

    let provider = rustls::crypto::ring::default_provider();
    let mut config = rustls::ServerConfig::builder_with_provider(Arc::new(provider))
        .with_safe_default_protocol_versions()
        .expect("protocol versions")
        .with_no_client_auth()
        .with_single_cert(cert_chain, private_key)
        .expect("server TLS config");
    config.alpn_protocols = vec![b"http/1.1".to_vec()];
    config
}

fn poller_http_client_with_ca(ca_bundle_path: &str) -> PluginHttpClient {
    PluginHttpClient::new(
        &ferrum_edge::config::PoolConfig::default(),
        DnsCache::new(DnsConfig::default()),
        1000,
        0,
        100,
        false,
        Some(ca_bundle_path),
        Arc::new(Vec::new()),
        ferrum_edge::config::types::DEFAULT_NAMESPACE,
        ferrum_edge::config::BackendEgressPolicy::unrestricted(),
        Arc::new(Vec::new()),
        0,
    )
}

/// Tiny tokio HTTPS responder that serves a static body on the first hit and
/// can be reconfigured to return errors after that. The poller is driven
/// through it to exercise success → backoff → recovery in a single test.
async fn start_mock_federation_endpoint(
    body: String,
    extra_failures_before_success: usize,
) -> MockFederationEndpoint {
    let (ca_pem, cert_pem, key_pem) = generate_mock_federation_tls();
    let ca_dir = tempfile::tempdir().expect("tempdir");
    let ca_path = ca_dir.path().join("mock-federation-ca.pem");
    std::fs::write(&ca_path, ca_pem).expect("write CA bundle");
    let http_client =
        poller_http_client_with_ca(ca_path.to_str().expect("CA bundle path is UTF-8"));
    let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(mock_federation_server_config(
        &cert_pem, &key_pem,
    )));

    let listener = TcpListener::bind_test("127.0.0.1:0").await.expect("bind");
    let addr = listener.local_addr().expect("local_addr");
    let endpoint = format!("https://{addr}/.well-known/spiffe");
    let request_count = Arc::new(AtomicUsize::new(0));
    let (shutdown_tx, mut shutdown_rx) = watch::channel(false);
    let counter = request_count.clone();
    tokio::spawn(async move {
        loop {
            tokio::select! {
                accept = listener.accept() => {
                    let Ok((stream, _)) = accept else { return };
                    let body = body.clone();
                    let counter = counter.clone();
                    let acceptor = acceptor.clone();
                    tokio::spawn(async move {
                        let Ok(mut stream) = acceptor.accept(stream).await else { return };
                        let mut buf = vec![0u8; 4096];
                        let _ = stream.read(&mut buf).await;
                        let n = counter.fetch_add(1, Ordering::SeqCst);
                        let status_line = if n < extra_failures_before_success {
                            "HTTP/1.1 503 Service Unavailable"
                        } else {
                            "HTTP/1.1 200 OK"
                        };
                        let response = format!(
                            "{status_line}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                            body.len(),
                            body
                        );
                        let _ = stream.write_all(response.as_bytes()).await;
                        let _ = stream.shutdown().await;
                    });
                }
                _ = shutdown_rx.changed() => {
                    if *shutdown_rx.borrow() { return; }
                }
            }
        }
    });
    MockFederationEndpoint {
        endpoint,
        request_count,
        shutdown: shutdown_tx,
        http_client,
        _ca_dir: ca_dir,
    }
}

/// 30 s poll interval, 5 s request timeout, the default 3600 s max-stale.
fn poller_config(fail_open: bool) -> Option<FederationPollerConfig> {
    FederationPollerConfig::from_env_with_max_stale(30, 5, fail_open, 3600)
}

async fn wait_for_first_success(store: &FederationStore, attempts: usize) {
    let mut waited = 0;
    while !store.has_first_success() && waited < attempts {
        tokio::time::sleep(Duration::from_millis(100)).await;
        waited += 1;
    }
}

fn remote_cluster(name: &str, endpoint: &str) -> RemoteCluster {
    RemoteCluster {
        name: name.to_string(),
        trust_domain: td(TEST_TRUST_DOMAIN),
        network: None,
        control_plane_url: None,
        federation_endpoint: Some(endpoint.to_string()),
        discovery_credential_ref: None,
    }
}

#[tokio::test]
async fn federation_poller_populates_store_on_success() {
    let body = json!({
        "trust_domain": TEST_TRUST_DOMAIN,
        "x509_authorities": [sample_cert_base64()],
        "refresh_hint_seconds": 60u64,
    })
    .to_string();
    let mock = start_mock_federation_endpoint(body, 0).await;
    let multi_cluster = MultiClusterConfig {
        local_cluster: Some("local-cluster".to_string()),
        federation_endpoint: None,
        remote_clusters: vec![remote_cluster("remote", &mock.endpoint)],
        east_west_gateways: Vec::new(),
    };
    let store = FederationStore::new();
    let mut manager = FederationPollerManager::new(
        poller_config(false),
        mock.http_client.clone(),
        store.clone(),
    );
    manager.reconcile(Some(&multi_cluster));

    wait_for_first_success(&store, 50).await;
    assert!(
        store.has_first_success(),
        "poller never marked first success"
    );
    let snapshot = store.snapshot();
    assert_eq!(snapshot.bundles.len(), 1, "exactly one bundle stored");
    let bundle = snapshot
        .bundles
        .get(&td(TEST_TRUST_DOMAIN))
        .expect("expected trust domain present");
    assert_eq!(bundle.bundle.x509_authorities.len(), 1);
    assert_eq!(bundle.bundle.refresh_hint_seconds, Some(60));
    // Only the origin of the configured URL is retained (it is served by
    // `GET /mesh/federation`); the path is dropped.
    assert_eq!(
        bundle.endpoint,
        mock.endpoint.trim_end_matches("/.well-known/spiffe")
    );
    assert_eq!(bundle.cluster_name, "remote");
    assert!(mock.request_count.load(Ordering::SeqCst) >= 1);

    manager.shutdown();
    let _ = mock.shutdown.send(true);
}

#[tokio::test]
async fn federation_poller_keeps_last_good_after_transient_failure() {
    // Endpoint serves 503 twice then succeeds. The poller should ignore the
    // 503s, eventually install the bundle, and keep working through transient
    // upstream errors without panicking.
    let body = json!({
        "trust_domain": TEST_TRUST_DOMAIN,
        "x509_authorities": [sample_cert_base64()],
    })
    .to_string();
    let mock = start_mock_federation_endpoint(body, 2).await;
    let multi_cluster = MultiClusterConfig {
        local_cluster: Some("local-cluster".to_string()),
        federation_endpoint: None,
        remote_clusters: vec![remote_cluster("remote", &mock.endpoint)],
        east_west_gateways: Vec::new(),
    };
    let store = FederationStore::new();
    let mut manager =
        FederationPollerManager::new(poller_config(true), mock.http_client.clone(), store.clone());
    manager.reconcile(Some(&multi_cluster));

    wait_for_first_success(&store, 200).await;
    assert!(
        store.has_first_success(),
        "poller never recovered from transient failures"
    );
    let snapshot = store.snapshot();
    assert!(snapshot.bundles.contains_key(&td(TEST_TRUST_DOMAIN)));
    assert!(
        mock.request_count.load(Ordering::SeqCst) >= 3,
        "expected at least 3 endpoint hits (2 fails + 1 success), saw {}",
        mock.request_count.load(Ordering::SeqCst)
    );

    manager.shutdown();
    let _ = mock.shutdown.send(true);
}

#[test]
fn federation_poller_disabled_when_interval_zero() {
    assert!(
        FederationPollerConfig::from_env_with_max_stale(0, 30, false, 3600).is_none(),
        "interval=0 disables the poller"
    );
}

/// A slice that withdraws the remote cluster (or drops its federation
/// endpoint) must stop the poller AND remove the once-fetched bundle, so a
/// decommissioned trust anchor stops being overlaid onto slice applies without
/// a gateway restart.
#[tokio::test]
async fn federation_poller_manager_removes_bundle_when_cluster_is_withdrawn() {
    let body = json!({
        "trust_domain": TEST_TRUST_DOMAIN,
        "x509_authorities": [sample_cert_base64()],
    })
    .to_string();
    let mock = start_mock_federation_endpoint(body, 0).await;
    let with_remote = MultiClusterConfig {
        local_cluster: Some("local-cluster".to_string()),
        federation_endpoint: None,
        remote_clusters: vec![remote_cluster("remote", &mock.endpoint)],
        east_west_gateways: Vec::new(),
    };
    let store = FederationStore::new();
    let mut manager = FederationPollerManager::new(
        poller_config(false),
        mock.http_client.clone(),
        store.clone(),
    );
    manager.reconcile(Some(&with_remote));
    wait_for_first_success(&store, 50).await;
    assert!(
        store
            .snapshot()
            .bundles
            .contains_key(&td(TEST_TRUST_DOMAIN)),
        "poller never installed the remote bundle"
    );
    let revision_before = *store.subscribe().borrow();

    let without_remote = MultiClusterConfig {
        remote_clusters: Vec::new(),
        ..with_remote.clone()
    };
    manager.reconcile(Some(&without_remote));
    assert!(
        !store
            .snapshot()
            .bundles
            .contains_key(&td(TEST_TRUST_DOMAIN)),
        "withdrawn cluster's federated bundle must be removed"
    );
    assert!(
        *store.subscribe().borrow() > revision_before,
        "withdrawal must bump the federation revision so slice apply re-runs"
    );

    // The poller is stopped, so no later poll can reinstall the bundle.
    let hits_after_withdrawal = mock.request_count.load(Ordering::SeqCst);
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert!(
        !store
            .snapshot()
            .bundles
            .contains_key(&td(TEST_TRUST_DOMAIN))
    );
    assert_eq!(
        mock.request_count.load(Ordering::SeqCst),
        hits_after_withdrawal
    );

    manager.shutdown();
    let _ = mock.shutdown.send(true);
}

// ── /mesh/federation admin endpoint coverage ───────────────────────────────

#[derive(Clone)]
struct AdminTestConfig {
    jwt_secret: String,
    jwt_issuer: String,
    max_ttl: u64,
}

impl Default for AdminTestConfig {
    fn default() -> Self {
        Self {
            jwt_secret: "test-secret-key-for-mesh-federation-32".to_string(),
            jwt_issuer: "test-ferrum-edge".to_string(),
            max_ttl: 3600,
        }
    }
}

fn jwt_manager(config: &AdminTestConfig) -> JwtManager {
    JwtManager::new(JwtConfig {
        secret: config.jwt_secret.clone(),
        issuer: config.jwt_issuer.clone(),
        audience: None,
        max_ttl_seconds: config.max_ttl,
        algorithm: jsonwebtoken::Algorithm::HS256,
    })
}

fn admin_token(config: &AdminTestConfig) -> String {
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
    encode(&header, &claims, &key).expect("token")
}

fn build_admin_state(jwt: JwtManager, mesh_runtime_state: Option<MeshRuntimeState>) -> AdminState {
    let cfg = GatewayConfig {
        version: "1".to_string(),
        loaded_at: Utc::now(),
        ..GatewayConfig::default()
    };
    let env_config = EnvConfig {
        namespace: "alpha".to_string(),
        ..EnvConfig::default()
    };
    let (proxy_state, _handles) = ProxyState::new(
        cfg,
        DnsCache::new(DnsConfig::default()),
        env_config,
        None,
        None,
    )
    .expect("proxy state");

    AdminState {
        db: None,
        jwt_manager: jwt,
        metrics_auth: Default::default(),
        cached_config: None,
        proxy_state: Some(proxy_state),
        mode: "mesh".to_string(),
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
        mesh_runtime_state,
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

async fn start_test_admin(state: AdminState) -> (String, watch::Sender<bool>) {
    let addr: SocketAddr = "127.0.0.1:0".parse().unwrap();
    let (shutdown_tx, shutdown_rx) = watch::channel(false);
    let listener = tokio::net::TcpListener::bind_test(addr).await.unwrap();
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
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    panic!("admin listener at {} never became ready", actual_addr);
}

#[tokio::test]
async fn mesh_federation_endpoint_returns_404_without_mesh_runtime() {
    let tc = AdminTestConfig::default();
    let token = admin_token(&tc);
    let state = build_admin_state(jwt_manager(&tc), None);
    let (base_url, _shutdown) = start_test_admin(state).await;
    let response = reqwest::Client::new()
        .get(format!("{base_url}/mesh/federation"))
        .header("authorization", format!("Bearer {token}"))
        .send()
        .await
        .unwrap();
    assert_eq!(response.status().as_u16(), 404);
}

#[tokio::test]
async fn mesh_federation_endpoint_returns_404_before_first_poll_success() {
    let tc = AdminTestConfig::default();
    let token = admin_token(&tc);
    let mesh_runtime = MeshRuntimeState::new();
    // No install of any federated bundle.
    let state = build_admin_state(jwt_manager(&tc), Some(mesh_runtime));
    let (base_url, _shutdown) = start_test_admin(state).await;
    let response = reqwest::Client::new()
        .get(format!("{base_url}/mesh/federation"))
        .header("authorization", format!("Bearer {token}"))
        .send()
        .await
        .unwrap();
    assert_eq!(response.status().as_u16(), 404);
}

#[tokio::test]
async fn mesh_federation_endpoint_returns_polled_bundles() {
    let tc = AdminTestConfig::default();
    let token = admin_token(&tc);
    let body = json!({
        "trust_domain": TEST_TRUST_DOMAIN,
        "x509_authorities": [sample_cert_base64(), sample_cert_base64()],
    })
    .to_string();
    let mock = start_mock_federation_endpoint(body, 0).await;
    // A credential-bearing endpoint (userinfo + signed query + fragment): the
    // poller dials it as configured, but the admin view must expose only its
    // origin (GHSA-pr43-4rj8-h494).
    let credentialed_endpoint = format!(
        "{}?sig=fed-query-secret#fed-fragment-secret",
        mock.endpoint
            .replacen("https://", "https://fed-user:fed-password-secret@", 1)
    );
    let mesh_runtime = MeshRuntimeState::new();
    let multi_cluster = MultiClusterConfig {
        local_cluster: Some("local-cluster".to_string()),
        federation_endpoint: None,
        remote_clusters: vec![remote_cluster("remote", &credentialed_endpoint)],
        east_west_gateways: Vec::new(),
    };
    let store = mesh_runtime.federation_store().clone();
    let mut manager = FederationPollerManager::new(
        poller_config(false),
        mock.http_client.clone(),
        store.clone(),
    );
    manager.reconcile(Some(&multi_cluster));

    wait_for_first_success(&store, 50).await;
    assert!(store.has_first_success(), "poller never populated store");

    let state = build_admin_state(jwt_manager(&tc), Some(mesh_runtime));
    let (base_url, _admin_shutdown) = start_test_admin(state).await;
    let response: Value = reqwest::Client::new()
        .get(format!("{base_url}/mesh/federation"))
        .header("authorization", format!("Bearer {token}"))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let bundles = response["bundles"].as_array().expect("bundles array");
    assert_eq!(bundles.len(), 1);
    assert_eq!(bundles[0]["trust_domain"], TEST_TRUST_DOMAIN);
    assert_eq!(bundles[0]["cluster"], "remote");
    assert_eq!(bundles[0]["x509_authorities"], 2);
    assert_eq!(bundles[0]["jwt_authorities"], 0);
    assert_eq!(
        bundles[0]["endpoint"],
        mock.endpoint.trim_end_matches("/.well-known/spiffe"),
        "the admin view must report only the endpoint origin"
    );
    let rendered = response.to_string();
    for fragment in ["fed-user", "secret", ".well-known"] {
        assert!(
            !rendered.contains(fragment),
            "GET /mesh/federation must not echo {fragment:?} of the configured endpoint: {rendered}"
        );
    }

    manager.shutdown();
    let _ = mock.shutdown.send(true);
}

#[tokio::test]
async fn mesh_federation_endpoint_requires_jwt() {
    let tc = AdminTestConfig::default();
    let mesh_runtime = MeshRuntimeState::new();
    let state = build_admin_state(jwt_manager(&tc), Some(mesh_runtime));
    let (base_url, _shutdown) = start_test_admin(state).await;
    let response = reqwest::Client::new()
        .get(format!("{base_url}/mesh/federation"))
        .send()
        .await
        .unwrap();
    assert_eq!(response.status().as_u16(), 401);
}
