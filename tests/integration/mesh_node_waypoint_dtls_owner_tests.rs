//! Owner-scoped NodeWaypoint DTLS candidate-build contract (issue #3858).
//!
//! A generated listener that resolves to Strict PeerAuthentication with no
//! `FERRUM_DTLS_CLIENT_CA_CERT_PATH` is a candidate-build error. The complete
//! candidate slice is rejected before `update_mesh_config`, and the last-good
//! routing plus owner-scoped DTLS generation are retained. Omitting that
//! listener and still returning `Ok` would accept routing while
//! `publish_mesh_node_waypoint_dtls_generation` skipped the already-running
//! listener, leaving a Permissive verifier in place after a Strict policy
//! advance.

use crate::scaffolding::port_registry::TestSocket;

use std::collections::HashMap;
use std::sync::Arc;

use ferrum_edge::config::EnvConfig;
use ferrum_edge::config::db_backend::NamespacedResourceId;
use ferrum_edge::config::types::{BackendScheme, DispatchKind, GatewayConfig};
use ferrum_edge::dns::{DnsCache, DnsConfig};
use ferrum_edge::modes::mesh::config::{
    AppProtocol, MeshService, MtlsMode, PeerAuthentication, ServicePort, Workload, WorkloadRef,
    WorkloadSelector,
};
use ferrum_edge::modes::mesh::slice::MeshSlice;
use ferrum_edge::modes::mesh::{
    MeshRuntimeConfig, MeshTopology, build_node_waypoint_dtls_owner_configs,
    node_waypoint_udp_proxy_id, publish_initial_node_waypoint_dtls_generation,
};
use ferrum_edge::proxy::ProxyState;
use rcgen::{CertificateParams, KeyPair};

use super::mesh_test_support::{DEFAULT_NAMESPACE, http_proxy, runtime_for_topology, workload_for};

const PERMISSIVE_PORT: u16 = 5684;
const STRICT_PORT: u16 = 5685;

struct DtlsIdentity {
    _dir: tempfile::TempDir,
    cert_path: String,
    key_path: String,
}

fn ensure_crypto_provider() {
    let _ = rustls::crypto::ring::default_provider().install_default();
}

fn write_dtls_identity() -> DtlsIdentity {
    let dir = tempfile::TempDir::new().expect("dtls identity tempdir");
    let key_pair = KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).expect("ECDSA P-256 key");
    let params = CertificateParams::new(vec!["localhost".to_string()]).expect("dtls cert params");
    let cert = params
        .self_signed(&key_pair)
        .expect("self-signed DTLS cert");
    let cert_path = dir.path().join("dtls.crt");
    let key_path = dir.path().join("dtls.key");
    std::fs::write(&cert_path, cert.pem()).expect("write DTLS cert");
    std::fs::write(&key_path, key_pair.serialize_pem()).expect("write DTLS key");
    DtlsIdentity {
        cert_path: cert_path.to_string_lossy().into_owned(),
        key_path: key_path.to_string_lossy().into_owned(),
        _dir: dir,
    }
}

fn dtls_env(identity: &DtlsIdentity, client_ca: Option<&str>) -> EnvConfig {
    EnvConfig {
        pool_warmup_enabled: false,
        shutdown_drain_seconds: 0,
        accept_threads: 1,
        dtls_cert_path: Some(identity.cert_path.clone()),
        dtls_key_path: Some(identity.key_path.clone()),
        dtls_client_ca_cert_path: client_ca.map(str::to_string),
        ..EnvConfig::default()
    }
}

fn test_proxy_state(env: EnvConfig, config: GatewayConfig) -> ProxyState {
    ProxyState::new(config, DnsCache::new(DnsConfig::default()), env, None, None)
        .expect("proxy state")
        .0
}

fn node_waypoint_runtime() -> MeshRuntimeConfig {
    runtime_for_topology(MeshTopology::NodeWaypoint)
}

fn generated_dtls_proxy(service: &str, port: u16) -> ferrum_edge::config::types::Proxy {
    let mut proxy = http_proxy("unused", "example.invalid", 9);
    proxy.id = node_waypoint_udp_proxy_id(DEFAULT_NAMESPACE, service, port)
        .expect("test service names are admitted Kubernetes identities");
    proxy.namespace = DEFAULT_NAMESPACE.to_string();
    proxy.name = Some(service.to_string());
    proxy.hosts = Vec::new();
    proxy.listen_path = None;
    proxy.backend_scheme = Some(BackendScheme::Udp);
    proxy.dispatch_kind = DispatchKind::from(BackendScheme::Udp);
    proxy.listen_port = Some(port);
    proxy.frontend_tls = true;
    proxy.strip_listen_path = false;
    proxy
}

fn dtls_service(name: &str, port: u16, workload: &Workload) -> MeshService {
    MeshService {
        cluster_ips: vec!["10.96.0.10".to_string()],
        name: name.to_string(),
        namespace: DEFAULT_NAMESPACE.to_string(),
        ports: vec![ServicePort {
            port,
            protocol: AppProtocol::Dtls,
            name: Some(name.to_string()),
            target_port: None,
        }],
        workloads: vec![WorkloadRef {
            spiffe_id: workload.spiffe_id.clone(),
        }],
        protocol_overrides: HashMap::new(),
        uid: None,
    }
}

fn namespace_peer_auth(
    mode: MtlsMode,
    port_overrides: HashMap<u16, MtlsMode>,
) -> PeerAuthentication {
    PeerAuthentication {
        name: "default".to_string(),
        namespace: DEFAULT_NAMESPACE.to_string(),
        scope: None,
        selector: None,
        mtls_mode: mode,
        port_overrides,
    }
}

fn dtls_slice(
    services: Vec<MeshService>,
    workloads: Vec<Workload>,
    peer_authentications: Vec<PeerAuthentication>,
) -> MeshSlice {
    MeshSlice {
        namespace: DEFAULT_NAMESPACE.to_string(),
        services,
        workloads,
        peer_authentications: peer_authentications.clone(),
        node_waypoint_capture_peer_authentications: peer_authentications,
        ..MeshSlice::default()
    }
}

fn listener_key(service: &str, port: u16) -> String {
    NamespacedResourceId::new(
        DEFAULT_NAMESPACE.to_string(),
        node_waypoint_udp_proxy_id(DEFAULT_NAMESPACE, service, port)
            .expect("test service names are admitted Kubernetes identities"),
    )
    .runtime_key()
}

/// The first accepted slice is the apply loop's baseline, so startup must
/// publish its owner-scoped DTLS generation before the initial listener
/// reconcile. A generated listener must bind only after that exact generation
/// exists; deferred-without-a-socket is not startup success.
#[tokio::test]
async fn initial_dtls_generation_precedes_generated_listener_startup() {
    ensure_crypto_provider();
    let identity = write_dtls_identity();
    let backend = workload_for(
        "coap",
        DEFAULT_NAMESPACE,
        [("app", "coap")],
        ["10.244.3.12"],
    );
    let holder = tokio::net::UdpSocket::bind_test("127.0.0.1:0")
        .await
        .expect("reserve UDP listener port");
    let port = holder.local_addr().expect("reserved address").port();
    drop(holder);

    let slice = dtls_slice(
        vec![dtls_service("coap", port, &backend)],
        vec![backend],
        vec![namespace_peer_auth(MtlsMode::Permissive, HashMap::new())],
    );
    let config = GatewayConfig {
        proxies: vec![generated_dtls_proxy("coap", port)],
        ..GatewayConfig::default()
    };
    let state = test_proxy_state(dtls_env(&identity, None), config);
    let runtime = node_waypoint_runtime();

    assert!(
        state
            .stream_listener_manager
            .snapshot_mesh_node_waypoint_dtls_generation()
            .is_none(),
        "a fresh manager has no owner-scoped generation"
    );
    publish_initial_node_waypoint_dtls_generation(&state, &runtime, &slice)
        .await
        .expect("initial accepted DTLS generation must be servable");

    let accepted = state
        .stream_listener_manager
        .snapshot_mesh_node_waypoint_dtls_generation()
        .expect("initial owner-scoped generation published");
    assert_eq!(
        accepted.covered_listener_keys(),
        vec![listener_key("coap", port)]
    );
    assert!(
        state
            .stream_listener_manager
            .snapshot_frontend_dtls_generation()
            .is_none(),
        "initial mesh publication must not seed the operator DTLS slot"
    );

    state
        .initial_reconcile_stream_listeners()
        .await
        .expect("initial generated listener reconcile");
    state
        .stream_listener_manager
        .wait_until_started(std::time::Duration::from_secs(2))
        .await
        .expect("generated listener must bind after its owner generation publishes");
    assert!(
        state
            .stream_listener_manager
            .stream_bind_failures()
            .is_empty(),
        "a covered initial listener must not remain deferred or degraded"
    );

    state.stream_listener_manager.shutdown_all().await;
}

/// A mixed Permissive+Strict candidate without a client CA must not return Ok
/// with the Strict listener omitted. That is the all-candidate atomicity
/// contract: one unservable required candidate rejects the complete slice.
#[tokio::test]
async fn strict_dtls_without_client_ca_rejects_the_complete_candidate() {
    ensure_crypto_provider();
    let identity = write_dtls_identity();
    let coap = workload_for(
        "coap",
        DEFAULT_NAMESPACE,
        [("app", "coap")],
        ["10.244.3.12"],
    );
    let secure = workload_for(
        "secure",
        DEFAULT_NAMESPACE,
        [("app", "secure")],
        ["10.244.3.13"],
    );
    let slice = dtls_slice(
        vec![
            dtls_service("coap", PERMISSIVE_PORT, &coap),
            dtls_service("secure", STRICT_PORT, &secure),
        ],
        vec![coap, secure],
        vec![
            namespace_peer_auth(MtlsMode::Strict, HashMap::new()),
            // Istio portLevelMtls applies only on a workload-selector policy;
            // selector-less namespace policies deliberately ignore
            // `port_overrides`. Make the coap workload's port permissive while
            // the secure workload retains the namespace-wide Strict posture.
            PeerAuthentication {
                name: "coap-permissive".to_string(),
                namespace: DEFAULT_NAMESPACE.to_string(),
                scope: None,
                selector: Some(WorkloadSelector {
                    labels: HashMap::from([("app".to_string(), "coap".to_string())]),
                    namespace: None,
                }),
                mtls_mode: MtlsMode::Strict,
                port_overrides: HashMap::from([(PERMISSIVE_PORT, MtlsMode::Permissive)]),
            },
        ],
    );
    let config = GatewayConfig {
        proxies: vec![
            generated_dtls_proxy("coap", PERMISSIVE_PORT),
            generated_dtls_proxy("secure", STRICT_PORT),
        ],
        ..GatewayConfig::default()
    };
    let state = test_proxy_state(dtls_env(&identity, None), config.clone());
    let runtime = node_waypoint_runtime();

    let error = build_node_waypoint_dtls_owner_configs(&state, &runtime, &slice, &config)
        .err()
        .expect("STRICT without a client CA must reject the complete candidate");
    assert!(
        error.contains("STRICT"),
        "diagnostic must name the unservable STRICT posture: {error}"
    );
    assert!(
        error.contains("FERRUM_DTLS_CLIENT_CA_CERT_PATH"),
        "diagnostic must name the missing client-CA setting: {error}"
    );
    assert!(
        error.contains(&STRICT_PORT.to_string()),
        "diagnostic must name the unservable listener port: {error}"
    );
}

/// Permissive-to-Strict without a client CA must not publish a generation that
/// omits the listener. The last-good accepted routing and owner-scoped
/// generation stay in place, matching `apply_mesh_slice_generation`'s Err
/// path (record failure, do not `update_mesh_config`, do not publish).
#[tokio::test]
async fn permissive_to_strict_without_client_ca_retains_last_good_generation() {
    ensure_crypto_provider();
    let identity = write_dtls_identity();
    let backend = workload_for(
        "coap",
        DEFAULT_NAMESPACE,
        [("app", "coap")],
        ["10.244.3.12"],
    );
    let services = vec![dtls_service("coap", PERMISSIVE_PORT, &backend)];
    let workloads = vec![backend];
    let config = GatewayConfig {
        proxies: vec![generated_dtls_proxy("coap", PERMISSIVE_PORT)],
        ..GatewayConfig::default()
    };
    let state = test_proxy_state(dtls_env(&identity, None), config.clone());
    let runtime = node_waypoint_runtime();
    let last_good_config = state.config.load_full();

    let permissive_slice = dtls_slice(
        services.clone(),
        workloads.clone(),
        vec![namespace_peer_auth(MtlsMode::Permissive, HashMap::new())],
    );
    let permissive =
        build_node_waypoint_dtls_owner_configs(&state, &runtime, &permissive_slice, &config)
            .expect("PERMISSIVE does not require a client CA");
    let listener = listener_key("coap", PERMISSIVE_PORT);
    assert_eq!(
        permissive.keys().cloned().collect::<Vec<_>>(),
        vec![listener.clone()]
    );
    assert!(
        permissive[&listener].client_cert_verifier.is_none(),
        "PERMISSIVE must not install a client-certificate verifier"
    );

    let (generation, swapped) = state
        .stream_listener_manager
        .publish_mesh_node_waypoint_dtls_generation(permissive)
        .await;
    assert_eq!(generation, 1);
    assert_eq!(swapped, 0, "no generated listener is bound in this test");
    let accepted = state
        .stream_listener_manager
        .snapshot_mesh_node_waypoint_dtls_generation()
        .expect("Permissive generation published");
    assert_eq!(accepted.covered_listener_keys(), vec![listener.clone()]);

    let strict_slice = dtls_slice(
        services,
        workloads,
        vec![namespace_peer_auth(MtlsMode::Strict, HashMap::new())],
    );
    let error = build_node_waypoint_dtls_owner_configs(&state, &runtime, &strict_slice, &config)
        .err()
        .expect("STRICT without a client CA must reject before config apply");
    assert!(
        error.contains("STRICT") && error.contains("FERRUM_DTLS_CLIENT_CA_CERT_PATH"),
        "diagnostic must name STRICT and the missing client CA: {error}"
    );

    state
        .stream_listener_manager
        .record_mesh_node_waypoint_dtls_candidate_failure();

    let retained = state
        .stream_listener_manager
        .snapshot_mesh_node_waypoint_dtls_generation()
        .expect("last-good generation retained");
    assert!(
        Arc::ptr_eq(&accepted, &retained),
        "a rejected STRICT candidate must not replace the last-good generation"
    );
    assert_eq!(retained.covered_listener_keys(), vec![listener]);
    let status = state
        .stream_listener_manager
        .mesh_node_waypoint_dtls_reload_status();
    assert_eq!(status.last_outcome, "rejected");
    assert_eq!(status.generation, generation);
    assert!(status.last_failure_unix.is_some());
    assert!(
        Arc::ptr_eq(&last_good_config, &state.config.load_full()),
        "rejection must happen before update_mesh_config so last-good routing is retained"
    );
    assert!(
        state
            .stream_listener_manager
            .snapshot_frontend_dtls_generation()
            .is_none(),
        "owner-scoped reject/publish must never seed the ordinary FERRUM_DTLS_* slot"
    );
}

/// Strict with a configured client CA remains a valid required candidate and
/// installs a client-certificate verifier. This is the servable counterpart of
/// the reject path above, not an omit-and-apply shortcut.
#[tokio::test]
async fn strict_dtls_with_client_ca_builds_a_verifier() {
    ensure_crypto_provider();
    let identity = write_dtls_identity();
    let backend = workload_for(
        "coap",
        DEFAULT_NAMESPACE,
        [("app", "coap")],
        ["10.244.3.12"],
    );
    let slice = dtls_slice(
        vec![dtls_service("coap", STRICT_PORT, &backend)],
        vec![backend],
        vec![namespace_peer_auth(MtlsMode::Strict, HashMap::new())],
    );
    let config = GatewayConfig {
        proxies: vec![generated_dtls_proxy("coap", STRICT_PORT)],
        ..GatewayConfig::default()
    };
    let ca_path = identity.cert_path.clone();
    let state = test_proxy_state(dtls_env(&identity, Some(&ca_path)), config.clone());
    let runtime = node_waypoint_runtime();

    let built = build_node_waypoint_dtls_owner_configs(&state, &runtime, &slice, &config)
        .expect("STRICT with a client CA must be a valid required candidate");
    let listener = listener_key("coap", STRICT_PORT);
    assert_eq!(
        built.keys().cloned().collect::<Vec<_>>(),
        vec![listener.clone()]
    );
    assert!(
        built[&listener].client_cert_verifier.is_some(),
        "STRICT must require and verify a client certificate"
    );
}
