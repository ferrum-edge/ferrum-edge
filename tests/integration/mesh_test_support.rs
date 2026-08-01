//! Shared mesh-mode test fixtures.
//!
//! Mesh integration tests repeat the same `MeshRuntimeConfig` boilerplate,
//! the same `ProxyState::new(... OperatingMode::Mesh ...)` setup, and the
//! same listener spawn pattern. This module centralises those so individual
//! test files focus on the scenario they care about — workloads, services,
//! policies, request shape, expected outcome — instead of the 40-line
//! runtime literal that each rebuilds from scratch.
//!
//! The helpers deliberately stay close to the existing call sites
//! (`mesh_hbone_tests.rs`, `mesh_destination_rule_*`,
//! `mesh_destination_rule_locality_lb_tests.rs`): same field defaults, same
//! `127.0.0.1:0` listener addresses, same `OperatingMode::Mesh`. Migrating a
//! test from local helpers to this module should be a mechanical swap.
#![allow(dead_code)]

use std::collections::{BTreeMap, HashMap};
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use chrono::Utc;
use ferrum_edge::capture::CaptureMode;
use ferrum_edge::config::types::{
    AuthMode, BackendScheme, DispatchKind, GatewayConfig, LoadBalancerAlgorithm, MAX_TARGET_WEIGHT,
    Proxy, Upstream, UpstreamTarget,
};
use ferrum_edge::config::{EnvConfig, OperatingMode};
use ferrum_edge::dns::{DnsCache, DnsConfig};
use ferrum_edge::identity::spiffe::{SpiffeId, TrustDomain};
use ferrum_edge::modes::mesh::config::{
    AppProtocol, MeshConfig, MeshPolicy, MeshRule, MeshService, OutboundTrafficPolicy,
    PolicyAction, PolicyScope, PrincipalMatch, RequestMatch, ServicePort, Workload, WorkloadPort,
    WorkloadRef, WorkloadSelector,
};
use ferrum_edge::modes::mesh::slice::MeshSlice;
use ferrum_edge::modes::mesh::{
    MeshConfigProtocol, MeshRuntimeConfig, MeshTopology, prepare_gateway_config_for_mesh,
};
use ferrum_edge::proxy::{ProxyState, start_proxy_listener_with_bound_listener};
use tokio::net::TcpListener;
use tokio::sync::watch;

pub const DEFAULT_NAMESPACE: &str = "default";
pub const DEFAULT_TRUST_DOMAIN: &str = "cluster.local";

/// Build a [`MeshRuntimeConfig`] with the values mesh integration tests use
/// by default: `Sidecar` topology, `Native` MeshSubscribe protocol, ephemeral
/// listener addrs, no DNS proxy, no Sidecar egress narrowing.
///
/// Mutate fields before passing to other helpers when a test needs to flip
/// topology, opt into egress scoping, or stamp a workload SPIFFE identity.
pub fn default_mesh_runtime() -> MeshRuntimeConfig {
    MeshRuntimeConfig {
        node_id: "mesh-test-node".to_string(),
        namespace: DEFAULT_NAMESPACE.to_string(),
        cp_urls: vec!["http://127.0.0.1:1".to_string()],
        config_protocol: MeshConfigProtocol::Native,
        file_config_path: None,
        topology: MeshTopology::Sidecar,
        inbound_listen_addr: "127.0.0.1:0".parse().expect("addr"),
        outbound_listen_addr: "127.0.0.1:0".parse().expect("addr"),
        hbone_listen_addr: "127.0.0.1:0".parse().expect("addr"),
        east_west_listen_port: 15443,
        egress_hbone_port: 15008,
        egress_mtls_port: 15006,
        egress_listen_addr: "127.0.0.1:0".parse().expect("addr"),
        workload_spiffe_id: None,
        waypoint_name: None,
        workload_svid_cert_path: None,
        workload_svid_key_path: None,
        workload_svid_trust_bundle_path: None,
        ca_backend: ferrum_edge::identity::ca::CaBackend::None,
        xds_node_cluster: DEFAULT_NAMESPACE.to_string(),
        xds_stream_channel_capacity: 32,
        xds_primary_retry_secs: 300,
        xds_connect_timeout_seconds: 10,
        trust_domain_aliases: Vec::new(),
        trusted_hbone_assertors: Vec::new(),
        workload_labels: HashMap::new(),
        dns_enabled: false,
        dns_listen_addr: "127.0.0.1:15053".parse().expect("addr"),
        dns_upstream_addr: "127.0.0.53:53".parse().expect("addr"),
        dns_ttl_seconds: 60,
        dns_max_concurrent_queries: 1024,
        dns_response_cache_max_entries: 4096,
        cluster_domain: DEFAULT_TRUST_DOMAIN.to_string(),
        capture_mode: CaptureMode::Explicit,
        outbound_traffic_policy: OutboundTrafficPolicy::AllowAny,
        outbound_registry_reject_status: 502,
        sidecar_enforced: false,
        sidecar_enforced_dry_run: false,
        sidecar_identity_narrowing: false,
        egress_stream_enabled: false,
        egress_stream_allow_plaintext: false,
        request_auth_require_exp: true,
        locality_lb_strict: false,
    }
}

/// Returns [`default_mesh_runtime`] reshaped for `topology`. Callers that need
/// additional knobs should mutate the returned value before use.
pub fn runtime_for_topology(topology: MeshTopology) -> MeshRuntimeConfig {
    MeshRuntimeConfig {
        topology,
        ..default_mesh_runtime()
    }
}

/// Build a minimal `Workload` for the default trust domain. The `service_account`
/// is `default` so the SPIFFE ID encodes a realistic Istio path.
pub fn workload_for(
    name: &str,
    namespace: &str,
    labels: impl IntoIterator<Item = (&'static str, &'static str)>,
    addresses: impl IntoIterator<Item = &'static str>,
) -> Workload {
    let service_account = name.to_string();
    let spiffe = format!("spiffe://{DEFAULT_TRUST_DOMAIN}/ns/{namespace}/sa/{service_account}");
    Workload {
        spiffe_id: SpiffeId::new(spiffe).expect("valid SPIFFE ID"),
        selector: WorkloadSelector {
            labels: labels
                .into_iter()
                .map(|(k, v)| (k.to_string(), v.to_string()))
                .collect(),
            namespace: Some(namespace.to_string()),
        },
        service_name: name.to_string(),
        addresses: addresses.into_iter().map(|s| s.to_string()).collect(),
        ports: vec![WorkloadPort {
            port: 8080,
            protocol: AppProtocol::Http,
            name: Some("http".to_string()),
        }],
        trust_domain: TrustDomain::new(DEFAULT_TRUST_DOMAIN).expect("trust domain"),
        namespace: namespace.to_string(),
        network: None,
        cluster: None,
        weight: None,
        locality: None,
        service_account: Some(service_account),
        pod_uid: None,
        node_waypoint: None,
        remote_provenance: false,
    }
}

/// Build a [`MeshService`] with a single 8080/HTTP port, referencing the given
/// workloads by SPIFFE ID.
pub fn service_for(name: &str, namespace: &str, workloads: &[&Workload]) -> MeshService {
    MeshService {
        cluster_ips: Vec::new(),
        name: name.to_string(),
        namespace: namespace.to_string(),
        ports: vec![ServicePort {
            port: 8080,
            protocol: AppProtocol::Http,
            name: Some("http".to_string()),
            target_port: None,
        }],
        workloads: workloads
            .iter()
            .map(|w| WorkloadRef {
                spiffe_id: w.spiffe_id.clone(),
            })
            .collect(),
        protocol_overrides: HashMap::new(),
    }
}

/// Build a `MeshPolicy` ALLOW rule that admits a specific SPIFFE ID glob.
/// Use [`policy_deny_principal`] for the DENY-first counterpart.
pub fn policy_allow_principal(
    name: &str,
    namespace: &str,
    scope: PolicyScope,
    principal_glob: &str,
) -> MeshPolicy {
    MeshPolicy {
        name: name.to_string(),
        namespace: namespace.to_string(),
        scope,
        rules: vec![MeshRule {
            from: vec![PrincipalMatch {
                spiffe_id_pattern: Some(principal_glob.to_string()),
                namespace_pattern: None,
                trust_domain: Some(TrustDomain::new(DEFAULT_TRUST_DOMAIN).expect("trust domain")),
                trust_domain_pattern: None,
            }],
            to: Vec::new(),
            when: Vec::new(),
            request_principals: Vec::new(),
            not_request_principals: Vec::new(),
            source_negation: Default::default(),
            never_matches: false,
            action: PolicyAction::Allow,
        }],
    }
}

/// Build a `MeshPolicy` DENY rule that blocks a specific SPIFFE ID glob.
pub fn policy_deny_principal(
    name: &str,
    namespace: &str,
    scope: PolicyScope,
    principal_glob: &str,
) -> MeshPolicy {
    MeshPolicy {
        name: name.to_string(),
        namespace: namespace.to_string(),
        scope,
        rules: vec![MeshRule {
            from: vec![PrincipalMatch {
                spiffe_id_pattern: Some(principal_glob.to_string()),
                namespace_pattern: None,
                trust_domain: Some(TrustDomain::new(DEFAULT_TRUST_DOMAIN).expect("trust domain")),
                trust_domain_pattern: None,
            }],
            to: Vec::new(),
            when: Vec::new(),
            request_principals: Vec::new(),
            not_request_principals: Vec::new(),
            source_negation: Default::default(),
            never_matches: false,
            action: PolicyAction::Deny,
        }],
    }
}

/// Build an AUDIT-only `MeshPolicy` for a specific SPIFFE ID glob. AUDIT is
/// non-enforcing per Istio semantics (records metadata and continues), so it is
/// used to assert the construction-time fail-closed scope guards EXEMPT
/// audit-only selector policies.
pub fn policy_audit_principal(
    name: &str,
    namespace: &str,
    scope: PolicyScope,
    principal_glob: &str,
) -> MeshPolicy {
    MeshPolicy {
        name: name.to_string(),
        namespace: namespace.to_string(),
        scope,
        rules: vec![MeshRule {
            from: vec![PrincipalMatch {
                spiffe_id_pattern: Some(principal_glob.to_string()),
                namespace_pattern: None,
                trust_domain: Some(TrustDomain::new(DEFAULT_TRUST_DOMAIN).expect("trust domain")),
                trust_domain_pattern: None,
            }],
            to: Vec::new(),
            when: Vec::new(),
            request_principals: Vec::new(),
            not_request_principals: Vec::new(),
            source_negation: Default::default(),
            never_matches: false,
            action: PolicyAction::Audit,
        }],
    }
}

/// Build an ALLOW policy that also constrains the request path/method.
pub fn policy_allow_request(
    name: &str,
    namespace: &str,
    scope: PolicyScope,
    principal_glob: &str,
    request: RequestMatch,
) -> MeshPolicy {
    MeshPolicy {
        name: name.to_string(),
        namespace: namespace.to_string(),
        scope,
        rules: vec![MeshRule {
            from: vec![PrincipalMatch {
                spiffe_id_pattern: Some(principal_glob.to_string()),
                namespace_pattern: None,
                trust_domain: Some(TrustDomain::new(DEFAULT_TRUST_DOMAIN).expect("trust domain")),
                trust_domain_pattern: None,
            }],
            to: vec![request],
            when: Vec::new(),
            request_principals: Vec::new(),
            not_request_principals: Vec::new(),
            source_negation: Default::default(),
            never_matches: false,
            action: PolicyAction::Allow,
        }],
    }
}

/// Convenience: [`MeshSlice`] populated from `runtime` + the supplied
/// resources. The slice's `version` field stamps the current time so two
/// slices built in the same test never compare equal by accident.
pub fn mesh_slice_with(
    runtime: &MeshRuntimeConfig,
    workloads: Vec<Workload>,
    services: Vec<MeshService>,
    mesh_policies: Vec<MeshPolicy>,
) -> MeshSlice {
    MeshSlice {
        node_id: runtime.node_id.clone(),
        namespace: runtime.namespace.clone(),
        workload_spiffe_id: runtime.workload_spiffe_id.clone(),
        waypoint_name: runtime.waypoint_name.clone(),
        labels: runtime
            .workload_labels
            .iter()
            .map(|(k, v)| (k.clone(), v.clone()))
            .collect::<BTreeMap<_, _>>(),
        version: Utc::now().to_rfc3339(),
        workloads,
        services,
        mesh_policies,
        ..MeshSlice::default()
    }
}

/// Build a Ferrum [`Proxy`] aimed at `127.0.0.1:backend_port` over plain HTTP.
/// `host` is matched as a single-element `hosts` entry — this mirrors the way
/// mesh outbound capture proxies route by Host header / SNI.
pub fn http_proxy(id: &str, host: &str, backend_port: u16) -> Proxy {
    let now = Utc::now();
    Proxy {
        id: id.to_string(),
        namespace: ferrum_edge::config::types::default_namespace(),
        name: Some(id.to_string()),
        api_spec_id: None,
        hosts: vec![host.to_string()],
        listen_path: Some("/".to_string()),
        backend_scheme: Some(BackendScheme::Http),
        dispatch_kind: DispatchKind::from(BackendScheme::Http),
        backend_host: "127.0.0.1".to_string(),
        backend_port,
        backend_path: None,
        strip_listen_path: true,
        preserve_host_header: false,
        backend_connect_timeout_ms: 5000,
        backend_read_timeout_ms: 30000,
        backend_write_timeout_ms: 30000,
        backend_tls_client_cert_path: None,
        backend_tls_client_key_path: None,
        backend_tls_verify_server_cert: true,
        backend_tls_server_ca_cert_path: None,
        resolved_tls: Default::default(),
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
        circuit_breaker: None,
        retry: None,
        response_body_mode: Default::default(),
        listen_port: None,
        frontend_tls: false,
        passthrough: false,
        udp_idle_timeout_seconds: 60,
        udp_max_response_amplification_factor: None,
        stream_proxy_protocol: None,
        tcp_idle_timeout_seconds: Some(300),
        websocket_idle_timeout_seconds: None,
        allowed_methods: None,
        allowed_ws_origins: vec![],
        created_at: now,
        updated_at: now,
    }
}

/// Build a mesh-mode [`Upstream`] with a single HTTP target.
pub fn http_upstream(id: &str, host: &str, port: u16) -> Upstream {
    let now = Utc::now();
    Upstream {
        id: id.to_string(),
        namespace: ferrum_edge::config::types::default_namespace(),
        name: Some(id.to_string()),
        targets: vec![UpstreamTarget {
            host: host.to_string(),
            port,
            service_port_policy_key: None,
            weight: MAX_TARGET_WEIGHT.min(1),
            tags: HashMap::new(),
            locality: None,
            path: None,
        }],
        algorithm: LoadBalancerAlgorithm::RoundRobin,
        hash_on: None,
        hash_on_cookie_config: None,
        health_checks: None,
        service_discovery: None,
        subsets: None,
        port_overrides: HashMap::new(),
        source_locality: None,
        locality_lb_strict: false,
        locality_lb_setting: None,
        backend_tls_client_cert_path: None,
        backend_tls_client_key_path: None,
        backend_tls_verify_server_cert: true,
        backend_tls_server_ca_cert_path: None,
        backend_tls_sni: None,
        backend_tls_san_allow_list: Vec::new(),
        resolved_subset_tls: HashMap::new(),
        dispatch_port_override_fallback: None,
        api_spec_id: None,
        created_at: now,
        updated_at: now,
    }
}

/// Build an empty `GatewayConfig` with `mesh: Some(MeshConfig{...})` and the
/// supplied proxies/upstreams/policies attached. Callers feed the result to
/// [`prepare_gateway_config_for_mesh`] before constructing `ProxyState`.
pub fn gateway_config_with_mesh(
    proxies: Vec<Proxy>,
    upstreams: Vec<Upstream>,
    mesh: MeshConfig,
) -> GatewayConfig {
    GatewayConfig {
        version: "test".to_string(),
        proxies,
        upstreams,
        consumers: Vec::new(),
        plugin_configs: Vec::new(),
        loaded_at: Utc::now(),
        known_namespaces: Vec::new(),
        frontend_tls_cert_path: None,
        frontend_tls_key_path: None,
        frontend_tls_source_namespace: None,
        frontend_tls_namespace_sources: Vec::new(),
        trust_bundles: None,
        mesh: Some(Box::new(mesh)),
        mesh_revision: None,
        k8s_mesh_overlay: Default::default(),
    }
}

/// Build a [`MeshConfig`] from the supplied resources. Inherits the canonical
/// `istio-system` default for `istio_root_namespace` via `MeshConfig::default`.
pub fn mesh_config_with(
    workloads: Vec<Workload>,
    services: Vec<MeshService>,
    mesh_policies: Vec<MeshPolicy>,
) -> MeshConfig {
    MeshConfig {
        workloads,
        services,
        mesh_policies,
        ..MeshConfig::default()
    }
}

/// Prepare a mesh-mode `ProxyState` for `proxies` and `upstreams`, with the
/// supplied `MeshConfig`. Runs the full `prepare_gateway_config_for_mesh`
/// pipeline so plugin injection, locality projection, and DR materialisation
/// all match production. The returned tuple shares the same shape as
/// [`ProxyState::new`] so callers can also keep the health-check task
/// handles if they ever want to.
pub fn build_mesh_proxy_state(
    runtime: &MeshRuntimeConfig,
    proxies: Vec<Proxy>,
    upstreams: Vec<Upstream>,
    mesh: MeshConfig,
) -> ProxyState {
    let config = gateway_config_with_mesh(proxies, upstreams, mesh);
    let prepared = prepare_gateway_config_for_mesh(config, runtime).expect("mesh-prepared config");
    let env_config = EnvConfig {
        mode: OperatingMode::Mesh,
        log_level: "error".to_string(),
        proxy_http_port: 0,
        proxy_https_port: 0,
        admin_http_port: 0,
        admin_https_port: 0,
        shutdown_drain_seconds: 0,
        max_connections: 0,
        namespace: runtime.namespace.clone(),
        ..EnvConfig::default()
    };
    ProxyState::new(
        prepared,
        DnsCache::new(DnsConfig::default()),
        env_config,
        None,
        None,
    )
    .expect("mesh proxy state")
    .0
}

/// Spawn an HTTP proxy listener for the given `ProxyState`. Returns the bound
/// address and a shutdown sender. Drops both to tear down the gateway.
pub async fn start_mesh_gateway(state: ProxyState) -> (SocketAddr, watch::Sender<bool>) {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind mesh gateway");
    let addr = listener.local_addr().expect("gateway local addr");
    let (shutdown_tx, shutdown_rx) = watch::channel(false);
    tokio::spawn(async move {
        let _ = start_proxy_listener_with_bound_listener(listener, state, shutdown_rx, None).await;
    });
    // Give the accept loop a beat to install before tests start sending.
    tokio::time::sleep(Duration::from_millis(50)).await;
    (addr, shutdown_tx)
}

/// Function the scripted backend invokes per request. Returns the response
/// body bytes to write back to the client. Factored into a type alias because
/// the bare `Arc<dyn Fn ...>` shape tripped clippy's `type_complexity` lint.
pub type BackendResponder = Arc<dyn Fn(&str) -> Vec<u8> + Send + Sync>;

/// Captured-request log shared between a [`BackendResponder`] and the test.
pub type BackendCaptureLog = Arc<std::sync::Mutex<Vec<String>>>;

/// Spawn a bare-bones HTTP/1.1 backend that responds `200 OK` with the request
/// body echoed back. Returns the bound address and the join handle so callers
/// can await graceful drain.
///
/// `responder` lets tests substitute custom logic (e.g. inspect headers,
/// return a specific status). The default [`echo_backend_handler`] echoes
/// `"backend-ok\n"` regardless of input.
pub async fn start_http_backend(
    responder: BackendResponder,
) -> (SocketAddr, tokio::task::JoinHandle<()>) {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind http backend");
    let addr = listener.local_addr().expect("backend addr");
    let handle = tokio::spawn(async move {
        loop {
            let (mut stream, _peer) = match listener.accept().await {
                Ok(conn) => conn,
                Err(_) => return,
            };
            let responder = responder.clone();
            tokio::spawn(async move {
                let mut buf = [0u8; 4096];
                let n = match stream.read(&mut buf).await {
                    Ok(0) | Err(_) => return,
                    Ok(n) => n,
                };
                let request = String::from_utf8_lossy(&buf[..n]).into_owned();
                let body = responder(&request);
                let response = format!(
                    "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                    body.len()
                );
                let _ = stream.write_all(response.as_bytes()).await;
                let _ = stream.write_all(&body).await;
                let _ = stream.shutdown().await;
            });
        }
    });
    (addr, handle)
}

/// Default HTTP backend responder: returns `backend-ok\n` regardless of input.
pub fn echo_backend_handler() -> BackendResponder {
    Arc::new(|_request: &str| b"backend-ok\n".to_vec())
}

/// HTTP backend responder that captures every received request line for later
/// inspection. Returns a tuple of `(responder, captured_log)` where
/// `captured_log` is appended to on each request.
pub fn capturing_backend_handler() -> (BackendResponder, BackendCaptureLog) {
    let log: BackendCaptureLog = Arc::new(std::sync::Mutex::new(Vec::new()));
    let log_cloned = log.clone();
    let responder: BackendResponder = Arc::new(move |request: &str| {
        if let Ok(mut guard) = log_cloned.lock() {
            guard.push(request.to_string());
        }
        b"backend-ok\n".to_vec()
    });
    (responder, log)
}
