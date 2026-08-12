//! External integration coverage for Sidecar ingress dedicated `bind`
//! ownership (issue #3266): prepare materializes conflict-checked listen_port
//! proxies and bind overrides, and withdraws them on reload.

use std::collections::HashMap;

use ferrum_edge::config::types::GatewayConfig;
use ferrum_edge::identity::spiffe::{SpiffeId, TrustDomain};
use ferrum_edge::modes::mesh::config::{
    AppProtocol, MeshConfig, MeshService, MeshSidecar, MeshSidecarIngress, ServicePort, Workload,
    WorkloadPort, WorkloadRef, WorkloadSelector,
};
use ferrum_edge::modes::mesh::{MeshTopology, prepare_gateway_config_for_mesh};

use super::mesh_test_support::default_mesh_runtime;

fn local_echo(spiffe: &str, app_port: u16) -> (Workload, MeshService) {
    let id = SpiffeId::new(spiffe).expect("spiffe");
    let trust = TrustDomain::new("cluster.local").expect("td");
    let workload = Workload {
        spiffe_id: id.clone(),
        selector: WorkloadSelector {
            labels: HashMap::from([("app".to_string(), "echo".to_string())]),
            namespace: Some("default".to_string()),
        },
        service_name: "echo".to_string(),
        service_namespace: None,
        addresses: vec!["127.0.0.1".to_string()],
        ports: vec![WorkloadPort {
            port: app_port,
            protocol: AppProtocol::Tcp,
            name: Some("tcp".to_string()),
        }],
        trust_domain: trust,
        namespace: "default".to_string(),
        network: None,
        cluster: None,
        weight: None,
        locality: None,
        service_account: Some("echo".to_string()),
        pod_uid: None,
        node_waypoint: None,
        remote_provenance: false,
    };
    let service = MeshService {
        cluster_ips: Vec::new(),
        name: "echo".to_string(),
        namespace: "default".to_string(),
        ports: vec![ServicePort {
            port: app_port,
            protocol: AppProtocol::Tcp,
            name: Some("tcp".to_string()),
            target_port: None,
        }],
        workloads: vec![WorkloadRef { spiffe_id: id }],
        protocol_overrides: HashMap::new(),
        uid: None,
    };
    (workload, service)
}

fn prepare_with_bind(bind: Option<&str>, listener_port: u16, endpoint_port: u16) -> GatewayConfig {
    let spiffe = "spiffe://cluster.local/ns/default/sa/echo";
    let (workload, service) = local_echo(spiffe, endpoint_port);
    let mut runtime = default_mesh_runtime();
    runtime.workload_spiffe_id = Some(spiffe.to_string());
    runtime.sidecar_enforced = true;
    runtime.topology = MeshTopology::Sidecar;
    runtime.inbound_listen_addr = "127.0.0.1:0".parse().expect("addr");
    runtime.outbound_listen_addr = "127.0.0.1:0".parse().expect("addr");

    let config = GatewayConfig {
        mesh: Some(Box::new(MeshConfig {
            workloads: vec![workload],
            services: vec![service],
            sidecars: vec![MeshSidecar {
                name: "echo-ingress".to_string(),
                namespace: "default".to_string(),
                workload_selector: None,
                egress_inherits_defaults: true,
                egress: Vec::new(),
                outbound_traffic_policy: None,
                ingress_declared: true,
                ingress: vec![MeshSidecarIngress {
                    port: listener_port,
                    protocol: AppProtocol::Tcp,
                    name: None,
                    bind: bind.map(str::to_string),
                    default_endpoint: format!("127.0.0.1:{endpoint_port}"),
                }],
            }],
            ..MeshConfig::default()
        })),
        ..GatewayConfig::default()
    };
    prepare_gateway_config_for_mesh(config, &runtime).expect("prepare")
}

#[test]
fn dedicated_loopback_bind_materializes_stream_ownership() {
    let prepared = prepare_with_bind(Some("127.0.0.1"), 16379, 6379);
    let mesh = prepared.mesh.as_deref().expect("mesh");
    assert_eq!(
        mesh.sidecar_ingress_bind_override(16379),
        Some("127.0.0.1".parse().expect("ip"))
    );
    let bind_proxy = prepared
        .proxies
        .iter()
        .find(|p| p.id.starts_with("__mesh-ingress-bind-"))
        .expect("dedicated bind proxy");
    assert_eq!(bind_proxy.listen_port, Some(16379));
    assert_eq!(bind_proxy.backend_port, 6379);
    assert!(bind_proxy.dispatch_kind.is_stream());
    assert_eq!(mesh.local_inbound_tcp_routes.len(), 1);
}

#[test]
fn omitted_bind_keeps_shared_capture_only() {
    let prepared = prepare_with_bind(None, 16379, 6379);
    let mesh = prepared.mesh.as_deref().expect("mesh");
    assert!(mesh.sidecar_ingress_bind_overrides.is_empty());
    assert!(
        !prepared
            .proxies
            .iter()
            .any(|p| p.id.starts_with("__mesh-ingress-bind-"))
    );
    assert_eq!(mesh.local_inbound_tcp_routes.len(), 1);
}

#[test]
fn dedicated_bind_withdrawal_clears_ownership() {
    let with_bind = prepare_with_bind(Some("127.0.0.1"), 16379, 6379);
    assert!(
        with_bind
            .proxies
            .iter()
            .any(|p| p.id.starts_with("__mesh-ingress-bind-"))
    );
    let withdrawn = prepare_with_bind(None, 16379, 6379);
    assert!(
        !withdrawn
            .proxies
            .iter()
            .any(|p| p.id.starts_with("__mesh-ingress-bind-"))
    );
    assert!(
        withdrawn
            .mesh
            .as_deref()
            .expect("mesh")
            .sidecar_ingress_bind_overrides
            .is_empty()
    );
}

#[test]
fn unrepresentable_bind_fails_closed_at_prepare() {
    // A non-loopback bind never resolves into local_ingress_listeners, so the
    // declared ingress block fails closed (no capture routes, no bind proxy).
    let prepared = prepare_with_bind(Some("10.0.0.5"), 16379, 6379);
    let mesh = prepared.mesh.as_deref().expect("mesh");
    assert!(mesh.sidecar_ingress_bind_overrides.is_empty());
    assert!(mesh.local_inbound_tcp_routes.is_empty());
    assert!(
        !prepared
            .proxies
            .iter()
            .any(|p| p.id.starts_with("__mesh-ingress-"))
    );
}
