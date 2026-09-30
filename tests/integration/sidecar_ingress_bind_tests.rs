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

const BIND_ROUTE_PREFIX: &str = "__mesh-ingress-bind:";

fn local_echo(
    namespace: &str,
    service_name: &str,
    spiffe: &str,
    app_port: u16,
    protocol: AppProtocol,
) -> (Workload, MeshService) {
    let id = SpiffeId::new(spiffe).expect("spiffe");
    let trust = TrustDomain::new("cluster.local").expect("td");
    let port_name = match protocol {
        AppProtocol::Http => "http",
        _ => "tcp",
    };
    let workload = Workload {
        spiffe_id: id.clone(),
        selector: WorkloadSelector {
            labels: HashMap::from([("app".to_string(), service_name.to_string())]),
            namespace: Some(namespace.to_string()),
        },
        service_name: service_name.to_string(),
        service_namespace: None,
        addresses: vec!["127.0.0.1".to_string()],
        ports: vec![WorkloadPort {
            port: app_port,
            protocol,
            name: Some(port_name.to_string()),
        }],
        trust_domain: trust,
        namespace: namespace.to_string(),
        network: None,
        cluster: None,
        weight: None,
        locality: None,
        service_account: Some(service_name.to_string()),
        pod_uid: None,
        node_waypoint: None,
        remote_provenance: false,
    };
    let service = MeshService {
        cluster_ips: Vec::new(),
        name: service_name.to_string(),
        namespace: namespace.to_string(),
        ports: vec![ServicePort {
            port: app_port,
            protocol,
            name: Some(port_name.to_string()),
            target_port: None,
        }],
        workloads: vec![WorkloadRef { spiffe_id: id }],
        protocol_overrides: HashMap::new(),
        uid: None,
        allow_path_parameters: false,
    };
    (workload, service)
}

fn prepare_sidecar(
    namespace: &str,
    service_name: &str,
    protocol: AppProtocol,
    bind: Option<&str>,
    listener_port: u16,
    endpoint_port: u16,
) -> GatewayConfig {
    let spiffe = format!("spiffe://cluster.local/ns/{namespace}/sa/{service_name}");
    let (workload, service) = local_echo(namespace, service_name, &spiffe, endpoint_port, protocol);
    let mut runtime = default_mesh_runtime();
    runtime.namespace = namespace.to_string();
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
                name: format!("{service_name}-ingress"),
                namespace: namespace.to_string(),
                workload_selector: None,
                egress_inherits_defaults: true,
                egress: Vec::new(),
                outbound_traffic_policy: None,
                ingress_declared: true,
                ingress: vec![MeshSidecarIngress {
                    port: listener_port,
                    protocol,
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

fn prepare_in_namespace(
    namespace: &str,
    bind: Option<&str>,
    listener_port: u16,
    endpoint_port: u16,
) -> GatewayConfig {
    prepare_sidecar(
        namespace,
        "echo",
        AppProtocol::Tcp,
        bind,
        listener_port,
        endpoint_port,
    )
}

fn prepare_with_bind(bind: Option<&str>, listener_port: u16, endpoint_port: u16) -> GatewayConfig {
    prepare_in_namespace("default", bind, listener_port, endpoint_port)
}

fn dedicated_bind_ids(config: &GatewayConfig) -> Vec<&str> {
    config
        .proxies
        .iter()
        .filter(|proxy| proxy.id.starts_with(BIND_ROUTE_PREFIX))
        .map(|proxy| proxy.id.as_str())
        .collect()
}

#[test]
fn dedicated_loopback_bind_materializes_stream_ownership() {
    let prepared = prepare_with_bind(Some("127.0.0.1"), 16379, 6379);
    let mesh = prepared.mesh.as_deref().expect("mesh");
    assert_eq!(
        mesh.sidecar_ingress_bind_override(16379),
        Some("127.0.0.1".parse().expect("ip"))
    );
    let bind_ids = dedicated_bind_ids(&prepared);
    assert_eq!(bind_ids, vec!["__mesh-ingress-bind:default-echo-16379"]);
    let bind_proxy = prepared
        .proxies
        .iter()
        .find(|p| p.id == bind_ids[0])
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
    assert!(dedicated_bind_ids(&prepared).is_empty());
    assert_eq!(mesh.local_inbound_tcp_routes.len(), 1);
}

#[test]
fn bind_prefixed_namespace_http_shared_capture_is_not_a_bind_route() {
    // Stream-family shared capture does not emit an HTTP `__mesh-ingress-*`
    // proxy, so the prefix collision is an HTTP-family classifier bug: namespace
    // `bind-prod` used to produce `__mesh-ingress-bind-prod-echo-16379`, which
    // matched the old `__mesh-ingress-bind-` hyphen prefix.
    let prepared = prepare_sidecar("bind-prod", "echo", AppProtocol::Http, None, 16379, 6379);
    let ingress_proxy = prepared
        .proxies
        .iter()
        .find(|proxy| proxy.id == "__mesh-ingress-bind-prod-echo-16379")
        .expect("shared ingress proxy");

    assert_eq!(ingress_proxy.listen_port, None);
    assert!(
        !ingress_proxy.id.starts_with(BIND_ROUTE_PREFIX),
        "shared-capture id must stay outside the dedicated-bind family"
    );
    assert!(dedicated_bind_ids(&prepared).is_empty());
}

#[test]
fn hyphenated_namespace_dedicated_bind_id_is_injective() {
    let prepared = prepare_in_namespace("bind-prod", Some("127.0.0.1"), 16379, 6379);
    assert_eq!(
        dedicated_bind_ids(&prepared),
        vec!["__mesh-ingress-bind:bind_dash_prod-echo-16379"]
    );
}

#[test]
fn hyphenated_namespace_http_bind_and_capture_ids_stay_disjoint() {
    let prepared = prepare_sidecar(
        "bind-prod",
        "echo",
        AppProtocol::Http,
        Some("127.0.0.1"),
        16379,
        6379,
    );
    let capture = prepared
        .proxies
        .iter()
        .find(|proxy| proxy.id == "__mesh-ingress-bind-prod-echo-16379")
        .expect("shared capture sibling");
    assert_eq!(capture.listen_port, None);
    assert_eq!(
        dedicated_bind_ids(&prepared),
        vec!["__mesh-ingress-bind:bind_dash_prod-echo-16379"]
    );
}

#[test]
fn same_name_cross_namespace_dedicated_bind_ids_do_not_collide() {
    let payments = prepare_sidecar(
        "payments",
        "echo",
        AppProtocol::Tcp,
        Some("127.0.0.1"),
        16379,
        6379,
    );
    let checkout = prepare_sidecar(
        "checkout",
        "echo",
        AppProtocol::Tcp,
        Some("127.0.0.1"),
        16379,
        6379,
    );
    let payments_ids = dedicated_bind_ids(&payments);
    let checkout_ids = dedicated_bind_ids(&checkout);
    assert_eq!(
        payments_ids,
        vec!["__mesh-ingress-bind:payments-echo-16379"]
    );
    assert_eq!(
        checkout_ids,
        vec!["__mesh-ingress-bind:checkout-echo-16379"]
    );
    assert_ne!(payments_ids, checkout_ids);
}

#[test]
fn hyphen_join_delimiter_pairs_do_not_collide_bind_ids() {
    // `{ns}-{name}` is lossy: `a-b`/`c` and `a`/`b-c` join to the same string.
    // Bind ids encode `-` as `_dash_` so the two sidecars stay distinct.
    let ab_c = prepare_sidecar("a-b", "c", AppProtocol::Tcp, Some("127.0.0.1"), 16379, 6379);
    let a_bc = prepare_sidecar("a", "b-c", AppProtocol::Tcp, Some("127.0.0.1"), 16379, 6379);
    let ab_c_ids = dedicated_bind_ids(&ab_c);
    let a_bc_ids = dedicated_bind_ids(&a_bc);
    assert_eq!(ab_c_ids, vec!["__mesh-ingress-bind:a_dash_b-c-16379"]);
    assert_eq!(a_bc_ids, vec!["__mesh-ingress-bind:a-b_dash_c-16379"]);
    assert_ne!(ab_c_ids, a_bc_ids);
}

#[test]
fn dedicated_bind_withdrawal_clears_ownership() {
    let with_bind = prepare_with_bind(Some("127.0.0.1"), 16379, 6379);
    assert!(!dedicated_bind_ids(&with_bind).is_empty());
    let withdrawn = prepare_with_bind(None, 16379, 6379);
    assert!(dedicated_bind_ids(&withdrawn).is_empty());
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
