//! External integration coverage for Sidecar ingress dedicated `bind`
//! ownership (issue #3266): prepare materializes conflict-checked listen_port
//! proxies and bind overrides, and withdraws them on reload. Also covers the
//! proxy hop limit's build-time guard (issue #6109): an `ingress[]`
//! `defaultEndpoint` or an inbound `targetPort` that names a port the gateway
//! itself listens on is refused fail-closed.

use std::collections::HashMap;

use ferrum_edge::config::types::GatewayConfig;
use ferrum_edge::identity::spiffe::{SpiffeId, TrustDomain};
use ferrum_edge::modes::mesh::config::{
    AppProtocol, MeshConfig, MeshService, MeshSidecar, MeshSidecarIngress, ServicePort, Workload,
    WorkloadPort, WorkloadRef, WorkloadSelector,
};
use ferrum_edge::modes::mesh::{MeshRuntimeConfig, MeshTopology, prepare_gateway_config_for_mesh};

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
    prepare_sidecar_with_path_parameters(
        namespace,
        service_name,
        protocol,
        bind,
        listener_port,
        endpoint_port,
        false,
    )
}

/// [`prepare_sidecar`] with the owner service's `;` path-parameter opt-in
/// (`MeshService.allow_path_parameters`, issue #5937).
fn prepare_sidecar_with_path_parameters(
    namespace: &str,
    service_name: &str,
    protocol: AppProtocol,
    bind: Option<&str>,
    listener_port: u16,
    endpoint_port: u16,
    allow_path_parameters: bool,
) -> GatewayConfig {
    prepare_sidecar_ingress(
        namespace,
        service_name,
        protocol,
        endpoint_port,
        allow_path_parameters,
        vec![ingress_entry(protocol, bind, listener_port, endpoint_port)],
    )
}

fn ingress_entry(
    protocol: AppProtocol,
    bind: Option<&str>,
    listener_port: u16,
    endpoint_port: u16,
) -> MeshSidecarIngress {
    MeshSidecarIngress {
        port: listener_port,
        protocol,
        name: None,
        bind: bind.map(str::to_string),
        default_endpoint: format!("127.0.0.1:{endpoint_port}"),
    }
}

/// Prepare a Sidecar whose applicable `Sidecar` resource declares exactly
/// `ingress`. `app_port` is the owner service's and workload's declared port.
fn prepare_sidecar_ingress(
    namespace: &str,
    service_name: &str,
    protocol: AppProtocol,
    app_port: u16,
    allow_path_parameters: bool,
    ingress: Vec<MeshSidecarIngress>,
) -> GatewayConfig {
    let spiffe = format!("spiffe://cluster.local/ns/{namespace}/sa/{service_name}");
    let (workload, mut service) = local_echo(namespace, service_name, &spiffe, app_port, protocol);
    service.allow_path_parameters = allow_path_parameters;
    let runtime = sidecar_runtime(namespace, &spiffe);

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
                ingress,
            }],
            ..MeshConfig::default()
        })),
        ..GatewayConfig::default()
    };
    prepare_gateway_config_for_mesh(config, &runtime).expect("prepare")
}

fn sidecar_runtime(namespace: &str, spiffe: &str) -> MeshRuntimeConfig {
    let mut runtime = default_mesh_runtime();
    runtime.namespace = namespace.to_string();
    runtime.workload_spiffe_id = Some(spiffe.to_string());
    runtime.sidecar_enforced = true;
    runtime.topology = MeshTopology::Sidecar;
    runtime.inbound_listen_addr = "127.0.0.1:0".parse().expect("addr");
    runtime.outbound_listen_addr = "127.0.0.1:0".parse().expect("addr");
    runtime
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

#[test]
fn http_ingress_routes_carry_the_owner_service_path_parameter_opt_in() {
    // Sidecar `ingress[]` routes forward to the owner service's
    // `defaultEndpoint`, so they carry that service's opt-in: on the shared
    // capture route, and on both routes of a dedicated bind.
    const CAPTURE_ID: &str = "__mesh-ingress-default-echo-16379";
    const BIND_ID: &str = "__mesh-ingress-bind:default-echo-16379";
    for opt_in in [true, false] {
        let shared = prepare_sidecar_with_path_parameters(
            "default",
            "echo",
            AppProtocol::Http,
            None,
            16379,
            6379,
            opt_in,
        );
        let capture = shared
            .proxies
            .iter()
            .find(|proxy| proxy.id == CAPTURE_ID)
            .expect("shared capture ingress route");
        assert_eq!(capture.allow_path_parameters, opt_in);
        assert!(dedicated_bind_ids(&shared).is_empty());

        let dedicated = prepare_sidecar_with_path_parameters(
            "default",
            "echo",
            AppProtocol::Http,
            Some("127.0.0.1"),
            16379,
            6379,
            opt_in,
        );
        for id in [CAPTURE_ID, BIND_ID] {
            let route = dedicated
                .proxies
                .iter()
                .find(|proxy| proxy.id == id)
                .unwrap_or_else(|| panic!("{id} must be materialized"));
            assert_eq!(
                route.allow_path_parameters, opt_in,
                "{id} must carry the owner service's opt-in"
            );
        }
    }
}

/// Issue #6109: two dedicated binds whose `defaultEndpoint`s name each other
/// would bounce a request between two gateway listeners. Both are refused at
/// prepare, for the whole entry, exactly like a bind conflict.
#[test]
fn ingress_binds_pointing_at_each_other_are_refused() {
    let prepared = prepare_sidecar_ingress(
        "default",
        "echo",
        AppProtocol::Http,
        6379,
        false,
        vec![
            ingress_entry(AppProtocol::Http, Some("127.0.0.1"), 19001, 19002),
            ingress_entry(AppProtocol::Http, Some("127.0.0.1"), 19002, 19001),
        ],
    );
    let mesh = prepared.mesh.as_deref().expect("mesh");
    assert!(
        mesh.local_ingress_listeners.is_empty(),
        "neither looping entry may stay admitted"
    );
    assert!(mesh.sidecar_ingress_bind_overrides.is_empty());
    assert!(dedicated_bind_ids(&prepared).is_empty());
    assert!(
        !prepared
            .proxies
            .iter()
            .any(|p| p.id.starts_with("__mesh-ingress-")),
        "no capture or bind route may target another gateway listener"
    );
    assert!(
        mesh.sidecar_ingress_declared,
        "the declared ingress block still replaces the service-port defaults"
    );
}

/// Issue #6109: a dedicated bind whose `defaultEndpoint` is its own bind port
/// would forward every request straight back into itself.
#[test]
fn ingress_endpoint_on_its_own_bind_port_is_refused() {
    let prepared = prepare_sidecar_ingress(
        "default",
        "echo",
        AppProtocol::Tcp,
        6379,
        false,
        vec![ingress_entry(
            AppProtocol::Tcp,
            Some("127.0.0.1"),
            19003,
            19003,
        )],
    );
    let mesh = prepared.mesh.as_deref().expect("mesh");
    assert!(mesh.local_ingress_listeners.is_empty());
    assert!(mesh.sidecar_ingress_bind_overrides.is_empty());
    assert!(mesh.local_inbound_tcp_routes.is_empty());
    assert!(dedicated_bind_ids(&prepared).is_empty());
}

/// Issue #6109: a shared-capture entry whose `defaultEndpoint` names another
/// entry's dedicated bind is refused; the bind itself, which forwards to the
/// application, is still admitted.
#[test]
fn shared_capture_endpoint_on_another_bind_is_refused_and_the_bind_survives() {
    let prepared = prepare_sidecar_ingress(
        "default",
        "echo",
        AppProtocol::Http,
        6379,
        false,
        vec![
            ingress_entry(AppProtocol::Http, None, 18080, 19004),
            ingress_entry(AppProtocol::Http, Some("127.0.0.1"), 19004, 6379),
        ],
    );
    let mesh = prepared.mesh.as_deref().expect("mesh");
    let admitted: Vec<u16> = mesh
        .local_ingress_listeners
        .iter()
        .map(|listener| listener.port)
        .collect();
    assert_eq!(admitted, vec![19004]);
    assert_eq!(
        dedicated_bind_ids(&prepared),
        vec!["__mesh-ingress-bind:default-echo-19004"]
    );
    assert!(
        !prepared
            .proxies
            .iter()
            .any(|p| p.id == "__mesh-ingress-default-echo-18080"),
        "the entry targeting the bind listener must not materialize"
    );
}

/// Issue #6109: a default service-port inbound route whose resolved local
/// target is a mesh listener port (here the outbound capture listener) is
/// refused; an ordinary application port still materializes.
#[test]
fn inbound_target_port_on_a_gateway_listener_is_refused() {
    let spiffe = "spiffe://cluster.local/ns/default/sa/echo";
    let inbound_routes = |app_port: u16| {
        let (workload, service) =
            local_echo("default", "echo", spiffe, app_port, AppProtocol::Http);
        let mut runtime = sidecar_runtime("default", spiffe);
        runtime.outbound_listen_addr = "127.0.0.1:19010".parse().expect("addr");
        let config = GatewayConfig {
            mesh: Some(Box::new(MeshConfig {
                workloads: vec![workload],
                services: vec![service],
                ..MeshConfig::default()
            })),
            ..GatewayConfig::default()
        };
        let prepared = prepare_gateway_config_for_mesh(config, &runtime).expect("prepare");
        prepared
            .proxies
            .iter()
            .filter(|proxy| proxy.id.starts_with("__mesh-inbound-"))
            .map(|proxy| proxy.backend_port)
            .collect::<Vec<u16>>()
    };
    assert_eq!(
        inbound_routes(19010),
        Vec::<u16>::new(),
        "an inbound route to the outbound capture listener must be refused"
    );
    assert_eq!(inbound_routes(19011), vec![19011]);
}
