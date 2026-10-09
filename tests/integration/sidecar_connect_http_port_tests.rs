//! A bare authenticated HTTP/2 CONNECT on the Sidecar inbound listener
//! (`:15006`) is the raw-TCP egress lane. It must not reach a port that a
//! materialized HTTP-family inbound route serves, or the request would be
//! relayed as opaque bytes and skip that route's plugin chain (issue #6110).
//! Stream-family ports, the datagram relay, and Ambient HBONE are unchanged.

use std::collections::HashMap;
use std::net::IpAddr;

use ferrum_edge::_test_support::inbound_connect_relay_synthesis_refusal_for_test;
use ferrum_edge::config::types::GatewayConfig;
use ferrum_edge::identity::spiffe::{SpiffeId, TrustDomain};
use ferrum_edge::modes::mesh::config::{
    AppProtocol, InboundRelayDenial, MeshConfig, MeshService, ServicePort, Workload, WorkloadPort,
    WorkloadRef, WorkloadSelector,
};
use ferrum_edge::modes::mesh::{MeshTopology, prepare_gateway_config_for_mesh};

use super::mesh_test_support::default_mesh_runtime;

const NAMESPACE: &str = "default";
const SERVICE: &str = "reviews";
const POD_IP: &str = "10.244.1.7";
const HTTP_PORT: u16 = 9080;
const TCP_PORT: u16 = 6379;

fn pod_ip() -> IpAddr {
    POD_IP.parse().expect("pod IP")
}

/// Relay synthesis for `authority`: the refusal's denial reason, or `None`
/// when a relay proxy is synthesized.
fn synthesis_refusal(
    authority: &str,
    mesh: &MeshConfig,
    is_udp_connect: bool,
    accepted_local_ip: Option<IpAddr>,
) -> Option<&'static str> {
    inbound_connect_relay_synthesis_refusal_for_test(
        authority,
        mesh,
        is_udp_connect,
        accepted_local_ip,
    )
}

/// The local `reviews` pod: one HTTP-family port and one stream-family port.
fn local_service(spiffe: &str) -> (Workload, MeshService) {
    let id = SpiffeId::new(spiffe).expect("spiffe");
    let workload = Workload {
        spiffe_id: id.clone(),
        selector: WorkloadSelector {
            labels: HashMap::from([("app".to_string(), SERVICE.to_string())]),
            namespace: Some(NAMESPACE.to_string()),
        },
        service_name: SERVICE.to_string(),
        service_namespace: None,
        addresses: vec![POD_IP.to_string()],
        ports: vec![
            WorkloadPort {
                port: HTTP_PORT,
                protocol: AppProtocol::Http,
                name: Some("http".to_string()),
            },
            WorkloadPort {
                port: TCP_PORT,
                protocol: AppProtocol::Tcp,
                name: Some("tcp".to_string()),
            },
        ],
        trust_domain: TrustDomain::new("cluster.local").expect("trust domain"),
        namespace: NAMESPACE.to_string(),
        network: None,
        cluster: None,
        weight: None,
        locality: None,
        service_account: Some(SERVICE.to_string()),
        pod_uid: None,
        node_waypoint: None,
        remote_provenance: false,
    };
    let service = MeshService {
        cluster_ips: Vec::new(),
        name: SERVICE.to_string(),
        namespace: NAMESPACE.to_string(),
        ports: vec![
            ServicePort {
                port: HTTP_PORT,
                protocol: AppProtocol::Http,
                name: Some("http".to_string()),
                target_port: None,
            },
            ServicePort {
                port: TCP_PORT,
                protocol: AppProtocol::Tcp,
                name: Some("tcp".to_string()),
                target_port: None,
            },
        ],
        workloads: vec![WorkloadRef { spiffe_id: id }],
        protocol_overrides: HashMap::new(),
        uid: None,
        allow_path_parameters: false,
    };
    (workload, service)
}

/// Prepare the local pod's mesh view the way mesh mode does for `topology`.
fn prepared_mesh(topology: MeshTopology) -> MeshConfig {
    let spiffe = format!("spiffe://cluster.local/ns/{NAMESPACE}/sa/{SERVICE}");
    let (workload, service) = local_service(&spiffe);
    let mut runtime = default_mesh_runtime();
    runtime.namespace = NAMESPACE.to_string();
    runtime.workload_spiffe_id = Some(spiffe);
    runtime.topology = topology;
    let config = GatewayConfig {
        mesh: Some(Box::new(MeshConfig {
            workloads: vec![workload],
            services: vec![service],
            ..MeshConfig::default()
        })),
        ..GatewayConfig::default()
    };
    let prepared = prepare_gateway_config_for_mesh(config, &runtime).expect("prepare");
    *prepared.mesh.expect("prepared mesh block")
}

#[test]
fn sidecar_materialization_records_only_http_family_application_ports() {
    let mesh = prepared_mesh(MeshTopology::Sidecar);
    assert_eq!(mesh.sidecar_inbound_http_app_ports, vec![HTTP_PORT]);
    // The stream-family port keeps its raw-TCP inbound entry.
    assert!(
        mesh.local_inbound_tcp_routes
            .iter()
            .any(|route| route.match_port == TCP_PORT)
    );
}

#[test]
fn ambient_materializes_no_http_application_ports() {
    let mesh = prepared_mesh(MeshTopology::Ambient);
    assert!(mesh.sidecar_inbound_http_app_ports.is_empty());
}

#[test]
fn sidecar_connect_to_an_http_application_port_is_refused_at_synthesis() {
    let mesh = prepared_mesh(MeshTopology::Sidecar);
    let own = Some(pod_ip());

    // Both the own pod address and the own-namespace loopback name the HTTP
    // port: refused, because an HTTP route serves it.
    for authority in [
        format!("{POD_IP}:{HTTP_PORT}"),
        format!("127.0.0.1:{HTTP_PORT}"),
    ] {
        assert_eq!(
            synthesis_refusal(&authority, &mesh, false, own),
            Some("http_application_port"),
            "{authority}"
        );
    }
    // The stream-family port still relays.
    assert_eq!(
        synthesis_refusal(&format!("{POD_IP}:{TCP_PORT}"), &mesh, false, own),
        None
    );
    // The datagram relay never reaches an HTTP route and is unchanged.
    assert_eq!(
        synthesis_refusal(&format!("{POD_IP}:{HTTP_PORT}"), &mesh, true, own),
        None
    );
    // Ownership is decided first, so other destinations keep their reasons.
    assert_eq!(
        synthesis_refusal(&format!("{POD_IP}:9999"), &mesh, false, own),
        Some("port_not_declared")
    );
    assert_eq!(
        synthesis_refusal(&format!("10.244.9.9:{HTTP_PORT}"), &mesh, false, own),
        Some("address_not_terminated_here")
    );
}

#[test]
fn ambient_connect_to_the_same_port_still_relays() {
    let mesh = prepared_mesh(MeshTopology::Ambient);
    let authority = format!("{POD_IP}:{HTTP_PORT}");
    assert_eq!(
        synthesis_refusal(&authority, &mesh, false, Some(pod_ip())),
        None,
        "HBONE carries every port of an Ambient workload, HTTP included"
    );
}

#[test]
fn the_stream_decision_refuses_only_after_ownership_is_proven() {
    let own_address_ports = prepared_mesh(MeshTopology::Sidecar).inbound_relay_own_address_ports;
    let mesh = MeshConfig {
        inbound_relay_admits_accepted_local_address: true,
        inbound_relay_admits_loopback_namespace: true,
        inbound_relay_own_address_ports: own_address_ports,
        sidecar_inbound_http_app_ports: vec![HTTP_PORT],
        ..MeshConfig::default()
    };
    let own = Some(pod_ip());

    assert_eq!(
        mesh.inbound_stream_relay_destination_decision(POD_IP, HTTP_PORT, own),
        Err(InboundRelayDenial::HttpApplicationPort)
    );
    assert_eq!(
        mesh.inbound_stream_relay_destination_decision(POD_IP, TCP_PORT, own),
        Ok(())
    );
    // The ordinary (datagram) decision is unchanged.
    assert_eq!(
        mesh.inbound_relay_destination_decision(POD_IP, HTTP_PORT, own),
        Ok(())
    );
    assert_eq!(
        mesh.inbound_stream_relay_destination_decision(POD_IP, 9999, own),
        Err(InboundRelayDenial::PortNotDeclared)
    );
    assert_eq!(
        InboundRelayDenial::HttpApplicationPort.as_str(),
        "http_application_port"
    );
}
