//! A bare authenticated HTTP/2 CONNECT on the Sidecar inbound listener
//! (`:15006`) is the raw-TCP egress lane. It must not reach a port that a
//! materialized HTTP-family inbound route serves, whether the CONNECT misses
//! every route (the relay is synthesized from the authority) or matches the
//! HTTP route itself (a service-host authority). Either way the request would
//! be relayed as opaque bytes and skip that route's plugin chain (issue #6110).
//! Stream-family ports, the datagram relay, and Ambient HBONE are unchanged.

use std::collections::HashMap;
use std::net::IpAddr;
use std::time::Duration;

use hyper::{Method, Request, StatusCode};
use tokio::net::TcpListener;
use tokio::sync::watch;

use crate::scaffolding::port_registry::TestSocket;

use ferrum_edge::_test_support::inbound_connect_relay_synthesis_refusal_for_test;
use ferrum_edge::config::types::GatewayConfig;
use ferrum_edge::config::{EnvConfig, OperatingMode};
use ferrum_edge::dns::{DnsCache, DnsConfig};
use ferrum_edge::identity::spiffe::{SpiffeId, TrustDomain};
use ferrum_edge::modes::mesh::config::{
    AppProtocol, InboundRelayDenial, MeshConfig, MeshService, ResolvedIngressListener,
    ServicePort, SidecarIngressConnectRelay, Workload, WorkloadPort, WorkloadRef,
    WorkloadSelector,
};
use ferrum_edge::modes::mesh::{
    MeshTopology, MeshTrafficDirection, prepare_gateway_config_for_mesh,
};
use ferrum_edge::proxy::{ProxyState, start_proxy_listener_with_bound_listener_and_mesh_direction};

use super::mesh_hbone_tests::{
    connect_hbone_h2_mtls, generate_hbone_mtls_certs, hbone_client_config, hbone_server_config,
};
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
fn local_service(spiffe: &str, http_port: u16, tcp_port: u16) -> (Workload, MeshService) {
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
                port: http_port,
                protocol: AppProtocol::Http,
                name: Some("http".to_string()),
            },
            WorkloadPort {
                port: tcp_port,
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
                port: http_port,
                protocol: AppProtocol::Http,
                name: Some("http".to_string()),
                target_port: None,
            },
            ServicePort {
                port: tcp_port,
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
    let prepared = prepared_config(topology, true, HTTP_PORT, TCP_PORT);
    *prepared.mesh.expect("prepared mesh block")
}

/// Prepare the local pod's whole gateway config the way mesh mode does for
/// `topology`, with or without the Sidecar's own workload identity.
fn prepared_config(
    topology: MeshTopology,
    with_workload_identity: bool,
    http_port: u16,
    tcp_port: u16,
) -> GatewayConfig {
    let spiffe = format!("spiffe://cluster.local/ns/{NAMESPACE}/sa/{SERVICE}");
    let (workload, service) = local_service(&spiffe, http_port, tcp_port);
    let mut runtime = default_mesh_runtime();
    runtime.namespace = NAMESPACE.to_string();
    runtime.workload_spiffe_id = with_workload_identity.then_some(spiffe);
    runtime.topology = topology;
    let config = GatewayConfig {
        mesh: Some(Box::new(MeshConfig {
            workloads: vec![workload],
            services: vec![service],
            ..MeshConfig::default()
        })),
        ..GatewayConfig::default()
    };
    prepare_gateway_config_for_mesh(config, &runtime).expect("prepare")
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

/// Every Sidecar refuses a bare CONNECT that MATCHES an HTTP route, including
/// one with no workload identity (which materializes nothing of its own but can
/// still carry operator HTTP proxies): the rule only refuses. Ambient keeps
/// matched-route CONNECT dispatch.
#[test]
fn every_sidecar_refuses_a_connect_matching_an_http_route() {
    assert!(prepared_mesh(MeshTopology::Sidecar).sidecar_inbound_refuses_matched_http_connect);
    assert!(!prepared_mesh(MeshTopology::Ambient).sidecar_inbound_refuses_matched_http_connect);
    let identity_less = prepared_config(MeshTopology::Sidecar, false, HTTP_PORT, TCP_PORT);
    let identity_less = identity_less.mesh.expect("prepared mesh block");
    assert!(identity_less.sidecar_inbound_refuses_matched_http_connect);
    assert!(identity_less.sidecar_inbound_http_app_ports.is_empty());
}

fn build_state(prepared: GatewayConfig) -> ProxyState {
    let env_config = EnvConfig {
        mode: OperatingMode::Mesh,
        log_level: "error".to_string(),
        proxy_http_port: 0,
        proxy_https_port: 0,
        admin_http_port: 0,
        admin_https_port: 0,
        shutdown_drain_seconds: 0,
        max_connections: 0,
        namespace: NAMESPACE.to_string(),
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

/// The real accept loop and dispatcher, as the Sidecar inbound mTLS listener.
async fn start_inbound_gateway(
    state: ProxyState,
    server_config: std::sync::Arc<rustls::ServerConfig>,
) -> (std::net::SocketAddr, watch::Sender<bool>) {
    let listener = TcpListener::bind_test("127.0.0.1:0")
        .await
        .expect("bind gateway");
    let addr = listener.local_addr().expect("gateway local addr");
    let (shutdown_tx, shutdown_rx) = watch::channel(false);
    tokio::spawn(async move {
        let _ = start_proxy_listener_with_bound_listener_and_mesh_direction(
            listener,
            state,
            shutdown_rx,
            Some(server_config),
            Some(MeshTrafficDirection::Inbound),
        )
        .await;
    });
    tokio::time::sleep(Duration::from_millis(50)).await;
    (addr, shutdown_tx)
}

async fn read_body(body: &mut h2::RecvStream) -> Vec<u8> {
    let mut out = Vec::new();
    while let Some(chunk) = body.data().await {
        let chunk = chunk.expect("response chunk");
        let _ = body.flow_control().release_capacity(chunk.len());
        out.extend_from_slice(&chunk);
    }
    out
}

/// A bare CONNECT whose authority is the service host plus its HTTP port
/// MATCHES the materialized inbound HTTP route instead of missing every route,
/// so the route-miss relay guard never sees it. The dispatcher refuses it
/// before the route's plugin chain runs, with the documented relay-destination
/// `403`, rather than byte-relaying the tunnel to the route's loopback backend.
#[tokio::test(flavor = "multi_thread")]
async fn a_sidecar_connect_matching_the_service_http_route_is_refused() {
    // Both application ports are held by real listeners, so a regression that
    // relayed the CONNECT would get a `200` tunnel rather than a dial failure.
    let http_backend = TcpListener::bind_test("127.0.0.1:0")
        .await
        .expect("bind HTTP application port");
    let tcp_backend = TcpListener::bind_test("127.0.0.1:0")
        .await
        .expect("bind TCP application port");
    let http_port = http_backend.local_addr().expect("HTTP port").port();
    let tcp_port = tcp_backend.local_addr().expect("TCP port").port();

    let prepared = prepared_config(MeshTopology::Sidecar, true, http_port, tcp_port);
    assert!(
        prepared
            .proxies
            .iter()
            .any(|proxy| proxy.backend_port == http_port),
        "the Sidecar materializes an inbound HTTP route for the application port"
    );
    let certs = generate_hbone_mtls_certs("spiffe://cluster.local/ns/default/sa/client");
    let state = build_state(prepared);
    let (gateway_addr, shutdown_tx) =
        start_inbound_gateway(state, hbone_server_config(&certs)).await;
    let (mut sender, conn_task) =
        connect_hbone_h2_mtls(gateway_addr, hbone_client_config(&certs)).await;

    let authority = format!("{SERVICE}.{NAMESPACE}.svc.cluster.local:{http_port}");
    let request = Request::builder()
        .method(Method::CONNECT)
        .uri(authority.as_str())
        .body(())
        .expect("CONNECT request");
    let (response, _request_body) = sender.send_request(request, false).expect("send CONNECT");
    let response = tokio::time::timeout(Duration::from_secs(5), response)
        .await
        .expect("CONNECT response within deadline")
        .expect("CONNECT response");
    assert_eq!(
        response.status(),
        StatusCode::FORBIDDEN,
        "{authority}: a CONNECT matching the HTTP route must not be relayed as bytes"
    );
    let mut body_stream = response.into_body();
    let body = tokio::time::timeout(Duration::from_secs(5), read_body(&mut body_stream))
        .await
        .expect("refusal body within deadline");
    assert_eq!(
        body,
        br#"{"error":"HBONE relay destination not allowed"}"#.to_vec(),
        "the refusal is the documented relay-destination denial"
    );

    let _ = shutdown_tx.send(true);
    conn_task.abort();
    drop((http_backend, tcp_backend));
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

/// A Sidecar `ingress[]` listener on `port` forwarding to loopback
/// `endpoint_port`, owned by the local `reviews` service.
fn ingress_listener(
    port: u16,
    endpoint_port: u16,
    protocol: AppProtocol,
) -> ResolvedIngressListener {
    ResolvedIngressListener {
        port,
        endpoint_host: "127.0.0.1".to_string(),
        endpoint_port,
        protocol,
        endpoint_unix_path: None,
        endpoint_unix_h2c: false,
        owner_namespace: NAMESPACE.to_string(),
        owner_service: SERVICE.to_string(),
        bind: None,
    }
}

/// `ingress[]` applies the "HTTP wins a shared port" rule too: a stream-family
/// listener whose `defaultEndpoint` port an HTTP-family listener also forwards
/// to is refused `http_application_port` rather than relayed as opaque bytes
/// past the HTTP route's plugin chain. A stream listener with its own endpoint
/// port still relays, and the post-plugin re-check (also the fence's gate)
/// agrees with synthesis.
#[test]
fn an_ingress_stream_listener_sharing_an_http_listener_endpoint_is_refused() {
    let mesh = MeshConfig {
        sidecar_ingress_declared: true,
        local_ingress_listeners: vec![
            ingress_listener(9080, 8080, AppProtocol::Http),
            ingress_listener(9081, 8080, AppProtocol::Tcp),
            ingress_listener(9082, 6379, AppProtocol::Tcp),
        ],
        local_workload_addresses: vec![pod_ip()],
        ..MeshConfig::default()
    };
    let own = Some(pod_ip());

    assert_eq!(
        mesh.resolve_sidecar_ingress_connect_relay(POD_IP, 9081, own),
        SidecarIngressConnectRelay::HttpApplicationPort
    );
    assert_eq!(
        synthesis_refusal(&format!("{POD_IP}:9081"), &mesh, false, own),
        Some("http_application_port")
    );
    assert!(!mesh.sidecar_ingress_connect_relay_endpoint_matches(9081, "127.0.0.1", 8080));

    // A stream listener on its own application port keeps the remap.
    assert_eq!(
        synthesis_refusal(&format!("{POD_IP}:9082"), &mesh, false, own),
        None
    );
    assert!(mesh.sidecar_ingress_connect_relay_endpoint_matches(9082, "127.0.0.1", 6379));

    // Ownership is decided first: a sibling replica's address keeps the
    // ordinary mapping refusal, and so does the HTTP listener port itself.
    assert_eq!(
        synthesis_refusal("10.244.9.9:9081", &mesh, false, own),
        Some("ingress_endpoint_mapping_mismatch")
    );
    assert_eq!(
        synthesis_refusal(&format!("{POD_IP}:9080"), &mesh, false, own),
        Some("ingress_endpoint_mapping_mismatch")
    );
}
