//! External regression tests for [`GatewayListenerPlan::from_config`].
//!
//! Plain HTTP listeners may share a numeric port with UDP/DTLS because TCP and
//! UDP are distinct transports. TLS-class listeners also share that TCP port
//! when HTTP/3 is enabled: only the optional QUIC half is refused
//! (`quic_refused`), while the TCP listener stays in `ports`.

use std::collections::{BTreeMap, HashSet};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use chrono::Utc;
use ferrum_edge::config::types::{AuthMode, BackendScheme, DispatchKind, GatewayConfig, Proxy};
use ferrum_edge::modes::mesh::config::MeshConfig;
use ferrum_edge::proxy::gateway_listener::{
    DesiredGatewayListener, GatewayListenerClass, GatewayListenerPlan,
    GatewayListenerProtocolFailure,
};
use ferrum_edge::proxy::gateway_listener_status::GatewayListenerFailureCategory;

const PORT: u16 = 9000;
const DEFAULT_BIND: IpAddr = IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED);

fn http_proxy(id: &str, port: u16) -> Proxy {
    let proxy: Proxy = serde_json::from_value(serde_json::json!({
        "id": id,
        "hosts": ["app.example.com"],
        "listen_path": "/api",
        "backend_scheme": "http",
        "backend_host": "127.0.0.1",
        "backend_port": 1,
        "listen_port": port,
    }))
    .expect("http proxy");
    proxy
}

fn stream_proxy(id: &str, scheme: BackendScheme, port: u16) -> Proxy {
    Proxy {
        id: id.into(),
        namespace: ferrum_edge::config::types::default_namespace(),
        name: None,
        hosts: vec![],
        listen_path: None,
        backend_scheme: Some(scheme),
        dispatch_kind: DispatchKind::from(scheme),
        backend_host: "127.0.0.1".into(),
        backend_port: 1,
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
        api_spec_id: None,
        circuit_breaker: None,
        retry: None,
        response_body_mode: Default::default(),
        listen_port: Some(port),
        frontend_tls: false,
        passthrough: false,
        udp_idle_timeout_seconds: 60,
        tcp_idle_timeout_seconds: Some(300),
        websocket_idle_timeout_seconds: None,
        allowed_methods: None,
        allowed_ws_origins: vec![],
        udp_max_response_amplification_factor: None,
        stream_proxy_protocol: None,
        backend_proxy_protocol: None,
        stream_match: None,
        compiled_stream_match: None,
        created_at: Utc::now(),
        updated_at: Utc::now(),
        pending_limit_scope: None,
    }
}

fn plan_for(proxies: Vec<Proxy>) -> GatewayListenerPlan {
    let mut config = GatewayConfig {
        proxies,
        ..GatewayConfig::default()
    };
    config.resolve_dispatch_kind();
    GatewayListenerPlan::from_config(
        &config,
        &HashSet::new(),
        &BTreeMap::new(),
        DEFAULT_BIND,
        false,
    )
}

fn plan_with_frontends(
    mut config: GatewayConfig,
    existing_frontends: BTreeMap<u16, GatewayListenerClass>,
) -> GatewayListenerPlan {
    config.resolve_dispatch_kind();
    GatewayListenerPlan::from_config(
        &config,
        &HashSet::new(),
        &existing_frontends,
        DEFAULT_BIND,
        false,
    )
}

fn tls_plan_for(proxies: Vec<Proxy>, http3_enabled: bool) -> GatewayListenerPlan {
    let mut config = GatewayConfig {
        proxies,
        ..GatewayConfig::default()
    };
    config.resolve_dispatch_kind();
    config
        .http_tls_listen_ports
        .insert((ferrum_edge::config::types::default_namespace(), PORT));
    GatewayListenerPlan::from_config(
        &config,
        &HashSet::new(),
        &BTreeMap::new(),
        DEFAULT_BIND,
        http3_enabled,
    )
}

#[test]
fn http_and_udp_stream_may_share_numeric_port() {
    let plan = plan_for(vec![
        http_proxy("http-gw", PORT),
        stream_proxy("udp-stream", BackendScheme::Udp, PORT),
    ]);

    assert_eq!(
        plan.ports.get(&PORT).map(|d| d.class),
        Some(GatewayListenerClass::Plaintext)
    );
    assert!(
        !plan.refused.contains_key(&PORT),
        "UDP must not withdraw the HTTP-family listener: {:?}",
        plan.refused
    );
    assert!(
        plan.quic_refused.is_empty(),
        "plaintext listeners never own QUIC: {:?}",
        plan.quic_refused
    );
}

#[test]
fn http_and_dtls_stream_may_share_numeric_port() {
    let plan = plan_for(vec![
        http_proxy("http-gw", PORT),
        stream_proxy("dtls-stream", BackendScheme::Dtls, PORT),
    ]);

    assert_eq!(
        plan.ports.get(&PORT).map(|d| d.class),
        Some(GatewayListenerClass::Plaintext)
    );
    assert!(
        !plan.refused.contains_key(&PORT),
        "DTLS must not withdraw the HTTP-family listener: {:?}",
        plan.refused
    );
    assert!(plan.quic_refused.is_empty());
}

#[test]
fn http3_and_udp_stream_refuses_quic_only() {
    let plan = tls_plan_for(
        vec![
            http_proxy("https-gw", PORT),
            stream_proxy("udp-stream", BackendScheme::Udp, PORT),
        ],
        true,
    );

    assert_eq!(
        plan.ports.get(&PORT).map(|desired| desired.class),
        Some(GatewayListenerClass::Tls)
    );
    assert!(
        !plan.refused.contains_key(&PORT),
        "UDP must not refuse the TCP half: {:?}",
        plan.refused
    );
    assert_eq!(
        plan.quic_refused.get(&PORT),
        Some(&GatewayListenerProtocolFailure::UdpStreamCollision)
    );
    let message = GatewayListenerProtocolFailure::UdpStreamCollision.message(PORT);
    assert!(
        message.contains("HTTP/3 socket"),
        "unexpected refusal message: {message}"
    );
    assert_eq!(
        GatewayListenerProtocolFailure::UdpStreamCollision.category(),
        GatewayListenerFailureCategory::UdpStreamCollision
    );
}

#[test]
fn http3_and_dtls_stream_refuses_quic_only() {
    let plan = tls_plan_for(
        vec![
            http_proxy("https-gw", PORT),
            stream_proxy("dtls-stream", BackendScheme::Dtls, PORT),
        ],
        true,
    );

    assert_eq!(
        plan.ports.get(&PORT).map(|desired| desired.class),
        Some(GatewayListenerClass::Tls)
    );
    assert!(
        !plan.refused.contains_key(&PORT),
        "DTLS must not refuse the TCP half: {:?}",
        plan.refused
    );
    assert_eq!(
        plan.quic_refused.get(&PORT),
        Some(&GatewayListenerProtocolFailure::UdpStreamCollision)
    );
}

#[test]
fn https_and_udp_stream_may_share_numeric_port_when_http3_is_disabled() {
    let plan = tls_plan_for(
        vec![
            http_proxy("https-gw", PORT),
            stream_proxy("udp-stream", BackendScheme::Udp, PORT),
        ],
        false,
    );

    assert_eq!(
        plan.ports.get(&PORT).map(|d| d.class),
        Some(GatewayListenerClass::Tls)
    );
    assert!(
        !plan.refused.contains_key(&PORT),
        "disabled HTTP/3 owns no UDP socket: {:?}",
        plan.refused
    );
    assert!(
        plan.quic_refused.is_empty(),
        "disabled HTTP/3 must not mark QUIC refused: {:?}",
        plan.quic_refused
    );
}

#[test]
fn http_and_tcp_stream_on_same_port_is_refused() {
    let plan = plan_for(vec![
        http_proxy("http-gw", PORT),
        stream_proxy("tcp-stream", BackendScheme::Tcp, PORT),
    ]);

    assert!(
        !plan.ports.contains_key(&PORT),
        "HTTP must not bind when raw TCP claims the port: {:?}",
        plan.ports
    );
    let refusal = plan.refused.get(&PORT).expect("refusal reason");
    assert_eq!(
        refusal.category,
        GatewayListenerFailureCategory::StreamPortCollision
    );
    assert!(
        refusal.message.contains("TCP/TLS stream proxy"),
        "refusal must name the TCP stream collision: {}",
        refusal.message
    );
    assert!(plan.quic_refused.is_empty());
}

#[test]
fn http_and_tcp_tls_stream_on_same_port_is_refused() {
    let plan = plan_for(vec![
        http_proxy("http-gw", PORT),
        stream_proxy("tcp-tls-stream", BackendScheme::Tcps, PORT),
    ]);

    assert!(
        !plan.ports.contains_key(&PORT),
        "HTTP must not bind when TCP/TLS claims the port: {:?}",
        plan.ports
    );
    let refusal = plan.refused.get(&PORT).expect("refusal reason");
    assert_eq!(
        refusal.category,
        GatewayListenerFailureCategory::StreamPortCollision
    );
    assert!(
        refusal.message.contains("TCP/TLS stream proxy"),
        "refusal must name the TCP/TLS stream collision: {}",
        refusal.message
    );
}

#[test]
fn process_global_same_class_frontend_is_already_served_with_udp_present() {
    let mut config = GatewayConfig {
        proxies: vec![
            http_proxy("https-gw", PORT),
            stream_proxy("udp-stream", BackendScheme::Udp, PORT),
        ],
        ..GatewayConfig::default()
    };
    config.resolve_dispatch_kind();
    config
        .http_tls_listen_ports
        .insert((ferrum_edge::config::types::default_namespace(), PORT));
    let mut existing = BTreeMap::new();
    existing.insert(PORT, GatewayListenerClass::Tls);

    let plan =
        GatewayListenerPlan::from_config(&config, &HashSet::new(), &existing, DEFAULT_BIND, true);

    assert!(
        plan.ports.is_empty(),
        "same-class process-global frontend needs no dynamic bind: {:?}",
        plan.ports
    );
    assert_eq!(
        plan.already_served.get(&PORT),
        Some(&GatewayListenerClass::Tls)
    );
    assert!(
        !plan.refused.contains_key(&PORT),
        "UDP must not withdraw an already-served same-class frontend: {:?}",
        plan.refused
    );
    assert!(
        plan.quic_refused.is_empty(),
        "gateway manager does not own process-global QUIC: {:?}",
        plan.quic_refused
    );
}

#[test]
fn quic_udp_collision_is_numeric_port_not_address_family() {
    // Planner ownership is by listen_port number. IPv4 vs IPv6 bind addresses
    // used by stream vs gateway listeners must not reintroduce a "whichever
    // family binds wins" race — the UDP/DTLS claim always wins the QUIC half.
    let _v4 = IpAddr::V4(Ipv4Addr::LOCALHOST);
    let _v6 = IpAddr::V6(Ipv6Addr::LOCALHOST);
    let plan = tls_plan_for(
        vec![
            http_proxy("https-gw", PORT),
            stream_proxy("udp-stream", BackendScheme::Udp, PORT),
        ],
        true,
    );
    assert_eq!(
        plan.ports.get(&PORT).map(|desired| desired.class),
        Some(GatewayListenerClass::Tls)
    );
    assert_eq!(
        plan.quic_refused.get(&PORT),
        Some(&GatewayListenerProtocolFailure::UdpStreamCollision)
    );
}

#[test]
fn dedicated_sidecar_bind_is_carried_in_desired_identity() {
    let loopback: IpAddr = "127.0.0.1".parse().expect("ip");
    let mut mesh = MeshConfig::default();
    mesh.sidecar_ingress_bind_overrides.insert(PORT, loopback);
    let config = GatewayConfig {
        proxies: vec![http_proxy("http-gw", PORT)],
        mesh: Some(Box::new(mesh)),
        ..GatewayConfig::default()
    };
    let plan = plan_with_frontends(config, BTreeMap::new());
    assert_eq!(
        plan.ports.get(&PORT),
        Some(&DesiredGatewayListener {
            class: GatewayListenerClass::Plaintext,
            bind_addr: loopback,
            mesh_direction: Some(ferrum_edge::modes::mesh::MeshTrafficDirection::Inbound),
        })
    );
}

#[test]
fn dedicated_sidecar_tls_bind_is_refused_with_a_bounded_reason() {
    let loopback: IpAddr = "127.0.0.1".parse().expect("ip");
    let mut mesh = MeshConfig::default();
    mesh.sidecar_ingress_bind_overrides.insert(PORT, loopback);
    let mut config = GatewayConfig {
        proxies: vec![http_proxy("https-gw", PORT)],
        mesh: Some(Box::new(mesh)),
        ..GatewayConfig::default()
    };
    config
        .http_tls_listen_ports
        .insert((ferrum_edge::config::types::default_namespace(), PORT));

    let plan = plan_with_frontends(config, BTreeMap::new());
    assert!(!plan.ports.contains_key(&PORT));
    let refusal = plan.refused.get(&PORT).expect("refusal");
    assert_eq!(
        refusal.category,
        GatewayListenerFailureCategory::DedicatedBindTlsUnsupported
    );
    assert!(refusal.message.contains("plaintext HTTP-family"));
}

#[test]
fn same_class_process_global_frontend_is_already_served_without_dedicated_bind() {
    let config = GatewayConfig {
        proxies: vec![http_proxy("http-gw", PORT)],
        ..GatewayConfig::default()
    };
    let mut existing = BTreeMap::new();
    existing.insert(PORT, GatewayListenerClass::Plaintext);
    let plan = plan_with_frontends(config, existing);
    assert_eq!(
        plan.already_served.get(&PORT),
        Some(&GatewayListenerClass::Plaintext)
    );
    assert!(!plan.ports.contains_key(&PORT));
    assert!(!plan.refused.contains_key(&PORT));
}

#[test]
fn dedicated_bind_cannot_be_absorbed_by_process_global_same_class_frontend() {
    let loopback: IpAddr = "127.0.0.1".parse().expect("ip");
    let mut mesh = MeshConfig::default();
    mesh.sidecar_ingress_bind_overrides.insert(PORT, loopback);
    let config = GatewayConfig {
        proxies: vec![http_proxy("http-gw", PORT)],
        mesh: Some(Box::new(mesh)),
        ..GatewayConfig::default()
    };
    let mut existing = BTreeMap::new();
    existing.insert(PORT, GatewayListenerClass::Plaintext);
    let plan = plan_with_frontends(config, existing);
    assert!(
        !plan.already_served.contains_key(&PORT),
        "dedicated bind must not widen onto the global frontend: {:?}",
        plan.already_served
    );
    assert!(!plan.ports.contains_key(&PORT));
    let reason = plan.refused.get(&PORT).expect("refusal");
    assert_eq!(
        reason.category,
        GatewayListenerFailureCategory::DedicatedBindConflict
    );
    assert!(
        reason.message.contains("dedicated Sidecar ingress bind"),
        "refusal must name dedicated-bind isolation: {}",
        reason.message
    );
}
