//! External regression tests for [`GatewayListenerPlan::from_config`].
//!
//! Plain HTTP listeners may share a numeric port with UDP/DTLS because TCP and
//! UDP are distinct transports. TLS-class listeners also own that UDP port when
//! HTTP/3 is enabled and must then be refused on a stream collision.

use std::collections::{BTreeMap, HashSet};

use chrono::Utc;
use ferrum_edge::config::types::{AuthMode, BackendScheme, DispatchKind, GatewayConfig, Proxy};
use ferrum_edge::proxy::gateway_listener::{GatewayListenerClass, GatewayListenerPlan};

const PORT: u16 = 9000;

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
    }
}

fn plan_for(proxies: Vec<Proxy>) -> GatewayListenerPlan {
    let mut config = GatewayConfig {
        proxies,
        ..GatewayConfig::default()
    };
    config.resolve_dispatch_kind();
    GatewayListenerPlan::from_config(&config, &HashSet::new(), &BTreeMap::new(), false)
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
    GatewayListenerPlan::from_config(&config, &HashSet::new(), &BTreeMap::new(), http3_enabled)
}

#[test]
fn http_and_udp_stream_may_share_numeric_port() {
    let plan = plan_for(vec![
        http_proxy("http-gw", PORT),
        stream_proxy("udp-stream", BackendScheme::Udp, PORT),
    ]);

    assert_eq!(
        plan.ports.get(&PORT),
        Some(&GatewayListenerClass::Plaintext)
    );
    assert!(
        !plan.refused.contains_key(&PORT),
        "UDP must not withdraw the HTTP-family listener: {:?}",
        plan.refused
    );
}

#[test]
fn http_and_dtls_stream_may_share_numeric_port() {
    let plan = plan_for(vec![
        http_proxy("http-gw", PORT),
        stream_proxy("dtls-stream", BackendScheme::Dtls, PORT),
    ]);

    assert_eq!(
        plan.ports.get(&PORT),
        Some(&GatewayListenerClass::Plaintext)
    );
    assert!(
        !plan.refused.contains_key(&PORT),
        "DTLS must not withdraw the HTTP-family listener: {:?}",
        plan.refused
    );
}

#[test]
fn http3_and_udp_stream_on_same_port_is_refused() {
    let plan = tls_plan_for(
        vec![
            http_proxy("https-gw", PORT),
            stream_proxy("udp-stream", BackendScheme::Udp, PORT),
        ],
        true,
    );

    assert!(!plan.ports.contains_key(&PORT));
    let reason = plan.refused.get(&PORT).expect("refusal reason");
    assert!(
        reason.contains("HTTP/3 socket"),
        "unexpected refusal: {reason}"
    );
}

#[test]
fn http3_and_dtls_stream_on_same_port_is_refused() {
    let plan = tls_plan_for(
        vec![
            http_proxy("https-gw", PORT),
            stream_proxy("dtls-stream", BackendScheme::Dtls, PORT),
        ],
        true,
    );

    assert!(!plan.ports.contains_key(&PORT));
    let reason = plan.refused.get(&PORT).expect("refusal reason");
    assert!(
        reason.contains("UDP/DTLS stream proxy"),
        "unexpected refusal: {reason}"
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

    assert_eq!(plan.ports.get(&PORT), Some(&GatewayListenerClass::Tls));
    assert!(
        !plan.refused.contains_key(&PORT),
        "disabled HTTP/3 owns no UDP socket: {:?}",
        plan.refused
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
    let reason = plan.refused.get(&PORT).expect("refusal reason");
    assert!(
        reason.contains("TCP/TLS stream proxy"),
        "refusal must name the TCP stream collision: {reason}"
    );
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
    let reason = plan.refused.get(&PORT).expect("refusal reason");
    assert!(
        reason.contains("TCP/TLS stream proxy"),
        "refusal must name the TCP/TLS stream collision: {reason}"
    );
}
