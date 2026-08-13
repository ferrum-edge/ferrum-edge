//! Same-timestamp authored mesh-tag reloads must republish the request epoch.
//!
//! `ConfigDelta` keys upstream modifications on `updated_at`. A file/admin
//! rewrite that changes only `UpstreamTarget.tags` (host and declared app port
//! fixed) while leaving timestamps alone therefore yields an empty delta. The
//! empty-delta publish path must still rebuild the upstream via
//! `projected_dr_dispatch_changed_upstreams` so admin projection, LB selection,
//! and H3→gRPC mesh transport materialization all observe the new pins
//! (issue #3284 / PR #3673).

use chrono::{DateTime, Utc};
use ferrum_edge::config::types::*;
use ferrum_edge::proxy::{ConfigApplyOutcome, ProxyState};
use std::collections::HashMap;

fn ts(secs: i64) -> DateTime<Utc> {
    DateTime::from_timestamp(secs, 0).expect("valid test timestamp")
}

fn mesh_target(host: &str, port: u16, tags: &[(&str, &str)]) -> UpstreamTarget {
    UpstreamTarget {
        host: host.to_string(),
        port,
        service_port_policy_key: None,
        weight: 100,
        tags: tags
            .iter()
            .map(|(k, v)| ((*k).to_string(), (*v).to_string()))
            .collect(),
        locality: None,
        path: None,
    }
}

fn upstream_with_target(id: &str, target: UpstreamTarget, updated_at: DateTime<Utc>) -> Upstream {
    Upstream {
        id: id.to_string(),
        namespace: default_namespace(),
        name: None,
        targets: vec![target],
        algorithm: LoadBalancerAlgorithm::default(),
        hash_on: None,
        hash_on_cookie_config: None,
        health_checks: None,
        service_discovery: None,
        subsets: None,
        port_overrides: HashMap::new(),
        source_locality: None,
        source_labels: Default::default(),
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
        created_at: updated_at,
        updated_at,
        k8s_service_uid: None,
        pending_limit_scope: None,
    }
}

fn proxy_for_upstream(id: &str, upstream_id: &str, updated_at: DateTime<Utc>) -> Proxy {
    Proxy {
        id: id.to_string(),
        namespace: default_namespace(),
        name: None,
        hosts: vec![],
        listen_path: Some("/mesh".to_string()),
        backend_scheme: Some(BackendScheme::Http),
        dispatch_kind: DispatchKind::from(BackendScheme::Http),
        backend_host: "127.0.0.1".to_string(),
        backend_port: 9,
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
        upstream_id: Some(upstream_id.to_string()),
        upstream_subset: None,
        api_spec_id: None,
        circuit_breaker: None,
        retry: None,
        response_body_mode: ResponseBodyMode::default(),
        listen_port: None,
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
        created_at: updated_at,
        updated_at,
        pending_limit_scope: None,
    }
}

fn config_with_mesh_tags(tags: &[(&str, &str)], stamp: DateTime<Utc>) -> GatewayConfig {
    let upstream = upstream_with_target(
        "h3-mesh-grpc-upstream",
        mesh_target("127.0.0.1", 18080, tags),
        stamp,
    );
    let proxy = proxy_for_upstream("h3-mesh-grpc", "h3-mesh-grpc-upstream", stamp);
    let mut config = GatewayConfig {
        version: "1".to_string(),
        proxies: vec![proxy],
        consumers: Vec::new(),
        plugin_configs: Vec::new(),
        upstreams: vec![upstream],
        loaded_at: stamp,
        known_namespaces: Vec::new(),
        ..GatewayConfig::default()
    };
    config.normalize_fields();
    config
}

async fn proxy_state_from(config: GatewayConfig) -> ProxyState {
    let dns_cache = ferrum_edge::dns::DnsCache::new(ferrum_edge::dns::DnsConfig::default());
    let env_config = ferrum_edge::config::env_config::EnvConfig::default();
    let (state, _) = ProxyState::new(config, dns_cache, env_config, None, None)
        .expect("test proxy state should build");
    state
}

fn live_tags(state: &ProxyState) -> HashMap<String, String> {
    state
        .config
        .load_full()
        .upstreams
        .iter()
        .find(|upstream| upstream.id == "h3-mesh-grpc-upstream")
        .expect("admin/config projection must expose the mesh upstream")
        .targets
        .first()
        .expect("mesh upstream must keep its target")
        .tags
        .clone()
}

fn epoch_tags(state: &ProxyState) -> HashMap<String, String> {
    state
        .request_epoch
        .load()
        .config()
        .upstreams
        .iter()
        .find(|upstream| upstream.id == "h3-mesh-grpc-upstream")
        .expect("request epoch must expose the mesh upstream")
        .targets
        .first()
        .expect("request-epoch mesh upstream must keep its target")
        .tags
        .clone()
}

fn lb_tags(state: &ProxyState) -> HashMap<String, String> {
    state
        .load_balancer_cache
        .get_upstream(&default_namespace(), "h3-mesh-grpc-upstream")
        .expect("LB cache must retain the mesh upstream")
        .targets
        .first()
        .expect("LB mesh upstream must keep its target")
        .tags
        .clone()
}

#[tokio::test]
async fn same_timestamp_mesh_tag_only_reload_republishes_admin_epoch_and_lb() {
    let stamp = ts(1_700_000_000);
    let peer_a = [
        ("mesh.mtls", "true"),
        ("mesh.mtls_port", "15006"),
        (
            "mesh.spiffe_id",
            "spiffe://cluster.local/ns/ferrum/sa/h3-peer",
        ),
        (
            "mesh.mtls_authority_host",
            "h3-peer.ferrum.svc.cluster.local",
        ),
    ];
    let peer_b = [
        ("mesh.mtls", "true"),
        ("mesh.mtls_port", "15007"),
        (
            "mesh.spiffe_id",
            "spiffe://cluster.local/ns/ferrum/sa/h3-peer-b",
        ),
        (
            "mesh.mtls_authority_host",
            "h3-peer.ferrum.svc.cluster.local",
        ),
    ];

    let state = proxy_state_from(config_with_mesh_tags(&peer_a, stamp)).await;
    assert_eq!(
        live_tags(&state).get("mesh.mtls_port").map(String::as_str),
        Some("15006")
    );

    // Same resource timestamps, host, and declared app port — only mesh tags move.
    let outcome = state.update_config(config_with_mesh_tags(&peer_b, stamp));
    assert_eq!(
        outcome,
        ConfigApplyOutcome::Applied,
        "a same-timestamp authored tag rewrite must not be treated as Unchanged; \
         projected_dr_dispatch_changed_upstreams must rebuild the upstream"
    );

    let expected: HashMap<String, String> = peer_b
        .iter()
        .map(|(k, v)| ((*k).to_string(), (*v).to_string()))
        .collect();
    assert_eq!(
        live_tags(&state),
        expected,
        "ProxyState.config (admin projection) must publish the new mesh tags"
    );
    assert_eq!(
        epoch_tags(&state),
        expected,
        "request_epoch.config must publish the new mesh tags for datapath materialization"
    );
    assert_eq!(
        lb_tags(&state),
        expected,
        "load-balancer upstream snapshot must carry the new mesh tags"
    );
}

#[tokio::test]
async fn withdrawing_mesh_tags_at_same_timestamp_clears_live_projection() {
    let stamp = ts(1_700_000_100);
    let peer = [
        ("mesh.mtls", "true"),
        ("mesh.mtls_port", "15006"),
        (
            "mesh.spiffe_id",
            "spiffe://cluster.local/ns/ferrum/sa/h3-peer",
        ),
    ];
    let state = proxy_state_from(config_with_mesh_tags(&peer, stamp)).await;

    let outcome = state.update_config(config_with_mesh_tags(&[], stamp));
    assert_eq!(outcome, ConfigApplyOutcome::Applied);
    assert!(
        live_tags(&state).is_empty(),
        "withdrawing mesh tags must clear the admin/config projection: {:?}",
        live_tags(&state)
    );
    assert!(
        epoch_tags(&state).is_empty(),
        "withdrawing mesh tags must clear the request-epoch projection: {:?}",
        epoch_tags(&state)
    );
    assert!(
        lb_tags(&state).is_empty(),
        "withdrawing mesh tags must clear the LB projection: {:?}",
        lb_tags(&state)
    );
}
