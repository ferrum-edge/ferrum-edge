//! Integration coverage for DestinationRule
//! `trafficPolicy.portLevelSettings[].connectionPool.tcp.maxConnections`
//! flowing from the Istio K8s translator through `MeshSlice`, onto
//! `Upstream.port_overrides[port].max_connections`, and through
//! `GatewayConfig::resolve_dispatch_port_overrides()` onto a referencing
//! proxy's `dispatch_port_overrides`.
//!
//! This is the wiring that Finding #7b reported was a silent no-op for
//! HTTP-family destinations. These tests prove (a) the cap reaches the
//! per-port dispatch override the WebSocket dispatch path reads, and (b) the
//! shared `ProxyState.backend_conn_limit` makes exactly the runtime
//! accept/reject decision the WebSocket handler makes
//! (`src/proxy/mod.rs::handle_websocket_request_authenticated` and
//! `src/http3/websocket.rs::handle_h3_websocket`): under the cap a slot is
//! granted, at the cap the next connection is refused, and dropping a guard
//! frees the slot — so a closed WebSocket session releases its backend
//! connection count without leaking.

use std::collections::HashMap;

use chrono::Utc;
use ferrum_edge::_test_support::resolve_backend_max_connections;
use ferrum_edge::capture::CaptureMode;
use ferrum_edge::config::EnvConfig;
use ferrum_edge::config::types::{
    GatewayConfig, LoadBalancerAlgorithm, MAX_TARGET_WEIGHT, Proxy, Upstream, UpstreamTarget,
};
use ferrum_edge::config_sources::k8s::{
    K8sMetadata, K8sObject, K8sTranslationOptions, translate_k8s_objects,
};
use ferrum_edge::dns::{DnsCache, DnsConfig};
use ferrum_edge::identity::spiffe::TrustDomain;
use ferrum_edge::modes::mesh::config::OutboundTrafficPolicy;
use ferrum_edge::modes::mesh::{
    MeshConfigProtocol, MeshRuntimeConfig, MeshTopology, prepare_gateway_config_for_mesh,
};
use ferrum_edge::proxy::ProxyState;

const HOST_FQDN: &str = "ws.default.svc.cluster.local";

fn istio_object(kind: &str, name: &str, spec: serde_json::Value) -> K8sObject {
    K8sObject {
        api_version: "networking.istio.io/v1".to_string(),
        kind: kind.to_string(),
        metadata: K8sMetadata {
            name: name.to_string(),
            uid: String::new(),
            namespace: "default".to_string(),
            generation: None,
            labels: Default::default(),
            annotations: Default::default(),
            creation_timestamp: None,
            deletion_timestamp: None,
        },
        spec,
        status: serde_json::Value::Object(serde_json::Map::new()),
    }
}

fn k8s_options() -> K8sTranslationOptions {
    K8sTranslationOptions::new(
        "default".to_string(),
        TrustDomain::new("cluster.local").expect("trust domain"),
    )
}

fn runtime() -> MeshRuntimeConfig {
    MeshRuntimeConfig {
        node_id: "node-a".to_string(),
        namespace: "default".to_string(),
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
        egress_listen_addr: "0.0.0.0:15090".parse().expect("addr"),
        workload_spiffe_id: None,
        waypoint_name: None,
        workload_svid_cert_path: None,
        workload_svid_key_path: None,
        workload_svid_trust_bundle_path: None,
        ca_backend: ferrum_edge::identity::ca::CaBackend::None,
        xds_node_cluster: "default".to_string(),
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
        cluster_domain: "cluster.local".to_string(),
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

/// Upstream with two destination ports (8080 and 9090) so a DR that caps only
/// 8080 leaves 9090 unbounded — the same "phantom / unconfigured port stays
/// unbounded" contract the dispatch path relies on.
fn ws_upstream(id: &str) -> Upstream {
    let now = Utc::now();
    Upstream {
        id: id.to_string(),
        namespace: "default".to_string(),
        name: Some(id.to_string()),
        targets: vec![
            UpstreamTarget {
                host: HOST_FQDN.to_string(),
                port: 8080,
                service_port_policy_key: None,
                weight: MAX_TARGET_WEIGHT.min(1),
                tags: HashMap::new(),
                locality: None,
                path: None,
            },
            UpstreamTarget {
                host: HOST_FQDN.to_string(),
                port: 9090,
                service_port_policy_key: None,
                weight: MAX_TARGET_WEIGHT.min(1),
                tags: HashMap::new(),
                locality: None,
                path: None,
            },
        ],
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

/// A WebSocket-capable proxy (plain `http` backend serves WS upgrades — gRPC
/// and WebSocket are runtime flavors, not schemes) bound to the upstream.
fn ws_proxy(upstream_id: &str) -> Proxy {
    let mut proxy: Proxy = serde_json::from_value(serde_json::json!({
        "id": "ws-maxconn",
        "listen_path": "/ws",
        "backend_scheme": "http",
        "backend_host": HOST_FQDN,
        "backend_port": 8080,
        "strip_listen_path": false,
        "upstream_id": upstream_id,
    }))
    .expect("ws proxy should deserialize");
    proxy.namespace = "default".to_string();
    proxy
}

/// Translate a DR that caps `maxConnections` on port 8080 only, attach a
/// matching upstream + WS proxy, and drive the config through the same
/// normalize + mesh-apply path the runtime uses. Returns the prepared config.
fn prepared_config_with_max_connections(cap: u32) -> GatewayConfig {
    let object = istio_object(
        "DestinationRule",
        "ws",
        serde_json::json!({
            "host": HOST_FQDN,
            "trafficPolicy": {
                "portLevelSettings": [
                    {
                        "port": { "number": 8080 },
                        "connectionPool": { "tcp": { "maxConnections": cap } }
                    }
                ]
            }
        }),
    );

    let mut config = translate_k8s_objects(&[object], k8s_options())
        .expect("DR translation")
        .config;
    config.upstreams.push(ws_upstream("ws-u"));
    config.proxies.push(ws_proxy("ws-u"));
    config.normalize_fields();

    prepare_gateway_config_for_mesh(config, &runtime()).expect("mesh apply")
}

#[test]
fn destination_rule_max_connections_projects_onto_upstream_and_dispatch() {
    let prepared = prepared_config_with_max_connections(2);

    // (a) The DR cap landed on the upstream's per-port override slot for 8080.
    let upstream = prepared
        .upstreams
        .iter()
        .find(|u| u.id == "ws-u")
        .expect("upstream present");
    assert_eq!(
        upstream
            .port_overrides
            .get(&8080)
            .expect("port 8080 override populated")
            .max_connections,
        Some(2),
        "DR connectionPool.tcp.maxConnections must land on Upstream.port_overrides[8080]"
    );
    // Port 9090 had no DR entry — it must stay unbounded (no override slot).
    assert!(
        upstream
            .port_overrides
            .get(&9090)
            .and_then(|o| o.max_connections)
            .is_none(),
        "port 9090 has no DR entry and must remain unbounded"
    );

    // (b) `resolve_dispatch_port_overrides()` (run by normalize_fields) projected
    // the cap onto the referencing proxy's hot-path dispatch map — the field the
    // WebSocket dispatch path actually reads.
    let proxy = prepared
        .proxies
        .iter()
        .find(|p| p.id == "ws-maxconn")
        .expect("proxy present");
    assert_eq!(
        resolve_backend_max_connections(proxy, 8080),
        Some(2),
        "WS dispatch must resolve the per-port maxConnections cap for port 8080"
    );
    assert_eq!(
        resolve_backend_max_connections(proxy, 9090),
        None,
        "WS dispatch must treat the uncapped port 9090 as unbounded"
    );
}

#[tokio::test]
async fn proxy_state_backend_conn_limit_enforces_destination_rule_cap() {
    // End-to-end through ProxyState: the cap materialized from the DR drives
    // the same accept/reject/free decision the WebSocket handler makes via
    // `state.backend_conn_limit`.
    let prepared = prepared_config_with_max_connections(1);
    let proxy = prepared
        .proxies
        .iter()
        .find(|p| p.id == "ws-maxconn")
        .expect("proxy present")
        .clone();
    let cap = resolve_backend_max_connections(&proxy, 8080);
    assert_eq!(cap, Some(1), "precondition: port 8080 capped at 1");

    let dns_cache = DnsCache::new(DnsConfig::default());
    let (state, _handles) = ProxyState::new(prepared, dns_cache, EnvConfig::default(), None, None)
        .expect("ProxyState construction");

    // First WS session to (HOST, 8080) acquires the only slot.
    let first = state
        .backend_conn_limit
        .try_acquire(HOST_FQDN, 8080, cap)
        .expect("first acquire under cap")
        .expect("guard present when cap configured");

    // Second concurrent session to the same destination is refused (503-class).
    let err = state
        .backend_conn_limit
        .try_acquire(HOST_FQDN, 8080, cap)
        .expect_err("second acquire must be refused at the cap");
    assert_eq!(err.current, 1);
    assert_eq!(err.cap, 1);

    // The uncapped port 9090 is unbounded — repeated acquires all succeed.
    for _ in 0..4 {
        let none_cap = resolve_backend_max_connections(&proxy, 9090);
        let slot = state
            .backend_conn_limit
            .try_acquire(HOST_FQDN, 9090, none_cap)
            .expect("uncapped acquire never errors");
        assert!(slot.is_none(), "no cap => no guard handed out");
    }

    // Closing the first WS session (guard drop) frees the slot for reuse — a
    // closed session must not leak its backend connection count.
    drop(first);
    let _reused = state
        .backend_conn_limit
        .try_acquire(HOST_FQDN, 8080, cap)
        .expect("slot freed after the first session closed")
        .expect("guard present");
}
