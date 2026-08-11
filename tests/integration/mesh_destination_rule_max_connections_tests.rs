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
use ferrum_edge::_test_support::{
    resolve_backend_connection_proxy_for_target, resolve_backend_max_connections,
};
use ferrum_edge::backend_conn_limit::{BackendConnectionLimiter, PooledConnectionAdmission};
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
        stock_xds_urls: Vec::new(),
        stock_xds_node_id: None,
        stock_xds_node_metadata: Default::default(),
        stock_xds_token_file: None,
        stock_xds_limits: Default::default(),
        topology: MeshTopology::Sidecar,
        inbound_listen_addr: "127.0.0.1:0".parse().expect("addr"),
        outbound_listen_addr: "127.0.0.1:0".parse().expect("addr"),
        hbone_listen_addr: "127.0.0.1:0".parse().expect("addr"),
        east_west_listen_port: 15443,
        egress_hbone_port: 15008,
        egress_mtls_port: 15006,
        egress_listen_addr: "0.0.0.0:15090".parse().expect("addr"),
        egress_gateway: None,
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
        unix_socket_allowed_roots: Vec::new(),
        unix_socket_allowed_uids: Vec::new(),
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

/// The same upstream + WS proxy with NO DestinationRule at all — the shape a
/// reload/delete leaves behind once the operator removes the rule.
fn prepared_config_without_destination_rule() -> GatewayConfig {
    let mut config = GatewayConfig::default();
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

// ============================================================================
// Pooled-transport admission (issue #3290)
//
// The pooled, multiplexed transports (direct H2, gRPC, native H3, HBONE,
// mesh-mTLS) resolve their `maxConnections` lane through
// `PooledConnectionAdmission::resolve` at the exact moment a NEW physical
// connection is about to be constructed. These tests pin the resolution rules
// and the permit lifecycle those transports depend on: reuse/multiplexing
// takes no slot, exhaustion refuses, retirement frees, and every transport
// lands on ONE lane per destination.
// ============================================================================

/// A proxy carrying `dispatch_port_overrides` exactly as the pooled transports
/// see them after `resolve_backend_connection_proxy_for_target`.
///
/// Built through serde (like `ws_proxy`) so the fixture cannot drift from the
/// `Proxy` struct definition.
fn proxy_with_port_override(port: u16, cap: Option<u32>, policy_port: Option<u16>) -> Proxy {
    let mut proxy: Proxy = serde_json::from_value(serde_json::json!({
        "id": "pooled-maxconn",
        "listen_path": "/pooled",
        "backend_scheme": "https",
        "backend_host": HOST_FQDN,
        "backend_port": port,
        "strip_listen_path": false,
    }))
    .expect("pooled proxy should deserialize");
    proxy.namespace = "default".to_string();
    let mut overrides = HashMap::new();
    overrides.insert(
        port,
        ferrum_edge::config::types::ResolvedPortOverride {
            max_connections: cap,
            policy_port,
            ..Default::default()
        },
    );
    proxy.dispatch_port_overrides = Some(overrides);
    proxy
}

#[test]
fn pooled_admission_is_absent_without_limiter_or_cap() {
    let limiter = BackendConnectionLimiter::new();
    let capped = proxy_with_port_override(8080, Some(4), None);

    // No limiter installed (a focused-test / standalone pool): no enforcement.
    assert!(
        PooledConnectionAdmission::resolve(None, &capped, HOST_FQDN, 8080).is_none(),
        "a pool without an installed limiter must never enforce a cap"
    );
    // No cap on the resolved port: the transport dials unconditionally.
    assert!(
        PooledConnectionAdmission::resolve(Some(&limiter), &capped, HOST_FQDN, 9090).is_none(),
        "a port with no override entry must resolve to no admission"
    );
    let uncapped = proxy_with_port_override(8080, None, None);
    assert!(
        PooledConnectionAdmission::resolve(Some(&limiter), &uncapped, HOST_FQDN, 8080).is_none(),
        "an override entry without maxConnections must resolve to no admission"
    );
}

#[test]
fn pooled_admission_lane_uses_policy_port_not_dial_port() {
    // A Kubernetes `targetPort` remap: policy lives on service port 80, the
    // socket dials workload port 8080. The counter lane must key on 80 so a
    // pooled connection and a WebSocket session share ONE ceiling.
    let limiter = BackendConnectionLimiter::new();
    let remapped = proxy_with_port_override(8080, Some(2), Some(80));
    let admission = PooledConnectionAdmission::resolve(Some(&limiter), &remapped, HOST_FQDN, 8080)
        .expect("mirrored per-port policy resolves an admission lane");
    assert_eq!(admission.policy_port(), 80);
    assert_eq!(admission.cap(), 2);
    assert_eq!(admission.host(), HOST_FQDN);

    // Without a remap the lookup port already IS the policy port.
    let direct = proxy_with_port_override(8080, Some(2), None);
    let admission = PooledConnectionAdmission::resolve(Some(&limiter), &direct, HOST_FQDN, 8080)
        .expect("direct per-port policy resolves an admission lane");
    assert_eq!(admission.policy_port(), 8080);
}

#[test]
fn targetport_remap_stamps_the_policy_port_on_the_dispatch_clone() {
    // `resolve_backend_connection_proxy_for_target` mirrors a service-port
    // policy onto the dial port for the pools that only see the effective
    // proxy. Issue #3290 additionally stamps the port the policy came from so
    // the admission lane does not drift to the workload port.
    let proxy = proxy_with_port_override(80, Some(3), None);
    let target = UpstreamTarget {
        host: HOST_FQDN.to_string(),
        port: 8080,
        // Kubernetes `targetPort` remap: declared Service port 80 -> pod 8080.
        service_port_policy_key: Some(80),
        weight: MAX_TARGET_WEIGHT.min(1),
        tags: HashMap::new(),
        locality: None,
        path: None,
    };
    assert_eq!(target.dispatch_policy_port(), 80);

    let effective = resolve_backend_connection_proxy_for_target(&proxy, Some(&target));
    let mirrored = effective
        .dispatch_port_overrides
        .as_ref()
        .expect("dispatch overrides present")
        .get(&8080)
        .expect("service-port policy mirrored onto the dial port");
    assert_eq!(mirrored.max_connections, Some(3));
    assert_eq!(
        mirrored.policy_port,
        Some(80),
        "the mirrored entry must remember the service port it came from"
    );

    let limiter = BackendConnectionLimiter::new();
    let admission = PooledConnectionAdmission::resolve(
        Some(&limiter),
        effective.as_ref(),
        HOST_FQDN,
        effective.backend_port,
    )
    .expect("pooled transports resolve the mirrored policy by dial port");
    assert_eq!(
        admission.policy_port(),
        80,
        "the pooled lane must be the service policy port, not the workload port"
    );
}

#[test]
fn pooled_slot_is_per_connection_not_per_request() {
    // One admitted connection serves unlimited multiplexed streams: the pooled
    // transports acquire ONLY when constructing a connection, so cloning the
    // reservation (candidate attempts, in-flight request handles) never bumps
    // the count.
    let limiter = BackendConnectionLimiter::new();
    let proxy = proxy_with_port_override(8080, Some(1), None);
    let admission = PooledConnectionAdmission::resolve(Some(&limiter), &proxy, HOST_FQDN, 8080)
        .expect("capped destination resolves an admission lane");

    let connection = admission.acquire().expect("first connection admitted");
    let streams: Vec<_> = (0..64).map(|_| connection.clone()).collect();
    assert_eq!(
        limiter.current(HOST_FQDN, 8080),
        1,
        "64 multiplexed streams on one connection must still count as one socket"
    );
    drop(streams);
    assert_eq!(limiter.current(HOST_FQDN, 8080), 1);

    // A SECOND physical connection to the same destination is refused.
    let err = admission
        .acquire()
        .expect_err("a second physical connection must be refused at the cap");
    assert_eq!(err.current, 1);
    assert_eq!(err.cap, 1);

    // Connection close (the connection driver task, which owns the slot, ends)
    // frees it, and the destination recovers immediately.
    drop(connection);
    assert_eq!(
        limiter.current(HOST_FQDN, 8080),
        0,
        "retiring the connection must release its slot exactly once"
    );
    let _recovered = admission
        .acquire()
        .expect("the destination recovers once the connection is retired");
    assert_eq!(limiter.current(HOST_FQDN, 8080), 1);
}

#[test]
fn failed_connection_attempts_do_not_leak_slots() {
    // The reservation is cloned per DNS candidate; every failed candidate drops
    // its clone, and a create that never establishes drops the reservation
    // entirely. Neither may wedge the destination.
    let limiter = BackendConnectionLimiter::new();
    let proxy = proxy_with_port_override(8080, Some(1), None);
    let admission = PooledConnectionAdmission::resolve(Some(&limiter), &proxy, HOST_FQDN, 8080)
        .expect("capped destination resolves an admission lane");

    for _ in 0..8 {
        let reservation = admission.acquire().expect("attempt admitted");
        let candidate_clones: Vec<_> = (0..3).map(|_| reservation.clone()).collect();
        // Every candidate fails and the create returns an error.
        drop(candidate_clones);
        drop(reservation);
        assert_eq!(
            limiter.current(HOST_FQDN, 8080),
            0,
            "a failed connection attempt must not retain its slot"
        );
    }
}

#[tokio::test]
async fn pooled_and_websocket_transports_share_one_destination_ceiling() {
    // The pooled transports and the WebSocket/raw-TCP paths admit against the
    // SAME `ProxyState.backend_conn_limit`, so a destination gets one ceiling
    // rather than one per transport.
    let prepared = prepared_config_with_max_connections(2);
    let proxy = prepared
        .proxies
        .iter()
        .find(|p| p.id == "ws-maxconn")
        .expect("proxy present")
        .clone();
    let dns_cache = DnsCache::new(DnsConfig::default());
    let (state, _handles) = ProxyState::new(prepared, dns_cache, EnvConfig::default(), None, None)
        .expect("ProxyState construction");

    // A pooled connection takes the first of the two slots.
    let pooled = PooledConnectionAdmission::resolve(
        Some(&*state.backend_conn_limit),
        &proxy,
        HOST_FQDN,
        8080,
    )
    .expect("capped destination resolves an admission lane")
    .acquire()
    .expect("pooled connection admitted");

    // A WebSocket session takes the second through the WS dispatch entry point.
    let cap = resolve_backend_max_connections(&proxy, 8080);
    let ws_session = state
        .backend_conn_limit
        .try_acquire(HOST_FQDN, 8080, cap)
        .expect("websocket session admitted under the shared ceiling")
        .expect("guard present when cap configured");

    // The destination is now at its ceiling for BOTH transports.
    state
        .backend_conn_limit
        .try_acquire(HOST_FQDN, 8080, cap)
        .expect_err("a third connection of any transport must be refused");

    drop(ws_session);
    let _pooled_again = PooledConnectionAdmission::resolve(
        Some(&*state.backend_conn_limit),
        &proxy,
        HOST_FQDN,
        8080,
    )
    .expect("admission lane still resolved")
    .acquire()
    .expect("closing the websocket session frees a slot for a pooled connection");
    drop(pooled);
}

#[test]
fn removing_the_destination_rule_lifts_the_pooled_cap() {
    // Reload/delete: once the DestinationRule is gone the projection carries no
    // cap, so the next pooled connection resolves no admission lane at all.
    let capped = prepared_config_with_max_connections(1);
    let capped_proxy = capped
        .proxies
        .iter()
        .find(|p| p.id == "ws-maxconn")
        .expect("proxy present")
        .clone();
    assert_eq!(
        resolve_backend_max_connections(&capped_proxy, 8080),
        Some(1)
    );

    let uncapped = prepared_config_without_destination_rule();
    let uncapped_proxy = uncapped
        .proxies
        .iter()
        .find(|p| p.id == "ws-maxconn")
        .expect("proxy present")
        .clone();
    assert_eq!(
        resolve_backend_max_connections(&uncapped_proxy, 8080),
        None,
        "deleting the DestinationRule must remove the projected cap"
    );

    let limiter = BackendConnectionLimiter::new();
    assert!(
        PooledConnectionAdmission::resolve(Some(&limiter), &uncapped_proxy, HOST_FQDN, 8080)
            .is_none(),
        "an uncapped destination must resolve no admission lane after reload"
    );
}

// ============================================================================
// One socket, one charge: mesh WebSocket egress must not double-count
//
// A WebSocket to a `mesh.mtls` / `mesh.hbone` destination dials its OWN 1:1
// tunnel connection, and the WebSocket connect loop already reserves a
// session-scoped `BackendConnectionGuard` on the logical `(backend host,
// policy port)` lane before that dial and holds it for the whole session. If the mesh
// pool ALSO admitted the dial, one physical socket would consume two slots —
// and at `maxConnections: 1` the dial would refuse itself, so EVERY WebSocket
// upgrade to a capped mesh destination would fail (observed live as
// `first=502` with `1 open (cap 1)` on the very first upgrade).
//
// The pooled tunnel creates and the raw-TCP / datagram tunnel dials have no
// caller-side guard, so those sites must keep resolving their own lane. These
// source pins hold both halves of that ownership split in place.
// ============================================================================

/// Body of the method introduced by `signature` in `source`, ending at that
/// method's own closing brace (the first line that is exactly `    }`).
fn method_body<'a>(source: &'a str, signature: &str) -> &'a str {
    let start = source.find(signature).unwrap_or(usize::MAX);
    assert!(start != usize::MAX, "{signature} must exist");
    let rest = &source[start..];
    let end = rest.find("\n    }\n").unwrap_or(usize::MAX);
    assert!(end != usize::MAX, "{signature} must have a closing brace");
    &rest[..end]
}

/// Source of the two mesh tunnel pools, pinned as text.
fn mesh_mtls_pool_source() -> &'static str {
    include_str!("../../src/proxy/mesh_mtls_pool.rs")
}

fn hbone_pool_source() -> &'static str {
    include_str!("../../src/proxy/hbone_pool.rs")
}

#[test]
fn mesh_websocket_dedicated_dials_do_not_double_charge_the_session_slot() {
    let sidecar = method_body(
        mesh_mtls_pool_source(),
        "pub async fn open_ws_connect_tunnel(",
    );
    assert!(
        !sidecar.contains("self.conn_admission("),
        "the WebSocket-over-mesh-mTLS 1:1 dial must not re-admit: the WebSocket \
         connect loop already holds this socket's maxConnections slot, so a \
         second charge self-refuses the upgrade at maxConnections=1"
    );

    let ambient = method_body(hbone_pool_source(), "pub async fn get_ws_byte_tunnel(");
    assert!(
        !ambient.contains("self.conn_admission("),
        "the WebSocket-over-HBONE 1:1 dial must not re-admit: the WebSocket \
         connect loop already holds this socket's maxConnections slot, so a \
         second charge self-refuses the upgrade at maxConnections=1"
    );
}

#[test]
fn non_websocket_mesh_tunnel_dials_still_resolve_their_own_admission_lane() {
    // These dials have no caller-side session guard, so dropping their
    // admission would remove the cap entirely for those transports.
    let mtls = mesh_mtls_pool_source();
    let hbone = hbone_pool_source();

    let raw_tcp = method_body(mtls, "pub async fn open_connect_tunnel(");
    assert!(
        raw_tcp.contains("self.conn_admission("),
        "the mesh-mTLS raw-TCP tunnel owns its physical connection"
    );

    let mtls_udp = method_body(mtls, "pub async fn open_datagram_tunnel(");
    assert!(
        mtls_udp.contains("self.conn_admission("),
        "the mesh-mTLS datagram tunnel owns its physical connection"
    );

    let hbone_udp = method_body(hbone, "pub async fn get_datagram_tunnel(");
    assert!(
        hbone_udp.contains("self.conn_admission("),
        "the HBONE datagram tunnel owns its physical connection"
    );

    let mtls_pooled = method_body(mtls, "async fn get_or_create_sender(");
    assert!(
        mtls_pooled.contains("self.conn_admission("),
        "the pooled mesh-mTLS connection owns its physical connection"
    );

    let hbone_pooled = method_body(hbone, "async fn get_or_create_sender(");
    assert!(
        hbone_pooled.contains("self.conn_admission("),
        "the pooled HBONE tunnel owns its physical connection"
    );
}

/// Resolve the pooled admission lane for a capped destination.
///
/// A tiny wrapper so the call sites below stay readable; `resolve` returning
/// `None` here would mean the fixture itself is wrong, not the code under test.
fn pooled_lane<'a>(
    limiter: &'a BackendConnectionLimiter,
    proxy: &'a Proxy,
    host: &'a str,
    policy_port: u16,
) -> PooledConnectionAdmission<'a> {
    PooledConnectionAdmission::resolve(Some(limiter), proxy, host, policy_port)
        .expect("a capped destination must resolve a pooled admission lane")
}

// ============================================================================
// Raw TCP is on the SAME gateway-wide limiter as everything else
// ----------------------------------------------------------------------------
// `TcpProxyMetrics` is built once per stream LISTENER. Its `backend_inflight`
// field used to be an owned `BackendConnectionLimiter`, so every raw-TCP
// listener enforced a private copy of the cap while `ProxyState
// .backend_conn_limit` governed only the HTTP family. A raw-TCP socket plus a
// pooled/WebSocket socket could therefore exceed the configured ceiling, and two
// raw-TCP listeners could each get their own. These tests pin the field as a
// shared handle and pin the wiring that installs it.
// ============================================================================

/// Raw TCP admits through `TcpProxyMetrics.backend_inflight`; the pooled
/// transports admit through `PooledConnectionAdmission`. Given the ONE shared
/// limiter, both must land on the same `(host, policy port)` counter.
#[test]
fn raw_tcp_and_pooled_transports_share_one_destination_ceiling() {
    use ferrum_edge::proxy::tcp_proxy::TcpProxyMetrics;
    use std::sync::Arc;

    const CAP: u32 = 2;
    const POLICY_PORT: u16 = 80;

    let limiter = Arc::new(BackendConnectionLimiter::new());
    // Exactly how `StreamListenerManager` builds a listener's metrics.
    let metrics = Arc::new(TcpProxyMetrics::with_backend_conn_limit(limiter.clone()));

    let proxy = proxy_with_port_override(POLICY_PORT, Some(CAP), None);
    let pooled = pooled_lane(&limiter, &proxy, HOST_FQDN, POLICY_PORT);

    // One raw-TCP relay session takes the first of two slots.
    let tcp_slot = metrics
        .backend_inflight
        .try_acquire(HOST_FQDN, POLICY_PORT, Some(CAP))
        .expect("first raw-TCP session is under the cap")
        .expect("a capped destination hands out a guard");
    assert_eq!(
        limiter.current(HOST_FQDN, POLICY_PORT),
        1,
        "the raw-TCP session must be counted on the gateway-wide limiter, not a \
         private per-listener one"
    );

    // A pooled transport takes the second — it must SEE the raw-TCP socket.
    let pooled_slot = pooled
        .acquire()
        .expect("second connection to the destination is still under the cap");
    assert_eq!(limiter.current(HOST_FQDN, POLICY_PORT), 2);

    // The destination is now full for BOTH families.
    assert!(
        pooled.acquire().is_err(),
        "a pooled connection must be refused once raw TCP + pooled have filled \
         the destination's ceiling"
    );
    assert!(
        metrics
            .backend_inflight
            .try_acquire(HOST_FQDN, POLICY_PORT, Some(CAP))
            .is_err(),
        "a raw-TCP dial must be refused once the destination's ceiling is full, \
         even though the other slot belongs to a pooled transport"
    );

    // Retirement recovers, from either side.
    drop(tcp_slot);
    assert_eq!(limiter.current(HOST_FQDN, POLICY_PORT), 1);
    let recovered = pooled
        .acquire()
        .expect("a retired raw-TCP slot must free capacity for a pooled dial");
    drop(recovered);
    drop(pooled_slot);
    assert_eq!(
        limiter.current(HOST_FQDN, POLICY_PORT),
        0,
        "every slot must retire exactly once"
    );
}

/// Two stream listeners must not each get their own copy of the cap.
#[test]
fn two_raw_tcp_listeners_share_one_destination_ceiling() {
    use ferrum_edge::proxy::tcp_proxy::TcpProxyMetrics;
    use std::sync::Arc;

    const POLICY_PORT: u16 = 80;

    let limiter = Arc::new(BackendConnectionLimiter::new());
    let listener_a = Arc::new(TcpProxyMetrics::with_backend_conn_limit(limiter.clone()));
    let listener_b = Arc::new(TcpProxyMetrics::with_backend_conn_limit(limiter.clone()));

    let a_slot = listener_a
        .backend_inflight
        .try_acquire(HOST_FQDN, POLICY_PORT, Some(1))
        .expect("listener A is under the cap")
        .expect("guard present");
    assert!(
        listener_b
            .backend_inflight
            .try_acquire(HOST_FQDN, POLICY_PORT, Some(1))
            .is_err(),
        "a second stream listener must not get its own `maxConnections: 1`; the \
         cap is per destination, not per listener"
    );

    // Listener-local observability counters stay independent.
    listener_a
        .active_backend_connections
        .store(1, std::sync::atomic::Ordering::Relaxed);
    assert_eq!(
        listener_b
            .active_backend_connections
            .load(std::sync::atomic::Ordering::Relaxed),
        0,
        "sharing the admission counter must not merge per-listener metrics"
    );

    drop(a_slot);
    assert!(
        listener_b
            .backend_inflight
            .try_acquire(HOST_FQDN, POLICY_PORT, Some(1))
            .is_ok(),
        "listener B must be admitted once listener A's session retired"
    );
}

/// The wiring: `ProxyState` installs its limiter on the stream listener manager
/// before any reconcile, every spawned listener clones that instance, and the
/// install is one-shot so a reload/restart cannot swap the limiter out from
/// under relays whose guards are still counted.
#[test]
fn stream_listeners_are_wired_to_the_gateway_backend_conn_limit() {
    const PROXY_SOURCE: &str = include_str!("../../src/proxy/mod.rs");
    const STREAM_SOURCE: &str = include_str!("../../src/proxy/stream_listener.rs");
    const TCP_SOURCE: &str = include_str!("../../src/proxy/tcp_proxy.rs");

    assert!(
        PROXY_SOURCE.contains("stream_listener_manager.attach_backend_conn_limit("),
        "ProxyState must hand the stream listener manager the SAME limiter the \
         HTTP-family transports use; without it every raw-TCP listener enforces \
         a private copy of maxConnections"
    );
    // The spawn site itself: a listener's metrics come from the manager's
    // shared limiter, not from `TcpProxyMetrics::default()` (which owns a
    // private one and is reserved for standalone/test constructors).
    assert!(
        STREAM_SOURCE.contains("let conn_limit = self.backend_conn_limit();")
            && STREAM_SOURCE.contains("TcpProxyMetrics::with_backend_conn_limit(conn_limit)"),
        "the spawned stream listener must build its metrics from the manager's \
         shared limiter, not from `TcpProxyMetrics::default()`, so every \
         listener shares the gateway-wide counter"
    );
    assert!(
        TCP_SOURCE.contains("pub backend_inflight: Arc<BackendConnectionLimiter>"),
        "TcpProxyMetrics.backend_inflight must be a shared handle, not an owned \
         per-listener limiter"
    );
    // One-shot install: a config reload or listener restart must not replace a
    // limiter that live `BackendConnectionGuard`s are still counted against.
    assert!(
        STREAM_SOURCE
            .contains("backend_conn_limit: std::sync::OnceLock<SharedBackendConnectionLimiter>"),
        "the manager's limiter slot must be a OnceLock so it can never be \
         replaced while open guards exist"
    );
    let attach = STREAM_SOURCE
        .split("pub fn attach_backend_conn_limit(")
        .nth(1)
        .expect("attach_backend_conn_limit must exist");
    let attach_body: String = attach.chars().take(400).collect();
    assert!(
        attach_body.contains("self.backend_conn_limit.set("),
        "attaching must be a one-shot `OnceLock::set`, not a swap"
    );
}

// ============================================================================
// One destination, one counter key — host normalization lives in the limiter
// ----------------------------------------------------------------------------
// The callers disagree on how a host is spelled: raw TCP / WebSocket / the
// direct pools pass the configured `Upstream`/`UpstreamTarget` host verbatim,
// while reqwest's connector sees a URL-normalized authority (bracketed IPv6
// literal, lowercased registered name). Normalizing at only one of them split
// `Backend.Example` from `backend.example` and `[::1]` from `::1` into two
// counters for ONE destination — an effective 2x ceiling.
// ============================================================================

#[test]
fn limiter_keys_one_destination_regardless_of_host_spelling() {
    const CAP: u32 = 1;
    const PORT: u16 = 80;

    // Case: the configured host vs. the lowercased authority reqwest sees.
    let limiter = BackendConnectionLimiter::new();
    let configured = limiter
        .try_acquire("Backend.Example", PORT, Some(CAP))
        .expect("first connection is under the cap")
        .expect("guard present");
    assert!(
        limiter
            .try_acquire("backend.example", PORT, Some(CAP))
            .is_err(),
        "a case-different spelling of the SAME destination must not get its own \
         counter — that is an effective 2x ceiling"
    );
    assert_eq!(
        limiter.current("backend.example", PORT),
        1,
        "the diagnostic lookup must normalize the same way the acquire path does"
    );
    assert_eq!(
        limiter.current("BACKEND.EXAMPLE", PORT),
        1,
        "and it must do so for any spelling"
    );
    drop(configured);
    assert_eq!(limiter.current("Backend.Example", PORT), 0);

    // Case: an IPv6 literal, bracketed by the URL form and bare in config.
    let limiter = BackendConnectionLimiter::new();
    let bare = limiter
        .try_acquire("::1", PORT, Some(CAP))
        .expect("first connection is under the cap")
        .expect("guard present");
    assert!(
        limiter.try_acquire("[::1]", PORT, Some(CAP)).is_err(),
        "the bracketed URL form of an IPv6 literal is the same destination as \
         the bare configured form"
    );
    assert_eq!(limiter.current("[::1]", PORT), 1);
    drop(bare);
    assert_eq!(limiter.current("[::1]", PORT), 0);

    // Distinct destinations must still be distinct.
    let limiter = BackendConnectionLimiter::new();
    let _a = limiter
        .try_acquire("a.example", PORT, Some(CAP))
        .expect("a is under its own cap")
        .expect("guard present");
    assert!(
        limiter
            .try_acquire("b.example", PORT, Some(CAP))
            .is_ok_and(|guard| guard.is_some()),
        "normalization must not collapse different destinations onto one lane"
    );
}

/// Cross-caller: the shared limiter must see a raw-TCP session and a pooled
/// dial to the same destination as one lane even when they spell the host
/// differently — the exact split the reqwest connector's own normalization used
/// to hide.
#[test]
fn raw_tcp_and_pooled_admission_share_a_lane_across_host_spellings() {
    use ferrum_edge::proxy::tcp_proxy::TcpProxyMetrics;
    use std::sync::Arc;

    const POLICY_PORT: u16 = 80;
    // `UpstreamTarget.host` as an operator might write it in config.
    const CONFIGURED: &str = "WS.Default.SVC.Cluster.Local";
    // The same destination as a URL authority would carry it.
    const NORMALIZED: &str = "ws.default.svc.cluster.local";

    let limiter = Arc::new(BackendConnectionLimiter::new());
    let metrics = Arc::new(TcpProxyMetrics::with_backend_conn_limit(limiter.clone()));

    let tcp_slot = metrics
        .backend_inflight
        .try_acquire(CONFIGURED, POLICY_PORT, Some(1))
        .expect("raw TCP is under the cap")
        .expect("guard present");

    let proxy = proxy_with_port_override(POLICY_PORT, Some(1), None);
    let pooled = pooled_lane(&limiter, &proxy, NORMALIZED, POLICY_PORT);
    assert!(
        pooled.acquire().is_err(),
        "the pooled dial must see the raw-TCP socket already occupying this \
         destination's only slot, despite the different host spelling"
    );

    drop(tcp_slot);
    assert!(
        pooled.acquire().is_ok(),
        "retiring the raw-TCP session must free the slot for the pooled dial"
    );
}
