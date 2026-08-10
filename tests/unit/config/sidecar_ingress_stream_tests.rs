//! External unit coverage for Sidecar `ingress[]` stream-family listeners
//! (issue #3260): resolve, protocol classification lock-step with the K8s
//! translator predicates, carrier decode fail-closure, the authenticated
//! mesh-mTLS CONNECT remap onto `defaultEndpoint`, and bind-contract
//! documentation (#3266 boundary).

use ferrum_edge::modes::mesh::config::MeshConfig;
use ferrum_edge::modes::mesh::config::ResolvedIngressListener;
use ferrum_edge::modes::mesh::config::SidecarIngressConnectRelay as Remap;
use ferrum_edge::modes::mesh::config::{
    AppProtocol, IngressListenerUnsupported, MeshSidecarIngress, is_http_family_app_protocol,
    is_modeled_ingress_app_protocol, is_stream_family_app_protocol,
};

fn entry(port: u16, protocol: AppProtocol, endpoint: &str) -> MeshSidecarIngress {
    MeshSidecarIngress {
        port,
        protocol,
        name: None,
        bind: None,
        default_endpoint: endpoint.to_string(),
    }
}

/// This workload's own pod address, as the slice declares it.
const POD_IP: &str = "10.244.1.7";

fn resolved(
    port: u16,
    protocol: AppProtocol,
    endpoint_host: &str,
    endpoint_port: u16,
) -> ResolvedIngressListener {
    ResolvedIngressListener {
        port,
        endpoint_host: endpoint_host.to_string(),
        endpoint_port,
        protocol,
        endpoint_unix_path: None,
        endpoint_unix_h2c: false,
        owner_namespace: "default".to_string(),
        owner_service: "redis".to_string(),
    }
}

/// The canonical #3260 listener: declared `16379` → `defaultEndpoint`
/// `127.0.0.1:6379` (the two ports deliberately differ).
fn redis_listener() -> ResolvedIngressListener {
    resolved(16379, AppProtocol::Redis, "127.0.0.1", 6379)
}

fn expected_relay() -> Remap {
    Remap::Relay {
        listener_port: 16379,
        endpoint_host: "127.0.0.1".to_string(),
        endpoint_port: 6379,
    }
}

/// A prepared local mesh view: this workload owns `POD_IP` and declares the
/// given resolved ingress listeners.
fn local_mesh(listeners: Vec<ResolvedIngressListener>) -> MeshConfig {
    MeshConfig {
        local_ingress_listeners: listeners,
        sidecar_ingress_declared: true,
        local_workload_addresses: vec![POD_IP.parse().expect("test pod IP")],
        ..MeshConfig::default()
    }
}

/// The authenticated inbound CONNECT boundary's resolution.
fn remap(mesh: &MeshConfig, host: &str, port: u16) -> Remap {
    mesh.resolve_sidecar_ingress_connect_relay(
        host,
        port,
        Some(POD_IP.parse().expect("test pod IP")),
    )
}

/// The post-plugin effective-destination re-check for a remapped relay.
fn endpoint_ok(mesh: &MeshConfig, listener: u16, host: &str, port: u16) -> bool {
    mesh.sidecar_ingress_connect_relay_endpoint_matches(listener, host, port)
}

fn decode_carrier(json: &str) -> ResolvedIngressListener {
    serde_json::from_str(json).expect("carrier entry decodes")
}

/// A carrier entry whose `protocol` field the source OMITTED.
const PROTOCOL_LESS_CARRIER: &str = r#"{
    "port": 16379,
    "endpoint_host": "127.0.0.1",
    "endpoint_port": 6379,
    "owner_namespace": "default",
    "owner_service": "redis"
}"#;

const UDP_CARRIER: &str = r#"{
    "port": 16379,
    "endpoint_host": "127.0.0.1",
    "endpoint_port": 6379,
    "protocol": "udp",
    "owner_namespace": "default",
    "owner_service": "redis"
}"#;

const UNKNOWN_CARRIER: &str = r#"{
    "port": 16379,
    "endpoint_host": "127.0.0.1",
    "endpoint_port": 6379,
    "protocol": "unknown",
    "owner_namespace": "default",
    "owner_service": "redis"
}"#;

#[test]
fn stream_family_protocols_partition_from_http_and_unknown() {
    for protocol in [
        AppProtocol::Tcp,
        AppProtocol::Tls,
        AppProtocol::Mongo,
        AppProtocol::Redis,
        AppProtocol::Mysql,
        AppProtocol::Postgres,
    ] {
        assert!(is_stream_family_app_protocol(protocol));
        assert!(!is_http_family_app_protocol(protocol));
        assert!(is_modeled_ingress_app_protocol(protocol));
    }
    for protocol in [AppProtocol::Http, AppProtocol::Http2, AppProtocol::Grpc] {
        assert!(is_http_family_app_protocol(protocol));
        assert!(!is_stream_family_app_protocol(protocol));
        assert!(is_modeled_ingress_app_protocol(protocol));
    }
    assert!(!is_modeled_ingress_app_protocol(AppProtocol::Unknown));
    assert!(!is_modeled_ingress_app_protocol(AppProtocol::Udp));
}

#[test]
fn stream_ingress_resolves_loopback_and_preserves_protocol() {
    let resolved = entry(16379, AppProtocol::Redis, "127.0.0.1:6379")
        .resolve()
        .expect("redis ingress resolves");
    assert_eq!(resolved.port, 16379);
    assert_eq!(resolved.endpoint_port, 6379);
    assert_eq!(resolved.protocol, AppProtocol::Redis);
    assert!(resolved.is_stream_family());
}

#[test]
fn stream_ingress_maps_instance_ip_wildcard_to_loopback() {
    let resolved = entry(9000, AppProtocol::Tcp, "0.0.0.0:6000")
        .resolve()
        .expect("instance-IP TCP ingress resolves");
    assert_eq!(resolved.endpoint_host, "127.0.0.1");
    assert_eq!(resolved.endpoint_port, 6000);
}

#[test]
fn stream_ingress_rejects_unix_and_off_box_endpoints() {
    assert_eq!(
        entry(9000, AppProtocol::Tcp, "unix:///var/run/app.sock").resolve(),
        Err(IngressListenerUnsupported::UnixProtocolUnsupported)
    );
    assert_eq!(
        entry(9000, AppProtocol::Tcp, "10.0.0.5:6000").resolve(),
        Err(IngressListenerUnsupported::UnparseableEndpoint)
    );
}

#[test]
fn custom_bind_is_preserved_but_does_not_affect_resolve() {
    // Issue #3266 boundary: custom bind is observability-only under the
    // shared :15006 capture contract required by #3260. Resolve still keys
    // off port + protocol + defaultEndpoint.
    let mut with_bind = entry(9000, AppProtocol::Tcp, "127.0.0.1:6000");
    with_bind.bind = Some("127.0.0.1".to_string());
    let resolved = with_bind.resolve().expect("bind does not block resolve");
    assert_eq!(resolved.port, 9000);
    assert_eq!(resolved.endpoint_port, 6000);
}

// ── Carrier decode boundary ───────────────────────────────────────────────

/// The ECDS / native `LocalIngressListeners` carrier is untrusted wire JSON.
/// An OMITTED `protocol` must never mean "HTTP listener": it decodes to
/// `Unknown` and is inert on BOTH lanes, exactly like an explicitly hostile
/// `udp`. Without this, omitting one field on the wire silently manufactures a
/// live HTTP listener on the declared port.
#[test]
fn carried_listener_without_protocol_decodes_unknown_and_stays_inert() {
    let carried = decode_carrier(PROTOCOL_LESS_CARRIER);

    assert_eq!(
        carried.protocol,
        AppProtocol::Unknown,
        "an omitted carrier protocol must not default to a live HTTP listener"
    );
    assert!(
        !carried.endpoint_is_valid(&[]),
        "an Unknown-protocol carrier entry must fail the shared validity gate \
         the back-projection chokepoint and the materializer both apply"
    );
    assert!(!carried.is_http_family());
    assert!(!carried.is_stream_family());

    // ...and it is inert at the authenticated CONNECT boundary too.
    let mesh = local_mesh(vec![carried]);
    assert_eq!(remap(&mesh, POD_IP, 16379), Remap::Deny);
    assert!(!endpoint_ok(&mesh, 16379, "127.0.0.1", 6379));
}

#[test]
fn carried_listener_with_hostile_protocol_stays_inert() {
    for json in [UDP_CARRIER, UNKNOWN_CARRIER] {
        let carried = decode_carrier(json);
        assert!(!carried.endpoint_is_valid(&[]));
        let mesh = local_mesh(vec![carried]);
        assert_eq!(remap(&mesh, POD_IP, 16379), Remap::Deny);
        assert!(!endpoint_ok(&mesh, 16379, "127.0.0.1", 6379));
    }
}

#[test]
fn resolved_listener_protocol_round_trips_on_the_carrier() {
    let listener = redis_listener();
    let encoded = serde_json::to_string(&listener).expect("serialize");
    let decoded = decode_carrier(&encoded);
    assert_eq!(decoded, listener, "protocol must survive the carrier");
    assert!(decoded.endpoint_is_valid(&[]));
}

// ── Authenticated mesh-mTLS CONNECT remap (issue #3260) ───────────────────

/// The identity-protected Sidecar inbound path is a fresh mesh-mTLS H2 CONNECT
/// to `:15006`, which never reaches the REDIRECT-captured
/// `local_inbound_tcp_routes` table. An authenticated CONNECT for a declared
/// stream ingress listener must therefore be remapped here (`pod-ip:16379` →
/// `127.0.0.1:6379`) while authorization stays keyed to the DECLARED listener
/// port so a listener-scoped `AuthorizationPolicy` DENY still fires.
#[test]
fn authenticated_connect_maps_declared_listener_port_to_default_endpoint() {
    let mesh = local_mesh(vec![redis_listener()]);

    assert_eq!(
        remap(&mesh, POD_IP, 16379),
        expected_relay(),
        "the declared listener port must relay to defaultEndpoint, not itself"
    );
    // The backend port alone selects nothing: only the DECLARED listener port
    // is the match key, mirroring the direct-capture `mesh_tcp_inbound` table.
    assert_eq!(remap(&mesh, POD_IP, 6379), Remap::Deny);
}

#[test]
fn connect_remap_folds_ipv4_mapped_local_addresses() {
    let mesh = local_mesh(vec![redis_listener()]);
    assert!(mesh.host_is_local_service_workload_address("::ffff:10.244.1.7"));
    let mapped = remap(&mesh, "::ffff:10.244.1.7", 16379);
    assert_eq!(mapped, expected_relay());
}

/// The authority must positively identify THIS workload. Sharing a port number
/// with a declared listener is not permission to remap a sibling replica's, or
/// a bare loopback, destination onto our application.
#[test]
fn connect_remap_refuses_foreign_and_loopback_authorities() {
    let mut mesh = local_mesh(vec![redis_listener()]);
    // Local-service resolution can include sibling replicas. Reaching this
    // pod's socket does not authorize an authority naming the sibling.
    mesh.local_workload_addresses
        .push("10.244.1.9".parse().expect("sibling pod IP"));

    for hostile in ["10.244.1.9", "127.0.0.1", "redis.default.svc"] {
        assert_eq!(
            remap(&mesh, hostile, 16379),
            Remap::Deny,
            "authority {hostile} does not identify this workload"
        );
    }

    // No local identity resolved at all ⇒ nothing can be remapped.
    let anonymous = MeshConfig {
        local_ingress_listeners: vec![redis_listener()],
        sidecar_ingress_declared: true,
        ..MeshConfig::default()
    };
    assert_eq!(remap(&anonymous, POD_IP, 16379), Remap::Deny);
}

#[test]
fn connect_remap_refuses_ambiguous_ownerless_and_non_stream_listeners() {
    // Ambiguity: two entries claim the same declared port. Picking one by
    // iteration order would let a hostile carrier choose the mapping.
    let ambiguous = local_mesh(vec![
        redis_listener(),
        resolved(16379, AppProtocol::Redis, "127.0.0.1", 7000),
    ]);
    assert_eq!(remap(&ambiguous, POD_IP, 16379), Remap::Deny);
    assert!(!endpoint_ok(&ambiguous, 16379, "127.0.0.1", 6379));

    // Missing owner stamp: no local service anchors the listener.
    let mut ownerless = redis_listener();
    ownerless.owner_service = String::new();
    let mesh = local_mesh(vec![ownerless]);
    assert_eq!(remap(&mesh, POD_IP, 16379), Remap::Deny);
    assert!(!endpoint_ok(&mesh, 16379, "127.0.0.1", 6379));

    // Off-box / zero-port endpoints the raw resolution path would have deferred.
    for bad in [
        resolved(16379, AppProtocol::Redis, "10.0.0.5", 6379),
        resolved(16379, AppProtocol::Redis, "127.0.0.1", 0),
    ] {
        let mesh = local_mesh(vec![bad]);
        assert_eq!(remap(&mesh, POD_IP, 16379), Remap::Deny);
    }

    // HTTP-family listeners are served by their materialized `__mesh-ingress-*`
    // HTTP route; a bare byte-stream CONNECT naming one is refused rather than
    // relayed to the listener port the operator replaced.
    for http in [AppProtocol::Http, AppProtocol::Http2, AppProtocol::Grpc] {
        let mesh = local_mesh(vec![resolved(8443, http, "127.0.0.1", 8080)]);
        assert_eq!(
            remap(&mesh, POD_IP, 8443),
            Remap::Deny,
            "{http:?} ingress must not take the raw-stream remap"
        );
    }
}

/// Once Sidecar ingress is declared, it replaces the ordinary inbound surface.
/// Unlisted ports must not fall through to the transparent relay, including
/// explicit-empty and all-invalid listener sets.
#[test]
fn connect_remap_declared_block_denies_unlisted_and_unresolved_ports() {
    let mesh = local_mesh(vec![redis_listener()]);
    for port in [8080u16, 15008, 1] {
        assert_eq!(remap(&mesh, POD_IP, port), Remap::Deny);
    }
    assert_eq!(remap(&local_mesh(Vec::new()), POD_IP, 16379), Remap::Deny);
}

/// Withdrawal (reload / update / delete / xDS carrier removal) must not leave a
/// stale mapping or declaration behind: the resolution AND the post-plugin
/// re-check both read the live prepared view, so removing the Sidecar block
/// restores ordinary relay behavior without preserving the old endpoint.
#[test]
fn connect_remap_withdrawal_leaves_no_stale_routing() {
    let declared = local_mesh(vec![redis_listener()]);
    assert_eq!(remap(&declared, POD_IP, 16379), expected_relay());

    let withdrawn = MeshConfig {
        local_workload_addresses: vec![POD_IP.parse().expect("test pod IP")],
        ..MeshConfig::default()
    };
    assert_eq!(remap(&withdrawn, POD_IP, 16379), Remap::NotDeclared);
    assert!(
        !endpoint_ok(&withdrawn, 16379, "127.0.0.1", 6379),
        "a withdrawn listener must not keep authorizing its old backend dial"
    );
}

/// Post-plugin re-check: only the exact declared mapping survives, so a
/// `mesh_route_dispatch` route override (or an upstream selection) cannot widen
/// the remapped destination before the dial.
#[test]
fn connect_remap_effective_destination_admits_only_the_declared_mapping() {
    let mesh = local_mesh(vec![redis_listener()]);

    assert!(endpoint_ok(&mesh, 16379, "127.0.0.1", 6379));
    // A widened port, a different backend, an off-box override, the declared
    // listener port itself, and an unknown listener port all fail closed.
    assert!(!endpoint_ok(&mesh, 16379, "127.0.0.1", 16379));
    assert!(!endpoint_ok(&mesh, 16379, "127.0.0.1", 5432));
    assert!(!endpoint_ok(&mesh, 16379, "10.0.0.5", 6379));
    assert!(!endpoint_ok(&mesh, 16379, POD_IP, 6379));
    assert!(!endpoint_ok(&mesh, 9999, "127.0.0.1", 6379));
}
