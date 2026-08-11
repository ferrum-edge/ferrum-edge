//! Istio ServiceEntry + egress materialization conformance.
//!
//! Exercises:
//!   - `ServiceEntry` translation through `translate_k8s_objects`
//!     (`location: MESH_EXTERNAL` vs `MESH_INTERNAL`, multi-port, multi-host).
//!   - Egress gateway materialization of HTTP-family + stream-family
//!     ServiceEntries (T5-A, PR #907) via `prepare_gateway_config_for_mesh`.
//!   - `outboundTrafficPolicy: REGISTRY_ONLY` injects the
//!     `mesh_outbound_registry` plugin on topologies with an outbound capture
//!     listener (T5-B, PR #893).

use std::collections::HashMap;
use std::net::SocketAddr;

use ferrum_edge::capture::CaptureMode;
use ferrum_edge::config::types::{BackendScheme, GatewayConfig};
use ferrum_edge::config_sources::k8s::{
    K8sMetadata, K8sObject, K8sTranslationOptions, translate_k8s_objects,
};
use ferrum_edge::identity::spiffe::TrustDomain;
use ferrum_edge::modes::mesh::config::{
    AppProtocol, MeshConfig, MeshEgressUdpDialEndpoint, MeshEndpoint, OutboundTrafficPolicy,
    Resolution, ServiceEntry, ServiceEntryLocation, ServicePort,
};
use ferrum_edge::modes::mesh::{
    MESH_OUTBOUND_REGISTRY_PLUGIN_ID, MeshConfigProtocol, MeshEgressGatewayEndpoint,
    MeshRuntimeConfig, MeshTopology, prepare_gateway_config_for_mesh,
};
use serde_json::{Value, json};

use crate::conformance::registry::Status;

const CATEGORY: &str = "istio_service_entry_egress";

fn options() -> K8sTranslationOptions {
    K8sTranslationOptions::new(
        "default".to_string(),
        TrustDomain::new("cluster.local").expect("test trust domain"),
    )
}

fn service_entry(name: &str, spec: Value) -> K8sObject {
    K8sObject {
        api_version: "networking.istio.io/v1beta1".to_string(),
        kind: "ServiceEntry".to_string(),
        metadata: K8sMetadata {
            name: name.to_string(),
            namespace: "default".to_string(),
            ..K8sMetadata::default()
        },
        spec,
        status: Value::Object(serde_json::Map::new()),
    }
}

fn egress_runtime() -> MeshRuntimeConfig {
    MeshRuntimeConfig {
        node_id: "conformance-egress".to_string(),
        namespace: "default".to_string(),
        cp_urls: vec!["http://127.0.0.1:1".to_string()],
        config_protocol: MeshConfigProtocol::Native,
        file_config_path: None,
        stock_xds_urls: Vec::new(),
        stock_xds_node_id: None,
        stock_xds_node_metadata: Default::default(),
        stock_xds_token_file: None,
        stock_xds_limits: Default::default(),
        topology: MeshTopology::EgressGateway,
        inbound_listen_addr: "127.0.0.1:0".parse::<SocketAddr>().unwrap(),
        outbound_listen_addr: "127.0.0.1:0".parse::<SocketAddr>().unwrap(),
        hbone_listen_addr: "127.0.0.1:0".parse::<SocketAddr>().unwrap(),
        east_west_listen_port: 15443,
        egress_hbone_port: 15008,
        egress_mtls_port: 15006,
        egress_listen_addr: "127.0.0.1:15090".parse::<SocketAddr>().unwrap(),
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
        dns_listen_addr: "127.0.0.1:15053".parse::<SocketAddr>().unwrap(),
        dns_upstream_addr: "127.0.0.53:53".parse::<SocketAddr>().unwrap(),
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
        egress_stream_enabled: true,
        egress_stream_allow_plaintext: false,
        request_auth_require_exp: true,
        locality_lb_strict: false,
    }
}

fn sidecar_runtime_with_policy(policy: OutboundTrafficPolicy) -> MeshRuntimeConfig {
    let mut rt = egress_runtime();
    rt.topology = MeshTopology::Sidecar;
    rt.outbound_traffic_policy = policy;
    // mesh_outbound_registry plugin is only injected when at least one
    // outbound capture listener exists (mesh_outbound_registry_listen_ports
    // filters port != 0). Use the documented default sidecar capture port
    // 15001 so the plugin auto-injection path runs.
    rt.outbound_listen_addr = "127.0.0.1:15001".parse::<SocketAddr>().unwrap();
    rt
}

fn external_se(name: &str, hosts: Vec<&str>, port: u16, protocol: &str) -> K8sObject {
    service_entry(
        name,
        json!({
            "hosts": hosts,
            "location": "MESH_EXTERNAL",
            "resolution": "DNS",
            "ports": [{
                "number": port,
                "name": protocol.to_lowercase(),
                "protocol": protocol
            }]
        }),
    )
}

fn build_mesh_config_from(translation_input: &[K8sObject]) -> GatewayConfig {
    let translation =
        translate_k8s_objects(translation_input, options()).expect("translation succeeds");
    translation.config
}

/// `ServiceEntry` with `location: MESH_EXTERNAL` translates with the right
/// location tag.
#[test]
fn se_mesh_external_translates() {
    register_feature!(
        category = CATEGORY,
        feature = "location: MESH_EXTERNAL",
        status = Status::Supported,
        notes = "Marks the entry as eligible for egress gateway materialization.",
    );
    let config =
        build_mesh_config_from(&[external_se("api", vec!["api.external.com"], 443, "TLS")]);
    let mesh = config.mesh.expect("mesh config");
    let se = mesh.service_entries.first().expect("one SE");
    assert_eq!(se.location, ServiceEntryLocation::MeshExternal);
    assert_eq!(se.hosts, vec!["api.external.com".to_string()]);
    assert_eq!(se.ports[0].protocol, AppProtocol::Tls);
}

/// `ServiceEntry` with `location: MESH_INTERNAL` translates with the right
/// tag — and the egress materializer skips it.
#[test]
fn se_mesh_internal_skipped_by_egress() {
    register_feature!(
        category = CATEGORY,
        feature = "location: MESH_INTERNAL skipped by egress materialization",
        status = Status::Supported,
        notes = "Only MESH_EXTERNAL entries materialize as egress proxies; internal entries flow through the registry instead.",
    );
    let translation = translate_k8s_objects(
        &[service_entry(
            "internal",
            json!({
                "hosts": ["api.internal"],
                "location": "MESH_INTERNAL",
                "resolution": "DNS",
                "ports": [{"number": 8080, "name": "http", "protocol": "HTTP"}]
            }),
        )],
        options(),
    )
    .expect("translation succeeds");

    let prepared =
        prepare_gateway_config_for_mesh(translation.config, &egress_runtime()).expect("mesh apply");

    // No egress proxy for the internal entry. (The host `api.internal` would
    // encode into an egress id as `api_dot_internal` under the injective id
    // scheme; assert that token is absent.)
    assert!(
        prepared
            .proxies
            .iter()
            .all(|p| !p.id.contains("api_dot_internal")),
        "MESH_INTERNAL entry must not materialize as an egress proxy"
    );
}

/// HTTP-family ServiceEntry materializes one egress proxy per host on the
/// shared 15090 listener.
#[test]
fn se_http_egress_materializes() {
    register_feature!(
        category = CATEGORY,
        feature = "HTTP-family egress materialization",
        status = Status::Supported,
        notes = "TLS/HTTP/HTTP2/GRPC protocols map to one host-routed HTTP-family proxy on the shared egress listener.",
    );
    let translation = translate_k8s_objects(
        &[external_se("api", vec!["api.external.com"], 443, "TLS")],
        options(),
    )
    .expect("translation succeeds");
    let prepared =
        prepare_gateway_config_for_mesh(translation.config, &egress_runtime()).expect("mesh apply");

    let egress = prepared
        .proxies
        .iter()
        .find(|p| p.id.starts_with("mesh-egress"))
        .expect("HTTP egress proxy materialized");
    assert!(
        egress.hosts.iter().any(|h| h == "api.external.com"),
        "HTTP egress proxy must carry the SE host"
    );
    assert_eq!(egress.backend_scheme, Some(BackendScheme::Https));
    assert!(
        egress.listen_port.is_none(),
        "HTTP-family egress proxies route by host, not port"
    );
}

/// Stream-family ServiceEntry — T5-A (PR #907). `TCP` protocol materializes
/// as a TCP listener on the entry's own destination port.
#[test]
fn se_tcp_egress_materializes_as_stream_proxy() {
    register_feature!(
        category = CATEGORY,
        feature = "TCP ServiceEntry → stream egress proxy (T5-A)",
        status = Status::Supported,
        notes = "T5-A (PR #907): TCP protocols bind their own listen_port; backend_scheme=Tcp; hosts=[].",
    );
    let translation = translate_k8s_objects(
        &[external_se(
            "kafka",
            vec!["kafka.external.com"],
            9092,
            "TCP",
        )],
        options(),
    )
    .expect("translation succeeds");
    let prepared =
        prepare_gateway_config_for_mesh(translation.config, &egress_runtime()).expect("mesh apply");

    let stream = prepared
        .proxies
        .iter()
        .find(|p| p.listen_port == Some(9092))
        .expect("TCP stream egress proxy must bind on the SE port");
    assert_eq!(stream.backend_scheme, Some(BackendScheme::Tcp));
    assert!(stream.hosts.is_empty(), "stream proxies route by port");
    assert!(stream.listen_path.is_none());
}

/// Stream-family ServiceEntry: database protocols (Mongo, Mysql, Postgres,
/// Redis) all map to TCP egress per T5-A. Spot-check Mongo + Postgres.
#[test]
fn se_database_protocols_egress_materialize_as_stream_proxies() {
    register_feature!(
        category = CATEGORY,
        feature = "Mongo/Mysql/Postgres/Redis ServiceEntry → stream egress proxy (T5-A)",
        status = Status::Supported,
        notes = "T5-A (PR #907): each database protocol binds its own listen_port; no protocol-aware wire mediation (T5-C).",
    );
    let translation = translate_k8s_objects(
        &[
            external_se("mongo", vec!["mongo.external.com"], 27017, "MONGO"),
            external_se("pg", vec!["pg.external.com"], 5432, "POSTGRES"),
        ],
        options(),
    )
    .expect("translation succeeds");
    let prepared =
        prepare_gateway_config_for_mesh(translation.config, &egress_runtime()).expect("mesh apply");

    assert!(
        prepared
            .proxies
            .iter()
            .any(|p| p.listen_port == Some(27017)),
        "Mongo egress proxy on 27017"
    );
    assert!(
        prepared.proxies.iter().any(|p| p.listen_port == Some(5432)),
        "Postgres egress proxy on 5432"
    );
}

/// REGISTRY_ONLY policy injects the `mesh_outbound_registry` plugin on
/// Sidecar topology — T5-B (PR #893).
#[test]
fn outbound_traffic_policy_registry_only_injects_plugin() {
    register_feature!(
        category = CATEGORY,
        feature = "outboundTrafficPolicy: REGISTRY_ONLY injects mesh_outbound_registry",
        status = Status::Supported,
        notes = "T5-B (PR #893): plugin is auto-injected on topologies with an outbound capture listener and rejects unknown destinations.",
    );
    let config = GatewayConfig {
        mesh: Some(Box::new(MeshConfig {
            service_entries: vec![ServiceEntry {
                name: "known".to_string(),
                namespace: "default".to_string(),
                hosts: vec!["api.external.com".to_string()],
                endpoints: Vec::new(),
                resolution: Resolution::Dns,
                location: ServiceEntryLocation::MeshExternal,
                ports: vec![ServicePort {
                    port: 443,
                    protocol: AppProtocol::Tls,
                    name: Some("https".to_string()),
                    target_port: None,
                }],
                export_to: Vec::new(),
                workload_selector: None,
            }],
            ..MeshConfig::default()
        })),
        ..GatewayConfig::default()
    };

    let runtime = sidecar_runtime_with_policy(OutboundTrafficPolicy::RegistryOnly);
    let prepared = prepare_gateway_config_for_mesh(config, &runtime).expect("mesh apply succeeds");

    assert!(
        prepared
            .plugin_configs
            .iter()
            .any(|p| p.id == MESH_OUTBOUND_REGISTRY_PLUGIN_ID),
        "REGISTRY_ONLY must inject the mesh_outbound_registry plugin"
    );
}

/// AllowAny policy does NOT inject the registry plugin — default behavior.
#[test]
fn outbound_traffic_policy_allow_any_omits_plugin() {
    register_feature!(
        category = CATEGORY,
        feature = "outboundTrafficPolicy: ALLOW_ANY (default) — no registry plugin",
        status = Status::Supported,
        notes =
            "Default behavior: unknown destinations flow through unblocked when policy=ALLOW_ANY.",
    );
    let config = GatewayConfig {
        mesh: Some(Box::new(MeshConfig::default())),
        ..GatewayConfig::default()
    };
    let runtime = sidecar_runtime_with_policy(OutboundTrafficPolicy::AllowAny);
    let prepared = prepare_gateway_config_for_mesh(config, &runtime).expect("mesh apply succeeds");

    assert!(
        prepared
            .plugin_configs
            .iter()
            .all(|p| p.id != MESH_OUTBOUND_REGISTRY_PLUGIN_ID),
        "ALLOW_ANY must NOT inject the mesh_outbound_registry plugin"
    );
}

/// `ServiceEntry` host normalization: hosts are lowercased at admission per
/// `Proxy.normalize_fields()` invariant.
#[test]
fn se_host_normalization() {
    register_feature!(
        category = CATEGORY,
        feature = "ServiceEntry hosts ASCII-lowercased at admission",
        status = Status::Supported,
        notes = "Hostname normalization invariant (CLAUDE.md Domain Model): ASCII-lowercase at every entry point.",
    );
    let config = build_mesh_config_from(&[external_se("api", vec!["API.EXAMPLE.com"], 443, "TLS")]);
    let se = config.mesh.unwrap().service_entries[0].clone();
    assert_eq!(se.hosts, vec!["api.example.com".to_string()]);
}

/// Istio `Sidecar.outboundTrafficPolicy` overrides the mesh-wide policy for the
/// workloads that `Sidecar` selects — issue #3262.
///
/// Both directions are exercised: a workload-scoped `REGISTRY_ONLY` arms the
/// registry gate over an `ALLOW_ANY` mesh, and a workload-scoped `ALLOW_ANY`
/// disarms it over a `REGISTRY_ONLY` mesh.
#[test]
fn sidecar_outbound_traffic_policy_overrides_the_mesh_wide_policy() {
    register_feature!(
        category = CATEGORY,
        feature = "Sidecar.outboundTrafficPolicy overrides MeshConfig.outboundTrafficPolicy",
        status = Status::Supported,
        notes = "Issue #3262: the applicable Sidecar's mode wins for its selected workloads, in both directions, under FERRUM_MESH_SIDECAR_ENFORCED (dry-run excluded).",
    );

    for (mesh_wide, sidecar_mode, expect_plugin) in [
        (
            OutboundTrafficPolicy::AllowAny,
            OutboundTrafficPolicy::RegistryOnly,
            true,
        ),
        (
            OutboundTrafficPolicy::RegistryOnly,
            OutboundTrafficPolicy::AllowAny,
            false,
        ),
    ] {
        let config = GatewayConfig {
            mesh: Some(Box::new(MeshConfig {
                sidecars: vec![ferrum_edge::modes::mesh::config::MeshSidecar {
                    name: "default-sidecar".to_string(),
                    namespace: "default".to_string(),
                    workload_selector: None,
                    egress_inherits_defaults: false,
                    egress: vec![ferrum_edge::modes::mesh::config::MeshSidecarEgress {
                        hosts: vec!["*/*".to_string()],
                        port: None,
                    }],
                    ingress_declared: false,
                    ingress: Vec::new(),
                    outbound_traffic_policy: Some(sidecar_mode),
                }],
                ..MeshConfig::default()
            })),
            ..GatewayConfig::default()
        };
        let mut runtime = sidecar_runtime_with_policy(mesh_wide);
        runtime.namespace = "default".to_string();
        runtime.sidecar_enforced = true;
        let prepared =
            prepare_gateway_config_for_mesh(config, &runtime).expect("mesh apply succeeds");
        let injected = prepared
            .plugin_configs
            .iter()
            .any(|p| p.id == MESH_OUTBOUND_REGISTRY_PLUGIN_ID);
        assert_eq!(
            injected,
            expect_plugin,
            "mesh-wide {mesh_wide:?} + Sidecar {sidecar_mode:?} must \
             {} the registry gate",
            if expect_plugin { "arm" } else { "disarm" }
        );
    }
}

/// A present-but-unrepresentable `Sidecar.outboundTrafficPolicy` is accepted and
/// enforced as `REGISTRY_ONLY` rather than rejected — issue #3262.
///
/// Rejecting the resource would drop its `egress` narrowing as well, widening
/// both the workload's service view and the registry derived from it.
#[test]
fn sidecar_unrepresentable_outbound_traffic_policy_fails_closed() {
    register_feature!(
        category = CATEGORY,
        feature = "Sidecar.outboundTrafficPolicy unsupported variants fail closed to REGISTRY_ONLY",
        status = Status::Supported,
        notes = "Issue #3262: unknown/non-string mode, non-object block, and egressProxy all enforce REGISTRY_ONLY with a field-specific deferred_fields entry; the Sidecar itself stays accepted. An omitted mode uses Istio's documented ALLOW_ANY default.",
    );

    let cases = [
        json!({ "mode": "ALOW_ANY" }),
        json!({ "mode": 1 }),
        json!("REGISTRY_ONLY"),
        json!({
            "mode": "ALLOW_ANY",
            "egressProxy": { "host": "istio-egressgateway.istio-system.svc.cluster.local" },
        }),
    ];
    for policy in cases {
        let object = K8sObject {
            api_version: "networking.istio.io/v1".to_string(),
            kind: "Sidecar".to_string(),
            metadata: K8sMetadata {
                name: "degraded".to_string(),
                uid: String::new(),
                namespace: "default".to_string(),
                generation: Some(1),
                labels: HashMap::new(),
                annotations: HashMap::new(),
                creation_timestamp: None,
                deletion_timestamp: None,
            },
            spec: json!({
                "egress": [{ "hosts": ["*/*"] }],
                "outboundTrafficPolicy": policy,
            }),
            status: Value::Object(serde_json::Map::new()),
        };
        let translation = translate_k8s_objects(&[object], options()).expect("translation");
        let mesh = translation.config.mesh.as_deref().expect("mesh block");
        assert_eq!(
            mesh.sidecars.len(),
            1,
            "the Sidecar must survive translation for {policy}"
        );
        assert_eq!(
            mesh.sidecars[0].outbound_traffic_policy,
            Some(OutboundTrafficPolicy::RegistryOnly),
            "{policy} must fail closed to REGISTRY_ONLY"
        );
        assert_eq!(
            mesh.sidecars[0].egress.len(),
            1,
            "{policy} must not cost the Sidecar its egress narrowing"
        );
    }
}

/// UDP ServiceEntry → EgressGateway datagram-over-mesh egress (issue #3263).
/// A `protocol: UDP` external port materializes a destination ADMISSION rather
/// than a listener or upstream: `MeshConfig.egress_udp_destinations` is what the
/// gateway's authenticated mesh CONNECT terminator consults.
#[test]
fn se_udp_egress_materializes_relay_destination_not_listener() {
    register_feature!(
        category = CATEGORY,
        feature = "UDP ServiceEntry → EgressGateway datagram-over-mesh destination (#3263)",
        status = Status::Supported,
        notes = "#3263: UDP external ports materialize `mesh.egress_udp_destinations`; no UDP/DTLS listener and no upstream, by design.",
    );
    let translation = translate_k8s_objects(
        &[external_se("dns", vec!["dns.external.com"], 53, "UDP")],
        options(),
    )
    .expect("translation succeeds");
    let prepared =
        prepare_gateway_config_for_mesh(translation.config, &egress_runtime()).expect("mesh apply");

    assert!(
        !prepared.proxies.iter().any(|p| p.listen_port == Some(53)),
        "UDP ServiceEntry must not bind an egress listener"
    );
    let mesh = prepared.mesh.as_deref().expect("prepared mesh block");
    assert_eq!(
        mesh.egress_udp_destinations
            .iter()
            .map(|destination| (
                destination.host.as_str(),
                destination.port,
                destination.dial_endpoints.clone()
            ))
            .collect::<Vec<_>>(),
        vec![(
            "dns.external.com",
            53,
            vec![MeshEgressUdpDialEndpoint {
                host: "dns.external.com".to_string(),
                port: 53,
            }]
        )],
    );
}

/// Reload/update/delete: the admission set is REBUILT and reassigned on every
/// apply, so withdrawing the ServiceEntry withdraws the admission and does not
/// leave a stale destination behind.
#[test]
fn se_udp_egress_destinations_are_withdrawn_on_reload() {
    register_feature!(
        category = CATEGORY,
        feature = "UDP egress destination allowlist is rebuilt per apply (#3263)",
        status = Status::Supported,
        notes = "#3263: an update that changes the port re-keys the admission; a delete clears it; a non-EgressGateway topology never admits.",
    );
    let initial = translate_k8s_objects(
        &[external_se("dns", vec!["dns.external.com"], 53, "UDP")],
        options(),
    )
    .expect("translation succeeds");
    let prepared =
        prepare_gateway_config_for_mesh(initial.config, &egress_runtime()).expect("mesh apply");
    assert_eq!(
        prepared
            .mesh
            .as_deref()
            .expect("mesh block")
            .egress_udp_destinations
            .len(),
        1
    );

    // Update: the operator moves the port. The old (host, 53) admission must
    // not survive alongside the new one.
    let updated = translate_k8s_objects(
        &[external_se("dns", vec!["dns.external.com"], 5353, "UDP")],
        options(),
    )
    .expect("translation succeeds");
    let prepared =
        prepare_gateway_config_for_mesh(updated.config, &egress_runtime()).expect("mesh apply");
    assert_eq!(
        prepared
            .mesh
            .as_deref()
            .expect("mesh block")
            .egress_udp_destinations
            .iter()
            .map(|destination| destination.port)
            .collect::<Vec<_>>(),
        vec![5353]
    );

    // Delete: no ServiceEntry at all leaves an EMPTY allowlist, which denies.
    let deleted = translate_k8s_objects(
        &[external_se(
            "kafka",
            vec!["kafka.external.com"],
            9092,
            "TCP",
        )],
        options(),
    )
    .expect("translation succeeds");
    let prepared =
        prepare_gateway_config_for_mesh(deleted.config, &egress_runtime()).expect("mesh apply");
    assert!(
        prepared
            .mesh
            .as_deref()
            .expect("mesh block")
            .egress_udp_destinations
            .is_empty(),
        "a withdrawn UDP ServiceEntry must withdraw its admission"
    );
}

/// Fail-closed by topology: the same UDP ServiceEntry admits nothing when the
/// process is not an EgressGateway.
#[test]
fn se_udp_egress_destinations_are_empty_off_egress_gateway() {
    register_feature!(
        category = CATEGORY,
        feature = "UDP egress destinations are EgressGateway-only (#3263)",
        status = Status::Supported,
        notes = "#3263: a Sidecar/Ambient process never publishes external UDP admissions, so its CONNECT terminator cannot relay to external hosts.",
    );
    let translation = translate_k8s_objects(
        &[external_se("dns", vec!["dns.external.com"], 53, "UDP")],
        options(),
    )
    .expect("translation succeeds");
    let prepared = prepare_gateway_config_for_mesh(
        translation.config,
        &sidecar_runtime_with_policy(OutboundTrafficPolicy::AllowAny),
    )
    .expect("mesh apply");

    assert!(
        prepared
            .mesh
            .as_deref()
            .expect("mesh block")
            .egress_udp_destinations
            .is_empty()
    );
}

/// Fail-closed by opt-in: with `FERRUM_MESH_EGRESS_STREAM_ENABLED=false` the UDP
/// ServiceEntry admits nothing — there is no plaintext-UDP fallback.
#[test]
fn se_udp_egress_destinations_require_stream_egress_opt_in() {
    register_feature!(
        category = CATEGORY,
        feature = "UDP egress destinations require FERRUM_MESH_EGRESS_STREAM_ENABLED (#3263)",
        status = Status::Supported,
        notes = "#3263: the datagram relay rides the same operator opt-in the TCP stream listeners do; off means denied, never plaintext.",
    );
    let translation = translate_k8s_objects(
        &[external_se("dns", vec!["dns.external.com"], 53, "UDP")],
        options(),
    )
    .expect("translation succeeds");
    let mut runtime = egress_runtime();
    runtime.egress_stream_enabled = false;
    let prepared =
        prepare_gateway_config_for_mesh(translation.config, &runtime).expect("mesh apply");

    assert!(
        prepared
            .mesh
            .as_deref()
            .expect("mesh block")
            .egress_udp_destinations
            .is_empty()
    );
}

// ── STATIC endpoint semantics + source-side producer (issue #3263) ─────────

fn static_udp_service_entry(
    name: &str,
    hosts: Vec<impl Into<String>>,
    port: u16,
    endpoints: Vec<impl Into<String>>,
) -> K8sObject {
    let hosts: Vec<String> = hosts.into_iter().map(Into::into).collect();
    let endpoints: Vec<String> = endpoints.into_iter().map(Into::into).collect();
    service_entry(
        name,
        json!({
            "hosts": hosts,
            "location": "MESH_EXTERNAL",
            "resolution": "STATIC",
            "endpoints": endpoints
                .iter()
                .map(|address| json!({"address": address}))
                .collect::<Vec<_>>(),
            "ports": [{"number": port, "name": "udp", "protocol": "UDP"}]
        }),
    )
}

/// A `Sidecar` source runtime with an explicitly configured, identity-pinned
/// EgressGateway.
fn sidecar_source_runtime_with_gateway() -> MeshRuntimeConfig {
    let mut rt = sidecar_runtime_with_policy(OutboundTrafficPolicy::AllowAny);
    rt.egress_gateway = Some(MeshEgressGatewayEndpoint {
        host: "ferrum-egress.istio-system.svc.cluster.local".to_string(),
        port: 15090,
        spiffe_id: "spiffe://cluster.local/ns/istio-system/sa/ferrum-egress"
            .parse()
            .expect("gateway spiffe id"),
    });
    rt
}

/// A `STATIC` ServiceEntry is dialed at its DECLARED endpoints, never by
/// resolving the service host: the admitted authority and the dial endpoints are
/// represented separately.
#[test]
fn se_udp_egress_static_authority_dials_declared_endpoints() {
    register_feature!(
        category = CATEGORY,
        feature = "STATIC UDP ServiceEntry dials endpoints[], never the authority host (#3263)",
        status = Status::Supported,
        notes = "#3263: authority and dial destination are separate; a STATIC host is never DNS-resolved by the relay, and an endpoint-IP authority dials only that endpoint.",
    );
    let translation = translate_k8s_objects(
        &[static_udp_service_entry(
            "ntp",
            vec!["ntp.external.com"],
            123,
            vec!["203.0.113.10", "203.0.113.11"],
        )],
        options(),
    )
    .expect("translation succeeds");
    let prepared =
        prepare_gateway_config_for_mesh(translation.config, &egress_runtime()).expect("mesh apply");
    let mesh = prepared.mesh.as_deref().expect("prepared mesh block");

    let host_admission = mesh
        .egress_udp_destinations
        .iter()
        .find(|destination| destination.host == "ntp.external.com")
        .expect("the service host is admitted as an authority");
    assert_eq!(
        host_admission
            .dial_endpoints
            .iter()
            .map(|endpoint| (endpoint.host.as_str(), endpoint.port))
            .collect::<Vec<_>>(),
        vec![("203.0.113.10", 123), ("203.0.113.11", 123)],
        "a STATIC host must dial its declared endpoints, not itself"
    );

    let endpoint_admission = mesh
        .egress_udp_destinations
        .iter()
        .find(|destination| destination.host == "203.0.113.11")
        .expect("each endpoint IP is admitted as an authority in its own right");
    assert_eq!(
        endpoint_admission
            .dial_endpoints
            .iter()
            .map(|endpoint| (endpoint.host.as_str(), endpoint.port))
            .collect::<Vec<_>>(),
        vec![("203.0.113.11", 123)],
        "an endpoint-IP authority must dial only the endpoint it names"
    );
}

/// A `STATIC` ServiceEntry whose endpoints are all unusable admits NOTHING —
/// falling back to resolving the authority would bypass STATIC semantics.
#[test]
fn se_udp_egress_static_without_usable_endpoints_admits_nothing() {
    register_feature!(
        category = CATEGORY,
        feature = "STATIC UDP ServiceEntry with no usable endpoint fails closed (#3263)",
        status = Status::Supported,
        notes = "#3263: no dialable endpoint means no admission; the relay never falls back to DNS-resolving a STATIC authority.",
    );
    let translation = translate_k8s_objects(
        &[static_udp_service_entry(
            "broken",
            vec!["broken.external.com"],
            123,
            vec!["not-an-ip.example"],
        )],
        options(),
    )
    .expect("translation succeeds");
    let prepared =
        prepare_gateway_config_for_mesh(translation.config, &egress_runtime()).expect("mesh apply");

    assert!(
        prepared
            .mesh
            .as_deref()
            .expect("mesh block")
            .egress_udp_destinations
            .is_empty()
    );
}

/// SOURCE side: a Sidecar with a configured EgressGateway materializes a
/// captured-datagram route per STATIC endpoint plus the identity-pinned upstream
/// that dials the gateway. Without it the ServiceEntry would stay inert.
#[test]
fn se_udp_source_side_routes_captured_datagrams_through_the_egress_gateway() {
    register_feature!(
        category = CATEGORY,
        feature = "Source-side external UDP egress to a configured EgressGateway (#3263)",
        status = Status::Supported,
        notes = "#3263: a Sidecar/Ambient source materializes a (endpoint IP, port) route whose single upstream target dials the configured gateway over SVID-mTLS, pinned to the gateway SPIFFE id, with the external endpoint as the CONNECT authority.",
    );
    let translation = translate_k8s_objects(
        &[static_udp_service_entry(
            "syslog",
            vec!["syslog.external.com"],
            514,
            vec!["203.0.113.7"],
        )],
        options(),
    )
    .expect("translation succeeds");
    let prepared =
        prepare_gateway_config_for_mesh(translation.config, &sidecar_source_runtime_with_gateway())
            .expect("mesh apply");
    let mesh = prepared.mesh.as_deref().expect("prepared mesh block");

    let route = mesh
        .external_udp_egress_routes
        .first()
        .expect("one source-side route per STATIC endpoint");
    assert_eq!(route.dest_ip, "203.0.113.7");
    assert_eq!(route.port, 514);
    assert_eq!(route.service_fqdn, "syslog.external.com");

    let upstream = prepared
        .upstreams
        .iter()
        .find(|upstream| upstream.id == route.upstream_id)
        .expect("the route's upstream materialized");
    let target = upstream
        .targets
        .first()
        .expect("one identity-pinned gateway target");
    assert_eq!(
        target.host, "ferrum-egress.istio-system.svc.cluster.local",
        "the source dials the CONFIGURED gateway, never the external destination"
    );
    assert_eq!(
        target.port, 514,
        "target.port is the CONNECT authority port (the ServiceEntry service port)"
    );
    assert_eq!(
        target.tags.get("mesh.mtls").map(String::as_str),
        Some("true")
    );
    assert_eq!(
        target.tags.get("mesh.mtls_port").map(String::as_str),
        Some("15090"),
        "the gateway's mesh mTLS listener port must be stamped"
    );
    assert_eq!(
        target.tags.get("mesh.spiffe_id").map(String::as_str),
        Some("spiffe://cluster.local/ns/istio-system/sa/ferrum-egress"),
        "the gateway identity must be pinned for the outbound handshake"
    );
    assert_eq!(
        target
            .tags
            .get("mesh.mtls_authority_host")
            .map(String::as_str),
        Some("203.0.113.7"),
        "the CONNECT authority names the EXTERNAL endpoint the gateway admits"
    );
    assert!(
        !target.tags.contains_key("mesh.hbone"),
        "the EgressGateway exposes no :15008 HBONE listener"
    );
}

/// A large accepted slice must not expand the source-side route/upstream table
/// without bound. Routes beyond the shared external-UDP cap are omitted
/// fail-closed, and every retained route still has exactly one gateway
/// upstream.
#[test]
fn se_udp_source_side_routes_respect_total_cap() {
    register_feature!(
        category = CATEGORY,
        feature = "Source-side external UDP routes have a total materialization cap (#3263)",
        status = Status::Supported,
        notes = "#3263: the same fixed bound that limits the gateway allowlist also limits source-side endpoint routes and their synthesized upstreams; excess entries stay unroutable.",
    );
    let limit = ferrum_edge::modes::mesh::MAX_EGRESS_UDP_DESTINATIONS;
    let objects: Vec<K8sObject> = (0..=limit)
        .map(|index| {
            let address = format!("198.18.{}.{}", index / 254, index % 254 + 1);
            static_udp_service_entry(
                &format!("udp-{index}"),
                vec![format!("udp-{index}.external.test")],
                514,
                vec![address],
            )
        })
        .collect();
    let translation = translate_k8s_objects(&objects, options()).expect("translation succeeds");
    let prepared =
        prepare_gateway_config_for_mesh(translation.config, &sidecar_source_runtime_with_gateway())
            .expect("mesh apply");
    let routes = &prepared
        .mesh
        .as_deref()
        .expect("mesh block")
        .external_udp_egress_routes;
    assert_eq!(routes.len(), limit, "routes beyond the cap must be omitted");
    let external_upstreams: Vec<_> = prepared
        .upstreams
        .iter()
        .filter(|upstream| upstream.id.starts_with("__mesh-out-udp-ext-upstream-"))
        .collect();
    assert_eq!(
        external_upstreams.len(),
        limit,
        "the source must not synthesize upstreams beyond the route cap"
    );
    assert!(routes.iter().all(|route| {
        external_upstreams
            .iter()
            .any(|upstream| upstream.id == route.upstream_id)
    }));
}

/// Fail closed: without an explicitly configured gateway endpoint/identity the
/// source materializes NO route — captured datagrams are dropped, never
/// direct-dialed to the external destination.
#[test]
fn se_udp_source_side_without_configured_gateway_materializes_nothing() {
    register_feature!(
        category = CATEGORY,
        feature = "Source-side external UDP egress requires a configured gateway (#3263)",
        status = Status::Supported,
        notes = "#3263: no FERRUM_MESH_EGRESS_GATEWAY_ADDR/SPIFFE_ID means no route; Ferrum never guesses a gateway and never direct-dials the external destination.",
    );
    let translation = translate_k8s_objects(
        &[static_udp_service_entry(
            "syslog",
            vec!["syslog.external.com"],
            514,
            vec!["203.0.113.7"],
        )],
        options(),
    )
    .expect("translation succeeds");
    let prepared = prepare_gateway_config_for_mesh(
        translation.config,
        &sidecar_runtime_with_policy(OutboundTrafficPolicy::AllowAny),
    )
    .expect("mesh apply");

    assert!(
        prepared
            .mesh
            .as_deref()
            .expect("mesh block")
            .external_udp_egress_routes
            .is_empty()
    );
    assert!(
        !prepared
            .upstreams
            .iter()
            .any(|upstream| upstream.id.starts_with("__mesh-out-udp-ext-upstream-")),
        "no gateway upstream may materialize without a configured gateway"
    );
}

/// Fail closed by the shared opt-in: with `FERRUM_MESH_EGRESS_STREAM_ENABLED=false`
/// the Sidecar/Ambient source publishes no external UDP routes — matching the
/// gateway allowlist contract so the two halves cannot disagree.
#[test]
fn se_udp_source_side_routes_require_stream_egress_opt_in() {
    register_feature!(
        category = CATEGORY,
        feature =
            "Source-side external UDP routes require FERRUM_MESH_EGRESS_STREAM_ENABLED (#3263)",
        status = Status::Supported,
        notes = "#3263: source and gateway share the stream-egress opt-in; flag-off clears source routes and admits nothing on the gateway, never a black-hole half-pair.",
    );
    let translation = translate_k8s_objects(
        &[static_udp_service_entry(
            "syslog",
            vec!["syslog.external.com"],
            514,
            vec!["203.0.113.7"],
        )],
        options(),
    )
    .expect("translation succeeds");
    let mut runtime = sidecar_source_runtime_with_gateway();

    // Flag on: STATIC source routes materialize.
    let prepared =
        prepare_gateway_config_for_mesh(translation.config.clone(), &runtime).expect("mesh apply");
    assert_eq!(
        prepared
            .mesh
            .as_deref()
            .expect("mesh block")
            .external_udp_egress_routes
            .len(),
        1,
        "opt-in on must publish the STATIC source-side route"
    );

    // Flag off on a subsequent apply must withdraw the prior route set.
    runtime.egress_stream_enabled = false;
    let prepared =
        prepare_gateway_config_for_mesh(translation.config, &runtime).expect("mesh apply");
    assert!(
        prepared
            .mesh
            .as_deref()
            .expect("mesh block")
            .external_udp_egress_routes
            .is_empty(),
        "flag-off must withdraw source-side external UDP routes"
    );
    assert!(
        !prepared
            .upstreams
            .iter()
            .any(|upstream| upstream.id.starts_with("__mesh-out-udp-ext-upstream-")),
        "flag-off must not leave a source-side external UDP upstream behind"
    );
}

/// Fail closed: a `DNS`/`NONE` resolution entry declares no endpoint address, so
/// a captured datagram (which carries no Host) cannot be attributed to it. It is
/// refused rather than guessed at.
#[test]
fn se_udp_source_side_refuses_non_static_resolution() {
    register_feature!(
        category = CATEGORY,
        feature = "Source-side external UDP egress requires STATIC resolution (#3263)",
        status = Status::Supported,
        notes = "#3263: a UDP datagram carries no Host, so only a declared endpoint address can key a captured datagram; DNS/NONE entries are refused with a field-specific diagnostic.",
    );
    let translation = translate_k8s_objects(
        &[external_se("dns", vec!["dns.external.com"], 53, "UDP")],
        options(),
    )
    .expect("translation succeeds");
    let prepared =
        prepare_gateway_config_for_mesh(translation.config, &sidecar_source_runtime_with_gateway())
            .expect("mesh apply");

    assert!(
        prepared
            .mesh
            .as_deref()
            .expect("mesh block")
            .external_udp_egress_routes
            .is_empty()
    );
}

/// Reload/update/delete withdrawal on the SOURCE side: the route set is rebuilt
/// and reassigned on every apply, so a withdrawn ServiceEntry stops steering
/// captured datagrams immediately.
#[test]
fn se_udp_source_side_routes_are_withdrawn_on_reload() {
    register_feature!(
        category = CATEGORY,
        feature = "Source-side external UDP routes are rebuilt per apply (#3263)",
        status = Status::Supported,
        notes = "#3263: an update re-keys the route; a delete clears it; a topology without a UDP source-capture producer never materializes one.",
    );
    let runtime = sidecar_source_runtime_with_gateway();
    let initial = translate_k8s_objects(
        &[static_udp_service_entry(
            "syslog",
            vec!["syslog.external.com"],
            514,
            vec!["203.0.113.7"],
        )],
        options(),
    )
    .expect("translation succeeds");
    let prepared = prepare_gateway_config_for_mesh(initial.config, &runtime).expect("mesh apply");
    assert_eq!(
        prepared
            .mesh
            .as_deref()
            .expect("mesh block")
            .external_udp_egress_routes
            .len(),
        1
    );

    // Update: the endpoint moves. The old route must not survive beside it.
    let updated = translate_k8s_objects(
        &[static_udp_service_entry(
            "syslog",
            vec!["syslog.external.com"],
            514,
            vec!["203.0.113.99"],
        )],
        options(),
    )
    .expect("translation succeeds");
    let prepared = prepare_gateway_config_for_mesh(updated.config, &runtime).expect("mesh apply");
    assert_eq!(
        prepared
            .mesh
            .as_deref()
            .expect("mesh block")
            .external_udp_egress_routes
            .iter()
            .map(|route| route.dest_ip.clone())
            .collect::<Vec<_>>(),
        vec!["203.0.113.99".to_string()]
    );

    // Delete: nothing external left ⇒ no routes at all.
    let deleted = translate_k8s_objects(
        &[external_se(
            "kafka",
            vec!["kafka.external.com"],
            9092,
            "TCP",
        )],
        options(),
    )
    .expect("translation succeeds");
    let prepared = prepare_gateway_config_for_mesh(deleted.config, &runtime).expect("mesh apply");
    assert!(
        prepared
            .mesh
            .as_deref()
            .expect("mesh block")
            .external_udp_egress_routes
            .is_empty(),
        "a withdrawn UDP ServiceEntry must withdraw its source-side route"
    );
}

/// Fail closed by topology: an EgressGateway itself never materializes
/// source-side routes (it terminates them), and neither does a topology with no
/// UDP source-capture producer.
#[test]
fn se_udp_source_side_routes_are_empty_on_non_producer_topologies() {
    register_feature!(
        category = CATEGORY,
        feature = "Source-side external UDP routes are producer-topology-only (#3263)",
        status = Status::Supported,
        notes = "#3263: only Sidecar/Ambient have a UDP source-capture producer; every other topology materializes no source-side route.",
    );
    let translation = translate_k8s_objects(
        &[static_udp_service_entry(
            "syslog",
            vec!["syslog.external.com"],
            514,
            vec!["203.0.113.7"],
        )],
        options(),
    )
    .expect("translation succeeds");
    let mut runtime = egress_runtime();
    runtime.egress_gateway = Some(MeshEgressGatewayEndpoint {
        host: "ferrum-egress.istio-system.svc.cluster.local".to_string(),
        port: 15090,
        spiffe_id: "spiffe://cluster.local/ns/istio-system/sa/ferrum-egress"
            .parse()
            .expect("gateway spiffe id"),
    });
    let prepared =
        prepare_gateway_config_for_mesh(translation.config, &runtime).expect("mesh apply");

    assert!(
        prepared
            .mesh
            .as_deref()
            .expect("mesh block")
            .external_udp_egress_routes
            .is_empty()
    );
}

/// Both halves must refuse the SAME entry shapes, or the source publishes a
/// route whose CONNECT the gateway is guaranteed to refuse.
///
/// A host-less `ServiceEntry` is structurally invalid and is rejected at the
/// public `prepare_gateway_config_for_mesh` boundary (`hosts must not be empty`)
/// before either materializer runs. The source-side materializer also refuses
/// empty `hosts[]` as defense in depth for slice carriers that bypass the
/// operator-input validator (xDS / native-slice paths).
#[test]
fn se_udp_hostless_service_entry_admits_nothing_on_either_half() {
    register_feature!(
        category = CATEGORY,
        feature = "Host-less external UDP ServiceEntry is refused by BOTH halves (#3263)",
        status = Status::Supported,
        notes = "#3263: a host-less ServiceEntry is rejected at the public mesh boundary on both runtimes; the source-side materializer also skips empty hosts[] so slice carriers cannot publish a route the gateway would refuse.",
    );
    let hostless = || GatewayConfig {
        mesh: Some(Box::new(MeshConfig {
            service_entries: vec![ServiceEntry {
                name: "syslog".to_string(),
                namespace: "default".to_string(),
                // No hosts: structurally invalid at the public mesh boundary.
                hosts: Vec::new(),
                endpoints: vec![MeshEndpoint {
                    address: "203.0.113.7".to_string(),
                    ports: HashMap::new(),
                    labels: HashMap::new(),
                    network: None,
                }],
                resolution: Resolution::Static,
                location: ServiceEntryLocation::MeshExternal,
                ports: vec![ServicePort {
                    port: 514,
                    protocol: AppProtocol::Udp,
                    name: Some("udp".to_string()),
                    target_port: None,
                }],
                export_to: vec!["*".to_string()],
                workload_selector: None,
            }],
            ..MeshConfig::default()
        })),
        ..GatewayConfig::default()
    };

    let assert_rejected_at_mesh_boundary = |runtime: &MeshRuntimeConfig, half: &str| {
        let err = prepare_gateway_config_for_mesh(hostless(), runtime).expect_err(&format!(
            "{half} half must reject a host-less ServiceEntry at the mesh boundary"
        ));
        let err = err.to_string();
        assert!(
            err.contains("Mesh configuration validation failed"),
            "{half} half: expected mesh-boundary validation failure, got {err}"
        );
        assert!(
            err.contains("hosts must not be empty"),
            "{half} half: expected hosts[] rejection, got {err}"
        );
        assert!(
            err.contains("ServiceEntry"),
            "{half} half: diagnostic should name the resource kind, got {err}"
        );
        assert!(
            !err.contains("203.0.113.7"),
            "{half} half: diagnostic must not echo endpoint address payload"
        );
        assert!(
            err.len() < 256,
            "{half} half: diagnostic must stay bounded, got len {}",
            err.len()
        );
    };

    // Gateway half: public admission rejects before egress UDP materialization.
    assert_rejected_at_mesh_boundary(&egress_runtime(), "gateway");

    // Source half: the same structural rejection at the public boundary.
    assert_rejected_at_mesh_boundary(&sidecar_source_runtime_with_gateway(), "source");
}
