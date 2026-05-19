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
    AppProtocol, MeshConfig, OutboundTrafficPolicy, Resolution, ServiceEntry, ServiceEntryLocation,
    ServicePort,
};
use ferrum_edge::modes::mesh::{
    MESH_OUTBOUND_REGISTRY_PLUGIN_ID, MeshConfigProtocol, MeshRuntimeConfig, MeshTopology,
    prepare_gateway_config_for_mesh,
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
        topology: MeshTopology::EgressGateway,
        inbound_listen_addr: "127.0.0.1:0".parse::<SocketAddr>().unwrap(),
        outbound_listen_addr: "127.0.0.1:0".parse::<SocketAddr>().unwrap(),
        hbone_listen_addr: "127.0.0.1:0".parse::<SocketAddr>().unwrap(),
        east_west_listen_port: 15443,
        egress_listen_addr: "127.0.0.1:15090".parse::<SocketAddr>().unwrap(),
        workload_spiffe_id: None,
        waypoint_name: None,
        workload_svid_cert_path: None,
        workload_svid_key_path: None,
        workload_svid_trust_bundle_path: None,
        xds_node_cluster: "default".to_string(),
        xds_stream_channel_capacity: 32,
        xds_primary_retry_secs: 300,
        xds_connect_timeout_seconds: 10,
        trust_domain_aliases: Vec::new(),
        trusted_hbone_assertors: Vec::new(),
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

    // No egress proxy for the internal entry.
    assert!(
        prepared
            .proxies
            .iter()
            .all(|p| !p.id.contains("api-dot-internal")),
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
