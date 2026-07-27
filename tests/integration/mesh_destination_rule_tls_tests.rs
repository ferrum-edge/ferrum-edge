//! Integration coverage for `DestinationRule.trafficPolicy.tls` flowing from
//! the Istio K8s translator all the way through `MeshSlice` and onto a
//! resolved `Upstream`'s `backend_tls_*` fields.
//!
//! Today the cell at [`docs/mesh.md`](../../docs/mesh.md) for
//! `trafficPolicy.tls` says it is honored as a backend TLS override on the
//! upstream when set, and that PeerAuthentication-derived posture continues
//! to drive the default when unset. These tests pin both halves of that
//! contract.

use ferrum_edge::capture::CaptureMode;
use ferrum_edge::config::types::{
    GatewayConfig, MAX_TARGET_WEIGHT, Proxy, Upstream, UpstreamTarget,
};
use ferrum_edge::config_sources::k8s::{
    K8sMetadata, K8sObject, K8sTranslationOptions, translate_k8s_objects,
};
use ferrum_edge::identity::spiffe::TrustDomain;
use ferrum_edge::modes::mesh::config::{
    MeshTrafficPolicy, MeshTrafficPolicyTls, MtlsMode, OutboundTrafficPolicy,
};
use ferrum_edge::modes::mesh::slice::{MeshSlice, MeshSliceRequest};
use ferrum_edge::modes::mesh::{
    MeshConfigProtocol, MeshRuntimeConfig, MeshTopology, prepare_gateway_config_for_mesh,
};

fn slice_request_for_default_ns() -> MeshSliceRequest {
    MeshSliceRequest {
        namespace: "default".to_string(),
        ..Default::default()
    }
}

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
            creation_timestamp: None,
            deletion_timestamp: None,
            annotations: Default::default(),
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

fn test_addr(raw: &str) -> std::net::SocketAddr {
    raw.parse().expect("valid socket address")
}

fn test_runtime() -> MeshRuntimeConfig {
    MeshRuntimeConfig {
        node_id: "node-a".to_string(),
        namespace: "default".to_string(),
        cp_urls: vec!["http://127.0.0.1:1".to_string()],
        config_protocol: MeshConfigProtocol::Native,
        file_config_path: None,
        topology: MeshTopology::Sidecar,
        inbound_listen_addr: test_addr("127.0.0.1:15006"),
        outbound_listen_addr: test_addr("127.0.0.1:15001"),
        hbone_listen_addr: test_addr("127.0.0.1:15008"),
        east_west_listen_port: 15443,
        egress_hbone_port: 15008,
        egress_mtls_port: 15006,
        egress_listen_addr: test_addr("0.0.0.0:15090"),
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
        workload_labels: Default::default(),
        dns_enabled: false,
        dns_listen_addr: test_addr("127.0.0.1:15053"),
        dns_upstream_addr: test_addr("127.0.0.53:53"),
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

/// Build a matching `Upstream` so the DR's host resolves to it during cold-path
/// apply. The DR cold-path matches on `target.host` (or `upstream.name`) so we
/// give the upstream a single target with the same FQDN as the DR's host.
fn build_matching_upstream(id: &str, host_fqdn: &str) -> Upstream {
    use std::collections::HashMap;
    let now = chrono::Utc::now();
    Upstream {
        id: id.to_string(),
        namespace: "default".to_string(),
        name: Some(id.to_string()),
        targets: vec![UpstreamTarget {
            host: host_fqdn.to_string(),
            port: 8080,
            service_port_policy_key: None,
            weight: MAX_TARGET_WEIGHT.min(1),
            tags: HashMap::new(),
            locality: None,
            path: None,
        }],
        algorithm: Default::default(),
        hash_on: None,
        hash_on_cookie_config: None,
        health_checks: None,
        service_discovery: None,
        subsets: None,
        backend_tls_client_cert_path: None,
        backend_tls_client_key_path: None,
        backend_tls_verify_server_cert: true,
        backend_tls_server_ca_cert_path: None,
        backend_tls_sni: None,
        backend_tls_san_allow_list: Vec::new(),
        resolved_subset_tls: HashMap::new(),
        dispatch_port_override_fallback: None,
        port_overrides: HashMap::new(),
        source_locality: None,
        locality_lb_strict: false,
        locality_lb_setting: None,
        api_spec_id: None,
        created_at: now,
        updated_at: now,
    }
}

fn build_proxy(id: &str, upstream_id: &str) -> Proxy {
    // `resolve_upstream_tls` looks up upstreams by `(proxy.namespace, upstream_id)`.
    // Mesh fixtures stamp upstreams with the owning Service namespace (`default`);
    // the serde default for Proxy.namespace is `ferrum`, so omit the field and
    // the projection silently misses.
    serde_json::from_value(serde_json::json!({
        "id": id,
        "namespace": "default",
        "hosts": [format!("{id}.example.com")],
        "backend_host": "",
        "backend_port": 0,
        "upstream_id": upstream_id
    }))
    .expect("test proxy")
}

/// Translate a single Istio DestinationRule object and return the resulting
/// `GatewayConfig` plus the parsed `MeshTrafficPolicyTls` (if any).
fn translate_dr(spec: serde_json::Value) -> (GatewayConfig, Option<MeshTrafficPolicyTls>) {
    let result = translate_k8s_objects(
        &[istio_object("DestinationRule", "reviews", spec)],
        k8s_options(),
    )
    .expect("translation should succeed");
    let mesh = result.config.mesh.as_ref().expect("mesh present");
    let tls = mesh.destination_rules[0]
        .traffic_policy
        .as_ref()
        .and_then(|tp| tp.tls.clone());
    (result.config, tls)
}

#[test]
fn dr_tls_simple_flows_through_to_upstream_backend_tls() {
    // ── 1. Translate the DestinationRule YAML/JSON. ──
    let (mut config, tls) = translate_dr(serde_json::json!({
        "host": "reviews.default.svc.cluster.local",
        "trafficPolicy": {
            "tls": {
                "mode": "SIMPLE",
                "caCertificates": "/etc/certs/ca.pem"
            }
        }
    }));

    let tls = tls.expect("DR.tls should be parsed");
    assert_eq!(tls.mode, MtlsMode::Simple);
    assert_eq!(tls.ca_certificates.as_deref(), Some("/etc/certs/ca.pem"));

    // ── 2. Attach an upstream that the DR's host matches. ──
    config.upstreams.push(build_matching_upstream(
        "reviews-u",
        "reviews.default.svc.cluster.local",
    ));

    // ── 3. Run slice projection + cold-path DR apply via the public API. ──
    let slice = MeshSlice::from_gateway_config(&config, slice_request_for_default_ns());
    // The CP applies DRs onto the GatewayConfig at slice projection time; we
    // simulate that here by walking the slice's destination_rules and running
    // the same projection through the runtime's public preparation entry
    // point. Since `prepare_gateway_config_for_mesh` requires a
    // `MeshRuntimeConfig`, we instead reach for the integration-safe
    // primitive: rebuild a GatewayConfig from the slice + the upstream, then
    // assert the in-slice MeshDestinationRule carries the tls we expect.
    //
    // Cold-path application is unit-tested in `src/modes/mesh/mod.rs`; here
    // we anchor the wire-level contract: the slice transports the tls.
    assert_eq!(slice.destination_rules.len(), 1);
    let dr_tls = slice.destination_rules[0]
        .traffic_policy
        .as_ref()
        .and_then(|tp| tp.tls.as_ref())
        .expect("slice DR.tls present");
    assert_eq!(dr_tls.mode, MtlsMode::Simple);
    assert_eq!(dr_tls.ca_certificates.as_deref(), Some("/etc/certs/ca.pem"));
}

#[test]
fn dr_tls_mutual_carries_client_cert_and_key_through_slice() {
    let (_, tls) = translate_dr(serde_json::json!({
        "host": "reviews.default.svc.cluster.local",
        "trafficPolicy": {
            "tls": {
                "mode": "MUTUAL",
                "caCertificates": "/etc/certs/ca.pem",
                "clientCertificate": "/etc/certs/client.pem",
                "privateKey": "/etc/certs/client.key"
            }
        }
    }));

    let tls = tls.expect("DR.tls should be parsed");
    assert_eq!(tls.mode, MtlsMode::Mutual);
    assert_eq!(tls.ca_certificates.as_deref(), Some("/etc/certs/ca.pem"));
    assert_eq!(
        tls.client_certificate.as_deref(),
        Some("/etc/certs/client.pem")
    );
    assert_eq!(tls.private_key.as_deref(), Some("/etc/certs/client.key"));
}

#[test]
fn dr_tls_istio_mutual_translates_without_explicit_cert_material() {
    let (_, tls) = translate_dr(serde_json::json!({
        "host": "reviews.default.svc.cluster.local",
        "trafficPolicy": {
            "tls": {"mode": "ISTIO_MUTUAL"}
        }
    }));

    let tls = tls.expect("DR.tls should be parsed");
    assert_eq!(tls.mode, MtlsMode::IstioMutual);
    assert!(tls.client_certificate.is_none());
    assert!(tls.private_key.is_none());
    assert!(tls.ca_certificates.is_none());
}

#[test]
fn dr_istio_mutual_projects_workload_svid_onto_upstream() {
    let (mut config, tls) = translate_dr(serde_json::json!({
        "host": "reviews.default.svc.cluster.local",
        "trafficPolicy": {
            "tls": {"mode": "ISTIO_MUTUAL"}
        }
    }));
    assert_eq!(
        tls.expect("DR.tls should be parsed").mode,
        MtlsMode::IstioMutual
    );

    config.upstreams.push(build_matching_upstream(
        "reviews-u",
        "reviews.default.svc.cluster.local",
    ));
    config.proxies.push(build_proxy("reviews-p", "reviews-u"));
    let runtime = MeshRuntimeConfig {
        workload_svid_cert_path: Some("/var/run/secrets/ferrum/svid.pem".to_string()),
        workload_svid_key_path: Some("/var/run/secrets/ferrum/svid.key".to_string()),
        workload_svid_trust_bundle_path: Some(
            "/var/run/secrets/ferrum/trust-bundle.pem".to_string(),
        ),
        ..test_runtime()
    };

    let prepared =
        prepare_gateway_config_for_mesh(config, &runtime).expect("mesh preparation succeeds");
    let upstream = prepared
        .upstreams
        .iter()
        .find(|upstream| upstream.id == "reviews-u")
        .expect("matching upstream");
    assert_eq!(
        upstream.backend_tls_client_cert_path.as_deref(),
        Some("/var/run/secrets/ferrum/svid.pem")
    );
    assert_eq!(
        upstream.backend_tls_client_key_path.as_deref(),
        Some("/var/run/secrets/ferrum/svid.key")
    );
    assert_eq!(
        upstream.backend_tls_server_ca_cert_path.as_deref(),
        Some("/var/run/secrets/ferrum/trust-bundle.pem")
    );
    assert!(upstream.backend_tls_verify_server_cert);

    let proxy = prepared
        .proxies
        .iter()
        .find(|proxy| proxy.id == "reviews-p")
        .expect("proxy");
    assert_eq!(
        proxy.resolved_tls.client_cert_path.as_deref(),
        Some("/var/run/secrets/ferrum/svid.pem")
    );
    assert_eq!(
        proxy.resolved_tls.client_key_path.as_deref(),
        Some("/var/run/secrets/ferrum/svid.key")
    );
    assert_eq!(
        proxy.resolved_tls.server_ca_cert_path.as_deref(),
        Some("/var/run/secrets/ferrum/trust-bundle.pem")
    );
}

#[test]
fn dr_istio_mutual_without_runtime_svid_fails_mesh_preparation() {
    let (mut config, tls) = translate_dr(serde_json::json!({
        "host": "reviews.default.svc.cluster.local",
        "trafficPolicy": {
            "tls": {"mode": "ISTIO_MUTUAL"}
        }
    }));
    assert_eq!(
        tls.expect("DR.tls should be parsed").mode,
        MtlsMode::IstioMutual
    );

    let mut upstream = build_matching_upstream("reviews-u", "reviews.default.svc.cluster.local");
    upstream.backend_tls_client_cert_path = Some("/existing/client.pem".to_string());
    upstream.backend_tls_client_key_path = Some("/existing/client.key".to_string());
    config.upstreams.push(upstream);
    config.proxies.push(build_proxy("reviews-p", "reviews-u"));

    let err = prepare_gateway_config_for_mesh(config, &test_runtime())
        .expect_err("ISTIO_MUTUAL without runtime SVID material must fail");

    assert!(
        err.to_string()
            .contains("requires FERRUM_GATEWAY_SVID_CERT_PATH"),
        "got: {err}"
    );
}

#[test]
fn dr_tls_sni_and_sans_project_onto_upstream() {
    let (mut config, tls) = translate_dr(serde_json::json!({
        "host": "reviews.default.svc.cluster.local",
        "trafficPolicy": {
            "tls": {
                "mode": "SIMPLE",
                "sni": "reviews.mesh.internal",
                "subjectAltNames": [
                    "reviews.mesh.internal",
                    "spiffe://cluster.local/ns/default/sa/reviews"
                ]
            }
        }
    }));
    let tls = tls.expect("DR.tls should be parsed");
    assert_eq!(tls.sni.as_deref(), Some("reviews.mesh.internal"));
    assert_eq!(tls.subject_alt_names.len(), 2);

    config.upstreams.push(build_matching_upstream(
        "reviews-u",
        "reviews.default.svc.cluster.local",
    ));
    config.proxies.push(build_proxy("reviews-p", "reviews-u"));

    let prepared = prepare_gateway_config_for_mesh(config, &test_runtime())
        .expect("mesh preparation succeeds");
    let upstream = prepared
        .upstreams
        .iter()
        .find(|upstream| upstream.id == "reviews-u")
        .expect("matching upstream");
    assert_eq!(
        upstream.backend_tls_sni.as_deref(),
        Some("reviews.mesh.internal")
    );
    assert_eq!(
        upstream.backend_tls_san_allow_list,
        vec![
            "reviews.mesh.internal".to_string(),
            "spiffe://cluster.local/ns/default/sa/reviews".to_string(),
        ]
    );

    let proxy = prepared
        .proxies
        .iter()
        .find(|proxy| proxy.id == "reviews-p")
        .expect("proxy");
    assert_eq!(
        proxy.resolved_tls.sni.as_deref(),
        Some("reviews.mesh.internal")
    );
    assert_eq!(
        proxy.resolved_tls.san_allow_list,
        vec![
            "reviews.mesh.internal".to_string(),
            "spiffe://cluster.local/ns/default/sa/reviews".to_string(),
        ]
    );
}

#[test]
fn dr_without_tls_block_yields_none_on_slice() {
    // Today's behavior must continue to work — DR without trafficPolicy.tls
    // leaves the upstream's backend_tls_* unchanged.
    let (mut config, tls) = translate_dr(serde_json::json!({
        "host": "reviews.default.svc.cluster.local",
        "trafficPolicy": {
            "loadBalancer": {"simple": "ROUND_ROBIN"}
        }
    }));

    assert!(tls.is_none(), "absent tls block must serialize as None");

    config.upstreams.push(build_matching_upstream(
        "reviews-u",
        "reviews.default.svc.cluster.local",
    ));

    let slice = MeshSlice::from_gateway_config(&config, slice_request_for_default_ns());
    assert_eq!(slice.destination_rules.len(), 1);
    assert!(
        slice.destination_rules[0]
            .traffic_policy
            .as_ref()
            .and_then(|tp| tp.tls.as_ref())
            .is_none(),
        "DR.tls must remain None when not specified"
    );
}

#[test]
fn dr_tls_subset_traffic_policy_carries_tls_block_without_warning() {
    // Subset-level tls block: parsed onto the `MeshSubset.traffic_policy.tls`
    // AND applied per-subset by the cold-path apply
    // (`resolve_subset_traffic_policy_tls`). No translator warning expected.
    let result = translate_k8s_objects(
        &[istio_object(
            "DestinationRule",
            "reviews",
            serde_json::json!({
                "host": "reviews.default.svc.cluster.local",
                "subsets": [{
                    "name": "v1",
                    "labels": {"version": "v1"},
                    "trafficPolicy": {
                        "tls": {
                            "mode": "SIMPLE",
                            "caCertificates": "/etc/certs/v1-ca.pem"
                        }
                    }
                }]
            }),
        )],
        k8s_options(),
    )
    .expect("translation succeeds");

    let mesh = result.config.mesh.expect("mesh");
    let subset = &mesh.destination_rules[0].subsets[0];
    let tls = subset
        .traffic_policy
        .as_ref()
        .expect("subset tp")
        .tls
        .as_ref()
        .expect("subset tls");
    assert_eq!(tls.mode, MtlsMode::Simple);
    assert_eq!(tls.ca_certificates.as_deref(), Some("/etc/certs/v1-ca.pem"));

    assert!(
        !result
            .warnings
            .iter()
            .any(|w| w.contains("trafficPolicy.tls is parsed but not yet applied per-subset")),
        "subset-level tls must NOT emit the 'not applied per-subset' warning: {:?}",
        result.warnings
    );
}

#[test]
fn dr_two_subsets_with_different_cas_fragment_backend_pool() {
    // GAP-3B core scenario: a single upstream carrying two DR subsets — v1 and
    // v2 — each with a distinct CA. After cold-path apply + resolve_upstream_tls,
    // two proxies that select the v1 vs v2 subset must:
    //   1. Land on different `BackendTlsConfig` values via `Proxy.resolved_tls`.
    //   2. Produce different backend pool keys across HTTP / H2 / gRPC / H3.
    //
    // The combined TLS-identity + `subset_name` partitioning is what guarantees
    // distinct TLS identities never share connections (see CLAUDE.md
    // "Connection Pool Keys").
    use ferrum_edge::http3::client::Http3ConnectionPool;

    let result = translate_k8s_objects(
        &[istio_object(
            "DestinationRule",
            "reviews",
            serde_json::json!({
                "host": "reviews.default.svc.cluster.local",
                "subsets": [
                    {
                        "name": "v1",
                        "labels": {"version": "v1"},
                        "trafficPolicy": {
                            "tls": {
                                "mode": "SIMPLE",
                                "caCertificates": "/etc/certs/ca-v1.pem"
                            }
                        }
                    },
                    {
                        "name": "v2",
                        "labels": {"version": "v2"},
                        "trafficPolicy": {
                            "tls": {
                                "mode": "SIMPLE",
                                "caCertificates": "/etc/certs/ca-v2.pem"
                            }
                        }
                    }
                ]
            }),
        )],
        k8s_options(),
    )
    .expect("translation succeeds");
    let mut config = result.config;

    // Attach the matching upstream (same FQDN, single target) so the cold-path
    // DR application has something to project onto.
    config.upstreams.push(build_matching_upstream(
        "reviews-u",
        "reviews.default.svc.cluster.local",
    ));

    // Two proxies — one per subset — sharing the upstream.
    // Namespace must match the upstream (`default`); see `build_proxy`.
    let proxy_v1: Proxy = serde_json::from_value(serde_json::json!({
        "id": "p-v1",
        "namespace": "default",
        "hosts": ["v1.example.com"],
        "backend_host": "",
        "backend_port": 0,
        "upstream_id": "reviews-u",
        "upstream_subset": "v1",
    }))
    .expect("p-v1");
    let proxy_v2: Proxy = serde_json::from_value(serde_json::json!({
        "id": "p-v2",
        "namespace": "default",
        "hosts": ["v2.example.com"],
        "backend_host": "",
        "backend_port": 0,
        "upstream_id": "reviews-u",
        "upstream_subset": "v2",
    }))
    .expect("p-v2");
    config.proxies.push(proxy_v1);
    config.proxies.push(proxy_v2);

    // Run the full mesh preparation: apply_destination_rules +
    // normalize_fields + resolve_upstream_tls. This is the same pipeline the
    // DP uses on each slice apply.
    let prepared = prepare_gateway_config_for_mesh(config, &test_runtime())
        .expect("mesh preparation succeeds");

    // ── 1. Upstream carries per-subset resolved TLS for both subsets. ──
    let upstream = prepared
        .upstreams
        .iter()
        .find(|u| u.id == "reviews-u")
        .expect("upstream present");
    let v1_tls = upstream
        .resolved_subset_tls
        .get("v1")
        .and_then(|r| r.tls.as_ref())
        .expect("v1 has resolved tls");
    let v2_tls = upstream
        .resolved_subset_tls
        .get("v2")
        .and_then(|r| r.tls.as_ref())
        .expect("v2 has resolved tls");
    assert_eq!(
        v1_tls.server_ca_cert_path.as_deref(),
        Some("/etc/certs/ca-v1.pem")
    );
    assert_eq!(
        v2_tls.server_ca_cert_path.as_deref(),
        Some("/etc/certs/ca-v2.pem")
    );

    // ── 2. Each proxy's `resolved_tls` reflects its subset's CA. ──
    let p_v1 = prepared
        .proxies
        .iter()
        .find(|p| p.id == "p-v1")
        .expect("p-v1");
    let p_v2 = prepared
        .proxies
        .iter()
        .find(|p| p.id == "p-v2")
        .expect("p-v2");
    assert_eq!(
        p_v1.resolved_tls.server_ca_cert_path.as_deref(),
        Some("/etc/certs/ca-v1.pem"),
        "p-v1.resolved_tls reflects subset v1 CA"
    );
    assert_eq!(
        p_v2.resolved_tls.server_ca_cert_path.as_deref(),
        Some("/etc/certs/ca-v2.pem"),
        "p-v2.resolved_tls reflects subset v2 CA"
    );

    // ── 3. HTTP/3 pool keys differ across the two subsets. The H3 pool key
    //       is the most exhaustive (includes host:port + dns_override + subset
    //       + the full TLS material). If H3 partitions cleanly, the reqwest
    //       HTTP/H2/gRPC pool keys (which use the same TLS-field appender)
    //       also partition — both the CA path AND the subset name differ.
    let pool_v1 = Http3ConnectionPool::pool_key_for_target(
        p_v1,
        "reviews.default.svc.cluster.local",
        8080,
        0,
    );
    let pool_v2 = Http3ConnectionPool::pool_key_for_target(
        p_v2,
        "reviews.default.svc.cluster.local",
        8080,
        0,
    );
    assert_ne!(
        pool_v1, pool_v2,
        "two-subset upstream with distinct CAs must fragment backend H3 pool key"
    );
    assert!(
        pool_v1.contains("ca-v1.pem"),
        "v1 pool key must carry v1 CA: {pool_v1}"
    );
    assert!(
        pool_v2.contains("ca-v2.pem"),
        "v2 pool key must carry v2 CA: {pool_v2}"
    );
    assert!(
        pool_v1.contains("|v1|"),
        "v1 pool key must carry subset marker: {pool_v1}"
    );
    assert!(
        pool_v2.contains("|v2|"),
        "v2 pool key must carry subset marker: {pool_v2}"
    );
}

#[test]
fn mesh_traffic_policy_with_tls_none_omits_tls_key_from_json() {
    // Wire-compatibility invariant: a `MeshTrafficPolicy { tls: None, .. }`
    // serializes WITHOUT a `tls` key so old DPs reading new-format slices
    // see this as a no-op and round-trip stays loss-less. Same is true for
    // every other `Option<...>` field on the struct.
    let policy = MeshTrafficPolicy {
        connect_timeout_ms: Some(1000),
        outlier_detection: None,
        load_balancer: None,
        tls: None,
        locality_lb_setting: None,
        max_connections: None,
        tcp_keepalive: None,
        connection_pool_http: None,
    };

    let json = serde_json::to_value(&policy).expect("serialize");
    let object = json.as_object().expect("object");
    assert!(
        !object.contains_key("tls"),
        "tls=None must NOT appear in serialized JSON (wire compatibility): {json}"
    );
    assert!(
        !object.contains_key("locality_lb_setting"),
        "locality_lb_setting=None must NOT appear in serialized JSON \
         (wire compatibility): {json}"
    );
    assert!(
        !object.contains_key("max_connections"),
        "max_connections=None must NOT appear in serialized JSON \
         (wire compatibility): {json}"
    );
    assert!(
        !object.contains_key("tcp_keepalive"),
        "tcp_keepalive=None must NOT appear in serialized JSON \
         (wire compatibility): {json}"
    );
    assert!(
        !object.contains_key("connection_pool_http"),
        "connection_pool_http=None must NOT appear in serialized JSON \
         (wire compatibility): {json}"
    );
    // Sanity: the explicitly-set field is present.
    assert_eq!(
        object.get("connect_timeout_ms"),
        Some(&serde_json::json!(1000))
    );
}

#[test]
fn mesh_traffic_policy_tls_optional_sub_fields_skip_when_none() {
    // Sub-field wire-compatibility: every `Option<String>` / `Vec<String>`
    // field skips when empty. `mode` always serializes (no
    // `skip_serializing_if`); only it and any explicitly-set extras
    // appear in the JSON.
    let tls = MeshTrafficPolicyTls {
        mode: MtlsMode::Simple,
        ..MeshTrafficPolicyTls::default()
    };

    let json = serde_json::to_value(&tls).expect("serialize");
    let object = json.as_object().expect("object");
    assert!(object.contains_key("mode"));
    assert!(!object.contains_key("sni"));
    assert!(!object.contains_key("ca_certificates"));
    assert!(!object.contains_key("client_certificate"));
    assert!(!object.contains_key("private_key"));
    assert!(!object.contains_key("subject_alt_names"));
    // `insecure_skip_verify` is a primitive bool; it does serialize when
    // false today (no `skip_serializing_if`). Verify the value, not the
    // presence, so the contract here is explicit.
    assert_eq!(
        object.get("insecure_skip_verify"),
        Some(&serde_json::json!(false))
    );
}

#[test]
fn mesh_traffic_policy_tls_round_trips_through_serde() {
    // Round-trip a populated TLS block to verify the JSON wire format is
    // deserializable back to an equivalent struct (catches any rename /
    // skip-serializing-if drift between fields).
    let original = MeshTrafficPolicyTls {
        mode: MtlsMode::Mutual,
        sni: Some("reviews.example.com".to_string()),
        ca_certificates: Some("/etc/certs/ca.pem".to_string()),
        client_certificate: Some("/etc/certs/client.pem".to_string()),
        private_key: Some("/etc/certs/client.key".to_string()),
        subject_alt_names: vec!["spiffe://example/sa/reviews".to_string()],
        insecure_skip_verify: true,
    };

    let json = serde_json::to_string(&original).expect("serialize");
    let parsed: MeshTrafficPolicyTls = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(parsed, original);
}

#[test]
fn mesh_traffic_policy_tls_defaults_mode_to_simple_when_omitted() {
    // Hand-authored or partially-updated TLS blocks may omit `mode`. The
    // serde default must match Istio's `ClientTLSSettings.mode` default
    // (SIMPLE) and the `translate_client_tls_settings` translator, otherwise
    // a JSON payload like `{ "tls": { "sni": "reviews.example.com" } }`
    // fails to load even though Istio semantics treat it as SIMPLE.
    let parsed: MeshTrafficPolicyTls =
        serde_json::from_str(r#"{"sni":"reviews.example.com"}"#).expect("deserialize");
    assert_eq!(parsed.mode, MtlsMode::Simple);
    assert_eq!(parsed.sni.as_deref(), Some("reviews.example.com"));

    // Empty object is also valid and produces the full default.
    let empty: MeshTrafficPolicyTls = serde_json::from_str("{}").expect("deserialize empty");
    assert_eq!(empty, MeshTrafficPolicyTls::default());
    assert_eq!(empty.mode, MtlsMode::Simple);
}

#[test]
fn dr_tls_translation_rejects_istio_mutual_with_explicit_cert() {
    let err = translate_k8s_objects(
        &[istio_object(
            "DestinationRule",
            "reviews",
            serde_json::json!({
                "host": "reviews.default.svc.cluster.local",
                "trafficPolicy": {
                    "tls": {
                        "mode": "ISTIO_MUTUAL",
                        "clientCertificate": "/etc/certs/client.pem",
                        "privateKey": "/etc/certs/client.key"
                    }
                }
            }),
        )],
        k8s_options(),
    )
    .expect_err("ISTIO_MUTUAL with explicit cert must be rejected");
    assert!(
        err.to_string()
            .contains("ISTIO_MUTUAL must not set clientCertificate/privateKey/caCertificates"),
        "got: {err}"
    );
}

#[test]
fn dr_subset_istio_mutual_without_runtime_svid_fails_closed() {
    // GAP-3B fail-closed regression guard: a subset configured for
    // `ISTIO_MUTUAL` without SVID material must REJECT the slice, not
    // silently fall back to upstream-level TLS. The upstream-level path
    // already does this (see `dr_istio_mutual_without_runtime_svid_fails_mesh_preparation`);
    // the subset-level path must match to prevent an operator's
    // "v1 MUST use mTLS" requirement from quietly degrading to the
    // upstream's posture (which may be `SIMPLE` with a public CA).
    let (mut config, _tls) = translate_dr(serde_json::json!({
        "host": "reviews.default.svc.cluster.local",
        "subsets": [{
            "name": "v1",
            "labels": {"version": "v1"},
            "trafficPolicy": {
                "tls": {"mode": "ISTIO_MUTUAL"}
            }
        }]
    }));

    let upstream = build_matching_upstream("reviews-u", "reviews.default.svc.cluster.local");
    config.upstreams.push(upstream);
    let mut proxy = build_proxy("reviews-p-v1", "reviews-u");
    proxy.upstream_subset = Some("v1".to_string());
    config.proxies.push(proxy);

    let err = prepare_gateway_config_for_mesh(config, &test_runtime())
        .expect_err("subset ISTIO_MUTUAL without runtime SVID must reject the slice");

    let err_str = err.to_string();
    assert!(
        err_str.contains("subset trafficPolicy.tls projection failed"),
        "expected fail-closed subset projection error, got: {err_str}"
    );
    assert!(
        err_str.contains("v1") && err_str.contains("reviews-u"),
        "error should identify the offending subset and upstream, got: {err_str}"
    );
}
