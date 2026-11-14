//! DestinationRule + ServiceEntry projection coverage.
//!
//! Locks in the cold-path materialisation that `prepare_gateway_config_via_mesh_slice`
//! performs:
//!
//! - DestinationRule top-level `traffic_policy` lands on `Upstream.algorithm`,
//!   `Upstream.passive_health_check`, `Upstream.backend_*` (TLS), and
//!   `Upstream.port_overrides` for per-port settings.
//! - DestinationRule per-port `connection_pool.tcp.connectTimeout` lands on
//!   `Upstream.port_overrides[port].connect_timeout_ms` so HTTP/H2/H3/gRPC/TCP/HBONE
//!   dispatch can pick it up.
//! - ServiceEntry visibility (`export_to`) controls which workloads see the
//!   service entry in their slice; this test focuses on the slice-projection
//!   side rather than DNS resolution (which has its own coverage in
//!   `mesh_k8s_pod_discovery_tests.rs`).
//!
//! Per-port LB/outlier projection and TLS material projection are already
//! covered in `mesh_destination_rule_port_policy_tests.rs` and
//! `mesh_destination_rule_tls_tests.rs`; this file fills gaps in the
//! upstream-level + service-entry slice contract.

use std::collections::HashMap;

use ferrum_edge::config::types::{LoadBalancerAlgorithm, Proxy, Upstream};
use ferrum_edge::modes::mesh::config::{
    AppProtocol, MeshDestinationRule, MeshLoadBalancer, MeshOutlierDetection, MeshSimpleLb,
    MeshTrafficPolicy, Resolution, ServiceEntry, ServiceEntryLocation, ServicePort,
};
use ferrum_edge::modes::mesh::prepare_gateway_config_via_mesh_slice;

use super::mesh_test_support::{
    DEFAULT_NAMESPACE, default_mesh_runtime, gateway_config_with_mesh, http_proxy, http_upstream,
    mesh_config_with, service_for, workload_for,
};

const SERVICE_FQDN: &str = "reviews.default.svc.cluster.local";

fn destination_rule(traffic_policy: Option<MeshTrafficPolicy>) -> MeshDestinationRule {
    MeshDestinationRule {
        name: "reviews-dr".to_string(),
        namespace: DEFAULT_NAMESPACE.to_string(),
        host: SERVICE_FQDN.to_string(),
        traffic_policy,
        port_level_settings: HashMap::new(),
        subsets: Vec::new(),
        export_to: vec!["*".to_string()],
    }
}

/// PR a8dce394 scoped `apply_destination_rules` to namespace, so this
/// test module needs the test proxy and upstream to share the same
/// namespace the DR targets (`DEFAULT_NAMESPACE = "default"`). The
/// `mesh_test_support` helpers default to the gateway namespace
/// (`"ferrum"`), so each test rebinds the namespace on the helpers'
/// output before assembling the config.
fn align_namespace(proxy: &mut Proxy, upstream: &mut Upstream) {
    proxy.namespace = DEFAULT_NAMESPACE.to_string();
    upstream.namespace = DEFAULT_NAMESPACE.to_string();
}

#[test]
fn destination_rule_top_level_load_balancer_projects_to_upstream_algorithm() {
    let mut runtime = default_mesh_runtime();
    runtime.namespace = DEFAULT_NAMESPACE.to_string();

    let mut upstream = http_upstream("reviews-u", SERVICE_FQDN, 8080);
    let mut proxy = {
        let mut p = http_proxy("reviews-p", "reviews.example.com", 8080);
        p.upstream_id = Some("reviews-u".to_string());
        p
    };
    align_namespace(&mut proxy, &mut upstream);
    let dr = destination_rule(Some(MeshTrafficPolicy {
        load_balancer: Some(MeshLoadBalancer::Simple(MeshSimpleLb::LeastRequest)),
        ..MeshTrafficPolicy::default()
    }));
    let mut mesh = mesh_config_with(Vec::new(), Vec::new(), Vec::new());
    mesh.destination_rules.push(dr);
    let config = gateway_config_with_mesh(vec![proxy], vec![upstream], mesh);
    let prepared = prepare_gateway_config_via_mesh_slice(config, &runtime).expect("dr prepared");
    let upstream = prepared
        .upstreams
        .iter()
        .find(|u| u.id == "reviews-u")
        .expect("upstream survived");
    assert_eq!(
        upstream.algorithm,
        LoadBalancerAlgorithm::LeastConnections,
        "Istio LEAST_REQUEST maps to Ferrum LeastConnections"
    );
}

#[test]
fn destination_rule_passthrough_projects_to_upstream_algorithm() {
    let mut runtime = default_mesh_runtime();
    runtime.namespace = DEFAULT_NAMESPACE.to_string();

    let mut upstream = http_upstream("reviews-u", SERVICE_FQDN, 8080);
    let mut proxy = {
        let mut p = http_proxy("reviews-p", "reviews.example.com", 8080);
        p.upstream_id = Some("reviews-u".to_string());
        p
    };
    align_namespace(&mut proxy, &mut upstream);
    let dr = destination_rule(Some(MeshTrafficPolicy {
        load_balancer: Some(MeshLoadBalancer::Simple(MeshSimpleLb::Passthrough)),
        ..MeshTrafficPolicy::default()
    }));
    let mut mesh = mesh_config_with(Vec::new(), Vec::new(), Vec::new());
    mesh.destination_rules.push(dr);
    let config = gateway_config_with_mesh(vec![proxy], vec![upstream], mesh);
    let prepared = prepare_gateway_config_via_mesh_slice(config, &runtime).expect("dr prepared");
    let upstream = prepared
        .upstreams
        .iter()
        .find(|u| u.id == "reviews-u")
        .expect("upstream survived");
    assert_eq!(
        upstream.algorithm,
        LoadBalancerAlgorithm::Passthrough,
        "Istio PASSTHROUGH maps to Ferrum Passthrough, not RoundRobin"
    );
}

#[test]
fn destination_rule_outlier_detection_projects_to_upstream_passive_health() {
    let mut runtime = default_mesh_runtime();
    runtime.namespace = DEFAULT_NAMESPACE.to_string();

    let mut upstream = http_upstream("reviews-u", SERVICE_FQDN, 8080);
    let mut proxy = {
        let mut p = http_proxy("reviews-p", "reviews.example.com", 8080);
        p.upstream_id = Some("reviews-u".to_string());
        p
    };
    align_namespace(&mut proxy, &mut upstream);
    let dr = destination_rule(Some(MeshTrafficPolicy {
        outlier_detection: Some(MeshOutlierDetection {
            consecutive_errors: Some(7),
            interval_seconds: Some(13),
            base_ejection_seconds: Some(19),
            max_ejection_percent: Some(40),
        }),
        ..MeshTrafficPolicy::default()
    }));
    let mut mesh = mesh_config_with(Vec::new(), Vec::new(), Vec::new());
    mesh.destination_rules.push(dr);
    let config = gateway_config_with_mesh(vec![proxy], vec![upstream], mesh);
    let prepared = prepare_gateway_config_via_mesh_slice(config, &runtime).expect("dr prepared");
    let upstream = prepared
        .upstreams
        .iter()
        .find(|u| u.id == "reviews-u")
        .expect("upstream survived");
    let passive = upstream
        .health_checks
        .as_ref()
        .and_then(|h| h.passive.as_ref())
        .expect("passive health check projected to upstream");
    assert_eq!(passive.unhealthy_threshold, 7);
    assert_eq!(passive.unhealthy_window_seconds, 13);
    assert_eq!(passive.healthy_after_seconds, 19);
    assert_eq!(passive.max_ejection_percent, Some(40));
}

#[test]
fn destination_rule_connect_timeout_projects_to_proxy_connect_timeout() {
    // `connection_pool.tcp.connectTimeout` flows onto the proxy's
    // `backend_connect_timeout_ms` so HTTP-family / gRPC / TCP /
    // HBONE dispatch all pick it up — locks in the cross-protocol
    // contract documented in CLAUDE.md.
    let mut runtime = default_mesh_runtime();
    runtime.namespace = DEFAULT_NAMESPACE.to_string();
    let mut upstream = http_upstream("reviews-u", SERVICE_FQDN, 8080);
    let mut proxy = {
        let mut p = http_proxy("reviews-p", "reviews.example.com", 8080);
        p.upstream_id = Some("reviews-u".to_string());
        p
    };
    align_namespace(&mut proxy, &mut upstream);
    let dr = destination_rule(Some(MeshTrafficPolicy {
        connect_timeout_ms: Some(2500),
        ..MeshTrafficPolicy::default()
    }));
    let mut mesh = mesh_config_with(Vec::new(), Vec::new(), Vec::new());
    mesh.destination_rules.push(dr);
    let config = gateway_config_with_mesh(vec![proxy], vec![upstream], mesh);
    let prepared = prepare_gateway_config_via_mesh_slice(config, &runtime).expect("dr prepared");
    let proxy = prepared
        .proxies
        .iter()
        .find(|p| p.id == "reviews-p")
        .expect("proxy survived");
    assert_eq!(
        proxy.backend_connect_timeout_ms, 2500,
        "top-level connect_timeout from DR must project onto proxy.backend_connect_timeout_ms"
    );
}

#[test]
fn destination_rule_with_no_matching_upstream_is_a_no_op() {
    // DR targets `reviews.default.svc.cluster.local` but only an unrelated
    // upstream exists in the config. Verify the prepared config does not
    // spuriously mutate the unrelated upstream.
    let mut runtime = default_mesh_runtime();
    runtime.namespace = DEFAULT_NAMESPACE.to_string();
    let upstream = http_upstream("ratings-u", "ratings.default.svc.cluster.local", 8080);
    let initial_algo = upstream.algorithm;
    let initial_timeout =
        http_proxy("ratings-p", "ratings.example.com", 8080).backend_connect_timeout_ms;
    let proxy = {
        let mut p = http_proxy("ratings-p", "ratings.example.com", 8080);
        p.upstream_id = Some("ratings-u".to_string());
        p
    };
    let dr = destination_rule(Some(MeshTrafficPolicy {
        load_balancer: Some(MeshLoadBalancer::Simple(MeshSimpleLb::Random)),
        connect_timeout_ms: Some(9999),
        ..MeshTrafficPolicy::default()
    }));
    let mut mesh = mesh_config_with(Vec::new(), Vec::new(), Vec::new());
    mesh.destination_rules.push(dr);
    let config = gateway_config_with_mesh(vec![proxy], vec![upstream], mesh);
    let prepared = prepare_gateway_config_via_mesh_slice(config, &runtime).expect("dr prepared");
    let upstream = prepared
        .upstreams
        .iter()
        .find(|u| u.id == "ratings-u")
        .expect("ratings upstream survived");
    assert_eq!(
        upstream.algorithm, initial_algo,
        "non-matching DR must not touch unrelated upstream's algorithm"
    );
    let proxy = prepared
        .proxies
        .iter()
        .find(|p| p.id == "ratings-p")
        .expect("ratings proxy survived");
    assert_eq!(
        proxy.backend_connect_timeout_ms, initial_timeout,
        "non-matching DR must not touch unrelated proxy's connect timeout"
    );
}

#[test]
fn destination_rule_host_match_is_case_insensitive_against_canonical_host() {
    // FQDNs in the wild come with varying case. The DR/Upstream match
    // path normalises both sides, so a DR scoped to a mixed-case host
    // should still attach.
    let mut runtime = default_mesh_runtime();
    runtime.namespace = DEFAULT_NAMESPACE.to_string();
    let mut upstream = http_upstream("reviews-u", "Reviews.Default.SVC.cluster.local", 8080);
    let mut proxy = {
        let mut p = http_proxy("reviews-p", "reviews.example.com", 8080);
        p.upstream_id = Some("reviews-u".to_string());
        p
    };
    align_namespace(&mut proxy, &mut upstream);
    let dr = destination_rule(Some(MeshTrafficPolicy {
        load_balancer: Some(MeshLoadBalancer::Simple(MeshSimpleLb::Random)),
        ..MeshTrafficPolicy::default()
    }));
    let mut mesh = mesh_config_with(Vec::new(), Vec::new(), Vec::new());
    mesh.destination_rules.push(dr);
    let config = gateway_config_with_mesh(vec![proxy], vec![upstream], mesh);
    let prepared = prepare_gateway_config_via_mesh_slice(config, &runtime).expect("dr prepared");
    let upstream = prepared
        .upstreams
        .iter()
        .find(|u| u.id == "reviews-u")
        .expect("upstream survived");
    assert_eq!(
        upstream.algorithm,
        LoadBalancerAlgorithm::Random,
        "case-mixed host should still match the DR"
    );
}

#[test]
fn destination_rule_short_host_form_resolves_to_namespace_qualified_fqdn() {
    // A DR with `host: reviews` (no namespace / FQDN suffix) should
    // attach to an upstream whose target is the fully-qualified
    // `reviews.default.svc.cluster.local`. Mirrors Istio's documented
    // short-host behaviour where the DR's namespace anchors the
    // resolution.
    let mut runtime = default_mesh_runtime();
    runtime.namespace = DEFAULT_NAMESPACE.to_string();
    let mut upstream = http_upstream("reviews-u", "reviews.default.svc.cluster.local", 8080);
    let mut proxy = {
        let mut p = http_proxy("reviews-p", "reviews.example.com", 8080);
        p.upstream_id = Some("reviews-u".to_string());
        p
    };
    align_namespace(&mut proxy, &mut upstream);
    let mut dr = destination_rule(Some(MeshTrafficPolicy {
        load_balancer: Some(MeshLoadBalancer::Simple(MeshSimpleLb::Random)),
        ..MeshTrafficPolicy::default()
    }));
    dr.host = "reviews".to_string();
    let mut mesh = mesh_config_with(Vec::new(), Vec::new(), Vec::new());
    mesh.destination_rules.push(dr);
    let config = gateway_config_with_mesh(vec![proxy], vec![upstream], mesh);
    let prepared = prepare_gateway_config_via_mesh_slice(config, &runtime).expect("dr prepared");
    let upstream = prepared
        .upstreams
        .iter()
        .find(|u| u.id == "reviews-u")
        .expect("upstream survived");
    assert_eq!(
        upstream.algorithm,
        LoadBalancerAlgorithm::Random,
        "short host should resolve via namespace anchor"
    );
}

// ── ServiceEntry projection ───────────────────────────────────────────────

fn service_entry_external(name: &str, hosts: Vec<&str>, ports: Vec<u16>) -> ServiceEntry {
    ServiceEntry {
        name: name.to_string(),
        namespace: DEFAULT_NAMESPACE.to_string(),
        hosts: hosts.into_iter().map(String::from).collect(),
        endpoints: Vec::new(),
        resolution: Resolution::Dns,
        location: ServiceEntryLocation::MeshExternal,
        ports: ports
            .into_iter()
            .map(|p| ServicePort {
                port: p,
                protocol: AppProtocol::Http,
                name: Some("http".to_string()),
                target_port: None,
            })
            .collect(),
        export_to: Vec::new(),
        workload_selector: None,
    }
}

#[test]
fn service_entry_with_no_export_to_admits_workload_in_same_namespace() {
    // No `export_to` defaults to namespace-local visibility — a workload
    // in the same namespace as the entry should see it in its slice.
    let mut runtime = default_mesh_runtime();
    runtime.namespace = DEFAULT_NAMESPACE.to_string();
    let workload = workload_for(
        "reviews",
        DEFAULT_NAMESPACE,
        [("app", "reviews")],
        ["10.0.0.1"],
    );
    let entry = service_entry_external("ext-payments", vec!["payments.example.com"], vec![443]);
    let mut mesh = mesh_config_with(vec![workload], Vec::new(), Vec::new());
    mesh.service_entries.push(entry);
    let config = gateway_config_with_mesh(Vec::new(), Vec::new(), mesh);
    let prepared = prepare_gateway_config_via_mesh_slice(config, &runtime).expect("prepared");
    let mesh_block = prepared.mesh.as_ref().expect("mesh block survives");
    assert_eq!(
        mesh_block.service_entries.len(),
        1,
        "namespace-local ServiceEntry must be visible to same-namespace workload, got {:?}",
        mesh_block.service_entries
    );
    assert_eq!(mesh_block.service_entries[0].name, "ext-payments");
}

#[test]
fn service_entry_exported_to_star_is_visible_to_other_namespaces() {
    // `export_to: ["*"]` makes the entry mesh-wide. A workload in a
    // different namespace should still see it.
    let mut runtime = default_mesh_runtime();
    runtime.namespace = "other".to_string();
    let workload = workload_for("rater", "other", [("app", "rater")], ["10.0.0.2"]);
    let mut entry = service_entry_external("ext-payments", vec!["payments.example.com"], vec![443]);
    entry.export_to = vec!["*".to_string()];
    let mut mesh = mesh_config_with(vec![workload], Vec::new(), Vec::new());
    mesh.service_entries.push(entry);
    let config = gateway_config_with_mesh(Vec::new(), Vec::new(), mesh);
    let prepared = prepare_gateway_config_via_mesh_slice(config, &runtime).expect("prepared");
    let mesh_block = prepared.mesh.as_ref().expect("mesh block survives");
    let names: Vec<_> = mesh_block.service_entries.iter().map(|e| &e.name).collect();
    assert!(
        names.iter().any(|n| n.as_str() == "ext-payments"),
        "ServiceEntry with export_to=['*'] must be visible mesh-wide, got {names:?}"
    );
}

#[test]
fn service_entry_with_namespace_scoped_export_only_admits_listed_namespace() {
    // `export_to: ["specific-ns"]` should restrict visibility to that
    // namespace. A workload in `unrelated` shouldn't see the entry.
    let mut runtime = default_mesh_runtime();
    runtime.namespace = "unrelated".to_string();
    let workload = workload_for("other", "unrelated", [("app", "other")], ["10.0.0.3"]);
    let mut entry = service_entry_external("ext-private", vec!["private.example.com"], vec![443]);
    entry.export_to = vec!["specific-ns".to_string()];
    entry.namespace = "specific-ns".to_string();
    let mut mesh = mesh_config_with(vec![workload], Vec::new(), Vec::new());
    mesh.service_entries.push(entry);
    let config = gateway_config_with_mesh(Vec::new(), Vec::new(), mesh);
    let prepared = prepare_gateway_config_via_mesh_slice(config, &runtime).expect("prepared");
    let mesh_block = prepared.mesh.as_ref().expect("mesh block survives");
    let names: Vec<_> = mesh_block.service_entries.iter().map(|e| &e.name).collect();
    assert!(
        !names.iter().any(|n| n.as_str() == "ext-private"),
        "namespace-scoped ServiceEntry must NOT be visible to workload in another namespace, got {names:?}"
    );
}

#[test]
fn service_entry_mesh_internal_location_is_round_tripped_through_slice() {
    // `location: MESH_INTERNAL` ServiceEntries are used to register
    // VM workloads — the egress-gateway materialisation specifically
    // excludes them (only MESH_EXTERNAL is materialised). Verify the
    // location field survives projection unchanged.
    let mut runtime = default_mesh_runtime();
    runtime.namespace = DEFAULT_NAMESPACE.to_string();
    let workload = workload_for("vm", DEFAULT_NAMESPACE, [("app", "vm")], ["10.0.0.10"]);
    let mut entry = service_entry_external("vm-entry", vec!["vm.internal"], vec![80]);
    entry.location = ServiceEntryLocation::MeshInternal;
    entry.resolution = Resolution::Static;
    let mut mesh = mesh_config_with(vec![workload], Vec::new(), Vec::new());
    mesh.service_entries.push(entry);
    let config = gateway_config_with_mesh(Vec::new(), Vec::new(), mesh);
    let prepared = prepare_gateway_config_via_mesh_slice(config, &runtime).expect("prepared");
    let mesh_block = prepared.mesh.as_ref().expect("mesh block survives");
    let entry = mesh_block
        .service_entries
        .iter()
        .find(|e| e.name == "vm-entry")
        .expect("entry survived projection");
    assert_eq!(entry.location, ServiceEntryLocation::MeshInternal);
    assert_eq!(entry.resolution, Resolution::Static);
}

#[test]
fn mesh_service_visible_in_slice_when_workload_in_same_namespace() {
    let mut runtime = default_mesh_runtime();
    runtime.namespace = DEFAULT_NAMESPACE.to_string();
    let workload = workload_for(
        "reviews",
        DEFAULT_NAMESPACE,
        [("app", "reviews")],
        ["10.0.0.1"],
    );
    let service = service_for("reviews", DEFAULT_NAMESPACE, &[&workload]);
    let mesh = mesh_config_with(vec![workload], vec![service], Vec::new());
    let config = gateway_config_with_mesh(Vec::new(), Vec::new(), mesh);
    let prepared = prepare_gateway_config_via_mesh_slice(config, &runtime).expect("prepared");
    let mesh_block = prepared.mesh.as_ref().expect("mesh block survives");
    assert!(
        mesh_block.services.iter().any(|s| s.name == "reviews"),
        "same-namespace MeshService must be visible"
    );
}

#[test]
fn destination_rule_combines_multiple_fields_in_a_single_traffic_policy() {
    // Real-world DRs typically set load_balancer + outlier_detection +
    // connect_timeout together. Lock in that the projection applies all
    // three simultaneously rather than the last one wins / first-only.
    let mut runtime = default_mesh_runtime();
    runtime.namespace = DEFAULT_NAMESPACE.to_string();
    let mut upstream = http_upstream("reviews-u", SERVICE_FQDN, 8080);
    let mut proxy = {
        let mut p = http_proxy("reviews-p", "reviews.example.com", 8080);
        p.upstream_id = Some("reviews-u".to_string());
        p
    };
    align_namespace(&mut proxy, &mut upstream);
    let dr = destination_rule(Some(MeshTrafficPolicy {
        load_balancer: Some(MeshLoadBalancer::Simple(MeshSimpleLb::Random)),
        connect_timeout_ms: Some(3500),
        outlier_detection: Some(MeshOutlierDetection {
            consecutive_errors: Some(3),
            interval_seconds: Some(10),
            base_ejection_seconds: Some(30),
            max_ejection_percent: Some(50),
        }),
        ..MeshTrafficPolicy::default()
    }));
    let mut mesh = mesh_config_with(Vec::new(), Vec::new(), Vec::new());
    mesh.destination_rules.push(dr);
    let config = gateway_config_with_mesh(vec![proxy], vec![upstream], mesh);
    let prepared = prepare_gateway_config_via_mesh_slice(config, &runtime).expect("prepared");
    let upstream = prepared
        .upstreams
        .iter()
        .find(|u| u.id == "reviews-u")
        .expect("upstream survived");
    let proxy = prepared
        .proxies
        .iter()
        .find(|p| p.id == "reviews-p")
        .expect("proxy survived");
    assert_eq!(upstream.algorithm, LoadBalancerAlgorithm::Random);
    let passive = upstream
        .health_checks
        .as_ref()
        .and_then(|h| h.passive.as_ref())
        .expect("passive projected");
    assert_eq!(passive.unhealthy_threshold, 3);
    assert_eq!(proxy.backend_connect_timeout_ms, 3500);
}
