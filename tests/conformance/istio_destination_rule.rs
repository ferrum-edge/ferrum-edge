//! Istio DestinationRule conformance.
//!
//! Covers the canonical `trafficPolicy.{connectionPool,outlierDetection,loadBalancer,tls,portLevelSettings}`
//! fields that operators set on a DR. Each test translates a focused DR and
//! asserts the field landed on the resolved Mesh data model.
//!
//! Where Ferrum intentionally defers a field (parsed and warned about, but no
//! enforcement yet) the test registers `Status::Deferred` with the tracking
//! note. Deferred fields are also surfaced in the DestinationRule
//! `status.ferrum.translation.deferred_fields` block by the Istio controller.

use ferrum_edge::config_sources::k8s::{
    K8sMetadata, K8sObject, K8sTranslationOptions, translate_k8s_objects,
};
use ferrum_edge::identity::spiffe::TrustDomain;
use ferrum_edge::modes::mesh::config::{
    MeshDestinationRule, MeshLoadBalancer, MeshSimpleLb, MtlsMode,
};
use serde_json::{Value, json};

use crate::conformance::registry::{Maturity, Status};

const CATEGORY: &str = "istio_destination_rule";

fn options() -> K8sTranslationOptions {
    K8sTranslationOptions::new(
        "default".to_string(),
        TrustDomain::new("cluster.local").expect("test trust domain"),
    )
}

fn destination_rule(spec: Value) -> K8sObject {
    K8sObject {
        api_version: "networking.istio.io/v1beta1".to_string(),
        kind: "DestinationRule".to_string(),
        metadata: K8sMetadata {
            name: "dr-under-test".to_string(),
            namespace: "default".to_string(),
            ..K8sMetadata::default()
        },
        spec,
        status: Value::Object(serde_json::Map::new()),
    }
}

fn translated(spec: Value) -> MeshDestinationRule {
    let result =
        translate_k8s_objects(&[destination_rule(spec)], options()).expect("translation succeeds");
    let mesh = result.config.mesh.expect("mesh config");
    mesh.destination_rules
        .into_iter()
        .next()
        .expect("one mesh destination rule emitted")
}

/// `trafficPolicy.connectionPool.tcp.connectTimeout` is the single most-used DR
/// field. Lands on `MeshTrafficPolicy.connect_timeout_ms`. Per CLAUDE.md:
/// "Applied to `Proxy.backend_connect_timeout_ms` for every proxy referencing
/// the matching upstream."
#[test]
fn dr_connection_pool_tcp_connect_timeout() {
    register_feature!(
        category = CATEGORY,
        feature = "trafficPolicy.connectionPool.tcp.connectTimeout",
        status = Status::Supported,
        maturity = Maturity::Ga,
        notes = "Translated to MeshTrafficPolicy.connect_timeout_ms; applied across HTTP/H2/H3/gRPC/TCP/HBONE dispatch.",
    );
    let dr = translated(json!({
        "host": "echo.default.svc.cluster.local",
        "trafficPolicy": {
            "connectionPool": {"tcp": {"connectTimeout": "2s"}}
        }
    }));
    let policy = dr.traffic_policy.expect("traffic policy emitted");
    assert_eq!(policy.connect_timeout_ms, Some(2000));
}

/// `subsets[].trafficPolicy.connectionPool.tcp.connectTimeout` — per-subset
/// connect timeout. Translated onto the mesh DR subset; at slice apply it
/// overrides `backend_connect_timeout_ms` for proxies whose `upstream_subset`
/// selects this subset (taking precedence over the DR top-level connectTimeout,
/// verified by `dr_subset_connect_timeout_overrides_top_level_for_subset_bound_proxies`
/// in `src/modes/mesh/mod.rs`).
#[test]
fn dr_subset_connect_timeout() {
    register_feature!(
        category = CATEGORY,
        feature = "subsets[].trafficPolicy.connectionPool.tcp.connectTimeout",
        status = Status::Supported,
        notes = "Per-subset connect timeout: overrides backend_connect_timeout_ms for proxies bound to the subset, taking precedence over the DR top-level connectTimeout.",
    );
    let dr = translated(json!({
        "host": "api.default.svc.cluster.local",
        "subsets": [{
            "name": "v1",
            "labels": {"version": "v1"},
            "trafficPolicy": {"connectionPool": {"tcp": {"connectTimeout": "2s"}}}
        }]
    }));
    let subset = dr
        .subsets
        .iter()
        .find(|s| s.name == "v1")
        .expect("v1 subset emitted");
    let tp = subset
        .traffic_policy
        .as_ref()
        .expect("subset traffic policy emitted");
    assert_eq!(tp.connect_timeout_ms, Some(2000));
}

/// `subsets[].trafficPolicy.outlierDetection` — per-subset passive health. The
/// ejection *thresholds* (consecutive errors / interval / base-ejection /
/// min-health) are applied per-subset at slice apply, overriding the
/// upstream-level passive health for subset-bound proxies; the
/// `maxEjectionPercent` *cap* remains upstream-level. Apply behavior is pinned
/// by `dr_subset_outlier_resolves_passive_health_thresholds` and
/// `passive_health_for_target_prefers_subset_over_upstream` in the source crate.
#[test]
fn dr_subset_outlier_detection() {
    register_feature!(
        category = CATEGORY,
        feature = "subsets[].trafficPolicy.outlierDetection",
        status = Status::Supported,
        notes = "Per-subset outlier thresholds (consecutive errors / interval / base-ejection / min-health) applied per-subset, overriding upstream-level passive health; the maxEjectionPercent cap is still resolved at the upstream level.",
    );
    let dr = translated(json!({
        "host": "api.default.svc.cluster.local",
        "subsets": [{
            "name": "v1",
            "labels": {"version": "v1"},
            "trafficPolicy": {"outlierDetection": {"consecutive5xxErrors": 5, "interval": "30s"}}
        }]
    }));
    let subset = dr
        .subsets
        .iter()
        .find(|s| s.name == "v1")
        .expect("v1 subset emitted");
    let tp = subset
        .traffic_policy
        .as_ref()
        .expect("subset traffic policy emitted");
    let od = tp
        .outlier_detection
        .as_ref()
        .expect("subset outlierDetection translated");
    assert_eq!(od.consecutive_errors, Some(5));
}

/// `trafficPolicy.connectionPool.tcp.maxConnections` — T1-D (PR #897).
/// Lands on `MeshConnectionPoolTcp.max_connections`.
#[test]
fn dr_connection_pool_tcp_max_connections() {
    register_feature!(
        category = CATEGORY,
        feature = "trafficPolicy.connectionPool.tcp.maxConnections",
        status = Status::Supported,
        maturity = Maturity::Ga,
        notes = "T1-D (PR #897): translated to MeshConnectionPoolTcp.max_connections; enforced by stream-family (TCP/TCP+TLS) dispatch and by HTTP-family WebSocket dispatch (one dedicated backend connection per session). Pooled multiplexed HTTP transports (reqwest H1/H2, direct H2, gRPC, H3, HBONE) do not enforce it — see docs/mesh.md.",
    );
    let dr = translated(json!({
        "host": "echo.default.svc.cluster.local",
        "trafficPolicy": {
            "connectionPool": {"tcp": {"maxConnections": 100}}
        }
    }));
    let policy = dr.traffic_policy.expect("traffic policy emitted");
    assert_eq!(policy.max_connections, Some(100));
}

/// `trafficPolicy.connectionPool.tcp.tcpKeepalive` — T1-D (PR #897). Maps onto
/// `MeshConnectionPoolTcp.tcp_keepalive` with the structured probes/time/interval fields.
#[test]
fn dr_connection_pool_tcp_keepalive() {
    register_feature!(
        category = CATEGORY,
        feature = "trafficPolicy.connectionPool.tcp.tcpKeepalive",
        status = Status::Supported,
        notes = "T1-D (PR #897): structured probes/time/interval; rejects sub-second precision.",
    );
    let dr = translated(json!({
        "host": "echo.default.svc.cluster.local",
        "trafficPolicy": {
            "connectionPool": {"tcp": {"tcpKeepalive": {
                "probes": 5,
                "time": "30s",
                "interval": "10s"
            }}}
        }
    }));
    let policy = dr.traffic_policy.expect("traffic policy emitted");
    let keepalive = policy.tcp_keepalive.expect("keepalive emitted");
    assert_eq!(keepalive.probes, Some(5));
    assert_eq!(keepalive.time_seconds, Some(30));
    assert_eq!(keepalive.interval_seconds, Some(10));
}

/// `trafficPolicy.connectionPool.http.maxRequestsPerConnection` is parsed and
/// validated, but deferred because Ferrum does not enforce close-after-N
/// backend requests.
#[test]
fn dr_connection_pool_http_max_requests_per_connection() {
    register_feature!(
        category = CATEGORY,
        feature = "trafficPolicy.connectionPool.http.maxRequestsPerConnection",
        status = Status::Deferred,
        notes = "Parsed and validated, but not projected: backend close-after-N-requests is unsupported. Status reports the field as deferred.",
    );
    let result = translate_k8s_objects(
        &[destination_rule(json!({
            "host": "echo.default.svc.cluster.local",
            "trafficPolicy": {
                "connectionPool": {"http": {"maxRequestsPerConnection": 500}}
            }
        }))],
        options(),
    )
    .expect("translation succeeds");
    assert!(
        result.warnings.iter().any(|warning| {
            warning.contains("maxRequestsPerConnection") && warning.contains("not applied")
        }),
        "deferred field must warn: {:?}",
        result.warnings
    );
    let mesh = result.config.mesh.expect("mesh config");
    let dr = mesh
        .destination_rules
        .into_iter()
        .next()
        .expect("one mesh destination rule emitted");
    assert!(
        dr.traffic_policy
            .and_then(|policy| policy.connection_pool_http)
            .is_none(),
        "maxRequestsPerConnection-only block must not create an effective overlay"
    );
}

/// `trafficPolicy.connectionPool.http.idleTimeout` — T1-C (PR #908).
#[test]
fn dr_connection_pool_http_idle_timeout() {
    register_feature!(
        category = CATEGORY,
        feature = "trafficPolicy.connectionPool.http.idleTimeout",
        status = Status::Supported,
        notes = "T1-C (PR #908): persisted as idle_timeout_ms; sub-second values rejected.",
    );
    let dr = translated(json!({
        "host": "echo.default.svc.cluster.local",
        "trafficPolicy": {
            "connectionPool": {"http": {"idleTimeout": "30s"}}
        }
    }));
    let http = dr
        .traffic_policy
        .expect("traffic policy")
        .connection_pool_http
        .expect("http overlay");
    assert_eq!(http.idle_timeout_ms, Some(30_000));
}

/// `trafficPolicy.connectionPool.http.http2MaxRequests` — T1-C (PR #908).
/// Projects onto `Proxy.pool_http2_max_concurrent_streams` per port at
/// `resolve_effective_proxy_for_target` time.
#[test]
fn dr_connection_pool_http_http2_max_requests() {
    register_feature!(
        category = CATEGORY,
        feature = "trafficPolicy.connectionPool.http.http2MaxRequests",
        status = Status::Supported,
        notes = "T1-C (PR #908): projects onto Proxy.pool_http2_max_concurrent_streams via the H2/gRPC builder knobs.",
    );
    let dr = translated(json!({
        "host": "echo.default.svc.cluster.local",
        "trafficPolicy": {
            "connectionPool": {"http": {"http2MaxRequests": 100}}
        }
    }));
    let http = dr
        .traffic_policy
        .expect("traffic policy")
        .connection_pool_http
        .expect("http overlay");
    assert_eq!(http.http2_max_requests, Some(100));
}

/// `trafficPolicy.connectionPool.http.h2UpgradePolicy` — F5.1.
/// Projects onto `Proxy.h2_upgrade_policy` per port and drives the plain-HTTPS
/// H2-vs-H1 dispatch fork (`DO_NOT_UPGRADE` forces reqwest/H1; `UPGRADE` prefers
/// direct-H2 incl. for `Unknown` targets, fail-safe against proven-Unsupported).
#[test]
fn dr_connection_pool_http_h2_upgrade_policy() {
    register_feature!(
        category = CATEGORY,
        feature = "trafficPolicy.connectionPool.http.h2UpgradePolicy",
        status = Status::Supported,
        notes = "F5.1: projects onto Proxy.h2_upgrade_policy; consulted at the plain-HTTPS h1-vs-h2 dispatch fork. DEFAULT maps to None; unknown values rejected.",
    );
    let dr = translated(json!({
        "host": "echo.default.svc.cluster.local",
        "trafficPolicy": {
            "connectionPool": {"http": {"h2UpgradePolicy": "DO_NOT_UPGRADE"}}
        }
    }));
    let http = dr
        .traffic_policy
        .expect("traffic policy")
        .connection_pool_http
        .expect("http overlay");
    assert_eq!(
        http.h2_upgrade_policy,
        Some(ferrum_edge::config::types::H2UpgradePolicy::DoNotUpgrade)
    );
}

/// `trafficPolicy.connectionPool.http.maxRetries` — F5.1.
/// Interpreted as a per-request retry-count CAP (an upper bound on
/// `Proxy.retry.max_retries`), NOT Envoy's cluster-wide outstanding-retry
/// budget. Never increases retries and never enables retries when the proxy has
/// no retry policy. Zero/negative rejected at translate time.
#[test]
fn dr_connection_pool_http_max_retries() {
    register_feature!(
        category = CATEGORY,
        feature = "trafficPolicy.connectionPool.http.maxRetries",
        status = Status::Supported,
        notes = "F5.1: per-request retry-count CAP (min(existing, dr); no-enable when no policy) — honest reinterpretation of Envoy's cluster-wide outstanding-retry budget.",
    );
    let dr = translated(json!({
        "host": "echo.default.svc.cluster.local",
        "trafficPolicy": {
            "connectionPool": {"http": {"maxRetries": 2}}
        }
    }));
    let http = dr
        .traffic_policy
        .expect("traffic policy")
        .connection_pool_http
        .expect("http overlay");
    assert_eq!(http.max_retries, Some(2));
}

/// `trafficPolicy.connectionPool.http.http1MaxPendingRequests` (F5.1 final knob):
/// projected onto the HTTP overlay and enforced at runtime as a per-`(host,port)`
/// HTTP/1.1 pending-request gate (503 "upstream overflow" when full). No longer
/// deferred at top-level / `portLevelSettings`.
#[test]
fn dr_connection_pool_http_http1_max_pending_requests_supported() {
    register_feature!(
        category = CATEGORY,
        feature = "trafficPolicy.connectionPool.http.http1MaxPendingRequests",
        status = Status::Supported,
        notes = "Projected onto port_overrides[port].http1_max_pending_requests → Proxy.pool_http1_max_pending_requests; enforced as a 503-on-overflow pending-request gate on the reqwest/HTTP-1.1 dispatch path (src/backend_pending_limit.rs).",
    );
    let dr = translated(json!({
        "host": "echo.default.svc.cluster.local",
        "trafficPolicy": {
            "connectionPool": {"http": {"http1MaxPendingRequests": 50}}
        }
    }));
    let http = dr
        .traffic_policy
        .as_ref()
        .expect("traffic policy")
        .connection_pool_http
        .as_ref()
        .expect("http overlay");
    assert_eq!(http.http1_max_pending_requests, Some(50));
}

/// `trafficPolicy.loadBalancer.simple = ROUND_ROBIN` → `RoundRobin`.
#[test]
fn dr_load_balancer_simple_round_robin() {
    register_feature!(
        category = CATEGORY,
        feature = "trafficPolicy.loadBalancer.simple = ROUND_ROBIN",
        status = Status::Supported,
        notes = "Maps to LoadBalancerAlgorithm::RoundRobin.",
    );
    let dr = translated(json!({
        "host": "echo.default.svc.cluster.local",
        "trafficPolicy": {"loadBalancer": {"simple": "ROUND_ROBIN"}}
    }));
    let lb = dr
        .traffic_policy
        .expect("traffic policy")
        .load_balancer
        .expect("lb");
    match lb {
        MeshLoadBalancer::Simple(MeshSimpleLb::RoundRobin) => {}
        other => panic!("expected RoundRobin, got {other:?}"),
    }
}

/// `trafficPolicy.loadBalancer.simple = LEAST_REQUEST` → `LeastConnections`.
#[test]
fn dr_load_balancer_simple_least_request() {
    register_feature!(
        category = CATEGORY,
        feature = "trafficPolicy.loadBalancer.simple = LEAST_REQUEST / LEAST_CONN",
        status = Status::Supported,
        notes = "Both LEAST_REQUEST and LEAST_CONN map to LoadBalancerAlgorithm::LeastConnections.",
    );
    let dr = translated(json!({
        "host": "echo.default.svc.cluster.local",
        "trafficPolicy": {"loadBalancer": {"simple": "LEAST_REQUEST"}}
    }));
    let lb = dr
        .traffic_policy
        .expect("traffic policy")
        .load_balancer
        .expect("lb");
    match lb {
        MeshLoadBalancer::Simple(MeshSimpleLb::LeastRequest) => {}
        other => panic!("expected LeastRequest, got {other:?}"),
    }
}

/// `trafficPolicy.loadBalancer.consistentHash.httpHeaderName` →
/// `LoadBalancerAlgorithm::ConsistentHashing` + `Upstream.hash_on`.
#[test]
fn dr_load_balancer_consistent_hash_header() {
    register_feature!(
        category = CATEGORY,
        feature = "trafficPolicy.loadBalancer.consistentHash.httpHeaderName",
        status = Status::Supported,
        notes = "Maps to LoadBalancerAlgorithm::ConsistentHashing with hash_on=header:<name>.",
    );
    let dr = translated(json!({
        "host": "echo.default.svc.cluster.local",
        "trafficPolicy": {"loadBalancer": {"consistentHash": {"httpHeaderName": "x-user-id"}}}
    }));
    let lb = dr
        .traffic_policy
        .expect("traffic policy")
        .load_balancer
        .expect("lb");
    match lb {
        MeshLoadBalancer::ConsistentHash(hash) => {
            assert_eq!(hash.http_header_name.as_deref(), Some("x-user-id"));
        }
        other => panic!("expected ConsistentHash, got {other:?}"),
    }
}

/// `trafficPolicy.outlierDetection.consecutive5xxErrors` →
/// `PassiveHealthCheck.unhealthy_threshold`.
#[test]
fn dr_outlier_detection_consecutive_5xx() {
    register_feature!(
        category = CATEGORY,
        feature = "trafficPolicy.outlierDetection.consecutive5xxErrors",
        status = Status::Supported,
        notes = "Maps to PassiveHealthCheck.unhealthy_threshold.",
    );
    let dr = translated(json!({
        "host": "echo.default.svc.cluster.local",
        "trafficPolicy": {"outlierDetection": {"consecutive5xxErrors": 7}}
    }));
    let outlier = dr
        .traffic_policy
        .expect("traffic policy")
        .outlier_detection
        .expect("outlier");
    assert_eq!(outlier.consecutive_errors, Some(7));
}

/// `trafficPolicy.tls.mode = SIMPLE` → `MtlsMode::Simple` projected onto
/// `Upstream.backend_tls_*`. Test the model-layer round-trip (operator → DR →
/// MeshDestinationRule → cold-path apply); the wire-level cert paths are
/// covered by `tests/integration/mesh_destination_rule_tls_tests.rs`.
#[test]
fn dr_traffic_policy_tls_simple() {
    register_feature!(
        category = CATEGORY,
        feature = "trafficPolicy.tls.mode = SIMPLE",
        status = Status::Supported,
        notes = "GAP-3B (PR #882): mode SIMPLE forces server-cert verify; ca_certificates / sni / subjectAltNames project onto Upstream.backend_tls_*.",
    );
    let dr = translated(json!({
        "host": "echo.default.svc.cluster.local",
        "trafficPolicy": {"tls": {
            "mode": "SIMPLE",
            "caCertificates": "/etc/ferrum/ca.pem",
            "sni": "echo.example.com",
            "subjectAltNames": ["echo.example.com"]
        }}
    }));
    let tls = dr.traffic_policy.expect("traffic policy").tls.expect("tls");
    assert_eq!(tls.mode, MtlsMode::Simple);
    assert_eq!(tls.sni.as_deref(), Some("echo.example.com"));
    assert_eq!(tls.ca_certificates.as_deref(), Some("/etc/ferrum/ca.pem"));
    assert_eq!(tls.subject_alt_names, vec!["echo.example.com".to_string()]);
}

/// `trafficPolicy.tls.mode = ISTIO_MUTUAL` → projects SVID paths onto
/// `Upstream.backend_tls_*`. Just confirm the model carries the mode.
#[test]
fn dr_traffic_policy_tls_istio_mutual() {
    register_feature!(
        category = CATEGORY,
        feature = "trafficPolicy.tls.mode = ISTIO_MUTUAL",
        status = Status::Supported,
        notes = "GAP-3B (PR #882): projects FERRUM_GATEWAY_SVID_* onto the upstream client cert/key; slice apply fails closed if SVID material is missing.",
    );
    let dr = translated(json!({
        "host": "echo.default.svc.cluster.local",
        "trafficPolicy": {"tls": {"mode": "ISTIO_MUTUAL"}}
    }));
    let tls = dr.traffic_policy.expect("traffic policy").tls.expect("tls");
    assert_eq!(tls.mode, MtlsMode::IstioMutual);
}

/// `trafficPolicy.portLevelSettings` → per-port `MeshTrafficPolicy` entries
/// keyed by port number. Cold-path apply layers these onto the matching
/// upstream's `port_overrides`. Phantom ports (DR entry references a port
/// unused by any target) are skipped with a warning at apply time, which is
/// tested in the lib unit suite — we just confirm the translator parses both
/// port entries.
#[test]
fn dr_port_level_settings() {
    register_feature!(
        category = CATEGORY,
        feature = "trafficPolicy.portLevelSettings[]",
        status = Status::Supported,
        notes = "Per-port traffic policy entries; HTTP/H2/H3/gRPC/WebSocket/HBONE dispatch consults port_overrides[port].",
    );
    let dr = translated(json!({
        "host": "echo.default.svc.cluster.local",
        "trafficPolicy": {
            "portLevelSettings": [
                {"port": {"number": 8080}, "connectionPool": {"tcp": {"connectTimeout": "1s"}}},
                {"port": {"number": 9090}, "connectionPool": {"tcp": {"connectTimeout": "5s"}}}
            ]
        }
    }));
    assert_eq!(dr.port_level_settings.len(), 2);
    let p8080 = dr.port_level_settings.get(&8080).expect("port 8080");
    assert_eq!(p8080.connect_timeout_ms, Some(1000));
    let p9090 = dr.port_level_settings.get(&9090).expect("port 9090");
    assert_eq!(p9090.connect_timeout_ms, Some(5000));
}

/// `trafficPolicy.portLevelSettings[].tls` — per-port backend TLS. Resolved at
/// apply time onto `Upstream.port_overrides[port].tls` and projected onto the
/// effective proxy's `resolved_tls` for dials to that port (apply behavior is
/// pinned by `dr_port_level_tls_resolves_onto_port_override` and
/// `resolve_effective_proxy_applies_per_port_tls` in the source crate).
#[test]
fn dr_port_level_tls() {
    register_feature!(
        category = CATEGORY,
        feature = "trafficPolicy.portLevelSettings[].tls",
        status = Status::Supported,
        notes = "Per-port backend TLS: resolved onto port_overrides[port].tls and projected onto the effective proxy's resolved_tls. resolved_tls is part of the backend pool key, so a distinct per-port TLS posture fragments its own pool.",
    );
    let dr = translated(json!({
        "host": "secure.default.svc.cluster.local",
        "trafficPolicy": {
            "portLevelSettings": [
                {"port": {"number": 8443}, "tls": {"mode": "SIMPLE", "caCertificates": "/etc/certs/ca.pem"}}
            ]
        }
    }));
    let port = dr.port_level_settings.get(&8443).expect("port 8443 entry");
    let tls = port.tls.as_ref().expect("port 8443 tls translated");
    assert_eq!(tls.mode, MtlsMode::Simple);
    assert_eq!(tls.ca_certificates.as_deref(), Some("/etc/certs/ca.pem"));
}

/// `subsets[]` with per-subset `trafficPolicy` → `SubsetDefinition` +
/// `SubsetTrafficPolicy.tls` per CLAUDE.md "subsets[].trafficPolicy.tls is
/// projected onto Upstream.resolved_subset_tls[subset_name] and partitions
/// the backend pool."
#[test]
fn dr_subsets_with_traffic_policy() {
    register_feature!(
        category = CATEGORY,
        feature = "subsets[].name + subsets[].labels + subsets[].trafficPolicy",
        status = Status::Supported,
        notes = "Per-subset TLS overlay lands on Upstream.resolved_subset_tls[<subset>]; partitions backend pool.",
    );
    let dr = translated(json!({
        "host": "echo.default.svc.cluster.local",
        "subsets": [
            {"name": "v1", "labels": {"version": "v1"}},
            {"name": "v2", "labels": {"version": "v2"}, "trafficPolicy": {
                "tls": {"mode": "SIMPLE", "sni": "v2.example.com"}
            }}
        ]
    }));
    assert_eq!(dr.subsets.len(), 2);
    let v2 = dr
        .subsets
        .iter()
        .find(|s| s.name == "v2")
        .expect("v2 subset");
    let tls = v2
        .traffic_policy
        .as_ref()
        .expect("v2 traffic policy")
        .tls
        .as_ref()
        .expect("v2 tls");
    assert_eq!(tls.sni.as_deref(), Some("v2.example.com"));
}
