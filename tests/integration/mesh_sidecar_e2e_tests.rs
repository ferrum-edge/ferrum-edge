//! End-to-end coverage for the `Sidecar` mesh topology.
//!
//! These tests drive real HTTP requests through a mesh-mode `ProxyState`
//! (the same code path Ferrum takes in production when
//! `FERRUM_MODE=mesh`/`FERRUM_MESH_TOPOLOGY=sidecar`), so they exercise
//! the slice-apply → plugin-injection → router-cache pipeline together
//! with the request hot path. Pure projection / validation behaviour is
//! covered separately by inline `#[cfg(test)]` modules in
//! `src/modes/mesh/mod.rs` and the unit suite — the goal here is to lock
//! in observable, request-level behaviour for the sidecar topology.

use std::collections::HashMap;
use std::time::Duration;

use ferrum_edge::modes::mesh::config::{
    MeshSidecar, MeshSidecarEgress, OutboundTrafficPolicy, PolicyScope,
};
use ferrum_edge::modes::mesh::{
    MESH_ACCESS_LOG_PLUGIN_ID, MESH_AUTHZ_PLUGIN_ID, MESH_SPIFFE_IDENTITY_PLUGIN_ID,
    MESH_WORKLOAD_METRICS_PLUGIN_ID, MeshListenerKind, MeshTopology, MeshTrafficDirection,
    prepare_gateway_config_for_mesh,
};

use super::mesh_test_support::{
    build_mesh_proxy_state, capturing_backend_handler, default_mesh_runtime, echo_backend_handler,
    gateway_config_with_mesh, http_proxy, http_upstream, mesh_config_with, policy_allow_principal,
    service_for, start_http_backend, start_mesh_gateway, workload_for,
};

const REVIEWS_HOST: &str = "reviews.default.svc.cluster.local";

/// Drive one HTTP/1.1 GET through the mesh gateway. Returns
/// `(status_code, body)`; panics on any I/O / protocol failure since these
/// tests are happy-path-focused.
async fn issue_get(addr: std::net::SocketAddr, host: &str, path: &str) -> (u16, String) {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let mut stream = tokio::net::TcpStream::connect(addr).await.expect("connect");
    let _ = stream.set_nodelay(true);
    let req = format!(
        "GET {path} HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n",
        path = path,
        host = host,
    );
    stream
        .write_all(req.as_bytes())
        .await
        .expect("write request");
    // Do NOT half-close the write side here — hyper's H1 server treats a
    // FIN on the request side before the response has flushed as a
    // `client_disconnect` and abandons the upstream call. `Connection: close`
    // alone tells the proxy to close after the response, which is what we
    // want when we follow up with `read_to_end`.
    let mut response = Vec::new();
    tokio::time::timeout(Duration::from_secs(5), stream.read_to_end(&mut response))
        .await
        .expect("read response timed out")
        .expect("read response");
    let text = String::from_utf8_lossy(&response).into_owned();
    let (head, body) = text
        .split_once("\r\n\r\n")
        .map(|(h, b)| (h.to_string(), b.to_string()))
        .unwrap_or((text.clone(), String::new()));
    let status = head
        .lines()
        .next()
        .and_then(|line| line.split_whitespace().nth(1))
        .and_then(|s| s.parse::<u16>().ok())
        .unwrap_or_else(|| {
            panic!(
                "status code missing — full response text:\n{text}\n(end of response, len={})",
                text.len()
            )
        });
    (status, body)
}

#[test]
fn sidecar_listener_plan_includes_outbound_capture_and_inbound_mtls() {
    let runtime = default_mesh_runtime();
    let plan = runtime.listener_plan();
    assert_eq!(plan.len(), 2, "sidecar topology has 2 listeners");
    let outbound = plan
        .iter()
        .find(|l| l.direction == MeshTrafficDirection::Outbound)
        .expect("outbound listener present");
    assert_eq!(
        outbound.kind,
        MeshListenerKind::PlaintextCapture,
        "sidecar outbound is plaintext capture"
    );
    let inbound = plan
        .iter()
        .find(|l| l.direction == MeshTrafficDirection::Inbound)
        .expect("inbound listener present");
    assert_eq!(
        inbound.kind,
        MeshListenerKind::MtlsTermination,
        "sidecar inbound is mTLS termination"
    );
}

#[test]
fn sidecar_prepare_injects_default_mesh_plugins() {
    let mut runtime = default_mesh_runtime();
    runtime.topology = MeshTopology::Sidecar;
    let workload = workload_for("reviews", "default", [("app", "reviews")], ["10.0.0.1"]);
    let service = service_for("reviews", "default", &[&workload]);
    let mesh = mesh_config_with(vec![workload], vec![service], Vec::new());
    let config = gateway_config_with_mesh(Vec::new(), Vec::new(), mesh);
    let prepared = prepare_gateway_config_for_mesh(config, &runtime).expect("mesh-prepared");
    let ids: std::collections::HashSet<_> = prepared
        .plugin_configs
        .iter()
        .map(|p| p.id.as_str())
        .collect();
    assert!(
        ids.contains(MESH_SPIFFE_IDENTITY_PLUGIN_ID),
        "spiffe_identity plugin injected, got {ids:?}"
    );
    assert!(
        ids.contains(MESH_AUTHZ_PLUGIN_ID),
        "mesh_authz plugin injected, got {ids:?}"
    );
    assert!(
        ids.contains(MESH_WORKLOAD_METRICS_PLUGIN_ID),
        "workload_metrics plugin injected, got {ids:?}"
    );
    assert!(
        ids.contains(MESH_ACCESS_LOG_PLUGIN_ID),
        "mesh access-log (stdout_logging) plugin injected, got {ids:?}"
    );
}

#[test]
fn sidecar_source_locality_projects_onto_upstreams_when_workload_matches() {
    // Stamp the runtime's workload identity to one that has a locality, then
    // verify the prepared config back-fills `Upstream.source_locality`. This
    // is the mesh-mode path that lets the locality-LB algorithm prefer
    // same-AZ targets without an admin-API change.
    let mut runtime = default_mesh_runtime();
    runtime.workload_spiffe_id = Some("spiffe://cluster.local/ns/default/sa/reviews".to_string());
    runtime.namespace = "default".to_string();
    let mut workload = workload_for("reviews", "default", [("app", "reviews")], ["10.0.0.1"]);
    workload.locality = Some("us-west/us-west-1/a".to_string());

    let mut upstream = http_upstream("reviews-u", REVIEWS_HOST, 8080);
    upstream.source_locality = None;
    let proxy = {
        let mut p = http_proxy("reviews-p", "reviews.example.com", 8080);
        p.upstream_id = Some("reviews-u".to_string());
        p
    };
    let mesh = mesh_config_with(vec![workload], Vec::new(), Vec::new());
    let config = gateway_config_with_mesh(vec![proxy], vec![upstream], mesh);
    let prepared = prepare_gateway_config_for_mesh(config, &runtime).expect("mesh-prepared");
    let projected = prepared
        .upstreams
        .iter()
        .find(|u| u.id == "reviews-u")
        .expect("upstream survived projection");
    assert_eq!(
        projected.source_locality.as_deref(),
        Some("us-west/us-west-1/a"),
        "source locality propagated from matched workload"
    );
}

#[test]
fn sidecar_authz_plugin_config_carries_mesh_slice_with_workload_identity() {
    // The injected `mesh_authz` plugin must receive a fully-formed
    // `mesh_slice` block that includes the workload-identity fields the
    // plugin uses for its construction-time scope filter (`namespace`,
    // `labels`, `mesh_policies`).
    //
    // NOTE: Scope filtering is applied twice in production —
    //   1. at slice projection time (`MeshSlice::from_gateway_config`
    //      drops policies whose `PolicyScope` doesn't match this
    //      workload's namespace/labels), and
    //   2. defensively again in `MeshAuthz::new` (the plugin re-filters
    //      its own `mesh_slice.mesh_policies`).
    // So a policy scoped to a non-applicable workload is gone by the
    // time the plugin config is serialised — the `mesh_slice.mesh_policies`
    // array reaching the plugin contains only the policies that already
    // passed slice-level filtering. This test locks in *both* the
    // identity context being preserved AND the slice-level filter
    // already running before plugin construction.
    let mut runtime = default_mesh_runtime();
    runtime
        .workload_labels
        .insert("app".to_string(), "reviews".to_string());
    let reviews_policy = policy_allow_principal(
        "reviews-allow",
        "default",
        PolicyScope::WorkloadSelector {
            selector: ferrum_edge::modes::mesh::config::WorkloadSelector {
                labels: HashMap::from([("app".to_string(), "reviews".to_string())]),
                namespace: Some("default".to_string()),
            },
        },
        "spiffe://cluster.local/ns/default/sa/client",
    );
    let ratings_policy = policy_allow_principal(
        "ratings-allow",
        "default",
        PolicyScope::WorkloadSelector {
            selector: ferrum_edge::modes::mesh::config::WorkloadSelector {
                labels: HashMap::from([("app".to_string(), "ratings".to_string())]),
                namespace: Some("default".to_string()),
            },
        },
        "spiffe://cluster.local/ns/default/sa/client",
    );
    let mesh = mesh_config_with(
        Vec::new(),
        Vec::new(),
        vec![reviews_policy.clone(), ratings_policy.clone()],
    );
    let config = gateway_config_with_mesh(Vec::new(), Vec::new(), mesh);
    let prepared = prepare_gateway_config_for_mesh(config, &runtime).expect("mesh-prepared");
    let authz = prepared
        .plugin_configs
        .iter()
        .find(|p| p.id == MESH_AUTHZ_PLUGIN_ID)
        .expect("mesh_authz plugin present");
    let mesh_slice = authz
        .config
        .get("mesh_slice")
        .expect("mesh_authz config carries `mesh_slice` block");
    let labels = mesh_slice
        .get("labels")
        .and_then(|v| v.as_object())
        .expect("mesh_slice carries `labels` object");
    assert_eq!(
        labels.get("app").and_then(|v| v.as_str()),
        Some("reviews"),
        "workload labels propagated into mesh_slice (so the plugin's \
         construction-time filter sees the right identity)"
    );
    let policies = mesh_slice
        .get("mesh_policies")
        .and_then(|v| v.as_array())
        .expect("mesh_slice carries `mesh_policies` array");
    let policy_names: Vec<_> = policies
        .iter()
        .filter_map(|p| p.get("name").and_then(|n| n.as_str()))
        .collect();
    // Slice projection DOES scope-filter mesh_policies (see
    // `MeshSlice::from_gateway_config`), so the policy scoped to a
    // non-applicable workload is dropped before the plugin config is
    // serialised. The matching policy survives. This is the
    // observable contract the request hot path depends on.
    assert!(
        policy_names.contains(&"reviews-allow"),
        "reviews-scoped policy must survive slice projection for an \
         app=reviews workload, got {policy_names:?}"
    );
    assert!(
        !policy_names.contains(&"ratings-allow"),
        "ratings-scoped policy must be filtered out by slice projection \
         for an app=reviews workload, got {policy_names:?}"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn sidecar_outbound_request_reaches_backend_through_mesh_proxy_chain() {
    let (backend_addr, backend_handle) = start_http_backend(echo_backend_handler()).await;
    let runtime = default_mesh_runtime();
    let workload = workload_for("reviews", "default", [("app", "reviews")], ["127.0.0.1"]);
    let service = service_for("reviews", "default", &[&workload]);
    let proxy = http_proxy("reviews-p", "reviews.example.com", backend_addr.port());
    let mesh = mesh_config_with(vec![workload], vec![service], Vec::new());

    let state = build_mesh_proxy_state(&runtime, vec![proxy], Vec::new(), mesh);
    let (gateway_addr, shutdown_tx) = start_mesh_gateway(state).await;

    let (status, body) = issue_get(gateway_addr, "reviews.example.com", "/api/items").await;
    assert_eq!(
        status, 200,
        "sidecar outbound capture should route to backend"
    );
    assert!(
        body.contains("backend-ok"),
        "response body should come from backend, got {body:?}"
    );

    shutdown_tx.send(true).expect("shutdown gateway");
    drop(backend_handle); // backend task drops cleanly when listener closes
}

#[tokio::test(flavor = "multi_thread")]
async fn sidecar_proxy_chain_forwards_host_and_path_to_backend() {
    let (responder, captured) = capturing_backend_handler();
    let (backend_addr, _backend_handle) = start_http_backend(responder).await;
    let runtime = default_mesh_runtime();
    let workload = workload_for("reviews", "default", [("app", "reviews")], ["127.0.0.1"]);
    let service = service_for("reviews", "default", &[&workload]);
    let proxy = {
        // `strip_listen_path: true` and `listen_path: "/"`: the proxy is
        // a host-only route effectively, so the original path flows
        // through to the backend unchanged.
        let mut p = http_proxy("reviews-p", "reviews.example.com", backend_addr.port());
        p.strip_listen_path = false;
        p
    };
    let mesh = mesh_config_with(vec![workload], vec![service], Vec::new());

    let state = build_mesh_proxy_state(&runtime, vec![proxy], Vec::new(), mesh);
    let (gateway_addr, shutdown_tx) = start_mesh_gateway(state).await;

    let (status, _body) =
        issue_get(gateway_addr, "reviews.example.com", "/api/v1/items?id=42").await;
    assert_eq!(status, 200);

    // Backend received the GET. Inspect captured request lines to confirm
    // path + Host propagated through the proxy chain.
    let log = captured.lock().expect("captured log lock");
    assert!(!log.is_empty(), "backend received at least one request");
    let first = log
        .first()
        .expect("captured request")
        .lines()
        .next()
        .unwrap_or("")
        .to_string();
    assert!(
        first.contains("/api/v1/items"),
        "request line should preserve original path, got {first:?}"
    );

    shutdown_tx.send(true).expect("shutdown gateway");
}

#[tokio::test(flavor = "multi_thread")]
async fn sidecar_handles_multiple_sequential_requests_on_same_listener() {
    let (responder, captured) = capturing_backend_handler();
    let (backend_addr, _backend_handle) = start_http_backend(responder).await;
    let runtime = default_mesh_runtime();
    let workload = workload_for("reviews", "default", [("app", "reviews")], ["127.0.0.1"]);
    let service = service_for("reviews", "default", &[&workload]);
    let proxy = http_proxy("reviews-p", "reviews.example.com", backend_addr.port());
    let mesh = mesh_config_with(vec![workload], vec![service], Vec::new());

    let state = build_mesh_proxy_state(&runtime, vec![proxy], Vec::new(), mesh);
    let (gateway_addr, shutdown_tx) = start_mesh_gateway(state).await;

    for i in 0..5 {
        let (status, _body) =
            issue_get(gateway_addr, "reviews.example.com", &format!("/req/{i}")).await;
        assert_eq!(status, 200, "request {i} failed");
    }
    assert_eq!(
        captured.lock().expect("captured log lock").len(),
        5,
        "backend received all 5 sequential requests"
    );

    shutdown_tx.send(true).expect("shutdown gateway");
}

#[tokio::test(flavor = "multi_thread")]
async fn sidecar_returns_404_for_unmatched_host() {
    let (backend_addr, _backend_handle) = start_http_backend(echo_backend_handler()).await;
    let runtime = default_mesh_runtime();
    let workload = workload_for("reviews", "default", [("app", "reviews")], ["127.0.0.1"]);
    let service = service_for("reviews", "default", &[&workload]);
    let proxy = http_proxy("reviews-p", "reviews.example.com", backend_addr.port());
    let mesh = mesh_config_with(vec![workload], vec![service], Vec::new());

    let state = build_mesh_proxy_state(&runtime, vec![proxy], Vec::new(), mesh);
    let (gateway_addr, shutdown_tx) = start_mesh_gateway(state).await;

    let (status, _body) = issue_get(gateway_addr, "unknown.example.com", "/").await;
    assert_eq!(
        status, 404,
        "unmatched host should fall through to 404 (no catch-all proxy)"
    );

    shutdown_tx.send(true).expect("shutdown gateway");
}

// ── Sidecar outboundTrafficPolicy (issue #3262) ───────────────────────────
//
// These exercise the projection + capture-classification halves of the
// workload-scoped policy: that the applicable `Sidecar` decides whether the
// HTTP-family `mesh_outbound_registry` plugin is injected, and that the
// stream-family enforcement built from the same slice actually denies unknown
// destinations on the capture port while skipping non-capture listeners.
// Translation, selection precedence, and carrier parity live in
// `tests/unit/config/sidecar_outbound_policy_tests.rs`; the HTTP request-path
// rejection lives in `tests/integration/mesh_outbound_registry_route_miss_tests.rs`.

const REGISTRY_PLUGIN_ID: &str = ferrum_edge::modes::mesh::MESH_OUTBOUND_REGISTRY_PLUGIN_ID;
/// Concrete outbound capture port. The default test runtime binds `:0`, and the
/// injection path correctly skips a port-0 capture listener (there is nothing to
/// enforce against), so a policy test must declare a real port.
const CAPTURE_PORT: u16 = 15001;

/// Sidecar-enforcing runtime for `app=reviews` in `default`, with a concrete
/// outbound capture port and the given mesh-wide policy.
fn outbound_policy_runtime(
    mesh_wide: OutboundTrafficPolicy,
    sidecar_enforced: bool,
) -> ferrum_edge::modes::mesh::MeshRuntimeConfig {
    let mut runtime = default_mesh_runtime();
    runtime.outbound_traffic_policy = mesh_wide;
    runtime.outbound_listen_addr = format!("127.0.0.1:{CAPTURE_PORT}").parse().expect("addr");
    runtime.sidecar_enforced = sidecar_enforced;
    runtime.workload_labels = HashMap::from([("app".to_string(), "reviews".to_string())]);
    runtime
}

/// Namespace-default `Sidecar` carrying `policy`, with an allow-everything
/// egress scope so narrowing never confounds the policy assertion.
fn outbound_policy_sidecar(policy: Option<OutboundTrafficPolicy>) -> MeshSidecar {
    MeshSidecar {
        name: "default-sidecar".to_string(),
        namespace: "default".to_string(),
        workload_selector: None,
        egress_inherits_defaults: false,
        egress: vec![MeshSidecarEgress {
            hosts: vec!["*/*".to_string()],
            port: None,
        }],
        ingress_declared: false,
        ingress: Vec::new(),
        outbound_traffic_policy: policy,
    }
}

/// One `reviews` service/workload plus a `Sidecar` carrying `policy`.
fn outbound_policy_mesh(
    policy: Option<OutboundTrafficPolicy>,
) -> ferrum_edge::modes::mesh::config::MeshConfig {
    let workload = workload_for("reviews", "default", [("app", "reviews")], ["10.0.0.1"]);
    let service = service_for("reviews", "default", &[&workload]);
    let mut mesh = mesh_config_with(vec![workload], vec![service], Vec::new());
    mesh.sidecars = vec![outbound_policy_sidecar(policy)];
    mesh
}

fn registry_plugin_injected(
    mesh_wide: OutboundTrafficPolicy,
    sidecar_policy: Option<OutboundTrafficPolicy>,
    sidecar_enforced: bool,
) -> bool {
    let runtime = outbound_policy_runtime(mesh_wide, sidecar_enforced);
    let mesh = outbound_policy_mesh(sidecar_policy);
    let config = gateway_config_with_mesh(Vec::new(), Vec::new(), mesh);
    let prepared = prepare_gateway_config_for_mesh(config, &runtime).expect("prepared");
    prepared
        .plugin_configs
        .iter()
        .any(|p| p.id == REGISTRY_PLUGIN_ID)
}

/// A workload-scoped `REGISTRY_ONLY` arms the HTTP-family gate even though the
/// mesh-wide policy (and the env default) are permissive.
#[test]
fn sidecar_registry_only_policy_arms_the_outbound_registry_plugin() {
    assert!(
        registry_plugin_injected(
            OutboundTrafficPolicy::AllowAny,
            Some(OutboundTrafficPolicy::RegistryOnly),
            true,
        ),
        "a Sidecar REGISTRY_ONLY must inject mesh_outbound_registry"
    );
}

/// The mirror direction, and the reason the tiers must stay distinct: a
/// workload-scoped `ALLOW_ANY` disarms an otherwise mesh-wide `REGISTRY_ONLY`
/// for exactly this workload (Istio semantics).
#[test]
fn sidecar_allow_any_policy_disarms_a_mesh_wide_registry_only() {
    assert!(
        registry_plugin_injected(OutboundTrafficPolicy::RegistryOnly, None, true),
        "control: the mesh-wide policy alone arms the gate"
    );
    assert!(
        !registry_plugin_injected(
            OutboundTrafficPolicy::RegistryOnly,
            Some(OutboundTrafficPolicy::AllowAny),
            true,
        ),
        "a Sidecar ALLOW_ANY must override the mesh-wide REGISTRY_ONLY"
    );
}

/// Without the rollout gate the workload-scoped value is inert in BOTH
/// directions — it never arms the gate, and it never disarms a mesh-wide one.
#[test]
fn sidecar_outbound_policy_is_inert_without_the_enforcement_gate() {
    assert!(
        !registry_plugin_injected(
            OutboundTrafficPolicy::AllowAny,
            Some(OutboundTrafficPolicy::RegistryOnly),
            false,
        ),
        "FERRUM_MESH_SIDECAR_ENFORCED gates arming the registry"
    );
    assert!(
        registry_plugin_injected(
            OutboundTrafficPolicy::RegistryOnly,
            Some(OutboundTrafficPolicy::AllowAny),
            false,
        ),
        "and a gated-off Sidecar must not weaken the mesh-wide policy either"
    );
}

/// The injected plugin carries the slice-derived registry and the capture port,
/// so the arming decision produces a usable gate rather than an empty one.
#[test]
fn sidecar_armed_registry_plugin_carries_the_slice_destinations_and_capture_port() {
    let runtime = outbound_policy_runtime(OutboundTrafficPolicy::AllowAny, true);
    let mesh = outbound_policy_mesh(Some(OutboundTrafficPolicy::RegistryOnly));
    let config = gateway_config_with_mesh(Vec::new(), Vec::new(), mesh);
    let prepared = prepare_gateway_config_for_mesh(config, &runtime).expect("prepared");
    let plugin = prepared
        .plugin_configs
        .iter()
        .find(|p| p.id == REGISTRY_PLUGIN_ID)
        .expect("registry plugin injected");
    let registry_value = plugin.config["registry"].clone();
    let registry: Vec<String> = serde_json::from_value(registry_value).expect("registry");
    assert!(
        registry.iter().any(|entry| entry.starts_with(REVIEWS_HOST)),
        "the slice's own service must be an admitted destination, got {registry:?}"
    );
    let ports_value = plugin.config["outbound_listen_ports"].clone();
    let ports: Vec<u16> = serde_json::from_value(ports_value).expect("capture ports");
    assert_eq!(
        ports,
        vec![CAPTURE_PORT],
        "the gate must be scoped to the mesh outbound capture listener"
    );
}

/// Capture-path classification: the stream-family enforcement built from a
/// Sidecar-`REGISTRY_ONLY` slice denies an unknown destination on the capture
/// port, admits a slice-declared one, and skips a non-capture listener (so the
/// policy never gates inbound traffic).
#[test]
fn sidecar_registry_only_capture_classification_denies_unknown_destinations() {
    use ferrum_edge::modes::mesh::outbound_enforcement::{Decision, MeshOutboundEnforcement};

    let runtime = outbound_policy_runtime(OutboundTrafficPolicy::AllowAny, true);
    let mesh = outbound_policy_mesh(Some(OutboundTrafficPolicy::RegistryOnly));
    let config = gateway_config_with_mesh(Vec::new(), Vec::new(), mesh);
    let slice = ferrum_edge::modes::mesh::slice::MeshSlice::from_gateway_config(
        &config,
        runtime.mesh_slice_request(),
    );
    assert_eq!(
        slice.effective_outbound_traffic_policy(runtime.outbound_traffic_policy),
        OutboundTrafficPolicy::RegistryOnly,
        "the Sidecar must decide the effective policy for this workload"
    );

    let enforcement = MeshOutboundEnforcement::from_slice(
        &slice,
        &runtime.cluster_domain,
        runtime.namespace.clone(),
        vec![CAPTURE_PORT],
        runtime.outbound_registry_reject_status,
    )
    .expect("enforcement built from a RegistryOnly slice");

    assert_eq!(
        enforcement.check_destination(CAPTURE_PORT, REVIEWS_HOST, 8080),
        Decision::Admit,
        "a slice-declared destination stays reachable"
    );
    assert_eq!(
        enforcement.check_destination(CAPTURE_PORT, "evil.example.com", 443),
        Decision::Deny,
        "an unknown destination is refused on the capture listener"
    );
    assert_eq!(
        enforcement.check_destination(CAPTURE_PORT, "10.9.9.9", 443),
        Decision::Deny,
        "a raw-IP escape to an address the slice never declared is refused"
    );
    assert_eq!(
        enforcement.check_destination(15006, "evil.example.com", 443),
        Decision::Skip,
        "outbound policy must never gate the inbound mTLS listener"
    );
    let unknown = Some("evil.example.com");
    assert_eq!(
        enforcement.http_route_miss_reject_status(CAPTURE_PORT, unknown, Some(443)),
        Some(runtime.outbound_registry_reject_status),
        "an outbound-capture HTTP route miss takes the configured reject status"
    );
}

/// A Sidecar `ALLOW_ANY` leaves the stream-family slot empty, so every captured
/// connect falls through — the documented passthrough behaviour.
#[test]
fn sidecar_allow_any_leaves_the_capture_path_ungated() {
    let runtime = outbound_policy_runtime(OutboundTrafficPolicy::RegistryOnly, true);
    let mesh = outbound_policy_mesh(Some(OutboundTrafficPolicy::AllowAny));
    let config = gateway_config_with_mesh(Vec::new(), Vec::new(), mesh);
    let slice = ferrum_edge::modes::mesh::slice::MeshSlice::from_gateway_config(
        &config,
        runtime.mesh_slice_request(),
    );
    assert_eq!(
        slice.effective_outbound_traffic_policy(runtime.outbound_traffic_policy),
        OutboundTrafficPolicy::AllowAny,
        "the Sidecar override must reach the effective policy"
    );
    assert!(
        !registry_plugin_injected(
            OutboundTrafficPolicy::RegistryOnly,
            Some(OutboundTrafficPolicy::AllowAny),
            true,
        ),
        "and no HTTP-family gate is installed"
    );
}

// ── Rewritten kubelet application probes (issue #4533) ───────────────────
//
// The injector points every application `httpGet` / `tcpSocket` / `grpc`
// probe at the sidecar's own probe port and records the ORIGINAL handler in
// `FERRUM_MESH_APP_PROBES`. These tests run the real server against real
// loopback applications — an HTTP server, a bare TCP listener, and a tonic
// `grpc.health.v1` server — and assert the 200/503 mapping per probe type,
// plus that `timeoutSeconds` actually bounds a hung application.
mod app_probe_rewrite {
    use crate::scaffolding::port_registry::TestSocket;

    use std::collections::BTreeMap;
    use std::sync::Arc;
    use std::time::{Duration, Instant};

    use ferrum_edge::health_check::grpc_health_v1::{
        HealthCheckRequest, HealthCheckResponse,
        health_check_response::ServingStatus,
        health_server::{Health, HealthServer},
    };
    use ferrum_edge::modes::mesh::app_probe::{
        AppProbeGrpc, AppProbeHttpGet, AppProbeScheme, AppProbeServer, AppProbeSpec,
        AppProbeTcpSocket, app_probe_key, app_probe_path, run_app_probe_server,
    };
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;
    use tokio_stream::wrappers::TcpListenerStream;

    /// Minimal loopback HTTP application that answers every request with a
    /// fixed status line, like a real `httpGet`-probed container would.
    async fn start_http_app(status_line: &'static str) -> u16 {
        let listener = TcpListener::bind_test("127.0.0.1:0")
            .await
            .expect("bind app");
        let port = listener.local_addr().expect("app addr").port();
        tokio::spawn(async move {
            while let Ok((mut stream, _)) = listener.accept().await {
                tokio::spawn(async move {
                    let mut buf = [0u8; 1024];
                    let _ = stream.read(&mut buf).await;
                    let _ = stream
                        .write_all(
                            format!("HTTP/1.1 {status_line}\r\nContent-Length: 0\r\n\r\n")
                                .as_bytes(),
                        )
                        .await;
                    let _ = stream.flush().await;
                });
            }
        });
        port
    }

    /// A listener that accepts and then never answers: the probe can connect
    /// but the HTTP exchange never completes, which is what `timeoutSeconds`
    /// exists to bound.
    async fn start_black_hole_app() -> u16 {
        let listener = TcpListener::bind_test("127.0.0.1:0")
            .await
            .expect("bind hole");
        let port = listener.local_addr().expect("hole addr").port();
        tokio::spawn(async move {
            let mut held = Vec::new();
            while let Ok((stream, _)) = listener.accept().await {
                held.push(stream);
            }
        });
        port
    }

    /// A bound-and-accepting TCP port, which is all a `tcpSocket` probe needs.
    async fn start_tcp_app() -> u16 {
        let listener = TcpListener::bind_test("127.0.0.1:0")
            .await
            .expect("bind tcp");
        let port = listener.local_addr().expect("tcp addr").port();
        tokio::spawn(async move { while listener.accept().await.is_ok() {} });
        port
    }

    /// A closed port: nothing is listening, so connect fails immediately.
    async fn closed_port() -> u16 {
        let listener = TcpListener::bind_test("127.0.0.1:0")
            .await
            .expect("bind closed");
        let port = listener.local_addr().expect("closed addr").port();
        drop(listener);
        port
    }

    struct StubHealth;

    #[tonic::async_trait]
    impl Health for StubHealth {
        async fn check(
            &self,
            request: tonic::Request<HealthCheckRequest>,
        ) -> Result<tonic::Response<HealthCheckResponse>, tonic::Status> {
            let status = match request.into_inner().service.as_str() {
                "down" => ServingStatus::NotServing,
                "unknown" => return Err(tonic::Status::not_found("no such service")),
                _ => ServingStatus::Serving,
            };
            Ok(tonic::Response::new(HealthCheckResponse {
                status: status as i32,
            }))
        }
    }

    async fn start_grpc_health_app() -> u16 {
        let listener = TcpListener::bind_test("127.0.0.1:0")
            .await
            .expect("bind grpc");
        let port = listener.local_addr().expect("grpc addr").port();
        tokio::spawn(async move {
            let _ = tonic::transport::Server::builder()
                .add_service(HealthServer::new(StubHealth))
                .serve_with_incoming(TcpListenerStream::new(listener))
                .await;
        });
        port
    }

    /// Start the real probe server on an ephemeral loopback port.
    async fn start_probe_server(targets: BTreeMap<String, AppProbeSpec>) -> std::net::SocketAddr {
        let listener = TcpListener::bind_test("127.0.0.1:0")
            .await
            .expect("bind probe");
        let addr = listener.local_addr().expect("probe addr");
        let server = Arc::new(AppProbeServer::new(targets));
        let (shutdown_tx, rx) = tokio::sync::watch::channel(false);
        tokio::spawn(async move {
            // Hold the sender inside the task so the accept loop never sees a
            // closed channel and shuts down mid-assertion.
            let _shutdown_tx = shutdown_tx;
            run_app_probe_server(listener, server, rx).await;
        });
        addr
    }

    async fn probe_status(addr: std::net::SocketAddr, path: &str) -> u16 {
        let mut stream = tokio::net::TcpStream::connect(addr).await.expect("connect");
        let request = format!("GET {path} HTTP/1.1\r\nHost: probe\r\nConnection: close\r\n\r\n");
        stream
            .write_all(request.as_bytes())
            .await
            .expect("write probe request");
        let mut response = Vec::new();
        stream
            .read_to_end(&mut response)
            .await
            .expect("read probe response");
        let head = String::from_utf8_lossy(&response);
        let status = head
            .split_whitespace()
            .nth(1)
            .expect("status code in response");
        status.parse::<u16>().expect("numeric status")
    }

    fn http_target(port: u16, path: &str, timeout_seconds: u64) -> AppProbeSpec {
        AppProbeSpec::from_http_get(
            AppProbeHttpGet {
                path: path.to_string(),
                port,
                scheme: AppProbeScheme::Http,
                host: None,
                http_headers: Vec::new(),
            },
            timeout_seconds,
        )
    }

    #[tokio::test]
    async fn every_rewritten_probe_type_maps_to_200_or_503() {
        let healthy_http = start_http_app("200 OK").await;
        let redirecting_http = start_http_app("301 Moved Permanently").await;
        let unhealthy_http = start_http_app("503 Service Unavailable").await;
        let tcp_up = start_tcp_app().await;
        let tcp_down = closed_port().await;
        let grpc = start_grpc_health_app().await;

        let mut targets = BTreeMap::new();
        targets.insert(
            app_probe_key("app", "livenessProbe"),
            http_target(healthy_http, "/livez", 5),
        );
        targets.insert(
            app_probe_key("app", "readinessProbe"),
            http_target(redirecting_http, "/readyz", 5),
        );
        targets.insert(
            app_probe_key("app", "startupProbe"),
            http_target(unhealthy_http, "/startz", 5),
        );
        targets.insert(
            app_probe_key("tcpapp", "readinessProbe"),
            AppProbeSpec::from_tcp_socket(AppProbeTcpSocket { port: tcp_up }, 5),
        );
        targets.insert(
            app_probe_key("tcpapp", "livenessProbe"),
            AppProbeSpec::from_tcp_socket(AppProbeTcpSocket { port: tcp_down }, 5),
        );
        targets.insert(
            app_probe_key("grpcapp", "readinessProbe"),
            AppProbeSpec::from_grpc(
                AppProbeGrpc {
                    port: grpc,
                    service: None,
                },
                5,
            ),
        );
        targets.insert(
            app_probe_key("grpcapp", "livenessProbe"),
            AppProbeSpec::from_grpc(
                AppProbeGrpc {
                    port: grpc,
                    service: Some("down".to_string()),
                },
                5,
            ),
        );
        targets.insert(
            app_probe_key("grpcapp", "startupProbe"),
            AppProbeSpec::from_grpc(
                AppProbeGrpc {
                    port: closed_port().await,
                    service: None,
                },
                5,
            ),
        );

        let addr = start_probe_server(targets).await;

        for (container, probe, expected) in [
            // kubelet treats any 2xx/3xx as success.
            ("app", "livenessProbe", 200),
            ("app", "readinessProbe", 200),
            ("app", "startupProbe", 503),
            // `tcpSocket` success is a completed connect.
            ("tcpapp", "readinessProbe", 200),
            ("tcpapp", "livenessProbe", 503),
            // gRPC health: only SERVING is success.
            ("grpcapp", "readinessProbe", 200),
            ("grpcapp", "livenessProbe", 503),
            ("grpcapp", "startupProbe", 503),
        ] {
            let path = app_probe_path(container, probe);
            assert_eq!(
                probe_status(addr, &path).await,
                expected,
                "{container}/{probe} must map to {expected}"
            );
        }

        // Nothing outside the recorded target set is reachable through this
        // listener — it is not a proxy.
        assert_eq!(probe_status(addr, "/app-probe/app/unknownProbe").await, 404);
        assert_eq!(probe_status(addr, "/livez").await, 404);
    }

    #[tokio::test]
    async fn a_hung_application_is_bounded_by_the_recorded_timeout_seconds() {
        let black_hole = start_black_hole_app().await;
        let mut targets = BTreeMap::new();
        targets.insert(
            app_probe_key("app", "livenessProbe"),
            http_target(black_hole, "/livez", 1),
        );
        let addr = start_probe_server(targets).await;

        let started = Instant::now();
        let status = probe_status(addr, &app_probe_path("app", "livenessProbe")).await;
        let elapsed = started.elapsed();

        assert_eq!(status, 503, "a hung application must not report ready");
        assert!(
            elapsed >= Duration::from_millis(900),
            "the probe must actually wait out timeoutSeconds, took {elapsed:?}"
        );
        assert!(
            elapsed < Duration::from_secs(10),
            "the probe must not outlive timeoutSeconds by an order of magnitude, took {elapsed:?}"
        );
    }
}
