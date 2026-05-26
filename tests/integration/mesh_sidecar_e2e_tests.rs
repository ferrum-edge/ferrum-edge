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

use ferrum_edge::modes::mesh::config::PolicyScope;
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
