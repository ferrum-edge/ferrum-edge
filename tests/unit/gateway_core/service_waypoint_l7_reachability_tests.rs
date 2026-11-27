//! The ServiceWaypoint L7 partition route is reachable ONLY from an admitted,
//! fenced L7-terminated HBONE CONNECT (issue #7501).
//!
//! `mesh_route_admitted_for_direction` stays strict for every outer inbound
//! listener: it refuses carried `istio-vs-*` routes and the default L7 routes
//! on the Sidecar `:15006`, the NodeWaypoint `:15008` and a direct request on
//! the ServiceWaypoint `:15008`. The request handler skips that direction
//! filter for exactly one case: a request whose route came from a bound
//! Service's partition, which requires `RequestContext::service_waypoint_l7`.
//! These checks pin, over the source, that the only producer of that context
//! is the inner server of a tunnel that `terminate_connect` admitted AND
//! registered with the admission fence, so no listener, header or other path
//! can reach the bypass. The behavioural halves (a direct request never
//! reaches an L7 route; carried routes refused on all three inbound
//! listeners) are pinned by the integration suites.

use std::path::Path;

const PROXY_SOURCE: &str = include_str!("../../../src/proxy/mod.rs");
const L7_SOURCE: &str = include_str!("../../../src/proxy/service_waypoint_l7_proxy.rs");
const MESH_SOURCE: &str = include_str!("../../../src/modes/mesh/mod.rs");

/// Source with `//` comments removed, so a comment naming a pattern never
/// counts.
fn code(source: &str) -> String {
    source
        .lines()
        .filter(|line| !line.trim_start().starts_with("//"))
        .collect::<Vec<_>>()
        .join("\n")
}

fn rust_files(dir: &Path, out: &mut Vec<std::path::PathBuf>) {
    for entry in std::fs::read_dir(dir).expect("read src dir") {
        let path = entry.expect("dir entry").path();
        if path.is_dir() {
            rust_files(&path, out);
        } else if path.extension().is_some_and(|ext| ext == "rs") {
            out.push(path);
        }
    }
}

/// Every non-comment occurrence of `pattern` under `src/`, as
/// `(relative path, count)`.
fn occurrences(pattern: &str) -> Vec<(String, usize)> {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
    let mut files = Vec::new();
    rust_files(&root, &mut files);
    files.sort();
    files
        .into_iter()
        .filter_map(|path| {
            let source = std::fs::read_to_string(&path).expect("read source");
            let count = code(&source).matches(pattern).count();
            (count > 0).then(|| {
                (
                    path.strip_prefix(&root)
                        .expect("under src")
                        .display()
                        .to_string(),
                    count,
                )
            })
        })
        .collect()
}

/// The connection metadata that carries the context is set to `Some` in
/// exactly one place: the inner server's per-request service. Every listener
/// sets it to `None` (or leaves the default).
#[test]
fn only_the_inner_server_produces_the_service_waypoint_connection_context() {
    assert_eq!(
        occurrences("service_waypoint_l7: Some("),
        vec![("proxy/service_waypoint_l7_proxy.rs".to_string(), 1)],
        "only the L7 inner server may hand a request a ServiceWaypoint context"
    );
    let serve = code(L7_SOURCE);
    let serve_start = serve
        .find("async fn serve_tunnel(")
        .expect("serve_tunnel exists");
    let produced = serve
        .find("service_waypoint_l7: Some(")
        .expect("the inner server produces the context");
    assert!(
        produced > serve_start,
        "the context is produced inside serve_tunnel"
    );
}

/// The request context's field is copied only from that connection metadata.
#[test]
fn the_request_context_field_is_copied_only_from_the_connection_metadata() {
    assert_eq!(
        occurrences("ctx.service_waypoint_l7 = Some("),
        vec![("proxy/mod.rs".to_string(), 1)]
    );
    let proxy = code(PROXY_SOURCE);
    assert!(
        proxy
            .contains("let service_waypoint_l7 = connection_metadata.service_waypoint_l7.clone();"),
        "the handler reads the context from the connection metadata"
    );
    assert!(
        proxy.contains("ctx.service_waypoint_l7 = Some(Arc::clone(service_waypoint));"),
        "and copies exactly that value onto the request context"
    );
    // No other assignment of the field anywhere.
    assert_eq!(
        occurrences(".service_waypoint_l7 = "),
        vec![("proxy/mod.rs".to_string(), 1)]
    );
}

/// `serve_tunnel` runs only from `terminate_connect`, after the tunnel was
/// admitted by every outer gate and registered with the admission fence.
#[test]
fn the_inner_server_runs_only_for_a_fenced_admitted_connect() {
    let l7 = code(L7_SOURCE);
    assert_eq!(
        occurrences("serve_tunnel("),
        vec![("proxy/service_waypoint_l7_proxy.rs".to_string(), 2)],
        "one definition and one call"
    );
    let terminate = l7
        .find("fn terminate_connect(")
        .expect("terminate_connect exists");
    let peer_gate = l7[terminate..]
        .find("admit_verified_peer_certificate_principal(ctx)")
        .expect("peer identity gate");
    let credential_gate = l7[terminate..]
        .find("HbonePeerCredential::from_admitted_connect")
        .expect("credential gate");
    let transport_gate = l7[terminate..]
        .find("mesh_inbound_peer_auth_transport_mismatch(")
        .expect("PeerAuthentication gate");
    let fenced = l7[terminate..]
        .find("hbone_admission_fence.admit(")
        .expect("fence registration");
    let gate = l7[terminate..]
        .find("HboneRelayDestinationGate::ServiceWaypointL7(")
        .expect("the ServiceWaypointL7 fence gate");
    let served = l7[terminate..]
        .find("serve_tunnel(")
        .expect("the inner server call");
    assert!(
        peer_gate < credential_gate
            && credential_gate < transport_gate
            && transport_gate < fenced
            && fenced < gate
            && gate < served,
        "peer identity, credential and transport gates, then fence registration under the \
         ServiceWaypointL7 gate, then the inner server"
    );
    // `terminate_connect` itself is reached only from the classification of an
    // authenticated byte-stream HBONE CONNECT on an inbound listener.
    let proxy = code(PROXY_SOURCE);
    assert_eq!(occurrences("terminate_connect("), {
        let mut expected = vec![
            ("proxy/mod.rs".to_string(), 1),
            ("proxy/service_waypoint_l7_proxy.rs".to_string(), 1),
        ];
        expected.sort();
        expected
    });
    let call = proxy
        .find("service_waypoint_l7_proxy::terminate_connect(")
        .expect("the classification call");
    let guard = proxy[..call]
        .rfind("if is_hbone_connect\n")
        .expect("the CONNECT guard precedes the call");
    let guard_block = &proxy[guard..call];
    assert!(
        guard_block.contains(
            "ctx.mesh_direction == Some(crate::modes::mesh::MeshTrafficDirection::Inbound)"
        ) && guard_block.contains("ServiceWaypointConnectMode::TerminateL7("),
        "only an inbound HBONE CONNECT the target index terminates reaches it"
    );
    assert!(
        proxy.contains(
            "service_waypoint_l7.is_none() && is_hbone_connect_request(&req, &state.env_config);"
        ),
        "an inner request is never itself an HBONE CONNECT"
    );
}

/// The direction filter is skipped only for a partition route, and the
/// partition is derived only from the request's ServiceWaypoint context.
#[test]
fn the_direction_filter_is_skipped_only_for_partition_routes() {
    let proxy = code(PROXY_SOURCE);
    assert_eq!(
        proxy
            .matches("service_waypoint_partition.is_none()")
            .count(),
        1,
        "exactly one exemption"
    );
    let exemption = proxy
        .find("service_waypoint_partition.is_none()")
        .expect("the exemption");
    let admission = proxy[exemption..]
        .find("crate::modes::mesh::mesh_route_admitted_for_direction(")
        .expect("the strict predicate follows in the same guard");
    assert!(
        admission < 200,
        "the exemption guards the direction filter itself"
    );
    let derived = proxy
        .find("let service_waypoint_partition = match ctx.service_waypoint_l7.clone() {")
        .expect("the partition comes from the request's context");
    assert!(derived < exemption);
    // The strict predicate keeps refusing the default L7 routes on every
    // listener, and carried routes on every inbound listener.
    let mesh = code(MESH_SOURCE);
    let predicate = mesh
        .find("pub(crate) fn mesh_route_admitted_for_direction(")
        .expect("predicate");
    let body_end = mesh[predicate..]
        .find("\n}\n")
        .map_or(mesh.len(), |end| predicate + end);
    let body = &mesh[predicate..body_end];
    assert!(body.contains(
        "if service_waypoint_l7::is_service_waypoint_l7_route_id(id) {\n        return false;"
    ));
    assert!(body.contains("|| !config::is_virtual_service_http_route_proxy_id(id)"));
}
