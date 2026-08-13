//! Every CRD the Gateway API controller watches must be granted by the chart's
//! control-plane ClusterRole.
//!
//! A watched-but-ungranted kind is not a quiet degradation: the watcher starts
//! unconditionally once the CRD group is discovered, the API server rejects
//! each list `403`, and the reflector retries for the life of the process. That
//! retry pressure competes with every other scope's relist generation, and a
//! reflector store that cannot finish relisting keeps serving its previous
//! object set — including a `Namespace` set whose labels predate the operator's
//! last edit, which silently denies `allowedRoutes.namespaces.from: Selector`
//! attachments.
//!
//! Static `include_str!` / const inspection only — no Kubernetes runtime.

use ferrum_edge::k8s_controller::watcher::{GATEWAY_API_CRDS, K8S_NAMESPACE_RESOURCES};

const CONTROL_PLANE_RBAC: &str =
    include_str!("../../../charts/ferrum-mesh/templates/control-plane-rbac.yaml");

/// Plurals whose `status` subresource the Gateway API status writer patches.
/// `ServiceImport` is read-only (GEP-1748 backendRef resolution).
const STATUS_WRITTEN_PLURALS: &[&str] = &[
    "gatewayclasses",
    "gateways",
    "httproutes",
    "grpcroutes",
    "tlsroutes",
    "tcproutes",
    "udproutes",
    "backendtlspolicies",
    "backendlbpolicies",
    "xbackendtrafficpolicies",
    "listenersets",
];

fn rule_grants(group: &str, plural: &str) -> bool {
    let expected_group = format!("[\"{group}\"]");
    CONTROL_PLANE_RBAC
        .split("  - apiGroups: ")
        .skip(1)
        .any(|rule| {
            let Some((declared_group, body)) = rule.split_once('\n') else {
                return false;
            };
            declared_group.trim() == expected_group
                && body.lines().any(|line| {
                    line.trim()
                        .strip_prefix("- ")
                        .is_some_and(|resource| resource == plural)
                })
        })
}

#[test]
fn every_watched_gateway_api_crd_is_granted_by_the_control_plane_cluster_role() {
    for crd in GATEWAY_API_CRDS {
        assert!(
            rule_grants(crd.group, crd.plural),
            "chart RBAC must grant list/watch on {} ({}) or its watcher 403-loops for the \
             life of the control plane",
            crd.plural,
            crd.group
        );
    }
}

#[test]
fn every_status_written_gateway_api_kind_is_granted_its_status_subresource() {
    for plural in STATUS_WRITTEN_PLURALS {
        let crd = GATEWAY_API_CRDS
            .iter()
            .find(|crd| crd.plural == *plural)
            .unwrap_or_else(|| panic!("{plural} is claimed as status-written but is not watched"));
        assert!(
            rule_grants(crd.group, &format!("{plural}/status")),
            "chart RBAC must grant the {plural} status subresource under apiGroup {}",
            crd.group
        );
    }
}

/// `allowedRoutes.namespaces.from: Selector` is evaluated against the labels of
/// the route's own `Namespace` object, so the cluster-scoped Namespace watch is
/// part of the Gateway API authorization boundary rather than an optimization.
#[test]
fn the_namespace_watch_backing_allowed_routes_selectors_is_granted() {
    assert!(
        K8S_NAMESPACE_RESOURCES
            .iter()
            .any(|resource| resource.kind == "Namespace" && !resource.namespaced),
        "the Namespace watch must stay cluster-scoped"
    );
    assert!(
        rule_grants("", "namespaces"),
        "chart RBAC must grant the cluster-scoped Namespace watch that \
         allowedRoutes namespace selectors resolve against"
    );
}
