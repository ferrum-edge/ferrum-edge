//! JWT-authenticated, namespace-authorized backend policy discovery (#5994).
//!
//! This is metadata about the loaded enforcement policy, never a DNS probe or
//! an assertion that a control plane's policy is installed on its data planes.
//! On a control plane, `data_plane_attestation` additionally reports the
//! policies its connected data planes self-reported over ConfigSync (#6020).

use bytes::Bytes;
use http_body_util::Full;
use hyper::{Response, StatusCode};
use serde::Serialize;
use serde_json::json;

use super::{
    AdminState, NamespaceServingScope, active_data_plane_namespace, json_response,
    namespace_serving_scope,
};
use crate::config::BackendAllowIps;
use crate::grpc::backend_egress_attestation::{
    DataPlaneEgressSummary, EgressMode, ReportedEgressPolicy, attestation_label,
};
use crate::grpc::cp_server::DpNodeInfo;

/// `data_plane_attestation.source`: reports arrive on ConfigSync Subscribe.
const ATTESTATION_SOURCE: &str = "configsync-subscribe";

#[derive(Serialize)]
struct BackendEgressPolicyResponse<'a> {
    schema_version: u8,
    ip_classification: &'static str,
    namespace: &'a str,
    policy_scope: &'static str,
    enforcement_scope: &'static str,
    mode: &'static str,
    mode_allowed_ip_classes: &'static [&'static str],
    mode_blocked_ip_classes: &'static [&'static str],
    dangerous_ranges_blocked: bool,
    allow_cidr_overrides_present: bool,
    deny_cidr_overrides_present: bool,
    evaluation_order: [&'static str; 4],
    public_only_guaranteed: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    data_plane_attestation: Option<DataPlaneAttestation>,
}

/// Live ConfigSync streams of one namespace and their reported policies. Each
/// stream counts as one data plane, so streams sharing a node id are all
/// listed and all weaken the aggregate.
#[derive(Serialize)]
struct DataPlaneAttestation {
    source: &'static str,
    #[serde(flatten)]
    summary: DataPlaneEgressSummary,
    data_planes: Vec<DataPlaneEgressEntry>,
}

/// One live stream. The build is omitted: the ConfigSync build gate already
/// pins it to the CP's own, and namespace viewers need no fleet build detail.
#[derive(Serialize)]
struct DataPlaneEgressEntry {
    node_id: String,
    connected_at: String,
    attestation: &'static str,
    policy: Option<ReportedEgressPolicy>,
}

pub(super) fn handle_get(state: &AdminState, namespace: &str) -> Response<Full<Bytes>> {
    // ProxyState is authoritative on serving processes. CP/node-agent admin
    // states hold the same loaded policy for admission, without a local dialer.
    let policy = state
        .proxy_state
        .as_ref()
        .map_or(&state.backend_allow_ips, |proxy| {
            &proxy.env_config.backend_allow_ips
        })
        .metadata();
    let mode = EgressMode::from_allow_ips(&policy.allow_ips);
    let scope = namespace_serving_scope(state);
    let enforcement_scope = match scope {
        NamespaceServingScope::SingleNamespaceDataPlane
            if active_data_plane_namespace(state) != Some(namespace) =>
        {
            "unserved-namespace"
        }
        NamespaceServingScope::SingleNamespaceDataPlane => "local-data-plane",
        NamespaceServingScope::ControlPlane => "admission-only",
        NamespaceServingScope::NoDataPlane => "no-data-plane",
    };
    // Any allow override may bypass the private/reserved block. Do not try to
    // reclassify or enumerate CIDRs here: a conservative false lets consumers
    // fail closed without duplicating the enforcement classifier. Only a local
    // data plane serving this namespace enforces the policy it reports; CP
    // admission, unserved-namespace and no-data-plane metadata guarantee nothing.
    let public_only_guaranteed = enforcement_scope == "local-data-plane"
        && matches!(policy.allow_ips, BackendAllowIps::Public)
        && !policy.allow_cidr_overrides_present;
    // The CP's own fields keep their admission-only meaning; what its data
    // planes report is a separate, additive object.
    let data_plane_attestation = match scope {
        NamespaceServingScope::ControlPlane => Some(connected_data_planes(state, namespace)),
        _ => None,
    };
    let response = BackendEgressPolicyResponse {
        // v2: `public_only_guaranteed` also requires local enforcement. The
        // optional CP `data_plane_attestation` object is additive within v2.
        schema_version: 2,
        ip_classification: "ferrum-private-reserved-v1",
        namespace,
        policy_scope: "process",
        enforcement_scope,
        mode: mode.as_str(),
        mode_allowed_ip_classes: mode.allowed_ip_classes(),
        mode_blocked_ip_classes: mode.blocked_ip_classes(),
        dangerous_ranges_blocked: policy.dangerous_ranges_blocked,
        allow_cidr_overrides_present: policy.allow_cidr_overrides_present,
        deny_cidr_overrides_present: policy.deny_cidr_overrides_present,
        evaluation_order: ["allow-cidrs", "deny-cidrs", "dangerous-ranges", "ip-mode"],
        public_only_guaranteed,
        data_plane_attestation,
    };
    json_response(StatusCode::OK, &json!(response))
}

/// Only data planes subscribed to the requested namespace serve it, and the
/// caller is authorized for that namespace alone. The registry holds one entry
/// per live stream, so every stream of this namespace is counted, including
/// several sharing one node id; another namespace's streams never are.
fn connected_data_planes(state: &AdminState, namespace: &str) -> DataPlaneAttestation {
    let mut nodes: Vec<DpNodeInfo> = state
        .dp_registry
        .as_ref()
        .map(|registry| registry.snapshot())
        .unwrap_or_default();
    nodes.retain(|node| node.namespace == namespace);
    nodes.sort_by(|a, b| {
        a.node_id
            .cmp(&b.node_id)
            .then(a.connected_at.cmp(&b.connected_at))
    });
    let reports = nodes.iter().map(|node| node.backend_egress_policy);
    let summary = DataPlaneEgressSummary::from_reports(reports);
    let data_planes = nodes
        .into_iter()
        .map(|node| DataPlaneEgressEntry {
            attestation: attestation_label(node.backend_egress_policy.as_ref()),
            policy: node.backend_egress_policy,
            node_id: node.node_id,
            connected_at: node.connected_at.to_rfc3339(),
        })
        .collect();
    DataPlaneAttestation {
        source: ATTESTATION_SOURCE,
        summary,
        data_planes,
    }
}
