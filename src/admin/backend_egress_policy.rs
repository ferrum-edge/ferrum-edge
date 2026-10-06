//! JWT-authenticated, namespace-authorized backend policy discovery (#5994).
//!
//! This is metadata about the loaded enforcement policy, never a DNS probe or
//! an assertion that a control plane's policy is installed on its data planes.

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
    let (mode, allowed, blocked): (&str, &[&str], &[&str]) = match policy.allow_ips {
        BackendAllowIps::Both => ("both", &["public", "private-reserved"], &[]),
        BackendAllowIps::Public => ("public", &["public"], &["private-reserved"]),
        BackendAllowIps::Private => ("private", &["private-reserved"], &["public"]),
    };
    let enforcement_scope = match namespace_serving_scope(state) {
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
    let response = BackendEgressPolicyResponse {
        // v2: `public_only_guaranteed` also requires local enforcement.
        schema_version: 2,
        ip_classification: "ferrum-private-reserved-v1",
        namespace,
        policy_scope: "process",
        enforcement_scope,
        mode,
        mode_allowed_ip_classes: allowed,
        mode_blocked_ip_classes: blocked,
        dangerous_ranges_blocked: policy.dangerous_ranges_blocked,
        allow_cidr_overrides_present: policy.allow_cidr_overrides_present,
        deny_cidr_overrides_present: policy.deny_cidr_overrides_present,
        evaluation_order: ["allow-cidrs", "deny-cidrs", "dangerous-ranges", "ip-mode"],
        public_only_guaranteed,
    };
    json_response(StatusCode::OK, &json!(response))
}
