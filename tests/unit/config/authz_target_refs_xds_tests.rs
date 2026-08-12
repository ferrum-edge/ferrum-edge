//! External xDS round-trip coverage for AuthorizationPolicy `targetRefs`
//! (issue #3226 / PR #3602).
//!
//! Drives the real CP encode (`translate_mesh_slice_to_snapshot` /
//! `build_slice_carriers`) → ECDS TypedExtensionConfig wire → DP decode
//! (`MeshSliceCarrier::decode` / `apply_carrier`) path, then proves that an
//! xDS-recovered slice enforces exactly what a natively-built one does:
//!
//! * a `GatewayClass` policy attaches only on an exact class stamp;
//! * a mixed `{Service, other-Gateway}` policy does not broaden onto a sibling
//!   destination just because it was retained (finding 1);
//! * a missing / malformed / oversized / duplicate class carrier never invents
//!   or reuses a stamp, and an ENFORCING class-targeted policy without its
//!   authoritative carrier refuses the slice instead of silently degrading to
//!   allow-by-default.

use std::collections::HashMap;

use ferrum_edge::identity::spiffe::{SpiffeId, TrustDomain};
use ferrum_edge::modes::mesh::config::{
    MAX_POLICY_TARGET_REF_NAME_LEN, MAX_POLICY_TARGET_REF_NAMESPACE_LEN, MeshConfig, MeshPolicy,
    MeshRule, MeshService, PolicyAction, PolicyScope, PolicyTargetAttachment, WaypointAttachment,
    Workload, WorkloadSelector,
};
use ferrum_edge::modes::mesh::policy::{
    MeshAuthzDecision, MeshAuthzRequest, evaluate_mesh_authorization_policies,
};
use ferrum_edge::modes::mesh::runtime::PolicyScopeCache;
use ferrum_edge::modes::mesh::slice::MeshSlice;
use ferrum_edge::plugins::mesh::authz::MeshAuthz;
use ferrum_edge::plugins::{Plugin, PluginResult, RequestContext};
use ferrum_edge::xds::proto;
use ferrum_edge::xds::{
    ECDS_TYPE_URL, FERRUM_ECDS_WAYPOINT_GATEWAY_CLASS_TYPE_URL,
    MAX_WAYPOINT_GATEWAY_CLASS_CARRIER_BYTES, MAX_WAYPOINT_GATEWAY_CLASS_LEN, MeshSliceCarrier,
    apply_carrier, build_slice_carriers, translate_mesh_slice_to_snapshot,
};
use prost::Message;
use serde_json::json;

const WAYPOINT: &str = "reviews-waypoint";
const OTHER_WAYPOINT: &str = "other-waypoint";
const NS: &str = "default";

fn deny_policy(name: &str, attachments: Vec<PolicyTargetAttachment>) -> MeshPolicy {
    MeshPolicy {
        name: name.to_string(),
        namespace: "istio-system".to_string(),
        scope: PolicyScope::TargetRefs { attachments },
        rules: vec![MeshRule {
            action: PolicyAction::Deny,
            ..MeshRule::default()
        }],
    }
}

fn gateway_class_deny_policy(class_name: &str) -> MeshPolicy {
    deny_policy(
        "deny-class",
        vec![PolicyTargetAttachment::GatewayClass {
            name: class_name.to_string(),
        }],
    )
}

fn waypoint_slice(class: Option<&str>, policies: Vec<MeshPolicy>) -> MeshSlice {
    MeshSlice {
        node_id: "wp-node".to_string(),
        namespace: NS.to_string(),
        waypoint_name: Some(WAYPOINT.to_string()),
        waypoint_gateway_class: class.map(str::to_string),
        mesh_policies: policies,
        version: "v1".to_string(),
        ..MeshSlice::default()
    }
}

/// Recover a slice from a CP snapshot the same way the DP folds ECDS carriers,
/// then stamp `waypoint_name` from the DP client config (name rides Node
/// metadata; class rides the dedicated carrier).
fn recover_from_snapshot(
    snapshot: &ferrum_edge::xds::XdsSnapshot,
    waypoint_name: Option<&str>,
) -> Result<MeshSlice, String> {
    let mut recovered = MeshSlice {
        node_id: "wp-node".to_string(),
        namespace: NS.to_string(),
        waypoint_name: waypoint_name.map(str::to_string),
        version: snapshot.version.clone(),
        ..MeshSlice::default()
    };
    let mut class_seen = false;
    for resource in snapshot.resources(ECDS_TYPE_URL) {
        let typed = proto::TypedExtensionConfig::decode(resource.value.as_slice())
            .map_err(|e| format!("TypedExtensionConfig decode: {e}"))?;
        let Some(inner) = typed.typed_config.as_ref() else {
            continue;
        };
        match MeshSliceCarrier::decode(&inner.type_url, &inner.value) {
            Ok(Some(carrier @ MeshSliceCarrier::WaypointGatewayClass(_))) => {
                if class_seen {
                    return Err(
                        "duplicate WaypointGatewayClass carrier; exactly one authoritative value required"
                            .to_string(),
                    );
                }
                class_seen = true;
                apply_carrier(&mut recovered, carrier);
            }
            Ok(Some(carrier)) => apply_carrier(&mut recovered, carrier),
            Ok(None) => {}
            Err(e) => {
                return Err(format!(
                    "carrier decode failed for '{}': {e}",
                    inner.type_url
                ));
            }
        }
    }
    Ok(recovered)
}

async fn gateway_class_policy_enforced(slice: &MeshSlice) -> bool {
    let plugin = MeshAuthz::new(&json!({ "mesh_slice": slice }))
        .expect("mesh_authz builds from recovered slice");
    let mut ctx = RequestContext::new("127.0.0.1".to_string(), "GET".to_string(), "/".to_string());
    matches!(
        plugin.authorize(&mut ctx).await,
        PluginResult::Reject { .. }
    )
}

fn workload_for(service: &str) -> Workload {
    Workload {
        spiffe_id: SpiffeId::new(format!("spiffe://cluster.local/ns/{NS}/sa/{service}"))
            .expect("valid spiffe"),
        selector: WorkloadSelector {
            labels: HashMap::from([("app".to_string(), "backend".to_string())]),
            namespace: Some(NS.to_string()),
        },
        service_name: service.to_string(),
        service_namespace: None,
        addresses: vec!["10.0.0.1".to_string()],
        ports: Vec::new(),
        trust_domain: TrustDomain::new("cluster.local").expect("trust domain"),
        namespace: NS.to_string(),
        network: None,
        cluster: None,
        weight: None,
        locality: None,
        service_account: Some(service.to_string()),
        pod_uid: None,
        node_waypoint: None,
        remote_provenance: false,
    }
}

/// Evaluate the recovered slice's policies against one destination service,
/// using the slice's own recovered waypoint identity — the exact evidence the
/// request path uses.
fn destination_decision(slice: &MeshSlice, service: &str) -> MeshAuthzDecision {
    let scope = PolicyScopeCache::for_destination_service(&workload_for(service), NS, service);
    let waypoint = WaypointAttachment {
        namespace: &slice.namespace,
        name: slice.waypoint_name.as_deref(),
        gateway_class: slice.waypoint_gateway_class.as_deref(),
    };
    let request = MeshAuthzRequest {
        method: Some("GET".to_string()),
        path: Some("/".to_string()),
        ..MeshAuthzRequest::default()
    };
    evaluate_mesh_authorization_policies(
        slice
            .mesh_policies
            .iter()
            .filter(|policy| scope.policy_applies_for_destination(policy, waypoint)),
        &request,
    )
}

#[tokio::test]
async fn xds_round_trip_exact_matching_gateway_class_retains_authz_policy() {
    let native = waypoint_slice(
        Some("istio-waypoint"),
        vec![gateway_class_deny_policy("istio-waypoint")],
    );
    let snapshot = translate_mesh_slice_to_snapshot(&native);
    let recovered =
        recover_from_snapshot(&snapshot, Some(WAYPOINT)).expect("exact-class snapshot recovers");
    assert_eq!(
        recovered.waypoint_gateway_class.as_deref(),
        Some("istio-waypoint")
    );
    assert_eq!(recovered.mesh_policies, native.mesh_policies);
    assert!(
        gateway_class_policy_enforced(&recovered).await,
        "exact matching GatewayClass policy must survive mesh_authz retain"
    );
}

#[tokio::test]
async fn xds_round_trip_different_gateway_class_drops_authz_policy() {
    let native = waypoint_slice(
        Some("ferrum-waypoint"),
        vec![gateway_class_deny_policy("istio-waypoint")],
    );
    let snapshot = translate_mesh_slice_to_snapshot(&native);
    let recovered = recover_from_snapshot(&snapshot, Some(WAYPOINT))
        .expect("different-class snapshot recovers");
    assert_eq!(
        recovered.waypoint_gateway_class.as_deref(),
        Some("ferrum-waypoint")
    );
    assert!(
        !gateway_class_policy_enforced(&recovered).await,
        "mismatched GatewayClass must fail closed at mesh_authz retain"
    );
}

/// Finding 1 over the xDS carrier path: a `{Service reviews, Gateway
/// other-waypoint}` policy survives the round trip intact (attachments are NOT
/// pruned), and the recovered slice still enforces it only on `reviews`.
#[tokio::test]
async fn xds_round_trip_mixed_target_refs_do_not_broaden_to_sibling_destination() {
    let mixed = deny_policy(
        "deny-reviews",
        vec![
            PolicyTargetAttachment::Service {
                namespace: NS.to_string(),
                name: "reviews".to_string(),
            },
            PolicyTargetAttachment::Gateway {
                namespace: NS.to_string(),
                name: OTHER_WAYPOINT.to_string(),
            },
        ],
    );
    let native = waypoint_slice(Some("istio-waypoint"), vec![mixed.clone()]);
    let recovered =
        recover_from_snapshot(&translate_mesh_slice_to_snapshot(&native), Some(WAYPOINT))
            .expect("mixed-ref snapshot recovers");

    assert_eq!(
        recovered.mesh_policies, native.mesh_policies,
        "the carrier must round-trip the full attachment list without pruning"
    );
    assert_eq!(
        destination_decision(&recovered, "reviews"),
        MeshAuthzDecision::Deny {
            policy: "deny-reviews".to_string()
        }
    );
    assert_eq!(
        destination_decision(&recovered, "ratings"),
        MeshAuthzDecision::Allow,
        "the unmatched other-waypoint Gateway arm must not broaden onto a sibling destination"
    );

    // Native parity: the same slice built without the xDS hop decides the same.
    assert_eq!(
        destination_decision(&native, "reviews"),
        destination_decision(&recovered, "reviews")
    );
    assert_eq!(
        destination_decision(&native, "ratings"),
        destination_decision(&recovered, "ratings")
    );
}

/// An ENFORCING GatewayClass-targeted policy whose authoritative class carrier
/// is absent must refuse the plugin generation (the DP keeps last-good) rather
/// than silently dropping the policy into allow-by-default.
#[test]
fn missing_gateway_class_carrier_refuses_an_enforcing_class_policy() {
    let native = waypoint_slice(
        Some("istio-waypoint"),
        vec![gateway_class_deny_policy("istio-waypoint")],
    );
    let carriers: Vec<_> = build_slice_carriers(&native)
        .into_iter()
        .filter(|c| !matches!(c, MeshSliceCarrier::WaypointGatewayClass(_)))
        .collect();
    let mut recovered = MeshSlice {
        node_id: native.node_id.clone(),
        namespace: native.namespace.clone(),
        waypoint_name: native.waypoint_name.clone(),
        mesh_policies: native.mesh_policies.clone(),
        ..MeshSlice::default()
    };
    for carrier in carriers {
        apply_carrier(&mut recovered, carrier);
    }
    assert!(
        recovered.waypoint_gateway_class.is_none(),
        "missing carrier must not invent a class stamp"
    );

    let error = MeshAuthz::new(&json!({ "mesh_slice": recovered }))
        .err()
        .expect("an enforcing class policy without its class stamp must refuse the slice");
    assert!(
        error.contains("no authoritative waypoint gateway class"),
        "unexpected refusal: {error}"
    );
}

/// An AUDIT-only class-targeted policy is non-enforcing, so a missing class
/// stamp is not a fail-open and must not refuse the slice.
#[tokio::test]
async fn missing_gateway_class_carrier_tolerates_an_audit_only_class_policy() {
    let audit = MeshPolicy {
        name: "audit-class".to_string(),
        namespace: "istio-system".to_string(),
        scope: PolicyScope::TargetRefs {
            attachments: vec![PolicyTargetAttachment::GatewayClass {
                name: "istio-waypoint".to_string(),
            }],
        },
        rules: vec![MeshRule {
            action: PolicyAction::Audit,
            ..MeshRule::default()
        }],
    };
    let slice = waypoint_slice(None, vec![audit]);
    assert!(
        !gateway_class_policy_enforced(&slice).await,
        "an audit-only policy never rejects and must not refuse the slice"
    );
}

#[test]
fn xds_round_trip_malformed_and_oversized_gateway_class_carrier_rejected() {
    assert!(
        MeshSliceCarrier::decode(FERRUM_ECDS_WAYPOINT_GATEWAY_CLASS_TYPE_URL, b"{not-json")
            .is_err()
    );
    assert!(
        MeshSliceCarrier::decode(FERRUM_ECDS_WAYPOINT_GATEWAY_CLASS_TYPE_URL, b"\"\"").is_err()
    );
    let oversized =
        serde_json::to_vec(&"a".repeat(MAX_WAYPOINT_GATEWAY_CLASS_LEN + 1)).expect("json");
    assert!(
        MeshSliceCarrier::decode(FERRUM_ECDS_WAYPOINT_GATEWAY_CLASS_TYPE_URL, &oversized).is_err()
    );
    let huge_payload = format!(
        "\"{}\"",
        "x".repeat(MAX_WAYPOINT_GATEWAY_CLASS_CARRIER_BYTES)
    );
    assert!(
        MeshSliceCarrier::decode(
            FERRUM_ECDS_WAYPOINT_GATEWAY_CLASS_TYPE_URL,
            huge_payload.as_bytes()
        )
        .is_err()
    );
}

#[tokio::test]
async fn xds_round_trip_gateway_class_change_updates_authz_and_content_eq() {
    let istio = waypoint_slice(
        Some("istio-waypoint"),
        vec![gateway_class_deny_policy("istio-waypoint")],
    );
    let ferrum = waypoint_slice(
        Some("ferrum-waypoint"),
        vec![gateway_class_deny_policy("istio-waypoint")],
    );
    assert!(
        !istio.content_eq(&ferrum),
        "class-only change must move MeshSlice::content_eq"
    );

    let istio_recovered =
        recover_from_snapshot(&translate_mesh_slice_to_snapshot(&istio), Some(WAYPOINT))
            .expect("istio class recovers");
    let ferrum_recovered =
        recover_from_snapshot(&translate_mesh_slice_to_snapshot(&ferrum), Some(WAYPOINT))
            .expect("ferrum class recovers");

    assert!(gateway_class_policy_enforced(&istio_recovered).await);
    assert!(
        !gateway_class_policy_enforced(&ferrum_recovered).await,
        "class change to a non-matching stamp must drop the policy"
    );
    assert!(!istio_recovered.content_eq(&ferrum_recovered));
}

#[tokio::test]
async fn xds_round_trip_gateway_class_carrier_removal_clears_stamp_and_policy() {
    let with_class = waypoint_slice(
        Some("istio-waypoint"),
        vec![gateway_class_deny_policy("istio-waypoint")],
    );
    let without_class = waypoint_slice(None, Vec::new());
    assert!(!with_class.content_eq(&without_class));

    let removed = recover_from_snapshot(
        &translate_mesh_slice_to_snapshot(&without_class),
        Some(WAYPOINT),
    )
    .expect("class-less snapshot recovers");
    assert!(
        removed.waypoint_gateway_class.is_none(),
        "carrier removal must clear the class, not reuse a stale stamp"
    );
    assert!(!gateway_class_policy_enforced(&removed).await);

    assert!(
        !build_slice_carriers(&without_class)
            .iter()
            .any(|c| matches!(c, MeshSliceCarrier::WaypointGatewayClass(_)))
    );
    assert!(
        build_slice_carriers(&with_class)
            .iter()
            .any(|c| matches!(c, MeshSliceCarrier::WaypointGatewayClass(_)))
    );
}

#[test]
fn native_target_refs_reject_over_limit_hostile_strings() {
    let over_name = "n".repeat(MAX_POLICY_TARGET_REF_NAME_LEN + 1);
    let over_ns = "n".repeat(MAX_POLICY_TARGET_REF_NAMESPACE_LEN + 1);

    let errors = MeshConfig {
        istio_root_namespace: NS.to_string(),
        services: vec![MeshService {
            name: "reviews".to_string(),
            namespace: NS.to_string(),
            ports: Vec::new(),
            workloads: Vec::new(),
            protocol_overrides: HashMap::new(),
            cluster_ips: Vec::new(),
            uid: None,
        }],
        mesh_policies: vec![MeshPolicy {
            name: "hostile".to_string(),
            namespace: NS.to_string(),
            scope: PolicyScope::TargetRefs {
                attachments: vec![
                    PolicyTargetAttachment::Service {
                        namespace: over_ns,
                        name: "reviews".to_string(),
                    },
                    PolicyTargetAttachment::GatewayClass { name: over_name },
                ],
            },
            rules: vec![MeshRule {
                action: PolicyAction::Deny,
                ..MeshRule::default()
            }],
        }],
        ..MeshConfig::default()
    }
    .validate();

    assert!(
        errors
            .iter()
            .any(|e| e.contains("namespace") && e.contains("at most")),
        "over-limit namespace must reject: {errors:?}"
    );
    assert!(
        errors
            .iter()
            .any(|e| e.contains("name") && e.contains("at most")),
        "over-limit GatewayClass/name must reject: {errors:?}"
    );
}

#[test]
fn native_target_refs_reject_over_limit_attachment_count() {
    let attachments: Vec<_> = (0..(ferrum_edge::modes::mesh::config::MAX_POLICY_TARGET_REFS + 1))
        .map(|i| PolicyTargetAttachment::Service {
            namespace: NS.to_string(),
            name: format!("svc-{i}"),
        })
        .collect();
    let errors = MeshConfig {
        mesh_policies: vec![MeshPolicy {
            name: "too-many".to_string(),
            namespace: NS.to_string(),
            scope: PolicyScope::TargetRefs { attachments },
            rules: vec![MeshRule {
                action: PolicyAction::Deny,
                ..MeshRule::default()
            }],
        }],
        ..MeshConfig::default()
    }
    .validate();
    assert!(
        errors
            .iter()
            .any(|e| e.contains("at most") && e.contains("attachments")),
        "over-limit attachment count must reject: {errors:?}"
    );
}
