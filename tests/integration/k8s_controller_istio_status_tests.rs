//! Integration tests for the T2-B Istio CRD status writer.
//!
//! Covers the `plan_istio_status_updates` planning surface as exercised
//! against realistic mixes of Istio resources. Conflict-safe
//! GET → merge → PATCH behaviour (resourceVersion/UID CAS, foreign
//! condition preservation, bounded retry) lives in
//! `k8s_controller_istio_status_cas_tests.rs` against a mock API server.
//!
//! What this file exercises:
//! - Mixed cluster snapshots: every translated Istio kind in one snapshot
//!   generates a status update (all ten kinds are covered).
//! - Resource accepted vs. rejected: rejected resources still produce a
//!   `FerrumAccepted: False` update so operators see the failure — including
//!   the newly-covered kinds (VirtualService, ServiceEntry,
//!   RequestAuthentication, Sidecar, Telemetry, WorkloadEntry, ProxyConfig).
//! - Skip behaviour: kinds the status writer does not own (e.g. EnvoyFilter)
//!   do not produce updates.
//! - Stability: the same input always produces the same set of updates
//!   (no nondeterminism), and `lastTransitionTime` is preserved across
//!   no-op replans.
//!
//! Field-by-field assertions live in the inline unit tests; this file
//! sticks to integration-level invariants.

use ferrum_edge::config_sources::k8s::{
    K8sMetadata, K8sObject, K8sTranslationOptions, translate_k8s_objects,
};
use ferrum_edge::identity::spiffe::TrustDomain;
use ferrum_edge::k8s_controller::istio_status::{IstioStatusUpdate, plan_istio_status_updates};
use serde_json::{Value, json};
use std::collections::HashMap;

fn options() -> K8sTranslationOptions {
    K8sTranslationOptions::new(
        "default".to_string(),
        TrustDomain::new("cluster.local").expect("test trust domain"),
    )
}

fn object(api_version: &str, kind: &str, name: &str, spec: Value) -> K8sObject {
    K8sObject {
        api_version: api_version.to_string(),
        kind: kind.to_string(),
        metadata: K8sMetadata {
            name: name.to_string(),
            uid: format!("uid-{name}"),
            namespace: "default".to_string(),
            generation: Some(3),
            labels: HashMap::new(),
            annotations: HashMap::new(),
            creation_timestamp: None,
            deletion_timestamp: None,
        },
        spec,
        status: Value::Object(serde_json::Map::new()),
    }
}

fn update_for<'a>(
    updates: &'a [IstioStatusUpdate],
    kind: &str,
    name: &str,
) -> &'a IstioStatusUpdate {
    updates
        .iter()
        .find(|u| u.kind == kind && u.name == name)
        .unwrap_or_else(|| panic!("missing update for {kind}/{name}"))
}

fn find_condition<'a>(conditions: &'a [Value], condition_type: &str) -> &'a Value {
    conditions
        .iter()
        .find(|c| c["type"].as_str() == Some(condition_type))
        .unwrap_or_else(|| panic!("missing condition {condition_type}"))
}

/// A realistic mesh-config snapshot produces one update for every
/// translated Istio kind (all ten are covered). An unowned kind
/// (`EnvoyFilter`) is silently skipped — it shows up as no update in
/// the plan, so operators don't see a stale "Ferrum doesn't manage this"
/// condition for a resource the status writer doesn't own.
#[test]
fn mixed_istio_snapshot_emits_update_per_supported_kind() {
    let objects = vec![
        object(
            "security.istio.io/v1",
            "AuthorizationPolicy",
            "lock-down",
            json!({ "action": "ALLOW" }),
        ),
        object(
            "security.istio.io/v1",
            "PeerAuthentication",
            "default-strict",
            json!({ "mtls": { "mode": "STRICT" } }),
        ),
        object(
            "networking.istio.io/v1",
            "DestinationRule",
            "reviews",
            json!({ "host": "reviews.default.svc.cluster.local" }),
        ),
        object(
            "security.istio.io/v1",
            "RequestAuthentication",
            "jwt",
            json!({ "jwtRules": [{
                "issuer": "https://issuer.example.com",
                "jwksUri": "https://issuer.example.com/jwks"
            }] }),
        ),
        object(
            "networking.istio.io/v1",
            "VirtualService",
            "edge-vs",
            json!({ "hosts": ["api.example.com"] }),
        ),
        object(
            "networking.istio.io/v1",
            "ServiceEntry",
            "external",
            json!({ "hosts": ["api.example.com"], "resolution": "DNS" }),
        ),
        object(
            "networking.istio.io/v1",
            "WorkloadEntry",
            "vm-1",
            json!({ "address": "10.0.0.5", "serviceAccount": "payments" }),
        ),
        object(
            "networking.istio.io/v1",
            "Sidecar",
            "egress-scope",
            json!({ "egress": [{ "hosts": ["./*"] }] }),
        ),
        object(
            "telemetry.istio.io/v1",
            "Telemetry",
            "mesh-default",
            json!({ "accessLogging": [{ "disabled": false }] }),
        ),
        object(
            "networking.istio.io/v1beta1",
            "ProxyConfig",
            "default-pc",
            json!({ "concurrency": 2, "tracing": { "sampling": 5.0 } }),
        ),
        // Not a status-writer kind: must be skipped.
        object(
            "networking.istio.io/v1alpha3",
            "EnvoyFilter",
            "ef",
            json!({}),
        ),
    ];

    let updates = plan_istio_status_updates(&objects, options());
    assert_eq!(
        updates.len(),
        10,
        "expected one update per translated Istio kind, got {updates:?}"
    );
    for kind in [
        "AuthorizationPolicy",
        "PeerAuthentication",
        "DestinationRule",
        "RequestAuthentication",
        "VirtualService",
        "ServiceEntry",
        "WorkloadEntry",
        "Sidecar",
        "Telemetry",
        "ProxyConfig",
    ] {
        assert!(
            updates.iter().any(|u| u.kind == kind),
            "expected an update for {kind}, got {updates:?}"
        );
    }
    assert!(
        !updates.iter().any(|u| u.kind == "EnvoyFilter"),
        "EnvoyFilter must not produce a status update"
    );
}

/// Each newly-covered kind produces a `FerrumAccepted: True` condition on
/// valid input. This complements the inline unit tests by asserting the
/// integration-level invariant across all six new kinds in one place.
#[test]
fn newly_covered_kinds_report_accepted_on_valid_input() {
    let cases = vec![
        object(
            "networking.istio.io/v1",
            "VirtualService",
            "vs-ok",
            json!({
                "hosts": ["reviews.default.svc.cluster.local"],
                "http": [{ "route": [{ "destination": { "host": "reviews.default.svc.cluster.local" } }] }]
            }),
        ),
        object(
            "networking.istio.io/v1",
            "ServiceEntry",
            "se-ok",
            json!({ "hosts": ["api.example.com"], "resolution": "DNS" }),
        ),
        object(
            "security.istio.io/v1",
            "RequestAuthentication",
            "ra-ok",
            json!({ "jwtRules": [{
                "issuer": "https://issuer.example.com",
                "jwksUri": "https://issuer.example.com/jwks"
            }] }),
        ),
        object(
            "networking.istio.io/v1",
            "WorkloadEntry",
            "we-ok",
            json!({ "address": "10.0.0.9", "serviceAccount": "payments" }),
        ),
        object(
            "networking.istio.io/v1",
            "Sidecar",
            "sc-ok",
            json!({ "egress": [{ "hosts": ["./*"] }] }),
        ),
        object(
            "telemetry.istio.io/v1",
            "Telemetry",
            "tel-ok",
            json!({ "metrics": [{ "providers": [{ "name": "prometheus" }] }] }),
        ),
    ];

    for obj in cases {
        let kind = obj.kind.clone();
        let name = obj.metadata.name.clone();
        let updates = plan_istio_status_updates(&[obj], options());
        let update = update_for(&updates, &kind, &name);
        let condition = find_condition(
            update.status["conditions"].as_array().unwrap(),
            "FerrumAccepted",
        );
        assert_eq!(
            condition["status"].as_str(),
            Some("True"),
            "{kind}/{name} should be Accepted"
        );
        assert_eq!(condition["reason"].as_str(), Some("Accepted"));
    }
}

/// Each newly-covered kind produces a `FerrumAccepted: False`/`Invalid`
/// condition (with a translator error in the detail block) when the
/// resource is rejected — a hard rejection must never be silent to
/// operators.
#[test]
fn newly_covered_kinds_report_invalid_on_rejection() {
    let cases = vec![
        // VirtualService: route destination without a host.
        object(
            "networking.istio.io/v1",
            "VirtualService",
            "vs-bad",
            json!({
                "hosts": ["reviews.default.svc.cluster.local"],
                "http": [{ "route": [{ "destination": { "subset": "v1" } }] }]
            }),
        ),
        // ServiceEntry: missing hosts.
        object(
            "networking.istio.io/v1",
            "ServiceEntry",
            "se-bad",
            json!({ "resolution": "DNS" }),
        ),
        // RequestAuthentication: jwtRules entry without issuer.
        object(
            "security.istio.io/v1",
            "RequestAuthentication",
            "ra-bad",
            json!({ "jwtRules": [{ "audiences": ["a"] }] }),
        ),
        // WorkloadEntry: cross-namespace service host.
        object(
            "networking.istio.io/v1",
            "WorkloadEntry",
            "we-bad",
            json!({
                "address": "10.0.0.9",
                "serviceAccount": "payments",
                "service": "payments.other-ns.svc.cluster.local"
            }),
        ),
        // Sidecar: empty egress hosts array.
        object(
            "networking.istio.io/v1",
            "Sidecar",
            "sc-bad",
            json!({ "egress": [{ "hosts": [] }] }),
        ),
        // Telemetry: unsupported tracing match mode.
        object(
            "telemetry.istio.io/v1",
            "Telemetry",
            "tel-bad",
            json!({ "tracing": [{ "match": { "mode": "NONSENSE" } }] }),
        ),
    ];

    for obj in cases {
        let kind = obj.kind.clone();
        let name = obj.metadata.name.clone();
        let updates = plan_istio_status_updates(&[obj], options());
        let update = update_for(&updates, &kind, &name);
        let condition = find_condition(
            update.status["conditions"].as_array().unwrap(),
            "FerrumAccepted",
        );
        assert_eq!(
            condition["status"].as_str(),
            Some("False"),
            "{kind}/{name} should be rejected"
        );
        assert_eq!(condition["reason"].as_str(), Some("Invalid"));
        let detail = update
            .ferrum_detail
            .as_ref()
            .unwrap_or_else(|| panic!("{kind}/{name} should carry a detail block"));
        assert!(
            detail["translation"]["error"].is_string(),
            "{kind}/{name} detail should carry the translator error"
        );
    }
}

/// A rejected resource still produces an update; the planner doesn't
/// drop failures (otherwise operators would never see the failure
/// surfaced in `kubectl describe`).
#[test]
fn rejected_resource_still_emits_update_with_false_status() {
    // Invalid action triggers a translator error.
    let objects = vec![object(
        "security.istio.io/v1",
        "AuthorizationPolicy",
        "bad-action",
        json!({ "action": "INVALID" }),
    )];
    let updates = plan_istio_status_updates(&objects, options());
    assert_eq!(updates.len(), 1);
    let update = &updates[0];
    let condition = find_condition(
        update.status["conditions"].as_array().unwrap(),
        "FerrumAccepted",
    );
    assert_eq!(condition["status"].as_str(), Some("False"));
    assert_eq!(condition["reason"].as_str(), Some("Invalid"));
    let detail = update.ferrum_detail.as_ref().expect("detail block");
    assert!(detail["translation"]["error"].is_string());
}

#[test]
fn authorization_policy_singular_target_ref_is_reported_as_an_attachment() {
    let service = object(
        "v1",
        "Service",
        "reviews",
        json!({
            "selector": {"app": "reviews"},
            "ports": [{"port": 9080, "name": "http"}]
        }),
    );
    let policy = object(
        "security.istio.io/v1",
        "AuthorizationPolicy",
        "targeted",
        json!({
            "targetRef": {"group": "", "kind": "Service", "name": "reviews"},
            "action": "DENY",
            "rules": [{}]
        }),
    );

    let updates = plan_istio_status_updates(&[service, policy], options());
    let update = update_for(&updates, "AuthorizationPolicy", "targeted");
    let condition = find_condition(
        update.status["conditions"].as_array().unwrap(),
        "FerrumAccepted",
    );
    assert_eq!(condition["status"].as_str(), Some("True"));
    let detail = update.ferrum_detail.as_ref().expect("detail block");
    let target_refs = detail["translation"]["target_refs"]
        .as_array()
        .expect("target attachment projection");
    assert_eq!(target_refs.len(), 1);
    assert_eq!(target_refs[0]["name"].as_str(), Some("reviews"));
}

/// Deterministic output: calling the planner twice on the same input
/// yields the same set of updates with the same condition messages.
/// `lastTransitionTime` is wall-clock and may differ — checked
/// separately by the inline unit tests' "preserve unchanged time" path.
#[test]
fn planner_is_deterministic_across_repeated_calls() {
    let objects = vec![
        object(
            "security.istio.io/v1",
            "AuthorizationPolicy",
            "p1",
            json!({ "action": "ALLOW", "rules": [{"to": [{"operation": {"paths": ["/api"]}}]}] }),
        ),
        object(
            "networking.istio.io/v1",
            "DestinationRule",
            "dr1",
            json!({ "host": "svc.default.svc.cluster.local" }),
        ),
    ];
    let first = plan_istio_status_updates(&objects, options());
    let second = plan_istio_status_updates(&objects, options());

    assert_eq!(first.len(), second.len());
    for (left, right) in first.iter().zip(second.iter()) {
        assert_eq!(left.kind, right.kind);
        assert_eq!(left.name, right.name);
        // Reasons and detail blocks are deterministic; messages and
        // observedGeneration are derived from input.
        let left_c = find_condition(
            left.status["conditions"].as_array().unwrap(),
            "FerrumAccepted",
        );
        let right_c = find_condition(
            right.status["conditions"].as_array().unwrap(),
            "FerrumAccepted",
        );
        assert_eq!(left_c["status"], right_c["status"]);
        assert_eq!(left_c["reason"], right_c["reason"]);
        assert_eq!(left_c["message"], right_c["message"]);
        assert_eq!(left_c["observedGeneration"], right_c["observedGeneration"]);
        assert_eq!(left.ferrum_detail, right.ferrum_detail);
    }
}

/// Observed-generation tracking: when an object's `metadata.generation`
/// bumps (operator edits the spec), the new update carries the new
/// generation in every owned condition. Operators rely on
/// `observedGeneration` to know if a controller has caught up.
#[test]
fn observed_generation_matches_object_metadata() {
    let mut obj = object(
        "security.istio.io/v1",
        "AuthorizationPolicy",
        "tracked",
        json!({ "action": "ALLOW" }),
    );
    obj.metadata.generation = Some(42);
    let updates = plan_istio_status_updates(&[obj], options());
    let update = &updates[0];
    let c = find_condition(
        update.status["conditions"].as_array().unwrap(),
        "FerrumAccepted",
    );
    assert_eq!(c["observedGeneration"].as_i64(), Some(42));
}

/// When `metadata.generation` is missing (some legacy / client-managed
/// resources omit it), the planner still produces a usable update with
/// `observedGeneration=1`. Without this, the patch would fail server
/// validation (`observedGeneration` is a required field on Conditions
/// in many CRD schemas).
#[test]
fn missing_generation_falls_back_to_one() {
    let mut obj = object(
        "security.istio.io/v1",
        "PeerAuthentication",
        "no-gen",
        json!({}),
    );
    obj.metadata.generation = None;
    let updates = plan_istio_status_updates(&[obj], options());
    let c = find_condition(
        updates[0].status["conditions"].as_array().unwrap(),
        "FerrumAccepted",
    );
    assert_eq!(c["observedGeneration"].as_i64(), Some(1));
}

/// Mixed accept/reject: a snapshot with one good resource and one bad
/// resource produces an update for both, preserving translation order
/// — failures of one resource don't suppress status for siblings.
#[test]
fn mixed_accept_reject_snapshot_produces_updates_for_both() {
    let objects = vec![
        object(
            "security.istio.io/v1",
            "AuthorizationPolicy",
            "ok-policy",
            json!({ "action": "ALLOW", "rules": [{"to": [{"operation": {"paths": ["/ok"]}}]}] }),
        ),
        object(
            "security.istio.io/v1",
            "AuthorizationPolicy",
            "bad-policy",
            json!({ "action": "INVALID-ACTION" }),
        ),
    ];
    let updates = plan_istio_status_updates(&objects, options());
    assert_eq!(updates.len(), 2);
    let ok = update_for(&updates, "AuthorizationPolicy", "ok-policy");
    let bad = update_for(&updates, "AuthorizationPolicy", "bad-policy");
    let ok_c = find_condition(
        ok.status["conditions"].as_array().unwrap(),
        "FerrumAccepted",
    );
    let bad_c = find_condition(
        bad.status["conditions"].as_array().unwrap(),
        "FerrumAccepted",
    );
    assert_eq!(ok_c["status"].as_str(), Some("True"));
    assert_eq!(bad_c["status"].as_str(), Some("False"));
}

/// PeerAuthentication port-level overrides surface in the translation
/// detail block so operators can verify their mixed-mode config without
/// running `ferrum-edge admin` queries.
#[test]
fn peer_authentication_port_level_overrides_visible_in_detail() {
    let obj = object(
        "security.istio.io/v1",
        "PeerAuthentication",
        "mixed",
        json!({
            "selector": { "matchLabels": { "app": "api" } },
            "mtls": { "mode": "STRICT" },
            "portLevelMtls": {
                "8080": { "mode": "PERMISSIVE" }
            }
        }),
    );
    let updates = plan_istio_status_updates(&[obj], options());
    let detail = updates[0].ferrum_detail.as_ref().unwrap();
    let overrides = detail["translation"]["port_level_overrides"]
        .as_array()
        .unwrap();
    assert_eq!(overrides.len(), 1);
    assert!(overrides[0].as_str().unwrap().contains("PERMISSIVE"));
}

/// Once per-app-port enforcement is active, `portLevelMtls` remains accepted
/// and is no longer reported as deferred.
#[test]
fn peer_authentication_port_level_mtls_is_not_deferred() {
    let obj = object(
        "security.istio.io/v1",
        "PeerAuthentication",
        "mixed-mode",
        json!({
            "selector": { "matchLabels": { "app": "api" } },
            "mtls": { "mode": "STRICT" },
            "portLevelMtls": {
                "8080": { "mode": "PERMISSIVE" }
            }
        }),
    );
    let updates = plan_istio_status_updates(&[obj], options());
    let update = &updates[0];

    // Still accepted — this is honest-surface, not a rejection.
    let condition = find_condition(
        update.status["conditions"].as_array().unwrap(),
        "FerrumAccepted",
    );
    assert_eq!(condition["status"].as_str(), Some("True"));
    assert_eq!(condition["reason"].as_str(), Some("Accepted"));
    assert!(!condition["message"].as_str().unwrap().contains("deferred"));

    let detail = update.ferrum_detail.as_ref().unwrap();
    assert!(
        detail["translation"].get("deferred_fields").is_none(),
        "enforced portLevelMtls must not be reported as deferred"
    );
}

/// A PeerAuthentication with NO `portLevelMtls` must NOT gain a spurious
/// deferred-field entry — the honest-surface warning is only for the
/// unenforceable per-app-port case.
#[test]
fn peer_authentication_without_port_level_mtls_has_no_deferred_fields() {
    let obj = object(
        "security.istio.io/v1",
        "PeerAuthentication",
        "plain-strict",
        json!({ "mtls": { "mode": "STRICT" } }),
    );
    let updates = plan_istio_status_updates(&[obj], options());
    let detail = updates[0].ferrum_detail.as_ref().unwrap();
    assert!(
        detail["translation"].get("deferred_fields").is_none(),
        "PeerAuthentication has no deferred fields"
    );
}

/// Enforced `portLevelMtls` no longer emits the temporary non-enforcement warning.
#[test]
fn peer_authentication_port_level_mtls_emits_no_deferral_warning() {
    let obj = object(
        "security.istio.io/v1",
        "PeerAuthentication",
        "mixed-mode",
        json!({
            "selector": { "matchLabels": { "app": "api" } },
            "mtls": { "mode": "STRICT" },
            "portLevelMtls": {
                "8080": { "mode": "PERMISSIVE" },
                "9090": { "mode": "DISABLE" }
            }
        }),
    );
    let translation = translate_k8s_objects(&[obj], options()).expect("translation should succeed");
    assert!(
        translation
            .warnings
            .iter()
            .all(|w| !w.contains("portLevelMtls")),
        "unexpected portLevelMtls warning: {:?}",
        translation.warnings
    );
}

#[test]
fn peer_authentication_selectorless_port_level_mtls_is_reported_ignored() {
    let obj = object(
        "security.istio.io/v1",
        "PeerAuthentication",
        "namespace-strict",
        json!({
            "selector": { "matchLabels": {} },
            "mtls": { "mode": "STRICT" },
            "portLevelMtls": {
                "8080": { "mode": "DISABLE" }
            }
        }),
    );
    let updates = plan_istio_status_updates(&[obj], options());
    let update = &updates[0];
    let condition = find_condition(
        update.status["conditions"].as_array().unwrap(),
        "FerrumAccepted",
    );
    assert!(condition["message"].as_str().unwrap().contains("ignored"));

    let translation = &update.ferrum_detail.as_ref().unwrap()["translation"];
    assert_eq!(translation["scope"].as_str(), Some("Namespace"));
    assert!(
        translation["port_level_overrides"]
            .as_array()
            .unwrap()
            .is_empty()
    );
    assert_eq!(
        translation["port_level_overrides_ignored_without_nonempty_selector"].as_bool(),
        Some(true)
    );
}

#[test]
fn root_namespace_peer_authentication_resolves_to_mesh_wide_scope() {
    let mut obj = object(
        "security.istio.io/v1",
        "PeerAuthentication",
        "root-strict",
        json!({ "mtls": { "mode": "STRICT" } }),
    );
    obj.metadata.namespace = "istio-system".to_string();
    let updates = plan_istio_status_updates(&[obj], options());
    assert_eq!(updates.len(), 1);
    let update = &updates[0];
    let c = find_condition(
        update.status["conditions"].as_array().unwrap(),
        "FerrumAccepted",
    );
    assert_eq!(c["status"].as_str(), Some("True"));
    assert!(
        c["message"].as_str().unwrap().contains("scope: MeshWide"),
        "root-namespace PA should resolve to MeshWide scope"
    );
    let detail = update.ferrum_detail.as_ref().unwrap();
    assert_eq!(detail["translation"]["scope"].as_str(), Some("MeshWide"),);
}

/// Successfully applied subset HTTP connection-pool fields must not be reported
/// as deferred in either the detail block or condition message.
#[test]
fn destination_rule_applied_subset_http_fields_are_not_deferred() {
    let obj = object(
        "networking.istio.io/v1",
        "DestinationRule",
        "secured",
        json!({
            "host": "secured.default.svc.cluster.local",
            // Top-level: applied — must NOT be deferred.
            "trafficPolicy": {
                "connectionPool": { "http": { "http1MaxPendingRequests": 128 } }
            },
            "subsets": [{
                "name": "v1",
                "labels": { "version": "v1" },
                // Subset: applied — must NOT be surfaced as deferred.
                "trafficPolicy": {
                    "connectionPool": { "http": { "http1MaxPendingRequests": 64 } }
                }
            }]
        }),
    );
    let updates = plan_istio_status_updates(&[obj], options());
    let detail = updates[0].ferrum_detail.as_ref().unwrap();
    let deferred: Vec<&str> = detail["translation"]["deferred_fields"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(Value::as_str)
        .collect();
    assert!(
        deferred.is_empty(),
        "applied top-level and subset http1MaxPendingRequests must not be deferred: {deferred:?}"
    );
    // The top-level (applied) value must NOT appear as deferred.
    assert!(
        !deferred
            .iter()
            .any(|f| f.starts_with("trafficPolicy.connectionPool.http")),
        "top-level applied http1MaxPendingRequests must not be deferred; got: {deferred:?}"
    );
    let message = find_condition(
        updates[0].status["conditions"].as_array().unwrap(),
        "FerrumAccepted",
    )["message"]
        .as_str()
        .unwrap();
    assert!(
        !message.contains("deferred fields"),
        "message must not claim applied fields are deferred: {message}"
    );
}

/// Successfully applied subset HTTP connection-pool fields — including
/// `idleTimeout` / `http2MaxRequests` — must not be reported as deferred.
#[test]
fn destination_rule_subset_scoped_idle_timeout_and_http2_max_requests_are_applied() {
    let obj = object(
        "networking.istio.io/v1",
        "DestinationRule",
        "reviews",
        json!({
            "host": "reviews.default.svc.cluster.local",
            "trafficPolicy": {
                "connectionPool": { "http": {
                    "idleTimeout": "30s",
                    "http2MaxRequests": 100
                } }
            },
            "subsets": [{
                "name": "v1",
                "labels": { "version": "v1" },
                "trafficPolicy": {
                    "connectionPool": { "http": {
                        "idleTimeout": "45s",
                        "http2MaxRequests": 10,
                        "http1MaxPendingRequests": 64
                    } }
                }
            }]
        }),
    );
    let updates = plan_istio_status_updates(&[obj], options());
    let detail = updates[0].ferrum_detail.as_ref().unwrap();
    let deferred: Vec<&str> = detail["translation"]["deferred_fields"]
        .as_array()
        .expect("deferred_fields array")
        .iter()
        .filter_map(Value::as_str)
        .collect();

    assert!(
        deferred.is_empty(),
        "subset idleTimeout/http2MaxRequests are applied and must not be deferred: {deferred:?}"
    );
    let message = find_condition(
        updates[0].status["conditions"].as_array().unwrap(),
        "FerrumAccepted",
    )["message"]
        .as_str()
        .unwrap();
    assert!(
        !message.contains("deferred fields"),
        "message must not claim applied subset idleTimeout/http2MaxRequests are deferred: {message}"
    );
}

/// The same two fields at top-level / `portLevelSettings` scope only — no
/// subset uses them — must produce NO deferred entry at all.
#[test]
fn destination_rule_top_level_idle_timeout_and_http2_max_requests_are_not_deferred() {
    let obj = object(
        "networking.istio.io/v1",
        "DestinationRule",
        "ratings",
        json!({
            "host": "ratings.default.svc.cluster.local",
            "trafficPolicy": {
                "connectionPool": { "http": {
                    "idleTimeout": "30s",
                    "http2MaxRequests": 100
                } },
                "portLevelSettings": [{
                    "port": {"number": 8080},
                    "connectionPool": { "http": {
                        "idleTimeout": "10s",
                        "http2MaxRequests": 20
                    } }
                }]
            },
            "subsets": [{
                "name": "v1",
                "labels": { "version": "v1" },
                "trafficPolicy": {
                    "connectionPool": { "http": { "maxRetries": 1 } }
                }
            }]
        }),
    );
    let updates = plan_istio_status_updates(&[obj], options());
    let detail = updates[0].ferrum_detail.as_ref().unwrap();
    let deferred: Vec<&str> = detail["translation"]["deferred_fields"]
        .as_array()
        .expect("deferred_fields array")
        .iter()
        .filter_map(Value::as_str)
        .collect();
    assert!(
        deferred.is_empty(),
        "top-level/per-port idleTimeout+http2MaxRequests are applied at those scopes: {deferred:?}"
    );
}

#[test]
fn destination_rule_failover_priority_status_reflects_outlier_activation() {
    let without_outlier = object(
        "networking.istio.io/v1",
        "DestinationRule",
        "priority-inert",
        json!({
            "host": "reviews.default.svc.cluster.local",
            "trafficPolicy": {
                "loadBalancer": {
                    "localityLbSetting": {
                        "failoverPriority": ["topology.kubernetes.io/region"]
                    }
                }
            }
        }),
    );
    let with_outlier = object(
        "networking.istio.io/v1",
        "DestinationRule",
        "priority-active",
        json!({
            "host": "ratings.default.svc.cluster.local",
            "trafficPolicy": {
                "outlierDetection": {},
                "loadBalancer": {
                    "localityLbSetting": {
                        "failoverPriority": ["topology.kubernetes.io/region"]
                    }
                }
            }
        }),
    );
    let updates = plan_istio_status_updates(&[without_outlier, with_outlier], options());

    let inert = update_for(&updates, "DestinationRule", "priority-inert");
    let inert_fields = inert.ferrum_detail.as_ref().unwrap()["translation"]["deferred_fields"]
        .as_array()
        .expect("inactive policy advisory");
    assert!(inert_fields.iter().any(|field| {
        field
            .as_str()
            .is_some_and(|field| field.contains("accepted but inactive"))
    }));

    let active = update_for(&updates, "DestinationRule", "priority-active");
    assert_eq!(
        active.ferrum_detail.as_ref().unwrap()["translation"]["deferred_fields"],
        json!([]),
        "applicable outlierDetection must activate failoverPriority without an inactive advisory"
    );
}

/// A `subsets[].trafficPolicy.outlierDetection` resolves into that subset's
/// passive health check, which the load balancer treats as an activating
/// failover signal for the subset lane. The status advisory must not claim the
/// ranks are inert when a subset lane is in fact ranking.
#[test]
fn destination_rule_failover_priority_subset_outlier_suppresses_inactive_advisory() {
    let subset_outlier = object(
        "networking.istio.io/v1",
        "DestinationRule",
        "priority-subset-active",
        json!({
            "host": "reviews.default.svc.cluster.local",
            "trafficPolicy": {
                "loadBalancer": {
                    "localityLbSetting": {
                        "failoverPriority": ["topology.kubernetes.io/region"]
                    }
                }
            },
            "subsets": [{
                "name": "v1",
                "labels": {"version": "v1"},
                "trafficPolicy": {"outlierDetection": {}}
            }]
        }),
    );
    let updates = plan_istio_status_updates(&[subset_outlier], options());

    let active = update_for(&updates, "DestinationRule", "priority-subset-active");
    assert_eq!(
        active.ferrum_detail.as_ref().unwrap()["translation"]["deferred_fields"],
        json!([]),
        "a subset-scoped outlierDetection activates the subset lane, so no inactive advisory"
    );
}

// ── Sidecar outboundTrafficPolicy (issue #3262) ───────────────────────────

/// Read the `translation` detail block of a `Sidecar` status update.
fn sidecar_translation<'a>(updates: &'a [IstioStatusUpdate], name: &str) -> &'a Value {
    &update_for(updates, "Sidecar", name)
        .ferrum_detail
        .as_ref()
        .expect("ferrum detail")["translation"]
}

/// The `FerrumAccepted` condition of a `Sidecar` status update.
fn sidecar_condition<'a>(updates: &'a [IstioStatusUpdate], name: &str) -> &'a Value {
    find_condition(
        update_for(updates, "Sidecar", name).status["conditions"]
            .as_array()
            .expect("conditions"),
        "FerrumAccepted",
    )
}

/// A supported mode is reported verbatim, and — with the enforcement gate on —
/// as actually enforced. Nothing is deferred.
#[test]
fn sidecar_supported_outbound_traffic_policy_is_reported_as_enforced() {
    let enforced = options().with_mesh_sidecar_ingress_enforced(true);
    for (name, mode) in [("sc-allow", "ALLOW_ANY"), ("sc-registry", "REGISTRY_ONLY")] {
        let obj = object(
            "networking.istio.io/v1",
            "Sidecar",
            name,
            json!({
                "egress": [{ "hosts": ["./*"] }],
                "outboundTrafficPolicy": { "mode": mode },
            }),
        );
        let updates = plan_istio_status_updates(&[obj], enforced.clone());
        let translation = sidecar_translation(&updates, name);
        assert_eq!(translation["outbound_traffic_policy"], json!(mode));
        assert_eq!(
            translation["outbound_traffic_policy_enforced"],
            json!(true),
            "with the gate on, the translated mode is live"
        );
        assert_eq!(
            translation["deferred_fields"],
            json!([]),
            "a supported mode defers nothing"
        );
    }
}

#[test]
fn sidecar_omitted_mode_reports_the_istio_allow_any_default_without_deferral() {
    let obj = object(
        "networking.istio.io/v1",
        "Sidecar",
        "sc-default-mode",
        json!({ "outboundTrafficPolicy": {} }),
    );
    let updates =
        plan_istio_status_updates(&[obj], options().with_mesh_sidecar_ingress_enforced(true));
    let translation = sidecar_translation(&updates, "sc-default-mode");
    assert_eq!(translation["outbound_traffic_policy"], json!("ALLOW_ANY"));
    assert_eq!(translation["outbound_traffic_policy_enforced"], json!(true));
    assert_eq!(translation["deferred_fields"], json!([]));
}

/// An omitted block reports `Inherit` and is never claimed as enforced — the
/// mesh-wide policy is what is actually in force.
#[test]
fn sidecar_without_outbound_traffic_policy_reports_inherit() {
    let obj = object(
        "networking.istio.io/v1",
        "Sidecar",
        "sc-inherit",
        json!({ "egress": [{ "hosts": ["./*"] }] }),
    );
    let updates =
        plan_istio_status_updates(&[obj], options().with_mesh_sidecar_ingress_enforced(true));
    let translation = sidecar_translation(&updates, "sc-inherit");
    assert_eq!(translation["outbound_traffic_policy"], json!("Inherit"));
    assert_eq!(
        translation["outbound_traffic_policy_enforced"],
        json!(false)
    );
    assert_eq!(translation["deferred_fields"], json!([]));
}

/// With the rollout gate off, the mode is still translated and reported, but
/// must NOT be claimed as enforced — the same gate-honest framing
/// `ingress_modeled` uses.
#[test]
fn sidecar_outbound_traffic_policy_not_reported_as_enforced_when_gate_is_off() {
    let obj = object(
        "networking.istio.io/v1",
        "Sidecar",
        "sc-gated",
        json!({ "outboundTrafficPolicy": { "mode": "REGISTRY_ONLY" } }),
    );
    // Default options() leaves the effective sidecar gate off.
    let updates = plan_istio_status_updates(&[obj], options());
    let translation = sidecar_translation(&updates, "sc-gated");
    assert_eq!(
        translation["outbound_traffic_policy"],
        json!("REGISTRY_ONLY")
    );
    assert_eq!(
        translation["outbound_traffic_policy_enforced"],
        json!(false),
        "the status must never claim a policy is live while the gate is off"
    );
    let message = sidecar_condition(&updates, "sc-gated")["message"]
        .as_str()
        .expect("condition message");
    assert!(
        message.contains("not applied"),
        "the condition message must say the policy is inert, got {message}"
    );
}

/// Every unrepresentable variant is ACCEPTED, reported as the enforced
/// fail-closed `REGISTRY_ONLY`, and names the exact field in `deferred_fields`.
#[test]
fn sidecar_unrepresentable_outbound_traffic_policy_is_accepted_and_deferred_fail_closed() {
    let enforced = options().with_mesh_sidecar_ingress_enforced(true);
    let cases: Vec<(&str, Value, &str)> = vec![
        (
            "sc-bad-mode",
            json!({ "mode": "ALOW_ANY" }),
            "not ALLOW_ANY or REGISTRY_ONLY",
        ),
        (
            "sc-nonstring-mode",
            json!({ "mode": 1 }),
            "not ALLOW_ANY or REGISTRY_ONLY",
        ),
        ("sc-not-object", json!("REGISTRY_ONLY"), "not an object"),
        (
            "sc-egress-proxy",
            json!({
                "mode": "ALLOW_ANY",
                "egressProxy": { "host": "istio-egressgateway.istio-system.svc.cluster.local" },
            }),
            "egressProxy is not supported",
        ),
    ];
    for (name, policy, expected_fragment) in cases {
        let obj = object(
            "networking.istio.io/v1",
            "Sidecar",
            name,
            json!({
                "egress": [{ "hosts": ["./*"] }],
                "outboundTrafficPolicy": policy,
            }),
        );
        let updates = plan_istio_status_updates(&[obj], enforced.clone());
        assert_eq!(
            sidecar_condition(&updates, name)["status"].as_str(),
            Some("True"),
            "{name} must stay ACCEPTED — rejecting it would drop its egress \
             narrowing and widen the slice"
        );
        let translation = sidecar_translation(&updates, name);
        assert_eq!(
            translation["outbound_traffic_policy"],
            json!("REGISTRY_ONLY"),
            "{name} must report the fail-closed mode it actually enforces"
        );
        assert_eq!(
            translation["outbound_traffic_policy_enforced"],
            json!(true),
            "{name} is enforced under the gate"
        );
        let deferred = translation["deferred_fields"]
            .as_array()
            .expect("deferred_fields array");
        assert!(
            deferred
                .iter()
                .filter_map(Value::as_str)
                .any(|entry| entry.contains(expected_fragment)),
            "{name} must defer a reason naming {expected_fragment:?}, got {deferred:?}"
        );
        assert!(
            deferred
                .iter()
                .filter_map(Value::as_str)
                .any(|entry| entry.contains("REGISTRY_ONLY")),
            "{name} must name the enforced fail-closed outcome, got {deferred:?}"
        );
    }
}

/// The raw, operator-supplied `mode` value must never be echoed back into the
/// status (it reaches the writer straight off an untrusted CRD).
#[test]
fn sidecar_outbound_traffic_policy_status_does_not_echo_the_raw_mode_value() {
    let hostile = "<script>alert(1)</script>";
    let obj = object(
        "networking.istio.io/v1",
        "Sidecar",
        "sc-hostile",
        json!({ "outboundTrafficPolicy": { "mode": hostile } }),
    );
    let updates =
        plan_istio_status_updates(&[obj], options().with_mesh_sidecar_ingress_enforced(true));
    let update = update_for(&updates, "Sidecar", "sc-hostile");
    let rendered = serde_json::to_string(&update.ferrum_detail).expect("detail encodes");
    let condition = serde_json::to_string(&update.status).expect("status encodes");
    assert!(
        !rendered.contains(hostile) && !condition.contains(hostile),
        "the unsupported mode value must not be echoed into status"
    );
    assert_eq!(
        sidecar_translation(&updates, "sc-hostile")["outbound_traffic_policy"],
        json!("REGISTRY_ONLY")
    );
}

/// An explicit `egressProxy: null` is proto-JSON for "unset": the declared mode
/// is honored and no `egressProxy` reason is deferred. A NON-null value still
/// fails closed.
#[test]
fn sidecar_null_egress_proxy_is_reported_as_absent() {
    let enforced = options().with_mesh_sidecar_ingress_enforced(true);
    let obj = object(
        "networking.istio.io/v1",
        "Sidecar",
        "sc-null-proxy",
        json!({
            "outboundTrafficPolicy": { "mode": "ALLOW_ANY", "egressProxy": null },
        }),
    );
    let updates = plan_istio_status_updates(&[obj], enforced.clone());
    let translation = sidecar_translation(&updates, "sc-null-proxy");
    assert_eq!(translation["outbound_traffic_policy"], json!("ALLOW_ANY"));
    assert_eq!(
        translation["deferred_fields"],
        json!([]),
        "a null egressProxy is unset, so nothing is deferred"
    );

    let obj = object(
        "networking.istio.io/v1",
        "Sidecar",
        "sc-real-proxy",
        json!({
            "outboundTrafficPolicy": {
                "mode": "ALLOW_ANY",
                "egressProxy": { "host": "istio-egressgateway.istio-system.svc.cluster.local" },
            },
        }),
    );
    let updates = plan_istio_status_updates(&[obj], enforced);
    let translation = sidecar_translation(&updates, "sc-real-proxy");
    assert_eq!(
        translation["outbound_traffic_policy"],
        json!("REGISTRY_ONLY")
    );
    let deferred = translation["deferred_fields"]
        .as_array()
        .expect("deferred_fields array");
    assert!(
        deferred
            .iter()
            .filter_map(Value::as_str)
            .any(|entry| entry.contains("egressProxy is not supported")),
        "a real egressProxy must still defer its own reason, got {deferred:?}"
    );
}

/// `outbound_traffic_policy_enforced` is deliberately RESOURCE-LOCAL: it means
/// "this Sidecar carries a translatable policy AND the rollout gate is on", not
/// "this Sidecar was selected for some workload". A `workloadSelector` matching
/// nothing still reports `true`, and the condition message must not overclaim
/// live per-workload enforcement.
#[test]
fn sidecar_outbound_policy_enforced_flag_is_resource_local_not_workload_selection() {
    let obj = object(
        "networking.istio.io/v1",
        "Sidecar",
        "sc-selects-nothing",
        json!({
            "workloadSelector": { "labels": { "app": "no-such-workload" } },
            "outboundTrafficPolicy": { "mode": "REGISTRY_ONLY" },
        }),
    );
    let updates =
        plan_istio_status_updates(&[obj], options().with_mesh_sidecar_ingress_enforced(true));
    let translation = sidecar_translation(&updates, "sc-selects-nothing");
    assert_eq!(
        translation["outbound_traffic_policy_enforced"],
        json!(true),
        "the flag reports the gate + a translatable policy, not per-workload selection"
    );
    let message = sidecar_condition(&updates, "sc-selects-nothing")["message"]
        .as_str()
        .expect("condition message");
    assert!(
        message.contains("for the workloads this Sidecar is selected for"),
        "the message must scope enforcement to the selected workloads rather than \
         claiming it is live everywhere, got {message}"
    );
}

/// A REJECTED Sidecar is no longer dropped (GHSA-2r85-85hh-23mw): it is
/// published as a fail-closed marker, so its detail block reports what that
/// marker enforces. An untranslatable `ingress` becomes `ingress: []`, while an
/// omitted `egress` and a translatable `outboundTrafficPolicy` are kept.
#[test]
fn rejected_sidecar_reports_its_fail_closed_marker() {
    let obj = object(
        "networking.istio.io/v1",
        "Sidecar",
        "sc-rejected",
        json!({
            // `ingress` must be an array — this rejects the whole resource.
            "ingress": "not-an-array",
            "outboundTrafficPolicy": { "mode": "REGISTRY_ONLY" },
        }),
    );
    let updates =
        plan_istio_status_updates(&[obj], options().with_mesh_sidecar_ingress_enforced(true));
    let condition = sidecar_condition(&updates, "sc-rejected");
    assert_eq!(
        condition["status"].as_str(),
        Some("False"),
        "the fixture must actually be rejected, or the assertion below is vacuous"
    );
    assert!(
        condition["message"]
            .as_str()
            .unwrap()
            .contains("fail closed"),
        "the status must state the fail-closed consequence: {condition}"
    );
    let translation = sidecar_translation(&updates, "sc-rejected");
    assert_eq!(translation["enforcement"], json!("fail_closed"));
    assert_eq!(
        translation["outbound_traffic_policy"],
        json!("REGISTRY_ONLY")
    );
    assert_eq!(
        translation["outbound_traffic_policy_enforced"],
        json!(true),
        "the marker is enforced under the same gate as an accepted Sidecar"
    );
    assert_eq!(translation["ingress_blocked"], json!(true));
    assert_eq!(
        translation["egress_blocked"],
        json!(false),
        "an omitted egress block still inherits the namespace default"
    );
}

/// An untranslatable `egress` block blocks all egress with REGISTRY_ONLY,
/// whatever `outboundTrafficPolicy` asked for; with the rollout gate off the
/// marker is reported but not enforced.
#[test]
fn rejected_sidecar_egress_reports_block_all_registry_only() {
    let obj = || {
        object(
            "networking.istio.io/v1",
            "Sidecar",
            "sc-bad-egress",
            json!({
                "egress": [{ "hosts": "not-an-array" }],
                "outboundTrafficPolicy": { "mode": "ALLOW_ANY" },
            }),
        )
    };
    let updates =
        plan_istio_status_updates(&[obj()], options().with_mesh_sidecar_ingress_enforced(true));
    assert_eq!(
        sidecar_condition(&updates, "sc-bad-egress")["status"].as_str(),
        Some("False")
    );
    let translation = sidecar_translation(&updates, "sc-bad-egress");
    assert_eq!(
        translation["outbound_traffic_policy"],
        json!("REGISTRY_ONLY")
    );
    assert_eq!(translation["outbound_traffic_policy_enforced"], json!(true));
    assert_eq!(translation["egress_blocked"], json!(true));
    assert_eq!(translation["ingress_blocked"], json!(false));

    let gated_off = plan_istio_status_updates(&[obj()], options());
    assert_eq!(
        sidecar_translation(&gated_off, "sc-bad-egress")["outbound_traffic_policy_enforced"],
        json!(false),
        "without FERRUM_MESH_SIDECAR_ENFORCED the marker is not applied"
    );
}

// ── Deferred-field visibility (issues #4277, #4292, #4304, #4305) ─────────

fn deferred_fields_for(obj: K8sObject) -> Vec<String> {
    let kind = obj.kind.clone();
    let name = obj.metadata.name.clone();
    let updates = plan_istio_status_updates(&[obj], options());
    let update = update_for(&updates, &kind, &name);
    let condition = find_condition(
        update.status["conditions"].as_array().unwrap(),
        "FerrumAccepted",
    );
    assert_eq!(
        condition["status"].as_str(),
        Some("True"),
        "{kind}/{name} must stay accepted while reporting deferred fields"
    );
    update
        .ferrum_detail
        .as_ref()
        .and_then(|detail| detail["translation"]["deferred_fields"].as_array())
        .map(|entries| {
            entries
                .iter()
                .map(|entry| entry.as_str().unwrap_or_default().to_string())
                .collect()
        })
        .unwrap_or_default()
}

/// `outputPayloadToHeader` / `fromCookies` are recognized but unenforced, so
/// they must be visible in `kubectl describe` — by FIELD NAME only. Echoing a
/// `fromCookies` VALUE would publish the cookie a token rides in.
#[test]
fn request_authentication_reports_output_payload_and_cookie_fields_as_deferred() {
    let deferred = deferred_fields_for(object(
        "security.istio.io/v1",
        "RequestAuthentication",
        "ra-deferred",
        json!({
            "jwtRules": [{
                "issuer": "https://issuer.example.com",
                "jwksUri": "https://issuer.example.com/jwks",
                "outputPayloadToHeader": "x-jwt-payload",
                "fromCookies": ["session-token"],
            }]
        }),
    ));

    assert!(
        deferred
            .iter()
            .any(|entry| entry.contains("outputPayloadToHeader")),
        "{deferred:?}"
    );
    assert!(
        deferred.iter().any(|entry| entry.contains("fromCookies")),
        "{deferred:?}"
    );
    assert!(
        !deferred.iter().any(|entry| entry.contains("session-token")),
        "a deferred-field label must not republish the cookie name: {deferred:?}"
    );
}

/// An enforced `outputClaimToHeaders` is NOT deferred — the header is stripped
/// and re-asserted by the injected `jwks_auth` plugin.
#[test]
fn request_authentication_output_claim_to_headers_is_not_deferred() {
    let deferred = deferred_fields_for(object(
        "security.istio.io/v1",
        "RequestAuthentication",
        "ra-claims",
        json!({
            "jwtRules": [{
                "issuer": "https://issuer.example.com",
                "jwksUri": "https://issuer.example.com/jwks",
                "outputClaimToHeaders": [{"header": "x-jwt-claim-sub", "claim": "sub"}],
            }]
        }),
    ));
    assert!(deferred.is_empty(), "{deferred:?}");
}

/// The `outlierDetection` knobs Ferrum parses past must be visible, with no
/// operator-configured value echoed into the status object.
#[test]
fn destination_rule_reports_unenforced_outlier_fields_as_deferred() {
    let deferred = deferred_fields_for(object(
        "networking.istio.io/v1",
        "DestinationRule",
        "dr-outlier",
        json!({
            "host": "reviews.default.svc.cluster.local",
            "trafficPolicy": {
                "outlierDetection": {
                    "consecutive5xxErrors": 5,
                    "consecutiveGatewayErrors": 3,
                    "consecutiveLocalOriginFailures": 2,
                    "minHealthPercent": 40,
                    "splitExternalLocalOriginErrors": true
                }
            }
        }),
    ));

    for field in [
        "consecutiveGatewayErrors",
        "consecutiveLocalOriginFailures",
        "minHealthPercent",
        "splitExternalLocalOriginErrors",
    ] {
        assert!(
            deferred.iter().any(|entry| entry.contains(field)),
            "{field} must be reported as deferred: {deferred:?}"
        );
    }
    assert!(
        !deferred.iter().any(|entry| entry.contains("40")),
        "labels must not echo configured values: {deferred:?}"
    );
    assert!(
        deferred.iter().any(|entry| entry == SPLIT_TOP_LEVEL_LABEL),
        "top-level split=true must carry the top-level label: {deferred:?}"
    );
}

const SPLIT_TOP_LEVEL_LABEL: &str = "trafficPolicy.outlierDetection.splitExternalLocalOriginErrors \
     (not applied: local-origin failures share the consecutive5xxErrors bucket)";
const SPLIT_PORT_LEVEL_LABEL: &str = "trafficPolicy.portLevelSettings[].outlierDetection.\
     splitExternalLocalOriginErrors (not applied: local-origin failures share the \
     consecutive5xxErrors bucket)";
const SPLIT_SUBSET_LABEL: &str = "subsets[].trafficPolicy.outlierDetection.\
     splitExternalLocalOriginErrors (not applied: local-origin failures share the \
     consecutive5xxErrors bucket)";

fn split_labels(deferred: &[String]) -> Vec<&str> {
    deferred
        .iter()
        .map(String::as_str)
        .filter(|entry| entry.contains("splitExternalLocalOriginErrors"))
        .collect()
}

/// `splitExternalLocalOriginErrors: false` is Istio's default and the only
/// mode Ferrum implements, so it must not be reported as a deferred gap; a
/// `true` value is reported under the scope of the tier that carries it.
#[test]
fn destination_rule_split_local_origin_is_reported_per_tier() {
    let deferred = deferred_fields_for(object(
        "networking.istio.io/v1",
        "DestinationRule",
        "dr-outlier-split-false",
        json!({
            "host": "reviews.default.svc.cluster.local",
            "trafficPolicy": {
                "outlierDetection": {
                    "consecutive5xxErrors": 5,
                    "splitExternalLocalOriginErrors": false
                }
            }
        }),
    ));
    assert!(split_labels(&deferred).is_empty(), "{deferred:?}");

    // Top-level false, subset true: only the subset scope is named.
    let deferred = deferred_fields_for(object(
        "networking.istio.io/v1",
        "DestinationRule",
        "dr-outlier-split-subset",
        json!({
            "host": "reviews.default.svc.cluster.local",
            "trafficPolicy": {
                "outlierDetection": {"splitExternalLocalOriginErrors": false}
            },
            "subsets": [{
                "name": "v1",
                "labels": {"version": "v1"},
                "trafficPolicy": {
                    "outlierDetection": {"splitExternalLocalOriginErrors": true}
                }
            }]
        }),
    ));
    assert_eq!(split_labels(&deferred), vec![SPLIT_SUBSET_LABEL]);

    let deferred = deferred_fields_for(object(
        "networking.istio.io/v1",
        "DestinationRule",
        "dr-outlier-split-port",
        json!({
            "host": "reviews.default.svc.cluster.local",
            "trafficPolicy": {
                "portLevelSettings": [{
                    "port": {"number": 8080},
                    "outlierDetection": {"splitExternalLocalOriginErrors": true}
                }]
            }
        }),
    ));
    assert_eq!(split_labels(&deferred), vec![SPLIT_PORT_LEVEL_LABEL]);

    // A subset's own portLevelSettings are never parsed: the generic
    // unsupported-tier entry covers them and no split label is invented.
    let deferred = deferred_fields_for(object(
        "networking.istio.io/v1",
        "DestinationRule",
        "dr-outlier-split-subset-port",
        json!({
            "host": "reviews.default.svc.cluster.local",
            "subsets": [{
                "name": "v1",
                "labels": {"version": "v1"},
                "trafficPolicy": {
                    "portLevelSettings": [{
                        "port": {"number": 8080},
                        "outlierDetection": {"splitExternalLocalOriginErrors": true}
                    }]
                }
            }]
        }),
    ));
    assert!(split_labels(&deferred).is_empty(), "{deferred:?}");
    assert!(
        deferred
            .iter()
            .any(|entry| entry.starts_with("subsets[].trafficPolicy.portLevelSettings")),
        "subset port-level settings keep the unsupported-tier entry: {deferred:?}"
    );
}

/// Per-destination header transforms on a weighted split cannot be bound to one
/// share of the split, so the gap must be operator-visible; the route-level
/// `http[].headers` block is applied and therefore never deferred.
#[test]
fn virtual_service_reports_weighted_destination_headers_as_deferred() {
    let deferred = deferred_fields_for(object(
        "networking.istio.io/v1",
        "VirtualService",
        "vs-dest-headers",
        json!({
            "hosts": ["api.example.com"],
            "http": [{
                "match": [{"uri": {"prefix": "/api"}}],
                "headers": {"request": {"remove": ["x-internal-auth"]}},
                "route": [
                    {
                        "destination": {"host": "a.default.svc.cluster.local", "port": {"number": 8080}},
                        "weight": 50,
                        "headers": {"request": {"set": {"x-share": "a"}}}
                    },
                    {
                        "destination": {"host": "b.default.svc.cluster.local", "port": {"number": 8080}},
                        "weight": 50
                    }
                ]
            }]
        }),
    ));

    assert!(
        deferred
            .iter()
            .any(|entry| entry.contains("http[].route[].headers")),
        "{deferred:?}"
    );
    assert!(
        !deferred
            .iter()
            .any(|entry| entry.contains("http[].headers.request")),
        "the applied route-level block must not be reported as deferred: {deferred:?}"
    );
}

/// A singular `targetRef`-carrying `RequestAuthentication` / `Telemetry` is rejected
/// rather than widened, and the status reports the attachment COUNT without
/// republishing the referenced resource identities.
#[test]
fn singular_target_ref_on_request_authentication_and_telemetry_reports_invalid() {
    for obj in [
        object(
            "security.istio.io/v1",
            "RequestAuthentication",
            "ra-targeted",
            json!({
                "targetRef": {"kind": "Service", "name": "reviews"},
                "jwtRules": [{
                    "issuer": "https://issuer.example.com",
                    "jwksUri": "https://issuer.example.com/jwks"
                }]
            }),
        ),
        object(
            "telemetry.istio.io/v1",
            "Telemetry",
            "tel-targeted",
            json!({
                "targetRef": {"kind": "Service", "name": "reviews"},
                "accessLogging": [{"disabled": true}]
            }),
        ),
    ] {
        let kind = obj.kind.clone();
        let name = obj.metadata.name.clone();
        let updates = plan_istio_status_updates(&[obj], options());
        let update = update_for(&updates, &kind, &name);
        let condition = find_condition(
            update.status["conditions"].as_array().unwrap(),
            "FerrumAccepted",
        );
        assert_eq!(
            condition["status"].as_str(),
            Some("False"),
            "{kind}/{name} must not be accepted with an unenforceable targetRef"
        );
        assert_eq!(condition["reason"].as_str(), Some("Invalid"));
        let detail = update
            .ferrum_detail
            .as_ref()
            .unwrap_or_else(|| panic!("{kind}/{name} should carry a detail block"));
        assert_eq!(
            detail["translation"]["target_refs_declared"].as_u64(),
            Some(1),
            "{kind}/{name} should report the attachment count"
        );
        // The structured projection carries a COUNT, never the referenced
        // group/kind/name/namespace. (The translator diagnostic in
        // `translation.error` is the operator's actionable message and is
        // reported as-is, exactly as it is for AuthorizationPolicy.)
        assert!(
            detail["translation"]["error"].is_string(),
            "{kind}/{name} should carry the translator error"
        );
    }
}

/// DNS wildcard HTTP-family entries are live because request dispatch
/// concretizes their target, so status must not report the host as deferred.
#[test]
fn service_entry_dns_http_wildcard_host_is_not_deferred() {
    let obj = object(
        "networking.istio.io/v1",
        "ServiceEntry",
        "wildcard-dns",
        json!({
            "hosts": ["*.api.example.com"],
            "location": "MESH_EXTERNAL",
            "resolution": "DNS",
            "ports": [{"number": 443, "name": "https", "protocol": "TLS"}]
        }),
    );
    let updates = plan_istio_status_updates(&[obj], options());
    let condition = find_condition(
        updates[0].status["conditions"].as_array().unwrap(),
        "FerrumAccepted",
    );
    assert_eq!(
        condition["status"].as_str(),
        Some("True"),
        "the resource is accepted and materialized"
    );
    let detail = updates[0].ferrum_detail.as_ref().unwrap();
    let deferred: Vec<&str> = detail["translation"]["deferred_fields"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(Value::as_str)
        .collect();
    assert!(
        deferred.iter().all(|f| !f.starts_with("spec.hosts[]:")),
        "a routable HTTP wildcard must not be reported as deferred: {deferred:?}"
    );
    assert!(
        !condition["message"]
            .as_str()
            .unwrap()
            .contains("deferred fields")
    );
}

/// Issue #4535, stream family: the stream materializer still skips a wildcard
/// `spec.hosts[]` element without declared endpoints (a raw stream has no
/// request authority to concretize), so the status writer must surface it as a
/// deferred field rather than reporting a fully accepted resource that serves
/// nothing on that port. `FerrumAccepted` stays `True` — the resource IS
/// translated, just inert for that host.
#[test]
fn service_entry_stream_wildcard_host_is_reported_as_deferred() {
    let obj = object(
        "networking.istio.io/v1",
        "ServiceEntry",
        "wildcard-dns-tcp",
        json!({
            "hosts": ["*.db.example.com"],
            "location": "MESH_EXTERNAL",
            "resolution": "DNS",
            "ports": [{"number": 5432, "name": "postgres", "protocol": "TCP"}]
        }),
    );
    let updates = plan_istio_status_updates(&[obj], options());
    let condition = find_condition(
        updates[0].status["conditions"].as_array().unwrap(),
        "FerrumAccepted",
    );
    assert_eq!(
        condition["status"].as_str(),
        Some("True"),
        "the resource is still accepted/translated, just inert for that host"
    );
    let detail = updates[0].ferrum_detail.as_ref().unwrap();
    let deferred: Vec<&str> = detail["translation"]["deferred_fields"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(Value::as_str)
        .collect();
    assert!(
        deferred.iter().any(|f| f.starts_with("spec.hosts[]:")),
        "an unresolvable stream wildcard host must be reported as deferred: {deferred:?}"
    );
    assert!(
        condition["message"]
            .as_str()
            .unwrap()
            .contains("deferred fields"),
        "the condition message must name the deferral: {condition:?}"
    );
}

/// The converse: a wildcard host under `resolution: STATIC` with declared
/// `endpoints[]` IS materialized (the endpoints are the dial set), so it must
/// NOT be reported as deferred.
#[test]
fn service_entry_static_wildcard_host_with_endpoints_is_not_deferred() {
    let obj = object(
        "networking.istio.io/v1",
        "ServiceEntry",
        "wildcard-static",
        json!({
            "hosts": ["*.api.example.com"],
            "location": "MESH_EXTERNAL",
            "resolution": "STATIC",
            "endpoints": [{"address": "203.0.113.10"}],
            "ports": [{"number": 443, "name": "https", "protocol": "TLS"}]
        }),
    );
    let updates = plan_istio_status_updates(&[obj], options());
    let detail = updates[0].ferrum_detail.as_ref().unwrap();
    let deferred: Vec<&str> = detail["translation"]["deferred_fields"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(Value::as_str)
        .collect();
    assert!(
        !deferred.iter().any(|f| f.starts_with("spec.hosts[]:")),
        "a STATIC wildcard entry with endpoints materializes and must not be deferred: {deferred:?}"
    );
}

/// Issue #7243: `spec.workloadSelector` is carried but not consumed (no
/// endpoint selection from the selected workloads), so status must report it
/// as deferred instead of presenting the entry as fully effective.
#[test]
fn service_entry_workload_selector_is_reported_deferred() {
    let deferred_for = |spec: Value| -> Vec<String> {
        let obj = object("networking.istio.io/v1", "ServiceEntry", "selected", spec);
        let updates = plan_istio_status_updates(&[obj], options());
        let condition = find_condition(
            updates[0].status["conditions"].as_array().unwrap(),
            "FerrumAccepted",
        );
        assert_eq!(condition["status"].as_str(), Some("True"));
        updates[0].ferrum_detail.as_ref().unwrap()["translation"]["deferred_fields"]
            .as_array()
            .unwrap()
            .iter()
            .filter_map(Value::as_str)
            .map(str::to_string)
            .collect()
    };
    let base = json!({
        "hosts": ["api.example.com"],
        "resolution": "DNS",
        "location": "MESH_EXTERNAL",
        "ports": [{"number": 443, "name": "https", "protocol": "TLS"}]
    });
    let mut selected = base.clone();
    selected["workloadSelector"] = json!({"labels": {"app": "vm"}});

    assert!(
        deferred_for(selected)
            .iter()
            .any(|field| field.starts_with("spec.workloadSelector")),
        "a ServiceEntry workloadSelector must be reported deferred"
    );
    assert!(
        !deferred_for(base)
            .iter()
            .any(|field| field.starts_with("spec.workloadSelector")),
        "an entry without workloadSelector must not report it"
    );
}

/// Issue #7390: a mesh-bound VirtualService's `http[]` routes are applied only
/// by NodeWaypoint data planes, so its status must say so instead of reporting
/// the route count alone. A VirtualService bound only to an ingress gateway,
/// or one with no `http[]` routes, carries no such note.
#[test]
fn mesh_bound_virtual_service_status_reports_where_http_routes_apply() {
    use ferrum_edge::k8s_controller::istio_status::{
        VIRTUAL_SERVICE_MESH_HTTP_ROUTES_NOTE, VIRTUAL_SERVICE_MESH_HTTP_ROUTES_SCOPE,
    };
    let http = json!([{
        "route": [{"destination": {
            "host": "reviews.default.svc.cluster.local",
            "port": {"number": 8080}
        }}]
    }]);
    let report = |name: &str, spec: Value| -> (String, Value) {
        let obj = object("networking.istio.io/v1", "VirtualService", name, spec);
        let updates = plan_istio_status_updates(&[obj], options());
        let update = update_for(&updates, "VirtualService", name);
        let condition = find_condition(
            update.status["conditions"].as_array().unwrap(),
            "FerrumAccepted",
        );
        assert_eq!(condition["status"].as_str(), Some("True"), "{name}");
        (
            condition["message"].as_str().unwrap().to_string(),
            update.ferrum_detail.as_ref().unwrap()["translation"]["mesh_http_routes"].clone(),
        )
    };

    for (name, gateways) in [
        ("omitted-gateways", None),
        ("explicit-mesh", Some(json!(["mesh", "ingress-gw"]))),
    ] {
        let mut spec = json!({"hosts": ["reviews.default.svc.cluster.local"], "http": http});
        if let Some(gateways) = gateways {
            spec["gateways"] = gateways;
        }
        let (message, scope) = report(name, spec);
        assert_eq!(
            scope,
            json!(VIRTUAL_SERVICE_MESH_HTTP_ROUTES_SCOPE),
            "{name}: the status records that only NodeWaypoint applies the routes"
        );
        assert!(
            message.contains(VIRTUAL_SERVICE_MESH_HTTP_ROUTES_NOTE),
            "{name}: the condition message names the topologies that ignore them: {message}"
        );
    }

    let (message, scope) = report(
        "ingress-only",
        json!({
            "hosts": ["reviews.default.svc.cluster.local"],
            "gateways": ["ingress-gw"],
            "http": http
        }),
    );
    assert_eq!(
        scope,
        Value::Null,
        "an ingress-only VirtualService binds no mesh"
    );
    assert!(!message.contains(VIRTUAL_SERVICE_MESH_HTTP_ROUTES_NOTE));

    let (message, scope) = report(
        "tcp-only",
        json!({
            "hosts": ["reviews.default.svc.cluster.local"],
            "tcp": [{
                "match": [{"port": 9000}],
                "route": [{"destination": {
                    "host": "reviews.default.svc.cluster.local",
                    "port": {"number": 9000}
                }}]
            }]
        }),
    );
    assert_eq!(scope, Value::Null, "no http[] routes, nothing to qualify");
    assert!(!message.contains(VIRTUAL_SERVICE_MESH_HTTP_ROUTES_NOTE));
}

/// `(condition message, cross-namespace deferred entries)` of a VirtualService
/// named `name` with `spec`, planned under `options`.
fn cross_namespace_report(
    name: &str,
    spec: Value,
    options: K8sTranslationOptions,
) -> (String, Vec<String>) {
    use ferrum_edge::k8s_controller::istio_status::VIRTUAL_SERVICE_CROSS_NAMESPACE_DEFERRED_PREFIX;

    let obj = object("networking.istio.io/v1", "VirtualService", name, spec);
    let updates = plan_istio_status_updates(&[obj], options);
    let update = update_for(&updates, "VirtualService", name);
    let condition = find_condition(
        update.status["conditions"].as_array().unwrap(),
        "FerrumAccepted",
    );
    assert_eq!(
        condition["status"].as_str(),
        Some("True"),
        "{name}: gateway routes are still served, so the VirtualService stays accepted"
    );
    let refused = update.ferrum_detail.as_ref().unwrap()["translation"]["deferred_fields"]
        .as_array()
        .expect("deferred_fields")
        .iter()
        .filter_map(Value::as_str)
        .filter(|field| field.starts_with(VIRTUAL_SERVICE_CROSS_NAMESPACE_DEFERRED_PREFIX))
        .map(str::to_string)
        .collect();
    (condition["message"].as_str().unwrap().to_string(), refused)
}

fn cross_namespace_leg(host: &str, weight: u32) -> Value {
    json!({"destination": {"host": host, "port": {"number": 8080}}, "weight": weight})
}

fn cross_namespace_direct(host: &str) -> Value {
    json!({
        "hosts": ["reviews.default.svc.cluster.local"],
        "http": [{"route": [cross_namespace_leg(host, 100)]}]
    })
}

/// Issue #7499: Sidecar and NodeWaypoint data planes refuse a carried route
/// whose destination is a Service in another namespace (and keep routing the
/// host to its plain Service). A mesh-bound VirtualService naming one stays
/// `FerrumAccepted=True` (gateway routes are unaffected), counts them in the
/// condition message and lists each in `status.ferrum.translation.deferred_fields`.
/// Same-namespace Services, external hosts and gateway-only VirtualServices
/// report nothing.
#[test]
fn mesh_bound_virtual_service_status_reports_refused_cross_namespace_destinations() {
    for host in [
        "ratings.other.svc.cluster.local",
        "ratings.other.svc",
        "ratings.other",
    ] {
        let (message, refused) =
            cross_namespace_report("cross", cross_namespace_direct(host), options());
        assert_eq!(refused.len(), 1, "{host}: {refused:?}");
        assert!(
            refused[0].contains("http[0].route[0]")
                && refused[0].contains("\"other\"/\"ratings\"")
                && refused[0].contains("Sidecar and NodeWaypoint mesh data planes refuse")
                && refused[0].contains("plain Service route where one exists")
                && refused[0].contains("relative to the controller's cluster domain")
                && refused[0].contains("#7499"),
            "{host}: {}",
            refused[0]
        );
        assert!(
            message.contains("1 http[] destination(s) name a Service in another namespace")
                && message.contains("FERRUM_MESH_CLUSTER_DOMAIN"),
            "{host}: the condition message counts them and states the domain caveat: {message}"
        );
        assert!(
            !message.contains(&refused[0]),
            "{host}: the message summarizes instead of repeating each entry"
        );
    }

    // Every split leg is reported. A zero-weight leg of a multi-destination
    // route is omitted during translation, so it is described that way.
    let (message, refused) = cross_namespace_report(
        "split",
        json!({
            "hosts": ["reviews.default.svc.cluster.local"],
            "http": [{"route": [
                cross_namespace_leg("reviews.default.svc.cluster.local", 90),
                cross_namespace_leg("ratings.other.svc.cluster.local", 10),
                cross_namespace_leg("details.third.svc.cluster.local", 0)
            ]}]
        }),
        options(),
    );
    assert_eq!(refused.len(), 2, "{refused:?}");
    assert!(
        refused[0].contains("http[0].route[1]")
            && refused[0].contains("\"other\"/\"ratings\"")
            && refused[0].contains("data planes refuse")
    );
    assert!(
        refused[1].contains("http[0].route[2]")
            && refused[1].contains("\"third\"/\"details\"")
            && refused[1].contains("omitted during translation")
            && !refused[1].contains("data planes refuse"),
        "{}",
        refused[1]
    );
    assert!(message.contains("2 http[] destination(s)"), "{message}");

    // A single destination is kept by translation whatever its weight, so a
    // zero-weight single destination is refused by the data planes.
    let (_, refused) = cross_namespace_report(
        "single-zero",
        json!({
            "hosts": ["reviews.default.svc.cluster.local"],
            "http": [{"route": [cross_namespace_leg("ratings.other.svc.cluster.local", 0)]}]
        }),
        options(),
    );
    assert_eq!(refused.len(), 1, "{refused:?}");
    assert!(refused[0].contains("data planes refuse"), "{}", refused[0]);

    for (name, spec) in [
        (
            "same-namespace",
            cross_namespace_direct("reviews.default.svc.cluster.local"),
        ),
        ("short-name", cross_namespace_direct("reviews")),
        ("external", cross_namespace_direct("api.example.com")),
        (
            "gateway-only",
            json!({
                "hosts": ["reviews.default.svc.cluster.local"],
                "gateways": ["ingress-gw"],
                "http": [{"route": [cross_namespace_leg("ratings.other.svc.cluster.local", 100)]}]
            }),
        ),
    ] {
        let (message, refused) = cross_namespace_report(name, spec, options());
        assert!(refused.is_empty(), "{name}: {refused:?}");
        assert!(!message.contains("another namespace"), "{name}: {message}");
    }
}

/// Issue #7499: the configured cluster domain is normalized (surrounding
/// dots, case) exactly as the data plane's host index normalizes it, so a
/// custom domain written with a trailing dot classifies the same way.
#[test]
fn cross_namespace_status_normalizes_a_custom_cluster_domain() {
    let custom = || options().with_cluster_domain("Corp.Example.".to_string());
    for host in [
        "ratings.other.svc.corp.example",
        "ratings.other.svc.corp.example.",
    ] {
        let (_, refused) = cross_namespace_report("custom", cross_namespace_direct(host), custom());
        assert_eq!(refused.len(), 1, "{host}: {refused:?}");
    }
    // Mismatched settings: the controller's domain is `corp.example` while a
    // data plane may still use `cluster.local`. A fully qualified host is read
    // with the controller's domain (the documented caveat: the two settings
    // must match for status to predict the refusal), so a `cluster.local`
    // FQDN is external here and not reported...
    let (_, refused) = cross_namespace_report(
        "custom-external",
        cross_namespace_direct("ratings.other.svc.cluster.local"),
        custom(),
    );
    assert!(refused.is_empty(), "{refused:?}");
    // ...while the domain-independent forms are reported whatever the domain.
    for host in ["ratings.other", "ratings.other.svc"] {
        let (_, refused) =
            cross_namespace_report("custom-short", cross_namespace_direct(host), custom());
        assert_eq!(refused.len(), 1, "{host}: {refused:?}");
    }
}

/// Issue #7499: the listed destinations are budgeted by count and bytes, and
/// the rest are counted in one entry, so a VirtualService with many legs
/// cannot push its status update past the API server's request limit.
#[test]
fn cross_namespace_status_budgets_the_listed_destinations() {
    use ferrum_edge::k8s_controller::istio_status::{
        MAX_VIRTUAL_SERVICE_CROSS_NAMESPACE_DEFERRED_BYTES,
        MAX_VIRTUAL_SERVICE_CROSS_NAMESPACE_DEFERRED_ENTRIES,
    };

    let total = MAX_VIRTUAL_SERVICE_CROSS_NAMESPACE_DEFERRED_ENTRIES + 8;
    let http: Vec<Value> = (0..total)
        .map(|index| {
            json!({
                "match": [{"headers": {"x-leg": {"exact": format!("leg-{index}")}}}],
                "route": [cross_namespace_leg(&format!("svc-{index}.other.svc.cluster.local"), 100)]
            })
        })
        .collect();
    let (message, refused) = cross_namespace_report(
        "many",
        json!({"hosts": ["reviews.default.svc.cluster.local"], "http": http}),
        options(),
    );
    assert!(
        message.contains(&format!("{total} http[] destination(s)")),
        "the message counts every destination: {message}"
    );
    let (listed, omitted) = refused.split_at(refused.len() - 1);
    assert!(listed.len() <= MAX_VIRTUAL_SERVICE_CROSS_NAMESPACE_DEFERRED_ENTRIES);
    assert!(
        listed.iter().map(String::len).sum::<usize>()
            <= MAX_VIRTUAL_SERVICE_CROSS_NAMESPACE_DEFERRED_BYTES
    );
    assert!(
        omitted[0].contains(&format!("{} more destination(s)", total - listed.len())),
        "{}",
        omitted[0]
    );

    // At the budget nothing is omitted.
    let http: Vec<Value> = (0..4)
        .map(|index| {
            json!({
                "match": [{"headers": {"x-leg": {"exact": format!("leg-{index}")}}}],
                "route": [cross_namespace_leg(&format!("svc-{index}.other.svc.cluster.local"), 100)]
            })
        })
        .collect();
    let (_, refused) = cross_namespace_report(
        "few",
        json!({"hosts": ["reviews.default.svc.cluster.local"], "http": http}),
        options(),
    );
    assert_eq!(refused.len(), 4);
    assert!(
        refused
            .iter()
            .all(|entry| !entry.contains("more destination(s)"))
    );
}

/// Issue #7500: a mesh-bound VirtualService whose route host names a Service
/// bound to a ServiceWaypoint, but which that waypoint will not carry, says so
/// on its status with the projection's own reason: never a silent drop.
#[test]
fn virtual_service_status_reports_service_waypoint_route_exclusions() {
    let in_namespace = |api_version: &str, kind: &str, namespace: &str, name: &str, spec: Value| {
        let mut obj = object(api_version, kind, name, spec);
        obj.metadata.namespace = namespace.to_string();
        obj.metadata.uid = format!("uid-{namespace}-{name}");
        obj
    };
    let gateway = in_namespace(
        "gateway.networking.k8s.io/v1",
        "Gateway",
        "wp",
        "waypoint",
        json!({
            "gatewayClassName": "istio-waypoint",
            "listeners": [{"name": "mesh", "port": 15008, "protocol": "HBONE"}]
        }),
    );
    let mut service = in_namespace(
        "v1",
        "Service",
        "tenant",
        "orders",
        json!({"ports": [{"name": "http", "port": 8080, "protocol": "TCP", "targetPort": 8080}]}),
    );
    service
        .metadata
        .annotations
        .insert("istio.io/use-waypoint".to_string(), "waypoint".to_string());
    service.metadata.annotations.insert(
        "istio.io/use-waypoint-namespace".to_string(),
        "wp".to_string(),
    );
    let route = |namespace: &str, name: &str, export_to: Option<&[&str]>| {
        let mut spec = json!({
            "hosts": ["orders.tenant.svc.cluster.local"],
            "http": [{"route": [{"destination": {
                "host": "orders.tenant.svc.cluster.local",
                "port": {"number": 8080}
            }}]}]
        });
        if let Some(export_to) = export_to {
            spec["exportTo"] = json!(export_to);
        }
        in_namespace(
            "networking.istio.io/v1",
            "VirtualService",
            namespace,
            name,
            spec,
        )
    };
    let objects = vec![
        gateway,
        service,
        route("tenant", "orders-local", Some(&["."])),
        route("tenant", "orders-exported", None),
        route("evil", "hijack", Some(&["*"])),
        route("wp", "from-waypoint", Some(&["."])),
        route("wp", "from-waypoint-exported", Some(&[".", "tenant"])),
    ];
    let options = K8sTranslationOptions::new(
        "wp".to_string(),
        TrustDomain::new("cluster.local").expect("test trust domain"),
    )
    .with_source_namespaces(Vec::new());
    let updates = plan_istio_status_updates(&objects, options);
    let exclusions = |name: &str| -> (String, Value) {
        let update = update_for(&updates, "VirtualService", name);
        let condition = find_condition(
            update.status["conditions"].as_array().unwrap(),
            "FerrumAccepted",
        );
        assert_eq!(condition["status"].as_str(), Some("True"), "{name}");
        (
            condition["message"].as_str().unwrap().to_string(),
            update.ferrum_detail.as_ref().unwrap()["translation"]
                ["service_waypoint_route_exclusions"]
                .clone(),
        )
    };
    for (name, reason) in [
        ("orders-local", "not_exported_to_waypoint_namespace"),
        ("hijack", "foreign_namespace"),
        ("from-waypoint", "not_exported_to_service_namespace"),
    ] {
        let (message, detail) = exclusions(name);
        assert_eq!(
            detail,
            json!([{"service": "tenant/orders", "reason": reason}]),
            "{name}"
        );
        assert!(
            message.contains("bound to a ServiceWaypoint that does not carry them"),
            "{name}: {message}"
        );
    }
    for name in ["orders-exported", "from-waypoint-exported"] {
        let (message, detail) = exclusions(name);
        assert!(detail.is_null(), "{name} is carried: {detail}");
        assert!(
            !message.contains("ServiceWaypoint that does not carry"),
            "{name}"
        );
    }
}
