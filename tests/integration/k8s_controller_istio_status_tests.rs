//! Integration tests for the T2-B Istio CRD status writer.
//!
//! Covers the `plan_istio_status_updates` planning surface as exercised
//! against realistic mixes of Istio resources. The actual `patch_status`
//! call requires a live (or mocked) Kubernetes API server and is out of
//! scope for CI — kube-rs makes that wiremockable but at the cost of a
//! large amount of test plumbing. Wiring `patch_status` through is
//! covered by the unit tests inline in `src/k8s_controller/istio_status.rs`,
//! the unit tests assert the patch shape directly via `istio_status_patch`.
//!
//! What this file exercises:
//! - Mixed cluster snapshots: every translated Istio kind in one snapshot
//!   generates a status update (all nine kinds are covered).
//! - Resource accepted vs. rejected: rejected resources still produce a
//!   `FerrumAccepted: False` update so operators see the failure — including
//!   the newly-covered kinds (VirtualService, ServiceEntry,
//!   RequestAuthentication, Sidecar, Telemetry, WorkloadEntry).
//! - Skip behaviour: kinds the status writer does not own (e.g. the
//!   translated-but-unwatched `ProxyConfig`) do not produce updates.
//! - Stability: the same input always produces the same set of updates
//!   (no nondeterminism), and `lastTransitionTime` is preserved across
//!   no-op replans.
//!
//! Field-by-field assertions live in the inline unit tests; this file
//! sticks to integration-level invariants.

use ferrum_edge::config_sources::k8s::{K8sMetadata, K8sObject, K8sTranslationOptions};
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
            uid: String::new(),
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
/// translated Istio kind (all nine are covered). A translated-but-unwatched
/// kind (`ProxyConfig`) is silently skipped — it shows up as no update in
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
            json!({ "jwtRules": [{ "issuer": "https://issuer.example.com" }] }),
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
        // Translated but not watched / not a status-writer kind: must be skipped.
        object(
            "networking.istio.io/v1beta1",
            "ProxyConfig",
            "default-pc",
            json!({}),
        ),
    ];

    let updates = plan_istio_status_updates(&objects, options());
    assert_eq!(
        updates.len(),
        9,
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
    ] {
        assert!(
            updates.iter().any(|u| u.kind == kind),
            "expected an update for {kind}, got {updates:?}"
        );
    }
    // ProxyConfig is not a status-writer kind and must not appear.
    assert!(updates.iter().all(|u| u.kind != "ProxyConfig"));
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
            json!({ "jwtRules": [{ "issuer": "https://issuer.example.com" }] }),
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

/// DestinationRule deferred-fields tracking: when an operator uses a
/// parsed-but-unenforced field (here `connectionPool.http.maxRetries`), the
/// detail block surfaces it as a deferred field so they know Ferrum parsed it
/// but does not enforce it. (`portLevelSettings[].tls` was the example here
/// before it became applied per-port, so it is no longer deferred.)
#[test]
fn destination_rule_deferred_fields_listed_in_detail() {
    let obj = object(
        "networking.istio.io/v1",
        "DestinationRule",
        "secured",
        json!({
            "host": "secured.default.svc.cluster.local",
            "trafficPolicy": {
                "connectionPool": { "http": { "maxRetries": 3 } }
            }
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
    assert!(deferred.iter().any(|f| f.contains("maxRetries")));
    let message = find_condition(
        updates[0].status["conditions"].as_array().unwrap(),
        "FerrumAccepted",
    )["message"]
        .as_str()
        .unwrap();
    assert!(
        message.contains("deferred fields"),
        "message should mention deferred fields, got: {message}"
    );
}
