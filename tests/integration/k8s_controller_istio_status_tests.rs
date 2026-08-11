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

/// A REJECTED Sidecar is dropped from the translation entirely, so it enforces
/// nothing. Its detail block must carry the explicit `false` qualifier — an
/// `outbound_traffic_policy` with no sibling flag reads as enforced.
#[test]
fn rejected_sidecar_reports_outbound_policy_as_not_enforced() {
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
    let translation = sidecar_translation(&updates, "sc-rejected");
    assert_eq!(
        translation["outbound_traffic_policy"],
        json!("REGISTRY_ONLY"),
        "the classified mode is still reported for diagnosis"
    );
    assert_eq!(
        translation["outbound_traffic_policy_enforced"],
        json!(false),
        "a dropped resource enforces nothing; the qualifier must be explicit"
    );
}
