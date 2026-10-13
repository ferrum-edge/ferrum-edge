//! Istio translation regressions for `RequestAuthentication`,
//! `Telemetry`, and `DestinationRule.outlierDetection`
//! (issues #4277, #4292, #4305).
//!
//! Three fail-open shapes are guarded here:
//!
//! * `jwtRules[].outputClaimToHeaders` must reach `MeshJwtRule` — an
//!   unmapped entry leaves the header unowned, so a client-supplied
//!   `x-jwt-claim-sub: admin` would reach a backend migrated from Istio.
//! * a `targetRefs`-only `RequestAuthentication` / `Telemetry` must never be
//!   admitted as "no selector" and widened to namespace — or, in the Istio
//!   root namespace, mesh — scope.
//! * a translated `outlierDetection` that omits `maxEjectionPercent` must
//!   inherit Istio's 10% cap rather than Ferrum's uncapped native default.

use std::collections::HashMap;

use ferrum_edge::config_sources::k8s::{
    K8sMetadata, K8sObject, K8sTranslationOptions, translate_k8s_objects,
};
use ferrum_edge::identity::spiffe::TrustDomain;
use ferrum_edge::modes::mesh::config::{MeshConfig, PolicyScope};
use serde_json::{Value, json};

const ROOT_NS: &str = "istio-system";

fn options(namespace: &str) -> K8sTranslationOptions {
    K8sTranslationOptions::new(
        namespace.to_string(),
        TrustDomain::new("cluster.local").expect("test trust domain"),
    )
    .with_istio_root_namespace(ROOT_NS.to_string())
}

fn object(api_version: &str, kind: &str, namespace: &str, name: &str, spec: Value) -> K8sObject {
    K8sObject {
        api_version: api_version.to_string(),
        kind: kind.to_string(),
        metadata: K8sMetadata {
            name: name.to_string(),
            uid: format!("uid-{name}"),
            namespace: namespace.to_string(),
            generation: Some(1),
            labels: HashMap::new(),
            annotations: HashMap::new(),
            creation_timestamp: None,
            deletion_timestamp: None,
        },
        spec,
        status: Value::Object(serde_json::Map::new()),
    }
}

fn request_authentication(namespace: &str, spec: Value) -> K8sObject {
    object(
        "security.istio.io/v1",
        "RequestAuthentication",
        namespace,
        "ra",
        spec,
    )
}

fn telemetry(namespace: &str, spec: Value) -> K8sObject {
    object(
        "telemetry.istio.io/v1",
        "Telemetry",
        namespace,
        "telemetry",
        spec,
    )
}

fn translate_in(namespace: &str, objects: &[K8sObject]) -> Result<MeshConfig, String> {
    translate_k8s_objects(objects, options(namespace))
        .map(|translation| {
            *translation
                .config
                .mesh
                .clone()
                .expect("mesh present in translation")
        })
        .map_err(|error| error.to_string())
}

// ── #4277 outputClaimToHeaders ────────────────────────────────────────────

#[test]
fn output_claim_to_headers_reaches_the_translated_jwt_rule() {
    let mesh = translate_in(
        "default",
        &[request_authentication(
            "default",
            json!({
                "jwtRules": [{
                    "issuer": "https://issuer.example.com",
                    "jwksUri": "https://issuer.example.com/jwks",
                    "outputClaimToHeaders": [
                        {"header": "X-Jwt-Claim-Sub", "claim": "sub"},
                        {"header": "x-jwt-claim-groups", "claim": "profile.groups"},
                    ],
                }]
            }),
        )],
    )
    .expect("a RequestAuthentication with outputClaimToHeaders is admitted");

    let rule = &mesh.request_authentications[0].jwt_rules[0];
    let mapped: Vec<(&str, &str)> = rule
        .output_claim_to_headers
        .iter()
        .map(|entry| (entry.header.as_str(), entry.claim.as_str()))
        .collect();
    assert_eq!(
        mapped,
        vec![
            ("x-jwt-claim-sub", "sub"),
            ("x-jwt-claim-groups", "profile.groups"),
        ],
        "header names normalize to lowercase and declaration order is preserved"
    );
}

#[test]
fn unrepresentable_output_claim_entries_are_rejected_not_dropped() {
    // Each of these would otherwise leave the header unowned — and therefore
    // client-forgeable — on a backend that trusts it.
    for entry in [
        json!({"header": "Authorization", "claim": "sub"}),
        json!({"header": "host", "claim": "sub"}),
        json!({"header": "x-forwarded-for", "claim": "sub"}),
        json!({"header": "bad header", "claim": "sub"}),
        json!({"header": "x-ok", "claim": ""}),
        json!({"header": "x-ok", "claim": "a..b"}),
        json!({"header": "x-ok", "claim": "sub", "unknown": "x"}),
        json!({"claim": "sub"}),
        json!({"header": "x-ok"}),
        json!("x-ok"),
    ] {
        let error = translate_in(
            "default",
            &[request_authentication(
                "default",
                json!({
                    "jwtRules": [{
                        "issuer": "https://issuer.example.com",
                        "jwksUri": "https://issuer.example.com/jwks",
                        "outputClaimToHeaders": [entry],
                    }]
                }),
            )],
        )
        .expect_err("an unrepresentable outputClaimToHeaders entry must fail closed");
        assert!(
            error.contains("outputClaimToHeaders"),
            "diagnostic should name the field, got: {error}"
        );
    }
}

#[test]
fn duplicate_output_claim_destination_is_rejected() {
    let error = translate_in(
        "default",
        &[request_authentication(
            "default",
            json!({
                "jwtRules": [{
                    "issuer": "https://issuer.example.com",
                    "jwksUri": "https://issuer.example.com/jwks",
                    "outputClaimToHeaders": [
                        {"header": "x-claim", "claim": "sub"},
                        {"header": "X-Claim", "claim": "email"},
                    ],
                }]
            }),
        )],
    )
    .expect_err("one destination asserted from two claims is ambiguous");
    assert!(
        error.contains("more than once"),
        "expected a duplicate-destination diagnostic, got: {error}"
    );
}

#[test]
fn recognized_but_unenforced_jwt_rule_fields_still_translate() {
    // `outputPayloadToHeader` / `fromCookies` are reported as deferred fields
    // (see the status-planning tests); they must not reject the resource.
    let mesh = translate_in(
        "default",
        &[request_authentication(
            "default",
            json!({
                "jwtRules": [{
                    "issuer": "https://issuer.example.com",
                    "jwksUri": "https://issuer.example.com/jwks",
                    "outputPayloadToHeader": "x-jwt-payload",
                    "fromCookies": ["session"],
                }]
            }),
        )],
    )
    .expect("a deferred field is accepted, not rejected");
    assert_eq!(mesh.request_authentications[0].jwt_rules.len(), 1);
}

// ── #4305 targetRefs must not widen ───────────────────────────────────────

#[test]
fn request_authentication_with_singular_target_ref_is_not_widened_to_namespace() {
    let error = translate_in(
        "default",
        &[
            object(
                "gateway.networking.k8s.io/v1",
                "GatewayClass",
                "",
                "istio-waypoint",
                json!({"controllerName": "istio.io/gateway-controller"}),
            ),
            object(
                "gateway.networking.k8s.io/v1",
                "Gateway",
                "default",
                "waypoint",
                json!({
                    "gatewayClassName": "istio-waypoint",
                    "listeners": [{"name": "mesh", "port": 15008, "protocol": "HBONE"}]
                }),
            ),
            request_authentication(
                "default",
                json!({
                    "targetRef": {
                        "group": "gateway.networking.k8s.io",
                        "kind": "Gateway",
                        "name": "waypoint"
                    },
                    "jwtRules": [{
                        "issuer": "https://issuer.example.com",
                        "jwksUri": "https://issuer.example.com/jwks"
                    }]
                }),
            ),
        ],
    )
    .expect_err("a targetRef-only RequestAuthentication must not be silently widened");
    assert!(
        error.contains("targetRef is not supported"),
        "expected a fail-closed targetRef diagnostic, got: {error}"
    );
}

#[test]
fn telemetry_with_singular_target_ref_is_not_widened_to_mesh_wide() {
    let error = translate_in(
        ROOT_NS,
        &[
            object(
                "gateway.networking.k8s.io/v1",
                "GatewayClass",
                "",
                "istio-waypoint",
                json!({"controllerName": "istio.io/gateway-controller"}),
            ),
            object(
                "gateway.networking.k8s.io/v1",
                "Gateway",
                ROOT_NS,
                "ingress",
                json!({
                    "gatewayClassName": "istio-waypoint",
                    "listeners": [{"name": "mesh", "port": 15008, "protocol": "HBONE"}]
                }),
            ),
            telemetry(
                ROOT_NS,
                json!({
                    "targetRef": {
                        "group": "gateway.networking.k8s.io",
                        "kind": "Gateway",
                        "name": "ingress"
                    },
                    "accessLogging": [{"disabled": true}]
                }),
            ),
        ],
    )
    .expect_err("a root-namespace targetRef Telemetry must not become MeshWide");
    assert!(
        error.contains("targetRef is not supported"),
        "expected a fail-closed targetRef diagnostic, got: {error}"
    );
}

#[test]
fn selector_and_target_refs_together_are_rejected_on_both_kinds() {
    for object in [
        request_authentication(
            "default",
            json!({
                "selector": {"matchLabels": {"app": "reviews"}},
                "targetRefs": [{"kind": "Service", "name": "reviews"}],
                "jwtRules": [{
                    "issuer": "https://issuer.example.com",
                    "jwksUri": "https://issuer.example.com/jwks"
                }]
            }),
        ),
        telemetry(
            "default",
            json!({
                "selector": {"matchLabels": {"app": "reviews"}},
                "targetRefs": [{"kind": "Service", "name": "reviews"}],
                "accessLogging": [{"disabled": true}]
            }),
        ),
    ] {
        let kind = object.kind.clone();
        let error = translate_in("default", &[object])
            .expect_err("selector + targetRefs is mutually exclusive");
        assert!(
            error.contains("at most one of selector or targetRefs"),
            "{kind}: expected the exclusivity diagnostic, got: {error}"
        );
    }
}

#[test]
fn a_selector_scoped_resource_keeps_its_workload_scope() {
    // Guardrail for the rejection above: the ordinary selector path is
    // untouched, so the fix cannot have narrowed anything else.
    let mesh = translate_in(
        "default",
        &[request_authentication(
            "default",
            json!({
                "selector": {"matchLabels": {"app": "reviews"}},
                "jwtRules": [{
                    "issuer": "https://issuer.example.com",
                    "jwksUri": "https://issuer.example.com/jwks"
                }]
            }),
        )],
    )
    .expect("a selector-scoped RequestAuthentication still translates");
    let scope = &mesh.request_authentications[0].scope;
    assert!(matches!(scope, PolicyScope::WorkloadSelector { .. }));
}

#[test]
fn a_root_namespace_resource_without_target_refs_is_still_mesh_wide() {
    let mesh = translate_in(
        ROOT_NS,
        &[telemetry(
            ROOT_NS,
            json!({"accessLogging": [{"disabled": true}]}),
        )],
    )
    .expect("a selector-less root-namespace Telemetry is mesh-wide as before");
    assert!(matches!(
        mesh.telemetry_resources[0].scope,
        PolicyScope::MeshWide
    ));
}

// ── #4292 outlier detection defaults ──────────────────────────────────────

fn destination_rule(outlier: Value) -> K8sObject {
    object(
        "networking.istio.io/v1",
        "DestinationRule",
        "default",
        "reviews",
        json!({
            "host": "reviews.default.svc.cluster.local",
            "trafficPolicy": {"outlierDetection": outlier}
        }),
    )
}

#[test]
fn translated_outlier_detection_preserves_an_omitted_cap_for_overlay_time() {
    let mesh = translate_in(
        "default",
        &[destination_rule(json!({
            "consecutive5xxErrors": 5,
            "interval": "10s"
        }))],
    )
    .expect("DestinationRule translates");

    let outlier = mesh.destination_rules[0]
        .traffic_policy
        .as_ref()
        .and_then(|policy| policy.outlier_detection.as_ref())
        .expect("outlierDetection translated");
    assert_eq!(outlier.consecutive_errors, Some(5));
    assert_eq!(
        outlier.max_ejection_percent, None,
        "translation must not synthesize a per-block default that overwrites a lower tier"
    );
}

#[test]
fn an_explicit_max_ejection_percent_still_wins() {
    let mesh = translate_in(
        "default",
        &[destination_rule(json!({
            "consecutive5xxErrors": 5,
            "maxEjectionPercent": 50
        }))],
    )
    .expect("DestinationRule translates");

    assert_eq!(
        mesh.destination_rules[0]
            .traffic_policy
            .as_ref()
            .and_then(|policy| policy.outlier_detection.as_ref())
            .and_then(|outlier| outlier.max_ejection_percent),
        Some(50)
    );
}

#[test]
fn malformed_outlier_detection_values_fail_closed() {
    for (outlier, field) in [
        (json!({"consecutive5xxErrors": "5"}), "consecutive5xxErrors"),
        (json!({"consecutive5xxErrors": -1}), "consecutive5xxErrors"),
        (json!({"consecutive5xxErrors": 5.5}), "consecutive5xxErrors"),
        (
            json!({"consecutive5xxErrors": u64::from(u32::MAX) + 1}),
            "consecutive5xxErrors",
        ),
        (json!({"interval": 10}), "interval"),
        (json!({"interval": "later"}), "interval"),
        (json!({"interval": "0s"}), "interval"),
        (json!({"baseEjectionTime": 30}), "baseEjectionTime"),
        (json!({"baseEjectionTime": "later"}), "baseEjectionTime"),
        (json!({"maxEjectionPercent": "10"}), "maxEjectionPercent"),
        (json!({"maxEjectionPercent": 101}), "maxEjectionPercent"),
    ] {
        let error = translate_in("default", &[destination_rule(outlier)])
            .expect_err("an unrepresentable outlierDetection value must fail closed");
        assert!(
            error.contains(field),
            "expected a field-shaped {field} diagnostic, got: {error}"
        );
    }
}

#[test]
fn unenforced_outlier_fields_do_not_reject_the_resource() {
    // They are reported through `deferred_fields` (status-planning tests).
    let mesh = translate_in(
        "default",
        &[destination_rule(json!({
            "consecutive5xxErrors": 5,
            "consecutiveGatewayErrors": 3,
            "consecutiveLocalOriginFailures": 2,
            "minHealthPercent": 40
        }))],
    )
    .expect("deferred outlier fields are accepted, not rejected");
    assert!(
        mesh.destination_rules[0]
            .traffic_policy
            .as_ref()
            .and_then(|policy| policy.outlier_detection.as_ref())
            .is_some()
    );
}

#[test]
fn translated_outlier_detection_preserves_an_omitted_threshold_for_overlay_time() {
    let mesh = translate_in(
        "default",
        &[destination_rule(json!({
            "interval": "10s"
        }))],
    )
    .expect("DestinationRule translates");

    let outlier = mesh.destination_rules[0]
        .traffic_policy
        .as_ref()
        .and_then(|policy| policy.outlier_detection.as_ref())
        .expect("outlierDetection translated");
    assert_eq!(
        outlier.consecutive_errors, None,
        "translation must preserve omission so a lower tier can supply the threshold"
    );
    assert_eq!(outlier.max_ejection_percent, None);
}

#[test]
fn translated_outlier_detection_empty_block_preserves_omitted_fields() {
    let mesh = translate_in("default", &[destination_rule(json!({}))])
        .expect("empty outlierDetection translates");

    assert_eq!(
        mesh.destination_rules[0]
            .traffic_policy
            .as_ref()
            .and_then(|policy| policy.outlier_detection.as_ref())
            .and_then(|outlier| outlier.consecutive_errors),
        None
    );
}

#[test]
fn explicit_zero_consecutive5xx_errors_is_preserved_as_disabled() {
    let mesh = translate_in(
        "default",
        &[destination_rule(json!({
            "consecutive5xxErrors": 0,
            "interval": "10s"
        }))],
    )
    .expect("DestinationRule translates");

    assert_eq!(
        mesh.destination_rules[0]
            .traffic_policy
            .as_ref()
            .and_then(|policy| policy.outlier_detection.as_ref())
            .and_then(|outlier| outlier.consecutive_errors),
        Some(0)
    );
}

#[test]
fn legacy_consecutive_errors_alias_is_preserved_for_overlay() {
    let mesh = translate_in(
        "default",
        &[destination_rule(json!({
            "consecutiveErrors": 9
        }))],
    )
    .expect("DestinationRule translates");

    assert_eq!(
        mesh.destination_rules[0]
            .traffic_policy
            .as_ref()
            .and_then(|policy| policy.outlier_detection.as_ref())
            .and_then(|outlier| outlier.consecutive_errors),
        Some(9)
    );
}
