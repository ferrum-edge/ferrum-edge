//! Istio AuthorizationPolicy conformance.
//!
//! Focuses on the empty-rule semantics + DENY/ALLOW interaction surface
//! highlighted in the CLAUDE.md "Istio empty-rule semantics" invariant and in
//! the 2026-05-18 user feedback. The translator + policy evaluator must agree
//! that:
//!   - `ALLOW` with no `rules` is allow-nothing (implicit-deny via a
//!     never-matching synthetic rule).
//!   - `DENY` / `AUDIT` with no `rules` are no-ops (zero rules emitted).
//!   - `RequestMatch.notMethods` / `notPaths` form a single AND-block on the
//!     same rule, not two separate DENY policies.
//!   - A request matching both an ALLOW and a DENY rule is denied (DENY first
//!     in `evaluate_mesh_authorization`).

use ferrum_edge::config_sources::k8s::{
    K8sMetadata, K8sObject, K8sTranslationOptions, translate_k8s_objects,
};
use ferrum_edge::identity::spiffe::TrustDomain;
use ferrum_edge::modes::mesh::config::{
    MeshPolicy, MeshRule, PolicyAction, PolicyScope, PrincipalMatch, RequestMatch,
};
use ferrum_edge::modes::mesh::policy::{
    MeshAuthzAttribute, MeshAuthzDecision, MeshAuthzProtocol, MeshAuthzRequest,
    evaluate_mesh_authorization_policies,
};
use serde_json::{Value, json};

use crate::conformance::registry::{Maturity, Status};

const CATEGORY: &str = "istio_authorization_policy";

fn options() -> K8sTranslationOptions {
    K8sTranslationOptions::new(
        "default".to_string(),
        TrustDomain::new("cluster.local").expect("test trust domain"),
    )
}

fn authz_policy(spec: Value) -> K8sObject {
    K8sObject {
        api_version: "security.istio.io/v1beta1".to_string(),
        kind: "AuthorizationPolicy".to_string(),
        metadata: K8sMetadata {
            name: "authz-under-test".to_string(),
            namespace: "default".to_string(),
            ..K8sMetadata::default()
        },
        spec,
        status: Value::Object(serde_json::Map::new()),
    }
}

fn translated(spec: Value) -> MeshPolicy {
    let result =
        translate_k8s_objects(&[authz_policy(spec)], options()).expect("translation succeeds");
    let mesh = result.config.mesh.expect("mesh config");
    mesh.mesh_policies
        .into_iter()
        .next()
        .expect("one mesh policy emitted")
}

/// CLAUDE.md "Istio empty-rule semantics" invariant: ALLOW + no rules =
/// allow-nothing. Emitted as a synthetic never-matching rule so the engine's
/// implicit-deny path fires; every request denies.
#[test]
fn authz_allow_no_rules_is_allow_nothing() {
    register_feature!(
        category = CATEGORY,
        feature = "ALLOW + no rules = allow-nothing",
        status = Status::Supported,
        notes = "Translator emits a synthetic never_matches=true rule so the engine's implicit-deny path fires on every request.",
    );
    let policy = translated(json!({"action": "ALLOW"}));
    assert_eq!(policy.rules.len(), 1, "synthetic never-match rule expected");
    assert!(policy.rules[0].never_matches);

    let decision = evaluate_mesh_authorization_policies(&[policy], &MeshAuthzRequest::default());
    assert_eq!(
        decision,
        MeshAuthzDecision::Deny {
            policy: "implicit-deny".to_string()
        }
    );
}

/// CLAUDE.md invariant: DENY + no rules = no-op. Zero rules emitted.
#[test]
fn authz_deny_no_rules_is_noop() {
    register_feature!(
        category = CATEGORY,
        feature = "DENY + no rules = no-op",
        status = Status::Supported,
        notes = "Zero rules emitted; the policy does not contribute to the engine's evaluation.",
    );
    let policy = translated(json!({"action": "DENY"}));
    assert!(
        policy.rules.is_empty(),
        "DENY with no rules must compile to zero rules"
    );
}

/// CLAUDE.md invariant: AUDIT + no rules = no-op. Mirrors DENY.
#[test]
fn authz_audit_no_rules_is_noop() {
    register_feature!(
        category = CATEGORY,
        feature = "AUDIT + no rules = no-op",
        status = Status::Supported,
        notes = "Zero rules emitted; AUDIT with no rules logs nothing.",
    );
    let policy = translated(json!({"action": "AUDIT"}));
    assert!(
        policy.rules.is_empty(),
        "AUDIT with no rules must compile to zero rules"
    );
}

/// DENY rule matches before ALLOW (CLAUDE.md "Authorization evaluation"):
/// `evaluate_mesh_authorization` is short-circuited on the first matching
/// DENY rule. Build a slice with an ALLOW + DENY policy that both match the
/// same request — assert the DENY wins.
#[test]
fn authz_deny_wins_when_both_match() {
    register_feature!(
        category = CATEGORY,
        feature = "DENY beats ALLOW on overlap",
        status = Status::Supported,
        maturity = Maturity::Ga,
        notes = "Per CLAUDE.md: DENY rules are evaluated first; any DENY match short-circuits the \
                 engine. Live-gated by sidecar.authz.denied_principal_rejected (a valid-mTLS peer \
                 denied by an identity-scoped DENY at the destination) in the mesh-e2e-sidecar suite.",
    );
    let allow = MeshPolicy {
        name: "allow-all".to_string(),
        namespace: "default".to_string(),
        scope: PolicyScope::MeshWide,
        rules: vec![MeshRule {
            action: PolicyAction::Allow,
            ..MeshRule::default()
        }],
    };
    let deny = MeshPolicy {
        name: "deny-rogue".to_string(),
        namespace: "default".to_string(),
        scope: PolicyScope::MeshWide,
        rules: vec![MeshRule {
            action: PolicyAction::Deny,
            from: vec![PrincipalMatch {
                spiffe_id_pattern: Some("spiffe://cluster.local/ns/default/sa/rogue".to_string()),
                namespace_pattern: None,
                trust_domain: None,
                trust_domain_pattern: None,
            }],
            ..MeshRule::default()
        }],
    };

    let req = MeshAuthzRequest {
        source_principal: Some(
            ferrum_edge::identity::SpiffeId::new("spiffe://cluster.local/ns/default/sa/rogue")
                .expect("valid spiffe id"),
        ),
        ..MeshAuthzRequest::default()
    };
    let decision = evaluate_mesh_authorization_policies(&[allow, deny], &req);
    assert_eq!(
        decision,
        MeshAuthzDecision::Deny {
            policy: "deny-rogue".to_string()
        }
    );
}

/// CLAUDE.md "RequestMatch supports Istio-style conjunctive negative-match
/// fields (notMethods / notPaths / notHosts / notPorts) — a rule with
/// `methods=[GET] AND not_paths=[/admin]` forms a single AND-block; do NOT
/// split into separate DENY policies." Translate the canonical AND-block
/// and assert one rule with both positive + negative match fields.
#[test]
fn authz_request_match_not_methods_is_single_and_block() {
    register_feature!(
        category = CATEGORY,
        feature = "rule with methods=[GET] AND notPaths=[/admin] stays one rule",
        status = Status::Supported,
        notes = "CLAUDE.md invariant: conjunctive negative-match fields form a single AND-block, not two policies.",
    );
    let policy = translated(json!({
        "action": "DENY",
        "rules": [{
            "to": [{"operation": {"methods": ["GET"], "notPaths": ["/admin"]}}]
        }]
    }));

    // Exactly one rule must carry both arms. If the translator split into
    // two rules, that's a regression.
    assert_eq!(
        policy.rules.len(),
        1,
        "single-source rule with conjunctive not-arms must stay one rule"
    );
    let to = &policy.rules[0].to;
    assert_eq!(to.len(), 1, "single AND-block on operation");
    assert_eq!(to[0].methods, vec!["GET".to_string()]);
    assert_eq!(to[0].not_paths, vec!["/admin".to_string()]);
}

/// ALLOW + matching rule: the engine returns Allow when the request matches.
/// Confirms the positive happy path that operators upgrade from "allow-nothing"
/// to "allow-list".
#[test]
fn authz_allow_with_rules_admits_matching_request() {
    register_feature!(
        category = CATEGORY,
        feature = "ALLOW + rule admits matching request",
        status = Status::Supported,
        maturity = Maturity::Ga,
        notes = "Operator-built allow-list of method+path admits the matching request and \
                 implicit-denies the rest. Live-gated in the mesh-e2e-sidecar suite: the \
                 authenticated positive traverses an ALLOW rule \
                 (sidecar.peer_auth.strict_mtls_authenticated) and the token-less gated-path \
                 probe proves the implicit deny (sidecar.request_auth.missing_jwt_rejected).",
    );
    let policy = translated(json!({
        "action": "ALLOW",
        "rules": [{
            "to": [{"operation": {"methods": ["GET"], "paths": ["/healthz"]}}]
        }]
    }));

    let allowed = MeshAuthzRequest {
        method: Some("GET".to_string()),
        path: Some("/healthz".to_string()),
        ..MeshAuthzRequest::default()
    };
    assert_eq!(
        evaluate_mesh_authorization_policies(std::slice::from_ref(&policy), &allowed),
        MeshAuthzDecision::Allow
    );

    let denied = MeshAuthzRequest {
        method: Some("POST".to_string()),
        path: Some("/healthz".to_string()),
        ..MeshAuthzRequest::default()
    };
    assert_eq!(
        evaluate_mesh_authorization_policies(&[policy], &denied),
        MeshAuthzDecision::Deny {
            policy: "implicit-deny".to_string()
        }
    );
}

#[test]
fn authz_unsupported_when_key_rejects_policy() {
    register_feature!(
        category = CATEGORY,
        feature = "unsupported when keys fail closed",
        status = Status::Supported,
        notes = "Translator rejects unsupported AuthorizationPolicy.when keys so DENY conditions cannot silently fail open.",
    );

    let err = translate_k8s_objects(
        &[authz_policy(json!({
            "action": "DENY",
            "rules": [{
                "when": [{
                    "key": "destination.labels[app]",
                    "values": ["payments"]
                }]
            }]
        }))],
        options(),
    )
    .expect_err("unsupported when key should reject the policy");

    let message = err.to_string();
    assert!(
        message.contains("rules[].when[0].key \"destination.labels[app]\" is unsupported"),
        "error should identify unsupported when key, got: {message}"
    );
}

/// PolicyScope is derived from the selector / namespace combination at
/// translation time. Confirm a `selector: matchLabels` produces a
/// `WorkloadSelector` scope so the request hot path can filter policies
/// before evaluation.
#[test]
fn authz_workload_selector_scope_is_preserved() {
    register_feature!(
        category = CATEGORY,
        feature = "selector.matchLabels → WorkloadSelector scope",
        status = Status::Supported,
        notes = "PolicyScope filtering precedence (WorkloadSelector > Namespace > MeshWide) per CLAUDE.md.",
    );
    let policy = translated(json!({
        "action": "DENY",
        "selector": {"matchLabels": {"app": "api"}},
        "rules": [{
            "from": [{"source": {"namespaces": ["other"]}}]
        }]
    }));
    match policy.scope {
        PolicyScope::WorkloadSelector { selector } => {
            assert_eq!(selector.labels.get("app").map(String::as_str), Some("api"));
            assert_eq!(selector.namespace.as_deref(), Some("default"));
        }
        other => panic!("expected WorkloadSelector scope, got {other:?}"),
    }
}

/// Translated rule body has `not_methods` field projected from
/// `notMethods` operator key (typed integration).
#[test]
fn authz_translates_request_match_negative_arms() {
    register_feature!(
        category = CATEGORY,
        feature = "RequestMatch.notMethods / notPaths / notHosts / notPorts",
        status = Status::Supported,
        notes = "Negative-match arms project into RequestMatch.not_methods/not_paths/not_hosts/not_ports/not_port_patterns.",
    );
    let policy = translated(json!({
        "action": "DENY",
        "rules": [{
            "to": [{"operation": {
                "notMethods": ["DELETE"],
                "notPaths": ["/admin"],
                "notHosts": ["internal.example.com"],
                "notPorts": ["8443"]
            }}]
        }]
    }));
    let to = &policy.rules[0].to[0];
    let _expected: &RequestMatch = to; // type-check
    assert_eq!(to.not_methods, vec!["DELETE".to_string()]);
    assert_eq!(to.not_paths, vec!["/admin".to_string()]);
    assert_eq!(to.not_hosts, vec!["internal.example.com".to_string()]);
    assert_eq!(to.not_ports, vec![8443]);
    assert!(to.not_port_patterns.is_empty());
}

/// Bounded Istio `notPorts` wildcards project into `not_port_patterns` and are
/// evaluated conjunctively with positive fields without widening the allow set.
#[test]
fn authz_translates_and_enforces_not_ports_wildcard_patterns() {
    register_feature!(
        category = CATEGORY,
        feature = "RequestMatch.notPorts wildcard patterns (8*, *443, *)",
        status = Status::Supported,
        notes = "Wildcard notPorts compile into RequestMatch.not_port_patterns with the same \
                 bounded grammar as positive ports; evaluation stays conjunctive and fail-closed \
                 when the destination port is absent.",
    );
    let policy = translated(json!({
        "action": "ALLOW",
        "rules": [{
            "to": [{"operation": {
                "ports": ["9180", "9090"],
                "notPorts": ["90*", "8080"]
            }}]
        }]
    }));
    assert_eq!(policy.rules.len(), 1);
    let to = &policy.rules[0].to[0];
    assert_eq!(to.ports, vec![9180, 9090]);
    assert_eq!(to.not_ports, vec![8080]);
    assert_eq!(to.not_port_patterns, vec!["90*".to_string()]);

    let allowed = MeshAuthzRequest {
        port: Some(9180),
        ..MeshAuthzRequest::default()
    };
    assert_eq!(
        evaluate_mesh_authorization_policies(std::slice::from_ref(&policy), &allowed),
        MeshAuthzDecision::Allow
    );

    let excluded_by_pattern = MeshAuthzRequest {
        port: Some(9090),
        ..MeshAuthzRequest::default()
    };
    assert_eq!(
        evaluate_mesh_authorization_policies(std::slice::from_ref(&policy), &excluded_by_pattern),
        MeshAuthzDecision::Deny {
            policy: "implicit-deny".to_string()
        }
    );

    let missing_port = MeshAuthzRequest {
        port: None,
        ..MeshAuthzRequest::default()
    };
    assert_eq!(
        evaluate_mesh_authorization_policies(std::slice::from_ref(&policy), &missing_port),
        MeshAuthzDecision::Deny {
            policy: "implicit-deny".to_string()
        }
    );
}

#[test]
fn authz_rejects_malformed_not_ports_wildcard_patterns() {
    register_feature!(
        category = CATEGORY,
        feature = "RequestMatch.notPorts rejects mid-string / named / out-of-range forms",
        status = Status::Supported,
        notes = "Malformed notPorts values fail closed with a field-specific diagnostic \
                 that does not echo the operator-supplied value.",
    );
    let err = translate_k8s_objects(
        &[authz_policy(json!({
            "action": "ALLOW",
            "rules": [{
                "to": [{"operation": {"notPorts": ["8*9"]}}]
            }]
        }))],
        options(),
    )
    .expect_err("mid-string notPorts must fail closed");
    let message = err.to_string();
    assert!(message.contains("rules[].to[].operation.notPorts"));
    assert!(
        message.contains("must be a numeric port in 1..=65535 or an admissible port pattern"),
        "notPorts diagnostic must use the field-specific no-echo wording: {message}"
    );
    assert!(
        !message.contains("8*9"),
        "notPorts diagnostic must not echo the operator-supplied value: {message}"
    );
}

#[test]
fn authz_target_refs_service_attachment_is_preserved() {
    register_feature!(
        category = CATEGORY,
        feature = "targetRefs → Service attachment scope",
        status = Status::Supported,
        notes = "AuthorizationPolicy targetRefs to a SAME-NAMESPACE Service resolve into \
                 PolicyScope::TargetRefs carrying resource identity only (no selector labels); \
                 runtime attachment is exact Service namespace/name membership at a waypoint. \
                 selector + targetRefs exclusivity, unsupported group/kind, and cross-namespace \
                 references all fail closed.",
    );

    use ferrum_edge::modes::mesh::config::PolicyTargetAttachment;

    let service = K8sObject {
        api_version: "v1".to_string(),
        kind: "Service".to_string(),
        metadata: K8sMetadata {
            name: "reviews".to_string(),
            namespace: "default".to_string(),
            ..K8sMetadata::default()
        },
        spec: json!({
            "selector": {"app": "reviews"},
            "ports": [{"port": 9080, "name": "http"}]
        }),
        status: Value::Object(serde_json::Map::new()),
    };
    let policy = authz_policy(json!({
        "targetRefs": [{
            "group": "",
            "kind": "Service",
            "name": "reviews"
        }],
        "action": "DENY",
        "rules": [{
            "from": [{"source": {"namespaces": ["evil"]}}]
        }]
    }));
    let result = translate_k8s_objects(&[service, policy], options())
        .expect("targetRefs Service translates");
    let mesh = result.config.mesh.expect("mesh");
    match &mesh.mesh_policies[0].scope {
        PolicyScope::TargetRefs { attachments } => match &attachments[0] {
            PolicyTargetAttachment::Service { namespace, name } => {
                assert_eq!(namespace, "default");
                assert_eq!(name, "reviews");
            }
            other => panic!("expected Service attachment, got {other:?}"),
        },
        other => panic!("expected TargetRefs scope, got {other:?}"),
    }

    let err = translate_k8s_objects(
        &[authz_policy(json!({
            "selector": {"matchLabels": {"app": "reviews"}},
            "targetRefs": [{"kind": "Service", "name": "reviews"}],
            "rules": [{}]
        }))],
        options(),
    )
    .expect_err("selector + targetRefs must fail closed");
    assert!(
        err.to_string()
            .contains("at most one of selector or targetRefs")
    );
}

#[test]
fn authz_singular_target_ref_service_attachment_is_preserved() {
    use ferrum_edge::modes::mesh::config::PolicyTargetAttachment;

    let service = K8sObject {
        api_version: "v1".to_string(),
        kind: "Service".to_string(),
        metadata: K8sMetadata {
            name: "reviews".to_string(),
            namespace: "default".to_string(),
            ..K8sMetadata::default()
        },
        spec: json!({
            "selector": {"app": "reviews"},
            "ports": [{"port": 9080, "name": "http"}]
        }),
        status: Value::Object(serde_json::Map::new()),
    };
    let policy = authz_policy(json!({
        "targetRef": {
            "group": "",
            "kind": "Service",
            "name": "reviews"
        },
        "action": "DENY",
        "rules": [{}]
    }));

    let result = translate_k8s_objects(&[service, policy], options())
        .expect("singular targetRef Service translates");
    let mesh = result.config.mesh.expect("mesh");
    match &mesh.mesh_policies[0].scope {
        PolicyScope::TargetRefs { attachments } => match &attachments[0] {
            PolicyTargetAttachment::Service { namespace, name } => {
                assert_eq!(namespace, "default");
                assert_eq!(name, "reviews");
            }
            other => panic!("expected Service attachment, got {other:?}"),
        },
        other => panic!("singular targetRef must not widen scope, got {other:?}"),
    }
}

/// Istio's contract lists `Gateway` / `Service` / `ServiceEntry` `targetRefs`
/// as same-namespace only, and `GatewayClass` as root-namespace. Ferrum matches
/// the namespace rules and declares `ServiceEntry` unsupported rather than
/// translating a policy it cannot enforce.
#[test]
fn authz_target_refs_namespace_and_kind_boundaries_fail_closed() {
    register_feature!(
        category = CATEGORY,
        feature = "targetRefs namespace + kind boundaries",
        status = Status::Supported,
        maturity = Maturity::Beta,
        notes = "Gateway/Service targetRefs are same-namespace only (a Gateway API \
                 ReferenceGrant does NOT widen the Istio policy-attachment contract, and \
                 Ferrum's CP owner-namespace filter would drop such a policy before the \
                 target data plane). GatewayClass requires the Istio root namespace and an \
                 observed cluster-scoped object. ServiceEntry attachments are REJECTED with a \
                 scoped diagnostic: Ferrum has no ServiceEntry-to-waypoint association model, \
                 so accepting one would report Accepted for an unenforceable policy.",
    );

    let remote_service = K8sObject {
        api_version: "v1".to_string(),
        kind: "Service".to_string(),
        metadata: K8sMetadata {
            name: "payments".to_string(),
            namespace: "other".to_string(),
            ..K8sMetadata::default()
        },
        spec: json!({"selector": {"app": "payments"}, "ports": [{"port": 8080}]}),
        status: Value::Object(serde_json::Map::new()),
    };
    let cross_namespace = authz_policy(json!({
        "targetRefs": [{"kind": "Service", "name": "payments", "namespace": "other"}],
        "rules": [{}]
    }));
    let err = translate_k8s_objects(
        &[remote_service, cross_namespace],
        options().with_source_namespaces(vec!["default".to_string(), "other".to_string()]),
    )
    .expect_err("cross-namespace Service targetRefs must fail closed");
    assert!(
        err.to_string().contains("same-namespace only"),
        "diagnostic must state the same-namespace contract: {err}"
    );

    let service_entry_ref = authz_policy(json!({
        "targetRefs": [{
            "group": "networking.istio.io",
            "kind": "ServiceEntry",
            "name": "ext"
        }],
        "rules": [{}]
    }));
    let err = translate_k8s_objects(&[service_entry_ref], options())
        .expect_err("ServiceEntry targetRefs must fail closed");
    assert!(
        err.to_string()
            .contains("ServiceEntry attachments are not supported yet"),
        "diagnostic must scope the refusal to ServiceEntry: {err}"
    );
}

// ── AuthorizationPolicy `when:` condition keys (issue #3236) ───────────────

/// Build a mesh-wide policy carrying a single `when[]` condition, translated
/// from the Istio CRD shape so the test covers the translator as well as the
/// evaluator.
fn condition_policy(action: &str, key: &str, values: Value, not_values: Value) -> MeshPolicy {
    let mut condition = serde_json::Map::new();
    condition.insert("key".to_string(), Value::String(key.to_string()));
    if !matches!(&values, Value::Null) {
        condition.insert("values".to_string(), values);
    }
    if !matches!(&not_values, Value::Null) {
        condition.insert("notValues".to_string(), not_values);
    }
    translated(json!({
        "action": action,
        "rules": [{"when": [Value::Object(condition)]}]
    }))
}

fn condition_translation_error(key: &str, values: Value) -> String {
    translate_k8s_objects(
        &[authz_policy(json!({
            "action": "DENY",
            "rules": [{"when": [{"key": key, "values": values}]}]
        }))],
        options(),
    )
    .expect_err("malformed when condition must fail closed")
    .to_string()
}

/// Every key in Istio's conditions reference translates. This is the coverage
/// claim of issue #3236: a valid Istio policy using any documented key must
/// install, not be rejected into oblivion (which is fail-OPEN for a DENY).
#[test]
fn authz_translates_the_complete_documented_condition_key_set() {
    register_feature!(
        category = CATEGORY,
        feature = "complete AuthorizationPolicy when-condition key set",
        status = Status::Supported,
        notes = "Every key documented at istio.io/docs/reference/config/security/conditions \
                 translates, including destination.ip, nested request.auth.claims[a][b], and \
                 experimental.envoy.filters.<filter>[<key>]. Keys outside the documented set \
                 are still rejected with a field-specific diagnostic.",
    );

    let documented: &[(&str, Value)] = &[
        (
            "source.principal",
            json!(["cluster.local/ns/default/sa/web"]),
        ),
        ("source.namespace", json!(["default"])),
        ("source.serviceAccount", json!(["default/web"])),
        ("source.trustDomain", json!(["cluster.local"])),
        ("source.ip", json!(["10.1.2.3", "10.2.0.0/16"])),
        ("remote.ip", json!(["203.0.113.0/24"])),
        ("destination.ip", json!(["10.96.0.0/12"])),
        ("destination.port", json!(["80", "443"])),
        ("connection.sni", json!(["www.example.com"])),
        ("request.auth.principal", json!(["issuer.example.com/sub"])),
        ("request.auth.audiences", json!(["example.com"])),
        ("request.auth.presenter", json!(["123.example.com"])),
        ("request.auth.claims[iss]", json!(["issuer.example.com"])),
        ("request.auth.claims[realm_access][roles]", json!(["admin"])),
        ("request.headers[user-agent]", json!(["Mozilla/*"])),
        (
            "experimental.envoy.filters.network.mysql_proxy[db.table]",
            json!(["books"]),
        ),
    ];

    for (key, values) in documented {
        let policy = condition_policy("DENY", key, values.clone(), Value::Null);
        assert_eq!(
            policy.rules.len(),
            1,
            "documented condition key '{key}' must translate to exactly one rule"
        );
        assert_eq!(
            policy.rules[0].when[0].key, *key,
            "documented condition key '{key}' must be preserved verbatim"
        );
    }
}

/// Istio's `destination.ip` is CIDR-matched against a transport-observed
/// destination. Missing destination evidence is unsourceable, not absent, so it
/// fails closed in both directions.
#[test]
fn authz_destination_ip_condition_matches_cidr_and_fails_closed_without_evidence() {
    register_feature!(
        category = CATEGORY,
        feature = "when: destination.ip (CIDR, fail-closed without evidence)",
        status = Status::Supported,
        notes = "destination.ip is CIDR-matched against the captured pre-NAT original \
                 destination or the connection's local address. It is never derived from a \
                 client-settable header. With no destination evidence (UDP/DTLS today) a DENY \
                 still applies and an ALLOW can never match.",
    );

    let deny = condition_policy(
        "DENY",
        "destination.ip",
        json!(["10.96.0.0/12"]),
        Value::Null,
    );

    let inside = destination_ip_request("10.96.4.7");
    assert_eq!(
        evaluate_mesh_authorization_policies(std::slice::from_ref(&deny), &inside),
        MeshAuthzDecision::Deny {
            policy: "authz-under-test".to_string()
        }
    );

    let outside = destination_ip_request("192.168.1.5");
    assert_eq!(
        evaluate_mesh_authorization_policies(std::slice::from_ref(&deny), &outside),
        MeshAuthzDecision::Allow
    );

    // No transport evidence at all: the DENY must not be disarmed.
    assert_eq!(
        evaluate_mesh_authorization_policies(
            std::slice::from_ref(&deny),
            &MeshAuthzRequest::default()
        ),
        MeshAuthzDecision::Deny {
            policy: "authz-under-test".to_string()
        }
    );

    let allow = condition_policy(
        "ALLOW",
        "destination.ip",
        json!(["10.96.0.0/12"]),
        Value::Null,
    );
    assert_eq!(
        evaluate_mesh_authorization_policies(
            std::slice::from_ref(&allow),
            &MeshAuthzRequest::default()
        ),
        MeshAuthzDecision::Deny {
            policy: "implicit-deny".to_string()
        },
        "an ALLOW gated on an unobservable destination.ip must never match"
    );
}

fn destination_ip_request(ip: &str) -> MeshAuthzRequest {
    let parsed: std::net::IpAddr = ip.parse().expect("test destination ip");
    let mut attributes = std::collections::BTreeMap::new();
    attributes.insert(
        "destination.ip".to_string(),
        MeshAuthzAttribute::Scalar(ip.to_string()),
    );
    MeshAuthzRequest {
        attributes,
        destination_ip: Some(parsed),
        protocol: MeshAuthzProtocol::Http,
        ..MeshAuthzRequest::default()
    }
}

/// Istio's documented non-HTTP-port behavior: HTTP-only `when` fields are
/// ignored by a DENY rule (which still matches) and make an ALLOW rule never
/// match. On HTTP the same key is sourceable and follows ordinary semantics.
#[test]
fn authz_http_only_condition_keys_follow_istio_non_http_port_semantics() {
    register_feature!(
        category = CATEGORY,
        feature = "HTTP-only when keys on non-HTTP ports",
        status = Status::Supported,
        notes = "On a TCP/UDP/DTLS connection an HTTP-only key (request.headers[...], \
                 request.auth.*) is unsourceable: DENY ignores the field and still matches, \
                 ALLOW/AUDIT can never match — including a notValues-only condition, which \
                 would otherwise be satisfied by the absent-attribute rule and grant every raw \
                 connection. On HTTP the key is sourceable and an absent attribute simply \
                 fails the values check.",
    );

    let deny = condition_policy(
        "DENY",
        "request.auth.claims[role]",
        json!(["admin"]),
        Value::Null,
    );
    assert_eq!(
        evaluate_mesh_authorization_policies(
            std::slice::from_ref(&deny),
            &MeshAuthzRequest::default()
        ),
        MeshAuthzDecision::Deny {
            policy: "authz-under-test".to_string()
        },
        "a raw L4 connection cannot carry JWT claims, so the DENY stays armed"
    );
    assert_eq!(
        evaluate_mesh_authorization_policies(std::slice::from_ref(&deny), &http_request()),
        MeshAuthzDecision::Allow,
        "on HTTP the claim is sourceable and absent, so the values check fails"
    );

    let allow_not_values = condition_policy(
        "ALLOW",
        "request.headers[x-env]",
        Value::Null,
        json!(["blocked"]),
    );
    assert_eq!(
        evaluate_mesh_authorization_policies(
            std::slice::from_ref(&allow_not_values),
            &MeshAuthzRequest::default()
        ),
        MeshAuthzDecision::Deny {
            policy: "implicit-deny".to_string()
        },
        "a notValues-only HTTP-only ALLOW condition must not grant a raw L4 connection"
    );
    assert_eq!(
        evaluate_mesh_authorization_policies(
            std::slice::from_ref(&allow_not_values),
            &http_request()
        ),
        MeshAuthzDecision::Allow,
        "on HTTP an absent attribute satisfies a notValues-only condition (Istio not_rule)"
    );
}

fn http_request() -> MeshAuthzRequest {
    MeshAuthzRequest {
        protocol: MeshAuthzProtocol::Http,
        ..MeshAuthzRequest::default()
    }
}

/// `experimental.envoy.filters.*` is documented by Istio but backed by Envoy
/// dynamic metadata Ferrum has no equivalent for. The policy still installs;
/// the condition is permanently unsourceable.
#[test]
fn authz_experimental_envoy_filter_condition_installs_and_fails_closed() {
    register_feature!(
        category = CATEGORY,
        feature = "when: experimental.envoy.filters.<filter>[<key>]",
        status = Status::OutOfScope,
        maturity = Maturity::Experimental,
        notes = "Accepted at translation so the surrounding AuthorizationPolicy still installs \
                 (rejecting it drops the whole policy, which is fail-OPEN for a DENY), but \
                 Ferrum has no Envoy filter chain to source the metadata from. The condition is \
                 permanently unsourceable: DENY ignores the field and still matches, ALLOW/AUDIT \
                 can never match. A malformed experimental key with no bracketed metadata name \
                 is rejected outright.",
    );

    let key = "experimental.envoy.filters.network.mysql_proxy[db.table]";
    let deny = condition_policy("DENY", key, json!(["books"]), Value::Null);
    assert_eq!(
        evaluate_mesh_authorization_policies(std::slice::from_ref(&deny), &http_request()),
        MeshAuthzDecision::Deny {
            policy: "authz-under-test".to_string()
        }
    );

    let allow = condition_policy("ALLOW", key, Value::Null, json!(["books"]));
    assert_eq!(
        evaluate_mesh_authorization_policies(std::slice::from_ref(&allow), &http_request()),
        MeshAuthzDecision::Deny {
            policy: "implicit-deny".to_string()
        }
    );

    let message = condition_translation_error(
        "experimental.envoy.filters.network.mysql_proxy",
        json!(["books"]),
    );
    assert!(
        message.contains("rules[].when[0].key") && message.contains("unsupported"),
        "a bare experimental key with no bracketed metadata name must fail closed: {message}"
    );
}

/// Field-specific, fail-closed rejection of malformed condition values and of
/// the bounds that keep an externally supplied policy from growing unbounded
/// per-request matching work.
#[test]
fn authz_rejects_malformed_and_unbounded_when_conditions() {
    register_feature!(
        category = CATEGORY,
        feature = "when-condition validation and bounds",
        status = Status::Supported,
        notes = "One shared validator backs the Kubernetes translator, MeshConfig validation, \
                 and the mesh_authz construction gate. It rejects empty/oversized/control-char \
                 keys and values, non-numeric destination.port values, malformed IP CIDRs, and \
                 collections over 64 when[] entries per rule or 256 values per list — each with \
                 a field-specific diagnostic — while preserving Istio's loose dynamic map-key \
                 framing for request headers and JWT claims.",
    );

    let port = condition_translation_error("destination.port", json!(["http"]));
    assert!(
        port.contains("rules[].when[0].values[0]")
            && port.contains("must be a numeric port in 0..=65535"),
        "non-numeric destination.port must fail closed with a field-specific diagnostic: {port}"
    );

    let out_of_range = condition_translation_error("destination.port", json!(["70000"]));
    assert!(
        out_of_range.contains("rules[].when[0].values[0]"),
        "out-of-range destination.port must fail closed: {out_of_range}"
    );

    let bad_cidr = condition_translation_error("destination.ip", json!(["10.0.0.0/40"]));
    assert!(
        bad_cidr.contains("rules[].when[0].values[0]") && bad_cidr.contains("prefix length"),
        "malformed destination.ip CIDR must fail closed: {bad_cidr}"
    );

    let empty_value = condition_translation_error("connection.sni", json!([""]));
    assert!(
        empty_value.contains("rules[].when[0].values[0]")
            && empty_value.contains("must not be empty"),
        "an empty condition value can never match and must fail closed: {empty_value}"
    );

    let control_char = condition_translation_error("connection.sni", json!(["ok\u{7}bad"]));
    assert!(
        control_char.contains("rules[].when[0].values[0]")
            && control_char.contains("control characters"),
        "a control character in a condition value must fail closed: {control_char}"
    );

    // `connection.sni` values are normalized rather than rejected: rejecting
    // one drops the whole AuthorizationPolicy, which is fail-OPEN for a DENY.
    // Only a non-ASCII value with no A-label spelling fails translation.
    let unconvertible = condition_translation_error("connection.sni", json!(["bü example"]));
    assert!(
        unconvertible.contains("rules[].when[0].values[0]") && unconvertible.contains("A-label"),
        "an unconvertible connection.sni value must fail closed: {unconvertible}"
    );
    let not_values_unconvertible = translate_k8s_objects(
        &[authz_policy(json!({
            "action": "DENY",
            "rules": [{"when": [{"key": "connection.sni", "notValues": ["bü*"]}]}]
        }))],
        options(),
    )
    .expect_err("an unconvertible connection.sni notValues entry must fail closed")
    .to_string();
    assert!(
        not_values_unconvertible.contains("rules[].when[0].notValues[0]")
            && not_values_unconvertible.contains("cannot be converted to an A-label"),
        "an unconvertible connection.sni notValues entry must fail closed: \
         {not_values_unconvertible}"
    );

    // The translated values take the received SNI's spelling: one trailing dot
    // stripped, ASCII lowercased, and a U-label converted to its A-label.
    let normalized = condition_policy(
        "DENY",
        "connection.sni",
        json!(["Admin.Example.COM.", "Bücher.Example"]),
        json!(["*.Public.Example.COM.", "*.bücher.example"]),
    );
    assert_eq!(
        normalized.rules[0].when[0].values,
        vec!["admin.example.com", "xn--bcher-kva.example"]
    );
    assert_eq!(
        normalized.rules[0].when[0].not_values,
        vec!["*.public.example.com", "*.xn--bcher-kva.example"]
    );

    let long_key = format!("request.headers[{}]", "a".repeat(300));
    let long = condition_translation_error(&long_key, json!(["x"]));
    assert!(
        long.contains("rules[].when[0].key") && long.contains("at most 256 UTF-8 bytes"),
        "an oversized condition key must fail closed: {long}"
    );
    assert!(
        !long.contains(&"a".repeat(300)),
        "the oversized-key diagnostic must not echo the operator-supplied key: {long}"
    );

    // Istio's validateMapKey uses only the first `[` and final `]` as map-key
    // framing and requires a non-empty interior. It does not validate dynamic
    // header names or claim paths here. Ferrum must admit the same shapes so
    // one unusual condition cannot discard unrelated rules in the policy.
    for istio_admitted_map_key in [
        "request.headers[:authority]",
        "request.headers[x env]",
        "request.headers[x-team][nested]",
        "request.headers[x:invalid]",
        "request.auth.claims[realm_access[roles]",
        "request.auth.claims[realm_access][]",
    ] {
        let policy = condition_policy("DENY", istio_admitted_map_key, json!(["x"]), Value::Null);
        assert_eq!(
            policy.rules[0].when[0].key, istio_admitted_map_key,
            "Istio-admitted dynamic map key must survive translation"
        );
    }

    // Istio's validateMapKey/envoyFilterGenerator treats the first `[` and
    // final `]` as delimiters; an interior `]` remains part of the metadata
    // key. Ferrum must admit the same documented key shape so a DENY policy is
    // not dropped before unsourceable-attribute fail-closed evaluation.
    let experimental_with_bracket = condition_policy(
        "DENY",
        "experimental.envoy.filters.network.mysql_proxy[db]table]",
        json!(["books"]),
        Value::Null,
    );
    assert_eq!(
        experimental_with_bracket.rules[0].when[0].key,
        "experimental.envoy.filters.network.mysql_proxy[db]table]",
        "an Istio-valid experimental metadata key must be admitted"
    );

    let too_many_values: Vec<String> = (0..300).map(|index| format!("v{index}")).collect();
    let values_message = condition_translation_error("connection.sni", json!(too_many_values));
    assert!(
        values_message.contains("rules[].when[0].values")
            && values_message.contains("at most 256 entries"),
        "an unbounded values list must fail closed: {values_message}"
    );

    let too_many_conditions: Vec<Value> = (0..100)
        .map(|index| json!({"key": format!("request.headers[x-{index}]"), "values": ["v"]}))
        .collect();
    let conditions_message = translate_k8s_objects(
        &[authz_policy(json!({
            "action": "DENY",
            "rules": [{"when": too_many_conditions}]
        }))],
        options(),
    )
    .expect_err("an unbounded when[] list must fail closed")
    .to_string();
    assert!(
        conditions_message.contains("rules[].when supports at most 64 entries"),
        "an unbounded when[] list must fail closed with a bound diagnostic: {conditions_message}"
    );
}

/// Istio's `StringMatcherWithPrefix` grammar, verbatim, for the keys that
/// actually compile to it: `*` is presence, a trailing `*` is a prefix match, a
/// leading `*` is a suffix match, and a mid-string `*` is an exact match on the
/// literal text.
///
/// This is NOT the grammar for every condition key — `source.serviceAccount` and
/// `source.namespace` compile to their own Istio matchers, covered by
/// [`authz_source_service_account_condition_is_exact_and_namespace_relative`] and
/// [`authz_source_namespace_condition_treats_every_star_as_a_wildcard`].
#[test]
fn authz_condition_values_follow_istio_string_matcher_grammar() {
    register_feature!(
        category = CATEGORY,
        feature = "when-condition value grammar (presence / prefix / suffix / exact)",
        status = Status::Supported,
        notes = "Matches Istio's matcher.StringMatcherWithPrefix for the keys that compile to \
                 it: '*' presence, '<prefix>*' prefix, '*<suffix>' suffix, anything else exact — \
                 including a mid-string '*', which Istio also treats as a literal exact match. \
                 source.serviceAccount (exact, namespace-relative) and source.namespace (every \
                 '*' is an arbitrary substring) have their own Istio grammars and are covered \
                 separately.",
    );

    let deny_prefix = condition_policy(
        "DENY",
        "request.headers[user-agent]",
        json!(["BadBot/*"]),
        Value::Null,
    );
    assert_eq!(
        evaluate_mesh_authorization_policies(
            std::slice::from_ref(&deny_prefix),
            &header_request("user-agent", "BadBot/1.0")
        ),
        MeshAuthzDecision::Deny {
            policy: "authz-under-test".to_string()
        }
    );

    // Istio checks the leading wildcard before the trailing wildcard. Thus a
    // double-ended pattern is a suffix match for the literal trailing `*`, not
    // an undocumented contains matcher.
    let deny_double_ended = condition_policy(
        "DENY",
        "request.headers[x-env]",
        json!(["*prod*"]),
        Value::Null,
    );
    assert_eq!(
        evaluate_mesh_authorization_policies(
            std::slice::from_ref(&deny_double_ended),
            &header_request("x-env", "release-prod*")
        ),
        MeshAuthzDecision::Deny {
            policy: "authz-under-test".to_string()
        }
    );
    assert_eq!(
        evaluate_mesh_authorization_policies(
            std::slice::from_ref(&deny_double_ended),
            &header_request("x-env", "release-prod-canary")
        ),
        MeshAuthzDecision::Allow
    );

    let deny_suffix = condition_policy(
        "DENY",
        "request.headers[user-agent]",
        json!(["*-canary"]),
        Value::Null,
    );
    assert_eq!(
        evaluate_mesh_authorization_policies(
            std::slice::from_ref(&deny_suffix),
            &header_request("user-agent", "client-canary")
        ),
        MeshAuthzDecision::Deny {
            policy: "authz-under-test".to_string()
        }
    );

    let deny_middle = condition_policy(
        "DENY",
        "request.headers[x-env]",
        json!(["pr*d"]),
        Value::Null,
    );
    assert_eq!(
        evaluate_mesh_authorization_policies(
            std::slice::from_ref(&deny_middle),
            &header_request("x-env", "prod")
        ),
        MeshAuthzDecision::Allow,
        "a mid-string '*' is a literal exact match, so it must not match 'prod'"
    );
    assert_eq!(
        evaluate_mesh_authorization_policies(
            std::slice::from_ref(&deny_middle),
            &header_request("x-env", "pr*d")
        ),
        MeshAuthzDecision::Deny {
            policy: "authz-under-test".to_string()
        },
        "a mid-string '*' must exact-match the literal text"
    );
}

fn header_request(name: &str, value: &str) -> MeshAuthzRequest {
    let mut attributes = std::collections::BTreeMap::new();
    attributes.insert(
        format!("request.headers[{name}]"),
        MeshAuthzAttribute::Scalar(value.to_string()),
    );
    MeshAuthzRequest {
        attributes,
        protocol: MeshAuthzProtocol::Http,
        ..MeshAuthzRequest::default()
    }
}

fn source_attribute_request(key: &str, value: &str) -> MeshAuthzRequest {
    let mut attributes = std::collections::BTreeMap::new();
    let attribute = MeshAuthzAttribute::Scalar(value.to_string());
    attributes.insert(key.to_string(), attribute);
    MeshAuthzRequest {
        attributes,
        protocol: MeshAuthzProtocol::Http,
        ..MeshAuthzRequest::default()
    }
}

fn deny_condition(key: &str, values: Value) -> MeshPolicy {
    condition_policy("DENY", key, values, Value::Null)
}

fn denied() -> MeshAuthzDecision {
    MeshAuthzDecision::Deny {
        policy: "authz-under-test".to_string(),
    }
}

/// Istio compiles `source.serviceAccount` to an EXACT matcher over
/// `<namespace>/<service-account>` (`serviceAccountRegex` in
/// `pilot/pkg/security/authz/model/generator.go`), and a bare
/// `<service-account>` is resolved against the namespace of the
/// `AuthorizationPolicy` that declared it — so the same policy text means
/// different things in different namespaces.
#[test]
fn authz_source_service_account_condition_is_exact_and_namespace_relative() {
    register_feature!(
        category = CATEGORY,
        feature = "when: source.serviceAccount (exact, namespace-relative)",
        status = Status::Supported,
        notes = "A bare '<service-account>' resolves against the declaring AuthorizationPolicy's \
                 namespace, matching Istio's serviceAccountRegex; the explicit \
                 '<namespace>/<service-account>' form is namespace-independent. The key is \
                 matched exactly — the generic string matcher is NOT used, and wildcards are \
                 rejected at translation rather than installed as conditions that can never \
                 fire.",
    );

    let bare = deny_condition("source.serviceAccount", json!(["checkout"]));
    assert_eq!(bare.namespace, "default");
    assert_eq!(
        evaluate_mesh_authorization_policies(
            std::slice::from_ref(&bare),
            &source_attribute_request("source.serviceAccount", "default/checkout")
        ),
        denied(),
        "a bare service account must resolve against the policy's own namespace"
    );
    assert_eq!(
        evaluate_mesh_authorization_policies(
            std::slice::from_ref(&bare),
            &source_attribute_request("source.serviceAccount", "payments/checkout")
        ),
        MeshAuthzDecision::Allow,
        "the same bare value must not match an identically named account in another namespace"
    );

    // The identical policy text, owned by another namespace, follows it.
    let mut relocated = bare.clone();
    relocated.namespace = "payments".to_string();
    assert_eq!(
        evaluate_mesh_authorization_policies(
            std::slice::from_ref(&relocated),
            &source_attribute_request("source.serviceAccount", "payments/checkout")
        ),
        denied(),
        "a bare service account is relative to the OWNING policy namespace"
    );
    assert_eq!(
        evaluate_mesh_authorization_policies(
            std::slice::from_ref(&relocated),
            &source_attribute_request("source.serviceAccount", "default/checkout")
        ),
        MeshAuthzDecision::Allow
    );

    // The explicit form is namespace-independent and still exact.
    let explicit = deny_condition("source.serviceAccount", json!(["payments/checkout"]));
    assert_eq!(
        evaluate_mesh_authorization_policies(
            std::slice::from_ref(&explicit),
            &source_attribute_request("source.serviceAccount", "payments/checkout")
        ),
        denied()
    );
    assert_eq!(
        evaluate_mesh_authorization_policies(
            std::slice::from_ref(&explicit),
            &source_attribute_request("source.serviceAccount", "payments/checkout-canary")
        ),
        MeshAuthzDecision::Allow,
        "source.serviceAccount is exact — it must not behave as a prefix match"
    );
}

/// Istio's `srcNamespaceGenerator` rewrites EVERY `*` in a `source.namespace`
/// value to `.*`, so a mid-string or repeated star is a real wildcard here even
/// though it is literal text for the generic string matcher.
#[test]
fn authz_source_namespace_condition_treats_every_star_as_a_wildcard() {
    register_feature!(
        category = CATEGORY,
        feature = "when: source.namespace (arbitrary-position wildcard)",
        status = Status::Supported,
        notes = "srcNamespaceGenerator replaces every '*' with '.*', so leading, trailing, \
                 mid-string, and repeated stars all behave as arbitrary substrings. This \
                 deliberately differs from matcher.StringMatcherWithPrefix, where a mid-string \
                 '*' is literal text.",
    );

    let middle = deny_condition("source.namespace", json!(["pr*d"]));
    for namespace in ["prod", "pr-team-d"] {
        assert_eq!(
            evaluate_mesh_authorization_policies(
                std::slice::from_ref(&middle),
                &source_attribute_request("source.namespace", namespace)
            ),
            denied(),
            "a mid-string '*' is an arbitrary substring for source.namespace ({namespace})"
        );
    }
    assert_eq!(
        evaluate_mesh_authorization_policies(
            std::slice::from_ref(&middle),
            &source_attribute_request("source.namespace", "staging")
        ),
        MeshAuthzDecision::Allow
    );

    let repeated = deny_condition("source.namespace", json!(["*pay*ments*"]));
    assert_eq!(
        evaluate_mesh_authorization_policies(
            std::slice::from_ref(&repeated),
            &source_attribute_request("source.namespace", "eu-pay-core-ments-1")
        ),
        denied(),
        "repeated stars are each an arbitrary substring"
    );
    assert_eq!(
        evaluate_mesh_authorization_policies(
            std::slice::from_ref(&repeated),
            &source_attribute_request("source.namespace", "eu-ments-core-pay-1")
        ),
        MeshAuthzDecision::Allow,
        "the literal segments must still appear in order"
    );

    // A star-free value stays exact.
    let exact = deny_condition("source.namespace", json!(["prod"]));
    assert_eq!(
        evaluate_mesh_authorization_policies(
            std::slice::from_ref(&exact),
            &source_attribute_request("source.namespace", "production")
        ),
        MeshAuthzDecision::Allow
    );
}

/// `source.trustDomain` keeps the presence / prefix / suffix matcher, which is
/// only correct because Istio's restricted `CheckTrustDomainValues` grammar is
/// enforced at admission on both value directions.
#[test]
fn authz_source_service_account_and_trust_domain_grammars_fail_closed_at_translation() {
    register_feature!(
        category = CATEGORY,
        feature = "when: source.serviceAccount / source.trustDomain value grammars",
        status = Status::Supported,
        notes = "CheckServiceAccount (exact '<namespace>/<service-account>' or bare \
                 '<service-account>', no '*', at most one '/') and CheckTrustDomainValues \
                 (exact, presence '*', one leading or one trailing '*', no '/') are enforced on \
                 both values and notValues. A value that would silently never match is \
                 fail-OPEN for a DENY, so it is rejected instead.",
    );

    let rejected: &[(&str, &str, &str)] = &[
        ("source.serviceAccount", "*", "must not contain '*'"),
        (
            "source.serviceAccount",
            "payments/*",
            "must not contain '*'",
        ),
        ("source.serviceAccount", "a/b/c", "at most one '/'"),
        ("source.serviceAccount", "/checkout", "non-empty namespace"),
        (
            "source.trustDomain",
            "clus*er.local",
            "leading or trailing wildcard",
        ),
        ("source.trustDomain", "*a*b*", "at most one '*'"),
        (
            "source.trustDomain",
            "cluster.local/ns",
            "must not contain '/'",
        ),
    ];

    for (key, value, reason) in rejected {
        let values_message = condition_translation_error(key, json!([value]));
        assert!(
            values_message.contains(reason) && values_message.contains("values[0]"),
            "'{key}' values '{value}' must fail closed with '{reason}': {values_message}"
        );

        let not_values_message = translate_k8s_objects(
            &[authz_policy(json!({
                "action": "DENY",
                "rules": [{"when": [{"key": key, "notValues": [value]}]}]
            }))],
            options(),
        )
        .expect_err("a malformed notValues entry must fail closed")
        .to_string();
        assert!(
            not_values_message.contains(reason) && not_values_message.contains("notValues[0]"),
            "'{key}' notValues '{value}' must fail closed with '{reason}': {not_values_message}"
        );
    }

    // The admitted trust-domain shapes still evaluate through the presence /
    // prefix / suffix matcher.
    let suffix = deny_condition("source.trustDomain", json!(["*.local"]));
    assert_eq!(
        evaluate_mesh_authorization_policies(
            std::slice::from_ref(&suffix),
            &source_attribute_request("source.trustDomain", "cluster.local")
        ),
        denied()
    );
    assert_eq!(
        evaluate_mesh_authorization_policies(
            std::slice::from_ref(&suffix),
            &source_attribute_request("source.trustDomain", "cluster.remote")
        ),
        MeshAuthzDecision::Allow
    );
}
