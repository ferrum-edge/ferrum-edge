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
    MeshAuthzDecision, MeshAuthzRequest, evaluate_mesh_authorization_policies,
};
use serde_json::{Value, json};

use crate::conformance::registry::Status;

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
        notes = "Per CLAUDE.md: DENY rules are evaluated first; any DENY match short-circuits the engine.",
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
        notes = "Operator-built allow-list of method+path admits the matching request and implicit-denies the rest.",
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
        notes = "Negative-match arms project into RequestMatch.not_methods/not_paths/not_hosts/not_ports.",
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
}
