//! `from[].source.requestPrincipals` / `notRequestPrincipals` are action- and
//! protocol-aware (issue #4275).
//!
//! Both fields are JWT-derived, and a JWT only exists on an HTTP-family path.
//! On a Layer-4 session (raw TCP, TLS passthrough, UDP, DTLS) they are
//! *unevaluable*, not merely absent, so they must follow the same Istio
//! non-HTTP-port model the HTTP-only `to.operation` fields and the
//! `when: request.auth.*` conditions already use:
//!
//! * `DENY` (and `CUSTOM`) ignore the field and still match on the rule's
//!   remaining constraints — an unreadable attribute can never disarm a deny.
//! * `ALLOW` / `AUDIT` can never match on it — access is never granted on an
//!   attribute this path cannot read.
//!
//! Before the fix, `requestPrincipals` fell through the "no JWT ⇒ no match"
//! branch (a DENY silently missed and the L4 connection was admitted) and
//! `notRequestPrincipals` fell through the "no JWT ⇒ negative matcher
//! succeeds" branch (a `from:`-only ALLOW silently granted a raw session).
//!
//! An empty pattern list stays a no-op on every protocol: the emptiness check
//! runs ahead of the protocol gate.

use ferrum_edge::identity::spiffe::SpiffeId;
use ferrum_edge::modes::mesh::config::{MeshPolicy, MeshRule, PolicyAction, PolicyScope};
use ferrum_edge::modes::mesh::policy::{
    MeshAuthzDecision, MeshAuthzProtocol, MeshAuthzRequest, evaluate_mesh_authorization_policies,
};

const NS: &str = "default";
const ISSUER_PATTERN: &str = "https://issuer.example.com/*";
const PRINCIPAL: &str = "https://issuer.example.com/alice";

fn source() -> SpiffeId {
    SpiffeId::new("spiffe://cluster.local/ns/default/sa/client").expect("test SPIFFE id")
}

/// A raw TCP session on a non-HTTP port, exactly as the stream path builds it
/// (`Plugin::on_stream_connect` has no header map and no JWT context).
fn l4_request() -> MeshAuthzRequest {
    MeshAuthzRequest {
        source_principal: Some(source()),
        port: Some(3306),
        protocol: MeshAuthzProtocol::L4,
        ..MeshAuthzRequest::default()
    }
}

/// An HTTP request carrying a validated JWT principal.
fn http_request_with_principal() -> MeshAuthzRequest {
    MeshAuthzRequest {
        source_principal: Some(source()),
        request_principal: Some(PRINCIPAL.to_string()),
        path: Some("/api".to_string()),
        method: Some("GET".to_string()),
        port: Some(8080),
        protocol: MeshAuthzProtocol::Http,
        ..MeshAuthzRequest::default()
    }
}

/// An anonymous HTTP request (no JWT presented).
fn anonymous_http_request() -> MeshAuthzRequest {
    MeshAuthzRequest {
        request_principal: None,
        ..http_request_with_principal()
    }
}

fn policy(name: &str, action: PolicyAction, rule: MeshRule) -> MeshPolicy {
    MeshPolicy {
        name: name.to_string(),
        namespace: NS.to_string(),
        scope: PolicyScope::MeshWide,
        rules: vec![MeshRule { action, ..rule }],
    }
}

fn evaluate(policies: Vec<MeshPolicy>, request: &MeshAuthzRequest) -> MeshAuthzDecision {
    evaluate_mesh_authorization_policies(&policies, request)
}

fn deny(policy: &str) -> MeshAuthzDecision {
    MeshAuthzDecision::Deny {
        policy: policy.to_string(),
    }
}

fn implicit_deny() -> MeshAuthzDecision {
    deny("implicit-deny")
}

// ── DENY ──────────────────────────────────────────────────────────────────

#[test]
fn an_l4_deny_with_request_principals_still_denies() {
    let policies = vec![policy(
        "deny-jwt",
        PolicyAction::Deny,
        MeshRule {
            request_principals: vec![ISSUER_PATTERN.to_string()],
            ..MeshRule::default()
        },
    )];
    assert_eq!(
        evaluate(policies, &l4_request()),
        deny("deny-jwt"),
        "an HTTP-only requestPrincipals predicate must not disarm an L4 DENY"
    );
}

#[test]
fn an_l4_deny_with_not_request_principals_still_denies() {
    let policies = vec![policy(
        "deny-anonymous",
        PolicyAction::Deny,
        MeshRule {
            not_request_principals: vec!["*".to_string()],
            ..MeshRule::default()
        },
    )];
    assert_eq!(
        evaluate(policies, &l4_request()),
        deny("deny-anonymous"),
        "DENY notRequestPrincipals must keep matching on an L4 session"
    );
}

// ── CUSTOM ────────────────────────────────────────────────────────────────
//
// Istio documents HTTP-only fields on a TCP port as always matched for DENY
// AND CUSTOM. Treating CUSTOM like ALLOW here would make a CUSTOM rule that
// carries requestPrincipals / notRequestPrincipals silently inert on an L4
// session — a fail-open hole, because an unexecutable L4 delegation denies.

#[test]
fn an_l4_custom_with_principal_fields_still_denies() {
    for rule in [
        MeshRule {
            request_principals: vec![ISSUER_PATTERN.to_string()],
            ..MeshRule::default()
        },
        MeshRule {
            not_request_principals: vec!["*".to_string()],
            ..MeshRule::default()
        },
    ] {
        let policies = vec![policy(
            "delegate-jwt",
            PolicyAction::Custom {
                provider: "ext-authz".to_string(),
            },
            rule.clone(),
        )];
        assert_eq!(
            evaluate(policies, &l4_request()),
            deny("custom:delegate-jwt"),
            "an HTTP-only principal field must not disarm an L4 CUSTOM delegation: {rule:?}"
        );
    }
}

// ── ALLOW ─────────────────────────────────────────────────────────────────

#[test]
fn an_l4_allow_with_request_principals_cannot_grant() {
    let policies = vec![policy(
        "allow-jwt",
        PolicyAction::Allow,
        MeshRule {
            request_principals: vec![ISSUER_PATTERN.to_string()],
            ..MeshRule::default()
        },
    )];
    assert_eq!(
        evaluate(policies, &l4_request()),
        implicit_deny(),
        "an ALLOW requiring an unreadable attribute must fall to the implicit-deny floor"
    );
}

#[test]
fn an_l4_from_only_allow_with_not_request_principals_cannot_grant() {
    let policies = vec![policy(
        "allow-anonymous-from-ns",
        PolicyAction::Allow,
        MeshRule {
            not_request_principals: vec!["*".to_string()],
            ..MeshRule::default()
        },
    )];
    assert_eq!(
        evaluate(policies, &l4_request()),
        implicit_deny(),
        "notRequestPrincipals must not manufacture an L4 allow grant"
    );
}

// ── AUDIT ─────────────────────────────────────────────────────────────────

#[test]
fn an_l4_audit_with_principal_fields_never_matches() {
    for rule in [
        MeshRule {
            request_principals: vec![ISSUER_PATTERN.to_string()],
            ..MeshRule::default()
        },
        MeshRule {
            not_request_principals: vec!["*".to_string()],
            ..MeshRule::default()
        },
    ] {
        let policies = vec![policy("audit-jwt", PolicyAction::Audit, rule.clone())];
        assert_eq!(
            evaluate(policies, &l4_request()),
            MeshAuthzDecision::Allow,
            "an AUDIT rule must not match on an unreadable attribute: {rule:?}"
        );
    }
}

// ── Empty patterns stay a no-op ───────────────────────────────────────────

#[test]
fn empty_principal_patterns_remain_a_no_op_on_l4() {
    // An ALLOW whose principal lists are unset must still grant the L4
    // session: the emptiness check runs before the protocol gate, so an unset
    // field never resolves through the non-HTTP-port model.
    let allow = vec![policy(
        "allow-all",
        PolicyAction::Allow,
        MeshRule::default(),
    )];
    assert_eq!(evaluate(allow, &l4_request()), MeshAuthzDecision::Allow);

    // The DENY side of the same no-op: it matches on its remaining (empty)
    // constraints, exactly as it did before the protocol gate existed.
    let deny_all = vec![policy("deny-all", PolicyAction::Deny, MeshRule::default())];
    assert_eq!(evaluate(deny_all, &l4_request()), deny("deny-all"));
}

// ── HTTP behavior is unchanged ────────────────────────────────────────────

fn allow_request_principals(patterns: &[&str]) -> Vec<MeshPolicy> {
    vec![policy(
        "allow-jwt",
        PolicyAction::Allow,
        MeshRule {
            request_principals: patterns.iter().map(|p| p.to_string()).collect(),
            ..MeshRule::default()
        },
    )]
}

fn deny_anonymous_policies() -> Vec<MeshPolicy> {
    vec![policy(
        "deny-anonymous",
        PolicyAction::Deny,
        MeshRule {
            not_request_principals: vec!["*".to_string()],
            ..MeshRule::default()
        },
    )]
}

#[test]
fn http_request_principal_matching_is_unchanged() {
    assert_eq!(
        evaluate(
            allow_request_principals(&[ISSUER_PATTERN]),
            &http_request_with_principal()
        ),
        MeshAuthzDecision::Allow,
        "a matching JWT principal still satisfies an HTTP ALLOW"
    );
    assert_eq!(
        evaluate(
            allow_request_principals(&[ISSUER_PATTERN]),
            &anonymous_http_request()
        ),
        implicit_deny(),
        "an anonymous HTTP request still fails a requestPrincipals ALLOW"
    );
    assert_eq!(
        evaluate(
            allow_request_principals(&["https://other.example.com/*"]),
            &http_request_with_principal()
        ),
        implicit_deny(),
        "a non-matching issuer pattern still fails"
    );
}

#[test]
fn http_not_request_principal_matching_is_unchanged() {
    assert_eq!(
        evaluate(deny_anonymous_policies(), &anonymous_http_request()),
        deny("deny-anonymous"),
        "DENY notRequestPrincipals: [\"*\"] still catches anonymous HTTP requests"
    );
    assert_eq!(
        evaluate(deny_anonymous_policies(), &http_request_with_principal()),
        MeshAuthzDecision::Allow,
        "an authenticated HTTP request is still excluded by the negative matcher"
    );

    let allow_anonymous = vec![policy(
        "allow-anonymous",
        PolicyAction::Allow,
        MeshRule {
            not_request_principals: vec!["*".to_string()],
            ..MeshRule::default()
        },
    )];
    assert_eq!(
        evaluate(allow_anonymous, &anonymous_http_request()),
        MeshAuthzDecision::Allow,
        "an HTTP `from:`-only ALLOW with notRequestPrincipals still grants anonymous traffic"
    );
}
