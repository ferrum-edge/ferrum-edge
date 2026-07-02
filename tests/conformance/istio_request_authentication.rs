//! Istio RequestAuthentication conformance.
//!
//! Covers `jwtRules[]` translation onto [`MeshRequestAuthentication`] /
//! [`MeshJwtRule`] — issuer, inline `jwks` vs `jwksUri`, audiences, custom
//! header/param extraction, `forwardOriginalToken`, scope resolution, and the
//! fail-closed rejection of a rule without an issuer. Runtime semantics
//! (permissive pass-through without a token, 401 on an invalid token, the
//! `<iss>/<sub>` request principal consumed by `mesh_authz`
//! `requestPrincipals`) are enforced by the `jwks_auth`/`mesh_authz` plugin
//! suites and live-gated end-to-end by the `mesh-e2e-sidecar` suite's
//! `sidecar.request_auth.*` assertions.

use ferrum_edge::config_sources::k8s::{
    K8sMetadata, K8sObject, K8sTranslationOptions, translate_k8s_objects,
};
use ferrum_edge::identity::spiffe::TrustDomain;
use ferrum_edge::modes::mesh::config::{MeshRequestAuthentication, PolicyScope};
use serde_json::{Value, json};

use crate::conformance::registry::{Maturity, Status};

const CATEGORY: &str = "istio_request_authentication";

fn options() -> K8sTranslationOptions {
    K8sTranslationOptions::new(
        "default".to_string(),
        TrustDomain::new("cluster.local").expect("test trust domain"),
    )
}

fn request_auth(name: &str, namespace: &str, spec: Value) -> K8sObject {
    K8sObject {
        api_version: "security.istio.io/v1beta1".to_string(),
        kind: "RequestAuthentication".to_string(),
        metadata: K8sMetadata {
            name: name.to_string(),
            namespace: namespace.to_string(),
            ..K8sMetadata::default()
        },
        spec,
        status: Value::Object(serde_json::Map::new()),
    }
}

fn translate_one(spec: Value) -> MeshRequestAuthentication {
    let result =
        translate_k8s_objects(&[request_auth("ra-under-test", "default", spec)], options())
            .expect("translation succeeds");
    let mesh = result.config.mesh.expect("mesh config");
    mesh.request_authentications
        .into_iter()
        .next()
        .expect("one request authentication emitted")
}

/// `jwtRules[].issuer` + inline `jwks` project onto `MeshJwtRule` — the pair
/// the runtime validates RS256 tokens against without any JWKS fetch.
#[test]
fn request_auth_issuer_and_inline_jwks() {
    register_feature!(
        category = CATEGORY,
        feature = "jwtRules[].issuer + inline jwks",
        status = Status::Supported,
        maturity = Maturity::Ga,
        notes = "Maps to MeshJwtRule.issuer/.jwks (inline JWKS JSON string); enforced by the \
                 auto-injected __mesh_request_auth (jwks_auth) plugin and live-gated by \
                 sidecar.request_auth.{valid_jwt_admitted,missing_jwt_rejected,invalid_jwt_rejected}.",
    );
    let jwks = r#"{"keys":[{"kty":"RSA","alg":"RS256","kid":"k1","n":"abc","e":"AQAB"}]}"#;
    let ra = translate_one(json!({
        "jwtRules": [{"issuer": "https://issuer.example", "jwks": jwks}]
    }));
    assert_eq!(ra.jwt_rules.len(), 1);
    let rule = &ra.jwt_rules[0];
    assert_eq!(rule.issuer, "https://issuer.example");
    assert_eq!(rule.jwks.as_deref(), Some(jwks));
    assert!(rule.jwks_uri.is_none());
}

/// `jwtRules[].jwksUri` projects onto `MeshJwtRule.jwks_uri` (fetched JWKS).
#[test]
fn request_auth_jwks_uri() {
    register_feature!(
        category = CATEGORY,
        feature = "jwtRules[].jwksUri",
        status = Status::Supported,
        notes = "Maps to MeshJwtRule.jwks_uri; the jwks_auth plugin fetches and caches the JWKS.",
    );
    let ra = translate_one(json!({
        "jwtRules": [{"issuer": "iss", "jwksUri": "https://issuer.example/jwks.json"}]
    }));
    assert_eq!(
        ra.jwt_rules[0].jwks_uri.as_deref(),
        Some("https://issuer.example/jwks.json")
    );
}

/// `jwtRules[].audiences` projects onto `MeshJwtRule.audiences`.
#[test]
fn request_auth_audiences() {
    register_feature!(
        category = CATEGORY,
        feature = "jwtRules[].audiences",
        status = Status::Supported,
        notes = "Maps to MeshJwtRule.audiences; empty list means no audience validation.",
    );
    let ra = translate_one(json!({
        "jwtRules": [{"issuer": "iss", "jwks": "{}", "audiences": ["svc-a", "svc-b"]}]
    }));
    assert_eq!(ra.jwt_rules[0].audiences, vec!["svc-a", "svc-b"]);
}

/// `jwtRules[].fromHeaders` (name + optional prefix) projects onto
/// `MeshJwtRule.from_headers`.
#[test]
fn request_auth_from_headers() {
    register_feature!(
        category = CATEGORY,
        feature = "jwtRules[].fromHeaders name + prefix",
        status = Status::Supported,
        notes = "Maps to MeshJwtRule.from_headers (JwtHeader{name, prefix}); default extraction \
                 without fromHeaders is `Authorization: Bearer`.",
    );
    let ra = translate_one(json!({
        "jwtRules": [{
            "issuer": "iss",
            "jwks": "{}",
            "fromHeaders": [
                {"name": "x-jwt-assertion"},
                {"name": "x-token", "prefix": "Token "}
            ]
        }]
    }));
    let headers = &ra.jwt_rules[0].from_headers;
    assert_eq!(headers.len(), 2);
    assert_eq!(headers[0].name, "x-jwt-assertion");
    assert!(headers[0].prefix.is_none());
    assert_eq!(headers[1].name, "x-token");
    assert_eq!(headers[1].prefix.as_deref(), Some("Token "));
}

/// `jwtRules[].fromParams` projects onto `MeshJwtRule.from_params`.
#[test]
fn request_auth_from_params() {
    register_feature!(
        category = CATEGORY,
        feature = "jwtRules[].fromParams",
        status = Status::Supported,
        notes = "Maps to MeshJwtRule.from_params (query-parameter token extraction).",
    );
    let ra = translate_one(json!({
        "jwtRules": [{"issuer": "iss", "jwks": "{}", "fromParams": ["access_token"]}]
    }));
    assert_eq!(ra.jwt_rules[0].from_params, vec!["access_token"]);
}

/// `jwtRules[].forwardOriginalToken` projects onto
/// `MeshJwtRule.forward_original_token` (default false).
#[test]
fn request_auth_forward_original_token() {
    register_feature!(
        category = CATEGORY,
        feature = "jwtRules[].forwardOriginalToken",
        status = Status::Supported,
        notes = "Maps to MeshJwtRule.forward_original_token; false when omitted (token stripped \
                 after validation).",
    );
    let ra = translate_one(json!({
        "jwtRules": [{"issuer": "iss", "jwks": "{}", "forwardOriginalToken": true}]
    }));
    assert!(ra.jwt_rules[0].forward_original_token);
    let ra_default = translate_one(json!({
        "jwtRules": [{"issuer": "iss", "jwks": "{}"}]
    }));
    assert!(!ra_default.jwt_rules[0].forward_original_token);
}

/// A `jwtRules[]` entry without `issuer` is rejected at translation
/// (fail-closed), not silently dropped.
#[test]
fn request_auth_missing_issuer_fails_closed() {
    register_feature!(
        category = CATEGORY,
        feature = "jwtRules[].issuer missing fails closed",
        status = Status::Supported,
        notes = "Translation rejects the resource (K8sTranslateError -> FerrumAccepted=False); \
                 an issuer-less rule is never installed.",
    );
    let result = translate_k8s_objects(
        &[request_auth(
            "ra-no-issuer",
            "default",
            json!({"jwtRules": [{"jwks": "{}"}]}),
        )],
        options(),
    );
    assert!(
        result.is_err(),
        "issuer-less jwt rule must fail translation"
    );
}

/// `selector.matchLabels` scopes the policy to a workload selector; no
/// selector means namespace scope.
#[test]
fn request_auth_selector_scope() {
    register_feature!(
        category = CATEGORY,
        feature = "selector.matchLabels → WorkloadSelector scope",
        status = Status::Supported,
        notes = "Mirrors AuthorizationPolicy/PeerAuthentication scope resolution; \
                 MeshRequestAuthentication is additive after scope filtering.",
    );
    let scoped = translate_one(json!({
        "selector": {"matchLabels": {"app": "svc"}},
        "jwtRules": [{"issuer": "iss", "jwks": "{}"}]
    }));
    match &scoped.scope {
        PolicyScope::WorkloadSelector { selector } => {
            assert_eq!(selector.labels.get("app").map(String::as_str), Some("svc"));
        }
        other => panic!("expected WorkloadSelector scope, got {other:?}"),
    }
    let unscoped = translate_one(json!({
        "jwtRules": [{"issuer": "iss", "jwks": "{}"}]
    }));
    assert!(
        !matches!(unscoped.scope, PolicyScope::WorkloadSelector { .. }),
        "selector-less RequestAuthentication must not be workload-scoped"
    );
}
