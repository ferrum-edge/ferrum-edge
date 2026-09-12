//! Istio `RequestAuthentication.jwtRules[].outputClaimToHeaders` projection
//! onto `jwks_auth` (issue #4277).
//!
//! Istio SETS and OVERWRITES these headers from the validated token, which is
//! what makes them trustworthy to a backend. The load-bearing invariant here is
//! the other half: a declared destination is **gateway-owned**, so it is
//! removed from every inbound request — including one that never authenticates
//! — before any verified value can be installed. Without that, an app migrated
//! from Istio would trust a client-supplied `x-jwt-claim-sub: admin`.

use std::collections::HashMap;

use chrono::Utc;
use serde_json::json;

use ferrum_edge::ConsumerIndex;
use ferrum_edge::config::types::{Consumer, default_namespace};
use ferrum_edge::plugins::{Plugin, RequestContext, jwks_auth::JwksAuth};

use super::jwks_auth_support::{build_rsa_jwks_from_pem, create_rs256_token, default_client};
use super::plugin_utils::assert_continue;

const PRIVATE_KEY: &[u8] = include_bytes!("../../../tests/fixtures/test_rsa_private.pem");
const PUBLIC_KEY: &[u8] = include_bytes!("../../../tests/fixtures/test_rsa_public.pem");

fn ctx() -> RequestContext {
    RequestContext::new(
        "127.0.0.1".to_string(),
        "GET".to_string(),
        "/protected".to_string(),
    )
}

fn consumer_index() -> ConsumerIndex {
    ConsumerIndex::new(&[Consumer {
        labels: Default::default(),
        id: "alice-id".to_string(),
        username: "alice".to_string(),
        namespace: default_namespace(),
        custom_id: None,
        credentials: HashMap::new(),
        acl_groups: Vec::new(),
        created_at: Utc::now(),
        updated_at: Utc::now(),
    }])
}

fn plugin_with(output_claim_headers: serde_json::Value) -> Result<JwksAuth, String> {
    JwksAuth::new(
        &json!({
            "providers": [{
                "jwks": build_rsa_jwks_from_pem(PUBLIC_KEY),
                "output_claim_headers": output_claim_headers,
            }]
        }),
        default_client(),
    )
}

/// Run authenticate + before_proxy over `client_headers`, returning the
/// backend-visible header map.
async fn run(
    plugin: &JwksAuth,
    token: Option<&str>,
    client_headers: &[(&str, &str)],
) -> HashMap<String, String> {
    let mut ctx = ctx();
    if let Some(token) = token {
        ctx.headers
            .insert("authorization".to_string(), format!("Bearer {token}"));
    }
    for (name, value) in client_headers {
        ctx.headers
            .insert((*name).to_string(), (*value).to_string());
    }
    assert_continue(plugin.authenticate(&mut ctx, &consumer_index()).await);
    let mut headers = ctx.headers.clone();
    assert_continue(plugin.before_proxy(&mut ctx, &mut headers).await);
    headers
}

fn header<'a>(headers: &'a HashMap<String, String>, name: &str) -> Option<&'a str> {
    headers
        .iter()
        .find(|(key, _)| key.eq_ignore_ascii_case(name))
        .map(|(_, value)| value.as_str())
}

#[tokio::test]
async fn output_claim_headers_are_stripped_from_an_unauthenticated_request() {
    let plugin = plugin_with(json!([{"header": "x-jwt-claim-sub", "claim": "sub"}]))
        .expect("valid jwks_auth config");
    assert!(plugin.modifies_request_headers());

    // No token at all: RequestAuthentication is permissive, so the request
    // passes — but it must not carry a forged claim header to the backend.
    let headers = run(&plugin, None, &[("X-JWT-Claim-Sub", "admin")]).await;

    assert_eq!(
        header(&headers, "x-jwt-claim-sub"),
        None,
        "an unauthenticated request must not forge a declared output header: {headers:?}"
    );
}

#[tokio::test]
async fn output_claim_headers_are_overwritten_from_the_validated_claim() {
    let plugin = plugin_with(json!([{"header": "X-JWT-Claim-Sub", "claim": "sub"}]))
        .expect("valid jwks_auth config");
    let token = create_rs256_token(&json!({"sub": "alice"}), PRIVATE_KEY);

    let headers = run(&plugin, Some(&token), &[("X-JWT-Claim-Sub", "admin")]).await;

    assert_eq!(
        header(&headers, "x-jwt-claim-sub"),
        Some("alice"),
        "the validated claim must overwrite the client value: {headers:?}"
    );
    assert!(
        !headers.contains_key("X-JWT-Claim-Sub"),
        "the client's case-variant copy must not survive: {headers:?}"
    );
}

#[tokio::test]
async fn istio_scalar_claims_are_rendered_safely() {
    let plugin = plugin_with(json!([
        {"header": "x-claim-age", "claim": "age"},
        {"header": "x-claim-active", "claim": "active"},
        {"header": "x-claim-nested", "claim": "profile.email"},
    ]))
    .expect("valid jwks_auth config");
    let token = create_rs256_token(
        &json!({
            "sub": "alice",
            "age": 42,
            "active": true,
            "profile": {"email": "alice@example.test"},
        }),
        PRIVATE_KEY,
    );

    let headers = run(&plugin, Some(&token), &[]).await;

    assert_eq!(header(&headers, "x-claim-age"), Some("42"));
    assert_eq!(header(&headers, "x-claim-active"), Some("true"));
    assert_eq!(
        header(&headers, "x-claim-nested"),
        Some("alice@example.test")
    );
}

#[tokio::test]
async fn array_and_float_claims_leave_the_destination_absent() {
    let plugin = plugin_with(json!([
        {"header": "x-claim-groups", "claim": "groups"},
        {"header": "x-claim-ratio", "claim": "ratio"},
    ]))
    .expect("valid jwks_auth config");
    let token = create_rs256_token(
        &json!({
            "sub": "alice",
            "groups": ["admin", "dev"],
            "ratio": 1.5,
        }),
        PRIVATE_KEY,
    );

    let headers = run(
        &plugin,
        Some(&token),
        &[
            ("x-claim-groups", "attacker"),
            ("x-claim-ratio", "attacker"),
        ],
    )
    .await;

    assert_eq!(
        header(&headers, "x-claim-groups"),
        None,
        "array claims are unsupported by Istio ClaimToHeader: {headers:?}"
    );
    assert_eq!(
        header(&headers, "x-claim-ratio"),
        None,
        "floating-point claims are unsupported by Istio ClaimToHeader: {headers:?}"
    );
}

#[tokio::test]
async fn unusable_claims_leave_the_destination_absent() {
    let plugin = plugin_with(json!([{"header": "x-claim-value", "claim": "value"}]))
        .expect("valid jwks_auth config");

    let mut unusable_claims = vec![
        json!({"sub": "alice"}),
        json!({"sub": "alice", "value": null}),
        json!({"sub": "alice", "value": ""}),
        json!({"sub": "alice", "value": "   "}),
        json!({"sub": "alice", "value": {"nested": "x"}}),
        json!({"sub": "alice", "value": []}),
        json!({"sub": "alice", "value": [{"nested": "x"}]}),
        // A header-illegal value must be dropped, never spliced into the
        // backend request.
        json!({"sub": "alice", "value": "bad\r\nx-injected: 1"}),
    ];
    unusable_claims.push(json!({
        "sub": "alice",
        "value": "x".repeat(8 * 1024 + 1),
    }));
    for claims in unusable_claims {
        let token = create_rs256_token(&claims, PRIVATE_KEY);
        let headers = run(&plugin, Some(&token), &[("x-claim-value", "attacker")]).await;
        assert_eq!(
            header(&headers, "x-claim-value"),
            None,
            "claims {claims} must leave the destination absent, got {headers:?}"
        );
    }
}

#[tokio::test]
async fn one_claim_may_be_published_to_several_headers() {
    let plugin = plugin_with(json!([
        {"header": "x-claim-sub", "claim": "sub"},
        {"header": "x-user-id", "claim": "sub"},
    ]))
    .expect("one claim may target two headers");
    let token = create_rs256_token(&json!({"sub": "alice"}), PRIVATE_KEY);

    let headers = run(&plugin, Some(&token), &[]).await;

    assert_eq!(header(&headers, "x-claim-sub"), Some("alice"));
    assert_eq!(header(&headers, "x-user-id"), Some("alice"));
}

#[test]
fn duplicate_destination_headers_are_rejected_at_config_load() {
    let error = match plugin_with(json!([
        {"header": "x-claim-sub", "claim": "sub"},
        {"header": "X-Claim-Sub", "claim": "email"},
    ])) {
        Ok(_) => panic!("a destination asserted from two claims must be rejected"),
        Err(error) => error,
    };
    assert!(
        error.contains("more than once"),
        "expected a duplicate-destination diagnostic, got: {error}"
    );
}

#[test]
fn reserved_and_malformed_destinations_are_rejected_at_config_load() {
    for entry in [
        json!([{"header": "Authorization", "claim": "sub"}]),
        json!([{"header": "Host", "claim": "sub"}]),
        json!([{"header": "Content-Length", "claim": "sub"}]),
        json!([{"header": "Cookie", "claim": "sub"}]),
        json!([{"header": "Forwarded", "claim": "sub"}]),
        json!([{"header": "X-Forwarded-For", "claim": "sub"}]),
        json!([{"header": "X-Ferrum-Identity", "claim": "sub"}]),
        json!([{"header": "bad header", "claim": "sub"}]),
        json!([{"header": "", "claim": "sub"}]),
        json!([{"header": "x-ok", "claim": ""}]),
        json!([{"header": "x-ok", "claim": "a..b"}]),
        json!([{"header": "x-ok", "claim": "sub", "unknown": true}]),
        json!([{"claim": "sub"}]),
        json!([{"header": "x-ok"}]),
        json!({"header": "x-ok", "claim": "sub"}),
    ] {
        assert!(
            plugin_with(entry.clone()).is_err(),
            "output_claim_headers {entry} must be rejected"
        );
    }
}

#[test]
fn output_claim_headers_are_bounded_at_config_load() {
    let entries: Vec<_> = (0..17)
        .map(|index| json!({"header": format!("x-claim-{index}"), "claim": "sub"}))
        .collect();
    let error = match plugin_with(json!(entries)) {
        Ok(_) => panic!("an oversized mapping list must reject"),
        Err(error) => error,
    };
    assert!(
        error.contains("at most 16"),
        "expected a bounded-list diagnostic, got: {error}"
    );
}

#[test]
fn effective_claim_header_family_collisions_are_rejected() {
    for config in [
        json!({
            "claim_headers": {"email": "x-identity"},
            "providers": [{
                "jwks": build_rsa_jwks_from_pem(PUBLIC_KEY),
                "output_claim_headers": [{"header": "X-Identity", "claim": "sub"}],
            }],
        }),
        json!({
            "providers": [{
                "jwks": build_rsa_jwks_from_pem(PUBLIC_KEY),
                "claim_headers": {"email": "x-identity"},
                "output_claim_headers": [{"header": "X-Identity", "claim": "sub"}],
            }],
        }),
    ] {
        let error = match JwksAuth::new(&config, default_client()) {
            Ok(_) => panic!("one destination cannot use both mapping families"),
            Err(error) => error,
        };
        assert!(
            error.contains("both 'claim_headers' and 'output_claim_headers'"),
            "expected a cross-family collision diagnostic, got: {error}"
        );
    }
}
