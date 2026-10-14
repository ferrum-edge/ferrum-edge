//! `jwks_auth` bounds how many providers one token is verified against:
//! providers are capped at admission, and a token is only tried against
//! providers pinning its exact `iss` plus providers that pin no issuer.

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use ferrum_edge::_test_support::jwks_auth_candidate_providers_for_test;
use ferrum_edge::ConsumerIndex;
use ferrum_edge::plugins::Plugin;
use ferrum_edge::plugins::jwks_auth::{JwksAuth, MAX_JWKS_CANDIDATE_PROVIDERS, MAX_JWKS_PROVIDERS};
use serde_json::{Value, json};

use super::jwks_auth_support::{
    build_rsa_jwks_from_pem, create_rs256_token, default_client, make_ctx,
};
use super::plugin_utils::{assert_continue, assert_reject};

fn inline_jwks() -> String {
    let public_key_pem = include_bytes!("../../../tests/fixtures/test_rsa_public.pem");
    build_rsa_jwks_from_pem(public_key_pem).to_string()
}

fn provider(issuer: Option<&str>, jwks: &str) -> Value {
    match issuer {
        Some(issuer) => json!({ "issuer": issuer, "jwks": jwks }),
        None => json!({ "jwks": jwks }),
    }
}

fn build(providers: Vec<Value>) -> Result<JwksAuth, String> {
    JwksAuth::new(&json!({ "providers": providers }), default_client())
}

/// An unsigned token shape: only the payload matters for provider selection.
fn unsigned_token(payload: &Value) -> String {
    let header = URL_SAFE_NO_PAD.encode(br#"{"alg":"RS256","kid":"test-key-1"}"#);
    let payload = URL_SAFE_NO_PAD.encode(payload.to_string());
    format!("{header}.{payload}.c2ln")
}

#[test]
fn provider_count_is_capped_at_admission() {
    let jwks = inline_jwks();
    let at_cap: Vec<Value> = (0..MAX_JWKS_PROVIDERS)
        .map(|i| provider(Some(&format!("https://idp{i}.example.com")), &jwks))
        .collect();
    assert!(
        build(at_cap).is_ok(),
        "{MAX_JWKS_PROVIDERS} providers must be accepted"
    );

    let over_cap: Vec<Value> = (0..=MAX_JWKS_PROVIDERS)
        .map(|i| provider(Some(&format!("https://idp{i}.example.com")), &jwks))
        .collect();
    let err = build(over_cap)
        .err()
        .expect("over-cap providers must be refused");
    assert!(err.contains("at most 64"), "unexpected error: {err}");
}

#[test]
fn providers_without_issuer_are_capped() {
    let jwks = inline_jwks();
    let at_cap: Vec<Value> = (0..MAX_JWKS_CANDIDATE_PROVIDERS)
        .map(|_| provider(None, &jwks))
        .collect();
    assert!(build(at_cap).is_ok());

    let over_cap: Vec<Value> = (0..=MAX_JWKS_CANDIDATE_PROVIDERS)
        .map(|_| provider(None, &jwks))
        .collect();
    let err = build(over_cap)
        .err()
        .expect("too many issuer-less providers");
    assert!(err.contains("omit `issuer`"), "unexpected error: {err}");
}

#[test]
fn providers_sharing_an_issuer_plus_issuerless_are_capped() {
    let jwks = inline_jwks();
    let shared = "https://shared.example.com";
    let mut providers: Vec<Value> = (0..MAX_JWKS_CANDIDATE_PROVIDERS - 2)
        .map(|_| provider(Some(shared), &jwks))
        .collect();
    providers.push(provider(None, &jwks));
    providers.push(provider(None, &jwks));
    // Many distinct issuers do not count against one realm.
    for i in 0..20 {
        providers.push(provider(
            Some(&format!("https://other{i}.example.com")),
            &jwks,
        ));
    }
    assert!(build(providers.clone()).is_ok(), "exactly at the realm cap");

    providers.push(provider(Some(shared), &jwks));
    let err = build(providers).err().expect("realm over the cap");
    assert!(
        err.contains("sharing one `issuer`"),
        "unexpected error: {err}"
    );
}

#[test]
fn verifications_per_token_are_bounded() {
    let jwks = inline_jwks();
    let mut providers: Vec<Value> = (0..60)
        .map(|i| provider(Some(&format!("https://idp{i}.example.com")), &jwks))
        .collect();
    providers.push(provider(None, &jwks));
    providers.push(provider(None, &jwks));
    let plugin = build(providers).expect("valid config");

    let cases: Vec<(String, Vec<usize>)> = vec![
        // Garbage and no-iss tokens only reach issuer-less providers.
        ("garbage".to_string(), vec![60, 61]),
        ("a.b.c".to_string(), vec![60, 61]),
        (unsigned_token(&json!({"sub": "x"})), vec![60, 61]),
        // A matching iss adds exactly that provider, tried first.
        (
            unsigned_token(&json!({"iss": "https://idp7.example.com"})),
            vec![7, 60, 61],
        ),
        // Unknown, array-valued and non-string iss never fan out.
        (
            unsigned_token(&json!({"iss": "https://unknown.example.com"})),
            vec![60, 61],
        ),
        (
            unsigned_token(
                &json!({"iss": ["https://idp1.example.com", "https://idp2.example.com"]}),
            ),
            vec![60, 61],
        ),
        (unsigned_token(&json!({"iss": 7})), vec![60, 61]),
    ];
    for (token, expected) in cases {
        let candidates = jwks_auth_candidate_providers_for_test(&plugin, &token);
        assert!(
            candidates.len() <= MAX_JWKS_CANDIDATE_PROVIDERS,
            "token {token:?} reaches {} providers",
            candidates.len()
        );
        assert_eq!(candidates, expected, "token {token:?}");
    }
}

#[tokio::test]
async fn token_is_verified_by_its_issuer_among_many_providers() {
    let private_key_pem = include_bytes!("../../../tests/fixtures/test_rsa_private.pem");
    let jwks = inline_jwks();
    let providers: Vec<Value> = (0..40)
        .map(|i| provider(Some(&format!("https://idp{i}.example.com")), &jwks))
        .collect();
    let plugin = build(providers).expect("valid config");
    plugin.warmup_jwks().await;

    let token = create_rs256_token(
        &json!({"iss": "https://idp39.example.com", "sub": "last-provider-user"}),
        private_key_pem,
    );
    let mut ctx = make_ctx();
    ctx.headers
        .insert("authorization".to_string(), format!("Bearer {token}"));
    assert_continue(
        plugin
            .authenticate(&mut ctx, &ConsumerIndex::new(&[]))
            .await,
    );
    assert_eq!(
        ctx.authenticated_identity.as_deref(),
        Some("last-provider-user")
    );

    // A correctly signed token whose iss no provider pins is not accepted by
    // trying the pinned providers anyway.
    let foreign = create_rs256_token(
        &json!({"iss": "https://foreign.example.com", "sub": "foreign"}),
        private_key_pem,
    );
    let mut ctx = make_ctx();
    ctx.headers
        .insert("authorization".to_string(), format!("Bearer {foreign}"));
    assert_reject(
        plugin
            .authenticate(&mut ctx, &ConsumerIndex::new(&[]))
            .await,
        Some(401),
    );
}

#[tokio::test]
async fn issuerless_provider_still_accepts_any_issuer() {
    let private_key_pem = include_bytes!("../../../tests/fixtures/test_rsa_private.pem");
    let jwks = inline_jwks();
    let plugin = build(vec![
        provider(Some("https://pinned.example.com"), &jwks),
        provider(None, &jwks),
    ])
    .expect("valid config");
    plugin.warmup_jwks().await;

    let token = create_rs256_token(
        &json!({"iss": "https://elsewhere.example.com", "sub": "open-user"}),
        private_key_pem,
    );
    let mut ctx = make_ctx();
    ctx.headers
        .insert("authorization".to_string(), format!("Bearer {token}"));
    assert_continue(
        plugin
            .authenticate(&mut ctx, &ConsumerIndex::new(&[]))
            .await,
    );
    assert_eq!(ctx.authenticated_identity.as_deref(), Some("open-user"));
}
