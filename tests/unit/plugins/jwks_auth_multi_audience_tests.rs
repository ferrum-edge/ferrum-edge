use ferrum_edge::ConsumerIndex;
use ferrum_edge::plugins::{Plugin, jwks_auth::JwksAuth};
use serde_json::json;

use super::jwks_auth_support::{
    build_rsa_jwks_from_pem, create_rs256_token, default_client, make_ctx,
};
use super::plugin_utils::{assert_continue, assert_reject};

fn inline_jwks() -> String {
    build_rsa_jwks_from_pem(include_bytes!(
        "../../../tests/fixtures/test_rsa_public.pem"
    ))
    .to_string()
}

#[tokio::test]
async fn multi_audience_accepts_any_configured_audience() {
    let private_key_pem = include_bytes!("../../../tests/fixtures/test_rsa_private.pem");
    let plugin = JwksAuth::new(
        &json!({
            "providers": [{
                "issuer": "https://issuer.example.com",
                "jwks": inline_jwks(),
                "audiences": ["api-a", "api-b"]
            }]
        }),
        default_client(),
    )
    .unwrap();

    let token = create_rs256_token(
        &json!({
            "iss": "https://issuer.example.com",
            "sub": "aud-user",
            "aud": "api-b"
        }),
        private_key_pem,
    );
    let mut ctx = make_ctx();
    ctx.headers
        .insert("authorization".to_string(), format!("Bearer {token}"));

    let result = plugin
        .authenticate(&mut ctx, &ConsumerIndex::new(&[]))
        .await;
    assert_continue(result);
    assert_eq!(ctx.authenticated_identity.as_deref(), Some("aud-user"));
}

#[tokio::test]
async fn multi_audience_rejects_unconfigured_audience() {
    let private_key_pem = include_bytes!("../../../tests/fixtures/test_rsa_private.pem");
    let plugin = JwksAuth::new(
        &json!({
            "providers": [{
                "issuer": "https://issuer.example.com",
                "jwks": inline_jwks(),
                "audiences": ["api-a", "api-b"]
            }]
        }),
        default_client(),
    )
    .unwrap();

    let token = create_rs256_token(
        &json!({
            "iss": "https://issuer.example.com",
            "sub": "aud-user",
            "aud": "api-c"
        }),
        private_key_pem,
    );
    let mut ctx = make_ctx();
    ctx.headers
        .insert("authorization".to_string(), format!("Bearer {token}"));

    let result = plugin
        .authenticate(&mut ctx, &ConsumerIndex::new(&[]))
        .await;
    assert_reject(result, Some(401));
}

#[tokio::test]
async fn legacy_audience_alias_still_validates() {
    let private_key_pem = include_bytes!("../../../tests/fixtures/test_rsa_private.pem");
    let plugin = JwksAuth::new(
        &json!({
            "providers": [{
                "issuer": "https://issuer.example.com",
                "jwks": inline_jwks(),
                "audience": "legacy-api"
            }]
        }),
        default_client(),
    )
    .unwrap();

    let token = create_rs256_token(
        &json!({
            "iss": "https://issuer.example.com",
            "sub": "legacy-user",
            "aud": "legacy-api"
        }),
        private_key_pem,
    );
    let mut ctx = make_ctx();
    ctx.headers
        .insert("authorization".to_string(), format!("Bearer {token}"));

    let result = plugin
        .authenticate(&mut ctx, &ConsumerIndex::new(&[]))
        .await;
    assert_continue(result);
    assert_eq!(ctx.authenticated_identity.as_deref(), Some("legacy-user"));
}

#[tokio::test]
async fn configured_audiences_reject_token_missing_aud() {
    let private_key_pem = include_bytes!("../../../tests/fixtures/test_rsa_private.pem");
    let plugin = JwksAuth::new(
        &json!({
            "providers": [{
                "issuer": "https://issuer.example.com",
                "jwks": inline_jwks(),
                "audiences": ["orders-api"]
            }]
        }),
        default_client(),
    )
    .unwrap();

    let token = create_rs256_token(
        &json!({
            "iss": "https://issuer.example.com",
            "sub": "aud-user"
        }),
        private_key_pem,
    );
    let mut ctx = make_ctx();
    ctx.headers
        .insert("authorization".to_string(), format!("Bearer {token}"));

    let result = plugin
        .authenticate(&mut ctx, &ConsumerIndex::new(&[]))
        .await;
    assert_reject(result, Some(401));
    assert!(ctx.authenticated_identity.is_none());
}

#[tokio::test]
async fn configured_audiences_accept_matching_array_aud() {
    let private_key_pem = include_bytes!("../../../tests/fixtures/test_rsa_private.pem");
    let plugin = JwksAuth::new(
        &json!({
            "providers": [{
                "issuer": "https://issuer.example.com",
                "jwks": inline_jwks(),
                "audiences": ["orders-api"]
            }]
        }),
        default_client(),
    )
    .unwrap();

    let token = create_rs256_token(
        &json!({
            "iss": "https://issuer.example.com",
            "sub": "aud-user",
            "aud": ["orders-api", "other-api"]
        }),
        private_key_pem,
    );
    let mut ctx = make_ctx();
    ctx.headers
        .insert("authorization".to_string(), format!("Bearer {token}"));

    let result = plugin
        .authenticate(&mut ctx, &ConsumerIndex::new(&[]))
        .await;
    assert_continue(result);
    assert_eq!(ctx.authenticated_identity.as_deref(), Some("aud-user"));
}

#[tokio::test]
async fn configured_issuer_rejects_token_missing_iss() {
    let private_key_pem = include_bytes!("../../../tests/fixtures/test_rsa_private.pem");
    let plugin = JwksAuth::new(
        &json!({
            "providers": [{
                "issuer": "https://issuer.example.com",
                "jwks": inline_jwks(),
                "audiences": ["orders-api"]
            }]
        }),
        default_client(),
    )
    .unwrap();

    let token = create_rs256_token(
        &json!({
            "sub": "iss-user",
            "aud": "orders-api"
        }),
        private_key_pem,
    );
    let mut ctx = make_ctx();
    ctx.headers
        .insert("authorization".to_string(), format!("Bearer {token}"));

    let result = plugin
        .authenticate(&mut ctx, &ConsumerIndex::new(&[]))
        .await;
    assert_reject(result, Some(401));
}

#[tokio::test]
async fn configured_issuer_rejects_mismatch_and_accepts_exact() {
    let private_key_pem = include_bytes!("../../../tests/fixtures/test_rsa_private.pem");
    let plugin = JwksAuth::new(
        &json!({
            "providers": [{
                "issuer": "https://issuer.example.com",
                "jwks": inline_jwks()
            }]
        }),
        default_client(),
    )
    .unwrap();

    let mismatch = create_rs256_token(
        &json!({
            "iss": "https://other.example.com",
            "sub": "iss-user"
        }),
        private_key_pem,
    );
    let mut mismatch_ctx = make_ctx();
    mismatch_ctx
        .headers
        .insert("authorization".to_string(), format!("Bearer {mismatch}"));
    let mismatch_result = plugin
        .authenticate(&mut mismatch_ctx, &ConsumerIndex::new(&[]))
        .await;
    assert_reject(mismatch_result, Some(401));

    let matching = create_rs256_token(
        &json!({
            "iss": "https://issuer.example.com",
            "sub": "iss-user"
        }),
        private_key_pem,
    );
    let mut matching_ctx = make_ctx();
    matching_ctx
        .headers
        .insert("authorization".to_string(), format!("Bearer {matching}"));
    let matching_result = plugin
        .authenticate(&mut matching_ctx, &ConsumerIndex::new(&[]))
        .await;
    assert_continue(matching_result);
    assert_eq!(
        matching_ctx.authenticated_identity.as_deref(),
        Some("iss-user")
    );
}

#[tokio::test]
async fn unconfigured_audiences_keep_jsonwebtoken_aud_default() {
    // Deliberate: with no provider audience restriction, tokens that omit
    // `aud` still authenticate, but a token that *carries* `aud` is rejected
    // because no acceptable audience is configured (RFC 7519 §4.1.3).
    let private_key_pem = include_bytes!("../../../tests/fixtures/test_rsa_private.pem");
    let plugin = JwksAuth::new(
        &json!({
            "providers": [{
                "issuer": "https://issuer.example.com",
                "jwks": inline_jwks()
            }]
        }),
        default_client(),
    )
    .unwrap();

    let without_aud = create_rs256_token(
        &json!({
            "iss": "https://issuer.example.com",
            "sub": "no-aud-user"
        }),
        private_key_pem,
    );
    let mut without_ctx = make_ctx();
    without_ctx
        .headers
        .insert("authorization".to_string(), format!("Bearer {without_aud}"));
    let without_result = plugin
        .authenticate(&mut without_ctx, &ConsumerIndex::new(&[]))
        .await;
    assert_continue(without_result);
    assert_eq!(
        without_ctx.authenticated_identity.as_deref(),
        Some("no-aud-user")
    );

    let with_aud = create_rs256_token(
        &json!({
            "iss": "https://issuer.example.com",
            "sub": "aud-user",
            "aud": "orders-api"
        }),
        private_key_pem,
    );
    let mut with_ctx = make_ctx();
    with_ctx
        .headers
        .insert("authorization".to_string(), format!("Bearer {with_aud}"));
    let with_result = plugin
        .authenticate(&mut with_ctx, &ConsumerIndex::new(&[]))
        .await;
    assert_reject(with_result, Some(401));
}

/// With no audience configured, malformed `aud` values that jsonwebtoken
/// treats as absent or unparsed (null, number, object, mixed array) are still
/// rejected at the verified-claims boundary in `jwt_verifier`.
#[tokio::test]
async fn unconfigured_audiences_reject_malformed_aud_shapes() {
    let private_key_pem = include_bytes!("../../../tests/fixtures/test_rsa_private.pem");
    let plugin = JwksAuth::new(
        &json!({
            "providers": [{
                "issuer": "https://issuer.example.com",
                "jwks": inline_jwks()
            }]
        }),
        default_client(),
    )
    .unwrap();

    for aud in [
        json!(null),
        json!(123),
        json!({"service": "orders-api"}),
        json!(["orders-api", 1]),
    ] {
        let token = create_rs256_token(
            &json!({
                "iss": "https://issuer.example.com",
                "sub": "aud-user",
                "aud": aud
            }),
            private_key_pem,
        );
        let mut ctx = make_ctx();
        ctx.headers
            .insert("authorization".to_string(), format!("Bearer {token}"));
        let result = plugin
            .authenticate(&mut ctx, &ConsumerIndex::new(&[]))
            .await;
        assert_reject(result, Some(401));
    }
}
