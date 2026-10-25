use ferrum_edge::ConsumerIndex;
use ferrum_edge::plugins::{Plugin, jwks_auth::JwksAuth};
use serde_json::json;

use super::jwks_auth_support::{
    build_rsa_jwks_from_pem, create_rs256_token, create_rs256_token_exact, default_client, make_ctx,
};
use super::plugin_utils::{assert_continue, assert_reject};

fn plugin_with_custom_locations() -> JwksAuth {
    let jwks = build_rsa_jwks_from_pem(include_bytes!(
        "../../../tests/fixtures/test_rsa_public.pem"
    ))
    .to_string();
    JwksAuth::new(
        &json!({
            "providers": [{
                "issuer": "https://issuer.example.com",
                "jwks": jwks,
                "from_headers": [{"name": "X-Token", "prefix": "Token "}],
                "from_params": ["access_token"]
            }]
        }),
        default_client(),
    )
    .unwrap()
}

fn token_for(subject: &str) -> String {
    token_for_issuer("https://issuer.example.com", subject)
}

fn token_for_issuer(issuer: &str, subject: &str) -> String {
    create_rs256_token(
        &json!({
            "iss": issuer,
            "sub": subject
        }),
        include_bytes!("../../../tests/fixtures/test_rsa_private.pem"),
    )
}

#[test]
fn custom_header_locations_are_registered_as_credentials() {
    let plugin = plugin_with_custom_locations();
    assert_eq!(plugin.request_headers_to_redact(), &["x-token"]);
}

#[tokio::test]
async fn custom_header_empty_prefix_accepts_raw_header_value() {
    let jwks = build_rsa_jwks_from_pem(include_bytes!(
        "../../../tests/fixtures/test_rsa_public.pem"
    ))
    .to_string();
    let plugin = JwksAuth::new(
        &json!({
            "providers": [{
                "issuer": "https://issuer.example.com",
                "jwks": jwks,
                "from_headers": [{"name": "X-Token", "prefix": ""}]
            }]
        }),
        default_client(),
    )
    .unwrap();
    let mut ctx = make_ctx();
    ctx.headers
        .insert("x-token".to_string(), token_for("header-user"));

    let result = plugin
        .authenticate(&mut ctx, &ConsumerIndex::new(&[]))
        .await;
    assert_continue(result);
    assert_eq!(ctx.authenticated_identity.as_deref(), Some("header-user"));
}

#[tokio::test]
async fn prefixless_authorization_location_skips_foreign_scheme() {
    let jwks = build_rsa_jwks_from_pem(include_bytes!(
        "../../../tests/fixtures/test_rsa_public.pem"
    ))
    .to_string();
    let plugin = JwksAuth::new(
        &json!({
            "providers": [{
                "issuer": "https://issuer.example.com",
                "jwks": jwks,
                "from_headers": [{"name": "Authorization"}]
            }]
        }),
        default_client(),
    )
    .unwrap();
    let mut ctx = make_ctx();
    ctx.headers.insert(
        "authorization".to_string(),
        "Basic dXNlcjpwYXNz".to_string(),
    );

    let result = plugin
        .authenticate(&mut ctx, &ConsumerIndex::new(&[]))
        .await;
    assert_continue(result);
    assert!(ctx.authenticated_identity.is_none());
}

#[tokio::test]
async fn custom_header_location_strips_prefix() {
    let plugin = plugin_with_custom_locations();
    let mut ctx = make_ctx();
    ctx.headers.insert(
        "x-token".to_string(),
        format!("Token {}", token_for("header-user")),
    );

    let result = plugin
        .authenticate(&mut ctx, &ConsumerIndex::new(&[]))
        .await;
    assert_continue(result);
    assert_eq!(ctx.authenticated_identity.as_deref(), Some("header-user"));
}

#[tokio::test]
async fn custom_query_param_location_extracts_token() {
    let plugin = plugin_with_custom_locations();
    assert!(
        plugin.requires_decoded_query_params(),
        "query-token extraction must ask the plugin cache to materialize decoded query params"
    );
    let mut ctx = make_ctx();
    ctx.query_params
        .insert("access_token".to_string(), token_for("query-user"));

    let result = plugin
        .authenticate(&mut ctx, &ConsumerIndex::new(&[]))
        .await;
    assert_continue(result);
    assert_eq!(ctx.authenticated_identity.as_deref(), Some("query-user"));
}

#[test]
fn custom_header_only_location_does_not_require_query_params() {
    let jwks = build_rsa_jwks_from_pem(include_bytes!(
        "../../../tests/fixtures/test_rsa_public.pem"
    ))
    .to_string();
    let plugin = JwksAuth::new(
        &json!({
            "providers": [{
                "issuer": "https://issuer.example.com",
                "jwks": jwks,
                "from_headers": [{"name": "X-Token", "prefix": "Token "}]
            }]
        }),
        default_client(),
    )
    .unwrap();

    assert!(!plugin.requires_decoded_query_params());
}

#[tokio::test]
async fn mixed_providers_keep_authorization_fallback_for_default_provider() {
    let jwks = build_rsa_jwks_from_pem(include_bytes!(
        "../../../tests/fixtures/test_rsa_public.pem"
    ))
    .to_string();
    let plugin = JwksAuth::new(
        &json!({
            "providers": [
                {
                    "issuer": "https://custom.example.com",
                    "jwks": jwks,
                    "from_headers": [{"name": "X-Token", "prefix": "Token "}]
                },
                {
                    "issuer": "https://issuer.example.com",
                    "jwks": jwks
                }
            ]
        }),
        default_client(),
    )
    .unwrap();
    let mut ctx = make_ctx();
    ctx.headers.insert(
        "authorization".to_string(),
        format!("Bearer {}", token_for("authorization-user")),
    );

    let result = plugin
        .authenticate(&mut ctx, &ConsumerIndex::new(&[]))
        .await;
    assert_continue(result);
    assert_eq!(
        ctx.authenticated_identity.as_deref(),
        Some("authorization-user")
    );
}

#[tokio::test]
async fn custom_header_missing_prefix_is_ignored() {
    let plugin = plugin_with_custom_locations();
    let mut ctx = make_ctx();
    ctx.headers
        .insert("x-token".to_string(), token_for("header-user"));

    let result = plugin
        .authenticate(&mut ctx, &ConsumerIndex::new(&[]))
        .await;
    assert_continue(result);
    assert!(ctx.authenticated_identity.is_none());
}

#[tokio::test]
async fn custom_header_missing_prefix_continues_to_later_location() {
    let plugin = plugin_with_custom_locations();
    let mut ctx = make_ctx();
    ctx.headers
        .insert("x-token".to_string(), token_for("header-user"));
    ctx.query_params
        .insert("access_token".to_string(), token_for("query-user"));

    let result = plugin
        .authenticate(&mut ctx, &ConsumerIndex::new(&[]))
        .await;
    assert_continue(result);
    assert_eq!(ctx.authenticated_identity.as_deref(), Some("query-user"));
}

#[tokio::test]
async fn custom_header_empty_token_continues_to_later_location() {
    let plugin = plugin_with_custom_locations();
    let mut ctx = make_ctx();
    ctx.headers
        .insert("x-token".to_string(), "Token ".to_string());
    ctx.query_params
        .insert("access_token".to_string(), token_for("query-user"));

    let result = plugin
        .authenticate(&mut ctx, &ConsumerIndex::new(&[]))
        .await;
    assert_continue(result);
    assert_eq!(ctx.authenticated_identity.as_deref(), Some("query-user"));
}

#[tokio::test]
async fn custom_header_token_is_stripped_when_forward_original_token_false() {
    let jwks = build_rsa_jwks_from_pem(include_bytes!(
        "../../../tests/fixtures/test_rsa_public.pem"
    ))
    .to_string();
    let plugin = JwksAuth::new(
        &json!({
            "providers": [{
                "issuer": "https://issuer.example.com",
                "jwks": jwks,
                "from_headers": [{"name": "X-Token", "prefix": "Token "}],
                "forward_original_token": false
            }]
        }),
        default_client(),
    )
    .unwrap();
    assert!(plugin.modifies_request_headers());
    let mut ctx = make_ctx();
    ctx.headers.insert(
        "x-token".to_string(),
        format!("Token {}", token_for("header-user")),
    );

    let result = plugin
        .authenticate(&mut ctx, &ConsumerIndex::new(&[]))
        .await;
    assert_continue(result);

    let mut outbound = ctx.headers.clone();
    let result = plugin.before_proxy(&mut ctx, &mut outbound).await;
    assert_continue(result);
    assert!(!outbound.contains_key("x-token"));
}

#[tokio::test]
async fn custom_query_token_marks_param_for_backend_strip() {
    let jwks = build_rsa_jwks_from_pem(include_bytes!(
        "../../../tests/fixtures/test_rsa_public.pem"
    ))
    .to_string();
    let plugin = JwksAuth::new(
        &json!({
            "providers": [{
                "issuer": "https://issuer.example.com",
                "jwks": jwks,
                "from_params": ["access_token"],
                "forward_original_token": false
            }]
        }),
        default_client(),
    )
    .unwrap();
    assert!(!plugin.modifies_request_headers());
    let mut ctx = make_ctx();
    ctx.query_params
        .insert("access_token".to_string(), token_for("query-user"));
    ctx.query_params
        .insert("safe".to_string(), "visible-to-egress-plugins".to_string());

    let result = plugin
        .authenticate(&mut ctx, &ConsumerIndex::new(&[]))
        .await;
    assert_continue(result);
    assert_eq!(ctx.authenticated_identity.as_deref(), Some("query-user"));
    assert!(
        ctx.metadata
            .contains_key("auth.strip_query_param.access_token")
    );
    assert!(
        !ctx.query_params.contains_key("access_token"),
        "query-token credentials should be removed before before_proxy egress plugins run"
    );
    assert_eq!(
        ctx.query_params.get("safe").map(String::as_str),
        Some("visible-to-egress-plugins")
    );
}

#[tokio::test]
async fn custom_location_rejects_expired_token() {
    let plugin = plugin_with_custom_locations();
    let expired = create_rs256_token_exact(
        &json!({
            "iss": "https://issuer.example.com",
            "sub": "expired-user",
            "exp": chrono::Utc::now().timestamp() - 3600
        }),
        include_bytes!("../../../tests/fixtures/test_rsa_private.pem"),
    );
    let mut ctx = make_ctx();
    ctx.headers
        .insert("x-token".to_string(), format!("Token {expired}"));

    let result = plugin
        .authenticate(&mut ctx, &ConsumerIndex::new(&[]))
        .await;
    assert_reject(result, Some(401));
}

/// An explicit `Authorization` location on one provider must not hide a
/// default-location sibling that reads the very same `Authorization: Bearer`
/// credential. Before the fix the custom-location pass returned only the
/// explicit provider, issuer routing dropped it, and the default provider was
/// never tried — a valid token got the generic 401 in either provider order.
#[tokio::test]
async fn explicit_authorization_location_keeps_default_provider_with_same_token_eligible() {
    let jwks = build_rsa_jwks_from_pem(include_bytes!(
        "../../../tests/fixtures/test_rsa_public.pem"
    ))
    .to_string();
    let explicit = json!({
        "issuer": "https://a.example.com",
        "jwks": jwks,
        "from_headers": [{"name": "Authorization"}]
    });
    let default_location = json!({
        "issuer": "https://b.example.com",
        "jwks": jwks
    });

    for providers in [
        json!([explicit.clone(), default_location.clone()]),
        json!([default_location.clone(), explicit.clone()]),
    ] {
        let plugin = JwksAuth::new(&json!({ "providers": providers }), default_client())
            .expect("explicit and default Authorization providers are a valid mix");
        let mut ctx = make_ctx();
        ctx.headers.insert(
            "authorization".to_string(),
            format!(
                "Bearer {}",
                token_for_issuer("https://b.example.com", "default-provider-user")
            ),
        );

        let result = plugin
            .authenticate(&mut ctx, &ConsumerIndex::new(&[]))
            .await;
        assert_continue(result);
        assert_eq!(
            ctx.authenticated_identity.as_deref(),
            Some("default-provider-user"),
            "the default-location provider must verify its own token: {providers}"
        );
    }
}

/// The default-location sibling is added only when `Authorization: Bearer`
/// actually carries the identical credential. A token presented solely in a
/// custom header stays scoped to the providers that read that header.
#[tokio::test]
async fn custom_header_token_does_not_reach_default_provider_without_authorization() {
    let jwks = build_rsa_jwks_from_pem(include_bytes!(
        "../../../tests/fixtures/test_rsa_public.pem"
    ))
    .to_string();
    let plugin = JwksAuth::new(
        &json!({
            "providers": [
                {
                    "issuer": "https://a.example.com",
                    "jwks": jwks,
                    "from_headers": [{"name": "X-Token"}]
                },
                {
                    "issuer": "https://b.example.com",
                    "jwks": jwks
                }
            ]
        }),
        default_client(),
    )
    .unwrap();
    let mut ctx = make_ctx();
    ctx.headers.insert(
        "x-token".to_string(),
        token_for_issuer("https://b.example.com", "custom-header-user"),
    );

    let result = plugin
        .authenticate(&mut ctx, &ConsumerIndex::new(&[]))
        .await;
    assert_reject(result, Some(401));
    assert!(ctx.authenticated_identity.is_none());
}
