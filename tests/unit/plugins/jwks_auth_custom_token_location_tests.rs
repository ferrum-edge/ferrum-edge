use ferrum_edge::ConsumerIndex;
use ferrum_edge::plugins::{Plugin, jwks_auth::JwksAuth};
use serde_json::json;

use super::jwks_auth_support::{
    build_rsa_jwks_from_pem, create_rs256_token, create_rs256_token_exact, default_client, make_ctx,
};
use super::plugin_utils::{
    assert_continue, assert_reject, assert_reject_body, create_test_consumer,
};

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

// ── Semicolon-aliased query tokens (issue #6579, GHSA-c259-vchc-3vgr) ──────
//
// The shared `token_extract` helpers give `jwks_auth` the same contract as
// `key_auth`: a `from_params` token that also rides behind a `;`
// sub-parameter is refused, marked for policy redaction, and (with
// `forward_original_token: false`) stripped even when another mechanism
// authenticates the request.

const AMBIGUOUS_QUERY_TOKEN_BODY: &str = r#"{"error":"Ambiguous token query parameter"}"#;

fn query_only_plugin(forward_original_token: bool) -> JwksAuth {
    let jwks = build_rsa_jwks_from_pem(include_bytes!(
        "../../../tests/fixtures/test_rsa_public.pem"
    ))
    .to_string();
    JwksAuth::new(
        &json!({
            "providers": [{
                "issuer": "https://issuer.example.com",
                "jwks": jwks,
                "from_params": ["access_token"],
                "forward_original_token": forward_original_token
            }]
        }),
        default_client(),
    )
    .unwrap()
}

fn ctx_with_raw_query(raw_query: &str) -> ferrum_edge::plugins::RequestContext {
    let mut ctx = make_ctx();
    ctx.set_raw_query_string(raw_query.to_string());
    ctx.materialize_query_params();
    ctx
}

#[tokio::test]
async fn semicolon_aliased_query_token_is_refused_in_single_auth() {
    let plugin = std::sync::Arc::new(query_only_plugin(false));
    let auth_plugins: Vec<std::sync::Arc<dyn Plugin>> = vec![plugin.clone()];
    let token = token_for("query-user");
    for raw_query in [
        // Only the alias carries the (valid) token: it must not authenticate.
        format!("carrier=;access_token={token}"),
        // A valid ordinary occurrence beside a different aliased value.
        format!("access_token={token}&carrier=;access_token=other.jwt.value"),
        // The `;` sits in the NAME, so Ferrum's name is `access_token;x`.
        "access_token;x=1&carrier=1".to_string(),
        // Percent-encoded sub-pair name.
        format!("carrier=;access%5Ftoken={token}"),
    ] {
        let mut ctx = ctx_with_raw_query(&raw_query);
        assert_reject_body(
            plugin
                .authenticate(&mut ctx, &ConsumerIndex::new(&[]))
                .await,
            AMBIGUOUS_QUERY_TOKEN_BODY,
        );
        assert!(ctx.authenticated_identity.is_none(), "{raw_query}");

        let mut ctx = ctx_with_raw_query(&raw_query);
        let (status, _, _) = ferrum_edge::proxy::run_authentication_phase(
            ferrum_edge::config::types::AuthMode::Single,
            &auth_plugins,
            &mut ctx,
            &ConsumerIndex::new(&[]),
        )
        .await
        .expect("an ambiguous query token must be rejected");
        assert_eq!(status, 401, "{raw_query}");
        assert!(ctx.authenticated_identity.is_none(), "{raw_query}");
    }

    // A `;` inside an unrelated value is not an alias.
    let mut ctx = ctx_with_raw_query(&format!("access_token={token}&carrier=a;b=c"));
    assert_continue(
        plugin
            .authenticate(&mut ctx, &ConsumerIndex::new(&[]))
            .await,
    );
    assert_eq!(ctx.authenticated_identity.as_deref(), Some("query-user"));
}

/// Another mechanism wins a multi-auth chain before `jwks_auth` runs while
/// the query token rides only behind a `;`. Discovery runs for every auth
/// instance before the chain short-circuits, so the alias is marked for
/// policy redaction and, because the provider does not forward the original
/// token, removed from the forwarded query.
#[tokio::test]
async fn semicolon_aliased_query_token_is_hidden_when_another_mechanism_wins() {
    let jwks_plugin = std::sync::Arc::new(query_only_plugin(false));
    let key_plugin = std::sync::Arc::new(
        ferrum_edge::plugins::key_auth::KeyAuth::new(&json!({})).expect("valid key auth config"),
    );
    let auth_plugins: Vec<std::sync::Arc<dyn Plugin>> =
        vec![key_plugin.clone(), jwks_plugin.clone()];
    let consumer_index = ConsumerIndex::new(&[create_test_consumer()]);
    let token = token_for("query-user");
    let mut ctx = ctx_with_raw_query(&format!("carrier=;access_token={token}&keep=1"));
    ctx.headers
        .insert("x-api-key".to_string(), "test-api-key".to_string());
    assert!(!ctx.query_params.contains_key("access_token"));

    assert!(
        ferrum_edge::proxy::run_authentication_phase(
            ferrum_edge::config::types::AuthMode::Multi,
            &auth_plugins,
            &mut ctx,
            &consumer_index,
        )
        .await
        .is_none()
    );
    assert_eq!(ctx.auth_method, Some("key_auth"));
    assert!(ctx.authenticated_identity.is_none());
    assert_eq!(
        ctx.metadata
            .get("auth.query_credential_param.access_token")
            .map(String::as_str),
        Some("true"),
        "the alias must be marked so delegated-policy payloads redact it"
    );
    assert_eq!(
        ctx.metadata
            .get("auth.strip_query_param.access_token")
            .map(String::as_str),
        Some("true")
    );

    let mut headers = ctx.headers.clone();
    assert_continue(key_plugin.before_proxy(&mut ctx, &mut headers).await);
    assert_continue(jwks_plugin.before_proxy(&mut ctx, &mut headers).await);
    let forwarded = ferrum_edge::_test_support::effective_backend_query_string_for_test(&ctx);
    assert_eq!(forwarded, "keep=1");
    assert!(!forwarded.contains(&token));
}

#[tokio::test]
async fn semicolon_aliased_query_token_respects_forward_original_token() {
    let plugin = query_only_plugin(true);
    let raw_query = "carrier=;access_token=aliased.jwt.value&keep=1";
    let mut ctx = ctx_with_raw_query(raw_query);
    plugin.mark_query_credentials_for_redaction(&mut ctx);
    // Policy redaction still applies; forwarding is the operator's choice.
    assert_eq!(
        ctx.metadata
            .get("auth.query_credential_param.access_token")
            .map(String::as_str),
        Some("true")
    );
    assert!(
        !ctx.metadata
            .contains_key("auth.strip_query_param.access_token")
    );
    assert_eq!(
        ferrum_edge::_test_support::effective_backend_query_string_for_test(&ctx),
        raw_query
    );
}

/// A `;` alias at any configured query location is terminal for the
/// instance: a valid token in another location (explicit `Authorization`, a
/// later provider's implicit `Bearer` fallback, or a provider with the
/// opposite forwarding setting) must not mask it, in either provider order.
#[tokio::test]
async fn semicolon_aliased_query_token_is_terminal_beside_a_valid_header_token() {
    let jwks = build_rsa_jwks_from_pem(include_bytes!(
        "../../../tests/fixtures/test_rsa_public.pem"
    ))
    .to_string();
    let header_and_param = json!({"providers": [{
        "issuer": "https://issuer.example.com",
        "jwks": jwks,
        "from_headers": [{"name": "Authorization"}],
        "from_params": ["access_token"]
    }]});
    let param_provider = json!({
        "issuer": "https://custom.example.com",
        "jwks": jwks,
        "from_params": ["access_token"],
        "forward_original_token": true
    });
    let fallback_provider = json!({
        "issuer": "https://issuer.example.com",
        "jwks": jwks,
        "forward_original_token": false
    });
    let configs = [
        header_and_param,
        json!({"providers": [param_provider.clone(), fallback_provider.clone()]}),
        json!({"providers": [fallback_provider, param_provider]}),
    ];
    let header = format!("Bearer {}", token_for("header-user"));
    for config in configs {
        let plugin = std::sync::Arc::new(JwksAuth::new(&config, default_client()).unwrap());
        let auth_plugins: Vec<std::sync::Arc<dyn Plugin>> = vec![plugin.clone()];
        for raw_query in [
            "carrier=;access_token=other.jwt.value",
            "access_token;x=1&carrier=1",
        ] {
            let mut ctx = ctx_with_raw_query(raw_query);
            ctx.headers
                .insert("authorization".to_string(), header.clone());
            assert_reject_body(
                plugin
                    .authenticate(&mut ctx, &ConsumerIndex::new(&[]))
                    .await,
                AMBIGUOUS_QUERY_TOKEN_BODY,
            );
            assert!(ctx.authenticated_identity.is_none(), "{config} {raw_query}");

            let mut ctx = ctx_with_raw_query(raw_query);
            ctx.headers
                .insert("authorization".to_string(), header.clone());
            let (status, _, _) = ferrum_edge::proxy::run_authentication_phase(
                ferrum_edge::config::types::AuthMode::Single,
                &auth_plugins,
                &mut ctx,
                &ConsumerIndex::new(&[]),
            )
            .await
            .expect("an ambiguous query token must be rejected");
            assert_eq!(status, 401, "{config} {raw_query}");
            assert!(ctx.authenticated_identity.is_none(), "{config} {raw_query}");
        }

        // Without the alias the header token still authenticates.
        let mut ctx = ctx_with_raw_query("carrier=a;b=c");
        ctx.headers
            .insert("authorization".to_string(), header.clone());
        assert_continue(
            plugin
                .authenticate(&mut ctx, &ConsumerIndex::new(&[]))
                .await,
        );
        assert_eq!(
            ctx.authenticated_identity.as_deref(),
            Some("header-user"),
            "{config}"
        );
    }
}
