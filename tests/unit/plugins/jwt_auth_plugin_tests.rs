//! Tests for jwt_auth plugin (proxy-side JWT authentication, not admin JWT)

use ferrum_edge::ConsumerIndex;
use ferrum_edge::plugins::{
    HTTP_FAMILY_PROTOCOLS, Plugin, RequestContext, jwt_auth::JwtAuth, priority,
};
use serde_json::json;

use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use chrono::Utc;
use ferrum_edge::config::types::Consumer;
use serde_json::Value;
use std::collections::HashMap;

use super::plugin_utils::{
    assert_continue, assert_reject, assert_reject_body, context_with_materialized_raw_header,
    context_with_materialized_raw_header_bytes, context_with_materialized_raw_header_lines,
    create_test_consumer,
};

fn make_ctx() -> RequestContext {
    RequestContext::new(
        "127.0.0.1".to_string(),
        "GET".to_string(),
        "/test".to_string(),
    )
}

fn create_jwt_token(claims: &serde_json::Value, secret: &str) -> String {
    let mut claims = claims.clone();
    if let Some(obj) = claims.as_object_mut() {
        obj.entry("exp")
            .or_insert_with(|| serde_json::Value::from(9_999_999_999u64));
        obj.entry("nbf")
            .or_insert_with(|| serde_json::Value::from(0u64));
    }
    create_jwt_token_exact(&claims, secret)
}

fn create_jwt_token_exact(claims: &serde_json::Value, secret: &str) -> String {
    use jsonwebtoken::{EncodingKey, Header, encode};
    encode(
        &Header::default(),
        claims,
        &EncodingKey::from_secret(secret.as_bytes()),
    )
    .unwrap()
}

#[tokio::test]
async fn test_jwt_auth_plugin_creation() {
    let plugin = JwtAuth::new(&json!({})).unwrap();
    assert_eq!(plugin.name(), "jwt_auth");
}

#[tokio::test]
async fn test_jwt_auth_skips_foreign_authorization_scheme() {
    let plugin = JwtAuth::new(&json!({})).unwrap();
    let mut ctx = make_ctx();
    ctx.headers.insert(
        "authorization".to_string(),
        "Basic dXNlcjpwYXNz".to_string(),
    );

    let result = plugin
        .authenticate(&mut ctx, &ConsumerIndex::new(&[]))
        .await;
    assert_continue(result);
}

#[tokio::test]
async fn test_jwt_auth_rejects_empty_bearer_credential() {
    let plugin = JwtAuth::new(&json!({})).unwrap();
    for value in ["Bearer", "Bearer ", "bearer \t "] {
        let mut ctx = make_ctx();
        ctx.headers
            .insert("authorization".to_string(), value.to_string());

        let result = plugin
            .authenticate(&mut ctx, &ConsumerIndex::new(&[]))
            .await;
        assert_reject(result, Some(401));
    }
}

#[test]
fn test_jwt_auth_plugin_contract() {
    let plugin = JwtAuth::new(&json!({})).unwrap();

    assert_eq!(plugin.priority(), priority::JWT_AUTH);
    assert_eq!(plugin.priority(), 1100);
    assert_eq!(plugin.supported_protocols(), HTTP_FAMILY_PROTOCOLS);
    assert!(plugin.is_auth_plugin());
    assert!(!plugin.modifies_request_headers());
    assert!(!plugin.modifies_request_body());
    assert!(!plugin.requires_request_body_before_before_proxy());
    assert!(!plugin.requires_request_body_before_authenticate());
    assert!(!plugin.needs_request_body_bytes());
    assert!(!plugin.requires_request_body_buffering());
    assert!(!plugin.requires_response_body_buffering());
    assert!(!plugin.applies_after_proxy_on_reject());
}

#[tokio::test]
async fn test_jwt_auth_creation_with_config() {
    let plugin = JwtAuth::new(&json!({
        "token_lookup": "header:X-Token",
        "consumer_claim_field": "user_id"
    }))
    .unwrap();
    assert_eq!(plugin.name(), "jwt_auth");
    assert_eq!(plugin.request_headers_to_redact(), &["x-token"]);
}

#[test]
fn test_jwt_auth_rejects_invalid_config() {
    let invalid_configs = [
        json!(null),
        json!(""),
        json!({"token_lookup": 123}),
        json!({"token_lookup": ""}),
        json!({"token_lookup": "cookie:jwt"}),
        json!({"token_lookup": "header:"}),
        json!({"token_lookup": "query:"}),
        json!({"consumer_claim_field": 123}),
        json!({"consumer_claim_field": ""}),
        json!({"require_exp": "yes"}),
        json!({"require_nbf": "yes"}),
        json!({"expected_issuer": ""}),
        json!({"expected_issuers": ["https://issuer", ""]}),
        json!({"expected_issuer": "https://issuer", "expected_issuers": ["https://issuer"]}),
        json!({"audiences": [""]}),
        json!({"leeway_secs": "60"}),
        json!({"leeway_secs": 301}),
    ];

    for config in invalid_configs {
        assert!(
            JwtAuth::new(&config).is_err(),
            "config should be rejected: {config}"
        );
    }
}

#[test]
fn test_jwt_auth_rejects_unknown_security_policy_keys() {
    for (config, unknown_key) in [
        (json!({"audience": ["payments-api"]}), "audience"),
        (
            json!({"expected_issuer_url": "https://issuer.example"}),
            "expected_issuer_url",
        ),
        (
            json!({"audiences": ["payments-api"], "__proto__": {"audiences": []}}),
            "__proto__",
        ),
    ] {
        let err = JwtAuth::new(&config)
            .err()
            .expect("unknown jwt_auth config key must fail closed");
        assert_eq!(err, format!("jwt_auth: unknown config key {unknown_key:?}"));
    }
}

#[test]
fn test_jwt_auth_accepts_every_known_config_key() {
    let plugin = JwtAuth::new(&json!({
        "token_lookup": "query:token",
        "consumer_claim_field": "client_id",
        "require_exp": true,
        "require_nbf": true,
        "expected_issuers": ["https://issuer.example"],
        "audiences": ["payments-api"],
        "leeway_secs": 30
    }))
    .expect("all documented jwt_auth config keys should be accepted");

    assert_eq!(plugin.name(), "jwt_auth");
}

#[tokio::test]
async fn test_jwt_auth_rejects_missing_exp_by_default() {
    let plugin = JwtAuth::new(&json!({})).unwrap();
    let consumer_index = ConsumerIndex::new(&[create_test_consumer()]);
    let token = create_jwt_token_exact(
        &json!({"sub": "testuser"}),
        "test-jwt-secret-0123456789abcdefghij",
    );

    let mut ctx = make_ctx();
    ctx.headers
        .insert("authorization".to_string(), format!("Bearer {}", token));

    let result = plugin.authenticate(&mut ctx, &consumer_index).await;
    assert_reject(result, Some(401));
}

#[tokio::test]
async fn test_jwt_auth_require_exp_false_allows_legacy_token_without_exp() {
    let plugin = JwtAuth::new(&json!({"require_exp": false, "require_nbf": false})).unwrap();
    let consumer_index = ConsumerIndex::new(&[create_test_consumer()]);
    let token = create_jwt_token_exact(
        &json!({"sub": "testuser"}),
        "test-jwt-secret-0123456789abcdefghij",
    );

    let mut ctx = make_ctx();
    ctx.headers
        .insert("authorization".to_string(), format!("Bearer {}", token));

    let result = plugin.authenticate(&mut ctx, &consumer_index).await;
    assert_continue(result);
}

#[tokio::test]
async fn token_missing_nbf_rejects_when_require_nbf_true() {
    let plugin = JwtAuth::new(&json!({"require_nbf": true})).unwrap();
    let consumer_index = ConsumerIndex::new(&[create_test_consumer()]);
    let token = create_jwt_token_exact(
        &json!({"sub": "testuser", "exp": 9_999_999_999u64}),
        "test-jwt-secret-0123456789abcdefghij",
    );

    let mut ctx = make_ctx();
    ctx.headers
        .insert("authorization".to_string(), format!("Bearer {}", token));

    let result = plugin.authenticate(&mut ctx, &consumer_index).await;
    assert_reject(result, Some(401));
}

#[tokio::test]
async fn token_missing_nbf_authenticates_by_default() {
    // `nbf` is optional (RFC 7519); the default config must accept a token that
    // omits it. Regression guard for require_nbf defaulting to true, which
    // rejected the (very common) nbf-less tokens with 401.
    let plugin = JwtAuth::new(&json!({})).unwrap();
    let consumer_index = ConsumerIndex::new(&[create_test_consumer()]);
    let token = create_jwt_token_exact(
        &json!({"sub": "testuser", "exp": 9_999_999_999u64}),
        "test-jwt-secret-0123456789abcdefghij",
    );

    let mut ctx = make_ctx();
    ctx.headers
        .insert("authorization".to_string(), format!("Bearer {}", token));

    let result = plugin.authenticate(&mut ctx, &consumer_index).await;
    assert_continue(result);
}

#[tokio::test]
async fn valid_token_with_expected_issuer_succeeds() {
    let plugin = JwtAuth::new(&json!({"expected_issuer": "https://issuer"})).unwrap();
    let consumer_index = ConsumerIndex::new(&[create_test_consumer()]);
    let token = create_jwt_token(
        &json!({"sub": "testuser", "iss": "https://issuer"}),
        "test-jwt-secret-0123456789abcdefghij",
    );

    let mut ctx = make_ctx();
    ctx.headers
        .insert("authorization".to_string(), format!("Bearer {}", token));

    let result = plugin.authenticate(&mut ctx, &consumer_index).await;
    assert_continue(result);
}

#[tokio::test]
async fn token_with_wrong_issuer_rejects_with_401() {
    let plugin = JwtAuth::new(&json!({"expected_issuer": "https://issuer"})).unwrap();
    let consumer_index = ConsumerIndex::new(&[create_test_consumer()]);
    let token = create_jwt_token(
        &json!({"sub": "testuser", "iss": "https://other"}),
        "test-jwt-secret-0123456789abcdefghij",
    );

    let mut ctx = make_ctx();
    ctx.headers
        .insert("authorization".to_string(), format!("Bearer {}", token));

    let result = plugin.authenticate(&mut ctx, &consumer_index).await;
    assert_reject(result, Some(401));
}

#[tokio::test]
async fn valid_token_with_matching_audience_succeeds() {
    let plugin = JwtAuth::new(&json!({"audiences": ["my-api"]})).unwrap();
    let consumer_index = ConsumerIndex::new(&[create_test_consumer()]);
    let token = create_jwt_token(
        &json!({"sub": "testuser", "aud": "my-api"}),
        "test-jwt-secret-0123456789abcdefghij",
    );

    let mut ctx = make_ctx();
    ctx.headers
        .insert("authorization".to_string(), format!("Bearer {}", token));

    let result = plugin.authenticate(&mut ctx, &consumer_index).await;
    assert_continue(result);
}

#[tokio::test]
async fn token_with_wrong_audience_rejects_with_401() {
    let plugin = JwtAuth::new(&json!({"audiences": ["my-api"]})).unwrap();
    let consumer_index = ConsumerIndex::new(&[create_test_consumer()]);
    let token = create_jwt_token(
        &json!({"sub": "testuser", "aud": "other-api"}),
        "test-jwt-secret-0123456789abcdefghij",
    );

    let mut ctx = make_ctx();
    ctx.headers
        .insert("authorization".to_string(), format!("Bearer {}", token));

    let result = plugin.authenticate(&mut ctx, &consumer_index).await;
    assert_reject(result, Some(401));
}

// Regression for finding #27: when an operator configures an expected issuer,
// a validly-signed token that simply OMITS the `iss` claim must be rejected
// (not accepted), because `set_issuer` alone only rejects a *mismatching* iss.
#[tokio::test]
async fn token_missing_issuer_rejects_when_issuer_configured() {
    let plugin = JwtAuth::new(&json!({"expected_issuer": "https://issuer"})).unwrap();
    let consumer_index = ConsumerIndex::new(&[create_test_consumer()]);
    // No `iss` claim at all.
    let token = create_jwt_token(
        &json!({"sub": "testuser"}),
        "test-jwt-secret-0123456789abcdefghij",
    );

    let mut ctx = make_ctx();
    ctx.headers
        .insert("authorization".to_string(), format!("Bearer {}", token));

    let result = plugin.authenticate(&mut ctx, &consumer_index).await;
    assert_reject(result, Some(401));
}

// Regression for finding #27: when an operator configures expected audiences,
// a validly-signed token that OMITS the `aud` claim must be rejected.
#[tokio::test]
async fn token_missing_audience_rejects_when_audience_configured() {
    let plugin = JwtAuth::new(&json!({"audiences": ["my-api"]})).unwrap();
    let consumer_index = ConsumerIndex::new(&[create_test_consumer()]);
    // No `aud` claim at all.
    let token = create_jwt_token(
        &json!({"sub": "testuser"}),
        "test-jwt-secret-0123456789abcdefghij",
    );

    let mut ctx = make_ctx();
    ctx.headers
        .insert("authorization".to_string(), format!("Bearer {}", token));

    let result = plugin.authenticate(&mut ctx, &consumer_index).await;
    assert_reject(result, Some(401));
}

// No-regression guard for finding #27: when neither issuer nor audience is
// configured, a token lacking `iss`/`aud` must still be accepted (the fix must
// only require the claims that the operator explicitly opted into).
#[tokio::test]
async fn token_missing_issuer_and_audience_succeeds_when_not_configured() {
    let plugin = JwtAuth::new(&json!({})).unwrap();
    let consumer_index = ConsumerIndex::new(&[create_test_consumer()]);
    let token = create_jwt_token(
        &json!({"sub": "testuser"}),
        "test-jwt-secret-0123456789abcdefghij",
    );

    let mut ctx = make_ctx();
    ctx.headers
        .insert("authorization".to_string(), format!("Bearer {}", token));

    let result = plugin.authenticate(&mut ctx, &consumer_index).await;
    assert_continue(result);
}

// With no audiences configured, a validly signed token that carries an `aud`
// claim was minted for some other audience and must be rejected (strict
// jsonwebtoken default, matching `jwt_verifier.rs` and the admin verifier).
// With audiences configured, a malformed `aud` that jsonwebtoken would treat
// as unparsed must still be rejected.
#[tokio::test]
async fn malformed_audience_rejects_when_audience_configured() {
    let plugin = JwtAuth::new(&json!({"audiences": ["my-api"]})).unwrap();
    let consumer_index = ConsumerIndex::new(&[create_test_consumer()]);
    for aud in [
        json!(123),
        json!({"service": "my-api"}),
        json!(["my-api", 1]),
        json!([]),
    ] {
        let token = create_jwt_token(
            &json!({"sub": "testuser", "aud": aud}),
            "test-jwt-secret-0123456789abcdefghij",
        );

        let mut ctx = make_ctx();
        ctx.headers
            .insert("authorization".to_string(), format!("Bearer {}", token));

        let result = plugin.authenticate(&mut ctx, &consumer_index).await;
        assert_reject(result, Some(401));
    }
}

#[tokio::test]
async fn token_with_audience_rejects_when_no_audience_configured() {
    let plugin = JwtAuth::new(&json!({})).unwrap();
    let consumer_index = ConsumerIndex::new(&[create_test_consumer()]);
    for aud in [
        json!("other-api"),
        json!(["other-api"]),
        json!([]),
        json!(null),
        json!(123),
        json!({"service": "other-api"}),
        json!(["other-api", 1]),
    ] {
        let token = create_jwt_token(
            &json!({"sub": "testuser", "aud": aud}),
            "test-jwt-secret-0123456789abcdefghij",
        );

        let mut ctx = make_ctx();
        ctx.headers
            .insert("authorization".to_string(), format!("Bearer {}", token));

        let result = plugin.authenticate(&mut ctx, &consumer_index).await;
        assert_reject(result, Some(401));
    }
}

#[tokio::test]
async fn leeway_allows_token_within_skew_window() {
    let plugin = JwtAuth::new(&json!({"leeway_secs": 60})).unwrap();
    let consumer_index = ConsumerIndex::new(&[create_test_consumer()]);
    let token = create_jwt_token_exact(
        &json!({
            "sub": "testuser",
            "exp": Utc::now().timestamp() - 30,
            "nbf": 0
        }),
        "test-jwt-secret-0123456789abcdefghij",
    );

    let mut ctx = make_ctx();
    ctx.headers
        .insert("authorization".to_string(), format!("Bearer {}", token));

    let result = plugin.authenticate(&mut ctx, &consumer_index).await;
    assert_continue(result);
}

#[tokio::test]
async fn test_jwt_auth_successful_with_bearer_header() {
    let plugin = JwtAuth::new(&json!({})).unwrap();
    let consumer = create_test_consumer();
    let consumer_index = ConsumerIndex::new(&[consumer]);

    let token = create_jwt_token(
        &json!({"sub": "testuser"}),
        "test-jwt-secret-0123456789abcdefghij",
    );

    let mut ctx = make_ctx();
    ctx.headers
        .insert("authorization".to_string(), format!("Bearer {}", token));
    ctx.identified_consumer = None;

    let result = plugin.authenticate(&mut ctx, &consumer_index).await;
    assert_continue(result);
    assert!(ctx.identified_consumer.is_some());
    assert_eq!(ctx.identified_consumer.unwrap().username, "testuser");
}

#[tokio::test]
async fn test_jwt_auth_successful_with_consumer_id() {
    let plugin = JwtAuth::new(&json!({})).unwrap();
    let consumer = create_test_consumer();
    let consumer_index = ConsumerIndex::new(&[consumer]);

    // Use consumer ID instead of username
    let token = create_jwt_token(
        &json!({"sub": "test-consumer"}),
        "test-jwt-secret-0123456789abcdefghij",
    );

    let mut ctx = make_ctx();
    ctx.headers
        .insert("authorization".to_string(), format!("Bearer {}", token));
    ctx.identified_consumer = None;

    let result = plugin.authenticate(&mut ctx, &consumer_index).await;
    assert_continue(result);
    assert!(ctx.identified_consumer.is_some());
}

#[tokio::test]
async fn test_jwt_auth_wrong_secret() {
    let plugin = JwtAuth::new(&json!({})).unwrap();
    let consumer = create_test_consumer();
    let consumer_index = ConsumerIndex::new(&[consumer]);

    let token = create_jwt_token(&json!({"sub": "testuser"}), "wrong-secret");

    let mut ctx = make_ctx();
    ctx.headers
        .insert("authorization".to_string(), format!("Bearer {}", token));
    ctx.identified_consumer = None;

    let result = plugin.authenticate(&mut ctx, &consumer_index).await;
    assert_reject(result, Some(401));
}

#[tokio::test]
async fn test_jwt_auth_missing_token() {
    let plugin = JwtAuth::new(&json!({})).unwrap();
    let consumer_index = ConsumerIndex::new(&[create_test_consumer()]);

    let mut ctx = make_ctx();
    // No authorization header

    let result = plugin.authenticate(&mut ctx, &consumer_index).await;
    assert_continue(result);
    assert!(ctx.identified_consumer.is_none());
}

#[tokio::test]
async fn test_jwt_auth_wrong_claim_value() {
    let plugin = JwtAuth::new(&json!({})).unwrap();
    let consumer = create_test_consumer();
    let consumer_index = ConsumerIndex::new(&[consumer]);

    // Token signed with correct secret but sub doesn't match any consumer
    let token = create_jwt_token(
        &json!({"sub": "unknown-user"}),
        "test-jwt-secret-0123456789abcdefghij",
    );

    let mut ctx = make_ctx();
    ctx.headers
        .insert("authorization".to_string(), format!("Bearer {}", token));
    ctx.identified_consumer = None;

    let result = plugin.authenticate(&mut ctx, &consumer_index).await;
    assert_reject(result, Some(401));
}

#[tokio::test]
async fn test_jwt_auth_custom_claim_field() {
    let plugin = JwtAuth::new(&json!({"consumer_claim_field": "user_id"})).unwrap();
    let consumer = create_test_consumer();
    let consumer_index = ConsumerIndex::new(&[consumer]);

    let token = create_jwt_token(
        &json!({"user_id": "testuser"}),
        "test-jwt-secret-0123456789abcdefghij",
    );

    let mut ctx = make_ctx();
    ctx.headers
        .insert("authorization".to_string(), format!("Bearer {}", token));
    ctx.identified_consumer = None;

    let result = plugin.authenticate(&mut ctx, &consumer_index).await;
    assert_continue(result);
    assert!(ctx.identified_consumer.is_some());
}

#[tokio::test]
async fn test_jwt_auth_query_param_lookup() {
    let plugin = JwtAuth::new(&json!({"token_lookup": "query:jwt"})).unwrap();
    let consumer = create_test_consumer();
    let consumer_index = ConsumerIndex::new(&[consumer]);

    let token = create_jwt_token(
        &json!({"sub": "testuser"}),
        "test-jwt-secret-0123456789abcdefghij",
    );

    let mut ctx = make_ctx();
    ctx.query_params.insert("jwt".to_string(), token);
    ctx.identified_consumer = None;

    plugin.mark_query_credentials_for_redaction(&mut ctx);
    let result = plugin.authenticate(&mut ctx, &consumer_index).await;
    assert_continue(result);
    assert!(ctx.identified_consumer.is_some());
    assert_eq!(
        ctx.metadata
            .get("auth.query_credential_param.jwt")
            .map(String::as_str),
        Some("true")
    );
}

#[tokio::test]
async fn test_jwt_auth_custom_header_lookup() {
    let plugin = JwtAuth::new(&json!({"token_lookup": "header:X-Token"})).unwrap();
    let consumer = create_test_consumer();
    let consumer_index = ConsumerIndex::new(&[consumer]);

    let token = create_jwt_token(
        &json!({"sub": "testuser"}),
        "test-jwt-secret-0123456789abcdefghij",
    );

    let mut ctx = make_ctx();
    ctx.headers.insert("x-token".to_string(), token);
    ctx.identified_consumer = None;

    let result = plugin.authenticate(&mut ctx, &consumer_index).await;
    assert_continue(result);
    assert!(ctx.identified_consumer.is_some());
}

#[tokio::test]
async fn test_jwt_auth_bearer_lowercase() {
    let plugin = JwtAuth::new(&json!({})).unwrap();
    let consumer = create_test_consumer();
    let consumer_index = ConsumerIndex::new(&[consumer]);

    let token = create_jwt_token(
        &json!({"sub": "testuser"}),
        "test-jwt-secret-0123456789abcdefghij",
    );

    let mut ctx = make_ctx();
    ctx.headers
        .insert("authorization".to_string(), format!("bearer {}", token));
    ctx.identified_consumer = None;

    let result = plugin.authenticate(&mut ctx, &consumer_index).await;
    assert_continue(result);
}

#[tokio::test]
async fn test_jwt_auth_bearer_uppercase() {
    let plugin = JwtAuth::new(&json!({})).unwrap();
    let consumer = create_test_consumer();
    let consumer_index = ConsumerIndex::new(&[consumer]);

    let token = create_jwt_token(
        &json!({"sub": "testuser"}),
        "test-jwt-secret-0123456789abcdefghij",
    );

    let mut ctx = make_ctx();
    ctx.headers
        .insert("authorization".to_string(), format!("BEARER {}", token));
    ctx.identified_consumer = None;

    let result = plugin.authenticate(&mut ctx, &consumer_index).await;
    assert_continue(result);
}

#[tokio::test]
async fn test_jwt_auth_custom_header_strips_bearer_case_insensitively() {
    let plugin = JwtAuth::new(&json!({"token_lookup": "header:X-Token"})).unwrap();
    let consumer = create_test_consumer();
    let consumer_index = ConsumerIndex::new(&[consumer]);

    let token = create_jwt_token(
        &json!({"sub": "testuser"}),
        "test-jwt-secret-0123456789abcdefghij",
    );

    let mut ctx = make_ctx();
    ctx.headers
        .insert("x-token".to_string(), format!("BeArEr {}", token));
    ctx.identified_consumer = None;

    let result = plugin.authenticate(&mut ctx, &consumer_index).await;
    assert_continue(result);
}

#[tokio::test]
async fn test_jwt_auth_empty_consumers() {
    let plugin = JwtAuth::new(&json!({})).unwrap();
    let consumer_index = ConsumerIndex::new(&[]);

    let token = create_jwt_token(
        &json!({"sub": "testuser"}),
        "test-jwt-secret-0123456789abcdefghij",
    );

    let mut ctx = make_ctx();
    ctx.headers
        .insert("authorization".to_string(), format!("Bearer {}", token));

    let result = plugin.authenticate(&mut ctx, &consumer_index).await;
    assert_reject(result, Some(401));
}

#[tokio::test]
async fn test_jwt_auth_malformed_token() {
    let plugin = JwtAuth::new(&json!({})).unwrap();
    let consumer_index = ConsumerIndex::new(&[create_test_consumer()]);

    let mut ctx = make_ctx();
    ctx.headers
        .insert("authorization".to_string(), "Bearer not.a.jwt".to_string());

    let result = plugin.authenticate(&mut ctx, &consumer_index).await;
    assert_reject(result, Some(401));
}

// ---- Multi-credential rotation tests ----

fn make_consumer_with_jwt_secrets(secrets: &[&str]) -> Consumer {
    let mut credentials = HashMap::new();
    let arr: Vec<Value> = secrets.iter().map(|s| json!({"secret": s})).collect();
    credentials.insert("jwt".to_string(), Value::Array(arr));

    Consumer {
        labels: Default::default(),
        id: "test-consumer".to_string(),
        namespace: ferrum_edge::config::types::default_namespace(),
        username: "testuser".to_string(),
        custom_id: Some("custom-123".to_string()),
        credentials,
        acl_groups: Vec::new(),
        created_at: Utc::now(),
        updated_at: Utc::now(),
    }
}

#[tokio::test]
async fn test_jwt_auth_multi_secret_old_secret_still_works() {
    let plugin = JwtAuth::new(&json!({})).unwrap();
    let consumer = make_consumer_with_jwt_secrets(&[
        "old-secret-0123456789abcdefghijklmnop",
        "new-secret-0123456789abcdefghijklmnop",
    ]);
    let consumer_index = ConsumerIndex::new(&[consumer]);

    let token = create_jwt_token(
        &json!({"sub": "testuser"}),
        "old-secret-0123456789abcdefghijklmnop",
    );
    let mut ctx = make_ctx();
    ctx.headers
        .insert("authorization".to_string(), format!("Bearer {}", token));

    let result = plugin.authenticate(&mut ctx, &consumer_index).await;
    assert_continue(result);
    assert_eq!(ctx.identified_consumer.unwrap().username, "testuser");
}

#[tokio::test]
async fn test_jwt_auth_multi_secret_new_secret_works() {
    let plugin = JwtAuth::new(&json!({})).unwrap();
    let consumer = make_consumer_with_jwt_secrets(&[
        "old-secret-0123456789abcdefghijklmnop",
        "new-secret-0123456789abcdefghijklmnop",
    ]);
    let consumer_index = ConsumerIndex::new(&[consumer]);

    let token = create_jwt_token(
        &json!({"sub": "testuser"}),
        "new-secret-0123456789abcdefghijklmnop",
    );
    let mut ctx = make_ctx();
    ctx.headers
        .insert("authorization".to_string(), format!("Bearer {}", token));

    let result = plugin.authenticate(&mut ctx, &consumer_index).await;
    assert_continue(result);
    assert_eq!(ctx.identified_consumer.unwrap().username, "testuser");
}

#[tokio::test]
async fn test_jwt_auth_multi_secret_wrong_secret_rejected() {
    let plugin = JwtAuth::new(&json!({})).unwrap();
    let consumer = make_consumer_with_jwt_secrets(&[
        "secret-a-0123456789abcdefghijklmnopqr",
        "secret-b-0123456789abcdefghijklmnopqr",
    ]);
    let consumer_index = ConsumerIndex::new(&[consumer]);

    let token = create_jwt_token(&json!({"sub": "testuser"}), "wrong-secret");
    let mut ctx = make_ctx();
    ctx.headers
        .insert("authorization".to_string(), format!("Bearer {}", token));

    let result = plugin.authenticate(&mut ctx, &consumer_index).await;
    assert_reject(result, Some(401));
}

// ---- Algorithm confusion / alg:none security regression tests ----
//
// The jsonwebtoken crate v10 does not include Algorithm::None in its enum,
// so alg:"none" tokens fail header deserialization. These tests serve as
// regression guards: if the crate or our code ever changes, they catch it.

/// Build a raw JWT string with an arbitrary header (bypassing the
/// jsonwebtoken encoder so we can forge headers the library refuses to create).
fn forge_jwt(header_json: &str, claims: &serde_json::Value, signature: &str) -> String {
    let header_b64 = URL_SAFE_NO_PAD.encode(header_json.as_bytes());
    let claims_b64 = URL_SAFE_NO_PAD.encode(serde_json::to_vec(claims).unwrap());
    format!("{}.{}.{}", header_b64, claims_b64, signature)
}

#[tokio::test]
async fn test_jwt_auth_rejects_alg_none_unsigned() {
    let plugin = JwtAuth::new(&json!({})).unwrap();
    let consumer_index = ConsumerIndex::new(&[create_test_consumer()]);

    // Forge a token with alg:"none" and an empty signature
    let token = forge_jwt(
        r#"{"alg":"none","typ":"JWT"}"#,
        &json!({"sub": "testuser", "exp": 9999999999u64}),
        "",
    );

    let mut ctx = make_ctx();
    ctx.headers
        .insert("authorization".to_string(), format!("Bearer {}", token));

    let result = plugin.authenticate(&mut ctx, &consumer_index).await;
    assert_reject(result, Some(401));
    assert!(ctx.identified_consumer.is_none());
}

#[tokio::test]
async fn test_jwt_auth_rejects_alg_none_case_variations() {
    let plugin = JwtAuth::new(&json!({})).unwrap();
    let consumer_index = ConsumerIndex::new(&[create_test_consumer()]);

    for alg in &["none", "None", "NONE", "nOnE"] {
        let header = format!(r#"{{"alg":"{}","typ":"JWT"}}"#, alg);
        let token = forge_jwt(
            &header,
            &json!({"sub": "testuser", "exp": 9999999999u64}),
            "",
        );

        let mut ctx = make_ctx();
        ctx.headers
            .insert("authorization".to_string(), format!("Bearer {}", token));

        let result = plugin.authenticate(&mut ctx, &consumer_index).await;
        assert_reject(result, Some(401));
        assert!(
            ctx.identified_consumer.is_none(),
            "alg:{} must not authenticate",
            alg
        );
    }
}

#[tokio::test]
async fn test_jwt_auth_rejects_alg_none_with_valid_consumer_secret_as_signature() {
    // An attacker might set alg:none but still attach a real HMAC signature,
    // hoping the server ignores the algorithm field and verifies anyway.
    let plugin = JwtAuth::new(&json!({})).unwrap();
    let consumer_index = ConsumerIndex::new(&[create_test_consumer()]);

    // Create a legitimately signed token to steal its signature
    let legit_token = create_jwt_token(
        &json!({"sub": "testuser", "exp": 9999999999u64}),
        "test-jwt-secret-0123456789abcdefghij",
    );
    let legit_sig = legit_token.rsplit('.').next().unwrap_or("");

    // Forge a token with alg:none but the legit signature
    let token = forge_jwt(
        r#"{"alg":"none","typ":"JWT"}"#,
        &json!({"sub": "testuser", "exp": 9999999999u64}),
        legit_sig,
    );

    let mut ctx = make_ctx();
    ctx.headers
        .insert("authorization".to_string(), format!("Bearer {}", token));

    let result = plugin.authenticate(&mut ctx, &consumer_index).await;
    assert_reject(result, Some(401));
}

#[tokio::test]
async fn test_jwt_auth_rejects_algorithm_mismatch_rs256_header_with_hmac_secret() {
    // Algorithm confusion: attacker sets alg:RS256 in header but the consumer
    // only has an HMAC secret. The library must reject the family mismatch.
    let plugin = JwtAuth::new(&json!({})).unwrap();
    let consumer_index = ConsumerIndex::new(&[create_test_consumer()]);

    let token = forge_jwt(
        r#"{"alg":"RS256","typ":"JWT"}"#,
        &json!({"sub": "testuser", "exp": 9999999999u64}),
        "fakesignature",
    );

    let mut ctx = make_ctx();
    ctx.headers
        .insert("authorization".to_string(), format!("Bearer {}", token));

    let result = plugin.authenticate(&mut ctx, &consumer_index).await;
    assert_reject(result, Some(401));
    assert!(ctx.identified_consumer.is_none());
}

#[tokio::test]
async fn test_jwt_auth_rejects_expired_token() {
    let plugin = JwtAuth::new(&json!({})).unwrap();
    let consumer_index = ConsumerIndex::new(&[create_test_consumer()]);

    // exp in the past (before the 60s leeway)
    let token = create_jwt_token(
        &json!({"sub": "testuser", "exp": 1000000000u64}),
        "test-jwt-secret-0123456789abcdefghij",
    );

    let mut ctx = make_ctx();
    ctx.headers
        .insert("authorization".to_string(), format!("Bearer {}", token));

    let result = plugin.authenticate(&mut ctx, &consumer_index).await;
    assert_reject(result, Some(401));
}

#[tokio::test]
async fn test_jwt_auth_rejects_completely_empty_signature() {
    // A properly-structured 3-part JWT with a valid HS256 header but empty signature
    let plugin = JwtAuth::new(&json!({})).unwrap();
    let consumer_index = ConsumerIndex::new(&[create_test_consumer()]);

    let token = forge_jwt(
        r#"{"alg":"HS256","typ":"JWT"}"#,
        &json!({"sub": "testuser", "exp": 9999999999u64}),
        "",
    );

    let mut ctx = make_ctx();
    ctx.headers
        .insert("authorization".to_string(), format!("Bearer {}", token));

    let result = plugin.authenticate(&mut ctx, &consumer_index).await;
    assert_reject(result, Some(401));
}

#[tokio::test]
async fn test_jwt_auth_non_ascii_custom_header_token_returns_invalid_not_missing() {
    let plugin = JwtAuth::new(&json!({"token_lookup": "header:X-Token"})).unwrap();
    let consumer_index = ConsumerIndex::new(&[create_test_consumer()]);
    let mut ctx = context_with_materialized_raw_header("X-Token", "token\u{3000}value");

    let result = plugin.authenticate(&mut ctx, &consumer_index).await;
    assert_reject_body(result, r#"{"error":"Invalid JWT token"}"#);
    assert!(ctx.identified_consumer.is_none());
}

#[tokio::test]
async fn test_jwt_auth_non_ascii_bearer_token_returns_invalid_not_missing() {
    let plugin = JwtAuth::new(&json!({})).unwrap();
    let consumer_index = ConsumerIndex::new(&[create_test_consumer()]);
    let mut ctx = context_with_materialized_raw_header(
        "Authorization",
        "Bearer \u{3000}not-a-valid-jwt-token",
    );

    let result = plugin.authenticate(&mut ctx, &consumer_index).await;
    assert_reject_body(result, r#"{"error":"Invalid JWT token"}"#);
    assert!(ctx.identified_consumer.is_none());
}

#[tokio::test]
async fn test_jwt_auth_invalid_utf8_custom_header_returns_invalid_not_missing() {
    let plugin = JwtAuth::new(&json!({"token_lookup": "header:X-Token"})).unwrap();
    let consumer_index = ConsumerIndex::new(&[create_test_consumer()]);
    let mut ctx = context_with_materialized_raw_header_bytes("X-Token", b"token\xffvalue");

    let result = plugin.authenticate(&mut ctx, &consumer_index).await;
    assert_reject_body(result, r#"{"error":"Invalid JWT token"}"#);
    assert!(ctx.identified_consumer.is_none());
}

#[tokio::test]
async fn test_jwt_auth_malformed_repeated_line_cannot_hide_behind_materialized_value() {
    let plugin = JwtAuth::new(&json!({"token_lookup": "header:X-Token"})).unwrap();
    let consumer_index = ConsumerIndex::new(&[create_test_consumer()]);
    let mut ctx = context_with_materialized_raw_header_lines(
        "X-Token",
        &[b"visible-token", b"malformed\xff-token"],
    );

    let result = plugin.authenticate(&mut ctx, &consumer_index).await;
    assert_reject_body(result, r#"{"error":"Invalid JWT token"}"#);
    assert!(ctx.identified_consumer.is_none());
}

// ────────────────────────────────────────────────────────────────────
// Issue #5020 — `token_lookup` must name a location a request can satisfy
// ────────────────────────────────────────────────────────────────────

/// `jwt_auth` is fail-closed, so a credential location no request could ever
/// carry publishes a route that answers every request `401` while `validate`,
/// the admin API, and DP/CP admission all report the configuration as good.
/// The contract mirrors `key_auth`'s `key_location` (closed by #2201).
#[test]
fn token_lookup_rejects_locations_no_request_can_satisfy() {
    for token_lookup in [
        "header:x bad",
        "header:x\ty",
        "header:x:y",
        "header:x\u{7f}y",
        "header:Authorization ",
        " header:Authorization",
        "header: Authorization",
        "query:a b",
        "query:   ",
        "query:token ",
    ] {
        let error = JwtAuth::new(&json!({"token_lookup": token_lookup}))
            .err()
            .unwrap_or_else(|| panic!("token_lookup {token_lookup:?} must be refused"));
        assert!(
            error.contains("token_lookup"),
            "unexpected error for {token_lookup:?}: {error}"
        );
    }
}

#[test]
fn token_lookup_admits_valid_header_and_query_locations() {
    for token_lookup in [
        "header:Authorization",
        "header:X-Token",
        "header:X-Tenant_Key~V2",
        "query:token",
        "query:tenant-key.v2",
    ] {
        JwtAuth::new(&json!({"token_lookup": token_lookup}))
            .unwrap_or_else(|_| panic!("token_lookup {token_lookup:?} must be admitted"));
    }
}

/// The redaction list is built from the canonical (lowercased) header name, so
/// a mixed-case configuration still redacts the field it reads.
#[test]
fn token_lookup_header_redaction_uses_the_canonical_name() {
    let config = json!({"token_lookup": "header:X-Tenant_Key~V2"});
    let plugin = JwtAuth::new(&config).expect("valid custom header location");
    assert_eq!(plugin.request_headers_to_redact(), &["x-tenant_key~v2"]);
}

// ────────────────────────────────────────────────────────────────────
// Issue #5019 — HTTP/3 query decoding parity (sibling of #2200)
// ────────────────────────────────────────────────────────────────────

/// Every frontend now materializes decoded query parameters (#6580), so this
/// no longer gates H3 decoding. A `query:` token lookup still declares that the
/// plugin decides on the query, the hint early route-total planning reads.
#[test]
fn query_token_lookup_requires_decoded_query_params() {
    for (config, expected) in [
        (json!({"token_lookup": "query:token"}), true),
        (json!({"token_lookup": "header:Authorization"}), false),
        (json!({"token_lookup": "header:X-Token"}), false),
        (json!({}), false),
    ] {
        let plugin = JwtAuth::new(&config).expect("valid token_lookup");
        assert_eq!(
            plugin.requires_decoded_query_params(),
            expected,
            "unexpected query-predicate hint for {config}"
        );
    }
}

/// The decoded view is what the plugin reads, so a percent-encoded parameter
/// name and a percent-encoded token both authenticate once H3 materializes it.
#[tokio::test]
async fn percent_encoded_query_credentials_authenticate_from_the_decoded_view() {
    let plugin = JwtAuth::new(&json!({"token_lookup": "query:token"})).unwrap();
    let consumer_index = ConsumerIndex::new(&[create_test_consumer()]);
    let token = create_jwt_token(
        &json!({"sub": "testuser"}),
        "test-jwt-secret-0123456789abcdefghij",
    );

    let mut ctx = make_ctx();
    // The decoded view HTTP/3 now materializes for this plugin: the client sent
    // `?t%6fken=<jwt with %2E for its dots>`, which H1/H2 always decoded.
    ctx.query_params.insert("token".to_string(), token);

    let result = plugin.authenticate(&mut ctx, &consumer_index).await;
    assert_continue(result);
    assert!(ctx.identified_consumer.is_some());
}

// ────────────────────────────────────────────────────────────────────
// Issue #5522: `iss` is ONE `StringOrURI` (RFC 7519 §4.1.1)
// ────────────────────────────────────────────────────────────────────

/// `jsonwebtoken` models a multi-valued issuer internally and matches `iss` by
/// set intersection, so a signed token claiming `["https://issuer", …]`
/// satisfied an exactly configured `https://issuer`. The configured issuer
/// check is exact string equality against ONE claimed issuer.
#[tokio::test]
async fn issuer_must_be_a_single_string() {
    let plugin = JwtAuth::new(&json!({"expected_issuer": "https://issuer"})).unwrap();
    let index = ConsumerIndex::new(&[create_test_consumer()]);
    let token = create_jwt_token(
        &json!({"sub": "testuser", "iss": ["https://issuer", "https://other"]}),
        "test-jwt-secret-0123456789abcdefghij",
    );
    let mut ctx = make_ctx();
    ctx.headers
        .insert("authorization".into(), format!("Bearer {token}"));

    assert_reject(plugin.authenticate(&mut ctx, &index).await, Some(401));
    assert!(ctx.identified_consumer.is_none());
    assert!(ctx.authenticated_identity.is_none());
}

/// The same contract for every other non-string JSON shape, and for a token
/// whose single array element is the configured issuer — an array of one is
/// still not a `StringOrURI`.
#[tokio::test]
async fn malformed_issuer_shapes_reject_regardless_of_content() {
    let plugin = JwtAuth::new(&json!({"expected_issuer": "https://issuer"})).unwrap();
    let index = ConsumerIndex::new(&[create_test_consumer()]);
    for issuer in [
        json!(["https://issuer"]),
        json!({"value": "https://issuer"}),
        json!(1234),
        json!(true),
        json!(null),
    ] {
        let token = create_jwt_token(
            &json!({"sub": "testuser", "iss": issuer}),
            "test-jwt-secret-0123456789abcdefghij",
        );
        let mut ctx = make_ctx();
        ctx.headers
            .insert("authorization".into(), format!("Bearer {token}"));

        assert_reject(plugin.authenticate(&mut ctx, &index).await, Some(401));
        assert!(
            ctx.identified_consumer.is_none(),
            "non-string iss must not establish a consumer: {issuer}"
        );
    }
}

/// The shape contract holds even where no issuer is configured, so an array
/// `iss` can never reach a backend as an authenticated claim. Configuring
/// several ACCEPTED issuers is an operator decision about trust; it never lets
/// one token claim more than one.
#[tokio::test]
async fn array_issuer_rejects_with_several_accepted_issuers_configured() {
    let plugin = JwtAuth::new(&json!({
        "expected_issuers": ["https://issuer", "https://second"]
    }))
    .unwrap();
    let index = ConsumerIndex::new(&[create_test_consumer()]);
    let token = create_jwt_token(
        &json!({"sub": "testuser", "iss": ["https://issuer", "https://second"]}),
        "test-jwt-secret-0123456789abcdefghij",
    );
    let mut ctx = make_ctx();
    ctx.headers
        .insert("authorization".into(), format!("Bearer {token}"));

    assert_reject(plugin.authenticate(&mut ctx, &index).await, Some(401));

    // Each accepted issuer still authenticates on its own, as a string.
    for issuer in ["https://issuer", "https://second"] {
        let token = create_jwt_token(
            &json!({"sub": "testuser", "iss": issuer}),
            "test-jwt-secret-0123456789abcdefghij",
        );
        let mut ctx = make_ctx();
        ctx.headers
            .insert("authorization".into(), format!("Bearer {token}"));
        assert_continue(plugin.authenticate(&mut ctx, &index).await);
        assert!(
            ctx.identified_consumer.is_some(),
            "accepted issuer {issuer}"
        );
    }
}

/// No-regression guard: an unconfigured issuer still admits a token that
/// carries no `iss` at all, and a plain string `iss` stays acceptable.
#[tokio::test]
async fn unconfigured_issuer_still_admits_string_and_absent_claims() {
    let plugin = JwtAuth::new(&json!({})).unwrap();
    let index = ConsumerIndex::new(&[create_test_consumer()]);
    for claims in [
        json!({"sub": "testuser"}),
        json!({"sub": "testuser", "iss": "https://anything"}),
    ] {
        let token = create_jwt_token(&claims, "test-jwt-secret-0123456789abcdefghij");
        let mut ctx = make_ctx();
        ctx.headers
            .insert("authorization".into(), format!("Bearer {token}"));
        assert_continue(plugin.authenticate(&mut ctx, &index).await);
        assert!(ctx.identified_consumer.is_some(), "claims: {claims}");
    }
}

/// With no issuer configured, an array `iss` is still a malformed registered
/// claim and must not authenticate.
#[tokio::test]
async fn array_issuer_rejects_even_with_no_issuer_configured() {
    let plugin = JwtAuth::new(&json!({})).unwrap();
    let index = ConsumerIndex::new(&[create_test_consumer()]);
    let token = create_jwt_token(
        &json!({"sub": "testuser", "iss": ["a", "b"]}),
        "test-jwt-secret-0123456789abcdefghij",
    );
    let mut ctx = make_ctx();
    ctx.headers
        .insert("authorization".into(), format!("Bearer {token}"));

    assert_reject(plugin.authenticate(&mut ctx, &index).await, Some(401));
    assert!(ctx.identified_consumer.is_none());
}

#[test]
fn configuration_diagnostics_keep_schema_and_withhold_supplied_values() {
    let canary = "'SECURITY_DIAGNOSTIC_CANARY\"`\n\\payload";
    let cases: &[(serde_json::Value, &[&str])] = &[
        (json!({(canary): true}), &["unknown config key"]),
        (
            json!({"audiences": [true]}),
            &["`audiences[0]`", "must be a string"],
        ),
        (
            json!({"leeway_secs": -8675309}),
            &["`leeway_secs`", "unsigned integer"],
        ),
    ];

    for (config, expected) in cases {
        let error = ferrum_edge::plugins::validate_plugin_config("jwt_auth", config)
            .expect_err("invalid configuration must still be rejected");
        let rendered = ferrum_edge::startup::render_startup_error(anyhow::Error::msg(error), &[]);
        for &fragment in *expected {
            assert!(
                rendered.contains(fragment),
                "missing {fragment:?}: {rendered}"
            );
        }
        for supplied in [
            "SECURITY_DIAGNOSTIC_CANARY",
            "security-diagnostic-canary",
            "8675309",
            "54321",
            "16384",
            "true",
        ] {
            assert!(
                !rendered.contains(supplied),
                "leaked {supplied:?}: {rendered}"
            );
        }
    }
}

// ---- Production-launch review fixes (jwt_auth-SOL-1/SOL-2, CLAUDE-2..6) ----

const STRONG_JWT_SECRET: &str = "strong-jwt-secret-0123456789abcdefghij";

fn consumer_with_jwt_secret(id: &str, username: &str, secret: &str) -> Consumer {
    let mut credentials = HashMap::new();
    credentials.insert("jwt".to_string(), json!([{ "secret": secret }]));
    Consumer {
        labels: Default::default(),
        id: id.to_string(),
        namespace: ferrum_edge::config::types::default_namespace(),
        username: username.to_string(),
        custom_id: None,
        credentials,
        acl_groups: Vec::new(),
        created_at: Utc::now(),
        updated_at: Utc::now(),
    }
}

fn bearer_ctx(token: &str) -> RequestContext {
    let mut ctx = make_ctx();
    ctx.headers
        .insert("authorization".to_string(), format!("Bearer {token}"));
    ctx
}

fn create_jwt_token_with_algorithm(
    claims: &serde_json::Value,
    secret: &str,
    algorithm: jsonwebtoken::Algorithm,
) -> String {
    use jsonwebtoken::{EncodingKey, Header, encode};
    encode(
        &Header::new(algorithm),
        claims,
        &EncodingKey::from_secret(secret.as_bytes()),
    )
    .unwrap()
}

/// SOL-2: a stored secret below the documented floor (reachable through an
/// out-of-band or pre-floor database row) is never used as a signing key.
#[tokio::test]
async fn stored_secret_below_the_floor_never_verifies() {
    let plugin = JwtAuth::new(&json!({})).unwrap();
    for weak in [
        "test-jwt-secret".to_string(),
        " ".repeat(32),
        format!("a{}", " ".repeat(31)),
        format!("{}x", "\t".repeat(31)),
    ] {
        let index = ConsumerIndex::new(&[consumer_with_jwt_secret("alice", "alice", &weak)]);
        let token = create_jwt_token(&json!({"sub": "alice"}), &weak);
        let mut ctx = bearer_ctx(&token);

        assert_reject_body(
            plugin.authenticate(&mut ctx, &index).await,
            r#"{"error":"Invalid JWT token"}"#,
        );
        assert!(ctx.identified_consumer.is_none(), "weak secret {weak:?}");
    }
}

/// SOL-2: a weak rotation entry is skipped while the strong entry still
/// authenticates (the load-time quarantine strips the whole credential; the
/// verifier guard is defense in depth).
#[tokio::test]
async fn strong_rotation_entry_still_verifies_beside_a_weak_one() {
    let plugin = JwtAuth::new(&json!({})).unwrap();
    let mut consumer = consumer_with_jwt_secret("alice", "alice", STRONG_JWT_SECRET);
    consumer.credentials.insert(
        "jwt".to_string(),
        json!([{"secret": "short"}, {"secret": STRONG_JWT_SECRET}]),
    );
    let index = ConsumerIndex::new(&[consumer]);

    let mut ctx = bearer_ctx(&create_jwt_token(&json!({"sub": "alice"}), "short"));
    assert_reject(plugin.authenticate(&mut ctx, &index).await, Some(401));

    let mut ctx = bearer_ctx(&create_jwt_token(
        &json!({"sub": "alice"}),
        STRONG_JWT_SECRET,
    ));
    assert_continue(plugin.authenticate(&mut ctx, &index).await);
    assert_eq!(ctx.identified_consumer.unwrap().id, "alice");
}

/// SOL-1: when two Consumers share a JWT secret, the holder of one can name
/// the other in `sub`. The load/swap quarantine strips the secret from every
/// holder, so the published index cannot authenticate the impersonation, and
/// distinct-secret Consumers keep working.
#[tokio::test]
async fn shared_secret_quarantine_blocks_cross_consumer_impersonation() {
    use ferrum_edge::config::types::GatewayConfig;

    let shared = "shared-jwt-secret-0123456789abcdefghij";
    let mut config = GatewayConfig {
        consumers: vec![
            consumer_with_jwt_secret("alice", "alice", shared),
            consumer_with_jwt_secret("eve", "eve", shared),
            consumer_with_jwt_secret("bob", "bob", STRONG_JWT_SECRET),
        ],
        ..Default::default()
    };
    assert!(config.validate_unique_consumer_credentials().is_err());

    let plugin = JwtAuth::new(&json!({})).unwrap();
    // Without the quarantine, Eve's secret signs a token naming Alice.
    let unquarantined = ConsumerIndex::new(&config.consumers);
    let forged = create_jwt_token(&json!({"sub": "alice"}), shared);
    let mut ctx = bearer_ctx(&forged);
    assert_continue(plugin.authenticate(&mut ctx, &unquarantined).await);

    assert_eq!(config.quarantine_invalid_jwt_credentials().len(), 2);
    let index = ConsumerIndex::new(&config.consumers);
    for sub in ["alice", "eve"] {
        let mut ctx = bearer_ctx(&create_jwt_token(&json!({ "sub": sub }), shared));
        assert_reject(plugin.authenticate(&mut ctx, &index).await, Some(401));
        assert!(
            ctx.identified_consumer.is_none(),
            "{sub} must not authenticate"
        );
    }
    let mut ctx = bearer_ctx(&create_jwt_token(&json!({"sub": "bob"}), STRONG_JWT_SECRET));
    assert_continue(plugin.authenticate(&mut ctx, &index).await);
    assert_eq!(ctx.identified_consumer.unwrap().id, "bob");
}

/// CLAUDE-6: the HMAC algorithm is pinned per instance and never taken from
/// the token header.
#[tokio::test]
async fn configured_hmac_algorithm_is_pinned() {
    use jsonwebtoken::Algorithm;

    let index = ConsumerIndex::new(&[consumer_with_jwt_secret(
        "alice",
        "alice",
        STRONG_JWT_SECRET,
    )]);
    let claims = json!({"sub": "alice", "exp": 9_999_999_999u64});
    let hs512 = JwtAuth::new(&json!({"algorithm": "HS512"})).unwrap();
    let hs384 = JwtAuth::new(&json!({"algorithm": "HS384"})).unwrap();
    let hs256_default = JwtAuth::new(&json!({})).unwrap();

    let token_512 = create_jwt_token_with_algorithm(&claims, STRONG_JWT_SECRET, Algorithm::HS512);
    let token_384 = create_jwt_token_with_algorithm(&claims, STRONG_JWT_SECRET, Algorithm::HS384);
    let token_256 = create_jwt_token_with_algorithm(&claims, STRONG_JWT_SECRET, Algorithm::HS256);

    let mut ctx = bearer_ctx(&token_512);
    assert_continue(hs512.authenticate(&mut ctx, &index).await);
    assert_eq!(ctx.identified_consumer.unwrap().id, "alice");
    let mut ctx = bearer_ctx(&token_384);
    assert_continue(hs384.authenticate(&mut ctx, &index).await);

    for (plugin, token) in [
        (&hs512, &token_256),
        (&hs512, &token_384),
        (&hs256_default, &token_512),
        (&hs256_default, &token_384),
    ] {
        let mut ctx = bearer_ctx(token);
        assert_reject(plugin.authenticate(&mut ctx, &index).await, Some(401));
        assert!(ctx.identified_consumer.is_none());
    }
}

#[test]
fn algorithm_config_admits_only_the_hmac_family() {
    for algorithm in ["HS256", "HS384", "HS512"] {
        assert!(JwtAuth::new(&json!({ "algorithm": algorithm })).is_ok());
    }
    for invalid in [
        json!("RS256"),
        json!("ES256"),
        json!("none"),
        json!("hs256"),
        json!(" HS256"),
        json!(""),
        json!(256),
        json!(["HS256"]),
    ] {
        assert!(
            JwtAuth::new(&json!({ "algorithm": invalid })).is_err(),
            "algorithm {invalid} must be refused"
        );
    }
    assert!(JwtAuth::new(&json!({"hide_credentials": "yes"})).is_err());
}

/// CLAUDE-5: `hide_credentials` strips a Bearer `Authorization` header before
/// forwarding, but leaves another scheme's credential alone.
#[tokio::test]
async fn hide_credentials_strips_bearer_authorization_header() {
    let plugin = JwtAuth::new(&json!({"hide_credentials": true})).unwrap();
    assert!(plugin.modifies_request_headers());
    assert!(!plugin.modifies_request_query());
    assert_eq!(
        plugin.modified_request_header_names(),
        Some(vec!["authorization".to_string()])
    );

    let index = ConsumerIndex::new(&[consumer_with_jwt_secret(
        "alice",
        "alice",
        STRONG_JWT_SECRET,
    )]);
    let token = create_jwt_token(&json!({"sub": "alice"}), STRONG_JWT_SECRET);
    let mut ctx = bearer_ctx(&token);
    assert_continue(plugin.authenticate(&mut ctx, &index).await);

    let mut headers = HashMap::new();
    headers.insert("authorization".to_string(), format!("Bearer {token}"));
    headers.insert("x-other".to_string(), "kept".to_string());
    assert_continue(plugin.before_proxy(&mut ctx, &mut headers).await);
    assert!(!headers.contains_key("authorization"));
    assert_eq!(headers.get("x-other").map(String::as_str), Some("kept"));

    // Another mechanism's scheme on the shared header is not this plugin's
    // credential.
    let mut headers = HashMap::new();
    headers.insert(
        "authorization".to_string(),
        "Basic dXNlcjpwYXNz".to_string(),
    );
    assert_continue(plugin.before_proxy(&mut ctx, &mut headers).await);
    assert_eq!(
        headers.get("authorization").map(String::as_str),
        Some("Basic dXNlcjpwYXNz")
    );
}

#[tokio::test]
async fn hide_credentials_strips_custom_header_and_query_token() {
    let header_plugin = JwtAuth::new(&json!({
        "token_lookup": "header:X-Token",
        "hide_credentials": true
    }))
    .unwrap();
    let mut ctx = make_ctx();
    let mut headers = HashMap::new();
    headers.insert("x-token".to_string(), "raw.jwt.value".to_string());
    assert_continue(header_plugin.before_proxy(&mut ctx, &mut headers).await);
    assert!(!headers.contains_key("x-token"));

    let query_plugin = JwtAuth::new(&json!({
        "token_lookup": "query:jwt",
        "hide_credentials": true
    }))
    .unwrap();
    assert!(query_plugin.modifies_request_query());
    assert!(!query_plugin.modifies_request_headers());

    let index = ConsumerIndex::new(&[consumer_with_jwt_secret(
        "alice",
        "alice",
        STRONG_JWT_SECRET,
    )]);
    let token = create_jwt_token(&json!({"sub": "alice"}), STRONG_JWT_SECRET);
    let mut ctx = make_ctx();
    ctx.query_params.insert("jwt".to_string(), token);
    ctx.query_params.insert("page".to_string(), "2".to_string());
    query_plugin.mark_query_credentials_for_redaction(&mut ctx);
    assert_eq!(
        ctx.metadata
            .get("auth.strip_query_param.jwt")
            .map(String::as_str),
        Some("true")
    );
    assert_continue(query_plugin.authenticate(&mut ctx, &index).await);
    let mut headers = HashMap::new();
    assert_continue(query_plugin.before_proxy(&mut ctx, &mut headers).await);
    assert!(!ctx.query_params.contains_key("jwt"));
    assert_eq!(ctx.query_params.get("page").map(String::as_str), Some("2"));
}

/// Default `hide_credentials: false` keeps forwarding the token so backends
/// that re-verify it are unaffected.
#[tokio::test]
async fn hide_credentials_defaults_to_forwarding_the_token() {
    let plugin = JwtAuth::new(&json!({"token_lookup": "query:jwt"})).unwrap();
    assert!(!plugin.modifies_request_headers());
    assert!(!plugin.modifies_request_query());

    let mut ctx = make_ctx();
    ctx.query_params
        .insert("jwt".to_string(), "raw.jwt.value".to_string());
    plugin.mark_query_credentials_for_redaction(&mut ctx);
    assert!(ctx.metadata.get("auth.strip_query_param.jwt").is_none());
    let mut headers = HashMap::new();
    headers.insert(
        "authorization".to_string(),
        "Bearer raw.jwt.value".to_string(),
    );
    assert_continue(plugin.before_proxy(&mut ctx, &mut headers).await);
    assert!(ctx.query_params.contains_key("jwt"));
    assert!(headers.contains_key("authorization"));

    let header_plugin = JwtAuth::new(&json!({})).unwrap();
    let mut headers = HashMap::new();
    headers.insert(
        "authorization".to_string(),
        "Bearer raw.jwt.value".to_string(),
    );
    assert_continue(header_plugin.before_proxy(&mut ctx, &mut headers).await);
    assert!(headers.contains_key("authorization"));
}

const JWT_AUTH_SOURCE: &str = include_str!("../../../src/plugins/jwt_auth.rs");

/// Each `tracing` macro invocation in the plugin source, as raw text from the
/// macro name through its closing parenthesis.
fn log_macro_invocations(source: &str) -> Vec<&str> {
    let mut invocations = Vec::new();
    for name in ["trace!(", "debug!(", "info!(", "warn!(", "error!("] {
        let mut search_from = 0;
        while let Some(offset) = source[search_from..].find(name) {
            let start = search_from + offset;
            let mut depth = 0usize;
            let mut in_string = false;
            let mut previous = '\0';
            let mut end = source.len();
            for (index, ch) in source[start..].char_indices() {
                if in_string {
                    if ch == '"' && previous != '\\' {
                        in_string = false;
                    }
                } else if ch == '"' {
                    in_string = true;
                } else if ch == '(' {
                    depth += 1;
                } else if ch == ')' {
                    depth -= 1;
                    if depth == 0 {
                        end = start + index + 1;
                        break;
                    }
                }
                previous = ch;
            }
            invocations.push(&source[start..end]);
            search_from = end;
        }
    }
    invocations
}

/// Remove string-literal contents so only the macro's arguments remain.
fn without_string_literals(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    let mut in_string = false;
    let mut previous = '\0';
    for ch in text.chars() {
        if in_string {
            if ch == '"' && previous != '\\' {
                in_string = false;
                out.push('"');
            }
        } else {
            out.push(ch);
            if ch == '"' {
                in_string = true;
            }
        }
        previous = ch;
    }
    out
}

/// CLAUDE-3: the identity claim is read from an UNVERIFIED token, so no log
/// record may interpolate it (log forging, unverified credential metadata).
#[test]
fn log_records_never_interpolate_the_unverified_identity_claim() {
    let invocations = log_macro_invocations(JWT_AUTH_SOURCE);
    assert!(
        invocations
            .iter()
            .any(|invocation| invocation.contains("no consumer found")),
        "the unknown-identity diagnostic must still exist"
    );
    for invocation in invocations {
        let arguments = without_string_literals(invocation);
        assert!(
            !arguments.contains("identity") && !arguments.contains("claims"),
            "log macro interpolates unverified token data: {invocation}"
        );
    }
}

/// CLAUDE-4: an unknown identity, and a Consumer with no eligible secret, each
/// spend one discarded verification so response timing does not reveal which
/// identities exist.
#[test]
fn unknown_identity_paths_spend_an_equalizing_verification() {
    let lookup = JWT_AUTH_SOURCE
        .find("consumer_index.find_by_identity(identity)")
        .expect("identity lookup");
    let not_found = lookup
        + JWT_AUTH_SOURCE[lookup..]
            .find("VerifyOutcome::ConsumerNotFound")
            .expect("not-found outcome");
    assert!(
        JWT_AUTH_SOURCE[lookup..not_found].contains("self.equalize_verification_work(&token)"),
        "the unknown-identity branch must run the equalizing verification"
    );
    let no_eligible = JWT_AUTH_SOURCE
        .find("if verification_attempted {")
        .expect("no-eligible-secret branch");
    let failed = no_eligible
        + JWT_AUTH_SOURCE[no_eligible..]
            .find("VerifyOutcome::VerificationFailed")
            .expect("verification-failed outcome");
    assert!(
        JWT_AUTH_SOURCE[no_eligible..failed].contains("self.equalize_verification_work(&token)"),
        "a Consumer without an eligible secret must run the equalizing verification"
    );
}

/// CLAUDE-4 behavior: an unknown identity is indistinguishable in the
/// response from a known identity with a wrong signature.
#[tokio::test]
async fn unknown_identity_and_wrong_signature_answer_identically() {
    let plugin = JwtAuth::new(&json!({})).unwrap();
    let index = ConsumerIndex::new(&[consumer_with_jwt_secret(
        "alice",
        "alice",
        STRONG_JWT_SECRET,
    )]);
    let wrong_key = "another-jwt-secret-0123456789abcdefghij";
    for sub in ["alice", "nobody"] {
        let mut ctx = bearer_ctx(&create_jwt_token(&json!({ "sub": sub }), wrong_key));
        assert_reject_body(
            plugin.authenticate(&mut ctx, &index).await,
            r#"{"error":"Invalid JWT token"}"#,
        );
    }
}
