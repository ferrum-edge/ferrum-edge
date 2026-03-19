//! Tests for oauth2_auth plugin

use ferrum_gateway::ConsumerIndex;
use ferrum_gateway::plugins::{Plugin, RequestContext, oauth2_auth::OAuth2Auth};
use serde_json::json;
use std::collections::HashMap;

use super::plugin_utils::{assert_continue, assert_reject};

fn make_ctx() -> RequestContext {
    RequestContext::new(
        "127.0.0.1".to_string(),
        "GET".to_string(),
        "/test".to_string(),
    )
}

fn create_oauth2_consumer(username: &str, secret: &str) -> ferrum_gateway::config::types::Consumer {
    use chrono::Utc;
    use serde_json::{Map, Value};

    let mut credentials = HashMap::new();
    let mut oauth_creds = Map::new();
    oauth_creds.insert("secret".to_string(), Value::String(secret.to_string()));
    credentials.insert("oauth2".to_string(), Value::Object(oauth_creds));

    ferrum_gateway::config::types::Consumer {
        id: format!("{}-id", username),
        username: username.to_string(),
        custom_id: None,
        credentials,
        created_at: Utc::now(),
        updated_at: Utc::now(),
    }
}

fn create_jwt_token(claims: &serde_json::Value, secret: &str) -> String {
    use jsonwebtoken::{EncodingKey, Header, encode};
    encode(
        &Header::default(),
        claims,
        &EncodingKey::from_secret(secret.as_bytes()),
    )
    .unwrap()
}

#[tokio::test]
async fn test_oauth2_auth_plugin_creation() {
    let plugin = OAuth2Auth::new(&json!({}));
    assert_eq!(plugin.name(), "oauth2_auth");
}

#[tokio::test]
async fn test_oauth2_auth_creation_with_config() {
    let plugin = OAuth2Auth::new(&json!({
        "validation_mode": "jwks",
        "expected_issuer": "https://auth.example.com",
        "expected_audience": "my-api"
    }));
    assert_eq!(plugin.name(), "oauth2_auth");
    assert_eq!(plugin.jwks_uri(), None);
}

#[tokio::test]
async fn test_oauth2_auth_jwks_uri_config() {
    let plugin = OAuth2Auth::new(&json!({
        "jwks_uri": "https://auth.example.com/.well-known/jwks.json"
    }));
    assert_eq!(
        plugin.jwks_uri(),
        Some("https://auth.example.com/.well-known/jwks.json")
    );
}

#[tokio::test]
async fn test_oauth2_auth_jwks_mode_valid_token() {
    let plugin = OAuth2Auth::new(&json!({"validation_mode": "jwks"}));
    let consumer = create_oauth2_consumer("oauth-user", "my-oauth-secret");
    let consumer_index = ConsumerIndex::new(&[consumer]);

    let token = create_jwt_token(&json!({"sub": "oauth-user"}), "my-oauth-secret");

    let mut ctx = make_ctx();
    ctx.headers
        .insert("authorization".to_string(), format!("Bearer {}", token));
    ctx.identified_consumer = None;

    let result = plugin.authenticate(&mut ctx, &consumer_index).await;
    assert_continue(result);
    assert!(ctx.identified_consumer.is_some());
    assert_eq!(ctx.identified_consumer.unwrap().username, "oauth-user");
}

#[tokio::test]
async fn test_oauth2_auth_jwks_mode_invalid_token() {
    let plugin = OAuth2Auth::new(&json!({"validation_mode": "jwks"}));
    let consumer = create_oauth2_consumer("oauth-user", "my-oauth-secret");
    let consumer_index = ConsumerIndex::new(&[consumer]);

    let token = create_jwt_token(&json!({"sub": "oauth-user"}), "wrong-secret");

    let mut ctx = make_ctx();
    ctx.headers
        .insert("authorization".to_string(), format!("Bearer {}", token));

    let result = plugin.authenticate(&mut ctx, &consumer_index).await;
    assert_reject(result, Some(401));
}

#[tokio::test]
async fn test_oauth2_auth_missing_bearer_token() {
    let plugin = OAuth2Auth::new(&json!({}));
    let consumer_index = ConsumerIndex::new(&[create_oauth2_consumer("oauth-user", "secret")]);

    let mut ctx = make_ctx();
    // No authorization header

    let result = plugin.authenticate(&mut ctx, &consumer_index).await;
    assert_reject(result, Some(401));
}

#[tokio::test]
async fn test_oauth2_auth_non_bearer_scheme() {
    let plugin = OAuth2Auth::new(&json!({}));
    let consumer_index = ConsumerIndex::new(&[create_oauth2_consumer("oauth-user", "secret")]);

    let mut ctx = make_ctx();
    ctx.headers.insert(
        "authorization".to_string(),
        "Basic dXNlcjpwYXNz".to_string(),
    );

    let result = plugin.authenticate(&mut ctx, &consumer_index).await;
    assert_reject(result, Some(401));
}

#[tokio::test]
async fn test_oauth2_auth_introspection_mode_no_url() {
    // Introspection mode without a URL should reject
    let plugin = OAuth2Auth::new(&json!({"validation_mode": "introspection"}));
    let consumer_index = ConsumerIndex::new(&[create_oauth2_consumer("oauth-user", "secret")]);

    let token = create_jwt_token(&json!({"sub": "oauth-user"}), "secret");

    let mut ctx = make_ctx();
    ctx.headers
        .insert("authorization".to_string(), format!("Bearer {}", token));

    let result = plugin.authenticate(&mut ctx, &consumer_index).await;
    assert_reject(result, Some(401));
}

#[tokio::test]
async fn test_oauth2_auth_empty_consumers() {
    let plugin = OAuth2Auth::new(&json!({"validation_mode": "jwks"}));
    let consumer_index = ConsumerIndex::new(&[]);

    let token = create_jwt_token(&json!({"sub": "nobody"}), "any-secret");

    let mut ctx = make_ctx();
    ctx.headers
        .insert("authorization".to_string(), format!("Bearer {}", token));

    let result = plugin.authenticate(&mut ctx, &consumer_index).await;
    assert_reject(result, Some(401));
}

#[tokio::test]
async fn test_oauth2_auth_jwks_with_issuer_validation() {
    let plugin = OAuth2Auth::new(&json!({
        "validation_mode": "jwks",
        "expected_issuer": "https://auth.example.com"
    }));
    let consumer = create_oauth2_consumer("oauth-user", "my-oauth-secret");
    let consumer_index = ConsumerIndex::new(&[consumer]);

    // Token with matching issuer
    let token = create_jwt_token(
        &json!({"sub": "oauth-user", "iss": "https://auth.example.com"}),
        "my-oauth-secret",
    );

    let mut ctx = make_ctx();
    ctx.headers
        .insert("authorization".to_string(), format!("Bearer {}", token));
    ctx.identified_consumer = None;

    let result = plugin.authenticate(&mut ctx, &consumer_index).await;
    assert_continue(result);
}

#[tokio::test]
async fn test_oauth2_auth_jwks_wrong_issuer_rejected() {
    let plugin = OAuth2Auth::new(&json!({
        "validation_mode": "jwks",
        "expected_issuer": "https://auth.example.com"
    }));
    let consumer = create_oauth2_consumer("oauth-user", "my-oauth-secret");
    let consumer_index = ConsumerIndex::new(&[consumer]);

    // Token with wrong issuer
    let token = create_jwt_token(
        &json!({"sub": "oauth-user", "iss": "https://evil.example.com"}),
        "my-oauth-secret",
    );

    let mut ctx = make_ctx();
    ctx.headers
        .insert("authorization".to_string(), format!("Bearer {}", token));

    let result = plugin.authenticate(&mut ctx, &consumer_index).await;
    assert_reject(result, Some(401));
}

#[tokio::test]
async fn test_oauth2_auth_jwks_with_audience_validation() {
    let plugin = OAuth2Auth::new(&json!({
        "validation_mode": "jwks",
        "expected_audience": "my-api"
    }));
    let consumer = create_oauth2_consumer("oauth-user", "my-oauth-secret");
    let consumer_index = ConsumerIndex::new(&[consumer]);

    let token = create_jwt_token(
        &json!({"sub": "oauth-user", "aud": "my-api"}),
        "my-oauth-secret",
    );

    let mut ctx = make_ctx();
    ctx.headers
        .insert("authorization".to_string(), format!("Bearer {}", token));
    ctx.identified_consumer = None;

    let result = plugin.authenticate(&mut ctx, &consumer_index).await;
    assert_continue(result);
}

#[tokio::test]
async fn test_oauth2_auth_default_mode_is_jwks() {
    // Default validation_mode should be "jwks"
    let plugin = OAuth2Auth::new(&json!({}));
    let consumer = create_oauth2_consumer("oauth-user", "my-oauth-secret");
    let consumer_index = ConsumerIndex::new(&[consumer]);

    let token = create_jwt_token(&json!({"sub": "oauth-user"}), "my-oauth-secret");

    let mut ctx = make_ctx();
    ctx.headers
        .insert("authorization".to_string(), format!("Bearer {}", token));
    ctx.identified_consumer = None;

    let result = plugin.authenticate(&mut ctx, &consumer_index).await;
    assert_continue(result);
    assert!(ctx.identified_consumer.is_some());
}
