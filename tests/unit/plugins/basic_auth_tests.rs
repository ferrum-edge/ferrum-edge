//! Tests for basic_auth plugin

use ferrum_gateway::ConsumerIndex;
use ferrum_gateway::plugins::{Plugin, RequestContext, basic_auth::BasicAuth};
use serde_json::json;

use super::plugin_utils::{assert_continue, assert_reject};

fn make_ctx() -> RequestContext {
    RequestContext::new(
        "127.0.0.1".to_string(),
        "GET".to_string(),
        "/test".to_string(),
    )
}

fn basic_header(user: &str, pass: &str) -> String {
    use base64::Engine;
    let encoded = base64::engine::general_purpose::STANDARD.encode(format!("{}:{}", user, pass));
    format!("Basic {}", encoded)
}

/// Create a consumer with a known password bcrypt hash.
fn create_basic_auth_consumer() -> ferrum_gateway::config::types::Consumer {
    use chrono::Utc;
    use serde_json::{Map, Value};
    use std::collections::HashMap;

    let hash = bcrypt::hash("password", 4).unwrap(); // cost=4 for fast tests

    let mut credentials = HashMap::new();
    let mut basicauth_creds = Map::new();
    basicauth_creds.insert("password_hash".to_string(), Value::String(hash));
    credentials.insert("basicauth".to_string(), Value::Object(basicauth_creds));

    ferrum_gateway::config::types::Consumer {
        id: "basic-consumer".to_string(),
        username: "testuser".to_string(),
        custom_id: None,
        credentials,
        created_at: Utc::now(),
        updated_at: Utc::now(),
    }
}

#[tokio::test]
async fn test_basic_auth_plugin_creation() {
    let plugin = BasicAuth::new(&json!({}));
    assert_eq!(plugin.name(), "basic_auth");
}

#[tokio::test]
async fn test_basic_auth_successful() {
    let plugin = BasicAuth::new(&json!({}));
    let consumer = create_basic_auth_consumer();
    let consumer_index = ConsumerIndex::new(&[consumer]);

    let mut ctx = make_ctx();
    // The test consumer has bcrypt hash for password "password"
    ctx.headers.insert(
        "authorization".to_string(),
        basic_header("testuser", "password"),
    );
    ctx.identified_consumer = None;

    let result = plugin.authenticate(&mut ctx, &consumer_index).await;
    assert_continue(result);
    assert!(ctx.identified_consumer.is_some());
    assert_eq!(ctx.identified_consumer.unwrap().username, "testuser");
}

#[tokio::test]
async fn test_basic_auth_wrong_password() {
    let plugin = BasicAuth::new(&json!({}));
    let consumer = create_basic_auth_consumer();
    let consumer_index = ConsumerIndex::new(&[consumer]);

    let mut ctx = make_ctx();
    ctx.headers.insert(
        "authorization".to_string(),
        basic_header("testuser", "wrongpassword"),
    );
    ctx.identified_consumer = None;

    let result = plugin.authenticate(&mut ctx, &consumer_index).await;
    assert_reject(result, Some(401));
}

#[tokio::test]
async fn test_basic_auth_wrong_username() {
    let plugin = BasicAuth::new(&json!({}));
    let consumer = create_basic_auth_consumer();
    let consumer_index = ConsumerIndex::new(&[consumer]);

    let mut ctx = make_ctx();
    ctx.headers.insert(
        "authorization".to_string(),
        basic_header("unknownuser", "password"),
    );
    ctx.identified_consumer = None;

    let result = plugin.authenticate(&mut ctx, &consumer_index).await;
    assert_reject(result, Some(401));
}

#[tokio::test]
async fn test_basic_auth_missing_header() {
    let plugin = BasicAuth::new(&json!({}));
    let consumer_index = ConsumerIndex::new(&[create_basic_auth_consumer()]);

    let mut ctx = make_ctx();
    // No authorization header
    let result = plugin.authenticate(&mut ctx, &consumer_index).await;
    assert_reject(result, Some(401));
}

#[tokio::test]
async fn test_basic_auth_invalid_scheme() {
    let plugin = BasicAuth::new(&json!({}));
    let consumer_index = ConsumerIndex::new(&[create_basic_auth_consumer()]);

    let mut ctx = make_ctx();
    ctx.headers
        .insert("authorization".to_string(), "Bearer some-token".to_string());

    let result = plugin.authenticate(&mut ctx, &consumer_index).await;
    assert_reject(result, Some(401));
}

#[tokio::test]
async fn test_basic_auth_invalid_base64() {
    let plugin = BasicAuth::new(&json!({}));
    let consumer_index = ConsumerIndex::new(&[create_basic_auth_consumer()]);

    let mut ctx = make_ctx();
    ctx.headers.insert(
        "authorization".to_string(),
        "Basic !!!not-valid-base64!!!".to_string(),
    );

    let result = plugin.authenticate(&mut ctx, &consumer_index).await;
    assert_reject(result, Some(401));
}

#[tokio::test]
async fn test_basic_auth_missing_colon_separator() {
    let plugin = BasicAuth::new(&json!({}));
    let consumer_index = ConsumerIndex::new(&[create_basic_auth_consumer()]);

    let mut ctx = make_ctx();
    use base64::Engine;
    let encoded = base64::engine::general_purpose::STANDARD.encode("nocolonhere");
    ctx.headers
        .insert("authorization".to_string(), format!("Basic {}", encoded));

    let result = plugin.authenticate(&mut ctx, &consumer_index).await;
    assert_reject(result, Some(401));
}

#[tokio::test]
async fn test_basic_auth_case_insensitive_scheme() {
    let plugin = BasicAuth::new(&json!({}));
    let consumer = create_basic_auth_consumer();
    let consumer_index = ConsumerIndex::new(&[consumer]);

    let mut ctx = make_ctx();
    // Use lowercase "basic" instead of "Basic"
    use base64::Engine;
    let encoded = base64::engine::general_purpose::STANDARD.encode("testuser:password");
    ctx.headers
        .insert("authorization".to_string(), format!("basic {}", encoded));
    ctx.identified_consumer = None;

    let result = plugin.authenticate(&mut ctx, &consumer_index).await;
    assert_continue(result);
    assert!(ctx.identified_consumer.is_some());
}

#[tokio::test]
async fn test_basic_auth_empty_consumers() {
    let plugin = BasicAuth::new(&json!({}));
    let consumer_index = ConsumerIndex::new(&[]);

    let mut ctx = make_ctx();
    ctx.headers.insert(
        "authorization".to_string(),
        basic_header("testuser", "password"),
    );

    let result = plugin.authenticate(&mut ctx, &consumer_index).await;
    assert_reject(result, Some(401));
}

#[tokio::test]
async fn test_basic_auth_password_with_colon() {
    let plugin = BasicAuth::new(&json!({}));
    // Password containing colons should work because splitn(2, ':') is used
    let consumer = create_basic_auth_consumer();
    let consumer_index = ConsumerIndex::new(&[consumer]);

    let mut ctx = make_ctx();
    // "testuser:pass:word:with:colons" should split as user="testuser", pass="pass:word:with:colons"
    use base64::Engine;
    let encoded =
        base64::engine::general_purpose::STANDARD.encode("testuser:pass:word:with:colons");
    ctx.headers
        .insert("authorization".to_string(), format!("Basic {}", encoded));
    ctx.identified_consumer = None;

    // This will fail because the password hash won't match, but the parsing should succeed
    let result = plugin.authenticate(&mut ctx, &consumer_index).await;
    assert_reject(result, Some(401));
}

#[tokio::test]
async fn test_basic_auth_bcrypt_fallback() {
    // Verify bcrypt hash verification works (the default path when HMAC is not configured)
    let plugin = BasicAuth::new(&json!({}));

    // Create a consumer with a known bcrypt hash for "mypassword"
    let hash = bcrypt::hash("mypassword", 4).unwrap(); // cost=4 for fast tests

    use chrono::Utc;
    use serde_json::{Map, Value};

    let mut credentials = std::collections::HashMap::new();
    let mut basicauth_creds = Map::new();
    basicauth_creds.insert("password_hash".to_string(), Value::String(hash));
    credentials.insert("basicauth".to_string(), Value::Object(basicauth_creds));

    let consumer = ferrum_gateway::config::types::Consumer {
        id: "bcrypt-consumer".to_string(),
        username: "bcryptuser".to_string(),
        custom_id: None,
        credentials,
        created_at: Utc::now(),
        updated_at: Utc::now(),
    };
    let consumer_index = ConsumerIndex::new(&[consumer]);

    // Correct password should succeed
    let mut ctx = make_ctx();
    ctx.headers.insert(
        "authorization".to_string(),
        basic_header("bcryptuser", "mypassword"),
    );
    ctx.identified_consumer = None;

    let result = plugin.authenticate(&mut ctx, &consumer_index).await;
    assert_continue(result);
    assert!(ctx.identified_consumer.is_some());
    assert_eq!(ctx.identified_consumer.unwrap().username, "bcryptuser");

    // Wrong password should fail
    let mut ctx2 = make_ctx();
    ctx2.headers.insert(
        "authorization".to_string(),
        basic_header("bcryptuser", "wrongpassword"),
    );
    ctx2.identified_consumer = None;

    let result2 = plugin.authenticate(&mut ctx2, &consumer_index).await;
    assert_reject(result2, Some(401));
}
