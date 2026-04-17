//! Tests for key_auth plugin

use ferrum_edge::ConsumerIndex;
use ferrum_edge::plugins::{Plugin, key_auth::KeyAuth};
use serde_json::json;

use super::plugin_utils::{
    assert_continue, assert_reject, create_test_consumer, create_test_context,
};

#[tokio::test]
async fn test_key_auth_plugin_creation() {
    let config = json!({
        "key_location": "header:X-API-Key"
    });
    let plugin = KeyAuth::new(&config).unwrap();
    assert_eq!(plugin.name(), "key_auth");
}

#[tokio::test]
async fn test_key_auth_plugin_default_config() {
    let config = json!({});
    let plugin = KeyAuth::new(&config).unwrap();
    assert_eq!(plugin.name(), "key_auth");
}

#[tokio::test]
async fn test_key_auth_plugin_successful_auth() {
    let config = json!({
        "key_location": "header:X-API-Key"
    });
    let plugin = KeyAuth::new(&config).unwrap();

    let consumer = create_test_consumer();
    let consumer_index = ConsumerIndex::new(&[consumer]);

    // Test successful authentication
    let mut valid_ctx = create_test_context();
    valid_ctx
        .headers
        .insert("X-API-Key".to_string(), "test-api-key".to_string());

    let result = plugin.authenticate(&mut valid_ctx, &consumer_index).await;
    assert_continue(result);
    assert!(valid_ctx.identified_consumer.is_some());
}

#[tokio::test]
async fn test_key_auth_plugin_missing_key() {
    let config = json!({
        "key_location": "header:X-API-Key"
    });
    let plugin = KeyAuth::new(&config).unwrap();

    let consumer = create_test_consumer();
    let consumer_index = ConsumerIndex::new(&[consumer]);

    // Test failed authentication with missing key
    let mut invalid_ctx = create_test_context();
    invalid_ctx.headers.remove("X-API-Key");

    let result = plugin.authenticate(&mut invalid_ctx, &consumer_index).await;
    assert_reject(result, Some(401));
}

#[tokio::test]
async fn test_key_auth_plugin_invalid_key() {
    let config = json!({
        "key_location": "header:X-API-Key"
    });
    let plugin = KeyAuth::new(&config).unwrap();

    let consumer = create_test_consumer();
    let consumer_index = ConsumerIndex::new(&[consumer]);

    // Test failed authentication with invalid key
    let mut invalid_ctx = create_test_context();
    invalid_ctx
        .headers
        .insert("X-API-Key".to_string(), "invalid-key".to_string());

    let result = plugin.authenticate(&mut invalid_ctx, &consumer_index).await;
    assert_reject(result, Some(401));
}

#[tokio::test]
async fn test_key_auth_plugin_query_parameter() {
    let config = json!({
        "key_location": "query:api_key"
    });
    let plugin = KeyAuth::new(&config).unwrap();

    let consumer = create_test_consumer();
    let consumer_index = ConsumerIndex::new(&[consumer]);

    // Test successful authentication via query parameter
    let mut valid_ctx = create_test_context();
    valid_ctx.headers.remove("X-API-Key");
    valid_ctx.headers.remove("x-api-key");
    valid_ctx.identified_consumer = None;
    valid_ctx
        .query_params
        .insert("api_key".to_string(), "test-api-key".to_string());

    let result = plugin.authenticate(&mut valid_ctx, &consumer_index).await;
    assert_continue(result);
    assert!(valid_ctx.identified_consumer.is_some());
}

#[tokio::test]
async fn test_key_auth_empty_key_in_header_is_rejected() {
    let config = json!({
        "key_location": "header:X-API-Key"
    });
    let plugin = KeyAuth::new(&config).unwrap();

    let consumer = create_test_consumer();
    let consumer_index = ConsumerIndex::new(&[consumer]);

    let mut ctx = create_test_context();
    ctx.headers.insert("X-API-Key".to_string(), "".to_string());
    ctx.identified_consumer = None;

    let result = plugin.authenticate(&mut ctx, &consumer_index).await;
    assert_reject(result, Some(401));
}

#[tokio::test]
async fn test_key_auth_whitespace_key_is_rejected() {
    let config = json!({
        "key_location": "header:X-API-Key"
    });
    let plugin = KeyAuth::new(&config).unwrap();

    let consumer = create_test_consumer();
    let consumer_index = ConsumerIndex::new(&[consumer]);

    let mut ctx = create_test_context();
    ctx.headers
        .insert("X-API-Key".to_string(), "   ".to_string());
    ctx.identified_consumer = None;

    let result = plugin.authenticate(&mut ctx, &consumer_index).await;
    assert_reject(result, Some(401));
}

#[tokio::test]
async fn test_key_auth_case_insensitive_header_lookup() {
    let config = json!({
        "key_location": "header:X-API-Key"
    });
    let plugin = KeyAuth::new(&config).unwrap();

    let consumer = create_test_consumer();
    let consumer_index = ConsumerIndex::new(&[consumer]);

    // Key lookup does lowercase fallback — test with lowercase header
    let mut ctx = create_test_context();
    ctx.headers.remove("X-API-Key");
    ctx.headers
        .insert("x-api-key".to_string(), "test-api-key".to_string());
    ctx.identified_consumer = None;

    let result = plugin.authenticate(&mut ctx, &consumer_index).await;
    assert_continue(result);
    assert!(ctx.identified_consumer.is_some());
}

#[tokio::test]
async fn test_key_auth_missing_query_param() {
    let config = json!({
        "key_location": "query:apikey"
    });
    let plugin = KeyAuth::new(&config).unwrap();

    let consumer = create_test_consumer();
    let consumer_index = ConsumerIndex::new(&[consumer]);

    let mut ctx = create_test_context();
    ctx.query_params.clear();
    ctx.headers.remove("X-API-Key");
    ctx.headers.remove("x-api-key");
    ctx.identified_consumer = None;

    let result = plugin.authenticate(&mut ctx, &consumer_index).await;
    assert_reject(result, Some(401));
}

#[tokio::test]
async fn test_key_auth_custom_header_name() {
    let config = json!({
        "key_location": "header:Authorization-Token"
    });
    let plugin = KeyAuth::new(&config).unwrap();

    let consumer = create_test_consumer();
    let consumer_index = ConsumerIndex::new(&[consumer]);

    let mut ctx = create_test_context();
    ctx.headers.insert(
        "Authorization-Token".to_string(),
        "test-api-key".to_string(),
    );
    ctx.identified_consumer = None;

    let result = plugin.authenticate(&mut ctx, &consumer_index).await;
    assert_continue(result);
}

#[tokio::test]
async fn test_key_auth_multiple_consumers_correct_match() {
    let config = json!({
        "key_location": "header:X-API-Key"
    });
    let plugin = KeyAuth::new(&config).unwrap();

    // Create two consumers with different keys
    let mut consumer1 = create_test_consumer();
    consumer1.id = "consumer-1".to_string();
    consumer1.username = "user1".to_string();
    let mut keyauth1 = serde_json::Map::new();
    keyauth1.insert(
        "key".to_string(),
        serde_json::Value::String("key-one".to_string()),
    );
    consumer1
        .credentials
        .insert("keyauth".to_string(), serde_json::Value::Object(keyauth1));

    let mut consumer2 = create_test_consumer();
    consumer2.id = "consumer-2".to_string();
    consumer2.username = "user2".to_string();
    let mut keyauth2 = serde_json::Map::new();
    keyauth2.insert(
        "key".to_string(),
        serde_json::Value::String("key-two".to_string()),
    );
    consumer2
        .credentials
        .insert("keyauth".to_string(), serde_json::Value::Object(keyauth2));

    let consumer_index = ConsumerIndex::new(&[consumer1, consumer2]);

    // Authenticate with consumer2's key
    let mut ctx = create_test_context();
    ctx.headers
        .insert("X-API-Key".to_string(), "key-two".to_string());
    ctx.identified_consumer = None;

    let result = plugin.authenticate(&mut ctx, &consumer_index).await;
    assert_continue(result);
    assert_eq!(
        ctx.identified_consumer.as_ref().unwrap().username,
        "user2",
        "Should match the correct consumer"
    );
}

#[tokio::test]
async fn test_key_auth_fallback_default_header() {
    // When key_location has unknown prefix, falls back to x-api-key / X-API-Key
    let config = json!({
        "key_location": "cookie:token"
    });
    let plugin = KeyAuth::new(&config).unwrap();

    let consumer = create_test_consumer();
    let consumer_index = ConsumerIndex::new(&[consumer]);

    let mut ctx = create_test_context();
    ctx.headers
        .insert("x-api-key".to_string(), "test-api-key".to_string());
    ctx.identified_consumer = None;

    let result = plugin.authenticate(&mut ctx, &consumer_index).await;
    assert_continue(result);
}

#[tokio::test]
async fn test_key_auth_empty_key_does_not_match_any_consumer() {
    // Defense in depth: even if a consumer was somehow registered with an
    // empty `key` value, an empty header value must not authenticate as
    // that consumer. The plugin short-circuits empty/whitespace keys
    // before consulting the consumer index.
    use chrono::Utc;
    use ferrum_edge::config::types::{Consumer, default_namespace};
    use serde_json::{Map, Value};
    use std::collections::HashMap;

    let config = json!({"key_location": "header:X-API-Key"});
    let plugin = KeyAuth::new(&config).unwrap();

    // Build a consumer with empty key (simulates misconfiguration).
    let mut keyauth = Map::new();
    keyauth.insert("key".to_string(), Value::String("".to_string()));
    let mut credentials = HashMap::new();
    credentials.insert("keyauth".to_string(), Value::Object(keyauth));
    let consumer = Consumer {
        id: "empty-key-consumer".to_string(),
        namespace: default_namespace(),
        username: "ghost".to_string(),
        custom_id: None,
        credentials,
        acl_groups: Vec::new(),
        created_at: Utc::now(),
        updated_at: Utc::now(),
    };
    let consumer_index = ConsumerIndex::new(&[consumer]);

    let mut ctx = create_test_context();
    ctx.headers.insert("X-API-Key".to_string(), "".to_string());
    ctx.identified_consumer = None;

    let result = plugin.authenticate(&mut ctx, &consumer_index).await;
    assert_reject(result, Some(401));
    assert!(ctx.identified_consumer.is_none());
}
