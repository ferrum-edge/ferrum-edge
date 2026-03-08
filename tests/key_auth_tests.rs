//! Tests for key_auth plugin

use ferrum_gateway::plugins::{key_auth::KeyAuth, Plugin, PluginResult};
use serde_json::json;

mod plugin_utils;
use plugin_utils::{create_test_consumer, create_test_context, assert_continue, assert_reject};

#[tokio::test]
async fn test_key_auth_plugin_creation() {
    let config = json!({
        "key_lookup": "header:X-API-Key"
    });
    let plugin = KeyAuth::new(&config);
    assert_eq!(plugin.name(), "key_auth");
}

#[tokio::test]
async fn test_key_auth_plugin_default_config() {
    let config = json!({});
    let plugin = KeyAuth::new(&config);
    assert_eq!(plugin.name(), "key_auth");
}

#[tokio::test]
async fn test_key_auth_plugin_successful_auth() {
    let config = json!({
        "key_lookup": "header:X-API-Key"
    });
    let plugin = KeyAuth::new(&config);
    
    let consumer = create_test_consumer();
    let consumers = vec![consumer.clone()];
    
    // Test successful authentication
    let mut valid_ctx = create_test_context();
    valid_ctx.headers.insert("X-API-Key".to_string(), "test-api-key".to_string());
    
    let result = plugin.authenticate(&mut valid_ctx, &consumers).await;
    assert_continue(result);
    assert!(valid_ctx.identified_consumer.is_some());
}

#[tokio::test]
async fn test_key_auth_plugin_missing_key() {
    let config = json!({
        "key_lookup": "header:X-API-Key"
    });
    let plugin = KeyAuth::new(&config);
    
    let consumer = create_test_consumer();
    let consumers = vec![consumer];
    
    // Test failed authentication with missing key
    let mut invalid_ctx = create_test_context();
    invalid_ctx.headers.remove("X-API-Key");
    
    let result = plugin.authenticate(&mut invalid_ctx, &consumers).await;
    assert_reject(result, Some(401));
}

#[tokio::test]
async fn test_key_auth_plugin_invalid_key() {
    let config = json!({
        "key_lookup": "header:X-API-Key"
    });
    let plugin = KeyAuth::new(&config);
    
    let consumer = create_test_consumer();
    let consumers = vec![consumer];
    
    // Test failed authentication with invalid key
    let mut invalid_ctx = create_test_context();
    invalid_ctx.headers.insert("X-API-Key".to_string(), "invalid-key".to_string());
    
    let result = plugin.authenticate(&mut invalid_ctx, &consumers).await;
    assert_reject(result, Some(401));
}

#[tokio::test]
async fn test_key_auth_plugin_query_parameter() {
    let config = json!({
        "key_lookup": "query:api_key"
    });
    let plugin = KeyAuth::new(&config);
    
    let consumer = create_test_consumer();
    let consumers = vec![consumer];
    
    // Test successful authentication via query parameter
    let mut valid_ctx = create_test_context();
    valid_ctx.query_params.insert("api_key".to_string(), "test-api-key".to_string());
    
    let result = plugin.authenticate(&mut valid_ctx, &consumers).await;
    assert_continue(result);
    assert!(valid_ctx.identified_consumer.is_some());
}
