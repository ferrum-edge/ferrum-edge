use ferrum_edge::plugins::{PluginResult, RequestContext, create_plugin};
use serde_json::json;
use std::collections::HashMap;

use super::plugin_utils::{assert_continue, assert_reject, create_test_context};

fn create_graphql_context(query: &str, operation_name: Option<&str>) -> RequestContext {
    let mut ctx = create_test_context();
    ctx.method = "POST".to_string();
    ctx.headers
        .insert("content-type".to_string(), "application/json".to_string());

    let mut body = serde_json::Map::new();
    body.insert(
        "query".to_string(),
        serde_json::Value::String(query.to_string()),
    );
    if let Some(name) = operation_name {
        body.insert(
            "operationName".to_string(),
            serde_json::Value::String(name.to_string()),
        );
    }
    ctx.metadata.insert(
        "request_body".to_string(),
        serde_json::to_string(&body).unwrap(),
    );
    ctx
}

// ── Plugin creation ──

#[test]
fn test_graphql_plugin_creation() {
    let config = json!({
        "max_depth": 10,
        "max_complexity": 100
    });
    let plugin = create_plugin("graphql", &config).unwrap().unwrap();
    assert_eq!(plugin.name(), "graphql");
    assert_eq!(plugin.priority(), 2850);
    assert!(plugin.requires_request_body_buffering());
}

#[test]
fn test_graphql_empty_config_returns_error() {
    let result = create_plugin("graphql", &json!({}));
    assert!(result.is_err(), "Empty config should return Err");
    let err = result.err().unwrap();
    assert!(err.contains("no protection rules configured"));
}

#[test]
fn test_graphql_only_buffers_matching_post_json_requests() {
    let plugin = create_plugin("graphql", &json!({"max_depth": 5}))
        .unwrap()
        .unwrap();

    let post_json_ctx = create_graphql_context("{ user { id } }", None);
    assert!(plugin.should_buffer_request_body(&post_json_ctx));

    let mut get_ctx = create_graphql_context("{ user { id } }", None);
    get_ctx.method = "GET".to_string();
    assert!(!plugin.should_buffer_request_body(&get_ctx));

    let mut text_ctx = create_graphql_context("{ user { id } }", None);
    text_ctx
        .headers
        .insert("content-type".to_string(), "text/plain".to_string());
    assert!(!plugin.should_buffer_request_body(&text_ctx));
}

#[test]
fn test_graphql_in_available_plugins() {
    let plugins = ferrum_edge::plugins::available_plugins();
    assert!(plugins.contains(&"graphql"));
}

// ── Depth limiting ──

#[tokio::test]
async fn test_depth_within_limit() {
    let config = json!({ "max_depth": 5 });
    let plugin = create_plugin("graphql", &config).unwrap().unwrap();

    let query = "{ user { name email } }";
    let mut ctx = create_graphql_context(query, None);
    let mut headers = HashMap::new();
    let result = plugin.before_proxy(&mut ctx, &mut headers).await;
    assert_continue(result);
}

#[tokio::test]
async fn test_depth_exceeds_limit() {
    let config = json!({ "max_depth": 2 });
    let plugin = create_plugin("graphql", &config).unwrap().unwrap();

    let query = "{ user { posts { comments { author { name } } } } }";
    let mut ctx = create_graphql_context(query, None);
    let mut headers = HashMap::new();
    let result = plugin.before_proxy(&mut ctx, &mut headers).await;
    assert_reject(result, Some(400));
}

#[tokio::test]
async fn test_depth_at_exact_limit() {
    let config = json!({ "max_depth": 3 });
    let plugin = create_plugin("graphql", &config).unwrap().unwrap();

    // Depth of 3: { user { posts { title } } }
    let query = "{ user { posts { title } } }";
    let mut ctx = create_graphql_context(query, None);
    let mut headers = HashMap::new();
    let result = plugin.before_proxy(&mut ctx, &mut headers).await;
    assert_continue(result);
}

// ── Complexity limiting ──

#[tokio::test]
async fn test_complexity_within_limit() {
    let config = json!({ "max_complexity": 10 });
    let plugin = create_plugin("graphql", &config).unwrap().unwrap();

    let query = "{ user { name email } }";
    let mut ctx = create_graphql_context(query, None);
    let mut headers = HashMap::new();
    let result = plugin.before_proxy(&mut ctx, &mut headers).await;
    assert_continue(result);
}

#[tokio::test]
async fn test_complexity_exceeds_limit() {
    let config = json!({ "max_complexity": 3 });
    let plugin = create_plugin("graphql", &config).unwrap().unwrap();

    let query = "{ user { name email age phone address } }";
    let mut ctx = create_graphql_context(query, None);
    let mut headers = HashMap::new();
    let result = plugin.before_proxy(&mut ctx, &mut headers).await;
    assert_reject(result, Some(400));
}

// ── Alias limiting ──

#[tokio::test]
async fn test_alias_within_limit() {
    let config = json!({ "max_aliases": 2 });
    let plugin = create_plugin("graphql", &config).unwrap().unwrap();

    let query = "{ first: user(id: 1) { name } second: user(id: 2) { name } }";
    let mut ctx = create_graphql_context(query, None);
    let mut headers = HashMap::new();
    let result = plugin.before_proxy(&mut ctx, &mut headers).await;
    assert_continue(result);
}

#[tokio::test]
async fn test_alias_exceeds_limit() {
    let config = json!({ "max_aliases": 1 });
    let plugin = create_plugin("graphql", &config).unwrap().unwrap();

    let query = "{ a: user(id: 1) { name } b: user(id: 2) { name } c: user(id: 3) { name } }";
    let mut ctx = create_graphql_context(query, None);
    let mut headers = HashMap::new();
    let result = plugin.before_proxy(&mut ctx, &mut headers).await;
    assert_reject(result, Some(400));
}

// ── Introspection control ──

#[tokio::test]
async fn test_introspection_allowed_by_default() {
    // Use a minimal valid config so the plugin instantiates; introspection_allowed defaults to true
    let config = json!({"max_depth": 10});
    let plugin = create_plugin("graphql", &config).unwrap().unwrap();

    let query = "{ __schema { types { name } } }";
    let mut ctx = create_graphql_context(query, None);
    let mut headers = HashMap::new();
    let result = plugin.before_proxy(&mut ctx, &mut headers).await;
    assert_continue(result);
}

#[tokio::test]
async fn test_introspection_blocked() {
    let config = json!({ "introspection_allowed": false });
    let plugin = create_plugin("graphql", &config).unwrap().unwrap();

    let query = "{ __schema { types { name } } }";
    let mut ctx = create_graphql_context(query, None);
    let mut headers = HashMap::new();
    let result = plugin.before_proxy(&mut ctx, &mut headers).await;
    assert_reject(result, Some(403));
}

#[tokio::test]
async fn test_introspection_type_blocked() {
    let config = json!({ "introspection_allowed": false });
    let plugin = create_plugin("graphql", &config).unwrap().unwrap();

    let query = r#"{ __type(name: "User") { fields { name } } }"#;
    let mut ctx = create_graphql_context(query, None);
    let mut headers = HashMap::new();
    let result = plugin.before_proxy(&mut ctx, &mut headers).await;
    assert_reject(result, Some(403));
}

// ── Operation type detection ──

#[tokio::test]
async fn test_mutation_detected() {
    let config = json!({ "max_depth": 100 });
    let plugin = create_plugin("graphql", &config).unwrap().unwrap();

    let query = "mutation CreateUser { createUser(name: \"test\") { id } }";
    let mut ctx = create_graphql_context(query, None);
    let mut headers = HashMap::new();
    let result = plugin.before_proxy(&mut ctx, &mut headers).await;
    assert_continue(result);
    assert_eq!(
        ctx.metadata.get("graphql_operation_type").unwrap(),
        "mutation"
    );
    assert_eq!(
        ctx.metadata.get("graphql_operation_name").unwrap(),
        "CreateUser"
    );
}

#[tokio::test]
async fn test_subscription_detected() {
    let config = json!({ "max_depth": 100 });
    let plugin = create_plugin("graphql", &config).unwrap().unwrap();

    let query = "subscription OnMessage { messageAdded { content } }";
    let mut ctx = create_graphql_context(query, None);
    let mut headers = HashMap::new();
    let result = plugin.before_proxy(&mut ctx, &mut headers).await;
    assert_continue(result);
    assert_eq!(
        ctx.metadata.get("graphql_operation_type").unwrap(),
        "subscription"
    );
}

#[tokio::test]
async fn test_shorthand_query() {
    let config = json!({ "max_depth": 100 });
    let plugin = create_plugin("graphql", &config).unwrap().unwrap();

    let query = "{ user { name } }";
    let mut ctx = create_graphql_context(query, None);
    let mut headers = HashMap::new();
    let result = plugin.before_proxy(&mut ctx, &mut headers).await;
    assert_continue(result);
    assert_eq!(ctx.metadata.get("graphql_operation_type").unwrap(), "query");
}

#[tokio::test]
async fn test_operation_name_from_body() {
    let config = json!({ "max_depth": 100 });
    let plugin = create_plugin("graphql", &config).unwrap().unwrap();

    let query = "query GetUser { user { name } }";
    let mut ctx = create_graphql_context(query, Some("GetUser"));
    let mut headers = HashMap::new();
    let result = plugin.before_proxy(&mut ctx, &mut headers).await;
    assert_continue(result);
    assert_eq!(
        ctx.metadata.get("graphql_operation_name").unwrap(),
        "GetUser"
    );
}

// ── Per-type rate limiting ──

#[tokio::test]
async fn test_type_rate_limiting() {
    let config = json!({
        "type_rate_limits": {
            "mutation": { "max_requests": 2, "window_seconds": 60 }
        }
    });
    let plugin = create_plugin("graphql", &config).unwrap().unwrap();

    let query = "mutation { createUser(name: \"a\") { id } }";

    // First two should pass
    for _ in 0..2 {
        let mut ctx = create_graphql_context(query, None);
        let mut headers = HashMap::new();
        let result = plugin.before_proxy(&mut ctx, &mut headers).await;
        assert_continue(result);
    }

    // Third should be rate limited
    let mut ctx = create_graphql_context(query, None);
    let mut headers = HashMap::new();
    let result = plugin.before_proxy(&mut ctx, &mut headers).await;
    assert_reject(result, Some(429));
}

#[tokio::test]
async fn test_query_type_not_limited_when_mutation_limited() {
    let config = json!({
        "type_rate_limits": {
            "mutation": { "max_requests": 1, "window_seconds": 60 }
        }
    });
    let plugin = create_plugin("graphql", &config).unwrap().unwrap();

    // Exhaust mutation limit
    let mutation = "mutation { deleteUser(id: 1) { id } }";
    let mut ctx = create_graphql_context(mutation, None);
    let mut headers = HashMap::new();
    let _ = plugin.before_proxy(&mut ctx, &mut headers).await;

    let mut ctx = create_graphql_context(mutation, None);
    let mut headers = HashMap::new();
    let result = plugin.before_proxy(&mut ctx, &mut headers).await;
    assert_reject(result, Some(429));

    // Queries should still work
    let query = "{ user { name } }";
    let mut ctx = create_graphql_context(query, None);
    let mut headers = HashMap::new();
    let result = plugin.before_proxy(&mut ctx, &mut headers).await;
    assert_continue(result);
}

// ── Per-named-operation rate limiting ──

#[tokio::test]
async fn test_named_operation_rate_limiting() {
    let config = json!({
        "operation_rate_limits": {
            "GetUser": { "max_requests": 1, "window_seconds": 60 }
        }
    });
    let plugin = create_plugin("graphql", &config).unwrap().unwrap();

    let query = "query GetUser { user { name } }";

    // First request passes
    let mut ctx = create_graphql_context(query, Some("GetUser"));
    let mut headers = HashMap::new();
    let result = plugin.before_proxy(&mut ctx, &mut headers).await;
    assert_continue(result);

    // Second is rate limited
    let mut ctx = create_graphql_context(query, Some("GetUser"));
    let mut headers = HashMap::new();
    let result = plugin.before_proxy(&mut ctx, &mut headers).await;
    assert_reject(result, Some(429));
}

#[tokio::test]
async fn test_consumer_rate_limiting_uses_authenticated_identity_fallback() {
    let config = json!({
        "limit_by": "consumer",
        "type_rate_limits": {
            "mutation": { "max_requests": 1, "window_seconds": 60 }
        }
    });
    let plugin = create_plugin("graphql", &config).unwrap().unwrap();
    let query = "mutation { createUser(name: \"a\") { id } }";

    let mut ctx = create_graphql_context(query, None);
    ctx.identified_consumer = None;
    ctx.authenticated_identity = Some("oidc-user-a".to_string());
    let mut headers = HashMap::new();
    let result = plugin.before_proxy(&mut ctx, &mut headers).await;
    assert_continue(result);

    let mut ctx = create_graphql_context(query, None);
    ctx.identified_consumer = None;
    ctx.authenticated_identity = Some("oidc-user-a".to_string());
    let mut headers = HashMap::new();
    let result = plugin.before_proxy(&mut ctx, &mut headers).await;
    assert_reject(result, Some(429));

    let mut ctx = create_graphql_context(query, None);
    ctx.identified_consumer = None;
    ctx.authenticated_identity = Some("oidc-user-b".to_string());
    let mut headers = HashMap::new();
    let result = plugin.before_proxy(&mut ctx, &mut headers).await;
    assert_continue(result);
}

// ── Non-GraphQL requests pass through ──

#[tokio::test]
async fn test_get_request_passes_through() {
    let config = json!({ "max_depth": 1 });
    let plugin = create_plugin("graphql", &config).unwrap().unwrap();

    let mut ctx = create_test_context();
    ctx.method = "GET".to_string();
    let mut headers = HashMap::new();
    let result = plugin.before_proxy(&mut ctx, &mut headers).await;
    assert_continue(result);
}

#[tokio::test]
async fn test_non_json_passes_through() {
    let config = json!({ "max_depth": 1 });
    let plugin = create_plugin("graphql", &config).unwrap().unwrap();

    let mut ctx = create_test_context();
    ctx.method = "POST".to_string();
    ctx.headers
        .insert("content-type".to_string(), "text/plain".to_string());
    let mut headers = HashMap::new();
    let result = plugin.before_proxy(&mut ctx, &mut headers).await;
    assert_continue(result);
}

#[tokio::test]
async fn test_no_query_field_passes_through() {
    let config = json!({ "max_depth": 1 });
    let plugin = create_plugin("graphql", &config).unwrap().unwrap();

    let mut ctx = create_test_context();
    ctx.method = "POST".to_string();
    ctx.headers
        .insert("content-type".to_string(), "application/json".to_string());
    ctx.metadata.insert(
        "request_body".to_string(),
        r#"{"data": "not graphql"}"#.to_string(),
    );
    let mut headers = HashMap::new();
    let result = plugin.before_proxy(&mut ctx, &mut headers).await;
    assert_continue(result);
}

// ── Comments and strings in queries ──

#[tokio::test]
async fn test_comments_ignored_in_depth() {
    let config = json!({ "max_depth": 2 });
    let plugin = create_plugin("graphql", &config).unwrap().unwrap();

    let query = r#"{
        # This is a comment
        user {
            name # inline comment
        }
    }"#;
    let mut ctx = create_graphql_context(query, None);
    let mut headers = HashMap::new();
    let result = plugin.before_proxy(&mut ctx, &mut headers).await;
    assert_continue(result);
}

#[tokio::test]
async fn test_string_braces_not_counted() {
    let config = json!({ "max_depth": 2 });
    let plugin = create_plugin("graphql", &config).unwrap().unwrap();

    let query = r#"{ user(filter: "{ nested: { deep } }") { name } }"#;
    let mut ctx = create_graphql_context(query, None);
    let mut headers = HashMap::new();
    let result = plugin.before_proxy(&mut ctx, &mut headers).await;
    assert_continue(result);
}

// ── Metadata populated ──

#[tokio::test]
async fn test_metadata_populated() {
    let config = json!({ "max_depth": 100, "max_complexity": 100 });
    let plugin = create_plugin("graphql", &config).unwrap().unwrap();

    let query = "query GetUser { user { name email } }";
    let mut ctx = create_graphql_context(query, Some("GetUser"));
    let mut headers = HashMap::new();
    let result = plugin.before_proxy(&mut ctx, &mut headers).await;
    assert_continue(result);

    assert_eq!(ctx.metadata.get("graphql_operation_type").unwrap(), "query");
    assert_eq!(
        ctx.metadata.get("graphql_operation_name").unwrap(),
        "GetUser"
    );
    assert!(ctx.metadata.contains_key("graphql_depth"));
    assert!(ctx.metadata.contains_key("graphql_complexity"));
}

// ── Edge cases ──

#[test]
fn test_empty_config_returns_error_on_creation() {
    let result = create_plugin("graphql", &json!({}));
    assert!(result.is_err(), "Empty config should return Err");
    let err = result.err().unwrap();
    assert!(err.contains("no protection rules configured"));
}

#[tokio::test]
async fn test_combined_depth_and_complexity() {
    let config = json!({
        "max_depth": 3,
        "max_complexity": 5
    });
    let plugin = create_plugin("graphql", &config).unwrap().unwrap();

    // Within both limits
    let query = "{ user { name email } }";
    let mut ctx = create_graphql_context(query, None);
    let mut headers = HashMap::new();
    let result = plugin.before_proxy(&mut ctx, &mut headers).await;
    assert_continue(result);

    // Exceeds depth but not complexity
    let query = "{ a { b { c { d { e } } } } }";
    let mut ctx = create_graphql_context(query, None);
    let mut headers = HashMap::new();
    let result = plugin.before_proxy(&mut ctx, &mut headers).await;
    assert_reject(result, Some(400));
}

// ── Rejection body format ──

#[tokio::test]
async fn test_rejection_uses_graphql_error_format() {
    let config = json!({ "max_depth": 1 });
    let plugin = create_plugin("graphql", &config).unwrap().unwrap();

    let query = "{ user { posts { comments { text } } } }";
    let mut ctx = create_graphql_context(query, None);
    let mut headers = HashMap::new();
    let result = plugin.before_proxy(&mut ctx, &mut headers).await;

    match result {
        PluginResult::Reject {
            status_code,
            body,
            headers,
        } => {
            assert_eq!(status_code, 400);
            // Should be valid JSON with errors array
            let parsed: serde_json::Value = serde_json::from_str(&body).unwrap();
            assert!(parsed.get("errors").unwrap().as_array().is_some());
            assert_eq!(headers.get("content-type").unwrap(), "application/json");
        }
        _ => panic!("Expected Reject"),
    }
}
