use ferrum_edge::plugins::{PluginResult, ProxyProtocol, RequestContext, create_plugin, priority};
use serde_json::json;
use std::collections::HashMap;

use super::plugin_utils::{
    assert_continue, assert_reject, create_test_context,
    normalize_compressed_request_for_plugin_test,
};

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

fn make_graphql_headers() -> HashMap<String, String> {
    let mut headers = HashMap::new();
    headers.insert("content-type".to_string(), "application/json".to_string());
    headers
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
    assert_eq!(plugin.priority(), priority::GRAPHQL);
    assert_eq!(
        plugin.supported_protocols(),
        &[ProxyProtocol::Http, ProxyProtocol::WebSocket]
    );
    assert!(!plugin.requires_websocket_framing());
    assert!(!plugin.requires_ws_frame_hooks());
    assert!(plugin.requires_request_body_buffering());
    assert!(plugin.requires_request_body_before_before_proxy());
    assert!(!plugin.requires_response_body_buffering());
    assert!(!plugin.modifies_request_headers());
    assert!(!plugin.modifies_request_body());
    assert!(!plugin.is_auth_plugin());
}

#[test]
fn test_graphql_empty_config_returns_error() {
    let result = create_plugin("graphql", &json!({}));
    assert!(result.is_err(), "Empty config should return Err");
    let err = result.err().unwrap();
    assert!(err.contains("no protection rules configured"));
    assert!(err.contains("introspection_allowed: false"));
}

#[test]
fn test_graphql_non_object_config_returns_error() {
    let result = create_plugin("graphql", &json!("bad"));
    assert!(result.is_err(), "Non-object config should return Err");
    assert!(result.err().unwrap().contains("config must be an object"));
}

#[test]
fn test_graphql_rejects_invalid_scalar_config_types() {
    for config in [
        json!({"max_depth": "5"}),
        json!({"max_complexity": "100"}),
        json!({"max_aliases": "3"}),
        json!({"introspection_allowed": "false"}),
        json!({"limit_by": null}),
        json!({"sync_mode": null}),
        json!({"sync_mode": 1}),
    ] {
        let result = create_plugin("graphql", &config);
        assert!(result.is_err(), "config should be rejected: {config:?}");
    }

    let sync_mode_error = create_plugin("graphql", &json!({"max_depth": 5, "sync_mode": null}))
        .err()
        .expect("null sync_mode must be rejected");
    assert!(
        sync_mode_error.starts_with("graphql: 'sync_mode' must be a string"),
        "GraphQL must own the sync_mode admission error: {sync_mode_error}"
    );
}

#[test]
fn test_graphql_rejects_invalid_rate_limit_shapes() {
    for config in [
        json!({"type_rate_limits": "query"}),
        json!({"operation_rate_limits": []}),
        json!({"type_rate_limits": {"other": {"max_requests": 1, "window_seconds": 60}}}),
        json!({"operation_rate_limits": {"": {"max_requests": 1, "window_seconds": 60}}}),
        json!({"operation_rate_limits": {"bad-name": {"max_requests": 1, "window_seconds": 60}}}),
        json!({"type_rate_limits": {"query": "bad"}}),
        json!({"type_rate_limits": {"query": {"max_requests": "1", "window_seconds": 60}}}),
        json!({"type_rate_limits": {"query": {"max_requests": 0, "window_seconds": 60}}}),
        json!({"type_rate_limits": {"query": {"max_requests": 1, "window_seconds": 60, "burst": 2}}}),
        json!({"type_rate_limits": {}}),
        json!({"operation_rate_limits": {}}),
        json!({"introspection_allowed": true}),
        json!({"type_rate_limits": {"Query": {"max_requests": 1, "window_seconds": 60}}}),
        json!({"max_depth": 5, "limit_by": "IP"}),
        json!({"max_depth": 5, "sync_mode": "REDIS", "redis_url": "redis://localhost:6379"}),
        json!({"max_depth": 5, "sync_mode": "database"}),
        json!({"max_depth": 5, "sync_mode": "redis"}),
        json!({"max_depth": 5, "sync_mode": "local", "redis_url": "garbage"}),
        json!({"max_depth": 5, "sync_mode": "local", "redis_tls": "yes"}),
        json!({"max_depth": 5, "sync_mode": "local", "redis_pool_size": 0}),
    ] {
        let result = create_plugin("graphql", &config);
        assert!(result.is_err(), "config should be rejected: {config:?}");
    }
}

#[test]
fn test_graphql_rejects_unknown_top_level_keys() {
    // GHSA-q3p3-94cj-8wh6 GraphQL component: a valid rule must not mask typos.
    for config in [
        json!({"max_depth": 10, "introspection_allowd": false}),
        json!({
            "type_rate_limits": {"query": {"max_requests": 1, "window_seconds": 60}},
            "sync_mdoe": "redis",
            "redis_url": "redis://localhost:6379/0"
        }),
        json!({"max_depth": 5, "limit_byy": "consumer"}),
        json!({"max_depth": 5, "redis_key_prefx": "ferrum:graphql"}),
        json!({"max_depth": 5, "type_rate_limit": {"query": {"max_requests": 1, "window_seconds": 60}}}),
        json!({"max_depth": 5, "require_inspectable_transport": false}),
    ] {
        let err = create_plugin("graphql", &config)
            .err()
            .unwrap_or_else(|| panic!("config should be rejected: {config:?}"));
        assert!(
            err.contains("unknown configuration key"),
            "expected unknown-key rejection for {config:?}, got: {err}"
        );
    }
}

#[test]
fn test_graphql_accepts_closed_redis_and_named_operation_shapes() {
    for config in [
        json!({"introspection_allowed": false}),
        json!({"operation_rate_limits": {"getUser": {"max_requests": 1, "window_seconds": 60}}}),
        json!({
            "type_rate_limits": {
                "query": { "max_requests": 10, "window_seconds": 60 }
            },
            "sync_mode": "redis",
            "redis_url": "redis://cache.internal:6379/0",
            "redis_pool_size": 1,
            "redis_connect_timeout_seconds": 1,
            "redis_health_check_interval_seconds": 1
        }),
        json!({
            "type_rate_limits": {
                "query": { "max_requests": 10, "window_seconds": 60 }
            },
            "sync_mode": "redis",
            "redis_url": "redis://cache.internal:6379/0",
            "redis_connect_timeout_seconds": 5
        }),
        json!({
            "max_depth": 5,
            "sync_mode": "local",
            "redis_url": "redis://cache.internal:6379/0",
            "redis_tls": false,
            "redis_pool_size": 1
        }),
    ] {
        create_plugin("graphql", &config)
            .unwrap_or_else(|err| panic!("config should be accepted: {config:?}: {err}"))
            .unwrap();
    }
}

#[test]
fn test_graphql_warmup_hostnames_for_redis() {
    let plugin = create_plugin(
        "graphql",
        &json!({
            "type_rate_limits": {
                "query": { "max_requests": 10, "window_seconds": 60 }
            },
            "sync_mode": "redis",
            "redis_url": "redis://cache.internal:6379/0"
        }),
    )
    .unwrap()
    .unwrap();

    assert_eq!(
        plugin.warmup_hostnames(),
        vec!["cache.internal".to_string()]
    );
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
    let mut headers = make_graphql_headers();
    let result = plugin.before_proxy(&mut ctx, &mut headers).await;
    assert_continue(result);
}

#[tokio::test]
async fn test_depth_exceeds_limit() {
    let config = json!({ "max_depth": 2 });
    let plugin = create_plugin("graphql", &config).unwrap().unwrap();

    let query = "{ user { posts { comments { author { name } } } } }";
    let mut ctx = create_graphql_context(query, None);
    let mut headers = make_graphql_headers();
    let result = plugin.before_proxy(&mut ctx, &mut headers).await;
    assert_reject(result, Some(400));
}

#[tokio::test]
async fn configured_decompression_exposes_plaintext_before_graphql_policy() {
    let plugin = create_plugin("graphql", &json!({"max_depth": 2}))
        .unwrap()
        .unwrap();
    let plaintext = serde_json::to_vec(&json!({
        "query": "{ user { posts { comments { author { name } } } } }"
    }))
    .unwrap();

    for encoding in ["gzip", "br"] {
        let (mut ctx, mut headers, _) = normalize_compressed_request_for_plugin_test(
            "application/json",
            "/graphql",
            encoding,
            &plaintext,
        )
        .await;
        assert_reject(plugin.before_proxy(&mut ctx, &mut headers).await, Some(400));
    }
}

#[tokio::test]
async fn test_depth_at_exact_limit() {
    let config = json!({ "max_depth": 3 });
    let plugin = create_plugin("graphql", &config).unwrap().unwrap();

    // Depth of 3: { user { posts { title } } }
    let query = "{ user { posts { title } } }";
    let mut ctx = create_graphql_context(query, None);
    let mut headers = make_graphql_headers();
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
    let mut headers = make_graphql_headers();
    let result = plugin.before_proxy(&mut ctx, &mut headers).await;
    assert_continue(result);
}

#[tokio::test]
async fn test_complexity_exceeds_limit() {
    let config = json!({ "max_complexity": 3 });
    let plugin = create_plugin("graphql", &config).unwrap().unwrap();

    let query = "{ user { name email age phone address } }";
    let mut ctx = create_graphql_context(query, None);
    let mut headers = make_graphql_headers();
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
    let mut headers = make_graphql_headers();
    let result = plugin.before_proxy(&mut ctx, &mut headers).await;
    assert_continue(result);
}

#[tokio::test]
async fn test_alias_exceeds_limit() {
    let config = json!({ "max_aliases": 1 });
    let plugin = create_plugin("graphql", &config).unwrap().unwrap();

    let query = "{ a: user(id: 1) { name } b: user(id: 2) { name } c: user(id: 3) { name } }";
    let mut ctx = create_graphql_context(query, None);
    let mut headers = make_graphql_headers();
    let result = plugin.before_proxy(&mut ctx, &mut headers).await;
    assert_reject(result, Some(400));
}

#[tokio::test]
async fn test_alias_count_counts_ignored_tokens_before_colon() {
    let config = json!({ "max_aliases": 2 });
    let plugin = create_plugin("graphql", &config).unwrap().unwrap();

    let plain = "{ a1: f a2: f a3: f }";
    let comma = "{ a1,: f a2,: f a3,: f }";
    let comment = "{ a1# ign\n: f a2# ign\n: f a3# ign\n: f }";

    for query in [plain, comma, comment] {
        let mut ctx = create_graphql_context(query, None);
        let mut headers = make_graphql_headers();
        match plugin.before_proxy(&mut ctx, &mut headers).await {
            PluginResult::Reject {
                status_code, body, ..
            } => {
                assert_eq!(status_code, 400);
                assert!(
                    body.contains("Query uses 3 aliases, maximum allowed is 2"),
                    "expected alias-budget rejection for {query:?}, got {body}"
                );
            }
            other => panic!("Expected Reject(400) for {query:?}, got {other:?}"),
        }
    }
}

#[tokio::test]
async fn test_two_aliases_pass_with_ignored_tokens_before_colon() {
    let config = json!({ "max_aliases": 2 });
    let plugin = create_plugin("graphql", &config).unwrap().unwrap();

    let plain = "{ a1: f a2: f }";
    let comma = "{ a1,: f a2,: f }";
    let comment = "{ a1# ign\n: f a2# ign\n: f }";

    for query in [plain, comma, comment] {
        let mut ctx = create_graphql_context(query, None);
        let mut headers = make_graphql_headers();
        let result = plugin.before_proxy(&mut ctx, &mut headers).await;
        assert_continue(result);
    }
}

#[tokio::test]
async fn test_alias_count_unaffected_by_commas_in_argument_lists() {
    let config = json!({ "max_aliases": 2 });
    let plugin = create_plugin("graphql", &config).unwrap().unwrap();

    let query = "{ user(id: 1, status: active) { name } }";
    let mut ctx = create_graphql_context(query, None);
    let mut headers = make_graphql_headers();
    let result = plugin.before_proxy(&mut ctx, &mut headers).await;
    assert_continue(result);
}

// ── Introspection control ──

#[tokio::test]
async fn test_introspection_allowed_by_default() {
    // Use a minimal valid config so the plugin instantiates; introspection_allowed defaults to true
    let config = json!({"max_depth": 10});
    let plugin = create_plugin("graphql", &config).unwrap().unwrap();

    let query = "{ __schema { types { name } } }";
    let mut ctx = create_graphql_context(query, None);
    let mut headers = make_graphql_headers();
    let result = plugin.before_proxy(&mut ctx, &mut headers).await;
    assert_continue(result);
}

#[tokio::test]
async fn test_introspection_blocked() {
    let config = json!({ "introspection_allowed": false });
    let plugin = create_plugin("graphql", &config).unwrap().unwrap();

    let query = "{ __schema { types { name } } }";
    let mut ctx = create_graphql_context(query, None);
    let mut headers = make_graphql_headers();
    let result = plugin.before_proxy(&mut ctx, &mut headers).await;
    assert_reject(result, Some(403));
}

#[tokio::test]
async fn test_introspection_type_blocked() {
    let config = json!({ "introspection_allowed": false });
    let plugin = create_plugin("graphql", &config).unwrap().unwrap();

    let query = r#"{ __type(name: "User") { fields { name } } }"#;
    let mut ctx = create_graphql_context(query, None);
    let mut headers = make_graphql_headers();
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
    let mut headers = make_graphql_headers();
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
    let mut headers = make_graphql_headers();
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
    let mut headers = make_graphql_headers();
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
    let mut headers = make_graphql_headers();
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
        let mut headers = make_graphql_headers();
        let result = plugin.before_proxy(&mut ctx, &mut headers).await;
        assert_continue(result);
    }

    // Third should be rate limited
    let mut ctx = create_graphql_context(query, None);
    let mut headers = make_graphql_headers();
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
    let mut headers = make_graphql_headers();
    let _ = plugin.before_proxy(&mut ctx, &mut headers).await;

    let mut ctx = create_graphql_context(mutation, None);
    let mut headers = make_graphql_headers();
    let result = plugin.before_proxy(&mut ctx, &mut headers).await;
    assert_reject(result, Some(429));

    // Queries should still work
    let query = "{ user { name } }";
    let mut ctx = create_graphql_context(query, None);
    let mut headers = make_graphql_headers();
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
    let mut headers = make_graphql_headers();
    let result = plugin.before_proxy(&mut ctx, &mut headers).await;
    assert_continue(result);

    // Second is rate limited
    let mut ctx = create_graphql_context(query, Some("GetUser"));
    let mut headers = make_graphql_headers();
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
    let mut headers = make_graphql_headers();
    let result = plugin.before_proxy(&mut ctx, &mut headers).await;
    assert_continue(result);

    let mut ctx = create_graphql_context(query, None);
    ctx.identified_consumer = None;
    ctx.authenticated_identity = Some("oidc-user-a".to_string());
    let mut headers = make_graphql_headers();
    let result = plugin.before_proxy(&mut ctx, &mut headers).await;
    assert_reject(result, Some(429));

    let mut ctx = create_graphql_context(query, None);
    ctx.identified_consumer = None;
    ctx.authenticated_identity = Some("oidc-user-b".to_string());
    let mut headers = make_graphql_headers();
    let result = plugin.before_proxy(&mut ctx, &mut headers).await;
    assert_continue(result);
}

// ── Uninspectable transports (GHSA-762h) ──

fn assert_uninspectable_reject(result: PluginResult) {
    match result {
        PluginResult::Reject {
            status_code,
            body,
            headers,
        } => {
            assert_eq!(status_code, 400, "uninspectable transport must be 400");
            assert_eq!(
                headers.get("content-type").map(String::as_str),
                Some("application/json")
            );
            let parsed: serde_json::Value =
                serde_json::from_str(&body).expect("reject body must be JSON");
            let message = parsed["errors"][0]["message"]
                .as_str()
                .expect("GraphQL error message");
            assert!(!message.is_empty(), "reject message must be non-empty");
        }
        other => panic!("Expected Reject(400), got {other:?}"),
    }
}

#[tokio::test]
async fn test_get_query_rejected_by_default() {
    // GHSA-762h: GraphQL GET (?query=...) must not fail open.
    let config = json!({ "max_depth": 10, "introspection_allowed": false });
    let plugin = create_plugin("graphql", &config).unwrap().unwrap();

    let mut ctx = create_test_context();
    ctx.method = "GET".to_string();
    ctx.path =
        "/graphql?query=%7B%20__schema%20%7B%20types%20%7B%20name%20%7D%20%7D%20%7D".to_string();
    let mut headers = HashMap::new();
    let result = plugin.before_proxy(&mut ctx, &mut headers).await;
    assert_uninspectable_reject(result);
}

#[tokio::test]
async fn test_websocket_upgrade_rejected_before_uninspectable_frames() {
    let plugin = create_plugin("graphql", &json!({"max_depth": 10}))
        .unwrap()
        .unwrap();
    assert!(
        plugin
            .supported_protocols()
            .contains(&ProxyProtocol::WebSocket)
    );

    let mut ctx = create_test_context();
    ctx.method = "GET".to_string();
    let mut headers = HashMap::from([
        ("connection".to_string(), "Upgrade".to_string()),
        ("upgrade".to_string(), "websocket".to_string()),
        (
            "sec-websocket-protocol".to_string(),
            "graphql-transport-ws".to_string(),
        ),
    ]);

    let result = plugin.before_proxy(&mut ctx, &mut headers).await;
    assert_uninspectable_reject(result);
}

#[tokio::test]
async fn test_application_graphql_rejected_by_default() {
    let config = json!({ "max_depth": 10 });
    let plugin = create_plugin("graphql", &config).unwrap().unwrap();

    let mut ctx = create_test_context();
    ctx.method = "POST".to_string();
    ctx.headers.insert(
        "content-type".to_string(),
        "application/graphql".to_string(),
    );
    ctx.metadata
        .insert("request_body".to_string(), "{ user { id } }".to_string());
    let mut headers = HashMap::new();
    headers.insert(
        "content-type".to_string(),
        "application/graphql".to_string(),
    );
    let result = plugin.before_proxy(&mut ctx, &mut headers).await;
    assert_uninspectable_reject(result);
}

#[tokio::test]
async fn test_json_batch_array_rejected_by_default() {
    let config = json!({ "max_depth": 10 });
    let plugin = create_plugin("graphql", &config).unwrap().unwrap();

    let mut ctx = create_test_context();
    ctx.method = "POST".to_string();
    ctx.headers
        .insert("content-type".to_string(), "application/json".to_string());
    ctx.metadata.insert(
        "request_body".to_string(),
        r#"[{"query":"{ user { id } }"},{"query":"{ post { id } }"}]"#.to_string(),
    );
    let mut headers = make_graphql_headers();
    let result = plugin.before_proxy(&mut ctx, &mut headers).await;
    assert_uninspectable_reject(result);
}

#[tokio::test]
async fn test_apq_envelope_without_query_rejected_by_default() {
    let config = json!({ "max_depth": 10 });
    let plugin = create_plugin("graphql", &config).unwrap().unwrap();

    let mut ctx = create_test_context();
    ctx.method = "POST".to_string();
    ctx.headers
        .insert("content-type".to_string(), "application/json".to_string());
    ctx.metadata.insert(
        "request_body".to_string(),
        r#"{"extensions":{"persistedQuery":{"version":1,"sha256Hash":"abcdef"}}}"#.to_string(),
    );
    let mut headers = make_graphql_headers();
    let result = plugin.before_proxy(&mut ctx, &mut headers).await;
    assert_uninspectable_reject(result);
}

#[tokio::test]
async fn test_non_json_body_under_json_content_type_rejected_by_default() {
    let config = json!({ "max_depth": 10 });
    let plugin = create_plugin("graphql", &config).unwrap().unwrap();

    let mut ctx = create_test_context();
    ctx.method = "POST".to_string();
    ctx.headers
        .insert("content-type".to_string(), "application/json".to_string());
    ctx.metadata
        .insert("request_body".to_string(), "not-valid-json{{{".to_string());
    let mut headers = make_graphql_headers();
    let result = plugin.before_proxy(&mut ctx, &mut headers).await;
    assert_uninspectable_reject(result);
}

#[tokio::test]
async fn test_canonical_post_json_still_enforces_policy() {
    // Canonical path must still apply introspection/depth policy.
    let config = json!({
        "max_depth": 2,
        "introspection_allowed": false
    });
    let plugin = create_plugin("graphql", &config).unwrap().unwrap();

    let mut ctx = create_graphql_context("{ __schema { types { name } } }", None);
    let mut headers = make_graphql_headers();
    let result = plugin.before_proxy(&mut ctx, &mut headers).await;
    assert_reject(result, Some(403));

    let deep = "{ user { posts { comments { text } } } }";
    let mut ctx = create_graphql_context(deep, None);
    let mut headers = make_graphql_headers();
    let result = plugin.before_proxy(&mut ctx, &mut headers).await;
    assert_reject(result, Some(400));
}

#[tokio::test]
async fn test_graphql_enforces_limits_for_json_substring_content_types() {
    let plugin = create_plugin("graphql", &json!({"max_depth": 1}))
        .unwrap()
        .unwrap();
    let query = "{ user { posts { comments { text } } } }";

    for content_type in [
        "application/jsonp",
        "application/notjson",
        "text/application/json",
        "application/json-seq",
    ] {
        let mut ctx = create_graphql_context(query, None);
        ctx.headers
            .insert("content-type".to_string(), content_type.to_string());
        let mut headers = HashMap::new();
        headers.insert("content-type".to_string(), content_type.to_string());

        assert!(
            plugin.should_buffer_request_body(&ctx),
            "{content_type} must trigger GraphQL request-body buffering"
        );
        let result = plugin.before_proxy(&mut ctx, &mut headers).await;
        assert_reject(result, Some(400));
        assert!(
            ctx.metadata.contains_key("graphql_depth"),
            "{content_type} must be parsed as GraphQL JSON"
        );
    }
}

#[tokio::test]
async fn test_no_query_field_rejected_by_default() {
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
    let mut headers = make_graphql_headers();
    let result = plugin.before_proxy(&mut ctx, &mut headers).await;
    assert_uninspectable_reject(result);
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
    let mut headers = make_graphql_headers();
    let result = plugin.before_proxy(&mut ctx, &mut headers).await;
    assert_continue(result);
}

#[tokio::test]
async fn test_string_braces_not_counted() {
    let config = json!({ "max_depth": 2 });
    let plugin = create_plugin("graphql", &config).unwrap().unwrap();

    let query = r#"{ user(filter: "{ nested: { deep } }") { name } }"#;
    let mut ctx = create_graphql_context(query, None);
    let mut headers = make_graphql_headers();
    let result = plugin.before_proxy(&mut ctx, &mut headers).await;
    assert_continue(result);
}

#[tokio::test]
async fn test_introspection_tokens_in_strings_and_comments_are_ignored() {
    let config = json!({ "introspection_allowed": false });
    let plugin = create_plugin("graphql", &config).unwrap().unwrap();

    let query = r#"{
        # __schema in a comment is not an introspection field
        user(filter: "__type") { name }
    }"#;
    let mut ctx = create_graphql_context(query, None);
    let mut headers = make_graphql_headers();
    let result = plugin.before_proxy(&mut ctx, &mut headers).await;
    assert_continue(result);
}

#[tokio::test]
async fn test_non_ascii_query_text_does_not_panic() {
    let config = json!({ "max_depth": 10 });
    let plugin = create_plugin("graphql", &config).unwrap().unwrap();

    let query = "{ café { name } }";
    let mut ctx = create_graphql_context(query, None);
    let mut headers = make_graphql_headers();
    let result = plugin.before_proxy(&mut ctx, &mut headers).await;
    assert_continue(result);
}

#[tokio::test]
async fn test_leading_comment_before_operation_keyword() {
    let config = json!({ "max_depth": 100 });
    let plugin = create_plugin("graphql", &config).unwrap().unwrap();

    let query = "# warm-up comment\nmutation CreateUser { createUser(name: \"a\") { id } }";
    let mut ctx = create_graphql_context(query, None);
    let mut headers = make_graphql_headers();
    let result = plugin.before_proxy(&mut ctx, &mut headers).await;
    assert_continue(result);
    assert_eq!(
        ctx.metadata.get("graphql_operation_type").unwrap(),
        "mutation"
    );
}

// ── Metadata populated ──

#[tokio::test]
async fn test_metadata_populated() {
    let config = json!({ "max_depth": 100, "max_complexity": 100 });
    let plugin = create_plugin("graphql", &config).unwrap().unwrap();

    let query = "query GetUser { user { name email } }";
    let mut ctx = create_graphql_context(query, Some("GetUser"));
    let mut headers = make_graphql_headers();
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

// ── Constructor validation: limit_by ──

#[test]
fn test_unknown_limit_by_rejected() {
    let result = create_plugin(
        "graphql",
        &json!({
            "max_depth": 5,
            "limit_by": "country"
        }),
    );
    let err = result.err().expect("unknown limit_by must be rejected");
    assert!(
        err.contains("'limit_by' must be exactly 'ip' or 'consumer'"),
        "got: {err}"
    );
}

// ── Constructor validation: rate-limit specs ──

#[test]
fn test_zero_window_seconds_in_type_limit_rejected() {
    let result = create_plugin(
        "graphql",
        &json!({
            "type_rate_limits": {
                "query": { "max_requests": 5, "window_seconds": 0 }
            }
        }),
    );
    let err = result.err().expect("window_seconds=0 must be rejected");
    assert!(
        err.contains("'window_seconds' must be greater than zero"),
        "got: {err}"
    );
}

#[test]
fn test_missing_max_requests_in_operation_limit_rejected() {
    let result = create_plugin(
        "graphql",
        &json!({
            "operation_rate_limits": {
                "GetUser": { "window_seconds": 60 }
            }
        }),
    );
    let err = result.err().expect("missing max_requests must be rejected");
    assert!(err.contains("'max_requests' is required"), "got: {err}");
}

#[test]
fn test_missing_window_seconds_in_type_limit_rejected() {
    let result = create_plugin(
        "graphql",
        &json!({
            "type_rate_limits": {
                "query": { "max_requests": 5 }
            }
        }),
    );
    let err = result
        .err()
        .expect("missing window_seconds must be rejected");
    assert!(err.contains("'window_seconds' is required"), "got: {err}");
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
    let mut headers = make_graphql_headers();
    let result = plugin.before_proxy(&mut ctx, &mut headers).await;
    assert_continue(result);

    // Exceeds depth but not complexity
    let query = "{ a { b { c { d { e } } } } }";
    let mut ctx = create_graphql_context(query, None);
    let mut headers = make_graphql_headers();
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
    let mut headers = make_graphql_headers();
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

// ── Operation selection by operationName (finding #18) ──

#[tokio::test]
async fn test_operation_name_selects_correct_op_type() {
    // Multi-operation document: a leading query and a trailing mutation. With
    // operationName="B" the executed operation is the MUTATION, so op_type must
    // be "mutation" — not the first operation's "query".
    let config = json!({ "max_depth": 100 });
    let plugin = create_plugin("graphql", &config).unwrap().unwrap();

    let query = "query A { user { name } } mutation B { createUser(name: \"x\") { id } }";
    let mut ctx = create_graphql_context(query, Some("B"));
    let mut headers = make_graphql_headers();
    let result = plugin.before_proxy(&mut ctx, &mut headers).await;
    assert_continue(result);
    assert_eq!(
        ctx.metadata.get("graphql_operation_type").unwrap(),
        "mutation",
        "op_type must reflect the operation selected by operationName, not the first operation"
    );
    assert_eq!(ctx.metadata.get("graphql_operation_name").unwrap(), "B");
}

#[tokio::test]
async fn test_operation_name_selects_first_op_type() {
    // Same document, but operationName="A" selects the leading query.
    let config = json!({ "max_depth": 100 });
    let plugin = create_plugin("graphql", &config).unwrap().unwrap();

    let query = "query A { user { name } } mutation B { createUser(name: \"x\") { id } }";
    let mut ctx = create_graphql_context(query, Some("A"));
    let mut headers = make_graphql_headers();
    let result = plugin.before_proxy(&mut ctx, &mut headers).await;
    assert_continue(result);
    assert_eq!(ctx.metadata.get("graphql_operation_type").unwrap(), "query");
    assert_eq!(ctx.metadata.get("graphql_operation_name").unwrap(), "A");
}

#[tokio::test]
async fn test_per_type_rate_limit_not_bypassed_by_operation_selection() {
    // Regression for the per-type rate-limit bypass: a mutation limit must apply
    // when operationName selects the mutation in a multi-operation document.
    // Before the fix op_type was always "query" (the first op), so the mutation
    // bucket was never checked and the limit was silently bypassed.
    let config = json!({
        "type_rate_limits": {
            "mutation": { "max_requests": 2, "window_seconds": 60 }
        }
    });
    let plugin = create_plugin("graphql", &config).unwrap().unwrap();

    let query = "query A { user { name } } mutation B { createUser(name: \"x\") { id } }";

    // First two mutation invocations pass.
    for _ in 0..2 {
        let mut ctx = create_graphql_context(query, Some("B"));
        let mut headers = make_graphql_headers();
        let result = plugin.before_proxy(&mut ctx, &mut headers).await;
        assert_continue(result);
    }

    // Third is rate limited because the mutation bucket is now enforced.
    let mut ctx = create_graphql_context(query, Some("B"));
    let mut headers = make_graphql_headers();
    let result = plugin.before_proxy(&mut ctx, &mut headers).await;
    assert_reject(result, Some(429));
}

#[tokio::test]
async fn test_unrelated_large_operation_does_not_inflate_selected_op() {
    // The selected operation is small; an unrelated, deeply nested operation in
    // the same document must NOT cause a false-positive depth rejection. Before
    // the fix, depth was measured over the whole document.
    let config = json!({ "max_depth": 2, "max_complexity": 3 });
    let plugin = create_plugin("graphql", &config).unwrap().unwrap();

    let query = "query Small { user { id } } \
                 query Huge { a { b { c { d { e { f } } } } } }";
    let mut ctx = create_graphql_context(query, Some("Small"));
    let mut headers = make_graphql_headers();
    let result = plugin.before_proxy(&mut ctx, &mut headers).await;
    assert_continue(result);
    // Selected op depth is 2 (user{ id }), well within the limit.
    assert_eq!(ctx.metadata.get("graphql_depth").unwrap(), "2");

    // And selecting the huge operation IS rejected.
    let mut ctx = create_graphql_context(query, Some("Huge"));
    let mut headers = make_graphql_headers();
    let result = plugin.before_proxy(&mut ctx, &mut headers).await;
    assert_reject(result, Some(400));
}

#[tokio::test]
async fn test_multi_operation_without_operation_name_rejected() {
    // The GraphQL spec requires operationName when a document defines more than
    // one operation. Omitting it must be rejected rather than silently analyzing
    // (and rate-limiting against) the wrong operation.
    let config = json!({ "max_depth": 100 });
    let plugin = create_plugin("graphql", &config).unwrap().unwrap();

    let query = "query A { user { name } } mutation B { createUser(name: \"x\") { id } }";
    let mut ctx = create_graphql_context(query, None);
    let mut headers = make_graphql_headers();
    let result = plugin.before_proxy(&mut ctx, &mut headers).await;
    assert_reject(result, Some(400));
}

#[tokio::test]
async fn test_unknown_operation_name_rejected() {
    // operationName that matches no operation in the document is a client error.
    let config = json!({ "max_depth": 100 });
    let plugin = create_plugin("graphql", &config).unwrap().unwrap();

    let query = "query A { user { name } } mutation B { createUser(name: \"x\") { id } }";
    let mut ctx = create_graphql_context(query, Some("DoesNotExist"));
    let mut headers = make_graphql_headers();
    let result = plugin.before_proxy(&mut ctx, &mut headers).await;
    assert_reject(result, Some(400));
}

#[tokio::test]
async fn test_single_named_operation_without_operation_name_allowed() {
    // A single named operation does not require operationName (only multi-op
    // documents do), so this must still be analyzed normally.
    let config = json!({ "max_depth": 100 });
    let plugin = create_plugin("graphql", &config).unwrap().unwrap();

    let query = "query OnlyOne { user { name } }";
    let mut ctx = create_graphql_context(query, None);
    let mut headers = make_graphql_headers();
    let result = plugin.before_proxy(&mut ctx, &mut headers).await;
    assert_continue(result);
    assert_eq!(ctx.metadata.get("graphql_operation_type").unwrap(), "query");
    assert_eq!(
        ctx.metadata.get("graphql_operation_name").unwrap(),
        "OnlyOne"
    );
}

// ── Fragment-aware depth/complexity (finding #66) ──

#[tokio::test]
async fn test_fragment_spread_counts_toward_depth_limit() {
    // The operation spreads a fragment whose resolved nesting pushes total depth
    // past the limit. Each literal block (the operation and the fragment) nests
    // only 3 levels — within max_depth=4 — but the RESOLVED depth at the spread
    // site is 5. Before the fix fragments were not expanded, so the measured
    // depth was 3 and this bypassed the limit; now it is rejected.
    let config = json!({ "max_depth": 4 });
    let plugin = create_plugin("graphql", &config).unwrap().unwrap();

    let query = "query { a { b { ...Deep } } } fragment Deep on T { c { d { e } } }";
    let mut ctx = create_graphql_context(query, None);
    let mut headers = make_graphql_headers();
    let result = plugin.before_proxy(&mut ctx, &mut headers).await;
    assert_reject(result, Some(400));
    assert_eq!(
        ctx.metadata.get("graphql_depth").unwrap(),
        "5",
        "resolved depth must include the expanded fragment's nesting"
    );
}

#[tokio::test]
async fn test_fragment_syntax_without_structured_operation_is_rejected() {
    let config = json!({ "max_depth": 100 });
    let plugin = create_plugin("graphql", &config).unwrap().unwrap();

    let query = "fragment OnlyFragment on Query { viewer { id } }";
    let mut ctx = create_graphql_context(query, None);
    let mut headers = make_graphql_headers();
    let result = plugin.before_proxy(&mut ctx, &mut headers).await;

    assert_reject(result, Some(400));
}

#[tokio::test]
async fn test_fragment_spread_under_depth_limit_allowed() {
    // The same query passes when the limit accommodates the resolved depth,
    // confirming the expansion is accurate rather than blanket-rejecting
    // fragment-using queries.
    let config = json!({ "max_depth": 5 });
    let plugin = create_plugin("graphql", &config).unwrap().unwrap();

    let query = "query { a { b { ...Deep } } } fragment Deep on T { c { d { e } } }";
    let mut ctx = create_graphql_context(query, None);
    let mut headers = make_graphql_headers();
    let result = plugin.before_proxy(&mut ctx, &mut headers).await;
    assert_continue(result);
}

#[tokio::test]
async fn test_fragment_fanout_counts_toward_complexity_limit() {
    // A wide fragment spread at multiple sites: measured complexity before the
    // fix counted the fragment's fields once (~5) plus 3 spread tokens (~8);
    // the resolved complexity is 5 fields x 3 spreads = 15. With max_complexity
    // 10 the pre-fix value passed but the resolved value must be rejected.
    let config = json!({ "max_complexity": 10 });
    let plugin = create_plugin("graphql", &config).unwrap().unwrap();

    let query = "query { ...F ...F ...F } fragment F on T { a b c d e }";
    let mut ctx = create_graphql_context(query, None);
    let mut headers = make_graphql_headers();
    let result = plugin.before_proxy(&mut ctx, &mut headers).await;
    assert_reject(result, Some(400));
    assert_eq!(
        ctx.metadata.get("graphql_complexity").unwrap(),
        "15",
        "each fragment spread site must contribute the fragment's full field count"
    );
}

#[tokio::test]
async fn test_nested_fragment_chain_expands() {
    // Chained fragments (A spreads B spreads C) must compose their depth.
    let config = json!({ "max_depth": 3 });
    let plugin = create_plugin("graphql", &config).unwrap().unwrap();

    let query = "query { ...A } \
                 fragment A on T { a { ...B } } \
                 fragment B on T { b { ...C } } \
                 fragment C on T { c { d } }";
    let mut ctx = create_graphql_context(query, None);
    let mut headers = make_graphql_headers();
    let result = plugin.before_proxy(&mut ctx, &mut headers).await;
    // Resolved depth: a(1) > b(2) > c(3) > d(4) = 4 > max_depth 3 -> reject.
    assert_reject(result, Some(400));
    assert_eq!(ctx.metadata.get("graphql_depth").unwrap(), "4");
}

#[tokio::test]
async fn test_cyclic_fragment_terminates() {
    // Cyclic fragment spreads (A -> B -> A) are invalid GraphQL but a hostile
    // client can still send them. The analyzer MUST terminate (cycle-safe) and
    // not recurse forever, which would turn the limiter into its own DoS.
    let config = json!({ "max_depth": 100, "max_complexity": 100 });
    let plugin = create_plugin("graphql", &config).unwrap().unwrap();

    let query = "query { ...A } \
                 fragment A on T { x ...B } \
                 fragment B on T { y ...A }";
    let mut ctx = create_graphql_context(query, None);
    let mut headers = make_graphql_headers();
    // Completes without hanging; tiny resolved cost is within the limits.
    let result = plugin.before_proxy(&mut ctx, &mut headers).await;
    assert_continue(result);
}

#[tokio::test]
async fn test_self_referential_fragment_terminates() {
    // A fragment that spreads itself must also terminate.
    let config = json!({ "max_depth": 100, "max_complexity": 100 });
    let plugin = create_plugin("graphql", &config).unwrap().unwrap();

    let query = "query { ...Loop } fragment Loop on T { f ...Loop }";
    let mut ctx = create_graphql_context(query, None);
    let mut headers = make_graphql_headers();
    let result = plugin.before_proxy(&mut ctx, &mut headers).await;
    assert_continue(result);
}

#[tokio::test]
async fn test_inline_fragment_does_not_add_depth() {
    // Inline fragments (`... on Type { ... }`) select fields on the same level;
    // they must not add an extra nesting level.
    let config = json!({ "max_depth": 2 });
    let plugin = create_plugin("graphql", &config).unwrap().unwrap();

    // user { ... on Admin { name } } : depth is 2 (user -> name), not 3.
    let query = "{ user { ... on Admin { name } } }";
    let mut ctx = create_graphql_context(query, None);
    let mut headers = make_graphql_headers();
    let result = plugin.before_proxy(&mut ctx, &mut headers).await;
    assert_continue(result);
    assert_eq!(ctx.metadata.get("graphql_depth").unwrap(), "2");
}

#[tokio::test]
async fn test_keyword_spelled_nested_fields_count_toward_complexity() {
    // Selection-set identifiers that spell GraphQL keywords are legal field
    // names. `{ on { on { on { x } } } }` is four fields; the old keyword skip
    // measured complexity 1 (`x` only).
    let config = json!({ "max_complexity": 100 });
    let plugin = create_plugin("graphql", &config).unwrap().unwrap();

    let query = "{ on { on { on { x } } } }";
    let mut ctx = create_graphql_context(query, None);
    let mut headers = make_graphql_headers();
    let result = plugin.before_proxy(&mut ctx, &mut headers).await;
    assert_continue(result);
    let complexity: u32 = ctx
        .metadata
        .get("graphql_complexity")
        .unwrap()
        .parse()
        .unwrap();
    assert!(
        complexity >= 4,
        "keyword-named nested fields must count toward complexity, got {complexity}"
    );
}

#[tokio::test]
async fn test_keyword_named_fields_enforce_max_complexity() {
    let config = json!({ "max_complexity": 3 });
    let plugin = create_plugin("graphql", &config).unwrap().unwrap();

    let query = "{ on { on { on { x } } } }";
    let mut ctx = create_graphql_context(query, None);
    let mut headers = make_graphql_headers();
    let result = plugin.before_proxy(&mut ctx, &mut headers).await;
    assert_reject(result, Some(400));
    assert_eq!(ctx.metadata.get("graphql_complexity").unwrap(), "4");
}

#[tokio::test]
async fn test_aliased_keyword_named_fields_count_aliases_and_complexity() {
    // `{ a1: on a2: on a3: on }` is three aliases and three fields.
    let config = json!({ "max_complexity": 100, "max_aliases": 100 });
    let plugin = create_plugin("graphql", &config).unwrap().unwrap();

    let query = "{ a1: on a2: on a3: on }";
    let mut ctx = create_graphql_context(query, None);
    let mut headers = make_graphql_headers();
    let result = plugin.before_proxy(&mut ctx, &mut headers).await;
    assert_continue(result);
    assert_eq!(ctx.metadata.get("graphql_complexity").unwrap(), "3");
}

#[tokio::test]
async fn test_aliased_keyword_named_fields_enforce_max_aliases() {
    let config = json!({ "max_aliases": 2 });
    let plugin = create_plugin("graphql", &config).unwrap().unwrap();

    let query = "{ a1: on a2: on a3: on }";
    let mut ctx = create_graphql_context(query, None);
    let mut headers = make_graphql_headers();
    match plugin.before_proxy(&mut ctx, &mut headers).await {
        PluginResult::Reject {
            status_code, body, ..
        } => {
            assert_eq!(status_code, 400);
            assert!(
                body.contains("Query uses 3 aliases, maximum allowed is 2"),
                "expected alias-budget rejection, got {body}"
            );
        }
        other => panic!("Expected Reject(400), got {other:?}"),
    }
}

#[tokio::test]
async fn test_every_document_keyword_spelling_is_a_legal_field_name() {
    // Every identifier the selection-set analyzer used to skip is a legal
    // field name inside `{ ... }`.
    let spellings = [
        "query",
        "mutation",
        "subscription",
        "fragment",
        "on",
        "true",
        "false",
        "null",
    ];
    let config = json!({ "max_complexity": 100 });
    let plugin = create_plugin("graphql", &config).unwrap().unwrap();

    for name in spellings {
        let query = format!("{{ {name} {{ x }} }}");
        let mut ctx = create_graphql_context(&query, None);
        let mut headers = make_graphql_headers();
        let result = plugin.before_proxy(&mut ctx, &mut headers).await;
        assert_continue(result);
        assert_eq!(
            ctx.metadata.get("graphql_complexity").unwrap(),
            "2",
            "{name} as a nested field must count as complexity 2"
        );
    }
}

#[tokio::test]
async fn test_inline_fragment_on_is_not_counted_as_a_field() {
    // `{ ... on Foo { x } }` must count only `x`. Counting the type-condition
    // keyword would inflate complexity after the selection-set keyword skip
    // is removed.
    let config = json!({ "max_complexity": 100 });
    let plugin = create_plugin("graphql", &config).unwrap().unwrap();

    let query = "{ ... on Foo { x } }";
    let mut ctx = create_graphql_context(query, None);
    let mut headers = make_graphql_headers();
    let result = plugin.before_proxy(&mut ctx, &mut headers).await;
    assert_continue(result);
    assert_eq!(
        ctx.metadata.get("graphql_complexity").unwrap(),
        "1",
        "inline-fragment `on` must not be double-counted as a field"
    );
    assert_eq!(ctx.metadata.get("graphql_depth").unwrap(), "1");
}

#[tokio::test]
async fn test_argument_literals_and_directives_are_not_fields() {
    // true/false/null in arguments, `@on` directives, and keyword spellings
    // inside strings/comments must not contribute complexity.
    let config = json!({ "max_complexity": 100 });
    let plugin = create_plugin("graphql", &config).unwrap().unwrap();

    let query = r#"{ x(flag: true, n: null, b: false) @on(if: true) # on query
y(msg: "on true null") }"#;
    let mut ctx = create_graphql_context(query, None);
    let mut headers = make_graphql_headers();
    let result = plugin.before_proxy(&mut ctx, &mut headers).await;
    assert_continue(result);
    assert_eq!(
        ctx.metadata.get("graphql_complexity").unwrap(),
        "2",
        "argument literals, directives, strings, and comments must not count as fields"
    );
}

#[tokio::test]
async fn test_top_level_operation_keywords_still_parse() {
    let config = json!({ "max_complexity": 100 });
    let plugin = create_plugin("graphql", &config).unwrap().unwrap();

    for (query, op_type) in [
        ("query { user { id } }", "query"),
        ("mutation { createUser { id } }", "mutation"),
        ("subscription { messageAdded { content } }", "subscription"),
    ] {
        let mut ctx = create_graphql_context(query, None);
        let mut headers = make_graphql_headers();
        let result = plugin.before_proxy(&mut ctx, &mut headers).await;
        assert_continue(result);
        assert_eq!(ctx.metadata.get("graphql_operation_type").unwrap(), op_type);
        assert_eq!(ctx.metadata.get("graphql_complexity").unwrap(), "2");
    }
}

#[tokio::test]
async fn test_introspection_inside_fragment_is_detected() {
    // __schema hidden behind a fragment spread must still trip introspection
    // control once fragments are expanded into the selected operation.
    let config = json!({ "introspection_allowed": false });
    let plugin = create_plugin("graphql", &config).unwrap().unwrap();

    let query =
        "query { ...Introspect } fragment Introspect on Query { __schema { types { name } } }";
    let mut ctx = create_graphql_context(query, None);
    let mut headers = make_graphql_headers();
    let result = plugin.before_proxy(&mut ctx, &mut headers).await;
    assert_reject(result, Some(403));
}

#[tokio::test]
async fn test_deep_non_cyclic_fragment_chain_is_bounded() {
    // A long, non-cyclic chain of single-spread fragments (F0 -> F1 -> ... ->
    // Fn) would, if expanded naively, recurse once per link and could overflow
    // the stack — a DoS in the limiter itself. The analyzer caps recursion and
    // must reject (400) rather than panic/hang. The chain has no braces, so
    // measured depth stays 1; only the recursion bound stops it.
    let config = json!({ "max_depth": 1000, "max_complexity": 1_000_000 });
    let plugin = create_plugin("graphql", &config).unwrap().unwrap();

    let chain_len = 4000;
    let mut query = String::from("query { ...F0 }");
    for n in 0..chain_len {
        if n + 1 < chain_len {
            query.push_str(&format!(" fragment F{n} on T {{ ...F{} }}", n + 1));
        } else {
            query.push_str(&format!(" fragment F{n} on T {{ leaf }}"));
        }
    }

    let mut ctx = create_graphql_context(&query, None);
    let mut headers = make_graphql_headers();
    // Must complete (no stack overflow / hang) and reject the over-deep chain.
    let result = plugin.before_proxy(&mut ctx, &mut headers).await;
    assert_reject(result, Some(400));
}

// ── Final backend-visible envelope re-evaluation (GHSA-3xrr-4h3f-89pc) ──

/// The exact envelope `before_proxy` inspected must not be parsed or charged a
/// second time in the final request-body phase.
#[tokio::test]
async fn unchanged_envelope_is_not_re_evaluated_in_the_final_phase() {
    let plugin = create_plugin("graphql", &json!({ "max_depth": 3 }))
        .unwrap()
        .unwrap();
    let mut ctx = create_graphql_context("{ a { b } }", None);
    let mut headers = make_graphql_headers();

    assert_continue(plugin.before_proxy(&mut ctx, &mut headers).await);
    let depth_after_before_proxy = ctx.metadata.get("graphql_depth").cloned();

    let envelope = ctx.metadata.get("request_body").cloned().unwrap();
    let result = plugin
        .on_final_request_body_with_context(&mut ctx, &headers, envelope.as_bytes())
        .await;

    assert_continue(result);
    assert_eq!(
        ctx.metadata.get("graphql_depth").cloned(),
        depth_after_before_proxy
    );
}

/// A request transform that replaces `query` with a deeper document after
/// `before_proxy` allowed the original must be caught over the dispatched
/// envelope.
#[tokio::test]
async fn transformed_envelope_is_re_evaluated_against_the_depth_limit() {
    let plugin = create_plugin("graphql", &json!({ "max_depth": 2 }))
        .unwrap()
        .unwrap();
    let mut ctx = create_graphql_context("{ a }", None);
    let mut headers = make_graphql_headers();
    assert_continue(plugin.before_proxy(&mut ctx, &mut headers).await);

    let transformed = json!({ "query": "{ a { b { c { d { e } } } } }" }).to_string();
    let result = plugin
        .on_final_request_body_with_context(&mut ctx, &headers, transformed.as_bytes())
        .await;

    assert_reject(result, Some(400));
}

/// The same hazard through introspection: a rename can install an introspecting
/// document after the policy allowed an ordinary one.
#[tokio::test]
async fn transformed_envelope_is_re_evaluated_against_introspection_policy() {
    let plugin = create_plugin("graphql", &json!({ "introspection_allowed": false }))
        .unwrap()
        .unwrap();
    let mut ctx = create_graphql_context("{ user { id } }", None);
    let mut headers = make_graphql_headers();
    assert_continue(plugin.before_proxy(&mut ctx, &mut headers).await);

    let transformed = json!({ "query": "{ __schema { types { name } } }" }).to_string();
    let result = plugin
        .on_final_request_body_with_context(&mut ctx, &headers, transformed.as_bytes())
        .await;

    assert_reject(result, Some(403));
}

/// A transform that destroys the inspectable envelope is a rejection, not a
/// pass-through.
#[tokio::test]
async fn transformed_envelope_that_is_not_json_fails_closed() {
    let plugin = create_plugin("graphql", &json!({ "max_depth": 5 }))
        .unwrap()
        .unwrap();
    let mut ctx = create_graphql_context("{ a }", None);
    let mut headers = make_graphql_headers();
    assert_continue(plugin.before_proxy(&mut ctx, &mut headers).await);

    let result = plugin
        .on_final_request_body_with_context(&mut ctx, &headers, b"not json at all")
        .await;

    assert_reject(result, Some(400));
}

/// A request this instance never admitted has no recorded envelope digest, so
/// the final phase stays inert rather than inventing a decision.
#[tokio::test]
async fn final_phase_is_inert_without_a_before_proxy_decision() {
    let plugin = create_plugin("graphql", &json!({ "max_depth": 1 }))
        .unwrap()
        .unwrap();
    let mut ctx = create_graphql_context("{ a { b { c } } }", None);
    let headers = make_graphql_headers();

    let envelope = ctx.metadata.get("request_body").cloned().unwrap();
    let result = plugin
        .on_final_request_body_with_context(&mut ctx, &headers, envelope.as_bytes())
        .await;

    assert_continue(result);
}

/// Two configured instances each keep their own envelope marker, so one cannot
/// consume the other's decision.
#[tokio::test]
async fn multiple_instances_track_their_own_envelope_decisions() {
    let permissive = create_plugin("graphql", &json!({ "max_depth": 10 }))
        .unwrap()
        .unwrap();
    let strict = create_plugin("graphql", &json!({ "max_depth": 2 }))
        .unwrap()
        .unwrap();
    let mut ctx = create_graphql_context("{ a }", None);
    let mut headers = make_graphql_headers();
    assert_continue(permissive.before_proxy(&mut ctx, &mut headers).await);
    assert_continue(strict.before_proxy(&mut ctx, &mut headers).await);

    let transformed = json!({ "query": "{ a { b { c { d } } } }" }).to_string();
    assert_continue(
        permissive
            .on_final_request_body_with_context(&mut ctx, &headers, transformed.as_bytes())
            .await,
    );
    assert_reject(
        strict
            .on_final_request_body_with_context(&mut ctx, &headers, transformed.as_bytes())
            .await,
        Some(400),
    );
}

// ── Complete `Ignored` grammar: UnicodeBOM (GHSA-wr84-jm45-wrwp) ──

/// A `UnicodeBOM` between the operation keyword and the operation name is an
/// ignored token, so the operation is still NAMED and its configured
/// named-operation budget is consulted. Treating the BOM as an unknown byte
/// parsed the document as anonymous and let the budget be bypassed entirely.
#[tokio::test]
async fn bom_before_the_operation_name_keeps_the_named_operation_budget() {
    let config = json!({
        "operation_rate_limits": {
            "GetUser": { "max_requests": 1, "window_seconds": 60 }
        }
    });
    let plugin = create_plugin("graphql", &config).unwrap().unwrap();
    let query = "query\u{feff}GetUser { user { name } }";

    let mut ctx = create_graphql_context(query, None);
    let mut headers = make_graphql_headers();
    assert_continue(plugin.before_proxy(&mut ctx, &mut headers).await);
    let operation_name = ctx.metadata.get("graphql_operation_name").cloned();
    assert_eq!(
        operation_name.as_deref(),
        Some("GetUser"),
        "a BOM is an ignored token, so the operation keeps its name"
    );

    let mut ctx = create_graphql_context(query, None);
    let mut headers = make_graphql_headers();
    let result = plugin.before_proxy(&mut ctx, &mut headers).await;
    assert_reject(result, Some(429));
}

/// Every ignored-token class is equivalent between an operation keyword and its
/// name: whitespace, line terminators, commas, comments, and the BOM.
#[tokio::test]
async fn every_ignored_token_class_keeps_the_operation_name() {
    let config = json!({ "max_complexity": 100 });
    let plugin = create_plugin("graphql", &config).unwrap().unwrap();

    for separator in [
        " ",
        "\n",
        ",",
        "# ignored\n",
        "\u{feff}",
        "\u{feff} ,# ignored\n\u{feff}",
    ] {
        let query = format!("query{separator}GetUser {{ user {{ name }} }}");
        let mut ctx = create_graphql_context(&query, None);
        let mut headers = make_graphql_headers();
        assert_continue(plugin.before_proxy(&mut ctx, &mut headers).await);
        let operation_name = ctx.metadata.get("graphql_operation_name").cloned();
        assert_eq!(
            operation_name.as_deref(),
            Some("GetUser"),
            "separator {separator:?} must leave the operation named"
        );
        assert_eq!(ctx.metadata.get("graphql_complexity").unwrap(), "2");
    }
}

/// A BOM must not hide the `mutation` keyword from the whole-document fallback
/// scan either, which would downgrade the operation type and charge the wrong
/// per-type budget. The unbalanced document is what forces the fallback: the
/// structured parser finds no complete operation definition in it.
#[tokio::test]
async fn bom_before_a_leading_mutation_keyword_keeps_the_operation_type() {
    let config = json!({
        "type_rate_limits": {
            "mutation": { "max_requests": 1, "window_seconds": 60 }
        }
    });

    for query in [
        "\u{feff}mutation { createUser { id } }",
        "\u{feff}mutation { createUser { id }",
    ] {
        // A fresh instance per spelling so each starts with an unspent budget.
        let plugin = create_plugin("graphql", &config).unwrap().unwrap();

        let mut ctx = create_graphql_context(query, None);
        let mut headers = make_graphql_headers();
        assert_continue(plugin.before_proxy(&mut ctx, &mut headers).await);
        assert_eq!(
            ctx.metadata.get("graphql_operation_type").unwrap(),
            "mutation",
            "a leading BOM must not downgrade {query:?} to a query operation"
        );

        let mut ctx = create_graphql_context(query, None);
        let mut headers = make_graphql_headers();
        let result = plugin.before_proxy(&mut ctx, &mut headers).await;
        assert_reject(result, Some(429));
    }
}

/// The BOM is ignored wherever the other ignored tokens are: before an alias
/// colon and before a fragment name. A fragment whose name the parser loses is
/// never expanded, which hides everything it selects from the analyzer.
#[tokio::test]
async fn bom_is_ignored_before_alias_colons_and_fragment_names() {
    let alias_plugin = create_plugin("graphql", &json!({ "max_aliases": 1 }))
        .unwrap()
        .unwrap();
    let mut ctx = create_graphql_context("{ a1\u{feff}: f a2\u{feff}: f }", None);
    let mut headers = make_graphql_headers();
    assert_reject(
        alias_plugin.before_proxy(&mut ctx, &mut headers).await,
        Some(400),
    );

    let introspect = create_plugin("graphql", &json!({ "introspection_allowed": false }))
        .unwrap()
        .unwrap();
    let query = "query { ...F } fragment\u{feff}F on Query { __schema { types { name } } }";
    let mut ctx = create_graphql_context(query, None);
    let mut headers = make_graphql_headers();
    let result = introspect.before_proxy(&mut ctx, &mut headers).await;
    assert_reject(result, Some(403));
}

// ── Directive punctuator and directive name are distinct tokens (#5130) ──

/// `@` and the directive name are separate lexical tokens, so any ignored token
/// may sit between them. Inferring directive context from the immediately
/// preceding byte counted the directive name as a selected field and rejected
/// legitimate traffic with a complexity one higher than the adjacent spelling.
#[tokio::test]
async fn ignored_tokens_after_the_directive_punctuator_do_not_add_complexity() {
    let config = json!({ "max_complexity": 100 });
    let plugin = create_plugin("graphql", &config).unwrap().unwrap();

    for separator in ["", " ", "\n", ",", "# ignored\n", "\u{feff}", " ,\n"] {
        let query = format!("{{ ok @{separator}skip(if: false) }}");
        let mut ctx = create_graphql_context(&query, None);
        let mut headers = make_graphql_headers();
        assert_continue(plugin.before_proxy(&mut ctx, &mut headers).await);
        assert_eq!(
            ctx.metadata.get("graphql_complexity").unwrap(),
            "1",
            "separator {separator:?} after `@` must not turn the directive into a field"
        );
    }
}

/// The same rule in the whole-document fallback scanner. An unbalanced document
/// is what reaches it: the structured parser models no complete operation there
/// and hands the document to the legacy scan.
#[tokio::test]
async fn fallback_scanner_does_not_count_spaced_directives_as_fields() {
    let config = json!({ "max_complexity": 100 });
    let plugin = create_plugin("graphql", &config).unwrap().unwrap();

    for separator in ["", " ", ",", "\u{feff}"] {
        let query = format!("{{ ok @{separator}skip(if: false)");
        let mut ctx = create_graphql_context(&query, None);
        let mut headers = make_graphql_headers();
        assert_continue(plugin.before_proxy(&mut ctx, &mut headers).await);
        assert_eq!(
            ctx.metadata.get("graphql_complexity").unwrap(),
            "1",
            "fallback separator {separator:?} must not turn the directive into a field"
        );
    }
}

/// A one-field query with a directive must be admitted under `max_complexity: 1`
/// however its directive is spelled — the reported reproduction.
#[tokio::test]
async fn spaced_directive_is_admitted_under_a_one_field_complexity_budget() {
    let config = json!({ "max_complexity": 1 });
    let plugin = create_plugin("graphql", &config).unwrap().unwrap();

    for query in ["{ ok @skip(if: false) }", "{ ok @ skip(if: false) }"] {
        let mut ctx = create_graphql_context(query, None);
        let mut headers = make_graphql_headers();
        assert_continue(plugin.before_proxy(&mut ctx, &mut headers).await);
    }
}

/// Directive arguments must still be skipped, and a genuine field after a
/// directive must still be counted.
#[tokio::test]
async fn directives_still_skip_arguments_and_following_fields_still_count() {
    let config = json!({ "max_complexity": 100 });
    let plugin = create_plugin("graphql", &config).unwrap().unwrap();

    let query = "{ ok @ include(if: $show, other: nested) second }";
    let mut ctx = create_graphql_context(query, None);
    let mut headers = make_graphql_headers();
    assert_continue(plugin.before_proxy(&mut ctx, &mut headers).await);
    assert_eq!(ctx.metadata.get("graphql_complexity").unwrap(), "2");
}

// ── One token per rate bucket per request (#5131) ──

/// A body transform that changes the envelope without changing the operation
/// (adding an unrelated `extensions` member) must cost ONE token, not two.
/// Charging the final phase again refused the very first request under
/// `max_requests: 1`, with the backend never contacted.
#[tokio::test]
async fn harmless_body_transform_charges_the_type_budget_once() {
    let config = json!({
        "type_rate_limits": {
            "query": { "max_requests": 1, "window_seconds": 60 }
        }
    });
    let plugin = create_plugin("graphql", &config).unwrap().unwrap();

    let mut ctx = create_graphql_context("{ ok }", None);
    let mut headers = make_graphql_headers();
    assert_continue(plugin.before_proxy(&mut ctx, &mut headers).await);

    let transformed = r#"{"query":"{ ok }","extensions":{"audit":"enabled"}}"#;
    assert_continue(
        plugin
            .on_final_request_body_with_context(&mut ctx, &headers, transformed.as_bytes())
            .await,
    );
}

/// The same for a named-operation budget: the operation name is unchanged, so
/// the transformed envelope reuses the token the early phase already spent.
#[tokio::test]
async fn harmless_body_transform_charges_the_named_budget_once() {
    let config = json!({
        "operation_rate_limits": {
            "GetUser": { "max_requests": 1, "window_seconds": 60 }
        }
    });
    let plugin = create_plugin("graphql", &config).unwrap().unwrap();

    let query = "query GetUser { user { name } }";
    let mut ctx = create_graphql_context(query, Some("GetUser"));
    let mut headers = make_graphql_headers();
    assert_continue(plugin.before_proxy(&mut ctx, &mut headers).await);

    let transformed = json!({
        "query": query,
        "operationName": "GetUser",
        "extensions": { "audit": "enabled" }
    });
    let transformed = transformed.to_string();
    assert_continue(
        plugin
            .on_final_request_body_with_context(&mut ctx, &headers, transformed.as_bytes())
            .await,
    );
}

/// Re-serializing the same envelope (different bytes, same operation) is the
/// other shape of the same hazard.
#[tokio::test]
async fn reserialized_envelope_does_not_spend_a_second_token() {
    let config = json!({
        "type_rate_limits": {
            "query": { "max_requests": 1, "window_seconds": 60 }
        }
    });
    let plugin = create_plugin("graphql", &config).unwrap().unwrap();

    let mut ctx = create_graphql_context("{ ok }", None);
    let mut headers = make_graphql_headers();
    assert_continue(plugin.before_proxy(&mut ctx, &mut headers).await);

    let reserialized = "{\n  \"query\": \"{ ok }\"\n}";
    assert_continue(
        plugin
            .on_final_request_body_with_context(&mut ctx, &headers, reserialized.as_bytes())
            .await,
    );
}

/// Charging once is not the same as not charging: a second request over the
/// same budget must still be refused.
#[tokio::test]
async fn the_single_charge_still_exhausts_the_budget_for_the_next_request() {
    let config = json!({
        "type_rate_limits": {
            "query": { "max_requests": 1, "window_seconds": 60 }
        }
    });
    let plugin = create_plugin("graphql", &config).unwrap().unwrap();

    let transformed = r#"{"query":"{ ok }","extensions":{"audit":"enabled"}}"#;

    let mut ctx = create_graphql_context("{ ok }", None);
    let mut headers = make_graphql_headers();
    assert_continue(plugin.before_proxy(&mut ctx, &mut headers).await);
    assert_continue(
        plugin
            .on_final_request_body_with_context(&mut ctx, &headers, transformed.as_bytes())
            .await,
    );

    let mut ctx = create_graphql_context("{ ok }", None);
    let mut headers = make_graphql_headers();
    let result = plugin.before_proxy(&mut ctx, &mut headers).await;
    assert_reject(result, Some(429));
}

/// A transform that actually selects a DIFFERENT operation type reaches a
/// bucket this request never claimed, so the dispatched operation is still
/// charged and still enforced.
#[tokio::test]
async fn a_transform_to_another_operation_type_is_charged_and_enforced() {
    let config = json!({
        "type_rate_limits": {
            "mutation": { "max_requests": 1, "window_seconds": 60 }
        }
    });
    let plugin = create_plugin("graphql", &config).unwrap().unwrap();
    let transformed = r#"{"query":"mutation { createUser { id } }"}"#;

    // First request: the query passes freely, the transformed mutation spends
    // the mutation budget's only token.
    let mut ctx = create_graphql_context("{ ok }", None);
    let mut headers = make_graphql_headers();
    assert_continue(plugin.before_proxy(&mut ctx, &mut headers).await);
    assert_continue(
        plugin
            .on_final_request_body_with_context(&mut ctx, &headers, transformed.as_bytes())
            .await,
    );

    // Second request: the same transform now finds the mutation budget spent.
    let mut ctx = create_graphql_context("{ ok }", None);
    let mut headers = make_graphql_headers();
    assert_continue(plugin.before_proxy(&mut ctx, &mut headers).await);
    assert_reject(
        plugin
            .on_final_request_body_with_context(&mut ctx, &headers, transformed.as_bytes())
            .await,
        Some(429),
    );
}

/// The same for a renamed operation: the early phase charged `GetUser`, and the
/// dispatched `GetOrder` is charged against its own budget.
#[tokio::test]
async fn a_transform_to_another_operation_name_is_charged_and_enforced() {
    let config = json!({
        "operation_rate_limits": {
            "GetOrder": { "max_requests": 1, "window_seconds": 60 }
        }
    });
    let plugin = create_plugin("graphql", &config).unwrap().unwrap();
    let transformed = r#"{"query":"query GetOrder { order { id } }","operationName":"GetOrder"}"#;

    let mut ctx = create_graphql_context("query GetUser { user { name } }", Some("GetUser"));
    let mut headers = make_graphql_headers();
    assert_continue(plugin.before_proxy(&mut ctx, &mut headers).await);
    assert_continue(
        plugin
            .on_final_request_body_with_context(&mut ctx, &headers, transformed.as_bytes())
            .await,
    );

    let mut ctx = create_graphql_context("query GetUser { user { name } }", Some("GetUser"));
    let mut headers = make_graphql_headers();
    assert_continue(plugin.before_proxy(&mut ctx, &mut headers).await);
    assert_reject(
        plugin
            .on_final_request_body_with_context(&mut ctx, &headers, transformed.as_bytes())
            .await,
        Some(429),
    );
}

/// Two configured instances build identical bucket key strings over separate
/// budgets, so the claim is per instance: neither may consume the other's, and
/// neither may charge itself twice.
#[tokio::test]
async fn the_once_per_request_claim_is_scoped_to_one_instance() {
    let config = json!({
        "type_rate_limits": {
            "query": { "max_requests": 1, "window_seconds": 60 }
        }
    });
    let first = create_plugin("graphql", &config).unwrap().unwrap();
    let second = create_plugin("graphql", &config).unwrap().unwrap();

    let mut ctx = create_graphql_context("{ ok }", None);
    let mut headers = make_graphql_headers();
    assert_continue(first.before_proxy(&mut ctx, &mut headers).await);
    assert_continue(second.before_proxy(&mut ctx, &mut headers).await);

    let transformed = r#"{"query":"{ ok }","extensions":{"audit":"enabled"}}"#;
    assert_continue(
        first
            .on_final_request_body_with_context(&mut ctx, &headers, transformed.as_bytes())
            .await,
    );
    assert_continue(
        second
            .on_final_request_body_with_context(&mut ctx, &headers, transformed.as_bytes())
            .await,
    );
}

/// Structural policy is unaffected by the accounting claim: a transformed
/// envelope is still fully re-parsed and re-decided even when its rate bucket
/// was already charged.
#[tokio::test]
async fn structural_policy_still_runs_over_an_already_charged_bucket() {
    let config = json!({
        "max_depth": 2,
        "type_rate_limits": {
            "query": { "max_requests": 10, "window_seconds": 60 }
        }
    });
    let plugin = create_plugin("graphql", &config).unwrap().unwrap();

    let mut ctx = create_graphql_context("{ a }", None);
    let mut headers = make_graphql_headers();
    assert_continue(plugin.before_proxy(&mut ctx, &mut headers).await);

    let transformed = r#"{"query":"{ a { b { c { d } } } }"}"#;
    assert_reject(
        plugin
            .on_final_request_body_with_context(&mut ctx, &headers, transformed.as_bytes())
            .await,
        Some(400),
    );
}
