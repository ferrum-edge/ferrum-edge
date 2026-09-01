//! Authentication rejects on AI gateway routes use the OpenAI nested envelope.

use chrono::Utc;
use ferrum_edge::ConsumerIndex;
use ferrum_edge::config::types::{
    AuthMode, GatewayConfig, PluginConfig, PluginScope, default_namespace,
};
use ferrum_edge::plugin_cache::PluginCache;
use ferrum_edge::plugins::key_auth::KeyAuth;
use ferrum_edge::plugins::{Plugin, PluginResult, RequestContext};
use ferrum_edge::proxy::{
    adapt_auth_reject_for_openai_envelope, run_authentication_phase,
    run_authentication_phase_with_envelope,
};
use serde_json::{Value, json};
use std::sync::Arc;

use super::plugin_cache_tests::{make_plugin_config, make_proxy};
use super::plugin_utils::{create_test_consumer, create_test_context};

fn ai_federation_plugin_config(proxy_id: &str) -> PluginConfig {
    let mut plugin = make_plugin_config(
        "ai-fed",
        "ai_federation",
        PluginScope::Proxy,
        Some(proxy_id),
        true,
    );
    plugin.config = json!({
        "providers": [{
            "name": "openai",
            "provider_type": "openai",
            "api_key": "sk-test-key",
            "model_patterns": ["gpt-*"]
        }]
    });
    plugin
}

fn gateway_with_plugins(proxy_id: &str, plugin_configs: Vec<PluginConfig>) -> GatewayConfig {
    GatewayConfig {
        version: "1".to_string(),
        proxies: vec![make_proxy(proxy_id, "/ai", vec!["key-auth", "ai-fed"])],
        consumers: vec![],
        plugin_configs,
        upstreams: vec![],
        loaded_at: Utc::now(),
        known_namespaces: Vec::new(),
        ..Default::default()
    }
}

fn expected_openai_auth_body(message: &str, code: &str) -> Value {
    json!({
        "error": {
            "message": message,
            "type": "invalid_request_error",
            "param": null,
            "code": code,
        }
    })
}

fn assert_openai_auth_body(body: &[u8], message: &str, code: &str) {
    let parsed: Value = serde_json::from_slice(body).expect("auth reject must be JSON");
    assert_eq!(parsed, expected_openai_auth_body(message, code));
}

#[test]
fn plugin_cache_sets_openai_auth_error_envelope_flag_for_ai_plugins() {
    let config = gateway_with_plugins(
        "ai",
        vec![
            make_plugin_config("key-auth", "key_auth", PluginScope::Proxy, Some("ai"), true),
            ai_federation_plugin_config("ai"),
        ],
    );
    let cache = PluginCache::new(&config).expect("ai gateway cache must build");
    assert!(cache.uses_openai_auth_error_envelope(&default_namespace(), "ai"));

    let plain_config = GatewayConfig {
        version: "1".to_string(),
        proxies: vec![make_proxy("plain", "/plain", vec!["key-auth"])],
        consumers: vec![],
        plugin_configs: vec![make_plugin_config(
            "key-auth",
            "key_auth",
            PluginScope::Proxy,
            Some("plain"),
            true,
        )],
        upstreams: vec![],
        loaded_at: Utc::now(),
        known_namespaces: Vec::new(),
        ..Default::default()
    };
    let plain_cache = PluginCache::new(&plain_config).expect("plain cache must build");
    assert!(!plain_cache.uses_openai_auth_error_envelope(&default_namespace(), "plain"));
}

#[tokio::test]
async fn ai_route_missing_credential_uses_openai_auth_envelope() {
    let key_auth: Arc<dyn Plugin> = Arc::new(KeyAuth::new(&json!({})).unwrap());
    let auth_plugins = vec![key_auth];
    let consumer_index = ConsumerIndex::new(&[]);
    let mut ctx = RequestContext::new(
        "127.0.0.1".to_string(),
        "POST".to_string(),
        "/ai/chat".to_string(),
    );

    let (status_code, body, headers) = run_authentication_phase_with_envelope(
        AuthMode::Single,
        &auth_plugins,
        &mut ctx,
        &consumer_index,
        true,
    )
    .await
    .expect("missing credential must reject");

    assert_eq!(status_code, 401);
    assert_openai_auth_body(&body, "Authentication required", "missing_api_key");
    assert_eq!(
        headers.get("WWW-Authenticate").map(String::as_str),
        Some("ferrum-edge")
    );
}

#[tokio::test]
async fn ai_route_invalid_credential_uses_openai_auth_envelope() {
    let key_auth: Arc<dyn Plugin> = Arc::new(KeyAuth::new(&json!({})).unwrap());
    let auth_plugins = vec![key_auth];
    let consumer_index = ConsumerIndex::new(&[create_test_consumer()]);
    // Build the context directly: `create_test_context()` pre-seeds a VALID
    // `X-API-Key` and an already-identified consumer, so authentication
    // succeeds and there is no reject to inspect.
    let mut ctx = RequestContext::new(
        "127.0.0.1".to_string(),
        "POST".to_string(),
        "/ai/chat".to_string(),
    );
    ctx.headers
        .insert("X-API-Key".to_string(), "wrong-key".to_string());

    let (status_code, body, _) = run_authentication_phase_with_envelope(
        AuthMode::Single,
        &auth_plugins,
        &mut ctx,
        &consumer_index,
        true,
    )
    .await
    .expect("invalid credential must reject");

    assert_eq!(status_code, 401);
    assert_openai_auth_body(&body, "Invalid API key", "invalid_api_key");
}

#[tokio::test]
async fn non_ai_route_keeps_flat_auth_reject_body() {
    let key_auth: Arc<dyn Plugin> = Arc::new(KeyAuth::new(&json!({})).unwrap());
    let auth_plugins = vec![key_auth];
    let consumer_index = ConsumerIndex::new(&[]);
    let mut ctx = RequestContext::new(
        "127.0.0.1".to_string(),
        "GET".to_string(),
        "/plain".to_string(),
    );

    let (status_code, body, _) =
        run_authentication_phase(AuthMode::Single, &auth_plugins, &mut ctx, &consumer_index)
            .await
            .expect("missing credential must reject");

    assert_eq!(status_code, 401);
    assert_eq!(&body[..], br#"{"error":"Authentication required"}"#);
}

#[test]
fn adapt_auth_reject_leaves_non_401_and_already_nested_bodies_alone() {
    let flat = bytes::Bytes::from_static(br#"{"error":"Invalid API key"}"#);
    let adapted =
        adapt_auth_reject_for_openai_envelope(true, 403, flat.clone(), Default::default(), false);
    assert_eq!(adapted.0, 403);
    assert_eq!(adapted.1, flat);

    let nested = bytes::Bytes::from_static(
        br#"{"error":{"message":"nope","type":"invalid_request_error","param":null,"code":"invalid_api_key"}}"#,
    );
    let adapted =
        adapt_auth_reject_for_openai_envelope(true, 401, nested.clone(), Default::default(), false);
    assert_eq!(adapted.1, nested);
}

#[tokio::test]
async fn key_auth_plugin_reject_body_stays_flat_before_gateway_adaptation() {
    let plugin = KeyAuth::new(&json!({})).unwrap();
    let consumer_index = ConsumerIndex::new(&[create_test_consumer()]);
    let mut ctx = create_test_context();
    ctx.headers
        .insert("X-API-Key".to_string(), "wrong-key".to_string());

    match plugin.authenticate(&mut ctx, &consumer_index).await {
        PluginResult::Reject { body, .. } => {
            assert_eq!(body, r#"{"error":"Invalid API key"}"#);
        }
        other => panic!("expected reject, got {other:?}"),
    }
}
