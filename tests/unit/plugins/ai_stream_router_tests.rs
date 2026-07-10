//! Unit tests for the `ai_stream_router` plugin.

use super::plugin_utils::create_test_proxy;
use ferrum_edge::config::types::{BackendScheme, BackendTlsConfig};
use ferrum_edge::plugins::ai_federation::AiFederation;
use ferrum_edge::plugins::ai_stream_router::AiStreamRouter;
use ferrum_edge::plugins::{
    HTTP_ONLY_PROTOCOLS, Plugin, PluginHttpClient, PluginResult, RequestContext,
    ResponseStreamAction, ResponseStreamInspector, ResponseStreamInspectorStage,
    chain_response_stream_inspectors, priority,
};
use serde_json::{Value, json};
use std::collections::HashMap;
use std::sync::Arc;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn http_client() -> PluginHttpClient {
    PluginHttpClient::default()
}

fn build(config: Value) -> AiStreamRouter {
    AiStreamRouter::new(&config, http_client()).expect("config should be valid")
}

fn openai_and_anthropic_config() -> Value {
    json!({
        "enabled": true,
        "providers": [
            {
                "name": "openai",
                "provider_type": "openai",
                "endpoint": "https://api.openai.com/v1/chat/completions",
                "api_key": "sk-openai-secret",
                "model_patterns": ["gpt-*", "o*"],
                "priority": 1
            },
            {
                "name": "anthropic",
                "provider_type": "anthropic",
                "endpoint": "https://api.anthropic.com/v1/messages",
                "api_key": "sk-ant-secret",
                "model_patterns": ["claude-*"],
                "priority": 2,
                "anthropic_version": "2023-06-01"
            }
        ]
    })
}

fn json_headers() -> HashMap<String, String> {
    let mut h = HashMap::new();
    h.insert("content-type".to_string(), "application/json".to_string());
    h
}

fn post_ctx(body: &Value) -> RequestContext {
    let mut ctx = RequestContext::new(
        "127.0.0.1".to_string(),
        "POST".to_string(),
        "/v1/chat/completions".to_string(),
    );
    ctx.headers
        .insert("content-type".to_string(), "application/json".to_string());
    ctx.metadata.insert(
        "request_body".to_string(),
        serde_json::to_string(body).unwrap(),
    );
    ctx
}

fn reject_status(r: &PluginResult) -> Option<u16> {
    match r {
        PluginResult::Reject { status_code, .. } => Some(*status_code),
        PluginResult::RejectBinary { status_code, .. } => Some(*status_code),
        PluginResult::Continue => None,
    }
}

fn forwarded(action: ResponseStreamAction) -> Vec<u8> {
    match action {
        ResponseStreamAction::Forward(b) => b.to_vec(),
        ResponseStreamAction::Terminate(b) => b.map(|b| b.to_vec()).unwrap_or_default(),
    }
}

/// Test guardrail that cuts if provider-native Anthropic framing reaches it.
/// Its default stage is `Inspect`, so the chain must move a normalizer supplied
/// later in the vector ahead of it.
struct RejectProviderNative;

#[async_trait::async_trait]
impl ResponseStreamInspector for RejectProviderNative {
    async fn on_chunk(&mut self, chunk: &[u8]) -> ResponseStreamAction {
        if chunk
            .windows(b"content_block_delta".len())
            .any(|window| window == b"content_block_delta")
        {
            ResponseStreamAction::Terminate(None)
        } else {
            ResponseStreamAction::Forward(bytes::Bytes::copy_from_slice(chunk))
        }
    }
}

/// Replace the time-based `"created":<n>` field with a fixed value so two
/// separately-timed normalizer runs are comparable.
fn strip_created(s: &str) -> String {
    const KEY: &str = "\"created\":";
    let mut out = String::with_capacity(s.len());
    let mut rest = s;
    while let Some(idx) = rest.find(KEY) {
        out.push_str(&rest[..idx]);
        out.push_str("\"created\":0");
        rest = &rest[idx + KEY.len()..];
        let skip = rest
            .find(|c: char| !c.is_ascii_digit())
            .unwrap_or(rest.len());
        rest = &rest[skip..];
    }
    out.push_str(rest);
    out
}

// ---------------------------------------------------------------------------
// Config validation
// ---------------------------------------------------------------------------

#[test]
fn test_valid_config_parses() {
    let plugin = build(openai_and_anthropic_config());
    assert_eq!(plugin.name(), "ai_stream_router");
    assert_eq!(plugin.priority(), priority::AI_STREAM_ROUTER);
    assert_eq!(plugin.priority(), 2984);
    assert_eq!(plugin.supported_protocols(), HTTP_ONLY_PROTOCOLS);
    assert!(plugin.requires_request_body_before_before_proxy());
    assert!(plugin.modifies_request_headers());
    assert!(plugin.modifies_request_body());
    // An anthropic provider with normalization on wires the response-stream hook.
    assert!(plugin.requires_response_stream_hooks());
}

#[test]
fn test_config_must_be_object() {
    let err = AiStreamRouter::new(&json!([]), http_client())
        .err()
        .unwrap();
    assert!(err.contains("must be an object"), "{err}");
}

#[test]
fn test_config_rejects_empty_providers() {
    let err = AiStreamRouter::new(&json!({ "providers": [] }), http_client())
        .err()
        .unwrap();
    assert!(err.contains("must not be empty"), "{err}");
}

#[test]
fn test_config_rejects_missing_providers() {
    let err = AiStreamRouter::new(&json!({ "enabled": true }), http_client())
        .err()
        .unwrap();
    assert!(err.contains("providers"), "{err}");
}

#[test]
fn test_config_rejects_unknown_provider_type() {
    let cfg = json!({
        "providers": [{
            "name": "p", "provider_type": "cohere",
            "endpoint": "https://x.example.com/v1", "api_key": "k",
            "model_patterns": ["*"]
        }]
    });
    let err = AiStreamRouter::new(&cfg, http_client()).err().unwrap();
    assert!(err.contains("unknown provider_type"), "{err}");
}

#[test]
fn test_config_rejects_duplicate_provider_names() {
    let cfg = json!({
        "providers": [
            {"name": "dup", "provider_type": "openai", "endpoint": "https://a.example.com/v1", "api_key": "k", "model_patterns": ["gpt-*"]},
            {"name": "dup", "provider_type": "anthropic", "endpoint": "https://b.example.com/v1", "api_key": "k", "model_patterns": ["claude-*"]}
        ]
    });
    let err = AiStreamRouter::new(&cfg, http_client()).err().unwrap();
    assert!(err.contains("duplicate provider name"), "{err}");
}

#[test]
fn test_config_rejects_malformed_endpoint() {
    let cfg = json!({
        "providers": [{
            "name": "p", "provider_type": "openai",
            "endpoint": "not-a-url", "api_key": "k", "model_patterns": ["gpt-*"]
        }]
    });
    let err = AiStreamRouter::new(&cfg, http_client()).err().unwrap();
    assert!(
        err.contains("invalid endpoint") || err.contains("no host"),
        "{err}"
    );
}

#[test]
fn test_config_rejects_plaintext_endpoint_by_default() {
    let cfg = json!({
        "providers": [{
            "name": "p", "provider_type": "openai",
            "endpoint": "http://api.example.com/v1", "api_key": "k", "model_patterns": ["gpt-*"]
        }]
    });
    let err = AiStreamRouter::new(&cfg, http_client()).err().unwrap();
    assert!(err.contains("http://"), "{err}");
}

#[test]
fn test_config_allows_plaintext_endpoint_with_optin() {
    let cfg = json!({
        "providers": [{
            "name": "p", "provider_type": "openai",
            "endpoint": "http://api.example.com/v1", "api_key": "k",
            "model_patterns": ["gpt-*"], "allow_plaintext": true
        }]
    });
    assert!(AiStreamRouter::new(&cfg, http_client()).is_ok());
}

#[test]
fn test_config_requires_non_empty_model_patterns() {
    let cfg = json!({
        "providers": [{
            "name": "p", "provider_type": "openai",
            "endpoint": "https://a.example.com/v1", "api_key": "k", "model_patterns": []
        }]
    });
    let err = AiStreamRouter::new(&cfg, http_client()).err().unwrap();
    assert!(err.contains("model_patterns"), "{err}");
}

#[test]
fn test_config_rejects_zero_priority() {
    let cfg = json!({
        "providers": [{
            "name": "p", "provider_type": "openai",
            "endpoint": "https://a.example.com/v1", "api_key": "k",
            "model_patterns": ["gpt-*"], "priority": 0
        }]
    });
    let err = AiStreamRouter::new(&cfg, http_client()).err().unwrap();
    assert!(err.contains("positive"), "{err}");
}

#[test]
fn test_config_rejects_missing_api_key() {
    let cfg = json!({
        "providers": [{
            "name": "p", "provider_type": "openai",
            "endpoint": "https://a.example.com/v1", "model_patterns": ["gpt-*"]
        }]
    });
    let err = AiStreamRouter::new(&cfg, http_client()).err().unwrap();
    assert!(err.contains("api_key"), "{err}");
}

#[test]
fn test_config_google_gemini_not_yet_implemented() {
    let cfg = json!({
        "providers": [{
            "name": "gemini", "provider_type": "google_gemini",
            "endpoint": "https://generativelanguage.googleapis.com/v1beta/models/{model}:streamGenerateContent",
            "api_key": "k", "model_patterns": ["gemini-*"]
        }]
    });
    let err = AiStreamRouter::new(&cfg, http_client()).err().unwrap();
    assert!(err.contains("not yet implemented"), "{err}");
}

#[test]
fn test_config_rejects_ambiguous_federation_fields() {
    for field in [
        "stream",
        "streaming",
        "fallback_enabled",
        "fallback_on_status_codes",
    ] {
        let cfg = json!({
            field: true,
            "providers": [{"name": "p", "provider_type": "openai", "endpoint": "https://a.example.com/v1", "api_key": "k", "model_patterns": ["gpt-*"]}]
        });
        let err = AiStreamRouter::new(&cfg, http_client()).err().unwrap();
        assert!(
            err.contains(field) && err.contains("unsupported field"),
            "field {field}: {err}"
        );
    }
}

#[test]
fn test_disabled_plugin_does_not_wire_hooks() {
    let mut cfg = openai_and_anthropic_config();
    cfg["enabled"] = json!(false);
    let plugin = build(cfg);
    assert!(!plugin.requires_response_stream_hooks());
    assert!(!plugin.modifies_request_headers());
}

// ---------------------------------------------------------------------------
// before_proxy claim / pass-through
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_non_streaming_request_continues() {
    let plugin = build(openai_and_anthropic_config());
    let body = json!({"model": "gpt-4o", "messages": [{"role": "user", "content": "hi"}]});
    let mut ctx = post_ctx(&body);
    let mut headers = json_headers();
    let res = plugin.before_proxy(&mut ctx, &mut headers).await;
    assert!(matches!(res, PluginResult::Continue));
    // Not claimed → no route override, no coordination marker.
    assert!(ctx.route_override_backend_host.is_none());
    assert!(!ctx.metadata.contains_key("ai_stream_router_claimed"));
}

#[tokio::test]
async fn test_non_post_continues() {
    let plugin = build(openai_and_anthropic_config());
    let body = json!({"model": "gpt-4o", "stream": true, "messages": []});
    let mut ctx = post_ctx(&body);
    ctx.method = "GET".to_string();
    let mut headers = json_headers();
    let res = plugin.before_proxy(&mut ctx, &mut headers).await;
    assert!(matches!(res, PluginResult::Continue));
    assert!(ctx.route_override_backend_host.is_none());
}

#[tokio::test]
async fn test_streaming_missing_model_rejects_by_default() {
    let plugin = build(openai_and_anthropic_config());
    let body = json!({"stream": true, "messages": [{"role": "user", "content": "hi"}]});
    let mut ctx = post_ctx(&body);
    let mut headers = json_headers();
    let res = plugin.before_proxy(&mut ctx, &mut headers).await;
    assert_eq!(reject_status(&res), Some(400));
}

#[tokio::test]
async fn test_streaming_missing_model_continues_when_opted_out() {
    let mut cfg = openai_and_anthropic_config();
    cfg["fail_on_missing_model"] = json!(false);
    let plugin = build(cfg);
    let body = json!({"stream": true, "messages": []});
    let mut ctx = post_ctx(&body);
    let mut headers = json_headers();
    let res = plugin.before_proxy(&mut ctx, &mut headers).await;
    assert!(matches!(res, PluginResult::Continue));
    assert_eq!(
        ctx.metadata
            .get("ai_stream_router_pass_through")
            .map(String::as_str),
        Some("true")
    );
    assert_eq!(
        ctx.metadata.get("ai_request_streaming").map(String::as_str),
        Some("true")
    );
}

#[tokio::test]
async fn test_no_matching_provider_rejects_by_default() {
    let plugin = build(openai_and_anthropic_config());
    let body = json!({"model": "llama-3", "stream": true, "messages": []});
    let mut ctx = post_ctx(&body);
    let mut headers = json_headers();
    let res = plugin.before_proxy(&mut ctx, &mut headers).await;
    assert_eq!(reject_status(&res), Some(404));
}

#[tokio::test]
async fn test_no_matching_provider_continues_when_opted_out() {
    let mut cfg = openai_and_anthropic_config();
    cfg["fail_on_no_matching_provider"] = json!(false);
    let plugin = build(cfg);
    let body = json!({"model": "llama-3", "stream": true, "messages": []});
    let mut ctx = post_ctx(&body);
    let mut headers = json_headers();
    let res = plugin.before_proxy(&mut ctx, &mut headers).await;
    assert!(matches!(res, PluginResult::Continue));
    assert_eq!(
        ctx.metadata
            .get("ai_stream_router_pass_through")
            .map(String::as_str),
        Some("true")
    );
    assert_eq!(
        ctx.metadata.get("ai_request_streaming").map(String::as_str),
        Some("true")
    );
}

#[tokio::test]
async fn test_model_selection_picks_lowest_priority_value() {
    // Two providers both match "gpt-4o"; the lower priority value wins.
    let cfg = json!({
        "providers": [
            {"name": "secondary", "provider_type": "openai", "endpoint": "https://b.example.com/v1", "api_key": "k2", "model_patterns": ["gpt-*"], "priority": 5},
            {"name": "primary", "provider_type": "openai", "endpoint": "https://a.example.com/v1", "api_key": "k1", "model_patterns": ["gpt-4*"], "priority": 1}
        ]
    });
    let plugin = build(cfg);
    let body = json!({"model": "gpt-4o", "stream": true, "messages": []});
    let mut ctx = post_ctx(&body);
    let mut headers = json_headers();
    let res = plugin.before_proxy(&mut ctx, &mut headers).await;
    assert!(matches!(res, PluginResult::Continue));
    assert_eq!(
        ctx.metadata
            .get("ai_stream_router.provider")
            .map(String::as_str),
        Some("primary")
    );
    assert_eq!(
        ctx.route_override_backend_host.as_deref(),
        Some("a.example.com")
    );
}

#[tokio::test]
async fn test_route_override_and_metadata_set_for_openai() {
    let plugin = build(openai_and_anthropic_config());
    let body = json!({"model": "gpt-4o", "stream": true, "messages": []});
    let mut ctx = post_ctx(&body);
    let mut headers = json_headers();
    let res = plugin.before_proxy(&mut ctx, &mut headers).await;
    assert!(matches!(res, PluginResult::Continue));

    assert!(matches!(
        ctx.route_override_backend_scheme,
        Some(BackendScheme::Https)
    ));
    assert_eq!(
        ctx.route_override_backend_host.as_deref(),
        Some("api.openai.com")
    );
    assert_eq!(ctx.route_override_backend_port, Some(443));
    assert_eq!(
        ctx.route_override_path.as_deref(),
        Some("/v1/chat/completions")
    );
    assert!(ctx.route_override_path_is_absolute);
    assert_eq!(
        ctx.route_override_authority.as_deref(),
        Some("api.openai.com")
    );
    assert!(ctx.route_override_resolved_tls.is_some());

    // Provider auth injected, host set.
    assert_eq!(
        headers.get("authorization").map(String::as_str),
        Some("Bearer sk-openai-secret")
    );
    assert_eq!(
        headers.get("host").map(String::as_str),
        Some("api.openai.com")
    );

    // Metadata contract.
    assert_eq!(
        ctx.metadata
            .get("ai_stream_router.enabled")
            .map(String::as_str),
        Some("true")
    );
    assert_eq!(
        ctx.metadata
            .get("ai_stream_router.claimed")
            .map(String::as_str),
        Some("true")
    );
    assert_eq!(
        ctx.metadata
            .get("ai_stream_router_claimed")
            .map(String::as_str),
        Some("true")
    );
    assert_eq!(
        ctx.metadata
            .get("ai_stream_router.provider")
            .map(String::as_str),
        Some("openai")
    );
    assert_eq!(
        ctx.metadata
            .get("ai_stream_router.provider_type")
            .map(String::as_str),
        Some("openai")
    );
    assert_eq!(
        ctx.metadata
            .get("ai_stream_router.model")
            .map(String::as_str),
        Some("gpt-4o")
    );
    // OpenAI passthrough is not normalized.
    assert_eq!(
        ctx.metadata
            .get("ai_stream_router.normalized_response_stream")
            .map(String::as_str),
        Some("false")
    );
    assert_eq!(
        ctx.metadata
            .get("ai_stream_router.fallback_attempts")
            .map(String::as_str),
        Some("0")
    );
}

#[tokio::test]
async fn test_client_credentials_are_not_leaked() {
    let plugin = build(openai_and_anthropic_config());
    let body = json!({"model": "claude-3-5-sonnet", "stream": true, "messages": []});
    let mut ctx = post_ctx(&body);
    let mut headers = json_headers();
    // Client sends its own credentials — these must be stripped.
    headers.insert(
        "authorization".to_string(),
        "Bearer CLIENT-SECRET".to_string(),
    );
    headers.insert("x-api-key".to_string(), "CLIENT-KEY".to_string());
    headers.insert(
        "openai-organization".to_string(),
        "org-attacker".to_string(),
    );
    headers.insert("openai-project".to_string(), "proj-attacker".to_string());
    headers.insert("openai-beta".to_string(), "assistants=v2".to_string());
    headers.insert("anthropic-beta".to_string(), "tools-2024-04-04".to_string());

    let res = plugin.before_proxy(&mut ctx, &mut headers).await;
    assert!(matches!(res, PluginResult::Continue));

    // Anthropic uses x-api-key; the client Authorization must be gone entirely.
    assert!(
        !headers.contains_key("authorization"),
        "client Authorization leaked"
    );
    assert_eq!(
        headers.get("x-api-key").map(String::as_str),
        Some("sk-ant-secret")
    );
    assert_ne!(
        headers.get("x-api-key").map(String::as_str),
        Some("CLIENT-KEY")
    );
    assert_eq!(
        headers.get("anthropic-version").map(String::as_str),
        Some("2023-06-01")
    );
    assert!(!headers.contains_key("openai-organization"));
    assert!(!headers.contains_key("openai-project"));
    assert!(!headers.contains_key("openai-beta"));
    assert!(!headers.contains_key("anthropic-beta"));
}

// ---------------------------------------------------------------------------
// Request body transformation
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_openai_body_injects_include_usage_when_enabled() {
    let plugin = build(openai_and_anthropic_config());
    let body =
        json!({"model": "gpt-4o", "stream": true, "messages": [{"role": "user", "content": "hi"}]});
    let mut ctx = post_ctx(&body);
    let mut headers = json_headers();
    plugin.before_proxy(&mut ctx, &mut headers).await;

    let raw = serde_json::to_vec(&body).unwrap();
    let out = plugin
        .transform_request_body_with_context(&mut ctx, &raw, Some("application/json"), &headers)
        .await
        .expect("openai body should be rewritten to inject usage");
    let parsed: Value = serde_json::from_slice(&out).unwrap();
    assert_eq!(parsed["stream_options"]["include_usage"], json!(true));
}

#[tokio::test]
async fn test_openai_body_not_rewritten_when_injection_disabled() {
    let mut cfg = openai_and_anthropic_config();
    cfg["inject_usage_options"] = json!(false);
    let plugin = build(cfg);
    let body = json!({"model": "gpt-4o", "stream": true, "messages": []});
    let mut ctx = post_ctx(&body);
    let mut headers = json_headers();
    plugin.before_proxy(&mut ctx, &mut headers).await;

    let raw = serde_json::to_vec(&body).unwrap();
    let out = plugin
        .transform_request_body_with_context(&mut ctx, &raw, Some("application/json"), &headers)
        .await;
    assert!(out.is_none(), "openai body should pass through unchanged");
}

#[tokio::test]
async fn test_anthropic_body_translation() {
    let plugin = build(openai_and_anthropic_config());
    let body = json!({
        "model": "claude-3-5-sonnet",
        "stream": true,
        "max_tokens": 256,
        "temperature": 0.5,
        "messages": [
            {"role": "system", "content": "You are helpful."},
            {"role": "user", "content": "Hello"},
            {"role": "assistant", "content": "Hi there"},
            {"role": "user", "content": [{"type": "text", "text": "How are you?"}]}
        ]
    });
    let mut ctx = post_ctx(&body);
    let mut headers = json_headers();
    plugin.before_proxy(&mut ctx, &mut headers).await;

    let raw = serde_json::to_vec(&body).unwrap();
    let out = plugin
        .transform_request_body_with_context(&mut ctx, &raw, Some("application/json"), &headers)
        .await
        .expect("anthropic body should be translated");
    let parsed: Value = serde_json::from_slice(&out).unwrap();

    assert_eq!(parsed["model"], json!("claude-3-5-sonnet"));
    assert_eq!(parsed["max_tokens"], json!(256));
    assert_eq!(parsed["temperature"], json!(0.5));
    assert_eq!(parsed["stream"], json!(true));
    assert_eq!(parsed["system"], json!("You are helpful."));

    let messages = parsed["messages"].as_array().unwrap();
    // System is lifted out; only user/assistant remain.
    assert_eq!(messages.len(), 3);
    assert_eq!(messages[0]["role"], json!("user"));
    assert_eq!(messages[0]["content"], json!("Hello"));
    assert_eq!(messages[1]["role"], json!("assistant"));
    assert_eq!(messages[1]["content"], json!("Hi there"));
    // Array-of-text content is flattened to a string.
    assert_eq!(messages[2]["content"], json!("How are you?"));
}

#[tokio::test]
async fn test_anthropic_tools_translation() {
    let plugin = build(openai_and_anthropic_config());
    let body = json!({
        "model": "claude-3-5-sonnet",
        "stream": true,
        "messages": [{"role": "user", "content": "weather?"}],
        "tools": [{
            "type": "function",
            "function": {
                "name": "get_weather",
                "description": "Get weather",
                "parameters": {"type": "object", "properties": {"location": {"type": "string"}}}
            }
        }],
        "tool_choice": "auto"
    });
    let mut ctx = post_ctx(&body);
    let mut headers = json_headers();
    plugin.before_proxy(&mut ctx, &mut headers).await;

    let raw = serde_json::to_vec(&body).unwrap();
    let out = plugin
        .transform_request_body_with_context(&mut ctx, &raw, Some("application/json"), &headers)
        .await
        .unwrap();
    let parsed: Value = serde_json::from_slice(&out).unwrap();
    let tools = parsed["tools"].as_array().unwrap();
    assert_eq!(tools[0]["name"], json!("get_weather"));
    assert_eq!(tools[0]["description"], json!("Get weather"));
    assert_eq!(tools[0]["input_schema"]["type"], json!("object"));
    assert_eq!(parsed["tool_choice"], json!({"type": "auto"}));
}

#[tokio::test]
async fn test_transform_skips_unclaimed_request() {
    let plugin = build(openai_and_anthropic_config());
    // No before_proxy run → no claimed metadata.
    let mut ctx = RequestContext::new("127.0.0.1".into(), "POST".into(), "/".into());
    let raw = br#"{"model":"gpt-4o","stream":true}"#;
    let out = plugin
        .transform_request_body_with_context(
            &mut ctx,
            raw,
            Some("application/json"),
            &json_headers(),
        )
        .await;
    assert!(out.is_none());
}

// ---------------------------------------------------------------------------
// Response-stream normalization
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_forces_reqwest_dispatch_only_for_normalized_requests() {
    let plugin = build(openai_and_anthropic_config());

    // Anthropic (normalized) → forces reqwest dispatch.
    let claude = json!({"model": "claude-3-5-sonnet", "stream": true, "messages": []});
    let mut ctx = post_ctx(&claude);
    let mut headers = json_headers();
    plugin.before_proxy(&mut ctx, &mut headers).await;
    assert_eq!(
        ctx.metadata
            .get("ai_stream_router.normalized_response_stream")
            .map(String::as_str),
        Some("true")
    );
    assert!(plugin.forces_reqwest_dispatch(&ctx));

    // OpenAI passthrough → no forcing.
    let gpt = json!({"model": "gpt-4o", "stream": true, "messages": []});
    let mut ctx2 = post_ctx(&gpt);
    let mut headers2 = json_headers();
    plugin.before_proxy(&mut ctx2, &mut headers2).await;
    assert!(!plugin.forces_reqwest_dispatch(&ctx2));
}

#[tokio::test]
async fn test_inspector_gating() {
    let plugin = build(openai_and_anthropic_config());
    let claude = json!({"model": "claude-3-5-sonnet", "stream": true, "messages": []});
    let mut ctx = post_ctx(&claude);
    let mut headers = json_headers();
    plugin.before_proxy(&mut ctx, &mut headers).await;

    // 2xx event-stream → inspector present.
    assert!(
        plugin
            .response_stream_inspector(&ctx, 200, Some("text/event-stream"))
            .is_some()
    );
    // Non-2xx → none (error envelope reaches client untouched).
    assert!(
        plugin
            .response_stream_inspector(&ctx, 500, Some("text/event-stream"))
            .is_none()
    );
    // Non-SSE → none.
    assert!(
        plugin
            .response_stream_inspector(&ctx, 200, Some("application/json"))
            .is_none()
    );

    // OpenAI passthrough → no inspector even for a 2xx event-stream.
    let gpt = json!({"model": "gpt-4o", "stream": true, "messages": []});
    let mut ctx2 = post_ctx(&gpt);
    let mut headers2 = json_headers();
    plugin.before_proxy(&mut ctx2, &mut headers2).await;
    assert!(
        plugin
            .response_stream_inspector(&ctx2, 200, Some("text/event-stream"))
            .is_none()
    );
}

#[tokio::test]
async fn test_stream_normalizer_stage_precedes_policy_inspection() {
    let plugin = build(openai_and_anthropic_config());
    let claude = json!({"model": "claude-3-5-sonnet", "stream": true, "messages": []});
    let mut ctx = post_ctx(&claude);
    let mut headers = json_headers();
    plugin.before_proxy(&mut ctx, &mut headers).await;

    let normalizer = plugin
        .response_stream_inspector(&ctx, 200, Some("text/event-stream"))
        .expect("normalizer");
    assert_eq!(normalizer.stage(), ResponseStreamInspectorStage::Normalize);

    // Deliberately supply the policy inspector first. Stage ordering must still
    // normalize before it, without hard-coding plugin names or changing
    // request-side priority semantics.
    let mut chain =
        chain_response_stream_inspectors(vec![Box::new(RejectProviderNative), normalizer])
            .expect("chained inspectors");
    let output = match chain.on_chunk(ANTHROPIC_SSE.as_bytes()).await {
        ResponseStreamAction::Forward(output) => output,
        ResponseStreamAction::Terminate(_) => {
            panic!("policy inspector saw provider-native Anthropic SSE")
        }
    };
    let output = String::from_utf8(output.to_vec()).expect("normalized UTF-8 SSE");
    assert!(output.contains("chat.completion.chunk"));
    assert!(!output.contains("content_block_delta"));
}

const ANTHROPIC_SSE: &str = concat!(
    "event: message_start\n",
    "data: {\"type\":\"message_start\",\"message\":{\"id\":\"msg_123\",\"type\":\"message\",\"role\":\"assistant\",\"model\":\"claude-3-5-sonnet\",\"content\":[],\"stop_reason\":null,\"usage\":{\"input_tokens\":10,\"output_tokens\":1}}}\n\n",
    "event: content_block_start\n",
    "data: {\"type\":\"content_block_start\",\"index\":0,\"content_block\":{\"type\":\"text\",\"text\":\"\"}}\n\n",
    "event: ping\n",
    "data: {\"type\":\"ping\"}\n\n",
    "event: content_block_delta\n",
    "data: {\"type\":\"content_block_delta\",\"index\":0,\"delta\":{\"type\":\"text_delta\",\"text\":\"Hello\"}}\n\n",
    "event: content_block_delta\n",
    "data: {\"type\":\"content_block_delta\",\"index\":0,\"delta\":{\"type\":\"text_delta\",\"text\":\" world\"}}\n\n",
    "event: content_block_stop\n",
    "data: {\"type\":\"content_block_stop\",\"index\":0}\n\n",
    "event: message_delta\n",
    "data: {\"type\":\"message_delta\",\"delta\":{\"stop_reason\":\"end_turn\",\"stop_sequence\":null},\"usage\":{\"output_tokens\":5}}\n\n",
    "event: message_stop\n",
    "data: {\"type\":\"message_stop\"}\n\n",
);

async fn run_normalizer(chunk_size: usize) -> String {
    let plugin = build(openai_and_anthropic_config());
    let claude = json!({"model": "claude-3-5-sonnet", "stream": true, "messages": []});
    let mut ctx = post_ctx(&claude);
    let mut headers = json_headers();
    plugin.before_proxy(&mut ctx, &mut headers).await;
    let mut inspector: Box<dyn ResponseStreamInspector> = plugin
        .response_stream_inspector(&ctx, 200, Some("text/event-stream"))
        .expect("inspector should be created");

    let mut collected = Vec::new();
    for chunk in ANTHROPIC_SSE.as_bytes().chunks(chunk_size) {
        collected.extend_from_slice(&forwarded(inspector.on_chunk(chunk).await));
    }
    collected.extend_from_slice(&forwarded(inspector.on_end().await));
    String::from_utf8(collected).unwrap()
}

#[tokio::test]
async fn test_anthropic_sse_normalized_to_openai_chunks() {
    let out = run_normalizer(4096).await;

    assert!(
        out.contains("chat.completion.chunk"),
        "missing chunk object: {out}"
    );
    assert!(
        out.contains("\"role\":\"assistant\""),
        "missing role delta: {out}"
    );
    assert!(
        out.contains("\"content\":\"Hello\""),
        "missing first content: {out}"
    );
    assert!(
        out.contains("\"content\":\" world\""),
        "missing second content: {out}"
    );
    assert!(
        out.contains("\"finish_reason\":\"stop\""),
        "missing finish reason: {out}"
    );
    assert!(
        out.contains("\"prompt_tokens\":10"),
        "missing prompt tokens: {out}"
    );
    assert!(
        out.contains("\"completion_tokens\":5"),
        "missing completion tokens: {out}"
    );
    assert!(
        out.contains("\"total_tokens\":15"),
        "missing total tokens: {out}"
    );
    assert!(
        out.trim_end().ends_with("data: [DONE]"),
        "missing DONE terminator: {out}"
    );

    // Every emitted data line (except [DONE]) must be valid JSON.
    for line in out.lines() {
        if let Some(rest) = line.strip_prefix("data: ") {
            if rest == "[DONE]" {
                continue;
            }
            serde_json::from_str::<Value>(rest)
                .unwrap_or_else(|e| panic!("emitted non-JSON SSE data line `{rest}`: {e}"));
        }
    }
}

#[tokio::test]
async fn test_anthropic_sse_robust_to_chunk_splits() {
    // A tiny chunk size forces mid-event and mid-line boundaries.
    let split = run_normalizer(7).await;
    let whole = run_normalizer(4096).await;
    // Identical output (modulo the time-based `created` field) regardless of how
    // the provider stream is chunked.
    assert_eq!(
        strip_created(&split),
        strip_created(&whole),
        "normalizer output must be chunk-boundary independent"
    );
    assert!(split.contains("\"content\":\"Hello\""));
    assert!(split.trim_end().ends_with("data: [DONE]"));
}

#[tokio::test]
async fn test_buffered_anthropic_sse_is_normalized_too() {
    let plugin = build(openai_and_anthropic_config());
    let claude = json!({"model": "claude-3-5-sonnet", "stream": true, "messages": []});
    let mut ctx = post_ctx(&claude);
    let mut headers = json_headers();
    plugin.before_proxy(&mut ctx, &mut headers).await;

    let buffered = plugin
        .normalize_response_body_with_context(
            &mut ctx,
            200,
            ANTHROPIC_SSE.as_bytes(),
            Some("text/event-stream"),
            &HashMap::new(),
        )
        .await
        .expect("buffered Anthropic SSE should be normalized");
    let buffered = String::from_utf8(buffered).unwrap();
    let streamed = run_normalizer(4096).await;

    assert_eq!(strip_created(&buffered), strip_created(&streamed));
    assert!(buffered.contains("chat.completion.chunk"));
    assert!(buffered.trim_end().ends_with("data: [DONE]"));

    assert!(
        plugin
            .normalize_response_body_with_context(
                &mut ctx,
                500,
                ANTHROPIC_SSE.as_bytes(),
                Some("text/event-stream"),
                &HashMap::new(),
            )
            .await
            .is_none(),
        "provider error streams must stay untouched"
    );
}

// ---------------------------------------------------------------------------
// Claim-time markers, header hygiene, endpoint URL handling
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_claim_sets_shared_streaming_marker() {
    let plugin = build(openai_and_anthropic_config());
    let body = json!({"model": "gpt-4o", "stream": true, "messages": []});
    let mut ctx = post_ctx(&body);
    let mut headers = json_headers();
    plugin.before_proxy(&mut ctx, &mut headers).await;
    assert_eq!(
        ctx.metadata.get("ai_request_streaming").map(String::as_str),
        Some("true"),
        "claimed stream:true requests must set the shared streaming marker for response plugins"
    );

    // Unclaimed (non-streaming) requests must NOT set it.
    let non_streaming = json!({"model": "gpt-4o", "messages": []});
    let mut ctx2 = post_ctx(&non_streaming);
    let mut headers2 = json_headers();
    plugin.before_proxy(&mut ctx2, &mut headers2).await;
    assert!(!ctx2.metadata.contains_key("ai_request_streaming"));
}

#[tokio::test]
async fn test_claim_suppresses_consumer_identity_header_injection() {
    let plugin = build(openai_and_anthropic_config());
    let body = json!({"model": "gpt-4o", "stream": true, "messages": []});
    let mut ctx = post_ctx(&body);
    // Simulate an auth plugin having resolved a principal earlier.
    ctx.authenticated_identity = Some("internal-alice".to_string());
    assert_eq!(ctx.backend_consumer_username(), Some("internal-alice"));

    let mut headers = json_headers();
    plugin.before_proxy(&mut ctx, &mut headers).await;

    assert_eq!(
        ctx.metadata
            .get("suppress_backend_consumer_identity_headers")
            .map(String::as_str),
        Some("true")
    );
    // The proxy's injection sites read these accessors — both must go dark so
    // x-consumer-* never reaches the third-party provider.
    assert_eq!(
        ctx.backend_consumer_username(),
        None,
        "identity header injection must be suppressed for provider-routed requests"
    );
    assert_eq!(ctx.backend_consumer_custom_id(), None);
    // The principal itself stays resolved for rate limiting / logging.
    assert_eq!(ctx.effective_identity(), Some("internal-alice"));
}

#[tokio::test]
async fn test_cookie_and_proxy_authorization_stripped() {
    let plugin = build(openai_and_anthropic_config());
    let body = json!({"model": "gpt-4o", "stream": true, "messages": []});
    let mut ctx = post_ctx(&body);
    let mut headers = json_headers();
    headers.insert("cookie".to_string(), "session=SECRET".to_string());
    headers.insert("proxy-authorization".to_string(), "Basic AAAA".to_string());
    plugin.before_proxy(&mut ctx, &mut headers).await;
    assert!(
        !headers.contains_key("cookie"),
        "session cookie leaked to provider"
    );
    assert!(!headers.contains_key("proxy-authorization"));
}

fn azure_style_config() -> Value {
    json!({
        "providers": [{
            "name": "azure",
            "provider_type": "openai_compatible",
            "endpoint": "https://azure.example.com/openai/deployments/gpt/chat/completions?api-version=2024-02-01",
            "api_key": "sk-azure",
            "model_patterns": ["gpt-*"]
        }]
    })
}

#[tokio::test]
async fn test_endpoint_query_preserved_without_client_query() {
    let plugin = build(azure_style_config());
    let body = json!({"model": "gpt-4o", "stream": true, "messages": []});
    let mut ctx = post_ctx(&body);
    let mut headers = json_headers();
    plugin.before_proxy(&mut ctx, &mut headers).await;
    assert_eq!(
        ctx.route_override_path.as_deref(),
        Some("/openai/deployments/gpt/chat/completions?api-version=2024-02-01")
    );
    // No client query → nothing to strip.
    assert!(
        !ctx.metadata
            .keys()
            .any(|k| k.starts_with("auth.strip_query_param."))
    );
}

#[tokio::test]
async fn test_endpoint_query_merged_with_client_query() {
    let plugin = build(azure_style_config());
    let body = json!({"model": "gpt-4o", "stream": true, "messages": []});
    let mut ctx = post_ctx(&body);
    ctx.set_raw_query_string("foo=bar&baz=1".to_string());
    let mut headers = json_headers();
    plugin.before_proxy(&mut ctx, &mut headers).await;
    // Endpoint query first, client query appended with '&' — never a second '?'.
    assert_eq!(
        ctx.route_override_path.as_deref(),
        Some("/openai/deployments/gpt/chat/completions?api-version=2024-02-01&foo=bar&baz=1")
    );
    // Every client param is marked consumed so dispatch does not re-append it.
    assert_eq!(
        ctx.metadata
            .get("auth.strip_query_param.foo")
            .map(String::as_str),
        Some("true")
    );
    assert_eq!(
        ctx.metadata
            .get("auth.strip_query_param.baz")
            .map(String::as_str),
        Some("true")
    );
}

#[tokio::test]
async fn test_endpoint_query_omits_previously_stripped_client_credentials() {
    let plugin = build(azure_style_config());
    let body = json!({"model": "gpt-4o", "stream": true, "messages": []});
    let mut ctx = post_ctx(&body);
    ctx.set_raw_query_string("foo=bar&access_token=secret".to_string());
    ctx.metadata.insert(
        "auth.strip_query_param.access_token".to_string(),
        "true".to_string(),
    );
    let mut headers = json_headers();
    plugin.before_proxy(&mut ctx, &mut headers).await;
    assert_eq!(
        ctx.route_override_path.as_deref(),
        Some("/openai/deployments/gpt/chat/completions?api-version=2024-02-01&foo=bar")
    );
    assert!(
        !ctx.route_override_path
            .as_deref()
            .unwrap()
            .contains("secret"),
        "query credentials marked for strip must not be folded into the provider override path"
    );
}

#[tokio::test]
async fn test_endpoint_query_drops_client_duplicate_provider_params() {
    let plugin = build(azure_style_config());
    let body = json!({"model": "gpt-4o", "stream": true, "messages": []});
    let mut ctx = post_ctx(&body);
    ctx.set_raw_query_string("api-version=preview&foo=bar".to_string());
    let mut headers = json_headers();
    plugin.before_proxy(&mut ctx, &mut headers).await;
    assert_eq!(
        ctx.route_override_path.as_deref(),
        Some("/openai/deployments/gpt/chat/completions?api-version=2024-02-01&foo=bar")
    );
    assert_eq!(
        ctx.metadata
            .get("auth.strip_query_param.api-version")
            .map(String::as_str),
        Some("true")
    );
    assert_eq!(
        ctx.metadata
            .get("auth.strip_query_param.foo")
            .map(String::as_str),
        Some("true")
    );
}

#[tokio::test]
async fn test_plain_endpoint_keeps_client_query_forwarding_untouched() {
    let plugin = build(openai_and_anthropic_config());
    let body = json!({"model": "gpt-4o", "stream": true, "messages": []});
    let mut ctx = post_ctx(&body);
    ctx.set_raw_query_string("foo=bar".to_string());
    let mut headers = json_headers();
    plugin.before_proxy(&mut ctx, &mut headers).await;
    // No endpoint query → the dispatch path appends the client query normally.
    assert_eq!(
        ctx.route_override_path.as_deref(),
        Some("/v1/chat/completions")
    );
    assert!(
        !ctx.metadata
            .keys()
            .any(|k| k.starts_with("auth.strip_query_param."))
    );
}

#[tokio::test]
async fn test_ipv6_endpoint_authority_is_bracketed() {
    let cfg = json!({
        "providers": [{
            "name": "local6",
            "provider_type": "openai_compatible",
            "endpoint": "https://[::1]:8443/v1/chat/completions",
            "api_key": "sk-local",
            "model_patterns": ["gpt-*"]
        }]
    });
    let plugin = build(cfg);
    let body = json!({"model": "gpt-4o", "stream": true, "messages": []});
    let mut ctx = post_ctx(&body);
    let mut headers = json_headers();
    plugin.before_proxy(&mut ctx, &mut headers).await;
    // Backend host stays bare (the URL builder brackets it); authority/Host
    // must be bracketed.
    assert_eq!(ctx.route_override_backend_host.as_deref(), Some("::1"));
    assert_eq!(ctx.route_override_backend_port, Some(8443));
    assert_eq!(ctx.route_override_authority.as_deref(), Some("[::1]:8443"));
    assert_eq!(headers.get("host").map(String::as_str), Some("[::1]:8443"));
}

#[tokio::test]
async fn test_ipv6_endpoint_default_port_authority() {
    let cfg = json!({
        "providers": [{
            "name": "local6",
            "provider_type": "openai_compatible",
            "endpoint": "https://[::1]/v1/chat/completions",
            "api_key": "sk-local",
            "model_patterns": ["gpt-*"]
        }]
    });
    let plugin = build(cfg);
    let body = json!({"model": "gpt-4o", "stream": true, "messages": []});
    let mut ctx = post_ctx(&body);
    let mut headers = json_headers();
    plugin.before_proxy(&mut ctx, &mut headers).await;
    assert_eq!(ctx.route_override_authority.as_deref(), Some("[::1]"));
}

#[tokio::test]
async fn test_backend_tls_default_and_inherit() {
    // Default: HTTPS providers get default public-CA verification.
    let plugin = build(openai_and_anthropic_config());
    let body = json!({"model": "gpt-4o", "stream": true, "messages": []});
    let mut ctx = post_ctx(&body);
    let mut headers = json_headers();
    plugin.before_proxy(&mut ctx, &mut headers).await;
    assert!(ctx.route_override_resolved_tls.is_some());

    // inherit_backend_tls: true carries the proxy's own resolved backend TLS
    // (custom CA / SNI / mTLS), including TLS projected from an upstream.
    let cfg = json!({
        "providers": [{
            "name": "internal",
            "provider_type": "openai_compatible",
            "endpoint": "https://llm.internal.example.com/v1/chat/completions",
            "api_key": "sk-internal",
            "model_patterns": ["gpt-*"],
            "inherit_backend_tls": true
        }]
    });
    let plugin2 = build(cfg);
    let mut ctx2 = post_ctx(&body);
    let inherited_tls = BackendTlsConfig {
        client_cert_path: Some("/certs/client.pem".to_string()),
        client_key_path: Some("/certs/client.key".to_string()),
        server_ca_cert_path: Some("/certs/ca.pem".to_string()),
        verify_server_cert: true,
        sni: Some("llm.internal.example.com".to_string()),
        san_allow_list: vec!["llm.internal.example.com".to_string()],
        san_allow_list_key_digest: Some("digest".to_string()),
    };
    let mut proxy = create_test_proxy();
    proxy.resolved_tls = inherited_tls.clone();
    ctx2.matched_proxy = Some(Arc::new(proxy));
    let mut headers2 = json_headers();
    plugin2.before_proxy(&mut ctx2, &mut headers2).await;
    assert_eq!(
        ctx2.metadata
            .get("ai_stream_router.claimed")
            .map(String::as_str),
        Some("true")
    );
    assert_eq!(ctx2.route_override_resolved_tls, Some(inherited_tls));
}

// ---------------------------------------------------------------------------
// Normalizer carry bound
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_normalizer_terminates_on_oversized_sse_event() {
    let plugin = build(openai_and_anthropic_config());
    let claude = json!({"model": "claude-3-5-sonnet", "stream": true, "messages": []});
    let mut ctx = post_ctx(&claude);
    let mut headers = json_headers();
    plugin.before_proxy(&mut ctx, &mut headers).await;
    let mut inspector: Box<dyn ResponseStreamInspector> = plugin
        .response_stream_inspector(&ctx, 200, Some("text/event-stream"))
        .unwrap();

    // One giant never-terminated event: no blank-line boundary ever arrives.
    let filler = vec![b'a'; 64 * 1024];
    let mut terminated = None;
    // 1 MiB cap / 64 KiB chunks → must terminate well within 20 chunks.
    for i in 0..20 {
        match inspector.on_chunk(&filler).await {
            ResponseStreamAction::Forward(bytes) => {
                assert!(
                    bytes.is_empty(),
                    "no complete event exists; nothing should be forwarded (chunk {i})"
                );
            }
            ResponseStreamAction::Terminate(bytes) => {
                terminated = Some(bytes);
                break;
            }
        }
    }
    let final_bytes = terminated
        .expect("oversized unterminated SSE event must terminate the stream")
        .expect("termination must carry a client-facing SSE error payload");
    let text = String::from_utf8(final_bytes.to_vec()).unwrap();
    assert!(text.contains("upstream_error"), "{text}");
    assert!(text.contains("oversized"), "{text}");
    assert!(text.trim_end().ends_with("data: [DONE]"), "{text}");

    // After termination the inspector is inert.
    let after = inspector.on_chunk(b"data: {}\n\n").await;
    match after {
        ResponseStreamAction::Forward(bytes) => assert!(bytes.is_empty()),
        ResponseStreamAction::Terminate(_) => panic!("must not terminate twice"),
    }
}

// ---------------------------------------------------------------------------
// Composition with ai_federation
// ---------------------------------------------------------------------------

fn ai_federation_openai() -> AiFederation {
    let cfg = json!({
        "providers": [{
            "name": "openai", "provider_type": "openai",
            "api_key": "sk-fed", "model_patterns": ["gpt-*", "claude-*"]
        }]
    });
    AiFederation::new(&cfg, http_client()).unwrap()
}

#[tokio::test]
async fn test_ai_federation_rejects_streaming_without_marker() {
    // Baseline: ai_federation still rejects stream:true it would otherwise route.
    let fed = ai_federation_openai();
    let body =
        json!({"model": "gpt-4o", "stream": true, "messages": [{"role": "user", "content": "hi"}]});
    let mut ctx = post_ctx(&body);
    let mut headers = json_headers();
    let res = fed.before_proxy(&mut ctx, &mut headers).await;
    assert_eq!(reject_status(&res), Some(501));
}

#[tokio::test]
async fn test_ai_federation_defers_to_claimed_stream_router_request() {
    // With the coordination marker set, ai_federation immediately continues so
    // ai_stream_router owns the streaming request.
    let fed = ai_federation_openai();
    let body =
        json!({"model": "gpt-4o", "stream": true, "messages": [{"role": "user", "content": "hi"}]});
    let mut ctx = post_ctx(&body);
    ctx.metadata
        .insert("ai_stream_router_claimed".to_string(), "true".to_string());
    let mut headers = json_headers();
    let res = fed.before_proxy(&mut ctx, &mut headers).await;
    assert!(
        matches!(res, PluginResult::Continue),
        "ai_federation should defer to ai_stream_router"
    );
}

#[tokio::test]
async fn test_ai_federation_defers_to_stream_router_pass_through() {
    let fed = ai_federation_openai();
    let body = json!({"model": "gpt-unknown", "stream": true, "messages": [{"role": "user", "content": "hi"}]});
    let mut ctx = post_ctx(&body);
    ctx.metadata.insert(
        "ai_stream_router_pass_through".to_string(),
        "true".to_string(),
    );
    let mut headers = json_headers();
    let res = fed.before_proxy(&mut ctx, &mut headers).await;
    assert!(
        matches!(res, PluginResult::Continue),
        "ai_federation should defer to explicit ai_stream_router pass-through"
    );
}

#[tokio::test]
async fn test_end_to_end_composition_streaming_vs_non_streaming() {
    // stream:true → claimed by ai_stream_router; the same request then continues
    // through ai_federation which defers.
    let router = build(openai_and_anthropic_config());
    let fed = ai_federation_openai();

    let streaming =
        json!({"model": "gpt-4o", "stream": true, "messages": [{"role": "user", "content": "hi"}]});
    let mut ctx = post_ctx(&streaming);
    let mut headers = json_headers();
    assert!(matches!(
        router.before_proxy(&mut ctx, &mut headers).await,
        PluginResult::Continue
    ));
    assert_eq!(
        ctx.metadata
            .get("ai_stream_router_claimed")
            .map(String::as_str),
        Some("true")
    );
    assert!(matches!(
        fed.before_proxy(&mut ctx, &mut headers).await,
        PluginResult::Continue
    ));

    // stream:false → NOT claimed by ai_stream_router; ai_federation handles it
    // (rejects here because there is no live provider, proving it took ownership).
    let non_streaming = json!({"model": "gpt-4o", "messages": [{"role": "user", "content": "hi"}]});
    let mut ctx2 = post_ctx(&non_streaming);
    let mut headers2 = json_headers();
    assert!(matches!(
        router.before_proxy(&mut ctx2, &mut headers2).await,
        PluginResult::Continue
    ));
    assert!(!ctx2.metadata.contains_key("ai_stream_router_claimed"));
}
