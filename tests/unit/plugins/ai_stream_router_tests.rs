//! Unit tests for the `ai_stream_router` plugin.

use ferrum_edge::config::types::BackendScheme;
use ferrum_edge::plugins::ai_federation::AiFederation;
use ferrum_edge::plugins::ai_stream_router::AiStreamRouter;
use ferrum_edge::plugins::{
    HTTP_ONLY_PROTOCOLS, Plugin, PluginHttpClient, PluginResult, RequestContext,
    ResponseStreamAction, ResponseStreamInspector, priority,
};
use serde_json::{Value, json};
use std::collections::HashMap;

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
