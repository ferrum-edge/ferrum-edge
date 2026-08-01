//! Unit tests for the `ai_stream_router` plugin.

use super::plugin_utils::{create_test_proxy, normalize_compressed_request_for_plugin_test};
use ferrum_edge::config::types::{BackendScheme, BackendTlsConfig};
use ferrum_edge::plugins::ai_federation::AiFederation;
use ferrum_edge::plugins::ai_stream_router::{
    AiStreamRouter, MAX_SSE_EVENT_BYTES, MAX_SSE_EVENT_JSON_DEPTH, MAX_SSE_EVENTS,
    MAX_SSE_NORMALIZED_BODY_BYTES, MAX_SSE_NORMALIZED_OUTPUT_BYTES,
};
use ferrum_edge::plugins::mcp_gateway::McpGateway;
use ferrum_edge::plugins::mesh_route_dispatch::MeshRouteDispatch;
use ferrum_edge::plugins::request_deduplication::RequestDeduplication;
use ferrum_edge::plugins::request_mirror::RequestMirror;
use ferrum_edge::plugins::request_transformer::RequestTransformer;
use ferrum_edge::plugins::response_caching::ResponseCaching;
use ferrum_edge::plugins::serverless_function::ServerlessFunction;
use ferrum_edge::plugins::{
    HTTP_ONLY_PROTOCOLS, Plugin, PluginHttpClient, PluginResult, RequestContext,
    ResponseStreamAction, ResponseStreamInspector, ResponseStreamInspectorStage,
    chain_response_stream_inspectors, priority, validate_plugin_config,
};
use serde_json::{Value, json};
use std::collections::HashMap;
use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
};

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

async fn run_federation_final_body(
    plugin: &AiFederation,
    ctx: &mut RequestContext,
    headers: &HashMap<String, String>,
) -> PluginResult {
    let body = ctx
        .metadata
        .get("request_body")
        .cloned()
        .unwrap_or_default();
    let mut backend_header_overlay = HashMap::new();
    plugin
        .dispatch_finalized_request_egress(
            ctx,
            headers,
            body.as_bytes(),
            &mut backend_header_overlay,
        )
        .await
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
struct RejectProviderNative {
    saw_normalized: Arc<AtomicBool>,
}

#[async_trait::async_trait]
impl ResponseStreamInspector for RejectProviderNative {
    async fn on_chunk(&mut self, chunk: &[u8]) -> ResponseStreamAction {
        if chunk
            .windows(b"chat.completion.chunk".len())
            .any(|window| window == b"chat.completion.chunk")
        {
            self.saw_normalized.store(true, Ordering::SeqCst);
        }
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
    assert!(plugin.modifies_request_destination());
    assert!(plugin.modifies_request_body());
    assert!(plugin.needs_final_request_body_context());
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
fn test_shared_validation_rejects_invalid_ai_stream_router_config() {
    let err = validate_plugin_config("ai_stream_router", &json!({"enabled": true}))
        .expect_err("shared plugin validation must require a providers array");
    assert_eq!(
        err,
        "ai_stream_router: 'providers' must be a non-empty array"
    );
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

fn valid_provider() -> Value {
    json!({
        "name": "p",
        "provider_type": "openai",
        "endpoint": "https://a.example.com/v1/chat/completions",
        "api_key": "k",
        "model_patterns": ["gpt-*"]
    })
}

#[test]
fn test_config_rejects_unknown_root_keys_with_path_and_suggestion() {
    let mut cfg = json!({
        "enabeld": false,
        "providers": [valid_provider()]
    });
    let err = AiStreamRouter::new(&cfg, http_client()).err().unwrap();
    assert!(
        err.contains("unknown configuration key")
            && err.contains("'config.enabeld'")
            && err.contains("did you mean 'enabled'"),
        "{err}"
    );

    // Misspelled enablement must not silently leave the router enabled.
    assert!(
        validate_plugin_config("ai_stream_router", &cfg).is_err(),
        "shared admission must reject enablement typos"
    );

    cfg = json!({
        "fail_on_missing_mode": false,
        "inject_usage_option": false,
        "normalize_response_strem": false,
        "providers": [valid_provider()]
    });
    let err = AiStreamRouter::new(&cfg, http_client()).err().unwrap();
    assert!(err.contains("'config.fail_on_missing_mode'"), "{err}");
    assert!(err.contains("'config.inject_usage_option'"), "{err}");
    assert!(err.contains("'config.normalize_response_strem'"), "{err}");
    assert!(
        err.contains("did you mean 'fail_on_missing_model'")
            || err.contains("did you mean 'inject_usage_options'")
            || err.contains("did you mean 'normalize_response_stream'"),
        "{err}"
    );
}

/// Issue #3328: a `fallback` block must fail admission outright instead of
/// being parsed into a policy the runtime never honors. Every JSON shape is
/// refused — an object, a well-formed policy, an empty object, `null`, and a
/// scalar — so no operator can persist inert failover configuration.
#[test]
fn test_config_rejects_fallback_block_in_every_shape() {
    for fallback in [
        json!({"enabled": true, "on_connect_error": true, "on_5xx_before_first_byte": true, "max_attempts": 3}),
        json!({"enabled": false}),
        json!({}),
        Value::Null,
        json!(true),
        json!(2),
        json!("enabled"),
    ] {
        let cfg = json!({
            "providers": [valid_provider()],
            "fallback": fallback.clone(),
        });
        let err = AiStreamRouter::new(&cfg, http_client())
            .err()
            .unwrap_or_else(|| panic!("fallback {fallback} must be rejected"));
        assert!(
            err.contains("unsupported field 'fallback'"),
            "fallback {fallback}: {err}"
        );
        assert!(
            err.contains("provider fallback is not implemented"),
            "rejection must explain the missing capability, not read as a typo: {err}"
        );
        // The same fail-closed verdict must reach Admin API / file validate /
        // CP-DP publication through the shared admission entrypoint.
        assert!(
            validate_plugin_config("ai_stream_router", &cfg).is_err(),
            "shared admission must reject fallback {fallback}"
        );
    }
}

/// A `fallback` block is refused with its own diagnostic rather than being
/// reported as an unknown-key typo, so the operator learns the capability does
/// not exist.
#[test]
fn test_fallback_rejection_is_specific_not_a_typo_suggestion() {
    let cfg = json!({
        "providers": [valid_provider()],
        "fallback": {"on_connect_error": true},
    });
    let err = AiStreamRouter::new(&cfg, http_client()).err().unwrap();
    assert!(!err.contains("did you mean"), "{err}");
    assert!(!err.contains("unknown configuration key"), "{err}");
    assert!(err.contains("Remove the 'fallback' block"), "{err}");
}

/// Omitting `fallback` preserves the plugin's existing behavior exactly: the
/// router still constructs and still routes a claimed streaming request.
#[test]
fn test_omitted_fallback_preserves_construction() {
    let cfg = json!({
        "providers": [valid_provider()]
    });
    assert!(AiStreamRouter::new(&cfg, http_client()).is_ok());
    assert!(validate_plugin_config("ai_stream_router", &cfg).is_ok());
}

#[test]
fn test_config_rejects_unknown_provider_keys() {
    let cfg = json!({
        "providers": [{
            "name": "p",
            "provider_type": "openai",
            "endpoint": "https://a.example.com/v1/chat/completions",
            "api_key": "k",
            "model_patterns": ["gpt-*"],
            "inherit_backend_tl": true,
            "allow_plaintex": true
        }]
    });
    let err = AiStreamRouter::new(&cfg, http_client()).err().unwrap();
    assert!(
        err.contains("'config.providers[0].allow_plaintex'"),
        "{err}"
    );
    assert!(
        err.contains("'config.providers[0].inherit_backend_tl'"),
        "{err}"
    );
    assert!(
        err.contains("did you mean 'allow_plaintext'")
            || err.contains("did you mean 'inherit_backend_tls'"),
        "{err}"
    );
}

#[test]
fn test_shared_admission_and_failure_policy_for_unknown_keys() {
    use ferrum_edge::plugins::{PluginFailurePolicy, plugin_failure_policy};

    let err = validate_plugin_config(
        "ai_stream_router",
        &json!({
            "enabeld": false,
            "providers": [valid_provider()]
        }),
    )
    .expect_err("shared plugin validation must reject unknown keys");
    assert!(
        err.contains("'config.enabeld'") && err.contains("did you mean 'enabled'"),
        "{err}"
    );
    assert_eq!(
        plugin_failure_policy("ai_stream_router"),
        Some(PluginFailurePolicy::FailClosed)
    );
}

#[test]
fn test_disabled_plugin_does_not_wire_hooks() {
    let mut cfg = openai_and_anthropic_config();
    cfg["enabled"] = json!(false);
    let plugin = build(cfg);
    assert!(!plugin.requires_response_stream_hooks());
    assert!(!plugin.modifies_request_headers());
    assert!(!plugin.modifies_request_destination());
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
    // Issue #3328: no permanently-zero fallback counter is published — the
    // plugin never attempts a second provider, so the key would only advertise
    // a capability that does not exist.
    assert!(
        !ctx.metadata
            .contains_key("ai_stream_router.fallback_attempts"),
        "claimed requests must not stamp an inert fallback_attempts counter"
    );
}

#[tokio::test]
async fn configured_decompression_routes_compressed_streaming_requests() {
    let plugin = build(openai_and_anthropic_config());
    let request = serde_json::to_vec(&json!({
        "model": "claude-3-5-sonnet",
        "stream": true,
        "messages": [{"role": "user", "content": "route compressed request"}]
    }))
    .unwrap();

    for encoding in ["gzip", "br"] {
        let (mut ctx, mut headers, normalized) = normalize_compressed_request_for_plugin_test(
            "application/json",
            "/v1/chat/completions",
            encoding,
            &request,
        )
        .await;
        assert_eq!(normalized, request);

        let result = plugin.before_proxy(&mut ctx, &mut headers).await;

        assert!(matches!(result, PluginResult::Continue));
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
            Some("anthropic")
        );
        assert_eq!(
            ctx.route_override_backend_host.as_deref(),
            Some("api.anthropic.com")
        );
        assert_eq!(
            headers.get("x-api-key").map(String::as_str),
            Some("sk-ant-secret")
        );
        assert!(!headers.contains_key("content-encoding"));
    }
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

fn weather_tools() -> Value {
    json!([{
        "type": "function",
        "function": {
            "name": "get_weather",
            "description": "Get weather",
            "parameters": {"type": "object", "properties": {"location": {"type": "string"}}}
        }
    }])
}

async fn translate_anthropic_body(body: &Value) -> Option<Value> {
    let plugin = build(openai_and_anthropic_config());
    let mut ctx = post_ctx(body);
    let mut headers = json_headers();
    if reject_status(&plugin.before_proxy(&mut ctx, &mut headers).await).is_some() {
        return None;
    }
    let raw = serde_json::to_vec(body).unwrap();
    let out = plugin
        .transform_request_body_with_context(&mut ctx, &raw, Some("application/json"), &headers)
        .await?;
    Some(serde_json::from_slice(&out).unwrap())
}

#[tokio::test]
async fn test_anthropic_tool_choice_none_keeps_tools_and_emits_type_none() {
    let body = json!({
        "model": "claude-3-5-sonnet",
        "stream": true,
        "messages": [{"role": "user", "content": "weather?"}],
        "tools": weather_tools(),
        "tool_choice": "none"
    });
    let parsed = translate_anthropic_body(&body)
        .await
        .expect("none must translate");
    assert_eq!(parsed["tools"][0]["name"], json!("get_weather"));
    assert_eq!(parsed["tool_choice"], json!({"type": "none"}));
}

#[tokio::test]
async fn test_anthropic_tool_choice_required_and_named_preserve_semantics() {
    let required = json!({
        "model": "claude-3-5-sonnet",
        "stream": true,
        "messages": [{"role": "user", "content": "weather?"}],
        "tools": weather_tools(),
        "tool_choice": "required"
    });
    let parsed = translate_anthropic_body(&required)
        .await
        .expect("required must translate");
    assert_eq!(parsed["tool_choice"], json!({"type": "any"}));

    let named = json!({
        "model": "claude-3-5-sonnet",
        "stream": true,
        "messages": [{"role": "user", "content": "weather?"}],
        "tools": weather_tools(),
        "tool_choice": {
            "type": "function",
            "function": {"name": "get_weather"}
        }
    });
    let parsed = translate_anthropic_body(&named)
        .await
        .expect("named must translate");
    assert_eq!(
        parsed["tool_choice"],
        json!({"type": "tool", "name": "get_weather"})
    );
}

#[tokio::test]
async fn test_anthropic_rejects_malformed_and_unsupported_tool_choice() {
    let plugin = build(openai_and_anthropic_config());
    let invalid = vec![
        json!("maybe"),
        json!("any"),
        json!(42),
        json!(true),
        json!(["none"]),
        json!({}),
        json!({"type": "none"}),
        json!({"type": "auto"}),
        json!({"type": "any"}),
        json!({"type": "tool", "name": "get_weather"}),
        json!({"type": "function", "function": {"name": "not valid!"}}),
        json!({"type": "function", "function": {}}),
        json!({"type": "function"}),
        json!({
            "type": "function",
            "function": {"name": "get_weather"},
            "extra": true
        }),
        json!({
            "type": "function",
            "function": {"name": "get_weather", "description": "nope"}
        }),
    ];

    for tool_choice in invalid {
        let body = json!({
            "model": "claude-3-5-sonnet",
            "stream": true,
            "messages": [{"role": "user", "content": "weather?"}],
            "tools": weather_tools(),
            "tool_choice": tool_choice
        });
        let mut ctx = post_ctx(&body);
        let mut headers = json_headers();
        let result = plugin.before_proxy(&mut ctx, &mut headers).await;
        assert_eq!(
            reject_status(&result),
            Some(400),
            "must reject unsupported tool_choice without claiming the request"
        );
        if let PluginResult::Reject { body, .. } = result {
            assert!(
                !body.contains("maybe")
                    && !body.contains("get_weather")
                    && !body.contains("not valid"),
                "client error must not reflect untrusted tool_choice values: {body}"
            );
        }
    }

    // auto/required/named without tools are rejected rather than weakened.
    for tool_choice in [
        json!("auto"),
        json!("required"),
        json!({"type": "function", "function": {"name": "get_weather"}}),
    ] {
        let body = json!({
            "model": "claude-3-5-sonnet",
            "stream": true,
            "messages": [{"role": "user", "content": "hi"}],
            "tool_choice": tool_choice
        });
        let mut ctx = post_ctx(&body);
        let mut headers = json_headers();
        assert_eq!(
            reject_status(&plugin.before_proxy(&mut ctx, &mut headers).await),
            Some(400)
        );
    }

    // Named choice that does not match a declared tool.
    let body = json!({
        "model": "claude-3-5-sonnet",
        "stream": true,
        "messages": [{"role": "user", "content": "weather?"}],
        "tools": weather_tools(),
        "tool_choice": {
            "type": "function",
            "function": {"name": "other_tool"}
        }
    });
    let mut ctx = post_ctx(&body);
    let mut headers = json_headers();
    let result = plugin.before_proxy(&mut ctx, &mut headers).await;
    assert_eq!(reject_status(&result), Some(400));
    if let PluginResult::Reject { body, .. } = result {
        assert!(
            !body.contains("other_tool"),
            "client error must not echo the unmatched tool name: {body}"
        );
    }
}

#[tokio::test]
async fn test_anthropic_extended_thinking_tool_choice_combinations() {
    let plugin = build(openai_and_anthropic_config());

    // Manual enabled thinking + none/auto are admitted and forwarded.
    for (tool_choice, expected) in [
        (json!("none"), json!({"type": "none"})),
        (json!("auto"), json!({"type": "auto"})),
    ] {
        let body = json!({
            "model": "claude-3-5-sonnet",
            "stream": true,
            "max_tokens": 4096,
            "messages": [{"role": "user", "content": "weather?"}],
            "tools": weather_tools(),
            "tool_choice": tool_choice,
            "thinking": {"type": "enabled", "budget_tokens": 1024}
        });
        let parsed = translate_anthropic_body(&body)
            .await
            .expect("thinking with none/auto must translate");
        assert_eq!(parsed["tool_choice"], expected);
        assert_eq!(
            parsed["thinking"],
            json!({"type": "enabled", "budget_tokens": 1024})
        );
        assert_eq!(parsed["max_tokens"], json!(4096));
    }

    let adaptive = json!({
        "model": "claude-3-5-sonnet",
        "stream": true,
        "messages": [{"role": "user", "content": "weather?"}],
        "tools": weather_tools(),
        "tool_choice": "auto",
        "thinking": {"type": "adaptive"}
    });
    let parsed = translate_anthropic_body(&adaptive)
        .await
        .expect("adaptive thinking with auto must translate");
    assert_eq!(parsed["thinking"], json!({"type": "adaptive"}));

    // Adaptive thinking supports forced tool use (required / named).
    for (tool_choice, expected) in [
        (json!("required"), json!({"type": "any"})),
        (
            json!({"type": "function", "function": {"name": "get_weather"}}),
            json!({"type": "tool", "name": "get_weather"}),
        ),
    ] {
        let body = json!({
            "model": "claude-3-5-sonnet",
            "stream": true,
            "messages": [{"role": "user", "content": "weather?"}],
            "tools": weather_tools(),
            "tool_choice": tool_choice,
            "thinking": {"type": "adaptive"}
        });
        let parsed = translate_anthropic_body(&body)
            .await
            .expect("adaptive thinking with forced tool_choice must translate");
        assert_eq!(parsed["tool_choice"], expected);
        assert_eq!(parsed["thinking"], json!({"type": "adaptive"}));
    }

    // Forced tool use with manual enabled thinking is rejected at admission.
    for tool_choice in [
        json!("required"),
        json!({"type": "function", "function": {"name": "get_weather"}}),
    ] {
        let body = json!({
            "model": "claude-3-5-sonnet",
            "stream": true,
            "max_tokens": 4096,
            "messages": [{"role": "user", "content": "weather?"}],
            "tools": weather_tools(),
            "tool_choice": tool_choice,
            "thinking": {"type": "enabled", "budget_tokens": 1024}
        });
        let mut ctx = post_ctx(&body);
        let mut headers = json_headers();
        assert_eq!(
            reject_status(&plugin.before_proxy(&mut ctx, &mut headers).await),
            Some(400)
        );
    }

    // Disabled thinking does not block forced tool use.
    let disabled = json!({
        "model": "claude-3-5-sonnet",
        "stream": true,
        "messages": [{"role": "user", "content": "weather?"}],
        "tools": weather_tools(),
        "tool_choice": "required",
        "thinking": {"type": "disabled"}
    });
    let parsed = translate_anthropic_body(&disabled)
        .await
        .expect("disabled thinking with required must translate");
    assert_eq!(parsed["tool_choice"], json!({"type": "any"}));
    assert_eq!(parsed["thinking"], json!({"type": "disabled"}));

    // Manual budget must be >= 1024 and strictly less than forwarded max_tokens.
    let ok_budget = json!({
        "model": "claude-3-5-sonnet",
        "stream": true,
        "max_tokens": 2048,
        "messages": [{"role": "user", "content": "hi"}],
        "thinking": {"type": "enabled", "budget_tokens": 1024}
    });
    let parsed = translate_anthropic_body(&ok_budget)
        .await
        .expect("budget_tokens 1024 with sufficient max_tokens must translate");
    assert_eq!(
        parsed["thinking"],
        json!({"type": "enabled", "budget_tokens": 1024})
    );

    for (max_tokens, budget) in [
        (4096u64, 0u64),
        (4096, 1),
        (4096, 1023),
        (1024, 1024),
        (2048, 2048),
        (2048, 3000),
    ] {
        let body = json!({
            "model": "claude-3-5-sonnet",
            "stream": true,
            "max_tokens": max_tokens,
            "messages": [{"role": "user", "content": "hi"}],
            "thinking": {"type": "enabled", "budget_tokens": budget}
        });
        let mut ctx = post_ctx(&body);
        let mut headers = json_headers();
        let result = plugin.before_proxy(&mut ctx, &mut headers).await;
        assert_eq!(
            reject_status(&result),
            Some(400),
            "must reject invalid thinking budget without claiming the request"
        );
        if let PluginResult::Reject { body, .. } = result {
            assert!(
                !body.contains(&budget.to_string()) && !body.contains(&max_tokens.to_string()),
                "client error must not echo untrusted budget/max_tokens values: {body}"
            );
        }
    }

    // Malformed / open-ended thinking shapes are rejected.
    for thinking in [
        json!("enabled"),
        json!({"type": "enabled"}),
        json!({"type": "enabled", "budget_tokens": 0}),
        json!({"type": "enabled", "budget_tokens": 1024, "effort": "high"}),
        json!({"type": "adaptive", "budget_tokens": 1024}),
        json!({"type": "disabled", "budget_tokens": 1}),
        json!({"type": "mystery"}),
        json!({"type": "enabled", "budget_tokens": 1024.5}),
        json!({"type": "enabled", "budget_tokens": "1024"}),
    ] {
        let body = json!({
            "model": "claude-3-5-sonnet",
            "stream": true,
            "max_tokens": 4096,
            "messages": [{"role": "user", "content": "hi"}],
            "thinking": thinking
        });
        let mut ctx = post_ctx(&body);
        let mut headers = json_headers();
        assert_eq!(
            reject_status(&plugin.before_proxy(&mut ctx, &mut headers).await),
            Some(400)
        );
    }
}

const ANTHROPIC_TOOL_USE_SSE: &str = concat!(
    "event: message_start\n",
    "data: {\"type\":\"message_start\",\"message\":{\"id\":\"msg_tool\",\"type\":\"message\",\"role\":\"assistant\",\"model\":\"claude-3-5-sonnet\",\"content\":[],\"stop_reason\":null,\"usage\":{\"input_tokens\":3,\"output_tokens\":1}}}\n\n",
    "event: content_block_start\n",
    "data: {\"type\":\"content_block_start\",\"index\":0,\"content_block\":{\"type\":\"tool_use\",\"id\":\"call_secret\",\"name\":\"get_weather\",\"input\":{}}}\n\n",
    "event: content_block_delta\n",
    "data: {\"type\":\"content_block_delta\",\"index\":0,\"delta\":{\"type\":\"input_json_delta\",\"partial_json\":\"{\\\"location\\\":\\\"secret\\\"}\"}}\n\n",
    "event: content_block_stop\n",
    "data: {\"type\":\"content_block_stop\",\"index\":0}\n\n",
    "event: message_delta\n",
    "data: {\"type\":\"message_delta\",\"delta\":{\"stop_reason\":\"tool_use\",\"stop_sequence\":null},\"usage\":{\"output_tokens\":2}}\n\n",
    "event: message_stop\n",
    "data: {\"type\":\"message_stop\"}\n\n",
);

async fn claim_and_translate_tool_choice_none(
    plugin: &AiStreamRouter,
) -> (RequestContext, HashMap<String, String>) {
    let body = json!({
        "model": "claude-3-5-sonnet",
        "stream": true,
        "messages": [{"role": "user", "content": "weather?"}],
        "tools": weather_tools(),
        "tool_choice": "none"
    });
    let mut ctx = post_ctx(&body);
    let mut headers = json_headers();
    assert!(matches!(
        plugin.before_proxy(&mut ctx, &mut headers).await,
        PluginResult::Continue
    ));
    let raw = serde_json::to_vec(&body).unwrap();
    let translated = plugin
        .transform_request_body_with_context(&mut ctx, &raw, Some("application/json"), &headers)
        .await
        .expect("none must translate");
    let parsed: Value = serde_json::from_slice(&translated).unwrap();
    assert_eq!(parsed["tool_choice"], json!({"type": "none"}));
    assert_eq!(
        ctx.metadata
            .get("ai_stream_router.tool_choice_none")
            .map(String::as_str),
        Some("true")
    );
    (ctx, headers)
}

#[tokio::test]
async fn test_normalizer_fails_closed_when_provider_emits_tool_use_under_none() {
    let plugin = build(openai_and_anthropic_config());
    let (ctx, _) = claim_and_translate_tool_choice_none(&plugin).await;

    let mut inspector = plugin
        .response_stream_inspector(&ctx, 200, Some("text/event-stream"))
        .expect("inspector");
    let mut collected = Vec::new();
    match inspector.on_chunk(ANTHROPIC_TOOL_USE_SSE.as_bytes()).await {
        ResponseStreamAction::Forward(b) | ResponseStreamAction::Terminate(Some(b)) => {
            collected.extend_from_slice(&b)
        }
        ResponseStreamAction::Terminate(None) => {}
    }
    let out = String::from_utf8(collected).unwrap();
    assert!(
        out.contains("upstream_error"),
        "must fail closed instead of emitting tool_calls: {out}"
    );
    assert!(
        !out.contains("tool_calls"),
        "must not normalize forbidden tool_use into OpenAI tool_calls: {out}"
    );
    assert!(
        !out.contains("call_secret") && !out.contains("get_weather") && !out.contains("secret"),
        "error path must not reflect provider tool payload: {out}"
    );
    assert!(out.contains("[DONE]"));
}

#[tokio::test]
async fn test_buffered_normalizer_fails_closed_when_provider_emits_tool_use_under_none() {
    let plugin = build(openai_and_anthropic_config());
    let (mut ctx, _) = claim_and_translate_tool_choice_none(&plugin).await;

    let buffered = plugin
        .normalize_response_body_with_context(
            &mut ctx,
            200,
            ANTHROPIC_TOOL_USE_SSE.as_bytes(),
            Some("text/event-stream"),
            &HashMap::new(),
        )
        .await
        .expect("buffered path should produce a fail-closed SSE body");
    let out = String::from_utf8(buffered).unwrap();
    assert!(out.contains("upstream_error"));
    assert!(!out.contains("tool_calls"));
    assert!(out.contains("[DONE]"));
}

#[tokio::test]
async fn test_normalizer_still_emits_tool_calls_when_tool_choice_allows() {
    let plugin = build(openai_and_anthropic_config());
    let body = json!({
        "model": "claude-3-5-sonnet",
        "stream": true,
        "messages": [{"role": "user", "content": "weather?"}],
        "tools": weather_tools(),
        "tool_choice": "auto"
    });
    let mut ctx = post_ctx(&body);
    let mut headers = json_headers();
    plugin.before_proxy(&mut ctx, &mut headers).await;
    let raw = serde_json::to_vec(&body).unwrap();
    plugin
        .transform_request_body_with_context(&mut ctx, &raw, Some("application/json"), &headers)
        .await
        .expect("auto must translate");
    assert!(
        !ctx.metadata
            .contains_key("ai_stream_router.tool_choice_none")
    );

    let mut inspector = plugin
        .response_stream_inspector(&ctx, 200, Some("text/event-stream"))
        .expect("inspector");
    let mut collected = Vec::new();
    match inspector.on_chunk(ANTHROPIC_TOOL_USE_SSE.as_bytes()).await {
        ResponseStreamAction::Forward(b) | ResponseStreamAction::Terminate(Some(b)) => {
            collected.extend_from_slice(&b)
        }
        ResponseStreamAction::Terminate(None) => {}
    }
    if !String::from_utf8_lossy(&collected).contains("[DONE]") {
        match inspector.on_end().await {
            ResponseStreamAction::Forward(b) | ResponseStreamAction::Terminate(Some(b)) => {
                collected.extend_from_slice(&b)
            }
            ResponseStreamAction::Terminate(None) => {}
        }
    }
    let out = String::from_utf8(collected).unwrap();
    assert!(
        out.contains("tool_calls"),
        "auto must still normalize tool_use: {out}"
    );
    assert!(!out.contains("upstream_error"));
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
    let saw_normalized = Arc::new(AtomicBool::new(false));
    let mut chain = chain_response_stream_inspectors(vec![
        Box::new(RejectProviderNative {
            saw_normalized: Arc::clone(&saw_normalized),
        }),
        normalizer,
    ])
    .expect("chained inspectors");
    let output = match chain.on_chunk(ANTHROPIC_SSE.as_bytes()).await {
        ResponseStreamAction::Forward(output) | ResponseStreamAction::Terminate(Some(output)) => {
            output
        }
        ResponseStreamAction::Terminate(None) => {
            panic!("normalizer terminated without releasing OpenAI SSE")
        }
    };
    let output = String::from_utf8(output.to_vec()).expect("normalized UTF-8 SSE");
    assert!(output.contains("chat.completion.chunk"));
    assert!(!output.contains("content_block_delta"));
    assert!(
        saw_normalized.load(Ordering::SeqCst),
        "the downstream policy inspector must receive the normalizer's terminal window"
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
// Normalizer resource bounds (GHSA-7c68-39j4-mjg9)
// ---------------------------------------------------------------------------

async fn claimed_anthropic_inspector() -> (
    AiStreamRouter,
    RequestContext,
    Box<dyn ResponseStreamInspector>,
) {
    let plugin = build(openai_and_anthropic_config());
    let claude = json!({"model": "claude-3-5-sonnet", "stream": true, "messages": []});
    let mut ctx = post_ctx(&claude);
    let mut headers = json_headers();
    plugin.before_proxy(&mut ctx, &mut headers).await;
    let inspector = plugin
        .response_stream_inspector(&ctx, 200, Some("text/event-stream"))
        .expect("anthropic normalizer");
    (plugin, ctx, inspector)
}

fn assert_bound_termination(text: &str, needle: &str) {
    assert!(text.contains("upstream_error"), "{text}");
    assert!(text.contains(needle), "{text}");
    assert!(text.trim_end().ends_with("data: [DONE]"), "{text}");
    // Stable diagnostics must not echo raw provider payload bytes.
    assert!(!text.contains("aaaaaaaa"), "{text}");
}

fn oversized_complete_event(event_bytes: usize) -> Vec<u8> {
    // `data: ` (6) + filler + `\n\n` (2) == event_bytes.
    assert!(event_bytes >= 8, "event frame too small");
    let filler_len = event_bytes - 8;
    let mut event = Vec::with_capacity(event_bytes);
    event.extend_from_slice(b"data: ");
    event.resize(event.len() + filler_len, b'a');
    event.extend_from_slice(b"\n\n");
    assert_eq!(event.len(), event_bytes);
    event
}

#[tokio::test]
async fn test_normalizer_terminates_on_oversized_sse_event() {
    let (_plugin, _ctx, mut inspector) = claimed_anthropic_inspector().await;

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
    assert_bound_termination(&text, "oversized");

    // After termination the inspector keeps the stream closed without
    // emitting the terminal payload a second time.
    let after = inspector.on_chunk(b"data: {}\n\n").await;
    match after {
        ResponseStreamAction::Terminate(None) => {}
        ResponseStreamAction::Terminate(Some(_)) => panic!("must not emit terminal bytes twice"),
        ResponseStreamAction::Forward(_) => panic!("terminated inspector must remain closed"),
    }
}

#[tokio::test]
async fn test_normalizer_rejects_complete_event_at_exact_boundary_plus_one() {
    let (_plugin, _ctx, mut inspector) = claimed_anthropic_inspector().await;
    let event = oversized_complete_event(MAX_SSE_EVENT_BYTES + 1);
    let action = inspector.on_chunk(&event).await;
    match action {
        ResponseStreamAction::Terminate(Some(bytes)) => {
            let text = String::from_utf8(bytes.to_vec()).unwrap();
            assert_bound_termination(&text, "oversized");
        }
        other => panic!("boundary+1 complete event must terminate before parse: {other:?}"),
    }
}

#[tokio::test]
async fn test_normalizer_accepts_complete_event_at_exact_per_event_boundary() {
    let (_plugin, _ctx, mut inspector) = claimed_anthropic_inspector().await;
    // Exact-cap frame that is not valid Anthropic JSON: the size gate must
    // admit it so malformed-JSON rejection (not oversized) is what fires.
    let event = oversized_complete_event(MAX_SSE_EVENT_BYTES);
    let action = inspector.on_chunk(&event).await;
    match action {
        ResponseStreamAction::Terminate(Some(bytes)) => {
            let text = String::from_utf8(bytes.to_vec()).unwrap();
            assert!(text.contains("upstream_error"), "{text}");
            assert!(
                text.contains("malformed") || text.contains("JSON"),
                "exact-cap event must reach parse/framing checks, not the oversized gate: {text}"
            );
            assert!(!text.contains("oversized"), "{text}");
        }
        ResponseStreamAction::Forward(bytes) => {
            // Ignored non-JSON data frames may forward empty/partial output.
            assert!(
                bytes.is_empty()
                    || String::from_utf8_lossy(&bytes).contains("chat.completion.chunk"),
                "unexpected forward payload"
            );
        }
        other => panic!("exact-cap event must not be treated as oversized: {other:?}"),
    }
}

#[tokio::test]
async fn test_normalizer_rejects_split_oversized_event_before_boundary() {
    let (_plugin, _ctx, mut inspector) = claimed_anthropic_inspector().await;
    let half = MAX_SSE_EVENT_BYTES / 2 + 1;
    let first = vec![b'x'; half];
    match inspector.on_chunk(&first).await {
        ResponseStreamAction::Forward(bytes) => assert!(bytes.is_empty()),
        other => panic!("first half under the cap must not terminate: {other:?}"),
    }
    let second = vec![b'y'; half];
    match inspector.on_chunk(&second).await {
        ResponseStreamAction::Terminate(Some(bytes)) => {
            let text = String::from_utf8(bytes.to_vec()).unwrap();
            assert_bound_termination(&text, "oversized");
        }
        other => panic!("split oversized partial must terminate: {other:?}"),
    }
}

#[tokio::test]
async fn test_normalizer_rejects_when_boundary_arrives_with_final_oversized_bytes() {
    let (_plugin, _ctx, mut inspector) = claimed_anthropic_inspector().await;
    // Fill exactly to the cap with no delimiter, then deliver the blank line
    // that would complete an oversized frame.
    let prefix = vec![b'z'; MAX_SSE_EVENT_BYTES];
    match inspector.on_chunk(&prefix).await {
        ResponseStreamAction::Forward(bytes) => assert!(bytes.is_empty()),
        other => panic!("exact-cap partial must wait for more bytes: {other:?}"),
    }
    match inspector.on_chunk(b"\n\n").await {
        ResponseStreamAction::Terminate(Some(bytes)) => {
            let text = String::from_utf8(bytes.to_vec()).unwrap();
            assert_bound_termination(&text, "oversized");
        }
        other => panic!("delimiter completing an oversized event must terminate: {other:?}"),
    }
}

#[tokio::test]
async fn test_normalizer_many_small_events_stream_without_quadratic_growth() {
    let (_plugin, _ctx, mut inspector) = claimed_anthropic_inspector().await;
    // Many tiny complete frames in one chunk: cursor design must finish
    // without terminating and without requiring giant allocations.
    let event = b"data: {\"type\":\"ping\"}\n\n";
    let count = 2_048usize;
    let mut body = Vec::with_capacity(count * event.len());
    for _ in 0..count {
        body.extend_from_slice(event);
    }
    match inspector.on_chunk(&body).await {
        ResponseStreamAction::Forward(bytes) => {
            assert!(
                bytes.is_empty(),
                "ping frames produce no OpenAI output: {}",
                String::from_utf8_lossy(&bytes)
            );
        }
        other => panic!("many small in-limit events must not terminate: {other:?}"),
    }
    // Structural companion: library-inline `sse_buffer_tests` asserts cursor
    // compaction keeps capacity O(partial). Here we only prove the public
    // streaming path stays healthy under a many-event burst.
}

#[tokio::test]
async fn test_normalizer_rejects_excessive_normalized_output() {
    let (_plugin, _ctx, mut inspector) = claimed_anthropic_inspector().await;
    // Text-dominated frames expand ~1:1 and trip the 8 MiB plaintext ceiling
    // before the 16 MiB normalized-output ceiling. A long stream id is repeated
    // in every OpenAI envelope, so tiny Anthropic text deltas expand enough to
    // exercise the output bound while staying under the plaintext and
    // event-count caps.
    let stream_id = "m".repeat(32 * 1024);
    let start = format!(
        "event: message_start\n\
         data: {{\"type\":\"message_start\",\"message\":{{\"id\":\"{stream_id}\",\"type\":\"message\",\"role\":\"assistant\",\"model\":\"claude-3-5-sonnet\",\"content\":[],\"usage\":{{\"input_tokens\":1,\"output_tokens\":1}}}}}}\n\n"
    );
    match inspector.on_chunk(start.as_bytes()).await {
        ResponseStreamAction::Forward(_) => {}
        other => panic!("message_start must forward: {other:?}"),
    }

    let delta = b"data: {\"type\":\"content_block_delta\",\"index\":0,\"delta\":{\"type\":\"text_delta\",\"text\":\"x\"}}\n\n";
    assert!(
        delta.len() < 128,
        "fixture delta must stay tiny so OpenAI envelope expansion dominates"
    );
    const {
        assert!(
            MAX_SSE_NORMALIZED_OUTPUT_BYTES > MAX_SSE_NORMALIZED_BODY_BYTES,
            "output ceiling must sit above the plaintext ceiling"
        );
    }

    let batch_events = 64usize;
    let mut batch = Vec::with_capacity(batch_events * delta.len());
    for _ in 0..batch_events {
        batch.extend_from_slice(delta);
    }
    // Long enough to exceed the 16 MiB output ceiling under envelope expansion
    // (id repeated per OpenAI chunk), but still under the event-count hard cap.
    let max_batches = MAX_SSE_EVENTS / batch_events;

    for index in 0..max_batches {
        match inspector.on_chunk(&batch).await {
            ResponseStreamAction::Forward(_) => {}
            ResponseStreamAction::Terminate(Some(bytes)) => {
                let text = String::from_utf8(bytes.to_vec()).unwrap();
                assert_bound_termination(&text, "cumulative normalized size limit");
                // Distinguish from the plaintext body ceiling diagnostic.
                assert!(
                    !text.contains("exceeded the cumulative size limit"),
                    "{text}"
                );
                assert!(!text.contains("event count limit"), "{text}");
                assert!(!text.contains("oversized"), "{text}");
                return;
            }
            other => panic!("text delta batch {index} unexpected: {other:?}"),
        }
    }
    panic!("stream must terminate before {max_batches} batches exhaust the output cap");
}

#[tokio::test]
async fn test_normalizer_terminal_provider_error_cannot_bypass_output_cap() {
    let (_plugin, _ctx, mut inspector) = claimed_anthropic_inspector().await;
    let stream_id = "m".repeat(32 * 1024);
    let start = format!(
        "event: message_start\n\
         data: {{\"type\":\"message_start\",\"message\":{{\"id\":\"{stream_id}\",\"type\":\"message\",\"role\":\"assistant\",\"model\":\"claude-3-5-sonnet\",\"content\":[],\"usage\":{{\"input_tokens\":1,\"output_tokens\":1}}}}}}\n\n"
    );
    let mut forwarded = match inspector.on_chunk(start.as_bytes()).await {
        ResponseStreamAction::Forward(bytes) => bytes.len(),
        other => panic!("message_start must forward: {other:?}"),
    };

    let delta = b"data: {\"type\":\"content_block_delta\",\"index\":0,\"delta\":{\"type\":\"text_delta\",\"text\":\"x\"}}\n\n";
    let batch_events = 8usize;
    let mut batch = Vec::with_capacity(batch_events * delta.len());
    for _ in 0..batch_events {
        batch.extend_from_slice(delta);
    }

    // Stop with less than 900 KiB remaining. One batch expands by far less
    // than the 388 KiB gap between that target and the terminal reserve.
    const PROVIDER_MESSAGE_BYTES: usize = 900 * 1024;
    let target = MAX_SSE_NORMALIZED_OUTPUT_BYTES - PROVIDER_MESSAGE_BYTES;
    while forwarded < target {
        match inspector.on_chunk(&batch).await {
            ResponseStreamAction::Forward(bytes) => forwarded += bytes.len(),
            other => panic!("in-budget text deltas must forward: {other:?}"),
        }
    }

    let provider_marker = "PROVIDER-CONTROLLED-TERMINAL-SECRET:";
    let provider_message = format!(
        "{provider_marker}{}",
        "p".repeat(PROVIDER_MESSAGE_BYTES - provider_marker.len())
    );
    let provider_error = format!(
        "event: error\n\
         data: {{\"type\":\"error\",\"error\":{{\"message\":\"{provider_message}\"}}}}\n\n"
    );
    assert!(
        provider_error.len() < MAX_SSE_EVENT_BYTES,
        "terminal fixture must remain within the per-event cap"
    );

    let terminal = match inspector.on_chunk(provider_error.as_bytes()).await {
        ResponseStreamAction::Terminate(Some(bytes)) => bytes,
        other => panic!("oversized normalized terminal output must terminate: {other:?}"),
    };
    let text = String::from_utf8(terminal.to_vec()).unwrap();
    assert_bound_termination(&text, "cumulative normalized size limit");
    assert!(
        !text.contains(provider_marker),
        "provider-controlled terminal text must be replaced, not echoed"
    );
    assert_eq!(text.matches("data: [DONE]").count(), 1, "{text}");
    assert!(
        forwarded + text.len() <= MAX_SSE_NORMALIZED_OUTPUT_BYTES,
        "terminal output must remain within the cumulative normalized cap"
    );
}

#[tokio::test]
async fn test_normalizer_cumulative_body_exhaustion() {
    let (_plugin, _ctx, mut inspector) = claimed_anthropic_inspector().await;
    const EVENT_BYTES: usize = 512 * 1024;
    let prefix = b"data: {\"type\":\"ping\",\"padding\":\"";
    let suffix = b"\"}\n\n";
    let mut event = Vec::with_capacity(EVENT_BYTES);
    event.extend_from_slice(prefix);
    event.resize(EVENT_BYTES - suffix.len(), b'a');
    event.extend_from_slice(suffix);
    assert_eq!(event.len(), EVENT_BYTES);
    assert!(event.len() < MAX_SSE_EVENT_BYTES);
    assert_eq!(MAX_SSE_NORMALIZED_BODY_BYTES, 8 * 1024 * 1024);

    // Sixteen valid ~512 KiB frames exactly fill the 8 MiB plaintext budget.
    // The seventeenth must trip that budget specifically, well before either
    // the per-event or event-count limits.
    for index in 0..16 {
        match inspector.on_chunk(&event).await {
            ResponseStreamAction::Forward(bytes) => assert!(
                bytes.is_empty(),
                "valid ping frame {index} should produce no normalized output"
            ),
            other => panic!("in-budget valid frame {index} must continue: {other:?}"),
        }
    }
    match inspector.on_chunk(&event).await {
        ResponseStreamAction::Terminate(Some(bytes)) => {
            let text = String::from_utf8(bytes.to_vec()).unwrap();
            assert_bound_termination(&text, "cumulative size limit");
            assert!(!text.contains("event count limit"), "{text}");
            assert!(!text.contains("oversized"), "{text}");
        }
        other => panic!("seventeenth valid frame must cross the cumulative cap: {other:?}"),
    }
}

#[tokio::test]
async fn test_normalizer_event_count_exhaustion() {
    let (_plugin, _ctx, mut inspector) = claimed_anthropic_inspector().await;
    let event = b"data: {\"type\":\"ping\"}\n\n";
    // Stay under the cumulative byte cap while exhausting the event counter.
    assert!(
        (MAX_SSE_EVENTS + 1) * event.len() <= MAX_SSE_NORMALIZED_BODY_BYTES,
        "event-count fixture must fit under the body byte cap"
    );
    let batch = 1_024usize;
    let mut seen = 0usize;
    let mut terminated = None;
    while seen < MAX_SSE_EVENTS + 1 {
        let n = batch.min(MAX_SSE_EVENTS + 1 - seen);
        let mut chunk = Vec::with_capacity(n * event.len());
        for _ in 0..n {
            chunk.extend_from_slice(event);
        }
        match inspector.on_chunk(&chunk).await {
            ResponseStreamAction::Forward(_) => seen += n,
            ResponseStreamAction::Terminate(bytes) => {
                terminated = Some(bytes);
                break;
            }
        }
    }
    let final_bytes = terminated
        .expect("event-count exhaustion must terminate")
        .expect("termination payload required");
    let text = String::from_utf8(final_bytes.to_vec()).unwrap();
    assert_bound_termination(&text, "event count limit");
}

#[tokio::test]
async fn test_normalizer_rejects_excessive_json_depth() {
    let (_plugin, _ctx, mut inspector) = claimed_anthropic_inspector().await;
    let depth = MAX_SSE_EVENT_JSON_DEPTH + 1;
    let mut payload = String::new();
    for _ in 0..depth {
        payload.push('{');
        payload.push_str("\"k\":");
    }
    payload.push('1');
    for _ in 0..depth {
        payload.push('}');
    }
    let frame = format!("data: {payload}\n\n");
    match inspector.on_chunk(frame.as_bytes()).await {
        ResponseStreamAction::Terminate(Some(bytes)) => {
            let text = String::from_utf8(bytes.to_vec()).unwrap();
            assert_bound_termination(&text, "excessive JSON nesting");
        }
        other => panic!("over-deep JSON must fail closed before parse: {other:?}"),
    }
}

#[tokio::test]
async fn test_normalizer_trailing_incomplete_event_is_malformed() {
    let (_plugin, _ctx, mut inspector) = claimed_anthropic_inspector().await;
    let body = concat!(
        "event: message_start\n",
        "data: {\"type\":\"message_start\",\"message\":{\"id\":\"msg_tr\",\"type\":\"message\",\"role\":\"assistant\",\"model\":\"claude-3-5-sonnet\",\"content\":[],\"usage\":{\"input_tokens\":1,\"output_tokens\":1}}}\n\n",
        "data: {\"type\":\"content_block_delta\",\"index\":0,\"delta\":{\"type\":\"text_delta\",\"text\":\"x\"",
    );
    match inspector.on_chunk(body.as_bytes()).await {
        ResponseStreamAction::Forward(_) => {}
        other => panic!("incomplete trailing frame must wait for EOF: {other:?}"),
    }
    match inspector.on_end().await {
        ResponseStreamAction::Terminate(Some(bytes)) => {
            let text = String::from_utf8(bytes.to_vec()).unwrap();
            assert!(text.contains("malformed trailing data"), "{text}");
            // Delimiter-less EOF remainder must not use the complete-event
            // malformed-JSON diagnostic.
            assert!(!text.contains("malformed SSE JSON"), "{text}");
            assert!(text.trim_end().ends_with("data: [DONE]"), "{text}");
            assert_eq!(text.matches("data: [DONE]").count(), 1, "{text}");
        }
        other => panic!("EOF must fail closed on incomplete trailing data: {other:?}"),
    }
}

#[tokio::test]
async fn test_normalizer_sse_comment_frames_are_ignored() {
    let (_plugin, _ctx, mut inspector) = claimed_anthropic_inspector().await;
    let body = concat!(
        ": keepalive\n\n",
        "event: message_start\n",
        "data: {\"type\":\"message_start\",\"message\":{\"id\":\"msg_c\",\"type\":\"message\",\"role\":\"assistant\",\"model\":\"claude-3-5-sonnet\",\"content\":[],\"usage\":{\"input_tokens\":1,\"output_tokens\":1}}}\n\n",
        "event: content_block_delta\n",
        "data: {\"type\":\"content_block_delta\",\"index\":0,\"delta\":{\"type\":\"text_delta\",\"text\":\"ok\"}}\n\n",
        "event: message_delta\n",
        "data: {\"type\":\"message_delta\",\"delta\":{\"stop_reason\":\"end_turn\"},\"usage\":{\"output_tokens\":1}}\n\n",
        "event: message_stop\n",
        "data: {\"type\":\"message_stop\"}\n\n",
    );
    match inspector.on_chunk(body.as_bytes()).await {
        ResponseStreamAction::Forward(bytes) | ResponseStreamAction::Terminate(Some(bytes)) => {
            let text = String::from_utf8(bytes.to_vec()).unwrap();
            assert!(text.contains("\"content\":\"ok\""), "{text}");
            assert!(text.trim_end().ends_with("data: [DONE]"), "{text}");
            assert!(!text.contains("upstream_error"), "{text}");
        }
        ResponseStreamAction::Terminate(None) => {
            panic!("comment frames must not terminate the stream early")
        }
    }
}

#[tokio::test]
async fn test_normalizer_buffered_path_enforces_complete_event_size() {
    let (plugin, mut ctx, _inspector) = claimed_anthropic_inspector().await;
    let event = oversized_complete_event(MAX_SSE_EVENT_BYTES + 1);
    let out = plugin
        .normalize_response_body_with_context(
            &mut ctx,
            200,
            &event,
            Some("text/event-stream"),
            &HashMap::new(),
        )
        .await
        .expect("buffered normalize must return a body");
    let text = String::from_utf8(out).unwrap();
    assert_bound_termination(&text, "oversized");
}

#[tokio::test]
async fn test_normalizer_streamed_path_enforces_complete_event_size_single_chunk() {
    let (_plugin, _ctx, mut inspector) = claimed_anthropic_inspector().await;
    // Single chunk containing the entire oversized event and blank-line
    // boundary — the original advisory reproduction.
    let mut chunk = oversized_complete_event(MAX_SSE_EVENT_BYTES + 1);
    chunk.extend_from_slice(b"data: {\"type\":\"ping\"}\n\n");
    match inspector.on_chunk(&chunk).await {
        ResponseStreamAction::Terminate(Some(bytes)) => {
            let text = String::from_utf8(bytes.to_vec()).unwrap();
            assert_bound_termination(&text, "oversized");
        }
        other => panic!("single-chunk oversized complete event must terminate: {other:?}"),
    }
}

#[tokio::test]
async fn test_normalizer_malformed_utf8_fails_closed() {
    let (_plugin, _ctx, mut inspector) = claimed_anthropic_inspector().await;
    let frame = b"data: \xff\xfe not utf8\n\n";
    match inspector.on_chunk(frame).await {
        ResponseStreamAction::Terminate(Some(bytes)) => {
            let text = String::from_utf8(bytes.to_vec()).unwrap();
            assert!(text.contains("upstream_error"), "{text}");
            assert!(text.contains("malformed"), "{text}");
            assert!(text.trim_end().ends_with("data: [DONE]"), "{text}");
        }
        other => panic!("malformed UTF-8 must fail closed: {other:?}"),
    }
}

#[tokio::test]
async fn test_concurrent_independent_normalizers() {
    let plugin = build(openai_and_anthropic_config());
    let claude = json!({"model": "claude-3-5-sonnet", "stream": true, "messages": []});

    let mut handles = Vec::new();
    for i in 0..4 {
        let plugin = build(openai_and_anthropic_config());
        let mut ctx = post_ctx(&claude);
        let mut headers = json_headers();
        plugin.before_proxy(&mut ctx, &mut headers).await;
        handles.push(tokio::spawn(async move {
            let mut inspector = plugin
                .response_stream_inspector(&ctx, 200, Some("text/event-stream"))
                .expect("inspector");
            if i % 2 == 0 {
                let bad = oversized_complete_event(MAX_SSE_EVENT_BYTES + 1);
                match inspector.on_chunk(&bad).await {
                    ResponseStreamAction::Terminate(Some(bytes)) => {
                        let text = String::from_utf8(bytes.to_vec()).unwrap();
                        assert!(text.contains("oversized"), "{text}");
                    }
                    other => panic!("concurrent oversized path failed: {other:?}"),
                }
            } else {
                let ok = concat!(
                    "event: message_start\n",
                    "data: {\"type\":\"message_start\",\"message\":{\"id\":\"msg_c\",\"type\":\"message\",\"role\":\"assistant\",\"model\":\"claude-3-5-sonnet\",\"content\":[],\"usage\":{\"input_tokens\":1,\"output_tokens\":1}}}\n\n",
                    "event: content_block_delta\n",
                    "data: {\"type\":\"content_block_delta\",\"index\":0,\"delta\":{\"type\":\"text_delta\",\"text\":\"ok\"}}\n\n",
                    "event: message_delta\n",
                    "data: {\"type\":\"message_delta\",\"delta\":{\"stop_reason\":\"end_turn\"},\"usage\":{\"output_tokens\":1}}\n\n",
                    "event: message_stop\n",
                    "data: {\"type\":\"message_stop\"}\n\n",
                );
                let mut out = Vec::new();
                match inspector.on_chunk(ok.as_bytes()).await {
                    ResponseStreamAction::Forward(b) | ResponseStreamAction::Terminate(Some(b)) => {
                        out.extend_from_slice(&b);
                    }
                    ResponseStreamAction::Terminate(None) => {}
                }
                if !String::from_utf8_lossy(&out).contains("[DONE]") {
                    match inspector.on_end().await {
                        ResponseStreamAction::Forward(b)
                        | ResponseStreamAction::Terminate(Some(b)) => {
                            out.extend_from_slice(&b);
                        }
                        ResponseStreamAction::Terminate(None) => {}
                    }
                }
                let text = String::from_utf8(out).unwrap();
                assert!(text.contains("\"content\":\"ok\""), "{text}");
                assert!(text.contains("data: [DONE]"), "{text}");
            }
        }));
    }
    for handle in handles {
        handle.await.expect("normalizer task");
    }
    // Keep the outer plugin alive so the test clearly owns independent instances.
    let _ = plugin.name();
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
    let headers = json_headers();
    let res = run_federation_final_body(&fed, &mut ctx, &headers).await;
    assert_eq!(reject_status(&res), Some(501));
}

#[tokio::test]
async fn test_ai_federation_defers_to_claimed_stream_router_request() {
    // Drive a REAL claim rather than faking the public coordination marker:
    // the private typed claim is what `ai_federation` decides on
    // (`GHSA-xhp5-hqj8-3mwg`), so a marker-only fixture would no longer prove
    // the composition.
    let fed = ai_federation_openai();
    let (mut ctx, headers) = claimed_provider_context(None).await;
    let res = run_federation_final_body(&fed, &mut ctx, &headers).await;
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
    let headers = json_headers();
    let res = run_federation_final_body(&fed, &mut ctx, &headers).await;
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
        run_federation_final_body(&fed, &mut ctx, &headers).await,
        PluginResult::Continue
    ));

    // stream:false → NOT claimed by ai_stream_router and therefore remains
    // eligible for ai_federation's later finalized-egress phase.
    let non_streaming = json!({"model": "gpt-4o", "messages": [{"role": "user", "content": "hi"}]});
    let mut ctx2 = post_ctx(&non_streaming);
    let mut headers2 = json_headers();
    assert!(matches!(
        router.before_proxy(&mut ctx2, &mut headers2).await,
        PluginResult::Continue
    ));
    assert!(!ctx2.metadata.contains_key("ai_stream_router_claimed"));
}

// ---------------------------------------------------------------------------
// GHSA-xhp5-hqj8-3mwg — the PRIVATE claim, not the public marker, is what
// makes a built-in stand down.
//
// `ai_stream_router_claimed` is a plain string in a mutable metadata map. Every
// built-in that must not act on a provider-bound request now decides from
// `RequestContext::has_ai_stream_router_claim()`, so deleting or rewriting the
// marker after a real claim changes nothing.
// ---------------------------------------------------------------------------

/// How a later plugin might sabotage the public coordination marker.
#[derive(Clone, Copy)]
enum MarkerSabotage {
    Removed,
    RewrittenToFalse,
    RewrittenToGarbage,
}

const MARKER_SABOTAGE_CASES: [MarkerSabotage; 3] = [
    MarkerSabotage::Removed,
    MarkerSabotage::RewrittenToFalse,
    MarkerSabotage::RewrittenToGarbage,
];

/// Drive a REAL claim through `ai_stream_router`, then optionally sabotage the
/// public marker exactly as a later plugin could.
async fn claimed_provider_context(
    sabotage: Option<MarkerSabotage>,
) -> (RequestContext, HashMap<String, String>) {
    let router = build(openai_and_anthropic_config());
    let body = streaming_request("gpt-4o");
    let mut ctx = post_ctx(&body);
    ctx.matched_proxy = Some(Arc::new(create_test_proxy()));
    let mut headers = json_headers();
    assert!(matches!(
        router.before_proxy(&mut ctx, &mut headers).await,
        PluginResult::Continue
    ));
    assert_eq!(
        ctx.metadata
            .get("ai_stream_router_claimed")
            .map(String::as_str),
        Some("true"),
        "the observability marker should still be published for logs and \
         third-party coordination"
    );
    match sabotage {
        None => {}
        Some(MarkerSabotage::Removed) => {
            ctx.metadata.remove("ai_stream_router_claimed");
        }
        Some(MarkerSabotage::RewrittenToFalse) => {
            ctx.metadata
                .insert("ai_stream_router_claimed".to_string(), "false".to_string());
        }
        Some(MarkerSabotage::RewrittenToGarbage) => {
            ctx.metadata.insert(
                "ai_stream_router_claimed".to_string(),
                "TRUE-but-not-the-literal".to_string(),
            );
        }
    }
    (ctx, headers)
}

/// The committed provider destination, so a routing built-in can be shown not
/// to have moved it.
fn committed_destination(ctx: &RequestContext) -> (Option<String>, Option<u16>, Option<String>) {
    (
        ctx.route_override_backend_host.clone(),
        ctx.route_override_backend_port,
        ctx.route_override_path.clone(),
    )
}

#[tokio::test]
async fn federation_ignores_a_sabotaged_claim_marker() {
    let fed = ai_federation_openai();

    // Non-vacuity: with no claim at all, this exact request IS acted on.
    let body = streaming_request("gpt-4o");
    let mut unclaimed = post_ctx(&body);
    let headers = json_headers();
    assert_eq!(
        reject_status(&run_federation_final_body(&fed, &mut unclaimed, &headers).await),
        Some(501),
        "control: ai_federation acts on an unclaimed streaming request"
    );

    for sabotage in MARKER_SABOTAGE_CASES {
        let (mut ctx, headers) = claimed_provider_context(Some(sabotage)).await;
        assert!(
            matches!(
                run_federation_final_body(&fed, &mut ctx, &headers).await,
                PluginResult::Continue
            ),
            "federation must stand down on a real claim regardless of the marker"
        );
    }
}

#[tokio::test]
async fn request_mirror_ignores_a_sabotaged_claim_marker() {
    fn mirror() -> RequestMirror {
        RequestMirror::new(
            &json!({
                "mirror_host": "127.0.0.1",
                "mirror_port": 1,
                "mirror_protocol": "http",
                "percentage": 100.0,
                "mirror_request_body": false
            }),
            http_client(),
        )
        .expect("mirror config should be valid")
    }

    // Non-vacuity: an unclaimed request is dispatched to the shadow target.
    let control = mirror();
    let body = streaming_request("gpt-4o");
    let mut unclaimed = post_ctx(&body);
    unclaimed.matched_proxy = Some(Arc::new(create_test_proxy()));
    let headers = json_headers();
    let mut overlay = HashMap::new();
    let _ = control
        .dispatch_finalized_request_egress(&mut unclaimed, &headers, b"{}", &mut overlay)
        .await;
    let control_metrics =
        ferrum_edge::_test_support::request_mirror_metrics_snapshot_for_test(&control);
    assert_eq!(
        control_metrics.dispatched, 1,
        "control: an unclaimed request is mirrored"
    );

    for sabotage in MARKER_SABOTAGE_CASES {
        let plugin = mirror();
        let (mut ctx, headers) = claimed_provider_context(Some(sabotage)).await;
        let mut overlay = HashMap::new();
        assert!(matches!(
            plugin
                .dispatch_finalized_request_egress(&mut ctx, &headers, b"{}", &mut overlay)
                .await,
            PluginResult::Continue
        ));
        let metrics = ferrum_edge::_test_support::request_mirror_metrics_snapshot_for_test(&plugin);
        assert_eq!(
            metrics.dispatched, 0,
            "a provider-bound request must never be mirrored, whatever the marker says"
        );
    }
}

#[tokio::test]
async fn serverless_function_ignores_a_sabotaged_claim_marker() {
    fn serverless() -> ServerlessFunction {
        ServerlessFunction::new(
            &json!({
                "provider": "azure_functions",
                "function_url": "https://example.invalid/func",
                "forward_headers": ["Authorization"]
            }),
            http_client(),
        )
        .expect("serverless config should be valid")
    }

    for sabotage in MARKER_SABOTAGE_CASES {
        let plugin = serverless();
        let (mut ctx, headers) = claimed_provider_context(Some(sabotage)).await;
        let mut overlay = HashMap::new();
        assert!(matches!(
            plugin
                .dispatch_finalized_request_egress(&mut ctx, &headers, b"{}", &mut overlay)
                .await,
            PluginResult::Continue
        ));
        assert!(
            !ctx.metadata
                .keys()
                .any(|key| key.starts_with("serverless_function")),
            "the function must not be invoked for a provider-bound request"
        );
        assert!(
            overlay.is_empty(),
            "no backend header overlay may be published for a claimed request"
        );
    }
}

#[tokio::test]
async fn mcp_gateway_ignores_a_sabotaged_claim_marker() {
    // The MCP endpoint path deliberately equals the claimed request's path, so
    // the plugin WOULD select this request if the claim were not decisive.
    fn mcp() -> McpGateway {
        McpGateway::new(
            &json!({
                "enabled": true,
                "mode": "transparent_proxy",
                "endpoint": {"path": "/v1/chat/completions"},
                "servers": {
                    "primary": {
                        "upstream_url": "http://mcp.invalid/rpc",
                        "namespace": "primary",
                        "enabled": true
                    }
                }
            }),
            http_client(),
        )
        .expect("mcp_gateway config should be valid")
    }

    // Non-vacuity: the same endpoint selects an unclaimed request.
    let control = mcp();
    let body = streaming_request("gpt-4o");
    let mut unclaimed = post_ctx(&body);
    let mut control_headers = json_headers();
    let _ = control
        .before_proxy(&mut unclaimed, &mut control_headers)
        .await;
    assert_eq!(
        unclaimed.metadata.get("mcp.enabled").map(String::as_str),
        Some("true"),
        "control: mcp_gateway selects this endpoint when there is no claim"
    );
    assert_eq!(
        unclaimed.metadata.get("mcp.mode").map(String::as_str),
        Some("transparent_proxy"),
        "control: mcp_gateway engaged the canonical MCP metadata namespace"
    );

    for sabotage in MARKER_SABOTAGE_CASES {
        let plugin = mcp();
        let (mut ctx, mut headers) = claimed_provider_context(Some(sabotage)).await;
        let committed = committed_destination(&ctx);
        assert!(matches!(
            plugin.before_proxy(&mut ctx, &mut headers).await,
            PluginResult::Continue
        ));
        assert_eq!(
            committed_destination(&ctx),
            committed,
            "mcp_gateway must not repoint a request whose provider credential is \
             already committed"
        );
        assert!(
            !ctx.metadata.keys().any(|key| key.starts_with("mcp.")),
            "mcp_gateway must not even emit base metadata for a claimed request"
        );
    }
}

#[tokio::test]
async fn mesh_route_dispatch_ignores_a_sabotaged_claim_marker() {
    fn mesh() -> MeshRouteDispatch {
        MeshRouteDispatch::new(&json!({
            "rules": [{
                "match": {"methods": ["POST"]},
                "destination": {"backend_host": "mesh.invalid", "backend_port": 8443}
            }]
        }))
        .expect("mesh_route_dispatch config should be valid")
    }

    // Non-vacuity: the same rule repoints an unclaimed POST.
    let control = mesh();
    let body = streaming_request("gpt-4o");
    let mut unclaimed = post_ctx(&body);
    let mut control_headers = json_headers();
    let control_result = control
        .before_proxy(&mut unclaimed, &mut control_headers)
        .await;
    assert!(matches!(control_result, PluginResult::Continue));
    assert_eq!(
        unclaimed.route_override_backend_host.as_deref(),
        Some("mesh.invalid"),
        "control: mesh_route_dispatch repoints an unclaimed POST"
    );

    for sabotage in MARKER_SABOTAGE_CASES {
        let plugin = mesh();
        let (mut ctx, mut headers) = claimed_provider_context(Some(sabotage)).await;
        let committed = committed_destination(&ctx);
        assert!(matches!(
            plugin.before_proxy(&mut ctx, &mut headers).await,
            PluginResult::Continue
        ));
        assert_eq!(
            committed_destination(&ctx),
            committed,
            "mesh_route_dispatch must not move a provider-bound request"
        );
        assert_ne!(
            ctx.route_override_backend_host.as_deref(),
            Some("mesh.invalid"),
            "the committed provider destination must survive the sabotaged marker"
        );
    }
}

#[tokio::test]
async fn intentional_pass_through_still_coordinates_through_metadata() {
    // An UNCLAIMED pass-through is a genuinely different state: there is no
    // private claim to read, so the public `ai_stream_router_pass_through` key
    // remains the coordination signal and must keep working.
    let router = build(pass_through_config());
    let body = streaming_request("unmatched-model");
    let mut ctx = post_ctx(&body);
    let mut headers = json_headers();
    assert!(matches!(
        router.before_proxy(&mut ctx, &mut headers).await,
        PluginResult::Continue
    ));
    assert_eq!(
        ctx.metadata
            .get("ai_stream_router_pass_through")
            .map(String::as_str),
        Some("true"),
        "an unclaimed pass-through must still publish its coordination marker"
    );
    assert!(
        !ferrum_edge::_test_support::request_has_ai_stream_router_claim_for_test(&ctx),
        "pass-through must not record a private claim"
    );

    let fed = ai_federation_openai();
    assert!(
        matches!(
            run_federation_final_body(&fed, &mut ctx, &headers).await,
            PluginResult::Continue
        ),
        "ai_federation must still defer to an explicit pass-through"
    );
}

fn pass_through_config() -> Value {
    let mut config = openai_and_anthropic_config();
    config["fail_on_no_matching_provider"] = json!(false);
    config["fail_on_missing_model"] = json!(false);
    config
}

// ---------------------------------------------------------------------------
// #2272 — Anthropic terminal-state failure posture
// ---------------------------------------------------------------------------

const ANTHROPIC_PARTIAL_SSE: &str = concat!(
    "event: message_start\n",
    "data: {\"type\":\"message_start\",\"message\":{\"id\":\"msg_partial\",\"type\":\"message\",\"role\":\"assistant\",\"model\":\"claude-3-5-sonnet\",\"content\":[],\"stop_reason\":null,\"usage\":{\"input_tokens\":3,\"output_tokens\":1}}}\n\n",
    "event: content_block_delta\n",
    "data: {\"type\":\"content_block_delta\",\"index\":0,\"delta\":{\"type\":\"text_delta\",\"text\":\"cut short\"}}\n\n",
);

async fn run_sse_bytes(body: &[u8]) -> (String, bool) {
    let plugin = build(openai_and_anthropic_config());
    let claude = json!({"model": "claude-3-5-sonnet", "stream": true, "messages": [{"role":"user","content":"hi"}]});
    let mut ctx = post_ctx(&claude);
    let mut headers = json_headers();
    plugin.before_proxy(&mut ctx, &mut headers).await;
    let mut inspector = plugin
        .response_stream_inspector(&ctx, 200, Some("text/event-stream"))
        .expect("inspector");
    let mut collected = Vec::new();
    let mut terminated = false;
    match inspector.on_chunk(body).await {
        ResponseStreamAction::Forward(bytes) => collected.extend_from_slice(&bytes),
        ResponseStreamAction::Terminate(bytes) => {
            terminated = true;
            if let Some(bytes) = bytes {
                collected.extend_from_slice(&bytes);
            }
        }
    }
    if !terminated {
        match inspector.on_end().await {
            ResponseStreamAction::Forward(bytes) => collected.extend_from_slice(&bytes),
            ResponseStreamAction::Terminate(bytes) => {
                terminated = true;
                if let Some(bytes) = bytes {
                    collected.extend_from_slice(&bytes);
                }
            }
        }
    }
    (String::from_utf8(collected).unwrap(), terminated)
}

async fn run_sse(body: &str) -> (String, bool) {
    run_sse_bytes(body.as_bytes()).await
}

#[tokio::test]
async fn test_premature_anthropic_eof_is_upstream_error_not_success() {
    let (out, terminated) = run_sse(ANTHROPIC_PARTIAL_SSE).await;
    assert!(terminated);
    assert!(out.contains("\"type\":\"upstream_error\""));
    assert!(out.contains("before message_stop"));
    assert!(out.contains("cut short"));
    assert!(out.trim_end().ends_with("data: [DONE]"));
    // Exactly one DONE sentinel.
    assert_eq!(out.matches("data: [DONE]").count(), 1);
}

#[tokio::test]
async fn test_anthropic_message_stop_without_start_is_protocol_error() {
    let (out, terminated) = run_sse("data: {\"type\":\"message_stop\"}\n\n").await;
    assert!(terminated);
    assert!(out.contains("before message_start"));
    assert!(out.contains("upstream_error"));
    assert_eq!(out.matches("data: [DONE]").count(), 1);
}

#[tokio::test]
async fn test_malformed_complete_sse_event_fails_closed() {
    let body = concat!(
        "event: message_start\n",
        "data: {\"type\":\"message_start\",\"message\":{\"id\":\"msg_bad\",\"type\":\"message\",\"role\":\"assistant\",\"model\":\"claude-3-5-sonnet\",\"content\":[],\"usage\":{\"input_tokens\":1,\"output_tokens\":1}}}\n\n",
        "event: content_block_delta\n",
        "data: {not-json\n\n",
    );
    let (out, terminated) = run_sse(body).await;
    assert!(terminated);
    assert!(out.contains("\"type\":\"upstream_error\""));
    assert!(out.contains("malformed SSE JSON"));
    assert_eq!(out.matches("data: [DONE]").count(), 1);
}

#[tokio::test]
async fn test_known_anthropic_events_cannot_hide_malformed_protocol_data() {
    let malformed_events = [
        concat!(
            "event: content_block_delta\n",
            "data : {\"type\":\"content_block_delta\",\"index\":0,\"delta\":{\"type\":\"text_delta\",\"text\":\"lost\"}}\n\n",
        ),
        concat!(
            "event: content_block_delta\n",
            "data: {\"index\":0,\"delta\":{\"type\":\"text_delta\",\"text\":\"lost\"}}\n\n",
        ),
        concat!(
            "event: content_block_delta\n",
            "data: {\"type\":\"message_stop\"}\n\n",
        ),
    ];

    for malformed_event in malformed_events {
        let body = format!(
            "{}{}{}",
            "event: message_start\ndata: {\"type\":\"message_start\",\"message\":{\"id\":\"msg_bad_protocol\",\"type\":\"message\",\"role\":\"assistant\",\"model\":\"claude-3-5-sonnet\",\"content\":[],\"usage\":{\"input_tokens\":1,\"output_tokens\":1}}}\n\n",
            malformed_event,
            "event: message_stop\ndata: {\"type\":\"message_stop\"}\n\n",
        );
        let (out, terminated) = run_sse(&body).await;
        assert!(terminated);
        assert!(out.contains("\"type\":\"upstream_error\""), "{out}");
        assert_eq!(out.matches("data: [DONE]").count(), 1, "{out}");
        assert!(!out.contains("\"content\":\"lost\""), "{out}");
    }
}

#[tokio::test]
async fn test_invalid_utf8_anthropic_event_fails_closed() {
    let mut body = b"event: content_block_delta\ndata: {".to_vec();
    body.push(0xff);
    body.extend_from_slice(b"}\n\n");

    let (out, terminated) = run_sse_bytes(&body).await;
    assert!(terminated);
    assert!(out.contains("\"type\":\"upstream_error\""));
    assert_eq!(out.matches("data: [DONE]").count(), 1);
}

#[tokio::test]
async fn test_explicit_anthropic_error_event_terminates_once() {
    let body = concat!(
        "event: message_start\n",
        "data: {\"type\":\"message_start\",\"message\":{\"id\":\"msg_err\",\"type\":\"message\",\"role\":\"assistant\",\"model\":\"claude-3-5-sonnet\",\"content\":[],\"usage\":{\"input_tokens\":1,\"output_tokens\":1}}}\n\n",
        "event: error\n",
        "data: {\"type\":\"error\",\"error\":{\"type\":\"api_error\",\"message\":\"provider blew up\"}}\n\n",
    );
    let (out, terminated) = run_sse(body).await;
    assert!(terminated);
    assert!(out.contains("provider blew up"));
    assert!(out.contains("\"type\":\"upstream_error\""));
    assert_eq!(out.matches("data: [DONE]").count(), 1);
}

#[tokio::test]
async fn test_unknown_anthropic_sse_events_are_forward_compatible() {
    let body = concat!(
        "event: message_start\n",
        "data: {\"type\":\"message_start\",\"message\":{\"id\":\"msg_unk\",\"type\":\"message\",\"role\":\"assistant\",\"model\":\"claude-3-5-sonnet\",\"content\":[],\"usage\":{\"input_tokens\":1,\"output_tokens\":1}}}\n\n",
        "event: future_event\n",
        "data: {\"type\":\"future_event\",\"payload\":true}\n\n",
        "event: content_block_delta\n",
        "data: {\"type\":\"content_block_delta\",\"index\":0,\"delta\":{\"type\":\"text_delta\",\"text\":\"ok\"}}\n\n",
        "event: message_delta\n",
        "data: {\"type\":\"message_delta\",\"delta\":{\"stop_reason\":\"end_turn\"},\"usage\":{\"output_tokens\":1}}\n\n",
        "event: message_stop\n",
        "data: {\"type\":\"message_stop\"}\n\n",
    );
    let (out, terminated) = run_sse(body).await;
    assert!(terminated);
    assert!(out.contains("\"content\":\"ok\""));
    assert!(out.contains("\"finish_reason\":\"stop\""));
    assert!(!out.contains("upstream_error"));
    assert_eq!(out.matches("data: [DONE]").count(), 1);
}

#[tokio::test]
async fn test_message_stop_terminates_without_waiting_for_extra_eof_bytes() {
    let plugin = build(openai_and_anthropic_config());
    let claude = json!({"model": "claude-3-5-sonnet", "stream": true, "messages": [{"role":"user","content":"hi"}]});
    let mut ctx = post_ctx(&claude);
    let mut headers = json_headers();
    plugin.before_proxy(&mut ctx, &mut headers).await;
    let mut inspector = plugin
        .response_stream_inspector(&ctx, 200, Some("text/event-stream"))
        .expect("inspector");
    let first = inspector.on_chunk(ANTHROPIC_SSE.as_bytes()).await;
    match first {
        ResponseStreamAction::Terminate(Some(bytes)) => {
            let out = String::from_utf8(bytes.to_vec()).unwrap();
            assert!(out.trim_end().ends_with("data: [DONE]"));
        }
        other => panic!("message_stop must Terminate the inspector driver: {other:?}"),
    }
    // Exactly-once: a later on_end must not emit a second DONE.
    let trailing = forwarded(inspector.on_end().await);
    assert!(trailing.is_empty());
}

// ---------------------------------------------------------------------------
// #2274 — Accept-Encoding / Content-Encoding identity handling
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_normalized_claim_requests_identity_encoding() {
    let plugin = build(openai_and_anthropic_config());
    let body = json!({"model": "claude-3-5-sonnet", "stream": true, "messages": [{"role":"user","content":"hi"}]});
    let mut ctx = post_ctx(&body);
    let mut headers = json_headers();
    headers.insert("accept-encoding".to_string(), "gzip, br".to_string());
    headers.insert("Accept-Encoding".to_string(), "deflate".to_string());
    plugin.before_proxy(&mut ctx, &mut headers).await;
    let values: Vec<_> = headers
        .iter()
        .filter(|(name, _)| name.eq_ignore_ascii_case("accept-encoding"))
        .map(|(_, value)| value.as_str())
        .collect();
    assert_eq!(
        values,
        vec!["identity"],
        "normalized Anthropic claims must replace every client variant with identity"
    );
}

#[tokio::test]
async fn test_openai_passthrough_keeps_accept_encoding() {
    let plugin = build(openai_and_anthropic_config());
    let body =
        json!({"model": "gpt-4o", "stream": true, "messages": [{"role":"user","content":"hi"}]});
    let mut ctx = post_ctx(&body);
    let mut headers = json_headers();
    headers.insert("accept-encoding".to_string(), "gzip".to_string());
    plugin.before_proxy(&mut ctx, &mut headers).await;
    assert_eq!(
        headers.get("accept-encoding").map(String::as_str),
        Some("gzip")
    );
}

fn gzip_bytes(plain: &[u8]) -> Vec<u8> {
    use flate2::Compression;
    use flate2::write::GzEncoder;
    use std::io::Write;
    let mut encoder = GzEncoder::new(Vec::new(), Compression::default());
    encoder.write_all(plain).unwrap();
    encoder.finish().unwrap()
}

fn brotli_bytes(plain: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    {
        let mut encoder = brotli::CompressorWriter::new(&mut out, 4096, 5, 22);
        std::io::Write::write_all(&mut encoder, plain).unwrap();
    }
    out
}

#[tokio::test]
async fn test_gzip_encoded_streamed_anthropic_sse_is_normalized() {
    let plugin = build(openai_and_anthropic_config());
    let claude = json!({"model": "claude-3-5-sonnet", "stream": true, "messages": [{"role":"user","content":"hi"}]});
    let mut ctx = post_ctx(&claude);
    let mut req_headers = json_headers();
    plugin.before_proxy(&mut ctx, &mut req_headers).await;

    let mut resp_headers = HashMap::new();
    resp_headers.insert("content-type".to_string(), "text/event-stream".to_string());
    resp_headers.insert("content-encoding".to_string(), "gzip".to_string());
    resp_headers.insert("vary".to_string(), "Accept-Encoding, Origin".to_string());
    let after = plugin.after_proxy(&mut ctx, 200, &mut resp_headers).await;
    assert!(matches!(after, PluginResult::Continue));
    assert!(!resp_headers.contains_key("content-encoding"));
    assert_eq!(resp_headers.get("vary").map(String::as_str), Some("Origin"));
    assert_eq!(
        ctx.metadata
            .get("ai_stream_router.provider_content_encoding")
            .map(String::as_str),
        Some("gzip")
    );

    let mut inspector = plugin
        .response_stream_inspector(&ctx, 200, Some("text/event-stream"))
        .expect("decoding inspector");
    let encoded = gzip_bytes(ANTHROPIC_SSE.as_bytes());
    let mut collected = forwarded(inspector.on_chunk(&encoded).await);
    collected.extend_from_slice(&forwarded(inspector.on_end().await));
    let out = String::from_utf8(collected).unwrap();
    assert!(out.contains("\"content\":\"Hello\""));
    assert!(out.trim_end().ends_with("data: [DONE]"));
    assert!(!out.contains("upstream_error"));
}

#[tokio::test]
async fn test_gzip_streaming_decode_rejects_expansion_over_limit() {
    let plugin = build(openai_and_anthropic_config());
    let claude = json!({"model": "claude-3-5-sonnet", "stream": true, "messages": [{"role":"user","content":"hi"}]});
    let mut ctx = post_ctx(&claude);
    let mut req_headers = json_headers();
    plugin.before_proxy(&mut ctx, &mut req_headers).await;

    let mut resp_headers = HashMap::new();
    resp_headers.insert("content-type".to_string(), "text/event-stream".to_string());
    resp_headers.insert("content-encoding".to_string(), "gzip".to_string());
    assert!(matches!(
        plugin.after_proxy(&mut ctx, 200, &mut resp_headers).await,
        PluginResult::Continue
    ));

    let mut inspector = plugin
        .response_stream_inspector(&ctx, 200, Some("text/event-stream"))
        .expect("bounded decoding inspector");
    let oversized = vec![b'x'; 8 * 1024 * 1024 + 1];
    let encoded = gzip_bytes(&oversized);
    let mut collected = forwarded(inspector.on_chunk(&encoded).await);
    collected.extend_from_slice(&forwarded(inspector.on_end().await));
    let out = String::from_utf8(collected).unwrap();
    assert!(out.contains("upstream_error"));
    assert!(out.contains("decoded content exceeds"));
    assert_eq!(out.matches("data: [DONE]").count(), 1);
}

#[tokio::test]
async fn test_brotli_encoded_buffered_anthropic_sse_is_normalized() {
    let plugin = build(openai_and_anthropic_config());
    let claude = json!({"model": "claude-3-5-sonnet", "stream": true, "messages": [{"role":"user","content":"hi"}]});
    let mut ctx = post_ctx(&claude);
    let mut req_headers = json_headers();
    plugin.before_proxy(&mut ctx, &mut req_headers).await;

    let mut resp_headers = HashMap::new();
    resp_headers.insert("content-type".to_string(), "text/event-stream".to_string());
    resp_headers.insert("content-encoding".to_string(), "br".to_string());
    assert!(matches!(
        plugin.after_proxy(&mut ctx, 200, &mut resp_headers).await,
        PluginResult::Continue
    ));

    let encoded = brotli_bytes(ANTHROPIC_SSE.as_bytes());
    let buffered = plugin
        .normalize_response_body_with_context(
            &mut ctx,
            200,
            &encoded,
            Some("text/event-stream"),
            &resp_headers,
        )
        .await
        .expect("buffered decode+normalize");
    let out = String::from_utf8(buffered).unwrap();
    assert!(out.contains("chat.completion.chunk"));
    assert!(out.contains("\"content\":\"Hello\""));
    assert!(out.trim_end().ends_with("data: [DONE]"));
}

#[tokio::test]
async fn test_unsupported_content_encoding_is_rejected() {
    let plugin = build(openai_and_anthropic_config());
    let claude = json!({"model": "claude-3-5-sonnet", "stream": true, "messages": [{"role":"user","content":"hi"}]});
    for encoding in ["zstd", "gzip,", "gzip; q=1", "gzip, br"] {
        let mut ctx = post_ctx(&claude);
        let mut req_headers = json_headers();
        plugin.before_proxy(&mut ctx, &mut req_headers).await;

        let mut resp_headers = HashMap::new();
        resp_headers.insert("content-type".to_string(), "text/event-stream".to_string());
        resp_headers.insert("content-encoding".to_string(), encoding.to_string());
        let reject = plugin.after_proxy(&mut ctx, 200, &mut resp_headers).await;
        assert_eq!(
            reject_status(&reject),
            Some(502),
            "{encoding} must fail closed"
        );
    }
}

#[tokio::test]
async fn test_case_variant_duplicate_content_encoding_is_rejected() {
    let plugin = build(openai_and_anthropic_config());
    let claude = json!({"model": "claude-3-5-sonnet", "stream": true, "messages": [{"role":"user","content":"hi"}]});
    let mut ctx = post_ctx(&claude);
    let mut req_headers = json_headers();
    plugin.before_proxy(&mut ctx, &mut req_headers).await;

    let mut resp_headers = HashMap::new();
    resp_headers.insert("content-type".to_string(), "text/event-stream".to_string());
    resp_headers.insert("content-encoding".to_string(), "identity".to_string());
    resp_headers.insert("Content-Encoding".to_string(), "gzip".to_string());
    assert_eq!(
        reject_status(&plugin.after_proxy(&mut ctx, 200, &mut resp_headers).await),
        Some(502)
    );
}

#[tokio::test]
async fn test_identity_provider_content_encoding_repairs_rewritten_representation_headers() {
    let plugin = build(openai_and_anthropic_config());
    let claude = json!({"model": "claude-3-5-sonnet", "stream": true, "messages": [{"role":"user","content":"hi"}]});

    for encoding in [None, Some("identity")] {
        let mut ctx = post_ctx(&claude);
        let mut req_headers = json_headers();
        plugin.before_proxy(&mut ctx, &mut req_headers).await;

        let mut resp_headers = HashMap::new();
        resp_headers.insert("content-type".to_string(), "text/event-stream".to_string());
        resp_headers.insert("Content-Length".to_string(), "999".to_string());
        resp_headers.insert("ETag".to_string(), "\"provider\"".to_string());
        resp_headers.insert("Digest".to_string(), "sha-256=provider".to_string());
        resp_headers.insert("vary".to_string(), "Accept-Encoding, Origin".to_string());
        resp_headers.insert("Vary".to_string(), "origin, X-Trace".to_string());
        if let Some(encoding) = encoding {
            resp_headers.insert("Content-Encoding".to_string(), encoding.to_string());
        }
        assert!(matches!(
            plugin.after_proxy(&mut ctx, 200, &mut resp_headers).await,
            PluginResult::Continue
        ));
        assert!(
            !ctx.metadata
                .contains_key("ai_stream_router.provider_content_encoding")
        );
        for invalidated in ["content-encoding", "content-length", "etag", "digest"] {
            assert!(
                !resp_headers
                    .keys()
                    .any(|name| name.eq_ignore_ascii_case(invalidated)),
                "{invalidated} must be removed after identity SSE normalization"
            );
        }
        let vary_values: Vec<_> = resp_headers
            .iter()
            .filter(|(name, _)| name.eq_ignore_ascii_case("vary"))
            .map(|(_, value)| value.as_str())
            .collect();
        assert_eq!(vary_values.len(), 1);
        let vary_tokens: Vec<_> = vary_values[0]
            .split(',')
            .map(|token| token.trim().to_ascii_lowercase())
            .collect();
        assert_eq!(vary_tokens.len(), 2);
        assert!(vary_tokens.iter().any(|token| token == "origin"));
        assert!(vary_tokens.iter().any(|token| token == "x-trace"));
    }
}

// ---------------------------------------------------------------------------
// #2280 — tool-call / tool-result history translation
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_anthropic_tool_history_round_trip_translation() {
    let plugin = build(openai_and_anthropic_config());
    let body = json!({
        "model": "claude-3-5-sonnet",
        "stream": true,
        "messages": [
            {"role": "user", "content": "weather in Paris?"},
            {
                "role": "assistant",
                "content": "Let me check.",
                "tool_calls": [{
                    "id": "call_1",
                    "type": "function",
                    "function": {"name": "get_weather", "arguments": "{\"location\":\"Paris\"}"}
                }]
            },
            {"role": "tool", "tool_call_id": "call_1", "content": "22C and sunny"},
            {"role": "user", "content": "thanks"}
        ]
    });
    let mut ctx = post_ctx(&body);
    let mut headers = json_headers();
    assert!(matches!(
        plugin.before_proxy(&mut ctx, &mut headers).await,
        PluginResult::Continue
    ));
    let raw = serde_json::to_vec(&body).unwrap();
    let out = plugin
        .transform_request_body_with_context(&mut ctx, &raw, Some("application/json"), &headers)
        .await
        .expect("translated");
    let parsed: Value = serde_json::from_slice(&out).unwrap();
    let messages = parsed["messages"].as_array().unwrap();
    assert_eq!(messages.len(), 4);
    assert_eq!(messages[0]["role"], json!("user"));
    assert_eq!(messages[1]["role"], json!("assistant"));
    let assistant_blocks = messages[1]["content"].as_array().unwrap();
    assert_eq!(assistant_blocks[0]["type"], json!("text"));
    assert_eq!(assistant_blocks[0]["text"], json!("Let me check."));
    assert_eq!(assistant_blocks[1]["type"], json!("tool_use"));
    assert_eq!(assistant_blocks[1]["id"], json!("call_1"));
    assert_eq!(assistant_blocks[1]["name"], json!("get_weather"));
    assert_eq!(assistant_blocks[1]["input"]["location"], json!("Paris"));
    assert_eq!(messages[2]["role"], json!("user"));
    let tool_results = messages[2]["content"].as_array().unwrap();
    assert_eq!(tool_results[0]["type"], json!("tool_result"));
    assert_eq!(tool_results[0]["tool_use_id"], json!("call_1"));
    assert_eq!(tool_results[0]["content"], json!("22C and sunny"));
    assert_eq!(messages[3]["content"], json!("thanks"));
}

#[tokio::test]
async fn test_anthropic_parallel_tool_calls_and_results_preserve_order() {
    let plugin = build(openai_and_anthropic_config());
    let body = json!({
        "model": "claude-3-5-sonnet",
        "stream": true,
        "messages": [
            {"role": "user", "content": "multi"},
            {
                "role": "assistant",
                "content": null,
                "tool_calls": [
                    {"id": "call_a", "type": "function", "function": {"name": "alpha", "arguments": "{}"}},
                    {"id": "call_b", "type": "function", "function": {"name": "beta", "arguments": "{\"x\":1}"}}
                ]
            },
            {"role": "tool", "tool_call_id": "call_a", "content": null},
            {"role": "tool", "tool_call_id": "call_b", "content": "B", "is_error": true}
        ]
    });
    let mut ctx = post_ctx(&body);
    let mut headers = json_headers();
    assert!(matches!(
        plugin.before_proxy(&mut ctx, &mut headers).await,
        PluginResult::Continue
    ));
    let raw = serde_json::to_vec(&body).unwrap();
    let parsed: Value = serde_json::from_slice(
        &plugin
            .transform_request_body_with_context(&mut ctx, &raw, Some("application/json"), &headers)
            .await
            .unwrap(),
    )
    .unwrap();
    let assistant = parsed["messages"][1]["content"].as_array().unwrap();
    assert_eq!(assistant[0]["id"], json!("call_a"));
    assert_eq!(assistant[1]["id"], json!("call_b"));
    let results = parsed["messages"][2]["content"].as_array().unwrap();
    assert_eq!(results.len(), 2);
    assert_eq!(results[0]["tool_use_id"], json!("call_a"));
    assert_eq!(results[0]["content"], json!(""));
    assert_eq!(results[1]["tool_use_id"], json!("call_b"));
    assert_eq!(results[1]["is_error"], json!(true));
}

#[tokio::test]
async fn test_null_tool_call_fields_are_treated_as_absent() {
    let plugin = build(openai_and_anthropic_config());
    let body = json!({
        "model": "claude-3-5-sonnet",
        "stream": true,
        "messages": [
            {"role": "user", "content": "hi"},
            {
                "role": "assistant",
                "content": "done",
                "tool_calls": null,
                "function_call": null
            }
        ]
    });
    let mut ctx = post_ctx(&body);
    let mut headers = json_headers();
    assert!(matches!(
        plugin.before_proxy(&mut ctx, &mut headers).await,
        PluginResult::Continue
    ));
    let raw = serde_json::to_vec(&body).unwrap();
    let translated: Value = serde_json::from_slice(
        &plugin
            .transform_request_body_with_context(&mut ctx, &raw, Some("application/json"), &headers)
            .await
            .expect("translated"),
    )
    .unwrap();
    assert_eq!(translated["messages"][1]["content"], json!("done"));
}

#[tokio::test]
async fn test_malformed_tool_history_rejects_with_400() {
    let plugin = build(openai_and_anthropic_config());

    let orphaned = json!({
        "model": "claude-3-5-sonnet",
        "stream": true,
        "messages": [
            {"role": "user", "content": "hi"},
            {"role": "tool", "tool_call_id": "missing", "content": "x"}
        ]
    });
    let mut ctx = post_ctx(&orphaned);
    let mut headers = json_headers();
    assert_eq!(
        reject_status(&plugin.before_proxy(&mut ctx, &mut headers).await),
        Some(400)
    );

    let bad_args = json!({
        "model": "claude-3-5-sonnet",
        "stream": true,
        "messages": [
            {"role": "user", "content": "hi"},
            {
                "role": "assistant",
                "content": null,
                "tool_calls": [{
                    "id": "call_1",
                    "type": "function",
                    "function": {"name": "get_weather", "arguments": "not-json"}
                }]
            }
        ]
    });
    let mut ctx2 = post_ctx(&bad_args);
    let mut headers2 = json_headers();
    assert_eq!(
        reject_status(&plugin.before_proxy(&mut ctx2, &mut headers2).await),
        Some(400)
    );

    let missing_result = json!({
        "model": "claude-3-5-sonnet",
        "stream": true,
        "messages": [
            {"role": "user", "content": "hi"},
            {
                "role": "assistant",
                "content": null,
                "tool_calls": [{
                    "id": "call_1",
                    "type": "function",
                    "function": {"name": "get_weather", "arguments": "{}"}
                }]
            },
            {"role": "user", "content": "continue without a result"}
        ]
    });
    let mut ctx3 = post_ctx(&missing_result);
    let mut headers3 = json_headers();
    assert_eq!(
        reject_status(&plugin.before_proxy(&mut ctx3, &mut headers3).await),
        Some(400)
    );

    let duplicate_result = json!({
        "model": "claude-3-5-sonnet",
        "stream": true,
        "messages": [
            {"role": "user", "content": "hi"},
            {
                "role": "assistant",
                "content": null,
                "tool_calls": [{
                    "id": "call_1",
                    "type": "function",
                    "function": {"name": "get_weather", "arguments": "{}"}
                }]
            },
            {"role": "tool", "tool_call_id": "call_1", "content": "first"},
            {"role": "tool", "tool_call_id": "call_1", "content": "duplicate"}
        ]
    });
    let mut ctx4 = post_ctx(&duplicate_result);
    let mut headers4 = json_headers();
    assert_eq!(
        reject_status(&plugin.before_proxy(&mut ctx4, &mut headers4).await),
        Some(400)
    );
}

#[tokio::test]
async fn test_anthropic_translation_rejects_each_malformed_tool_history_shape() {
    let plugin = build(openai_and_anthropic_config());
    let invalid_requests = vec![
        (
            "missing messages",
            json!({"model": "claude-3-5-sonnet", "stream": true}),
        ),
        (
            "non-object message",
            json!({"model": "claude-3-5-sonnet", "stream": true, "messages": ["bad"]}),
        ),
        (
            "missing role",
            json!({"model": "claude-3-5-sonnet", "stream": true, "messages": [{"content": "bad"}]}),
        ),
        (
            "unsupported role",
            json!({"model": "claude-3-5-sonnet", "stream": true, "messages": [{"role": "critic", "content": "bad"}]}),
        ),
        (
            "non-text user content",
            json!({"model": "claude-3-5-sonnet", "stream": true, "messages": [{"role": "user", "content": 42}]}),
        ),
        (
            "legacy function call missing result",
            json!({"model": "claude-3-5-sonnet", "stream": true, "messages": [{"role": "assistant", "content": "calling", "function_call": {"name": "run", "arguments": "{}"}}]}),
        ),
        (
            "legacy function call with modern tool_calls",
            json!({
                "model": "claude-3-5-sonnet",
                "stream": true,
                "messages": [{
                    "role": "assistant",
                    "content": null,
                    "tool_calls": [{"id": "call_1", "type": "function", "function": {"name": "run", "arguments": "{}"}}],
                    "function_call": {"name": "run", "arguments": "{}"}
                }]
            }),
        ),
        (
            "empty tool call list",
            json!({"model": "claude-3-5-sonnet", "stream": true, "messages": [{"role": "assistant", "content": null, "tool_calls": []}]}),
        ),
        (
            "non-array tool calls",
            json!({"model": "claude-3-5-sonnet", "stream": true, "messages": [{"role": "assistant", "content": null, "tool_calls": {}}]}),
        ),
        (
            "non-object tool call",
            json!({"model": "claude-3-5-sonnet", "stream": true, "messages": [{"role": "assistant", "content": null, "tool_calls": [7]}]}),
        ),
        (
            "non-function tool call",
            json!({"model": "claude-3-5-sonnet", "stream": true, "messages": [{"role": "assistant", "content": null, "tool_calls": [{"id": "call_1", "type": "custom", "function": {"name": "run", "arguments": "{}"}}]}]}),
        ),
        (
            "missing tool call id",
            json!({"model": "claude-3-5-sonnet", "stream": true, "messages": [{"role": "assistant", "content": null, "tool_calls": [{"type": "function", "function": {"name": "run", "arguments": "{}"}}]}]}),
        ),
        (
            "missing function object",
            json!({"model": "claude-3-5-sonnet", "stream": true, "messages": [{"role": "assistant", "content": null, "tool_calls": [{"id": "call_1", "type": "function"}]}]}),
        ),
        (
            "invalid function name",
            json!({"model": "claude-3-5-sonnet", "stream": true, "messages": [{"role": "assistant", "content": null, "tool_calls": [{"id": "call_1", "type": "function", "function": {"name": "not valid!", "arguments": "{}"}}]}]}),
        ),
        (
            "non-string arguments",
            json!({"model": "claude-3-5-sonnet", "stream": true, "messages": [{"role": "assistant", "content": null, "tool_calls": [{"id": "call_1", "type": "function", "function": {"name": "run", "arguments": {}}}]}]}),
        ),
        (
            "non-object encoded arguments",
            json!({"model": "claude-3-5-sonnet", "stream": true, "messages": [{"role": "assistant", "content": null, "tool_calls": [{"id": "call_1", "type": "function", "function": {"name": "run", "arguments": "[]"}}]}]}),
        ),
        (
            "tool calls on user message",
            json!({"model": "claude-3-5-sonnet", "stream": true, "messages": [{"role": "user", "content": "bad", "tool_calls": []}]}),
        ),
        (
            "repeated tool call id",
            json!({
                "model": "claude-3-5-sonnet",
                "stream": true,
                "messages": [{
                    "role": "assistant",
                    "content": null,
                    "tool_calls": [
                        {"id": "same", "type": "function", "function": {"name": "first", "arguments": "{}"}},
                        {"id": "same", "type": "function", "function": {"name": "second", "arguments": "{}"}}
                    ]
                }]
            }),
        ),
        (
            "missing final tool result",
            json!({"model": "claude-3-5-sonnet", "stream": true, "messages": [{"role": "assistant", "content": null, "tool_calls": [{"id": "call_1", "type": "function", "function": {"name": "run", "arguments": "{}"}}]}]}),
        ),
        (
            "object tool result content",
            json!({
                "model": "claude-3-5-sonnet",
                "stream": true,
                "messages": [
                    {"role": "assistant", "content": null, "tool_calls": [{"id": "call_1", "type": "function", "function": {"name": "run", "arguments": "{}"}}]},
                    {"role": "tool", "tool_call_id": "call_1", "content": {}}
                ]
            }),
        ),
        (
            "non-text tool result part",
            json!({
                "model": "claude-3-5-sonnet",
                "stream": true,
                "messages": [
                    {"role": "assistant", "content": null, "tool_calls": [{"id": "call_1", "type": "function", "function": {"name": "run", "arguments": "{}"}}]},
                    {"role": "tool", "tool_call_id": "call_1", "content": [{"type": "image", "text": "bad"}]}
                ]
            }),
        ),
        (
            "missing tool result text",
            json!({
                "model": "claude-3-5-sonnet",
                "stream": true,
                "messages": [
                    {"role": "assistant", "content": null, "tool_calls": [{"id": "call_1", "type": "function", "function": {"name": "run", "arguments": "{}"}}]},
                    {"role": "tool", "tool_call_id": "call_1", "content": [{"type": "text"}]}
                ]
            }),
        ),
        (
            "empty assistant content",
            json!({"model": "claude-3-5-sonnet", "stream": true, "messages": [{"role": "assistant", "content": ""}]}),
        ),
    ];

    for (label, body) in invalid_requests {
        let mut ctx = post_ctx(&body);
        let mut headers = json_headers();
        assert_eq!(
            reject_status(&plugin.before_proxy(&mut ctx, &mut headers).await),
            Some(400),
            "{label} must fail closed"
        );
    }
}

// ---------------------------------------------------------------------------
// #3300 — legacy OpenAI function_call / role:function history
// ---------------------------------------------------------------------------

#[tokio::test]
async fn test_anthropic_legacy_function_call_history_round_trip() {
    let plugin = build(openai_and_anthropic_config());
    let body = json!({
        "model": "claude-3-5-sonnet",
        "stream": true,
        "messages": [
            {"role": "user", "content": "weather in Paris?"},
            {
                "role": "assistant",
                "content": "Let me check.",
                "function_call": {
                    "name": "get_weather",
                    "arguments": "{\"location\":\"Paris\"}"
                }
            },
            {"role": "function", "name": "get_weather", "content": "22C and sunny"},
            {"role": "user", "content": "thanks"}
        ]
    });
    let mut ctx = post_ctx(&body);
    let mut headers = json_headers();
    assert!(matches!(
        plugin.before_proxy(&mut ctx, &mut headers).await,
        PluginResult::Continue
    ));
    let raw = serde_json::to_vec(&body).unwrap();
    let out = plugin
        .transform_request_body_with_context(&mut ctx, &raw, Some("application/json"), &headers)
        .await
        .expect("legacy history must translate");
    let parsed: Value = serde_json::from_slice(&out).unwrap();
    let messages = parsed["messages"].as_array().unwrap();
    assert_eq!(messages.len(), 4);
    assert_eq!(messages[1]["role"], json!("assistant"));
    let assistant_blocks = messages[1]["content"].as_array().unwrap();
    assert_eq!(assistant_blocks[0]["type"], json!("text"));
    assert_eq!(assistant_blocks[0]["text"], json!("Let me check."));
    assert_eq!(assistant_blocks[1]["type"], json!("tool_use"));
    assert_eq!(assistant_blocks[1]["id"], json!("call_legacy_1"));
    assert_eq!(assistant_blocks[1]["name"], json!("get_weather"));
    assert_eq!(assistant_blocks[1]["input"]["location"], json!("Paris"));
    assert_eq!(messages[2]["role"], json!("user"));
    let tool_results = messages[2]["content"].as_array().unwrap();
    assert_eq!(tool_results[0]["type"], json!("tool_result"));
    assert_eq!(tool_results[0]["tool_use_id"], json!("call_legacy_1"));
    assert_eq!(tool_results[0]["content"], json!("22C and sunny"));
    assert_eq!(messages[3]["content"], json!("thanks"));
}

#[tokio::test]
async fn test_anthropic_legacy_function_call_with_null_content_and_text_parts_result() {
    let body = json!({
        "model": "claude-3-5-sonnet",
        "stream": true,
        "messages": [
            {"role": "user", "content": "lookup"},
            {
                "role": "assistant",
                "content": null,
                "function_call": {"name": "lookup", "arguments": "{}"}
            },
            {
                "role": "function",
                "name": "lookup",
                "content": [{"type": "text", "text": "ok"}],
                "is_error": true
            }
        ]
    });
    let parsed = translate_anthropic_body(&body)
        .await
        .expect("null content + text-parts function result");
    let assistant = parsed["messages"][1]["content"].as_array().unwrap();
    assert_eq!(assistant.len(), 1);
    assert_eq!(assistant[0]["type"], json!("tool_use"));
    assert_eq!(assistant[0]["id"], json!("call_legacy_1"));
    let results = parsed["messages"][2]["content"].as_array().unwrap();
    assert_eq!(results[0]["content"], json!("ok"));
    assert_eq!(results[0]["is_error"], json!(true));
}

#[tokio::test]
async fn test_anthropic_legacy_function_history_rejects_malformed_and_mixed_shapes() {
    let plugin = build(openai_and_anthropic_config());

    let cases = vec![
        (
            "malformed legacy arguments",
            json!({
                "model": "claude-3-5-sonnet",
                "stream": true,
                "messages": [
                    {"role": "user", "content": "hi"},
                    {
                        "role": "assistant",
                        "content": null,
                        "function_call": {
                            "name": "get_weather",
                            "arguments": "{\"api_key\":\"sk-live-secret\",not-json"
                        }
                    }
                ]
            }),
            Some("function_call"),
            vec!["sk-live-secret", "api_key"],
        ),
        (
            "orphaned function result",
            json!({
                "model": "claude-3-5-sonnet",
                "stream": true,
                "messages": [
                    {"role": "user", "content": "hi"},
                    {"role": "function", "name": "get_weather", "content": "x"}
                ]
            }),
            Some("function"),
            vec![],
        ),
        (
            "duplicate function result",
            json!({
                "model": "claude-3-5-sonnet",
                "stream": true,
                "messages": [
                    {"role": "user", "content": "hi"},
                    {
                        "role": "assistant",
                        "content": null,
                        "function_call": {"name": "get_weather", "arguments": "{}"}
                    },
                    {"role": "function", "name": "get_weather", "content": "first"},
                    {"role": "function", "name": "get_weather", "content": "duplicate"}
                ]
            }),
            Some("function"),
            vec![],
        ),
        (
            "mismatched function result name",
            json!({
                "model": "claude-3-5-sonnet",
                "stream": true,
                "messages": [
                    {"role": "user", "content": "hi"},
                    {
                        "role": "assistant",
                        "content": null,
                        "function_call": {"name": "get_weather", "arguments": "{}"}
                    },
                    {"role": "function", "name": "other_tool", "content": "x"}
                ]
            }),
            Some("name"),
            vec!["other_tool", "get_weather"],
        ),
        (
            "missing function result after legacy call",
            json!({
                "model": "claude-3-5-sonnet",
                "stream": true,
                "messages": [
                    {"role": "user", "content": "hi"},
                    {
                        "role": "assistant",
                        "content": null,
                        "function_call": {"name": "get_weather", "arguments": "{}"}
                    },
                    {"role": "user", "content": "continue"}
                ]
            }),
            Some("function_call"),
            vec![],
        ),
        (
            "modern tool_calls then legacy function result",
            json!({
                "model": "claude-3-5-sonnet",
                "stream": true,
                "messages": [
                    {"role": "user", "content": "hi"},
                    {
                        "role": "assistant",
                        "content": null,
                        "tool_calls": [{
                            "id": "call_1",
                            "type": "function",
                            "function": {"name": "get_weather", "arguments": "{}"}
                        }]
                    },
                    {"role": "function", "name": "get_weather", "content": "x"}
                ]
            }),
            Some("mixes"),
            vec![],
        ),
        (
            "legacy function_call then modern tool result",
            json!({
                "model": "claude-3-5-sonnet",
                "stream": true,
                "messages": [
                    {"role": "user", "content": "hi"},
                    {
                        "role": "assistant",
                        "content": null,
                        "function_call": {"name": "get_weather", "arguments": "{}"}
                    },
                    {"role": "tool", "tool_call_id": "call_legacy_1", "content": "x"}
                ]
            }),
            Some("mixes"),
            vec![],
        ),
        (
            "oversized legacy arguments",
            json!({
                "model": "claude-3-5-sonnet",
                "stream": true,
                "messages": [
                    {"role": "user", "content": "hi"},
                    {
                        "role": "assistant",
                        "content": null,
                        "function_call": {
                            "name": "get_weather",
                            "arguments": format!("{{\"pad\":\"{}\"}}", "x".repeat(256 * 1024))
                        }
                    }
                ]
            }),
            Some("maximum allowed size"),
            vec![],
        ),
        (
            "invalid legacy function name",
            json!({
                "model": "claude-3-5-sonnet",
                "stream": true,
                "messages": [{
                    "role": "assistant",
                    "content": null,
                    "function_call": {"name": "not valid!", "arguments": "{}"}
                }]
            }),
            Some("function_call"),
            vec!["not valid!"],
        ),
        (
            "non-object legacy arguments encoding",
            json!({
                "model": "claude-3-5-sonnet",
                "stream": true,
                "messages": [{
                    "role": "assistant",
                    "content": null,
                    "function_call": {"name": "run", "arguments": "[1]"}
                }]
            }),
            Some("JSON object"),
            vec![],
        ),
    ];

    for (label, body, needle, forbidden) in cases {
        let mut ctx = post_ctx(&body);
        let mut headers = json_headers();
        let result = plugin.before_proxy(&mut ctx, &mut headers).await;
        assert_eq!(
            reject_status(&result),
            Some(400),
            "{label} must fail closed"
        );
        if let PluginResult::Reject { body: err_body, .. } = result {
            if let Some(needle) = needle {
                assert!(
                    err_body.contains(needle),
                    "{label}: expected field-specific diagnostic containing {needle:?}: {err_body}"
                );
            }
            for secret in forbidden {
                assert!(
                    !err_body.contains(secret),
                    "{label}: diagnostic must not leak {secret:?}: {err_body}"
                );
            }
        } else {
            panic!("{label}: expected Reject");
        }
    }
}

#[tokio::test]
async fn test_anthropic_modern_tool_history_unchanged_alongside_legacy_support() {
    // Regression: modern parallel tool_calls still translate in order after #3300.
    let body = json!({
        "model": "claude-3-5-sonnet",
        "stream": true,
        "messages": [
            {"role": "user", "content": "multi"},
            {
                "role": "assistant",
                "content": null,
                "tool_calls": [
                    {"id": "call_a", "type": "function", "function": {"name": "alpha", "arguments": "{}"}},
                    {"id": "call_b", "type": "function", "function": {"name": "beta", "arguments": "{\"x\":1}"}}
                ]
            },
            {"role": "tool", "tool_call_id": "call_a", "content": "A"},
            {"role": "tool", "tool_call_id": "call_b", "content": "B"}
        ]
    });
    let parsed = translate_anthropic_body(&body)
        .await
        .expect("modern history must still translate");
    let assistant = parsed["messages"][1]["content"].as_array().unwrap();
    assert_eq!(assistant[0]["id"], json!("call_a"));
    assert_eq!(assistant[1]["id"], json!("call_b"));
    let results = parsed["messages"][2]["content"].as_array().unwrap();
    assert_eq!(results[0]["tool_use_id"], json!("call_a"));
    assert_eq!(results[1]["tool_use_id"], json!("call_b"));
}

#[tokio::test]
async fn test_anthropic_completed_modern_and_legacy_rounds_can_coexist() {
    let body = json!({
        "model": "claude-3-5-sonnet",
        "stream": true,
        "messages": [
            {"role": "user", "content": "first"},
            {
                "role": "assistant",
                "content": null,
                "tool_calls": [{
                    "id": "call_modern",
                    "type": "function",
                    "function": {"name": "alpha", "arguments": "{}"}
                }]
            },
            {"role": "tool", "tool_call_id": "call_modern", "content": "A"},
            {
                "role": "assistant",
                "content": null,
                "function_call": {"name": "beta", "arguments": "{\"x\":1}"}
            },
            {"role": "function", "name": "beta", "content": "B"}
        ]
    });

    let parsed = translate_anthropic_body(&body)
        .await
        .expect("completed modern and legacy rounds are unambiguous");
    assert_eq!(
        parsed["messages"][1]["content"][0]["id"],
        json!("call_modern")
    );
    assert_eq!(
        parsed["messages"][2]["content"][0]["tool_use_id"],
        json!("call_modern")
    );
    assert_eq!(
        parsed["messages"][3]["content"][0]["id"],
        json!("call_legacy_3")
    );
    assert_eq!(
        parsed["messages"][4]["content"][0]["tool_use_id"],
        json!("call_legacy_3")
    );
}

#[tokio::test]
async fn test_anthropic_modern_tool_id_and_arguments_are_bounded() {
    let long_id = format!("call_{}", "x".repeat(256));
    let large_arguments =
        serde_json::to_string(&json!({"payload": "x".repeat(256 * 1024)})).unwrap();
    let oversized_id = json!({
        "model": "claude-3-5-sonnet",
        "stream": true,
        "messages": [
            {"role": "user", "content": "large modern call"},
            {
                "role": "assistant",
                "content": null,
                "tool_calls": [{
                    "id": long_id,
                    "type": "function",
                    "function": {"name": "alpha", "arguments": large_arguments}
                }]
            },
            {"role": "tool", "tool_call_id": long_id, "content": "ok"}
        ]
    });
    let mut ctx = post_ctx(&oversized_id);
    let mut headers = json_headers();
    assert_eq!(
        reject_status(
            &build(openai_and_anthropic_config())
                .before_proxy(&mut ctx, &mut headers)
                .await
        ),
        Some(400)
    );

    let oversized_arguments = json!({
        "model": "claude-3-5-sonnet",
        "stream": true,
        "messages": [{
            "role": "assistant",
            "content": null,
            "tool_calls": [{
                "id": "call_1",
                "type": "function",
                "function": {"name": "alpha", "arguments": large_arguments}
            }]
        }]
    });
    let mut ctx = post_ctx(&oversized_arguments);
    let mut headers = json_headers();
    assert_eq!(
        reject_status(
            &build(openai_and_anthropic_config())
                .before_proxy(&mut ctx, &mut headers)
                .await
        ),
        Some(400)
    );

    let oversized_result_id = json!({
        "model": "claude-3-5-sonnet",
        "stream": true,
        "messages": [
            {
                "role": "assistant",
                "content": null,
                "tool_calls": [{
                    "id": "call_1",
                    "type": "function",
                    "function": {"name": "alpha", "arguments": "{}"}
                }]
            },
            {"role": "tool", "tool_call_id": long_id, "content": "ok"}
        ]
    });
    let mut ctx = post_ctx(&oversized_result_id);
    let mut headers = json_headers();
    assert_eq!(
        reject_status(
            &build(openai_and_anthropic_config())
                .before_proxy(&mut ctx, &mut headers)
                .await
        ),
        Some(400)
    );
}

#[tokio::test]
async fn test_anthropic_late_translation_failure_is_rejected_before_dispatch() {
    let plugin = build(openai_and_anthropic_config());
    let body = json!({
        "model": "claude-3-5-sonnet",
        "stream": true,
        "messages": [{"role": "user", "content": "hi"}]
    });
    let mut ctx = post_ctx(&body);
    let mut headers = json_headers();
    assert!(matches!(
        plugin.before_proxy(&mut ctx, &mut headers).await,
        PluginResult::Continue
    ));

    assert!(
        plugin
            .transform_request_body_with_context(
                &mut ctx,
                b"{",
                Some("application/json"),
                &headers,
            )
            .await
            .is_none()
    );
    assert_eq!(
        reject_status(
            &plugin
                .on_final_request_body_with_context(&mut ctx, &headers, b"{")
                .await
        ),
        Some(400)
    );
}

// ---------------------------------------------------------------------------
// Construction-side bounding of the buffered normalizer (GHSA-pwcm-6rh8-f2gh).
//
// The buffered path used to hand the streaming normalizer the WHOLE body in one
// `on_chunk`, which accumulates the complete normalized stream in an ordinary
// `String` and only then returns it — a full attacker-amplified replacement
// built before the ceiling-bounded sink saw a byte. It now drives the same
// normalizer in fixed-size slices, so these tests pin that the output is still
// exactly what the streaming path produces across a body large enough to span
// several slices.
// ---------------------------------------------------------------------------

/// An Anthropic SSE stream well past the buffered slice size, so the buffered
/// normalizer must cross slice boundaries mid-event.
fn long_anthropic_sse(delta_events: usize) -> String {
    let mut sse = String::new();
    sse.push_str("event: message_start\n");
    sse.push_str(
        "data: {\"type\":\"message_start\",\"message\":{\"id\":\"msg_long\",\"type\":\"message\",\"role\":\"assistant\",\"model\":\"claude-3-5-sonnet\",\"content\":[],\"stop_reason\":null,\"usage\":{\"input_tokens\":10,\"output_tokens\":1}}}\n\n",
    );
    sse.push_str("event: content_block_start\n");
    sse.push_str(
        "data: {\"type\":\"content_block_start\",\"index\":0,\"content_block\":{\"type\":\"text\",\"text\":\"\"}}\n\n",
    );
    for index in 0..delta_events {
        sse.push_str("event: content_block_delta\n");
        sse.push_str(&format!(
            "data: {{\"type\":\"content_block_delta\",\"index\":0,\"delta\":{{\"type\":\"text_delta\",\"text\":\"token-{index}-padding-padding-padding\"}}}}\n\n"
        ));
    }
    sse.push_str("event: content_block_stop\n");
    sse.push_str("data: {\"type\":\"content_block_stop\",\"index\":0}\n\n");
    sse.push_str("event: message_delta\n");
    sse.push_str(
        "data: {\"type\":\"message_delta\",\"delta\":{\"stop_reason\":\"end_turn\"},\"usage\":{\"output_tokens\":12}}\n\n",
    );
    sse.push_str("event: message_stop\n");
    sse.push_str("data: {\"type\":\"message_stop\"}\n\n");
    sse
}

#[tokio::test]
async fn test_buffered_normalizer_matches_streaming_across_slice_boundaries() {
    let body = long_anthropic_sse(600);
    assert!(
        body.len() > 64 * 1024,
        "the fixture must span several buffered slices, got {} bytes",
        body.len()
    );

    let plugin = build(openai_and_anthropic_config());
    let claude = json!({"model": "claude-3-5-sonnet", "stream": true, "messages": []});

    let mut buffered_ctx = post_ctx(&claude);
    let mut headers = json_headers();
    plugin.before_proxy(&mut buffered_ctx, &mut headers).await;
    let buffered = plugin
        .normalize_response_body_with_context(
            &mut buffered_ctx,
            200,
            body.as_bytes(),
            Some("text/event-stream"),
            &HashMap::new(),
        )
        .await
        .expect("a long Anthropic SSE body must still normalize");
    let buffered = String::from_utf8(buffered).unwrap();

    let mut streaming_ctx = post_ctx(&claude);
    let mut headers = json_headers();
    plugin.before_proxy(&mut streaming_ctx, &mut headers).await;
    let mut inspector: Box<dyn ResponseStreamInspector> = plugin
        .response_stream_inspector(&streaming_ctx, 200, Some("text/event-stream"))
        .expect("inspector should be created");
    let mut collected = Vec::new();
    for chunk in body.as_bytes().chunks(4096) {
        collected.extend_from_slice(&forwarded(inspector.on_chunk(chunk).await));
    }
    collected.extend_from_slice(&forwarded(inspector.on_end().await));
    let streamed = String::from_utf8(collected).unwrap();

    assert_eq!(
        strip_created(&buffered),
        strip_created(&streamed),
        "slicing the buffered body must not change the normalized stream"
    );
    assert!(buffered.contains("token-599-padding"));
    assert!(buffered.trim_end().ends_with("data: [DONE]"));
}

#[tokio::test]
async fn test_upstream_error_envelope_is_serialized_through_the_bound() {
    let plugin = build(openai_and_anthropic_config());
    let claude = json!({"model": "claude-3-5-sonnet", "stream": true, "messages": []});
    let mut ctx = post_ctx(&claude);
    let mut headers = json_headers();
    plugin.before_proxy(&mut ctx, &mut headers).await;

    // Two case-variant Content-Encoding headers are rejected before decoding,
    // and the diagnostic becomes the client-visible SSE error envelope.
    let mut response_headers = HashMap::new();
    response_headers.insert("content-encoding".to_string(), "gzip".to_string());
    response_headers.insert("Content-Encoding".to_string(), "br".to_string());

    let out = plugin
        .normalize_response_body_with_context(
            &mut ctx,
            200,
            b"data: {}\n\n",
            Some("text/event-stream"),
            &response_headers,
        )
        .await
        .expect("an unusable content-encoding must produce the error envelope");
    let out = String::from_utf8(out).unwrap();
    assert_eq!(
        out,
        "data: {\"error\":{\"message\":\"multiple case-variant Content-Encoding headers\",\"type\":\"upstream_error\"}}\n\ndata: [DONE]\n\n",
        "the envelope written through the sink must be byte-identical to the \
         document it replaced"
    );

    // The same envelope is refused (leaving the response alone) when the
    // response's retained ceiling cannot hold it, rather than being built first
    // and measured after.
    let mut tiny = post_ctx(&claude);
    let mut headers = json_headers();
    plugin.before_proxy(&mut tiny, &mut headers).await;
    tiny.max_response_body_size_bytes = 8;
    assert!(
        plugin
            .normalize_response_body_with_context(
                &mut tiny,
                200,
                b"data: {}\n\n",
                Some("text/event-stream"),
                &response_headers,
            )
            .await
            .is_none(),
        "an envelope larger than the retained ceiling must be refused during \
         construction"
    );
}

/// A route-effective retained ceiling BELOW the buffered slice size.
///
/// Slicing the input at a constant only bounds the input; the normalized
/// expansion of one slice is still unbounded by this response's ceiling. The
/// accumulator itself is now the bound, so a normalization whose output crosses
/// a small route ceiling is refused while it is being written — and a ceiling
/// that comfortably holds the same output still produces the exact bytes
/// (GHSA-pwcm-6rh8-f2gh).
#[tokio::test]
async fn test_buffered_normalizer_is_bounded_by_a_route_ceiling_below_the_slice_size() {
    let body = long_anthropic_sse(600);
    let plugin = build(openai_and_anthropic_config());
    let claude = json!({"model": "claude-3-5-sonnet", "stream": true, "messages": []});

    let mut roomy = post_ctx(&claude);
    let mut headers = json_headers();
    plugin.before_proxy(&mut roomy, &mut headers).await;
    let normalized = plugin
        .normalize_response_body_with_context(
            &mut roomy,
            200,
            body.as_bytes(),
            Some("text/event-stream"),
            &HashMap::new(),
        )
        .await
        .expect("an ample ceiling must still normalize");
    assert!(
        normalized.len() > 8 * 1024,
        "the fixture must normalize to more than the small ceiling below, got {}",
        normalized.len()
    );

    for ceiling in [1usize, 512, 8 * 1024, 16 * 1024] {
        let mut ctx = post_ctx(&claude);
        let mut headers = json_headers();
        plugin.before_proxy(&mut ctx, &mut headers).await;
        ctx.max_response_body_size_bytes = ceiling;
        assert!(
            plugin
                .normalize_response_body_with_context(
                    &mut ctx,
                    200,
                    body.as_bytes(),
                    Some("text/event-stream"),
                    &HashMap::new(),
                )
                .await
                .is_none(),
            "a normalization larger than a {ceiling}-byte retained ceiling must be \
             refused, including ceilings below the buffered slice size"
        );
    }

    // A ceiling that exactly covers the normalized output still admits it, so
    // the refusals above are the bound and not an unconditional failure.
    let mut exact = post_ctx(&claude);
    let mut headers = json_headers();
    plugin.before_proxy(&mut exact, &mut headers).await;
    exact.max_response_body_size_bytes = normalized.len();
    let admitted = plugin
        .normalize_response_body_with_context(
            &mut exact,
            200,
            body.as_bytes(),
            Some("text/event-stream"),
            &HashMap::new(),
        )
        .await
        .expect("a ceiling equal to the output must admit it");
    let admitted_text = std::str::from_utf8(&admitted).expect("normalized SSE must be UTF-8");
    let normalized_text = std::str::from_utf8(&normalized).expect("normalized SSE must be UTF-8");
    assert_eq!(
        strip_created(admitted_text),
        strip_created(normalized_text),
        "bounding the accumulator must not change the normalized bytes \
         (modulo the per-instance created epoch)"
    );
}

// Final provider boundary (GHSA-xhp5-hqj8-3mwg)
//
// `ai_stream_router` claims at priority 2984 while the generic
// `request_transformer` runs at 3000. These tests compose the two REAL plugins
// in that real order and assert the outcome through the shared lifecycle
// seams — the credential/model enforcement must happen after the later
// transform, not because of any priority change.
// ---------------------------------------------------------------------------

/// Run `before_proxy` for a plugin chain the way the shared proxy runner does:
/// in configured priority order, over one header map and one request context.
async fn run_before_proxy_chain(
    plugins: &[Arc<dyn Plugin>],
    ctx: &mut RequestContext,
    headers: &mut HashMap<String, String>,
) -> PluginResult {
    for plugin in plugins {
        match plugin.before_proxy(ctx, headers).await {
            PluginResult::Continue => {}
            reject => return reject,
        }
    }
    PluginResult::Continue
}

fn final_header_policy(
    plugins: &[Arc<dyn Plugin>],
    ctx: &RequestContext,
    headers: &mut HashMap<String, String>,
) {
    ferrum_edge::_test_support::run_final_backend_header_policy_hooks_for_test(
        plugins, ctx, headers,
    );
}

fn transformer(rules: Value) -> RequestTransformer {
    RequestTransformer::new(&json!({ "rules": rules })).expect("transformer config should be valid")
}

fn router_then_transformer(transformer_rules: Value) -> Vec<Arc<dyn Plugin>> {
    let router = build(openai_and_anthropic_config());
    let later = transformer(transformer_rules);
    assert!(
        router.priority() < later.priority(),
        "the composition under test requires the transformer to run AFTER the router"
    );
    let plugins: Vec<Arc<dyn Plugin>> = vec![Arc::new(router), Arc::new(later)];
    plugins
}

fn streaming_request(model: &str) -> Value {
    json!({
        "model": model,
        "stream": true,
        "messages": [{"role": "user", "content": "hi"}]
    })
}

/// Claim a streaming request through the composed chain and return the header
/// map after the FINAL backend header policy pass.
async fn claimed_final_headers(
    plugins: &[Arc<dyn Plugin>],
    model: &str,
    client_headers: HashMap<String, String>,
) -> (RequestContext, HashMap<String, String>) {
    let body = streaming_request(model);
    let mut ctx = post_ctx(&body);
    let mut headers = client_headers;
    assert!(matches!(
        run_before_proxy_chain(plugins, &mut ctx, &mut headers).await,
        PluginResult::Continue
    ));
    assert_eq!(
        ctx.metadata
            .get("ai_stream_router.claimed")
            .map(String::as_str),
        Some("true"),
        "fixture must actually be claimed by the router"
    );
    final_header_policy(plugins, &ctx, &mut headers);
    (ctx, headers)
}

fn assert_no_value_anywhere(headers: &HashMap<String, String>, needle: &str) {
    for (name, value) in headers {
        assert!(
            !value.contains(needle),
            "header '{name}' still carries a forbidden value"
        );
    }
}

// --- Header re-assertion -----------------------------------------------------

#[tokio::test]
async fn final_header_policy_overrides_a_later_authorization_update() {
    let plugins = router_then_transformer(json!([
        {"operation": "update", "target": "header", "key": "Authorization",
         "value": "Bearer INTERNAL-BACKEND-SECRET"}
    ]));
    let (_ctx, headers) = claimed_final_headers(&plugins, "gpt-4o", json_headers()).await;

    assert_eq!(
        headers.get("authorization").map(String::as_str),
        Some("Bearer sk-openai-secret")
    );
    assert_no_value_anywhere(&headers, "INTERNAL-BACKEND-SECRET");
}

#[tokio::test]
async fn final_header_policy_removes_a_later_added_client_credential() {
    let plugins = router_then_transformer(json!([
        {"operation": "add", "target": "header", "key": "X-Api-Key", "value": "client-token"},
        {"operation": "add", "target": "header", "key": "Cookie", "value": "session=abc"},
        {"operation": "add", "target": "header", "key": "Proxy-Authorization", "value": "Basic zzz"}
    ]));
    let (_ctx, headers) = claimed_final_headers(&plugins, "gpt-4o", json_headers()).await;

    assert!(!headers.contains_key("x-api-key"));
    assert!(!headers.contains_key("cookie"));
    assert!(!headers.contains_key("proxy-authorization"));
    assert_eq!(
        headers.get("authorization").map(String::as_str),
        Some("Bearer sk-openai-secret")
    );
}

#[tokio::test]
async fn final_header_policy_defeats_a_later_rename_into_a_credential_header() {
    // A normal-backend secret renamed onto the provider's credential header.
    let mut client_headers = json_headers();
    client_headers.insert(
        "x-internal-token".to_string(),
        "INTERNAL-BACKEND-SECRET".to_string(),
    );
    let plugins = router_then_transformer(json!([
        {"operation": "rename", "target": "header", "key": "X-Internal-Token",
         "new_key": "Authorization"}
    ]));
    let (_ctx, headers) = claimed_final_headers(&plugins, "gpt-4o", client_headers).await;

    assert_eq!(
        headers.get("authorization").map(String::as_str),
        Some("Bearer sk-openai-secret")
    );
    assert_no_value_anywhere(&headers, "INTERNAL-BACKEND-SECRET");
}

#[tokio::test]
async fn final_header_policy_restores_a_credential_a_later_rename_moved_away() {
    let plugins = router_then_transformer(json!([
        {"operation": "rename", "target": "header", "key": "Authorization",
         "new_key": "X-Api-Key"}
    ]));
    let (_ctx, headers) = claimed_final_headers(&plugins, "gpt-4o", json_headers()).await;

    assert_eq!(
        headers.get("authorization").map(String::as_str),
        Some("Bearer sk-openai-secret")
    );
    // The renamed copy landed on a credential header name and is stripped too.
    assert!(!headers.contains_key("x-api-key"));
}

#[tokio::test]
async fn final_header_policy_restores_a_credential_a_later_remove_deleted() {
    let plugins = router_then_transformer(json!([
        {"operation": "remove", "target": "header", "key": "Authorization"}
    ]));
    let (_ctx, headers) = claimed_final_headers(&plugins, "gpt-4o", json_headers()).await;

    assert_eq!(
        headers.get("authorization").map(String::as_str),
        Some("Bearer sk-openai-secret")
    );
}

#[tokio::test]
async fn final_header_policy_strips_reintroduced_gateway_identity_assertions() {
    let plugins = router_then_transformer(json!([
        {"operation": "add", "target": "header", "key": "X-Consumer-Username", "value": "alice"},
        {"operation": "add", "target": "header", "key": "X-Consumer-Custom-Id", "value": "cid-1"},
        {"operation": "add", "target": "header", "key": "X-Geo-Country", "value": "US"}
    ]));
    let (_ctx, headers) = claimed_final_headers(&plugins, "gpt-4o", json_headers()).await;

    assert!(!headers.contains_key("x-consumer-username"));
    assert!(!headers.contains_key("x-consumer-custom-id"));
    assert!(!headers.contains_key("x-geo-country"));
}

#[tokio::test]
async fn final_header_policy_restores_the_anthropic_provider_credential_set() {
    let plugins = router_then_transformer(json!([
        {"operation": "update", "target": "header", "key": "X-Api-Key", "value": "attacker-key"},
        {"operation": "remove", "target": "header", "key": "Anthropic-Version"},
        {"operation": "update", "target": "header", "key": "Accept-Encoding", "value": "gzip"}
    ]));
    let (_ctx, headers) =
        claimed_final_headers(&plugins, "claude-3-5-sonnet", json_headers()).await;

    assert_eq!(
        headers.get("x-api-key").map(String::as_str),
        Some("sk-ant-secret")
    );
    assert_eq!(
        headers.get("anthropic-version").map(String::as_str),
        Some("2023-06-01")
    );
    // Anthropic SSE is normalized, so identity encoding is re-asserted.
    assert_eq!(
        headers.get("accept-encoding").map(String::as_str),
        Some("identity")
    );
    assert!(!headers.contains_key("authorization"));
    assert_no_value_anywhere(&headers, "attacker-key");
}

#[tokio::test]
async fn final_header_policy_preserves_safe_non_credential_transforms() {
    let mut client_headers = json_headers();
    client_headers.insert("x-drop-me".to_string(), "yes".to_string());
    let plugins = router_then_transformer(json!([
        {"operation": "add", "target": "header", "key": "X-Request-Source", "value": "edge"},
        {"operation": "remove", "target": "header", "key": "X-Drop-Me"}
    ]));
    let (_ctx, headers) = claimed_final_headers(&plugins, "gpt-4o", client_headers).await;

    assert_eq!(
        headers.get("x-request-source").map(String::as_str),
        Some("edge"),
        "an intended non-credential transform must still reach the provider"
    );
    assert!(!headers.contains_key("x-drop-me"));
    assert_eq!(
        headers.get("host").map(String::as_str),
        Some("api.openai.com")
    );
    assert_eq!(
        headers.get("accept").map(String::as_str),
        Some("text/event-stream")
    );
}

#[tokio::test]
async fn final_header_policy_is_idempotent_for_replayed_retry_attempts() {
    let plugins = router_then_transformer(json!([
        {"operation": "update", "target": "header", "key": "Authorization", "value": "Bearer nope"}
    ]));
    let (ctx, headers) = claimed_final_headers(&plugins, "gpt-4o", json_headers()).await;
    let mut replayed = headers.clone();
    // A retry replays the already-finalized header map; re-running the pass over
    // it must not drift.
    final_header_policy(&plugins, &ctx, &mut replayed);
    final_header_policy(&plugins, &ctx, &mut replayed);
    assert_eq!(replayed, headers);
}

#[tokio::test]
async fn final_header_policy_does_not_touch_unclaimed_requests() {
    let plugins = router_then_transformer(json!([
        {"operation": "add", "target": "header", "key": "Authorization", "value": "Bearer client"}
    ]));
    // Non-streaming: the router never claims it, so the transformer's header
    // survives untouched.
    let body = json!({
        "model": "gpt-4o",
        "messages": [{"role": "user", "content": "hi"}]
    });
    let mut ctx = post_ctx(&body);
    let mut headers = json_headers();
    assert!(matches!(
        run_before_proxy_chain(&plugins, &mut ctx, &mut headers).await,
        PluginResult::Continue
    ));
    assert!(!ctx.metadata.contains_key("ai_stream_router.claimed"));
    final_header_policy(&plugins, &ctx, &mut headers);
    assert_eq!(
        headers.get("authorization").map(String::as_str),
        Some("Bearer client")
    );
}

// --- Body / model / route revalidation ---------------------------------------

/// Claim through the chain, then run the shared buffered request-body stage
/// (every `transform_request_body` hook, then every `on_final_request_body`
/// hook) exactly as the proxy does.
async fn claimed_body_stage(plugins: &[Arc<dyn Plugin>], model: &str) -> (Vec<u8>, PluginResult) {
    let body = streaming_request(model);
    let raw = serde_json::to_vec(&body).unwrap();
    let mut ctx = post_ctx(&body);
    let mut headers = json_headers();
    assert!(matches!(
        run_before_proxy_chain(plugins, &mut ctx, &mut headers).await,
        PluginResult::Continue
    ));
    final_header_policy(plugins, &ctx, &mut headers);
    ferrum_edge::_test_support::run_request_body_stage_with_context_for_test(
        plugins, &mut ctx, &headers, &raw,
    )
    .await
}

#[tokio::test]
async fn final_body_rejects_a_later_model_overwrite() {
    let plugins = router_then_transformer(json!([
        {"operation": "update", "target": "body", "key": "model", "value": "gpt-4o-expensive"}
    ]));
    let (_body, result) = claimed_body_stage(&plugins, "gpt-4o").await;
    assert_eq!(reject_status(&result), Some(400));
}

#[tokio::test]
async fn final_body_rejects_a_later_model_rename_from_a_client_alias() {
    // The client supplies an allowed `model` plus an attacker-chosen alias that
    // a later rule promotes to `model` after selection already happened.
    let mut body = streaming_request("gpt-4o");
    body["model_alias"] = json!("gpt-4o-expensive");
    let raw = serde_json::to_vec(&body).unwrap();

    let plugins = router_then_transformer(json!([
        {"operation": "remove", "target": "body", "key": "model"},
        {"operation": "rename", "target": "body", "key": "model_alias", "new_key": "model"}
    ]));
    let mut ctx = post_ctx(&body);
    let mut headers = json_headers();
    assert!(matches!(
        run_before_proxy_chain(&plugins, &mut ctx, &mut headers).await,
        PluginResult::Continue
    ));
    let (_final_body, result) =
        ferrum_edge::_test_support::run_request_body_stage_with_context_for_test(
            &plugins, &mut ctx, &headers, &raw,
        )
        .await;
    assert_eq!(reject_status(&result), Some(400));
}

#[tokio::test]
async fn final_body_allows_an_unrelated_safe_body_transform() {
    let plugins = router_then_transformer(json!([
        {"operation": "add", "target": "body", "key": "user", "value": "tenant-a"}
    ]));
    let (final_body, result) = claimed_body_stage(&plugins, "gpt-4o").await;
    assert!(matches!(result, PluginResult::Continue));
    let parsed: Value = serde_json::from_slice(&final_body).unwrap();
    assert_eq!(parsed["model"], json!("gpt-4o"));
    assert_eq!(parsed["user"], json!("tenant-a"));
}

#[tokio::test]
async fn final_body_accepts_the_translated_anthropic_representation() {
    let plugins = router_then_transformer(json!([
        {"operation": "add", "target": "header", "key": "X-Request-Source", "value": "edge"}
    ]));
    let (final_body, result) = claimed_body_stage(&plugins, "claude-3-5-sonnet").await;
    assert!(matches!(result, PluginResult::Continue));
    let parsed: Value = serde_json::from_slice(&final_body).unwrap();
    assert_eq!(parsed["model"], json!("claude-3-5-sonnet"));
}

#[tokio::test]
async fn final_body_rejects_a_later_anthropic_model_overwrite() {
    let plugins = router_then_transformer(json!([
        {"operation": "update", "target": "body", "key": "model", "value": "claude-3-opus"}
    ]));
    let (_body, result) = claimed_body_stage(&plugins, "claude-3-5-sonnet").await;
    assert_eq!(reject_status(&result), Some(400));
}

#[tokio::test]
async fn final_body_rejects_malformed_missing_and_ambiguous_final_models() {
    let plugin = build(openai_and_anthropic_config());
    for final_bytes in [
        // Not JSON at all after a later rewrite.
        b"not-json".to_vec(),
        // JSON, but no usable model.
        br#"{"stream":true}"#.to_vec(),
        // Present but empty.
        br#"{"model":"","stream":true}"#.to_vec(),
        // Present but not a string.
        br#"{"model":42,"stream":true}"#.to_vec(),
        // Duplicate members make the provider-visible generation
        // parser-dependent: the committed value must not launder the other one.
        br#"{"model":"gpt-4o-expensive","model":"gpt-4o","stream":true}"#.to_vec(),
    ] {
        let body = streaming_request("gpt-4o");
        let mut ctx = post_ctx(&body);
        let mut headers = json_headers();
        assert!(matches!(
            plugin.before_proxy(&mut ctx, &mut headers).await,
            PluginResult::Continue
        ));
        let result = plugin
            .on_final_request_body_with_context(&mut ctx, &headers, &final_bytes)
            .await;
        assert_eq!(
            reject_status(&result),
            Some(400),
            "final body {:?} must fail closed",
            String::from_utf8_lossy(&final_bytes)
        );
    }
}

#[tokio::test]
async fn final_body_rejects_a_route_override_changed_after_the_claim() {
    let plugin = build(openai_and_anthropic_config());
    let body = streaming_request("gpt-4o");
    let raw = serde_json::to_vec(&body).unwrap();

    for mutate in [
        (|ctx: &mut RequestContext| {
            ctx.route_override_backend_host = Some("evil.example.com".to_string())
        }) as fn(&mut RequestContext),
        |ctx: &mut RequestContext| ctx.route_override_backend_port = Some(8443),
        |ctx: &mut RequestContext| {
            ctx.route_override_authority = Some("evil.example.com".to_string())
        },
        |ctx: &mut RequestContext| ctx.route_override_path = Some("/v1/other".to_string()),
        |ctx: &mut RequestContext| ctx.route_override_path_is_absolute = false,
    ] {
        let mut ctx = post_ctx(&body);
        let mut headers = json_headers();
        assert!(matches!(
            plugin.before_proxy(&mut ctx, &mut headers).await,
            PluginResult::Continue
        ));
        mutate(&mut ctx);
        let result = plugin
            .on_final_request_body_with_context(&mut ctx, &headers, &raw)
            .await;
        assert_eq!(
            reject_status(&result),
            Some(500),
            "a repointed route override must fail closed"
        );
    }
}

#[tokio::test]
async fn final_body_revalidation_never_echoes_the_offending_value() {
    let plugin = build(openai_and_anthropic_config());
    let body = streaming_request("gpt-4o");
    let mut ctx = post_ctx(&body);
    let mut headers = json_headers();
    assert!(matches!(
        plugin.before_proxy(&mut ctx, &mut headers).await,
        PluginResult::Continue
    ));
    let result = plugin
        .on_final_request_body_with_context(
            &mut ctx,
            &headers,
            br#"{"model":"LEAKED-SECRET-VALUE","stream":true}"#,
        )
        .await;
    let rendered = match &result {
        PluginResult::Reject { body, .. } => body.clone(),
        other => panic!("expected a reject, got {other:?}"),
    };
    assert!(
        !rendered.contains("LEAKED-SECRET-VALUE"),
        "the rejection envelope must not echo the final body value"
    );
    assert!(rendered.contains("model_policy_violation"));
}

// --- Capability, wiring, and composition -------------------------------------

#[test]
fn final_backend_header_policy_capability_tracks_enabled() {
    assert!(build(openai_and_anthropic_config()).enforces_final_backend_header_policy());

    let mut disabled = openai_and_anthropic_config();
    disabled["enabled"] = json!(false);
    assert!(!build(disabled).enforces_final_backend_header_policy());
}

#[test]
fn enforcement_is_not_a_priority_reordering() {
    // The advisory's ordering is unchanged: the generic transformer still runs
    // AFTER the router. The fix is the later shared phase, not a renumbering.
    const {
        assert!(
            priority::AI_STREAM_ROUTER < priority::REQUEST_TRANSFORMER,
            "the fix must not depend on moving ai_stream_router after request_transformer"
        );
    }
}

#[test]
fn shared_lifecycle_wires_the_final_header_policy_on_every_dispatcher() {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
    let h1h2 = std::fs::read_to_string(root.join("src/proxy/mod.rs")).expect("read proxy/mod.rs");
    let h3 =
        std::fs::read_to_string(root.join("src/http3/server.rs")).expect("read http3/server.rs");

    // H1/H2: the post-before_proxy site, both deferred-pass sites, and the
    // finalized-egress overlay site, plus the definition itself.
    assert!(
        h1h2.matches("run_effective_final_backend_header_policy_hooks(")
            .count()
            >= 5,
        "the H1/H2 ladder must re-assert the final backend header policy after \
         before_proxy, after each deferred pass, and after the egress overlay"
    );
    // H3 must not be patched out: its own post-before_proxy site plus both
    // deferred-pass sites.
    assert!(
        h3.matches("run_final_backend_header_policy_hooks(").count() >= 3,
        "the native HTTP/3 ladder must re-assert the final backend header policy too"
    );
}

/// Declares only the final backend-header-policy capability. No built-in can
/// express that in isolation — `ai_stream_router` also transforms the request
/// body — so the rule is driven through the shared composition seam.
struct FinalHeaderPolicyOnlyPlugin;

#[async_trait::async_trait]
impl Plugin for FinalHeaderPolicyOnlyPlugin {
    fn name(&self) -> &str {
        "custom_final_header_policy"
    }

    fn enforces_final_backend_header_policy(&self) -> bool {
        true
    }
}

#[test]
fn deduplication_cannot_be_composed_with_a_final_backend_header_policy() {
    let plugins: Vec<Arc<dyn Plugin>> = vec![
        Arc::new(FinalHeaderPolicyOnlyPlugin),
        Arc::new(
            RequestDeduplication::new(&json!({ "scope_by_consumer": false }), http_client())
                .expect("dedup config should be valid"),
        ),
    ];
    let error = ferrum_edge::_test_support::validate_plugin_security_composition_for_test(&plugins)
        .expect_err("a before_proxy fingerprint cannot witness the later header re-assertion");
    assert!(
        error.contains("custom_final_header_policy")
            && error.contains("request_deduplication")
            && error.contains("backend-boundary header policy"),
        "unexpected composition diagnostic: {error}"
    );
}

#[test]
fn deduplication_already_refuses_the_router_as_a_deferred_body_transformer() {
    // The built-in declarer is rejected before the header-policy rule is even
    // reached, so the router can never reach a deduplication fingerprint.
    let plugins: Vec<Arc<dyn Plugin>> = vec![
        Arc::new(build(openai_and_anthropic_config())),
        Arc::new(
            RequestDeduplication::new(&json!({ "scope_by_consumer": false }), http_client())
                .expect("dedup config should be valid"),
        ),
    ];
    let error = ferrum_edge::_test_support::validate_plugin_security_composition_for_test(&plugins)
        .expect_err("ai_stream_router must not compose with request_deduplication");
    assert!(
        error.contains("ai_stream_router") && error.contains("request_deduplication"),
        "unexpected composition diagnostic: {error}"
    );
}

#[test]
fn response_caching_needs_no_added_final_header_policy_rule() {
    // Documents why the final-header-policy admission rule is deduplication-only:
    // `response_caching` already refuses this plugin as a deferred request-body
    // transformer, so a second rejection would be redundant.
    let plugins: Vec<Arc<dyn Plugin>> = vec![
        Arc::new(build(openai_and_anthropic_config())),
        Arc::new(
            ResponseCaching::new(&json!({ "ttl_seconds": 60 }))
                .expect("response_caching config should be valid"),
        ),
    ];
    let error = ferrum_edge::_test_support::validate_plugin_security_composition_for_test(&plugins)
        .expect_err("response_caching already refuses a deferred request-body transformer");
    assert!(
        error.contains("response_caching") && error.contains("ai_stream_router"),
        "unexpected composition diagnostic: {error}"
    );
}

// ---------------------------------------------------------------------------
// Final provider-visible QUERY (GHSA-xhp5-hqj8-3mwg)
//
// `request_transformer` (3000) runs after the claim (2984) and its query rules
// can add/update/rename/remove pairs. The committed query is frozen at claim
// time and replayed at the single capture funnel every dispatcher and every
// retry attempt reads.
// ---------------------------------------------------------------------------

/// The value the H1/H2 and native-H3 ladders actually capture once per request.
fn captured_backend_query(ctx: &RequestContext, raw_query: &str) -> String {
    let with_raw = ferrum_edge::_test_support::effective_backend_query_string_with_raw_for_test(
        ctx, raw_query,
    );
    // Both funnels must agree; the `_with_raw` form is what the ladders use and
    // the plain form is what the policy/replay consumers use.
    assert_eq!(
        with_raw,
        ferrum_edge::_test_support::effective_backend_query_string_for_test(ctx),
        "the two backend-query funnels disagree"
    );
    with_raw
}

fn post_ctx_with_query(body: &Value, raw_query: &str) -> RequestContext {
    let mut ctx = post_ctx(body);
    ctx.set_raw_query_string(raw_query.to_string());
    ctx
}

/// Claim `model` through `plugins` with `raw_query` on the wire, then return the
/// context plus the captured backend-visible query.
async fn claimed_backend_query(
    plugins: &[Arc<dyn Plugin>],
    model: &str,
    raw_query: &str,
) -> (RequestContext, String) {
    let body = streaming_request(model);
    let mut ctx = post_ctx_with_query(&body, raw_query);
    let mut headers = json_headers();
    assert!(matches!(
        run_before_proxy_chain(plugins, &mut ctx, &mut headers).await,
        PluginResult::Continue
    ));
    assert_eq!(
        ctx.metadata
            .get("ai_stream_router.claimed")
            .map(String::as_str),
        Some("true"),
        "fixture must actually be claimed by the router"
    );
    let captured = captured_backend_query(&ctx, raw_query);
    (ctx, captured)
}

fn azure_final_query_config() -> Value {
    json!({
        "enabled": true,
        "providers": [
            {
                "name": "azure",
                "provider_type": "openai_compatible",
                "endpoint": "https://azure.example.com/openai/chat/completions?api-version=2024-06-01",
                "api_key": "sk-azure-secret",
                "model_patterns": ["gpt-*"],
                "priority": 1
            }
        ]
    })
}

fn router_config_then_transformer(
    router_config: Value,
    transformer_rules: Value,
) -> Vec<Arc<dyn Plugin>> {
    let router = build(router_config);
    let later = transformer(transformer_rules);
    assert!(
        router.priority() < later.priority(),
        "the composition under test requires the transformer to run AFTER the router"
    );
    vec![Arc::new(router), Arc::new(later)]
}

#[tokio::test]
async fn final_query_discards_a_later_query_add() {
    let plugins = router_then_transformer(json!([
        {"operation": "add", "target": "query", "key": "backend_token",
         "value": "INTERNAL-BACKEND-SECRET"}
    ]));
    let (_ctx, query) = claimed_backend_query(&plugins, "gpt-4o", "temperature=0").await;

    assert_eq!(query, "temperature=0");
    assert!(
        !query.contains("INTERNAL-BACKEND-SECRET"),
        "a later query rule must not append a normal-backend secret to the provider URL"
    );
}

#[tokio::test]
async fn final_query_discards_later_update_rename_and_remove_rules() {
    for rules in [
        json!([{"operation": "update", "target": "query", "key": "temperature",
                "value": "INTERNAL-BACKEND-SECRET"}]),
        json!([{"operation": "rename", "target": "query", "key": "temperature",
                "new_key": "backend_token"}]),
        json!([{"operation": "remove", "target": "query", "key": "temperature"}]),
    ] {
        let plugins = router_then_transformer(rules.clone());
        let (_ctx, query) = claimed_backend_query(&plugins, "gpt-4o", "temperature=0").await;
        assert_eq!(
            query, "temperature=0",
            "later query rule {rules} must not reach the provider target"
        );
    }
}

#[tokio::test]
async fn final_query_preserves_a_safe_unchanged_client_query() {
    // No later query rule at all: the already-safe client query continues.
    let plugins = router_then_transformer(json!([
        {"operation": "add", "target": "header", "key": "X-Request-Source", "value": "edge"}
    ]));
    let (_ctx, query) = claimed_backend_query(&plugins, "gpt-4o", "a=1&b=2").await;
    assert_eq!(query, "a=1&b=2");
}

#[tokio::test]
async fn final_query_is_empty_when_an_endpoint_query_is_folded_into_the_path() {
    let plugins = router_config_then_transformer(
        azure_final_query_config(),
        json!([{"operation": "add", "target": "query", "key": "backend_token",
                "value": "INTERNAL-BACKEND-SECRET"}]),
    );
    let (ctx, query) = claimed_backend_query(&plugins, "gpt-4o", "a=1").await;

    // The endpoint query and the client query are both folded into the absolute
    // override path, so nothing may be appended separately — a second `?` would
    // otherwise be produced, and the later rule must not sneak a pair in here.
    assert_eq!(query, "");
    let path = ctx.route_override_path.as_deref().expect("committed path");
    assert!(
        path.contains("api-version=2024-06-01") && path.contains("a=1"),
        "endpoint + client query must be folded into the committed path: {path}"
    );
}

#[tokio::test]
async fn final_query_honors_authentication_strip_markers_at_claim_time() {
    let plugins = router_then_transformer(json!([
        {"operation": "add", "target": "query", "key": "late", "value": "x"}
    ]));
    let body = streaming_request("gpt-4o");
    let mut ctx = post_ctx_with_query(&body, "api_key=CLIENT-CREDENTIAL&keep=1");
    // Authentication-owned strip marker, exactly as a credential-consuming auth
    // plugin publishes it before `before_proxy` (`auth.strip_query_param.<name>`).
    ctx.metadata.insert(
        "auth.strip_query_param.api_key".to_string(),
        "true".to_string(),
    );
    let mut headers = json_headers();
    assert!(matches!(
        run_before_proxy_chain(&plugins, &mut ctx, &mut headers).await,
        PluginResult::Continue
    ));

    let query = captured_backend_query(&ctx, "api_key=CLIENT-CREDENTIAL&keep=1");
    assert_eq!(query, "keep=1");
    assert!(!query.contains("CLIENT-CREDENTIAL"));
}

#[tokio::test]
async fn final_query_replays_identically_for_every_retry_attempt() {
    let plugins = router_then_transformer(json!([
        {"operation": "add", "target": "query", "key": "backend_token", "value": "leak"}
    ]));
    let (ctx, first) = claimed_backend_query(&plugins, "gpt-4o", "a=1").await;
    // A retry recomputes/reuses the same capture; it must be byte-identical.
    for _ in 0..3 {
        assert_eq!(captured_backend_query(&ctx, "a=1"), first);
    }
    assert_eq!(first, "a=1");
}

#[tokio::test]
async fn final_query_is_untouched_for_an_unclaimed_request() {
    let plugins = router_then_transformer(json!([
        {"operation": "add", "target": "query", "key": "added", "value": "1"}
    ]));
    // Non-streaming: never claimed, so ordinary transformer semantics apply.
    let body = json!({
        "model": "gpt-4o",
        "messages": [{"role": "user", "content": "hi"}]
    });
    let mut ctx = post_ctx_with_query(&body, "a=1");
    let mut headers = json_headers();
    assert!(matches!(
        run_before_proxy_chain(&plugins, &mut ctx, &mut headers).await,
        PluginResult::Continue
    ));
    assert!(!ctx.metadata.contains_key("ai_stream_router.claimed"));
    let query = captured_backend_query(&ctx, "a=1");
    assert!(
        query.contains("a=1") && query.contains("added=1"),
        "an unclaimed request keeps ordinary transformer query semantics: {query}"
    );
}

// ---------------------------------------------------------------------------
// Committed destination witness: upstream identity, backend TLS, DNS
// ---------------------------------------------------------------------------

/// Claim a request with a single router instance and hand back the context and
/// the raw body, ready for a mutation + final-body revalidation.
async fn claimed_ctx(plugin: &AiStreamRouter, model: &str) -> (RequestContext, Vec<u8>) {
    let body = streaming_request(model);
    let raw = serde_json::to_vec(&body).unwrap();
    let mut ctx = post_ctx(&body);
    let mut headers = json_headers();
    assert!(matches!(
        plugin.before_proxy(&mut ctx, &mut headers).await,
        PluginResult::Continue
    ));
    (ctx, raw)
}

#[tokio::test]
async fn claim_clears_any_earlier_upstream_id_override() {
    let plugin = build(openai_and_anthropic_config());
    let body = streaming_request("gpt-4o");
    let mut ctx = post_ctx(&body);
    ctx.route_override_upstream_id = Some("internal-pool".to_string());
    let mut headers = json_headers();
    assert!(matches!(
        plugin.before_proxy(&mut ctx, &mut headers).await,
        PluginResult::Continue
    ));
    assert_eq!(
        ctx.route_override_upstream_id, None,
        "a direct provider claim must not leave load-balancer target selection in play"
    );
}

#[tokio::test]
async fn final_body_rejects_a_later_upstream_id_replacement() {
    let plugin = build(openai_and_anthropic_config());
    let (mut ctx, raw) = claimed_ctx(&plugin, "gpt-4o").await;
    // Same visible host/port/path — only the routing identity changed.
    ctx.route_override_upstream_id = Some("attacker-pool".to_string());
    let result = plugin
        .on_final_request_body_with_context(&mut ctx, &json_headers(), &raw)
        .await;
    assert_eq!(reject_status(&result), Some(500));
}

#[tokio::test]
async fn claim_commits_default_public_verification_for_an_https_provider() {
    let plugin = build(openai_and_anthropic_config());
    let (ctx, _raw) = claimed_ctx(&plugin, "gpt-4o").await;
    assert_eq!(
        ctx.route_override_resolved_tls,
        Some(BackendTlsConfig::default_verify())
    );
}

#[tokio::test]
async fn final_body_rejects_later_backend_tls_weakening_clearing_and_retargeting() {
    let plugin = build(openai_and_anthropic_config());
    let mutations: Vec<fn(&mut RequestContext)> = vec![
        // Verification disabled while the visible host stays identical.
        |ctx| {
            let mut tls = BackendTlsConfig::default_verify();
            tls.verify_server_cert = false;
            ctx.route_override_resolved_tls = Some(tls);
        },
        // SNI retargeted.
        |ctx| {
            let mut tls = BackendTlsConfig::default_verify();
            tls.sni = Some("evil.example.com".to_string());
            ctx.route_override_resolved_tls = Some(tls);
        },
        // A different trust anchor.
        |ctx| {
            let mut tls = BackendTlsConfig::default_verify();
            tls.server_ca_cert_path = Some("/tmp/attacker-ca.pem".to_string());
            ctx.route_override_resolved_tls = Some(tls);
        },
        // Ferrum's own backend mTLS identity attached to a third party.
        |ctx| {
            let mut tls = BackendTlsConfig::default_verify();
            tls.client_cert_path = Some("/tmp/gateway.pem".to_string());
            tls.client_key_path = Some("/tmp/gateway.key".to_string());
            ctx.route_override_resolved_tls = Some(tls);
        },
        // Cleared entirely, which would fall back to the proxy's own resolution.
        |ctx| ctx.route_override_resolved_tls = None,
    ];
    for mutate in mutations {
        let (mut ctx, raw) = claimed_ctx(&plugin, "gpt-4o").await;
        mutate(&mut ctx);
        let result = plugin
            .on_final_request_body_with_context(&mut ctx, &json_headers(), &raw)
            .await;
        assert_eq!(
            reject_status(&result),
            Some(500),
            "a mutated backend TLS resolution must fail closed"
        );
    }
}

#[tokio::test]
async fn inherit_backend_tls_commits_the_proxy_resolution_and_rejects_later_mutation() {
    let plugin = build(json!({
        "enabled": true,
        "providers": [{
            "name": "internal",
            "provider_type": "openai_compatible",
            "endpoint": "https://llm.internal.example.com/v1/chat/completions",
            "api_key": "sk-internal-secret",
            "model_patterns": ["gpt-*"],
            "inherit_backend_tls": true
        }]
    }));

    let mut proxy = create_test_proxy();
    proxy.resolved_tls = BackendTlsConfig {
        client_cert_path: Some("/tmp/client.pem".to_string()),
        client_key_path: Some("/tmp/client.key".to_string()),
        server_ca_cert_path: Some("/tmp/private-ca.pem".to_string()),
        verify_server_cert: true,
        sni: Some("llm.internal.example.com".to_string()),
        san_allow_list: vec!["spiffe://internal/llm".to_string()],
        san_allow_list_key_digest: None,
    };
    let inherited = proxy.resolved_tls.clone();

    let body = streaming_request("gpt-4o");
    let raw = serde_json::to_vec(&body).unwrap();
    let mut ctx = post_ctx(&body);
    ctx.matched_proxy = Some(Arc::new(proxy));
    let mut headers = json_headers();
    assert!(matches!(
        plugin.before_proxy(&mut ctx, &mut headers).await,
        PluginResult::Continue
    ));
    assert_eq!(ctx.route_override_resolved_tls, Some(inherited.clone()));
    assert!(matches!(
        plugin
            .on_final_request_body_with_context(&mut ctx, &headers, &raw)
            .await,
        PluginResult::Continue
    ));

    // Now weaken exactly one field of the inherited configuration.
    let mut weakened = inherited;
    weakened.verify_server_cert = false;
    ctx.route_override_resolved_tls = Some(weakened);
    let result = plugin
        .on_final_request_body_with_context(&mut ctx, &headers, &raw)
        .await;
    assert_eq!(reject_status(&result), Some(500));
}

#[tokio::test]
async fn provider_claim_clears_a_same_host_dns_override() {
    // The operator's proxy is already configured with the provider's hostname
    // and a pinned address. Host TEXT is unchanged by the claim, so only the
    // explicit DNS decision can revoke the pin.
    let plugin = build(openai_and_anthropic_config());
    let mut proxy = create_test_proxy();
    proxy.backend_host = "api.openai.com".to_string();
    proxy.dns_override = Some("10.0.0.9".to_string());
    let proxy = Arc::new(proxy);

    let body = streaming_request("gpt-4o");
    let mut ctx = post_ctx(&body);
    ctx.matched_proxy = Some(Arc::clone(&proxy));
    let mut headers = json_headers();
    assert!(matches!(
        plugin.before_proxy(&mut ctx, &mut headers).await,
        PluginResult::Continue
    ));

    let effective = ctx.apply_route_overrides(Arc::clone(&proxy));
    assert_eq!(
        effective.dns_override, None,
        "a same-host provider claim must not inherit the proxy's pinned address"
    );
    assert_eq!(effective.backend_host, "api.openai.com");
}

#[tokio::test]
async fn provider_claim_clears_a_different_host_dns_override() {
    let plugin = build(openai_and_anthropic_config());
    let mut proxy = create_test_proxy();
    proxy.backend_host = "backend.internal".to_string();
    proxy.dns_override = Some("10.0.0.9".to_string());
    let proxy = Arc::new(proxy);

    let body = streaming_request("gpt-4o");
    let mut ctx = post_ctx(&body);
    ctx.matched_proxy = Some(Arc::clone(&proxy));
    let mut headers = json_headers();
    assert!(matches!(
        plugin.before_proxy(&mut ctx, &mut headers).await,
        PluginResult::Continue
    ));

    let effective = ctx.apply_route_overrides(Arc::clone(&proxy));
    assert_eq!(effective.dns_override, None);
    assert_eq!(effective.backend_host, "api.openai.com");
}

#[test]
fn a_non_router_same_host_route_override_keeps_the_proxy_dns_override() {
    // Guards the narrowness of the mechanism: an ordinary route rewriter that
    // does not opt in keeps the historical same-host semantics.
    let mut proxy = create_test_proxy();
    proxy.backend_host = "backend.internal".to_string();
    proxy.dns_override = Some("10.0.0.9".to_string());
    let proxy = Arc::new(proxy);

    let mut ctx = RequestContext::new(
        "127.0.0.1".to_string(),
        "POST".to_string(),
        "/v1/chat/completions".to_string(),
    );
    ctx.route_override_backend_host = Some("backend.internal".to_string());
    ctx.route_override_backend_port = Some(9443);

    let effective = ctx.apply_route_overrides(Arc::clone(&proxy));
    assert_eq!(
        effective.dns_override,
        Some("10.0.0.9".to_string()),
        "an unrelated same-host route override must keep its pinned address"
    );
    assert_eq!(effective.backend_port, 9443);
}

// ---------------------------------------------------------------------------
// Multiple instances: exactly one owner (GHSA-xhp5-hqj8-3mwg)
// ---------------------------------------------------------------------------

/// Two enabled instances whose providers share the SAME name but differ in
/// endpoint, key, provider type, patterns, and normalization setting.
fn two_same_named_instances() -> Vec<Arc<dyn Plugin>> {
    let first = build(json!({
        "enabled": true,
        "normalize_response_stream": true,
        "providers": [{
            "name": "shared",
            "provider_type": "openai",
            "endpoint": "https://first.example.com/v1/chat/completions",
            "api_key": "sk-first-secret",
            "model_patterns": ["gpt-*"]
        }]
    }));
    let second = build(json!({
        "enabled": true,
        "normalize_response_stream": true,
        "providers": [{
            "name": "shared",
            "provider_type": "anthropic",
            "endpoint": "https://second.example.com/v1/messages",
            "api_key": "sk-second-secret",
            "model_patterns": ["gpt-*", "claude-*"]
        }]
    }));
    vec![Arc::new(first), Arc::new(second)]
}

#[tokio::test]
async fn two_same_named_instances_yield_exactly_one_owner_and_one_credential() {
    let plugins = two_same_named_instances();
    let (ctx, headers) = claimed_final_headers(&plugins, "gpt-4o", json_headers()).await;

    // The FIRST instance claimed: its endpoint, its key, its OpenAI (untranslated)
    // contract. The second instance must not have overwritten any of it, even
    // though it also matches `gpt-*` and publishes the same provider NAME.
    assert_eq!(
        headers.get("authorization").map(String::as_str),
        Some("Bearer sk-first-secret")
    );
    assert!(
        !headers.contains_key("x-api-key"),
        "the losing Anthropic instance must not install its own credential header"
    );
    assert!(!headers.contains_key("anthropic-version"));
    assert_no_value_anywhere(&headers, "sk-second-secret");

    assert_eq!(
        ctx.route_override_backend_host.as_deref(),
        Some("first.example.com")
    );
    assert_eq!(
        headers.get("host").map(String::as_str),
        Some("first.example.com")
    );
    assert_eq!(
        ctx.route_override_path.as_deref(),
        Some("/v1/chat/completions")
    );
}

#[tokio::test]
async fn only_the_owning_instance_transforms_the_request_body_and_revalidates() {
    let plugins = two_same_named_instances();
    let (final_body, result) = claimed_body_stage(&plugins, "gpt-4o").await;
    assert!(matches!(result, PluginResult::Continue));

    // The winner is the OpenAI instance, so the body must stay OpenAI-shaped.
    // A second (Anthropic) transform would have produced `max_tokens` + an
    // Anthropic message shape, and the loser's revalidation would then have
    // failed the request.
    let parsed: Value = serde_json::from_slice(&final_body).unwrap();
    assert_eq!(parsed["model"], json!("gpt-4o"));
    assert!(
        parsed.get("max_tokens").is_none(),
        "the losing Anthropic instance must not translate an already-claimed body"
    );
    assert_eq!(parsed["messages"][0]["role"], json!("user"));
}

#[tokio::test]
async fn only_the_owning_instance_selects_a_response_normalizer() {
    // BOTH instances are Anthropic and both would normalize, so
    // `response_stream_hooks` is true on each and ownership is the only thing
    // that can decide between them. A second normalizer would re-parse the
    // already OpenAI-shaped SSE the first one emits.
    let first = build(json!({
        "enabled": true,
        "providers": [{
            "name": "shared",
            "provider_type": "anthropic",
            "endpoint": "https://first.example.com/v1/messages",
            "api_key": "sk-first-secret",
            "model_patterns": ["claude-*"]
        }]
    }));
    let second = build(json!({
        "enabled": true,
        "providers": [{
            "name": "shared",
            "provider_type": "anthropic",
            "endpoint": "https://second.example.com/v1/messages",
            "api_key": "sk-second-secret",
            "model_patterns": ["claude-*"]
        }]
    }));
    assert!(first.requires_response_stream_hooks() && second.requires_response_stream_hooks());

    let body = streaming_request("claude-3-5-sonnet");
    let mut ctx = post_ctx(&body);
    let mut headers = json_headers();
    for plugin in [&first as &dyn Plugin, &second as &dyn Plugin] {
        assert!(matches!(
            plugin.before_proxy(&mut ctx, &mut headers).await,
            PluginResult::Continue
        ));
    }

    assert!(
        first
            .response_stream_inspector(&ctx, 200, Some("text/event-stream"))
            .is_some(),
        "the owning instance must install the normalizer"
    );
    assert!(
        second
            .response_stream_inspector(&ctx, 200, Some("text/event-stream"))
            .is_none(),
        "a losing instance must not install a second normalizer"
    );
    assert!(first.forces_reqwest_dispatch(&ctx));
    assert!(!second.forces_reqwest_dispatch(&ctx));

    // The response-header repair boundary is owned too: only the winner may
    // classify/repair the provider representation.
    let mut response_headers = HashMap::new();
    response_headers.insert("content-type".to_string(), "text/event-stream".to_string());
    response_headers.insert("content-length".to_string(), "42".to_string());
    assert!(matches!(
        second
            .after_proxy(&mut ctx, 200, &mut response_headers)
            .await,
        PluginResult::Continue
    ));
    assert_eq!(
        response_headers.get("content-length").map(String::as_str),
        Some("42"),
        "a losing instance must not repair the normalized representation headers"
    );
    assert!(matches!(
        first
            .after_proxy(&mut ctx, 200, &mut response_headers)
            .await,
        PluginResult::Continue
    ));
    assert!(
        !response_headers.contains_key("content-length"),
        "the owning instance repairs the representation headers"
    );
}

#[tokio::test]
async fn distinct_provider_names_still_yield_exactly_one_owner() {
    let first = build(json!({
        "enabled": true,
        "providers": [{
            "name": "alpha",
            "provider_type": "openai",
            "endpoint": "https://alpha.example.com/v1/chat/completions",
            "api_key": "sk-alpha-secret",
            "model_patterns": ["gpt-*"]
        }]
    }));
    let second = build(json!({
        "enabled": true,
        "providers": [{
            "name": "beta",
            "provider_type": "openai",
            "endpoint": "https://beta.example.com/v1/chat/completions",
            "api_key": "sk-beta-secret",
            "model_patterns": ["gpt-*"]
        }]
    }));
    let plugins: Vec<Arc<dyn Plugin>> = vec![Arc::new(first), Arc::new(second)];
    let (ctx, headers) = claimed_final_headers(&plugins, "gpt-4o", json_headers()).await;

    assert_eq!(
        headers.get("authorization").map(String::as_str),
        Some("Bearer sk-alpha-secret")
    );
    assert_no_value_anywhere(&headers, "sk-beta-secret");
    assert_eq!(
        ctx.metadata
            .get("ai_stream_router.provider")
            .map(String::as_str),
        Some("alpha")
    );
    assert_eq!(
        ctx.route_override_backend_host.as_deref(),
        Some("alpha.example.com")
    );
}

#[tokio::test]
async fn a_disabled_first_instance_lets_the_second_instance_claim() {
    let disabled = build(json!({
        "enabled": false,
        "providers": [{
            "name": "shared",
            "provider_type": "openai",
            "endpoint": "https://first.example.com/v1/chat/completions",
            "api_key": "sk-first-secret",
            "model_patterns": ["gpt-*"]
        }]
    }));
    let enabled = build(json!({
        "enabled": true,
        "providers": [{
            "name": "shared",
            "provider_type": "openai",
            "endpoint": "https://second.example.com/v1/chat/completions",
            "api_key": "sk-second-secret",
            "model_patterns": ["gpt-*"]
        }]
    }));
    let plugins: Vec<Arc<dyn Plugin>> = vec![Arc::new(disabled), Arc::new(enabled)];
    let (ctx, headers) = claimed_final_headers(&plugins, "gpt-4o", json_headers()).await;

    assert_eq!(
        headers.get("authorization").map(String::as_str),
        Some("Bearer sk-second-secret")
    );
    assert_eq!(
        ctx.route_override_backend_host.as_deref(),
        Some("second.example.com")
    );
}

#[tokio::test]
async fn a_nonmatching_first_instance_lets_the_second_instance_claim() {
    let nonmatching = build(json!({
        "enabled": true,
        "fail_on_no_matching_provider": false,
        "providers": [{
            "name": "shared",
            "provider_type": "openai",
            "endpoint": "https://first.example.com/v1/chat/completions",
            "api_key": "sk-first-secret",
            "model_patterns": ["llama-*"]
        }]
    }));
    let matching = build(json!({
        "enabled": true,
        "providers": [{
            "name": "shared",
            "provider_type": "openai",
            "endpoint": "https://second.example.com/v1/chat/completions",
            "api_key": "sk-second-secret",
            "model_patterns": ["gpt-*"]
        }]
    }));
    let plugins: Vec<Arc<dyn Plugin>> = vec![Arc::new(nonmatching), Arc::new(matching)];
    let (ctx, headers) = claimed_final_headers(&plugins, "gpt-4o", json_headers()).await;

    assert_eq!(
        headers.get("authorization").map(String::as_str),
        Some("Bearer sk-second-secret")
    );
    assert_eq!(
        ctx.route_override_backend_host.as_deref(),
        Some("second.example.com")
    );
}

#[tokio::test]
async fn an_unclaimed_request_still_fails_on_no_matching_provider_in_plugin_order() {
    // Ownership begins only on a successful claim: with nothing claimed, the
    // first instance's fail-closed policy still decides the request.
    let strict = build(json!({
        "enabled": true,
        "providers": [{
            "name": "shared",
            "provider_type": "openai",
            "endpoint": "https://first.example.com/v1/chat/completions",
            "api_key": "sk-first-secret",
            "model_patterns": ["llama-*"]
        }]
    }));
    let permissive = build(json!({
        "enabled": true,
        "providers": [{
            "name": "other",
            "provider_type": "openai",
            "endpoint": "https://second.example.com/v1/chat/completions",
            "api_key": "sk-second-secret",
            "model_patterns": ["gpt-*"]
        }]
    }));
    let plugins: Vec<Arc<dyn Plugin>> = vec![Arc::new(strict), Arc::new(permissive)];

    let body = streaming_request("gpt-4o");
    let mut ctx = post_ctx(&body);
    let mut headers = json_headers();
    let result = run_before_proxy_chain(&plugins, &mut ctx, &mut headers).await;
    assert_eq!(
        reject_status(&result),
        Some(404),
        "an unclaimed request keeps normal plugin-order fail-closed behavior"
    );
    assert!(ctx.route_override_backend_host.is_none());
}

#[test]
fn shared_lifecycle_captures_the_backend_query_through_one_funnel() {
    // The committed-query re-assertion lives inside
    // `effective_backend_query_string*`, so it is only complete while both
    // dispatch ladders capture their outbound query there and nowhere else.
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
    let h1h2 = std::fs::read_to_string(root.join("src/proxy/mod.rs")).expect("read proxy/mod.rs");
    let h3 =
        std::fs::read_to_string(root.join("src/http3/server.rs")).expect("read http3/server.rs");

    assert!(
        h1h2.contains("effective_backend_query_string_with_raw(&ctx, &query_string)"),
        "the H1/H2 ladder must capture its backend query through the shared funnel"
    );
    assert!(
        h3.contains("effective_backend_query_string_with_raw(&ctx, &query_string)"),
        "the native HTTP/3 ladder must capture its backend query through the shared funnel"
    );
}

// ---------------------------------------------------------------------------
// The committed model is private claim state, not metadata
// (GHSA-xhp5-hqj8-3mwg)
//
// `ai_stream_router.model` is published for observability and a later in-process
// plugin can write it. Enforcement and claim-owned response normalization must
// therefore read the model the CLAIM committed, never that key — otherwise a
// plugin that rewrote both the final body's model and the metadata key to the
// same new value would satisfy an equality check while bypassing the selection
// that chose the provider, the price, and (for `{model}` endpoints) the backend
// URL.
// ---------------------------------------------------------------------------

const MODEL_META_KEY: &str = "ai_stream_router.model";

/// Claim through the composed chain, let a later in-process plugin overwrite the
/// PUBLIC model metadata key, then run the shared buffered request-body stage
/// (every transform, then every final hook) exactly as the proxy does.
async fn forged_meta_body_stage(
    plugins: &[Arc<dyn Plugin>],
    model: &str,
    forged: &str,
) -> (Vec<u8>, PluginResult) {
    let body = streaming_request(model);
    let raw = serde_json::to_vec(&body).unwrap();
    let mut ctx = post_ctx(&body);
    let mut headers = json_headers();
    assert!(matches!(
        run_before_proxy_chain(plugins, &mut ctx, &mut headers).await,
        PluginResult::Continue
    ));
    assert_eq!(
        ctx.metadata.get(MODEL_META_KEY).map(String::as_str),
        Some(model),
        "fixture must start from the real committed model"
    );
    // A later plugin rewriting public metadata — exactly what the key being
    // observability rather than policy state has to tolerate.
    ctx.metadata
        .insert(MODEL_META_KEY.to_string(), forged.to_string());
    final_header_policy(plugins, &ctx, &mut headers);
    ferrum_edge::_test_support::run_request_body_stage_with_context_for_test(
        plugins, &mut ctx, &headers, &raw,
    )
    .await
}

/// Same shape, but the later plugin DELETES the observability key instead.
async fn dropped_meta_body_stage(
    plugins: &[Arc<dyn Plugin>],
    model: &str,
) -> (Vec<u8>, PluginResult) {
    let body = streaming_request(model);
    let raw = serde_json::to_vec(&body).unwrap();
    let mut ctx = post_ctx(&body);
    let mut headers = json_headers();
    assert!(matches!(
        run_before_proxy_chain(plugins, &mut ctx, &mut headers).await,
        PluginResult::Continue
    ));
    ctx.metadata.remove(MODEL_META_KEY);
    final_header_policy(plugins, &ctx, &mut headers);
    ferrum_edge::_test_support::run_request_body_stage_with_context_for_test(
        plugins, &mut ctx, &headers, &raw,
    )
    .await
}

fn safe_body_rule() -> Value {
    json!([
        {"operation": "add", "target": "body", "key": "user", "value": "tenant-a"}
    ])
}

fn model_overwrite_rule(value: &str) -> Value {
    json!([
        {"operation": "update", "target": "body", "key": "model", "value": value}
    ])
}

#[tokio::test]
async fn final_body_ignores_a_metadata_only_model_rewrite() {
    // Only the observability key moves; the backend-visible body still carries
    // the committed model. Enforcement must not notice, because it never reads
    // that key.
    let plugins = router_then_transformer(safe_body_rule());
    let (body, result) = forged_meta_body_stage(&plugins, "gpt-4o", "gpt-4o-x").await;
    assert!(
        matches!(result, PluginResult::Continue),
        "a metadata-only rewrite must not change enforcement"
    );
    let parsed: Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(parsed["model"], json!("gpt-4o"));
    assert_eq!(parsed["user"], json!("tenant-a"));
}

#[tokio::test]
async fn final_body_rejects_a_model_swap_that_also_rewrites_the_metadata_key() {
    // The advisory boundary: a later plugin changes the provider-visible model
    // AND republishes `ai_stream_router.model` as the same new value. The two
    // agree, both match `gpt-*`, and the request must still fail closed because
    // neither is what selected the provider.
    let plugins = router_then_transformer(model_overwrite_rule("gpt-4o-x"));
    let (_body, result) = forged_meta_body_stage(&plugins, "gpt-4o", "gpt-4o-x").await;
    assert_eq!(
        reject_status(&result),
        Some(400),
        "a matched pair of forged body + forged metadata must fail closed"
    );
}

#[tokio::test]
async fn final_body_rejects_an_anthropic_model_swap_that_rewrites_the_metadata_key() {
    // The same attack against the translating provider, where the model is
    // additionally baked into the translated provider body.
    let plugins = router_then_transformer(model_overwrite_rule("claude-3-opus"));
    let (_body, result) =
        forged_meta_body_stage(&plugins, "claude-3-5-sonnet", "claude-3-opus").await;
    assert_eq!(reject_status(&result), Some(400));
}

#[tokio::test]
async fn a_dropped_model_metadata_key_is_neither_fail_open_nor_fail_broken() {
    // Deleting the observability key must not open a hole...
    let plugins = router_then_transformer(model_overwrite_rule("gpt-4o-x"));
    let (_body, result) = dropped_meta_body_stage(&plugins, "gpt-4o").await;
    assert_eq!(reject_status(&result), Some(400));

    // ...and must not break an ordinary safe request either: the committed model
    // lives in the claim, so the key's presence is irrelevant in both directions.
    let plugins = router_then_transformer(safe_body_rule());
    let (body, result) = dropped_meta_body_stage(&plugins, "gpt-4o").await;
    assert!(matches!(result, PluginResult::Continue));
    let parsed: Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(parsed["model"], json!("gpt-4o"));
}

#[tokio::test]
async fn final_body_revalidation_echoes_neither_the_committed_nor_the_final_model() {
    // Fixed cardinality in both directions: a rejection may leak neither the
    // routed generation (a tenant's own model choice) nor the attacker-supplied
    // value, which a transform could have relocated a secret into.
    let plugin = build(openai_and_anthropic_config());
    let body = streaming_request("gpt-4o-COMMITTEDMARK");
    let mut ctx = post_ctx(&body);
    let mut headers = json_headers();
    assert!(matches!(
        plugin.before_proxy(&mut ctx, &mut headers).await,
        PluginResult::Continue
    ));
    let result = plugin
        .on_final_request_body_with_context(
            &mut ctx,
            &headers,
            br#"{"model":"gpt-4o-FINALMARK","stream":true}"#,
        )
        .await;
    let rendered = match &result {
        PluginResult::Reject { body, .. } => body.clone(),
        other => panic!("expected a reject, got {other:?}"),
    };
    assert!(
        !rendered.contains("COMMITTEDMARK"),
        "the rejection envelope must not echo the committed model"
    );
    assert!(
        !rendered.contains("FINALMARK"),
        "the rejection envelope must not echo the final body model"
    );
    assert!(rendered.contains("model_policy_violation"));
}

#[tokio::test]
async fn the_private_claim_is_never_rendered_by_request_context_debug() {
    // `RequestContext` derives `Debug`; the claim's own opaque implementation is
    // what keeps the committed model, the committed query, and the ownership
    // token out of any diagnostic that formats a context.
    let plugin = build(openai_and_anthropic_config());
    let body = streaming_request("gpt-4o-DEBUGMARK");
    let mut ctx = post_ctx(&body);
    let mut headers = json_headers();
    assert!(matches!(
        plugin.before_proxy(&mut ctx, &mut headers).await,
        PluginResult::Continue
    ));
    // Drop the two OBSERVABILITY copies so the only remaining source of the
    // marker is the private claim.
    assert!(ctx.metadata.remove("request_body").is_some());
    assert!(ctx.metadata.remove(MODEL_META_KEY).is_some());

    let rendered = format!("{ctx:?}");
    assert!(
        rendered.contains("AiStreamRouterClaim(<redacted>)"),
        "the claim must format as an opaque placeholder: {rendered}"
    );
    assert!(
        !rendered.contains("DEBUGMARK"),
        "the committed model must not reach a formatted request context"
    );
}

// --- Claim-owned response normalization --------------------------------------

/// Claim a streaming Anthropic request, then let a later plugin overwrite the
/// public model metadata key before any response hook runs.
async fn forged_meta_anthropic_ctx(plugin: &AiStreamRouter) -> RequestContext {
    let body = json!({
        "model": "claude-3-5-sonnet",
        "stream": true,
        "messages": [{"role": "user", "content": "hi"}]
    });
    let mut ctx = post_ctx(&body);
    let mut headers = json_headers();
    assert!(matches!(
        plugin.before_proxy(&mut ctx, &mut headers).await,
        PluginResult::Continue
    ));
    ctx.metadata
        .insert(MODEL_META_KEY.to_string(), "forged-identity".to_string());
    ctx
}

#[tokio::test]
async fn streaming_normalizer_identity_comes_from_the_private_claim() {
    let plugin = build(openai_and_anthropic_config());
    let ctx = forged_meta_anthropic_ctx(&plugin).await;

    let mut inspector = plugin
        .response_stream_inspector(&ctx, 200, Some("text/event-stream"))
        .expect("the owning instance must still install its normalizer");
    let mut collected = Vec::new();
    let chunk = inspector.on_chunk(ANTHROPIC_SSE.as_bytes()).await;
    collected.extend_from_slice(&forwarded(chunk));
    collected.extend_from_slice(&forwarded(inspector.on_end().await));
    let out = String::from_utf8(collected).unwrap();

    assert!(
        out.contains("\"model\":\"claude-3-5-sonnet\""),
        "client-visible chunks must carry the committed model: {out}"
    );
    assert!(
        !out.contains("forged-identity"),
        "a metadata rewrite must not change the generation identity: {out}"
    );
}

#[tokio::test]
async fn buffered_normalizer_identity_comes_from_the_private_claim() {
    let plugin = build(openai_and_anthropic_config());
    let mut ctx = forged_meta_anthropic_ctx(&plugin).await;

    let buffered = plugin
        .normalize_response_body_with_context(
            &mut ctx,
            200,
            ANTHROPIC_SSE.as_bytes(),
            Some("text/event-stream"),
            &HashMap::new(),
        )
        .await
        .expect("the owning instance must still normalize the buffered stream");
    let out = String::from_utf8(buffered).unwrap();

    assert!(out.contains("\"model\":\"claude-3-5-sonnet\""), "{out}");
    assert!(!out.contains("forged-identity"), "{out}");
}

#[tokio::test]
async fn the_tool_use_guard_cannot_be_disarmed_through_metadata() {
    // `tool_choice: "none"` is committed at claim time, so deleting the mirrored
    // observability key cannot re-enable normalization of provider `tool_use`
    // into client-visible `tool_calls`.
    let plugin = build(openai_and_anthropic_config());
    let (mut ctx, _) = claim_and_translate_tool_choice_none(&plugin).await;
    ctx.metadata.remove("ai_stream_router.tool_choice_none");

    let mut inspector = plugin
        .response_stream_inspector(&ctx, 200, Some("text/event-stream"))
        .expect("inspector");
    let mut collected = Vec::new();
    let chunk = inspector.on_chunk(ANTHROPIC_TOOL_USE_SSE.as_bytes()).await;
    collected.extend_from_slice(&forwarded(chunk));
    let streamed = String::from_utf8(collected).unwrap();
    assert!(streamed.contains("upstream_error"), "{streamed}");
    assert!(!streamed.contains("tool_calls"), "{streamed}");

    let buffered = plugin
        .normalize_response_body_with_context(
            &mut ctx,
            200,
            ANTHROPIC_TOOL_USE_SSE.as_bytes(),
            Some("text/event-stream"),
            &HashMap::new(),
        )
        .await
        .expect("the buffered path must still fail closed");
    let buffered = String::from_utf8(buffered).unwrap();
    assert!(buffered.contains("upstream_error"), "{buffered}");
    assert!(!buffered.contains("tool_calls"), "{buffered}");
}

#[tokio::test]
async fn the_anthropic_translation_witness_cannot_be_forged_through_metadata() {
    // The final hook's translation gate is private claim state written by this
    // instance's own transform on the same context. Publishing the mirrored
    // metadata key without ever running the transform must not admit an
    // untranslated OpenAI body to the Anthropic provider.
    let plugin = build(openai_and_anthropic_config());
    let body = streaming_request("claude-3-5-sonnet");
    let raw = serde_json::to_vec(&body).unwrap();
    let mut ctx = post_ctx(&body);
    let mut headers = json_headers();
    assert!(matches!(
        plugin.before_proxy(&mut ctx, &mut headers).await,
        PluginResult::Continue
    ));
    ctx.metadata.insert(
        "ai_stream_router.request_translated".to_string(),
        "true".to_string(),
    );

    let result = plugin
        .on_final_request_body_with_context(&mut ctx, &headers, &raw)
        .await;
    assert_eq!(
        reject_status(&result),
        Some(400),
        "a forged translation marker must not admit an untranslated body"
    );
}

// --- Ownership still decides, now with the committed model -------------------

#[tokio::test]
async fn only_the_owner_enforces_and_normalizes_under_a_forged_model_key() {
    // Two same-named Anthropic instances with different endpoints and keys.
    // Ownership still picks exactly one enforcer/normalizer, and that one uses
    // ITS OWN committed model rather than the shared metadata key.
    let first = build(json!({
        "enabled": true,
        "providers": [{
            "name": "shared",
            "provider_type": "anthropic",
            "endpoint": "https://first.example.com/v1/messages",
            "api_key": "sk-first-secret",
            "model_patterns": ["claude-*"]
        }]
    }));
    let second = build(json!({
        "enabled": true,
        "providers": [{
            "name": "shared",
            "provider_type": "anthropic",
            "endpoint": "https://second.example.com/v1/messages",
            "api_key": "sk-second-secret",
            "model_patterns": ["claude-*"]
        }]
    }));

    let body = streaming_request("claude-3-5-sonnet");
    let raw = serde_json::to_vec(&body).unwrap();
    let mut ctx = post_ctx(&body);
    let mut headers = json_headers();
    for plugin in [&first, &second] {
        assert!(matches!(
            plugin.before_proxy(&mut ctx, &mut headers).await,
            PluginResult::Continue
        ));
    }
    ctx.metadata
        .insert(MODEL_META_KEY.to_string(), "forged-identity".to_string());

    assert!(
        second
            .response_stream_inspector(&ctx, 200, Some("text/event-stream"))
            .is_none(),
        "a losing instance must not install a second normalizer"
    );
    let mut inspector = first
        .response_stream_inspector(&ctx, 200, Some("text/event-stream"))
        .expect("the owning instance normalizes");
    let mut collected = Vec::new();
    let chunk = inspector.on_chunk(ANTHROPIC_SSE.as_bytes()).await;
    collected.extend_from_slice(&forwarded(chunk));
    collected.extend_from_slice(&forwarded(inspector.on_end().await));
    let out = String::from_utf8(collected).unwrap();
    assert!(out.contains("\"model\":\"claude-3-5-sonnet\""), "{out}");
    assert!(!out.contains("forged-identity"), "{out}");

    // The owner translates and accepts; the loser neither re-translates nor
    // revalidates against its own provider policy.
    let translated = first
        .transform_request_body_with_context(&mut ctx, &raw, Some("application/json"), &headers)
        .await
        .expect("the owner translates");
    assert!(
        second
            .transform_request_body_with_context(
                &mut ctx,
                &translated,
                Some("application/json"),
                &headers
            )
            .await
            .is_none(),
        "a losing instance must not re-translate an already-claimed body"
    );
    assert!(matches!(
        second
            .on_final_request_body_with_context(&mut ctx, &headers, &translated)
            .await,
        PluginResult::Continue
    ));
    assert!(matches!(
        first
            .on_final_request_body_with_context(&mut ctx, &headers, &translated)
            .await,
        PluginResult::Continue
    ));
}
