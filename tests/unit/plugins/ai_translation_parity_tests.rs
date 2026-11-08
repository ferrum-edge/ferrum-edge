//! Issue #7070: `ai_federation` (buffered) and `ai_stream_router` (streaming)
//! translate the same OpenAI request into Gemini and Anthropic shapes and must
//! give it the same accept/reject answer. Each table row runs through both
//! plugins' real admission + translation entry points and asserts the decided
//! outcome on both.

use ferrum_edge::plugins::ai_federation::test_helpers;
use ferrum_edge::plugins::ai_stream_router::AiStreamRouter;
use ferrum_edge::plugins::{Plugin, PluginHttpClient, PluginResult, RequestContext};
use serde_json::{Value, json};
use std::collections::HashMap;

fn json_headers() -> HashMap<String, String> {
    let mut headers = HashMap::new();
    headers.insert("content-type".to_string(), "application/json".to_string());
    headers
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

fn stream_router_config() -> Value {
    json!({
        "providers": [
            {
                "name": "anthropic",
                "provider_type": "anthropic",
                "endpoint": "https://api.anthropic.com/v1/messages",
                "api_key": "sk-ant-secret",
                "model_patterns": ["claude-*"],
                "priority": 1,
                "anthropic_version": "2023-06-01"
            },
            {
                "name": "gemini",
                "provider_type": "google_gemini",
                "endpoint": "https://generativelanguage.googleapis.com/v1beta/models/{model}:streamGenerateContent",
                "api_key": "sk-gemini-secret",
                "model_patterns": ["gemini-*"],
                "priority": 2
            }
        ]
    })
}

/// Whether `ai_stream_router` admits and translates `body` (streamed).
async fn stream_router_admits(body: &Value) -> bool {
    let mut body = body.clone();
    body["stream"] = json!(true);
    let plugin = AiStreamRouter::new(&stream_router_config(), PluginHttpClient::default())
        .expect("stream router config is valid");
    let mut ctx = post_ctx(&body);
    let mut headers = json_headers();
    if !matches!(
        plugin.before_proxy(&mut ctx, &mut headers).await,
        PluginResult::Continue
    ) {
        return false;
    }
    let raw = serde_json::to_vec(&body).unwrap();
    plugin
        .transform_request_body_with_context(&mut ctx, &raw, Some("application/json"), &headers)
        .await
        .is_some()
}

/// Whether `ai_federation` admits and translates `body` for `provider_type`.
fn federation_admits(provider_type: &str, body: &Value) -> Result<(), String> {
    test_helpers::validate_openai_request_test(body)?;
    let model = body["model"].as_str().unwrap_or_default();
    test_helpers::translate_request_test(provider_type, body, model, &json!({})).map(|_| ())
}

async fn assert_both(provider_type: &str, label: &str, body: Value, admitted: bool) {
    let federation = federation_admits(provider_type, &body);
    assert_eq!(
        federation.is_ok(),
        admitted,
        "ai_federation {provider_type} `{label}`: {federation:?}"
    );
    assert_eq!(
        stream_router_admits(&body).await,
        admitted,
        "ai_stream_router {provider_type} `{label}`"
    );
}

fn strict_schema_request(schema: Value) -> Value {
    json!({
        "model": "gemini-2.0-flash",
        "messages": [{"role": "user", "content": "Classify it"}],
        "response_format": {
            "type": "json_schema",
            "json_schema": {"name": "result", "strict": true, "schema": schema}
        }
    })
}

#[tokio::test]
async fn gemini_strict_schema_rules_match_on_both_route_kinds() {
    let cases: [(&str, Value, bool); 11] = [
        (
            "representable with refs",
            json!({
                "type": "object",
                "$defs": {"item": {"type": "string", "enum": ["a", "b"]}},
                "properties": {
                    "when": {"type": "string", "format": "date-time"},
                    "items": {"type": "array", "items": {"$ref": "#/$defs/item"}}
                },
                "required": ["when"],
                "additionalProperties": false
            }),
            true,
        ),
        (
            "root $ref beside its $defs",
            json!({
                "$ref": "#/$defs/root",
                "$defs": {"root": {"type": "object", "properties": {"ok": {"type": "boolean"}}}}
            }),
            true,
        ),
        (
            "dangling #/$defs reference",
            json!({"type": "object", "properties": {"x": {"$ref": "#/$defs/missing"}}}),
            false,
        ),
        (
            "non-$defs local pointer",
            json!({"type": "object", "properties": {"x": {"$ref": "#/properties/y"}}}),
            false,
        ),
        (
            "remote reference",
            json!({"$ref": "https://schemas.example.invalid/remote.json"}),
            false,
        ),
        (
            "$ref cycle",
            json!({
                "$ref": "#/$defs/a",
                "$defs": {
                    "a": {"type": "object", "properties": {"b": {"$ref": "#/$defs/b"}}},
                    "b": {"type": "array", "items": {"$ref": "#/$defs/a"}}
                }
            }),
            false,
        ),
        (
            "self reference to the root",
            json!({"type": "object", "properties": {"child": {"$ref": "#"}}}),
            false,
        ),
        (
            "nested $defs",
            json!({
                "type": "object",
                "properties": {"x": {"type": "object", "$defs": {"y": {"type": "string"}}}}
            }),
            false,
        ),
        (
            "$ref with a description sibling",
            json!({
                "type": "array",
                "items": {"$ref": "#/$defs/item", "description": "x"},
                "$defs": {"item": {"type": "string"}}
            }),
            false,
        ),
        (
            "$ref with a constraint sibling",
            json!({
                "type": "object",
                "properties": {"score": {"$ref": "#/$defs/score", "maximum": 1}},
                "$defs": {"score": {"type": "number"}}
            }),
            false,
        ),
        (
            "unenforced keyword inside $defs",
            json!({"$ref": "#/$defs/r", "$defs": {"r": {"type": "string", "minLength": 3}}}),
            false,
        ),
    ];
    for (label, schema, admitted) in cases {
        assert_both(
            "google_gemini",
            label,
            strict_schema_request(schema),
            admitted,
        )
        .await;
    }
}

fn weather_tools() -> Value {
    json!([{
        "type": "function",
        "function": {
            "name": "get_weather",
            "parameters": {"type": "object", "properties": {"city": {"type": "string"}}}
        }
    }])
}

fn tool_round(call_id: &str, result_id: &str) -> Value {
    json!({
        "model": "claude-sonnet-4-20250514",
        "max_tokens": 256,
        "tools": weather_tools(),
        "messages": [
            {"role": "user", "content": "Weather in Paris?"},
            {
                "role": "assistant",
                "content": null,
                "tool_calls": [{
                    "id": call_id,
                    "type": "function",
                    "function": {"name": "get_weather", "arguments": "{\"city\":\"Paris\"}"}
                }]
            },
            {"role": "tool", "tool_call_id": result_id, "content": "sunny"}
        ]
    })
}

#[tokio::test]
async fn tool_call_rules_match_on_both_route_kinds() {
    let max_id = "c".repeat(128);
    let over_id = "c".repeat(129);
    let cases: [(&str, Value, bool); 6] = [
        ("128-byte tool-call id", tool_round(&max_id, &max_id), true),
        (
            "129-byte tool-call id",
            tool_round(&over_id, &over_id),
            false,
        ),
        (
            "empty tool_call_id on the result",
            tool_round("call_1", ""),
            false,
        ),
        (
            "assistant `tool_calls: null`",
            json!({
                "model": "claude-sonnet-4-20250514",
                "max_tokens": 256,
                "messages": [
                    {"role": "user", "content": "Hello"},
                    {"role": "assistant", "content": "Hi there", "tool_calls": null},
                    {"role": "user", "content": "How are you?"}
                ]
            }),
            true,
        ),
        (
            "user `tool_calls: null`",
            json!({
                "model": "claude-sonnet-4-20250514",
                "max_tokens": 256,
                "messages": [{"role": "user", "content": "Hello", "tool_calls": null}]
            }),
            true,
        ),
        (
            "assistant `tool_calls: []`",
            json!({
                "model": "claude-sonnet-4-20250514",
                "max_tokens": 256,
                "messages": [
                    {"role": "user", "content": "Hello"},
                    {"role": "assistant", "content": "Hi there", "tool_calls": []},
                    {"role": "user", "content": "How are you?"}
                ]
            }),
            false,
        ),
    ];
    for (label, body, admitted) in cases {
        assert_both("anthropic", label, body, admitted).await;
    }
}
