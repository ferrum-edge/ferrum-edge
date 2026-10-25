//! Tests for ai_token_metrics plugin

use base64::Engine;
use ferrum_edge::plugins::{
    Plugin, PluginResult, ProxyProtocol, RequestContext, ResponseStreamAction,
    ai_response_guard::AiResponseGuard,
    ai_token_metrics::AiTokenMetrics,
    create_response_stream_inspector,
    prometheus_metrics::MetricsRegistry,
    utils::ai_providers::{AiProvider, parse_ai_provider},
    utils::content_encoding::{DecodeLimits, decode_content_encoding},
    validate_plugin_config,
};
use ferrum_edge::proxy::deferred_log::BodyOutcome;
use serde_json::json;
use std::borrow::Cow;
use std::collections::HashMap;
use std::io::Write;
use std::sync::Arc;

use super::plugin_utils::{create_test_context, create_test_transaction_summary};

// Marker set by the proxy on `ctx.metadata` while the response-body hooks run
// over a synthetic 2xx plugin short-circuit body (mirrors
// `crate::proxy::SYNTHETIC_SHORT_CIRCUIT_METADATA_KEY`, which is `pub(crate)` and
// therefore not reachable from this external test crate).
const SYNTHETIC_SHORT_CIRCUIT_METADATA_KEY: &str = "ferrum:synthetic_short_circuit";

fn json_headers() -> HashMap<String, String> {
    let mut h = HashMap::new();
    h.insert("content-type".to_string(), "application/json".to_string());
    h
}

fn gzip(body: &[u8]) -> Vec<u8> {
    let mut encoder = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::fast());
    encoder.write_all(body).unwrap();
    encoder.finish().unwrap()
}

fn brotli(body: &[u8]) -> Vec<u8> {
    let mut encoded = Vec::new();
    let mut input = body;
    brotli::BrotliCompress(
        &mut input,
        &mut encoded,
        &brotli::enc::BrotliEncoderParams::default(),
    )
    .unwrap();
    encoded
}

#[test]
fn content_decoding_borrows_when_no_transform_is_required() {
    let body = b"plain provider response";
    let limits = DecodeLimits {
        max_decoded_bytes: 4 * 1024 * 1024,
        max_cumulative_bytes: 8 * 1024 * 1024,
        max_codings: 4,
        max_amplification_ratio: 0,
    };
    for header in [None, Some("identity")] {
        let decoded = decode_content_encoding(header, body, limits).unwrap();
        assert_eq!(decoded.as_ptr(), body.as_ptr());
        assert!(matches!(decoded, Cow::Borrowed(_)));
    }
}

fn ctx_with_content_type(method: &str, content_type: &str) -> RequestContext {
    let mut ctx = RequestContext::new(
        "127.0.0.1".to_string(),
        method.to_string(),
        "/chat".to_string(),
    );
    ctx.headers
        .insert("content-type".to_string(), content_type.to_string());
    ctx
}

fn ctx_without_content_type(method: &str) -> RequestContext {
    RequestContext::new(
        "127.0.0.1".to_string(),
        method.to_string(),
        "/chat".to_string(),
    )
}

fn assert_continue(result: PluginResult) {
    assert!(
        matches!(result, PluginResult::Continue),
        "Expected Continue, got {:?}",
        result
    );
}

fn assert_usage_and_metrics(
    ctx: &RequestContext,
    provider: &str,
    prompt: Option<u64>,
    completion: u64,
    total: Option<u64>,
    cost: &str,
) {
    assert_eq!(ctx.metadata["ai_provider"], provider);
    let export = ctx.authoritative_ai_usage_export().unwrap();
    assert_eq!(export.provider, provider);
    assert_eq!(export.prompt_tokens, prompt);
    assert_eq!(export.completion_tokens, Some(completion));
    assert_eq!(export.total_tokens, total);

    let mut summary = create_test_transaction_summary();
    summary.ai_usage_export = Some(export);
    let registry = MetricsRegistry::new();
    registry.configure(0, 3600, 0, 10_000, "");
    registry.record(&summary);
    let output = registry.render_uncached();
    // Configuring even an empty namespace emits its label on every AI series.
    let labels = format!("proxy_id=\"test-proxy\",provider=\"{provider}\",namespace=\"\"");
    for (metadata_key, metric, value) in [
        ("ai_prompt_tokens", "ferrum_ai_prompt_tokens_total", prompt),
        (
            "ai_completion_tokens",
            "ferrum_ai_completion_tokens_total",
            Some(completion),
        ),
        ("ai_total_tokens", "ferrum_ai_tokens_total", total),
    ] {
        let series = format!("{metric}{{{labels}}}");
        if let Some(value) = value {
            assert_eq!(ctx.metadata[metadata_key], value.to_string());
            assert!(
                output.contains(&format!("{series} {value}\n")),
                "missing {series} {value} in:\n{output}"
            );
        } else {
            assert!(!ctx.metadata.contains_key(metadata_key));
            assert!(!output.contains(&series));
        }
    }
    assert_eq!(ctx.metadata["ai_estimated_cost"], cost);
    assert!(output.contains(&format!(
        "ferrum_ai_estimated_cost_currency_units_total{{{labels}}} {cost}\n"
    )));
}

fn token_metrics_schema() -> serde_json::Value {
    let spec: serde_json::Value =
        serde_yaml::from_str(include_str!("../../../openapi.yaml")).unwrap();
    spec["components"]["schemas"]["AiTokenMetricsConfig"].clone()
}

#[test]
fn optional_cost_rate_admission_matches_openapi() {
    let schema = token_metrics_schema();
    let validator = jsonschema::draft202012::options().build(&schema).unwrap();
    assert!(validator.is_valid(&json!({})));
    assert!(AiTokenMetrics::new(&json!({})).is_ok());
    for field in ["cost_per_prompt_token", "cost_per_completion_token"] {
        for (value, accepted) in [
            (json!(null), true),
            (json!(0), true),
            (json!(18_446_744_073_709.55), true),
            (json!(-1), false),
            (json!(18_446_744_073_710.0), false),
            (json!("free"), false),
            (json!(true), false),
            (json!([]), false),
            (json!({}), false),
        ] {
            let config = json!({field: value});
            assert_eq!(AiTokenMetrics::new(&config).is_ok(), accepted);
            assert_eq!(validator.is_valid(&config), accepted, "{config}");
        }
    }
}

#[tokio::test]
async fn buffered_sse_event_framing_preserves_usage_and_prometheus_values() {
    let plugin = AiTokenMetrics::new(&json!({
        "buffer_streaming_responses": true,
        "cost_per_prompt_token": 0.000001,
        "cost_per_completion_token": 0.000002
    }))
    .unwrap();
    let single = concat!(
        "data: {\"object\":\"chat.completion\",\"model\":\"framing-model\",",
        "\"usage\":{\"prompt_tokens\":11,\"completion_tokens\":7,\"total_tokens\":18}}\n\n"
    );
    let multiline = concat!(
        ": keepalive\n",
        "event: message\n",
        "id: usage-1\n",
        "data: {\"object\":\"chat.completion\",\"model\":\"framing-model\",\n",
        "data\n",
        "data:\"usage\":{\"prompt_tokens\":11,\"completion_tokens\":7,\"total_tokens\":18}}\n\n"
    );
    for ending in ["\n", "\r\n", "\r"] {
        for event in [single, multiline] {
            // Repeated cumulative usage must replace, not add. An invalid
            // event must not leak data into the next event's JSON document.
            let body = format!("\u{feff}data: invalid\n\n{event}{event}data: [DONE]\n\n")
                .replace('\n', ending);
            let mut ctx = create_test_context();
            let mut headers =
                HashMap::from([("content-type".to_string(), "text/event-stream".to_string())]);
            let original_headers = headers.clone();
            assert_continue(
                plugin
                    .on_response_body(&mut ctx, 200, &mut headers, body.as_bytes())
                    .await,
            );
            assert_eq!(headers, original_headers);
            assert_eq!(ctx.metadata["ai_model"], "framing-model");
            assert_eq!(ctx.metadata["ai_streaming"], "true");
            assert_usage_and_metrics(&ctx, "openai", Some(11), 7, Some(18), "0.000025");
        }
    }
}

#[tokio::test]
async fn buffered_sse_does_not_parse_data_fields_as_independent_events() {
    let plugin = AiTokenMetrics::new(&json!({"buffer_streaming_responses": true})).unwrap();
    let usage = r#"{"usage":{"prompt_tokens":11,"completion_tokens":7}}"#;
    let body = format!("data: {usage}\ndata: {usage}\n\n");
    let mut ctx = create_test_context();
    let mut headers =
        HashMap::from([("content-type".to_string(), "text/event-stream".to_string())]);
    assert_continue(
        plugin
            .on_response_body(&mut ctx, 200, &mut headers, body.as_bytes())
            .await,
    );
    assert!(ctx.authoritative_ai_usage_export().is_none());
    assert!(!ctx.metadata.contains_key("ai_total_tokens"));
}

/// ai_token_metrics-claude-2: a final usage event whose terminating blank line
/// (or newline) is missing is dispatched at end of body, exactly as the shared
/// streaming extractor does, and stacked leading BOMs are stripped.
#[tokio::test]
async fn buffered_sse_dispatches_an_unterminated_final_event_and_strips_stacked_boms() {
    let plugin = AiTokenMetrics::new(&json!({
        "buffer_streaming_responses": true,
        "cost_per_prompt_token": 0.000001,
        "cost_per_completion_token": 0.000002
    }))
    .unwrap();
    let usage = r#"{"usage":{"prompt_tokens":11,"completion_tokens":7,"total_tokens":18}}"#;
    for body in [
        format!("data: {usage}\n"),
        format!("data: {usage}"),
        format!("data: {usage}\r"),
        format!("data: [DONE]\n\ndata: {usage}\r\n"),
        format!("\u{feff}\u{feff}data: {usage}\n\n"),
    ] {
        let mut ctx = create_test_context();
        let mut headers =
            HashMap::from([("content-type".to_string(), "text/event-stream".to_string())]);
        assert_continue(
            plugin
                .on_response_body(&mut ctx, 200, &mut headers, body.as_bytes())
                .await,
        );
        assert_eq!(ctx.metadata["ai_streaming"], "true", "{body:?}");
        assert_usage_and_metrics(&ctx, "openai", Some(11), 7, Some(18), "0.000025");
    }
}

#[tokio::test]
async fn every_admitted_provider_exports_usage_to_prometheus() {
    let schema = token_metrics_schema();
    for value in schema["properties"]["provider"]["enum"].as_array().unwrap() {
        let name = value.as_str().unwrap();
        if name == "auto" {
            continue;
        }
        let provider = parse_ai_provider(name).unwrap();
        assert_eq!(provider.as_str(), name);
        // Exhaustive match also makes an enum addition require an export
        // fixture, even if its schema entry has not been added yet.
        let body = match provider {
            AiProvider::OpenAi | AiProvider::Mistral => {
                json!({"usage": {"prompt_tokens": 11, "completion_tokens": 7}})
            }
            AiProvider::Anthropic => json!({"usage": {"input_tokens": 11, "output_tokens": 7}}),
            AiProvider::Google => {
                json!({"usageMetadata": {"promptTokenCount": 11, "candidatesTokenCount": 7}})
            }
            AiProvider::Cohere => {
                json!({"usage": {"tokens": {"input_tokens": 11, "output_tokens": 7}}})
            }
            AiProvider::Bedrock => json!({"usage": {"inputTokens": 11, "outputTokens": 7}}),
            AiProvider::Tgi => {
                json!({"details": {"generated_tokens": 7, "prefill": vec![json!({"id": 0}); 11]}})
            }
        };
        let plugin = AiTokenMetrics::new(&json!({
            "provider": name,
            "cost_per_prompt_token": 0.000001,
            "cost_per_completion_token": 0.000002
        }))
        .unwrap();
        let mut ctx = create_test_context();
        let mut headers = json_headers();
        assert_continue(
            plugin
                .on_response_body(
                    &mut ctx,
                    200,
                    &mut headers,
                    &serde_json::to_vec(&body).unwrap(),
                )
                .await,
        );
        assert_usage_and_metrics(&ctx, name, Some(11), 7, Some(18), "0.000025");
    }
}

#[tokio::test]
async fn tgi_json_and_terminal_sse_keep_completion_only_usage_partial() {
    for provider in ["auto", "tgi"] {
        let plugin = AiTokenMetrics::new(&json!({
            "provider": provider,
            "buffer_streaming_responses": true,
            "cost_per_prompt_token": 0.000001,
            "cost_per_completion_token": 0.000002
        }))
        .unwrap();
        for with_prompt in [false, true] {
            let mut body = json!({"generated_text": "ok", "details": {"generated_tokens": 7}});
            if with_prompt {
                body["details"]["prefill"] = json!(vec![json!({"id": 0}); 11]);
            }
            for streaming in [false, true] {
                let (content_type, body) = if streaming {
                    ("text/event-stream", format!("data: {body}\n\n"))
                } else {
                    ("application/json", body.to_string())
                };
                let mut ctx = create_test_context();
                let mut headers =
                    HashMap::from([("content-type".to_string(), content_type.to_string())]);
                assert_continue(
                    plugin
                        .on_response_body(&mut ctx, 200, &mut headers, body.as_bytes())
                        .await,
                );
                assert_usage_and_metrics(
                    &ctx,
                    "tgi",
                    with_prompt.then_some(11),
                    7,
                    with_prompt.then_some(18),
                    if with_prompt { "0.000025" } else { "0.000014" },
                );
            }
        }
    }
}

// ─── Plugin basics ──────────────────────────────────────────────────────

#[tokio::test]
async fn test_plugin_name_and_priority() {
    let plugin = AiTokenMetrics::new(&json!({})).unwrap();
    assert_eq!(plugin.name(), "ai_token_metrics");
    assert_eq!(plugin.priority(), 4070);
    assert_eq!(plugin.supported_protocols(), &[ProxyProtocol::Http]);
    assert!(plugin.requires_response_body_buffering());
    assert!(plugin.requires_response_stream_hooks());
    assert!(plugin.should_buffer_response_body(&ctx_with_content_type("POST", "application/json")));
    assert!(plugin.should_buffer_response_body(&ctx_with_content_type(
        "POST",
        "multipart/form-data; boundary=abc"
    )));
    assert!(plugin.should_buffer_response_body(&ctx_with_content_type("POST", "text/plain")));
    assert!(plugin.should_buffer_response_body(&ctx_without_content_type("POST")));
    // Spec change (PR #956 / commit 55a59396): token-metrics buffering is
    // no longer POST-only; otherwise non-POST AI responses skip token
    // accounting entirely.
    assert!(plugin.should_buffer_response_body(&ctx_with_content_type("GET", "application/json")));
}

#[test]
fn test_response_buffering_is_narrowed_by_response_content_type() {
    let plugin = AiTokenMetrics::new(&json!({})).unwrap();
    let ctx = ctx_with_content_type("GET", "application/json");

    assert!(plugin.should_buffer_response_body(&ctx));
    assert!(plugin.should_buffer_response_body_for_content_type(
        &ctx,
        Some("application/json; charset=utf-8"),
        200,
        &HashMap::new()
    ));
    assert!(!plugin.should_buffer_response_body_for_content_type(
        &ctx,
        Some("text/plain"),
        200,
        &HashMap::new()
    ));
    assert!(!plugin.should_buffer_response_body_for_content_type(
        &ctx,
        Some("text/event-stream"),
        200,
        &HashMap::new()
    ));
    assert!(!plugin.should_buffer_response_body_for_content_type(&ctx, None, 200, &HashMap::new()));
}

/// ai_token_metrics-claude-3: `on_response_body` never inspects a non-2xx
/// body, so the content-type refinement must release it instead of collecting
/// an error body only to discard it.
#[test]
fn non_2xx_responses_are_never_collected_for_inspection() {
    for config in [json!({}), json!({"buffer_streaming_responses": true})] {
        let plugin = AiTokenMetrics::new(&config).unwrap();
        let ctx = ctx_with_content_type("POST", "application/json");
        for content_type in ["application/json", "text/event-stream"] {
            for status in [199, 300, 404, 429, 500, 503] {
                assert!(
                    !plugin.should_buffer_response_body_for_content_type(
                        &ctx,
                        Some(content_type),
                        status,
                        &HashMap::new()
                    ),
                    "{config} {content_type} {status}"
                );
            }
        }
        for status in [200, 201, 299] {
            assert!(plugin.should_buffer_response_body_for_content_type(
                &ctx,
                Some("application/json"),
                status,
                &json_headers()
            ));
        }
    }
}

#[test]
fn test_streaming_response_buffering_requires_explicit_opt_in() {
    let default_plugin = AiTokenMetrics::new(&json!({})).unwrap();
    let opt_in_plugin = AiTokenMetrics::new(&json!({"buffer_streaming_responses": true})).unwrap();
    let ctx = ctx_with_content_type("POST", "application/json");

    assert!(
        !default_plugin.should_buffer_response_body_for_content_type(
            &ctx,
            Some("text/event-stream"),
            200,
            &HashMap::new()
        )
    );
    assert!(opt_in_plugin.should_buffer_response_body_for_content_type(
        &ctx,
        Some("text/event-stream"),
        200,
        &HashMap::new()
    ));
}

#[test]
fn retry_release_requires_origin_sse_and_no_buffering_opt_in() {
    for opt_in in [false, true] {
        let plugin = AiTokenMetrics::new(&json!({"buffer_streaming_responses": opt_in})).unwrap();
        let ctx = ctx_with_content_type("POST", "application/json");
        assert!(plugin.should_buffer_response_body(&ctx));
        assert_eq!(
            plugin.may_release_response_body_under_retries(&ctx),
            !opt_in
        );
        for (content_type, is_sse) in [
            ("text/event-stream", true),
            ("Text/Event-Stream; charset=utf-8", true),
            // This observer conservatively preserves streaming for variants,
            // using the same classification with and without retries (#5333).
            ("application/event-stream+json", true),
            ("application/vnd.acme-event-stream", true),
            ("application/json", false),
            ("text/plain", false),
        ] {
            let headers = HashMap::from([("Content-Type".to_string(), content_type.to_string())]);
            assert_eq!(
                plugin.should_release_response_body_under_retries(&ctx, 200, &headers),
                !opt_in && is_sse,
                "{content_type}, opt_in={opt_in}"
            );
            if is_sse {
                assert_eq!(
                    plugin.should_buffer_response_body_for_content_type(
                        &ctx,
                        Some(content_type),
                        200,
                        &headers,
                    ),
                    opt_in,
                    "{content_type}, opt_in={opt_in}"
                );
            }
        }
        assert!(!plugin.should_release_response_body_under_retries(&ctx, 200, &HashMap::new()));
        assert!(plugin.should_buffer_response_body_for_content_type(
            &ctx,
            Some("application/json"),
            200,
            &json_headers()
        ));
    }
}

// The pre-header `should_buffer_response_body` decision drives every backend
// dispatch path. These tests pin the request-shape gating that avoids buffering
// before origin headers and the retry-release refinement are available.

#[test]
fn test_pre_header_decision_streams_sse_accept_requests() {
    let default_plugin = AiTokenMetrics::new(&json!({})).unwrap();
    let opt_in_plugin = AiTokenMetrics::new(&json!({"buffer_streaming_responses": true})).unwrap();

    let mut ctx = ctx_with_content_type("POST", "application/json");
    ctx.headers
        .insert("accept".to_string(), "text/event-stream".to_string());

    // A client asking for a stream must not be buffered by default, even on the
    // retry / H3-backend paths before the content-type refinement.
    assert!(!default_plugin.should_buffer_response_body(&ctx));
    // Opt-in restores buffering for operators who want streamed token metrics.
    assert!(opt_in_plugin.should_buffer_response_body(&ctx));
}

#[test]
fn test_pre_header_decision_streams_request_streaming_marker() {
    let default_plugin = AiTokenMetrics::new(&json!({})).unwrap();
    let opt_in_plugin = AiTokenMetrics::new(&json!({"buffer_streaming_responses": true})).unwrap();

    let mut ctx = ctx_with_content_type("POST", "application/json");
    ctx.metadata
        .insert("ai_request_streaming".to_string(), "true".to_string());

    // A `stream: true` request flagged by an earlier AI plugin must not be
    // buffered by default.
    assert!(!default_plugin.should_buffer_response_body(&ctx));
    assert!(opt_in_plugin.should_buffer_response_body(&ctx));
}

#[test]
fn test_native_grpc_is_explicitly_unsupported() {
    let plugin = AiTokenMetrics::new(&json!({})).unwrap();
    assert_eq!(plugin.supported_protocols(), &[ProxyProtocol::Http]);
    assert!(!plugin.supported_protocols().contains(&ProxyProtocol::Grpc));
}

#[test]
fn test_pre_header_decision_buffers_plain_json_requests() {
    let plugin = AiTokenMetrics::new(&json!({})).unwrap();

    // A normal (non-streaming, non-gRPC) request keeps buffering so JSON token
    // accounting still works on every dispatch path.
    assert!(plugin.should_buffer_response_body(&ctx_with_content_type("POST", "application/json")));
    assert!(plugin.should_buffer_response_body(&ctx_with_content_type("GET", "application/json")));
    assert!(plugin.should_buffer_response_body(&ctx_without_content_type("POST")));
}

// ─── OpenAI format ──────────────────────────────────────────────────────

#[tokio::test]
async fn test_openai_format() {
    let plugin = AiTokenMetrics::new(&json!({})).unwrap();
    let mut ctx = create_test_context();
    let mut headers = json_headers();
    let body = serde_json::to_vec(&json!({
        "model": "gpt-4o",
        "usage": {
            "prompt_tokens": 100,
            "completion_tokens": 50,
            "total_tokens": 150
        }
    }))
    .unwrap();

    let result = plugin
        .on_response_body(&mut ctx, 200, &mut headers, &body)
        .await;
    assert_continue(result);

    assert_eq!(ctx.metadata.get("ai_provider").unwrap(), "openai");
    assert_eq!(ctx.metadata.get("ai_total_tokens").unwrap(), "150");
    assert_eq!(ctx.metadata.get("ai_prompt_tokens").unwrap(), "100");
    assert_eq!(ctx.metadata.get("ai_completion_tokens").unwrap(), "50");
    assert_eq!(ctx.metadata.get("ai_model").unwrap(), "gpt-4o");
}

// ─── Anthropic format ───────────────────────────────────────────────────

#[tokio::test]
async fn test_anthropic_format() {
    let plugin = AiTokenMetrics::new(&json!({})).unwrap();
    let mut ctx = create_test_context();
    let mut headers = json_headers();
    let body = serde_json::to_vec(&json!({
        "model": "claude-sonnet-4-20250514",
        "usage": {
            "input_tokens": 200,
            "output_tokens": 80
        }
    }))
    .unwrap();

    let result = plugin
        .on_response_body(&mut ctx, 200, &mut headers, &body)
        .await;
    assert_continue(result);

    assert_eq!(ctx.metadata.get("ai_provider").unwrap(), "anthropic");
    assert_eq!(ctx.metadata.get("ai_total_tokens").unwrap(), "280");
    assert_eq!(ctx.metadata.get("ai_prompt_tokens").unwrap(), "200");
    assert_eq!(ctx.metadata.get("ai_completion_tokens").unwrap(), "80");
    assert_eq!(
        ctx.metadata.get("ai_model").unwrap(),
        "claude-sonnet-4-20250514"
    );
}

// ─── Google Gemini format ───────────────────────────────────────────────

#[tokio::test]
async fn test_google_format() {
    let plugin = AiTokenMetrics::new(&json!({})).unwrap();
    let mut ctx = create_test_context();
    let mut headers = json_headers();
    let body = serde_json::to_vec(&json!({
        "modelVersion": "gemini-1.5-pro",
        "usageMetadata": {
            "promptTokenCount": 300,
            "candidatesTokenCount": 120,
            "totalTokenCount": 420
        }
    }))
    .unwrap();

    let result = plugin
        .on_response_body(&mut ctx, 200, &mut headers, &body)
        .await;
    assert_continue(result);

    assert_eq!(ctx.metadata.get("ai_provider").unwrap(), "google");
    assert_eq!(ctx.metadata.get("ai_total_tokens").unwrap(), "420");
    assert_eq!(ctx.metadata.get("ai_prompt_tokens").unwrap(), "300");
    assert_eq!(ctx.metadata.get("ai_completion_tokens").unwrap(), "120");
    assert_eq!(ctx.metadata.get("ai_model").unwrap(), "gemini-1.5-pro");
}

// ─── Cohere format ──────────────────────────────────────────────────────

#[tokio::test]
async fn test_cohere_format() {
    let plugin = AiTokenMetrics::new(&json!({})).unwrap();
    let mut ctx = create_test_context();
    let mut headers = json_headers();
    let body = serde_json::to_vec(&json!({
        "model": "command-r-plus",
        "meta": {
            "tokens": {
                "input_tokens": 50,
                "output_tokens": 30
            }
        }
    }))
    .unwrap();

    let result = plugin
        .on_response_body(&mut ctx, 200, &mut headers, &body)
        .await;
    assert_continue(result);

    assert_eq!(ctx.metadata.get("ai_provider").unwrap(), "cohere");
    assert_eq!(ctx.metadata.get("ai_total_tokens").unwrap(), "80");
    assert_eq!(ctx.metadata.get("ai_prompt_tokens").unwrap(), "50");
    assert_eq!(ctx.metadata.get("ai_completion_tokens").unwrap(), "30");
    assert_eq!(ctx.metadata.get("ai_model").unwrap(), "command-r-plus");
}

#[tokio::test]
async fn test_cohere_v2_buffered_format() {
    // Cohere v2 `/v2/chat` puts counts at `usage.tokens.*` (the v1 layout
    // was `meta.tokens.*`). Auto-detection must distinguish v2 from
    // OpenAI / Bedrock which also key off `usage.*`.
    let plugin = AiTokenMetrics::new(&json!({})).unwrap();
    let mut ctx = create_test_context();
    let mut headers = json_headers();
    let body = serde_json::to_vec(&json!({
        "id": "abc-123",
        "finish_reason": "COMPLETE",
        "usage": {
            "tokens": {
                "input_tokens": 17,
                "output_tokens": 9
            }
        }
    }))
    .unwrap();

    plugin
        .on_response_body(&mut ctx, 200, &mut headers, &body)
        .await;

    assert_eq!(ctx.metadata.get("ai_provider").unwrap(), "cohere");
    assert_eq!(ctx.metadata.get("ai_total_tokens").unwrap(), "26");
    assert_eq!(ctx.metadata.get("ai_prompt_tokens").unwrap(), "17");
    assert_eq!(ctx.metadata.get("ai_completion_tokens").unwrap(), "9");
}

#[tokio::test]
async fn test_cohere_v2_streaming_format() {
    // Cohere v2 SSE: the terminal `message-end` event carries counts under
    // `delta.usage.tokens.*`. The previous SSE detector classified all
    // `message*` events as Anthropic and dropped these.
    let plugin = AiTokenMetrics::new(&json!({"buffer_streaming_responses": true})).unwrap();
    let mut ctx = create_test_context();
    let mut headers = HashMap::new();
    headers.insert("content-type".to_string(), "text/event-stream".to_string());

    let sse = concat!(
        "data: {\"type\":\"message-start\",\"id\":\"abc\"}\n\n",
        "data: {\"type\":\"content-delta\",\"delta\":{\"message\":{\"content\":{\"text\":\"hi\"}}}}\n\n",
        "data: {\"type\":\"message-end\",\"delta\":{\"finish_reason\":\"COMPLETE\",\"usage\":{\"tokens\":{\"input_tokens\":23,\"output_tokens\":41}}}}\n\n",
    )
    .as_bytes();

    plugin
        .on_response_body(&mut ctx, 200, &mut headers, sse)
        .await;

    assert_eq!(ctx.metadata.get("ai_provider").unwrap(), "cohere");
    assert_eq!(ctx.metadata.get("ai_total_tokens").unwrap(), "64");
    assert_eq!(ctx.metadata.get("ai_prompt_tokens").unwrap(), "23");
    assert_eq!(ctx.metadata.get("ai_completion_tokens").unwrap(), "41");
}

#[tokio::test]
async fn cohere_cost_uses_processed_tokens_and_ignores_billed_units_only() {
    for provider in ["auto", "cohere"] {
        let plugin = AiTokenMetrics::new(&json!({
            "provider": provider,
            "buffer_streaming_responses": true,
            "cost_per_prompt_token": 0.000001,
            "cost_per_completion_token": 0.000002
        }))
        .unwrap();
        for location in ["usage", "delta", "meta"] {
            for with_tokens in [false, true] {
                let mut usage = json!({"billed_units": {"input_tokens": 9, "output_tokens": 5}});
                if with_tokens {
                    usage["tokens"] = json!({"input_tokens": 11, "output_tokens": 7});
                }
                let json = if location == "delta" {
                    json!({"type": "message-end", "delta": {"usage": usage}})
                } else {
                    json!({location: usage})
                };
                let (content_type, body) = if location == "delta" {
                    ("text/event-stream", format!("data: {json}\n\n"))
                } else {
                    ("application/json", json.to_string())
                };
                let mut ctx = create_test_context();
                let mut headers =
                    HashMap::from([("content-type".to_string(), content_type.to_string())]);
                assert_continue(
                    plugin
                        .on_response_body(&mut ctx, 200, &mut headers, body.as_bytes())
                        .await,
                );
                if with_tokens {
                    assert_usage_and_metrics(&ctx, "cohere", Some(11), 7, Some(18), "0.000025");
                } else {
                    assert!(ctx.authoritative_ai_usage_export().is_none());
                    assert!(!ctx.metadata.contains_key("ai_estimated_cost"));
                }
            }
        }
    }
}

// ─── Bedrock format ─────────────────────────────────────────────────────

#[tokio::test]
async fn test_bedrock_format() {
    let plugin = AiTokenMetrics::new(&json!({})).unwrap();
    let mut ctx = create_test_context();
    let mut headers = json_headers();
    let body = serde_json::to_vec(&json!({
        "usage": {
            "inputTokens": 150,
            "outputTokens": 75,
            "totalTokens": 225
        }
    }))
    .unwrap();

    let result = plugin
        .on_response_body(&mut ctx, 200, &mut headers, &body)
        .await;
    assert_continue(result);

    assert_eq!(ctx.metadata.get("ai_provider").unwrap(), "bedrock");
    assert_eq!(ctx.metadata.get("ai_total_tokens").unwrap(), "225");
    assert_eq!(ctx.metadata.get("ai_prompt_tokens").unwrap(), "150");
    assert_eq!(ctx.metadata.get("ai_completion_tokens").unwrap(), "75");
}

// ─── Explicit provider config ───────────────────────────────────────────

#[tokio::test]
async fn test_explicit_provider_openai() {
    let plugin = AiTokenMetrics::new(&json!({"provider": "openai"})).unwrap();
    let mut ctx = create_test_context();
    let mut headers = json_headers();
    let body = serde_json::to_vec(&json!({
        "model": "gpt-4",
        "usage": {"prompt_tokens": 10, "completion_tokens": 5, "total_tokens": 15}
    }))
    .unwrap();

    plugin
        .on_response_body(&mut ctx, 200, &mut headers, &body)
        .await;
    assert_eq!(ctx.metadata.get("ai_provider").unwrap(), "openai");
    assert_eq!(ctx.metadata.get("ai_total_tokens").unwrap(), "15");
}

#[test]
fn explicit_provider_requires_the_documented_lowercase_enum_spelling() {
    for provider in ["OpenAI", " openai", "openai ", "OPENAI"] {
        let err = AiTokenMetrics::new(&json!({"provider": provider}))
            .err()
            .expect("non-canonical provider spelling must be rejected");
        assert!(err.contains("unknown `provider` value"), "got: {err}");
    }
}

#[tokio::test]
async fn test_explicit_provider_mistral() {
    let plugin = AiTokenMetrics::new(&json!({"provider": "mistral"})).unwrap();
    let mut ctx = create_test_context();
    let mut headers = json_headers();
    let body = serde_json::to_vec(&json!({
        "model": "mistral-large",
        "usage": {"prompt_tokens": 10, "completion_tokens": 5, "total_tokens": 15}
    }))
    .unwrap();

    plugin
        .on_response_body(&mut ctx, 200, &mut headers, &body)
        .await;
    assert_eq!(ctx.metadata.get("ai_provider").unwrap(), "mistral");
}

// ─── Custom metadata prefix ─────────────────────────────────────────────

#[tokio::test]
async fn test_custom_prefix() {
    let plugin = AiTokenMetrics::new(&json!({"metadata_prefix": "llm"})).unwrap();
    let mut ctx = create_test_context();
    let mut headers = json_headers();
    let body = serde_json::to_vec(&json!({
        "usage": {"prompt_tokens": 10, "completion_tokens": 5, "total_tokens": 15}
    }))
    .unwrap();

    plugin
        .on_response_body(&mut ctx, 200, &mut headers, &body)
        .await;
    assert_eq!(ctx.metadata.get("llm_total_tokens").unwrap(), "15");
    assert_eq!(ctx.metadata.get("llm_prompt_tokens").unwrap(), "10");
    assert!(!ctx.metadata.contains_key("ai_total_tokens"));
}

// ─── Cost calculation ───────────────────────────────────────────────────

#[tokio::test]
async fn test_cost_calculation() {
    let plugin = AiTokenMetrics::new(&json!({
        "cost_per_prompt_token": 0.00001,
        "cost_per_completion_token": 0.00003
    }))
    .unwrap();
    let mut ctx = create_test_context();
    let mut headers = json_headers();
    let body = serde_json::to_vec(&json!({
        "usage": {"prompt_tokens": 1000, "completion_tokens": 500, "total_tokens": 1500}
    }))
    .unwrap();

    plugin
        .on_response_body(&mut ctx, 200, &mut headers, &body)
        .await;
    // Cost = 1000 * 0.00001 + 500 * 0.00003 = 0.01 + 0.015 = 0.025
    assert_eq!(ctx.metadata.get("ai_estimated_cost").unwrap(), "0.025000");
}

#[tokio::test]
async fn test_cost_calculation_prompt_only() {
    // Embedding models only have input cost
    let plugin = AiTokenMetrics::new(&json!({
        "cost_per_prompt_token": 0.0001
    }))
    .unwrap();
    let mut ctx = create_test_context();
    let mut headers = json_headers();
    let body = serde_json::to_vec(&json!({
        "usage": {"prompt_tokens": 1000, "total_tokens": 1000}
    }))
    .unwrap();

    plugin
        .on_response_body(&mut ctx, 200, &mut headers, &body)
        .await;
    // Cost = 1000 * 0.0001 + 0 * 0.0 = 0.1
    assert_eq!(ctx.metadata.get("ai_estimated_cost").unwrap(), "0.100000");
}

#[tokio::test]
async fn test_cost_not_calculated_when_no_rates() {
    let plugin = AiTokenMetrics::new(&json!({})).unwrap();
    let mut ctx = create_test_context();
    let mut headers = json_headers();
    let body = serde_json::to_vec(&json!({
        "usage": {"prompt_tokens": 1000, "completion_tokens": 500, "total_tokens": 1500}
    }))
    .unwrap();

    plugin
        .on_response_body(&mut ctx, 200, &mut headers, &body)
        .await;
    assert!(!ctx.metadata.contains_key("ai_estimated_cost"));
}

// ─── include_model = false ──────────────────────────────────────────────

#[tokio::test]
async fn test_include_model_false() {
    let plugin = AiTokenMetrics::new(&json!({"include_model": false})).unwrap();
    let mut ctx = create_test_context();
    let mut headers = json_headers();
    let body = serde_json::to_vec(&json!({
        "model": "gpt-4",
        "usage": {"prompt_tokens": 10, "completion_tokens": 5, "total_tokens": 15}
    }))
    .unwrap();

    plugin
        .on_response_body(&mut ctx, 200, &mut headers, &body)
        .await;
    assert!(!ctx.metadata.contains_key("ai_model"));
    assert_eq!(ctx.metadata.get("ai_total_tokens").unwrap(), "15");
}

// ─── include_token_details = false ──────────────────────────────────────

#[tokio::test]
async fn test_include_token_details_false() {
    let plugin = AiTokenMetrics::new(&json!({"include_token_details": false})).unwrap();
    let mut ctx = create_test_context();
    let mut headers = json_headers();
    let body = serde_json::to_vec(&json!({
        "usage": {"prompt_tokens": 10, "completion_tokens": 5, "total_tokens": 15}
    }))
    .unwrap();

    plugin
        .on_response_body(&mut ctx, 200, &mut headers, &body)
        .await;
    assert_eq!(ctx.metadata.get("ai_total_tokens").unwrap(), "15");
    assert!(!ctx.metadata.contains_key("ai_prompt_tokens"));
    assert!(!ctx.metadata.contains_key("ai_completion_tokens"));
}

// ─── Edge cases ─────────────────────────────────────────────────────────

#[tokio::test]
async fn test_non_json_content_type() {
    let plugin = AiTokenMetrics::new(&json!({})).unwrap();
    let mut ctx = create_test_context();
    let mut headers = HashMap::new();
    headers.insert("content-type".to_string(), "text/html".to_string());

    let result = plugin
        .on_response_body(&mut ctx, 200, &mut headers, b"not json")
        .await;
    assert_continue(result);
    assert!(!ctx.metadata.contains_key("ai_total_tokens"));
}

#[tokio::test]
async fn test_empty_body() {
    let plugin = AiTokenMetrics::new(&json!({})).unwrap();
    let mut ctx = create_test_context();
    let mut headers = json_headers();

    let result = plugin
        .on_response_body(&mut ctx, 200, &mut headers, b"")
        .await;
    assert_continue(result);
    assert!(!ctx.metadata.contains_key("ai_total_tokens"));
}

#[tokio::test]
async fn test_malformed_json() {
    let plugin = AiTokenMetrics::new(&json!({})).unwrap();
    let mut ctx = create_test_context();
    let mut headers = json_headers();

    let result = plugin
        .on_response_body(&mut ctx, 200, &mut headers, b"not valid json")
        .await;
    assert_continue(result);
    assert!(!ctx.metadata.contains_key("ai_total_tokens"));
}

#[tokio::test]
async fn test_missing_usage_fields() {
    let plugin = AiTokenMetrics::new(&json!({})).unwrap();
    let mut ctx = create_test_context();
    let mut headers = json_headers();
    let body = serde_json::to_vec(&json!({"id": "chatcmpl-123"})).unwrap();

    let result = plugin
        .on_response_body(&mut ctx, 200, &mut headers, &body)
        .await;
    assert_continue(result);
    // No provider detected, no metadata written
    assert!(!ctx.metadata.contains_key("ai_total_tokens"));
}

#[tokio::test]
async fn test_zero_tokens() {
    let plugin = AiTokenMetrics::new(&json!({})).unwrap();
    let mut ctx = create_test_context();
    let mut headers = json_headers();
    let body = serde_json::to_vec(&json!({
        "usage": {"prompt_tokens": 0, "completion_tokens": 0, "total_tokens": 0}
    }))
    .unwrap();

    plugin
        .on_response_body(&mut ctx, 200, &mut headers, &body)
        .await;
    assert_eq!(ctx.metadata.get("ai_total_tokens").unwrap(), "0");
    assert_eq!(ctx.metadata.get("ai_prompt_tokens").unwrap(), "0");
    assert_eq!(ctx.metadata.get("ai_completion_tokens").unwrap(), "0");
}

#[test]
fn test_unknown_configured_provider_rejected() {
    let err = AiTokenMetrics::new(&json!({"provider": "unknown_provider"}))
        .err()
        .unwrap();
    assert!(err.contains("provider"), "got: {err}");
}

#[tokio::test]
async fn test_bedrock_computed_total() {
    // Bedrock without explicit totalTokens — should compute from input + output
    let plugin = AiTokenMetrics::new(&json!({})).unwrap();
    let mut ctx = create_test_context();
    let mut headers = json_headers();
    let body = serde_json::to_vec(&json!({
        "usage": {"inputTokens": 100, "outputTokens": 50}
    }))
    .unwrap();

    plugin
        .on_response_body(&mut ctx, 200, &mut headers, &body)
        .await;
    assert_eq!(ctx.metadata.get("ai_total_tokens").unwrap(), "150");
}

// ─── Response status filtering ────────────────────────────────────────

#[tokio::test]
async fn test_skips_4xx_responses() {
    // Error responses (4xx) often have non-LLM body shapes — they must
    // not be parsed for token counts or pollute observability metrics.
    let plugin = AiTokenMetrics::new(&json!({})).unwrap();
    let mut ctx = create_test_context();
    let mut headers = json_headers();
    let body = serde_json::to_vec(&json!({
        "usage": {"prompt_tokens": 10, "completion_tokens": 20, "total_tokens": 30}
    }))
    .unwrap();

    plugin
        .on_response_body(&mut ctx, 401, &mut headers, &body)
        .await;
    assert!(
        !ctx.metadata.contains_key("ai_total_tokens"),
        "4xx response must not record token metrics"
    );
}

#[tokio::test]
async fn test_skips_5xx_responses() {
    let plugin = AiTokenMetrics::new(&json!({})).unwrap();
    let mut ctx = create_test_context();
    let mut headers = json_headers();
    let body = serde_json::to_vec(&json!({
        "usage": {"prompt_tokens": 10, "completion_tokens": 20, "total_tokens": 30}
    }))
    .unwrap();

    plugin
        .on_response_body(&mut ctx, 503, &mut headers, &body)
        .await;
    assert!(
        !ctx.metadata.contains_key("ai_total_tokens"),
        "5xx response must not record token metrics"
    );
}

#[tokio::test]
async fn test_processes_2xx_responses() {
    // Sanity check that the new filter doesn't accidentally drop happy-path
    // 2xx responses.
    let plugin = AiTokenMetrics::new(&json!({})).unwrap();
    let mut ctx = create_test_context();
    let mut headers = json_headers();
    let body = serde_json::to_vec(&json!({
        "usage": {"prompt_tokens": 10, "completion_tokens": 20, "total_tokens": 30}
    }))
    .unwrap();

    plugin
        .on_response_body(&mut ctx, 200, &mut headers, &body)
        .await;
    assert_eq!(ctx.metadata.get("ai_total_tokens").unwrap(), "30");
}

// ─── Cost validation ────────────────────────────────────────────────────

#[test]
fn test_negative_prompt_cost_rejected() {
    // Negative cost rates would produce negative cost metrics that pollute
    // observability and chargeback pipelines.
    let err = AiTokenMetrics::new(&json!({"cost_per_prompt_token": -0.0001}))
        .err()
        .unwrap();
    assert!(err.contains("cost_per_prompt_token"), "got: {err}");
    assert!(err.contains("non-negative"), "got: {err}");
}

#[test]
fn test_negative_completion_cost_rejected() {
    let err = AiTokenMetrics::new(&json!({"cost_per_completion_token": -0.001}))
        .err()
        .unwrap();
    assert!(err.contains("cost_per_completion_token"), "got: {err}");
    assert!(err.contains("non-negative"), "got: {err}");
}

#[test]
fn test_nan_cost_handled_safely() {
    // The serde_json::json!() macro coerces non-finite f64 values to
    // Value::Null, so a NaN/Inf field is the same as omitting the field.
    // Verify the constructor accepts that path (treats it as "no cost
    // tracking") rather than panicking on `.as_f64()`.
    assert!(
        AiTokenMetrics::new(&json!({"cost_per_prompt_token": f64::NAN})).is_ok(),
        "NaN serializes to JSON null and should be treated as 'unset'"
    );
    assert!(
        AiTokenMetrics::new(&json!({"cost_per_completion_token": f64::INFINITY})).is_ok(),
        "Infinity serializes to JSON null and should be treated as 'unset'"
    );
}

#[test]
fn test_zero_cost_accepted() {
    // Zero is a valid cost rate (e.g., free-tier accounting).
    assert!(
        AiTokenMetrics::new(&json!({
            "cost_per_prompt_token": 0.0,
            "cost_per_completion_token": 0.0
        }))
        .is_ok()
    );
}

#[test]
fn cost_rate_maximum_matches_the_openapi_contract() {
    assert!(
        AiTokenMetrics::new(&json!({
            "cost_per_prompt_token": 18_446_744_073_709.55,
            "cost_per_completion_token": 18_446_744_073_709.55
        }))
        .is_ok()
    );
    assert!(AiTokenMetrics::new(&json!({"cost_per_prompt_token": 18_446_744_073_710.0})).is_err());
}

#[test]
fn test_invalid_config_shapes_rejected() {
    for (config, needle) in [
        (json!(null), "config must be an object"),
        (json!({"provider": ""}), "provider"),
        (json!({"include_model": "yes"}), "include_model"),
        (
            json!({"include_token_details": "yes"}),
            "include_token_details",
        ),
        (
            json!({"buffer_streaming_responses": "yes"}),
            "buffer_streaming_responses",
        ),
        (json!({"metadata_prefix": ""}), "metadata_prefix"),
        (
            json!({"cost_per_prompt_token": "free"}),
            "cost_per_prompt_token",
        ),
        (
            json!({"cost_per_completion_token": "free"}),
            "cost_per_completion_token",
        ),
    ] {
        let err = AiTokenMetrics::new(&config).err().unwrap();
        assert!(err.contains(needle), "needle={needle}, got: {err}");
    }
}

#[test]
fn test_shared_validation_rejects_invalid_ai_token_metrics_config() {
    let err = validate_plugin_config("ai_token_metrics", &json!({"include_model": "yes"}))
        .expect_err("shared plugin validation must reject a non-boolean include_model");
    assert_eq!(err, "ai_token_metrics: `include_model` must be a boolean");
}

// ─── Synthetic short-circuit accounting guard ───────────────────────────────

// Regression: a synthetic short-circuit 2xx body (an `ai_semantic_cache` hit, a
// `response_mock` returning a canned chat-completion, a `serverless_function`
// terminate, an `ai_federation` synthetic response, …) never reached the
// upstream model, so its token usage must NOT be recorded. Even if the synthetic
// body carries a provider-shaped `usage` block, charging it would inflate token
// metrics / logging sinks / chargeback with phantom usage. The proxy sets the
// synthetic marker for the duration of the response-body-hook phase.
#[tokio::test]
async fn synthetic_short_circuit_body_is_not_token_accounted() {
    let plugin = AiTokenMetrics::new(&json!({})).unwrap();
    let mut ctx = create_test_context();
    // Emulate the proxy marking the context before running the body hooks.
    ctx.metadata.insert(
        SYNTHETIC_SHORT_CIRCUIT_METADATA_KEY.to_string(),
        "true".to_string(),
    );
    let mut headers = json_headers();
    // A canned OpenAI-shaped body that WOULD otherwise be accounted.
    let body = serde_json::to_vec(&json!({
        "model": "gpt-4o",
        "usage": {
            "prompt_tokens": 100,
            "completion_tokens": 50,
            "total_tokens": 150
        }
    }))
    .unwrap();

    let result = plugin
        .on_response_body(&mut ctx, 200, &mut headers, &body)
        .await;
    assert_continue(result);

    // No token-usage metadata was written for the synthetic body.
    assert!(
        !ctx.metadata.contains_key("ai_total_tokens"),
        "synthetic short-circuit body must not record token usage"
    );
    assert!(!ctx.metadata.contains_key("ai_provider"));
    assert!(!ctx.metadata.contains_key("ai_prompt_tokens"));
    assert!(!ctx.metadata.contains_key("ai_completion_tokens"));
    assert!(!ctx.metadata.contains_key("ai_model"));
}

// Control: a GENUINE backend response (no synthetic marker) with the same
// provider-shaped body IS accounted. Guards against the synthetic skip
// accidentally disabling normal token metrics.
#[tokio::test]
async fn genuine_response_is_token_accounted_without_synthetic_marker() {
    let plugin = AiTokenMetrics::new(&json!({})).unwrap();
    let mut ctx = create_test_context();
    let mut headers = json_headers();
    let body = serde_json::to_vec(&json!({
        "model": "gpt-4o",
        "usage": {
            "prompt_tokens": 100,
            "completion_tokens": 50,
            "total_tokens": 150
        }
    }))
    .unwrap();

    let result = plugin
        .on_response_body(&mut ctx, 200, &mut headers, &body)
        .await;
    assert_continue(result);

    assert_eq!(ctx.metadata.get("ai_total_tokens").unwrap(), "150");
    assert_eq!(ctx.metadata.get("ai_provider").unwrap(), "openai");
}

#[tokio::test]
async fn anthropic_sse_merges_cumulative_terminal_usage_without_double_counting() {
    let plugin = AiTokenMetrics::new(&json!({
        "buffer_streaming_responses": true,
        "cost_per_prompt_token": 0.01,
        "cost_per_completion_token": 0.02
    }))
    .unwrap();
    let mut ctx = create_test_context();
    let mut headers =
        HashMap::from([("content-type".to_string(), "text/event-stream".to_string())]);
    let body = concat!(
        "data: {\"type\":\"message_start\",\"message\":{\"model\":\"claude-test\",\"usage\":{\"input_tokens\":25,\"output_tokens\":1}}}\n\n",
        "data: {\"type\":\"message_delta\",\"usage\":{\"output_tokens\":7}}\n\n",
        "data: {\"type\":\"message_delta\",\"usage\":{\"output_tokens\":15}}\n\n",
        "data: {\"type\":\"message_stop\"}\n\n"
    );

    plugin
        .on_response_body(&mut ctx, 200, &mut headers, body.as_bytes())
        .await;

    assert_eq!(
        ctx.metadata.get("ai_provider").map(String::as_str),
        Some("anthropic")
    );
    assert_eq!(
        ctx.metadata.get("ai_prompt_tokens").map(String::as_str),
        Some("25")
    );
    assert_eq!(
        ctx.metadata.get("ai_completion_tokens").map(String::as_str),
        Some("15")
    );
    assert_eq!(
        ctx.metadata.get("ai_total_tokens").map(String::as_str),
        Some("40")
    );
    assert_eq!(
        ctx.metadata.get("ai_estimated_cost").map(String::as_str),
        Some("0.550000")
    );
}

#[tokio::test]
async fn anthropic_sse_without_message_start_keeps_explicit_partial_usage() {
    let plugin = AiTokenMetrics::new(&json!({"buffer_streaming_responses": true})).unwrap();
    let mut ctx = create_test_context();
    let mut headers =
        HashMap::from([("content-type".to_string(), "text/event-stream".to_string())]);
    let body = b"data: {\"type\":\"message_delta\",\"usage\":{\"output_tokens\":9}}\n\n";

    plugin
        .on_response_body(&mut ctx, 200, &mut headers, body)
        .await;

    assert_eq!(
        ctx.metadata.get("ai_completion_tokens").map(String::as_str),
        Some("9")
    );
    assert!(!ctx.metadata.contains_key("ai_prompt_tokens"));
    assert!(!ctx.metadata.contains_key("ai_total_tokens"));
}

#[tokio::test]
async fn partial_sse_component_update_retains_earlier_authoritative_total() {
    let plugin = AiTokenMetrics::new(&json!({
        "provider": "openai",
        "buffer_streaming_responses": true
    }))
    .unwrap();
    let mut ctx = create_test_context();
    let mut headers =
        HashMap::from([("content-type".to_string(), "text/event-stream".to_string())]);
    let body = concat!(
        "data: {\"usage\":{\"total_tokens\":100}}\n\n",
        "data: {\"usage\":{\"completion_tokens\":7}}\n\n",
        "data: [DONE]\n\n"
    );

    plugin
        .on_response_body(&mut ctx, 200, &mut headers, body.as_bytes())
        .await;

    assert_eq!(
        ctx.metadata.get("ai_completion_tokens").map(String::as_str),
        Some("7")
    );
    assert_eq!(
        ctx.metadata.get("ai_total_tokens").map(String::as_str),
        Some("100")
    );
    assert!(!ctx.metadata.contains_key("ai_prompt_tokens"));
    let export = ctx
        .authoritative_ai_usage_export()
        .expect("partial SSE usage must retain typed export provenance");
    assert_eq!(export.prompt_tokens, None);
    assert_eq!(export.completion_tokens, Some(7));
    assert_eq!(export.total_tokens, Some(100));
}

#[tokio::test]
async fn openai_responses_buffered_and_completed_sse_are_supported() {
    let buffered = json!({
        "id": "resp_123",
        "object": "response",
        "model": "gpt-4.1",
        "usage": {
            "input_tokens": 36,
            "input_tokens_details": {"cached_tokens": 10},
            "output_tokens": 87,
            "output_tokens_details": {"reasoning_tokens": 12},
            "total_tokens": 123
        }
    });
    for config in [
        json!({"cost_per_prompt_token": 0.01, "cost_per_completion_token": 0.02}),
        json!({"provider": "openai", "cost_per_prompt_token": 0.01, "cost_per_completion_token": 0.02}),
    ] {
        let plugin = AiTokenMetrics::new(&config).unwrap();
        let mut ctx = create_test_context();
        plugin
            .on_response_body(
                &mut ctx,
                200,
                &mut json_headers(),
                &serde_json::to_vec(&buffered).unwrap(),
            )
            .await;
        assert_eq!(
            ctx.metadata.get("ai_provider").map(String::as_str),
            Some("openai")
        );
        assert_eq!(
            ctx.metadata.get("ai_prompt_tokens").map(String::as_str),
            Some("36")
        );
        assert_eq!(
            ctx.metadata.get("ai_completion_tokens").map(String::as_str),
            Some("87")
        );
        assert_eq!(
            ctx.metadata.get("ai_total_tokens").map(String::as_str),
            Some("123")
        );
        assert_eq!(
            ctx.metadata.get("ai_estimated_cost").map(String::as_str),
            Some("2.100000")
        );
    }

    let plugin = AiTokenMetrics::new(&json!({"buffer_streaming_responses": true})).unwrap();
    let mut ctx = create_test_context();
    let mut headers = HashMap::from([(
        "content-type".to_string(),
        "text/event-stream; charset=utf-8".to_string(),
    )]);
    let event = format!(
        "data: {}\n\ndata: [DONE]\n\n",
        json!({
            "type": "response.completed",
            "response": buffered
        })
    );
    plugin
        .on_response_body(&mut ctx, 200, &mut headers, event.as_bytes())
        .await;
    assert_eq!(
        ctx.metadata.get("ai_total_tokens").map(String::as_str),
        Some("123")
    );
}

#[tokio::test]
async fn non_terminal_or_malformed_openai_responses_do_not_invent_usage() {
    let plugin = AiTokenMetrics::new(&json!({
        "provider": "openai",
        "buffer_streaming_responses": true,
        "cost_per_prompt_token": 1.0
    }))
    .unwrap();
    let mut headers =
        HashMap::from([("content-type".to_string(), "text/event-stream".to_string())]);
    for event_type in ["response.failed", "response.in_progress"] {
        let mut ctx = create_test_context();
        let event = format!(
            "data: {}\n\n",
            json!({"type": event_type, "response": {"usage": {"input_tokens": 5}}})
        );
        plugin
            .on_response_body(&mut ctx, 200, &mut headers, event.as_bytes())
            .await;
        assert!(!ctx.metadata.contains_key("ai_provider"));
        assert!(!ctx.metadata.contains_key("ai_estimated_cost"));
        assert_eq!(ctx.metadata["ai_unmetered_reason"], "no_usage");
    }

    // `response.incomplete` is TERMINAL: a finished response that stopped early
    // (for example at `max_output_tokens`) and bills the usage it reports
    // (ai_rate_limiter-SOL-4). It is read exactly like `response.completed`.
    let mut ctx = create_test_context();
    let incomplete = format!(
        "data: {}\n\n",
        json!({
            "type": "response.incomplete",
            "response": {
                "status": "incomplete",
                "incomplete_details": {"reason": "max_output_tokens"},
                "usage": {"input_tokens": 20, "output_tokens": 64, "total_tokens": 84}
            }
        })
    );
    plugin
        .on_response_body(&mut ctx, 200, &mut headers, incomplete.as_bytes())
        .await;
    assert_eq!(
        ctx.metadata.get("ai_prompt_tokens").map(String::as_str),
        Some("20")
    );
    assert_eq!(
        ctx.metadata.get("ai_completion_tokens").map(String::as_str),
        Some("64")
    );
    assert_eq!(
        ctx.metadata.get("ai_total_tokens").map(String::as_str),
        Some("84")
    );

    let mut ctx = create_test_context();
    let malformed = serde_json::to_vec(&json!({
        "object": "response",
        "usage": {"input_tokens": 1.5, "output_tokens": "2", "total_tokens": -1}
    }))
    .unwrap();
    plugin
        .on_response_body(&mut ctx, 200, &mut json_headers(), &malformed)
        .await;
    // No usage is invented: the only key written is the bounded diagnostic
    // that labels this 2xx response as unmetered rather than zero usage.
    assert_eq!(
        ctx.metadata
            .iter()
            .map(|(key, value)| (key.as_str(), value.as_str()))
            .collect::<Vec<_>>(),
        vec![("ai_unmetered_reason", "no_usage")]
    );
    assert!(ctx.authoritative_ai_usage_export().is_none());
}

#[tokio::test]
async fn google_sse_merges_repeated_partial_usage_for_auto_and_fixed_provider() {
    let mut headers =
        HashMap::from([("content-type".to_string(), "text/event-stream".to_string())]);
    let body = concat!(
        "data: {\"candidates\":[{\"content\":{\"parts\":[{\"text\":\"hi\"}]}}],\"modelVersion\":\"gemini-test\"}\n\n",
        "data: {\"usageMetadata\":{\"promptTokenCount\":11}}\n\n",
        "data: {\"usageMetadata\":{\"candidatesTokenCount\":7,\"totalTokenCount\":18}}\n\n",
        "data: [DONE]\n\n"
    );
    for config in [
        json!({"buffer_streaming_responses": true}),
        json!({"provider": "google", "buffer_streaming_responses": true}),
    ] {
        let plugin = AiTokenMetrics::new(&config).unwrap();
        let mut ctx = create_test_context();
        plugin
            .on_response_body(&mut ctx, 200, &mut headers, body.as_bytes())
            .await;
        assert_eq!(
            ctx.metadata.get("ai_provider").map(String::as_str),
            Some("google")
        );
        assert_eq!(
            ctx.metadata.get("ai_prompt_tokens").map(String::as_str),
            Some("11")
        );
        assert_eq!(
            ctx.metadata.get("ai_completion_tokens").map(String::as_str),
            Some("7")
        );
        assert_eq!(
            ctx.metadata.get("ai_total_tokens").map(String::as_str),
            Some("18")
        );
        assert_eq!(
            ctx.metadata.get("ai_model").map(String::as_str),
            Some("gemini-test")
        );
    }
}

#[tokio::test]
async fn bedrock_titan_invoke_model_is_supported_without_ambiguous_result_summing() {
    let plugin = AiTokenMetrics::new(&json!({
        "cost_per_prompt_token": 0.01,
        "cost_per_completion_token": 0.02
    }))
    .unwrap();
    let mut ctx = create_test_context();
    let body = serde_json::to_vec(&json!({
        "inputTextTokenCount": 21,
        "results": [{"tokenCount": 8, "outputText": "hello", "completionReason": "FINISH"}]
    }))
    .unwrap();
    plugin
        .on_response_body(&mut ctx, 200, &mut json_headers(), &body)
        .await;
    assert_eq!(
        ctx.metadata.get("ai_provider").map(String::as_str),
        Some("bedrock")
    );
    assert_eq!(
        ctx.metadata.get("ai_prompt_tokens").map(String::as_str),
        Some("21")
    );
    assert_eq!(
        ctx.metadata.get("ai_completion_tokens").map(String::as_str),
        Some("8")
    );
    assert_eq!(
        ctx.metadata.get("ai_total_tokens").map(String::as_str),
        Some("29")
    );
    assert_eq!(
        ctx.metadata.get("ai_estimated_cost").map(String::as_str),
        Some("0.370000")
    );

    for results in [json!([]), json!([{"tokenCount": 2}, {"tokenCount": 3}])] {
        let mut ctx = create_test_context();
        let body = serde_json::to_vec(&json!({
            "inputTextTokenCount": 5,
            "results": results
        }))
        .unwrap();
        plugin
            .on_response_body(&mut ctx, 200, &mut json_headers(), &body)
            .await;
        assert_eq!(
            ctx.metadata.get("ai_prompt_tokens").map(String::as_str),
            Some("5")
        );
        assert!(!ctx.metadata.contains_key("ai_completion_tokens"));
        assert!(!ctx.metadata.contains_key("ai_total_tokens"));
    }
}

#[tokio::test]
async fn encoded_json_supports_gzip_brotli_and_coding_chains_without_mutation() {
    let plugin = AiTokenMetrics::new(&json!({})).unwrap();
    let plain = serde_json::to_vec(&json!({
        "model": "gpt-test",
        "usage": {"prompt_tokens": 10, "completion_tokens": 5, "total_tokens": 15}
    }))
    .unwrap();
    let cases = [
        ("GZip", gzip(&plain)),
        ("br", brotli(&plain)),
        ("gzip, BR", brotli(&gzip(&plain))),
    ];

    for (encoding, encoded) in cases {
        let original = encoded.clone();
        let mut headers = HashMap::from([
            (
                "Content-Type".to_string(),
                "application/json; charset=utf-8".to_string(),
            ),
            ("Content-Encoding".to_string(), encoding.to_string()),
            ("Content-Length".to_string(), encoded.len().to_string()),
            ("ETag".to_string(), "encoded-validator".to_string()),
        ]);
        let mut ctx = create_test_context();
        plugin
            .on_response_body(&mut ctx, 200, &mut headers, &encoded)
            .await;
        assert_eq!(
            ctx.metadata.get("ai_total_tokens").map(String::as_str),
            Some("15")
        );
        assert_eq!(encoded, original);
        assert_eq!(
            headers.get("Content-Encoding").map(String::as_str),
            Some(encoding)
        );
        assert_eq!(
            headers
                .get("Content-Length")
                .and_then(|value| value.parse::<usize>().ok()),
            Some(encoded.len())
        );
        assert_eq!(
            headers.get("ETag").map(String::as_str),
            Some("encoded-validator")
        );
    }
}

/// A collected SSE body never reaches the stream observer, so it is metered
/// from the buffered body even when a sibling (not this instance's opt-in)
/// caused the collection; otherwise that sibling would silently drop usage.
#[tokio::test]
async fn collected_encoded_sse_is_metered_with_or_without_the_buffering_opt_in() {
    let event = b"data: {\"usage\":{\"prompt_tokens\":4,\"completion_tokens\":6,\"total_tokens\":10}}\n\ndata: [DONE]\n\n";
    let encoded = gzip(event);
    let mut headers = HashMap::from([
        ("content-type".to_string(), "text/event-stream".to_string()),
        ("content-encoding".to_string(), "gzip".to_string()),
    ]);

    for (enabled, expected) in [(false, Some("10")), (true, Some("10"))] {
        let plugin = AiTokenMetrics::new(&json!({"buffer_streaming_responses": enabled})).unwrap();
        let mut ctx = create_test_context();
        plugin
            .on_response_body(&mut ctx, 200, &mut headers, &encoded)
            .await;
        assert_eq!(
            ctx.metadata.get("ai_total_tokens").map(String::as_str),
            expected
        );
    }
}

#[tokio::test]
async fn encoded_json_rejects_malformed_unsupported_concatenated_and_oversized_content() {
    let plugin = AiTokenMetrics::new(&json!({})).unwrap();
    let plain = br#"{"usage":{"prompt_tokens":1,"completion_tokens":1,"total_tokens":2}}"#;
    let mut concatenated = gzip(plain);
    concatenated.extend_from_slice(&gzip(plain));
    let oversized = gzip(&vec![b' '; 4 * 1024 * 1024 + 1]);
    let cases = [
        ("gzip", b"not-gzip".to_vec()),
        ("zstd", plain.to_vec()),
        ("gzip; level=9", gzip(plain)),
        ("gzip", concatenated),
        ("gzip", oversized),
    ];
    for (encoding, body) in cases {
        let mut headers = HashMap::from([
            ("content-type".to_string(), "application/json".to_string()),
            ("content-encoding".to_string(), encoding.to_string()),
        ]);
        let mut ctx = create_test_context();
        plugin
            .on_response_body(&mut ctx, 200, &mut headers, &body)
            .await;
        assert!(
            !ctx.metadata.contains_key("ai_total_tokens"),
            "encoding={encoding}"
        );
    }
}

#[tokio::test]
async fn checked_usage_arithmetic_never_saturates_into_invented_totals() {
    let plugin = AiTokenMetrics::new(&json!({})).unwrap();
    let mut ctx = create_test_context();
    let body = serde_json::to_vec(&json!({
        "usage": {"prompt_tokens": u64::MAX, "completion_tokens": 1}
    }))
    .unwrap();
    plugin
        .on_response_body(&mut ctx, 200, &mut json_headers(), &body)
        .await;
    assert_eq!(
        ctx.metadata.get("ai_prompt_tokens").map(String::as_str),
        Some("18446744073709551615")
    );
    assert_eq!(
        ctx.metadata.get("ai_completion_tokens").map(String::as_str),
        Some("1")
    );
    assert!(!ctx.metadata.contains_key("ai_total_tokens"));
}

#[test]
fn every_unknown_root_config_key_is_rejected_with_allowed_key_list() {
    for key in [
        "providre",
        "include_modle",
        "include_token_detail",
        "metadata_prefx",
        "buffer_streaming_response",
        "cost_per_prompt_tokn",
        "cost_per_completion_tokn",
        "model_pricng",
    ] {
        let err = AiTokenMetrics::new(&json!({(key): true})).err().unwrap();
        assert!(err.contains(key), "got: {err}");
        assert!(err.contains("allowed keys"), "got: {err}");
        assert!(err.contains("metadata_prefix"), "got: {err}");
    }
}

/// Issue #6623: the `message_start` `output_tokens` placeholder is not a
/// completion count; a stream interrupted before `message_delta` keeps only
/// its authoritative input (with prompt-cache categories).
#[tokio::test]
async fn anthropic_sse_interrupted_after_message_start_reports_input_only() {
    let plugin = AiTokenMetrics::new(&json!({"buffer_streaming_responses": true})).unwrap();
    let mut ctx = create_test_context();
    let mut headers =
        HashMap::from([("content-type".to_string(), "text/event-stream".to_string())]);
    let body = concat!(
        "data: {\"type\":\"message_start\",\"message\":{\"model\":\"claude-test\",\"usage\":{\"input_tokens\":25,\"cache_read_input_tokens\":100,\"output_tokens\":1}}}\n\n",
        "data: {\"type\":\"content_block_delta\",\"index\":0,\"delta\":{\"type\":\"text_delta\",\"text\":\"partial\"}}\n\n",
    );
    plugin
        .on_response_body(&mut ctx, 200, &mut headers, body.as_bytes())
        .await;
    assert_eq!(
        ctx.metadata.get("ai_prompt_tokens").map(String::as_str),
        Some("125")
    );
    assert!(!ctx.metadata.contains_key("ai_completion_tokens"));
    assert!(!ctx.metadata.contains_key("ai_total_tokens"));
}

/// A category-only update reaches the cumulative merge: a valid one extends
/// the prompt, a malformed one invalidates the stale count.
#[tokio::test]
async fn anthropic_sse_category_only_updates_reach_the_merge() {
    let run = |delta: &'static str| async move {
        let plugin = AiTokenMetrics::new(&json!({"buffer_streaming_responses": true})).unwrap();
        let mut ctx = create_test_context();
        let mut headers =
            HashMap::from([("content-type".to_string(), "text/event-stream".to_string())]);
        let body = format!(
            "data: {{\"type\":\"message_start\",\"message\":{{\"model\":\"claude-test\",\"usage\":{{\"input_tokens\":10}}}}}}\n\n\
             data: {{\"type\":\"message_delta\",\"usage\":{{\"output_tokens\":5}}}}\n\n\
             data: {{\"type\":\"message_delta\",\"usage\":{delta}}}\n\n"
        );
        plugin
            .on_response_body(&mut ctx, 200, &mut headers, body.as_bytes())
            .await;
        ctx
    };

    let ctx = run("{\"cache_read_input_tokens\":100}").await;
    assert_eq!(
        ctx.metadata.get("ai_prompt_tokens").map(String::as_str),
        Some("110")
    );
    assert_eq!(
        ctx.metadata.get("ai_total_tokens").map(String::as_str),
        Some("115")
    );

    let ctx = run("{\"cache_read_input_tokens\":\"bad\"}").await;
    assert!(!ctx.metadata.contains_key("ai_prompt_tokens"));
    assert!(!ctx.metadata.contains_key("ai_total_tokens"));
}

/// Gemini usage that omits a zero `promptTokenCount` is still detected under
/// automatic provider selection and counted like an explicit `google` config.
#[tokio::test]
async fn gemini_usage_without_prompt_count_is_detected_automatically() {
    let body = serde_json::to_vec(&json!({"usageMetadata": {
        "toolUsePromptTokenCount": 3,
        "candidatesTokenCount": 5,
        "thoughtsTokenCount": 40,
        "totalTokenCount": 48
    }}))
    .unwrap();
    for config in [json!({}), json!({"provider": "google"})] {
        let plugin = AiTokenMetrics::new(&config).unwrap();
        let mut ctx = create_test_context();
        let mut headers = json_headers();
        plugin
            .on_response_body(&mut ctx, 200, &mut headers, &body)
            .await;
        assert_eq!(
            ctx.metadata.get("ai_prompt_tokens").map(String::as_str),
            Some("3"),
            "{config}"
        );
        assert_eq!(
            ctx.metadata.get("ai_completion_tokens").map(String::as_str),
            Some("45"),
            "{config}"
        );
        assert_eq!(
            ctx.metadata.get("ai_total_tokens").map(String::as_str),
            Some("48"),
            "{config}"
        );
    }
}

/// Bedrock's terminal invocation metrics can carry the cache counters alone;
/// the SSE metrics path must fold them into the Anthropic stream's usage.
#[tokio::test]
async fn bedrock_terminal_metrics_cache_counters_reach_sse_metrics() {
    let plugin = AiTokenMetrics::new(&json!({"buffer_streaming_responses": true})).unwrap();
    let mut ctx = create_test_context();
    let mut headers =
        HashMap::from([("content-type".to_string(), "text/event-stream".to_string())]);
    let body = concat!(
        "data: {\"type\":\"message_start\",\"message\":{\"model\":\"claude-test\",\"usage\":{\"input_tokens\":10,\"output_tokens\":1}}}\n\n",
        "data: {\"type\":\"message_delta\",\"usage\":{\"output_tokens\":5}}\n\n",
        "data: {\"type\":\"message_stop\",\"amazon-bedrock-invocationMetrics\":{\"inputTokenCount\":10,\"outputTokenCount\":5,\"cacheReadInputTokenCount\":1000}}\n\n",
    );
    plugin
        .on_response_body(&mut ctx, 200, &mut headers, body.as_bytes())
        .await;
    assert_eq!(
        ctx.metadata.get("ai_prompt_tokens").map(String::as_str),
        Some("1010")
    );
    assert_eq!(
        ctx.metadata.get("ai_total_tokens").map(String::as_str),
        Some("1015")
    );
}

/// Under an explicit `bedrock` provider, the wrapped Anthropic events are still
/// read by their own shape, so terminal metrics that omit the cache counters
/// cannot drop the cache reads the start reported.
#[tokio::test]
async fn explicit_bedrock_keeps_wrapped_anthropic_cache_categories() {
    let plugin = AiTokenMetrics::new(&json!({
        "provider": "bedrock",
        "buffer_streaming_responses": true
    }))
    .unwrap();
    let mut ctx = create_test_context();
    let mut headers =
        HashMap::from([("content-type".to_string(), "text/event-stream".to_string())]);
    let body = concat!(
        "data: {\"type\":\"message_start\",\"message\":{\"model\":\"claude-test\",\"usage\":{\"input_tokens\":10,\"cache_read_input_tokens\":1000,\"output_tokens\":1}}}\n\n",
        "data: {\"type\":\"message_delta\",\"usage\":{\"output_tokens\":5}}\n\n",
        "data: {\"type\":\"message_stop\",\"amazon-bedrock-invocationMetrics\":{\"inputTokenCount\":10,\"outputTokenCount\":5}}\n\n",
    );
    plugin
        .on_response_body(&mut ctx, 200, &mut headers, body.as_bytes())
        .await;
    assert_eq!(
        ctx.metadata.get("ai_prompt_tokens").map(String::as_str),
        Some("1010")
    );
    assert_eq!(
        ctx.metadata.get("ai_total_tokens").map(String::as_str),
        Some("1015")
    );
    assert_eq!(
        ctx.metadata.get("ai_provider").map(String::as_str),
        Some("bedrock"),
        "an explicit provider keeps the exported identity"
    );
}

/// Native usage and Bedrock invocation metrics in the same event are merged
/// independently, matching the shared streaming accumulator.
#[tokio::test]
async fn co_located_native_usage_and_invocation_metrics_both_merge() {
    let run = |delta_usage: &'static str| async move {
        let plugin = AiTokenMetrics::new(&json!({"buffer_streaming_responses": true})).unwrap();
        let mut ctx = create_test_context();
        let mut headers =
            HashMap::from([("content-type".to_string(), "text/event-stream".to_string())]);
        let body = format!(
            "data: {{\"type\":\"message_start\",\"message\":{{\"model\":\"claude-test\",\"usage\":{{\"input_tokens\":10}}}}}}\n\n\
             data: {{\"type\":\"message_delta\",\"usage\":{delta_usage},\"amazon-bedrock-invocationMetrics\":{{\"inputTokenCount\":10,\"outputTokenCount\":5}}}}\n\n"
        );
        plugin
            .on_response_body(&mut ctx, 200, &mut headers, body.as_bytes())
            .await;
        ctx
    };

    let ctx = run("{\"cache_read_input_tokens\":1000,\"output_tokens\":5}").await;
    assert_eq!(
        ctx.metadata.get("ai_prompt_tokens").map(String::as_str),
        Some("1010")
    );
    assert_eq!(
        ctx.metadata.get("ai_total_tokens").map(String::as_str),
        Some("1015")
    );

    // A malformed native cache counter is not hidden by valid metrics.
    let ctx = run("{\"cache_read_input_tokens\":\"bad\",\"output_tokens\":5}").await;
    assert!(!ctx.metadata.contains_key("ai_total_tokens"));
}

/// Cache counters supplied only by co-located invocation metrics are merged
/// beside the native usage of the same event; malformed metrics invalidate.
#[tokio::test]
async fn co_located_invocation_metrics_supply_their_own_categories() {
    let run = |metrics: &'static str| async move {
        let plugin = AiTokenMetrics::new(&json!({"buffer_streaming_responses": true})).unwrap();
        let mut ctx = create_test_context();
        let mut headers =
            HashMap::from([("content-type".to_string(), "text/event-stream".to_string())]);
        let body = format!(
            "data: {{\"type\":\"message_start\",\"message\":{{\"model\":\"claude-test\",\"usage\":{{\"input_tokens\":10}}}}}}\n\n\
             data: {{\"type\":\"message_delta\",\"usage\":{{\"output_tokens\":5}},\"amazon-bedrock-invocationMetrics\":{metrics}}}\n\n"
        );
        plugin
            .on_response_body(&mut ctx, 200, &mut headers, body.as_bytes())
            .await;
        ctx
    };
    let ctx =
        run("{\"inputTokenCount\":10,\"outputTokenCount\":5,\"cacheReadInputTokenCount\":1000}")
            .await;
    assert_eq!(
        ctx.metadata.get("ai_total_tokens").map(String::as_str),
        Some("1015")
    );
    let ctx = run("{\"inputTokenCount\":10,\"cacheReadInputTokenCount\":\"bad\"}").await;
    assert!(!ctx.metadata.contains_key("ai_total_tokens"));
}

/// A standalone invocation-metrics event (detected as Bedrock under `auto`)
/// continues the Anthropic stream it terminates and merges into it.
#[tokio::test]
async fn standalone_invocation_metrics_event_merges_under_auto_detection() {
    let plugin = AiTokenMetrics::new(&json!({"buffer_streaming_responses": true})).unwrap();
    let mut ctx = create_test_context();
    let mut headers =
        HashMap::from([("content-type".to_string(), "text/event-stream".to_string())]);
    let body = concat!(
        "data: {\"type\":\"message_start\",\"message\":{\"model\":\"claude-test\",\"usage\":{\"input_tokens\":10}}}\n\n",
        "data: {\"type\":\"message_delta\",\"usage\":{\"output_tokens\":5}}\n\n",
        "data: {\"amazon-bedrock-invocationMetrics\":{\"inputTokenCount\":10,\"outputTokenCount\":5,\"cacheReadInputTokenCount\":1000}}\n\n",
    );
    plugin
        .on_response_body(&mut ctx, 200, &mut headers, body.as_bytes())
        .await;
    assert_eq!(
        ctx.metadata.get("ai_total_tokens").map(String::as_str),
        Some("1015")
    );
    assert_eq!(
        ctx.metadata.get("ai_provider").map(String::as_str),
        Some("anthropic")
    );
}

// ─── Production-launch review regressions ───────────────────────────────

/// ai_token_metrics-SOL-1: a reject-mode `ai_response_guard` refusing a 2xx
/// generation the provider already produced must not erase that generation's
/// usage. The plugins run in priority order exactly as the proxy's
/// `on_response_body` loop does, which stops at the first rejection.
#[tokio::test]
async fn usage_survives_a_response_guard_rejection_of_a_consumed_generation() {
    let guard =
        AiResponseGuard::new(&json!({"pii_patterns": ["ssn"], "action": "reject"})).unwrap();
    let metrics = AiTokenMetrics::new(&json!({
        "cost_per_prompt_token": 0.01,
        "cost_per_completion_token": 0.02
    }))
    .unwrap();
    assert!(
        metrics.priority() < guard.priority(),
        "token metrics must observe before a rejecting response guard"
    );
    let mut chain: Vec<Arc<dyn Plugin>> = vec![Arc::new(guard), Arc::new(metrics)];
    chain.sort_by_key(|plugin| plugin.priority());

    let body = serde_json::to_vec(&json!({
        "model": "example-model",
        "choices": [{"message": {"content": "Your SSN is 123-45-6789"}}],
        "usage": {"prompt_tokens": 10, "completion_tokens": 5, "total_tokens": 15}
    }))
    .unwrap();
    let mut ctx = ctx_with_content_type("POST", "application/json");
    let mut headers = json_headers();
    let mut rejected = false;
    for plugin in &chain {
        match plugin
            .on_response_body(&mut ctx, 200, &mut headers, &body)
            .await
        {
            PluginResult::Continue => {}
            PluginResult::Reject { status_code, .. } => {
                assert_eq!(status_code, 502);
                rejected = true;
                break;
            }
            other => panic!("unexpected response-body result: {other:?}"),
        }
    }
    assert!(rejected, "the guard must still refuse the SSN response");
    assert_eq!(ctx.metadata["ai_total_tokens"], "15");
    assert_eq!(ctx.metadata["ai_model"], "example-model");
    assert_eq!(ctx.metadata["ai_estimated_cost"], "0.200000");
    let export = ctx.authoritative_ai_usage_export().unwrap();
    assert_eq!(export.provider, "openai");
    assert_eq!(export.prompt_tokens, Some(10));
    assert_eq!(export.completion_tokens, Some(5));
    assert_eq!(export.total_tokens, Some(15));
    assert!(export.cost.is_some());
}

/// Drive one streamed response through the shared inspector entry point used
/// by every H1/H2, native H3, and cross-protocol dispatcher, then the terminal
/// hook. Returns the bytes forwarded for each chunk, or `None` when no
/// inspector attached.
async fn drive_token_stream(
    plugin: &Arc<AiTokenMetrics>,
    ctx: &mut RequestContext,
    status: u16,
    content_type: &str,
    chunks: &[&[u8]],
    complete: bool,
) -> Option<Vec<Vec<u8>>> {
    let chain: Vec<Arc<dyn Plugin>> = vec![plugin.clone()];
    let mut forwarded = None;
    if let Some(mut inspector) =
        create_response_stream_inspector(&chain, ctx, status, Some(content_type))
    {
        let mut per_chunk = Vec::new();
        for chunk in chunks {
            match inspector.on_chunk(chunk).await {
                ResponseStreamAction::Forward(bytes) => per_chunk.push(bytes.to_vec()),
                ResponseStreamAction::Terminate(_) => {
                    panic!("ai_token_metrics must never truncate a response stream")
                }
            }
        }
        if complete {
            match inspector.on_end().await {
                ResponseStreamAction::Forward(bytes) => assert!(bytes.is_empty()),
                ResponseStreamAction::Terminate(_) => {
                    panic!("ai_token_metrics must never truncate a response stream")
                }
            }
        }
        drop(inspector);
        forwarded = Some(per_chunk);
    }
    let outcome = if complete {
        BodyOutcome::success(0)
    } else {
        BodyOutcome::client_disconnect(0)
    };
    plugin
        .on_response_stream_terminated(ctx, status, &outcome)
        .await;
    forwarded
}

fn priced_streaming_plugin(mut config: serde_json::Value) -> Arc<AiTokenMetrics> {
    config["cost_per_prompt_token"] = json!(0.000001);
    config["cost_per_completion_token"] = json!(0.000002);
    Arc::new(AiTokenMetrics::new(&config).unwrap())
}

const OPENAI_USAGE_STREAM: &str = concat!(
    "data: {\"object\":\"chat.completion.chunk\",\"model\":\"stream-model\",",
    "\"choices\":[{\"delta\":{\"content\":\"he\"}}],\"usage\":null}\n\n",
    "data: {\"object\":\"chat.completion.chunk\",\"model\":\"stream-model\",\"choices\":[],",
    "\"usage\":{\"prompt_tokens\":11,\"completion_tokens\":7,\"total_tokens\":18}}\n\n",
    "data: [DONE]\n\n",
);

/// ai_token_metrics-SOL-2 / ai_token_metrics-claude-1: a live SSE stream is
/// metered without buffering under the DEFAULT configuration. Every chunk is
/// forwarded unchanged at `on_chunk` time (first-token delivery is not
/// delayed), and the terminal hook publishes the same metadata, cost, and
/// Prometheus values the buffered path would, wherever the chunk boundaries
/// fall.
#[tokio::test]
async fn default_config_meters_a_live_sse_stream_without_buffering() {
    let body = OPENAI_USAGE_STREAM.as_bytes();
    for split in (1..body.len()).step_by(17) {
        let plugin = priced_streaming_plugin(json!({}));
        let mut ctx = create_test_context();
        ctx.headers
            .insert("accept".to_string(), "text/event-stream".to_string());
        assert!(
            !plugin.should_buffer_response_body(&ctx),
            "a streamed request must stay unbuffered"
        );
        let (first, rest) = body.split_at(split);
        let forwarded = drive_token_stream(
            &plugin,
            &mut ctx,
            200,
            "text/event-stream",
            &[first, rest],
            true,
        )
        .await
        .expect("a 2xx SSE stream attaches the usage observer");
        assert_eq!(
            forwarded,
            vec![first.to_vec(), rest.to_vec()],
            "split={split}"
        );
        assert_eq!(ctx.metadata["ai_model"], "stream-model");
        assert_eq!(ctx.metadata["ai_streaming"], "true");
        assert!(!ctx.metadata.contains_key("ai_unmetered_reason"));
        assert_usage_and_metrics(&ctx, "openai", Some(11), 7, Some(18), "0.000025");
    }
}

/// A stream the client abandons after the provider already reported usage
/// still publishes it: the observer hands its state back before the terminal
/// hook runs.
#[tokio::test]
async fn client_disconnect_after_the_usage_event_still_publishes_usage() {
    let plugin = priced_streaming_plugin(json!({}));
    let mut ctx = create_test_context();
    let body = OPENAI_USAGE_STREAM.as_bytes();
    let cut = OPENAI_USAGE_STREAM
        .find("data: [DONE]")
        .expect("fixture carries a terminal sentinel");
    drive_token_stream(
        &plugin,
        &mut ctx,
        200,
        "text/event-stream",
        &[&body[..cut]],
        false,
    )
    .await
    .expect("observer attaches");
    assert_usage_and_metrics(&ctx, "openai", Some(11), 7, Some(18), "0.000025");
}

/// AWS Bedrock `InvokeModelWithResponseStream` binary framing is observed
/// incrementally too (it was previously never parsed by this plugin).
#[tokio::test]
async fn bedrock_event_stream_is_metered_incrementally() {
    let inner = serde_json::to_vec(&json!({
        "type": "message_stop",
        "amazon-bedrock-invocationMetrics": {"inputTokenCount": 30, "outputTokenCount": 20}
    }))
    .unwrap();
    let encoded = base64::engine::general_purpose::STANDARD.encode(inner);
    let payload = serde_json::to_vec(&json!({"bytes": encoded})).unwrap();
    let message =
        ferrum_edge::_test_support::encode_aws_event_stream_message_for_test(b"", &payload);
    let (first, rest) = message.split_at(message.len() / 2);

    let plugin = priced_streaming_plugin(json!({}));
    let mut ctx = create_test_context();
    drive_token_stream(
        &plugin,
        &mut ctx,
        200,
        "application/vnd.amazon.eventstream",
        &[first, rest],
        true,
    )
    .await
    .expect("observer attaches to AWS event-stream framing");
    assert_usage_and_metrics(&ctx, "bedrock", Some(30), 20, Some(50), "0.000070");
}

/// A configured provider labels streamed usage, as it does buffered usage.
#[tokio::test]
async fn configured_provider_labels_streamed_usage() {
    let plugin = priced_streaming_plugin(json!({"provider": "mistral"}));
    let mut ctx = create_test_context();
    drive_token_stream(
        &plugin,
        &mut ctx,
        200,
        "text/event-stream",
        &[OPENAI_USAGE_STREAM.as_bytes()],
        true,
    )
    .await
    .expect("observer attaches");
    assert_usage_and_metrics(&ctx, "mistral", Some(11), 7, Some(18), "0.000025");
}

/// Streams that must not be metered get no observer: non-2xx, synthetic
/// short-circuit bodies, non-stream media types, and content-coded origin
/// streams (whose octets the incremental parser cannot read).
#[tokio::test]
async fn ineligible_streams_attach_no_observer() {
    let plugin = priced_streaming_plugin(json!({}));
    let body = OPENAI_USAGE_STREAM.as_bytes();

    for (status, content_type) in [
        (500, "text/event-stream"),
        (429, "text/event-stream"),
        (200, "application/octet-stream"),
        (200, "text/plain"),
    ] {
        let mut ctx = create_test_context();
        assert!(
            drive_token_stream(&plugin, &mut ctx, status, content_type, &[body], true)
                .await
                .is_none(),
            "{status} {content_type}"
        );
        assert!(ctx.authoritative_ai_usage_export().is_none());
        assert!(!ctx.metadata.contains_key("ai_total_tokens"));
        assert!(!ctx.metadata.contains_key("ai_unmetered_reason"));
    }

    let mut synthetic = create_test_context();
    synthetic.metadata.insert(
        SYNTHETIC_SHORT_CIRCUIT_METADATA_KEY.to_string(),
        "true".to_string(),
    );
    assert!(
        drive_token_stream(
            &plugin,
            &mut synthetic,
            200,
            "text/event-stream",
            &[body],
            true
        )
        .await
        .is_none()
    );
    assert!(synthetic.authoritative_ai_usage_export().is_none());
    assert!(!synthetic.metadata.contains_key("ai_unmetered_reason"));

    // A gzip origin stream is delivered untouched and labelled, never parsed.
    let mut encoded = create_test_context();
    let origin_headers = HashMap::from([
        ("content-type".to_string(), "text/event-stream".to_string()),
        ("content-encoding".to_string(), "gzip".to_string()),
    ]);
    ferrum_edge::_test_support::stamp_original_response_metadata_for_test(
        &mut encoded,
        200,
        &origin_headers,
    );
    let compressed = gzip(body);
    assert!(
        drive_token_stream(
            &plugin,
            &mut encoded,
            200,
            "text/event-stream",
            &[compressed.as_slice()],
            true,
        )
        .await
        .is_none()
    );
    assert!(encoded.authoritative_ai_usage_export().is_none());
    assert_eq!(
        encoded.metadata["ai_unmetered_reason"],
        "stream_not_inspected"
    );
}

/// ai_token_metrics-claude-5: a stream that ends without any usage report is
/// labelled rather than silently looking like zero usage.
#[tokio::test]
async fn stream_without_usage_is_labelled_unmetered() {
    let plugin = priced_streaming_plugin(json!({}));
    let mut ctx = create_test_context();
    let body: &[u8] =
        b"data: {\"object\":\"chat.completion.chunk\",\"choices\":[]}\n\ndata: [DONE]\n\n";
    drive_token_stream(&plugin, &mut ctx, 200, "text/event-stream", &[body], true)
        .await
        .expect("observer attaches");
    assert!(ctx.authoritative_ai_usage_export().is_none());
    assert!(!ctx.metadata.contains_key("ai_total_tokens"));
    assert_eq!(ctx.metadata["ai_unmetered_reason"], "stream_without_usage");
}

/// `(plugin, content-encoding, body, expected unmetered reason)`.
type UnmeteredCase<'a> = (&'a AiTokenMetrics, Option<&'a str>, Vec<u8>, &'a str);

/// ai_token_metrics-claude-5: every buffered 2xx skip path names its reason;
/// a later successful extraction clears it; non-2xx, synthetic, and non-JSON
/// responses are not labelled.
#[tokio::test]
async fn buffered_unmetered_responses_name_their_reason() {
    let auto = AiTokenMetrics::new(&json!({})).unwrap();
    let fixed = AiTokenMetrics::new(&json!({"provider": "openai"})).unwrap();
    let oversized = vec![b' '; 4 * 1024 * 1024 + 1];
    let cases: Vec<UnmeteredCase<'_>> = vec![
        (&auto, None, oversized, "body_too_large"),
        (&auto, Some("gzip"), b"not-gzip".to_vec(), "decode_failed"),
        (&auto, Some("zstd"), b"{}".to_vec(), "decode_failed"),
        (&auto, None, b"not valid json".to_vec(), "malformed_body"),
        (
            &auto,
            None,
            br#"{"id":"chatcmpl-123"}"#.to_vec(),
            "provider_undetected",
        ),
        (
            &fixed,
            None,
            br#"{"id":"chatcmpl-123"}"#.to_vec(),
            "no_usage",
        ),
        (&auto, None, Vec::new(), "no_usage"),
    ];
    for (plugin, encoding, body, reason) in cases {
        let mut headers = json_headers();
        if let Some(encoding) = encoding {
            headers.insert("content-encoding".to_string(), encoding.to_string());
        }
        let mut ctx = create_test_context();
        assert_continue(
            plugin
                .on_response_body(&mut ctx, 200, &mut headers, &body)
                .await,
        );
        assert_eq!(ctx.metadata["ai_unmetered_reason"], reason);
        assert!(!ctx.metadata.contains_key("ai_total_tokens"));
    }

    // Buffered SSE without a usage event.
    let mut ctx = create_test_context();
    let mut sse_headers =
        HashMap::from([("content-type".to_string(), "text/event-stream".to_string())]);
    auto.on_response_body(&mut ctx, 200, &mut sse_headers, b"data: {\"x\":1}\n\n")
        .await;
    assert_eq!(ctx.metadata["ai_unmetered_reason"], "no_usage");

    // A successful extraction clears a stale reason.
    let mut ctx = create_test_context();
    ctx.metadata
        .insert("ai_unmetered_reason".to_string(), "no_usage".to_string());
    let body = br#"{"usage":{"prompt_tokens":1,"completion_tokens":2,"total_tokens":3}}"#;
    auto.on_response_body(&mut ctx, 200, &mut json_headers(), body)
        .await;
    assert_eq!(ctx.metadata["ai_total_tokens"], "3");
    assert!(!ctx.metadata.contains_key("ai_unmetered_reason"));

    // Deliberate exclusions are not "unmetered".
    for (status, content_type) in [(500, "application/json"), (200, "text/html")] {
        let mut ctx = create_test_context();
        let mut headers = HashMap::from([("content-type".to_string(), content_type.to_string())]);
        auto.on_response_body(&mut ctx, status, &mut headers, b"not json")
            .await;
        assert!(!ctx.metadata.contains_key("ai_unmetered_reason"));
    }
    let mut ctx = create_test_context();
    ctx.metadata.insert(
        SYNTHETIC_SHORT_CIRCUIT_METADATA_KEY.to_string(),
        "true".to_string(),
    );
    auto.on_response_body(&mut ctx, 200, &mut json_headers(), b"not json")
        .await;
    assert!(!ctx.metadata.contains_key("ai_unmetered_reason"));

    // The reason key follows `metadata_prefix`.
    let prefixed = AiTokenMetrics::new(&json!({"metadata_prefix": "tenant"})).unwrap();
    let mut ctx = create_test_context();
    prefixed
        .on_response_body(&mut ctx, 200, &mut json_headers(), b"not valid json")
        .await;
    assert_eq!(ctx.metadata["tenant_unmetered_reason"], "malformed_body");
}

/// ai_token_metrics-claude-4: the backend-controlled model string is bounded
/// before it reaches metadata (and every log sink); token counts still export.
#[tokio::test]
async fn oversized_or_control_bearing_model_names_are_not_published() {
    let plugin = AiTokenMetrics::new(&json!({})).unwrap();
    let at_limit = "m".repeat(256);
    for (model, published) in [
        (at_limit.as_str(), true),
        ("gpt-4o", true),
        (&*"m".repeat(257), false),
        ("gpt\n-4o", false),
        ("gpt\u{0}4o", false),
        ("", false),
    ] {
        let body = serde_json::to_vec(&json!({
            "model": model,
            "usage": {"prompt_tokens": 3, "completion_tokens": 4, "total_tokens": 7}
        }))
        .unwrap();
        let mut ctx = create_test_context();
        plugin
            .on_response_body(&mut ctx, 200, &mut json_headers(), &body)
            .await;
        assert_eq!(ctx.metadata["ai_total_tokens"], "7");
        assert_eq!(
            ctx.metadata.get("ai_model").map(String::as_str),
            published.then_some(model),
            "model of {} bytes",
            model.len()
        );
    }

    // The streaming observer applies the same bound.
    let streaming = priced_streaming_plugin(json!({}));
    let long_model = "s".repeat(300);
    let stream = format!(
        "data: {}\n\n",
        json!({
            "model": long_model,
            "usage": {"prompt_tokens": 3, "completion_tokens": 4, "total_tokens": 7}
        })
    );
    let mut ctx = create_test_context();
    drive_token_stream(
        &streaming,
        &mut ctx,
        200,
        "text/event-stream",
        &[stream.as_bytes()],
        true,
    )
    .await
    .expect("observer attaches");
    assert_eq!(ctx.metadata["ai_total_tokens"], "7");
    assert!(!ctx.metadata.contains_key("ai_model"));
}

fn usage_body(model: &str) -> Vec<u8> {
    serde_json::to_vec(&json!({
        "model": model,
        "usage": {"prompt_tokens": 10, "completion_tokens": 5, "total_tokens": 15}
    }))
    .unwrap()
}

/// ai_token_metrics-claude-6: one instance prices each model with its own
/// rates (first matching glob wins) and falls back to the flat rates.
#[tokio::test]
async fn model_pricing_selects_the_first_matching_glob_and_falls_back_to_flat_rates() {
    let plugin = AiTokenMetrics::new(&json!({
        "cost_per_prompt_token": 0.0001,
        "cost_per_completion_token": 0.0002,
        "model_pricing": [
            {"model": "gpt-4o-mini*", "cost_per_prompt_token": 0.001, "cost_per_completion_token": 0.002},
            {"model": "gpt-4o*", "cost_per_prompt_token": 0.01, "cost_per_completion_token": 0.02},
            {"model": "claude-*", "cost_per_completion_token": 0.02}
        ]
    }))
    .unwrap();
    for (model, cost) in [
        ("gpt-4o-mini-2024-07-18", Some("0.020000")),
        ("gpt-4o-2024-08-06", Some("0.200000")),
        ("gpt-4o", Some("0.200000")),
        // Omitted entry rate: only the completion side is priced.
        ("claude-sonnet", Some("0.100000")),
        // No match: flat rates.
        ("mistral-large", Some("0.002000")),
        // An unpublishable model never selects an entry.
        (
            &*format!("gpt-4o-mini{}", "x".repeat(300)),
            Some("0.002000"),
        ),
    ] {
        let mut ctx = create_test_context();
        plugin
            .on_response_body(&mut ctx, 200, &mut json_headers(), &usage_body(model))
            .await;
        assert_eq!(
            ctx.metadata.get("ai_estimated_cost").map(String::as_str),
            cost,
            "{model}"
        );
        assert!(ctx.authoritative_ai_usage_export().unwrap().cost.is_some());
    }

    // A response without a model is priced at the flat rates too.
    let mut ctx = create_test_context();
    let body = br#"{"usage":{"prompt_tokens":10,"completion_tokens":5,"total_tokens":15}}"#;
    plugin
        .on_response_body(&mut ctx, 200, &mut json_headers(), body)
        .await;
    assert_eq!(ctx.metadata["ai_estimated_cost"], "0.002000");

    // Without flat rates an unmatched model is unpriced.
    let per_model_only = AiTokenMetrics::new(&json!({
        "model_pricing": [{"model": "gpt-4o*", "cost_per_prompt_token": 0.01}]
    }))
    .unwrap();
    let mut ctx = create_test_context();
    per_model_only
        .on_response_body(&mut ctx, 200, &mut json_headers(), &usage_body("o3"))
        .await;
    assert!(!ctx.metadata.contains_key("ai_estimated_cost"));
    assert!(ctx.authoritative_ai_usage_export().unwrap().cost.is_none());
}

#[test]
fn model_pricing_admission_matches_openapi() {
    let schema = token_metrics_schema();
    let validator = jsonschema::draft202012::options().build(&schema).unwrap();
    let too_many: Vec<_> = (0..129)
        .map(|index| json!({"model": format!("m{index}"), "cost_per_prompt_token": 1}))
        .collect();
    let max: Vec<_> = (0..128)
        .map(|index| json!({"model": format!("m{index}"), "cost_per_prompt_token": 1}))
        .collect();
    for (pricing, accepted) in [
        (json!([]), true),
        (json!(max), true),
        (
            json!([{"model": "gpt-4o*", "cost_per_prompt_token": 0.0000025}]),
            true,
        ),
        (
            json!([{"model": "claude-*", "cost_per_prompt_token": null, "cost_per_completion_token": 0.00001}]),
            true,
        ),
        (
            json!([{"model": "a.b:c/d+e_f-*", "cost_per_completion_token": 0}]),
            true,
        ),
        (json!(too_many), false),
        (json!({}), false),
        (json!(null), false),
        (json!([{"model": "gpt-4o"}]), false),
        (
            json!([{"model": "gpt-4o", "cost_per_prompt_token": null}]),
            false,
        ),
        (json!([{"cost_per_prompt_token": 1}]), false),
        (json!([{"model": "", "cost_per_prompt_token": 1}]), false),
        (
            json!([{"model": "a..b", "cost_per_prompt_token": 1}]),
            false,
        ),
        (
            json!([{"model": "gpt 4", "cost_per_prompt_token": 1}]),
            false,
        ),
        (
            json!([{"model": "m".repeat(257), "cost_per_prompt_token": 1}]),
            false,
        ),
        (
            json!([{"model": "gpt", "cost_per_prompt_token": -1}]),
            false,
        ),
        (
            json!([{"model": "gpt", "cost_per_prompt_token": 18_446_744_073_710.0}]),
            false,
        ),
        (
            json!([{"model": "gpt", "cost_per_prompt_token": "free"}]),
            false,
        ),
        (
            json!([{"model": "gpt", "cost_per_prompt_token": 1, "currency": "usd"}]),
            false,
        ),
        (json!(["gpt-4o"]), false),
    ] {
        let config = json!({"model_pricing": pricing});
        assert_eq!(
            AiTokenMetrics::new(&config).is_ok(),
            accepted,
            "runtime {config}"
        );
        assert_eq!(validator.is_valid(&config), accepted, "schema {config}");
    }
}

/// PR #6857 review MUSE-1: under a retry configuration the proxy releases a
/// response to stream only when this plugin confirms it, so the vote must
/// accept every representation the stream observer meters — AWS event-stream
/// (Bedrock streams, which send no SSE `Accept` hint) as well as SSE — while
/// JSON stays buffered for inspection.
#[test]
fn retry_release_confirms_every_observer_metered_stream_representation() {
    let plugin = AiTokenMetrics::new(&json!({})).unwrap();
    // An AWS SDK request: JSON body, no `Accept: text/event-stream`, no
    // `stream: true` marker, so the pre-header decision buffers.
    let ctx = ctx_with_content_type("POST", "application/json");
    assert!(plugin.should_buffer_response_body(&ctx));
    assert!(plugin.may_release_response_body_under_retries(&ctx));
    for (content_type, released) in [
        ("application/vnd.amazon.eventstream", true),
        ("Application/VND.Amazon.EventStream; charset=binary", true),
        ("text/event-stream", true),
        ("application/json", false),
        ("text/plain", false),
    ] {
        let headers = HashMap::from([("Content-Type".to_string(), content_type.to_string())]);
        assert_eq!(
            plugin.should_release_response_body_under_retries(&ctx, 200, &headers),
            released,
            "{content_type}"
        );
        // Released representations are also not collected without retries.
        if released {
            assert!(!plugin.should_buffer_response_body_for_content_type(
                &ctx,
                Some(content_type),
                200,
                &headers
            ));
        }
    }
}

/// A collected AWS event-stream body (buffered by a sibling, a route policy,
/// or a retry decision) is metered by the same bounded extractor.
#[tokio::test]
async fn collected_aws_event_stream_body_is_metered() {
    let inner = serde_json::to_vec(&json!({
        "type": "message_stop",
        "amazon-bedrock-invocationMetrics": {"inputTokenCount": 30, "outputTokenCount": 20}
    }))
    .unwrap();
    let encoded = base64::engine::general_purpose::STANDARD.encode(inner);
    let payload = serde_json::to_vec(&json!({"bytes": encoded})).unwrap();
    let message =
        ferrum_edge::_test_support::encode_aws_event_stream_message_for_test(b"", &payload);
    let plugin = priced_streaming_plugin(json!({}));
    let mut ctx = create_test_context();
    let mut headers = HashMap::from([(
        "content-type".to_string(),
        "application/vnd.amazon.eventstream".to_string(),
    )]);
    assert_continue(
        plugin
            .on_response_body(&mut ctx, 200, &mut headers, &message)
            .await,
    );
    assert_eq!(ctx.metadata["ai_streaming"], "true");
    assert_usage_and_metrics(&ctx, "bedrock", Some(30), 20, Some(50), "0.000070");

    // A collected event stream without usage is labelled, not silent.
    let empty = ferrum_edge::_test_support::encode_aws_event_stream_message_for_test(
        b"",
        br#"{"bytes":"e30="}"#,
    );
    let mut ctx = create_test_context();
    plugin
        .on_response_body(&mut ctx, 200, &mut headers, &empty)
        .await;
    assert!(ctx.authoritative_ai_usage_export().is_none());
    assert_eq!(ctx.metadata["ai_unmetered_reason"], "no_usage");
}

const INVALIDATED_ANTHROPIC_STREAM: &str = concat!(
    "data: {\"type\":\"message_start\",\"message\":{\"model\":\"claude-test\",",
    "\"usage\":{\"input_tokens\":10,\"output_tokens\":1}}}\n\n",
    "data: {\"type\":\"message_delta\",\"usage\":{\"input_tokens\":20,",
    "\"cache_read_input_tokens\":\"bad\",\"output_tokens\":5}}\n\n",
);

/// PR #6857 review SOL-1: a stream whose malformed categories invalidated
/// every counter was observed but carries no usable usage. Both the live
/// observer and buffered SSE must label it unmetered (and must not clear a
/// stale reason or claim a metered stream), while an explicit zero is still
/// metered.
#[tokio::test]
async fn invalidated_stream_usage_is_labelled_unmetered_on_both_paths() {
    // Live observation.
    let plugin = priced_streaming_plugin(json!({}));
    let mut ctx = create_test_context();
    ctx.metadata
        .insert("ai_unmetered_reason".to_string(), "no_usage".to_string());
    drive_token_stream(
        &plugin,
        &mut ctx,
        200,
        "text/event-stream",
        &[INVALIDATED_ANTHROPIC_STREAM.as_bytes()],
        true,
    )
    .await
    .expect("observer attaches");
    assert!(ctx.authoritative_ai_usage_export().is_none());
    assert!(!ctx.metadata.contains_key("ai_total_tokens"));
    assert!(!ctx.metadata.contains_key("ai_streaming"));
    assert_eq!(ctx.metadata["ai_unmetered_reason"], "stream_without_usage");

    // Buffered SSE.
    let mut ctx = create_test_context();
    let mut headers =
        HashMap::from([("content-type".to_string(), "text/event-stream".to_string())]);
    plugin
        .on_response_body(
            &mut ctx,
            200,
            &mut headers,
            INVALIDATED_ANTHROPIC_STREAM.as_bytes(),
        )
        .await;
    assert!(ctx.authoritative_ai_usage_export().is_none());
    assert!(!ctx.metadata.contains_key("ai_streaming"));
    assert_eq!(ctx.metadata["ai_unmetered_reason"], "no_usage");

    // Control: an explicit zero report is usage, on both paths.
    let zero =
        "data: {\"usage\":{\"prompt_tokens\":0,\"completion_tokens\":0,\"total_tokens\":0}}\n\n";
    let mut ctx = create_test_context();
    drive_token_stream(
        &plugin,
        &mut ctx,
        200,
        "text/event-stream",
        &[zero.as_bytes()],
        true,
    )
    .await
    .expect("observer attaches");
    assert_eq!(ctx.metadata["ai_total_tokens"], "0");
    assert!(!ctx.metadata.contains_key("ai_unmetered_reason"));
    let mut ctx = create_test_context();
    plugin
        .on_response_body(&mut ctx, 200, &mut headers, zero.as_bytes())
        .await;
    assert_eq!(ctx.metadata["ai_total_tokens"], "0");
    assert!(!ctx.metadata.contains_key("ai_unmetered_reason"));
}
