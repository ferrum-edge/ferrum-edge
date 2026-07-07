//! Unit tests for the `ai_transcript_audit` plugin.
//!
//! Config-validation and metadata-emission tests drive the plugin hooks
//! directly. Record-content tests point the HTTP sink at a `wiremock` server
//! and assert on the captured batch (matching the `ai_federation` test style).

use async_trait::async_trait;
use bytes::Bytes;
use ferrum_edge::config::types::DEFAULT_NAMESPACE;
use ferrum_edge::config::{BackendAllowIps, BackendEgressPolicy, PoolConfig};
use ferrum_edge::dns::{DnsCache, DnsConfig};
use ferrum_edge::plugins::ai_transcript_audit::AiTranscriptAudit;
use ferrum_edge::plugins::utils::ai_pii::PiiRedactor;
use ferrum_edge::plugins::{
    HTTP_ONLY_PROTOCOLS, Plugin, PluginFailurePolicy, PluginHttpClient, PluginResult,
    RequestContext, ResponseStreamAction, ResponseStreamInspector,
    chain_response_stream_inspectors, plugin_failure_policy, priority,
};
use ferrum_edge::proxy::deferred_log::BodyOutcome;
use serde_json::{Value, json};
use std::collections::HashMap;
use std::sync::Arc;
use wiremock::matchers::method;
use wiremock::{Mock, MockServer, ResponseTemplate};

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// A `PluginHttpClient` whose egress policy allows loopback, so a wiremock sink
/// at `127.0.0.1` passes construction-time SSRF screening.
fn loopback_http_client() -> PluginHttpClient {
    let backend_allow_ips = BackendEgressPolicy::from_allow_ips(BackendAllowIps::Both);
    let dns_config = DnsConfig {
        backend_allow_ips: backend_allow_ips.clone(),
        ..Default::default()
    };
    PluginHttpClient::new(
        &PoolConfig::default(),
        DnsCache::new(dns_config),
        1000,
        0,
        100,
        false,
        None,
        Arc::new(Vec::new()),
        DEFAULT_NAMESPACE,
        backend_allow_ips,
        Arc::new(Vec::new()),
        0,
    )
}

fn json_headers() -> HashMap<String, String> {
    let mut headers = HashMap::new();
    headers.insert("content-type".to_string(), "application/json".to_string());
    headers
}

fn content_type_headers(content_type: &str) -> HashMap<String, String> {
    let mut headers = HashMap::new();
    headers.insert("content-type".to_string(), content_type.to_string());
    headers
}

fn make_ctx() -> RequestContext {
    let mut ctx = RequestContext::new(
        "127.0.0.1".to_string(),
        "POST".to_string(),
        "/v1/chat/completions".to_string(),
    );
    ctx.headers
        .insert("content-type".to_string(), "application/json".to_string());
    ctx
}

fn ai_request_body() -> &'static [u8] {
    br#"{"model":"gpt-4o","messages":[{"role":"user","content":"my ssn is 123-45-6789"}]}"#
}

/// Config with an HTTP sink pointed at `endpoint`, plus caller overrides merged
/// over the top-level object.
fn config_with_sink(endpoint: &str, overrides: Value) -> Value {
    let mut config = json!({
        "sink": {
            "type": "http",
            "endpoint_url": endpoint,
            "batch_size": 1,
            "flush_interval_ms": 100,
        }
    });
    if let (Some(base), Some(extra)) = (config.as_object_mut(), overrides.as_object()) {
        for (key, value) in extra {
            base.insert(key.clone(), value.clone());
        }
    }
    config
}

/// Poll the mock server until it has received a batch, then return the records.
async fn wait_for_records(server: &MockServer) -> Vec<Value> {
    for _ in 0..60 {
        if let Some(requests) = server.received_requests().await
            && let Some(last) = requests.last()
            && let Ok(body) = serde_json::from_slice::<Value>(&last.body)
            && let Some(records) = body.as_array()
        {
            return records.clone();
        }
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    }
    Vec::new()
}

async fn mock_sink() -> MockServer {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .respond_with(ResponseTemplate::new(200))
        .mount(&server)
        .await;
    server
}

/// Drive request + response capture for `body`/`resp_body`, return emitted records.
async fn capture_roundtrip(config_overrides: Value, resp_body: &[u8]) -> Vec<Value> {
    let server = mock_sink().await;
    let endpoint = format!("{}/ingest", server.uri());
    let plugin = AiTranscriptAudit::new(
        &config_with_sink(&endpoint, config_overrides),
        loopback_http_client(),
    )
    .expect("valid config");
    let mut ctx = make_ctx();
    let headers = json_headers();
    plugin
        .on_final_request_body_with_context(&mut ctx, &headers, ai_request_body())
        .await;
    plugin
        .on_final_response_body(&mut ctx, 200, &headers, resp_body)
        .await;
    wait_for_records(&server).await
}

// ---------------------------------------------------------------------------
// Metadata + protocol
// ---------------------------------------------------------------------------

#[tokio::test]
async fn name_priority_and_protocols() {
    let plugin = AiTranscriptAudit::new(
        &config_with_sink("https://audit.example.com/x", json!({})),
        loopback_http_client(),
    )
    .unwrap();
    assert_eq!(plugin.name(), "ai_transcript_audit");
    assert_eq!(plugin.priority(), priority::AI_TRANSCRIPT_AUDIT);
    assert_eq!(plugin.priority(), 2924);
    assert_eq!(plugin.supported_protocols(), HTTP_ONLY_PROTOCOLS);
    assert_eq!(
        plugin_failure_policy("ai_transcript_audit"),
        Some(PluginFailurePolicy::FailClosed)
    );
    assert_eq!(
        plugin.warmup_hostnames(),
        vec!["audit.example.com".to_string()]
    );
}

// ---------------------------------------------------------------------------
// Config validation
// ---------------------------------------------------------------------------

#[tokio::test]
async fn config_must_be_object() {
    let err = AiTranscriptAudit::new(&json!("nope"), loopback_http_client())
        .err()
        .expect("expected config rejection");
    assert!(err.contains("must be an object"), "got: {err}");
}

#[tokio::test]
async fn sink_is_required() {
    let err = AiTranscriptAudit::new(&json!({ "mode": "redacted_body" }), loopback_http_client())
        .err()
        .expect("expected config rejection");
    assert!(
        err.contains("'sink' configuration is required"),
        "got: {err}"
    );
}

#[tokio::test]
async fn full_body_requires_explicit_opt_in() {
    let config = config_with_sink(
        "https://audit.example.com/x",
        json!({ "mode": "full_body" }),
    );
    let err = AiTranscriptAudit::new(&config, loopback_http_client())
        .err()
        .expect("expected config rejection");
    assert!(err.contains("allow_full_body"), "got: {err}");

    // With the opt-in it constructs.
    let ok = config_with_sink(
        "https://audit.example.com/x",
        json!({ "mode": "full_body", "allow_full_body": true }),
    );
    assert!(AiTranscriptAudit::new(&ok, loopback_http_client()).is_ok());
}

#[tokio::test]
async fn invalid_mode_rejected() {
    let config = config_with_sink(
        "https://audit.example.com/x",
        json!({ "mode": "everything" }),
    );
    let err = AiTranscriptAudit::new(&config, loopback_http_client())
        .err()
        .expect("expected config rejection");
    assert!(err.contains("'mode' must be one of"), "got: {err}");
}

#[tokio::test]
async fn all_captures_disabled_rejected() {
    let config = config_with_sink(
        "https://audit.example.com/x",
        json!({ "capture": { "request": false, "response": false, "streaming_response": false } }),
    );
    let err = AiTranscriptAudit::new(&config, loopback_http_client())
        .err()
        .expect("expected config rejection");
    assert!(err.contains("at least one of"), "got: {err}");
}

#[tokio::test]
async fn sampling_rate_out_of_range_rejected() {
    let config = config_with_sink(
        "https://audit.example.com/x",
        json!({ "sampling": { "rate": 1.5 } }),
    );
    let err = AiTranscriptAudit::new(&config, loopback_http_client())
        .err()
        .expect("expected config rejection");
    assert!(err.contains("sampling.rate"), "got: {err}");
}

#[tokio::test]
async fn zero_limit_rejected() {
    let config = config_with_sink(
        "https://audit.example.com/x",
        json!({ "limits": { "max_request_bytes": 0 } }),
    );
    let err = AiTranscriptAudit::new(&config, loopback_http_client())
        .err()
        .expect("expected config rejection");
    assert!(err.contains("max_request_bytes"), "got: {err}");
}

#[tokio::test]
async fn invalid_on_buffer_full_rejected() {
    let config = json!({
        "sink": { "type": "http", "endpoint_url": "https://audit.example.com/x", "on_buffer_full": "explode" }
    });
    let err = AiTranscriptAudit::new(&config, loopback_http_client())
        .err()
        .expect("expected config rejection");
    assert!(err.contains("on_buffer_full"), "got: {err}");
}

#[tokio::test]
async fn invalid_custom_regex_rejected() {
    let config = config_with_sink(
        "https://audit.example.com/x",
        json!({ "redaction": { "custom_patterns": [{ "name": "bad", "regex": "([" }] } }),
    );
    let err = AiTranscriptAudit::new(&config, loopback_http_client())
        .err()
        .expect("expected config rejection");
    assert!(err.contains("custom redaction pattern"), "got: {err}");
}

#[tokio::test]
async fn unknown_builtin_pattern_rejected() {
    let config = config_with_sink(
        "https://audit.example.com/x",
        json!({ "redaction": { "builtins": ["not_a_real_pattern"] } }),
    );
    let err = AiTranscriptAudit::new(&config, loopback_http_client())
        .err()
        .expect("expected config rejection");
    assert!(
        err.contains("unknown built-in redaction pattern"),
        "got: {err}"
    );
}

#[tokio::test]
async fn non_http_sink_scheme_rejected() {
    let config = json!({
        "sink": { "type": "http", "endpoint_url": "ftp://audit.example.com/x" }
    });
    let err = AiTranscriptAudit::new(&config, loopback_http_client())
        .err()
        .expect("expected config rejection");
    assert!(err.contains("http:// or https://"), "got: {err}");
}

// ---------------------------------------------------------------------------
// Request-side metadata emission
// ---------------------------------------------------------------------------

#[tokio::test]
async fn ai_request_sets_candidate_metadata() {
    let plugin = AiTranscriptAudit::new(
        &config_with_sink("https://audit.example.com/x", json!({})),
        loopback_http_client(),
    )
    .unwrap();
    let mut ctx = make_ctx();
    let headers = json_headers();
    let result = plugin
        .on_final_request_body_with_context(&mut ctx, &headers, ai_request_body())
        .await;
    assert!(matches!(result, PluginResult::Continue));
    assert_eq!(
        ctx.metadata
            .get("ai_transcript_audit.candidate")
            .map(String::as_str),
        Some("true")
    );
    assert!(ctx.metadata.contains_key("ai_transcript_audit.record_id"));
    let hash = ctx
        .metadata
        .get("ai_transcript_audit.request_hash")
        .expect("request hash");
    assert_eq!(hash.len(), 64, "sha256 hex should be 64 chars");
    // The raw SSN must never appear in the transaction-log metadata.
    for value in ctx.metadata.values() {
        assert!(
            !value.contains("123-45-6789"),
            "PII leaked into metadata: {value}"
        );
    }
}

#[tokio::test]
async fn non_ai_json_is_not_a_candidate() {
    let plugin = AiTranscriptAudit::new(
        &config_with_sink("https://audit.example.com/x", json!({})),
        loopback_http_client(),
    )
    .unwrap();
    let mut ctx = make_ctx();
    let headers = json_headers();
    plugin
        .on_final_request_body_with_context(&mut ctx, &headers, br#"{"order_id":42,"total":9.99}"#)
        .await;
    assert_eq!(
        ctx.metadata
            .get("ai_transcript_audit.candidate")
            .map(String::as_str),
        Some("false")
    );
    assert!(!ctx.metadata.contains_key("ai_transcript_audit.record_id"));
}

#[tokio::test]
async fn non_candidate_json_does_not_request_response_buffering() {
    let plugin = AiTranscriptAudit::new(
        &config_with_sink("https://audit.example.com/x", json!({})),
        loopback_http_client(),
    )
    .unwrap();
    let mut ctx = make_ctx();
    ctx.metadata
        .insert("request_body".to_string(), r#"{"order_id":42}"#.to_string());
    let mut headers = json_headers();
    plugin.before_proxy(&mut ctx, &mut headers).await;
    assert_eq!(
        ctx.metadata
            .get("ai_transcript_audit.candidate")
            .map(String::as_str),
        Some("false")
    );
    assert!(
        !plugin.should_buffer_response_body(&ctx),
        "explicit candidate=false must suppress the JSON fallback"
    );
}

#[tokio::test]
async fn before_proxy_reads_live_header_argument() {
    let plugin = AiTranscriptAudit::new(
        &config_with_sink("https://audit.example.com/x", json!({})),
        loopback_http_client(),
    )
    .unwrap();
    let mut ctx = make_ctx();
    ctx.headers.clear();
    ctx.metadata.insert(
        "request_body".to_string(),
        String::from_utf8(ai_request_body().to_vec()).unwrap(),
    );
    let mut headers = json_headers();
    plugin.before_proxy(&mut ctx, &mut headers).await;
    assert_eq!(
        ctx.metadata
            .get("ai_transcript_audit.candidate")
            .map(String::as_str),
        Some("true")
    );
}

#[tokio::test]
async fn final_request_body_rechecks_after_non_candidate_pretransform_body() {
    let plugin = AiTranscriptAudit::new(
        &config_with_sink("https://audit.example.com/x", json!({})),
        loopback_http_client(),
    )
    .unwrap();
    let mut ctx = make_ctx();
    ctx.metadata
        .insert("request_body".to_string(), r#"{"order_id":42}"#.to_string());
    let mut proxy_headers = json_headers();
    plugin.before_proxy(&mut ctx, &mut proxy_headers).await;
    assert_eq!(
        ctx.metadata
            .get("ai_transcript_audit.candidate")
            .map(String::as_str),
        Some("false")
    );

    let headers = json_headers();
    plugin
        .on_final_request_body_with_context(&mut ctx, &headers, ai_request_body())
        .await;
    assert_eq!(
        ctx.metadata
            .get("ai_transcript_audit.candidate")
            .map(String::as_str),
        Some("true")
    );
    assert!(ctx.metadata.contains_key("ai_transcript_audit.record_id"));
}

// ---------------------------------------------------------------------------
// Record content (via wiremock sink)
// ---------------------------------------------------------------------------

#[tokio::test]
async fn request_capture_redacts_pii() {
    let records = capture_roundtrip(
        json!({ "mode": "redacted_body" }),
        br#"{"choices":[{"message":{"content":"ok"}}]}"#,
    )
    .await;
    assert_eq!(records.len(), 1, "expected one record");
    let request_body = records[0]["request_body"]
        .as_str()
        .expect("request_body present");
    assert!(
        !request_body.contains("123-45-6789"),
        "SSN not redacted: {request_body}"
    );
    assert!(
        request_body.contains("[REDACTED"),
        "expected placeholder: {request_body}"
    );
    assert_eq!(records[0]["mode"], "redacted_body");
    assert_eq!(records[0]["model"], "gpt-4o");
    assert!(records[0]["request_hash"].is_string());
}

#[tokio::test]
async fn request_capture_redacts_decoded_json_string_escapes() {
    let server = mock_sink().await;
    let endpoint = format!("{}/ingest", server.uri());
    let plugin = AiTranscriptAudit::new(
        &config_with_sink(&endpoint, json!({ "mode": "redacted_body" })),
        loopback_http_client(),
    )
    .unwrap();
    let mut ctx = make_ctx();
    let headers = json_headers();
    plugin
        .on_final_request_body_with_context(
            &mut ctx,
            &headers,
            br#"{"model":"gpt-4o","messages":[{"role":"user","content":"my ssn is 123\u002d45\u002d6789"}]}"#,
        )
        .await;
    plugin
        .on_final_response_body(&mut ctx, 200, &headers, br#"{"ok":true}"#)
        .await;
    let records = wait_for_records(&server).await;
    assert_eq!(records.len(), 1);
    let request_body = records[0]["request_body"].as_str().unwrap();
    assert!(
        !request_body.contains("123-45-6789") && !request_body.contains("123\\u002d45"),
        "escaped SSN was not redacted after JSON decoding: {request_body}"
    );
    assert!(request_body.contains("[REDACTED"));
}

#[tokio::test]
async fn request_capture_redacts_json_keys_and_numeric_scalars() {
    let server = mock_sink().await;
    let endpoint = format!("{}/ingest", server.uri());
    let plugin = AiTranscriptAudit::new(
        &config_with_sink(
            &endpoint,
            json!({
                "mode": "redacted_body",
                "redaction": {
                    "builtins": [],
                    "custom_patterns": [
                        { "name": "email", "regex": "jane@example\\.com" },
                        { "name": "digits", "regex": "123456789" }
                    ]
                }
            }),
        ),
        loopback_http_client(),
    )
    .unwrap();
    let mut ctx = make_ctx();
    let headers = json_headers();
    plugin
        .on_final_request_body_with_context(
            &mut ctx,
            &headers,
            br#"{"model":"gpt-4o","messages":[],"jane@example.com":"key","ssn":123456789}"#,
        )
        .await;
    plugin
        .on_final_response_body(&mut ctx, 200, &headers, br#"{"ok":true}"#)
        .await;
    let records = wait_for_records(&server).await;
    assert_eq!(records.len(), 1);
    let request_body = records[0]["request_body"].as_str().unwrap();
    assert!(!request_body.contains("jane@example.com"), "{request_body}");
    assert!(!request_body.contains("123456789"), "{request_body}");
    assert!(request_body.contains("[REDACTED:email"), "{request_body}");
    assert!(request_body.contains("[REDACTED:digits"), "{request_body}");
}

#[tokio::test]
async fn request_capture_applies_custom_redactor_to_serialized_json_payload() {
    let server = mock_sink().await;
    let endpoint = format!("{}/ingest", server.uri());
    let plugin = AiTranscriptAudit::new(
        &config_with_sink(
            &endpoint,
            json!({
                "mode": "redacted_body",
                "redaction": {
                    "builtins": [],
                    "custom_patterns": [
                        { "name": "context", "regex": "\"content\":\"context-secret\"" }
                    ]
                }
            }),
        ),
        loopback_http_client(),
    )
    .unwrap();
    let mut ctx = make_ctx();
    let headers = json_headers();
    plugin
        .on_final_request_body_with_context(
            &mut ctx,
            &headers,
            br#"{"model":"gpt-4o","messages":[{"role":"user","content":"context-secret"}]}"#,
        )
        .await;
    plugin
        .on_final_response_body(&mut ctx, 200, &headers, br#"{"ok":true}"#)
        .await;
    let records = wait_for_records(&server).await;
    assert_eq!(records.len(), 1);
    let request_body = records[0]["request_body"].as_str().unwrap();
    assert!(
        !request_body.contains("context-secret"),
        "context-dependent custom redactor did not see full JSON payload: {request_body}"
    );
    assert!(request_body.contains("[REDACTED:context"), "{request_body}");
}

#[tokio::test]
async fn response_capture_redacts_pii() {
    let records = capture_roundtrip(
        json!({ "mode": "redacted_body", "redaction": { "builtins": ["email"] } }),
        br#"{"choices":[{"message":{"content":"reach me at jane.doe@example.com"}}]}"#,
    )
    .await;
    assert_eq!(records.len(), 1);
    let response_body = records[0]["response_body"]
        .as_str()
        .expect("response_body present");
    assert!(
        !response_body.contains("jane.doe@example.com"),
        "email not redacted: {response_body}"
    );
    assert!(
        response_body.contains("[REDACTED"),
        "expected placeholder: {response_body}"
    );
    assert!(records[0]["response_hash"].is_string());
}

#[tokio::test]
async fn non_json_buffered_response_does_not_export_body_or_hash() {
    let server = mock_sink().await;
    let endpoint = format!("{}/ingest", server.uri());
    let plugin = AiTranscriptAudit::new(
        &config_with_sink(&endpoint, json!({ "mode": "redacted_body" })),
        loopback_http_client(),
    )
    .unwrap();
    let mut ctx = make_ctx();
    let request_headers = json_headers();
    plugin
        .on_final_request_body_with_context(&mut ctx, &request_headers, ai_request_body())
        .await;
    let response_headers = content_type_headers("text/html");
    plugin
        .on_final_response_body(
            &mut ctx,
            200,
            &response_headers,
            b"<html>not an AI JSON response</html>",
        )
        .await;
    let records = wait_for_records(&server).await;
    assert_eq!(records.len(), 1);
    assert!(records[0].get("response_body").is_none());
    assert!(records[0].get("response_hash").is_none());
    assert!(
        !ctx.metadata
            .contains_key("ai_transcript_audit.response_hash")
    );
}

#[tokio::test]
async fn buffered_sse_response_capture_uses_streaming_policy() {
    let server = mock_sink().await;
    let endpoint = format!("{}/ingest", server.uri());
    let plugin = AiTranscriptAudit::new(
        &config_with_sink(
            &endpoint,
            json!({
                "mode": "redacted_body",
                "capture": { "streaming_response": true },
                "redaction": { "builtins": ["email"] }
            }),
        ),
        loopback_http_client(),
    )
    .unwrap();
    let mut ctx = make_ctx();
    plugin
        .on_final_request_body_with_context(&mut ctx, &json_headers(), ai_request_body())
        .await;
    let response_headers = content_type_headers("text/event-stream");
    let body = br#"data: {"choices":[{"delta":{"content":"email jane.doe@example.com"}}]}

data: [DONE]

"#;
    plugin
        .on_final_response_body(&mut ctx, 200, &response_headers, body)
        .await;
    let records = wait_for_records(&server).await;
    assert_eq!(records.len(), 1);
    let excerpt = records[0]["response_body"]
        .as_str()
        .expect("buffered SSE response body captured");
    assert!(!excerpt.contains("jane.doe@example.com"), "{excerpt}");
    assert!(excerpt.contains("[REDACTED"), "{excerpt}");
    assert!(records[0]["response_hash"].is_string());
    assert!(
        ctx.metadata
            .contains_key("ai_transcript_audit.response_hash")
    );
}

#[tokio::test]
async fn metadata_only_emits_no_body() {
    let records = capture_roundtrip(
        json!({ "mode": "metadata_only" }),
        br#"{"choices":[{"message":{"content":"hello"}}]}"#,
    )
    .await;
    assert_eq!(records.len(), 1);
    assert!(
        records[0].get("request_body").is_none(),
        "metadata_only must not carry a body"
    );
    assert!(
        records[0].get("response_body").is_none(),
        "metadata_only must not carry a body"
    );
    // Hashes and model metadata are still present.
    assert!(records[0]["request_hash"].is_string());
    assert!(records[0]["response_hash"].is_string());
    assert_eq!(records[0]["model"], "gpt-4o");
}

#[tokio::test]
async fn hash_only_emits_hashes_without_body_or_metadata() {
    let records = capture_roundtrip(
        json!({ "mode": "hash_only" }),
        br#"{"model":"gpt-4o","choices":[{"message":{"content":"hi"}}]}"#,
    )
    .await;
    assert_eq!(records.len(), 1);
    assert!(records[0]["request_hash"].is_string());
    assert!(records[0]["response_hash"].is_string());
    assert!(records[0].get("request_body").is_none());
    assert!(records[0].get("response_body").is_none());
    // hash_only strips harvested metadata down to the envelope.
    assert!(
        records[0].get("model").is_none(),
        "hash_only must not carry model"
    );
    assert!(
        records[0].get("tokens").is_none(),
        "hash_only must not carry tokens"
    );
}

#[tokio::test]
async fn sampling_rate_zero_skips_by_default() {
    // rate 0 with no guardrail/error: nothing should be emitted.
    let server = mock_sink().await;
    let endpoint = format!("{}/ingest", server.uri());
    let config = config_with_sink(
        &endpoint,
        json!({ "sampling": { "rate": 0.0, "always_capture_on_guardrail": true } }),
    );
    let plugin = AiTranscriptAudit::new(&config, loopback_http_client()).unwrap();
    let mut ctx = make_ctx();
    let headers = json_headers();
    plugin
        .on_final_request_body_with_context(&mut ctx, &headers, ai_request_body())
        .await;
    plugin
        .on_final_response_body(&mut ctx, 200, &headers, br#"{"ok":true}"#)
        .await;
    // Give any (erroneous) async send a chance to arrive.
    tokio::time::sleep(std::time::Duration::from_millis(300)).await;
    let received = server.received_requests().await.unwrap_or_default();
    assert!(
        received.is_empty(),
        "rate 0 without guardrail should emit nothing"
    );
    assert_eq!(
        ctx.metadata
            .get("ai_transcript_audit.sampled")
            .map(String::as_str),
        Some("false")
    );
}

#[tokio::test]
async fn sampling_rate_zero_still_captures_on_guardrail() {
    let server = mock_sink().await;
    let endpoint = format!("{}/ingest", server.uri());
    let config = config_with_sink(
        &endpoint,
        json!({ "sampling": { "rate": 0.0, "always_capture_on_guardrail": true } }),
    );
    let plugin = AiTranscriptAudit::new(&config, loopback_http_client()).unwrap();
    let mut ctx = make_ctx();
    let headers = json_headers();
    plugin
        .on_final_request_body_with_context(&mut ctx, &headers, ai_request_body())
        .await;
    // Simulate a downstream guard firing before the response is finalized.
    ctx.metadata
        .insert("ai_response_guard_detected".to_string(), "true".to_string());
    plugin
        .on_final_response_body(&mut ctx, 200, &headers, br#"{"ok":true}"#)
        .await;
    let records = wait_for_records(&server).await;
    assert_eq!(
        records.len(),
        1,
        "guardrail should force capture despite rate 0"
    );
    assert_eq!(records[0]["capture_reason"], "guardrail");
}

#[tokio::test]
async fn sampling_rate_zero_captures_non_empty_guardrail_metadata() {
    let server = mock_sink().await;
    let endpoint = format!("{}/ingest", server.uri());
    let config = config_with_sink(
        &endpoint,
        json!({ "sampling": { "rate": 0.0, "always_capture_on_guardrail": true } }),
    );
    let plugin = AiTranscriptAudit::new(&config, loopback_http_client()).unwrap();
    let mut ctx = make_ctx();
    let headers = json_headers();
    plugin
        .on_final_request_body_with_context(&mut ctx, &headers, ai_request_body())
        .await;
    ctx.metadata.insert(
        "ai_response_guard_detected".to_string(),
        "ssn,email".to_string(),
    );
    plugin
        .on_final_response_body(&mut ctx, 200, &headers, br#"{"ok":true}"#)
        .await;
    let records = wait_for_records(&server).await;
    assert_eq!(records.len(), 1);
    assert_eq!(records[0]["capture_reason"], "guardrail");
}

#[tokio::test]
async fn sampling_rate_zero_captures_reject_guardrail_markers() {
    for (key, value) in [
        ("ai_shield_rejected", "ssn"),
        ("ai_response_guard_rejected", "email"),
    ] {
        let server = mock_sink().await;
        let endpoint = format!("{}/ingest", server.uri());
        let config = config_with_sink(
            &endpoint,
            json!({ "sampling": { "rate": 0.0, "always_capture_on_guardrail": true } }),
        );
        let plugin = AiTranscriptAudit::new(&config, loopback_http_client()).unwrap();
        let mut ctx = make_ctx();
        let headers = json_headers();
        plugin
            .on_final_request_body_with_context(&mut ctx, &headers, ai_request_body())
            .await;
        ctx.metadata.insert(key.to_string(), value.to_string());
        plugin
            .on_final_response_body(&mut ctx, 200, &headers, br#"{"ok":true}"#)
            .await;
        let records = wait_for_records(&server).await;
        assert_eq!(records.len(), 1, "expected guardrail capture for {key}");
        assert_eq!(records[0]["capture_reason"], "guardrail");
    }
}

#[tokio::test]
async fn sampling_rate_zero_captures_scoped_semantic_firewall_metadata() {
    let server = mock_sink().await;
    let endpoint = format!("{}/ingest", server.uri());
    let config = config_with_sink(
        &endpoint,
        json!({ "sampling": { "rate": 0.0, "always_capture_on_guardrail": true } }),
    );
    let plugin = AiTranscriptAudit::new(&config, loopback_http_client()).unwrap();
    let mut ctx = make_ctx();
    let headers = json_headers();
    plugin
        .on_final_request_body_with_context(&mut ctx, &headers, ai_request_body())
        .await;
    ctx.metadata.insert(
        "ai_semantic_firewall.response.decision".to_string(),
        "warn".to_string(),
    );
    plugin
        .on_final_response_body(&mut ctx, 200, &headers, br#"{"ok":true}"#)
        .await;
    let records = wait_for_records(&server).await;
    assert_eq!(records.len(), 1);
    assert_eq!(records[0]["capture_reason"], "guardrail");
}

#[tokio::test]
async fn error_status_capture_reason_is_error() {
    let server = mock_sink().await;
    let endpoint = format!("{}/ingest", server.uri());
    let config = config_with_sink(
        &endpoint,
        json!({ "sampling": { "rate": 0.0, "always_capture_on_error": true } }),
    );
    let plugin = AiTranscriptAudit::new(&config, loopback_http_client()).unwrap();
    let mut ctx = make_ctx();
    let headers = json_headers();
    plugin
        .on_final_request_body_with_context(&mut ctx, &headers, ai_request_body())
        .await;
    plugin
        .on_final_response_body(&mut ctx, 500, &headers, br#"{"error":"boom"}"#)
        .await;
    let records = wait_for_records(&server).await;
    assert_eq!(records.len(), 1);
    assert_eq!(records[0]["capture_reason"], "error");
    assert_eq!(records[0]["status_code"], 500);
}

// ---------------------------------------------------------------------------
// before_proxy staging + hook advertisement
// ---------------------------------------------------------------------------

#[tokio::test]
async fn advertises_prebuffer_and_context_body_hooks() {
    let plugin = AiTranscriptAudit::new(
        &config_with_sink("https://audit.example.com/x", json!({})),
        loopback_http_client(),
    )
    .unwrap();
    // Without these, staging never happens: the context-free final-body
    // default would run instead of the context-aware hook, and the body would
    // not be prebuffered for before_proxy classification.
    assert!(plugin.requires_request_body_buffering());
    assert!(plugin.requires_request_body_before_before_proxy());
    assert!(plugin.needs_final_request_body_context());
}

#[tokio::test]
async fn before_proxy_stages_candidate_from_prebuffered_body() {
    let plugin = AiTranscriptAudit::new(
        &config_with_sink(
            "https://audit.example.com/x",
            json!({ "capture": { "streaming_response": true } }),
        ),
        loopback_http_client(),
    )
    .unwrap();
    let mut ctx = make_ctx();
    let body_str = std::str::from_utf8(ai_request_body()).unwrap();
    ctx.metadata
        .insert("request_body".to_string(), body_str.to_string());
    let mut headers = ctx.headers.clone();
    let result = plugin.before_proxy(&mut ctx, &mut headers).await;
    assert!(matches!(result, PluginResult::Continue));
    assert_eq!(
        ctx.metadata
            .get("ai_transcript_audit.candidate")
            .map(String::as_str),
        Some("true"),
        "candidate must be staged in before_proxy, before terminators and buffering decisions"
    );
    assert!(ctx.metadata.contains_key("ai_transcript_audit.record_id"));
    // Streaming capture marker must exist before backend dispatch so
    // forces_reqwest_dispatch can keep the response off native-H3.
    assert_eq!(
        ctx.metadata
            .get("ai_transcript_audit.stream_marker")
            .map(String::as_str),
        Some("true")
    );
    assert!(plugin.forces_reqwest_dispatch(&ctx));
    // The prebuffered body must be preserved for later before_proxy plugins
    // (e.g. ai_federation reads it from the same metadata slot).
    assert_eq!(
        ctx.metadata.get("request_body").map(String::as_str),
        Some(body_str)
    );
    // Response buffering refinement sees the candidate.
    assert!(plugin.should_buffer_response_body(&ctx));
}

#[tokio::test]
async fn streaming_capture_marks_json_shape_before_transform_classification() {
    let plugin = AiTranscriptAudit::new(
        &config_with_sink(
            "https://audit.example.com/x",
            json!({ "capture": { "streaming_response": true } }),
        ),
        loopback_http_client(),
    )
    .unwrap();
    let mut ctx = make_ctx();
    ctx.metadata
        .insert("request_body".to_string(), r#"{"order_id":42}"#.to_string());
    let mut headers = ctx.headers.clone();
    plugin.before_proxy(&mut ctx, &mut headers).await;
    assert_eq!(
        ctx.metadata
            .get("ai_transcript_audit.candidate")
            .map(String::as_str),
        Some("false")
    );
    assert!(
        plugin.forces_reqwest_dispatch(&ctx),
        "stream marker must be available before dispatch decisions in case a later request transform creates an AI body"
    );
    assert!(
        !plugin.should_buffer_response_body(&ctx),
        "non-candidate JSON should still avoid buffered-response capture"
    );

    plugin
        .on_final_request_body_with_context(&mut ctx, &json_headers(), ai_request_body())
        .await;
    assert_eq!(
        ctx.metadata
            .get("ai_transcript_audit.candidate")
            .map(String::as_str),
        Some("true")
    );
    assert!(ctx.metadata.contains_key("ai_transcript_audit.record_id"));
}

#[tokio::test]
async fn final_body_hook_refreshes_staged_capture_after_transforms() {
    let server = mock_sink().await;
    let endpoint = format!("{}/ingest", server.uri());
    let plugin = AiTranscriptAudit::new(
        &config_with_sink(&endpoint, json!({})),
        loopback_http_client(),
    )
    .unwrap();
    let mut ctx = make_ctx();
    ctx.metadata.insert(
        "request_body".to_string(),
        std::str::from_utf8(ai_request_body()).unwrap().to_string(),
    );
    let mut proxy_headers = ctx.headers.clone();
    plugin.before_proxy(&mut ctx, &mut proxy_headers).await;
    let staged_hash = ctx
        .metadata
        .get("ai_transcript_audit.request_hash")
        .cloned()
        .expect("staged hash");

    // A request transform changed the body; the final hook must refresh the
    // captured hash/excerpt/model with the final backend-visible bytes.
    let final_body =
        br#"{"model":"gpt-4o-mini","messages":[{"role":"user","content":"transformed"}]}"#;
    let headers = json_headers();
    plugin
        .on_final_request_body_with_context(&mut ctx, &headers, final_body)
        .await;
    let refreshed_hash = ctx
        .metadata
        .get("ai_transcript_audit.request_hash")
        .cloned()
        .expect("refreshed hash");
    assert_ne!(
        staged_hash, refreshed_hash,
        "hash must track the final body"
    );

    plugin
        .on_final_response_body(&mut ctx, 200, &headers, br#"{"ok":true}"#)
        .await;
    let records = wait_for_records(&server).await;
    assert_eq!(records.len(), 1);
    assert_eq!(records[0]["model"], "gpt-4o-mini");
    let excerpt = records[0]["request_body"].as_str().expect("request body");
    assert!(excerpt.contains("transformed"), "got: {excerpt}");
}

#[tokio::test]
async fn backend_path_after_proxy_does_not_revert_final_request_capture_from_stale_metadata() {
    let server = mock_sink().await;
    let endpoint = format!("{}/ingest", server.uri());
    let plugin = AiTranscriptAudit::new(
        &config_with_sink(&endpoint, json!({})),
        loopback_http_client(),
    )
    .unwrap();
    let mut ctx = make_ctx();
    ctx.metadata.insert(
        "request_body".to_string(),
        std::str::from_utf8(ai_request_body()).unwrap().to_string(),
    );
    let mut proxy_headers = ctx.headers.clone();
    plugin.before_proxy(&mut ctx, &mut proxy_headers).await;

    let final_body =
        br#"{"model":"gpt-4o-mini","messages":[{"role":"user","content":"backend-visible"}]}"#;
    let headers = json_headers();
    plugin
        .on_final_request_body_with_context(&mut ctx, &headers, final_body)
        .await;
    // The real proxy preserves the original request_body metadata across the
    // final-body context swap. A stale after_proxy refresh must not overwrite the
    // final backend-visible capture.
    ctx.metadata.insert(
        "request_body".to_string(),
        std::str::from_utf8(ai_request_body()).unwrap().to_string(),
    );
    let mut response_headers = HashMap::new();
    plugin
        .after_proxy(&mut ctx, 200, &mut response_headers)
        .await;
    plugin
        .on_final_response_body(&mut ctx, 200, &headers, br#"{"ok":true}"#)
        .await;
    let records = wait_for_records(&server).await;
    assert_eq!(records.len(), 1);
    assert_eq!(records[0]["model"], "gpt-4o-mini");
    let excerpt = records[0]["request_body"].as_str().expect("request body");
    assert!(excerpt.contains("backend-visible"), "got: {excerpt}");
}

#[tokio::test]
async fn synthetic_response_refreshes_live_request_metadata_before_emitting() {
    let server = mock_sink().await;
    let endpoint = format!("{}/ingest", server.uri());
    let plugin = AiTranscriptAudit::new(
        &config_with_sink(&endpoint, json!({})),
        loopback_http_client(),
    )
    .unwrap();
    let mut ctx = make_ctx();
    ctx.metadata.insert(
        "request_body".to_string(),
        std::str::from_utf8(ai_request_body()).unwrap().to_string(),
    );
    let mut proxy_headers = ctx.headers.clone();
    plugin.before_proxy(&mut ctx, &mut proxy_headers).await;
    ctx.metadata.insert(
        "request_body".to_string(),
        r#"{"model":"gpt-4o-mini","messages":[{"role":"user","content":"synthetic-visible"}]}"#
            .to_string(),
    );
    ctx.metadata.insert(
        "ferrum:synthetic_short_circuit".to_string(),
        "true".to_string(),
    );

    let headers = json_headers();
    plugin
        .on_final_response_body(&mut ctx, 200, &headers, br#"{"ok":true}"#)
        .await;
    let records = wait_for_records(&server).await;
    assert_eq!(records.len(), 1);
    assert_eq!(records[0]["model"], "gpt-4o-mini");
    let excerpt = records[0]["request_body"].as_str().expect("request body");
    assert!(excerpt.contains("synthetic-visible"), "got: {excerpt}");
}

// ---------------------------------------------------------------------------
// Streaming capture policy
// ---------------------------------------------------------------------------

#[tokio::test]
async fn sampled_streaming_capture_honors_sampling_rate() {
    let plugin = AiTranscriptAudit::new(
        &config_with_sink(
            "https://audit.example.com/x",
            json!({
                "capture": { "streaming_response": "sampled" },
                "sampling": { "rate": 0.0 }
            }),
        ),
        loopback_http_client(),
    )
    .unwrap();
    let headers = json_headers();

    // rate 0, no guardrail: the stream must NOT be teed just because the
    // always_capture_* defaults are on.
    let mut ctx = make_ctx();
    plugin
        .on_final_request_body_with_context(&mut ctx, &headers, ai_request_body())
        .await;
    assert!(
        !ctx.metadata
            .contains_key("ai_transcript_audit.stream_marker"),
        "sampled mode must honor sampling.rate for the tee decision"
    );
    assert!(!plugin.forces_reqwest_dispatch(&ctx));

    // A request-side guardrail already fired: always_capture_on_guardrail
    // justifies the tee even for an un-sampled request.
    let mut guardrail_ctx = make_ctx();
    guardrail_ctx
        .metadata
        .insert("ai_shield_redacted".to_string(), "true".to_string());
    plugin
        .on_final_request_body_with_context(&mut guardrail_ctx, &headers, ai_request_body())
        .await;
    assert_eq!(
        guardrail_ctx
            .metadata
            .get("ai_transcript_audit.stream_marker")
            .map(String::as_str),
        Some("true")
    );
}

#[tokio::test]
async fn error_sse_response_is_teed_when_error_capture_enabled() {
    let plugin = AiTranscriptAudit::new(
        &config_with_sink(
            "https://audit.example.com/x",
            json!({ "capture": { "streaming_response": true } }),
        ),
        loopback_http_client(),
    )
    .unwrap();
    let mut ctx = make_ctx();
    plugin
        .on_final_request_body_with_context(&mut ctx, &json_headers(), ai_request_body())
        .await;
    assert!(
        plugin
            .response_stream_inspector(&ctx, 200, Some("text/event-stream"))
            .is_some()
    );
    // always_capture_on_error (default true) wants response evidence for
    // error transactions — error SSE must be teed too.
    assert!(
        plugin
            .response_stream_inspector(&ctx, 500, Some("text/event-stream"))
            .is_some()
    );
    // Redirects are neither successes nor error captures.
    assert!(
        plugin
            .response_stream_inspector(&ctx, 304, Some("text/event-stream"))
            .is_none()
    );

    // With error capture disabled, non-2xx SSE stays un-teed.
    let no_error_capture = AiTranscriptAudit::new(
        &config_with_sink(
            "https://audit.example.com/x",
            json!({
                "capture": { "streaming_response": true },
                "sampling": { "always_capture_on_error": false }
            }),
        ),
        loopback_http_client(),
    )
    .unwrap();
    let mut ctx2 = make_ctx();
    no_error_capture
        .on_final_request_body_with_context(&mut ctx2, &json_headers(), ai_request_body())
        .await;
    assert!(
        no_error_capture
            .response_stream_inspector(&ctx2, 500, Some("text/event-stream"))
            .is_none()
    );
}

#[tokio::test]
async fn stream_inspector_without_body_drive_does_not_emit_pending_record() {
    let server = mock_sink().await;
    let endpoint = format!("{}/ingest", server.uri());
    let plugin = AiTranscriptAudit::new(
        &config_with_sink(
            &endpoint,
            json!({ "capture": { "streaming_response": true } }),
        ),
        loopback_http_client(),
    )
    .unwrap();
    let mut ctx = make_ctx();
    plugin
        .on_final_request_body_with_context(&mut ctx, &json_headers(), ai_request_body())
        .await;
    let _inspector = plugin
        .response_stream_inspector(&ctx, 200, Some("text/event-stream"))
        .expect("inspector");

    plugin
        .on_response_stream_terminated(&ctx, 200, &BodyOutcome::success(0))
        .await;
    tokio::time::sleep(std::time::Duration::from_millis(300)).await;
    let received = server.received_requests().await.unwrap_or_default();
    assert!(
        received.is_empty(),
        "an inspector that never handled body bytes must not leave an emit-ready pending stream"
    );
}

struct TerminateOnEnd;

#[async_trait]
impl ResponseStreamInspector for TerminateOnEnd {
    async fn on_chunk(&mut self, chunk: &[u8]) -> ResponseStreamAction {
        ResponseStreamAction::Forward(Bytes::copy_from_slice(chunk))
    }

    async fn on_end(&mut self) -> ResponseStreamAction {
        ResponseStreamAction::Terminate(Some(Bytes::from_static(b"data: blocked\n\n")))
    }
}

#[tokio::test]
async fn downstream_stream_cut_omits_pre_cut_capture_and_forces_guardrail_sample() {
    let server = mock_sink().await;
    let endpoint = format!("{}/ingest", server.uri());
    let plugin = AiTranscriptAudit::new(
        &config_with_sink(
            &endpoint,
            json!({
                "capture": { "streaming_response": true },
                "sampling": { "rate": 0.0, "always_capture_on_guardrail": true }
            }),
        ),
        loopback_http_client(),
    )
    .unwrap();
    let mut ctx = make_ctx();
    plugin
        .on_final_request_body_with_context(&mut ctx, &json_headers(), ai_request_body())
        .await;
    let audit = plugin
        .response_stream_inspector(&ctx, 200, Some("text/event-stream"))
        .expect("audit inspector");
    let mut chain = chain_response_stream_inspectors(vec![audit, Box::new(TerminateOnEnd)])
        .expect("chained inspector");
    let stream = b"data: {\"choices\":[{\"delta\":{\"content\":\"secret backend bytes\"}}]}\n\n";
    assert!(matches!(
        chain.on_chunk(stream).await,
        ResponseStreamAction::Forward(_)
    ));
    assert!(matches!(
        chain.on_end().await,
        ResponseStreamAction::Terminate(_)
    ));

    plugin
        .on_response_stream_terminated(&ctx, 200, &BodyOutcome::success(stream.len() as u64))
        .await;
    let records = wait_for_records(&server).await;
    assert_eq!(records.len(), 1);
    assert_eq!(records[0]["capture_reason"], "guardrail");
    assert!(
        records[0].get("response_body").is_none(),
        "pre-cut backend bytes must not be exported as client-visible stream data"
    );
    assert!(records[0].get("response_hash").is_none());
    assert_eq!(records[0]["response_body_truncated"], true);
}

// ---------------------------------------------------------------------------
// Redaction ordering and policy
// ---------------------------------------------------------------------------

#[tokio::test]
async fn redaction_runs_before_truncation_at_capture_boundary() {
    // Build a body where the SSN straddles the max_request_bytes boundary; a
    // truncate-then-redact order would emit the raw prefix of the SSN.
    let body = format!(
        r#"{{"model":"gpt-4o","messages":[{{"role":"user","content":"{}my ssn is 123-45-6789"}}]}}"#,
        "x".repeat(64)
    );
    let cut = body.find("123-45-6789").expect("ssn present") + 6;
    let server = mock_sink().await;
    let endpoint = format!("{}/ingest", server.uri());
    let plugin = AiTranscriptAudit::new(
        &config_with_sink(
            &endpoint,
            json!({ "mode": "redacted_body", "limits": { "max_request_bytes": cut } }),
        ),
        loopback_http_client(),
    )
    .unwrap();
    let mut ctx = make_ctx();
    let headers = json_headers();
    plugin
        .on_final_request_body_with_context(&mut ctx, &headers, body.as_bytes())
        .await;
    plugin
        .on_final_response_body(&mut ctx, 200, &headers, br#"{"ok":true}"#)
        .await;
    let records = wait_for_records(&server).await;
    assert_eq!(records.len(), 1);
    let excerpt = records[0]["request_body"].as_str().expect("request body");
    assert!(
        !excerpt.contains("123-45") && !excerpt.contains("123-4"),
        "raw SSN prefix leaked across the capture boundary: {excerpt}"
    );
    assert_eq!(records[0]["request_body_truncated"], true);
}

#[tokio::test]
async fn stream_capture_tail_guard_prevents_boundary_leak() {
    let server = mock_sink().await;
    let endpoint = format!("{}/ingest", server.uri());
    let plugin = AiTranscriptAudit::new(
        &config_with_sink(
            &endpoint,
            json!({
                "capture": { "streaming_response": true },
                "limits": { "max_stream_capture_bytes": 300 }
            }),
        ),
        loopback_http_client(),
    )
    .unwrap();
    let mut ctx = make_ctx();
    plugin
        .on_final_request_body_with_context(&mut ctx, &json_headers(), ai_request_body())
        .await;
    let mut inspector = plugin
        .response_stream_inspector(&ctx, 200, Some("text/event-stream"))
        .expect("inspector");
    // The SSN starts just before the 300-byte capture cap, so the accumulator
    // holds only its raw prefix — the tail guard must drop it before redaction.
    let mut stream = format!("data: {}", "y".repeat(288));
    stream.push_str("123-45-6789 and more trailing data beyond the cap");
    let _ = inspector.on_chunk(stream.as_bytes()).await;
    let _ = inspector.on_end().await;
    plugin
        .on_response_stream_terminated(&ctx, 200, &BodyOutcome::success(stream.len() as u64))
        .await;
    let records = wait_for_records(&server).await;
    assert_eq!(records.len(), 1);
    let excerpt = records[0]["response_body"].as_str().unwrap_or_default();
    assert!(
        !excerpt.contains("123"),
        "raw SSN prefix leaked at the stream capture boundary: {excerpt}"
    );
    assert_eq!(records[0]["response_body_truncated"], true);
}

#[tokio::test]
async fn stream_capture_redacts_decoded_sse_json_frames() {
    let server = mock_sink().await;
    let endpoint = format!("{}/ingest", server.uri());
    let plugin = AiTranscriptAudit::new(
        &config_with_sink(
            &endpoint,
            json!({
                "mode": "redacted_body",
                "capture": { "streaming_response": true }
            }),
        ),
        loopback_http_client(),
    )
    .unwrap();
    let mut ctx = make_ctx();
    plugin
        .on_final_request_body_with_context(&mut ctx, &json_headers(), ai_request_body())
        .await;
    let mut inspector = plugin
        .response_stream_inspector(&ctx, 200, Some("text/event-stream"))
        .expect("inspector");
    let stream = br#"data: {"choices":[{"delta":{"content":"ssn 123\u002d45\u002d6789"}}]}

data: provider-error jane.doe@example.com

data: [DONE]

"#;
    let _ = inspector.on_chunk(stream).await;
    let _ = inspector.on_end().await;
    plugin
        .on_response_stream_terminated(&ctx, 200, &BodyOutcome::success(stream.len() as u64))
        .await;
    let records = wait_for_records(&server).await;
    assert_eq!(records.len(), 1);
    let excerpt = records[0]["response_body"].as_str().unwrap_or_default();
    assert!(!excerpt.contains("123-45-6789"), "{excerpt}");
    assert!(!excerpt.contains("123\\u002d45"), "{excerpt}");
    assert!(!excerpt.contains("jane.doe@example.com"), "{excerpt}");
    assert!(excerpt.contains("[REDACTED"), "{excerpt}");
}

#[tokio::test]
async fn empty_redaction_pattern_set_rejected_in_redacted_mode() {
    let config = config_with_sink(
        "https://audit.example.com/x",
        json!({ "mode": "redacted_body", "redaction": { "builtins": [] } }),
    );
    let err = AiTranscriptAudit::new(&config, loopback_http_client())
        .err()
        .expect("expected config rejection");
    assert!(err.contains("unredacted payloads"), "got: {err}");

    // Non-body modes never emit excerpts, so an empty pattern set is fine.
    let metadata_only = config_with_sink(
        "https://audit.example.com/x",
        json!({ "mode": "metadata_only", "redaction": { "builtins": [] } }),
    );
    assert!(AiTranscriptAudit::new(&metadata_only, loopback_http_client()).is_ok());
}

#[tokio::test]
async fn hash_secret_keys_the_redacted_value_digest() {
    // Too-short secrets are rejected.
    let short = config_with_sink(
        "https://audit.example.com/x",
        json!({ "redaction": { "hash_secret": "short" } }),
    );
    let err = AiTranscriptAudit::new(&short, loopback_http_client())
        .err()
        .expect("expected config rejection");
    assert!(err.contains("hash_secret"), "got: {err}");

    // Same secret => stable placeholders; different secret => different
    // digests; no secret => per-process random key (still not the unsalted
    // SHA-256 an offline attacker could brute-force).
    let builtins = vec!["ssn".to_string()];
    let make = |secret: Option<&str>| {
        PiiRedactor::from_config(&builtins, &[], "[REDACTED:{type}]", true, secret, "test")
            .expect("valid redactor")
    };
    let keyed_a = make(Some("fleet-stable-hmac-key"));
    let keyed_b = make(Some("fleet-stable-hmac-key"));
    let keyed_other = make(Some("a-different-hmac-key"));
    let random_a = make(None);
    let random_b = make(None);
    let text = "ssn 123-45-6789";
    assert_eq!(keyed_a.redact(text), keyed_b.redact(text));
    assert_ne!(keyed_a.redact(text), keyed_other.redact(text));
    assert_ne!(random_a.redact(text), random_b.redact(text));
    for output in [keyed_a.redact(text), random_a.redact(text)] {
        assert!(!output.contains("123-45-6789"), "got: {output}");
        assert!(output.contains("[REDACTED:ssn:"), "got: {output}");
    }
}

// ---------------------------------------------------------------------------
// Fail-closed sink recovery
// ---------------------------------------------------------------------------

#[tokio::test]
async fn sink_recovers_after_transient_outage_with_reject_policy() {
    let server = MockServer::start().await;
    // First batch fails (transient outage), everything after succeeds.
    Mock::given(method("POST"))
        .respond_with(ResponseTemplate::new(500))
        .up_to_n_times(1)
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .respond_with(ResponseTemplate::new(200))
        .mount(&server)
        .await;
    let endpoint = format!("{}/ingest", server.uri());
    let config = json!({
        "sink": {
            "type": "http",
            "endpoint_url": endpoint,
            "batch_size": 1,
            "flush_interval_ms": 100,
            "max_retries": 0,
            "on_sink_error": "reject"
        }
    });
    let plugin = AiTranscriptAudit::new(&config, loopback_http_client()).unwrap();

    async fn roundtrip(plugin: &AiTranscriptAudit) -> PluginResult {
        let headers = json_headers();
        let mut ctx = make_ctx();
        plugin
            .on_final_request_body_with_context(&mut ctx, &headers, ai_request_body())
            .await;
        plugin
            .on_final_response_body(&mut ctx, 200, &headers, br#"{"ok":true}"#)
            .await
    }

    // The first record flushes into the 500 and flips the sink unhealthy;
    // poll until a request observes the fail-closed rejection.
    let mut saw_reject = false;
    for _ in 0..100 {
        if matches!(
            roundtrip(&plugin).await,
            PluginResult::Reject { .. } | PluginResult::RejectBinary { .. }
        ) {
            saw_reject = true;
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    }
    assert!(saw_reject, "sink outage never produced a rejection");

    // The rejected transactions still enqueued their records; flushing them
    // against the recovered sink must restore health and stop the rejects.
    let mut recovered = false;
    for _ in 0..100 {
        if matches!(roundtrip(&plugin).await, PluginResult::Continue) {
            recovered = true;
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    }
    assert!(
        recovered,
        "sink never recovered after the outage cleared — fail-closed rejection is permanent"
    );
}

#[tokio::test]
async fn permanent_collector_4xx_does_not_poison_reject_policy_sink() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .respond_with(ResponseTemplate::new(401))
        .mount(&server)
        .await;
    let endpoint = format!("{}/ingest", server.uri());
    let config = json!({
        "sink": {
            "type": "http",
            "endpoint_url": endpoint,
            "batch_size": 1,
            "flush_interval_ms": 100,
            "max_retries": 0,
            "on_sink_error": "reject"
        }
    });
    let plugin = AiTranscriptAudit::new(&config, loopback_http_client()).unwrap();
    let headers = json_headers();

    for _ in 0..10 {
        let mut ctx = make_ctx();
        plugin
            .on_final_request_body_with_context(&mut ctx, &headers, ai_request_body())
            .await;
        let result = plugin
            .on_final_response_body(&mut ctx, 200, &headers, br#"{"ok":true}"#)
            .await;
        assert!(
            matches!(result, PluginResult::Continue),
            "permanent collector 4xx should be discarded, not treated as a sink outage"
        );
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    }
}

#[tokio::test]
async fn harvests_guardrail_and_token_metadata() {
    let server = mock_sink().await;
    let endpoint = format!("{}/ingest", server.uri());
    let plugin = AiTranscriptAudit::new(
        &config_with_sink(&endpoint, json!({})),
        loopback_http_client(),
    )
    .unwrap();
    let mut ctx = make_ctx();
    let headers = json_headers();
    plugin
        .on_final_request_body_with_context(&mut ctx, &headers, ai_request_body())
        .await;
    // Simulate metadata other AI plugins publish.
    ctx.metadata
        .insert("ai_total_tokens".to_string(), "123".to_string());
    ctx.metadata
        .insert("ai_provider".to_string(), "openai".to_string());
    ctx.metadata.insert(
        "ai_semantic_firewall.decision".to_string(),
        "allow".to_string(),
    );
    plugin
        .on_final_response_body(&mut ctx, 200, &headers, br#"{"ok":true}"#)
        .await;
    let records = wait_for_records(&server).await;
    assert_eq!(records.len(), 1);
    assert_eq!(records[0]["provider"], "openai");
    assert_eq!(records[0]["tokens"]["ai_total_tokens"], "123");
    assert_eq!(
        records[0]["guardrails"]["ai_semantic_firewall.decision"],
        "allow"
    );
}
