//! Unit tests for the `ai_transcript_audit` plugin.
//!
//! Config-validation and metadata-emission tests drive the plugin hooks
//! directly. Record-content tests point the HTTP sink at a `wiremock` server
//! and assert on the captured batch (matching the `ai_federation` test style).

use ferrum_edge::config::types::DEFAULT_NAMESPACE;
use ferrum_edge::config::{BackendAllowIps, BackendEgressPolicy, PoolConfig};
use ferrum_edge::dns::{DnsCache, DnsConfig};
use ferrum_edge::plugins::ai_transcript_audit::AiTranscriptAudit;
use ferrum_edge::plugins::{
    HTTP_ONLY_PROTOCOLS, Plugin, PluginHttpClient, PluginResult, RequestContext, priority,
};
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
    assert_eq!(plugin.priority(), 2979);
    assert_eq!(plugin.supported_protocols(), HTTP_ONLY_PROTOCOLS);
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
