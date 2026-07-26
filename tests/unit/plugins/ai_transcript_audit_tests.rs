//! Unit tests for the `ai_transcript_audit` plugin.
//!
//! Config-validation and metadata-emission tests drive the plugin hooks
//! directly. Record-content tests point the HTTP sink at a `wiremock` server
//! and assert on the captured batch (matching the `ai_federation` test style).

use async_trait::async_trait;
use bytes::Bytes;
use ferrum_edge::_test_support::clone_log_metadata;
use ferrum_edge::config::types::DEFAULT_NAMESPACE;
use ferrum_edge::config::{BackendAllowIps, BackendEgressPolicy, PoolConfig};
use ferrum_edge::dns::{DnsCache, DnsConfig};
use ferrum_edge::plugins::ai_transcript_audit::{
    AI_TRANSCRIPT_AUDIT_CAPTURE_KEYS, AI_TRANSCRIPT_AUDIT_CONFIG_KEYS,
    AI_TRANSCRIPT_AUDIT_CUSTOM_PATTERN_KEYS, AI_TRANSCRIPT_AUDIT_LIMITS_KEYS,
    AI_TRANSCRIPT_AUDIT_PRIVACY_KEYS, AI_TRANSCRIPT_AUDIT_REDACTION_KEYS,
    AI_TRANSCRIPT_AUDIT_SAMPLING_KEYS, AI_TRANSCRIPT_AUDIT_SINK_KEYS, AiTranscriptAudit,
    HARD_MAX_CAPTURE_BYTES_AGGREGATE, HARD_MAX_REQUEST_BYTES, HARD_MAX_RESPONSE_BYTES,
    HARD_MAX_STREAM_CAPTURE_BYTES, MAX_MODEL_BYTES, MAX_TOOL_NAME_BYTES, MAX_TOOL_NAMES,
    MAX_TOOL_NAMES_AGGREGATE_BYTES, max_retained_record_bytes, snapshots,
};
use ferrum_edge::plugins::request_deduplication::RequestDeduplication;
use ferrum_edge::plugins::utils::ai_pii::PiiRedactor;
use ferrum_edge::plugins::{
    HTTP_ONLY_PROTOCOLS, Plugin, PluginFailurePolicy, PluginHttpClient, PluginResult,
    RequestContext, ResponseStreamAction, ResponseStreamInspector,
    chain_response_stream_inspectors, plugin_failure_policy, priority, validate_plugin_config,
};
use ferrum_edge::proxy::deferred_log::{BodyOutcome, run_response_stream_termination_hooks};
use serde_json::{Value, json};
use std::collections::HashMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use wiremock::matchers::method;
use wiremock::{Mock, MockServer, ResponseTemplate};

use super::plugin_utils::{
    create_test_proxy, create_test_transaction_summary, read_http11_request_headers,
};
use crate::unit::env_lock::EnvGuard;

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
            "allow_insecure_loopback": true,
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

async fn wait_for_total_records(server: &MockServer, expected: usize) -> Vec<Value> {
    for _ in 0..100 {
        let mut records = Vec::new();
        if let Some(requests) = server.received_requests().await {
            for request in requests {
                if let Ok(Value::Array(batch)) = serde_json::from_slice::<Value>(&request.body) {
                    records.extend(batch);
                }
            }
        }
        if records.len() >= expected {
            return records;
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

#[async_trait]
trait AuditBufferedResponseTestExt {
    async fn capture_final_response_body(
        &self,
        ctx: &mut RequestContext,
        status: u16,
        headers: &HashMap<String, String>,
        body: &[u8],
    ) -> PluginResult;
}

#[async_trait]
impl AuditBufferedResponseTestExt for AiTranscriptAudit {
    async fn capture_final_response_body(
        &self,
        ctx: &mut RequestContext,
        status: u16,
        headers: &HashMap<String, String>,
        body: &[u8],
    ) -> PluginResult {
        let result = self
            .on_final_response_body(ctx, status, headers, body)
            .await;
        match &result {
            PluginResult::Continue => {
                self.on_response_committed(ctx, status, headers, body).await;
            }
            PluginResult::Reject {
                status_code,
                body,
                headers,
            } => {
                self.on_response_committed(ctx, *status_code, headers, body.as_bytes())
                    .await;
            }
            PluginResult::RejectBinary {
                status_code,
                body,
                headers,
            } => {
                self.on_response_committed(ctx, *status_code, headers, body)
                    .await;
            }
        }
        result
    }
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
    // Live delivery fixtures must stage then commit the deferred batching worker.
    plugin.start_background_tasks().expect("live start");
    plugin.commit_background_tasks();
    let mut ctx = make_ctx();
    let headers = json_headers();
    plugin
        .on_final_request_body_with_context(&mut ctx, &headers, ai_request_body())
        .await;
    plugin
        .capture_final_response_body(&mut ctx, 200, &headers, resp_body)
        .await;
    wait_for_records(&server).await
}

/// A request path that embeds an email and a token in its segments — the kind of
/// sensitive material issue #3068 must not export by default.
const SENSITIVE_PATH: &str = "/users/alice@example.com/reset/SECRET-9f1c";

/// `make_ctx` with a caller-chosen path and an optional matched proxy (whose
/// `listen_path` is `/test`, the route identifier `path_mode: template` exports).
fn ctx_with_path(path: &str, with_proxy: bool) -> RequestContext {
    let mut ctx = make_ctx();
    ctx.path = path.to_string();
    if with_proxy {
        ctx.matched_proxy = Some(Arc::new(create_test_proxy()));
    }
    ctx
}

/// Drive a buffered request+response roundtrip over `ctx`, returning the records.
async fn capture_roundtrip_over_ctx(
    config_overrides: Value,
    mut ctx: RequestContext,
) -> Vec<Value> {
    let server = mock_sink().await;
    let endpoint = format!("{}/ingest", server.uri());
    let plugin = AiTranscriptAudit::new(
        &config_with_sink(&endpoint, config_overrides),
        loopback_http_client(),
    )
    .expect("valid config");
    plugin.start_background_tasks().expect("live start");
    plugin.commit_background_tasks();
    let headers = json_headers();
    plugin
        .on_final_request_body_with_context(&mut ctx, &headers, ai_request_body())
        .await;
    plugin
        .capture_final_response_body(&mut ctx, 200, &headers, br#"{"ok":true}"#)
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
    assert_eq!(plugin.priority(), 2740);
    assert_eq!(plugin.supported_protocols(), HTTP_ONLY_PROTOCOLS);
    assert!(plugin.requires_response_committed_hook());
    // Privacy and fail-closed sink typos must reject the candidate generation so
    // reload keeps the last-known-good audit instance. Runtime fail-closed
    // capture remains the explicit on_sink_error/on_buffer_full=reject config.
    assert_eq!(
        plugin_failure_policy("ai_transcript_audit"),
        Some(PluginFailurePolicy::KeepLastKnownGood)
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

#[tokio::test]
async fn cleartext_sink_requires_explicit_loopback_only_opt_in() {
    for config in [
        json!({
            "sink": {
                "type": "http",
                "endpoint_url": "http://127.0.0.1:9001/audit"
            }
        }),
        json!({
            "sink": {
                "type": "http",
                "endpoint_url": "http://collector.example.com/audit",
                "allow_insecure_loopback": true
            }
        }),
    ] {
        let err = AiTranscriptAudit::new(&config, loopback_http_client())
            .err()
            .expect("cleartext policy must reject");
        assert!(
            err.contains("https://") || err.contains("loopback"),
            "got: {err}"
        );
    }

    let loopback = json!({
        "sink": {
            "type": "http",
            "endpoint_url": "http://[::1]:9001/audit",
            "allow_insecure_loopback": true
        }
    });
    assert!(
        AiTranscriptAudit::new(&loopback, loopback_http_client()).is_ok(),
        "explicit IPv6 loopback cleartext should remain available for local development"
    );
}

#[tokio::test]
async fn rejects_multiple_unknown_root_keys_sorted_with_suggestions() {
    let config = config_with_sink(
        "https://audit.example.com/x",
        json!({
            "zzz_unknown": true,
            "allow_full_bod": true,
            "aaa_unknown": false
        }),
    );
    let err = AiTranscriptAudit::new(&config, loopback_http_client())
        .err()
        .expect("unknown root keys must fail closed");
    assert!(err.contains("unknown configuration key"), "got: {err}");
    assert!(
        err.contains("'config.aaa_unknown'")
            && err.contains("'config.allow_full_bod'")
            && err.contains("'config.zzz_unknown'"),
        "got: {err}"
    );
    let aaa = err.find("'config.aaa_unknown'").expect("aaa path");
    let allow = err.find("'config.allow_full_bod'").expect("allow path");
    let zzz = err.find("'config.zzz_unknown'").expect("zzz path");
    assert!(
        aaa < allow && allow < zzz,
        "unknown keys must be sorted: {err}"
    );
    assert!(
        err.contains("did you mean 'allow_full_body'"),
        "typo should suggest allow_full_body: {err}"
    );
}

#[tokio::test]
async fn rejects_privacy_capture_sampling_redaction_limits_and_fail_posture_typos() {
    for (overrides, needle, suggestion) in [
        (
            json!({ "privacy": { "include_consumer_usernme": false } }),
            "config.privacy.include_consumer_usernme",
            Some("include_consumer_username"),
        ),
        (
            json!({ "capture": { "respose": false } }),
            "config.capture.respose",
            Some("response"),
        ),
        (
            json!({ "sampling": { "always_capture_on_guardrai": false } }),
            "config.sampling.always_capture_on_guardrai",
            Some("always_capture_on_guardrail"),
        ),
        (
            json!({ "redaction": { "hash_secre": "fleet-stable-hmac-key" } }),
            "config.redaction.hash_secre",
            Some("hash_secret"),
        ),
        (
            json!({ "limits": { "max_request_byte": 1024 } }),
            "config.limits.max_request_byte",
            Some("max_request_bytes"),
        ),
        (
            json!({
                "sink": {
                    "type": "http",
                    "endpoint_url": "https://audit.example.com/x",
                    "on_sink_eror": "reject"
                }
            }),
            "config.sink.on_sink_eror",
            Some("on_sink_error"),
        ),
        (
            json!({
                "sink": {
                    "type": "http",
                    "endpoint_url": "https://audit.example.com/x",
                    "on_buffer_ful": "reject"
                }
            }),
            "config.sink.on_buffer_ful",
            Some("on_buffer_full"),
        ),
        (
            json!({
                "redaction": {
                    "custom_patterns": [{
                        "name": "internal_id",
                        "regex": "CUST-[0-9]+",
                        "flagz": "i"
                    }]
                }
            }),
            "config.redaction.custom_patterns[0].flagz",
            None,
        ),
    ] {
        let config = if overrides.get("sink").is_some() {
            overrides
        } else {
            config_with_sink("https://audit.example.com/x", overrides)
        };
        let err = AiTranscriptAudit::new(&config, loopback_http_client())
            .err()
            .expect("security-relevant typo must fail closed");
        assert!(
            err.contains("unknown configuration key"),
            "missing unknown-key wording for {needle}: {err}"
        );
        assert!(
            err.contains(&format!("'{needle}'")),
            "error did not identify {needle}: {err}"
        );
        if let Some(suggestion) = suggestion {
            assert!(
                err.contains(&format!("did you mean '{suggestion}'")),
                "expected suggestion {suggestion} for {needle}: {err}"
            );
        }
    }
}

#[tokio::test]
async fn null_optional_nested_objects_keep_defaults_and_custom_headers_stay_free_form() {
    let config = json!({
        "mode": null,
        "allow_full_body": null,
        "capture": null,
        "sampling": null,
        "redaction": null,
        "limits": null,
        "privacy": null,
        "sink": {
            "type": "http",
            "endpoint_url": "https://audit.example.com/x",
            "custom_headers": {
                "Authorization": "Bearer ${secret:AUDIT_TOKEN}",
                "X-Custom-Collector": "fleet-a"
            },
            "retry_delay_ms": 250
        }
    });
    assert!(
        AiTranscriptAudit::new(&config, loopback_http_client()).is_ok(),
        "null nested objects and free-form custom_headers must remain valid"
    );
}

#[test]
fn shared_admission_rejects_unknown_keys_and_uses_keep_last_known_good() {
    let err = validate_plugin_config(
        "ai_transcript_audit",
        &json!({
            "privacy": { "include_consumer_usernme": false },
            "sink": {
                "type": "http",
                "endpoint_url": "https://audit.example.com/x"
            }
        }),
    )
    .expect_err("shared admission must reject privacy typo");
    assert!(
        err.contains("config.privacy.include_consumer_usernme"),
        "got: {err}"
    );
    assert_eq!(
        plugin_failure_policy("ai_transcript_audit"),
        Some(PluginFailurePolicy::KeepLastKnownGood)
    );
}

#[test]
fn accepted_config_key_sets_are_exported_for_schema_parity() {
    assert_eq!(
        AI_TRANSCRIPT_AUDIT_CONFIG_KEYS,
        &[
            "mode",
            "allow_full_body",
            "capture",
            "sampling",
            "redaction",
            "limits",
            "privacy",
            "sink",
        ]
    );
    assert_eq!(
        AI_TRANSCRIPT_AUDIT_CAPTURE_KEYS,
        &[
            "request",
            "response",
            "streaming_response",
            "headers",
            "tool_calls"
        ]
    );
    assert_eq!(
        AI_TRANSCRIPT_AUDIT_SAMPLING_KEYS,
        &[
            "rate",
            "always_capture_on_guardrail",
            "always_capture_on_error",
            "max_records_per_minute",
        ]
    );
    assert_eq!(
        AI_TRANSCRIPT_AUDIT_REDACTION_KEYS,
        &[
            "builtins",
            "custom_patterns",
            "placeholder",
            "hash_redacted_values",
            "hash_secret",
        ]
    );
    assert_eq!(AI_TRANSCRIPT_AUDIT_CUSTOM_PATTERN_KEYS, &["name", "regex"]);
    assert_eq!(
        AI_TRANSCRIPT_AUDIT_LIMITS_KEYS,
        &[
            "max_request_bytes",
            "max_response_bytes",
            "max_stream_capture_bytes",
        ]
    );
    assert_eq!(
        AI_TRANSCRIPT_AUDIT_PRIVACY_KEYS,
        &[
            "include_consumer_username",
            "include_client_ip",
            "include_raw_headers",
            "path_mode",
        ]
    );
    assert_eq!(
        AI_TRANSCRIPT_AUDIT_SINK_KEYS,
        &[
            "type",
            "endpoint_url",
            "allow_insecure_loopback",
            "custom_headers",
            "batch_size",
            "flush_interval_ms",
            "buffer_capacity",
            "max_retries",
            "retry_delay_ms",
            "on_buffer_full",
            "on_sink_error",
        ]
    );
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
    assert_eq!(hash.len(), 64, "hmac-sha256 hex should be 64 chars");
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

#[tokio::test]
async fn final_request_body_drops_stale_candidate_after_ai_is_transformed_away() {
    for final_body in [
        br#"{"order_id":42}"#.as_slice(),
        br#"{"messages":"#.as_slice(),
    ] {
        let plugin = AiTranscriptAudit::new(
            &config_with_sink(
                "https://audit.example.com/x",
                json!({ "capture": { "streaming_response": true } }),
            ),
            loopback_http_client(),
        )
        .unwrap();
        let mut ctx = make_ctx();
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

        plugin
            .on_final_request_body_with_context(&mut ctx, &headers, final_body)
            .await;
        assert_eq!(
            ctx.metadata
                .get("ai_transcript_audit.candidate")
                .map(String::as_str),
            Some("false")
        );
        assert!(!plugin.forces_reqwest_dispatch(&ctx));
        assert!(
            plugin
                .response_stream_inspector(&ctx, 200, Some("text/event-stream"))
                .is_none()
        );
    }
}

#[tokio::test]
async fn staging_has_a_hard_bound_and_uses_configured_fail_closed_overload_behavior() {
    let plugin = AiTranscriptAudit::new(
        &json!({
            "mode": "metadata_only",
            "capture": {
                "request": true,
                "response": false,
                "streaming_response": false
            },
            "sampling": {
                "rate": 0.0,
                "always_capture_on_guardrail": false,
                "always_capture_on_error": false
            },
            "sink": {
                "type": "http",
                "endpoint_url": "https://audit.example.com/x",
                "on_buffer_full": "reject"
            }
        }),
        loopback_http_client(),
    )
    .unwrap();
    let headers = json_headers();
    for index in 0..4096 {
        let mut ctx = make_ctx();
        let result = plugin
            .on_final_request_body_with_context(&mut ctx, &headers, ai_request_body())
            .await;
        assert!(
            matches!(result, PluginResult::Continue),
            "staging slot {index} should be admitted"
        );
    }

    let mut overflow = make_ctx();
    let result = plugin
        .on_final_request_body_with_context(&mut overflow, &headers, ai_request_body())
        .await;
    assert!(matches!(
        result,
        PluginResult::Reject {
            status_code: 503,
            ..
        }
    ));
    assert_eq!(
        overflow
            .metadata
            .get("ai_transcript_audit.sink_status")
            .map(String::as_str),
        Some("rejected")
    );
    assert_eq!(
        overflow
            .metadata
            .get("ai_transcript_audit.candidate")
            .map(String::as_str),
        Some("false")
    );
    let overflow_log_metadata = clone_log_metadata(&overflow);
    assert_eq!(
        overflow_log_metadata
            .get("ai_transcript_audit.sink_status")
            .map(String::as_str),
        Some("rejected"),
        "staging saturation must remain visible in transaction logs"
    );
    assert!(
        !overflow_log_metadata.contains_key("ai_transcript_audit.candidate"),
        "internal candidate state must still be removed"
    );

    let peer = AiTranscriptAudit::new(
        &config_with_sink(
            "https://audit.example.com/x",
            json!({ "capture": { "streaming_response": true } }),
        ),
        loopback_http_client(),
    )
    .unwrap();
    let mut peer_overflow = make_ctx();
    assert!(matches!(
        peer.on_final_request_body_with_context(&mut peer_overflow, &headers, ai_request_body(),)
            .await,
        PluginResult::Continue
    ));
    assert!(peer.forces_reqwest_dispatch(&peer_overflow));

    let result = plugin
        .on_final_request_body_with_context(&mut peer_overflow, &headers, ai_request_body())
        .await;
    assert!(matches!(
        result,
        PluginResult::Reject {
            status_code: 503,
            ..
        }
    ));
    assert_eq!(
        peer_overflow
            .metadata
            .get("ai_transcript_audit.candidate")
            .map(String::as_str),
        Some("true"),
        "a saturated instance must not erase a peer instance's staged candidate"
    );
    assert!(peer.forces_reqwest_dispatch(&peer_overflow));
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
async fn redacted_body_redacts_sensitive_parent_keys_and_json_encoded_tool_arguments() {
    let server = mock_sink().await;
    let endpoint = format!("{}/ingest", server.uri());
    let plugin = AiTranscriptAudit::new(
        &config_with_sink(&endpoint, json!({ "mode": "redacted_body" })),
        loopback_http_client(),
    )
    .unwrap();
    plugin.start_background_tasks().expect("live start");
    plugin.commit_background_tasks();
    let request = br#"{
        "model":"gpt-4o",
        "messages":[{"role":"user","content":"use the tool"}],
        "password":"correct horse battery staple",
        "pass\u200bword":"zero width secret",
        "auth":"short auth secret",
        "cookie":"opaque cookie secret",
        "authorization":"opaque credential",
        "tool_arguments":"{\"nested\":{\"client_secret\":\"tool secret\"}}"
    }"#;
    let mut ctx = make_ctx();
    let headers = json_headers();
    plugin
        .on_final_request_body_with_context(&mut ctx, &headers, request)
        .await;
    plugin
        .on_final_response_body(&mut ctx, 200, &headers, br#"{"ok":true}"#)
        .await;
    plugin
        .on_response_committed(&mut ctx, 200, &headers, br#"{"ok":true}"#)
        .await;
    let records = wait_for_records(&server).await;
    let captured = records[0]["request_body"].as_str().unwrap();
    for secret in [
        "correct horse battery staple",
        "zero width secret",
        "short auth secret",
        "opaque cookie secret",
        "opaque credential",
        "tool secret",
    ] {
        assert!(!captured.contains(secret), "secret leaked: {captured}");
    }
    assert!(captured.contains("[REDACTED]"));
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
    plugin.start_background_tasks().expect("live start");
    plugin.commit_background_tasks();
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
        .capture_final_response_body(&mut ctx, 200, &headers, br#"{"ok":true}"#)
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
    plugin.start_background_tasks().expect("live start");
    plugin.commit_background_tasks();
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
        .capture_final_response_body(&mut ctx, 200, &headers, br#"{"ok":true}"#)
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
    plugin.start_background_tasks().expect("live start");
    plugin.commit_background_tasks();
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
        .capture_final_response_body(&mut ctx, 200, &headers, br#"{"ok":true}"#)
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
    plugin.start_background_tasks().expect("live start");
    plugin.commit_background_tasks();
    let mut ctx = make_ctx();
    let request_headers = json_headers();
    plugin
        .on_final_request_body_with_context(&mut ctx, &request_headers, ai_request_body())
        .await;
    let response_headers = content_type_headers("text/html");
    plugin
        .capture_final_response_body(
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
    plugin.start_background_tasks().expect("live start");
    plugin.commit_background_tasks();
    let mut ctx = make_ctx();
    plugin
        .on_final_request_body_with_context(&mut ctx, &json_headers(), ai_request_body())
        .await;
    let response_headers = content_type_headers("text/event-stream");
    let body = br#"data: {"choices":[{"delta":{"content":"email jane.doe@example.com"}}]}

data: [DONE]

"#;
    plugin
        .capture_final_response_body(&mut ctx, 200, &response_headers, body)
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
        .capture_final_response_body(&mut ctx, 200, &headers, br#"{"ok":true}"#)
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
    plugin.start_background_tasks().expect("live start");
    plugin.commit_background_tasks();
    let mut ctx = make_ctx();
    let headers = json_headers();
    plugin
        .on_final_request_body_with_context(&mut ctx, &headers, ai_request_body())
        .await;
    // Simulate a downstream guard firing before the response is finalized.
    ctx.metadata
        .insert("ai_response_guard_detected".to_string(), "true".to_string());
    plugin
        .capture_final_response_body(&mut ctx, 200, &headers, br#"{"ok":true}"#)
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
    plugin.start_background_tasks().expect("live start");
    plugin.commit_background_tasks();
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
        .capture_final_response_body(&mut ctx, 200, &headers, br#"{"ok":true}"#)
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
        plugin.start_background_tasks().expect("live start");
        plugin.commit_background_tasks();
        let mut ctx = make_ctx();
        let headers = json_headers();
        plugin
            .on_final_request_body_with_context(&mut ctx, &headers, ai_request_body())
            .await;
        ctx.metadata.insert(key.to_string(), value.to_string());
        plugin
            .capture_final_response_body(&mut ctx, 200, &headers, br#"{"ok":true}"#)
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
    plugin.start_background_tasks().expect("live start");
    plugin.commit_background_tasks();
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
        .capture_final_response_body(&mut ctx, 200, &headers, br#"{"ok":true}"#)
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
    plugin.start_background_tasks().expect("live start");
    plugin.commit_background_tasks();
    let mut ctx = make_ctx();
    let headers = json_headers();
    plugin
        .on_final_request_body_with_context(&mut ctx, &headers, ai_request_body())
        .await;
    plugin
        .capture_final_response_body(&mut ctx, 500, &headers, br#"{"error":"boom"}"#)
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
    // Instance-local staging, rather than pointer-derived metadata, selects
    // the stream path.
    assert!(
        ctx.metadata
            .keys()
            .all(|key| !key.starts_with("ai_transcript_audit.stream_marker"))
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
async fn stream_capture_state_is_instance_local_and_candidate_scoped() {
    let plugin = AiTranscriptAudit::new(
        &config_with_sink(
            "https://audit.example.com/x",
            json!({ "capture": { "streaming_response": true } }),
        ),
        loopback_http_client(),
    )
    .unwrap();
    // A non-AI JSON POST must not select stream capture.
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
        !ctx.metadata
            .contains_key("ai_transcript_audit.stream_marker"),
        "non-AI JSON must not carry internal stream metadata"
    );
    assert!(
        !plugin.forces_reqwest_dispatch(&ctx),
        "non-AI JSON must stay on the native-H3 dispatch path"
    );
    assert!(
        !plugin.should_buffer_response_body(&ctx),
        "non-candidate JSON should still avoid buffered-response capture"
    );

    // An AI-shaped body is selected through instance-local staging without
    // publishing a process pointer or lifecycle key.
    let mut ai_ctx = make_ctx();
    ai_ctx.metadata.insert(
        "request_body".to_string(),
        std::str::from_utf8(ai_request_body()).unwrap().to_string(),
    );
    let mut ai_headers = ai_ctx.headers.clone();
    plugin.before_proxy(&mut ai_ctx, &mut ai_headers).await;
    assert!(
        ai_ctx
            .metadata
            .keys()
            .all(|key| !key.starts_with("ai_transcript_audit.stream_marker"))
    );
    assert!(plugin.forces_reqwest_dispatch(&ai_ctx));
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
    plugin.start_background_tasks().expect("live start");
    plugin.commit_background_tasks();
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
        .capture_final_response_body(&mut ctx, 200, &headers, br#"{"ok":true}"#)
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
    plugin.start_background_tasks().expect("live start");
    plugin.commit_background_tasks();
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
        .capture_final_response_body(&mut ctx, 200, &headers, br#"{"ok":true}"#)
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
    plugin.start_background_tasks().expect("live start");
    plugin.commit_background_tasks();
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
        .capture_final_response_body(&mut ctx, 200, &headers, br#"{"ok":true}"#)
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

    // rate 0, no guardrail: instance-local staging exists, but the tee gate
    // must NOT fire just because the always_capture_* defaults are on.
    let mut ctx = make_ctx();
    plugin
        .on_final_request_body_with_context(&mut ctx, &headers, ai_request_body())
        .await;
    assert!(ctx.metadata.contains_key("ai_transcript_audit.record_id"));
    assert!(
        !plugin.forces_reqwest_dispatch(&ctx),
        "sampled mode must honor sampling.rate for the dispatch decision"
    );
    assert!(
        plugin
            .response_stream_inspector(&ctx, 200, Some("text/event-stream"))
            .is_none(),
        "sampled mode must honor sampling.rate for the tee decision"
    );

    // A request-side guardrail already fired: always_capture_on_guardrail
    // justifies the tee even for an un-sampled request.
    let mut guardrail_ctx = make_ctx();
    guardrail_ctx
        .metadata
        .insert("ai_shield_redacted".to_string(), "true".to_string());
    plugin
        .on_final_request_body_with_context(&mut guardrail_ctx, &headers, ai_request_body())
        .await;
    assert!(plugin.forces_reqwest_dispatch(&guardrail_ctx));
    assert!(
        plugin
            .response_stream_inspector(&guardrail_ctx, 200, Some("text/event-stream"))
            .is_some()
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

    // With error capture disabled AND the request un-sampled (rate 0), a non-2xx
    // SSE stays un-teed: the record would not emit, so there is no body to
    // capture. (A *sampled* error stream is teed — see
    // `sampled_error_sse_is_teed_and_captures_body`.)
    let no_error_capture = AiTranscriptAudit::new(
        &config_with_sink(
            "https://audit.example.com/x",
            json!({
                "capture": { "streaming_response": true },
                "sampling": { "always_capture_on_error": false, "rate": 0.0 }
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
async fn streaming_selection_releases_precommit_buffer_reservation() {
    let plugin = AiTranscriptAudit::new(
        &json!({
            "capture": { "response": true, "streaming_response": false },
            "sink": {
                "type": "http",
                "endpoint_url": "https://audit.example.com/x",
                "batch_size": 1,
                "flush_interval_ms": 100,
                "buffer_capacity": 1,
                "on_buffer_full": "reject"
            }
        }),
        loopback_http_client(),
    )
    .unwrap();
    plugin.start_background_tasks().expect("live start");
    plugin.commit_background_tasks();
    assert!(
        plugin.requires_response_stream_hooks(),
        "fail-closed buffered capture must observe a content-type downgrade to release its slot"
    );
    let headers = json_headers();

    let mut first = make_ctx();
    first.metadata.insert(
        "request_body".to_string(),
        std::str::from_utf8(ai_request_body()).unwrap().to_string(),
    );
    let mut first_headers = headers.clone();
    assert!(matches!(
        plugin.before_proxy(&mut first, &mut first_headers).await,
        PluginResult::Continue
    ));
    plugin.on_response_stream_selected(&first, 200, Some("text/plain"));

    let mut second = make_ctx();
    second.metadata.insert(
        "request_body".to_string(),
        std::str::from_utf8(ai_request_body()).unwrap().to_string(),
    );
    let mut second_headers = headers;
    assert!(matches!(
        plugin.before_proxy(&mut second, &mut second_headers).await,
        PluginResult::Continue
    ));
}

#[tokio::test]
async fn selected_stream_reserves_queue_capacity_before_commit() {
    let plugin = AiTranscriptAudit::new(
        &json!({
            "capture": { "response": false, "streaming_response": true },
            "sink": {
                "type": "http",
                "endpoint_url": "https://audit.example.com/x",
                "batch_size": 1,
                "flush_interval_ms": 100,
                "buffer_capacity": 1,
                "on_buffer_full": "reject"
            }
        }),
        loopback_http_client(),
    )
    .unwrap();
    plugin.start_background_tasks().expect("live start");
    plugin.commit_background_tasks();
    let request_headers = json_headers();
    let stream_body =
        br#"{"model":"gpt-4o","messages":[{"role":"user","content":"hi"}],"stream":true}"#;
    let mut response_headers =
        HashMap::from([("content-type".to_string(), "text/event-stream".to_string())]);

    let mut first = make_ctx();
    plugin
        .on_final_request_body_with_context(&mut first, &request_headers, stream_body)
        .await;
    assert!(matches!(
        plugin
            .after_proxy(&mut first, 200, &mut response_headers)
            .await,
        PluginResult::Continue
    ));
    plugin.on_response_stream_selected(&first, 200, Some("text/event-stream"));

    let mut second = make_ctx();
    plugin
        .on_final_request_body_with_context(&mut second, &request_headers, stream_body)
        .await;
    assert!(matches!(
        plugin
            .after_proxy(&mut second, 200, &mut response_headers)
            .await,
        PluginResult::Reject {
            status_code: 503,
            ..
        }
    ));
    assert_eq!(
        second
            .metadata
            .get("ai_transcript_audit.sink_status")
            .map(String::as_str),
        Some("rejected")
    );
}

#[tokio::test]
async fn streaming_capture_preserves_buffered_response_admission() {
    let plugin = AiTranscriptAudit::new(
        &json!({
            "capture": { "response": true, "streaming_response": "sampled" },
            "sampling": {
                "rate": 0.0,
                "always_capture_on_error": true,
                "always_capture_on_guardrail": false
            },
            "sink": {
                "type": "http",
                "endpoint_url": "https://audit.example.com/x",
                "batch_size": 1,
                "flush_interval_ms": 100,
                "buffer_capacity": 1,
                "on_buffer_full": "reject"
            }
        }),
        loopback_http_client(),
    )
    .unwrap();
    plugin.start_background_tasks().expect("live start");
    plugin.commit_background_tasks();
    let request_headers = json_headers();
    let request_body = br#"{"model":"gpt-4o","messages":[{"role":"user","content":"hi"}]}"#;
    let mut response_headers = json_headers();

    let mut first = make_ctx();
    plugin
        .on_final_request_body_with_context(&mut first, &request_headers, request_body)
        .await;
    assert!(matches!(
        plugin
            .after_proxy(&mut first, 200, &mut response_headers)
            .await,
        PluginResult::Continue
    ));

    let mut second = make_ctx();
    plugin
        .on_final_request_body_with_context(&mut second, &request_headers, request_body)
        .await;
    assert!(matches!(
        plugin
            .after_proxy(&mut second, 200, &mut response_headers)
            .await,
        PluginResult::Reject {
            status_code: 503,
            ..
        }
    ));
}

#[tokio::test]
async fn response_guardrail_candidate_reserves_stream_capacity_before_commit() {
    let plugin = AiTranscriptAudit::new(
        &json!({
            "capture": { "response": false, "streaming_response": "sampled" },
            "sampling": {
                "rate": 0.0,
                "always_capture_on_error": false,
                "always_capture_on_guardrail": true
            },
            "sink": {
                "type": "http",
                "endpoint_url": "https://audit.example.com/x",
                "batch_size": 1,
                "flush_interval_ms": 100,
                "buffer_capacity": 1,
                "on_buffer_full": "reject"
            }
        }),
        loopback_http_client(),
    )
    .unwrap();
    plugin.start_background_tasks().expect("live start");
    plugin.commit_background_tasks();
    let request_headers = json_headers();
    let stream_body =
        br#"{"model":"gpt-4o","messages":[{"role":"user","content":"hi"}],"stream":true}"#;
    let mut response_headers =
        HashMap::from([("content-type".to_string(), "text/event-stream".to_string())]);

    let mut first = make_ctx();
    plugin
        .on_final_request_body_with_context(&mut first, &request_headers, stream_body)
        .await;
    assert!(matches!(
        plugin
            .after_proxy(&mut first, 200, &mut response_headers)
            .await,
        PluginResult::Continue
    ));
    plugin.on_response_stream_selected(&first, 200, Some("text/event-stream"));

    let mut second = make_ctx();
    plugin
        .on_final_request_body_with_context(&mut second, &request_headers, stream_body)
        .await;
    assert!(matches!(
        plugin
            .after_proxy(&mut second, 200, &mut response_headers)
            .await,
        PluginResult::Reject {
            status_code: 503,
            ..
        }
    ));
}

#[tokio::test]
async fn possible_final_sse_relabel_is_admitted_before_header_rewrite() {
    let plugin = AiTranscriptAudit::new(
        &json!({
            "capture": { "response": false, "streaming_response": "sampled" },
            "sampling": {
                "rate": 0.0,
                "always_capture_on_error": false,
                "always_capture_on_guardrail": true
            },
            "sink": {
                "type": "http",
                "endpoint_url": "https://audit.example.com/x",
                "batch_size": 1,
                "flush_interval_ms": 100,
                "buffer_capacity": 1,
                "on_buffer_full": "reject"
            }
        }),
        loopback_http_client(),
    )
    .unwrap();
    plugin.start_background_tasks().expect("live start");
    plugin.commit_background_tasks();
    let request_headers = json_headers();
    // No `stream:true`: a later response hook can still relabel this candidate
    // to SSE, so admission cannot depend on the request or current response
    // content type.
    let stream_body = br#"{"model":"gpt-4o","messages":[{"role":"user","content":"hi"}]}"#;
    let mut original_headers =
        HashMap::from([("content-type".to_string(), "application/json".to_string())]);

    let mut first = make_ctx();
    plugin
        .on_final_request_body_with_context(&mut first, &request_headers, stream_body)
        .await;
    assert!(matches!(
        plugin
            .after_proxy(&mut first, 200, &mut original_headers)
            .await,
        PluginResult::Continue
    ));
    plugin.on_response_stream_selected(&first, 200, Some("text/event-stream"));

    let mut second = make_ctx();
    plugin
        .on_final_request_body_with_context(&mut second, &request_headers, stream_body)
        .await;
    assert!(matches!(
        plugin
            .after_proxy(&mut second, 200, &mut original_headers)
            .await,
        PluginResult::Reject {
            status_code: 503,
            ..
        }
    ));
}

#[tokio::test]
async fn unsampled_stream_with_error_override_reserves_fail_closed_capacity() {
    // A 2xx stream can still fail after headers commit. With the error override
    // enabled, even a sampling miss must reserve its terminal audit slot before
    // bytes flow, so a concurrent candidate cannot consume the sole capacity.
    let plugin = AiTranscriptAudit::new(
        &json!({
            "capture": { "response": false, "streaming_response": "sampled" },
            "sampling": {
                "rate": 0.0,
                "always_capture_on_error": true,
                "always_capture_on_guardrail": false
            },
            "sink": {
                "type": "http",
                "endpoint_url": "https://audit.example.com/x",
                "batch_size": 1,
                "flush_interval_ms": 100,
                "buffer_capacity": 1,
                "on_buffer_full": "reject"
            }
        }),
        loopback_http_client(),
    )
    .unwrap();
    plugin.start_background_tasks().expect("live start");
    plugin.commit_background_tasks();
    let request_headers = json_headers();
    let stream_body =
        br#"{"model":"gpt-4o","messages":[{"role":"user","content":"hi"}],"stream":true}"#;
    let mut response_headers =
        HashMap::from([("content-type".to_string(), "text/event-stream".to_string())]);

    let mut success = make_ctx();
    plugin
        .on_final_request_body_with_context(&mut success, &request_headers, stream_body)
        .await;
    assert!(matches!(
        plugin
            .after_proxy(&mut success, 200, &mut response_headers)
            .await,
        PluginResult::Continue
    ));

    let mut concurrent = make_ctx();
    plugin
        .on_final_request_body_with_context(&mut concurrent, &request_headers, stream_body)
        .await;
    assert!(matches!(
        plugin
            .after_proxy(&mut concurrent, 200, &mut response_headers)
            .await,
        PluginResult::Reject {
            status_code: 503,
            ..
        }
    ));
}

#[tokio::test]
async fn request_only_capture_reserves_fail_closed_capacity_on_final_body_fallback() {
    let plugin = AiTranscriptAudit::new(
        &json!({
            "capture": {
                "request": true,
                "response": false,
                "streaming_response": false
            },
            "sampling": {
                "rate": 1.0,
                "always_capture_on_error": false,
                "always_capture_on_guardrail": false
            },
            "sink": {
                "type": "http",
                "endpoint_url": "https://audit.example.com/x",
                "batch_size": 1,
                "flush_interval_ms": 100,
                "buffer_capacity": 1,
                "on_buffer_full": "reject"
            }
        }),
        loopback_http_client(),
    )
    .unwrap();
    plugin.start_background_tasks().expect("live start");
    plugin.commit_background_tasks();
    let headers = json_headers();

    let mut first = make_ctx();
    assert!(matches!(
        plugin
            .on_final_request_body_with_context(&mut first, &headers, ai_request_body())
            .await,
        PluginResult::Continue
    ));

    let mut second = make_ctx();
    assert!(matches!(
        plugin
            .on_final_request_body_with_context(&mut second, &headers, ai_request_body())
            .await,
        PluginResult::Reject {
            status_code: 503,
            ..
        }
    ));
    assert_eq!(
        second
            .metadata
            .get("ai_transcript_audit.sink_status")
            .map(String::as_str),
        Some("rejected")
    );
}

#[tokio::test]
async fn request_only_capture_rejects_before_dispatch_after_sink_becomes_unhealthy() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .respond_with(ResponseTemplate::new(401))
        .mount(&server)
        .await;
    let endpoint = format!("{}/ingest", server.uri());
    let plugin = AiTranscriptAudit::new(
        &config_with_sink(
            &endpoint,
            json!({
                "capture": {
                    "request": true,
                    "response": false,
                    "streaming_response": false
                },
                "sampling": {
                    "rate": 1.0,
                    "always_capture_on_error": false,
                    "always_capture_on_guardrail": false
                },
                "sink": {
                    "type": "http",
                    "endpoint_url": endpoint.clone(),
                    "allow_insecure_loopback": true,
                    "batch_size": 1,
                    "flush_interval_ms": 100,
                    "max_retries": 0,
                    "on_sink_error": "reject"
                }
            }),
        ),
        loopback_http_client(),
    )
    .unwrap();
    plugin.start_background_tasks().expect("live start");
    plugin.commit_background_tasks();
    let headers = json_headers();

    let mut first = make_ctx();
    first.metadata.insert(
        "request_body".to_string(),
        String::from_utf8(ai_request_body().to_vec()).unwrap(),
    );
    let mut first_headers = headers.clone();
    assert!(matches!(
        plugin.before_proxy(&mut first, &mut first_headers).await,
        PluginResult::Continue
    ));
    let mut first_summary = create_test_transaction_summary();
    first_summary.metadata = first.metadata.clone();
    plugin.log(&first_summary).await;

    let mut rejected = false;
    for _ in 0..100 {
        let mut ctx = make_ctx();
        ctx.metadata.insert(
            "request_body".to_string(),
            String::from_utf8(ai_request_body().to_vec()).unwrap(),
        );
        let mut request_headers = headers.clone();
        if matches!(
            plugin.before_proxy(&mut ctx, &mut request_headers).await,
            PluginResult::Reject {
                status_code: 503,
                ..
            }
        ) {
            rejected = true;
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    }
    assert!(
        rejected,
        "request-only capture must enforce on_sink_error=reject before backend dispatch"
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
        .on_response_stream_terminated(&mut ctx, 200, &BodyOutcome::success(0))
        .await;
    tokio::time::sleep(std::time::Duration::from_millis(300)).await;
    let received = server.received_requests().await.unwrap_or_default();
    assert!(
        received.is_empty(),
        "an inspector that never handled body bytes must not leave an emit-ready pending stream"
    );
}

#[tokio::test]
async fn unsampled_completed_stream_writes_hash_before_deferring_emit() {
    let server = mock_sink().await;
    let endpoint = format!("{}/ingest", server.uri());
    let plugin = AiTranscriptAudit::new(
        &config_with_sink(
            &endpoint,
            json!({
                "capture": { "streaming_response": true },
                "sampling": { "rate": 0.0 }
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
    let stream =
        b"data: {\"choices\":[{\"delta\":{\"content\":\"complete\"}}]}\n\ndata: [DONE]\n\n";
    let _ = inspector.on_chunk(stream).await;
    let _ = inspector.on_end().await;

    plugin
        .on_response_stream_terminated(&mut ctx, 200, &BodyOutcome::success(stream.len() as u64))
        .await;
    assert_eq!(
        ctx.metadata
            .get("ai_transcript_audit.response_hash")
            .map(String::len),
        Some(64)
    );
    assert_eq!(
        ctx.metadata
            .get("ai_transcript_audit.sink_status")
            .map(String::as_str),
        Some("deferred")
    );
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    assert!(
        server
            .received_requests()
            .await
            .unwrap_or_default()
            .is_empty()
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
    plugin.start_background_tasks().expect("live start");
    plugin.commit_background_tasks();
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
        .on_response_stream_terminated(&mut ctx, 200, &BodyOutcome::success(stream.len() as u64))
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
    assert!(
        !ctx.metadata
            .contains_key("ai_transcript_audit.response_hash")
    );
    assert_eq!(
        ctx.metadata
            .get("ai_transcript_audit.sink_status")
            .map(String::as_str),
        Some("queued")
    );
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
    plugin.start_background_tasks().expect("live start");
    plugin.commit_background_tasks();
    let mut ctx = make_ctx();
    let headers = json_headers();
    plugin
        .on_final_request_body_with_context(&mut ctx, &headers, body.as_bytes())
        .await;
    plugin
        .capture_final_response_body(&mut ctx, 200, &headers, br#"{"ok":true}"#)
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
    plugin.start_background_tasks().expect("live start");
    plugin.commit_background_tasks();
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
        .on_response_stream_terminated(&mut ctx, 200, &BodyOutcome::success(stream.len() as u64))
        .await;
    let records = wait_for_records(&server).await;
    assert_eq!(records.len(), 1);
    let excerpt = records[0]["response_body"].as_str().unwrap_or_default();
    assert!(
        !excerpt.contains("123"),
        "raw SSN prefix leaked at the stream capture boundary: {excerpt}"
    );
    assert_eq!(records[0]["response_body_truncated"], true);
    assert!(
        ctx.metadata
            .contains_key("ai_transcript_audit.response_hash"),
        "stream-terminal hook must write the completed response hash"
    );
    assert_eq!(
        ctx.metadata
            .get("ai_transcript_audit.sink_status")
            .map(String::as_str),
        Some("queued")
    );
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
    plugin.start_background_tasks().expect("live start");
    plugin.commit_background_tasks();
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
        .on_response_stream_terminated(&mut ctx, 200, &BodyOutcome::success(stream.len() as u64))
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
    assert!(
        err.contains("unredacted request-derived data"),
        "got: {err}"
    );

    // hash_only exports no request-derived strings (envelope + keyed hashes
    // only), so an empty pattern set is fine there. metadata_only is covered
    // by metadata_only_empty_redaction_patterns_rejected.
    let hash_only = config_with_sink(
        "https://audit.example.com/x",
        json!({ "mode": "hash_only", "redaction": { "builtins": [] } }),
    );
    assert!(AiTranscriptAudit::new(&hash_only, loopback_http_client()).is_ok());
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
    // digests; no secret => process-wide random key shared by every redactor
    // built without a secret (correlatable within the process, still not the
    // unsalted SHA-256 an offline attacker could brute-force).
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
    assert_eq!(
        random_a.redact(text),
        random_b.redact(text),
        "fallback-keyed placeholders must correlate across constructions in one process"
    );
    assert_ne!(
        keyed_a.redact(text),
        random_a.redact(text),
        "the fallback key must not collide with an operator-provided secret"
    );
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
            "allow_insecure_loopback": true,
            "batch_size": 1,
            "flush_interval_ms": 100,
            "max_retries": 0,
            "on_sink_error": "reject"
        }
    });
    let plugin = AiTranscriptAudit::new(&config, loopback_http_client()).unwrap();
    plugin.start_background_tasks().expect("live start");

    plugin.commit_background_tasks();
    async fn roundtrip(plugin: &AiTranscriptAudit) -> PluginResult {
        let headers = json_headers();
        let mut ctx = make_ctx();
        plugin
            .on_final_request_body_with_context(&mut ctx, &headers, ai_request_body())
            .await;
        plugin
            .capture_final_response_body(&mut ctx, 200, &headers, br#"{"ok":true}"#)
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

// NOTE (review round 6): the former `permanent_collector_4xx_does_not_poison_
// reject_policy_sink` test asserted that a non-retryable collector 4xx keeps
// the sink healthy — the exact silent-record-loss hole the round-6 review
// flagged. Superseded by `non_retryable_sink_4xx_marks_sink_unhealthy_under_
// reject` and `sink_2xx_after_4xx_restores_health` below.

#[tokio::test]
async fn harvests_guardrail_and_token_metadata() {
    let server = mock_sink().await;
    let endpoint = format!("{}/ingest", server.uri());
    let plugin = AiTranscriptAudit::new(
        &config_with_sink(&endpoint, json!({})),
        loopback_http_client(),
    )
    .unwrap();
    plugin.start_background_tasks().expect("live start");
    plugin.commit_background_tasks();
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
        .capture_final_response_body(&mut ctx, 200, &headers, br#"{"ok":true}"#)
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

// ---------------------------------------------------------------------------
// Review round: capture completeness, sink headers, privacy, fallbacks
// ---------------------------------------------------------------------------

#[tokio::test]
async fn records_per_minute_limit_drops_excess() {
    // `max_records_per_minute` caps enqueues within the fixed window; excess
    // records are dropped under the default `on_buffer_full = drop`.
    let server = mock_sink().await;
    let endpoint = format!("{}/ingest", server.uri());
    let plugin = AiTranscriptAudit::new(
        &config_with_sink(
            &endpoint,
            json!({ "sampling": { "max_records_per_minute": 1 } }),
        ),
        loopback_http_client(),
    )
    .unwrap();
    plugin.start_background_tasks().expect("live start");
    plugin.commit_background_tasks();
    let headers = json_headers();
    for _ in 0..3 {
        let mut ctx = make_ctx();
        plugin
            .on_final_request_body_with_context(&mut ctx, &headers, ai_request_body())
            .await;
        let result = plugin
            .capture_final_response_body(&mut ctx, 200, &headers, br#"{"ok":true}"#)
            .await;
        assert!(matches!(result, PluginResult::Continue));
    }
    tokio::time::sleep(std::time::Duration::from_millis(300)).await;
    let received = server.received_requests().await.unwrap_or_default();
    let total: usize = received
        .iter()
        .filter_map(|r| serde_json::from_slice::<Value>(&r.body).ok())
        .filter_map(|body| body.as_array().map(Vec::len))
        .sum();
    assert_eq!(
        total, 1,
        "records-per-minute cap must drop everything past the budget"
    );
}

#[tokio::test]
async fn sampled_error_sse_is_teed_and_captures_body() {
    // Streaming capture on, `always_capture_on_error` OFF, but the request is
    // sampled (rate 1.0). A 5xx SSE must still be teed so the sampled record
    // carries the response transcript instead of a body-less `log` fallback.
    let server = mock_sink().await;
    let endpoint = format!("{}/ingest", server.uri());
    let plugin = AiTranscriptAudit::new(
        &config_with_sink(
            &endpoint,
            json!({
                "capture": { "streaming_response": true },
                "sampling": { "always_capture_on_error": false, "rate": 1.0 }
            }),
        ),
        loopback_http_client(),
    )
    .unwrap();
    plugin.start_background_tasks().expect("live start");
    plugin.commit_background_tasks();
    let mut ctx = make_ctx();
    plugin
        .on_final_request_body_with_context(&mut ctx, &json_headers(), ai_request_body())
        .await;
    let inspector = plugin
        .response_stream_inspector(&ctx, 500, Some("text/event-stream"))
        .expect("sampled error SSE must be teed");
    let mut chain = chain_response_stream_inspectors(vec![inspector]).expect("inspector");
    let body = b"data: {\"error\":{\"message\":\"upstream boom\"}}\n\ndata: [DONE]\n\n";
    let _ = chain.on_chunk(body).await;
    let _ = chain.on_end().await;
    plugin
        .on_response_stream_terminated(&mut ctx, 500, &BodyOutcome::success(body.len() as u64))
        .await;
    let records = wait_for_records(&server).await;
    assert_eq!(records.len(), 1);
    assert_eq!(records[0]["capture_reason"], "sampled");
    assert_eq!(records[0]["status_code"], 500);
    assert!(records[0]["response_hash"].is_string());
    assert!(
        records[0]["response_body"]
            .as_str()
            .is_some_and(|body| body.contains("upstream boom")),
        "{:?}",
        records[0]["response_body"]
    );
}

#[tokio::test]
async fn buffered_sse_captured_when_buffered_json_capture_disabled() {
    // `capture.response = false` turns off buffered JSON capture, but streaming
    // capture is on. When the proxy (or another plugin) buffered the SSE stream,
    // this hook is the only path left to attach the transcript.
    let server = mock_sink().await;
    let endpoint = format!("{}/ingest", server.uri());
    let plugin = AiTranscriptAudit::new(
        &config_with_sink(
            &endpoint,
            json!({
                "mode": "redacted_body",
                "capture": { "response": false, "streaming_response": true },
                "redaction": { "builtins": ["email"] }
            }),
        ),
        loopback_http_client(),
    )
    .unwrap();
    plugin.start_background_tasks().expect("live start");
    plugin.commit_background_tasks();
    let mut ctx = make_ctx();
    plugin
        .on_final_request_body_with_context(&mut ctx, &json_headers(), ai_request_body())
        .await;
    let response_headers = content_type_headers("text/event-stream");
    let body = br#"data: {"choices":[{"delta":{"content":"reach me at jane.doe@example.com"}}]}

data: [DONE]

"#;
    plugin
        .capture_final_response_body(&mut ctx, 200, &response_headers, body)
        .await;
    let records = wait_for_records(&server).await;
    assert_eq!(records.len(), 1);
    let excerpt = records[0]["response_body"]
        .as_str()
        .expect("buffered SSE captured despite capture.response=false");
    assert!(!excerpt.contains("jane.doe@example.com"), "{excerpt}");
    assert!(records[0]["response_hash"].is_string());
}

#[tokio::test]
async fn buffered_json_response_not_captured_when_response_capture_disabled() {
    // With `capture.response = false`, a buffered *JSON* response is not
    // captured — only buffered SSE rides the streaming policy through this hook.
    let plugin = AiTranscriptAudit::new(
        &config_with_sink(
            "https://audit.example.com/x",
            json!({ "capture": { "response": false, "streaming_response": true } }),
        ),
        loopback_http_client(),
    )
    .unwrap();
    let mut ctx = make_ctx();
    plugin
        .on_final_request_body_with_context(&mut ctx, &json_headers(), ai_request_body())
        .await;
    let result = plugin
        .capture_final_response_body(&mut ctx, 200, &json_headers(), br#"{"choices":[]}"#)
        .await;
    assert!(matches!(result, PluginResult::Continue));
    assert!(
        !ctx.metadata
            .contains_key("ai_transcript_audit.response_hash"),
        "JSON response must not be captured when capture.response=false"
    );
}

#[tokio::test]
async fn custom_sink_headers_materialize_allowlisted_secret_and_literals() {
    // A `${secret:NAME}` reference resolves ONLY FERRUM_TRANSCRIPT_SINK_SECRET_<NAME>,
    // and is materialized once at activation. Literal segments pass through.
    let server = mock_sink().await;
    let endpoint = format!("{}/ingest", server.uri());
    let config = json!({
        "sink": {
            "type": "http",
            "endpoint_url": endpoint,
            "allow_insecure_loopback": true,
            "batch_size": 1,
            "flush_interval_ms": 100,
            "custom_headers": {
                "Authorization": "Bearer ${secret:AUDIT_TOKEN}",
                "x-fixed": "fleet-a"
            }
        }
    });
    // Materialize the secret into the worker while holding the env lock, then
    // drop the guard (restoring the env) before the async roundtrip — the worker
    // never re-reads the environment, so the header stays materialized.
    let plugin = {
        let env = EnvGuard::new(&["FERRUM_TRANSCRIPT_SINK_SECRET_AUDIT_TOKEN"]);
        env.set("FERRUM_TRANSCRIPT_SINK_SECRET_AUDIT_TOKEN", "s3cr3t-value");
        let plugin = AiTranscriptAudit::new(&config, loopback_http_client()).unwrap();
        plugin.start_background_tasks().expect("live start");
        plugin.commit_background_tasks();
        plugin
    };
    let mut ctx = make_ctx();
    let headers = json_headers();
    plugin
        .on_final_request_body_with_context(&mut ctx, &headers, ai_request_body())
        .await;
    plugin
        .capture_final_response_body(&mut ctx, 200, &headers, br#"{"ok":true}"#)
        .await;
    let records = wait_for_records(&server).await;
    assert_eq!(records.len(), 1);
    let received = server.received_requests().await.unwrap_or_default();
    let request = received.last().expect("a sink request");
    let authorization = request
        .headers
        .get("authorization")
        .and_then(|value| value.to_str().ok())
        .expect("authorization header present");
    assert_eq!(
        authorization, "Bearer s3cr3t-value",
        "secret must materialize"
    );
    let fixed = request
        .headers
        .get("x-fixed")
        .and_then(|value| value.to_str().ok())
        .expect("literal header present");
    assert_eq!(fixed, "fleet-a");
}

#[test]
fn unrelated_process_env_cannot_be_referenced_in_sink_headers() {
    // The core of #3047: no generic `${NAME}` interpolation. Every attempt to
    // reference an unrelated env var — Ferrum, database, cloud, or system — is a
    // hard config error at parse (no environment is read to decide this).
    let cfg = |value: &str| {
        json!({
            "sink": {
                "type": "http",
                "endpoint_url": "https://audit.example.com/x",
                "custom_headers": { "Authorization": value }
            }
        })
    };
    let client = loopback_http_client();
    for hostile in [
        "Bearer ${FERRUM_DATABASE_PASSWORD}",
        "${FERRUM_ADMIN_JWT_SECRET}",
        "${FERRUM_DB_URL}",
        "${AWS_SECRET_ACCESS_KEY}",
        "${AZURE_CLIENT_SECRET}",
        "${GOOGLE_APPLICATION_CREDENTIALS}",
        "${PATH}",
        "${HOME}",
        "${env:FERRUM_DB_URL}",
        "${secret:lowercase}",
        "${secret:}",
        "${secret:HAS SPACE}",
        "${secret:9LEADING_DIGIT}",
        "Bearer ${secret:UNCLOSED",
    ] {
        let result = AiTranscriptAudit::new(&cfg(hostile), client.clone());
        assert!(
            result.is_err(),
            "hostile/invalid header reference must be rejected at admission: {hostile}"
        );
    }
    // The one allowlisted, well-formed form parses (secret resolved later).
    let allowed = AiTranscriptAudit::new(&cfg("Bearer ${secret:AUDIT_TOKEN}"), client.clone());
    assert!(allowed.is_ok());
    // An empty literal value is also rejected.
    let empty = AiTranscriptAudit::new(&cfg(""), client);
    assert!(empty.is_err());
}

#[tokio::test]
async fn missing_empty_or_invalid_sink_secret_fails_activation() {
    // #3069: a referenced-but-unset/empty/invalid secret must fail activation
    // (start_background_tasks Err), so the plugin generation is never published
    // instead of the header being skipped and the batch sent anyway.
    let env = EnvGuard::new(&["FERRUM_TRANSCRIPT_SINK_SECRET_ACTIVATE"]);
    let config = json!({
        "sink": {
            "type": "http",
            "endpoint_url": "https://audit.example.com/x",
            "custom_headers": { "Authorization": "Bearer ${secret:ACTIVATE}" }
        }
    });

    // Unset -> activation fails.
    env.unset("FERRUM_TRANSCRIPT_SINK_SECRET_ACTIVATE");
    let plugin = AiTranscriptAudit::new(&config, loopback_http_client()).expect("config parses");
    assert!(
        plugin.start_background_tasks().is_err(),
        "unset secret must fail activation"
    );

    // Empty -> activation fails.
    env.set("FERRUM_TRANSCRIPT_SINK_SECRET_ACTIVATE", "");
    let plugin = AiTranscriptAudit::new(&config, loopback_http_client()).expect("config parses");
    assert!(
        plugin.start_background_tasks().is_err(),
        "empty secret must fail activation"
    );

    // A value that produces an invalid HeaderValue (embedded newline) -> fails.
    env.set("FERRUM_TRANSCRIPT_SINK_SECRET_ACTIVATE", "line1\nline2");
    let plugin = AiTranscriptAudit::new(&config, loopback_http_client()).expect("config parses");
    assert!(
        plugin.start_background_tasks().is_err(),
        "secret that yields an invalid header value must fail activation"
    );

    // A valid value -> activation succeeds.
    env.set("FERRUM_TRANSCRIPT_SINK_SECRET_ACTIVATE", "good-token");
    let plugin = AiTranscriptAudit::new(&config, loopback_http_client()).expect("config parses");
    assert!(
        plugin.start_background_tasks().is_ok(),
        "valid secret must activate"
    );
    plugin.commit_background_tasks();
}

#[tokio::test]
async fn first_request_fail_closed_when_required_sink_secret_missing() {
    // With on_sink_error=reject and a required auth secret that is not set,
    // activation fails. The plugin-cache generation containing this instance is
    // therefore rejected (start_background_tasks failure aborts the generation),
    // so admission never begins healthy and the first request is never admitted
    // and sent unauthenticated. Providing the secret lets activation proceed.
    let env = EnvGuard::new(&["FERRUM_TRANSCRIPT_SINK_SECRET_FIRSTREQ"]);
    let config = json!({
        "sink": {
            "type": "http",
            "endpoint_url": "https://audit.example.com/x",
            "on_sink_error": "reject",
            "custom_headers": { "Authorization": "Bearer ${secret:FIRSTREQ}" }
        }
    });

    env.unset("FERRUM_TRANSCRIPT_SINK_SECRET_FIRSTREQ");
    let plugin = AiTranscriptAudit::new(&config, loopback_http_client()).expect("config parses");
    assert!(
        plugin.start_background_tasks().is_err(),
        "reject-on-error with a missing auth secret must fail activation before admission"
    );

    env.set("FERRUM_TRANSCRIPT_SINK_SECRET_FIRSTREQ", "token");
    let plugin = AiTranscriptAudit::new(&config, loopback_http_client()).expect("config parses");
    assert!(plugin.start_background_tasks().is_ok());
    plugin.commit_background_tasks();
}

#[tokio::test]
async fn custom_sink_headers_validation_errors() {
    let cfg = |custom: Value| {
        json!({
            "sink": {
                "type": "http",
                "endpoint_url": "https://audit.example.com/x",
                "custom_headers": custom
            }
        })
    };
    assert!(AiTranscriptAudit::new(&cfg(json!("nope")), loopback_http_client()).is_err());
    assert!(AiTranscriptAudit::new(&cfg(json!({ "x-audit": 5 })), loopback_http_client()).is_err());
    assert!(
        AiTranscriptAudit::new(&cfg(json!({ "bad name!": "v" })), loopback_http_client()).is_err()
    );
}

// ---------------------------------------------------------------------------
// Path privacy (#3068)
// ---------------------------------------------------------------------------

#[tokio::test]
async fn privacy_modes_default_to_route_template_not_literal_path() {
    // #3068: metadata_only / redacted_body / hash_only must NOT export the
    // literal sensitive path by default — they export the route identifier.
    for mode in ["metadata_only", "redacted_body", "hash_only"] {
        let ctx = ctx_with_path(SENSITIVE_PATH, true);
        let records = capture_roundtrip_over_ctx(json!({ "mode": mode }), ctx).await;
        assert_eq!(records.len(), 1, "mode {mode}");
        assert_eq!(
            records[0]["path"], "/test",
            "mode {mode} must export the route template, not the literal path"
        );
        let serialized = records[0].to_string();
        assert!(
            !serialized.contains("alice@example.com") && !serialized.contains("SECRET-9f1c"),
            "mode {mode} leaked a sensitive path segment: {serialized}"
        );
    }
}

#[tokio::test]
async fn full_body_mode_defaults_to_raw_path() {
    // full_body is the deliberate raw-capture opt-in, so the literal path is
    // exported by default there (and only there).
    let records = capture_roundtrip_over_ctx(
        json!({ "mode": "full_body", "allow_full_body": true }),
        ctx_with_path(SENSITIVE_PATH, true),
    )
    .await;
    assert_eq!(records.len(), 1);
    assert_eq!(records[0]["path"], SENSITIVE_PATH);
}

#[tokio::test]
async fn explicit_path_modes_transform_sensitive_path() {
    // omit -> no path field at all.
    let records = capture_roundtrip_over_ctx(
        json!({ "privacy": { "path_mode": "omit" } }),
        ctx_with_path(SENSITIVE_PATH, true),
    )
    .await;
    assert_eq!(records.len(), 1);
    assert!(
        records[0].get("path").is_none(),
        "omit must not export a path"
    );

    // redact -> literal path with the PII redactor applied (email removed).
    let records = capture_roundtrip_over_ctx(
        json!({ "privacy": { "path_mode": "redact" } }),
        ctx_with_path(SENSITIVE_PATH, true),
    )
    .await;
    let path = records[0]["path"].as_str().expect("redacted path present");
    assert!(
        !path.contains("alice@example.com") && path.contains("[REDACTED"),
        "redact must remove the email: {path}"
    );

    // hash -> keyed HMAC-SHA256 hex digest, no literal leakage.
    let records = capture_roundtrip_over_ctx(
        json!({ "privacy": { "path_mode": "hash" } }),
        ctx_with_path(SENSITIVE_PATH, true),
    )
    .await;
    let path = records[0]["path"].as_str().expect("hashed path present");
    assert_eq!(path.len(), 64, "hex sha256 digest: {path}");
    assert!(
        path.bytes().all(|b| b.is_ascii_hexdigit()) && !path.contains("alice"),
        "hash must not leak segments: {path}"
    );

    // raw -> literal path verbatim (explicit opt-in).
    let records = capture_roundtrip_over_ctx(
        json!({ "privacy": { "path_mode": "raw" } }),
        ctx_with_path(SENSITIVE_PATH, true),
    )
    .await;
    assert_eq!(records[0]["path"], SENSITIVE_PATH);

    // template with no matched proxy -> omitted (no route identifier available),
    // never a fallback to the literal path.
    let records = capture_roundtrip_over_ctx(
        json!({ "privacy": { "path_mode": "template" } }),
        ctx_with_path(SENSITIVE_PATH, false),
    )
    .await;
    assert!(
        records[0].get("path").is_none(),
        "template without a route identifier must omit the path, not fall back to literal"
    );
}

#[test]
fn path_mode_redact_requires_a_redaction_pattern() {
    // A pass-through redactor would export the literal path while claiming
    // redaction, so redact mode requires at least one pattern.
    let config = json!({
        "mode": "hash_only",
        "redaction": { "builtins": [] },
        "privacy": { "path_mode": "redact" },
        "sink": { "type": "http", "endpoint_url": "https://audit.example.com/x" }
    });
    assert!(AiTranscriptAudit::new(&config, loopback_http_client()).is_err());
}

#[test]
fn invalid_path_mode_rejected() {
    let config = json!({
        "privacy": { "path_mode": "verbatim" },
        "sink": { "type": "http", "endpoint_url": "https://audit.example.com/x" }
    });
    assert!(AiTranscriptAudit::new(&config, loopback_http_client()).is_err());
}

#[tokio::test]
async fn privacy_client_ip_and_redacted_response_headers_captured() {
    let server = mock_sink().await;
    let endpoint = format!("{}/ingest", server.uri());
    let plugin = AiTranscriptAudit::new(
        &config_with_sink(
            &endpoint,
            json!({
                "capture": { "headers": true },
                "privacy": { "include_client_ip": true, "include_raw_headers": true }
            }),
        ),
        loopback_http_client(),
    )
    .unwrap();
    plugin.start_background_tasks().expect("live start");
    plugin.commit_background_tasks();
    let mut ctx = make_ctx();
    let mut response_headers = json_headers();
    response_headers.insert("x-model-name".to_string(), "gpt-4o".to_string());
    response_headers.insert("authorization".to_string(), "Bearer sk-secret".to_string());
    plugin
        .on_final_request_body_with_context(&mut ctx, &json_headers(), ai_request_body())
        .await;
    plugin
        .capture_final_response_body(&mut ctx, 200, &response_headers, br#"{"ok":true}"#)
        .await;
    let records = wait_for_records(&server).await;
    assert_eq!(records.len(), 1);
    assert_eq!(records[0]["client_ip"], "127.0.0.1");
    assert_eq!(records[0]["headers"]["x-model-name"], "gpt-4o");
    assert_ne!(
        records[0]["headers"]["authorization"], "Bearer sk-secret",
        "sensitive header value must be redacted by key"
    );
}

#[tokio::test]
async fn tool_names_extracted_from_tools_and_functions() {
    let body = br#"{"model":"gpt-4o","messages":[{"role":"user","content":"hi"}],"tools":[{"type":"function","function":{"name":"get_weather"}}],"functions":[{"name":"legacy_fn"}]}"#;
    let server = mock_sink().await;
    let endpoint = format!("{}/ingest", server.uri());
    let plugin = AiTranscriptAudit::new(
        &config_with_sink(&endpoint, json!({})),
        loopback_http_client(),
    )
    .unwrap();
    plugin.start_background_tasks().expect("live start");
    plugin.commit_background_tasks();
    let mut ctx = make_ctx();
    let headers = json_headers();
    plugin
        .on_final_request_body_with_context(&mut ctx, &headers, body)
        .await;
    plugin
        .capture_final_response_body(&mut ctx, 200, &headers, br#"{"ok":true}"#)
        .await;
    let records = wait_for_records(&server).await;
    assert_eq!(records.len(), 1);
    let names: Vec<&str> = records[0]["tool_names"]
        .as_array()
        .expect("tool_names")
        .iter()
        .filter_map(|value| value.as_str())
        .collect();
    assert!(names.contains(&"get_weather"), "{names:?}");
    assert!(names.contains(&"legacy_fn"), "{names:?}");
}

#[tokio::test]
async fn stream_end_without_on_end_omits_body() {
    // Bytes arrived but `on_end` never ran (abnormal end): the terminated hook
    // omits the body/hash and marks the capture truncated.
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
    plugin.start_background_tasks().expect("live start");
    plugin.commit_background_tasks();
    let mut ctx = make_ctx();
    plugin
        .on_final_request_body_with_context(&mut ctx, &json_headers(), ai_request_body())
        .await;
    let mut inspector = plugin
        .response_stream_inspector(&ctx, 200, Some("text/event-stream"))
        .expect("inspector");
    let _ = inspector
        .on_chunk(b"data: {\"choices\":[{\"delta\":{\"content\":\"partial\"}}]}\n\n")
        .await;
    drop(inspector); // on_end never ran
    plugin
        .on_response_stream_terminated(&mut ctx, 200, &BodyOutcome::success(32))
        .await;
    let records = wait_for_records(&server).await;
    assert_eq!(records.len(), 1);
    assert!(records[0].get("response_body").is_none());
    assert!(records[0].get("response_hash").is_none());
    assert_eq!(records[0]["response_body_truncated"], true);
}

#[tokio::test]
async fn framed_grpc_response_does_not_export_body() {
    let server = mock_sink().await;
    let endpoint = format!("{}/ingest", server.uri());
    let plugin = AiTranscriptAudit::new(
        &config_with_sink(&endpoint, json!({})),
        loopback_http_client(),
    )
    .unwrap();
    plugin.start_background_tasks().expect("live start");
    plugin.commit_background_tasks();
    let mut ctx = make_ctx();
    plugin
        .on_final_request_body_with_context(&mut ctx, &json_headers(), ai_request_body())
        .await;
    let response_headers = content_type_headers("application/grpc");
    plugin
        .capture_final_response_body(&mut ctx, 200, &response_headers, b"\x00\x00\x00\x00\x02hi")
        .await;
    let records = wait_for_records(&server).await;
    assert_eq!(records.len(), 1);
    assert!(records[0].get("response_body").is_none());
    assert!(records[0].get("response_hash").is_none());
}

#[tokio::test]
async fn log_fallback_emits_from_summary_envelope() {
    // When no response hook consumed the staging entry, `log` emits using the
    // `TransactionSummary` envelope (proxy/consumer/client_ip/status).
    let server = mock_sink().await;
    let endpoint = format!("{}/ingest", server.uri());
    let plugin = AiTranscriptAudit::new(
        &config_with_sink(
            &endpoint,
            json!({ "privacy": { "include_client_ip": true } }),
        ),
        loopback_http_client(),
    )
    .unwrap();
    plugin.start_background_tasks().expect("live start");
    plugin.commit_background_tasks();
    let mut ctx = make_ctx();
    plugin
        .on_final_request_body_with_context(&mut ctx, &json_headers(), ai_request_body())
        .await;
    let mut summary = create_test_transaction_summary();
    summary.metadata = ctx.metadata.clone();
    plugin.log(&summary).await;
    let records = wait_for_records(&server).await;
    assert_eq!(records.len(), 1);
    assert_eq!(records[0]["client_ip"], "127.0.0.1");
    assert_eq!(records[0]["consumer_username"], "testuser");
    assert_eq!(records[0]["proxy_id"], "test-proxy");
    // The log fallback has no response-body access.
    assert!(records[0].get("response_body").is_none());
}

// ---------------------------------------------------------------------------
// Review round 2: staging retention, provider precedence, sampled field,
// per-instance stream sampling
// ---------------------------------------------------------------------------

#[tokio::test]
async fn sampled_validator_rejected_response_emits_committed_status_and_body() {
    // rate 1, backend 2xx: the sampled audit record is deferred. A later
    // validator replaces the response, and the committed hook must export that
    // client-visible rejection rather than the backend success.
    let server = mock_sink().await;
    let endpoint = format!("{}/ingest", server.uri());
    let plugin = AiTranscriptAudit::new(
        &config_with_sink(&endpoint, json!({ "sampling": { "rate": 1.0 } })),
        loopback_http_client(),
    )
    .unwrap();
    plugin.start_background_tasks().expect("live start");
    plugin.commit_background_tasks();
    let mut ctx = make_ctx();
    let headers = json_headers();
    plugin
        .on_final_request_body_with_context(&mut ctx, &headers, ai_request_body())
        .await;
    // Sampled backend 2xx at the audit hook: not emitted until commit.
    let result = plugin
        .on_final_response_body(&mut ctx, 200, &headers, br#"{"ok":true}"#)
        .await;
    assert!(matches!(result, PluginResult::Continue));
    let rejection_body = br#"{"error":"response schema validation failed"}"#;
    plugin
        .on_response_committed(&mut ctx, 422, &headers, rejection_body)
        .await;
    let records = wait_for_records(&server).await;
    assert_eq!(records.len(), 1);
    assert_eq!(records[0]["status_code"], 422);
    assert_eq!(
        records[0]["response_body"],
        "{\"error\":\"response schema validation failed\"}"
    );
    assert_eq!(records[0]["capture_reason"], "error");
    assert_eq!(records[0]["sampled"], true);
}

#[tokio::test]
async fn provider_prefers_ai_provider_over_federation_name() {
    // `ai_federation` publishes both keys; the exported provider must be
    // deterministic (the provider type), not HashMap-iteration-order dependent.
    let server = mock_sink().await;
    let endpoint = format!("{}/ingest", server.uri());
    let plugin = AiTranscriptAudit::new(
        &config_with_sink(&endpoint, json!({})),
        loopback_http_client(),
    )
    .unwrap();
    plugin.start_background_tasks().expect("live start");
    plugin.commit_background_tasks();
    let mut ctx = make_ctx();
    let headers = json_headers();
    plugin
        .on_final_request_body_with_context(&mut ctx, &headers, ai_request_body())
        .await;
    ctx.metadata.insert(
        "ai_federation_provider".to_string(),
        "prod-route".to_string(),
    );
    ctx.metadata
        .insert("ai_provider".to_string(), "anthropic".to_string());
    plugin
        .capture_final_response_body(&mut ctx, 200, &headers, br#"{"ok":true}"#)
        .await;
    let records = wait_for_records(&server).await;
    assert_eq!(records.len(), 1);
    assert_eq!(records[0]["provider"], "anthropic");
}

#[tokio::test]
async fn sampled_field_reflects_roll_not_emit_on_guardrail_capture() {
    // rate 0 but a guardrail fires: the record is emitted (capture_reason
    // guardrail) yet its `sampled` field reflects the (false) sampling roll.
    let server = mock_sink().await;
    let endpoint = format!("{}/ingest", server.uri());
    let plugin = AiTranscriptAudit::new(
        &config_with_sink(
            &endpoint,
            json!({ "sampling": { "rate": 0.0, "always_capture_on_guardrail": true } }),
        ),
        loopback_http_client(),
    )
    .unwrap();
    plugin.start_background_tasks().expect("live start");
    plugin.commit_background_tasks();
    let mut ctx = make_ctx();
    let headers = json_headers();
    plugin
        .on_final_request_body_with_context(&mut ctx, &headers, ai_request_body())
        .await;
    ctx.metadata
        .insert("ai_shield_rejected".to_string(), "true".to_string());
    plugin
        .capture_final_response_body(&mut ctx, 200, &headers, br#"{"ok":true}"#)
        .await;
    let records = wait_for_records(&server).await;
    assert_eq!(records.len(), 1);
    assert_eq!(records[0]["capture_reason"], "guardrail");
    assert_eq!(records[0]["sampled"], false);
}

#[tokio::test]
async fn stream_sampling_reads_instance_staging_not_shared_metadata() {
    // Two coexisting instances share the record id; the second overwrites the
    // shared `sample_hit` metadata with its own roll. Instance A must still tee
    // its sampled error stream by reading its own staged roll.
    let cfg = |rate: f64| {
        config_with_sink(
            "https://audit.example.com/x",
            json!({
                "capture": { "streaming_response": true },
                "sampling": { "always_capture_on_error": false, "rate": rate }
            }),
        )
    };
    let instance_a = AiTranscriptAudit::new(&cfg(1.0), loopback_http_client()).unwrap();
    let instance_b = AiTranscriptAudit::new(&cfg(0.0), loopback_http_client()).unwrap();
    let mut ctx = make_ctx();
    let body_str = std::str::from_utf8(ai_request_body()).unwrap();
    let mut headers = ctx.headers.clone();
    // Instance A stages first (rate 1.0 -> sample_hit true).
    ctx.metadata
        .insert("request_body".to_string(), body_str.to_string());
    instance_a.before_proxy(&mut ctx, &mut headers).await;
    assert_eq!(
        ctx.metadata
            .get("ai_transcript_audit.sample_hit")
            .map(String::as_str),
        Some("true")
    );
    // Instance B stages next (rate 0.0) and overwrites the shared sample_hit.
    instance_b.before_proxy(&mut ctx, &mut headers).await;
    assert_eq!(
        ctx.metadata
            .get("ai_transcript_audit.sample_hit")
            .map(String::as_str),
        Some("false")
    );
    // A must still tee its sampled 5xx SSE, reading its own staged roll.
    assert!(
        instance_a
            .response_stream_inspector(&ctx, 500, Some("text/event-stream"))
            .is_some(),
        "instance A must tee its sampled error stream despite B overwriting shared sample_hit"
    );
    // B (un-sampled, error capture off) does not tee.
    assert!(
        instance_b
            .response_stream_inspector(&ctx, 500, Some("text/event-stream"))
            .is_none()
    );
}

// ---------------------------------------------------------------------------
// Review round 3: fail-closed status, stream:true buffering, short-circuit
// request refresh
// ---------------------------------------------------------------------------

#[tokio::test]
async fn fail_closed_record_carries_503_status() {
    // on_sink_error=reject: once the sink is unhealthy, the client-visible
    // outcome is a 503 from the plugin, so the recovery-probe record must carry
    // 503 — not the backend 200 that would misreport a fail-closed outage.
    let server = MockServer::start().await;
    // First flush fails (flips sink unhealthy); everything after succeeds so the
    // 503 probe records land.
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
            "allow_insecure_loopback": true,
            "batch_size": 1,
            "flush_interval_ms": 100,
            "max_retries": 0,
            "on_sink_error": "reject"
        }
    });
    let plugin = AiTranscriptAudit::new(&config, loopback_http_client()).unwrap();
    plugin.start_background_tasks().expect("live start");
    plugin.commit_background_tasks();
    let headers = json_headers();
    let mut saw_503 = false;
    for _ in 0..100 {
        let mut ctx = make_ctx();
        plugin
            .on_final_request_body_with_context(&mut ctx, &headers, ai_request_body())
            .await;
        let _ = plugin
            .capture_final_response_body(&mut ctx, 200, &headers, br#"{"ok":true}"#)
            .await;
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        let received = server.received_requests().await.unwrap_or_default();
        for req in &received {
            if let Ok(body) = serde_json::from_slice::<Value>(&req.body)
                && let Some(arr) = body.as_array()
                && arr.iter().any(|r| r["status_code"] == 503)
            {
                saw_503 = true;
            }
        }
        if saw_503 {
            break;
        }
    }
    assert!(
        saw_503,
        "fail-closed audit record must carry the client-visible 503 status"
    );
}

#[tokio::test]
async fn stream_true_request_is_not_buffered() {
    let plugin = AiTranscriptAudit::new(
        &config_with_sink("https://audit.example.com/x", json!({})),
        loopback_http_client(),
    )
    .unwrap();
    // A stream:true candidate expects SSE; it must NOT request response buffering.
    let mut ctx = make_ctx();
    let stream_body =
        br#"{"model":"gpt-4o","messages":[{"role":"user","content":"hi"}],"stream":true}"#;
    plugin
        .on_final_request_body_with_context(&mut ctx, &json_headers(), stream_body)
        .await;
    assert_eq!(
        ctx.metadata
            .get("ai_transcript_audit.stream_request")
            .map(String::as_str),
        Some("true")
    );
    assert!(!plugin.should_buffer_response_body(&ctx));

    // A non-stream candidate still buffers its (JSON) response.
    let mut ctx2 = make_ctx();
    plugin
        .on_final_request_body_with_context(&mut ctx2, &json_headers(), ai_request_body())
        .await;
    assert!(plugin.should_buffer_response_body(&ctx2));
}

#[tokio::test]
async fn non_2xx_short_circuit_refreshes_staged_request_via_after_proxy() {
    // full_body mode captures raw request bytes. A before_proxy terminator
    // redacted request_body and then returned a non-2xx RejectBinary (no final
    // request-body hook, no synthetic response-body hooks). after_proxy must
    // refresh the staged request so the record reflects the redacted request,
    // not the pre-redaction prompt.
    let server = mock_sink().await;
    let endpoint = format!("{}/ingest", server.uri());
    let plugin = AiTranscriptAudit::new(
        &config_with_sink(
            &endpoint,
            json!({ "mode": "full_body", "allow_full_body": true }),
        ),
        loopback_http_client(),
    )
    .unwrap();
    plugin.start_background_tasks().expect("live start");
    plugin.commit_background_tasks();
    let mut ctx = make_ctx();
    ctx.metadata.insert(
        "request_body".to_string(),
        std::str::from_utf8(ai_request_body()).unwrap().to_string(),
    );
    let mut proxy_headers = ctx.headers.clone();
    plugin.before_proxy(&mut ctx, &mut proxy_headers).await;
    // Downstream terminator redacted the body, then surfaced a provider 502.
    let redacted =
        r#"{"model":"gpt-4o","messages":[{"role":"user","content":"my ssn is [REDACTED]"}]}"#;
    ctx.metadata
        .insert("request_body".to_string(), redacted.to_string());
    let mut response_headers = HashMap::new();
    plugin
        .after_proxy(&mut ctx, 502, &mut response_headers)
        .await;
    let mut summary = create_test_transaction_summary();
    summary.response_status_code = 502;
    summary.metadata = ctx.metadata.clone();
    plugin.log(&summary).await;
    let records = wait_for_records(&server).await;
    assert_eq!(records.len(), 1);
    let excerpt = records[0]["request_body"].as_str().expect("request body");
    assert!(
        !excerpt.contains("123-45-6789"),
        "pre-redaction SSN must not leak: {excerpt}"
    );
    assert!(
        excerpt.contains("[REDACTED]"),
        "record must reflect the redacted request: {excerpt}"
    );
}

// ---------------------------------------------------------------------------
// Review round 5: keyed body hashes, request-derived metadata redaction,
// transaction-log sampled flag, guardrail-override stream tee
// ---------------------------------------------------------------------------

/// Reference redactor sharing `secret`, used to compute expected keyed hashes.
fn keyed_reference(secret: &str) -> PiiRedactor {
    PiiRedactor::from_config(
        &["ssn".to_string()],
        &[],
        "[REDACTED:{type}]",
        true,
        Some(secret),
        "test",
    )
    .expect("valid redactor")
}

#[tokio::test]
async fn body_hashes_are_keyed_hmac_not_plain_sha256() {
    // With a configured hash_secret, the exported request/response hashes must
    // be HMAC-SHA256 under that key — reusing the redaction-placeholder key —
    // and never the plain SHA-256 an offline attacker could brute-force through
    // a predictable JSON wrapper.
    let secret = "fleet-stable-hmac-key";
    let resp_body: &[u8] = br#"{"choices":[{"message":{"content":"hi"}}]}"#;
    let records =
        capture_roundtrip(json!({ "redaction": { "hash_secret": secret } }), resp_body).await;
    assert_eq!(records.len(), 1);
    let reference = keyed_reference(secret);
    assert_eq!(
        records[0]["request_hash"],
        json!(reference.keyed_hash_hex(ai_request_body()))
    );
    assert_eq!(
        records[0]["response_hash"],
        json!(reference.keyed_hash_hex(resp_body))
    );
    use sha2::Digest;
    let plain_request = hex::encode(sha2::Sha256::digest(ai_request_body()));
    assert_ne!(
        records[0]["request_hash"],
        json!(plain_request),
        "exported body hash must not be an unkeyed SHA-256 oracle"
    );

    // hash_only mode uses the same keyed digest for consistency.
    let hash_only = capture_roundtrip(
        json!({ "mode": "hash_only", "redaction": { "hash_secret": secret } }),
        resp_body,
    )
    .await;
    assert_eq!(hash_only.len(), 1);
    assert_eq!(
        hash_only[0]["request_hash"],
        json!(reference.keyed_hash_hex(ai_request_body()))
    );
}

#[tokio::test]
async fn body_hashes_without_secret_use_process_wide_random_key() {
    // No hash_secret: the fallback key is a PROCESS-WIDE random key shared by
    // every redactor built without a secret (config reloads, multiple
    // instances), so the same body hashes identically across instances — the
    // documented "correlatable within one process lifetime" guarantee — while
    // still never being a stable public SHA-256.
    let resp_body: &[u8] = br#"{"ok":true}"#;
    let first = capture_roundtrip(json!({}), resp_body).await;
    let second = capture_roundtrip(json!({}), resp_body).await;
    assert_eq!(first.len(), 1);
    assert_eq!(second.len(), 1);
    assert_eq!(
        first[0]["request_hash"], second[0]["request_hash"],
        "fallback-keyed hashes must correlate across instances within one process"
    );
    use sha2::Digest;
    let plain_request = hex::encode(sha2::Sha256::digest(ai_request_body()));
    assert_ne!(
        first[0]["request_hash"],
        json!(plain_request),
        "fallback-keyed hash must not be an unkeyed SHA-256 oracle"
    );
}

#[tokio::test]
async fn pii_redactor_fallback_key_is_shared_across_constructions() {
    // Direct check on the shared utility: two separately-constructed redactors
    // without a hash_secret (a config reload) must produce identical keyed
    // hashes and identical hashed placeholders.
    let make = || {
        PiiRedactor::from_config(
            &["ssn".to_string()],
            &[],
            "[REDACTED:{type}]",
            true,
            None,
            "test",
        )
        .expect("valid redactor")
    };
    let first = make();
    let second = make();
    assert_eq!(
        first.keyed_hash_hex(b"payload"),
        second.keyed_hash_hex(b"payload"),
        "process-wide fallback key must survive redactor reconstruction"
    );
    assert_eq!(
        first.redact("ssn 123-45-6789"),
        second.redact("ssn 123-45-6789"),
        "hashed placeholders must stay correlatable across reconstructions"
    );
}

#[tokio::test]
async fn stream_hash_is_incremental_keyed_hmac_over_teed_bytes() {
    let secret = "fleet-stable-hmac-key";
    let server = mock_sink().await;
    let endpoint = format!("{}/ingest", server.uri());
    let plugin = AiTranscriptAudit::new(
        &config_with_sink(
            &endpoint,
            json!({
                "capture": { "streaming_response": true },
                "redaction": { "hash_secret": secret }
            }),
        ),
        loopback_http_client(),
    )
    .unwrap();
    plugin.start_background_tasks().expect("live start");
    plugin.commit_background_tasks();
    let mut ctx = make_ctx();
    plugin
        .on_final_request_body_with_context(&mut ctx, &json_headers(), ai_request_body())
        .await;
    let mut inspector = plugin
        .response_stream_inspector(&ctx, 200, Some("text/event-stream"))
        .expect("inspector");
    let chunk_a: &[u8] = b"data: {\"choices\":[{\"delta\":{\"content\":\"hel\"}}]}\n\n";
    let chunk_b: &[u8] = b"data: [DONE]\n\n";
    let _ = inspector.on_chunk(chunk_a).await;
    let _ = inspector.on_chunk(chunk_b).await;
    let _ = inspector.on_end().await;
    plugin
        .on_response_stream_terminated(
            &mut ctx,
            200,
            &BodyOutcome::success((chunk_a.len() + chunk_b.len()) as u64),
        )
        .await;
    let records = wait_for_records(&server).await;
    assert_eq!(records.len(), 1);
    let mut full_stream = chunk_a.to_vec();
    full_stream.extend_from_slice(chunk_b);
    assert_eq!(
        records[0]["response_hash"],
        json!(keyed_reference(secret).keyed_hash_hex(&full_stream)),
        "streamed hash must be the keyed HMAC over the full teed byte sequence"
    );
}

#[tokio::test]
async fn request_derived_model_and_tool_names_are_redacted() {
    // `model` and tool names are copied straight from the user request body, so
    // PII smuggled into them must not bypass redaction via the metadata side
    // door — in redacted_body AND metadata_only modes. full_body (the explicit
    // raw-capture opt-in) keeps the raw values.
    let body: &[u8] = br#"{"model":"gpt-4o-ssn-123-45-6789","messages":[{"role":"user","content":"hi"}],"tools":[{"type":"function","function":{"name":"lookup-123-45-6789"}}]}"#;
    for overrides in [json!({}), json!({ "mode": "metadata_only" })] {
        let server = mock_sink().await;
        let endpoint = format!("{}/ingest", server.uri());
        let plugin = AiTranscriptAudit::new(
            &config_with_sink(&endpoint, overrides.clone()),
            loopback_http_client(),
        )
        .expect("valid config");
        plugin.start_background_tasks().expect("live start");
        plugin.commit_background_tasks();
        let mut ctx = make_ctx();
        let headers = json_headers();
        plugin
            .on_final_request_body_with_context(&mut ctx, &headers, body)
            .await;
        plugin
            .capture_final_response_body(&mut ctx, 200, &headers, br#"{"ok":true}"#)
            .await;
        let records = wait_for_records(&server).await;
        assert_eq!(records.len(), 1, "overrides: {overrides}");
        let model = records[0]["model"].as_str().expect("model");
        assert!(
            !model.contains("123-45-6789"),
            "raw SSN leaked through the model field ({overrides}): {model}"
        );
        assert!(model.contains("[REDACTED:ssn:"), "got: {model}");
        let tool = records[0]["tool_names"][0].as_str().expect("tool name");
        assert!(
            !tool.contains("123-45-6789"),
            "raw SSN leaked through a tool name ({overrides}): {tool}"
        );
        assert!(tool.contains("[REDACTED:ssn:"), "got: {tool}");
    }

    // full_body keeps the raw request-derived values (deliberate opt-in).
    let server = mock_sink().await;
    let endpoint = format!("{}/ingest", server.uri());
    let plugin = AiTranscriptAudit::new(
        &config_with_sink(
            &endpoint,
            json!({ "mode": "full_body", "allow_full_body": true }),
        ),
        loopback_http_client(),
    )
    .unwrap();
    plugin.start_background_tasks().expect("live start");
    plugin.commit_background_tasks();
    let mut ctx = make_ctx();
    let headers = json_headers();
    plugin
        .on_final_request_body_with_context(&mut ctx, &headers, body)
        .await;
    plugin
        .capture_final_response_body(&mut ctx, 200, &headers, br#"{"ok":true}"#)
        .await;
    let records = wait_for_records(&server).await;
    assert_eq!(records.len(), 1);
    assert_eq!(records[0]["model"], "gpt-4o-ssn-123-45-6789");
}

#[tokio::test]
async fn transaction_log_sampled_flag_carries_roll_not_emit() {
    // rate 0 + guardrail override: the record emits, but the transaction-log
    // `sampled` metadata must carry the losing sampling roll (matching the
    // exported record's `sampled` field) — `sink_status` already conveys
    // whether a record was emitted.
    let server = mock_sink().await;
    let endpoint = format!("{}/ingest", server.uri());
    let plugin = AiTranscriptAudit::new(
        &config_with_sink(
            &endpoint,
            json!({ "sampling": { "rate": 0.0, "always_capture_on_guardrail": true } }),
        ),
        loopback_http_client(),
    )
    .unwrap();
    plugin.start_background_tasks().expect("live start");
    plugin.commit_background_tasks();
    let mut ctx = make_ctx();
    let headers = json_headers();
    plugin
        .on_final_request_body_with_context(&mut ctx, &headers, ai_request_body())
        .await;
    ctx.metadata
        .insert("ai_shield_rejected".to_string(), "true".to_string());
    plugin
        .capture_final_response_body(&mut ctx, 200, &headers, br#"{"ok":true}"#)
        .await;
    assert_eq!(
        ctx.metadata
            .get("ai_transcript_audit.sampled")
            .map(String::as_str),
        Some("false"),
        "transaction-log sampled flag must be the roll, not the emit decision"
    );
    assert_eq!(
        ctx.metadata
            .get("ai_transcript_audit.sink_status")
            .map(String::as_str),
        Some("queued")
    );
    let records = wait_for_records(&server).await;
    assert_eq!(records.len(), 1);
    assert_eq!(records[0]["sampled"], false);
    assert_eq!(records[0]["capture_reason"], "guardrail");
}

#[tokio::test]
async fn tool_governor_request_decision_forces_request_only_capture_and_is_harvested() {
    let server = mock_sink().await;
    let endpoint = format!("{}/ingest", server.uri());
    let plugin = AiTranscriptAudit::new(
        &config_with_sink(
            &endpoint,
            json!({
                "capture": {
                    "request": true,
                    "response": false,
                    "streaming_response": false
                },
                "sampling": {
                    "rate": 0.0,
                    "always_capture_on_guardrail": true,
                    "always_capture_on_error": false
                }
            }),
        ),
        loopback_http_client(),
    )
    .unwrap();
    plugin.start_background_tasks().expect("live start");
    plugin.commit_background_tasks();

    let mut ctx = make_ctx();
    plugin
        .on_final_request_body_with_context(&mut ctx, &json_headers(), ai_request_body())
        .await;
    ctx.metadata.insert(
        "ai_tool_governor.decision".to_string(),
        "require_approval".to_string(),
    );
    ctx.metadata.insert(
        "ai_tool_governor.tool_names".to_string(),
        "lookup_customer".to_string(),
    );
    ctx.metadata
        .insert("ai_tool_governor.risk".to_string(), "high".to_string());
    let mut summary = create_test_transaction_summary();
    summary.response_status_code = 200;
    summary.metadata = ctx.metadata.clone();
    plugin.log(&summary).await;

    let records = wait_for_records(&server).await;
    assert_eq!(records.len(), 1);
    assert_eq!(records[0]["sampled"], false);
    assert_eq!(records[0]["capture_reason"], "guardrail");
    assert_eq!(
        records[0]["guardrails"]["ai_tool_governor.decision"],
        "require_approval"
    );
    assert_eq!(
        records[0]["guardrails"]["ai_tool_governor.tool_names"],
        "lookup_customer"
    );
    assert_eq!(records[0]["guardrails"]["ai_tool_governor.risk"], "high");
}

struct TerminalToolGovernorDecision;

#[async_trait]
impl Plugin for TerminalToolGovernorDecision {
    fn name(&self) -> &str {
        "terminal_tool_governor_decision"
    }

    fn priority(&self) -> u16 {
        priority::AI_TOOL_GOVERNOR
    }

    async fn on_response_stream_terminated(
        &self,
        ctx: &mut RequestContext,
        _response_status: u16,
        _outcome: &BodyOutcome,
    ) {
        ctx.metadata.insert(
            "ai_tool_governor.decision".to_string(),
            "redact_args".to_string(),
        );
    }
}

#[tokio::test]
async fn tool_governor_buffered_and_terminal_stream_decisions_force_capture_but_allow_does_not() {
    let overrides = json!({
        "capture": {
            "request": true,
            "response": true,
            "streaming_response": true
        },
        "sampling": {
            "rate": 0.0,
            "always_capture_on_guardrail": true,
            "always_capture_on_error": false
        }
    });

    let buffered_server = mock_sink().await;
    let buffered_endpoint = format!("{}/ingest", buffered_server.uri());
    let buffered = AiTranscriptAudit::new(
        &config_with_sink(&buffered_endpoint, overrides.clone()),
        loopback_http_client(),
    )
    .unwrap();
    buffered.start_background_tasks().expect("live start");
    buffered.commit_background_tasks();
    let headers = json_headers();
    let mut buffered_ctx = make_ctx();
    buffered
        .on_final_request_body_with_context(&mut buffered_ctx, &headers, ai_request_body())
        .await;
    buffered_ctx.metadata.insert(
        "ai_tool_governor.decision".to_string(),
        "dry_run".to_string(),
    );
    buffered_ctx.metadata.insert(
        "ai_tool_governor.policy_ids".to_string(),
        "sensitive-tools".to_string(),
    );
    buffered
        .capture_final_response_body(&mut buffered_ctx, 200, &headers, br#"{"ok":true}"#)
        .await;
    let buffered_records = wait_for_records(&buffered_server).await;
    assert_eq!(buffered_records.len(), 1);
    assert_eq!(buffered_records[0]["capture_reason"], "guardrail");
    assert_eq!(
        buffered_records[0]["guardrails"]["ai_tool_governor.decision"],
        "dry_run"
    );

    let stream_server = mock_sink().await;
    let stream_endpoint = format!("{}/ingest", stream_server.uri());
    let streaming = Arc::new(
        AiTranscriptAudit::new(
            &config_with_sink(&stream_endpoint, overrides),
            loopback_http_client(),
        )
        .unwrap(),
    );
    streaming.start_background_tasks().expect("live start");
    streaming.commit_background_tasks();
    let mut stream_ctx = make_ctx();
    streaming
        .on_final_request_body_with_context(&mut stream_ctx, &headers, ai_request_body())
        .await;
    let mut inspector = streaming
        .response_stream_inspector(&stream_ctx, 200, Some("text/event-stream"))
        .expect("streaming capture is enabled");
    let stream =
        b"data: {\"object\":\"chat.completion.chunk\",\"choices\":[{\"index\":0,\"delta\":{\"content\":\"ok\"}}]}\n\ndata: [DONE]\n\n";
    let _ = inspector.on_chunk(stream).await;
    let _ = inspector.on_end().await;
    let termination_plugins: Vec<Arc<dyn Plugin>> =
        vec![streaming.clone(), Arc::new(TerminalToolGovernorDecision)];
    run_response_stream_termination_hooks(
        &termination_plugins,
        &mut stream_ctx,
        200,
        &BodyOutcome::success(stream.len() as u64),
    )
    .await;
    let stream_records = wait_for_records(&stream_server).await;
    assert_eq!(stream_records.len(), 1);
    assert_eq!(stream_records[0]["capture_reason"], "guardrail");
    assert_eq!(
        stream_records[0]["guardrails"]["ai_tool_governor.decision"],
        "redact_args"
    );

    let allow_server = mock_sink().await;
    let allow_endpoint = format!("{}/ingest", allow_server.uri());
    let allow = AiTranscriptAudit::new(
        &config_with_sink(
            &allow_endpoint,
            json!({
                "sampling": {
                    "rate": 0.0,
                    "always_capture_on_guardrail": true,
                    "always_capture_on_error": false
                }
            }),
        ),
        loopback_http_client(),
    )
    .unwrap();
    allow.start_background_tasks().expect("live start");
    allow.commit_background_tasks();
    let mut allow_ctx = make_ctx();
    allow
        .on_final_request_body_with_context(&mut allow_ctx, &headers, ai_request_body())
        .await;
    allow_ctx
        .metadata
        .insert("ai_tool_governor.decision".to_string(), "allow".to_string());
    allow
        .capture_final_response_body(&mut allow_ctx, 200, &headers, br#"{"ok":true}"#)
        .await;
    tokio::time::sleep(std::time::Duration::from_millis(300)).await;
    assert!(
        allow_server
            .received_requests()
            .await
            .unwrap_or_default()
            .is_empty(),
        "an ordinary allow decision must not override a losing sampling roll"
    );
}

#[tokio::test]
async fn transcript_internal_lifecycle_state_never_reaches_transaction_log_metadata() {
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
    ctx.metadata.insert(
        "ai_transcript_audit.stream_marker.0x7ffeeabc".to_string(),
        "true".to_string(),
    );
    let logged = clone_log_metadata(&ctx);
    for key in logged.keys() {
        assert!(
            !matches!(
                key.as_str(),
                "ai_transcript_audit.candidate"
                    | "ai_transcript_audit.sample_hit"
                    | "ai_transcript_audit.stream_request"
                    | "ai_transcript_audit.final_req_seen"
            ) && !key.starts_with("ai_transcript_audit.stream_marker"),
            "internal or pointer-derived transcript state leaked to logs: {key}"
        );
    }
    assert!(
        logged.contains_key("ai_transcript_audit.record_id"),
        "documented candidate correlation metadata must remain available"
    );
}

#[tokio::test]
async fn local_dedup_replay_is_staged_first_and_emits_exactly_one_marked_record() {
    let server = mock_sink().await;
    let endpoint = format!("{}/ingest", server.uri());
    let audit = AiTranscriptAudit::new(
        &config_with_sink(&endpoint, json!({ "sampling": { "rate": 1.0 } })),
        loopback_http_client(),
    )
    .unwrap();
    audit.start_background_tasks().expect("live start");
    audit.commit_background_tasks();
    let dedup = RequestDeduplication::new(
        &json!({ "scope_by_consumer": false }),
        loopback_http_client(),
    )
    .unwrap();
    assert!(
        audit.priority() < dedup.priority(),
        "audit staging must run before a replay can terminate the chain"
    );
    let request_body = ai_request_body();
    let response_body = br#"{"id":"chatcmpl-1","choices":[{"message":{"content":"ok"}}]}"#;

    let mut first = make_ctx();
    first.request_body_bytes = Some(Bytes::copy_from_slice(request_body));
    first.metadata.insert(
        "request_body".to_string(),
        String::from_utf8(request_body.to_vec()).unwrap(),
    );
    let mut first_headers = json_headers();
    first_headers.insert(
        "idempotency-key".to_string(),
        "audit-replay-key".to_string(),
    );
    assert!(matches!(
        audit.before_proxy(&mut first, &mut first_headers).await,
        PluginResult::Continue
    ));
    assert!(matches!(
        dedup.before_proxy(&mut first, &mut first_headers).await,
        PluginResult::Continue
    ));
    dedup
        .on_final_response_body(&mut first, 200, &json_headers(), response_body)
        .await;
    audit
        .capture_final_response_body(&mut first, 200, &json_headers(), response_body)
        .await;

    let mut replay = make_ctx();
    replay.request_body_bytes = Some(Bytes::copy_from_slice(request_body));
    replay.metadata.insert(
        "request_body".to_string(),
        String::from_utf8(request_body.to_vec()).unwrap(),
    );
    let mut replay_headers = json_headers();
    replay_headers.insert(
        "idempotency-key".to_string(),
        "audit-replay-key".to_string(),
    );
    assert!(matches!(
        audit.before_proxy(&mut replay, &mut replay_headers).await,
        PluginResult::Continue
    ));
    let replay_result = dedup.before_proxy(&mut replay, &mut replay_headers).await;
    let (status, headers, body) = match replay_result {
        PluginResult::RejectBinary {
            status_code,
            headers,
            body,
        } => (status_code, headers, body),
        other => panic!("expected cached replay, got {other:?}"),
    };
    assert_eq!(
        replay
            .metadata
            .get("request_deduplication.replayed")
            .map(String::as_str),
        Some("true")
    );
    audit
        .capture_final_response_body(&mut replay, status, &headers, &body)
        .await;

    let records = wait_for_total_records(&server, 2).await;
    assert_eq!(
        records.len(),
        2,
        "the original and replay must each emit exactly one record"
    );
    let replay_records: Vec<&Value> = records
        .iter()
        .filter(|record| record["cache"]["request_deduplication.replayed"].as_str() == Some("true"))
        .collect();
    assert_eq!(replay_records.len(), 1);
    assert_eq!(replay_records[0]["status_code"], 200);
    assert!(replay_records[0]["response_body"].is_string());
    assert_ne!(records[0]["record_id"], records[1]["record_id"]);
}

#[tokio::test]
async fn request_guardrail_after_staging_tees_unsampled_stream() {
    // capture.streaming_response = "sampled" with a losing roll: a request-side
    // guardrail (ai_prompt_shield 2925 / ai_semantic_firewall 2968 /
    // ai_request_guard 2975) fires AFTER this plugin staged at 2740 but BEFORE
    // the proxy's dispatch decision. The tee gate is evaluated at dispatch
    // time, so always_capture_on_guardrail still captures response evidence.
    let server = mock_sink().await;
    let endpoint = format!("{}/ingest", server.uri());
    let plugin = AiTranscriptAudit::new(
        &config_with_sink(
            &endpoint,
            json!({
                "capture": { "streaming_response": "sampled" },
                "sampling": { "rate": 0.0, "always_capture_on_guardrail": true }
            }),
        ),
        loopback_http_client(),
    )
    .unwrap();
    plugin.start_background_tasks().expect("live start");
    plugin.commit_background_tasks();
    let mut ctx = make_ctx();
    let headers = json_headers();
    plugin
        .on_final_request_body_with_context(&mut ctx, &headers, ai_request_body())
        .await;
    // Losing roll, no guardrail yet: not teed.
    assert!(!plugin.forces_reqwest_dispatch(&ctx));
    // A request-side guardrail publishes its marker after staging.
    ctx.metadata
        .insert("ai_shield_redacted".to_string(), "true".to_string());
    assert!(
        plugin.forces_reqwest_dispatch(&ctx),
        "request-side guardrail hit must tee the un-sampled stream"
    );
    let mut inspector = plugin
        .response_stream_inspector(&ctx, 200, Some("text/event-stream"))
        .expect("guardrail-flagged un-sampled stream must get an inspector");
    let stream: &[u8] = b"data: {\"choices\":[{\"delta\":{\"content\":\"evidence\"}}]}\n\n";
    let _ = inspector.on_chunk(stream).await;
    let _ = inspector.on_end().await;
    plugin
        .on_response_stream_terminated(&mut ctx, 200, &BodyOutcome::success(stream.len() as u64))
        .await;
    let records = wait_for_records(&server).await;
    assert_eq!(records.len(), 1);
    assert_eq!(records[0]["capture_reason"], "guardrail");
    assert!(
        records[0]["response_hash"].is_string(),
        "guardrail-teed stream must carry response evidence"
    );
    assert!(
        records[0]["response_body"]
            .as_str()
            .unwrap_or_default()
            .contains("evidence")
    );

    // With the guardrail override disabled, the same hit must NOT tee.
    let no_override = AiTranscriptAudit::new(
        &config_with_sink(
            "https://audit.example.com/x",
            json!({
                "capture": { "streaming_response": "sampled" },
                "sampling": { "rate": 0.0, "always_capture_on_guardrail": false }
            }),
        ),
        loopback_http_client(),
    )
    .unwrap();
    let mut ctx2 = make_ctx();
    no_override
        .on_final_request_body_with_context(&mut ctx2, &headers, ai_request_body())
        .await;
    ctx2.metadata
        .insert("ai_shield_redacted".to_string(), "true".to_string());
    assert!(!no_override.forces_reqwest_dispatch(&ctx2));
    assert!(
        no_override
            .response_stream_inspector(&ctx2, 200, Some("text/event-stream"))
            .is_none()
    );
}

// ---------------------------------------------------------------------------
// Review round 6: content-type re-pin gate, non-retryable sink 4xx health,
// SSE delta reassembly, metadata_only empty-redactor, staged sampled flag,
// deferred sink_status
// ---------------------------------------------------------------------------

#[tokio::test]
async fn stream_true_request_is_not_re_pinned_by_content_type_hook() {
    // `should_buffer_response_body_for_content_type` also runs when the proxy
    // re-evaluates buffer-vs-stream for a released response. It must honor the
    // same per-request `stream: true` opt-out as `should_buffer_response_body`,
    // or a co-located plugin's released non-SSE JSON stream response gets
    // re-pinned to the buffered path.
    let plugin = AiTranscriptAudit::new(
        &config_with_sink("https://audit.example.com/x", json!({})),
        loopback_http_client(),
    )
    .unwrap();
    let headers = json_headers();
    let mut ctx = make_ctx();
    let stream_body =
        br#"{"model":"gpt-4o","messages":[{"role":"user","content":"hi"}],"stream":true}"#;
    plugin
        .on_final_request_body_with_context(&mut ctx, &headers, stream_body)
        .await;
    assert!(
        !plugin.should_buffer_response_body_for_content_type(
            &ctx,
            Some("application/json"),
            200,
            &headers,
        ),
        "stream:true request must never be re-pinned to buffered by the content-type hook"
    );

    // A non-stream candidate still buffers a JSON response via this hook.
    let mut ctx2 = make_ctx();
    plugin
        .on_final_request_body_with_context(&mut ctx2, &headers, ai_request_body())
        .await;
    assert!(plugin.should_buffer_response_body_for_content_type(
        &ctx2,
        Some("application/json"),
        200,
        &headers,
    ));
}

#[tokio::test]
async fn non_candidate_json_is_not_re_pinned_by_content_type_hook() {
    // Review round 7: a non-AI JSON POST is classified `candidate=false`; its
    // (possibly large) ordinary JSON response must not be re-pinned to the
    // buffered path by the content-type re-evaluation — `on_final_response_body`
    // would ignore it anyway. The hook must mirror `should_buffer_response_body`'s
    // full per-request decision, including the candidate tri-state.
    let plugin = AiTranscriptAudit::new(
        &config_with_sink("https://audit.example.com/x", json!({})),
        loopback_http_client(),
    )
    .unwrap();
    let headers = json_headers();
    let mut ctx = make_ctx();
    plugin
        .on_final_request_body_with_context(&mut ctx, &headers, br#"{"order_id":42,"total":9.99}"#)
        .await;
    assert_eq!(
        ctx.metadata
            .get("ai_transcript_audit.candidate")
            .map(String::as_str),
        Some("false")
    );
    assert!(
        !plugin.should_buffer_response_body_for_content_type(
            &ctx,
            Some("application/json"),
            200,
            &headers,
        ),
        "candidate=false must suppress content-type re-pinning of non-AI JSON responses"
    );
    // The two buffering hooks must agree on the classified non-AI request.
    assert!(!plugin.should_buffer_response_body(&ctx));

    // With no candidate marker at all (request never went through staging),
    // both hooks fall back to the same POST + JSON-request heuristic.
    let unstaged = make_ctx();
    assert!(plugin.should_buffer_response_body(&unstaged));
    assert!(
        plugin.should_buffer_response_body_for_content_type(
            &unstaged,
            Some("application/json"),
            200,
            &headers,
        ),
        "hooks must never disagree for an unstaged request"
    );
}

#[tokio::test]
async fn non_retryable_sink_4xx_marks_sink_unhealthy_under_reject() {
    // A collector returning a non-retryable non-2xx (e.g. 401 from an expired
    // token) passes through the shared batch helper as Ok (batch discarded, no
    // retry) — but every record was lost, so under on_sink_error=reject the
    // sink must go unhealthy and subsequent buffered-response requests must be
    // rejected rather than flow unaudited.
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
            "allow_insecure_loopback": true,
            "batch_size": 1,
            "flush_interval_ms": 100,
            "max_retries": 0,
            "on_sink_error": "reject"
        }
    });
    let plugin = AiTranscriptAudit::new(&config, loopback_http_client()).unwrap();
    plugin.start_background_tasks().expect("live start");
    plugin.commit_background_tasks();
    let headers = json_headers();
    let mut saw_reject = false;
    for _ in 0..100 {
        let mut ctx = make_ctx();
        plugin
            .on_final_request_body_with_context(&mut ctx, &headers, ai_request_body())
            .await;
        let result = plugin
            .capture_final_response_body(&mut ctx, 200, &headers, br#"{"ok":true}"#)
            .await;
        if matches!(
            result,
            PluginResult::Reject {
                status_code: 503,
                ..
            }
        ) {
            assert_eq!(
                ctx.metadata
                    .get("ai_transcript_audit.sink_status")
                    .map(String::as_str),
                Some("rejected")
            );
            saw_reject = true;
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    }
    assert!(
        saw_reject,
        "a 401-discarding collector must flip the sink unhealthy and reject audited traffic"
    );
}

#[tokio::test]
async fn unhealthy_sink_rejects_unsampled_candidate_that_may_emit_at_commit() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .respond_with(ResponseTemplate::new(401))
        .mount(&server)
        .await;
    let endpoint = format!("{}/ingest", server.uri());
    let plugin = AiTranscriptAudit::new(
        &config_with_sink(
            &endpoint,
            json!({
                "sampling": { "rate": 0.0, "always_capture_on_error": true },
                "sink": {
                    "type": "http",
                    "endpoint_url": endpoint.clone(),
                    "allow_insecure_loopback": true,
                    "batch_size": 1,
                    "flush_interval_ms": 100,
                    "max_retries": 0,
                    "on_sink_error": "reject"
                }
            }),
        ),
        loopback_http_client(),
    )
    .unwrap();
    plugin.start_background_tasks().expect("live start");
    plugin.commit_background_tasks();
    let headers = json_headers();

    // Emit one error record so the collector 401 marks the sink unhealthy.
    let mut error_ctx = make_ctx();
    plugin
        .on_final_request_body_with_context(&mut error_ctx, &headers, ai_request_body())
        .await;
    plugin
        .capture_final_response_body(&mut error_ctx, 500, &headers, br#"{"error":"backend"}"#)
        .await;

    let mut saw_reject = false;
    for _ in 0..100 {
        let mut ctx = make_ctx();
        plugin
            .on_final_request_body_with_context(&mut ctx, &headers, ai_request_body())
            .await;
        let result = plugin
            .on_final_response_body(&mut ctx, 200, &headers, br#"{"ok":true}"#)
            .await;
        if matches!(
            result,
            PluginResult::Reject {
                status_code: 503,
                ..
            }
        ) {
            saw_reject = true;
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    }
    assert!(
        saw_reject,
        "an unsampled candidate that a later validator may turn into an error must fail closed"
    );
}

#[tokio::test]
async fn sink_2xx_after_4xx_restores_health() {
    // Recovery stays on the probe model: once the collector answers 2xx again,
    // the flushed probe records flip sink_healthy back and rejects stop.
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .respond_with(ResponseTemplate::new(403))
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
            "allow_insecure_loopback": true,
            "batch_size": 1,
            "flush_interval_ms": 100,
            "max_retries": 0,
            "on_sink_error": "reject"
        }
    });
    let plugin = AiTranscriptAudit::new(&config, loopback_http_client()).unwrap();
    plugin.start_background_tasks().expect("live start");
    plugin.commit_background_tasks();
    let headers = json_headers();
    let mut saw_reject = false;
    let mut recovered = false;
    for _ in 0..100 {
        let mut ctx = make_ctx();
        plugin
            .on_final_request_body_with_context(&mut ctx, &headers, ai_request_body())
            .await;
        let result = plugin
            .capture_final_response_body(&mut ctx, 200, &headers, br#"{"ok":true}"#)
            .await;
        match result {
            PluginResult::Reject { .. } => saw_reject = true,
            PluginResult::Continue if saw_reject => {
                recovered = true;
                break;
            }
            _ => {}
        }
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    }
    assert!(
        saw_reject,
        "the initial 403 must reject at least one request"
    );
    assert!(
        recovered,
        "a successful batch send must restore sink health and stop the rejects"
    );
}

#[tokio::test]
async fn sse_pii_split_across_deltas_is_redacted_in_reassembled_excerpt() {
    // PII split across `delta.content` fragments evades per-frame regexes; in
    // redacted_body mode the exported excerpt must be the redaction of the
    // REASSEMBLED per-choice completion text.
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
    plugin.start_background_tasks().expect("live start");
    plugin.commit_background_tasks();
    let mut ctx = make_ctx();
    plugin
        .on_final_request_body_with_context(&mut ctx, &json_headers(), ai_request_body())
        .await;
    let mut inspector = plugin
        .response_stream_inspector(&ctx, 200, Some("text/event-stream"))
        .expect("inspector");
    // The SSN 123-45-6789 is split so no single frame matches the regex.
    let chunks: [&[u8]; 4] = [
        b"data: {\"object\":\"chat.completion.chunk\",\"choices\":[{\"index\":0,\"delta\":{\"content\":\"your ssn is 123-\"}}]}\n\n",
        b"data: {\"object\":\"chat.completion.chunk\",\"choices\":[{\"index\":0,\"delta\":{\"content\":\"45-67\"}}]}\n\n",
        b"data: {\"object\":\"chat.completion.chunk\",\"choices\":[{\"index\":0,\"delta\":{\"content\":\"89 ok\"}}]}\n\n",
        b"data: [DONE]\n\n",
    ];
    let mut total = 0u64;
    for chunk in chunks {
        let _ = inspector.on_chunk(chunk).await;
        total += chunk.len() as u64;
    }
    let _ = inspector.on_end().await;
    plugin
        .on_response_stream_terminated(&mut ctx, 200, &BodyOutcome::success(total))
        .await;
    let records = wait_for_records(&server).await;
    assert_eq!(records.len(), 1);
    let excerpt = records[0]["response_body"].as_str().expect("excerpt");
    assert!(
        !excerpt.contains("123-45-6789") && !excerpt.contains("45-67"),
        "split-delta SSN must not survive reassembled redaction: {excerpt}"
    );
    assert!(
        excerpt.contains("[REDACTED:ssn:"),
        "reassembled excerpt must carry the redaction placeholder: {excerpt}"
    );
    assert!(
        excerpt.contains("sse_reassembled"),
        "SSE excerpt must be annotated as reassembled completion text: {excerpt}"
    );
    assert!(
        excerpt.contains("your ssn is"),
        "non-PII completion text must survive reassembly: {excerpt}"
    );
}

#[tokio::test]
async fn mixed_sse_text_and_interleaved_tool_calls_are_reassembled_and_redacted() {
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
    plugin.start_background_tasks().expect("live start");
    plugin.commit_background_tasks();
    let mut ctx = make_ctx();
    plugin
        .on_final_request_body_with_context(&mut ctx, &json_headers(), ai_request_body())
        .await;
    let mut inspector = plugin
        .response_stream_inspector(&ctx, 200, Some("text/event-stream"))
        .expect("inspector");
    let chunks: [&[u8]; 6] = [
        b"data: {\"object\":\"chat.completion.chunk\",\"choices\":[{\"index\":0,\"delta\":{\"content\":\"I will look that up.\"}}]}\n\n",
        b"data: {\"object\":\"chat.completion.chunk\",\"choices\":[{\"index\":0,\"delta\":{\"tool_calls\":[{\"index\":0,\"id\":\"call_\",\"type\":\"function\",\"function\":{\"name\":\"lookup_\",\"arguments\":\"{\\\"pass\"}},{\"index\":1,\"id\":\"call_b\",\"type\":\"function\",\"function\":{\"name\":\"notify\",\"arguments\":\"{\\\"token\\\":\\\"abc\"}}]}}]}\n\n",
        b"data: {\"object\":\"chat.completion.chunk\",\"choices\":[{\"index\":0,\"delta\":{\"tool_calls\":[{\"index\":1,\"function\":{\"arguments\":\"123\\\"}\"}},{\"index\":0,\"id\":\"a\",\"function\":{\"name\":\"customer\",\"arguments\":\"word\\\":\\\"secret-one\\\"}\"}}]}}]}\n\n",
        b"data: {\"object\":\"chat.completion.chunk\",\"choices\":[{\"index\":0,\"delta\":{\"tool_calls\":[{\"index\":0,\"id\":\"call_a\",\"type\":\"function\",\"function\":{\"name\":\"lookup_customer\",\"arguments\":\"\"}},{\"index\":1,\"id\":\"call_b\",\"type\":\"function\",\"function\":{\"name\":\"notify\",\"arguments\":\"\"}}]}}]}\n\n",
        b"data: {\"object\":\"chat.completion.chunk\",\"choices\":[{\"index\":0,\"delta\":{},\"finish_reason\":\"tool_calls\"}]}\n\n",
        b"data: [DONE]\n\n",
    ];
    let mut total = 0u64;
    for chunk in chunks {
        let _ = inspector.on_chunk(chunk).await;
        total += chunk.len() as u64;
    }
    let _ = inspector.on_end().await;
    plugin
        .on_response_stream_terminated(&mut ctx, 200, &BodyOutcome::success(total))
        .await;

    let records = wait_for_records(&server).await;
    assert_eq!(records.len(), 1);
    let excerpt: Value = serde_json::from_str(
        records[0]["response_body"]
            .as_str()
            .expect("response excerpt"),
    )
    .expect("reassembled excerpt JSON");
    assert_eq!(excerpt["sse_reassembled"], true);
    assert_eq!(excerpt["completion_text"]["0"], "I will look that up.");
    assert_eq!(excerpt["finish_reason"]["0"], "tool_calls");
    let calls = excerpt["tool_calls"]["0"]
        .as_array()
        .expect("choice tool calls");
    assert_eq!(calls.len(), 2);
    assert_eq!(calls[0]["index"], 0);
    assert_eq!(calls[0]["id"], "call_a");
    assert_eq!(calls[0]["type"], "function");
    assert_eq!(calls[0]["function"]["name"], "lookup_customer");
    let first_args: Value = serde_json::from_str(
        calls[0]["function"]["arguments"]
            .as_str()
            .expect("arguments"),
    )
    .expect("reassembled first arguments");
    assert_eq!(first_args["password"], "[REDACTED]");
    assert_eq!(calls[1]["index"], 1);
    assert_eq!(calls[1]["id"], "call_b");
    assert_eq!(calls[1]["function"]["name"], "notify");
    let second_args: Value = serde_json::from_str(
        calls[1]["function"]["arguments"]
            .as_str()
            .expect("arguments"),
    )
    .expect("reassembled second arguments");
    assert_eq!(second_args["token"], "[REDACTED]");
    let raw_excerpt = records[0]["response_body"].as_str().unwrap();
    assert!(!raw_excerpt.contains("secret-one"), "{raw_excerpt}");
    assert!(!raw_excerpt.contains("abc123"), "{raw_excerpt}");
}

#[tokio::test]
async fn tool_call_only_sse_uses_reassembled_shape() {
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
    plugin.start_background_tasks().expect("live start");
    plugin.commit_background_tasks();
    let mut ctx = make_ctx();
    plugin
        .on_final_request_body_with_context(&mut ctx, &json_headers(), ai_request_body())
        .await;
    let mut inspector = plugin
        .response_stream_inspector(&ctx, 200, Some("text/event-stream"))
        .expect("inspector");
    let stream = b"data: {\"object\":\"chat.completion.chunk\",\"choices\":[{\"index\":2,\"delta\":{\"tool_calls\":[{\"index\":0,\"id\":\"call_only\",\"type\":\"function\",\"function\":{\"name\":\"lookup\",\"arguments\":\"{\\\"id\\\":42}\"}}]}}]}\n\ndata: {\"object\":\"chat.completion.chunk\",\"choices\":[{\"index\":2,\"delta\":{},\"finish_reason\":\"tool_calls\"}]}\n\ndata: [DONE]\n\n";
    let _ = inspector.on_chunk(stream).await;
    let _ = inspector.on_end().await;
    plugin
        .on_response_stream_terminated(&mut ctx, 200, &BodyOutcome::success(stream.len() as u64))
        .await;

    let records = wait_for_records(&server).await;
    let excerpt: Value = serde_json::from_str(
        records[0]["response_body"]
            .as_str()
            .expect("response excerpt"),
    )
    .expect("reassembled excerpt JSON");
    assert_eq!(excerpt["sse_reassembled"], true);
    assert!(excerpt.get("completion_text").is_none());
    assert_eq!(excerpt["tool_calls"]["2"][0]["id"], "call_only");
    assert_eq!(excerpt["finish_reason"]["2"], "tool_calls");
}

/// Drive one SSE body through a live streaming capture and return the exported
/// `response_body` excerpt.
async fn captured_sse_excerpt(stream: &str) -> String {
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
    plugin.start_background_tasks().expect("live start");
    plugin.commit_background_tasks();
    let mut ctx = make_ctx();
    plugin
        .on_final_request_body_with_context(&mut ctx, &json_headers(), ai_request_body())
        .await;
    let mut inspector = plugin
        .response_stream_inspector(&ctx, 200, Some("text/event-stream"))
        .expect("inspector");
    let _ = inspector.on_chunk(stream.as_bytes()).await;
    let _ = inspector.on_end().await;
    plugin
        .on_response_stream_terminated(&mut ctx, 200, &BodyOutcome::success(stream.len() as u64))
        .await;

    let records = wait_for_records(&server).await;
    assert_eq!(records.len(), 1);
    records[0]["response_body"]
        .as_str()
        .expect("response excerpt")
        .to_string()
}

#[tokio::test]
async fn repeated_indexless_tool_call_frames_withhold_ambiguous_arguments() {
    // Two `index`-less deltas for one choice: position cannot prove the second
    // continues the first, so the fragments are neither joined (which could
    // fabricate attacker-chosen JSON) nor exported apart (which would leak the
    // value half of a split `token`).
    let stream = concat!(
        r#"data: {"object":"chat.completion.chunk","choices":[{"index":0,"delta":{"tool_calls":[{"id":"call_1","type":"function","function":{"name":"lookup","arguments":"{\"token\":\"AAA"}}]}}]}"#,
        "\n\n",
        r#"data: {"object":"chat.completion.chunk","choices":[{"index":0,"delta":{"tool_calls":[{"function":{"arguments":"BBB\"}"}}]}}]}"#,
        "\n\ndata: [DONE]\n\n",
    );
    let excerpt = captured_sse_excerpt(stream).await;
    // The reassembled path is retained — the leaky per-frame fallback is not
    // an acceptable answer to ambiguity.
    assert!(excerpt.contains("sse_reassembled"), "{excerpt}");
    assert!(!excerpt.contains("AAA"), "{excerpt}");
    assert!(!excerpt.contains("BBB"), "{excerpt}");
    let parsed: Value = serde_json::from_str(&excerpt).expect("reassembled excerpt JSON");
    let calls = parsed["tool_calls"]["0"].as_array().expect("tool calls");
    assert_eq!(calls.len(), 1, "{excerpt}");
    assert_eq!(calls[0]["position"], 0);
    assert!(calls[0].get("index").is_none(), "{excerpt}");
    assert_eq!(calls[0]["arguments_withheld"], true);
    assert_eq!(
        calls[0]["function"]["arguments"],
        "[REDACTED:ambiguous_tool_call]"
    );
    // Unidentified entries also drop their positionally merged scalars.
    assert!(calls[0].get("id").is_none(), "{excerpt}");
    assert!(calls[0]["function"].get("name").is_none(), "{excerpt}");
}

#[tokio::test]
async fn indexless_tool_call_never_continues_an_indexed_call() {
    // Mixed indexed/`index`-less: the two key spaces are disjoint, so the
    // trailing fragment must not silently complete `index: 0`. Both fragments
    // are withheld because either could be the other's split half.
    let stream = concat!(
        r#"data: {"object":"chat.completion.chunk","choices":[{"index":0,"delta":{"tool_calls":[{"index":0,"id":"call_a","type":"function","function":{"name":"notify","arguments":"{\"token\":\"AAA"}}]}}]}"#,
        "\n\n",
        r#"data: {"object":"chat.completion.chunk","choices":[{"index":0,"delta":{"tool_calls":[{"function":{"arguments":"BBB\"}"}}]}}]}"#,
        "\n\ndata: [DONE]\n\n",
    );
    let excerpt = captured_sse_excerpt(stream).await;
    assert!(!excerpt.contains("AAA"), "{excerpt}");
    assert!(!excerpt.contains("BBB"), "{excerpt}");
    let parsed: Value = serde_json::from_str(&excerpt).expect("reassembled excerpt JSON");
    let calls = parsed["tool_calls"]["0"].as_array().expect("tool calls");
    assert_eq!(calls.len(), 2, "slots must stay disjoint: {excerpt}");
    // Provider-declared identity survives; its arguments do not.
    assert_eq!(calls[0]["index"], 0);
    assert_eq!(calls[0]["id"], "call_a");
    assert_eq!(calls[0]["function"]["name"], "notify");
    assert_eq!(calls[0]["arguments_withheld"], true);
    assert_eq!(calls[1]["position"], 0);
    assert_eq!(calls[1]["arguments_withheld"], true);
}

#[tokio::test]
async fn single_delta_indexless_tool_call_is_reassembled_and_redacted() {
    // One contributing delta is unambiguous by construction: array positions
    // are distinct calls and nothing is joined across frames.
    let stream = concat!(
        r#"data: {"object":"chat.completion.chunk","choices":[{"index":0,"delta":{"tool_calls":[{"id":"call_x","type":"function","function":{"name":"lookup","arguments":"{\"token\":\"AAA\",\"note\":\"keep\"}"}},{"id":"call_y","function":{"name":"other","arguments":"{\"note\":\"second\"}"}}]}}]}"#,
        "\n\n",
        r#"data: {"object":"chat.completion.chunk","choices":[{"index":0,"delta":{},"finish_reason":"tool_calls"}]}"#,
        "\n\ndata: [DONE]\n\n",
    );
    let excerpt = captured_sse_excerpt(stream).await;
    assert!(!excerpt.contains("AAA"), "{excerpt}");
    let parsed: Value = serde_json::from_str(&excerpt).expect("reassembled excerpt JSON");
    let calls = parsed["tool_calls"]["0"].as_array().expect("tool calls");
    assert_eq!(calls.len(), 2, "{excerpt}");
    assert_eq!(calls[0]["position"], 0);
    assert!(calls[0].get("arguments_withheld").is_none(), "{excerpt}");
    assert_eq!(calls[0]["id"], "call_x");
    let first: Value = serde_json::from_str(
        calls[0]["function"]["arguments"]
            .as_str()
            .expect("arguments"),
    )
    .expect("first arguments JSON");
    assert_eq!(first["token"], "[REDACTED]");
    assert_eq!(first["note"], "keep");
    assert_eq!(calls[1]["position"], 1);
    assert_eq!(calls[1]["id"], "call_y");
}

#[tokio::test]
async fn tool_call_ambiguity_is_scoped_to_one_choice() {
    // Choice 0 is correlated by provider `index` and stays reassembled; the
    // `index`-less repetition in choice 1 must not degrade it.
    let stream = concat!(
        r#"data: {"object":"chat.completion.chunk","choices":[{"index":0,"delta":{"tool_calls":[{"index":0,"id":"call_a","function":{"name":"n0","arguments":"{\"token\":\"AAA"}}]}},{"index":1,"delta":{"tool_calls":[{"id":"call_b","function":{"arguments":"{\"token\":\"CCC"}}]}}]}"#,
        "\n\n",
        r#"data: {"object":"chat.completion.chunk","choices":[{"index":0,"delta":{"tool_calls":[{"index":0,"function":{"arguments":"BBB\"}"}}]}},{"index":1,"delta":{"tool_calls":[{"function":{"arguments":"DDD\"}"}}]}}]}"#,
        "\n\ndata: [DONE]\n\n",
    );
    let excerpt = captured_sse_excerpt(stream).await;
    for leaked in ["AAABBB", "AAA", "BBB", "CCC", "DDD"] {
        assert!(!excerpt.contains(leaked), "{leaked} in {excerpt}");
    }
    let parsed: Value = serde_json::from_str(&excerpt).expect("reassembled excerpt JSON");
    let unambiguous = parsed["tool_calls"]["0"].as_array().expect("choice 0");
    assert_eq!(unambiguous.len(), 1, "{excerpt}");
    assert!(
        unambiguous[0].get("arguments_withheld").is_none(),
        "{excerpt}"
    );
    let joined: Value = serde_json::from_str(
        unambiguous[0]["function"]["arguments"]
            .as_str()
            .expect("arguments"),
    )
    .expect("choice 0 arguments JSON");
    assert_eq!(joined["token"], "[REDACTED]");
    let ambiguous = parsed["tool_calls"]["1"].as_array().expect("choice 1");
    assert_eq!(ambiguous.len(), 1, "{excerpt}");
    assert_eq!(ambiguous[0]["arguments_withheld"], true);
}

#[tokio::test]
async fn malformed_tool_call_index_is_unidentified_not_a_capture_downgrade() {
    // A `null` or non-integer `index` must not let a backend force the leaky
    // raw-frame fallback; it is treated as unidentified instead.
    let stream = concat!(
        r#"data: {"object":"chat.completion.chunk","choices":[{"index":0,"delta":{"tool_calls":[{"index":null,"id":"call_1","function":{"name":"lookup","arguments":"{\"token\":\"AAA"}}]}}]}"#,
        "\n\n",
        r#"data: {"object":"chat.completion.chunk","choices":[{"index":"0","delta":{"tool_calls":[{"index":"0","function":{"arguments":"BBB\"}"}}]}}]}"#,
        "\n\ndata: [DONE]\n\n",
    );
    let excerpt = captured_sse_excerpt(stream).await;
    assert!(excerpt.contains("sse_reassembled"), "{excerpt}");
    assert!(!excerpt.contains("AAA"), "{excerpt}");
    assert!(!excerpt.contains("BBB"), "{excerpt}");
    let parsed: Value = serde_json::from_str(&excerpt).expect("reassembled excerpt JSON");
    let calls = parsed["tool_calls"]["0"].as_array().expect("tool calls");
    assert_eq!(calls.len(), 1, "{excerpt}");
    assert_eq!(calls[0]["position"], 0);
    assert_eq!(calls[0]["arguments_withheld"], true);
}

#[tokio::test]
async fn indexed_tool_calls_survive_reordered_and_missing_frames() {
    // Provider-declared indices remain the trusted identity even when a call
    // is absent from a delta and the array order changes between deltas.
    let stream = concat!(
        r#"data: {"object":"chat.completion.chunk","choices":[{"index":0,"delta":{"tool_calls":[{"index":0,"id":"c0","function":{"name":"a","arguments":"{\"token\":\"XX"}},{"index":1,"id":"c1","function":{"name":"b","arguments":"{\"note\":\"pu"}}]}}]}"#,
        "\n\n",
        r#"data: {"object":"chat.completion.chunk","choices":[{"index":0,"delta":{"tool_calls":[{"index":1,"function":{"arguments":"bl"}}]}}]}"#,
        "\n\n",
        r#"data: {"object":"chat.completion.chunk","choices":[{"index":0,"delta":{"tool_calls":[{"index":1,"function":{"arguments":"ic\"}"}},{"index":0,"function":{"arguments":"YY\"}"}}]}}]}"#,
        "\n\ndata: [DONE]\n\n",
    );
    let excerpt = captured_sse_excerpt(stream).await;
    assert!(!excerpt.contains("XXYY"), "{excerpt}");
    let parsed: Value = serde_json::from_str(&excerpt).expect("reassembled excerpt JSON");
    let calls = parsed["tool_calls"]["0"].as_array().expect("tool calls");
    assert_eq!(calls.len(), 2, "{excerpt}");
    assert!(calls[0].get("arguments_withheld").is_none(), "{excerpt}");
    let first: Value = serde_json::from_str(
        calls[0]["function"]["arguments"]
            .as_str()
            .expect("arguments"),
    )
    .expect("call 0 arguments JSON");
    assert_eq!(first["token"], "[REDACTED]");
    let second: Value = serde_json::from_str(
        calls[1]["function"]["arguments"]
            .as_str()
            .expect("arguments"),
    )
    .expect("call 1 arguments JSON");
    assert_eq!(second["note"], "public");
}

#[tokio::test]
async fn non_openai_sse_capture_keeps_per_frame_redacted_fallback() {
    // Frames that are not uniformly parseable OpenAI chunks keep the raw
    // per-frame-redacted excerpt (documented residual): whole-frame PII is
    // still redacted, and the frames are exported as captured.
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
    plugin.start_background_tasks().expect("live start");
    plugin.commit_background_tasks();
    let mut ctx = make_ctx();
    plugin
        .on_final_request_body_with_context(&mut ctx, &json_headers(), ai_request_body())
        .await;
    let mut inspector = plugin
        .response_stream_inspector(&ctx, 200, Some("text/event-stream"))
        .expect("inspector");
    // Anthropic-style event frames: no object=chat.completion.chunk.
    let chunk: &[u8] =
        b"data: {\"type\":\"content_block_delta\",\"delta\":{\"text\":\"ssn 123-45-6789\"}}\n\n";
    let _ = inspector.on_chunk(chunk).await;
    let _ = inspector.on_end().await;
    plugin
        .on_response_stream_terminated(&mut ctx, 200, &BodyOutcome::success(chunk.len() as u64))
        .await;
    let records = wait_for_records(&server).await;
    assert_eq!(records.len(), 1);
    let excerpt = records[0]["response_body"].as_str().expect("excerpt");
    assert!(
        !excerpt.contains("sse_reassembled"),
        "non-OpenAI frames must not claim reassembly: {excerpt}"
    );
    assert!(
        !excerpt.contains("123-45-6789"),
        "whole-frame PII must still be redacted per-frame: {excerpt}"
    );
    assert!(excerpt.contains("content_block_delta"), "got: {excerpt}");
}

#[tokio::test]
async fn metadata_only_empty_redaction_patterns_rejected() {
    // metadata_only still exports the request-derived model/tool_names through
    // the redactor, so an explicitly emptied pattern set is rejected there too.
    // hash_only exports no request-derived strings and stays exempt.
    let base = json!({
        "mode": "metadata_only",
        "redaction": { "builtins": [] }
    });
    let err = AiTranscriptAudit::new(
        &config_with_sink("https://audit.example.com/x", base),
        loopback_http_client(),
    )
    .err()
    .expect("metadata_only with an empty pattern set must be rejected");
    assert!(err.contains("metadata_only"), "got: {err}");
    assert!(err.contains("full_body"), "got: {err}");

    let hash_only = json!({
        "mode": "hash_only",
        "redaction": { "builtins": [] }
    });
    assert!(
        AiTranscriptAudit::new(
            &config_with_sink("https://audit.example.com/x", hash_only),
            loopback_http_client(),
        )
        .is_ok(),
        "hash_only exports no request-derived strings; empty patterns stay allowed"
    );
}

#[tokio::test]
async fn sampled_flag_is_written_at_staging_for_streamed_and_request_only() {
    // The roll is known at staging: request-only configs and streamed
    // responses (which never reach the buffered response hook) must still
    // carry the documented `sampled` transaction-log field.
    let plugin = AiTranscriptAudit::new(
        &config_with_sink("https://audit.example.com/x", json!({})),
        loopback_http_client(),
    )
    .unwrap();
    let mut ctx = make_ctx();
    plugin
        .on_final_request_body_with_context(&mut ctx, &json_headers(), ai_request_body())
        .await;
    // rate defaults to 1.0, so the roll always wins.
    assert_eq!(
        ctx.metadata
            .get("ai_transcript_audit.sampled")
            .map(String::as_str),
        Some("true"),
        "sampled must be stamped at staging, not only on the buffered response path"
    );
    assert_eq!(
        ctx.metadata.get("ai_transcript_audit.sampled"),
        ctx.metadata.get("ai_transcript_audit.sample_hit"),
        "at staging the sampled flag is exactly the roll"
    );
}

#[tokio::test]
async fn unsampled_buffered_precommit_stamps_deferred_sink_status() {
    // rate 0, buffered 2xx, no overrides: staging is retained for a possible
    // later-validator error emission at commit, so the pre-commit sink_status
    // must remain the non-terminal `deferred`.
    let plugin = AiTranscriptAudit::new(
        &config_with_sink(
            "https://audit.example.com/x",
            json!({ "sampling": { "rate": 0.0 } }),
        ),
        loopback_http_client(),
    )
    .unwrap();
    let mut ctx = make_ctx();
    let headers = json_headers();
    plugin
        .on_final_request_body_with_context(&mut ctx, &headers, ai_request_body())
        .await;
    let result = plugin
        .on_final_response_body(&mut ctx, 200, &headers, br#"{"ok":true}"#)
        .await;
    assert!(matches!(result, PluginResult::Continue));
    assert_eq!(
        ctx.metadata
            .get("ai_transcript_audit.sink_status")
            .map(String::as_str),
        Some("deferred")
    );
}

#[tokio::test]
async fn fail_closed_rejected_then_unsampled_keeps_rejected_sink_status() {
    // A terminal fail-closed rejection must survive a later not-emitting commit
    // decision. Config: unsampled (rate 0) with `always_capture_on_error: false`
    // but the default `always_capture_on_guardrail: true`, so `commit_may_emit`
    // is true and the fail-closed admission runs, yet a plain error status does
    // NOT force emit at commit. Once an unhealthy sink under `on_sink_error:
    // reject` stamps `sink_status = "rejected"` and returns a 503, the observe-
    // only committed hook (which decides `emit = false` here) must not clobber
    // that terminal verdict with `"skipped"` — otherwise the client-visible 503
    // is mislogged and the fail-closed audit trail is lost.
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .respond_with(ResponseTemplate::new(401))
        .mount(&server)
        .await;
    let endpoint = format!("{}/ingest", server.uri());
    let plugin = AiTranscriptAudit::new(
        &config_with_sink(
            &endpoint,
            json!({
                "sampling": { "rate": 0.0, "always_capture_on_error": false },
                "sink": {
                    "type": "http",
                    "endpoint_url": endpoint.clone(),
                    "allow_insecure_loopback": true,
                    "batch_size": 1,
                    "flush_interval_ms": 100,
                    "max_retries": 0,
                    "on_sink_error": "reject"
                }
            }),
        ),
        loopback_http_client(),
    )
    .unwrap();
    plugin.start_background_tasks().expect("live start");
    plugin.commit_background_tasks();
    let headers = json_headers();

    // Emit one guardrail record (guardrail forces emit even with
    // always_capture_on_error=false) so the collector 401 flips the sink
    // unhealthy.
    let mut error_ctx = make_ctx();
    error_ctx.metadata.insert(
        "ai_semantic_firewall_rejected".to_string(),
        "true".to_string(),
    );
    plugin
        .on_final_request_body_with_context(&mut error_ctx, &headers, ai_request_body())
        .await;
    plugin
        .capture_final_response_body(&mut error_ctx, 200, &headers, br#"{"ok":true}"#)
        .await;

    // Now drive an unsampled, no-guardrail candidate over the buffered committed
    // path. The fail-closed admission rejects (503) and stamps "rejected"; the
    // committed hook then runs with emit=false and must NOT overwrite it.
    let mut saw_reject = false;
    for _ in 0..100 {
        let mut ctx = make_ctx();
        plugin
            .on_final_request_body_with_context(&mut ctx, &headers, ai_request_body())
            .await;
        let result = plugin
            .capture_final_response_body(&mut ctx, 200, &headers, br#"{"ok":true}"#)
            .await;
        if matches!(
            result,
            PluginResult::Reject {
                status_code: 503,
                ..
            }
        ) {
            assert_eq!(
                ctx.metadata
                    .get("ai_transcript_audit.sink_status")
                    .map(String::as_str),
                Some("rejected"),
                "a fail-closed rejection must not be downgraded to skipped by the \
                 not-emitting committed decision"
            );

            // Replaying `after_proxy` over an already-fixed rejection cannot
            // replace that response: proxy core intentionally ignores Reject
            // results in this scoped pass. The audit hook must therefore skip a
            // fresh fail-closed admission instead of stamping `rejected` for a
            // 503 the client will not receive.
            let mut replay_ctx = make_ctx();
            plugin
                .on_final_request_body_with_context(&mut replay_ctx, &headers, ai_request_body())
                .await;
            replay_ctx
                .metadata
                .insert("ferrum:rejection_response".to_string(), "true".to_string());
            let replay_result = plugin
                .after_proxy(&mut replay_ctx, 403, &mut HashMap::new())
                .await;
            assert!(matches!(replay_result, PluginResult::Continue));
            assert_ne!(
                replay_ctx
                    .metadata
                    .get("ai_transcript_audit.sink_status")
                    .map(String::as_str),
                Some("rejected"),
                "reject-path after_proxy replay must not claim an ignored fail-closed 503"
            );
            saw_reject = true;
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    }
    assert!(
        saw_reject,
        "the unhealthy sink under on_sink_error=reject must fail closed for this candidate"
    );
}

async fn spawn_audit_keepalive_server(
    responses: Vec<(u16, &'static [u8])>,
) -> (String, Arc<AtomicUsize>, Arc<AtomicUsize>) {
    use tokio::io::AsyncWriteExt;
    use tokio::net::TcpListener;

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let connections = Arc::new(AtomicUsize::new(0));
    let requests = Arc::new(AtomicUsize::new(0));
    let connections_task = Arc::clone(&connections);
    let requests_task = Arc::clone(&requests);
    tokio::spawn(async move {
        loop {
            let Ok((mut socket, _)) = listener.accept().await else {
                break;
            };
            connections_task.fetch_add(1, Ordering::SeqCst);
            let responses = responses.clone();
            let requests = Arc::clone(&requests_task);
            tokio::spawn(async move {
                let mut index = 0usize;
                loop {
                    if !read_http11_request_headers(&mut socket).await {
                        break;
                    }
                    requests.fetch_add(1, Ordering::SeqCst);
                    let (status, body) = responses[index % responses.len()];
                    index = index.saturating_add(1);
                    let headers = format!(
                        "HTTP/1.1 {status} Status\r\nContent-Length: {}\r\nConnection: keep-alive\r\n\r\n",
                        body.len()
                    );
                    if socket.write_all(headers.as_bytes()).await.is_err() {
                        break;
                    }
                    tokio::time::sleep(std::time::Duration::from_millis(15)).await;
                    if socket.write_all(body).await.is_err() {
                        break;
                    }
                }
            });
        }
    });
    (format!("http://{addr}/ingest"), connections, requests)
}

async fn wait_for_audit_count(counter: &AtomicUsize, expected: usize) {
    for _ in 0..100 {
        if counter.load(Ordering::SeqCst) >= expected {
            return;
        }
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
    }
    panic!(
        "timed out waiting for {expected} audit sink requests; saw {}",
        counter.load(Ordering::SeqCst)
    );
}

async fn audit_roundtrip(plugin: &AiTranscriptAudit) {
    let headers = json_headers();
    let mut ctx = make_ctx();
    plugin
        .on_final_request_body_with_context(&mut ctx, &headers, ai_request_body())
        .await;
    plugin
        .capture_final_response_body(&mut ctx, 200, &headers, br#"{"ok":true}"#)
        .await;
}

#[tokio::test(flavor = "current_thread")]
async fn ai_transcript_audit_reuses_http11_connection_across_successful_batches() {
    let (endpoint, connections, requests) = spawn_audit_keepalive_server(vec![(200, b"OK")]).await;
    let plugin = AiTranscriptAudit::new(
        &config_with_sink(
            &endpoint,
            json!({
                "mode": "metadata_only",
            }),
        ),
        loopback_http_client(),
    )
    .unwrap();
    plugin.start_background_tasks().expect("live start");
    plugin.commit_background_tasks();
    // Ensure sink batching settings from config_with_sink (batch_size 1).
    audit_roundtrip(&plugin).await;
    audit_roundtrip(&plugin).await;
    wait_for_audit_count(&requests, 2).await;
    assert_eq!(
        connections.load(Ordering::SeqCst),
        1,
        "ai_transcript_audit must drain sink ACKs through the shared helper and reuse HTTP/1.1"
    );
}

#[tokio::test(flavor = "current_thread")]
async fn ai_transcript_audit_reuses_http11_connection_across_retry() {
    let (endpoint, connections, requests) =
        spawn_audit_keepalive_server(vec![(503, b"no"), (200, b"OK")]).await;
    let config = json!({
        "mode": "metadata_only",
        "sink": {
            "type": "http",
            "endpoint_url": endpoint,
            "allow_insecure_loopback": true,
            "batch_size": 1,
            "flush_interval_ms": 100,
            "max_retries": 1,
            "retry_delay_ms": 1,
        }
    });
    let plugin = AiTranscriptAudit::new(&config, loopback_http_client()).unwrap();
    plugin.start_background_tasks().expect("live start");
    plugin.commit_background_tasks();
    audit_roundtrip(&plugin).await;
    wait_for_audit_count(&requests, 2).await;
    assert_eq!(
        connections.load(Ordering::SeqCst),
        1,
        "ai_transcript_audit must drain retryable sink bodies before reusing the connection"
    );
}

// Chunked oversized ACK capping is covered directly by
// `shared_helper_aborts_oversized_chunked_ack_body` in
// `http_batch_response_drain_tests.rs` (asserts `HttpBatchDrainOutcome::LimitExceeded`).
// A caller-level wall-clock check cannot distinguish capped abort from an
// uncapped EOF read of ~1.1 MiB, so the redundant audit fixture was removed.

// ---------------------------------------------------------------------------
// Capture hard maxima, aggregate admission, and bounded model/tool metadata
// (issues #3045 / #3046)
// ---------------------------------------------------------------------------

#[tokio::test]
async fn capture_limit_hard_maxima_boundary_admission() {
    let client = loopback_http_client();
    for (key, hard_max) in [
        ("max_request_bytes", HARD_MAX_REQUEST_BYTES),
        ("max_response_bytes", HARD_MAX_RESPONSE_BYTES),
        ("max_stream_capture_bytes", HARD_MAX_STREAM_CAPTURE_BYTES),
    ] {
        let below = config_with_sink(
            "https://audit.example.com/x",
            json!({ "limits": { (key): hard_max - 1 } }),
        );
        AiTranscriptAudit::new(&below, client.clone()).expect("below hard max must admit");

        let at = config_with_sink(
            "https://audit.example.com/x",
            json!({ "limits": { (key): hard_max } }),
        );
        AiTranscriptAudit::new(&at, client.clone()).expect("exact hard max must admit");

        let above = config_with_sink(
            "https://audit.example.com/x",
            json!({ "limits": { (key): hard_max + 1 } }),
        );
        let err = AiTranscriptAudit::new(&above, client.clone())
            .err()
            .expect("above hard max must reject");
        assert!(
            err.contains(key) && err.contains("hard maximum"),
            "got: {err}"
        );
    }
}

#[tokio::test]
async fn capture_limit_aggregate_admission_boundaries() {
    let client = loopback_http_client();
    // Individually under each hard max, aggregate exactly at the hard sum.
    let at = config_with_sink(
        "https://audit.example.com/x",
        json!({
            "limits": {
                "max_request_bytes": HARD_MAX_REQUEST_BYTES,
                "max_response_bytes": HARD_MAX_RESPONSE_BYTES - 1,
                "max_stream_capture_bytes": 1
            }
        }),
    );
    AiTranscriptAudit::new(&at, client.clone()).expect("exact aggregate must admit");

    let above = config_with_sink(
        "https://audit.example.com/x",
        json!({
            "limits": {
                "max_request_bytes": HARD_MAX_REQUEST_BYTES,
                "max_response_bytes": HARD_MAX_RESPONSE_BYTES,
                "max_stream_capture_bytes": 1
            }
        }),
    );
    let err = AiTranscriptAudit::new(&above, client.clone())
        .err()
        .expect("over-aggregate must reject");
    assert!(
        err.contains("must be <=") && err.contains(&HARD_MAX_CAPTURE_BYTES_AGGREGATE.to_string()),
        "got: {err}"
    );
}

#[tokio::test]
async fn platform_max_capture_limit_rejected_fail_closed() {
    let config = config_with_sink(
        "https://audit.example.com/x",
        json!({ "limits": { "max_request_bytes": u64::MAX } }),
    );
    let err = AiTranscriptAudit::new(&config, loopback_http_client())
        .err()
        .expect("platform-max limit must reject");
    assert!(
        err.contains("max_request_bytes") && err.contains("hard maximum"),
        "got: {err}"
    );
}

#[tokio::test]
async fn authenticated_status_exposes_admitted_limits_without_content() {
    let plugin = AiTranscriptAudit::new(
        &config_with_sink(
            "https://audit.example.com/x",
            json!({
                "limits": {
                    "max_request_bytes": 1024,
                    "max_response_bytes": 2048,
                    "max_stream_capture_bytes": 4096
                }
            }),
        ),
        loopback_http_client(),
    )
    .unwrap();
    let before = snapshots();
    assert!(
        !before.iter().any(|snap| snap.max_request_bytes == 1024
            && snap.max_response_bytes == 2048
            && snap.max_stream_capture_bytes == 4096),
        "uncommitted construction must not publish status"
    );

    plugin.start_background_tasks().expect("live start");
    plugin.commit_background_tasks();
    let snap = plugin.status_snapshot();
    assert_eq!(snap.max_request_bytes, 1024);
    assert_eq!(snap.max_response_bytes, 2048);
    assert_eq!(snap.max_stream_capture_bytes, 4096);
    assert_eq!(snap.hard_max_request_bytes, HARD_MAX_REQUEST_BYTES as u64);
    assert_eq!(
        snap.hard_max_capture_bytes_aggregate,
        HARD_MAX_CAPTURE_BYTES_AGGREGATE as u64
    );
    assert_eq!(snap.max_model_bytes, MAX_MODEL_BYTES as u64);
    assert_eq!(snap.max_tool_names, MAX_TOOL_NAMES as u64);
    assert_eq!(snap.max_tool_name_bytes, MAX_TOOL_NAME_BYTES as u64);
    assert_eq!(
        snap.max_tool_names_aggregate_bytes,
        MAX_TOOL_NAMES_AGGREGATE_BYTES as u64
    );
    assert_eq!(
        snap.max_retained_record_bytes,
        max_retained_record_bytes(1024, 2048, 4096) as u64
    );
    let published = snapshots();
    assert!(
        published
            .iter()
            .any(|entry| entry.instance_id == snap.instance_id),
        "committed instance must appear in authenticated snapshots"
    );
    let encoded = serde_json::to_string(&snap).expect("status serializes");
    assert!(!encoded.contains("gpt"));
    assert!(!encoded.contains("ssn"));
    assert!(!encoded.contains("messages"));
    drop(plugin);
    assert!(
        !snapshots()
            .iter()
            .any(|entry| entry.instance_id == snap.instance_id),
        "drop must unregister status"
    );
}

#[tokio::test]
async fn huge_model_is_bounded_with_truncation_hash() {
    let mock = MockServer::start().await;
    Mock::given(method("POST"))
        .respond_with(ResponseTemplate::new(200))
        .mount(&mock)
        .await;
    let plugin = AiTranscriptAudit::new(
        &config_with_sink(
            &mock.uri(),
            json!({
                "mode": "full_body",
                "allow_full_body": true,
                "limits": { "max_request_bytes": 512 }
            }),
        ),
        loopback_http_client(),
    )
    .unwrap();
    plugin.start_background_tasks().expect("live start");
    plugin.commit_background_tasks();

    // The excess bytes must differ from the retained prefix: a single-character
    // fixture cannot observe a bypass, because any slice past the ceiling is
    // trivially "contained" in the bounded prefix.
    let huge_model = "m".repeat(MAX_MODEL_BYTES) + &"z".repeat(4096);
    let body =
        format!(r#"{{"model":"{huge_model}","messages":[{{"role":"user","content":"hi"}}]}}"#);
    let mut ctx = make_ctx();
    let headers = json_headers();
    plugin
        .on_final_request_body_with_context(&mut ctx, &headers, body.as_bytes())
        .await;
    plugin
        .capture_final_response_body(&mut ctx, 200, &headers, br#"{"ok":true}"#)
        .await;

    let records = wait_for_records(&mock).await;
    let model = records[0]["model"].as_str().expect("model");
    assert_eq!(model.len(), MAX_MODEL_BYTES);
    assert!(!model.contains(&huge_model[MAX_MODEL_BYTES..MAX_MODEL_BYTES + 16]));
    assert_eq!(records[0]["model_truncated"], true);
    let hash = records[0]["model_hash"].as_str().expect("model_hash");
    assert_eq!(hash.len(), 64);
    assert!(records[0].get("request_body").is_some());
}

#[tokio::test]
async fn huge_tool_count_and_name_lengths_are_bounded() {
    let mock = MockServer::start().await;
    Mock::given(method("POST"))
        .respond_with(ResponseTemplate::new(200))
        .mount(&mock)
        .await;
    let plugin = AiTranscriptAudit::new(
        &config_with_sink(
            &mock.uri(),
            json!({
                "mode": "full_body",
                "allow_full_body": true,
                "capture": { "tool_calls": true },
                "limits": { "max_request_bytes": 256 }
            }),
        ),
        loopback_http_client(),
    )
    .unwrap();
    plugin.start_background_tasks().expect("live start");
    plugin.commit_background_tasks();

    // Excess bytes differ from the retained prefix so the per-name and
    // record-wide leak assertions below can actually observe a bypass.
    let long_name = "t".repeat(MAX_TOOL_NAME_BYTES) + &"z".repeat(64);
    let mut tools = Vec::new();
    for index in 0..(MAX_TOOL_NAMES + 32) {
        let name = if index == 0 {
            long_name.clone()
        } else {
            format!("tool_{index:04}")
        };
        tools.push(json!({"type":"function","function":{"name": name}}));
    }
    // Also add many large names that would blow the aggregate budget.
    for index in 0..64 {
        let name = format!("{}{index}", "a".repeat(MAX_TOOL_NAME_BYTES));
        tools.push(json!({"type":"function","function":{"name": name}}));
    }
    // Pad the prompt past `max_request_bytes` so the `full_body` raw request
    // excerpt (an explicit opt-in that legitimately keeps raw bytes) can never
    // reach the tool array; the record-wide assertion then only observes the
    // bounded `tool_names`.
    let body = json!({
        "model": "gpt-4o",
        "messages": [{"role":"user","content": "h".repeat(512)}],
        "tools": tools
    });
    let body_bytes = serde_json::to_vec(&body).unwrap();

    let mut ctx = make_ctx();
    let headers = json_headers();
    plugin
        .on_final_request_body_with_context(&mut ctx, &headers, &body_bytes)
        .await;
    plugin
        .capture_final_response_body(&mut ctx, 200, &headers, br#"{"ok":true}"#)
        .await;

    let records = wait_for_records(&mock).await;
    let names = records[0]["tool_names"].as_array().expect("tool_names");
    assert!(names.len() <= MAX_TOOL_NAMES);
    let mut aggregate = 0usize;
    for name in names {
        let name = name.as_str().expect("name str");
        assert!(name.len() <= MAX_TOOL_NAME_BYTES);
        aggregate += name.len();
        assert!(!name.contains(&long_name[MAX_TOOL_NAME_BYTES..]));
    }
    assert!(aggregate <= MAX_TOOL_NAMES_AGGREGATE_BYTES);
    assert_eq!(records[0]["tool_names_truncated"], true);
    assert!(records[0]["tool_names_omitted"].as_u64().unwrap() > 0);
    let hash = records[0]["tool_names_hash"].as_str().expect("hash");
    assert_eq!(hash.len(), 64);
    let encoded = serde_json::to_string(&records[0]).unwrap();
    assert!(!encoded.contains(&long_name[MAX_TOOL_NAME_BYTES..MAX_TOOL_NAME_BYTES + 8]));
}

#[tokio::test]
async fn truncation_metadata_stable_serialization_omits_false_flags() {
    let mock = MockServer::start().await;
    Mock::given(method("POST"))
        .respond_with(ResponseTemplate::new(200))
        .mount(&mock)
        .await;
    let plugin = AiTranscriptAudit::new(
        &config_with_sink(
            &mock.uri(),
            json!({ "mode": "full_body", "allow_full_body": true }),
        ),
        loopback_http_client(),
    )
    .unwrap();
    plugin.start_background_tasks().expect("live start");
    plugin.commit_background_tasks();

    let mut ctx = make_ctx();
    let headers = json_headers();
    let body = br#"{"model":"gpt-4o","messages":[{"role":"user","content":"hi"}],"tools":[{"type":"function","function":{"name":"get_weather"}}]}"#;
    plugin
        .on_final_request_body_with_context(&mut ctx, &headers, body)
        .await;
    plugin
        .capture_final_response_body(&mut ctx, 200, &headers, br#"{"ok":true}"#)
        .await;
    let records = wait_for_records(&mock).await;
    assert!(records[0].get("model_truncated").is_none());
    assert!(records[0].get("model_hash").is_none());
    assert!(records[0].get("tool_names_truncated").is_none());
    assert!(records[0].get("tool_names_omitted").is_none());
    assert!(records[0].get("tool_names_hash").is_none());
    assert_eq!(records[0]["model"], "gpt-4o");
    assert_eq!(records[0]["tool_names"], json!(["get_weather"]));
}

#[tokio::test]
async fn metadata_only_mode_still_bounds_model_and_tools() {
    let mock = MockServer::start().await;
    Mock::given(method("POST"))
        .respond_with(ResponseTemplate::new(200))
        .mount(&mock)
        .await;
    let plugin = AiTranscriptAudit::new(
        &config_with_sink(
            &mock.uri(),
            json!({
                "mode": "metadata_only",
                "capture": { "tool_calls": true },
                "limits": { "max_request_bytes": 64 }
            }),
        ),
        loopback_http_client(),
    )
    .unwrap();
    plugin.start_background_tasks().expect("live start");
    plugin.commit_background_tasks();

    let huge_model = "Z".repeat(MAX_MODEL_BYTES * 8);
    let tools: Vec<Value> = (0..(MAX_TOOL_NAMES + 8))
        .map(|index| json!({"type":"function","function":{"name": format!("fn_{index}")}}))
        .collect();
    let body = json!({
        "model": huge_model,
        "messages": [{"role":"user","content":"x"}],
        "tools": tools
    });
    let body_bytes = serde_json::to_vec(&body).unwrap();
    let mut ctx = make_ctx();
    let headers = json_headers();
    plugin
        .on_final_request_body_with_context(&mut ctx, &headers, &body_bytes)
        .await;
    plugin
        .capture_final_response_body(&mut ctx, 200, &headers, br#"{"ok":true}"#)
        .await;
    let records = wait_for_records(&mock).await;
    assert!(records[0].get("request_body").is_none());
    let model = records[0]["model"].as_str().unwrap();
    assert!(model.len() <= MAX_MODEL_BYTES);
    assert_eq!(records[0]["model_truncated"], true);
    assert!(records[0]["tool_names"].as_array().unwrap().len() <= MAX_TOOL_NAMES);
    assert_eq!(records[0]["tool_names_truncated"], true);
}

#[tokio::test]
async fn model_and_tool_pii_crossing_bound_is_redacted_before_truncation() {
    // Pad so the SSN straddles the model/tool ceilings: truncate-then-redact
    // would export the unmatched raw prefix ("123-45"). Protected modes must
    // redact the full observed string first; full_body may keep the raw prefix.
    let ssn = "123-45-6789";
    let model_pad = MAX_MODEL_BYTES - 6;
    let tool_pad = MAX_TOOL_NAME_BYTES - 6;
    // The pad ends on a non-word character so the SSN is a real `\b`-delimited
    // span: a digit run glued to word characters is not PII to the builtin
    // pattern, and the fixture would prove nothing about ordering.
    let model_lead = "m".repeat(model_pad - 1) + "/";
    let tool_lead = "t".repeat(tool_pad - 1) + "/";
    let huge_model = format!("{model_lead}{ssn}");
    let huge_tool = format!("{tool_lead}{ssn}");
    // Straddle check: the retained window ends mid-SSN.
    assert!(huge_model[..MAX_MODEL_BYTES].ends_with("123-45"));
    assert!(huge_tool[..MAX_TOOL_NAME_BYTES].ends_with("123-45"));

    let body = json!({
        "model": huge_model.clone(),
        "messages": [{"role":"user","content":"hi"}],
        "tools": [{"type":"function","function":{"name": huge_tool.clone()}}]
    });
    let body_bytes = serde_json::to_vec(&body).unwrap();
    let secret = "fleet-stable-hmac-key";

    for mode in [
        json!({ "mode": "redacted_body" }),
        json!({ "mode": "metadata_only" }),
    ] {
        let server = mock_sink().await;
        let endpoint = format!("{}/ingest", server.uri());
        let mut overrides = mode.clone();
        if let Some(obj) = overrides.as_object_mut() {
            obj.insert("capture".to_string(), json!({ "tool_calls": true }));
            obj.insert("redaction".to_string(), json!({ "hash_secret": secret }));
        }
        let plugin = AiTranscriptAudit::new(
            &config_with_sink(&endpoint, overrides.clone()),
            loopback_http_client(),
        )
        .expect("valid config");
        plugin.start_background_tasks().expect("live start");
        plugin.commit_background_tasks();
        let mut ctx = make_ctx();
        let headers = json_headers();
        plugin
            .on_final_request_body_with_context(&mut ctx, &headers, &body_bytes)
            .await;
        plugin
            .capture_final_response_body(&mut ctx, 200, &headers, br#"{"ok":true}"#)
            .await;
        let records = wait_for_records(&server).await;
        assert_eq!(records.len(), 1, "overrides: {overrides}");

        let model = records[0]["model"].as_str().expect("model");
        assert!(
            model.len() <= MAX_MODEL_BYTES,
            "model must stay hard-bounded ({overrides}): len={}",
            model.len()
        );
        assert!(
            !model.contains("123-45") && !model.contains("123-4"),
            "raw SSN prefix leaked through model after bound ({overrides}): {model}"
        );
        assert_eq!(records[0]["model_truncated"], true);
        assert_eq!(
            records[0]["model_hash"].as_str().expect("model_hash"),
            keyed_reference(secret).keyed_hash_hex(huge_model.as_bytes()),
            "truncation hash must cover the full original model ({overrides})"
        );

        let tool = records[0]["tool_names"][0].as_str().expect("tool name");
        assert!(
            tool.len() <= MAX_TOOL_NAME_BYTES,
            "tool name must stay hard-bounded ({overrides}): len={}",
            tool.len()
        );
        assert!(
            !tool.contains("123-45") && !tool.contains("123-4"),
            "raw SSN prefix leaked through tool name after bound ({overrides}): {tool}"
        );
        assert_eq!(records[0]["tool_names_truncated"], true);
        assert!(records[0]["tool_names_hash"].as_str().is_some());
    }

    // full_body keeps the bounded raw prefix (explicit opt-in), including the
    // unmatched SSN fragment that protected modes must not export.
    let server = mock_sink().await;
    let endpoint = format!("{}/ingest", server.uri());
    let plugin = AiTranscriptAudit::new(
        &config_with_sink(
            &endpoint,
            json!({
                "mode": "full_body",
                "allow_full_body": true,
                "capture": { "tool_calls": true },
                "redaction": { "hash_secret": secret }
            }),
        ),
        loopback_http_client(),
    )
    .unwrap();
    plugin.start_background_tasks().expect("live start");
    plugin.commit_background_tasks();
    let mut ctx = make_ctx();
    let headers = json_headers();
    plugin
        .on_final_request_body_with_context(&mut ctx, &headers, &body_bytes)
        .await;
    plugin
        .capture_final_response_body(&mut ctx, 200, &headers, br#"{"ok":true}"#)
        .await;
    let records = wait_for_records(&server).await;
    assert_eq!(records.len(), 1);
    let model = records[0]["model"].as_str().expect("model");
    assert_eq!(model, &huge_model[..MAX_MODEL_BYTES]);
    assert!(model.ends_with("123-45"));
    assert_eq!(records[0]["model_truncated"], true);
    assert_eq!(
        records[0]["model_hash"].as_str().expect("model_hash"),
        keyed_reference(secret).keyed_hash_hex(huge_model.as_bytes())
    );
    let tool = records[0]["tool_names"][0].as_str().expect("tool name");
    assert_eq!(tool, &huge_tool[..MAX_TOOL_NAME_BYTES]);
    assert!(tool.ends_with("123-45"));
    assert_eq!(records[0]["tool_names_truncated"], true);
}

#[tokio::test]
async fn custom_redaction_expansion_is_not_reapplied_after_bounding() {
    let server = mock_sink().await;
    let endpoint = format!("{}/ingest", server.uri());
    let placeholder = "X".repeat(MAX_MODEL_BYTES * 2);
    let plugin = AiTranscriptAudit::new(
        &config_with_sink(
            &endpoint,
            json!({
                "mode": "metadata_only",
                "capture": { "tool_calls": true },
                "redaction": {
                    "builtins": [],
                    "custom_patterns": [{ "name": "every_char", "regex": "." }],
                    "placeholder": placeholder,
                    "hash_redacted_values": false
                }
            }),
        ),
        loopback_http_client(),
    )
    .expect("valid expanding redactor");
    plugin.start_background_tasks().expect("live start");
    plugin.commit_background_tasks();

    let body = serde_json::to_vec(&json!({
        "model": "m",
        "messages": [{"role":"user","content":"hi"}],
        "tools": [{"type":"function","function":{"name":"t"}}]
    }))
    .unwrap();
    let mut ctx = make_ctx();
    let headers = json_headers();
    plugin
        .on_final_request_body_with_context(&mut ctx, &headers, &body)
        .await;
    plugin
        .capture_final_response_body(&mut ctx, 200, &headers, br#"{"ok":true}"#)
        .await;

    let records = wait_for_records(&server).await;
    assert_eq!(records.len(), 1);
    let model = records[0]["model"].as_str().expect("model");
    let tool = records[0]["tool_names"][0].as_str().expect("tool");
    assert_eq!(model.len(), MAX_MODEL_BYTES);
    assert_eq!(tool.len(), MAX_TOOL_NAME_BYTES);
    assert!(model.bytes().all(|byte| byte == b'X'));
    assert!(tool.bytes().all(|byte| byte == b'X'));
    assert_eq!(records[0]["model_truncated"], true);
    assert_eq!(records[0]["tool_names_truncated"], true);
}

#[test]
fn retained_record_contract_matches_documented_formula() {
    assert_eq!(
        max_retained_record_bytes(65536, 65536, 65536),
        65536 + 65536 + MAX_MODEL_BYTES + MAX_TOOL_NAMES_AGGREGATE_BYTES
    );
    assert_eq!(
        max_retained_record_bytes(100, 50, 200),
        100 + 200 + MAX_MODEL_BYTES + MAX_TOOL_NAMES_AGGREGATE_BYTES
    );
}
